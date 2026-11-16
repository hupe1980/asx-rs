//! A real MSH over TLS on 127.0.0.1, for end-to-end tests of the built-in
//! client's transport: the handshake, the client certificate, SNI,
//! connection reuse and the server-chain revocation check.
//!
//! [`TlsMsh`] serves an `asx::Inbound` over TLS with the server party's TLS
//! certificate and **requires** a client certificate that chains to the
//! given CA, as a BDEW MSH does (BDEW AS4-Profil 1.2 Kap. 2.2.6.1). It records
//! every client chain presented, the SNI name and the handshake count. A
//! second, plain-HTTP listener serves the CRLs every [`TestCa`] publishes,
//! so revocation checks run over the network too.
//!
//! The built-in client refuses loopback addresses; point it at the MSH with
//! `Builder::resolve`, the explicit, visible pin:
//!
//! ```rust,no_run
//! # async fn demo(us: asx::testkit::pki::TestParty, them: asx::testkit::pki::TestParty,
//! #               ca: asx::testkit::pki::TestCa, receiver: asx::Inbound) -> asx::Result<()> {
//! use asx::testkit::{pki::CRL_HOST, tls::TlsMsh};
//! let msh = TlsMsh::start(&them, &ca, receiver).await;
//! let client = asx::as4::As4::builder(asx::Profile::bdew())
//!     .local(us.local())
//!     .trust_anchor(us.anchor())
//!     .partner(them.partner(msh.url()))
//!     .resolve(msh.host(), msh.addr())
//!     .resolve(CRL_HOST, msh.crl_addr())
//!     .build()?;
//! # let _ = client; Ok(()) }
//! ```

use super::pki::{TestCa, TestParty};
use hyper_util::rt::{TokioExecutor, TokioIo};
use openssl::ssl::{NameType, Ssl, SslAcceptor, SslMethod, SslVerifyMode, SslVersion};
use openssl::x509::X509;
use openssl::x509::store::X509StoreBuilder;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

#[derive(Default)]
struct State {
    chains: Mutex<Vec<Vec<asx::Certificate>>>,
    server_names: Mutex<Vec<Option<String>>>,
    handshakes: AtomicUsize,
    requests: AtomicUsize,
}

/// A TLS MSH bound to 127.0.0.1; stops when dropped.
pub struct TlsMsh {
    url: String,
    host: String,
    addr: SocketAddr,
    crl_addr: SocketAddr,
    state: Arc<State>,
    tasks: Vec<JoinHandle<()>>,
}

impl std::fmt::Debug for TlsMsh {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsMsh")
            .field("url", &self.url)
            .field("addr", &self.addr)
            .field("crl_addr", &self.crl_addr)
            .field("handshakes", &self.handshakes())
            .finish()
    }
}

impl Drop for TlsMsh {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl TlsMsh {
    /// Serve `inbound` as `server` at its endpoint (a BDEW party's URI
    /// subjectAltName; `https://msh.testkit.example/as4` when it has none),
    /// with `server.tls` as the TLS certificate, requiring a client
    /// certificate issued under `client_ca`. TLS 1.2 and 1.3, the TR-03116-3
    /// groups (Brainpool first).
    ///
    /// # Panics
    ///
    /// When the sockets cannot be bound or the server's key pair is
    /// unusable: a test setup failure.
    pub async fn start(server: &TestParty, client_ca: &TestCa, inbound: asx::Inbound) -> TlsMsh {
        Self::spawn(server, client_ca, inbound, false).await
    }

    /// [`TlsMsh::start`], capped at TLS 1.2 — the version a peer on
    /// OpenSSL before 3.2 speaks with Brainpool certificates.
    pub async fn start_tls12(
        server: &TestParty,
        client_ca: &TestCa,
        inbound: asx::Inbound,
    ) -> TlsMsh {
        Self::spawn(server, client_ca, inbound, true).await
    }

    async fn spawn(
        server: &TestParty,
        client_ca: &TestCa,
        inbound: asx::Inbound,
        tls12_only: bool,
    ) -> TlsMsh {
        let url = server
            .endpoint
            .clone()
            .unwrap_or_else(|| "https://msh.testkit.example/as4".to_string());
        let host = http::Uri::try_from(url.as_str())
            .ok()
            .and_then(|u| u.host().map(str::to_owned))
            .expect("the endpoint has a host");
        let acceptor = acceptor(server, client_ca, tls12_only);
        let state = Arc::new(State::default());

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind TLS");
        let addr = listener.local_addr().expect("TLS addr");
        let tls_task = tokio::spawn(serve_tls(listener, acceptor, inbound, state.clone()));

        let crl_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind CRL");
        let crl_addr = crl_listener.local_addr().expect("CRL addr");
        let crl_task = tokio::spawn(serve_crls(crl_listener));

        TlsMsh {
            url,
            host,
            addr,
            crl_addr,
            state,
            tasks: vec![tls_task, crl_task],
        }
    }

    /// The endpoint URL the server's certificates name.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The endpoint's host: pin it to [`TlsMsh::addr`].
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The TLS listener.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The plain-HTTP CRL listener: pin [`super::pki::CRL_HOST`] to it.
    pub fn crl_addr(&self) -> SocketAddr {
        self.crl_addr
    }

    /// Every client certificate chain presented (leaf first), one per
    /// completed handshake.
    pub fn client_certificates(&self) -> Vec<Vec<asx::Certificate>> {
        self.state.chains.lock().expect("chains").clone()
    }

    /// The SNI host name of each completed handshake (`None`: none sent).
    pub fn server_names(&self) -> Vec<Option<String>> {
        self.state.server_names.lock().expect("names").clone()
    }

    /// Completed TLS handshakes.
    pub fn handshakes(&self) -> usize {
        self.state.handshakes.load(Ordering::SeqCst)
    }

    /// HTTP requests served over TLS.
    pub fn requests(&self) -> usize {
        self.state.requests.load(Ordering::SeqCst)
    }
}

fn acceptor(server: &TestParty, client_ca: &TestCa, tls12_only: bool) -> SslAcceptor {
    let mut builder =
        SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server()).expect("acceptor");
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .expect("min version");
    let mut groups = "brainpoolP256r1:brainpoolP384r1:prime256v1:secp384r1".to_string();
    if openssl::version::number() >= 0x3020_0000 && !tls12_only {
        groups.push_str(":brainpoolP256r1tls13:brainpoolP384r1tls13");
    } else {
        builder
            .set_max_proto_version(Some(SslVersion::TLS1_2))
            .expect("max version");
    }
    builder.set_groups_list(&groups).expect("groups");
    let mut certs = X509::stack_from_pem(&server.tls.cert_pem).expect("server certificate");
    let leaf = certs.remove(0);
    builder.set_certificate(&leaf).expect("server certificate");
    for extra in certs {
        builder.add_extra_chain_cert(extra).expect("server chain");
    }
    let key = openssl::pkey::PKey::private_key_from_pem(&server.tls.key_pem).expect("server key");
    builder.set_private_key(&key).expect("server key");
    builder.check_private_key().expect("server key matches");
    let mut store = X509StoreBuilder::new().expect("store");
    for ca in X509::stack_from_pem(client_ca.cert_pem()).expect("client CA") {
        store.add_cert(ca).expect("client CA");
    }
    builder
        .set_verify_cert_store(store.build())
        .expect("verify store");
    builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
    builder.build()
}

async fn serve_tls(
    listener: TcpListener,
    acceptor: SslAcceptor,
    inbound: asx::Inbound,
    state: Arc<State>,
) {
    while let Ok((tcp, _)) = listener.accept().await {
        let ssl = match Ssl::new(acceptor.context()) {
            Ok(ssl) => ssl,
            Err(_) => continue,
        };
        let inbound = inbound.clone();
        let state = state.clone();
        tokio::spawn(async move {
            let Ok(mut stream) = tokio_openssl::SslStream::new(ssl, tcp) else {
                return;
            };
            if Pin::new(&mut stream).accept().await.is_err() {
                return;
            }
            record(&state, stream.ssl());
            let counted = state.clone();
            let service =
                hyper::service::service_fn(move |request: http::Request<hyper::body::Incoming>| {
                    counted.requests.fetch_add(1, Ordering::SeqCst);
                    let mut inbound = inbound.clone();
                    async move { tower_service::Service::call(&mut inbound, request).await }
                });
            let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}

fn record(state: &State, ssl: &openssl::ssl::SslRef) {
    let to_cert = |x: &openssl::x509::X509Ref| {
        asx::Certificate::from_pem(&x.to_pem().expect("pem")).expect("certificate")
    };
    // Server side: the peer's chain excludes its leaf.
    let mut chain = Vec::new();
    if let Some(leaf) = ssl.peer_certificate() {
        chain.push(to_cert(&leaf));
    }
    if let Some(rest) = ssl.peer_cert_chain() {
        chain.extend(rest.iter().map(to_cert));
    }
    state.chains.lock().expect("chains").push(chain);
    state
        .server_names
        .lock()
        .expect("names")
        .push(ssl.servername(NameType::HOST_NAME).map(str::to_owned));
    state.handshakes.fetch_add(1, Ordering::SeqCst);
}

async fn serve_crls(listener: TcpListener) {
    while let Ok((tcp, _)) = listener.accept().await {
        tokio::spawn(async move {
            let service = hyper::service::service_fn(
                |request: http::Request<hyper::body::Incoming>| async move {
                    let url = format!("http://{}{}", super::pki::CRL_HOST, request.uri().path());
                    let response = match super::pki::published_crl(&url) {
                        Some(crl) => http::Response::builder()
                            .status(200)
                            .header(http::header::CONTENT_TYPE, "application/pkix-crl")
                            .body(http_body_util::Full::new(bytes::Bytes::from(crl))),
                        None => http::Response::builder()
                            .status(404)
                            .body(http_body_util::Full::new(bytes::Bytes::new())),
                    };
                    Ok::<_, std::convert::Infallible>(response.expect("response"))
                },
            );
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(tcp), service)
                .await;
        });
    }
}
