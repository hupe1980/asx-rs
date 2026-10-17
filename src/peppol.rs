//! Peppol network rules that sit above a single protocol: participant
//! discovery ([`Smp`](crate::peppol::Smp), BDXL on the OpenPeppol SML) and the "not serviced here"
//! handler answer ([`not_serviced`](crate::peppol::not_serviced)). The wire is [`crate::as4`] under
//! [`crate::Profile::peppol`].

/// The Peppol participant identifier scheme, used everywhere a party is named.
///
/// ISO 6523 ICD-qualified identifiers, e.g. `0088:5790002590993` for a trading
/// participant or `0242:987654` for a Service Provider.
pub(crate) const PEPPOL_PARTICIPANT_SCHEME: &str = "iso6523-actorid-upis";

// Crate-private.
#[allow(unreachable_pub, dead_code)]
pub(crate) mod mls;

#[cfg(feature = "peppol")]
use crate::error::{Error, Result, Stage};
#[cfg(feature = "peppol")]
use crate::http_client::HttpClient;
#[cfg(feature = "peppol")]
use crate::keys::Certificate;
#[cfg(feature = "peppol")]
use crate::party::Partner;
#[cfg(feature = "peppol")]
use std::sync::Arc;

#[cfg(feature = "peppol")]
/// SMP lookup through BDXL on the OpenPeppol SML, over the given
/// [`HttpClient`]. The SMP's signature must chain to the trust anchor.
#[derive(Debug, Clone)]
pub struct Smp {
    zone: &'static str,
    http: Arc<dyn HttpClient>,
    anchors: Vec<Certificate>,
    static_smp: Option<String>,
    resolver: Option<Arc<dyn crate::smp::bdxl::BdxlResolver>>,
    /// The SMP signer's revocation, over `http`.
    revocation: Arc<crate::revocation::Revocation>,
}

#[cfg(feature = "peppol")]
impl Smp {
    /// The production SML.
    pub fn production(http: impl HttpClient, smp_trust_anchor: Certificate) -> Smp {
        Self::new(
            crate::smp::PEPPOL_PRODUCTION_SML_ZONE,
            http,
            smp_trust_anchor,
        )
    }

    /// The test SML.
    pub fn test(http: impl HttpClient, smp_trust_anchor: Certificate) -> Smp {
        Self::new(crate::smp::PEPPOL_TEST_SML_ZONE, http, smp_trust_anchor)
    }

    fn new(zone: &'static str, http: impl HttpClient, anchor: Certificate) -> Smp {
        let http: Arc<dyn HttpClient> = Arc::new(http);
        let anchors = vec![anchor];
        Smp {
            zone,
            revocation: Self::revocation(&http, &anchors),
            http,
            anchors,
            static_smp: None,
            resolver: None,
        }
    }

    /// The SMP signer rule: CRL-DP then OCSP; revoked refuses, a status
    /// that cannot be obtained is accepted with a WARN.
    fn revocation(
        http: &Arc<dyn HttpClient>,
        anchors: &[Certificate],
    ) -> Arc<crate::revocation::Revocation> {
        Arc::new(crate::revocation::Revocation::new(
            crate::revocation::RevocationRule::smp(),
            http.clone(),
            crate::clock::system(),
            anchors.iter().map(|a| a.x509().clone()).collect(),
            Vec::new(),
            None,
        ))
    }

    /// Test hook: skip BDXL and query this SMP base URL.
    #[doc(hidden)]
    pub fn __with_static_smp(mut self, base_url: &str) -> Smp {
        self.static_smp = Some(base_url.to_string());
        self
    }

    /// Test hook: an intermediate CA the SMP signer chains through.
    #[doc(hidden)]
    pub fn __with_intermediate(mut self, certificate: Certificate) -> Smp {
        self.anchors.push(certificate);
        self.revocation = Self::revocation(&self.http, &self.anchors);
        self
    }

    /// `participant` / `document_type` / `process` are `scheme::value`
    /// identifiers (Peppol Policy for use of identifiers 4.4.0). Returns a
    /// `Partner` carrying endpoint, AP certificate (signing and encryption)
    /// and party id = certificate CN, type
    /// `urn:fdc:peppol.eu:2017:identifiers:ap` (Peppol AS4 §4.5).
    pub async fn lookup(
        &self,
        participant: &str,
        document_type: &str,
        process: &str,
    ) -> Result<Partner> {
        let value = |id: &str| id.split_once("::").map_or(id, |(_, v)| v).to_string();
        let mut config = match &self.static_smp {
            Some(url) => crate::smp::SmpConfig::with_static_smp(url.clone()),
            None => crate::smp::SmpConfig {
                sml_zone: self.zone.to_string(),
                ..crate::smp::SmpConfig::peppol_production()
            },
        };
        let anchors = crate::crypto::wssec::OwnedChainPolicy::production(
            self.anchors.iter().map(Certificate::pem).collect(),
        );
        config.signature_policy = crate::smp::SmpSignaturePolicy::Verify(Box::new(anchors));
        let mut client = crate::smp::SmpClient::with_config(config);
        if let Some(resolver) = &self.resolver {
            client = client.with_resolver(resolver.clone());
        } else if self.static_smp.is_none() {
            let resolver = crate::smp::bdxl::HickoryBdxlResolver::from_system_config()
                .map_err(|e| Error::from_internal(Stage::SmpLookup, e))?;
            client = client.with_resolver(Arc::new(resolver));
        }
        let request = crate::smp::SmpLookupRequest::new(
            value(participant),
            value(document_type),
            value(process),
        );
        let endpoint = client
            .lookup_endpoint_with(request, self.http.as_ref())
            .await
            .map_err(|e| Error::from_internal(Stage::SmpLookup, e))?;
        let outcome = self.revocation.check(&endpoint.signer_path).await;
        if outcome.refused() {
            return Err(Error::new(
                crate::ErrorKind::Rejected,
                format!("the SMP signer: {}", outcome.describe()),
            ));
        }
        let der = endpoint
            .certificate_der_b64
            .as_deref()
            .and_then(|b64| {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD
                    .decode(b64.split_whitespace().collect::<String>())
                    .ok()
            })
            .ok_or_else(|| {
                Error::new(
                    crate::ErrorKind::Rejected,
                    "the SMP endpoint carries no access point certificate",
                )
            })?;
        let certificate = Certificate::from_der(&der)?;
        let cn = certificate.subject_cn().ok_or_else(|| {
            Error::new(
                crate::ErrorKind::Rejected,
                "the access point certificate has no single CN (Peppol AS4 §4.5)",
            )
        })?;
        Ok(Partner::new(cn)
            .endpoint(endpoint.url)
            .signing_cert(certificate.clone())
            .encryption_cert(certificate))
    }
}

#[cfg(feature = "peppol")]
/// The handler answer "receiver not serviced here": EBMS:0004 with
/// `PEPPOL:NOT_SERVICED` (Peppol AS4 §4.4).
pub fn not_serviced() -> crate::Reject {
    crate::Reject::with_fault(crate::inbound::Fault::NotServiced)
}
