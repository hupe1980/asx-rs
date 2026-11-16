//! `Builder<C>`: collects the configuration, and `build()` validates it once
//! against the profile.

use crate::audit::AuditSink;
use crate::clock::SharedClock;
use crate::error::{Error, Result};
use crate::http_client::HttpClient;
use crate::keys::{Certificate, KeyKind};
use crate::party::{LocalParty, Partner};
use crate::profile::{PartnerPolicy, PartyTypeRule, Profile, ProfileId, Protocol, SenderRule};
use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::Arc;

/// Builder for [`as4::As4`](crate::as4::As4) and [`as2::As2`](crate::as2::As2).
/// Nothing is validated until `build()`.
#[must_use]
pub struct Builder<C> {
    profile: Profile,
    local: Option<LocalParty>,
    partners: Vec<Partner>,
    anchors: Vec<Certificate>,
    crl_signers: Vec<Certificate>,
    http: Option<Arc<dyn HttpClient>>,
    /// Operator pins for the built-in client, in the order given (a
    /// duplicate host is refused at `build()`).
    pins: Vec<(String, std::net::SocketAddr)>,
    audit: Option<Arc<dyn AuditSink>>,
    /// Always the system clock outside crate tests.
    clock: SharedClock,
    _client: PhantomData<fn() -> C>,
}

impl<C> std::fmt::Debug for Builder<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Builder")
            .field("profile", &self.profile.name())
            .field("local", &self.local)
            .field("partners", &self.partners.len())
            .field("anchors", &self.anchors.len())
            .field("crl_signers", &self.crl_signers.len())
            .field("resolve", &self.pins)
            .finish_non_exhaustive()
    }
}

impl<C> Builder<C> {
    pub(crate) fn new(profile: Profile) -> Self {
        Self {
            profile,
            local: None,
            partners: Vec::new(),
            anchors: Vec::new(),
            crl_signers: Vec::new(),
            http: None,
            pins: Vec::new(),
            audit: None,
            clock: crate::clock::system(),
            _client: PhantomData,
        }
    }

    /// Build under `clock` instead of the system clock (crate tests only).
    #[cfg(test)]
    pub(crate) fn clock(self, clock: SharedClock) -> Builder<C> {
        Builder { clock, ..self }
    }

    /// Who we are: identity, signer, decrypters, TLS identity.
    pub fn local(self, party: LocalParty) -> Builder<C> {
        Builder {
            local: Some(party),
            ..self
        }
    }

    /// Register a partner; repeat per partner. Duplicate (type, id) is refused
    /// at `build()`.
    pub fn partner(mut self, partner: Partner) -> Builder<C> {
        self.partners.push(partner);
        self
    }

    /// A certificate every signer must chain to (partners, SMP). At least one
    /// is required.
    pub fn trust_anchor(mut self, certificate: Certificate) -> Builder<C> {
        self.anchors.push(certificate);
        self
    }

    /// A certificate allowed to sign *indirect* CRLs on behalf of a CA (RFC
    /// 5280 §5.3.3), e.g. the SM-PKI CCRL-S(Root) that signs the Root-CA CRL
    /// (BSI TR-03109-4 §4.2.1). Must chain to a trust anchor and assert
    /// `cRLSign`; checked at `build()`. Repeat for several.
    pub fn crl_signer(mut self, certificate: Certificate) -> Builder<C> {
        self.crl_signers.push(certificate);
        self
    }

    /// Replace the built-in HTTP client (required when feature `http-client`
    /// is off). It also carries revocation fetches (CRLs, OCSP), which may be
    /// plain `http` (signed objects, RFC 5280 §4.2.1.13).
    pub fn http_client(self, client: impl HttpClient) -> Builder<C> {
        Builder {
            http: Some(Arc::new(client)),
            ..self
        }
    }

    /// Connect every connection of the built-in client to `host` — whatever
    /// the URL's port — to `addr`. SNI and certificate verification still use
    /// `host`. A pinned host is exempt from the private-address filter: the
    /// pin is your decision, made in code, and shown in `Debug`. Every other
    /// host stays filtered.
    ///
    /// For a partner on a private interconnect, split-horizon DNS, or an
    /// end-to-end test against a local MSH (`testkit::tls::TlsMsh`).
    /// Refused at `build()` when a host is pinned twice or when a custom
    /// [`HttpClient`] is set (the pin would configure nothing).
    pub fn resolve(mut self, host: impl Into<String>, addr: std::net::SocketAddr) -> Builder<C> {
        self.pins.push((host.into().to_ascii_lowercase(), addr));
        self
    }

    /// Write one evidence record per verified receipt or MDN, sent or
    /// received. A `Durable` sink's failure fails the exchange; a
    /// `BestEffort` sink's failure is logged and counted.
    pub fn audit(self, sink: impl AuditSink + 'static) -> Builder<C> {
        Builder {
            audit: Some(Arc::new(sink)),
            ..self
        }
    }

    /// Validate everything and resolve the partner policies.
    pub(crate) fn validate(self, protocol: Protocol) -> Result<ClientConfig> {
        validate(self, protocol)
    }
}

/// The validated configuration a client is built from.
#[derive(Debug, Clone)]
pub(crate) struct ClientConfig {
    pub(crate) profile: Profile,
    pub(crate) local: LocalParty,
    pub(crate) partners: HashMap<(Option<String>, String), PartnerPolicy>,
    pub(crate) anchors: Vec<Certificate>,
    pub(crate) http: Arc<dyn HttpClient>,
    pub(crate) audit: Option<Arc<dyn AuditSink>>,
    /// The client's only wall clock; every partner policy and
    /// internal session carries the same one.
    pub(crate) clock: SharedClock,
    /// The client's one revocation validator: the profile's rule,
    /// the HTTP client, the clock, the anchors and CRL signers.
    pub(crate) revocation: Arc<crate::revocation::Revocation>,
}

impl ClientConfig {
    /// The registered partner `(type, id)`, or the profile's unregistered
    /// policy.
    pub(crate) fn policy_for(&self, party_type: Option<&str>, id: &str) -> Option<&PartnerPolicy> {
        self.partners
            .get(&(party_type.map(str::to_owned), id.to_string()))
            .or_else(|| {
                // A registered partner whose type the sender did not repeat,
                // or vice versa: the id alone decides when it is unambiguous.
                let mut by_id = self.partners.iter().filter(|((_, pid), _)| pid == id);
                match (by_id.next(), by_id.next()) {
                    (Some((_, policy)), None) => Some(policy),
                    _ => None,
                }
            })
    }
}

fn refuse(
    profile: &Profile,
    setting: &str,
    detail: impl std::fmt::Display,
    section: &str,
) -> Error {
    if section.is_empty() {
        Error::config(format!("{setting}: {detail}"))
    } else {
        Error::config(format!("{setting}: {detail} ({})", profile.cite(section)))
    }
}

/// BDEW: the MP-ID is a 13-digit number (B Kap. 2.3.1.1).
pub(crate) fn is_mp_id(id: &str) -> bool {
    id.len() == 13 && id.bytes().all(|b| b.is_ascii_digit())
}

/// BDEW: the MP-ID is carried in the subject's OU (RzÜ AS4 2.6 Kap. 5.2: "Das
/// Feld Organisational Unit („OU") des Subject muss die MP-ID enthalten";
/// B Kap. 2.3.4.4). One OU value must equal the MP-ID exactly; a CN or a
/// substring does not count.
pub(crate) fn bdew_subject_carries(cert: &Certificate, mp_id: &str) -> bool {
    cert.subject_values().iter().any(|(nid, value)| {
        *nid == openssl::nid::Nid::ORGANIZATIONALUNITNAME && value.trim() == mp_id
    })
}

/// RzÜ AS4 2.6 Kap. 5.2: "Der Parameter im Feld „Alternativer
/// Antragstellername" mit der Ausprägung UniformResourceIdentifier muss
/// vorhanden sein und mit der Kommunikationsadresse des WebServices befüllt
/// werden. Mehrere Kommunikationsadressen in einem Zertifikat sind nicht
/// zulässig." The one URI, or why there is not exactly one.
pub(crate) fn bdew_endpoint_uri(cert: &Certificate) -> std::result::Result<String, String> {
    match cert.uri_sans().as_slice() {
        [one] => Ok(one.clone()),
        [] => Err(
            "the certificate carries no URI subjectAltName (the AS4 web-service address)".into(),
        ),
        many => Err(format!(
            "the certificate carries {} URI subjectAltNames; exactly one AS4 web-service address is allowed",
            many.len()
        )),
    }
}

/// The citation of the triple rules.
const RZUE_5_2: &str = "RzÜ AS4 2.6 Kap. 5.2";

/// Key-pair separation where the profile requires it, compared by key, not
/// by certificate: a CA can certify one key pair twice
/// (`Certificate::same_key`). BDEW AS4-Profil 1.2 Kap. 2.3.4.4: „Für die
/// Signatur, die Verschlüsselung und den Aufbau der TLS-Verbindung MÜSSEN
/// unterschiedliche Schlüsselpaare verwendet werden."
fn check_key_roles(p: &Profile, local: &LocalParty, signer: &Certificate) -> Result<()> {
    if !p.separate_keys() {
        return Ok(());
    }
    let decrypters: Vec<&Certificate> = local
        .decrypters
        .iter()
        .map(|d| d.decrypter.certificate())
        .collect();
    if decrypters.iter().any(|d| d.same_key(signer)) {
        return Err(refuse(
            p,
            "LocalParty::signer",
            "the signing key pair must differ from the decryption key pair",
            "2.3.4.4",
        ));
    }
    if let Some(tls) = &local.tls
        && (tls.leaf().same_key(signer) || decrypters.iter().any(|d| d.same_key(tls.leaf())))
    {
        return Err(refuse(
            p,
            "LocalParty::tls_identity",
            "the TLS key pair must differ from the signing and decryption key pairs",
            "2.3.4.4",
        ));
    }
    Ok(())
}

/// Every pair of decrypters must leave inbound key selection unambiguous.
/// Two certificates over one key (a renewal) act as one key, refused only
/// where the PKI forbids renewals (CP SM-PKI §4.5); one SKI over different
/// keys would name two keys. Refusals name both positions (from 1).
fn check_decrypter_pairs(p: &Profile, local: &LocalParty) -> Result<()> {
    let certs: Vec<&Certificate> = local
        .decrypters
        .iter()
        .map(|d| d.decrypter.certificate())
        .collect();
    for (i, cert) in certs.iter().enumerate() {
        for (j, earlier) in certs[..i].iter().enumerate() {
            let pair = format!("decrypters {} and {}", j + 1, i + 1);
            let serials = format!("serials {} and {}", earlier.serial_hex(), cert.serial_hex());
            let refusal = |detail: String| refuse(p, "LocalParty::decrypter", detail, "");
            if earlier == cert {
                return Err(refusal(format!(
                    "{pair} are the same certificate (serial {})",
                    cert.serial_hex()
                )));
            }
            if earlier.same_key(cert) {
                if p.renewals_allowed() {
                    continue;
                }
                return Err(refusal(format!(
                    "{pair} ({serials}) certify one key; a key certified twice is a renewal, \
                     which the PKI forbids (CP SM-PKI §4.5)"
                )));
            }
            let earlier_skis = earlier.ski_candidates();
            if cert
                .ski_candidates()
                .iter()
                .any(|s| earlier_skis.contains(s))
            {
                return Err(refusal(format!(
                    "{pair} ({serials}) certify different keys under one key identifier \
                     (an SKI reference would be ambiguous)"
                )));
            }
        }
    }
    Ok(())
}

/// Both rules of RzÜ AS4 2.6 Kap. 5.2 for one certificate of `mp_id`'s
/// triple: the MP-ID in the subject's OU and exactly one URI SAN.
fn check_bdew_triple_cert(
    profile: &Profile,
    setting: &str,
    cert: &Certificate,
    mp_id: &str,
) -> Result<()> {
    if !bdew_subject_carries(cert, mp_id) {
        return Err(refuse(
            profile,
            setting,
            format!("the certificate subject (OU) does not carry the MP-ID {mp_id} ({RZUE_5_2})"),
            "2.3.4.4",
        ));
    }
    bdew_endpoint_uri(cert)
        .map(|_| ())
        .map_err(|detail| refuse(profile, setting, format!("{detail} ({RZUE_5_2})"), ""))
}

/// An endpoint URL in comparable form (RFC 3986 §6.2.2–6.2.3): scheme and
/// host lowercased, the default port dropped, an empty path as `/`.
pub(crate) fn normalize_endpoint(url: &str) -> Option<String> {
    let uri: http::Uri = url.parse().ok()?;
    let scheme = uri.scheme_str()?.to_ascii_lowercase();
    let host = uri.host()?.to_ascii_lowercase();
    let port = match (scheme.as_str(), uri.port_u16()) {
        ("https", Some(443)) | ("http", Some(80)) | (_, None) => String::new(),
        (_, Some(port)) => format!(":{port}"),
    };
    let path = uri.path_and_query().map_or("/", |pq| pq.as_str());
    let path = if path.is_empty() { "/" } else { path };
    Some(format!("{scheme}://{host}{port}{path}"))
}

/// RFC 4130 §6.2: AS2 identifiers are 1–128 printable ASCII characters.
pub(crate) fn is_as2_id(id: &str) -> bool {
    (1..=128).contains(&id.len()) && id.bytes().all(|b| (0x20..0x7f).contains(&b))
}

/// Partner endpoints: an absolute `https` URL without userinfo.
pub(crate) fn check_endpoint(url: &str) -> std::result::Result<(), String> {
    let parsed: http::Uri = url.parse().map_err(|_| format!("{url:?} is not a URL"))?;
    if parsed.scheme_str() != Some("https") {
        return Err(format!("{url:?} is not https"));
    }
    let Some(authority) = parsed.authority() else {
        return Err(format!("{url:?} has no host"));
    };
    if authority.as_str().contains('@') {
        return Err(format!("{url:?} carries userinfo"));
    }
    if authority.host().is_empty() {
        return Err(format!("{url:?} has no host"));
    }
    Ok(())
}

/// Whether `leaf` (with `intermediates`) chains to one of `anchors` at `now`.
pub(crate) fn chains_to(
    leaf: &Certificate,
    intermediates: &[Certificate],
    anchors: &[Certificate],
    now: std::time::SystemTime,
) -> bool {
    use openssl::stack::Stack;
    use openssl::x509::store::X509StoreBuilder;
    use openssl::x509::verify::X509VerifyParam;
    use openssl::x509::{X509, X509StoreContext};
    let Ok(mut store) = X509StoreBuilder::new() else {
        return false;
    };
    let Ok(mut param) = X509VerifyParam::new() else {
        return false;
    };
    param.set_time(crate::time_utils::unix_secs(now) as _);
    if store.set_param(&param).is_err() {
        return false;
    }
    for anchor in anchors {
        if store.add_cert(anchor.x509().clone()).is_err() {
            return false;
        }
    }
    let store = store.build();
    let Ok(mut chain) = Stack::<X509>::new() else {
        return false;
    };
    for cert in intermediates {
        if chain.push(cert.x509().clone()).is_err() {
            return false;
        }
    }
    let Ok(mut ctx) = X509StoreContext::new() else {
        return false;
    };
    ctx.init(&store, leaf.x509(), &chain, |c| c.verify_cert())
        .unwrap_or(false)
}

/// BDEW: the partner's triple (RzÜ AS4 2.6 Kap. 5.2) and its endpoint
/// (Kap. 2: taken from the certificate; Kap. 3: SNI needs a DNS name).
fn check_bdew_partner(profile: &Profile, partner: &Partner) -> Result<()> {
    let id = partner.id();
    let setting = |what: &str| format!("Partner({id})::{what}");
    for cert in partner.signing_certs() {
        bdew_endpoint_uri(cert).map_err(|detail| {
            refuse(
                profile,
                &setting("signing_cert"),
                format!("{detail} ({RZUE_5_2})"),
                "",
            )
        })?;
    }
    let Some(enc) = partner.encryption_certificate() else {
        return Ok(());
    };
    check_bdew_triple_cert(profile, &setting("encryption_cert"), enc, id)?;
    // Kap. 2.3.4.4 binds the partner's key pairs too: never encrypt to a key
    // its holder also signs with.
    if profile.separate_keys() && partner.signing_certs().iter().any(|c| c.same_key(enc)) {
        return Err(refuse(
            profile,
            &setting("signing_cert"),
            "the signing key pair must differ from the encryption key pair",
            "2.3.4.4",
        ));
    }
    let san = bdew_endpoint_uri(enc).unwrap_or_default();
    let endpoint = partner.endpoint_url().unwrap_or(&san);
    if let Some(url) = partner.endpoint_url()
        && normalize_endpoint(url) != normalize_endpoint(&san)
    {
        return Err(refuse(
            profile,
            &setting("endpoint"),
            format!(
                "{url:?} is not the AS4 address its encryption certificate names ({san:?}); \
                 the endpoint is taken from the certificate (RzÜ AS4 2.6 Kap. 2)"
            ),
            "",
        ));
    }
    let host = endpoint
        .parse::<http::Uri>()
        .ok()
        .and_then(|u| u.host().map(|h| h.trim_matches(['[', ']']).to_owned()))
        .unwrap_or_default();
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Err(refuse(
            profile,
            &setting("endpoint"),
            format!(
                "{endpoint:?} names an IP address; TLS needs a DNS name for SNI \
                 (RzÜ AS4 2.6 Kap. 3, RFC 6066 §3)"
            ),
            "",
        ));
    }
    check_endpoint(endpoint).map_err(|d| refuse(profile, &setting("endpoint"), d, ""))
}

/// Check one partner against the profile. Shared with
/// `send` for unregistered partners.
pub(crate) fn check_partner(
    profile: &Profile,
    partner: &Partner,
    registered: bool,
    now: std::time::SystemTime,
) -> Result<()> {
    let id = partner.id();
    let setting = |what: &str| format!("Partner({id})::{what}");
    if let Some(url) = partner.endpoint_url() {
        check_endpoint(url).map_err(|d| refuse(profile, &setting("endpoint"), d, ""))?;
        // Under BDEW a partner may be reached for the payload-less
        // path-switch service alone (B Kap. 2.3.2 dynamic P-Mode, 2.3.7): `send`
        // refuses a business message to it.
        if partner.encryption_certificate().is_none() && !profile.path_switch() {
            return Err(refuse(
                profile,
                &setting("encryption_cert"),
                "a partner with an endpoint needs an encryption certificate (every profile encrypts)",
                "",
            ));
        }
    }
    if registered
        && profile.sender_rule() == SenderRule::RegisteredOnly
        && partner.signing_certs().is_empty()
    {
        return Err(refuse(
            profile,
            &setting("signing_cert"),
            "a registered partner needs a pinned signing certificate (configured partners only)",
            "",
        ));
    }
    for cert in partner.signing_certs() {
        let kind = cert.key_kind();
        if !profile.signer_keys().allows(kind) {
            return Err(refuse(
                profile,
                &setting("signing_cert"),
                format!(
                    "{} key not allowed, the profile requires {}",
                    kind.describe(),
                    profile.signer_keys().describe()
                ),
                signature_section(profile),
            ));
        }
        if !cert.is_valid_at(now) {
            return Err(refuse(
                profile,
                &setting("signing_cert"),
                "the certificate is expired or not yet valid",
                "",
            ));
        }
        match profile.sender_rule() {
            SenderRule::AnchorAndSubject if !bdew_subject_carries(cert, id) => {
                return Err(refuse(
                    profile,
                    &setting("signing_cert"),
                    format!("the certificate subject (OU) does not carry the MP-ID {id}"),
                    "2.3.4.4",
                ));
            }
            SenderRule::AnchorAndCn if cert.subject_cn().as_deref() != Some(id) => {
                return Err(refuse(
                    profile,
                    &setting("signing_cert"),
                    format!("the certificate CN is not the party id {id}"),
                    "4.5",
                ));
            }
            _ => {}
        }
    }
    if profile.sender_rule() == SenderRule::AnchorAndSubject {
        check_bdew_partner(profile, partner)?;
    }
    if let Some(cert) = partner.encryption_certificate() {
        let kind = cert.key_kind();
        if !encryption_allowed(profile, kind) {
            return Err(refuse(
                profile,
                &setting("encryption_cert"),
                format!(
                    "{} key not allowed, the profile requires {}",
                    kind.describe(),
                    profile.decrypter_keys().describe()
                ),
                encryption_section(profile),
            ));
        }
        if !cert.is_valid_at(now) {
            return Err(refuse(
                profile,
                &setting("encryption_cert"),
                "the certificate is expired or not yet valid",
                "",
            ));
        }
    }
    for quirk in partner.quirks() {
        if quirk.protocol() != profile.protocol() {
            return Err(refuse(
                profile,
                &setting("quirk"),
                format!("{quirk:?} belongs to the other protocol"),
                "",
            ));
        }
    }
    check_party_type(profile, &setting("party_type"), partner.type_ref())?;
    if profile.protocol() == Protocol::As2 && !is_as2_id(id) {
        return Err(refuse(
            profile,
            &setting("id"),
            "an AS2 identifier is 1-128 printable ASCII characters",
            "6.2",
        ));
    }
    Ok(())
}

fn encryption_allowed(profile: &Profile, kind: KeyKind) -> bool {
    // AS2 encrypts with RSA (CMS key transport).
    profile.decrypter_keys().allows(kind)
}

fn signature_section(profile: &Profile) -> &'static str {
    match profile.id() {
        ProfileId::Bdew12 => "2.2.6.2.1",
        ProfileId::Peppol203 => "3",
        ProfileId::Edelivery115 => "3.2.6",
        ProfileId::Entsog36 => "2.2.6.2",
        ProfileId::As2 => "2.4",
    }
}

fn encryption_section(profile: &Profile) -> &'static str {
    match profile.id() {
        ProfileId::Bdew12 => "2.2.6.2.2",
        ProfileId::Peppol203 => "3",
        ProfileId::Edelivery115 => "3.2.6",
        ProfileId::Entsog36 => "2.2.6.3",
        ProfileId::As2 => "2.4",
    }
}

fn check_party_type(profile: &Profile, setting: &str, party_type: Option<&str>) -> Result<()> {
    match profile.party_types() {
        PartyTypeRule::OneOf(allowed) => match party_type {
            Some(t) if allowed.contains(&t) => Ok(()),
            Some(t) => Err(refuse(
                profile,
                setting,
                format!("{t:?} is not one of {allowed:?}"),
                "2.3.1.1",
            )),
            None => Err(refuse(
                profile,
                setting,
                format!("a party type is required, one of {allowed:?}"),
                "2.3.1.1",
            )),
        },
        PartyTypeRule::Fixed(fixed) => match party_type {
            None => Ok(()),
            Some(_) => Err(refuse(
                profile,
                setting,
                format!("the profile fixes the party type to {fixed:?}; do not set it"),
                "4.5",
            )),
        },
        PartyTypeRule::CallerSet => Ok(()),
    }
}

fn validate<C>(builder: Builder<C>, protocol: Protocol) -> Result<ClientConfig> {
    let Builder {
        profile,
        local,
        partners,
        anchors,
        crl_signers,
        http,
        pins,
        audit,
        clock,
        ..
    } = builder;
    let p = &profile;
    // One reading for the whole validation.
    let now = clock.now();

    if profile.protocol() != protocol {
        return Err(refuse(
            p,
            "Profile",
            format!(
                "{} is a {:?} profile; use the {:?} client",
                profile.name(),
                profile.protocol(),
                profile.protocol()
            ),
            "",
        ));
    }
    if let Some(requested) = profile.requested_max()
        && (requested == 0 || requested > profile.ceiling())
    {
        return Err(refuse(
            p,
            "Profile::max_message_bytes",
            format!(
                "{requested} is outside 1..={} (tighten-only, never clamped)",
                profile.ceiling()
            ),
            "",
        ));
    }
    let Some(local) = local else {
        return Err(refuse(p, "Builder::local", "no LocalParty configured", ""));
    };
    let signer = match local.signers.as_slice() {
        [one] => one,
        [] => return Err(refuse(p, "LocalParty::signer", "no signer configured", "")),
        _ => {
            return Err(refuse(
                p,
                "LocalParty::signer",
                "exactly one signer is allowed",
                "",
            ));
        }
    };
    if local.decrypters.is_empty() {
        return Err(refuse(
            p,
            "LocalParty::decrypter",
            "no decrypter configured (every profile encrypts inbound)",
            encryption_section(p),
        ));
    }
    let chain = signer.signer.certificate_chain();
    let Some(signer_leaf) = chain.first() else {
        return Err(refuse(
            p,
            "LocalParty::signer",
            "the signer's certificate chain is empty",
            "",
        ));
    };
    if !signer_leaf.is_valid_at(now) {
        return Err(refuse(
            p,
            "LocalParty::signer",
            "the signing certificate is expired or not yet valid",
            "",
        ));
    }
    let kind = signer_leaf.key_kind();
    if !p.signer_keys().allows(kind) {
        return Err(refuse(
            p,
            "LocalParty::signer",
            format!(
                "{} key not allowed, the profile requires {}",
                kind.describe(),
                p.signer_keys().describe()
            ),
            signature_section(p),
        ));
    }
    for decrypter in &local.decrypters {
        let cert = decrypter.decrypter.certificate();
        let kind = cert.key_kind();
        if !encryption_allowed(p, kind) {
            return Err(refuse(
                p,
                "LocalParty::decrypter",
                format!(
                    "{} key not allowed, the profile requires {}",
                    kind.describe(),
                    p.decrypter_keys().describe()
                ),
                encryption_section(p),
            ));
        }
    }
    check_decrypter_pairs(p, &local)?;
    if let Some(tls) = &local.tls
        && p.separate_keys()
        && !matches!(tls.key_kind(), KeyKind::Ec { .. })
    {
        // BDEW AS4-Profil 1.2 Kap. 2.3.4.4: "Die Schlüsselpaare MÜSSEN
        // EC-basiert sein" — the TLS pair too.
        return Err(refuse(
            p,
            "LocalParty::tls_identity",
            format!(
                "{} key not allowed, the TLS key pair must be EC",
                tls.key_kind().describe()
            ),
            "2.3.4.4",
        ));
    }
    check_key_roles(p, &local, signer_leaf)?;
    if p.sender_rule() == SenderRule::AnchorAndSubject {
        check_bdew_triple_cert(p, "LocalParty::signer", signer_leaf, &local.id)?;
        for decrypter in &local.decrypters {
            check_bdew_triple_cert(
                p,
                "LocalParty::decrypter",
                decrypter.decrypter.certificate(),
                &local.id,
            )?;
        }
        if let Some(tls) = &local.tls {
            check_bdew_triple_cert(p, "LocalParty::tls_identity", tls.leaf(), &local.id)?;
        }
    }
    if p.id() == ProfileId::Bdew12 && !is_mp_id(&local.id) {
        return Err(refuse(
            p,
            "LocalParty::new",
            format!("{:?} is not a 13-digit MP-ID", local.id),
            "2.3.1.1",
        ));
    }
    if protocol == Protocol::As2 && !is_as2_id(&local.id) {
        return Err(refuse(
            p,
            "LocalParty::new",
            "an AS2 identifier is 1-128 printable ASCII characters",
            "6.2",
        ));
    }
    check_party_type(p, "LocalParty::party_type", local.party_type.as_deref())?;
    if anchors.is_empty() {
        return Err(refuse(
            p,
            "Builder::trust_anchor",
            "at least one trust anchor is required",
            "",
        ));
    }
    if !chains_to(signer_leaf, &chain[1..], &anchors, now) {
        return Err(refuse(
            p,
            "LocalParty::signer",
            "the signing certificate does not chain to a configured trust anchor",
            "",
        ));
    }
    let mut resolved = HashMap::new();
    for partner in &partners {
        check_partner(p, partner, true, now)?;
        if partner.id() == local.id {
            return Err(refuse(
                p,
                &format!("Partner({})", partner.id()),
                "a partner cannot have the local party's id",
                "",
            ));
        }
        let key = partner.key();
        if resolved.contains_key(&key) {
            return Err(refuse(
                p,
                &format!("Partner({})", partner.id()),
                "registered twice with the same (type, id)",
                "",
            ));
        }
        resolved.insert(key, crate::profile::resolve(p, partner, &clock));
    }
    check_crl_signers(p, &crl_signers, &anchors, now)?;
    let pins = check_pins(p, pins, http.is_some())?;
    let (http, builtin) = match http {
        Some(http) => (http, None),
        None => default_http(p, &local, &anchors, pins)?,
    };
    let revocation = Arc::new(crate::revocation::Revocation::new(
        profile.revocation(),
        http.clone(),
        clock.clone(),
        anchors.iter().map(|a| a.x509().clone()).collect(),
        crl_signers.iter().map(|c| c.x509().clone()).collect(),
        None,
    ));
    wire_revocation(builtin, &revocation);
    Ok(ClientConfig {
        profile,
        local,
        partners: resolved,
        anchors,
        http,
        audit,
        clock,
        revocation,
    })
}

/// An indirect-CRL signer chains to a trust anchor, asserts `cRLSign`,
/// is not itself an anchor and is not repeated.
fn check_crl_signers(
    profile: &Profile,
    signers: &[Certificate],
    anchors: &[Certificate],
    now: std::time::SystemTime,
) -> Result<()> {
    let refuse_signer = |detail: &str| refuse(profile, "Builder::crl_signer", detail, "");
    for (i, signer) in signers.iter().enumerate() {
        if signers[..i].contains(signer) {
            return Err(refuse_signer("the same CRL signer is configured twice"));
        }
        if anchors.contains(signer) {
            return Err(refuse_signer(
                "a trust anchor cannot be a CRL signer (supply the CCRL-S certificate)",
            ));
        }
        if !signer.has_crl_sign() {
            return Err(refuse_signer(
                "the certificate's keyUsage does not assert cRLSign",
            ));
        }
        if !chains_to(signer, &[], anchors, now) {
            return Err(refuse_signer(
                "the CRL signer does not chain to a configured trust anchor",
            ));
        }
    }
    Ok(())
}

/// An internal session: the client's anchors, the partner's pins and
/// encryption certificate. (Revocation is the client's
/// [`ClientConfig::revocation`], not the session's.)
pub(crate) fn base_session(
    config: &ClientConfig,
    partner_id: &str,
    pins: Vec<crate::crypto::CertFingerprint>,
    encryption_cert: Option<&Certificate>,
    signing_certs: &[Certificate],
) -> Result<crate::core::SessionContext> {
    let mut builder = crate::core::SessionContextBuilder::new(config.local.id.clone(), partner_id)
        .profile_name(config.profile.name());
    for anchor in &config.anchors {
        builder = builder.with_trust_anchor_pem(anchor.pem());
    }
    if let Some(cert) = encryption_cert {
        builder = builder.with_recipient_cert_pem(cert.pem());
    }
    // AS2 verifies CMS with PKCS7_NOINTERN: the signer's leaf is supplied out
    // of band, never taken from the message.
    for cert in signing_certs {
        builder = builder.with_intermediate_ca_pem(cert.pem());
    }
    let session = builder.build().map_err(Error::internal)?;
    Ok(session.with_profile_metadata(pins, config.clock.clone()))
}

/// The validated pins: lowercased, non-empty, unique, and only with the
/// built-in client.
fn check_pins(
    profile: &Profile,
    pins: Vec<(String, std::net::SocketAddr)>,
    custom_http: bool,
) -> Result<HashMap<String, std::net::SocketAddr>> {
    let refuse_pin = |detail: String| refuse(profile, "Builder::resolve", detail, "");
    if custom_http && !pins.is_empty() {
        return Err(refuse_pin(
            "pins apply to the built-in HTTP client only; a custom HttpClient resolves itself"
                .into(),
        ));
    }
    let mut out = HashMap::new();
    for (host, addr) in pins {
        if host.is_empty() || host.contains(['/', ':', '@', ' ']) {
            return Err(refuse_pin(format!("{host:?} is not a host name")));
        }
        if out.insert(host.clone(), addr).is_some() {
            return Err(refuse_pin(format!("{host:?} is pinned twice")));
        }
    }
    Ok(out)
}

/// The built-in client, when it is the one in use: its TLS policy comes from
/// the profile, never from the peer (D92).
#[cfg(feature = "http-client")]
type Builtin = Option<crate::http_client::BuiltinClient>;
#[cfg(not(feature = "http-client"))]
type Builtin = Option<std::convert::Infallible>;

#[cfg(feature = "http-client")]
fn default_http(
    profile: &Profile,
    local: &LocalParty,
    anchors: &[Certificate],
    pins: HashMap<String, std::net::SocketAddr>,
) -> Result<(Arc<dyn HttpClient>, Builtin)> {
    use crate::transport::tls::TlsPolicy;
    let bdew = profile.id() == ProfileId::Bdew12;
    // BDEW AS4-Profil 1.2 Kap. 2.2.6.1: "Client-Authentifizierung ist
    // ERFORDERLICH."
    if bdew && local.tls.is_none() {
        return Err(refuse(
            profile,
            "LocalParty::tls_identity",
            "the built-in client needs a TLS identity: client authentication is required",
            "2.2.6.1",
        ));
    }
    let policy = if bdew {
        TlsPolicy::Bdew {
            anchors: anchors.to_vec(),
        }
    } else {
        TlsPolicy::Platform
    };
    let client = crate::http_client::BuiltinClient::new(policy, local.tls.as_ref(), Arc::new(pins))
        .map_err(|detail| refuse(profile, "LocalParty::tls_identity", detail, ""))?;
    Ok((Arc::new(client.clone()), Some(client)))
}

#[cfg(not(feature = "http-client"))]
fn default_http(
    profile: &Profile,
    _local: &LocalParty,
    _anchors: &[Certificate],
    _pins: HashMap<String, std::net::SocketAddr>,
) -> Result<(Arc<dyn HttpClient>, Builtin)> {
    Err(refuse(
        profile,
        "Builder::http_client",
        "no HTTP client: enable feature `http-client` or supply one",
        "",
    ))
}

#[cfg(feature = "http-client")]
fn wire_revocation(builtin: Builtin, revocation: &Arc<crate::revocation::Revocation>) {
    if let Some(client) = builtin {
        client.set_revocation(Arc::downgrade(revocation));
    }
}

#[cfg(not(feature = "http-client"))]
fn wire_revocation(_builtin: Builtin, _revocation: &Arc<crate::revocation::Revocation>) {}

#[cfg(feature = "as4")]
impl Builder<crate::as4::As4> {
    /// Validate the configuration against the profile and build the client.
    /// Every refusal is [`ErrorKind::Config`](crate::ErrorKind::Config),
    /// naming the setting and the profile section.
    pub fn build(self) -> Result<crate::as4::As4> {
        let config = self.validate(Protocol::As4)?;
        crate::as4::As4::from_config(config)
    }
}

#[cfg(feature = "as2")]
impl Builder<crate::as2::As2> {
    /// Validate the configuration against the profile and build the client.
    /// Every refusal is [`ErrorKind::Config`](crate::ErrorKind::Config),
    /// naming the setting and the profile section.
    pub fn build(self) -> Result<crate::as2::As2> {
        let config = self.validate(Protocol::As2)?;
        crate::as2::As2::from_config(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_rules() {
        assert!(check_endpoint("https://as4.example.org/msh").is_ok());
        assert!(check_endpoint("http://as4.example.org/msh").is_err());
        assert!(check_endpoint("https://user:pw@as4.example.org/msh").is_err());
        assert!(check_endpoint("not a url").is_err());
    }

    #[test]
    fn mp_id_and_as2_id() {
        assert!(is_mp_id("9900000000001"));
        assert!(!is_mp_id("990000000000"));
        assert!(!is_mp_id("99000000000x1"));
        assert!(is_as2_id("OURAS2ID"));
        assert!(!is_as2_id(""));
        assert!(!is_as2_id("a\nb"));
        assert!(!is_as2_id(&"a".repeat(129)));
    }

    /// The clock travels with the resolved
    /// configuration; a built client reads the system clock.
    #[cfg(feature = "as2")]
    mod clock {
        use super::*;
        use crate::as2::As2;
        use crate::clock::{ManualClock, SharedClock};
        use crate::keys::KeyPair;
        use std::time::Duration;

        #[derive(Debug)]
        struct NoHttp;
        impl HttpClient for NoHttp {
            fn send(
                &self,
                _request: http::Request<bytes::Bytes>,
            ) -> crate::BoxFuture<
                '_,
                std::result::Result<
                    http::Response<bytes::Bytes>,
                    Box<dyn std::error::Error + Send + Sync>,
                >,
            > {
                Box::pin(async { Err("no network in this test".into()) })
            }
        }

        const YEAR: Duration = Duration::from_secs(400 * 24 * 3600);

        /// A valid AS2 configuration: certificates valid for a year from now.
        fn builder() -> Builder<As2> {
            let (local_cert, local_key) = crate::test_support::self_signed_rsa("LOCALAS2");
            let (partner_cert, _) = crate::test_support::self_signed_rsa("PARTNERAS2");
            let pair = || KeyPair::from_pem(&local_cert, &local_key).unwrap();
            let partner_cert = Certificate::from_pem(&partner_cert).unwrap();
            As2::builder(Profile::as2())
                .local(LocalParty::new("LOCALAS2").signer(pair()).decrypter(pair()))
                .trust_anchor(Certificate::from_pem(&local_cert).unwrap())
                .trust_anchor(partner_cert.clone())
                .partner(
                    Partner::new("PARTNERAS2")
                        .endpoint("https://as2.example.org/in")
                        .signing_cert(partner_cert.clone())
                        .encryption_cert(partner_cert),
                )
                .http_client(NoHttp)
        }

        fn same(a: &SharedClock, b: &SharedClock) -> bool {
            Arc::ptr_eq(a, b)
        }

        #[test]
        fn a_built_client_carries_the_system_clock() {
            let client = builder().build().unwrap();
            let config = client.config();
            let system = crate::clock::system();
            assert!(same(&config.clock, &system));
            assert!(!config.partners.is_empty());
            for policy in config.partners.values() {
                assert!(same(&policy.clock, &system));
            }
            for session in client.0.sessions.values() {
                assert!(same(session.clock(), &system));
            }
        }

        #[test]
        fn a_test_clock_reaches_every_policy_and_session() {
            let manual: SharedClock =
                ManualClock::at(crate::clock::system().now() + Duration::from_secs(5));
            let client = builder().clock(manual.clone()).build().unwrap();
            let config = client.config();
            assert!(same(&config.clock, &manual));
            for policy in config.partners.values() {
                assert!(same(&policy.clock, &manual));
            }
            for session in client.0.sessions.values() {
                assert!(same(session.clock(), &manual));
            }
        }

        #[test]
        fn build_reads_certificate_validity_from_the_clock() {
            let later = ManualClock::at(crate::clock::system().now() + YEAR);
            let err = builder().clock(later).build().unwrap_err();
            assert_eq!(err.kind(), crate::ErrorKind::Config);
            assert!(
                err.to_string().contains("expired or not yet valid"),
                "{err}"
            );

            let earlier =
                ManualClock::at(crate::clock::system().now() - Duration::from_secs(48 * 3600));
            let err = builder().clock(earlier).build().unwrap_err();
            assert!(
                err.to_string().contains("expired or not yet valid"),
                "{err}"
            );
        }

        #[test]
        fn validity_at_use_reads_the_policy_clock() {
            // The test certificates are valid from "now" at second
            // resolution, issued after this reading: start a little later so
            // a second boundary in between cannot make them not yet valid.
            let manual = ManualClock::at(crate::clock::system().now() + Duration::from_secs(5));
            let client = builder().clock(manual.clone()).build().unwrap();
            let config = client.config();
            let policy = config.partners.values().next().unwrap();
            crate::as2::client::check_validity_at_use(config, policy).unwrap();
            manual.advance(YEAR);
            let err = crate::as2::client::check_validity_at_use(config, policy).unwrap_err();
            assert_eq!(err.kind(), crate::ErrorKind::Config);
        }
    }
}
