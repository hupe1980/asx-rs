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
        Error::config(format!(
            "{setting}: {detail} ({} {section})",
            profile.citation()
        ))
    }
}

/// BDEW: the MP-ID is a 13-digit number (B §2.3.1.1).
pub(crate) fn is_mp_id(id: &str) -> bool {
    id.len() == 13 && id.bytes().all(|b| b.is_ascii_digit())
}

/// BDEW: the MP-ID is carried in the subject's OU (RzÜ AS4 2.6 §5.2: "Das
/// Feld Organisational Unit („OU") des Subject muss die MP-ID enthalten";
/// B §2.3.4.4). One OU value must equal the MP-ID exactly; a CN or a
/// substring does not count.
pub(crate) fn bdew_subject_carries(cert: &Certificate, mp_id: &str) -> bool {
    cert.subject_values().iter().any(|(nid, value)| {
        *nid == openssl::nid::Nid::ORGANIZATIONALUNITNAME && value.trim() == mp_id
    })
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
        // path-switch service alone (B §2.3.2 dynamic P-Mode, §2.3.7): `send`
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
                    "§2.3.4.4",
                ));
            }
            SenderRule::AnchorAndCn if cert.subject_cn().as_deref() != Some(id) => {
                return Err(refuse(
                    profile,
                    &setting("signing_cert"),
                    format!("the certificate CN is not the party id {id}"),
                    "§4.5",
                ));
            }
            _ => {}
        }
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
            "§6.2",
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
        ProfileId::Bdew12 => "§2.2.6.2.1",
        ProfileId::Peppol203 => "§3",
        ProfileId::Edelivery115 => "§3.2.6",
        ProfileId::Entsog36 => "§2.2.6.2",
        ProfileId::As2 => "§2.4",
    }
}

fn encryption_section(profile: &Profile) -> &'static str {
    match profile.id() {
        ProfileId::Bdew12 => "§2.2.6.2.2",
        ProfileId::Peppol203 => "§3",
        ProfileId::Edelivery115 => "§3.2.6",
        ProfileId::Entsog36 => "§2.2.6.3",
        ProfileId::As2 => "§2.4",
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
                "§2.3.1.1",
            )),
            None => Err(refuse(
                profile,
                setting,
                format!("a party type is required, one of {allowed:?}"),
                "§2.3.1.1",
            )),
        },
        PartyTypeRule::Fixed(fixed) => match party_type {
            None => Ok(()),
            Some(_) => Err(refuse(
                profile,
                setting,
                format!("the profile fixes the party type to {fixed:?}; do not set it"),
                "§4.5",
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
    let mut seen_certs: Vec<&Certificate> = Vec::new();
    let mut seen_skis: Vec<Vec<u8>> = Vec::new();
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
        let skis = cert.ski_candidates();
        if seen_certs.contains(&cert) || skis.iter().any(|s| seen_skis.contains(s)) {
            return Err(refuse(
                p,
                "LocalParty::decrypter",
                "two decrypters with the same certificate or key identifier (inbound key selection would be ambiguous)",
                "",
            ));
        }
        seen_certs.push(cert);
        seen_skis.extend(skis);
    }
    if p.separate_keys() {
        if seen_certs.contains(&signer_leaf) {
            return Err(refuse(
                p,
                "LocalParty::signer",
                "the signing key pair must differ from the decryption key pair",
                "§2.3.4.4",
            ));
        }
        if let Some(tls) = &local.tls
            && (tls.leaf() == signer_leaf || seen_certs.contains(&tls.leaf()))
        {
            return Err(refuse(
                p,
                "LocalParty::tls_identity",
                "the TLS key pair must differ from the signing and decryption key pairs",
                "§2.3.4.4",
            ));
        }
    }
    if p.id() == ProfileId::Bdew12 && !is_mp_id(&local.id) {
        return Err(refuse(
            p,
            "LocalParty::new",
            format!("{:?} is not a 13-digit MP-ID", local.id),
            "§2.3.1.1",
        ));
    }
    if protocol == Protocol::As2 && !is_as2_id(&local.id) {
        return Err(refuse(
            p,
            "LocalParty::new",
            "an AS2 identifier is 1-128 printable ASCII characters",
            "§6.2",
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
    let http = match http {
        Some(http) => http,
        None => default_http(p, &local)?,
    };
    let revocation = Arc::new(crate::revocation::Revocation::new(
        profile.revocation(),
        http.clone(),
        clock.clone(),
        anchors.iter().map(|a| a.x509().clone()).collect(),
        crl_signers.iter().map(|c| c.x509().clone()).collect(),
        None,
    ));
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

#[cfg(feature = "http-client")]
fn default_http(_profile: &Profile, local: &LocalParty) -> Result<Arc<dyn HttpClient>> {
    Ok(Arc::new(crate::http_client::BuiltinClient::new(
        local.tls.as_ref(),
    )?))
}

#[cfg(not(feature = "http-client"))]
fn default_http(profile: &Profile, _local: &LocalParty) -> Result<Arc<dyn HttpClient>> {
    Err(refuse(
        profile,
        "Builder::http_client",
        "no HTTP client: enable feature `http-client` or supply one",
        "",
    ))
}

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
