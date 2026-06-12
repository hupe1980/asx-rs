use asx::core::SessionContext;
#[cfg(feature = "as4")]
use asx::core::{CertHandle, OcspMode};
#[cfg(feature = "as4")]
use asx::crypto::wssec::{WsSecOutboundKeyInfoProfile, generate_xmlsig_signature};
use asx::reliability::InMemoryDedupBackend;
#[cfg(feature = "as4")]
use sha2::{Digest, Sha256};

#[inline]
#[cfg(feature = "as4")]
pub fn as4_strict_push_policy() -> asx::as4::As4PushPolicy {
    asx::as4::As4PushPolicyBuilder::new()
        .fail_closed_audit_events(false)
        .build()
        .expect("as4_strict_push_policy")
}

#[inline]
#[cfg(feature = "as4")]
pub fn as4_unsigned_push_policy() -> asx::as4::As4PushPolicy {
    asx::as4::As4PushPolicyBuilder::new()
        .allow_unsigned_push(true)
        .fail_closed_audit_events(false)
        .build()
        .expect("as4_unsigned_push_policy")
}

#[inline]
pub fn fixture(name: &str) -> Vec<u8> {
    let path = format!("tests/fixtures/{name}");
    std::fs::read(&path).unwrap_or_else(|_| panic!("failed to read fixture: {path}"))
}

#[inline]
pub fn pki_fixture(name: &str) -> Vec<u8> {
    let path = format!("tests/fixtures/pki/{name}");
    std::fs::read(&path).unwrap_or_else(|_| panic!("failed to read pki fixture: {path}"))
}

#[cfg(feature = "as4")]
pub fn signed_receipt_fixture(ref_to_message_id: &str) -> Vec<u8> {
    const SIGNAL_WSU_ID: &str = "as4-receipt-signal";

    let unsigned = format!(
        r#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
        xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
        xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
        xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <S12:Header>
        <eb:Messaging>
            <eb:SignalMessage wsu:Id="{signal_wsu_id}">
                <eb:MessageInfo>
                    <eb:RefToMessageId>{ref_to_message_id}</eb:RefToMessageId>
                </eb:MessageInfo>
                <eb:Receipt>
                    <eb:NonRepudiationInformation/>
                </eb:Receipt>
            </eb:SignalMessage>
        </eb:Messaging>
        <!-- signature-placeholder -->
    </S12:Header>
    <S12:Body/>
</S12:Envelope>"#,
        signal_wsu_id = SIGNAL_WSU_ID,
        ref_to_message_id = ref_to_message_id,
    );

    let signing_key_pem = pki_fixture("receipt_signing.key.pem");
    let signing_cert_pem = pki_fixture("receipt_signing.cert.pem");
    let reference_uri = format!("#{SIGNAL_WSU_ID}");
    let reference_uris = [reference_uri.as_str()];
    let signature_xml = generate_xmlsig_signature(
        &unsigned,
        &reference_uris,
        &signing_key_pem,
        &signing_cert_pem,
        WsSecOutboundKeyInfoProfile::X509DataAndRsaKeyValue,
    )
    .expect("valid receipt signature");

    unsigned
        .replace("<!-- signature-placeholder -->", &signature_xml)
        .into_bytes()
}

#[inline]
pub fn session() -> SessionContext {
    SessionContext::new("as4-session-1", "partner-a", "strict").expect("session")
}

#[cfg(feature = "as4")]
fn cert_fingerprint_sha256_hex(cert_pem: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let cert = openssl::x509::X509::from_pem(cert_pem).expect("valid certificate PEM");
    let der = cert.to_der().expect("valid certificate DER");
    let digest = Sha256::digest(&der);
    let mut out = String::with_capacity(digest.len() * 2);
    for &byte in &digest {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(feature = "as4")]
pub fn session_with_trust_anchor_and_fingerprint_pin(anchor_pem: &[u8]) -> SessionContext {
    let mut cert_handle = CertHandle::new("as4-receipt-signing-anchor-with-pin");
    cert_handle.trust_anchor_pems =
        vec![String::from_utf8(anchor_pem.to_vec()).expect("trust-anchor PEM must be UTF-8")];
    cert_handle.ocsp_mode = OcspMode::Disabled;
    cert_handle.fingerprint_sha256 = cert_fingerprint_sha256_hex(anchor_pem);

    SessionContext::new("as4-session-1", "partner-a", "strict")
        .expect("session")
        .with_cert_handle(cert_handle)
        .expect("session trust configuration with pin")
}

#[inline]
pub fn dedup_backend() -> InMemoryDedupBackend {
    InMemoryDedupBackend::default()
}
