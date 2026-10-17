//! DOM → closed values. Every identifier check is decided here, from
//! attacker-visible input, **before any key is used** — so naming the refused
//! item is not an oracle.
//! Elements are matched by namespace URI and local name; the XML Encryption
//! 1.1 elements (`KeyDerivationMethod`, `ConcatKDFParams`, `MGF`) only in
//! `xenc11`, the XMLDSig 1.1 ones (`ECKeyValue`, `NamedCurve`, `PublicKey`)
//! only in `dsig11`.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use roxmltree::Node;

use super::kdf::ConcatKdfParams;
use crate::core::{AsxError, ErrorCode, ErrorContext, Result};
use crate::crypto::alg::{
    AgreementAlg, KdfAlg, KeyTransportAlg, KeyWrapAlg, MgfAlg, NamedCurve, XmlEncPayloadAlgorithm,
};
use crate::crypto::wssec::WsSecDigestMethod;
use crate::xml::ns;

const STAGE: &str = "wssec_decrypt_payload";

fn refused(message: String) -> AsxError {
    AsxError::new(
        ErrorCode::InteropViolation,
        message,
        ErrorContext::new(STAGE),
    )
}

fn malformed(message: String) -> AsxError {
    AsxError::new(ErrorCode::ParseFailed, message, ErrorContext::new(STAGE))
}

fn is(node: &Node<'_, '_>, namespace: &str, local: &str) -> bool {
    node.is_element()
        && node.tag_name().namespace() == Some(namespace)
        && node.tag_name().name() == local
}

/// Element children of `parent` named `local`, in any namespace.
fn named<'a, 'i>(parent: Node<'a, 'i>, local: &'static str) -> Vec<Node<'a, 'i>> {
    parent
        .children()
        .filter(|n| n.is_element() && n.tag_name().name() == local)
        .collect()
}

/// The `local` children of `parent` in `namespace`. A child of that name in
/// another namespace is refused naming element and namespace.
fn children_in<'a, 'i>(
    parent: Node<'a, 'i>,
    namespace: &'static str,
    local: &'static str,
) -> Result<Vec<Node<'a, 'i>>> {
    let all = named(parent, local);
    if let Some(stray) = all
        .iter()
        .find(|n| n.tag_name().namespace() != Some(namespace))
    {
        return Err(refused(format!(
            "{local} is declared in namespace {}; it is defined only in {namespace}",
            stray.tag_name().namespace().unwrap_or("(none)")
        )));
    }
    Ok(all)
}

fn exactly_one<'a, 'i>(nodes: Vec<Node<'a, 'i>>, what: &str) -> Result<Node<'a, 'i>> {
    match nodes.as_slice() {
        [one] => Ok(*one),
        [] => Err(refused(format!(
            "{what} is absent; exactly one is required"
        ))),
        many => Err(refused(format!(
            "{what} appears {} times; exactly one is required",
            many.len()
        ))),
    }
}

fn algorithm<'a>(node: Node<'a, '_>, what: &str) -> Result<&'a str> {
    node.attribute("Algorithm")
        .map(str::trim)
        .filter(|a| !a.is_empty())
        .ok_or_else(|| malformed(format!("{what} has no Algorithm")))
}

fn base64_text(node: Node<'_, '_>, what: &str) -> Result<Vec<u8>> {
    let text: String = node
        .descendants()
        .filter(|n| n.is_text())
        .filter_map(|n| n.text())
        .flat_map(str::chars)
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    if text.is_empty() {
        return Err(malformed(format!("{what} is empty")));
    }
    BASE64_STANDARD
        .decode(text)
        .map_err(|e| malformed(format!("{what} is not base64: {e}")))
}

fn cipher_value(parent: Node<'_, '_>, what: &str) -> Result<Vec<u8>> {
    let data = exactly_one(
        children_in(parent, ns::XENC, "CipherData")?,
        "xenc:CipherData",
    )?;
    let value = exactly_one(
        children_in(data, ns::XENC, "CipherValue")?,
        "xenc:CipherData/xenc:CipherValue",
    )?;
    base64_text(value, what)
}

/// RSA-OAEP parameters. Only SHA-256 / MGF1-SHA-256 with no label are accepted
/// (BDEW AS4-Profil 1.2 §2.2.6.2.2; eDelivery AS4 1.15).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RsaOaepParams {
    pub(crate) digest: WsSecDigestMethod,
    pub(crate) mgf: MgfAlg,
}

/// The key derivation an `AgreementMethod` declares.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum KeyDerivation {
    ConcatKdf {
        digest: WsSecDigestMethod,
        params: ConcatKdfParams,
    },
}

/// A parsed ECDH-ES `xenc:AgreementMethod`.
#[derive(Clone, Debug)]
pub(crate) struct AgreementSpec {
    pub(crate) kdf: KeyDerivation,
    pub(crate) originator_curve: NamedCurve,
    /// `dsig11:PublicKey`, validated against the curve in `bind`.
    pub(crate) originator_point: Vec<u8>,
    pub(crate) wrap: KeyWrapAlg,
}

#[derive(Clone, Debug)]
pub(crate) enum KeyTransportSpec {
    RsaOaep(RsaOaepParams),
    Agreement(AgreementSpec),
}

/// A parsed `xenc:EncryptedKey`.
#[derive(Clone, Debug)]
pub(crate) struct EncryptedKeySpec {
    pub(crate) transport: KeyTransportSpec,
    pub(crate) wrapped_key: Vec<u8>,
    /// How the sender named our key, if it did.
    pub(crate) recipient: Option<RecipientRef>,
}

/// A reference to the recipient's key in an `xenc:EncryptedKey`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RecipientRef {
    /// `ds:X509SKI` or a `wsse:KeyIdentifier` of type X509SubjectKeyIdentifier.
    Ski(Vec<u8>),
    /// `ds:X509Certificate` or a `wsse:KeyIdentifier` of type X509v3.
    Certificate(Vec<u8>),
    /// `ds:X509IssuerSerial`: the issuer DN text and the decimal serial.
    IssuerSerial { issuer: String, serial: String },
}

/// The recipient reference under an `xenc:EncryptedKey`, ignoring the
/// originator's key information. A malformed value is no reference.
fn recipient_ref(key: Node<'_, '_>) -> Option<RecipientRef> {
    let under_originator = |n: &Node<'_, '_>| {
        n.ancestors().any(|a| {
            a.is_element()
                && a.tag_name().namespace() == Some(ns::XENC)
                && a.tag_name().name() == "OriginatorKeyInfo"
        })
    };
    let text = |n: Node<'_, '_>| n.text().map(|t| t.split_whitespace().collect::<String>());
    for node in key
        .descendants()
        .filter(|n| n.is_element() && !under_originator(n))
    {
        let (namespace, name) = (node.tag_name().namespace(), node.tag_name().name());
        match (namespace, name) {
            (Some(ns::DS), "X509SKI") => {
                return BASE64_STANDARD
                    .decode(text(node)?)
                    .ok()
                    .map(RecipientRef::Ski);
            }
            (Some(ns::DS), "X509Certificate") => {
                return BASE64_STANDARD
                    .decode(text(node)?)
                    .ok()
                    .map(RecipientRef::Certificate);
            }
            (Some(ns::DS), "X509IssuerSerial") => {
                let child = |local: &str| {
                    node.children()
                        .find(|c| c.is_element() && c.tag_name().name() == local)
                        .and_then(|c| c.text())
                        .map(|t| t.trim().to_string())
                };
                return Some(RecipientRef::IssuerSerial {
                    issuer: child("X509IssuerName")?,
                    serial: child("X509SerialNumber")?,
                });
            }
            (Some(ns::WSSE), "KeyIdentifier") => {
                let value_type = node.attribute("ValueType").unwrap_or_default();
                let bytes = BASE64_STANDARD.decode(text(node)?).ok()?;
                if value_type.ends_with("#X509SubjectKeyIdentifier") {
                    return Some(RecipientRef::Ski(bytes));
                }
                if value_type.ends_with("#X509v3") {
                    return Some(RecipientRef::Certificate(bytes));
                }
            }
            _ => {}
        }
    }
    None
}

pub(crate) fn parse_encrypted_key(node: Node<'_, '_>) -> Result<EncryptedKeySpec> {
    let method = exactly_one(
        children_in(node, ns::XENC, "EncryptionMethod")?,
        "xenc:EncryptedKey/xenc:EncryptionMethod",
    )?;
    let uri = algorithm(method, "EncryptedKey method")?;
    let transport = if let Ok(alg) = KeyTransportAlg::from_uri(uri) {
        match alg {
            KeyTransportAlg::RsaOaep => KeyTransportSpec::RsaOaep(parse_rsa_oaep_params(method)?),
        }
    } else if let Ok(wrap) = KeyWrapAlg::from_uri(uri) {
        let key_info = exactly_one(
            children_in(node, ns::DS, "KeyInfo")?,
            "xenc:EncryptedKey/ds:KeyInfo",
        )?;
        let agreement = exactly_one(
            children_in(key_info, ns::XENC, "AgreementMethod")?,
            "xenc:AgreementMethod",
        )?;
        KeyTransportSpec::Agreement(parse_agreement_method(agreement, wrap)?)
    } else {
        return Err(refused(format!(
            "unsupported key transport or key wrap algorithm: {uri}"
        )));
    };
    let wrapped_key = cipher_value(node, "wrapped XML Encryption key")?;
    Ok(EncryptedKeySpec {
        transport,
        wrapped_key,
        recipient: recipient_ref(node),
    })
}

/// XMLenc11 §5.5.2: an absent `ds:DigestMethod` means SHA-1 and an absent
/// `xenc11:MGF` means MGF1-SHA-1 — defined values, refused as such.
pub(crate) fn parse_rsa_oaep_params(method: Node<'_, '_>) -> Result<RsaOaepParams> {
    let digest = match children_in(method, ns::DS, "DigestMethod")?.as_slice() {
        [] => {
            return Err(refused(
                "RSA-OAEP DigestMethod absent (SHA-1 default); SHA-256 is required".to_string(),
            ));
        }
        [one] => {
            let uri = algorithm(*one, "RSA-OAEP DigestMethod")?;
            match WsSecDigestMethod::from_algorithm_uri(uri) {
                Ok(WsSecDigestMethod::Sha256) => WsSecDigestMethod::Sha256,
                _ => {
                    return Err(refused(format!(
                        "RSA-OAEP DigestMethod {uri} is not supported; SHA-256 is required"
                    )));
                }
            }
        }
        many => {
            return Err(refused(format!(
                "RSA-OAEP DigestMethod appears {} times",
                many.len()
            )));
        }
    };
    let mgf = match children_in(method, ns::XENC11, "MGF")?.as_slice() {
        [] => {
            return Err(refused(
                "RSA-OAEP MGF absent (MGF1-SHA-1 default); MGF1-SHA-256 is required".to_string(),
            ));
        }
        [one] => {
            let uri = algorithm(*one, "RSA-OAEP MGF")?;
            MgfAlg::from_uri(uri).map_err(|_| {
                refused(format!(
                    "RSA-OAEP MGF {uri} is not supported; MGF1-SHA-256 is required"
                ))
            })?
        }
        many => {
            return Err(refused(format!(
                "RSA-OAEP MGF appears {} times",
                many.len()
            )));
        }
    };
    for label in children_in(method, ns::XENC, "OAEPparams")? {
        if label
            .descendants()
            .filter(|n| n.is_text())
            .filter_map(|n| n.text())
            .any(|t| !t.trim().is_empty())
        {
            return Err(refused(
                "RSA-OAEP OAEPparams (a label) is not supported; it must be absent or empty"
                    .to_string(),
            ));
        }
    }
    Ok(RsaOaepParams { digest, mgf })
}

pub(crate) fn parse_agreement_method(
    node: Node<'_, '_>,
    wrap: KeyWrapAlg,
) -> Result<AgreementSpec> {
    // ECDH-ES is the only registered agreement; the lookup refuses others.
    AgreementAlg::from_uri(algorithm(node, "AgreementMethod")?)?;

    // Exactly one xenc11:KeyDerivationMethod (ECDH-ES has no default).
    let kdm = exactly_one(
        children_in(node, ns::XENC11, "KeyDerivationMethod")?,
        "xenc11:KeyDerivationMethod (ECDH-ES has no default KDF)",
    )?;
    // A registry KDF.
    let kdf_alg = KdfAlg::from_uri(algorithm(kdm, "KeyDerivationMethod")?)?;
    let kdf = match kdf_alg {
        KdfAlg::ConcatKdf => {
            // Exactly one xenc11:ConcatKDFParams.
            let params_node = exactly_one(
                children_in(kdm, ns::XENC11, "ConcatKDFParams")?,
                "xenc11:ConcatKDFParams",
            )?;
            // Exactly one ds:DigestMethod in it.
            let digest_node = exactly_one(
                children_in(params_node, ns::DS, "DigestMethod")?,
                "ConcatKDFParams/DigestMethod",
            )?;
            // SHA-256 only.
            let uri = algorithm(digest_node, "ConcatKDFParams/DigestMethod")?;
            let digest = match WsSecDigestMethod::from_algorithm_uri(uri) {
                Ok(WsSecDigestMethod::Sha256) => WsSecDigestMethod::Sha256,
                _ => {
                    return Err(refused(format!(
                        "ConcatKDF digest {uri} is not supported; SHA-256 is required"
                    )));
                }
            };
            KeyDerivation::ConcatKdf {
                digest,
                params: ConcatKdfParams::from_node(params_node)?,
            }
        }
    };

    // OriginatorKeyInfo/ds:KeyValue/dsig11:ECKeyValue/dsig11:NamedCurve.
    let originator = exactly_one(
        children_in(node, ns::XENC, "OriginatorKeyInfo")?,
        "xenc:OriginatorKeyInfo",
    )?;
    let key_value = exactly_one(
        children_in(originator, ns::DS, "KeyValue")?,
        "OriginatorKeyInfo/ds:KeyValue",
    )?;
    let ec = exactly_one(
        children_in(key_value, ns::DSIG11, "ECKeyValue")?,
        "dsig11:ECKeyValue",
    )?;
    if ec.children().any(|n| is(&n, ns::DSIG11, "ECParameters")) {
        return Err(refused(
            "dsig11:ECParameters (explicit curve parameters) is not supported; a \
             dsig11:NamedCurve is required"
                .to_string(),
        ));
    }
    let curve_node = exactly_one(
        children_in(ec, ns::DSIG11, "NamedCurve")?,
        "dsig11:NamedCurve",
    )?;
    let urn = curve_node
        .attribute("URI")
        .map(str::trim)
        .unwrap_or_default();
    let originator_curve = NamedCurve::from_uri(urn)?;
    let point_node = exactly_one(
        children_in(ec, ns::DSIG11, "PublicKey")?,
        "dsig11:PublicKey",
    )?;
    let originator_point = base64_text(point_node, "originator public key")?;

    Ok(AgreementSpec {
        kdf,
        originator_curve,
        originator_point,
        wrap,
    })
}

// ── The SwA envelope ────────────────────────────────────────────────────────

/// One attachment `xenc:EncryptedData` of the envelope.
#[derive(Clone, Debug)]
pub(crate) struct DataSpec {
    /// The targeted Content-ID, normalized (no `cid:`, no angle brackets).
    pub(crate) cid: String,
    pub(crate) cipher: XmlEncPayloadAlgorithm,
    /// `@MimeType`: the type before encryption, when declared.
    pub(crate) mime_type: Option<String>,
}

/// The encryption content of one `wsse:Security` header, resolved without
/// any key: one key, one data element per encrypted part.
#[derive(Clone, Debug)]
pub(crate) struct ResolvedEnvelope {
    pub(crate) key: EncryptedKeySpec,
    /// In header order.
    pub(crate) data: Vec<DataSpec>,
}

/// The algorithm identifiers a partner's profile admits, compared as URIs
/// before anything else of the key is read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Suite {
    /// `EncryptedKey/EncryptionMethod/@Algorithm`: the key transport (RSA) or
    /// the key wrap (ECDH-ES).
    pub(crate) key_method: &'static str,
    /// ECDH-ES: `(AgreementMethod, KeyDerivationMethod, ConcatKDF digest)`.
    pub(crate) agreement: Option<(&'static str, &'static str, &'static str)>,
    /// `EncryptedData/EncryptionMethod/@Algorithm`.
    pub(crate) content: &'static str,
}

fn suite_refused(detail: String) -> AsxError {
    AsxError::new(
        ErrorCode::PolicyViolation,
        format!("encryption algorithm outside the partner's profile suite: {detail}"),
        ErrorContext::new(STAGE),
    )
}

/// The `Id` (XML Encryption 1.x) or `wsu:Id` (2.0) of `node`; both present
/// and different is refused.
fn element_id(node: Node<'_, '_>) -> Result<Option<String>> {
    // The unqualified `Id` only (a `&str` lookup also matches `wsu:Id`).
    let plain = node
        .attributes()
        .find(|a| a.namespace().is_none() && a.name() == "Id")
        .map(|a| a.value());
    let wsu = node.attribute((ns::WSU, "Id"));
    match (plain, wsu) {
        (Some(a), Some(b)) if a != b => Err(refused(format!(
            "{} carries Id {a:?} and wsu:Id {b:?}",
            node.tag_name().name()
        ))),
        (a, b) => Ok(a.or(b).map(str::to_owned)),
    }
}

/// Every element of the document whose `Id`, `wsu:Id` or `xml:id` is `id`.
fn elements_with_id<'a, 'i>(doc: &'a roxmltree::Document<'i>, id: &str) -> Vec<Node<'a, 'i>> {
    doc.descendants()
        .filter(|n| {
            n.is_element()
                && (n.attribute("Id") == Some(id)
                    || n.attribute((ns::WSU, "Id")) == Some(id)
                    || n.attribute((ns::XML, "id")) == Some(id))
        })
        .collect()
}

/// `#id` → `id`; anything else is not a same-document reference.
fn fragment(uri: &str) -> Option<&str> {
    uri.trim().strip_prefix('#').filter(|id| !id.is_empty())
}

/// Strip a `cid:` scheme and angle brackets.
pub(crate) fn normalize_cid(value: &str) -> &str {
    let value = value.trim();
    let value = value.strip_prefix('<').unwrap_or(value);
    let value = value.strip_suffix('>').unwrap_or(value);
    value
        .get(..4)
        .filter(|p| p.eq_ignore_ascii_case("cid:"))
        .map_or(value, |_| &value[4..])
}

/// Resolve the encryption envelope of `security` (the `wsse:Security` the
/// signature was verified in) against the declared payload parts — the
/// envelope structure, then the suite (when `suite` is given), then the
/// identifier checks of the key.
/// **No key is used.** `Ok(None)`: the header encrypts nothing.
pub(crate) fn resolve_envelope(
    doc: &roxmltree::Document<'_>,
    security: Node<'_, '_>,
    declared: &[String],
    suite: Option<&Suite>,
    max_parts: usize,
) -> Result<Option<ResolvedEnvelope>> {
    // Every xenc: element (and any wsse11:EncryptedHeader) lies inside
    // an EncryptedKey or EncryptedData child of the targeted header.
    for node in doc.descendants().filter(|n| n.is_element()) {
        let namespace = node.tag_name().namespace();
        let encrypted_header =
            namespace == Some(ns::WSSE11) && node.tag_name().name() == "EncryptedHeader";
        if namespace != Some(ns::XENC) && namespace != Some(ns::XENC11) && !encrypted_header {
            continue;
        }
        let top = node
            .ancestors()
            .take_while(|a| *a != security)
            .last()
            .filter(|_| node.ancestors().any(|a| a == security));
        let allowed = top.is_some_and(|top| {
            is(&top, ns::XENC, "EncryptedKey")
                || is(&top, ns::XENC, "EncryptedData")
                || is(&top, ns::XENC, "ReferenceList")
        });
        if !allowed {
            return Err(refused(format!(
                "{} outside an xenc:EncryptedKey, xenc:EncryptedData or xenc:ReferenceList \
                 of the targeted wsse:Security header (eb:Messaging and the Body are never encrypted; \
                 eDelivery AS4 1.15 §3.2.6)",
                node.tag_name().name()
            )));
        }
    }

    let keys: Vec<Node<'_, '_>> = security
        .children()
        .filter(|n| is(n, ns::XENC, "EncryptedKey"))
        .collect();
    let datas: Vec<Node<'_, '_>> = security
        .children()
        .filter(|n| is(n, ns::XENC, "EncryptedData"))
        .collect();
    if keys.is_empty() && datas.is_empty() {
        return Ok(None);
    }
    // Exactly one EncryptedKey.
    let key = match keys.as_slice() {
        [one] => *one,
        [] => {
            return Err(refused(
                "xenc:EncryptedData without an xenc:EncryptedKey".to_string(),
            ));
        }
        many => {
            return Err(refused(format!(
                "{} xenc:EncryptedKey elements; exactly one is accepted",
                many.len()
            )));
        }
    };
    if datas.len() > max_parts {
        return Err(refused(format!(
            "{} xenc:EncryptedData elements exceed the part cap {max_parts}",
            datas.len()
        )));
    }
    // `Id` and `wsu:Id` must agree.
    let key_id = element_id(key)?;

    // The ReferenceLists name each EncryptedData exactly once. A list
    // sits inside the EncryptedKey (eDelivery 1.15 §5) or directly in the
    // header (WSS SOAP Message Security 1.1 §9.3; phase4/WSS4J under BDEW).
    let mut lists = children_in(key, ns::XENC, "ReferenceList")?;
    lists.extend(
        security
            .children()
            .filter(|n| is(n, ns::XENC, "ReferenceList")),
    );
    let mut named: Vec<Node<'_, '_>> = Vec::new();
    for list in &lists {
        for reference in list.children().filter(|n| n.is_element()) {
            if !is(&reference, ns::XENC, "DataReference") {
                return Err(refused(format!(
                    "xenc:ReferenceList carries {}; only xenc:DataReference is accepted",
                    reference.tag_name().name()
                )));
            }
            let uri = reference.attribute("URI").unwrap_or_default();
            let id = fragment(uri).ok_or_else(|| {
                refused(format!(
                    "xenc:DataReference URI {uri:?} is not a same-document reference"
                ))
            })?;
            let target = match elements_with_id(doc, id).as_slice() {
                [] => {
                    return Err(refused(format!(
                        "xenc:DataReference {uri:?} resolves to no element"
                    )));
                }
                [one] => *one,
                _ => {
                    return Err(refused(format!(
                        "xenc:DataReference {uri:?} resolves to several elements"
                    )));
                }
            };
            if !datas.contains(&target) {
                return Err(refused(format!(
                    "xenc:DataReference {uri:?} does not name an xenc:EncryptedData of the header"
                )));
            }
            if named.contains(&target) {
                return Err(refused(format!(
                    "xenc:EncryptedData {uri:?} is named twice"
                )));
            }
            named.push(target);
        }
    }
    if let Some(orphan) = datas.iter().find(|d| !named.contains(d)) {
        return Err(refused(format!(
            "xenc:EncryptedData {:?} is named by no xenc:DataReference",
            orphan.attribute("Id").unwrap_or_default()
        )));
    }

    let mut data = Vec::with_capacity(datas.len());
    for node in &datas {
        let spec = resolve_data(*node, key_id.as_deref(), declared)?;
        // No two EncryptedData target the same part.
        if data.iter().any(|d: &DataSpec| d.cid == spec.cid) {
            return Err(refused(format!(
                "two xenc:EncryptedData target cid:{}",
                spec.cid
            )));
        }
        data.push(spec);
    }

    // The algorithm tuple, as URIs, before the key is parsed further.
    if let Some(suite) = suite {
        check_suite(key, &datas, suite)?;
    }

    let mut key = parse_encrypted_key(key)?;
    if key.recipient.is_none() {
        key.recipient = bst_reference(doc, security, keys[0])?;
    }
    Ok(Some(ResolvedEnvelope { key, data }))
}

/// One `EncryptedData`: `Type`, `ds:KeyInfo`, `CipherReference` and its
/// transform list.
fn resolve_data(node: Node<'_, '_>, key_id: Option<&str>, declared: &[String]) -> Result<DataSpec> {
    element_id(node)?;
    let type_uri = node.attribute("Type").unwrap_or("(absent)");
    if type_uri != ns::SWA_CONTENT_ONLY {
        return Err(refused(format!(
            "xenc:EncryptedData Type {type_uri} is not supported; only \
             Attachment-Content-Only is accepted (WSS SwA 1.1 §5.4.2)"
        )));
    }
    let method = exactly_one(
        children_in(node, ns::XENC, "EncryptionMethod")?,
        "xenc:EncryptedData/xenc:EncryptionMethod",
    )?;
    let cipher = XmlEncPayloadAlgorithm::from_uri(algorithm(method, "EncryptedData method")?)?;
    for key_info in children_in(node, ns::DS, "KeyInfo")? {
        let target = key_info
            .children()
            .filter(|n| n.is_element())
            .collect::<Vec<_>>();
        let points_at_key = match target.as_slice() {
            [str_]
                if is(str_, ns::WSSE, "SecurityTokenReference")
                    && str_
                        .attribute((ns::WSSE11, "TokenType"))
                        .is_none_or(|t| t == ns::WSSE11_ENCRYPTED_KEY_TOKEN) =>
            {
                let refs: Vec<_> = str_.children().filter(|n| n.is_element()).collect();
                matches!(refs.as_slice(), [r] if is(r, ns::WSSE, "Reference")
                    && r.attribute("URI").and_then(fragment).is_some()
                    && r.attribute("URI").and_then(fragment) == key_id)
            }
            _ => false,
        };
        if !points_at_key {
            return Err(refused(
                "xenc:EncryptedData/ds:KeyInfo does not reference the xenc:EncryptedKey \
                 that names it"
                    .to_string(),
            ));
        }
    }
    let cipher_data = exactly_one(
        children_in(node, ns::XENC, "CipherData")?,
        "xenc:EncryptedData/xenc:CipherData",
    )?;
    if !children_in(cipher_data, ns::XENC, "CipherValue")?.is_empty() {
        return Err(refused(
            "an attachment xenc:EncryptedData carries an inline xenc:CipherValue; a \
             CipherReference to the MIME part is required (WSS SwA 1.1 §5.5)"
                .to_string(),
        ));
    }
    let reference = exactly_one(
        children_in(cipher_data, ns::XENC, "CipherReference")?,
        "xenc:CipherData/xenc:CipherReference",
    )?;
    let uri = reference.attribute("URI").unwrap_or_default();
    if !uri
        .trim()
        .get(..4)
        .is_some_and(|p| p.eq_ignore_ascii_case("cid:"))
    {
        return Err(refused(format!(
            "xenc:CipherReference URI {uri:?} is not a cid: reference"
        )));
    }
    let cid = normalize_cid(uri).to_string();
    if !declared.iter().any(|d| normalize_cid(d) == cid) {
        return Err(refused(format!(
            "xenc:CipherReference cid:{cid} is not a part eb:PartInfo declares"
        )));
    }
    let transforms: Vec<Node<'_, '_>> = children_in(reference, ns::XENC, "Transforms")?
        .into_iter()
        .flat_map(|t| t.children().filter(|n| n.is_element()))
        .collect();
    let exactly_ciphertext = matches!(transforms.as_slice(), [t] if is(t, ns::DS, "Transform")
        && t.attribute("Algorithm") == Some(ns::SWA_CIPHERTEXT_TRANSFORM));
    if !exactly_ciphertext || reference.children().filter(|n| n.is_element()).count() != 1 {
        return Err(refused(format!(
            "xenc:CipherReference cid:{cid} must carry exactly the \
             Attachment-Ciphertext-Transform"
        )));
    }
    Ok(DataSpec {
        cid,
        cipher,
        mime_type: node.attribute("MimeType").map(str::to_owned),
    })
}

/// The suite check on the identifiers as written.
fn check_suite(key: Node<'_, '_>, datas: &[Node<'_, '_>], suite: &Suite) -> Result<()> {
    let attr_of = |node: Option<Node<'_, '_>>| {
        node.and_then(|n| n.attribute("Algorithm"))
            .map(str::trim)
            .unwrap_or("(absent)")
            .to_string()
    };
    fn child<'a, 'i>(parent: Node<'a, 'i>, namespace: &str, local: &str) -> Option<Node<'a, 'i>> {
        parent.children().find(|n| is(n, namespace, local))
    }
    let method = attr_of(child(key, ns::XENC, "EncryptionMethod"));
    if method != suite.key_method {
        return Err(suite_refused(format!(
            "EncryptedKey method {method} (the profile requires {})",
            suite.key_method
        )));
    }
    let agreement =
        child(key, ns::DS, "KeyInfo").and_then(|k| child(k, ns::XENC, "AgreementMethod"));
    match (suite.agreement, agreement) {
        (None, Some(_)) => {
            return Err(suite_refused(
                "key agreement where the profile requires key transport".to_string(),
            ));
        }
        (Some((want, _, _)), None) => {
            return Err(suite_refused(format!(
                "no xenc:AgreementMethod (the profile requires {want})"
            )));
        }
        (Some((want_agreement, want_kdf, want_digest)), Some(am)) => {
            let have = attr_of(Some(am));
            if have != want_agreement {
                return Err(suite_refused(format!(
                    "AgreementMethod {have} (the profile requires {want_agreement})"
                )));
            }
            let kdm = child(am, ns::XENC11, "KeyDerivationMethod");
            let have = attr_of(kdm);
            if have != want_kdf {
                return Err(suite_refused(format!(
                    "KeyDerivationMethod {have} (the profile requires {want_kdf})"
                )));
            }
            let digest = kdm
                .and_then(|k| child(k, ns::XENC11, "ConcatKDFParams"))
                .and_then(|p| child(p, ns::DS, "DigestMethod"));
            let have = attr_of(digest);
            if have != want_digest {
                return Err(suite_refused(format!(
                    "ConcatKDF digest {have} (the profile requires {want_digest})"
                )));
            }
        }
        (None, None) => {}
    }
    for data in datas {
        let have = attr_of(child(*data, ns::XENC, "EncryptionMethod"));
        if have != suite.content {
            return Err(suite_refused(format!(
                "content encryption {have} (the profile requires {})",
                suite.content
            )));
        }
    }
    Ok(())
}

/// A `wsse:Reference` to a `#X509v3` BinarySecurityToken of the same header
/// (the eDelivery/Peppol recipient form): the certificate it carries.
fn bst_reference(
    doc: &roxmltree::Document<'_>,
    security: Node<'_, '_>,
    key: Node<'_, '_>,
) -> Result<Option<RecipientRef>> {
    let Some(reference) = key
        .children()
        .filter(|n| is(n, ns::DS, "KeyInfo"))
        .flat_map(|k| k.descendants())
        .find(|n| {
            is(n, ns::WSSE, "Reference")
                && !n.ancestors().any(|a| is(&a, ns::XENC, "OriginatorKeyInfo"))
        })
    else {
        return Ok(None);
    };
    let uri = reference.attribute("URI").unwrap_or_default();
    let Some(id) = fragment(uri) else {
        return Ok(None);
    };
    let token = match elements_with_id(doc, id).as_slice() {
        [one] if is(one, ns::WSSE, "BinarySecurityToken") && one.parent() == Some(security) => *one,
        _ => return Ok(None),
    };
    if !token
        .attribute("ValueType")
        .is_some_and(|v| v.ends_with("#X509v3"))
    {
        return Ok(None);
    }
    Ok(base64_text(token, "recipient BinarySecurityToken")
        .ok()
        .map(RecipientRef::Certificate))
}
