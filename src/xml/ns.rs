//! Namespace URIs, in one place. Algorithm identifiers are not namespaces and
//! live in the registry (`crypto::alg`).

/// SOAP 1.2 envelope.
pub(crate) const SOAP12: &str = "http://www.w3.org/2003/05/soap-envelope";
/// SOAP 1.1 envelope.
pub(crate) const SOAP11: &str = "http://schemas.xmlsoap.org/soap/envelope/";
/// ebMS 3.0 core header.
pub(crate) const EBMS3: &str = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/";
/// ebBP signals (`NonRepudiationInformation`).
pub(crate) const EBBP_SIGNALS: &str = "http://docs.oasis-open.org/ebxml-bp/ebbp-signals-2.0";
/// WS-Security 1.0 secext.
pub(crate) const WSSE: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
/// WS-Security 1.0 utility (`wsu:Id`, `wsu:Timestamp`).
pub(crate) const WSU: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
/// `wsse:BinarySecurityToken/@ValueType` of a single X.509 v3 certificate.
pub(crate) const WSSE_X509V3_VALUE_TYPE: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3";
/// `wsse:BinarySecurityToken/@ValueType` of an X.509 PKI path.
pub(crate) const WSSE_X509_PKIPATH_VALUE_TYPE: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509PKIPathv1";
/// `wsse:KeyIdentifier/@ValueType` of an X.509 Subject Key Identifier.
pub(crate) const WSSE_SKI_VALUE_TYPE: &str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier";
/// WS-Security 1.1 secext (`wsse11:TokenType`).
pub(crate) const WSSE11: &str =
    "http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd";
/// `wsse11:TokenType` of a reference to an `xenc:EncryptedKey`.
pub(crate) const WSSE11_ENCRYPTED_KEY_TOKEN: &str =
    "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#EncryptedKey";
/// WSS SwA 1.1 §5.4.2: `xenc:EncryptedData/@Type` of an encrypted attachment
/// body (headers not encrypted). The only type accepted.
pub(crate) const SWA_CONTENT_ONLY: &str =
    "http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Content-Only";
/// WSS SwA 1.1 §5.5.2: the one transform of an attachment `CipherReference`.
pub(crate) const SWA_CIPHERTEXT_TRANSFORM: &str =
    "http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Ciphertext-Transform";
/// `wsse:BinarySecurityToken/@EncodingType` base64.
pub(crate) const WSSE_BASE64_ENCODING: &str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary";
/// WS-Addressing 1.0.
pub(crate) const WSA: &str = "http://www.w3.org/2005/08/addressing";
/// XML Signature.
pub(crate) const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
/// XML Signature 1.1 (`dsig11:ECKeyValue`, `NamedCurve`, `PublicKey`).
pub(crate) const DSIG11: &str = "http://www.w3.org/2009/xmldsig11#";
/// Exclusive C14N (`ec:InclusiveNamespaces`).
pub(crate) const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
/// XML Encryption.
pub(crate) const XENC: &str = "http://www.w3.org/2001/04/xmlenc#";
/// XML Encryption 1.1 (`KeyDerivationMethod`, `ConcatKDFParams`, `MGF`).
pub(crate) const XENC11: &str = "http://www.w3.org/2009/xmlenc11#";
/// UN/CEFACT Standard Business Document Header.
pub(crate) const SBDH: &str =
    "http://www.unece.org/cefact/namespaces/StandardBusinessDocumentHeader";
/// Peppol non-XML payload envelope.
pub(crate) const PEPPOL_ENVELOPE: &str = "http://peppol.eu/xsd/ticc/envelope/1.0";
/// The `xml:` prefix (`xml:id`, `xml:lang`).
pub(crate) const XML: &str = "http://www.w3.org/XML/1998/namespace";
