//! AS4 signal generation: Receipt, Error, and PullRequest signals.

use super::stream::normalize_mpc;
use super::types::{
    As4ErrorCode, As4ErrorSeverity, As4GeneratePullRequestPolicy, As4NriReference,
    As4ReceivePushOutput,
};
use crate::core::{AsxError, ErrorCode, ErrorContext, Result, SessionContext};
#[cfg(feature = "as4")]
use crate::crypto::soap_builder::WsSecurityHeaderBuilder;
use crate::crypto::wssec::generate_xmlsig_signature;

/// Generate an AS4 `eb:Receipt` SignalMessage per ebMS3 §5.2.2.1 and §5.1.3.
///
/// The returned bytes are a complete SOAP 1.2 envelope containing a
/// `eb:SignalMessage` with an `eb:Receipt` element referencing
/// `ref_to_message_id`. The receipt contains an empty
/// `<ebbpsig:NonRepudiationInformation/>` placeholder.
///
/// For a conformant NRO receipt that echoes the original message's signed
/// references, use [`generate_receipt_with_nri`] instead.
///
/// The receipt is unsigned; if the P-Mode requires a signed receipt (NRI),
/// the caller must sign the returned bytes before transmitting them.
pub fn generate_receipt(
    session: &SessionContext,
    message_id: &str,
    ref_to_message_id: &str,
) -> Result<Vec<u8>> {
    generate_receipt_with_nri(session, message_id, ref_to_message_id, &[])
}

/// Generate an AS4 `eb:Receipt` SignalMessage with Non-Repudiation of Origin
/// (NRO) information per ebMS3 §5.2.2.1 and eDelivery AS4 §5.1.3.
///
/// When `nri_refs` is non-empty each entry becomes a
/// `<ebbpsig:MessagePartNRInformation>/<ds:Reference>` element inside the
/// `<ebbpsig:NonRepudiationInformation>` block, as required by the AS4
/// Non-Repudiation of Origin profile.
///
/// Obtain `nri_refs` by calling
/// [`crate::crypto::wssec::parse_signature_references`] on the raw bytes of
/// the inbound signed message and mapping each
/// [`crate::crypto::wssec::WsSecSignatureReference`] to
/// [`As4NriReference`]:
///
/// ```text
/// let sig_refs = parse_signature_references(xml_str)?;
/// let nri: Vec<As4NriReference> = sig_refs.into_iter().map(As4NriReference::from).collect();
/// let receipt = generate_receipt_with_nri(&session, &id, &ref_id, &nri)?;
/// ```
#[cfg_attr(feature = "trace", tracing::instrument(skip_all, fields(message_id = %message_id, partner_id = %session.partner_id())))]
pub fn generate_receipt_with_nri(
    session: &SessionContext,
    message_id: &str,
    ref_to_message_id: &str,
    nri_refs: &[As4NriReference],
) -> Result<Vec<u8>> {
    if message_id.trim().is_empty() {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            "message_id must not be empty",
            ErrorContext::for_session("as4_generate_receipt", session),
        ));
    }
    if ref_to_message_id.trim().is_empty() {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            "ref_to_message_id must not be empty",
            ErrorContext::for_session("as4_generate_receipt", session),
        ));
    }

    let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    // SECURITY: Escape caller-supplied values to prevent XML injection.
    let message_id_escaped = crate::wire::escape_xml(message_id);
    let ref_to_message_id_escaped = crate::wire::escape_xml(ref_to_message_id);

    // Build <ebbpsig:NonRepudiationInformation> content.
    // When NRI references are provided, each becomes a MessagePartNRInformation
    // entry that echoes the original message's ds:Reference — conformant with
    // eDelivery AS4 §5.1.3 Non-Repudiation of Origin.
    let (nri_xml, ds_ns_attr) = if nri_refs.is_empty() {
        ("<ebbpsig:NonRepudiationInformation/>".to_string(), "")
    } else {
        let mut nri = "<ebbpsig:NonRepudiationInformation>".to_string();
        for r in nri_refs {
            // SECURITY: escape all caller-controlled fields.
            let uri_esc = crate::wire::escape_xml(&r.uri);
            let dig_method_esc = crate::wire::escape_xml(&r.digest_method_uri);
            let dig_value_esc = crate::wire::escape_xml(&r.digest_value_b64);
            nri.push_str(&format!(
                "<ebbpsig:MessagePartNRInformation>\
<ds:Reference URI=\"{uri}\">\
<ds:DigestMethod Algorithm=\"{dig_method}\"\
></ds:DigestMethod\
><ds:DigestValue>{dig_value}</ds:DigestValue>\
</ds:Reference>\
</ebbpsig:MessagePartNRInformation>",
                uri = uri_esc,
                dig_method = dig_method_esc,
                dig_value = dig_value_esc,
            ));
        }
        nri.push_str("</ebbpsig:NonRepudiationInformation>");
        (nri, " xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"")
    };

    let xml = format!(
        "<S12:Envelope \
 xmlns:S12=\"http://www.w3.org/2003/05/soap-envelope\" \
 xmlns:eb=\"http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/\" \
 xmlns:ebbpsig=\"http://docs.oasis-open.org/ebxml-bp/ebbp-signals-2.0\"{ds_ns}>\
<S12:Header>\
<eb:Messaging S12:mustUnderstand=\"true\">\
<eb:SignalMessage>\
<eb:MessageInfo>\
<eb:Timestamp>{timestamp}</eb:Timestamp>\
<eb:MessageId>{message_id_escaped}</eb:MessageId>\
<eb:RefToMessageId>{ref_to_message_id_escaped}</eb:RefToMessageId>\
</eb:MessageInfo>\
<eb:Receipt>{nri_xml}</eb:Receipt>\
</eb:SignalMessage>\
</eb:Messaging>\
</S12:Header>\
<S12:Body/>\
</S12:Envelope>",
        ds_ns = ds_ns_attr,
    );
    Ok(xml.into_bytes())
}

/// Generate an AS4 `eb:Error` SignalMessage per ebMS3 §6.7.3.
pub fn generate_error_signal(
    session: &SessionContext,
    message_id: &str,
    ref_to_message_id: &str,
    error_code: As4ErrorCode,
    severity: As4ErrorSeverity,
    description: &str,
) -> Result<Vec<u8>> {
    if message_id.trim().is_empty() {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            "message_id must not be empty",
            ErrorContext::for_session("as4_generate_error_signal", session),
        ));
    }
    if ref_to_message_id.trim().is_empty() {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            "ref_to_message_id must not be empty",
            ErrorContext::for_session("as4_generate_error_signal", session),
        ));
    }
    if description.trim().is_empty() {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            "description must not be empty",
            ErrorContext::for_session("as4_generate_error_signal", session),
        ));
    }

    let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let message_id_escaped = crate::wire::escape_xml(message_id);
    let ref_id_escaped = crate::wire::escape_xml(ref_to_message_id);
    let description_escaped = crate::wire::escape_xml(description);

    let xml = format!(
        "<S12:Envelope \
              xmlns:S12=\"http://www.w3.org/2003/05/soap-envelope\" \
              xmlns:eb=\"http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/\">\
              <S12:Header>\
                <eb:Messaging S12:mustUnderstand=\"true\">\
                  <eb:SignalMessage>\
                    <eb:MessageInfo>\
                      <eb:Timestamp>{timestamp}</eb:Timestamp>\
                      <eb:MessageId>{message_id_escaped}</eb:MessageId>\
                      <eb:RefToMessageId>{ref_id_escaped}</eb:RefToMessageId>\
                    </eb:MessageInfo>\
                    <eb:Error errorCode=\"{error_code}\" severity=\"{severity}\" \
                              category=\"CONTENT\" origin=\"ebMS\">\
                      <eb:Description xml:lang=\"en\">{description_escaped}</eb:Description>\
                    </eb:Error>\
                  </eb:SignalMessage>\
                </eb:Messaging>\
              </S12:Header>\
              <S12:Body/>\
            </S12:Envelope>",
        timestamp = timestamp,
        message_id_escaped = message_id_escaped,
        ref_id_escaped = ref_id_escaped,
        error_code = error_code.ebms_code(),
        severity = severity.as_str(),
        description_escaped = description_escaped,
    );
    Ok(xml.into_bytes())
}

/// Generate an AS4 `eb:PullRequest` signal message, optionally signed.
///
/// Per eDelivery AS4 v1.15 §4.5.5, pull requests sent by the Receiver MSH
/// MUST carry a WS-Security XML Signature when credentials are supplied.
#[cfg_attr(feature = "trace", tracing::instrument(skip_all, fields(message_id = %policy.message_id, partner_id = %session.partner_id())))]
pub fn generate_pull_request(
    session: &SessionContext,
    policy: &As4GeneratePullRequestPolicy,
) -> Result<Vec<u8>> {
    let stage = "as4_generate_pull_request";

    let mpc = normalize_mpc(&policy.mpc);
    if mpc.is_empty() {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            "AS4 PullRequest MPC must not be empty",
            ErrorContext::for_session(stage, session),
        ));
    }
    if policy.message_id.trim().is_empty() {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            "AS4 PullRequest message_id must not be empty",
            ErrorContext::for_session(stage, session),
        ));
    }

    if let Some(ref auth) = policy.authorization_info
        && auth.trim().is_empty()
    {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            "AS4 PullRequest authorization_info must not be empty when set",
            ErrorContext::for_session(stage, session),
        ));
    }

    if let Some(creds) = &policy.credentials {
        let signing_cert =
            openssl::x509::X509::from_pem(&creds.signing_cert_pem).map_err(|_err| {
                AsxError::new(
                    ErrorCode::InvalidInput,
                    "AS4 PullRequest signing_cert_pem is not a valid PEM X.509 certificate",
                    ErrorContext::for_session(stage, session),
                )
            })?;

        let signing_key = openssl::pkey::PKey::private_key_from_pem(&creds.signing_key_pem)
            .map_err(|_err| {
                AsxError::new(
                    ErrorCode::InvalidInput,
                    "AS4 PullRequest signing_key_pem is not a valid PEM private key",
                    ErrorContext::for_session(stage, session),
                )
            })?;

        let signing_cert_public = signing_cert.public_key().map_err(|_err| {
            AsxError::new(
                ErrorCode::InvalidInput,
                "AS4 PullRequest signing_cert_pem does not contain a usable public key",
                ErrorContext::for_session(stage, session),
            )
        })?;

        if !signing_key.public_eq(&signing_cert_public) {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                "AS4 PullRequest signing_cert_pem does not match signing_key_pem",
                ErrorContext::for_session(stage, session),
            ));
        }
    }

    let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let mpc_escaped = crate::wire::escape_xml(mpc);
    let message_id_escaped = crate::wire::escape_xml(&policy.message_id);

    const PULL_REQUEST_WSU_ID: &str = "as4-pull-request";

    let auth_info_xml = policy
        .authorization_info
        .as_deref()
        .map(|v| {
            format!(
                "\n        <eb:AuthorizationInfo>{}</eb:AuthorizationInfo>",
                crate::wire::escape_xml(v)
            )
        })
        .unwrap_or_default();

    let messaging_header = format!(
        r#"<!-- wsse-placeholder -->
    <eb:Messaging S12:mustUnderstand="true">
      <eb:SignalMessage>
        <eb:MessageInfo>
          <eb:Timestamp>{timestamp}</eb:Timestamp>
          <eb:MessageId>{message_id_escaped}</eb:MessageId>
        </eb:MessageInfo>
        <eb:PullRequest wsu:Id="{PULL_REQUEST_WSU_ID}" eb:mpc="{mpc_escaped}">{auth_info}</eb:PullRequest>
      </eb:SignalMessage>
    </eb:Messaging>"#,
        timestamp = timestamp,
        message_id_escaped = message_id_escaped,
        mpc_escaped = mpc_escaped,
        auth_info = auth_info_xml,
    );

    let envelope = format!(
        r#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
  xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
  xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
  xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <S12:Header>
    {messaging_header}
  </S12:Header>
  <S12:Body/>
</S12:Envelope>"#,
        messaging_header = messaging_header,
    );

    if let Some(creds) = &policy.credentials {
        let reference_uri = format!("#{PULL_REQUEST_WSU_ID}");
        let reference_uris = [reference_uri.as_str()];
        let signature_xml = generate_xmlsig_signature(
            &envelope,
            &reference_uris,
            &creds.signing_key_pem,
            &creds.signing_cert_pem,
            creds.key_info_profile,
        )?;
        let wsse_header = WsSecurityHeaderBuilder::new()
            .with_signing_cert(creds.signing_cert_pem.clone())
            .with_signature_xml(signature_xml)
            .build()
            .map_err(|err| {
                AsxError::new(
                    ErrorCode::ParseFailed,
                    format!("failed to build WS-Security header for pull request: {err:?}"),
                    ErrorContext::for_session(stage, session),
                )
            })?;
        let wsse_str = String::from_utf8(wsse_header).map_err(|_| {
            AsxError::new(
                ErrorCode::ParseFailed,
                "WS-Security header for pull request is not valid UTF-8",
                ErrorContext::for_session(stage, session),
            )
        })?;

        let signed_envelope = envelope.replace("<!-- wsse-placeholder -->", &wsse_str);
        Ok(signed_envelope.into_bytes())
    } else {
        let unsigned_envelope = envelope.replace("<!-- wsse-placeholder -->\n    ", "");
        Ok(unsigned_envelope.into_bytes())
    }
}

/// Convenience wrapper: generate a receipt for a completed receive output.
///
/// Equivalent to calling [`generate_receipt_with_nri`] with
/// `ref_to_message_id = output.user_message.message_id` and an empty NRI
/// slice.  For NRO-profile receipts (with `<NonRepudiationInformation>`),
/// use [`generate_receipt_with_nri`] directly with refs extracted from the
/// raw inbound bytes.
///
/// # Example
/// ```rust,ignore
/// let outcome = asx_rs::as4::receive_push_with_dedup_async(&session, &bus, req, dedup).await?;
/// if let As4ReceiveOutcome::FirstSeen(output) = outcome {
///     let receipt_id = format!("receipt@{}", uuid::Uuid::new_v4());
///     let receipt_bytes = generate_receipt_for_output(&session, &receipt_id, &output)?;
/// }
/// ```
pub fn generate_receipt_for_output(
    session: &SessionContext,
    receipt_message_id: &str,
    output: &As4ReceivePushOutput,
) -> Result<Vec<u8>> {
    generate_receipt_with_nri(
        session,
        receipt_message_id,
        &output.user_message.message_id,
        &[],
    )
}
