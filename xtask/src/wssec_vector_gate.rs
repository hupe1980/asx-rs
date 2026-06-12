use asx::core::ErrorCode;
use asx::crypto::wssec::{
    WsSecCanonicalizationKind, WsSecCanonicalizationProfile, canonical_vector_diff,
    canonicalize_reference, parse_signature_references, verify_signature_references_strict,
};

const BASE_XML_FIXTURE: &str = "tests/fixtures/wssec/signed_message.xml.golden";
const C14N_GOLDEN_FIXTURE: &str = "tests/fixtures/wssec/payload-1.c14n.golden";
const SHA256_URI: &str = "http://www.w3.org/2001/04/xmlenc#sha256";

pub fn run(args: &[String]) -> Result<(), String> {
    if !args.is_empty() {
        return Err("usage: wssec-vector-gate".to_string());
    }

    let template = std::fs::read_to_string(BASE_XML_FIXTURE)
        .map_err(|err| format!("failed reading wssec fixture: {}", err))?;
    let unsigned = template.replace("{{DIGEST}}", "placeholder");

    let canonicalized = canonicalize_reference(
        &unsigned,
        "#payload-1",
        WsSecCanonicalizationProfile::default(),
    )
    .map_err(|err| format!("canonicalization failed: {}", err))?;

    let expected = std::fs::read_to_string(C14N_GOLDEN_FIXTURE)
        .map_err(|err| format!("failed reading c14n golden fixture: {}", err))?;
    let actual = String::from_utf8_lossy(&canonicalized.canonical_bytes);
    if actual != expected.trim_end() {
        return Err(format!(
            "canonical vector mismatch\n{}",
            canonical_vector_diff(expected.trim_end(), &actual)
        ));
    }

    let digest = canonicalized.digest_value_base64;
    let signed = template.replace("{{DIGEST}}", &digest);
    let refs = parse_signature_references(&signed)
        .map_err(|err| format!("failed to parse signature references: {}", err))?;

    verify_signature_references_strict(&signed, &refs)
        .map_err(|err| format!("strict reference verification failed: {}", err))?;

    let wrapped_signed = signed.replace("URI=\"#payload-1\"", "URI=\" #payload-1 \"");
    match parse_signature_references(&wrapped_signed) {
        Err(err) => {
            if err.code != ErrorCode::InteropViolation {
                return Err(format!(
                    "expected wrapped-uri parse rejection InteropViolation, got {}",
                    err
                ));
            }
        }
        Ok(wrapped_refs) => {
            let wrapped_uri_err =
                verify_signature_references_strict(&wrapped_signed, &wrapped_refs)
                    .expect_err("strict mode must reject wrapped URI");
            if wrapped_uri_err.code != ErrorCode::InvalidInput {
                return Err(format!(
                    "expected wrapped-uri verification rejection InvalidInput, got {}",
                    wrapped_uri_err
                ));
            }
        }
    }

    let whitespace_payload =
        "    <eb:Payload wsu:Id=\"payload-1\">\n      <eb:Value>ABC</eb:Value>\n    </eb:Payload>";
    let whitespace_unsigned = signed_xml("#payload-1", whitespace_payload, "placeholder");
    let whitespace_digest = canonicalize_reference(
        &whitespace_unsigned,
        "#payload-1",
        WsSecCanonicalizationProfile {
            kind: WsSecCanonicalizationKind::Exclusive,
            include_comments: false,
            strip_blank_text: false,
            inclusive_ns_prefixes: Vec::new(),
        },
    )
    .map_err(|err| format!("whitespace-profile digest generation failed: {}", err))?
    .digest_value_base64;

    let whitespace_signed = signed_xml("#payload-1", whitespace_payload, &whitespace_digest);
    let whitespace_refs = parse_signature_references(&whitespace_signed)
        .map_err(|err| format!("failed to parse whitespace signed refs: {}", err))?;

    let whitespace_err = verify_signature_references_strict(&whitespace_signed, &whitespace_refs)
        .expect_err("strict mode must reject whitespace digest mismatch");

    if whitespace_err.code != ErrorCode::SecurityVerificationFailed {
        return Err(format!(
            "expected whitespace digest rejection SecurityVerificationFailed, got {}",
            whitespace_err
        ));
    }

    println!(
        "{{\"wssec_vector_gate\":\"ok\",\"profiles\":[\"SpecStrict\"],\"verification_mode\":\"strict-only\"}}"
    );

    Ok(())
}

fn signed_xml(reference_uri: &str, payload_xml: &str, digest_base64: &str) -> String {
    format!(
        r#"<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
    xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
    xmlns:eb="urn:example:eb">
  <soap:Header>
    <ds:Signature>
      <ds:SignedInfo>
        <ds:Reference URI="{reference_uri}">
          <ds:DigestMethod Algorithm="{SHA256_URI}"/>
          <ds:DigestValue>{digest_base64}</ds:DigestValue>
        </ds:Reference>
      </ds:SignedInfo>
      <ds:SignatureValue>stub-signature</ds:SignatureValue>
    </ds:Signature>
  </soap:Header>
  <soap:Body>
{payload_xml}
  </soap:Body>
</soap:Envelope>"#
    )
}
