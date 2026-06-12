#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

fail=0

check_no_matches() {
  local label="$1"
  local token="$2"
  shift 2

  local matches
  matches="$(rg -n --fixed-strings -- "$token" "$@" || true)"
  if [[ -n "$matches" ]]; then
    echo "[as4-strict-deprecations] FAIL: ${label}" >&2
    echo "$matches" >&2
    fail=1
  fi
}

check_required_match() {
  local label="$1"
  local token="$2"
  local file="$3"

  if ! rg -n --fixed-strings -- "$token" "$file" >/dev/null; then
    echo "[as4-strict-deprecations] FAIL: missing required invariant: ${label}" >&2
    fail=1
  fi
}

check_matches_confined_to_paths() {
  local label="$1"
  local token="$2"
  local allowed_path_regex="$3"
  shift 3

  local matches
  matches="$(rg -n --fixed-strings -- "$token" "$@" || true)"
  if [[ -z "$matches" ]]; then
    return
  fi

  local disallowed
  disallowed="$(printf '%s\n' "$matches" | awk -F: -v allowed="$allowed_path_regex" '$1 !~ allowed')"
  if [[ -n "$disallowed" ]]; then
    echo "[as4-strict-deprecations] FAIL: ${label}" >&2
    echo "$disallowed" >&2
    fail=1
  fi
}

as4_send_surface=(
  src/as4/send.rs
  src/as4/types.rs
  src/as4/pmode.rs
  src/as4/large_message.rs
  src/as4/mime_packaging.rs
  src/as4/mod.rs
)

check_no_matches "SOAP 1.1 enum/path token in strict AS4 send surface" "As4SoapVersion::Soap11" "${as4_send_surface[@]}"
check_no_matches "SOAP 1.1 token in strict AS4 send surface" "Soap11" "${as4_send_surface[@]}"
check_no_matches "embedded SOAP payload mode token in strict AS4 send surface" "SoapBodyEmbedded" "${as4_send_surface[@]}"
check_no_matches "legacy SOAP 1.1 media type token in strict AS4 send surface" "text/xml" "${as4_send_surface[@]}"
check_no_matches "deprecated As4SoapVersion token in strict AS4 send surface" "As4SoapVersion" "${as4_send_surface[@]}"
check_no_matches "deprecated soap_version policy API token in strict AS4 send surface" "soap_version(" "${as4_send_surface[@]}"

as4_stream_surface=(
  src/as4/stream.rs
)

check_no_matches "deprecated bare-LF boundary fallback token in AS4 stream parser" "boundary_lf" "${as4_stream_surface[@]}"

as4_builder_surface=(
  src/crypto/soap_builder.rs
)

check_no_matches "SOAP 1.1 namespace token in SOAP builder" "schemas.xmlsoap.org/soap/envelope" "${as4_builder_surface[@]}"
check_no_matches "SOAP version enum compatibility token in SOAP builder" "SoapVersion" "${as4_builder_surface[@]}"
check_no_matches "SOAP version setter compatibility token in SOAP builder" "with_soap_version" "${as4_builder_surface[@]}"
check_no_matches "SOAP 1.1 enum/path token in SOAP builder" "Soap11" "${as4_builder_surface[@]}"

# Parser guardrails: strict AS4 parser surface is SOAP 1.2-only.
check_no_matches "parser must not accept SOAP 1.1 actor targeting" "\"actor\" if soap_ns == SOAP11_NS" src/as4/parser.rs
check_no_matches "parser must not accept dual SOAP11/SOAP12 namespaces" "Some(SOAP12_NS | SOAP11_NS)" src/as4/parser.rs
check_no_matches "parser must not carry SOAP11 namespace token" "SOAP11_NS" src/as4/parser.rs
check_required_match "parser strict SOAP 1.2 namespace error message" "AS4 policy requires SOAP 1.2 envelope namespace" src/as4/parser.rs
check_no_matches "parser must not contain any explicit fallback return of parse state" "return Ok(state);" src/as4/parser.rs
check_no_matches "parser must not use policy-style strict requires wording" "strict AS4 policy requires" src/as4/parser.rs
check_no_matches "parser must not use policy-style strict rejects wording" "strict AS4 policy rejects" src/as4/parser.rs
check_required_match "parser non-envelope root must fail explicitly" "AS4 payload root element must be SOAP Envelope" src/as4/parser.rs
check_required_match "parser namespace-less envelope must fail explicitly" "AS4 SOAP Envelope must declare namespace" src/as4/parser.rs
check_required_match "parser missing SOAP Header must fail explicitly" "AS4 SOAP Envelope missing Header" src/as4/parser.rs
check_required_match "parser missing SOAP Body must fail explicitly" "AS4 SOAP Envelope missing Body" src/as4/parser.rs
check_required_match "parser missing eb:Messaging must fail explicitly" "AS4 SOAP Header missing eb:Messaging" src/as4/parser.rs
check_required_match "parser missing UserMessage must fail explicitly" "AS4 eb:Messaging missing UserMessage" src/as4/parser.rs
check_required_match "parser missing wsse:Security must fail explicitly in strict mode" "AS4 SOAP Header missing wsse:Security" src/as4/parser.rs
check_required_match "parser strict messaging mustUnderstand contract" "AS4 eb:Messaging must set SOAP mustUnderstand=true" src/as4/parser.rs
check_required_match "parser strict mpc URI contract" "AS4 UserMessage mpc must be a valid URI" src/as4/parser.rs
check_required_match "parser duplicate MessageId contract" "AS4 UserMessage contains duplicate MessageId" src/as4/parser.rs
check_required_match "parser duplicate Action contract" "AS4 UserMessage contains duplicate Action" src/as4/parser.rs
check_required_match "parser invalid Messaging mustUnderstand contract" "AS4 eb:Messaging has invalid SOAP mustUnderstand token" src/as4/parser.rs
check_required_match "parser invalid top-level header mustUnderstand contract" "AS4 SOAP Header block has invalid SOAP mustUnderstand token" src/as4/parser.rs
check_required_match "parser unknown mandatory receiver-targeted header contract" "AS4 SOAP Header contains unknown mandatory receiver-targeted block" src/as4/parser.rs
check_required_match "parser missing originalSender property must fail explicitly" "AS4 UserMessage missing Property originalSender" src/as4/parser.rs
check_required_match "parser missing finalRecipient property must fail explicitly" "AS4 UserMessage missing Property finalRecipient" src/as4/parser.rs
check_required_match "parser missing trackingIdentifier property must fail explicitly" "AS4 UserMessage missing Property trackingIdentifier" src/as4/parser.rs
check_no_matches "parser must not use deprecated generic structure catch-all message" "AS4 SOAP envelope is missing required SOAP/ebMS structure" src/as4/parser.rs
check_no_matches "parser must not use deprecated strict policy message for missing wsse:Security" "strict AS4 policy requires wsse:Security header" src/as4/parser.rs
check_no_matches "parser must not use deprecated strict policy message for missing originalSender" "strict AS4 policy requires UserMessage Property originalSender" src/as4/parser.rs
check_no_matches "parser must not use deprecated strict policy message for missing finalRecipient" "strict AS4 policy requires UserMessage Property finalRecipient" src/as4/parser.rs
check_no_matches "parser must not use deprecated strict policy message for missing trackingIdentifier" "strict AS4 policy requires UserMessage Property trackingIdentifier" src/as4/parser.rs
check_required_match "user-message precheck missing Envelope must fail explicitly" "AS4 payload missing SOAP Envelope marker" src/as4/parser.rs
check_required_match "user-message precheck missing Header must fail explicitly" "AS4 payload missing SOAP Header marker" src/as4/parser.rs
check_required_match "user-message precheck missing Body must fail explicitly" "AS4 payload missing SOAP Body marker" src/as4/parser.rs
check_required_match "user-message precheck missing Header messaging marker must fail explicitly" "AS4 SOAP Header missing eb:Messaging marker" src/as4/parser.rs
check_required_match "user-message precheck missing Header user-message marker must fail explicitly" "AS4 SOAP Header missing eb:UserMessage marker" src/as4/parser.rs
check_required_match "receipt precheck missing Envelope must fail explicitly" "AS4 receipt payload missing SOAP Envelope marker" src/as4/parser.rs
check_required_match "receipt precheck missing SignalMessage must fail explicitly" "AS4 receipt payload missing eb:SignalMessage marker" src/as4/parser.rs
check_required_match "receipt precheck missing Receipt must fail explicitly" "AS4 receipt payload missing eb:Receipt marker" src/as4/parser.rs
check_required_match "receipt precheck missing RefToMessageId must fail explicitly" "AS4 receipt payload missing eb:RefToMessageId marker" src/as4/parser.rs
check_required_match "receipt parser missing SignalMessage must fail explicitly" "AS4 signal payload missing eb:SignalMessage" src/as4/parser.rs
check_required_match "receipt parser missing Receipt under SignalMessage must fail explicitly" "AS4 eb:SignalMessage missing eb:Receipt" src/as4/parser.rs
check_no_matches "user-message precheck must not use deprecated generic structural marker error" "AS4 payload is missing required SOAP/ebMS structural markers" src/as4/parser.rs
check_no_matches "user-message precheck must not use deprecated generic header/ebMS marker error" "AS4 payload is missing required Header/ebMS UserMessage structural markers" src/as4/parser.rs
check_no_matches "receipt precheck must not use deprecated generic structural marker error" "AS4 receipt payload is missing required SOAP/ebMS structural markers" src/as4/parser.rs
check_no_matches "user-message precheck must not use deprecated body-boundary marker error" "AS4 payload is missing SOAP Body structural boundary" src/as4/parser.rs
check_no_matches "receipt parser must not use deprecated generic receipt-missing message" "AS4 signal payload does not contain eb:Receipt" src/as4/parser.rs

as4_transport_surface=(
  src/transport/egress.rs
  src/transport/ingress.rs
)

check_no_matches "transport must not emit or parse SOAPAction compatibility header" "SOAPAction" "${as4_transport_surface[@]}"
check_no_matches "transport must not carry SOAP 1.1 envelope namespace token" "schemas.xmlsoap.org/soap/envelope" "${as4_transport_surface[@]}"

check_no_matches "SOAP 1.1 envelope namespace token must not appear in src/ or xtask/ surfaces" "schemas.xmlsoap.org/soap/envelope" src xtask

check_matches_confined_to_paths \
  "SOAP 1.1 envelope namespace token in tests must stay confined to explicit adversarial fixtures" \
  "schemas.xmlsoap.org/soap/envelope" \
  "^tests/as4_ebms_adversarial\.rs$" \
  tests

if [[ "$fail" -ne 0 ]]; then
  exit 1
fi

echo "[as4-strict-deprecations] ok"
