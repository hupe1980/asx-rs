use crate::core::{AsxError, ErrorCode, ErrorContext, Result};
use smallvec::SmallVec;
use std::collections::HashMap;
use std::sync::Arc;

/// Header list optimized for common small cardinalities.
///
/// Typical AS2/AS4 exchanges carry fewer than 16 headers; storing these
/// inline avoids one heap allocation for the header vector itself.
pub type HttpHeaders = SmallVec<[(String, String); 16]>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpEndpointPolicy {
    pub allow_absolute_path_targets: bool,
    pub allowed_absolute_path_prefixes: Vec<String>,
    pub allowed_uri_schemes: Vec<String>,
    pub allowed_uri_authorities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartnerEndpointGovernance {
    pub default_policy: HttpEndpointPolicy,
    pub partner_policies: HashMap<String, HttpEndpointPolicy>,
}

impl PartnerEndpointGovernance {
    pub fn ingress_strict() -> Self {
        Self {
            default_policy: HttpEndpointPolicy::ingress_strict(),
            partner_policies: HashMap::new(),
        }
    }

    pub fn with_partner_policy(
        mut self,
        partner_id: impl Into<String>,
        policy: HttpEndpointPolicy,
    ) -> Self {
        self.partner_policies
            .insert(partner_id.into().to_ascii_lowercase(), policy);
        self
    }

    pub fn policy_for_partner(&self, partner_id: &str) -> &HttpEndpointPolicy {
        self.partner_policies
            .get(&partner_id.to_ascii_lowercase())
            .unwrap_or(&self.default_policy)
    }
}

impl HttpEndpointPolicy {
    pub fn ingress_strict() -> Self {
        Self {
            allow_absolute_path_targets: true,
            allowed_absolute_path_prefixes: vec!["/as2".into(), "/as4".into()],
            allowed_uri_schemes: vec!["https".into()],
            allowed_uri_authorities: Vec::new(),
        }
    }

    pub fn with_allowed_path_prefix(mut self, path_prefix: impl Into<String>) -> Self {
        let mut prefix = path_prefix.into();
        if !prefix.starts_with('/') {
            prefix = format!("/{prefix}");
        }
        self.allowed_absolute_path_prefixes.push(prefix);
        self
    }

    pub fn with_allowed_authority(mut self, authority: impl Into<String>) -> Self {
        self.allowed_uri_authorities
            .push(authority.into().to_ascii_lowercase());
        self
    }

    fn allows_target(&self, uri: &str) -> bool {
        if uri.starts_with('/') {
            return self.allow_absolute_path_targets
                && self
                    .allowed_absolute_path_prefixes
                    .iter()
                    .any(|prefix| uri.starts_with(prefix));
        }

        let Some((scheme, authority)) = parse_absolute_uri_target(uri) else {
            return false;
        };

        let scheme_allowed = !self.allowed_uri_schemes.is_empty()
            && self
                .allowed_uri_schemes
                .iter()
                .any(|configured| configured.eq_ignore_ascii_case(scheme));
        if !scheme_allowed {
            return false;
        }

        self.allowed_uri_authorities
            .iter()
            .any(|configured| configured.eq_ignore_ascii_case(authority))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: String,
    pub uri: String,
    pub headers: HttpHeaders,
    pub body: Arc<[u8]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedHttpRequest(HttpRequest);

impl ValidatedHttpRequest {
    pub fn into_inner(self) -> HttpRequest {
        self.0
    }
}

impl std::ops::Deref for ValidatedHttpRequest {
    type Target = HttpRequest;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl HttpRequest {
    pub fn into_validated(self) -> Result<ValidatedHttpRequest> {
        self.validate()?;
        Ok(ValidatedHttpRequest(self))
    }

    pub fn into_validated_with_policy(
        self,
        policy: &HttpEndpointPolicy,
    ) -> Result<ValidatedHttpRequest> {
        self.validate_with_policy(policy)?;
        Ok(ValidatedHttpRequest(self))
    }

    pub fn into_validated_for_partner(
        self,
        partner_id: &str,
        governance: &PartnerEndpointGovernance,
    ) -> Result<ValidatedHttpRequest> {
        self.validate_for_partner(partner_id, governance)?;
        Ok(ValidatedHttpRequest(self))
    }

    pub fn validate(&self) -> Result<()> {
        self.validate_with_policy(&HttpEndpointPolicy::ingress_strict())
    }

    pub fn validate_with_policy(&self, policy: &HttpEndpointPolicy) -> Result<()> {
        let method = self.method.trim();
        if method.is_empty() {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                "http method must not be empty",
                ErrorContext::new("http_request_validation"),
            ));
        }

        if method != self.method {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                "http method must not contain leading/trailing whitespace",
                ErrorContext::new("http_request_validation"),
            ));
        }

        if !is_valid_http_method_token(method) {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                "http method must be a valid RFC token",
                ErrorContext::new("http_request_validation"),
            ));
        }

        let uri = self.uri.trim();
        if uri.is_empty() {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                "http uri must not be empty",
                ErrorContext::new("http_request_validation"),
            ));
        }

        if uri != self.uri {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                "http uri must not contain leading/trailing whitespace",
                ErrorContext::new("http_request_validation"),
            ));
        }

        if !is_valid_http_request_uri(uri) {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                "http uri must be an absolute URI or absolute path without control/space characters",
                ErrorContext::new("http_request_validation"),
            ));
        }

        if !policy.allows_target(uri) {
            return Err(AsxError::new(
                ErrorCode::PolicyViolation,
                "http request target is not allowed by endpoint policy",
                ErrorContext::new("http_request_validation"),
            ));
        }

        Ok(())
    }

    pub fn validate_for_partner(
        &self,
        partner_id: &str,
        governance: &PartnerEndpointGovernance,
    ) -> Result<()> {
        if partner_id.trim().is_empty() {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                "partner_id must not be empty for endpoint governance validation",
                ErrorContext::new("http_request_validation"),
            ));
        }

        self.validate_with_policy(governance.policy_for_partner(partner_id))
    }
}

fn is_valid_http_method_token(method: &str) -> bool {
    method.bytes().all(is_valid_http_token_char)
}

fn is_valid_http_token_char(b: u8) -> bool {
    matches!(b,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' |
        b'^' | b'_' | b'`' | b'|' | b'~' |
        b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z')
}

fn is_valid_http_request_uri(uri: &str) -> bool {
    if uri.bytes().any(|b| b <= 0x20 || b == 0x7f) {
        return false;
    }

    // Allow absolute-path form and strict absolute-URI form for ingress parsing boundaries.
    if uri.starts_with('/') {
        return !uri.contains('#');
    }

    is_valid_absolute_uri(uri)
}

fn is_valid_absolute_uri(uri: &str) -> bool {
    let Some((scheme, authority)) = parse_absolute_uri_target(uri) else {
        return false;
    };

    !scheme.is_empty() && !authority.is_empty()
}

fn parse_absolute_uri_target(uri: &str) -> Option<(&str, &str)> {
    let scheme_sep = uri.find("://")?;
    let scheme = &uri[..scheme_sep];
    if !is_valid_uri_scheme(scheme) {
        return None;
    }

    let rest = &uri[scheme_sep + 3..];
    if rest.is_empty() || uri.contains('#') {
        return None;
    }

    let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty() {
        return None;
    }

    if authority.starts_with('[') && !authority.contains(']') {
        return None;
    }

    if authority
        .bytes()
        .any(|b| b <= 0x20 || b == 0x7f || b == b'/' || b == b'\\')
    {
        return None;
    }

    Some((scheme, authority))
}

fn is_valid_uri_scheme(scheme: &str) -> bool {
    if scheme.is_empty() {
        return false;
    }

    let mut bytes = scheme.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };

    if !first.is_ascii_alphabetic() {
        return false;
    }

    bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: HttpHeaders,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

#[cfg(feature = "client")]
#[derive(Debug, Clone, Default)]
pub struct ClientRuntime {
    pub user_agent: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_request() -> HttpRequest {
        HttpRequest {
            method: "POST".into(),
            uri: "https://partner.example/as2".into(),
            headers: HttpHeaders::new(),
            body: vec![].into(),
        }
    }

    #[test]
    fn request_validation_accepts_absolute_uri_and_path_forms() {
        let mut absolute_path = base_request();
        absolute_path.uri = "/as2/inbox".to_string();
        absolute_path
            .validate()
            .expect("absolute path form must pass");

        let absolute_uri = base_request();
        let err = absolute_uri
            .validate()
            .expect_err("default ingress policy must reject absolute URI targets");
        assert_eq!(err.code, ErrorCode::PolicyViolation);

        absolute_uri
            .validate_with_policy(
                &HttpEndpointPolicy::ingress_strict().with_allowed_authority("partner.example"),
            )
            .expect("allowlisted authority must pass");

        let mut non_allowlisted_path = base_request();
        non_allowlisted_path.uri = "/unknown/inbox".to_string();
        let err = non_allowlisted_path
            .validate()
            .expect_err("non-allowlisted absolute path must fail");
        assert_eq!(err.code, ErrorCode::PolicyViolation);

        non_allowlisted_path
            .validate_with_policy(
                &HttpEndpointPolicy::ingress_strict().with_allowed_path_prefix("/unknown"),
            )
            .expect("explicit path-prefix allowlist must pass");
    }

    #[test]
    fn request_validation_rejects_invalid_method_tokens() {
        let mut request = base_request();
        request.method = "PO ST".to_string();
        let err = request.validate().expect_err("space in method must fail");
        assert_eq!(err.code, ErrorCode::InvalidInput);

        request.method = "POST\n".to_string();
        let err = request
            .validate()
            .expect_err("control character in method must fail");
        assert_eq!(err.code, ErrorCode::InvalidInput);
    }

    #[test]
    fn request_validation_rejects_invalid_uri_forms() {
        let mut request = base_request();
        request.uri = "as2/inbox".to_string();
        let err = request
            .validate()
            .expect_err("relative URI without slash must fail");
        assert_eq!(err.code, ErrorCode::InvalidInput);

        request.uri = "https://partner.example/as2 inbox".to_string();
        let err = request.validate().expect_err("URI with spaces must fail");
        assert_eq!(err.code, ErrorCode::InvalidInput);

        request.uri = "foo://".to_string();
        let err = request
            .validate()
            .expect_err("absolute URI without authority must fail");
        assert_eq!(err.code, ErrorCode::InvalidInput);

        request.uri = "1http://partner.example/as2".to_string();
        let err = request
            .validate()
            .expect_err("scheme must start with alphabetic character");
        assert_eq!(err.code, ErrorCode::InvalidInput);

        request.uri = "https://partner.example/as2#frag".to_string();
        let err = request.validate().expect_err("URI fragments must fail");
        assert_eq!(err.code, ErrorCode::InvalidInput);
    }

    #[test]
    fn request_validation_for_partner_applies_governance_map() {
        let mut request = base_request();
        request.uri = "https://partner-a.example/as2".to_string();

        let governance = PartnerEndpointGovernance::ingress_strict().with_partner_policy(
            "partner-a",
            HttpEndpointPolicy::ingress_strict().with_allowed_authority("partner-a.example"),
        );

        request
            .validate_for_partner("partner-a", &governance)
            .expect("partner-specific authority allowlist must pass");

        let err = request
            .validate_for_partner("partner-b", &governance)
            .expect_err("default policy must reject non-allowlisted absolute URI target");
        assert_eq!(err.code, ErrorCode::PolicyViolation);

        request.uri = "/partner-a/inbox".to_string();
        let governance = governance.with_partner_policy(
            "partner-a",
            HttpEndpointPolicy::ingress_strict().with_allowed_path_prefix("/partner-a"),
        );
        request
            .validate_for_partner("partner-a", &governance)
            .expect("partner-specific path-prefix allowlist must pass");
    }

    #[test]
    fn request_validation_rejects_absolute_uri_when_scheme_allowlist_empty() {
        let request = HttpRequest {
            method: "POST".into(),
            uri: "https://partner.example/as2".into(),
            headers: HttpHeaders::new(),
            body: vec![].into(),
        };

        let policy = HttpEndpointPolicy {
            allow_absolute_path_targets: false,
            allowed_absolute_path_prefixes: Vec::new(),
            allowed_uri_schemes: Vec::new(),
            allowed_uri_authorities: vec!["partner.example".into()],
        };

        let err = request
            .validate_with_policy(&policy)
            .expect_err("empty scheme allowlist must fail closed");
        assert_eq!(err.code, ErrorCode::PolicyViolation);
    }

    #[test]
    fn into_validated_for_partner_preserves_request_bytes() {
        let request = HttpRequest {
            method: "POST".into(),
            uri: "/as2/inbox".into(),
            headers: HttpHeaders::from_vec(vec![(
                "Content-Type".into(),
                "multipart/signed; boundary=abc".into(),
            )]),
            body: vec![1, 2, 3, 4].into(),
        };

        let validated = request
            .clone()
            .into_validated_for_partner("partner-a", &PartnerEndpointGovernance::ingress_strict())
            .expect("validated request");

        assert_eq!(validated.method, request.method);
        assert_eq!(validated.uri, request.uri);
        assert_eq!(validated.headers, request.headers);
        assert_eq!(validated.body, request.body);
    }
}
