use super::As2MicAlgorithm;

/// Parse the `signed-receipt-micalg` value from a Disposition-Notification-Options header.
pub(crate) fn parse_signed_receipt_micalg(options: &str) -> Option<As2MicAlgorithm> {
    for param in options.split(';') {
        let mut parts = param.splitn(2, '=');
        let key = parts.next().map(str::trim).unwrap_or_default();
        if !key.eq_ignore_ascii_case("signed-receipt-micalg") {
            continue;
        }

        let value = parts
            .next()
            .map(str::trim)
            .unwrap_or_default()
            .trim_matches('"');

        for token in value.split(',') {
            let token = token.trim();
            if token.eq_ignore_ascii_case("sha-256") || token.eq_ignore_ascii_case("sha256") {
                return Some(As2MicAlgorithm::Sha256);
            }
            if token.eq_ignore_ascii_case("sha-384") || token.eq_ignore_ascii_case("sha384") {
                return Some(As2MicAlgorithm::Sha384);
            }
            if token.eq_ignore_ascii_case("sha-512") || token.eq_ignore_ascii_case("sha512") {
                return Some(As2MicAlgorithm::Sha512);
            }
        }
    }
    None
}
