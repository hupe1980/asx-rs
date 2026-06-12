/// OCSP responder URL discovery from X.509 certificates
/// Implements extraction of Authority Info Access (AIA) extension values
use openssl::x509::X509;

/// Discover OCSP responder URLs from a certificate's Authority Info Access extension
///
/// RFC 5280 §4.2.2.1 defines the Authority Info Access extension which can contain
/// OCSP responder URLs. This function extracts all OCSP URLs from a given certificate.
///
/// Note: This is a simplified implementation that parses the certificate's text representation.
/// For production use with complex multi-valued extensions, consider using full ASN.1 parsing.
///
/// # Arguments
/// * `cert` - The X.509 certificate to inspect
///
/// # Returns
/// A vector of OCSP responder URLs found in the certificate's AIA extension
pub fn discover_ocsp_responder_urls(cert: &X509) -> Vec<String> {
    let mut urls = Vec::new();

    // Get the certificate text representation and search for OCSP URLs
    if let Ok(text_bytes) = cert.to_text() {
        if let Ok(text_str) = std::str::from_utf8(&text_bytes) {
            urls = extract_ocsp_urls_from_text(text_str);
        }
    } else if let Ok(pem) = cert.to_pem()
        && let Ok(pem_str) = std::str::from_utf8(&pem)
    {
        urls = extract_ocsp_urls_from_text(pem_str);
    }

    urls
}

/// Extract OCSP URLs from certificate text representation
fn extract_ocsp_urls_from_text(text: &str) -> Vec<String> {
    let mut urls = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Look for Authority Info Access section which contains OCSP URLs
    let lines: Vec<&str> = text.lines().collect();

    for (i, line) in lines.iter().enumerate() {
        // Check for Authority Info Access extension marker
        if line.contains("Authority Info Access") {
            // Check following lines for OCSP URLs (up to 20 lines ahead)
            let search_end = std::cmp::min(i + 20, lines.len());
            for (j, next_line) in lines
                .iter()
                .enumerate()
                .skip(i + 1)
                .take(search_end - i - 1)
            {
                // Look for URI: entries which contain OCSP URLs
                if next_line.trim_start().starts_with("URI:")
                    && let Some(url) = extract_url_from_line(next_line)
                    && seen.insert(url.clone())
                {
                    urls.push(url);
                }

                // Stop if we hit another extension
                if j > i + 1 && next_line.contains("X509v3") {
                    break;
                }
            }
        }
    }

    urls
}

/// Extract a URL from a certificate text line
fn extract_url_from_line(line: &str) -> Option<String> {
    if let Some(uri_pos) = line.find("URI:") {
        let after_uri = &line[uri_pos + 4..].trim_start();

        // Find end of URL (space, comma, newline, or end of string)
        let end_pos = after_uri
            .find(|c: char| c.is_whitespace() || c == ',' || c == ';')
            .unwrap_or(after_uri.len());

        let url = &after_uri[..end_pos].trim();

        if url.starts_with("http://") || url.starts_with("https://") {
            Some(url.to_string())
        } else {
            None
        }
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_url_from_line_valid_http() {
        let line = "    OCSP - URI:http://ocsp.example.com/";
        let url = extract_url_from_line(line);
        assert_eq!(url, Some("http://ocsp.example.com/".to_string()));
    }

    #[test]
    fn test_extract_url_from_line_valid_https() {
        let line = "    OCSP - URI:https://ocsp.example.com/, Other:value";
        let url = extract_url_from_line(line);
        assert_eq!(url, Some("https://ocsp.example.com/".to_string()));
    }

    #[test]
    fn test_extract_url_from_line_invalid_protocol() {
        let line = "    OCSP - URI:ftp://ocsp.example.com/";
        let url = extract_url_from_line(line);
        assert_eq!(url, None);
    }

    #[test]
    fn test_extract_url_from_line_no_uri() {
        let line = "    Some other line";
        let url = extract_url_from_line(line);
        assert_eq!(url, None);
    }

    #[test]
    fn test_extract_url_from_line_with_whitespace() {
        let line = "  URI:http://ocsp.example.com/path  ";
        let url = extract_url_from_line(line);
        assert_eq!(url, Some("http://ocsp.example.com/path".to_string()));
    }

    #[test]
    fn test_extract_ocsp_urls_empty_text() {
        let text = "";
        let urls = extract_ocsp_urls_from_text(text);
        assert!(urls.is_empty());
    }

    #[test]
    fn test_extract_ocsp_urls_no_aia_section() {
        let text = r#"
        Certificate:
            Data:
                Subject: CN=example.com
        "#;

        let urls = extract_ocsp_urls_from_text(text);
        assert!(urls.is_empty());
    }
}
