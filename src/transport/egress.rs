//! The egress address filter (SSRF) and the response-body cap. The built-in
//! [`crate::HttpClient`]'s connector (`transport::connector`) applies the
//! filter to every connection it makes (messages, revocation fetches, SMP).

use crate::core::{AsxError, ErrorCode, ErrorContext, Result};

/// Returns `true` when `addr` is a private/loopback/link-local/otherwise
/// non-globally-routable address that an egress transport must never contact
/// (SSRF defence).
///
/// IPv6 addresses are first mapped to their canonical form via
/// [`std::net::IpAddr::to_canonical`], so an IPv4-mapped address such as
/// `::ffff:127.0.0.1` or `::ffff:169.254.169.254` is evaluated under the IPv4
/// rules rather than slipping through as an ordinary public v6 address.
pub(crate) fn is_private_ip(addr: std::net::IpAddr) -> bool {
    // Collapse IPv4-mapped/compatible v6 addresses (e.g. `::ffff:127.0.0.1`)
    // down to their embedded IPv4 form before classification.
    match addr.to_canonical() {
        std::net::IpAddr::V4(ip) => is_private_ipv4(ip),
        std::net::IpAddr::V6(ip) => is_private_ipv6(ip),
    }
}

/// IPv4 ranges that must not be reachable from egress.
fn is_private_ipv4(ip: std::net::Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    ip.is_loopback()            // 127.0.0.0/8
        || ip.is_private()      // 10/8, 172.16/12, 192.168/16
        || ip.is_link_local()   // 169.254.0.0/16 (incl. cloud metadata 169.254.169.254)
        || ip.is_broadcast()    // 255.255.255.255
        || ip.is_documentation()// 192.0.2/24, 198.51.100/24, 203.0.113/24
        || ip.is_multicast()    // 224.0.0.0/4
        || a == 0               // 0.0.0.0/8 ("this host"; 0.0.0.0 routes to localhost)
        || (a == 100 && (64..=127).contains(&b)) // 100.64.0.0/10 carrier-grade NAT
        || (a == 192 && b == 0) // 192.0.0.0/24 IETF protocol assignments
        || (a == 198 && (b == 18 || b == 19)) // 198.18.0.0/15 benchmarking (RFC 2544)
        || a >= 240 // 240.0.0.0/4 reserved (incl. 255/8)
}

/// IPv6 ranges that must not be reachable from egress.
///
/// Transition addresses that embed an IPv4 address — NAT64 `64:ff9b::/96`
/// (RFC 6052) and `64:ff9b:1::/48` (RFC 8215), 6to4 `2002::/16` (RFC 3056)
/// and IPv4-compatible `::/96` — are judged by the IPv4 they embed. Teredo
/// `2001::/32` (RFC 4380) is refused wholesale: its embedded server address is
/// not the destination.
fn is_private_ipv6(ip: std::net::Ipv6Addr) -> bool {
    let seg = ip.segments();
    let low32 = std::net::Ipv4Addr::new(
        (seg[6] >> 8) as u8,
        seg[6] as u8,
        (seg[7] >> 8) as u8,
        seg[7] as u8,
    );
    let nat64_wkp = seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2..6] == [0, 0, 0, 0];
    let nat64_local = seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2] == 0x0001;
    let ipv4_compatible = seg[0..6] == [0, 0, 0, 0, 0, 0];
    if nat64_wkp || nat64_local || ipv4_compatible {
        // `::` and `::1` fall here and are private as 0.0.0.0/8.
        return is_private_ipv4(low32);
    }
    if seg[0] == 0x2002 {
        let embedded = std::net::Ipv4Addr::new(
            (seg[1] >> 8) as u8,
            seg[1] as u8,
            (seg[2] >> 8) as u8,
            seg[2] as u8,
        );
        return is_private_ipv4(embedded);
    }

    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        // unique-local fc00::/7
        || (seg[0] & 0xfe00) == 0xfc00
        // link-local fe80::/10
        || (seg[0] & 0xffc0) == 0xfe80
        // Teredo 2001::/32
        || (seg[0] == 0x2001 && seg[1] == 0x0000)
        // documentation 2001:db8::/32
        || (seg[0] == 0x2001 && seg[1] == 0x0db8)
        // discard-only 100::/64 (RFC 6666)
        || seg[0..4] == [0x0100, 0, 0, 0]
}

/// Returns `true` when `host` is a private/loopback/link-local address or
/// hostname that should not be contacted from an egress transport.
pub(crate) fn is_private_host(host: &str) -> bool {
    // Named loopback hostnames.
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }

    // Try to parse as an IP address (bare or bracket-wrapped).
    let h_lower = host.to_ascii_lowercase();
    let h_bare = h_lower.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = h_bare.parse::<std::net::IpAddr>() {
        return is_private_ip(ip);
    }

    false
}

// ── Response bodies ─────────────────────────────────────────────────────────

/// Read a response body, refusing more than `cap` bytes with
/// [`ErrorCode::PayloadTooLarge`].
///
/// A declared `Content-Length` over the cap is refused before anything is
/// read; otherwise frames are accumulated until the cap would be exceeded, so
/// at most `cap` plus one frame is ever buffered. Every response the built-in
/// client reads (partner sends, SMP, CRL, OCSP) goes through here: the peer
/// chooses its size.
pub(crate) async fn read_body_capped(
    response: http::Response<hyper::body::Incoming>,
    cap: usize,
    stage: &'static str,
) -> Result<bytes::Bytes> {
    use http_body_util::BodyExt;
    let too_large = |size: String| {
        AsxError::new(
            ErrorCode::PayloadTooLarge,
            format!("response body {size} exceeds the {cap} byte limit"),
            ErrorContext::new(stage),
        )
    };
    let declared = response
        .headers()
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok());
    if let Some(declared) = declared
        && declared > cap as u64
    {
        return Err(too_large(format!("of {declared} bytes (Content-Length)")));
    }
    let mut incoming = response.into_body();
    let mut body = bytes::BytesMut::new();
    while let Some(frame) = incoming.frame().await {
        let frame = frame.map_err(|err| {
            AsxError::new(
                ErrorCode::TransportFailure,
                format!("failed to read response body: {err}"),
                ErrorContext::new(stage),
            )
        })?;
        let Ok(chunk) = frame.into_data() else {
            continue; // trailers
        };
        if body.len().saturating_add(chunk.len()) > cap {
            return Err(too_large(format!(
                "of more than {} bytes",
                body.len().saturating_add(chunk.len())
            )));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body.freeze())
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_and_reserved_ranges_are_private() {
        for addr in [
            "127.0.0.1",
            "127.1.2.3",
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.100",
            "169.254.1.1",
            "169.254.169.254",
            "0.0.0.0",
            "100.64.0.1",
            "203.0.113.9",
            "::1",
            "fc00::1",
            "fd12:3456:789a::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "::ffff:10.0.0.1",
        ] {
            let ip: std::net::IpAddr = addr.parse().expect(addr);
            assert!(is_private_ip(ip), "{addr} must be private");
        }
        for host in ["localhost", "LOCALHOST", "[::1]", "127.0.0.1"] {
            assert!(is_private_host(host), "{host}");
        }
        assert!(!is_private_host("example.org"));
    }

    #[test]
    fn transition_benchmark_and_documentation_ranges_are_private() {
        let private = [
            "64:ff9b::10.0.0.1", // NAT64 (RFC 6052) embedding 10.0.0.1
            "64:ff9b:1::a00:1",  // local-use NAT64 (RFC 8215) embedding 10.0.0.1
            "2002:0a00:0001::1", // 6to4 (RFC 3056) embedding 10.0.0.1
            "::10.0.0.1",        // IPv4-compatible
            "2001:0::1",         // Teredo (RFC 4380)
            "198.18.0.1",        // benchmarking (RFC 2544)
            "2001:db8::1",       // documentation
            "100::1",            // discard-only (RFC 6666)
        ];
        for addr in private {
            let ip: std::net::IpAddr = addr.parse().expect(addr);
            assert!(is_private_ip(ip), "{addr} must be private");
        }
        let public = [
            "64:ff9b::8.8.8.8",
            "2002:0808:0808::1",
            "8.8.8.8",
            "2606:4700::1111",
        ];
        for addr in public {
            let ip: std::net::IpAddr = addr.parse().expect(addr);
            assert!(!is_private_ip(ip), "{addr} must stay public");
        }
    }
}
