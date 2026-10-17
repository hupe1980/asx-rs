//! Minimal RFC 3339 date/time helpers on `std::time`: protocol timestamp
//! generation, inbound timestamp parsing and the audit record's millisecond
//! form. Calendar arithmetic works on signed Unix epoch seconds.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Public(crate) API
// ---------------------------------------------------------------------------

/// Signed Unix seconds of `t` (negative before 1970).
pub(crate) fn unix_secs(t: SystemTime) -> i64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
        Err(e) => i64::try_from(e.duration().as_secs()).map_or(i64::MIN, |s| -s),
    }
}

/// Unix seconds of an OpenSSL-printed ASN.1 time (`ASN1_TIME_print`:
/// `"Jan  2 03:04:05 2026 GMT"`, optionally with fractional seconds, which are
/// dropped). The only way to read an `Asn1GeneralizedTimeRef` without unsafe
/// code.
pub(crate) fn parse_openssl_print_time(s: &str) -> Option<i64> {
    let mut it = s.split_whitespace();
    let month = match it.next()? {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    let day: i64 = it.next()?.parse().ok()?;
    let hms = it.next()?;
    let hms = hms.split('.').next()?;
    let mut parts = hms.split(':').map(|p| p.parse::<i64>().ok());
    let (h, mi, sec) = (parts.next()??, parts.next()??, parts.next()??);
    let year: i64 = it.next()?.parse().ok()?;
    if it.next()? != "GMT" || it.next().is_some() {
        return None;
    }
    if !(1..=31).contains(&day) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    let days = calendar_to_days(year, month, day)?;
    Some(days * 86_400 + h * 3600 + mi * 60 + sec)
}

/// Format a [`SystemTime`] as `YYYY-MM-DDTHH:MM:SSZ` (RFC 3339 UTC, second
/// precision). A time before the Unix epoch formats as the epoch.
pub(crate) fn format_rfc3339_secs(t: SystemTime) -> String {
    let epoch_secs = t
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs() as i64;
    let (y, mo, d, h, mi, s) = epoch_secs_to_calendar(epoch_secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// Format a [`SystemTime`] as RFC 3339 UTC with exactly three fractional
/// digits: `YYYY-MM-DDTHH:MM:SS.mmmZ` (the audit record's `recorded_at`).
pub(crate) fn format_rfc3339_millis(t: SystemTime) -> String {
    let since = t.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
    let (y, mo, d, h, mi, s) = epoch_secs_to_calendar(since.as_secs() as i64);
    let ms = since.subsec_millis();
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{ms:03}Z")
}

/// Parse exactly the form [`format_rfc3339_millis`] writes. Anything else —
/// another precision, an offset, a missing `Z` — is `None`: the stored form
/// is a contract, not a liberal input.
pub(crate) fn parse_rfc3339_millis(s: &str) -> Option<SystemTime> {
    let b = s.as_bytes();
    if b.len() != 24 || b[19] != b'.' || b[23] != b'Z' {
        return None;
    }
    let secs = parse_rfc3339_to_unix_secs(s)?;
    let ms = parse_fixed::<3>(&b[20..23])?;
    let secs = u64::try_from(secs).ok()?;
    Some(UNIX_EPOCH + Duration::from_secs(secs) + Duration::from_millis(ms))
}

/// Parse an RFC 3339 timestamp string and return the number of seconds since
/// the Unix epoch (1970-01-01T00:00:00Z), or `None` on any parse failure.
///
/// Accepted forms:
/// - `YYYY-MM-DDTHH:MM:SSZ`
/// - `YYYY-MM-DDTHH:MM:SS.fZ` (fractional seconds — fraction is discarded)
/// - `YYYY-MM-DDTHH:MM:SS+HH:MM` / `…-HH:MM` (timezone offset)
/// - `T` may be lowercase `t`
///
/// Restrictions:
/// - Year must be in `[0001, 9999]`.
/// - Month and day are checked for gross invalidity (`>12`, `>31`) but
///   day-of-month precision (e.g. day 31 in a 30-day month) is not enforced —
///   AS4 gateways always produce well-formed timestamps.
pub(crate) fn parse_rfc3339_to_unix_secs(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    // Minimum valid form: "2026-01-02T03:04:05Z" = 20 bytes
    if b.len() < 20 {
        return None;
    }

    if b[4] != b'-' || b[7] != b'-' || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let sep = b[10];
    if sep != b'T' && sep != b't' {
        return None;
    }

    let year = parse_fixed::<4>(&b[0..4])? as i64;
    let month = parse_fixed::<2>(&b[5..7])? as i64;
    let day = parse_fixed::<2>(&b[8..10])? as i64;
    let hour = parse_fixed::<2>(&b[11..13])? as i64;
    let min = parse_fixed::<2>(&b[14..16])? as i64;
    let sec = parse_fixed::<2>(&b[17..19])? as i64;

    // Skip optional fractional seconds (e.g. `.789` or `.123456`)
    let mut pos = 19usize;
    if b.get(pos) == Some(&b'.') {
        pos += 1;
        while pos < b.len() && b[pos].is_ascii_digit() {
            pos += 1;
        }
    }

    let offset_secs: i64 = match b.get(pos) {
        Some(&b'Z') | Some(&b'z') => 0,
        Some(&b'+') | Some(&b'-') => {
            if b.len() < pos + 6 {
                return None;
            }
            let sign: i64 = if b[pos] == b'+' { 1 } else { -1 };
            let oh = parse_fixed::<2>(&b[pos + 1..pos + 3])? as i64;
            if b.get(pos + 3) != Some(&b':') {
                return None;
            }
            let om = parse_fixed::<2>(&b[pos + 4..pos + 6])? as i64;
            if oh > 23 || om > 59 {
                return None;
            }
            sign * (oh * 3600 + om * 60)
        }
        _ => return None,
    };

    // Gross range validation
    if !(1..=9999).contains(&year) || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    if hour > 23 || min > 59 || sec > 60 {
        // sec == 60 is a valid leap-second value in RFC 3339
        return None;
    }

    let days = calendar_to_days(year, month, day)?;
    let utc_secs = days * 86400 + hour * 3600 + min * 60 + sec - offset_secs;
    Some(utc_secs)
}

// ---------------------------------------------------------------------------
// Internal calendar arithmetic (Howard Hinnant's era-based algorithm)
// ---------------------------------------------------------------------------

/// Convert an RFC 3339 / proleptic-Gregorian calendar date to days since
/// the Unix epoch (1970-01-01).
///
/// Returns `None` only if `calendar_to_days` encounters an out-of-range date
/// (should not happen given the range checks above).
fn calendar_to_days(y: i64, m: i64, d: i64) -> Option<i64> {
    // Shift Jan/Feb to the previous year so the leap day falls at year-end.
    let y = if m <= 2 { y - 1 } else { y };
    let m = if m <= 2 { m + 9 } else { m - 3 };

    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400); // year-of-era [0, 399]
    let doy = (153 * m + 2) / 5 + d - 1; // day-of-year [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // day-of-era [0, 146096]
    let z = era * 146097 + doe; // days since 0000-03-01

    // Shift from 0000-03-01 epoch to 1970-01-01 epoch.
    Some(z - 719468)
}

/// Convert Unix epoch seconds to `(year, month, day, hour, minute, second)`.
///
/// Inverse of [`calendar_to_days`] combined with time-of-day decomposition.
/// Correct for the full `i64` range; used with clock readings.
fn epoch_secs_to_calendar(secs: i64) -> (i32, u8, u8, u8, u8, u8) {
    let z = secs.div_euclid(86400) + 719468;
    let era = z.div_euclid(146097) as i32;
    let doe = z.rem_euclid(146097) as u64;
    let yoe = (doe - doe / 1461 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i32 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u8;
    let mo = if mp < 10 { mp as u8 + 3 } else { mp as u8 - 9 };
    let y = if mo <= 2 { y + 1 } else { y };

    let tod = secs.rem_euclid(86400) as u64;
    let h = (tod / 3600) as u8;
    let mi = ((tod % 3600) / 60) as u8;
    let s = (tod % 60) as u8;

    (y, mo, d, h, mi, s)
}

/// Parse exactly `N` ASCII decimal digits into a `u64`.
#[inline]
fn parse_fixed<const N: usize>(b: &[u8]) -> Option<u64> {
    if b.len() != N {
        return None;
    }
    let mut n: u64 = 0;
    for &c in b {
        if !c.is_ascii_digit() {
            return None;
        }
        n = n * 10 + (c - b'0') as u64;
    }
    Some(n)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {

    #[test]
    fn openssl_printed_times_parse_to_unix_seconds() {
        use openssl::asn1::Asn1Time;
        for secs in [0_i64, 86_399, 1_700_000_000, 1_767_225_600, 4_102_444_799] {
            let printed = Asn1Time::from_unix(secs).unwrap().to_string();
            assert_eq!(parse_openssl_print_time(&printed), Some(secs), "{printed}");
        }
        assert_eq!(
            parse_openssl_print_time("Jan  2 03:04:05.123 2026 GMT"),
            parse_openssl_print_time("Jan  2 03:04:05 2026 GMT")
        );
        assert_eq!(parse_openssl_print_time("Foo  2 03:04:05 2026 GMT"), None);
        assert_eq!(parse_openssl_print_time("Jan  2 03:04:05 2026 CET"), None);
        assert_eq!(parse_openssl_print_time(""), None);
    }

    #[test]
    fn unix_secs_is_signed() {
        assert_eq!(unix_secs(UNIX_EPOCH + Duration::from_secs(5)), 5);
        assert_eq!(unix_secs(UNIX_EPOCH - Duration::from_secs(5)), -5);
    }

    use super::*;

    #[test]
    fn unix_epoch_formats_correctly() {
        assert_eq!(format_rfc3339_secs(UNIX_EPOCH), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn known_date_formats_correctly() {
        // 2000-01-01T00:00:00Z = 10957 days * 86400 s/day
        let t = UNIX_EPOCH + Duration::from_secs(10957 * 86400);
        assert_eq!(format_rfc3339_secs(t), "2000-01-01T00:00:00Z");
    }

    #[test]
    fn format_rfc3339_round_trip() {
        let secs = 1_748_000_000u64; // a specific plausible timestamp
        let t = UNIX_EPOCH + Duration::from_secs(secs);
        let s = format_rfc3339_secs(t);
        let parsed = parse_rfc3339_to_unix_secs(&s).expect("should parse back");
        assert_eq!(parsed, secs as i64);
    }

    #[test]
    fn parse_utc_z_suffix() {
        let secs = parse_rfc3339_to_unix_secs("2026-05-27T12:34:56Z").unwrap();
        assert_eq!(
            format_rfc3339_secs(UNIX_EPOCH + Duration::from_secs(secs as u64)),
            "2026-05-27T12:34:56Z"
        );
    }

    #[test]
    fn parse_positive_offset() {
        // +02:00 → subtract 2h for UTC
        let a = parse_rfc3339_to_unix_secs("2026-05-27T14:34:56+02:00").unwrap();
        let b = parse_rfc3339_to_unix_secs("2026-05-27T12:34:56Z").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn parse_negative_offset() {
        // -05:00 → add 5h for UTC
        let a = parse_rfc3339_to_unix_secs("2026-05-27T07:34:56-05:00").unwrap();
        let b = parse_rfc3339_to_unix_secs("2026-05-27T12:34:56Z").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn parse_fractional_seconds_discarded() {
        let a = parse_rfc3339_to_unix_secs("2026-05-27T12:34:56.789Z").unwrap();
        let b = parse_rfc3339_to_unix_secs("2026-05-27T12:34:56Z").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn parse_known_unix_epoch_2000() {
        // 2000-01-01T00:00:00Z is exactly 10957 days after 1970-01-01
        let secs = parse_rfc3339_to_unix_secs("2000-01-01T00:00:00Z").unwrap();
        assert_eq!(secs, 10957 * 86400);
    }

    #[test]
    fn reject_too_short() {
        assert!(parse_rfc3339_to_unix_secs("2026-05-27").is_none());
        assert!(parse_rfc3339_to_unix_secs("").is_none());
    }

    #[test]
    fn reject_missing_timezone() {
        assert!(parse_rfc3339_to_unix_secs("2026-05-27T12:34:56").is_none());
    }

    #[test]
    fn reject_invalid_month() {
        assert!(parse_rfc3339_to_unix_secs("2026-13-01T00:00:00Z").is_none());
        assert!(parse_rfc3339_to_unix_secs("2026-00-01T00:00:00Z").is_none());
    }

    #[test]
    fn reject_invalid_separators() {
        assert!(parse_rfc3339_to_unix_secs("2026/05/27T12:34:56Z").is_none());
        assert!(parse_rfc3339_to_unix_secs("2026-05-27X12:34:56Z").is_none());
    }

    #[test]
    fn reject_non_ascii_digit_fields() {
        assert!(parse_rfc3339_to_unix_secs("20XY-05-27T12:34:56Z").is_none());
    }

    #[test]
    fn lowercase_t_accepted() {
        let a = parse_rfc3339_to_unix_secs("2026-05-27t12:34:56Z").unwrap();
        let b = parse_rfc3339_to_unix_secs("2026-05-27T12:34:56Z").unwrap();
        assert_eq!(a, b);
    }
}
