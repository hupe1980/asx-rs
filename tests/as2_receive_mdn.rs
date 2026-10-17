#![cfg(feature = "as2")]
//! MDN verification on the sending side (RFC 4130 §7.4, RFC 3798), through
//! `As2::send`.
//!
//! Each case replaces the partner's genuine MDN with the crafted shape, signed
//! by the partner's pinned key, and answers the message the client just sent.
//! A parse or interop failure is `Indeterminate`; a verified MDN is `Ok`.

#[path = "common/as2_peers.rs"]
mod as2_peers;

mod api_0_16 {
    use super::as2_peers::{field, pair, replace_with, sign_entity};
    use asx::ErrorKind;

    const ID: &str = "port@test";

    /// Send, answering with `shape(mic)`: the crafted entity, signed by `b`.
    async fn answer_with(
        shape: impl Fn(&str) -> Vec<u8> + Send + Sync + 'static,
    ) -> Result<asx::Verified<asx::Receipt>, asx::Error> {
        let p = std::sync::Arc::new(pair());
        let signer = p.b.signing.clone();
        p.loopback.intercept(move |resp| {
            let mic = field(resp.body(), "Received-Content-MIC").expect("genuine MDN has a MIC");
            replace_with(resp, sign_entity(&signer, &shape(&mic)));
        });
        p.sender.send(p.message(b"x").message_id(ID)).await
    }

    fn report(notification: &str) -> Vec<u8> {
        format!(
            "Content-Type: multipart/report; report-type=disposition-notification; boundary=\"as2-mdn-b\"\r\n\r\n\
             --as2-mdn-b\r\nContent-Type: text/plain\r\n\r\nHuman-readable summary\r\n\r\n\
             --as2-mdn-b\r\nContent-Type: message/disposition-notification\r\n\r\n{notification}\r\n\
             --as2-mdn-b--\r\n"
        )
        .into_bytes()
    }

    async fn indeterminate(shape: impl Fn(&str) -> Vec<u8> + Send + Sync + 'static) {
        let err = answer_with(shape).await.expect_err("refused MDN");
        assert_eq!(err.kind(), ErrorKind::Indeterminate, "{err}");
    }

    #[tokio::test]
    async fn malformed_boundary_is_indeterminate() {
        indeterminate(|mic| {
            format!(
                "Content-Type: multipart/report; report-type=disposition-notification\r\n\r\n\
                 Final-Recipient: rfc822; partner-a\r\nOriginal-Message-ID: <{ID}>\r\n\
                 Disposition: automatic-action/MDN-sent-automatically; processed\r\n\
                 Received-content-MIC: {mic}\r\n"
            )
            .into_bytes()
        })
        .await;
    }

    #[tokio::test]
    async fn report_without_machine_readable_part_is_indeterminate() {
        indeterminate(|_| {
            b"Content-Type: multipart/report; report-type=disposition-notification; boundary=\"as2-mdn-b\"\r\n\r\n\
              --as2-mdn-b\r\nContent-Type: text/plain\r\n\r\nHuman-readable only\r\n\r\n--as2-mdn-b--\r\n"
                .to_vec()
        })
        .await;
    }

    #[tokio::test]
    async fn structured_report_with_returned_content_is_verified() {
        answer_with(|mic| {
            format!(
                "Content-Type: multipart/report; report-type=disposition-notification; boundary=\"as2-mdn-b\"\r\n\r\n\
                 --as2-mdn-b\r\nContent-Type: text/plain\r\n\r\nHuman-readable summary\r\n\r\n\
                 --as2-mdn-b\r\nContent-Type: message/disposition-notification\r\n\r\n\
                 Final-Recipient: rfc822; partner-a\r\nOriginal-Message-ID: <{ID}>\r\n\
                 Disposition: automatic-action/MDN-sent-automatically; processed\r\n\
                 Received-Content-MIC: {mic}\r\n\r\n\
                 --as2-mdn-b\r\nContent-Type: message/rfc822\r\n\r\n[original message]\r\n\r\n--as2-mdn-b--\r\n"
            )
            .into_bytes()
        })
        .await
        .expect("structured multipart/report verifies");
    }

    #[tokio::test]
    async fn duplicate_disposition_fields_are_indeterminate() {
        indeterminate(|mic| {
            report(&format!(
                "Final-Recipient: rfc822; partner-a\r\nOriginal-Message-ID: <{ID}>\r\n\
                 Disposition: automatic-action/MDN-sent-automatically; processed\r\n\
                 Disposition: automatic-action/MDN-sent-automatically; processed\r\n\
                 Received-Content-MIC: {mic}\r\n"
            ))
        })
        .await;
    }

    #[tokio::test]
    async fn duplicate_received_content_mic_fields_are_indeterminate() {
        indeterminate(|mic| {
            report(&format!(
                "Final-Recipient: rfc822; partner-a\r\nOriginal-Message-ID: <{ID}>\r\n\
                 Disposition: automatic-action/MDN-sent-automatically; processed\r\n\
                 Received-Content-MIC: {mic}\r\nReceived-Content-MIC: {mic}\r\n"
            ))
        })
        .await;
    }

    #[tokio::test]
    async fn notification_with_non_utf8_octets_is_indeterminate() {
        indeterminate(|mic| {
            let mut notification = b"Final-Recipient: rfc822; partner-".to_vec();
            notification.push(0xFF);
            notification.extend_from_slice(
                format!(
                    "\r\nOriginal-Message-ID: <{ID}>\r\n\
                     Disposition: automatic-action/MDN-sent-automatically; processed\r\n\
                     Received-Content-MIC: {mic}\r\n"
                )
                .as_bytes(),
            );
            let mut out = b"Content-Type: multipart/report; report-type=disposition-notification; boundary=\"as2-mdn-b\"\r\n\r\n\
                --as2-mdn-b\r\nContent-Type: text/plain\r\n\r\nHuman-readable\r\n\r\n\
                --as2-mdn-b\r\nContent-Type: message/disposition-notification\r\n\r\n"
                .to_vec();
            out.extend_from_slice(&notification);
            out.extend_from_slice(b"\r\n--as2-mdn-b--\r\n");
            out
        })
        .await;
    }

    #[tokio::test]
    async fn quoted_received_content_mic_is_verified() {
        answer_with(|mic| {
            let (digest, alg) = mic.split_once(',').unwrap();
            report(&format!(
                "Final-Recipient: rfc822; partner-a\r\nOriginal-Message-ID: <{ID}>\r\n\
                 Disposition: automatic-action/MDN-sent-automatically; processed\r\n\
                 Received-Content-MIC: \"{}\",{alg}\r\n",
                digest.trim()
            ))
        })
        .await
        .expect("a quoted MIC matches");
    }

    #[tokio::test]
    async fn folded_received_content_mic_is_verified() {
        answer_with(|mic| {
            let (head, tail) = mic.split_at(20);
            report(&format!(
                "Final-Recipient: rfc822; partner-a\r\nOriginal-Message-ID: <{ID}>\r\n\
                 Disposition: automatic-action/MDN-sent-automatically; processed\r\n\
                 Received-Content-MIC: {head}\r\n {tail}\r\n"
            ))
        })
        .await
        .expect("a folded MIC matches");
    }

    /// A warning MDN is accepted only with the matching MIC.
    #[tokio::test]
    async fn warning_mdn_needs_the_mic() {
        answer_with(|mic| {
            report(&format!(
                "Final-Recipient: rfc822; partner-a\r\nOriginal-Message-ID: <{ID}>\r\n\
                 Disposition: automatic-action/MDN-sent-automatically; processed/warning: duplicate-document\r\n\
                 Received-Content-MIC: {mic}\r\n"
            ))
        })
        .await
        .expect("warnings are allowed");
        indeterminate(|_| {
            report(&format!(
                "Final-Recipient: rfc822; partner-a\r\nOriginal-Message-ID: <{ID}>\r\n\
                 Disposition: automatic-action/MDN-sent-automatically; processed/warning: authentication-failed, processing continued\r\n"
            ))
        })
        .await;
    }

    #[tokio::test]
    async fn mdn_for_a_different_message_is_indeterminate() {
        indeterminate(|mic| {
            report(&format!(
                "Final-Recipient: rfc822; partner-a\r\nOriginal-Message-ID: <msg-42@example>\r\n\
                 Disposition: automatic-action/MDN-sent-automatically; processed\r\n\
                 Received-Content-MIC: {mic}\r\n"
            ))
        })
        .await;
    }

    #[tokio::test]
    async fn mdn_without_original_message_id_is_indeterminate() {
        indeterminate(|mic| {
            report(&format!(
                "Final-Recipient: rfc822; partner-a\r\n\
                 Disposition: automatic-action/MDN-sent-automatically; processed\r\n\
                 Received-Content-MIC: {mic}\r\n"
            ))
        })
        .await;
    }
}
