#![cfg(feature = "as2")]
//! The AS2 send goldens through `As2::send`.
//!
//! `Profile::as2()` always signs and encrypts (and adds the MDN request
//! headers), so the encrypted body is not reproducible octet for octet. What
//! stays byte-identical is checked instead: the payload the partner recovers is
//! the golden payload, and the MIC is taken over the signed entity built from
//! exactly those octets (RFC 4130 §7.3.1).

#[path = "common/as2_peers.rs"]
mod as2_peers;

mod api_0_16 {
    use super::as2_peers::{EDI, field, pair};
    use asx::Payload;
    use asx::as2::Message;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use sha2::{Digest, Sha256};
    use std::sync::{Arc, Mutex};

    async fn send_and_capture(payload: &[u8], media_type: &str) -> (Vec<u8>, String, String) {
        let p = pair();
        let mic: Arc<Mutex<Option<String>>> = Arc::default();
        {
            let mic = mic.clone();
            p.loopback.intercept(move |resp| {
                *mic.lock().unwrap() = field(resp.body(), "Received-Content-MIC");
            });
        }
        let mdn = p
            .sender
            .send(Message::to(
                &p.to_b,
                Payload::new(payload.to_vec(), media_type),
            ))
            .await
            .expect("verified MDN");
        let json = serde_json::to_value(mdn.evidence()).unwrap();
        let recorded = json["mic"]["value"].as_str().unwrap().to_string();
        let delivered = p.delivered.lock().unwrap()[0].clone();
        assert_eq!(delivered.3, media_type);
        let echoed = mic.lock().unwrap().clone().expect("the MDN echoes a MIC");
        assert_eq!(echoed, format!("{recorded}, sha-256"));
        (delivered.2, recorded, delivered.3)
    }

    fn entity_mic(media_type: &str, payload: &[u8]) -> String {
        let mut entity =
            format!("Content-Type: {media_type}\r\nContent-Transfer-Encoding: binary\r\n\r\n")
                .into_bytes();
        entity.extend_from_slice(payload);
        STANDARD.encode(Sha256::digest(&entity))
    }

    #[tokio::test]
    async fn golden_payload_round_trips_with_the_entity_mic() {
        let payload =
            std::fs::read("tests/fixtures/as2_send_payload.golden").expect("payload fixture");
        let content_mic = std::fs::read_to_string("tests/fixtures/as2_send_mic.golden")
            .expect("mic fixture")
            .trim()
            .to_string();
        // The golden octets are unchanged.
        assert_eq!(STANDARD.encode(Sha256::digest(&payload)), content_mic);
        let (delivered, mic, _) = send_and_capture(&payload, "application/octet-stream").await;
        assert_eq!(
            delivered, payload,
            "the partner recovers the golden payload byte for byte"
        );
        assert_eq!(mic, entity_mic("application/octet-stream", &payload));
    }

    #[tokio::test]
    async fn header_looking_payload_is_opaque_content() {
        let payload = b"Content-Transfer-Encoding: binary\r\n\r\nA\r\nB\r\n--x--".to_vec();
        let (delivered, mic, media_type) = send_and_capture(&payload, EDI).await;
        assert_eq!(delivered, payload);
        assert_eq!(media_type, EDI);
        assert_eq!(mic, entity_mic(EDI, &payload));
    }
}
