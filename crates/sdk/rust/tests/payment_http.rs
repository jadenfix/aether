use aether_sdk::{
    build_payment_required_response, decode_payment_header, decode_payment_header_with_hash,
    encode_payment_header, payment_envelope_hash, payment_headers, PaymentEnvelope,
    PaymentEnvelopeBuilder, PaymentRequiredOptions, PaymentToken, SideEffect, SignatureEnvelope,
    SigningAlgorithm, AETHER_PAYMENT_HASH_HEADER, AETHER_PAYMENT_HEADER, AETHER_PAYMENT_SCHEME,
    PAYMENT_SIGNATURE_DOMAIN,
};
use aether_types::{Address, H256};

fn h(byte: u8) -> H256 {
    H256::from([byte; 32])
}

fn addr(byte: u8) -> Address {
    Address::from([byte; 20])
}

fn payment() -> PaymentEnvelope {
    PaymentEnvelope {
        token: PaymentToken::Aic,
        amount: 1_500_000_000_000_000_000,
        recipient: addr(0x11),
        quote_hash: h(0x22),
        request_hash: h(0x33),
        result_hash: Some(h(0x44)),
        nonce: [0x55; 32],
        expires_at_slot: 100,
        chain_id: 7,
        side_effect: SideEffect::Purchase,
        max_replays: 1,
        signature: SignatureEnvelope::new(
            SigningAlgorithm::Ed25519,
            PAYMENT_SIGNATURE_DOMAIN,
            7,
            "agent-session-ed25519",
            H256::from([
                0x67, 0xa3, 0x1c, 0xca, 0x14, 0x24, 0x1a, 0x7b, 0x60, 0x47, 0x31, 0x13, 0xee, 0xdb,
                0x59, 0x78, 0xff, 0x3c, 0x58, 0x6e, 0x8b, 0xfa, 0xf9, 0xdb, 0xd6, 0xea, 0x8f, 0xf9,
                0x2d, 0xbb, 0xe1, 0x31,
            ]),
            vec![0xaa; 64],
            None,
        ),
    }
}

#[test]
fn rust_payment_hash_matches_typescript_golden_vector() {
    let payment = payment();

    assert_eq!(
        format!("{:?}", payment.signing_payload_hash().unwrap()),
        "0x67a31cca14241a7b60473113eedb5978ff3c586e8bfaf9dbd6ea8ff92dbbe131"
    );
    assert_eq!(
        payment_envelope_hash(&payment).unwrap(),
        "0x0831ce74c89358835be790d4a7794a2bb30cd7e5968bafb5cc99423ea5f25783"
    );
}

#[test]
fn payment_header_roundtrips_and_binds_hash_header() {
    let payment = payment();
    let header = encode_payment_header(&payment).unwrap();
    let decoded = decode_payment_header(&header).unwrap();
    assert_eq!(decoded, payment);

    let headers = payment_headers(&payment).unwrap();
    assert_eq!(headers.get(AETHER_PAYMENT_HEADER), Some(&header));
    assert_eq!(
        headers.get(AETHER_PAYMENT_HASH_HEADER),
        Some(&payment_envelope_hash(&payment).unwrap())
    );
    assert_eq!(
        decode_payment_header_with_hash(
            headers.get(AETHER_PAYMENT_HEADER).unwrap(),
            headers.get(AETHER_PAYMENT_HASH_HEADER).unwrap(),
        )
        .unwrap(),
        payment
    );
    assert!(decode_payment_header_with_hash(&header, &format!("{:?}", h(0xee))).is_err());
}

#[test]
fn payment_required_response_serializes_to_typescript_shape() {
    let response = build_payment_required_response(PaymentRequiredOptions {
        network: "aether-mainnet".to_string(),
        resource: "mcp://beater.mail/send".to_string(),
        recipient: addr(0x11),
        token: PaymentToken::Aic,
        amount: 2_500_000,
        quote_hash: h(0x22),
        request_hash: h(0x33),
        side_effect: SideEffect::Send,
        chain_id: 7,
        expires_at_slot: 100,
        description: Some("Pay for a tool call".to_string()),
    })
    .unwrap();

    assert_eq!(response.error.as_deref(), Some("payment_required"));
    assert_eq!(response.accepts[0].scheme, AETHER_PAYMENT_SCHEME);
    assert_eq!(response.accepts[0].max_amount_required, "2500000");
    assert_eq!(response.accepts[0].extra.side_effect, SideEffect::Send);

    let json = serde_json::to_value(&response).unwrap();
    assert_eq!(json["accepts"][0]["pay_to"], format!("{:?}", addr(0x11)));
    assert_eq!(
        json["accepts"][0]["extra"]["quote_hash"],
        format!("{:?}", h(0x22))
    );
}

#[test]
fn payment_builder_exposes_unsigned_signing_payload_hash() {
    let hash = PaymentEnvelopeBuilder::new()
        .amount(1_500_000_000_000_000_000)
        .recipient(addr(0x11))
        .quote_hash(h(0x22))
        .request_hash(h(0x33))
        .result_hash(h(0x44))
        .nonce([0x55; 32])
        .expires_at_slot(100)
        .chain_id(7)
        .side_effect(SideEffect::Purchase)
        .signing_payload_hash()
        .unwrap();

    assert_eq!(
        format!("{hash:?}"),
        "0x67a31cca14241a7b60473113eedb5978ff3c586e8bfaf9dbd6ea8ff92dbbe131"
    );
}

#[test]
fn payment_required_response_rejects_invalid_requirements() {
    let err = build_payment_required_response(PaymentRequiredOptions {
        network: "aether-mainnet".to_string(),
        resource: "mcp://beater.mail/send".to_string(),
        recipient: addr(0x11),
        token: PaymentToken::Aic,
        amount: 0,
        quote_hash: h(0x22),
        request_hash: h(0x33),
        side_effect: SideEffect::Send,
        chain_id: 7,
        expires_at_slot: 100,
        description: None,
    })
    .unwrap_err();
    assert!(err.to_string().contains("amount"));
}
