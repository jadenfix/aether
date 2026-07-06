use aether_account_abstraction::{AccountValidator, EntryPoint, UserOperation};
use aether_crypto_primitives::Keypair;
use aether_program_agent_run_escrow::AgentRunEscrowState;
use aether_sdk::{
    journal_proof, journal_root_from_receipt_hashes, AgentAuthorization, AgentAuthorizationBuilder,
    AgentRunId, JournalRoot, PaymentEnvelope, PaymentEnvelopeBuilder, SettlementPolicy, SideEffect,
    SignatureEnvelope, SignatureEnvelopeBuilder, SigningAlgorithm, StepKind, StepReceiptBuilder,
};
use aether_types::{Address, H256};
use anyhow::Result;
use frost_ristretto255::{
    aggregate,
    keys::{generate_with_dealer, IdentifierList, KeyPackage, PublicKeyPackage, SecretShare},
    round1, round2, Identifier, SigningPackage,
};
use rand::thread_rng;
use std::collections::BTreeMap;

struct AcceptAll;

impl AccountValidator for AcceptAll {
    fn validate_signature(&self, _: &Address, _: &H256, _: &[u8]) -> Result<()> {
        Ok(())
    }
}

fn h(byte: u8) -> H256 {
    H256::from([byte; 32])
}

fn addr(byte: u8) -> Address {
    Address::from([byte; 20])
}

fn signature(domain: &str, payload_hash: H256) -> SignatureEnvelope {
    SignatureEnvelopeBuilder::new()
        .domain(domain)
        .chain_id(1)
        .key_id("agent-session")
        .payload_hash(payload_hash)
        .signature(vec![7; 64])
        .build()
        .unwrap()
}

fn payment_signature(session_key: &Keypair, payment: &PaymentEnvelope) -> SignatureEnvelope {
    let payload_hash = payment.signing_payload_hash().unwrap();
    SignatureEnvelopeBuilder::new()
        .domain("aether/payment/v1")
        .chain_id(payment.chain_id)
        .key_id("agent-session")
        .payload_hash(payload_hash)
        .signature(session_key.sign(payload_hash.as_bytes()))
        .build()
        .unwrap()
}

fn frost_key_material() -> (
    [Identifier; 3],
    BTreeMap<Identifier, SecretShare>,
    PublicKeyPackage,
) {
    let mut rng = thread_rng();
    let identifiers = [
        Identifier::try_from(1).unwrap(),
        Identifier::try_from(2).unwrap(),
        Identifier::try_from(3).unwrap(),
    ];
    let (shares, public_key_package) =
        generate_with_dealer(3, 2, IdentifierList::Custom(&identifiers), &mut rng).unwrap();
    (identifiers, shares, public_key_package)
}

fn frost_signature(
    message: &[u8],
    identifiers: &[Identifier; 3],
    shares: &BTreeMap<Identifier, SecretShare>,
    public_key_package: &PublicKeyPackage,
) -> Vec<u8> {
    let mut rng = thread_rng();
    let mut commitments = BTreeMap::new();
    let mut nonces = BTreeMap::new();

    for identifier in identifiers.iter().take(2) {
        let key_package: KeyPackage = shares.get(identifier).unwrap().clone().try_into().unwrap();
        let (signing_nonces, signing_commitments) =
            round1::commit(key_package.signing_share(), &mut rng);
        commitments.insert(*identifier, signing_commitments);
        nonces.insert(*identifier, (signing_nonces, key_package));
    }

    let signing_package = SigningPackage::new(commitments, message);
    let mut signature_shares = BTreeMap::new();
    for (identifier, (signing_nonces, key_package)) in nonces {
        let share = round2::sign(&signing_package, &signing_nonces, &key_package).unwrap();
        signature_shares.insert(identifier, share);
    }

    aggregate(&signing_package, &signature_shares, public_key_package)
        .unwrap()
        .serialize()
        .unwrap()
}

fn authorization(
    sender: Address,
    provider: Address,
    session_public_key: Vec<u8>,
    guardian_public_key: Vec<u8>,
    guardian_signature: SignatureEnvelope,
) -> AgentAuthorization {
    AgentAuthorizationBuilder::new()
        .agent_account(sender)
        .session_public_key(session_public_key)
        .delegated_by(sender)
        .valid_slots(1, 1_000)
        .spend_limits(10_000, 2_000)
        .allow_side_effect(SideEffect::Read)
        .allow_side_effect(SideEffect::Purchase)
        .allow_tool("browser.checkout")
        .allow_recipient(provider)
        .policy_hash(h(30))
        .guardian_threshold(2)
        .guardian_public_key(guardian_public_key)
        .signature(guardian_signature)
        .build(10)
        .unwrap()
}

#[test]
fn sdk_to_account_abstraction_to_escrow_settlement_flow() {
    let sender = addr(1);
    let provider = addr(2);
    let run_id = AgentRunId::new([42; 32]);
    let session_key = Keypair::generate();

    let unsigned_payment = PaymentEnvelopeBuilder::new()
        .amount(1_500)
        .recipient(provider)
        .quote_hash(h(11))
        .request_hash(h(12))
        .result_hash(h(13))
        .nonce([14; 32])
        .expires_at_slot(1_000)
        .chain_id(1)
        .side_effect(SideEffect::Purchase)
        .signature(signature("aether/payment/v1", H256::zero()))
        .build(10)
        .unwrap();
    let payment = PaymentEnvelopeBuilder::new()
        .amount(unsigned_payment.amount)
        .recipient(unsigned_payment.recipient)
        .quote_hash(unsigned_payment.quote_hash)
        .request_hash(unsigned_payment.request_hash)
        .result_hash(unsigned_payment.result_hash.unwrap())
        .nonce(unsigned_payment.nonce)
        .expires_at_slot(unsigned_payment.expires_at_slot)
        .chain_id(unsigned_payment.chain_id)
        .side_effect(unsigned_payment.side_effect)
        .signature(payment_signature(&session_key, &unsigned_payment))
        .build(10)
        .unwrap();

    let (identifiers, shares, public_key_package) = frost_key_material();
    let guardian_public_key = public_key_package.verifying_key().serialize().unwrap();
    let placeholder_auth = authorization(
        sender,
        provider,
        session_key.public_key(),
        guardian_public_key.clone(),
        SignatureEnvelopeBuilder::new()
            .algorithm(SigningAlgorithm::FrostRistretto255)
            .domain("aether/agent_authorization/v1")
            .chain_id(1)
            .key_id("guardian-frost")
            .payload_hash(H256::zero())
            .signature(vec![1; 64])
            .build()
            .unwrap(),
    );

    let mut op = UserOperation {
        sender,
        nonce: 0,
        call_data: b"agent:browser.checkout".to_vec(),
        call_gas_limit: 100_000,
        verification_gas_limit: 50_000,
        pre_verification_gas: 10_000,
        max_fee_per_gas: 100,
        paymaster: None,
        paymaster_data: Vec::new(),
        signature: vec![9; 64],
        side_effect: Some(SideEffect::Purchase),
        agent_authorization: Some(placeholder_auth),
        payment: Some(payment),
    };

    let policy_hash = op.agent_policy_hash();
    let guardian_signature = frost_signature(
        policy_hash.as_bytes(),
        &identifiers,
        &shares,
        &public_key_package,
    );
    op.agent_authorization = Some(authorization(
        sender,
        provider,
        session_key.public_key(),
        guardian_public_key,
        SignatureEnvelopeBuilder::new()
            .algorithm(SigningAlgorithm::FrostRistretto255)
            .domain("aether/agent_authorization/v1")
            .chain_id(1)
            .key_id("guardian-frost")
            .payload_hash(policy_hash)
            .signature(guardian_signature)
            .build()
            .unwrap(),
    ));

    let mut entry_point = EntryPoint::new();
    entry_point.set_current_slot(10);
    entry_point.register_account(sender, h(21));
    entry_point.validate_user_op(&op, &AcceptAll).unwrap();

    let receipt = StepReceiptBuilder::new()
        .run_id(run_id)
        .seq(1)
        .kind(StepKind::ToolCall)
        .side_effect(SideEffect::Purchase)
        .request_hash(h(12))
        .result_hash(h(13))
        .evidence_uri_hash(h(16))
        .tool_identity("browser.checkout")
        .signer(provider)
        .signature(signature("aether/receipt/v1", h(17)))
        .build()
        .unwrap();
    let receipt_hash = receipt.receipt_hash().unwrap();
    let journal_root = journal_root_from_receipt_hashes(&[receipt_hash]).unwrap();
    let inclusion_proof = journal_proof(&[receipt_hash], 0).unwrap();
    inclusion_proof.verify(journal_root).unwrap();

    let mut escrow = AgentRunEscrowState::new();
    let policy = SettlementPolicy {
        min_escrow_aic: 100,
        challenge_slots: 5,
        requires_human_confirm: false,
    };
    escrow
        .open_run(
            run_id,
            sender,
            provider,
            1_500,
            JournalRoot(h(18)),
            policy,
            10,
            100,
        )
        .unwrap();
    escrow
        .commit_step(
            run_id,
            provider,
            receipt.seq,
            receipt_hash,
            receipt.side_effect,
            11,
        )
        .unwrap();
    escrow
        .close_run(run_id, provider, journal_root, h(20), 12)
        .unwrap();

    assert!(matches!(
        escrow.settle_run(run_id, 17),
        Err(aether_program_agent_run_escrow::AgentRunEscrowError::ChallengeWindowActive)
    ));
    let settled = escrow.settle_run(run_id, 18).unwrap();
    assert_eq!(settled, (provider, 1_500));
    assert_eq!(escrow.provider_claimable.get(&provider), Some(&1_500));
    assert!(!escrow.requester_escrow.contains_key(&sender));
}
