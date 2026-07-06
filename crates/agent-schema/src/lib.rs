//! Shared agent settlement schema.
//!
//! This crate intentionally contains wire-level data types and validation only.
//! Concrete signing, FROST, post-quantum, TEE, and zk verification live in
//! crypto/verifier crates that consume these envelopes.

use aether_types::{Address, Slot, H256};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod schema;
pub use schema::agent_contract_schema;

const DOMAIN_PREFIX: &str = "aether/";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AgentSchemaError {
    #[error("domain must start with aether/")]
    InvalidDomain,
    #[error("chain_id must be non-zero")]
    InvalidChainId,
    #[error("key_id must not be empty")]
    EmptyKeyId,
    #[error("signature must not be empty")]
    EmptySignature,
    #[error("post-quantum signature is required for {0:?}")]
    MissingPostQuantumSignature(SigningAlgorithm),
    #[error("expiration slot must be greater than the current slot")]
    Expired,
    #[error("spend limits are inconsistent")]
    InvalidSpendLimit,
    #[error("guardian threshold is required for high-risk side effects")]
    MissingGuardianThreshold,
    #[error("guardian public key is required for high-risk side effects")]
    MissingGuardianPublicKey,
    #[error("high-risk side effects require a FROST guardian signature")]
    MissingFrostGuardianSignature,
    #[error("allowed side effects must not be empty")]
    EmptySideEffects,
    #[error("payment amount must be non-zero")]
    ZeroPaymentAmount,
    #[error("payment recipient must not be zero")]
    ZeroPaymentRecipient,
    #[error("replay count must be non-zero")]
    ZeroReplayCount,
    #[error("request/result binding is required for settled payments")]
    MissingResultBinding,
    #[error("receipt sequence cannot be zero")]
    InvalidReceiptSequence,
    #[error("tool identity must not be empty")]
    EmptyToolIdentity,
    #[error("journal must contain at least one receipt hash")]
    EmptyJournal,
    #[error("journal leaf index is out of bounds")]
    InvalidJournalLeafIndex,
    #[error("journal proof does not match the expected root")]
    InvalidJournalProof,
    #[error("serialization failed: {0}")]
    Serialization(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningAlgorithm {
    Ed25519,
    Bls12381,
    FrostRistretto255,
    Ed25519MlDsa87,
    MlDsa87,
    SlhDsaSha2256f,
}

impl SigningAlgorithm {
    #[must_use]
    pub const fn requires_post_quantum_component(self) -> bool {
        matches!(
            self,
            SigningAlgorithm::Ed25519MlDsa87
                | SigningAlgorithm::MlDsa87
                | SigningAlgorithm::SlhDsaSha2256f
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureEnvelope {
    pub alg: SigningAlgorithm,
    pub domain: String,
    pub chain_id: u64,
    pub key_id: String,
    pub payload_hash: H256,
    pub signature: Vec<u8>,
    pub pq_signature: Option<Vec<u8>>,
}

impl SignatureEnvelope {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        alg: SigningAlgorithm,
        domain: impl Into<String>,
        chain_id: u64,
        key_id: impl Into<String>,
        payload_hash: H256,
        signature: Vec<u8>,
        pq_signature: Option<Vec<u8>>,
    ) -> Self {
        Self {
            alg,
            domain: domain.into(),
            chain_id,
            key_id: key_id.into(),
            payload_hash,
            signature,
            pq_signature,
        }
    }

    pub fn validate(&self) -> Result<(), AgentSchemaError> {
        validate_domain(&self.domain)?;
        validate_chain_id(self.chain_id)?;
        if self.key_id.trim().is_empty() {
            return Err(AgentSchemaError::EmptyKeyId);
        }
        if self.signature.is_empty() {
            return Err(AgentSchemaError::EmptySignature);
        }
        if self.alg.requires_post_quantum_component()
            && self.pq_signature.as_ref().is_none_or(Vec::is_empty)
        {
            return Err(AgentSchemaError::MissingPostQuantumSignature(self.alg));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SideEffect {
    Read,
    Draft,
    Write,
    Send,
    Purchase,
    Delete,
}

impl SideEffect {
    #[must_use]
    pub const fn requires_guardian(self) -> bool {
        matches!(
            self,
            SideEffect::Send | SideEffect::Purchase | SideEffect::Delete
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepKind {
    LlmCall,
    ToolCall,
    BrowseAct,
    SandboxExec,
    McpCall,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Running,
    Completed,
    Failed,
    NeedsReview,
    Disputed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentRunId(pub [u8; 32]);

impl AgentRunId {
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct JournalRoot(pub H256);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MerkleSide {
    Left,
    Right,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalProofNode {
    pub side: MerkleSide,
    pub hash: H256,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalProof {
    pub leaf_hash: H256,
    pub leaf_index: u64,
    pub leaf_count: u64,
    pub siblings: Vec<JournalProofNode>,
}

impl JournalProof {
    pub fn verify(&self, root: JournalRoot) -> Result<(), AgentSchemaError> {
        if self.leaf_count == 0 || self.leaf_index >= self.leaf_count {
            return Err(AgentSchemaError::InvalidJournalLeafIndex);
        }

        let mut hash = self.leaf_hash;
        for sibling in &self.siblings {
            hash = match sibling.side {
                MerkleSide::Left => journal_node_hash(sibling.hash, hash),
                MerkleSide::Right => journal_node_hash(hash, sibling.hash),
            };
        }

        if hash == root.0 {
            Ok(())
        } else {
            Err(AgentSchemaError::InvalidJournalProof)
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementPolicy {
    pub min_escrow_aic: u128,
    pub challenge_slots: u64,
    pub requires_human_confirm: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentAuthorization {
    pub agent_account: Address,
    pub session_public_key: Vec<u8>,
    pub delegated_by: Address,
    pub valid_from_slot: Slot,
    pub valid_until_slot: Slot,
    pub max_aic: u128,
    pub max_per_call_aic: u128,
    pub allowed_side_effects: Vec<SideEffect>,
    pub allowed_tools: Vec<String>,
    pub allowed_recipients: Vec<Address>,
    pub policy_hash: H256,
    pub guardian_threshold: Option<u16>,
    pub guardian_public_key: Option<Vec<u8>>,
    pub signature: SignatureEnvelope,
}

impl AgentAuthorization {
    pub fn validate(&self, current_slot: Slot) -> Result<(), AgentSchemaError> {
        self.signature.validate()?;
        if self.valid_until_slot <= current_slot || self.valid_until_slot <= self.valid_from_slot {
            return Err(AgentSchemaError::Expired);
        }
        if self.max_per_call_aic > self.max_aic {
            return Err(AgentSchemaError::InvalidSpendLimit);
        }
        if self.allowed_side_effects.is_empty() {
            return Err(AgentSchemaError::EmptySideEffects);
        }
        if self
            .allowed_side_effects
            .iter()
            .any(|effect| effect.requires_guardian())
        {
            if self.guardian_threshold.unwrap_or_default() == 0 {
                return Err(AgentSchemaError::MissingGuardianThreshold);
            }
            if self.guardian_public_key.as_ref().is_none_or(Vec::is_empty) {
                return Err(AgentSchemaError::MissingGuardianPublicKey);
            }
            if self.signature.alg != SigningAlgorithm::FrostRistretto255 {
                return Err(AgentSchemaError::MissingFrostGuardianSignature);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepReceipt {
    pub run_id: AgentRunId,
    pub seq: u64,
    pub prev_receipt_hash: Option<H256>,
    pub kind: StepKind,
    pub side_effect: SideEffect,
    pub request_hash: H256,
    pub result_hash: H256,
    pub evidence_uri_hash: Option<H256>,
    pub tool_identity: String,
    pub signer: Address,
    pub signature: SignatureEnvelope,
}

impl StepReceipt {
    pub fn validate(&self) -> Result<(), AgentSchemaError> {
        self.signature.validate()?;
        if self.seq == 0 {
            return Err(AgentSchemaError::InvalidReceiptSequence);
        }
        if self.tool_identity.trim().is_empty() {
            return Err(AgentSchemaError::EmptyToolIdentity);
        }
        Ok(())
    }

    pub fn receipt_hash(&self) -> Result<H256, AgentSchemaError> {
        typed_hash("aether/agent_step_receipt/v1", self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentToken {
    Aic,
    Swr,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentEnvelope {
    pub token: PaymentToken,
    pub amount: u128,
    pub recipient: Address,
    pub quote_hash: H256,
    pub request_hash: H256,
    pub result_hash: Option<H256>,
    pub nonce: [u8; 32],
    pub expires_at_slot: Slot,
    pub chain_id: u64,
    pub side_effect: SideEffect,
    pub max_replays: u32,
    pub signature: SignatureEnvelope,
}

impl PaymentEnvelope {
    pub fn validate(&self, current_slot: Slot) -> Result<(), AgentSchemaError> {
        self.signature.validate()?;
        validate_chain_id(self.chain_id)?;
        if self.amount == 0 {
            return Err(AgentSchemaError::ZeroPaymentAmount);
        }
        if self.recipient == Address::from([0u8; 20]) {
            return Err(AgentSchemaError::ZeroPaymentRecipient);
        }
        if self.expires_at_slot <= current_slot {
            return Err(AgentSchemaError::Expired);
        }
        if self.max_replays == 0 {
            return Err(AgentSchemaError::ZeroReplayCount);
        }
        if self.side_effect.requires_guardian() && self.result_hash.is_none() {
            return Err(AgentSchemaError::MissingResultBinding);
        }
        Ok(())
    }

    pub fn payment_hash(&self) -> Result<H256, AgentSchemaError> {
        typed_hash("aether/agent_payment_envelope/v1", self)
    }

    pub fn signing_payload_hash(&self) -> Result<H256, AgentSchemaError> {
        typed_hash(
            "aether/agent_payment_authorization/v1",
            &PaymentEnvelopeSigningPayload {
                token: self.token,
                amount: self.amount,
                recipient: self.recipient,
                quote_hash: self.quote_hash,
                request_hash: self.request_hash,
                result_hash: self.result_hash,
                nonce: self.nonce,
                expires_at_slot: self.expires_at_slot,
                chain_id: self.chain_id,
                side_effect: self.side_effect,
                max_replays: self.max_replays,
            },
        )
    }
}

#[derive(Serialize)]
struct PaymentEnvelopeSigningPayload {
    token: PaymentToken,
    amount: u128,
    recipient: Address,
    quote_hash: H256,
    request_hash: H256,
    result_hash: Option<H256>,
    nonce: [u8; 32],
    expires_at_slot: Slot,
    chain_id: u64,
    side_effect: SideEffect,
    max_replays: u32,
}

pub fn typed_hash<T: Serialize>(domain: &str, value: &T) -> Result<H256, AgentSchemaError> {
    validate_domain(domain)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain.as_bytes());
    hasher.update(&[0]);
    let encoded = bincode::serialize(value)
        .map_err(|err| AgentSchemaError::Serialization(err.to_string()))?;
    hasher.update(&encoded);
    let mut out = [0u8; 32];
    out.copy_from_slice(hasher.finalize().as_bytes());
    Ok(H256::from(out))
}

pub fn journal_root_from_receipt_hashes(
    receipt_hashes: &[H256],
) -> Result<JournalRoot, AgentSchemaError> {
    if receipt_hashes.is_empty() {
        return Err(AgentSchemaError::EmptyJournal);
    }
    Ok(JournalRoot(journal_root_hash(receipt_hashes)))
}

pub fn journal_proof(
    receipt_hashes: &[H256],
    leaf_index: usize,
) -> Result<JournalProof, AgentSchemaError> {
    if receipt_hashes.is_empty() {
        return Err(AgentSchemaError::EmptyJournal);
    }
    if leaf_index >= receipt_hashes.len() {
        return Err(AgentSchemaError::InvalidJournalLeafIndex);
    }

    let mut level = receipt_hashes.to_vec();
    let mut index = leaf_index;
    let mut siblings = Vec::new();

    while level.len() > 1 {
        let sibling_index = if index % 2 == 0 {
            (index + 1).min(level.len() - 1)
        } else {
            index - 1
        };
        siblings.push(JournalProofNode {
            side: if index % 2 == 0 {
                MerkleSide::Right
            } else {
                MerkleSide::Left
            },
            hash: level[sibling_index],
        });

        level = journal_next_level(&level);
        index /= 2;
    }

    Ok(JournalProof {
        leaf_hash: receipt_hashes[leaf_index],
        leaf_index: leaf_index as u64,
        leaf_count: receipt_hashes.len() as u64,
        siblings,
    })
}

fn journal_root_hash(receipt_hashes: &[H256]) -> H256 {
    let mut level = receipt_hashes.to_vec();
    while level.len() > 1 {
        level = journal_next_level(&level);
    }
    level[0]
}

fn journal_next_level(level: &[H256]) -> Vec<H256> {
    level
        .chunks(2)
        .map(|pair| {
            let left = pair[0];
            let right = pair.get(1).copied().unwrap_or(left);
            journal_node_hash(left, right)
        })
        .collect()
}

fn journal_node_hash(left: H256, right: H256) -> H256 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"aether/agent_journal_node/v1");
    hasher.update(&[0]);
    hasher.update(left.as_bytes());
    hasher.update(right.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(hasher.finalize().as_bytes());
    H256::from(out)
}

fn validate_domain(domain: &str) -> Result<(), AgentSchemaError> {
    if !domain.starts_with(DOMAIN_PREFIX) {
        return Err(AgentSchemaError::InvalidDomain);
    }
    Ok(())
}

fn validate_chain_id(chain_id: u64) -> Result<(), AgentSchemaError> {
    if chain_id == 0 {
        return Err(AgentSchemaError::InvalidChainId);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn h(byte: u8) -> H256 {
        H256::from([byte; 32])
    }

    fn addr(byte: u8) -> Address {
        Address::from([byte; 20])
    }

    fn sig() -> SignatureEnvelope {
        SignatureEnvelope::new(
            SigningAlgorithm::Ed25519,
            "aether/test/v1",
            1,
            "session-key",
            h(7),
            vec![9; 64],
            None,
        )
    }

    #[test]
    fn signature_envelope_rejects_bad_domain() {
        let mut envelope = sig();
        envelope.domain = "other/test/v1".to_string();
        assert_eq!(envelope.validate(), Err(AgentSchemaError::InvalidDomain));
    }

    #[test]
    fn pq_algorithm_requires_pq_signature() {
        let envelope = SignatureEnvelope::new(
            SigningAlgorithm::Ed25519MlDsa87,
            "aether/identity/v1",
            1,
            "identity-root",
            h(1),
            vec![2; 64],
            None,
        );
        assert_eq!(
            envelope.validate(),
            Err(AgentSchemaError::MissingPostQuantumSignature(
                SigningAlgorithm::Ed25519MlDsa87
            ))
        );
    }

    #[test]
    fn high_risk_authorization_requires_guardian_threshold() {
        let authorization = AgentAuthorization {
            agent_account: addr(1),
            session_public_key: vec![2; 32],
            delegated_by: addr(3),
            valid_from_slot: 10,
            valid_until_slot: 100,
            max_aic: 10_000,
            max_per_call_aic: 1_000,
            allowed_side_effects: vec![SideEffect::Read, SideEffect::Purchase],
            allowed_tools: vec!["checkout".to_string()],
            allowed_recipients: vec![addr(4)],
            policy_hash: h(5),
            guardian_threshold: None,
            guardian_public_key: None,
            signature: sig(),
        };

        assert_eq!(
            authorization.validate(20),
            Err(AgentSchemaError::MissingGuardianThreshold)
        );
    }

    #[test]
    fn high_risk_authorization_requires_frost_signature() {
        let authorization = AgentAuthorization {
            agent_account: addr(1),
            session_public_key: vec![2; 32],
            delegated_by: addr(3),
            valid_from_slot: 10,
            valid_until_slot: 100,
            max_aic: 10_000,
            max_per_call_aic: 1_000,
            allowed_side_effects: vec![SideEffect::Purchase],
            allowed_tools: vec!["checkout".to_string()],
            allowed_recipients: vec![addr(4)],
            policy_hash: h(5),
            guardian_threshold: Some(2),
            guardian_public_key: Some(vec![7; 32]),
            signature: sig(),
        };

        assert_eq!(
            authorization.validate(20),
            Err(AgentSchemaError::MissingFrostGuardianSignature)
        );
    }

    #[test]
    fn high_risk_payment_requires_result_binding() {
        let payment = PaymentEnvelope {
            token: PaymentToken::Aic,
            amount: 10,
            recipient: addr(1),
            quote_hash: h(2),
            request_hash: h(3),
            result_hash: None,
            nonce: [4; 32],
            expires_at_slot: 100,
            chain_id: 1,
            side_effect: SideEffect::Purchase,
            max_replays: 1,
            signature: sig(),
        };

        assert_eq!(
            payment.validate(20),
            Err(AgentSchemaError::MissingResultBinding)
        );
    }

    #[test]
    fn journal_proof_verifies_receipt_inclusion() {
        let leaves = [h(1), h(2), h(3), h(4), h(5)];
        let root = journal_root_from_receipt_hashes(&leaves).unwrap();

        for index in 0..leaves.len() {
            let proof = journal_proof(&leaves, index).unwrap();
            assert_eq!(proof.leaf_hash, leaves[index]);
            proof.verify(root).unwrap();
        }
    }

    #[test]
    fn journal_proof_rejects_tampered_leaf_or_root() {
        let leaves = [h(1), h(2), h(3)];
        let root = journal_root_from_receipt_hashes(&leaves).unwrap();
        let mut proof = journal_proof(&leaves, 1).unwrap();

        proof.leaf_hash = h(9);
        assert_eq!(
            proof.verify(root),
            Err(AgentSchemaError::InvalidJournalProof)
        );

        let proof = journal_proof(&leaves, 1).unwrap();
        assert_eq!(
            proof.verify(JournalRoot(h(9))),
            Err(AgentSchemaError::InvalidJournalProof)
        );
    }

    #[test]
    fn journal_root_requires_non_empty_receipts() {
        assert_eq!(
            journal_root_from_receipt_hashes(&[]),
            Err(AgentSchemaError::EmptyJournal)
        );
        assert_eq!(journal_proof(&[], 0), Err(AgentSchemaError::EmptyJournal));
        assert_eq!(
            journal_proof(&[h(1)], 1),
            Err(AgentSchemaError::InvalidJournalLeafIndex)
        );
    }

    proptest! {
        #[test]
        fn typed_hash_changes_when_domain_changes(bytes in proptest::array::uniform32(any::<u8>())) {
            let run_id = AgentRunId::new(bytes);
            let a = typed_hash("aether/receipt/v1", &run_id).unwrap();
            let b = typed_hash("aether/payment/v1", &run_id).unwrap();
            prop_assert_ne!(a, b);
        }

        #[test]
        fn receipt_hash_changes_when_sequence_changes(seq in 1u64..u64::MAX) {
            let mut receipt = StepReceipt {
                run_id: AgentRunId::new([1; 32]),
                seq,
                prev_receipt_hash: Some(h(2)),
                kind: StepKind::ToolCall,
                side_effect: SideEffect::Write,
                request_hash: h(3),
                result_hash: h(4),
                evidence_uri_hash: Some(h(5)),
                tool_identity: "beater.js/tool".to_string(),
                signer: addr(6),
                signature: sig(),
            };
            let first = receipt.receipt_hash().unwrap();
            receipt.seq = receipt.seq.saturating_add(1);
            let second = receipt.receipt_hash().unwrap();
            prop_assert_ne!(first, second);
        }
    }
}
