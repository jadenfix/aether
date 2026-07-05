use serde_json::{json, Value};

/// JSON Schema for the language-neutral agent settlement wire contract.
///
/// The Rust structs remain the source implementation, but this schema is the
/// cross-repo artifact consumed by beater.js, tempo, beatbox, and other SDKs.
#[must_use]
pub fn agent_contract_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://aether.dev/schema/agent-settlement/v1",
        "title": "Aether Agent Settlement Schema",
        "type": "object",
        "additionalProperties": false,
        "required": ["signatureEnvelope", "agentAuthorization", "stepReceipt", "paymentEnvelope"],
        "properties": {
            "signatureEnvelope": { "$ref": "#/$defs/SignatureEnvelope" },
            "agentAuthorization": { "$ref": "#/$defs/AgentAuthorization" },
            "stepReceipt": { "$ref": "#/$defs/StepReceipt" },
            "paymentEnvelope": { "$ref": "#/$defs/PaymentEnvelope" }
        },
        "$defs": {
            "H160": {
                "type": "string",
                "pattern": "^0x[0-9a-fA-F]{40}$",
                "description": "20-byte Aether address encoded as 0x-prefixed hex"
            },
            "H256": {
                "type": "string",
                "pattern": "^0x[0-9a-fA-F]{64}$",
                "description": "32-byte hash encoded as 0x-prefixed hex"
            },
            "Bytes": {
                "type": "string",
                "pattern": "^0x[0-9a-fA-F]*$",
                "description": "Arbitrary bytes encoded as 0x-prefixed hex"
            },
            "SigningAlgorithm": {
                "type": "string",
                "enum": [
                    "ed25519",
                    "bls12381",
                    "frost_ristretto255",
                    "ed25519_ml_dsa87",
                    "ml_dsa87",
                    "slh_dsa_sha2256f"
                ]
            },
            "SideEffect": {
                "type": "string",
                "enum": ["read", "draft", "write", "send", "purchase", "delete"]
            },
            "StepKind": {
                "type": "string",
                "enum": ["llm_call", "tool_call", "browse_act", "sandbox_exec", "mcp_call"]
            },
            "PaymentToken": {
                "type": "string",
                "enum": ["aic", "swr"]
            },
            "AgentRunId": {
                "$ref": "#/$defs/H256"
            },
            "SignatureEnvelope": {
                "type": "object",
                "additionalProperties": false,
                "required": ["alg", "domain", "chain_id", "key_id", "payload_hash", "signature"],
                "properties": {
                    "alg": { "$ref": "#/$defs/SigningAlgorithm" },
                    "domain": {
                        "type": "string",
                        "pattern": "^aether/.+",
                        "description": "Domain-separated signing context"
                    },
                    "chain_id": { "type": "integer", "minimum": 1 },
                    "key_id": { "type": "string", "minLength": 1 },
                    "payload_hash": { "$ref": "#/$defs/H256" },
                    "signature": { "$ref": "#/$defs/Bytes" },
                    "pq_signature": {
                        "anyOf": [{ "$ref": "#/$defs/Bytes" }, { "type": "null" }]
                    }
                }
            },
            "AgentAuthorization": {
                "type": "object",
                "additionalProperties": false,
                "required": [
                    "agent_account",
                    "session_public_key",
                    "delegated_by",
                    "valid_from_slot",
                    "valid_until_slot",
                    "max_aic",
                    "max_per_call_aic",
                    "allowed_side_effects",
                    "allowed_tools",
                    "allowed_recipients",
                    "policy_hash",
                    "guardian_public_key",
                    "signature"
                ],
                "properties": {
                    "agent_account": { "$ref": "#/$defs/H160" },
                    "session_public_key": { "$ref": "#/$defs/Bytes" },
                    "delegated_by": { "$ref": "#/$defs/H160" },
                    "valid_from_slot": { "type": "integer", "minimum": 0 },
                    "valid_until_slot": { "type": "integer", "minimum": 1 },
                    "max_aic": { "type": "integer", "minimum": 0 },
                    "max_per_call_aic": { "type": "integer", "minimum": 0 },
                    "allowed_side_effects": {
                        "type": "array",
                        "minItems": 1,
                        "items": { "$ref": "#/$defs/SideEffect" }
                    },
                    "allowed_tools": {
                        "type": "array",
                        "items": { "type": "string" }
                    },
                    "allowed_recipients": {
                        "type": "array",
                        "items": { "$ref": "#/$defs/H160" }
                    },
                    "policy_hash": { "$ref": "#/$defs/H256" },
                    "guardian_threshold": {
                        "anyOf": [{ "type": "integer", "minimum": 1 }, { "type": "null" }]
                    },
                    "guardian_public_key": {
                        "anyOf": [{ "$ref": "#/$defs/Bytes" }, { "type": "null" }]
                    },
                    "signature": { "$ref": "#/$defs/SignatureEnvelope" }
                }
            },
            "StepReceipt": {
                "type": "object",
                "additionalProperties": false,
                "required": [
                    "run_id",
                    "seq",
                    "kind",
                    "side_effect",
                    "request_hash",
                    "result_hash",
                    "tool_identity",
                    "signer",
                    "signature"
                ],
                "properties": {
                    "run_id": { "$ref": "#/$defs/AgentRunId" },
                    "seq": { "type": "integer", "minimum": 1 },
                    "prev_receipt_hash": {
                        "anyOf": [{ "$ref": "#/$defs/H256" }, { "type": "null" }]
                    },
                    "kind": { "$ref": "#/$defs/StepKind" },
                    "side_effect": { "$ref": "#/$defs/SideEffect" },
                    "request_hash": { "$ref": "#/$defs/H256" },
                    "result_hash": { "$ref": "#/$defs/H256" },
                    "evidence_uri_hash": {
                        "anyOf": [{ "$ref": "#/$defs/H256" }, { "type": "null" }]
                    },
                    "tool_identity": { "type": "string", "minLength": 1 },
                    "signer": { "$ref": "#/$defs/H160" },
                    "signature": { "$ref": "#/$defs/SignatureEnvelope" }
                }
            },
            "PaymentEnvelope": {
                "type": "object",
                "additionalProperties": false,
                "required": [
                    "token",
                    "amount",
                    "recipient",
                    "quote_hash",
                    "request_hash",
                    "nonce",
                    "expires_at_slot",
                    "chain_id",
                    "side_effect",
                    "max_replays",
                    "signature"
                ],
                "properties": {
                    "token": { "$ref": "#/$defs/PaymentToken" },
                    "amount": { "type": "integer", "minimum": 1 },
                    "recipient": { "$ref": "#/$defs/H160" },
                    "quote_hash": { "$ref": "#/$defs/H256" },
                    "request_hash": { "$ref": "#/$defs/H256" },
                    "result_hash": {
                        "anyOf": [{ "$ref": "#/$defs/H256" }, { "type": "null" }]
                    },
                    "nonce": { "$ref": "#/$defs/H256" },
                    "expires_at_slot": { "type": "integer", "minimum": 1 },
                    "chain_id": { "type": "integer", "minimum": 1 },
                    "side_effect": { "$ref": "#/$defs/SideEffect" },
                    "max_replays": { "type": "integer", "minimum": 1 },
                    "signature": { "$ref": "#/$defs/SignatureEnvelope" }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_is_valid_json_object_with_expected_defs() {
        let schema = agent_contract_schema();
        assert_eq!(
            schema.get("$schema").and_then(Value::as_str),
            Some("https://json-schema.org/draft/2020-12/schema")
        );
        let defs = schema
            .get("$defs")
            .and_then(Value::as_object)
            .expect("schema must contain definitions");
        for required in [
            "SignatureEnvelope",
            "AgentAuthorization",
            "StepReceipt",
            "PaymentEnvelope",
            "SideEffect",
            "StepKind",
        ] {
            assert!(defs.contains_key(required), "missing {required}");
        }
    }

    #[test]
    fn signature_envelope_schema_requires_crypto_agility_fields() {
        let schema = agent_contract_schema();
        let required = schema["$defs"]["SignatureEnvelope"]["required"]
            .as_array()
            .expect("required fields must be an array");
        for field in [
            "alg",
            "domain",
            "chain_id",
            "key_id",
            "payload_hash",
            "signature",
        ] {
            assert!(
                required.iter().any(|value| value.as_str() == Some(field)),
                "missing required SignatureEnvelope field {field}"
            );
        }
    }
}
