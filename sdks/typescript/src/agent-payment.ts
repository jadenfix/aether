import { blake3 } from "@noble/hashes/blake3.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { verify as verifyEd25519 } from "@noble/ed25519";

export const AETHER_PAYMENT_SCHEME = "aether-agent-payment-v1";
export const AETHER_PAYMENT_HEADER = "X-PAYMENT";
export const AETHER_PAYMENT_HASH_HEADER = "X-AETHER-PAYMENT-HASH";

export const AGENT_AUTHORIZATION_SIGNATURE_DOMAIN =
  "aether/agent_authorization/v1";
export const PAYMENT_SIGNATURE_DOMAIN = "aether/payment/v1";
// Domain for the canonical payment signing payload hash. The signature
// envelope itself must use PAYMENT_SIGNATURE_DOMAIN.
export const PAYMENT_AUTHORIZATION_DOMAIN =
  "aether/agent_payment_authorization/v1";
export const PAYMENT_ENVELOPE_DOMAIN = "aether/agent_payment_envelope/v1";

export type Hex = `0x${string}`;
export type H160 = Hex;
export type H256 = Hex;
export type DecimalAmount = string;

export type SigningAlgorithm =
  | "ed25519"
  | "bls12381"
  | "frost_ristretto255"
  | "ed25519_ml_dsa87"
  | "ml_dsa87"
  | "slh_dsa_sha2256f";

export type SideEffect =
  | "read"
  | "draft"
  | "write"
  | "send"
  | "purchase"
  | "delete";

export type PaymentToken = "aic" | "swr";
export type AmountInput = bigint | number | string;

export interface SignatureEnvelope {
  alg: SigningAlgorithm;
  domain: string;
  chain_id: number;
  key_id: string;
  payload_hash: H256;
  signature: Hex;
  pq_signature?: Hex | null;
}

export interface UnsignedPaymentEnvelope {
  token: PaymentToken;
  amount: DecimalAmount;
  recipient: H160;
  quote_hash: H256;
  request_hash: H256;
  result_hash?: H256 | null;
  nonce: H256;
  expires_at_slot: number;
  chain_id: number;
  side_effect: SideEffect;
  max_replays: number;
}

export interface PaymentEnvelope extends UnsignedPaymentEnvelope {
  signature: SignatureEnvelope;
}

export interface PaymentEnvelopeInput {
  token: PaymentToken;
  amount: AmountInput;
  recipient: H160;
  quoteHash: H256;
  requestHash: H256;
  resultHash?: H256 | null;
  nonce: H256;
  expiresAtSlot: number;
  chainId: number;
  sideEffect: SideEffect;
  maxReplays?: number;
}

export interface PaymentSignatureInput {
  alg?: SigningAlgorithm;
  domain?: string;
  chainId?: number;
  keyId: string;
  signature: Hex;
  pqSignature?: Hex | null;
}

export interface PaymentRequiredOptions {
  network: string;
  resource: string;
  recipient: H160;
  token: PaymentToken;
  amount: AmountInput;
  quoteHash: H256;
  requestHash: H256;
  sideEffect: SideEffect;
  chainId: number;
  expiresAtSlot: number;
  description?: string;
}

export interface PaymentAcceptOption {
  scheme: typeof AETHER_PAYMENT_SCHEME;
  network: string;
  resource: string;
  pay_to: H160;
  token: PaymentToken;
  max_amount_required: DecimalAmount;
  extra: {
    quote_hash: H256;
    request_hash: H256;
    side_effect: SideEffect;
    chain_id: number;
    expires_at_slot: number;
  };
}

export interface PaymentRequiredResponse {
  accepts: PaymentAcceptOption[];
  error?: string;
  description?: string;
}

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const H160_RE = /^0x[0-9a-fA-F]{40}$/;
const H256_RE = /^0x[0-9a-fA-F]{64}$/;
const HEX_RE = /^0x(?:[0-9a-fA-F]{2})*$/;
const DECIMAL_RE = /^(?:0|[1-9][0-9]*)$/;
const SIGNING_ALGORITHMS = new Set<SigningAlgorithm>([
  "ed25519",
  "bls12381",
  "frost_ristretto255",
  "ed25519_ml_dsa87",
  "ml_dsa87",
  "slh_dsa_sha2256f",
]);
const PAYMENT_TOKENS = new Set<PaymentToken>(["aic", "swr"]);
const SIDE_EFFECTS = new Set<SideEffect>([
  "read",
  "draft",
  "write",
  "send",
  "purchase",
  "delete",
]);
const PQ_ALGORITHMS = new Set<SigningAlgorithm>([
  "ed25519_ml_dsa87",
  "ml_dsa87",
  "slh_dsa_sha2256f",
]);
const HIGH_RISK_EFFECTS = new Set<SideEffect>([
  "send",
  "purchase",
  "delete",
]);
const U128_MAX = (1n << 128n) - 1n;
const U64_MAX = (1n << 64n) - 1n;

export function buildUnsignedPaymentEnvelope(
  input: PaymentEnvelopeInput,
): UnsignedPaymentEnvelope {
  const envelope: UnsignedPaymentEnvelope = {
    token: input.token,
    amount: normalizeAmount(input.amount),
    recipient: normalizeHex(input.recipient) as H160,
    quote_hash: normalizeHex(input.quoteHash) as H256,
    request_hash: normalizeHex(input.requestHash) as H256,
    result_hash:
      input.resultHash === undefined || input.resultHash === null
        ? null
        : (normalizeHex(input.resultHash) as H256),
    nonce: normalizeHex(input.nonce) as H256,
    expires_at_slot: input.expiresAtSlot,
    chain_id: input.chainId,
    side_effect: input.sideEffect,
    max_replays: input.maxReplays ?? 1,
  };
  validateUnsignedPaymentEnvelope(envelope);
  return envelope;
}

export function attachPaymentSignature(
  envelope: UnsignedPaymentEnvelope,
  input: PaymentSignatureInput,
): PaymentEnvelope {
  validateUnsignedPaymentEnvelope(envelope);
  const payment: PaymentEnvelope = {
    ...envelope,
    signature: {
      alg: input.alg ?? "ed25519",
      domain: input.domain ?? PAYMENT_SIGNATURE_DOMAIN,
      chain_id: input.chainId ?? envelope.chain_id,
      key_id: input.keyId,
      payload_hash: paymentSigningPayloadHash(envelope),
      signature: normalizeHex(input.signature) as Hex,
      pq_signature:
        input.pqSignature === undefined || input.pqSignature === null
          ? null
          : (normalizeHex(input.pqSignature) as Hex),
    },
  };
  validatePaymentEnvelope(payment);
  return payment;
}

export function paymentSigningPayload(
  envelope: PaymentEnvelope | UnsignedPaymentEnvelope,
): UnsignedPaymentEnvelope {
  const { signature: _signature, ...payload } = envelope as PaymentEnvelope;
  return {
    ...payload,
    result_hash: payload.result_hash ?? null,
  };
}

export function paymentSigningPayloadHash(
  envelope: PaymentEnvelope | UnsignedPaymentEnvelope,
): H256 {
  return typedBincodeHash(
    PAYMENT_AUTHORIZATION_DOMAIN,
    encodePaymentSigningPayload(paymentSigningPayload(envelope)),
  );
}

export function paymentEnvelopeHash(envelope: PaymentEnvelope): H256 {
  validatePaymentEnvelope(envelope);
  return typedBincodeHash(PAYMENT_ENVELOPE_DOMAIN, encodePaymentEnvelope(envelope));
}

export function encodePaymentHeader(envelope: PaymentEnvelope): string {
  validatePaymentEnvelope(envelope);
  return encodeBase64Url(canonicalJson(envelope));
}

export function decodePaymentHeader(header: string): PaymentEnvelope {
  const decoded = decodeBase64Url(header);
  const parsed = JSON.parse(decoded) as PaymentEnvelope;
  validatePaymentEnvelope(parsed);
  return parsed;
}

export function paymentHeaders(envelope: PaymentEnvelope): Record<string, string> {
  return {
    [AETHER_PAYMENT_HEADER]: encodePaymentHeader(envelope),
    [AETHER_PAYMENT_HASH_HEADER]: paymentEnvelopeHash(envelope),
  };
}

export function buildPaymentRequiredResponse(
  options: PaymentRequiredOptions,
): PaymentRequiredResponse {
  const amount = normalizeAmount(options.amount);
  assertPositiveAmount(amount, "amount");
  assertPaymentToken(options.token);
  assertSideEffect(options.sideEffect);
  if (options.network.trim() === "") {
    throw new Error("network must not be empty");
  }
  if (options.resource.trim() === "") {
    throw new Error("resource must not be empty");
  }
  assertH160(options.recipient, "recipient");
  assertH256(options.quoteHash, "quoteHash");
  assertH256(options.requestHash, "requestHash");
  assertPositiveInteger(options.chainId, "chainId");
  assertPositiveInteger(options.expiresAtSlot, "expiresAtSlot");

  return {
    accepts: [
      {
        scheme: AETHER_PAYMENT_SCHEME,
        network: options.network,
        resource: options.resource,
        pay_to: normalizeHex(options.recipient) as H160,
        token: options.token,
        max_amount_required: amount,
        extra: {
          quote_hash: normalizeHex(options.quoteHash) as H256,
          request_hash: normalizeHex(options.requestHash) as H256,
          side_effect: options.sideEffect,
          chain_id: options.chainId,
          expires_at_slot: options.expiresAtSlot,
        },
      },
    ],
    error: "payment_required",
    description: options.description,
  };
}

/**
 * Performs schema and invariant validation only. Use
 * verifyPaymentEnvelopeSignature() with the authorized session public key before
 * accepting a payment as signed by an agent.
 */
export function validatePaymentEnvelope(
  envelope: PaymentEnvelope,
  currentSlot = 0,
): void {
  validateUnsignedPaymentEnvelope(envelope, currentSlot);
  validateSignatureEnvelope(envelope.signature);
  if (envelope.signature.domain !== PAYMENT_SIGNATURE_DOMAIN) {
    throw new Error(`signature domain must be ${PAYMENT_SIGNATURE_DOMAIN}`);
  }
  if (envelope.signature.chain_id !== envelope.chain_id) {
    throw new Error("signature chain_id must match payment chain_id");
  }
  const expectedPayloadHash = paymentSigningPayloadHash(envelope);
  if (
    envelope.signature.payload_hash.toLowerCase() !==
    expectedPayloadHash.toLowerCase()
  ) {
    throw new Error("signature payload_hash does not match payment payload");
  }
}

export function validateUnsignedPaymentEnvelope(
  envelope: UnsignedPaymentEnvelope,
  currentSlot = 0,
): void {
  assertPaymentToken(envelope.token);
  assertSideEffect(envelope.side_effect);
  assertPositiveAmount(envelope.amount, "amount");
  assertH160(envelope.recipient, "recipient");
  if (/^0x0{40}$/i.test(envelope.recipient)) {
    throw new Error("recipient must not be the zero address");
  }
  assertH256(envelope.quote_hash, "quote_hash");
  assertH256(envelope.request_hash, "request_hash");
  if (envelope.result_hash !== undefined && envelope.result_hash !== null) {
    assertH256(envelope.result_hash, "result_hash");
  }
  assertH256(envelope.nonce, "nonce");
  assertPositiveInteger(envelope.expires_at_slot, "expires_at_slot");
  assertPositiveInteger(envelope.chain_id, "chain_id");
  assertPositiveInteger(envelope.max_replays, "max_replays");
  if (envelope.expires_at_slot <= currentSlot) {
    throw new Error("expires_at_slot must be greater than currentSlot");
  }
  if (
    HIGH_RISK_EFFECTS.has(envelope.side_effect) &&
    (envelope.result_hash === undefined || envelope.result_hash === null)
  ) {
    throw new Error("result_hash is required for high-risk side effects");
  }
}

export function validateSignatureEnvelope(envelope: SignatureEnvelope): void {
  assertSigningAlgorithm(envelope.alg);
  if (!envelope.domain.startsWith("aether/")) {
    throw new Error("signature domain must start with aether/");
  }
  assertPositiveInteger(envelope.chain_id, "signature.chain_id");
  if (envelope.key_id.trim() === "") {
    throw new Error("signature key_id must not be empty");
  }
  assertH256(envelope.payload_hash, "signature.payload_hash");
  assertHex(envelope.signature, "signature.signature");
  if (envelope.signature.length === 2) {
    throw new Error("signature signature must not be empty");
  }
  if (envelope.pq_signature !== undefined && envelope.pq_signature !== null) {
    assertHex(envelope.pq_signature, "signature.pq_signature");
  }
  if (
    PQ_ALGORITHMS.has(envelope.alg) &&
    (envelope.pq_signature === undefined ||
      envelope.pq_signature === null ||
      envelope.pq_signature.length === 2)
  ) {
    throw new Error("post-quantum signature is required for this algorithm");
  }
}

/**
 * Verifies an Ed25519 payment signature over the same bincode typed payload
 * hash used by Rust settlement verification.
 */
export async function verifyPaymentEnvelopeSignature(
  envelope: PaymentEnvelope,
  sessionPublicKey: Hex | Uint8Array,
): Promise<boolean> {
  validatePaymentEnvelope(envelope);
  if (envelope.signature.alg !== "ed25519") {
    throw new Error("payment signature verification currently supports ed25519");
  }
  try {
    return await verifyEd25519(
      hexToBytes(envelope.signature.signature),
      hexToBytes(envelope.signature.payload_hash),
      bytesInput(sessionPublicKey, "sessionPublicKey"),
    );
  } catch {
    return false;
  }
}

export function typedBincodeHash(domain: string, encodedValue: Uint8Array): H256 {
  if (!domain.startsWith("aether/")) {
    throw new Error("domain must start with aether/");
  }
  const domainBytes = textEncoder.encode(domain);
  const bytes = new Uint8Array(domainBytes.length + 1 + encodedValue.length);
  bytes.set(domainBytes, 0);
  bytes[domainBytes.length] = 0;
  bytes.set(encodedValue, domainBytes.length + 1);
  return `0x${bytesToHex(blake3(bytes))}`;
}

/**
 * BLAKE3(domain || 0x00 || canonical-json(value)) for HTTP/x402 transport
 * binding. Rust chain verification uses its bincode typed hash internally.
 */
export function typedJsonHash(domain: string, value: unknown): H256 {
  if (!domain.startsWith("aether/")) {
    throw new Error("domain must start with aether/");
  }
  const domainBytes = textEncoder.encode(domain);
  const payloadBytes = textEncoder.encode(canonicalJson(value));
  const bytes = new Uint8Array(domainBytes.length + 1 + payloadBytes.length);
  bytes.set(domainBytes, 0);
  bytes[domainBytes.length] = 0;
  bytes.set(payloadBytes, domainBytes.length + 1);
  return `0x${bytesToHex(blake3(bytes))}`;
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

function canonicalize(value: unknown): unknown {
  if (value === null) {
    return null;
  }
  if (typeof value === "bigint") {
    return value.toString(10);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error("canonical JSON cannot encode non-finite numbers");
    }
    return value;
  }
  if (typeof value === "string" || typeof value === "boolean") {
    return value;
  }
  if (value === undefined || typeof value === "function") {
    throw new Error("canonical JSON cannot encode undefined values");
  }
  if (Array.isArray(value)) {
    return value.map((item) => canonicalize(item));
  }
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(record).sort()) {
      const next = record[key];
      if (next !== undefined) {
        out[key] = canonicalize(next);
      }
    }
    return out;
  }
  throw new Error(`canonical JSON cannot encode ${typeof value}`);
}

function normalizeAmount(amount: AmountInput): DecimalAmount {
  if (typeof amount === "bigint") {
    if (amount < 0n) {
      throw new Error("amount must not be negative");
    }
    return amount.toString(10);
  }
  if (typeof amount === "number") {
    if (!Number.isSafeInteger(amount) || amount < 0) {
      throw new Error("amount number must be a non-negative safe integer");
    }
    return amount.toString(10);
  }
  if (!DECIMAL_RE.test(amount)) {
    throw new Error("amount must be a base-10 integer string");
  }
  return amount;
}

function normalizeHex(value: Hex): Hex {
  return value.toLowerCase() as Hex;
}

function encodePaymentSigningPayload(envelope: UnsignedPaymentEnvelope): Uint8Array {
  const encoder = new BincodeEncoder();
  encoder.writeU32(paymentTokenVariant(envelope.token));
  encoder.writeU128(BigInt(envelope.amount));
  encoder.writeFixedBytes(hexToBytes(envelope.recipient), 20, "recipient");
  encoder.writeFixedBytes(hexToBytes(envelope.quote_hash), 32, "quote_hash");
  encoder.writeFixedBytes(hexToBytes(envelope.request_hash), 32, "request_hash");
  encoder.writeOptionFixedBytes(
    envelope.result_hash === undefined || envelope.result_hash === null
      ? null
      : hexToBytes(envelope.result_hash),
    32,
    "result_hash",
  );
  encoder.writeFixedBytes(hexToBytes(envelope.nonce), 32, "nonce");
  encoder.writeU64(BigInt(envelope.expires_at_slot));
  encoder.writeU64(BigInt(envelope.chain_id));
  encoder.writeU32(sideEffectVariant(envelope.side_effect));
  encoder.writeU32(envelope.max_replays);
  return encoder.finish();
}

function encodePaymentEnvelope(envelope: PaymentEnvelope): Uint8Array {
  const encoder = new BincodeEncoder();
  encoder.writeBytes(encodePaymentSigningPayload(envelope));
  encoder.writeBytes(encodeSignatureEnvelope(envelope.signature));
  return encoder.finish();
}

function encodeSignatureEnvelope(envelope: SignatureEnvelope): Uint8Array {
  const encoder = new BincodeEncoder();
  encoder.writeU32(signingAlgorithmVariant(envelope.alg));
  encoder.writeString(envelope.domain);
  encoder.writeU64(BigInt(envelope.chain_id));
  encoder.writeString(envelope.key_id);
  encoder.writeFixedBytes(hexToBytes(envelope.payload_hash), 32, "signature.payload_hash");
  encoder.writeVecBytes(hexToBytes(envelope.signature));
  encoder.writeOptionVecBytes(
    envelope.pq_signature === undefined || envelope.pq_signature === null
      ? null
      : hexToBytes(envelope.pq_signature),
  );
  return encoder.finish();
}

function signingAlgorithmVariant(value: SigningAlgorithm): number {
  switch (value) {
    case "ed25519":
      return 0;
    case "bls12381":
      return 1;
    case "frost_ristretto255":
      return 2;
    case "ed25519_ml_dsa87":
      return 3;
    case "ml_dsa87":
      return 4;
    case "slh_dsa_sha2256f":
      return 5;
  }
}

function paymentTokenVariant(value: PaymentToken): number {
  switch (value) {
    case "aic":
      return 0;
    case "swr":
      return 1;
  }
}

function sideEffectVariant(value: SideEffect): number {
  switch (value) {
    case "read":
      return 0;
    case "draft":
      return 1;
    case "write":
      return 2;
    case "send":
      return 3;
    case "purchase":
      return 4;
    case "delete":
      return 5;
  }
}

function assertSigningAlgorithm(value: SigningAlgorithm): void {
  if (!SIGNING_ALGORITHMS.has(value)) {
    throw new Error("signature alg is not supported");
  }
}

function assertPaymentToken(value: PaymentToken): void {
  if (!PAYMENT_TOKENS.has(value)) {
    throw new Error("token must be aic or swr");
  }
}

function assertSideEffect(value: SideEffect): void {
  if (!SIDE_EFFECTS.has(value)) {
    throw new Error("side_effect is not supported");
  }
}

function assertH160(value: string, name: string): void {
  if (!H160_RE.test(value)) {
    throw new Error(`${name} must be a 20-byte 0x-prefixed hex string`);
  }
}

function assertH256(value: string, name: string): void {
  if (!H256_RE.test(value)) {
    throw new Error(`${name} must be a 32-byte 0x-prefixed hex string`);
  }
}

function assertHex(value: string, name: string): void {
  if (!HEX_RE.test(value)) {
    throw new Error(`${name} must be an even-length 0x-prefixed hex string`);
  }
}

function assertPositiveAmount(value: DecimalAmount, name: string): void {
  if (!DECIMAL_RE.test(value)) {
    throw new Error(`${name} must be a positive base-10 integer string`);
  }
  const parsed = BigInt(value);
  if (parsed === 0n) {
    throw new Error(`${name} must be a positive base-10 integer string`);
  }
  if (parsed > U128_MAX) {
    throw new Error(`${name} must fit in u128`);
  }
}

function assertPositiveInteger(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${name} must be a positive safe integer`);
  }
}

function encodeBase64Url(value: string): string {
  const bytes = textEncoder.encode(value);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

function decodeBase64Url(value: string): string {
  const padded = value
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return textDecoder.decode(bytes);
}

function hexToBytes(value: Hex): Uint8Array {
  assertHex(value, "hex");
  const hex = value.slice(2);
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

function bytesInput(value: Hex | Uint8Array, name: string): Uint8Array {
  if (value instanceof Uint8Array) {
    return value;
  }
  assertHex(value, name);
  return hexToBytes(value);
}

class BincodeEncoder {
  private readonly chunks: Uint8Array[] = [];

  writeBytes(bytes: Uint8Array): void {
    this.chunks.push(bytes);
  }

  writeFixedBytes(bytes: Uint8Array, length: number, name: string): void {
    if (bytes.length !== length) {
      throw new Error(`${name} must be exactly ${length} bytes`);
    }
    this.writeBytes(bytes);
  }

  writeOptionFixedBytes(
    bytes: Uint8Array | null,
    length: number,
    name: string,
  ): void {
    if (bytes === null) {
      this.writeU8(0);
      return;
    }
    this.writeU8(1);
    this.writeFixedBytes(bytes, length, name);
  }

  writeOptionVecBytes(bytes: Uint8Array | null): void {
    if (bytes === null) {
      this.writeU8(0);
      return;
    }
    this.writeU8(1);
    this.writeVecBytes(bytes);
  }

  writeVecBytes(bytes: Uint8Array): void {
    this.writeU64(BigInt(bytes.length));
    this.writeBytes(bytes);
  }

  writeString(value: string): void {
    this.writeVecBytes(textEncoder.encode(value));
  }

  writeU8(value: number): void {
    if (!Number.isInteger(value) || value < 0 || value > 0xff) {
      throw new Error("u8 out of range");
    }
    this.writeBytes(Uint8Array.of(value));
  }

  writeU32(value: number): void {
    if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
      throw new Error("u32 out of range");
    }
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(0, value, true);
    this.writeBytes(bytes);
  }

  writeU64(value: bigint): void {
    if (value < 0n || value > U64_MAX) {
      throw new Error("u64 out of range");
    }
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigUint64(0, value, true);
    this.writeBytes(bytes);
  }

  writeU128(value: bigint): void {
    if (value < 0n || value > U128_MAX) {
      throw new Error("u128 out of range");
    }
    const bytes = new Uint8Array(16);
    let cursor = value;
    for (let index = 0; index < bytes.length; index += 1) {
      bytes[index] = Number(cursor & 0xffn);
      cursor >>= 8n;
    }
    this.writeBytes(bytes);
  }

  finish(): Uint8Array {
    const total = this.chunks.reduce((sum, chunk) => sum + chunk.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const chunk of this.chunks) {
      out.set(chunk, offset);
      offset += chunk.length;
    }
    return out;
  }
}
