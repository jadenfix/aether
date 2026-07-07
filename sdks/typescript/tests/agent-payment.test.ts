import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { test } from "node:test";

import { getPublicKey, sign } from "@noble/ed25519";

import {
  AETHER_PAYMENT_HASH_HEADER,
  AETHER_PAYMENT_HEADER,
  AETHER_PAYMENT_SCHEME,
  PAYMENT_AUTHORIZATION_DOMAIN,
  PAYMENT_SIGNATURE_DOMAIN,
  attachPaymentSignature,
  buildPaymentRequiredResponse,
  buildUnsignedPaymentEnvelope,
  canonicalJson,
  decodePaymentHeader,
  paymentEnvelopeHash,
  paymentHeaders,
  paymentSigningPayloadHash,
  typedJsonHash,
  verifyPaymentEnvelopeSignature,
} from "../src/index.js";

type AgentPaymentFixture = {
  payment: ReturnType<typeof signedPayment>;
  expected: {
    signing_payload_hash: string;
    payment_hash: string;
    payment_header_name: string;
    payment_hash_header_name: string;
    payment_header: string;
    payment_hash_header: string;
  };
};

const h = (byte: string) => `0x${byte.repeat(64)}` as const;
const addr = (byte: string) => `0x${byte.repeat(40)}` as const;
const toHex = (bytes: Uint8Array) =>
  `0x${Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("")}` as const;
const hexToBytes = (hex: string) => {
  const raw = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(raw.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(raw.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
};

function signedPayment() {
  const unsigned = buildUnsignedPaymentEnvelope({
    token: "aic",
    amount: 1_500_000_000_000_000_000n,
    recipient: addr("1"),
    quoteHash: h("2"),
    requestHash: h("3"),
    resultHash: h("4"),
    nonce: h("5"),
    expiresAtSlot: 100,
    chainId: 7,
    sideEffect: "purchase",
  });

  return attachPaymentSignature(unsigned, {
    keyId: "agent-session-ed25519",
    signature: `0x${"aa".repeat(64)}`,
  });
}

function conformanceFixture(): AgentPaymentFixture {
  return JSON.parse(
    readFileSync(resolve(process.cwd(), "../../fixtures/agent-payment-v1.json"), "utf8"),
  ) as AgentPaymentFixture;
}

test("canonical JSON and typed hashes are deterministic", () => {
  const left = { z: 1, a: { y: "2", x: [true, null] } };
  const right = { a: { x: [true, null], y: "2" }, z: 1 };

  assert.equal(canonicalJson(left), canonicalJson(right));
  assert.equal(typedJsonHash("aether/test/v1", left), typedJsonHash("aether/test/v1", right));
  assert.notEqual(
    typedJsonHash("aether/test/v1", left),
    typedJsonHash("aether/other/v1", left),
  );
});

test("payment signing payload excludes signature and changes on settlement fields", () => {
  const payment = signedPayment();
  const baseline = paymentSigningPayloadHash(payment);

  assert.equal(payment.signature.domain, PAYMENT_SIGNATURE_DOMAIN);
  assert.equal(PAYMENT_AUTHORIZATION_DOMAIN, PAYMENT_SIGNATURE_DOMAIN);
  assert.equal(payment.signature.payload_hash, baseline);
  assert.equal(
    baseline,
    "0x67a31cca14241a7b60473113eedb5978ff3c586e8bfaf9dbd6ea8ff92dbbe131",
  );
  assert.equal(
    paymentEnvelopeHash(payment),
    "0x0831ce74c89358835be790d4a7794a2bb30cd7e5968bafb5cc99423ea5f25783",
  );
  assert.equal(
    paymentSigningPayloadHash({
      ...payment,
      signature: {
        ...payment.signature,
        signature: `0x${"bb".repeat(64)}`,
      },
    }),
    baseline,
  );
  assert.notEqual(
    paymentSigningPayloadHash({
      ...payment,
      amount: "1500000000000000001",
    }),
    baseline,
  );
  assert.notEqual(
    paymentSigningPayloadHash({
      ...payment,
      result_hash: h("6"),
    }),
    baseline,
  );
});

test("payment envelope matches shared Rust/TypeScript conformance fixture", () => {
  const fixture = conformanceFixture();

  assert.equal(paymentSigningPayloadHash(fixture.payment), fixture.expected.signing_payload_hash);
  assert.equal(paymentEnvelopeHash(fixture.payment), fixture.expected.payment_hash);
  assert.equal(paymentHeaders(fixture.payment)[AETHER_PAYMENT_HEADER], fixture.expected.payment_header);
  assert.equal(
    paymentHeaders(fixture.payment)[AETHER_PAYMENT_HASH_HEADER],
    fixture.expected.payment_hash_header,
  );
  assert.equal(fixture.expected.payment_header_name, AETHER_PAYMENT_HEADER);
  assert.equal(fixture.expected.payment_hash_header_name, AETHER_PAYMENT_HASH_HEADER);
  assert.deepEqual(decodePaymentHeader(fixture.expected.payment_header), fixture.payment);
});

test("payment validation rejects non-canonical signature domains", () => {
  const payment = signedPayment();

  assert.throws(
    () =>
      paymentEnvelopeHash({
        ...payment,
        signature: {
          ...payment.signature,
          domain: "aether/not_payment/v1",
        },
      }),
    /signature domain must be aether\/agent_payment_authorization\/v1/,
  );
});

test("payment headers round-trip an Aether HTTP payment payload", () => {
  const payment = signedPayment();
  const headers = paymentHeaders(payment);

  assert.ok(headers[AETHER_PAYMENT_HEADER]);
  assert.equal(headers[AETHER_PAYMENT_HASH_HEADER], paymentEnvelopeHash(payment));
  assert.deepEqual(decodePaymentHeader(headers[AETHER_PAYMENT_HEADER]), payment);
});

test("payment signature verification accepts real Ed25519 signatures", async () => {
  const unsigned = buildUnsignedPaymentEnvelope({
    token: "aic",
    amount: "2500000",
    recipient: addr("1"),
    quoteHash: h("2"),
    requestHash: h("3"),
    resultHash: h("4"),
    nonce: h("5"),
    expiresAtSlot: 100,
    chainId: 7,
    sideEffect: "purchase",
  });
  const privateKey = new Uint8Array(32).fill(7);
  const publicKey = await getPublicKey(privateKey);
  const payloadHash = paymentSigningPayloadHash(unsigned);
  const signature = await sign(hexToBytes(payloadHash), privateKey);
  const payment = attachPaymentSignature(unsigned, {
    keyId: "agent-session-ed25519",
    signature: toHex(signature),
  });

  assert.equal(await verifyPaymentEnvelopeSignature(payment, publicKey), true);
  assert.equal(
    await verifyPaymentEnvelopeSignature(
      {
        ...payment,
        signature: {
          ...payment.signature,
          signature: `0x${"bb".repeat(64)}`,
        },
      },
      publicKey,
    ),
    false,
  );
});

test("high-risk payments require a result hash", () => {
  assert.throws(
    () =>
      buildUnsignedPaymentEnvelope({
        token: "aic",
        amount: "1",
        recipient: addr("1"),
        quoteHash: h("2"),
        requestHash: h("3"),
        nonce: h("5"),
        expiresAtSlot: 100,
        chainId: 7,
        sideEffect: "purchase",
      }),
    /result_hash is required/,
  );
});

test("payment validation rejects unsafe amounts and stale expirations", () => {
  assert.throws(
    () =>
      buildUnsignedPaymentEnvelope({
        token: "aic",
        amount: 0n,
        recipient: addr("1"),
        quoteHash: h("2"),
        requestHash: h("3"),
        nonce: h("5"),
        expiresAtSlot: 100,
        chainId: 7,
        sideEffect: "read",
      }),
    /amount must be a positive/,
  );

  const payment = signedPayment();
  assert.throws(
    () => paymentEnvelopeHash({ ...payment, expires_at_slot: 0 }),
    /expires_at_slot must be a positive/,
  );
});

test("payment required response exposes a stable accept option", () => {
  const response = buildPaymentRequiredResponse({
    network: "aether-mainnet",
    resource: "mcp://beater.mail/send",
    recipient: addr("1"),
    token: "aic",
    amount: "2500000",
    quoteHash: h("2"),
    requestHash: h("3"),
    sideEffect: "send",
    chainId: 7,
    expiresAtSlot: 100,
    description: "Pay for a tool call",
  });

  assert.equal(response.error, "payment_required");
  assert.equal(response.description, "Pay for a tool call");
  assert.equal(response.accepts[0].scheme, AETHER_PAYMENT_SCHEME);
  assert.equal(response.accepts[0].max_amount_required, "2500000");
  assert.equal(response.accepts[0].extra.side_effect, "send");
});

test("payment required response rejects invalid requirements", () => {
  assert.throws(
    () =>
      buildPaymentRequiredResponse({
        network: "aether-mainnet",
        resource: "mcp://beater.mail/send",
        recipient: addr("1"),
        token: "aic",
        amount: "0",
        quoteHash: h("2"),
        requestHash: h("3"),
        sideEffect: "send",
        chainId: 7,
        expiresAtSlot: 100,
      }),
    /amount must be a positive/,
  );
  assert.throws(
    () =>
      buildPaymentRequiredResponse({
        network: "",
        resource: "mcp://beater.mail/send",
        recipient: addr("1"),
        token: "aic",
        amount: "1",
        quoteHash: h("2"),
        requestHash: h("3"),
        sideEffect: "send",
        chainId: 7,
        expiresAtSlot: 100,
      }),
    /network must not be empty/,
  );
});
