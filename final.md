# aether — L1 settlement layer for the agent ecosystem

> **This is a design document, not a roadmap.** It describes *what Aether is*, *how it fits with the sibling Beater projects*, *what must change for ecosystem compatibility*, and *how we know each piece is done*. There are no dates. **§4** is the compatibility gap analysis; **§5** is the required change set; **§6** is the dependency graph; **§8** is the Definition of Done.

Aether is a Rust-first L1 with AI-verified compute (TEE + VCR), parallel WASM execution, sub-2s finality, and a dual-token economy (**SWR** staking/governance, **AIC** compute credits). Sibling projects live alongside it under the same workspace root: `../beater`, `../beater.js`, `../tempo`, `../beatbox`, `../beaterOS`.

---

## 1. Vision — what Aether *is* when it's done

Aether is the **value, identity, and dispute layer** for agent work — not the place where agents run.

Today's design already targets a tradable L1:

- **SWR** — stake, govern, earn validator rewards; tradable on the on-chain AMM.
- **AIC** — escrow for verifiable work; burned or transferred on settlement.
- **Job escrow + AI mesh** — post inference job → TEE worker → VCR proof → challenge window → pay.
- **Reputation** — provider scoring for routing and slashing eligibility.
- **Account abstraction** — programmable wallets (multisig, paymasters, custom validators).

The sibling stack owns **execution**:

| Sibling | Owns |
| --- | --- |
| **beater.js** | Web app + durable agent loop + MCP serve + polyglot tools |
| **tempo** | Structured browser observation/action + machine-web handshake |
| **beatbox** | Untrusted code sandbox (Wasmtime lanes) |
| **beater** | Traces, datasets, evals, CI gates, replay cassettes |
| **beaterOS** | OS-level authority, policy, receipts (future) |

**Done** means Aether can settle agent-native work from those systems without re-implementing their runtimes on-chain. The chain holds **escrow, tokens, reputation anchors, and dispute outcomes**; off-chain systems hold **journals, traces, browser state, and eval evidence**.

### What Aether is *not*

- Not a replacement for beater.js, tempo, or beatbox execution paths.
- Not an on-chain DOM, MCP server, or agent loop.
- Not a requirement for the OSS beater observability stack to function locally.
- Not a macOS/Linux replacement (that is beaterOS's lane).

---

## 2. First-principles requirements

1. **Tradable native assets.** SWR and AIC must be transferable, swappable (AMM), and usable for staking/governance without off-chain trust.
2. **Verifiable settlement.** Payment releases only after proof or challenge-window expiry — today via VCR for inference; extended for agent steps per §5.2.
3. **Programmable identity.** Agents need wallets with policy (spending caps, SideEffect gates, multisig confirm) — account abstraction is the hook.
4. **Separation of execution and settlement.** On-chain state is minimal hashes and escrow balances; full journals and traces stay off-chain (beater-agent, beater-replay, tempo-session).
5. **Protocol integration, not source coupling.** Bridges are SDK + JSON-RPC + shared wire types; Aether does not import beater/tempo crates into consensus hot paths.
6. **Honest verification scope.** VCR/TEE for LLM inference; receipts + optimistic challenge for browser/tool/sandbox steps. Do not claim full agent replay is cryptographically proved on L1.
7. **SideEffect-aware economics.** High-risk actions (Send, Purchase, Delete) require more escrow, longer challenge windows, or human co-sign — aligned with `beater-connect::SideEffect`.
8. **Eval-informed reputation.** On-chain reputation scores may be updated from beater eval outcomes, but raw eval logic stays in beater.

---

## 3. Current architecture (baseline)

```
Clients / aetherctl / SDKs / wallet / explorer
            |
            v
    JSON-RPC / gRPC firehose
            |
            v
  Node -> mempool -> consensus (VRF + HotStuff + BLS) -> runtime (parallel WASM) -> ledger (eUTxO++) -> state
            |
            +-> P2P / QUIC / Turbine DA
            |
            +-> Programs: staking, governance, AMM, job-escrow, aic-token, reputation, account-abstraction
            |
            +-> AI mesh (router / coordinator / worker) + verifiers (TEE, KZG, VCR)
```

### What ships in-repo today

| Area | Status |
| --- | --- |
| L1 protocol crates (node, consensus, ledger, runtime, p2p, da) | Substantial; devnet-ready, mainnet hardening in progress |
| SWR / AIC token programs | Present |
| AMM (SWR/AIC) | Present |
| Job escrow (inference-shaped) | Present — `model_hash`, `input_hash`, `output_hash`, VCR verify |
| AI mesh + VCR pipeline | Present |
| Account abstraction (ERC-4337 style) | Present |
| Genesis ceremony / mainnet launch | **Not done** — `config/genesis.toml` accounts/validators empty |
| Ecosystem bridges (beater.js / tempo / beater / beatbox) | **Not started** — zero cross-repo references |

### Current "AI-native" vs target "agent-native"

| Dimension | Aether today | Beater ecosystem |
| --- | --- | --- |
| Unit of work | Single **inference job** | **Agent run** with many steps |
| Verification | VCR + TEE attestation | Journal + idempotency + eval gates |
| Side effects | N/A (hash in / hash out) | `SideEffect`: Read → Draft → Write → Send → Purchase → Delete |
| Tooling | AI mesh workers | MCP tools, tempo act/observe, beatbox execute |
| Quality gate | On-chain reputation + slashing | beater eval CI + `needs_review` on non-idempotent crash |
| Discovery | JSON-RPC | beater-connect (`.well-known/beater.json`, OpenAPI, MCP) |

**Compatibility does not require replacing the L1.** It requires a new **application layer** (programs + bridges + token semantics) on top of the existing chain.

---

## 4. Compatibility gap analysis

### 4.1 What already maps

| Aether today | Ecosystem use |
| --- | --- |
| AIC escrow | Pay for agent runs, tempo sessions, beatbox executions |
| Job escrow state machine | Template for multi-step **AgentRunEscrow** |
| Reputation (provider EWMA) | Extend to **agent operators** and **tool providers** |
| Account abstraction | Agent wallets with SideEffect policy validators |
| VCR + TEE | Attest **LLM steps** inside an agent run |
| AMM | Trade SWR/AIC; liquidity for agent credits |
| WASM programs | Custom escrow rules, spending policies |

### 4.2 What is missing (the big gaps)

1. **On-chain agent primitives** — no `AgentRun`, `StepReceipt`, or `ToolCallEscrow`; only flat inference jobs.
2. **SideEffect taxonomy** — no chain-level alignment with `beater-connect::SideEffect` confirmation/idempotency rules.
3. **Journal anchoring** — no standard to commit `run_id` + journal Merkle root + step seq for dispute resolution.
4. **Hybrid verification** — VCR cannot cover browser clicks, MCP HTTP calls, or beatbox Wasm runs; need receipt + challenge model.
5. **Cross-repo SDK bridges** — beater.js, tempo, beater, beatbox have no settlement hooks.
6. **Machine-web payments** — no x402 / beater-connect paid-action flow tied to AIC micropayments.
7. **Eval → reputation pipe** — beater gate outcomes do not feed on-chain scores.
8. **Token semantics** — AIC is inference-only; agent workloads need action/session/sandbox metering.
9. **Identity binding** — no canonical link between agent session keys and chain addresses.

### 4.3 What we explicitly will not put on-chain

- Full agent journals, OTLP spans, or tempo observation blobs (too large; anchor hashes only).
- MCP JSON-RPC transport or browser rendering.
- beater eval execution (WASI sandbox stays in beater).
- Real-time LLM streaming (settle per step or per run, not per token, in v1).

---

## 5. Required changes for ecosystem compatibility

These are the **big changes** — ordered by dependency. None require forking consensus; all are additive.

### 5.1 Shared wire contracts (`aether-agent-schema`)

Freeze a language-neutral schema crate (JSON Schema + Rust types) shared with siblings via published crate or git submodule — **not** by coupling consensus to beater crates.

Minimum types:

```text
AgentRunId          — 32-byte id (matches beater-agent run id convention)
JournalRoot         — Merkle root over ordered steps
StepKind            — llm_call | tool_call | browse_act | sandbox_exec | mcp_call
SideEffect          — read | draft | write | send | purchase | delete  (matches beater-connect)
StepReceipt         — { run_id, seq, kind, side_effect, tool_use_id, request_hash, result_hash, signer }
RunStatus           — running | completed | failed | needs_review | disputed
SettlementPolicy    — { min_escrow_aic, challenge_slots, requires_human_confirm }
```

**Done when:** tempo, beater.js, and Aether SDKs serialize identical `StepReceipt` JSON; conformance tests pass in CI on both sides.

### 5.2 New on-chain programs

#### 5.2.1 `agent-run-escrow` (extends job-escrow)

Replace inference-only jobs with run-scoped escrow:

```text
open_run(run_id, requester, budget_aic, journal_root, policy)
commit_step(run_id, seq, receipt_hash)     — optional anchor per high-risk step
close_run(run_id, final_journal_root, evidence_uri)
dispute_step(run_id, seq, challenger, evidence_hash)
settle_run(run_id)                           — after challenge window
refund_run(run_id)                           — if never started or cancelled
```

State machine parallels beater-agent:

| Off-chain (beater-agent) | On-chain (agent-run-escrow) |
| --- | --- |
| `running` | escrow locked |
| `completed` | settle → provider/requester per policy |
| `failed` | partial refund rules |
| `needs_review` | escrow frozen until human tx or timeout |
| dangling `tool_call` + non-idempotent | frozen; no auto-settle |

**Done when:** integration test opens escrow from beater.js hello agent, completes run, settles on-chain; kill-9 mid-run → `needs_review` freezes escrow.

#### 5.2.2 `side-effect-gate` (policy program)

Encodes `beater-connect::SideEffect` economics on-chain:

| SideEffect | Default confirm | Idempotency required | Escrow multiplier (v1 proposal) |
| --- | --- | --- | --- |
| Read | no | no | 1× |
| Draft | no | no | 1× |
| Write | no | yes | 2× |
| Send | yes | yes | 5× |
| Purchase | yes | yes | 10× |
| Delete | yes | yes | 10× |

Integrates with account-abstraction validators: a UserOperation that triggers Purchase without co-sign fails verification.

**Done when:** AA wallet with SideEffect cap rejects Purchase above daily limit; Send requires 2-of-2 multisig in test.

#### 5.2.3 `reputation-bridge` (eval-informed scores)

Read-only oracle pattern (v1): authorized beater tenant publishes signed **EvalAttestation** `{ agent_address, eval_run_id, pass, delta, holdout_pass, timestamp }`. On-chain reputation EWMA updates on valid attestation; slashing remains separate.

v2: ZK or TEE attestation of eval result (optional; not blocking v1).

**Done when:** beater RSI gate pass on a candidate produces attestation → on-chain score increases; forged attestation rejected.

### 5.3 Hybrid verification model

Not every step gets VCR. Assign verification tier per `StepKind`:

| Step kind | Verification | Settlement trigger |
| --- | --- | --- |
| `llm_call` | VCR + TEE (existing pipeline) | Auto after challenge window if proof valid |
| `tool_call` (idempotent) | `StepReceipt` signed by runtime + `tool_use_id` | Optimistic; challengeable |
| `tool_call` (non-idempotent) | Receipt + human confirm tx or beater `needs_review` clear | Manual or eval attestation |
| `browse_act` (tempo) | Receipt + observation hash at seq N | Optimistic; challenge compares cassette |
| `sandbox_exec` (beatbox) | `ExecutionResult` hash from beatbox daemon | Optimistic; beatbox MCP/API signature |
| `mcp_call` (remote) | Receipt + HTTP response hash | Optimistic |

**Challenge flow:** challenger posts bond + counter-evidence URI; validators or watchtower arbitrate within `challenge_slots`; loser slashed.

**Done when:** doc test matrix covers all six step kinds; at least three have integration tests (llm_call, tool_call, sandbox_exec).

### 5.4 Token economics extension

Broaden **AIC** from "inference credits" to **agent action credits** without a new token (v1):

| Spend category | Meter |
| --- | --- |
| LLM inference | Existing job-escrow / VCR path |
| Agent run base fee | `open_run` flat + per-step micro-fee |
| tempo session | Per `observe` / `act_batch` anchored step |
| beatbox execution | Per `ExecuteRequest` fuel/wall-clock tier |
| High SideEffect | Escrow multiplier (§5.2.2), not just burn |

Optional v2: **streaming micropayments** (x402-style) for MCP tools — payment channel or per-call AIC debit inside account abstraction session keys.

**Done when:** genesis + docs describe unified AIC metering; AMM pair unchanged (SWR/AIC); SDK builder supports `open_run` + `pay_tool` helpers.

### 5.5 Cross-repo bridges (integration layer)

Protocol-only integrations — each sibling adds a thin settlement module:

| Sibling | Bridge crate / module | Hooks |
| --- | --- | --- |
| **beater.js** | `beater-settle` or runtime feature flag | Before agent run: `open_run`; after step: optional `commit_step`; on complete: `settle_run`; wallet via AA |
| **tempo** | `tempo-settle` | Session start escrow; per `act_batch` receipt; handshake fast-path API calls metered separately |
| **beatbox** | `beatbox-settle` | Pre/post `ExecuteRequest` receipt; link `ExecutionResult.receipt_hash` to step |
| **beater** | `beater-onchain` (optional) | Eval attestation publisher; trace export includes `run_id` + on-chain escrow id |
| **beaterOS** | future | OS policy receipts anchor to same `AgentRunId` |

Environment variables (v1 convention):

```text
AETHER_RPC_URL          — JSON-RPC endpoint
AETHER_CHAIN_ID         — numeric chain id
AETHER_AGENT_ADDRESS    — AA wallet address
AETHER_SETTLE_MODE      — off | observe | enforce
```

**Done when:** `beater.js` hello agent completes with `AETHER_SETTLE_MODE=enforce` on local devnet; tempo smoke test anchors one browse step; beatbox fib example posts receipt.

### 5.6 Machine-web payments (beater-connect client)

tempo already probes `.well-known/beater.json` and OpenAPI (client side of beater-connect). Aether adds **settlement**:

1. Resource/action advertises `payment: { token: AIC, amount }` in connect manifest (schema extension in beater-connect, not Aether alone).
2. tempo or beater.js client includes payment proof in request (signed AIC debit or escrow reference).
3. Server verifies via JSON-RPC read or light client proof before executing Write+ actions.

**Done when:** beater.js route with priced action accepts AIC-backed call; tempo handshake skips render path with paid API lane.

### 5.7 Identity and wallets

- Map beater-agent / MCP bearer identity → **AA smart account** with session keys (time-bounded, SideEffect-capped).
- Paymasters sponsor gas for new users; AIC covers action escrow not necessarily SWR gas (policy choice).
- Human confirm for Send/Purchase/Delete via multisig guardian key (wallet app or beater dashboard).

**Done when:** session key cannot Purchase above cap; guardian signature required and enforced on-chain.

### 5.8 Indexer and observability

Extend `aether-indexer` + firehose:

- Index `AgentRunOpened`, `StepCommitted`, `RunSettled`, `DisputeOpened` events.
- Correlate with beater trace id via shared `run_id` label.
- Prometheus metrics: escrow locked AIC, dispute rate, settlement latency.

**Done when:** Grafana dashboard panel shows open agent escrows; explorer page for run id.

---

## 6. Dependency graph

```text
                    ┌─────────────────────────────────────────┐
                    │  L0: aether-agent-schema (freeze first) │
                    └────────────────────┬────────────────────┘
                                         │
         ┌───────────────────────────────┼───────────────────────────────┐
         │                               │                               │
         v                               v                               v
  agent-run-escrow              side-effect-gate                 reputation-bridge
         │                               │                               │
         └───────────────────────────────┼───────────────────────────────┘
                                         │
                    ┌────────────────────v────────────────────┐
                    │  L1: AIC metering + AA session keys      │
                    └────────────────────┬────────────────────┘
                                         │
         ┌───────────────┬───────────────┼───────────────┬───────────────┐
         v               v               v               v               v
   beater.js        tempo           beatbox          beater       beater-connect
   bridge           bridge          bridge           attestation   payment schema
         │               │               │               │               │
         └───────────────┴───────────────┴───────────────┴───────────────┘
                                         │
                    ┌────────────────────v────────────────────┐
                    │  L2: machine-web paid actions (tempo + JS) │
                    └────────────────────┬────────────────────┘
                                         │
                    ┌────────────────────v────────────────────┐
                    │  L3: beaterOS receipt anchoring (future)   │
                    └───────────────────────────────────────────┘
```

### Parallel vs sequential

| Can parallelize | Must be sequential |
| --- | --- |
| side-effect-gate + reputation-bridge after schema | schema before any program |
| beater.js / tempo / beatbox bridges after escrow API stable | agent-run-escrow before bridges |
| indexer/explorer UI | hybrid verification doc before challenge tests |
| beater-connect payment schema (with beater.js team) | AIC metering before enforce mode |

**Load-bearing spine:** `aether-agent-schema` → `agent-run-escrow` → `beater.js` bridge → devnet enforce-mode e2e.

---

## 7. Three deployment modes (product choice)

Not mutually exclusive — pick per environment:

| Mode | Description | Ecosystem fit |
| --- | --- | --- |
| **A. L1 only** | Tradable SWR/AIC + inference marketplace | Minimal; agents pay for LLM via AIC only |
| **B. Settlement layer** | Mode A + agent-run-escrow + bridges | **Recommended target** — full agent-native economics |
| **C. Full anchor** | Mode B + every step committed on-chain | High cost; defer unless demand exists |

Default recommendation: **Mode B** with optional per-step anchors for SideEffect ≥ Write.

---

## 8. Definition of Done

### 8.1 Per-crate / program bars

| Component | Acceptance bar |
| --- | --- |
| `aether-agent-schema` | JSON Schema published; round-trip tests with beater.js types; semver policy |
| `agent-run-escrow` | State machine matches beater-agent statuses; property tests on escrow invariants |
| `side-effect-gate` | All six SideEffect levels; AA integration tests |
| `reputation-bridge` | Signed eval attestation verify; reject replay/expired |
| Hybrid verification | Matrix documented; ≥3 step kinds integration-tested |
| SDK (`aether-sdk`) | `open_run`, `commit_step`, `settle_run` builders in Rust + TS + Python |
| Indexer | All new events indexed; run_id search in explorer |

### 8.2 Milestone gates (ecosystem compatibility)

| Gate | Evidence required |
| --- | --- |
| **G0 — Schema frozen** | Cross-repo CI job passes receipt serialization |
| **G1 — Escrow solo** | Local devnet: open → settle inference job (existing) + agent run (new) |
| **G2 — beater.js enforce** | Hello agent run with kill-9 → frozen escrow → manual settle path |
| **G3 — beatbox receipt** | fib.wasm execution produces on-chain step receipt |
| **G4 — tempo step** | One `act_batch` anchored; dispute test with cassette evidence |
| **G5 — beater eval → rep** | RSI pass publishes attestation; on-chain score updates |
| **G6 — paid connect action** | Priced beater-connect action succeeds with AIC proof |
| **G7 — mainnet-ready settlement** | External audit scope includes agent-run-escrow + challenge economics |

### 8.3 Non-goals for compatibility v1

- Full on-chain agent replay or WASM agent loop.
- Replacing beater eval gates with on-chain voting.
- CEX listing or token launch ops (documented separately from this engineering plan).
- ZK proofs of arbitrary tool execution.
- Merging aether and beater repositories.

---

## 9. Risks

| Risk | Mitigation |
| --- | --- |
| On-chain cost too high for browse loops | Optimistic receipts; anchor only Write+ or batch boundaries |
| VCR scope creep | Strict step-kind → verification tier table (§5.3) |
| Bridge security | Read-only RPC + signed receipts; no private keys in tempo/beatbox hot paths |
| Token regulatory surface | AIC as utility credit; legal review outside this doc |
| Schema drift | Single `aether-agent-schema` crate; conformance CI across repos |
| `needs_review` deadlock | Timeout refund policy + human multisig path documented |

---

## 10. Coordination contract

When multiple agents or teams work in parallel:

1. Freeze **§5.1 schema** before program work diverges.
2. Land **agent-run-escrow** before sibling bridge PRs.
3. Each bridge PR includes `AETHER_SETTLE_MODE=off` default so OSS users are unaffected.
4. Update this file when gate evidence lands (link devnet tx hashes or CI job names).
5. Do not weaken SideEffect or idempotency rules to make settlement easier — match beater-connect semantics.

---

## 11. Related documents

| Document | Purpose |
| --- | --- |
| [README.md](./README.md) | Project summary and quick start |
| [docs/architecture.md](./docs/architecture.md) | Current L1 component design |
| [IMPLEMENTATION_ROADMAP.md](./IMPLEMENTATION_ROADMAP.md) | L1 delivery and ops maturity |
| [config/genesis.toml](./config/genesis.toml) | Chain economics parameters |
| [../tempo/final.md](../tempo/final.md) | Browser layer; tempo-settle consumer |
| [../beater.js/final.md](../beater.js/final.md) | Agent runtime; journal source of truth |
| [../beater.js/crates/beater-connect/ARCHITECTURE.md](../beater.js/crates/beater-connect/ARCHITECTURE.md) | SideEffect and action policy |
| [../beatbox/ARCHITECTURE.md](../beatbox/ARCHITECTURE.md) | Sandbox execution receipts |
