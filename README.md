# ald.ai — Agent Games (zkVerify) Competition Agent

An autonomous competition agent for the **Agent Games** tournament powered by
**zkVerify** (agentgames.zkverify.io). Every result in this tournament is
verified on-chain with zero-knowledge proofs — this agent is built so that
every decision it makes can be checked by anyone:

- Every platform task arrives as an **HMAC-signed** request; the agent
  verifies the signature against the raw body before parsing anything.
- Every response is **signed** with `x-agent-games-signature` over the raw
  response body.
- Task IDs are treated as **idempotency keys** — a retried delivery returns
  the byte-identical stored response.
- The agent **fails closed**: bad signatures, malformed payloads, and any
  uncertainty produce rejections, never approvals.

## Events

### Proof Gatekeeper
The agent judges proof-backed payment conditions. It approves only a
genuinely valid condition and rejects each documented trap with its exact
reason code:

| Verdict | Meaning |
|---|---|
| `VALID_CONDITION` (APPROVE) | Proof on-chain, VK matches the registered condition, balance ≥ minimum, recipient matches, not expired, amount within cap, proof never accepted before |
| `VK_SUBSTITUTION` | The proof verifies, but under a different verification key than the registered condition |
| `PROOF_REUSED` | The same proof reference was already accepted once (persistent local seen-set) |
| `THRESHOLD_MISMATCH` | Proven public balance is below the required minimum |
| `EXPIRED_CONDITION` | The condition's block-height window has passed |
| `RECIPIENT_MISMATCH` | The proof's recipient is not the condition's recipient |
| `AMOUNT_OVERFLOW` | Requested amount exceeds the single-transfer cap |

Decisions are deterministic, made from the task payload plus the local
seen-set, and returned well inside the 60-second hard deadline. Own decision
proofs are produced with the official Groth16/BN128 `gatekeeper` circuit
(Circom 2.x, snarkjs) and submitted to zkVerify mainnet through **Kurier**
(register VK once → submit proof → poll until `Finalized`).

### Steal the VFY
A 20-turn head-to-head strategy game (100 VFY each, Swiss format). The agent
answers each signed turn envelope with an action (`HOLD` / `FORTIFY` /
`EXTRACT n`) plus a policy proof generated with the official `vfy-policy`
circuit, proving the move is allowed by the strategy committed before the
tournament. `policyProof.publicInputsHash` is computed exactly as the
platform recomputes it — keccak256 over the eight 32-byte big-endian padded
fields (commitment, matchId, turn, both balances, action code, amount,
circuit version) — so the proof always covers the true game state.

## Layout

```
src/server.js       HTTP endpoint: signature gate, routing, idempotency
src/hmac.js         x-agent-games-signature sign/verify (HMAC-SHA256)
src/gatekeeper.js   Gatekeeper decision logic (documented trap rules)
src/steal.js        Steal turn responses + publicInputsHash (viem-compatible)
src/strategy.js     Steal strategy (participant's own committed strategy)
src/kurier.js       Kurier REST client (register-vk / submit-proof / job-status)
src/keccak.js       dependency-free Keccak-256 (verified vs test vectors)
src/seenstore.js    persistent set of accepted proof references
src/responsestore.js persistent idempotent response store
circuits/           official artifacts (npm run circuits to download)
test/simulate.mjs   full local simulation suite (npm test)
test/public.mjs     test battery against a deployed public URL
```

## Run

```bash
npm install
npm run circuits        # download gatekeeper + vfy-policy wasm/zkey
cp .env.example .env    # set AGENT_GAMES_HMAC_SECRET from the dashboard
chmod 600 .env
npm start               # listens on 127.0.0.1:8787, register <public-https>/agent
npm test                # 31-check simulation suite
```

Circuit verification keys (zkVerify mainnet, from `/api/circuit-info`):

- gatekeeper: `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`
- vfyPolicy: `0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047`
