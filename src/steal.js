// Steal the VFY turn handler plumbing.
//
// Source of truth: agentgames.zkverify.io/build §06 and
// /events/steal-the-vfy. The STRATEGY itself lives in strategy.js and is
// the participant's own decision (see the warning there). This module only
// guarantees the wire contract:
//
//  - Echo matchId and turn EXACTLY as received (a stale echo is a
//    documented common mistake).
//  - action.amount is present ONLY for EXTRACT; for HOLD/FORTIFY the field
//    must be omitted entirely (the schema rejects it even when 0).
//  - policyProof.publicInputsHash computed EXACTLY as the platform does:
//    keccak256 over eight 32-byte big-endian padded fields:
//      [ commitment, matchId (UUID as integer), turn, selfBalance,
//        opponentBalance, actionCode (HOLD=0, FORTIFY=1, EXTRACT=2),
//        amount (0 for HOLD/FORTIFY), circuitVersion ("v1" -> 1) ]
//    The platform recomputes this hash from the game state it knows and
//    rejects any proof whose hash diverges.
//  - idempotencyKey is unique per (matchId, turn) and stable across retries
//    of the same turn, so a platform retry never double-plays a turn.

import { keccak256, pad32 } from './keccak.js';
import { decideTurn } from './strategy.js';

export const ACTION_CODES = { HOLD: 0n, FORTIFY: 1n, EXTRACT: 2n };
export const CIRCUIT_VERSION = 'v1';

export function computePublicInputsHash(envelope, actionType, amount) {
  const state = envelope.state ?? {};
  const commitment = envelope.strategyCommitment?.hash ?? '0x0';
  const matchIdInt = BigInt('0x' + String(envelope.matchId ?? '').replace(/-/g, ''));
  const packed = Buffer.concat([
    pad32(BigInt(commitment)),
    pad32(matchIdInt),
    pad32(BigInt(envelope.turn ?? 0)),
    pad32(BigInt(state.selfBalance ?? 0)),
    pad32(BigInt(state.opponentBalance ?? 0)),
    pad32(ACTION_CODES[actionType]),
    pad32(BigInt(amount ?? 0)),
    pad32(1n), // circuitVersion "v1" -> 1
  ]);
  return '0x' + keccak256(packed).toString('hex');
}

// deps.provePolicy?: async ({ envelope, action, publicInputsHash }) =>
//   { proof, publicSignals, proofReference } | null
// Proving needs the vfy-policy circuit (circuits/vfy-policy.wasm +
// vfy-policy_final.zkey) and the committed strategy's witness layout, which
// is only final once the strategy is committed at registration. Until then
// the handler answers with circuitVersion + publicInputsHash and no proof
// fields; per the docs a response with missing required proof fields is
// treated as HOLD with no proof — acceptable in pre-registration testing,
// NOT acceptable for scored play.
export async function buildStealTurnResponse(envelope, deps = {}) {
  const action = decideTurn(envelope.state, envelope.turn, envelope);
  const amount = action.type === 'EXTRACT' ? Number(action.amount ?? 0) : 0;
  const publicInputsHash = computePublicInputsHash(envelope, action.type, amount);

  const actionBody = { type: action.type };
  if (action.type === 'EXTRACT') actionBody.amount = amount;

  const policyProof = { circuitVersion: CIRCUIT_VERSION, publicInputsHash };
  if (deps.provePolicy) {
    const proven = await deps.provePolicy({ envelope, action, publicInputsHash });
    if (proven) {
      policyProof.proof = proven.proof;
      policyProof.public_signals = proven.publicSignals;
      if (proven.proofReference) policyProof.proofReference = proven.proofReference;
    }
  }

  return {
    matchId: envelope.matchId,
    turn: envelope.turn,
    action: actionBody,
    policyProof,
    agentTimestamp: new Date().toISOString(),
    idempotencyKey: `turn-${envelope.matchId}-${envelope.turn}`,
  };
}
