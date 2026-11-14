// Proof Gatekeeper decision logic.
//
// Source of truth: agentgames.zkverify.io/events/proof-gatekeeper (sample
// payload, trap encyclopedia, build checklist, score model) and /build §02/§04.
//
// A task presents a payment condition plus a ZK proof reference (proof_tx)
// that supposedly satisfies it. The agent must APPROVE only a genuinely valid
// condition and REJECT each documented trap with its exact reason_code:
//
//   VALID_CONDITION     proof on-chain, VK matches, balance >= minimum,
//                       recipient matches, not expired, amount within cap,
//                       proof not previously accepted        (~50% of tasks)
//   VK_SUBSTITUTION     proof verifies but its VK != registered condition VK
//   PROOF_REUSED        proof reference already accepted in a previous task
//   THRESHOLD_MISMATCH  public_balance < minimum
//   EXPIRED_CONDITION   current_block > expiry_block
//   RECIPIENT_MISMATCH  recipient != condition_recipient
//   AMOUNT_OVERFLOW     amount > max_transfer
//
// Fail closed: any uncertainty (malformed input, failed on-chain check)
// results in REJECT, per the build guide ("Reject on timeout or
// uncertainty"). Wrong approvals (-6) cost twice as much as wrong
// rejections (-3), so caution is also the score-optimal bias.

function lc(v) {
  return typeof v === 'string' ? v.toLowerCase() : v;
}

function toBigInt(v) {
  try {
    return BigInt(v);
  } catch {
    return null;
  }
}

function reject(reason_code, proof_tx, detail) {
  return { decision: 'REJECT', reason_code, proof_tx, detail };
}

function approve(proof_tx, detail) {
  return { decision: 'APPROVE', reason_code: 'VALID_CONDITION', proof_tx, detail };
}

// ctx: {
//   seenStore,                 // SeenStore of previously ACCEPTED proof_tx (competition mode)
//   onchainCheck?: async (input) => { ok: true } | { ok: false, kind: 'vk_mismatch' | 'unverified' }
// }
// Returns { decision, reason_code, proof_tx, detail } — `detail` is internal
// diagnostics and is stripped before the response is sent.
export async function decideGatekeeper(task, ctx) {
  const input = task?.input ?? {};
  const proofTx = input.proof_tx ?? null;
  const mode = task?.mode ?? 'competition';

  const required = [
    'registered_vk', 'proof_vk', 'minimum', 'public_balance',
    'expiry_block', 'current_block', 'recipient', 'condition_recipient',
    'amount', 'max_transfer', 'proof_tx',
  ];
  for (const field of required) {
    if (input[field] === undefined || input[field] === null || input[field] === '') {
      return reject('MALFORMED_INPUT', proofTx, `missing field: ${field}`);
    }
  }

  // 1) Verification-key substitution: the proof's VK must be the VK that was
  //    registered for this condition.
  if (lc(input.proof_vk) !== lc(input.registered_vk)) {
    return reject('VK_SUBSTITUTION', proofTx, 'proof_vk != registered_vk');
  }

  // 2) Optional independent on-chain confirmation (zkVerifyJS/Kurier hook).
  //    Disabled by default; when enabled it must confirm the proof is
  //    finalized on-chain with a matching VK before we can approve.
  if (ctx.onchainCheck) {
    const res = await ctx.onchainCheck(input);
    if (!res.ok) {
      if (res.kind === 'vk_mismatch') {
        return reject('VK_SUBSTITUTION', proofTx, 'on-chain VK mismatch');
      }
      return reject('UNVERIFIED_ONCHAIN', proofTx, `on-chain check failed: ${res.kind}`);
    }
  }

  // 3) Proof reuse: a proof reference that was already ACCEPTED once can
  //    never be accepted again. Only competition-mode history is consulted,
  //    and only competition-mode approvals are recorded (see server.js), so
  //    practice replays cannot poison the scored seen-set.
  if (mode === 'competition' && ctx.seenStore?.has(proofTx)) {
    return reject('PROOF_REUSED', proofTx, 'proof_tx already accepted in a previous task');
  }

  // 4) Expiry: the condition's block-height window must still be open.
  const expiry = toBigInt(input.expiry_block);
  const current = toBigInt(input.current_block);
  if (expiry === null || current === null) {
    return reject('MALFORMED_INPUT', proofTx, 'block heights are not integers');
  }
  if (current > expiry) {
    return reject('EXPIRED_CONDITION', proofTx, `current_block ${current} > expiry_block ${expiry}`);
  }

  // 5) Threshold: the public balance proven must meet the condition minimum.
  const balance = toBigInt(input.public_balance);
  const minimum = toBigInt(input.minimum);
  if (balance === null || minimum === null) {
    return reject('MALFORMED_INPUT', proofTx, 'balance/minimum are not integers');
  }
  if (balance < minimum) {
    return reject('THRESHOLD_MISMATCH', proofTx, `public_balance ${balance} < minimum ${minimum}`);
  }

  // 6) Recipient: the proof's recipient must be the condition's recipient.
  if (lc(input.recipient) !== lc(input.condition_recipient)) {
    return reject('RECIPIENT_MISMATCH', proofTx, 'recipient != condition_recipient');
  }

  // 7) Amount cap: the requested transfer must fit the single-transfer cap.
  const amount = toBigInt(input.amount);
  const maxTransfer = toBigInt(input.max_transfer);
  if (amount === null || maxTransfer === null) {
    return reject('MALFORMED_INPUT', proofTx, 'amount/max_transfer are not integers');
  }
  if (amount > maxTransfer) {
    return reject('AMOUNT_OVERFLOW', proofTx, `amount ${amount} > max_transfer ${maxTransfer}`);
  }

  return approve(proofTx, 'all documented checks passed');
}

// The exact response shape from the official docs. Internal diagnostics are
// deliberately NOT included.
export function gatekeeperResponseBody(decision) {
  return JSON.stringify({
    decision: decision.decision,
    reason_code: decision.reason_code,
    proof_tx: decision.proof_tx,
  });
}
