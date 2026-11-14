// End-to-end simulation tests against a locally spawned server instance.
//
// Covers: keccak-256 vectors, health, HMAC accept/reject, preflight,
// every documented Gatekeeper trap, idempotent replay, proof-reuse
// detection, and the Steal the VFY response shape + publicInputsHash.
//
// Run: npm test   (spawns the server on a scratch port with a test secret;
// state is written to a temp DATA_DIR and removed afterwards)

import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { keccak256Hex, pad32 } from '../src/keccak.js';
import { computePublicInputsHash } from '../src/steal.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, '..');
const PORT = 18787;
const BASE = `http://127.0.0.1:${PORT}`;
const SECRET = 'test-secret-for-simulation-only';
const DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-games-test-'));

let failures = 0;
function check(name, cond, extra = '') {
  if (cond) console.log(`  ok  ${name}`);
  else { console.error(`FAIL  ${name} ${extra}`); failures++; }
}

// --- keccak vectors ---
check('keccak256("")', keccak256Hex('') === '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470');
check('keccak256("abc")', keccak256Hex('abc') === '0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45');
check('pad32(1)', pad32(1n).toString('hex') === '0'.repeat(63) + '1');

// --- publicInputsHash composition (self-consistency + shape) ---
const sampleEnvelope = {
  matchId: '9f4e1b2a-3c4d-4e5f-8a9b-1c2d3e4f5a6b',
  turn: 3,
  state: { selfBalance: '95', opponentBalance: '105' },
  strategyCommitment: { hash: '0x7d3a0000000000000000000000000000000000000000000000000000000000f291' },
};
const h1 = computePublicInputsHash(sampleEnvelope, 'EXTRACT', 5);
check('publicInputsHash is 32-byte hex', /^0x[0-9a-f]{64}$/.test(h1));
check('publicInputsHash differs by action', h1 !== computePublicInputsHash(sampleEnvelope, 'HOLD', 0));
check('publicInputsHash differs by turn', h1 !== computePublicInputsHash({ ...sampleEnvelope, turn: 4 }, 'EXTRACT', 5));

// --- spawn server ---
const server = spawn('node', [path.join(ROOT, 'src/server.js')], {
  env: {
    ...process.env,
    PORT: String(PORT),
    HOST: '127.0.0.1',
    AGENT_GAMES_HMAC_SECRET: SECRET,
    DATA_DIR,
  },
  stdio: ['ignore', 'pipe', 'pipe'],
});
server.stderr.on('data', (d) => process.stderr.write(`[server] ${d}`));

async function waitReady() {
  for (let i = 0; i < 50; i++) {
    try {
      const r = await fetch(`${BASE}/health`);
      if (r.ok) return;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error('server did not start');
}

function sign(raw) {
  return crypto.createHmac('sha256', SECRET).update(raw).digest('hex');
}

async function postSigned(obj, { badSignature = false } = {}) {
  const raw = JSON.stringify(obj);
  const res = await fetch(`${BASE}/agent`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-agent-games-signature': badSignature ? 'deadbeef'.repeat(8) : sign(raw),
    },
    body: raw,
  });
  const text = await res.text();
  // every response must carry a valid signature over its raw body
  const sig = res.headers.get('x-agent-games-signature');
  check(`response signed (${obj.type ?? obj.eventId ?? '?'})`, sig === sign(text), `status=${res.status}`);
  return { status: res.status, body: JSON.parse(text), rawText: text };
}

const VK = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const ADDR = '0xDe42000000000000000000000000000000009f01'.toLowerCase();
let txCounter = 0;
function gatekeeperTask(overrides = {}, inputOverrides = {}) {
  txCounter += 1;
  return {
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: `gk_test_${txCounter}`,
    mode: 'competition',
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60_000).toISOString(),
    input: {
      registered_vk: VK,
      proof_vk: VK,
      minimum: '1000',
      public_balance: '1460',
      expiry_block: 8430000,
      current_block: 8420000,
      recipient: ADDR,
      condition_recipient: ADDR,
      amount: '500',
      max_transfer: '1000',
      proof_tx: `0xtx${txCounter}`,
      ...inputOverrides,
    },
    ...overrides,
  };
}

try {
  await waitReady();

  const health = await (await fetch(`${BASE}/health`)).json();
  check('health ok', health.ok === true && health.protocolVersion === 'v1');

  const pre = await postSigned({ type: 'agent-games.preflight.v1', agent_id: 'agt_test', issued_at: new Date().toISOString(), nonce: 'abc123' });
  check('preflight ok', pre.status === 200 && pre.body.ok === true && pre.body.protocolVersion === 'v1');

  const bad = await postSigned({ type: 'agent-games.preflight.v1', agent_id: 'agt_test' }, { badSignature: true });
  check('bad signature rejected 401', bad.status === 401);

  const valid = await postSigned(gatekeeperTask());
  check('valid condition APPROVE', valid.body.decision === 'APPROVE' && valid.body.reason_code === 'VALID_CONDITION', JSON.stringify(valid.body));

  const vkTrap = await postSigned(gatekeeperTask({}, { proof_vk: '0x13aa00000000000000000000000000000000000000000000000000000000b8ff' }));
  check('VK_SUBSTITUTION', vkTrap.body.decision === 'REJECT' && vkTrap.body.reason_code === 'VK_SUBSTITUTION', JSON.stringify(vkTrap.body));

  const thrTrap = await postSigned(gatekeeperTask({}, { public_balance: '900' }));
  check('THRESHOLD_MISMATCH', thrTrap.body.reason_code === 'THRESHOLD_MISMATCH', JSON.stringify(thrTrap.body));

  const expTrap = await postSigned(gatekeeperTask({}, { current_block: 8430001 }));
  check('EXPIRED_CONDITION', expTrap.body.reason_code === 'EXPIRED_CONDITION', JSON.stringify(expTrap.body));

  const recTrap = await postSigned(gatekeeperTask({}, { recipient: '0x1111111111111111111111111111111111111111' }));
  check('RECIPIENT_MISMATCH', recTrap.body.reason_code === 'RECIPIENT_MISMATCH', JSON.stringify(recTrap.body));

  const amtTrap = await postSigned(gatekeeperTask({}, { amount: '1500' }));
  check('AMOUNT_OVERFLOW', amtTrap.body.reason_code === 'AMOUNT_OVERFLOW', JSON.stringify(amtTrap.body));

  // proof reuse: same proof_tx as the approved task, brand-new task_id
  const reused = await postSigned(gatekeeperTask({}, { proof_tx: valid.body.proof_tx }));
  check('PROOF_REUSED', reused.body.decision === 'REJECT' && reused.body.reason_code === 'PROOF_REUSED', JSON.stringify(reused.body));

  // idempotent replay: resend the ORIGINAL valid task -> byte-identical body
  const replayTask = gatekeeperTask();
  replayTask.task_id = valid.body.proof_tx ? 'gk_test_1' : 'gk_test_1';
  replayTask.input.proof_tx = valid.body.proof_tx;
  const replay = await postSigned(replayTask);
  check('replay byte-identical', replay.rawText === valid.rawText, `${replay.rawText} vs ${valid.rawText}`);

  // steal turn (placeholder strategy = HOLD)
  const steal = await postSigned({
    protocolVersion: 'v1',
    eventId: 'steal-the-vfy',
    mode: 'competition',
    matchId: sampleEnvelope.matchId,
    turn: 3,
    issuedAt: new Date().toISOString(),
    deadlineAt: new Date(Date.now() + 300_000).toISOString(),
    state: { selfBalance: '95', opponentBalance: '105', selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null },
    strategyCommitment: { hash: sampleEnvelope.strategyCommitment.hash },
    resolverVersion: 'v1',
    nonce: '3c2f1a',
  });
  check('steal echo matchId/turn', steal.body.matchId === sampleEnvelope.matchId && steal.body.turn === 3);
  check('steal HOLD omits amount', steal.body.action.type === 'HOLD' && !('amount' in steal.body.action), JSON.stringify(steal.body.action));
  check('steal hash matches module', steal.body.policyProof.publicInputsHash === computePublicInputsHash(sampleEnvelope, 'HOLD', 0));
  check('steal idempotencyKey per turn', steal.body.idempotencyKey === `turn-${sampleEnvelope.matchId}-3`);
} finally {
  server.kill('SIGTERM');
  fs.rmSync(DATA_DIR, { recursive: true, force: true });
}

if (failures > 0) {
  console.error(`\n${failures} test(s) FAILED`);
  process.exit(1);
}
console.log('\nAll simulation tests passed.');
