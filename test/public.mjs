// Public-URL test battery for the deployed Agent Games endpoint.
// Usage: AG_TEST_SECRET=<secret> node public-test.mjs <baseUrl>
import crypto from 'node:crypto';

const BASE = process.argv[2];
const SECRET = process.env.AG_TEST_SECRET;
if (!BASE || !SECRET) { console.error('missing BASE or AG_TEST_SECRET'); process.exit(2); }

let failures = 0;
function check(name, cond, extra = '') {
  if (cond) console.log(`  ok  ${name}`);
  else { console.error(`FAIL  ${name} ${extra}`); failures++; }
}
const sign = (raw) => crypto.createHmac('sha256', SECRET).update(raw).digest('hex');

async function postSigned(obj, opts = {}) {
  const raw = JSON.stringify(obj);
  const res = await fetch(`${BASE}/agent`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-agent-games-signature': opts.bad ? 'ab'.repeat(32) : sign(raw) },
    body: raw,
  });
  const text = await res.text();
  check(`signed response (${obj.type ?? obj.eventId})`, res.headers.get('x-agent-games-signature') === sign(text), `status=${res.status}`);
  return { status: res.status, body: JSON.parse(text) };
}

// health over public HTTPS
const healthRes = await fetch(`${BASE}/health`);
check('public GET /health 200', healthRes.status === 200, `status=${healthRes.status}`);
const health = await healthRes.json();
check('health payload', health.ok === true && health.protocolVersion === 'v1');

const pre = await postSigned({ type: 'agent-games.preflight.v1', agent_id: 'agt_publictest', issued_at: new Date().toISOString(), nonce: 'pub1' });
check('public preflight', pre.status === 200 && pre.body.ok === true, JSON.stringify(pre.body));

const bad = await postSigned({ type: 'agent-games.preflight.v1', agent_id: 'agt_publictest' }, { bad: true });
check('public bad signature 401', bad.status === 401);

const VK = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const ADDR = '0xde42000000000000000000000000000000009f01';
const gk = {
  type: 'agent-games.proof-gatekeeper.v1', task_id: 'gk_public_1', mode: 'competition',
  issued_at: new Date().toISOString(), deadline_at: new Date(Date.now() + 60000).toISOString(),
  input: { registered_vk: VK, proof_vk: VK, minimum: '1000', public_balance: '1460', expiry_block: 8430000, current_block: 8420000, recipient: ADDR, condition_recipient: ADDR, amount: '500', max_transfer: '1000', proof_tx: '0xpubtx1' },
};
const t0 = Date.now();
const gkRes = await postSigned(gk);
check('public gatekeeper APPROVE', gkRes.body.decision === 'APPROVE' && gkRes.body.reason_code === 'VALID_CONDITION', JSON.stringify(gkRes.body));
console.log(`  gatekeeper round-trip: ${Date.now() - t0}ms`);

const trap = structuredClone(gk);
trap.task_id = 'gk_public_2';
trap.input.proof_vk = '0x13aa00000000000000000000000000000000000000000000000000000000b8ff';
trap.input.proof_tx = '0xpubtx2';
const trapRes = await postSigned(trap);
check('public gatekeeper VK_SUBSTITUTION', trapRes.body.decision === 'REJECT' && trapRes.body.reason_code === 'VK_SUBSTITUTION', JSON.stringify(trapRes.body));

const steal = await postSigned({
  protocolVersion: 'v1', eventId: 'steal-the-vfy', mode: 'competition',
  matchId: '9f4e1b2a-3c4d-4e5f-8a9b-1c2d3e4f5a6b', turn: 3,
  issuedAt: new Date().toISOString(), deadlineAt: new Date(Date.now() + 300000).toISOString(),
  state: { selfBalance: '95', opponentBalance: '105', selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null },
  strategyCommitment: { hash: '0x7d3a0000000000000000000000000000000000000000000000000000000000f291' },
  resolverVersion: 'v1', nonce: '3c2f1a',
});
check('public steal shape', steal.body.matchId === '9f4e1b2a-3c4d-4e5f-8a9b-1c2d3e4f5a6b' && steal.body.turn === 3 && steal.body.action.type === 'HOLD' && !('amount' in steal.body.action) && /^0x[0-9a-f]{64}$/.test(steal.body.policyProof.publicInputsHash), JSON.stringify(steal.body));

if (failures) { console.error(`\n${failures} FAILURES`); process.exit(1); }
console.log('\nAll public tests passed.');
