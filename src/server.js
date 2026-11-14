// Agent Games endpoint server (zero-dependency Node http).
//
// One registered URL, full handler path (default /agent), receives every
// signed delivery from the platform:
//
//   POST /agent   body.type === "agent-games.preflight.v1"      -> { ok: true, protocolVersion: "v1" }
//   POST /agent   body.type === "agent-games.proof-gatekeeper.v1" -> Gatekeeper decision
//   POST /agent   body.eventId === "steal-the-vfy" (turn envelope) -> Steal turn response
//   GET  /agent   health (also GET /health and GET /)
//
// Contract enforced here (docs: /build §02/§04/§05, /rules §1.2–§1.3):
//  - Verify `x-agent-games-signature` against the RAW body BEFORE parsing.
//  - Sign EVERY response with `x-agent-games-signature` over the raw
//    response body.
//  - Task IDs are idempotency keys: a retried delivery gets the stored,
//    byte-identical response (see responsestore.js).
//  - Fail closed: bad signature, malformed JSON, unknown payloads, and
//    internal errors never produce an approval.
//  - Gatekeeper decisions are made well inside the 60-second hard deadline;
//    no network call is on the default decision path.

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { SIGNATURE_HEADER, signBody, verifyBody } from './hmac.js';
import { SeenStore } from './seenstore.js';
import { ResponseStore } from './responsestore.js';
import { decideGatekeeper, gatekeeperResponseBody } from './gatekeeper.js';
import { buildStealTurnResponse } from './steal.js';
import { KurierClient } from './kurier.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function loadDotEnv() {
  const envPath = path.join(__dirname, '..', '.env');
  try {
    for (const line of fs.readFileSync(envPath, 'utf8').split('\n')) {
      const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
      if (m && process.env[m[1]] === undefined) process.env[m[1]] = m[2];
    }
  } catch { /* env may come from systemd EnvironmentFile instead */ }
}
loadDotEnv();

const PORT = Number(process.env.PORT || 8787);
const HOST = process.env.HOST || '127.0.0.1';
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || '';
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, '..', 'data');
const AGENT_NAME = process.env.AGENT_NAME || 'ald-ai-agent';

if (!SECRET) {
  console.error('[agent-games] FATAL: AGENT_GAMES_HMAC_SECRET is not set — refusing to start (fail closed).');
  process.exit(1);
}

const seenStore = new SeenStore(path.join(DATA_DIR, 'seen-proofs.json'));
const responseStore = new ResponseStore(path.join(DATA_DIR, 'responses.json'));
const kurier = new KurierClient({ apiKey: process.env.KURIER_API_KEY || '' });

// Optional independent on-chain confirmation for Gatekeeper tasks.
// Default OFF: the documented trap set is fully determined by the payload
// fields + local seen-set. Turning this on requires pinning down how a
// task's proof_tx is looked up on zkVerify mainnet (see PROTOKOL.md §4.3);
// until then the hook stays inert rather than guessing an API.
const onchainCheck = process.env.GATEKEEPER_ONCHAIN_CHECK === 'on'
  ? async () => ({ ok: false, kind: 'unverified' }) // fail closed if misconfigured
  : null;

function log(event, fields = {}) {
  console.log(JSON.stringify({ ts: new Date().toISOString(), event, ...fields }));
}

function sendSigned(res, status, rawBody) {
  res.writeHead(status, {
    'content-type': 'application/json',
    [SIGNATURE_HEADER]: signBody(SECRET, rawBody),
  });
  res.end(rawBody);
}

function sendJson(res, status, obj) {
  sendSigned(res, status, JSON.stringify(obj));
}

async function handleTask(rawBody) {
  let body;
  try {
    body = JSON.parse(rawBody.toString('utf8'));
  } catch {
    return { status: 400, obj: { error: 'invalid_json' } };
  }

  // --- Preflight (build guide §02) ---
  if (body?.type === 'agent-games.preflight.v1') {
    log('preflight', { agent_id: body.agent_id ?? null });
    return { status: 200, obj: { ok: true, protocolVersion: 'v1' } };
  }

  // --- Proof Gatekeeper ---
  if (body?.type === 'agent-games.proof-gatekeeper.v1') {
    const taskId = String(body.task_id ?? '');
    if (!taskId) return { status: 400, obj: { error: 'missing_task_id' } };

    const cached = responseStore.get(`gk:${taskId}`);
    if (cached) {
      log('gatekeeper_replay', { task_id: taskId });
      return { status: 200, raw: cached };
    }

    const decision = await decideGatekeeper(body, { seenStore, onchainCheck });
    log('gatekeeper_decision', {
      task_id: taskId,
      mode: body.mode ?? null,
      decision: decision.decision,
      reason_code: decision.reason_code,
      detail: decision.detail,
    });

    const raw = gatekeeperResponseBody(decision);
    responseStore.set(`gk:${taskId}`, raw);
    // Record the proof reference only AFTER a competition-mode approval —
    // this is the seen-set the PROOF_REUSED trap is judged against.
    if (decision.decision === 'APPROVE' && (body.mode ?? 'competition') === 'competition') {
      seenStore.add(decision.proof_tx);
    }
    return { status: 200, raw };
  }

  // --- Steal the VFY turn envelope ---
  if (body?.eventId === 'steal-the-vfy' && body?.matchId && Number.isInteger(body?.turn)) {
    const key = `steal:${body.matchId}:${body.turn}`;
    const cached = responseStore.get(key);
    if (cached) {
      log('steal_replay', { matchId: body.matchId, turn: body.turn });
      return { status: 200, raw: cached };
    }
    const responseObj = await buildStealTurnResponse(body, {});
    log('steal_turn', {
      matchId: body.matchId,
      turn: body.turn,
      action: responseObj.action.type,
      publicInputsHash: responseObj.policyProof.publicInputsHash,
    });
    const raw = JSON.stringify(responseObj);
    responseStore.set(key, raw);
    return { status: 200, raw };
  }

  return { status: 400, obj: { error: 'unknown_payload' } };
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host ?? 'localhost'}`);

    if (req.method === 'GET' && (url.pathname === '/health' || url.pathname === '/' || url.pathname === '/agent')) {
      return sendJson(res, 200, {
        ok: true,
        service: 'agent-games-endpoint',
        agent: AGENT_NAME,
        protocolVersion: 'v1',
        events: ['proof-gatekeeper', 'steal-the-vfy'],
        kurierConfigured: kurier.configured,
        seenProofs: seenStore.size,
      });
    }

    if (req.method === 'POST' && url.pathname === '/agent') {
      const chunks = [];
      let size = 0;
      for await (const chunk of req) {
        size += chunk.length;
        if (size > 1_000_000) {
          return sendJson(res, 413, { error: 'body_too_large' });
        }
        chunks.push(chunk);
      }
      const rawBody = Buffer.concat(chunks);

      // Verify BEFORE parsing or processing (build guide §02).
      if (!verifyBody(SECRET, rawBody, req.headers[SIGNATURE_HEADER])) {
        log('signature_rejected', { path: url.pathname });
        return sendJson(res, 401, { error: 'invalid_signature' });
      }

      const { status, obj, raw } = await handleTask(rawBody);
      if (raw !== undefined) return sendSigned(res, status, raw);
      return sendJson(res, status, obj);
    }

    return sendJson(res, 404, { error: 'not_found' });
  } catch (err) {
    log('internal_error', { message: String(err?.message ?? err) });
    return sendJson(res, 500, { error: 'internal_error' });
  }
});

server.listen(PORT, HOST, () => {
  log('listening', { host: HOST, port: PORT, agent: AGENT_NAME });
});
