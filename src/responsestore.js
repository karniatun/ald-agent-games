// Persistent idempotency store for already-answered tasks/turns.
//
// Rules §1.2: task IDs are idempotency keys — the platform may retry a
// delivery after a network failure and expects the SAME response. This
// matters beyond politeness: without it, a retried Gatekeeper task whose
// first answer was APPROVE (and whose proof_tx entered the seen-set) would
// be re-judged as PROOF_REUSED, turning a correct +12 into a wrong -3.
// Responses are stored verbatim (raw body string) keyed by task_id for
// Gatekeeper and by matchId:turn for Steal the VFY.

import fs from 'node:fs';
import path from 'node:path';

export class ResponseStore {
  constructor(filePath) {
    this.filePath = filePath;
    this.map = new Map();
    try {
      const obj = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      for (const [k, v] of Object.entries(obj)) this.map.set(k, v);
    } catch { /* fresh store */ }
  }

  get(key) {
    return this.map.get(key);
  }

  set(key, rawBody) {
    if (this.map.has(key)) return;
    this.map.set(key, rawBody);
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    const tmp = this.filePath + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(Object.fromEntries(this.map)));
    fs.renameSync(tmp, this.filePath);
  }
}
