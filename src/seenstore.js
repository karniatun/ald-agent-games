// Persistent seen-set of accepted Gatekeeper proof references.
//
// The PROOF_REUSED trap (~11% of tasks) can only be detected if the agent
// remembers every proof_tx it has previously ACCEPTED, across restarts.
// Stored as a JSON file under DATA_DIR; writes are synchronous and atomic
// (tmp file + rename) because a lost write could mean approving a reused
// proof in a scored round.

import fs from 'node:fs';
import path from 'node:path';

export class SeenStore {
  constructor(filePath) {
    this.filePath = filePath;
    this.set = new Set();
    try {
      const raw = fs.readFileSync(filePath, 'utf8');
      const arr = JSON.parse(raw);
      if (Array.isArray(arr)) for (const v of arr) this.set.add(String(v).toLowerCase());
    } catch { /* fresh store */ }
  }

  has(proofTx) {
    return this.set.has(String(proofTx).toLowerCase());
  }

  add(proofTx) {
    const key = String(proofTx).toLowerCase();
    if (this.set.has(key)) return;
    this.set.add(key);
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    const tmp = this.filePath + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify([...this.set]));
    fs.renameSync(tmp, this.filePath);
  }

  get size() {
    return this.set.size;
  }
}
