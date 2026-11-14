// Kurier REST client (zkVerify proof submission service).
//
// Source: docs.zkverify.io/overview/getting-started/kurier and
// agentgames.zkverify.io/build §03 (Kurier = recommended path).
//
//   Base URL (mainnet): https://api.kurier.xyz/api/v1
//   POST /register-vk/{API_KEY}    register a verification key once -> vkHash
//   POST /submit-proof/{API_KEY}   submit a proof for verification -> { jobId, optimisticVerify }
//   GET  /job-status/{API_KEY}/{jobId}  poll until status === "Finalized"
//
// Job statuses: Queued, Valid, Submitted, IncludedInBlock, Finalized, Failed.
// Only "Finalized" is safe to treat as confirmed on-chain.

const DEFAULT_BASE = 'https://api.kurier.xyz/api/v1';

export class KurierClient {
  constructor({ apiKey, baseUrl = DEFAULT_BASE, fetchImpl = fetch } = {}) {
    this.apiKey = apiKey || '';
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.fetch = fetchImpl;
  }

  get configured() {
    return Boolean(this.apiKey);
  }

  async #post(pathSuffix, body) {
    if (!this.configured) throw new Error('KURIER_API_KEY is not configured');
    const res = await this.fetch(`${this.baseUrl}${pathSuffix}/${this.apiKey}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new Error(`Kurier POST ${pathSuffix} failed: HTTP ${res.status} ${JSON.stringify(data)}`);
    }
    return data;
  }

  async #get(pathSuffix) {
    if (!this.configured) throw new Error('KURIER_API_KEY is not configured');
    const res = await this.fetch(`${this.baseUrl}${pathSuffix}/${this.apiKey}`);
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new Error(`Kurier GET ${pathSuffix} failed: HTTP ${res.status} ${JSON.stringify(data)}`);
    }
    return data;
  }

  // Register a verification key (snarkjs groth16 vk JSON) once; returns the
  // registration payload containing vkHash.
  async registerVk(vkJson) {
    return this.#post('/register-vk', {
      proofType: 'groth16',
      proofOptions: { library: 'snarkjs', curve: 'bn128' },
      vk: vkJson,
    });
  }

  // Submit one of OUR OWN Groth16 proofs (gatekeeper decision proof or
  // vfy-policy proof) against an already-registered vk hash.
  // Returns { jobId, optimisticVerify }.
  async submitProof({ vkHash, proof, publicSignals }) {
    return this.#post('/submit-proof', {
      proofType: 'groth16',
      vkRegistered: true,
      proofOptions: { library: 'snarkjs', curve: 'bn128' },
      proofData: { proof, publicSignals, vk: vkHash },
    });
  }

  async jobStatus(jobId) {
    return this.#get(`/job-status/${jobId}`);
  }

  // Poll job-status until Finalized (or Failed / timeout).
  async waitForFinalized(jobId, { timeoutMs = 45_000, intervalMs = 3_000 } = {}) {
    const deadline = Date.now() + timeoutMs;
    let last = null;
    while (Date.now() < deadline) {
      last = await this.jobStatus(jobId);
      if (last.status === 'Finalized') return last;
      if (last.status === 'Failed') {
        throw new Error(`Kurier job ${jobId} failed`);
      }
      await new Promise((r) => setTimeout(r, intervalMs));
    }
    throw new Error(`Kurier job ${jobId} not finalized within ${timeoutMs}ms (last status: ${last?.status})`);
  }
}
