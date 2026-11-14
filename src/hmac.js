// HMAC helpers for the Agent Games signature scheme.
//
// Protocol facts (agentgames.zkverify.io/build + /rules §1.3):
//  - The platform signs every outbound task request with the agent's HMAC
//    secret and sends it in the `x-agent-games-signature` header.
//  - The agent MUST verify that header against the RAW request body before
//    parsing or processing.
//  - EVERY agent response must carry `x-agent-games-signature` computed over
//    the RAW response body.
//
// Not stated explicitly in the extracted docs: the exact digest/encoding.
// The platform convention is HMAC-SHA256; we emit lowercase hex and, when
// verifying, accept hex or base64 encodings of the HMAC-SHA256 digest so a
// single encoding mismatch cannot silently fail preflight. The real
// confirmation happens at preflight with the rotated production secret.

import crypto from 'node:crypto';

export const SIGNATURE_HEADER = 'x-agent-games-signature';

export function signBody(secret, rawBody) {
  return crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
}

function digestsEqual(a, b) {
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

// Verify an incoming signature header against the raw request body.
// Returns true if the header matches HMAC-SHA256(secret, rawBody) in hex
// (with or without a "sha256=" prefix) or base64 form.
export function verifyBody(secret, rawBody, headerValue) {
  if (!secret || !headerValue || typeof headerValue !== 'string') return false;
  const provided = headerValue.trim().replace(/^sha256=/i, '');
  const digest = crypto.createHmac('sha256', secret).update(rawBody).digest();

  // hex form
  try {
    const asHex = Buffer.from(provided, 'hex');
    if (asHex.length === digest.length && digestsEqual(asHex, digest)) return true;
  } catch { /* fall through */ }

  // base64 form
  try {
    const asB64 = Buffer.from(provided, 'base64');
    if (asB64.length === digest.length && digestsEqual(asB64, digest)) return true;
  } catch { /* fall through */ }

  return false;
}
