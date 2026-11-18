// HMAC-SHA256 helpers for the Agent Games signed contract.
// The platform signs every inbound request with the header
// "x-agent-games-signature" computed over the RAW request body, and expects
// every response to carry the same header computed over the RAW response body.
// Source: https://agentgames.zkverify.io/build (sections 02, 04).
"use strict";

const crypto = require("node:crypto");

const SIGNATURE_HEADER = "x-agent-games-signature";

/** Compute HMAC-SHA256 hex of a raw body with the given secret. */
function signBody(secret, rawBody) {
  const body = Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(rawBody, "utf8");
  return crypto.createHmac("sha256", secret).update(body).digest("hex");
}

/**
 * Verify a signature header against a raw body.
 * Accepts the plain hex digest, or a "sha256=<hex>" prefixed value.
 * Uses a timing-safe comparison. Returns false when there is no secret
 * configured or the header is missing — never accept unsigned requests.
 */
function verifySignature(secret, rawBody, headerValue) {
  if (!secret || !headerValue) return false;
  const presented = (Array.isArray(headerValue) ? headerValue[0] : headerValue)
    .trim()
    .replace(/^sha256=/i, "")
    .toLowerCase();
  const expected = signBody(secret, rawBody);
  const a = Buffer.from(presented, "utf8");
  const b = Buffer.from(expected, "utf8");
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

module.exports = { SIGNATURE_HEADER, signBody, verifySignature };
