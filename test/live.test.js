// LIVE-proof tests: real Groth16 proofs against the official vfy-policy
// circuit, self-verified locally. Requires `npm run commitment` first
// (so .env.strategy exists) and circuits/ present.
//
// Run: npm run test:live
// Env: AGENT_GAMES_HMAC_SECRET defaults to a dummy test secret here
// (the platform secret is only needed for real deployment).
// KURIER_API_KEY is NOT set, so no on-chain submission happens.
"use strict";

process.env.AGENT_GAMES_HMAC_SECRET = process.env.AGENT_GAMES_HMAC_SECRET || "test-hmac-secret-dummy-only";
delete process.env.PROOF_ENABLED; // live proofs on

const test = require("node:test");
const assert = require("node:assert/strict");
const snarkjs = require("snarkjs");

const { config } = require("../src/config");
const { signBody } = require("../src/hmac");
const { createApp } = require("../src/server");
const { handleTurn, clearIdempotencyCache } = require("../src/turn");
const { generatePolicyProof, exportVerificationKey } = require("../src/proof");
const { computePublicInputsHash } = require("../src/publicInputsHash");

const SECRET = config.hmacSecret;
const COMMITMENT = config.strategyCommitmentHash;
const PARAMS = config.strategyParams;

if (!COMMITMENT || !config.strategySalt) {
  throw new Error("STRATEGY_COMMITMENT_HASH / STRATEGY_SALT missing — run `npm run commitment` first.");
}

let baseUrl;
let server;

test.before(async () => {
  const app = createApp();
  await new Promise((resolve) => {
    server = app.listen(0, "127.0.0.1", resolve);
  });
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

test.after(async () => {
  await new Promise((resolve) => server.close(resolve));
});

function envelope(matchId, turn, self, opp, hash = COMMITMENT) {
  return {
    protocolVersion: "v1",
    eventId: "steal-the-vfy",
    matchId,
    turn,
    issuedAt: new Date().toISOString(),
    deadlineAt: new Date(Date.now() + 60_000).toISOString(),
    state: { selfBalance: self, opponentBalance: opp, selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null },
    strategyCommitment: { hash },
  };
}

async function postAgent(body) {
  const raw = JSON.stringify(body);
  const res = await fetch(`${baseUrl}/agent`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-agent-games-signature": signBody(SECRET, raw) },
    body: raw,
  });
  const text = await res.text();
  return { status: res.status, json: JSON.parse(text), raw: text };
}

test("live turn 100/100 over HTTP: EXTRACT 10 with a real, self-verified proof", async () => {
  clearIdempotencyCache();
  const matchId = "a2345678-a234-a234-a234-a23456789abc";
  const t0 = Date.now();
  const r = await postAgent(envelope(matchId, 1, 100, 100));
  const ms = Date.now() - t0;
  console.log(`# live turn proof took ${ms}ms (HTTP round-trip incl. proof)`);
  assert.equal(r.status, 200);
  assert.deepEqual(r.json.action, { type: "EXTRACT", amount: 10 });
  const pp = r.json.policyProof;
  assert.equal(pp.circuitVersion, "v1");
  assert.ok(Array.isArray(pp.publicSignals) && pp.publicSignals.length === 9, "9 public signals");
  assert.ok(pp.proof && typeof pp.proof === "object");
  // Public-signal order (Wajib): [digest, commitment, matchId, turn,
  // selfBalance, opponentBalance, action, amount, circuitVersion].
  const s = pp.publicSignals.map(String);
  assert.equal(s[1], BigInt(COMMITMENT).toString());
  assert.equal(s[2], BigInt("0x" + matchId.replace(/-/g, "")).toString());
  assert.equal(s[3], "1");
  assert.equal(s[4], "100");
  assert.equal(s[5], "100");
  assert.equal(s[6], "2"); // EXTRACT
  assert.equal(s[7], "10");
  assert.equal(s[8], "1"); // v1
  // publicInputsHash matches the independent computation — and is NOT the
  // circuit digest (publicSignals[0]).
  const expectedHash = computePublicInputsHash({
    commitmentHash: COMMITMENT, matchId, turn: 1, selfBalance: 100, opponentBalance: 100,
    action: "EXTRACT", amount: 10, circuitVersion: "v1",
  });
  assert.equal(pp.publicInputsHash, expectedHash);
  assert.notEqual(pp.publicInputsHash, "0x" + BigInt(s[0]).toString(16).padStart(64, "0"));
  // Independent verification against the official VK (zero repo code path
  // beyond snarkjs + the exported key).
  const vk = await exportVerificationKey();
  assert.equal(await snarkjs.groth16.verify(vk, s, pp.proof), true);
});

test("live HTTP retry returns the identical response (no second proof)", async () => {
  const matchId = "b2345678-b234-b234-b234-b23456789abc";
  const env = envelope(matchId, 1, 100, 100);
  const r1 = await postAgent(env);
  const r2 = await postAgent(env);
  assert.equal(r1.status, 200);
  assert.equal(r2.raw, r1.raw);
});

test("live HOLD turn (opponent 0): proved HOLD, no amount field", async () => {
  clearIdempotencyCache();
  const matchId = "c2345678-c234-c234-c234-c23456789abc";
  const outcome = await handleTurn(envelope(matchId, 2, 100, 0));
  assert.deepEqual(outcome.response.action, { type: "HOLD" });
  assert.ok(!("amount" in outcome.response.action));
  const pp = outcome.response.policyProof;
  assert.ok(Array.isArray(pp.publicSignals) && pp.publicSignals.length === 9);
  const s = pp.publicSignals.map(String);
  assert.equal(s[6], "0"); // HOLD
  assert.equal(s[7], "0");
  const vk = await exportVerificationKey();
  assert.equal(await snarkjs.groth16.verify(vk, s, pp.proof), true);
});

test("refusal: EXTRACT 11 is refused by the circuit (no proof exists)", async () => {
  const matchId = "d2345678-d234-d234-d234-d23456789abc";
  await assert.rejects(
    generatePolicyProof(envelope(matchId, 1, 100, 100), { type: "EXTRACT", amount: 11 }, { params: PARAMS, salt: config.strategySalt }),
    /Assert Failed|assert/i
  );
});

test("refusal: EXTRACT 10 at opponent 0 is refused by the circuit", async () => {
  const matchId = "e2345678-e234-e234-e234-e23456789abc";
  await assert.rejects(
    generatePolicyProof(envelope(matchId, 2, 100, 0), { type: "EXTRACT", amount: 10 }, { params: PARAMS, salt: config.strategySalt }),
    /Assert Failed|assert/i
  );
});

test("commitment mismatch -> HOLD with no proof (live handler)", async () => {
  clearIdempotencyCache();
  const matchId = "f2345678-f234-f234-f234-f23456789abc";
  const outcome = await handleTurn(envelope(matchId, 1, 100, 100, "0x" + "00".repeat(31) + "01"));
  assert.equal(outcome.response.action.type, "HOLD");
  assert.equal(outcome.response.policyProof.proof, undefined);
});

test("POST /verify: real proof verifies, tampered signals do not", async () => {
  clearIdempotencyCache();
  const matchId = "12345678-1234-1234-1234-123456789abc";
  const outcome = await handleTurn(envelope(matchId, 1, 100, 100));
  const pp = outcome.response.policyProof;
  const good = await fetch(`${baseUrl}/verify`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ proof: pp.proof, publicSignals: pp.publicSignals }),
  });
  assert.equal((await good.json()).valid, true);
  const tampered = [...pp.publicSignals];
  tampered[4] = "99"; // selfBalance changed
  const bad = await fetch(`${baseUrl}/verify`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ proof: pp.proof, publicSignals: tampered }),
  });
  assert.equal((await bad.json()).valid, false);
});

test("GET /demo-turn returns a fresh real proof", async () => {
  const t0 = Date.now();
  const res = await fetch(`${baseUrl}/demo-turn`);
  const ms = Date.now() - t0;
  console.log(`# /demo-turn took ${ms}ms`);
  assert.equal(res.status, 200);
  const j = await res.json();
  assert.equal(j.ok, true);
  assert.deepEqual(j.action, { type: "EXTRACT", amount: 10 });
  assert.equal(j.valid, true);
  const vk = await exportVerificationKey();
  assert.equal(await snarkjs.groth16.verify(vk, j.publicSignals.map(String), j.proof), true);
});
