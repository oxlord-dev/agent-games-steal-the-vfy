// Unit + HTTP tests WITHOUT live proof generation (PROOF_ENABLED=false
// is set by `npm test`). Live-proof tests live in test/live.test.js.
//
// Run: npm test
// Env expected (set by the npm script): AGENT_GAMES_HMAC_SECRET=<dummy>,
// PROOF_ENABLED=false. Strategy params default [10,0,0,0,0,0,0,0].
// If .env.strategy exists, its commitment hash is the expected one;
// otherwise a dummy 0xab… hash is used.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const { config } = require("../src/config");
const { signBody, verifySignature } = require("../src/hmac");
const { decideActionFromParams } = require("../src/strategy");
const { validateStrategyParams } = require("../src/strategyParams");
const { computePublicInputsHash, matchIdToBigInt } = require("../src/publicInputsHash");
const { verifyCircuitArtifacts } = require("../src/circuitArtifacts");
const { createJsonStore } = require("../src/store");
const { createApp } = require("../src/server");

const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || "test-hmac-secret-dummy-only";
const COMMITMENT = config.strategyCommitmentHash || "0x" + "ab".repeat(32);
const MATCH_ID = "12345678-1234-1234-1234-123456789abc";

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

function envelope(overrides = {}) {
  return {
    protocolVersion: "v1",
    eventId: "steal-the-vfy",
    matchId: MATCH_ID,
    turn: 1,
    issuedAt: new Date().toISOString(),
    deadlineAt: new Date(Date.now() + 60_000).toISOString(),
    state: { selfBalance: 100, opponentBalance: 100, selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null },
    strategyCommitment: { hash: COMMITMENT },
    ...overrides,
  };
}

async function postAgent(body, secret = SECRET) {
  const raw = JSON.stringify(body);
  const res = await fetch(`${baseUrl}/agent`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(secret ? { "x-agent-games-signature": signBody(secret, raw) } : {}),
    },
    body: raw,
  });
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    /* keep null */
  }
  return { status: res.status, json, raw: text, sig: res.headers.get("x-agent-games-signature") };
}

test("health + GET /agent usage", async () => {
  const h = await fetch(`${baseUrl}/health`);
  assert.equal(h.status, 200);
  const hj = await h.json();
  assert.equal(hj.ok, true);
  assert.equal(hj.service, "agent-games-steal-the-vfy");

  const g = await fetch(`${baseUrl}/agent`);
  assert.equal(g.status, 200);
  const gj = await g.json();
  assert.match(gj.usage, /preflight/i);
});

test("preflight valid returns exactly {ok:true, protocolVersion:'v1'} and is signed", async () => {
  const body = { type: "agent-games.preflight.v1", agent_id: "test-agent", issued_at: new Date().toISOString(), nonce: "n1" };
  const r = await postAgent(body);
  assert.equal(r.status, 200);
  assert.deepEqual(r.json, { ok: true, protocolVersion: "v1" });
  assert.ok(r.sig, "response must carry x-agent-games-signature");
  assert.equal(signBody(SECRET, r.raw), r.sig);
});

test("preflight with stale issued_at (>5 min old) -> 401", async () => {
  const body = { type: "agent-games.preflight.v1", agent_id: "t", issued_at: new Date(Date.now() - 6 * 60_000).toISOString(), nonce: "n2" };
  const r = await postAgent(body);
  assert.equal(r.status, 401);
});

test("preflight with future issued_at (>5 min ahead) -> 401", async () => {
  const body = { type: "agent-games.preflight.v1", agent_id: "t", issued_at: new Date(Date.now() + 6 * 60_000).toISOString(), nonce: "n3" };
  const r = await postAgent(body);
  assert.equal(r.status, 401);
});

test("unsigned POST /agent -> 401 fail-closed", async () => {
  const r = await postAgent(envelope(), null);
  assert.equal(r.status, 401);
  assert.equal(r.json.error, "invalid signature");
});

test("bad HMAC signature -> 401 fail-closed", async () => {
  const r = await postAgent(envelope(), "wrong-secret");
  assert.equal(r.status, 401);
});

test("valid turn 100/100 -> EXTRACT 10, proof inside policyProof, schema exact", async () => {
  const env = envelope({ matchId: "22345678-2234-2234-2234-223456789abc", turn: 1 });
  const r = await postAgent(env);
  assert.equal(r.status, 200);
  assert.equal(r.json.protocolVersion, "v1");
  assert.equal(r.json.matchId, env.matchId);
  assert.equal(r.json.turn, 1);
  assert.deepEqual(r.json.action, { type: "EXTRACT", amount: 10 });
  // proof + publicSignals must be INSIDE policyProof (never top-level).
  assert.equal(r.json.proof, undefined);
  assert.equal(r.json.publicSignals, undefined);
  assert.equal(r.json.policyProof.circuitVersion, "v1");
  assert.match(r.json.policyProof.publicInputsHash, /^0x[0-9a-f]{64}$/);
  assert.ok(r.json.agentTimestamp);
  assert.ok(r.json.idempotencyKey);
  // Response itself is HMAC-signed over the raw body.
  assert.equal(signBody(SECRET, r.raw), r.sig);
});

test("platform retry with same envelope returns the identical response", async () => {
  const env = envelope({ matchId: "32345678-3234-3234-3234-323456789abc", turn: 3 });
  const r1 = await postAgent(env);
  const r2 = await postAgent(env);
  assert.equal(r1.status, 200);
  assert.equal(r2.status, 200);
  assert.equal(r2.raw, r1.raw);
});

test("opponent balance 0 -> HOLD, action has NO amount field at all", async () => {
  const env = envelope({
    matchId: "42345678-4234-4234-4234-423456789abc",
    turn: 2,
    state: { selfBalance: 100, opponentBalance: 0, selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null },
  });
  const r = await postAgent(env);
  assert.equal(r.status, 200);
  assert.deepEqual(r.json.action, { type: "HOLD" });
  assert.ok(!("amount" in r.json.action), "amount must be omitted entirely for HOLD");
});

test("commitment mismatch -> HOLD without proof", async () => {
  const env = envelope({
    matchId: "52345678-5234-5234-5234-523456789abc",
    turn: 1,
    strategyCommitment: { hash: "0x" + "00".repeat(31) + "01" },
  });
  const r = await postAgent(env);
  assert.equal(r.status, 200);
  assert.equal(r.json.action.type, "HOLD");
  assert.equal(r.json.policyProof.proof, undefined);
  assert.equal(r.json.policyProof.publicInputsHash, undefined);
});

test("deadline already passed -> HOLD without proof", async () => {
  const env = envelope({
    matchId: "62345678-6234-6234-6234-623456789abc",
    turn: 1,
    deadlineAt: new Date(Date.now() - 60_000).toISOString(),
  });
  const r = await postAgent(env);
  assert.equal(r.status, 200);
  assert.equal(r.json.action.type, "HOLD");
  assert.equal(r.json.policyProof.proof, undefined);
});

test("invalid envelope (turn 21) -> HOLD", async () => {
  const env = envelope({ matchId: "72345678-7234-7234-7234-723456789abc", turn: 21 });
  const r = await postAgent(env);
  assert.equal(r.status, 200);
  assert.equal(r.json.action.type, "HOLD");
});

test("strategy decision list branches (pure, any params)", () => {
  const ctx = (self, opp) => ({ turn: 1, selfBalance: self, opponentBalance: opp, selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null });
  assert.deepEqual(decideActionFromParams(ctx(100, 100), [10, 0, 0, 0, 0, 0, 0, 0]), { type: "EXTRACT", amount: 10 });
  assert.deepEqual(decideActionFromParams(ctx(100, 0), [10, 0, 0, 0, 0, 0, 0, 0]), { type: "HOLD" });
  assert.deepEqual(decideActionFromParams(ctx(50, 100), [10, 70, 0, 0, 0, 0, 0, 0]), { type: "FORTIFY" });
  assert.deepEqual(decideActionFromParams(ctx(100, 100), [10, 0, 0, 1, 0, 0, 0, 0]), { type: "HOLD" });
  assert.deepEqual(decideActionFromParams(ctx(100, 5), [5, 0, 20, 0, 0, 0, 0, 0]), { type: "HOLD" });
});

test("validateStrategyParams rejects bad params", () => {
  assert.throws(() => validateStrategyParams([0, 0, 0, 0, 0, 0, 0, 0]), /1\.\.10/);
  assert.throws(() => validateStrategyParams([11, 0, 0, 0, 0, 0, 0, 0]), /1\.\.10/);
  assert.throws(() => validateStrategyParams([10, 0, 0, 2, 0, 0, 0, 0]), /0 or 1/);
  assert.throws(() => validateStrategyParams([10, 0, 0, 0, 1, 0, 0, 0]), /exactly 0/);
  assert.throws(() => validateStrategyParams([10, 0, 0]), /exactly 8/);
  assert.deepEqual(validateStrategyParams([10, 0, 0, 0, 0, 0, 0, 0]), [10, 0, 0, 0, 0, 0, 0, 0]);
});

test("publicInputsHash is deterministic and sensitive to every field", () => {
  const base = {
    commitmentHash: COMMITMENT,
    matchId: MATCH_ID,
    turn: 1,
    selfBalance: 100,
    opponentBalance: 100,
    action: "EXTRACT",
    amount: 10,
    circuitVersion: "v1",
  };
  const h1 = computePublicInputsHash(base);
  assert.match(h1, /^0x[0-9a-f]{64}$/);
  assert.equal(computePublicInputsHash(base), h1, "same inputs -> same hash");
  assert.notEqual(computePublicInputsHash({ ...base, turn: 2 }), h1);
  assert.notEqual(computePublicInputsHash({ ...base, selfBalance: 99 }), h1);
  assert.notEqual(computePublicInputsHash({ ...base, action: "HOLD", amount: 0 }), h1);
  assert.notEqual(computePublicInputsHash({ ...base, matchId: "22345678-2234-2234-2234-223456789abc" }), h1);
  assert.equal(matchIdToBigInt(MATCH_ID).toString(16), "12345678123412341234123456789abc");
});

test("hmac helpers: sha256= prefix accepted, wrong secret rejected", () => {
  const raw = Buffer.from('{"a":1}', "utf8");
  const sig = signBody(SECRET, raw);
  assert.equal(verifySignature(SECRET, raw, sig), true);
  assert.equal(verifySignature(SECRET, raw, `sha256=${sig}`), true);
  assert.equal(verifySignature(SECRET, raw, "deadbeef"), false);
  assert.equal(verifySignature("", raw, sig), false);
  assert.equal(verifySignature(SECRET, raw, undefined), false);
});

test("circuit artifacts verify against pinned SHA-256", () => {
  const verified = verifyCircuitArtifacts();
  assert.equal(verified.length, 2);
  assert.equal(verified[0].file, "vfy-policy.wasm");
  assert.equal(verified[0].sha256, "bc0998250d2baf75b89deef5306867ffa7085a08d4f7d2caf0dd63a060b134d2");
  assert.equal(verified[1].file, "vfy-policy_final.zkey");
  assert.equal(verified[1].sha256, "f9666a1655279ef27f7fee6d535ac8aa9e39286ac40ff6279fea87c21ab6ce41");
});

test("json store round-trips and ignores corrupt files", () => {
  const dir = fs.mkdtempSync(path.join(__dirname, "tmp-store-"));
  const file = path.join(dir, "idempotency.json");
  const store = createJsonStore(file);
  assert.equal(store.load(), null);
  store.save([["k1", { a: 1 }]]);
  assert.deepEqual(store.load(), [["k1", { a: 1 }]]);
  fs.writeFileSync(file, "{not json");
  assert.equal(store.load(), null);
  fs.rmSync(dir, { recursive: true, force: true });
});

test("poseidon commitment recomputes to the registered hash (if .env.strategy exists)", async () => {
  const strategyFile = path.join(__dirname, "..", ".env.strategy");
  if (!fs.existsSync(strategyFile)) {
    console.log("# skip: .env.strategy not present yet — run `npm run commitment` first");
    return;
  }
  // Read params + salt from the file; never log the salt.
  const dotenv = require("dotenv");
  const parsed = dotenv.parse(fs.readFileSync(strategyFile, "utf8"));
  const { computeCommitment } = require("../src/poseidon");
  const recomputed = await computeCommitment(JSON.parse(parsed.STRATEGY_PARAMS), parsed.STRATEGY_SALT);
  assert.equal(recomputed.toLowerCase(), parsed.STRATEGY_COMMITMENT_HASH.toLowerCase());
  assert.equal(recomputed.toLowerCase(), config.strategyCommitmentHash);
});
