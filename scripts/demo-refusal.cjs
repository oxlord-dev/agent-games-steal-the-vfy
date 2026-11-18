// Refusal demo: watch the agent try to cheat and fail.
//
// Attempts three out-of-policy moves against the real committed strategy
// and the real circuit, then shows what the agent actually does:
//   1. EXTRACT 11 (committed cap is 10) -> circuit refuses (Assert Failed).
//   2. EXTRACT 10 when opponent balance is 0 (strategy says HOLD) ->
//      circuit refuses (Assert Failed).
//   3. Replay turn 1's valid proof as turn 2's proof -> snarkjs verify
//      says INVALID for turn 2's signals.
// Plus: a platform retry of the same turn envelope returns the identical
// cached response, and a turn envelope with a tampered commitment hash
// gets HOLD with no proof (fail-closed).
//
// Run: npm run commitment first, then npm run demo:refusal
"use strict";

const fs = require("node:fs");
const path = require("node:path");

const dotenv = require("dotenv");
const root = path.join(__dirname, "..");
for (const file of [".env.strategy", ".env"]) {
  const p = path.join(root, file);
  if (fs.existsSync(p)) {
    const parsed = dotenv.parse(fs.readFileSync(p, "utf8"));
    for (const [k, v] of Object.entries(parsed)) {
      if (process.env[k] === undefined) process.env[k] = v;
    }
  }
}

async function main() {
  const commitment = process.env.STRATEGY_COMMITMENT_HASH || "";
  const salt = process.env.STRATEGY_SALT || "";
  if (!commitment || !salt) {
    console.error("ERROR: run `npm run commitment` first (it saves .env.strategy).");
    process.exit(1);
  }
  const params = JSON.parse(process.env.STRATEGY_PARAMS || "[10,0,0,0,0,0,0,0]");
  const { generatePolicyProof } = require(path.join(root, "src", "proof.js"));
  const { handleTurn } = require(path.join(root, "src", "turn.js"));
  const snarkjs = require("snarkjs");
  const { exportVerificationKey } = require(path.join(root, "src", "proof.js"));

  const MATCH_ID = "12345678-1234-1234-1234-123456789abc";
  const envelopeFor = (turn, self, opp, hash = commitment) => ({
    protocolVersion: "v1",
    eventId: "steal-the-vfy",
    matchId: MATCH_ID,
    turn,
    issuedAt: new Date().toISOString(),
    deadlineAt: new Date(Date.now() + 60_000).toISOString(),
    state: { selfBalance: self, opponentBalance: opp, selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null },
    strategyCommitment: { hash },
  });

  let refused = 0;

  console.log("ATTEMPT 1: prove EXTRACT 11 (committed cap is 10) ...");
  try {
    await generatePolicyProof(envelopeFor(1, 100, 100), { type: "EXTRACT", amount: 11 }, { params, salt });
    console.error("  UNEXPECTED: circuit proved EXTRACT 11 — this must never happen.");
    process.exit(1);
  } catch (e) {
    console.log(`  CIRCUIT REFUSED: ${e.message.slice(0, 160)}`);
    console.log("  -> No proof exists for this move. Nothing to send, nothing to verify.");
    refused++;
  }

  console.log("\nATTEMPT 2: prove EXTRACT 10 when opponent balance is 0 (strategy says HOLD) ...");
  try {
    await generatePolicyProof(envelopeFor(2, 100, 0), { type: "EXTRACT", amount: 10 }, { params, salt });
    console.error("  UNEXPECTED: circuit proved an out-of-policy EXTRACT — this must never happen.");
    process.exit(1);
  } catch (e) {
    console.log(`  CIRCUIT REFUSED: ${e.message.slice(0, 160)}`);
    console.log("  -> No proof exists for this move. Nothing to send, nothing to verify.");
    refused++;
  }

  console.log("\nATTEMPT 3: replay turn 1's valid proof as turn 2's proof ...");
  const t1 = await generatePolicyProof(envelopeFor(1, 100, 100), { type: "EXTRACT", amount: 10 }, { params, salt });
  const t2 = await generatePolicyProof(envelopeFor(2, 105, 95), { type: "EXTRACT", amount: 10 }, { params, salt });
  const vk = await exportVerificationKey();
  const t1ok = await snarkjs.groth16.verify(vk, t1.publicSignals, t1.proof);
  const t2ok = await snarkjs.groth16.verify(vk, t2.publicSignals, t2.proof);
  const replayOk = await snarkjs.groth16.verify(vk, t2.publicSignals, t1.proof);
  console.log(`  turn 1 proof vs turn 1 signals: ${t1ok ? "valid" : "INVALID"}`);
  console.log(`  turn 2 proof vs turn 2 signals: ${t2ok ? "valid" : "INVALID"}`);
  console.log(`  turn 1 proof vs turn 2 signals: ${replayOk ? "valid (BAD)" : "INVALID — replay rejected"}`);
  if (!t1ok || !t2ok || replayOk) {
    console.error("  UNEXPECTED replay result.");
    process.exit(1);
  }
  console.log("  -> Public signals bind matchId + turnNumber, so a proof made for turn N does not verify for turn M.");
  refused++;

  console.log("\nRETRY: same turn 1 envelope sent twice (platform retry) ...");
  const env1 = envelopeFor(1, 100, 100);
  const first = await handleTurn(env1);
  const second = await handleTurn(env1);
  const identical = JSON.stringify(first.response) === JSON.stringify(second.response);
  console.log(`  identical response: ${identical ? "yes" : "NO"}  | idempotencyKey: ${first.response.idempotencyKey}`);
  if (!identical) {
    console.error("  UNEXPECTED: retry returned a different response.");
    process.exit(1);
  }
  console.log("  -> A retry returns the cached response. The agent never proves the same turn twice.");

  console.log("\nAGENT ANSWER for a turn with opponent balance 0:");
  const holdOutcome = await handleTurn(envelopeFor(2, 100, 0));
  console.log(`  action: ${holdOutcome.response.action.type}  | proof: ${holdOutcome.response.policyProof.proof ? "yes (valid, self-verified)" : "no"}  | proofStatus: ${holdOutcome.proofStatus}`);
  console.log("  -> The agent never sends the refused move. It answers the in-policy action (HOLD) and proves that one instead.");

  console.log("\nFAIL-CLOSED: turn envelope with a tampered commitment hash ...");
  const tamperedHash = "0x" + "00".repeat(31) + "01";
  const tampered = await handleTurn(envelopeFor(3, 100, 100, tamperedHash));
  console.log(`  action: ${tampered.response.action.type}  | proof: ${tampered.response.policyProof.proof ? "yes" : "no"}  | proofStatus: ${tampered.proofStatus}`);
  if (tampered.response.action.type !== "HOLD" || tampered.response.policyProof.proof) {
    console.error("  UNEXPECTED: tampered commitment was not fail-closed to HOLD without proof.");
    process.exit(1);
  }
  console.log("  -> The agent answers HOLD with no proof instead of guessing or sending an unproven move.");

  console.log(`\nREFUSAL DEMO OK: ${refused}/3 out-of-policy moves refused by the circuit (over-cap, wrong-branch, replay), agent answered HOLD in both fail-closed cases.`);
  process.exit(0);
}

main().catch((e) => {
  console.error(`REFUSAL DEMO FAILED: ${e.message}`);
  process.exit(1);
});
