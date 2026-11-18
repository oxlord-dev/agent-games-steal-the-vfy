// Demo: simulate a full 20-turn Steal the VFY match against a scripted
// opponent, using the REAL turn handler (src/turn.js) and REAL Groth16
// proofs (snarkjs + official circuit), verified locally per turn.
//
//   1. Loads .env and .env.strategy (run `npm run commitment` first).
//   2. Plays 20 turns: our agent answers via handleTurn(); the opponent
//      follows a fixed script (see OPPONENT below). Balances are updated
//      by a documented resolver simulation (NOT the platform resolver).
//   3. Prints a per-turn summary (action, proof status, ms, balances)
//      and totals. Exits non-zero if any turn fails to produce a proof.
//   4. If KURIER_API_KEY is set, submits ONE proof (turn 1) via Kurier
//      and polls it to Finalized. If it is NOT set, the Kurier step is
//      skipped gracefully — never asks for a key.
//
// Resolver rules used for the simulation (documented assumptions, from
// the official event page):
//   - FORTIFY costs 2 VFY and protects against extraction on the NEXT
//     turn only (fortifiedUntil = turn + 1); it blocks up to 6 VFY.
//   - EXTRACT steals up to the requested amount from the opponent's
//     balance; a fortified defender reduces the gain by 6 (min 0).
//   - Both sides' gains are computed from START-of-turn balances, then
//     applied together (simultaneous submission, like the real resolver).
//
// SECURITY: the Kurier key is read from the environment only, never
// printed, never written to a file. The strategy salt is never printed.
"use strict";

const fs = require("node:fs");
const path = require("node:path");

// --- 1. Load env files BEFORE requiring src/ (config reads env at import).
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

const kurierApiKey = process.env.KURIER_API_KEY || "";

// Keep Kurier OUT of the per-turn handler (one submit only, at the end).
if (process.env.KURIER_API_KEY) delete process.env.KURIER_API_KEY;

const { handleTurn } = require(path.join(root, "src", "turn.js"));
const { submitProofToKurier, pollKurierJob } = require(path.join(root, "src", "proof.js"));

const MATCH_ID = "12345678-1234-1234-1234-123456789abc";

// Scripted opponent (deterministic, documented):
//   - balance <= 30 -> EXTRACT 10 (desperate)
//   - every 5th turn -> FORTIFY
//   - otherwise -> EXTRACT 5
function opponentAction(turn, oppBalance) {
  if (oppBalance <= 30) return { type: "EXTRACT", amount: 10 };
  if (turn % 5 === 0) return { type: "FORTIFY" };
  return { type: "EXTRACT", amount: 5 };
}

async function main() {
  const commitment = process.env.STRATEGY_COMMITMENT_HASH || "";
  if (!commitment) {
    console.error("ERROR: STRATEGY_COMMITMENT_HASH is not set. Run `npm run commitment` first (it saves .env.strategy).");
    process.exit(1);
  }
  if (!process.env.STRATEGY_SALT) {
    console.error("ERROR: STRATEGY_SALT is not set. Run `npm run commitment` first.");
    process.exit(1);
  }

  const params = process.env.STRATEGY_PARAMS || "[10,0,0,0,0,0,0,0]";
  console.log("Demo match — Steal the VFY (simulated, 20 turns)");
  console.log(`matchId: ${MATCH_ID}`);
  console.log(`params: ${params}  commitment: ${commitment}`);
  console.log(`Kurier: ${kurierApiKey ? "key present — one proof will be submitted at the end" : "no KURIER_API_KEY — Kurier step will be skipped"}`);
  console.log("");

  let self = 100;
  let opp = 100;
  let selfFortifiedUntil = null;
  let oppFortifiedUntil = null;
  let firstProof = null;
  let proved = 0;
  let totalMs = 0;
  const proofMs = [];

  for (let turn = 1; turn <= 20; turn++) {
    const startSelf = self;
    const startOpp = opp;
    const envelope = {
      protocolVersion: "v1",
      eventId: "steal-the-vfy",
      matchId: MATCH_ID,
      turn,
      issuedAt: new Date().toISOString(),
      deadlineAt: new Date(Date.now() + 25_000).toISOString(),
      state: {
        selfBalance: startSelf,
        opponentBalance: startOpp,
        selfFortifiedUntilTurn: selfFortifiedUntil,
        opponentFortifiedUntilTurn: oppFortifiedUntil,
      },
      strategyCommitment: { hash: commitment },
      // No idempotencyKey on purpose: the handler derives the deterministic
      // UUIDv5 key from matchId:turn.
    };

    const t0 = Date.now();
    const outcome = await handleTurn(envelope);
    const ms = Date.now() - t0;
    totalMs += ms;
    proofMs.push(ms);

    const action = outcome.response.action;
    const hasProof = !!outcome.response.policyProof.proof && Array.isArray(outcome.response.policyProof.publicSignals);
    if (hasProof) {
      proved++;
      if (turn === 1) firstProof = outcome.response.policyProof;
    }

    const oppAction = opponentAction(turn, startOpp);

    // Resolver: gains from start-of-turn balances, applied together.
    let selfGain = 0;
    let oppGain = 0;
    let selfCost = 0;
    let oppCost = 0;
    if (action.type === "EXTRACT") {
      selfGain = Math.min(action.amount, startOpp);
      if (oppFortifiedUntil === turn) selfGain = Math.max(0, selfGain - 6);
    } else if (action.type === "FORTIFY") {
      selfCost = 2;
    }
    if (oppAction.type === "EXTRACT") {
      oppGain = Math.min(oppAction.amount, startSelf);
      if (selfFortifiedUntil === turn) oppGain = Math.max(0, oppGain - 6);
    } else if (oppAction.type === "FORTIFY") {
      oppCost = 2;
    }
    self = startSelf - oppGain - selfCost + selfGain;
    opp = startOpp - selfGain - oppCost + oppGain;

    // Fortify played this turn protects NEXT turn only.
    selfFortifiedUntil = action.type === "FORTIFY" ? turn + 1 : null;
    oppFortifiedUntil = oppAction.type === "FORTIFY" ? turn + 1 : null;

    const ourAction = action.type + (action.amount ? ` ${action.amount}` : "");
    const theirAction = oppAction.type + (oppAction.amount ? ` ${oppAction.amount}` : "");
    console.log(
      `turn ${String(turn).padStart(2)}: us ${ourAction.padEnd(11)} | opp ${theirAction.padEnd(11)} | ` +
        `proof=${outcome.proofStatus.padEnd(20)} | ${ms}ms | balances ${startSelf}->${self} / ${startOpp}->${opp}` +
        (hasProof ? "" : "  <-- NO PROOF")
    );
  }

  const sorted = [...proofMs].sort((a, b) => a - b);
  console.log("");
  console.log(`Totals: ${proved}/20 turns proved + locally verified, ${totalMs}ms total, avg ${Math.round(totalMs / 20)}ms/turn, median ${sorted[9]}ms, max ${sorted[19]}ms.`);
  console.log(`Final balances: us ${self} — opponent ${opp} → ${self > opp ? "US WIN" : self < opp ? "OPPONENT WIN" : "DRAW"}.`);

  // --- 4. Kurier: exactly ONE proof (turn 1).
  if (!kurierApiKey) {
    console.log("\nKurier step skipped: KURIER_API_KEY is not set in the environment.");
  } else if (!firstProof) {
    console.log("\nKurier step skipped: turn 1 produced no proof to submit.");
  } else {
    console.log("\nSubmitting turn 1 proof to Kurier (VK registration first, then submit + poll)...");
    try {
      const { registerKurierVk } = require(path.join(root, "src", "proof.js"));
      const { vkHash } = await registerKurierVk(kurierApiKey);
      console.log(`VK registered, vkHash=${vkHash}`);
      const job = await submitProofToKurier(
        { proof: firstProof.proof, publicSignals: firstProof.publicSignals },
        undefined,
        kurierApiKey
      );
      console.log(`Kurier job submitted, jobId=${job.jobId}, status=${job.status}`);
      const final = await pollKurierJob(job, { timeoutMs: 120_000, apiKey: kurierApiKey });
      console.log(`Kurier job ${final.jobId} final status: ${final.status}`);
      if (final.proofReference) console.log(`proofReference: ${final.proofReference}`);
    } catch (e) {
      console.error(`Kurier step FAILED: ${e.message}`);
      process.exit(1);
    }
  }

  if (proved !== 20) {
    console.error(`\nDEMO FAILED: only ${proved}/20 turns produced a proof.`);
    process.exit(1);
  }
  console.log("\nDEMO OK: all 20 turns proved + locally verified.");
  // snarkjs leaves worker MessagePorts open after fullProve, which keeps
  // the Node event loop alive forever — exit explicitly (this is a CLI).
  process.exit(0);
}

main().catch((e) => {
  console.error(`DEMO FAILED: ${e.message}`);
  process.exit(1);
});
