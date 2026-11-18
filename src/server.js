// HTTP server for the Steal the VFY agent.
//
// Routes:
//   GET  /health  — liveness probe for the platform health check / VPS / Railway.
//   GET  /agent   — public, read-only usage info + a signed-turn example.
//   GET  /demo-turn — public, read-only: one REAL turn-1 proof, generated live
//                   (no HMAC needed, no state change, no Kurier submission).
//   POST /verify  — public, read-only: verify a submitted Groth16 proof
//                   against the official vfy-policy VK with snarkjs.
//                   Accepts { proof, publicSignals }, returns { valid }.
//   GET  /proof-status/:jobId — Kurier job status (needs KURIER_API_KEY).
//   POST /agent   — the registered handler path. The platform posts signed
//                   turn envelopes AND the signed preflight request here.
//                   Register the FULL path (e.g. https://<host>/agent),
//                   not just the root — a root path that 404s fails
//                   preflight and every task (official Build page).
//
// Security, per the official pages:
//   - HMAC is verified against the RAW request body BEFORE parsing JSON.
//   - Every response carries x-agent-games-signature over its raw body.
//   - No secrets are ever logged.
"use strict";

const express = require("express");
const snarkjs = require("snarkjs");
const { assertConfigForServing, config } = require("./config");
const { SIGNATURE_HEADER, signBody, verifySignature } = require("./hmac");
const { handleTurn, isIdempotencyPersistent } = require("./turn");
const {
  exportVerificationKey,
  generatePolicyProof,
  getKurierJobStatus,
  registerKurierVk,
} = require("./proof");
const { decideAction, toStrategyContext } = require("./strategy");
const { verifyCircuitArtifacts } = require("./circuitArtifacts");

function createApp() {
  const app = express();

  app.use((req, res, next) => {
    res.setHeader("access-control-allow-origin", "*");
    res.setHeader("access-control-allow-methods", "GET, POST, OPTIONS");
    res.setHeader("access-control-allow-headers", "content-type, x-agent-games-signature");
    if (req.method === "OPTIONS") return res.status(204).end();
    return next();
  });

  // Capture the raw body for HMAC verification (must run before parsing).
  app.use(
    express.json({
      verify: (req, _res, buf) => {
        req.rawBody = buf;
      },
    })
  );

  app.get("/health", (_req, res) => {
    res.status(200).json({
      ok: true,
      service: "agent-games-steal-the-vfy",
      circuitVersion: config.circuitVersion,
      proofEnabled: config.proofEnabled,
      idempotencyPersistent: isIdempotencyPersistent(),
      time: new Date().toISOString(),
    });
  });

  // Public, read-only usage info for the handler path (no auth, no state).
  app.get("/agent", (_req, res) => {
    res.status(200).json({
      service: "agent-games-steal-the-vfy",
      usage:
        "POST /agent with a signed turn envelope: HMAC-SHA256 over the raw JSON body, " +
        "sent as the x-agent-games-signature header. Preflight: " +
        "{ type: 'agent-games.preflight.v1', agent_id, issued_at, nonce } " +
        "-> { ok: true, protocolVersion: 'v1' }. Unsigned requests are rejected with 401.",
      circuitVersion: config.circuitVersion,
      proofEnabled: config.proofEnabled,
      exampleEnvelope: {
        protocolVersion: "v1",
        eventId: "steal-the-vfy",
        matchId: "12345678-1234-1234-1234-123456789abc",
        turn: 1,
        state: { selfBalance: 100, opponentBalance: 100 },
        strategyCommitment: { hash: config.strategyCommitmentHash || "0x<commitment>" },
      },
      note: "This GET route is read-only usage info. It never processes a turn and never returns a proof.",
    });
  });

  // Public, read-only live proof on demand: one REAL turn-1 proof of the
  // committed strategy, generated live by this server — the same code path
  // as POST /agent turns, without needing the platform HMAC secret.
  // No state change, no Kurier submission: this endpoint proves, it does
  // not publish.
  app.get("/demo-turn", async (_req, res) => {
    if (!config.proofEnabled) {
      return res.status(503).json({
        ok: false,
        error: "proof generation is disabled on this deployment (PROOF_ENABLED=false)",
      });
    }
    if (!config.strategySalt || !config.strategyCommitmentHash) {
      return res.status(503).json({
        ok: false,
        error:
          "this deployment has no committed strategy configured " +
          "(STRATEGY_SALT / STRATEGY_COMMITMENT_HASH not set)",
      });
    }
    const t0 = Date.now();
    try {
      const envelope = {
        protocolVersion: "v1",
        eventId: "steal-the-vfy",
        matchId: "52345678-5234-5234-5234-523456789abc",
        turn: 1,
        issuedAt: new Date().toISOString(),
        deadlineAt: new Date(Date.now() + 25_000).toISOString(),
        state: {
          selfBalance: 100,
          opponentBalance: 100,
          selfFortifiedUntilTurn: null,
          opponentFortifiedUntilTurn: null,
        },
        strategyCommitment: { hash: config.strategyCommitmentHash },
      };
      const action = decideAction(toStrategyContext(1, envelope.state));
      const { proof, publicSignals } = await generatePolicyProof(envelope, action);
      return res.status(200).json({
        ok: true,
        demo: "Turn 1 (balances 100/100, committed strategy).",
        matchId: envelope.matchId,
        turn: 1,
        action,
        commitment: config.strategyCommitmentHash,
        vkHash: config.vkHash,
        proof,
        publicSignals,
        valid: true,
        provingMs: Date.now() - t0,
        verifyWith: "POST /verify with { proof, publicSignals }.",
        note: "This endpoint proves, it does not publish: no proof is submitted to Kurier here.",
      });
    } catch (e) {
      return res.status(503).json({
        ok: false,
        error: `live proof generation failed: ${e.message}`,
      });
    }
  });

  // Public, read-only Kurier job status. The Kurier API key stays
  // server-side; only the jobId the caller asks about is sent to Kurier.
  app.get("/proof-status/:jobId", async (req, res) => {
    const jobId = String(req.params.jobId ?? "");
    if (!/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(jobId)) {
      return res.status(400).json({ ok: false, error: "jobId must be a Kurier job UUID" });
    }
    if (!config.kurierApiKey) {
      return res.status(503).json({
        ok: false,
        jobId,
        error: "Kurier is not configured on this deployment (KURIER_API_KEY not set).",
      });
    }
    try {
      const status = await getKurierJobStatus(jobId);
      return res.status(200).json({
        ok: true,
        jobId,
        status: status.status ?? null,
        proofReference: status.proofReference ?? null,
        raw: status.raw,
      });
    } catch (e) {
      return res.status(502).json({ ok: false, jobId, error: e.message });
    }
  });

  // Public, read-only proof verification: verify a submitted Groth16
  // proof against the OFFICIAL vfy-policy verification key with snarkjs.
  // Body: { proof, publicSignals }. Returns { valid: true|false }.
  // No state change, no secrets, no HMAC needed.
  app.post("/verify", async (req, res) => {
    const body = req.body ?? {};
    const proof = body.proof;
    const publicSignals = body.publicSignals;
    if (!proof || typeof proof !== "object" || Array.isArray(proof)) {
      return res.status(400).json({ valid: false, error: "body.proof must be a Groth16 proof object" });
    }
    if (!Array.isArray(publicSignals) || publicSignals.length !== 9) {
      return res.status(400).json({ valid: false, error: "body.publicSignals must be an array of 9 public signals" });
    }
    try {
      const vk = await exportVerificationKey();
      const valid = await snarkjs.groth16.verify(vk, publicSignals.map(String), proof);
      return res.status(200).json({
        valid,
        circuit: "official vfy-policy (Groth16/bn128)",
        vkHash: config.vkHash,
        note: valid
          ? "The proof verifies against the official verification key."
          : "The proof does NOT verify — it is not a valid proof for these public signals.",
      });
    } catch (e) {
      return res.status(400).json({ valid: false, error: `verification failed: ${e.message}` });
    }
  });

  app.post("/agent", async (req, res) => {
    const rawBody = req.rawBody ?? Buffer.from(JSON.stringify(req.body ?? {}), "utf8");
    const finish = (status, payload) => {
      const body = JSON.stringify(payload);
      if (config.hmacSecret) {
        res.setHeader(SIGNATURE_HEADER, signBody(config.hmacSecret, body));
      }
      res.status(status).type("application/json").send(body);
    };

    // 1. Authenticate FIRST, before trusting anything in the body.
    if (!verifySignature(config.hmacSecret, rawBody, req.headers[SIGNATURE_HEADER])) {
      return finish(401, { error: "invalid signature" });
    }

    const body = req.body;

    // 2. Preflight handshake:
    //    { type: "agent-games.preflight.v1", agent_id, issued_at, nonce }
    //    -> { ok: true, protocolVersion: "v1" }, signed, no extra fields.
    if (body?.type === "agent-games.preflight.v1") {
      if (body.issued_at) {
        const issued = Date.parse(body.issued_at);
        if (!Number.isNaN(issued) && Math.abs(Date.now() - issued) > 5 * 60_000) {
          return finish(401, { error: "preflight issued_at too old" });
        }
      }
      return finish(200, { ok: true, protocolVersion: "v1" });
    }

    // 3. Turn envelope.
    try {
      const outcome = await handleTurn(body);
      // Log the outcome WITHOUT secrets (match/turn/action/reason only).
      console.log(
        `[turn] match=${String(body.matchId ?? "?").slice(0, 8)} turn=${body.turn} ` +
          `action=${outcome.response.action.type} proof=${outcome.proofStatus} reason=${outcome.reason}`
      );
      return finish(200, outcome.response);
    } catch (e) {
      // handleTurn is designed not to throw; this is a last-resort guard.
      console.error("[turn] unexpected error:", e.message);
      return finish(200, {
        protocolVersion: "v1",
        matchId: body.matchId ?? "",
        turn: body.turn ?? 0,
        action: { type: "HOLD" },
        policyProof: { circuitVersion: config.circuitVersion },
        agentTimestamp: new Date().toISOString(),
        idempotencyKey: body.idempotencyKey ?? "fallback",
      });
    }
  });

  // Anything else: 404 (the platform only ever calls /agent and /health).
  app.use((_req, res) => {
    res.status(404).json({ error: "not found" });
  });

  return app;
}

function startServer() {
  const warnings = assertConfigForServing();
  for (const w of warnings) console.warn(`[config] WARNING: ${w}`);

  // Fail closed on a swapped circuit: verify the pinned SHA-256 hashes
  // of the official artifacts before listening at all.
  const artifacts = verifyCircuitArtifacts();
  for (const a of artifacts) {
    console.log(`[circuit] verified ${a.file} sha256=${a.sha256.slice(0, 16)}…`);
  }

  if (config.idempotencyStorePath) {
    console.log(`[store] idempotency persisted to ${config.idempotencyStorePath}`);
  } else {
    console.log("[store] idempotency in-memory only (IDEMPOTENCY_STORE_PATH not set)");
  }

  const app = createApp();
  app.listen(config.port, () => {
    console.log(`[server] steal-the-vfy agent listening on :${config.port} (proofEnabled=${config.proofEnabled})`);
  });

  // Register the circuit verification key with Kurier once, in the
  // background — never blocks listen() and never throws. Without this,
  // Kurier rejects every submit-proof job immediately (vkRegistered: true
  // with no registered VK).
  if (config.kurierApiKey) {
    registerKurierVk()
      .then(({ vkHash }) => console.log(`[kurier] VK registered, vkHash=${vkHash}`))
      .catch((e) => console.warn(`[kurier] VK registration failed (proof submits will fail until VK is registered): ${e.message}`));
  } else {
    console.log("[kurier] VK registration skipped: KURIER_API_KEY not set.");
  }

  return app;
}

module.exports = { createApp, startServer };
