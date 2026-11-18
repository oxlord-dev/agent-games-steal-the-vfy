// Groth16 policy-proof generation (snarkjs) + Kurier submission.
//
// Flow per the official Build page (sections 02.5 and 03):
//   1. Generate the proof LOCALLY with snarkjs from the downloaded
//      circuits/vfy-policy.wasm + circuits/vfy-policy_final.zkey.
//   2. SELF-VERIFY it locally against the official verification key
//      (exported from the .zkey) BEFORE returning it — a proof that does
//      not verify is never sent; the caller fails closed to HOLD.
//   3. Submit it to Kurier (recommended REST path) with the registered
//      vk_hash, then poll until the job reaches "Finalized".
//
// The circuit inputs are 9 scalars + strategyParams[0..7], with
// commitment = Poseidon(params, salt). A proof is only generated for an
// action that matches the circuit's decision list for the configured
// params — otherwise fullProve throws the circuit assert.
"use strict";

const snarkjs = require("snarkjs");
const { config } = require("./config");
const { buildCircuitInputs, ProofInputsIncompleteError } = require("./circuitInputs");

const PROOF_TIMEOUT_MS = 20_000;

/** Verification key exported from the official .zkey (cached). */
let vkPromise = null;

function exportVerificationKey() {
  if (!vkPromise) {
    vkPromise = snarkjs.zKey.exportVerificationKey(config.zkeyPath);
  }
  return vkPromise;
}

function withTimeout(promise, ms, label) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => {
    if (timer) clearTimeout(timer);
  });
}

/**
 * Generate a Groth16 policy proof for one turn and self-verify it locally.
 *
 * Throws ProofInputsIncompleteError when the salt/commitment/params are
 * missing or invalid, or any snarkjs error if proof generation or local
 * verification fails. Never returns an unverified proof: callers treat
 * any throw as "no proof available" and fail closed to HOLD.
 */
async function generatePolicyProof(envelope, action, opts = {}) {
  const inputs = buildCircuitInputs(envelope, action, opts);
  const { proof, publicSignals } = await withTimeout(
    snarkjs.groth16.fullProve(inputs, config.wasmPath, config.zkeyPath),
    PROOF_TIMEOUT_MS,
    "snarkjs fullProve"
  );
  const signals = publicSignals.map(String);
  if (signals.length !== 9) {
    throw new Error(`Expected 9 public signals from the vfy-policy circuit, got ${signals.length}.`);
  }
  const vk = await exportVerificationKey();
  const valid = await snarkjs.groth16.verify(vk, signals, proof);
  if (!valid) {
    throw new Error("Generated proof FAILED local verification against the official verification key — refusing to return it.");
  }
  return { proof, publicSignals: signals };
}

function kurierHeaders() {
  return { "content-type": "application/json" };
}

/**
 * Register the circuit verification key with Kurier once, so later
 * submit-proof calls find it (vkRegistered: true). Without this step
 * Kurier rejects jobs immediately.
 * Returns the vkHash Kurier reports. Throws on network/HTTP errors or
 * when no API key is configured.
 */
async function registerKurierVk(apiKey = config.kurierApiKey) {
  if (!apiKey) {
    throw new Error("KURIER_API_KEY is not configured; cannot register the verification key with Kurier.");
  }
  const vk = await exportVerificationKey();
  const url = `${config.kurierApiUrl}/register-vk/${apiKey}`;
  const res = await fetch(url, {
    method: "POST",
    headers: kurierHeaders(),
    body: JSON.stringify({
      proofType: "groth16",
      proofOptions: { library: "snarkjs", curve: "bn128" },
      vk,
    }),
  });
  const text = await res.text();
  if (!res.ok) {
    throw new Error(`Kurier register-vk failed: HTTP ${res.status} ${text.slice(0, 300)}`);
  }
  let raw = text;
  try {
    raw = JSON.parse(text);
  } catch {
    /* keep raw text */
  }
  const vkHash =
    (typeof raw.vkHash === "string" && raw.vkHash) ||
    (typeof raw.uniq_vk_hash === "string" && raw.uniq_vk_hash) ||
    config.vkHash;
  return { vkHash, raw };
}

/**
 * Submit a proof to Kurier for verification.
 *   POST {KURIER_API_URL}/submit-proof/{KURIER_API_KEY}
 *   { proofType: "groth16", vkRegistered: true,
 *     proofOptions: { library: "snarkjs", curve: "bn128" },
 *     proofData: { proof, publicSignals, vk: <registered vkHash> } }
 * Returns the job object; poll with pollKurierJob() until Finalized.
 */
async function submitProofToKurier(generated, vkHash = config.vkHash, apiKey = config.kurierApiKey) {
  if (!apiKey) {
    throw new Error("KURIER_API_KEY is not configured; cannot submit a proof to Kurier.");
  }
  const url = `${config.kurierApiUrl}/submit-proof/${apiKey}`;
  const res = await fetch(url, {
    method: "POST",
    headers: kurierHeaders(),
    body: JSON.stringify({
      proofType: "groth16",
      vkRegistered: true,
      proofOptions: { library: "snarkjs", curve: "bn128" },
      proofData: { proof: generated.proof, publicSignals: generated.publicSignals, vk: vkHash },
    }),
  });
  if (!res.ok) {
    throw new Error(`Kurier submit-proof failed: HTTP ${res.status} ${await res.text()}`);
  }
  const raw = await res.json();
  return {
    jobId: raw.jobId ?? raw.id,
    status: raw.status ?? "Submitted",
    proofReference: raw.proofReference ?? raw.jobId,
    raw,
  };
}

/**
 * Poll a Kurier job until it reaches "Finalized" or the timeout elapses.
 *   GET {KURIER_API_URL}/job-status/{KURIER_API_KEY}/{jobId}
 * Throws on network/HTTP errors, on a Failed job, or on timeout.
 */
async function pollKurierJob(job, opts = {}) {
  const timeoutMs = opts.timeoutMs ?? 120_000;
  const intervalMs = opts.intervalMs ?? 5_000;
  const apiKey = opts.apiKey ?? config.kurierApiKey;
  if (!job.jobId) throw new Error("Kurier job has no jobId to poll.");
  if (!apiKey) throw new Error("KURIER_API_KEY is not configured; cannot poll a Kurier job.");
  const deadline = Date.now() + timeoutMs;
  let current = job;
  while (Date.now() < deadline) {
    if (current.status === "Finalized") return current;
    if (current.status === "Failed") {
      throw new Error(`Kurier job ${job.jobId} Failed: ${JSON.stringify(current.raw).slice(0, 300)}`);
    }
    await new Promise((r) => setTimeout(r, intervalMs));
    const res = await fetch(
      `${config.kurierApiUrl}/job-status/${apiKey}/${encodeURIComponent(job.jobId)}`,
      { headers: kurierHeaders() }
    );
    if (!res.ok) {
      throw new Error(`Kurier job-status failed: HTTP ${res.status}`);
    }
    const raw = await res.json();
    current = {
      jobId: job.jobId,
      status: raw.status ?? current.status,
      proofReference: raw.proofReference ?? current.proofReference,
      raw,
    };
  }
  throw new Error(`Kurier job ${job.jobId} did not reach Finalized within ${timeoutMs}ms (last status: ${current.status}).`);
}

/**
 * Read-only Kurier job status (used by GET /proof-status/:jobId).
 * Returns the status + proof reference (if any) + the raw Kurier reply.
 */
async function getKurierJobStatus(jobId, apiKey = config.kurierApiKey) {
  if (!apiKey) {
    throw new Error("KURIER_API_KEY is not configured; cannot check a Kurier job status.");
  }
  const res = await fetch(`${config.kurierApiUrl}/job-status/${apiKey}/${encodeURIComponent(jobId)}`, {
    headers: kurierHeaders(),
    signal: AbortSignal.timeout(20_000),
  });
  const text = await res.text();
  let raw = text;
  try {
    raw = JSON.parse(text);
  } catch {
    /* keep raw text */
  }
  if (!res.ok) {
    throw new Error(`Kurier job-status failed: HTTP ${res.status} ${text.slice(0, 300)}`);
  }
  return {
    status: typeof raw.status === "string" ? raw.status : undefined,
    proofReference:
      (typeof raw.proofReference === "string" && raw.proofReference) ||
      (typeof raw.txHash === "string" && raw.txHash) ||
      undefined,
    raw,
  };
}

module.exports = {
  ProofInputsIncompleteError,
  exportVerificationKey,
  generatePolicyProof,
  registerKurierVk,
  submitProofToKurier,
  pollKurierJob,
  getKurierJobStatus,
};
