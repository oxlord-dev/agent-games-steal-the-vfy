// Strategy parameters for the vfy-policy circuit.
//
// SPEC (verified against the official circuit with snarkjs fullProve +
// local verification; see CIRCUIT_NOTES.md):
//   commitment = Poseidon(strategyParams[0..7], salt), params first, salt last.
//   [0] = EXTRACT amount, valid 1..10
//   [1] = FORTIFY threshold: FORTIFY when selfBalance < [1]
//   [2] = HOLD threshold: HOLD when opponentBalance <= [2] OR [3] == 1
//   [3] in {0,1}; [4..7] must be exactly 0.
//   Strict priority: FORTIFY -> HOLD -> EXTRACT with amount == [0] exactly.
//
// This module is pure (no imports) so config, circuit inputs and the
// strategy decision can all share one validation without import cycles.
"use strict";

/** Default policy: always EXTRACT 10 — the simplest provable policy. */
const DEFAULT_STRATEGY_PARAMS = [10, 0, 0, 0, 0, 0, 0, 0];

/**
 * Validate a strategy-params value. Returns a copy of the 8 numbers.
 * Throws a plain Error naming the exact rule that failed — callers show
 * this message and fail closed (HOLD) instead of generating a proof.
 */
function validateStrategyParams(params) {
  if (!Array.isArray(params)) {
    throw new Error(`STRATEGY_PARAMS must be a JSON array of 8 integers, got: ${JSON.stringify(params)}`);
  }
  if (params.length !== 8) {
    throw new Error(`STRATEGY_PARAMS must have exactly 8 elements, got ${params.length}: ${JSON.stringify(params)}`);
  }
  for (let i = 0; i < 8; i++) {
    const v = params[i];
    if (typeof v !== "number" || !Number.isInteger(v)) {
      throw new Error(`STRATEGY_PARAMS[${i}] must be an integer, got: ${JSON.stringify(v)}`);
    }
  }
  const p = params;
  if (p[0] < 1 || p[0] > 10) {
    throw new Error(
      `STRATEGY_PARAMS[0] (EXTRACT amount) must be 1..10, got ${p[0]}. ` +
        `Note: [0,0,0,0,0,0,0,0] can never prove — the range assert rejects amount 0.`
    );
  }
  if (p[1] < 0) {
    throw new Error(`STRATEGY_PARAMS[1] (FORTIFY threshold) must be >= 0, got ${p[1]}.`);
  }
  if (p[2] < 0) {
    throw new Error(`STRATEGY_PARAMS[2] (HOLD threshold) must be >= 0, got ${p[2]}.`);
  }
  if (p[3] !== 0 && p[3] !== 1) {
    throw new Error(`STRATEGY_PARAMS[3] must be 0 or 1, got ${p[3]}.`);
  }
  for (let i = 4; i < 8; i++) {
    if (p[i] !== 0) {
      throw new Error(`STRATEGY_PARAMS[${i}] must be exactly 0, got ${p[i]}.`);
    }
  }
  return [...p];
}

/**
 * Parse STRATEGY_PARAMS from the environment. Empty/unset -> the default
 * [10,0,0,0,0,0,0,0]. Anything else must be a JSON array of 8 numbers.
 */
function parseStrategyParams(raw) {
  if (raw === undefined || raw.trim() === "") return [...DEFAULT_STRATEGY_PARAMS];
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(`STRATEGY_PARAMS is not valid JSON: ${raw}`);
  }
  return validateStrategyParams(parsed);
}

module.exports = { DEFAULT_STRATEGY_PARAMS, validateStrategyParams, parseStrategyParams };
