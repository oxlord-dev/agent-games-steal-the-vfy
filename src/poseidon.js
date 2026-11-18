// Poseidon hashing via circomlibjs — the same implementation the
// vfy-policy circuit template uses (circomlib Poseidon, bn128 field).
//
// Used for exactly one thing here: the strategy commitment
//   commitment = Poseidon(strategyParams[0..7], salt)
// with the 8 params first and the salt last.
//
// Salt rule: the salt MUST be a field element, i.e. smaller than the bn128
// field modulus (~2^254). The commitment script generates 31-byte salts
// (< 2^248), so this is always satisfied there. computeCommitment() throws
// on a salt >= the modulus instead of silently reducing it, so a commitment
// can never depend on an ambiguous reduction.
"use strict";

/** bn128 scalar-field modulus. */
const FIELD_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/** circomlibjs Poseidon instance (lazy, built once). */
let poseidonPromise = null;

async function getPoseidon() {
  if (!poseidonPromise) {
    const { buildPoseidon } = require("circomlibjs");
    poseidonPromise = buildPoseidon();
  }
  return poseidonPromise;
}

/**
 * Poseidon over 1..16 field elements -> field element as BigInt.
 * (circomlibjs WASM build supports at most 16 inputs per call.)
 */
async function poseidonHash(inputs) {
  if (inputs.length < 1 || inputs.length > 16) {
    throw new Error(`Poseidon needs 1..16 inputs in one call, got ${inputs.length}`);
  }
  for (const v of inputs) {
    if (v < 0n || v >= FIELD_MODULUS) {
      throw new Error(`Poseidon input is not a bn128 field element: ${v}`);
    }
  }
  const poseidon = await getPoseidon();
  return BigInt(poseidon.F.toString(poseidon(inputs)));
}

/** Parse a salt given as "0x..." hex or a decimal string into a BigInt. */
function saltToBigInt(salt) {
  const s = salt.trim();
  if (s === "") throw new Error("STRATEGY_SALT is empty.");
  const v = BigInt(s.startsWith("0x") || s.startsWith("0X") ? s : s);
  if (v < 0n || v >= FIELD_MODULUS) {
    throw new Error("STRATEGY_SALT must be a bn128 field element (< 2^254). Generate a fresh 31-byte salt with `npm run commitment`.");
  }
  return v;
}

/**
 * commitment = Poseidon(strategyParams[0..7], salt).
 * Returns the commitment as a 0x-prefixed 64-hex-digit string.
 */
async function computeCommitment(params, salt) {
  const saltBig = typeof salt === "bigint" ? salt : saltToBigInt(salt);
  if (saltBig < 0n || saltBig >= FIELD_MODULUS) {
    throw new Error("Salt must be a bn128 field element (< 2^254).");
  }
  const digest = await poseidonHash([...params.map(BigInt), saltBig]);
  return "0x" + digest.toString(16).padStart(64, "0");
}

module.exports = { FIELD_MODULUS, poseidonHash, saltToBigInt, computeCommitment };
