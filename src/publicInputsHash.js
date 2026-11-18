// publicInputsHash — EXACTLY as specified on the official Build page.
// https://agentgames.zkverify.io/build (section 06, "Policy proof — public inputs hash")
//
//   keccak256 of ABI-packed fields, each padded to 32 bytes big-endian, in
//   this exact order:
//     1. strategyCommitment.hash
//     2. matchId, as a hex number (UUID dashes removed)
//     3. turn
//     4. selfBalance
//     5. opponentBalance
//     6. action code: HOLD = 0, FORTIFY = 1, EXTRACT = 2
//     7. amount (0 for HOLD / FORTIFY)
//     8. circuitVersion "v1" -> 1
//
// The platform independently computes this hash from the game state it knows
// and rejects any proof where the hashes diverge, so the field order and the
// 32-byte padding must match the snippet above bit for bit.
//
// NOTE: this hash is NOT the same as the circuit digest (publicSignals[0]).
// The digest is a Poseidon hash inside the circuit; this one is keccak256
// of the ABI-packed public inputs, for the platform's independent check.
"use strict";

const { concat, keccak256, numberToHex } = require("viem");

const ACTION_CODE = {
  HOLD: 0n,
  FORTIFY: 1n,
  EXTRACT: 2n,
};

function circuitVersionToNumber(version) {
  const m = /^v(\d+)$/.exec(version.trim());
  if (!m) throw new Error(`Invalid circuitVersion: ${JSON.stringify(version)} (expected e.g. "v1")`);
  return BigInt(m[1]);
}

/** Parse a 0x-prefixed hex string into a bigint. Throws on bad input. */
function hexToBigInt(value, label) {
  const v = value.trim().toLowerCase();
  if (!/^0x[0-9a-f]+$/.test(v)) throw new Error(`Invalid hex for ${label}: ${JSON.stringify(value)}`);
  return BigInt(v);
}

/** Parse a matchId UUID ("9f4e1b2a-...") into the bigint the hash expects. */
function matchIdToBigInt(matchId) {
  const compact = matchId.trim().replace(/-/g, "").toLowerCase();
  if (!/^[0-9a-f]{32}$/.test(compact)) {
    throw new Error(`matchId is not a 32-hex-digit UUID: ${JSON.stringify(matchId)}`);
  }
  return BigInt("0x" + compact);
}

function computePublicInputsHash(input) {
  const fields = [
    numberToHex(hexToBigInt(input.commitmentHash, "commitmentHash"), { size: 32 }),
    numberToHex(matchIdToBigInt(input.matchId), { size: 32 }),
    numberToHex(BigInt(input.turn), { size: 32 }),
    numberToHex(BigInt(input.selfBalance), { size: 32 }),
    numberToHex(BigInt(input.opponentBalance), { size: 32 }),
    numberToHex(ACTION_CODE[input.action], { size: 32 }),
    numberToHex(BigInt(input.amount), { size: 32 }),
    numberToHex(circuitVersionToNumber(input.circuitVersion), { size: 32 }),
  ];
  return keccak256(concat(fields));
}

module.exports = {
  ACTION_CODE,
  circuitVersionToNumber,
  hexToBigInt,
  matchIdToBigInt,
  computePublicInputsHash,
};
