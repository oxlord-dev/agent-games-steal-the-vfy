// Circuit inputs for the vfy-policy Groth16 circuit.
//
// The circuit takes 17 inputs: 9 scalars
//   commitment, matchId, selfBalance, opponentBalance, action, amount,
//   circuitVersion, turnNumber, salt
// plus ONE array input, strategyParams[0..7] (the 8 previously "missing"
// inputs are this array, not 8 separate names).
//
// Params semantics + commitment formula:
//   commitment = Poseidon(strategyParams[0..7], salt), params first, salt last.
//   [0] = EXTRACT amount, valid 1..10
//   [1] = FORTIFY threshold: FORTIFY when selfBalance < [1]
//   [2] = HOLD threshold: HOLD when opponentBalance <= [2] OR [3] == 1
//   [3] in {0,1}; [4..7] must be exactly 0.
//   Strict priority: FORTIFY -> HOLD -> EXTRACT with amount == [0] exactly.
//
// The decision the agent returns MUST follow that same list for the
// configured params (see src/strategy.js decideActionFromParams) —
// otherwise fullProve throws the circuit assert and no proof is produced.
"use strict";

const { actionAmountForHash } = require("./strategy");
const { ACTION_CODE, circuitVersionToNumber } = require("./publicInputsHash");
const { config } = require("./config");
const { validateStrategyParams } = require("./strategyParams");
const { saltToBigInt } = require("./poseidon");

/** Input names verified against the real circuit. */
const KNOWN_INPUTS = [
  "commitment",
  "matchId",
  "selfBalance",
  "opponentBalance",
  "action",
  "amount",
  "circuitVersion",
  "turnNumber",
  "salt",
  "strategyParams",
];

/** The circuit takes 17 inputs: 9 scalars + strategyParams[0..7]. */
const TOTAL_INPUTS = 17;

class ProofInputsIncompleteError extends Error {
  constructor(message) {
    super(message);
    this.name = "ProofInputsIncompleteError";
  }
}

/**
 * Build the 17 circuit inputs for a turn, as decimal strings (the format
 * snarkjs fullProve accepts for bn128 field elements).
 *
 * @throws ProofInputsIncompleteError when the salt or the commitment is
 *         missing, or when the params fail validation — the caller must
 *         fail closed to HOLD (no proof), never guess.
 */
function buildCircuitInputs(envelope, action, opts = {}) {
  const params = validateStrategyParams(opts.params ?? config.strategyParams);
  const saltRaw = opts.salt ?? config.strategySalt;
  if (!saltRaw) {
    throw new ProofInputsIncompleteError(
      "STRATEGY_SALT is not set. Run `npm run commitment` to generate a fresh salt " +
        "and save it to .env.strategy (or set STRATEGY_SALT in the environment). " +
        "Without the salt no valid proof can be produced."
    );
  }
  const salt = saltToBigInt(saltRaw).toString();
  const commitment = opts.commitment ?? envelope.strategyCommitment?.hash;
  if (!commitment) {
    throw new ProofInputsIncompleteError("Envelope has no strategyCommitment.hash.");
  }
  return {
    commitment: BigInt(commitment).toString(),
    matchId: BigInt("0x" + envelope.matchId.replace(/-/g, "")).toString(),
    selfBalance: BigInt(envelope.state.selfBalance).toString(),
    opponentBalance: BigInt(envelope.state.opponentBalance).toString(),
    action: ACTION_CODE[action.type].toString(),
    amount: actionAmountForHash(action).toString(),
    circuitVersion: circuitVersionToNumber(config.circuitVersion).toString(),
    turnNumber: BigInt(envelope.turn).toString(),
    salt,
    strategyParams: params.map((p) => p.toString()),
  };
}

module.exports = {
  KNOWN_INPUTS,
  TOTAL_INPUTS,
  ProofInputsIncompleteError,
  buildCircuitInputs,
  validateStrategyParams,
};
