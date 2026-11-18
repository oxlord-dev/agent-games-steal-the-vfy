# Circuit notes — vfy-policy (Steal the VFY)

Official artifacts, downloaded from `https://agentgames.zkverify.io/circuits/`:

| File | Size | SHA-256 |
|---|---|---|
| `vfy-policy.wasm` | 2,991,212 | `bc0998250d2baf75b89deef5306867ffa7085a08d4f7d2caf0dd63a060b134d2` |
| `vfy-policy_final.zkey` | 810,586 | `f9666a1655279ef27f7fee6d535ac8aa9e39286ac40ff6279fea87c21ab6ce41` |

- `vkHash`: `0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047`
  (confirmed via `https://agentgames.zkverify.io/api/circuit-info`,
  copy in `circuits/circuit-info.json`).
- Proving system: Groth16 / BN128, Circom 2.x. `snarkjs@0.7.6`.
- `verification_key.json` exported from the `.zkey` with
  `npm run export:vk`; one turn-1 proof was verified against it with the
  standalone `snarkjs` CLI (`OK`).

## Inputs (17 total)

9 scalars + one array:

```
commitment, matchId, selfBalance, opponentBalance, action, amount,
circuitVersion, turnNumber, salt, strategyParams[0..7]
```

- `commitment = Poseidon(strategyParams[0..7], salt)`, params first,
  salt last (circomlibjs Poseidon, bn128 field).
- Action codes: HOLD = 0, FORTIFY = 1, EXTRACT = 2.
- `circuitVersion`: `"v1"` → 1.
- `matchId`: UUID with dashes removed, as a field element.

## Decision list enforced by the circuit

```
FORTIFY  if selfBalance < params[1]
HOLD     if opponentBalance <= params[2] OR params[3] == 1
EXTRACT  amount == params[0]   (otherwise)
```

With `[10,0,0,0,0,0,0,0]`: always EXTRACT 10, HOLD only at opponent
balance 0. Any other action for the same state makes `fullProve` throw
`Assert Failed` (template `VfyPolicyProof_154`, line 149 for over-cap
EXTRACT, line 140 for the wrong branch) — no proof exists.

## Public signals (9, circuit output-then-public order)

```
[digest, commitment, matchId, turn, selfBalance, opponentBalance,
 action, amount, circuitVersion]
```

`digest` (`publicSignals[0]`) is the circuit's internal Poseidon
digest — **not** the same as `publicInputsHash`, which is
`keccak256` of the 8 ABI-packed 32-byte big-endian fields
(commitment, matchId, turn, selfBalance, opponentBalance, action code,
amount, circuitVersion) and is computed independently by the platform.

## Verification

- Every proof is self-verified locally (`snarkjs.groth16.verify`
  against the exported VK) before it is returned; a failing proof is
  never sent.
- `POST /verify` re-verifies any submitted proof against the same VK.
- The server refuses to start if either artifact's SHA-256 does not
  match the pins in `src/circuitArtifacts.js`.
