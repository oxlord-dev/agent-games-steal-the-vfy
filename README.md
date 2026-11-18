# Steal the VFY — every move provably bound to a pre-committed strategy

A Node agent for the **Steal the VFY** track of zkVerify Agent Games
Season 01, for `@joesscrypto` (GitHub `oxlord-dev`).

**Commit once, prove every move.** Every turn carries a Groth16 proof
(BN128, official `vfy-policy` circuit) that the move follows the strategy
committed to before pairing. A wrong move has no proof at all — the
circuit refuses, and the agent answers HOLD.

> This repo is **separate** from the Proof Gatekeeper agent (different
> repo, different endpoint, different HMAC secret, different commitment).
> One agent per event, as the platform requires.

## Status (local build, 2026-11-18)

| Check | Result |
|---|---|
| `npm run commitment` | Commitment generated, EXTRACT + HOLD branches prove |
| `npm test` (no live proofs) | **19/19 pass** |
| `npm run test:live` (real proofs) | **8/8 pass** |
| `npm run demo` (20-turn match) | **20/20 proved + locally verified, US WIN 168–28** |
| `npm run demo:refusal` | **3/3 out-of-policy moves refused by the circuit** |
| Independent proof check | `snarkjs groth16 verify` CLI: **OK** |
| Deploy / dashboard registration | **NOT done** — code + local tests only, by design |

## Strategy

Params `[10, 0, 0, 0, 0, 0, 0, 0]` — **always EXTRACT 10**, except HOLD
when the opponent's balance is 0. The circuit's decision list enforces
it:

1. FORTIFY when `selfBalance < params[1]` (unreachable: `params[1] = 0`)
2. else HOLD when `opponentBalance <= params[2]` OR `params[3] == 1`
3. else EXTRACT with `amount == params[0]` exactly

Commitment (public — register this hash in the dashboard before pairing):

```
STRATEGY_PARAMS=[10,0,0,0,0,0,0,0]
STRATEGY_COMMITMENT_HASH=0x12524fdc3dc2d0437d9d1acd2fd7a2c62be2c95f4e624999b1eafe297ffb0240
```

The salt is secret: it lives only in gitignored `.env.strategy`
(mode 0600) on the build machine. Never paste it anywhere.

## Proof timing (this VM, Node 24)

| Measurement | Time |
|---|---|
| First proof in a process (incl. WASM load) | ~1,300–1,500 ms |
| Steady-state proof per turn | ~520–720 ms |
| Demo match, 20 turns | 12,658 ms total, avg 633 ms, median 589 ms, max 1,355 ms |
| Turn deadline | 5 min (platform waits ~30 s per push) |

Huge margin: proof time is ~2% of the platform's per-push wait.

## Run it locally

```bash
npm install
npm run commitment   # fresh salt + commitment -> .env.strategy (0600)
npm test             # 19 unit/HTTP tests, no live proofs
npm run test:live    # 8 live-proof tests (real Groth16 proofs)
npm run demo         # 20-turn simulated match, 20/20 proved
npm run demo:refusal # 3/3 refusals + retry + tampered-commitment checks
npm start            # long-lived server on $PORT (default 3000)
```

`.env` (local, gitignored) currently holds only a **dummy** HMAC secret
for tests. For a real run, set the real values (see below).

## Deploy

This is a **long-lived Node server** (not serverless-only), so it runs
identically on a VPS and on Railway. No step below has been run yet —
hosting (VPS vs Railway) is still undecided.

### Option A — VPS (Docker)

```bash
docker build -t steal-the-vfy .
docker run -d --name steal-the-vfy --restart unless-stopped \
  -p 3000:3000 \
  -e AGENT_GAMES_HMAC_SECRET='<from dashboard Rotate Secret>' \
  -e STRATEGY_PARAMS='[10,0,0,0,0,0,0,0]' \
  -e STRATEGY_SALT='<from .env.strategy — copy by hand, never commit>' \
  -e STRATEGY_COMMITMENT_HASH='0x12524fdc3dc2d0437d9d1acd2fd7a2c62be2c95f4e624999b1eafe297ffb0240' \
  -e KURIER_API_KEY='<optional, Kurier mainnet key>' \
  -e IDEMPOTENCY_STORE_PATH='/data/idempotency.json' \
  -v /data:/data \
  steal-the-vfy
# Put it behind HTTPS (Caddy/nginx + TLS) and register https://<host>/agent
```

### Option B — Railway

1. Push this repo to GitHub (`oxlord-dev`), connect it in Railway.
2. `railway.json` already sets the Dockerfile builder + `/health` check.
3. Set the same env vars as above in Railway Variables (copy the three
   strategy values from `.env.strategy` by hand).
4. Railway gives a public HTTPS domain; register `https://<host>/agent`.

### After deploy (dashboard, not done yet)

1. Register the agent: name + track (Steal the VFY) + public GitHub repo
   URL + endpoint `https://<host>/agent`.
2. Copy the platform-issued HMAC secret (Rotate Secret, shown once)
   into `AGENT_GAMES_HMAC_SECRET` and redeploy/restart.
3. Health check must pass, then signed preflight + at least one
   practice turn.
4. Register the strategy commitment hash above **before the next Swiss
   pairing** (R6; R5 was current on 18 Nov 07:54 WIB). The commitment
   is frozen mid-match — changing params later needs a fresh salt +
   commitment + re-registration before the following pairing.

## Environment variables

| Var | Required | Notes |
|---|---|---|
| `AGENT_GAMES_HMAC_SECRET` | Yes (deploy) | Dashboard Rotate Secret; dummy locally |
| `STRATEGY_PARAMS` | Yes | `[10,0,0,0,0,0,0,0]` |
| `STRATEGY_SALT` | Yes | From `.env.strategy`, secret |
| `STRATEGY_COMMITMENT_HASH` | Yes | `0x12524fdc…ff0240` |
| `KURIER_API_KEY` | No | Kurier mainnet key; empty = proofs self-verified only, submitted nowhere |
| `KURIER_API_URL` | No | Default `https://api.kurier.xyz/api/v1` |
| `CIRCUIT_VERSION` | No | Default `v1` — must match the registered commitment |
| `VK_HASH` | No | Default `0x6c56509f…be047` (vfy-policy, from `/api/circuit-info`) |
| `PROOF_ENABLED` | No | Default `true`; `false` = answer without proof (scored as HOLD) |
| `IDEMPOTENCY_STORE_PATH` | No | e.g. `/data/idempotency.json` on a host with a volume |
| `PORT` | No | Default `3000` |

## How it works

- `POST /agent` — signed turn endpoint. HMAC-SHA256 verified against
  the **raw body** before parsing; every response is signed the same way.
  Preflight `{type:"agent-games.preflight.v1", …}` → exactly
  `{ok:true, protocolVersion:"v1"}` (stale/future `issued_at` > 5 min → 401).
  Unsigned / bad-signature requests → 401, fail-closed.
- `src/turn.js` — decides the action from the circuit's decision list,
  computes `publicInputsHash` (keccak256 of 8 ABI-packed 32-byte fields),
  generates + self-verifies the Groth16 proof, and returns it **inside**
  `policyProof` (`proof` + `publicSignals`, 9 signals in circuit order).
  `action.amount` is present **only** for EXTRACT — omitted entirely for
  HOLD/FORTIFY. Retries with the same `idempotencyKey` return the
  identical cached response (in-memory + optional atomic JSON mirror at
  `IDEMPOTENCY_STORE_PATH`).
- Fail-closed: commitment mismatch, expired `deadlineAt`, invalid
  envelope, or a proof the circuit refuses (e.g. EXTRACT 11, or EXTRACT
  when the strategy says HOLD) → **HOLD with no proof**. A proof is
  never invented.
- Kurier submission is fire-and-forget in the background and never
  blocks the turn response. With no `KURIER_API_KEY` it is skipped.
- `GET /health`, `GET /agent` (usage), `GET /demo-turn` (one fresh
  real turn-1 proof), `POST /verify` (verify any proof against the
  official VK), `GET /proof-status/:jobId`.

## What's in this repo

```
src/            config, hmac, poseidon, strategyParams, strategy,
                publicInputsHash, circuitInputs, proof, store,
                circuitArtifacts, turn, server, index
scripts/        commitment.cjs, demo-match.cjs, demo-refusal.cjs
test/           agent.test.js (19), live.test.js (8)
circuits/       vfy-policy.wasm + vfy-policy_final.zkey (official,
                SHA-256 pinned), verification_key.json, circuit-info.json
Dockerfile      node:24-alpine, long-lived server
railway.json    Dockerfile builder, /health check, 1 replica
```

## Honest limits / unknowns

- **Not deployed, not registered.** No endpoint, no platform HMAC
  secret, no Kurier key, and the commitment hash above has **not**
  been entered in the dashboard yet.
- The exact dashboard field/format for the strategy commitment was
  **not visible yet** (it appears after agent registration + health
  check, before pairing) — verify the field name/format at that step
  and paste the hash above verbatim.
- The demo match uses a **simulated** resolver (documented assumptions
  in `scripts/demo-match.cjs`); the platform resolver is authoritative
  in real matches. Balances/fortify flags always come from the turn
  envelope — the agent keeps no game state of its own.
- Kurier Finalized verification has not been exercised (no API key);
  proofs are self-verified locally against the official VK, and one
  proof was additionally verified with the standalone `snarkjs` CLI.

## References

- https://agentgames.zkverify.io/build
- https://agentgames.zkverify.io/events/steal-the-vfy
- https://github.com/JM-03/agent-games-steal-the-vfy (reference
  implementation — strategy/turn/proof/circuit-input logic adapted,
  rewritten here in plain JS for this agent; not a copy of the repo)
