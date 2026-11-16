# Steal the VFY agent — zkVerify Agent Games, Season 01

A standalone Node.js agent for the **Steal the VFY** event. It receives a
signed turn envelope, picks an action with a fixed deterministic strategy,
and returns the action with a Groth16 policy proof (vfy-policy circuit,
generated locally with snarkjs) — plus, when configured, an on-chain
Kurier submission whose finalized tx hash is attached as
`policyProof.proofReference`.

> Status: built + tested locally. **NOT deployed, NOT registered, NOT
> submitted.** Remaining steps are listed at the bottom
> ("Deploy + register").

## Event recap (from the official pages, 2026-11-16)

- Two agents, **20 turns** per match, **100 VFY** starting balance each.
  Highest balance wins. Swiss (7 rounds) → Top 16 knockout.
- Schedule: **13–17 Nov 2026**. Turn deadline 5 min; the platform waits
  ~30 s per push. Missing the deadline substitutes HOLD (−1/turn).
  A response with a missing/invalid proof is −2/turn, resolved as HOLD.
- Match win +18, draw +9, loss +3, verified-turn reliability bonus +0..+2.
- Actions: **HOLD** (0 VFY, no transfer), **FORTIFY** (2 VFY, blocks up to
  6 VFY of incoming extraction this turn), **EXTRACT N** (0 VFY, steals
  up to N, max 10, from the opponent's spendable balance; a fortified
  opponent reduces the gain by 6). Both agents can EXTRACT simultaneously;
  the resolver uses prior public state only, never arrival order.
- Entry requirements: registered HTTPS endpoint, passing preflight,
  practice turn, and a **registered strategy commitment** (see below).
  One agent per owner; register mid-tournament to join from the next
  Swiss round, until the final round is paired.

## Strategy: always EXTRACT 10

`decideAction()` in `server.js` returns **EXTRACT 10 every turn**, and
**HOLD only when the opponent's balance is 0** (nothing left to take).

Why this wins turns — EXTRACT weakly dominates every other action in a
single-turn payoff (amounts in VFY, opponent's move across the top):

| we \ opp | HOLD | FORTIFY | EXTRACT 10 |
|---|---:|---:|---:|
| **EXTRACT 10** | **+10** | **+4** | **0** |
| FORTIFY | −2 | −2 | −6 |
| HOLD | 0 | 0 | −10 |

- EXTRACT is **free** and gains ≥ 0 in every matchup: +10 vs HOLD,
  +4 vs FORTIFY (10 − 6 blocked), 0 vs EXTRACT (both take 10 from each
  other when both have ≥ 10 exposed).
- FORTIFY costs 2 to block at most 6, so it only pays when the opponent
  extracts ≥ 8 — and even then EXTRACT nets 0 vs an extracting opponent
  while FORTIFY nets −6.
- HOLD gains 0 and gives the opponent a free extraction window.
- The only state where EXTRACT gains 0 is an opponent at 0 balance —
  hence HOLD there. This is not just the sensible choice: the circuit
  PROVES it (see "Circuit semantics" — at opponent balance 0,
  EXTRACT 10 fails the proof at line 140 and HOLD 0 proves).

A fortified opponent still yields up to 4 VFY to an extraction, so the
agent keeps extracting even when `opponentFortifiedUntilTurn >= turn`
(logged, not a reason to fortify).

### Backtest (`tools/backtest.js`)

`node tools/backtest.js` simulates the documented resolver over 20
turns against 7 opponent policies (plus a seeded random opponent,
20 seeds). Results (2026-11-16):

| opponent | final (us − them) | outcome | points |
|---|---:|---|---:|
| mirror (always EXTRACT 10) | 100 − 100 | DRAW | +9 |
| always HOLD | 200 − 0 | WIN | +18 |
| always FORTIFY | 164 − 0 | WIN | +18 |
| greedy (extract if ahead, else fortify) | 100 − 100 | DRAW | +9 |
| defensive (fortify if behind by >10) | 100 − 100 | DRAW | +9 |
| adaptive (fortify if behind by >20) | 100 − 100 | DRAW | +9 |
| tit-for-tat | 100 − 100 | DRAW | +9 |
| random (20 seeds) | 20/20 wins, worst 174 − 14 | WIN | +18.0 avg |

Mean across the 8 types: **12.4 / 18** match points. The strategy
**never loses** in simulation — and under the documented resolver
that is a theorem, not just an observation: every turn our gain ≥ the
opponent's gain (they gain 10 only when they extract, and then we gain
10 too; otherwise we gain 4–10 and they gain 0), and our fortify cost
is 0. So our balance never falls and theirs never rises: the final is
always us ≥ 100, them ≤ 100 — WIN or DRAW, never a loss. No action can
beat a mirroring extractor (vs an extracting opponent EXTRACT nets 0,
FORTIFY −6, HOLD −10), so the mirror draw is the ceiling, not a failure.

**Honest caveat.** If the field is mostly always-extract agents, most
matches are draws (+9) and the standings are decided by wins over
weaker agents PLUS the +0..+2 verified-turn reliability bonus — which
is why the Kurier on-chain `proofReference` matters: it is the
differentiator in a mirror-heavy field. The "never loses" claim also
rests on the documented resolver (fortify reduces the gain by 6);
even if fortify blocked ALL extraction, vs always-FORTIFY we would
still win 100−60 (they burn 2/turn, we lose 0).

## Strategy commitment

Before pairing, register the commitment in the dashboard:
**Dashboard → My Agents → Edit agent → Steal the VFY section.**
It commits a hash of the policy circuit; the platform freezes it when
matches are paired and rejects turns using a different circuit version.

> **What to register is NOT the vkHash.** The vfy-policy circuit
> proves `commitment == Poseidon(strategyParams ++ [salt])`
> (template line 72 — proven by FNV probing, see "Circuit semantics").
> Registering the vkHash
> (`0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047`)
> would make **every proof fail at line 72**. Register this instead:
>
> **`0x027f7cef3ba97234ac7e57b829a5e9e555c32b1f1f9416ed952589f07223d017`**
>
> = Poseidon([10, 0, 0, 0, 0, 0, 0, 0, 1]) — strategyParams
> `[10,0,0,0,0,0,0,0]` with the fixed salt `1`. The server's default
> `STEAL_COMMITMENT` is exactly this value (see `.env.example`).
> The salt is FIXED per strategy: changing it (or the params) after
> pairing invalidates every proof, because the frozen commitment no
> longer equals Poseidon(params, salt).

At runtime the server **always uses the commitment hash the platform
echoes back in each turn envelope** (`strategyCommitment.hash`) for the
proof inputs and for `publicInputsHash` — the local default is only a
fallback for envelopes that carry none. If the dashboard shows a
different expected format at registration time, stop and confirm it
there before pairing: the envelope value is authoritative, and the
registered value must be the Poseidon commitment above.

## Turn envelope (what the platform sends)

`POST /agent` (signed, HMAC over the raw body — see "Security").
Verbatim from the /build page (2026-11-16):

```json
{
  "protocolVersion": "v1",
  "eventId": "steal-the-vfy",
  "mode": "competition",
  "matchId": "9f4e1b2a-...",
  "turn": 3,
  "issuedAt": "<issued-at>",
  "deadlineAt": "<deadline-at>",
  "state": {
    "selfBalance": "95",
    "opponentBalance": "105",
    "selfFortifiedUntilTurn": null,
    "opponentFortifiedUntilTurn": null
  },
  "strategyCommitment": { "hash": "0x7d...91" },
  "resolverVersion": "v1",
  "nonce": "3c2f1a..."
}
```

Note: balances arrive as **strings** (`"95"`), fortification fields
are `null` when not fortified, and `turn` is a number. The server
accepts all of these; an invalid matchId (not a real UUID) fails
closed to HOLD.

## Response (what the agent returns)

Verbatim shape from the /build page (2026-11-16):

```json
{
  "matchId": "9f4e1b2a-...",
  "turn": 3,
  "action": { "type": "EXTRACT", "amount": 5 },
  "policyProof": {
    "circuitVersion": "v1",
    "proof": { "pi_a": ["...", "...", "1"], "pi_b": [["...", "..."], ["...", "..."], ["1", "0"]], "pi_c": ["...", "...", "1"], "protocol": "groth16", "curve": "bn128" },
    "public_signals": ["...", "...", "..."],
    "proofReference": "0xa8...2c",
    "publicInputsHash": "0x..."
  },
  "agentTimestamp": "<agent-timestamp>",
  "idempotencyKey": "a1b2c3d4-..."
}
```

Rules from the /build "Common mistakes" list, all enforced by the
server and the harness:

- `proof` and `public_signals` sit **INSIDE** `policyProof`, never at
  the top level; `public_signals` are the circuit's output-then-public
  order (snarkjs returns them that way).
- `action.amount` is sent **ONLY for EXTRACT** and omitted entirely
  for HOLD/FORTIFY — the schema rejects the field even when it is 0.
  (The *circuit* input still uses amount 0 for HOLD/FORTIFY, and the
  hash below still hashes amount 0 — only the response field is omitted.)
- `action.type` is the uppercase string (`"EXTRACT"` / `"HOLD"` /
  `"FORTIFY"`), per the official response example.
- `idempotencyKey` is unique per (matchId, turn): `${matchId}:${turn}`.
- `proofReference` and `publicInputsHash` are optional audit pointers
  inside `policyProof`. The platform verifies the actual Groth16 proof
  + public_signals; a correct hash alone does not pass a turn.

`publicInputsHash` = keccak256 of ABI-packed 32-byte big-endian fields,
in order: commitment (`strategyCommitment.hash`), matchId (UUID with
dashes stripped, as a 128-bit integer), turn, selfBalance,
opponentBalance, action enum (HOLD 0 / FORTIFY 1 / EXTRACT 2), amount
(0 for HOLD/FORTIFY), circuitVersion 1. This is verbatim from the
/build TypeScript snippet (`concat` + `numberToHex(..., {size: 32})`
from viem); the server computes it with ethers `AbiCoder`
(`uint256[8]`) — see `computePublicInputsHash()`. Two independent
computations (AbiCoder vs manual hex concat) agree on the test vector
(turn 3, 95/105, EXTRACT 10, commitment 0x027f...):
`0x35030521c72b8eeb874a43269c7c3bd07b42a2d27ba5c93a00a5294cc7c4c552`
— asserted by `test/harness.js --prove`.

### Kurier (on-chain proof submission, optional)

After generating the local proof, the server submits it to Kurier
(`POST /submit-proof/{key}`, `proofType: groth16`,
`vkRegistered: true` + the vfy-policy vkHash, fallback full VK) and
polls `job-status` every 3 s until Finalized/Failed or the budget
runs out. On Finalized with a tx hash, `policyProof.proofReference`
is set to that hash — the audit pointer the platform links to the
match replay and proof record, and the best shot at the +0..+2
verified-turn reliability bonus. The pattern mirrors the Gatekeeper
agent (commit 596ac6b), adapted for Steal: the budget is 15 s
(`KURIER_POLL_BUDGET_MS`), capped so the answer still lands inside
the 25 s answer budget and the ~30 s push window. **Fail-soft:** any
Kurier failure leaves the response exactly as it was (action + local
proof, which still verifies offline against the platform key).
Without `KURIER_API_KEY` the feature is off entirely. Tested with a
mock Kurier (`test/kurier-mock.js`, 10/10): happy path sets the
reference in 5.6 s; Kurier-down and Kurier-500 both answer with the
local proof, no reference, inside budget.

Duplicate pushes of the same turn are answered from an in-memory cache:
the response is deterministic per (matchId, turn), so a retry replays
the identical response (same action, same proof).

## Security

- HMAC-SHA256 is verified over the **raw** request body before any JSON
  parsing, against header `x-agent-games-signature`. Mismatch → 401.
- Every response is signed the same way over the raw response body.
- The HMAC secret comes only from env `AGENT_GAMES_HMAC_SECRET`
  (dashboard → Rotate Secret). It is never logged.
- Fail closed: malformed envelope, past deadline, or any error →
  HOLD. If proof generation fails, the action is still answered
  without a proof (a proof-less response costs −2 and resolves as
  HOLD; a missing answer forfeits the turn and risks the agent's
  health record, so a signed answer is always returned).
- The server binds to `0.0.0.0:$PORT` (default 8080) and serves
  `GET /health` → `{ ok: true, protocolVersion: "v1", proofMode }`
  and `POST /agent` only.

## Circuit inputs

Recovered from `circuits/vfy-policy.wasm` by FNV-hash probing
(`tools/probe-signals.js`): **17 inputs** (witness size 1909,
template `VfyPolicyProof_154`), **9 public signals** (VK exported
from the zkey, `nPublic = 9`).

| # | input | type | encoding (proven) |
|---|---|---|---|
| 1 | `commitment` | public | `BigInt(0x hash) mod FIELD_PRIME`; must equal `Poseidon(strategyParams ++ [salt])` |
| 2 | `matchId` | public | `BigInt("0x" + uuid without dashes) mod FIELD_PRIME` |
| 3 | `turnNumber` | public | `BigInt(decimal)` |
| 4 | `selfBalance` | public | `BigInt(decimal)` |
| 5 | `opponentBalance` | public | `BigInt(decimal)` |
| 6 | `action` | public | enum: HOLD 0, FORTIFY 1, EXTRACT 2 |
| 7 | `amount` | public | `BigInt(decimal)`; 0 for HOLD/FORTIFY |
| 8 | `circuitVersion` | public | `1` |
| 9 | `salt` | private | FIXED `1` (env `STEAL_SALT`) — the value bound into the registered commitment |
| 10–17 | `strategyParams[0..7]` | private | `[10,0,0,0,0,0,0,0]` (env `STRATEGY_PARAMS`) |

Public signals (snarkjs order, output-then-public):
`[output, commitment, matchId, turnNumber, selfBalance,
opponentBalance, action, amount, circuitVersion]`.
The output signal is **`Poseidon(matchId, turnNumber, circuitVersion)`**
— proven 2026-11-16 (matches all three observed outputs: turn 1,
turn 20, and a real UUID matchId; 21 other Poseidon candidates ruled
out first). It binds the proof to its match and turn, exactly as the
events page says ("each proof is tied to its match and turn number,
so a proof can't be reused"). The harness asserts this equality on
every `--prove` run.

## Circuit semantics

What the template actually checks, in order (line numbers from the
`fullProve` error messages; each finding was proven by a decisive
trial, not inferred):

- **Line 38 — params range check.** `strategyParams[0]=100` fails
  here (too large). Params must be small; `[10,0,0,0,0,0,0,0]` passes.
- **Line 72 — commitment binding.** `commitment ==
  Poseidon(strategyParams ++ [salt])`. Arbitrary commitments (0, 1,
  12345, the vkHash) fail here in a 24-combination sweep (0/24); the
  Poseidon value passes. This is why the registered commitment must be
  the Poseidon value, not the vkHash.
- **Line 75 / 78 — further params checks.** `strategyParams =
  [1,2,3,4,5,6,7,8]` fails at 75; `[0,0,0,0,0,0,0,1]` fails at 78.
  The exact rules are NOT yet known — but all-zero `params[1..7]`
  pass, so the proven configuration is safe. (See "Uncertainties".)
- **Line 90 — `params[0] > 0`.** All-zero params fail here for every
  action/amount tried; `params[0]=10` and `params[0]=1` pass. The
  extract amount must be positive.
- **Line 140 — wrong action.** With `params[0]=10`, HOLD 0 fails
  here (the strategy prescribes EXTRACT) — including at opponent
  balance 0, where EXTRACT also fails. The only provable action at
  opponent balance 0 is HOLD (see below).
- **Line 149 — wrong amount.** With `params[0]=1`, EXTRACT 10 fails
  here (the prescribed amount is 1); with `params[0]=10`, EXTRACT 3
  fails here. **The amount must equal `params[0]` exactly** — the
  server never caps the amount at the opponent's balance (an earlier
  draft did; the probe killed it). The resolver caps the gain.

Decisive trials (all with `params=[10,0,0,0,0,0,0,0]`, salt 1,
commitment Poseidon — each proof verified against the VK):

| trial | result |
|---|---|
| EXTRACT 10, turn 1, 100/100 | VALID |
| EXTRACT 10, turn 20, 100/100 | VALID |
| EXTRACT 10, turn 1, 50/150 and 150/50 | VALID |
| EXTRACT 10, turn 1, 100/3 (opponent low) | VALID — circuit does NOT check amount ≤ opponent balance |
| EXTRACT 3, turn 1, 100/3 (capped) | FAIL line 149 |
| EXTRACT 10, turn 1, 100/0 (opponent zero) | FAIL line 140 |
| HOLD 0, turn 1, 100/0 (opponent zero) | VALID |
| EXTRACT 10, turn 1, 5/5 | VALID |
| EXTRACT 10, turn 3, 95/105, real UUID matchId | VALID |

So the circuit's policy is: **EXTRACT exactly `params[0]` (10) —
except when the opponent is at 0, where HOLD is prescribed.** The
server implements exactly that, and nothing else.

## Run it

```bash
npm install            # deps: ethers, snarkjs; dev: circomlibjs (harness Poseidon check)
cp .env.example .env   # set AGENT_GAMES_HMAC_SECRET (and KURIER_API_KEY to enable Kurier)
node server.js         # PORT=8080 PROOF_MODE=prove (default)
```

Tests (all must be green before any deploy):

```bash
node test/harness.js           # stub mode: 21 checks, decisions + auth + response shape
node test/harness.js --prove   # 30 checks: + real proofs, VK verification, signal vectors, hash vector
node test/kurier-mock.js       # 10 checks: Kurier happy path + fail-soft (mock, no real key)
node tools/backtest.js         # strategy simulation vs 7 opponent policies + random (20 seeds)
```

Latest results (2026-11-16 23:34 WIB): harness stub **21/21**, harness
--prove **30/30** (every proof verifies against the VK exported from
the zkey; public-signals vectors match exactly; publicInputsHash
matches the independent computation), kurier-mock **10/10** (worst
answer 5.6 s of the 25 s budget), backtest **never loses** (see table
above).

## Uncertainties (honest list — nothing hidden)

1. **Whether the platform awards the +0..+2 reliability bonus only
   for on-chain-finalized proofs.** The Gatekeeper track showed a
   proof counts as verified only once submitted via Kurier and
   Finalized (correct decisions scored +10, not +12, with 0 verified
   proofs). For Steal the score model lists the reliability bonus
   separately from the match outcome, and the /build page calls
   `proofReference` "optional audit pointers only — accepted but NOT
   used for verification". The Kurier integration is the best shot at
   the bonus, and it can only help (fail-soft); but the exact mapping
   is platform-side and unconfirmed until a live practice turn.
2. **`strategyParams[1..7]` meanings and the line 75/78 rules.**
   All zeros pass; nonzero values trip checks we have not fully
   mapped. Irrelevant to this build (we use zeros), but a future
   adaptive strategy (e.g. different amounts per state) would need
   that mapping first — do not guess it.
3. **`publicInputsHash` divergence check.** The field order is
   verbatim from the official TypeScript snippet and two independent
   computations agree, but the platform "independently computes this
   hash from the game state it knows and rejects any proof where the
   hashes diverge" — that rejection can only be observed on a live
   practice turn, which requires deployment + registration.
4. **No live round has been played yet.** Everything above is local
   proof: the server has never received a real turn envelope, and the
   dashboard preflight + practice turn are the first live checks
   (see "Deploy + register").

## Deploy + register (NOT done — remaining steps)

1. **Push to GitHub** (public repo, e.g. `cervus-snoopy/agent-games-steal-vfy`)
   or deploy the `server.js` + `circuits/` + `package.json` as-is.
2. **Deploy to Railway** (same pattern as the Gatekeeper agent):
   project → service from the repo, start command `node server.js`,
   env vars `AGENT_GAMES_HMAC_SECRET` (from the dashboard Rotate Secret
   for this agent — the Gatekeeper secret is a *different* agent's secret
   and must NOT be reused), `PROOF_MODE=prove`, and `KURIER_API_KEY`
   (the Kurier Mainnet "Server" key, stored mode 600 at
   `~/workspace/agent-games/.kurier-api-key` — copy its value, never
   print or commit it). Generate a public domain, manual Redeploy
   (GitHub pushes do not auto-redeploy). Verify:
   `GET https://<domain>/health` → `{ ok: true, ... }` and a signed
   preflight `POST /agent` → `{ ok: true, protocolVersion: "v1" }`.
3. **Register the agent** in the Agent Games dashboard (My Agents →
   Add agent): name `hi5-steal` (or `hi5`), events `["Steal the VFY"]`,
   repo URL, endpoint `https://<domain>/agent`.
4. **Register the strategy commitment** (Dashboard → My Agents →
   Edit agent → Steal the VFY section) with the Poseidon commitment
   **`0x027f7cef3ba97234ac7e57b829a5e9e555c32b1f1f9416ed952589f07223d017`**,
   **before pairing**. NOT the vkHash. Keep `STRATEGY_PARAMS`
   (`10,0,0,0,0,0,0,0`) and `STEAL_SALT` (`1`) identical to the
   deployed server. Register mid-tournament to join from the next
   Swiss round (rounds run through 17 Nov 2026).
5. **Preflight** from the dashboard until Healthy, then run a
   **practice turn** and confirm `proofStatus: verified` — and, with
   Kurier configured, that the server log shows `kurier Finalized`
   and the response carries a `proofReference`.
6. Watch the scored rounds. Between rounds only for redeploys or
   commitment changes — the commitment is frozen mid-match.
