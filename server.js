/**
 * Steal the VFY agent — zkVerify Agent Games, Season 01.
 *
 * Plain Node.js (no framework). Listens for POSTs on /agent:
 *   - type "agent-games.preflight.v1" -> { ok: true, protocolVersion: "v1" }
 *   - Steal turn envelope (eventId "steal-the-vfy", matchId + turn + state)
 *     -> action + Groth16 policy proof (vfy-policy circuit)
 *
 * Contract (verified from https://agentgames.zkverify.io/build,
 * /events/steal-the-vfy and /api/circuit-info, 2026-11-16):
 *   - HMAC-SHA256 verified over the RAW request body BEFORE any JSON
 *     parsing, against header `x-agent-games-signature`. Mismatch -> 401.
 *   - Every response is signed with the same HMAC over the raw response
 *     body, returned in `x-agent-games-signature`.
 *   - Turn envelope: { protocolVersion:"v1", eventId:"steal-the-vfy",
 *     mode, matchId (UUID), turn (1..20), issuedAt, deadlineAt,
 *     state:{ selfBalance, opponentBalance, selfFortifiedUntilTurn,
 *     opponentFortifiedUntilTurn }, strategyCommitment:{ hash },
 *     resolverVersion:"v1", nonce }.
 *   - Response: { matchId, turn, action:{ type, amount },
 *     policyProof:{ circuitVersion:"v1", proof, public_signals,
 *     publicInputsHash }, agentTimestamp, idempotencyKey }.
 *     proofReference is optional and omitted (audit pointer only).
 *   - publicInputsHash = keccak256 of ABI-packed 32-byte big-endian
 *     fields, in order: commitment (strategyCommitment.hash), matchId
 *     (UUID with dashes stripped, as a 128-bit integer), turn,
 *     selfBalance, opponentBalance, action enum (HOLD 0 / FORTIFY 1 /
 *     EXTRACT 2), amount (0 for HOLD/FORTIFY), circuitVersion 1.
 *   - Actions: HOLD 0 VFY (no transfer); FORTIFY 2 VFY (blocks up to
 *     6 VFY of incoming extraction this turn); EXTRACT N 0 VFY (steals
 *     up to N, max 10, from the opponent's spendable balance; a
 *     fortified opponent reduces the gain by 6). Start 100 VFY each.
 *   - Turn deadline 5 min; the platform waits ~30 s per push. Missing
 *     the deadline substitutes HOLD with a -1 timeout penalty; a
 *     response with a missing/invalid proof is -2 and resolved as HOLD.
 *   - Strategy commitment: register BEFORE pairing, Dashboard ->
 *     My Agents -> Edit agent (Steal the VFY section). It commits a
 *     hash of the policy circuit; the platform freezes it when matches
 *     are paired and rejects turns using a different circuit version.
 *     The envelope echoes the frozen hash back each turn as
 *     strategyCommitment.hash — the server uses THAT value (never a
 *     stale local copy) for the proof inputs and the publicInputsHash.
 *     !!! THE COMMITMENT IS NOT THE vkHash !!! The vfy-policy circuit
 *     proves commitment == Poseidon(strategyParams ++ [salt]) (line 72
 *     of the template, proven by FNV probing 2026-11-16). So the value
 *     to register is Poseidon([10,0,0,0,0,0,0,0, 1]) =
 *     0x027f7cef3ba97234ac7e57b829a5e9e555c32b1f1f9416ed952589f07223d017
 *     (params [10,0,0,0,0,0,0,0], salt 1). Registering the vkHash
 *     instead makes every proof fail at line 72. The salt is FIXED
 *     (env STEAL_SALT, default 1) — a per-match salt would change the
 *     commitment every turn and break the frozen registration.
 *   - The HMAC secret comes ONLY from env AGENT_GAMES_HMAC_SECRET
 *     (dashboard -> Rotate Secret). No secret is ever logged.
 *   - Fail closed: on any error / malformed envelope / past deadline,
 *     answer HOLD (decision-only if no proof can be produced). A
 *     proof-less response costs -2; a missing answer forfeits the turn
 *     and risks the agent's health record, so a signed answer is
 *     always returned when the request itself was authenticated.
 *
 * Proof generation (snarkjs, local, Groth16/BN128, Circom 2.x):
 *   Circuit inputs were recovered from circuits/vfy-policy.wasm by
 *   FNV-hash probing (see tools/probe-signals.js). All 17 inputs:
 *     commitment, matchId, turnNumber, selfBalance, opponentBalance,
 *     action, amount, circuitVersion, salt (9 scalars) and
 *     strategyParams[0..7] (8 elements).
 *   Verification key: circuits/vfy-policy_final.zkey, vkHash
 *     0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047
 *   The public signals are reported by snarkjs with the proof
 *   (see tools/probe-circuit.js for the empirically observed order).
 *
 *   !!! ENCODING — PROVEN BY FNV PROBING, 2026-11-16 (tools/probe-*.js) !!!
 *   The platform never published how the 256-bit commitment hash, the
 *   UUID matchId, or the strategyParams are encoded as field elements,
 *   nor what the 8 strategyParams mean. The mapping in
 *   buildCircuitInput() is now PROVEN locally (proof verifies against
 *   the VK exported from the zkey, 10/10 decisive trials):
 *     - commitment: BigInt(0x hash) mod FIELD_PRIME. MUST equal
 *       Poseidon(strategyParams ++ [salt]) — template line 72.
 *     - matchId: BigInt("0x" + uuid without dashes) mod FIELD_PRIME.
 *     - integers (turnNumber, balances, action, amount,
 *       circuitVersion): BigInt(decimal).
 *     - action enum: HOLD 0, FORTIFY 1, EXTRACT 2.
 *     - salt: FIXED (env STEAL_SALT, default 1) — the same value
 *       bound into the registered commitment. NEVER per-match.
 *     - strategyParams: [10,0,0,0,0,0,0,0] (env STRATEGY_PARAMS).
 *       params[0] is the prescribed EXTRACT amount: the circuit
 *       demands amount == params[0] EXACTLY (line 149) and
 *       params[0] > 0 (line 90). params[1..7] are all zero in the
 *       proven configuration; their individual meanings are NOT yet
 *       known (see README "Circuit semantics" for the partial map:
 *       line 38 = params range check, line 75/78 = params checks
 *       that nonzero params[1..7] can trip). Zeros are safe.
 *   State-dependent action rule (proven): with params[0]=10,
 *   EXTRACT 10 proves at every tested state (turns 1 and 20;
 *   balances 100/100, 50/150, 150/50, 100/3, 5/5; real UUID
 *   matchId) — the circuit does NOT check amount <= opponent
 *   balance; the resolver caps the gain. BUT at opponentBalance 0,
 *   EXTRACT 10 FAILS (line 140) and HOLD 0 PROVES — so the agent
 *   HOLDs exactly there, and only there.
 *   Public signals order (snarkjs, verified): [output, commitment,
 *   matchId, turnNumber, selfBalance, opponentBalance, action,
 *   amount, circuitVersion] — output-then-public, as the build
 *   guide requires. The output signal is Poseidon(matchId,
 *   turnNumber, circuitVersion) — proven 2026-11-16 (matches all
 *   three observed outputs: turn 1, turn 20, and a real UUID
 *   matchId; 21 other Poseidon candidates ruled out first). It
 *   binds the proof to its match and turn, exactly as the events
 *   page says ("each proof is tied to its match and turn number, so
 *   a proof can't be reused"). The harness asserts this equality on
 *   every --prove run.
 *   disables proof generation entirely (action-only responses) while
 *   that is investigated. NEVER send a fabricated proof.
 *
 * Strategy (see README for the full argument + backtest):
 *   EXTRACT 10 every turn, HOLD only when the opponent has nothing
 *   left to take. EXTRACT is free and gains >= 0 in every matchup,
 *   so it weakly dominates HOLD (gains 0) and FORTIFY (costs 2 to
 *   block at most 6): vs an extracting opponent EXTRACT nets 0 while
 *   FORTIFY nets -6 and HOLD nets -10; vs a holding opponent EXTRACT
 *   nets +10; vs a fortifying opponent EXTRACT nets +4. Backtest
 *   (tools/backtest.js): always-EXTRACT-10 wins or draws every
 *   simulated match vs 7 opponent policies (details in README).
 *
 * Response shape (build guide, "Common mistakes" — verified
 * 2026-11-16): proof + public_signals sit INSIDE policyProof;
 * action.amount is sent ONLY for EXTRACT and omitted entirely for
 * HOLD/FORTIFY (the schema rejects the field even when it is 0);
 * idempotencyKey is unique per (matchId, turn).
 *
 * Usage:
 *   AGENT_GAMES_HMAC_SECRET=<from dashboard Rotate Secret> node server.js
 *   PORT=8080 PROOF_MODE=prove node server.js   (default: prove)
 *   PORT=8080 PROOF_MODE=stub  node server.js   (action only, no proof)
 */

'use strict';

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ---------------------------------------------------------------- env ----
function loadEnvFile(file) {
  try {
    const lines = fs.readFileSync(file, 'utf8').split('\n');
    for (const line of lines) {
      const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
      if (m && process.env[m[1]] === undefined) {
        process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
      }
    }
  } catch (_) { /* .env is optional */ }
}
loadEnvFile(path.join(__dirname, '.env'));

const PORT = parseInt(process.env.PORT || '8080', 10);
const HMAC_SECRET = process.env.AGENT_GAMES_HMAC_SECRET || '';
const PROOF_MODE = (process.env.PROOF_MODE || 'prove').toLowerCase();
const PROOF_BUDGET_MS = parseInt(process.env.PROOF_BUDGET_MS || '20000', 10);
// The platform waits ~30 s per push; answer well inside that.
const ANSWER_BUDGET_MS = parseInt(process.env.ANSWER_BUDGET_MS || '25000', 10);
// Kurier on-chain submission (optional, env KURIER_API_KEY). Absent a key
// the agent answers with the local proof only (same as before). When set,
// the proof is submitted to Kurier after generation and, on Finalized,
// policyProof.proofReference is set to the on-chain tx hash — the audit
// pointer the platform links to the match replay and proof record.
// Budget is capped so the answer still lands inside ANSWER_BUDGET_MS.
const KURIER_API_KEY = (process.env.KURIER_API_KEY || '').trim();
const KURIER_BASE = (process.env.KURIER_BASE || 'https://api.kurier.xyz/api/v1').replace(/\/+$/, '');
const KURIER_POLL_BUDGET_MS = parseInt(process.env.KURIER_POLL_BUDGET_MS || '15000', 10);

const WASM_PATH = path.join(__dirname, 'circuits', 'vfy-policy.wasm');
const ZKEY_PATH = path.join(__dirname, 'circuits', 'vfy-policy_final.zkey');

// BN128 scalar field prime (also the field of the vfy-policy circuit).
const FIELD_PRIME = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');
// Platform-registered vfy-policy verification-key hash (from /api/circuit-info).
const PLATFORM_VK_HASH = '0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047';
// Default commitment: Poseidon(strategyParams ++ [salt]) with the default
// params [10,0,0,0,0,0,0,0] and the fixed salt 1 — the value that MUST be
// registered on the dashboard (see the header comment). NOT the vkHash:
// the circuit proves commitment == Poseidon(params, salt), so registering
// the vkHash makes every proof fail at template line 72. The envelope's
// echoed hash always wins over this default when present.
const DEFAULT_COMMITMENT = (process.env.STEAL_COMMITMENT ||
  '0x027f7cef3ba97234ac7e57b829a5e9e555c32b1f1f9416ed952589f07223d017').trim().toLowerCase();
// Fixed salt for the commitment binding (env STEAL_SALT, default 1).
// The salt MUST be the same value used to compute the registered
// commitment; a per-match salt would break the frozen registration.
const STEAL_SALT = (process.env.STEAL_SALT || '1').trim();

const STRATEGY_PARAMS = (() => {
  const raw = (process.env.STRATEGY_PARAMS || '10,0,0,0,0,0,0,0').trim();
  const parts = raw.split(',').map((s) => s.trim());
  if (parts.length !== 8 || parts.some((p) => !/^\d+$/.test(p))) {
    throw new Error('STRATEGY_PARAMS must be 8 comma-separated integers');
  }
  return parts;
})();

const ACTIONS = { HOLD: 0, FORTIFY: 1, EXTRACT: 2 };
const ACTION_NAMES = ['HOLD', 'FORTIFY', 'EXTRACT'];
const MAX_EXTRACT = 10;
const FORTIFY_COST = 2;
const FORTIFY_BLOCK = 6;
const MAX_TURNS = 20;

if (!HMAC_SECRET) {
  console.error('[steal] FATAL: AGENT_GAMES_HMAC_SECRET is not set. ' +
    'Get it from the Agent Games dashboard (Rotate Secret) and put it in .env. Refusing to start.');
  process.exit(1);
}
if (PROOF_MODE !== 'prove' && PROOF_MODE !== 'stub') {
  console.error('[steal] FATAL: PROOF_MODE must be "prove" or "stub".');
  process.exit(1);
}
if (PROOF_MODE === 'prove' && (!fs.existsSync(WASM_PATH) || !fs.existsSync(ZKEY_PATH))) {
  console.error('[steal] FATAL: circuit artifacts missing under circuits/. ' +
    'Download vfy-policy.wasm and vfy-policy_final.zkey first (see README).');
  process.exit(1);
}
if (!/^0x[0-9a-f]{64}$/.test(DEFAULT_COMMITMENT)) {
  console.error('[steal] FATAL: STEAL_COMMITMENT must be a 0x 32-byte hash.');
  process.exit(1);
}

// ------------------------------------------------------------ HMAC utils --
function hmacHex(secret, bodyBuffer) {
  return crypto.createHmac('sha256', secret).update(bodyBuffer).digest('hex');
}

/** Accept a plain hex signature, or a "sha256=<hex>" prefixed one. */
function normalizeSignature(headerValue) {
  if (!headerValue) return '';
  return headerValue.replace(/^sha256=/i, '').trim().toLowerCase();
}

function signaturesMatch(expectedHex, providedHeader) {
  const provided = normalizeSignature(providedHeader);
  if (!provided || provided.length !== expectedHex.length) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(expectedHex, 'utf8'), Buffer.from(provided, 'utf8'));
  } catch (_) {
    return false;
  }
}

// ------------------------------------------------------------ eth utils ---
let ethersLib = null;
function ethers() {
  if (!ethersLib) ethersLib = require('ethers');
  return ethersLib;
}
function keccak256Hex(str) {
  const { keccak256, toUtf8Bytes } = ethers();
  return keccak256(toUtf8Bytes(str));
}

/** keccak256 over ABI-packed uint256 fields (each 32 bytes big-endian). */
function abiPackedKeccak256(values) {
  const { AbiCoder, keccak256 } = ethers();
  const coder = AbiCoder.defaultAbiCoder();
  const encoded = coder.encode(values.map(() => 'uint256'), values);
  return keccak256(encoded);
}

// ------------------------------------------------------- decision logic --
function toBigInt(value, field) {
  if (typeof value === 'bigint') return value;
  if (typeof value === 'number') {
    if (!Number.isInteger(value) || value < 0) throw new Error(`invalid ${field}: ${value}`);
    return BigInt(value);
  }
  if (typeof value === 'string') {
    const s = value.trim();
    if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s);
    if (/^\d+$/.test(s)) return BigInt(s);
    throw new Error(`invalid ${field}: ${value}`);
  }
  throw new Error(`invalid ${field}: ${String(value)}`);
}

function parseMatchId(value) {
  if (typeof value !== 'string') throw new Error('invalid matchId');
  const s = value.trim();
  // UUID form (with dashes) or bare 32-hex form.
  if (!/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(s) &&
      !/^[0-9a-fA-F]{32}$/.test(s)) {
    throw new Error(`invalid matchId: ${value}`);
  }
  return s;
}

function matchIdToBigInt(matchId) {
  return BigInt('0x' + matchId.replace(/-/g, ''));
}

/**
 * Parse a Steal turn envelope. Returns the parsed game state.
 * Throws on malformed envelopes (caller maps that to a HOLD).
 */
function parseTurn(env) {
  if (!env || typeof env !== 'object') throw new Error('envelope is not an object');
  if (env.eventId && env.eventId !== 'steal-the-vfy') throw new Error(`wrong eventId: ${env.eventId}`);
  const matchId = parseMatchId(env.matchId);
  const turn = toBigInt(env.turn, 'turn');
  if (turn < 1n || turn > BigInt(MAX_TURNS)) throw new Error(`turn out of range: ${env.turn}`);
  const state = env.state;
  if (!state || typeof state !== 'object') throw new Error('missing state');
  const selfBalance = toBigInt(state.selfBalance, 'selfBalance');
  const opponentBalance = toBigInt(state.opponentBalance, 'opponentBalance');
  const selfFortifiedUntilTurn = state.selfFortifiedUntilTurn == null
    ? null : toBigInt(state.selfFortifiedUntilTurn, 'selfFortifiedUntilTurn');
  const opponentFortifiedUntilTurn = state.opponentFortifiedUntilTurn == null
    ? null : toBigInt(state.opponentFortifiedUntilTurn, 'opponentFortifiedUntilTurn');
  // The frozen commitment hash echoed by the platform wins over any local
  // default. Fall back to the env-configured default (the circuit vkHash).
  let commitment = DEFAULT_COMMITMENT;
  if (env.strategyCommitment && typeof env.strategyCommitment.hash === 'string' &&
      /^0x[0-9a-fA-F]{64}$/.test(env.strategyCommitment.hash.trim())) {
    commitment = env.strategyCommitment.hash.trim().toLowerCase();
  }
  const deadlineMs = env.deadlineAt ? Date.parse(env.deadlineAt) : NaN;
  if (env.deadlineAt && Number.isNaN(deadlineMs)) throw new Error('invalid deadlineAt');
  return {
    matchId, turn, selfBalance, opponentBalance,
    selfFortifiedUntilTurn, opponentFortifiedUntilTurn,
    commitment, deadlineMs,
    nonce: typeof env.nonce === 'string' ? env.nonce : '',
  };
}

/**
 * The strategy. EXTRACT 10 every turn, HOLD only when the opponent has
 * nothing left to take. See the header comment + README for the
 * dominance argument and the backtest. Returns { type, amount }.
 *
 * !!! DO NOT CAP THE AMOUNT !!! The circuit requires amount ==
 * strategyParams[0] == 10 EXACTLY (template line 149 — proven
 * 2026-11-16: EXTRACT 3 at opponent balance 3 FAILS the proof).
 * The resolver caps the actual gain at the opponent's spendable
 * balance, so sending 10 is safe even when the opponent is low.
 * And when the opponent is at 0, EXTRACT 10 fails the proof
 * (line 140) while HOLD 0 PROVES — so HOLD is the only provable
 * action there, not just the sensible one.
 */
function decideAction(parsed) {
  const { opponentBalance, opponentFortifiedUntilTurn, turn } = parsed;
  if (opponentBalance <= 0n) return { type: 'HOLD', amount: 0 };
  // A fortified opponent still yields up to MAX_EXTRACT - FORTIFY_BLOCK
  // (4 VFY) to an extraction, and extraction is free — so keep
  // extracting even then. Log the fortification for the operator.
  if (opponentFortifiedUntilTurn !== null && opponentFortifiedUntilTurn >= turn) {
    console.log(`[steal] match ${parsed.matchId} turn ${turn}: opponent fortified ` +
      `(until turn ${opponentFortifiedUntilTurn}) — extracting anyway (gain up to ${MAX_EXTRACT - FORTIFY_BLOCK})`);
  }
  // Always the full 10: the circuit demands amount == params[0].
  return { type: 'EXTRACT', amount: MAX_EXTRACT };
}

// ------------------------------------------------------- proof building --
/** Salt: the FIXED value bound into the registered commitment. The
 * commitment is Poseidon(strategyParams ++ [salt]); the salt in the
 * circuit input must be the same value used when the commitment was
 * computed, otherwise template line 72 fails. STEAL_SALT overrides
 * the default 1 — only change it together with the registered
 * commitment (and DEFAULT_COMMITMENT above). */
function saltFor(matchId) {
  void matchId; // the salt is fixed per strategy, NOT per match.
  return STEAL_SALT;
}

/**
 * publicInputsHash per the build guide: keccak256 of ABI-packed
 * 32-byte big-endian fields in order:
 *   commitment, matchId, turn, selfBalance, opponentBalance,
 *   action enum, amount, circuitVersion (1).
 */
function computePublicInputsHash(parsed, action) {
  return abiPackedKeccak256([
    BigInt(parsed.commitment),
    matchIdToBigInt(parsed.matchId),
    parsed.turn,
    parsed.selfBalance,
    parsed.opponentBalance,
    BigInt(ACTIONS[action.type]),
    BigInt(action.amount),
    1n,
  ]);
}

/**
 * Map a parsed turn + action to the circuit's 17 input signals.
 * ENCODING ASSUMPTIONS — see the header comment. If the platform
 * rejects proofs, this mapping is the first thing to re-check.
 */
function buildCircuitInput(parsed, action) {
  const field = (hex) => (BigInt(hex) % FIELD_PRIME).toString();
  return {
    commitment: field(parsed.commitment),
    matchId: (matchIdToBigInt(parsed.matchId) % FIELD_PRIME).toString(),
    turnNumber: parsed.turn.toString(),
    selfBalance: parsed.selfBalance.toString(),
    opponentBalance: parsed.opponentBalance.toString(),
    action: String(ACTIONS[action.type]),
    amount: String(action.amount),
    circuitVersion: '1',
    salt: saltFor(parsed.matchId),
    strategyParams: [...STRATEGY_PARAMS],
  };
}

let snarkjsPromise = null;
function getSnarkjs() {
  if (!snarkjsPromise) snarkjsPromise = Promise.resolve().then(() => require('snarkjs'));
  return snarkjsPromise;
}

/** Generate a Groth16 proof, or throw. Caller time-boxes this. */
async function generateProof(circuitInput) {
  const snarkjs = await getSnarkjs();
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    circuitInput, WASM_PATH, ZKEY_PATH);
  return { proof, publicSignals };
}

function withTimeout(promise, ms, label) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

// ------------------------------------------------- Kurier (on-chain) -----
// Mirrors ~/workspace/agent-games/gatekeeper-agent/server.js (proven
// pattern, commit 596ac6b). The Steal difference: on Finalized the tx
// hash goes into policyProof.proofReference (the build guide's optional
// on-chain audit pointer), NOT into a proof_tx field. Fail-soft: any
// Kurier failure leaves the response exactly as it was (action + local
// proof). The local proof still verifies offline against the platform
// key, so a Kurier miss costs at most the +0..+2 verified-turn
// reliability bonus — never the turn itself.

// Full verification key, exported ONCE at startup (only when prove mode +
// a Kurier key are set) and cached in memory — used for the
// vkRegistered:false fallback. Never hardcoded.
let fullVkPromise = null;
function initFullVk() {
  if (PROOF_MODE !== 'prove' || !KURIER_API_KEY) return;
  if (fullVkPromise) return;
  fullVkPromise = (async () => {
    try {
      const snarkjs = await getSnarkjs();
      return await snarkjs.zKey.exportVerificationKey(ZKEY_PATH);
    } catch (e) {
      console.warn('[steal] WARN: could not export full verification key for Kurier fallback:', e.message);
      return null;
    }
  })();
}
async function getFullVk() {
  return fullVkPromise ? await fullVkPromise : null;
}
initFullVk();

async function fetchJson(url, opts, timeoutMs) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), Math.max(1, timeoutMs));
  try {
    const res = await fetch(url, { ...opts, signal: ctrl.signal });
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch (_) { /* non-JSON body */ }
    return { status: res.status, ok: res.ok, json, text };
  } finally { clearTimeout(t); }
}

function kurierStatusOf(resp) {
  if (!resp) return 'UNKNOWN';
  const j = resp.json;
  if (typeof j === 'string') return j;
  if (j && typeof j === 'object') {
    for (const k of ['status', 'state', 'result']) {
      if (typeof j[k] === 'string') return j[k];
    }
    if (j.job && typeof j.job.status === 'string') return j.job.status;
  }
  return 'UNKNOWN';
}

function kurierTxHashOf(resp) {
  if (!resp || !resp.json || typeof resp.json !== 'object') return null;
  const j = resp.json;
  return j.txHash || j.tx_hash || j.transactionHash || (j.job && j.job.txHash) || null;
}

/**
 * Submit a proof to Kurier and poll until Finalized/Failed or the budget
 * runs out. Returns { jobId, status, txHash, ms }. NEVER throws.
 * Attempt 1: vkRegistered:true + the vfy-policy vkHash. If that submit
 * fails (non-OK or no jobId), attempt 2: vkRegistered:false + the full
 * verification key. Per-fetch timeouts are capped by the remaining
 * budget, so total Kurier time can never exceed budgetMs.
 */
async function kurierSubmitAndPoll(proof, publicSignals, registeredVkHex, budgetMs, fullVk) {
  const t0 = Date.now();
  const remaining = () => budgetMs - (Date.now() - t0);
  const attempts = [
    { vkRegistered: true, vk: registeredVkHex, label: 'vkHash' },
    { vkRegistered: false, vk: fullVk, label: 'fullVk' },
  ];
  try {
    for (const att of attempts) {
      if (att.vk === null || att.vk === undefined) {
        console.warn(`[steal] kurier: skipping ${att.label} attempt (no verification key available)`);
        continue;
      }
      if (remaining() <= 1000) break;
      let submit;
      try {
        submit = await fetchJson(
          `${KURIER_BASE}/submit-proof/${KURIER_API_KEY}`,
          {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
              proofType: 'groth16',
              vkRegistered: att.vkRegistered,
              proofOptions: { library: 'snarkjs', curve: 'bn128' },
              proofData: { proof, publicSignals, vk: att.vk },
            }),
          },
          Math.min(15000, remaining()),
        );
      } catch (e) {
        console.warn(`[steal] kurier submit failed (${att.label}): ${e.message}`);
        continue; // try the next attempt (fullVk fallback)
      }
      if (!submit.ok) {
        console.warn(`[steal] kurier submit failed (${att.label}): HTTP ${submit.status} ${(submit.text || '').slice(0, 200)}`);
        continue; // try the next attempt (fullVk fallback)
      }
      const jobId = submit.json && (submit.json.jobId || submit.json.job_id || submit.json.id || (submit.json.job && submit.json.job.id));
      if (!jobId) {
        console.warn(`[steal] kurier submit: no jobId in response (${att.label})`);
        return { jobId: null, status: 'NO_JOB_ID', txHash: null, ms: Date.now() - t0 };
      }
      // Poll until Finalized / Failed / budget.
      let status = 'UNKNOWN';
      let txHash = null;
      while (remaining() > 1000) {
        let st;
        try {
          st = await fetchJson(`${KURIER_BASE}/job-status/${KURIER_API_KEY}/${jobId}`, {}, Math.min(10000, remaining()));
        } catch (e) {
          console.warn(`[steal] kurier job-status failed: ${e.message}`);
          break;
        }
        status = kurierStatusOf(st);
        txHash = kurierTxHashOf(st);
        if (/final/i.test(status) || /fail/i.test(status)) break;
        await new Promise((r) => setTimeout(r, Math.min(3000, remaining())));
      }
      return { jobId: String(jobId), status, txHash, ms: Date.now() - t0 };
    }
    return { jobId: null, status: 'SUBMIT_FAILED', txHash: null, ms: Date.now() - t0 };
  } catch (e) {
    console.warn(`[steal] kurier error: ${e.message}`);
    return { jobId: null, status: 'ERROR', txHash: null, ms: Date.now() - t0 };
  }
}

// -------------------------------------------------- idempotency (retries) --
// The platform may re-push a turn (retries). The response is fully
// deterministic per (matchId, turn) — same action, same salt, same
// proof inputs — so cache it and replay it verbatim on a duplicate push.
const responseCache = new Map();
function cacheKey(matchId, turn) { return `${matchId}:${turn}`; }

// ------------------------------------------------------------ HTTP layer --
function sendJson(res, status, obj, sign = true) {
  const body = Buffer.from(JSON.stringify(obj), 'utf8');
  const headers = { 'content-type': 'application/json', 'content-length': body.length };
  if (sign) headers['x-agent-games-signature'] = hmacHex(HMAC_SECRET, body);
  res.writeHead(status, headers);
  res.end(body);
}

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > 1_000_000) { reject(new Error('body too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function isTurnEnvelope(env) {
  if (!env || typeof env !== 'object') return false;
  if (env.eventId === 'steal-the-vfy') return true;
  if (typeof env.type === 'string' && /steal|vfy-policy/i.test(env.type)) return true;
  // The build guide's example envelope has no "type" field at all —
  // matchId + turn + state is enough to recognise a turn.
  return typeof env.matchId === 'string' && env.turn !== undefined &&
    env.state && typeof env.state === 'object';
}

async function handleAgent(req, res, rawBody) {
  // 1. Authenticate FIRST, before parsing anything.
  const expected = hmacHex(HMAC_SECRET, rawBody);
  if (!signaturesMatch(expected, req.headers['x-agent-games-signature'])) {
    console.warn('[steal] 401 HMAC mismatch');
    return sendJson(res, 401, { error: 'invalid signature' });
  }

  // 2. Parse.
  let env;
  try {
    env = JSON.parse(rawBody.toString('utf8'));
  } catch (_) {
    return sendJson(res, 400, { error: 'invalid JSON' });
  }

  // 3. Preflight handshake.
  if (env && env.type === 'agent-games.preflight.v1') {
    console.log('[steal] preflight ok');
    return sendJson(res, 200, { ok: true, protocolVersion: 'v1' });
  }

  // 4. Turn envelope.
  if (!isTurnEnvelope(env)) {
    return sendJson(res, 400, { error: 'unknown envelope type' });
  }

  const startedAt = Date.now();
  const matchId = typeof env.matchId === 'string' ? env.matchId : '(no matchId)';
  const turn = env.turn !== undefined ? String(env.turn) : '(no turn)';

  // 4a. Idempotent replay of a duplicate push.
  const key = cacheKey(matchId, turn);
  if (responseCache.has(key)) {
    console.log(`[steal] match ${matchId} turn ${turn}: duplicate push — replaying cached response`);
    return sendJson(res, 200, responseCache.get(key));
  }

  // 4b. Parse + decide. Any failure -> HOLD (fail closed).
  let parsed;
  let action = { type: 'HOLD', amount: 0 };
  let parseFailed = false;
  try {
    parsed = parseTurn(env);
    if (!Number.isNaN(parsed.deadlineMs) && Date.now() > parsed.deadlineMs) {
      console.warn(`[steal] match ${matchId} turn ${turn}: past deadline — HOLD`);
      parseFailed = true; // deadline passed: answer HOLD, no proof attempt
    } else {
      action = decideAction(parsed);
    }
  } catch (e) {
    console.warn(`[steal] match ${matchId} turn ${turn}: malformed envelope (${e.message}) -> HOLD`);
    parseFailed = true;
  }

  const response = {
    matchId,
    turn: Number.isNaN(Number(turn)) ? turn : Number(turn),
    // Build guide, "Common mistakes": NEVER send action.amount for
    // HOLD or FORTIFY — it must be omitted entirely; the schema
    // rejects the field even when it is 0. Only EXTRACT carries it.
    action: action.type === 'EXTRACT'
      ? { type: 'EXTRACT', amount: action.amount }
      : { type: action.type },
    policyProof: { circuitVersion: 'v1' },
    agentTimestamp: new Date().toISOString(),
    idempotencyKey: `${matchId}:${turn}`,
  };

  // 5. Proof (best effort, time-boxed inside the ~30 s push window).
  // A proof-less action response costs -2 and resolves as HOLD, so a
  // proof is attempted for every decided action including HOLD — the
  // circuit must allow the action under the committed strategy.
  if (PROOF_MODE === 'prove' && parsed && !parseFailed) {
    const remaining = ANSWER_BUDGET_MS - (Date.now() - startedAt) - 3000; // 3 s margin to answer
    const budget = Math.max(1000, Math.min(PROOF_BUDGET_MS, remaining));
    try {
      const circuitInput = buildCircuitInput(parsed, action);
      const { proof, publicSignals } = await withTimeout(
        generateProof(circuitInput), budget, 'proof generation');
      response.policyProof.proof = proof;
      response.policyProof.public_signals = publicSignals;
      response.policyProof.publicInputsHash = computePublicInputsHash(parsed, action);
      console.log(`[steal] match ${matchId} turn ${turn}: ${action.type} ${action.amount} + proof, ${Date.now() - startedAt}ms`);
    } catch (e) {
      // No proof — but still answer with the action (a missing answer
      // forfeits the turn AND risks the agent's health record; a
      // proof-less response is a bounded -2, resolved as HOLD).
      console.error(`[steal] match ${matchId} turn ${turn}: ${action.type} ${action.amount} WITHOUT proof: ${e.message}`);
    }
  } else {
    const why = PROOF_MODE === 'stub' ? 'disabled (stub mode)'
      : 'skipped (malformed input or past deadline)';
    console.log(`[steal] match ${matchId} turn ${turn}: ${action.type} ${action.amount} [proof ${why}], ${Date.now() - startedAt}ms`);
  }

  // 6. Kurier: submit the proof on-chain and wait for Finalized (best
  // effort, strictly inside the ~30 s push window). On Finalized with a
  // txHash, the on-chain tx hash is attached as
  // policyProof.proofReference — the audit pointer the platform links
  // to the match replay and proof record, and the best shot at the
  // +0..+2 verified-turn reliability bonus. Any failure leaves the
  // response exactly as it was (action + local proof, which still
  // verifies offline against the platform key).
  if (KURIER_API_KEY && response.policyProof.proof) {
    const kurierBudget = Math.min(
      KURIER_POLL_BUDGET_MS,
      ANSWER_BUDGET_MS - (Date.now() - startedAt) - 2000,
    );
    if (kurierBudget > 5000) {
      const fullVk = await getFullVk();
      const kurier = await kurierSubmitAndPoll(
        response.policyProof.proof, response.policyProof.public_signals,
        PLATFORM_VK_HASH, kurierBudget, fullVk);
      console.log(`[steal] match ${matchId} turn ${turn}: kurier ${kurier.status} job=${kurier.jobId || '-'} ${kurier.ms}ms`);
      if (/final/i.test(kurier.status) && kurier.txHash) {
        response.policyProof.proofReference = kurier.txHash;
        console.log(`[steal] match ${matchId} turn ${turn}: proofReference set to on-chain txHash ${kurier.txHash}`);
      }
    } else {
      console.log(`[steal] match ${matchId} turn ${turn}: kurier skipped (budget ${kurierBudget}ms too small)`);
    }
  }

  responseCache.set(key, response);
  return sendJson(res, 200, response);
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === 'GET' && req.url === '/health') {
      return sendJson(res, 200, { ok: true, protocolVersion: 'v1', proofMode: PROOF_MODE }, false);
    }
    if (req.method !== 'POST' || req.url !== '/agent') {
      res.writeHead(404, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ error: 'not found' }));
    }
    const rawBody = await readRawBody(req);
    await handleAgent(req, res, rawBody);
  } catch (e) {
    console.error('[steal] handler error:', e.message);
    try { sendJson(res, 500, { error: 'internal error' }); } catch (_) { /* socket gone */ }
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[steal] listening on 0.0.0.0:${PORT} /agent (proof mode: ${PROOF_MODE}, ` +
    `proof budget: ${PROOF_BUDGET_MS}ms, kurier: ${KURIER_API_KEY ? 'configured' : 'not configured'}, ` +
    `commitment: ${DEFAULT_COMMITMENT.slice(0, 10)}..., params: [${STRATEGY_PARAMS.join(',')}])`);
});
