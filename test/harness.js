/**
 * Test harness for the Steal the VFY agent server.
 *
 * Starts server.js as a child process on a scratch port with a TEST
 * HMAC secret, then replays signed sample turn envelopes and checks
 * the actions, the response shape (per the /build "Common mistakes"
 * list), the response signatures, and — in --prove mode — the full
 * Groth16 proof round-trip against the VK exported from the zkey.
 *
 *   node test/harness.js           # decision logic only (PROOF_MODE=stub)
 *   node test/harness.js --prove   # also runs real fullProve round-trips
 *
 * Exit code 0 = all cases passed, 1 = any failure.
 *
 * Test envelopes use the REGISTERED commitment
 * Poseidon([10,0,0,0,0,0,0,0, 1]) =
 * 0x027f7cef3ba97234ac7e57b829a5e9e555c32b1f1f9416ed952589f07223d017
 * (NOT the vkHash — the circuit proves commitment ==
 * Poseidon(params, salt), so the vkHash would fail at line 72).
 * The matchId is a valid UUID, 9f4e1b2a-1a2b-3c4d-5e6f-708192a3b4c5
 * (8-4-4-4-12). The docs' example is truncated ("9f4e1b2a-..."), and
 * an earlier draft used 708192a3b4c (11 hex chars, 31 digits total) —
 * the server rightly rejected it as an invalid UUID, which surfaced
 * as every MATCH_ID turn answering HOLD. That 11-char form is now
 * test 15's invalid-matchId case.
 */
'use strict';

const http = require('http');
const crypto = require('crypto');
const { spawn } = require('child_process');
const path = require('path');

const TEST_SECRET = 'test-secret-do-not-use-in-production';
const PORT = 18000 + Math.floor(Math.random() * 900); // random per run: no stale-port collisions
const BASE = `http://127.0.0.1:${PORT}`;
const WITH_PROOF = process.argv.includes('--prove');

const COMMITMENT_HEX = '0x027f7cef3ba97234ac7e57b829a5e9e555c32b1f1f9416ed952589f07223d017';
const COMMITMENT_DEC = '1129877540650774363083839624141057200381268645865202340914753086235506626583';
const FIELD_PRIME = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');

function hmac(body) {
  return crypto.createHmac('sha256', TEST_SECRET).update(body).digest('hex');
}

function post(pathname, bodyObj, { sign = true, rawBody = null } = {}) {
  const body = rawBody !== null ? rawBody : Buffer.from(JSON.stringify(bodyObj), 'utf8');
  return new Promise((resolve, reject) => {
    const req = http.request(BASE + pathname, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'content-length': body.length,
        ...(sign ? { 'x-agent-games-signature': hmac(body) } : {}),
      },
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const raw = Buffer.concat(chunks);
        let json = null;
        try { json = JSON.parse(raw.toString('utf8')); } catch (_) { /* not JSON */ }
        resolve({ status: res.statusCode, headers: res.headers, raw, json });
      });
    });
    req.on('error', reject);
    req.end(body);
  });
}

function verifyResponseSignature(res) {
  const expected = crypto.createHmac('sha256', TEST_SECRET).update(res.raw).digest('hex');
  const got = (res.headers['x-agent-games-signature'] || '').replace(/^sha256=/i, '');
  return got.length === expected.length && crypto.timingSafeEqual(Buffer.from(got), Buffer.from(expected));
}

const MATCH_ID = '9f4e1b2a-1a2b-3c4d-5e6f-708192a3b4c5';
const MATCH_ID_BIG = BigInt('0x' + MATCH_ID.replace(/-/g, ''));

function turn(matchId, turnNumber, overrides = {}, stateOverrides = {}) {
  return {
    protocolVersion: 'v1',
    eventId: 'steal-the-vfy',
    mode: 'competition',
    matchId,
    turn: turnNumber,
    issuedAt: new Date().toISOString(),
    deadlineAt: new Date(Date.now() + 300000).toISOString(),
    state: {
      selfBalance: '100',
      opponentBalance: '100',
      selfFortifiedUntilTurn: null,
      opponentFortifiedUntilTurn: null,
      ...stateOverrides,
    },
    strategyCommitment: { hash: COMMITMENT_HEX },
    resolverVersion: 'v1',
    nonce: `test-nonce-${matchId}-${turnNumber}`,
    ...overrides,
  };
}

async function waitReady(tries = 50) {
  for (let i = 0; i < tries; i++) {
    try {
      const r = await new Promise((resolve, reject) => {
        http.get(BASE + '/health', (res) => resolve(res.statusCode)).on('error', reject);
      });
      if (r === 200) return true;
    } catch (_) { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 200));
  }
  return false;
}

// Expected publicInputsHash for the doc-example turn:
// commitment 0x027f..., matchId 9f4e1b2a-1a2b-3c4d-5e6f-708192a3b4c5,
// turn 3, self 95, opp 105, EXTRACT 10, circuitVersion 1.
// Computed two independent ways (ethers AbiCoder + manual hex concat);
// both agree. Field order is verbatim from the /build TypeScript snippet.
const HASH_VECTOR = '0x35030521c72b8eeb874a43269c7c3bd07b42a2d27ba5c93a00a5294cc7c4c552';

(async () => {
  const proofMode = WITH_PROOF ? 'prove' : 'stub';
  const server = spawn(process.execPath, ['server.js'], {
    cwd: path.join(__dirname, '..'),
    env: {
      ...process.env,
      PORT: String(PORT),
      AGENT_GAMES_HMAC_SECRET: TEST_SECRET,
      PROOF_MODE: proofMode,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let serverLog = '';
  server.stdout.on('data', (d) => { serverLog += d.toString(); });
  server.stderr.on('data', (d) => { serverLog += d.toString(); });

  const results = [];
  function check(name, cond, detail = '') {
    results.push({ name, pass: !!cond, detail });
    console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${detail ? ` — ${detail}` : ''}`);
  }

  // --prove helpers (loaded lazily so stub mode stays dependency-light).
  let vk = null;
  let poseidon = null;
  let poseidonF = null;
  async function loadProveDeps() {
    const snarkjs = require('snarkjs');
    vk = await snarkjs.zKey.exportVerificationKey(path.join(__dirname, '..', 'circuits', 'vfy-policy_final.zkey'));
    const { buildPoseidon } = require('circomlibjs');
    poseidon = await buildPoseidon();
    poseidonF = poseidon.F;
  }
  function poseidonOut(matchId, turnNumber) {
    // Circuit output = Poseidon(matchId, turnNumber, circuitVersion).
    const m = (BigInt('0x' + matchId.replace(/-/g, '')) % FIELD_PRIME).toString();
    return poseidonF.toString(poseidon([poseidonF.e(m), poseidonF.e(String(turnNumber)), poseidonF.e('1')]));
  }
  async function verifyProof(res) {
    const snarkjs = require('snarkjs');
    return snarkjs.groth16.verify(vk, res.json.policyProof.public_signals, res.json.policyProof.proof);
  }
  function expectedSignals(matchId, turnNumber, selfBal, oppBal, actionEnum, amount) {
    return [
      poseidonOut(matchId, turnNumber),
      COMMITMENT_DEC,
      (BigInt('0x' + matchId.replace(/-/g, '')) % FIELD_PRIME).toString(),
      String(turnNumber),
      String(selfBal),
      String(oppBal),
      String(actionEnum),
      String(amount),
      '1',
    ];
  }

  try {
    if (!await waitReady()) {
      console.error('FAIL  server did not become ready');
      console.error(serverLog);
      process.exit(1);
    }
    if (WITH_PROOF) await loadProveDeps();

    // 1. Preflight
    let r = await post('/agent', { type: 'agent-games.preflight.v1', agent_id: 'agt_test', issued_at: new Date().toISOString(), nonce: 'abc123' });
    check('preflight returns {ok:true, protocolVersion:v1} signed', r.status === 200 && r.json && r.json.ok === true && r.json.protocolVersion === 'v1' && verifyResponseSignature(r), `status=${r.status}`);

    // 2. Turn 1, 100/100 -> EXTRACT 10 (amount present for EXTRACT)
    r = await post('/agent', turn(MATCH_ID, 1));
    check('turn 1 (100/100) -> EXTRACT 10', r.status === 200 && r.json && r.json.action && r.json.action.type === 'EXTRACT' && r.json.action.amount === 10, JSON.stringify(r.json && r.json.action));
    check('turn 1 response is signed', verifyResponseSignature(r));
    check('turn 1 echoes matchId + turn', r.json && r.json.matchId === MATCH_ID && r.json.turn === 1, `matchId=${r.json && r.json.matchId} turn=${r.json && r.json.turn}`);
    check('turn 1 policyProof.circuitVersion is v1', r.json && r.json.policyProof && r.json.policyProof.circuitVersion === 'v1');
    check('turn 1 idempotencyKey is a deterministic UUID (v5-shaped)', r.json && /^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(r.json.idempotencyKey || ''), r.json && r.json.idempotencyKey);
    const key1 = r.json && r.json.idempotencyKey;
    if (WITH_PROOF) {
      check('turn 1 includes proof + public_signals (9)', !!(r.json && r.json.policyProof && r.json.policyProof.proof && Array.isArray(r.json.policyProof.public_signals) && r.json.policyProof.public_signals.length === 9), `publicSignals=${r.json && r.json.policyProof && r.json.policyProof.public_signals && r.json.policyProof.public_signals.length}`);
      check('turn 1 includes publicInputsHash (0x 32-byte)', !!(r.json && r.json.policyProof && /^0x[0-9a-f]{64}$/.test(r.json.policyProof.publicInputsHash || '')), r.json && r.json.policyProof && r.json.policyProof.publicInputsHash);
      const sig = r.json.policyProof.public_signals;
      const expected = expectedSignals(MATCH_ID, 1, 100, 100, 2, 10);
      check('turn 1 public_signals equal the expected vector', JSON.stringify(sig) === JSON.stringify(expected), `got=[${sig && sig.join(',')}]`);
      check('turn 1 proof verifies against the VK from the zkey', await verifyProof(r));
    } else {
      check('stub mode: turn 1 has no proof (expected)', !(r.json && r.json.policyProof && r.json.policyProof.proof), 'proof present in stub mode');
    }

    // 3. Duplicate push of turn 1 -> identical response (idempotent replay)
    const first = JSON.stringify(r.json);
    r = await post('/agent', turn(MATCH_ID, 1));
    check('duplicate push of turn 1 replays identical response', JSON.stringify(r.json) === first, 'response differed');

    // 4. Opponent at 0 -> HOLD, and amount MUST be omitted (build guide:
    // "the schema rejects the field even when it is 0").
    r = await post('/agent', turn(MATCH_ID, 2, {}, { opponentBalance: '0' }));
    check('opponent 0 -> HOLD with NO amount field', r.json && r.json.action && r.json.action.type === 'HOLD' && !('amount' in r.json.action), JSON.stringify(r.json && r.json.action));
    check('turn 2 idempotencyKey differs from turn 1 (unique per turn)', r.json && r.json.idempotencyKey && r.json.idempotencyKey !== key1, r.json && r.json.idempotencyKey);
    if (WITH_PROOF) {
      check('opponent 0 HOLD carries a proof (provable path)', !!(r.json && r.json.policyProof && r.json.policyProof.proof), 'no proof for HOLD');
      const sig = r.json.policyProof.public_signals;
      const expected = expectedSignals(MATCH_ID, 2, 100, 0, 0, 0);
      check('opponent 0 public_signals equal the expected vector', JSON.stringify(sig) === JSON.stringify(expected), `got=[${sig && sig.join(',')}]`);
      check('opponent 0 HOLD proof verifies against the VK', await verifyProof(r));
    }

    // 5. Opponent low balance (3) -> EXTRACT 10 (NO cap: the circuit
    // demands amount == params[0] == 10 exactly, line 149; the
    // resolver caps the gain, not the amount).
    r = await post('/agent', turn(MATCH_ID, 3, {}, { opponentBalance: '3' }));
    check('opponent 3 -> EXTRACT 10 (uncapped)', r.json && r.json.action && r.json.action.type === 'EXTRACT' && r.json.action.amount === 10, JSON.stringify(r.json && r.json.action));

    // 6. Doc-example turn: turn 3, 95/105 -> publicInputsHash must equal
    // the precomputed test vector (two independent computations agree).
    // (Different match: use a fresh matchId so the turn-3 cache key
    // from test 5 does not collide.)
    const MATCH2 = '11111111-2222-3333-4444-555555555555';
    r = await post('/agent', turn(MATCH2, 3, {}, { selfBalance: '95', opponentBalance: '105' }));
    check('doc-example turn -> EXTRACT 10', r.json && r.json.action && r.json.action.type === 'EXTRACT' && r.json.action.amount === 10, JSON.stringify(r.json && r.json.action));
    if (WITH_PROOF) {
      // The hash vector above is for MATCH_ID (9f4e1b2a-...), not MATCH2,
      // so recompute the expectation for MATCH2 from the server's own
      // function path is NOT a check — instead verify the MATCH_ID
      // vector with a dedicated turn below (test 6b).
      check('doc-example turn includes publicInputsHash', !!(r.json && r.json.policyProof && /^0x[0-9a-f]{64}$/.test(r.json.policyProof.publicInputsHash || '')));
    }

    // 6b. publicInputsHash test vector: turn 3, 95/105, EXTRACT 10,
    // commitment 0x027f... The stored vector (0x350305...) is for
    // MATCH_ID, but MATCH_ID turn 3 is already cached from test 5
    // (same key, different balances) — so verify the hash against a
    // FRESH match (MATCH3) computed the same two independent ways,
    // and reproduce the stored MATCH_ID vector as a pure computation.
    const MATCH3 = '22222222-3333-4444-5555-666666666666';
    r = await post('/agent', turn(MATCH3, 3, {}, { selfBalance: '95', opponentBalance: '105' }));
    check('hash-vector turn -> EXTRACT 10', r.json && r.json.action && r.json.action.type === 'EXTRACT' && r.json.action.amount === 10);
    if (WITH_PROOF) {
      // The stored vector is for MATCH_ID; recompute it for MATCH3 with
      // the same two-method cross-check used to derive the vector.
      const { AbiCoder, keccak256 } = require('ethers');
      const coder = AbiCoder.defaultAbiCoder();
      const fields = [BigInt(COMMITMENT_HEX), BigInt('0x' + MATCH3.replace(/-/g, '')), 3n, 95n, 105n, 2n, 10n, 1n];
      const expectedHash = keccak256(coder.encode(fields.map(() => 'uint256'), fields));
      check('publicInputsHash equals the independently computed value', r.json.policyProof.publicInputsHash === expectedHash, `got=${r.json.policyProof.publicInputsHash} want=${expectedHash}`);
      // And the stored MATCH_ID vector itself (sanity: the derivation).
      const fId = [BigInt(COMMITMENT_HEX), MATCH_ID_BIG, 3n, 95n, 105n, 2n, 10n, 1n];
      const hashId = keccak256(coder.encode(fId.map(() => 'uint256'), fId));
      check('stored hash test vector reproduces (0x350305...)', hashId === HASH_VECTOR, `got=${hashId}`);
    }

    // 7. Fortified opponent -> still EXTRACT 10 (gain up to 4, free)
    r = await post('/agent', turn(MATCH_ID, 4, {}, { opponentFortifiedUntilTurn: 4 }));
    check('fortified opponent -> EXTRACT 10', r.json && r.json.action && r.json.action.type === 'EXTRACT' && r.json.action.amount === 10, JSON.stringify(r.json && r.json.action));

    // 8. Past deadline -> HOLD
    r = await post('/agent', turn(MATCH_ID, 5, { deadlineAt: new Date(Date.now() - 1000).toISOString() }));
    check('past deadline -> HOLD', r.json && r.json.action && r.json.action.type === 'HOLD', JSON.stringify(r.json && r.json.action));

    // 9. Malformed envelope (missing state) -> HOLD
    r = await post('/agent', { protocolVersion: 'v1', eventId: 'steal-the-vfy', matchId: MATCH_ID, turn: 6 });
    check('malformed envelope -> HOLD', r.json && r.json.action && r.json.action.type === 'HOLD', JSON.stringify(r.json && r.json.action));

    // 10. Bad HMAC -> 401
    r = await post('/agent', turn(MATCH_ID, 7), { sign: false });
    check('missing/invalid HMAC -> 401', r.status === 401, `status=${r.status}`);

    // 11. Malformed JSON with valid HMAC -> 400
    r = await post('/agent', null, { rawBody: Buffer.from('{not json', 'utf8') });
    check('malformed JSON -> 400', r.status === 400, `status=${r.status}`);

    // 12. Unknown envelope type -> 400
    r = await post('/agent', { type: 'agent-games.something-else.v1' });
    check('unknown envelope type -> 400', r.status === 400, `status=${r.status}`);

    // 13. Wrong path -> 404
    r = await post('/other', turn(MATCH_ID, 8));
    check('wrong path -> 404', r.status === 404, `status=${r.status}`);

    // 14. Wrong eventId -> HOLD (not a crash)
    r = await post('/agent', turn(MATCH_ID, 9, { eventId: 'proof-gatekeeper' }));
    check('wrong eventId -> HOLD', r.json && r.json.action && r.json.action.type === 'HOLD', JSON.stringify(r.json && r.json.action));

    // 15. Invalid matchId (11-char last group — the old harness bug) -> HOLD
    r = await post('/agent', turn('9f4e1b2a-1a2b-3c4d-5e6f-708192a3b4c', 10));
    check('invalid matchId -> HOLD (fail closed)', r.json && r.json.action && r.json.action.type === 'HOLD', JSON.stringify(r.json && r.json.action));
  } finally {
    server.kill('SIGTERM');
  }

  const failed = results.filter((x) => !x.pass).length;
  console.log(`\n${results.length - failed}/${results.length} passed (proof mode: ${proofMode})`);
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error('HARNESS ERROR:', e); process.exit(1); });
