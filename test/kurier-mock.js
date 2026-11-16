/**
 * Kurier integration test (mock — no real API key, no on-chain tx).
 *
 * Spins up a fake Kurier server, then the agent with
 * KURIER_API_KEY=test-key and KURIER_BASE pointed at the fake, and
 * checks:
 *   1. Happy path: submit -> poll -> Finalized -> the response's
 *      policyProof.proofReference is the mock tx hash.
 *   2. Kurier down (connection refused): the turn still answers with
 *      the local proof and NO proofReference (fail-soft), inside the
 *      answer budget.
 *   3. Kurier submit 500: same fail-soft behaviour.
 *
 * The REAL key (kurier.xyz Mainnet "Server") is never used here.
 * It is verified separately by the deploy checklist (job-status on a
 * fake ID returns 404 "Job not found", not 401).
 *
 *   node test/kurier-mock.js
 *
 * Exit code 0 = all cases passed, 1 = any failure.
 */
'use strict';

const http = require('http');
const crypto = require('crypto');
const { spawn } = require('child_process');
const path = require('path');

const TEST_SECRET = 'test-secret-do-not-use-in-production';
const COMMITMENT_HEX = '0x027f7cef3ba97234ac7e57b829a5e9e555c32b1f1f9416ed952589f07223d017';
const MOCK_TX = '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef';

function hmac(body) {
  return crypto.createHmac('sha256', TEST_SECRET).update(body).digest('hex');
}

function post(port, bodyObj) {
  const body = Buffer.from(JSON.stringify(bodyObj), 'utf8');
  return new Promise((resolve, reject) => {
    const req = http.request(`http://127.0.0.1:${port}/agent`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'content-length': body.length,
        'x-agent-games-signature': hmac(body),
      },
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch (_) { /* no */ }
        resolve({ status: res.statusCode, json });
      });
    });
    req.on('error', reject);
    req.end(body);
  });
}

function turn(matchId, turnNumber) {
  return {
    protocolVersion: 'v1',
    eventId: 'steal-the-vfy',
    mode: 'competition',
    matchId,
    turn: turnNumber,
    issuedAt: new Date().toISOString(),
    deadlineAt: new Date(Date.now() + 300000).toISOString(),
    state: { selfBalance: '100', opponentBalance: '100', selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null },
    strategyCommitment: { hash: COMMITMENT_HEX },
    resolverVersion: 'v1',
    nonce: `kurier-test-${matchId}-${turnNumber}`,
  };
}

async function waitReady(port, tries = 50) {
  for (let i = 0; i < tries; i++) {
    try {
      const r = await new Promise((resolve, reject) => {
        http.get(`http://127.0.0.1:${port}/health`, (res) => resolve(res.statusCode)).on('error', reject);
      });
      if (r === 200) return true;
    } catch (_) { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 200));
  }
  return false;
}

function startAgent(port, kurierBase) {
  const server = spawn(process.execPath, ['server.js'], {
    cwd: path.join(__dirname, '..'),
    env: {
      ...process.env,
      PORT: String(port),
      AGENT_GAMES_HMAC_SECRET: TEST_SECRET,
      PROOF_MODE: 'prove',
      KURIER_API_KEY: 'test-key-do-not-use',
      KURIER_BASE: kurierBase,
      KURIER_POLL_BUDGET_MS: '15000',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let log = '';
  server.stdout.on('data', (d) => { log += d.toString(); });
  server.stderr.on('data', (d) => { log += d.toString(); });
  return { server, log: () => log };
}

(async () => {
  const results = [];
  function check(name, cond, detail = '') {
    results.push({ name, pass: !!cond, detail });
    console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${detail ? ` — ${detail}` : ''}`);
  }

  // ---- mock Kurier -------------------------------------------------
  let statusCalls = 0;
  let submitCalls = 0;
  let mode = 'ok'; // 'ok' | 'submit500'
  const mock = http.createServer((req, res) => {
    if (req.url.startsWith('/submit-proof/')) {
      submitCalls++;
      if (mode === 'submit500') {
        res.writeHead(500, { 'content-type': 'application/json' });
        return res.end(JSON.stringify({ error: 'boom' }));
      }
      let body = '';
      req.on('data', (c) => { body += c; });
      req.on('end', () => {
        const j = JSON.parse(body);
        const okShape = j.proofType === 'groth16' && j.proofOptions && j.proofOptions.library === 'snarkjs'
          && j.proofData && j.proofData.proof && Array.isArray(j.proofData.publicSignals);
        res.writeHead(okShape ? 200 : 400, { 'content-type': 'application/json' });
        res.end(JSON.stringify(okShape ? { jobId: 'mock-job-1' } : { error: 'bad shape' }));
      });
      return;
    }
    if (req.url.startsWith('/job-status/')) {
      statusCalls++;
      // First poll: Submitted; second poll: Finalized + txHash.
      const done = statusCalls >= 2;
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify(done
        ? { status: 'Finalized', txHash: MOCK_TX }
        : { status: 'Submitted' }));
    }
    res.writeHead(404);
    res.end();
  });
  await new Promise((r) => mock.listen(0, '127.0.0.1', r));
  const mockPort = mock.address().port;
  const mockBase = `http://127.0.0.1:${mockPort}`;

  try {
    // 1. Happy path.
    const port1 = 18100 + Math.floor(Math.random() * 800);
    const a1 = startAgent(port1, mockBase);
    if (!await waitReady(port1)) { console.error('FAIL  agent 1 did not start'); console.error(a1.log()); process.exit(1); }
    const t0 = Date.now();
    let r = await post(port1, turn('aaaaaaaa-1111-2222-3333-444444444444', 1));
    const ms1 = Date.now() - t0;
    check('kurier happy path: proofReference is the mock tx hash', r.json && r.json.policyProof && r.json.policyProof.proofReference === MOCK_TX, `got=${r.json && r.json.policyProof && r.json.policyProof.proofReference}`);
    check('kurier happy path: local proof still present', !!(r.json && r.json.policyProof && r.json.policyProof.proof));
    check('kurier happy path: answer inside 25 s budget', ms1 < 25000, `${ms1}ms`);
    check('kurier mock saw submit + >=2 status polls', submitCalls >= 1 && statusCalls >= 2, `submit=${submitCalls} status=${statusCalls}`);
    a1.server.kill('SIGTERM');

    // 2. Kurier down (dead port) — fail-soft.
    const port2 = 18200 + Math.floor(Math.random() * 800);
    const a2 = startAgent(port2, 'http://127.0.0.1:9'); // nothing listens on 9
    if (!await waitReady(port2)) { console.error('FAIL  agent 2 did not start'); console.error(a2.log()); process.exit(1); }
    const t2 = Date.now();
    r = await post(port2, turn('bbbbbbbb-1111-2222-3333-444444444444', 1));
    const ms2 = Date.now() - t2;
    check('kurier down: turn still answers with local proof', r.status === 200 && !!(r.json && r.json.policyProof && r.json.policyProof.proof), `status=${r.status}`);
    check('kurier down: no proofReference set', !(r.json && r.json.policyProof && r.json.policyProof.proofReference), `got=${r.json && r.json.policyProof && r.json.policyProof.proofReference}`);
    check('kurier down: answer inside 25 s budget', ms2 < 25000, `${ms2}ms`);
    a2.server.kill('SIGTERM');

    // 3. Kurier submit 500 — fail-soft (falls through to fullVk attempt,
    // which also 500s, then answers with the local proof).
    mode = 'submit500';
    submitCalls = 0; statusCalls = 0;
    const port3 = 18300 + Math.floor(Math.random() * 800);
    const a3 = startAgent(port3, mockBase);
    if (!await waitReady(port3)) { console.error('FAIL  agent 3 did not start'); console.error(a3.log()); process.exit(1); }
    const t3 = Date.now();
    r = await post(port3, turn('cccccccc-1111-2222-3333-444444444444', 1));
    const ms3 = Date.now() - t3;
    check('kurier 500: turn still answers with local proof', r.status === 200 && !!(r.json && r.json.policyProof && r.json.policyProof.proof), `status=${r.status}`);
    check('kurier 500: no proofReference set', !(r.json && r.json.policyProof && r.json.policyProof.proofReference));
    check('kurier 500: answer inside 25 s budget', ms3 < 25000, `${ms3}ms`);
    a3.server.kill('SIGTERM');
  } finally {
    mock.close();
  }

  const failed = results.filter((x) => !x.pass).length;
  console.log(`\n${results.length - failed}/${results.length} passed (kurier mock)`);
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error('KURIER MOCK ERROR:', e); process.exit(1); });
