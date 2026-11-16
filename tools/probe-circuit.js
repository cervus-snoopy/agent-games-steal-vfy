// Empirically probe the vfy-policy circuit semantics.
// Loads the VK exported to /tmp/vfy-vk.json, then generates + locally
// verifies proofs for crafted inputs. Answers: which (strategyParams,
// action, amount) combos have a valid proof, and what the public
// signals are.
const snarkjs = require('snarkjs');
const fs = require('fs');

const FIELD_P = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');
const field = (hex) => (BigInt(hex) % FIELD_P).toString();

async function trial(vk, name, input) {
  const t0 = Date.now();
  try {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      input, 'circuits/vfy-policy.wasm', 'circuits/vfy-policy_final.zkey');
    const ok = await snarkjs.groth16.verify(vk, publicSignals, proof);
    console.log(`${name}: prove+verify ${ok ? 'VALID' : 'INVALID'} (${Date.now() - t0}ms) publicSignals=[${publicSignals.join(',')}]`);
    return ok;
  } catch (e) {
    console.log(`${name}: FAILED (${Date.now() - t0}ms): ${e.message.split('\n')[0]}`);
    return null;
  }
}

(async () => {
  const vk = JSON.parse(fs.readFileSync('/tmp/vfy-vk.json', 'utf8'));
  console.log('VK loaded, nPublic =', vk.IC.length - 1);
  const base = {
    commitment: '0',
    matchId: '1',
    turnNumber: '1',
    selfBalance: '100',
    opponentBalance: '100',
    action: '0',
    amount: '0',
    circuitVersion: '1',
    salt: '1',
    strategyParams: ['0', '0', '0', '0', '0', '0', '0', '0'],
  };
  await trial(vk, 'A zeros, HOLD 0', { ...base });
  await trial(vk, 'B zeros, EXTRACT 10', { ...base, action: '2', amount: '10' });
  await trial(vk, 'C zeros, FORTIFY 0', { ...base, action: '1', amount: '0' });
  await trial(vk, 'D zeros, EXTRACT 11 (over cap)', { ...base, action: '2', amount: '11' });
  await trial(vk, 'E zeros, action=3 (bad enum)', { ...base, action: '3', amount: '0' });
  await trial(vk, 'F zeros, circuitVersion=2', { ...base, circuitVersion: '2' });
  await trial(vk, 'G params[0]=1, HOLD 0', { ...base, strategyParams: ['1', '0', '0', '0', '0', '0', '0', '0'] });
  await trial(vk, 'H params[0]=1, EXTRACT 10', { ...base, strategyParams: ['1', '0', '0', '0', '0', '0', '0', '0'], action: '2', amount: '10' });
})().catch(e => { console.error('ERR', e); process.exit(1); });
