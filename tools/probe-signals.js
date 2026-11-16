// Probe vfy-policy circom wasm input signal names by FNV-hash matching.
// Adapted from gatekeeper-agent/tools/probe-signals.js (same method).
const fs = require('fs');
const { WitnessCalculatorBuilder } = require('circom_runtime');

function fnvHash(str) {
  let h = 0xcbf29ce484222325n;
  const buf = Buffer.from(str, 'utf8');
  for (const b of buf) {
    h ^= BigInt(b);
    h = (h * 0x100000001b3n) & 0xffffffffffffffffn;
  }
  return h.toString(16).padStart(16, '0');
}

(async () => {
  const wasm = fs.readFileSync(process.argv[2] || 'circuits/vfy-policy.wasm');
  const wc = await WitnessCalculatorBuilder(wasm, {});
  const nInputs = wc.instance.exports.getInputSize();
  console.log('INPUT SIZE:', nInputs, '| WITNESS SIZE:', wc.witnessSize);

  const bases = [
    // from the publicInputsHash spec (build page)
    'commitment', 'strategyCommitment', 'commitmentHash', 'matchId', 'match_id',
    'turn', 'selfBalance', 'opponentBalance', 'self_balance', 'opponent_balance',
    'action', 'actionType', 'actionEnum', 'amount', 'circuitVersion', 'version',
    'publicInputsHash', 'inputsHash', 'hash',
    // envelope extras
    'salt', 'nonce', 'selfFortifiedUntilTurn', 'opponentFortifiedUntilTurn',
    'resolverVersion', 'eventId', 'mode', 'protocolVersion',
    // game mechanics
    'exposed', 'selfExposed', 'opponentExposed', 'spendable', 'selfSpendable',
    'opponentSpendable', 'fortifyCost', 'extractCap', 'maxExtract', 'maxAmount',
    'fortified', 'selfFortified', 'opponentFortified',
    // strategy / policy internals
    'strategy', 'policy', 'policyHash', 'strategyHash', 'threshold',
    'extractThreshold', 'fortifyThreshold', 'leadThreshold', 'behindThreshold',
    'turnsLeft', 'turnsRemaining', 'isLastTurn', 'isEarly', 'isLate',
    // validity / outcome
    'valid', 'isValid', 'policyOk', 'allowed', 'isAllowed', 'decision', 'ok',
    'in0', 'in1', 'in2', 'in3', 'in4', 'in5', 'in6', 'in7', 'in8', 'in9',
    'in10', 'in11', 'in12', 'in13', 'in14', 'in15',
    'a', 'b', 'c', 'd', 'e', 'f', 'x', 'y', 'input', 'output', 'out',
  ];
  const prefixes = ['', 'main.', 'in.', 'input.', 'main.input.'];
  for (const g of ['zzzz_not_a_signal_12345', 'qqqqqqqq']) {
    const h = fnvHash(g);
    const s = wc.instance.exports.getInputSignalSize(parseInt(h.slice(0, 8), 16), parseInt(h.slice(8, 16), 16));
    console.log('CONTROL:', g, 'size=', s);
  }
  const found = [];
  for (const p of prefixes) {
    for (const b of bases) {
      const name = p + b;
      const h = fnvHash(name);
      const hMSB = parseInt(h.slice(0, 8), 16);
      const hLSB = parseInt(h.slice(8, 16), 16);
      let size;
      try { size = wc.instance.exports.getInputSignalSize(hMSB, hLSB); } catch (e) { size = -1; }
      if (size > 0) {
        found.push({ name, size });
        console.log('FOUND:', name, 'size=', size);
      }
    }
  }
  console.log('TOTAL FOUND:', found.length, 'of', nInputs, 'inputs');
})().catch(e => { console.error('ERR', e); process.exit(1); });
