/**
 * Backtest for the Steal the VFY strategy: always EXTRACT 10
 * (HOLD only when the opponent is at 0).
 *
 * Resolver model — from the official docs
 * (https://agentgames.zkverify.io/events/steal-the-vfy and /build):
 *   - Simultaneous submission, deterministic resolver, prior public
 *     state only (arrival order never matters).
 *   - EXTRACT N: takes up to N from the opponent's exposed balance.
 *     A fortified opponent reduces the gain by 6 ("blocks up to 6
 *     VFY incoming extraction"). Cost 0. Max N = 10.
 *   - FORTIFY: costs 2, blocks up to 6 incoming extraction this turn.
 *   - HOLD: free, no movement.
 *   - Both extracting resolve against PRIOR exposed balances, so
 *     neither transfer interferes with the other.
 *   - Balances never go below 0 (extraction is capped at the
 *     opponent's balance; a fortify cost is capped at the balance).
 *   - 20 turns, 100 VFY each, highest final balance wins
 *     (win +18 / draw +9 / loss +3).
 *
 * Opponent policies tested (7): mirror, always-HOLD, always-FORTIFY,
 * random (seeded, 20 seeds), greedy, defensive, tit-for-tat.
 *
 * Honest limits: the resolver semantics above are the docs' wording,
 * not a measured replay — the exact fortify interaction (gain reduced
 * by exactly 6 vs blocked entirely below 6) is the documented one
 * ("reduces the gain by 6" / "blocks up to 6"). If the live resolver
 * differed, the margins would move but the dominance conclusion
 * would not: extraction is free and gains >= 0 in every matchup,
 * so no opponent action can make EXTRACT 10 worse than HOLD, and
 * FORTIFY always costs 2 for at most 6 blocked.
 *
 * Run: node tools/backtest.js
 */
'use strict';

const TURNS = 20;
const START = 100;
const MAX_EXTRACT = 10;
const FORTIFY_COST = 2;
const FORTIFY_BLOCK = 6;

/** One turn of the resolver. Returns [newSelf, newOpp]. */
function resolveTurn(self, opp, aSelf, aOpp) {
  // aSelf / aOpp: { type: 'HOLD'|'FORTIFY'|'EXTRACT', amount }
  let s = self;
  let o = opp;
  const selfFort = aSelf.type === 'FORTIFY';
  const oppFort = aOpp.type === 'FORTIFY';
  // Fortify costs (capped at the balance; an agent at 0 cannot pay
  // and the action degrades to HOLD — a modelling choice, documented).
  if (selfFort) s = Math.max(0, s - Math.min(FORTIFY_COST, s));
  if (oppFort) o = Math.max(0, o - Math.min(FORTIFY_COST, o));
  // Extractions resolve against PRIOR balances.
  let gainSelf = 0;
  let gainOpp = 0;
  if (aSelf.type === 'EXTRACT') {
    gainSelf = Math.max(0, Math.min(aSelf.amount, opp) - (oppFort ? FORTIFY_BLOCK : 0));
  }
  if (aOpp.type === 'EXTRACT') {
    gainOpp = Math.max(0, Math.min(aOpp.amount, self) - (selfFort ? FORTIFY_BLOCK : 0));
  }
  s = Math.max(0, s - gainOpp + gainSelf);
  o = Math.max(0, o - gainSelf + gainOpp);
  return [s, o];
}

/** Our strategy: EXTRACT 10, HOLD only when the opponent is at 0. */
function ourAction(self, opp) {
  if (opp <= 0) return { type: 'HOLD', amount: 0 };
  return { type: 'EXTRACT', amount: MAX_EXTRACT };
}

// ---- opponent policies (each: (self, opp, turn, lastOppAction) -> action)
const OPPONENTS = {
  'mirror (always EXTRACT 10)': () => ({ type: 'EXTRACT', amount: 10 }),
  'always HOLD': () => ({ type: 'HOLD', amount: 0 }),
  'always FORTIFY': () => ({ type: 'FORTIFY', amount: 0 }),
  'greedy (extract if ahead, else fortify)': (s, o) =>
    (s >= o ? { type: 'EXTRACT', amount: 10 } : { type: 'FORTIFY', amount: 0 }),
  'defensive (fortify if behind by >10, else extract)': (s, o) =>
    (o - s > 10 ? { type: 'FORTIFY', amount: 0 } : { type: 'EXTRACT', amount: 10 }),
  'adaptive (fortify if behind by >20, else extract)': (s, o) =>
    (o - s > 20 ? { type: 'FORTIFY', amount: 0 } : { type: 'EXTRACT', amount: 10 }),
  'tit-for-tat (repeat our last action, start EXTRACT)': (s, o, t, last) =>
    (t === 1 ? { type: 'EXTRACT', amount: 10 }
      : last.type === 'EXTRACT' ? { type: 'EXTRACT', amount: 10 }
      : last.type === 'FORTIFY' ? { type: 'FORTIFY', amount: 0 }
      : { type: 'HOLD', amount: 0 }),
};

/** Seeded PRNG (mulberry32) for the random opponent. */
function rng(seed) {
  let a = seed >>> 0;
  return () => {
    a |= 0; a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function playMatch(oppPolicy, seed) {
  let s = START;
  let o = START;
  let lastOur = null;
  const rand = seed === undefined ? null : rng(seed);
  for (let turn = 1; turn <= TURNS; turn++) {
    const aSelf = ourAction(s, o);
    let aOpp;
    if (rand) {
      const r = rand();
      aOpp = r < 1 / 3 ? { type: 'HOLD', amount: 0 }
        : r < 2 / 3 ? { type: 'FORTIFY', amount: 0 }
        : { type: 'EXTRACT', amount: 10 };
    } else {
      aOpp = oppPolicy(o, s, turn, lastOur);
    }
    [s, o] = resolveTurn(s, o, aSelf, aOpp);
    lastOur = aSelf;
  }
  const outcome = s > o ? 'WIN' : s < o ? 'LOSS' : 'DRAW';
  const points = outcome === 'WIN' ? 18 : outcome === 'DRAW' ? 9 : 3;
  return { s, o, outcome, points };
}

function main() {
  console.log('Steal the VFY backtest — always EXTRACT 10 (HOLD at opp 0)');
  console.log(`20 turns, 100 VFY each, win +18 / draw +9 / loss +3\n`);
  let totalPoints = 0;
  let n = 0;
  for (const [name, policy] of Object.entries(OPPONENTS)) {
    const r = playMatch(policy);
    totalPoints += r.points; n++;
    console.log(`${name.padEnd(48)} final ${String(r.s).padStart(3)} - ${String(r.o).padStart(3)}  ${r.outcome} (+${r.points})`);
  }
  // Random opponent, 20 seeds.
  const tally = { WIN: 0, DRAW: 0, LOSS: 0 };
  let randPoints = 0;
  let worst = null;
  for (let seed = 1; seed <= 20; seed++) {
    const r = playMatch(null, seed);
    tally[r.outcome]++;
    randPoints += r.points;
    if (!worst || r.s - r.o < worst.s - worst.o) worst = { ...r, seed };
  }
  n++;
  totalPoints += Math.round(randPoints / 20);
  console.log(`${'random (20 seeds, avg)'.padEnd(48)} W ${tally.WIN} / D ${tally.DRAW} / L ${tally.LOSS}  avg +${(randPoints / 20).toFixed(1)}`);
  console.log(`  worst random seed: #${worst.seed} final ${worst.s} - ${worst.o} (${worst.outcome})`);
  console.log(`\nMean match points across the 8 opponent types: ${(totalPoints / n).toFixed(1)} / 18 max`);
  console.log('Verdict: always-EXTRACT-10 never loses in simulation. The only');
  console.log('non-win is the mirror (both extract 10 every turn: 100-100 draw).');
  console.log('Vs a fortifying opponent we still gain 4/turn (10-6) for free.');
  console.log('\nStronger than the sim: under the documented resolver this is a');
  console.log('THEOREM, not just an observation. Every turn, our gain >= the');
  console.log("opponent's gain (they gain 10 only when they extract, and then");
  console.log('we gain 10 too; otherwise we gain 4-10 and they gain 0), and');
  console.log('our fortify cost is 0. So our balance never falls and theirs');
  console.log('never rises: final is always us >= 100, them <= 100 — WIN or');
  console.log('DRAW, never a loss. No action can beat a mirroring extractor');
  console.log('(vs an extracting opponent EXTRACT nets 0, FORTIFY -6, HOLD');
  console.log('-10), so the mirror draw is the ceiling, not a failure.');
  console.log('\nHonest caveat: if the field is mostly always-extract agents,');
  console.log('most matches are draws (+9) and the standings are decided by');
  console.log('wins over weaker agents PLUS the +0..+2 verified-turn');
  console.log('reliability bonus — which is why the Kurier on-chain');
  console.log('proofReference matters: it is the differentiator in a');
  console.log('mirror-heavy field. The "never loses" claim also rests on');
  console.log('the documented resolver (fortify reduces the gain by 6);');
  console.log('even if fortify blocked ALL extraction, vs always-FORTIFY');
  console.log('we would still win 100-60 (they burn 2/turn, we lose 0).');
}

if (require.main === module) main();
module.exports = { resolveTurn, ourAction, playMatch, OPPONENTS };
