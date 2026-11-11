/**
 * Off-chain simulation of gatedswap.compact with the compiler-generated
 * Contract class and @midnight-ntwrk/compact-runtime 0.16.0: no network, no
 * proof server, no deploy. Every circuit runs exactly as it would before
 * proving, including witness calls, ledger reads/writes and asserts.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import * as RT from '@midnight-ntwrk/compact-runtime';
import { Contract, ledger, pureCircuits } from '../src/managed/gatedswap/contract/index.js';
import { pureCircuits as ShieldPass } from '../src/managed/shieldpass/contract/index.js';
import { quote, quoteDiv } from '../lib/quote.mjs';

const COIN = '0'.repeat(64);
const ADDR = RT.sampleContractAddress();
const b32 = () => new Uint8Array(randomBytes(32));
const hex = (b) => Buffer.from(b).toString('hex');

const P = pureCircuits;
const NOW = 1_792_000_000n; // 2026-10-15-ish, unix seconds
const YEAR = 31_556_952n;
const OFFSET_1900 = 2_208_988_800n;
const born = (unix) => BigInt(unix) + OFFSET_1900;
const yearsAgo = (y, extra = 0n) => born(NOW - BigInt(y) * YEAR + extra);

const US = 840n, DE = 276n, KP = 408n, IR = 364n, CU = 192n;
const POOL_A = 1_000_000n;
const POOL_B = 1_000_000n;
const START_A = 10_000n;

const operatorSk = b32();
const OP = { sk: operatorSk };

const witnesses = {
  localSecretKey: ({ privateState }) => [privateState, privateState.sk],
  heldCredential: ({ privateState }) => [privateState, privateState.credential],
  credentialPath: ({ privateState, ledger: l }, leaf) => {
    const p = privateState.path ?? l.credentials.findPathForLeaf(leaf);
    if (!p) throw new Error('credential not in registry (no Merkle path)');
    return [privateState, p];
  },
  quoteDiv: ({ privateState }, numer, denom) => [privateState, quoteDiv(numer, denom)],
};
const contract = new Contract(witnesses);
const as = (sk, extra = {}) => ({ sk, ...extra });

function deploy(app = b32(), policy = rules(), a = POOL_A, b = POOL_B) {
  return {
    app,
    state: contract.initialState(RT.createConstructorContext(OP, COIN), app, policy, a, b).currentContractState,
  };
}
function call(state, ps, name, args, time = NOW) {
  const ctx = RT.createCircuitContext(ADDR, COIN, state, ps, undefined, undefined, Number(time));
  return contract.impureCircuits[name](ctx, ...args).context.currentQueryContext.state;
}
const L = (s) => ledger(s);
const bal = (s, book, who) => {
  const m = L(s)[book];
  return m.member(who) ? m.lookup(who) : 0n;
};

const rules = (o = {}) => ({
  minKycLevel: 1n,
  requireSanctionsClear: true,
  requireAccredited: false,
  minAge: 18n,
  blockedCountries: [KP, IR, CU, 0n, 0n, 0n, 0n, 0n],
  ...o,
});

function credential(holderSk, o = {}) {
  return {
    holder: P.roleCommitment(holderSk, P.holderTag()),
    country: US,
    birthDate: yearsAgo(30),
    kycLevel: 2n,
    sanctionsClear: true,
    accredited: false,
    expiry: NOW + 365n * 86_400n,
    salt: b32(),
    ...o,
  };
}

/** Deploy a pool, admit `cred`, credit `recipient` with START_A of asset A. */
function ready(holderSk, credOpts = {}, policy = rules()) {
  const recipient = b32();
  const { app, state: deployed } = deploy(b32(), policy);
  const cred = credential(holderSk, credOpts);
  const leaf = P.credentialLeaf(cred);
  let s = call(deployed, OP, 'admitLeaf', [leaf]);
  s = call(s, OP, 'credit', [recipient, START_A, 0n]);
  return { app, state: s, cred, leaf, recipient };
}

const swap = (s, holderSk, cred, { sid = b32(), amountIn = 1_000n, minOut, aToB = true, now = NOW, time = now, recipient, path } = {}) => {
  const q = quote(aToB ? L(s).reserveA : L(s).reserveB, aToB ? L(s).reserveB : L(s).reserveA, amountIn);
  return {
    sid,
    amountOut: q,
    state: call(s, as(holderSk, { credential: cred, ...(path ? { path } : {}) }), 'swap', [sid, amountIn, minOut ?? q, aToB, now, recipient], time),
  };
};

// ---------------------------------------------------------------- constructor and operator

test('constructor fixes the operator, app id, rules and positive reserves', () => {
  const app = b32();
  const { state } = deploy(app);
  const l = L(state.data);
  assert.equal(hex(l.operator), hex(P.roleCommitment(operatorSk, P.operatorTag())));
  assert.equal(hex(l.appId), hex(app));
  assert.equal(l.reserveA, POOL_A);
  assert.equal(l.reserveB, POOL_B);
  assert.equal(l.rules.minAge, 18n);
  assert.equal(l.swaps, 0n);
  assert.throws(() => deploy(new Uint8Array(32)), /empty app id/);
  assert.throws(() => deploy(b32(), rules(), 0n, POOL_B), /reserves must be positive/);
  assert.throws(() => deploy(b32(), rules(), POOL_A, 0n), /reserves must be positive/);
});

test('admitLeaf, credit, fund and setRules are operator-only', () => {
  const { app, state } = deploy();
  const stranger = as(b32());
  const leaf = P.credentialLeaf(credential(b32()));
  const who = b32();
  assert.throws(() => call(state, stranger, 'admitLeaf', [leaf]), /not the operator/);
  assert.throws(() => call(state, stranger, 'credit', [who, 1n, 0n]), /not the operator/);
  assert.throws(() => call(state, stranger, 'fund', [1n, 1n]), /not the operator/);
  assert.throws(() => call(state, stranger, 'setRules', [rules({ minAge: 21n })]), /not the operator/);
  let s = call(state, OP, 'admitLeaf', [leaf]);
  assert.equal(L(s).credentialSlots, 1n);
  assert.ok(L(s).credentialIndex.member(leaf));
  assert.throws(() => call(s, OP, 'admitLeaf', [leaf]), /already admitted/);
  assert.throws(() => call(s, OP, 'admitLeaf', [new Uint8Array(32)]), /empty credential leaf/);
  s = call(s, OP, 'credit', [who, 50n, 7n]);
  assert.equal(bal(s, 'balanceA', who), 50n);
  assert.equal(bal(s, 'balanceB', who), 7n);
  assert.throws(() => call(s, OP, 'credit', [new Uint8Array(32), 1n, 0n]), /empty recipient/);
  s = call(s, OP, 'fund', [100n, 200n]);
  assert.equal(L(s).reserveA, POOL_A + 100n);
  assert.equal(L(s).reserveB, POOL_B + 200n);
  s = call(s, OP, 'setRules', [rules({ minAge: 21n })]);
  assert.equal(L(s).rules.minAge, 21n);
});

// ---------------------------------------------------------------- the gate

test('swap refuses a holder whose credential was never admitted', () => {
  const holder = b32();
  const { state, recipient } = ready(holder);
  const outsider = b32();
  const cred = credential(outsider);
  assert.throws(() => swap(state, outsider, cred, { recipient }), /not in registry|not in the live registry/);
});

test('predicates: expiry, KYC, sanctions, accreditation, minimum age, blocked countries', () => {
  const h = b32();
  const cases = [
    [{ expiry: NOW }, /credential expired/],
    [{ kycLevel: 0n }, /KYC level below/],
    [{ sanctionsClear: false }, /sanctions screening required/],
    [{ birthDate: yearsAgo(18, 3600n) }, /below minimum age/],
    [{ country: KP }, /country is blocked/],
    [{ country: CU }, /country is blocked/],
    [{ country: 0n }, /no country/],
  ];
  for (const [o, re] of cases) {
    const w = ready(h, o);
    assert.throws(() => swap(w.state, h, w.cred, { recipient: w.recipient }), re, JSON.stringify(o, (_, v) => (typeof v === 'bigint' ? String(v) : v)));
  }
  for (const o of [{ birthDate: yearsAgo(18) }, { country: DE }]) {
    const w = ready(h, o);
    const { state } = swap(w.state, h, w.cred, { recipient: w.recipient });
    assert.equal(L(state).swaps, 1n);
  }
  const accNeeded = ready(h, { birthDate: yearsAgo(25) }, rules({ requireAccredited: true, minAge: 21n }));
  assert.throws(() => swap(accNeeded.state, h, accNeeded.cred, { recipient: accNeeded.recipient }), /accredited investor status required/);
  const accOk = ready(h, { birthDate: yearsAgo(40), accredited: true }, rules({ requireAccredited: true, minAge: 21n }));
  swap(accOk.state, h, accOk.cred, { recipient: accOk.recipient });
});

test('the proof must open an admitted leaf held by the caller: no forged attributes, no borrowed credential', () => {
  const h = b32();
  const w = ready(h, { country: KP });
  const realPath = L(w.state).credentials.findPathForLeaf(w.leaf);
  assert.throws(() => swap(w.state, h, { ...w.cred, country: US }, { recipient: w.recipient, path: realPath }), /path does not lead/);
  assert.throws(() => swap(w.state, h, { ...w.cred, country: US }, { recipient: w.recipient }), /not in registry/);
  const good = ready(h);
  assert.throws(() => swap(good.state, b32(), good.cred, { recipient: good.recipient }), /not held by this key/);
});

test('`now` must match the block time within the freshness window', () => {
  const h = b32();
  const w = ready(h);
  swap(w.state, h, w.cred, { recipient: w.recipient, now: NOW, time: NOW + 899n });
  assert.throws(() => swap(w.state, h, w.cred, { recipient: w.recipient, now: NOW, time: NOW + 901n }), /too far from the block time/);
  assert.throws(() => swap(w.state, h, w.cred, { recipient: w.recipient, now: NOW + 3600n, time: NOW }), /too far from the block time/);
});

// ---------------------------------------------------------------- the swap itself

test('a compliant swap moves balances and reserves at the constant-product quote and hides the credential', () => {
  const h = b32();
  const w = ready(h);
  const amountIn = 1_000n;
  const expected = quote(POOL_A, POOL_B, amountIn);
  assert.equal(expected, 999n);
  const sid = b32();
  const { state, amountOut } = swap(w.state, h, w.cred, { sid, amountIn, recipient: w.recipient });
  assert.equal(amountOut, expected);
  const l = L(state);
  assert.equal(l.reserveA, POOL_A + amountIn);
  assert.equal(l.reserveB, POOL_B - expected);
  assert.equal(bal(state, 'balanceA', w.recipient), START_A - amountIn);
  assert.equal(bal(state, 'balanceB', w.recipient), expected);
  assert.equal(l.swaps, 1n);
  assert.equal(l.volumeA, amountIn);
  assert.equal(l.volumeB, 0n);
  const key = P.sessionKey(w.app, sid);
  assert.ok(l.usedSessions.member(key));
  assert.equal(l.fillOut.lookup(key), expected);
  assert.equal(hex(l.fillNullifier.lookup(key)), hex(P.appNullifier(w.app, h)));
  // the public fill records do not carry the leaf, holder commitment or secret
  const publicHex = [hex(l.fillNullifier.lookup(key))];
  for (const secret of [w.leaf, w.cred.holder, w.cred.salt, h]) assert.ok(!publicHex.includes(hex(secret)));
});

test('B-to-A swaps, slippage, zero input, insufficient balance and empty recipient are refused', () => {
  const h = b32();
  const { app, state: deployed } = deploy();
  const cred = credential(h);
  let s = call(deployed, OP, 'admitLeaf', [P.credentialLeaf(cred)]);
  const who = b32();
  s = call(s, OP, 'credit', [who, 0n, 5_000n]);
  const expected = quote(POOL_B, POOL_A, 1_000n);
  const { state, amountOut } = swap(s, h, cred, { amountIn: 1_000n, aToB: false, recipient: who });
  assert.equal(amountOut, expected);
  assert.equal(L(state).reserveB, POOL_B + 1_000n);
  assert.equal(L(state).reserveA, POOL_A - expected);
  assert.equal(bal(state, 'balanceB', who), 5_000n - 1_000n);
  assert.equal(bal(state, 'balanceA', who), expected);

  const w = ready(h);
  assert.throws(() => swap(w.state, h, w.cred, { recipient: w.recipient, amountIn: 1_000n, minOut: 1_000n }), /slippage/);
  assert.throws(() => swap(w.state, h, w.cred, { recipient: w.recipient, amountIn: 0n, minOut: 0n }), /zero input/);
  assert.throws(() => swap(w.state, h, w.cred, { recipient: w.recipient, amountIn: START_A + 1n, minOut: 1n }), /insufficient balance/);
  assert.throws(() => swap(w.state, h, w.cred, { recipient: new Uint8Array(32) }), /empty recipient/);
});

test('a session is consumed by the first fill; a second session from the same holder still works and keeps the same nullifier', () => {
  const h = b32();
  const w = ready(h);
  const sid = b32();
  const first = swap(w.state, h, w.cred, { sid, recipient: w.recipient, amountIn: 100n });
  assert.throws(() => swap(first.state, h, w.cred, { sid, recipient: w.recipient, amountIn: 100n }), /session already used/);
  const second = swap(first.state, h, w.cred, { recipient: w.recipient, amountIn: 100n });
  assert.equal(L(second.state).swaps, 2n);
  const n1 = L(first.state).fillNullifier.lookup(P.sessionKey(w.app, sid));
  const n2 = L(second.state).fillNullifier.lookup(P.sessionKey(w.app, second.sid));
  assert.equal(hex(n1), hex(n2), 'stable per-app nullifier');
  assert.equal(hex(n1), hex(P.appNullifier(w.app, h)));
});

test('historic roots: a path fetched before later admissions still verifies', () => {
  const h = b32();
  const w = ready(h);
  const cached = L(w.state).credentials.findPathForLeaf(w.leaf);
  let s = w.state;
  for (let i = 0; i < 3; i++) s = call(s, OP, 'admitLeaf', [P.credentialLeaf(credential(b32()))]);
  assert.equal(L(s).credentialSlots, 4n);
  swap(s, h, w.cred, { recipient: w.recipient, path: cached });
});

test('tightening the rules after admission blocks a previously eligible holder', () => {
  const h = b32();
  const w = ready(h, { birthDate: yearsAgo(20) });
  swap(w.state, h, w.cred, { recipient: w.recipient, amountIn: 10n });
  const tightened = call(w.state, OP, 'setRules', [rules({ minAge: 21n })]);
  assert.throws(() => swap(tightened, h, w.cred, { recipient: w.recipient, amountIn: 10n }), /below minimum age/);
});

// ---------------------------------------------------------------- compatibility with ShieldPass

test('credentialLeaf, sessionKey, appNullifier and roleCommitment match shieldpass.compact byte for byte', () => {
  for (let i = 0; i < 8; i++) {
    const [a, b] = [b32(), b32()];
    assert.equal(hex(P.sessionKey(a, b)), hex(ShieldPass.sessionKey(a, b)));
    assert.equal(hex(P.appNullifier(a, b)), hex(ShieldPass.appNullifier(a, b)));
    assert.equal(hex(P.roleCommitment(b, P.holderTag())), hex(ShieldPass.roleCommitment(b, ShieldPass.holderTag())));
    const c = credential(a);
    assert.equal(hex(P.credentialLeaf(c)), hex(ShieldPass.credentialLeaf(c)));
  }
  assert.equal(P.secondsPerYear(), ShieldPass.secondsPerYear());
  assert.equal(P.epoch1900Offset(), ShieldPass.epoch1900Offset());
  assert.equal(P.freshness(), ShieldPass.freshness());
});
