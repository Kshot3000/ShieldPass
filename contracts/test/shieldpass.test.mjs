/**
 * Off-chain simulation of shieldpass.compact with the compiler-generated
 * Contract class and @midnight-ntwrk/compact-runtime 0.16.0: no network, no
 * proof server, no deploy. Every circuit runs exactly as it would before
 * proving, including witness calls, ledger reads/writes and asserts.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, createHash } from 'node:crypto';
import * as RT from '@midnight-ntwrk/compact-runtime';
import { Contract, ledger, pureCircuits, CredentialStatus } from '../src/managed/shieldpass/contract/index.js';

const COIN = '0'.repeat(64);
const ADDR = RT.sampleContractAddress();
const b32 = () => new Uint8Array(randomBytes(32));
const hex = (b) => Buffer.from(b).toString('hex');
const pad32 = (s) => {
  const out = new Uint8Array(32);
  out.set(new TextEncoder().encode(s));
  return out;
};
const sha = (...parts) => new Uint8Array(createHash('sha256').update(Buffer.concat(parts.map((p) => Buffer.from(p)))).digest());

const P = pureCircuits;
const NOW = 1_792_000_000n; // 2026-10-15-ish, unix seconds
const YEAR = 31_556_952n;
const OFFSET_1900 = 2_208_988_800n;
/** unix seconds -> the contract's birthDate (seconds since 1900-01-01). */
const born = (unix) => BigInt(unix) + OFFSET_1900;
const yearsAgo = (y, extra = 0n) => born(NOW - BigInt(y) * YEAR + extra);

const US = 840n, DE = 276n, KP = 408n, IR = 364n, CU = 192n;

const operatorSk = b32();
const issuerSks = [b32(), b32(), b32()];
const seats = issuerSks.map((sk) => P.roleCommitment(sk, P.issuerTag()));

/* Witnesses: private state = { sk, credential?, path? (a cached path, to model stale-root attacks) }. */
const witnesses = {
  localSecretKey: ({ privateState }) => [privateState, privateState.sk],
  heldCredential: ({ privateState }) => [privateState, privateState.credential],
  credentialPath: ({ privateState, ledger: l }, leaf) => {
    const p = privateState.path ?? l.credentials.findPathForLeaf(leaf);
    if (!p) throw new Error('credential not in registry (no Merkle path)');
    return [privateState, p];
  },
};
const contract = new Contract(witnesses);
const as = (sk, extra = {}) => ({ sk, ...extra });
const I = issuerSks.map((sk) => as(sk));
const OP = as(operatorSk);

function deploy(m = 2n, members = seats) {
  return contract.initialState(RT.createConstructorContext(OP, COIN), members, m).currentContractState;
}
function call(state, ps, name, args, time = NOW) {
  const ctx = RT.createCircuitContext(ADDR, COIN, state, ps, undefined, undefined, Number(time));
  return contract.impureCircuits[name](ctx, ...args).context.currentQueryContext.state;
}
const L = (s) => ledger(s);

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

/** Issue a credential through `approvers` issuer seats; returns { state, cred, leaf }. */
function issue(state, holderSk, o = {}, approvers = [0, 1]) {
  const cred = credential(holderSk, o);
  const leaf = P.credentialLeaf(cred);
  for (const i of approvers) state = call(state, I[i], 'approveCredential', [leaf]);
  return { state, cred, leaf };
}

const APP = b32();
const APP2 = b32();
function world({ m = 2n, appRules = rules() } = {}) {
  let s = deploy(m);
  s = call(s, OP, 'registerApp', [APP, appRules]);
  s = call(s, OP, 'registerApp', [APP2, rules({ minAge: 21n, requireAccredited: true })]);
  return s;
}
const verify = (s, holderSk, cred, { app = APP, sid = b32(), now = NOW, time = now, path } = {}) =>
  call(s, as(holderSk, { credential: cred, ...(path ? { path } : {}) }), 'verifySession', [app, sid, now], time);
const sessionOf = (s, app, sid) => {
  const k = P.sessionKey(app, sid);
  return L(s).verified.member(k) ? L(s).verified.lookup(k) : null;
};

// ---------------------------------------------------------------- committee

test('constructor fixes three distinct issuer seats, a 1..3 threshold and the operator', () => {
  const l = L(deploy().data);
  assert.equal(l.threshold, 2n);
  assert.deepEqual(l.issuers.map(hex), seats.map(hex));
  assert.equal(hex(l.operator), hex(P.roleCommitment(operatorSk, P.operatorTag())));
  assert.throws(() => deploy(0n), /threshold must be 1..3/);
  assert.throws(() => deploy(4n), /threshold must be 1..3/);
  assert.throws(() => deploy(2n, [seats[0], seats[0], seats[2]]), /distinct/);
  assert.throws(() => deploy(2n, [seats[0], new Uint8Array(32), seats[2]]), /empty issuer seat/);
});

test('2-of-3 issuance: one approval is PENDING and not provable, the second makes it ACTIVE', () => {
  let s = world();
  const holder = b32();
  const cred = credential(holder);
  const leaf = P.credentialLeaf(cred);
  s = call(s, I[0], 'approveCredential', [leaf]);
  assert.equal(L(s).credentialStatus.lookup(leaf), CredentialStatus.PENDING);
  assert.equal(L(s).credentialsIssued, 0n);
  assert.throws(() => verify(s, holder, cred), /not in registry|not in the live registry/);
  s = call(s, I[2], 'approveCredential', [leaf]);
  const l = L(s);
  assert.equal(l.credentialStatus.lookup(leaf), CredentialStatus.ACTIVE);
  assert.equal(l.credentialsIssued, 1n);
  assert.equal(l.credentialIndex.lookup(leaf), 0n);
  assert.equal(l.issueApprovals.lookup(leaf), 2n);
  assert.ok(l.issuerVotes.member(P.voteKey(P.issueAction(), leaf, seats[0])));
  assert.ok(!l.issuerVotes.member(P.voteKey(P.issueAction(), leaf, seats[1])));
  verify(s, holder, cred);
});

test('a seat cannot approve twice; operator, holders and strangers cannot approve at all', () => {
  let s = world();
  const leaf = P.credentialLeaf(credential(b32()));
  s = call(s, I[1], 'approveCredential', [leaf]);
  assert.throws(() => call(s, I[1], 'approveCredential', [leaf]), /already approved/);
  for (const ps of [OP, as(b32())]) assert.throws(() => call(s, ps, 'approveCredential', [leaf]), /not an issuer seat/);
  assert.throws(() => call(s, I[0], 'approveCredential', [new Uint8Array(32)]), /empty credential leaf/);
});

test('an issued credential cannot be approved again (no duplicate leaves), threshold 1 and 3 behave', () => {
  let s = world();
  const { state, leaf } = issue(s, b32());
  assert.throws(() => call(state, I[2], 'approveCredential', [leaf]), /already issued or revoked/);
  const t1 = issue(world({ m: 1n }), b32(), {}, [2]);
  assert.equal(L(t1.state).credentialStatus.lookup(t1.leaf), CredentialStatus.ACTIVE);
  const t3 = issue(world({ m: 3n }), b32(), {}, [0, 1]);
  assert.equal(L(t3.state).credentialStatus.lookup(t3.leaf), CredentialStatus.PENDING);
  const done = call(t3.state, I[2], 'approveCredential', [t3.leaf]);
  assert.equal(L(done).credentialStatus.lookup(t3.leaf), CredentialStatus.ACTIVE);
});

// ---------------------------------------------------------------- holder proof

test('verifySession writes one SessionRecord (app, per-app nullifier, policy version, time) and nothing about the holder', () => {
  const holder = b32();
  const { state, cred, leaf } = issue(world(), holder);
  const sid = b32();
  const s = verify(state, holder, cred, { sid });
  const r = sessionOf(s, APP, sid);
  assert.ok(r);
  assert.equal(hex(r.appId), hex(APP));
  assert.equal(hex(r.nullifier), hex(P.appNullifier(APP, holder)));
  assert.equal(r.policyVersion, 1n);
  assert.equal(r.verifiedAt, NOW);
  assert.equal(L(s).sessionsVerified, 1n);
  // the record carries no credential leaf, holder commitment or attribute
  const rec = [r.appId, r.nullifier].map(hex);
  for (const secret of [leaf, cred.holder, cred.salt, holder]) assert.ok(!rec.includes(hex(secret)));
});

test('predicates: expiry, KYC level, sanctions, accreditation, minimum age, blocked countries', () => {
  const h = b32();
  const cases = [
    [{ expiry: NOW }, /credential expired/],
    [{ kycLevel: 0n }, /KYC level below/],
    [{ sanctionsClear: false }, /sanctions screening required/],
    [{ birthDate: yearsAgo(18, 3600n) }, /below minimum age/], // turns 18 in an hour
    [{ country: KP }, /country is blocked/],
    [{ country: CU }, /country is blocked/],
    [{ country: 0n }, /no country/],
  ];
  for (const [o, re] of cases) {
    const { state, cred } = issue(world(), h, o);
    assert.throws(() => verify(state, h, cred), re, JSON.stringify(o, (_, v) => (typeof v === 'bigint' ? String(v) : v)));
  }
  // exactly 18 today passes; DE passes; APP2 additionally needs accreditation and 21+
  for (const o of [{ birthDate: yearsAgo(18) }, { country: DE }]) {
    const { state, cred } = issue(world(), h, o);
    verify(state, h, cred);
  }
  const plain = issue(world(), h, { birthDate: yearsAgo(25) });
  assert.throws(() => verify(plain.state, h, plain.cred, { app: APP2 }), /accredited investor status required/);
  const acc = issue(world(), h, { birthDate: yearsAgo(20), accredited: true });
  assert.throws(() => verify(acc.state, h, acc.cred, { app: APP2 }), /below minimum age/);
  const ok = issue(world(), h, { birthDate: yearsAgo(40), accredited: true });
  verify(ok.state, h, ok.cred, { app: APP2 });
});

test('rules that do not ask for sanctions screening accept an unscreened credential', () => {
  const h = b32();
  const { state, cred } = issue(world({ appRules: rules({ requireSanctionsClear: false, minAge: 0n, minKycLevel: 0n }) }), h, { sanctionsClear: false, kycLevel: 0n, birthDate: yearsAgo(5) });
  verify(state, h, cred);
});

test('the proof must open a registry leaf held by the caller: no forged attributes, no borrowed credential', () => {
  const h = b32();
  const { state, cred } = issue(world(), h, { country: KP });
  // lie about the country: the leaf changes, so the path no longer leads to it
  const realPath = L(state).credentials.findPathForLeaf(P.credentialLeaf(cred));
  assert.throws(() => verify(state, h, { ...cred, country: US }, { path: realPath }), /path does not lead/);
  assert.throws(() => verify(state, h, { ...cred, country: US }), /not in registry/);
  // someone else's key cannot use it
  const good = issue(world(), h);
  assert.throws(() => verify(good.state, b32(), good.cred), /not held by this key/);
  // an unissued credential with a self-made path never matches a registry root
  const fake = credential(h);
  assert.throws(() => verify(good.state, h, fake, { path: { ...realPath, leaf: P.credentialLeaf(fake) } }), /not in the live registry/);
});

test('replay and cross-app: a session verifies once, is scoped to its app, nullifiers are per-app pseudonyms', () => {
  const h = b32();
  const { state, cred } = issue(world({ appRules: rules() }), h, { accredited: true });
  const sid = b32();
  let s = verify(state, h, cred, { sid });
  assert.throws(() => verify(s, h, cred, { sid }), /session already verified/);
  assert.equal(sessionOf(s, APP2, sid), null, 'app A session is not visible under app B');
  s = verify(s, h, cred, { sid, app: APP2 }); // same session id in another app is a different key
  const a = sessionOf(s, APP, sid).nullifier;
  const b = sessionOf(s, APP2, sid).nullifier;
  assert.notEqual(hex(a), hex(b), 'unlinkable across apps');
  s = verify(s, h, cred);
  const sessions = [...L(s).verified].map(([, r]) => r).filter((r) => hex(r.appId) === hex(APP));
  assert.equal(sessions.length, 2);
  assert.equal(hex(sessions[0].nullifier), hex(sessions[1].nullifier), 'stable inside one app (one account per person)');
  // a different holder in the same app gets a different nullifier
  const h2 = b32();
  const two = issue(s, h2);
  const sid2 = b32();
  s = verify(two.state, h2, two.cred, { sid: sid2 });
  assert.notEqual(hex(sessionOf(s, APP, sid2).nullifier), hex(a));
});

test('`now` must match the block time within the freshness window', () => {
  const h = b32();
  const { state, cred } = issue(world(), h);
  verify(state, h, cred, { now: NOW, time: NOW + 899n });
  assert.throws(() => verify(state, h, cred, { now: NOW, time: NOW + 901n }), /too far from the block time/);
  assert.throws(() => verify(state, h, cred, { now: NOW + 3600n, time: NOW }), /too far from the block time/);
  // an expired credential can't dodge expiry by back-dating `now`
  const old = issue(world(), h, { expiry: NOW - 10n });
  assert.throws(() => verify(old.state, h, old.cred, { now: NOW - 3600n, time: NOW }), /too far from the block time/);
});

// ---------------------------------------------------------------- registry roots and revocation

test('historic roots: a path fetched before later issuances still verifies', () => {
  const h = b32();
  let { state, cred, leaf } = issue(world(), h);
  const cached = L(state).credentials.findPathForLeaf(leaf);
  for (let i = 0; i < 3; i++) state = issue(state, b32()).state;
  assert.equal(L(state).credentialsIssued, 4n);
  verify(state, h, cred, { path: cached });
});

test('2-of-3 revocation: one vote changes nothing, the second kills current and cached proofs; others keep working', () => {
  const h = b32();
  const other = b32();
  let { state, cred, leaf } = issue(world(), h);
  const o = issue(state, other);
  state = o.state;
  const cached = L(state).credentials.findPathForLeaf(leaf);
  state = call(state, I[0], 'revokeCredential', [leaf]);
  assert.throws(() => call(state, I[0], 'revokeCredential', [leaf]), /already voted to revoke/);
  assert.throws(() => call(state, OP, 'revokeCredential', [leaf]), /not an issuer seat/);
  verify(state, h, cred); // still live after 1 of 2
  state = call(state, I[1], 'revokeCredential', [leaf]);
  const l = L(state);
  assert.equal(l.credentialStatus.lookup(leaf), CredentialStatus.REVOKED);
  assert.equal(l.credentialsRevoked, 1n);
  assert.equal(l.credentials.findPathForLeaf(leaf), undefined);
  assert.throws(() => verify(state, h, cred), /not in registry/);
  assert.throws(() => verify(state, h, cred, { path: cached }), /not in the live registry/, 'stale root rejected after resetHistory');
  verify(state, other, o.cred); // fresh path against the new root
  assert.throws(() => call(state, I[2], 'revokeCredential', [leaf]), /not active/);
  assert.throws(() => call(state, I[2], 'approveCredential', [leaf]), /already issued or revoked/, 'a revoked leaf cannot be re-issued');
});

test('revocation needs an ACTIVE credential (pending or unknown leaves are refused)', () => {
  let s = world();
  const leaf = P.credentialLeaf(credential(b32()));
  assert.throws(() => call(s, I[0], 'revokeCredential', [leaf]), /not active/);
  s = call(s, I[0], 'approveCredential', [leaf]);
  assert.throws(() => call(s, I[1], 'revokeCredential', [leaf]), /not active/);
});

// ---------------------------------------------------------------- apps (operator, billing)

test('apps: operator-only registration, versioned rule updates, suspension', () => {
  let s = deploy();
  assert.throws(() => call(s, I[0], 'registerApp', [APP, rules()]), /not the operator/);
  s = call(s, OP, 'registerApp', [APP, rules()]);
  assert.throws(() => call(s, OP, 'registerApp', [APP, rules()]), /already registered/);
  assert.throws(() => call(s, OP, 'registerApp', [new Uint8Array(32), rules()]), /empty app id/);
  const h = b32();
  let { state, cred } = issue(s, h, { country: DE });
  const sid1 = b32();
  state = verify(state, h, cred, { sid: sid1 });
  state = call(state, OP, 'updateAppRules', [APP, rules({ blockedCountries: [DE, 0n, 0n, 0n, 0n, 0n, 0n, 0n] })]);
  assert.equal(L(state).apps.lookup(APP).version, 2n);
  assert.throws(() => verify(state, h, cred), /country is blocked/);
  assert.equal(sessionOf(state, APP, sid1).policyVersion, 1n, 'old sessions keep their version');
  state = call(state, OP, 'updateAppRules', [APP, rules()]);
  state = call(state, OP, 'setAppActive', [APP, false]);
  assert.throws(() => verify(state, h, cred), /app is suspended/);
  assert.throws(() => call(state, I[0], 'setAppActive', [APP, true]), /not the operator/);
  state = call(state, OP, 'setAppActive', [APP, true]);
  assert.equal(L(state).apps.lookup(APP).version, 3n);
  verify(state, h, cred);
  assert.throws(() => verify(state, h, cred, { app: b32() }), /unknown app/);
  assert.throws(() => call(state, OP, 'updateAppRules', [b32(), rules()]), /unknown app/);
});

// ---------------------------------------------------------------- SDK mirrors

test('pure circuits are plain SHA-256 over 32-byte words (what @shieldpass/verify recomputes without WASM)', () => {
  for (let i = 0; i < 8; i++) {
    const [a, b] = [b32(), b32()];
    assert.equal(hex(P.sessionKey(a, b)), hex(sha(pad32('shieldpass:session:v1'), a, b)));
    assert.equal(hex(P.appNullifier(a, b)), hex(sha(pad32('shieldpass:nullifier:v1'), a, b)));
    assert.equal(hex(P.roleCommitment(b, P.holderTag())), hex(sha(pad32('shieldpass:role:'), pad32('holder'), b)));
  }
});
