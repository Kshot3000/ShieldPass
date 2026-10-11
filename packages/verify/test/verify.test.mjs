import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as RT from '@midnight-ntwrk/compact-runtime';
import { world, P, ledger, b32, hex, NOW } from './world.mjs';
import { sessionKey, appNullifier, sessionFromState, resolveIndexer, isSessionVerified, checkSession, fetchContractState, newSessionId, bytesToHex } from '../src/index.ts';

const ADDR = 'ab'.repeat(32);
const ID = 'nightpreprodTESTSECRET123';

/** A fetch stub that serves one contract's state and records requests. */
function indexerStub(states) {
  const calls = [];
  const f = async (url, init) => {
    calls.push({ url, init });
    const { variables } = JSON.parse(init.body);
    const state = states[variables.a];
    return { ok: true, status: 200, json: async () => ({ data: { contractAction: state ? { state } : null } }) };
  };
  return { f, calls };
}
const exactDecode = (stateHex, key) => {
  const l = ledger(RT.ContractState.deserialize(Buffer.from(stateHex, 'hex')).data);
  const k = Buffer.from(key, 'hex');
  if (!l.verified.member(k)) return null;
  const r = l.verified.lookup(k);
  return { appId: hex(r.appId), nullifier: hex(r.nullifier), policyVersion: Number(r.policyVersion), verifiedAt: Number(r.verifiedAt) };
};

test('sessionKey and appNullifier match the compiled contract byte for byte', async () => {
  for (let i = 0; i < 16; i++) {
    const [a, b] = [b32(), b32()];
    assert.equal(await sessionKey(hex(a), hex(b)), hex(P.sessionKey(a, b)));
    assert.equal(await appNullifier(hex(a), hex(b)), hex(P.appNullifier(a, b)));
  }
  assert.match(newSessionId(), /^[0-9a-f]{64}$/);
  await assert.rejects(() => sessionKey('12', hex(b32())), /appId must be 32 bytes/);
});

test('string decoder agrees with ledger() for every session, including app ids with trailing zero bytes', async () => {
  const w = world();
  const apps = [w.registerApp(), w.registerApp()];
  const z = b32();
  z.fill(0, 20); // trailing zeros: shorter cell encoding
  apps.push(w.registerApp(z));
  const holders = [w.holder(), w.holder(), w.holder()];
  const sessions = [];
  for (const a of apps) for (const h of holders) sessions.push({ a, sid: w.verify(h, a) });
  w.bumpRules(apps[0]);
  sessions.push({ a: apps[0], sid: w.verify(holders[0], apps[0], b32(), NOW + 1234n) });
  const s = w.stateHex();
  const l = w.ledger();
  assert.equal([...l.verified].length, sessions.length);
  for (const { a, sid } of sessions) {
    const key = hex(P.sessionKey(a, sid));
    const want = l.verified.lookup(P.sessionKey(a, sid));
    const got = sessionFromState(s, key);
    assert.deepEqual(got, { appId: hex(want.appId), nullifier: hex(want.nullifier), policyVersion: Number(want.policyVersion), verifiedAt: Number(want.verifiedAt) });
    assert.deepEqual(got, exactDecode(s, key));
  }
  assert.equal(sessionFromState(s, hex(P.sessionKey(apps[0], b32()))), null);
  assert.equal(sessionFromState(s, '00'.repeat(32)), null);
  assert.equal(sessionFromState(s, 'zz'), null);
});

test('isSessionVerified: true only for this app\'s verified session; fails closed', async () => {
  const w = world();
  const appA = w.registerApp();
  const appB = w.registerApp();
  const h = w.holder();
  const sid = w.verify(h, appA);
  const { f, calls } = indexerStub({ [ADDR]: w.stateHex() });
  const base = { contractAddress: ADDR, indexer: { projectId: ID }, fetch: f };
  assert.equal(await isSessionVerified({ ...base, appId: hex(appA), sessionId: hex(sid) }), true);
  assert.equal(await isSessionVerified({ ...base, appId: hex(appB), sessionId: hex(sid) }), false, 'same session id, other app');
  assert.equal(await isSessionVerified({ ...base, appId: hex(appA), sessionId: hex(b32()) }), false);
  assert.equal(await isSessionVerified({ ...base, contractAddress: 'cd'.repeat(32), appId: hex(appA), sessionId: hex(sid) }), false);
  const r = await checkSession({ ...base, appId: hex(appA), sessionId: hex(sid) });
  assert.equal(r.verified, true);
  assert.equal(r.session.nullifier, hex(P.appNullifier(appA, h.sk)));
  // request shape: Blockfrost default URL, project id as header + query, contract address as variable
  const c = calls[0];
  assert.ok(c.url.startsWith('https://midnight-preprod.blockfrost.io/api/v0?project_id='));
  assert.equal(c.init.headers.project_id, ID);
  assert.equal(JSON.parse(c.init.body).variables.a, ADDR);
});

test('policy version and age limits; exact decoder option', async () => {
  const w = world();
  const app = w.registerApp();
  const h = w.holder();
  const sid = w.verify(h, app);
  w.bumpRules(app);
  const { f } = indexerStub({ [ADDR]: w.stateHex() });
  const o = { contractAddress: ADDR, appId: hex(app), sessionId: hex(sid), indexer: { projectId: ID }, fetch: f };
  assert.equal((await checkSession({ ...o, minPolicyVersion: 2 })).reason, 'old-policy');
  assert.equal(await isSessionVerified({ ...o, minPolicyVersion: 1 }), true);
  assert.equal((await checkSession({ ...o, maxAgeSeconds: 600, now: Number(NOW) + 601 })).reason, 'too-old');
  assert.equal(await isSessionVerified({ ...o, maxAgeSeconds: 600, now: Number(NOW) + 599 }), true);
  assert.equal(await isSessionVerified({ ...o, decodeLedger: exactDecode }), true);
});

test('indexer errors throw (never a silent false), with hints and without the project id', async () => {
  for (const status of [410, 403, 500]) {
    const f = async () => ({ ok: false, status, json: async () => ({}) });
    const err = await isSessionVerified({ contractAddress: ADDR, appId: hex(b32()), sessionId: hex(b32()), indexer: { projectId: ID }, fetch: f }).catch((e) => e);
    assert.ok(err instanceof Error);
    assert.match(err.message, new RegExp(`HTTP ${status}`));
    assert.doesNotMatch(err.message, /TESTSECRET/);
    if (status === 410) assert.match(err.message, /retired/);
    if (status === 403) assert.match(err.message, /project id/);
  }
  const gql = async () => ({ ok: true, status: 200, json: async () => ({ errors: [{ message: 'bad address' }] }) });
  await assert.rejects(() => fetchContractState(ADDR, resolveIndexer({ projectId: ID }), { fetch: gql }), /bad address/);
});

test('resolveIndexer: Blockfrost by default, env vars, custom URL, mainnet; no keyless default', () => {
  const bf = resolveIndexer({}, { BLOCKFROST_MIDNIGHT_PREPROD_ID: ID });
  assert.deepEqual(bf, { url: 'https://midnight-preprod.blockfrost.io/api/v0', projectId: ID, redacted: 'https://midnight-preprod.blockfrost.io/api/v0' });
  assert.throws(() => resolveIndexer({}, { BLOCKFROST_MIDNIGHT_PREPROD_ID: 'previewABC' }), /nightpreprod/);
  const own = resolveIndexer({}, { MIDNIGHT_PREPROD_INDEXER_URL: 'http://localhost:8088/api/v4/graphql?project_id=s3cret' });
  assert.equal(own.url, 'http://localhost:8088/api/v4/graphql?project_id=s3cret');
  assert.doesNotMatch(own.redacted, /s3cret/);
  // a Blockfrost id wins over a URL in env; an explicit url wins over everything
  assert.equal(resolveIndexer({}, { BLOCKFROST_MIDNIGHT_PREPROD_ID: ID, MIDNIGHT_PREPROD_INDEXER_URL: 'http://x' }).projectId, ID);
  assert.equal(resolveIndexer({ url: 'http://mine/graphql' }, { BLOCKFROST_MIDNIGHT_PREPROD_ID: ID }).url, 'http://mine/graphql');
  const main = resolveIndexer({ network: 'mainnet' }, { BLOCKFROST_MIDNIGHT_MAINNET_ID: 'nightmainnetX' });
  assert.equal(main.url, 'https://midnight-mainnet.blockfrost.io/api/v0');
  assert.equal(resolveIndexer({ network: 'mainnet' }, { BLOCKFROST_MIDNIGHT_PREPROD_ID: ID, MIDNIGHT_MAINNET_INDEXER_URL: 'http://m' }).url, 'http://m', 'preprod id never used for mainnet');
  assert.throws(() => resolveIndexer({}, {}), /BLOCKFROST_MIDNIGHT_PREPROD_ID/);
  assert.throws(() => resolveIndexer({}, {}), (e) => !/indexer\.preprod\.midnight\.network/.test(e.message));
});

test('bytesToHex round-trips', () => {
  const b = b32();
  assert.equal(bytesToHex(b), hex(b));
});
