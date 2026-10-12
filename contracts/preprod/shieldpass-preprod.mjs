#!/usr/bin/env node
/**
 * ShieldPass on Midnight Preprod: deploy (once), then a live drill, all in one
 * wallet sync:
 *
 *   1. deployContract(committee = 3 issuer seat commitments, m = 2) as the
 *      operator (the deployer's localSecretKey becomes the operator role).
 *   2. registerApp(demo appId, demo rules) as the operator.
 *   3. approveCredential(leaf) from issuer seat 0, then seat 2: the 2nd
 *      approval puts the demo credential in the registry (ACTIVE).
 *   4. verifySession(appId, sessionId, now) as the holder: ZK proof of Merkle
 *      membership + every rule of the app's policy.
 *   5. Off-chain check with @shieldpass/verify: isSessionVerified() must be
 *      true for that session and false for an unknown session id (and for the
 *      wrong app), reading the Blockfrost Midnight indexer.
 *
 * Idempotent: each step re-reads the ledger first and is skipped if it already
 * landed (rerun after a crash resumes). Only reports a tx from finalized data
 * (txId + blockHeight + SucceedEntirely).
 *
 * Secrets (operator, seat and holder secrets, demo credential) live in
 * $SHIELDPASS_SECRETS (created 0600, never printed, never committed). Public
 * results go to $SHIELDPASS_PUBLIC_RECORD (deployments/preprod.json).
 *
 * Endpoints: BLOCKFROST_MIDNIGHT_PREPROD_ID (nightpreprod… project id) builds
 * the Blockfrost indexer URLs; MIDNIGHT_INDEXER_URL / MIDNIGHT_INDEXER_WS_URL
 * override. The wallet (MIDNIGHT_WALLET_FACADE) resolves its indexer + node the
 * same way. URLs carry the project id and are never logged (log() redacts).
 *
 * Runtime: midnight-js 4.1.1, wallet-sdk 1.2.0, compact-runtime 0.16.0, proof
 * server 8.1.0 on :6300, Node 22.18+. Bare midnight-js specifiers: run a copy
 * from a workspace that has those packages (see run-preprod.sh).
 */
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { deployContract, findDeployedContract } from '@midnight-ntwrk/midnight-js-contracts';
import { CompiledContract } from '@midnight-ntwrk/midnight-js-protocol/compact-js';
import { levelPrivateStateProvider } from '@midnight-ntwrk/midnight-js-level-private-state-provider';
import { setNetworkId } from '@midnight-ntwrk/midnight-js-network-id';
import { indexerPublicDataProvider } from '@midnight-ntwrk/midnight-js-indexer-public-data-provider';
import { httpClientProofProvider } from '@midnight-ntwrk/midnight-js-http-client-proof-provider';
import { NodeZkConfigProvider } from '@midnight-ntwrk/midnight-js-node-zk-config-provider';
import { WebSocket } from 'ws';

const env = (k, d) => process.env[k] ?? d;
const need = (k) => {
  const v = process.env[k];
  if (!v) throw new Error(`${k} is required`);
  return v;
};

const BF_ID = env('BLOCKFROST_MIDNIGHT_PREPROD_ID', '').trim();
if (BF_ID && !BF_ID.startsWith('nightpreprod')) throw new Error('BLOCKFROST_MIDNIGHT_PREPROD_ID must be a Midnight Preprod Blockfrost project id (starts with nightpreprod)');
const BF_Q = BF_ID ? `?project_id=${encodeURIComponent(BF_ID)}` : '';
const INDEXER = env('MIDNIGHT_INDEXER_URL', '') || (BF_ID ? `https://midnight-preprod.blockfrost.io/api/v0${BF_Q}` : '');
const INDEXER_WS = env('MIDNIGHT_INDEXER_WS_URL', '') || (BF_ID ? `wss://midnight-preprod.blockfrost.io/api/v0/ws${BF_Q}` : '');
if (!INDEXER) throw new Error('set BLOCKFROST_MIDNIGHT_PREPROD_ID (Midnight Preprod Blockfrost project id) or MIDNIGHT_INDEXER_URL');
const PROOF = env('MIDNIGHT_PROOF_SERVER', 'http://127.0.0.1:6300');

const OUT = need('SHIELDPASS_OUT'); // compiled managed/shieldpass (contract/, keys/, zkir/)
const SECRETS = need('SHIELDPASS_SECRETS');
const FACADE = need('MIDNIGHT_WALLET_FACADE');
const VERIFY_SDK = need('SHIELDPASS_VERIFY_SDK'); // packages/verify/src/index.ts
const PUBLIC_RECORD = env('SHIELDPASS_PUBLIC_RECORD', '');
const THRESHOLD = Number(env('SHIELDPASS_THRESHOLD', '2'));
const DRY = process.argv.includes('--dry-run');

const redactPid = (x) => {
  const s = typeof x === 'string' ? x : x?.stack ? String(x.stack) : null;
  return s == null ? x : s.replace(/([?&]project_id=)[^&\s"']*/g, '$1…').replace(/nightpreprod[A-Za-z0-9]+/g, 'nightpreprod…');
};
const log = (...a) => console.error(new Date().toISOString(), ...a.map(redactPid));
const hex = (b) => Buffer.from(b).toString('hex');
const u8 = (h) => new Uint8Array(Buffer.from(h, 'hex'));
const rand = () => hex(globalThis.crypto.getRandomValues(new Uint8Array(32)));
const jsonText = (v) => `${JSON.stringify(v, (_, x) => (typeof x === 'bigint' ? x.toString() : x), 2)}\n`;
const jsonOut = (file, v) => fs.writeFileSync(file, jsonText(v), { mode: 0o600 });

const finalized = (label, f) => {
  const p = f?.public ?? {};
  if (!p.txId || p.blockHeight == null) throw new Error(`${label}: no txId/blockHeight; not claiming success`);
  if (p.status && p.status !== 'SucceedEntirely') throw new Error(`${label}: status ${p.status}`);
  return { txId: String(p.txId), txHash: p.txHash ? String(p.txHash) : null, blockHeight: p.blockHeight, blockHash: p.blockHash ? String(p.blockHash) : null, status: p.status ?? null };
};

// ---------------------------------------------------------------- secrets (never printed)

fs.mkdirSync(SECRETS, { recursive: true, mode: 0o700 });
const ROLES_FILE = path.join(SECRETS, 'preprod-roles.json');
const RUN_FILE = path.join(SECRETS, 'preprod-run.json'); // public results + resume state (no secrets)

function loadRoles() {
  if (fs.existsSync(ROLES_FILE)) return JSON.parse(fs.readFileSync(ROLES_FILE, 'utf8'));
  const now = Math.floor(Date.now() / 1000);
  const roles = {
    schema: 'shieldpass/preprod-roles@1',
    note: 'Testnet demo secrets. Each issuer seat should move to its own operator before anything real.',
    operatorSk: rand(),
    seats: [rand(), rand(), rand()],
    holderSk: rand(),
    // Demo credential (fake person): US, 30 years old, KYC level 2, sanctions-clear, not accredited, valid 1 year.
    credential: { country: '840', birthDate: String(now - 30 * 31_556_952 + 2_208_988_800), kycLevel: '2', sanctionsClear: true, accredited: false, expiry: String(now + 365 * 86_400), salt: rand() },
    createdAt: new Date().toISOString(),
  };
  jsonOut(ROLES_FILE, roles);
  return roles;
}

const DEMO_APP_ID = createHash('sha256').update('ShieldPass Preprod demo app #1').digest('hex');
const DEMO_RULES = { minKycLevel: 1n, requireSanctionsClear: true, requireAccredited: false, minAge: 18n, blockedCountries: [408n, 364n, 192n, 0n, 0n, 0n, 0n, 0n] };
const rulesPublic = { minKycLevel: 1, requireSanctionsClear: true, requireAccredited: false, minAge: 18, blockedCountries: [408, 364, 192] };

const credentialOf = (roles, P) => ({
  holder: P.roleCommitment(u8(roles.holderSk), P.holderTag()),
  country: BigInt(roles.credential.country),
  birthDate: BigInt(roles.credential.birthDate),
  kycLevel: BigInt(roles.credential.kycLevel),
  sanctionsClear: roles.credential.sanctionsClear,
  accredited: roles.credential.accredited,
  expiry: BigInt(roles.credential.expiry),
  salt: u8(roles.credential.salt),
});

// Private states are plain JSON (hex strings); witnesses convert.
let ROLES = null;
let PURE = null;
const witnesses = {
  localSecretKey: ({ privateState }) => [privateState, u8(privateState.sk)],
  heldCredential: ({ privateState }) => [privateState, credentialOf(ROLES, PURE)],
  credentialPath: ({ privateState, ledger: l }, leaf) => {
    const p = l.credentials.findPathForLeaf(leaf);
    if (!p) throw new Error('credential leaf is not in the registry tree');
    return [privateState, p];
  },
};

// ---------------------------------------------------------------- main

async function main() {
  if (process.env.MIDNIGHT_LOAD_ENV) (await import(pathToFileURL(process.env.MIDNIGHT_LOAD_ENV).href)).loadPreprodEnv();
  const { Contract, ledger, pureCircuits: P } = await import(pathToFileURL(path.join(OUT, 'contract/index.js')).href);
  const V = await import(pathToFileURL(VERIFY_SDK).href);
  PURE = P;
  ROLES = loadRoles();
  setNetworkId('preprod');
  if (!globalThis.WebSocket) globalThis.WebSocket = WebSocket;
  for (const c of ['registerApp', 'approveCredential', 'verifySession']) {
    if (!fs.existsSync(path.join(OUT, 'keys', `${c}.prover`))) throw new Error(`no prover key for ${c}: run the full ZK compile (pnpm compile)`);
  }
  if (!(await fetch(`${PROOF}/health`).then((r) => r.ok).catch(() => false))) throw new Error(`proof server ${PROOF} is not healthy`);

  const committee = ROLES.seats.map((s) => P.roleCommitment(u8(s), P.issuerTag()));
  const credential = credentialOf(ROLES, P);
  const leaf = P.credentialLeaf(credential);
  const run = fs.existsSync(RUN_FILE) ? JSON.parse(fs.readFileSync(RUN_FILE, 'utf8')) : { network: 'midnight-preprod', txs: {} };
  run.txs ??= {};
  run.sessionId ??= rand();
  run.appId = DEMO_APP_ID;
  run.leaf = hex(leaf);
  const save = () => {
    jsonOut(RUN_FILE, run);
    if (PUBLIC_RECORD) fs.writeFileSync(PUBLIC_RECORD, jsonText(publicRecord(run, committee, P)));
  };

  const publicData = indexerPublicDataProvider(INDEXER, INDEXER_WS);
  const readLedger = async (address) => {
    const state = await publicData.queryContractState(address);
    if (!state) return null;
    try {
      return ledger(state.data);
    } catch {
      return ledger(state);
    }
  };

  if (run.contractAddress) {
    const l = await readLedger(run.contractAddress);
    log(`contract ${run.contractAddress}: ${l ? `apps ${l.apps.size()}, issued ${l.credentialsIssued}, sessions ${l.sessionsVerified}` : 'not found on the indexer'}`);
  }
  if (DRY) {
    log(`dry run (no wallet, no txs): ${run.contractAddress ? 'join' : 'deploy'} -> registerApp -> approveCredential seats 0,2 -> verifySession -> @shieldpass/verify`);
    return;
  }

  log('building wallet (seed from env, never printed)…');
  const W = await import(pathToFileURL(FACADE).href);
  const ctx = await W.buildPreprodWalletFromEnv();
  log('unshielded', ctx.unshieldedAddress);
  try {
    await W.waitUntilConnected(ctx.wallet, { timeoutMs: 180_000 });
    await W.waitForNightBalance(ctx.wallet, ctx.unshieldedKeystore, { timeoutMs: 900_000 });
    log('syncing (Preprod dust sync can take ~30 min)…');
    const synced = await W.waitForSynced(ctx.wallet, { timeoutMs: 3_600_000 });
    log('synced; tNIGHT', W.formatNight(W.nightBalanceFromState(synced, ctx.unshieldedKeystore)), 'tDUST', W.formatDust(W.dustBalanceFromState(synced)));
    const dust = await W.ensureDustRegistered(ctx.wallet, ctx.unshieldedKeystore, { dustWaitTimeoutMs: 900_000 });
    if (dust.dustBalance <= 0n) throw new Error('tDUST is 0');

    const walletProvider = W.makeWalletMidnightProvider(ctx.wallet, ctx.shieldedSecretKeys, ctx.dustSecretKey);
    const accountId = String(ctx.unshieldedKeystore.getBech32Address());
    const zkConfigProvider = new NodeZkConfigProvider(OUT);
    const providers = {
      privateStateProvider: levelPrivateStateProvider({
        privateStateStoreName: 'shieldpass-private-state',
        signingKeyStoreName: 'shieldpass-signing-keys',
        privateStoragePasswordProvider: () => need('PRIVATE_STATE_PASSWORD'),
        accountId,
      }),
      publicDataProvider: publicData,
      zkConfigProvider,
      proofProvider: httpClientProofProvider(PROOF, zkConfigProvider),
      walletProvider,
      midnightProvider: walletProvider,
    };
    const compiled = CompiledContract.withCompiledFileAssets(CompiledContract.withWitnesses(CompiledContract.make('shieldpass', Contract), witnesses), OUT);
    const join = (id, sk) => findDeployedContract(providers, { compiledContract: compiled, contractAddress: run.contractAddress, privateStateId: id, initialPrivateState: { sk } });

    // 1. deploy once
    let operator;
    if (!run.contractAddress) {
      log(`deployContract shieldpass (${THRESHOLD}-of-3 issuer committee) (prove + balance + submit)…`);
      const deployed = await deployContract(providers, {
        compiledContract: compiled,
        privateStateId: 'shieldpassOperator',
        initialPrivateState: { sk: ROLES.operatorSk },
        args: [committee, BigInt(THRESHOLD)],
      });
      const p = deployed.deployTxData.public;
      if (!p.contractAddress) throw new Error('deploy returned no contractAddress');
      run.contractAddress = String(p.contractAddress);
      run.txs.deploy = { txId: p.txId ? String(p.txId) : null, txHash: p.txHash ? String(p.txHash) : null, blockHeight: p.blockHeight ?? null, status: p.status ?? null };
      run.deployer = ctx.unshieldedAddress;
      run.deployedAt = new Date().toISOString();
      save();
      log('DEPLOYED', run.contractAddress, 'tx', run.txs.deploy.txId, 'block', run.txs.deploy.blockHeight);
      operator = deployed;
    } else {
      log('joining', run.contractAddress);
      operator = await join('shieldpassOperator', ROLES.operatorSk);
    }
    const address = run.contractAddress;

    // 2. registerApp
    let l = await readLedger(address);
    if (!l.apps.member(u8(DEMO_APP_ID))) {
      log('registerApp (operator)…');
      run.txs.registerApp = finalized('registerApp', await operator.callTx.registerApp(u8(DEMO_APP_ID), DEMO_RULES));
      save();
      log('REGISTERED app tx', run.txs.registerApp.txId, 'block', run.txs.registerApp.blockHeight);
    } else log('app already registered');

    // 3. approveCredential from seats 0 and 2
    for (const seat of [0, 2]) {
      l = await readLedger(address);
      const vk = P.voteKey(P.issueAction(), leaf, committee[seat]);
      if (l.issuerVotes.member(vk)) {
        log(`seat ${seat} already approved`);
        continue;
      }
      log(`approveCredential (issuer seat ${seat})…`);
      const c = await join(`shieldpassSeat${seat}`, ROLES.seats[seat]);
      run.txs[`approveCredentialSeat${seat}`] = finalized(`approveCredential seat ${seat}`, await c.callTx.approveCredential(leaf));
      save();
      log(`APPROVED seat ${seat} tx`, run.txs[`approveCredentialSeat${seat}`].txId, 'block', run.txs[`approveCredentialSeat${seat}`].blockHeight);
    }
    l = await readLedger(address);
    const st = Number(l.credentialStatus.lookup(leaf));
    if (st !== 2) throw new Error(`credential status ${st} after 2 approvals, expected ACTIVE (2)`);
    run.credential = { status: 'ACTIVE', approvals: Number(l.issueApprovals.lookup(leaf)), credentialsIssued: String(l.credentialsIssued) };
    save();

    // 4. verifySession as the holder
    const skey = P.sessionKey(u8(DEMO_APP_ID), u8(run.sessionId));
    if (!l.verified.member(skey)) {
      const now = BigInt(Math.floor(Date.now() / 1000));
      log('verifySession (holder ZK proof)…');
      const h = await join('shieldpassHolder', ROLES.holderSk);
      run.txs.verifySession = { ...finalized('verifySession', await h.callTx.verifySession(u8(DEMO_APP_ID), u8(run.sessionId), now)), now: String(now) };
      save();
      log('VERIFIED session tx', run.txs.verifySession.txId, 'block', run.txs.verifySession.blockHeight);
    } else log('session already verified');
    l = await readLedger(address);
    const rec = l.verified.lookup(skey);
    run.session = { sessionId: run.sessionId, sessionKey: hex(skey), nullifier: hex(rec.nullifier), policyVersion: Number(rec.policyVersion), verifiedAt: String(rec.verifiedAt), sessionsVerified: String(l.sessionsVerified) };
    save();
  } finally {
    await ctx.wallet.stop().catch(() => {});
  }
  await sdkCheck(V, run);
  save();
  if (!run.sdkCheck.ok) throw new Error(`@shieldpass/verify check failed: ${JSON.stringify(run.sdkCheck)}`);
  log('DRILL OK', JSON.stringify(run.sdkCheck));
}

/** 5. @shieldpass/verify against the live indexer: true for the session, false for an unknown one / wrong app. */
async function sdkCheck(V, run) {
  const indexer = BF_ID ? { url: 'https://midnight-preprod.blockfrost.io/api/v0', projectId: BF_ID } : { url: INDEXER };
  const base = { contractAddress: run.contractAddress, indexer };
  let known = null;
  for (let i = 0; i < 20; i++) {
    known = await V.isSessionVerified({ ...base, appId: run.appId, sessionId: run.sessionId });
    if (known) break;
    await new Promise((r) => setTimeout(r, 6000)); // indexer catching up
  }
  const unknownSessionId = V.newSessionId();
  const unknown = await V.isSessionVerified({ ...base, appId: run.appId, sessionId: unknownSessionId });
  const wrongApp = await V.isSessionVerified({ ...base, appId: createHash('sha256').update('not the demo app').digest('hex'), sessionId: run.sessionId });
  const detail = await V.checkSession({ ...base, appId: run.appId, sessionId: run.sessionId, minPolicyVersion: 1 });
  // Cross-check the no-WASM decoder against the compiled contract's ledger() read (via midnight-js) of the same record.
  const exact = run.session ? { verified: true, session: { nullifier: run.session.nullifier } } : { verified: null };
  run.sdkCheck = {
    at: new Date().toISOString(),
    indexer: 'https://midnight-preprod.blockfrost.io/api/v0',
    knownSession: known,
    unknownSession: unknown,
    unknownSessionId,
    wrongApp,
    nullifier: detail.verified ? detail.session.nullifier : null,
    decoderMatchesCompiledLedger: exact.verified === true ? exact.session.nullifier === detail.session?.nullifier : null,
    ok: known === true && unknown === false && wrongApp === false,
  };
}

function publicRecord(run, committee, P) {
  return {
    network: 'midnight-preprod',
    status: run.contractAddress ? (run.sdkCheck?.ok ? 'deployed-drill-passed' : 'deployed') : 'not-deployed',
    contract: 'contracts/src/shieldpass.compact',
    compiler: 'compactc 0.31.1',
    runtime: 'compact-runtime 0.16.0, midnight-js 4.1.1, proof server 8.1.0',
    contractAddress: run.contractAddress ?? null,
    deployer: run.deployer ?? null,
    deployedAt: run.deployedAt ?? null,
    indexer: 'https://midnight-preprod.blockfrost.io/api/v0 (Blockfrost Midnight Preprod; project id required)',
    operatorCommitment: ROLES ? hex(P.roleCommitment(u8(ROLES.operatorSk), P.operatorTag())) : null,
    committee: committee.map(hex),
    threshold: THRESHOLD,
    demo: {
      appId: run.appId,
      rules: rulesPublic,
      credentialLeaf: run.leaf,
      credential: run.credential ?? null,
      session: run.session ?? null,
      note: 'Demo credential for a fake person; its attributes stay off-chain (salted leaf only).',
    },
    txs: run.txs,
    sdkCheck: run.sdkCheck ?? null,
    explorer: run.contractAddress ? `https://preprod.midnightexplorer.com/contracts/0x${run.contractAddress}` : null,
    _note: 'Public Midnight Preprod data only. No keys, seeds or seat secrets. Testnet only, not audited; all three issuer seats are team-run for now.',
  };
}

main().then(
  () => process.exit(0),
  (e) => {
    log('FAILED (not claiming success):', e?.stack || e);
    let c = e?.cause;
    for (let i = 0; c && i < 5; i++, c = c.cause) log(`cause[${i}]`, c?.stack || c);
    process.exit(1);
  },
);
