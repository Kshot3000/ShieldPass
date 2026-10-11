#!/usr/bin/env node
/**
 * Local ZK proofs for the ShieldPass lifecycle against a proof server
 * (default http://127.0.0.1:6300, midnightntwrk/proof-server 8.1.0).
 *
 * Runs deploy -> registerApp -> approveCredential x2 -> verifySession ->
 * revokeCredential x2 in the compact-runtime simulator, then asks the proof
 * server to /check and /prove every circuit call with the full-ZK artifacts
 * from `pnpm compile`. No wallet, no network submit, no deploy: this shows the
 * circuits prove with real keys, nothing more.
 *
 * Writes a public report (sizes, timings, no secrets) to stdout.
 */
import { randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import * as RT from '@midnight-ntwrk/compact-runtime';
import { NodeZkConfigProvider } from '@midnight-ntwrk/midnight-js-node-zk-config-provider';
import { httpClientProvingProvider } from '@midnight-ntwrk/midnight-js-http-client-proof-provider';
import { setNetworkId } from '@midnight-ntwrk/midnight-js-network-id';

const OUT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'src', 'managed', 'shieldpass');
const PROOF = process.env.MIDNIGHT_PROOF_SERVER ?? 'http://127.0.0.1:6300';
if (!existsSync(path.join(OUT, 'keys', 'verifySession.prover'))) throw new Error('no prover keys: run `pnpm compile` (full ZK build) first');
const health = await fetch(`${PROOF}/health`).then((r) => r.ok).catch(() => false);
if (!health) throw new Error(`proof server ${PROOF} is not healthy`);
setNetworkId('preprod');

const { Contract, pureCircuits: P } = await import(path.join(OUT, 'contract', 'index.js'));
const b32 = () => new Uint8Array(randomBytes(32));
const witnesses = {
  localSecretKey: ({ privateState }) => [privateState, privateState.sk],
  heldCredential: ({ privateState }) => [privateState, privateState.credential],
  credentialPath: ({ privateState, ledger: l }, leaf) => [privateState, l.credentials.findPathForLeaf(leaf)],
};
const contract = new Contract(witnesses);
const COIN = '0'.repeat(64);
const ADDR = RT.sampleContractAddress();
const now = BigInt(Math.floor(Date.now() / 1000));

const op = { sk: b32() };
const seats = [b32(), b32(), b32()];
let state = contract.initialState(RT.createConstructorContext(op, COIN), seats.map((s) => P.roleCommitment(s, P.issuerTag())), 2n).currentContractState.data;

const zk = new NodeZkConfigProvider(OUT);
const prover = httpClientProvingProvider(PROOF, zk, { timeout: 600_000 });
const report = [];
async function proveCall(ps, name, args) {
  const r = contract.impureCircuits[name](RT.createCircuitContext(ADDR, COIN, state, ps, undefined, undefined, Number(now)), ...args);
  state = r.context.currentQueryContext.state;
  const pd = r.proofData;
  const pre = RT.proofDataIntoSerializedPreimage(pd.input, pd.output, pd.publicTranscript, pd.privateTranscriptOutputs, name);
  const t0 = Date.now();
  await prover.check(pre, name);
  const t1 = Date.now();
  const proof = await prover.prove(pre, name);
  const t2 = Date.now();
  if (!(proof instanceof Uint8Array) || !proof.byteLength) throw new Error(`${name}: empty proof`);
  const row = { circuit: name, preimageBytes: pre.byteLength, proofBytes: proof.byteLength, checkMs: t1 - t0, proveMs: t2 - t1 };
  report.push(row);
  console.error(`proved ${name}: ${row.proofBytes} B in ${row.proveMs} ms`);
}

const app = b32();
await proveCall(op, 'registerApp', [app, { minKycLevel: 1n, requireSanctionsClear: true, requireAccredited: false, minAge: 18n, blockedCountries: [408n, 364n, 192n, 0n, 0n, 0n, 0n, 0n] }]);
const holderSk = b32();
const credential = { holder: P.roleCommitment(holderSk, P.holderTag()), country: 840n, birthDate: now - 30n * 31_556_952n + 2_208_988_800n, kycLevel: 2n, sanctionsClear: true, accredited: false, expiry: now + 86_400n * 365n, salt: b32() };
const leaf = P.credentialLeaf(credential);
await proveCall({ sk: seats[0] }, 'approveCredential', [leaf]);
await proveCall({ sk: seats[2] }, 'approveCredential', [leaf]);
await proveCall({ sk: holderSk, credential }, 'verifySession', [app, b32(), now]);
await proveCall({ sk: seats[1] }, 'revokeCredential', [leaf]);
await proveCall({ sk: seats[2] }, 'revokeCredential', [leaf]);
await proveCall(op, 'setAppActive', [app, false]);

console.log(JSON.stringify({ claim: 'local ZK proofs against the proof server; not submitted, not a deploy', compiler: 'compactc 0.31.1', runtime: '@midnight-ntwrk/compact-runtime 0.16.0', proofServer: PROOF, at: new Date().toISOString(), proofs: report }, null, 2));
