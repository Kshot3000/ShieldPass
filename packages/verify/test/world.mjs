/** Real ShieldPass contract states for the decoder tests (compiled contract + compact-runtime simulation). */
import { randomBytes } from 'node:crypto';
import * as RT from '@midnight-ntwrk/compact-runtime';
import { Contract, ledger, pureCircuits as P } from '../../../contracts/src/managed/shieldpass/contract/index.js';

export const NOW = 1_792_000_000n;
export const b32 = () => new Uint8Array(randomBytes(32));
export const hex = (b) => Buffer.from(b).toString('hex');
export { P, ledger };

const witnesses = {
  localSecretKey: ({ privateState }) => [privateState, privateState.sk],
  heldCredential: ({ privateState }) => [privateState, privateState.credential],
  credentialPath: ({ privateState, ledger: l }, leaf) => [privateState, l.credentials.findPathForLeaf(leaf)],
};
const contract = new Contract(witnesses);
const anyRules = { minKycLevel: 0n, requireSanctionsClear: false, requireAccredited: false, minAge: 0n, blockedCountries: Array(8).fill(0n) };

export function world() {
  const op = { sk: b32() };
  const iss = [b32(), b32(), b32()];
  const cs = contract.initialState(RT.createConstructorContext(op, '0'.repeat(64)), iss.map((s) => P.roleCommitment(s, P.issuerTag())), 2n).currentContractState;
  let data = cs.data;
  const call = (ps, name, args, time = NOW) => {
    data = contract.impureCircuits[name](RT.createCircuitContext(RT.sampleContractAddress(), '0'.repeat(64), data, ps, undefined, undefined, Number(time)), ...args).context.currentQueryContext.state;
  };
  const w = {
    registerApp(appId = b32()) {
      call(op, 'registerApp', [appId, anyRules]);
      return appId;
    },
    bumpRules(appId) {
      call(op, 'updateAppRules', [appId, anyRules]);
    },
    holder() {
      const sk = b32();
      const credential = { holder: P.roleCommitment(sk, P.holderTag()), country: 840n, birthDate: 3_000_000_000n, kycLevel: 1n, sanctionsClear: true, accredited: false, expiry: NOW + 86_400n, salt: b32() };
      const leaf = P.credentialLeaf(credential);
      call({ sk: iss[0] }, 'approveCredential', [leaf]);
      call({ sk: iss[1] }, 'approveCredential', [leaf]);
      return { sk, credential };
    },
    verify(h, appId, sessionId = b32(), now = NOW) {
      call({ sk: h.sk, credential: h.credential }, 'verifySession', [appId, sessionId, now], now);
      return sessionId;
    },
    stateHex() {
      cs.data = data;
      return hex(cs.serialize());
    },
    ledger: () => ledger(data),
  };
  return w;
}

/** decodeLedger for @shieldpass/verify built on the compiled contract (exact, needs WASM-free runtime only). */
export function exactDecoder(stateHex) {
  const l = ledger(RT.ContractState.deserialize(Buffer.from(stateHex, 'hex')).data);
  return l;
}
