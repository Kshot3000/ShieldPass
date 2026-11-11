/**
 * In-memory ShieldPass + gated-swap world for the local demo and its tests.
 * No network, no wallet, no keys leave this process. Demo credentials are fake.
 */
import { randomBytes } from 'node:crypto';
import * as RT from '@midnight-ntwrk/compact-runtime';
import { Contract as ShieldPass, ledger as spLedger, pureCircuits as SP } from '../../contracts/src/managed/shieldpass/contract/index.js';
import { Contract as GatedSwap, ledger as gsLedger, pureCircuits as GS } from '../../contracts/src/managed/gatedswap/contract/index.js';
import { quote, quoteDiv } from '../../contracts/lib/quote.mjs';
import { checkSession, newSessionId, bytesToHex, hexToBytes32 } from '@shieldpass/verify';

export const hex = (b) => Buffer.from(b).toString('hex');
const b32 = () => new Uint8Array(randomBytes(32));
const pad32 = (s) => {
  const out = new Uint8Array(32);
  out.set(new TextEncoder().encode(s));
  return out;
};

const COIN = '0'.repeat(64);
const ADDR_SP = RT.sampleContractAddress();
const ADDR_GS = RT.sampleContractAddress();

const US = 840n, DE = 276n, KP = 408n, IR = 364n, CU = 192n;
const YEAR = 31_556_952n;
const OFFSET_1900 = 2_208_988_800n;
export const COUNTRY = { 840: 'US', 276: 'DE', 408: 'KP', 364: 'IR', 192: 'CU' };
export const POOL_A = 1_000_000n;
export const POOL_B = 1_000_000n;
export const START_A = 10_000n;
export const RECIPIENT = pad32('demo-wallet');
export const APP = pad32('shieldpass-gated-swap');

const rules = () => ({
  minKycLevel: 1n,
  requireSanctionsClear: true,
  requireAccredited: false,
  minAge: 18n,
  blockedCountries: [KP, IR, CU, 0n, 0n, 0n, 0n, 0n],
});

function credential(holderSk, now, o = {}) {
  return {
    holder: SP.roleCommitment(holderSk, SP.holderTag()),
    country: US,
    birthDate: (now - 30n * YEAR) + OFFSET_1900,
    kycLevel: 2n,
    sanctionsClear: true,
    accredited: false,
    expiry: now + 365n * 86_400n,
    salt: b32(),
    ...o,
  };
}

const profiles = (now) => ({
  compliant: { label: 'Compliant demo holder (30, US, KYC 2, sanctions-clear)', opts: {} },
  underage: { label: 'Under 18', opts: { birthDate: (now - 17n * YEAR) + OFFSET_1900 } },
  blocked: { label: 'Blocked country', opts: { country: KP } },
  expired: { label: 'Expired credential', opts: { expiry: now } },
  unscreened: { label: 'Not sanctions-clear', opts: { sanctionsClear: false } },
});

export const PROFILE_IDS = ['compliant', 'underage', 'blocked', 'expired', 'unscreened'];

function spWitnesses() {
  return {
    localSecretKey: ({ privateState }) => [privateState, privateState.sk],
    heldCredential: ({ privateState }) => [privateState, privateState.credential],
    credentialPath: ({ privateState, ledger: l }, leaf) => {
      const p = privateState.path ?? l.credentials.findPathForLeaf(leaf);
      if (!p) throw new Error('credential not in registry (no Merkle path)');
      return [privateState, p];
    },
  };
}
function gsWitnesses() {
  return {
    ...spWitnesses(),
    quoteDiv: ({ privateState }, numer, denom) => [privateState, quoteDiv(numer, denom)],
  };
}

function call(contract, addr, state, ps, name, args, time) {
  const ctx = RT.createCircuitContext(addr, COIN, state, ps, undefined, undefined, Number(time));
  return contract.impureCircuits[name](ctx, ...args).context.currentQueryContext.state;
}

function errMessage(e) {
  return String(e && e.message ? e.message : e);
}

function decodeSession(stateHex, key) {
  const l = spLedger(RT.ContractState.deserialize(Buffer.from(stateHex, 'hex')).data);
  const k = Buffer.from(key, 'hex');
  if (!l.verified.member(k)) return null;
  const r = l.verified.lookup(k);
  return { appId: hex(r.appId), nullifier: hex(r.nullifier), policyVersion: Number(r.policyVersion), verifiedAt: Number(r.verifiedAt) };
}

export function createWorld(now = BigInt(Math.floor(Date.now() / 1000))) {
  const operatorSk = b32();
  const issuerSks = [b32(), b32(), b32()];
  const OP = { sk: operatorSk };
  const seats = issuerSks.map((sk) => SP.roleCommitment(sk, SP.issuerTag()));
  const shield = new ShieldPass(spWitnesses());
  const swapC = new GatedSwap(gsWitnesses());

  let sp = shield.initialState(RT.createConstructorContext(OP, COIN), seats, 2n).currentContractState;
  const callSp = (ps, name, args, time = now) => {
    sp.data = call(shield, ADDR_SP, sp.data, ps, name, args, time);
  };
  callSp(OP, 'registerApp', [APP, rules()]);

  const holders = {};
  for (const [id, meta] of Object.entries(profiles(now))) {
    const sk = b32();
    const cred = credential(sk, now, meta.opts);
    const leaf = SP.credentialLeaf(cred);
    callSp({ sk: issuerSks[0] }, 'approveCredential', [leaf]);
    callSp({ sk: issuerSks[1] }, 'approveCredential', [leaf]);
    holders[id] = { sk, cred, leaf, label: meta.label };
  }

  let gs = swapC.initialState(RT.createConstructorContext(OP, COIN), APP, rules(), POOL_A, POOL_B).currentContractState;
  const callGs = (ps, name, args, time = now) => {
    gs.data = call(swapC, ADDR_GS, gs.data, ps, name, args, time);
  };
  for (const h of Object.values(holders)) callGs(OP, 'admitLeaf', [h.leaf]);
  callGs(OP, 'credit', [RECIPIENT, START_A, 0n]);

  const contractState = () => {
    return hex(sp.serialize());
  };

  const world = {
    now,
    holders,
    session: null,
    async prove(profileId = 'compliant') {
      if (profileId === 'none') {
        world.session = null;
        return { ok: false, reason: 'no-proof', message: 'No credential was presented.' };
      }
      const h = holders[profileId];
      if (!h) return { ok: false, reason: 'unknown-profile', message: `Unknown profile: ${profileId}` };
      const sid = hexToBytes32(newSessionId());
      try {
        callSp({ sk: h.sk, credential: h.cred }, 'verifySession', [APP, sid, world.now], world.now);
      } catch (e) {
        world.session = null;
        return { ok: false, reason: 'verify-failed', profile: profileId, message: errMessage(e) };
      }
      const check = await checkSession({
        contractAddress: 'ab'.repeat(32),
        appId: hex(APP),
        sessionId: hex(sid),
        indexer: { url: 'http://demo.invalid', redacted: 'demo' },
        fetch: async () => ({ ok: true, status: 200, json: async () => ({ data: { contractAction: { state: contractState() } } }) }),
        decodeLedger: decodeSession,
        now: Number(world.now),
      });
      if (!check.verified) {
        world.session = null;
        return { ok: false, reason: check.reason, message: `isSessionVerified returned false (${check.reason})` };
      }
      world.session = { id: hex(sid), profile: profileId, nullifier: check.session.nullifier, verifiedAt: check.session.verifiedAt };
      return { ok: true, profile: profileId, session: world.session };
    },
    quote(amountIn, aToB = true) {
      const l = gsLedger(gs.data);
      return quote(aToB ? l.reserveA : l.reserveB, aToB ? l.reserveB : l.reserveA, amountIn);
    },
    swap({ amountIn, aToB = true, minOut, skipSessionCheck = false, profile } = {}) {
      const profileId = profile ?? world.session?.profile;
      if (!skipSessionCheck) {
        if (!world.session) return { ok: false, reason: 'no-session', message: 'The swap is closed: isSessionVerified is false. Prove a ShieldPass credential first.' };
      }
      if (!profileId || !holders[profileId]) return { ok: false, reason: 'no-credential', message: 'No credential is loaded for this swap.' };
      const h = holders[profileId];
      const sid = world.session && !skipSessionCheck ? hexToBytes32(world.session.id) : b32();
      const ain = BigInt(amountIn);
      let expected;
      try {
        expected = world.quote(ain, aToB);
      } catch (e) {
        return { ok: false, reason: 'quote', message: errMessage(e) };
      }
      const min = minOut == null ? expected : BigInt(minOut);
      try {
        callGs({ sk: h.sk, credential: h.cred }, 'swap', [sid, ain, min, aToB, world.now, RECIPIENT], world.now);
      } catch (e) {
        return { ok: false, reason: 'swap-failed', message: errMessage(e) };
      }
      if (world.session && !skipSessionCheck) world.session = { ...world.session, used: true };
      return { ok: true, amountIn: String(ain), amountOut: String(expected), aToB, sessionId: hex(sid) };
    },
    snapshot() {
      const l = gsLedger(gs.data);
      const bal = (book, who) => (book.member(who) ? book.lookup(who) : 0n);
      return {
        now: String(world.now),
        appId: hex(APP),
        recipient: hex(RECIPIENT),
        policy: {
          minKycLevel: Number(l.rules.minKycLevel),
          requireSanctionsClear: l.rules.requireSanctionsClear,
          requireAccredited: l.rules.requireAccredited,
          minAge: Number(l.rules.minAge),
          blockedCountries: l.rules.blockedCountries.filter((c) => c !== 0n).map((c) => COUNTRY[Number(c)] ?? String(c)),
        },
        reserves: { A: String(l.reserveA), B: String(l.reserveB) },
        balances: { A: String(bal(l.balanceA, RECIPIENT)), B: String(bal(l.balanceB, RECIPIENT)) },
        swaps: String(l.swaps),
        volumeA: String(l.volumeA),
        volumeB: String(l.volumeB),
        admittedLeaves: String(l.credentialSlots),
        gate: world.session && !world.session.used ? 'open' : 'closed',
        session: world.session,
        profiles: Object.fromEntries(Object.entries(holders).map(([id, h]) => [id, h.label])),
      };
    },
  };
  return world;
}

export { quote, bytesToHex };
