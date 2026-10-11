/**
 * @shieldpass/verify — ask Midnight whether a ShieldPass session was verified.
 *
 *   const ok = await isSessionVerified({ contractAddress, appId, sessionId });
 *
 * A dApp backend (or browser) passes the ShieldPass contract address, its own
 * app id and the session id it handed the user; it gets back `true` only if
 * the contract's `verified` map holds a record for
 *   sessionKey(appId, sessionId) = SHA-256(pad32("shieldpass:session:v1") || appId || sessionId)
 * whose appId is this app (and, optionally, a recent enough policy version /
 * verification time). That record exists only if a holder's zero-knowledge
 * proof passed every rule of the app's policy in `verifySession`.
 *
 * No WASM, no wallet, no keys: one GraphQL POST to a Midnight indexer for the
 * contract's latest serialized state, then a small string decoder (the same
 * approach as PlutusShield's apps/web/src/lib/midnightIndexer.ts). Pass
 * `decodeLedger` to use the compiled contract's own ledger() instead.
 *
 * Indexer: Midnight retired indexer.preprod.midnight.network on 2026-10-09
 * (HTTP 410). The default is Blockfrost's Midnight indexer, which needs a
 * project id (Preprod ids start with `nightpreprod`). Configure with
 * options.indexer, or env BLOCKFROST_MIDNIGHT_PREPROD_ID /
 * MIDNIGHT_PREPROD_INDEXER_URL (mainnet: BLOCKFROST_MIDNIGHT_MAINNET_ID /
 * MIDNIGHT_MAINNET_INDEXER_URL). Project ids are never put in error messages.
 */

export type MidnightNetworkName = "preprod" | "mainnet";

export type IndexerConfig = {
  /** GraphQL HTTP endpoint (no project id in it if you also pass projectId). */
  url: string;
  /** Blockfrost project id, sent as the `project_id` header and query parameter. */
  projectId?: string;
  /** Safe to print: the URL with any project id removed. */
  redacted: string;
};

export type Env = Record<string, string | undefined>;

const BLOCKFROST: Record<MidnightNetworkName, string> = {
  preprod: "https://midnight-preprod.blockfrost.io/api/v0",
  mainnet: "https://midnight-mainnet.blockfrost.io/api/v0",
};

const redact = (u: string) => u.replace(/([?&]project_id=)[^&]*/gi, "$1…");

/**
 * Resolve the indexer for a network from explicit options or the environment.
 * Order: explicit url > Blockfrost project id > *_INDEXER_URL env. Blockfrost
 * is the default; without a project id or a URL this throws (the old hosted
 * Preprod indexer is gone, so there is no keyless default).
 */
export function resolveIndexer(
  opts: { network?: MidnightNetworkName; url?: string; projectId?: string } = {},
  env: Env = (globalThis as { process?: { env: Env } }).process?.env ?? {},
): IndexerConfig {
  const network = opts.network ?? "preprod";
  const NET = network.toUpperCase();
  if (opts.url) return { url: opts.url, projectId: opts.projectId?.trim() || undefined, redacted: redact(opts.url) };
  const id = (opts.projectId ?? env[`BLOCKFROST_MIDNIGHT_${NET}_ID`])?.trim();
  if (id) {
    if (network === "preprod" && !id.startsWith("nightpreprod")) {
      throw new Error("BLOCKFROST_MIDNIGHT_PREPROD_ID must be a Midnight Preprod Blockfrost project id (starts with nightpreprod)");
    }
    return { url: BLOCKFROST[network], projectId: id, redacted: BLOCKFROST[network] };
  }
  const url = env[`MIDNIGHT_${NET}_INDEXER_URL`]?.trim();
  if (url) return { url, redacted: redact(url) };
  throw new Error(
    `no Midnight ${network} indexer configured: set BLOCKFROST_MIDNIGHT_${NET}_ID (Blockfrost project id) or MIDNIGHT_${NET}_INDEXER_URL`,
  );
}

// ---------------------------------------------------------------- hashing (WebCrypto, mirrors the contract)

const enc = new TextEncoder();

function subtle(): SubtleCrypto {
  const c = (globalThis as { crypto?: Crypto }).crypto;
  if (!c?.subtle) throw new Error("WebCrypto (globalThis.crypto.subtle) is unavailable; use Node 20+ or a browser over HTTPS");
  return c.subtle;
}

export function pad32(text: string): Uint8Array {
  const b = enc.encode(text);
  if (b.length > 32) throw new Error(`"${text}" is longer than 32 bytes`);
  const out = new Uint8Array(32);
  out.set(b);
  return out;
}

export function hexToBytes32(hex: string, what = "value"): Uint8Array {
  const h = hex.trim().toLowerCase().replace(/^0x/, "");
  if (!/^[0-9a-f]{64}$/.test(h)) throw new Error(`${what} must be 32 bytes (64 hex chars)`);
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export const bytesToHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

async function sha256(...parts: Uint8Array[]): Promise<Uint8Array> {
  const buf = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    buf.set(p, o);
    o += p.length;
  }
  return new Uint8Array(await subtle().digest("SHA-256", buf));
}

/** Contract `sessionKey(appId, sessionId)`; hex in, hex out. */
export async function sessionKey(appId: string, sessionId: string): Promise<string> {
  return bytesToHex(await sha256(pad32("shieldpass:session:v1"), hexToBytes32(appId, "appId"), hexToBytes32(sessionId, "sessionId")));
}

/** Contract `appNullifier(appId, holderSk)`: what the holder's wallet can show to prove which pseudonym is theirs. */
export async function appNullifier(appId: string, holderSecret: string): Promise<string> {
  return bytesToHex(await sha256(pad32("shieldpass:nullifier:v1"), hexToBytes32(appId, "appId"), hexToBytes32(holderSecret, "holder secret")));
}

/** A fresh random 32-byte session id (hex) for the dApp to hand the user. */
export function newSessionId(): string {
  const b = new Uint8Array(32);
  (globalThis as { crypto: Crypto }).crypto.getRandomValues(b);
  return bytesToHex(b);
}

// ---------------------------------------------------------------- state decoding (no WASM)

export type SessionRecord = {
  appId: string;
  /** Per-app holder pseudonym: stable inside this app, unrelated across apps. */
  nullifier: string;
  policyVersion: number;
  /** Unix seconds the holder proved at (checked against block time ±900 s). */
  verifiedAt: number;
};

/**
 * One value cell as the indexer serializes contract state: little-endian
 * bytes with trailing zero bytes stripped; a byte < 0x40 is a one-byte value
 * by itself, 0x40+n (n < 32) prefixes n bytes, 0x60 0x01 prefixes 32 bytes.
 */
function readCell(s: string, i: number): { v: string; next: number } | null {
  if (i + 2 > s.length) return null;
  const b = parseInt(s.slice(i, i + 2), 16);
  if (Number.isNaN(b)) return null;
  if (b < 0x40) return { v: s.slice(i, i + 2), next: i + 2 };
  if (b < 0x60) {
    const end = i + 2 + (b - 0x40) * 2;
    return end > s.length ? null : { v: s.slice(i + 2, end), next: end };
  }
  if (s.slice(i, i + 4) === "6001") {
    const end = i + 4 + 64;
    return end > s.length ? null : { v: s.slice(i + 4, end), next: end };
  }
  return null;
}

/** Encode a 32-byte value the way readCell reads it. */
function cellHex(hex32: string): string {
  const v = hex32.replace(/(00)+$/, "");
  const n = v.length / 2;
  if (n === 32) return `6001${v}`;
  if (n === 0) return "00";
  if (n === 1 && parseInt(v, 16) < 0x40) return v;
  return (0x40 + n).toString(16) + v;
}

const pad64 = (v: string) => (v === "00" ? "" : v).padEnd(64, "0");
const leNumber = (v: string) => {
  let n = 0n;
  for (let i = v.length - 2; i >= 0; i -= 2) n = (n << 8n) | BigInt(parseInt(v.slice(i, i + 2), 16));
  return Number(n);
};

/**
 * The SessionRecord stored under `key` (sessionKey hex) in a serialized
 * ShieldPass state, or null. A map entry is the key cell followed by a struct
 * header `2001 xxxx 0184` (4 fields) and four cells: appId, nullifier,
 * policyVersion (Uint<32>), verifiedAt (Uint<64>).
 * contracts/test (and this package's tests) hold it to the compiled ledger().
 */
export function sessionFromState(stateHex: string, key: string): SessionRecord | null {
  const s = stateHex.toLowerCase();
  const k = key.toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(k) || /^0+$/.test(k)) return null;
  const needle = cellHex(k) + "2001";
  for (let i = s.indexOf(needle); i !== -1; i = s.indexOf(needle, i + 1)) {
    if (i % 2) continue;
    let p = i + needle.length;
    if (s.slice(p + 4, p + 8) !== "0184") continue;
    p += 8;
    const cells: string[] = [];
    for (let f = 0; f < 4; f++) {
      const c = readCell(s, p);
      if (!c) break;
      cells.push(c.v);
      p = c.next;
    }
    if (cells.length !== 4) continue;
    const [appId, nullifier, version, at] = cells;
    if (appId.length > 64 || nullifier.length > 64 || version.length > 8 || at.length > 16) continue;
    return { appId: pad64(appId), nullifier: pad64(nullifier), policyVersion: leNumber(version), verifiedAt: leNumber(at) };
  }
  return null;
}

// ---------------------------------------------------------------- indexer

export type FetchLike = (url: string, init: { method: string; headers: Record<string, string>; body: string; signal?: AbortSignal }) => Promise<{
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
}>;

/** Latest serialized state (hex) of a contract, or null if the indexer doesn't know it. */
export async function fetchContractState(
  contractAddress: string,
  indexer: IndexerConfig,
  opts: { fetch?: FetchLike; signal?: AbortSignal } = {},
): Promise<string | null> {
  const f = opts.fetch ?? (globalThis.fetch as unknown as FetchLike);
  const headers: Record<string, string> = { "content-type": "application/json", accept: "application/graphql-response+json, application/json" };
  let url = indexer.url;
  if (indexer.projectId) {
    headers.project_id = indexer.projectId;
    url += `${url.includes("?") ? "&" : "?"}project_id=${encodeURIComponent(indexer.projectId)}`;
  }
  const res = await f(url, {
    method: "POST",
    headers,
    body: JSON.stringify({ query: "query($a: HexEncoded!) { contractAction(address: $a) { state } }", variables: { a: contractAddress } }),
    signal: opts.signal,
  });
  if (!res.ok) {
    const hint = res.status === 410 ? " (this indexer was retired; use Blockfrost Midnight)" : res.status === 403 || res.status === 401 ? " (check the Blockfrost Midnight project id)" : "";
    throw new Error(`Midnight indexer ${indexer.redacted} returned HTTP ${res.status}${hint}`);
  }
  const body = (await res.json()) as { data?: { contractAction: { state?: string } | null }; errors?: { message: string }[] };
  if (body.errors?.length) throw new Error(`Midnight indexer: ${body.errors[0].message}`);
  const state = body.data?.contractAction?.state;
  return state ? state : null;
}

export type VerifyOptions = {
  contractAddress: string;
  /** Your app id (64 hex) as registered with ShieldPass. */
  appId: string;
  /** The session id (64 hex) you gave the user for this login / action. */
  sessionId: string;
  network?: MidnightNetworkName;
  /** Explicit indexer; otherwise resolved from env (see resolveIndexer). */
  indexer?: IndexerConfig | { url?: string; projectId?: string };
  /** Reject sessions proved under an older policy version (after you tightened your rules). */
  minPolicyVersion?: number;
  /** Reject sessions proved more than this many seconds ago. */
  maxAgeSeconds?: number;
  /** Clock for maxAgeSeconds (unix seconds). */
  now?: number;
  /** Exact decoding via the compiled contract instead of the string decoder. */
  decodeLedger?: (stateHex: string, key: string) => SessionRecord | null;
  fetch?: FetchLike;
  signal?: AbortSignal;
};

export type SessionCheck =
  | { verified: true; session: SessionRecord }
  | { verified: false; reason: "contract-not-found" | "no-session" | "wrong-app" | "old-policy" | "too-old"; session?: SessionRecord };

/** Same as isSessionVerified, with the record and the reason for a `false`. */
export async function checkSession(o: VerifyOptions): Promise<SessionCheck> {
  const appId = bytesToHex(hexToBytes32(o.appId, "appId"));
  const key = await sessionKey(appId, o.sessionId);
  const ix = o.indexer && "redacted" in o.indexer ? o.indexer : resolveIndexer({ network: o.network, ...(o.indexer ?? {}) });
  const state = await fetchContractState(o.contractAddress, ix as IndexerConfig, { fetch: o.fetch, signal: o.signal });
  if (!state) return { verified: false, reason: "contract-not-found" };
  const session = o.decodeLedger ? o.decodeLedger(state, key) : sessionFromState(state, key);
  if (!session) return { verified: false, reason: "no-session" };
  if (session.appId.toLowerCase() !== appId) return { verified: false, reason: "wrong-app", session };
  if (o.minPolicyVersion != null && session.policyVersion < o.minPolicyVersion) return { verified: false, reason: "old-policy", session };
  if (o.maxAgeSeconds != null) {
    const now = o.now ?? Math.floor(Date.now() / 1000);
    if (now - session.verifiedAt > o.maxAgeSeconds) return { verified: false, reason: "too-old", session };
  }
  return { verified: true, session };
}

/** true iff a ShieldPass proof verified this app's session on-chain. Throws on indexer/config errors (fail closed). */
export async function isSessionVerified(o: VerifyOptions): Promise<boolean> {
  return (await checkSession(o)).verified;
}
