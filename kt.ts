// Key transparency (crypto-spec/SPEC.md §8.3): a public, append-only directory of every
// account's key log, like WhatsApp's auditable key directory. Each epoch the server commits
// to one value per account – the current head of its account log – in a sparse Merkle tree,
// and signs a head that chains to the previous one. Clients check a contact's keys against
// it (everyone sees the same keys), check their own entry (nobody slipped in a key for them),
// and an independent auditor checks that the directory only ever moves forward.
//
// Pure: no I/O, only WebCrypto. The server (supabase/functions/kt) builds trees with it.

// Self-contained (no imports): the Deno edge function imports this file directly.
// Plain `Uint8Array` in older TypeScript (Deno), `Uint8Array<ArrayBuffer>` in newer.
const bytes = (n: number) => new Uint8Array(n);
type Bytes = ReturnType<typeof bytes>;
function concat(...parts: Uint8Array[]): Bytes {
  const out = bytes(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}
function u32(n: number): Bytes {
  const b = bytes(4);
  new DataView(b.buffer).setUint32(0, n);
  return b;
}
function u64(n: number): Bytes {
  const b = bytes(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n));
  return b;
}
const utf8 = (s: string): Bytes => new TextEncoder().encode(s) as Bytes;
const lp = (b: Uint8Array | string) => {
  const raw = typeof b === "string" ? utf8(b) : b;
  return concat(u32(raw.length), raw);
};
function uuidBytes(id: string): Bytes {
  const h = id.replace(/-/g, "").toLowerCase();
  if (!/^[0-9a-f]{32}$/.test(h)) throw new KtError("format", "uuid");
  return Uint8Array.from(h.match(/../g)!.map((x) => parseInt(x, 16))) as Bytes;
}
export function b64u(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
export function fromB64u(s: string): Bytes {
  const t = s.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(t + "=".repeat((4 - (t.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0)) as Bytes;
}
function equal(a: Uint8Array, b: Uint8Array) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

const DEPTH = 256;

async function sha256(...parts: Uint8Array[]): Promise<Bytes> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", concat(...parts)));
}

export class KtError extends Error {
  constructor(readonly code: "proof" | "signature" | "chain" | "mismatch" | "format", message: string) {
    super(`kt ${code}: ${message}`);
  }
}

/** Where an account sits in the tree: hashed, so the tree reveals no user IDs. */
export const ktKey = (userId: string) => sha256(lp("colap.kt.key.v1"), uuidBytes(userId));

/** One account log row, as stored (everything that's signed, and the link to the row before). */
export type KtRow = { prev_hash: string | null; body: string; signer: string; sig: string };

export const ktRowDigest = (r: KtRow) =>
  sha256(lp("colap.kt.row.v1"), lp(r.prev_hash ?? ""), lp(r.body), lp(r.signer), lp(r.sig));

/** What the directory holds per account: the n-th version, pointing at log row `seq`. */
export type KtValue = { version: number; seq: number; digest: Bytes };

export const ktLeaf = (key: Uint8Array, v: KtValue) => sha256(Uint8Array.of(0), key, u32(v.version), u64(v.seq), v.digest);

// Empty subtrees: empty[256] is an empty leaf slot, empty[d] a whole empty subtree at depth d.
let emptyCache: Bytes[] | null = null;
async function empties(): Promise<Bytes[]> {
  if (emptyCache) return emptyCache;
  const e: Bytes[] = new Array(DEPTH + 1);
  e[DEPTH] = await sha256(Uint8Array.of(2));
  for (let d = DEPTH - 1; d >= 0; d--) e[d] = await sha256(Uint8Array.of(1), e[d + 1], e[d + 1]);
  emptyCache = e;
  return e;
}

const bit = (key: Uint8Array, d: number) => (key[d >> 3] >> (7 - (d & 7))) & 1;
const node = (l: Uint8Array, r: Uint8Array) => sha256(Uint8Array.of(1), l, r);

/** Root of the tree over `leaves` (key → leaf hash). Server side. */
export async function ktRoot(leaves: { key: Bytes; leaf: Bytes }[]): Promise<Bytes> {
  const e = await empties();
  const sorted = [...leaves].sort((a, b) => cmp(a.key, b.key));
  async function build(items: typeof sorted, d: number): Promise<Bytes> {
    if (items.length === 0) return e[d];
    if (d === DEPTH) return items[0].leaf;
    const split = items.findIndex((i) => bit(i.key, d) === 1);
    const left = split === -1 ? items : items.slice(0, split);
    const right = split === -1 ? [] : items.slice(split);
    return node(await build(left, d + 1), await build(right, d + 1));
  }
  return build(sorted, 0);
}

/**
 * Proof for `key`: the siblings along its path, top-down, leaving out empty ones (marked in a
 * 256-bit bitmap). Server side.
 */
export async function ktProve(leaves: { key: Bytes; leaf: Bytes }[], key: Bytes): Promise<string> {
  const e = await empties();
  const sorted = [...leaves].sort((a, b) => cmp(a.key, b.key));
  const bitmap = bytes(32);
  const siblings: Bytes[] = [];
  async function hashOf(items: typeof sorted, d: number): Promise<Bytes> {
    if (items.length === 0) return e[d];
    if (d === DEPTH) return items[0].leaf;
    const split = items.findIndex((i) => bit(i.key, d) === 1);
    const left = split === -1 ? items : items.slice(0, split);
    const right = split === -1 ? [] : items.slice(split);
    return node(await hashOf(left, d + 1), await hashOf(right, d + 1));
  }
  let items = sorted;
  for (let d = 0; d < DEPTH; d++) {
    const mine = items.filter((i) => bit(i.key, d) === bit(key, d));
    const other = items.filter((i) => bit(i.key, d) !== bit(key, d));
    if (other.length) {
      bitmap[d >> 3] |= 1 << (7 - (d & 7));
      siblings.push(await hashOf(other, d + 1));
    }
    items = mine;
  }
  return b64u(concat(bitmap, ...siblings));
}

/** Recomputes the root from a proof: for `value` (or for an absent key when null). */
export async function ktRootFromProof(key: Uint8Array, value: KtValue | null, proof: string): Promise<Bytes> {
  const e = await empties();
  let raw: Bytes;
  try {
    raw = fromB64u(proof);
  } catch {
    throw new KtError("format", "proof encoding");
  }
  const bitmap = raw.subarray(0, 32);
  let count = 0;
  for (let d = 0; d < DEPTH; d++) count += (bitmap[d >> 3] >> (7 - (d & 7))) & 1;
  if (raw.length !== 32 + count * 32) throw new KtError("format", "proof length");
  const siblings: Uint8Array[] = [];
  for (let i = 0; i < count; i++) siblings.push(raw.subarray(32 + i * 32, 64 + i * 32));
  let h = value ? await ktLeaf(key, value) : e[DEPTH];
  for (let d = DEPTH - 1; d >= 0; d--) {
    const present = (bitmap[d >> 3] >> (7 - (d & 7))) & 1;
    const sib = present ? siblings.pop()! : e[d + 1];
    h = bit(key, d) ? await node(sib, h) : await node(h, sib);
  }
  return h;
}

// ---------- Signed epoch heads ----------

export type KtHead = { epoch: number; root: string; prev: string | null; time: number; sig: string };

export const ktHeadHash = (h: Omit<KtHead, "sig">) =>
  sha256(lp("colap.kt.head.v1"), u64(h.epoch), fromB64u(h.root), h.prev ? fromB64u(h.prev) : bytes(32), u64(h.time));

async function verifySig(pub: Uint8Array, sig: Uint8Array, data: Uint8Array) {
  const key = await crypto.subtle.importKey("raw", pub as Bytes, { name: "Ed25519" }, false, ["verify"]);
  return crypto.subtle.verify({ name: "Ed25519" }, key, sig as Bytes, data as Bytes);
}

/**
 * Verifies a run of consecutive heads: signatures by the directory's key, and each linking to
 * the one before. `from` is the last head this client trusted (or null on first use).
 */
export async function ktVerifyHeads(serverPub: Uint8Array, from: { epoch: number; hash: Uint8Array } | null, heads: KtHead[]) {
  let prev = from;
  for (const h of heads) {
    const hash = await ktHeadHash(h);
    if (!(await verifySig(serverPub, fromB64u(h.sig), hash))) throw new KtError("signature", `head ${h.epoch}`);
    // On first contact (no `from`) the first head is taken as is; links are checked from there.
    if (prev && (h.epoch !== prev.epoch + 1 || !h.prev || !equal(fromB64u(h.prev), prev.hash))) {
      throw new KtError("chain", `head ${h.epoch}`);
    }
    prev = { epoch: h.epoch, hash };
  }
  return prev;
}

// ---------- What a client checks ----------

/** A contact's account log, as fetched, against their directory entry. */
export async function ktCheckLog(
  rows: (KtRow & { seq: number })[],
  value: KtValue | null,
  identitySeq: number,
): Promise<"verified" | "pending"> {
  // Not in the directory yet (new account), or its identity is newer than the last epoch.
  if (!value || identitySeq > value.seq) return "pending";
  const row = rows.find((r) => r.seq === value.seq);
  // The directory points past the log we were served, or at a different row: someone is being
  // shown a different history than everyone else.
  if (!row || !equal(await ktRowDigest(row), value.digest)) throw new KtError("mismatch", `row ${value.seq}`);
  return "verified";
}

export const ktValueJson = (v: KtValue) => ({ version: v.version, seq: v.seq, digest: b64u(v.digest) });
export const ktValueFrom = (j: { version: number; seq: number; digest: string }): KtValue => ({ version: j.version, seq: j.seq, digest: fromB64u(j.digest) });

function cmp(a: Uint8Array, b: Uint8Array) {
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return 0;
}
