// Independent auditor for the key directory (crypto-spec/SPEC.md §8.3), the role Cloudflare
// plays for WhatsApp. Run it somewhere the Colap operator doesn't control (another cloud, a
// partner, a GitHub Action) and publish its output where apps can fetch it
// (NEXT_PUBLIC_KT_AUDITOR_URL / KT_AUDITOR_URL).
//
// It replays the public audit feed from the first epoch and checks that
//   * every head is signed by the directory key and links to the one before (no fork, no
//     rewritten history),
//   * every epoch's root is exactly the tree of all values published so far,
//   * per account, versions go up by one and the log position only moves forward.
// It can't tell whether a value is genuine – that's what each user's app checks for its own
// account – but it makes sure everyone is shown the same directory.
//
//   KT_URL=https://<project>.supabase.co/functions/v1/kt KT_PUBLIC_KEY=<base64url> \
//     deno run --allow-net --allow-env --allow-read --allow-write supabase/scripts/kt-audit.ts [state.json] [out.json]
//
// state.json keeps where it got to (and the tree) between runs; out.json gets {epoch, hash}.

import { b64u, fromB64u, ktHeadHash, ktLeaf, ktRoot, ktVerifyHeads, type KtHead } from "./kt.ts"

const url = Deno.env.get("KT_URL")
const pub = Deno.env.get("KT_PUBLIC_KEY")
if (!url || !pub) {
  console.error("KT_URL and KT_PUBLIC_KEY are required.")
  Deno.exit(1)
}
const [statePath = "kt-audit-state.json", outPath = "kt-audited-head.json"] = Deno.args

type Value = { key: string; version: number; epoch: number; seq: number; digest: string }
type State = { epoch: number; hash: string | null; values: Record<string, Value> }

let state: State = { epoch: 0, hash: null, values: {} }
try {
  state = JSON.parse(await Deno.readTextFile(statePath))
} catch {
  // First run: from the beginning.
}

function fail(message: string): never {
  console.error(`AUDIT FAILED: ${message}`)
  Deno.exit(2)
}

for (;;) {
  const res = await fetch(`${url}?op=audit&after=${state.epoch}`)
  if (!res.ok) fail(`audit feed ${res.status}`)
  const { heads, values } = (await res.json()) as { heads: KtHead[]; values: Value[] }
  if (!heads.length) break
  const from = state.hash ? { epoch: state.epoch, hash: fromB64u(state.hash) } : null
  try {
    await ktVerifyHeads(fromB64u(pub), from, heads)
  } catch (e) {
    fail(`heads after ${state.epoch}: ${(e as Error).message}`)
  }
  if (!from && heads[0].epoch !== 1) fail("the first run must start at epoch 1")
  for (const head of heads) {
    for (const v of values.filter((x) => x.epoch === head.epoch)) {
      const before = state.values[v.key]
      if (v.version !== (before?.version ?? 0) + 1) fail(`epoch ${head.epoch}: version of ${v.key} jumps`)
      if (before && v.seq <= before.seq) fail(`epoch ${head.epoch}: log position of ${v.key} goes back`)
      state.values[v.key] = v
    }
    const leaves = await Promise.all(
      Object.values(state.values).map(async (v) => ({
        key: fromB64u(v.key),
        leaf: await ktLeaf(fromB64u(v.key), { version: v.version, seq: v.seq, digest: fromB64u(v.digest) }),
      })),
    )
    if (b64u(await ktRoot(leaves)) !== head.root) fail(`epoch ${head.epoch}: root doesn't match the published values`)
    state.epoch = head.epoch
    state.hash = b64u(await ktHeadHash(head))
  }
}

await Deno.writeTextFile(statePath, JSON.stringify(state))
await Deno.writeTextFile(outPath, JSON.stringify({ epoch: state.epoch, hash: state.hash, audited_at: new Date().toISOString() }))
console.log(`audited up to epoch ${state.epoch}: ${Object.keys(state.values).length} accounts, consistent`)
