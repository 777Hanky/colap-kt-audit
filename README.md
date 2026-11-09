# Colap key directory auditor

Independent auditor for Colap's public key directory (key transparency), the role Cloudflare
plays for WhatsApp. Every 15 minutes a GitHub Action replays the directory's public audit feed
and checks that

- every signed head is signed by the directory key and links to the one before (no fork, no
  rewritten history),
- every epoch's root is exactly the tree of all values published so far,
- per account, versions only go up by one and log positions only move forward.

The latest audited head is published at
`https://raw.githubusercontent.com/777Hanky/colap-kt-audit/audit/head.json`.
The Colap apps compare it with the directory they are shown, so the server can't show different
people different directories without it being noticed.

`kt.ts` is the same code the apps use (`web/src/lib/e2ee/kt.ts` in Colap).
Directory signing key (Ed25519, base64url): `mxWJz3Iim0IbNMaoNWkVpjn_TdNKEtLNKGfcUwq7GNo`
