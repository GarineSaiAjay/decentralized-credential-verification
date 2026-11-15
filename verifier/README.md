# Standalone credential verifier

`index.html` is one self-contained page. Open it from disk or put it on any web host. It checks an ACVS
credential file against a public blockchain and **never contacts the university's server**. The file is
read in the browser and is not uploaded anywhere.

## Using it

1. Open `index.html` and choose the credential file the graduate gave you.
2. Enter the address of a node of the network the file names (a public RPC endpoint works).
3. If the page does not recognise the issuer registry the file names, check that address against one
   published by a body you trust, then tick the box. **A forged file can name a registry of its own**, so
   the file alone must never decide whom to trust.
4. Press **Verify**.

## What it checks

| Check | How |
|---|---|
| The four stage signatures | Ed25519, over exactly `ACVS-APPROVAL-v1\|id\|stage\|hash`, in the browser |
| The fields shown are the ones signed | Only with the full file: the hash is recomputed from the text it carries |
| The issuer is recognised | `IssuerRegistry.issuer(id)`: listed, not suspended. Its name and DID come from the registry, not the file |
| The anchor is the issuer's | The ledger contract must be the one the registry names for that issuer |
| Each signing key is the issuer's | `IssuerRegistry.keyInfo`: registered for that stage, and not revoked |
| The credential is in the anchored block | `LedgerAnchor.credentialStatus`: the Merkle proof is checked by the contract, at the stated position |
| It has not been revoked | The revocation bit for that position |

## Two kinds of file

| File | Who can get it | What the verifier can say |
|---|---|---|
| `credential.json` | Anyone, from the public verification page | The issuer signed and anchored a credential with this ID, and has not revoked it. **The name and other details are not proven**, because the hash also covers the student ID, which this file leaves out |
| `credential-full.json` | Signed-in staff, who hand it to the graduate | The above, and every field shown is the one that was signed |

## Verdicts

| Verdict | Meaning |
|---|---|
| `VALID` | Everything checks, and the fields are proven (full file) |
| `GENUINE RECORD, DETAILS NOT PROVEN` | Everything checks for the public file; the details shown are not covered |
| `REVOKED` | Genuinely issued, and revoked since |
| `INVALID` | A check failed; the page says which |
| `ISSUED, BUT RE-ANCHORED SINCE` | The issuer started a new ledger epoch that replaces this block; ask the issuer |
| `SIGNATURES ONLY` | The file names no blockchain anchor (exported before its block was anchored) |
| `NOT CHECKED` | The registry was not confirmed, or the file names none |
| `COULD NOT BE CHECKED` | The node could not be reached, or is on another network. Nothing is wrong with the file because of this |

## Limits

- It does not check personal (security-key) countersignatures or the university's rules on signing order.
  The university's own verification page does.
- Revocation is what the chain says. A revocation the worker has not yet written to the chain is not seen.
- It needs a current browser (Ed25519 in Web Crypto: Chrome or Edge 137+, Firefox 129+, Safari 17+).
- The node you choose can lie by omission (for example, serve an old state). Use one you trust, or two.

## Recognised registries

The list is the `KNOWN` constant at the top of the script in `index.html`. A registry in that list needs
no tick. Anyone hosting this page decides what goes in it.

## Test

`scripts/chain-test.sh` opens this page from disk in Chrome with the backend stopped, and checks that it
accepts a genuine file and rejects each tampered one (`e2e/verifier.mjs`).
