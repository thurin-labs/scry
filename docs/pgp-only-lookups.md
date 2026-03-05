# PGP-Only Lookups (Future Consideration)

## The Idea

Allow Scry to look up any PGP fingerprint directly from `keys.openpgp.org` — without requiring an on-chain Signet registration. This would show key info and verify `proof@thurin.id` notations for anyone with a PGP key, even if they've never touched Ethereum.

## Why Consider It

- The overlap of ETH users and PGP key users is very small
- Requiring Signet registration creates a high barrier to entry
- PGP-only lookups could serve as a discovery funnel: user sees their proofs on Scry, then learns about on-chain identity claims via Signet
- Expands the potential user base significantly

## Why Wait

- This is essentially what Keyoxide already does — need a clear differentiator
- Scry's unique value is the on-chain identity layer (ETH address + PGP key binding)
- Adding PGP-only lookups changes the product positioning
- Should validate the core on-chain flow first before broadening scope
- Risk of diluting the message: "prove your identity on-chain" vs "another PGP key viewer"

## Two-Tier Model (If Implemented)

1. **PGP tier** — Key info, user IDs, proof verification (works for anyone with a PGP key)
2. **On-chain tier** — ETH address binding, attestation status, signature verification, SBT status (requires Signet)

For unclaimed keys, the on-chain section would show a CTA: "Link this key to your ETH address on Signet."

## What Would Change

- `FingerprintDetail` would need to fetch keys from `keys.openpgp.org` independently of contract events
- New fallback UI when no on-chain claims exist but the key is valid
- Search input would need to handle bare fingerprints that aren't on-chain
- Proof verification already works independently — no changes needed there

## Key ID Shorthand (Related)

Support lookup by the last 16 hex chars of a fingerprint (the "long key ID"). This would allow shorter URLs like `scry.thurin.id/#/pgp/CD3D0D7F0C9E5FB8` instead of the full 40-char fingerprint.

### Options

1. **Keyserver resolve** — Hit `keys.openpgp.org` to resolve key ID → full fingerprint, then query the contract. Adds a network request but no contract changes.
2. **Contract v2** — Store/index by key ID alongside the full fingerprint. Requires contract redeployment and migration of existing attestations.

Option 1 could ship independently. Option 2 is a v2 contract conversation.

## Decision

Parking both for now. Focus on getting traction with Scry + Signet as-is before broadening scope.
