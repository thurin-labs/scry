# Supported Proof Providers

Thurin Proofs currently support the following platforms:

| Provider | Proof Method | Client-side | Notation Example |
|---|---|---|---|
| [GitHub](./github.md) | Public gist | Yes | `proof@thurin.id=https://gist.github.com/user/id` |
| [DNS](./dns.md) | TXT record | Yes (via DoH) | `proof@thurin.id=dns:example.com?type=TXT` |
| [Farcaster](./farcaster.md) | Public cast | Yes | `proof@thurin.id=https://warpcast.com/user/0xhash` |

## Adding a New Provider

To add support for a new platform, the following must be defined:

1. **URL pattern** — How to identify and parse the proof URL from a notation
2. **Fetch method** — How to retrieve the proof content (API endpoint, CORS requirements)
3. **Verification** — Confirm the content contains `openpgp4fpr:FINGERPRINT` matching the key

All providers follow the same bidirectional linking model described in the [Thurin Proofs spec](../thurin-proofs.md).

## Planned Providers

The following providers are under consideration for future support:

- **X/Twitter** — Requires server-side proxy (no CORS, API key needed)
- **Mastodon/Fediverse** — Requires server-side proxy (no CORS, HTTP signatures)
- **Bluesky** — Public API with CORS support
- **Telegram** — Requires server-side proxy (Bot API)

## Implicitly Verified

Some identity links are verified through existing Scry functionality without needing Thurin Proofs:

- **ENS** — Verified through Ethereum address resolution (already part of Scry lookups)
- **Email** — Verified when the PGP key is found on `keys.openpgp.org` (the keyserver verifies email ownership before publishing user IDs)
