# DNS Proof

Verify domain ownership by adding a TXT record containing your PGP fingerprint.

## Setup

### 1. Add a DNS TXT record

Add a TXT record to your domain with your fingerprint:

```
example.com.  IN  TXT  "openpgp4fpr:653909A2F0E37C106F5FAF546C8857E0D8E8F074"
```

The TXT record can be added to the root domain or a subdomain. You can verify the record is live:

```bash
dig TXT example.com +short
```

### 2. Add the notation to your PGP key

Use the `dns:` URI scheme with your domain:

```bash
gpg --edit-key YOUR_KEY_ID
uid 1
notation proof@thurin.id=dns:example.com?type=TXT
save
```

### 3. Upload your updated key

```bash
gpg --export --armor YOUR_KEY_ID | curl -T - https://keys.openpgp.org
```

## How Scry Verifies

1. Parses the `dns:` URI from the `proof@thurin.id` notation
2. Extracts the domain name
3. Queries DNS TXT records via Cloudflare DNS-over-HTTPS (DoH):
   ```
   https://cloudflare-dns.com/dns-query?name=example.com&type=TXT
   ```
4. Searches all TXT records for `openpgp4fpr:FINGERPRINT`
5. Confirms the fingerprint matches the PGP key

## Requirements

- The TXT record must be publicly resolvable
- The notation URI must use the format `dns:DOMAIN?type=TXT`
- The TXT record must contain `openpgp4fpr:` followed by your 40-character fingerprint
- The full record value (with quotes) must be under the 255-character TXT record limit

## CORS

DNS lookups use Cloudflare's DoH endpoint, which supports CORS. Verification happens entirely client-side.

## Notes

- DNS propagation can take up to 48 hours, though most providers propagate within minutes
- You can add the TXT record alongside existing records — it won't conflict with MX, A, or other record types
- If you use a subdomain (e.g., `_thurin.example.com`), adjust the notation URI accordingly: `dns:_thurin.example.com?type=TXT`
