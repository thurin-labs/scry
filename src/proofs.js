// ─── Proof provider detection & verification ────────────────────────────────

const PROVIDERS = [
  {
    provider: 'github',
    label: 'GitHub',
    pattern: /^https:\/\/gist\.github\.com\/([^/]+)\/([a-f0-9]+)$/i,
    parse: (m) => ({ user: m[1], gistId: m[2] }),
  },
  {
    provider: 'dns',
    label: 'DNS',
    pattern: /^dns:([^?]+)\?type=TXT$/i,
    parse: (m) => ({ domain: m[1] }),
  },
  {
    provider: 'farcaster',
    label: 'Farcaster',
    pattern: /^https:\/\/farcaster\.xyz\/([^/]+)\/(0x[a-f0-9]+)$/i,
    parse: (m) => ({ user: m[1], castHash: m[2] }),
  },
]

export function identifyProof(notation) {
  if (notation.name !== 'proof@thurin.id') return null

  for (const { provider, label, pattern, parse } of PROVIDERS) {
    const m = notation.value.match(pattern)
    if (m) {
      return { provider, label, url: notation.value, ...parse(m) }
    }
  }

  return { provider: 'unknown', label: 'Unknown', url: notation.value }
}

export function displayUrl(proof) {
  if (proof.provider === 'dns') return proof.domain
  if (proof.provider === 'github') return proof.user
  if (proof.provider === 'farcaster') return `@${proof.user}`
  return proof.url
}

export function proofHref(proof) {
  if (proof.provider === 'dns') return `https://${proof.domain}`
  if (proof.provider === 'github') return `https://github.com/${proof.user}`
  if (proof.provider === 'farcaster') return `https://farcaster.xyz/${proof.user}`
  if (proof.url.startsWith('http')) return proof.url
  return null
}

export function proofSecondaryHref(proof) {
  if (proof.provider === 'github') return proof.url
  if (proof.provider === 'farcaster') return proof.url
  return null
}

// ─── Verification functions ──────────────────────────────────────────────────

const FPR_TOKEN = 'OPENPGP4FPR:'

function containsFingerprint(text, fingerprint) {
  return text.toUpperCase().includes(FPR_TOKEN + fingerprint.toUpperCase())
}

async function verifyGitHub(proof, fingerprint) {
  try {
    const resp = await fetch(`https://api.github.com/gists/${proof.gistId}`)
    if (!resp.ok) return { verified: false, reason: `GitHub API returned ${resp.status}` }
    const data = await resp.json()

    for (const file of Object.values(data.files || {})) {
      if (file.content && containsFingerprint(file.content, fingerprint)) {
        return { verified: true }
      }
    }
    return { verified: false, reason: 'Fingerprint token not found in gist' }
  } catch (err) {
    return { verified: false, reason: `GitHub fetch failed: ${err.message}` }
  }
}

async function verifyDNS(proof, fingerprint) {
  try {
    const resp = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(proof.domain)}&type=TXT`,
      { headers: { Accept: 'application/dns-json' } },
    )
    if (!resp.ok) return { verified: false, reason: `DNS query returned ${resp.status}` }
    const data = await resp.json()

    for (const answer of data.Answer || []) {
      if (answer.data && containsFingerprint(answer.data, fingerprint)) {
        return { verified: true }
      }
    }
    return { verified: false, reason: 'Fingerprint token not found in TXT records' }
  } catch (err) {
    return { verified: false, reason: `DNS fetch failed: ${err.message}` }
  }
}

const NEYNAR_HUB = 'https://hub-api.neynar.com'
const NEYNAR_KEY = import.meta.env.VITE_NEYNAR_API_KEY

const fcHeaders = { 'x-api-key': NEYNAR_KEY }

async function resolveFid(username) {
  const resp = await fetch(
    `${NEYNAR_HUB}/v1/userNameProofByName?name=${encodeURIComponent(username)}`,
    { headers: fcHeaders },
  )
  if (!resp.ok) return null
  const data = await resp.json()
  return data.fid ?? null
}

async function verifyFarcaster(proof, fingerprint) {
  try {
    const fid = await resolveFid(proof.user)
    if (!fid) return { verified: false, reason: `Could not resolve Farcaster user "${proof.user}"` }

    // Scan recent casts for hash prefix match
    let pageToken = ''
    for (let page = 0; page < 5; page++) {
      const url = `${NEYNAR_HUB}/v1/castsByFid?fid=${fid}&pageSize=100&reverse=true${pageToken ? `&pageToken=${pageToken}` : ''}`
      const resp = await fetch(url, { headers: fcHeaders })
      if (!resp.ok) return { verified: false, reason: `Farcaster Hub returned ${resp.status}` }
      const data = await resp.json()

      for (const msg of data.messages || []) {
        if (msg.hash && msg.hash.startsWith(proof.castHash)) {
          const text = msg.data?.castAddBody?.text || ''
          if (containsFingerprint(text, fingerprint)) {
            return { verified: true }
          }
          return { verified: false, reason: 'Cast found but fingerprint token not in text' }
        }
      }

      if (!data.nextPageToken) break
      pageToken = data.nextPageToken
    }

    return { verified: false, reason: 'Cast not found' }
  } catch (err) {
    return { verified: false, reason: `Farcaster fetch failed: ${err.message}` }
  }
}

const verifiers = {
  github: verifyGitHub,
  dns: verifyDNS,
  farcaster: verifyFarcaster,
}

export async function verifyProof(proof, fingerprint) {
  const fn = verifiers[proof.provider]
  if (!fn) return { verified: false, reason: 'Unknown provider' }
  return fn(proof, fingerprint)
}
