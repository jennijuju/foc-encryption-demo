const CID_PATTERN = /^b[a-z2-7]{20,120}$/

export interface FragmentParams {
  cid: string
}

/** Parse a CID-only URL fragment. */
export function parseFragment(hash: string): FragmentParams | null {
  const raw = hash.startsWith('#') ? hash.slice(1) : hash
  if (!raw) return null

  const entries = [...new URLSearchParams(raw).entries()]
  if (entries.length !== 1 || entries[0][0] !== 'cid') return null

  const cid = entries[0][1]
  return CID_PATTERN.test(cid) ? { cid } : null
}

/** Build a password-free URL fragment for an encrypted Root CID. */
export function buildFragment({ cid }: FragmentParams): string {
  if (!CID_PATTERN.test(cid)) {
    throw new Error('Invalid encrypted Root CID')
  }
  return `#cid=${cid}`
}
