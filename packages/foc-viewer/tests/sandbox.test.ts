import { describe, expect, it } from 'vitest'
import { LOCKED_FRAME_CSP } from '../src/sandbox.js'

describe('locked HTML policy', () => {
  it('permits static styling while blocking scripts and every network-capable resource class', () => {
    expect(LOCKED_FRAME_CSP).toContain("default-src 'none'")
    expect(LOCKED_FRAME_CSP).toContain("script-src 'none'")
    expect(LOCKED_FRAME_CSP).toContain("connect-src 'none'")
    expect(LOCKED_FRAME_CSP).toContain("form-action 'none'")
    expect(LOCKED_FRAME_CSP).toContain("base-uri 'none'")
    expect(LOCKED_FRAME_CSP).toContain("frame-src 'none'")
    expect(LOCKED_FRAME_CSP).toContain("object-src 'none'")
    expect(LOCKED_FRAME_CSP).not.toContain("script-src 'unsafe-inline'")
  })
})
