import { describe, expect, it } from 'vitest'
import { isValidAccessKey, unlockErrorMessage } from '../src/ui.js'

const ACCESS_KEY_ERROR = 'That access key could not decrypt this share. Check it and try again.'
const LOAD_ERROR = 'This share could not be loaded yet. It may still be propagating; try again shortly.'

describe('isValidAccessKey', () => {
  it('accepts only the generated 50-character Engram format', () => {
    expect(isValidAccessKey(`engram_${'A'.repeat(43)}`)).toBe(true)
    expect(isValidAccessKey(`engram_${'A'.repeat(42)}`)).toBe(false)
    expect(isValidAccessKey(`engram_${'A'.repeat(44)}`)).toBe(false)
    expect(isValidAccessKey(`engram_${'!'.repeat(43)}`)).toBe(false)
  })
})

describe('unlockErrorMessage', () => {
  it('uses the access-key message only for authenticated-decryption failures', () => {
    const error = new Error('AEAD authentication failed on chunk 0')
    error.name = 'AuthenticationError'
    expect(unlockErrorMessage(error)).toBe(ACCESS_KEY_ERROR)
  })

  it.each([
    new Error('Gateway does not support byte-range retrieval'),
    new Error('Gateway returned an invalid Content-Range'),
    new Error('HTTP 416'),
  ])('does not blame the access key for retrieval failure', (error) => {
    expect(unlockErrorMessage(error)).toBe(LOAD_ERROR)
  })
})
