import { describe, expect, it } from 'vitest'
import { unlockErrorMessage } from '../src/ui.js'

const PASSWORD_ERROR = 'That password could not decrypt this share. Check all six words and try again.'
const LOAD_ERROR = 'This share could not be loaded yet. It may still be propagating; try again shortly.'

describe('unlockErrorMessage', () => {
  it('uses the password message only for authenticated-decryption failures', () => {
    const error = new Error('AEAD authentication failed on chunk 0')
    error.name = 'AuthenticationError'
    expect(unlockErrorMessage(error)).toBe(PASSWORD_ERROR)
  })

  it.each([
    new Error('Gateway does not support byte-range retrieval'),
    new Error('Gateway returned an invalid Content-Range'),
    new Error('HTTP 416'),
  ])('does not blame the password for retrieval failure', (error) => {
    expect(unlockErrorMessage(error)).toBe(LOAD_ERROR)
  })
})
