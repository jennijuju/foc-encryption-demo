const c = globalThis.crypto

export function getRandomValues(length: number): Uint8Array {
  const buf = new Uint8Array(length)
  c.getRandomValues(buf)
  return buf
}

export async function aesGcmEncrypt(
  key: CryptoKey,
  iv: Uint8Array,
  plaintext: Uint8Array,
  additionalData: Uint8Array
): Promise<Uint8Array> {
  const result = await c.subtle.encrypt(
    { name: 'AES-GCM', iv: iv as BufferSource, additionalData: additionalData as BufferSource, tagLength: 128 },
    key,
    plaintext as BufferSource
  )
  return new Uint8Array(result)
}

export async function aesGcmDecrypt(
  key: CryptoKey,
  iv: Uint8Array,
  ciphertext: Uint8Array,
  additionalData: Uint8Array
): Promise<Uint8Array> {
  const result = await c.subtle.decrypt(
    { name: 'AES-GCM', iv: iv as BufferSource, additionalData: additionalData as BufferSource, tagLength: 128 },
    key,
    ciphertext as BufferSource
  )
  return new Uint8Array(result)
}

export async function importAesGcmKey(rawKey: Uint8Array): Promise<CryptoKey> {
  return c.subtle.importKey('raw', rawKey as BufferSource, 'AES-GCM', false, ['encrypt', 'decrypt'])
}

const CHUNK_OBJECT_KEY_INFO = new TextEncoder().encode('FEE v1 chunked AES-256-GCM object key')

export async function deriveAesGcmObjectKey(rawKey: Uint8Array, objectNonce: Uint8Array): Promise<CryptoKey> {
  const hkdfKey = await c.subtle.importKey('raw', rawKey as BufferSource, 'HKDF', false, ['deriveKey'])
  return c.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: objectNonce as BufferSource,
      info: CHUNK_OBJECT_KEY_INFO as BufferSource,
    },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  )
}
