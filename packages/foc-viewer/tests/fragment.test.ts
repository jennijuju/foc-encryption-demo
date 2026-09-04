import { describe, expect, it } from 'vitest'
import { parseFragment } from '../src/fragment.js'

const CID = 'bafybeigdyrzt5sfp7udm7hu76uh7y26nf3udhvy6o2x4i5woy4vgr3vnz4'

describe('parseFragment', () => {
  it('parses one encrypted Root CID', () => {
    expect(parseFragment(`#cid=${CID}`)).toEqual({ cid: CID })
    expect(parseFragment(`cid=${CID}`)).toEqual({ cid: CID })
  })

  it.each([
    '',
    '#',
    '#pw=secret',
    '#url=https%3A%2F%2Fexample.com',
    `#cid=${CID}&pw=secret`,
    `#cid=${CID}&url=https%3A%2F%2Fexample.com`,
    '#cid=../../etc/passwd',
    '#cid=bafy',
    `#cid=${CID.toUpperCase()}`,
  ])('rejects unsafe or unsupported fragment %s', (hash) => {
    expect(parseFragment(hash)).toBeNull()
  })
})

