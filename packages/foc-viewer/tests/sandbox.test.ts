// @vitest-environment happy-dom
// @vitest-environment-options { "settings": { "disableJavaScriptFileLoading": true, "disableCSSFileLoading": true, "disableIframePageLoading": true } }
import { describe, expect, it } from 'vitest'
import { LOCKED_FRAME_CSP, assertLockedMarkup, sanitizeStaticHtml } from '../src/sandbox.js'

const HOSTILE_CORPUS: Array<[name: string, html: string]> = [
  ['inline script', '<p>hi</p><script>fetch("https://evil.test")</script>'],
  ['event handler', '<img alt="x" onerror="fetch(\'https://evil.test\')">'],
  ['meta refresh', '<meta http-equiv="refresh" content="0;url=https://evil.test"><p>hi</p>'],
  ['base rewrite', '<base href="https://evil.test/"><p>hi</p>'],
  ['stylesheet link', '<link rel="stylesheet" href="https://evil.test/x.css">'],
  ['nested frame', '<iframe src="https://evil.test"></iframe>'],
  ['object embed', '<object data="https://evil.test"></object><embed src="https://evil.test">'],
  ['form action', '<form action="https://evil.test"><input formaction="https://evil.test"></form>'],
  ['anchor exfil', '<a href="https://evil.test" ping="https://evil.test">click</a>'],
  ['svg anchor', '<svg><a href="https://evil.test"><text>go</text></a></svg>'],
  ['svg smil', '<svg><animate attributeName="href" to="https://evil.test"></animate><set to="1"></set></svg>'],
  ['resource urls', '<img src="https://evil.test/x.png" srcset="https://evil.test/y.png 2x"><video poster="https://evil.test/p.png"></video>'],
  ['xlink href', '<svg><image xlink:href="https://evil.test/x.png"></image></svg>'],
  ['noscript payload', '<noscript><img src="https://evil.test" onerror="alert(1)"></noscript>'],
  ['image map area', '<map><area href="https://evil.test"></map>'],
  ['mxss math specimen', '<math><mtext><table><mglyph><style><!--</style><img src="https://evil.test" onerror="alert(1)">--></style></mglyph></table></mtext></math>'],
  ['mxss svg specimen', '<svg><p><style><!--</style><img src="https://evil.test" onerror="alert(1)">--></style></p></svg>'],
]

const NAVIGATION_ATTRIBUTE_NAMES = [
  'action',
  'background',
  'cite',
  'data',
  'formaction',
  'href',
  'manifest',
  'ping',
  'poster',
  'profile',
  'src',
  'srcset',
  'xlink:href',
]

function reparse(html: string): Document {
  return new DOMParser().parseFromString(html, 'text/html')
}

describe('sanitizeStaticHtml', () => {
  it.each(HOSTILE_CORPUS)('neutralizes %s', (_name, html) => {
    const output = sanitizeStaticHtml(html)
    const doc = reparse(output)

    expect(
      doc.querySelector('script,base,link,iframe,frame,object,embed,form,area,animate,animateMotion,animateTransform,set,a')
    ).toBeNull()
    const metas = Array.from(doc.querySelectorAll('meta'))
    expect(metas).toHaveLength(1)
    expect(metas[0].getAttribute('http-equiv')).toBe('Content-Security-Policy')
    expect(metas[0].getAttribute('content')).toBe(LOCKED_FRAME_CSP)
    for (const element of Array.from(doc.querySelectorAll('*'))) {
      if (element === metas[0]) continue
      for (const attribute of Array.from(element.attributes)) {
        const name = attribute.name.toLowerCase()
        expect(name.startsWith('on'), `${_name}: ${name}`).toBe(false)
        expect(NAVIGATION_ATTRIBUTE_NAMES.includes(name), `${_name}: ${name}`).toBe(false)
      }
    }
  })

  it('keeps static text and layout content', () => {
    const output = sanitizeStaticHtml('<h1>Report</h1><p class="lead">All <strong>good</strong>.</p>')
    const doc = reparse(output)

    expect(doc.querySelector('h1')?.textContent).toBe('Report')
    expect(doc.querySelector('p.lead strong')?.textContent).toBe('good')
  })

  it('unwraps anchors but keeps their text', () => {
    const doc = reparse(sanitizeStaticHtml('<p>see <a href="https://evil.test">the appendix</a> now</p>'))
    expect(doc.querySelector('a')).toBeNull()
    expect(doc.querySelector('p')?.textContent).toBe('see the appendix now')
  })
})

describe('assertLockedMarkup', () => {
  it('accepts sanitizer output', () => {
    expect(() => assertLockedMarkup(sanitizeStaticHtml('<p>fine</p>'))).not.toThrow()
  })

  it.each([
    ['resurrected script', `<!doctype html><html><head><meta http-equiv="Content-Security-Policy" content="${LOCKED_FRAME_CSP}"></head><body><script>1</script></body></html>`],
    ['second meta', `<!doctype html><html><head><meta http-equiv="Content-Security-Policy" content="${LOCKED_FRAME_CSP}"><meta http-equiv="refresh" content="0;url=https://evil.test"></head><body></body></html>`],
    ['missing policy', '<!doctype html><html><head></head><body><p>x</p></body></html>'],
    ['event handler', `<!doctype html><html><head><meta http-equiv="Content-Security-Policy" content="${LOCKED_FRAME_CSP}"></head><body><img alt="x" onerror="1"></body></html>`],
    ['navigation attribute', `<!doctype html><html><head><meta http-equiv="Content-Security-Policy" content="${LOCKED_FRAME_CSP}"></head><body><img src="https://evil.test"></body></html>`],
  ])('rejects %s', (_name, html) => {
    expect(() => assertLockedMarkup(html)).toThrow(/rendered safely/)
  })
})

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
