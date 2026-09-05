export const LOCKED_FRAME_CSP =
  "default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; img-src data: blob:; media-src data: blob:; font-src data:; connect-src 'none'; form-action 'none'; base-uri 'none'; frame-src 'none'; object-src 'none'"

const UNWRAP_ELEMENTS = 'a'
const BLOCKED_ELEMENTS =
  'script,meta,base,link,iframe,frame,object,embed,form,area,animate,animateMotion,animateTransform,set'
const NAVIGATION_ATTRIBUTES: Record<string, true> = {
  action: true,
  background: true,
  cite: true,
  data: true,
  formaction: true,
  href: true,
  manifest: true,
  ping: true,
  poster: true,
  profile: true,
  src: true,
  srcset: true,
  'xlink:href': true,
}
const REPARSE_BLOCKED_SELECTOR =
  'script,base,link,iframe,frame,object,embed,form,area,animate,animateMotion,animateTransform,set,a'

/**
 * Structural mXSS defense: re-parse the serialized markup exactly as the
 * srcdoc frame will and refuse to render if any blocked construct survived
 * or resurfaced through a serialize/parse differential.
 */
export function assertLockedMarkup(html: string): void {
  const reparsed = new DOMParser().parseFromString(html, 'text/html')
  const metas = Array.from(reparsed.querySelectorAll('meta'))
  const policy = metas[0]
  if (
    metas.length !== 1 ||
    policy.getAttribute('http-equiv') !== 'Content-Security-Policy' ||
    policy.getAttribute('content') !== LOCKED_FRAME_CSP ||
    reparsed.querySelector(REPARSE_BLOCKED_SELECTOR) !== null
  ) {
    throw new Error('Decrypted HTML could not be rendered safely')
  }
  for (const element of Array.from(reparsed.querySelectorAll('*'))) {
    if (element === policy) continue
    for (const attribute of Array.from(element.attributes)) {
      const name = attribute.name.toLowerCase()
      if (name.startsWith('on') || NAVIGATION_ATTRIBUTES[name]) {
        throw new Error('Decrypted HTML could not be rendered safely')
      }
    }
  }
}

export function sanitizeStaticHtml(html: string): string {
  const parsed = new DOMParser().parseFromString(html, 'text/html')
  for (const element of Array.from(parsed.querySelectorAll(UNWRAP_ELEMENTS))) {
    element.replaceWith(...Array.from(element.childNodes))
  }
  for (const element of Array.from(parsed.querySelectorAll(BLOCKED_ELEMENTS))) element.remove()
  for (const element of Array.from(parsed.querySelectorAll('*'))) {
    for (const attribute of Array.from(element.attributes)) {
      const name = attribute.name.toLowerCase()
      if (name.startsWith('on') || NAVIGATION_ATTRIBUTES[name]) {
        element.removeAttribute(attribute.name)
      }
    }
  }
  const policy = parsed.createElement('meta')
  policy.httpEquiv = 'Content-Security-Policy'
  policy.content = LOCKED_FRAME_CSP
  parsed.head.prepend(policy)
  const serialized = `<!doctype html>${parsed.documentElement.outerHTML}`
  assertLockedMarkup(serialized)
  return serialized
}

export function createLockedHtmlFrame(html: string): HTMLIFrameElement {
  const frame = document.createElement('iframe')
  frame.setAttribute('sandbox', '')
  frame.referrerPolicy = 'no-referrer'
  frame.title = 'Decrypted HTML'
  frame.srcdoc = sanitizeStaticHtml(html)
  return frame
}
