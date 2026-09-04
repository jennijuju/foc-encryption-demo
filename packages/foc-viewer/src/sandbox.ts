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

function sanitizeStaticHtml(html: string): string {
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
  return `<!doctype html>${parsed.documentElement.outerHTML}`
}

export function createLockedHtmlFrame(html: string): HTMLIFrameElement {
  const frame = document.createElement('iframe')
  frame.setAttribute('sandbox', '')
  frame.referrerPolicy = 'no-referrer'
  frame.title = 'Decrypted HTML'
  frame.srcdoc = sanitizeStaticHtml(html)
  return frame
}
