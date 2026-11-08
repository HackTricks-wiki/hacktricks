const assert = require('node:assert/strict')
const { readFileSync } = require('node:fs')
const { test } = require('node:test')
const vm = require('node:vm')

const source = readFileSync(require('node:path').join(__dirname, '../theme/discount.js'), 'utf8')
const KEY = 'htDiscountDismissedUntil:black-friday-2026'
const TEN_DAYS = 10 * 24 * 60 * 60 * 1000

function load(date, { storage = new Map(), blocked = false, search = '', loading = false } = {}) {
  const now = Date.parse(date)
  const nodes = []
  const listeners = new Map()
  function element() {
    const node = {
      style: { setProperty() {} },
      children: [], attributes: {}, handlers: {}, isConnected: false,
      classList: { contains: () => false, add() {}, remove() {} },
      setAttribute(name, value) { this.attributes[name] = value },
      append(...children) { children.forEach(child => this.appendChild(child)) },
      appendChild(child) { this.children.push(child); child.isConnected = true },
      addEventListener(name, fn) { this.handlers[name] = fn },
      remove() { this.isConnected = false },
    }
    nodes.push(node)
    return node
  }
  const document = {
    readyState: loading ? 'loading' : 'complete',
    baseURI: 'https://cloud.hacktricks.wiki/es/nested/page.html',
    documentElement: element(), body: element(), createElement: element,
    querySelector: () => nodes.find(n => n.className === 'ht-discount-overlay' && n.isConnected),
    addEventListener: (name, fn) => listeners.set(name, fn),
    removeEventListener: name => listeners.delete(name),
  }
  const window = {
    path_to_root: '../', location: { search, href: document.baseURI },
    matchMedia: () => ({ matches: true }), setTimeout: fn => fn(),
    localStorage: {
      getItem(key) { if (blocked) throw Error('blocked'); return storage.get(key) ?? null },
      setItem(key, value) { if (blocked) throw Error('blocked'); storage.set(key, value) },
    },
  }
  class Clock extends Date { static now() { return now } }
  vm.runInNewContext(source, { window, document, Date: Clock, URL, URLSearchParams })
  return { nodes, storage, listeners, overlay: () => document.querySelector(), find: name => nodes.find(n => n.className === name) }
}

test('campaign appears only throughout November 2026, including UTC boundaries', () => {
  for (const date of ['2026-11-01T00:00:00Z', '2026-11-30T23:59:59.999Z']) {
    assert.ok(load(date).overlay(), date)
  }
  for (const date of ['2026-10-31T23:59:59.999Z', '2026-12-01T00:00:00Z', '2026-07-15T12:00:00Z', '2027-11-08T12:00:00Z']) {
    const page = load(date)
    assert.equal(page.overlay(), undefined, date)
    assert.equal(page.find('ht-discount-image'), undefined, 'inactive campaigns must not download the image')
  }
})

test('translated nested pages use their language root and the training courses link', () => {
  const page = load('2026-11-08T12:00:00Z')
  assert.equal(page.find('ht-discount-image').src, 'https://cloud.hacktricks.wiki/es/images/hacktricks-black-friday-2026-v1.webp')
  assert.match(page.find('ht-discount-image').alt, /20% off courses, 15% off labs and exams/)
  assert.equal(page.find('ht-discount-primary').href, 'https://hacktricks-training.com/courses')
})

test('hide persists across navigation and expires exactly after ten days', () => {
  const page = load('2026-11-08T12:00:00Z')
  page.find('ht-discount-delay').handlers.click()
  assert.equal(page.overlay(), undefined)
  assert.equal(Number(page.storage.get(KEY)), Date.parse('2026-11-08T12:00:00Z') + TEN_DAYS)
  assert.equal(load('2026-11-18T11:59:59.999Z', page).overlay(), undefined)
  assert.ok(load('2026-11-18T12:00:00Z', page).overlay())
})

test('summer dismissal does not hide Black Friday and preview overrides its dismissal', () => {
  const storage = new Map([['htDiscountDismissedUntil:summer-2026', String(Date.parse('2026-12-01T00:00:00Z'))]])
  assert.ok(load('2026-11-08T12:00:00Z', { storage }).overlay())
  storage.set(KEY, String(Date.parse('2026-11-20T12:00:00Z')))
  assert.equal(load('2026-11-08T12:00:00Z', { storage }).overlay(), undefined)
  assert.ok(load('2026-11-08T12:00:00Z', { storage, search: '?discount=show' }).overlay())
  assert.equal(load('2026-12-01T00:00:00Z', { storage, search: '?discount=show' }).overlay(), undefined)
})

test('close, Escape and outside click close only the current page', () => {
  for (const method of ['close', 'escape', 'outside']) {
    const page = load('2026-11-08T12:00:00Z')
    if (method === 'close') page.find('ht-discount-close').handlers.click()
    if (method === 'escape') page.listeners.get('keydown')({ key: 'Escape' })
    if (method === 'outside') page.overlay().handlers.click({ target: page.overlay() })
    assert.equal(page.overlay(), undefined)
    assert.equal(page.listeners.has('keydown'), false)
    assert.equal(page.storage.size, 0)
    assert.ok(load('2026-11-08T12:00:01Z', page).overlay())
  }
})

test('blocked storage keeps the page and close controls working', () => {
  const page = load('2026-11-08T12:00:00Z', { blocked: true })
  assert.ok(page.overlay())
  assert.doesNotThrow(() => page.find('ht-discount-delay').handlers.click())
  assert.equal(page.overlay(), undefined)
})

test('initial page load waits for the DOM', () => {
  const page = load('2026-11-08T12:00:00Z', { loading: true })
  assert.equal(page.overlay(), undefined)
  page.listeners.get('DOMContentLoaded')()
  assert.ok(page.overlay())
})
