import test from 'node:test'
import assert from 'node:assert/strict'
import { pct, num, splitUrlForDisplay, verdictCopy } from '../src/format.js'

const roles = (raw) => Object.fromEntries(splitUrlForDisplay(raw).map((p) => [p.text, p.role]))

test('only the hostname is marked as analysed', () => {
  const parts = splitUrlForDisplay('https://www.Example.com:8080/a/b?x=1')
  assert.deepEqual(parts.map((p) => p.text), ['https://', 'www.', 'Example.com', ':8080', '/a/b?x=1'])
  assert.deepEqual(parts.map((p) => p.role), ['ignored', 'ignored', 'analysed', 'ignored', 'ignored'])
})

test('no scheme, user-info and bare host', () => {
  assert.equal(roles('example.com/login')['example.com'], 'analysed')
  assert.equal(roles('https://user:pw@evil.net/')['user:pw@'], 'ignored')
  assert.equal(roles('https://user:pw@evil.net/')['evil.net'], 'analysed')
  assert.equal(roles('www.com')['www.com'], 'analysed') // mirrors backend: www. kept when only two labels
})

test('pct / num helpers', () => {
  assert.equal(pct(0.8123), '81.2%')
  assert.equal(pct(undefined), 'n/a')
  assert.equal(num(1234567), '1,234,567')
})

test('verdict copy never claims safety', () => {
  assert.equal(verdictCopy({ prediction: 'phishing' }).headline, 'Potential Phishing')
  const legit = verdictCopy({ prediction: 'legitimate' })
  assert.equal(legit.headline, 'Likely Legitimate')
  assert.match(legit.body, /does not prove/)
})
