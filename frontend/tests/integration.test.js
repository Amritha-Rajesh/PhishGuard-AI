// Full-stack check: frontend API client -> real HTTP -> Flask -> saved model.
// Start the backend first (python app.py). The tests are skipped if it is not reachable.
import test from 'node:test'
import assert from 'node:assert/strict'
import { scanUrl, getReport, getHealth, ApiError } from '../src/api.js'

const baseUrl = process.env.PHISHGUARD_API || 'http://127.0.0.1:5000'
let up = false
try { up = (await getHealth({ baseUrl, timeoutMs: 2000 })).model_loaded === true } catch { up = false }
const opts = { skip: up ? false : 'backend is not running or model not loaded (start: python app.py)' }

test('health reports the model as loaded', opts, async () => {
  const h = await getHealth({ baseUrl })
  assert.equal(h.status, 'ok')
  assert.equal(h.model_loaded, true)
})

test('a new URL gets a real model prediction', opts, async () => {
  const r = await scanUrl('https://brand-new-host-81xz2q.secure-login-verify.top/account', { baseUrl })
  assert.ok(['phishing', 'legitimate'].includes(r.prediction))
  assert.ok(r.phishing_probability >= 0 && r.phishing_probability <= 1)
  assert.equal(r.analyzed_host, 'brand-new-host-81xz2q.secure-login-verify.top')
  assert.equal(r.path_or_query_ignored, true)
  assert.ok(r.notes.length >= 1)
})

test('different URLs produce different scores', opts, async () => {
  const a = await scanUrl('https://wikipedia.org', { baseUrl })
  const b = await scanUrl('http://paypal-secure-login.verify-account.xyz', { baseUrl })
  assert.notEqual(a.phishing_probability, b.phishing_probability)
  assert.ok(b.phishing_probability > a.phishing_probability)
})

test('invalid input comes back as a readable ApiError', opts, async () => {
  for (const bad of ['', 'not a url', 'javascript:alert(1)']) {
    await assert.rejects(scanUrl(bad, { baseUrl }), (e) => e instanceof ApiError && e.code === 'invalid_url' && e.status === 422 && e.message.length > 0)
  }
})

test('training report is served for the dashboard', opts, async () => {
  const rep = await getReport({ baseUrl })
  assert.ok(rep.final_model.test.accuracy > 0)
  assert.equal(rep.split.overlapping_hostnames, 0)
})

test('CORS: the dev origin is allowed, a foreign origin is not', opts, async () => {
  const good = await fetch(`${baseUrl}/api/health`, { headers: { Origin: 'http://localhost:5173' } })
  assert.equal(good.headers.get('access-control-allow-origin'), 'http://localhost:5173')
  const evil = await fetch(`${baseUrl}/api/health`, { headers: { Origin: 'http://evil.example' } })
  assert.equal(evil.headers.get('access-control-allow-origin'), null)
})

test('an unreachable backend produces the friendly network error', async () => {
  await assert.rejects(scanUrl('a.com', { baseUrl: 'http://127.0.0.1:1', timeoutMs: 2000 }), (e) => e.code === 'network_error')
})
