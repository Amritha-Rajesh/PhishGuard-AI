import test from 'node:test'
import assert from 'node:assert/strict'
import { scanUrl, getReport, ApiError } from '../src/api.js'

const ok = (data) => async () => ({ ok: true, status: 200, json: async () => data })
const fail = (status, data) => async () => ({ ok: false, status, json: async () => data })

test('scanUrl sends the URL as JSON to /api/predict and returns the result', async () => {
  let seen
  const fetchImpl = async (url, init) => {
    seen = { url, init }
    return { ok: true, status: 200, json: async () => ({ prediction: 'legitimate', phishing_probability: 0.12 }) }
  }
  const out = await scanUrl('https://example.com', { baseUrl: 'http://api.test/', fetchImpl })
  assert.equal(seen.url, 'http://api.test/api/predict')
  assert.equal(seen.init.method, 'POST')
  assert.deepEqual(JSON.parse(seen.init.body), { url: 'https://example.com' })
  assert.equal(out.prediction, 'legitimate')
})

test('server validation errors keep their code and message', async () => {
  const fetchImpl = fail(422, { error: { code: 'invalid_url', message: 'Please enter a URL.' } })
  await assert.rejects(scanUrl('', { baseUrl: 'http://api.test', fetchImpl }), (e) => {
    assert.ok(e instanceof ApiError)
    assert.equal(e.code, 'invalid_url')
    assert.equal(e.status, 422)
    assert.equal(e.message, 'Please enter a URL.')
    return true
  })
})

test('model-not-trained (503) is reported clearly', async () => {
  const fetchImpl = fail(503, { error: { code: 'model_not_available', message: 'Model files not found. Train the model first by running: python train.py' } })
  await assert.rejects(scanUrl('a.com', { baseUrl: 'http://api.test', fetchImpl }), (e) => e.code === 'model_not_available' && /train/.test(e.message))
})

test('network failure becomes a friendly error', async () => {
  const fetchImpl = async () => { throw new TypeError('fetch failed') }
  await assert.rejects(scanUrl('a.com', { baseUrl: 'http://api.test', fetchImpl }), (e) => e.code === 'network_error' && /backend/.test(e.message))
})

test('timeout becomes a friendly error', async () => {
  const fetchImpl = async () => { const e = new Error('t'); e.name = 'TimeoutError'; throw e }
  await assert.rejects(scanUrl('a.com', { baseUrl: 'http://api.test', fetchImpl }), (e) => e.code === 'timeout')
})

test('non-JSON response is handled', async () => {
  const fetchImpl = async () => ({ ok: true, status: 200, json: async () => { throw new SyntaxError('bad json') } })
  await assert.rejects(scanUrl('a.com', { baseUrl: 'http://api.test', fetchImpl }), (e) => e.code === 'bad_response')
})

test('getReport returns the report; 404 gives report_not_available', async () => {
  assert.deepEqual(await getReport({ baseUrl: 'http://api.test', fetchImpl: ok({ a: 1 }) }), { a: 1 })
  const fetchImpl = fail(404, { error: { code: 'report_not_available', message: 'No training report found.' } })
  await assert.rejects(getReport({ baseUrl: 'http://api.test', fetchImpl }), (e) => e.code === 'report_not_available')
})
