import test from 'node:test'
import assert from 'node:assert/strict'
import { scanReducer, initialScanState } from '../src/scanState.js'

test('idle -> loading -> success', () => {
  let s = scanReducer(initialScanState, { type: 'submit', url: 'a.com' })
  assert.equal(s.status, 'loading')
  assert.equal(s.submittedUrl, 'a.com')
  s = scanReducer(s, { type: 'success', result: { prediction: 'legitimate' } })
  assert.equal(s.status, 'success')
  assert.equal(s.result.prediction, 'legitimate')
})

test('loading -> error keeps the message and clears old result', () => {
  let s = scanReducer(initialScanState, { type: 'submit', url: 'a.com' })
  s = scanReducer(s, { type: 'failure', error: { code: 'invalid_url', message: 'bad' } })
  assert.equal(s.status, 'error')
  assert.equal(s.error.message, 'bad')
  assert.equal(s.result, null)
})

test('double submit while loading is ignored', () => {
  const loading = scanReducer(initialScanState, { type: 'submit', url: 'a.com' })
  assert.equal(scanReducer(loading, { type: 'submit', url: 'b.com' }).submittedUrl, 'a.com')
})

test('late responses after reset are ignored; reset returns to idle', () => {
  let s = scanReducer(initialScanState, { type: 'submit', url: 'a.com' })
  s = scanReducer(s, { type: 'reset' })
  assert.deepEqual(s, initialScanState)
  assert.deepEqual(scanReducer(s, { type: 'success', result: {} }), initialScanState)
})
