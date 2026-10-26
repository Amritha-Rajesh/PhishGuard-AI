import { useRef, useState } from 'react'
import { scanUrl } from '../api.js'
import ResultCard from './ResultCard.jsx'

export default function ScanPage({ scan, dispatch }) {
  const [value, setValue] = useState(scan.submittedUrl || '')
  const inputRef = useRef(null)
  const requestId = useRef(0)
  const loading = scan.status === 'loading'

  async function onSubmit(e) {
    e.preventDefault()
    const url = value.trim()
    const id = ++requestId.current
    dispatch({ type: 'submit', url })
    if (!url) {
      dispatch({ type: 'failure', error: { code: 'empty', message: 'Please enter a URL to scan.' } })
      return
    }
    try {
      const result = await scanUrl(url)
      if (id === requestId.current) dispatch({ type: 'success', result })
    } catch (err) {
      if (id === requestId.current) {
        dispatch({ type: 'failure', error: { code: err.code || 'unknown', message: err.message || 'Something went wrong.' } })
      }
    }
  }

  function tryAnother() {
    requestId.current++ // ignore any answer still on its way
    dispatch({ type: 'reset' })
    setValue('')
    inputRef.current?.focus()
  }

  return (
    <div className="page scan">
      <section className="hero">
        <h1>Check a link before you trust it</h1>
        <p className="lede">
          Paste a URL and a trained machine learning model estimates whether its hostname resembles phishing sites. The link is never opened.
        </p>

        <form className="address" onSubmit={onSubmit} noValidate>
          <label htmlFor="url-input" className="sr-only">URL to scan</label>
          <input
            id="url-input"
            ref={inputRef}
            type="text"
            inputMode="url"
            autoComplete="off"
            autoCapitalize="off"
            spellCheck={false}
            placeholder="https://example.com/login"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            disabled={loading}
            aria-describedby="url-hint"
            aria-invalid={scan.status === 'error'}
          />
          <button type="submit" className="btn" disabled={loading}>{loading ? 'Scanning…' : 'Scan URL'}</button>
        </form>
        <p id="url-hint" className="hint">
          Example format: <code>https://secure-login.example.com/account</code>. Writing http:// or https:// is optional.
        </p>
      </section>

      <div className="feedback" aria-live="polite">
        {loading && (
          <p className="loading"><span className="spinner" aria-hidden="true" /> Running the saved model on this hostname…</p>
        )}
        {scan.status === 'error' && (
          <div className="error" role="alert">
            <strong>Could not scan this URL</strong>
            <p>{scan.error.message}</p>
          </div>
        )}
        {scan.status === 'success' && (
          <ResultCard result={scan.result} submittedUrl={scan.submittedUrl} onReset={tryAnother} />
        )}
      </div>

      <section className="privacy" aria-labelledby="privacy-title">
        <h2 id="privacy-title">Privacy and safety</h2>
        <ul>
          <li>The URL is sent only to this app&apos;s own backend and analysed as text. It is not visited, downloaded or followed.</li>
          <li>The backend does not write submitted URLs to its logs.</li>
          <li>No live threat-intelligence or blocklist service is consulted. The result comes from the trained model alone.</li>
          <li>Never rely on this tool alone before entering passwords or payment details.</li>
        </ul>
      </section>
    </div>
  )
}
