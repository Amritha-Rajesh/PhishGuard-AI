import { useEffect, useReducer, useState } from 'react'
import { initialScanState, scanReducer } from './scanState.js'
import ScanPage from './components/ScanPage.jsx'
import Dashboard from './components/Dashboard.jsx'
import About from './components/About.jsx'

const TABS = [
  { id: 'scan', label: 'Scan a URL' },
  { id: 'performance', label: 'Model performance' },
  { id: 'about', label: 'About' },
]

const tabFromHash = () => {
  const id = window.location.hash.replace('#/', '')
  return TABS.some((t) => t.id === id) ? id : 'scan'
}

export default function App() {
  const [tab, setTab] = useState(tabFromHash)
  // scan state lives here so the result survives switching tabs
  const [scan, dispatch] = useReducer(scanReducer, initialScanState)

  useEffect(() => {
    const onHash = () => setTab(tabFromHash())
    window.addEventListener('hashchange', onHash)
    return () => window.removeEventListener('hashchange', onHash)
  }, [])

  return (
    <>
      <a className="skip" href="#main">Skip to content</a>
      <header className="topbar">
        <div className="brand">
          <svg width="30" height="30" viewBox="0 0 32 32" aria-hidden="true">
            <path d="M16 2 4 7v8c0 7.2 5 12.6 12 15 7-2.4 12-7.8 12-15V7L16 2Z" fill="none" stroke="var(--cyan)" strokeWidth="2" strokeLinejoin="round" />
            <path d="m10.5 16 4 4 7-8" fill="none" stroke="var(--blue)" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          <div>
            <p className="brand-name">PhishGuard AI</p>
            <p className="brand-sub">Machine Learning-Based Phishing URL Detection System</p>
          </div>
        </div>
        <nav aria-label="Main">
          {TABS.map((t) => (
            <a key={t.id} href={`#/${t.id}`} aria-current={tab === t.id ? 'page' : undefined}>{t.label}</a>
          ))}
        </nav>
      </header>

      <div className="notice" role="note">
        <strong>An estimate, not a guarantee.</strong> Predictions use the hostname text only, so a malicious page on a normal-looking domain can be missed and a safe site can be flagged.
      </div>

      <main id="main">
        {tab === 'scan' && <ScanPage scan={scan} dispatch={dispatch} />}
        {tab === 'performance' && <Dashboard />}
        {tab === 'about' && <About />}
      </main>

      <footer className="footer">
        PhishGuard AI is a college Machine Learning and Data Mining project. It does not visit URLs and does not query live threat-intelligence services.
      </footer>
    </>
  )
}
