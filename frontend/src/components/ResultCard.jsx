import { pct, verdictCopy } from '../format.js'
import UrlAnatomy from './UrlAnatomy.jsx'

export default function ResultCard({ result, submittedUrl, onReset }) {
  const phishing = result.prediction === 'phishing'
  const copy = verdictCopy(result)
  const p = result.phishing_probability
  const threshold = result.decision_threshold ?? 0.5

  return (
    <article className={`result ${phishing ? 'is-phishing' : 'is-legit'}`} aria-labelledby="verdict">
      <header className="result-head">
        <span className="badge" aria-hidden="true">{phishing ? '!' : '✓'}</span>
        <div>
          <h2 id="verdict">{copy.headline}</h2>
          <p>{copy.body}</p>
        </div>
      </header>

      <UrlAnatomy raw={submittedUrl} host={result.analyzed_host} />

      <div className="gauge-block">
        <div className="gauge-row">
          <span>Model score for phishing</span>
          <strong>{pct(p)}</strong>
        </div>
        <div className="gauge" role="img" aria-label={`Phishing score ${pct(p)}; decision threshold ${pct(threshold, 0)}`}>
          <div className="gauge-fill" style={{ width: `${Math.max(1, p * 100)}%` }} />
          <div className="gauge-tick" style={{ left: `${threshold * 100}%` }} />
        </div>
        <div className="gauge-scale">
          <span>0%</span>
          <span>Decision threshold {pct(threshold, 0)}</span>
          <span>100%</span>
        </div>
        <p className="fine">
          This is the model&apos;s score from hostname patterns, not a verified probability that the site is dangerous. Scores near the threshold are the least reliable.
        </p>
      </div>

      <details className="features">
        <summary>Hostname features the model used</summary>
        <dl>
          {Object.entries(result.features).map(([k, v]) => (
            <div key={k}><dt>{k}</dt><dd>{typeof v === 'number' ? Number(v.toFixed(3)) : v}</dd></div>
          ))}
        </dl>
        <p className="fine">Model: {result.model?.name} v{result.model?.version}. Scope: {result.model?.scope === 'hostname_only' ? 'hostname only' : result.model?.scope}.</p>
      </details>

      <button type="button" className="btn secondary" onClick={onReset}>Try another URL</button>
    </article>
  )
}
