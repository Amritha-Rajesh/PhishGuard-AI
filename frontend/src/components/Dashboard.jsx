import { useEffect, useState } from 'react'
import { getReport } from '../api.js'
import { num, pct } from '../format.js'

function Stat({ label, value, note }) {
  return (
    <div className="stat">
      <dd>{value}</dd>
      <dt>{label}</dt>
      {note && <p>{note}</p>}
    </div>
  )
}

function SplitBar({ label, counts }) {
  const total = counts.legitimate + counts.phishing
  const phishShare = total ? (counts.phishing / total) * 100 : 0
  return (
    <div className="splitbar">
      <div className="splitbar-head"><span>{label}</span><span>{num(total)} hostnames</span></div>
      <div className="splitbar-track" role="img" aria-label={`${label}: ${num(counts.legitimate)} legitimate, ${num(counts.phishing)} phishing`}>
        <div className="seg-legit" style={{ width: `${100 - phishShare}%` }} />
        <div className="seg-phish" style={{ width: `${phishShare}%` }} />
      </div>
      <div className="splitbar-foot"><span>Legitimate {num(counts.legitimate)}</span><span>Phishing {num(counts.phishing)}</span></div>
    </div>
  )
}

function ConfusionMatrix({ cm }) {
  const rows = [
    { name: 'Actually legitimate', cells: [cm.tn, cm.fp], good: 0 },
    { name: 'Actually phishing', cells: [cm.fn, cm.tp], good: 1 },
  ]
  return (
    <table className="cm">
      <caption>Confusion matrix on the held-out test set</caption>
      <thead>
        <tr><td /><th scope="col">Predicted legitimate</th><th scope="col">Predicted phishing</th></tr>
      </thead>
      <tbody>
        {rows.map((r) => {
          const total = r.cells[0] + r.cells[1]
          return (
            <tr key={r.name}>
              <th scope="row">{r.name}</th>
              {r.cells.map((c, j) => {
                const correct = j === r.good
                const frac = total ? c / total : 0
                return (
                  <td key={j} className={correct ? 'cm-good' : 'cm-bad'} style={{ '--fill': 0.12 + frac * 0.55 }}>
                    <strong>{num(c)}</strong>
                    <span>{pct(frac)} of row · {correct ? 'correct' : 'error'}</span>
                  </td>
                )
              })}
            </tr>
          )
        })}
      </tbody>
    </table>
  )
}

function RocChart({ roc, point }) {
  const S = 300, M = 38
  const x = (v) => M + v * (S - M - 12)
  const y = (v) => S - M - v * (S - M - 12)
  const pts = roc.fpr.map((f, i) => `${x(f).toFixed(1)},${y(roc.tpr[i]).toFixed(1)}`).join(' ')
  return (
    <figure className="roc">
      <svg viewBox={`0 0 ${S} ${S}`} role="img" aria-label={`ROC curve, area under curve ${roc.auc.toFixed(3)}`}>
        {[0, 0.25, 0.5, 0.75, 1].map((t) => (
          <g key={t}>
            <line x1={x(0)} x2={x(1)} y1={y(t)} y2={y(t)} className="grid" />
            <line x1={x(t)} x2={x(t)} y1={y(0)} y2={y(1)} className="grid" />
            <text x={M - 6} y={y(t) + 4} textAnchor="end" className="tick">{t}</text>
            <text x={x(t)} y={S - M + 16} textAnchor="middle" className="tick">{t}</text>
          </g>
        ))}
        <line x1={x(0)} y1={y(0)} x2={x(1)} y2={y(1)} className="diag" />
        <polyline points={pts} className="curve" />
        <circle cx={x(point.fpr)} cy={y(point.tpr)} r="5" className="op" />
        <text x={(M + S) / 2} y={S - 6} textAnchor="middle" className="axis">False positive rate</text>
        <text x="12" y={S / 2 - 10} textAnchor="middle" className="axis" transform={`rotate(-90 12 ${S / 2 - 10})`}>True positive rate</text>
      </svg>
      <figcaption>Area under the curve: <strong>{roc.auc.toFixed(3)}</strong>. The dot marks the model&apos;s actual operating point at the 50% threshold; the dashed line is random guessing.</figcaption>
    </figure>
  )
}

export default function Dashboard() {
  const [state, setState] = useState({ status: 'loading' })

  useEffect(() => {
    let cancelled = false
    getReport()
      .then((report) => !cancelled && setState({ status: 'ready', report }))
      .catch((error) => !cancelled && setState({ status: 'error', error }))
    return () => { cancelled = true }
  }, [])

  if (state.status === 'loading') return <div className="page"><p className="loading"><span className="spinner" aria-hidden="true" /> Loading the training report…</p></div>

  if (state.status === 'error') {
    const missing = state.error.code === 'report_not_available'
    return (
      <div className="page">
        <h1>Model performance</h1>
        <div className="error" role="alert">
          <strong>{missing ? 'No training results available yet' : 'Could not load the training report'}</strong>
          <p>{missing ? 'The model has not been trained on this computer. Run python train.py in the backend folder, then reload this page.' : state.error.message}</p>
        </div>
      </div>
    )
  }

  const r = state.report
  const t = r.final_model.test
  const cd = r.class_distribution
  const sel = r.selection.selected
  const struct = r.hostname_structure_check.share_with_two_or_fewer_labels
  const cl = r.cleaning
  const maxImp = Math.max(...r.feature_importance.map((f) => f.importance), 1e-9)

  return (
    <div className="page dash">
      <h1>Model performance</h1>
      <p className="lede">
        Every number on this page comes from <code>reports/training_report.json</code>, written by <code>train.py</code> on {new Date(r.generated_at).toLocaleString()}. Scores are measured on {num(r.split.test_rows)} hostnames the model never saw in training.
      </p>

      <section aria-labelledby="h-final">
        <h2 id="h-final">Final model: {sel}</h2>
        <dl className="stats">
          <Stat label="Accuracy" value={pct(t.accuracy)} note={`Always guessing “legitimate” would score ${pct(r.baselines.majority_class_accuracy)}`} />
          <Stat label="Precision (phishing)" value={pct(t.precision)} note="Of URLs flagged, how many truly were phishing" />
          <Stat label="Recall (phishing)" value={pct(t.recall)} note="Of real phishing hostnames, how many were caught" />
          <Stat label="F1-score (phishing)" value={pct(t.f1)} />
          <Stat label="ROC-AUC" value={t.roc_auc.toFixed(3)} />
          <Stat label="Missed phishing" value={pct(t.false_negative_rate)} note="False-negative rate" />
        </dl>
        <p className="fine">Phishing is treated as the positive class. Selection used 3-fold grouped cross-validation on the training part only and picked the highest phishing F2 score (recall counts twice as much as precision).</p>
      </section>

      <section aria-labelledby="h-eval" className="two-col">
        <div>
          <h2 id="h-eval">Confusion matrix</h2>
          <ConfusionMatrix cm={r.final_model.confusion_matrix} />
        </div>
        <div>
          <h2>ROC curve</h2>
          <RocChart roc={r.final_model.roc} point={{ fpr: t.false_positive_rate, tpr: t.recall }} />
        </div>
      </section>

      <section aria-labelledby="h-compare">
        <h2 id="h-compare">Algorithm comparison</h2>
        <p className="fine">Cross-validation on the training part (mean of 3 folds). The test set was not used to choose between models.</p>
        <div className="table-wrap">
          <table className="data">
            <thead>
              <tr><th scope="col">Algorithm</th><th scope="col">Accuracy</th><th scope="col">Precision</th><th scope="col">Recall</th><th scope="col">F1</th><th scope="col">F2</th><th scope="col">ROC-AUC</th></tr>
            </thead>
            <tbody>
              {r.candidates.map((c) => (
                <tr key={c.name} className={c.selected ? 'picked' : undefined}>
                  <th scope="row">{c.name}{c.selected && <span className="tag">Selected</span>}<small>{c.description}</small></th>
                  <td>{pct(c.cv.accuracy.mean)}</td><td>{pct(c.cv.precision.mean)}</td><td>{pct(c.cv.recall.mean)}</td>
                  <td>{pct(c.cv.f1.mean)}</td><td>{pct(c.cv.f2.mean)}</td><td>{c.cv.roc_auc.mean.toFixed(3)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section aria-labelledby="h-data">
        <h2 id="h-data">Dataset and class distribution</h2>
        <p>
          <strong>{r.dataset.file}</strong>: {num(r.dataset.rows_raw)} rows × {r.dataset.columns_raw} columns. Only the <code>URL</code> and <code>label</code> columns are used (dataset label 1 = legitimate, 0 = phishing; the model uses phishing as the positive class).
        </p>
        <div className="splitbars">
          <SplitBar label="Raw dataset" counts={cd.raw} />
          <SplitBar label="After cleaning (one row per hostname)" counts={cd.after_cleaning} />
          <SplitBar label="Training set" counts={cd.train} />
          <SplitBar label="Test set" counts={cd.test} />
        </div>
        <ul className="plain">
          <li>Removed {num(cl.dropped_duplicate_urls)} duplicate URLs, {num(cl.dropped_invalid_urls)} invalid URLs and {num(cl.hostnames_with_conflicting_labels)} hostnames that appeared with both labels ({num(cl.rows_removed_for_conflicting_hostnames)} rows).</li>
          <li>Collapsed {num(cl.dropped_duplicate_hostnames)} repeated hostnames so each hostname counts once.</li>
          <li>The split keeps related hostnames together: {num(r.split.overlapping_hostnames)} hostnames and {num(r.split.overlapping_groups)} registered domains appear in both training and test.</li>
        </ul>
      </section>

      <section aria-labelledby="h-features">
        <h2 id="h-features">Features used</h2>
        <p className="fine">Calculated from the hostname text only. The bars show how much the ROC-AUC drops on the test sample when a feature is shuffled (permutation importance).</p>
        <div className="table-wrap">
          <table className="data">
            <thead><tr><th scope="col">Feature</th><th scope="col">Meaning</th><th scope="col">Importance</th></tr></thead>
            <tbody>
              {r.features.map((f) => {
                const imp = r.feature_importance.find((i) => i.feature === f.name)?.importance ?? 0
                return (
                  <tr key={f.name}>
                    <th scope="row"><code>{f.name}</code></th>
                    <td>{f.description}</td>
                    <td className="impcell"><span className="impbar" style={{ width: `${Math.max(2, (imp / maxImp) * 100)}%` }} /><span>{imp.toFixed(3)}</span></td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </section>

      <section aria-labelledby="h-limits" className="callout">
        <h2 id="h-limits">What these numbers do not tell you</h2>
        <ul className="plain">
          <li>In this dataset, {pct(struct.legitimate, 0)} of legitimate hostnames are plain registered domains such as <code>example.com</code>, against {pct(struct.phishing, 0)} of phishing ones. Hostnames with extra subdomains (for example <code>accounts.example.com</code>) are therefore more likely to be flagged, even when they are legitimate.</li>
          <li>Removing the dot-count and label-count features changed test accuracy from {pct(t.accuracy)} to {pct(r.ablation.test.accuracy)}, so the model is not relying on those two features alone, but the pattern above is still present in the data.</li>
          <li>Paths, query strings and page content are ignored. Phishing pages hosted on trusted domains can be missed.</li>
          <li>The test set comes from the same collection as the training data. Results on new, real-world links may be lower.</li>
        </ul>
      </section>
    </div>
  )
}
