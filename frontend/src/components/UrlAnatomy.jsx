import { splitUrlForDisplay } from '../format.js'

// Shows the user which part of what they typed was analysed (cyan) and which parts were ignored (dimmed).
export default function UrlAnatomy({ raw, host }) {
  const parts = splitUrlForDisplay(raw)
  return (
    <div className="anatomy">
      <p className="anatomy-url" aria-label={`You entered ${raw}. The analysed hostname is ${host}.`}>
        {parts.map((p, i) => (
          <span key={i} className={p.role === 'analysed' ? 'part-host' : 'part-ignored'}>{p.text}</span>
        ))}
      </p>
      <p className="anatomy-legend">
        <span className="part-host">Analysed</span> is the hostname the model scored. <span className="part-ignored">Dimmed</span> parts (scheme, www, port, path, query) are ignored in this version.
      </p>
    </div>
  )
}
