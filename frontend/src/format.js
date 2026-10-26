export const pct = (v, digits = 1) => (Number.isFinite(v) ? `${(v * 100).toFixed(digits)}%` : 'n/a')
export const num = (v) => (Number.isFinite(v) ? Number(v).toLocaleString('en-US') : 'n/a')

// Splits what the user typed into pieces and says which ones the model actually analyses.
// Mirrors the backend rules: scheme, user-info, "www.", port, path/query/fragment are ignored.
export function splitUrlForDisplay(raw) {
  const text = String(raw ?? '').trim()
  const m = text.match(/^([a-z][a-z0-9+.-]*:\/\/)?([^/?#]*)(.*)$/i)
  if (!m) return [{ text, role: 'ignored' }]
  const [, scheme = '', authority = '', rest = ''] = m
  const at = authority.lastIndexOf('@')
  const userinfo = at >= 0 ? authority.slice(0, at + 1) : ''
  let hostPort = at >= 0 ? authority.slice(at + 1) : authority
  let port = ''
  const pm = hostPort.match(/^(.*?)(:\d*)$/)
  if (pm && !hostPort.startsWith('[')) {
    hostPort = pm[1]
    port = pm[2]
  }
  let www = ''
  if (/^www\./i.test(hostPort) && (hostPort.match(/\./g) || []).length >= 2) {
    www = hostPort.slice(0, 4)
    hostPort = hostPort.slice(4)
  }
  return [
    { text: scheme, role: 'ignored' },
    { text: userinfo, role: 'ignored' },
    { text: www, role: 'ignored' },
    { text: hostPort, role: 'analysed' },
    { text: port, role: 'ignored' },
    { text: rest, role: 'ignored' },
  ].filter((p) => p.text)
}

export function verdictCopy(result) {
  if (result.prediction === 'phishing') {
    return {
      headline: 'Potential Phishing',
      body: 'The hostname looks more like the phishing hostnames the model saw in training than the legitimate ones. Do not enter passwords or personal details unless you can confirm the site another way.',
    }
  }
  return {
    headline: 'Likely Legitimate',
    body: 'The hostname looks more like the legitimate hostnames the model saw in training. That does not prove the site is safe: a phishing page can sit on a normal-looking domain.',
  }
}
