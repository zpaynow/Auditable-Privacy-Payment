export interface LogLine {
  t: number
  text: string
  level: 'info' | 'ok' | 'err'
}

export function Activity({ lines }: { lines: LogLine[] }) {
  return (
    <section className="card">
      <header>
        <h2>Activity</h2>
      </header>
      {lines.length === 0 ? (
        <p className="empty">Progress and results of your operations appear here.</p>
      ) : (
        <div className="log">
          {lines.map((l) => (
            <div key={l.t + l.text} className={l.level === 'info' ? '' : l.level}>
              {new Date(l.t).toLocaleTimeString()} {l.text}
            </div>
          ))}
        </div>
      )}
    </section>
  )
}
