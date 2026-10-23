type Bullet = { title: string; text: string };

export function TrustPanel({ title, bullets }: { title: string; bullets: Bullet[] }) {
  return (
    <section className="panel stack">
      <h2 style={{ margin: 0, fontSize: "1rem" }}>{title}</h2>
      <div className="grid" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))" }}>
        {bullets.map((item) => (
          <div key={item.title} style={{ borderTop: "1px solid var(--border)", paddingTop: "0.7rem" }}>
            <strong>{item.title}</strong>
            <p className="muted" style={{ margin: "0.35rem 0 0", fontSize: "0.85rem" }}>
              {item.text}
            </p>
          </div>
        ))}
      </div>
    </section>
  );
}
