type Bullet = { title: string; text: string };

export function TrustPanel({ title, bullets }: { title: string; bullets: Bullet[] }) {
  return (
    <section className="trust-strip" aria-label={title}>
      <span className="eyebrow">{title}</span>
      <div className="chip-row">
        {bullets.map((item) => (
          <span key={item.title} className="chip chip-strong" title={item.text}>
            {item.title}
          </span>
        ))}
      </div>
    </section>
  );
}
