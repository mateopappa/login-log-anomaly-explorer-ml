const LAYERS = [
  {
    title: "Product",
    items: ["Console", "Live", "Cases", "Eval"],
  },
  {
    title: "Engine",
    items: ["Simulate", "Rules∥ML", "Correlate", "Agent", "Review"],
  },
  {
    title: "Platform",
    items: ["API", "Postgres", "Redpanda", "Worker", "Grafana"],
  },
];

export function ArchStrip() {
  return (
    <section className="panel arch-strip" aria-label="Architecture layers">
      <p className="eyebrow">Architecture</p>
      <div className="arch-layers">
        {LAYERS.map((layer) => (
          <div key={layer.title} className="arch-layer">
            <strong>{layer.title}</strong>
            <div className="chip-row">
              {layer.items.map((item) => (
                <span key={item} className="chip chip-strong">
                  {item}
                </span>
              ))}
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}
