import { Link } from "react-router-dom";

export type DemoStep = {
  id: string;
  title: string;
  route: string;
  action: string;
  why: string;
};

type Props = {
  pitch: string;
  steps: DemoStep[];
  talkingPoints: string[];
};

export function DemoPath({ pitch, steps, talkingPoints }: Props) {
  return (
    <section className="panel stack demo-path">
      <div>
        <h2 style={{ margin: 0, fontSize: "1rem" }}>Demo path</h2>
        <p style={{ margin: "0.4rem 0 0" }}>{pitch}</p>
      </div>
      <ol className="demo-steps">
        {steps.map((step) => (
          <li key={step.id}>
            <div className="demo-step-head">
              <strong>{step.title}</strong>
              <Link className="btn" to={step.route}>
                Go
              </Link>
            </div>
            <p className="muted" style={{ margin: "0.25rem 0" }}>
              <span className="mono">{step.action}</span>
            </p>
            <p className="muted" style={{ margin: 0, fontSize: "0.85rem" }}>
              {step.why}
            </p>
          </li>
        ))}
      </ol>
      <div>
        <h3 style={{ margin: "0 0 0.4rem", fontSize: "0.9rem" }}>Talking points</h3>
        <ul className="muted" style={{ margin: 0, paddingLeft: "1.1rem", fontSize: "0.85rem" }}>
          {talkingPoints.map((point) => (
            <li key={point}>{point}</li>
          ))}
        </ul>
      </div>
    </section>
  );
}
