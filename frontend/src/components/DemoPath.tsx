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
  presenterRoute?: string;
  primaryAction?: { label: string; onClick: () => void; busy?: boolean };
};

export function DemoPath({ pitch, steps, talkingPoints, presenterRoute, primaryAction }: Props) {
  return (
    <section className="panel stack demo-path">
      <div className="demo-path-top">
        <div>
          <p className="eyebrow">Demo path</p>
          <h2 className="demo-pitch">{pitch}</h2>
        </div>
        <div className="hero-actions">
          {presenterRoute && (
            <Link className="btn btn-lg" to={presenterRoute}>
              Presenter
            </Link>
          )}
          {primaryAction && (
            <button className="btn primary btn-lg" onClick={primaryAction.onClick} disabled={primaryAction.busy}>
              {primaryAction.busy ? "Seeding…" : primaryAction.label}
            </button>
          )}
        </div>
      </div>

      <ol className="demo-steps-row">
        {steps.map((step, index) => (
          <li key={step.id}>
            <span className="demo-num">{index + 1}</span>
            <strong>{step.title}</strong>
            <span className="muted demo-why">{step.why}</span>
            <Link className="btn btn-lg demo-go" to={step.route}>
              {step.action}
            </Link>
          </li>
        ))}
      </ol>

      <div className="chip-row" aria-label="Talking points">
        {talkingPoints.map((point) => (
          <span key={point} className="chip">
            {point}
          </span>
        ))}
      </div>
    </section>
  );
}
