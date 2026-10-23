import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api, type StoryResponse } from "../api/client";

export function StoryPage() {
  const [story, setStory] = useState<StoryResponse | null>(null);
  const [index, setIndex] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();

  useEffect(() => {
    void api
      .story()
      .then(setStory)
      .catch((err) => setError(err instanceof Error ? err.message : String(err)));
  }, []);

  const beats = story?.beats ?? [];
  const beat = beats[index];
  const last = index >= beats.length - 1;

  const go = useCallback(
    (delta: number) => {
      setIndex((current) => {
        const next = current + delta;
        if (next < 0) return 0;
        if (next >= beats.length) return Math.max(0, beats.length - 1);
        return next;
      });
    },
    [beats.length],
  );

  useEffect(() => {
    function onKey(event: KeyboardEvent) {
      if (event.key === "Escape") {
        navigate("/");
        return;
      }
      if (event.key === "ArrowRight" || event.key === " " || event.key === "PageDown") {
        event.preventDefault();
        go(1);
      }
      if (event.key === "ArrowLeft" || event.key === "PageUp") {
        event.preventDefault();
        go(-1);
      }
      if (event.key === "Home") setIndex(0);
      if (event.key === "End" && beats.length) setIndex(beats.length - 1);
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [go, navigate, beats.length]);

  if (error) return <div className="story-shell"><div className="error">{error}</div></div>;
  if (!story || !beat) return <div className="story-shell"><div className="empty">Loading story…</div></div>;

  return (
    <div className="story-shell" data-beat={beat.id}>
      <header className="story-top">
        <div>
          <p className="eyebrow">{story.title}</p>
          <span className="muted story-progress">
            {index + 1} / {beats.length}
          </span>
        </div>
        <div className="story-top-actions">
          <span className="muted mono">{story.controls}</span>
          <Link className="btn" to="/">
            Exit
          </Link>
        </div>
      </header>

      <main className="story-stage" key={beat.id}>
        <p className="eyebrow story-kicker">{beat.kicker}</p>
        <h1 className="story-headline">{beat.headline}</h1>
        <p className="story-line">{beat.line}</p>
        <div className="story-blocks">
          {beat.blocks.map((block) => (
            <span key={block} className="story-block">
              {block}
            </span>
          ))}
        </div>
        {beat.cta && (
          <Link className="btn primary btn-xl story-cta" to={beat.cta.route}>
            {beat.cta.label}
          </Link>
        )}
      </main>

      <footer className="story-nav">
        <button className="btn btn-lg" type="button" disabled={index === 0} onClick={() => go(-1)}>
          Back
        </button>
        <div className="story-dots" aria-hidden>
          {beats.map((item, i) => (
            <button
              key={item.id}
              type="button"
              className={`story-dot ${i === index ? "on" : ""}`}
              onClick={() => setIndex(i)}
              aria-label={`Beat ${i + 1}`}
            />
          ))}
        </div>
        {last ? (
          <Link className="btn primary btn-lg" to="/?seed=42&autoseed=1">
            Live demo
          </Link>
        ) : (
          <button className="btn primary btn-lg" type="button" onClick={() => go(1)}>
            Next
          </button>
        )}
      </footer>
    </div>
  );
}
