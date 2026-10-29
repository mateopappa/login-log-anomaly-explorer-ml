import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api, type StoryResponse } from "../api/client";

export function StoryPage({ onClose }: { onClose?: () => void }) {
  const [story, setStory] = useState<StoryResponse | null>(null);
  const [index, setIndex] = useState(0);
  const [notes, setNotes] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();
  const close = onClose ?? (() => navigate("/"));

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
        close();
        return;
      }
      if (event.key === "n" || event.key === "N") {
        setNotes((open) => !open);
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
  }, [go, close, beats.length]);

  if (error) return <div className="story-shell"><div className="error">{error}</div></div>;
  if (!story || !beat) return <div className="story-shell"><div className="empty">Loading story…</div></div>;

  return (
    <div className={`story-shell ${onClose ? "story-overlay" : ""}`} data-beat={beat.id}>
      <header className="story-top">
        <div>
          <p className="eyebrow">{story.title}</p>
          <span className="muted story-progress">
            {index + 1} / {beats.length}
          </span>
        </div>
        <div className="story-top-actions">
          <span className="muted mono">{story.controls}</span>
          <button className="btn" type="button" onClick={close}>
            Board
          </button>
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
        {notes && beat.say && (
          <aside className="story-say" aria-label="Speaker cue">
            <span className="story-say-label">Decí</span>
            <p>{beat.say}</p>
          </aside>
        )}
        {beat.cta && (
          <Link className="btn primary btn-xl story-cta" to={beat.cta.route} onClick={close}>
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
          <button className="btn primary btn-lg" type="button" onClick={close}>
            Board
          </button>
        ) : (
          <button className="btn primary btn-lg" type="button" onClick={() => go(1)}>
            Next
          </button>
        )}
      </footer>
    </div>
  );
}
