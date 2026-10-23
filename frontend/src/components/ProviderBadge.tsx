type Props = {
  mode?: string | null;
  providerId?: string | null;
  model?: string | null;
};

export function ProviderBadge({ mode, providerId, model }: Props) {
  if (!mode) return <span className="badge">—</span>;
  const isMock = mode === "mock";
  return (
    <span className={`badge ${isMock ? "mock" : "llm"}`} title={providerId ?? undefined}>
      {isMock ? "Mock baseline" : `Claude Haiku${model ? ` · ${model}` : ""}`}
    </span>
  );
}
