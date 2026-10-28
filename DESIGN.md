# DESIGN.md - Login Anomaly Explorer

## Context (from discovery)

- Artifact type: SaaS application (SOC console) + presentation/deck (`/story`)
- Positioning: technical
- Audience: Proofpoint bootcamp / security engineers (Córdoba detection & platform roles) | Primary action: triage a seeded case and show scored detection
- Adjectives: precise, calm, technical, honest, restrained
- Visual word translations:
  - precise -> tabular nums, mono for IDs/metrics, tight label tracking
  - calm -> cool light field, low chrominance, generous section gaps
  - technical -> sans + mono pair, hairline rules, no marketing cards in hero
  - honest -> status copy matches architecture; accent only for live/action
  - restrained -> one accent hue; max two radii; border XOR soft elevation
- Aesthetic essence (3 words): quiet detection lab
- Single-minded proposition: This is a measurable auth-detection workbench, not a chatbot demo.
- Archetype: Sage
- References: admire Linear (quiet chrome, keyboard affordances), Grafana (status meaning), Stripe Dashboard (tabular calm); avoid generic AI indigo SaaS, cream+terracotta editorial
- Mode: light | Density: balanced (not dense, not airy marketing)
- Constraints: React + plain CSS; WCAG AA; keep pill topbar; EN UI; projector-safe light; no purple/indigo brand band

## Aesthetic

- Direction: Light detection lab (OKLCH single-accent minimal, cool paper)
- Defining trait: Cool light neutrals + one teal signal; data in mono; sections separated by space and hairlines, not card stacks
- Signature move: Teal underline rule under page titles; live pulse only when sim is actually running

## Typography

- Display / body: Source Sans 3 | Google Fonts | OFL
- Mono: IBM Plex Mono | Google Fonts | OFL
- Scale: ratio 1.25 (Major Third), base 16px
  | step | size | line-height | use |
  |------|------|-------------|-----|
  | display | 2.25rem | 1.1 | hero h1 |
  | h1 | 1.75rem | 1.15 | page title |
  | h2 | 1.1rem | 1.3 | section |
  | body | 1rem | 1.5 | text |
  | small | 0.8125rem | 1.4 | meta |
  | micro | 0.72rem | 1.3 | eyebrow / labels |
- Weights: 400 / 600 / 700 | Measure: ~60ch for prose | Tracking: display -0.03em; eyebrows 0.08em uppercase

## Color

- Strategy: Cool paper lab (blue-gray neutrals). Accent is teal (hue ~195), far from indigo/violet AI default. Risk colors are semantic only.
- Distribution: 60 neutral / 30 ink surfaces / 10 teal accent
- Palette (role -> OKLCH | hex):
  - bg: oklch(0.985 0.004 230) | #f6f8fa
  - surface: oklch(0.995 0.002 230) | #ffffff
  - fg: oklch(0.28 0.02 250) | #1c2430
  - muted: oklch(0.94 0.008 230) | #e8eef3
  - muted-fg: oklch(0.52 0.02 250) | #5b6777
  - border: oklch(0.88 0.012 230) | #d0dae4
  - accent: oklch(0.52 0.11 195) | #0f766e
  - accent-fg: oklch(0.99 0.005 195) | #f0fdfa
  - primary (ink CTA): oklch(0.28 0.02 250) | #1c2430
  - success: oklch(0.55 0.14 150) | #15803d
  - warning: oklch(0.68 0.14 75) | #b45309
  - error: oklch(0.55 0.18 25) | #b91c1c
- Dark mode: out of scope (light lab locked)

## Spacing, radius, shadow

- Spacing base: 8px; scale 4/8/12/16/24/32/48
- Radius: 6px (controls/surfaces), 999px (topbar + status chips only)
- Shadow approach: soft elevation on sticky topbar only (`0 10px 30px` low-opacity ink). Panels use border, not shadow.

## Layout and composition

- Grid: modular content max 1200px; metrics auto-fit; demo steps 3-col collapsing to 1
- Spacing rhythm: tight inside panels (8–12px); loose between page sections (24–32px)
- Signature layout move: centered pill topbar + title with teal underline; CTAs right-aligned in hero-header
- Density: balanced | Scanning: F-pattern (status top-right, queue below)
- Responsive: desktop-first demo; stack hero actions under 860px

## Components and states

- Button hierarchy: primary filled ink; secondary bordered surface; Present uses accent tint (importance = demo CTA). States: hover lightens/darkens 6%; focus ring accent 2px offset; disabled 0.5 opacity
- Inputs: visible labels (eyebrow style); mono for seed/ids; border focus -> accent
- Tables: left-align text; right-align / mono tabular-nums for counts; light row separators
- Empty / loading / error: muted empty; error panel with error border tint
- Focus ring: `0 0 0 2px var(--surface), 0 0 0 4px var(--accent)`

## Motion

- Duration: fast 120ms / normal 200ms / pulse 1.6s (live only)
- Easing: ease-out
- What animates: opacity/transform; pulse-dot only when sim running
- reduced-motion: disable pulse; instant state swaps

## Iconography

- Minimal custom SVG brand mark; no icon-tile feature grids

## Imagery and illustration

- Mode: product UI only (no stock photography)
- Avoid: gradient blobs, purple glows, corporate-Memphis

## Dark mode

- Not in scope for this lock.

## Accessibility

- Contrast: AA on light field | Focus: visible managed
- Keyboard: nav links and controls operable | Targets: >=24px (buttons >= 2.1rem)
- Color independence: status also has text labels | Reduced motion: respected

## Tokens (source of truth)

```css
:root {
  --font-display: "Source Sans 3", system-ui, sans-serif;
  --font-body: "Source Sans 3", system-ui, sans-serif;
  --font-mono: "IBM Plex Mono", ui-monospace, monospace;
  --background: oklch(0.985 0.004 230);
  --surface: oklch(0.995 0.002 230);
  --foreground: oklch(0.28 0.02 250);
  --muted: oklch(0.94 0.008 230);
  --muted-foreground: oklch(0.52 0.02 250);
  --border: oklch(0.88 0.012 230);
  --accent: oklch(0.52 0.11 195);
  --accent-fg: oklch(0.99 0.005 195);
  --primary: oklch(0.28 0.02 250);
  --primary-foreground: oklch(0.99 0.005 230);
  --risk-low: oklch(0.55 0.14 150);
  --risk-medium: oklch(0.68 0.14 75);
  --risk-high: oklch(0.55 0.18 25);
  --radius: 0.375rem;
  --shadow-topbar: 0 10px 30px oklch(0.28 0.02 250 / 0.08);
  --ease-out: cubic-bezier(0.22, 1, 0.36, 1);
  --duration-fast: 120ms;
  --duration-normal: 200ms;
}
```

- Adapter: plain CSS custom properties (`frontend/src/index.css`)

## Cards and surfaces

- Panels/metrics: 1px border, surface fill, radius 6px, no shadow
- Nesting: avoid panel-in-panel; prefer section-head + table

## Slop audit

- Date: 2026-10-26 | Result: pass
- Notes: No Inter/Roboto/indigo/cream-terracotta; removed decorative story radial; pulse only when live; soft shadow topbar-only; focus-visible + reduced-motion; title teal underline shipped as signature; FE build + 5 pipeline tests green. Full browser screenshot audit deferred until Docker is up.

## Changelog

- 2026-10-27: Solid top bar (no blur). Active nav stays weight 600. Metric labels and badges at 0.8125rem.
- 2026-10-26: Console = Operations workspace (seed + metrics + Cases/Live). Kill walkthrough/guardrails/tutorial copy on app pages. Narrative only in Present `/story`.
- 2026-10-26: Slimmed Pipeline (real flow diagram with obs links labeled by what they show). Removed ArchStrip chip dump.
- 2026-10-26: Locked light detection lab (user chose option 1). Applied tokens to `frontend/src/index.css`. Adjectives precise/calm/technical/honest/restrained. Teal accent, Source Sans 3 + IBM Plex Mono, signature title underline.
