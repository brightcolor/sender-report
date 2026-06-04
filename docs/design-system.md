# sender.report — Design System & „make it look like this" guide

The sender.report look is **not** a named, off-the-shelf theme. It's a thin
**custom layer on top of Bootstrap 5.3** (AdminLTE 4 is used for the shell, but
it's optional — the distinctive look comes from the layer, not the admin template).

Visual style in one line: **clean, modern flat / "soft-UI" SaaS dashboard** —
lots of whitespace, rounded cards, subtle borders & shadows, a tinted status
color system, soft radial "glow" accents, the Inter font, and dark-mode support.

---

## The 7 ingredients that make it look good

1. **Inter (variable font).** Single biggest upgrade over default templates.
2. **Bootstrap CSS variables as design tokens.** Every tint is
   `rgba(var(--bs-success-rgb), .1)` etc. — never hard-coded hex. This is *why*
   dark mode and rebranding "just work".
3. **A status color system** (success/warning/danger/info = green/yellow/red/blue),
   shown as **tinted pill badges** and small square status icons.
4. **Soft surfaces:** rounded cards (`border-radius: .75rem`), 1px borders in
   `var(--bs-border-color)`, very gentle shadows. Nothing harsh.
5. **Subtle accents, not decoration:** faint `radial-gradient` glows, a
   coloured left accent bar, a conic-gradient score ring.
6. **Typographic hierarchy:** bold headlines with slightly negative
   `letter-spacing`; numbers with `font-variant-numeric: tabular-nums`; a mono
   font for code/scores.
7. **Dark mode for free** via `data-bs-theme="light|dark"` on `<html>`.

---

## Quick start (drop-in)

```html
<!doctype html>
<html lang="de" data-bs-theme="light">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
  <!-- load AFTER Bootstrap -->
  <link rel="stylesheet" href="sender-report-theme.css">
</head>
<body>
  …
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
```

`sender-report-theme.css` (in this folder) provides the reusable pieces:
`.sr-pill`, `.sr-status-dot`, `.sr-glow`, `.sr-ring`, `.sr-stats`,
`.sr-section-header`, `.sr-imp`, plus base typography & card polish.
Rebrand by changing `--sr-accent` / `--sr-accent-rgb` at the top.

### Component examples

```html
<!-- status pills -->
<span class="sr-pill pass"><i class="bi bi-check2"></i> Bestanden</span>
<span class="sr-pill warn"><i class="bi bi-exclamation-triangle"></i> Warnung</span>
<span class="sr-pill fail"><i class="bi bi-x-circle"></i> Fehler</span>

<!-- score ring -->
<div class="sr-ring" style="--score:73%; --ring:var(--bs-warning)">
  <div class="sr-ring-inner">
    <span class="sr-ring-value">7.3</span><span class="sr-ring-sub">/10</span>
  </div>
</div>

<!-- hero card with a soft green glow + left accent -->
<div class="card sr-glow sr-accent-left pass" style="--g-rgb: var(--bs-success-rgb)">
  <div class="card-body">…</div>
</div>

<!-- importance badge -->
<span class="sr-imp" data-level="kritisch">Kritisch</span>
```

---

## Copy-paste prompt for an LLM

> Style this UI like a **clean, modern flat "soft-UI" SaaS dashboard** (think
> Linear / Vercel / Stripe dashboards), built on **Bootstrap 5.3**. Rules:
>
> - Use the **Inter** variable font for all text; bold headlines with slightly
>   negative `letter-spacing`; numbers with `font-variant-numeric: tabular-nums`;
>   a monospace font for code/IDs/scores.
> - **Never hard-code colors.** Use Bootstrap CSS variables and build every tint
>   as `rgba(var(--bs-*-rgb), .1)`. Make the brand color the Bootstrap `--bs-primary`.
> - Cards: `border-radius: .75rem`, a 1px `var(--bs-border-color)` border, and a
>   very subtle shadow. Generous padding/whitespace. No heavy borders/shadows.
> - A **status color system** (success/warning/danger/info = green/yellow/red/blue),
>   shown as **tinted pill badges** (rounded-pill, tinted bg + matching border +
>   matching text color) and small rounded-square status icons.
> - Subtle accents only: faint `radial-gradient` glows behind hero areas, a
>   coloured 3px left accent bar on status cards, optional conic-gradient "score
>   ring". Tasteful, not flashy.
> - Use **Bootstrap Icons**, not FontAwesome.
> - Full **dark mode** via `data-bs-theme="light|dark"` on `<html>` — it must work
>   automatically because all colors come from CSS variables.
> - Mobile-first; let things wrap; use Bootstrap utility classes for spacing.
>
> Do **not** rely on the default AdminLTE/Bootstrap look — add a thin custom CSS
> layer with these tokens and components. Keep it minimal and consistent.

(You can also just hand the LLM `docs/sender-report-theme.css` from this repo and
say: "match this style and reuse these classes.")
