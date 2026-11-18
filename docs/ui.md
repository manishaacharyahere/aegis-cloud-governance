# Dashboard design system

The dashboard in `apps/web` is built from one component library, `src/components/ui`. Pages import only from there (`@/components/ui`), so every screen uses the same building blocks and behaves the same way. To add a screen, compose existing components. Add a new component only when a pattern is needed in two places.

## Direction

The dashboard is an operations console that security, compliance and FinOps staff use every day. It is dense, quiet and quick to scan.

- **Accent:** one teal "signal" accent marks interactive and active elements.
- **Colours:** the colours for findings and states (danger, high, warning, success, info) appear only where a status is shown, always next to an icon and a label.
- **Signal rail:** a 3px bar on the left of KPI tiles and table rows shows severity, so a scan down the left edge finds the problems.
- **Motion:** movement only shows a change of state. Numbers roll in the direction they changed, toasts and dialogs lift in, and the segmented control's indicator slides. Everything respects `prefers-reduced-motion`.

## Tokens

Colours are CSS variables in `src/index.css`, defined twice: dark (the default) and `[data-theme="light"]`. The theme button in the top bar cycles through system, light and dark, and the choice is remembered. Tailwind 4 maps the variables to utilities (`bg-surface`, `text-fg-muted`, `border-border`, `text-danger`, and so on). Components never hard-code colours.

What a status looks like is decided in one place, `src/lib/tones.ts`: `toneOf('pending_approval')` returns `'warning'`, and `StatusBadge` picks its icon and colour from that. `SEVERITY_ORDER` is the single severity ordering.

## Components

| Component | Use it for |
|---|---|
| `Card` | Every surface: title, description, icon and actions in the header. Cards are not nested. |
| `StatCard`, `StatGrid` | KPIs. `tone="auto"` stays neutral at zero, so "0 critical" never looks alarming. `onOpen` links the tile to its list. |
| `DataTable` | Every table. It always renders a header row, has built-in loading, error (with Retry) and empty states, and an optional severity rail. With `onRowOpen`, the main cell is a real button, so keyboard users can open rows too. |
| `Pager` | Cursor paging: "Load more" for feeds, Previous/Next for browsable lists. |
| `StatusBadge`, `Chip` | Statuses and severities (icon plus label plus colour), and plain labels. |
| `Button` | primary, secondary, ghost, danger and link variants, with a `loading` state. |
| `ConfirmAction` | Irreversible actions (reject, release, revoke, dismiss, approve baseline). It opens a native modal `<dialog>`, which traps focus, closes on Escape and returns focus afterwards. |
| `Field`, `Input`, `Select`, `Textarea`, `RadioGroup` | Forms. `Field` connects the label, hint and error to the control. Selects are native. |
| `Callout`, `EmptyState`, `ErrorState`, `Skeleton` | Notices, empty and error states, and loading placeholders. |
| `Segmented` | A small set of mutually exclusive filters (risk band). |
| `DiffList`, `Timeline`, `KeyValue` | Before → after changes, decisions over time, and detail fields. |
| `Mono`, `CopyButton` | Identifiers and hashes: truncated, with the full value on hover, and copyable. |
| `BarList`, `AreaChart`, `Meter` | Single-series charts (see below). |
| `Toaster`, `useToast` | Confirmations after an action. Errors use `role="alert"`. |
| `ErrorBoundary`, `BackLink`, `SectionTitle`, `ThemeToggle` | Page shell helpers. |

## Charts

The charts follow one method:

- one hue for a single series, with no legend because the card title names it;
- thin marks: bars no thicker than 12px with a 4px rounded end, 2px lines over a 10% area wash;
- hairline gridlines and "clean" axis ticks (`lib/ticks.ts`);
- values shown in text colours, never in the series colour.

The area chart has a crosshair tooltip that keyboard users can drive with the arrow keys, and a "Show as table" view, so nothing is hidden behind hover.

## Accessibility

- **Navigation:** a skip link and grouped navigation with `aria-current`. Filters live in the URL, so views can be bookmarked and Back works.
- **Keyboard:** row-opening buttons, disclosure buttons with `aria-expanded` (risk findings), and evidence citations that move focus to the cited item.
- **Not colour alone:** every status has an icon and a label, and charts have table views.
- **Not yet:** an automated axe check in CI. Until then, the e2e journeys exercise the same roles and labels a screen reader uses.

## Credits

Some components adapt designs from [SmoothUI](https://smoothui.dev) (MIT, © Eduardo Calvo): the motion tempo (`lib/motion.ts`), `CopyButton`, the rolling `AnimatedNumber`, the citation chips, and the neutral and semantic token values. Each adapted file says so in its header. Icons come from [Lucide](https://lucide.dev) (ISC). The fonts are Geist and Geist Mono (SIL OFL), bundled locally with no font CDN.
