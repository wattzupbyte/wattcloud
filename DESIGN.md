# DESIGN.md — Wattcloud Design System

> **Purpose**: Single source of truth for visual design, layout, and
> interaction patterns. Wattcloud is a browser SPA; a coding agent should
> be able to implement any screen from this document alone.

---

## 1. Design Principles

1. **Dark, minimal, private** — Every pixel should communicate security and calm. No visual clutter.
2. **Mobile-first** — All layouts designed for 360px first, then scaled up. Desktop is the adaptation, not the baseline.
3. **One language across viewports** — Phone, tablet, and desktop share the same components and interactions. No desktop-only paradigms grafted onto mobile (or vice versa).
4. **Touch-optimized** — Minimum tap target: 44×44dp. Generous spacing between interactive elements.

---

## 2. Color System

All colors defined as HSL. No opacity-based grays — use explicit surface tones for predictability.

### 2.1 Background Surfaces (darkest → lightest)

| Token                  | HSL                    | Hex       | Usage                                      |
|------------------------|------------------------|-----------|---------------------------------------------|
| `--bg-base`            | hsl(0, 0%, 7%)         | `#121212` | App background, root canvas                 |
| `--bg-surface`         | hsl(0, 0%, 11%)        | `#1C1C1C` | Cards, bottom sheets, list items            |
| `--bg-surface-raised`  | hsl(0, 0%, 15%)        | `#262626` | Modals, dropdowns, FAB, elevated elements   |
| `--bg-surface-hover`   | hsl(0, 0%, 18%)        | `#2E2E2E` | Hover/press state for surfaces              |
| `--bg-input`           | hsl(0, 0%, 13%)        | `#212121` | Text inputs, search bars, dropdowns         |

### 2.2 Accent (Green — Privacy/Encryption)

| Token                  | HSL                     | Hex       | Usage                                     |
|------------------------|-------------------------|-----------|-------------------------------------------|
| `--accent`             | hsl(142, 60%, 45%)      | `#2EB860` | Primary buttons, FAB, active tabs, links  |
| `--accent-hover`       | hsl(142, 60%, 52%)      | `#40D474` | Hover/press on accent elements            |
| `--accent-muted`       | hsl(142, 40%, 18%)      | `#1B3627` | Accent backgrounds (chips, badges, tags)  |
| `--accent-text`        | hsl(142, 70%, 65%)      | `#5FDB8A` | Text on dark backgrounds needing accent   |

### 2.3 Text

| Token                  | HSL                    | Hex       | Usage                                      |
|------------------------|------------------------|-----------|---------------------------------------------|
| `--text-primary`       | hsl(0, 0%, 93%)        | `#EDEDED` | Headings, primary labels, file names        |
| `--text-secondary`     | hsl(0, 0%, 60%)        | `#999999` | Metadata, timestamps, helper text           |
| `--text-disabled`      | hsl(0, 0%, 38%)        | `#616161` | Disabled labels, placeholders               |
| `--text-inverse`       | hsl(0, 0%, 7%)         | `#121212` | Text on accent-colored buttons              |

### 2.4 Semantic

| Token                  | HSL                    | Hex       | Usage                                      |
|------------------------|------------------------|-----------|---------------------------------------------|
| `--danger`             | hsl(0, 65%, 55%)       | `#D64545` | Delete actions, error states                |
| `--danger-muted`       | hsl(0, 40%, 18%)       | `#3D1F1F` | Error background tints                      |
| `--warning`            | hsl(36, 85%, 55%)      | `#E0A320` | Warnings, quota alerts (same as `--accent-warm`) |
| `--success`            | same as `--accent`     |           | Reuse accent green for success              |

### 2.5 Secondary Accent (Warm Amber) — see Section 29.2 for usage rules

| Token                  | HSL                     | Hex       | Usage                                        |
|------------------------|-------------------------|-----------|----------------------------------------------|
| `--accent-warm`        | hsl(36, 85%, 55%)       | `#E0A320` | Favorites, starred items, premium highlights |
| `--accent-warm-muted`  | hsl(36, 50%, 18%)       | `#3D2E10` | Background tint for warm-accent elements     |
| `--accent-warm-text`   | hsl(36, 90%, 68%)       | `#F0C04A` | Warm accent text on dark backgrounds         |

### 2.6 Borders & Dividers

| Token                  | HSL                    | Hex       | Usage                                      |
|------------------------|------------------------|-----------|---------------------------------------------|
| `--border`             | hsl(0, 0%, 18%)        | `#2E2E2E` | Subtle dividers, card borders               |
| `--border-focus`       | `--accent`             |           | Focused input borders                       |

---

## 3. Typography

**Font family**: `Inter` — loaded via Google Fonts or bundled. Fallback: `-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif`.

All sizes in `rem` (base 16px). Line heights are unitless multipliers.

| Token          | Size     | Weight | Line Height | Letter Spacing | Usage                              |
|----------------|----------|--------|-------------|----------------|------------------------------------|
| `--t-h1`       | 1.5rem   | 700    | 1.3         | -0.02em        | Screen titles (e.g. "Files")       |
| `--t-h2`       | 1.125rem | 600    | 1.35        | -0.01em        | Section headers, modal titles      |
| `--t-body`     | 0.9375rem| 400    | 1.5         | 0              | Default body text, file names      |
| `--t-body-sm`  | 0.8125rem| 400    | 1.45        | 0.01em         | Metadata, timestamps, captions     |
| `--t-label`    | 0.75rem  | 500    | 1.4         | 0.03em         | Uppercase labels, tab labels       |
| `--t-button`   | 0.875rem | 600    | 1           | 0.02em         | Buttons, chips, FAB labels         |

**Rules**:
- Never use font sizes below 12px (0.75rem).
- All caps only for `--t-label` (tab labels, section overlines). Nowhere else.
- No bold body text for emphasis — use `--accent-text` color instead.

---

## 4. Spacing & Grid

**Base unit**: 4px. All spacing values are multiples of 4.

| Token       | Value | Usage                                           |
|-------------|-------|-------------------------------------------------|
| `--sp-xs`   | 4px   | Icon-to-label gap, inline padding               |
| `--sp-sm`   | 8px   | Between related elements, list item inner pad    |
| `--sp-md`   | 16px  | Card padding, section gaps, standard margin      |
| `--sp-lg`   | 24px  | Between sections, modal padding                  |
| `--sp-xl`   | 32px  | Screen-level top/bottom padding                  |
| `--sp-2xl`  | 48px  | Large separations, empty state centering          |

### Content Margins

- **Mobile (< 600px)**: 16px horizontal padding from screen edge.
- **Tablet & Desktop (≥ 600px)**: Content max-width 960px, centered. 24px horizontal padding.

---

## 5. Radius

Style: **fully rounded pills** for interactive elements, softer rounding for containers.

| Token              | Value    | Usage                                        |
|--------------------|----------|----------------------------------------------|
| `--r-pill`         | 9999px   | Buttons, chips, tags, search bar, FAB        |
| `--r-card`         | 16px     | Cards, bottom sheets, modals, dropdowns      |
| `--r-input`        | 12px     | Text inputs, dropdowns, select fields        |
| `--r-thumbnail`    | 8px      | File/photo thumbnails in grid view           |
| `--r-avatar`       | 9999px   | User avatars (always circular)               |

---

## 6. Elevation & Shadows

Minimal shadows. Elevation communicated primarily through surface color changes (see Section 2.1), not drop shadows. Shadows used only for floating elements.

| Token              | Value                                         | Usage                  |
|--------------------|-----------------------------------------------|------------------------|
| `--shadow-fab`     | `0 4px 12px rgba(0,0,0,0.5)`                  | FAB only               |
| `--shadow-sheet`   | `0 -4px 24px rgba(0,0,0,0.4)`                 | Bottom sheets          |
| `--shadow-dropdown`| `0 4px 16px rgba(0,0,0,0.4)`                  | Dropdown menus         |

No shadows on cards, list items, or buttons. They rely on `--bg-surface` vs `--bg-base` contrast.

---

## 7. Icons

**Icon set**: [Phosphor Icons](https://phosphoricons.com/) — open source, 6 weights (thin, light, regular, bold, fill, duotone).

| Property          | Value                |
|-------------------|----------------------|
| Default size      | 20×20dp              |
| Default weight    | `regular` (1.5px stroke equivalent) |
| Color             | `--text-secondary`   |
| Active color      | `--accent`           |
| Tap target        | 44×44dp minimum      |

### Weight Usage Rules

| Context                              | Phosphor Weight  |
|--------------------------------------|------------------|
| Default UI icons (toolbar, menus)    | `regular`        |
| Bottom nav — inactive tab            | `regular`        |
| Bottom nav — active tab              | `fill`           |
| Emphasis/headings (empty states)     | `light`          |
| Inline small icons (metadata, tags)  | `regular`        |
| Destructive action icons             | `bold`           |

Use `regular` as the baseline. Never mix more than two weights on the same screen region. `duotone` and `thin` are reserved — do not use them to keep visual noise low.

---

## 8. Breakpoints

Mobile-first. Only two breakpoints — keep it simple.

| Name       | Min-width | Behavior                                              |
|------------|-----------|-------------------------------------------------------|
| **Mobile** | 0         | Single column. Bottom nav. FAB visible. Full-width content. |
| **Desktop**| 600px     | Top nav replaces bottom nav. Content max-width 960px centered. FAB remains. Grid columns increase. |

No intermediate "tablet" breakpoint. Devices 600px+ use the desktop layout.

---

## 9. Navigation

### 9.1 Mobile (< 600px): Bottom Tab Bar

- **Position**: Fixed at screen bottom, above safe area insets.
- **Height**: 56dp.
- **Background**: `--bg-surface` with a 1px top border `--border`.
- **Tabs (3 visible)**:
  1. **Files** — `folder` icon
  2. **Photos** — `image` icon
  3. **Favorites** — `star` icon
- **Active tab**: Icon changes to filled variant + `--accent` color. Label in `--accent` color.
- **Inactive tab**: Stroke icon + label in `--text-secondary`.
- **Label**: Always visible, `--t-label` size, below icon. No label-hiding on scroll.
- **Interaction**: Tap only. No swipe between tabs.

Settings and Trash are not top-level tabs — they live in the drawer (9.2) / avatar dropdown (9.3). This keeps the main surface focused on user files and matches the lock-a-vault mental model: secondary screens are one level deeper than the daily-use surfaces.

### 9.2 Mobile: Swipe-Out Drawer

- **Trigger**: Hamburger icon (top-left of the screen top bar) OR swipe from left edge.
- **Overlay**: Semi-transparent black overlay (`rgba(0,0,0,0.5)`) behind the drawer.
- **Drawer width**: 280dp, max 80% of screen width.
- **Background**: `--bg-surface-raised`.
- **Content**:
  - App wordmark at top (40dp height, `--sp-lg` padding).
  - Section: Navigation links duplicating bottom tabs (for discoverability).
  - Section: Providers (active storage backends with status dot; tap opens provider context sheet).
  - Section: Storage usage bar (thin accent-colored progress bar, "X of Y used" label, per-provider breakdown).
  - Section: Settings · Trash · About / Help.
  - Section: **Lock vault** (destructive-style row, `--danger` text). Replaces a generic "Log out" — BYO has no server session to terminate; this purges in-memory keys and returns to the unlock screen.
- **Animation**: Slide in from left, 250ms ease-out.

### 9.3 Desktop (≥ 600px): Top Navigation Bar

- **Position**: Fixed at top, full width.
- **Height**: 56dp.
- **Background**: `--bg-surface`.
- **Bottom border**: 1px `--border`.
- **Layout (left → right)**:
  - App wordmark (left-aligned).
  - Nav links: Files, Photos, Favorites — `--t-body` weight 500. Active link has `--accent` color + a 2px bottom accent underline inside the bar.
  - Right side: Search icon button, per-provider status indicator cluster, user menu (pseudonymous device label in a 32dp circle avatar derived from the device fingerprint).
- **User menu dropdown**: Settings, Trash, About, Help, Lock vault.
- **No hamburger** on desktop. Drawer content is accessible via the nav and the user-menu dropdown.

### 9.4 Top Bar (per-screen, below nav on desktop / at screen top on mobile)

- **Height**: 56dp.
- **Background**: transparent (inherits `--bg-base`).
- **Left**: Hamburger menu icon (mobile) or nothing (desktop). On sub-pages: back arrow.
- **Center**: Screen title in `--t-h1`.
- **Right**: Contextual actions (e.g. search icon, sort/view toggle, select-all).

---

## 10. Floating Action Button (FAB)

- **Position**: Fixed, bottom-right. 16dp from right edge, 16dp above bottom nav (mobile) or 24dp from bottom (desktop).
- **Size**: 56×56dp.
- **Shape**: Circular (`--r-pill`).
- **Color**: `--accent` background, `--text-inverse` icon.
- **Shadow**: `--shadow-fab`.
- **Icon**: `plus` (Phosphor) at 24dp.
- **Press state**: Scale to 0.95 + `--accent-hover` background, 100ms.

### FAB Expansion (on tap)

Instead of navigating to a new screen, the FAB expands into a **mini bottom sheet** or a **speed-dial menu** upward:

- **Options** (contextual per screen):
  - Files screen: "Upload file", "Create folder".
  - Photos screen: "Upload photos".
- **Speed-dial items**: Each item is a pill-shaped row: icon + label, `--bg-surface-raised` background, stacked vertically above the FAB with 8dp gaps.
- **Animation**: Items fade + slide up in staggered sequence (50ms delay per item, 200ms duration each).
- **Dismiss**: Tap outside, tap FAB again, or back gesture. Background dims with `rgba(0,0,0,0.3)`.

---

## 11. Bottom Sheets

All modals, confirmations, pickers, and contextual menus render as **bottom sheets** on both mobile and desktop viewports. This keeps modality consistent regardless of screen size.

### 11.1 Structure

```
┌──────────────────────────────────────┐
│           [drag handle]              │  ← 4dp × 36dp pill, --text-disabled
│                                      │
│  Title (--t-h2)                      │
│  Subtitle/description (--t-body-sm)  │
│                                      │
│  [Content / form / list]             │
│                                      │
│  [Action buttons]                    │
└──────────────────────────────────────┘
```

- **Overlay**: `rgba(0,0,0,0.5)`.
- **Background**: `--bg-surface-raised`.
- **Radius**: `--r-card` on top-left and top-right only. Bottom corners: 0 (flush with screen bottom).
- **Shadow**: `--shadow-sheet`.
- **Max height**: 85% of viewport height. Content scrolls internally if overflow.
- **Desktop width**: Max 480px, centered horizontally, anchored to bottom.
- **Animation**: Slide up from bottom, 300ms ease-out.
- **Dismiss**: Drag down, tap overlay, or explicit close/cancel button.
- **Drag handle**: Always visible. 4dp tall, 36dp wide, centered, `--text-disabled` color, `--r-pill` radius.

### 11.2 Bottom Sheet Types

**Confirmation sheet** (e.g. "Delete 3 files?"):
- Title: action description.
- Body: consequence description in `--text-secondary`.
- Buttons: "Cancel" (ghost button) + "Delete" (danger pill button). Buttons are full-width stacked vertically on mobile, side-by-side on desktop.

**Selection sheet** (e.g. "Move to folder"):
- Scrollable list of options, each 48dp tall with icon + label.
- Active/selected option has `--accent-muted` background.

**Form sheet** (e.g. "Rename file"):
- Input field(s) inside the sheet.
- Primary action button at bottom.

---

## 12. Buttons

All buttons use `--r-pill` radius.

| Variant        | Background           | Text color        | Border             | Usage                          |
|----------------|----------------------|-------------------|--------------------|--------------------------------|
| **Primary**    | `--accent`           | `--text-inverse`  | none               | Main CTAs: Save, Upload, Confirm |
| **Secondary**  | `--bg-surface-raised`| `--text-primary`  | 1px `--border`     | Cancel, secondary actions      |
| **Ghost**      | transparent          | `--text-secondary` | none              | Tertiary actions, "Skip"       |
| **Danger**     | `--danger`           | white              | none              | Delete, remove                 |
| **Icon-only**  | transparent          | `--text-secondary` | none              | Toolbar actions, nav icons     |

### States

| State     | Behavior                                                        |
|-----------|-----------------------------------------------------------------|
| Default   | As defined above                                                |
| Hover     | Background lightens by one surface step (desktop only)          |
| Pressed   | Scale 0.97, 100ms ease                                         |
| Disabled  | Opacity 0.4, no pointer events                                 |
| Loading   | Text replaced by 20dp spinner (accent-colored), button width preserved |

### Sizes

| Size     | Height | Horizontal Padding | Font           |
|----------|--------|--------------------|----------------|
| Default  | 44dp   | 24dp               | `--t-button`   |
| Small    | 36dp   | 16dp               | `--t-body-sm` weight 600 |

---

## 13. Form Elements

### 13.1 Text Input

- **Height**: 48dp.
- **Background**: `--bg-input`.
- **Border**: 1px `--border`, changes to `--accent` on focus.
- **Radius**: `--r-input`.
- **Text**: `--t-body`, `--text-primary`.
- **Placeholder**: `--text-disabled`.
- **Label**: Displayed above the input, `--t-body-sm` weight 500, `--text-secondary`. 8dp gap below label.
- **Error state**: Border becomes `--danger`. Error message below input in `--danger` color, `--t-body-sm`.

### 13.2 Search Bar

- **Height**: 44dp.
- **Background**: `--bg-input`.
- **Radius**: `--r-pill`.
- **Icon**: `search` icon (Phosphor) at left, `--text-disabled`.
- **Clear button**: `x` icon at right, visible when input has value.
- **Placeholder**: "Search files..." in `--text-disabled`.

### 13.3 Dropdown / Select

- Same dimensions and styling as text input.
- Chevron-down icon at right.
- Opens a **bottom sheet** with option list (not a native `<select>` picker).

### 13.4 Checkbox

- **Size**: 20×20dp.
- **Unchecked**: `--bg-input` fill, 1.5px `--border` stroke, `--r-input` radius (slightly rounded square).
- **Checked**: `--accent` fill, white `check` icon inside.
- **Label**: `--t-body`, 12dp gap from checkbox.

### 13.5 Toggle / Switch

- **Track**: 40×24dp, `--bg-input` when off, `--accent` when on. Pill-shaped (`--r-pill`).
- **Thumb**: 20×20dp circle, white. Slides left/right with 150ms ease.

### 13.6 Passphrase Input

Wattcloud-specific. Passphrase is the entry point to every crypto operation — UX must encourage strong entries without leaking length or content.

- Base style identical to Text Input (13.1).
- Trailing `eye` / `eye-slash` icon button (Phosphor, `--text-secondary`) toggles reveal. Reveal is momentary; collapse happens on blur.
- No native browser autofill beyond `autocomplete="current-password"` / `new-password`. Never expose passphrase to any wrapping form submission.
- Optional strength meter (3-segment bar below input) during **initial setup only**. Hidden during unlock — entropy display there is a timing-side-channel surface.
- Argon2id progress (see `Argon2Progress.svelte`) renders as a thin accent strip beneath the input while the KDF runs, paired with "Deriving keys…" helper text. No percentage — the operation is meant to feel deliberate, not instant.

---

## 14. Lists & Items

### 14.1 File/Folder List Item (list view)

```
┌────────────────────────────────────────────────────┐
│  [icon 40dp]  [name]                    [⋮ menu]   │
│               [size · date]                         │
│               --text-secondary                      │
└────────────────────────────────────────────────────┘
```

- **Height**: 64dp.
- **Padding**: 16dp horizontal.
- **Icon**: File-type icon or folder icon, 40×40dp, `--r-thumbnail` radius, `--bg-surface-raised` background.
- **Name**: `--t-body`, single line, ellipsis overflow.
- **Metadata**: `--t-body-sm`, `--text-secondary`.
- **Three-dot menu**: `dots-three-vertical` icon, right-aligned, opens bottom sheet with actions.
- **Divider**: 1px `--border` between items, inset from left by 68dp (after icon).
- **Hover (desktop)**: `--bg-surface-hover` background.
- **Long press (mobile) / Right click (desktop)**: Enters selection mode.

### 14.2 File/Folder Grid Item (grid view)

```
┌──────────────────┐
│                  │
│   [thumbnail]    │  ← aspect ratio 1:1, --r-thumbnail
│                  │
│  filename.ext    │  ← --t-body-sm, 1 line, ellipsis
│  12 MB           │  ← --t-body-sm, --text-secondary
└──────────────────┘
```

- **Grid columns**: 2 on mobile (<600px), 4 on desktop (≥600px).
- **Gap**: 8dp.
- **Card background**: `--bg-surface`.
- **Card radius**: `--r-card`.
- **Card padding**: 0 for thumbnail area, 12dp for text area below.
- **Selection**: Tap thumbnail area to preview. Long press to select. When selected, a green check circle overlays the top-right corner of the thumbnail.

### 14.3 View Toggle

- Position: Top bar, right side.
- Two icon buttons side-by-side: `grid` and `list` (Phosphor).
- Active icon: `--accent`. Inactive: `--text-secondary`.
- Wrap in a shared pill-shaped container (`--bg-surface`, `--r-pill`), 36dp tall.

---

## 15. Selection Mode

Triggered by long press (mobile) or right click (desktop) on any file/folder item.

- **Top bar transforms**: Title changes to "[N] selected". Left: close/X icon to exit selection. Right: action icons (share, move, delete, more).
- **Top bar background**: `--bg-surface-raised` to visually distinguish from normal state.
- **Items**: Show a circular checkbox overlay (top-left for list, top-right for grid). Selected items get `--accent-muted` background tint.
- **Bottom bar (mobile)**: Hides during selection mode. Action toolbar appears at bottom instead: icon buttons for share, move, favorite, delete, more.
- **FAB**: Hidden during selection mode.
- **Select all**: Available via top bar action or three-dot menu.

---

## 16. Photo Timeline Screen

### 16.1 Calendar Strip (Month Navigation)

- **Position**: Fixed below the top bar, horizontally scrollable.
- **Height**: 48dp.
- **Background**: `--bg-base`.
- **Items**: Month + year labels (e.g. "Jan 2025"), pill-shaped chips.
  - Inactive: `--bg-surface`, `--text-secondary`.
  - Active/current: `--accent-muted` background, `--accent-text` text.
- **Scroll behavior**: Tapping a month scrolls the grid to that month's photos. Scrolling the grid updates the active month in the strip.
- **Bottom border**: 1px `--border`.

### 16.2 Photo Grid

- **Layout**: Uniform square grid (not masonry).
- **Columns**: 3 on mobile, 5 on desktop.
- **Gap**: 2dp (tight, photos-app density).
- **Thumbnail radius**: 0 (edge-to-edge within the grid for density).
- **Date headers**: Sticky, `--t-label` uppercase, `--text-secondary`, `--bg-base` background, 8dp vertical padding. Format: "MONDAY, JAN 13, 2025".
- **Selection**: Same as files — long press reveals circular checkbox overlay (top-right).

### 16.3 Collections

- **Access**: Tab or filter toggle at the top of the Photos screen, next to "Timeline" label.
- **Tabs**: "Timeline" | "Collections" — styled as text tabs, underlined active state in `--accent`, `--t-body` weight 600.
- **Collection card**: Thumbnail (first image, `--r-card` radius) + collection name below. Grid of 2 columns mobile, 4 desktop.

---

## 17. File Preview

- **Trigger**: Tap on a file in list or grid view.
- **Behavior**: Full-screen overlay on `--bg-base` (opacity 0.95).
- **Top bar**: Transparent, floating. Left: back/close icon. Center: filename. Right: share, download, delete icons.
- **Content area**: Centered. Images scale to fit. Documents show embedded viewer. Unsupported types show file icon + metadata + "Download" button.
- **Swipe**: Left/right to navigate between files in the current folder.
- **Animation**: Fade in 200ms. Image zooms from thumbnail position (if grid view) with 300ms ease.
- **Dismiss**: Back button, close icon, or swipe down.

---

## 18. Settings Screens

### 18.1 Layout

Standard vertical list of setting groups.

- **Screen background**: `--bg-base`.
- **Section header**: `--t-label` uppercase, `--text-secondary`, 32dp top margin, 8dp bottom margin, 16dp left padding.
- **Setting row**: 56dp height, `--bg-surface` background, 16dp horizontal padding.
  - Left: label `--t-body`.
  - Right: value/control (toggle, chevron for sub-page, value text in `--text-secondary`).
- **Grouped rows**: Consecutive rows share a container with `--r-card` radius on first and last item. 1px `--border` dividers between rows (inset).
- **Destructive items** (e.g. "Delete all local data"): Label in `--danger` color.

### 18.2 Settings Content

Wattcloud is serverless from the user's perspective — there is no account, no profile, no admin surface. The settings screen reflects the five things an operator of their own vault actually needs to control:

**Vault**
- Change passphrase → opens a flow that rewraps every provider's vault key without re-encrypting body blobs.
- Export recovery key → reveals the recovery key once (`ByoRecovery.svelte`), paired with a "I have stored this safely" confirmation.
- Auto-lock timeout → dropdown (Never / 5 min / 15 min / 1 hour). Default: 15 min.

**Providers**
- List of enrolled storage providers with status dot (green/amber/red). Tap row → provider context sheet (`ProviderContextSheet.svelte`): rename, reauthorize, move vault, remove.
- "Add provider" row (chevron) → `AddProviderSheet.svelte`.

**Devices**
- List of enrolled devices (pseudonymous labels derived from the device fingerprint). Tap row → revoke device.
- "Link another device" → opens QR/SAS pairing flow (`DeviceEnrollment.svelte` + `QrDisplay.svelte` + `SasConfirmation.svelte`).

**Preferences**
- Default view (Files/Photos) on app launch.
- Reduced motion (toggle — honors OS default if not set).
- Upload concurrency (small/medium/large — cosmetic sugar over the upload queue's parallel-slot count).

**About**
- Version, build SHA, upstream SecureCloud BYO protocol version.
- Link to the GitHub repo and SECURITY.md.
- "Lock vault now" (destructive row) — purges in-memory keys and returns to the unlock screen.

---

## 19. Favorites Screen

Identical layout to the Files screen (switchable grid/list view) but filtered to favorited items only.

- **Empty state**: Centered icon (`star` at 48dp, `--text-disabled`), heading "No favorites yet" (`--t-h2`, `--text-secondary`), subtext "Long press a file or folder and tap the star to add it here." (`--t-body-sm`, `--text-disabled`).
- **Items**: Same file/folder components as Section 14, with a filled star icon badge visible on each item.

---

## 20. Toast Notifications (Snackbar)

- **Position**: Bottom center, 16dp above bottom nav (mobile) or 24dp from bottom (desktop).
- **Size**: Auto-width, max 400dp. Height auto, min 48dp. Pill-shaped (`--r-pill`).
- **Background**: `--bg-surface-raised`.
- **Text**: `--t-body-sm`, `--text-primary`. Single line preferred.
- **Action** (optional): Single text button, `--accent-text` color (e.g. "Undo").
- **Duration**: 3 seconds, then fade out (200ms).
- **Animation**: Slide up + fade in, 200ms ease-out.
- **Stacking**: Only one toast visible at a time. New toasts replace the current one immediately.
- **Z-index**: Above everything including bottom sheets and FAB.

---

## 21. Empty States

Every screen must define an empty state. Consistent pattern:

- **Centering**: Vertically and horizontally centered in the content area.
- **Icon**: Relevant Phosphor icon, 48dp, `--text-disabled`.
- **Heading**: `--t-h2`, `--text-secondary`.
- **Description**: `--t-body-sm`, `--text-disabled`, max 240dp wide, centered.
- **CTA** (optional): Primary pill button below description, 16dp gap.

See §29.5 for the branded variant that wraps the icon in a cloud.

---

## 22. Loading States

- **Skeleton screens**: Preferred over spinners for initial data load. Rounded rectangles (`--r-card`) in `--bg-surface` with a shimmer animation (subtle left-to-right gradient sweep, 1.5s loop).
- **Inline spinner**: 20dp circular spinner in `--accent`, used inside buttons or small areas.
- **Full-screen loader**: Only for initial app launch. Centered cloud motif + 24dp spinner below it (see §29.3.1 for the vault-lock animation that replaces generic loaders during auth).
- **Pull-to-refresh** (mobile): Accent-colored circular spinner at top of scrollable content. 48dp pull threshold. See §29.3.5 for the branded shield-spin variant (`PullToRefresh.svelte`).

---

## 23. Animations & Transitions

Keep animations subtle and functional. No decorative animation.

| Interaction          | Animation                                       | Duration | Easing         |
|----------------------|-------------------------------------------------|----------|----------------|
| Screen transition    | Slide left (push) / slide right (pop)           | 250ms    | ease-out       |
| Bottom sheet open    | Slide up from bottom                            | 300ms    | ease-out       |
| Bottom sheet close   | Slide down                                      | 200ms    | ease-in        |
| FAB speed dial open  | Staggered fade + slide up                       | 200ms    | ease-out       |
| Toast appear         | Slide up + fade in                              | 200ms    | ease-out       |
| Toast disappear      | Fade out                                        | 200ms    | ease-in        |
| Selection checkbox   | Scale from 0 → 1                                | 150ms    | ease-out       |
| Button press         | Scale to 0.97                                   | 100ms    | ease            |
| View toggle (grid↔list)| Crossfade content                             | 200ms    | ease            |
| Skeleton shimmer     | Horizontal gradient sweep                       | 1500ms   | linear (loop)  |

**Reduced motion**: Respect `prefers-reduced-motion`. When active, replace all animations with instant state changes (0ms duration). Always implement this.

---

## 24. Responsive Layout Summary

| Element              | Mobile (< 600px)                     | Desktop (≥ 600px)                     |
|----------------------|--------------------------------------|---------------------------------------|
| Navigation           | Bottom tab bar + hamburger drawer    | Top nav bar + user-menu dropdown      |
| Content width        | Full width, 16dp padding             | Max 960dp centered, 24dp padding      |
| FAB                  | Above bottom nav, right              | Bottom-right, 24dp inset              |
| File grid columns    | 2                                    | 4                                     |
| Photo grid columns   | 3                                    | 5                                     |
| Collection grid cols | 2                                    | 4                                     |
| Bottom sheet width   | Full screen width                    | Max 480dp, centered                   |
| Modals               | Bottom sheet always                  | Bottom sheet always                   |
| Toast width          | Screen width - 32dp                  | Max 400dp, centered                   |
| Buttons in sheets    | Stacked vertically, full width       | Side-by-side, right-aligned           |

---

## 25. Accessibility Requirements

- **Contrast**: All text meets WCAG AA (4.5:1 for body, 3:1 for large text) against its background. The defined palette satisfies this.
- **Focus indicators**: 2px `--accent` outline with 2dp offset on all interactive elements (keyboard navigation, desktop).
- **Tap targets**: Minimum 44×44dp.
- **Screen readers**: All icons must have `aria-label`. Decorative icons use `aria-hidden="true"`.
- **Reduced motion**: Honored (see Section 23).
- **Font scaling**: Layouts must not break at 200% font scale. Use rem/em, never px for text.

---

## 26. Z-Index Scale

| Layer                | Z-index | Element                        |
|----------------------|---------|--------------------------------|
| Base content         | 0       | Screen content                 |
| Sticky headers       | 10      | Date headers, calendar strip   |
| Top bar              | 20      | Navigation bars                |
| Bottom nav           | 20      | Bottom tab bar                 |
| FAB                  | 30      | Floating action button         |
| Overlay              | 40      | Drawer/sheet background dim    |
| Bottom sheet         | 50      | All bottom sheets              |
| Toast                | 60      | Snackbar notifications         |

---

## 27. File Type Icon Mapping

Use colored Phosphor icons or simple SVG icons within a 40dp rounded square (`--r-thumbnail`, `--bg-surface-raised`).

| Type        | Icon (Phosphor)   | Accent tint              |
|-------------|-----------------|--------------------------|
| Folder      | `folder`        | `--accent-muted`         |
| Image       | `image`         | hsl(280, 40%, 25%)       |
| Video       | `video-camera` | hsl(0, 40%, 25%)         |
| PDF         | `file-text`     | hsl(0, 60%, 30%)         |
| Document    | `file-text`     | hsl(210, 40%, 25%)       |
| Spreadsheet | `table`         | hsl(142, 40%, 22%)       |
| Archive     | `file-zip`      | hsl(30, 40%, 25%)        |
| Audio       | `music-note`    | hsl(200, 40%, 25%)       |
| Code        | `file-code`     | hsl(180, 40%, 22%)       |
| Unknown     | `file`          | `--bg-surface-raised`    |

---

## 28. Implementation Notes (Web)

Wattcloud is browser-only. There is no Android or iOS client.

- All tokens live as CSS custom properties in `frontend/src/lib/styles/design-system.css`; reusable component classes in `frontend/src/lib/styles/component-classes.css`.
- Inter loaded via `<link>` from Google Fonts (weights 400, 500, 600, 700). Self-hosted fallback is acceptable; subset to Latin-Extended to keep bundles small.
- Bottom sheets: use a portal/overlay div. Implement drag-to-dismiss with Pointer Events (not Touch Events — Pointer Events cover both mouse and touch).
- Bottom nav: `position: fixed; bottom: 0`. Account for viewport insets on iOS Safari (`env(safe-area-inset-bottom)`) — many users will add Wattcloud to their home screen as a PWA.
- All crypto runs in a Web Worker; the UI thread never blocks. Argon2 progress (§13.6) is the longest foreground wait — budget for it with a dedicated progress component.
- Test matrix: iPhone SE (375dp), iPhone 15 (393dp), Pixel 7 (412dp), iPad Mini (744dp), 1440p desktop. Chrome, Safari, Firefox — latest two major versions each.

---

## 29. Brand Identity — "The Vault"

This section defines the signature patterns that make Wattcloud **instantly recognizable**. Every element here is mandatory — it's what separates the app from generic dark-green cloud apps.

### 29.1 The Vault Motif

The app's recurring visual metaphor is a **plain cloud silhouette** — Phosphor-style, drawn in duotone (tinted body under a crisp outline). It is not a logo, it is a **UI motif** that shows up as chrome across the app wherever the brand reads, and it communicates "your encrypted vault, in the cloud" by itself — without any other icon placed on top of it.

**The Cloud Badge shape**: A Phosphor-style rounded cloud (three bumps across the top and a flat baseline) rendered on a 48×48 viewBox. Drawn in two passes: a tinted body fill in `--accent-muted` at ~45% opacity, then a crisp 2.5px outline in `--accent`. No secondary puff, no inner ornament. Proportions follow the Phosphor `cloud` icon family so it composes cleanly alongside other Phosphor icons in the UI.

**Never place another icon inside the cloud.** The cloud is already the icon. Any screen that needs to say "locked", "encrypted", "sealed", "secured", "connected", "empty", or "done" picks the matching **plain Phosphor icon** (`Lock`, `CheckCircle`, `ShieldCheck`, `Warning`, `Folder`, etc.) and uses it on its own — not layered over the cloud. This applies everywhere: heroes, empty states, toasts, enrollment success screens, auth screens. The cloud badge and the Phosphor icon are peers, never composed.

Where the cloud motif appears (as itself, alone):
- **Splash / favicon / drawer wordmark / mobile top bar wordmark**: Cloud outline as the brand mark.
- **File encryption badge** (`CloudEncBadge`): 14–16dp filled cloud overlayed on encrypted thumbnails — the cloud alone signals "in your vault".
- **App shell chrome** (header app-name, drawer logo): Small outline cloud paired with the wordmark.

Where a plain Phosphor icon replaces the cloud (was previously a composite):
- ByoUnlock / VaultsListScreen / ProviderReauthSheet / RecoveryKeyDisplay hero → `Lock`.
- AddProviderSheet trust-banner inline → `Lock`.
- ByoSetup "Vault created" completion / DeviceEnrollment "Device enrolled" / ByoToastHost `seal` accent → `CheckCircle`.
- ByoToastHost `warn` accent → `Warning`. `danger` accent → `WarningCircle`.

**Implementation**: `CloudBadge.svelte` is a self-contained SVG with two variants — no slot children, no composite interior:
- `outline` — duotone body + outline stroke (default, brand chrome)
- `solid` — saturated fill + stroke (small inline badges)

### 29.2 Signature Color Pairing — Green + Warm Amber

A single green accent is forgettable. The identity becomes distinctive with a **deliberate secondary warm accent** that creates tension and recognition.

**Usage rules — green vs. amber**:

| Green (`--accent`)                        | Amber (`--accent-warm`)                     |
|-------------------------------------------|---------------------------------------------|
| Primary actions (upload, save, confirm)   | Favorites star icon (filled)                |
| Active navigation states                  | Storage quota warning bar                   |
| Encryption/security indicators            | "Starred" or "pinned" item highlight        |
| FAB, primary buttons                      | Collection cover accent borders             |
| Toggle switches (on state)                | Toast undo action text                      |

This green + amber pairing is rare in privacy-adjacent apps (Signal is blue, Element is green-only, Proton is purple, Ente is magenta). The warm amber avoids the cold/clinical feel most security apps default to and makes the UI feel alive.

**Critical rule**: Amber is the **secondary** accent. It should appear on roughly 15–20% of screens. Green remains dominant. Never use amber for primary CTAs or navigation.

### 29.3 Signature Micro-Interactions

These are the moments users remember and associate with Wattcloud.

#### 29.3.1 The Vault Lock — App Launch & Unlock

When the app opens or the user completes the unlock flow (`ByoUnlock.svelte`):
- A cloud outline draws itself on screen (SVG path animation), stroke in `--accent`, 600ms, ease-in-out. The path uses `pathLength="100"` so the draw-on animates `stroke-dashoffset` from 100 to 0 regardless of viewBox size.
- At ~50% draw progress the cloud's duotone body fades in beneath the outline (the "sealing" moment) — no padlock or bolt ornament is composed inside the cloud, per §29.1.
- Once fully drawn the cloud holds briefly (~300ms), then fades out (200ms) as the main UI fades in beneath it.
- **Total duration**: ~1100ms. The draw-and-fill itself is the unlock ritual.
- On subsequent loads within the same session (e.g. tab refocus while keys are still in-memory), skip this animation entirely.

Implemented in `VaultLockAnimation.svelte`.

#### 29.3.2 The Seal — Upload & Encryption Completion

When a file finishes uploading and is confirmed encrypted:
1. The upload progress bar (thin, accent-colored, at the top of the screen) reaches 100%.
2. The bar morphs into a small cloud (24dp) centered where the bar ended (right side), with a scale-in animation (0→1, 200ms, ease-out).
3. Inside the cloud, a checkmark draws itself (path animation, 200ms).
4. The cloud holds for 800ms, then fades out.
5. A toast appears: "File encrypted and saved".

This replaces a generic "upload complete" toast with a **branded completion ritual** the user learns to recognize.

#### 29.3.3 Favorite Toggle — Star Burst

When a user taps the star to favorite an item:
- The star icon scales up to 1.3× (100ms) and fills with `--accent-warm` simultaneously.
- At peak scale, 4–6 tiny dots (3dp circles, `--accent-warm`, random spread within 20dp radius) appear and fade outward over 300ms (a subtle "burst").
- Star scales back to 1.0× (100ms).
- **Unfavorite**: Star simply scales to 0.9×, color fades to `--text-secondary`, scales back. No burst. The asymmetry makes favoriting feel rewarding and unfavoriting feel lightweight.

#### 29.3.4 Selection Ripple

When entering selection mode via long press:
- A subtle ring expands outward from the press point (like a sonar ping), `--accent` at 15% opacity, expanding to 80dp diameter over 300ms, then fading.
- This signals "you've activated something" and distinguishes long press from regular tap visually.

#### 29.3.5 Pull-to-Refresh — Cloud Spin

Replace the generic circular spinner for pull-to-refresh:
- As the user pulls down, the cloud outline (24dp) is drawn progressively (pull distance maps to path draw percentage, 0–100%, via `stroke-dashoffset` on a `pathLength="100"` path).
- On release (if threshold met), the completed cloud rotates 360° once (400ms, ease-in-out) while the refresh happens.
- On completion, the cloud scales down and fades (200ms).

Implemented in `PullToRefresh.svelte`.

### 29.4 Encryption Status Strip

A persistent, ultra-subtle visual element that reinforces the zero-knowledge posture without being intrusive.

- **Position**: Top of every screen, directly below the top bar. Height: 2dp.
- **Default state** (all providers synced and ciphertext up-to-date): A thin solid line in `--accent` at 30% opacity. Barely visible — but it's always there, like a security seal.
- **Syncing/encrypting state**: The 2dp strip becomes an animated gradient that slides left-to-right (the same accent green, pulsing between 20% and 60% opacity, 2s loop). This is a subtle "heartbeat" that tells the user encryption is actively working.
- **Error state**: Strip turns `--danger` at 60% opacity, static. A tap on it opens a bottom sheet with error details.
- **Offline state** (any enrolled provider unreachable): Strip becomes `--text-disabled` at 30% opacity, dashed (alternating 8dp dash, 4dp gap). `OfflineBanner.svelte` renders the per-provider detail below when expanded.

This strip is the app's **signature ambient element** — users will subconsciously learn to glance at it. No other cloud app does this.

### 29.5 Empty States

Empty states use a **single plain Phosphor icon** sized 56dp in `light` weight at `--text-disabled` — no cloud wrapper. The cloud motif shows up elsewhere (splash, unlock, file-encryption badge, upload seal, toasts) often enough that every empty state doesn't need to re-brand; a meaningful, literal icon communicates the screen's state more clearly than a framed one.

| Screen    | Empty State Icon                                      | Heading                   | Subtext                                                           |
|-----------|-------------------------------------------------------|---------------------------|-------------------------------------------------------------------|
| Files     | `FolderSimple` (light, 56dp, `--text-disabled`)       | "Your vault is empty"     | "Upload files to start."                                          |
| Photos    | `Image` (light, 56dp, `--text-disabled`)              | "No memories yet"         | "Photos you upload will appear here."                             |
| Favorites | `Star` (light, 56dp, `--accent-warm` @ 55% opacity)   | "Nothing starred yet"     | "Star files and folders for quick access."                        |
| Providers | `Plugs` (light, 56dp, `--text-disabled`)              | "No storage connected"    | "Connect Google Drive, Dropbox, OneDrive, Box, pCloud, WebDAV, SFTP, or S3 to get started." |
| Trash     | `Trash` (light, 56dp, `--text-disabled`)              | "Nothing in trash"        | "Items you delete will appear here."                              |
| Shares    | `Link` (light, 56dp, `--text-disabled`)               | "No active shares"        | "Share links you create will appear here."                        |

Do not wrap any of these icons in a cloud. See §29.1 — the motif lives in the chrome (header, splash, file badges, unlock hero, toasts) so empty states can stay clean.

### 29.6 Signature Sound (Optional)

Consider a subtle audio cue to reinforce the vault metaphor:
- **Lock/unlock**: A soft metallic "click" (< 100ms) when the vault unlocks. Think a high-quality mechanical lock, not a digital beep.
- **Upload sealed**: A quiet, low "thunk" when encryption completes (the cloud seal moment).
- **Default**: Sounds off. User must opt-in via Settings → Preferences. Never auto-play sounds — autoplay is hostile in a browser tab.

This is optional but the apps people remember often have audio identity.

---

## 30. Identity Checklist — "Could This Be Any Other App?"

Before shipping any screen, apply this test. If the answer to any question is "yes, this could be any dark cloud app", the screen needs more identity work.

| Check                                                        | Pass Criteria                                            |
|--------------------------------------------------------------|----------------------------------------------------------|
| Is the cloud motif visible somewhere on this screen?         | At minimum: encryption strip at top, or cloud badge on items |
| Does the screen use both green AND amber where appropriate?  | Favorites show amber stars; storage warnings use amber    |
| Are empty states branded (cloud wrapper)?                    | No plain floating icons                                  |
| Does the completion of an action feel unique?                | Upload seal animation, favorite burst, selection ripple   |
| Would a screenshot be attributable to Wattcloud specifically?| Color pairing + cloud + strip = recognizable              |

---

## 31. Glassmorphism Layer

This section defines the frosted glass treatment applied selectively to floating and chrome elements. It builds on top of the existing token system — all opaque tokens remain as fallbacks.

### 31.1 Glass Surface Tokens

| Token                    | Value                                                                 | Usage                                               |
|--------------------------|-----------------------------------------------------------------------|-----------------------------------------------------|
| `--glass-bg`             | `rgba(28, 28, 28, 0.65)`                                              | Primary glass surface fill                          |
| `--glass-bg-heavy`       | `rgba(28, 28, 28, 0.80)`                                              | Bottom sheets, overlays needing more opacity        |
| `--glass-blur`           | `blur(20px)`                                                          | Standard backdrop blur radius                       |
| `--glass-blur-light`     | `blur(12px)`                                                          | Lighter blur for smaller elements (toasts)          |
| `--glass-border`         | `1px solid rgba(255, 255, 255, 0.08)`                                 | Subtle luminous edge on all glass surfaces          |
| `--glass-border-accent`  | `1px solid rgba(46, 184, 96, 0.25)`                                   | Accent-tinted edge for active/focused glass elements |
| `--glass-highlight`      | `linear-gradient(135deg, rgba(255,255,255,0.06) 0%, transparent 50%)` | Top-left inner highlight for depth illusion         |
| `--glass-shadow`         | `0 8px 32px rgba(0, 0, 0, 0.4)`                                       | Soft shadow beneath floating glass elements         |

### 31.2 Fallback Rule

Not all browsers/GPUs support `backdrop-filter` performantly. Every glass element must define both layers:

```css
/* Applied together */
background: var(--glass-bg);
backdrop-filter: var(--glass-blur);
-webkit-backdrop-filter: var(--glass-blur);
border: var(--glass-border);

/* Fallback when backdrop-filter unsupported or reduced-motion active */
@supports not (backdrop-filter: blur(1px)) {
  background: var(--bg-surface-raised);  /* opaque fallback from Section 2 */
}
```

When `prefers-reduced-transparency: reduce` is set, collapse to the opaque fallback regardless of feature support.

### 31.3 Which Elements Get Glass — Definitive List

#### Floating glass (layout + visual change)

| Element                  | Layout Change                                                                                                    | Glass Treatment                                                                |
|--------------------------|------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------|
| **Bottom nav bar**       | No longer edge-to-edge. Inset 12dp from left, right, and bottom. Pill-shaped (`--r-pill`). Hovers above content. | `--glass-bg`, `--glass-blur`, `--glass-border`, `--glass-shadow`.              |
| **Top bar**              | Remains full-width and fixed, but becomes transparent. Content scrolls behind it.                                | `--glass-bg`, `--glass-blur`, `--glass-border` (bottom edge only). No shadow.  |
| **Toasts**               | No layout change (already floating). Increase bottom margin to 24dp above floating nav (mobile).                 | `--glass-bg`, `--glass-blur-light`, `--glass-border`.                          |
| **FAB**                  | No layout change. Position: 16dp above the floating nav pill (mobile), 24dp from bottom (desktop).               | Remains opaque `--accent`. No glass on FAB itself — it must stay high-contrast.|
| **FAB speed-dial items** | No layout change.                                                                                                | `--glass-bg`, `--glass-blur-light`, `--glass-border`.                          |

#### Anchored glass (visual change only, no layout shift)

| Element                      | Glass Treatment                                                                                                                    |
|------------------------------|------------------------------------------------------------------------------------------------------------------------------------|
| **Bottom sheets**            | `--glass-bg-heavy`, `--glass-blur`, `--glass-border` on top edge. Stays anchored to bottom.                                        |
| **Calendar strip**           | `--glass-bg`, `--glass-blur`. Content scrolls behind it. Bottom border becomes `--glass-border`.                                   |
| **Selection toolbar**        | `--glass-bg`, `--glass-blur`, `--glass-border`. Stays edge-anchored at top (mobile) or top bar area (desktop).                     |
| **Dropdown menus**           | `--glass-bg`, `--glass-blur`, `--glass-border`, `--glass-shadow`.                                                                  |
| **Swipe drawer overlay**     | Drawer panel itself: `--glass-bg-heavy`, `--glass-blur`. Background dim stays `rgba(0,0,0,0.5)`.                                   |
| **Encryption status strip**  | Unchanged (2dp height is too thin for blur). Stays as defined in Section 29.4. Gains extra visual pop floating above glass top bar. |

#### Stays opaque (no glass)

| Element                          | Reason                                     |
|---------------------------------|-------------------------------------------|
| File/folder list items           | Readability, scroll performance            |
| File/folder grid cards           | Readability, scroll performance            |
| Photo grid                       | Performance with many thumbnails           |
| Settings rows                    | Readability of labels and controls         |
| Input fields, checkboxes, toggles| Interaction clarity                        |
| Buttons (all variants)           | Must stay high-contrast for tap clarity    |
| Empty state containers           | Already on `--bg-base`, nothing behind them |

### 31.4 Floating Bottom Nav — Detailed Spec

This is the most visible layout change. Precise spec:

```
┌──────────────────────────────────────────────┐
│                                              │
│              [screen content]                │
│                                              │
│                                              │
│                                              │
│   ┌──────────────────────────────────────┐   │
│   │  Files    Photos    Favs             │   │  ← floating pill, glass bg
│   └──────────────────────────────────────┘   │
│                                          [+] │  ← FAB sits above nav pill
└──────────────────────────────────────────────┘
```

- Margins: 12dp from left, right, and bottom (above safe area inset).
- Height: 56dp (unchanged).
- Shape: `--r-pill` (fully rounded ends).
- Background: `--glass-bg` + `--glass-blur`.
- Border: `--glass-border` (full perimeter).
- Shadow: `--glass-shadow`.
- Inner highlight: Apply `--glass-highlight` as a pseudo-element for subtle top-left light reflection.
- Content: Same 3 tabs as Section 9.1. Icons and labels centered within the pill.
- Safe area: The 12dp bottom margin is measured FROM the safe area inset (`env(safe-area-inset-bottom)`), not from the screen edge. On devices without a home indicator, 12dp from screen bottom.

### 31.5 Glass Top Bar — Detailed Spec

- Background: `--glass-bg` + `--glass-blur`. Replaces the previous opaque `--bg-surface`.
- Border: `--glass-border` on bottom edge only.
- No shadow.
- Content scrolls behind it: The top bar's glass area reveals a frosted version of whatever is scrolling beneath. This is the key visual payoff — it looks premium only if content actually moves behind it.
- Title and icons: No change to colors or sizing. `--text-primary` on glass is readable at the defined 65% opacity.
- Desktop top nav: Same treatment. Full-width glass bar, content scrolls behind.

### 31.6 Inner Highlight Technique

To make glass surfaces feel three-dimensional rather than flat, apply a subtle diagonal gradient highlight:

```css
.glass-element::before {
  content: '';
  position: absolute;
  inset: 0;
  border-radius: inherit;
  background: var(--glass-highlight);
  pointer-events: none;
}
```

Apply this to: floating bottom nav, bottom sheets, dropdown menus, drawer panel. Do NOT apply to: top bar (too subtle to notice at full width), toasts (too small).

### 31.7 Animation Adjustments for Glass

- Bottom sheet open: Unchanged timing (300ms ease-out slide up). The glass blur is visible during the slide — content behind the sheet frosts as it rises. This looks correct without extra work.
- Floating nav on scroll: When scrolling down rapidly, optionally hide the floating nav (translate Y + 80dp, 200ms ease-in). Show on scroll up (200ms ease-out). This is optional — if implemented, the FAB stays visible.
- Drawer open: Unchanged. The glass drawer slides over the dimmed background — blur applies to the dim overlay content.

### 31.8 Performance Budget

Glass effects are GPU-intensive. Set these limits:

- Maximum simultaneous blurred elements on screen: 3 (typically: top bar + bottom nav + one bottom sheet OR one dropdown).
- Photo timeline scroll: If frame rate drops below 50fps during scroll with glass top bar + glass calendar strip, disable blur on the calendar strip (fall back to opaque `--bg-surface`).
- `backdrop-filter` is hardware-accelerated in all current Chrome / Safari / Firefox versions. On older Firefox (< 103) it falls back to the opaque style via the `@supports` guard in 31.2 — no action required.
- Detect `matchMedia('(update: slow)')` and collapse to opaque fallbacks for low-end devices that advertise themselves as such.
