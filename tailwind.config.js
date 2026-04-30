/**
 * Tailwind config for CaddyUI's build-time CSS compile.
 *
 * History: a v2.12.39 attempt at this produced a 3.76 MB tailwind.css
 * because `extend` keeps Tailwind's default 22-color palette in addition
 * to the custom brand/ink colors, and Tailwind's JIT auto-generates
 * variants across the entire palette × shade × opacity-modifier matrix.
 *
 * Fix in v2.12.41: replace the entire `theme.colors` (no `extend`) with
 * a hand-picked subset based on a grep audit of web/templates/. Drops
 * 11 unused palettes (zinc, neutral, stone, lime, cyan, fuchsia +
 * a few more) and short-circuits the variant explosion.
 *
 * Usage counts from `grep -aohE '<color>-[0-9]+' web/templates/`:
 *   gray   1622×    blue   205×    purple   65×    yellow   6×
 *   red     282×    slate  167×    emerald  33×    orange   6×
 *   amber   227×    green  147×    sky      20×    + others <5×
 *
 * @type {import('tailwindcss').Config}
 */
const colors = require('tailwindcss/colors')

module.exports = {
  darkMode: 'class',
  content: [
    // Templates only. v2.12.39 had a bug where scanning internal/server/*.go
    // pulled in classes from the AI-prompt knowledge dump (English prose
    // describing the UI, not actual DOM classes). Don't scan Go files.
    './web/templates/**/*.html',
  ],
  theme: {
    // OVERRIDE colors entirely — no `extend`. This is the critical line
    // that prevents the 3.76 MB blowup. Tailwind only generates utility
    // classes for the palettes listed here.
    colors: {
      transparent: 'transparent',
      current: 'currentColor',
      white: '#fff',
      black: '#000',
      // Heavy usage (>20× in templates)
      gray:    colors.gray,
      red:     colors.red,
      amber:   colors.amber,
      blue:    colors.blue,
      slate:   colors.slate,
      green:   colors.green,
      purple:  colors.purple,
      emerald: colors.emerald,
      sky:     colors.sky,
      // Light usage (1–20× in templates) — kept because they appear
      // somewhere in the UI; if any of these go unused after a future
      // refactor, drop them to shrink output further.
      yellow:  colors.yellow,
      orange:  colors.orange,
      teal:    colors.teal,
      rose:    colors.rose,
      pink:    colors.pink,
      violet:  colors.violet,
      indigo:  colors.indigo,
      // Custom brand palette (mirrors what was in the previous inline
      // tailwind.config in layout.html). The Carbon Orange theme then
      // overrides these via attribute-selector CSS in app.css.
      brand: {
        50:  '#eff6ff',
        100: '#dbeafe',
        200: '#bfdbfe',
        300: '#93c5fd',
        500: '#3b82f6',
        600: '#2563eb',
        700: '#1d4ed8',
      },
      ink: {
        50:  '#f8fafc',
        100: '#f1f5f9',
        200: '#e2e8f0',
        300: '#cbd5e1',
        400: '#94a3b8',
        500: '#64748b',
        600: '#475569',
        700: '#334155',
        800: '#1e293b',
        900: '#0f172a',
      },
    },
    extend: {
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'BlinkMacSystemFont', '"Segoe UI"', 'Roboto', 'sans-serif'],
      },
      boxShadow: {
        card: '0 1px 2px 0 rgb(15 23 42 / 0.04)',
        'card-hover': '0 4px 12px -2px rgb(15 23 42 / 0.08), 0 2px 4px -1px rgb(15 23 42 / 0.04)',
      },
    },
  },
  // No safelist. The v2.12.39 attempt with safelist patterns blew up
  // due to opacity-modifier auto-expansion. Templates have all the real
  // classes; the content scanner finds them. If a JS-assembled class
  // shows up missing in production, add the LITERAL class to a template
  // comment so the scanner sees it.
}
