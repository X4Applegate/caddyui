/**
 * Tailwind CSS config for CaddyUI's build-time CSS compilation.
 *
 * Replaces the JIT runtime via cdn.tailwindcss.com that v2.11.x → v2.12.38
 * shipped with. The CLI scans the files listed in `content` for class names
 * and emits only the CSS for the classes that actually appear, dropping
 * the ~250 KB JIT runtime + recompile-on-every-page-load cost.
 *
 * @type {import('tailwindcss').Config}
 */
module.exports = {
  darkMode: 'class',
  content: [
    // Every Go template renders directly to HTML — class names live here.
    './web/templates/**/*.html',
    // The Go server has class names baked into a few error pages, the AI
    // assistant's system prompt knowledge dump, and a couple of HTMX
    // fragments. Scanning catches them so they don't get tree-shaken.
    './internal/server/*.go',
    // The static service worker + manifest reference no Tailwind classes
    // today, but include for future-proofing.
    './web/static/sw.js',
  ],
  theme: {
    extend: {
      // v2.11.x palette (mirrors the previous inline tailwind.config in
      // layout.html). The Carbon Orange theme is layered on top via raw
      // attribute-selector overrides in the layout.html <style> block —
      // those use the same brand-* class names so swapping themes still
      // works.
      colors: {
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
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'BlinkMacSystemFont', '"Segoe UI"', 'Roboto', 'sans-serif'],
      },
      boxShadow: {
        // v2.12.25: softer card shadow — single hairline + barely-there
        // 1px lift. Pairs with a 1px ink-200 border to hold the edge.
        card: '0 1px 2px 0 rgb(15 23 42 / 0.04)',
        'card-hover': '0 4px 12px -2px rgb(15 23 42 / 0.08), 0 2px 4px -1px rgb(15 23 42 / 0.04)',
      },
    },
  },
  // Safelist: classes that the CLI's static scanner can't see because they
  // get assembled at runtime. Most CaddyUI JS uses static-string class
  // branches (e.g. `u.healthy ? 'bg-green-500' : 'bg-red-500'`) which DO
  // get scanned, so this list is intentionally short — only the cases
  // where class names get genuinely concatenated from variables.
  safelist: [
    // Brand pill on the AI model name (assembled in renderToolCallCard JS)
    'bg-brand-100',
    'text-brand-700',
    'dark:bg-brand-900/40',
    'dark:text-brand-300',
    // Update badge variants
    'bg-amber-100',
    'text-amber-700',
    // Color tag pill — brand color is set per-host from a string variable
    {
      pattern: /(bg|text|border)-(red|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink|rose|slate|gray|zinc|neutral|stone)-(50|100|200|300|400|500|600|700|800|900)/,
      variants: ['hover', 'dark', 'focus'],
    },
  ],
}
