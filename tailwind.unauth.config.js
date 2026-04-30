/**
 * Tiny Tailwind config for unauthenticated pages only — login, setup,
 * reset_password, forgot_password, accept_invite. Compiled output
 * (web/static/auth.css) replaces the cdn.tailwindcss.com runtime
 * for those pages, dropping ~124 KB of JS that gets parsed on every
 * cold load. Mobile (with 4× CPU throttling) saves the most.
 *
 * Authenticated pages still use the CDN — they have a much wider
 * class surface (300+ unique classes) where the JIT runtime makes
 * sense.
 */
module.exports = {
  darkMode: 'class',
  content: [
    './web/templates/login.html',
    './web/templates/setup.html',
    './web/templates/reset_password.html',
    './web/templates/forgot_password.html',
    './web/templates/accept_invite.html',
    // Layout pieces shown on unauth pages: the <head> + the centered
    // content card. The conditional sidebar/topbar are gated behind
    // {{if .User}} so they don't render on these pages.
    './web/templates/layout.html',
  ],
  theme: {
    extend: {
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
    },
  },
}
