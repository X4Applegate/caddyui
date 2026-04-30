// CaddyUI service worker — v2.12.39 minimal rewrite.
//
// History: the v2.11.15 → v2.12.38 SW did aggressive cache-first for
// /static/* and network-first-with-cache-fallback for HTML, with a
// hardcoded cache name "caddyui-v1" that NEVER bumped between releases.
// After every docker pull to a new CaddyUI build, users kept getting
// the OLD /static/app.css from cache because the SW never invalidated
// it — visible as broken layout, stale theme overrides, or "feels
// slow" because the browser was serving stale cache instead of
// re-fetching the actually-fast HTTP-cached responses underneath.
//
// This rewrite:
//
// 1. Bumps the cache name to include the (currently-shipping)
//    CaddyUI version. Activate purges every cache that isn't this
//    one — cleans up the stale v1 cache from older releases on first
//    visit after upgrade.
//
// 2. Removes /static/* SW caching entirely. The Go server already
//    sets Cache-Control: public, max-age=86400 on /static/* (v2.12.38)
//    so the browser's HTTP cache handles repeat visits — no SW layer
//    needed, no staleness to manage, upgrades work correctly because
//    the HTTP cache respects them while the SW cache wasn't.
//
// 3. Removes HTML page caching. CaddyUI is an online admin tool; an
//    offline-capable cache of /proxy-hosts is more confusing than
//    useful (shows yesterday's hosts list with no "stale" indicator).
//
// 4. Keeps the registration + an empty fetch handler so the PWA
//    install prompt still triggers on Chrome / Edge / Safari iOS.
//    The empty handler is required — Chrome won't show "Install app"
//    on a page whose SW has no fetch listener.

const CACHE_VERSION = 'caddyui-v2.12.39';

self.addEventListener('install', () => {
  // Take over immediately so the new SW replaces the old one without
  // waiting for every tab to close.
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE_VERSION).map(k => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

// Empty fetch handler — every request goes straight to the network and
// is then cached by the browser's normal HTTP cache (controlled by the
// Cache-Control header the Go server sends). No SW interception, no
// stale-cache footguns. The handler exists only to satisfy the PWA
// installability requirement "must have a fetch event listener."
self.addEventListener('fetch', () => {
  // intentionally empty
});
