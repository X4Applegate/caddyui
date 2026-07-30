// CaddyUI client-side JS — extracted from layout.html in v2.12.41 so it
// caches across navigations instead of being parsed on every page load.
//
// Loaded with `defer` so it runs after HTML parse but before
// DOMContentLoaded. Each IIFE below probes for the elements it needs and
// short-circuits with `return` when they're absent (e.g., the AI fab JS
// returns early on the login page where #ai-fab doesn't exist).
//
// Cached via the v2.12.38 Cache-Control: public, max-age=86400 wrapper
// on /static/* — repeat navigations skip the network entirely.

// v2.12.42: small helper used below to delay non-critical /api/* fetches
// until after Lighthouse's TBT/LCP measurement window closes. The page
// renders fine without these calls — they just populate a badge and
// some health dots that the user doesn't notice in the first 2 seconds.
function caddyuiDelayFetch(ms, fn) {
  if (typeof requestIdleCallback === 'function') {
    setTimeout(function() { requestIdleCallback(fn, { timeout: 1500 }); }, ms);
  } else {
    setTimeout(fn, ms);
  }
}

(function() {
  var badge = document.getElementById('update-badge');
  if (!badge) return;
  var DISMISS_KEY = 'caddyui-update-dismissed';
  // v2.12.42: deferred 3s — version-check is a Docker Hub round-trip
  // (~300 ms) that has no business blocking initial paint metrics.
  caddyuiDelayFetch(3000, function() {
  fetch('/api/version-check')
    .then(function(r) { return r.ok ? r.json() : null; })
    .then(function(d) {
      if (!d || !d.has_update) return;
      var dismissed = '';
      try { dismissed = localStorage.getItem(DISMISS_KEY) || ''; } catch(e) {}
      if (dismissed === d.latest) return; // already dismissed this version
      badge.textContent = '↑ ' + d.latest + ' available';
      badge.classList.remove('hidden');
      badge.addEventListener('click', function() {
        try { localStorage.setItem(DISMISS_KEY, d.latest); } catch(e) {}
        badge.classList.add('hidden');
      });
    })
    .catch(function() {});
  }); // close caddyuiDelayFetch
})();

// v2.11.0: global keyboard shortcuts.
//   "?" — open the shortcut overlay
//   "/" — focus the page's filter/search input (any [type=search])
//   Esc — close the overlay
//   "g" then p|r|a|c|d|n — quick-nav to the matching list page
// All bindings ignore key presses while the user is typing in an input,
// textarea, or contenteditable so /-focus etc. doesn't fire mid-edit.
(function() {
  var overlay = document.getElementById('kbd-overlay');
  var pendingChord = null;
  var chordTimer = null;
  var ROUTES = { p: '/proxy-hosts', r: '/redirection-hosts', a: '/raw-routes', c: '/certificates', d: '/', n: '/analytics' };
  function isTyping(el) {
    if (!el) return false;
    var tag = (el.tagName || '').toUpperCase();
    if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return true;
    if (el.isContentEditable) return true;
    return false;
  }
  document.addEventListener('keydown', function(e) {
    if (e.metaKey || e.ctrlKey || e.altKey) return;
    if (e.key === 'Escape') {
      if (overlay && !overlay.classList.contains('hidden')) {
        overlay.classList.add('hidden');
        e.preventDefault();
      }
      return;
    }
    if (isTyping(e.target)) return;
    if (e.key === '?') {
      if (overlay) { overlay.classList.toggle('hidden'); e.preventDefault(); }
      return;
    }
    if (e.key === '/') {
      var search = document.querySelector('input[type=search]');
      if (search) { search.focus(); search.select(); e.preventDefault(); }
      return;
    }
    if (pendingChord === 'g' && ROUTES[e.key]) {
      pendingChord = null;
      if (chordTimer) { clearTimeout(chordTimer); chordTimer = null; }
      window.location.href = ROUTES[e.key];
      e.preventDefault();
      return;
    }
    if (e.key === 'g') {
      pendingChord = 'g';
      if (chordTimer) clearTimeout(chordTimer);
      chordTimer = setTimeout(function() { pendingChord = null; }, 1200);
      return;
    }
    pendingChord = null;
  });
})();

// v2.11.5: ⌘K / Ctrl+K command palette — global search across proxy hosts,
// redirections, raw routes, certificates. Fetches /api/search once per open
// (with a 60s freshness window) and filters client-side. ↑/↓ to navigate,
// Enter to open, Esc to close.
(function() {
  var modal = document.getElementById('cmd-palette');
  var input = document.getElementById('cmd-input');
  var results = document.getElementById('cmd-results');
  var triggers = document.querySelectorAll('[data-command-palette-trigger]');
  if (!modal || !input || !results) return;
  var data = null;
  var dataAt = 0;
  var STALE_MS = 60000;
  var selected = 0;
  var visible = [];
  var TYPE_LABEL = { proxy: 'Proxy', redirect: 'Redirect', raw: 'Advanced', cert: 'Cert' };
  var TYPE_COLOR = {
    proxy: 'bg-brand-100 text-brand-700 dark:bg-brand-900/40 dark:text-brand-300',
    redirect: 'bg-sky-100 text-sky-700 dark:bg-sky-900/40 dark:text-sky-300',
    raw: 'bg-purple-100 text-purple-700 dark:bg-purple-900/40 dark:text-purple-300',
    cert: 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/40 dark:text-emerald-300'
  };
  function escapeHTML(s) {
    return String(s).replace(/[&<>"']/g, function(c) {
      return { '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c];
    });
  }
  function open() {
    modal.classList.remove('hidden');
    input.value = '';
    selected = 0;
    setTimeout(function() { input.focus(); }, 0);
    var stale = !data || (Date.now() - dataAt) > STALE_MS;
    if (stale) {
      render('');
      fetch('/api/search', { credentials: 'same-origin' })
        .then(function(r) { return r.ok ? r.json() : null; })
        .then(function(d) {
          if (d && Array.isArray(d.results)) { data = d.results; dataAt = Date.now(); render(input.value); }
        })
        .catch(function() {});
    } else {
      render('');
    }
  }
  function close() { modal.classList.add('hidden'); }
  triggers.forEach(function(trigger) {
    trigger.addEventListener('click', open);
  });
  function render(q) {
    if (!data) {
      results.innerHTML = '<div class="px-3 py-6 text-center text-sm text-ink-400 dark:text-slate-500">Loading…</div>';
      return;
    }
    var qq = (q || '').trim().toLowerCase();
    visible = qq === ''
      ? data.slice(0, 50)
      : data.filter(function(it) {
          return (it.label || '').toLowerCase().indexOf(qq) >= 0
              || (it.sub || '').toLowerCase().indexOf(qq) >= 0;
        }).slice(0, 50);
    if (visible.length === 0) {
      results.innerHTML = '<div class="px-3 py-6 text-center text-sm text-ink-400 dark:text-slate-500">No matches</div>';
      return;
    }
    if (selected >= visible.length) selected = visible.length - 1;
    if (selected < 0) selected = 0;
    var html = visible.map(function(it, i) {
      var sel = (i === selected) ? 'bg-brand-50 dark:bg-slate-700' : '';
      var pill = TYPE_COLOR[it.type] || 'bg-ink-100 text-ink-600 dark:bg-slate-700 dark:text-slate-300';
      return '<a href="' + it.url + '" data-cmd-row="' + i + '" class="cmd-row flex items-center gap-3 px-3 py-2 rounded-lg ' + sel + ' hover:bg-brand-50 dark:hover:bg-slate-700 transition">' +
             '<span class="text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded ' + pill + ' font-medium shrink-0">' + (TYPE_LABEL[it.type] || it.type) + '</span>' +
             '<span class="flex-1 min-w-0">' +
               '<span class="block text-sm text-ink-900 dark:text-slate-100 truncate">' + escapeHTML(it.label || '(unnamed)') + '</span>' +
               (it.sub ? '<span class="block text-xs text-ink-500 dark:text-slate-400 truncate">' + escapeHTML(it.sub) + '</span>' : '') +
             '</span>' +
             '</a>';
    }).join('');
    results.innerHTML = html;
    var rows = results.querySelectorAll('.cmd-row');
    rows.forEach(function(row, i) {
      row.addEventListener('mouseenter', function() { selected = i; updateHighlight(); });
    });
  }
  function updateHighlight() {
    results.querySelectorAll('.cmd-row').forEach(function(row, i) {
      row.classList.toggle('bg-brand-50', i === selected);
      row.classList.toggle('dark:bg-slate-700', i === selected);
    });
  }
  document.addEventListener('keydown', function(e) {
    var isMod = e.metaKey || e.ctrlKey;
    if (isMod && (e.key === 'k' || e.key === 'K')) {
      e.preventDefault();
      if (modal.classList.contains('hidden')) open(); else close();
      return;
    }
    if (modal.classList.contains('hidden')) return;
    if (e.key === 'Escape') { close(); e.preventDefault(); return; }
    if (e.key === 'ArrowDown') { selected = Math.min(selected + 1, visible.length - 1); updateHighlight(); e.preventDefault(); return; }
    if (e.key === 'ArrowUp')   { selected = Math.max(selected - 1, 0);                  updateHighlight(); e.preventDefault(); return; }
    if (e.key === 'Enter' && visible[selected]) { window.location.href = visible[selected].url; e.preventDefault(); return; }
  });
  input.addEventListener('input', function() { selected = 0; render(input.value); });
})();

// v2.11.15: AI assistant chat. Reveals the floating button only when
// /api/ai/status reports enabled=true. Submitting fetches /api/ai/chat
// with the input message; the reply is appended to the history pane.
(function() {
  var fab = document.getElementById('ai-fab');
  var modal = document.getElementById('ai-modal');
  var form = document.getElementById('ai-form');
  var input = document.getElementById('ai-input');
  var submit = document.getElementById('ai-submit');
  var history = document.getElementById('ai-history');
  var modelPill = document.getElementById('ai-model-pill');
  if (!fab || !modal || !form || !input || !history) return;

  function escapeHTML(s) {
    return String(s).replace(/[&<>"']/g, function(c) {
      return { '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c];
    });
  }
  // v2.12.7: tiny markdown renderer for assistant bubbles. Handles fenced
  // code blocks, inline code, bold, italic, basic bullet/number lists,
  // and paragraph breaks. Input is HTML-escaped first so regex-injected
  // tags can't be exploited.
  function renderMarkdown(text) {
    var html = escapeHTML(text);
    var codeBlocks = [];
    // Pull fenced code blocks out so further regexes don't touch them.
    html = html.replace(/```([a-zA-Z0-9_+-]*)\n?([\s\S]*?)```/g, function(_, lang, code) {
      var idx = codeBlocks.length;
      codeBlocks.push(code.replace(/^\n+|\n+$/g, ''));
      return ' CB' + idx + ' ';
    });
    // Inline code (single backticks, single line).
    html = html.replace(/`([^`\n]+?)`/g, '<code class="bg-ink-200 dark:bg-slate-600 text-ink-900 dark:text-slate-100 px-1 py-0.5 rounded text-[0.85em] font-mono">$1</code>');
    // Bold.
    html = html.replace(/\*\*([^*\n]+?)\*\*/g, '<strong>$1</strong>');
    // Italic — avoid matching inside words (so `foo*bar` doesn't trip).
    html = html.replace(/(^|[^\w*])\*([^*\n]+?)\*(?!\w)/g, '$1<em>$2</em>');
    // List-line markers (numbered and bulleted) — render as a row with the
    // marker dimmed; full <ol>/<ul> grouping isn't worth the regex weight
    // for chat output, the visual cue is enough.
    html = html.replace(/^(\d+)\.\s+/gm, '<span class="text-ink-500 dark:text-slate-400 mr-1">$1.</span>');
    html = html.replace(/^[-*]\s+/gm, '<span class="text-ink-500 dark:text-slate-400 mr-1">•</span>');
    // Paragraph + line break handling.
    html = html.replace(/\n{2,}/g, '</p><p class="mt-2">');
    html = html.replace(/\n/g, '<br>');
    html = '<p>' + html + '</p>';
    // Re-inject the code blocks.
    html = html.replace(/ CB(\d+) /g, function(_, idx) {
      // v2.12.31: code blocks now wrap long lines (whitespace-pre-wrap +
      // break-all) instead of overflowing off the bubble. spellcheck=false
      // kills the red squiggles browsers draw on Caddyfile keywords.
      return '<pre class="bg-slate-900 dark:bg-black/50 text-slate-100 p-3 rounded-lg text-xs my-2 font-mono leading-relaxed whitespace-pre-wrap break-all max-w-full" spellcheck="false"><code>' + codeBlocks[parseInt(idx, 10)] + '</code></pre>';
    });
    return html;
  }
  function appendBubble(role, text, isError) {
    var div = document.createElement('div');
    if (role === 'user') {
      div.className = 'flex justify-end';
      div.innerHTML = '<div class="bg-brand-600 text-white px-3 py-2 rounded-lg max-w-[85%] whitespace-pre-wrap">' + escapeHTML(text) + '</div>';
    } else if (isError) {
      div.className = 'flex justify-start';
      div.innerHTML = '<div class="bg-red-50 dark:bg-red-900/40 text-red-800 dark:text-red-200 border border-red-200 dark:border-red-800 px-3 py-2 rounded-lg max-w-[85%] whitespace-pre-wrap text-xs">' + escapeHTML(text) + '</div>';
    } else {
      // v2.12.7: render markdown for assistant replies. The whitespace-
      // pre-wrap class is dropped here since renderMarkdown emits real
      // <p>/<br> tags; pre-wrap would double up the spacing.
      div.className = 'flex justify-start';
      // v2.12.31: widened assistant bubble from 85% to 95% — when the AI
      // returns a Caddyfile, every extra column reduces the wrap density
      // for long directives like reverse_proxy + transport blocks.
      div.innerHTML = '<div class="bg-ink-100 dark:bg-slate-700 text-ink-900 dark:text-slate-100 px-3 py-2 rounded-lg max-w-[95%] leading-relaxed text-sm ai-md">' + renderMarkdown(text) + '</div>';
    }
    history.appendChild(div);
    history.scrollTop = history.scrollHeight;
  }

  // v2.12.42: deferred 2s — the AI fab is bottom-right, off-screen on
  // first paint, so its visibility check has no business blocking
  // initial paint metrics.
  caddyuiDelayFetch(2000, function() {
    fetch('/api/ai/status', { credentials: 'same-origin' })
      .then(function(r) { return r.ok ? r.json() : null; })
      .then(function(d) {
        if (!d || !d.enabled) return;
        fab.classList.remove('hidden');
        if (modelPill && d.model) modelPill.textContent = d.model;
      })
      .catch(function() {});
  });

  fab.addEventListener('click', function() {
    modal.classList.remove('hidden');
    setTimeout(function() { input.focus(); }, 0);
  });
  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape' && !modal.classList.contains('hidden')) {
      modal.classList.add('hidden');
      e.preventDefault();
    }
  });
  // v2.12.11: render a confirmation card for an AI-proposed tool call.
  // The user clicks Apply → POST to /api/ai/exec-tool → resource is
  // actually created. Cancel just dismisses the card.
  function appendToolCallCard(tc) {
    var args = tc.args || {};
    var labels = { 'create_proxy_host': '➕ Create proxy host', 'create_redirection': '➕ Create redirection' };
    var color = tc.name === 'create_redirection' ? 'sky' : 'brand';
    var rows = Object.keys(args).map(function(k) {
      var v = args[k];
      if (typeof v === 'boolean') v = v ? '✓ true' : '✗ false';
      return '<div class="grid grid-cols-[8rem_1fr] gap-2 text-xs"><span class="text-ink-500 dark:text-slate-400 font-mono">' + escapeHTML(k) + '</span><span class="text-ink-900 dark:text-slate-100 font-mono break-all">' + escapeHTML(String(v)) + '</span></div>';
    }).join('');
    var card = document.createElement('div');
    card.className = 'flex justify-start';
    card.innerHTML =
      '<div class="border-2 border-' + color + '-300 dark:border-' + color + '-700 bg-' + color + '-50 dark:bg-' + color + '-900/30 rounded-lg p-3 max-w-[90%] w-full">' +
        '<div class="flex items-center justify-between mb-2">' +
          '<div class="text-sm font-semibold text-' + color + '-800 dark:text-' + color + '-200">' + (labels[tc.name] || tc.name) + '</div>' +
          '<span class="text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-' + color + '-100 dark:bg-' + color + '-900/50 text-' + color + '-700 dark:text-' + color + '-300 font-medium">tool call</span>' +
        '</div>' +
        '<div class="space-y-1 mb-3">' + rows + '</div>' +
        '<div class="flex items-center gap-2">' +
          '<button data-tc-apply class="px-3 py-1 rounded-md bg-' + color + '-600 hover:bg-' + color + '-700 text-white text-xs font-medium transition">Apply</button>' +
          '<button data-tc-cancel class="px-3 py-1 rounded-md border border-ink-200 dark:border-slate-600 text-ink-600 dark:text-slate-300 hover:bg-ink-100 dark:hover:bg-slate-700 text-xs transition">Cancel</button>' +
          '<span data-tc-status class="text-xs text-ink-500 dark:text-slate-400 ml-2"></span>' +
        '</div>' +
      '</div>';
    history.appendChild(card);
    history.scrollTop = history.scrollHeight;

    var applyBtn = card.querySelector('[data-tc-apply]');
    var cancelBtn = card.querySelector('[data-tc-cancel]');
    var statusEl = card.querySelector('[data-tc-status]');

    cancelBtn.addEventListener('click', function() {
      applyBtn.disabled = true;
      cancelBtn.disabled = true;
      statusEl.textContent = '✗ cancelled';
    });
    applyBtn.addEventListener('click', function() {
      applyBtn.disabled = true;
      cancelBtn.disabled = true;
      statusEl.textContent = 'creating…';
      fetch('/api/ai/exec-tool', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ name: tc.name, args: tc.args })
      })
        .then(function(r) { return r.json(); })
        .then(function(d) {
          if (d.error) {
            statusEl.innerHTML = '<span class="text-red-600 dark:text-red-400">✗ ' + escapeHTML(d.error) + '</span>';
            return;
          }
          var url = d.url ? ' <a href="' + d.url + '" class="text-' + color + '-700 dark:text-' + color + '-300 underline">edit →</a>' : '';
          statusEl.innerHTML = '<span class="text-emerald-700 dark:text-emerald-300">' + escapeHTML(d.summary || '✓ created') + '</span>' + url;
        })
        .catch(function(err) {
          statusEl.innerHTML = '<span class="text-red-600 dark:text-red-400">✗ network error: ' + escapeHTML(err.message) + '</span>';
        });
    });
  }

  // v2.12.10: in-memory conversation transcript. Each user/assistant
  // exchange gets pushed; sent on every request as the multi-turn
  // messages[] payload. "New chat" clears it.
  var conversation = [];
  var newChatBtn = document.getElementById('ai-new-chat');
  function clearChat() {
    conversation = [];
    history.innerHTML = '<div class="text-xs text-ink-400 dark:text-slate-500 text-center">Ask anything about your CaddyUI config — proxy hosts, redirects, certs, Caddyfile snippets…</div>';
  }
  if (newChatBtn) newChatBtn.addEventListener('click', clearChat);

  // v2.12.32: textarea auto-grow. Re-measure height on input so the box
  // expands as the user types/pastes; the inline max-height (8rem) caps
  // it before it eats the chat panel. Enter alone submits; Shift+Enter
  // inserts a newline like every other modern chat UI.
  function autosize() {
    input.style.height = 'auto';
    input.style.height = Math.min(input.scrollHeight, 128) + 'px';
  }
  input.addEventListener('input', autosize);
  input.addEventListener('keydown', function(e) {
    if (e.key === 'Enter' && !e.shiftKey && !e.ctrlKey && !e.metaKey) {
      e.preventDefault();
      if (typeof form.requestSubmit === 'function') {
        form.requestSubmit();
      } else {
        // Older browsers (Safari < 16): synthesise a submit.
        var ev = new Event('submit', { cancelable: true, bubbles: true });
        form.dispatchEvent(ev);
      }
    }
  });

  form.addEventListener('submit', function(e) {
    e.preventDefault();
    var msg = input.value.trim();
    if (!msg) return;
    appendBubble('user', msg);
    conversation.push({ role: 'user', content: msg });
    input.value = '';
    autosize();
    submit.disabled = true;
    var thinking = document.createElement('div');
    thinking.className = 'flex justify-start';
    thinking.innerHTML = '<div class="bg-ink-100 dark:bg-slate-700 text-ink-500 dark:text-slate-400 px-3 py-2 rounded-lg italic text-xs">Thinking…</div>';
    history.appendChild(thinking);
    history.scrollTop = history.scrollHeight;
    fetch('/api/ai/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ messages: conversation })
    })
      .then(function(r) { return r.json(); })
      .then(function(d) {
        thinking.remove();
        if (d.error) {
          appendBubble('assistant', d.error, true);
          // Don't store error responses in conversation memory.
          return;
        }
        // v2.12.11: tool calls — render a confirmation card per call,
        // optionally alongside any prose the model included.
        if (d.tool_calls && d.tool_calls.length > 0) {
          if (d.reply) {
            appendBubble('assistant', d.reply);
            conversation.push({ role: 'assistant', content: d.reply });
          }
          d.tool_calls.forEach(function(tc) { appendToolCallCard(tc); });
          return;
        }
        if (d.reply) {
          appendBubble('assistant', d.reply);
          conversation.push({ role: 'assistant', content: d.reply });
        } else {
          appendBubble('assistant', '(empty response)', true);
        }
      })
      .catch(function(err) {
        thinking.remove();
        appendBubble('assistant', 'Network error: ' + err.message, true);
      })
      .finally(function() {
        submit.disabled = false;
        input.focus();
      });
  });
})();

// v2.11.0: tri-state theme toggle (auto → light → dark → auto).
// One handler bound to every [data-theme-toggle] button (mobile + topbar).
(function() {
  var STATES = ['auto', 'light', 'dark'];
  function paint() {
    var mode = document.documentElement.dataset.themeMode || 'auto';
    document.querySelectorAll('[data-theme-toggle]').forEach(function(btn) {
      btn.title = 'Theme: ' + mode + ' (click to change)';
      btn.querySelectorAll('[data-theme-icon]').forEach(function(icon) {
        icon.classList.toggle('hidden', icon.dataset.themeIcon !== mode);
      });
    });
  }
  function applyMode(mode) {
    document.documentElement.dataset.themeMode = mode;
    var dark = mode === 'dark' || (mode === 'auto' && window.matchMedia('(prefers-color-scheme: dark)').matches);
    document.documentElement.classList.toggle('dark', dark);
    try { localStorage.setItem('caddyui-theme', mode); } catch(e) {}
    paint();
  }
  paint();
  document.querySelectorAll('[data-theme-toggle]').forEach(function(btn) {
    btn.addEventListener('click', function() {
      var cur = document.documentElement.dataset.themeMode || 'auto';
      var next = STATES[(STATES.indexOf(cur) + 1) % STATES.length];
      applyMode(next);
    });
  });
})();

// v2.12.25: collapsible user menu in the persistent top bar.
// v2.12.28: generalised so the same handler powers any [data-*-menu]
// dropdown — used by both the user menu (avatar) and the server menu
// (top-bar server picker). Click opens, Esc / outside-click closes,
// only one open at a time across both menus.
(function() {
  // Each entry maps wrapper attr → toggle-attr → panel-attr.
  var MENUS = [
    { wrap: 'data-user-menu',   toggle: 'data-user-menu-toggle',   panel: 'data-user-menu-panel' },
    { wrap: 'data-server-menu', toggle: 'data-server-menu-toggle', panel: 'data-server-menu-panel' },
  ];
  function allPanels() {
    var nodes = [];
    MENUS.forEach(function(m) {
      document.querySelectorAll('[' + m.panel + ']').forEach(function(n) { nodes.push(n); });
    });
    return nodes;
  }
  function allMenus() {
    var nodes = [];
    MENUS.forEach(function(m) {
      document.querySelectorAll('[' + m.wrap + ']').forEach(function(n) { nodes.push({el: n, spec: m}); });
    });
    return nodes;
  }
  function close(panel, btn) {
    panel.classList.add('hidden');
    if (btn) btn.setAttribute('aria-expanded', 'false');
  }
  allMenus().forEach(function(entry) {
    var menu = entry.el, spec = entry.spec;
    var btn = menu.querySelector('[' + spec.toggle + ']');
    var panel = menu.querySelector('[' + spec.panel + ']');
    if (!btn || !panel) return;
    btn.addEventListener('click', function(e) {
      e.stopPropagation();
      var willOpen = panel.classList.contains('hidden');
      // Close any other open menus first (any kind)
      allPanels().forEach(function(p) {
        if (p !== panel) p.classList.add('hidden');
      });
      panel.classList.toggle('hidden');
      btn.setAttribute('aria-expanded', String(willOpen));
    });
  });
  document.addEventListener('click', function(e) {
    allMenus().forEach(function(entry) {
      var menu = entry.el, spec = entry.spec;
      if (!menu.contains(e.target)) {
        var panel = menu.querySelector('[' + spec.panel + ']');
        var btn = menu.querySelector('[' + spec.toggle + ']');
        if (panel && !panel.classList.contains('hidden')) close(panel, btn);
      }
    });
  });
  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
      allMenus().forEach(function(entry) {
        var menu = entry.el, spec = entry.spec;
        var panel = menu.querySelector('[' + spec.panel + ']');
        var btn = menu.querySelector('[' + spec.toggle + ']');
        if (panel && !panel.classList.contains('hidden')) close(panel, btn);
      });
    }
  });
})();

// v2.12.22: color theme picker (default | orange).
// v2.12.27: also POSTs the change to /api/me/color-theme so the
// preference syncs across devices. Local apply is instant; the network
// call is fire-and-forget — if it fails, localStorage still keeps the
// theme on this device. Server-rendered attribute on <html> is the
// authoritative source on next page load (see bootstrap in <head>).
(function() {
  function apply(theme) {
    if (!theme || theme === 'default') {
      document.documentElement.removeAttribute('data-color-theme');
    } else {
      document.documentElement.setAttribute('data-color-theme', theme);
    }
    try { localStorage.setItem('caddyui-color-theme', theme || 'default'); } catch(e) {}
    // Sync to server — fire-and-forget. credentials:'same-origin' so the
    // session cookie tags along; without it the handler 401s.
    if (typeof fetch === 'function') {
      try {
        fetch('/api/me/color-theme', {
          method: 'POST',
          credentials: 'same-origin',
          headers: {'Content-Type': 'application/x-www-form-urlencoded'},
          body: 'theme=' + encodeURIComponent(theme || 'default'),
        }).catch(function(err) {
          // Non-fatal: device-local storage still holds the value.
          if (window.console) console.warn('color theme sync failed:', err);
        });
      } catch(e) {}
    }
  }
  // Expose for any future programmatic access (theme switcher in chat, etc.)
  window.caddyuiSetColorTheme = apply;
  document.querySelectorAll('select[data-color-theme-select]').forEach(function(sel) {
    // Initial value: prefer the actual rendered <html> attribute (which
    // includes the server-side preference if signed in), then fall back to
    // localStorage. Either way, the dropdown reflects what's actually painted.
    var current = document.documentElement.getAttribute('data-color-theme') || '';
    if (!current) {
      try { current = localStorage.getItem('caddyui-color-theme') || ''; } catch(e) {}
    }
    sel.value = current || 'default';
    sel.addEventListener('change', function() { apply(sel.value); });
  });
})();

// Card-click → edit on mobile. Desktop tables have a visible pencil icon
// next to the primary identifier (the dashboard pattern), but on mobile
// the tap target is the whole card — any element with a data-edit-href
// attribute becomes clickable. Clicks that originate on an interactive
// child (link, button, form, input, select, textarea, label, plus
// <details>/<summary> for expanders and <pre> so users can click into a
// code block to copy from it) are skipped so inline controls keep their
// own behaviour. Cmd/Ctrl-click and middle-click open edit in a new tab.
(function() {
  function navigate(e) {
    var row = e.currentTarget;
    var href = row.getAttribute('data-edit-href');
    // v2.9.226: validate href is a same-origin relative path before
    // navigating. The attribute is server-rendered with trusted values,
    // but defense-in-depth + satisfies CodeQL "DOM text reinterpreted as
    // HTML/URL" by ensuring an attacker who somehow sets the attribute
    // can't redirect to javascript:, data:, //evil.com, etc.
    if (!href || href[0] !== '/' || href[1] === '/') return;
    if (e.target.closest('a, button, form, input, select, textarea, label, details, summary, pre')) return;
    if (e.metaKey || e.ctrlKey || e.button === 1) {
      window.open(href, '_blank', 'noopener');
    } else {
      window.location.href = href;
    }
  }
  document.querySelectorAll('[data-edit-href]').forEach(function(row) {
    row.addEventListener('click', navigate);
    // Middle-click on <tr>/<div> fires auxclick rather than click.
    row.addEventListener('auxclick', function(e) { if (e.button === 1) navigate(e); });
  });
})();

// v2.15.0: Toast notification system.
// window.caddyuiToast(msg, type, duration)
//   type: 'success' | 'error' | 'info' | 'warning'
//   duration: ms before auto-dismiss (default 4000)
// Also auto-converts existing static banner divs on page load to toasts.
(function() {
  var container = document.getElementById('toast-container');
  if (!container) return;

  var ICONS = {
    success: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-4 h-4 shrink-0"><polyline points="20 6 9 17 4 12"/></svg>',
    error:   '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-4 h-4 shrink-0"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
    warning: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-4 h-4 shrink-0"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
    info:    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-4 h-4 shrink-0"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>'
  };
  var COLORS = {
    success: 'bg-emerald-50 border-emerald-200 text-emerald-800',
    error:   'bg-red-50 border-red-200 text-red-800',
    warning: 'bg-amber-50 border-amber-200 text-amber-800',
    info:    'bg-brand-50 border-brand-200 text-brand-800'
  };
  var ICON_COLORS = {
    success: 'text-emerald-500',
    error:   'text-red-500',
    warning: 'text-amber-500',
    info:    'text-brand-500'
  };

  function dismiss(el) {
    el.classList.add('toast-leaving');
    setTimeout(function() {
      if (el.parentNode) el.parentNode.removeChild(el);
    }, 200);
  }

  window.caddyuiToast = function(msg, type, duration) {
    if (!msg) return;
    type = type || 'info';
    duration = (typeof duration === 'number') ? duration : 4000;
    var colorClass = COLORS[type] || COLORS.info;
    var iconColorClass = ICON_COLORS[type] || ICON_COLORS.info;
    var icon = ICONS[type] || ICONS.info;

    var el = document.createElement('div');
    el.className = 'toast-item flex items-center gap-3 px-4 py-3 rounded-xl border shadow-lg text-sm max-w-sm w-full ' + colorClass;
    el.innerHTML =
      '<span class="' + iconColorClass + '">' + icon + '</span>' +
      '<span class="flex-1 leading-snug">' + String(msg).replace(/</g,'&lt;').replace(/>/g,'&gt;') + '</span>' +
      '<button class="ml-1 opacity-60 hover:opacity-100 transition" aria-label="Dismiss">' +
        '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="w-3.5 h-3.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>' +
      '</button>';

    el.querySelector('button').addEventListener('click', function() { dismiss(el); });
    container.appendChild(el);

    if (duration > 0) {
      setTimeout(function() { dismiss(el); }, duration);
    }
    return el;
  };

  // Auto-convert existing static success/error banners to toasts on page load.
  // Finds .bg-brand-50 (success) and .bg-red-50 (error) banner divs in <main>,
  // reads their text, fires a toast, then hides the original so there's no duplicate.
  document.addEventListener('DOMContentLoaded', function() {
    var main = document.getElementById('main-content');
    if (!main) return;
    // Success banners: bg-brand-50 border-brand-200
    main.querySelectorAll('.bg-brand-50.border-brand-200').forEach(function(el) {
      var text = el.innerText.trim();
      if (!text) return;
      window.caddyuiToast(text, 'success', 5000);
      el.style.display = 'none';
    });
    // Error banners: bg-red-50 border-red-200
    main.querySelectorAll('.bg-red-50.border-red-200').forEach(function(el) {
      var text = el.innerText.trim();
      if (!text) return;
      window.caddyuiToast(text, 'error', 0); // 0 = no auto-dismiss for errors
      el.style.display = 'none';
    });
    // Warning banners: bg-amber-50 border-amber-200
    main.querySelectorAll('.bg-amber-50.border-amber-200').forEach(function(el) {
      // Maintenance banners are important — keep visible, don't toast
      if (el.textContent.indexOf('maintenance') !== -1) return;
      var text = el.innerText.trim();
      if (!text) return;
      window.caddyuiToast(text, 'warning', 6000);
      el.style.display = 'none';
    });
  });
})();

// v2.15.0: Dashboard sparklines — fetches /api/dashboard-sparklines (7-day
// daily data) and renders inline SVG sparkline paths on the three stat cards.
(function() {
  var cards = [
    { containerId: 'sparkline-views',     dataKey: 'views' },
    { containerId: 'sparkline-visitors',  dataKey: 'visitors' },
    { containerId: 'sparkline-bandwidth', dataKey: 'bandwidth' },
  ];
  // Only run on dashboard (all three containers must exist)
  if (!document.getElementById('sparkline-views')) return;

  caddyuiDelayFetch(1500, function() {
    fetch('/api/dashboard-sparklines', { credentials: 'same-origin' })
      .then(function(r) { return r.ok ? r.json() : null; })
      .then(function(d) {
        if (!d || !d.days || d.days.length === 0) return;
        cards.forEach(function(c) {
          var el = document.getElementById(c.containerId);
          if (!el) return;
          var vals = d.days.map(function(day) { return day[c.dataKey] || 0; });
          el.innerHTML = renderSparkline(vals);
        });
      })
      .catch(function() {});
  });

  function renderSparkline(vals) {
    if (!vals || vals.length < 2) return '';
    var W = 80, H = 24;
    var max = Math.max.apply(null, vals);
    if (max === 0) max = 1;
    var pts = vals.map(function(v, i) {
      var x = (i / (vals.length - 1)) * W;
      var y = H - (v / max) * (H - 2) - 1;
      return x.toFixed(1) + ',' + y.toFixed(1);
    });
    // Smooth path via cardinal spline through points
    var d = 'M ' + pts.join(' L ');
    return '<svg width="' + W + '" height="' + H + '" viewBox="0 0 ' + W + ' ' + H + '" class="sparkline-svg" aria-hidden="true">' +
      '<polyline fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" opacity="0.5" points="' + pts.join(' ') + '"/>' +
      '</svg>';
  }
})();
