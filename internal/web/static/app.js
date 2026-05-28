let mailboxPollTimer = null;
let mailboxEventSource = null;

// ── Theme ─────────────────────────────────────────────────────────────────────

function resolveThemePreference(preference) {
  if (preference === 'dark' || preference === 'light') return preference;
  return window.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function applyThemePreference(preference) {
  const selected = preference || localStorage.getItem('mailprobe-theme') || 'auto';
  const resolved = resolveThemePreference(selected);
  document.documentElement.dataset.bsTheme = resolved;
  document.documentElement.dataset.themePreference = selected;
  const icon = document.querySelector('#theme-toggle .theme-icon');
  if (icon) {
    icon.textContent = selected === 'auto' ? 'AUTO' : (resolved === 'dark' ? 'DARK' : 'LIGHT');
  }
}

function setupThemeToggle() {
  applyThemePreference(localStorage.getItem('mailprobe-theme') || 'auto');
  document.getElementById('theme-toggle')?.addEventListener('click', () => {
    const current = document.documentElement.dataset.themePreference || 'auto';
    const next = current === 'auto' ? 'dark' : current === 'dark' ? 'light' : 'auto';
    localStorage.setItem('mailprobe-theme', next);
    applyThemePreference(next);
  });
  window.matchMedia?.('(prefers-color-scheme: dark)').addEventListener('change', () => {
    if ((localStorage.getItem('mailprobe-theme') || 'auto') === 'auto') applyThemePreference('auto');
  });
}

// ── Clipboard ─────────────────────────────────────────────────────────────────

async function writeClipboardWithFallback(text) {
  if (navigator.clipboard && window.isSecureContext) {
    try { await navigator.clipboard.writeText(text); return true; } catch (_) {}
  }
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.setAttribute('readonly', '');
  ta.style.cssText = 'position:absolute;left:-9999px';
  document.body.appendChild(ta);
  ta.select();
  let ok = false;
  try { ok = document.execCommand('copy'); } catch (_) {}
  document.body.removeChild(ta);
  return ok;
}

async function copyAddress() {
  const text = document.getElementById('mail-address')?.innerText?.trim();
  if (!text) return;
  const ok = await writeClipboardWithFallback(text);
  setTransientStatus(ok ? 'Adresse kopiert.' : 'Kopieren fehlgeschlagen – bitte manuell markieren.', ok ? 'ok' : 'warn');
}

// ── API helpers ───────────────────────────────────────────────────────────────

async function fetchMailboxStatus(token) {
  const res = await fetch(`/api/mailboxes/${token}/status`, { cache: 'no-store' });
  if (!res.ok) throw new Error('status fetch failed');
  return res.json();
}

async function createMailbox() {
  const res = await fetch('/api/mailboxes', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    cache: 'no-store',
    body: '{}',
  });
  if (!res.ok) throw new Error('mailbox create failed');
  return res.json();
}

// ── Time formatting ───────────────────────────────────────────────────────────

function formatExpiry(value) {
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleString(navigator.language || 'de-DE', {
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
    timeZoneName: 'short',
  });
}

function localizeStaticTimes() {
  document.querySelectorAll('[data-time]').forEach((el) => {
    el.textContent = formatExpiry(el.dataset.time);
  });
}

// ── Mailbox identity update ───────────────────────────────────────────────────

function updateMailboxIdentity(data) {
  const panel    = document.getElementById('check-panel');
  const address  = document.getElementById('mail-address');
  const expires  = document.getElementById('mail-expires-at');
  const link     = document.getElementById('mailbox-direct-link');
  const statCard = document.getElementById('status-card');

  if (panel)   panel.dataset.token = data.token;
  if (address) address.textContent = data.address;
  if (expires) {
    expires.dataset.time = data.expires_at;
    expires.textContent  = formatExpiry(data.expires_at);
  }
  if (link) {
    link.href        = data.mailbox_url;
    link.textContent = data.mailbox_url;
  }
  if (statCard) {
    statCard.dataset.token           = data.token;
    statCard.dataset.latestMessageId = '0';
  }
  sessionStorage.setItem(`mailprobe:lastmsg:${data.token}`, '0');
}

async function createNewAddress() {
  const button = document.getElementById('new-address-btn');
  if (!button) return;
  const oldText = button.textContent;
  button.disabled    = true;
  button.textContent = 'Erzeuge Adresse …';
  stopMailboxPolling();
  try {
    const data = await createMailbox();
    updateMailboxIdentity(data);
    saveMbToHistory(data.token);        // track new token if consented
    setCheckUIState(false, 'Neue Testadresse bereit.', 'ok');
    setupMailboxPolling();
  } catch (_) {
    setTransientStatus('Neue Adresse konnte nicht erzeugt werden.', 'warn');
  } finally {
    button.disabled    = false;
    button.textContent = oldText;
  }
}

// ── Status UI helpers ─────────────────────────────────────────────────────────

function setStatusDot(state) {
  const dot = document.querySelector('.status-dot');
  if (!dot) return;
  dot.className = 'status-dot';
  if (state) dot.classList.add(`dot-${state}`);
}

function updateMailboxStatusText(data) {
  const statusText = document.getElementById('status-text');
  if (!statusText) return;
  if (data.latest_report_path) {
    setStatusDot('ready');
    statusText.innerHTML = `Analyse abgeschlossen (Score: <strong>${data.latest_score}/10</strong>). <a href="${data.latest_report_path}">Report öffnen →</a>`;
    return;
  }
  if (data.latest_message_id) {
    setStatusDot('received');
    statusText.textContent = 'Mail empfangen – Analyse läuft …';
    return;
  }
  setStatusDot('waiting');
  statusText.textContent = 'Warte auf eingehende E-Mail …';
}

function setCheckUIState(active, message, tone) {
  const status = document.getElementById('check-status');
  const loader = document.getElementById('check-loader');
  const button = document.getElementById('check-btn');
  if (!status || !loader || !button) return;

  status.textContent = message;
  status.classList.remove('is-ok', 'is-warn');
  if (tone === 'ok')   status.classList.add('is-ok');
  if (tone === 'warn') status.classList.add('is-warn');

  if (active) {
    loader.classList.remove('d-none');
    button.disabled = true;
  } else {
    loader.classList.add('d-none');
    button.disabled = false;
  }
}

function setTransientStatus(message, tone) {
  const checkStatus = document.getElementById('check-status');
  if (checkStatus) {
    checkStatus.textContent = message;
    checkStatus.classList.remove('is-ok', 'is-warn');
    if (tone === 'ok')   checkStatus.classList.add('is-ok');
    if (tone === 'warn') checkStatus.classList.add('is-warn');
    return;
  }
  const mailboxStatus = document.getElementById('status-text');
  if (mailboxStatus) { mailboxStatus.textContent = message; return; }
  const toast = document.createElement('div');
  toast.className   = `copy-toast ${tone === 'ok' ? 'is-ok' : 'is-warn'}`;
  toast.textContent = message;
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 2200);
}

// ── Check loop (home page) ────────────────────────────────────────────────────

function handleCheckStatusEvent(data) {
  if (data.latest_report_path) {
    setCheckUIState(false, 'Report bereit – Weiterleitung …', 'ok');
    window.location.href = data.latest_report_path;
    return;
  }
  if (data.latest_message_id) {
    setCheckUIState(true, 'Mail eingegangen – Analyse läuft …', 'warn');
    return;
  }
  setCheckUIState(true, 'Noch keine Mail eingegangen – ich warte weiter …', 'warn');
}

function startCheckLoop() {
  const token = document.getElementById('check-panel')?.dataset?.token;
  if (!token) return;

  setCheckUIState(true, 'Prüfe Eingang …', 'warn');
  if (mailboxPollTimer) clearInterval(mailboxPollTimer);

  const run = async () => {
    try {
      const data = await fetchMailboxStatus(token);
      handleCheckStatusEvent(data);
      if (data.latest_report_path) {
        clearInterval(mailboxPollTimer);
        mailboxPollTimer = null;
      }
    } catch (_) {
      setCheckUIState(true, 'Statusabfrage fehlgeschlagen – ich versuche es weiter …', 'warn');
    }
  };
  run();
  mailboxPollTimer = setInterval(run, 2500);
}

function setupCheckButton() {
  document.getElementById('check-btn')?.addEventListener('click', startCheckLoop);
}

function setupNewAddressButton() {
  document.getElementById('new-address-btn')?.addEventListener('click', createNewAddress);
}

// ── Copy buttons ──────────────────────────────────────────────────────────────

function setupCopyButtons() {
  document.querySelectorAll('[data-copy]').forEach((button) => {
    button.addEventListener('click', async () => {
      const ok = await writeClipboardWithFallback(button.getAttribute('data-copy') || '');
      const original = button.textContent;
      button.textContent = ok ? 'Kopiert' : 'Fehler';
      button.classList.toggle('is-ok', ok);
      button.classList.toggle('is-warn', !ok);
      setTimeout(() => {
        button.textContent = original;
        button.classList.remove('is-ok', 'is-warn');
      }, 1600);
    });
  });
}

// ── Mailbox live updates via SSE (mailbox page) ───────────────────────────────

function stopMailboxPolling() {
  if (mailboxPollTimer)   { clearInterval(mailboxPollTimer); mailboxPollTimer = null; }
  if (mailboxEventSource) { mailboxEventSource.close(); mailboxEventSource = null; }
}

function setupMailboxPolling() {
  const card = document.getElementById('status-card');
  if (!card) return;

  const token    = card.dataset.token;
  const stateKey = `mailprobe:lastmsg:${token}`;
  if (!sessionStorage.getItem(stateKey)) {
    sessionStorage.setItem(stateKey, card.dataset.latestMessageId || '0');
  }

  const onStatus = (data) => {
    const lastKnown = sessionStorage.getItem(stateKey) || '0';
    const latest    = String(data.latest_message_id || '0');
    if (latest !== '0' && latest !== lastKnown) {
      sessionStorage.setItem(stateKey, latest);
      location.reload();
      return;
    }
    updateMailboxStatusText(data);
  };

  if (typeof EventSource !== 'undefined') {
    startMailboxSSE(token, onStatus);
  } else {
    startMailboxPollingFallback(token, onStatus);
  }

  setStatusDot('waiting');
}

function startMailboxSSE(token, onStatus) {
  stopMailboxPolling();
  let retryDelay = 2000;

  function connect() {
    const es = new EventSource(`/api/mailboxes/${token}/events`);
    mailboxEventSource = es;

    es.addEventListener('status', (ev) => {
      retryDelay = 2000;
      try { onStatus(JSON.parse(ev.data)); } catch (_) {}
    });

    es.addEventListener('error', () => {
      es.close();
      mailboxEventSource = null;
      retryDelay = Math.min(retryDelay * 1.5, 30000);
      setTimeout(connect, retryDelay);
    });
  }

  connect();
}

function startMailboxPollingFallback(token, onStatus) {
  stopMailboxPolling();
  const run = async () => {
    try {
      onStatus(await fetchMailboxStatus(token));
    } catch (_) {
      const el = document.getElementById('status-text');
      if (el) el.textContent = 'Statusabfrage fehlgeschlagen. Bitte Seite neu laden.';
    }
  };
  run();
  mailboxPollTimer = setInterval(run, 5000);
}

// ── Report: check filter bar ──────────────────────────────────────────────────

function setupCheckFilter() {
  const bar = document.getElementById('check-filter-bar');
  if (!bar) return;

  const allBtn      = bar.querySelector('[data-filter="all"]');
  const filterBtns  = [...bar.querySelectorAll('[data-filter]:not([data-filter="all"])')];

  function applyFilter() {
    const active = new Set(
      filterBtns.filter((b) => b.classList.contains('active')).map((b) => b.dataset.filter)
    );
    const showAll = active.size === 0;

    // Show / hide individual check items
    document.querySelectorAll('.mp-check-item').forEach((item) => {
      const visible = showAll || active.has(item.dataset.status);
      if (!visible) {
        // Collapse any open accordion before hiding
        const collapseEl = item.querySelector('.accordion-collapse.show');
        if (collapseEl) {
          if (typeof bootstrap !== 'undefined') {
            const inst = bootstrap.Collapse.getInstance(collapseEl);
            if (inst) { inst.hide(); } else { collapseEl.classList.remove('show'); }
          } else {
            collapseEl.classList.remove('show');
          }
          const aBtn = item.querySelector('.accordion-button');
          if (aBtn) { aBtn.classList.add('collapsed'); aBtn.setAttribute('aria-expanded', 'false'); }
        }
        item.classList.add('mp-filter-hidden');
      } else {
        item.classList.remove('mp-filter-hidden');
      }
    });

    // Hide group cards whose every item is now hidden
    document.querySelectorAll('.card').forEach((card) => {
      const accordion = card.querySelector('.mp-check-accordion');
      if (!accordion) return;
      const allItems     = accordion.querySelectorAll('.mp-check-item');
      const visibleItems = accordion.querySelectorAll('.mp-check-item:not(.mp-filter-hidden)');
      card.classList.toggle('d-none', allItems.length > 0 && visibleItems.length === 0);
    });

    // Keep "All" button in sync: active when nothing else is selected
    if (allBtn) allBtn.classList.toggle('active', showAll);
  }

  bar.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-filter]');
    if (!btn) return;

    if (btn.dataset.filter === 'all') {
      // "All" clears every other selection
      filterBtns.forEach((b) => b.classList.remove('active'));
    } else {
      // Toggle the clicked status button
      btn.classList.toggle('active');
    }

    applyFilter();
  });
}

// ── Score delta coloring ──────────────────────────────────────────────────────

function colorScoreDeltas() {
  document.querySelectorAll('.mp-delta').forEach((el) => {
    const v = parseFloat(el.textContent);
    if (v < 0) el.classList.add('delta-neg');
    else if (v > 0) el.classList.add('delta-pos');
  });
}

// ── Score mini coloring (mailbox list) ────────────────────────────────────────

function colorScoreMinis() {
  document.querySelectorAll('.mp-score-mini').forEach((el) => {
    // Support both direct data-score attribute and parsing from inner <strong>
    const raw = el.dataset.score ?? el.querySelector('strong')?.textContent;
    const v = parseFloat(raw ?? 'NaN');
    if (Number.isNaN(v)) return;
    if (v >= 7.5)      el.classList.add('score-pass');
    else if (v >= 5.5) el.classList.add('score-warn');
    else               el.classList.add('score-fail');
  });
}

// ── Cookie consent & mailbox history ─────────────────────────────────────────

function getConsentState() {
  try { return localStorage.getItem('mailprobe:consent'); } catch (_) { return null; }
}

function saveMbToHistory(token) {
  if (!token || getConsentState() !== 'granted') return;
  try {
    const stored = JSON.parse(localStorage.getItem('mailprobe:mailboxes') || '[]');
    const updated = [token, ...stored.filter((t) => t !== token)].slice(0, 12);
    localStorage.setItem('mailprobe:mailboxes', JSON.stringify(updated));
  } catch (_) {}
}

function removeFromHistory(token) {
  try {
    const stored = JSON.parse(localStorage.getItem('mailprobe:mailboxes') || '[]');
    localStorage.setItem('mailprobe:mailboxes', JSON.stringify(stored.filter((t) => t !== token)));
  } catch (_) {}
}

function scoreClass(score) {
  if (score >= 7.5) return 'score-pass';
  if (score >= 5.5) return 'score-warn';
  return 'score-fail';
}

async function loadPreviousMailboxes() {
  if (getConsentState() !== 'granted') return;
  const section = document.getElementById('prev-mailboxes-section');
  const list    = document.getElementById('prev-mailboxes-list');
  if (!section || !list) return;

  const currentToken = document.getElementById('check-panel')?.dataset?.token || '';
  let stored = [];
  try { stored = JSON.parse(localStorage.getItem('mailprobe:mailboxes') || '[]'); } catch (_) {}
  const others = stored.filter((t) => t !== currentToken);
  if (others.length === 0) return;

  const results = await Promise.allSettled(others.map((t) => fetchMailboxStatus(t)));
  const items   = [];
  results.forEach((res, i) => {
    if (res.status === 'fulfilled') {
      items.push({ token: others[i], data: res.value });
    } else {
      removeFromHistory(others[i]); // stale / deleted mailbox
    }
  });

  if (items.length === 0) return;
  section.classList.remove('d-none');

  list.innerHTML = items.map(({ token, data }) => {
    const expired   = data.expires_at && new Date(data.expires_at) < new Date();
    const scoreHtml = data.latest_score != null
      ? `<span class="mp-score-mini ${scoreClass(data.latest_score)}">` +
        `<strong>${Number(data.latest_score).toFixed(1)}</strong><span>/10</span></span>`
      : '';
    const reportBtn = data.latest_report_path
      ? `<a href="${data.latest_report_path}" class="btn btn-sm btn-primary py-0 px-2">Report</a>`
      : '';
    return `<div class="d-flex align-items-center gap-2 py-2 px-3 rounded border mp-prev-mb-item${expired ? ' opacity-50' : ''}">
      <i class="bi bi-envelope-at text-secondary flex-shrink-0"></i>
      <code class="flex-grow-1 text-truncate mp-prev-mb-addr">${data.mailbox || token}</code>
      ${scoreHtml}
      ${reportBtn}
      <a href="/mailbox/${token}" class="btn btn-sm btn-outline-secondary py-0 px-2">Öffnen</a>
    </div>`;
  }).join('');
}

function setupCookieConsent() {
  if (getConsentState() === null) {
    // Show banner after a short delay so it doesn't flash on first paint
    setTimeout(() => document.getElementById('mp-consent-banner')?.classList.remove('d-none'), 800);
  } else if (getConsentState() === 'granted') {
    const token = document.getElementById('check-panel')?.dataset?.token;
    if (token) saveMbToHistory(token);
    loadPreviousMailboxes();
  }
}

// Called from HTML onclick – must be global
function consentAccept() {
  try { localStorage.setItem('mailprobe:consent', 'granted'); } catch (_) {}
  document.getElementById('mp-consent-banner')?.classList.add('d-none');
  const token = document.getElementById('check-panel')?.dataset?.token;
  if (token) saveMbToHistory(token);
  loadPreviousMailboxes();
}

function consentDecline() {
  try { localStorage.setItem('mailprobe:consent', 'declined'); } catch (_) {}
  document.getElementById('mp-consent-banner')?.classList.add('d-none');
}

// ── Boot ──────────────────────────────────────────────────────────────────────

setupThemeToggle();
setupCheckButton();
setupNewAddressButton();
setupCopyButtons();
localizeStaticTimes();
setupMailboxPolling();
setupCheckFilter();
setupCookieConsent();
colorScoreDeltas();
colorScoreMinis();
