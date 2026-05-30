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

  // Visual flash on the clickable box (home page)
  const box = document.querySelector('.mp-addr-box');
  if (box && ok) {
    const hintIcon = box.querySelector('.mp-addr-copy-hint i');
    const hintSpan = box.querySelector('.mp-addr-copy-hint');
    if (hintIcon) { hintIcon.className = 'bi bi-check2-circle me-1'; }
    if (hintSpan) { hintSpan.lastChild.textContent = 'Kopiert!'; }
    box.classList.add('mp-copied');
    setTimeout(() => {
      box.classList.remove('mp-copied');
      if (hintIcon) { hintIcon.className = 'bi bi-clipboard me-1'; }
      if (hintSpan) { hintSpan.lastChild.textContent = 'Klicken zum Kopieren'; }
    }, 1800);
  }

  // Visual flash on the inline address chip (mailbox page)
  const chip = document.querySelector('.mp-addr-inline');
  if (chip && ok) {
    chip.classList.add('mp-copied');
    setTimeout(() => chip.classList.remove('mp-copied'), 1800);
  }

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
    _stopStepAnimation();
    setCheckUIState(false, 'Neue Mailbox bereit.', 'ok');
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
  // New animated wait icon
  const waitIcon = document.getElementById('mp-wait-icon');
  if (waitIcon) {
    waitIcon.dataset.state = state || 'waiting';
  }
  // Legacy dot (kept for backwards compat in case it exists on the page)
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
  const status     = document.getElementById('check-status');
  const statusIdle = document.getElementById('check-status-idle');
  const loader     = document.getElementById('check-loader');
  const actions    = document.getElementById('check-actions');
  const button     = document.getElementById('check-btn');
  if (!loader) return;

  if (active) {
    // Zeige Spinner-Wartezustand
    loader.classList.remove('d-none');
    if (actions)    actions.classList.add('d-none');
    if (statusIdle) statusIdle.classList.add('d-none');
    if (button)     button.disabled = true;
  } else {
    // Zurück zu Buttons
    loader.classList.add('d-none');
    if (actions)    actions.classList.remove('d-none');
    if (statusIdle) statusIdle.classList.remove('d-none');
    if (button)     button.disabled = false;
  }

  if (status) {
    status.textContent = message;
    status.classList.remove('is-ok', 'is-warn');
    if (tone === 'ok')   status.classList.add('is-ok');
    if (tone === 'warn') status.classList.add('is-warn');
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

// matchIds: which check IDs from the report map to this step
// "worst" status (fail > warn > info > pass) across all matched checks is shown
const ANALYSIS_STEPS = [
  { label: 'E-Mail wird empfangen',           matchIds: [] },
  { label: 'SPF-Record wird geprüft',         matchIds: ['spf', 'spf_alignment'] },
  { label: 'DKIM-Signatur wird verifiziert',  matchIds: ['dkim', 'dkim_alignment'] },
  { label: 'DMARC-Policy wird analysiert',    matchIds: ['dmarc', 'dmarc_alignment'] },
  { label: 'PTR / Reverse-DNS wird geprüft',  matchIds: ['ptr'] },
  { label: 'HELO-Identität wird validiert',   matchIds: ['helo', 'from_alignment'] },
  { label: 'TLS-Verbindung wird geprüft',     matchIds: ['tls_transport'] },
  { label: 'Blacklists werden abgefragt',     matchIds: ['rbl'] },
  { label: 'MIME-Struktur wird analysiert',   matchIds: ['mime_parse','mime_ct','mime_boundary','plain_text','html','html_validity','hidden_html','body_read'] },
  { label: 'Spam-Score wird berechnet',       matchIds: ['spamassassin','rspamd'] },
  { label: 'Header-Chain wird ausgewertet',   matchIds: ['mx_records','address_records','received_chain','date','date_skew','subject','subject_exclaim','subject_caps','links','tracking_links','shortener'] },
  { label: 'Report wird finalisiert',         matchIds: [] },
];

const STATUS_RANK = { fail: 3, warn: 2, info: 1, pass: 0 };

function _worstStatus(checks, ids) {
  if (!checks || !ids.length) return null;
  let worst = null;
  for (const c of checks) {
    if (!ids.includes(c.id)) continue;
    if (worst === null || (STATUS_RANK[c.status] ?? 0) > (STATUS_RANK[worst] ?? 0)) {
      worst = c.status;
    }
  }
  return worst;
}

function _statusIcon(status) {
  switch (status) {
    case 'fail': return '<i class="bi bi-x-circle text-danger"></i>';
    case 'warn': return '<i class="bi bi-exclamation-triangle text-warning"></i>';
    case 'info': return '<i class="bi bi-info-circle text-info"></i>';
    default:     return '<i class="bi bi-check2-circle text-success"></i>';
  }
}

function _statusClass(status) {
  switch (status) {
    case 'fail': return 'mp-check-step result-fail';
    case 'warn': return 'mp-check-step result-warn';
    case 'info': return 'mp-check-step result-info';
    default:     return 'mp-check-step done';
  }
}

let _stepTimer    = null;
let _stepIdx      = 0;
let _stepDone     = false;
let _pendingHref  = null;
let _reportChecks = null;

function _reportApiUrl(reportPath) {
  const m = String(reportPath).match(/\/report\/([^?/]+)\?msg=([^&]+)/);
  return m ? `/api/reports/${m[1]}/${m[2]}` : null;
}

async function _fetchReportChecks(reportPath) {
  const url = _reportApiUrl(reportPath);
  if (!url) return;
  try {
    const res = await fetch(url, { cache: 'no-store' });
    if (!res.ok) return;
    const data = await res.json();
    _reportChecks = data.report?.checks ?? null;
  } catch (_) {}
}

function _renderSteps(upTo) {
  const el = document.getElementById('check-steps');
  if (!el) return;
  el.innerHTML = ANALYSIS_STEPS.slice(0, upTo + 1).map((s, i) => {
    if (i < upTo) {
      return `<div class="mp-check-step done">
        <i class="bi bi-check2-circle text-success"></i>
        <span>${s.label}</span>
      </div>`;
    }
    return `<div class="mp-check-step active">
      <span class="spinner-border spinner-border-sm text-primary mp-step-spin" role="status"></span>
      <span>${s.label} …</span>
    </div>`;
  }).join('');
  el.lastElementChild?.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
}

function _renderStepsWithResults(checks) {
  const el = document.getElementById('check-steps');
  if (!el) return;
  el.innerHTML = ANALYSIS_STEPS.map((s) => {
    const status = _worstStatus(checks, s.matchIds) || 'pass';
    return `<div class="${_statusClass(status)}">
      ${_statusIcon(status)}
      <span>${s.label}</span>
    </div>`;
  }).join('');
}

function _stepDelay() {
  return Math.floor(Math.random() * 440) + 380;
}

function _onAnimationComplete() {
  const doRedirect = () => { if (_pendingHref) window.location.href = _pendingHref; };

  if (_reportChecks) {
    _renderStepsWithResults(_reportChecks);
    setTimeout(doRedirect, 1800);
  } else if (_pendingHref) {
    // Fetch might still be in flight — give it 600 ms then redirect anyway
    setTimeout(() => {
      if (_reportChecks) _renderStepsWithResults(_reportChecks);
      setTimeout(doRedirect, _reportChecks ? 1800 : 0);
    }, 600);
  }
  // If no report yet, just stay in "waiting" state — poll will trigger again
}

function _startStepAnimation() {
  _stepIdx      = 0;
  _stepDone     = false;
  _pendingHref  = null;
  _reportChecks = null;
  _renderSteps(0);

  function scheduleNext() {
    _stepTimer = setTimeout(() => {
      _stepIdx++;
      if (_stepIdx >= ANALYSIS_STEPS.length) {
        _stepTimer = null;
        _stepDone  = true;
        _onAnimationComplete();
        return;
      }
      _renderSteps(_stepIdx);
      scheduleNext();
    }, _stepDelay());
  }
  scheduleNext();
}

function _stopStepAnimation() {
  if (_stepTimer) { clearTimeout(_stepTimer); _stepTimer = null; }
  _stepDone = false; _pendingHref = null; _reportChecks = null;
  const el = document.getElementById('check-steps');
  if (el) el.innerHTML = '';
}

function handleCheckStatusEvent(data) {
  if (data.latest_report_path) {
    // Fetch report data in background so results can be shown in the step list
    if (!_reportChecks && !_pendingHref) {
      _fetchReportChecks(data.latest_report_path);
    }
    if (_stepDone) {
      _onAnimationComplete();
    } else {
      _pendingHref = data.latest_report_path;
    }
    return;
  }
  if (data.latest_message_id) {
    // Mail empfangen — Schritt-Animation starten (einmalig)
    if (!_stepTimer && !_stepDone) {
      document.getElementById('check-wait-msg')?.classList.add('d-none');
      document.getElementById('check-steps')?.classList.remove('d-none');
      _startStepAnimation();
    }
    return;
  }
}

function startCheckLoop() {
  const token = document.getElementById('check-panel')?.dataset?.token;
  if (!token) return;

  // Zurücksetzen & Spinner zeigen — Schritte kommen erst wenn Mail da
  _stopStepAnimation();
  document.getElementById('check-wait-msg')?.classList.remove('d-none');
  document.getElementById('check-steps')?.classList.add('d-none');
  setCheckUIState(true, '', 'warn');
  if (mailboxPollTimer) clearInterval(mailboxPollTimer);

  const run = async () => {
    try {
      const data = await fetchMailboxStatus(token);
      handleCheckStatusEvent(data);
      if (data.latest_report_path && _stepDone) {
        clearInterval(mailboxPollTimer);
        mailboxPollTimer = null;
      }
    } catch (_) { /* still waiting */ }
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

// Format remaining time until `isoDate` in a sensible unit (live countdown)
function formatTimeRemaining(isoDate) {
  if (!isoDate) return '';
  const diff = new Date(isoDate) - Date.now();
  if (diff <= 0) return 'abgelaufen';
  const mins  = Math.floor(diff / 60000);
  const hours = Math.floor(diff / 3600000);
  const days  = Math.floor(diff / 86400000);
  if (days >= 2)  return `noch ${days} Tage`;
  if (hours >= 1) return `noch ${hours} Std.`;
  if (mins >= 1)  return `noch ${mins} Min.`;
  return 'läuft gleich ab';
}

// Format exact datetime for tooltip
function formatExactDate(isoDate) {
  if (!isoDate) return '';
  try {
    return new Date(isoDate).toLocaleString('de-DE', {
      day: '2-digit', month: '2-digit', year: 'numeric',
      hour: '2-digit', minute: '2-digit',
    });
  } catch (_) { return isoDate; }
}

// Refresh all countdown labels every 60 s
function startPrevMbCountdown() {
  clearInterval(window._mpCountdownTimer);
  window._mpCountdownTimer = setInterval(() => {
    document.querySelectorAll('[data-mb-expires]').forEach((el) => {
      el.textContent = formatTimeRemaining(el.dataset.mbExpires);
    });
  }, 60000);
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
      removeFromHistory(others[i]); // abgelaufene / gelöschte Mailbox entfernen
    }
  });

  if (items.length === 0) return;
  section.classList.remove('d-none');

  list.innerHTML = items.map(({ token, data }) => {
    const expired    = data.expires_at && new Date(data.expires_at) < new Date();
    const ttlLabel   = formatTimeRemaining(data.expires_at);
    const ttlTooltip = formatExactDate(data.expires_at);
    const ttlClass   = expired ? 'text-danger' : (ttlLabel.includes('Min') ? 'text-warning' : 'text-secondary');

    const scoreHtml = data.latest_score != null
      ? `<span class="mp-score-mini ${scoreClass(data.latest_score)}">` +
        `<strong>${Number(data.latest_score).toFixed(1)}</strong><span>/10</span></span>`
      : '';
    const reportBtn = data.latest_report_path
      ? `<a href="${data.latest_report_path}" class="btn btn-sm btn-primary py-0 px-2">Report</a>`
      : '';

    return `<div class="d-flex align-items-center gap-2 py-2 px-3 rounded border mp-prev-mb-item${expired ? ' mp-prev-mb-expired' : ''}"
                 data-token="${token}">
      <i class="bi bi-envelope-at text-secondary flex-shrink-0"></i>
      <code class="flex-grow-1 text-truncate mp-prev-mb-addr">${data.mailbox || token}</code>
      ${scoreHtml}
      <span class="${ttlClass} small mp-ttl-label"
            data-mb-expires="${data.expires_at || ''}"
            title="${ttlTooltip}"
            style="white-space:nowrap">${ttlLabel}</span>
      ${reportBtn}
      <a href="/mailbox/${token}" class="btn btn-sm btn-outline-secondary py-0 px-2">Öffnen</a>
      <button class="btn btn-sm btn-outline-danger py-0 px-2 mp-delete-mb-btn"
              data-token="${token}"
              data-addr="${data.mailbox || token}"
              data-count="${data.message_count || 0}"
              title="Mailbox löschen"
              type="button">
        <i class="bi bi-trash3"></i>
      </button>
    </div>`;
  }).join('');

  // Bootstrap-Tooltips für Ablaufzeiten initialisieren
  list.querySelectorAll('[title]').forEach((el) => {
    if (typeof bootstrap !== 'undefined') {
      new bootstrap.Tooltip(el, { trigger: 'hover', placement: 'top' });
    }
  });

  // Lösch-Buttons verdrahten
  list.querySelectorAll('.mp-delete-mb-btn').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      openDeleteModal(btn.dataset.token, btn.dataset.addr, parseInt(btn.dataset.count, 10) || 0);
    });
  });

  startPrevMbCountdown();
}

// ── Mailbox-Löschung ──────────────────────────────────────────────────────────

let _deleteTarget = null;

function openDeleteModal(token, addr, msgCount) {
  _deleteTarget = token;
  const addrEl    = document.getElementById('mp-delete-addr');
  const warnEl    = document.getElementById('mp-delete-msg-warn');
  const countEl   = document.getElementById('mp-delete-msg-count');
  if (addrEl)  addrEl.textContent = addr;
  if (warnEl && countEl) {
    if (msgCount > 0) {
      countEl.textContent = msgCount === 1
        ? 'Es befindet sich noch 1 E-Mail in dieser Mailbox, die ebenfalls gelöscht wird.'
        : `Es befinden sich noch ${msgCount} E-Mails in dieser Mailbox, die ebenfalls gelöscht werden.`;
      warnEl.classList.remove('d-none');
    } else {
      warnEl.classList.add('d-none');
    }
  }
  const modal = document.getElementById('mp-delete-modal');
  if (modal && typeof bootstrap !== 'undefined') {
    bootstrap.Modal.getOrCreate(modal).show();
  }
}

async function confirmDeleteMailbox() {
  const token = _deleteTarget;
  if (!token) return;

  const modal = document.getElementById('mp-delete-modal');
  if (modal && typeof bootstrap !== 'undefined') bootstrap.Modal.getInstance(modal)?.hide();

  try {
    const res = await fetch(`/api/mailboxes/${token}/delete`, { method: 'POST', cache: 'no-store' });
    if (!res.ok && res.status !== 404) throw new Error('Löschen fehlgeschlagen');
  } catch (_) {
    // Auch bei Fehler aus dem lokalen Verlauf entfernen
  }
  removeFromHistory(token);

  // Zeile animiert ausblenden
  const row = document.querySelector(`[data-token="${token}"].mp-prev-mb-item`);
  if (row) {
    row.style.transition = 'opacity .3s';
    row.style.opacity = '0';
    setTimeout(() => {
      row.remove();
      const list = document.getElementById('prev-mailboxes-list');
      if (list && list.children.length === 0) {
        document.getElementById('prev-mailboxes-section')?.classList.add('d-none');
      }
    }, 320);
  }
  _deleteTarget = null;
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

// Lösch-Bestätigung im Modal
document.getElementById('mp-delete-confirm-btn')?.addEventListener('click', confirmDeleteMailbox);
