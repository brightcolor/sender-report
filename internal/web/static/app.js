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

// ── Crypto token storage ──────────────────────────────────────────────────────

const SR_SECRET_PREFIX = 'sr:secret:';

function storeSecret(identifier, token) {
  // The decryption key is stored client-side only and never transmitted to the
  // server (it lives in the URL fragment + browser storage). It is the user's
  // own key for their own data, so no consent gate applies — without it the
  // user could not read their own encrypted mailbox. It is wiped on mailbox
  // delete / expiry (see removeSecret callers). Documented in /privacy §2.5.
  try { sessionStorage.setItem(SR_SECRET_PREFIX + identifier, token); } catch (_) {}
  try { localStorage.setItem(SR_SECRET_PREFIX + identifier, token); } catch (_) {}
}

function loadSecret(identifier) {
  try {
    return localStorage.getItem(SR_SECRET_PREFIX + identifier)
      || sessionStorage.getItem(SR_SECRET_PREFIX + identifier)
      || null;
  } catch (_) { return null; }
}

function removeSecret(identifier) {
  try { localStorage.removeItem(SR_SECRET_PREFIX + identifier); } catch (_) {}
  try { sessionStorage.removeItem(SR_SECRET_PREFIX + identifier); } catch (_) {}
}

// withReportKey appends the locally-stored decryption key as a URL fragment to a
// /report/{token}... path so the report auto-decrypts and the link stays
// shareable. Returns the path unchanged if no key is stored or it already has a
// fragment. The key never reaches the server (fragments are not sent in HTTP).
function withReportKey(reportPath) {
  if (!reportPath || reportPath.indexOf('#') !== -1) return reportPath;
  const m = reportPath.match(/\/report\/([^/?#]+)/);
  if (!m) return reportPath;
  const secret = loadSecret(m[1]);
  return secret ? reportPath + '#' + secret : reportPath;
}

// ── Mailbox creation (E2E crypto path) ───────────────────────────────────────

async function createMailboxWithCrypto() {
  const crypto = window.SenderReportCrypto;
  if (!crypto) throw new Error('SenderReportCrypto not loaded');
  const { token, public: pub, identifier } = await crypto.generateToken();
  const pubHex = crypto._bytesToHex(pub);
  const res = await fetch('/api/mailboxes', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    cache: 'no-store',
    body: JSON.stringify({ identifier, public_key: pubHex }),
  });
  if (!res.ok) throw new Error('mailbox create failed');
  const data = await res.json();
  storeSecret(identifier, token);
  // Append secret token to mailbox_url as a URL fragment so the link is shareable.
  // The fragment is never sent to the server — the key stays client-side.
  if (data.mailbox_url) data.mailbox_url = data.mailbox_url + '#' + token;
  data._secret_token = token;
  return data;
}

// ── URL-Fragment: read token from #hash on mailbox/report pages ───────────────
// When a user opens a shared link like /mailbox/{id}#secretToken, this function
// reads the fragment and stores the secret. The identifier is already in the URL
// path, so no async derivation is needed for the initial store.
//
// Security: never overwrites an existing key synchronously — this prevents an
// attacker from sending a crafted link (/report/{victim-id}#wrong-token) to
// destroy the victim's stored decryption key. If a key already exists, the
// fragment is only applied after async verification confirms it matches.
function readAndStoreTokenFromFragment() {
  const hash = (location.hash || '').slice(1); // strip leading #
  if (!hash) return;
  // Identifier is the last non-empty path segment: /mailbox/{id} or /report/{id}
  const segments = location.pathname.split('/').filter(Boolean);
  const identifier = segments[segments.length - 1];
  if (!identifier || identifier.length < 8) return;

  const hadExisting = !!loadSecret(identifier);

  if (!hadExisting) {
    // No key stored yet — safe to store optimistically.
    // Worst case: wrong key stored temporarily, removed by async verification;
    // user reopens original link to restore.
    storeSecret(identifier, hash);
  }

  // Async verification: confirm the fragment token actually belongs to this mailbox.
  if (window.SenderReportCrypto) {
    window.SenderReportCrypto.fromToken(hash).then(function(info) {
      if (info.identifier === identifier) {
        // Valid token for this mailbox — persist and clean fragment from history.
        storeSecret(identifier, hash);
        if (location.hash) {
          history.replaceState(null, '', location.pathname + location.search);
        }
      } else if (!hadExisting) {
        // Wrong identifier — remove what we optimistically stored, put under real id.
        removeSecret(identifier);
        storeSecret(info.identifier, hash);
      }
      // If hadExisting and wrong identifier: touch nothing — preserve user's key.
    }).catch(function() {
      if (!hadExisting) {
        removeSecret(identifier); // invalid token, remove what we stored
      }
      // If hadExisting: preserve the existing key.
    });
  }
}

async function createMailbox() {
  // Use E2E crypto path if available, otherwise fall back.
  if (window.SenderReportCrypto) {
    return createMailboxWithCrypto();
  }
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

  // Phase 2: reveal main content, hide loading spinner.
  const loader  = document.getElementById('mb-init-loader');
  const content = document.getElementById('mb-main-content');
  if (loader)  loader.classList.add('d-none');
  if (content) content.classList.remove('d-none');

  // Show E2E badge + footer hint if this is an encrypted mailbox.
  if (data.encrypted) {
    document.getElementById('mp-e2e-badge')?.classList.remove('d-none');
    document.getElementById('mp-e2e-footer')?.classList.remove('d-none');
  }
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
    statusText.innerHTML = `Analyse abgeschlossen (Score: <strong>${data.latest_score}/10</strong>). <a href="${withReportKey(data.latest_report_path)}">Report öffnen →</a>`;
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

let _stepTimer      = null;
let _stepIdx        = 0;
let _animStarted    = false;
let _pendingHref    = null;
let _reportChecks   = null;

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

// Render steps 0..upTo; completed steps (< upTo) show real status,
// current step (= upTo) shows the spinning indicator.
function _renderSteps(upTo, checks) {
  const el = document.getElementById('check-steps');
  if (!el) return;
  el.innerHTML = ANALYSIS_STEPS.slice(0, upTo + 1).map((s, i) => {
    if (i < upTo) {
      // Already processed — show real result
      const status = _worstStatus(checks, s.matchIds) || 'pass';
      return `<div class="${_statusClass(status)}">${_statusIcon(status)}<span>${s.label}</span></div>`;
    }
    // Currently active
    return `<div class="mp-check-step active">
      <span class="spinner-border spinner-border-sm text-primary mp-step-spin" role="status"></span>
      <span>${s.label} …</span>
    </div>`;
  }).join('');
  el.lastElementChild?.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
}

function _stepDelay() {
  return Math.floor(Math.random() * 440) + 380;
}

function _startStepAnimation(checks) {
  _stepIdx     = 0;
  _animStarted = true;
  _renderSteps(0, checks);

  function scheduleNext() {
    _stepTimer = setTimeout(() => {
      _stepIdx++;
      if (_stepIdx >= ANALYSIS_STEPS.length) {
        // All steps done — show real result for last step, then navigate
        _stepTimer = null;
        const el = document.getElementById('check-steps');
        if (el) {
          const last = ANALYSIS_STEPS[ANALYSIS_STEPS.length - 1];
          const status = _worstStatus(checks, last.matchIds) || 'pass';
          el.lastElementChild.className = _statusClass(status);
          el.lastElementChild.innerHTML = `${_statusIcon(status)}<span>${last.label}</span>`;
        }
        setTimeout(() => { if (_pendingHref) window.location.href = _pendingHref; }, 900);
        return;
      }
      _renderSteps(_stepIdx, checks);
      scheduleNext();
    }, _stepDelay());
  }
  scheduleNext();
}

function _stopStepAnimation() {
  if (_stepTimer) { clearTimeout(_stepTimer); _stepTimer = null; }
  _animStarted = false; _pendingHref = null; _reportChecks = null;
  const el = document.getElementById('check-steps');
  if (el) el.innerHTML = '';
}

function handleCheckStatusEvent(data) {
  if (data.latest_report_path) {
    // Report ready — fetch real check data, then start animation (once)
    if (!_animStarted) {
      _pendingHref = withReportKey(data.latest_report_path);
      _fetchReportChecks(data.latest_report_path).then(() => {
        document.getElementById('check-wait-msg')?.classList.add('d-none');
        document.getElementById('check-steps')?.classList.remove('d-none');
        _startStepAnimation(_reportChecks || []);
      });
    }
    return;
  }
  if (data.latest_message_id) {
    // Mail empfangen, Report noch nicht fertig — Hinweis aktualisieren
    const waitMsg = document.getElementById('check-wait-msg');
    if (waitMsg && !_animStarted) {
      waitMsg.innerHTML = 'Mail empfangen &ndash; Analyse läuft &hellip;';
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
      if (data.latest_report_path && _animStarted) {
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
  // Guard against double-binding: setupCheckFilter runs at boot AND again after
  // client-side decryption. Without this guard the click handler is attached
  // twice and each click toggles the button on then off again (no net effect).
  if (bar.dataset.filterBound === '1') return;
  bar.dataset.filterBound = '1';

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

    // Hide group cards whose every item is now hidden. Match both the
    // server-rendered accordion (.mp-check-accordion) and the client-side
    // decrypted one (.accordion-flush inside a card with mp-check-items).
    document.querySelectorAll('.card').forEach((card) => {
      const items = card.querySelectorAll('.mp-check-item');
      if (items.length === 0) return;
      const visibleItems = card.querySelectorAll('.mp-check-item:not(.mp-filter-hidden)');
      card.classList.toggle('d-none', visibleItems.length === 0);
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
      removeSecret(others[i]);     // zugehörigen Schlüssel ebenfalls bereinigen
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
      ? `<a href="${withReportKey(data.latest_report_path)}" class="btn btn-sm btn-primary py-0 px-2">Report</a>`
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
    bootstrap.Modal.getOrCreateInstance(modal).show();
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
  removeSecret(token); // also wipe decryption key — mailbox is gone

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

// ── Mailbox extend ────────────────────────────────────────────────────────────

function setupExtendModal() {
  const btn = document.querySelector('.mp-extend-btn');
  if (!btn) return;

  const token    = btn.dataset.token;
  const maxDays  = parseInt(btn.dataset.maxDays, 10) || 7;
  const created  = new Date(btn.dataset.created);
  const expires  = new Date(btn.dataset.expires);
  const now      = new Date();

  const slider   = document.getElementById('mp-extend-slider');
  const datePick = document.getElementById('mp-extend-date');
  const label    = document.getElementById('mp-extend-days-label');
  const info     = document.getElementById('mp-extend-info');
  const tooEarly = document.getElementById('mp-extend-too-early');
  const earlyMsg = document.getElementById('mp-extend-earliest-msg');
  const confirmB = document.getElementById('mp-extend-confirm-btn');

  if (!slider || !datePick) return;

  // Cap slider to maxDays
  slider.max = String(maxDays);

  // Check if we're past the half-lifetime point
  const lifetime   = expires - created;
  const halfPoint  = new Date(created.getTime() + lifetime / 2);
  const tooEarlyNow = now < halfPoint;

  // Helpers
  function toLocalDatetimeValue(d) {
    // datetime-local needs "YYYY-MM-DDTHH:MM" in local time
    const pad = (n) => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}` +
           `T${pad(d.getHours())}:${pad(d.getMinutes())}`;
  }

  function daysFromNow(d) {
    return Math.round((d - now) / 86400000);
  }

  function updateFromSlider() {
    const days = parseInt(slider.value, 10);
    const target = new Date(now.getTime() + days * 86400000);
    datePick.value = toLocalDatetimeValue(target);
    label.textContent = `${days} Tag${days !== 1 ? 'e' : ''}`;
    updateInfo(target);
  }

  function updateFromDate() {
    const target = new Date(datePick.value);
    if (isNaN(target)) return;
    const days = Math.max(1, Math.min(maxDays, daysFromNow(target)));
    slider.value = String(days);
    label.textContent = `${days} Tag${days !== 1 ? 'e' : ''}`;
    updateInfo(target);
  }

  function updateInfo(target) {
    const fmt = target.toLocaleString('de-DE', {
      day:'2-digit', month:'2-digit', year:'numeric',
      hour:'2-digit', minute:'2-digit'
    });
    if (info) info.textContent = `Neue Ablaufzeit: ${fmt}`;
  }

  // Set min/max for date picker
  const minDate = new Date(now.getTime() + 3600000); // at least 1 h from now
  const maxDate = new Date(now.getTime() + maxDays * 86400000);
  datePick.min = toLocalDatetimeValue(minDate);
  datePick.max = toLocalDatetimeValue(maxDate);

  // Initial value: half the max extend
  slider.value = String(Math.ceil(maxDays / 2));
  updateFromSlider();

  slider.addEventListener('input', updateFromSlider);
  datePick.addEventListener('input', updateFromDate);

  btn.addEventListener('click', () => {
    // Show/hide too-early warning
    if (tooEarly && earlyMsg) {
      if (tooEarlyNow) {
        const fmt = halfPoint.toLocaleString('de-DE', {
          day:'2-digit', month:'2-digit', year:'numeric',
          hour:'2-digit', minute:'2-digit'
        });
        earlyMsg.textContent = `Verlängerung ist erst ab ${fmt} möglich (nach der Hälfte der aktuellen Laufzeit).`;
        tooEarly.classList.remove('d-none');
        if (confirmB) confirmB.disabled = true;
      } else {
        tooEarly.classList.add('d-none');
        if (confirmB) confirmB.disabled = false;
      }
    }
    bootstrap.Modal.getOrCreateInstance(document.getElementById('mp-extend-modal')).show();
  });

  if (confirmB) {
    confirmB.addEventListener('click', async () => {
      const target = new Date(datePick.value);
      if (isNaN(target) || target <= now) return;
      confirmB.disabled = true;
      try {
        const res = await fetch(`/api/mailboxes/${token}/extend`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ expires_at: target.toISOString() }),
          cache: 'no-store',
        });
        const data = await res.json();
        if (!res.ok) {
          alert(data.error || 'Verlängerung fehlgeschlagen.');
          confirmB.disabled = false;
          return;
        }
        // Update the displayed expiry time and close modal
        const newExpiry = new Date(data.expires_at);
        const fmt = newExpiry.toLocaleString('de-DE', {
          day:'2-digit', month:'2-digit', year:'numeric',
          hour:'2-digit', minute:'2-digit', timeZoneName:'short'
        });
        document.querySelectorAll('[data-time]').forEach((el) => {
          el.dataset.time = data.expires_at;
          el.textContent  = fmt;
        });
        btn.dataset.expires = data.expires_at;
        bootstrap.Modal.getInstance(document.getElementById('mp-extend-modal'))?.hide();
        setTransientStatus('Gültigkeit verlängert bis ' + fmt, 'ok');
      } catch (_) {
        alert('Netzwerkfehler – bitte erneut versuchen.');
        confirmB.disabled = false;
      }
    });
  }
}

// ── Home page: client-side mailbox initialisation (Phase 2) ──────────────────

async function initHomeMailbox() {
  const panel = document.getElementById('check-panel');
  if (!panel) return; // not on home page

  // Run crypto self-test in background (logs to console).
  window.SenderReportCrypto?.cryptoSelfTest().catch(() => {});

  // Try to restore an existing mailbox from localStorage.
  // We look for the most recent identifier in mailprobe:mailboxes whose
  // secret token is still stored and whose server-side mailbox is alive.
  const crypto = window.SenderReportCrypto;
  if (crypto) {
    try {
      const raw = localStorage.getItem('mailprobe:mailboxes');
      const history = raw ? JSON.parse(raw) : [];
      for (const entry of history.slice(0, 5)) {
        const identifier = typeof entry === 'string' ? entry : entry?.token;
        if (!identifier) continue;
        const secret = loadSecret(identifier);
        if (!secret) continue;
        try {
          const res = await fetch(`/api/mailboxes/${identifier}/status`, { cache: 'no-store' });
          if (!res.ok) { removeSecret(identifier); continue; }
          const status = await res.json();
          if (status.expired) { removeSecret(identifier); continue; }
          // Mailbox is alive — restore identity including shareable fragment URL.
          const addr = identifier + '@' + (panel.dataset.domain || location.hostname);
          updateMailboxIdentity({
            token: identifier,
            address: status.address || addr,
            expires_at: status.expires_at,
            mailbox_url: `/mailbox/${identifier}#${secret}`,
            status_path: `/api/mailboxes/${identifier}/status`,
            events_path: `/api/mailboxes/${identifier}/events`,
            encrypted: true,
          });
          setupMailboxPolling();
          return;
        } catch (_) { continue; }
      }
    } catch (_) {}
  }

  // No restorable mailbox found — create a fresh one.
  try {
    const data = await createMailbox();
    updateMailboxIdentity(data);
    saveMbToHistory(data.token);
    setupMailboxPolling();
  } catch (_) {
    setTransientStatus('Mailbox konnte nicht erstellt werden. Seite neu laden.', 'warn');
  }
}

// ── Boot ──────────────────────────────────────────────────────────────────────

setupThemeToggle();
setupCheckButton();
setupNewAddressButton();
setupCopyButtons();
localizeStaticTimes();
setupCheckFilter();
setupCookieConsent();
colorScoreDeltas();
colorScoreMinis();

// Lösch-Bestätigung im Modal
document.getElementById('mp-delete-confirm-btn')?.addEventListener('click', confirmDeleteMailbox);

// Verlängern-Modal
setupExtendModal();

// Home page: async mailbox init (after DOM ready, crypto libs loaded).
if (document.getElementById('check-panel')) {
  initHomeMailbox();
} else {
  setupMailboxPolling();
}
