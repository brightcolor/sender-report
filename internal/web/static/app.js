let mailboxPollTimer = null;
let mailboxEventSource = null;

// Merkt ob die aktuelle Mailbox-Adresse schon mindestens einmal kopiert wurde.
// Erst dann wird sie in der History (localStorage) gespeichert.
let _mbAddressCopied = false;

// ── Theme ─────────────────────────────────────────────────────────────────────

function resolveThemePreference(preference) {
  if (preference === 'dark' || preference === 'light') return preference;
  return window.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function applyThemePreference(preference) {
  const selected = preference || localStorage.getItem('sr:theme') || 'auto';
  const resolved = resolveThemePreference(selected);
  document.documentElement.dataset.bsTheme = resolved;
  document.documentElement.dataset.themePreference = selected;
  const btn  = document.getElementById('theme-toggle');
  const icon = btn?.querySelector('.theme-icon');
  if (icon) {
    // Ikon + Tooltip je nach aktivem Modus
    if (selected === 'dark') {
      icon.className = 'theme-icon bi bi-moon-fill';
      icon.textContent = '';
      if (btn) btn.title = 'Dunkles Theme aktiv – klicken für helles Theme';
    } else if (selected === 'light') {
      icon.className = 'theme-icon bi bi-sun-fill';
      icon.textContent = '';
      if (btn) btn.title = 'Helles Theme aktiv – klicken für System-Theme';
    } else {
      icon.className = 'theme-icon bi bi-circle-half';
      icon.textContent = '';
      if (btn) btn.title = 'System-Theme (' + (resolved === 'dark' ? 'dunkel' : 'hell') + ') – klicken für dunkles Theme';
    }
  }
}

function setupThemeToggle() {
  applyThemePreference(localStorage.getItem('sr:theme') || 'auto');
  document.getElementById('theme-toggle')?.addEventListener('click', () => {
    // Always flip to the opposite of the currently *visible* theme. So from the
    // default "auto" (resolved via the system) the very first click switches the
    // actually shown theme — e.g. system=dark → first click = light.
    const resolved = resolveThemePreference(localStorage.getItem('sr:theme') || 'auto');
    const next = resolved === 'dark' ? 'light' : 'dark';
    localStorage.setItem('sr:theme', next);
    applyThemePreference(next);
  });
  window.matchMedia?.('(prefers-color-scheme: dark)').addEventListener('change', () => {
    if ((localStorage.getItem('sr:theme') || 'auto') === 'auto') applyThemePreference('auto');
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

  // Erst nach dem ersten Kopieren in die History aufnehmen.
  if (ok && !_mbAddressCopied) {
    _mbAddressCopied = true;
    const token = document.getElementById('check-panel')?.dataset?.token;
    if (token) saveMbToHistory(token);
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

// ── Erweiterte Reputations-Checks (opt-in, Drittanbieter) ─────────────────────
// Die Auswahl wird lokal als Nutzer-Präferenz gespeichert und pro Mailbox an den
// Server übermittelt (POST /api/mailboxes/{token}/checks). Standard: alles aus.

const ADV_CHECKS_KEY = 'sr:advchecks';

function loadAdvChecks() {
  try {
    const o = JSON.parse(localStorage.getItem(ADV_CHECKS_KEY) || '{}');
    return { domain_age: !!o.domain_age, domain_blocklist: !!o.domain_blocklist, broken_links: !!o.broken_links };
  } catch (_) {
    return { domain_age: false, domain_blocklist: false, broken_links: false };
  }
}

function saveAdvChecks(prefs) {
  try { localStorage.setItem(ADV_CHECKS_KEY, JSON.stringify(prefs)); } catch (_) {}
}

function updateAdvChecksBadge() {
  const badge = document.getElementById('adv-checks-count');
  if (!badge) return;
  const prefs = loadAdvChecks();
  const n = (prefs.domain_age ? 1 : 0) + (prefs.domain_blocklist ? 1 : 0) + (prefs.broken_links ? 1 : 0);
  if (n > 0) { badge.textContent = String(n); badge.classList.remove('d-none'); }
  else       { badge.classList.add('d-none'); }
}

async function syncAdvChecks(token) {
  if (!token) return;
  const prefs = loadAdvChecks();
  try {
    await fetch(`/api/mailboxes/${token}/checks`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      cache: 'no-store',
      body: JSON.stringify({
        check_domain_age: prefs.domain_age,
        check_domain_blocklist: prefs.domain_blocklist,
        check_broken_links: prefs.broken_links,
      }),
    });
  } catch (_) { /* best effort */ }
}

// Apply the user's stored preference to a freshly ready mailbox. Only contacts
// the server when at least one check is enabled (new mailboxes default to off).
function applyAdvChecksOnReady(token) {
  updateAdvChecksBadge();
  const prefs = loadAdvChecks();
  if (prefs.domain_age || prefs.domain_blocklist || prefs.broken_links) {
    syncAdvChecks(token);
  }
}

function setupAdvChecksModal() {
  const modal = document.getElementById('mp-adv-checks-modal');
  if (!modal) return;
  const ageSw     = document.getElementById('adv-check-domain-age');
  const blSw      = document.getElementById('adv-check-domain-blocklist');
  const blinkSw   = document.getElementById('adv-check-broken-links');
  const saveBtn   = document.getElementById('mp-adv-checks-save');

  // Reflect stored prefs each time the modal opens.
  modal.addEventListener('show.bs.modal', () => {
    const prefs = loadAdvChecks();
    if (ageSw)   ageSw.checked   = prefs.domain_age;
    if (blSw)    blSw.checked    = prefs.domain_blocklist;
    if (blinkSw) blinkSw.checked = prefs.broken_links;
  });

  saveBtn?.addEventListener('click', async () => {
    const prefs = {
      domain_age:       !!ageSw?.checked,
      domain_blocklist: !!blSw?.checked,
      broken_links:     !!blinkSw?.checked,
    };
    saveAdvChecks(prefs);
    updateAdvChecksBadge();
    await syncAdvChecks(document.getElementById('check-panel')?.dataset?.token);
    if (typeof bootstrap !== 'undefined') bootstrap.Modal.getInstance(modal)?.hide();
    setTransientStatus(
      (prefs.domain_age || prefs.domain_blocklist || prefs.broken_links)
        ? 'Erweiterte Checks für diese Mailbox aktiviert.'
        : 'Erweiterte Checks deaktiviert.',
      'ok');
  });

  updateAdvChecksBadge();
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

// maskKey: zeige max. die erste Hälfte des Schlüssels + '…'
// Der Schlüssel darf niemals vollständig sichtbar sein.
function maskKey(key) {
  if (!key) return '—';
  const half = Math.ceil(key.length / 2);
  return key.slice(0, half) + '…';
}

// mbCopyShare: kopiert den echten Wert des Share-Felds (Home-Seite)
// und zeigt kurz visuelles Feedback.
function mbCopyShare(which) {
  const map    = { full: 'mb-share-full', nokey: 'mb-share-nokey', key: 'mb-share-key' };
  const boxMap = { full: 'mb-share-full-box', nokey: 'mb-share-nokey-box', key: 'mb-share-key-box' };
  const el  = document.getElementById(map[which]);
  const box = document.getElementById(boxMap[which]);
  if (!el) return;
  const val = el.dataset.val || '';
  if (!val) return;
  navigator.clipboard.writeText(val).then(() => {
    if (box) {
      box.classList.add('mp-share-copied');
      const hint = box.querySelector('.mp-addr-copy-hint');
      const prev = hint ? hint.innerHTML : '';
      if (hint) hint.innerHTML = '<i class="bi bi-check2 me-1"></i>Kopiert!';
      setTimeout(() => {
        if (box) box.classList.remove('mp-share-copied');
        if (hint) hint.innerHTML = prev;
      }, 1500);
    }
  }).catch(() => {});
}

function updateMailboxIdentity(data) {
  const panel    = document.getElementById('check-panel');
  const address  = document.getElementById('mail-address');
  const expires  = document.getElementById('mail-expires-at');
  const linkRow  = document.getElementById('mailbox-link-row');
  const statCard = document.getElementById('status-card');

  if (panel)   panel.dataset.token = data.token;
  if (address) address.textContent = data.address;
  if (expires) {
    expires.dataset.time = data.expires_at;
    expires.textContent  = formatExpiry(data.expires_at);
  }

  // Vollständiger Link inkl. Schlüssel (maskiert) – klickbar zum Kopieren
  if (linkRow) {
    // Immer absolute URL – Restore-Pfad liefert nur /mailbox/…, Create-Pfad die volle URL
    const rawUrl  = data.mailbox_url || '';
    const fullUrl = rawUrl.startsWith('http') ? rawUrl : location.origin + rawUrl;
    // Schlüssel-Anteil maskieren: URL bis # vollständig, Key nur erste Hälfte + …
    const hashIdx = fullUrl.indexOf('#');
    const displayUrl = hashIdx === -1
      ? fullUrl
      : fullUrl.slice(0, hashIdx + 1) + maskKey(fullUrl.slice(hashIdx + 1));

    const elFull = document.getElementById('mb-share-full');
    if (elFull) { elFull.textContent = displayUrl; elFull.dataset.val = fullUrl; }

    const box = document.getElementById('mb-share-full-box');
    if (box && !box.dataset.bound) {
      box.dataset.bound = '1';
      box.addEventListener('click', () => mbCopyShare('full'));
    }

    linkRow.classList.remove('d-none');
  }

  if (statCard) {
    statCard.dataset.token           = data.token;
    statCard.dataset.latestMessageId = '0';
  }
  sessionStorage.setItem(`sr:lastmsg:${data.token}`, '0');

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

  // Apply the user's advanced-check preference to this mailbox.
  applyAdvChecksOnReady(data.token);
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
    _mbAddressCopied = false;           // neue Mailbox → erst nach Kopieren speichern
    updateMailboxIdentity(data);
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

// ── Check loop (home page): wait for the mail, then open the report ──────────

let _animStarted = false; // guards against a double redirect

function _stopStepAnimation() {
  _animStarted = false;
  document.getElementById("check-steps")?.classList.add("d-none");
  document.querySelector(".mp-inbox-anim")?.classList.remove("d-none");
  const wait = document.getElementById("check-wait-msg");
  if (wait) { wait.classList.remove("d-none"); wait.innerHTML = "Warte auf eingehende E-Mail &hellip;"; }
}

// When the report is ready, briefly confirm receipt and open the report.
function handleCheckStatusEvent(data) {
  if (data.latest_report_path) {
    if (_animStarted) return;
    _animStarted = true;
    const href = withReportKey(data.latest_report_path);
    const wait = document.getElementById("check-wait-msg");
    if (wait) wait.innerHTML = "<i class=\"bi bi-check2-circle text-success me-1\"></i>Mail empfangen — Report wird geöffnet &hellip;";
    if (href) setTimeout(function(){ window.location.href = href; }, 500);
    return;
  }
  if (data.latest_message_id) {
    const wait = document.getElementById("check-wait-msg");
    if (wait && !_animStarted) wait.innerHTML = "Mail empfangen &ndash; Analyse läuft &hellip;";
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

  // SSE läuft bereits (setupMailboxPolling) → kein Interval nötig,
  // nur einmalig abfragen falls Mail schon angekommen ist.
  if (mailboxEventSource) {
    fetchMailboxStatus(token).then(handleCheckStatusEvent).catch(() => {});
    return;
  }

  // Fallback: Interval-Polling wenn kein SSE verfügbar
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
  const card  = document.getElementById('status-card');
  const panel = document.getElementById('check-panel');

  if (card) {
    // ── Mailbox-Seite: Reload wenn neue Nachricht ──────────────────────────
    const token    = card.dataset.token;
    const stateKey = `sr:lastmsg:${token}`;
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
    return;
  }

  if (panel) {
    // ── Startseite: SSE im Hintergrund, liefert Mail/Report-Events ─────────
    const token = panel.dataset.token;
    if (!token) return;
    if (typeof EventSource !== 'undefined') {
      startMailboxSSE(token, (data) => {
        // Nur weiterleiten wenn der User aktiv einen Check gestartet hat
        // (check-loader sichtbar = Check läuft). Verhindert automatische
        // Weiterleitung zu alten Reports beim Laden der Seite.
        const checkActive = !document.getElementById('check-loader')?.classList.contains('d-none');
        if (checkActive && (data.latest_message_id || data.latest_report_path)) {
          handleCheckStatusEvent(data);
        }
      });
    }
  }
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

// setGroupExpanded opens/closes a collapsible check-group card, keeping the
// toggle button's state (collapsed class + aria-expanded) in sync.
function setGroupExpanded(card, expanded) {
  const btn = card.querySelector('.mp-group-toggle');
  if (!btn) return;
  const sel = btn.getAttribute('data-bs-target');
  const panel = sel ? card.querySelector(sel) : null;
  if (!panel) return;
  if (typeof bootstrap !== 'undefined' && bootstrap.Collapse) {
    bootstrap.Collapse.getOrCreateInstance(panel, { toggle: false })[expanded ? 'show' : 'hide']();
  } else {
    panel.classList.toggle('show', expanded);
  }
  btn.classList.toggle('collapsed', !expanded);
  btn.setAttribute('aria-expanded', expanded ? 'true' : 'false');
}

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

    // Groups are collapsed by default. When a status filter is active, auto-expand
    // the still-visible groups so the matching checks are actually shown; collapse
    // everything again when returning to "Alle".
    document.querySelectorAll('.mp-group-card').forEach((card) => {
      if (card.classList.contains('d-none')) { setGroupExpanded(card, false); return; }
      setGroupExpanded(card, !showAll);
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
  try { return localStorage.getItem('sr:consent'); } catch (_) { return null; }
}

function saveMbToHistory(token) {
  if (!token || getConsentState() !== 'granted') return;
  try {
    const stored = JSON.parse(localStorage.getItem('sr:mailboxes') || '[]');
    const updated = [token, ...stored.filter((t) => t !== token)].slice(0, 12);
    localStorage.setItem('sr:mailboxes', JSON.stringify(updated));
  } catch (_) {}
}

function removeFromHistory(token) {
  try {
    const stored = JSON.parse(localStorage.getItem('sr:mailboxes') || '[]');
    localStorage.setItem('sr:mailboxes', JSON.stringify(stored.filter((t) => t !== token)));
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
  try { stored = JSON.parse(localStorage.getItem('sr:mailboxes') || '[]'); } catch (_) {}
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
    // Nur speichern wenn Adresse bereits kopiert wurde
    if (token && _mbAddressCopied) saveMbToHistory(token);
    loadPreviousMailboxes();
  }
}

// Called from HTML onclick – must be global
function consentAccept() {
  try { localStorage.setItem('sr:consent', 'granted'); } catch (_) {}
  document.getElementById('mp-consent-banner')?.classList.add('d-none');
  const token = document.getElementById('check-panel')?.dataset?.token;
  // Nur speichern wenn Adresse bereits kopiert wurde
  if (token && _mbAddressCopied) saveMbToHistory(token);
  loadPreviousMailboxes();
}

function consentDecline() {
  try { localStorage.setItem('sr:consent', 'declined'); } catch (_) {}
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
  // We look for the most recent identifier in sr:mailboxes whose
  // secret token is still stored and whose server-side mailbox is alive.
  const crypto = window.SenderReportCrypto;
  if (crypto) {
    try {
      const raw = localStorage.getItem('sr:mailboxes');
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
    _mbAddressCopied = false;           // erst nach Kopieren in History speichern
    updateMailboxIdentity(data);
    setupMailboxPolling();
  } catch (_) {
    setTransientStatus('Mailbox konnte nicht erstellt werden. Seite neu laden.', 'warn');
  }
}

// ── Boot ──────────────────────────────────────────────────────────────────────

setupThemeToggle();
setupCheckButton();
setupNewAddressButton();
setupAdvChecksModal();
setupCopyButtons();
localizeStaticTimes();
setupCheckFilter();
setupCookieConsent();
colorScoreDeltas();
colorScoreMinis();

// ── Stats-Leiste: Count-up + Live-Update ───────────────────────────────────────

function fmtStatNum(n) {
  if (typeof Intl !== 'undefined') return new Intl.NumberFormat('de-DE').format(n);
  return String(n);
}

// animateCount ramps an element's number from 0 to `to` with an ease-out curve.
function animateCount(el, to, decimals) {
  if (!el) return;
  decimals = decimals || 0;
  if (to <= 0) { el.textContent = decimals ? (0).toFixed(decimals) : '0'; return; }
  var dur = 900, t0 = (performance && performance.now) ? performance.now() : Date.now();
  function tick(now) {
    var p = Math.min(1, (now - t0) / dur);
    var eased = 1 - Math.pow(1 - p, 3);
    var val = to * eased;
    el.textContent = decimals ? val.toFixed(decimals) : fmtStatNum(Math.round(val));
    if (p < 1) requestAnimationFrame(tick);
    else el.textContent = decimals ? to.toFixed(decimals) : fmtStatNum(Math.round(to));
  }
  requestAnimationFrame(tick);
}

// initStatCountUp animates the server-rendered values up from zero once on load.
function initStatCountUp() {
  var bar = document.getElementById('mp-stats-bar');
  if (!bar || bar.classList.contains('d-none')) return;
  ['stat-messages', 'stat-mailboxes', 'stat-active'].forEach(function(id) {
    var el = document.getElementById(id);
    if (!el) return;
    var to = parseInt(String(el.textContent).replace(/[^0-9]/g, ''), 10) || 0;
    el.textContent = '0';
    animateCount(el, to, 0);
  });
  var sc = document.getElementById('stat-score');
  if (sc) { var to = parseFloat(sc.textContent) || 0; sc.textContent = '0.0'; animateCount(sc, to, 1); }
}

function setupStatsPolling() {
  if (!document.getElementById('mp-stats-bar')) return;

  function updateStat(id, val) {
    var el = document.getElementById(id);
    if (!el) return;
    var newVal = (id === 'stat-score') ? parseFloat(val).toFixed(1) : fmtStatNum(val);
    if (el.textContent === newVal) return;
    el.textContent = newVal;
    el.classList.add('mp-stat-updated');
    setTimeout(function() { el.classList.remove('mp-stat-updated'); }, 800);
  }

  function applyStats(d) {
    if (!d) return;
    // Reveal the bar the moment a fresh instance gets its first activity.
    var bar = document.getElementById('mp-stats-bar');
    if (bar && bar.classList.contains('d-none') &&
        (d.total_messages > 0 || d.total_mailboxes > 0 || d.total_reports > 0)) {
      bar.classList.remove('d-none');
    }
    updateStat('stat-messages',  d.total_messages);
    updateStat('stat-mailboxes', d.total_mailboxes);
    updateStat('stat-active',    d.active_mailboxes);
    if (d.total_reports > 0) updateStat('stat-score', d.avg_score);
  }

  function poll() {
    fetch('/api/stats', { cache: 'no-store' })
      .then(function(r) { return r.ok ? r.json() : null; })
      .then(applyStats)
      .catch(function() {});
  }

  var pollTimer = null;
  function startPollingFallback() {
    if (pollTimer) return;
    poll();
    pollTimer = setInterval(poll, 15000);
  }

  function start() {
    // Live updates via SSE; fall back to polling if unavailable or on error.
    if (typeof EventSource === 'undefined') { startPollingFallback(); return; }
    var es = new EventSource('/api/stats/events');
    es.addEventListener('stats', function(ev) {
      try { applyStats(JSON.parse(ev.data)); } catch (_) {}
    });
    es.addEventListener('error', function() {
      es.close();
      startPollingFallback();
    });
  }

  // Start after the count-up animation (~1s) so the initial ramp isn't cut short.
  setTimeout(start, 1300);
}

// Lösch-Bestätigung im Modal
document.getElementById('mp-delete-confirm-btn')?.addEventListener('click', confirmDeleteMailbox);

// Verlängern-Modal
setupExtendModal();

// Home page: async mailbox init (after DOM ready, crypto libs loaded).
if (document.getElementById('check-panel')) {
  initHomeMailbox();
  initStatCountUp();
  setupStatsPolling();
} else {
  setupMailboxPolling();
}
