/**
 * Client-side PDF generation for sender.report
 *
 * Renders a high-quality, client-facing PDF that mirrors the web report
 * (light mode). Uses jsPDF only (no autoTable) for full layout control:
 * score ring, tinted status pills, info cards, group headers, fix boxes.
 *
 * jsPDF standard Helvetica uses WinAnsi encoding, so German umlauts
 * (ä ö ü ß) render natively. Typographic symbols outside WinAnsi
 * (em dash, arrows, check marks) are sanitised in clean().
 *
 * Entry point: window.mpGeneratePDF(opts)
 *   opts: { pass, warn, fail, info, hero, meta, details }  (booleans)
 * Data source: window.__mpReport  (set by report.html, updated after E2E decrypt)
 */
(function () {
  'use strict';

  // ── Geometry (mm, A4 portrait) ────────────────────────────────────────────────
  var PAGE_W = 210, PAGE_H = 297;
  var MARGIN = 14;
  var CW = PAGE_W - 2 * MARGIN;   // 182 content width
  var X0 = MARGIN;                // left content edge
  var PAGE_BOTTOM = 280;          // content must end before footer
  var TOP_CONT = 16;              // top Y on continuation pages

  // ── Bootstrap 5 light palette ─────────────────────────────────────────────────
  var COL = {
    primary: [13, 110, 253],
    success: [25, 135, 84],
    warning: [253, 126, 20],   // orange (readable on light; matches print sheet)
    danger:  [220, 53, 69],
    info:    [13, 202, 240],
    gray:    [108, 117, 125],
    dark:    [33, 37, 41],
    body:    [73, 80, 87],
    border:  [222, 226, 230],
    track:   [233, 236, 239],   // bs-secondary-bg (ring track)
    white:   [255, 255, 255],
  };

  function statusColor(s) {
    return COL[{pass:'success',warn:'warning',fail:'danger',info:'info'}[s]] || COL.gray;
  }
  function statusGlyph(s) {
    return {pass:'OK', warn:'!', fail:'X', info:'i'}[s] || '-';
  }
  function statusWord(s) {
    return {pass:'Bestanden', warn:'Warnung', fail:'Fehler', info:'Info'}[s] || s;
  }
  function scoreColor(v) {
    return v >= 7.5 ? COL.success : v >= 5.5 ? COL.warning : COL.danger;
  }

  // rgba(color, alpha) composited over white — mirrors the web's tinted look.
  function tint(c, a) {
    return [Math.round(255 + (c[0]-255)*a),
            Math.round(255 + (c[1]-255)*a),
            Math.round(255 + (c[2]-255)*a)];
  }

  // Sanitise text for jsPDF WinAnsi: keep umlauts/Latin-1, replace symbols >0xFF.
  function clean(s) {
    if (s == null) return '';
    var map = {
      '–':'-', '—':'-',        // – —
      '‘':"'", '’':"'",        // ' '
      '“':'"', '”':'"',        // " "
      '…':'...', '•':'-',      // … •
      '→':'->', '←':'<-',      // → ←
      '⇒':'=>',                      // ⇒
      '✓':'OK', '✔':'OK',      // ✓ ✔
      '✗':'x', '✘':'x',        // ✗ ✘
      '⚠':'!', '✅':'OK',       // ⚠ ✅
      ' ':' ',                      // nbsp
    };
    var out = '';
    for (var i = 0; i < s.length; i++) {
      var ch = s[i], cp = s.charCodeAt(i);
      if (map[ch] !== undefined) { out += map[ch]; continue; }
      if (cp <= 0xFF) { out += ch; continue; }   // WinAnsi-safe Latin-1
      // drop other non-WinAnsi codepoints
    }
    return out;
  }

  // ── Low-level draw helpers ────────────────────────────────────────────────────
  function fill(doc, c)  { doc.setFillColor(c[0], c[1], c[2]); }
  function stroke(doc, c){ doc.setDrawColor(c[0], c[1], c[2]); }
  function ink(doc, c)   { doc.setTextColor(c[0], c[1], c[2]); }
  function font(doc, style, size) { doc.setFont('helvetica', style); doc.setFontSize(size); }

  // Filled pie sector — polygon approximation of an arc (for the score ring).
  function fillSector(doc, cx, cy, r, a0, a1, c) {
    var steps = Math.max(2, Math.ceil(Math.abs(a1 - a0) / 4));
    var verts = [[cx, cy]];
    for (var i = 0; i <= steps; i++) {
      var a = (a0 + (a1 - a0) * i / steps) * Math.PI / 180;
      verts.push([cx + r * Math.cos(a), cy + r * Math.sin(a)]);
    }
    var rel = [];
    for (var j = 1; j < verts.length; j++) {
      rel.push([verts[j][0]-verts[j-1][0], verts[j][1]-verts[j-1][1]]);
    }
    fill(doc, c);
    doc.lines(rel, verts[0][0], verts[0][1], [1, 1], 'F', true);
  }

  // Donut progress ring with centred score text.
  function drawRing(doc, cx, cy, R, thick, score) {
    var pct = Math.max(0, Math.min(1, score / 10));
    var c = scoreColor(score);
    // track
    fill(doc, COL.track);
    doc.circle(cx, cy, R, 'F');
    // progress arc (from top, clockwise)
    if (pct > 0) fillSector(doc, cx, cy, R, -90, -90 + pct * 360, c);
    // inner white → donut
    fill(doc, COL.white);
    doc.circle(cx, cy, R - thick, 'F');
    // score value
    font(doc, 'bold', 22); ink(doc, c);
    doc.text(score.toFixed(1), cx, cy + 1.5, {align:'center'});
    font(doc, 'normal', 7); ink(doc, COL.gray);
    doc.text('/ 10', cx, cy + 6.5, {align:'center'});
  }

  // Tinted pill (status chip). Returns its width.
  function pill(doc, x, y, text, c, h) {
    h = h || 5.2;
    font(doc, 'bold', 7);
    var tw = doc.getTextWidth(text);
    var w = tw + 6;
    fill(doc, tint(c, 0.10));
    stroke(doc, tint(c, 0.30));
    doc.setLineWidth(0.2);
    doc.roundedRect(x, y, w, h, h/2, h/2, 'FD');
    ink(doc, c);
    doc.text(text, x + w/2, y + h/2 + 1.1, {align:'center'});
    return w;
  }

  function truncate(doc, text, maxW) {
    if (doc.getTextWidth(text) <= maxW) return text;
    while (text.length > 1 && doc.getTextWidth(text + '...') > maxW) text = text.slice(0, -1);
    return text + '...';
  }

  // ── Header (page 1 only) ───────────────────────────────────────────────────────
  function drawHeader(doc, data) {
    var barH = 24, stripH = 9;

    fill(doc, COL.primary);
    doc.rect(0, 0, PAGE_W, barH, 'F');

    // Logo: white rounded square + envelope + green check
    fill(doc, COL.white);
    doc.roundedRect(MARGIN, 6, 12, 12, 1.6, 1.6, 'F');
    fill(doc, COL.primary);
    doc.rect(MARGIN + 1.6, 8.4, 8.8, 6, 'F');
    stroke(doc, COL.white); doc.setLineWidth(0.5);
    doc.line(MARGIN + 1.6, 8.9, MARGIN + 6, 12.2);
    doc.line(MARGIN + 6, 12.2, MARGIN + 10.4, 8.9);
    fill(doc, COL.success);
    doc.circle(MARGIN + 11, 17, 2.9, 'F');
    font(doc, 'bold', 6); ink(doc, COL.white);
    doc.text('OK', MARGIN + 11, 18, {align:'center'});

    // Wordmark
    font(doc, 'bold', 13); ink(doc, COL.white);
    doc.text(clean(data.appName || 'sender.report'), MARGIN + 16, 15);
    font(doc, 'normal', 8.5);
    doc.text('DELIVERABILITY REPORT', PAGE_W - MARGIN, 15, {align:'right'});

    // Info strip
    fill(doc, [248, 249, 250]);
    doc.rect(0, barH, PAGE_W, stripH, 'F');
    stroke(doc, COL.border); doc.setLineWidth(0.2);
    doc.line(0, barH + stripH, PAGE_W, barH + stripH);

    font(doc, 'normal', 8); ink(doc, COL.body);
    var addr  = data.mailbox ? data.mailbox.address : '';
    var when  = data.generatedAt ? new Date(data.generatedAt) : new Date();
    var whenS = when.toLocaleString('de-DE', {dateStyle:'medium', timeStyle:'short'});
    doc.text(clean('Mailbox: ' + addr), MARGIN, barH + 5.8);
    doc.text(clean('Erstellt: ' + whenS), PAGE_W - MARGIN, barH + 5.8, {align:'right'});

    return barH + stripH + 6;
  }

  // ── Score hero card (mirrors .mp-score-hero) ───────────────────────────────────
  function drawHero(doc, data, y) {
    var c = scoreColor(data.score);
    var cardH = 48;
    var ringCx = X0 + 26, ringCy = y + cardH/2, ringR = 17;

    // Card: white, rounded, subtle border, coloured left accent
    fill(doc, COL.white);
    doc.roundedRect(X0, y, CW, cardH, 2.5, 2.5, 'F');
    fill(doc, c);
    doc.rect(X0, y + 2.5, 3, cardH - 5, 'F');           // left accent body
    doc.roundedRect(X0, y, 3.5, cardH, 2.5, 2.5, 'F');  // rounded accent cap
    stroke(doc, COL.border); doc.setLineWidth(0.25);
    doc.roundedRect(X0, y, CW, cardH, 2.5, 2.5, 'S');

    // Ring
    drawRing(doc, ringCx, ringCy, ringR, 4, data.score);

    // Text block
    var tx = ringCx + ringR + 8;
    var tw = X0 + CW - tx - 8;
    var ty = y + 11;

    font(doc, 'bold', 7); ink(doc, COL.gray);
    doc.text('GESAMTSCORE', tx, ty);

    font(doc, 'bold', 17); ink(doc, COL.dark);
    doc.text(clean(data.scoreLabel || ''), tx, ty + 8);

    if (data.heroSubtitle) {
      font(doc, 'normal', 8.5); ink(doc, COL.body);
      var subLines = doc.splitTextToSize(clean(data.heroSubtitle), tw).slice(0, 2);
      var sy = ty + 14;
      subLines.forEach(function(ln) { doc.text(ln, tx, sy); sy += 4.2; });
    }

    // Count pills
    var counts = {pass:0, warn:0, fail:0, info:0};
    (data.groups || []).forEach(function(g) {
      (g.checks || []).forEach(function(ch) {
        if (counts[ch.status] !== undefined) counts[ch.status]++;
      });
    });
    var pills = [
      ['pass', counts.pass + ' bestanden'],
      ['warn', counts.warn + ' Warnungen'],
      ['fail', counts.fail + ' Fehler'],
      ['info', counts.info + ' Infos'],
    ];
    var px = tx, py = y + cardH - 10;
    pills.forEach(function(p) {
      var w = pill(doc, px, py, p[1], statusColor(p[0]));
      px += w + 3;
    });

    return y + cardH + 6;
  }

  // ── Metadata cards (2×2, mirrors .info-box) ────────────────────────────────────
  function drawMeta(doc, data, y) {
    var msg = data.message || {};
    function val(v) { return (!v || v === '[encrypted]') ? '(Ende-zu-Ende verschlüsselt)' : v; }
    var received = '';
    if (msg.receivedAt && msg.receivedAt !== '0001-01-01T00:00:00Z') {
      try { received = new Date(msg.receivedAt).toLocaleString('de-DE', {dateStyle:'medium', timeStyle:'medium'}); }
      catch(e) { received = msg.receivedAt; }
    }
    var items = [
      ['Betreff',          val(msg.subject)],
      ['Empfangen',        received || '(Ende-zu-Ende verschlüsselt)'],
      ['Envelope-From',    val(msg.smtpFrom)],
      ['Quelle (IP / HELO)', (msg.remoteIP && msg.remoteIP !== '[encrypted]')
          ? msg.remoteIP + (msg.helo && msg.helo !== '[encrypted]' ? '  /  ' + msg.helo : '')
          : '(Ende-zu-Ende verschlüsselt)'],
    ];

    var gap = 4, cellW = (CW - gap) / 2, cellH = 15;
    items.forEach(function(it, i) {
      var col = i % 2, row = (i / 2) | 0;
      var ix = X0 + col * (cellW + gap);
      var iy = y + row * (cellH + gap);

      fill(doc, COL.white);
      stroke(doc, COL.border); doc.setLineWidth(0.25);
      doc.roundedRect(ix, iy, cellW, cellH, 2, 2, 'FD');
      // primary left accent
      fill(doc, COL.primary);
      doc.roundedRect(ix, iy + 2, 2.5, cellH - 4, 1, 1, 'F');

      font(doc, 'bold', 6.5); ink(doc, COL.gray);
      doc.text(clean(it[0].toUpperCase()), ix + 6, iy + 5.5);

      font(doc, 'bold', 9); ink(doc, COL.dark);
      doc.text(truncate(doc, clean(it[1]), cellW - 10), ix + 6, iy + 11);
    });

    return y + 2 * cellH + gap + 6;
  }

  // ── Group header (mirrors .mp-group-header) ────────────────────────────────────
  function drawGroupHeader(doc, name, counts, y, cont) {
    var h = cont ? 8 : 11;
    fill(doc, tint(COL.primary, 0.06));
    doc.rect(X0, y, CW, h, 'F');
    // bottom border (2px tinted primary)
    stroke(doc, tint(COL.primary, 0.35)); doc.setLineWidth(0.5);
    doc.line(X0, y + h, X0 + CW, y + h);
    // solid primary accent bar before title
    fill(doc, COL.primary);
    doc.roundedRect(X0 + 4, y + (h-5.5)/2, 1.6, 5.5, 0.6, 0.6, 'F');

    font(doc, 'bold', cont ? 9 : 11); ink(doc, COL.dark);
    var title = clean(name) + (cont ? '  (Forts.)' : '');
    doc.text(title, X0 + 8, y + (cont ? 5.4 : 7.2));

    // count badges right-aligned
    if (counts) {
      var defs = [['pass', counts.pass], ['warn', counts.warn], ['fail', counts.fail], ['info', counts.info]];
      var bx = X0 + CW - 2;
      for (var i = defs.length - 1; i >= 0; i--) {
        if (!defs[i][1]) continue;
        var c = statusColor(defs[i][0]);
        var txt = defs[i][1] + ' ' + statusGlyph(defs[i][0]);
        font(doc, 'bold', 6.8);
        var w = doc.getTextWidth(txt) + 5;
        bx -= w;
        fill(doc, tint(c, 0.12));
        doc.roundedRect(bx, y + (h-5)/2, w, 5, 2.2, 2.2, 'F');
        ink(doc, c);
        doc.text(txt, bx + w/2, y + h/2 + 1.1, {align:'center'});
        bx -= 2;
      }
    }
    return y + h + 3;
  }

  // ── Measure a single check block height ────────────────────────────────────────
  function measureCheck(doc, chk, opts, textW) {
    var h = 2.5; // top pad
    h += 5;      // name row
    font(doc, 'normal', 8);
    var summ = clean(chk.summary || '');
    if (!summ.trim()) summ = '(Inhalt Ende-zu-Ende verschlüsselt)';
    h += doc.splitTextToSize(summ, textW).length * 4.0;

    if (opts.details && chk.explanation && chk.explanation.trim()) {
      h += 4.5; // ERKLÄRUNG label
      font(doc, 'normal', 8.5);
      h += doc.splitTextToSize(clean(chk.explanation), textW).length * 4.3;
      h += 1.5;
    }
    if (opts.details && chk.recommendation && chk.recommendation.trim() &&
        (chk.status === 'warn' || chk.status === 'fail')) {
      h += 2.5;  // gap before box
      h += 3;    // box top pad
      h += 5;    // "Empfehlung" heading
      font(doc, 'normal', 8.5);
      h += doc.splitTextToSize(clean(chk.recommendation), textW - 6).length * 4.3;
      h += 3;    // box bottom pad
    }
    h += 3.5; // bottom pad + separator gap
    return h;
  }

  // ── Draw a single check block, returns new y ───────────────────────────────────
  function drawCheck(doc, chk, y) {
    var c = statusColor(chk.status);
    var dotX = X0 + 1.5, dotY = y + 2, dotS = 7;
    var textX = X0 + 12;

    // Right cluster: pill + delta on the name line
    var deltaNum = Number(chk.score_delta || 0);
    var deltaStr = (deltaNum > 0 ? '+' : '') + deltaNum.toFixed(1);
    font(doc, 'bold', 8);
    var deltaW = doc.getTextWidth(deltaStr);
    font(doc, 'bold', 7);
    var pillTxt = statusWord(chk.status);
    var pillW = doc.getTextWidth(pillTxt) + 6;
    var rightEdge = X0 + CW;
    var pillX = rightEdge - pillW;
    var deltaX = pillX - deltaW - 4;
    var nameMaxW = deltaX - textX - 3;
    var textW = CW - 12 - 2;

    // Status dot (rounded square, tinted)
    fill(doc, tint(c, 0.12));
    doc.roundedRect(dotX, dotY, dotS, dotS, 1.6, 1.6, 'F');
    font(doc, 'bold', chk.status === 'pass' ? 6.5 : 7.5); ink(doc, c);
    doc.text(statusGlyph(chk.status), dotX + dotS/2, dotY + dotS/2 + 1.2, {align:'center'});

    // Name
    font(doc, 'bold', 9.5); ink(doc, COL.dark);
    doc.text(truncate(doc, clean(chk.name || ''), nameMaxW), textX, y + 4.2);

    // Pill
    pill(doc, pillX, y + 0.6, pillTxt, c);

    // Delta
    font(doc, 'bold', 8);
    ink(doc, deltaNum > 0 ? COL.success : (deltaNum < 0 ? COL.danger : COL.gray));
    doc.text(deltaStr, deltaX + deltaW, y + 4.2, {align:'right'});

    var cur = y + 7;

    // Summary
    var summ = clean(chk.summary || '');
    if (!summ.trim()) summ = '(Inhalt Ende-zu-Ende verschlüsselt)';
    font(doc, 'normal', 8); ink(doc, COL.body);
    doc.splitTextToSize(summ, textW).forEach(function(ln) {
      doc.text(ln, textX, cur); cur += 4.0;
    });

    // Explanation
    if (window.__pdfDetails && chk.explanation && chk.explanation.trim()) {
      cur += 1.5;
      font(doc, 'bold', 6.5); ink(doc, COL.gray);
      doc.text('ERKLÄRUNG', textX, cur); cur += 4.5;
      font(doc, 'normal', 8.5); ink(doc, COL.dark);
      doc.splitTextToSize(clean(chk.explanation), textW).forEach(function(ln) {
        doc.text(ln, textX, cur); cur += 4.3;
      });
    }

    // Recommendation (green fix-box, mirrors .mp-fix-box)
    if (window.__pdfDetails && chk.recommendation && chk.recommendation.trim() &&
        (chk.status === 'warn' || chk.status === 'fail')) {
      cur += 2.5;
      font(doc, 'normal', 8.5);
      var recoLines = doc.splitTextToSize(clean(chk.recommendation), textW - 6);
      var boxH = 3 + 5 + recoLines.length * 4.3 + 3;
      var boxY = cur;
      fill(doc, tint(COL.success, 0.08));
      stroke(doc, tint(COL.success, 0.25)); doc.setLineWidth(0.25);
      doc.roundedRect(textX, boxY, textW, boxH, 2, 2, 'FD');
      font(doc, 'bold', 7.5); ink(doc, COL.success);
      doc.text('EMPFEHLUNG', textX + 3, boxY + 4.5);
      font(doc, 'normal', 8.5); ink(doc, COL.dark);
      var ry = boxY + 9;
      recoLines.forEach(function(ln) { doc.text(ln, textX + 3, ry); ry += 4.3; });
      cur = boxY + boxH;
    }

    cur += 2;
    // subtle separator
    stroke(doc, COL.border); doc.setLineWidth(0.15);
    doc.line(X0, cur, X0 + CW, cur);
    return cur + 1.5;
  }

  // ── Footer + page numbers (all pages, at the end) ──────────────────────────────
  function addFooters(doc, data) {
    var n = doc.internal.getNumberOfPages();
    var appName = clean(data.appName || 'sender.report');
    for (var i = 1; i <= n; i++) {
      doc.setPage(i);
      stroke(doc, COL.border); doc.setLineWidth(0.2);
      doc.line(MARGIN, PAGE_H - 12, PAGE_W - MARGIN, PAGE_H - 12);
      font(doc, 'normal', 7); ink(doc, COL.gray);
      doc.text(appName + '  ·  Deliverability Report', MARGIN, PAGE_H - 8);
      doc.text('Seite ' + i + ' von ' + n, PAGE_W - MARGIN, PAGE_H - 8, {align:'right'});
    }
  }

  // ── E2E notice (mirrors .alert-secondary lock banner) ──────────────────────────
  function drawE2ENotice(doc, y) {
    var h = 11;
    fill(doc, tint(COL.warning, 0.08));
    stroke(doc, tint(COL.warning, 0.30)); doc.setLineWidth(0.25);
    doc.roundedRect(X0, y, CW, h, 2, 2, 'FD');
    fill(doc, COL.warning);
    doc.roundedRect(X0, y + 2, 2.5, h - 4, 1, 1, 'F');
    font(doc, 'bold', 8); ink(doc, [120, 80, 10]);
    doc.text('Ende-zu-Ende verschlüsselt', X0 + 6, y + 4.8);
    font(doc, 'normal', 7.5); ink(doc, COL.body);
    doc.text('Betreff, Absender und IP sind nur im Browser lesbar. Score und alle Prüfergebnisse sind vollständig enthalten.',
             X0 + 6, y + 8.5);
    return y + h + 6;
  }

  // ── Main entry point ───────────────────────────────────────────────────────────
  window.mpGeneratePDF = function(opts) {
    var data = window.__mpReport;
    if (!data) { alert('Report-Daten nicht verfügbar. Seite neu laden.'); return; }
    var jsPDF = window.jspdf && window.jspdf.jsPDF;
    if (!jsPDF) { alert('jsPDF nicht geladen.'); return; }

    window.__pdfDetails = opts.details !== false;
    var doc = new jsPDF({orientation:'p', unit:'mm', format:'a4', compress:true});

    var y = drawHeader(doc, data);

    if (data.encrypted) y = drawE2ENotice(doc, y);
    if (opts.hero !== false) y = drawHero(doc, data, y);
    if (opts.meta !== false) {
      if (y + 36 > PAGE_BOTTOM) { doc.addPage(); y = TOP_CONT; }
      y = drawMeta(doc, data, y);
    }

    var textW = CW - 12 - 2;

    (data.groups || []).forEach(function(grp) {
      var checks = (grp.checks || []).filter(function(ch) { return opts[ch.status] !== false; });
      if (!checks.length) return;

      var counts = {pass:0, warn:0, fail:0, info:0};
      checks.forEach(function(ch){ if (counts[ch.status]!==undefined) counts[ch.status]++; });

      // Keep group header with at least one check on the page
      var firstH = measureCheck(doc, checks[0], opts, textW);
      if (y + 14 + firstH > PAGE_BOTTOM) { doc.addPage(); y = TOP_CONT; }

      y = drawGroupHeader(doc, grp.name, counts, y, false);

      checks.forEach(function(chk) {
        var bh = measureCheck(doc, chk, opts, textW);
        if (y + bh > PAGE_BOTTOM) {
          doc.addPage(); y = TOP_CONT;
          y = drawGroupHeader(doc, grp.name, null, y, true);
        }
        y = drawCheck(doc, chk, y);
      });

      y += 4; // gap between groups
    });

    addFooters(doc, data);

    var token = (data.mailbox && data.mailbox.token) ? data.mailbox.token.slice(0, 8) : 'report';
    doc.save('deliverability-report-' + token + '.pdf');
  };

})();
