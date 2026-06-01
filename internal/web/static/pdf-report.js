/**
 * Client-side PDF generation for sender.report
 * Uses jsPDF + jspdf-autotable (both vendored, self-hosted).
 *
 * Entry point: window.mpGeneratePDF(opts)
 *   opts: { pass, warn, fail, info, hero, meta, details }  (all boolean)
 *
 * Data source: window.__mpReport  (set by report.html for both plain and E2E reports)
 */
(function () {
  'use strict';

  // ── Palette ──────────────────────────────────────────────────────────────────
  var C = {
    primary:   [13,  110, 253],
    success:   [25,  135, 84 ],
    warning:   [253, 126, 20 ],
    danger:    [220, 53,  69 ],
    info:      [13,  202, 240],
    gray:      [108, 117, 125],
    dark:      [33,  37,  41 ],
    light:     [248, 249, 250],
    border:    [222, 226, 230],
    white:     [255, 255, 255],
    grpBg:     [235, 242, 255],
    grpFg:     [10,  66,  180],
    explBg:    [241, 243, 255],
    explFg:    [40,  50,  110],
    recoBg:    [255, 248, 230],
    recoFg:    [102, 68,  3  ],
  };

  function statusColor(s) {
    return C[{pass:'success',warn:'warning',fail:'danger',info:'info'}[s]] || C.gray;
  }
  function statusLabel(s) {
    return {pass:'OK',warn:'WARNUNG',fail:'FEHLER',info:'INFO'}[s] || s.toUpperCase();
  }
  function scoreColor(score) {
    return score >= 7.5 ? C.success : score >= 5.5 ? C.warning : C.danger;
  }
  function scoreLabel(score) {
    if (score >= 9)   return 'Ausgezeichnet';
    if (score >= 7.5) return 'Sehr gut';
    if (score >= 5.5) return 'Verbesserungsbedarf';
    return 'Kritisch';
  }
  function lighten(c, t) {
    return [Math.round(c[0]+(255-c[0])*t), Math.round(c[1]+(255-c[1])*t), Math.round(c[2]+(255-c[2])*t)];
  }

  // ── Header ───────────────────────────────────────────────────────────────────
  function drawHeader(doc, data) {
    var W   = doc.internal.pageSize.getWidth();
    var barH = 22, stripH = 9;

    // Blue bar
    doc.setFillColor.apply(doc, C.primary);
    doc.rect(0, 0, W, barH, 'F');

    // Logo: white rounded square
    doc.setFillColor.apply(doc, C.white);
    doc.roundedRect(10, 5, 12, 12, 1.5, 1.5, 'F');

    // Envelope body (primary on white)
    doc.setFillColor.apply(doc, C.primary);
    doc.rect(11.5, 7, 9, 6, 'F');

    // Envelope V-flap (white lines)
    doc.setDrawColor.apply(doc, C.white);
    doc.setLineWidth(0.55);
    doc.line(11.5, 7.5, 16, 11);
    doc.line(16, 11, 20.5, 7.5);

    // Green check badge
    doc.setFillColor.apply(doc, C.success);
    doc.circle(21, 16, 3, 'F');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(6);
    doc.setTextColor.apply(doc, C.white);
    doc.text('+', 21, 16.4, {align: 'center'});

    // App name
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(12);
    doc.setTextColor.apply(doc, C.white);
    doc.text(data.appName || 'sender.report', 25, 14);

    // Report label (right-aligned)
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.text('DELIVERABILITY REPORT', W - 13, 14, {align: 'right'});

    // Info strip
    doc.setFillColor.apply(doc, C.light);
    doc.rect(0, barH, W, stripH, 'F');
    doc.setDrawColor.apply(doc, C.border);
    doc.setLineWidth(0.2);
    doc.line(0, barH + stripH, W, barH + stripH);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor.apply(doc, [73, 80, 87]);

    var addr = data.mailbox ? data.mailbox.address : '';
    var score = data.score ? data.score.toFixed(1) : '—';
    var genAt = data.generatedAt ? new Date(data.generatedAt).toLocaleString('de-DE', {dateStyle:'short',timeStyle:'short'}) : new Date().toLocaleString('de-DE',{dateStyle:'short',timeStyle:'short'});

    doc.text('Mailbox: ' + addr, 14, barH + 5.5);
    doc.text('Score: ' + score + ' / 10', W / 2, barH + 5.5, {align: 'center'});
    doc.text('Erstellt: ' + genAt, W - 14, barH + 5.5, {align: 'right'});

    return barH + stripH + 5; // Y position after header
  }

  // ── Score Hero ───────────────────────────────────────────────────────────────
  function drawHero(doc, data, startY) {
    var W = doc.internal.pageSize.getWidth();
    var cw = W - 28; // content width
    var x  = 14, y = startY;
    var cardH = 42, sideW = 46;

    var col   = scoreColor(data.score);
    var label = scoreLabel(data.score);

    // White card bg
    doc.setFillColor.apply(doc, C.white);
    doc.roundedRect(x, y, cw, cardH, 2, 2, 'F');

    // Coloured left panel
    doc.setFillColor.apply(doc, col);
    doc.rect(x, y, sideW, cardH, 'F');
    doc.roundedRect(x, y, sideW, cardH, 2, 2, 'F'); // overdraw to round left

    // Card border
    doc.setDrawColor.apply(doc, C.border);
    doc.setLineWidth(0.2);
    doc.roundedRect(x, y, cw, cardH, 2, 2, 'D');

    // Vertical divider
    doc.setLineWidth(0.12);
    doc.line(x + sideW, y + 2, x + sideW, y + cardH - 2);

    // Score number
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(26);
    doc.setTextColor.apply(doc, C.white);
    var scoreStr = (data.score || 0).toFixed(1);
    var scoreW = doc.getStringUnitWidth(scoreStr) * 26 / doc.internal.scaleFactor;
    doc.text(scoreStr, x + sideW / 2, y + 21, {align: 'center'});

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(9);
    doc.text('/ 10', x + sideW / 2, y + 28, {align: 'center'});

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(6);
    doc.setTextColor.apply(doc, lighten(col, 0.55));
    doc.text(label.toUpperCase(), x + sideW / 2, y + 35, {align: 'center'});

    // Right panel
    var rx = x + sideW + 5, rw = cw - sideW - 8;

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(6.5);
    doc.setTextColor.apply(doc, C.gray);
    doc.text('GESAMTSCORE', rx, y + 8);

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(15);
    doc.setTextColor.apply(doc, C.dark);
    doc.text(label, rx, y + 17);

    // Status pills
    var counts = {pass: 0, warn: 0, fail: 0, info: 0};
    (data.groups || []).forEach(function(g) {
      (g.checks || []).forEach(function(c) {
        if (counts[c.status] !== undefined) counts[c.status]++;
      });
    });
    var pillDefs = [
      {s:'pass',lbl:'bestanden'},{s:'warn',lbl:'Warnungen'},
      {s:'fail',lbl:'Fehler'   },{s:'info',lbl:'Infos'   }
    ];
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(6.5);
    var px = rx, py = y + 23;
    pillDefs.forEach(function(p) {
      var sc = statusColor(p.s);
      var txt = counts[p.s] + ' ' + p.lbl;
      var tw = doc.getStringUnitWidth(txt) * 6.5 / doc.internal.scaleFactor;
      var pw = tw + 6;
      if (px + pw > x + cw - 3) { px = rx; py += 8; }
      doc.setFillColor.apply(doc, lighten(sc, 0.82));
      doc.roundedRect(px, py, pw, 6, 1, 1, 'F');
      doc.setTextColor.apply(doc, sc);
      doc.text(txt, px + pw / 2, py + 4.2, {align: 'center'});
      px += pw + 3;
    });

    return y + cardH;
  }

  // ── Metadata ─────────────────────────────────────────────────────────────────
  function drawMeta(doc, data, startY) {
    var W  = doc.internal.pageSize.getWidth();
    var cw = W - 28;
    var x  = 14, gap = 4, cellH = 14;
    var cellW = (cw - gap) / 2;
    var y = startY;

    var msg = data.message || {};
    function metaVal(v) {
      if (!v || v === '[encrypted]') return '(E2E-verschluesselt)';
      return v;
    }
    var received = '';
    if (msg.receivedAt && msg.receivedAt !== '0001-01-01T00:00:00Z') {
      try { received = new Date(msg.receivedAt).toLocaleString('de-DE',{dateStyle:'short',timeStyle:'medium'}); }
      catch(e) { received = msg.receivedAt; }
    }

    var items = [
      {label: 'Betreff',         value: metaVal(msg.subject)},
      {label: 'Empfangen',       value: received || '(E2E-verschluesselt)'},
      {label: 'Envelope-From',   value: metaVal(msg.smtpFrom)},
      {label: 'Quelle (IP/HELO)',value: (msg.remoteIP && msg.remoteIP !== '[encrypted]')
        ? msg.remoteIP + (msg.helo && msg.helo !== '[encrypted]' ? ' / ' + msg.helo : '')
        : '(E2E-verschluesselt)'},
    ];

    doc.setDrawColor.apply(doc, C.border);
    doc.setLineWidth(0.2);

    items.forEach(function(item, i) {
      var col = i % 2, row = Math.floor(i / 2);
      var ix = x + col * (cellW + gap);
      var iy = y + row * (cellH + 2);

      doc.setFillColor.apply(doc, C.white);
      doc.roundedRect(ix, iy, cellW, cellH, 1.5, 1.5, 'FD');

      // Top accent line
      doc.setFillColor.apply(doc, C.primary);
      doc.rect(ix + 1.5, iy, cellW - 3, 2, 'F');

      // Label
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(6.5);
      doc.setTextColor.apply(doc, C.gray);
      doc.text(item.label, ix + 4, iy + 6.5);

      // Value (truncated if needed)
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(8);
      doc.setTextColor.apply(doc, C.dark);
      var val = item.value;
      while (val.length > 4 &&
             doc.getStringUnitWidth(val) * 8 / doc.internal.scaleFactor > cellW - 8) {
        val = val.slice(0, -4) + '...';
      }
      doc.text(val, ix + 4, iy + 11);
    });

    return y + 2 * (cellH + 2);
  }

  // ── Check groups ─────────────────────────────────────────────────────────────
  function drawCheckGroups(doc, data, opts, startY) {
    var W  = doc.internal.pageSize.getWidth();
    var cw = W - 28;
    var y  = startY;

    (data.groups || []).forEach(function(grp) {
      var filtered = (grp.checks || []).filter(function(c) {
        return opts[c.status] !== false;
      });
      if (!filtered.length) return;

      // Build table rows
      var tableBody = [];
      filtered.forEach(function(chk) {
        var delta = chk.score_delta !== undefined && chk.score_delta !== 0
          ? (chk.score_delta > 0 ? '+' : '') + Number(chk.score_delta).toFixed(1)
          : '0.0';

        var summary = chk.summary || '';
        if (!summary.trim()) summary = '(Inhalt moeglicherweise E2E-verschluesselt)';

        // Main check row
        tableBody.push({
          _type: 'check',
          _status: chk.status,
          cells: [statusLabel(chk.status), chk.name || '', summary, delta]
        });

        // Explanation sub-row
        if (opts.details && chk.explanation && chk.explanation.trim()) {
          tableBody.push({
            _type: 'expl',
            cells: ['', 'Erklaerung', chk.explanation, '']
          });
        }

        // Recommendation sub-row (warn/fail only)
        if (opts.details && chk.recommendation && chk.recommendation.trim() &&
            (chk.status === 'warn' || chk.status === 'fail')) {
          tableBody.push({
            _type: 'reco',
            cells: ['', 'Empfehlung', chk.recommendation, '']
          });
        }
      });

      // Group counts for header
      var pc=0,wc=0,fc=0,ic=0;
      filtered.forEach(function(c){
        if(c.status==='pass')pc++; else if(c.status==='warn')wc++;
        else if(c.status==='fail')fc++; else ic++;
      });
      var countStr = [pc?pc+' OK':'',wc?wc+' W':'',fc?fc+' F':'',ic?ic+' I':'']
                       .filter(Boolean).join('  ');

      doc.autoTable({
        startY: y,
        margin: {left: 14, right: 14},
        tableWidth: cw,

        head: [[
          {content: grp.name, styles: {halign:'left', fontStyle:'bold', fontSize:8.5, textColor:C.grpFg, fillColor:C.grpBg}},
          {content: '', styles: {fillColor:C.grpBg}},
          {content: countStr, styles: {halign:'right', fontStyle:'normal', fontSize:7, textColor:C.gray, fillColor:C.grpBg}},
          {content: '', styles: {fillColor:C.grpBg}},
        ]],

        body: tableBody.map(function(r) { return r.cells; }),

        columnStyles: {
          0: {cellWidth: 20, halign: 'center', fontStyle: 'bold', fontSize: 7},
          1: {cellWidth: 60, fontStyle: 'bold', fontSize: 8},
          2: {cellWidth: 'auto', fontSize: 7.5},
          3: {cellWidth: 16, halign: 'right', fontStyle: 'bold', fontSize: 7.5},
        },

        headStyles: {
          fillColor: C.grpBg,
          textColor: C.grpFg,
          lineColor: C.border,
          lineWidth: {bottom: 0.3, top: 0, left: 0, right: 0},
          cellPadding: {top: 3, right: 4, bottom: 3, left: 4},
        },

        bodyStyles: {
          fontSize: 7.5,
          cellPadding: {top: 3, right: 4, bottom: 3, left: 4},
          minCellHeight: 8,
        },

        alternateRowStyles: {fillColor: [252, 252, 254]},

        styles: {
          overflow: 'linebreak',
          lineColor: C.border,
          lineWidth: {bottom: 0.12, top: 0, left: 0, right: 0},
        },

        didParseCell: function(d) {
          var raw = tableBody[d.row.index];
          if (!raw) return;

          if (raw._type === 'check') {
            var sc = statusColor(raw._status);
            if (d.column.index === 0) {
              d.cell.styles.textColor = C.white;
              d.cell.styles.fillColor = sc;
              d.cell.styles.fontStyle = 'bold';
              d.cell.styles.fontSize  = 6.5;
            } else if (d.column.index === 3) {
              d.cell.styles.textColor = sc;
            }
            // Left accent line drawn in willDrawCell
          }

          if (raw._type === 'expl') {
            d.cell.styles.fillColor  = C.explBg;
            d.cell.styles.textColor  = C.explFg;
            d.cell.styles.fontStyle  = d.column.index === 1 ? 'bold' : 'normal';
            d.cell.styles.fontSize   = 7;
            d.cell.styles.cellPadding = {top:2, right:4, bottom:2, left: d.column.index===0?4:6};
          }

          if (raw._type === 'reco') {
            d.cell.styles.fillColor  = C.recoBg;
            d.cell.styles.textColor  = C.recoFg;
            d.cell.styles.fontStyle  = d.column.index === 1 ? 'bold' : 'normal';
            d.cell.styles.fontSize   = 7;
            d.cell.styles.cellPadding = {top:2, right:4, bottom:2, left: d.column.index===0?4:6};
          }
        },

        willDrawCell: function(d) {
          var raw = tableBody[d.row.index];
          if (!raw || raw._type !== 'check' || d.column.index !== 0) return;
          // Draw 4mm left accent stripe in status colour before the cell
          var sc = statusColor(raw._status);
          d.doc.setFillColor.apply(d.doc, sc);
          d.doc.rect(14, d.cell.y, 4, d.cell.height, 'F');
        },

        didDrawTable: function(d) {
          y = d.finalY + 5;
        },
      });
    });

    return y;
  }

  // ── Page numbers ─────────────────────────────────────────────────────────────
  function addPageNumbers(doc, data) {
    var W      = doc.internal.pageSize.getWidth();
    var H      = doc.internal.pageSize.getHeight();
    var pages  = doc.internal.getNumberOfPages();
    var appName = data.appName || 'sender.report';

    for (var i = 1; i <= pages; i++) {
      doc.setPage(i);
      doc.setDrawColor.apply(doc, C.border);
      doc.setLineWidth(0.2);
      doc.line(14, H - 12, W - 14, H - 12);
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(6.5);
      doc.setTextColor.apply(doc, C.gray);
      doc.text(appName + '  -  Deliverability Report  -  Seite ' + i + ' von ' + pages,
               W / 2, H - 8, {align: 'center'});
    }
  }

  // ── E2E notice ───────────────────────────────────────────────────────────────
  function drawE2ENotice(doc, startY) {
    var W = doc.internal.pageSize.getWidth();
    var cw = W - 28, x = 14, h = 10;

    doc.setFillColor(255, 248, 230);
    doc.setDrawColor(253, 200, 100);
    doc.setLineWidth(0.2);
    doc.roundedRect(x, startY, cw, h, 1.5, 1.5, 'FD');

    // Left accent
    doc.setFillColor(253, 126, 20);
    doc.rect(x, startY, 3, h, 'F');
    doc.roundedRect(x, startY, 3, h, 1.5, 1.5, 'F');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7.5);
    doc.setTextColor(102, 68, 3);
    doc.text('E2E-verschluesselt: Betreff, Absender und IP sind nur im Browser mit deinem Schluessel lesbar.', x + 6, startY + 4.5);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(6.5);
    doc.text('Score und alle Pruefergebnisse sind serverseitig verfuegbar und vollstaendig im PDF enthalten.', x + 6, startY + 8);

    return startY + h;
  }

  // ── Category overview table ───────────────────────────────────────────────────
  function drawCategoryTable(doc, data, opts, startY) {
    var W  = doc.internal.pageSize.getWidth();
    var cw = W - 28;

    var rows = [];
    (data.groups || []).forEach(function(grp) {
      var filtered = (grp.checks || []).filter(function(c){ return opts[c.status]!==false; });
      if (!filtered.length) return;
      var pc=0,wc=0,fc=0,ic=0;
      filtered.forEach(function(c){
        if(c.status==='pass')pc++; else if(c.status==='warn')wc++;
        else if(c.status==='fail')fc++; else ic++;
      });
      rows.push([grp.name, pc||'–', wc||'–', fc||'–', ic||'–']);
    });

    if (!rows.length) return startY;

    doc.autoTable({
      startY: startY,
      margin: {left: 14, right: 14},
      tableWidth: cw,

      head: [['Kategorie', 'OK', 'Warnungen', 'Fehler', 'Infos']],
      body: rows,

      columnStyles: {
        0: {cellWidth: 'auto', fontStyle: 'bold'},
        1: {cellWidth: 26, halign: 'center'},
        2: {cellWidth: 26, halign: 'center'},
        3: {cellWidth: 26, halign: 'center'},
        4: {cellWidth: 26, halign: 'center'},
      },

      headStyles: {
        fillColor: C.primary,
        textColor: C.white,
        fontStyle: 'bold',
        fontSize: 8,
        cellPadding: {top:3, right:4, bottom:3, left:4},
      },

      bodyStyles: {fontSize: 8, cellPadding: {top:2.5, right:4, bottom:2.5, left:4}},
      alternateRowStyles: {fillColor: [245, 247, 252]},

      styles: {
        lineColor: C.border,
        lineWidth: {bottom: 0.12, top: 0, left: 0, right: 0},
      },

      didParseCell: function(d) {
        if (d.section === 'body') {
          if (d.column.index === 1 && d.cell.raw !== '–') d.cell.styles.textColor = C.success;
          if (d.column.index === 2 && d.cell.raw !== '–') d.cell.styles.textColor = C.warning;
          if (d.column.index === 3 && d.cell.raw !== '–') d.cell.styles.textColor = C.danger;
          if (d.column.index === 4 && d.cell.raw !== '–') d.cell.styles.textColor = C.info;
        }
      },
    });

    return doc.lastAutoTable.finalY + 5;
  }

  // ── Main entry point ─────────────────────────────────────────────────────────
  window.mpGeneratePDF = function(opts) {
    var data = window.__mpReport;
    if (!data) {
      alert('Report-Daten nicht verfuegbar. Seite neu laden.');
      return;
    }

    var jsPDF = window.jspdf && window.jspdf.jsPDF;
    if (!jsPDF) {
      alert('jsPDF nicht geladen.');
      return;
    }

    var doc = new jsPDF({orientation:'p', unit:'mm', format:'a4'});

    var y = drawHeader(doc, data);

    // E2E notice
    if (data.encrypted) {
      y = drawE2ENotice(doc, y) + 4;
    }

    // Score hero
    if (opts.hero !== false) {
      y = drawHero(doc, data, y) + 5;
    }

    // Category overview
    y = drawCategoryTable(doc, data, opts, y) + 0;

    // Metadata
    if (opts.meta !== false) {
      // Page break if needed
      var H = doc.internal.pageSize.getHeight();
      if (y + 35 > H - 20) { doc.addPage(); y = 14; }
      y = drawMeta(doc, data, y) + 5;
    }

    // Check groups
    drawCheckGroups(doc, data, opts, y);

    // Page numbers (last, after all content)
    addPageNumbers(doc, data);

    var token = (data.mailbox && data.mailbox.token) ? data.mailbox.token.slice(0, 8) : 'report';
    doc.save('deliverability-report-' + token + '.pdf');
  };

})();
