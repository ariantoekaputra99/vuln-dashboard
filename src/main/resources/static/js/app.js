/* VulnDash - dashboard tanpa dependensi.
 * Semua data dari scanner dianggap tidak tepercaya: dirender hanya via textContent / createTextNode (tidak pernah innerHTML). */
(function () {
  'use strict';

  var SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  var SEV_COLOR = { CRITICAL: '#b42318', HIGH: '#e8590c', MEDIUM: '#d99a00', LOW: '#2f9e44', INFO: '#8a94a6' };
  var PRI_COLOR = { P1: '#b42318', P2: '#e8590c', P3: '#d99a00', P4: '#2f9e44' };
  var PRI_LABEL = { P1: 'P1 - segera', P2: 'P2 - tinggi', P3: 'P3 - sedang', P4: 'P4 - rutin' };
  var STATUS_LABEL = {
    OPEN: 'Open', IN_PROGRESS: 'In progress', FIXED: 'Fixed', VERIFIED: 'Verified',
    ACCEPTED_RISK: 'Risk accepted', FALSE_POSITIVE: 'False positive'
  };
  var EVENT_LABEL = {
    DETECTED: 'Terdeteksi', REOPENED: 'Dibuka kembali', STATUS_CHANGE: 'Perubahan status',
    AUTO_RESOLVED: 'Otomatis tertutup', ASSIGNED: 'Penugasan', COMMENT: 'Catatan'
  };

  var state = {
    key: sessionStorage.getItem('vd.key') || '',
    actor: sessionStorage.getItem('vd.actor') || '',
    filters: { q: '', status: 'ACTIVE', severity: '', tool: '', overdue: false, kev: false, sort: 'priority', dir: 'desc', page: 0, size: 20 }
  };

  /* ---------- util DOM ---------- */
  function $(sel, root) { return (root || document).querySelector(sel); }

  function h(tag, props) {
    var el = document.createElement(tag);
    var kids = Array.prototype.slice.call(arguments, 2);
    Object.keys(props || {}).forEach(function (k) {
      var v = props[k];
      if (v === null || v === undefined || v === false) return;
      if (k === 'class') el.className = v;
      else if (k === 'text') el.textContent = v;
      else if (k === 'value') el.value = v;
      else if (k === 'checked') el.checked = !!v;
      else if (k.indexOf('on') === 0) el.addEventListener(k.slice(2).toLowerCase(), v);
      else el.setAttribute(k, v === true ? '' : String(v));
    });
    (function add(list) {
      list.forEach(function (kid) {
        if (kid === null || kid === undefined || kid === false) return;
        if (Array.isArray(kid)) return add(kid);
        el.appendChild(kid.nodeType ? kid : document.createTextNode(String(kid)));
      });
    })(kids);
    return el;
  }

  function svg(tag, attrs) {
    var el = document.createElementNS('http://www.w3.org/2000/svg', tag);
    Object.keys(attrs || {}).forEach(function (k) { el.setAttribute(k, String(attrs[k])); });
    for (var i = 2; i < arguments.length; i++) if (arguments[i]) el.appendChild(arguments[i]);
    return el;
  }

  function toast(msg, isErr) {
    var t = $('#toast');
    t.textContent = msg;
    t.className = 'toast' + (isErr ? ' err' : '');
    clearTimeout(toast._t);
    toast._t = setTimeout(function () { t.className = 'toast hidden'; }, 4500);
  }

  /* ---------- API ---------- */
  function asciiHeader(s) { return s.replace(/[^\x20-\x7E]/g, '?'); }

  function api(path, opts) {
    opts = opts || {};
    var headers = {};
    if (state.key) headers['X-API-Key'] = state.key;
    if (state.actor) headers['X-Actor'] = asciiHeader(state.actor);
    var body = opts.body;
    if (opts.json !== undefined) { headers['Content-Type'] = 'application/json'; body = JSON.stringify(opts.json); }
    return fetch(path, { method: opts.method || 'GET', headers: headers, body: body }).then(function (res) {
      if (!res.ok) {
        return res.json().catch(function () { return {}; }).then(function (j) {
          var msg = j.detail || j.title || ('HTTP ' + res.status);
          if (res.status === 401) msg += ' - isi API Key pada menu "Akses API"';
          var e = new Error(msg); e.status = res.status; throw e;
        });
      }
      var ct = res.headers.get('content-type') || '';
      return ct.indexOf('json') >= 0 ? res.json() : res.text();
    });
  }

  /* ---------- format ---------- */
  function fmtDate(iso) { return iso ? String(iso).slice(0, 10) : '-'; }
  function fmtEpss(v) { return v === null || v === undefined ? '-' : (v * 100).toFixed(1) + '%'; }
  function fmtNum(v) { return v === null || v === undefined ? '-' : String(v); }
  function slaText(f) {
    if (f.status !== 'OPEN' && f.status !== 'IN_PROGRESS') return h('span', { class: 'muted', text: '-' });
    if (f.overdue) return h('span', { class: 'danger', text: 'Lewat ' + Math.max(1, -f.daysToDue) + ' hari' });
    return h('span', { text: f.daysToDue + ' hari' });
  }
  function sevBadge(s) { return h('span', { class: 'badge sev-' + s, text: s }); }
  function priBadge(p) { return h('span', { class: 'badge pri-' + p, text: p }); }
  function stBadge(s) { return h('span', { class: 'badge st', text: STATUS_LABEL[s] || s }); }

  /* ---------- komponen ---------- */
  function card(title, content) {
    return h('div', { class: 'card' }, title ? h('h3', { text: title }) : null, content);
  }

  function kpi(value, label, cls) {
    return h('div', { class: 'card kpi ' + (cls || '') }, h('div', { class: 'v', text: String(value) }), h('div', { class: 'l', text: label }));
  }

  function barChart(rows) {
    var max = Math.max.apply(null, rows.map(function (r) { return r.value; }).concat([1]));
    if (rows.every(function (r) { return r.value === 0; })) return h('div', { class: 'empty', text: 'Tidak ada data.' });
    return h('div', null, rows.map(function (r) {
      var fill = h('div', { class: 'bar-fill' });
      fill.style.width = (r.value / max * 100) + '%';
      fill.style.background = r.color;
      return h('div', { class: 'bar-row' }, h('span', { text: r.label }), h('div', { class: 'bar-track' }, fill), h('b', { text: String(r.value) }));
    }));
  }

  function trendChart(points) {
    var W = 400, H = 190, padL = 34, padR = 10, padT = 12, padB = 26;
    var max = Math.max.apply(null, points.map(function (p) { return p.open; }).concat([1]));
    var x = function (i) { return padL + (W - padL - padR) * (points.length === 1 ? 0.5 : i / (points.length - 1)); };
    var y = function (v) { return padT + (H - padT - padB) * (1 - v / max); };
    var root = svg('svg', { viewBox: '0 0 ' + W + ' ' + H, 'class': 'chart-svg', role: 'img', 'aria-label': 'Tren temuan terbuka mingguan' });
    [0, 0.5, 1].forEach(function (t) {
      var v = Math.round(max * t);
      root.appendChild(svg('line', { x1: padL, x2: W - padR, y1: y(v), y2: y(v), stroke: '#e3e8ef' }));
      var lbl = svg('text', { x: padL - 6, y: y(v) + 4, 'text-anchor': 'end', 'font-size': 10, fill: '#667085' });
      lbl.textContent = String(v);
      root.appendChild(lbl);
    });
    var d = points.map(function (p, i) { return (i ? 'L' : 'M') + x(i).toFixed(1) + ' ' + y(p.open).toFixed(1); }).join(' ');
    root.appendChild(svg('path', { d: d, fill: 'none', stroke: '#2f5bea', 'stroke-width': 2.5, 'stroke-linejoin': 'round' }));
    points.forEach(function (p, i) {
      var c = svg('circle', { cx: x(i), cy: y(p.open), r: 3.5, fill: '#2f5bea' });
      var tip = svg('title', {}); tip.textContent = p.date + ': ' + p.open + ' temuan terbuka';
      c.appendChild(tip);
      root.appendChild(c);
      if (i === 0 || i === points.length - 1 || i === Math.floor(points.length / 2)) {
        var tl = svg('text', { x: x(i), y: H - 8, 'text-anchor': i === points.length - 1 ? 'end' : (i === 0 ? 'start' : 'middle'), 'font-size': 10, fill: '#667085' });
        tl.textContent = p.date.slice(5);
        root.appendChild(tl);
      }
    });
    return root;
  }

  function findingsTable(list, emptyText) {
    if (!list.length) return h('div', { class: 'empty', text: emptyText || 'Tidak ada temuan.' });
    return h('table', null,
      h('thead', null, h('tr', null,
        ['Skor', 'Prio', 'Severity', 'Aset', 'Temuan', 'CVE', 'CVSS', 'EPSS', 'Status', 'SLA'].map(function (t) { return h('th', { text: t }); }))),
      h('tbody', null, list.map(function (f) {
        return h('tr', { class: 'click', onclick: function () { openDrawer(f.id); } },
          h('td', { class: 'score', text: f.priorityScore.toFixed(1) }),
          h('td', null, priBadge(f.priority)),
          h('td', null, sevBadge(f.severity)),
          h('td', { class: 'trunc', text: f.assetName }),
          h('td', { class: 'trunc', title: f.title }, f.title, f.knownExploited ? h('span', { class: 'badge kev', text: 'KEV', style: 'margin-left:6px' }) : null),
          h('td', { text: f.cveId || '-' }),
          h('td', { text: fmtNum(f.cvss) }),
          h('td', { text: fmtEpss(f.epss) }),
          h('td', null, stBadge(f.status)),
          h('td', null, slaText(f)));
      })));
  }

  /* ---------- views ---------- */
  function viewOverview(root) {
    return api('/api/dashboard/summary').then(function (s) {
      var k = s.kpis;
      var compliance = k.slaCompliancePercent;
      root.appendChild(h('h2', { text: 'Ringkasan postur kerentanan' }));
      root.appendChild(h('div', { class: 'grid kpis' },
        kpi(k.active, 'Temuan aktif'),
        kpi(k.criticalAndHigh, 'Critical + High', k.criticalAndHigh ? 'bad' : ''),
        kpi(k.overdue, 'Melewati SLA', k.overdue ? 'bad' : 'good'),
        kpi(k.dueIn7Days, 'Jatuh tempo ≤ 7 hari', k.dueIn7Days ? 'warn' : ''),
        kpi(k.knownExploited, 'Dieksploitasi aktif (KEV)', k.knownExploited ? 'bad' : ''),
        kpi(compliance === null ? 'n/a' : compliance + '%', 'Kepatuhan SLA (' + k.resolved + ' selesai)', compliance !== null && compliance < 80 ? 'warn' : 'good')));

      root.appendChild(h('div', { class: 'grid cols-3' },
        card('Aktif per severity', barChart(SEVERITIES.map(function (sv) { return { label: sv, value: s.activeBySeverity[sv] || 0, color: SEV_COLOR[sv] }; }))),
        card('Aktif per prioritas (CVSS + EPSS + aset)', barChart(['P1', 'P2', 'P3', 'P4'].map(function (p) { return { label: PRI_LABEL[p].split(' ')[0], value: s.activeByPriority[p] || 0, color: PRI_COLOR[p] }; }))),
        card('Tren temuan terbuka (mingguan)', trendChart(s.trend))));

      var mttrRows = SEVERITIES.filter(function (sv) { return s.mttrDaysBySeverity[sv] !== undefined; })
        .map(function (sv) { return h('tr', null, h('td', null, sevBadge(sv)), h('td', { text: s.mttrDaysBySeverity[sv] + ' hari' })); });
      root.appendChild(h('div', { class: 'grid cols-3' },
        card('Per tool (aktif)', barChart(Object.keys(s.activeByTool).map(function (t) { return { label: t, value: s.activeByTool[t], color: '#2f5bea' }; }))),
        card('Per status (semua)', barChart(Object.keys(s.byStatus).map(function (t) { return { label: STATUS_LABEL[t] || t, value: s.byStatus[t], color: '#667085' }; }))),
        card('MTTR (rata-rata hari ke penyelesaian)', mttrRows.length
          ? h('table', null, h('thead', null, h('tr', null, h('th', { text: 'Severity' }), h('th', { text: 'MTTR' }))), h('tbody', null, mttrRows))
          : h('div', { class: 'empty', text: 'Belum ada temuan yang selesai.' }))));

      root.appendChild(card('Prioritas teratas', findingsTable(s.topFindings)));
      root.appendChild(h('div', { style: 'height:14px' }));
      root.appendChild(card('Melewati SLA', findingsTable(s.slaBreaches, 'Tidak ada temuan yang melewati SLA.')));
      root.appendChild(h('div', { style: 'height:14px' }));
      root.appendChild(card('Aset berisiko tertinggi', s.topAssets.length ? h('table', null,
        h('thead', null, h('tr', null, ['Aset', 'Kritikalitas', 'Aktif', 'Critical', 'High', 'Lewat SLA', 'Skor risiko'].map(function (t) { return h('th', { text: t }); }))),
        h('tbody', null, s.topAssets.map(function (a) {
          return h('tr', { class: 'click', onclick: function () { state.filters.assetId = a.id; location.hash = '#findings'; } },
            h('td', { text: a.name }), h('td', { text: a.criticality }), h('td', { text: String(a.active) }),
            h('td', { text: String(a.critical) }), h('td', { text: String(a.high) }),
            h('td', { class: a.overdue ? 'danger' : '', text: String(a.overdue) }), h('td', { class: 'score', text: String(a.riskScore) }));
        }))) : h('div', { class: 'empty', text: 'Belum ada aset. Upload hasil scan terlebih dahulu.' })));
    });
  }

  function selectEl(options, value, onchange) {
    var sel = h('select', { onchange: onchange }, options.map(function (o) { return h('option', { value: o[0], text: o[1] }); }));
    sel.value = value;
    return sel;
  }

  function viewFindings(root) {
    var f = state.filters;
    var box = h('div');
    root.appendChild(h('h2', { text: 'Temuan' }));

    var q = h('input', { type: 'search', placeholder: 'cari judul, CVE, lokasi, aset…', value: f.q });
    q.addEventListener('keydown', function (e) { if (e.key === 'Enter') { f.q = q.value; f.page = 0; load(); } });

    var statusOpts = [['ACTIVE', 'Aktif (Open + In progress)'], ['ALL', 'Semua status']].concat(Object.keys(STATUS_LABEL).map(function (s) { return [s, STATUS_LABEL[s]]; }));
    var filters = h('div', { class: 'filters' },
      h('label', null, 'Cari', q),
      h('label', null, 'Status', selectEl(statusOpts, f.status, function (e) { f.status = e.target.value; f.page = 0; load(); })),
      h('label', null, 'Severity', selectEl([['', 'Semua']].concat(SEVERITIES.map(function (s) { return [s, s]; })), f.severity, function (e) { f.severity = e.target.value; f.page = 0; load(); })),
      h('label', null, 'Tool', selectEl([['', 'Semua'], ['TRIVY', 'Trivy'], ['ZAP', 'OWASP ZAP'], ['NUCLEI', 'Nuclei']], f.tool, function (e) { f.tool = e.target.value; f.page = 0; load(); })),
      h('label', null, 'Urutkan', selectEl([['priority', 'Prioritas'], ['cvss', 'CVSS'], ['epss', 'EPSS'], ['due', 'Jatuh tempo'], ['firstSeen', 'Pertama terlihat'], ['title', 'Judul']], f.sort, function (e) { f.sort = e.target.value; f.dir = f.sort === 'due' || f.sort === 'title' ? 'asc' : 'desc'; load(); })),
      h('label', { class: 'chk' }, h('input', { type: 'checkbox', checked: f.overdue, onchange: function (e) { f.overdue = e.target.checked; f.page = 0; load(); } }), 'Lewat SLA'),
      h('label', { class: 'chk' }, h('input', { type: 'checkbox', checked: f.kev, onchange: function (e) { f.kev = e.target.checked; f.page = 0; load(); } }), 'KEV saja'),
      f.assetId ? h('button', { class: 'btn secondary', type: 'button', onclick: function () { f.assetId = null; f.page = 0; load(); } }, 'Hapus filter aset #' + f.assetId) : null,
      h('button', { class: 'btn secondary', type: 'button', onclick: function () { f.q = ''; f.q = ''; f.status = 'ACTIVE'; f.severity = ''; f.tool = ''; f.overdue = false; f.kev = false; f.assetId = null; f.page = 0; f.sort = 'priority'; f.dir = 'desc'; render(); } }, 'Reset'));
    root.appendChild(filters);
    root.appendChild(box);

    function load() {
      var p = new URLSearchParams();
      if (f.q) p.set('q', f.q);
      if (f.status === 'ACTIVE') p.set('status', 'OPEN,IN_PROGRESS');
      else if (f.status !== 'ALL') p.set('status', f.status);
      if (f.severity) p.set('severity', f.severity);
      if (f.tool) p.set('tool', f.tool);
      if (f.assetId) p.set('assetId', f.assetId);
      if (f.overdue) p.set('overdue', 'true');
      if (f.kev) p.set('kev', 'true');
      p.set('sort', f.sort); p.set('dir', f.dir); p.set('page', f.page); p.set('size', f.size);
      return api('/api/findings?' + p.toString()).then(function (page) {
        box.replaceChildren(card(null, findingsTable(page.content, 'Tidak ada temuan yang cocok dengan filter.')),
          h('div', { class: 'pager' },
            h('span', { class: 'muted', text: page.totalElements + ' temuan • halaman ' + (page.number + 1) + ' / ' + Math.max(1, page.totalPages) }),
            h('button', { class: 'btn secondary', type: 'button', disabled: page.first, onclick: function () { f.page--; load(); } }, '‹ Sebelumnya'),
            h('button', { class: 'btn secondary', type: 'button', disabled: page.last, onclick: function () { f.page++; load(); } }, 'Berikutnya ›')));
      }).catch(function (e) { box.replaceChildren(h('div', { class: 'card danger', text: e.message })); });
    }
    return load();
  }

  function viewAssets(root) {
    return api('/api/assets').then(function (list) {
      root.appendChild(h('h2', { text: 'Aset' }));
      root.appendChild(h('p', { class: 'muted', text: 'Kritikalitas aset memengaruhi skor prioritas. Mengubahnya menghitung ulang skor semua temuan aset tersebut.' }));
      root.appendChild(card(null, list.length ? h('table', null,
        h('thead', null, h('tr', null, ['Aset', 'Tipe', 'Pemilik', 'Kritikalitas', 'Aktif', 'Lewat SLA', 'Prioritas maks'].map(function (t) { return h('th', { text: t }); }))),
        h('tbody', null, list.map(function (a) {
          var sel = selectEl(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map(function (c) { return [c, c]; }), a.criticality, function (e) {
            api('/api/assets/' + a.id, { method: 'PATCH', json: { criticality: e.target.value } })
              .then(function () { toast('Kritikalitas ' + a.name + ' diperbarui; skor dihitung ulang'); render(); })
              .catch(function (err) { toast(err.message, true); e.target.value = a.criticality; });
          });
          return h('tr', null, h('td', { text: a.name }), h('td', { text: a.type }), h('td', { text: a.owner || '-' }), h('td', null, sel),
            h('td', { text: String(a.activeFindings) }), h('td', { class: a.overdue ? 'danger' : '', text: String(a.overdue) }),
            h('td', { class: 'score', text: a.maxPriority.toFixed(1) }));
        }))) : h('div', { class: 'empty', text: 'Belum ada aset.' })));
    });
  }

  function viewReports(root) {
    var listBox = h('div');
    function loadFiles() {
      return api('/api/reports/files').then(function (names) {
        listBox.replaceChildren(names.length ? h('ul', null, names.map(function (n) {
          return h('li', null, h('a', { href: '/api/reports/files/' + encodeURIComponent(n), text: n }));
        })) : h('div', { class: 'empty', text: 'Belum ada file laporan. Laporan mingguan dibuat otomatis (Senin 02:00 UTC) atau klik "Generate sekarang".' }));
      }).catch(function (e) { listBox.replaceChildren(h('div', { class: 'danger', text: e.message })); });
    }
    root.appendChild(h('h2', { text: 'Laporan' }));
    root.appendChild(h('div', { class: 'grid cols-2' },
      card('Laporan langsung', h('div', null,
        h('p', { class: 'muted', text: 'Laporan eksekutif berformat HTML (cetak ke PDF lewat browser) dan ekspor CSV seluruh temuan.' }),
        h('p', null, h('a', { class: 'btn', href: '/api/reports/executive', target: '_blank', rel: 'noopener' }, 'Buka laporan eksekutif'), ' ',
          h('a', { class: 'btn secondary', href: '/api/reports/findings.csv' }, 'Unduh CSV')))),
      card('Laporan otomatis tersimpan', h('div', null,
        h('p', null, h('button', { class: 'btn', type: 'button', onclick: function () {
          api('/api/reports/generate', { method: 'POST' }).then(function () { toast('Laporan dibuat'); return loadFiles(); }).catch(function (e) { toast(e.message, true); });
        } }, 'Generate sekarang')),
        listBox))));
    return loadFiles();
  }

  function viewUpload(root) {
    var out = h('div');
    var file = h('input', { type: 'file', required: true, accept: '.json,.jsonl,.txt' });
    var tool = selectEl([['TRIVY', 'Trivy (--format json)'], ['ZAP', 'OWASP ZAP (Traditional JSON)'], ['NUCLEI', 'Nuclei (-jsonl)']], 'TRIVY', function () { });
    var asset = h('input', { type: 'text', placeholder: 'opsional - default diambil dari isi file' });
    var crit = selectEl([['', '(biarkan / default MEDIUM)'], ['LOW', 'LOW'], ['MEDIUM', 'MEDIUM'], ['HIGH', 'HIGH'], ['CRITICAL', 'CRITICAL']], '', function () { });
    var auto = h('input', { type: 'checkbox', checked: true });
    var btn = h('button', { class: 'btn', type: 'submit' }, 'Upload & proses');

    var form = h('form', { class: 'upload-form' },
      h('label', null, 'Tool', tool),
      h('label', null, 'File hasil scan', file),
      h('label', null, 'Nama aset', asset),
      h('label', null, 'Kritikalitas aset', crit),
      h('label', { style: 'flex-direction:row;align-items:center;gap:8px' }, auto, 'Tutup otomatis temuan yang tidak muncul lagi (scan ulang penuh)'),
      btn);
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      if (!file.files.length) return;
      var fd = new FormData();
      fd.append('tool', tool.value);
      fd.append('file', file.files[0]);
      if (asset.value.trim()) fd.append('asset', asset.value.trim());
      if (crit.value) fd.append('criticality', crit.value);
      fd.append('autoResolve', auto.checked ? 'true' : 'false');
      btn.disabled = true;
      api('/api/scans', { method: 'POST', body: fd }).then(function (r) {
        out.replaceChildren(h('div', { class: 'result' },
          h('b', { text: 'Scan #' + r.scanId + ' (' + r.tool + ') berhasil diproses' }),
          h('div', { text: r.total + ' temuan • baru ' + r.created + ' • diperbarui ' + r.updated + ' • dibuka kembali ' + r.reopened + ' • tertutup otomatis ' + r.autoResolved }),
          h('div', { class: 'muted', text: 'Aset: ' + r.assets.join(', ') })));
        toast('Scan diimpor');
      }).catch(function (err) { out.replaceChildren(h('div', { class: 'result danger', text: err.message })); toast(err.message, true); })
        .then(function () { btn.disabled = false; });
    });

    root.appendChild(h('h2', { text: 'Upload hasil scan' }));
    root.appendChild(card(null, h('div', null, form, out)));
    root.appendChild(h('p', { class: 'muted', text: 'Perlu API Key (menu "Akses API"). Untuk CI/CD gunakan: curl -H "X-API-Key: $KEY" -F tool=TRIVY -F file=@trivy.json <host>/api/scans' }));
    return Promise.resolve();
  }

  /* ---------- drawer detail ---------- */
  function closeDrawer() { $('#drawer').classList.add('hidden'); $('#scrim').classList.add('hidden'); }

  function openDrawer(id) {
    $('#drawer').classList.remove('hidden');
    $('#scrim').classList.remove('hidden');
    var body = $('#drawer-body');
    body.replaceChildren(h('p', { class: 'muted', text: 'Memuat…' }));
    api('/api/findings/' + id).then(function (d) {
      var f = d.finding;
      var statusSel = selectEl([['', '- ubah status -']].concat(d.allowedNext.map(function (s) { return [s, STATUS_LABEL[s] || s]; })), '', function () { });
      var note = h('textarea', { placeholder: 'Catatan / justifikasi (wajib untuk Risk accepted & False positive)' });
      var assignee = h('input', { type: 'text', value: f.assignee || '', placeholder: 'ditugaskan ke…' });
      var save = h('button', { class: 'btn', type: 'button', onclick: function () {
        var payload = {};
        if (statusSel.value) payload.status = statusSel.value;
        if ((assignee.value || '') !== (f.assignee || '')) payload.assignee = assignee.value;
        if (note.value.trim()) payload.note = note.value.trim();
        if (!Object.keys(payload).length) return toast('Tidak ada perubahan');
        save.disabled = true;
        api('/api/findings/' + id, { method: 'PATCH', json: payload })
          .then(function () { toast('Tersimpan'); openDrawer(id); render(true); })
          .catch(function (e) { toast(e.message, true); save.disabled = false; });
      } }, 'Simpan perubahan');

      body.replaceChildren(
        h('div', { style: 'display:flex;justify-content:space-between;gap:12px' },
          h('div', null, sevBadge(f.severity), ' ', priBadge(f.priority), ' ', stBadge(f.status), ' ', f.knownExploited ? h('span', { class: 'badge kev', text: 'KEV - dieksploitasi aktif' }) : null),
          h('button', { class: 'btn secondary', type: 'button', onclick: closeDrawer }, 'Tutup')),
        h('h2', { style: 'margin-top:12px', text: f.title }),
        h('dl', { class: 'meta' },
          h('dt', { text: 'Skor prioritas' }), h('dd', { class: 'score', text: f.priorityScore.toFixed(1) + ' / 100' }),
          h('dt', { text: 'Aset' }), h('dd', { text: f.assetName }),
          h('dt', { text: 'Tool' }), h('dd', { text: f.tool }),
          h('dt', { text: 'CVE / CWE' }), h('dd', { text: (f.cveId || '-') + ' / ' + (f.cweId || '-') }),
          h('dt', { text: 'CVSS / EPSS' }), h('dd', { text: fmtNum(f.cvss) + ' / ' + fmtEpss(f.epss) }),
          h('dt', { text: 'Lokasi' }), h('dd', { text: f.location || '-' }),
          h('dt', { text: 'Komponen' }), h('dd', { text: f.component ? f.component + ' ' + (f.installedVersion || '') + (f.fixedVersion ? ' → ' + f.fixedVersion : '') : '-' }),
          h('dt', { text: 'Pertama terlihat' }), h('dd', { text: fmtDate(f.firstSeen) }),
          h('dt', { text: 'Jatuh tempo SLA' }), h('dd', null, fmtDate(f.dueDate) + ' ', slaText(f)),
          h('dt', { text: 'Assignee' }), h('dd', { text: f.assignee || '-' })),
        d.description ? h('div', null, h('h3', { text: 'Deskripsi' }), h('pre', { class: 'desc', text: d.description })) : null,
        d.remediation ? h('div', null, h('h3', { style: 'margin-top:14px', text: 'Remediasi' }), h('pre', { class: 'desc', text: d.remediation })) : null,
        h('h3', { style: 'margin-top:18px', text: 'Tindak lanjut' }),
        h('div', { class: 'form-row' }, h('label', null, 'Status', statusSel), h('label', null, 'Assignee', assignee)),
        note, h('div', { style: 'margin-top:8px' }, save),
        h('h3', { style: 'margin-top:20px', text: 'Riwayat' }),
        h('ul', { class: 'timeline' }, d.events.map(function (ev) {
          var change = ev.from || ev.to ? ' ' + (ev.from ? (STATUS_LABEL[ev.from] || ev.from) : '') + ' → ' + (ev.to ? (STATUS_LABEL[ev.to] || ev.to) : '') : '';
          return h('li', null, h('b', { text: EVENT_LABEL[ev.type] || ev.type }), h('span', { text: change }),
            h('div', { class: 'muted', text: fmtDate(ev.at) + ' • ' + (ev.actor || '-') }), ev.note ? h('div', { text: ev.note }) : null);
        })));
    }).catch(function (e) { body.replaceChildren(h('p', { class: 'danger', text: e.message }), h('button', { class: 'btn secondary', type: 'button', onclick: closeDrawer }, 'Tutup')); });
  }

  /* ---------- router ---------- */
  var VIEWS = { overview: viewOverview, findings: viewFindings, assets: viewAssets, reports: viewReports, upload: viewUpload };

  function currentView() {
    var v = (location.hash || '#overview').slice(1);
    return VIEWS[v] ? v : 'overview';
  }

  function render() {
    var name = currentView();
    document.querySelectorAll('#nav a').forEach(function (a) { a.classList.toggle('active', a.getAttribute('data-view') === name); });
    var root = $('#app');
    root.replaceChildren(h('p', { class: 'muted', text: 'Memuat…' }));
    var tmp = h('div');
    return Promise.resolve(VIEWS[name](tmp)).then(function () { root.replaceChildren.apply(root, Array.prototype.slice.call(tmp.childNodes)); })
      .catch(function (e) { root.replaceChildren(h('div', { class: 'card danger', text: 'Gagal memuat: ' + e.message })); });
  }

  /* ---------- akses ---------- */
  $('#btn-access').addEventListener('click', function () { $('#access-panel').classList.toggle('hidden'); });
  $('#in-key').value = state.key;
  $('#in-actor').value = state.actor;
  $('#btn-save-access').addEventListener('click', function () {
    state.key = $('#in-key').value.trim();
    state.actor = $('#in-actor').value.trim();
    sessionStorage.setItem('vd.key', state.key);
    sessionStorage.setItem('vd.actor', state.actor);
    $('#access-panel').classList.add('hidden');
    toast('Disimpan untuk sesi ini');
  });
  $('#scrim').addEventListener('click', closeDrawer);
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape') closeDrawer(); });
  window.addEventListener('hashchange', function () { closeDrawer(); render(); });

  render();
})();
