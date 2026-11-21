/* Mode demo statis: meniru REST API VulnDash di sisi browser memakai snapshot JSON (data ilustrasi).
 * Operasi baca (filter, sort, paging, detail) bekerja; operasi tulis ditolak karena tidak ada backend. */
(function () {
  'use strict';
  var realFetch = window.fetch.bind(window);
  var cache = {};

  function load(name) {
    if (!cache[name]) cache[name] = realFetch('data/' + name + '.json').then(function (r) { return r.json(); });
    return cache[name];
  }
  function json(body, status) {
    return Promise.resolve(new Response(JSON.stringify(body), { status: status || 200, headers: { 'Content-Type': 'application/json' } }));
  }
  function problem(status, detail) { return json({ status: status, title: 'Demo', detail: detail }, status); }

  var SORT = { priority: 'priorityScore', cvss: 'cvss', epss: 'epss', due: 'dueDate', firstSeen: 'firstSeen', title: 'title' };

  function listFindings(params) {
    return load('findings').then(function (all) {
      var q = (params.get('q') || '').toLowerCase();
      var status = params.get('status') ? params.get('status').split(',') : null;
      var sev = params.get('severity') ? params.get('severity').split(',') : null;
      var rows = all.filter(function (f) {
        if (status && status.indexOf(f.status) < 0) return false;
        if (sev && sev.indexOf(f.severity) < 0) return false;
        if (params.get('tool') && f.tool !== params.get('tool')) return false;
        if (params.get('assetId') && String(f.assetId) !== params.get('assetId')) return false;
        if (params.get('overdue') === 'true' && !f.overdue) return false;
        if (params.get('kev') === 'true' && !f.knownExploited) return false;
        if (q) {
          var hay = [f.title, f.cveId, f.location, f.component, f.assetName].join(' ').toLowerCase();
          if (hay.indexOf(q) < 0) return false;
        }
        return true;
      });
      var key = SORT[params.get('sort') || 'priority'] || 'priorityScore';
      var dir = params.get('dir') === 'asc' ? 1 : -1;
      rows.sort(function (a, b) {
        var x = a[key], y = b[key];
        if (x === null || x === undefined) x = dir > 0 ? Infinity : -Infinity;
        if (y === null || y === undefined) y = dir > 0 ? Infinity : -Infinity;
        return x < y ? -dir : x > y ? dir : a.id - b.id;
      });
      var size = Math.min(200, Math.max(1, parseInt(params.get('size') || '25', 10)));
      var page = Math.max(0, parseInt(params.get('page') || '0', 10));
      var pages = Math.max(1, Math.ceil(rows.length / size));
      return json({ content: rows.slice(page * size, page * size + size), totalElements: rows.length, totalPages: pages, number: page, first: page === 0, last: page >= pages - 1 });
    });
  }

  window.fetch = function (input, init) {
    var url = new URL(typeof input === 'string' ? input : input.url, location.href);
    if (!url.pathname.startsWith('/api/')) return realFetch(input, init);
    var method = ((init && init.method) || 'GET').toUpperCase();
    if (method !== 'GET') return problem(403, 'Mode demo statis (read-only): perubahan tidak disimpan. Jalankan versi lengkap lewat Docker Compose untuk mencoba upload dan workflow.');

    var p = url.pathname;
    if (p === '/api/dashboard/summary') return load('summary').then(json);
    if (p === '/api/assets') return load('assets').then(json);
    if (p === '/api/findings') return listFindings(url.searchParams);
    var m = p.match(/^\/api\/findings\/(\d+)$/);
    if (m) return load('details').then(function (d) { return d[m[1]] ? json(d[m[1]]) : problem(404, 'Temuan tidak ditemukan'); });
    if (p === '/api/reports/files') return json([]);
    return problem(404, 'Endpoint tidak tersedia pada demo statis');
  };

  document.addEventListener('DOMContentLoaded', function () {
    var bar = document.createElement('div');
    bar.setAttribute('style', 'background:#fef0c7;color:#93370d;padding:8px 24px;font-size:13px;border-bottom:1px solid #fedf89');
    bar.appendChild(document.createTextNode('Demo statis dengan data ilustrasi (read-only). Kode lengkap, API, dan upload scan: '));
    var a = document.createElement('a');
    a.href = 'https://github.com/ariantoekaputra99/vuln-dashboard';
    a.textContent = 'github.com/ariantoekaputra99/vuln-dashboard';
    a.setAttribute('style', 'color:#93370d;font-weight:600');
    bar.appendChild(a);
    document.body.insertBefore(bar, document.body.firstChild);
  });
})();
