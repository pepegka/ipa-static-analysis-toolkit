(function () {
  'use strict';

  var SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }

  function wireFindings() {
    var bar = document.getElementById('finding-filter');
    var list = document.getElementById('findings');
    if (!bar || !list) return;
    var cards = Array.prototype.slice.call(list.querySelectorAll('details[data-sev]'));
    if (!cards.length) return;

    var active = Object.create(null);
    var query = '';

    var counts = Object.create(null);
    cards.forEach(function (c) {
      var s = c.getAttribute('data-sev');
      counts[s] = (counts[s] || 0) + 1;
    });

    var tally = el('span', 'count');

    function apply() {
      var shown = 0;
      var anySev = Object.keys(active).length > 0;
      cards.forEach(function (c) {
        var okSev = !anySev || active[c.getAttribute('data-sev')];
        var okText = !query || c.getAttribute('data-find').indexOf(query) >= 0;
        var show = okSev && okText;
        c.hidden = !show;
        if (show) shown++;
      });
      tally.textContent = shown === cards.length
        ? cards.length + ' findings'
        : shown + ' of ' + cards.length + ' findings';
    }

    SEVERITIES.forEach(function (sev) {
      if (!counts[sev]) return;
      var b = el('button', 'sev-' + sev, sev + ' (' + counts[sev] + ')');
      b.type = 'button';
      b.setAttribute('aria-pressed', 'false');
      b.addEventListener('click', function () {
        if (active[sev]) { delete active[sev]; } else { active[sev] = true; }
        b.setAttribute('aria-pressed', active[sev] ? 'true' : 'false');
        apply();
      });
      bar.appendChild(b);
    });

    var search = el('input');
    search.type = 'search';
    search.placeholder = 'Filter by rule, title or vector';
    search.addEventListener('input', function () {
      query = search.value.trim().toLowerCase();
      apply();
    });
    bar.appendChild(search);

    function bulk(label, open) {
      var b = el('button', null, label);
      b.type = 'button';
      b.addEventListener('click', function () {
        cards.forEach(function (c) { if (!c.hidden) c.open = open; });
      });
      bar.appendChild(b);
    }
    bulk('Expand all', true);
    bulk('Collapse all', false);

    bar.appendChild(tally);
    bar.classList.add('on');
    apply();
  }

  function bytes(n) {
    var u = ['B', 'KB', 'MB', 'GB'], i = 0;
    while (n >= 1000 && i < u.length - 1) { n /= 1000; i++; }
    return (i === 0 ? n : n.toFixed(1)) + ' ' + u[i];
  }

  function wireManifest() {
    var host = document.getElementById('manifest');
    var src = document.getElementById('manifest-data');
    if (!host || !src) return;

    var data;
    try { data = JSON.parse(src.textContent); } catch (e) { return; }
    var rows = data.rows || [];

    var box = el('div', 'scroll ev');
    var table = el('table');
    table.innerHTML = '<thead><tr><th>File</th><th>Kind</th><th>Size</th><th>SHA-256</th></tr></thead>';
    var body = el('tbody');
    table.appendChild(body);
    box.appendChild(table);

    var PAGE = 300;
    var filtered = rows, drawn = 0;

    var status = el('p', 'note');
    var more = el('button', null, 'Show more');
    more.type = 'button';

    function draw(reset) {
      if (reset) { body.textContent = ''; drawn = 0; }
      var end = Math.min(drawn + PAGE, filtered.length);
      var frag = document.createDocumentFragment();
      for (var i = drawn; i < end; i++) {
        var r = filtered[i], tr = el('tr');
        var c0 = el('td'); c0.appendChild(el('code', null, r[0])); tr.appendChild(c0);
        tr.appendChild(el('td', null, r[1]));
        tr.appendChild(el('td', 'num', bytes(r[2])));
        var c3 = el('td'); if (r[3]) c3.appendChild(el('code', null, r[3])); tr.appendChild(c3);
        frag.appendChild(tr);
      }
      body.appendChild(frag);
      drawn = end;
      more.hidden = drawn >= filtered.length;
      var of = data.total && data.total > rows.length
        ? ' · ' + rows.length + ' of ' + data.total + ' files embedded, full list in report.json'
        : '';
      status.textContent = 'Showing ' + drawn + ' of ' + filtered.length + ' rows' + of;
    }

    more.addEventListener('click', function () { draw(false); });

    var search = el('input');
    search.type = 'search';
    search.placeholder = 'Filter files by path';
    search.addEventListener('input', function () {
      var q = search.value.trim().toLowerCase();
      filtered = q ? rows.filter(function (r) { return r[0].toLowerCase().indexOf(q) >= 0; }) : rows;
      draw(true);
    });

    var bar = el('div', 'filter on');
    bar.appendChild(search);
    host.appendChild(bar);
    host.appendChild(box);
    host.appendChild(status);
    host.appendChild(more);
    draw(true);

    if (data.total && data.total > rows.length && /^https?:$/.test(location.protocol)) {
      fetch('report.json').then(function (r) { return r.json(); }).then(function (full) {
        var all = (full.fileManifest || []).map(function (e) {
          return [e.relativePath, e.kind, e.sizeBytes, e.sha256 || ''];
        });
        if (all.length <= rows.length) return;
        rows = all;
        data.total = all.length;
        search.dispatchEvent(new Event('input'));
      }).catch(function () {});
    }
  }

  function wireTOC() {
    var links = Array.prototype.slice.call(document.querySelectorAll('.toc a[href^="#"]'));
    if (!links.length || !window.IntersectionObserver) return;
    var byID = Object.create(null);
    links.forEach(function (a) { byID[a.getAttribute('href').slice(1)] = a; });

    var seen = Object.create(null);
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) { seen[e.target.id] = e.isIntersecting; });
      var current = null;
      Object.keys(byID).forEach(function (id) {
        var h = document.getElementById(id);
        if (h && seen[id] && !current) current = id;
      });
      links.forEach(function (a) { a.classList.remove('on'); });
      if (current && byID[current]) byID[current].classList.add('on');
    }, { rootMargin: '0px 0px -75% 0px' });

    Object.keys(byID).forEach(function (id) {
      var h = document.getElementById(id);
      if (h) io.observe(h);
    });
  }

  function init() { wireFindings(); wireManifest(); wireTOC(); }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
