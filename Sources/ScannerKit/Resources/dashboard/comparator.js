(function () {
  var combo = document.getElementById('cmpCombo');
  if (!combo) return;
  var R; try { R = JSON.parse(document.getElementById('msdata').textContent); } catch (e) { return; }
  var ADVICE = {}; try { ADVICE = JSON.parse(document.getElementById('msadvice').textContent); } catch (e) {}
  var APPS = (R.apps || []).filter(function (a) { return a.error == null && a.findingsCount != null; });
  var byId = {}; APPS.forEach(function (a, i) { a._uid = String(i); byId[a._uid] = a; });
  var search = document.getElementById('cmpSearch');
  var chipsEl = document.getElementById('cmpChips');
  var drop = document.getElementById('cmpDrop');
  var count = document.getElementById('cmpCount');
  var clearBtn = document.getElementById('cmpClear');
  var out = document.getElementById('cmpOut');
  var MIN = 2, MAX = 10;
  var T = typeof tok === 'function' ? tok : function (_n, f) { return f; };
  var RC = { green: T('good', '#1aa050'), yellow: T('warn', '#d1a417'),
             orange: T('serious', '#e0820a'), red: T('critical', '#e0392f') };
  var SEV = ['critical', 'high', 'medium', 'low', 'info'];
  var SC_FALLBACK = { info: 'sev-info-fill', low: 'sev-low-fill', medium: 'sev-medium-fill',
                      high: 'sev-high-fill', critical: 'sev-critical-fill' };
  function sevColor(sev) {
    var pub = window.__sevColors;
    return (pub && pub[sev]) || T(SC_FALLBACK[sev], '#888');
  }
  var SC = { get info() { return sevColor('info'); }, get low() { return sevColor('low'); },
             get medium() { return sevColor('medium'); }, get high() { return sevColor('high'); },
             get critical() { return sevColor('critical'); } };
  var SEVRANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  function rank(sev) { return SEVRANK[sev] != null ? SEVRANK[sev] : 9; }
  var PALETTE = [T('cat-1'), T('cat-2'), T('cat-3'), T('cat-4'), T('cat-5'), T('cat-6')];
  var OTHER = T('ink-ghost', '#39414c');
  function catColor(i) { return i < PALETTE.length ? PALETTE[i] : OTHER; }
  var sel = [];
  var matches = [];
  var active = -1;
  var curApps = [];
  var cmpCharts = [];

  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"]/g, function (c) { return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]; }); }
  function bytes(b) { b = b || 0; var u = ['B', 'KB', 'MB', 'GB']; var i = 0; while (b >= 1000 && i < u.length - 1) { b /= 1000; i++; } return (i === 0 ? b : b.toFixed(1)) + ' ' + u[i]; }
  function worstSeverity(a) {
    var sc = a.severityCounts || {};
    if ((a.criticalCount || sc.critical || 0) > 0) return 'critical';
    if ((a.highCount || sc.high || 0) > 0) return 'high';
    if ((sc.medium || 0) > 0) return 'medium';
    if ((sc.low || 0) > 0) return 'low';
    return 'info';
  }
  function dot(a) { return '<span class=cdot style="background:' + (SC[worstSeverity(a)] || '#888') + '"></span>'; }
  function shortName(n) { n = String(n == null ? '' : n).trim(); return n.length > 34 ? n.slice(0, 33) + '…' : n; }
  function shortPerm(k) { return String(k).trim().replace(/^NS/, '').replace(/UsageDescription$/, ''); }

  function renderChips() {
    chipsEl.innerHTML = sel.map(function (id) {
      var a = byId[id]; if (!a) return '';
      return '<span class=chip>' + dot(a)
        + '<span class=cname>' + esc(a.appStoreName) + '</span>'
        + '<button class=cx data-id="' + id + '" title=Remove>×</button></span>';
    }).join('');
  }
  function renderDrop() {
    var q = search.value.trim().toLowerCase();
    var pool = APPS.filter(function (a) { return sel.indexOf(a._uid) < 0; });
    matches = pool.filter(function (a) {
      if (!q) return true;
      return (a.appStoreName + ' ' + a.bundleID + ' ' + (a.category || '')).toLowerCase().indexOf(q) >= 0;
    });
    if (sel.length >= MAX) { drop.innerHTML = '<div class=cmp-empty>Maximum of ' + MAX + ' apps. Remove one to add another.</div>'; return; }
    if (matches.length === 0) { drop.innerHTML = '<div class=cmp-empty>No apps match “' + esc(search.value) + '”.</div>'; return; }
    if (active >= matches.length) active = matches.length - 1;
    drop.innerHTML = matches.slice(0, 60).map(function (a, i) {
      var meta = [a.category, a.version ? 'v' + a.version : ''].filter(Boolean).join(' · ');
      return '<div class="drow' + (i === active ? ' active' : '') + '" data-id="' + a._uid + '">'
        + '<span class=ddot style="background:' + (SC[worstSeverity(a)] || '#888') + '"></span>'
        + '<span>' + esc(a.appStoreName) + '</span>'
        + '<span class=dmeta>' + esc(meta) + ' · <span class=dscore>' + (a.findingsCount || 0) + ' findings</span></span></div>';
    }).join('');
  }
  function openDrop() { renderDrop(); drop.hidden = false; search.setAttribute('aria-expanded', 'true'); }
  function closeDrop() { drop.hidden = true; active = -1; search.setAttribute('aria-expanded', 'false'); }
  function addApp(id) { if (!byId[id] || sel.indexOf(id) >= 0 || sel.length >= MAX) return; sel.push(id); search.value = ''; active = -1; afterChange(); }
  function removeApp(id) { sel = sel.filter(function (x) { return x !== id; }); afterChange(); }
  function afterChange() { renderChips(); updateCount(); if (!drop.hidden) renderDrop(); renderCompare(); }
  function updateCount() {
    var n = sel.length;
    if (n === 0) { count.textContent = 'Pick 2–10 apps to compare'; count.className = 'cmp-count'; }
    else if (n < MIN) { count.textContent = n + ' selected, add at least ' + (MIN - n) + ' more'; count.className = 'cmp-count warn'; }
    else { count.textContent = n + ' / ' + MAX + ' apps selected'; count.className = 'cmp-count'; }
  }

  search.addEventListener('input', function () { active = -1; openDrop(); });
  search.addEventListener('focus', function () { openDrop(); });
  search.addEventListener('keydown', function (e) {
    if (e.key === 'ArrowDown') { e.preventDefault(); if (drop.hidden) openDrop(); active = Math.min(active + 1, Math.min(matches.length, 60) - 1); renderDrop(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); active = Math.max(active - 1, 0); renderDrop(); }
    else if (e.key === 'Enter') { var pick = (active >= 0 ? matches[active] : matches[0]); if (!drop.hidden && pick) { e.preventDefault(); addApp(pick._uid); } }
    else if (e.key === 'Escape') { closeDrop(); }
    else if (e.key === 'Backspace' && search.value === '' && sel.length) { removeApp(sel[sel.length - 1]); }
  });
  drop.addEventListener('mousedown', function (e) { var r = e.target.closest('.drow'); if (r) { e.preventDefault(); addApp(r.getAttribute('data-id')); search.focus(); } });
  chipsEl.addEventListener('click', function (e) { var b = e.target.closest('.cx'); if (b) { removeApp(b.getAttribute('data-id')); search.focus(); } });
  clearBtn.addEventListener('click', function () { sel = []; search.value = ''; afterChange(); });
  document.addEventListener('click', function (e) { if (!combo.contains(e.target)) closeDrop(); });

  function camelHead(s) { var m = String(s).match(/^[A-Z][a-z]+|^[a-z]+|^[A-Z]+(?![a-z])/); return m ? m[0] : String(s); }
  function entityOf(f) {
    return { k: f.vector + '|' + (f.label || f.title), label: f.label || f.title, sub: f.vector,
             sev: f.severity, fam: f.group || 'Unmapped', adv: ADVICE[f.vector],
             val: f.count != null ? f.count : true, detail: f.detail || null };
  }
  function eFindings(sev, group) {
    return function (a) {
      return a.details.findings.filter(function (f) { return (!sev || f.severity === sev) && (!group || f.group === group); })
        .map(entityOf);
    };
  }
  function clusterOf(f) {
    if (f.cluster) return f.cluster;
    return (f.vector || '').indexOf('TGAP-') === 0 ? 'APPLE-POLICY' : (f.group || '');
  }
  function eCluster(cluster) {
    return function (a) {
      return a.details.findings.filter(function (f) { return f.polarity !== 'defensive' && clusterOf(f) === cluster; })
        .map(entityOf);
    };
  }
  function sevMix(a, cluster) {
    var counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, total = 0;
    ((a.details || {}).findings || []).forEach(function (f) {
      if (cluster && clusterOf(f) !== cluster) return;
      if (counts[f.severity] == null) return;
      counts[f.severity]++; total++;
    });
    if (!total) return '';
    var bar = SEV.map(function (sv) {
      return counts[sv] ? '<i class="b-' + sv + '" style="flex:' + counts[sv] + '" title="' + counts[sv] + ' ' + sv + '"></i>' : '';
    }).join('');
    return '<div class=sevbar>' + bar + '</div>';
  }

  function eVectors(a) { return a.details.vectors.map(function (v) { return { k: v.code, label: v.code, sub: v.title, sev: v.severity, fam: v.group || 'Unmapped', adv: ADVICE[v.code], val: v.artifacts }; }); }
  function eTrackers(a) { return a.details.trackers.map(function (t) { return { k: t.name, label: t.name, sub: [t.owner, t.country].filter(Boolean).join(' · '), fam: t.category || t.owner || 'Tracker', val: true }; }); }
  function ePermissions(a) { return a.details.permissions.map(function (p) { var l = shortPerm(p.key); return { k: p.key, label: l, sub: p.category || '', fam: camelHead(l), val: true }; }); }
  function noPIE(h) { return !h.pie; }
  function isEncrypted(h) { return !!h.encrypted; }
  function hardeningCount(a, test) {
    if (!a.details || !a.details.hardening) { return null; }
    return a.details.hardening.filter(test).length;
  }
  function hardeningCell(a, test) {
    var v = hardeningCount(a, test);
    return v == null ? '—' : v;
  }

  function eHardening(a) {
    return a.details.hardening.map(function (h) {
      var f = [h.pie ? 'PIE' : 'no PIE'];
      if (h.canary != null) { f.push(h.canary ? 'canary' : 'no canary'); }
      if (h.arc != null) { f.push(h.arc ? 'ARC' : 'no ARC'); }
      if (h.encrypted) { f.push('encrypted'); }
      return { k: h.name, label: h.name, sub: '', fam: '', val: f.join(' · ') };
    });
  }

  function matrixRows(apps, entitiesOf) {
    var n = apps.length;
    var union = {};
    var perApp = apps.map(function (a) {
      var m = {};
      (a.details ? entitiesOf(a) : []).forEach(function (e) {
        var cur = m[e.k];
        if (!cur) {
          cur = m[e.k] = { n: 0, num: null, details: [], val: e.val };
        }
        cur.n++;
        if (typeof e.val === 'number') cur.num = (cur.num || 0) + e.val;
        else if (typeof e.val === 'string') cur.val = e.val;
        if (e.detail && cur.details.indexOf(e.detail) < 0) cur.details.push(e.detail);
        var u = union[e.k];
        if (!u) { u = union[e.k] = { label: e.label, sub: e.sub, sev: e.sev, fam: e.fam || '', adv: e.adv, c: 0 }; }
        else if (e.sev && rank(e.sev) < rank(u.sev)) { u.sev = e.sev; }
        if (cur.n === 1) u.c++;
      });
      return m;
    });
    var keys = Object.keys(union);
    if (!keys.length) return '<tr class=subrow><td class="metric sub"><span class=subnone>no detail</span></td><td class=v colspan=' + n + '></td></tr>';
    var famWorst = {};
    keys.forEach(function (k) {
      var f = union[k].fam, r = rank(union[k].sev);
      if (famWorst[f] == null || r < famWorst[f]) { famWorst[f] = r; }
    });
    keys.sort(function (x, y) {
      var ux = union[x], uy = union[y];
      if (ux.fam !== uy.fam) {
        return (famWorst[ux.fam] - famWorst[uy.fam]) || (ux.fam < uy.fam ? -1 : 1);
      }
      return (rank(ux.sev) - rank(uy.sev))
        || ((ux.sub || '') < (uy.sub || '') ? -1 : (ux.sub || '') > (uy.sub || '') ? 1 : 0)
        || (ux.label < uy.label ? -1 : ux.label > uy.label ? 1 : 0);
    });
    var prevFam = null;
    return keys.map(function (k) {
      var u = union[k], shared = u.c === n;
      var famBreak = (prevFam !== null && u.fam !== prevFam); prevFam = u.fam;
      var cells = perApp.map(function (m) {
        var e = m[k];
        if (!e) return '<td class="v cell-no">·</td>';
        var shown = e.num != null ? e.num : (typeof e.val === 'string' ? e.val : (e.n > 1 ? e.n : '✓'));
        var tip = e.details.length ? ' title="' + esc(e.details.join(' · ')) + '"' : '';
        return '<td class="v cell-yes"' + tip + '>' + esc(String(shown)) + '</td>';
      }).join('');
      var lbl = (u.sev ? '<span class="sdot s-' + u.sev + '"></span>' : '')
        + '<span class=subname' + (shared ? ' shared' : '') + '>' + esc(u.label) + '</span>'
        + (u.sub ? ' <span class=subdim>' + esc(u.sub) + '</span>' : '')
        + (u.adv ? ' <span class=advtip title="' + esc(u.adv) + '">ⓘ</span>' : '');
      return '<tr class="subrow' + (famBreak ? ' famtop' : '') + '"><td class="metric sub">' + lbl + '</td>' + cells + '</tr>';
    }).join('');
  }
  var EXP = {
    'f:all': function (a) { return matrixRows(a, eFindings(null, null)); },
    'f:critical': function (a) { return matrixRows(a, eFindings('critical', null)); },
    'f:high': function (a) { return matrixRows(a, eFindings('high', null)); },
    'f:medium': function (a) { return matrixRows(a, eFindings('medium', null)); },
    'f:low': function (a) { return matrixRows(a, eFindings('low', null)); },
    'f:info': function (a) { return matrixRows(a, eFindings('info', null)); },
    'vectors': function (a) { return matrixRows(a, eVectors); },
    'trackers': function (a) { return matrixRows(a, eTrackers); },
    'permissions': function (a) { return matrixRows(a, ePermissions); },
    'hardening': function (a) { return matrixRows(a, eHardening); }
  };
  function expanderFor(key) {
    if (EXP[key]) return EXP[key];
    if (key.indexOf('c:') === 0) {
      var cl = key.slice(2);
      return function (a) { return matrixRows(a, eCluster(cl)); };
    }
    return null;
  }

  var ROWS = [
    { g: 'Findings' },
    { label: 'Total findings', key: 'f:all', num: function (a) { return a.findingsCount || 0; }, dir: 'low', cell: function (a) { return a.findingsCount || 0; } },
    { label: 'Critical', key: 'f:critical', num: function (a) { return a.criticalCount || 0; }, dir: 'low', cell: function (a) { return a.criticalCount || 0; } },
    { label: 'High', key: 'f:high', num: function (a) { return a.highCount || 0; }, dir: 'low', cell: function (a) { return a.highCount || 0; } },
    { label: 'Medium', key: 'f:medium', num: function (a) { return (a.severityCounts || {}).medium || 0; }, dir: 'low', cell: function (a) { return (a.severityCounts || {}).medium || 0; } },
    { label: 'Low', key: 'f:low', num: function (a) { return (a.severityCounts || {}).low || 0; }, dir: 'low', cell: function (a) { return (a.severityCounts || {}).low || 0; } },
    { label: 'Info', key: 'f:info', num: function (a) { return (a.severityCounts || {}).info || 0; }, dir: null, cell: function (a) { return (a.severityCounts || {}).info || 0; } },
    { g: 'Attack vectors' },
    { label: 'Distinct vectors detected', key: 'vectors', num: function (a) { return a.details ? a.details.vectors.length : null; }, dir: 'low', cell: function (a) { return a.details ? a.details.vectors.length : '—'; } },
    { g: 'Privacy & network' },
    { label: 'Trackers', key: 'trackers', num: function (a) { return a.trackerCount || 0; }, dir: 'low', cell: function (a) { return a.trackerCount || 0; } },
    { label: 'Declared permissions', key: 'permissions', num: function (a) { return a.details ? a.details.permissions.length : null; }, dir: 'low', cell: function (a) { return a.details ? a.details.permissions.length : '—'; } },
    { label: 'Hard-coded credentials', num: function (a) { return a.secretCount || 0; }, dir: 'low', cell: function (a) { return a.secretCount || 0; } },
    { label: 'ATS arbitrary loads', num: function (a) { return a.atsArbitraryLoads ? 1 : 0; }, dir: 'low', cell: function (a) { return a.atsArbitraryLoads ? '⚠︎ yes' : 'no'; } },
    { g: 'Binary hardening' },
    { label: 'Binaries without PIE', key: 'hardening', num: function (a) { return hardeningCount(a, noPIE); }, dir: 'low', cell: function (a) { return hardeningCell(a, noPIE); } },
    { label: 'FairPlay-encrypted binaries', num: function (a) { return hardeningCount(a, isEncrypted); }, dir: null, cell: function (a) { return hardeningCell(a, isEncrypted); } },
    { g: 'Metadata' },
    { label: 'Category', optional: function (a) { return a.category; }, dir: null, cell: function (a) { return esc(a.category || '—'); } },
    { label: 'Developer', optional: function (a) { return a.artist; }, dir: null, cell: function (a) { return esc(a.artist || '—'); } },
    { label: 'Version', dir: null, cell: function (a) { return esc(a.version || '—'); } },
    { label: 'Chart rank', optional: function (a) { return a.chartRank; }, num: function (a) { return a.chartRank || null; }, dir: 'low', cell: function (a) { return a.chartRank != null ? '#' + a.chartRank : '—'; } },
    { label: 'Download size', num: function (a) { return a.sizeBytes || null; }, dir: null, cell: function (a) { return a.sizeBytes ? bytes(a.sizeBytes) : '—'; } },
    { label: 'Scan time', num: function (a) { return a.scanSeconds || null; }, dir: null, cell: function (a) { return a.scanSeconds != null ? a.scanSeconds.toFixed(1) + 's' : '—'; } }
  ];
  var CLUSTER_ORDER = ['MASVS-PRIVACY', 'MASVS-NETWORK', 'MASVS-STORAGE', 'MASVS-CRYPTO',
                       'MASVS-PLATFORM', 'MASVS-CODE', 'MASVS-RESILIENCE', 'MASVS-AUTH',
                       'APPLE-POLICY', 'INDICATORS'];
  function clusterRows(apps) {
    return CLUSTER_ORDER.filter(function (g) {
      return apps.some(function (a) { return ((a.clusterCounts || {})[g] || 0) > 0; });
    }).map(function (g) {
      return { label: g.replace('MASVS-', ''), key: 'c:' + g, dir: 'low',
        num: function (a) { return (a.clusterCounts || {})[g] || 0; },
        cell: function (a) {
          var n = (a.clusterCounts || {})[g] || 0;
          return '<span class=grptot>' + n + '</span>' + (n ? sevMix(a, g) : '');
        } };
    });
  }

  function renderCompare() {
    cmpCharts.forEach(function (c) { try { c.dispose(); } catch (e) {} }); cmpCharts = [];
    var apps = sel.map(function (id) { return byId[id]; }).filter(Boolean);
    curApps = apps;
    if (apps.length < MIN) { out.innerHTML = ''; return; }

    var rows = ROWS.filter(function (r) {
      return !r.optional || apps.some(function (a) { return r.optional(a) != null && r.optional(a) !== ''; });
    });
    var ci = rows.findIndex(function (r) { return r.g === 'Findings'; });
    var cr = [{ g: 'Findings by cluster' }].concat(clusterRows(apps));
    rows = rows.slice(0, ci).concat(cr, rows.slice(ci));

    var html = '';
    if (typeof echarts !== 'undefined') {
      html += '<div class=cmp-charts><div class=card><h3>Findings by severity</h3>'
            + '<div id=cmpSev class="chart tall"></div></div></div>';
    }
    html += '<div class=scroll><table class=cmp><thead><tr><th class=metric>Metric</th>';
    apps.forEach(function (a) { html += '<th class=v title="' + esc(a.appStoreName) + '">' + dot(a) + ' ' + esc(shortName(a.appStoreName)) + '</th>'; });
    html += '</tr></thead><tbody>';

    rows.forEach(function (row) {
      if (row.g) { html += '<tr class=grp><td class=metric>' + esc(row.g) + '</td><td colspan=' + apps.length + '></td></tr>'; return; }
      var lo = null, hi = null, common = null;
      if (row.dir) {
        var nums = apps.map(row.num).filter(function (v) { return v != null; });
        if (nums.length) {
          hi = Math.max.apply(null, nums); lo = Math.min.apply(null, nums);
          if (hi === lo) { lo = hi = null; }
          var freq = {};
          nums.forEach(function (v) { freq[v] = (freq[v] || 0) + 1; });
          Object.keys(freq).forEach(function (k) { if (freq[k] * 2 > nums.length) common = +k; });
        }
      }
      var exp = row.key ? expanderFor(row.key) : null;
      html += '<tr' + (exp ? ' class=expandable data-key="' + row.key + '"' : '') + '><td class=metric>' + esc(row.label) + '</td>';
      apps.forEach(function (a) {
        var v = row.num ? row.num(a) : null, cls = 'v', style = '';
        if (lo !== null && v != null) {
          var t = (v - lo) / (hi - lo);
          if (row.dir === 'high') t = 1 - t;
          cls += ' ramp ' + (t > 0.5 ? 'hi' : 'lo');
          if ((t === 0 || t === 1) && v !== common) cls += ' edge';
          var a2 = v === common ? 0 : (t > 0.5 ? (t - 0.5) * 2 : (0.5 - t) * 2);
          style = ' style="--t:' + a2.toFixed(2) + '"';
        }
        html += '<td class="' + cls + '"' + style + '>' + row.cell(a) + '</td>';
      });
      html += '</tr>';
    });
    html += '</tbody></table></div>';
    out.innerHTML = html;
    if (typeof echarts !== 'undefined') {
      drawSev(apps);
      requestAnimationFrame(function () {
        cmpCharts.forEach(function (c) { try { c.resize(); } catch (e) {} });
      });
    }
  }

  out.addEventListener('click', function (e) {
    var tr = e.target.closest('tr.expandable'); if (!tr || !out.contains(tr)) return;
    if (tr.classList.contains('open')) {
      var n = tr.nextElementSibling;
      while (n && n.classList.contains('subrow')) { var x = n; n = n.nextElementSibling; x.parentNode.removeChild(x); }
      tr.classList.remove('open');
    } else {
      var fn = expanderFor(tr.getAttribute('data-key'));
      tr.insertAdjacentHTML('afterend', fn ? fn(curApps) : '');
      tr.classList.add('open');
    }
  });

  function drawSev(apps) {
    var el = document.getElementById('cmpSev'); if (!el) return;
    el.classList.remove('tall'); el.classList.add('auto');
    el.style.height = Math.max(288, apps.length * 38 + 68) + 'px';
    var c = echarts.init(el, null, { renderer: 'canvas' }); cmpCharts.push(c);
    var rows = apps.slice().reverse();
    var names = rows.map(function (a) { return shortName(a.appStoreName); });
    var CA = (window.__catAxis || function () { return { left: 150, label: { fontSize: 11, width: 144, overflow: 'truncate' } }; })(names, el, 11);
    var totals = rows.map(function (a) {
      return SEV.reduce(function (n, sv) { return n + (((a.severityCounts || {})[sv]) || 0); }, 0);
    });
    var maxTotal = Math.max.apply(null, totals.concat([1]));
    var series = SEV.map(function (sev, si) {
      return { name: sev, type: 'bar', stack: 'sev', barWidth: '56%',
        itemStyle: { color: SC[sev] },
        emphasis: { focus: 'series' },
        label: si === SEV.length - 1
          ? { show: true, position: 'right', color: T('ink-2', '#9aa4b0'), fontSize: 11,
              formatter: function (p) { return totals[p.dataIndex]; } }
          : { show: false },
        data: rows.map(function (a) { return ((a.severityCounts || {})[sev]) || 0; }) };
    });
    c.setOption({ backgroundColor: 'transparent', textStyle: { color: T('ink', '#c7ccd1') },
      legend: { bottom: 0, itemWidth: 11, itemHeight: 11,
        textStyle: { color: T('ink-mute', '#8b929b'), fontSize: 11 },
        data: SEV.slice() },
      grid: { left: CA.left, right: 52, top: 12, bottom: 34, containLabel: false },
      xAxis: { type: 'value', max: Math.ceil(maxTotal * 1.08),
        axisLabel: { color: T('ink-mute', '#8b929b'), fontSize: 10 },
        splitLine: { lineStyle: { color: T('br', '#1c222b') } } },
      yAxis: { type: 'category', data: names, axisLabel: CA.label,
        axisTick: { show: false }, axisLine: { lineStyle: { color: T('br', '#2a313a') } } },
      series: series,
      tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' },
        formatter: function (ps) {
          if (!ps.length) return '';
          var i = ps[0].dataIndex;
          var s = '<b>' + esc(rows[i].appStoreName) + '</b><br>' + totals[i] + ' findings';
          ps.slice().reverse().forEach(function (p) {
            if (!p.value) return;
            s += '<br>' + p.marker + p.seriesName + ': <b>' + p.value + '</b>';
          });
          return s;
        } } });
  }
  window.addEventListener('resize', function () { cmpCharts.forEach(function (c) { try { c.resize(); } catch (e) {} }); });

  updateCount(); renderChips();
  window.__redrawComparator = function () { if (sel.length >= 2) renderCompare(); };

})();
