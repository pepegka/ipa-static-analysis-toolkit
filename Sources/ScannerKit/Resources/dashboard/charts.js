function escH(v) {
  return String(v == null ? '' : v).replace(/[&<>"']/g, function (c) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
  });
}
function tok(name, fallback) {
  try {
    var v = getComputedStyle(document.documentElement).getPropertyValue('--' + name).trim();
    return v || fallback;
  } catch (e) { return fallback; }
}

window.__drawDashboard = function () {
  if (typeof echarts === 'undefined') { document.getElementById('offline').style.display = 'block'; return; }
  var R = JSON.parse(document.getElementById('msdata').textContent);
  var ST = R.stats || {};
  var APPS = (R.apps || []).filter(function (a) { return a.error == null && a.findingsCount != null; });
  if (window.__msCharts) {
    window.__msCharts.forEach(function (c) { try { c.dispose(); } catch (e) {} });
  }
  var charts = window.__msCharts = [];
  var AX = tok('br', '#2a313a'), GRID = tok('br', '#1c222b'),
      TXT = tok('ink', '#c7ccd1'), DIM = tok('ink-mute', '#8b929b'),
      SURFACE = tok('panel-hi', '#161b22'), RAISED = tok('raised', '#1a1f27');
  var RC = { green: tok('good', '#1aa050'), yellow: tok('warn', '#d1a417'),
             orange: tok('serious', '#e0820a'), red: tok('critical', '#e0392f') };
  var SEV = ['info', 'low', 'medium', 'high', 'critical'];
  var DAPPS = APPS.filter(function (a) { return a.details; });
  function clusterOf(f) {
    if (f.cluster) return f.cluster;
    return (f.vector || '').indexOf('TGAP-') === 0 ? 'APPLE-POLICY' : (f.group || '');
  }
  function isMitigation(f) { return f.polarity === 'defensive'; }
  function isWeakness(f) { return !f.polarity || f.polarity === 'offensive'; }
  function isReachable(f) { return isWeakness(f) && f.severity !== 'info'; }
  var MIN_CAT_N = 3;
  var SC = { info: tok('sev-info-fill', '#4d545f'), low: tok('sev-low-fill', '#7f8a9e'),
             medium: tok('sev-medium-fill', '#d6b60a'), high: tok('sev-high-fill', '#e0820a'),
             critical: tok('sev-critical-fill', '#e0392f') };
  window.__sevColors = SC;
  var PALETTE = [tok('cat-1'), tok('cat-2'), tok('cat-3'), tok('cat-4'), tok('cat-5'), tok('cat-6')];
  var OTHER = tok('ink-ghost', '#39414c');
  function catColor(i) { return i < PALETTE.length ? PALETTE[i] : OTHER; }

  function mk(id) {
    var d = document.getElementById(id); if (!d) return null;
    var c = echarts.init(d, null, { renderer: 'canvas' });
    charts.push(c);
    if (window.ResizeObserver) {
      var ro = new ResizeObserver(function () { c.resize(); });
      ro.observe(d);
    }
    return c;
  }
  var FONT = '-apple-system, system-ui, sans-serif';

  function later(fn, ms) { if (typeof setTimeout === 'function') setTimeout(fn, ms || 0); }
  function nextFrame(fn) { later(fn, 32); }

  function base(o) {
    o.backgroundColor = 'transparent';
    o.textStyle = { color: TXT, fontFamily: FONT };
    var tip = o.tooltip;
    function themed(t) {
      t = t || {};
      t.backgroundColor = RAISED; t.borderColor = tok('br-hi', '#283041'); t.borderWidth = 1;
      t.textStyle = { color: TXT, fontSize: 11.5, fontFamily: FONT };
      t.extraCssText = 'box-shadow:0 8px 24px -12px rgba(0,0,0,.7);border-radius:8px';
      return t;
    }
    if (Object.prototype.toString.call(tip) === '[object Array]') o.tooltip = tip.map(themed);
    else if (tip) o.tooltip = themed(tip);
    return o;
  }

  var _measureCtx = (function () {
    try { return document.createElement('canvas').getContext('2d'); } catch (e) { return null; }
  })();

  function textWidth(str, px) {
    if (!_measureCtx) return String(str).length * (px * 0.58);
    _measureCtx.font = px + 'px ' + FONT;
    return _measureCtx.measureText(String(str)).width;
  }

  function widestLabel(labels, px) {
    return labels.reduce(function (w, l) { return Math.max(w, textWidth(l, px)); }, 0);
  }

  function catAxis(cats, dom, px, opts) {
    px = px || 11;
    opts = opts || {};
    var lines = opts.lines || 1;
    var boxW = (dom && dom.clientWidth) || 441;
    var cap = Math.round(boxW * (opts.maxFrac || 0.44));
    var need = Math.ceil(widestLabel(cats, px) / lines) + (lines > 1 ? 30 : 18);
    var gutter = Math.min(cap, need);
    var label = { color: TXT, fontSize: px, width: Math.max(40, gutter - 6),
                  overflow: lines > 1 ? 'none' : 'truncate' };
    if (lines > 1) {
      var w = Math.max(40, gutter - 10);
      label.lineHeight = px + 3;
      label.formatter = function (v) { return wrapWords(String(v), px, w, lines); };
    }
    return { left: gutter, label: label };
  }
  function wrapWords(text, px, width, maxLines) {
    var words = text.split(/\s+/), out = [], cur = '';
    for (var i = 0; i < words.length; i++) {
      var next = cur ? cur + ' ' + words[i] : words[i];
      if (!cur || textWidth(next, px) <= width) { cur = next; continue; }
      out.push(cur); cur = words[i];
      if (out.length === maxLines - 1) { cur = words.slice(i).join(' '); break; }
    }
    if (cur) out.push(cur);
    var last = out[out.length - 1];
    if (out.length === maxLines && textWidth(last, px) > width) {
      while (last.length > 1 && textWidth(last + '…', px) > width) last = last.slice(0, -1);
      out[out.length - 1] = last + '…';
    }
    return out.join('\n');
  }
  window.__catAxis = catAxis;
  function val(items) { return (items || []).filter(function (i) { return i.count > 0; }); }
  var HAS_CATS = APPS.some(function (a) { return a.category && a.category !== '(unknown)'; });
  function note(id, msg) { var c = mk(id); if (!c) return; c.setOption(base({
    title: { text: msg, left: 'center', top: 'middle', textStyle: { color: DIM, fontSize: 12, fontWeight: 400 } } })); }
  var NO_CAT = 'No App Store category data (scan-only run)';
  function shortPerm(k) { return String(k).replace(/^NS/, '').replace(/UsageDescription$/, '').replace(/([a-z])([A-Z])/g, '$1 $2'); }
  function permFamily(key) {
    var k = String(key).replace(/(UsageDescription|Dictionary)$/, '');
    function P(fam, sub) { return { fam: fam, sub: sub }; }
    if (/^NSLocationTemporary/.test(k)) return P('Location', 'Temporary');
    if (/^NSLocationAlwaysAndWhenInUse/.test(k)) return P('Location', 'Always & when-in-use');
    if (/^NSLocationAlways/.test(k)) return P('Location', 'Always');
    if (/^NSLocationWhenInUse/.test(k)) return P('Location', 'When in use');
    if (/^NSLocation/.test(k)) return P('Location', null);
    if (/^NSPhotoLibraryAdd/.test(k)) return P('Photos', 'Add only');
    if (/^NSPhotoLibrary/.test(k)) return P('Photos', 'Full library');
    if (/^NSCalendarsWriteOnly/.test(k)) return P('Calendar', 'Write-only');
    if (/^NSCalendarsFull/.test(k)) return P('Calendar', 'Full access');
    if (/^NSCalendars?/.test(k)) return P('Calendar', 'Events');
    if (/^NSRemindersFull/.test(k)) return P('Reminders', 'Full access');
    if (/^NSReminders/.test(k)) return P('Reminders', null);
    if (/^NSBluetoothPeripheral/.test(k)) return P('Bluetooth', 'Peripheral');
    if (/^NSBluetooth/.test(k)) return P('Bluetooth', 'Always');
    if (/^NSHealthShare/.test(k)) return P('Health', 'Read');
    if (/^NSHealthUpdate/.test(k)) return P('Health', 'Write');
    if (/^NSHealth/.test(k)) return P('Health', null);
    if (/^NSCamera/.test(k)) return P('Camera', null);
    if (/^NSMicrophone/.test(k)) return P('Microphone', null);
    if (/^NSContacts/.test(k)) return P('Contacts', null);
    if (/^NSMotion/.test(k)) return P('Motion & fitness', null);
    if (/^NSFaceID/.test(k)) return P('Face ID', null);
    if (/^NSSpeechRecognition/.test(k)) return P('Speech recognition', null);
    if (/^NSUserTracking/.test(k)) return P('App tracking (ATT)', null);
    if (/^(NSAppleMusic|NSMediaLibrary)/.test(k)) return P('Media library', null);
    if (/^NSLocalNetwork/.test(k)) return P('Local network', null);
    if (/^NSSiri/.test(k)) return P('Siri', null);
    if (/^NSNearbyInteraction/.test(k)) return P('Nearby interaction', null);
    if (/^NSHomeKit/.test(k)) return P('HomeKit', null);
    if (/^NSAppleEvents|^NSSystemAdministration/.test(k)) return P('Automation', null);
    return P(shortPerm(key), null);
  }
  function permFamilyStats() {
    var withPerms = APPS.filter(function (a) { return a.details && a.details.permissions; });
    var fam = {};
    function bump(name) { return fam[name] || (fam[name] = { apps: 0, subs: {} }); }
    if (withPerms.length) {
      withPerms.forEach(function (a) {
        var seenF = {}, seenS = {};
        a.details.permissions.forEach(function (p) {
          var pf = permFamily(p.key), f = bump(pf.fam);
          if (!seenF[pf.fam]) { seenF[pf.fam] = 1; f.apps++; }
          if (pf.sub) { var sk = pf.fam + '|' + pf.sub; if (!seenS[sk]) { seenS[sk] = 1; f.subs[pf.sub] = (f.subs[pf.sub] || 0) + 1; } }
        });
      });
    } else {
      (ST.topPermissions || []).forEach(function (i) { var pf = permFamily(i.label), f = bump(pf.fam); f.apps += i.count; if (pf.sub) f.subs[pf.sub] = (f.subs[pf.sub] || 0) + i.count; });
    }
    return Object.keys(fam).map(function (k) {
      var subs = Object.keys(fam[k].subs).sort(function (a, b) { return fam[k].subs[b] - fam[k].subs[a]; });
      return { label: k, count: fam[k].apps,
               detail: subs.map(function (s) { return s + ' (' + fam[k].subs[s] + ')'; }).join(' · ') };
    }).sort(function (a, b) { return b.count - a.count; });
  }

  function foldTail(data, keep) {
    keep = keep || PALETTE.length;
    if (data.length <= keep + 1) return data;
    var head = data.slice(0, keep);
    var tail = data.slice(keep);
    var sum = tail.reduce(function (n, d) { return n + (d.value || 0); }, 0);
    if (sum <= 0) return head;
    head.push({ name: 'Other (' + tail.length + ')', value: sum, itemStyle: { color: OTHER } });
    return head;
  }

  function rankedSlices(m) {
    return Object.keys(m)
      .map(function (k) { return { name: k, value: m[k] }; })
      .sort(function (x, y) { return y.value - x.value || (x.name < y.name ? -1 : 1); })
      .map(function (d, i) { d.itemStyle = { color: catColor(i) }; return d; });
  }

  var NAMED_GRID = { left: 26, right: 16, top: 16, bottom: 34, containLabel: true };

  function axisNamed(name, vertical, extra) {
    var ax = { name: name, nameLocation: 'middle', nameGap: vertical ? 30 : 26,
               nameTextStyle: { color: DIM }, axisLabel: { color: DIM },
               splitLine: { lineStyle: { color: GRID } } };
    if (vertical) ax.nameRotate = 90;
    Object.keys(extra || {}).forEach(function (k) { ax[k] = extra[k]; });
    return ax;
  }

  function appNameAxisLabel(names) {
    return { color: TXT, rotate: names.length > 8 ? 40 : 0,
             interval: names.length > 60 ? 4 : 0,
             width: 110, overflow: 'truncate', lineHeight: 13, hideOverlap: true };
  }

  var MIN_SLICE_DEG = 4;

  var PIE_LABEL_MIN_W = 380;

  function legendRows(names, w) {
    var run = names.reduce(function (n, s) { return n + s.length * 6.2 + 30; }, 0);
    return Math.max(1, Math.ceil(run / Math.max(120, w - 16)));
  }

  function pieLayout(dom, donut, legendNames) {
    var w = dom.clientWidth || 441, h = dom.clientHeight || 288;
    var labelled = w >= PIE_LABEL_MIN_W;
    var gutter = labelled ? Math.max(70, Math.min(104, w * 0.24)) : 6;
    var reserve = legendNames.length ? legendRows(legendNames, w) * 18 + 14 : 0;
    var outer = Math.max(46, Math.min((h - reserve) * 0.46, w / 2 - gutter));
    return {
      labelled: labelled,
      labelWidth: Math.max(56, Math.round(gutter - 14)),
      center: ['50%', Math.round((h - reserve) / 2)],
      radius: donut ? [Math.round(outer * 0.62), Math.round(outer)] : Math.round(outer)
    };
  }

  function pie(id, data, donut) {
    var dom = document.getElementById(id);
    var c = mk(id); if (!c) return;
    var total = data.reduce(function (n, d) { return n + (d.value || 0); }, 0);
    var slivers = total > 0
      ? data.filter(function (d) { return 360 * (d.value || 0) / total < MIN_SLICE_DEG; })
            .map(function (d) { return d.name; })
      : [];

    var allNames = data.map(function (d) { return d.name; });

    function render(first) {
      var wide = (dom.clientWidth || 441) >= PIE_LABEL_MIN_W;
      var legendNames = !wide ? allNames
        : (slivers.length && allNames.length <= 8) ? allNames
        : slivers;
      var L = pieLayout(dom, donut, legendNames);
      var opt = {
        series: [{ type: 'pie', radius: L.radius, center: L.center,
          minShowLabelAngle: L.labelled ? MIN_SLICE_DEG : 361,
          label: { show: L.labelled, color: TXT, fontSize: 11,
                   width: L.labelWidth, overflow: 'break', lineHeight: 13 } }]
      };
      if (first) {
        opt.tooltip = { trigger: 'item', formatter: '{b}: {c} ({d}%)' };
        opt.series[0].avoidLabelOverlap = true;
        opt.series[0].itemStyle = { borderColor: SURFACE, borderWidth: 2 };
        opt.series[0].labelLayout = { hideOverlap: true };
        opt.series[0].data = data;
      }
      opt.legend = legendNames.length
        ? { type: 'plain', bottom: 0, data: legendNames, itemWidth: 12, itemHeight: 8,
            itemGap: 10, textStyle: { color: DIM, fontSize: 11 } }
        : { show: false };
      c.setOption(first ? base(opt) : opt, { replaceMerge: ['legend'] });
    }

    render(true);
    if (window.ResizeObserver) {
      var last = dom.clientWidth + 'x' + dom.clientHeight;
      new ResizeObserver(function () {
        var now = dom.clientWidth + 'x' + dom.clientHeight;
        if (now === last) return;
        last = now;
        render(false);
      }).observe(dom);
    }
  }

  function hbar(id, items, colorFn, limit) {
    var d = document.getElementById(id);
    items = (items || []).slice(0, limit || 12);
    if (d && items.length) {
      d.classList.add('auto');
      d.style.height = Math.max(288, items.length * 30 + 54) + 'px';
    }
    var c = mk(id); if (!c) return;
    var cats = items.map(function (i) { return i.label; }).reverse();
    var vals = items.map(function (i) {
      return { value: i.count, name: i.label, detail: i.detail || '',
               itemStyle: { color: (typeof colorFn === 'function' ? colorFn(i.label) : colorFn), borderRadius: 3 } };
    }).reverse();
    var CA = catAxis(cats, d);
    c.setOption(base({
      grid: { left: CA.left, right: 36, top: 8, bottom: 26, containLabel: false },
      tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' },
        formatter: function (p) { var d = p[0].data; return escH(d.name) + (d.detail ? '<br><span style="color:' + DIM + '">' + escH(d.detail) + '</span>' : '') + '<br><b>' + d.value + '</b> app(s)'; } },
      xAxis: { type: 'value', axisLabel: { color: DIM }, splitLine: { lineStyle: { color: GRID } } },
      yAxis: { type: 'category', data: cats, axisLabel: CA.label, axisLine: { lineStyle: { color: AX } }, axisTick: { show: false } },
      series: [{ type: 'bar', data: vals, barWidth: '62%', label: { show: true, position: 'right', color: DIM } }]
    }));
  }

  function tileFits(rect, d, unit) {
    if (!rect) return true;
    var need = Math.max(textWidth(d.name, 12.5), textWidth(d.value + ' ' + (unit || ''), 10.5));
    return rect.width >= need + 16 && rect.height >= 38;
  }

  function treemapOption(data, unit, dropped) {
    return base({
      title: dropped ? { bottom: 0, left: 2, textStyle: { color: DIM, fontSize: 11, fontWeight: 400 },
                         text: '+ ' + dropped + ' smaller, listed in the table' } : { show: false },
      tooltip: { formatter: function (p) { return escH(p.name) + ': <b>' + p.value + '</b> ' + escH(unit || ''); } },
      series: [{ type: 'treemap', roam: false, nodeClick: false, breadcrumb: { show: false },
        left: 1, right: 1, top: 1, bottom: dropped ? 20 : 1,
        label: { show: true, position: 'insideTopLeft', distance: 5, lineHeight: 15, overflow: 'truncate',
          formatter: function (p) { return '{n|' + p.name + '}\n{v|' + p.value + ' ' + (unit || '') + '}'; },
          rich: { n: { fontSize: 12.5, fontWeight: 700, color: '#fff' },
                  v: { fontSize: 10.5, color: 'rgba(255,255,255,.82)', padding: [2, 0, 0, 0] } } },
        itemStyle: { borderColor: SURFACE, borderWidth: 2, gapWidth: 2, borderRadius: 3 },
        data: data }]
    });
  }

  function treemap(c, data, unit, dom) {
    if (!c) return;
    var shown = data.slice(), dropped = 0;
    for (var pass = 0; pass < 4; pass++) {
      c.setOption(treemapOption(shown, unit, dropped), { replaceMerge: ['series', 'title'] });
      var layout = [];
      try {
        var series = c.getModel().getSeriesByIndex(0);
        var store = series.getData();
        store.each(function (i) { layout[i] = store.getItemLayout(i); });
      } catch (e) { break; }
      var keep = shown.filter(function (d, i) { return tileFits(layout[i + 1], d, unit); });
      if (!keep.length || keep.length === shown.length) break;
      dropped += shown.length - keep.length;
      shown = keep;
    }
    if (dropped) c.setOption(treemapOption(shown, unit, dropped), { replaceMerge: ['series', 'title'] });
  }

  function vbar(id, items, colorFn) {
    var c = mk(id); if (!c) return;
    items = items || [];
    c.setOption(base({
      grid: { left: 6, right: 12, top: 16, bottom: 6, containLabel: true },
      tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
      xAxis: { type: 'category', data: items.map(function (i) { return i.label; }), axisLabel: { color: TXT }, axisLine: { lineStyle: { color: AX } } },
      yAxis: { type: 'value', axisLabel: { color: DIM }, splitLine: { lineStyle: { color: GRID } } },
      series: [{ type: 'bar', barWidth: '52%', label: { show: true, position: 'top', color: DIM },
        data: items.map(function (i) { return { value: i.count, itemStyle: { color: (typeof colorFn === 'function' ? colorFn(i.label) : colorFn), borderRadius: [4, 4, 0, 0] } }; }) }]
    }));
  }

  var CLUSTER_ORDER = ['MASVS-PRIVACY', 'MASVS-NETWORK', 'MASVS-STORAGE', 'MASVS-CRYPTO',
                       'MASVS-PLATFORM', 'MASVS-CODE', 'MASVS-RESILIENCE', 'MASVS-AUTH',
                       'APPLE-POLICY', 'INDICATORS'];

  (function () {
    var c = mk('c_cluster'); if (!c) return;
    var tally = {};
    CLUSTER_ORDER.forEach(function (k) { tally[k] = { info: 0, low: 0, medium: 0, high: 0, critical: 0 }; });
    DAPPS.forEach(function (a) {
      (a.details.findings || []).forEach(function (f) {
        if (isMitigation(f)) return;
        var k = clusterOf(f);
        if (tally[k]) { tally[k][f.severity] = (tally[k][f.severity] || 0) + 1; }
      });
    });
    var names = CLUSTER_ORDER.filter(function (k) {
      return SEV.reduce(function (n, s) { return n + tally[k][s]; }, 0) > 0;
    });
    if (!names.length) { note('c_cluster', 'No findings to cluster.'); return; }
    var CG = catAxis(names, document.getElementById('c_cluster'));
    c.setOption(base({
      tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
      legend: { type: 'scroll', bottom: 0, textStyle: { color: DIM } },
      grid: { left: CG.left, right: 24, top: 10, bottom: 40, containLabel: false },
      xAxis: { type: 'value', axisLabel: { color: DIM }, splitLine: { lineStyle: { color: GRID } } },
      yAxis: { type: 'category', data: names.slice().reverse(), axisLabel: CG.label, axisLine: { lineStyle: { color: AX } } },
      series: SEV.map(function (sev) {
        return { name: sev, type: 'bar', stack: 'c', emphasis: { focus: 'series' },
          itemStyle: { color: SC[sev] },
          data: names.slice().reverse().map(function (n) { return tally[n][sev] || 0; }) };
      })
    }));
  })();

  (function () {
    var c = mk('c_maswe'); if (!c) return;
    var items = val(ST.masweFrequency).slice(0, 18);
    if (!items.length) { note('c_maswe', 'No MASWE weakness classes bound.'); return; }
    var labels = items.map(function (i) { return i.detail ? i.label + ' · ' + i.detail : i.label; });
    var mdom = document.getElementById('c_maswe');
    var narrow = mdom && mdom.clientWidth && mdom.clientWidth < 520;
    var lines = narrow ? 3 : 2, rowH = narrow ? 54 : 40;
    if (mdom) { mdom.classList.add('auto'); mdom.style.height = (items.length * rowH + 54) + 'px'; }
    var MG = catAxis(labels, mdom, 11, { lines: lines, maxFrac: 0.52 });
    c.setOption(base({
      grid: { left: MG.left, right: 44, top: 8, bottom: 26, containLabel: false },
      tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' },
        formatter: function (p) { return escH(p[0].name) + '<br><b>' + p[0].value + '</b> finding(s)'; } },
      xAxis: { type: 'value', axisLabel: { color: DIM }, splitLine: { lineStyle: { color: GRID } } },
      yAxis: { type: 'category', data: labels.slice().reverse(), axisLabel: MG.label, axisLine: { lineStyle: { color: AX } }, axisTick: { show: false } },
      series: [{ type: 'bar', barWidth: '62%', label: { show: true, position: 'right', color: DIM },
        data: items.slice().reverse().map(function (i) { return { value: i.count, itemStyle: { color: tok('accent-2', '#a974e0'), borderRadius: 3 } }; }) }]
    }));
  })();

  (function () {
    var c = mk('c_clusterreach'); if (!c) return;
    var pool = DAPPS.length ? DAPPS : APPS;
    var reach = CLUSTER_ORDER.map(function (k) {
      return { label: k, count: pool.filter(function (a) {
        if (!a.details) return ((a.clusterCounts || {})[k] || 0) > 0;
        return (a.details.findings || []).some(function (f) { return isReachable(f) && clusterOf(f) === k; });
      }).length };
    }).filter(function (i) { return i.count > 0; });
    if (!reach.length) { note('c_clusterreach', 'No clusters hit.'); return; }
    var RG = catAxis(reach.map(function (i) { return i.label; }), document.getElementById('c_clusterreach'));
    c.setOption(base({
      grid: { left: RG.left, right: 44, top: 8, bottom: 26, containLabel: false },
      tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' },
        formatter: function (p) { return escH(p[0].name) + '<br><b>' + p[0].value + '</b> of ' + pool.length + ' app(s) with a low-or-above weakness here'; } },
      xAxis: { type: 'value', max: pool.length, axisLabel: { color: DIM }, splitLine: { lineStyle: { color: GRID } } },
      yAxis: { type: 'category', data: reach.map(function (i) { return i.label; }).reverse(), axisLabel: RG.label, axisLine: { lineStyle: { color: AX } }, axisTick: { show: false } },
      series: [{ type: 'bar', barWidth: '62%', label: { show: true, position: 'right', color: DIM },
        data: reach.slice().reverse().map(function (i) { return { value: i.count, itemStyle: { color: tok('accent', '#4a8ad6'), borderRadius: 3 } }; }) }]
    }));
  })();

  function originOf(f) {
    var fw = f.framework;
    if (!fw || fw === '(main)' || /\.appex$/i.test(fw)) return null;
    return fw;
  }

  (function () {
    var c = mk('c_origin'); if (!c) return;
    if (!DAPPS.length) { note('c_origin', 'No per-app detail in this dashboard.'); return; }
    var own = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
    var sdk = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
    DAPPS.forEach(function (a) {
      (a.details.findings || []).forEach(function (f) {
        if (isMitigation(f)) return;
        var b = originOf(f) ? sdk : own;
        b[f.severity] = (b[f.severity] || 0) + 1;
      });
    });
    var rows = ['First-party code', 'Embedded SDKs'];
    var OG = catAxis(rows, document.getElementById('c_origin'));
    c.setOption(base({
      tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
      legend: { type: 'scroll', bottom: 0, textStyle: { color: DIM } },
      grid: { left: OG.left, right: 24, top: 10, bottom: 40, containLabel: false },
      xAxis: { type: 'value', axisLabel: { color: DIM }, splitLine: { lineStyle: { color: GRID } } },
      yAxis: { type: 'category', data: rows.slice().reverse(), axisLabel: OG.label, axisLine: { lineStyle: { color: AX } } },
      series: SEV.map(function (sev) {
        return { name: sev, type: 'bar', stack: 'o', emphasis: { focus: 'series' },
          itemStyle: { color: SC[sev] },
          data: [sdk[sev] || 0, own[sev] || 0] };
      })
    }));
  })();

  (function () {
    var c = mk('c_sdkfindings'); if (!c) return;
    if (!DAPPS.length) { note('c_sdkfindings', 'No per-app detail in this dashboard.'); return; }
    var byFw = {}, appsPerFw = {};
    DAPPS.forEach(function (a) {
      var seen = {};
      (a.details.findings || []).forEach(function (f) {
        if (isMitigation(f)) return;
        var fw = originOf(f); if (!fw) return;
        byFw[fw] = (byFw[fw] || 0) + 1;
        if (!seen[fw]) { seen[fw] = 1; appsPerFw[fw] = (appsPerFw[fw] || 0) + 1; }
      });
    });
    var items = Object.keys(byFw).map(function (k) { return { label: k, count: byFw[k], apps: appsPerFw[k] }; })
      .sort(function (x, y) { return y.count - x.count; }).slice(0, 18);
    if (!items.length) { note('c_sdkfindings', 'No findings attributed to an embedded SDK.'); return; }
    var FG = catAxis(items.map(function (i) { return i.label; }), document.getElementById('c_sdkfindings'));
    c.setOption(base({
      grid: { left: FG.left, right: 56, top: 8, bottom: 26, containLabel: false },
      tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' },
        formatter: function (p) { var d = p[0].data; return escH(p[0].name) + '<br><b>' + d.value + '</b> finding(s) across ' + d.apps + ' app(s)'; } },
      xAxis: { type: 'value', axisLabel: { color: DIM }, splitLine: { lineStyle: { color: GRID } } },
      yAxis: { type: 'category', data: items.map(function (i) { return i.label; }).reverse(), axisLabel: FG.label, axisLine: { lineStyle: { color: AX } }, axisTick: { show: false } },
      series: [{ type: 'bar', barWidth: '62%', label: { show: true, position: 'right', color: DIM },
        data: items.slice().reverse().map(function (i) { return { value: i.count, apps: i.apps, itemStyle: { color: tok('accent-2', '#a974e0'), borderRadius: 3 } }; }) }]
    }));
  })();

  (function () {
    var c = mk('c_hardflags'); if (!c) return;
    if (!DAPPS.length) { note('c_hardflags', 'No per-app detail in this dashboard.'); return; }
    var n = 0, t = { pie: 0, canary: 0, arc: 0, encrypted: 0 };
    DAPPS.forEach(function (a) {
      (a.details.hardening || []).forEach(function (b) {
        n++;
        if (b.pie) t.pie++;
        if (b.canary) t.canary++;
        if (b.arc) t.arc++;
        if (b.encrypted) t.encrypted++;
      });
    });
    if (!n) { note('c_hardflags', 'No analysable binaries.'); return; }
    var rows = [
      { label: 'PIE / ASLR', v: t.pie, good: true },
      { label: 'Stack canary', v: t.canary, good: true },
      { label: 'ARC', v: t.arc, good: true },
      { label: 'FairPlay encrypted', v: t.encrypted, good: false }
    ];
    var HG = catAxis(rows.map(function (r) { return r.label; }), document.getElementById('c_hardflags'));
    c.setOption(base({
      grid: { left: HG.left, right: 48, top: 10, bottom: 26, containLabel: false },
      tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' },
        formatter: function (p) { return escH(p[0].name) + '<br><b>' + p[0].data.value + '%</b> of ' + n + ' binaries'; } },
      xAxis: { type: 'value', max: 100, axisLabel: { color: DIM, formatter: '{value}%' }, splitLine: { lineStyle: { color: GRID } } },
      yAxis: { type: 'category', data: rows.map(function (r) { return r.label; }).reverse(), axisLabel: HG.label, axisLine: { lineStyle: { color: AX } }, axisTick: { show: false } },
      series: [{ type: 'bar', barWidth: '58%', label: { show: true, position: 'right', color: DIM, formatter: '{c}%' },
        data: rows.slice().reverse().map(function (r) {
          return { value: Math.round(r.v / n * 100),
                   itemStyle: { color: r.good ? tok('good', '#1aa050') : tok('warn', '#d1a417'), borderRadius: 3 } };
        }) }]
    }));
  })();

  (function () {
    var c = mk('c_devs'); if (!c) return;
    var m = {}, appsPer = {};
    APPS.forEach(function (a) {
      var d = a.artist; if (!d) return;
      m[d] = (m[d] || 0) + (a.findingsCount || 0);
      appsPer[d] = (appsPer[d] || 0) + 1;
    });
    var items = Object.keys(m).filter(function (k) { return appsPer[k] >= 2; })
      .map(function (k) { return { label: k, count: +(m[k] / appsPer[k]).toFixed(1), apps: appsPer[k] }; })
      .sort(function (x, y) { return y.count - x.count; }).slice(0, 15);
    if (!items.length) { note('c_devs', 'No developer has two or more apps in this batch.'); return; }
    var DG = catAxis(items.map(function (i) { return i.label + ' (' + i.apps + ')'; }), document.getElementById('c_devs'));
    c.setOption(base({
      grid: { left: DG.left, right: 56, top: 8, bottom: 26, containLabel: false },
      tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' },
        formatter: function (p) { var d = p[0].data; return escH(p[0].name) + '<br><b>' + d.value + '</b> findings per app, mean of ' + d.apps + ' apps'; } },
      xAxis: { type: 'value', axisLabel: { color: DIM }, splitLine: { lineStyle: { color: GRID } } },
      yAxis: { type: 'category', data: items.map(function (i) { return i.label + ' (' + i.apps + ')'; }).reverse(), axisLabel: DG.label, axisLine: { lineStyle: { color: AX } }, axisTick: { show: false } },
      series: [{ type: 'bar', barWidth: '62%', label: { show: true, position: 'right', color: DIM },
        data: items.slice().reverse().map(function (i) { return { value: i.count, apps: i.apps, itemStyle: { color: tok('teal', '#16a3a3'), borderRadius: 3 } }; }) }]
    }));
  })();

  pie('c_sev', val(ST.severityHistogram).map(function (i) { return { name: i.label, value: i.count, itemStyle: { color: SC[i.label] || '#888' } }; }), true);
  (function () {
    if (!HAS_CATS) { note('c_cats', NO_CAT); return; }
    var m = {}; APPS.forEach(function (a) { var k = a.category || '(unknown)'; m[k] = (m[k] || 0) + 1; });
    pie('c_cats', foldTail(rankedSlices(m)), true);
  })();

  (function () {
    var c = mk('c_appsev'); if (!c) return;
    var names = APPS.map(function (a) { return a.appStoreName; });
    var series = SEV.map(function (sev) {
      return { name: sev, type: 'bar', stack: 'sev', emphasis: { focus: 'series' },
        itemStyle: { color: SC[sev] },
        data: APPS.map(function (a) { return (a.severityCounts || {})[sev] || 0; }) };
    });
    var WINDOW = 40, zoom = names.length > WINDOW;
    c.setOption(base({
      tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
      legend: { type: 'scroll', bottom: 0, textStyle: { color: DIM } },
      dataZoom: zoom ? [{ type: 'slider', xAxisIndex: 0, bottom: 26, height: 16, startValue: 0, endValue: WINDOW - 1,
                          zoomLock: true, brushSelect: false, showDetail: false,
                          borderColor: AX, fillerColor: 'rgba(120,140,170,0.18)', textStyle: { color: DIM } },
                        { type: 'inside', xAxisIndex: 0, zoomLock: true }] : [],
      grid: { left: 6, right: 14, top: 12, bottom: zoom ? 56 : 34, containLabel: true },
      xAxis: { type: 'category', data: names, axisLabel: appNameAxisLabel(zoom ? names.slice(0, WINDOW) : names), axisLine: { lineStyle: { color: AX } } },
      yAxis: { type: 'value', axisLabel: { color: DIM }, splitLine: { lineStyle: { color: GRID } } },
      series: series
    }));
  })();

  (function () {
    var c = mk('c_radar'); if (!c) return;
    var order = ['MASVS-PRIVACY', 'MASVS-NETWORK', 'MASVS-STORAGE', 'MASVS-CRYPTO', 'MASVS-PLATFORM', 'MASVS-CODE', 'MASVS-RESILIENCE', 'MASVS-AUTH'];
    var present = order.filter(function (g) { return APPS.some(function (a) { return (a.masvsCounts || {})[g] != null; }); });
    if (present.length < 3) { present = order; }
    var apps = APPS.slice(0, PALETTE.length);
    var axisMax = {};
    present.forEach(function (g) {
      var m = 1;
      apps.forEach(function (a) { m = Math.max(m, (a.masvsCounts || {})[g] || 0); });
      axisMax[g] = m;
    });
    c.setOption(base({
      tooltip: { formatter: function (p) {
        return escH(p.name) + '<br>' + present.map(function (g, i) {
          return g.replace('MASVS-', '') + ': <b>' + p.value[i] + '</b>';
        }).join('<br>'); } },
      legend: { type: 'scroll', bottom: 0, textStyle: { color: DIM, fontSize: 11 } },
      radar: { indicator: present.map(function (g) { return { name: g.replace('MASVS-', ''), max: axisMax[g] }; }),
        radius: '62%', center: ['50%', '46%'],
        axisName: { color: DIM, fontSize: 11 }, splitLine: { lineStyle: { color: GRID } },
        splitArea: { areaStyle: { color: ['transparent', tok('raised', '#1a1f27')], opacity: 0.35 } }, axisLine: { lineStyle: { color: AX } } },
      series: [{ type: 'radar', data: apps.map(function (a, i) {
        return { name: a.appStoreName, value: present.map(function (g) { return (a.masvsCounts || {})[g] || 0; }),
          lineStyle: { color: catColor(i), width: 1.5 }, itemStyle: { color: catColor(i) }, areaStyle: { opacity: 0.05 } };
      }) }]
    }));
  })();

  hbar('c_masvs', (ST.masvsGroupFrequency || []).map(function (i) {
    var parts = String(i.label).split(/\s+[\u00b7\u2013\u2014-]\s+/);
    return { label: (parts[1] || parts[0]).trim(), count: i.count, detail: i.detail || parts[0].trim() };
  }), function (_l) { return tok('accent-2', '#a974e0'); }, 12);

  hbar('c_trackers', ST.topTrackers, function (_l) { return RC.orange; }, 12);
  hbar('c_countries', ST.topEndpointCountries, function (_l) { return tok('teal', '#16a3a3'); }, 12);
  hbar('c_perms', permFamilyStats(), function (_l) { return RC.yellow; }, 14);
  var cVectors = mk('c_vectors');

  (function () {
    var c = mk('c_owners'); if (!c) return;
    var data = (ST.topEndpointOwners || []).map(function (i, idx) {
      return { name: i.label, value: i.count, itemStyle: { color: catColor(idx) } };
    });
    treemap(c, data, 'app(s)', document.getElementById('c_owners'));
  })();

  (function () {
    var gd = document.getElementById('c_graph');
    if (gd) { gd.classList.add('auto'); gd.style.height = '820px'; }
    var c = mk('c_graph'); if (!c) return;
    var APP_COLOR = tok('accent', '#4a8ad6'), TRK_COLOR = RC.orange;
    var nodes = [], links = [], seen = {}, nset = {};
    function addNode(n) { if (nset[n.name]) return; nset[n.name] = 1; nodes.push(n); }
    APPS.forEach(function (a, ai) {
      var an = 'app:' + ai;
      addNode({ name: an, disp: a.appStoreName || an, category: 0, reach: (a.trackerNames || []).length,
        symbolSize: Math.max(14, Math.min(46, 12 + (a.trackerCount || 0) * 4)) });
      (a.trackerNames || []).forEach(function (t) {
        if (!seen[t]) { seen[t] = 0; }
        seen[t]++;
        links.push({ source: an, target: 'trk:' + t });
      });
    });
    Object.keys(seen).forEach(function (t) {
      addNode({ name: 'trk:' + t, disp: t, category: 1, reach: seen[t],
        symbolSize: Math.max(12, Math.min(40, 8 + seen[t] * 6)) });
    });
    (function () {
      var keepTrk = {};
      Object.keys(seen).forEach(function (t) { if (seen[t] >= 2) keepTrk['trk:' + t] = 1; });
      var linked = {};
      links = links.filter(function (l) {
        if (!keepTrk[l.target]) return false;
        linked[l.source] = 1; linked[l.target] = 1; return true;
      });
      nodes = nodes.filter(function (n) { return linked[n.name]; });
    })();

    var idxOf = {}, adj = {};
    nodes.forEach(function (n, i) { idxOf[n.name] = i; });
    links.forEach(function (l) {
      (adj[l.source] = adj[l.source] || []).push(l.target);
      (adj[l.target] = adj[l.target] || []).push(l.source);
    });
    function neighbourIdx(name) {
      return (adj[name] || []).map(function (nm) { return idxOf[nm]; })
        .filter(function (i) { return i != null; });
    }

    var GRAPH_INSET = { t: 26, b: 10, l: 10, r: 10 };

    var gBox = gd ? { w: gd.clientWidth || 1422, h: gd.clientHeight || 560 } : { w: 1422, h: 560 };
    var perNode = Math.sqrt((gBox.w * gBox.h) / Math.max(1, nodes.length));
    var FORCE = { repulsion: Math.round(Math.max(90, Math.min(420, perNode * 6))),
                  edgeLength: Math.round(Math.max(50, Math.min(180, perNode * 2.6))),
                  gravity: 0.1, friction: 0.35, layoutAnimation: false };

    var readout = null;
    if (gd) {
      var stale = gd.querySelector('.graph-readout');
      if (stale) stale.parentNode.removeChild(stale);
      readout = document.createElement('div');
      readout.className = 'graph-readout';
      readout.hidden = true;
      gd.appendChild(readout);
    }
    function describe(d) {
      if (d.category === 1) return 'tracker · shared by ' + d.reach + ' app(s)';
      var shown = (adj[d.name] || []).length;
      return shown < d.reach
        ? 'app · ' + shown + ' of ' + d.reach + ' trackers shared with another app'
        : 'app · ' + d.reach + ' tracker(s)';
    }
    function showReadout(d, isPinned) {
      if (!readout) return;
      if (!d) { readout.hidden = true; readout.textContent = ''; return; }
      readout.textContent = '';
      var t = document.createElement('b'); t.textContent = d.disp || '';
      var s = document.createElement('span'); s.textContent = describe(d);
      readout.appendChild(t); readout.appendChild(s);
      if (isPinned) {
        var h = document.createElement('i');
        h.textContent = 'pinned · click the background or press Esc';
        readout.appendChild(h);
      }
      readout.hidden = false;
    }

    function emphLabel(placed) {
      var l = { show: true, position: (placed && placed.side) || placed || 'right',
                color: TXT, fontSize: 11,
                backgroundColor: RAISED, padding: [2, 5], borderRadius: 4,
                formatter: function (p) { return (p.data && p.data.disp) || ''; } };
      if (placed && placed.offset) l.offset = placed.offset;
      return l;
    }

    c.setOption(base({
      color: [APP_COLOR, TRK_COLOR],
      tooltip: { show: false },
      legend: { data: ['app', 'tracker'], top: 0, right: 0, textStyle: { color: DIM }, icon: 'circle' },
      series: [{ type: 'graph', layout: 'force', roam: 'move', draggable: true,
        top: GRAPH_INSET.t, bottom: GRAPH_INSET.b, left: GRAPH_INSET.l, right: GRAPH_INSET.r,
        categories: [{ name: 'app', itemStyle: { color: APP_COLOR } }, { name: 'tracker', itemStyle: { color: TRK_COLOR } }],
        label: { show: true, color: TXT, fontSize: 10, position: 'right',
                 formatter: function (p) { return (p.data && p.data.labelled) ? p.data.disp : ''; } },
        force: FORCE,
        lineStyle: { color: OTHER, opacity: 0.5, curveness: 0.1 },
        emphasis: { label: emphLabel('right') },
        data: nodes, links: links }]
    }));

    function nodePixels() {
      var layout = [];
      try {
        var series = c.getModel().getSeriesByIndex(0);
        var store = series.getData();
        var t = series.coordinateSystem && series.coordinateSystem.transform;
        var sx = t ? t[0] : 1, sy = t ? t[3] : 1, tx = t ? t[4] : 0, ty = t ? t[5] : 0;
        store.each(function (i) {
          var l = store.getItemLayout(i);
          layout[i] = l ? [l[0] * sx + tx, l[1] * sy + ty] : null;
        });
      } catch (e) { return null; }
      if (layout.length < nodes.length || !layout.slice(0, nodes.length).some(function (p) { return p; })) {
        return null;
      }
      return layout;
    }

    var _tw = {};
    function labelWidth(s, px) {
      var k = px + '|' + s;
      if (_tw[k] == null) _tw[k] = textWidth(s, px) + 4;
      return _tw[k];
    }
    function boxFor(side, p, r, tw, th, off) {
      var dx = off ? off[0] : 0, dy = off ? off[1] : 0;
      if (side === 'left') return { x: p[0] - r - 4 - tw + dx, y: p[1] - th / 2 + dy, w: tw, h: th };
      if (side === 'top') return { x: p[0] - tw / 2 + dx, y: p[1] - r - 4 - th + dy, w: tw, h: th };
      if (side === 'bottom') return { x: p[0] - tw / 2 + dx, y: p[1] + r + 4 + dy, w: tw, h: th };
      return { x: p[0] + r + 4 + dx, y: p[1] - th / 2 + dy, w: tw, h: th };
    }
    var OFFSETS = [0, 15, -15, 30, -30, 46, -46, 64, -64];

    var SIDES_STATIC = ['right', 'left'];
    var SIDES_FOCUS = ['right', 'left', 'top', 'bottom'];
    function placeIn(layout, indices, seeds, sides, fontSize, pad) {
      var padX = pad ? pad[0] : 0, padY = pad ? pad[1] : 0;
      var right = c.getWidth() - GRAPH_INSET.r, left = GRAPH_INSET.l;
      var top = GRAPH_INSET.t, bottom = c.getHeight() - GRAPH_INSET.b;
      var mid = (left + right) / 2;
      var taken = (seeds || []).slice();
      nodes.forEach(function (n, i) {
        var p = layout[i]; if (!p) return;
        var r = (n.symbolSize || 14) / 2;
        taken.push({ x: p[0] - r, y: p[1] - r, w: r * 2, h: r * 2 });
      });
      function overlapArea(box) {
        var a = 0;
        taken.forEach(function (q) {
          var w = Math.min(box.x + box.w, q.x + q.w) - Math.max(box.x, q.x);
          var h = Math.min(box.y + box.h, q.y + q.h) - Math.max(box.y, q.y);
          if (w > 0 && h > 0) a += w * h;
        });
        return a;
      }
      function hits(box) { return overlapArea(box) > 0; }
      function outOfBounds(box, l, t, rr, b) {
        var dx = Math.max(0, l - box.x) + Math.max(0, box.x + box.w - rr);
        var dy = Math.max(0, t - box.y) + Math.max(0, box.y + box.h - b);
        return dx * box.h + dy * box.w;
      }
      var chosen = {};
      indices.map(function (i) { return { n: nodes[i], i: i }; })
        .sort(function (a, b) { return (b.n.reach || 0) - (a.n.reach || 0); })
        .forEach(function (o) {
          var p = layout[o.i], side = null;
          if (p) {
            var r = (o.n.symbolSize || 14) / 2;
            var tw = labelWidth(o.n.disp, fontSize) + padX, th = fontSize + 4 + padY;
            var order = sides.slice();
            if (p[0] > mid) { order[0] = sides[1]; order[1] = sides[0]; }
            var focusPass = sides.length > 2;
            var ladder = focusPass ? OFFSETS : [0];
            var best = null, bestCost = Infinity, bestBox = null;
            for (var m = 0; m < ladder.length && !side; m++) {
              for (var k = 0; k < order.length; k++) {
                var horiz = order[k] === 'top' || order[k] === 'bottom';
                var off = horiz ? [ladder[m], 0] : [0, ladder[m]];
                var box = boxFor(order[k], p, r, tw, th, off);
                var spill = outOfBounds(box, left, top, right, bottom);
                if (!spill && !hits(box)) { taken.push(box); side = { side: order[k], offset: off }; break; }
                var cost = spill + overlapArea(box);
                if (cost < bestCost) { bestCost = cost; best = { side: order[k], offset: off }; bestBox = box; }
              }
            }
            if (!side && best && focusPass) { taken.push(bestBox); side = best; }
          }
          chosen[o.i] = side;
        });
      return chosen;
    }

    function placeLabels() {
      var layout = nodePixels();
      if (!layout) return false;
      var all = nodes.map(function (_n, i) { return i; });
      var chosen = placeIn(layout, all, [], SIDES_STATIC, 10);
      var changed = false;
      nodes.forEach(function (n, i) {
        var side = chosen[i] ? chosen[i].side : null;
        if (n.labelled !== !!side || n.labelSide !== side) {
          n.labelled = !!side;
          n.labelSide = side;
          n.label = side ? { position: side } : undefined;
          changed = true;
        }
      });
      if (changed) c.setOption({ series: [{ data: nodes.concat(fitAnchors) }] });
      return true;
    }

    var focusSet = [];
    var DIM_NODE = 0.16, DIM_EDGE = 0.05;
    function restoreStaticLabel(j) {
      var n = nodes[j];
      n.labelled = !!n.labelSide;
      n.label = n.labelSide ? { position: n.labelSide } : undefined;
      n.emphasis = undefined;
      n.itemStyle = undefined;
    }
    function applyFocus(i) {
      focusSet.forEach(restoreStaticLabel);
      focusSet = [];
      if (i != null) {
        var layout = nodePixels();
        if (layout) {
          var set = [i].concat(neighbourIdx(nodes[i].name));
          var inSet = {};
          set.forEach(function (j) { inSet[j] = 1; });
          var seeds = [];
          if (readout && !readout.hidden && gd) {
            var rb = readout.getBoundingClientRect(), gb = gd.getBoundingClientRect();
            seeds.push({ x: rb.left - gb.left - 6, y: rb.top - gb.top - 6,
                         w: rb.width + 12, h: rb.height + 12 });
          }
          var chosen = placeIn(layout, set, seeds, SIDES_FOCUS, 11, [14, 8]);
          nodes.forEach(function (n, j) {
            if (inSet[j]) return;
            if (!n.labelled) return;
            n.labelled = false; n.label = { show: false };
            focusSet.push(j);
          });
          set.forEach(function (j) {
            nodes[j].labelled = true;
            nodes[j].label = emphLabel(chosen[j]);
            nodes[j].emphasis = { label: emphLabel(chosen[j]) };
            focusSet.push(j);
          });
          nodes.forEach(function (n, j) {
            if (inSet[j]) {
              n.itemStyle = (pinned === j) ? { borderColor: TXT, borderWidth: 2 } : undefined;
            } else {
              n.itemStyle = { opacity: DIM_NODE };
              if (focusSet.indexOf(j) < 0) focusSet.push(j);
            }
          });
          var hub = nodes[i].name;
          links.forEach(function (l) {
            var on = l.source === hub || l.target === hub;
            l.lineStyle = on ? { opacity: 0.9, width: 2, color: TRK_COLOR }
                             : { opacity: DIM_EDGE };
          });
        }
      }
      if (i == null) { links.forEach(function (l) { l.lineStyle = undefined; }); }
      c.setOption({ series: [{ data: nodes.concat(fitAnchors), links: links }] });
    }

    var pinned = null, focused = null;
    function isNode(p) {
      return !!(p && p.dataType !== 'edge' && p.data && String(p.data.name).indexOf(ANCHOR) !== 0);
    }
    function spotlight(i) {
      if (focused === i) return;
      focused = i;
      showReadout(i == null ? null : nodes[i], pinned === i && i != null);
      applyFocus(i);
    }
    function unpin() {
      pendingFocus = null; sawArrival = false;
      if (pinned == null) return;
      pinned = null;
      spotlight(null);
    }
    var pendingFocus, sawArrival = false, focusTimer = null;
    function requestFocus(i) {
      if (i == null) { if (sawArrival) return; } else { sawArrival = true; }
      pendingFocus = i;
      if (focusTimer != null) return;
      focusTimer = 1;
      later(function () { focusTimer = null; sawArrival = false; spotlight(pendingFocus); }, 40);
    }
    c.on('mouseover', function (p) { if (pinned == null && isNode(p)) requestFocus(p.dataIndex); });
    c.on('mouseout', function (p) { if (pinned == null && isNode(p)) requestFocus(null); });
    c.on('click', function (p) {
      if (!isNode(p)) return;
      if (pinned === p.dataIndex) { unpin(); return; }
      pinned = p.dataIndex;
      focused = null;
      spotlight(p.dataIndex);
    });
    try {
      c.getZr().on('click', function (e) { if (!e.target) unpin(); });
    } catch (e) {}
    if (typeof document.addEventListener === 'function') {
      document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape' || e.keyCode === 27) unpin();
      });
    }

    var ANCHOR = '__fitAnchor', fitAnchors = [];

    function relaxOverlaps(pts, rounds, rad) {
      var GAP = 3;
      for (var pass = 0; pass < rounds; pass++) {
        var moved = 0;
        for (var i = 0; i < nodes.length; i++) {
          for (var j = i + 1; j < nodes.length; j++) {
            var dx = pts[j][0] - pts[i][0], dy = pts[j][1] - pts[i][1];
            var need = rad[i] + rad[j] + GAP;
            var d2 = dx * dx + dy * dy;
            if (d2 >= need * need) continue;
            var d = Math.sqrt(d2);
            if (d < 1e-6) { dx = (i % 2 ? 1 : -1); dy = (j % 2 ? 1 : -1); d = Math.sqrt(2); }
            var push = (need - d) / 2 / d;
            var ox = dx * push, oy = dy * push;
            pts[i][0] -= ox; pts[i][1] -= oy;
            pts[j][0] += ox; pts[j][1] += oy;
            moved++;
          }
        }
        if (!moved) break;
      }
    }

    function extentOf(pts, radii) {
      var e = { x0: Infinity, y0: Infinity, x1: -Infinity, y1: -Infinity };
      nodes.forEach(function (_n, i) {
        var r = radii[i];
        e.x0 = Math.min(e.x0, pts[i][0] - r); e.x1 = Math.max(e.x1, pts[i][0] + r);
        e.y0 = Math.min(e.y0, pts[i][1] - r); e.y1 = Math.max(e.y1, pts[i][1] + r);
      });
      return e;
    }

    function fitToBox() {
      var pts = [];
      try {
        var series0 = c.getModel().getSeriesByIndex(0);
        var store = series0.getData();
        var t0 = series0.coordinateSystem && series0.coordinateSystem.transform;
        var a0 = t0 ? t0[0] : 1, d0 = t0 ? t0[3] : 1, e0 = t0 ? t0[4] : 0, f0 = t0 ? t0[5] : 0;
        store.each(function (i) {
          var l = store.getItemLayout(i);
          pts[i] = l ? [l[0] * a0 + e0, l[1] * d0 + f0] : null;
        });
      } catch (e) { return false; }
      if (pts.length < nodes.length) return false;
      if (pts.some(function (p) { return !p || !isFinite(p[0]) || !isFinite(p[1]); })) return false;
      var spread = 0;
      for (var i = 1; i < nodes.length; i++) {
        spread = Math.max(spread, Math.abs(pts[i][0] - pts[0][0]), Math.abs(pts[i][1] - pts[0][1]));
      }
      if (spread < 1) return false;

      nodes.forEach(function (n) { if (n.baseSize == null) n.baseSize = n.symbolSize || 14; });

      var baseRad = nodes.map(function (n) { return n.baseSize / 2; });
      relaxOverlaps(pts, 60, baseRad);

      var rw = Math.max(1, c.getWidth() - GRAPH_INSET.l - GRAPH_INSET.r);
      var rh = Math.max(1, c.getHeight() - GRAPH_INSET.t - GRAPH_INSET.b);
      var b = extentOf(pts, baseRad);
      var bw = Math.max(1, b.x1 - b.x0), bh = Math.max(1, b.y1 - b.y0);
      var kx = rw / bw, ky = rh / bh, ks = Math.min(kx, ky);
      var cx = (b.x0 + b.x1) / 2, cy = (b.y0 + b.y1) / 2;
      var rad = nodes.map(function (n) { return Math.max(4, n.baseSize * ks) / 2; });
      var pos = pts.map(function (p) { return [(p[0] - cx) * kx, (p[1] - cy) * ky]; });
      relaxOverlaps(pos, 60, rad);

      var s = extentOf(pos, rad);
      var fx = Math.min(1, rw / Math.max(1, s.x1 - s.x0)), fy = Math.min(1, rh / Math.max(1, s.y1 - s.y0));
      var f = Math.min(fx, fy);
      var scx = (s.x0 + s.x1) / 2, scy = (s.y0 + s.y1) / 2;
      nodes.forEach(function (n, j) {
        n.x = (pos[j][0] - scx) * f;
        n.y = (pos[j][1] - scy) * f;
        n.symbolSize = Math.max(4, n.baseSize * ks * f);
        n.fixed = true;
      });

      var fin = extentOf(nodes.map(function (n) { return [n.x, n.y]; }),
                         nodes.map(function (n) { return n.symbolSize / 2; }));
      var halfW = Math.max(fin.x1 - fin.x0, rw) / 2, halfH = Math.max(fin.y1 - fin.y0, rh) / 2;
      if (halfW / halfH < rw / rh) halfW = halfH * (rw / rh); else halfH = halfW / (rw / rh);
      fitAnchors = [[-halfW, -halfH], [halfW, halfH]].map(function (pt, idx) {
        return { name: ANCHOR + idx, x: pt[0], y: pt[1], fixed: true, symbolSize: 0.1,
                 silent: true, category: 0, itemStyle: { opacity: 0 }, label: { show: false },
                 emphasis: { disabled: true } };
      });
      c.setOption({ series: [{ layout: 'none', data: nodes.concat(fitAnchors) }] });
      return true;
    }

    var labelsPlaced = false;
    function labelWhenReady(tries) {
      if (labelsPlaced) return;
      if (placeLabels()) { labelsPlaced = true; return; }
      if (tries > 0) later(function () { labelWhenReady(tries - 1); }, 120);
    }

    function labelOnNextRender() {
      function onFinished() {
        if (labelsPlaced) { c.off('finished', onFinished); return; }
        if (placeLabels()) { labelsPlaced = true; c.off('finished', onFinished); }
      }
      c.on('finished', onFinished);
      labelWhenReady(30);
    }

    var settled = false;
    function settleGraph(tries) {
      if (settled) return;
      if (fitToBox()) {
        settled = true;
        nextFrame(labelOnNextRender);
        return;
      }
      if (tries > 0) later(function () { settleGraph(tries - 1); }, 100);
    }
    later(function () { settleGraph(40); }, 0);

    if (window.IntersectionObserver && gd) {
      var io = new IntersectionObserver(function (entries) {
        if (!entries.some(function (e) { return e.isIntersecting; })) return;
        io.disconnect();
        settleGraph(40);
        if (settled) labelOnNextRender();
      }, { threshold: 0.01 });
      io.observe(gd);
    }

    if (window.ResizeObserver && gd) {
      var lastGraphBox = '';
      new ResizeObserver(function () {
        var now = gd.clientWidth + 'x' + gd.clientHeight;
        if (now === lastGraphBox) return;
        lastGraphBox = now;
        unpin();
        focusSet = [];
        nodes.forEach(function (n) { n.labelled = false; n.labelSide = null; n.label = undefined; });
        later(function () {
          if (fitToBox()) { labelsPlaced = false; nextFrame(labelOnNextRender); }
        }, 200);
      }).observe(gd);
    }
  })();

  (function () {
    if (!HAS_CATS) { note('c_catrisk', NO_CAT); return; }
    var c = mk('c_catrisk'); if (!c) return;
    var m = {}; APPS.forEach(function (a) { var k = a.category || '(unknown)'; (m[k] = m[k] || { s: 0, n: 0 }); m[k].s += a.findingsCount || 0; m[k].n++; });
    var arr = Object.keys(m).filter(function (k) { return m[k].n >= MIN_CAT_N; })
      .map(function (k) { return { label: k + ' (' + m[k].n + ')', cat: k, avg: m[k].s / m[k].n, n: m[k].n }; })
      .sort(function (a, b) { return a.avg - b.avg; });
    if (!arr.length) { note('c_catrisk', 'No category has ' + MIN_CAT_N + ' or more apps.'); return; }
    var CR = catAxis(arr.map(function (i) { return i.label; }), document.getElementById('c_catrisk'));
    c.setOption(base({
      grid: { left: CR.left, right: 44, top: 8, bottom: 26, containLabel: false },
      tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' }, formatter: function (p) { var d = p[0].data; return escH(d.cat) + '<br><b>' + d.value.toFixed(1) + '</b> findings per app · ' + d.n + ' app(s)'; } },
      xAxis: { type: 'value', axisLabel: { color: DIM }, splitLine: { lineStyle: { color: GRID } } },
      yAxis: { type: 'category', data: arr.map(function (i) { return i.label; }), axisLabel: CR.label, axisLine: { lineStyle: { color: AX } }, axisTick: { show: false } },
      series: [{ type: 'bar', barWidth: '62%', label: { show: true, position: 'right', color: DIM, formatter: function (p) { return p.data.value.toFixed(0); } },
        data: arr.map(function (i) { return { value: +i.avg.toFixed(1), cat: i.cat, n: i.n, itemStyle: { color: tok('accent', '#4a8ad6'), borderRadius: 3 } }; }) }]
    }));
  })();

  (function () {
    var buckets = ['0', '1', '2', '3', '4', '5+'];
    var counts = [0, 0, 0, 0, 0, 0];
    APPS.forEach(function (a) { var t = a.trackerCount || 0; counts[Math.min(t, 5)]++; });
    vbar('c_trkdist', buckets.map(function (b, i) { return { label: b, count: counts[i] }; }),
      function (l) { return l === '0' ? RC.green : l === '5+' ? RC.red : RC.orange; });
  })();

  (function () {
    var defs = [['<50 MB', 0, 50e6], ['50–100', 50e6, 100e6], ['100–200', 100e6, 200e6], ['200–500', 200e6, 500e6], ['500 MB+', 500e6, Infinity]];
    var items = defs.map(function (d) { return { label: d[0], count: APPS.filter(function (a) { var s = a.sizeBytes || 0; return s >= d[1] && s < d[2]; }).length }; });
    vbar('c_sizedist', items, tok('teal', '#16a3a3'));
  })();

  (function () {
    var c = mk('c_sensperm'); if (!c) return;
    var N = APPS.length || 1;
    var sensitive = { 'Location': 1, 'Camera': 1, 'Microphone': 1, 'Contacts': 1, 'Photos': 1,
      'App tracking (ATT)': 1, 'Health': 1, 'Bluetooth': 1, 'Motion & fitness': 1, 'Face ID': 1,
      'Local network': 1, 'Speech recognition': 1, 'Calendar': 1, 'Reminders': 1 };
    var items = permFamilyStats().filter(function (i) { return sensitive[i.label]; })
      .map(function (i) { return { label: i.label, count: i.count, detail: i.detail, pct: Math.round(i.count / N * 100) }; })
      .sort(function (a, b) { return a.count - b.count; }).slice(-12);
    var SP = catAxis(items.map(function (i) { return i.label; }), document.getElementById('c_sensperm'));
    c.setOption(base({
      grid: { left: SP.left, right: 46, top: 8, bottom: 26, containLabel: false },
      tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' }, formatter: function (p) { var d = p[0].data; return escH(d.name) + '<br><b>' + d.value + '%</b> of apps · ' + d.apps + ' app(s)' + (d.detail ? '<br><span style="color:' + DIM + '">' + escH(d.detail) + '</span>' : ''); } },
      xAxis: { type: 'value', max: 100, axisLabel: { color: DIM, formatter: '{value}%' }, splitLine: { lineStyle: { color: GRID } } },
      yAxis: { type: 'category', data: items.map(function (i) { return i.label; }), axisLabel: SP.label, axisLine: { lineStyle: { color: AX } }, axisTick: { show: false } },
      series: [{ type: 'bar', barWidth: '62%', label: { show: true, position: 'right', color: DIM, formatter: function (p) { return p.data.value + '%'; } },
        data: items.map(function (i) { return { value: i.pct, name: i.label, apps: i.count, detail: i.detail, itemStyle: { color: RC.yellow, borderRadius: 3 } }; }) }]
    }));
  })();

  (function () {
    var c = mk('c_trkpriv'); if (!c) return;
    c.setOption(base({
      tooltip: { formatter: function (p) { return escH(p.data.name) + '<br>' + p.data.value[0] + ' trackers · ' + p.data.value[1] + ' privacy findings'; } },
      grid: NAMED_GRID,
      xAxis: axisNamed('trackers', false, { min: 0 }),
      yAxis: axisNamed('MASVS-PRIVACY findings', true, { min: 0 }),
      series: [{ type: 'scatter', symbolSize: 12,
        data: APPS.map(function (a) { return { name: a.appStoreName, value: [a.trackerCount || 0, (a.clusterCounts || {})['MASVS-PRIVACY'] || 0], itemStyle: { color: tok('accent', '#4a8ad6'), opacity: 0.8 } }; }) }]
    }));
  })();

  (function () {
    var c = mk('c_sizefind'); if (!c) return;
    c.setOption(base({
      tooltip: { formatter: function (p) { return escH(p.data.name) + '<br>' + p.data.value[0] + ' MB · ' + p.data.value[1] + ' findings'; } },
      grid: NAMED_GRID,
      xAxis: axisNamed('MB', false, { min: 0 }),
      yAxis: axisNamed('findings', true, { min: 0 }),
      series: [{ type: 'scatter', symbolSize: 11,
        data: APPS.map(function (a) { return { name: a.appStoreName, value: [+((a.sizeBytes || 0) / 1e6).toFixed(0), a.findingsCount || 0], itemStyle: { color: tok('accent', '#4a8ad6'), opacity: 0.8 } }; }) }]
    }));
  })();

  var CATCOLOR = { advertising: RC.orange, analytics: tok('accent', '#4a8ad6'), attribution: tok('accent-2', '#a974e0'), antifraud: RC.red,
    'session-replay': catColor(1), push: tok('teal', '#16a3a3'), crash: SC.medium, payment: RC.green, identity: RC.yellow,
    social: catColor(0), support: DIM, maps: catColor(5), messaging: catColor(1), consent: DIM, cdn: OTHER };

  function trackerTally(keyFn) {
    var m = {};
    DAPPS.forEach(function (a) {
      var seen = {};
      (a.details.trackers || []).forEach(function (t) {
        var k = keyFn(t); if (!k) return;
        var uk = a.appID + '|' + k; if (seen[uk]) return; seen[uk] = 1;
        m[k] = (m[k] || 0) + 1;
      });
    });
    return m;
  }

  (function () {
    if (!DAPPS.length) return;
    var m = trackerTally(function (t) { return t.category; });
    var data = Object.keys(m).map(function (k) { return { name: k, value: m[k], itemStyle: { color: CATCOLOR[k] || OTHER } }; })
      .sort(function (a, b) { return b.value - a.value; });
    pie('c_trkcat', foldTail(data), true);
  })();

  (function () {
    if (!DAPPS.length) return;
    var m = trackerTally(function (t) { return t.country; });
    pie('c_trkcountry', foldTail(rankedSlices(m)), true);
  })();

  (function () {
    if (!DAPPS.length) return;
    var m = trackerTally(function (t) { return t.owner; });
    var items = Object.keys(m).map(function (k) { return { label: k, count: m[k] }; })
      .sort(function (a, b) { return b.count - a.count; }).slice(0, 14);
    hbar('c_trkowner', items, tok('accent-2', '#a974e0'), 14);
  })();

  (function () {
    var c = mk('c_trktree'); if (!c || !DAPPS.length) return;
    var m = trackerTally(function (t) { return t.category; });
    var data = Object.keys(m)
      .map(function (k) { return { name: k, value: m[k], itemStyle: { color: CATCOLOR[k] || OTHER } }; })
      .sort(function (x, y) { return y.value - x.value; });
    treemap(c, data, 'app(s)', document.getElementById('c_trktree'));
  })();

  (function () {
    if (!HAS_CATS) { note('c_catsev', NO_CAT); return; }
    var c = mk('c_catsev'); if (!c) return;
    var cats = {}, catN = {};
    APPS.forEach(function (a) { var k = a.category || '(unknown)'; catN[k] = (catN[k] || 0) + 1; cats[k] = cats[k] || { info: 0, low: 0, medium: 0, high: 0, critical: 0 }; SEV.forEach(function (s) { cats[k][s] += (a.severityCounts || {})[s] || 0; }); });
    Object.keys(cats).forEach(function (k) { SEV.forEach(function (s) { cats[k][s] = +(cats[k][s] / catN[k]).toFixed(1); }); });
    var names = Object.keys(cats).filter(function (k) { return catN[k] >= MIN_CAT_N; })
      .sort(function (a, b) { function t(o) { return o.info + o.low + o.medium + o.high + o.critical; } return t(cats[b]) - t(cats[a]); }).slice(0, 12);
    if (!names.length) { note('c_catsev', 'No category has ' + MIN_CAT_N + ' or more apps.'); return; }
    var cd = document.getElementById('c_catsev');
    if (cd) { cd.classList.add('auto'); cd.style.height = Math.max(288, names.length * 30 + 64) + 'px'; c.resize(); }
    var rows = names.slice().reverse();
    var shown = rows.map(function (n) { return n + ' (' + catN[n] + ')'; });
    var CS = catAxis(shown, cd);
    c.setOption(base({
      tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
      legend: { type: 'scroll', bottom: 0, textStyle: { color: DIM } },
      grid: { left: CS.left, right: 20, top: 10, bottom: 34, containLabel: false },
      xAxis: { type: 'value', axisLabel: { color: DIM }, splitLine: { lineStyle: { color: GRID } } },
      yAxis: { type: 'category', data: shown, axisLabel: CS.label, axisLine: { lineStyle: { color: AX } }, axisTick: { show: false } },
      series: SEV.map(function (s) { return { name: s, type: 'bar', stack: 's', barWidth: '62%', itemStyle: { color: SC[s] }, data: rows.map(function (n) { return cats[n][s]; }) }; })
    }));
  })();

  function vectorTally() {
    var by = {};
    APPS.forEach(function (a) {
      var vs = (a.details && a.details.vectors) || [];
      var seen = {};
      var real = {};
      ((a.details && a.details.findings) || []).forEach(function (f) { if (isReachable(f)) real[f.vector] = 1; });
      vs.forEach(function (v) {
        if (seen[v.code] || !real[v.code]) return;
        seen[v.code] = 1;
        var e = by[v.code] || (by[v.code] = { code: v.code, title: v.title || '', group: v.group || '', apps: 0 });
        e.apps += 1;
      });
    });
    return Object.keys(by).map(function (k) { return by[k]; })
      .sort(function (x, y) { return y.apps - x.apps || (x.code < y.code ? -1 : 1); });
  }

  if (cVectors) {
    var top = vectorTally().slice(0, 12);
    var vd = document.getElementById('c_vectors');
    if (vd && top.length) { vd.classList.add('auto'); vd.style.height = Math.max(288, top.length * 30 + 54) + 'px'; cVectors.resize(); }
    var vecCats = top.map(function (r) { return r.code; }).reverse();
    var vecGutter = Math.ceil(widestLabel(vecCats, 11)) + 18;
    var vecMax = Math.max.apply(null, top.map(function (r) { return r.apps; }).concat([1]));
    cVectors.setOption(base({
      grid: { left: vecGutter, right: 36, top: 8, bottom: 26, containLabel: false },
      tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' },
        formatter: function (p) { var d = p[0].data; return escH(d.name) + '<br><span style="color:' + DIM + '">' + escH(d.detail) + '</span><br><b>' + d.value + '</b> app(s)'; } },
      xAxis: { type: 'value', axisLabel: { color: DIM }, splitLine: { lineStyle: { color: GRID } } },
      yAxis: { type: 'category', data: vecCats,
               axisLabel: { color: TXT, fontSize: 11, width: Math.max(40, vecGutter - 6), overflow: 'truncate' },
               axisLine: { lineStyle: { color: AX } }, axisTick: { show: false } },
      series: [{ type: 'bar', barWidth: '62%',
        labelLayout: { hideOverlap: false },
        data: top.map(function (r) {
          var wide = r.apps / vecMax > 0.42;
          return { value: r.apps, name: r.code + ' — ' + r.title, detail: r.group,
                   label: { show: true, position: wide ? 'insideLeft' : 'right',
                            color: wide ? '#fff' : DIM, fontSize: 10.5,
                            formatter: wide ? r.title : (r.apps + '  ' + r.title) },
                   itemStyle: { color: tok('accent-2', '#8b5cf6'), borderRadius: 3 } };
        }).reverse() }]
    }), { replaceMerge: ['series'] });
  }

  window.addEventListener('resize', function () { charts.forEach(function (c) { c.resize(); }); });
};

function sortT(col) {
  var t = document.getElementById('apps'), tb = t.tBodies[0], rows = Array.prototype.slice.call(tb.rows);
  var dir = t.getAttribute('data-d') === col + 'a' ? col + 'd' : col + 'a';
  t.setAttribute('data-d', dir); var asc = dir.charAt(dir.length - 1) === 'a';
  rows.sort(function (a, b) {
    var ca = a.cells[col], cb = b.cells[col];
    var va = ca.getAttribute('data-v'), vb = cb.getAttribute('data-v');
    if (va !== null && vb !== null) { return asc ? va - vb : vb - va; }
    var xa = ca.innerText.trim(), xb = cb.innerText.trim();
    return asc ? xa.localeCompare(xb) : xb.localeCompare(xa);
  });
  rows.forEach(function (r) { tb.appendChild(r); });
}

(function () {
  var t = document.getElementById('apps'); if (!t) return;
  t.classList.add('hide-cl');

  function pinOffset() {
    var first = t.tBodies[0] && t.tBodies[0].rows[0] && t.tBodies[0].rows[0].cells[0];
    if (!first) return;
    var w = Math.round(first.getBoundingClientRect().width);
    if (w > 0) { t.style.setProperty('--pin2', w + 'px'); }
  }
  pinOffset();
  window.addEventListener('resize', pinOffset);

  var btn = document.getElementById('cluster-cols');
  if (btn) {
    btn.addEventListener('click', function () {
      var hidden = t.classList.toggle('hide-cl');
      btn.setAttribute('aria-pressed', hidden ? 'false' : 'true');
      btn.textContent = (hidden ? 'Show' : 'Hide') + ' MASVS cluster columns';
      pinOffset();
    });
  }
})();
