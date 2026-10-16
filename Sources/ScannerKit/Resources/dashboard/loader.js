(function () {
  function go() { if (window.__drawDashboard) window.__drawDashboard(); }
  function add(src, onok, onerr) { var s = document.createElement('script'); s.src = src; s.onload = onok; s.onerror = onerr; document.head.appendChild(s); }
  function cdn() { add('https://cdn.jsdelivr.net/npm/echarts@5.5.0/dist/echarts.min.js', go, function () { document.getElementById('offline').style.display = 'block'; }); }
  add('echarts.min.js', go, cdn);
})();
