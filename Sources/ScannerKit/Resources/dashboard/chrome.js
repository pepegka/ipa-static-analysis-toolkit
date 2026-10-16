(function () {
  var KEY = 'ms_theme';
  var root = document.documentElement;
  var btn = document.getElementById('theme-toggle');

  function stored() { try { return localStorage.getItem(KEY); } catch (e) { return null; } }
  function systemDark() {
    return !window.matchMedia || window.matchMedia('(prefers-color-scheme: dark)').matches;
  }
  function effective() {
    var s = root.getAttribute('data-theme');
    return s || (systemDark() ? 'dark' : 'light');
  }
  var SUN = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor"'
    + ' stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="4.2"/>'
    + '<path d="M12 2.4v2.2M12 19.4v2.2M2.4 12h2.2M19.4 12h2.2'
    + 'M5.2 5.2l1.6 1.6M17.2 17.2l1.6 1.6M18.8 5.2l-1.6 1.6M6.8 17.2l-1.6 1.6"/></svg>';
  var MOON = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor"'
    + ' stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
    + '<path d="M20 14.3A8.2 8.2 0 1 1 9.7 4a6.6 6.6 0 0 0 10.3 10.3z"/></svg>';

  function label() {
    if (!btn) return;
    var dark = effective() === 'dark';
    var next = dark ? 'light' : 'dark';
    btn.innerHTML = dark ? SUN : MOON;
    btn.setAttribute('aria-label', 'Switch to ' + next + ' theme');
    btn.title = 'Switch to ' + next + ' theme';
  }
  function repaint() {
    requestAnimationFrame(function () {
      if (window.__drawDashboard) window.__drawDashboard();
      if (window.__redrawComparator) window.__redrawComparator();
    });
  }
  function set(theme, persist) {
    if (theme) root.setAttribute('data-theme', theme); else root.removeAttribute('data-theme');
    if (persist) { try { localStorage.setItem(KEY, theme || ''); } catch (e) {} }
    label();
    repaint();
  }

  var saved = stored();
  if (saved === 'light' || saved === 'dark') root.setAttribute('data-theme', saved);
  label();
  if (btn) {
    btn.addEventListener('click', function () { set(effective() === 'dark' ? 'light' : 'dark', true); });
  }
  if (window.matchMedia) {
    var mq = window.matchMedia('(prefers-color-scheme: dark)');
    var onChange = function () { if (!root.getAttribute('data-theme')) { label(); repaint(); } };
    if (mq.addEventListener) mq.addEventListener('change', onChange);
    else if (mq.addListener) mq.addListener(onChange);
  }

  var nav = document.getElementById('secnav');
  if (!nav) return;
  var heads = Array.prototype.slice.call(document.querySelectorAll('h2[id]'));
  if (heads.length < 2) return;

  heads.forEach(function (h) {
    var a = document.createElement('a');
    a.href = '#' + h.id;
    a.textContent = (h.getAttribute('data-nav') || h.firstChild.textContent || h.id).trim();
    nav.appendChild(a);
  });

  var links = {};
  Array.prototype.forEach.call(nav.querySelectorAll('a'), function (a) {
    links[a.getAttribute('href').slice(1)] = a;
  });
  function mark(id) {
    Array.prototype.forEach.call(nav.querySelectorAll('a'), function (a) { a.classList.remove('on'); });
    if (links[id]) links[id].classList.add('on');
  }
  var ticking = false;
  function current() {
    var edge = (nav.getBoundingClientRect().bottom || 0) + 24;
    var id = heads[0].id;
    for (var i = 0; i < heads.length; i++) {
      if (heads[i].getBoundingClientRect().top <= edge) id = heads[i].id; else break;
    }
    if (window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 2) {
      id = heads[heads.length - 1].id;
    }
    return id;
  }
  function update() {
    ticking = false;
    var id = current();
    mark(id);
    var a = links[id];
    if (a && nav.scrollWidth > nav.clientWidth) {
      var l = a.offsetLeft, r = l + a.offsetWidth;
      if (l < nav.scrollLeft || r > nav.scrollLeft + nav.clientWidth) nav.scrollLeft = l - 16;
    }
  }
  window.addEventListener('scroll', function () {
    if (!ticking) { ticking = true; setTimeout(update, 60); }
  }, { passive: true });
  window.addEventListener('resize', update);
  document.addEventListener('visibilitychange', function () { if (!document.hidden) update(); });
  update();
})();
