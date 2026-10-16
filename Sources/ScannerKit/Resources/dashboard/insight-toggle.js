(function () {
  var KEY = 'ms_hidden_insights';
  var hidden;
  try { hidden = JSON.parse(localStorage.getItem(KEY) || '[]'); } catch (e) { hidden = []; }
  function save() { try { localStorage.setItem(KEY, JSON.stringify(hidden)); } catch (e) {} }
  function labelOf(card) { var l = card.querySelector('.ilab'); return l ? l.textContent.trim() : ''; }
  function apply() {
    document.querySelectorAll('.insight').forEach(function (card) {
      card.classList.toggle('ihidden', hidden.indexOf(labelOf(card)) >= 0);
    });
    var btn = document.getElementById('insight-restore');
    if (btn) { var n = hidden.length; btn.hidden = n === 0; var s = btn.querySelector('.n'); if (s) s.textContent = n; }
  }
  document.addEventListener('click', function (e) {
    var h = e.target.closest('.ihide');
    if (h) { var card = h.closest('.insight'); if (card) { var lab = labelOf(card); if (hidden.indexOf(lab) < 0) hidden.push(lab); save(); apply(); } return; }
    if (e.target.closest('#insight-restore')) { hidden = []; save(); apply(); }
  });
  apply();
})();
