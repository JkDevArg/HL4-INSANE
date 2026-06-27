(function () {
  'use strict';

  var style = document.createElement('style');
  style.textContent = [
    '#ctf-bar{position:fixed;bottom:0;left:0;right:0;z-index:99999;',
    'background:#0d0d0d;border-top:2px solid #00ff41;',
    'padding:8px 20px;display:flex;align-items:center;gap:16px;',
    'font-family:"Courier New",monospace;font-size:13px;color:#00ff41;',
    'box-shadow:0 -2px 10px rgba(0,255,65,.15);}',
    '#ctf-bar-title{font-weight:bold;white-space:nowrap;}',
    '#ctf-bar-hint{flex:1;text-align:center;color:#556b55;}',
    '#ctf-bar-btn{background:#001a00;border:1px solid #00ff41;color:#00ff41;',
    'padding:5px 16px;font-family:monospace;font-size:13px;cursor:pointer;',
    'border-radius:2px;white-space:nowrap;transition:background .2s;}',
    '#ctf-bar-btn:hover:not(:disabled){background:#003300;}',
    '#ctf-bar-btn:disabled{opacity:.35;cursor:not-allowed;}',
    '#ctf-bar-flag{display:none;color:#00ff41;letter-spacing:1.5px;',
    'font-size:13px;font-weight:bold;background:#001a00;border:1px solid #00ff41;',
    'padding:4px 10px;border-radius:2px;}'
  ].join('');
  document.head.appendChild(style);

  var bar = document.createElement('div');
  bar.id = 'ctf-bar';
  bar.innerHTML = '<span id="ctf-bar-title">&#127918; POKE_L4BS &mdash; Gobl1n / INSANE</span>'
    + '<span id="ctf-bar-hint">Encuentra la flag dentro del juego y haz clic para revelarla.</span>'
    + '<button id="ctf-bar-btn">&#127987; Get Flag</button>'
    + '<code id="ctf-bar-flag"></code>';
  document.body.appendChild(bar);

  var hintEl = document.getElementById('ctf-bar-hint');
  var btn    = document.getElementById('ctf-bar-btn');
  var flagEl = document.getElementById('ctf-bar-flag');

  btn.addEventListener('click', function () {
    btn.disabled = true;
    fetch('/ctf/flag', { credentials: 'include' })
      .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, data: d }; }); })
      .then(function (res) {
        if (res.ok) {
          flagEl.textContent = res.data.flag;
          flagEl.style.display = 'inline';
          btn.style.display = 'none';
          hintEl.textContent = '¡Flag obtenida! Envíala en la plataforma.';
        } else {
          alert(res.data.detail || 'Error al obtener la flag.');
          btn.disabled = false;
        }
      })
      .catch(function () { btn.disabled = false; });
  });
})();
