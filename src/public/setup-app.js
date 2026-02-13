// Served at /setup/app.js
// No fancy syntax: keep it maximally compatible.

(function () {
  var statusEl = document.getElementById('status');
  var authGroupEl = document.getElementById('authGroup');
  var authChoiceEl = document.getElementById('authChoice');
  var logEl = document.getElementById('log');
  var oauthHintEl = document.getElementById('oauthHint');

  var oauthAuthChoices = [];

  function isOAuthChoice(choice) {
    return oauthAuthChoices.indexOf(choice) !== -1;
  }

  function escapeHtml(s) {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function linkifyUrls(text) {
    var escaped = escapeHtml(text);
    return escaped.replace(/(https?:\/\/[^\s<"']+)/g, '<a href="$1" target="_blank" rel="noopener">$1</a>');
  }

  function appendLog(text) {
    logEl.innerHTML += linkifyUrls(text);
    logEl.scrollTop = logEl.scrollHeight;
  }

  function fetchStream(url, payload, onEvent) {
    return fetch(url, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload)
    }).then(function (res) {
      if (!res.ok) {
        return res.text().then(function (t) { throw new Error('HTTP ' + res.status + ': ' + t); });
      }
      var reader = res.body.getReader();
      var decoder = new TextDecoder();
      var buf = '';

      function pump() {
        return reader.read().then(function (result) {
          if (result.done) return;
          buf += decoder.decode(result.value, { stream: true });
          var lines = buf.split('\n');
          buf = lines.pop() || '';
          for (var i = 0; i < lines.length; i++) {
            if (!lines[i].trim()) continue;
            try {
              onEvent(JSON.parse(lines[i]));
            } catch (_e) {
              // ignore malformed lines
            }
          }
          return pump();
        });
      }

      return pump();
    });
  }

  function setStatus(s) {
    statusEl.textContent = s;
  }

  function updateOAuthHint() {
    if (!oauthHintEl) return;
    oauthHintEl.style.display = isOAuthChoice(authChoiceEl.value) ? 'block' : 'none';
  }

  function renderAuth(groups) {
    authGroupEl.innerHTML = '';
    for (var i = 0; i < groups.length; i++) {
      var g = groups[i];
      var opt = document.createElement('option');
      opt.value = g.value;
      opt.textContent = g.label + (g.hint ? ' - ' + g.hint : '');
      authGroupEl.appendChild(opt);
    }

    authGroupEl.onchange = function () {
      var sel = null;
      for (var j = 0; j < groups.length; j++) {
        if (groups[j].value === authGroupEl.value) sel = groups[j];
      }
      authChoiceEl.innerHTML = '';
      var opts = (sel && sel.options) ? sel.options : [];
      for (var k = 0; k < opts.length; k++) {
        var o = opts[k];
        var opt2 = document.createElement('option');
        opt2.value = o.value;
        opt2.textContent = o.label + (o.hint ? ' - ' + o.hint : '');
        authChoiceEl.appendChild(opt2);
      }
      updateOAuthHint();
    };

    authGroupEl.onchange();
  }

  authChoiceEl.addEventListener('change', updateOAuthHint);

  function httpJson(url, opts) {
    opts = opts || {};
    opts.credentials = 'same-origin';
    return fetch(url, opts).then(function (res) {
      if (!res.ok) {
        return res.text().then(function (t) {
          throw new Error('HTTP ' + res.status + ': ' + (t || res.statusText));
        });
      }
      return res.json();
    });
  }

  function refreshStatus() {
    setStatus('Loading...');
    return httpJson('/setup/api/status').then(function (j) {
      var ver = j.openclawVersion ? (' | ' + j.openclawVersion) : '';
      setStatus((j.configured ? 'Configured - open /openclaw' : 'Not configured - run setup below') + ver);
      if (j.oauthAuthChoices) oauthAuthChoices = j.oauthAuthChoices;
      renderAuth(j.authGroups || []);
      // If channels are unsupported, surface it for debugging.
      if (j.channelsAddHelp && j.channelsAddHelp.indexOf('telegram') === -1) {
        appendLog('\nNote: this openclaw build does not list telegram in `channels add --help`. Telegram auto-add will be skipped.\n');
      }

    }).catch(function (e) {
      setStatus('Error: ' + String(e));
    });
  }

  document.getElementById('run').onclick = function () {
    var payload = {
      flow: document.getElementById('flow').value,
      authChoice: authChoiceEl.value,
      authSecret: document.getElementById('authSecret').value,
      subagentModel: document.getElementById('subagentModel').value,
      telegramToken: document.getElementById('telegramToken').value,
      discordToken: document.getElementById('discordToken').value,
      slackBotToken: document.getElementById('slackBotToken').value,
      slackAppToken: document.getElementById('slackAppToken').value
    };

    logEl.innerHTML = '';

    if (isOAuthChoice(payload.authChoice)) {
      appendLog('Starting interactive OAuth setup...\n');
      fetchStream('/setup/api/run-stream', payload, function (ev) {
        switch (ev.type) {
          case 'log':
            appendLog(ev.text || '');
            break;
          case 'status':
            appendLog('\n--- ' + (ev.message || ev.step) + ' ---\n');
            break;
          case 'done':
            appendLog('\n' + (ev.ok ? 'Setup complete!' : 'Setup finished with errors.') + '\n');
            refreshStatus();
            break;
          case 'error':
            appendLog('\nError: ' + (ev.message || 'unknown') + '\n');
            break;
        }
      }).catch(function (e) {
        appendLog('\nStream error: ' + String(e) + '\n');
      });
    } else {
      appendLog('Running...\n');

      fetch('/setup/api/run', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(payload)
      }).then(function (res) {
        return res.text();
      }).then(function (text) {
        var j;
        try { j = JSON.parse(text); } catch (_e) { j = { ok: false, output: text }; }
        appendLog(j.output || JSON.stringify(j, null, 2));
        return refreshStatus();
      }).catch(function (e) {
        appendLog('\nError: ' + String(e) + '\n');
      });
    }
  };

  // Update model config on a running instance
  document.getElementById('updateModels').onclick = function () {
    var subagentModel = document.getElementById('subagentModel').value;
    if (!subagentModel) {
      alert('Enter a sub-agent model first (e.g., openrouter/pony-alpha)');
      return;
    }
    var isOpenRouter = subagentModel.indexOf('openrouter/') === 0;
    logEl.innerHTML = '';
    appendLog('Updating model config...\n');
    fetch('/setup/api/update-models', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        subagentModel: subagentModel,
        enableOpenRouterFallback: isOpenRouter
      })
    }).then(function (res) { return res.json(); })
      .then(function (j) {
        appendLog((j.output || JSON.stringify(j, null, 2)) + '\n');
        if (j.ok) appendLog('\n✓ Model config updated. Gateway restarted.\n');
      })
      .catch(function (e) { appendLog('Error: ' + String(e) + '\n'); });
  };

  // Pairing approve helper
  var pairingBtn = document.getElementById('pairingApprove');
  if (pairingBtn) {
    pairingBtn.onclick = function () {
      var channel = prompt('Enter channel (telegram or discord):');
      if (!channel) return;
      channel = channel.trim().toLowerCase();
      if (channel !== 'telegram' && channel !== 'discord') {
        alert('Channel must be "telegram" or "discord"');
        return;
      }
      var code = prompt('Enter pairing code (e.g. 3EY4PUYS):');
      if (!code) return;
      appendLog('\nApproving pairing for ' + channel + '...\n');
      fetch('/setup/api/pairing/approve', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ channel: channel, code: code.trim() })
      }).then(function (r) { return r.text(); })
        .then(function (t) { appendLog(t + '\n'); })
        .catch(function (e) { appendLog('Error: ' + String(e) + '\n'); });
    };
  }

  document.getElementById('reset').onclick = function () {
    if (!confirm('Reset setup? This deletes the config file so onboarding can run again.')) return;
    logEl.innerHTML = '';
    appendLog('Resetting...\n');
    fetch('/setup/api/reset', { method: 'POST', credentials: 'same-origin' })
      .then(function (res) { return res.text(); })
      .then(function (t) { appendLog(t + '\n'); return refreshStatus(); })
      .catch(function (e) { appendLog('Error: ' + String(e) + '\n'); });
  };

  refreshStatus();
})();
