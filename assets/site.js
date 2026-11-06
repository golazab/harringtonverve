// Progressive enhancement for the introduction form. Without JS the form still
// posts normally and the server answers with a redirect.
(function () {
  var form = document.getElementById('enquiry');
  if (!form) return;
  var status = document.getElementById('status');
  var stamp = document.getElementById('t');
  stamp.value = String(Date.now());

  var fields = ['name', 'email', 'interest'];
  var EMAIL = /^[^\s@<>()[\]\\,;:"]+@[^\s@<>()[\]\\,;:"]+\.[^\s@<>()[\]\\,;:"]{2,}$/;

  function check() {
    var bad = null;
    fields.forEach(function (id) {
      var el = form.elements[id];
      var v = el.value.trim();
      var ok = v.length > 0 && (id !== 'email' || EMAIL.test(v));
      el.setAttribute('aria-invalid', ok ? 'false' : 'true');
      if (!ok && !bad) bad = el;
    });
    return bad;
  }

  function say(text, kind) {
    status.textContent = text;
    status.className = 'status ' + (kind || '');
  }

  // Links like "Request an invitation" pre-select the matching interest.
  document.querySelectorAll('a[data-interest]').forEach(function (a) {
    a.addEventListener('click', function () {
      var sel = form.elements.interest;
      sel.value = a.getAttribute('data-interest');
      sel.setAttribute('aria-invalid', 'false');
    });
  });

  if (location.search.indexOf('sent=1') !== -1) say('Thank you. Your request has been received.', 'ok');

  form.addEventListener('submit', function (e) {
    e.preventDefault();
    var bad = check();
    if (bad) {
      say(bad.id === 'email' ? 'Enter a valid email address.' : 'Complete the highlighted fields.', 'err');
      bad.focus();
      return;
    }
    var btn = form.querySelector('button');
    btn.disabled = true;
    say('Sending…');

    var data = {};
    new FormData(form).forEach(function (v, k) { data[k] = v; });

    var ctrl = new AbortController();
    var timer = setTimeout(function () { ctrl.abort(); }, 12000);

    fetch(form.action, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify(data),
      credentials: 'same-origin',
      signal: ctrl.signal
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (j) { return { ok: r.ok, status: r.status, j: j }; });
    }).then(function (res) {
      if (res.ok) {
        form.reset();
        stamp.value = String(Date.now());
        say('Thank you. Your request has been received.', 'ok');
      } else if (res.status === 429) {
        say('Too many requests from this connection. Try again in a few minutes.', 'err');
      } else {
        say(res.j.error || 'The request could not be sent. Write to enquiries@harringtonverve.com instead.', 'err');
      }
    }).catch(function () {
      say('The connection timed out. Write to enquiries@harringtonverve.com instead.', 'err');
    }).then(function () {
      clearTimeout(timer);
      btn.disabled = false;
    });
  });
})();
