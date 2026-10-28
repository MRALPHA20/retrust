"""The one script the server hands out: /static/retrust.js.

Every page and flow works without it (the no-JS markup is the contract); this
only adds search suggestions, a drawer focus trap, toasts, a loading note,
copy-all and mark-as-sent, gap-card focus and Esc for tooltips.

Rules the string below must keep (tests/test_enhance.py checks the first two):
  * no innerHTML, outerHTML, insertAdjacentHTML, document.write, eval or
    new Function: every node is built with createElement and textContent, so
    text from the index can never become markup;
  * no URL other than a same-origin path (the only request is
    fetch('/search.json?q=...'));
  * every behaviour sits in its own try/catch, so one failure cannot take the
    others (or the page) down.

It is a raw string: the JS escapes such as \\u2026 reach the browser as written
and the file stays ASCII.
"""

SCRIPT = r"""'use strict';
(function () {
  var doc = document;
  var root = doc.documentElement;
  // Read when needed, not once: the attribute is the page's, not the script's.
  function isHosted() { return root.getAttribute('data-hosted') === '1'; }
  var TOAST_MS = 5000;
  var WAKE_MS = 4000;
  var DEBOUNCE_MS = 150;
  var MIN_QUERY = 2;

  function el(tag, cls, text) {
    var node = doc.createElement(tag);
    if (cls) { node.className = cls; }
    if (text !== undefined && text !== null) { node.textContent = String(text); }
    return node;
  }

  function closest(node, selector) {
    return node && node.closest ? node.closest(selector) : null;
  }

  function attempt(fn) {
    try { fn(); } catch (err) { /* an enhancement must never break the page */ }
  }

  // Only same-origin absolute paths are ever navigated to from fetched data.
  function safePath(href) {
    return typeof href === 'string' && href.charAt(0) === '/'
      && href.charAt(1) !== '/' && href.charAt(1) !== '\\';
  }

  // ---------------------------------------------------------------- toasts
  var region = null;

  function removeNode(node) {
    if (node.parentNode) { node.parentNode.removeChild(node); }
  }

  function toast(message, kind) {
    kind = (kind === 'error' || kind === 'success') ? kind : 'info';
    var tone = kind === 'success' ? 'prefer' : (kind === 'error' ? 'avoid' : 'neutral');
    var glyph = kind === 'success' ? '\u2713' : (kind === 'error' ? '\u25A0' : 'i');
    var node = el('div', 'rt-toast rt-toast--' + tone);
    if (kind === 'error') { node.setAttribute('role', 'alert'); }
    var mark = el('span', 'rt-toast__glyph', glyph);
    mark.setAttribute('aria-hidden', 'true');
    node.appendChild(mark);
    node.appendChild(el('span', 'rt-toast__text', message));
    if (kind === 'error') {
      // Errors stay until the reader has seen them.
      var close = el('button', 'rt-toast__close', '\u00D7');
      close.type = 'button';
      close.setAttribute('aria-label', 'Dismiss');
      close.addEventListener('click', function () { removeNode(node); });
      node.appendChild(close);
    }
    var fresh = !region || !region.isConnected;
    if (fresh) {
      region = el('div', 'rt-toasts');
      region.setAttribute('role', 'status');
      doc.body.appendChild(region);
    }
    var show = function () {
      while (region.children.length >= 4) { removeNode(region.firstChild); }
      region.appendChild(node);
      if (kind !== 'error') { setTimeout(function () { removeNode(node); }, TOAST_MS); }
    };
    // A live region must exist before its content does, or it is not announced.
    if (fresh) { setTimeout(show, 60); } else { show(); }
    return node;
  }

  // ---------------------------------------------------------- global search
  // Which shortcut to print in the hint. Both Ctrl+K and Cmd+K always work;
  // this only decides what the placeholder says, so any failure to read the
  // platform falls back to the non-Apple wording rather than throwing.
  function isApple() {
    try {
      var nav = window.navigator || {};
      var platform = (nav.userAgentData && nav.userAgentData.platform) || nav.platform || '';
      return /mac|iphone|ipad|ipod/i.test(String(platform));
    } catch (error) { return false; }
  }

  function initSearch() {
    var form = doc.querySelector('form[role=search]');
    var input = form ? form.querySelector('input[name=q]') : null;
    if (!input) { return; }

    var base = input.getAttribute('placeholder') || '';
    if (!(window.matchMedia && window.matchMedia('(pointer: coarse)').matches)) {
      input.setAttribute('placeholder', base + (isApple() ? ' \u2318K' : ' Ctrl K'));
    }

    var box = el('div', 'rt-suggest');
    box.hidden = true;
    var list = el('ul', 'rt-suggest__list');
    list.id = 'rt-suggest-list';
    list.setAttribute('role', 'listbox');
    list.setAttribute('aria-label', 'Product suggestions');
    var none = el('p', 'rt-suggest__empty');
    none.hidden = true;
    var live = el('div', 'rt-sr');
    live.setAttribute('role', 'status');
    box.appendChild(list);
    box.appendChild(none);
    form.appendChild(box);
    form.appendChild(live);

    input.setAttribute('role', 'combobox');
    input.setAttribute('aria-autocomplete', 'list');
    input.setAttribute('aria-haspopup', 'listbox');
    input.setAttribute('aria-expanded', 'false');
    input.setAttribute('aria-controls', list.id);

    var active = -1;
    var timer = null;
    var controller = null;

    function setActive(index) {
      var items = list.children;
      if (active >= 0 && items[active]) { items[active].setAttribute('aria-selected', 'false'); }
      active = index;
      if (index >= 0 && items[index]) {
        items[index].setAttribute('aria-selected', 'true');
        input.setAttribute('aria-activedescendant', items[index].id);
        attempt(function () { items[index].scrollIntoView({ block: 'nearest' }); });
      } else {
        active = -1;
        input.removeAttribute('aria-activedescendant');
      }
    }

    function closeList() {
      box.hidden = true;
      input.setAttribute('aria-expanded', 'false');
      setActive(-1);
    }

    function openList() {
      box.hidden = false;
      input.setAttribute('aria-expanded', 'true');
    }

    function go(row) {
      var href = row ? row.getAttribute('data-href') : '';
      if (safePath(href)) { window.location.assign(href); }
    }

    function render(data, typed) {
      while (list.firstChild) { list.removeChild(list.firstChild); }
      setActive(-1);
      var results = (data && Array.isArray(data.results)) ? data.results : [];
      var shown = 0;
      results.forEach(function (item) {
        if (!item || !safePath(item.href)) { return; }
        var row = el('li', 'rt-suggest__row');
        row.id = 'rt-suggest-' + shown;
        row.setAttribute('role', 'option');
        row.setAttribute('aria-selected', 'false');
        row.setAttribute('data-href', item.href);
        var primary = item.order_number || item.name || '';
        var secondary = item.order_number ? (item.name || '') : '';
        row.appendChild(el('span', 'rt-suggest__no', primary));
        if (secondary) { row.appendChild(el('span', 'rt-suggest__name', secondary)); }
        if (item.vendor) { row.appendChild(el('span', 'rt-suggest__vendor', item.vendor)); }
        list.appendChild(row);
        shown += 1;
      });
      if (shown) {
        none.hidden = true;
        list.hidden = false;
        live.textContent = shown + (shown === 1 ? ' suggestion' : ' suggestions');
        openList();
      } else if (data && data.empty) {
        list.hidden = true;
        none.textContent = 'No product matches "' + typed + '". Try the manufacturer order number.';
        none.hidden = false;
        live.textContent = none.textContent;
        openList();
      } else {
        closeList();
      }
    }

    function request(typed) {
      if (controller) { controller.abort(); }
      controller = (typeof AbortController === 'function') ? new AbortController() : null;
      var options = { credentials: 'same-origin', headers: { Accept: 'application/json' } };
      if (controller) { options.signal = controller.signal; }
      fetch('/search.json?q=' + encodeURIComponent(typed), options)
        .then(function (response) {
          if (!response.ok) { throw new Error('status ' + response.status); }
          return response.json();
        })
        .then(function (data) {
          // A slow answer for an old query must not replace the current one.
          if (input.value.trim() === typed) { render(data, typed); }
        })
        .catch(function () { /* aborted or offline: the form still submits */ });
    }

    input.addEventListener('input', function () {
      clearTimeout(timer);
      var typed = input.value.trim();
      if (typed.length < MIN_QUERY) {
        if (controller) { controller.abort(); }
        closeList();
        return;
      }
      timer = setTimeout(function () { request(typed); }, DEBOUNCE_MS);
    });

    input.addEventListener('keydown', function (event) {
      if (event.isComposing) { return; }
      var count = list.children.length;
      var isOpen = !box.hidden;
      if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
        if (!isOpen || !count) { return; }
        event.preventDefault();
        if (event.key === 'ArrowDown') { setActive(active < 0 || active >= count - 1 ? 0 : active + 1); }
        else { setActive(active <= 0 ? count - 1 : active - 1); }
      } else if (event.key === 'Enter') {
        // No highlighted row: the form submits normally.
        if (isOpen && active >= 0) { event.preventDefault(); go(list.children[active]); }
      } else if (event.key === 'Escape') {
        if (isOpen) { event.preventDefault(); event.stopPropagation(); closeList(); }
      } else if (event.key === 'Tab') {
        closeList();
      }
    });

    // Keep focus in the field while the pointer picks a row.
    list.addEventListener('mousedown', function (event) { event.preventDefault(); });
    list.addEventListener('click', function (event) { go(closest(event.target, '.rt-suggest__row')); });
    list.addEventListener('mouseover', function (event) {
      var row = closest(event.target, '.rt-suggest__row');
      if (row && row.parentNode === list) {
        setActive(Array.prototype.indexOf.call(list.children, row));
      }
    });
    form.addEventListener('focusout', function () {
      setTimeout(function () { if (!form.contains(doc.activeElement)) { closeList(); } }, 0);
    });
    window.addEventListener('pageshow', closeList);

    doc.addEventListener('keydown', function (event) {
      if ((event.ctrlKey || event.metaKey) && !event.altKey && !event.shiftKey
          && String(event.key).toLowerCase() === 'k') {
        event.preventDefault();
        input.focus();
        input.select();
      }
    });
  }

  // ---------------------------------------------------------------- drawers
  var FOCUSABLE = 'a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),'
    + 'textarea:not([disabled]),summary,[tabindex]:not([tabindex="-1"])';

  function visibleFocusables(container) {
    return Array.prototype.filter.call(container.querySelectorAll(FOCUSABLE), function (node) {
      return node.getClientRects().length > 0;
    });
  }

  function initDrawers() {
    var openers = {};
    var current = null;

    doc.addEventListener('click', function (event) {
      var opener = closest(event.target, '[popovertarget]');
      if (opener && opener.getAttribute('popovertargetaction') !== 'hide') {
        openers[opener.getAttribute('popovertarget')] = opener;
      }
    }, true);

    // toggle does not bubble, so listen in the capture phase.
    doc.addEventListener('toggle', function (event) {
      var drawer = event.target;
      if (!drawer.classList || !drawer.classList.contains('ev-drawer')) { return; }
      if (event.newState === 'open') {
        current = drawer;
        var close = drawer.querySelector('.ev-close');
        if (close) { close.focus(); }
      } else {
        if (current === drawer) { current = null; }
        var opener = openers[drawer.id];
        var at = doc.activeElement;
        // The browser normally restores focus; this covers the cases where it did not.
        if (opener && opener.isConnected && (!at || at === doc.body || drawer.contains(at))) {
          opener.focus();
        }
      }
    }, true);

    doc.addEventListener('keydown', function (event) {
      if (event.key !== 'Tab' || !current || !current.isConnected) { return; }
      var items = visibleFocusables(current);
      if (!items.length) { event.preventDefault(); return; }
      var first = items[0];
      var last = items[items.length - 1];
      var at = doc.activeElement;
      if (!current.contains(at)) { event.preventDefault(); first.focus(); }
      else if (event.shiftKey && at === first) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && at === last) { event.preventDefault(); first.focus(); }
    });
  }

  // ------------------------------------------------------------ export menu
  function initExportMenu() {
    doc.addEventListener('click', function (event) {
      var link = closest(event.target, '.rt-menu__list a[href]');
      if (!link || event.defaultPrevented) { return; }
      var name = link.getAttribute('data-filename');
      if (!name) {
        name = 'retrust-' + (link.getAttribute('href') || '').split('?')[0].split('/').pop();
      }
      toast('Exported ' + name, 'success');
      var menu = closest(link, '.rt-menu__list');
      // Hiding does not cancel the download: the anchor's own action still runs.
      attempt(function () { menu.hidePopover(); });
    });
  }

  // ---------------------------------------------------------- loading state
  var LOADING = {
    '/score': ['Assessing\u2026', 'Resolving product\u2026 \u00B7 Matching firmware\u2026 \u00B7 Scoring\u2026'],
    '/compare': ['Comparing\u2026', 'Resolving product\u2026 \u00B7 Matching firmware\u2026 \u00B7 Scoring\u2026'],
    '/': ['Searching\u2026', 'Searching the index\u2026']
  };
  var WAKING = 'The hosted demo is waking up on the free plan; this can take a minute.';
  var busy = [];

  function startLoading(form, submitter) {
    var path = '';
    attempt(function () { path = new URL(form.action, window.location.href).pathname; });
    var words = LOADING[path];
    var button = (submitter && submitter.tagName === 'BUTTON') ? submitter
      : (form.querySelector('button[type=submit].rt-btn--primary') || form.querySelector('button[type=submit]'));
    if (!words || !button) { return; }
    // Only a form that really switched to its loading look is guarded against a
    // second submit, so a form left alone can never be stuck.
    form.setAttribute('data-rt-busy', '1');

    var label = button.textContent.trim();
    var saved = doc.createDocumentFragment();
    while (button.firstChild) { saved.appendChild(button.firstChild); }
    var stack = el('span', 'rt-btn__stack');
    var ghost = el('span', 'rt-btn__label', label);
    ghost.setAttribute('aria-hidden', 'true');
    var working = el('span', 'rt-btn__busy');
    var spinner = el('span', 'rt-spinner');
    spinner.setAttribute('aria-hidden', 'true');
    working.appendChild(spinner);
    working.appendChild(el('span', '', words[0]));
    stack.appendChild(ghost);
    stack.appendChild(working);
    button.appendChild(stack);
    button.classList.add('rt-btn--loading');
    button.setAttribute('aria-busy', 'true');
    button.setAttribute('aria-disabled', 'true');

    var note = el('p', 'rt-loadnote');
    note.setAttribute('role', 'status');
    form.appendChild(note);
    var timers = [setTimeout(function () { note.textContent = words[1]; }, 50)];
    if (isHosted()) {
      timers.push(setTimeout(function () {
        note.appendChild(el('span', 'rt-loadnote__wake', ' ' + WAKING));
      }, WAKE_MS));
    }
    busy.push({ form: form, button: button, saved: saved, stack: stack, note: note, timers: timers });
  }

  function stopLoading() {
    busy.forEach(function (state) {
      state.timers.forEach(clearTimeout);
      removeNode(state.note);
      removeNode(state.stack);
      state.button.appendChild(state.saved);
      state.button.classList.remove('rt-btn--loading');
      state.button.removeAttribute('aria-busy');
      state.button.removeAttribute('aria-disabled');
      state.form.removeAttribute('data-rt-busy');
    });
    busy = [];
  }

  function initLoading() {
    doc.addEventListener('submit', function (event) {
      var form = event.target;
      if (!form || form.tagName !== 'FORM' || !closest(form, 'main')) { return; }
      if (form.getAttribute('data-rt-busy') === '1') { event.preventDefault(); return; }
      if (event.defaultPrevented) { return; }
      attempt(function () { startLoading(form, event.submitter); });
    });
    // Back/forward restores the page from memory, spinner and all.
    window.addEventListener('pageshow', stopLoading);
  }

  // ------------------------------------------------------ supplier questions
  function initQuestions() {
    var items = doc.querySelectorAll('ol.rt-qlist > li, ol.rt-questions > li');
    if (!items.length) { return; }
    var storeKey = 'retrust:sent:' + window.location.pathname + window.location.search;

    function load() {
      try {
        var raw = window.sessionStorage.getItem(storeKey);
        var parsed = raw ? JSON.parse(raw) : [];
        return Array.isArray(parsed) ? parsed : [];
      } catch (err) { return []; }
    }
    function save(list) {
      try { window.sessionStorage.setItem(storeKey, JSON.stringify(list)); } catch (err) { /* private mode */ }
    }

    var sent = load();
    var texts = [];
    Array.prototype.forEach.call(items, function (item) {
      var textNode = item.querySelector('.rt-q__text');
      if (!textNode) { return; }
      var text = textNode.textContent.trim();
      texts.push(text);
      var label = el('label', 'rt-check rt-sent');
      var box = el('input', 'rt-check__box');
      box.type = 'checkbox';
      var mark = function (on) {
        if (on) { item.setAttribute('data-sent', '1'); } else { item.removeAttribute('data-sent'); }
      };
      box.checked = sent.indexOf(text) !== -1;
      mark(box.checked);
      box.addEventListener('change', function () {
        sent = load().filter(function (entry) { return entry !== text; });
        if (box.checked) { sent.push(text); }
        save(sent);
        mark(box.checked);
      });
      label.appendChild(box);
      label.appendChild(el('span', 'rt-sent__text', 'Mark as sent'));
      // Beside the text, not as a new grid cell of the list item.
      var details = item.querySelector('details');
      if (details) { details.parentNode.insertBefore(label, details); }
      else { textNode.parentNode.appendChild(label); }
    });
    if (!texts.length) { return; }

    var foot = doc.querySelector('.rt-q__foot');
    if (!foot) {
      foot = el('div', 'rt-q__foot');
      var card = closest(items[0], 'section') || items[0].parentNode.parentNode;
      card.appendChild(foot);
    }
    var copy = el('button', 'rt-btn rt-btn--ghost');
    copy.type = 'button';
    copy.appendChild(el('span', 'rt-btn__label', 'Copy all'));
    copy.setAttribute('aria-label', 'Copy all ' + texts.length + ' questions');
    copy.addEventListener('click', function () {
      var body = texts.map(function (text, index) { return (index + 1) + '. ' + text; }).join('\n');
      var done = function () {
        toast('Copied ' + texts.length + (texts.length === 1 ? ' question' : ' questions'), 'success');
      };
      var fail = function () {
        toast('Could not copy. Open the plain text version and select the text instead.', 'error');
      };
      var fallback = function () {
        var area = el('textarea');
        area.value = body;
        area.setAttribute('readonly', '');
        area.className = 'rt-sr';
        doc.body.appendChild(area);
        area.select();
        var ok = false;
        attempt(function () { ok = doc.execCommand('copy'); });
        removeNode(area);
        copy.focus();
        if (ok) { done(); } else { fail(); }
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(body).then(done, fallback);
      } else {
        fallback();
      }
    });
    foot.insertBefore(copy, foot.firstChild);
  }

  // ------------------------------------------------------- gap card -> field
  function initGapLinks() {
    doc.addEventListener('click', function (event) {
      var link = closest(event.target, 'a.rt-gap__link[href^="#"]');
      if (!link || event.defaultPrevented) { return; }
      var id = decodeURIComponent(link.getAttribute('href').slice(1));
      var target = doc.getElementById(id);
      if (!target) { return; }
      var field = /^(INPUT|SELECT|TEXTAREA|BUTTON)$/.test(target.tagName)
        ? target : target.querySelector('input,select,textarea');
      if (!field) { return; }
      // The browser scrolls to the fragment and sets :target; then focus the control.
      setTimeout(function () { field.focus({ preventScroll: true }); }, 0);
    });
  }

  // --------------------------------------------------------------- tooltips
  function initTooltips() {
    doc.addEventListener('keydown', function (event) {
      if (event.key !== 'Escape') { return; }
      var tips = doc.querySelectorAll('.rt-tip:hover,.rt-tip:focus-within');
      Array.prototype.forEach.call(tips, function (tip) { tip.setAttribute('data-dismissed', '1'); });
    });
    var rearm = function (event) {
      var tip = closest(event.target, '.rt-tip[data-dismissed]');
      if (tip && !(event.relatedTarget && tip.contains(event.relatedTarget))) {
        tip.removeAttribute('data-dismissed');
      }
    };
    doc.addEventListener('mouseout', rearm);
    doc.addEventListener('focusout', rearm);
  }

  [initSearch, initDrawers, initExportMenu, initLoading, initQuestions, initGapLinks,
   initTooltips].forEach(attempt);
})();
"""
