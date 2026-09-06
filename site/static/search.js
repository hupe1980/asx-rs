/*!
 * Documentation search and code-block copy buttons.
 *
 * No third-party JavaScript and no CDN: everything here is served from the same
 * origin as the page. The search index is Zola's elasticlunr JSON, but only its
 * `documentStore` is read — the inverted index it also contains is not needed
 * for a site this size, and pulling in elasticlunr to query it would mean
 * shipping a library to do substring matching.
 *
 * The index is fetched lazily, on the first interaction that could need it, so
 * it costs nothing on page load.
 */
(function () {
  'use strict';

  // ── Search ────────────────────────────────────────────────────────────────

  var script = document.currentScript;
  var indexUrl = script && script.dataset ? script.dataset.index : null;
  var dialog = document.querySelector('[data-search-dialog]');
  var input = document.querySelector('[data-search-input]');
  var results = document.querySelector('[data-search-results]');
  var openers = document.querySelectorAll('[data-search-open]');

  var docs = null;
  var loading = null;

  function loadIndex() {
    if (docs) return Promise.resolve(docs);
    if (loading) return loading;
    loading = fetch(indexUrl)
      .then(function (r) {
        if (!r.ok) throw new Error('search index unavailable');
        return r.json();
      })
      .then(function (data) {
        var store = (data.documentStore && data.documentStore.docs) || {};
        docs = Object.keys(store).map(function (id) {
          var d = store[id];
          return {
            id: d.id || id,
            title: d.title || '',
            body: d.body || '',
            haystack: ((d.title || '') + ' ' + (d.body || '')).toLowerCase()
          };
        });
        return docs;
      })
      .catch(function () {
        docs = [];
        return docs;
      });
    return loading;
  }

  /**
   * Rank by where the terms hit: a title match is what the reader is usually
   * after, so it outranks a body match rather than merely adding to it.
   */
  function search(query) {
    var terms = query.toLowerCase().split(/\s+/).filter(Boolean);
    if (!terms.length) return [];

    return docs
      .map(function (doc) {
        var score = 0;
        var titleLower = doc.title.toLowerCase();
        for (var i = 0; i < terms.length; i++) {
          var term = terms[i];
          if (doc.haystack.indexOf(term) === -1) return null; // every term must appear
          if (titleLower.indexOf(term) !== -1) score += 10;
          var occurrences = doc.body.toLowerCase().split(term).length - 1;
          score += Math.min(occurrences, 5);
        }
        return { doc: doc, score: score, snippet: snippetFor(doc, terms[0]) };
      })
      .filter(Boolean)
      .sort(function (a, b) { return b.score - a.score; })
      .slice(0, 8);
  }

  function snippetFor(doc, term) {
    var body = doc.body;
    var at = body.toLowerCase().indexOf(term);
    if (at === -1) return body.slice(0, 120);
    var start = Math.max(0, at - 40);
    return (start > 0 ? '…' : '') + body.slice(start, start + 140).trim() + '…';
  }

  function escapeHtml(value) {
    return value.replace(/[&<>"']/g, function (ch) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch];
    });
  }

  function render(matches, query) {
    if (!query) {
      results.innerHTML = '<p class="search-empty">Type to search the documentation.</p>';
      return;
    }
    if (!matches.length) {
      results.innerHTML =
        '<p class="search-empty">No match for <strong>' + escapeHtml(query) + '</strong>.</p>';
      return;
    }
    results.innerHTML = matches
      .map(function (m) {
        return (
          '<a class="search-hit" href="' + escapeHtml(m.doc.id) + '">' +
          '<span class="search-hit-title">' + escapeHtml(m.doc.title) + '</span>' +
          '<span class="search-hit-snippet">' + escapeHtml(m.snippet) + '</span>' +
          '</a>'
        );
      })
      .join('');
  }

  function openSearch() {
    if (!dialog) return;
    loadIndex().then(function () {
      if (input.value) render(search(input.value), input.value);
    });
    if (!dialog.open) {
      if (typeof dialog.showModal === 'function') dialog.showModal();
      else dialog.setAttribute('open', '');
    }
    input.focus();
    input.select();
  }

  if (dialog && input && results) {
    for (var i = 0; i < openers.length; i++) {
      openers[i].addEventListener('click', openSearch);
    }

    input.addEventListener('input', function () {
      var query = input.value.trim();
      loadIndex().then(function () { render(search(query), query); });
    });

    // Keep Enter on the first hit rather than submitting an empty dialog form.
    input.addEventListener('keydown', function (event) {
      if (event.key !== 'Enter') return;
      var first = results.querySelector('.search-hit');
      if (first) {
        event.preventDefault();
        window.location.href = first.getAttribute('href');
      }
    });

    document.addEventListener('keydown', function (event) {
      var typingElsewhere =
        /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName) ||
        document.activeElement.isContentEditable;

      if ((event.key === '/' || (event.key === 'k' && (event.metaKey || event.ctrlKey))) &&
          !typingElsewhere) {
        event.preventDefault();
        openSearch();
      }
    });

    render([], '');
  }

  // ── Copy buttons on code blocks ───────────────────────────────────────────

  if (navigator.clipboard) {
    var blocks = document.querySelectorAll('.doc-body pre, .code-sample pre');
    for (var b = 0; b < blocks.length; b++) {
      (function (pre) {
        var button = document.createElement('button');
        button.type = 'button';
        button.className = 'copy-btn';
        button.textContent = 'Copy';
        button.setAttribute('aria-label', 'Copy code to clipboard');
        button.addEventListener('click', function () {
          navigator.clipboard.writeText(pre.innerText).then(
            function () {
              button.textContent = 'Copied';
              button.classList.add('is-copied');
              setTimeout(function () {
                button.textContent = 'Copy';
                button.classList.remove('is-copied');
              }, 1600);
            },
            function () {
              button.textContent = 'Press ⌘C';
            }
          );
        });
        pre.parentNode.insertBefore(button, pre);
        pre.parentNode.classList.add('has-copy');
      })(blocks[b]);
    }
  }
})();
