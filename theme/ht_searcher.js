/* ht_searcher.js ───────────────────────────────────────────────── */
/* Everything – UI + worker – lives in this one file. */

(() => {
    /* ──────────────────────────────
       0.  Build an inline Web Worker
       ────────────────────────────── */
    const workerCode = `
      /* inside the worker thread ################################## */
      self.window = self;                        /* let searchindex.js use window */
  
      /* 1. elasticlunr.min.js  (CDN → local) */
      try {
        importScripts('https://cdn.jsdelivr.net/npm/elasticlunr@0.9.5/elasticlunr.min.js');
      } catch (_) {
        importScripts('/elasticlunr.min.js');
      }
  
      /* 2. searchindex.js  (GitHub Raw → local) */
      (async () => {
        try {
          const r = await fetch(
            'https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/refs/heads/master/searchindex.js',
            { mode: 'cors' }
          );
          if (!r.ok) throw new Error(r.status);
          const blobURL = URL.createObjectURL(
            new Blob([await r.text()], { type: 'application/javascript' })
          );                                     /* force correct MIME */
          importScripts(blobURL);
        } catch (_) {
          importScripts('/searchindex.js');
        }
  
        /* 3. Build index & reply to queries */
        const idx = elasticlunr.Index.load(self.search.index);
  
        self.onmessage = ({ data: q }) => {
          const hits = idx.search(q, { bool: 'AND', expand: true });
          postMessage(hits);
        };
      })();
    `;
  
    /* Turn the string into a real worker file */
    const workerURL = URL.createObjectURL(
      new Blob([workerCode], { type: 'application/javascript' })
    );
    const worker = new Worker(workerURL);      /* classic worker, supports importScripts */
    URL.revokeObjectURL(workerURL);            /* clean up */
  
    /* ──────────────────────────────
       1.  Minimal search-UI glue
       ────────────────────────────── */
    const WRAP   = document.getElementById('search-wrapper');
    const TOG    = document.getElementById('search-toggle');
    const INP    = document.getElementById('searchbar');
    const LIST   = document.getElementById('searchresults');
    const HOTKEY = 83;          /* “s” */
    let debounce;
  
    /* Paint results that come back from the worker */
    const paint = hits => {
      LIST.innerHTML = hits.slice(0, 30).map(h =>
        '<li><a href="' + h.doc.url + '">' + h.doc.title + '</a></li>'
      ).join('');
    };
  
    worker.onmessage = ({ data }) => paint(data);
  
    /* Open the search UI */
    const open = () => {
      WRAP.classList.remove('hidden');
      INP.focus();
    };
  
    /* Toggle button */
    TOG.addEventListener('click', open);
  
    /* Keyboard shortcut: “s” (no modifiers) */
    document.addEventListener('keydown', e => {
      if (!e.metaKey && !e.ctrlKey && !e.altKey && e.keyCode === HOTKEY) {
        e.preventDefault();
        open();
      }
    });
  
    /* Debounced input → worker */
    INP.addEventListener('input', e => {
      clearTimeout(debounce);
      debounce = setTimeout(() => {
        worker.postMessage(e.target.value.trim());
      }, 120);
    });
  })();
  