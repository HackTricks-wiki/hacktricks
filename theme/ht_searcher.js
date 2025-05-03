/* ht_searcher.js ─────────────────────────────────────────────── */
(() => {
    /* ───────────── 0. Inline Web-Worker code ────────────────────── */
    const workerCode = `
      /* Make scripts written for browsers happy inside the worker */
      self.window  = self;
      self.search  = self.search || {};           /* ensure object */
    
      const abs = p => location.origin + p;       /* helper */
    
      /* 1 ─ elasticlunr.min.js  (CDN → local) */
      try {
        importScripts('https://cdn.jsdelivr.net/npm/elasticlunr@0.9.5/elasticlunr.min.js');
      } catch (e) {
        console.error('elasticlunr CDN failed →', e);
        importScripts(abs('/elasticlunr.min.js'));
      }
    
      /* 2 ─ searchindex.js  (GitHub Raw → local) */
      (async () => {
        try {
          const r = await fetch(
            'https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/refs/heads/master/searchindex.js',
            { mode:'cors' }
          );
          if (!r.ok) throw new Error('HTTP ' + r.status);
          const blobURL = URL.createObjectURL(
            new Blob([await r.text()], { type:'application/javascript' })
          );
          importScripts(blobURL);                  /* MIME coercion */
        } catch (e) {
          console.error('GitHub index fetch failed →', e);
          try {
            importScripts(abs('/searchindex.js'));
          } catch (e2) {
            console.error('Local index load failed →', e2);
            throw e2;                              /* abort loudly   */
          }
        }
    
        /* 3 ─ build index & answer queries */
        const idx = elasticlunr.Index.load(self.search.index);
    
        self.onmessage = ({ data:q }) => {
          if (!q) { postMessage([]); return; }     /* empty search */
          const raw  = idx.search(q, { bool:'AND', expand:true });
          const docs = raw.map(r => idx.documentStore.getDoc(r.ref));
          postMessage(docs);                       /* only docs cross thread */
        };
      })();
    `;
    
    const workerURL = URL.createObjectURL(
      new Blob([workerCode], { type:'application/javascript' })
    );
    const worker = new Worker(workerURL);
    URL.revokeObjectURL(workerURL);                /* tidy blob */
    
    /* ───────────── 1. Tiny UI glue ─────────────────────────────── */
    const WRAP  = document.getElementById('search-wrapper');
    const TOG   = document.getElementById('search-toggle');
    const INP   = document.getElementById('searchbar');
    const LIST  = document.getElementById('searchresults');
    const HOTKEY = 83;          /* “s” */
    let debounce;
    
    /* paint results */
    worker.onmessage = ({ data:docs }) => {
      LIST.innerHTML = docs.slice(0,30).map(d =>
        '<li><a href="' + d.url + '">' + d.title + '</a></li>'
      ).join('');
    };
    
    /* open UI */
    const open = () => { WRAP.classList.remove('hidden'); INP.focus(); };
    
    TOG.addEventListener('click', open);
    document.addEventListener('keydown', e => {
      if (!e.metaKey && !e.ctrlKey && !e.altKey && e.keyCode === HOTKEY) {
        e.preventDefault(); open();
      }
    });
    
    /* debounced keystrokes → worker */
    INP.addEventListener('input', e => {
      clearTimeout(debounce);
      debounce = setTimeout(() => {
        worker.postMessage(e.target.value.trim());
      }, 120);
    });
    })();
    