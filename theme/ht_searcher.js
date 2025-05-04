/* ht_searcher.js ────────────────────────────────────────────────
   Full Web-Worker search with “⏳” while loading and “🔍” after.
   Keeps every feature of the original theme (teasers, breadcrumbs,
   highlight link, hot-keys, arrow navigation, ESC to close, …).

   Dependencies already expected by the theme:
     • mark.js             (for in-page highlights)
     • elasticlunr.min.js  (worker fetches a CDN or /elasticlunr.min.js)
     • searchindex.js      (worker fetches GitHub raw or /searchindex.js)
*/

(() => {
  "use strict";

  /* ───────────────── 0. Worker code (string) ───────────────── */
  const workerCode = `
    self.window = self;                      /* make 'window' exist */
    self.search = self.search || {};

    const abs = p => location.origin + p;    /* helper */

    /* 0.1 load elasticlunr (CDN → local fallback) */
    try {
      importScripts('https://cdn.jsdelivr.net/npm/elasticlunr@0.9.5/elasticlunr.min.js');
    } catch {
      importScripts(abs('/elasticlunr.min.js'));
    }

    /* 0.2 load searchindex.js (GitHub → local fallback) */
    (async () => {
      async function loadRemote () {
        const r = await fetch(
          'https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/refs/heads/master/searchindex.js',
          { mode:'cors' }
        );
        if (!r.ok) throw new Error('HTTP '+r.status);
        importScripts(
          URL.createObjectURL(
            new Blob([await r.text()],{type:'application/javascript'})
          )
        );
      }
      try { await loadRemote(); }
      catch(e){ console.warn('remote index failed →',e);
                importScripts(abs('/searchindex.js')); }

      /* 0.3 build index once, keep for all queries */
      const idx       = elasticlunr.Index.load(self.search.index);
      const DOC_URLS  = self.search.doc_urls;
      const MAX       = 30;

      /* ping main-thread so it can swap the icon */
      postMessage({ready:true});

      self.onmessage = ({data:q}) => {
        if (!q) { postMessage([]); return; }
        const res = idx.search(q,{bool:'AND',expand:true}).slice(0,MAX);
        postMessage(res.map(r => {
          const d = idx.documentStore.getDoc(r.ref);
          return {                   /* only the fields the UI needs */
            ref        : r.ref,
            title      : d.title,
            body       : d.body,
            breadcrumbs: d.breadcrumbs,
            url        : DOC_URLS[r.ref]
          };
        }));
      };
    })();
  `;

  /* ───────────────── 1. Build worker ───────────────────────── */
  const workerURL = URL.createObjectURL(
    new Blob([workerCode],{type:'application/javascript'})
  );
  const worker = new Worker(workerURL);
  URL.revokeObjectURL(workerURL);             /* tidy blob */

  /* ───────────────── 2. DOM references ─────────────────────── */
  const wrap   = document.getElementById('search-wrapper');
  const modal  = document.getElementById('search-modal');
  const bar    = document.getElementById('searchbar');
  const list   = document.getElementById('searchresults');
  const listOut= document.getElementById('searchresults-outer');
  const header = document.getElementById('searchresults-header');
  const icon   = document.getElementById('search-toggle');

  /* ───────────────── 3. Constants & state ─────────────────── */
  const HOTKEY = 83, ESC=27, DOWN=40, UP=38, ENTER=13;
  const URL_MARK_PARAM = 'highlight';
  const MAX_RESULTS    = 30;
  const READY_ICON_HTML= icon.innerHTML;      /* save original “🔍” */
  icon.textContent     = '⏳';                /* show hour-glass   */
  icon.setAttribute('aria-label','Loading search …');

  let debounce, teaserCount = 0;

  /* ───────────────── 4. Helpers (escaped, teaser, format …) ─ */
  const escapeHTML = (() => {
    const MAP = {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&#34;',"'":'&#39;'};
    return s => s.replace(/[&<>'"]/g,c=>MAP[c]);
  })();

  function metric(c,t){
    return c===0 ? `No search results for '${t}'.`
         : c===1 ? `1 search result for '${t}':`
                  : `${c} search results for '${t}':`;
  }

  /* ── teaser algorithm (unchanged from theme, just ES-ified) ── */
  function makeTeaser(body,terms){
    const stem = w=>elasticlunr.stemmer(w.toLowerCase());
    const t    = terms.map(stem);
    const W_SEARCH=40,W_FIRST=8,W_NORM=2,WIN=30;
    const wArr=[],sents=body.toLowerCase().split('. ');
    let idx=0, val=W_FIRST, found=false;

    sents.forEach(sent=>{
      val=W_FIRST;
      sent.split(' ').forEach(word=>{
        if(word){
          if(t.some(st=>stem(word).startsWith(st))){val=W_SEARCH;found=true;}
          wArr.push([word,val,idx]); val=W_NORM;
        }
        idx+=word.length+1;
      });
      idx+=1;  /* account for '. ' */
    });
    if(!wArr.length) return body;

    const win = Math.min(wArr.length,WIN);
    const sums=[ wArr.slice(0,win).reduce((a,[,w])=>a+w,0) ];
    for(let i=1;i<=wArr.length-win;i++)
      sums[i]=sums[i-1]-wArr[i-1][1]+wArr[i+win-1][1];

    const best = found ? sums.lastIndexOf(Math.max(...sums)) : 0;
    const out=[], start=wArr[best][2];
    idx=start;
    for(let i=best;i<best+win;i++){
      const [word,w,pos] = wArr[i];
      if(idx<pos){out.push(body.substring(idx,pos)); idx=pos;}
      if(w===W_SEARCH) out.push('<em>');
      out.push(body.substr(pos,word.length));
      if(w===W_SEARCH) out.push('</em>');
      idx=pos+word.length;
    }
    return out.join('');
  }

  function formatResult(doc,terms){
    const teaser = makeTeaser(escapeHTML(doc.body),terms);
    teaserCount++;
    const enc = encodeURIComponent(terms.join(' ')).replace(/'/g,'%27');
    const u   = doc.url.split('#'); if(u.length===1)u.push('');
    return `<a href="${path_to_root}${u[0]}?${URL_MARK_PARAM}=${enc}#${u[1]}" aria-details="teaser_${teaserCount}">`+
           `${doc.breadcrumbs}<span class="teaser" id="teaser_${teaserCount}" aria-label="Search Result Teaser">`+
           `${teaser}</span></a>`;
  }

  const clear = el => { while(el.firstChild) el.removeChild(el.firstChild); };

  function showUI(show){
    wrap.classList.toggle('hidden',!show);
    icon.setAttribute('aria-expanded',show);
    if(!show){
      listOut.classList.add('hidden');
      [...list.children].forEach(li=>li.classList.remove('focus'));
    }else{
      window.scrollTo(0,0);
      bar.focus(); bar.select();
    }
  }

  function blurBar(){
    const tmp=document.createElement('input');
    tmp.style.position='absolute'; tmp.style.opacity=0;
    icon.appendChild(tmp); tmp.focus(); tmp.remove();
  }

  /* ───────────────── 5. Event handlers ─────────────────────── */
  icon.addEventListener('click',()=>showUI(wrap.classList.contains('hidden')));

  document.addEventListener('keydown',e=>{
    if(e.altKey||e.ctrlKey||e.metaKey||e.shiftKey) return;
    const isInput=/^(?:input|select|textarea)$/i.test(e.target.nodeName);

    if(e.keyCode===HOTKEY && !isInput){
      e.preventDefault(); showUI(true);
    }else if(e.keyCode===ESC){
      e.preventDefault(); showUI(false); blurBar();
    }else if(e.keyCode===DOWN && document.activeElement===bar){
      e.preventDefault();
      const first=list.firstElementChild;
      if(first){ blurBar(); first.classList.add('focus'); }
    }else if((e.keyCode===DOWN||e.keyCode===UP||e.keyCode===ENTER)
             && document.activeElement!==bar){
      const cur=list.querySelector('li.focus'); if(!cur) return;
      e.preventDefault();
      if(e.keyCode===DOWN){
        const nxt=cur.nextElementSibling;
        if(nxt){ cur.classList.remove('focus'); nxt.classList.add('focus'); }
      }else if(e.keyCode===UP){
        const prv=cur.previousElementSibling;
        cur.classList.remove('focus');
        if(prv){ prv.classList.add('focus'); } else { bar.focus(); }
      }else{ /* ENTER */
        const a=cur.querySelector('a'); if(a) window.location.assign(a.href);
      }
    }
  });

  bar.addEventListener('input',e=>{
    clearTimeout(debounce);
    debounce=setTimeout(()=>worker.postMessage(e.target.value.trim()),120);
  });

  /* ───────────────── 6. Worker messages ────────────────────── */
  worker.onmessage = ({data})=>{
    if(data && data.ready){                 /* first ping */
      icon.innerHTML=READY_ICON_HTML;       /* restore “🔍” */
      icon.setAttribute('aria-label','Open search (S)');
      return;
    }
    const docs=data;
    const q=bar.value.trim();
    const terms=q.split(/\s+/).filter(Boolean);
    header.textContent=metric(docs.length,q);
    clear(list);
    docs.forEach(d=>{
      const li=document.createElement('li');
      li.innerHTML=formatResult(d,terms);
      list.appendChild(li);
    });
    listOut.classList.toggle('hidden',!docs.length);
  };
})();
