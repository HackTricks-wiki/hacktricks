/* ht_searcher.js ────────────────────────────────────────────────
   Dual-index Web-Worker search (HackTricks + HackTricks-Cloud)
   with loading icon swap ⏳ → 🔍 and proper host prefix for
   cloud results (https://cloud.hacktricks.wiki).

   Dependencies already expected by the theme:
     • mark.js
     • elasticlunr.min.js          (worker fetches CDN or /elasticlunr.min.js)
     • searchindex.js              (local fallback copies for both wikis)
*/

(() => {
  "use strict";

  /* ───────────── 0. Utility (main thread) ─────────────────── */
  const clear = el => { while (el.firstChild) el.removeChild(el.firstChild); };

  /* ───────────── 1. Web‑Worker code (as string) ───────────── */
  const workerCode = `
    /* emulate browser globals inside worker */
    self.window = self;
    self.search = self.search || {};

    const abs = p => location.origin + p;          /* helper */

    /* 1 ─ elasticlunr (CDN → local) */
    try {
      importScripts('https://cdn.jsdelivr.net/npm/elasticlunr@0.9.5/elasticlunr.min.js');
    } catch {
      importScripts(abs('/elasticlunr.min.js'));
    }

    /* 2 ─ helper to load one search index */
    async function loadIndex(remoteRaw, localPath){
      try {
        const r = await fetch(remoteRaw, {mode:'cors'});
        if (!r.ok) throw new Error('HTTP '+r.status);
        importScripts(URL.createObjectURL(new Blob([await r.text()],{type:'application/javascript'})));
      } catch (e) {
        console.warn(remoteRaw,'→',e,'. Trying local fallback …');
        importScripts(abs(localPath));
      }
      const data = { idxJSON: self.search.index, urls: self.search.doc_urls };
      delete self.search.index; delete self.search.doc_urls;
      return data;
    }

    /* 3 ─ load BOTH indexes */
    (async () => {
      const MAIN_RAW  = 'https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/refs/heads/master/searchindex.js';
      const CLOUD_RAW = 'https://raw.githubusercontent.com/HackTricks-wiki/hacktricks-cloud/refs/heads/master/searchindex.js';

      const { idxJSON:mainJSON,  urls:mainURLs  } = await loadIndex(MAIN_RAW , '/searchindex.js');
      const { idxJSON:cloudJSON, urls:cloudURLs } = await loadIndex(CLOUD_RAW, '/searchindex-cloud.js');

      const mainIdx  = elasticlunr.Index.load(mainJSON);
      const cloudIdx = elasticlunr.Index.load(cloudJSON);
      const MAX_OUT  = 30;

      /* ✔ notify UI */
      postMessage({ready:true});

      /* 4 ─ search handler */
      self.onmessage = ({data:q}) => {
        if (!q) { postMessage([]); return; }
        const opts = { bool:'AND', expand:true };

        function searchAndScale(idx, urls, base=''){
          const res = idx.search(q, opts);
          if (!res.length) return [];
          const max = res[0].score || 1;
          return res.map(r => ({
            normScore: r.score / max,
            doc      : idx.documentStore.getDoc(r.ref),
            url      : base + urls[r.ref]
          }));
        }

        const combined = [
          ...searchAndScale(mainIdx , mainURLs , ''),
          ...searchAndScale(cloudIdx, cloudURLs, 'https://cloud.hacktricks.wiki/')
        ];

        combined.sort((a,b) => b.normScore - a.normScore);
        const top = combined.slice(0, MAX_OUT).map(o => ({
          title      : o.doc.title,
          body       : o.doc.body,
          breadcrumbs: o.doc.breadcrumbs,
          url        : o.url
        }));
        postMessage(top);
      };
    })();
  `;

  /* ───────────── 2. Spawn worker ─────────────────────────── */
  const worker = new Worker(URL.createObjectURL(new Blob([workerCode],{type:'application/javascript'})));

  /* ───────────── 3. DOM refs ─────────────────────────────── */
  const wrap    = document.getElementById('search-wrapper');
  const bar     = document.getElementById('searchbar');
  const list    = document.getElementById('searchresults');
  const listOut = document.getElementById('searchresults-outer');
  const header  = document.getElementById('searchresults-header');
  const icon    = document.getElementById('search-toggle');

  /* loading icon */
  const READY_ICON = icon.innerHTML;   /* theme SVG/HTML */
  icon.textContent = '⏳';
  icon.setAttribute('aria-label','Loading search …');

  /* key codes */
  const HOTKEY=83, ESC=27, DOWN=40, UP=38, ENTER=13;
  let debounce, teaserCount=0;

  /* ───────────── 4. helpers (teaser etc.) ─────────────── */
  const escapeHTML = (()=>{const M={'&':'&amp;','<':'&lt;','>':'&gt;','"':'&#34;','\'':'&#39;'};return s=>s.replace(/[&<>'"]/g,c=>M[c]);})();

  function metric(c,t){
    return c===0 ? `No search results for '${t}'.`
         : c===1 ? `1 search result for '${t}':`
                  : `${c} search results for '${t}':`;
  }

  function makeTeaser(body,terms){
    const stem=w=>elasticlunr.stemmer(w.toLowerCase());
    const T=terms.map(stem), W_SRCH=40,W_1ST=8,W_NRM=2,WIN=30;
    const W=[], sents=body.toLowerCase().split('. ');
    let idx=0, v=W_1ST, found=false;
    sents.forEach(s=>{
      v=W_1ST;
      s.split(' ').forEach(w=>{
        if(w){
          if(T.some(t=>stem(w).startsWith(t))){v=W_SRCH;found=true;}
          W.push([w,v,idx]); v=W_NRM;
        }
        idx+=w.length+1;
      });
      idx++;
    });
    if(!W.length) return body;
    const win=Math.min(W.length,WIN);
    const sums=[W.slice(0,win).reduce((a,[,wt])=>a+wt,0)];
    for(let i=1;i<=W.length-win;i++)
      sums[i]=sums[i-1]-W[i-1][1]+W[i+win-1][1];
    const best=found ? sums.lastIndexOf(Math.max(...sums)) : 0;
    const out=[]; idx=W[best][2];
    for(let i=best;i<best+win;i++){
      const [w,wt,pos]=W[i];
      if(idx<pos){out.push(body.substring(idx,pos)); idx=pos;}
      if(wt===W_SRCH) out.push('<em>');
      out.push(body.substr(pos,w.length));
      if(wt===W_SRCH) out.push('</em>');
      idx=pos+w.length;
    }
    return out.join('');
  }

  const URL_MARK_PARAM='highlight';
  function formatResult(d,terms){
    const teaser = makeTeaser(escapeHTML(d.body),terms);
    teaserCount++;
    const enc = encodeURIComponent(terms.join(' ')).replace(/'/g,'%27');

    /* decide if absolute */
    const absolute = d.url.startsWith('http');
    const parts = d.url.split('#'); if(parts.length===1) parts.push('');
    const base = absolute ? '' : path_to_root;
    const href = `${base}${parts[0]}?${URL_MARK_PARAM}=${enc}#${parts[1]}`;

    return `<a href="${href}" aria-details="teaser_${teaserCount}">`+
           `${d.breadcrumbs}<span class="teaser" id="teaser_${teaserCount}" aria-label="Search Result Teaser">`+
           `${teaser}</span></a>`;
  }

  function showUI(show){
    wrap.classList.toggle('hidden',!show);
    icon.setAttribute('aria-expanded',show);
    if(show){ window.scrollTo(0,0); bar.focus(); bar.select(); }
    else{ listOut.classList.add('hidden'); [...list.children].forEach(li=>li.classList.remove('focus')); }
  }
  function blurBar(){
    const tmp=document.createElement('input');
    tmp.style.cssText='position:absolute;opacity:0;';
    icon.appendChild(tmp); tmp.focus(); tmp.remove();
  }

  /* ───────────── 5. UI events ───────────────────────────── */
  icon.addEventListener('click',()=>showUI(wrap.classList.contains('hidden')));

  document.addEventListener('keydown',e=>{
    if(e.altKey||e.ctrlKey||e.metaKey||e.shiftKey) return;
    const inForm=/^(?:input|select|textarea)$/i.test(e.target.nodeName);
    if(e.keyCode===HOTKEY && !inForm){ e.preventDefault(); showUI(true); }
    else if(e.keyCode===ESC){ e.preventDefault(); showUI(false); blurBar(); }
    else if(e.keyCode===DOWN && document.activeElement===bar){
      e.preventDefault(); const first=list.firstElementChild; if(first){ blurBar(); first.classList.add('focus'); }
    }else if([DOWN,UP,ENTER].includes(e.keyCode) && document.activeElement!==bar){
      const cur=list.querySelector('li.focus'); if(!cur) return; e.preventDefault();
      if(e.keyCode===DOWN){ const nxt=cur.nextElementSibling; if(nxt){ cur.classList.remove('focus'); nxt.classList.add('focus'); }}
      else if(e.keyCode===UP){ const prv=cur.previousElementSibling; cur.classList.remove('focus'); if(prv){ prv.classList.add('focus'); } else { bar.focus(); }}
      else { const a=cur.querySelector('a'); if(a) window.location.assign(a.href); }
    }
  });

  bar.addEventListener('input',e=>{
    clearTimeout(debounce);
    debounce=setTimeout(()=>worker.postMessage(e.target.value.trim()),120);
  });

  /* ───────────── 6. Worker messages ─────────────────────── */
  worker.onmessage = ({data}) => {
    if(data && data.ready){
      icon.innerHTML=READY_ICON;
      icon.setAttribute('aria-label','Open search (S)');
      return;
    }
    const docs=data;
    const q = bar.value.trim(); const terms=q.split(/\s+/).filter(Boolean);
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
