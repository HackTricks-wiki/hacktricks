/* ht_searcher.js ────────────────────────────────────────────────
   Dual‑index Web‑Worker search (HackTricks + HackTricks‑Cloud)
   · keeps working even if one index fails
   · cloud results rendered **blue**
   · ⏳ while loading → 🔍 when ready
*/

(() => {
    "use strict";
  
    /* ───────────── 0. helpers (main thread) ───────────── */
    const clear = el => { while (el.firstChild) el.removeChild(el.firstChild); };
  
    /* ───────────── 1. Web‑Worker code ─────────────────── */
    const workerCode = `
      self.window = self;
      self.search = self.search || {};
      const abs = p => location.origin + p;
  
      /* 1 — elasticlunr */
      try { importScripts('https://cdn.jsdelivr.net/npm/elasticlunr@0.9.5/elasticlunr.min.js'); }
      catch { importScripts(abs('/elasticlunr.min.js')); }
  
    /* 2 — XOR decryption function */
    function xorDecrypt(encryptedData, key){
      const keyBytes = new TextEncoder().encode(key);
      const decrypted = new Uint8Array(encryptedData.length);
      for(let i = 0; i < encryptedData.length; i++){
        decrypted[i] = encryptedData[i] ^ keyBytes[i % keyBytes.length];
      }
      return decrypted.buffer;
    }

    /* 3 — decompress gzip data */
    async function decompressGzip(arrayBuffer){
      if(typeof DecompressionStream !== 'undefined'){
        /* Modern browsers: use native DecompressionStream */
        const stream = new Response(arrayBuffer).body.pipeThrough(new DecompressionStream('gzip'));
        const decompressed = await new Response(stream).arrayBuffer();
        return new TextDecoder().decode(decompressed);
      } else {
        /* Fallback: use pako library */
        if(typeof pako === 'undefined'){
          try { importScripts('https://cdn.jsdelivr.net/npm/pako@2.1.0/dist/pako.min.js'); }
          catch(e){ throw new Error('pako library required for decompression: '+e); }
        }
        const uint8Array = new Uint8Array(arrayBuffer);
        const decompressed = pako.ungzip(uint8Array, {to: 'string'});
        return decompressed;
      }
    }

    /* 4 — load a single index (remote → local) */
    async function loadIndex(remote, local, isCloud=false){
      const XOR_KEY = "Prevent_Online_AVs_From_Flagging_HackTricks_Search_Gzip_As_Malicious_394h7gt8rf9u3rf9g";
      let rawLoaded = false;
      if(remote){
        /* Try ONLY compressed version from GitHub (remote already includes .js.gz) */
        try {
          const r = await fetch(remote,{mode:'cors'});
          if (r.ok) {
            const encryptedCompressed = await r.arrayBuffer();
            /* Decrypt first */
            const compressed = xorDecrypt(new Uint8Array(encryptedCompressed), XOR_KEY);
            /* Then decompress */
            const text = await decompressGzip(compressed);
            importScripts(URL.createObjectURL(new Blob([text],{type:'application/javascript'})));
            rawLoaded = true;
            console.log('Loaded encrypted+compressed from GitHub:',remote);
          }
        } catch(e){ console.warn('encrypted+compressed GitHub',remote,'failed →',e); }
      }
      /* If remote (GitHub) failed, fall back to local uncompressed file */
      if(!rawLoaded && local){
        try { 
          importScripts(abs(local)); 
          rawLoaded = true;
          console.log('Loaded local fallback:',local);
        }
        catch(e){ console.error('local',local,'failed →',e); }
      }
      if(!rawLoaded) return null;                 /* give up on this index */
      const data = { json:self.search.index, urls:self.search.doc_urls, cloud:isCloud };
      delete self.search.index; delete self.search.doc_urls;
      return data;
    }

    async function loadWithFallback(remotes, local, isCloud=false){
      if(remotes.length){
        const [primary, ...secondary] = remotes;
        const primaryData = await loadIndex(primary, null, isCloud);
        if(primaryData) return primaryData;

        if(local){
          const localData = await loadIndex(null, local, isCloud);
          if(localData) return localData;
        }

        for (const remote of secondary){
          const data = await loadIndex(remote, null, isCloud);
          if(data) return data;
        }
      }

      return local ? loadIndex(null, local, isCloud) : null;
    }
    
    let built = [];
    const MAX = 30, opts = {bool:'AND', expand:true};
    
    self.onmessage = async ({data}) => {
      if(data.type === 'init'){
        const lang = data.lang || 'en';
        const searchindexBase = 'https://raw.githubusercontent.com/HackTricks-wiki/hacktricks-searchindex/master';

        /* Remote sources are .js.gz (compressed), local fallback is .js (uncompressed) */
        const mainFilenames = Array.from(new Set(['searchindex-' + lang + '.js.gz', 'searchindex-en.js.gz']));
        const cloudFilenames = Array.from(new Set(['searchindex-cloud-' + lang + '.js.gz', 'searchindex-cloud-en.js.gz']));

        const MAIN_REMOTE_SOURCES  = mainFilenames.map(function(filename) { return searchindexBase + '/' + filename; });
        const CLOUD_REMOTE_SOURCES = cloudFilenames.map(function(filename) { return searchindexBase + '/' + filename; });

        const indices = [];
        const main = await loadWithFallback(MAIN_REMOTE_SOURCES , '/searchindex-book.js',        false); if(main)  indices.push(main);
        const cloud= await loadWithFallback(CLOUD_REMOTE_SOURCES, '/searchindex.js',  true ); if(cloud) indices.push(cloud);  
        if(!indices.length){ postMessage({ready:false, error:'no-index'}); return; }
  
        /* build index objects */
        built = indices.map(d => ({
          idx : elasticlunr.Index.load(d.json),
          urls: d.urls,
          cloud: d.cloud,
          base: d.cloud ? 'https://cloud.hacktricks.wiki/' : ''
        }));
  
        postMessage({ready:true});
        return;
      }
      
      const q = data.query || data;
      if(!q){ postMessage([]); return; }
  
          const all = [];
          for(const s of built){
            const res = s.idx.search(q,opts);
            if(!res.length) continue;
            const max = res[0].score || 1;
            res.forEach(r => {
              const doc = s.idx.documentStore.getDoc(r.ref);
              all.push({
                norm : r.score / max,
                title: doc.title,
                body : doc.body,
                breadcrumbs: doc.breadcrumbs,
                url  : s.base + s.urls[r.ref],
                cloud: s.cloud
              });
            });
          }
          all.sort((a,b)=>b.norm-a.norm);
          postMessage(all.slice(0,MAX));
    };
    `;
  
    /* ───────────── 2. spawn worker ───────────── */
    const worker = new Worker(URL.createObjectURL(new Blob([workerCode],{type:'application/javascript'})));
    
    /* ───────────── 2.1. initialize worker with language ───────────── */
    const htmlLang = (document.documentElement.lang || 'en').toLowerCase();
    const lang = htmlLang.split('-')[0];
    worker.postMessage({type: 'init', lang: lang});
  
    /* ───────────── 3. DOM refs ─────────────── */
    const wrap    = document.getElementById('search-wrapper');
    const bar     = document.getElementById('searchbar');
    const list    = document.getElementById('searchresults');
    const listOut = document.getElementById('searchresults-outer');
    const header  = document.getElementById('searchresults-header');
    const icon    = document.getElementById('search-toggle');

    if(!wrap || !bar || !list || !listOut || !header || !icon) {
      console.error('[HT Search] Missing DOM elements:', {wrap:!!wrap, bar:!!bar, list:!!list, listOut:!!listOut, header:!!header, icon:!!icon});
      return;
    }

    /* Clear icon content and use emoji states directly */
    icon.textContent = '⏳';
    icon.setAttribute('aria-label','Loading search …');
    icon.setAttribute('title','Search is loading, please wait...');

    const setIconState = state => {
      if(state === 'ready'){
        icon.textContent = '🔍';
        icon.setAttribute('aria-label','Open search (S)');
        icon.removeAttribute('title');
      } else if(state === 'error'){
        icon.textContent = '❌';
        icon.setAttribute('aria-label','Search unavailable');
        icon.setAttribute('title','Search is unavailable');
      } else {
        icon.textContent = '⏳';
        icon.setAttribute('aria-label','Loading search …');
        icon.setAttribute('title','Search is loading, please wait...');
      }
    };

  
    const HOT=83, ESC=27, DOWN=40, UP=38, ENTER=13;
    let debounce, teaserCount=0;
  
    /* ───────────── helpers (teaser, metric) ───────────── */
    const escapeHTML = (()=>{const M={'&':'&amp;','<':'&lt;','>':'&gt;','"':'&#34;','\'':'&#39;'};return s=>s.replace(/[&<>'"]/g,c=>M[c]);})();
    const URL_MARK='highlight';
    function metric(c,t){return c?`${c} search result${c>1?'s':''} for '${t}':`:`No search results for '${t}'.`;}
  
    function makeTeaser(body,terms){
      const stem=w=>elasticlunr.stemmer(w.toLowerCase());
      const T=terms.map(stem),W_S=40,W_F=8,W_N=2,WIN=30;
      const W=[],sents=body.toLowerCase().split('. ');
      let i=0,v=W_F,found=false;
      sents.forEach(s=>{v=W_F; s.split(' ').forEach(w=>{ if(w){ if(T.some(t=>stem(w).startsWith(t))){v=W_S;found=true;} W.push([w,v,i]); v=W_N;} i+=w.length+1; }); i++;});
      if(!W.length) return body;
      const win=Math.min(W.length,WIN);
      const sums=[W.slice(0,win).reduce((a,[,wt])=>a+wt,0)];
      for(let k=1;k<=W.length-win;k++) sums[k]=sums[k-1]-W[k-1][1]+W[k+win-1][1];
      const best=found?sums.lastIndexOf(Math.max(...sums)):0;
      const out=[]; i=W[best][2];
      for(let k=best;k<best+win;k++){const [w,wt,pos]=W[k]; if(i<pos){out.push(body.substring(i,pos)); i=pos;} if(wt===W_S) out.push('<em>'); out.push(body.substr(pos,w.length)); if(wt===W_S) out.push('</em>'); i=pos+w.length;}
      return out.join('');
    }
  
    function format(d,terms){
      const teaser=makeTeaser(escapeHTML(d.body),terms);
      teaserCount++;
      const enc=encodeURIComponent(terms.join(' ')).replace(/'/g,'%27');
      const parts=d.url.split('#'); if(parts.length===1) parts.push('');
      const abs=d.url.startsWith('http');
      const href=`${abs?'':path_to_root}${parts[0]}?${URL_MARK}=${enc}#${parts[1]}`;
      const style=d.cloud?" style=\"color:#1e88e5\"":"";
      const isCloud=d.cloud?" [Cloud]":" [Book]";
      return `<a href="${href}" aria-details="teaser_${teaserCount}"${style}>`+
             `${d.breadcrumbs}${isCloud}<span class="teaser" id="teaser_${teaserCount}" aria-label="Search Result Teaser">${teaser}</span></a>`;
    }
  
    /* ───────────── UI control ───────────── */
    function showUI(s){wrap.classList.toggle('hidden',!s); icon.setAttribute('aria-expanded',s); if(s){window.scrollTo(0,0); bar.focus(); bar.select();} else {listOut.classList.add('hidden'); [...list.children].forEach(li=>li.classList.remove('focus'));}}
    function blur(){const t=document.createElement('input'); t.style.cssText='position:absolute;opacity:0;'; icon.appendChild(t); t.focus(); t.remove();}
  
    icon.addEventListener('click',()=>showUI(wrap.classList.contains('hidden')));
  
    document.addEventListener('keydown',e=>{
      if(e.altKey||e.ctrlKey||e.metaKey||e.shiftKey) return;
      const f=/^(?:input|select|textarea)$/i.test(e.target.nodeName);
      if(e.keyCode===HOT && !f){e.preventDefault(); showUI(true);} else if(e.keyCode===ESC){e.preventDefault(); showUI(false); blur();}
      else if(e.keyCode===DOWN && document.activeElement===bar){e.preventDefault(); const first=list.firstElementChild; if(first){blur(); first.classList.add('focus');}}
      else if([DOWN,UP,ENTER].includes(e.keyCode) && document.activeElement!==bar){const cur=list.querySelector('li.focus'); if(!cur) return; e.preventDefault(); if(e.keyCode===DOWN){const nxt=cur.nextElementSibling; if(nxt){cur.classList.remove('focus'); nxt.classList.add('focus');}} else if(e.keyCode===UP){const prv=cur.previousElementSibling; cur.classList.remove('focus'); if(prv){prv.classList.add('focus');} else {bar.focus();}} else {const a=cur.querySelector('a'); if(a) window.location.assign(a.href);}}
    });
  
    bar.addEventListener('input',e=>{ clearTimeout(debounce); debounce=setTimeout(()=>worker.postMessage({query: e.target.value.trim()}),120); });
  
    /* ───────────── worker messages ───────────── */
    worker.onmessage = ({data}) => {
      if(data && data.ready!==undefined){
        setIconState(data.ready ? 'ready' : 'error');
        return;
      }
      const docs=data, q=bar.value.trim(), terms=q.split(/\s+/).filter(Boolean);
      header.textContent=metric(docs.length,q);
      clear(list);
      docs.forEach(d=>{const li=document.createElement('li'); li.innerHTML=format(d,terms); list.appendChild(li);});
      listOut.classList.toggle('hidden',!docs.length);
    };
  })();
  