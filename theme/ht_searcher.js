/* ht_searcher.js - dual-index Web Worker search. */
(() => {
  "use strict";

  const clear = el => { while (el.firstChild) el.removeChild(el.firstChild); };
  const workerCode = `
    self.window = self;
    self.search = self.search || {};
    const abs = p => location.origin + p;

    try { importScripts('https://cdn.jsdelivr.net/npm/elasticlunr@0.9.5/elasticlunr.min.js'); }
    catch { importScripts(abs('/elasticlunr.min.js')); }

    const XOR_KEY = 'Prevent_Online_AVs_From_Flagging_HackTricks_Search_Gzip_As_Malicious_394h7gt8rf9u3rf9g';
    const MAX = 30;
    const CACHE_NAME = 'ht-search-indices-v2';
    const CACHE_TTL_MS = 24 * 60 * 60 * 1000;
    const PRIMARY_OPTIONS = {bool:'AND', expand:true};
    const SUPPLEMENTAL_OPTIONS = {bool:'OR', expand:true};

    function xorDecryptInPlace(encryptedData, key){
      const keyBytes = new TextEncoder().encode(key);
      for(let i = 0; i < encryptedData.length; i++) encryptedData[i] ^= keyBytes[i % keyBytes.length];
      return encryptedData.buffer;
    }

    async function decompressGzip(arrayBuffer){
      if(typeof DecompressionStream !== 'undefined'){
        const stream = new Response(arrayBuffer).body.pipeThrough(new DecompressionStream('gzip'));
        return new Response(stream).text();
      }
      if(typeof pako === 'undefined'){
        try { importScripts('https://cdn.jsdelivr.net/npm/pako@2.1.0/dist/pako.min.js'); }
        catch(e){ throw new Error('pako library required for decompression: ' + e); }
      }
      return pako.ungzip(new Uint8Array(arrayBuffer), {to:'string'});
    }

    function takeLegacyIndex(){
      const data = {format:'legacy', json:self.search.index, urls:self.search.doc_urls};
      delete self.search.index;
      delete self.search.doc_urls;
      delete self.search.search_options;
      delete self.search.results_options;
      return data;
    }

    function importLegacyIndex(text){
      const objectUrl = URL.createObjectURL(new Blob([text], {type:'application/javascript'}));
      try { importScripts(objectUrl); }
      finally { URL.revokeObjectURL(objectUrl); }
      return takeLegacyIndex();
    }

    async function fetchSearchAsset(url){
      let cache = null, cached = null;
      const metadataUrl = url + (url.includes('?') ? '&' : '?') + '__ht_cache_timestamp=1';

      if(typeof caches !== 'undefined'){
        try {
          cache = await caches.open(CACHE_NAME);
          const entries = await Promise.all([cache.match(url), cache.match(metadataUrl)]);
          cached = entries[0] || null;
          const cachedAt = entries[1] ? Number(await entries[1].text()) : 0;
          if(cached && cachedAt && Date.now() - cachedAt < CACHE_TTL_MS){
            console.log('Using cached search index:', url);
            return cached;
          }
        } catch(error){ console.warn('search cache read failed ->', error); }
      }

      try {
        const response = await fetch(url, {mode:'cors'});
        if(!response.ok && cached) return cached;
        if(response.ok && cache){
          try {
            await Promise.all([
              cache.put(url, response.clone()),
              cache.put(metadataUrl, new Response(String(Date.now())))
            ]);
          } catch(error){ console.warn('search cache write failed ->', error); }
        }
        return response;
      } catch(error){
        if(cached) return cached;
        throw error;
      }
    }

    async function loadRemote(source){
      const response = await fetchSearchAsset(source.url);
      if(!response.ok) throw new Error('HTTP ' + response.status);
      const encrypted = new Uint8Array(await response.arrayBuffer());
      const text = await decompressGzip(xorDecryptInPlace(encrypted, XOR_KEY));
      if(source.format === 'compact'){
        const data = JSON.parse(text);
        if(data.version !== 1) throw new Error('unsupported compact index version');
        return {format:'compact', data:data, urls:data.doc_urls};
      }
      return importLegacyIndex(text);
    }

    async function loadWithFallback(remotes, local){
      /* Exhaust every GitHub-hosted index before touching the production origin. */
      for(const source of remotes){
        try {
          const data = await loadRemote(source);
          console.log('Loaded search index:', source.url);
          return data;
        } catch(e){ console.warn('search index', source.url, 'failed ->', e); }
      }
      if(!local) return null;
      try {
        importScripts(abs(local));
        console.log('Loaded local fallback:', local);
        return takeLegacyIndex();
      } catch(e){
        console.error('local', local, 'failed ->', e);
        return null;
      }
    }

    function decodeTypedArray(encoded, Type){
      const binary = atob(encoded);
      const bytes = new Uint8Array(binary.length);
      for(let start = 0; start < binary.length; start += 32768){
        const end = Math.min(start + 32768, binary.length);
        for(let i = start; i < end; i++) bytes[i] = binary.charCodeAt(i);
      }
      return new Type(bytes.buffer);
    }

    function lowerBound(values, target){
      let low = 0, high = values.length;
      while(low < high){
        const middle = (low + high) >>> 1;
        if(values[middle] < target) low = middle + 1;
        else high = middle;
      }
      return low;
    }

    function fieldConfiguration(options, name){
      const defaultBool = options.bool || 'OR';
      const defaultExpand = options.expand || false;
      if(!options.fields) return {bool:defaultBool, expand:defaultExpand, boost:1};
      if(!Object.prototype.hasOwnProperty.call(options.fields, name)) return null;
      const configured = options.fields[name];
      return {
        bool:configured.bool || defaultBool,
        expand:configured.expand === undefined ? defaultExpand : configured.expand,
        boost:configured.boost === undefined ? 1 : configured.boost
      };
    }

    function searchCompact(index, query, options){
      const tokens = index.pipeline.run(elasticlunr.tokenizer(query));
      if(!tokens.length) return [];
      const combined = new Map();

      for(const field of index.fields){
        const config = fieldConfiguration(options, field.name);
        if(!config || config.boost === 0) continue;
        let fieldScores = null;
        const exactMatches = new Map();

        for(const token of tokens){
          const tokenScores = new Map();
          const first = lowerBound(field.terms, token);
          let last = first;
          if(config.expand){
            while(last < field.terms.length && field.terms[last].startsWith(token)) last++;
          } else if(first < field.terms.length && field.terms[first] === token){
            last = first + 1;
          }

          for(let termIndex = first; termIndex < last; termIndex++){
            const term = field.terms[termIndex];
            const exact = term === token;
            const begin = field.postingOffsets[termIndex];
            const end = field.postingOffsets[termIndex + 1];
            const idf = 1 + Math.log(index.documentCount / ((end - begin) + 1));
            const penalty = exact ? 1 : .15 * (1 - (term.length - token.length) / term.length);

            for(let posting = begin; posting < end; posting++){
              const ref = field.postingDocs[posting];
              if(fieldScores !== null && config.bool === 'AND' && !fieldScores.has(ref)) continue;
              if(exact) exactMatches.set(ref, (exactMatches.get(ref) || 0) + 1);
              const length = field.fieldLengths[ref];
              const lengthNorm = length ? 1 / Math.sqrt(length) : 1;
              const score = field.postingTermFrequencies[posting] * idf * lengthNorm * penalty;
              tokenScores.set(ref, (tokenScores.get(ref) || 0) + score);
            }
          }

          if(fieldScores === null){
            fieldScores = tokenScores;
          } else if(config.bool === 'AND'){
            const intersection = new Map();
            for(const [ref, score] of tokenScores){
              if(fieldScores.has(ref)) intersection.set(ref, fieldScores.get(ref) + score);
            }
            fieldScores = intersection;
          } else {
            for(const [ref, score] of tokenScores) fieldScores.set(ref, (fieldScores.get(ref) || 0) + score);
          }
        }

        if(!fieldScores) continue;
        for(const [ref, unnormalised] of fieldScores){
          const matches = exactMatches.get(ref);
          const score = (matches ? unnormalised * matches / tokens.length : unnormalised) * config.boost;
          combined.set(ref, (combined.get(ref) || 0) + score);
        }
      }

      return Array.from(combined, entry => ({ref:entry[0], score:entry[1]}))
        .sort((a, b) => (b.score - a.score) || (a.ref - b.ref));
    }

    function buildCompact(data, cloud){
      const documents = data.documents;
      const urls = data.doc_urls;
      const compact = {
        pipeline:elasticlunr.Pipeline.load(data.pipeline),
        documentCount:documents.length,
        fields:data.fields.map(field => {
          const hydrated = {
            name:field.name,
            terms:field.terms,
            postingOffsets:decodeTypedArray(field.posting_offsets, Uint32Array),
            postingDocs:decodeTypedArray(field.posting_docs, Uint32Array),
            postingTermFrequencies:decodeTypedArray(field.posting_term_frequencies, Float64Array),
            fieldLengths:decodeTypedArray(field.field_lengths, Uint32Array)
          };
          delete field.posting_offsets;
          delete field.posting_docs;
          delete field.posting_term_frequencies;
          delete field.field_lengths;
          return hydrated;
        })
      };
      return {
        cloud:cloud,
        base:cloud ? 'https://cloud.hacktricks.wiki/' : '',
        urls:urls,
        search:(query, options) => searchCompact(compact, query, options),
        getDoc:ref => {
          const doc = documents[ref];
          return doc ? {title:doc[0], body:doc[1], breadcrumbs:doc[2]} : null;
        }
      };
    }

    function buildLegacy(data, cloud){
      const index = elasticlunr.Index.load(data.json);
      return {
        cloud:cloud,
        base:cloud ? 'https://cloud.hacktricks.wiki/' : '',
        urls:data.urls,
        search:(query, options) => index.search(query, options),
        getDoc:ref => index.documentStore.getDoc(ref)
      };
    }

    function buildIndex(data, cloud){
      return data.format === 'compact' ? buildCompact(data.data, cloud) : buildLegacy(data, cloud);
    }

    function remoteSources(base, compactName, legacyName, lang){
      const sources = [];
      for(const language of Array.from(new Set([lang, 'en']))){
        sources.push({url:base + '/' + compactName(language), format:'compact'});
        sources.push({url:base + '/' + legacyName(language), format:'legacy'});
      }
      return sources;
    }

    let built = [];

    function topCandidates(query, options, excluded, limit){
      const all = [];
      for(let sourceIndex = 0; sourceIndex < built.length; sourceIndex++){
        const source = built[sourceIndex];
        const results = source.search(query, options);
        if(!results.length) continue;
        const maximum = results[0].score || 1;
        let accepted = 0;
        for(const result of results){
          const key = sourceIndex + ':' + result.ref;
          if(excluded && excluded.has(key)) continue;
          all.push({sourceIndex:sourceIndex, ref:result.ref, norm:result.score / maximum, key:key});
          if(++accepted === MAX) break;
        }
      }
      all.sort((a, b) => b.norm - a.norm);
      return all.slice(0, limit);
    }

    function runSearch(query){
      const selected = topCandidates(query, PRIMARY_OPTIONS, null, MAX);
      if(selected.length < MAX && query.trim().split(/\\s+/).length > 1){
        const excluded = new Set(selected.map(item => item.key));
        selected.push(...topCandidates(query, SUPPLEMENTAL_OPTIONS, excluded, MAX - selected.length));
      }
      return selected.map(item => {
        const source = built[item.sourceIndex];
        const doc = source.getDoc(item.ref);
        return doc && {
          title:doc.title,
          body:doc.body,
          breadcrumbs:doc.breadcrumbs,
          url:source.base + source.urls[item.ref],
          cloud:source.cloud
        };
      }).filter(Boolean);
    }

    self.onmessage = async ({data}) => {
      if(data.type === 'init'){
        try {
          const lang = data.lang || 'en';
          const base = 'https://raw.githubusercontent.com/HackTricks-wiki/hacktricks-searchindex/master';
          const mainSources = remoteSources(base,
            language => 'searchindex-v2-' + language + '.json.gz',
            language => 'searchindex-' + language + '.js.gz', lang);
          const cloudSources = remoteSources(base,
            language => 'searchindex-cloud-v2-' + language + '.json.gz',
            language => 'searchindex-cloud-' + language + '.js.gz', lang);

          const main = await loadWithFallback(mainSources, '/searchindex.js');
          if(main) built.push(buildIndex(main, false));
          const cloud = await loadWithFallback(cloudSources, null);
          if(cloud) built.push(buildIndex(cloud, true));
          if(!built.length){ postMessage({ready:false, error:'no-index'}); return; }
          postMessage({ready:true});
        } catch(error){
          console.error('[HT Search] initialization failed', error);
          postMessage({ready:false, error:String(error)});
        }
        return;
      }

      const query = (data.query || '').trim();
      if(!query){ postMessage({id:data.id, query:query, docs:[]}); return; }
      try { postMessage({id:data.id, query:query, docs:runSearch(query)}); }
      catch(error){
        console.error('[HT Search] query failed', error);
        postMessage({id:data.id, query:query, docs:[], error:String(error)});
      }
    };
  `;

  const wrap = document.getElementById('search-wrapper');
  const bar = document.getElementById('searchbar');
  const list = document.getElementById('searchresults');
  const listOut = document.getElementById('searchresults-outer');
  const header = document.getElementById('searchresults-header');
  const icon = document.getElementById('search-toggle');

  if(!wrap || !bar || !list || !listOut || !header || !icon){
    console.error('[HT Search] Missing DOM elements', {wrap:!!wrap, bar:!!bar, list:!!list, listOut:!!listOut, header:!!header, icon:!!icon});
    return;
  }

  icon.textContent = '🔍';
  icon.setAttribute('aria-label','Open search (S)');
  icon.removeAttribute('title');

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
  let worker=null, workerStarted=false;
  let debounce, teaserCount=0, ready=false, pendingQuery='', requestId=0;
  const escapeHTML = (()=>{const M={'&':'&amp;','<':'&lt;','>':'&gt;','"':'&#34;',"'":'&#39;'};return s=>s.replace(/[&<>'"]/g,c=>M[c]);})();
  const URL_MARK='highlight';
  function metric(c,t){return c?`${c} search result${c>1?'s':''} for '${t}':`:`No search results for '${t}'.`;}

  function makeTeaser(body,terms){
    const stem=w=>elasticlunr.stemmer(w.toLowerCase());
    const T=terms.map(stem),W_S=40,W_F=8,W_N=2,WIN=30;
    const W=[],sents=body.toLowerCase().split('. ');
    let i=0,v=W_F,found=false;
    sents.forEach(s=>{v=W_F; s.split(' ').forEach(w=>{if(w){if(T.some(t=>stem(w).startsWith(t))){v=W_S;found=true;} W.push([w,v,i]);v=W_N;}i+=w.length+1;});i++;});
    if(!W.length) return body;
    const win=Math.min(W.length,WIN);
    const sums=[W.slice(0,win).reduce((a,[,wt])=>a+wt,0)];
    for(let k=1;k<=W.length-win;k++) sums[k]=sums[k-1]-W[k-1][1]+W[k+win-1][1];
    let best=0;
    if(found){let bestScore=sums[0];for(let k=1;k<sums.length;k++){if(sums[k]>=bestScore){bestScore=sums[k];best=k;}}}
    const out=[];i=W[best][2];
    for(let k=best;k<best+win;k++){const [w,wt,pos]=W[k];if(i<pos){out.push(body.substring(i,pos));i=pos;}if(wt===W_S)out.push('<em>');out.push(body.substr(pos,w.length));if(wt===W_S)out.push('</em>');i=pos+w.length;}
    return out.join('');
  }

  function format(d,terms){
    const teaser=makeTeaser(escapeHTML(d.body),terms);
    teaserCount++;
    const enc=encodeURIComponent(terms.join(' ')).replace(/'/g,'%27');
    const parts=d.url.split('#');if(parts.length===1)parts.push('');
    const abs=d.url.startsWith('http');
    const href=`${abs?'':path_to_root}${parts[0]}?${URL_MARK}=${enc}#${parts[1]}`;
    const style=d.cloud?' style="color:#1e88e5"':'';
    const source=d.cloud?' [Cloud]':' [Book]';
    return `<a href="${href}" aria-details="teaser_${teaserCount}"${style}>${d.breadcrumbs}${source}<span class="teaser" id="teaser_${teaserCount}" aria-label="Search Result Teaser">${teaser}</span></a>`;
  }

  function render(docs,query){
    const terms=query.split(/\s+/).filter(Boolean);
    header.textContent=metric(docs.length,query);
    clear(list);
    docs.forEach(d=>{const li=document.createElement('li');li.innerHTML=format(d,terms);list.appendChild(li);});
    listOut.classList.toggle('hidden',!docs.length);
  }

  function sendQuery(query){
    startWorker();
    if(!ready){pendingQuery=query;return;}
    pendingQuery='';
    const id=++requestId;
    worker.postMessage({query:query,id:id});
  }

  function showUI(show){
    if(show)startWorker();
    wrap.classList.toggle('hidden',!show);
    icon.setAttribute('aria-expanded',show);
    if(show){window.scrollTo(0,0);bar.focus();bar.select();}
    else{listOut.classList.add('hidden');[...list.children].forEach(li=>li.classList.remove('focus'));}
  }
  function blur(){const t=document.createElement('input');t.style.cssText='position:absolute;opacity:0;';icon.appendChild(t);t.focus();t.remove();}

  icon.addEventListener('click',()=>showUI(wrap.classList.contains('hidden')));
  document.addEventListener('keydown',e=>{
    if(e.altKey||e.ctrlKey||e.metaKey||e.shiftKey)return;
    const f=/^(?:input|select|textarea)$/i.test(e.target.nodeName);
    if(e.keyCode===HOT&&!f){e.preventDefault();showUI(true);}else if(e.keyCode===ESC){e.preventDefault();showUI(false);blur();}
    else if(e.keyCode===DOWN&&document.activeElement===bar){e.preventDefault();const first=list.firstElementChild;if(first){blur();first.classList.add('focus');}}
    else if([DOWN,UP,ENTER].includes(e.keyCode)&&document.activeElement!==bar){const cur=list.querySelector('li.focus');if(!cur)return;e.preventDefault();if(e.keyCode===DOWN){const nxt=cur.nextElementSibling;if(nxt){cur.classList.remove('focus');nxt.classList.add('focus');}}else if(e.keyCode===UP){const prv=cur.previousElementSibling;cur.classList.remove('focus');if(prv){prv.classList.add('focus');}else{bar.focus();}}else{const a=cur.querySelector('a');if(a)window.location.assign(a.href);}}
  });

  bar.addEventListener('input',e=>{
    clearTimeout(debounce);
    const query=e.target.value.trim();
    if(!query){pendingQuery='';requestId++;render([],query);return;}
    debounce=setTimeout(()=>sendQuery(query),120);
  });

  function handleWorkerMessage({data}){
    if(data&&data.ready!==undefined){
      ready=Boolean(data.ready);
      setIconState(ready?'ready':'error');
      const query=pendingQuery||bar.value.trim();
      if(ready&&query)sendQuery(query);
      return;
    }
    if(!data||data.id!==requestId||data.query!==bar.value.trim())return;
    render(data.docs||[],data.query||'');
  }

  function startWorker(){
    if(workerStarted)return;
    workerStarted=true;
    setIconState('loading');
    const workerUrl=URL.createObjectURL(new Blob([workerCode],{type:'application/javascript'}));
    worker=new Worker(workerUrl);
    URL.revokeObjectURL(workerUrl);
    worker.onmessage=handleWorkerMessage;
    worker.onerror=error=>{console.error('[HT Search] worker failed',error);ready=false;setIconState('error');};
    const htmlLang=(document.documentElement.lang||'en').toLowerCase();
    worker.postMessage({type:'init',lang:htmlLang.split('-')[0]});
  }
})();
