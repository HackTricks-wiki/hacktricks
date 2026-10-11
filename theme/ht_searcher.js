/* ht_searcher.js - dual-index Web Worker search. */
(() => {
  "use strict";

  const clear = el => { while (el.firstChild) el.removeChild(el.firstChild); };
  const workerCode = String.raw`
    self.window = self;
    self.search = self.search || {};
    const abs = p => location.origin + p;

    try { importScripts('https://cdn.jsdelivr.net/npm/elasticlunr@0.9.5/elasticlunr.min.js'); }
    catch { importScripts(abs('/elasticlunr.min.js')); }

    const XOR_KEY = 'Prevent_Online_AVs_From_Flagging_HackTricks_Search_Gzip_As_Malicious_394h7gt8rf9u3rf9g';
    const MAX = 30;
    const CACHE_NAME = 'ht-search-indices-v2';
    const CACHE_TTL_MS = 24 * 60 * 60 * 1000;

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

    function isPrivateHost(hostname){
      const host = (hostname || '').toLowerCase().replace(/^\[|\]$/g, '');
      if(host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') ||
         host === 'host.docker.internal' || host.endsWith('.internal')) return true;
      if(host.includes(':')){
        if(host === '::1') return true;
        if(host.startsWith('::ffff:')) return isPrivateHost(host.slice(7));
        const first = parseInt(host.split(':')[0] || '0', 16);
        return (first & 0xfe00) === 0xfc00 || (first & 0xffc0) === 0xfe80;
      }
      const octets = host.split('.').map(Number);
      if(octets.length !== 4 || octets.some(value => !Number.isInteger(value) || value < 0 || value > 255)) return false;
      return octets[0] === 0 || octets[0] === 10 || octets[0] === 127 ||
        (octets[0] === 100 && octets[1] >= 64 && octets[1] <= 127) ||
        (octets[0] === 169 && octets[1] === 254) ||
        (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) ||
        (octets[0] === 192 && octets[1] === 168);
    }

    function localCandidates(local, lang){
      if(!local) return [];
      const safeLang = /^[a-z]{2,3}$/.test(lang) ? lang : 'en';
      return safeLang === 'en' ? [local] : ['/' + safeLang + local, local];
    }

    function loadLocal(locals){
      for(const local of locals){
        try {
          importScripts(abs(local));
          console.log('Loaded private-network search index:', local);
          return takeLegacyIndex();
        } catch(e){ console.warn('local', local, 'failed ->', e); }
      }
      return null;
    }

    async function loadWithPolicy(remotes, locals, privateHost){
      /* Private deployments stay self-contained; public deployments never use costly origin indexes. */
      if(privateHost) return loadLocal(locals);
      for(const source of remotes){
        try {
          const data = await loadRemote(source);
          console.log('Loaded search index:', source.url);
          return data;
        } catch(e){ console.warn('search index', source.url, 'failed ->', e); }
      }
      return null;
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

    function buildCompact(data, cloud){
      const documents = data.documents;
      const field = data.fields.find(field => field.name === 'body');
      const offsets = decodeTypedArray(field.posting_offsets, Uint32Array);
      const refs = decodeTypedArray(field.posting_docs, Uint32Array);
      const frequencies = decodeTypedArray(field.posting_term_frequencies, Float64Array);
      const lengths = decodeTypedArray(field.field_lengths, Uint32Array);
      const body = {
        terms:field.terms,
        documentFrequency:term => offsets[term + 1] - offsets[term],
        visit:(term, callback) => {
          for(let i = offsets[term]; i < offsets[term + 1]; i++) callback(refs[i], frequencies[i], lengths[refs[i]]);
        }
      };
      return prepareIndex({
        cloud:cloud,
        base:cloud ? 'https://cloud.hacktricks.wiki/' : '',
        urls:data.doc_urls,
        getDoc:ref => {
          const doc = documents[ref];
          return doc ? {title:doc[0], body:doc[1], breadcrumbs:doc[2]} : null;
        }
      }, body);
    }

    function buildLegacy(data, cloud){
      const index = data.json;
      const entries = [], stack = [['', index.index.body.root]];
      while(stack.length){
        const [term, node] = stack.pop();
        if(node.df > 0) entries.push([term, node.docs]);
        for(const key of Object.keys(node)){
          if(key !== 'df' && key !== 'docs') stack.push([term + key, node[key]]);
        }
      }
      entries.sort((a, b) => a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0);
      const body = {
        terms:entries.map(entry => entry[0]),
        documentFrequency:term => Object.keys(entries[term][1]).length,
        visit:(term, callback) => {
          for(const [ref, posting] of Object.entries(entries[term][1])){
            callback(Number(ref), posting.tf, index.documentStore.docInfo[ref].body || 0);
          }
        }
      };
      return prepareIndex({
        cloud:cloud,
        base:cloud ? 'https://cloud.hacktricks.wiki/' : '',
        urls:data.urls,
        getDoc:ref => index.documentStore.docs[ref]
      }, body);
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

    // Keep technical punctuation and Unicode letters; metadata also exposes camel-case parts.
    const fold = text => String(text || '').normalize('NFKD').replace(/\p{M}/gu, '').toLowerCase();
    const words = text => fold(text).match(/[\p{L}\p{N}]+(?:\+\+|#)?/gu) || [];
    const stem = token => /^[a-z]+$/.test(token) ? elasticlunr.stemmer(token) : token;
    const STOP_WORDS = new Set(('a an and are as at be by for from how i in is it of on or the to was what where with ' +
      'can could do does find me please show this about').split(' '));
    const ALIASES = Object.assign(Object.create(null), {
      privesc:['privilege escalation'], privs:['privileges'],
      sqli:['sql injection'], xss:['cross site scripting'],
      ssrf:['server side request forgery'], rce:['remote code execution'],
      lfi:['local file inclusion'], rfi:['remote file inclusion'],
      ssti:['server side template injection'], idor:['insecure direct object reference'],
      ad:['active directory'], k8s:['kubernetes'],
      'privilege escalation':['privesc'], 'sql injection':['sqli'],
      'cross site scripting':['xss'], 'server side request forgery':['ssrf'],
      'remote code execution':['rce'], 'active directory':['ad'], kubernetes:['k8s']
    });
    const TOKEN_ALIASES = new Map(Object.entries(ALIASES).filter(([token]) => !token.includes(' '))
      .map(([token, phrases]) => [token, phrases.flatMap(words)]));
    const TITLE_NOISE = new Set('basic basics information pentesting pentest overview introduction'.split(' '));

    function queryGroups(query, keepStopWords = false){
      const tokens = words(query.slice(0, 512)).filter(token => keepStopWords || !STOP_WORDS.has(token));
      const groups = [], seen = new Set();
      for(let i = 0; i < tokens.length && groups.length < 24; i++){
        let phrase = tokens[i];
        // Recognize full names before individual words so acronym-only pages remain searchable.
        for(let size = Math.min(5, tokens.length - i); size > 1; size--){
          const candidate = tokens.slice(i, i + size).join(' ');
          if(ALIASES[candidate]){ phrase = candidate; i += size - 1; break; }
        }
        const alternatives = [phrase, ...(ALIASES[phrase] || [])].map(words);
        const numbered = phrase.match(/^([a-z]{3,})(\d+)$/);
        if(numbered) alternatives.push([numbered[1], numbered[2]]);
        const canonical = alternatives.reduce((a, b) => a.join(' ').length >= b.join(' ').length ? a : b);
        const key = canonical.map(stem).join(' ');
        if(seen.has(key)) continue;
        seen.add(key);
        groups.push({tokens:words(phrase), alternatives:alternatives, canonical:canonical});
      }
      return groups;
    }

    function addLookup(lookup, token, value){
      if(!lookup.has(token)) lookup.set(token, []);
      lookup.get(token).push(value);
    }

    function prepareIndex(source, bodyField){
      const lookup = new Map();
      // Reuse existing body postings instead of tokenizing every large document on each query.
      for(let i = 0; i < bodyField.terms.length; i++){
        for(const token of new Set(words(bodyField.terms[i]))){
          addLookup(lookup, token, {field:bodyField, term:i});
        }
      }
      const metadata = new Map();
      source.metadata = [];
      source.pages = new Map();
      for(let ref = 0; ref < source.urls.length; ref++){
        const doc = source.getDoc(ref);
        if(!doc) continue;
        const title = words(doc.title).join(' ');
        const breadcrumbs = words(doc.breadcrumbs).join(' ');
        const crumbs = String(doc.breadcrumbs || '').split('»');
        const parent = crumbs.length > 1 ? words(crumbs[crumbs.length - 2]).join(' ') : breadcrumbs;
        const topic = String(doc.title || '').split(/\s+\/\s+|\(|\|/)[0];
        source.metadata[ref] = {title:title, breadcrumbs:breadcrumbs, primary:parent === title,
          topic:queryGroups(topic, true).flatMap(group => group.canonical).filter(token => !TITLE_NOISE.has(token))};
        let path = source.urls[ref] || '';
        const page = path.split('#')[0];
        if(!source.pages.has(page)) source.pages.set(page, []);
        source.pages.get(page).push(ref);
        try { path = decodeURIComponent(path); } catch {}
        for(const [text, weight] of [[doc.title, 12], [doc.breadcrumbs, 4], [path, 2]]){
          const separated = String(text || '').replace(/([a-z])([A-Z])/g, '$1 $2')
            .replace(/([A-Z])([A-Z][a-z])/g, '$1 $2');
          for(const [value, tokenWeight] of [[text, weight], [separated, weight * .75]]){
            const tokens = new Set(words(value).flatMap(token => [token, stem(token)]));
            for(const token of tokens){
              if(!metadata.has(token)) metadata.set(token, new Map());
              const refs = metadata.get(token);
              refs.set(ref, Math.max(refs.get(ref) || 0, tokenWeight));
            }
            for(const token of words(value)){
              const numbered = token.match(/^([a-z]{3,})(\d+)$/);
              const alternatives = [...(TOKEN_ALIASES.get(token) || []), ...(numbered ? numbered.slice(1) : [])];
              for(const related of new Set(alternatives.flatMap(token => [token, stem(token)]))){
                if(!metadata.has(related)) metadata.set(related, new Map());
                const refs = metadata.get(related);
                refs.set(ref, Math.max(refs.get(ref) || 0, tokenWeight * .85));
              }
            }
          }
        }
      }
      for(const [token, refs] of metadata) addLookup(lookup, token, {refs:refs});
      source.lookup = lookup;
      source.vocabulary = Array.from(lookup.keys()).sort();
      source.termCache = new Map();
      source.literalCache = new Map();
      return source;
    }

    // Bounded Damerau-Levenshtein distance includes adjacent swapped letters.
    function editDistance(a, b, limit){
      if(Math.abs(a.length - b.length) > limit) return limit + 1;
      let previousPrevious = null;
      let previous = Array.from({length:b.length + 1}, (_, i) => i);
      for(let i = 1; i <= a.length; i++){
        const row = [i];
        let minimum = i;
        for(let j = 1; j <= b.length; j++){
          row[j] = Math.min(row[j - 1] + 1, previous[j] + 1, previous[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
          if(previousPrevious && i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]){
            row[j] = Math.min(row[j], previousPrevious[j - 2] + 1);
          }
          minimum = Math.min(minimum, row[j]);
        }
        if(minimum > limit) return limit + 1;
        previousPrevious = previous;
        previous = row;
      }
      return previous[b.length];
    }

    function termMatches(source, token){
      if(source.termCache.has(token)) return source.termCache.get(token);
      const matches = new Map(), root = stem(token);
      if(source.lookup.has(token)) matches.set(token, 1);
      if(root !== token && source.lookup.has(root)) matches.set(root, .98);
      // Short acronyms and numbers require exact matches to avoid huge, irrelevant expansions.
      if(token.length >= 3 && !/\d|[+#]/.test(token)){
        let start = lowerBound(source.vocabulary, token), count = 0;
        while(start < source.vocabulary.length && source.vocabulary[start].startsWith(token) && count < 48){
          const candidate = source.vocabulary[start++];
          if(candidate !== token){ matches.set(candidate, .78 + .12 * token.length / candidate.length); count++; }
        }
      }
      if((token.length >= 4 || (token.length === 3 && !matches.size)) && token.length <= 40 &&
         !/\d|[+#]/.test(token) && !ALIASES[token]){
        const limit = token.length >= 8 ? 2 : 1;
        const candidates = [];
        for(const candidate of source.vocabulary){
          if(matches.has(candidate) || Math.abs(candidate.length - root.length) > limit || /\d|[+#]/.test(candidate)) continue;
          // A different first letter already costs an edit unless it was transposed.
          if(candidate[0] !== root[0] && candidate[1] !== root[0] && candidate[0] !== root[1]) continue;
          const distance = editDistance(root, candidate, limit);
          if(distance <= limit) candidates.push({token:candidate, distance:distance});
        }
        candidates.sort((a, b) => a.distance - b.distance || a.token.localeCompare(b.token));
        for(const candidate of candidates.slice(0, 12)) matches.set(candidate.token, candidate.distance === 1 ? .65 : .48);
      }
      if(source.termCache.size >= 128) source.termCache.delete(source.termCache.keys().next().value);
      source.termCache.set(token, matches);
      return matches;
    }

    function tokenScores(source, token){
      const scores = new Map();
      const record = (ref, score, quality, title, term) => {
        const current = scores.get(ref);
        if(!current) scores.set(ref, {score:score, quality:quality, title:title, terms:new Set([term])});
        else {
          current.score = Math.max(current.score, score);
          current.quality = Math.max(current.quality, quality);
          current.title = Math.max(current.title, title);
          if(current.terms.size < 48) current.terms.add(term);
        }
      };
      for(const [term, quality] of termMatches(source, token)){
        for(const entry of source.lookup.get(term)){
          if(entry.refs){
            for(const [ref, weight] of entry.refs) record(ref, weight * quality, quality, weight >= 9 ? quality * weight / 12 : 0, term);
          } else {
            const field = entry.field;
            const frequency = field.documentFrequency(entry.term);
            const idf = Math.min(4, 1 + Math.log(1 + source.urls.length / (frequency + 1)));
            field.visit(entry.term, (ref, tf, length) => {
              const score = quality * idf * (1 + Math.min(1, Math.log1p(tf))) / (1 + .2 * Math.log1p(length));
              record(ref, score, quality, 0, term);
            });
          }
        }
      }
      // The legacy English trimmer reduces both C++ and C# to "c". Verify these symbols
      // against stored text instead of treating different language names as interchangeable.
      if(/[+#]/.test(token)){
        if(!source.literalCache.has(token)){
          const escaped = token.replace(/[.*+?^{}$()|[\]\\]/g, '\\$&');
          const pattern = new RegExp('(^|[^\\p{L}\\p{N}])' + escaped + '(?=$|[^\\p{L}\\p{N}+#])', 'iu');
          const refs = [];
          for(let ref = 0; ref < source.urls.length; ref++){
            if(pattern.test(source.getDoc(ref).body || '')) refs.push(ref);
          }
          if(source.literalCache.size >= 16) source.literalCache.delete(source.literalCache.keys().next().value);
          source.literalCache.set(token, refs);
        }
        for(const ref of source.literalCache.get(token)) record(ref, 2, 1, 0, token);
      }
      return scores;
    }

    function sourceCandidates(source, sourceIndex, groups){
      const candidates = new Map(), tokens = new Map();
      const getScores = token => {
        if(!tokens.has(token)) tokens.set(token, tokenScores(source, token));
        return tokens.get(token);
      };
      const required = groups.filter(group => group.tokens.some(token => /\d|[+#]/.test(token))).length;
      for(const group of groups){
        const groupScores = new Map();
        group.alternatives.forEach((alternative, alternativeIndex) => {
          const parts = alternative.map(getScores);
          if(!parts.length) return;
          const smallest = parts.reduce((a, b) => a.size < b.size ? a : b);
          for(const ref of smallest.keys()){
            if(!parts.every(part => part.has(ref))) continue;
            const hits = parts.map(part => part.get(ref));
            const penalty = alternativeIndex ? .85 : 1;
            const hit = {
              score:hits.reduce((sum, value) => sum + value.score, 0) / parts.length * penalty,
              quality:Math.min(...hits.map(value => value.quality)) * penalty,
              title:Math.min(...hits.map(value => value.title)) * penalty,
              terms:hits.flatMap(value => Array.from(value.terms))
            };
            if(!groupScores.has(ref) || hit.score > groupScores.get(ref).score) groupScores.set(ref, hit);
          }
        });
        for(const [ref, hit] of groupScores){
          if(!candidates.has(ref)) candidates.set(ref, {sourceIndex:sourceIndex, ref:ref, coverage:0, required:0, score:0, title:0, terms:new Set()});
          const candidate = candidates.get(ref);
          candidate.coverage++;
          if(group.tokens.some(token => /\d|[+#]/.test(token))) candidate.required++;
          candidate.score += hit.score;
          candidate.title += hit.title;
          for(const term of hit.terms) if(candidate.terms.size < 48) candidate.terms.add(term);
        }
      }
      const phrase = groups.flatMap(group => group.tokens).join(' ');
      const canonical = groups.flatMap(group => group.canonical).map(stem).join(' ');
      const equivalentTitles = new Set([phrase]);
      if(groups.length === 1){
        for(const alternative of groups[0].alternatives){
          const expanded = alternative.join(' ');
          equivalentTitles.add(expanded);
          equivalentTitles.add(phrase + ' ' + expanded);
          equivalentTitles.add(expanded + ' ' + phrase);
        }
      }
      const selected = [];
      for(const candidate of candidates.values()){
        if(candidate.coverage < Math.ceil(groups.length * .6) || candidate.required < required) continue;
        const metadata = source.metadata[candidate.ref];
        if(equivalentTitles.has(metadata.title)) candidate.score += 80;
        else if((' ' + metadata.title + ' ').includes(' ' + phrase + ' ')) candidate.score += 40;
        if((' ' + metadata.breadcrumbs + ' ').includes(' ' + phrase + ' ')) candidate.score += 10;
        candidate.score += 20 * candidate.title / groups.length;
        candidate.score += 20 * candidate.title / Math.max(1, metadata.topic.length);
        // mdBook stores subsections separately: prefer the page introducing a topic over an aside.
        if(metadata.primary && candidate.title >= groups.length * .8) candidate.score += 50;
        if(metadata.primary && candidate.title >= groups.length * .8 && /(?:^|\/)index\.html(?:#|$)/.test(source.urls[candidate.ref])) candidate.score += 8;
        const topic = metadata.topic.filter(token => /\d/.test(canonical) || !/^\d+$/.test(token)).map(stem).join(' ');
        if(metadata.primary && topic === canonical) candidate.score += 60;
        selected.push(candidate);
      }
      return selected;
    }

    function runSearch(query){
      const groups = queryGroups(query);
      if(!groups.length) return [];
      const candidates = built.flatMap((source, index) => sourceCandidates(source, index, groups));
      const compare = (a, b) => b.coverage - a.coverage || b.score - a.score || a.sourceIndex - b.sourceIndex || a.ref - b.ref;
      candidates.sort(compare);
      // Only inspect a bounded shortlist for phrase proximity in body text.
      for(const candidate of candidates.slice(0, 200)){
        const phrase = groups.flatMap(group => group.tokens).join(' ');
        if(phrase.includes(' ') && (' ' + words(previewBody(built[candidate.sourceIndex], candidate.ref)).join(' ') + ' ').includes(' ' + phrase + ' ')) candidate.score += 8;
      }
      candidates.sort(compare);
      const selected = [], seen = new Set(), pages = new Map();
      // Exhaust the complete-match tier before considering relaxed results.
      for(let coverage = groups.length; coverage >= Math.ceil(groups.length * .6); coverage--){
        const deferred = [];
        for(const candidate of candidates){
          if(candidate.coverage !== coverage) continue;
          const source = built[candidate.sourceIndex];
          const url = source.base + source.urls[candidate.ref];
          if(seen.has(url)) continue;
          seen.add(url);
          const page = url.split('#')[0], count = pages.get(page) || 0;
          if(count >= 2){ deferred.push(candidate); continue; }
          selected.push(candidate);
          pages.set(page, count + 1);
          if(selected.length === MAX) break;
        }
        selected.push(...deferred.slice(0, MAX - selected.length));
        if(selected.length === MAX) break;
      }
      return selected.slice(0, MAX).map(candidate => {
        const source = built[candidate.sourceIndex], doc = source.getDoc(candidate.ref);
        return {title:doc.title, body:previewBody(source, candidate.ref), breadcrumbs:doc.breadcrumbs,
          url:source.base + source.urls[candidate.ref], cloud:source.cloud, terms:Array.from(candidate.terms)};
      });
    }

    function cleanBody(body){
      return String(body || '').replace(/(?:Tip )?Learn & practice AWS Hacking: HackTricks Training[\s\S]*?Share hacking tricks by submitting PRs to the HackTricks and HackTricks Cloud github repos\.\s*/g, '').trim();
    }

    function previewBody(source, ref){
      const body = cleanBody(source.getDoc(ref).body);
      if(body.length >= 40 || !source.metadata[ref].primary) return body;
      const page = source.urls[ref].split('#')[0];
      for(const sibling of source.pages.get(page) || []){
        if(sibling <= ref) continue;
        const doc = source.getDoc(sibling), preview = cleanBody(doc.body);
        if(preview.length >= 40 && !/^references?$/i.test(doc.title)) return preview;
      }
      return body;
    }

    self.onmessage = async ({data}) => {
      if(data.type === 'init'){
        try {
          const lang = data.lang || 'en';
          const privateHost = isPrivateHost(data.hostname);
          const base = 'https://raw.githubusercontent.com/HackTricks-wiki/hacktricks-searchindex/master';
          const mainSources = remoteSources(base,
            language => 'searchindex-v2-' + language + '.json.gz',
            language => 'searchindex-' + language + '.js.gz', lang);
          const cloudSources = remoteSources(base,
            language => 'searchindex-cloud-v2-' + language + '.json.gz',
            language => 'searchindex-cloud-' + language + '.js.gz', lang);

          const main = await loadWithPolicy(mainSources, localCandidates('/searchindex.js', lang), privateHost);
          if(main) built.push(buildIndex(main, false));
          const cloud = await loadWithPolicy(cloudSources, localCandidates(null, lang), privateHost);
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

  function makeTeaser(body, terms){
    const fold = text => text.normalize('NFKD').replace(/\p{M}/gu, '').toLowerCase();
    const normalize = token => /^[a-z]+$/.test(token) ? elasticlunr.stemmer(token) : token;
    const wanted = new Set(terms.flatMap(term => [fold(term), normalize(fold(term))]));
    const tokens = Array.from(String(body || '').matchAll(/\S+/gu), match => {
      const parts = fold(match[0]).match(/[\p{L}\p{N}]+(?:\+\+|#)?/gu) || [];
      const hit = parts.some(part => wanted.has(part) || wanted.has(normalize(part)));
      return {text:match[0], start:match.index, end:match.index + match[0].length, hit:hit};
    });
    if(!tokens.length) return '';
    const size = Math.min(30, tokens.length);
    let best = 0, score = 0, maximum = -1;
    for(let i = 0; i < tokens.length; i++){
      score += tokens[i].hit ? 1 : 0;
      if(i >= size) score -= tokens[i - size].hit ? 1 : 0;
      if(i >= size - 1 && score > maximum){ maximum = score; best = i - size + 1; }
    }
    const selected = tokens.slice(best, best + size);
    let out = best ? '… ' : '', position = selected[0].start;
    for(const token of selected){
      out += escapeHTML(body.slice(position, token.start));
      const text = escapeHTML(token.text);
      out += token.hit ? '<em>' + text + '</em>' : text;
      position = token.end;
    }
    return out + (best + size < tokens.length ? ' …' : '');
  }

  function format(d,terms){
    const teaser=makeTeaser(d.body || '', d.terms || terms);
    teaserCount++;
    const enc=encodeURIComponent(terms.join(' ')).replace(/'/g,'%27');
    const parts=d.url.split('#');if(parts.length===1)parts.push('');
    const abs=d.url.startsWith('http');
    const href=`${abs?'':path_to_root}${parts[0]}?${URL_MARK}=${enc}#${parts[1]}`;
    const style=d.cloud?' style="color:#1e88e5"':'';
    const source=d.cloud?' [Cloud]':' [Book]';
    return `<a href="${escapeHTML(href)}" aria-details="teaser_${teaserCount}"${style}>${escapeHTML(d.breadcrumbs || d.title || '')}${source}<span class="teaser" id="teaser_${teaserCount}" aria-label="Search Result Teaser">${teaser}</span></a>`;
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
    worker.postMessage({type:'init',lang:htmlLang.split('-')[0],hostname:window.location.hostname});
  }
})();
