/* search-worker.js ------------------------------------------------------- */
/* Make code written for window work in a worker: */
self.window = self;

////////////////////////////////////////////////////////////////////////////
// 1. elasticlunr.min.js : CDN first  →  local fallback
////////////////////////////////////////////////////////////////////////////
try {
  importScripts('https://cdn.jsdelivr.net/npm/elasticlunr@0.9.5/elasticlunr.min.js');
} catch (e) {
  importScripts('/elasticlunr.min.js');           // ship this with your site
}

////////////////////////////////////////////////////////////////////////////
// 2. searchindex.js : GitHub Raw first  →  local fallback
//    We fetch → wrap in a Blob({type:'application/javascript'}) to bypass
//    GitHub’s  text/plain + nosniff  MIME blocking.
////////////////////////////////////////////////////////////////////////////
try {
  const res  = await fetch(
    'https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/refs/heads/master/searchindex.js',
    {mode: 'cors'}
  );
  if (!res.ok) throw new Error(res.status);
  const blobUrl = URL.createObjectURL(
    new Blob([await res.text()], { type:'application/javascript' })
  );
  importScripts(blobUrl);                         // correct MIME, runs once
} catch (e) {
  importScripts('/searchindex.js');               // offline fallback
}

////////////////////////////////////////////////////////////////////////////
// 3. Build the index once and answer queries
////////////////////////////////////////////////////////////////////////////
const idx = elasticlunr.Index.load(self.search.index);

self.onmessage = ({data: q}) => {
  postMessage(idx.search(q, { bool:'AND', expand:true }));
};

