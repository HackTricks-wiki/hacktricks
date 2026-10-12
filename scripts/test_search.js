// Run: node --test scripts/test_search.js
// Full generated book indexes: HT_SEARCH_CORPUS=1 node --test scripts/test_search.js
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {test} = require('node:test');
const {performance} = require('node:perf_hooks');
const {gzipSync} = require('node:zlib');
const elasticlunr = require('../theme/elasticlunr.min.js');

const root = path.resolve(__dirname, '..');
const sourceText = fs.readFileSync(path.join(root, 'theme/ht_searcher.js'), 'utf8');
const quietConsole = {log(){}, warn(){}, error(){}};

function worker(text = sourceText, overrides = {}){
  const outer = {};
  vm.runInNewContext(text.slice(0, text.indexOf('  const wrap =')) + 'globalThis.code = workerCode;})();', outer);
  const context = {
    console:quietConsole, elasticlunr, importScripts(){},
    location:{origin:'http://localhost'}, TextEncoder, TextDecoder,
    URL, Blob, Response, DecompressionStream, atob, ...overrides
  };
  context.self = context;
  vm.createContext(context);
  vm.runInContext(outer.code, context);
  return context;
}

function legacy(documents){
  const index = elasticlunr(function(){
    this.setRef('id');
    this.addField('title'); this.addField('body'); this.addField('breadcrumbs');
  });
  documents.forEach((doc, id) => index.addDoc({id:String(id), breadcrumbs:doc.title, body:'', ...doc}));
  return {format:'legacy', json:index.toJSON(), urls:documents.map((doc, i) => doc.url || `page-${i}.html#section`)};
}

function compact(legacyData){
  const index = legacyData.json;
  const encode = (values, Type) => Buffer.from(new Type(values).buffer).toString('base64');
  return {format:'compact', data:{
    version:1, pipeline:index.pipeline, doc_urls:legacyData.urls,
    documents:legacyData.urls.map((_, ref) => {
      const doc = index.documentStore.docs[ref];
      return [doc.title, doc.body, doc.breadcrumbs];
    }),
    fields:index.fields.map(name => {
      const entries = [], stack = [['', index.index[name].root]];
      while(stack.length){
        const [term, node] = stack.pop();
        if(node.df) entries.push([term, node.docs]);
        for(const key of Object.keys(node)) if(key !== 'docs' && key !== 'df') stack.push([term + key, node[key]]);
      }
      entries.sort((a, b) => a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0);
      const offsets = [0], refs = [], frequencies = [];
      entries.forEach(([, postings]) => {
        for(const [ref, posting] of Object.entries(postings)){ refs.push(Number(ref)); frequencies.push(posting.tf); }
        offsets.push(refs.length);
      });
      return {name, terms:entries.map(entry => entry[0]),
        posting_offsets:encode(offsets, Uint32Array), posting_docs:encode(refs, Uint32Array),
        posting_term_frequencies:encode(frequencies, Float64Array),
        field_lengths:encode(legacyData.urls.map((_, ref) => index.documentStore.docInfo[ref][name] || 0), Uint32Array)};
    })
  }};
}

function install(context, sources){
  context.fixtures = sources;
  vm.runInContext('built = fixtures.map((fixture, i) => buildIndex(fixture, i === 1))', context);
  return query => {
    context.query = query;
    return JSON.parse(JSON.stringify(vm.runInContext('runSearch(query)', context)));
  };
}

const documents = [
  {title:'SQL Injection', body:'Database queries and parameter binding.', url:'sql-injection.html#sql-injection'},
  {title:'Unrelated notes', body:'SQL injection '.repeat(100)},
  {title:'Cross Site Scripting', body:'Browser output encoding.'},
  {title:'Server Side Request Forgery', body:'Outbound requests and URL validation.'},
  {title:'Linux Privilege Escalation', body:'Local permissions and capabilities.'},
  {title:'Kubernetes', body:'Cluster workloads and service accounts.'},
  {title:'SeImpersonatePrivilege', body:'Windows token privileges.'},
  {title:'AWS IAM', body:'Permission boundaries and iam:PassRole.', url:'aws/iam.html#overview'},
  {title:'PassRole', breadcrumbs:'AWS » IAM » PassRole', body:'Delegating roles.'},
  {title:'CVE-2024-1234', body:'Patch information for the specific advisory.'},
  {title:'CVE-2025-1234', body:'Different year and advisory.'},
  {title:'S3', body:'Object storage bucket configuration.'},
  {title:'S30', body:'Unrelated product.'},
  {title:'C++', body:'Compiler and language configuration.'},
  {title:'C#', body:'Managed runtime configuration.'},
  {title:'Résumé sécurité', body:'Énumération réseau.'},
  {title:'Redis', body:'Cache configuration.'},
  {title:'PHP object injection', body:'Serialized objects.'},
  {title:'Encoding', body:'base64_decode and /etc/passwd identifiers.'},
  {title:'Template rendering', body:'Jinja2 escaping and sandbox options.'},
  {title:'TLS 1.3', body:'Protocol settings.', url:'network/tls.html#tls-13'},
  {title:'OAuth 2.0', body:'Authorization protocol.'},
  {title:'日本語検索', body:'設定と認証の説明。'},
  {title:'Active Directory', body:'Directory services.'},
  {title:'HTTP request smuggling', body:'HTTP parser differences.'},
  {title:'Deserialization', body:'Serialization formats.'},
  {title:'OpenSearch', body:'Search service configuration.'},
  {title:'Remote Code Execution', body:'Code execution risk.'},
  {title:'JWT', body:'JSON web tokens.'},
  {title:'Unique heading', body:'needleword is only in body text.'},
  {title:'Needleword sidebar', body:'A generic sidebar.'},
  {title:'Constructor', body:'Object construction and prototypes.'}
];
const cloudDocuments = [
  {title:'SQL Logging', body:'SQL queries and database telemetry.'},
  {title:'AWS Lambda', body:'Serverless function configuration.'},
  {title:'Azure Managed Identity', body:'Identity configuration.'},
  {title:'Google Cloud Storage', body:'Storage buckets.'},
  {title:'AWS S3', body:'Object storage.'},
  {title:'AWS IAM PassRole', body:'Role delegation and boundaries.'}
];

const cases = [
  ['SQL Injection', 'SQL Injection'], ['sql injection', 'SQL Injection'],
  ['SQL INJECTION', 'SQL Injection'], ['  sql   injection  ', 'SQL Injection'],
  ['sql\tinjection\n', 'SQL Injection'], ['sql-injection', 'SQL Injection'],
  ['sql_injection', 'SQL Injection'], ['"SQL Injection"', 'SQL Injection'],
  ['sql/injection', 'SQL Injection'], ['SQLi', 'SQL Injection'],
  ['sql inject', 'SQL Injection'], ['sqli injection', 'SQL Injection'],
  ['sql injecton', 'SQL Injection'], ['sql inejection', 'SQL Injection'],
  ['sql ijnection', 'SQL Injection'], ['sqq injection', 'SQL Injection'],
  ['how do I find SQL injection', 'SQL Injection'], ['show me SQL injection please', 'SQL Injection'],
  ['injection sql', 'SQL Injection'], ['sql sql injection injection', 'SQL Injection'],
  ['ＱＺＬ', null], ['ＳＱＬ Ｉｎｊｅｃｔｉｏｎ', 'SQL Injection'],
  ['XSS', 'Cross Site Scripting'], ['cross-site scripting', 'Cross Site Scripting'],
  ['SSRF', 'Server Side Request Forgery'], ['server-side request forgery', 'Server Side Request Forgery'],
  ['privesc linux', 'Linux Privilege Escalation'], ['privilege escalation linux', 'Linux Privilege Escalation'],
  ['linux privilege escaltion', 'Linux Privilege Escalation'], ['linux privesc', 'Linux Privilege Escalation'],
  ['k8s', 'Kubernetes'], ['kubernets', 'Kubernetes'], ['kuberntees', 'Kubernetes'],
  ['kubernetes', 'Kubernetes'], ['kuber', 'Kubernetes'],
  ['SeImpersonatePrivilege', 'SeImpersonatePrivilege'], ['se impersonate privilege', 'SeImpersonatePrivilege'],
  ['seimpersonateprivileg', 'SeImpersonatePrivilege'],
  ['iam:PassRole', 'AWS IAM PassRole'], ['aws passrole', 'AWS IAM PassRole'],
  ['passrole iam', 'AWS IAM PassRole'], ['pass role aws', 'AWS IAM PassRole'],
  ['CVE-2024-1234', 'CVE-2024-1234'], ['cve 2024 1234', 'CVE-2024-1234'],
  ['S3', 'S3'], ['s3', 'S3'], ['C++', 'C++'], ['C#', 'C#'],
  ['resume securite', 'Résumé sécurité'], ['résumé sécurité', 'Résumé sécurité'],
  ['ReSuMe SeCuRiTe', 'Résumé sécurité'], ['Redis', 'Redis'], ['redi', 'Redis'],
  ['PHP object injection', 'PHP object injection'], ['object injection php', 'PHP object injection'],
  ['base64_decode', 'Encoding'], ['/etc/passwd', 'Encoding'], ['etc passwd', 'Encoding'],
  ['template jinja2', 'Template rendering'], ['TLS 1.3', 'TLS 1.3'],
  ['oauth2', 'OAuth 2.0'], ['OAuth 2.0', 'OAuth 2.0'], ['tls1.3', 'TLS 1.3'], ['日本語検索', '日本語検索'],
  ['AD', 'Active Directory'], ['active directory', 'Active Directory'],
  ['HTTP request smuggling', 'HTTP request smuggling'],
  ['deserializaton', 'Deserialization'], ['opensearhc', 'OpenSearch'],
  ['rce', 'Remote Code Execution'], ['JWT', 'JWT'],
  ['unique needleword', 'Unique heading'], ['aws lambda', 'AWS Lambda'],
  ['azure managed identity', 'Azure Managed Identity'], ['gcp', null],
  ['', null], ['   ', null], ['!!!', null], ['<>()[]{}', null],
  ['the and of', null], ['qzxvbnmasdf', null], ['2029', null], ['s4', null],
  ['constructor', 'Constructor'], ['__proto__', 'Constructor']
];

for(const format of ['legacy', 'compact']){
  const context = worker();
  const fixtures = [legacy(documents), legacy(cloudDocuments)];
  const search = install(context, format === 'compact' ? fixtures.map(compact) : fixtures);
  for(const [query, expected] of cases){
    test(`${format}: ${JSON.stringify(query)} ranks ${expected || 'no match'}`, () => {
      const results = search(query);
      if(expected) assert.equal(results[0]?.title, expected, JSON.stringify(results.map(doc => doc.title)));
      else assert.equal(results.length, 0);
    });
  }
  test(`${format}: technical symbol and numeric matches stay distinct`, () => {
    assert.deepEqual(search('c++').map(doc => doc.title), ['C++']);
    assert.deepEqual(search('c#').map(doc => doc.title), ['C#']);
    assert.deepEqual(search('s3').map(doc => doc.title), ['S3', 'AWS S3']);
    assert.deepEqual(search('cve 2024 1234').map(doc => doc.title), ['CVE-2024-1234']);
  });
  test(`${format}: complete query coverage outranks repeated partial matches`, () => {
    assert.equal(search('sql injection')[0].title, 'SQL Injection');
    assert(!search('sql injection').some(doc => doc.title === 'SQL Logging'));
  });
  test(`${format}: worker query protocol preserves ids and handles empty input`, async () => {
    const messages = [];
    context.postMessage = message => messages.push(message);
    await context.onmessage({data:{id:7, query:'sql injecton'}});
    assert.equal(messages[0].id, 7);
    assert.equal(messages[0].docs[0].title, 'SQL Injection');
    await context.onmessage({data:{id:8, query:'  '}});
    assert.equal(messages[1].docs.length, 0);
  });
}

test('compact and legacy rankings agree for every regression query', () => {
  const fixtures = [legacy(documents), legacy(cloudDocuments)];
  const a = install(worker(), fixtures), b = install(worker(), fixtures.map(compact));
  for(const [query] of cases) assert.deepEqual(a(query), b(query), query);
});

test('full names also find acronym-only headings', () => {
  const search = install(worker(), [legacy([{title:'SQLi'}, {title:'XSS'}, {title:'K8s'}, {title:'Privesc'}])]);
  for(const [query, title] of [['sql injection','SQLi'], ['cross site scripting','XSS'], ['kubernetes','K8s'], ['privilege escalation','Privesc']]){
    assert.equal(search(query)[0]?.title, title);
  }
});

test('typos in full names also find acronym-only headings', () => {
  const search = install(worker(), [legacy([
    {title:'K8s - Pentesting', breadcrumbs:'K8s - Pentesting » K8s - Pentesting', url:'kubernetes/index.html#k8s'},
    {title:'DO - Kubernetes (DOKS)', breadcrumbs:'DO - Kubernetes (DOKS) » DO - Kubernetes (DOKS)'},
    {title:'Example Kubernetes Deployment'}
  ])]);
  assert.equal(search('kubernets')[0]?.title, 'K8s - Pentesting');
});

test('introductory previews use real content on the same page when the root is only a banner', () => {
  const banner = 'Tip Learn & practice AWS Hacking: HackTricks Training AWS Red Team Expert. Share hacking tricks by submitting PRs to the HackTricks and HackTricks Cloud github repos.';
  const search = install(worker(), [legacy([
    {title:'SQL Injection', breadcrumbs:'SQL Injection » SQL Injection', body:banner, url:'sql.html#intro'},
    {title:'References', body:'References '.repeat(10), url:'sql.html#refs'},
    {title:'Basic Information', body:banner + ' SQL injection changes a database query when data is treated as SQL syntax.', url:'sql.html#basic'},
    {title:'Unrelated', body:'Another page must never supply the preview.', url:'other.html#intro'}
  ])]);
  const result = search('sql injection')[0];
  assert.equal(result.title, 'SQL Injection');
  assert(result.url.endsWith('sql.html#intro'));
  assert(result.body.startsWith('SQL injection changes'));
  assert(!result.body.includes('Training'));
});

test('exact titles beat fuzzy and prefix titles across books', () => {
  const search = install(worker(), [legacy([{title:'Kubernets'}, {title:'Redistribution'}]), legacy([{title:'Kubernetes'}, {title:'Redis'}])]);
  assert.equal(search('kubernetes')[0]?.title, 'Kubernetes');
  assert.equal(search('redis')[0]?.title, 'Redis');
});

test('C++ and C# remain searchable and distinct when they appear only in body text', () => {
  const fixture = legacy([
    {title:'Native compiler', body:'A C++ compiler accepts this source file.'},
    {title:'Managed compiler', body:'Use C# for managed applications.'},
    {title:'Other languages', body:'C and C+++ are separate names.'}
  ]);
  for(const data of [fixture, compact(fixture)]){
    const search = install(worker(), [data]);
    assert.deepEqual(search('c++').map(doc => doc.title), ['Native compiler']);
    assert.deepEqual(search('c#').map(doc => doc.title), ['Managed compiler']);
  }
});

test('bounded results, distinct anchors and page diversity', () => {
  const docs = Array.from({length:50}, (_, i) => ({title:`Redis settings ${i}`, url:`redis.html#section-${i}`}));
  docs.push({title:'Redis configuration', url:'other.html#redis'});
  docs.push({title:'Redis configuration', url:'other.html#redis'});
  const results = install(worker(), [legacy(docs)])('redis');
  assert.equal(results.length, 30);
  assert.equal(new Set(results.map(doc => doc.url)).size, 30);
  assert(results.slice(0, 3).some(doc => /(?:^|\/)other\.html/.test(doc.url)));
});

test('long queries and repeated searches are bounded and deterministic', () => {
  const context = worker(), search = install(context, [legacy(documents)]);
  assert.deepEqual(search('sql '.repeat(10000)), search('sql'));
  const expected = search('sql injection');
  for(let i = 0; i < 150; i++) search(`unknownword${i}`);
  assert.deepEqual(search('sql injection'), expected);
  assert(vm.runInContext('built[0].termCache.size <= 128', context));
});

test('public/private host classification includes IPv4 and IPv6 boundaries', () => {
  const context = worker();
  for(const hostname of ['localhost','a.localhost','book.local','book.internal','host.docker.internal','127.0.0.1','10.2.3.4',
    '172.16.0.1','172.31.255.255','192.168.1.4','100.64.0.1','100.127.255.255','169.254.1.1',
    '::1','[::1]','fc00::1','fd12::1','fe80::1','febf::1','::ffff:192.168.1.2']){
    context.hostname = hostname;
    assert.equal(vm.runInContext('isPrivateHost(hostname)', context), true, hostname);
  }
  for(const hostname of ['hacktricks.wiki','cloud.hacktricks.wiki','localhost.evil.test','8.8.8.8','172.15.0.1',
    '172.32.0.1','100.63.255.255','100.128.0.1','192.169.1.1','2001:4860::8888','fec0::1']){
    context.hostname = hostname;
    assert.equal(vm.runInContext('isPrivateHost(hostname)', context), false, hostname);
  }
});

test('source policy never crosses from public to local or private to remote', async () => {
  const calls = [], context = worker();
  context.calls = calls;
  vm.runInContext("loadRemote = async source => { calls.push(source.url); throw Error('offline'); }; loadLocal = locals => { calls.push(...locals); return null; };", context);
  await vm.runInContext("loadWithPolicy([{url:'https://remote.test/index'}], ['/searchindex.js'], false)", context);
  assert.deepEqual(calls, ['https://remote.test/index']);
  calls.length = 0;
  await vm.runInContext("loadWithPolicy([{url:'https://remote.test/index'}], ['/es/searchindex.js', '/searchindex.js'], true)", context);
  assert.deepEqual(calls, ['/es/searchindex.js','/searchindex.js']);
  calls.length = 0;
  await vm.runInContext("loadWithPolicy([{url:'https://remote.test/cloud'}], [], true)", context);
  assert.deepEqual(calls, []);
});

test('translated source order prefers compact then legacy, with English fallback', () => {
  const context = worker();
  const urls = vm.runInContext("remoteSources('https://remote.test', l => 'v2-' + l, l => 'legacy-' + l, 'es').map(s => s.url)", context);
  assert.deepEqual(Array.from(urls), ['https://remote.test/v2-es','https://remote.test/legacy-es','https://remote.test/v2-en','https://remote.test/legacy-en']);
  assert.deepEqual(Array.from(vm.runInContext("localCandidates('/searchindex.js', 'es')", context)), ['/es/searchindex.js','/searchindex.js']);
  assert.deepEqual(Array.from(vm.runInContext("localCandidates('/searchindex.js', '../evil')", context)), ['/searchindex.js']);
});

test('24-hour cache refresh and stale cache fallback on network and HTTP failures', async () => {
  const url = 'https://remote.test/index.gz', entries = new Map();
  let fetches = 0, puts = 0, failure = '', now = 1_000_000_000;
  const context = worker(sourceText, {
    Date:{now:() => now},
    caches:{open:async () => ({match:async key => entries.get(key)?.clone(), put:async (key, response) => { entries.set(key, response); puts++; }})},
    fetch:async () => { fetches++; if(failure === 'network') throw Error('offline'); return new Response('payload', {status:failure === 'http' ? 503 : 200}); }
  });
  context.assetUrl = url;
  const load = () => vm.runInContext('fetchSearchAsset(assetUrl)', context);
  assert.equal(await (await load()).text(), 'payload');
  assert.equal(puts, 2);
  assert.equal(await (await load()).text(), 'payload');
  assert.equal(fetches, 1);
  now += 24 * 60 * 60 * 1000 + 1;
  failure = 'network'; assert.equal(await (await load()).text(), 'payload');
  failure = 'http'; assert.equal(await (await load()).text(), 'payload');
  failure = ''; assert.equal(await (await load()).text(), 'payload');
  assert.equal(fetches, 4); assert.equal(puts, 4);
});

test('cache API failures do not prevent successful downloads', async () => {
  const context = worker(sourceText, {caches:{open:async () => {throw Error('disabled');}}, fetch:async () => new Response('fresh')});
  const response = await vm.runInContext("fetchSearchAsset('https://remote.test/index')", context);
  assert.equal(await response.text(), 'fresh');
});

test('remote compressed compact payloads decrypt, decompress and hydrate into searchable indexes', async () => {
  const fixture = compact(legacy(documents)).data, context = worker();
  const key = Buffer.from(vm.runInContext('XOR_KEY', context));
  const bytes = gzipSync(JSON.stringify(fixture));
  for(let i = 0; i < bytes.length; i++) bytes[i] ^= key[i % key.length];
  context.fetch = async () => new Response(bytes);
  const loaded = await vm.runInContext("loadRemote({format:'compact',url:'https://remote.test/index'})", context);
  const search = install(context, [loaded]);
  assert.equal(search('sql injecton')[0]?.title, 'SQL Injection');
});

test('private translated initialization falls back locally and never fetches another book remotely', async () => {
  const imports = [], messages = [], fixture = legacy(documents);
  const context = worker(sourceText, {postMessage:message => messages.push(message), fetch:async () => {throw Error('unexpected remote download');}});
  context.importScripts = url => {
    imports.push(url);
    if(url !== 'http://localhost/searchindex.js') throw Error('local asset absent');
    context.search.index = fixture.json; context.search.doc_urls = fixture.urls;
  };
  await context.onmessage({data:{type:'init',hostname:'localhost',lang:'es'}});
  assert.equal(messages[0].ready, true);
  assert(imports.includes('http://localhost/es/searchindex.js'));
  assert(imports.includes('http://localhost/searchindex.js'));
  assert(imports.every(url => url.startsWith('http://localhost/')));
  await context.onmessage({data:{id:1,query:'sql injection'}});
  assert.equal(messages[1].docs[0]?.title, 'SQL Injection');
});

function uiHarness(){
  const elements = new Map(), documentEvents = new Map(), workers = [], timers = new Map();
  let timerId = 0;
  const context = {elasticlunr, console:quietConsole, path_to_root:'../',
    window:{location:{hostname:'localhost', assign(){}}, scrollTo(){}},
    URL:{createObjectURL:() => 'blob:test', revokeObjectURL(){}}, Blob,
    setTimeout:fn => { timers.set(++timerId, fn); return timerId; }, clearTimeout:id => timers.delete(id)};
  function element(name){
    const classes = new Set(['hidden']), listeners = new Map();
    const node = {nodeName:name, value:'', textContent:'', innerHTML:'', style:{}, children:[], listeners,
      classList:{contains:cls => classes.has(cls), toggle:(cls, yes) => yes ? classes.add(cls) : classes.delete(cls), add:cls => classes.add(cls), remove:cls => classes.delete(cls)},
      setAttribute(key, value){ this[key] = value; }, removeAttribute(key){ delete this[key]; },
      addEventListener(type, fn){ listeners.set(type, fn); },
      focus(){context.document.activeElement = this;}, select(){}, remove(){},
      appendChild(child){this.children.push(child);}, removeChild(child){this.children.splice(this.children.indexOf(child), 1);},
      get firstChild(){return this.children[0] || null;}, querySelector(){return null;}};
    return node;
  }
  for(const id of ['search-wrapper','searchbar','searchresults','searchresults-outer','searchresults-header','search-toggle']) elements.set(id, element(id === 'searchbar' ? 'INPUT' : 'DIV'));
  context.document = {documentElement:{lang:'en'}, getElementById:id => elements.get(id),
    createElement:element, addEventListener:(type, fn) => documentEvents.set(type, fn)};
  context.Worker = class {
    constructor(){this.messages = []; workers.push(this);}
    postMessage(message){this.messages.push(message);}
  };
  vm.createContext(context);
  vm.runInContext(sourceText.replace(/\}\)\(\);\s*$/, 'globalThis.searchTest = {makeTeaser, format};})();'), context);
  return {context, elements, workers, documentEvents,
    input(value){ const bar = elements.get('searchbar'); bar.value = value; bar.listeners.get('input')({target:bar}); },
    flush(){for(const [id, fn] of timers){timers.delete(id); fn();}},
    open(){elements.get('search-toggle').listeners.get('click')();}};
}

test('normal navigation and empty input do not start a worker or download an index', () => {
  const ui = uiHarness();
  assert.equal(ui.workers.length, 0);
  ui.input(''); ui.flush(); assert.equal(ui.workers.length, 0);
  ui.open(); assert.equal(ui.workers.length, 1);
  assert.equal(ui.workers[0].messages[0].type, 'init');
  ui.open(); ui.open(); assert.equal(ui.workers.length, 1);
});

test('debouncing, pending initialization, stale responses and clearing input', () => {
  const ui = uiHarness();
  ui.input('sql'); ui.input('sql injection'); ui.flush();
  const worker = ui.workers[0];
  assert.equal(worker.messages.length, 1);
  worker.onmessage({data:{ready:true}});
  const request = worker.messages.at(-1);
  assert.equal(request.query, 'sql injection');
  ui.input('redis');
  worker.onmessage({data:{id:request.id, query:request.query, docs:[{title:'wrong',body:'wrong',url:'wrong',breadcrumbs:'wrong'}]}});
  assert.equal(ui.elements.get('searchresults').children.length, 0);
  ui.flush(); const latest = worker.messages.at(-1);
  worker.onmessage({data:{id:latest.id, query:latest.query, docs:[{title:'Redis',body:'cache',url:'redis.html',breadcrumbs:'Redis'}]}});
  assert.equal(ui.elements.get('searchresults').children.length, 1);
  ui.input('');
  assert.equal(ui.elements.get('searchresults').children.length, 0);
  worker.onmessage({data:{id:latest.id, query:latest.query, docs:[{title:'late',body:'late',url:'late',breadcrumbs:'late'}]}});
  assert.equal(ui.elements.get('searchresults').children.length, 0);
});

test('S shortcut opens search, Escape closes it, input typing keeps focus', () => {
  const ui = uiHarness(), keydown = ui.documentEvents.get('keydown');
  let prevented = false;
  keydown({keyCode:83, target:{nodeName:'BODY'}, preventDefault(){prevented = true;}});
  assert(prevented); assert.equal(ui.workers.length, 1);
  assert(!ui.elements.get('search-wrapper').classList.contains('hidden'));
  keydown({keyCode:27, target:{nodeName:'BODY'}, preventDefault(){}});
  assert(ui.elements.get('search-wrapper').classList.contains('hidden'));
  keydown({keyCode:83, target:{nodeName:'INPUT'}, preventDefault(){throw Error('typing hijacked');}});
  assert(ui.elements.get('search-wrapper').classList.contains('hidden'));
});

test('teasers highlight corrected words, identifiers and accents, and escape HTML', () => {
  const {context} = uiHarness();
  const teaser = context.searchTest.makeTeaser;
  assert.match(teaser('SQL injection uses parameters.', ['sql','inject']), /<em>SQL<\/em> <em>injection<\/em>/);
  assert.match(teaser('Une énumération sûre.', ['enumer']), /<em>énumération<\/em>/);
  assert.match(teaser('Use iam:PassRole with care.', ['iam','passrole']), /<em>iam:PassRole<\/em>/);
  assert.match(teaser('<script>alert(1)</script> SQL', ['sql']), /&lt;script&gt;/);
  assert(!teaser('<script>alert(1)</script> SQL', ['sql']).includes('<script>'));
  assert.equal(teaser('', ['sql']), '');
  assert.match(teaser('filler '.repeat(60) + 'SQL injection here', ['sql','inject']), /… .*<em>SQL<\/em>/);
});

test('result links preserve relative roots and anchors and escape result labels', () => {
  const {context} = uiHarness();
  const format = context.searchTest.format;
  const result = format({title:'A',body:'query',breadcrumbs:'<img src=x>',url:'web/sql.html#section'}, ['sql']);
  assert(result.includes('href="../web/sql.html?highlight=sql#section"'));
  assert(result.includes('&lt;img src=x&gt;'));
  const cloud = format({title:'AWS',body:'cloud',breadcrumbs:'AWS',url:'https://cloud.hacktricks.wiki/aws.html#s3',cloud:true}, ['s3']);
  assert(cloud.includes('href="https://cloud.hacktricks.wiki/aws.html?highlight=s3#s3"'));
});

if(process.env.HT_SEARCH_CORPUS){
  test('generated corpus relevance and timing', {timeout:180000}, () => {
    const context = worker();
    const mainRoot = path.basename(root) === 'hacktricks-cloud' ? path.join(root, '../hacktricks') : root;
    const bookPaths = [mainRoot, process.env.HT_SEARCH_CLOUD_ROOT || path.join(mainRoot, '../hacktricks-cloud')];
    const indexPaths = [process.env.HT_SEARCH_MAIN_INDEX, process.env.HT_SEARCH_CLOUD_INDEX];
    const datasets = bookPaths.map((book, i) => {
      const indexPath = indexPaths[i] || path.join(book, 'book/searchindex.js');
      if(process.env.HT_SEARCH_CORPUS_FORMAT === 'compact') return {format:'compact', data:JSON.parse(fs.readFileSync(indexPath, 'utf8'))};
      const wrapper = {window:{search:{}}};
      vm.runInNewContext(fs.readFileSync(indexPath, 'utf8'), wrapper);
      const data = wrapper.window.search;
      return {format:'legacy', json:data.index, urls:data.doc_urls};
    });
    const start = performance.now();
    const search = install(context, datasets);
    console.log(`Search initialization: ${Math.round(performance.now() - start)}ms; ${datasets.reduce((n, d) => n + (d.urls || d.data.doc_urls).length, 0)} sections`);
    const queries = [
      ['sql injection', /sql-injection/], ['sql injecton', /sql-injection/],
      ['cross site scripting', /xss-cross-site-scripting/], ['xss', /xss-cross-site-scripting/],
      ['ssrf', /ssrf-server-side-request-forgery/], ['linux privesc', /linux-privilege-escalation/],
      ['SeImpersonatePrivilege', /seimpersonate/], ['kerberosting', /kerberoast/],
      ['iam:PassRole', /iam-passrole/], ['aws s3', /aws-s3/],
      ['kubernets', /kubernetes/], ['redis', /redis/],
      ['request smuggling', /request-smuggling/], ['prototype pollution', /prototype-pollution/],
      ['CVE-2021-44228', /log4shell|log4j/], ['docker', /docker/],
      ['azure managed identity', /managed-identit/], ['gcp cloud storage', /storage/]
    ];
    const timings = [], failures = [];
    for(const [query, expected] of queries){
      const before = performance.now(), results = search(query), elapsed = performance.now() - before;
      timings.push(elapsed);
      console.log(`${query}: ${Math.round(elapsed)}ms; ${results.slice(0, 3).map(doc => doc.title).join(' | ')}`);
      if(!results.slice(0, 5).some(doc => expected.test(doc.url))) failures.push(`${query}: ${results.slice(0, 5).map(doc => doc.url).join(', ')}`);
      assert(results.length <= 30);
    }
    console.log(`Cold query median: ${Math.round(timings.sort((a,b) => a-b)[Math.floor(timings.length/2)])}ms; maximum: ${Math.round(Math.max(...timings))}ms`);
    const before = performance.now(); search('sql injection');
    console.log(`Warm query: ${Math.round(performance.now() - before)}ms`);
    assert.deepEqual(failures, []);
  });
}
