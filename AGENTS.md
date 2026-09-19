# AGENTS.md

इस repository पर काम करने वाले future agents के लिए guidance।

## Repository Context

यह मुख्य HackTricks mdBook repository है। संबंधित cloud book यहां मौजूद है:

`/Users/carlospolop/git/hacktricks-cloud`

Shared theme/search behavior में किए गए changes अक्सर दोनों repositories में लागू करने पड़ते हैं।

## Search Index Loading Contract

Custom search UI यहां मौजूद है:

`theme/ht_searcher.js`

एक generated copy यहां भी हो सकती है:

`book/theme/ht_searcher.js`

यदि production पहले से बनी हुई `book/` directory deploy कर रहा है, तो दोनों copies update करें या deployment से पहले book rebuild करें।

Search index loading order महत्वपूर्ण और cost-sensitive है:

1. GitHub repository से प्रत्येक language-specific और fallback search index load करें:
`HackTricks-wiki/hacktricks-searchindex`
2. केवल तभी same-origin mdBook output पर fallback करें जब सभी GitHub-hosted candidates fail हो जाएं।

Local `/searchindex.js` fallback को किसी भी GitHub-hosted fallback, जैसे `searchindex-en.js.gz`, से पहले न रखें। Production में `hacktricks.wiki` से `searchindex.js` serve करना महंगा है।

इस repo के लिए expected local fallback है:

`/searchindex.js`

cloud index को इस origin से local fallback का उपयोग नहीं करना चाहिए। इसे remote
`searchindex-cloud-<lang>.js.gz` files पर निर्भर रहना चाहिए।

## Search Index Publishing

Encrypted compressed search indexes को
`HackTricks-wiki/hacktricks-searchindex` पर publish करने वाले workflows हैं:

- `.github/workflows/build_master.yml`
- `.github/workflows/translate_all.yml`

Generated source file है `book/searchindex.js`। Published remote artifact names हैं:

- `searchindex-v2-en.json.gz` (preferred compact index)
- `searchindex-v2-<lang>.json.gz` (preferred compact index)
- `searchindex-en.js.gz`
- `searchindex-<lang>.js.gz`

Browser loader compact v2 artifact को प्राथमिकता देता है और `.js.gz` artifact को legacy fallback के रूप में रखता है। दोनों XOR-encrypted gzip payloads हैं, जिनमें `theme/ht_searcher.js` में परिभाषित key का उपयोग होता है।

Loader lazy रहना चाहिए: सामान्य page navigation को search worker create नहीं करना चाहिए या index download नहीं करना चाहिए, जब तक visitor search खोलता या उपयोग नहीं करता। Remote compressed responses को प्रति origin 24 घंटे के लिए Cache Storage में persist किया जाता है, ताकि subsequent pages उनका पुनः उपयोग कर सकें। Expired entry को refresh करते समय failure होने पर stale-cache fallback को बनाए रखें।

## Build And Validation

Common local checks:

- `node --check theme/ht_searcher.js`
- `mdbook build`

यदि `mdbook build` fail हो, तो जांचें:

- `hacktricks-preprocessor-error.log`
- `hacktricks-preprocessor.log`

## Editing Notes

- Searching के लिए `rg` को प्राथमिकता दें।
- Generated `book/` output को commits से बाहर रखें, जब तक विशेष रूप से अनुरोध न किया गया हो। Search loader fixes इसका exception हैं, जब पहले से बने pages को तुरंत correct करना आवश्यक हो।
- Shared theme behavior बदलते समय matching file को
`/Users/carlospolop/git/hacktricks-cloud` में compare और update करें।
- असंबंधित local changes को revert न करें।
