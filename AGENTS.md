# AGENTS.md

この repository で作業する future agents 向けのガイダンス。

## Repository Context

これはメインの HackTricks mdBook repository です。関連する cloud book は次にあります：

`/Users/carlospolop/git/hacktricks-cloud`

共有 theme/search behavior への変更は、両方の repository に適用する必要がある場合があります。

## Search Index Loading Contract

custom search UI は次にあります：

`theme/ht_searcher.js`

generated copy が次に存在する場合もあります：

`book/theme/ht_searcher.js`

production がすでに build 済みの `book/` directory を deploy する場合は、両方の copy を更新するか、book を rebuild してください。

search index の loading order は重要であり、cost-sensitive です：

1. GitHub repository から、すべての language-specific および fallback search index を load する：
`HackTricks-wiki/hacktricks-searchindex`
2. GitHub-hosted の候補がすべて失敗した場合のみ、same-origin mdBook output に fallback する。

`searchindex-en.js.gz` などの GitHub-hosted fallback より前に、local `/searchindex.js` fallback を配置しないでください。production で `hacktricks.wiki` から `searchindex.js` を serve するのは高コストです。

この repo で想定される local fallback は次のとおりです：

`/searchindex.js`

cloud index はこの origin の local fallback を使用しないでください。remote の `searchindex-cloud-<lang>.js.gz` files に依存してください。

## Search Index Publishing

encrypted compressed search indexes を
`HackTricks-wiki/hacktricks-searchindex` に publish する workflows は次のとおりです：

- `.github/workflows/build_master.yml`
- `.github/workflows/translate_all.yml`

generated source file は `book/searchindex.js` です。published remote artifact names は次のとおりです：

- `searchindex-v2-en.json.gz` (preferred compact index)
- `searchindex-v2-<lang>.json.gz` (preferred compact index)
- `searchindex-en.js.gz`
- `searchindex-<lang>.js.gz`

browser loader は compact v2 artifact を優先し、`.js.gz` artifact を legacy fallback として保持します。どちらも `theme/ht_searcher.js` で定義された key を使用する XOR-encrypted gzip payload です。

## Build And Validation

Common local checks：

- `node --check theme/ht_searcher.js`
- `mdbook build`

`mdbook build` が失敗した場合は、次を確認してください：

- `hacktricks-preprocessor-error.log`
- `hacktricks-preprocessor.log`

## Editing Notes

- 検索には `rg` を優先してください。
- 明示的に要求されない限り、generated `book/` output を commits に含めないでください。すでに build 済みの pages を直ちに修正する必要がある場合は、search loader fixes は例外です。
- shared theme behavior を変更する場合は、
`/Users/carlospolop/git/hacktricks-cloud` にある対応する file と比較し、更新してください。
- 関係のない local changes を revert しないでください。
