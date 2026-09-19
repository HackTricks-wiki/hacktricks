# AGENTS.md

このリポジトリで作業する将来の agents 向けガイダンス。

## リポジトリコンテキスト

これはメインの HackTricks mdBook repository です。関連する cloud book は次の場所にあります。

`/Users/carlospolop/git/hacktricks-cloud`

共有 theme/search behavior への変更は、通常、両方の repository に適用する必要があります。

## Search Index Loading Contract

カスタム search UI は次の場所にあります。

`theme/ht_searcher.js`

生成済みのコピーが次の場所にある場合もあります。

`book/theme/ht_searcher.js`

production がすでに build 済みの `book/` directory を deploy している場合は、両方のコピーを更新するか、deployment 前に book を rebuild してください。

search index source policy は重要であり、cost-sensitive です。

- public host では、すべての language-specific および fallback candidate を
`HackTricks-wiki/hacktricks-searchindex` からのみ load してください。同一 origin の mdBook output には fallback しないでください。production で大きな index を `hacktricks.wiki` から serve すると高額になるためです。
- localhost、`.local`/`.internal` host、loopback、RFC1918、carrier-grade NAT、link-local、または private IPv6 address では、同一 origin の mdBook output のみを load してください。これにより local/container deployment を self-contained に保てます。英語以外の page では、まず language-prefixed local path を試し（例 `/es/searchindex.js`）、root English index は fallback としてのみ使用してください。

この repo で想定される local fallback は次のとおりです。

`/searchindex.js`

private host では、cloud index はこの origin から利用できないため、remote download を trigger してはいけません。public host では、remote の `searchindex-cloud-<lang>.js.gz` files を使用してください。

## Search Index Publishing

暗号化された圧縮 search index を `HackTricks-wiki/hacktricks-searchindex` に publish する workflow は次のとおりです。

- `.github/workflows/build_master.yml`
- `.github/workflows/translate_all.yml`

生成される source file は `book/searchindex.js` です。publish される remote artifact 名は次のとおりです。

- `searchindex-v2-en.json.gz`（preferred compact index）
- `searchindex-v2-<lang>.json.gz`（preferred compact index）
- `searchindex-en.js.gz`
- `searchindex-<lang>.js.gz`

browser loader は compact v2 artifact を優先し、`.js.gz` artifact は legacy fallback として保持します。どちらも、`theme/ht_searcher.js` で定義された key を使用する XOR-encrypted gzip payload です。

loader は lazy のままでなければなりません。通常の page navigation では、visitor が search を開くか使用するまで、search worker を作成したり index を download したりしてはいけません。remote compressed response は、origin ごとに 24 時間 Cache Storage に保存され、後続の page で再利用できます。期限切れの entry の refresh に失敗した場合は、stale-cache fallback を維持してください。

## Build And Validation

一般的な local check：

- `node --check theme/ht_searcher.js`
- `mdbook build`

`mdbook build` が失敗した場合は、次を確認してください。

- `hacktricks-preprocessor-error.log`
- `hacktricks-preprocessor.log`

## Editing Notes

- 検索には `rg` を優先してください。
- 明示的に要求されない限り、生成された `book/` output を commit に含めないでください。すでに build 済みの page を直ちに修正する必要がある場合は、search loader の修正は例外です。
- shared theme behavior を変更する場合は、
`/Users/carlospolop/git/hacktricks-cloud` の対応する file と比較し、更新してください。
- 関係のない local changes を revert しないでください。
