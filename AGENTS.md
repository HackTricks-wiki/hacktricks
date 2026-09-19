# AGENTS.md

このリポジトリで作業する将来のエージェント向けガイダンス。

## リポジトリのコンテキスト

これはメインの HackTricks mdBook リポジトリです。関連する cloud book は以下にあります。

`/Users/carlospolop/git/hacktricks-cloud`

共有テーマや search の動作に対する変更は、通常、両方のリポジトリに適用する必要があります。

## Search Index Loading Contract

カスタム search UI は以下にあります。

`theme/ht_searcher.js`

生成済みのコピーが以下に存在する場合もあります。

`book/theme/ht_searcher.js`

production でビルド済みの `book/` ディレクトリをデプロイしている場合は、両方のコピーを更新するか、デプロイ前に book を再ビルドしてください。

search index のソースポリシーは重要であり、コストにも影響します。

- public host では、すべての言語固有および fallback の候補を
`HackTricks-wiki/hacktricks-searchindex` からのみ読み込んでください。同一 origin の mdBook output には fallback しないでください。production で `hacktricks.wiki` から大容量の index を提供するとコストが高くなります。
- localhost、`.local`/`.internal` host、loopback、RFC1918、carrier-grade NAT、link-local、または private IPv6 address では、同一 origin の mdBook output のみを読み込んでください。これにより、local/container deployment が self-contained のまま維持されます。

この repo で想定される local fallback は以下です。

`/searchindex.js`

private host では、cloud index はこの origin から利用できないため、remote download を発生させてはいけません。public host では、remote の `searchindex-cloud-<lang>.js.gz` ファイルを使用してください。

## Search Index Publishing

暗号化された圧縮 search index を
`HackTricks-wiki/hacktricks-searchindex` に publish する workflow は以下です。

- `.github/workflows/build_master.yml`
- `.github/workflows/translate_all.yml`

生成される source file は `book/searchindex.js` です。publish される remote artifact 名は以下です。

- `searchindex-v2-en.json.gz` (preferred compact index)
- `searchindex-v2-<lang>.json.gz` (preferred compact index)
- `searchindex-en.js.gz`
- `searchindex-<lang>.js.gz`

browser loader は compact v2 artifact を優先し、`.js.gz` artifact を legacy fallback として保持します。どちらも `theme/ht_searcher.js` で定義されている key を使用した XOR-encrypted gzip payload です。

loader は lazy のままでなければなりません。通常のページ navigation では、visitor が search を開くか使用するまで search worker を作成したり index を download したりしてはいけません。remote の compressed response は origin ごとに 24 時間、Cache Storage に保存されるため、後続のページで再利用できます。期限切れの entry の refresh に失敗した場合は、stale-cache fallback を維持してください。

## Build And Validation

一般的な local check：

- `node --check theme/ht_searcher.js`
- `mdbook build`

`mdbook build` が失敗した場合は、以下を確認してください。

- `hacktricks-preprocessor-error.log`
- `hacktricks-preprocessor.log`

## Editing Notes

- 検索には `rg` を優先してください。
- 明示的に要求されない限り、生成された `book/` output を commit に含めないでください。すでにビルド済みのページを直ちに修正する必要がある場合は、search loader の修正は例外です。
- 共有 theme の動作を変更する場合は、
`/Users/carlospolop/git/hacktricks-cloud` にある対応する file と比較し、更新してください。
- 無関係な local の変更を元に戻さないでください。
