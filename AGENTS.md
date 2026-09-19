# AGENTS.md

このリポジトリで作業する今後の agent 向けガイダンス。

## Repository Context

これはメインの HackTricks mdBook リポジトリです。関連する cloud book は次の場所にあります。

`/Users/carlospolop/git/hacktricks-cloud`

共有 theme/search の動作に対する変更は、両方のリポジトリに適用する必要がある場合があります。

## Search Index Loading Contract

カスタム search UI は次の場所にあります。

`theme/ht_searcher.js`

生成済みのコピーが次の場所に存在する場合もあります。

`book/theme/ht_searcher.js`

production 環境でビルド済みの `book/` ディレクトリをデプロイしている場合は、両方のコピーを更新するか、デプロイ前に book を再ビルドしてください。

search index の読み込み順序は重要であり、コストにも影響します。

1. GitHub repository から、言語固有の search index と fallback search index をすべて読み込む：
`HackTricks-wiki/hacktricks-searchindex`
2. GitHub-hosted の候補がすべて失敗した場合に限り、same-origin の mdBook output にフォールバックする。

`searchindex-en.js.gz` などの GitHub-hosted fallback より前に、local `/searchindex.js` fallback を配置しないでください。production 環境で `hacktricks.wiki` から `searchindex.js` を配信するとコストが高くなります。

この repo で想定される local fallback は次のとおりです。

`/searchindex.js`

cloud index では、この origin の local fallback を使用しないでください。remote の `searchindex-cloud-<lang>.js.gz` ファイルに依存してください。

## Search Index Publishing

暗号化された圧縮 search index を `HackTricks-wiki/hacktricks-searchindex` に publish する workflow は次のとおりです。

- `.github/workflows/build_master.yml`
- `.github/workflows/translate_all.yml`

生成される source file は `book/searchindex.js` です。publish される remote artifact の名前は次のとおりです。

- `searchindex-v2-en.json.gz`（推奨される compact index）
- `searchindex-v2-<lang>.json.gz`（推奨される compact index）
- `searchindex-en.js.gz`
- `searchindex-<lang>.js.gz`

browser loader は compact v2 artifact を優先し、`.js.gz` artifact は legacy fallback として保持します。どちらも `theme/ht_searcher.js` で定義された key を使用する XOR-encrypted gzip payload です。

loader は lazy のままにしてください。通常のページ遷移では、visitor が search を開くか使用するまで search worker を作成したり、index を download したりしてはいけません。remote の圧縮 response は、origin ごとに 24 時間、Cache Storage に保存されるため、後続のページで再利用できます。期限切れの entry の更新に失敗した場合の stale-cache fallback を維持してください。

## Build And Validation

一般的な local check：

- `node --check theme/ht_searcher.js`
- `mdbook build`

`mdbook build` が失敗した場合は、次を確認してください。

- `hacktricks-preprocessor-error.log`
- `hacktricks-preprocessor.log`

## Editing Notes

- 検索には `rg` を優先して使用してください。
- 明示的に要求されていない限り、生成された `book/` output を commit に含めないでください。すでにビルド済みのページを直ちに修正する必要がある場合は、search loader の修正は例外です。
- 共有 theme の動作を変更する場合は、`/Users/carlospolop/git/hacktricks-cloud` 内の対応するファイルを比較して更新してください。
- 関係のない local changes を元に戻さないでください。
