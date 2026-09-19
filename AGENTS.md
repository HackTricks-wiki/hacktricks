# AGENTS.md

为未来在此 repository 中工作的 agents 提供指导。

## Repository Context

这是主要的 HackTricks mdBook repository。相关的 cloud book 位于：

`/Users/carlospolop/git/hacktricks-cloud`

对 shared theme/search behavior 的修改通常需要应用到两个 repository 中。

## Search Index Loading Contract

自定义 search UI 位于：

`theme/ht_searcher.js`

也可能存在一个 generated copy：

`book/theme/ht_searcher.js`

如果 production 部署的是已经构建好的 `book/` directory，请同时更新两个 copy，或在部署前重新构建
book。

Search index source policy 很重要，并且涉及成本：

- 在 public hosts 上，只能从
`HackTricks-wiki/hacktricks-searchindex` 加载所有 language-specific 和 fallback candidate。绝不能 fallback 到相同 origin 的 mdBook output；在 production 中从 `hacktricks.wiki` 提供大型 index 的成本很高。
- 在 localhost、`.local`/`.internal` hosts、loopback、RFC1918、carrier-grade NAT、link-local 或
private IPv6 addresses 上，只能加载相同 origin 的 mdBook output，以便 local/container deployments 保持 self-contained。对于非 English page，先尝试带 language prefix 的 local path（例如 `/es/searchindex.js`），仅在失败时使用 root English index 作为 fallback。

对于此 repo，预期的 local fallback 是：

`/searchindex.js`

在 private hosts 上，cloud index 无法从此 origin 获取，且不得触发 remote download。在 public hosts 上，应使用 remote `searchindex-cloud-<lang>.js.gz` files。

## Search Index Publishing

将 encrypted compressed search indexes 发布到
`HackTricks-wiki/hacktricks-searchindex` 的 workflows 是：

- `.github/workflows/build_master.yml`
- `.github/workflows/translate_all.yml`

生成的 source file 是 `book/searchindex.js`。发布的 remote artifact names 是：

- `searchindex-v2-en.json.gz`（preferred compact index）
- `searchindex-v2-<lang>.json.gz`（preferred compact index）
- `searchindex-en.js.gz`
- `searchindex-<lang>.js.gz`

Browser loader 优先使用 compact v2 artifact，并将 `.js.gz` artifact 保留为 legacy fallback。两者都是使用
`theme/ht_searcher.js` 中定义的 key 进行 XOR-encrypted 的 gzip payload。

Loader 必须保持 lazy：正常的 page navigation 不得创建 search worker 或 download index，直到 visitor 打开或使用 search。Remote compressed responses 会按 origin 持久化在 Cache Storage 中 24 小时，以便后续 pages 复用。刷新过期 entry 失败时，必须保留 stale-cache fallback。

## Build And Validation

常见的 local checks：

- `node --check theme/ht_searcher.js`
- `mdbook build`

如果 `mdbook build` 失败，请检查：

- `hacktricks-preprocessor-error.log`
- `hacktricks-preprocessor.log`

## Editing Notes

- 搜索时优先使用 `rg`。
- 除非明确请求，否则不要将 generated `book/` output 提交到 commits。Search loader fixes 是例外：当必须立即修正已经构建的 pages 时，可以提交。
- 如果修改 shared theme behavior，请对比并更新
`/Users/carlospolop/git/hacktricks-cloud` 中对应的 file。
- 不要 revert 无关的 local changes。
