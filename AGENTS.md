# AGENTS.md

为未来在此 repository 中工作的 agents 提供指导。

## Repository Context

这是主 HackTricks mdBook repository。相关的 cloud book 位于：

`/Users/carlospolop/git/hacktricks-cloud`

对共享 theme/search behavior 的更改通常需要同时应用到两个 repository。

## Search Index Loading Contract

自定义 search UI 位于：

`theme/ht_searcher.js`

也可能存在一个生成的副本：

`book/theme/ht_searcher.js`

如果 production 正在部署已经构建好的 `book/` directory，请同时更新两个副本，或在部署前重新构建 book。

Search index 的加载顺序很重要，并且会影响成本：

1. 从 GitHub repository `HackTricks-wiki/hacktricks-searchindex` 加载所有 language-specific 和 fallback search index。
2. 只有当所有 GitHub-hosted candidates 都失败时，才回退到 same-origin mdBook output。

不要将 local `/searchindex.js` fallback 放在任何 GitHub-hosted fallback（例如 `searchindex-en.js.gz`）之前。在 production 中从 `hacktricks.wiki` 提供 `searchindex.js` 的成本很高。

对于此 repo，预期的 local fallback 是：

`/searchindex.js`

cloud index 不应使用来自此 origin 的 local fallback，而应依赖 remote `searchindex-cloud-<lang>.js.gz` files。

## Search Index Publishing

将 encrypted compressed search indexes 发布到 `HackTricks-wiki/hacktricks-searchindex` 的 workflows 是：

- `.github/workflows/build_master.yml`
- `.github/workflows/translate_all.yml`

生成的 source file 是 `book/searchindex.js`。发布的 remote artifact 名称是：

- `searchindex-v2-en.json.gz`（首选 compact index）
- `searchindex-v2-<lang>.json.gz`（首选 compact index）
- `searchindex-en.js.gz`
- `searchindex-<lang>.js.gz`

browser loader 优先使用 compact v2 artifact，并将 `.js.gz` artifact 作为 legacy fallback。两者都是使用 `theme/ht_searcher.js` 中定义的 key 进行 XOR-encrypted 的 gzip payload。

loader 必须保持 lazy：普通 page navigation 不得创建 search worker，也不得下载 index，直到 visitor 打开或使用 search。Remote compressed responses 会按 origin 持久化到 Cache Storage 中，保存 24 小时，以便后续 pages 重用。刷新过期 entry 失败时，保留 stale-cache fallback。

## Build And Validation

常用的 local checks：

- `node --check theme/ht_searcher.js`
- `mdbook build`

如果 `mdbook build` 失败，请检查：

- `hacktricks-preprocessor-error.log`
- `hacktricks-preprocessor.log`

## Editing Notes

- 优先使用 `rg` 进行搜索。
- 除非明确要求，否则不要将生成的 `book/` output 提交到 commits 中。当必须立即修复已构建的 pages 时，search loader fixes 是例外。
- 如果更改 shared theme behavior，请对比并更新 `/Users/carlospolop/git/hacktricks-cloud` 中对应的 file。
- 不要 revert 无关的 local changes。
