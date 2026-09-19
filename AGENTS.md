# AGENTS.md

为未来在此 repository 中工作的 agents 提供指导。

## Repository Context

这是主 HackTricks mdBook repository。相关的 cloud book 位于：

`/Users/carlospolop/git/hacktricks-cloud`

对共享 theme/search behavior 的更改通常需要在两个 repositories 中同时应用。

## Search Index Loading Contract

自定义 search UI 位于：

`theme/ht_searcher.js`

也可能存在一个生成的副本：

`book/theme/ht_searcher.js`

如果 production 部署的是已经构建的 `book/` directory，请更新两个副本，或在部署前重新构建
book。

Search index 的 loading order 很重要，并且涉及成本：

1. 从 GitHub repository 加载所有 language-specific 和 fallback search index：
`HackTricks-wiki/hacktricks-searchindex`
2. 只有在所有托管于 GitHub 的候选项都失败后，才回退到同源的 mdBook output。

不要将本地 `/searchindex.js` fallback 放在任何 GitHub-hosted fallback（例如
`searchindex-en.js.gz`）之前。在 production 中从 `hacktricks.wiki` 提供 `searchindex.js` 的成本很高。

对于此 repo，预期的 local fallback 是：

`/searchindex.js`

cloud index 不应使用来自此 origin 的 local fallback。它应依赖远程的
`searchindex-cloud-<lang>.js.gz` files。

## Search Index Publishing

将加密压缩的 search indexes 发布到
`HackTricks-wiki/hacktricks-searchindex` 的 workflows 是：

- `.github/workflows/build_master.yml`
- `.github/workflows/translate_all.yml`

生成的 source file 是 `book/searchindex.js`。发布的远程 artifact names 是：

- `searchindex-v2-en.json.gz`（首选的 compact index）
- `searchindex-v2-<lang>.json.gz`（首选的 compact index）
- `searchindex-en.js.gz`
- `searchindex-<lang>.js.gz`

浏览器 loader 优先使用 compact v2 artifact，并将 `.js.gz` artifact 保留为 legacy
fallback。两者都是使用 `theme/ht_searcher.js` 中定义的 key 进行 XOR-encrypted 的 gzip payloads。

## Build And Validation

常见的 local checks：

- `node --check theme/ht_searcher.js`
- `mdbook build`

如果 `mdbook build` 失败，请检查：

- `hacktricks-preprocessor-error.log`
- `hacktricks-preprocessor.log`

## Editing Notes

- 搜索时优先使用 `rg`。
- 除非明确要求，否则不要将生成的 `book/` output 提交。若必须立即修复已经构建的 pages，search loader fixes 是例外。
- 如果更改 shared theme behavior，请对比并更新
`/Users/carlospolop/git/hacktricks-cloud` 中对应的 file。
- 不要还原无关的 local changes。
