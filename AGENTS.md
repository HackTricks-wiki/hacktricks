# AGENTS.md

Guidance for future agents working in this repository.

## Repository Context

This is the main HackTricks mdBook repository. The related cloud book lives at:

`/Users/carlospolop/git/hacktricks-cloud`

Changes to shared theme/search behavior often need to be applied in both repositories.

## Search Index Loading Contract

The custom search UI lives in:

`theme/ht_searcher.js`

There may also be a generated copy at:

`book/theme/ht_searcher.js`

If production is deploying the already-built `book/` directory, update both copies or rebuild the
book before deployment.

The search index loading order is important and cost-sensitive:

1. Load every language-specific and fallback search index from the GitHub repository:
   `HackTricks-wiki/hacktricks-searchindex`
2. Only if all GitHub-hosted candidates fail, fall back to the same-origin mdBook output.

Do not place the local `/searchindex.js` fallback before any GitHub-hosted fallback such as
`searchindex-en.js.gz`. Serving `searchindex.js` from `hacktricks.wiki` in production is expensive.

For this repo, the expected local fallback is:

`/searchindex.js`

The cloud index should not use a local fallback from this origin. It should rely on the remote
`searchindex-cloud-<lang>.js.gz` files.

## Search Index Publishing

The workflows that publish encrypted compressed search indexes to
`HackTricks-wiki/hacktricks-searchindex` are:

- `.github/workflows/build_master.yml`
- `.github/workflows/translate_all.yml`

The generated source file is `book/searchindex.js`. The published remote artifact names are:

- `searchindex-en.js.gz`
- `searchindex-<lang>.js.gz`

The browser loader expects the remote `.js.gz` files to be XOR-encrypted gzip payloads using the
key defined in `theme/ht_searcher.js`.

## Build And Validation

Common local checks:

- `node --check theme/ht_searcher.js`
- `mdbook build`

If `mdbook build` fails, check:

- `hacktricks-preprocessor-error.log`
- `hacktricks-preprocessor.log`

## Editing Notes

- Prefer `rg` for searching.
- Keep generated `book/` output out of commits unless explicitly requested. Search loader fixes are
  an exception when the already-built pages must be corrected immediately.
- If changing shared theme behavior, compare and update the matching file in
  `/Users/carlospolop/git/hacktricks-cloud`.
- Do not revert unrelated local changes.
