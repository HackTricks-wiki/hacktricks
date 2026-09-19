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

The search index source policy is important and cost-sensitive:

- On public hosts, load every language-specific and fallback candidate only from
  `HackTricks-wiki/hacktricks-searchindex`. Never fall back to the same-origin mdBook output;
  serving the large index from `hacktricks.wiki` in production is expensive.
- On localhost, `.local`/`.internal` hosts, loopback, RFC1918, carrier-grade NAT, link-local, or
  private IPv6 addresses, load only the same-origin mdBook output so local/container deployments
  remain self-contained.

For this repo, the expected local fallback is:

`/searchindex.js`

On private hosts, the cloud index is unavailable from this origin and must not trigger a remote
download. On public hosts it should use the remote `searchindex-cloud-<lang>.js.gz` files.

## Search Index Publishing

The workflows that publish encrypted compressed search indexes to
`HackTricks-wiki/hacktricks-searchindex` are:

- `.github/workflows/build_master.yml`
- `.github/workflows/translate_all.yml`

The generated source file is `book/searchindex.js`. The published remote artifact names are:

- `searchindex-v2-en.json.gz` (preferred compact index)
- `searchindex-v2-<lang>.json.gz` (preferred compact index)
- `searchindex-en.js.gz`
- `searchindex-<lang>.js.gz`

The browser loader prefers the compact v2 artifact and keeps the `.js.gz` artifact as a legacy
fallback. Both are XOR-encrypted gzip payloads using the key defined in `theme/ht_searcher.js`.

The loader must stay lazy: normal page navigation must not create the search worker or download an
index until the visitor opens or uses search. Remote compressed responses are persisted in Cache
Storage for 24 hours per origin so subsequent pages can reuse them. Preserve the stale-cache
fallback when refreshing an expired entry fails.

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
