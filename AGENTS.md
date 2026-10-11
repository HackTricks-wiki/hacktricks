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
remain self-contained. For a non-English page, try the language-prefixed local path first (for
example `/es/searchindex.js`) and use the root English index only as a fallback.

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

## Book Organization Notes

HackTricks books are growing every days and it's highly important to keep the organized. Follow the following recommendations when updating it:

- Techniques must be in only 1 place, in the most related place for the technique where is expected to find similar techniques, and referenced internally from wherever needed. We must not duplicate techniques.
- Files must not be super long or super short: We don't need 1 file per strict techniques because that would generate hundreds of thousands of pages in HackTricks, bu we also want to keep sections readable and properly organized, so we don't want pages with hundreds of techniques together. Therefore find a good tradecraft between the number of techniques to add in page and when to split a page so the organization and number of pages are really scalable.

## Content Syntax and Format Notes

- Use simple words so non native english speakers can easily read and understand every context
- By direct in the explanations, not adding words or sentences that doesn't add value
- Explain things properly in a comprehensive way, the gola of HackTricks is to clearly explain even complex techniques in a way that people starting cybersecurity can understand them. If the topic is simple or is a new technique inside a file that already explains the topic just explain the technique briefly but giving all needed details and examples and code to fully understand it. If the topic is complex start from the beginning explaining everything needed to understand the technique and then explain the technique. At the end of each explanation ask yourself if a person with basic IT knowledge will understand the technique or not with all the context of the page, and if not, improve the explanation/give more context
- Do not start paragraphs with few words likes like: "Do not reuse offsets across kernel builds." The start of a paragraph must start explaining from the begging the idea given in that paragraph and not the end (starting from the end idea is fucking confusing)
- If you see pages not following these directives, fix them also please