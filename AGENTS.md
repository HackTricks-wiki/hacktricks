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
- `node --test scripts/test_search.js` (matching, ranking, UI, source policy, and cache regressions)
- `HT_SEARCH_CORPUS=1 node --test scripts/test_search.js` (also checks both generated books when present)
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

## Branch and pull-request hygiene

These rules apply to agents working in this repository. Follow repository-specific review, release, and branch-protection policies as well.

1. **Target the actual default branch.** Read the repository's configured default branch before starting (`gh repo view --json defaultBranchRef --jq .defaultBranchRef.name`, or equivalent). Normally it is `main` or `master`, but never guess. Base ordinary change PRs on that branch and keep them up to date with it. Use a release/maintenance branch only when the task or repository policy specifically requires one. Aim to land approved work in the configured default branch; do not merge without the required authorization, reviews, and passing checks.
2. **Start clean and branch only when needed.** Check `git status` and existing worktrees first; preserve others' uncommitted work. Fetch the default branch, then make one clearly named, short-lived branch (or isolated worktree) per coherent change. Reuse that branch for revisions instead of creating duplicate or speculative branches. Never reset, force-push, or stash away someone else's work to make the checkout look clean.
3. **Keep work reviewable.** Push only the scoped changes to the work branch, open a PR against the correct base, and keep the branch while its PR is open or other work depends on it. Do not push directly to a protected default branch or bypass approvals.
4. **Clean up after a verified merge.** Confirm the PR really merged and its changes landed before deleting anything; a squash/rebase merge may not make the old branch an ancestor. Check that the branch is not protected, shared, used by another open PR, or carrying unmerged commits. Then delete only the completed work's remote branch (using the PR's delete-branch option when appropriate), switch away from and remove only its local branch/worktree, and prune stale remote-tracking refs. Never delete the configured default branch, release branches, forks, or anyone else's work.
5. **Leave a clean environment.** At handoff, check for uncommitted changes and leftover branches/worktrees created for this task; either clean up safely or report precisely what must remain and why. If a merge or deletion is not authorized or cannot be proven safe, leave the branch intact and explain the blocker rather than guessing.
