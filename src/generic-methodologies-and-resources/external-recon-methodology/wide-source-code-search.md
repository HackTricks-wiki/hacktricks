# Wide Source Code Search

{{#include ../../banners/hacktricks-training.md}}

The goal of this page is to enumerate **platforms that allow you to search code** (literal, regex, symbol-aware, or path-scoped) across **thousands/millions of repos**.

This is useful to:

- **Search for leaked information**
- **Search for vulnerable patterns**
- **Map technologies, internal hosts, CI/CD, and infrastructure-as-code**
- **Pivot from a company/org name into repos, branches, and high-signal files**

- [**Sourcebot**](https://www.sourcebot.dev/): Open-source/self-hosted code search. Very useful when you want to index **many repos** and, if configured, additional branches/tags while keeping regex filters such as `repo:`, `file:`, `lang:`, `rev:` and `sym:`.
- [**SourceGraph**](https://sourcegraph.com/search): Search in millions of repos. Regex is usually the safest option; structural search exists in some deployments, but it has performance limitations and is not always enabled.
- [**GitHub Code Search**](https://github.com/search): Supports regex, boolean logic, and qualifiers such as `repo:`, `org:`, `user:`, `path:`, `language:`, `symbol:`, `content:` and `is:`.
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/): Modern GitLab code search powered by Zoekt. Supports exact and regex modes with filters such as `file:`, `lang:`, `repo:` and `sym:`.
  - [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/) is still useful as a wider fallback because it can search code, comments, commits, merge requests, and wikis.
- [**SearchCode**](https://searchcode.com/): Search code in millions of projects.

## Useful search capabilities

When auditing an org in a bug bounty/red team context, the most useful capabilities are usually:

- **Regex** support to search for token formats, URL schemes, dangerous function names, or multiline fragments.
- **Path filters** to jump directly into high-value files such as `.github/workflows/`, `terraform/`, `helm/`, `.env`, `values.yaml`, `secrets.*`, `credentials.*`, `Dockerfile`, `Jenkinsfile`, or `nginx.conf`.
- **Language filters** to separate app code from IaC and pipelines.
- **Symbol-aware search** to enumerate handlers, auth middleware, webhook consumers, dangerous helper functions, or specific classes/methods.
- **Boolean operators** to reduce noise: `NOT path:test`, `NOT is:generated`, `NOT is:vendored`, `foo OR bar`.

## Practical methodology

1. **Start with the indexed platforms** to quickly identify repos, owners, paths, and code families.
2. **Pivot into high-signal locations** instead of searching only for generic `password`/`secret` strings.
3. **Search for attack surface, not only credentials**:
   - CI/CD workflows and deployment scripts
   - Terraform/Helm/Kubernetes manifests
   - SSO/OIDC/SAML integrations
   - Internal URLs, staging hosts, admin panels, message brokers, and callback endpoints
   - Dangerous code paths (`exec`, template rendering, SSRF fetchers, deserializers, ZIP extraction, YAML loaders, etc.)
4. **Clone and search locally** when you need non-default branches, full history, better regex support, or bulk automation.
5. **Escalate to dedicated scanners** when the goal is secrets triage or verification (for example, see the dedicated page below).

### High-signal query ideas

These are intentionally broad so you can adapt them to GitHub, GitLab, Sourcegraph, or Sourcebot syntax:

```text
org:target path:.github/workflows ("pull_request_target" OR "workflow_run" OR "ACTIONS_STEP_DEBUG")
org:target (path:terraform OR path:helm OR language:HCL OR language:YAML) ("role_arn" OR "assume_role" OR "client_secret" OR "access_key")
org:target ("BEGIN PRIVATE KEY" OR "ghp_" OR "github_pat_" OR "AIza" OR "xoxb-")
org:target (path:.env OR path:values.yaml OR path:application-prod OR path:credentials)
org:target ("internal" OR "corp" OR "staging") ("https://" OR "ssh://") NOT path:test
```

### Mass local search when indexed search is not enough

```bash
gh repo list TARGET_ORG --limit 1000 --json nameWithOwner,sshUrl \
| jq -r '.[].sshUrl' \
| while read -r repo; do
    dst="repos/$(basename "$repo" .git)"
    git clone --depth 1 "$repo" "$dst" 2>/dev/null || true
  done

rg -n --pcre2 \
  -g '!{.git,node_modules,vendor,dist,build,coverage}' \
  '(AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,255}|github_pat_[A-Za-z0-9_]{20,255}|AIza[0-9A-Za-z\-_]{35}|BEGIN (RSA|OPENSSH|EC) PRIVATE KEY)' \
  repos/
```

Use local searching when you need to:

- Search **non-default branches** or **tags**
- Search **git history**
- Run **PCRE2/multiline** queries more aggressively
- Batch triage many repositories without UI limits

## Common blind spots

- **Default-branch-only indexing** is common. Do not assume code search covers all branches/tags/history.
- **Large files, vendored code, generated code, or archives** may be skipped or noisy.
- **Comments, issues, PRs, gists, and wikis** are often outside the scope of generic code search and may require platform-specific tooling.
- **Search syntax differs per platform**. A dork that works in GitHub Code Search might need small changes for GitLab, Sourcegraph, or Sourcebot.

### Platform-specific gotchas

- **GitHub Code Search** is excellent for fast recon, but it searches the **default branch** only. If you need feature branches, deleted secrets, or historical code, clone the repo and search it locally.
- **GitLab Exact Code Search** also has a **default-branch** limitation and indexes only smaller files, but **Advanced Search** can still be useful to search comments, commits, and wikis.
- **Sourcebot** indexes the **default branch** by default, but it can be configured to index additional branches/tags and then searched with `rev:` filters, which is very convenient for branch/tag-focused internal audits when you control the index.
- **Sourcegraph** regex search is generally the most predictable option for offensive work; treat structural search as an optional bonus, not as a guaranteed capability.

> [!WARNING]
> When you look for leaks in a repo and run something like `git log -p` don't forget there might be **other branches with other commits** containing secrets!

For dedicated secret hunting, org-wide GitHub dorks, and tooling such as TruffleHog/Gitleaks, check:

{{#ref}}
github-leaked-secrets.md
{{#endref}}



## References

- [GitHub Code Search syntax](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
{{#include ../../banners/hacktricks-training.md}}
