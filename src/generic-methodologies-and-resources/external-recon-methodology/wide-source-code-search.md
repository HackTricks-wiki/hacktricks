# Wide Source Code Search

{{#include ../../banners/hacktricks-training.md}}

本页的目标是枚举**允许你搜索代码**（literal、regex、symbol-aware，或 path-scoped）的**平台**，覆盖**成千上万/数百万个 repos**。

这对以下用途很有帮助：

- **Search for leaked information**
- **Search for vulnerable patterns**
- **Map technologies, internal hosts, CI/CD, and infrastructure-as-code**
- **Pivot from a company/org name into repos, branches, and high-signal files**

- [**Sourcebot**](https://www.sourcebot.dev/): 开源/self-hosted code search。当你想索引**很多 repos**，并且在配置后索引额外的 branches/tags，同时保留 `repo:`、`file:`、`lang:`、`rev:` 和 `sym:` 这类 regex filters 时，它非常有用。
- [**SourceGraph**](https://sourcegraph.com/search): 在数百万个 repos 中搜索。regex 通常是最安全的选项；某些部署中支持 structural search，但它有性能限制，而且并不总是启用。
- [**GitHub Code Search**](https://github.com/search): 支持 regex、boolean logic，以及 `repo:`、`org:`、`user:`、`path:`、`language:`、`symbol:`、`content:` 和 `is:` 等 qualifiers。
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/): 由 Zoekt 驱动的现代 GitLab code search。支持 exact 和 regex 模式，并带有 `file:`、`lang:`、`repo:` 和 `sym:` 等 filters。
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/) 仍然很有用，作为更广泛的 fallback，因为它可以搜索 code、comments、commits、merge requests 和 wikis。
- [**SearchCode**](https://searchcode.com/): 在数百万个 projects 中搜索 code。

## Useful search capabilities

在 bug bounty/red team 场景中审计一个 org 时，最有用的能力通常是：

- **Regex** 支持，用于搜索 token formats、URL schemes、危险函数名，或 multiline fragments。
- **Path filters**，可直接跳到高价值文件，如 `.github/workflows/`、`terraform/`、`helm/`、`.env`、`values.yaml`、`secrets.*`、`credentials.*`、`Dockerfile`、`Jenkinsfile` 或 `nginx.conf`。
- **Language filters**，用于区分 app code、IaC 和 pipelines。
- **Symbol-aware search**，用于枚举 handlers、auth middleware、webhook consumers、危险 helper functions，或特定 classes/methods。
- **Boolean operators**，用于减少噪音：`NOT path:test`、`NOT is:generated`、`NOT is:vendored`、`foo OR bar`。

## Practical methodology

1. **Start with the indexed platforms** to quickly identify repos、owners、paths 和 code families。
2. **Pivot into high-signal locations**，而不是只搜索通用的 `password`/`secret` 字符串。
3. **Search for attack surface, not only credentials**:
- CI/CD workflows 和 deployment scripts
- Terraform/Helm/Kubernetes manifests
- SSO/OIDC/SAML integrations
- Internal URLs、staging hosts、admin panels、message brokers 和 callback endpoints
- Dangerous code paths (`exec`、template rendering、SSRF fetchers、deserializers、ZIP extraction、YAML loaders, etc.)
4. **Clone and search locally**，当你需要非默认 branches、完整 history、更好的 regex support，或批量自动化时。
5. **Escalate to dedicated scanners**，当目标是 secrets triage 或 verification 时（例如，见下面的 dedicated page）。

### High-signal query ideas

These are intentionally broad so you can adapt them to GitHub, GitLab, Sourcegraph, or Sourcebot syntax:
```text
org:target path:.github/workflows ("pull_request_target" OR "workflow_run" OR "ACTIONS_STEP_DEBUG")
org:target (path:terraform OR path:helm OR language:HCL OR language:YAML) ("role_arn" OR "assume_role" OR "client_secret" OR "access_key")
org:target ("BEGIN PRIVATE KEY" OR "ghp_" OR "github_pat_" OR "AIza" OR "xoxb-")
org:target (path:.env OR path:values.yaml OR path:application-prod OR path:credentials)
org:target ("internal" OR "corp" OR "staging") ("https://" OR "ssh://") NOT path:test
```
### 当索引搜索不够用时进行大规模本地搜索
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
> 当你在一个 repo 里查找 leak 并运行类似 `git log -p` 的命令时，不要忘了可能还有**其他分支的其他提交**包含 secrets！

For dedicated secret hunting, org-wide GitHub dorks, and tooling such as TruffleHog/Gitleaks, check:

{{#ref}}
github-leaked-secrets.md
{{#endref}}



## References

- [GitHub Code Search syntax](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
{{#include ../../banners/hacktricks-training.md}}
