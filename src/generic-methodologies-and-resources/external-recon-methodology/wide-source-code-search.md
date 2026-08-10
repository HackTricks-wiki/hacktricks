# Wide Source Code Search

本页面旨在列举**支持代码搜索的平台**（literal、regex、symbol-aware 或 path-scoped），可跨**数千/数百万个 repo**进行搜索。

这对于以下用途很有帮助：

- **搜索泄露的信息**
- **搜索存在漏洞的模式**
- **映射技术、内部主机、CI/CD 和 infrastructure-as-code**
- **从公司/org 名称 pivot 到 repo、branch 以及高信号文件**

- [**Sourcebot**](https://www.sourcebot.dev/)：支持 self-hosted 的开源代码搜索，可在多个 repository 中进行 regex、symbol 和过滤搜索。需要关注 branch 覆盖范围时，可配置额外的 branch/tag，并使用 `rev:` 查询它们。<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- [**Sourcegraph**](https://sourcegraph.com/search)：支持 regex、boolean、symbol、repository/file/language、branch/commit、diff 和 commit-message 查询的代码搜索工具。<sup>[[8]](#references)[[10]](#references)</sup> Structural search 是可选功能，因为当前文档说明其默认禁用且受性能限制。<sup>[[9]](#references)</sup>
- [**GitHub Code Search**](https://github.com/search)：支持 regex、boolean logic，以及 `repo:`、`org:`、`user:`、`path:`、`language:`、`symbol:`、`content:` 和 `is:` 等 qualifier。<sup>[[1]](#references)</sup>
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/)：由 Zoekt 提供支持的代码搜索，支持 exact 和 regex 模式，以及 `file:`、`lang:`、`repo:` 和 `sym:` 等 filter。<sup>[[2]](#references)</sup>
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/) 是一个覆盖范围更广的 fallback，因为它可以搜索代码、注释、commit、merge request 和 wiki。<sup>[[11]](#references)</sup>
- [**SearchCode**](https://searchcode.com/)：提供 boolean/regex/structural code search，以及 file 和 symbol retrieval 的 code-intelligence service。<sup>[[12]](#references)</sup>
- [**Grep**](https://grep.app/)：可在一百万个 GitHub repository 中进行 public code search，并支持 content、file 和 path search。<sup>[[13]](#references)</sup>

## Useful search capabilities

在 bug bounty/red team 场景中审计某个 org 时，通常最有用的功能包括：

- **Regex** 支持，用于搜索 token 格式、URL scheme、危险函数名称或多行片段。
- **Path filters**，用于直接定位 `.github/workflows/`、`terraform/`、`helm/`、`.env`、`values.yaml`、`secrets.*`、`credentials.*`、`Dockerfile`、`Jenkinsfile` 或 `nginx.conf` 等高价值文件。
- **Language filters**，用于将 app code 与 IaC 和 pipeline 分开。
- **Symbol-aware search**，用于枚举 handler、auth middleware、webhook consumer、危险 helper function 或特定 class/method。
- **Boolean operators**，用于降低噪声：`NOT path:test`、`NOT is:generated`、`NOT is:vendored`、`foo OR bar`。
- **Revision/diff search**（如果可用），这样无需先 clone 所有内容，就可以恢复**已删除的字符串**、跟踪**与安全相关的变更**，或检查**非默认 branch/tag**。

## Practical methodology

1. **从已建立索引的平台开始**，快速识别 repo、owner、path 和 code family。
2. **Pivot 到高信号位置**，而不是只搜索通用的 `password`/`secret` 字符串。
3. **搜索 attack surface，而不只是 credential**：
- CI/CD workflow、reusable workflow、composite action 和 deployment script
- Dev Containers / Codespaces bootstrap file 和 custom feature
- Terraform/Helm/Kubernetes manifest
- SSO/OIDC/SAML integration
- Internal URL、staging host、admin panel、message broker 和 callback endpoint
- 危险代码路径（`exec`、template rendering、SSRF fetcher、deserializer、ZIP extraction、YAML loader 等）
4. **需要非默认 branch、完整 history、更好的 regex 支持或批量自动化时，clone 并在本地搜索**。
5. **当目标是 secrets triage 或 verification 时，升级到专用 scanner**（例如，参见下面的专用页面）。

### High-signal query ideas

这些示例有意保持宽泛，以便你根据 GitHub、GitLab、Sourcegraph 或 Sourcebot 的 syntax 进行调整：
```text
org:target path:.github/workflows ("pull_request_target" OR "workflow_run" OR "ACTIONS_STEP_DEBUG")
org:target (path:terraform OR path:helm OR language:HCL OR language:YAML) ("role_arn" OR "assume_role" OR "client_secret" OR "access_key")
org:target ("BEGIN PRIVATE KEY" OR "ghp_" OR "github_pat_" OR "AIza" OR "xoxb-")
org:target (path:.env OR path:values.yaml OR path:application-prod OR path:credentials)
org:target path:.github/workflows ("pull_request_target" OR "workflow_run" OR "workflow_call" OR "secrets: inherit" OR "id-token: write" OR "self-hosted")
org:target path:.github/workflows ("uses:" AND NOT /@[0-9a-f]{40}/)
org:target (path:.devcontainer OR path:devcontainer.json) ("remoteEnv" OR "containerEnv" OR "initializeCommand" OR "postCreateCommand" OR "mounts")
org:target ("devcontainer-feature.json" OR "install.sh") ("curl " OR "wget " OR "docker.sock" OR "sudo ")
org:target ("internal" OR "corp" OR "staging") ("https://" OR "ssh://") NOT path:test
```
### 值得优先关注的较新高信号文件

- **`.github/workflows/*.yml`**：检查具有特权的 `pull_request_target` 和 `workflow_run` 触发器，以及仅固定到 tags/branches 而非完整 commit SHAs 的第三方 `uses:` 行。<sup>[[3]](#references)</sup> 另外搜索 `workflow_call`、`secrets: inherit`、`id-token: write` 和 `runs-on: self-hosted`。
- **`.devcontainer/devcontainer.json`**、**`.devcontainer/<variant>/devcontainer.json`** 和 **`.devcontainer.json`**：搜索 `remoteEnv`、`containerEnv`、`initializeCommand`、`postCreateCommand`、`mounts` 以及被引用的 Dockerfiles/scripts，以发现环境值、bootstrap commands、mounts 和相关文件。<sup>[[4]](#references)</sup>
- **Dev Container Features**（`devcontainer-feature.json`、`install.sh`）：检查这两个文件，因为 Feature 的最小布局包括 metadata 和一个 `install.sh` entrypoint script。<sup>[[14]](#references)</sup>
- **其他 CI/control-plane 文件**：`.gitlab-ci.yml`、`azure-pipelines.yml`、`cloudbuild.yaml`、`Jenkinsfile`、`buildkite*`、`atlantis.yaml`、`terragrunt.hcl`、`helmfile.yaml`、`skaffold.yaml`、`argocd*`。

### 索引搜索不足时进行大规模本地搜索
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
在以下情况下需要使用本地搜索：

- 搜索**非默认分支**或**标签**
- 搜索 **git history**
- 更积极地运行 **PCRE2/multiline** 查询
- 在没有 UI 限制的情况下批量筛查多个 repositories

### 显式搜索 history、分支和差异
```bash
REPO_DIR=repos/some-repo
git -C "$REPO_DIR" fetch --all --tags --prune

git -C "$REPO_DIR" for-each-ref --format='%(refname:short)' refs/remotes/origin refs/tags \
| while read -r ref; do
git -C "$REPO_DIR" grep -nI -E 'pull_request_target|workflow_call|id-token: write|secrets: inherit|remoteEnv|containerEnv' "$ref" || true
done

git -C "$REPO_DIR" log --all -p -G 'gh[pousr]_|github_pat_|BEGIN [A-Z ]+PRIVATE KEY|internal.*https?://' -- .
```
当有趣的字符串只存在于 **release branch**、**tag** 或 **deleted commit** 中时，这尤其有用。如果你的 Sourcegraph deployment 支持，`type:diff` 和 `type:commit` searches 是针对同一问题的优秀 no-clone pivot。<sup>[[8]](#references)[[10]](#references)</sup>

## 常见盲点

- **仅索引 default branch** 很常见。不要假设 code search 覆盖所有 branches/tags/history。
- **Large files、vendored code、generated code 或 archives** 可能会被跳过，或产生大量噪声。
- **Comments、issues、PRs、gists 和 wikis** 通常不在 generic code search 的范围内，可能需要特定 platform 的 tooling。
- **Codespaces / devcontainer configs 可能因 branch 而异**。它们可能存在于多个 `.devcontainer/<variant>/devcontainer.json` 路径中，因此 default branch 干净并不意味着所有地方的 dev environment 都干净。<sup>[[4]](#references)</sup>
- **Reusable workflows/actions 和 devcontainer features 可能位于不明显的文件之外**。搜索 `.github/actions/`、`action.yml`、`action.yaml`、`devcontainer-feature.json` 和 `install.sh`，不要只搜索顶层 workflow 文件。
- **不同 platform 的 search syntax 不同**。在 GitHub Code Search 中有效的 dork，可能需要针对 GitLab、Sourcegraph 或 Sourcebot 做小幅修改。

### 特定 platform 的常见问题

- **GitHub Code Search** 适合快速 recon，但它只搜索 **default branch**。如果需要 feature branches、deleted secrets 或 historical code，请 clone repo 后在本地搜索。<sup>[[15]](#references)</sup>
- **GitLab Exact Code Search** 存在 **default-branch** 限制，并且只索引小于 1 MB 且少于 20,000 个 trigrams 的文件。<sup>[[2]](#references)</sup> **Advanced Search** 仍然可以覆盖 comments、commits 和 wikis。<sup>[[11]](#references)</sup>
- **Sourcebot** 默认索引 **default branch**，但可以配置为索引其他 branches/tags，然后在你控制 index 时使用 `rev:` filters 进行搜索。<sup>[[7]](#references)</sup>
- **Sourcegraph** 支持 regex、symbol、diff 和 commit queries；仅在已启用的情况下使用 structural search，并注意其文档中说明的 performance limits。<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

> [!WARNING]
> 当你在 repo 中查找 leak 并运行类似 `git log -p` 的命令时，不要忘记可能存在包含 secrets 的 **其他 branches 和其他 commits**！

如需进行专门的 secret hunting、组织范围的 GitHub dorks，以及使用 TruffleHog/Gitleaks 等 tooling，请查看 [GitHub leaked secrets 页面](github-leaked-secrets.md)。

## References

- [1] [GitHub Code Search 语法](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [2] [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
- [3] [GitHub Actions 安全使用参考](https://docs.github.com/en/actions/reference/security/secure-use)
- [4] [Dev Container metadata 参考](https://containers.dev/implementors/json_reference/)
- [5] [Sourcebot](https://www.sourcebot.dev/)
- [6] [Sourcebot search API](https://docs.sourcebot.dev/api-reference/search-%26-navigation/search-code)
- [7] [Sourcebot multi-branch indexing](https://docs.sourcebot.dev/docs/features/search/multi-branch-indexing)
- [8] [Sourcegraph Code Search](https://sourcegraph.com/docs/code-search)
- [9] [Sourcegraph Structural Search](https://sourcegraph.com/docs/code-search/types/structural)
- [10] [Sourcegraph Search Query Syntax](https://sourcegraph.com/docs/code-search/queries)
- [11] [GitLab Advanced Search](https://docs.gitlab.com/user/search/advanced_search/)
- [12] [SearchCode](https://searchcode.com/)
- [13] [Grep.app](https://grep.app/)
- [14] [Authoring a Dev Container Feature](https://containers.dev/guide/author-a-feature)
- [15] [用于安全事件的 Investigation tools](https://docs.github.com/en/enterprise-cloud%40latest/code-security/reference/security-incident-response/investigation-tools)
{{#include ../../banners/hacktricks-training.md}}
