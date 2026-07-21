# Wide Source Code Search

{{#include ../../banners/hacktricks-training.md}}

本页面旨在列举**允许你搜索代码的平台**（literal、regex、symbol-aware 或 path-scoped），其范围覆盖**数千甚至数百万个 repos**。

这对于以下用途很有帮助：

- **搜索 leak 信息**
- **搜索存在漏洞的模式**
- **映射技术、内部主机、CI/CD 以及 infrastructure-as-code**
- **从公司/org 名称 pivot 到 repos、branches 和高信号文件**

- [**Sourcebot**](https://www.sourcebot.dev/)：开源/self-hosted code search。当你希望索引**大量 repos**，并在配置后索引额外的 branches/tags，同时保留 `repo:`、`file:`、`lang:`、`rev:` 和 `sym:` 等 regex filters 时，非常有用。
- [**SourceGraph**](https://sourcegraph.com/search)：在数百万个 repos 中进行搜索。Regex 通常是最安全的选项；部分 deployments 中存在 structural search，但它有性能限制，并不总是启用。
- [**GitHub Code Search**](https://github.com/search)：支持 regex、boolean logic，以及 `repo:`、`org:`、`user:`、`path:`、`language:`、`symbol:`、`content:` 和 `is:` 等 qualifiers。
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/)：由 Zoekt 提供支持的现代 GitLab code search。支持 exact 和 regex modes，并提供 `file:`、`lang:`、`repo:` 和 `sym:` 等 filters。
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/) 仍可作为更广泛的 fallback，因为它能够搜索 code、comments、commits、merge requests 和 wikis。
- [**SearchCode**](https://searchcode.com/)：在数百万个 projects 中搜索 code。
- [**Grep**](https://grep.app/)：在非常庞大的 GitHub corpus 中进行快速 public search。当你希望针对 **content**、**file** 和 **path** pivots 获取第二种 indexing/ranking 视图时非常有用。

## Useful search capabilities

在 bug bounty/red team 场景中审计某个 org 时，通常最有用的 capabilities 包括：

- **Regex** 支持，用于搜索 token formats、URL schemes、危险 function names 或 multiline fragments。
- **Path filters**，用于直接定位 `.github/workflows/`、`terraform/`、`helm/`、`.env`、`values.yaml`、`secrets.*`、`credentials.*`、`Dockerfile`、`Jenkinsfile` 或 `nginx.conf` 等高价值文件。
- **Language filters**，用于区分 app code、IaC 和 pipelines。
- **Symbol-aware search**，用于枚举 handlers、auth middleware、webhook consumers、危险 helper functions 或特定 classes/methods。
- **Boolean operators**，用于减少噪声：`NOT path:test`、`NOT is:generated`、`NOT is:vendored`、`foo OR bar`。
- **Revision/diff search**（如果可用），这样你可以恢复**已删除的 strings**、跟踪**与 security 相关的 changes**，或检查**非默认 branches/tags**，而无需先 clone 全部内容。

## Practical methodology

1. **从已索引的平台开始**，快速识别 repos、owners、paths 和 code families。
2. **Pivot 到高信号位置**，不要只搜索通用的 `password`/`secret` strings。
3. **搜索 attack surface，而不仅是 credentials**：
- CI/CD workflows、reusable workflows、composite actions 和 deployment scripts
- Dev Containers / Codespaces bootstrap files 和 custom features
- Terraform/Helm/Kubernetes manifests
- SSO/OIDC/SAML integrations
- Internal URLs、staging hosts、admin panels、message brokers 和 callback endpoints
- Dangerous code paths（`exec`、template rendering、SSRF fetchers、deserializers、ZIP extraction、YAML loaders 等）
4. **在本地 clone 并搜索**，当你需要 non-default branches、完整 history、更好的 regex 支持或 bulk automation 时。
5. **在目标是 secrets triage 或 verification 时升级到 dedicated scanners**（例如，参见下面的 dedicated page）。

### High-signal query ideas

以下内容有意保持宽泛，以便你根据 GitHub、GitLab、Sourcegraph 或 Sourcebot 的 syntax 进行调整：
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
### 值得优先关注的新高信号文件

- **`.github/workflows/*.yml`**：查找 `pull_request_target`、`workflow_run`、`workflow_call`、`secrets: inherit`、`id-token: write`、`runs-on: self-hosted`，以及仅固定到 tags/branches 而非完整 commit SHAs 的第三方 `uses:` 行。
- **`.devcontainer/devcontainer.json`**、**`.devcontainer/<variant>/devcontainer.json`** 和 **`.devcontainer.json`**：搜索 `remoteEnv`、`containerEnv`、`initializeCommand`、`postCreateCommand`、`mounts`，以及被引用的 Dockerfiles/scripts。这些文件经常暴露内部 package registries、bootstrap URLs、host mounts 和仅供开发者使用的 endpoints。
- **Dev Container Features**（`devcontainer-feature.json`、`install.sh`）：非常适合查找在环境创建期间执行的组织专用 installer logic。
- **其他 CI/control-plane 文件**：`.gitlab-ci.yml`、`azure-pipelines.yml`、`cloudbuild.yaml`、`Jenkinsfile`、`buildkite*`、`atlantis.yaml`、`terragrunt.hcl`、`helmfile.yaml`、`skaffold.yaml`、`argocd*`。

### 当 indexed search 不够用时进行大规模本地搜索
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
需要进行以下操作时，使用本地搜索：

- 搜索**非默认分支**或 **tags**
- 搜索 **git history**
- 更积极地运行 **PCRE2/multiline** 查询
- 在没有 UI 限制的情况下，对大量 repositories 进行批量初筛

### 明确搜索 history、分支和 diff
```bash
REPO_DIR=repos/some-repo
git -C "$REPO_DIR" fetch --all --tags --prune

git -C "$REPO_DIR" for-each-ref --format='%(refname:short)' refs/remotes/origin refs/tags \
| while read -r ref; do
git -C "$REPO_DIR" grep -nI -E 'pull_request_target|workflow_call|id-token: write|secrets: inherit|remoteEnv|containerEnv' "$ref" || true
done

git -C "$REPO_DIR" log --all -p -G 'gh[pousr]_|github_pat_|BEGIN [A-Z ]+PRIVATE KEY|internal.*https?://' -- .
```
当有趣的字符串只存在于 **release branch**、**tag** 或 **deleted commit** 中时，这尤其有用。如果你的 Sourcegraph deployment 支持此功能，`type:diff` 和 `type:commit` 搜索是针对同一问题的优秀 no-clone pivot。

## 常见盲点

- **仅索引默认分支** 很常见。不要假设 code search 覆盖所有 branches/tags/history。
- **大型文件、vendored code、generated code 或 archives** 可能会被跳过，或产生大量噪声。
- **Comments、issues、PRs、gists 和 wikis** 通常不在 generic code search 的范围内，可能需要使用特定于平台的 tooling。
- **Codespaces / devcontainer configs 可能特定于某个 branch**，并且可能存在于多个 `.devcontainer/<variant>/devcontainer.json` 路径中，因此 default branch 干净并不意味着所有地方的 dev environment 都干净。
- **Reusable workflows/actions 和 devcontainer features 可能位于不明显的文件中**。搜索 `.github/actions/`、`action.yml`、`action.yaml`、`devcontainer-feature.json` 和 `install.sh`，不要只搜索顶层 workflow 文件。
- **不同平台的 search syntax 不同**。在 GitHub Code Search 中有效的 dork，可能需要针对 GitLab、Sourcegraph 或 Sourcebot 做小幅修改。

### 特定平台的注意事项

- **GitHub Code Search** 非常适合快速 recon，但它只搜索 **default branch**。如果需要搜索 feature branches、deleted secrets 或 historical code，请 clone repo 后在本地搜索。
- **GitLab Exact Code Search** 同样存在 **default-branch** 限制，并且只索引较小的文件，但 **Advanced Search** 仍可用于搜索 comments、commits 和 wikis。
- **Sourcebot** 默认索引 **default branch**，但可以配置为索引其他 branches/tags，然后使用 `rev:` filters 进行搜索。当你控制 index 时，这对于以 branch/tag 为重点的内部审计非常方便。
- **Sourcegraph** 的 regex search 通常是 offensive work 中最可预测的选项；应将 structural search 视为可选 bonus，而不是保证可用的能力。如果 deployment 支持，`type:diff` 和 `type:commit` queries 非常适合恢复 deleted strings 或近期与 security 相关的 changes。

> [!WARNING]
> 当你在 repo 中寻找 leaks 并运行类似 `git log -p` 的命令时，不要忘记可能存在包含 secrets 的 **其他 branches 和其他 commits**！

如需进行专门的 secret hunting、org-wide GitHub dorks，以及使用 TruffleHog/Gitleaks 等 tooling，请查看：

{{#ref}}
github-leaked-secrets.md
{{#endref}}



## References

- [GitHub Code Search syntax](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
- [GitHub Actions secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [Dev Container metadata reference](https://containers.dev/implementors/json_reference/)
{{#include ../../banners/hacktricks-training.md}}
