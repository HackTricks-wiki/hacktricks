# Wide Source Code Search

{{#include ../../banners/hacktricks-training.md}}

이 페이지의 목표는 수천~수백만 개의 repos에서 **code를 검색할 수 있는 platforms**(literal, regex, symbol-aware 또는 path-scoped)을 열거하는 것입니다.

다음과 같은 경우에 유용합니다:

- **leak된 정보 검색**
- **취약한 패턴 검색**
- **기술, internal hosts, CI/CD 및 infrastructure-as-code 매핑**
- **회사/org 이름에서 repos, branches 및 high-signal files로 pivot**

- [**Sourcebot**](https://www.sourcebot.dev/): Open-source/self-hosted code search입니다. **많은 repos**를 index하고, 설정된 경우 추가 branches/tags도 index하면서 `repo:`, `file:`, `lang:`, `rev:` 및 `sym:` 같은 regex filters를 유지하고 싶을 때 매우 유용합니다.
- [**SourceGraph**](https://sourcegraph.com/search): 수백만 개의 repos를 검색합니다. Regex가 일반적으로 가장 안전한 option입니다. 일부 deployments에는 structural search가 존재하지만, performance limitations가 있으며 항상 enabled되어 있는 것은 아닙니다.
- [**GitHub Code Search**](https://github.com/search): regex, boolean logic 및 `repo:`, `org:`, `user:`, `path:`, `language:`, `symbol:`, `content:` 및 `is:`와 같은 qualifiers를 지원합니다.
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/): Zoekt 기반의 Modern GitLab code search입니다. `file:`, `lang:`, `repo:` 및 `sym:` 같은 filters와 함께 exact 및 regex modes를 지원합니다.
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/)는 code, comments, commits, merge requests 및 wikis를 검색할 수 있으므로 더 넓은 fallback으로 여전히 유용합니다.
- [**SearchCode**](https://searchcode.com/): 수백만 개의 projects에서 code를 검색합니다.
- [**Grep**](https://grep.app/): 매우 큰 GitHub corpus 전체를 빠르게 public search할 수 있습니다. **content**, **file** 및 **path** pivots에 대해 두 번째 indexing/ranking view가 필요할 때 유용합니다.

## 유용한 search capabilities

bug bounty/red team context에서 org를 audit할 때 일반적으로 가장 유용한 capabilities는 다음과 같습니다:

- token formats, URL schemes, dangerous function names 또는 multiline fragments를 검색할 수 있는 **Regex** support.
- `.github/workflows/`, `terraform/`, `helm/`, `.env`, `values.yaml`, `secrets.*`, `credentials.*`, `Dockerfile`, `Jenkinsfile` 또는 `nginx.conf`와 같은 high-value files로 바로 이동할 수 있는 **Path filters**.
- app code를 IaC 및 pipelines와 분리할 수 있는 **Language filters**.
- handlers, auth middleware, webhook consumers, dangerous helper functions 또는 특정 classes/methods를 열거할 수 있는 **Symbol-aware search**.
- noise를 줄이기 위한 **Boolean operators**: `NOT path:test`, `NOT is:generated`, `NOT is:vendored`, `foo OR bar`.
- 가능한 경우 **Revision/diff search**를 사용하면 모든 것을 먼저 cloning하지 않고도 **deleted strings**를 복구하고, **security-relevant changes**를 추적하거나, **non-default branches/tags**를 검사할 수 있습니다.

## Practical methodology

1. **Indexed platforms**에서 시작하여 repos, owners, paths 및 code families를 빠르게 식별합니다.
2. 일반적인 `password`/`secret` strings만 검색하지 말고 **high-signal locations**로 pivot합니다.
3. **credentials뿐만 아니라 attack surface를 검색합니다**:
- CI/CD workflows, reusable workflows, composite actions 및 deployment scripts
- Dev Containers / Codespaces bootstrap files 및 custom features
- Terraform/Helm/Kubernetes manifests
- SSO/OIDC/SAML integrations
- Internal URLs, staging hosts, admin panels, message brokers 및 callback endpoints
- Dangerous code paths (`exec`, template rendering, SSRF fetchers, deserializers, ZIP extraction, YAML loaders 등)
4. non-default branches, full history, 더 나은 regex support 또는 bulk automation이 필요할 때 **clone한 후 local에서 검색합니다**.
5. 목표가 secrets triage 또는 verification인 경우 **dedicated scanners**로 escalation합니다(예를 들어 아래의 dedicated page 참조).

### High-signal query ideas

다음 query들은 의도적으로 broad하게 작성되었으므로 GitHub, GitLab, Sourcegraph 또는 Sourcebot syntax에 맞게 적용할 수 있습니다:
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
### 우선순위를 높일 가치가 있는 최신 high-signal 파일

- **`.github/workflows/*.yml`**: `pull_request_target`, `workflow_run`, `workflow_call`, `secrets: inherit`, `id-token: write`, `runs-on: self-hosted`, 그리고 전체 commit SHA가 아닌 tag/branch에만 고정된 third-party `uses:` 라인을 찾습니다.
- **`.devcontainer/devcontainer.json`**, **`.devcontainer/<variant>/devcontainer.json`**, **`.devcontainer.json`**: `remoteEnv`, `containerEnv`, `initializeCommand`, `postCreateCommand`, `mounts` 및 참조된 Dockerfile/script를 검색합니다. 이러한 파일에서는 내부 package registry, bootstrap URL, host mount 및 developer-only endpoint가 노출되는 경우가 많습니다.
- **Dev Container Features** (`devcontainer-feature.json`, `install.sh`): environment 생성 중 실행되는 조직별 installer logic을 찾는 데 유용합니다.
- **기타 CI/control-plane 파일**: `.gitlab-ci.yml`, `azure-pipelines.yml`, `cloudbuild.yaml`, `Jenkinsfile`, `buildkite*`, `atlantis.yaml`, `terragrunt.hcl`, `helmfile.yaml`, `skaffold.yaml`, `argocd*`.

### 인덱싱된 검색만으로 충분하지 않을 때의 대규모 로컬 검색
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
다음과 같은 경우 로컬 검색을 사용하세요:

- **non-default branches** 또는 **tags** 검색
- **git history** 검색
- **PCRE2/multiline** 쿼리를 더 적극적으로 실행
- UI 제한 없이 여러 repositories를 일괄 triage

### history, branches, diffs를 명시적으로 검색
```bash
REPO_DIR=repos/some-repo
git -C "$REPO_DIR" fetch --all --tags --prune

git -C "$REPO_DIR" for-each-ref --format='%(refname:short)' refs/remotes/origin refs/tags \
| while read -r ref; do
git -C "$REPO_DIR" grep -nI -E 'pull_request_target|workflow_call|id-token: write|secrets: inherit|remoteEnv|containerEnv' "$ref" || true
done

git -C "$REPO_DIR" log --all -p -G 'gh[pousr]_|github_pat_|BEGIN [A-Z ]+PRIVATE KEY|internal.*https?://' -- .
```
이는 흥미로운 문자열이 **release branch**, **tag**, 또는 **deleted commit**에만 존재했던 경우 특히 유용합니다. Sourcegraph deployment가 이를 지원한다면 `type:diff` 및 `type:commit` search는 동일한 문제에 대해 clone 없이 전환할 수 있는 훌륭한 방법입니다.

## 일반적인 사각지대

- **Default branch만 indexing**하는 경우가 많습니다. Code search가 모든 branch/tag/history를 포함한다고 가정하지 마세요.
- **Large file, vendored code, generated code, 또는 archive**는 제외되거나 노이즈가 많을 수 있습니다.
- **Comment, issue, PR, gist, wiki**는 일반적인 code search 범위 밖에 있는 경우가 많으며, platform별 tooling이 필요할 수 있습니다.
- **Codespaces / devcontainer config**는 branch별로 다를 수 있으며 여러 `.devcontainer/<variant>/devcontainer.json` path에 존재할 수 있습니다. 따라서 깨끗한 default branch가 모든 환경에서 깨끗하다는 의미는 아닙니다.
- **Reusable workflow/action 및 devcontainer feature**는 명확해 보이는 file 외부에 존재할 수 있습니다. 최상위 workflow file만 검색하지 말고 `.github/actions/`, `action.yml`, `action.yaml`, `devcontainer-feature.json`, `install.sh`도 검색하세요.
- **Search syntax는 platform마다 다릅니다.** GitHub Code Search에서 작동하는 dork는 GitLab, Sourcegraph 또는 Sourcebot에서 사용하려면 약간 수정해야 할 수 있습니다.

### Platform별 주의 사항

- **GitHub Code Search**는 빠른 recon에 매우 유용하지만 **default branch**만 검색합니다. Feature branch, 삭제된 secret 또는 historical code가 필요하다면 repo를 clone한 후 local에서 검색하세요.
- **GitLab Exact Code Search**에도 **default branch** 제한이 있으며 작은 file만 indexing하지만, **Advanced Search**는 comment, commit, wiki를 검색하는 데 여전히 유용할 수 있습니다.
- **Sourcebot**은 기본적으로 **default branch**를 indexing하지만, 추가 branch/tag를 indexing하도록 설정한 뒤 `rev:` filter로 검색할 수 있습니다. Index를 직접 관리하는 경우 branch/tag 중심의 internal audit에 매우 편리합니다.
- **Sourcegraph**의 regex search는 일반적으로 offensive work에서 가장 예측 가능하며, structural search는 보장된 기능이 아닌 선택적인 보너스로 간주하세요. deployment가 지원한다면 `type:diff` 및 `type:commit` query는 삭제된 문자열이나 최근의 security 관련 변경 사항을 복구하는 데 매우 유용합니다.

> [!WARNING]
> Repo에서 leak을 찾으며 `git log -p`와 같은 명령을 실행할 때는 secret이 포함된 **다른 commit이 있는 다른 branch**가 존재할 수 있다는 점을 잊지 마세요!

전용 secret hunting, org-wide GitHub dork 및 TruffleHog/Gitleaks와 같은 tooling은 다음을 확인하세요.

{{#ref}}
github-leaked-secrets.md
{{#endref}}



## References

- [GitHub Code Search syntax](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
- [GitHub Actions secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [Dev Container metadata reference](https://containers.dev/implementors/json_reference/)
{{#include ../../banners/hacktricks-training.md}}
