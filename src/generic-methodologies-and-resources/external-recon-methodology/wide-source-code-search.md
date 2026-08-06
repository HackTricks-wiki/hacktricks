# 광범위한 Source Code Search

{{#include ../../banners/hacktricks-training.md}}

이 페이지의 목표는 **수천 개 또는 수백만 개의 repo에서 code를 검색**할 수 있는 **플랫폼**(literal, regex, symbol-aware 또는 path-scoped)을 열거하는 것입니다.

다음과 같은 경우에 유용합니다:

- **leak된 정보 검색**
- **취약한 패턴 검색**
- **기술, 내부 호스트, CI/CD 및 infrastructure-as-code 파악**
- **회사/org 이름에서 repo, branch 및 high-signal file로 pivot**

- [**Sourcebot**](https://www.sourcebot.dev/): Open-source/self-hosted code search입니다. **많은 repo**를 index하고, 설정에 따라 추가 branch/tag도 index하면서 `repo:`, `file:`, `lang:`, `rev:` 및 `sym:`과 같은 regex filter를 유지하고 싶을 때 매우 유용합니다.
- [**SourceGraph**](https://sourcegraph.com/search): 수백만 개의 repo를 검색합니다. 일반적으로 regex가 가장 안전한 옵션입니다. 일부 deployment에서는 structural search도 지원하지만 성능 제한이 있으며 항상 활성화되어 있는 것은 아닙니다.
- [**GitHub Code Search**](https://github.com/search): regex, boolean logic 및 `repo:`, `org:`, `user:`, `path:`, `language:`, `symbol:`, `content:` 및 `is:`와 같은 qualifier를 지원합니다.<sup>[[1]](#references)</sup>
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/): Zoekt 기반의 Modern GitLab code search입니다. `file:`, `lang:`, `repo:` 및 `sym:`과 같은 filter를 사용하여 exact 및 regex mode를 지원합니다.<sup>[[2]](#references)</sup>
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/)는 code, comment, commit, merge request 및 wiki를 검색할 수 있으므로 더 넓은 fallback으로 여전히 유용합니다.
- [**SearchCode**](https://searchcode.com/): 수백만 개의 project에서 code를 검색합니다.
- [**Grep**](https://grep.app/): 매우 큰 GitHub corpus 전체에서 빠른 public search를 제공합니다. **content**, **file** 및 **path** pivot에 대해 두 번째 indexing/ranking 관점이 필요할 때 유용합니다.

## 유용한 검색 기능

bug bounty/red team context에서 org를 audit할 때 일반적으로 가장 유용한 기능은 다음과 같습니다:

- **Regex** 지원: token format, URL scheme, 위험한 function name 또는 multiline fragment를 검색할 수 있습니다.
- **Path filter**: `.github/workflows/`, `terraform/`, `helm/`, `.env`, `values.yaml`, `secrets.*`, `credentials.*`, `Dockerfile`, `Jenkinsfile` 또는 `nginx.conf`와 같은 high-value file로 바로 이동할 수 있습니다.
- **Language filter**: app code를 IaC 및 pipeline과 구분할 수 있습니다.
- **Symbol-aware search**: handler, auth middleware, webhook consumer, 위험한 helper function 또는 특정 class/method를 열거할 수 있습니다.
- **Boolean operator**: noise를 줄일 수 있습니다: `NOT path:test`, `NOT is:generated`, `NOT is:vendored`, `foo OR bar`.
- **Revision/diff search**: 지원되는 경우 **삭제된 string을 복구**하고, **security-relevant change를 추적**하거나, 모든 항목을 먼저 clone하지 않고 **non-default branch/tag를 검사**할 수 있습니다.

## 실전 methodology

1. **Index된 platform에서 시작**하여 repo, owner, path 및 code family를 빠르게 식별합니다.
2. 일반적인 `password`/`secret` string만 검색하지 말고 **high-signal location으로 pivot**합니다.
3. **credential뿐만 아니라 attack surface를 검색**합니다:
- CI/CD workflow, reusable workflow, composite action 및 deployment script
- Dev Containers / Codespaces bootstrap file 및 custom feature
- Terraform/Helm/Kubernetes manifest
- SSO/OIDC/SAML integration
- 내부 URL, staging host, admin panel, message broker 및 callback endpoint
- 위험한 code path (`exec`, template rendering, SSRF fetcher, deserializer, ZIP extraction, YAML loader 등)
4. non-default branch, 전체 history, 향상된 regex 지원 또는 bulk automation이 필요할 때는 **local에서 clone하고 검색**합니다.
5. 목표가 secrets triage 또는 verification인 경우 **전용 scanner로 확장**합니다(예를 들어 아래의 전용 페이지를 참조).

### High-signal query 아이디어

다음 항목은 의도적으로 광범위하게 작성되었으므로 GitHub, GitLab, Sourcegraph 또는 Sourcebot syntax에 맞게 조정할 수 있습니다:
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
### 우선순위를 둘 가치가 있는 최신 high-signal 파일

- **`.github/workflows/*.yml`**: `pull_request_target`, `workflow_run`, `workflow_call`, `secrets: inherit`, `id-token: write`, `runs-on: self-hosted`, 그리고 전체 commit SHA가 아닌 tag/branch에만 pin된 third-party `uses:` 라인을 찾습니다.<sup>[[3]](#references)</sup>
- **`.devcontainer/devcontainer.json`**, **`.devcontainer/<variant>/devcontainer.json`**, **`.devcontainer.json`**: `remoteEnv`, `containerEnv`, `initializeCommand`, `postCreateCommand`, `mounts`, 그리고 참조된 Dockerfile/script를 검색합니다. 이러한 파일은 내부 package registry, bootstrap URL, host mount, developer 전용 endpoint를 노출하는 경우가 많습니다.<sup>[[4]](#references)</sup>
- **Dev Container Features** (`devcontainer-feature.json`, `install.sh`): environment 생성 중 실행되는 조직별 installer logic을 찾는 데 유용합니다.
- **기타 CI/control-plane 파일**: `.gitlab-ci.yml`, `azure-pipelines.yml`, `cloudbuild.yaml`, `Jenkinsfile`, `buildkite*`, `atlantis.yaml`, `terragrunt.hcl`, `helmfile.yaml`, `skaffold.yaml`, `argocd*`.

### indexed search만으로 충분하지 않을 때의 대규모 local search
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
필요한 경우 로컬 검색을 사용하세요:

- **non-default branches** 또는 **tags** 검색
- **git history** 검색
- **PCRE2/multiline** 쿼리를 더 적극적으로 실행
- UI 제한 없이 여러 repository를 일괄 triage

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
이는 관심 있는 문자열이 **release branch**, **tag**, 또는 **deleted commit**에만 존재했던 경우 특히 유용합니다. Sourcegraph deployment가 이를 지원한다면, `type:diff` 및 `type:commit` 검색은 같은 문제에 대해 clone 없이 수행할 수 있는 훌륭한 pivot입니다.

## 일반적인 사각지대

- **Default-branch-only indexing**은 흔합니다. Code Search가 모든 branch/tag/history를 포함한다고 가정하지 마세요.
- **Large files, vendored code, generated code, 또는 archives**는 건너뛰어지거나 noise가 많을 수 있습니다.
- **Comments, issues, PRs, gists, 및 wikis**는 일반적인 code search 범위에 포함되지 않는 경우가 많으며, platform-specific tooling이 필요할 수 있습니다.
- **Codespaces / devcontainer configs**는 branch-specific일 수 있으며 여러 `.devcontainer/<variant>/devcontainer.json` 경로에 존재할 수 있습니다. 따라서 깨끗한 default branch가 모든 위치의 dev environment도 깨끗하다는 의미는 아닙니다.
- **Reusable workflows/actions 및 devcontainer features**는 명확해 보이는 파일 외부에 있을 수 있습니다. 최상위 workflow 파일만 검색하지 말고 `.github/actions/`, `action.yml`, `action.yaml`, `devcontainer-feature.json`, `install.sh`도 검색하세요.
- **Search syntax는 platform마다 다릅니다**. GitHub Code Search에서 작동하는 dork도 GitLab, Sourcegraph 또는 Sourcebot에서는 약간 수정해야 할 수 있습니다.

### Platform-specific gotchas

- **GitHub Code Search**는 빠른 recon에 매우 유용하지만 **default branch**만 검색합니다. feature branches, deleted secrets 또는 historical code가 필요하다면 repo를 clone한 후 로컬에서 검색하세요.
- **GitLab Exact Code Search**에도 **default-branch** 제한이 있으며 더 작은 파일만 index하지만, **Advanced Search**를 사용하면 comments, commits 및 wikis를 검색하는 데 여전히 유용할 수 있습니다.<sup>[[2]](#references)</sup>
- **Sourcebot**은 기본적으로 **default branch**를 index하지만, 추가 branch/tag를 index하도록 설정한 뒤 `rev:` filters로 검색할 수 있습니다. index를 직접 제어하는 경우 branch/tag 중심의 internal audits에 매우 편리합니다.
- **Sourcegraph**의 regex search는 일반적으로 offensive work에서 가장 예측 가능한 옵션입니다. structural search는 보장된 capability가 아니라 optional bonus로 취급하세요. deployment가 지원한다면 `type:diff` 및 `type:commit` queries는 deleted strings 또는 최근의 security-relevant changes를 복구하는 데 매우 유용합니다.

> [!WARNING]
> repo에서 leaks를 찾기 위해 `git log -p` 같은 명령을 실행할 때, secrets를 포함한 **다른 commits가 있는 다른 branches**가 존재할 수 있다는 점을 잊지 마세요!

Dedicated secret hunting, org-wide GitHub dorks, 그리고 TruffleHog/Gitleaks 같은 tooling은 다음을 확인하세요.

{{#ref}}
github-leaked-secrets.md
{{#endref}}

## References

- [1] [GitHub Code Search syntax](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [2] [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
- [3] [GitHub Actions secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [4] [Dev Container metadata reference](https://containers.dev/implementors/json_reference/)

{{#include ../../banners/hacktricks-training.md}}
