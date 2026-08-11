# Wide Source Code Search

{{#include ../../banners/hacktricks-training.md}}

이 페이지의 목표는 **수천 개 또는 수백만 개의 repo**에서 code를 검색할 수 있는 **platform**(literal, regex, symbol-aware 또는 path-scoped 검색)을 열거하는 것입니다.

다음과 같은 경우에 유용합니다:

- **leak된 정보 검색**
- **취약한 pattern 검색**
- **technology, 내부 host, CI/CD 및 infrastructure-as-code 파악**
- **회사/org 이름에서 repo, branch 및 high-signal file로 pivot**

- [**Sourcebot**](https://www.sourcebot.dev/): repository 전체에서 regex, symbol 및 filter 기반 검색을 지원하는 open-source/self-hosted code search입니다. 추가 branch/tag를 구성하고 branch coverage가 중요한 경우 `rev:`를 사용해 query할 수 있습니다.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- [**Sourcegraph**](https://sourcegraph.com/search): regex, boolean, symbol, repository/file/language, branch/commit, diff 및 commit-message query를 지원하는 code search입니다.<sup>[[8]](#references)[[10]](#references)</sup> 현재 documentation에서는 structural search가 기본적으로 비활성화되어 있고 성능에 제한이 있다고 설명하므로 선택 사항입니다.<sup>[[9]](#references)</sup>
- [**GitHub Code Search**](https://github.com/search): regex, boolean logic 및 `repo:`, `org:`, `user:`, `path:`, `language:`, `symbol:`, `content:` 및 `is:`와 같은 qualifier를 지원합니다.<sup>[[1]](#references)</sup>
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/): Zoekt로 구동되는 code search로, exact 및 regex mode와 `file:`, `lang:`, `repo:` 및 `sym:`과 같은 filter를 지원합니다.<sup>[[2]](#references)</sup>
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/)는 code, comment, commit, merge request 및 wiki를 검색할 수 있으므로 더 광범위한 fallback입니다.<sup>[[11]](#references)</sup>
- [**SearchCode**](https://searchcode.com/): boolean/regex/structural code search와 file 및 symbol retrieval을 제공하는 code-intelligence service입니다.<sup>[[12]](#references)</sup>
- [**Grep**](https://grep.app/): 100만 개의 GitHub repository에서 content, file 및 path search를 제공하는 public code search입니다.<sup>[[13]](#references)</sup>

## 유용한 search capability

bug bounty/red team context에서 org를 audit할 때 일반적으로 가장 유용한 capability는 다음과 같습니다:

- **Regex** support: token format, URL scheme, 위험한 function name 또는 multiline fragment를 검색할 수 있습니다.
- **Path filter**: `.github/workflows/`, `terraform/`, `helm/`, `.env`, `values.yaml`, `secrets.*`, `credentials.*`, `Dockerfile`, `Jenkinsfile` 또는 `nginx.conf`와 같은 high-value file로 바로 이동할 수 있습니다.
- **Language filter**: app code를 IaC 및 pipeline과 분리할 수 있습니다.
- **Symbol-aware search**: handler, auth middleware, webhook consumer, 위험한 helper function 또는 특정 class/method를 열거할 수 있습니다.
- **Boolean operator**: noise를 줄일 수 있습니다: `NOT path:test`, `NOT is:generated`, `NOT is:vendored`, `foo OR bar`.
- **Revision/diff search**: 지원되는 경우 이를 사용하면 모든 항목을 먼저 clone하지 않고도 **삭제된 string**을 복구하고, **security-relevant change**를 추적하거나, **non-default branch/tag**를 검사할 수 있습니다.

## Practical methodology

1. **Indexed platform에서 시작**하여 repo, owner, path 및 code family를 빠르게 식별합니다.
2. 일반적인 `password`/`secret` string만 검색하지 말고 **high-signal location으로 pivot**합니다.
3. **credential뿐 아니라 attack surface를 검색**합니다:
- CI/CD workflow, reusable workflow, composite action 및 deployment script
- Dev Container / Codespaces bootstrap file 및 custom feature
- Terraform/Helm/Kubernetes manifest
- SSO/OIDC/SAML integration
- 내부 URL, staging host, admin panel, message broker 및 callback endpoint
- 위험한 code path (`exec`, template rendering, SSRF fetcher, deserializer, ZIP extraction, YAML loader 등)
4. non-default branch, full history, 향상된 regex support 또는 bulk automation이 필요한 경우 **clone한 뒤 local에서 검색**합니다.
5. 목표가 secret triage 또는 verification인 경우 **dedicated scanner로 escalate**합니다(예: 아래의 dedicated page 참조).

### High-signal query 아이디어

다음 query는 의도적으로 광범위하게 작성했으므로 GitHub, GitLab, Sourcegraph 또는 Sourcebot syntax에 맞게 조정할 수 있습니다:
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
### 우선순위를 높일 만한 최신 high-signal 파일

- **`.github/workflows/*.yml`**: 권한이 높은 `pull_request_target` 및 `workflow_run` 트리거와, 전체 commit SHA가 아닌 tag/branch에만 고정된 third-party `uses:` 라인을 검토합니다.<sup>[[3]](#references)</sup> 또한 `workflow_call`, `secrets: inherit`, `id-token: write`, `runs-on: self-hosted`를 검색합니다.
- **`.devcontainer/devcontainer.json`**, **`.devcontainer/<variant>/devcontainer.json`**, **`.devcontainer.json`**: `remoteEnv`, `containerEnv`, `initializeCommand`, `postCreateCommand`, `mounts`와 참조된 Dockerfile/script를 검색하여 environment 값, bootstrap command, mount 및 관련 파일을 확인합니다.<sup>[[4]](#references)</sup>
- **Dev Container Features** (`devcontainer-feature.json`, `install.sh`): Feature의 최소 layout에는 metadata와 `install.sh` entrypoint script가 포함되므로 두 파일을 모두 검사합니다.<sup>[[14]](#references)</sup>
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
특히 흥미로운 문자열이 **release branch**, **tag**, 또는 **deleted commit**에만 존재했던 경우에 유용합니다. Sourcegraph deployment가 이를 지원한다면 `type:diff` 및 `type:commit` 검색은 동일한 문제에 대한 훌륭한 no-clone pivot입니다.<sup>[[8]](#references)[[10]](#references)</sup>

## Common blind spots

- **Default-branch-only indexing**은 흔합니다. code search가 모든 branch/tag/history를 대상으로 한다고 가정하지 마세요.
- **Large files, vendored code, generated code, 또는 archives**는 건너뛰거나 검색 결과를 불필요하게 복잡하게 만들 수 있습니다.
- **Comments, issues, PRs, gists, 및 wikis**는 일반적인 code search의 범위 밖에 있는 경우가 많으며 platform-specific tooling이 필요할 수 있습니다.
- **Codespaces / devcontainer configs**는 branch-specific일 수 있습니다. 여러 `.devcontainer/<variant>/devcontainer.json` 경로에 존재할 수 있으므로, default branch가 깨끗하다고 해서 모든 곳의 dev environment가 깨끗한 것은 아닙니다.<sup>[[4]](#references)</sup>
- **Reusable workflows/actions 및 devcontainer features**는 명확해 보이는 파일 외부에 존재할 수 있습니다. 최상위 workflow 파일뿐만 아니라 `.github/actions/`, `action.yml`, `action.yaml`, `devcontainer-feature.json`, `install.sh`도 검색하세요.
- **Search syntax는 platform마다 다릅니다**. GitHub Code Search에서 작동하는 dork는 GitLab, Sourcegraph 또는 Sourcebot에서 약간 수정해야 할 수 있습니다.

### Platform-specific gotchas

- **GitHub Code Search**는 빠른 recon에 유용하지만 **default branch**만 검색합니다. feature branches, deleted secrets 또는 historical code가 필요하다면 repo를 clone한 후 로컬에서 검색하세요.<sup>[[15]](#references)</sup>
- **GitLab Exact Code Search**에는 **default-branch** 제한이 있으며 1 MB보다 작고 20,000개 미만의 trigram을 포함하는 파일만 index합니다.<sup>[[2]](#references)</sup> **Advanced Search**를 사용하면 comments, commits 및 wikis도 검색할 수 있습니다.<sup>[[11]](#references)</sup>
- **Sourcebot**은 기본적으로 **default branch**를 index하지만, index를 직접 관리하는 경우 추가 branch/tag를 index하도록 구성한 다음 `rev:` filter로 검색할 수 있습니다.<sup>[[7]](#references)</sup>
- **Sourcegraph**는 regex, symbol, diff 및 commit queries를 지원합니다. structural search는 활성화된 경우에만 사용하고, 문서에 명시된 performance limits를 고려하세요.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

> [!WARNING]
> repo에서 leak을 찾으며 `git log -p` 같은 명령을 실행할 때, secrets가 포함된 **다른 commits를 가진 다른 branches**가 있을 수 있다는 점을 잊지 마세요!

전용 secret hunting, org-wide GitHub dorks 및 TruffleHog/Gitleaks 같은 tooling은 [the GitHub leaked secrets page](github-leaked-secrets.md)를 확인하세요.

## References

- [1] [GitHub Code Search syntax](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [2] [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
- [3] [GitHub Actions secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [4] [Dev Container metadata reference](https://containers.dev/implementors/json_reference/)
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
- [15] [Investigation tools for security incidents](https://docs.github.com/en/enterprise-cloud%40latest/code-security/reference/security-incident-response/investigation-tools)
{{#include ../../banners/hacktricks-training.md}}
