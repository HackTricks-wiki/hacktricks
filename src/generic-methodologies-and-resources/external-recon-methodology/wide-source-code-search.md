# Wide Source Code Search

{{#include ../../banners/hacktricks-training.md}}

이 페이지의 목표는 **수천/수백만 개의 repo** 전반에서 code를 검색할 수 있게 해주는 **platform**을 열거하는 것이다. (literal, regex, symbol-aware, 또는 path-scoped)

이는 다음에 유용하다:

- **leak된 정보 검색**
- **취약한 pattern 검색**
- **technology, internal hosts, CI/CD, infrastructure-as-code 매핑**
- **company/org name에서 repo, branch, high-signal file로 pivot**

- [**Sourcebot**](https://www.sourcebot.dev/): Open-source/self-hosted code search. **many repos**를 index하고, 설정되어 있다면 `repo:`, `file:`, `lang:`, `rev:` 그리고 `sym:` 같은 regex filter를 유지한 채 추가 branch/tag까지 다룰 때 매우 유용하다.
- [**SourceGraph**](https://sourcegraph.com/search): 수백만 개의 repo를 검색한다. 보통 regex가 가장 안전한 선택이다; structural search는 일부 deployment에 존재하지만 성능 제한이 있고 항상 활성화되어 있지는 않다.
- [**GitHub Code Search**](https://github.com/search): regex, boolean logic, 그리고 `repo:`, `org:`, `user:`, `path:`, `language:`, `symbol:`, `content:`, `is:` 같은 qualifier를 지원한다.
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/): Zoekt 기반의 최신 GitLab code search. `file:`, `lang:`, `repo:`, `sym:` 같은 filter와 함께 exact 및 regex mode를 지원한다.
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/)는 code, comments, commits, merge requests, wikis까지 검색할 수 있어 더 넓은 fallback으로 여전히 유용하다.
- [**SearchCode**](https://searchcode.com/): 수백만 개의 project에서 code를 검색한다.

## Useful search capabilities

bug bounty/red team context에서 org를 감사할 때 가장 유용한 capability는 보통 다음과 같다:

- token format, URL scheme, dangerous function name, 또는 multiline fragment를 찾기 위한 **Regex** 지원.
- `.github/workflows/`, `terraform/`, `helm/`, `.env`, `values.yaml`, `secrets.*`, `credentials.*`, `Dockerfile`, `Jenkinsfile`, `nginx.conf` 같은 high-value file로 바로 들어가기 위한 **Path filter**.
- app code와 IaC, pipeline을 분리하기 위한 **Language filter**.
- handler, auth middleware, webhook consumer, dangerous helper function, 또는 특정 class/method를 열거하기 위한 **Symbol-aware search**.
- noise를 줄이기 위한 **Boolean operators**: `NOT path:test`, `NOT is:generated`, `NOT is:vendored`, `foo OR bar`.

## Practical methodology

1. **Indexed platform부터 시작**해서 repo, owner, path, code family를 빠르게 식별한다.
2. **generic `password`/`secret` 문자열만 검색하지 말고**, high-signal location으로 pivot한다.
3. **credential만이 아니라 attack surface도 검색**한다:
- CI/CD workflow와 deployment script
- Terraform/Helm/Kubernetes manifest
- SSO/OIDC/SAML integration
- Internal URL, staging host, admin panel, message broker, callback endpoint
- Dangerous code path (`exec`, template rendering, SSRF fetchers, deserializers, ZIP extraction, YAML loaders, etc.)
4. **default가 아닌 branch, full history, 더 나은 regex support, bulk automation**이 필요하면 local로 clone해서 검색한다.
5. **목표가 secret triage 또는 verification**이라면 dedicated scanner로 escalte한다 (예: 아래 dedicated page 참조).

### High-signal query ideas

이것들은 의도적으로 broad하므로 GitHub, GitLab, Sourcegraph, 또는 Sourcebot syntax에 맞게 조정할 수 있다:
```text
org:target path:.github/workflows ("pull_request_target" OR "workflow_run" OR "ACTIONS_STEP_DEBUG")
org:target (path:terraform OR path:helm OR language:HCL OR language:YAML) ("role_arn" OR "assume_role" OR "client_secret" OR "access_key")
org:target ("BEGIN PRIVATE KEY" OR "ghp_" OR "github_pat_" OR "AIza" OR "xoxb-")
org:target (path:.env OR path:values.yaml OR path:application-prod OR path:credentials)
org:target ("internal" OR "corp" OR "staging") ("https://" OR "ssh://") NOT path:test
```
### 인덱싱된 검색만으로는 충분하지 않을 때의 대규모 로컬 검색
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
