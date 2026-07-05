# Wide Source Code Search

{{#include ../../banners/hacktricks-training.md}}

Celem tej strony jest wyliczenie **platform, które pozwalają przeszukiwać code** (literalnie, regex, symbol-aware lub z zakresem path) wśród **tysięcy/milionów repozytoriów**.

Jest to przydatne do:

- **Wyszukiwania leaked information**
- **Wyszukiwania podatnych wzorców**
- **Mapowania technologii, wewnętrznych hostów, CI/CD i infrastructure-as-code**
- **Pivotowania od nazwy firmy/org do repozytoriów, branchy i plików o wysokim sygnale**

- [**Sourcebot**](https://www.sourcebot.dev/): Open-source/self-hosted code search. Bardzo przydatne, gdy chcesz zindeksować **wiele repozytoriów** i, jeśli skonfigurowane, dodatkowe branche/tagi, zachowując filtry regex takie jak `repo:`, `file:`, `lang:`, `rev:` i `sym:`.
- [**SourceGraph**](https://sourcegraph.com/search): Search in millions of repos. Regex jest zwykle najbezpieczniejszą opcją; structural search istnieje w niektórych wdrożeniach, ale ma ograniczenia wydajności i nie zawsze jest włączone.
- [**GitHub Code Search**](https://github.com/search): Supports regex, boolean logic, and qualifiers such as `repo:`, `org:`, `user:`, `path:`, `language:`, `symbol:`, `content:` and `is:`.
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/): Nowoczesny GitLab code search oparty o Zoekt. Supports exact and regex modes with filters such as `file:`, `lang:`, `repo:` and `sym:`.
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/) is still useful as a wider fallback because it can search code, comments, commits, merge requests, and wikis.
- [**SearchCode**](https://searchcode.com/): Search code in millions of projects.

## Useful search capabilities

Podczas audytu organizacji w kontekście bug bounty/red team, najbardziej przydatne możliwości to zwykle:

- **Regex** support do wyszukiwania formatów tokenów, schematów URL, niebezpiecznych nazw funkcji lub wieloliniowych fragmentów.
- **Path filters** do przechodzenia bezpośrednio do plików o wysokiej wartości, takich jak `.github/workflows/`, `terraform/`, `helm/`, `.env`, `values.yaml`, `secrets.*`, `credentials.*`, `Dockerfile`, `Jenkinsfile` lub `nginx.conf`.
- **Language filters** do oddzielenia app code od IaC i pipeline'ów.
- **Symbol-aware search** do wyliczania handlerów, auth middleware, webhook consumers, niebezpiecznych helper functions lub konkretnych classes/methods.
- **Boolean operators** do redukcji szumu: `NOT path:test`, `NOT is:generated`, `NOT is:vendored`, `foo OR bar`.

## Practical methodology

1. **Zacznij od zindeksowanych platform**, aby szybko zidentyfikować repozytoria, właścicieli, ścieżki i rodziny code.
2. **Pivotuj do miejsc o wysokim sygnale** zamiast wyszukiwać tylko ogólnych ciągów `password`/`secret`.
3. **Szukaj attack surface, a nie tylko credentials**:
- CI/CD workflows i deployment scripts
- Terraform/Helm/Kubernetes manifests
- SSO/OIDC/SAML integrations
- Internal URLs, staging hosts, admin panels, message brokers i callback endpoints
- Dangerous code paths (`exec`, template rendering, SSRF fetchers, deserializers, ZIP extraction, YAML loaders, etc.)
4. **Sklonuj i przeszukaj lokalnie**, gdy potrzebujesz branchy innych niż domyślne, pełnej historii, lepszego wsparcia regex lub automatyzacji masowej.
5. **Przejdź do dedykowanych scannerów**, gdy celem jest secrets triage lub verification (na przykład zobacz dedykowaną stronę poniżej).

### High-signal query ideas

Są one celowo szerokie, aby można je było dostosować do składni GitHub, GitLab, Sourcegraph lub Sourcebot:
```text
org:target path:.github/workflows ("pull_request_target" OR "workflow_run" OR "ACTIONS_STEP_DEBUG")
org:target (path:terraform OR path:helm OR language:HCL OR language:YAML) ("role_arn" OR "assume_role" OR "client_secret" OR "access_key")
org:target ("BEGIN PRIVATE KEY" OR "ghp_" OR "github_pat_" OR "AIza" OR "xoxb-")
org:target (path:.env OR path:values.yaml OR path:application-prod OR path:credentials)
org:target ("internal" OR "corp" OR "staging") ("https://" OR "ssh://") NOT path:test
```
### Masowe wyszukiwanie lokalne, gdy indeksowane wyszukiwanie nie wystarcza
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
