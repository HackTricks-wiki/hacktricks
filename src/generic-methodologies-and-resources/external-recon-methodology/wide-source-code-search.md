# Wide Source Code Search

{{#include ../../banners/hacktricks-training.md}}

Celem tej strony jest wyliczenie **platform umożliwiających wyszukiwanie kodu** (literalne, regex, uwzględniające symbole lub ograniczone do ścieżek) w **tysiącach/milionach repozytoriów**.

Jest to przydatne do:

- **Search for leaked information**
- **Search for vulnerable patterns**
- **Map technologies, internal hosts, CI/CD, and infrastructure-as-code**
- **Pivot from a company/org name into repos, branches, and high-signal files**

- [**Sourcebot**](https://www.sourcebot.dev/): Open-source/self-hosted code search. Bardzo przydatne, gdy chcesz zindeksować **wiele repozytoriów** oraz, po odpowiedniej konfiguracji, dodatkowe branches/tags, zachowując regex filters, takie jak `repo:`, `file:`, `lang:`, `rev:` i `sym:`.
- [**SourceGraph**](https://sourcegraph.com/search): Wyszukiwanie w milionach repozytoriów. Regex jest zazwyczaj najbezpieczniejszą opcją; structural search jest dostępne w niektórych deployments, ale ma ograniczenia wydajnościowe i nie zawsze jest włączone.
- [**GitHub Code Search**](https://github.com/search): Obsługuje regex, boolean logic oraz qualifiers, takie jak `repo:`, `org:`, `user:`, `path:`, `language:`, `symbol:`, `content:` i `is:`.
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/): Nowoczesne code search w GitLab, zasilane przez Zoekt. Obsługuje tryby exact i regex wraz z filtrami, takimi jak `file:`, `lang:`, `repo:` i `sym:`.
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/) nadal jest przydatne jako szerszy fallback, ponieważ umożliwia wyszukiwanie w kodzie, komentarzach, commitach, merge requests i wiki.
- [**SearchCode**](https://searchcode.com/): Wyszukiwanie kodu w milionach projektów.
- [**Grep**](https://grep.app/): Szybkie publiczne wyszukiwanie w bardzo dużym corpusie GitHub. Przydatne, gdy chcesz uzyskać drugi widok indeksowania/rankingu dla pivotów **content**, **file** i **path**.

## Useful search capabilities

Podczas audytowania org w kontekście bug bounty/red team najczęściej najbardziej przydatne są:

- Obsługa **Regex**, umożliwiająca wyszukiwanie formatów tokenów, schematów URL, nazw niebezpiecznych funkcji lub fragmentów wieloliniowych.
- **Path filters**, pozwalające przejść bezpośrednio do plików o wysokiej wartości, takich jak `.github/workflows/`, `terraform/`, `helm/`, `.env`, `values.yaml`, `secrets.*`, `credentials.*`, `Dockerfile`, `Jenkinsfile` lub `nginx.conf`.
- **Language filters**, umożliwiające oddzielenie kodu aplikacji od IaC i pipelines.
- **Symbol-aware search**, umożliwiające wyliczenie handlers, auth middleware, webhook consumers, niebezpiecznych helper functions lub konkretnych classes/methods.
- **Boolean operators**, ograniczające ilość szumu: `NOT path:test`, `NOT is:generated`, `NOT is:vendored`, `foo OR bar`.
- **Revision/diff search**, jeśli jest dostępne, aby odzyskać **deleted strings**, śledzić **security-relevant changes** lub analizować **non-default branches/tags** bez konieczności wcześniejszego klonowania wszystkiego.

## Practical methodology

1. **Rozpocznij od indexed platforms**, aby szybko zidentyfikować repozytoria, właścicieli, ścieżki i rodziny kodu.
2. **Wykonuj pivot do lokalizacji o wysokim poziomie sygnału**, zamiast wyszukiwać wyłącznie ogólne ciągi `password`/`secret`.
3. **Search for attack surface, not only credentials**:
- CI/CD workflows, reusable workflows, composite actions i deployment scripts
- Dev Containers / Codespaces bootstrap files i custom features
- Manifesty Terraform/Helm/Kubernetes
- Integracje SSO/OIDC/SAML
- Internal URLs, staging hosts, admin panels, message brokers i callback endpoints
- Niebezpieczne ścieżki kodu (`exec`, template rendering, SSRF fetchers, deserializers, ZIP extraction, YAML loaders itd.)
4. **Sklonuj repozytoria i wyszukuj lokalnie**, gdy potrzebujesz non-default branches, pełnej historii, lepszej obsługi regex lub bulk automation.
5. **Przejdź do dedicated scanners**, gdy celem jest secrets triage lub weryfikacja (na przykład zobacz poniższą dedykowaną stronę).

### High-signal query ideas

Są celowo szerokie, aby można je było dostosować do składni GitHub, GitLab, Sourcegraph lub Sourcebot:
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
### Nowsze pliki o wysokiej wartości sygnałowej, które warto traktować priorytetowo

- **`.github/workflows/*.yml`**: Szukaj `pull_request_target`, `workflow_run`, `workflow_call`, `secrets: inherit`, `id-token: write`, `runs-on: self-hosted` oraz linii `uses:` stron trzecich przypiętych wyłącznie do tagów/branchy zamiast pełnych commit SHA.
- **`.devcontainer/devcontainer.json`**, **`.devcontainer/<variant>/devcontainer.json`** oraz **`.devcontainer.json`**: Szukaj `remoteEnv`, `containerEnv`, `initializeCommand`, `postCreateCommand`, `mounts` oraz referencjonowanych Dockerfile i skryptów. Często ujawniają one wewnętrzne rejestry pakietów, URL-e bootstrapujące, mounty hosta i endpointy przeznaczone wyłącznie dla developerów.
- **Dev Container Features** (`devcontainer-feature.json`, `install.sh`): Doskonałe źródło logiki instalatorów specyficznej dla organizacji, wykonywanej podczas tworzenia środowiska.
- **Inne pliki CI/control-plane**: `.gitlab-ci.yml`, `azure-pipelines.yml`, `cloudbuild.yaml`, `Jenkinsfile`, `buildkite*`, `atlantis.yaml`, `terragrunt.hcl`, `helmfile.yaml`, `skaffold.yaml`, `argocd*`.

### Masowe wyszukiwanie lokalne, gdy wyszukiwanie indeksowane nie wystarcza
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
Używaj wyszukiwania lokalnego, gdy potrzebujesz:

- Przeszukiwać **non-default branches** lub **tags**
- Przeszukiwać **git history**
- Uruchamiać zapytania **PCRE2/multiline** w bardziej intensywny sposób
- Wstępnie analizować wiele repozytoriów bez ograniczeń interfejsu użytkownika

### Jawnie przeszukuj historię, branches i diffs
```bash
REPO_DIR=repos/some-repo
git -C "$REPO_DIR" fetch --all --tags --prune

git -C "$REPO_DIR" for-each-ref --format='%(refname:short)' refs/remotes/origin refs/tags \
| while read -r ref; do
git -C "$REPO_DIR" grep -nI -E 'pull_request_target|workflow_call|id-token: write|secrets: inherit|remoteEnv|containerEnv' "$ref" || true
done

git -C "$REPO_DIR" log --all -p -G 'gh[pousr]_|github_pat_|BEGIN [A-Z ]+PRIVATE KEY|internal.*https?://' -- .
```
Jest to szczególnie przydatne, gdy interesujący ciąg znaków istniał wyłącznie w **release branch**, **tag** lub **deleted commit**. Jeśli Twoje wdrożenie Sourcegraph to obsługuje, wyszukiwania `type:diff` i `type:commit` są doskonałym sposobem na rozwiązanie tego samego problemu bez klonowania repozytorium.

## Typowe ślepe punkty

- Często indeksowana jest wyłącznie **default branch**. Nie zakładaj, że code search obejmuje wszystkie branch, tagi i historię.
- **Duże pliki, kod vendored, kod generowany lub archiwa** mogą być pomijane albo generować dużo szumu.
- **Komentarze, issues, PR-y, gists i wiki** często znajdują się poza zakresem ogólnego code search i mogą wymagać narzędzi właściwych dla danej platformy.
- **Codespaces / konfiguracje devcontainer mogą być zależne od branch** i znajdować się w kilku ścieżkach `.devcontainer/<variant>/devcontainer.json`, dlatego czysty default branch nie oznacza, że środowisko deweloperskie jest wszędzie czyste.
- **Reusable workflows/actions i devcontainer features mogą znajdować się poza oczywistym plikiem**. Przeszukuj `.github/actions/`, `action.yml`, `action.yaml`, `devcontainer-feature.json` oraz `install.sh`, a nie tylko plik workflow znajdujący się w katalogu głównym.
- **Składnia wyszukiwania różni się w zależności od platformy**. Dork działający w GitHub Code Search może wymagać niewielkich zmian w GitLab, Sourcegraph lub Sourcebot.

### Pułapki związane z konkretnymi platformami

- **GitHub Code Search** doskonale sprawdza się w szybkim recon, ale przeszukuje wyłącznie **default branch**. Jeśli potrzebujesz feature branch, usuniętych sekretów lub historycznego kodu, sklonuj repozytorium i przeszukaj je lokalnie.
- **GitLab Exact Code Search** również ma ograniczenie do **default branch** i indeksuje tylko mniejsze pliki, ale **Advanced Search** nadal może być przydatne do przeszukiwania komentarzy, commitów i wiki.
- **Sourcebot** domyślnie indeksuje **default branch**, ale można go skonfigurować tak, aby indeksował dodatkowe branche/tagi, a następnie przeszukiwać je za pomocą filtrów `rev:`, co jest bardzo wygodne podczas wewnętrznych audytów skoncentrowanych na branch/tag, gdy kontrolujesz indeks.
- Wyszukiwanie regex w **Sourcegraph** jest zazwyczaj najbardziej przewidywalną opcją do zastosowań offensive; traktuj structural search jako opcjonalny bonus, a nie gwarantowaną funkcję. Jeśli wdrożenie to obsługuje, zapytania `type:diff` i `type:commit` bardzo dobrze nadają się do odzyskiwania usuniętych ciągów znaków lub niedawnych zmian istotnych z punktu widzenia security.

> [!WARNING]
> Gdy szukasz leak w repozytorium i uruchamiasz coś takiego jak `git log -p`, nie zapomnij, że mogą istnieć **inne branche z innymi commitami** zawierającymi sekrety!

Informacje na temat dedykowanego wyszukiwania sekretów, GitHub dorks obejmujących całą organizację oraz narzędzi takich jak TruffleHog/Gitleaks znajdziesz tutaj:

{{#ref}}
github-leaked-secrets.md
{{#endref}}



## Referencje

- [Składnia GitHub Code Search](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
- [Informacje dotyczące bezpiecznego używania GitHub Actions](https://docs.github.com/en/actions/reference/security/secure-use)
- [Informacje dotyczące metadanych Dev Container](https://containers.dev/implementors/json_reference/)
{{#include ../../banners/hacktricks-training.md}}
