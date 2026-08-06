# Szerokie wyszukiwanie kodu źródłowego

{{#include ../../banners/hacktricks-training.md}}

Celem tej strony jest wymienienie **platform umożliwiających wyszukiwanie kodu** (literalne, regex, uwzględniające symbole lub ograniczone do ścieżek) w **tysiącach/milionach repozytoriów**.

Jest to przydatne do:

- **Wyszukiwania wyciekłych informacji**
- **Wyszukiwania podatnych wzorców**
- **Mapowania technologii, wewnętrznych hostów, CI/CD i infrastruktury jako kodu**
- **Przejścia od nazwy firmy/organizacji do repozytoriów, branchy i plików o wysokiej wartości rozpoznawczej**

- [**Sourcebot**](https://www.sourcebot.dev/): Open-source/self-hosted code search. Bardzo przydatne, gdy chcesz zindeksować **wiele repozytoriów** oraz, po odpowiedniej konfiguracji, dodatkowe branche/tagi, zachowując filtry regex, takie jak `repo:`, `file:`, `lang:`, `rev:` i `sym:`.
- [**SourceGraph**](https://sourcegraph.com/search): Wyszukiwanie w milionach repozytoriów. Regex jest zazwyczaj najbezpieczniejszą opcją; structural search jest dostępne w niektórych wdrożeniach, ale ma ograniczenia wydajnościowe i nie zawsze jest włączone.
- [**GitHub Code Search**](https://github.com/search): Obsługuje regex, logikę Boolean oraz kwalifikatory, takie jak `repo:`, `org:`, `user:`, `path:`, `language:`, `symbol:`, `content:` i `is:`.<sup>[[1]](#references)</sup>
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/): Nowoczesne wyszukiwanie kodu GitLab oparte na Zoekt. Obsługuje tryby exact i regex wraz z filtrami, takimi jak `file:`, `lang:`, `repo:` i `sym:`.<sup>[[2]](#references)</sup>
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/) nadal jest przydatne jako szerszy fallback, ponieważ umożliwia wyszukiwanie w kodzie, komentarzach, commitach, merge requestach i wiki.
- [**SearchCode**](https://searchcode.com/): Wyszukiwanie kodu w milionach projektów.
- [**Grep**](https://grep.app/): Szybkie publiczne wyszukiwanie w bardzo dużym korpusie GitHub. Przydatne, gdy chcesz uzyskać drugi widok indeksowania/rankingu dla pivotów **content**, **file** i **path**.

## Przydatne możliwości wyszukiwania

Podczas audytowania organizacji w kontekście bug bounty/red team najczęściej najbardziej przydatne są:

- Obsługa **regex**, umożliwiająca wyszukiwanie formatów tokenów, schematów URL, nazw niebezpiecznych funkcji lub fragmentów wieloliniowych.
- **Filtry ścieżek**, pozwalające przejść bezpośrednio do plików o wysokiej wartości, takich jak `.github/workflows/`, `terraform/`, `helm/`, `.env`, `values.yaml`, `secrets.*`, `credentials.*`, `Dockerfile`, `Jenkinsfile` lub `nginx.conf`.
- **Filtry języków**, pozwalające oddzielić kod aplikacji od IaC i pipeline'ów.
- **Wyszukiwanie uwzględniające symbole**, służące do enumerowania handlerów, middleware auth, konsumentów webhooków, niebezpiecznych funkcji pomocniczych lub określonych klas/metod.
- **Operatory Boolean** ograniczające szum: `NOT path:test`, `NOT is:generated`, `NOT is:vendored`, `foo OR bar`.
- **Wyszukiwanie rewizji/diffów**, gdy jest dostępne, dzięki czemu można odzyskać **usunięte ciągi znaków**, śledzić **zmiany związane z bezpieczeństwem** lub analizować **branche/tagi inne niż domyślne** bez wcześniejszego klonowania wszystkiego.

## Praktyczna metodologia

1. **Rozpocznij od zindeksowanych platform**, aby szybko zidentyfikować repozytoria, właścicieli, ścieżki i rodziny kodu.
2. **Przejdź do lokalizacji o wysokiej wartości rozpoznawczej**, zamiast wyszukiwać wyłącznie ogólne ciągi `password`/`secret`.
3. **Szukaj attack surface, a nie tylko credentials**:
- Workflow CI/CD, reusable workflows, composite actions i skrypty wdrożeniowe
- Pliki startowe Dev Containers / Codespaces oraz custom features
- Manifesty Terraform/Helm/Kubernetes
- Integracje SSO/OIDC/SAML
- Wewnętrzne URL-e, hosty stagingowe, panele administracyjne, message brokery i endpointy callback
- Niebezpieczne ścieżki kodu (`exec`, renderowanie template'ów, fetchery SSRF, deserializery, rozpakowywanie ZIP, loadery YAML itd.)
4. **Sklonuj i przeszukaj lokalnie**, gdy potrzebujesz branchy innych niż domyślny, pełnej historii, lepszej obsługi regex lub automatyzacji zbiorczej.
5. **Przejdź do dedykowanych skanerów**, gdy celem jest triage lub weryfikacja secrets (przykład znajdziesz na dedykowanej stronie poniżej).

### Pomysły na zapytania o wysokiej wartości rozpoznawczej

Są one celowo szerokie, aby można je było dostosować do składni GitHub, GitLab, Sourcegraph lub Sourcebot:
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
### Nowsze pliki o wysokiej wartości, które warto priorytetyzować

- **`.github/workflows/*.yml`**: Szukaj `pull_request_target`, `workflow_run`, `workflow_call`, `secrets: inherit`, `id-token: write`, `runs-on: self-hosted` oraz wierszy z zewnętrznym `uses:`, przypiętym wyłącznie do tagów/branchy zamiast pełnych commit SHA.<sup>[[3]](#references)</sup>
- **`.devcontainer/devcontainer.json`**, **`.devcontainer/<variant>/devcontainer.json`** oraz **`.devcontainer.json`**: Wyszukuj `remoteEnv`, `containerEnv`, `initializeCommand`, `postCreateCommand`, `mounts` oraz wskazane Dockerfiles/skrypty. Często ujawniają one wewnętrzne rejestry pakietów, bootstrap URLs, mounty hosta oraz endpointy przeznaczone wyłącznie dla developerów.<sup>[[4]](#references)</sup>
- **Dev Container Features** (`devcontainer-feature.json`, `install.sh`): Świetne źródło logiki instalatorów specyficznych dla organizacji, wykonywanej podczas tworzenia środowiska.
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
Używaj lokalnego wyszukiwania, gdy potrzebujesz:

- Przeszukiwać **non-default branches** lub **tags**
- Przeszukiwać **git history**
- Uruchamiać zapytania **PCRE2/multiline** z większą intensywnością
- Wykonywać wstępny triage wielu repozytoriów bez ograniczeń UI

### Jawnie przeszukuj historię, branche i różnice zmian
```bash
REPO_DIR=repos/some-repo
git -C "$REPO_DIR" fetch --all --tags --prune

git -C "$REPO_DIR" for-each-ref --format='%(refname:short)' refs/remotes/origin refs/tags \
| while read -r ref; do
git -C "$REPO_DIR" grep -nI -E 'pull_request_target|workflow_call|id-token: write|secrets: inherit|remoteEnv|containerEnv' "$ref" || true
done

git -C "$REPO_DIR" log --all -p -G 'gh[pousr]_|github_pat_|BEGIN [A-Z ]+PRIVATE KEY|internal.*https?://' -- .
```
Jest to szczególnie przydatne, gdy interesujący ciąg znaków istniał wyłącznie w **release branch**, **tagu** lub **usuniętym commicie**. Jeśli Twoje wdrożenie Sourcegraph to obsługuje, wyszukiwania `type:diff` i `type:commit` są doskonałym sposobem na wykonanie pivotu bez klonowania w przypadku tego samego problemu.

## Typowe ślepe punkty

- Często indeksowana jest wyłącznie **default branch**. Nie zakładaj, że code search obejmuje wszystkie branche, tagi i historię.
- **Duże pliki, vendored code, generated code lub archiwa** mogą być pomijane albo generować dużo szumu.
- **Komentarze, issues, PR-y, gists i wiki** często znajdują się poza zakresem ogólnego code search i mogą wymagać narzędzi specyficznych dla danej platformy.
- Konfiguracje **Codespaces / devcontainer** mogą być zależne od brancha i znajdować się w kilku ścieżkach `.devcontainer/<variant>/devcontainer.json`, dlatego czysty default branch nie oznacza, że środowisko deweloperskie jest wszędzie czyste.
- **Reusable workflows/actions i devcontainer features** mogą znajdować się poza oczywistym plikiem. Szukaj w `.github/actions/`, `action.yml`, `action.yaml`, `devcontainer-feature.json` oraz `install.sh`, a nie tylko w pliku workflow znajdującym się w katalogu głównym.
- **Składnia wyszukiwania różni się między platformami**. Dork działający w GitHub Code Search może wymagać niewielkich zmian w GitLab, Sourcegraph lub Sourcebot.

### Pułapki specyficzne dla platform

- **GitHub Code Search** doskonale nadaje się do szybkiego recon, ale przeszukuje wyłącznie **default branch**. Jeśli potrzebujesz feature branchy, usuniętych sekretów lub historycznego kodu, sklonuj repozytorium i przeszukaj je lokalnie.
- **GitLab Exact Code Search** również ma ograniczenie dotyczące **default branch** i indeksuje tylko mniejsze pliki, ale **Advanced Search** nadal może być przydatne do przeszukiwania komentarzy, commitów i wiki.<sup>[[2]](#references)</sup>
- **Sourcebot** domyślnie indeksuje **default branch**, ale można go skonfigurować tak, aby indeksował dodatkowe branche i tagi, a następnie przeszukiwać je za pomocą filtrów `rev:`. Jest to bardzo wygodne podczas wewnętrznych audytów skoncentrowanych na konkretnym branchu lub tagu, gdy kontrolujesz indeks.
- Wyszukiwanie regex w **Sourcegraph** jest zwykle najbardziej przewidywalną opcją podczas działań offensive; structural search traktuj jako opcjonalny bonus, a nie gwarantowaną funkcję. Jeśli wdrożenie to obsługuje, zapytania `type:diff` i `type:commit` bardzo dobrze nadają się do odzyskiwania usuniętych ciągów znaków lub wyszukiwania niedawnych zmian związanych z bezpieczeństwem.

> [!WARNING]
> Gdy szukasz leaków w repozytorium i uruchamiasz coś takiego jak `git log -p`, nie zapominaj, że mogą istnieć **inne branche z innymi commitami**, które zawierają sekrety!

Informacje dotyczące wyszukiwania sekretów, GitHub dorks obejmujących całą organizację oraz narzędzi takich jak TruffleHog/Gitleaks znajdziesz tutaj:

{{#ref}}
github-leaked-secrets.md
{{#endref}}

## References

- [1] [Składnia GitHub Code Search](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [2] [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
- [3] [Dokumentacja bezpiecznego użycia GitHub Actions](https://docs.github.com/en/actions/reference/security/secure-use)
- [4] [Dokumentacja metadanych Dev Container](https://containers.dev/implementors/json_reference/)

{{#include ../../banners/hacktricks-training.md}}
