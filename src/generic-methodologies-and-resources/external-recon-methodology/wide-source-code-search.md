# Szerokie wyszukiwanie kodu źródłowego

{{#include ../../banners/hacktricks-training.md}}

Celem tej strony jest wymienienie **platform umożliwiających wyszukiwanie kodu** (literalne, regex, z uwzględnieniem symboli lub ograniczone do ścieżek) w **tysiącach/milionach repozytoriów**.

Jest to przydatne do:

- **Wyszukiwania leaków**
- **Wyszukiwania podatnych wzorców**
- **Mapowania technologii, wewnętrznych hostów, CI/CD i infrastructure-as-code**
- **Pivotowania od nazwy firmy/org do repozytoriów, branchy i plików o wysokiej wartości**

- [**Sourcebot**](https://www.sourcebot.dev/): Open-source/self-hosted code search z obsługą regex, symboli i filtrowanego wyszukiwania w repozytoriach. Skonfiguruj dodatkowe branche/tagi i wyszukuj w nich za pomocą `rev:`, gdy istotne jest pokrycie branchy.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- [**Sourcegraph**](https://sourcegraph.com/search): Code search z obsługą zapytań regex, boolean, symbol, repository/file/language, branch/commit, diff i commit-message.<sup>[[8]](#references)[[10]](#references)</sup> Structural search jest opcjonalne, ponieważ aktualna dokumentacja opisuje je jako domyślnie wyłączone i ograniczone pod względem wydajności.<sup>[[9]](#references)</sup>
- [**GitHub Code Search**](https://github.com/search): Obsługuje regex, logikę boolean oraz kwalifikatory takie jak `repo:`, `org:`, `user:`, `path:`, `language:`, `symbol:`, `content:` i `is:`.<sup>[[1]](#references)</sup>
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/): Code search obsługiwane przez Zoekt, z trybem exact i regex oraz filtrami takimi jak `file:`, `lang:`, `repo:` i `sym:`.<sup>[[2]](#references)</sup>
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/) jest szerszym fallbackiem, ponieważ umożliwia wyszukiwanie w kodzie, komentarzach, commitach, merge requestach i wiki.<sup>[[11]](#references)</sup>
- [**SearchCode**](https://searchcode.com/): Usługa code-intelligence z boolean/regex/structural code search oraz pobieraniem plików i symboli.<sup>[[12]](#references)</sup>
- [**Grep**](https://grep.app/): Publiczne code search w milionie repozytoriów GitHub, z wyszukiwaniem treści, plików i ścieżek.<sup>[[13]](#references)</sup>

## Przydatne możliwości wyszukiwania

Podczas audytowania org w kontekście bug bounty/red team najczęściej najbardziej przydatne są:

- Obsługa **Regex**, aby wyszukiwać formaty tokenów, schematy URL, nazwy niebezpiecznych funkcji lub fragmenty wieloliniowe.
- **Filtry ścieżek**, aby przechodzić bezpośrednio do plików o wysokiej wartości, takich jak `.github/workflows/`, `terraform/`, `helm/`, `.env`, `values.yaml`, `secrets.*`, `credentials.*`, `Dockerfile`, `Jenkinsfile` lub `nginx.conf`.
- **Filtry języków**, aby oddzielić kod aplikacji od IaC i pipeline'ów.
- **Wyszukiwanie z uwzględnieniem symboli**, aby wyliczać handlery, middleware auth, konsumentów webhooków, niebezpieczne funkcje pomocnicze lub określone klasy/metody.
- **Operatory boolean**, aby ograniczyć szum: `NOT path:test`, `NOT is:generated`, `NOT is:vendored`, `foo OR bar`.
- **Wyszukiwanie rewizji/diffów**, gdy jest dostępne, aby odzyskiwać **usunięte stringi**, śledzić **zmiany związane z bezpieczeństwem** lub przeglądać **niedomyślne branche/tagi** bez wcześniejszego klonowania wszystkiego.

## Praktyczna metodologia

1. **Zacznij od indeksowanych platform**, aby szybko zidentyfikować repozytoria, właścicieli, ścieżki i rodziny kodu.
2. **Pivotuj do lokalizacji o wysokiej wartości**, zamiast wyszukiwać wyłącznie ogólne stringi `password`/`secret`.
3. **Szukaj attack surface, a nie tylko credentials**:
- Workflow CI/CD, reusable workflows, composite actions i skrypty deploymentu
- Pliki bootstrap Dev Containers / Codespaces oraz custom features
- Manifesty Terraform/Helm/Kubernetes
- Integracje SSO/OIDC/SAML
- Wewnętrzne URL-e, hosty stagingowe, panele administracyjne, message brokery i endpointy callback
- Niebezpieczne ścieżki kodu (`exec`, renderowanie template'ów, fetchery SSRF, deserializery, rozpakowywanie ZIP, loadery YAML itd.)
4. **Klonuj i wyszukuj lokalnie**, gdy potrzebujesz niedomyślnych branchy, pełnej historii, lepszej obsługi regex lub automatyzacji zbiorczej.
5. **Przejdź do dedykowanych scannerów**, gdy celem jest triage lub weryfikacja sekretów (na przykład zobacz poniższą dedykowaną stronę).

### Pomysły na zapytania o wysokiej wartości

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
### Nowsze pliki o wysokiej wartości sygnału, które warto traktować priorytetowo

- **`.github/workflows/*.yml`**: Przeanalizuj uprzywilejowane triggery `pull_request_target` i `workflow_run` oraz linie `uses:` innych firm przypięte wyłącznie do tagów/branchy zamiast pełnych SHA commitów.<sup>[[3]](#references)</sup> Wyszukaj również `workflow_call`, `secrets: inherit`, `id-token: write` oraz `runs-on: self-hosted`.
- **`.devcontainer/devcontainer.json`**, **`.devcontainer/<variant>/devcontainer.json`** oraz **`.devcontainer.json`**: Wyszukaj `remoteEnv`, `containerEnv`, `initializeCommand`, `postCreateCommand`, `mounts` oraz wskazane Dockerfiles/skrypty, aby znaleźć wartości środowiskowe, komendy bootstrapujące, mounty i powiązane pliki.<sup>[[4]](#references)</sup>
- **Dev Container Features** (`devcontainer-feature.json`, `install.sh`): Przeanalizuj oba pliki, ponieważ minimalny układ Feature obejmuje metadane oraz skrypt wejściowy `install.sh`.<sup>[[14]](#references)</sup>
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
- Wykonywać wstępny przegląd wielu repozytoriów bez ograniczeń interfejsu

### Jawne przeszukiwanie historii, branchy i diffów
```bash
REPO_DIR=repos/some-repo
git -C "$REPO_DIR" fetch --all --tags --prune

git -C "$REPO_DIR" for-each-ref --format='%(refname:short)' refs/remotes/origin refs/tags \
| while read -r ref; do
git -C "$REPO_DIR" grep -nI -E 'pull_request_target|workflow_call|id-token: write|secrets: inherit|remoteEnv|containerEnv' "$ref" || true
done

git -C "$REPO_DIR" log --all -p -G 'gh[pousr]_|github_pat_|BEGIN [A-Z ]+PRIVATE KEY|internal.*https?://' -- .
```
Jest to szczególnie przydatne, gdy interesujący ciąg znaków istniał wyłącznie w **release branch**, **tag** lub **deleted commit**. Jeśli Twoje wdrożenie Sourcegraph to obsługuje, wyszukiwania `type:diff` i `type:commit` są doskonałym sposobem na rozwiązanie tego samego problemu bez klonowania.<sup>[[8]](#references)[[10]](#references)</sup>

## Common blind spots

- **Indeksowanie wyłącznie domyślnej gałęzi** jest powszechne. Nie zakładaj, że code search obejmuje wszystkie branches/tags/history.
- **Duże pliki, vendored code, generated code lub archives** mogą być pomijane albo powodować szum.
- **Comments, issues, PRs, gists i wikis** często znajdują się poza zakresem ogólnego code search i mogą wymagać narzędzi właściwych dla danej platformy.
- **Konfiguracje Codespaces / devcontainer mogą być zależne od brancha**. Mogą znajdować się w kilku ścieżkach `.devcontainer/<variant>/devcontainer.json`, więc czysty default branch nie oznacza, że środowisko deweloperskie jest wszędzie czyste.<sup>[[4]](#references)</sup>
- **Reusable workflows/actions i devcontainer features mogą znajdować się poza oczywistym plikiem**. Przeszukuj `.github/actions/`, `action.yml`, `action.yaml`, `devcontainer-feature.json` oraz `install.sh`, a nie tylko plik workflow najwyższego poziomu.
- **Składnia wyszukiwania różni się w zależności od platformy**. Dork działający w GitHub Code Search może wymagać niewielkich zmian w GitLab, Sourcegraph lub Sourcebot.

### Platform-specific gotchas

- **GitHub Code Search** jest przydatny do szybkiego recon, ale przeszukuje wyłącznie **default branch**. Jeśli potrzebujesz feature branches, deleted secrets lub historical code, sklonuj repo i przeszukaj je lokalnie.<sup>[[15]](#references)</sup>
- **GitLab Exact Code Search** ma ograniczenie do **default branch** i indeksuje wyłącznie pliki mniejsze niż 1 MB oraz zawierające mniej niż 20 000 trigramów.<sup>[[2]](#references)</sup> **Advanced Search** nadal może obejmować comments, commits i wikis.<sup>[[11]](#references)</sup>
- **Sourcebot** domyślnie indeksuje **default branch**, ale można go skonfigurować tak, aby indeksował dodatkowe branches/tags, a następnie przeszukiwać je za pomocą filtrów `rev:`, jeśli kontrolujesz index.<sup>[[7]](#references)</sup>
- **Sourcegraph** obsługuje zapytania regex, symbol, diff i commit; używaj structural search tylko tam, gdzie jest włączone, i uwzględniaj udokumentowane ograniczenia wydajności.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

> [!WARNING]
> Gdy szukasz leaków w repo i uruchamiasz coś takiego jak `git log -p`, nie zapominaj, że mogą istnieć **inne branches z innymi commits** zawierającymi secrets!

W przypadku dedykowanego secret hunting, GitHub dorks obejmujących całą organizację oraz narzędzi takich jak TruffleHog/Gitleaks sprawdź [stronę GitHub dotyczącą leaked secrets](github-leaked-secrets.md).

## References

- [1] [Składnia GitHub Code Search](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [2] [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
- [3] [Dokumentacja bezpiecznego używania GitHub Actions](https://docs.github.com/en/actions/reference/security/secure-use)
- [4] [Dokumentacja metadanych Dev Container](https://containers.dev/implementors/json_reference/)
- [5] [Sourcebot](https://www.sourcebot.dev/)
- [6] [API wyszukiwania Sourcebot](https://docs.sourcebot.dev/api-reference/search-%26-navigation/search-code)
- [7] [Indeksowanie wielu branches w Sourcebot](https://docs.sourcebot.dev/docs/features/search/multi-branch-indexing)
- [8] [Sourcegraph Code Search](https://sourcegraph.com/docs/code-search)
- [9] [Sourcegraph Structural Search](https://sourcegraph.com/docs/code-search/types/structural)
- [10] [Składnia zapytań wyszukiwania Sourcegraph](https://sourcegraph.com/docs/code-search/queries)
- [11] [GitLab Advanced Search](https://docs.gitlab.com/user/search/advanced_search/)
- [12] [SearchCode](https://searchcode.com/)
- [13] [Grep.app](https://grep.app/)
- [14] [Tworzenie Dev Container Feature](https://containers.dev/guide/author-a-feature)
- [15] [Narzędzia do badania incydentów bezpieczeństwa](https://docs.github.com/en/enterprise-cloud%40latest/code-security/reference/security-incident-response/investigation-tools)
{{#include ../../banners/hacktricks-training.md}}
