# Szerokie wyszukiwanie kodu źródłowego

Celem tej strony jest wymienienie **platform umożliwiających wyszukiwanie kodu** (literalne, regex, uwzględniające symbole lub ograniczone do ścieżek) w **tysiącach/milionach repozytoriów**.

Jest to przydatne do:

- **Wyszukiwania wycieków informacji**
- **Wyszukiwania podatnych wzorców**
- **Mapowania technologii, hostów wewnętrznych, CI/CD i infrastruktury jako kodu**
- **Przechodzenia od nazwy firmy/org do repozytoriów, branchy i plików o wysokiej wartości**

- [**Sourcebot**](https://www.sourcebot.dev/): Open-source/self-hosted code search z obsługą regex, symboli i filtrowanego wyszukiwania w repozytoriach. Skonfiguruj dodatkowe branche/tagi i wyszukuj w nich za pomocą `rev:`, gdy istotne jest pokrycie branchy.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- [**Sourcegraph**](https://sourcegraph.com/search): Code search z obsługą regex, logiki boolowskiej, symboli, repozytoriów/plików/języków, branchy/commitów, diffów i zapytań dotyczących wiadomości commitów.<sup>[[8]](#references)[[10]](#references)</sup> Structural search jest opcjonalne, ponieważ aktualna dokumentacja opisuje je jako domyślnie wyłączone i ograniczone wydajnościowo.<sup>[[9]](#references)</sup>
- [**GitHub Code Search**](https://github.com/search): Obsługuje regex, logikę boolowską oraz kwalifikatory takie jak `repo:`, `org:`, `user:`, `path:`, `language:`, `symbol:`, `content:` i `is:`.<sup>[[1]](#references)</sup>
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/): Code search zasilane przez Zoekt, z trybami exact i regex oraz filtrami takimi jak `file:`, `lang:`, `repo:` i `sym:`.<sup>[[2]](#references)</sup>
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/) jest szerszym rozwiązaniem awaryjnym, ponieważ umożliwia wyszukiwanie w kodzie, komentarzach, commitach, merge requestach i wiki.<sup>[[11]](#references)</sup>
- [**SearchCode**](https://searchcode.com/): Usługa code intelligence z boolowskim/regexowym/strukturalnym wyszukiwaniem kodu oraz pobieraniem plików i symboli.<sup>[[12]](#references)</sup>
- [**Grep**](https://grep.app/): Publiczne wyszukiwanie kodu w milionie repozytoriów GitHub, obejmujące wyszukiwanie treści, plików i ścieżek.<sup>[[13]](#references)</sup>

## Przydatne możliwości wyszukiwania

Podczas audytowania org w kontekście bug bounty/red team najprzydatniejsze możliwości to zazwyczaj:

- Obsługa **regex**, umożliwiająca wyszukiwanie formatów tokenów, schematów URL, nazw niebezpiecznych funkcji lub fragmentów wielowierszowych.
- **Filtry ścieżek**, umożliwiające bezpośrednie przejście do plików o wysokiej wartości, takich jak `.github/workflows/`, `terraform/`, `helm/`, `.env`, `values.yaml`, `secrets.*`, `credentials.*`, `Dockerfile`, `Jenkinsfile` lub `nginx.conf`.
- **Filtry języków**, umożliwiające oddzielenie kodu aplikacji od IaC i pipeline'ów.
- **Wyszukiwanie uwzględniające symbole**, umożliwiające wyliczenie handlerów, middleware auth, konsumentów webhooków, niebezpiecznych funkcji pomocniczych lub konkretnych klas/metod.
- **Operatory boolowskie** ograniczające szum: `NOT path:test`, `NOT is:generated`, `NOT is:vendored`, `foo OR bar`.
- **Wyszukiwanie rewizji/diffów**, jeśli jest dostępne, dzięki któremu można odzyskać **usunięte ciągi znaków**, śledzić **zmiany istotne z punktu widzenia security** lub analizować **niedomyślne branche/tagi** bez konieczności wcześniejszego klonowania wszystkiego.

## Praktyczna metodologia

1. **Zacznij od indeksowanych platform**, aby szybko zidentyfikować repozytoria, właścicieli, ścieżki i rodziny kodu.
2. **Przechodź do lokalizacji o wysokiej wartości**, zamiast wyszukiwać wyłącznie ogólne ciągi `password`/`secret`.
3. **Szukaj powierzchni ataku, a nie tylko credentials**:
- Workflow CI/CD, reusable workflows, composite actions i skrypty deploymentu
- Pliki bootstrap Dev Containers / Codespaces oraz custom features
- Manifesty Terraform/Helm/Kubernetes
- Integracje SSO/OIDC/SAML
- Wewnętrzne URL-e, hosty stagingowe, panele administracyjne, message brokery i endpointy callback
- Niebezpieczne ścieżki kodu (`exec`, renderowanie szablonów, fetchery SSRF, deserializery, rozpakowywanie ZIP, loadery YAML itd.)
4. **Klonuj i wyszukuj lokalnie**, gdy potrzebujesz niedomyślnych branchy, pełnej historii, lepszej obsługi regex lub automatyzacji masowej.
5. **Przejdź do dedykowanych skanerów**, gdy celem jest triage lub weryfikacja secrets (na przykład zobacz poniższą dedykowaną stronę).

### Pomysły na zapytania o wysokiej wartości

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
### Nowsze pliki o wysokiej wartości sygnału, które warto traktować priorytetowo

- **`.github/workflows/*.yml`**: Przeanalizuj uprzywilejowane wyzwalacze `pull_request_target` i `workflow_run` oraz wiersze innych firm `uses:`, przypięte wyłącznie do tagów/branchy zamiast pełnych commit SHA.<sup>[[3]](#references)</sup> Wyszukaj również `workflow_call`, `secrets: inherit`, `id-token: write` oraz `runs-on: self-hosted`.
- **`.devcontainer/devcontainer.json`**, **`.devcontainer/<variant>/devcontainer.json`** oraz **`.devcontainer.json`**: Wyszukaj `remoteEnv`, `containerEnv`, `initializeCommand`, `postCreateCommand`, `mounts` oraz wskazane Dockerfiles/skrypty, aby znaleźć wartości środowiskowe, polecenia bootstrapujące, mounty i powiązane pliki.<sup>[[4]](#references)</sup>
- **Dev Container Features** (`devcontainer-feature.json`, `install.sh`): Przeanalizuj oba pliki, ponieważ minimalny układ Feature obejmuje metadane i skrypt wejściowy `install.sh`.<sup>[[14]](#references)</sup>
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

- Przeszukiwać **gałęzie inne niż domyślna** lub **tagi**
- Przeszukiwać **historię git**
- Uruchamiać bardziej zaawansowane zapytania **PCRE2/multiline**
- Wstępnie analizować wiele repozytoriów bez limitów interfejsu

### Jawnie przeszukuj historię, gałęzie i różnice
```bash
REPO_DIR=repos/some-repo
git -C "$REPO_DIR" fetch --all --tags --prune

git -C "$REPO_DIR" for-each-ref --format='%(refname:short)' refs/remotes/origin refs/tags \
| while read -r ref; do
git -C "$REPO_DIR" grep -nI -E 'pull_request_target|workflow_call|id-token: write|secrets: inherit|remoteEnv|containerEnv' "$ref" || true
done

git -C "$REPO_DIR" log --all -p -G 'gh[pousr]_|github_pat_|BEGIN [A-Z ]+PRIVATE KEY|internal.*https?://' -- .
```
Jest to szczególnie przydatne, gdy interesujący ciąg znaków istniał wyłącznie w **release branch**, **tag** lub **deleted commit**. Jeśli Twoje wdrożenie Sourcegraph to obsługuje, wyszukiwania `type:diff` i `type:commit` są doskonałym podejściem no-clone do tego samego problemu.<sup>[[8]](#references)[[10]](#references)</sup>

## Common blind spots

- Często stosowane jest indeksowanie **wyłącznie domyślnej gałęzi**. Nie zakładaj, że code search obejmuje wszystkie gałęzie/tagi/historię.
- **Duże pliki, vendored code, generated code lub archiwa** mogą być pomijane albo generować dużo szumu.
- **Komentarze, issues, PR-y, gists i wiki** często wykraczają poza zakres ogólnego code search i mogą wymagać narzędzi charakterystycznych dla danej platformy.
- **Konfiguracje Codespaces / devcontainer mogą być zależne od gałęzi**. Mogą znajdować się w kilku ścieżkach `.devcontainer/<variant>/devcontainer.json`, dlatego czysta domyślna gałąź nie oznacza, że środowisko deweloperskie jest wszędzie bezpieczne.<sup>[[4]](#references)</sup>
- **Reusable workflows/actions i devcontainer features mogą znajdować się poza oczywistym plikiem**. Przeszukuj `.github/actions/`, `action.yml`, `action.yaml`, `devcontainer-feature.json` oraz `install.sh`, a nie tylko plik workflow znajdujący się w katalogu głównym.
- **Składnia wyszukiwania różni się w zależności od platformy**. Dork działający w GitHub Code Search może wymagać niewielkich zmian w GitLab, Sourcegraph lub Sourcebot.

### Platform-specific gotchas

- **GitHub Code Search** jest przydatny do szybkiego recon, ale przeszukuje wyłącznie **domyślną gałąź**. Jeśli potrzebujesz feature branches, deleted secrets lub historical code, sklonuj repozytorium i przeszukaj je lokalnie.<sup>[[15]](#references)</sup>
- **GitLab Exact Code Search** ma ograniczenie do **domyślnej gałęzi** i indeksuje wyłącznie pliki mniejsze niż 1 MB oraz zawierające mniej niż 20 000 trigramów.<sup>[[2]](#references)</sup> **Advanced Search** nadal może obejmować komentarze, commity i wiki.<sup>[[11]](#references)</sup>
- **Sourcebot** domyślnie indeksuje **domyślną gałąź**, ale można go skonfigurować tak, aby indeksował dodatkowe gałęzie/tagi, a następnie przeszukiwać je za pomocą filtrów `rev:`, gdy kontrolujesz indeks.<sup>[[7]](#references)</sup>
- **Sourcegraph** obsługuje zapytania regex, symbol, diff i commit; structural search stosuj wyłącznie tam, gdzie jest włączone, i uwzględniaj udokumentowane ograniczenia wydajności.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

> [!WARNING]
> Gdy szukasz leaków w repozytorium i uruchamiasz coś takiego jak `git log -p`, nie zapominaj, że mogą istnieć **inne gałęzie z innymi commitami**, zawierającymi secrets!

W przypadku dedykowanego secret hunting, org-wide GitHub dorks oraz narzędzi takich jak TruffleHog/Gitleaks sprawdź [stronę o wyciekach secrets z GitHub](github-leaked-secrets.md).

## References

- [1] [Składnia GitHub Code Search](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [2] [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
- [3] [Dokumentacja bezpiecznego użycia GitHub Actions](https://docs.github.com/en/actions/reference/security/secure-use)
- [4] [Dokumentacja metadanych Dev Container](https://containers.dev/implementors/json_reference/)
- [5] [Sourcebot](https://www.sourcebot.dev/)
- [6] [API wyszukiwania Sourcebot](https://docs.sourcebot.dev/api-reference/search-%26-navigation/search-code)
- [7] [Indeksowanie wielu gałęzi w Sourcebot](https://docs.sourcebot.dev/docs/features/search/multi-branch-indexing)
- [8] [Sourcegraph Code Search](https://sourcegraph.com/docs/code-search)
- [9] [Sourcegraph Structural Search](https://sourcegraph.com/docs/code-search/types/structural)
- [10] [Składnia zapytań wyszukiwania Sourcegraph](https://sourcegraph.com/docs/code-search/queries)
- [11] [GitLab Advanced Search](https://docs.gitlab.com/user/search/advanced_search/)
- [12] [SearchCode](https://searchcode.com/)
- [13] [Grep.app](https://grep.app/)
- [14] [Tworzenie Dev Container Feature](https://containers.dev/guide/author-a-feature)
- [15] [Narzędzia do badania incydentów bezpieczeństwa](https://docs.github.com/en/enterprise-cloud%40latest/code-security/reference/security-incident-response/investigation-tools)
{{#include ../../banners/hacktricks-training.md}}
