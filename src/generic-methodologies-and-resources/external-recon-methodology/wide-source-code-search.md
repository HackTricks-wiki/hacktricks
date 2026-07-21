# Ricerca estesa nel codice sorgente

{{#include ../../banners/hacktricks-training.md}}

L'obiettivo di questa pagina è elencare le **piattaforme che consentono di cercare codice** (letterale, regex, basato sui simboli o limitato a un path) in **migliaia/milioni di repo**.

È utile per:

- **Cercare informazioni oggetto di leak**
- **Cercare pattern vulnerabili**
- **Mappare tecnologie, host interni, CI/CD e infrastructure-as-code**
- **Eseguire pivot dal nome di un'azienda/organizzazione verso repo, branch e file ad alto valore informativo**

- [**Sourcebot**](https://www.sourcebot.dev/): code search open-source/self-hosted. Molto utile quando vuoi indicizzare **molti repo** e, se configurato, anche branch/tag aggiuntivi, mantenendo filtri regex come `repo:`, `file:`, `lang:`, `rev:` e `sym:`.
- [**SourceGraph**](https://sourcegraph.com/search): ricerca in milioni di repo. La regex è solitamente l'opzione più sicura; in alcuni deployment è disponibile la structural search, ma presenta limitazioni di performance e non è sempre abilitata.
- [**GitHub Code Search**](https://github.com/search): supporta regex, logica booleana e qualificatori come `repo:`, `org:`, `user:`, `path:`, `language:`, `symbol:`, `content:` e `is:`.
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/): code search moderna di GitLab basata su Zoekt. Supporta modalità exact e regex con filtri come `file:`, `lang:`, `repo:` e `sym:`.
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/) è ancora utile come fallback più ampio, perché può cercare in codice, commenti, commit, merge request e wiki.
- [**SearchCode**](https://searchcode.com/): ricerca codice in milioni di progetti.
- [**Grep**](https://grep.app/): ricerca pubblica veloce su un corpus GitHub molto esteso. Utile quando vuoi una seconda visualizzazione dell'indicizzazione/ranking per i pivot su **content**, **file** e **path**.

## Funzionalità di ricerca utili

Quando esegui l'audit di un'organizzazione in un contesto di bug bounty/red team, le funzionalità più utili sono solitamente:

- Supporto **Regex** per cercare formati di token, schemi URL, nomi di funzioni pericolose o frammenti multilinea.
- **Filtri path** per accedere direttamente a file ad alto valore come `.github/workflows/`, `terraform/`, `helm/`, `.env`, `values.yaml`, `secrets.*`, `credentials.*`, `Dockerfile`, `Jenkinsfile` o `nginx.conf`.
- **Filtri per linguaggio** per separare il codice dell'app da IaC e pipeline.
- **Ricerca basata sui simboli** per enumerare handler, middleware di autenticazione, consumer di webhook, funzioni helper pericolose o classi/metodi specifici.
- **Operatori booleani** per ridurre il rumore: `NOT path:test`, `NOT is:generated`, `NOT is:vendored`, `foo OR bar`.
- **Ricerca per revisione/diff**, quando disponibile, per recuperare **stringhe eliminate**, seguire **modifiche rilevanti per la sicurezza** o analizzare **branch/tag non predefiniti** senza dover clonare tutto prima.

## Metodologia pratica

1. **Inizia dalle piattaforme indicizzate** per identificare rapidamente repo, proprietari, path e famiglie di codice.
2. **Esegui il pivot verso le aree ad alto valore informativo** invece di cercare soltanto stringhe generiche come `password`/`secret`.
3. **Cerca la attack surface, non solo le credenziali**:
- Workflow CI/CD, reusable workflow, composite action e script di deployment
- File di bootstrap e custom feature di Dev Containers / Codespaces
- Manifest Terraform/Helm/Kubernetes
- Integrazioni SSO/OIDC/SAML
- URL interni, host di staging, pannelli admin, message broker ed endpoint di callback
- Path di codice pericolosi (`exec`, template rendering, fetcher SSRF, deserializer, estrazione ZIP, YAML loader, ecc.)
4. **Clona ed esegui la ricerca localmente** quando ti servono branch non predefiniti, la cronologia completa, un supporto regex migliore o l'automazione su larga scala.
5. **Passa a scanner dedicati** quando l'obiettivo è il triage o la verifica dei secret (ad esempio, consulta la pagina dedicata qui sotto).

### Idee per query ad alto valore informativo

Sono volutamente ampie, così puoi adattarle alla sintassi di GitHub, GitLab, Sourcegraph o Sourcebot:
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
### File più recenti ad alto segnale da prioritizzare

- **`.github/workflows/*.yml`**: Cerca `pull_request_target`, `workflow_run`, `workflow_call`, `secrets: inherit`, `id-token: write`, `runs-on: self-hosted` e righe `uses:` di terze parti fissate solo a tag/branch anziché a SHA completi dei commit.
- **`.devcontainer/devcontainer.json`**, **`.devcontainer/<variant>/devcontainer.json`** e **`.devcontainer.json`**: Cerca `remoteEnv`, `containerEnv`, `initializeCommand`, `postCreateCommand`, `mounts` e i Dockerfile/script referenziati. Spesso espongono registry di pacchetti interni, URL di bootstrap, mount dell'host ed endpoint riservati agli sviluppatori.
- **Dev Container Features** (`devcontainer-feature.json`, `install.sh`): Ottimi per trovare la logica di installer specifica dell'organizzazione che viene eseguita durante la creazione dell'ambiente.
- **Altri file CI/control-plane**: `.gitlab-ci.yml`, `azure-pipelines.yml`, `cloudbuild.yaml`, `Jenkinsfile`, `buildkite*`, `atlantis.yaml`, `terragrunt.hcl`, `helmfile.yaml`, `skaffold.yaml`, `argocd*`.

### Ricerca locale di massa quando la ricerca indicizzata non è sufficiente
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
Usa la ricerca locale quando devi:

- Cercare **rami non predefiniti** o **tag**
- Cercare nella **cronologia git**
- Eseguire query **PCRE2/multiline** in modo più aggressivo
- Eseguire il **triage in batch** di molti repository senza i limiti dell'interfaccia

### Cerca esplicitamente nella cronologia, nei rami e nei diff
```bash
REPO_DIR=repos/some-repo
git -C "$REPO_DIR" fetch --all --tags --prune

git -C "$REPO_DIR" for-each-ref --format='%(refname:short)' refs/remotes/origin refs/tags \
| while read -r ref; do
git -C "$REPO_DIR" grep -nI -E 'pull_request_target|workflow_call|id-token: write|secrets: inherit|remoteEnv|containerEnv' "$ref" || true
done

git -C "$REPO_DIR" log --all -p -G 'gh[pousr]_|github_pat_|BEGIN [A-Z ]+PRIVATE KEY|internal.*https?://' -- .
```
Ciò è particolarmente utile quando la stringa interessante esisteva solo in un **release branch**, **tag** o **deleted commit**. Se il tuo deployment di Sourcegraph lo supporta, le ricerche `type:diff` e `type:commit` sono un ottimo pivot no-clone per lo stesso problema.

## Punti ciechi comuni

- L'indicizzazione **solo del default branch** è comune. Non presumere che la code search copra tutti i branch/tag/la cronologia.
- **File di grandi dimensioni, codice vendorizzato, codice generato o archivi** potrebbero essere ignorati o produrre risultati rumorosi.
- **Commenti, issue, PR, gist e wiki** spesso non rientrano nell'ambito della generic code search e potrebbero richiedere tooling specifico della piattaforma.
- Le configurazioni di **Codespaces / devcontainer possono essere specifiche per branch** e trovarsi in diversi percorsi `.devcontainer/<variant>/devcontainer.json`; quindi un default branch pulito non significa che l'ambiente di sviluppo sia pulito ovunque.
- I **workflow/action riutilizzabili e le devcontainer features possono trovarsi al di fuori del file ovvio**. Cerca in `.github/actions/`, `action.yml`, `action.yaml`, `devcontainer-feature.json` e `install.sh`, non solo nel file workflow di primo livello.
- La **sintassi di ricerca varia a seconda della piattaforma**. Un dork che funziona nella GitHub Code Search potrebbe richiedere piccole modifiche per GitLab, Sourcegraph o Sourcebot.

### Problemi specifici delle piattaforme

- **GitHub Code Search** è eccellente per una recon rapida, ma cerca solo nel **default branch**. Se ti servono feature branch, secret eliminati o codice storico, clona il repo e cercalo localmente.
- Anche **GitLab Exact Code Search** ha una limitazione sul **default branch** e indicizza solo i file più piccoli, ma **Advanced Search** può comunque essere utile per cercare commenti, commit e wiki.
- **Sourcebot** indicizza il **default branch** per impostazione predefinita, ma può essere configurato per indicizzare branch/tag aggiuntivi e quindi cercare usando filtri `rev:`, cosa molto comoda per gli audit interni focalizzati su branch/tag quando controlli l'indice.
- La regex search di **Sourcegraph** è generalmente l'opzione più prevedibile per il lavoro offensivo; considera la structural search un bonus opzionale, non una funzionalità garantita. Se il deployment la supporta, le query `type:diff` e `type:commit` sono molto valide per recuperare stringhe eliminate o modifiche recenti rilevanti per la sicurezza.

> [!WARNING]
> Quando cerchi leak in un repo ed esegui qualcosa come `git log -p`, non dimenticare che potrebbero esserci **altri branch con altri commit** contenenti secret!

Per la ricerca dedicata di secret, i dork GitHub a livello di organizzazione e strumenti come TruffleHog/Gitleaks, consulta:

{{#ref}}
github-leaked-secrets.md
{{#endref}}



## Riferimenti

- [Sintassi della GitHub Code Search](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
- [Riferimento sull'uso sicuro di GitHub Actions](https://docs.github.com/en/actions/reference/security/secure-use)
- [Riferimento ai metadata dei Dev Container](https://containers.dev/implementors/json_reference/)
{{#include ../../banners/hacktricks-training.md}}
