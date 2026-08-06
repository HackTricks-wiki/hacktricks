# Ricerca ampia del codice sorgente

{{#include ../../banners/hacktricks-training.md}}

L'obiettivo di questa pagina è elencare le **piattaforme che consentono di cercare nel codice** (letterale, regex, consapevole dei simboli o con ambito limitato al percorso) attraverso **migliaia/milioni di repo**.

Questo è utile per:

- **Cercare informazioni sottoposte a leak**
- **Cercare pattern vulnerabili**
- **Mappare tecnologie, host interni, CI/CD e infrastructure-as-code**
- **Fare pivot dal nome di un'azienda/org verso repo, branch e file ad alto valore informativo**

- [**Sourcebot**](https://www.sourcebot.dev/): code search open-source/self-hosted. Molto utile quando vuoi indicizzare **molti repo** e, se configurato, branch/tag aggiuntivi mantenendo filtri regex come `repo:`, `file:`, `lang:`, `rev:` e `sym:`.
- [**SourceGraph**](https://sourcegraph.com/search): Cerca in milioni di repo. Regex è solitamente l'opzione più sicura; structural search è disponibile in alcune deployment, ma presenta limitazioni di performance e non è sempre abilitata.
- [**GitHub Code Search**](https://github.com/search): Supporta regex, logica booleana e qualificatori come `repo:`, `org:`, `user:`, `path:`, `language:`, `symbol:`, `content:` e `is:`.<sup>[[1]](#references)</sup>
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/): La moderna code search di GitLab, basata su Zoekt. Supporta modalità exact e regex con filtri come `file:`, `lang:`, `repo:` e `sym:`.<sup>[[2]](#references)</sup>
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/) è ancora utile come fallback più ampio, perché può cercare nel codice, nei commenti, nei commit, nelle merge request e nelle wiki.
- [**SearchCode**](https://searchcode.com/): Cerca codice in milioni di progetti.
- [**Grep**](https://grep.app/): Ricerca pubblica veloce su un corpus GitHub molto ampio. Utile quando vuoi una seconda visualizzazione dell'indicizzazione/ranking per i pivot su **content**, **file** e **path**.

## Capacità di ricerca utili

Quando esegui l'audit di un'org in un contesto di bug bounty/red team, le capacità più utili sono generalmente:

- Supporto **Regex** per cercare formati di token, schemi URL, nomi di funzioni pericolose o frammenti multilinea.
- **Filtri sui path** per raggiungere direttamente file ad alto valore come `.github/workflows/`, `terraform/`, `helm/`, `.env`, `values.yaml`, `secrets.*`, `credentials.*`, `Dockerfile`, `Jenkinsfile` o `nginx.conf`.
- **Filtri per linguaggio** per separare il codice dell'app da IaC e pipeline.
- **Ricerca consapevole dei simboli** per enumerare handler, middleware di autenticazione, consumer di webhook, funzioni helper pericolose o classi/metodi specifici.
- **Operatori booleani** per ridurre il rumore: `NOT path:test`, `NOT is:generated`, `NOT is:vendored`, `foo OR bar`.
- **Ricerca delle revision/diff** quando disponibile, così da poter recuperare **stringhe eliminate**, seguire **modifiche rilevanti per la sicurezza** o analizzare **branch/tag non predefiniti** senza clonare tutto in anticipo.

## Metodologia pratica

1. **Inizia dalle piattaforme indicizzate** per identificare rapidamente repo, owner, path e famiglie di codice.
2. **Fai pivot verso le posizioni ad alto valore informativo** invece di cercare soltanto stringhe generiche come `password`/`secret`.
3. **Cerca la attack surface, non solo le credenziali**:
- Workflow CI/CD, workflow riutilizzabili, composite action e script di deployment
- File di bootstrap e custom feature di Dev Containers / Codespaces
- Manifest Terraform/Helm/Kubernetes
- Integrazioni SSO/OIDC/SAML
- URL interni, host di staging, pannelli di amministrazione, message broker ed endpoint di callback
- Code path pericolosi (`exec`, template rendering, fetcher SSRF, deserializer, estrazione ZIP, YAML loader, ecc.)
4. **Clona e cerca localmente** quando ti servono branch non predefiniti, la cronologia completa, un supporto regex migliore o l'automazione in massa.
5. **Passa a scanner dedicati** quando l'obiettivo è il triage o la verifica dei secret (per esempio, consulta la pagina dedicata sotto).

### Idee per query ad alto valore informativo

Sono intenzionalmente ampie, così puoi adattarle alla sintassi di GitHub, GitLab, Sourcegraph o Sourcebot:
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

- **`.github/workflows/*.yml`**: Cerca `pull_request_target`, `workflow_run`, `workflow_call`, `secrets: inherit`, `id-token: write`, `runs-on: self-hosted` e righe `uses:` di terze parti bloccate solo su tag/branch anziché su SHA completi dei commit.<sup>[[3]](#references)</sup>
- **`.devcontainer/devcontainer.json`**, **`.devcontainer/<variant>/devcontainer.json`** e **`.devcontainer.json`**: Cerca `remoteEnv`, `containerEnv`, `initializeCommand`, `postCreateCommand`, `mounts` e i Dockerfile/script referenziati. Spesso espongono registri di pacchetti interni, URL di bootstrap, mount dell'host ed endpoint riservati agli sviluppatori.<sup>[[4]](#references)</sup>
- **Dev Container Features** (`devcontainer-feature.json`, `install.sh`): Sono ottimi per individuare la logica di installer specifica dell'organizzazione che viene eseguita durante la creazione dell'ambiente.
- **Altri file CI/control-plane**: `.gitlab-ci.yml`, `azure-pipelines.yml`, `cloudbuild.yaml`, `Jenkinsfile`, `buildkite*`, `atlantis.yaml`, `terragrunt.hcl`, `helmfile.yaml`, `skaffold.yaml`, `argocd*`.

### Ricerca locale massiva quando la ricerca indicizzata non è sufficiente
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
Usa la ricerca locale quando ti serve:

- Cercare nei **branch** o nei **tag** non predefiniti
- Cercare nella **cronologia di git**
- Eseguire query **PCRE2/multiline** in modo più aggressivo
- Eseguire il triage in batch di molti repository senza i limiti dell'UI

### Cerca esplicitamente nella cronologia, nei branch e nei diffiyanas
```bash
REPO_DIR=repos/some-repo
git -C "$REPO_DIR" fetch --all --tags --prune

git -C "$REPO_DIR" for-each-ref --format='%(refname:short)' refs/remotes/origin refs/tags \
| while read -r ref; do
git -C "$REPO_DIR" grep -nI -E 'pull_request_target|workflow_call|id-token: write|secrets: inherit|remoteEnv|containerEnv' "$ref" || true
done

git -C "$REPO_DIR" log --all -p -G 'gh[pousr]_|github_pat_|BEGIN [A-Z ]+PRIVATE KEY|internal.*https?://' -- .
```
Questo è particolarmente utile quando la stringa interessante esisteva solo in un **release branch**, **tag** o **deleted commit**. Se il tuo deployment di Sourcegraph lo supporta, le ricerche `type:diff` e `type:commit` sono un ottimo pivot senza clone per lo stesso problema.

## Punti ciechi comuni

- L'indicizzazione **solo del default branch** è comune. Non dare per scontato che la ricerca del codice copra tutti i branch/tag/history.
- **File di grandi dimensioni, codice vendorizzato, codice generato o archivi** possono essere ignorati o produrre molto rumore.
- **Commenti, issue, PR, gist e wiki** spesso non rientrano nell'ambito della ricerca generica del codice e possono richiedere tooling specifico della piattaforma.
- Le configurazioni di **Codespaces / devcontainer possono essere specifiche per branch** e trovarsi in diversi percorsi `.devcontainer/<variant>/devcontainer.json`; quindi un default branch pulito non significa che il dev environment sia pulito ovunque.
- **Reusable workflows/actions e devcontainer features possono trovarsi al di fuori del file ovvio**. Cerca in `.github/actions/`, `action.yml`, `action.yaml`, `devcontainer-feature.json` e `install.sh`, non solo nel file workflow di primo livello.
- La **sintassi di ricerca varia in base alla piattaforma**. Un dork che funziona in GitHub Code Search potrebbe richiedere piccole modifiche per GitLab, Sourcegraph o Sourcebot.

### Problemi specifici della piattaforma

- **GitHub Code Search** è eccellente per una ricognizione rapida, ma cerca solo nel **default branch**. Se ti servono feature branch, secret eliminati o codice storico, clona il repo e cercalo localmente.
- **GitLab Exact Code Search** ha anch'esso una limitazione sul **default branch** e indicizza solo i file più piccoli, ma **Advanced Search** può comunque essere utile per cercare commenti, commit e wiki.<sup>[[2]](#references)</sup>
- **Sourcebot** indicizza il **default branch** per impostazione predefinita, ma può essere configurato per indicizzare branch/tag aggiuntivi e quindi cercarli con filtri `rev:`; è molto pratico per audit interni focalizzati su branch/tag quando controlli l'indice.
- La ricerca regex di **Sourcegraph** è generalmente l'opzione più prevedibile per il lavoro offensivo; considera la ricerca strutturale un bonus opzionale, non una funzionalità garantita. Se il deployment la supporta, le query `type:diff` e `type:commit` sono molto efficaci per recuperare stringhe eliminate o modifiche recenti rilevanti per la sicurezza.

> [!WARNING]
> Quando cerchi leak in un repo ed esegui qualcosa come `git log -p`, non dimenticare che potrebbero esserci **altri branch con altri commit** contenenti secrets!

Per la ricerca dedicata di secrets, i dork GitHub a livello di organizzazione e strumenti come TruffleHog/Gitleaks, consulta:

{{#ref}}
github-leaked-secrets.md
{{#endref}}

## References

- [1] [GitHub Code Search syntax](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [2] [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
- [3] [GitHub Actions secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [4] [Dev Container metadata reference](https://containers.dev/implementors/json_reference/)

{{#include ../../banners/hacktricks-training.md}}
