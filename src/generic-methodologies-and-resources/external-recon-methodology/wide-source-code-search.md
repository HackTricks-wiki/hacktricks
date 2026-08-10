# Ricerca estesa del codice sorgente

L'obiettivo di questa pagina è elencare le **piattaforme che consentono di cercare nel codice** (letteralmente, con regex, in base ai simboli o limitando la ricerca ai percorsi) in **migliaia/milioni di repo**.

Questo è utile per:

- **Cercare informazioni sottoposte a leak**
- **Cercare pattern vulnerabili**
- **Mappare tecnologie, host interni, CI/CD e infrastructure-as-code**
- **Partire dal nome di un'azienda/org per raggiungere repo, branch e file ad alto segnale**

- [**Sourcebot**](https://www.sourcebot.dev/): Code search open-source/self-hosted con regex, simboli e filtri tra i repository. Configura branch/tag aggiuntivi e interrogali con `rev:` quando la copertura dei branch è importante.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- [**Sourcegraph**](https://sourcegraph.com/search): Code search con query regex, booleane, basate su simboli, repository/file/linguaggio, branch/commit, diff e messaggi di commit.<sup>[[8]](#references)[[10]](#references)</sup> La ricerca strutturale è opzionale perché la documentazione attuale la descrive come disabilitata per impostazione predefinita e limitata in termini di performance.<sup>[[9]](#references)</sup>
- [**GitHub Code Search**](https://github.com/search): Supporta regex, logica booleana e qualificatori come `repo:`, `org:`, `user:`, `path:`, `language:`, `symbol:`, `content:` e `is:`.<sup>[[1]](#references)</sup>
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/): Code search basato su Zoekt, con modalità exact e regex e filtri come `file:`, `lang:`, `repo:` e `sym:`.<sup>[[2]](#references)</sup>
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/) è un fallback più ampio perché può cercare codice, commenti, commit, merge request e wiki.<sup>[[11]](#references)</sup>
- [**SearchCode**](https://searchcode.com/): Servizio di code intelligence con code search booleana/regex/strutturale e recupero di file e simboli.<sup>[[12]](#references)</sup>
- [**Grep**](https://grep.app/): Code search pubblico su un milione di repository GitHub, con ricerca nel contenuto, nei file e nei percorsi.<sup>[[13]](#references)</sup>

## Funzionalità di ricerca utili

Quando si esegue l'audit di un'org in un contesto di bug bounty/red team, le funzionalità più utili sono solitamente:

- Supporto **Regex** per cercare formati di token, schemi URL, nomi di funzioni pericolose o frammenti multilinea.
- **Filtri per percorso** per raggiungere direttamente file di alto valore come `.github/workflows/`, `terraform/`, `helm/`, `.env`, `values.yaml`, `secrets.*`, `credentials.*`, `Dockerfile`, `Jenkinsfile` o `nginx.conf`.
- **Filtri per linguaggio** per separare il codice dell'app da IaC e pipeline.
- **Ricerca basata sui simboli** per enumerare handler, middleware di autenticazione, consumer di webhook, funzioni helper pericolose o classi/metodi specifici.
- **Operatori booleani** per ridurre il rumore: `NOT path:test`, `NOT is:generated`, `NOT is:vendored`, `foo OR bar`.
- **Ricerca per revisione/diff** quando disponibile, così da poter recuperare **stringhe eliminate**, seguire **modifiche rilevanti per la sicurezza** o analizzare **branch/tag non predefiniti** senza dover prima clonare tutto.

## Metodologia pratica

1. **Inizia dalle piattaforme indicizzate** per identificare rapidamente repo, proprietari, percorsi e famiglie di codice.
2. **Passa alle posizioni ad alto segnale** invece di cercare soltanto stringhe generiche come `password`/`secret`.
3. **Cerca la superficie d'attacco, non solo le credenziali**:
- Workflow CI/CD, reusable workflow, composite action e script di deployment
- File bootstrap di Dev Containers / Codespaces e custom feature
- Manifest Terraform/Helm/Kubernetes
- Integrazioni SSO/OIDC/SAML
- URL interni, host di staging, pannelli di amministrazione, message broker ed endpoint di callback
- Percorsi di codice pericolosi (`exec`, rendering di template, fetcher SSRF, deserializer, estrazione ZIP, loader YAML, ecc.)
4. **Clona e cerca localmente** quando servono branch non predefiniti, la cronologia completa, un supporto regex migliore o l'automazione massiva.
5. **Passa a scanner dedicati** quando l'obiettivo è il triage o la verifica dei secrets (ad esempio, consulta la pagina dedicata di seguito).

### Idee per query ad alto segnale

Queste sono intenzionalmente ampie, così puoi adattarle alla sintassi di GitHub, GitLab, Sourcegraph o Sourcebot:
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

- **`.github/workflows/*.yml`**: Esamina i trigger privilegiati `pull_request_target` e `workflow_run` e le righe `uses:` di terze parti fissate solo a tag/branch invece che a commit SHA completi.<sup>[[3]](#references)</sup> Cerca anche `workflow_call`, `secrets: inherit`, `id-token: write` e `runs-on: self-hosted`.
- **`.devcontainer/devcontainer.json`**, **`.devcontainer/<variant>/devcontainer.json`** e **`.devcontainer.json`**: Cerca `remoteEnv`, `containerEnv`, `initializeCommand`, `postCreateCommand`, `mounts` e i Dockerfile/script referenziati per individuare valori di ambiente, comandi di bootstrap, mount e file correlati.<sup>[[4]](#references)</sup>
- **Dev Container Features** (`devcontainer-feature.json`, `install.sh`): Esamina entrambi i file perché il layout minimo di una Feature include i metadati e uno script `install.sh` come entrypoint.<sup>[[14]](#references)</sup>
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
Usa la ricerca locale quando devi:

- Cercare **non-default branches** o **tags**
- Cercare nella **git history**
- Eseguire query **PCRE2/multiline** in modo più aggressivo
- Eseguire il **batch triage** di molti repository senza i limiti dell'interfaccia

### Cerca esplicitamente nella history, nei branch e nei diff
```bash
REPO_DIR=repos/some-repo
git -C "$REPO_DIR" fetch --all --tags --prune

git -C "$REPO_DIR" for-each-ref --format='%(refname:short)' refs/remotes/origin refs/tags \
| while read -r ref; do
git -C "$REPO_DIR" grep -nI -E 'pull_request_target|workflow_call|id-token: write|secrets: inherit|remoteEnv|containerEnv' "$ref" || true
done

git -C "$REPO_DIR" log --all -p -G 'gh[pousr]_|github_pat_|BEGIN [A-Z ]+PRIVATE KEY|internal.*https?://' -- .
```
Questo è particolarmente utile quando la stringa interessante esisteva soltanto in un **release branch**, in un **tag** o in un **commit eliminato**. Se la tua installazione di Sourcegraph lo supporta, le ricerche `type:diff` e `type:commit` sono un ottimo pivot senza clone per lo stesso problema.<sup>[[8]](#references)[[10]](#references)</sup>

## Punti ciechi comuni

- L'**indicizzazione limitata al default branch** è comune. Non dare per scontato che la ricerca del codice copra tutti i branch/tag/la cronologia.
- **File di grandi dimensioni, codice vendored, codice generato o archivi** potrebbero essere ignorati o produrre risultati rumorosi.
- **Commenti, issue, PR, gist e wiki** sono spesso al di fuori dell'ambito della ricerca generica del codice e potrebbero richiedere strumenti specifici della piattaforma.
- Le configurazioni di **Codespaces / devcontainer possono essere specifiche per branch**. Possono trovarsi in diversi percorsi `.devcontainer/<variant>/devcontainer.json`, quindi un default branch pulito non significa che l'ambiente di sviluppo sia pulito ovunque.<sup>[[4]](#references)</sup>
- **Reusable workflow/action e devcontainer feature possono trovarsi al di fuori del file ovvio**. Cerca `.github/actions/`, `action.yml`, `action.yaml`, `devcontainer-feature.json` e `install.sh`, non soltanto il file workflow di primo livello.
- La **sintassi di ricerca varia a seconda della piattaforma**. Un dork che funziona in GitHub Code Search potrebbe richiedere piccole modifiche per GitLab, Sourcegraph o Sourcebot.

### Problemi specifici della piattaforma

- **GitHub Code Search** è utile per una recon rapida, ma cerca soltanto nel **default branch**. Se ti servono feature branch, secret eliminati o codice storico, clona la repo e cercala localmente.<sup>[[15]](#references)</sup>
- **GitLab Exact Code Search** ha una limitazione sul **default branch** e indicizza soltanto file più piccoli di 1 MB con meno di 20.000 trigrammi.<sup>[[2]](#references)</sup> **Advanced Search** può comunque coprire commenti, commit e wiki.<sup>[[11]](#references)</sup>
- **Sourcebot** indicizza il **default branch** per impostazione predefinita, ma può essere configurato per indicizzare branch/tag aggiuntivi e poi cercare usando filtri `rev:` quando controlli l'indice.<sup>[[7]](#references)</sup>
- **Sourcegraph** supporta query regex, symbol, diff e commit; usa la structural search soltanto dove è abilitata e considera i limiti di performance documentati.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

> [!WARNING]
> Quando cerchi leak in una repo ed esegui qualcosa come `git log -p`, non dimenticare che potrebbero esserci **altri branch con altri commit** contenenti secret!

Per la ricerca dedicata di secret, i dork GitHub a livello di organizzazione e strumenti come TruffleHog/Gitleaks, consulta [la pagina sui secret leak di GitHub](github-leaked-secrets.md).

## References

- [1] [Sintassi di GitHub Code Search](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [2] [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
- [3] [Riferimento sull'uso sicuro di GitHub Actions](https://docs.github.com/en/actions/reference/security/secure-use)
- [4] [Riferimento ai metadati dei Dev Container](https://containers.dev/implementors/json_reference/)
- [5] [Sourcebot](https://www.sourcebot.dev/)
- [6] [API di ricerca di Sourcebot](https://docs.sourcebot.dev/api-reference/search-%26-navigation/search-code)
- [7] [Indicizzazione multi-branch di Sourcebot](https://docs.sourcebot.dev/docs/features/search/multi-branch-indexing)
- [8] [Code Search di Sourcegraph](https://sourcegraph.com/docs/code-search)
- [9] [Structural Search di Sourcegraph](https://sourcegraph.com/docs/code-search/types/structural)
- [10] [Sintassi delle query di ricerca di Sourcegraph](https://sourcegraph.com/docs/code-search/queries)
- [11] [Advanced Search di GitLab](https://docs.gitlab.com/user/search/advanced_search/)
- [12] [SearchCode](https://searchcode.com/)
- [13] [Grep.app](https://grep.app/)
- [14] [Creazione di una Dev Container Feature](https://containers.dev/guide/author-a-feature)
- [15] [Strumenti di investigazione per gli incidenti di sicurezza](https://docs.github.com/en/enterprise-cloud%40latest/code-security/reference/security-incident-response/investigation-tools)
{{#include ../../banners/hacktricks-training.md}}
