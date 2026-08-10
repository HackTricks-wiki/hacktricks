# Wide Source Code Search

Das Ziel dieser Seite ist es, **Plattformen aufzulisten, mit denen du Code durchsuchen kannst** (literal, regex-, symbol- oder pfadbezogen) und zwar über **Tausende/Millionen von Repos** hinweg.

Dies ist nützlich, um:

- **Nach leaked information zu suchen**
- **Nach verwundbaren Mustern zu suchen**
- **Technologien, interne Hosts, CI/CD und Infrastructure-as-Code zu erfassen**
- **Von einem Firmen-/Org-Namen in Repos, Branches und Dateien mit hoher Aussagekraft zu pivotieren**

- [**Sourcebot**](https://www.sourcebot.dev/): Open-Source-/self-hosted Code Search mit regex-, symbol- und filterbasierter Suche über Repositories hinweg. Konfiguriere zusätzliche Branches/Tags und frage sie mit `rev:` ab, wenn die Branch-Abdeckung relevant ist.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- [**Sourcegraph**](https://sourcegraph.com/search): Code Search mit regex-, Boolean-, Symbol-, Repository-/Datei-/Sprach-, Branch-/Commit-, Diff- und Commit-Message-Abfragen.<sup>[[8]](#references)[[10]](#references)</sup> Structural Search ist optional, da die aktuelle Dokumentation beschreibt, dass sie standardmäßig deaktiviert und in ihrer Performance eingeschränkt ist.<sup>[[9]](#references)</sup>
- [**GitHub Code Search**](https://github.com/search): Unterstützt regex, Boolean-Logik und Qualifier wie `repo:`, `org:`, `user:`, `path:`, `language:`, `symbol:`, `content:` und `is:`.<sup>[[1]](#references)</sup>
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/): Code Search auf Basis von Zoekt mit Exact- und regex-Modi sowie Filtern wie `file:`, `lang:`, `repo:` und `sym:`.<sup>[[2]](#references)</sup>
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/) ist ein breiterer Fallback, da damit Code, Kommentare, Commits, Merge Requests und Wikis durchsucht werden können.<sup>[[11]](#references)</sup>
- [**SearchCode**](https://searchcode.com/): Code-Intelligence-Service mit Boolean-/regex-/Structural-Code-Search sowie Datei- und Symbolabruf.<sup>[[12]](#references)</sup>
- [**Grep**](https://grep.app/): Öffentliche Code Search über eine Million GitHub-Repositories hinweg, mit Inhalts-, Datei- und Pfadsuche.<sup>[[13]](#references)</sup>

## Nützliche Search-Funktionen

Beim Audit einer Org im Bug-Bounty-/Red-Team-Kontext sind normalerweise folgende Funktionen am nützlichsten:

- **Regex-Unterstützung**, um Token-Formate, URL-Schemas, gefährliche Funktionsnamen oder mehrzeilige Fragmente zu suchen.
- **Pfadfilter**, um direkt zu Dateien mit hoher Aussagekraft zu springen, etwa `.github/workflows/`, `terraform/`, `helm/`, `.env`, `values.yaml`, `secrets.*`, `credentials.*`, `Dockerfile`, `Jenkinsfile` oder `nginx.conf`.
- **Sprachfilter**, um App-Code von IaC und Pipelines zu trennen.
- **Symbol-aware Search**, um Handler, Auth-Middleware, Webhook-Consumer, gefährliche Hilfsfunktionen oder bestimmte Klassen/Methoden aufzulisten.
- **Boolean-Operatoren**, um Rauschen zu reduzieren: `NOT path:test`, `NOT is:generated`, `NOT is:vendored`, `foo OR bar`.
- **Revision-/Diff-Suche**, sofern verfügbar, damit du **gelöschte Strings wiederherstellen**, **sicherheitsrelevante Änderungen verfolgen** oder **nicht standardmäßige Branches/Tags untersuchen** kannst, ohne vorher alles zu clonen.

## Praktische Methodik

1. **Beginne mit den indexierten Plattformen**, um schnell Repos, Besitzer, Pfade und Code-Familien zu identifizieren.
2. **Pivotiere in Pfade mit hoher Aussagekraft**, anstatt nur nach generischen `password`-/`secret`-Strings zu suchen.
3. **Suche nach Angriffsfläche, nicht nur nach Credentials**:
- CI/CD-Workflows, wiederverwendbare Workflows, Composite Actions und Deployment-Skripte
- Dev Containers-/Codespaces-Bootstrap-Dateien und benutzerdefinierte Features
- Terraform-/Helm-/Kubernetes-Manifeste
- SSO-/OIDC-/SAML-Integrationen
- Interne URLs, Staging-Hosts, Admin-Panels, Message Broker und Callback-Endpunkte
- Gefährliche Code-Pfade (`exec`, Template-Rendering, SSRF-Fetcher, Deserialisierer, ZIP-Extraktion, YAML-Loader usw.)
4. **Clone und suche lokal**, wenn du nicht standardmäßige Branches, die vollständige Historie, bessere regex-Unterstützung oder Bulk-Automatisierung benötigst.
5. **Wechsle zu spezialisierten Scannern**, wenn das Ziel Secrets-Triage oder Verifizierung ist (siehe beispielsweise die entsprechende dedizierte Seite weiter unten).

### Ideen für Abfragen mit hoher Aussagekraft

Diese sind absichtlich breit gehalten, damit du sie an die Syntax von GitHub, GitLab, Sourcegraph oder Sourcebot anpassen kannst:
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
### Neuere, aussagekräftige Dateien, die priorisiert werden sollten

- **`.github/workflows/*.yml`**: Überprüfe privilegierte `pull_request_target`- und `workflow_run`-Trigger sowie Third-Party-`uses:`-Zeilen, die nur auf Tags/Branches statt auf vollständige Commit-SHAs festgelegt sind.<sup>[[3]](#references)</sup> Suche außerdem nach `workflow_call`, `secrets: inherit`, `id-token: write` und `runs-on: self-hosted`.
- **`.devcontainer/devcontainer.json`**, **`.devcontainer/<variant>/devcontainer.json`** und **`.devcontainer.json`**: Suche nach `remoteEnv`, `containerEnv`, `initializeCommand`, `postCreateCommand`, `mounts` sowie referenzierten Dockerfiles/Skripten, um Umgebungswerte, Bootstrap-Befehle, Mounts und zugehörige Dateien zu entdecken.<sup>[[4]](#references)</sup>
- **Dev Container Features** (`devcontainer-feature.json`, `install.sh`): Untersuche beide Dateien, da das minimale Layout eines Features Metadaten und ein `install.sh`-Entry-Point-Skript umfasst.<sup>[[14]](#references)</sup>
- **Weitere CI-/Control-Plane-Dateien**: `.gitlab-ci.yml`, `azure-pipelines.yml`, `cloudbuild.yaml`, `Jenkinsfile`, `buildkite*`, `atlantis.yaml`, `terragrunt.hcl`, `helmfile.yaml`, `skaffold.yaml`, `argocd*`.

### Umfangreiche lokale Suche, wenn die indexierte Suche nicht ausreicht
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
Verwende die lokale Suche, wenn du Folgendes benötigst:

- Nach **nicht standardmäßigen Branches** oder **Tags** suchen
- Die **Git-Historie** durchsuchen
- **PCRE2/multiline**-Abfragen aggressiver ausführen
- Viele Repositories ohne **UI-Limits** per Batch vorsortieren

### Historie, Branches und Diffs explizit durchsuchen
```bash
REPO_DIR=repos/some-repo
git -C "$REPO_DIR" fetch --all --tags --prune

git -C "$REPO_DIR" for-each-ref --format='%(refname:short)' refs/remotes/origin refs/tags \
| while read -r ref; do
git -C "$REPO_DIR" grep -nI -E 'pull_request_target|workflow_call|id-token: write|secrets: inherit|remoteEnv|containerEnv' "$ref" || true
done

git -C "$REPO_DIR" log --all -p -G 'gh[pousr]_|github_pat_|BEGIN [A-Z ]+PRIVATE KEY|internal.*https?://' -- .
```
Dies ist besonders nützlich, wenn der interessante String nur in einem **release branch**, **tag** oder **gelöschten commit** existierte. Wenn deine Sourcegraph-Installation dies unterstützt, sind Suchen mit `type:diff` und `type:commit` ein hervorragender no-clone pivot für dasselbe Problem.<sup>[[8]](#references)[[10]](#references)</sup>

## Häufige blinde Flecken

- **Indexierung nur des default branch** ist üblich. Gehe nicht davon aus, dass die Code-Suche alle branches/tags/den Verlauf abdeckt.
- **Große Dateien, vendored code, generierter code oder Archive** werden möglicherweise übersprungen oder erzeugen viel Rauschen.
- **Kommentare, Issues, PRs, Gists und Wikis** liegen häufig außerhalb des Umfangs einer generischen Code-Suche und erfordern möglicherweise plattformspezifische Tools.
- **Codespaces-/devcontainer-Konfigurationen können branch-spezifisch sein**. Sie können in mehreren `.devcontainer/<variant>/devcontainer.json`-Pfade liegen. Ein sauberer default branch bedeutet daher nicht, dass die Dev-Umgebung überall sauber ist.<sup>[[4]](#references)</sup>
- **Wiederverwendbare Workflows/Actions und devcontainer features können außerhalb der offensichtlichen Datei liegen**. Durchsuche `.github/actions/`, `action.yml`, `action.yaml`, `devcontainer-feature.json` und `install.sh`, nicht nur die Workflow-Datei der obersten Ebene.
- **Die Suchsyntax unterscheidet sich je nach Plattform**. Ein Dork, der in GitHub Code Search funktioniert, benötigt möglicherweise kleine Änderungen für GitLab, Sourcegraph oder Sourcebot.

### Plattform-spezifische Fallstricke

- **GitHub Code Search** ist für schnelle Recon nützlich, durchsucht aber nur den **default branch**. Wenn du feature branches, gelöschte Secrets oder historischen Code benötigst, clone das Repo und durchsuche es lokal.<sup>[[15]](#references)</sup>
- **GitLab Exact Code Search** hat eine Einschränkung auf den **default branch** und indexiert nur Dateien, die kleiner als 1 MB sind und weniger als 20.000 Trigramme enthalten.<sup>[[2]](#references)</sup> **Advanced Search** kann weiterhin Kommentare, Commits und Wikis abdecken.<sup>[[11]](#references)</sup>
- **Sourcebot** indexiert standardmäßig den **default branch**, kann aber so konfiguriert werden, dass zusätzliche branches/tags indexiert werden. Anschließend können sie mit `rev:`-Filtern durchsucht werden, wenn du den Index kontrollierst.<sup>[[7]](#references)</sup>
- **Sourcegraph** unterstützt Regex-, Symbol-, Diff- und Commit-Abfragen. Verwende structural search nur, wenn sie aktiviert ist, und berücksichtige die dokumentierten Performance-Limits.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

> [!WARNING]
> Wenn du in einem Repo nach leaks suchst und etwas wie `git log -p` ausführst, vergiss nicht, dass es **andere branches mit anderen commits** geben kann, die Secrets enthalten!

Für dedizierte Secret-Suche, GitHub-Dorks für ganze Organisationen und Tools wie TruffleHog/Gitleaks siehe [die GitHub-Seite zu geleakten Secrets](github-leaked-secrets.md).

## References

- [1] [GitHub-Code-Search-Syntax](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [2] [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
- [3] [Referenz zur sicheren Verwendung von GitHub Actions](https://docs.github.com/en/actions/reference/security/secure-use)
- [4] [Referenz für Dev-Container-Metadaten](https://containers.dev/implementors/json_reference/)
- [5] [Sourcebot](https://www.sourcebot.dev/)
- [6] [Sourcebot Search API](https://docs.sourcebot.dev/api-reference/search-%26-navigation/search-code)
- [7] [Sourcebot-Indexierung mehrerer branches](https://docs.sourcebot.dev/docs/features/search/multi-branch-indexing)
- [8] [Sourcegraph Code Search](https://sourcegraph.com/docs/code-search)
- [9] [Sourcegraph Structural Search](https://sourcegraph.com/docs/code-search/types/structural)
- [10] [Sourcegraph Search Query Syntax](https://sourcegraph.com/docs/code-search/queries)
- [11] [GitLab Advanced Search](https://docs.gitlab.com/user/search/advanced_search/)
- [12] [SearchCode](https://searchcode.com/)
- [13] [Grep.app](https://grep.app/)
- [14] [Erstellen eines Dev-Container-Features](https://containers.dev/guide/author-a-feature)
- [15] [Tools zur Untersuchung von Sicherheitsvorfällen](https://docs.github.com/en/enterprise-cloud%40latest/code-security/reference/security-incident-response/investigation-tools)
{{#include ../../banners/hacktricks-training.md}}
