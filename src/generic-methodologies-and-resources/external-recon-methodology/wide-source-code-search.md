# Breite Source-Code-Suche

{{#include ../../banners/hacktricks-training.md}}

Ziel dieser Seite ist es, **Plattformen aufzulisten, die die Suche in Code ermöglichen** (literal, per Regex, symbolbasiert oder auf Pfade beschränkt) und zwar über **Tausende/Millionen von Repos** hinweg.

Dies ist nützlich, um:

- **Nach geleakten Informationen zu suchen**
- **Nach verwundbaren Mustern zu suchen**
- **Technologien, interne Hosts, CI/CD und Infrastructure-as-Code zu erfassen**
- **Von einem Unternehmens-/Org-Namen zu Repos, Branches und aussagekräftigen Dateien zu pivotieren**

- [**Sourcebot**](https://www.sourcebot.dev/): Open-Source-/selbst gehostete Code-Suche. Sehr nützlich, wenn du **viele Repos** indexieren und bei entsprechender Konfiguration zusätzliche Branches/Tags einbeziehen möchtest, während du Regex-Filter wie `repo:`, `file:`, `lang:`, `rev:` und `sym:` beibehältst.
- [**SourceGraph**](https://sourcegraph.com/search): Suche in Millionen von Repos. Regex ist normalerweise die sicherste Option; strukturelle Suche ist in einigen Deployments verfügbar, hat jedoch Performance-Einschränkungen und ist nicht immer aktiviert.
- [**GitHub Code Search**](https://github.com/search): Unterstützt Regex, boolesche Logik und Qualifier wie `repo:`, `org:`, `user:`, `path:`, `language:`, `symbol:`, `content:` und `is:`.<sup>[[1]](#references)</sup>
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/): Moderne GitLab-Code-Suche auf Basis von Zoekt. Unterstützt exakte und Regex-Modi mit Filtern wie `file:`, `lang:`, `repo:` und `sym:`.<sup>[[2]](#references)</sup>
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/) ist weiterhin als umfassenderer Fallback nützlich, da damit Code, Kommentare, Commits, Merge Requests und Wikis durchsucht werden können.
- [**SearchCode**](https://searchcode.com/): Suche in Millionen von Projekten.
- [**Grep**](https://grep.app/): Schnelle öffentliche Suche über einen sehr großen GitHub-Korpus. Nützlich, wenn du eine zweite Indexierungs-/Ranking-Ansicht für **Content**-, **File**- und **Path**-Pivots benötigst.

## Nützliche Suchfunktionen

Beim Audit einer Org im Bug-Bounty-/Red-Team-Kontext sind in der Regel folgende Funktionen am nützlichsten:

- Unterstützung für **Regex**, um nach Token-Formaten, URL-Schemata, gefährlichen Funktionsnamen oder mehrzeiligen Fragmenten zu suchen.
- **Pfadfilter**, um direkt zu besonders wertvollen Dateien wie `.github/workflows/`, `terraform/`, `helm/`, `.env`, `values.yaml`, `secrets.*`, `credentials.*`, `Dockerfile`, `Jenkinsfile` oder `nginx.conf` zu springen.
- **Sprachfilter**, um App-Code von IaC und Pipelines zu trennen.
- **Symbolbasierte Suche**, um Handler, Auth-Middleware, Webhook-Consumer, gefährliche Hilfsfunktionen oder bestimmte Klassen/Methoden aufzulisten.
- **Boolesche Operatoren**, um das Rauschen zu reduzieren: `NOT path:test`, `NOT is:generated`, `NOT is:vendored`, `foo OR bar`.
- **Revision-/Diff-Suche**, sofern verfügbar, damit du **gelöschte Strings** wiederherstellen, **sicherheitsrelevante Änderungen** verfolgen oder **nicht standardmäßige Branches/Tags** untersuchen kannst, ohne vorher alles zu clonen.

## Praktische Methodik

1. **Beginne mit den indexierten Plattformen**, um schnell Repos, Besitzer, Pfade und Codefamilien zu identifizieren.
2. **Pivotiere in aussagekräftige Bereiche**, anstatt nur nach generischen `password`-/`secret`-Strings zu suchen.
3. **Suche nach Angriffsfläche und nicht nur nach Credentials**:
- CI/CD-Workflows, wiederverwendbare Workflows, Composite Actions und Deployment-Skripte
- Dev-Containers-/Codespaces-Bootstrap-Dateien und benutzerdefinierte Features
- Terraform-/Helm-/Kubernetes-Manifeste
- SSO-/OIDC-/SAML-Integrationen
- Interne URLs, Staging-Hosts, Admin-Panels, Message Broker und Callback-Endpunkte
- Gefährliche Codepfade (`exec`, Template-Rendering, SSRF-Fetcher, Deserialisierer, ZIP-Extraktion, YAML-Loader usw.)
4. **Clone und durchsuche lokal**, wenn du nicht standardmäßige Branches, die vollständige Historie, bessere Regex-Unterstützung oder Bulk-Automatisierung benötigst.
5. **Weite auf dedizierte Scanner aus**, wenn das Ziel die Triage oder Verifizierung von Secrets ist (siehe beispielsweise die untenstehende dedizierte Seite).

### Ideen für aussagekräftige Suchanfragen

Diese sind absichtlich allgemein gehalten, damit du sie an die Syntax von GitHub, GitLab, Sourcegraph oder Sourcebot anpassen kannst:
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
### Neuere Dateien mit hoher Aussagekraft, die priorisiert werden sollten

- **`.github/workflows/*.yml`**: Suche nach `pull_request_target`, `workflow_run`, `workflow_call`, `secrets: inherit`, `id-token: write`, `runs-on: self-hosted` sowie nach Zeilen mit Drittanbieter-`uses:`, die nur auf Tags/Branches anstelle vollständiger Commit-SHAs festgelegt sind.<sup>[[3]](#references)</sup>
- **`.devcontainer/devcontainer.json`**, **`.devcontainer/<variant>/devcontainer.json`** und **`.devcontainer.json`**: Suche nach `remoteEnv`, `containerEnv`, `initializeCommand`, `postCreateCommand`, `mounts` sowie referenzierten Dockerfiles/Skripten. Diese legen häufig interne Package-Registries, Bootstrap-URLs, Host-Mounts und nur für Entwickler bestimmte Endpoints offen.<sup>[[4]](#references)</sup>
- **Dev Container Features** (`devcontainer-feature.json`, `install.sh`): Besonders geeignet, um organisationsspezifische Installer-Logik zu finden, die während der Umgebungserstellung ausgeführt wird.
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

- Suche in **nicht standardmäßigen Branches** oder **Tags**
- Suche in der **git-Historie**
- Führe **PCRE2-/Multiline**-Abfragen aggressiver aus
- Führe ein **Batch-Triage** vieler Repositories ohne **UI-Limits** durch

### Durchsuche Verlauf, Branches und Diffs explizit
```bash
REPO_DIR=repos/some-repo
git -C "$REPO_DIR" fetch --all --tags --prune

git -C "$REPO_DIR" for-each-ref --format='%(refname:short)' refs/remotes/origin refs/tags \
| while read -r ref; do
git -C "$REPO_DIR" grep -nI -E 'pull_request_target|workflow_call|id-token: write|secrets: inherit|remoteEnv|containerEnv' "$ref" || true
done

git -C "$REPO_DIR" log --all -p -G 'gh[pousr]_|github_pat_|BEGIN [A-Z ]+PRIVATE KEY|internal.*https?://' -- .
```
Dies ist besonders nützlich, wenn der interessante String nur in einem **release branch**, **tag** oder **gelöschten commit** existierte. Wenn deine Sourcegraph-Deployment dies unterstützt, sind Suchen mit `type:diff` und `type:commit` ein hervorragender no-clone-Pivot für dasselbe Problem.

## Häufige blinde Flecken

- **Indexierung ausschließlich des Default-Branches** ist üblich. Gehe nicht davon aus, dass die Code-Suche alle Branches/Tags/History abdeckt.
- **Große Dateien, vendored code, generierter Code oder Archive** können übersprungen werden oder für Rauschen sorgen.
- **Kommentare, Issues, PRs, Gists und Wikis** liegen oft außerhalb des Umfangs einer generischen Code-Suche und erfordern möglicherweise plattformspezifische Tools.
- **Codespaces-/devcontainer-Konfigurationen können branch-spezifisch sein** und in mehreren `.devcontainer/<variant>/devcontainer.json`-Pfade liegen. Ein sauberer Default-Branch bedeutet daher nicht, dass die Dev-Umgebung überall sauber ist.
- **Wiederverwendbare Workflows/Actions und devcontainer features können außerhalb der offensichtlichen Datei liegen**. Durchsuche `.github/actions/`, `action.yml`, `action.yaml`, `devcontainer-feature.json` und `install.sh`, nicht nur die Workflow-Datei auf der obersten Ebene.
- **Die Suchsyntax unterscheidet sich je nach Plattform**. Ein Dork, der in GitHub Code Search funktioniert, benötigt möglicherweise kleine Änderungen für GitLab, Sourcegraph oder Sourcebot.

### Plattformspezifische Stolpersteine

- **GitHub Code Search** eignet sich hervorragend für schnelle Recon, durchsucht aber nur den **Default-Branch**. Wenn du Feature-Branches, gelöschte Secrets oder historischen Code benötigst, clone das Repo und durchsuche es lokal.
- **GitLab Exact Code Search** ist ebenfalls auf den **Default-Branch** beschränkt und indexiert nur kleinere Dateien, aber **Advanced Search** kann weiterhin nützlich sein, um Kommentare, Commits und Wikis zu durchsuchen.<sup>[[2]](#references)</sup>
- **Sourcebot** indexiert standardmäßig den **Default-Branch**, kann aber so konfiguriert werden, dass zusätzliche Branches/Tags indexiert und anschließend mit `rev:`-Filtern durchsucht werden. Das ist sehr praktisch für interne Audits mit Fokus auf Branches/Tags, wenn du den Index kontrollierst.
- Die Regex-Suche von **Sourcegraph** ist für offensive Arbeit im Allgemeinen die vorhersehbarste Option. Betrachte die strukturelle Suche als optionalen Bonus und nicht als garantierte Funktion. Wenn die Deployment dies unterstützt, eignen sich `type:diff`- und `type:commit`-Abfragen sehr gut, um gelöschte Strings oder aktuelle sicherheitsrelevante Änderungen wiederherzustellen.

> [!WARNING]
> Wenn du in einem Repo nach leaks suchst und etwas wie `git log -p` ausführst, vergiss nicht, dass es **andere Branches mit anderen Commits** geben kann, die Secrets enthalten!

Für dediziertes Secret Hunting, GitHub-Dorks für die gesamte Organisation und Tools wie TruffleHog/Gitleaks siehe:

{{#ref}}
github-leaked-secrets.md
{{#endref}}

## Referenzen

- [1] [GitHub Code Search syntax](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [2] [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
- [3] [GitHub Actions secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [4] [Dev Container metadata reference](https://containers.dev/implementors/json_reference/)

{{#include ../../banners/hacktricks-training.md}}
