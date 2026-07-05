# Wide Source Code Search

{{#include ../../banners/hacktricks-training.md}}

Das Ziel dieser Seite ist es, **Plattformen aufzulisten, die es dir erlauben, Code zu durchsuchen** (literal, regex, symbol-aware oder pfadbezogen) über **tausende/Millionen von Repos**.

Das ist nützlich für:

- **Suche nach geleakten Informationen**
- **Suche nach verwundbaren Mustern**
- **Technologien, interne Hosts, CI/CD und infrastructure-as-code erfassen**
- **Von einem Unternehmens-/Org-Namen zu Repos, Branches und High-Signal-Dateien pivotieren**

- [**Sourcebot**](https://www.sourcebot.dev/): Open-source/self-hosted code search. Sehr nützlich, wenn du **viele Repos** indexieren willst und, falls konfiguriert, zusätzliche Branches/Tags, während du Regex-Filter wie `repo:`, `file:`, `lang:`, `rev:` und `sym:` beibehältst.
- [**SourceGraph**](https://sourcegraph.com/search): Suche in Millionen von Repos. Regex ist normalerweise die sicherste Option; structural search existiert in einigen Deployments, hat aber Performance-Einschränkungen und ist nicht immer aktiviert.
- [**GitHub Code Search**](https://github.com/search): Unterstützt regex, boolean logic und Qualifier wie `repo:`, `org:`, `user:`, `path:`, `language:`, `symbol:`, `content:` und `is:`.
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/): Moderne GitLab code search, betrieben von Zoekt. Unterstützt exact- und regex-Modi mit Filtern wie `file:`, `lang:`, `repo:` und `sym:`.
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/) ist weiterhin als breiter Fallback nützlich, weil damit code, comments, commits, merge requests und wikis durchsucht werden können.
- [**SearchCode**](https://searchcode.com/): Suche code in Millionen von Projekten.

## Nützliche Suchfunktionen

Beim Auditing einer Org in einem bug bounty/red team-Kontext sind die nützlichsten Funktionen normalerweise:

- **Regex**-Support, um nach Token-Formaten, URL-Schemata, gefährlichen Funktionsnamen oder mehrzeiligen Fragmenten zu suchen.
- **Path-Filter**, um direkt zu hochwertigen Dateien zu springen wie `.github/workflows/`, `terraform/`, `helm/`, `.env`, `values.yaml`, `secrets.*`, `credentials.*`, `Dockerfile`, `Jenkinsfile` oder `nginx.conf`.
- **Language-Filter**, um App-Code von IaC und Pipelines zu trennen.
- **Symbol-aware search**, um Handler, Auth-Middleware, Webhook-Consumer, gefährliche Helper-Funktionen oder bestimmte Klassen/Methoden zu enumerieren.
- **Boolean operators**, um Rauschen zu reduzieren: `NOT path:test`, `NOT is:generated`, `NOT is:vendored`, `foo OR bar`.

## Praktische Methodik

1. **Beginne mit den indexierten Plattformen**, um schnell Repos, Owner, Pfade und Code-Familien zu identifizieren.
2. **Pivotiere in High-Signal-Locations**, statt nur nach allgemeinen `password`/`secret`-Strings zu suchen.
3. **Suche nach Attack Surface, nicht nur nach Credentials**:
- CI/CD-Workflows und Deployment-Skripte
- Terraform/Helm/Kubernetes-Manifeste
- SSO/OIDC/SAML-Integrationen
- Interne URLs, Staging-Hosts, Admin-Panels, Message Broker und Callback-Endpunkte
- Gefährliche Code-Pfade (`exec`, template rendering, SSRF fetchers, deserializers, ZIP extraction, YAML loaders, etc.)
4. **Clone und lokal suchen**, wenn du nicht-Standard-Branches, den vollständigen Verlauf, bessere Regex-Unterstützung oder Bulk-Automation brauchst.
5. **Zu spezialisierten Scannern eskalieren**, wenn das Ziel secrets triage oder verification ist (siehe zum Beispiel die dedizierte Seite unten).

### High-Signal Query-Ideen

Diese sind absichtlich breit gehalten, damit du sie an die Syntax von GitHub, GitLab, Sourcegraph oder Sourcebot anpassen kannst:
```text
org:target path:.github/workflows ("pull_request_target" OR "workflow_run" OR "ACTIONS_STEP_DEBUG")
org:target (path:terraform OR path:helm OR language:HCL OR language:YAML) ("role_arn" OR "assume_role" OR "client_secret" OR "access_key")
org:target ("BEGIN PRIVATE KEY" OR "ghp_" OR "github_pat_" OR "AIza" OR "xoxb-")
org:target (path:.env OR path:values.yaml OR path:application-prod OR path:credentials)
org:target ("internal" OR "corp" OR "staging") ("https://" OR "ssh://") NOT path:test
```
### Mass lokale Suche, wenn indexierte Suche nicht ausreicht
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
Nutze lokales Suchen, wenn du Folgendes brauchst:

- Suche in **Nicht-Standard-Branches** oder **Tags**
- Suche in der **Git-History**
- Führe **PCRE2/multiline**-Abfragen aggressiver aus
- Verarbeite viele Repositories stapelweise ohne UI-Limits

## Häufige Blindstellen

- **Indexierung nur des Default-Branches** ist üblich. Gehe nicht davon aus, dass Code Search alle Branches/Tags/History abdeckt.
- **Große Dateien, vendorter Code, generierter Code oder Archive** können übersprungen oder unübersichtlich sein.
- **Kommentare, Issues, PRs, Gists und Wikis** liegen oft außerhalb des Bereichs generischer Code Search und erfordern möglicherweise plattformspezifische Tools.
- **Die Suchsyntax unterscheidet sich je nach Plattform**. Ein Dork, der in GitHub Code Search funktioniert, braucht vielleicht kleine Anpassungen für GitLab, Sourcegraph oder Sourcebot.

### Plattformspezifische Stolperfallen

- **GitHub Code Search** ist hervorragend für schnelle recon, durchsucht aber nur den **Default-Branch**. Wenn du Feature-Branches, gelöschte secrets oder historischen Code brauchst, klone das Repo und suche lokal darin.
- **GitLab Exact Code Search** hat ebenfalls eine **Default-Branch**-Einschränkung und indexiert nur kleinere Dateien, aber **Advanced Search** kann trotzdem nützlich sein, um Kommentare, Commits und Wikis zu durchsuchen.
- **Sourcebot** indexiert standardmäßig den **Default-Branch**, kann aber so konfiguriert werden, dass zusätzliche Branches/Tags indexiert werden und dann mit `rev:`-Filtern durchsucht werden können. Das ist sehr praktisch für interne Audits mit Fokus auf Branches/Tags, wenn du den Index kontrollierst.
- **Sourcegraph** Regex-Suche ist im Allgemeinen die vorhersehbarste Option für offensive work; behandle structural search als optionalen Bonus, nicht als garantierte Fähigkeit.

> [!WARNING]
> Wenn du in einem Repo nach leaks suchst und etwas wie `git log -p` ausführst, vergiss nicht, dass es **andere Branches mit anderen Commits** geben könnte, die secrets enthalten!

Für gezieltes secret hunting, org-weite GitHub dorks und Tools wie TruffleHog/Gitleaks, siehe:

{{#ref}}
github-leaked-secrets.md
{{#endref}}



## References

- [GitHub Code Search syntax](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
{{#include ../../banners/hacktricks-training.md}}
