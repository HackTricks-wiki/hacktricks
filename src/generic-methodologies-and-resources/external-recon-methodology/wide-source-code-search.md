# Wide Source Code Search

{{#include ../../banners/hacktricks-training.md}}

El objetivo de esta página es enumerar **platforms que permiten buscar code** (literal, regex, symbol-aware, o path-scoped) en **miles/millones de repos**.

Esto es útil para:

- **Buscar información leak**
- **Buscar patrones vulnerables**
- **Mapear tecnologías, hosts internos, CI/CD e infrastructure-as-code**
- **Pivotar desde el nombre de una empresa/org hacia repos, branches y archivos de alta señal**

- [**Sourcebot**](https://www.sourcebot.dev/): Búsqueda de code open-source/self-hosted. Muy útil cuando quieres indexar **muchos repos** y, si está configurado, branches/tags adicionales manteniendo filtros regex como `repo:`, `file:`, `lang:`, `rev:` y `sym:`.
- [**SourceGraph**](https://sourcegraph.com/search): Busca en millones de repos. Regex suele ser la opción más segura; la búsqueda estructural existe en algunos despliegues, pero tiene limitaciones de rendimiento y no siempre está habilitada.
- [**GitHub Code Search**](https://github.com/search): Soporta regex, lógica booleana y qualifiers como `repo:`, `org:`, `user:`, `path:`, `language:`, `symbol:`, `content:` e `is:`.
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/): Búsqueda moderna de code en GitLab impulsada por Zoekt. Soporta modos exacto y regex con filtros como `file:`, `lang:`, `repo:` y `sym:`.
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/) sigue siendo útil como fallback más amplio porque puede buscar code, comentarios, commits, merge requests y wikis.
- [**SearchCode**](https://searchcode.com/): Busca code en millones de proyectos.

## Useful search capabilities

Cuando auditas una org en un contexto de bug bounty/red team, las capacidades más útiles suelen ser:

- Soporte de **Regex** para buscar formatos de tokens, esquemas de URL, nombres de funciones peligrosas o fragmentos multilinea.
- **Path filters** para ir directamente a archivos de alto valor como `.github/workflows/`, `terraform/`, `helm/`, `.env`, `values.yaml`, `secrets.*`, `credentials.*`, `Dockerfile`, `Jenkinsfile` o `nginx.conf`.
- **Language filters** para separar code de app de IaC y pipelines.
- **Symbol-aware search** para enumerar handlers, auth middleware, consumidores de webhooks, funciones helper peligrosas o clases/métodos específicos.
- **Boolean operators** para reducir ruido: `NOT path:test`, `NOT is:generated`, `NOT is:vendored`, `foo OR bar`.

## Practical methodology

1. **Empieza con las platforms indexadas** para identificar rápidamente repos, owners, paths y familias de code.
2. **Pivota hacia ubicaciones de alta señal** en lugar de buscar solo cadenas genéricas como `password` o `secret`.
3. **Busca attack surface, no solo credentials**:
- workflows de CI/CD y scripts de deployment
- manifiestos de Terraform/Helm/Kubernetes
- integraciones SSO/OIDC/SAML
- URLs internas, hosts de staging, admin panels, message brokers y callback endpoints
- rutas de code peligrosas (`exec`, template rendering, SSRF fetchers, deserializers, ZIP extraction, YAML loaders, etc.)
4. **Clona y busca localmente** cuando necesites branches no predeterminadas, historial completo, mejor soporte regex o automatización masiva.
5. **Escala a scanners dedicados** cuando el objetivo sea triage o verificación de secrets (por ejemplo, mira la página dedicada abajo).

### High-signal query ideas

Estas están intencionalmente amplias para que puedas adaptarlas a la sintaxis de GitHub, GitLab, Sourcegraph o Sourcebot:
```text
org:target path:.github/workflows ("pull_request_target" OR "workflow_run" OR "ACTIONS_STEP_DEBUG")
org:target (path:terraform OR path:helm OR language:HCL OR language:YAML) ("role_arn" OR "assume_role" OR "client_secret" OR "access_key")
org:target ("BEGIN PRIVATE KEY" OR "ghp_" OR "github_pat_" OR "AIza" OR "xoxb-")
org:target (path:.env OR path:values.yaml OR path:application-prod OR path:credentials)
org:target ("internal" OR "corp" OR "staging") ("https://" OR "ssh://") NOT path:test
```
### Búsqueda local masiva cuando la búsqueda indexada no es suficiente
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
Usa búsqueda local cuando lo necesites para:

- Buscar **ramas no predeterminadas** o **tags**
- Buscar en el **historial de git**
- Ejecutar consultas **PCRE2/multiline** de forma más agresiva
- Hacer triage por lotes de muchos repositorios sin límites de UI

## Puntos ciegos comunes

- El **indexado solo de la rama predeterminada** es común. No asumas que la búsqueda de código cubre todas las ramas/tags/historial.
- **Archivos grandes, código vendorizado, código generado o archives** pueden omitirse o generar ruido.
- **Comments, issues, PRs, gists y wikis** a menudo quedan fuera del alcance de la búsqueda genérica de código y pueden requerir herramientas específicas de la plataforma.
- La **sintaxis de búsqueda difiere según la plataforma**. Un dork que funciona en GitHub Code Search puede necesitar pequeños cambios para GitLab, Sourcegraph o Sourcebot.

### Gotchas específicos de la plataforma

- **GitHub Code Search** es excelente para recon rápido, pero busca solo en la **default branch**. Si necesitas feature branches, secretos eliminados o código histórico, clona el repo y búscalo localmente.
- **GitLab Exact Code Search** también tiene una limitación de **default-branch** e indexa solo archivos más pequeños, pero **Advanced Search** puede seguir siendo útil para buscar comments, commits y wikis.
- **Sourcebot** indexa la **default branch** por defecto, pero puede configurarse para indexar branches/tags adicionales y luego buscarse con filtros `rev:`, lo cual es muy conveniente para auditorías internas enfocadas en ramas/tags cuando controlas el índice.
- La búsqueda regex de **Sourcegraph** suele ser la opción más predecible para offensive work; trata la búsqueda estructural como un extra opcional, no como una capacidad garantizada.

> [!WARNING]
> Cuando busques leaks en un repo y ejecutes algo como `git log -p` no olvides que puede haber **otras ramas con otros commits** que contengan secrets!

Para secret hunting dedicado, dorks de GitHub a nivel de org y herramientas como TruffleHog/Gitleaks, consulta:

{{#ref}}
github-leaked-secrets.md
{{#endref}}



## References

- [GitHub Code Search syntax](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
{{#include ../../banners/hacktricks-training.md}}
