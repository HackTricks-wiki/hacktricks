# Búsqueda amplia de código fuente

{{#include ../../banners/hacktricks-training.md}}

El objetivo de esta página es enumerar **plataformas que permiten buscar código** (literal, regex, con reconocimiento de símbolos o limitando por rutas) en **miles o millones de repositorios**.

Esto resulta útil para:

- **Buscar información filtrada**
- **Buscar patrones vulnerables**
- **Mapear tecnologías, hosts internos, CI/CD e infraestructura como código**
- **Pivotar desde el nombre de una empresa/organización hacia repositorios, ramas y archivos con señales de alto valor**

- [**Sourcebot**](https://www.sourcebot.dev/): Búsqueda de código open source y self-hosted. Muy útil cuando quieres indexar **muchos repositorios** y, si está configurado, también ramas/tags adicionales, manteniendo filtros regex como `repo:`, `file:`, `lang:`, `rev:` y `sym:`.
- [**SourceGraph**](https://sourcegraph.com/search): Busca en millones de repositorios. Regex suele ser la opción más segura; la búsqueda estructural existe en algunos despliegues, pero tiene limitaciones de rendimiento y no siempre está habilitada.
- [**GitHub Code Search**](https://github.com/search): Admite regex, lógica booleana y qualifiers como `repo:`, `org:`, `user:`, `path:`, `language:`, `symbol:`, `content:` e `is:`.
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/): Búsqueda moderna de código de GitLab basada en Zoekt. Admite modos exacto y regex, con filtros como `file:`, `lang:`, `repo:` y `sym:`.
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/) sigue siendo útil como alternativa más amplia, ya que puede buscar en código, comentarios, commits, merge requests y wikis.
- [**SearchCode**](https://searchcode.com/): Busca código en millones de proyectos.
- [**Grep**](https://grep.app/): Búsqueda pública rápida en un corpus muy grande de GitHub. Es útil cuando quieres una segunda perspectiva de indexación/clasificación para pivotar por **contenido**, **archivo** y **ruta**.

## Capacidades de búsqueda útiles

Al auditar una organización en un contexto de bug bounty/red team, las capacidades más útiles suelen ser:

- Compatibilidad con **Regex** para buscar formatos de tokens, esquemas de URL, nombres de funciones peligrosas o fragmentos multilínea.
- **Filtros de ruta** para acceder directamente a archivos de alto valor como `.github/workflows/`, `terraform/`, `helm/`, `.env`, `values.yaml`, `secrets.*`, `credentials.*`, `Dockerfile`, `Jenkinsfile` o `nginx.conf`.
- **Filtros de lenguaje** para separar el código de la aplicación de IaC y los pipelines.
- **Búsqueda con reconocimiento de símbolos** para enumerar handlers, middleware de autenticación, consumidores de webhooks, funciones helper peligrosas o clases/métodos específicos.
- **Operadores booleanos** para reducir el ruido: `NOT path:test`, `NOT is:generated`, `NOT is:vendored`, `foo OR bar`.
- **Búsqueda por revisión/diff** cuando esté disponible, para poder recuperar **strings eliminados**, seguir **cambios relevantes para la seguridad** o inspeccionar **ramas/tags que no sean los predeterminados** sin clonar todo primero.

## Metodología práctica

1. **Empieza con las plataformas indexadas** para identificar rápidamente repositorios, propietarios, rutas y familias de código.
2. **Haz pivot hacia ubicaciones con señales de alto valor** en lugar de buscar únicamente strings genéricos como `password`/`secret`.
3. **Busca superficie de ataque, no solo credenciales**:
- Workflows de CI/CD, workflows reutilizables, composite actions y scripts de despliegue
- Archivos de bootstrap de Dev Containers / Codespaces y features personalizadas
- Manifiestos de Terraform/Helm/Kubernetes
- Integraciones SSO/OIDC/SAML
- URLs internas, hosts de staging, paneles de administración, message brokers y endpoints de callback
- Rutas de código peligrosas (`exec`, renderizado de templates, fetchers SSRF, deserializadores, extracción de ZIP, cargadores YAML, etc.)
4. **Clona y busca localmente** cuando necesites ramas que no sean la predeterminada, el historial completo, mejor compatibilidad con regex o automatización masiva.
5. **Escala a scanners especializados** cuando el objetivo sea el triage o la verificación de secrets (por ejemplo, consulta la página específica que aparece más abajo).

### Ideas de queries con señales de alto valor

Estas ideas son intencionadamente amplias para que puedas adaptarlas a la sintaxis de GitHub, GitLab, Sourcegraph o Sourcebot:
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
### Archivos más nuevos y de alta señal que conviene priorizar

- **`.github/workflows/*.yml`**: Busca `pull_request_target`, `workflow_run`, `workflow_call`, `secrets: inherit`, `id-token: write`, `runs-on: self-hosted` y líneas de terceros `uses:` fijadas únicamente a tags/branches en lugar de SHA completos de commits.
- **`.devcontainer/devcontainer.json`**, **`.devcontainer/<variant>/devcontainer.json`** y **`.devcontainer.json`**: Busca `remoteEnv`, `containerEnv`, `initializeCommand`, `postCreateCommand`, `mounts` y los Dockerfiles/scripts referenciados. Estos suelen exponer registros de paquetes internos, URLs de bootstrap, montajes del host y endpoints exclusivos para desarrolladores.
- **Dev Container Features** (`devcontainer-feature.json`, `install.sh`): Son excelentes para encontrar lógica de instalación específica de la organización que se ejecuta durante la creación del entorno.
- **Otros archivos de CI/control plane**: `.gitlab-ci.yml`, `azure-pipelines.yml`, `cloudbuild.yaml`, `Jenkinsfile`, `buildkite*`, `atlantis.yaml`, `terragrunt.hcl`, `helmfile.yaml`, `skaffold.yaml`, `argocd*`.

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
Usa la búsqueda local cuando necesites:

- Buscar **branches no predeterminadas** o **tags**
- Buscar en el **historial de git**
- Ejecutar consultas **PCRE2/multiline** de forma más agresiva
- Hacer **triage** por lotes de muchos repositorios sin los límites de la UI

### Busca explícitamente en el historial, las branches y los diffs
```bash
REPO_DIR=repos/some-repo
git -C "$REPO_DIR" fetch --all --tags --prune

git -C "$REPO_DIR" for-each-ref --format='%(refname:short)' refs/remotes/origin refs/tags \
| while read -r ref; do
git -C "$REPO_DIR" grep -nI -E 'pull_request_target|workflow_call|id-token: write|secrets: inherit|remoteEnv|containerEnv' "$ref" || true
done

git -C "$REPO_DIR" log --all -p -G 'gh[pousr]_|github_pat_|BEGIN [A-Z ]+PRIVATE KEY|internal.*https?://' -- .
```
Esto resulta especialmente útil cuando la string interesante solo existía en una **release branch**, **tag** o **deleted commit**. Si tu implementación de Sourcegraph lo admite, las búsquedas `type:diff` y `type:commit` son un excelente pivot sin clonar para el mismo problema.

## Puntos ciegos comunes

- Es común que la indexación solo cubra la **default branch**. No asumas que la búsqueda de código cubre todas las branches/tags/historial.
- Los archivos grandes, el código de terceros, el código generado o los archivos comprimidos pueden omitirse o generar ruido.
- Los comentarios, issues, PRs, gists y wikis suelen quedar fuera del alcance de la búsqueda de código genérica y pueden requerir tooling específico de la plataforma.
- Las configuraciones de Codespaces / devcontainer pueden ser específicas de una branch y encontrarse en varias rutas `.devcontainer/<variant>/devcontainer.json`, por lo que una default branch limpia no significa que el entorno de desarrollo esté limpio en todas partes.
- Los reusable workflows/actions y las devcontainer features pueden encontrarse fuera del archivo obvio. Busca en `.github/actions/`, `action.yml`, `action.yaml`, `devcontainer-feature.json` e `install.sh`, no solo en el archivo de workflow de nivel superior.
- La sintaxis de búsqueda varía según la plataforma. Un dork que funciona en GitHub Code Search puede necesitar pequeños cambios para GitLab, Sourcegraph o Sourcebot.

### Problemas específicos de cada plataforma

- **GitHub Code Search** es excelente para hacer recon rápidamente, pero solo busca en la **default branch**. Si necesitas feature branches, secrets eliminados o código histórico, clona el repo y búscalo localmente.
- **GitLab Exact Code Search** también tiene una limitación de **default branch** e indexa únicamente archivos más pequeños, pero **Advanced Search** todavía puede ser útil para buscar comentarios, commits y wikis.
- **Sourcebot** indexa la **default branch** de forma predeterminada, pero puede configurarse para indexar branches/tags adicionales y después buscarse con filtros `rev:`, lo que resulta muy conveniente para auditorías internas centradas en branches/tags cuando controlas el índice.
- La búsqueda mediante regex de **Sourcegraph** suele ser la opción más predecible para trabajos ofensivos; considera la búsqueda estructural como una ventaja opcional, no como una capacidad garantizada. Si la implementación lo admite, las consultas `type:diff` y `type:commit` son muy buenas para recuperar strings eliminadas o cambios recientes relevantes para la seguridad.

> [!WARNING]
> Cuando busques leaks en un repo y ejecutes algo como `git log -p`, ¡no olvides que puede haber **otras branches con otros commits** que contengan secrets!

Para la búsqueda específica de secrets, los GitHub dorks para toda la organización y herramientas como TruffleHog/Gitleaks, consulta:

{{#ref}}
github-leaked-secrets.md
{{#endref}}



## Referencias

- [Sintaxis de GitHub Code Search](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
- [Referencia de uso seguro de GitHub Actions](https://docs.github.com/en/actions/reference/security/secure-use)
- [Referencia de metadatos de Dev Container](https://containers.dev/implementors/json_reference/)
{{#include ../../banners/hacktricks-training.md}}
