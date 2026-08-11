# Búsqueda amplia de código fuente

{{#include ../../banners/hacktricks-training.md}}

El objetivo de esta página es enumerar **plataformas que permiten buscar código** (literal, mediante regex, orientado a símbolos o limitado por rutas) en **miles o millones de repos**.

Esto resulta útil para:

- **Buscar información filtrada**
- **Buscar patrones vulnerables**
- **Mapear tecnologías, hosts internos, CI/CD e infraestructura como código**
- **Pasar del nombre de una empresa/organización a repos, ramas y archivos de alto valor**

- [**Sourcebot**](https://www.sourcebot.dev/): Code search de código open source/self-hosted con regex, símbolos y filtros en repositorios. Configura ramas/tags adicionales y consúltalos con `rev:` cuando la cobertura de ramas sea importante.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- [**Sourcegraph**](https://sourcegraph.com/search): Code search con consultas de regex, booleanas, símbolos, repositorios/archivos/lenguajes, ramas/commits, diffs y mensajes de commit.<sup>[[8]](#references)[[10]](#references)</sup> Structural search es opcional porque la documentación actual indica que está desactivado por defecto y limitado en rendimiento.<sup>[[9]](#references)</sup>
- [**GitHub Code Search**](https://github.com/search): Admite regex, lógica booleana y qualifiers como `repo:`, `org:`, `user:`, `path:`, `language:`, `symbol:`, `content:` e `is:`.<sup>[[1]](#references)</sup>
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/): Code search basado en Zoekt, con modos exact y regex, además de filtros como `file:`, `lang:`, `repo:` y `sym:`.<sup>[[2]](#references)</sup>
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/) es una alternativa más amplia porque puede buscar en código, comentarios, commits, merge requests y wikis.<sup>[[11]](#references)</sup>
- [**SearchCode**](https://searchcode.com/): Servicio de code intelligence con búsqueda de código booleana, mediante regex y estructural, además de recuperación de archivos y símbolos.<sup>[[12]](#references)</sup>
- [**Grep**](https://grep.app/): Búsqueda pública de código en un millón de repositorios de GitHub, con búsqueda de contenido, archivos y rutas.<sup>[[13]](#references)</sup>

## Capacidades de búsqueda útiles

Al auditar una organización en un contexto de bug bounty/red team, las capacidades más útiles suelen ser:

- Compatibilidad con **regex** para buscar formatos de tokens, esquemas de URL, nombres de funciones peligrosas o fragmentos multilínea.
- **Filtros de rutas** para acceder directamente a archivos de alto valor como `.github/workflows/`, `terraform/`, `helm/`, `.env`, `values.yaml`, `secrets.*`, `credentials.*`, `Dockerfile`, `Jenkinsfile` o `nginx.conf`.
- **Filtros de lenguaje** para separar el código de la aplicación de IaC y los pipelines.
- **Búsqueda orientada a símbolos** para enumerar handlers, middleware de autenticación, consumidores de webhooks, funciones auxiliares peligrosas o clases/métodos específicos.
- **Operadores booleanos** para reducir el ruido: `NOT path:test`, `NOT is:generated`, `NOT is:vendored`, `foo OR bar`.
- **Búsqueda de revisiones/diffs** cuando esté disponible, para poder recuperar **cadenas eliminadas**, seguir **cambios relevantes para la seguridad** o inspeccionar **ramas/tags que no sean los predeterminados** sin clonar todo previamente.

## Metodología práctica

1. **Empieza con las plataformas indexadas** para identificar rápidamente repos, propietarios, rutas y familias de código.
2. **Pasa a ubicaciones de alto valor** en lugar de buscar únicamente cadenas genéricas como `password`/`secret`.
3. **Busca superficie de ataque, no solo credenciales**:
- Workflows de CI/CD, workflows reutilizables, composite actions y scripts de despliegue
- Archivos de bootstrap de Dev Containers / Codespaces y features personalizadas
- Manifiestos de Terraform/Helm/Kubernetes
- Integraciones de SSO/OIDC/SAML
- URLs internas, hosts de staging, paneles de administración, message brokers y endpoints de callback
- Rutas de código peligrosas (`exec`, renderizado de plantillas, fetchers SSRF, deserializadores, extracción de ZIP, cargadores YAML, etc.)
4. **Clona y busca localmente** cuando necesites ramas que no sean las predeterminadas, el historial completo, mejor compatibilidad con regex o automatización masiva.
5. **Escala a scanners especializados** cuando el objetivo sea clasificar o verificar secrets (por ejemplo, consulta la página dedicada a continuación).

### Ideas de consultas de alto valor

Estas consultas son intencionadamente amplias para que puedas adaptarlas a la sintaxis de GitHub, GitLab, Sourcegraph o Sourcebot:
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
### Archivos más recientes y de alta señal que vale la pena priorizar

- **`.github/workflows/*.yml`**: Revisa los triggers privilegiados `pull_request_target` y `workflow_run`, así como las líneas `uses:` de terceros fijadas únicamente a tags/branches en lugar de a commits SHA completos.<sup>[[3]](#references)</sup> Busca también `workflow_call`, `secrets: inherit`, `id-token: write` y `runs-on: self-hosted`.
- **`.devcontainer/devcontainer.json`**, **`.devcontainer/<variant>/devcontainer.json`** y **`.devcontainer.json`**: Busca `remoteEnv`, `containerEnv`, `initializeCommand`, `postCreateCommand`, `mounts` y los Dockerfiles/scripts referenciados para descubrir valores de entorno, comandos de bootstrap, montajes y archivos relacionados.<sup>[[4]](#references)</sup>
- **Dev Container Features** (`devcontainer-feature.json`, `install.sh`): Inspecciona ambos archivos porque el layout mínimo de una Feature incluye metadatos y un script de entrada `install.sh`.<sup>[[14]](#references)</sup>
- **Otros archivos de CI/control-plane**: `.gitlab-ci.yml`, `azure-pipelines.yml`, `cloudbuild.yaml`, `Jenkinsfile`, `buildkite*`, `atlantis.yaml`, `terragrunt.hcl`, `helmfile.yaml`, `skaffold.yaml`, `argocd*`.

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

- Buscar en **branches** o **tags** que no sean los predeterminados
- Buscar en el **historial de git**
- Ejecutar consultas **PCRE2/multiline** de forma más agresiva
- Hacer un **triage** por lotes de muchos repositorios sin los límites de la UI

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
Esto es especialmente útil cuando el string interesante solo existía en una **release branch**, **tag** o **deleted commit**. Si tu implementación de Sourcegraph lo admite, las búsquedas `type:diff` y `type:commit` son un excelente pivote sin clonar para el mismo problema.<sup>[[8]](#references)[[10]](#references)</sup>

## Common blind spots

- La **indexación exclusiva de la default branch** es común. No asumas que la búsqueda de código cubre todas las branches/tags/historial.
- Los **archivos grandes, código vendorizado, código generado o archivos comprimidos** pueden omitirse o generar ruido.
- Los **comentarios, issues, PRs, gists y wikis** suelen estar fuera del alcance de la búsqueda de código genérica y pueden requerir tooling específico de la plataforma.
- Las configuraciones de **Codespaces / devcontainer pueden ser específicas de cada branch**. Pueden estar en varias rutas `.devcontainer/<variant>/devcontainer.json`, por lo que una default branch limpia no significa que el entorno de desarrollo esté limpio en todas partes.<sup>[[4]](#references)</sup>
- Los **workflows/actions reutilizables y las devcontainer features pueden estar fuera del archivo obvio**. Busca `.github/actions/`, `action.yml`, `action.yaml`, `devcontainer-feature.json` e `install.sh`, no solo el archivo de workflow de nivel superior.
- La **sintaxis de búsqueda difiere según la plataforma**. Un dork que funciona en GitHub Code Search puede necesitar pequeños cambios para GitLab, Sourcegraph o Sourcebot.

### Platform-specific gotchas

- **GitHub Code Search** es útil para una recon rápida, pero solo busca en la **default branch**. Si necesitas feature branches, secrets eliminados o código histórico, clona el repo y búscalo localmente.<sup>[[15]](#references)</sup>
- **GitLab Exact Code Search** tiene una limitación de **default branch** y solo indexa archivos de menos de 1 MB con menos de 20.000 trigramas.<sup>[[2]](#references)</sup> **Advanced Search** aún puede cubrir comentarios, commits y wikis.<sup>[[11]](#references)</sup>
- **Sourcebot** indexa la **default branch** de forma predeterminada, pero puede configurarse para indexar branches/tags adicionales y luego buscarse con filtros `rev:` cuando controlas el índice.<sup>[[7]](#references)</sup>
- **Sourcegraph** admite consultas regex, de símbolos, diff y commit; usa la búsqueda estructural solo donde esté habilitada y ten en cuenta sus límites de rendimiento documentados.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

> [!WARNING]
> Cuando busques leaks en un repo y ejecutes algo como `git log -p`, ¡no olvides que podría haber **otras branches con otros commits** que contengan secrets!

Para la búsqueda específica de secrets, los dorks de GitHub para toda la organización y herramientas como TruffleHog/Gitleaks, consulta [la página de secrets filtrados de GitHub](github-leaked-secrets.md).

## References

- [1] [Sintaxis de GitHub Code Search](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [2] [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
- [3] [Referencia sobre uso seguro de GitHub Actions](https://docs.github.com/en/actions/reference/security/secure-use)
- [4] [Referencia de metadatos de Dev Container](https://containers.dev/implementors/json_reference/)
- [5] [Sourcebot](https://www.sourcebot.dev/)
- [6] [API de búsqueda de Sourcebot](https://docs.sourcebot.dev/api-reference/search-%26-navigation/search-code)
- [7] [Indexación multi-branch de Sourcebot](https://docs.sourcebot.dev/docs/features/search/multi-branch-indexing)
- [8] [Sourcegraph Code Search](https://sourcegraph.com/docs/code-search)
- [9] [Sourcegraph Structural Search](https://sourcegraph.com/docs/code-search/types/structural)
- [10] [Sintaxis de consultas de Sourcegraph Search](https://sourcegraph.com/docs/code-search/queries)
- [11] [GitLab Advanced Search](https://docs.gitlab.com/user/search/advanced_search/)
- [12] [SearchCode](https://searchcode.com/)
- [13] [Grep.app](https://grep.app/)
- [14] [Authoring a Dev Container Feature](https://containers.dev/guide/author-a-feature)
- [15] [Herramientas de investigación para incidentes de seguridad](https://docs.github.com/en/enterprise-cloud%40latest/code-security/reference/security-incident-response/investigation-tools)
{{#include ../../banners/hacktricks-training.md}}
