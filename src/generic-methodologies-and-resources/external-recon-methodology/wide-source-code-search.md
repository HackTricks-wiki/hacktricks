# Busca ampla de código-fonte

{{#include ../../banners/hacktricks-training.md}}

O objetivo desta página é enumerar **plataformas que permitem pesquisar código** (literal, regex, com reconhecimento de símbolos ou limitado por caminho) em **milhares/milhões de repos**.

Isso é útil para:

- **Pesquisar informações vazadas**
- **Pesquisar padrões vulneráveis**
- **Mapear tecnologias, hosts internos, CI/CD e infraestrutura como código**
- **Fazer pivot do nome de uma empresa/organização para repos, branches e arquivos de alto sinal**

- [**Sourcebot**](https://www.sourcebot.dev/): Ferramenta open source/self-hosted de busca de código. Muito útil quando você deseja indexar **muitos repos** e, se configurado, branches/tags adicionais, mantendo filtros regex como `repo:`, `file:`, `lang:`, `rev:` e `sym:`.
- [**SourceGraph**](https://sourcegraph.com/search): Pesquisa em milhões de repos. Regex geralmente é a opção mais segura; structural search existe em algumas implementações, mas apresenta limitações de desempenho e nem sempre está habilitado.
- [**GitHub Code Search**](https://github.com/search): Oferece suporte a regex, lógica booleana e qualificadores como `repo:`, `org:`, `user:`, `path:`, `language:`, `symbol:`, `content:` e `is:`.
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/): Busca moderna de código do GitLab, baseada no Zoekt. Oferece suporte aos modos exact e regex, com filtros como `file:`, `lang:`, `repo:` e `sym:`.
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/) ainda é útil como um fallback mais amplo, pois pode pesquisar código, comentários, commits, merge requests e wikis.
- [**SearchCode**](https://searchcode.com/): Pesquisa código em milhões de projetos.
- [**Grep**](https://grep.app/): Busca pública rápida em um corpus muito grande do GitHub. Útil quando você deseja uma segunda perspectiva de indexação/classificação para pivots de **content**, **file** e **path**.

## Recursos úteis de busca

Ao auditar uma organização no contexto de bug bounty/red team, os recursos mais úteis geralmente são:

- Suporte a **Regex** para pesquisar formatos de tokens, esquemas de URL, nomes de funções perigosas ou fragmentos multilinha.
- **Filtros de caminho** para acessar diretamente arquivos de alto valor, como `.github/workflows/`, `terraform/`, `helm/`, `.env`, `values.yaml`, `secrets.*`, `credentials.*`, `Dockerfile`, `Jenkinsfile` ou `nginx.conf`.
- **Filtros de linguagem** para separar código da aplicação de IaC e pipelines.
- **Busca com reconhecimento de símbolos** para enumerar handlers, middleware de autenticação, consumidores de webhook, funções auxiliares perigosas ou classes/métodos específicos.
- **Operadores booleanos** para reduzir ruído: `NOT path:test`, `NOT is:generated`, `NOT is:vendored`, `foo OR bar`.
- **Busca por revisão/diff**, quando disponível, para recuperar **strings excluídas**, acompanhar **alterações relevantes para segurança** ou inspecionar **branches/tags não padrão** sem clonar tudo primeiro.

## Metodologia prática

1. **Comece pelas plataformas indexadas** para identificar rapidamente repos, proprietários, caminhos e famílias de código.
2. **Faça pivot para locais de alto sinal** em vez de pesquisar apenas strings genéricas como `password`/`secret`.
3. **Pesquise a superfície de ataque, não apenas credenciais**:
- Workflows de CI/CD, reusable workflows, composite actions e scripts de deployment
- Arquivos de inicialização de Dev Containers / Codespaces e custom features
- Manifestos de Terraform/Helm/Kubernetes
- Integrações de SSO/OIDC/SAML
- URLs internas, hosts de staging, painéis de administração, message brokers e endpoints de callback
- Caminhos de código perigosos (`exec`, renderização de templates, fetchers de SSRF, desserializadores, extração de ZIP, YAML loaders etc.)
4. **Clone e pesquise localmente** quando precisar de branches não padrão, histórico completo, melhor suporte a regex ou automação em massa.
5. **Escale para scanners dedicados** quando o objetivo for a triagem ou verificação de secrets (por exemplo, consulte a página dedicada abaixo).

### Ideias de queries de alto sinal

Estas ideias são intencionalmente amplas para que você possa adaptá-las à sintaxe do GitHub, GitLab, Sourcegraph ou Sourcebot:
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
### Arquivos mais recentes e de alto sinal que vale a pena priorizar

- **`.github/workflows/*.yml`**: Procure por `pull_request_target`, `workflow_run`, `workflow_call`, `secrets: inherit`, `id-token: write`, `runs-on: self-hosted` e linhas de terceiros com `uses:` fixadas apenas em tags/branches, em vez de SHAs de commits completos.
- **`.devcontainer/devcontainer.json`**, **`.devcontainer/<variant>/devcontainer.json`** e **`.devcontainer.json`**: Pesquise por `remoteEnv`, `containerEnv`, `initializeCommand`, `postCreateCommand`, `mounts` e Dockerfiles/scripts referenciados. Eles frequentemente expõem registries internos de pacotes, URLs de bootstrap, mounts do host e endpoints exclusivos para developers.
- **Dev Container Features** (`devcontainer-feature.json`, `install.sh`): Ótimos para encontrar a lógica de instalação específica da organização que é executada durante a criação do ambiente.
- **Outros arquivos de CI/control plane**: `.gitlab-ci.yml`, `azure-pipelines.yml`, `cloudbuild.yaml`, `Jenkinsfile`, `buildkite*`, `atlantis.yaml`, `terragrunt.hcl`, `helmfile.yaml`, `skaffold.yaml`, `argocd*`.

### Busca local em massa quando a busca indexada não é suficiente
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
Use a busca local quando precisar:

- Pesquisar **branches** ou **tags** que não sejam padrão
- Pesquisar o **histórico do git**
- Executar consultas **PCRE2/multiline** de forma mais agressiva
- Fazer a triagem em lote de muitos repositórios sem limites de UI

### Pesquise explicitamente no histórico, nas branches e nos diffs
```bash
REPO_DIR=repos/some-repo
git -C "$REPO_DIR" fetch --all --tags --prune

git -C "$REPO_DIR" for-each-ref --format='%(refname:short)' refs/remotes/origin refs/tags \
| while read -r ref; do
git -C "$REPO_DIR" grep -nI -E 'pull_request_target|workflow_call|id-token: write|secrets: inherit|remoteEnv|containerEnv' "$ref" || true
done

git -C "$REPO_DIR" log --all -p -G 'gh[pousr]_|github_pat_|BEGIN [A-Z ]+PRIVATE KEY|internal.*https?://' -- .
```
Isso é especialmente útil quando a string interessante existia apenas em uma **release branch**, **tag** ou **deleted commit**. Se sua implantação do Sourcegraph oferecer suporte, as buscas `type:diff` e `type:commit` são um excelente **no-clone pivot** para o mesmo problema.

## Pontos cegos comuns

- A indexação **apenas da default branch** é comum. Não presuma que a busca de código cobre todas as branches/tags/histórico.
- **Arquivos grandes, código vendorizado, código gerado ou archives** podem ser ignorados ou gerar muito ruído.
- **Comentários, issues, PRs, gists e wikis** geralmente estão fora do escopo da busca de código genérica e podem exigir ferramentas específicas da plataforma.
- As configurações de **Codespaces / devcontainer** podem ser específicas de cada branch e estar em vários caminhos `.devcontainer/<variant>/devcontainer.json`; portanto, uma default branch limpa não significa que o ambiente de desenvolvimento esteja limpo em todos os lugares.
- **Reusable workflows/actions e devcontainer features** podem estar fora do arquivo óbvio. Pesquise `.github/actions/`, `action.yml`, `action.yaml`, `devcontainer-feature.json` e `install.sh`, não apenas o arquivo de workflow no nível superior.
- A sintaxe de busca varia por plataforma. Um dork que funciona no GitHub Code Search pode precisar de pequenas alterações no GitLab, Sourcegraph ou Sourcebot.

### Particularidades específicas da plataforma

- O **GitHub Code Search** é excelente para recon rápida, mas pesquisa apenas a **default branch**. Se precisar de feature branches, secrets deletados ou código histórico, faça clone do repo e pesquise localmente.
- O **GitLab Exact Code Search** também tem uma limitação de **default branch** e indexa apenas arquivos menores, mas a **Advanced Search** ainda pode ser útil para pesquisar comentários, commits e wikis.
- O **Sourcebot** indexa a **default branch** por padrão, mas pode ser configurado para indexar branches/tags adicionais e, depois, pesquisado com filtros `rev:`, o que é muito conveniente para auditorias internas focadas em branch/tag quando você controla o índice.
- A busca regex do **Sourcegraph** geralmente é a opção mais previsível para trabalho ofensivo; trate a busca estrutural como um recurso opcional, não como uma capacidade garantida. Se a implantação oferecer suporte, as consultas `type:diff` e `type:commit` são muito boas para recuperar strings deletadas ou alterações recentes relevantes para a segurança.

> [!WARNING]
> Ao procurar leaks em um repo e executar algo como `git log -p`, não se esqueça de que pode haver **outras branches com outros commits** contendo secrets!

Para hunting dedicado de secrets, dorks do GitHub em toda a organização e ferramentas como TruffleHog/Gitleaks, consulte:

{{#ref}}
github-leaked-secrets.md
{{#endref}}



## Referências

- [Sintaxe do GitHub Code Search](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
- [Referência de uso seguro do GitHub Actions](https://docs.github.com/en/actions/reference/security/secure-use)
- [Referência de metadados do Dev Container](https://containers.dev/implementors/json_reference/)
{{#include ../../banners/hacktricks-training.md}}
