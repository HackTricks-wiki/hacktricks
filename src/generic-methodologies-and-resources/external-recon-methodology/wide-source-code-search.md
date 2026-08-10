# Pesquisa Ampla de Código-Fonte

O objetivo desta página é enumerar **plataformas que permitem pesquisar código** (literal, regex, com reconhecimento de símbolos ou restrito por caminho) em **milhares/milhões de repos**.

Isso é útil para:

- **Pesquisar informações em leak**
- **Pesquisar padrões vulneráveis**
- **Mapear tecnologias, hosts internos, CI/CD e infrastructure-as-code**
- **Fazer pivot de um nome de empresa/org para repos, branches e arquivos de alto sinal**

- [**Sourcebot**](https://www.sourcebot.dev/): code search open-source/self-hosted com regex, símbolos e filtros em repositórios. Configure branches/tags adicionais e consulte-os com `rev:` quando a cobertura de branches for importante.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- [**Sourcegraph**](https://sourcegraph.com/search): Code search com consultas de regex, booleanas, símbolos, repositórios/arquivos/linguagens, branch/commit, diff e mensagens de commit.<sup>[[8]](#references)[[10]](#references)</sup> Structural search é opcional, pois a documentação atual o descreve como desabilitado por padrão e limitado em desempenho.<sup>[[9]](#references)</sup>
- [**GitHub Code Search**](https://github.com/search): Suporta regex, lógica booleana e qualificadores como `repo:`, `org:`, `user:`, `path:`, `language:`, `symbol:`, `content:` e `is:`.<sup>[[1]](#references)</sup>
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/): Code search baseado no Zoekt, com modos exact e regex e filtros como `file:`, `lang:`, `repo:` e `sym:`.<sup>[[2]](#references)</sup>
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/) é um fallback mais amplo, pois pode pesquisar código, comentários, commits, merge requests e wikis.<sup>[[11]](#references)</sup>
- [**SearchCode**](https://searchcode.com/): Serviço de code intelligence com code search booleano/regex/estrutural, além de recuperação de arquivos e símbolos.<sup>[[12]](#references)</sup>
- [**Grep**](https://grep.app/): Code search público em um milhão de repositórios do GitHub, com pesquisa de conteúdo, arquivos e caminhos.<sup>[[13]](#references)</sup>

## Recursos úteis de pesquisa

Ao auditar uma org em um contexto de bug bounty/red team, os recursos mais úteis geralmente são:

- Suporte a **Regex** para pesquisar formatos de tokens, esquemas de URL, nomes de funções perigosas ou fragmentos multilinha.
- **Filtros de caminho** para acessar diretamente arquivos de alto valor, como `.github/workflows/`, `terraform/`, `helm/`, `.env`, `values.yaml`, `secrets.*`, `credentials.*`, `Dockerfile`, `Jenkinsfile` ou `nginx.conf`.
- **Filtros de linguagem** para separar código da aplicação de IaC e pipelines.
- **Pesquisa com reconhecimento de símbolos** para enumerar handlers, middleware de autenticação, consumidores de webhook, funções auxiliares perigosas ou classes/métodos específicos.
- **Operadores booleanos** para reduzir ruído: `NOT path:test`, `NOT is:generated`, `NOT is:vendored`, `foo OR bar`.
- **Pesquisa de revisions/diffs** quando disponível, para que você possa recuperar **strings deletadas**, acompanhar **alterações relevantes para a segurança** ou inspecionar **branches/tags não padrão** sem clonar tudo primeiro.

## Metodologia prática

1. **Comece pelas plataformas indexadas** para identificar rapidamente repos, owners, caminhos e famílias de código.
2. **Faça pivot para locais de alto sinal** em vez de pesquisar apenas strings genéricas como `password`/`secret`.
3. **Pesquise a attack surface, não apenas credenciais**:
- Workflows de CI/CD, reusable workflows, composite actions e scripts de deployment
- Arquivos de bootstrap do Dev Containers / Codespaces e custom features
- Manifestos de Terraform/Helm/Kubernetes
- Integrações de SSO/OIDC/SAML
- URLs internas, hosts de staging, painéis de administração, message brokers e endpoints de callback
- Caminhos de código perigosos (`exec`, renderização de templates, fetchers de SSRF, desserializadores, extração de ZIP, YAML loaders etc.)
4. **Clone e pesquise localmente** quando precisar de branches não padrão, histórico completo, melhor suporte a regex ou automação em massa.
5. **Escale para scanners dedicados** quando o objetivo for triagem ou verificação de secrets (por exemplo, consulte a página dedicada abaixo).

### Ideias de consultas de alto sinal

Estas são intencionalmente amplas para que você possa adaptá-las à sintaxe do GitHub, GitLab, Sourcegraph ou Sourcebot:
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

- **`.github/workflows/*.yml`**: Revise os gatilhos privilegiados `pull_request_target` e `workflow_run`, além das linhas `uses:` de terceiros fixadas apenas em tags/branches, em vez de hashes SHA completos.<sup>[[3]](#references)</sup> Pesquise também por `workflow_call`, `secrets: inherit`, `id-token: write` e `runs-on: self-hosted`.
- **`.devcontainer/devcontainer.json`**, **`.devcontainer/<variant>/devcontainer.json`** e **`.devcontainer.json`**: Pesquise por `remoteEnv`, `containerEnv`, `initializeCommand`, `postCreateCommand`, `mounts` e pelos Dockerfiles/scripts referenciados para descobrir valores de ambiente, comandos de bootstrap, mounts e arquivos relacionados.<sup>[[4]](#references)</sup>
- **Dev Container Features** (`devcontainer-feature.json`, `install.sh`): Inspecione ambos os arquivos, pois o layout mínimo de uma Feature inclui metadados e um script de entrypoint `install.sh`.<sup>[[14]](#references)</sup>
- **Outros arquivos de CI/control-plane**: `.gitlab-ci.yml`, `azure-pipelines.yml`, `cloudbuild.yaml`, `Jenkinsfile`, `buildkite*`, `atlantis.yaml`, `terragrunt.hcl`, `helmfile.yaml`, `skaffold.yaml`, `argocd*`.

### Pesquisa local em massa quando a pesquisa indexada não for suficiente
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

- Pesquisar **branches** ou **tags** **não padrão**
- Pesquisar o **histórico do git**
- Executar consultas **PCRE2/multiline** de forma mais agressiva
- Fazer a triagem em lote de muitos repositórios sem limites da UI

### Pesquisar explicitamente o histórico, as branches e os diffs
```bash
REPO_DIR=repos/some-repo
git -C "$REPO_DIR" fetch --all --tags --prune

git -C "$REPO_DIR" for-each-ref --format='%(refname:short)' refs/remotes/origin refs/tags \
| while read -r ref; do
git -C "$REPO_DIR" grep -nI -E 'pull_request_target|workflow_call|id-token: write|secrets: inherit|remoteEnv|containerEnv' "$ref" || true
done

git -C "$REPO_DIR" log --all -p -G 'gh[pousr]_|github_pat_|BEGIN [A-Z ]+PRIVATE KEY|internal.*https?://' -- .
```
Isso é especialmente útil quando a string interessante existia apenas em uma **release branch**, **tag** ou **deleted commit**. Se sua implantação do Sourcegraph oferecer suporte, as buscas `type:diff` e `type:commit` são uma excelente alternativa sem clone para o mesmo problema.<sup>[[8]](#references)[[10]](#references)</sup>

## Common blind spots

- A indexação apenas da **default branch** é comum. Não presuma que a busca de código cubra todas as branches/tags/histórico.
- **Arquivos grandes, código vendorizado, código gerado ou arquivos compactados** podem ser ignorados ou gerar ruído.
- **Comentários, issues, PRs, gists e wikis** geralmente estão fora do escopo da busca de código genérica e podem exigir ferramentas específicas da plataforma.
- As configurações de **Codespaces / devcontainer** podem ser específicas de uma branch. Elas podem estar em vários caminhos `.devcontainer/<variant>/devcontainer.json`, portanto uma default branch limpa não significa que o ambiente de desenvolvimento esteja limpo em todos os lugares.<sup>[[4]](#references)</sup>
- **Reusable workflows/actions e devcontainer features** podem estar fora do arquivo óbvio. Pesquise `.github/actions/`, `action.yml`, `action.yaml`, `devcontainer-feature.json` e `install.sh`, não apenas o arquivo de workflow de nível superior.
- A sintaxe de busca varia conforme a plataforma. Um dork que funciona no GitHub Code Search pode exigir pequenas alterações no GitLab, Sourcegraph ou Sourcebot.

### Platform-specific gotchas

- O **GitHub Code Search** é útil para recon rápida, mas pesquisa apenas a **default branch**. Se precisar de feature branches, secrets deletados ou código histórico, faça o clone do repositório e pesquise localmente.<sup>[[15]](#references)</sup>
- O **GitLab Exact Code Search** tem uma limitação de **default branch** e indexa apenas arquivos menores que 1 MB com menos de 20.000 trigramas.<sup>[[2]](#references)</sup> A **Advanced Search** ainda pode abranger comentários, commits e wikis.<sup>[[11]](#references)</sup>
- O **Sourcebot** indexa a **default branch** por padrão, mas pode ser configurado para indexar branches/tags adicionais e, depois, ser pesquisado com filtros `rev:` quando você controla o índice.<sup>[[7]](#references)</sup>
- O **Sourcegraph** oferece suporte a consultas regex, symbol, diff e commit; use a busca estrutural somente onde ela estiver habilitada e considere suas limitações de desempenho documentadas.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

> [!WARNING]
> Ao procurar leaks em um repo e executar algo como `git log -p`, não se esqueça de que pode haver **outras branches com outros commits** contendo secrets!

Para secret hunting dedicado, GitHub dorks em toda a organização e ferramentas como TruffleHog/Gitleaks, consulte [a página de secrets vazados do GitHub](github-leaked-secrets.md).

## References

- [1] [Sintaxe do GitHub Code Search](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [2] [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
- [3] [Referência de uso seguro do GitHub Actions](https://docs.github.com/en/actions/reference/security/secure-use)
- [4] [Referência de metadados do Dev Container](https://containers.dev/implementors/json_reference/)
- [5] [Sourcebot](https://www.sourcebot.dev/)
- [6] [API de busca do Sourcebot](https://docs.sourcebot.dev/api-reference/search-%26-navigation/search-code)
- [7] [Indexação de múltiplas branches do Sourcebot](https://docs.sourcebot.dev/docs/features/search/multi-branch-indexing)
- [8] [Sourcegraph Code Search](https://sourcegraph.com/docs/code-search)
- [9] [Sourcegraph Structural Search](https://sourcegraph.com/docs/code-search/types/structural)
- [10] [Sintaxe de consultas do Sourcegraph Search](https://sourcegraph.com/docs/code-search/queries)
- [11] [GitLab Advanced Search](https://docs.gitlab.com/user/search/advanced_search/)
- [12] [SearchCode](https://searchcode.com/)
- [13] [Grep.app](https://grep.app/)
- [14] [Como criar uma Dev Container Feature](https://containers.dev/guide/author-a-feature)
- [15] [Ferramentas de investigação para incidentes de segurança](https://docs.github.com/en/enterprise-cloud%40latest/code-security/reference/security-incident-response/investigation-tools)
{{#include ../../banners/hacktricks-training.md}}
