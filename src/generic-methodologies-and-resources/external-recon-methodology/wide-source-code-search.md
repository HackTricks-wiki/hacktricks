# Wide Source Code Search

{{#include ../../banners/hacktricks-training.md}}

O objetivo desta página é enumerar **plataformas que permitem pesquisar código** (literal, regex, symbol-aware, ou path-scoped) em **milhares/milhões de repos**.

Isso é útil para:

- **Pesquisar informações leak**
- **Pesquisar padrões vulneráveis**
- **Mapear tecnologias, hosts internos, CI/CD e infrastructure-as-code**
- **Pivotar de um nome de empresa/org para repos, branches e arquivos de alto sinal**

- [**Sourcebot**](https://www.sourcebot.dev/): code search open-source/self-hosted. Muito útil quando você quer indexar **muitos repos** e, se configurado, branches/tags adicionais enquanto mantém filtros regex como `repo:`, `file:`, `lang:`, `rev:` e `sym:`.
- [**SourceGraph**](https://sourcegraph.com/search): Pesquisa em milhões de repos. Regex geralmente é a opção mais segura; structural search existe em algumas implantações, mas tem limitações de performance e nem sempre está habilitada.
- [**GitHub Code Search**](https://github.com/search): Suporta regex, lógica booleana e qualifiers como `repo:`, `org:`, `user:`, `path:`, `language:`, `symbol:`, `content:` e `is:`.
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/): code search moderno do GitLab alimentado por Zoekt. Suporta modos exact e regex com filtros como `file:`, `lang:`, `repo:` e `sym:`.
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/) ainda é útil como fallback mais amplo porque pode pesquisar código, comentários, commits, merge requests e wikis.
- [**SearchCode**](https://searchcode.com/): Pesquise código em milhões de projetos.

## Useful search capabilities

Ao auditar uma org em um contexto de bug bounty/red team, as capacidades mais úteis geralmente são:

- Suporte a **Regex** para pesquisar formatos de tokens, esquemas de URL, nomes de funções perigosas ou fragmentos multilinha.
- **Path filters** para ir diretamente a arquivos de alto valor como `.github/workflows/`, `terraform/`, `helm/`, `.env`, `values.yaml`, `secrets.*`, `credentials.*`, `Dockerfile`, `Jenkinsfile` ou `nginx.conf`.
- **Language filters** para separar código da app de IaC e pipelines.
- **Symbol-aware search** para enumerar handlers, auth middleware, webhook consumers, funções helper perigosas ou classes/métodos específicos.
- **Boolean operators** para reduzir ruído: `NOT path:test`, `NOT is:generated`, `NOT is:vendored`, `foo OR bar`.

## Practical methodology

1. **Comece pelas plataformas indexadas** para identificar rapidamente repos, owners, paths e famílias de código.
2. **Faça pivot para locais de alto sinal** em vez de pesquisar apenas strings genéricas `password`/`secret`.
3. **Pesquise attack surface, não apenas credentials**:
- CI/CD workflows e scripts de deployment
- Manifests de Terraform/Helm/Kubernetes
- Integrações SSO/OIDC/SAML
- URLs internas, hosts de staging, admin panels, message brokers e callback endpoints
- Caminhos de código perigosos (`exec`, template rendering, SSRF fetchers, deserializers, ZIP extraction, YAML loaders, etc.)
4. **Clone e pesquise localmente** quando precisar de branches não padrão, histórico completo, melhor suporte a regex ou automação em massa.
5. **Escalone para scanners dedicados** quando o objetivo for triagem ou verificação de secrets (por exemplo, veja a página dedicada abaixo).

### High-signal query ideas

Estas são intencionalmente amplas para que você possa adaptá-las à sintaxe de GitHub, GitLab, Sourcegraph ou Sourcebot:
```text
org:target path:.github/workflows ("pull_request_target" OR "workflow_run" OR "ACTIONS_STEP_DEBUG")
org:target (path:terraform OR path:helm OR language:HCL OR language:YAML) ("role_arn" OR "assume_role" OR "client_secret" OR "access_key")
org:target ("BEGIN PRIVATE KEY" OR "ghp_" OR "github_pat_" OR "AIza" OR "xoxb-")
org:target (path:.env OR path:values.yaml OR path:application-prod OR path:credentials)
org:target ("internal" OR "corp" OR "staging") ("https://" OR "ssh://") NOT path:test
```
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
Use local searching when you need to:

- Search **non-default branches** or **tags**
- Search **git history**
- Run **PCRE2/multiline** queries more aggressively
- Batch triage many repositories without UI limits

## Common blind spots

- **Default-branch-only indexing** is common. Do not assume code search covers all branches/tags/history.
- **Large files, vendored code, generated code, or archives** may be skipped or noisy.
- **Comments, issues, PRs, gists, and wikis** are often outside the scope of generic code search and may require platform-specific tooling.
- **Search syntax differs per platform**. A dork that works in GitHub Code Search might need small changes for GitLab, Sourcegraph, or Sourcebot.

### Platform-specific gotchas

- **GitHub Code Search** is excellent for fast recon, but it searches the **default branch** only. If you need feature branches, deleted secrets, or historical code, clone the repo and search it locally.
- **GitLab Exact Code Search** also has a **default-branch** limitation and indexes only smaller files, but **Advanced Search** can still be useful to search comments, commits, and wikis.
- **Sourcebot** indexes the **default branch** by default, but it can be configured to index additional branches/tags and then searched with `rev:` filters, which is very convenient for branch/tag-focused internal audits when you control the index.
- **Sourcegraph** regex search is generally the most predictable option for offensive work; treat structural search as an optional bonus, not as a guaranteed capability.

> [!WARNING]
> When you look for leaks in a repo and run something like `git log -p` don't forget there might be **other branches with other commits** containing secrets!

For dedicated secret hunting, org-wide GitHub dorks, and tooling such as TruffleHog/Gitleaks, check:

{{#ref}}
github-leaked-secrets.md
{{#endref}}



## References

- [GitHub Code Search syntax](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
{{#include ../../banners/hacktricks-training.md}}
