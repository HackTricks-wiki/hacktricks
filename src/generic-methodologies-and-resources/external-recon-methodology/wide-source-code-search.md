# Wide Source Code Search

{{#include ../../banners/hacktricks-training.md}}

このページの目的は、**数千/数百万のリポジトリ**に対してコード検索（literal、regex、symbol-aware、または path-scoped）を許可する**platforms**を列挙することです。

これは以下に役立ちます:

- **漏えいした情報を検索する**
- **脆弱なパターンを検索する**
- **technologies、internal hosts、CI/CD、infra-as-code を把握する**
- **company/org name から repos、branches、high-signal files にピボットする**

- [**Sourcebot**](https://www.sourcebot.dev/): Open-source/self-hosted code search。**多くの repos** を index したいときに非常に便利で、設定次第で追加の branches/tags も、`repo:`、`file:`、`lang:`、`rev:`、`sym:` などの regex filters を維持したまま扱えます。
- [**SourceGraph**](https://sourcegraph.com/search): 数百万の repos を検索できます。通常は regex が最も安全な選択です。structured search は一部の deployments にありますが、performance limitations があり、常に有効とは限りません。
- [**GitHub Code Search**](https://github.com/search): regex、boolean logic、`repo:`、`org:`、`user:`、`path:`、`language:`、`symbol:`、`content:`、`is:` などの qualifiers をサポートします。
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/): Zoekt によって強化された最新の GitLab code search。`file:`、`lang:`、`repo:`、`sym:` などの filters を使った exact mode と regex mode をサポートします。
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/) は、code、comments、commits、merge requests、wikis も検索できるため、より広い fallback として依然有用です。
- [**SearchCode**](https://searchcode.com/): 数百万の projects の code を検索します。

## Useful search capabilities

bug bounty/red team の文脈で org を監査するとき、通常もっとも有用な機能は次のとおりです:

- **Regex** サポート: token formats、URL schemes、危険な function names、または multiline fragments を検索するため。
- **Path filters**: `.github/workflows/`、`terraform/`、`helm/`、`.env`、`values.yaml`、`secrets.*`、`credentials.*`、`Dockerfile`、`Jenkinsfile`、`nginx.conf` などの高価値ファイルへ直接移動するため。
- **Language filters**: app code と IaC や pipelines を分離するため。
- **Symbol-aware search**: handlers、auth middleware、webhook consumers、危険な helper functions、特定の classes/methods を列挙するため。
- **Boolean operators**: ノイズを減らすため。`NOT path:test`、`NOT is:generated`、`NOT is:vendored`、`foo OR bar`

## Practical methodology

1. **indexed platforms から始める**ことで、repos、owners、paths、code families を素早く特定します。
2. `password`/`secret` のような一般的な文字列だけを検索するのではなく、**high-signal locations** にピボットします。
3. **credentials だけでなく attack surface も検索**します:
- CI/CD workflows と deployment scripts
- Terraform/Helm/Kubernetes manifests
- SSO/OIDC/SAML integrations
- Internal URLs、staging hosts、admin panels、message brokers、callback endpoints
- 危険な code paths (`exec`、template rendering、SSRF fetchers、deserializers、ZIP extraction、YAML loaders、etc.)
4. **default 以外の branches、full history、より良い regex support、bulk automation** が必要なときは clone して local で検索します。
5. 目的が secrets triage または verification のときは、**dedicated scanners** に escalate します（たとえば、下の dedicated page を参照）。

### High-signal query ideas

これらは意図的に広めにしてあるため、GitHub、GitLab、Sourcegraph、または Sourcebot の syntax に合わせて調整できます:
```text
org:target path:.github/workflows ("pull_request_target" OR "workflow_run" OR "ACTIONS_STEP_DEBUG")
org:target (path:terraform OR path:helm OR language:HCL OR language:YAML) ("role_arn" OR "assume_role" OR "client_secret" OR "access_key")
org:target ("BEGIN PRIVATE KEY" OR "ghp_" OR "github_pat_" OR "AIza" OR "xoxb-")
org:target (path:.env OR path:values.yaml OR path:application-prod OR path:credentials)
org:target ("internal" OR "corp" OR "staging") ("https://" OR "ssh://") NOT path:test
```
### インデックス化された search だけでは不十分な場合の mass local search
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
> リポジトリで leak を探して `git log -p` のようなことを実行する場合、secret を含む**他のコミットがある別ブランチ**が存在するかもしれないことを忘れないでください！

For dedicated secret hunting, org-wide GitHub dorks, and tooling such as TruffleHog/Gitleaks, check:

{{#ref}}
github-leaked-secrets.md
{{#endref}}



## References

- [GitHub Code Search syntax](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
{{#include ../../banners/hacktricks-training.md}}
