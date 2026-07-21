# Wide Source Code Search

{{#include ../../banners/hacktricks-training.md}}

このページの目的は、**数千〜数百万の repo** を横断して **code を検索できる platform**（literal、regex、symbol-aware、path-scoped）を列挙することです。

これは次の用途に役立ちます。

- **leak した情報の検索**
- **vulnerable pattern の検索**
- **technology、internal host、CI/CD、infrastructure-as-code の把握**
- **company/org 名から repo、branch、高いシグナルを持つ file へ pivot**

- [**Sourcebot**](https://www.sourcebot.dev/): Open-source/self-hosted の code search。**多数の repo** を index したい場合に非常に便利で、設定すれば追加の branch/tag も対象にできます。また、`repo:`、`file:`、`lang:`、`rev:`、`sym:` などの regex filter を維持できます。
- [**SourceGraph**](https://sourcegraph.com/search): 数百万の repo を検索できます。通常は regex が最も安全な選択肢です。structural search は一部の deployment に存在しますが、performance 上の制限があり、常に有効とは限りません。
- [**GitHub Code Search**](https://github.com/search): regex、boolean logic、および `repo:`、`org:`、`user:`、`path:`、`language:`、`symbol:`、`content:`、`is:` などの qualifier をサポートします。
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/): Zoekt を基盤とする modern な GitLab code search。`file:`、`lang:`、`repo:`、`sym:` などの filter を使用した exact mode と regex mode をサポートします。
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/) は、code、comment、commit、merge request、wiki を検索できるため、より広範な fallback として現在も役立ちます。
- [**SearchCode**](https://searchcode.com/): 数百万の project 内の code を検索します。
- [**Grep**](https://grep.app/): 非常に大規模な GitHub corpus を対象とした高速な public search。**content**、**file**、**path** の pivot に対して、別の indexing/ranking view が必要な場合に便利です。

## Useful search capabilities

bug bounty/red team context で org を audit する場合、通常、次の capability が最も役立ちます。

- **Regex** support。token format、URL scheme、dangerous function name、multiline fragment を検索できます。
- **Path filter**。`.github/workflows/`、`terraform/`、`helm/`、`.env`、`values.yaml`、`secrets.*`、`credentials.*`、`Dockerfile`、`Jenkinsfile`、`nginx.conf` などの high-value file に直接移動できます。
- **Language filter**。app code を IaC や pipeline から分離できます。
- **Symbol-aware search**。handler、auth middleware、webhook consumer、dangerous helper function、特定の class/method を列挙できます。
- **Boolean operator**。`NOT path:test`、`NOT is:generated`、`NOT is:vendored`、`foo OR bar` のように noise を減らせます。
- 利用可能な場合は **revision/diff search**。**deleted string** を復元したり、**security-relevant change** を追跡したり、すべてを先に clone することなく **non-default branch/tag** を調査できます。

## Practical methodology

1. **indexed platform** から開始し、repo、owner、path、code family を迅速に特定します。
2. generic な `password`/`secret` string だけを検索するのではなく、**high-signal location に pivot** します。
3. **credential だけでなく attack surface を検索**します。
- CI/CD workflow、reusable workflow、composite action、deployment script
- Dev Container / Codespaces の bootstrap file と custom feature
- Terraform/Helm/Kubernetes manifest
- SSO/OIDC/SAML integration
- Internal URL、staging host、admin panel、message broker、callback endpoint
- Dangerous code path（`exec`、template rendering、SSRF fetcher、deserializer、ZIP extraction、YAML loader など）
4. non-default branch、full history、より優れた regex support、または bulk automation が必要な場合は、**clone して local で検索**します。
5. 目的が secrets triage または verification である場合は、**dedicated scanner にエスカレーション**します（例えば、以下の dedicated page を参照）。

### High-signal query ideas

これらは意図的に broad にしてあるため、GitHub、GitLab、Sourcegraph、Sourcebot の syntax に適応できます。
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
### 優先する価値の高い新しいファイル

- **`.github/workflows/*.yml`**: `pull_request_target`、`workflow_run`、`workflow_call`、`secrets: inherit`、`id-token: write`、`runs-on: self-hosted`、および完全な commit SHA ではなく tag/branch のみに pin されている third-party の `uses:` 行を探します。
- **`.devcontainer/devcontainer.json`**、**`.devcontainer/<variant>/devcontainer.json`**、および **`.devcontainer.json`**: `remoteEnv`、`containerEnv`、`initializeCommand`、`postCreateCommand`、`mounts`、参照されている Dockerfile と scripts を検索します。これらから、内部 package registry、bootstrap URL、host mount、開発者専用 endpoint が見つかることがよくあります。
- **Dev Container Features**（`devcontainer-feature.json`、`install.sh`）: environment 作成時に実行される、組織固有の installer logic を見つけるのに適しています。
- **その他の CI/control-plane ファイル**: `.gitlab-ci.yml`、`azure-pipelines.yml`、`cloudbuild.yaml`、`Jenkinsfile`、`buildkite*`、`atlantis.yaml`、`terragrunt.hcl`、`helmfile.yaml`、`skaffold.yaml`、`argocd*`。

### indexed search だけでは不十分な場合の大規模な local search
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
ローカル検索を使用する必要があるのは、次のような場合です。

- **non-default branches** または **tags** を検索する
- **git history** を検索する
- **PCRE2/multiline** クエリをより積極的に実行する
- UI の制限なしで多数のリポジトリを一括 **triage** する

### **history**、**branches**、**diffs** を明示的に検索する
```bash
REPO_DIR=repos/some-repo
git -C "$REPO_DIR" fetch --all --tags --prune

git -C "$REPO_DIR" for-each-ref --format='%(refname:short)' refs/remotes/origin refs/tags \
| while read -r ref; do
git -C "$REPO_DIR" grep -nI -E 'pull_request_target|workflow_call|id-token: write|secrets: inherit|remoteEnv|containerEnv' "$ref" || true
done

git -C "$REPO_DIR" log --all -p -G 'gh[pousr]_|github_pat_|BEGIN [A-Z ]+PRIVATE KEY|internal.*https?://' -- .
```
これは、対象となる文字列が **release branch**、**tag**、または **deleted commit** にのみ存在していた場合に特に有用です。Sourcegraph の deployment が対応している場合、`type:diff` と `type:commit` の検索は、同じ問題に対する clone 不要の優れた pivot になります。

## よくある見落とし

- **Default branch のみの indexing** は一般的です。code search がすべての branch、tag、history を対象としていると想定しないでください。
- **大きなファイル、vendored code、generated code、または archives** は skip されたり、noise が多くなったりする場合があります。
- **Comments、issues、PRs、gists、wikis** は generic code search の scope 外であることが多く、platform 固有の tooling が必要になる場合があります。
- **Codespaces / devcontainer configs** は branch-specific である可能性があり、複数の `.devcontainer/<variant>/devcontainer.json` paths に存在する場合があります。そのため、default branch が clean でも、すべての場所で dev environment が clean とは限りません。
- **Reusable workflows/actions と devcontainer features** は、明らかな file の外部に存在する場合があります。top-level workflow file だけでなく、`.github/actions/`、`action.yml`、`action.yaml`、`devcontainer-feature.json`、`install.sh` も検索してください。
- **Search syntax は platform ごとに異なります**。GitHub Code Search で動作する dork も、GitLab、Sourcegraph、Sourcebot では多少の変更が必要になる場合があります。

### Platform-specific gotchas

- **GitHub Code Search** は高速な recon に非常に優れていますが、検索対象は **default branch** のみです。feature branches、deleted secrets、または historical code が必要な場合は、repo を clone して local で検索してください。
- **GitLab Exact Code Search** にも **default-branch** の制限があり、小さな files のみを index しますが、**Advanced Search** は comments、commits、wikis の検索に引き続き役立ちます。
- **Sourcebot** はデフォルトで **default branch** を index しますが、追加の branches/tags を index するよう設定でき、その後 `rev:` filters で検索できます。index を管理できる場合、branch/tag に焦点を当てた internal audits に非常に便利です。
- **Sourcegraph** の regex search は、offensive work において一般的に最も予測しやすい option です。structural search は optional bonus と考え、利用可能であることを保証された capability として扱わないでください。deployment が対応している場合、`type:diff` と `type:commit` queries は、deleted strings や最近の security-relevant changes を recovery するのに非常に有効です。

> [!WARNING]
> repo 内の leaks を探して `git log -p` のようなコマンドを実行する際は、secrets を含む **他の commits を持つ他の branches** が存在する可能性を忘れないでください！

専用の secret hunting、org-wide GitHub dorks、TruffleHog/Gitleaks などの tooling については、以下を確認してください。

{{#ref}}
github-leaked-secrets.md
{{#endref}}



## References

- [GitHub Code Search 構文](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
- [GitHub Actions secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [Dev Container metadata reference](https://containers.dev/implementors/json_reference/)
{{#include ../../banners/hacktricks-training.md}}
