# 広範なソースコード検索

{{#include ../../banners/hacktricks-training.md}}

このページの目的は、**数千から数百万の repo** を横断してコード（リテラル、regex、symbol-aware、または path-scoped）を検索できる **platform** を列挙することです。

これは次の用途に役立ちます。

- **leak した情報の検索**
- **脆弱なパターンの検索**
- **technology、内部 host、CI/CD、Infrastructure-as-Code の把握**
- **company/org 名から repo、branch、高シグナルな file への pivot**

- [**Sourcebot**](https://www.sourcebot.dev/): Open-source/self-hosted の code search。**多数の repo** を index し、設定すれば追加の branch/tag も対象にしながら、`repo:`、`file:`、`lang:`、`rev:`、`sym:` などの regex filter を維持したい場合に非常に有用です。
- [**SourceGraph**](https://sourcegraph.com/search): 数百万の repo を検索できます。通常は regex が最も安全な選択肢です。structural search は一部の deployment に存在しますが、performance に制限があり、常に有効とは限りません。
- [**GitHub Code Search**](https://github.com/search): regex、boolean logic、`repo:`、`org:`、`user:`、`path:`、`language:`、`symbol:`、`content:`、`is:` などの qualifier をサポートします。<sup>[[1]](#references)</sup>
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/): Zoekt を基盤とする modern な GitLab code search。`file:`、`lang:`、`repo:`、`sym:` などの filter を使った exact mode と regex mode をサポートします。<sup>[[2]](#references)</sup>
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/) は、code、comment、commit、merge request、wiki を検索できるため、より広範な fallback として現在も有用です。
- [**SearchCode**](https://searchcode.com/): 数百万の project の code を検索します。
- [**Grep**](https://grep.app/): 非常に大規模な GitHub corpus を対象とした高速な public search。**content**、**file**、**path** の pivot に対して、別の indexing/ranking view が必要な場合に有用です。

## 便利な検索機能

bug bounty/red team の context で org を audit する場合、通常は次の機能が最も役立ちます。

- token format、URL scheme、危険な function name、または複数行の fragment を検索するための **regex** support。
- `.github/workflows/`、`terraform/`、`helm/`、`.env`、`values.yaml`、`secrets.*`、`credentials.*`、`Dockerfile`、`Jenkinsfile`、`nginx.conf` などの高価値な file に直接移動するための **path filter**。
- app code と IaC、pipeline を分離するための **language filter**。
- handler、auth middleware、webhook consumer、危険な helper function、特定の class/method を列挙するための **symbol-aware search**。
- ノイズを減らすための **boolean operator**：`NOT path:test`、`NOT is:generated`、`NOT is:vendored`、`foo OR bar`。
- 利用可能な場合の **revision/diff search**。すべてを先に clone せずに、**削除された string** を復元し、**security に関連する変更**を追跡し、**default ではない branch/tag** を調査できます。

## 実践的な methodology

1. **index された platform から開始**し、repo、owner、path、code family をすばやく特定します。
2. generic な `password`/`secret` string だけを検索するのではなく、**高シグナルな location に pivot** します。
3. **credential だけでなく attack surface を検索**します。
- CI/CD workflow、reusable workflow、composite action、deployment script
- Dev Container / Codespaces の bootstrap file と custom feature
- Terraform/Helm/Kubernetes manifest
- SSO/OIDC/SAML integration
- 内部 URL、staging host、admin panel、message broker、callback endpoint
- 危険な code path（`exec`、template rendering、SSRF fetcher、deserializer、ZIP extraction、YAML loader など）
4. non-default branch、full history、より優れた regex support、または bulk automation が必要な場合は、**clone して local で検索**します。
5. 目的が secret の triage または verification である場合は、**専用 scanner に移行**します（例については、以下の専用ページを参照）。

### 高シグナルな query のアイデア

これらは意図的に広範なものにしているため、GitHub、GitLab、Sourcegraph、Sourcebot の syntax に合わせて調整できます。
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

- **`.github/workflows/*.yml`**: `pull_request_target`、`workflow_run`、`workflow_call`、`secrets: inherit`、`id-token: write`、`runs-on: self-hosted`、および完全な commit SHA ではなくタグ/ブランチだけに pin されたサードパーティの `uses:` 行を探します。<sup>[[3]](#references)</sup>
- **`.devcontainer/devcontainer.json`**、**`.devcontainer/<variant>/devcontainer.json`**、および **`.devcontainer.json`**: `remoteEnv`、`containerEnv`、`initializeCommand`、`postCreateCommand`、`mounts`、参照されている Dockerfile/スクリプトを検索します。これらには、内部 package registry、bootstrap URL、host mount、開発者専用 endpoint が含まれていることがよくあります。<sup>[[4]](#references)</sup>
- **Dev Container Features**（`devcontainer-feature.json`、`install.sh`）: environment 作成中に実行される組織固有の installer ロジックを見つけるのに適しています。
- **その他の CI/control-plane ファイル**: `.gitlab-ci.yml`、`azure-pipelines.yml`、`cloudbuild.yaml`、`Jenkinsfile`、`buildkite*`、`atlantis.yaml`、`terragrunt.hcl`、`helmfile.yaml`、`skaffold.yaml`、`argocd*`。

### indexed search で不十分な場合の大規模なローカル検索
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
必要に応じて local searching を使用します。

- **non-default branches** または **tags** を検索する
- **git history** を検索する
- **PCRE2/multiline** クエリをより積極的に実行する
- UI の制限なしで多数のリポジトリを一括 triage する

### history、branches、diffs を明示的に検索する
```bash
REPO_DIR=repos/some-repo
git -C "$REPO_DIR" fetch --all --tags --prune

git -C "$REPO_DIR" for-each-ref --format='%(refname:short)' refs/remotes/origin refs/tags \
| while read -r ref; do
git -C "$REPO_DIR" grep -nI -E 'pull_request_target|workflow_call|id-token: write|secrets: inherit|remoteEnv|containerEnv' "$ref" || true
done

git -C "$REPO_DIR" log --all -p -G 'gh[pousr]_|github_pat_|BEGIN [A-Z ]+PRIVATE KEY|internal.*https?://' -- .
```
これは、興味深い文字列が **release branch**、**tag**、または **deleted commit** にのみ存在していた場合に、特に便利です。Sourcegraph deployment が対応していれば、`type:diff` および `type:commit` search は、同じ問題に対する優れた no-clone pivot になります。

## よくある見落とし

- **Default-branch-only indexing** が一般的です。code search がすべての branch、tag、history を対象にしていると想定しないでください。
- **Large files、vendored code、generated code、または archives** は、スキップされたり、ノイズが多くなったりする場合があります。
- **Comments、issues、PRs、gists、wikis** は、generic code search の対象外であることが多く、platform 固有の tooling が必要になる場合があります。
- **Codespaces / devcontainer configs** は branch 固有の場合があり、複数の `.devcontainer/<variant>/devcontainer.json` paths に存在する可能性があります。そのため、default branch がクリーンでも、すべての場所で dev environment がクリーンとは限りません。
- **Reusable workflows/actions と devcontainer features** は、明らかな file の外部に存在する場合があります。トップレベルの workflow file だけでなく、`.github/actions/`、`action.yml`、`action.yaml`、`devcontainer-feature.json`、`install.sh` も search してください。
- **Search syntax は platform ごとに異なります**。GitHub Code Search で機能する dork でも、GitLab、Sourcegraph、Sourcebot では小さな変更が必要になる場合があります。

### Platform-specific gotchas

- **GitHub Code Search** は高速な recon に非常に優れていますが、**default branch** のみを search します。feature branches、deleted secrets、または historical code が必要な場合は、repo を clone して local で search してください。
- **GitLab Exact Code Search** にも **default-branch** の制限があり、小さな file のみを index します。ただし、**Advanced Search** を使えば comments、commits、wikis の search にも役立ちます。<sup>[[2]](#references)</sup>
- **Sourcebot** はデフォルトで **default branch** を index しますが、追加の branches/tags を index するよう設定でき、その後 `rev:` filters で search できます。これは、index を管理している場合に、branch/tag に焦点を当てた internal audits に非常に便利です。
- **Sourcegraph** の regex search は、offensive work において一般的に最も予測可能な option です。structural search は guaranteed capability ではなく、optional bonus として扱ってください。deployment が対応していれば、`type:diff` および `type:commit` queries は、deleted strings や最近の security-relevant changes を復元するのに非常に有効です。

> [!WARNING]
> repo 内の leaks を探して `git log -p` のようなものを実行する場合、secrets を含む **他の commits を持つ別の branches** が存在する可能性を忘れないでください！

専用の secret hunting、org-wide GitHub dorks、TruffleHog/Gitleaks などの tooling については、以下を確認してください。

{{#ref}}
github-leaked-secrets.md
{{#endref}}

## References

- [1] [GitHub Code Search syntax](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [2] [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
- [3] [GitHub Actions secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [4] [Dev Container metadata reference](https://containers.dev/implementors/json_reference/)

{{#include ../../banners/hacktricks-training.md}}
