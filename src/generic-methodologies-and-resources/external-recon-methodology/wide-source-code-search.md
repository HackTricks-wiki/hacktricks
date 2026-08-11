# Wide Source Code Search

{{#include ../../banners/hacktricks-training.md}}

このページの目的は、**数千から数百万のリポジトリ**を横断してコード（literal、regex、symbol-aware、または path-scoped）を検索できる**platform**を列挙することです。

これは以下の用途に役立ちます。

- **leak された情報の検索**
- **脆弱なパターンの検索**
- **technologies、内部ホスト、CI/CD、infrastructure-as-code の把握**
- **会社名や org 名から repos、branches、高シグナルなファイルへ pivot**

- [**Sourcebot**](https://www.sourcebot.dev/): repos を横断して regex、symbol、filtered search に対応する、open-source/self-hosted の code search。追加の branches/tags を設定し、branch coverage が重要な場合は `rev:` で検索できます。<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- [**Sourcegraph**](https://sourcegraph.com/search): regex、boolean、symbol、repository/file/language、branch/commit、diff、commit-message queries に対応する code search。Structural search は optional です。現在のドキュメントでは、デフォルトで disabled であり、performance に制限があると説明されています。<sup>[[8]](#references)[[10]](#references)</sup> <sup>[[9]](#references)</sup>
- [**GitHub Code Search**](https://github.com/search): regex、boolean logic、`repo:`、`org:`、`user:`、`path:`、`language:`、`symbol:`、`content:`、`is:` などの qualifiers に対応します。<sup>[[1]](#references)</sup>
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/): Zoekt を利用した code search で、exact および regex modes、`file:`、`lang:`、`repo:`、`sym:` などの filters に対応します。<sup>[[2]](#references)</sup>
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/) は、code、comments、commits、merge requests、wikis を検索できるため、より広範な fallback となります。<sup>[[11]](#references)</sup>
- [**SearchCode**](https://searchcode.com/): boolean/regex/structural code search に加え、file および symbol retrieval に対応する code-intelligence service です。<sup>[[12]](#references)</sup>
- [**Grep**](https://grep.app/): 100万件の GitHub repositories を横断し、content、file、path search に対応する public code search です。<sup>[[13]](#references)</sup>

## Useful search capabilities

bug bounty/red team context で org を audit する場合、通常、最も有用な capabilities は以下のとおりです。

- **Regex** support：token formats、URL schemes、危険な function names、または複数行の fragments を検索できます。
- **Path filters**：`.github/workflows/`、`terraform/`、`helm/`、`.env`、`values.yaml`、`secrets.*`、`credentials.*`、`Dockerfile`、`Jenkinsfile`、`nginx.conf` などの high-value files に直接移動できます。
- **Language filters**：app code と IaC、pipelines を分離できます。
- **Symbol-aware search**：handlers、auth middleware、webhook consumers、危険な helper functions、または特定の classes/methods を列挙できます。
- **Boolean operators**：`NOT path:test`、`NOT is:generated`、`NOT is:vendored`、`foo OR bar` により noise を減らせます。
- **Revision/diff search**：利用できる場合は、**deleted strings** の復元、**security-relevant changes** の追跡、またはすべてを先に cloning せずに **non-default branches/tags** の調査が可能です。

## Practical methodology

1. **indexed platforms から開始**し、repos、owners、paths、code families を迅速に特定します。
2. generic な `password`/`secret` strings だけを検索するのではなく、**high-signal locations に pivot**します。
3. **credentials だけでなく attack surface を検索**します。
- CI/CD workflows、reusable workflows、composite actions、deployment scripts
- Dev Containers / Codespaces の bootstrap files および custom features
- Terraform/Helm/Kubernetes manifests
- SSO/OIDC/SAML integrations
- Internal URLs、staging hosts、admin panels、message brokers、callback endpoints
- 危険な code paths（`exec`、template rendering、SSRF fetchers、deserializers、ZIP extraction、YAML loaders など）
4. non-default branches、full history、より優れた regex support、または bulk automation が必要な場合は、**clone して local で検索**します。
5. 目的が secrets triage または verification の場合は、dedicated scanners に **escalate**します（たとえば、以下の dedicated page を参照）。

### High-signal query ideas

以下は意図的に広範な内容になっているため、GitHub、GitLab、Sourcegraph、Sourcebot の syntax に合わせて適応できます。
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
### 優先する価値のある、より高シグナルなファイル

- **`.github/workflows/*.yml`**: 特権的な `pull_request_target` と `workflow_run` トリガー、および完全なコミット SHA ではなくタグやブランチだけに固定されたサードパーティの `uses:` 行を確認します。<sup>[[3]](#references)</sup> また、`workflow_call`、`secrets: inherit`、`id-token: write`、`runs-on: self-hosted` も検索します。
- **`.devcontainer/devcontainer.json`**、**`.devcontainer/<variant>/devcontainer.json`**、**`.devcontainer.json`**: `remoteEnv`、`containerEnv`、`initializeCommand`、`postCreateCommand`、`mounts` と、参照されている Dockerfile やスクリプトを検索し、環境値、bootstrap コマンド、mount、関連ファイルを見つけます。<sup>[[4]](#references)</sup>
- **Dev Container Features**（`devcontainer-feature.json`、`install.sh`）: Feature の最小レイアウトにはメタデータと `install.sh` エントリポイントスクリプトが含まれるため、両方のファイルを調査します。<sup>[[14]](#references)</sup>
- **その他の CI/control-plane ファイル**: `.gitlab-ci.yml`、`azure-pipelines.yml`、`cloudbuild.yaml`、`Jenkinsfile`、`buildkite*`、`atlantis.yaml`、`terragrunt.hcl`、`helmfile.yaml`、`skaffold.yaml`、`argocd*`。

### インデックス検索だけでは不十分な場合のローカル一括検索
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
ローカル検索を使用する場面：

- **デフォルト以外のブランチ**または**タグ**を検索する場合
- **git の履歴**を検索する場合
- **PCRE2/multiline**クエリをより積極的に実行する場合
- UI の制限なしで多数のリポジトリを**バッチトリアージ**する場合

### 履歴、ブランチ、差分を明示的に検索する
```bash
REPO_DIR=repos/some-repo
git -C "$REPO_DIR" fetch --all --tags --prune

git -C "$REPO_DIR" for-each-ref --format='%(refname:short)' refs/remotes/origin refs/tags \
| while read -r ref; do
git -C "$REPO_DIR" grep -nI -E 'pull_request_target|workflow_call|id-token: write|secrets: inherit|remoteEnv|containerEnv' "$ref" || true
done

git -C "$REPO_DIR" log --all -p -G 'gh[pousr]_|github_pat_|BEGIN [A-Z ]+PRIVATE KEY|internal.*https?://' -- .
```
これは、対象の文字列が **release branch**、**tag**、または **deleted commit** にのみ存在していた場合に特に有用です。Sourcegraph の deployment が対応していれば、`type:diff` および `type:commit` 検索は、同じ問題に対する clone 不要の優れた切り替え手段になります。<sup>[[8]](#references)[[10]](#references)</sup>

## よくある見落とし

- **デフォルトブランチのみの indexing** は一般的です。コード検索がすべてのブランチ、tag、履歴を対象としていると仮定しないでください。
- **大きなファイル、vendored code、generated code、またはアーカイブ** はスキップされたり、大量のノイズを含んだりする場合があります。
- **コメント、issue、PR、gist、wiki** は一般的なコード検索の対象外であることが多く、platform 固有の tooling が必要になる場合があります。
- **Codespaces / devcontainer configs は branch 固有の場合があります**。複数の `.devcontainer/<variant>/devcontainer.json` パスに存在する可能性があるため、デフォルトブランチがクリーンでも、すべての場所で dev environment がクリーンとは限りません。<sup>[[4]](#references)</sup>
- **Reusable workflows/actions と devcontainer features は、明らかに見えるファイルの外部に存在する場合があります**。トップレベルの workflow file だけでなく、`.github/actions/`、`action.yml`、`action.yaml`、`devcontainer-feature.json`、`install.sh` も検索してください。
- **検索構文は platform ごとに異なります**。GitHub Code Search で機能する dork も、GitLab、Sourcegraph、Sourcebot では少し変更が必要になる場合があります。

### Platform 固有の注意点

- **GitHub Code Search** は高速な recon に便利ですが、検索対象は **デフォルトブランチ** のみです。feature branch、削除された secret、または過去の code が必要な場合は、repo を clone してローカルで検索してください。<sup>[[15]](#references)</sup>
- **GitLab Exact Code Search** には **デフォルトブランチ** の制限があり、1 MB 未満かつ 20,000 個未満の trigram を含むファイルのみ indexing されます。<sup>[[2]](#references)</sup> **Advanced Search** では、コメント、commit、wiki も対象にできます。<sup>[[11]](#references)</sup>
- **Sourcebot** はデフォルトでは **デフォルトブランチ** を indexing しますが、追加の branch/tag を indexing するよう設定でき、index を管理している場合は `rev:` filter で検索できます。<sup>[[7]](#references)</sup>
- **Sourcegraph** は regex、symbol、diff、commit query に対応しています。structural search は有効化されている場合にのみ使用し、文書化されている performance limit を考慮してください。<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

> [!WARNING]
> repo 内の leak を探して `git log -p` のようなコマンドを実行する場合、secret を含む **別の commit を持つ他の branch** が存在する可能性を忘れないでください！

専用の secret hunting、組織全体を対象とした GitHub dork、TruffleHog/Gitleaks などの tooling については、[GitHub leaked secrets page](github-leaked-secrets.md) を確認してください。

## References

- [1] [GitHub Code Search 構文](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [2] [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
- [3] [GitHub Actions の安全な利用に関するリファレンス](https://docs.github.com/en/actions/reference/security/secure-use)
- [4] [Dev Container metadata リファレンス](https://containers.dev/implementors/json_reference/)
- [5] [Sourcebot](https://www.sourcebot.dev/)
- [6] [Sourcebot search API](https://docs.sourcebot.dev/api-reference/search-%26-navigation/search-code)
- [7] [Sourcebot の multi-branch indexing](https://docs.sourcebot.dev/docs/features/search/multi-branch-indexing)
- [8] [Sourcegraph Code Search](https://sourcegraph.com/docs/code-search)
- [9] [Sourcegraph Structural Search](https://sourcegraph.com/docs/code-search/types/structural)
- [10] [Sourcegraph Search Query Syntax](https://sourcegraph.com/docs/code-search/queries)
- [11] [GitLab Advanced Search](https://docs.gitlab.com/user/search/advanced_search/)
- [12] [SearchCode](https://searchcode.com/)
- [13] [Grep.app](https://grep.app/)
- [14] [Dev Container Feature の作成](https://containers.dev/guide/author-a-feature)
- [15] [Security incident の investigation tools](https://docs.github.com/en/enterprise-cloud%40latest/code-security/reference/security-incident-response/investigation-tools)
{{#include ../../banners/hacktricks-training.md}}
