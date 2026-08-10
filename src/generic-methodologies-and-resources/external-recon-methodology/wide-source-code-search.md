# Wide Source Code Search

このページの目的は、**数千から数百万の repo を横断して code を検索できるプラットフォーム**（literal、regex、symbol-aware、または path-scoped）を列挙することです。

これは以下に役立ちます:

- **leak した情報を検索する**
- **vulnerable pattern を検索する**
- **technology、internal host、CI/CD、infrastructure-as-code を把握する**
- **company/org 名から repo、branch、高いシグナルを持つ file へ pivot する**

- [**Sourcebot**](https://www.sourcebot.dev/): repository 全体を対象に、regex、symbol、filter 検索が可能な open-source/self-hosted code search。追加の branch/tag を設定し、branch coverage が重要な場合は `rev:` で検索できます。<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- [**Sourcegraph**](https://sourcegraph.com/search): regex、boolean、symbol、repository/file/language、branch/commit、diff、commit-message query に対応する code search。<sup>[[8]](#references)[[10]](#references)</sup> Structural search は任意で、現在の documentation ではデフォルトで無効かつ performance に制限があると説明されています。<sup>[[9]](#references)</sup>
- [**GitHub Code Search**](https://github.com/search): regex、boolean logic、`repo:`、`org:`、`user:`、`path:`、`language:`、`symbol:`、`content:`、`is:` などの qualifier に対応しています。<sup>[[1]](#references)</sup>
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/): Zoekt を基盤とする code search で、exact および regex mode と、`file:`、`lang:`、`repo:`、`sym:` などの filter に対応しています。<sup>[[2]](#references)</sup>
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/) は、code、comment、commit、merge request、wiki を検索できるため、より広範な fallback になります。<sup>[[11]](#references)</sup>
- [**SearchCode**](https://searchcode.com/): boolean/regex/structural code search と file および symbol retrieval に対応する code-intelligence service です。<sup>[[12]](#references)</sup>
- [**Grep**](https://grep.app/): 100 万の GitHub repository を横断し、content、file、path を検索できる public code search です。<sup>[[13]](#references)</sup>

## Useful search capabilities

bug bounty/red team context で org を audit する場合、通常、最も役立つ capability は以下のとおりです:

- **Regex** support により、token format、URL scheme、dangerous function name、または multiline fragment を検索できます。
- **Path filter** により、`.github/workflows/`、`terraform/`、`helm/`、`.env`、`values.yaml`、`secrets.*`、`credentials.*`、`Dockerfile`、`Jenkinsfile`、`nginx.conf` などの高価値 file に直接移動できます。
- **Language filter** により、app code と IaC、pipeline を分離できます。
- **Symbol-aware search** により、handler、auth middleware、webhook consumer、dangerous helper function、特定の class/method を列挙できます。
- **Boolean operator** により、noise を減らせます: `NOT path:test`、`NOT is:generated`、`NOT is:vendored`、`foo OR bar`。
- 利用可能な場合は **revision/diff search** を使用すると、すべてを先に clone せずに **deleted string を復元**し、**security-relevant change を追跡**し、**non-default branch/tag を調査**できます。

## Practical methodology

1. **indexed platform から開始**し、repo、owner、path、code family を迅速に特定します。
2. generic な `password`/`secret` string だけを検索するのではなく、**高いシグナルを持つ location に pivot**します。
3. **credential だけでなく attack surface を検索**します:
- CI/CD workflow、reusable workflow、composite action、deployment script
- Dev Container / Codespaces の bootstrap file と custom feature
- Terraform/Helm/Kubernetes manifest
- SSO/OIDC/SAML integration
- Internal URL、staging host、admin panel、message broker、callback endpoint
- Dangerous code path（`exec`、template rendering、SSRF fetcher、deserializer、ZIP extraction、YAML loader など）
4. non-default branch、full history、より優れた regex support、または bulk automation が必要な場合は、**clone して local で検索**します。
5. 目的が secret triage または verification の場合は、**dedicated scanner にエスカレーション**します（例として、以下の dedicated page を参照）。

### High-signal query ideas

以下は意図的に広く記述しているため、GitHub、GitLab、Sourcegraph、Sourcebot の syntax に適応できます:
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

- **`.github/workflows/*.yml`**: 特権付きの `pull_request_target` および `workflow_run` トリガーと、完全な commit SHA ではなくタグやブランチだけに pin されたサードパーティーの `uses:` 行を確認します。<sup>[[3]](#references)</sup> また、`workflow_call`、`secrets: inherit`、`id-token: write`、`runs-on: self-hosted` も検索します。
- **`.devcontainer/devcontainer.json`**、**`.devcontainer/<variant>/devcontainer.json`**、**`.devcontainer.json`**: `remoteEnv`、`containerEnv`、`initializeCommand`、`postCreateCommand`、`mounts` と、参照されている Dockerfiles/scripts を検索し、環境値、bootstrap commands、mounts、関連ファイルを発見します。<sup>[[4]](#references)</sup>
- **Dev Container Features**（`devcontainer-feature.json`、`install.sh`）: Feature の最小構成には metadata と `install.sh` の entrypoint script が含まれるため、両方のファイルを調査します。<sup>[[14]](#references)</sup>
- **その他の CI/control-plane ファイル**: `.gitlab-ci.yml`、`azure-pipelines.yml`、`cloudbuild.yaml`、`Jenkinsfile`、`buildkite*`、`atlantis.yaml`、`terragrunt.hcl`、`helmfile.yaml`、`skaffold.yaml`、`argocd*`。

### インデックス検索だけでは不十分な場合の大規模なローカル検索
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
次のような場合は、local searchingを使用します。

- **non-default branches** または **tags** を検索する
- **git history** を検索する
- **PCRE2/multiline** クエリをより積極的に実行する
- UIの制限なしで多数のrepositoryをバッチでトリアージする

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
これは、興味深い文字列が **release branch**、**tag**、または **deleted commit** にのみ存在していた場合に特に便利です。Sourcegraph deployment が対応している場合、`type:diff` および `type:commit` 検索は、同じ問題に対する clone 不要の優れた pivot になります。<sup>[[8]](#references)[[10]](#references)</sup>

## よくある盲点

- **Default branch のみの indexing** は一般的です。code search がすべての branch、tag、history を対象にしていると想定しないでください。
- **大きなファイル、vendored code、generated code、または archive** は、skip されたりノイズが多くなったりする場合があります。
- **Comments、issues、PRs、gists、wikis** は generic code search の対象外であることが多く、platform-specific tooling が必要になる場合があります。
- **Codespaces / devcontainer configs は branch-specific になり得ます**。複数の `.devcontainer/<variant>/devcontainer.json` paths に存在する可能性があるため、default branch がクリーンでも、すべての場所で dev environment がクリーンとは限りません。<sup>[[4]](#references)</sup>
- **Reusable workflows/actions と devcontainer features は、分かりやすい file の外部に存在する場合があります**。top-level workflow file だけでなく、`.github/actions/`、`action.yml`、`action.yaml`、`devcontainer-feature.json`、`install.sh` も検索してください。
- **Search syntax は platform ごとに異なります**。GitHub Code Search で動作する dork でも、GitLab、Sourcegraph、Sourcebot では多少の変更が必要になる場合があります。

### Platform-specific gotchas

- **GitHub Code Search** は高速な recon に便利ですが、**default branch** のみを検索します。feature branches、deleted secrets、または historical code が必要な場合は、repo を clone して local で検索してください。<sup>[[15]](#references)</sup>
- **GitLab Exact Code Search** には **default branch** の制限があり、1 MB 未満かつ 20,000 trigrams 未満の file のみ indexing します。<sup>[[2]](#references)</sup> **Advanced Search** では comments、commits、wikis も引き続き対象にできます。<sup>[[11]](#references)</sup>
- **Sourcebot** はデフォルトで **default branch** を indexing しますが、追加の branches/tags を indexing するよう設定でき、index を管理している場合は `rev:` filters で検索できます。<sup>[[7]](#references)</sup>
- **Sourcegraph** は regex、symbol、diff、commit queries に対応しています。structural search は有効になっている場合にのみ使用し、文書化されている performance limits を考慮してください。<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

> [!WARNING]
> repo で leak を探して `git log -p` のようなコマンドを実行する場合、secret を含む **別の commit を持つ他の branches** が存在する可能性を忘れないでください！

専用の secret hunting、org-wide GitHub dorks、TruffleHog/Gitleaks などの tooling については、[the GitHub leaked secrets page](github-leaked-secrets.md) を確認してください。

## References

- [1] [GitHub Code Search syntax](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [2] [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
- [3] [GitHub Actions secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [4] [Dev Container metadata reference](https://containers.dev/implementors/json_reference/)
- [5] [Sourcebot](https://www.sourcebot.dev/)
- [6] [Sourcebot search API](https://docs.sourcebot.dev/api-reference/search-%26-navigation/search-code)
- [7] [Sourcebot multi-branch indexing](https://docs.sourcebot.dev/docs/features/search/multi-branch-indexing)
- [8] [Sourcegraph Code Search](https://sourcegraph.com/docs/code-search)
- [9] [Sourcegraph Structural Search](https://sourcegraph.com/docs/code-search/types/structural)
- [10] [Sourcegraph Search Query Syntax](https://sourcegraph.com/docs/code-search/queries)
- [11] [GitLab Advanced Search](https://docs.gitlab.com/user/search/advanced_search/)
- [12] [SearchCode](https://searchcode.com/)
- [13] [Grep.app](https://grep.app/)
- [14] [Authoring a Dev Container Feature](https://containers.dev/guide/author-a-feature)
- [15] [Investigation tools for security incidents](https://docs.github.com/en/enterprise-cloud%40latest/code-security/reference/security-incident-response/investigation-tools)
{{#include ../../banners/hacktricks-training.md}}
