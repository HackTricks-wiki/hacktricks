# Github Dorks & Leaks

{{#include ../../banners/hacktricks-training.md}}

### git repoやファイルシステム内のsecretを見つけるツール

- [TruffleHog](https://github.com/dxa4481/truffleHog)
- [Gitleaks](https://github.com/gitleaks/gitleaks)
- [Nosey Parker](https://github.com/praetorian-inc/noseyparker) (アーカイブ済み。後継は[Titus](https://github.com/praetorian-inc/titus))
- [ggshield](https://github.com/GitGuardian/ggshield)
- [RExpository](https://github.com/JaimePolop/RExpository)
- [detect-secrets](https://github.com/Yelp/detect-secrets)
- [gitGraber](https://github.com/hisxo/gitGraber)
- [shhgit](https://github.com/eth0izzle/shhgit) (メンテナンス終了)
- [github-dorks](https://github.com/techgaun/github-dorks)
- [gitrob](https://github.com/michenriksen/gitrob) (アーカイブ済み)
- [git-all-secrets](https://github.com/anshumanbh/git-all-secrets) (アーカイブ済み)
- [git-secrets](https://github.com/awslabs/git-secrets)
- [gittyleaks](https://github.com/kootenpv/gittyleaks)
- [GitDorker](https://github.com/obheda12/GitDorker)

> 注意事項
> - TruffleHog v3は多くのcredentialをリアルタイムで検証でき、GitHub org、issue/PR、gist、wikiをスキャンできます。例: `trufflehog github --org <ORG> --results=verified`.<sup>[[2]](#references)[[13]](#references)</sup>
> - GitleaksはGit repository、directory、archiveをスキャンします。履歴のスキャンには`gitleaks git -v --log-opts="--all" <repo>`、directoryのスキャンには`gitleaks dir -v <path>`を使い、archiveを調べるには`--max-archive-depth 1`を指定します。<sup>[[6]](#references)</sup>
> - Nosey Parkerはアーカイブ済みで、後継はTitusです。既存のインストール環境では、`noseyparker scan --datastore np.db <path|repo>`に続けて`noseyparker report --datastore np.db`を実行できます。<sup>[[7]](#references)[[8]](#references)</sup>
> - ggshield (GitGuardian CLI)はファイル、repository、Docker imageをスキャンし、ローカルやCIのworkflowと連携します: `ggshield secret scan repo <path-or-url>`.<sup>[[9]](#references)</sup>

### GitHubでsecretがよくleakする場所

- GitHub Code Searchがインデックスするのはdefault branchのみです。default branch以外は直接確認するか、cloneしてください。<sup>[[4]](#references)</sup>
- gitの全履歴およびその他のbranch/tag (cloneしてgitleaks/trufflehogでスキャンしてください。GitHub検索が対象とするのはインデックス済みのコンテンツのみです)。<sup>[[4]](#references)[[6]](#references)</sup>
- issue、pull request、comment、description (TruffleHogのGitHub sourceでは、`--issue-comments`や`--pr-comments`などのflagでこれらをスキャンできます)。<sup>[[2]](#references)</sup>
- Actionsのworkflow logとartifact (読み取り権限があれば閲覧またはダウンロードできます。また、secretが確実にマスキングされるとは限りません)。<sup>[[11]](#references)[[12]](#references)</sup>
- wikiとrelease asset。
- gist (ツールまたはUIで検索できます。一部のツールはgistも対象にできます)。<sup>[[2]](#references)[[13]](#references)</sup>

> 注意点
> - GitHub Code Search UIはregexに対応していますが、REST/API経由の検索 (`gh search code`を含む) では旧式のエンジンが使われ、regex機能は公開されていません。regexクエリにはUIを使ってください。<sup>[[3]](#references)[[5]](#references)</sup>
> - GitHub検索では、文書化されたサイズ上限を超えるファイルは対象外となり、網羅的な検索はできません。漏れなく調べるには、cloneしてローカルでsecret scannerを実行してください。<sup>[[4]](#references)</sup>

### org全体のプログラムによるスキャン

- TruffleHog (GitHub source)。<sup>[[2]](#references)[[13]](#references)</sup>
```bash
export GITHUB_TOKEN=<token>
trufflehog github --org Target --results=verified \
  --include-wikis --issue-comments --pr-comments --gist-comments
```
- すべての組織リポジトリを対象に Gitleaks を実行する（shallow clone し、`gitleaks dir` でスキャンする）。<sup>[[6]](#references)</sup>
```bash
gh repo list Target --limit 1000 --json nameWithOwner,url \
| jq -r '.[].url' | while read -r r; do
  tmp=$(mktemp -d); git clone --depth 1 "$r" "$tmp" && \
  gitleaks dir -v "$tmp" || true; rm -rf "$tmp";
done
```
- mono checkout 上で Nosey Parker を実行（既存のインストール向け）。<sup>[[7]](#references)</sup>
```bash
# after cloning many repos beneath ./org
noseyparker scan --datastore np.db org/ && noseyparker report --datastore np.db
```
- ggshieldのクイックスキャン。<sup>[[9]](#references)</sup>
```bash
# current working tree
ggshield secret scan path -r .
# full git history of a repo
ggshield secret scan repo <path-or-url>
```

> Tip: git history については、削除された secrets を検出できるよう、`git log -p --all` を解析する scanner を優先してください。<sup>[[6]](#references)</sup>

### Pull-request refs と Gist revision history

通常の clone では GitHub の `refs/pull/<number>/head` refs は取得されないため、取得するまでは `git log --all` でそれらの refs からのみ到達可能な commit を検出できません。<sup>[[14]](#references)[[17]](#references)</sup> PR refs からは、contributor が fork を削除した後でも、未 merge の commit が公開される可能性があります。<sup>[[15]](#references)</sup> branch history の書き換えだけでは、PR references を通じて機密性の高い commit に到達可能なままの場合があります。<sup>[[16]](#references)</sup>

full clone では、scan の前に選択した PR head を fetch するか、追加の download に見合う場合は、広告されているすべての PR head に対する wildcard refspec を使用してください。<sup>[[17]](#references)[[18]](#references)</sup> Gitleaks は `git log -p` を使ってローカルの commit patch を scan するため、refs の fetch 後に再実行してください。<sup>[[6]](#references)</sup>

```bash
git fetch origin 'refs/pull/123/head:refs/remotes/origin/pr/123'
# Or fetch every advertised PR head:
git fetch origin '+refs/pull/*/head:refs/remotes/origin/pr/*'
gitleaks git -v --log-opts="--all" .
```

GistにもGit履歴があるため、現在のファイルだけを確認すると、後のリビジョンで削除された認証情報を見落とすことがあります。<sup>[[19]](#references)</sup> スコープ内の公開Gistについては、Gitリポジトリをcloneして各リビジョンをスキャンしてください。<sup>[[19]](#references)[[6]](#references)</sup>

```bash
git clone https://gist.github.com/GIST_ID.git
gitleaks git -v --log-opts="--all" GIST_ID
```

### modern tokens向けに更新されたdorks

- GitHub tokens: `ghp_` `gho_` `ghu_` `ghs_` `ghr_` `github_pat_`.<sup>[[10]](#references)</sup>
- Slack tokens: `xoxb-` `xoxp-` `xoxa-` `xoxs-` `xoxc-` `xoxe-`
- Cloudおよび一般:
  - `AWS_ACCESS_KEY_ID` `AWS_SECRET_ACCESS_KEY` `aws_session_token`
  - `GOOGLE_API_KEY` `AZURE_TENANT_ID` `AZURE_CLIENT_SECRET`
  - `OPENAI_API_KEY` `ANTHROPIC_API_KEY`

### **Dorks**

```bash
".mlab.com password"
"access_key"
"access_token"
"amazonaws"
"api.googlemaps AIza"
"api_key"
"api_secret"
"apidocs"
"apikey"
"apiSecret"
"app_key"
"app_secret"
"appkey"
"appkeysecret"
"application_key"
"appsecret"
"appspot"
"auth"
"auth_token"
"authorizationToken"
"aws_access"
"aws_access_key_id"
"aws_key"
"aws_secret"
"aws_token"
"AWSSecretKey"
"bashrc password"
"bucket_password"
"client_secret"
"cloudfront"
"codecov_token"
"config"
"conn.login"
"connectionstring"
"consumer_key"
"credentials"
"database_password"
"db_password"
"db_username"
"dbpasswd"
"dbpassword"
"dbuser"
"dot-files"
"dotfiles"
"encryption_key"
"fabricApiSecret"
"fb_secret"
"firebase"
"ftp"
"gh_token"
"github_key"
"github_token"
"gitlab"
"gmail_password"
"gmail_username"
"herokuapp"
"internal"
"irc_pass"
"JEKYLL_GITHUB_TOKEN"
"key"
"keyPassword"
"ldap_password"
"ldap_username"
"login"
"mailchimp"
"mailgun"
"master_key"
"mydotfiles"
"mysql"
"node_env"
"npmrc _auth"
"oauth_token"
"pass"
"passwd"
"password"
"passwords"
"pem private"
"preprod"
"private_key"
"prod"
"pwd"
"pwds"
"rds.amazonaws.com password"
"redis_password"
"root_password"
"secret"
"secret.password"
"secret_access_key"
"secret_key"
"secret_token"
"secrets"
"secure"
"security_credentials"
"send.keys"
"send_keys"
"sendkeys"
"SF_USERNAME salesforce"
"sf_username"
"site.com" FIREBASE_API_JSON=
"site.com" vim_settings.xml
"slack_api"
"slack_token"
"sql_password"
"ssh"
"ssh2_auth_password"
"sshpass"
"staging"
"stg"
"storePassword"
"stripe"
"swagger"
"testuser"
"token"
"x-api-key"
"xoxb "
"xoxp"
[WFClient] Password= extension:ica
extension:avastlic "support.avast.com"
extension:bat
extension:cfg
extension:env
extension:exs
extension:ini
extension:json api.forecast.io
extension:json googleusercontent client_secret
extension:json mongolab.com
extension:pem
extension:pem private
extension:ppk
extension:ppk private
extension:properties
extension:sh
extension:sls
extension:sql
extension:sql mysql dump
extension:sql mysql dump password
extension:yaml mongolab.com
extension:zsh
filename:.bash_history
filename:.bash_history DOMAIN-NAME
filename:.bash_profile aws
filename:.bashrc mailchimp
filename:.bashrc password
filename:.cshrc
filename:.dockercfg auth
filename:.env DB_USERNAME NOT homestead
filename:.env MAIL_HOST=smtp.gmail.com
filename:.esmtprc password
filename:.ftpconfig
filename:.git-credentials
filename:.history
filename:.htpasswd
filename:.netrc password
filename:.npmrc _auth
filename:.pgpass
filename:.remote-sync.json
filename:.s3cfg
filename:.sh_history
filename:.tugboat NOT _tugboat
filename:_netrc password
filename:apikey
filename:bash
filename:bash_history
filename:bash_profile
filename:bashrc
filename:beanstalkd.yml
filename:CCCam.cfg
filename:composer.json
filename:config
filename:config irc_pass
filename:config.json auths
filename:config.php dbpasswd
filename:configuration.php JConfig password
filename:connections
filename:connections.xml
filename:constants
filename:credentials
filename:credentials aws_access_key_id
filename:cshrc
filename:database
filename:dbeaver-data-sources.xml
filename:deployment-config.json
filename:dhcpd.conf
filename:dockercfg
filename:environment
filename:express.conf
filename:express.conf path:.openshift
filename:filezilla.xml
filename:filezilla.xml Pass
filename:git-credentials
filename:gitconfig
filename:global
filename:history
filename:htpasswd
filename:hub oauth_token
filename:id_dsa
filename:id_rsa
filename:id_rsa or filename:id_dsa
filename:idea14.key
filename:known_hosts
filename:logins.json
filename:makefile
filename:master.key path:config
filename:netrc
filename:npmrc
filename:pass
filename:passwd path:etc
filename:pgpass
filename:prod.exs
filename:prod.exs NOT prod.secret.exs
filename:prod.secret.exs
filename:proftpdpasswd
filename:recentservers.xml
filename:recentservers.xml Pass
filename:robomongo.json
filename:s3cfg
filename:secrets.yml password
filename:server.cfg
filename:server.cfg rcon password
filename:settings
filename:settings.py SECRET_KEY
filename:sftp-config.json
filename:sftp-config.json password
filename:sftp.json path:.vscode
filename:shadow
filename:shadow path:etc
filename:spec
filename:sshd_config
filename:token
filename:tugboat
filename:ventrilo_srv.ini
filename:WebServers.xml
filename:wp-config
filename:wp-config.php
filename:zhrc
HEROKU_API_KEY language:json
HEROKU_API_KEY language:shell
HOMEBREW_GITHUB_API_TOKEN language:shell
jsforce extension:js conn.login
language:yaml -filename:travis
msg nickserv identify filename:config
org:Target "AWS_ACCESS_KEY_ID"
org:Target "list_aws_accounts"
org:Target "aws_access_key"
org:Target "aws_secret_key"
org:Target "bucket_name"
org:Target "S3_ACCESS_KEY_ID"
org:Target "S3_BUCKET"
org:Target "S3_ENDPOINT"
org:Target "S3_SECRET_ACCESS_KEY"
path:sites databases password
private -language:java
PT_TOKEN language:bash
SECRET_KEY_BASE=
shodan_api_key language:python
WORDPRESS_DB_PASSWORD=
xoxp OR xoxb OR xoxa
s3.yml
.exs
beanstalkd.yml
deploy.rake
.sls
AWS_SECRET_ACCESS_KEY
API KEY
API SECRET
API TOKEN
ROOT PASSWORD
ADMIN PASSWORD
GCP SECRET
AWS SECRET
"private" extension:pgp
```

追加の code-search ワークフローについては、[Wide Source Code Search](wide-source-code-search.md) を参照してください。



## References

- [1] [公開リポジトリに secrets を含めない（GitHub Blog、2024年2月29日）](https://github.blog/news-insights/product-news/keeping-secrets-out-of-public-repositories/)
- [2] [TruffleHog v3 – leak された認証情報の発見、検証、分析](https://github.com/trufflesecurity/trufflehog)
- [3] [GitHub Code Search 構文を理解する](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [4] [コードを検索する（legacy）](https://docs.github.com/en/search-github/searching-on-github/searching-code)
- [5] [gh search code](https://cli.github.com/manual/gh_search_code)
- [6] [Gitleaks README](https://github.com/gitleaks/gitleaks/blob/master/README.md)
- [7] [Nosey Parker README](https://github.com/praetorian-inc/noseyparker#readme)
- [8] [Titus README](https://github.com/praetorian-inc/titus#readme)
- [9] [ggshield README](https://github.com/GitGuardian/ggshield#readme)
- [10] [Secrets リファレンス（GitHub Actions）](https://docs.github.com/en/actions/reference/security/secrets)
- [11] [Secrets（GitHub Actions）](https://docs.github.com/en/actions/concepts/security/secrets)
- [12] [ワークフロー実行ログの使用（GitHub Actions）](https://docs.github.com/en/actions/how-tos/monitor-workflows/use-workflow-run-logs)
- [13] [TruffleHog GitHub ソースコード](https://github.com/trufflesecurity/trufflehog/blob/main/main.go)
- [14] [pull request の refs と merge ブランチ（GitHub Docs）](https://docs.github.com/en/pull-requests/reference/pull-requests)
- [15] [pull request をローカルで checkout する（GitHub Docs）](https://docs.github.com/en/pull-requests/how-tos/review-pull-requests/checking-out-pull-requests-locally)
- [16] [リポジトリから機密データを削除する（GitHub Docs）](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
- [17] [git-fetch ドキュメント](https://git-scm.com/docs/git-fetch)
- [18] [pull request のスキャン（betterleaks）](https://github.com/betterleaks/betterleaks/blob/main/docs/scanning.md)
- [19] [Gists の REST API エンドポイント（GitHub Docs）](https://docs.github.com/en/rest/gists/gists)
{{#include ../../banners/hacktricks-training.md}}
