# Github Dorks & Leaks

{{#include ../../banners/hacktricks-training.md}}

### 用于在 git 仓库和文件系统中查找 secrets 的工具

- [TruffleHog](https://github.com/dxa4481/truffleHog)
- [Gitleaks](https://github.com/gitleaks/gitleaks)
- [Nosey Parker](https://github.com/praetorian-inc/noseyparker) (已归档；由 [Titus](https://github.com/praetorian-inc/titus) 取代)
- [ggshield](https://github.com/GitGuardian/ggshield)
- [RExpository](https://github.com/JaimePolop/RExpository)
- [detect-secrets](https://github.com/Yelp/detect-secrets)
- [gitGraber](https://github.com/hisxo/gitGraber)
- [shhgit](https://github.com/eth0izzle/shhgit) (已停止维护)
- [github-dorks](https://github.com/techgaun/github-dorks)
- [gitrob](https://github.com/michenriksen/gitrob) (已归档)
- [git-all-secrets](https://github.com/anshumanbh/git-all-secrets) (已归档)
- [git-secrets](https://github.com/awslabs/git-secrets)
- [gittyleaks](https://github.com/kootenpv/gittyleaks)
- [GitDorker](https://github.com/obheda12/GitDorker)

> 注意
> - TruffleHog v3 可以实时验证许多凭据，并扫描 GitHub 组织、issues/PRs、gists 和 wikis。例如：`trufflehog github --org <ORG> --results=verified`。<sup>[[2]](#references)[[13]](#references)</sup>
> - Gitleaks 可以扫描 Git 仓库、目录和归档文件。使用 `gitleaks git -v --log-opts="--all" <repo>` 扫描历史记录，使用 `gitleaks dir -v <path>` 扫描目录，并使用 `--max-archive-depth 1` 检查归档文件。<sup>[[6]](#references)</sup>
> - Nosey Parker 已归档，由 Titus 取代。现有安装仍支持运行 `noseyparker scan --datastore np.db <path|repo>`，然后运行 `noseyparker report --datastore np.db`。<sup>[[7]](#references)[[8]](#references)</sup>
> - ggshield (GitGuardian CLI) 可以扫描文件、仓库和 Docker 镜像，并集成到本地或 CI 工作流中：`ggshield secret scan repo <path-or-url>`。<sup>[[9]](#references)</sup>

### GitHub 上常见的 secrets leak 位置

- GitHub Code Search 仅索引默认分支；请直接检查非默认分支或克隆这些分支。<sup>[[4]](#references)</sup>
- 完整的 git 历史记录以及其他分支/标签（克隆后使用 gitleaks/trufflehog 扫描；GitHub 搜索仅覆盖已索引的内容）。<sup>[[4]](#references)[[6]](#references)</sup>
- Issues、pull requests、评论和描述（TruffleHog 的 GitHub source 支持通过 `--issue-comments` 和 `--pr-comments` 等 flags 扫描这些内容）。<sup>[[2]](#references)</sup>
- Actions workflow 日志和 artifacts（具有读取权限即可查看或下载这些内容，且不能保证 secrets 一定会被遮蔽）。<sup>[[11]](#references)[[12]](#references)</sup>
- Wikis 和 release assets。
- Gists（使用工具或 UI 搜索；某些工具可以将 gists 纳入扫描）。<sup>[[2]](#references)[[13]](#references)</sup>

> 注意事项
> - GitHub 的 Code Search UI 支持 regex，而 REST/API 路径（包括 `gh search code`）使用旧版引擎，不支持 regex 功能。regex 查询建议使用 UI。<sup>[[3]](#references)[[5]](#references)</sup>
> - GitHub 搜索会排除超过其文档规定大小限制的文件，且无法穷尽所有内容。要全面检查，请克隆仓库，并在本地使用 secrets scanner 扫描。<sup>[[4]](#references)</sup>

### 以编程方式扫描整个组织

- TruffleHog (GitHub source)。<sup>[[2]](#references)[[13]](#references)</sup>
```bash
export GITHUB_TOKEN=<token>
trufflehog github --org Target --results=verified \
  --include-wikis --issue-comments --pr-comments --gist-comments
```
- 对所有组织仓库运行 Gitleaks（浅克隆并使用 `gitleaks dir` 扫描）。<sup>[[6]](#references)</sup>
```bash
gh repo list Target --limit 1000 --json nameWithOwner,url \
| jq -r '.[].url' | while read -r r; do
  tmp=$(mktemp -d); git clone --depth 1 "$r" "$tmp" && \
  gitleaks dir -v "$tmp" || true; rm -rf "$tmp";
done
```
- 对 mono checkout 运行 Nosey Parker（适用于现有安装）。<sup>[[7]](#references)</sup>
```bash
# after cloning many repos beneath ./org
noseyparker scan --datastore np.db org/ && noseyparker report --datastore np.db
```
- ggshield 快速扫描。<sup>[[9]](#references)</sup>
```bash
# current working tree
ggshield secret scan path -r .
# full git history of a repo
ggshield secret scan repo <path-or-url>
```

> 提示：对于 git 历史，优先使用能解析 `git log -p --all` 的扫描器，以发现已移除的 secrets。<sup>[[6]](#references)</sup>

### Pull-request refs 和 Gist 修订历史

普通 clone 不会获取 GitHub 的 `refs/pull/<number>/head` refs，因此 `git log --all` 会漏掉仅能通过这些 refs 访问的 commits，除非先获取它们。<sup>[[14]](#references)[[17]](#references)</sup> 即使贡献者删除了自己的 fork，PR refs 仍可能暴露未合并的 commits。<sup>[[15]](#references)</sup> 仅重写分支历史，可能仍会让敏感 commits 可通过 PR references 访问。<sup>[[16]](#references)</sup>

在完整 clone 中，扫描前先获取选定 PR 的 head；如果额外下载是合理的，也可以使用通配 refspec 获取所有已公布的 PR heads。<sup>[[17]](#references)[[18]](#references)</sup> Gitleaks 使用 `git log -p` 扫描本地 commit patches，因此获取这些 refs 后应重新运行扫描。<sup>[[6]](#references)</sup>

```bash
git fetch origin 'refs/pull/123/head:refs/remotes/origin/pr/123'
# Or fetch every advertised PR head:
git fetch origin '+refs/pull/*/head:refs/remotes/origin/pr/*'
gitleaks git -v --log-opts="--all" .
```

Gist 也有 Git 历史记录，因此只检查当前文件可能会漏掉在后续版本中移除的凭据。<sup>[[19]](#references)</sup> 对于范围内的公开 Gist，可克隆其 Git 仓库并扫描各个版本。<sup>[[19]](#references)[[6]](#references)</sup>

```bash
git clone https://gist.github.com/GIST_ID.git
gitleaks git -v --log-opts="--all" GIST_ID
```

### 适用于现代 tokens 的更新版 dorks

- GitHub tokens：`ghp_` `gho_` `ghu_` `ghs_` `ghr_` `github_pat_`.<sup>[[10]](#references)</sup>
- Slack tokens：`xoxb-` `xoxp-` `xoxa-` `xoxs-` `xoxc-` `xoxe-`
- 云服务和通用项：
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

有关其他代码搜索工作流，请参阅 [广泛的源代码搜索](wide-source-code-search.md)。



## References

- [1] [防止机密出现在公开仓库中（GitHub Blog，2024 年 2 月 29 日）](https://github.blog/news-insights/product-news/keeping-secrets-out-of-public-repositories/)
- [2] [TruffleHog v3 – 查找、验证并分析 leaked 凭证](https://github.com/trufflesecurity/trufflehog)
- [3] [了解 GitHub Code Search 语法](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [4] [搜索代码（旧版）](https://docs.github.com/en/search-github/searching-on-github/searching-code)
- [5] [gh search code](https://cli.github.com/manual/gh_search_code)
- [6] [Gitleaks README](https://github.com/gitleaks/gitleaks/blob/master/README.md)
- [7] [Nosey Parker README](https://github.com/praetorian-inc/noseyparker#readme)
- [8] [Titus README](https://github.com/praetorian-inc/titus#readme)
- [9] [ggshield README](https://github.com/GitGuardian/ggshield#readme)
- [10] [Secrets 参考（GitHub Actions）](https://docs.github.com/en/actions/reference/security/secrets)
- [11] [Secrets（GitHub Actions）](https://docs.github.com/en/actions/concepts/security/secrets)
- [12] [使用工作流运行日志（GitHub Actions）](https://docs.github.com/en/actions/how-tos/monitor-workflows/use-workflow-run-logs)
- [13] [TruffleHog GitHub 源代码](https://github.com/trufflesecurity/trufflehog/blob/main/main.go)
- [14] [Pull request refs 和合并分支（GitHub Docs）](https://docs.github.com/en/pull-requests/reference/pull-requests)
- [15] [在本地检出 pull request（GitHub Docs）](https://docs.github.com/en/pull-requests/how-tos/review-pull-requests/checking-out-pull-requests-locally)
- [16] [从仓库中删除敏感数据（GitHub Docs）](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
- [17] [git-fetch 文档](https://git-scm.com/docs/git-fetch)
- [18] [扫描 pull request（betterleaks）](https://github.com/betterleaks/betterleaks/blob/main/docs/scanning.md)
- [19] [Gists 的 REST API 端点（GitHub Docs）](https://docs.github.com/en/rest/gists/gists)
{{#include ../../banners/hacktricks-training.md}}
