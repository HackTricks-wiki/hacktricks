# Github Dorks & Leaks

{{#include ../../banners/hacktricks-training.md}}

### Git repo 및 file system에서 secrets를 찾는 Tools

- [TruffleHog](https://github.com/dxa4481/truffleHog)
- [Gitleaks](https://github.com/gitleaks/gitleaks)
- [Nosey Parker](https://github.com/praetorian-inc/noseyparker) (archived; [Titus](https://github.com/praetorian-inc/titus)로 대체됨)
- [ggshield](https://github.com/GitGuardian/ggshield)
- [RExpository](https://github.com/JaimePolop/RExpository)
- [detect-secrets](https://github.com/Yelp/detect-secrets)
- [gitGraber](https://github.com/hisxo/gitGraber)
- [shhgit](https://github.com/eth0izzle/shhgit) (unmaintained)
- [github-dorks](https://github.com/techgaun/github-dorks)
- [gitrob](https://github.com/michenriksen/gitrob) (archived)
- [git-all-secrets](https://github.com/anshumanbh/git-all-secrets) (archived)
- [git-secrets](https://github.com/awslabs/git-secrets)
- [gittyleaks](https://github.com/kootenpv/gittyleaks)
- [GitDorker](https://github.com/obheda12/GitDorker)

> Notes
> - TruffleHog v3는 많은 credentials를 실시간으로 verify하고 GitHub orgs, issues/PRs, gists 및 wikis를 scan할 수 있습니다. 예: `trufflehog github --org <ORG> --results=verified`.<sup>[[2]](#references)[[13]](#references)</sup>
> - Gitleaks는 Git repositories, directories 및 archives를 scan합니다. history에는 `gitleaks git -v --log-opts="--all" <repo>`, directories에는 `gitleaks dir -v <path>`, archives 검사에는 `--max-archive-depth 1`을 사용합니다.<sup>[[6]](#references)</sup>
> - Nosey Parker는 archived 상태이며 Titus로 대체되었습니다. 기존 installations에서는 여전히 `noseyparker scan --datastore np.db <path|repo>`를 실행한 다음 `noseyparker report --datastore np.db`를 사용할 수 있습니다.<sup>[[7]](#references)[[8]](#references)</sup>
> - ggshield (GitGuardian CLI)는 files, repositories 및 Docker images를 scan하며 local 또는 CI workflows와 통합됩니다: `ggshield secret scan repo <path-or-url>`.<sup>[[9]](#references)</sup>

### GitHub에서 secrets가 흔히 leak되는 위치

- GitHub Code Search는 default branch만 index합니다. non-default branches는 직접 inspect하거나 clone해야 합니다.<sup>[[4]](#references)</sup>
- 전체 git history 및 기타 branches/tags (clone한 뒤 gitleaks/trufflehog로 scan; GitHub search는 index된 content만 검색합니다).<sup>[[4]](#references)[[6]](#references)</sup>
- Issues, pull requests, comments 및 descriptions (TruffleHog의 GitHub source는 `--issue-comments` 및 `--pr-comments`와 같은 flags를 통해 이를 지원합니다).<sup>[[2]](#references)</sup>
- Actions workflow logs 및 artifacts (read access가 있으면 이를 보거나 download할 수 있으며, secret redaction은 보장되지 않습니다).<sup>[[11]](#references)[[12]](#references)</sup>
- Wikis 및 release assets.
- Gists (tooling 또는 UI로 검색; 일부 tools는 gists를 포함할 수 있습니다).<sup>[[2]](#references)[[13]](#references)</sup>

> Gotchas
> - GitHub의 Code Search UI는 regex를 지원하지만 REST/API 경로(`gh search code` 포함)는 legacy engine을 사용하며 regex features를 노출하지 않습니다. regex queries에는 UI를 우선 사용하세요.<sup>[[3]](#references)[[5]](#references)</sup>
> - GitHub search는 문서화된 size limit를 초과하는 files를 제외하며 exhaustive하지 않습니다. 철저히 검사하려면 clone한 뒤 secrets scanner로 local scan을 수행하세요.<sup>[[4]](#references)</sup>

### Programmatic org-wide scanning

- TruffleHog (GitHub source).<sup>[[2]](#references)[[13]](#references)</sup>
```bash
export GITHUB_TOKEN=<token>
trufflehog github --org Target --results=verified \
--include-wikis --issue-comments --pr-comments --gist-comments
```
- 조직의 모든 repo에 Gitleaks 적용 (shallow clone 후 `gitleaks dir`로 scan).<sup>[[6]](#references)</sup>
```bash
gh repo list Target --limit 1000 --json nameWithOwner,url \
| jq -r '.[].url' | while read -r r; do
tmp=$(mktemp -d); git clone --depth 1 "$r" "$tmp" && \
gitleaks dir -v "$tmp" || true; rm -rf "$tmp";
done
```
- 기존 설치 환경에서 mono checkout에 대해 Nosey Parker를 실행합니다.<sup>[[7]](#references)</sup>
```bash
# after cloning many repos beneath ./org
noseyparker scan --datastore np.db org/ && noseyparker report --datastore np.db
```
- ggshield 빠른 scan.<sup>[[9]](#references)</sup>
```bash
# current working tree
ggshield secret scan path -r .
# full git history of a repo
ggshield secret scan repo <path-or-url>
```
> 팁: git history의 경우 삭제된 secrets를 포착할 수 있도록 `git log -p --all`을 파싱하는 scanner를 우선 사용하세요.<sup>[[6]](#references)</sup>

### 최신 token을 위한 Dorks

- GitHub tokens: `ghp_` `gho_` `ghu_` `ghs_` `ghr_` `github_pat_`.<sup>[[10]](#references)</sup>
- Slack tokens: `xoxb-` `xoxp-` `xoxa-` `xoxs-` `xoxc-` `xoxe-`
- Cloud 및 일반:
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
추가적인 code-search workflows는 [Wide Source Code Search](wide-source-code-search.md)를 참조하세요.

## References

- [1] [public repositories에서 secrets 제외하기 (GitHub Blog, 2024년 2월 29일)](https://github.blog/news-insights/product-news/keeping-secrets-out-of-public-repositories/)
- [2] [TruffleHog v3 – leak된 credentials 찾기, verify 및 analyze](https://github.com/trufflesecurity/trufflehog)
- [3] [GitHub Code Search syntax 이해하기](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [4] [code 검색 (legacy)](https://docs.github.com/en/search-github/searching-on-github/searching-code)
- [5] [gh search code](https://cli.github.com/manual/gh_search_code)
- [6] [Gitleaks README](https://github.com/gitleaks/gitleaks/blob/master/README.md)
- [7] [Nosey Parker README](https://github.com/praetorian-inc/noseyparker#readme)
- [8] [Titus README](https://github.com/praetorian-inc/titus#readme)
- [9] [ggshield README](https://github.com/GitGuardian/ggshield#readme)
- [10] [Secrets reference (GitHub Actions)](https://docs.github.com/en/actions/reference/security/secrets)
- [11] [Secrets (GitHub Actions)](https://docs.github.com/en/actions/concepts/security/secrets)
- [12] [workflow run logs 사용하기 (GitHub Actions)](https://docs.github.com/en/actions/how-tos/monitor-workflows/use-workflow-run-logs)
- [13] [TruffleHog GitHub source](https://github.com/trufflesecurity/trufflehog/blob/main/main.go)
{{#include ../../banners/hacktricks-training.md}}
