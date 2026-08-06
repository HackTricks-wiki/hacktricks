# Github Dorks & Leaks

{{#include ../../banners/hacktricks-training.md}}


### git repo 및 file system에서 secrets를 찾는 Tools

- [https://github.com/dxa4481/truffleHog](https://github.com/dxa4481/truffleHog)
- [https://github.com/gitleaks/gitleaks](https://github.com/gitleaks/gitleaks)
- [https://github.com/praetorian-inc/noseyparker](https://github.com/praetorian-inc/noseyparker)
- [https://github.com/GitGuardian/ggshield](https://github.com/GitGuardian/ggshield)
- [https://github.com/JaimePolop/RExpository](https://github.com/JaimePolop/RExpository)
- [https://github.com/Yelp/detect-secrets](https://github.com/Yelp/detect-secrets)
- [https://github.com/hisxo/gitGraber](https://github.com/hisxo/gitGraber)
- https://github.com/eth0izzle/shhgit (unmaintained)
- [https://github.com/techgaun/github-dorks](https://github.com/techgaun/github-dorks)
- https://github.com/michenriksen/gitrob (archived)
- https://github.com/anshumanbh/git-all-secrets (archived)
- [https://github.com/awslabs/git-secrets](https://github.com/awslabs/git-secrets)
- [https://github.com/kootenpv/gittyleaks](https://github.com/kootenpv/gittyleaks)
- [https://github.com/obheda12/GitDorker](https://github.com/obheda12/GitDorker)

> 참고
> - TruffleHog v3는 많은 credentials를 실시간으로 검증하고 GitHub orgs, issues/PRs, gists 및 wikis를 scan할 수 있습니다. 예시: `trufflehog github --org <ORG> --results=verified`.<sup>[[2]](#references)</sup>
> - Gitleaks v8은 git history, directories 및 archives scan을 지원합니다: `gitleaks detect -v --source .` 또는 `gitleaks detect --source <repo> --log-opts="--all"`.
> - Nosey Parker는 엄선된 rules를 사용한 high-throughput scanning에 중점을 두며 triage를 위한 Explorer UI를 제공합니다. 예시: `noseyparker scan --datastore np.db <path|repo>`를 실행한 다음 `noseyparker report --datastore np.db`를 실행합니다.
> - ggshield (GitGuardian CLI)는 pre-commit/CI hooks 및 Docker image scanning을 제공합니다: `ggshield secret scan repo <path-or-url>`.

### GitHub에서 secrets가 일반적으로 leak되는 위치

- default 및 non-default branches의 Repository files (UI에서 `repo:owner/name@branch`를 검색).
- 전체 git history 및 기타 branches/tags (clone한 후 gitleaks/trufflehog로 scan; GitHub search는 indexed content에 집중).
- Issues, pull requests, comments 및 descriptions (TruffleHog GitHub source는 `--issue-comments`, `--pr-comments`와 같은 flags를 통해 이를 지원).
- Public repositories의 Actions logs 및 artifacts (masking은 best-effort 방식이므로, 표시되는 경우 logs/artifacts를 검토).
- Wikis 및 release assets.
- Gists (tooling 또는 UI를 사용해 검색; 일부 tools는 gists를 포함할 수 있음).

> 주의 사항
> - GitHub의 REST code search API는 legacy이며 regex를 지원하지 않습니다. Regex searches에는 Web UI를 사용하는 것이 좋습니다. gh CLI는 legacy API를 사용합니다.
> - 일정 크기 이하의 files만 search를 위해 indexed됩니다. 철저히 확인하려면 repository를 clone하고 secrets scanner로 로컬에서 scan합니다.

### Programmatic org-wide scanning

- TruffleHog (GitHub source):<sup>[[2]](#references)</sup>
```bash
export GITHUB_TOKEN=<token>
trufflehog github --org Target --results=verified \
--include-wikis --issue-comments --pr-comments --gist-comments
```
- 모든 조직 repo에서 Gitleaks 실행 (shallow clone 및 scan):
```bash
gh repo list Target --limit 1000 --json nameWithOwner,url \
| jq -r '.[].url' | while read -r r; do
tmp=$(mktemp -d); git clone --depth 1 "$r" "$tmp" && \
gitleaks detect --source "$tmp" -v || true; rm -rf "$tmp";
done
```
- mono checkout에서의 Nosey Parker:
```bash
# after cloning many repos beneath ./org
noseyparker scan --datastore np.db org/ && noseyparker report --datastore np.db
```
- ggshield 빠른 스캔:
```bash
# current working tree
ggshield secret scan path -r .
# full git history of a repo
ggshield secret scan repo <path-or-url>
```
> 팁: Git history의 경우 삭제된 secret을 포착할 수 있도록 `git log -p --all`을 파싱하는 scanner를 우선 사용하세요.

### 최신 token을 위한 업데이트된 dorks

- GitHub tokens: `ghp_` `gho_` `ghu_` `ghs_` `ghr_` `github_pat_`
- Slack tokens: `xoxb-` `xoxp-` `xoxa-` `xoxs-` `xoxc-` `xoxe-`
- 클라우드 및 일반:
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
access_key
bucket_password
dbpassword
dbuser
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
password
path:sites databases password
private -language:java
PT_TOKEN language:bash
redis_password
root_password
secret_access_key
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
{{#ref}}
wide-source-code-search.md
{{#endref}}

## 참고 자료

- [1] [공개 repository에 secret이 노출되지 않도록 하기 (GitHub Blog, 2024년 2월 29일)](https://github.blog/news-insights/product-news/keeping-secrets-out-of-public-repositories/)
- [2] [TruffleHog v3 – 유출된 credential 찾기, 검증 및 분석](https://github.com/trufflesecurity/trufflehog)

{{#include ../../banners/hacktricks-training.md}}
