# Github Dorks & Leaks

{{#include ../../banners/hacktricks-training.md}}

### git repo 및 파일 시스템에서 secrets를 찾는 도구

- [TruffleHog](https://github.com/dxa4481/truffleHog)
- [Gitleaks](https://github.com/gitleaks/gitleaks)
- [Nosey Parker](https://github.com/praetorian-inc/noseyparker) (아카이브됨; [Titus](https://github.com/praetorian-inc/titus)로 대체됨)
- [ggshield](https://github.com/GitGuardian/ggshield)
- [RExpository](https://github.com/JaimePolop/RExpository)
- [detect-secrets](https://github.com/Yelp/detect-secrets)
- [gitGraber](https://github.com/hisxo/gitGraber)
- [shhgit](https://github.com/eth0izzle/shhgit) (유지 관리되지 않음)
- [github-dorks](https://github.com/techgaun/github-dorks)
- [gitrob](https://github.com/michenriksen/gitrob) (아카이브됨)
- [git-all-secrets](https://github.com/anshumanbh/git-all-secrets) (아카이브됨)
- [git-secrets](https://github.com/awslabs/git-secrets)
- [gittyleaks](https://github.com/kootenpv/gittyleaks)
- [GitDorker](https://github.com/obheda12/GitDorker)

> 참고
> - TruffleHog v3는 다양한 credentials를 실시간으로 검증하고 GitHub org, issues/PRs, gists 및 wikis를 스캔할 수 있습니다. 예: `trufflehog github --org <ORG> --results=verified`.<sup>[[2]](#references)[[13]](#references)</sup>
> - Gitleaks는 Git repositories, directories 및 archives를 스캔합니다. 전체 history를 스캔하려면 `gitleaks git -v --log-opts="--all" <repo>`를, directories를 스캔하려면 `gitleaks dir -v <path>`를 사용하고, archives를 검사하려면 `--max-archive-depth 1`을 사용하세요.<sup>[[6]](#references)</sup>
> - Nosey Parker는 아카이브되었으며 Titus로 대체되었습니다. 기존 설치본에서도 `noseyparker scan --datastore np.db <path|repo>`를 실행한 다음 `noseyparker report --datastore np.db`를 실행할 수 있습니다.<sup>[[7]](#references)[[8]](#references)</sup>
> - ggshield (GitGuardian CLI)는 files, repositories 및 Docker images를 스캔하며 로컬 또는 CI workflows와 통합됩니다: `ggshield secret scan repo <path-or-url>`.<sup>[[9]](#references)</sup>

### GitHub에서 secrets가 흔히 leak되는 곳

- GitHub Code Search는 default branch만 인덱싱합니다. 다른 branches는 직접 확인하거나 clone하세요.<sup>[[4]](#references)</sup>
- 전체 git history와 다른 branches/tags (clone한 뒤 gitleaks/trufflehog로 스캔하세요. GitHub 검색은 인덱싱된 콘텐츠만 다룹니다).<sup>[[4]](#references)[[6]](#references)</sup>
- Issues, pull requests, comments 및 descriptions (TruffleHog의 GitHub source는 `--issue-comments`, `--pr-comments` 등의 flags를 통해 이를 지원합니다).<sup>[[2]](#references)</sup>
- Actions workflow logs 및 artifacts (읽기 권한이 있으면 확인하거나 다운로드할 수 있으며, secrets가 반드시 redaction되는 것은 아닙니다).<sup>[[11]](#references)[[12]](#references)</sup>
- Wikis 및 release assets.
- Gists (도구나 UI로 검색하세요. 일부 도구는 gists도 포함할 수 있습니다).<sup>[[2]](#references)[[13]](#references)</sup>

> 주의할 점
> - GitHub의 Code Search UI는 regex를 지원하지만 REST/API 경로(`gh search code` 포함)는 legacy engine을 사용하며 regex 기능을 제공하지 않습니다. regex 쿼리에는 UI를 사용하는 것이 좋습니다.<sup>[[3]](#references)[[5]](#references)</sup>
> - GitHub 검색은 문서화된 크기 제한을 초과하는 files를 제외하며, 모든 콘텐츠를 빠짐없이 검색하지는 않습니다. 철저히 확인하려면 clone한 뒤 로컬에서 secrets scanner로 스캔하세요.<sup>[[4]](#references)</sup>

### 조직 전체를 프로그래밍 방식으로 스캔하기

- TruffleHog (GitHub source).<sup>[[2]](#references)[[13]](#references)</sup>
```bash
export GITHUB_TOKEN=<token>
trufflehog github --org Target --results=verified \
  --include-wikis --issue-comments --pr-comments --gist-comments
```
- 모든 org repo에서 Gitleaks 실행 (shallow clone한 뒤 `gitleaks dir`로 스캔).<sup>[[6]](#references)</sup>
```bash
gh repo list Target --limit 1000 --json nameWithOwner,url \
| jq -r '.[].url' | while read -r r; do
  tmp=$(mktemp -d); git clone --depth 1 "$r" "$tmp" && \
  gitleaks dir -v "$tmp" || true; rm -rf "$tmp";
done
```
- (기존 설치의 경우) mono checkout에서 Nosey Parker 실행.<sup>[[7]](#references)</sup>
```bash
# after cloning many repos beneath ./org
noseyparker scan --datastore np.db org/ && noseyparker report --datastore np.db
```
- ggshield 빠른 스캔.<sup>[[9]](#references)</sup>
```bash
# current working tree
ggshield secret scan path -r .
# full git history of a repo
ggshield secret scan repo <path-or-url>
```

> 팁: git history에서는 삭제된 secrets도 포착할 수 있도록 `git log -p --all`을 파싱하는 scanner를 우선 사용하세요.<sup>[[6]](#references)</sup>

### Pull-request refs 및 Gist revision history

일반적인 clone은 GitHub의 `refs/pull/<number>/head` refs를 가져오지 않으므로, 해당 refs를 가져오기 전까지 `git log --all`은 그 refs를 통해서만 접근할 수 있는 commit을 놓칩니다.<sup>[[14]](#references)[[17]](#references)</sup> PR refs에는 기여자가 fork를 삭제한 후에도 병합되지 않은 commit이 노출될 수 있습니다.<sup>[[15]](#references)</sup> branch history만 다시 작성해도 민감한 commit이 PR references를 통해 계속 접근 가능할 수 있습니다.<sup>[[16]](#references)</sup>

전체 clone에서는 스캔 전에 선택한 PR head를 가져오거나, 추가 다운로드가 정당화되는 경우 모든 공개된 PR head에 wildcard refspec을 사용하세요.<sup>[[17]](#references)[[18]](#references)</sup> Gitleaks는 `git log -p`를 사용해 로컬 commit patch를 스캔하므로, refs를 가져온 후 다시 실행하세요.<sup>[[6]](#references)</sup>

```bash
git fetch origin 'refs/pull/123/head:refs/remotes/origin/pr/123'
# Or fetch every advertised PR head:
git fetch origin '+refs/pull/*/head:refs/remotes/origin/pr/*'
gitleaks git -v --log-opts="--all" .
```

Gist에도 Git history가 있으므로 현재 파일만 확인하면 이후 revision에서 제거된 credential을 놓칠 수 있습니다.<sup>[[19]](#references)</sup> 범위 내의 public Gist라면 Git repository를 clone하고 revision을 scan하세요.<sup>[[19]](#references)[[6]](#references)</sup>

```bash
git clone https://gist.github.com/GIST_ID.git
gitleaks git -v --log-opts="--all" GIST_ID
```

### 최신 토큰을 위한 업데이트된 dorks

- GitHub 토큰: `ghp_` `gho_` `ghu_` `ghs_` `ghr_` `github_pat_`.<sup>[[10]](#references)</sup>
- Slack 토큰: `xoxb-` `xoxp-` `xoxa-` `xoxs-` `xoxc-` `xoxe-`
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

추가 코드 검색 워크플로는 [광범위한 소스 코드 검색](wide-source-code-search.md)을 참조하세요.



## References

- [1] [공개 저장소에 secrets를 올리지 않는 방법 (GitHub Blog, 2024년 2월 29일)](https://github.blog/news-insights/product-news/keeping-secrets-out-of-public-repositories/)
- [2] [TruffleHog v3 – 유출된 자격 증명 찾기, 검증 및 분석](https://github.com/trufflesecurity/trufflehog)
- [3] [GitHub Code Search 구문 이해하기](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [4] [코드 검색 (레거시)](https://docs.github.com/en/search-github/searching-on-github/searching-code)
- [5] [gh search code](https://cli.github.com/manual/gh_search_code)
- [6] [Gitleaks README](https://github.com/gitleaks/gitleaks/blob/master/README.md)
- [7] [Nosey Parker README](https://github.com/praetorian-inc/noseyparker#readme)
- [8] [Titus README](https://github.com/praetorian-inc/titus#readme)
- [9] [ggshield README](https://github.com/GitGuardian/ggshield#readme)
- [10] [Secrets 참조 문서 (GitHub Actions)](https://docs.github.com/en/actions/reference/security/secrets)
- [11] [Secrets (GitHub Actions)](https://docs.github.com/en/actions/concepts/security/secrets)
- [12] [워크플로 실행 로그 사용하기 (GitHub Actions)](https://docs.github.com/en/actions/how-tos/monitor-workflows/use-workflow-run-logs)
- [13] [TruffleHog GitHub 소스 코드](https://github.com/trufflesecurity/trufflehog/blob/main/main.go)
- [14] [Pull request refs 및 merge 브랜치 (GitHub Docs)](https://docs.github.com/en/pull-requests/reference/pull-requests)
- [15] [Pull request를 로컬에서 체크아웃하기 (GitHub Docs)](https://docs.github.com/en/pull-requests/how-tos/review-pull-requests/checking-out-pull-requests-locally)
- [16] [저장소에서 민감한 데이터 제거하기 (GitHub Docs)](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
- [17] [git-fetch 문서](https://git-scm.com/docs/git-fetch)
- [18] [Pull request 스캔하기 (betterleaks)](https://github.com/betterleaks/betterleaks/blob/main/docs/scanning.md)
- [19] [Gists용 REST API 엔드포인트 (GitHub Docs)](https://docs.github.com/en/rest/gists/gists)
{{#include ../../banners/hacktricks-training.md}}
