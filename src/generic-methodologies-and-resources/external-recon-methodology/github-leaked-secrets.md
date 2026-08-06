# Github Dorks & Leaks

{{#include ../../banners/hacktricks-training.md}}


### Alati za pronalaženje tajni u git repozitorijumima i sistemu datoteka

- [https://github.com/dxa4481/truffleHog](https://github.com/dxa4481/truffleHog)
- [https://github.com/gitleaks/gitleaks](https://github.com/gitleaks/gitleaks)
- [https://github.com/praetorian-inc/noseyparker](https://github.com/praetorian-inc/noseyparker)
- [https://github.com/GitGuardian/ggshield](https://github.com/GitGuardian/ggshield)
- [https://github.com/JaimePolop/RExpository](https://github.com/JaimePolop/RExpository)
- [https://github.com/Yelp/detect-secrets](https://github.com/Yelp/detect-secrets)
- [https://github.com/hisxo/gitGraber](https://github.com/hisxo/gitGraber)
- https://github.com/eth0izzle/shhgit (ne održava se)
- [https://github.com/techgaun/github-dorks](https://github.com/techgaun/github-dorks)
- https://github.com/michenriksen/gitrob (arhiviran)
- https://github.com/anshumanbh/git-all-secrets (arhiviran)
- [https://github.com/awslabs/git-secrets](https://github.com/awslabs/git-secrets)
- [https://github.com/kootenpv/gittyleaks](https://github.com/kootenpv/gittyleaks)
- [https://github.com/obheda12/GitDorker](https://github.com/obheda12/GitDorker)

> Napomene
> - TruffleHog v3 može da proveri mnoge credential-e uživo i da skenira GitHub org-ove, issues/PR-ove, gists i wikije. Primer: `trufflehog github --org <ORG> --results=verified`.<sup>[[2]](#references)</sup>
> - Gitleaks v8 podržava skeniranje git istorije, direktorijuma i arhiva: `gitleaks detect -v --source .` ili `gitleaks detect --source <repo> --log-opts="--all"`.
> - Nosey Parker je usmeren na skeniranje velikom propusnošću, uz kurirana pravila, i ima Explorer UI za trijažu. Primer: `noseyparker scan --datastore np.db <path|repo>`, zatim `noseyparker report --datastore np.db`.
> - ggshield (GitGuardian CLI) obezbeđuje pre-commit/CI hooks i skeniranje Docker image-a: `ggshield secret scan repo <path-or-url>`.

### Gde tajne najčešće leak-uju na GitHub-u

- Datoteke repozitorijuma u podrazumevanim i nepodrazumevanim granama (u UI-ju pretražite `repo:owner/name@branch`).
- Kompletna git istorija i druge grane/tag-ovi (klonirajte i skenirajte pomoću gitleaks/trufflehog; GitHub pretraga se fokusira na indeksirani sadržaj).
- Issues, pull requests, komentari i opisi (TruffleHog GitHub source ih podržava pomoću flag-ova kao što su `--issue-comments`, `--pr-comments`).
- Actions logs i artifacts javnih repozitorijuma (masking je najbolji mogući pokušaj; pregledajte logs/artifacts ako su vidljivi).
- Wikiji i release assets.
- Gists (pretražite pomoću alata ili UI-ja; neki alati mogu da uključe gists).

> Zamke
> - GitHub-ov REST code search API je legacy i ne podržava regex; za regex pretrage koristite Web UI. gh CLI koristi legacy API.
> - Za pretragu se indeksiraju samo datoteke manje od određene veličine. Da biste bili temeljni, klonirajte repozitorijum i lokalno ga skenirajte pomoću scanner-a za tajne.

### Programatsko skeniranje cele organizacije

- TruffleHog (GitHub source):<sup>[[2]](#references)</sup>
```bash
export GITHUB_TOKEN=<token>
trufflehog github --org Target --results=verified \
--include-wikis --issue-comments --pr-comments --gist-comments
```
- Gitleaks nad svim repo-ovima organizacije (plitko klonirajte i skenirajte):
```bash
gh repo list Target --limit 1000 --json nameWithOwner,url \
| jq -r '.[].url' | while read -r r; do
tmp=$(mktemp -d); git clone --depth 1 "$r" "$tmp" && \
gitleaks detect --source "$tmp" -v || true; rm -rf "$tmp";
done
```
- Nosey Parker nad mono checkout-om:
```bash
# after cloning many repos beneath ./org
noseyparker scan --datastore np.db org/ && noseyparker report --datastore np.db
```
- ggshield brza skeniranja:
```bash
# current working tree
ggshield secret scan path -r .
# full git history of a repo
ggshield secret scan repo <path-or-url>
```
> Savet: Za git istoriju, prednost dajte scannerima koji analiziraju `git log -p --all` kako bi detektovali uklonjene secrets.

### Ažurirani Dorks za moderne tokene

- GitHub tokeni: `ghp_` `gho_` `ghu_` `ghs_` `ghr_` `github_pat_`
- Slack tokeni: `xoxb-` `xoxp-` `xoxa-` `xoxs-` `xoxc-` `xoxe-`
- Cloud i opšte:
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

## Reference

- [1] [Čuvanje tajni izvan javnih repozitorijuma (GitHub Blog, 29. februar 2024.)](https://github.blog/news-insights/product-news/keeping-secrets-out-of-public-repositories/)
- [2] [TruffleHog v3 – Pronalaženje, verifikacija i analiza procurelih akreditiva](https://github.com/trufflesecurity/trufflehog)

{{#include ../../banners/hacktricks-training.md}}
