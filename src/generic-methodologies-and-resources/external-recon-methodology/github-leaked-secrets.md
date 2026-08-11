# Github Dorks & Leaks

{{#include ../../banners/hacktricks-training.md}}

### Εργαλεία για την εύρεση secrets σε git repos και file system

- [TruffleHog](https://github.com/dxa4481/truffleHog)
- [Gitleaks](https://github.com/gitleaks/gitleaks)
- [Nosey Parker](https://github.com/praetorian-inc/noseyparker) (archived· αντικαταστάθηκε από το [Titus](https://github.com/praetorian-inc/titus))
- [ggshield](https://github.com/GitGuardian/ggshield)
- [RExpository](https://github.com/JaimePolop/RExpository)
- [detect-secrets](https://github.com/Yelp/detect-secrets)
- [gitGraber](https://github.com/hisxo/gitGraber)
- [shhgit](https://github.com/eth0izzle/shhgit) (μη συντηρούμενο)
- [github-dorks](https://github.com/techgaun/github-dorks)
- [gitrob](https://github.com/michenriksen/gitrob) (archived)
- [git-all-secrets](https://github.com/anshumanbh/git-all-secrets) (archived)
- [git-secrets](https://github.com/awslabs/git-secrets)
- [gittyleaks](https://github.com/kootenpv/gittyleaks)
- [GitDorker](https://github.com/obheda12/GitDorker)

> Σημειώσεις
> - Το TruffleHog v3 μπορεί να επαληθεύει live πολλά credentials και να σαρώνει GitHub orgs, issues/PRs, gists και wikis. Παράδειγμα: `trufflehog github --org <ORG> --results=verified`.<sup>[[2]](#references)[[13]](#references)</sup>
> - Το Gitleaks σαρώνει Git repositories, directories και archives. Χρησιμοποιήστε `gitleaks git -v --log-opts="--all" <repo>` για το history, `gitleaks dir -v <path>` για directories και `--max-archive-depth 1` για την επιθεώρηση archives.<sup>[[6]](#references)</sup>
> - Το Nosey Parker είναι archived και έχει αντικατασταθεί από το Titus. Οι υπάρχουσες εγκαταστάσεις εξακολουθούν να υποστηρίζουν `noseyparker scan --datastore np.db <path|repo>` και στη συνέχεια `noseyparker report --datastore np.db`.<sup>[[7]](#references)[[8]](#references)</sup>
> - Το ggshield (GitGuardian CLI) σαρώνει files, repositories και Docker images και ενσωματώνεται σε local ή CI workflows: `ggshield secret scan repo <path-or-url>`.<sup>[[9]](#references)</sup>

### Πού συνήθως κάνουν leak secrets στο GitHub

- Το GitHub Code Search κάνει index μόνο στο default branch· ελέγξτε απευθείας τα non-default branches ή κάντε clone.<sup>[[4]](#references)</sup>
- Το πλήρες git history και άλλα branches/tags (κάντε clone και scan με gitleaks/trufflehog· το GitHub search καλύπτει μόνο indexed content).<sup>[[4]](#references)[[6]](#references)</sup>
- Issues, pull requests, comments και descriptions (το GitHub source του TruffleHog υποστηρίζει αυτά τα στοιχεία μέσω flags όπως `--issue-comments` και `--pr-comments`).<sup>[[2]](#references)</sup>
- Actions workflow logs και artifacts (η read access επιτρέπει την προβολή ή λήψη τους και η απόκρυψη secrets δεν είναι εγγυημένη).<sup>[[11]](#references)[[12]](#references)</sup>
- Wikis και release assets.
- Gists (κάντε search με tooling ή από το UI· ορισμένα tools μπορούν να συμπεριλάβουν gists).<sup>[[2]](#references)[[13]](#references)</sup>

> Παγίδες
> - Το GitHub's Code Search UI υποστηρίζει regex, ενώ το REST/API path (συμπεριλαμβανομένου του `gh search code`) χρησιμοποιεί το legacy engine και δεν παρέχει regex features. Προτιμήστε το UI για regex queries.<sup>[[3]](#references)[[5]](#references)</sup>
> - Το GitHub search εξαιρεί files που υπερβαίνουν το τεκμηριωμένο size limit και δεν είναι εξαντλητικό. Για πληρέστερο έλεγχο, κάντε clone και scan τοπικά με secrets scanner.<sup>[[4]](#references)</sup>

### Programmatic org-wide scanning

- TruffleHog (GitHub source).<sup>[[2]](#references)[[13]](#references)</sup>
```bash
export GITHUB_TOKEN=<token>
trufflehog github --org Target --results=verified \
--include-wikis --issue-comments --pr-comments --gist-comments
```
- Gitleaks σε όλα τα repos του οργανισμού (κάντε shallow clone και σαρώστε με `gitleaks dir`).<sup>[[6]](#references)</sup>
```bash
gh repo list Target --limit 1000 --json nameWithOwner,url \
| jq -r '.[].url' | while read -r r; do
tmp=$(mktemp -d); git clone --depth 1 "$r" "$tmp" && \
gitleaks dir -v "$tmp" || true; rm -rf "$tmp";
done
```
- Nosey Parker σε ένα mono checkout (για υπάρχουσες εγκαταστάσεις).<sup>[[7]](#references)</sup>
```bash
# after cloning many repos beneath ./org
noseyparker scan --datastore np.db org/ && noseyparker report --datastore np.db
```
- Γρήγορες σαρώσεις του ggshield.<sup>[[9]](#references)</sup>
```bash
# current working tree
ggshield secret scan path -r .
# full git history of a repo
ggshield secret scan repo <path-or-url>
```
> Συμβουλή: Για το git history, προτιμήστε scanners που αναλύουν το `git log -p --all` για να εντοπίζουν secrets που έχουν αφαιρεθεί.<sup>[[6]](#references)</sup>

### Ενημερωμένα dorks για σύγχρονα tokens

- GitHub tokens: `ghp_` `gho_` `ghu_` `ghs_` `ghr_` `github_pat_`.<sup>[[10]](#references)</sup>
- Slack tokens: `xoxb-` `xoxp-` `xoxa-` `xoxs-` `xoxc-` `xoxe-`
- Cloud και γενικά:
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
Για πρόσθετες ροές εργασίας αναζήτησης κώδικα, δείτε το [Wide Source Code Search](wide-source-code-search.md).

## References

- [1] [Διατήρηση των secrets εκτός public repositories (GitHub Blog, 29 Φεβρουαρίου 2024)](https://github.blog/news-insights/product-news/keeping-secrets-out-of-public-repositories/)
- [2] [TruffleHog v3 – Εύρεση, επαλήθευση και ανάλυση leaked credentials](https://github.com/trufflesecurity/trufflehog)
- [3] [Κατανόηση της σύνταξης του GitHub Code Search](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [4] [Αναζήτηση κώδικα (παλαιού τύπου)](https://docs.github.com/en/search-github/searching-on-github/searching-code)
- [5] [gh search code](https://cli.github.com/manual/gh_search_code)
- [6] [Gitleaks README](https://github.com/gitleaks/gitleaks/blob/master/README.md)
- [7] [Nosey Parker README](https://github.com/praetorian-inc/noseyparker#readme)
- [8] [Titus README](https://github.com/praetorian-inc/titus#readme)
- [9] [ggshield README](https://github.com/GitGuardian/ggshield#readme)
- [10] [Αναφορά secrets (GitHub Actions)](https://docs.github.com/en/actions/reference/security/secrets)
- [11] [Secrets (GitHub Actions)](https://docs.github.com/en/actions/concepts/security/secrets)
- [12] [Χρήση logs εκτέλεσης workflow (GitHub Actions)](https://docs.github.com/en/actions/how-tos/monitor-workflows/use-workflow-run-logs)
- [13] [Πηγαίος κώδικας TruffleHog στο GitHub](https://github.com/trufflesecurity/trufflehog/blob/main/main.go)
{{#include ../../banners/hacktricks-training.md}}
