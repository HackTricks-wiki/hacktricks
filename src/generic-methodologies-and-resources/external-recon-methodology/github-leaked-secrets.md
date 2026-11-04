# Github Dorks & Leaks

{{#include ../../banners/hacktricks-training.md}}

### Tools zum Finden von Secrets in Git-Repos und Dateisystemen

- [TruffleHog](https://github.com/dxa4481/truffleHog)
- [Gitleaks](https://github.com/gitleaks/gitleaks)
- [Nosey Parker](https://github.com/praetorian-inc/noseyparker) (archiviert; ersetzt durch [Titus](https://github.com/praetorian-inc/titus))
- [ggshield](https://github.com/GitGuardian/ggshield)
- [RExpository](https://github.com/JaimePolop/RExpository)
- [detect-secrets](https://github.com/Yelp/detect-secrets)
- [gitGraber](https://github.com/hisxo/gitGraber)
- [shhgit](https://github.com/eth0izzle/shhgit) (nicht mehr gewartet)
- [github-dorks](https://github.com/techgaun/github-dorks)
- [gitrob](https://github.com/michenriksen/gitrob) (archiviert)
- [git-all-secrets](https://github.com/anshumanbh/git-all-secrets) (archiviert)
- [git-secrets](https://github.com/awslabs/git-secrets)
- [gittyleaks](https://github.com/kootenpv/gittyleaks)
- [GitDorker](https://github.com/obheda12/GitDorker)

> Hinweise
> - TruffleHog v3 kann viele Zugangsdaten live überprüfen und GitHub-Organisationen, Issues/PRs, Gists und Wikis scannen. Beispiel: `trufflehog github --org <ORG> --results=verified`.<sup>[[2]](#references)[[13]](#references)</sup>
> - Gitleaks scannt Git-Repositories, Verzeichnisse und Archive. Verwende `gitleaks git -v --log-opts="--all" <repo>` für den Verlauf, `gitleaks dir -v <path>` für Verzeichnisse und `--max-archive-depth 1`, um Archive zu untersuchen.<sup>[[6]](#references)</sup>
> - Nosey Parker ist archiviert und wurde durch Titus ersetzt. Bestehende Installationen unterstützen weiterhin `noseyparker scan --datastore np.db <path|repo>`, gefolgt von `noseyparker report --datastore np.db`.<sup>[[7]](#references)[[8]](#references)</sup>
> - ggshield (GitGuardian CLI) scannt Dateien, Repositories und Docker-Images und lässt sich in lokale oder CI-Workflows integrieren: `ggshield secret scan repo <path-or-url>`.<sup>[[9]](#references)</sup>

### Wo Secrets auf GitHub häufig leaken

- GitHub Code Search indexiert nur den Standard-Branch; untersuche andere Branches direkt oder klone sie.<sup>[[4]](#references)</sup>
- Der vollständige Git-Verlauf und andere Branches/Tags (klonen und mit gitleaks/trufflehog scannen; die GitHub-Suche erfasst nur indexierte Inhalte).<sup>[[4]](#references)[[6]](#references)</sup>
- Issues, Pull Requests, Kommentare und Beschreibungen (TruffleHogs GitHub-Quelle unterstützt diese über Flags wie `--issue-comments` und `--pr-comments`).<sup>[[2]](#references)</sup>
- Actions-Workflow-Logs und Artefakte (mit Leseberechtigung können sie angezeigt oder heruntergeladen werden; eine Schwärzung von Secrets ist nicht garantiert).<sup>[[11]](#references)[[12]](#references)</sup>
- Wikis und Release-Assets.
- Gists (mit Tools oder über die Benutzeroberfläche suchen; manche Tools können Gists einbeziehen).<sup>[[2]](#references)[[13]](#references)</sup>

> Stolperfallen
> - Die GitHub-Code-Search-Oberfläche unterstützt Regex, während der REST/API-Pfad (einschließlich `gh search code`) die Legacy-Engine verwendet und keine Regex-Funktionen bereitstellt. Verwende für Regex-Abfragen vorzugsweise die Benutzeroberfläche.<sup>[[3]](#references)[[5]](#references)</sup>
> - Die GitHub-Suche schließt Dateien aus, die über dem dokumentierten Größenlimit liegen, und ist nicht vollständig. Klone und scanne daher lokal mit einem Secrets-Scanner, um gründlich vorzugehen.<sup>[[4]](#references)</sup>

### Programmatisches organisationsweites Scannen

- TruffleHog (GitHub-Quelle).<sup>[[2]](#references)[[13]](#references)</sup>
```bash
export GITHUB_TOKEN=<token>
trufflehog github --org Target --results=verified \
  --include-wikis --issue-comments --pr-comments --gist-comments
```
- Gitleaks über alle Org-Repos hinweg (flach klonen und mit gitleaks dir scannen).<sup>[[6]](#references)</sup>
```bash
gh repo list Target --limit 1000 --json nameWithOwner,url \
| jq -r '.[].url' | while read -r r; do
  tmp=$(mktemp -d); git clone --depth 1 "$r" "$tmp" && \
  gitleaks dir -v "$tmp" || true; rm -rf "$tmp";
done
```
- Nosey Parker über einen Mono-Checkout (für bestehende Installationen).<sup>[[7]](#references)</sup>
```bash
# after cloning many repos beneath ./org
noseyparker scan --datastore np.db org/ && noseyparker report --datastore np.db
```
- ggshield-Schnellscans.<sup>[[9]](#references)</sup>
```bash
# current working tree
ggshield secret scan path -r .
# full git history of a repo
ggshield secret scan repo <path-or-url>
```

> Tipp: Für die Git-Historie sollten Scanner bevorzugt werden, die `git log -p --all` parsen, um entfernte Secrets zu finden.<sup>[[6]](#references)</sup>

### Pull-request-Refs und Gist-Revisionshistorie

Normale Klone rufen GitHubs `refs/pull/<number>/head`-Refs nicht ab, daher entgehen `git log --all` Commits, die nur über diese Refs erreichbar sind, bis sie abgerufen werden.<sup>[[14]](#references)[[17]](#references)</sup> PR-Refs können nicht gemergte Commits offenlegen, selbst nachdem ein Contributor seinen Fork gelöscht hat.<sup>[[15]](#references)</sup> Das alleinige Umschreiben der Branch-Historie kann dazu führen, dass sensible Commits weiterhin über PR-Referenzen erreichbar sind.<sup>[[16]](#references)</sup>

Rufe in einem vollständigen Klon vor dem Scannen einen ausgewählten PR-Head ab, oder verwende die Wildcard-Refspec für alle angekündigten PR-Heads, wenn der zusätzliche Download gerechtfertigt ist.<sup>[[17]](#references)[[18]](#references)</sup> Gitleaks scannt lokale Commit-Patches mit `git log -p`; führe es daher nach dem Abrufen der Refs erneut aus.<sup>[[6]](#references)</sup>

```bash
git fetch origin 'refs/pull/123/head:refs/remotes/origin/pr/123'
# Or fetch every advertised PR head:
git fetch origin '+refs/pull/*/head:refs/remotes/origin/pr/*'
gitleaks git -v --log-opts="--all" .
```

Ein Gist hat auch einen Git-Verlauf. Wenn du nur die aktuellen Dateien prüfst, kann dir ein Zugangsschlüssel entgehen, der in einer späteren Revision entfernt wurde.<sup>[[19]](#references)</sup> Klone bei einem im Scope enthaltenen öffentlichen Gist dessen Git-Repository und durchsuche die Revisionen.<sup>[[19]](#references)[[6]](#references)</sup>

```bash
git clone https://gist.github.com/GIST_ID.git
gitleaks git -v --log-opts="--all" GIST_ID
```

### Aktualisierte Dorks für moderne Tokens

- GitHub-Tokens: `ghp_` `gho_` `ghu_` `ghs_` `ghr_` `github_pat_`.<sup>[[10]](#references)</sup>
- Slack-Tokens: `xoxb-` `xoxp-` `xoxa-` `xoxs-` `xoxc-` `xoxe-`
- Cloud und allgemein:
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

Für zusätzliche Code-Such-Workflows siehe [Wide Source Code Search](wide-source-code-search.md).



## References

- [1] [Geheimnisse aus öffentlichen Repositories heraushalten (GitHub Blog, Feb 29, 2024)](https://github.blog/news-insights/product-news/keeping-secrets-out-of-public-repositories/)
- [2] [TruffleHog v3 – Find, verify, and analyze leaked credentials](https://github.com/trufflesecurity/trufflehog)
- [3] [Die Syntax der GitHub Code Search verstehen](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [4] [Code durchsuchen (veraltet)](https://docs.github.com/en/search-github/searching-on-github/searching-code)
- [5] [gh search code](https://cli.github.com/manual/gh_search_code)
- [6] [Gitleaks README](https://github.com/gitleaks/gitleaks/blob/master/README.md)
- [7] [Nosey Parker README](https://github.com/praetorian-inc/noseyparker#readme)
- [8] [Titus README](https://github.com/praetorian-inc/titus#readme)
- [9] [ggshield README](https://github.com/GitGuardian/ggshield#readme)
- [10] [Secrets-Referenz (GitHub Actions)](https://docs.github.com/en/actions/reference/security/secrets)
- [11] [Secrets (GitHub Actions)](https://docs.github.com/en/actions/concepts/security/secrets)
- [12] [Workflow-Ausführungsprotokolle verwenden (GitHub Actions)](https://docs.github.com/en/actions/how-tos/monitor-workflows/use-workflow-run-logs)
- [13] [TruffleHog-GitHub-Quellcode](https://github.com/trufflesecurity/trufflehog/blob/main/main.go)
- [14] [Pull-Request-Refs und Merge-Branches (GitHub Docs)](https://docs.github.com/en/pull-requests/reference/pull-requests)
- [15] [Pull Requests lokal auschecken (GitHub Docs)](https://docs.github.com/en/pull-requests/how-tos/review-pull-requests/checking-out-pull-requests-locally)
- [16] [Sensible Daten aus einem Repository entfernen (GitHub Docs)](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
- [17] [git-fetch-Dokumentation](https://git-scm.com/docs/git-fetch)
- [18] [Einen Pull Request scannen (betterleaks)](https://github.com/betterleaks/betterleaks/blob/main/docs/scanning.md)
- [19] [REST-API-Endpunkte für Gists (GitHub Docs)](https://docs.github.com/en/rest/gists/gists)
{{#include ../../banners/hacktricks-training.md}}
