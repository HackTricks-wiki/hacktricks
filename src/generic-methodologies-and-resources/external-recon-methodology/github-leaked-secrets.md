# Github Dorks & Leaks

{{#include ../../banners/hacktricks-training.md}}

### Narzędzia do wyszukiwania sekretów w repozytoriach git i systemie plików

- [TruffleHog](https://github.com/dxa4481/truffleHog)
- [Gitleaks](https://github.com/gitleaks/gitleaks)
- [Nosey Parker](https://github.com/praetorian-inc/noseyparker) (zarchiwizowane; zastąpione przez [Titus](https://github.com/praetorian-inc/titus))
- [ggshield](https://github.com/GitGuardian/ggshield)
- [RExpository](https://github.com/JaimePolop/RExpository)
- [detect-secrets](https://github.com/Yelp/detect-secrets)
- [gitGraber](https://github.com/hisxo/gitGraber)
- [shhgit](https://github.com/eth0izzle/shhgit) (nieutrzymywane)
- [github-dorks](https://github.com/techgaun/github-dorks)
- [gitrob](https://github.com/michenriksen/gitrob) (zarchiwizowane)
- [git-all-secrets](https://github.com/anshumanbh/git-all-secrets) (zarchiwizowane)
- [git-secrets](https://github.com/awslabs/git-secrets)
- [gittyleaks](https://github.com/kootenpv/gittyleaks)
- [GitDorker](https://github.com/obheda12/GitDorker)

> Uwagi
> - TruffleHog v3 może weryfikować wiele poświadczeń na żywo oraz skanować organizacje, issues/PR-y, gists i wiki w GitHub. Przykład: `trufflehog github --org <ORG> --results=verified`.<sup>[[2]](#references)[[13]](#references)</sup>
> - Gitleaks skanuje repozytoria Git, katalogi i archiwa. Użyj `gitleaks git -v --log-opts="--all" <repo>` do skanowania historii, `gitleaks dir -v <path>` do skanowania katalogów oraz `--max-archive-depth 1` do sprawdzania archiwów.<sup>[[6]](#references)</sup>
> - Nosey Parker zostało zarchiwizowane i zastąpione przez Titus. Istniejące instalacje nadal obsługują polecenie `noseyparker scan --datastore np.db <path|repo>`, a następnie `noseyparker report --datastore np.db`.<sup>[[7]](#references)[[8]](#references)</sup>
> - ggshield (CLI GitGuardian) skanuje pliki, repozytoria i obrazy Docker oraz integruje się z lokalnymi przepływami pracy lub CI: `ggshield secret scan repo <path-or-url>`.<sup>[[9]](#references)</sup>

### Gdzie w GitHub często dochodzi do wycieków sekretów

- GitHub Code Search indeksuje tylko domyślną gałąź; pozostałe gałęzie sprawdzaj bezpośrednio lub sklonuj repozytorium.<sup>[[4]](#references)</sup>
- Pełna historia git oraz inne gałęzie/tagi (sklonuj repozytorium i skanuj je za pomocą gitleaks/trufflehog; wyszukiwanie w GitHub obejmuje tylko zaindeksowaną zawartość).<sup>[[4]](#references)[[6]](#references)</sup>
- Issues, pull requesty, komentarze i opisy (źródło GitHub w TruffleHog obsługuje je za pomocą flag, takich jak `--issue-comments` i `--pr-comments`).<sup>[[2]](#references)</sup>
- Logi i artefakty workflow Actions (dostęp do odczytu pozwala je wyświetlać lub pobierać, a maskowanie sekretów nie jest gwarantowane).<sup>[[11]](#references)[[12]](#references)</sup>
- Wiki i zasoby wydań.
- Gists (wyszukuj za pomocą narzędzi lub interfejsu użytkownika; niektóre narzędzia mogą uwzględniać gists).<sup>[[2]](#references)[[13]](#references)</sup>

> Pułapki
> - Interfejs GitHub Code Search obsługuje regex, natomiast ścieżka REST/API (w tym `gh search code`) korzysta ze starszego silnika i nie udostępnia funkcji regex. Do zapytań regex używaj interfejsu użytkownika.<sup>[[3]](#references)[[5]](#references)</sup>
> - Wyszukiwanie w GitHub pomija pliki przekraczające udokumentowany limit rozmiaru i nie jest wyczerpujące. Aby przeprowadzić dokładne skanowanie, sklonuj repozytorium i użyj lokalnie skanera sekretów.<sup>[[4]](#references)</sup>

### Programowe skanowanie całej organizacji

- TruffleHog (źródło GitHub).<sup>[[2]](#references)[[13]](#references)</sup>
```bash
export GITHUB_TOKEN=<token>
trufflehog github --org Target --results=verified \
  --include-wikis --issue-comments --pr-comments --gist-comments
```
- Gitleaks we wszystkich repozytoriach organizacji (wykonaj shallow clone i przeskanuj za pomocą `gitleaks dir`).<sup>[[6]](#references)</sup>
```bash
gh repo list Target --limit 1000 --json nameWithOwner,url \
| jq -r '.[].url' | while read -r r; do
  tmp=$(mktemp -d); git clone --depth 1 "$r" "$tmp" && \
  gitleaks dir -v "$tmp" || true; rm -rf "$tmp";
done
```
- Nosey Parker w ramach mono checkoutu (dla istniejących instalacji).<sup>[[7]](#references)</sup>
```bash
# after cloning many repos beneath ./org
noseyparker scan --datastore np.db org/ && noseyparker report --datastore np.db
```
- szybkie skanowanie ggshield.<sup>[[9]](#references)</sup>
```bash
# current working tree
ggshield secret scan path -r .
# full git history of a repo
ggshield secret scan repo <path-or-url>
```

> Wskazówka: Do historii Git preferuj skanery analizujące `git log -p --all`, aby wykrywać usunięte sekrety.<sup>[[6]](#references)</sup>

### Referencje pull requestów i historia rewizji Gist

Zwykłe klony nie pobierają referencji GitHub `refs/pull/<number>/head`, dlatego `git log --all` pomija commity dostępne wyłącznie przez te referencje, dopóki ich nie pobierzesz.<sup>[[14]](#references)[[17]](#references)</sup> Referencje PR mogą ujawniać niepołączone commity nawet po usunięciu forka przez autora.<sup>[[15]](#references)</sup> Samo przepisanie historii gałęzi może pozostawić wrażliwe commity dostępne przez referencje PR.<sup>[[16]](#references)</sup>

W pełnym klonie pobierz wybraną referencję PR przed skanowaniem albo użyj refspec z symbolem wieloznacznym, aby pobrać wszystkie ogłaszane referencje PR, jeśli uzasadnia to dodatkowy transfer.<sup>[[17]](#references)[[18]](#references)</sup> Gitleaks skanuje lokalne łatki commitów za pomocą `git log -p`, więc uruchom go ponownie po pobraniu referencji.<sup>[[6]](#references)</sup>

```bash
git fetch origin 'refs/pull/123/head:refs/remotes/origin/pr/123'
# Or fetch every advertised PR head:
git fetch origin '+refs/pull/*/head:refs/remotes/origin/pr/*'
gitleaks git -v --log-opts="--all" .
```

Gist ma również historię Git, więc sprawdzenie tylko jego obecnych plików może nie ujawnić danych uwierzytelniających usuniętych w późniejszej rewizji.<sup>[[19]](#references)</sup> W przypadku publicznego Gist objętego zakresem sklonuj jego repozytorium Git i przeskanuj rewizje.<sup>[[19]](#references)[[6]](#references)</sup>

```bash
git clone https://gist.github.com/GIST_ID.git
gitleaks git -v --log-opts="--all" GIST_ID
```

### Zaktualizowane dorki dla nowoczesnych tokenów

- Tokeny GitHub: `ghp_` `gho_` `ghu_` `ghs_` `ghr_` `github_pat_`.<sup>[[10]](#references)</sup>
- Tokeny Slack: `xoxb-` `xoxp-` `xoxa-` `xoxs-` `xoxc-` `xoxe-`
- Chmura i ogólne:
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

Więcej informacji o przepływach pracy związanych z wyszukiwaniem kodu znajdziesz w [Wide Source Code Search] (wide-source-code-search.md).



## References

- [1] [Trzymaj sekrety z dala od publicznych repozytoriów (GitHub Blog, 29 lutego 2024)](https://github.blog/news-insights/product-news/keeping-secrets-out-of-public-repositories/)
- [2] [TruffleHog v3 – wyszukuj, weryfikuj i analizuj ujawnione dane uwierzytelniające](https://github.com/trufflesecurity/trufflehog)
- [3] [Zrozumienie składni GitHub Code Search](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [4] [Wyszukiwanie kodu (starsza wersja)](https://docs.github.com/en/search-github/searching-on-github/searching-code)
- [5] [gh search code](https://cli.github.com/manual/gh_search_code)
- [6] [Plik README Gitleaks](https://github.com/gitleaks/gitleaks/blob/master/README.md)
- [7] [Plik README Nosey Parker](https://github.com/praetorian-inc/noseyparker#readme)
- [8] [Plik README Titus](https://github.com/praetorian-inc/titus#readme)
- [9] [Plik README ggshield](https://github.com/GitGuardian/ggshield#readme)
- [10] [Informacje o sekretach (GitHub Actions)](https://docs.github.com/en/actions/reference/security/secrets)
- [11] [Sekrety (GitHub Actions)](https://docs.github.com/en/actions/concepts/security/secrets)
- [12] [Korzystanie z dzienników przebiegu workflow (GitHub Actions)](https://docs.github.com/en/actions/how-tos/monitor-workflows/use-workflow-run-logs)
- [13] [Kod źródłowy TruffleHog w GitHub](https://github.com/trufflesecurity/trufflehog/blob/main/main.go)
- [14] [Referencje pull requestów i gałęzie merge (GitHub Docs)](https://docs.github.com/en/pull-requests/reference/pull-requests)
- [15] [Lokalne pobieranie pull requestów (GitHub Docs)](https://docs.github.com/en/pull-requests/how-tos/review-pull-requests/checking-out-pull-requests-locally)
- [16] [Usuwanie poufnych danych z repozytorium (GitHub Docs)](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
- [17] [Dokumentacja git-fetch](https://git-scm.com/docs/git-fetch)
- [18] [Skanowanie pull requesta (betterleaks)](https://github.com/betterleaks/betterleaks/blob/main/docs/scanning.md)
- [19] [Punkty końcowe REST API dla Gists (GitHub Docs)](https://docs.github.com/en/rest/gists/gists)
{{#include ../../banners/hacktricks-training.md}}
