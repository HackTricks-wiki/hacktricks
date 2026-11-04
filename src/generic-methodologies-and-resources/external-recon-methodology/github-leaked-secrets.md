# Github Dorks & Leaks

{{#include ../../banners/hacktricks-training.md}}

### Інструменти для пошуку секретів у git-репозиторіях і файловій системі

- [TruffleHog](https://github.com/dxa4481/truffleHog)
- [Gitleaks](https://github.com/gitleaks/gitleaks)
- [Nosey Parker](https://github.com/praetorian-inc/noseyparker) (архівовано; замінено на [Titus](https://github.com/praetorian-inc/titus))
- [ggshield](https://github.com/GitGuardian/ggshield)
- [RExpository](https://github.com/JaimePolop/RExpository)
- [detect-secrets](https://github.com/Yelp/detect-secrets)
- [gitGraber](https://github.com/hisxo/gitGraber)
- [shhgit](https://github.com/eth0izzle/shhgit) (не підтримується)
- [github-dorks](https://github.com/techgaun/github-dorks)
- [gitrob](https://github.com/michenriksen/gitrob) (архівовано)
- [git-all-secrets](https://github.com/anshumanbh/git-all-secrets) (архівовано)
- [git-secrets](https://github.com/awslabs/git-secrets)
- [gittyleaks](https://github.com/kootenpv/gittyleaks)
- [GitDorker](https://github.com/obheda12/GitDorker)

> Примітки
> - TruffleHog v3 може перевіряти багато облікових даних у реальному часі та сканувати організації GitHub, issues/PRs, gists і wikis. Приклад: `trufflehog github --org <ORG> --results=verified`.<sup>[[2]](#references)[[13]](#references)</sup>
> - Gitleaks сканує Git-репозиторії, каталоги й архіви. Для історії використовуйте `gitleaks git -v --log-opts="--all" <repo>`, для каталогів — `gitleaks dir -v <path>`, а для перевірки архівів — `--max-archive-depth 1`.<sup>[[6]](#references)</sup>
> - Nosey Parker архівовано й замінено на Titus. Наявні інсталяції й надалі підтримують `noseyparker scan --datastore np.db <path|repo>`, а потім `noseyparker report --datastore np.db`.<sup>[[7]](#references)[[8]](#references)</sup>
> - ggshield (GitGuardian CLI) сканує файли, репозиторії та Docker-образи й інтегрується з локальними процесами або CI: `ggshield secret scan repo <path-or-url>`.<sup>[[9]](#references)</sup>

### Де секрети найчастіше leak у GitHub

- GitHub Code Search індексує лише гілку за замовчуванням; перевіряйте інші гілки безпосередньо або клонуйте їх.<sup>[[4]](#references)</sup>
- Повна історія git та інші гілки/теги (клонуйте й скануйте за допомогою gitleaks/trufflehog; пошук GitHub охоплює лише проіндексований вміст).<sup>[[4]](#references)[[6]](#references)</sup>
- Issues, pull requests, коментарі й описи (GitHub source у TruffleHog підтримує їх за допомогою таких прапорців, як `--issue-comments` і `--pr-comments`).<sup>[[2]](#references)</sup>
- Журнали workflow і артефакти Actions (за наявності доступу на читання їх можна переглядати або завантажувати, а редагування секретів не гарантоване).<sup>[[11]](#references)[[12]](#references)</sup>
- Wikis і ресурси релізів.
- Gists (шукайте за допомогою інструментів або через UI; деякі інструменти підтримують gists).<sup>[[2]](#references)[[13]](#references)</sup>

> Підводні камені
> - UI GitHub Code Search підтримує regex, тоді як шлях REST/API (зокрема `gh search code`) використовує застарілий рушій і не надає можливостей regex. Для regex-запитів надавайте перевагу UI.<sup>[[3]](#references)[[5]](#references)</sup>
> - Пошук GitHub виключає файли, що перевищують задокументований ліміт розміру, і не охоплює все. Щоб перевірити ретельніше, клонуйте репозиторій і скануйте його локально за допомогою сканера секретів.<sup>[[4]](#references)</sup>

### Програмне сканування всієї організації

- TruffleHog (GitHub source).<sup>[[2]](#references)[[13]](#references)</sup>
```bash
export GITHUB_TOKEN=<token>
trufflehog github --org Target --results=verified \
  --include-wikis --issue-comments --pr-comments --gist-comments
```
- Gitleaks для всіх репозиторіїв організації (клонуйте з малою глибиною історії та скануйте за допомогою `gitleaks dir`).<sup>[[6]](#references)</sup>
```bash
gh repo list Target --limit 1000 --json nameWithOwner,url \
| jq -r '.[].url' | while read -r r; do
  tmp=$(mktemp -d); git clone --depth 1 "$r" "$tmp" && \
  gitleaks dir -v "$tmp" || true; rm -rf "$tmp";
done
```
- Nosey Parker для mono checkout (для наявних інсталяцій).<sup>[[7]](#references)</sup>
```bash
# after cloning many repos beneath ./org
noseyparker scan --datastore np.db org/ && noseyparker report --datastore np.db
```
- швидке сканування ggshield.<sup>[[9]](#references)</sup>
```bash
# current working tree
ggshield secret scan path -r .
# full git history of a repo
ggshield secret scan repo <path-or-url>
```

> Порада: Для історії git віддавайте перевагу сканерам, які аналізують `git log -p --all`, щоб виявляти видалені секрети.<sup>[[6]](#references)</sup>

### Посилання pull request і історія ревізій Gist

Звичайні клони не отримують refs GitHub `refs/pull/<number>/head`, тому `git log --all` не враховує коміти, доступні лише через ці refs, доки ви їх не отримаєте.<sup>[[14]](#references)[[17]](#references)</sup> PR refs можуть відкривати доступ до незлитих комітів, навіть після того, як учасник видалить свій fork.<sup>[[15]](#references)</sup> Сама лише зміна історії гілки може залишити конфіденційні коміти доступними через PR refs.<sup>[[16]](#references)</sup>

У повному клоні перед скануванням отримайте вибраний PR head або використайте wildcard refspec для всіх оголошених PR heads, якщо додаткове завантаження виправдане.<sup>[[17]](#references)[[18]](#references)</sup> Gitleaks сканує локальні патчі комітів за допомогою `git log -p`, тож запустіть його повторно після отримання refs.<sup>[[6]](#references)</sup>

```bash
git fetch origin 'refs/pull/123/head:refs/remotes/origin/pr/123'
# Or fetch every advertised PR head:
git fetch origin '+refs/pull/*/head:refs/remotes/origin/pr/*'
gitleaks git -v --log-opts="--all" .
```

У Gist також є історія Git, тому перевірка лише його поточних файлів може не виявити облікові дані, видалені в пізнішій версії.<sup>[[19]](#references)</sup> Для публічного Gist у межах scope клонуйте його Git-репозиторій і перевірте всі версії.<sup>[[19]](#references)[[6]](#references)</sup>

```bash
git clone https://gist.github.com/GIST_ID.git
gitleaks git -v --log-opts="--all" GIST_ID
```

### Оновлені dorks для сучасних токенів

- Токени GitHub: `ghp_` `gho_` `ghu_` `ghs_` `ghr_` `github_pat_`.<sup>[[10]](#references)</sup>
- Токени Slack: `xoxb-` `xoxp-` `xoxa-` `xoxs-` `xoxc-` `xoxe-`
- Хмарні та загальні:
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

Для інших сценаріїв пошуку коду див. [Wide Source Code Search](wide-source-code-search.md).



## References

- [1] [Як не допустити потрапляння секретів до публічних репозиторіїв (GitHub Blog, 29 лютого 2024)](https://github.blog/news-insights/product-news/keeping-secrets-out-of-public-repositories/)
- [2] [TruffleHog v3 – Знайти, перевірити й проаналізувати leaked credentials](https://github.com/trufflesecurity/trufflehog)
- [3] [Розуміння синтаксису GitHub Code Search](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [4] [Пошук коду (застаріла версія)](https://docs.github.com/en/search-github/searching-on-github/searching-code)
- [5] [gh search code](https://cli.github.com/manual/gh_search_code)
- [6] [README Gitleaks](https://github.com/gitleaks/gitleaks/blob/master/README.md)
- [7] [README Nosey Parker](https://github.com/praetorian-inc/noseyparker#readme)
- [8] [README Titus](https://github.com/praetorian-inc/titus#readme)
- [9] [README ggshield](https://github.com/GitGuardian/ggshield#readme)
- [10] [Довідник секретів (GitHub Actions)](https://docs.github.com/en/actions/reference/security/secrets)
- [11] [Секрети (GitHub Actions)](https://docs.github.com/en/actions/concepts/security/secrets)
- [12] [Використання журналів запусків workflow (GitHub Actions)](https://docs.github.com/en/actions/how-tos/monitor-workflows/use-workflow-run-logs)
- [13] [Вихідний код TruffleHog на GitHub](https://github.com/trufflesecurity/trufflehog/blob/main/main.go)
- [14] [Посилання на pull request і гілки злиття (GitHub Docs)](https://docs.github.com/en/pull-requests/reference/pull-requests)
- [15] [Локальне отримання pull request (GitHub Docs)](https://docs.github.com/en/pull-requests/how-tos/review-pull-requests/checking-out-pull-requests-locally)
- [16] [Видалення конфіденційних даних із репозиторію (GitHub Docs)](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
- [17] [Документація git-fetch](https://git-scm.com/docs/git-fetch)
- [18] [Сканування pull request (betterleaks)](https://github.com/betterleaks/betterleaks/blob/main/docs/scanning.md)
- [19] [Кінцеві точки REST API для Gists (GitHub Docs)](https://docs.github.com/en/rest/gists/gists)
{{#include ../../banners/hacktricks-training.md}}
