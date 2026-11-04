# GitHub Dorks & Leaks

{{#include ../../banners/hacktricks-training.md}}

### Outils pour trouver des secrets dans les dépôts Git et le système de fichiers

- [TruffleHog](https://github.com/dxa4481/truffleHog)
- [Gitleaks](https://github.com/gitleaks/gitleaks)
- [Nosey Parker](https://github.com/praetorian-inc/noseyparker) (archivé ; remplacé par [Titus](https://github.com/praetorian-inc/titus))
- [ggshield](https://github.com/GitGuardian/ggshield)
- [RExpository](https://github.com/JaimePolop/RExpository)
- [detect-secrets](https://github.com/Yelp/detect-secrets)
- [gitGraber](https://github.com/hisxo/gitGraber)
- [shhgit](https://github.com/eth0izzle/shhgit) (non maintenu)
- [github-dorks](https://github.com/techgaun/github-dorks)
- [gitrob](https://github.com/michenriksen/gitrob) (archivé)
- [git-all-secrets](https://github.com/anshumanbh/git-all-secrets) (archivé)
- [git-secrets](https://github.com/awslabs/git-secrets)
- [gittyleaks](https://github.com/kootenpv/gittyleaks)
- [GitDorker](https://github.com/obheda12/GitDorker)

> Remarques
> - TruffleHog v3 peut vérifier en direct de nombreux identifiants et analyser les organisations GitHub, les issues/PRs, les gists et les wikis. Exemple : `trufflehog github --org <ORG> --results=verified`.<sup>[[2]](#references)[[13]](#references)</sup>
> - Gitleaks analyse les dépôts Git, les répertoires et les archives. Utilisez `gitleaks git -v --log-opts="--all" <repo>` pour l’historique, `gitleaks dir -v <path>` pour les répertoires et `--max-archive-depth 1` pour examiner les archives.<sup>[[6]](#references)</sup>
> - Nosey Parker est archivé et remplacé par Titus. Les installations existantes prennent toujours en charge `noseyparker scan --datastore np.db <path|repo>`, puis `noseyparker report --datastore np.db`.<sup>[[7]](#references)[[8]](#references)</sup>
> - ggshield (CLI GitGuardian) analyse les fichiers, les dépôts et les images Docker, et s’intègre aux workflows locaux ou CI : `ggshield secret scan repo <path-or-url>`.<sup>[[9]](#references)</sup>

### Où les secrets sont couramment divulgués sur GitHub

- GitHub Code Search indexe uniquement la branche par défaut ; examinez directement les autres branches ou clonez-les.<sup>[[4]](#references)</sup>
- L’historique complet de Git et les autres branches/tags (clonez et analysez avec gitleaks/trufflehog ; la recherche GitHub ne couvre que le contenu indexé).<sup>[[4]](#references)[[6]](#references)</sup>
- Les issues, les pull requests, les commentaires et les descriptions (la source GitHub de TruffleHog les prend en charge avec des options telles que `--issue-comments` et `--pr-comments`).<sup>[[2]](#references)</sup>
- Les journaux et artefacts des workflows Actions (un accès en lecture permet de les consulter ou de les télécharger, et la rédaction des secrets n’est pas garantie).<sup>[[11]](#references)[[12]](#references)</sup>
- Les wikis et les ressources des releases.
- Les gists (effectuez des recherches avec des outils ou l’interface ; certains outils peuvent inclure les gists).<sup>[[2]](#references)[[13]](#references)</sup>

> Points à noter
> - L’interface GitHub Code Search prend en charge les regex, tandis que la voie REST/API (y compris `gh search code`) utilise l’ancien moteur et ne propose pas de fonctionnalités regex. Privilégiez l’interface pour les requêtes regex.<sup>[[3]](#references)[[5]](#references)</sup>
> - La recherche GitHub exclut les fichiers dépassant la limite de taille documentée et n’est pas exhaustive. Pour être complet, clonez et analysez les dépôts localement avec un scanner de secrets.<sup>[[4]](#references)</sup>

### Analyse programmatique à l’échelle de l’organisation

- TruffleHog (source GitHub).<sup>[[2]](#references)[[13]](#references)</sup>
```bash
export GITHUB_TOKEN=<token>
trufflehog github --org Target --results=verified \
  --include-wikis --issue-comments --pr-comments --gist-comments
```
- Gitleaks sur tous les dépôts de l'organisation (clone superficiel et scan avec `gitleaks dir`).<sup>[[6]](#references)</sup>
```bash
gh repo list Target --limit 1000 --json nameWithOwner,url \
| jq -r '.[].url' | while read -r r; do
  tmp=$(mktemp -d); git clone --depth 1 "$r" "$tmp" && \
  gitleaks dir -v "$tmp" || true; rm -rf "$tmp";
done
```
- Nosey Parker sur un checkout mono (pour les installations existantes).<sup>[[7]](#references)</sup>
```bash
# after cloning many repos beneath ./org
noseyparker scan --datastore np.db org/ && noseyparker report --datastore np.db
```
- analyses rapides de ggshield.<sup>[[9]](#references)</sup>
```bash
# current working tree
ggshield secret scan path -r .
# full git history of a repo
ggshield secret scan repo <path-or-url>
```

> Conseil : pour l’historique Git, privilégiez les scanners qui analysent `git log -p --all` afin de détecter les secrets supprimés.<sup>[[6]](#references)</sup>

### Références des pull requests et historique des révisions de Gist

Les clones classiques ne récupèrent pas les références `refs/pull/<number>/head` de GitHub. Par conséquent, `git log --all` ignore les commits accessibles uniquement via ces références tant que vous ne les avez pas récupérées.<sup>[[14]](#references)[[17]](#references)</sup> Les références de PR peuvent exposer des commits non fusionnés, même après la suppression de son fork par un contributeur.<sup>[[15]](#references)</sup> La réécriture de l’historique d’une branche à elle seule peut laisser des commits sensibles accessibles via les références de PR.<sup>[[16]](#references)</sup>

Dans un clone complet, récupérez la tête d’une PR sélectionnée avant l’analyse, ou utilisez le refspec générique pour récupérer toutes les têtes de PR annoncées lorsque le téléchargement supplémentaire est justifié.<sup>[[17]](#references)[[18]](#references)</sup> Gitleaks analyse les patches des commits locaux avec `git log -p` : relancez-le donc après avoir récupéré les références.<sup>[[6]](#references)</sup>

```bash
git fetch origin 'refs/pull/123/head:refs/remotes/origin/pr/123'
# Or fetch every advertised PR head:
git fetch origin '+refs/pull/*/head:refs/remotes/origin/pr/*'
gitleaks git -v --log-opts="--all" .
```

Un Gist possède aussi un historique Git : examiner uniquement ses fichiers actuels peut donc faire manquer un identifiant supprimé dans une révision ultérieure.<sup>[[19]](#references)</sup> Pour un Gist public dans le périmètre, clonez son dépôt Git et analysez les révisions.<sup>[[19]](#references)[[6]](#references)</sup>

```bash
git clone https://gist.github.com/GIST_ID.git
gitleaks git -v --log-opts="--all" GIST_ID
```

### Dorks mis à jour pour les tokens modernes

- Tokens GitHub : `ghp_` `gho_` `ghu_` `ghs_` `ghr_` `github_pat_`.<sup>[[10]](#references)</sup>
- Tokens Slack : `xoxb-` `xoxp-` `xoxa-` `xoxs-` `xoxc-` `xoxe-`
- Cloud et général :
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

Pour d’autres workflows de recherche de code, consultez [Wide Source Code Search](wide-source-code-search.md).



## References

- [1] [Garder les secrets hors des dépôts publics (GitHub Blog, Feb 29, 2024)](https://github.blog/news-insights/product-news/keeping-secrets-out-of-public-repositories/)
- [2] [TruffleHog v3 – Trouver, vérifier et analyser les credentials leaked](https://github.com/trufflesecurity/trufflehog)
- [3] [Comprendre la syntaxe de GitHub Code Search](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [4] [Rechercher du code (ancienne version)](https://docs.github.com/en/search-github/searching-on-github/searching-code)
- [5] [gh search code](https://cli.github.com/manual/gh_search_code)
- [6] [README de Gitleaks](https://github.com/gitleaks/gitleaks/blob/master/README.md)
- [7] [README de Nosey Parker](https://github.com/praetorian-inc/noseyparker#readme)
- [8] [README de Titus](https://github.com/praetorian-inc/titus#readme)
- [9] [README de ggshield](https://github.com/GitGuardian/ggshield#readme)
- [10] [Référence des secrets (GitHub Actions)](https://docs.github.com/en/actions/reference/security/secrets)
- [11] [Secrets (GitHub Actions)](https://docs.github.com/en/actions/concepts/security/secrets)
- [12] [Utiliser les journaux d’exécution des workflows (GitHub Actions)](https://docs.github.com/en/actions/how-tos/monitor-workflows/use-workflow-run-logs)
- [13] [Code source GitHub de TruffleHog](https://github.com/trufflesecurity/trufflehog/blob/main/main.go)
- [14] [Références de pull request et branches de merge (GitHub Docs)](https://docs.github.com/en/pull-requests/reference/pull-requests)
- [15] [Extraire des pull requests localement (GitHub Docs)](https://docs.github.com/en/pull-requests/how-tos/review-pull-requests/checking-out-pull-requests-locally)
- [16] [Supprimer des données sensibles d’un dépôt (GitHub Docs)](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
- [17] [Documentation de git-fetch](https://git-scm.com/docs/git-fetch)
- [18] [Analyser une pull request (betterleaks)](https://github.com/betterleaks/betterleaks/blob/main/docs/scanning.md)
- [19] [Points de terminaison de l’API REST pour les Gists (GitHub Docs)](https://docs.github.com/en/rest/gists/gists)
{{#include ../../banners/hacktricks-training.md}}
