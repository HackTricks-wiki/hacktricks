# Github Dorks & Leaks

{{#include ../../banners/hacktricks-training.md}}

### Alati za pronalaženje tajni u git repozitorijumima i sistemu datoteka

- [TruffleHog](https://github.com/dxa4481/truffleHog)
- [Gitleaks](https://github.com/gitleaks/gitleaks)
- [Nosey Parker](https://github.com/praetorian-inc/noseyparker) (arhiviran; zamenio ga je [Titus](https://github.com/praetorian-inc/titus))
- [ggshield](https://github.com/GitGuardian/ggshield)
- [RExpository](https://github.com/JaimePolop/RExpository)
- [detect-secrets](https://github.com/Yelp/detect-secrets)
- [gitGraber](https://github.com/hisxo/gitGraber)
- [shhgit](https://github.com/eth0izzle/shhgit) (ne održava se)
- [github-dorks](https://github.com/techgaun/github-dorks)
- [gitrob](https://github.com/michenriksen/gitrob) (arhiviran)
- [git-all-secrets](https://github.com/anshumanbh/git-all-secrets) (arhiviran)
- [git-secrets](https://github.com/awslabs/git-secrets)
- [gittyleaks](https://github.com/kootenpv/gittyleaks)
- [GitDorker](https://github.com/obheda12/GitDorker)

> Napomene
> - TruffleHog v3 može da proveri veliki broj akreditiva uživo i da skenira GitHub organizacije, issues/PRs, gists i wikije. Primer: `trufflehog github --org <ORG> --results=verified`.<sup>[[2]](#references)[[13]](#references)</sup>
> - Gitleaks skenira Git repozitorijume, direktorijume i arhive. Koristite `gitleaks git -v --log-opts="--all" <repo>` za istoriju, `gitleaks dir -v <path>` za direktorijume i `--max-archive-depth 1` za pregled arhiva.<sup>[[6]](#references)</sup>
> - Nosey Parker je arhiviran, a zamenio ga je Titus. Postojeće instalacije i dalje podržavaju `noseyparker scan --datastore np.db <path|repo>`, a zatim `noseyparker report --datastore np.db`.<sup>[[7]](#references)[[8]](#references)</sup>
> - ggshield (GitGuardian CLI) skenira datoteke, repozitorijume i Docker slike i integriše se sa lokalnim ili CI tokovima rada: `ggshield secret scan repo <path-or-url>`.<sup>[[9]](#references)</sup>

### Gde tajne najčešće cure na GitHub-u

- GitHub Code Search indeksira samo podrazumevanu granu; ostale grane pregledajte direktno ili ih klonirajte.<sup>[[4]](#references)</sup>
- Celokupna git istorija i druge grane/oznake (klonirajte ih i skenirajte pomoću gitleaks/trufflehog; GitHub pretraga obuhvata samo indeksirani sadržaj).<sup>[[4]](#references)[[6]](#references)</sup>
- Issues, pull requests, komentari i opisi (TruffleHog-ov GitHub izvor podržava ove sadržaje pomoću opcija kao što su `--issue-comments` i `--pr-comments`).<sup>[[2]](#references)</sup>
- Dnevnici i artefakti Actions workflow-a (pristup za čitanje omogućava njihov pregled ili preuzimanje, a redigovanje tajni nije zagarantovano).<sup>[[11]](#references)[[12]](#references)</sup>
- Wikiji i sredstva izdanja.
- Gists (pretražujte pomoću alata ili kroz UI; neki alati mogu da obuhvate gists).<sup>[[2]](#references)[[13]](#references)</sup>

> Zamke
> - GitHub Code Search UI podržava regex, dok REST/API putanja (uključujući `gh search code`) koristi zastareli engine i ne nudi regex funkcije. Za regex upite prednost dajte UI-ju.<sup>[[3]](#references)[[5]](#references)</sup>
> - GitHub pretraga isključuje datoteke koje premašuju dokumentovano ograničenje veličine i nije sveobuhvatna. Za temeljnu proveru klonirajte repozitorijum i lokalno ga skenirajte pomoću alata za skeniranje tajni.<sup>[[4]](#references)</sup>

### Programatsko skeniranje cele organizacije

- TruffleHog (GitHub izvor).<sup>[[2]](#references)[[13]](#references)</sup>
```bash
export GITHUB_TOKEN=<token>
trufflehog github --org Target --results=verified \
  --include-wikis --issue-comments --pr-comments --gist-comments
```
- Gitleaks nad svim repozitorijumima organizacije (plitko ih klonirajte i skenirajte pomoću gitleaks dir).<sup>[[6]](#references)</sup>
```bash
gh repo list Target --limit 1000 --json nameWithOwner,url \
| jq -r '.[].url' | while read -r r; do
  tmp=$(mktemp -d); git clone --depth 1 "$r" "$tmp" && \
  gitleaks dir -v "$tmp" || true; rm -rf "$tmp";
done
```
- Nosey Parker nad mono checkout-om (za postojeće instalacije).<sup>[[7]](#references)</sup>
```bash
# after cloning many repos beneath ./org
noseyparker scan --datastore np.db org/ && noseyparker report --datastore np.db
```
- ggshield brza skeniranja.<sup>[[9]](#references)</sup>
```bash
# current working tree
ggshield secret scan path -r .
# full git history of a repo
ggshield secret scan repo <path-or-url>
```

> Savet: Za git istoriju, prednost dajte skenerima koji analiziraju `git log -p --all` kako bi otkrili uklonjene tajne.<sup>[[6]](#references)</sup>

### Pull-request refs i istorija revizija Gist-a

Uobičajeni klonovi ne preuzimaju GitHub-ove `refs/pull/<number>/head` refs, pa `git log --all` propušta commitove dostupne samo preko tih refs dok ih ne preuzmete.<sup>[[14]](#references)[[17]](#references)</sup> PR refs mogu da otkriju nemergovane commitove čak i nakon što saradnik obriše svoj fork.<sup>[[15]](#references)</sup> Samo ponovno pisanje istorije grane može ostaviti osetljive commitove dostupnim preko PR referenci.<sup>[[16]](#references)</sup>

U potpunom klonu, pre skeniranja preuzmite odabrani PR head ili koristite wildcard refspec za sve oglašene PR headove kada je dodatno preuzimanje opravdano.<sup>[[17]](#references)[[18]](#references)</sup> Gitleaks skenira lokalne commit zakrpe pomoću `git log -p`, pa ga ponovo pokrenite nakon preuzimanja refs.<sup>[[6]](#references)</sup>

```bash
git fetch origin 'refs/pull/123/head:refs/remotes/origin/pr/123'
# Or fetch every advertised PR head:
git fetch origin '+refs/pull/*/head:refs/remotes/origin/pr/*'
gitleaks git -v --log-opts="--all" .
```

Gist takođe ima Git istoriju, pa proveravanje samo njegovih trenutnih datoteka može propustiti credential uklonjen u kasnijoj reviziji.<sup>[[19]](#references)</sup> Za javni Gist koji je u opsegu, klonirajte njegov Git repozitorijum i skenirajte revizije.<sup>[[19]](#references)[[6]](#references)</sup>

```bash
git clone https://gist.github.com/GIST_ID.git
gitleaks git -v --log-opts="--all" GIST_ID
```

### Ažurirani dorkovi za moderne tokene

- GitHub tokeni: `ghp_` `gho_` `ghu_` `ghs_` `ghr_` `github_pat_`.<sup>[[10]](#references)</sup>
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

Za dodatne tokove rada za pretragu koda, pogledajte [Wide Source Code Search](wide-source-code-search.md).



## References

- [1] [Čuvanje tajni van javnih repozitorijuma (GitHub Blog, 29. februar 2024.)](https://github.blog/news-insights/product-news/keeping-secrets-out-of-public-repositories/)
- [2] [TruffleHog v3 – Pronalaženje, provera i analiza procurelih akreditiva](https://github.com/trufflesecurity/trufflehog)
- [3] [Razumevanje sintakse GitHub Code Search](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [4] [Pretraživanje koda (zastarelo)](https://docs.github.com/en/search-github/searching-on-github/searching-code)
- [5] [gh search code](https://cli.github.com/manual/gh_search_code)
- [6] [Gitleaks README](https://github.com/gitleaks/gitleaks/blob/master/README.md)
- [7] [Nosey Parker README](https://github.com/praetorian-inc/noseyparker#readme)
- [8] [Titus README](https://github.com/praetorian-inc/titus#readme)
- [9] [ggshield README](https://github.com/GitGuardian/ggshield#readme)
- [10] [Referenca za tajne (GitHub Actions)](https://docs.github.com/en/actions/reference/security/secrets)
- [11] [Tajne (GitHub Actions)](https://docs.github.com/en/actions/concepts/security/secrets)
- [12] [Korišćenje logova pokretanja workflow-a (GitHub Actions)](https://docs.github.com/en/actions/how-tos/monitor-workflows/use-workflow-run-logs)
- [13] [Izvorni kod TruffleHog-a na GitHub-u](https://github.com/trufflesecurity/trufflehog/blob/main/main.go)
- [14] [Pull request reference i merge grane (GitHub Docs)](https://docs.github.com/en/pull-requests/reference/pull-requests)
- [15] [Lokalno preuzimanje pull request-ova (GitHub Docs)](https://docs.github.com/en/pull-requests/how-tos/review-pull-requests/checking-out-pull-requests-locally)
- [16] [Uklanjanje osetljivih podataka iz repozitorijuma (GitHub Docs)](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
- [17] [Dokumentacija za git-fetch](https://git-scm.com/docs/git-fetch)
- [18] [Skeniranje pull request-a (betterleaks)](https://github.com/betterleaks/betterleaks/blob/main/docs/scanning.md)
- [19] [REST API endpoint-i za Gists (GitHub Docs)](https://docs.github.com/en/rest/gists/gists)
{{#include ../../banners/hacktricks-training.md}}
