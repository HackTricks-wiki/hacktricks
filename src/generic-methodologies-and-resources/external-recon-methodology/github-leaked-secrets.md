# Github Dorks & Leaks

{{#include ../../banners/hacktricks-training.md}}

### Zana za kutafuta secrets kwenye git repos na mfumo wa faili

- [TruffleHog](https://github.com/dxa4481/truffleHog)
- [Gitleaks](https://github.com/gitleaks/gitleaks)
- [Nosey Parker](https://github.com/praetorian-inc/noseyparker) (imehifadhiwa; nafasi yake imechukuliwa na [Titus](https://github.com/praetorian-inc/titus))
- [ggshield](https://github.com/GitGuardian/ggshield)
- [RExpository](https://github.com/JaimePolop/RExpository)
- [detect-secrets](https://github.com/Yelp/detect-secrets)
- [gitGraber](https://github.com/hisxo/gitGraber)
- [shhgit](https://github.com/eth0izzle/shhgit) (haitunzwani tena)
- [github-dorks](https://github.com/techgaun/github-dorks)
- [gitrob](https://github.com/michenriksen/gitrob) (imehifadhiwa)
- [git-all-secrets](https://github.com/anshumanbh/git-all-secrets) (imehifadhiwa)
- [git-secrets](https://github.com/awslabs/git-secrets)
- [gittyleaks](https://github.com/kootenpv/gittyleaks)
- [GitDorker](https://github.com/obheda12/GitDorker)

> Maelezo
> - TruffleHog v3 inaweza kuthibitisha credentials nyingi moja kwa moja na kuchanganua GitHub orgs, issues/PRs, gists, na wikis. Mfano: `trufflehog github --org <ORG> --results=verified`.<sup>[[2]](#references)[[13]](#references)</sup>
> - Gitleaks huchanganua Git repositories, directories, na archives. Tumia `gitleaks git -v --log-opts="--all" <repo>` kuchanganua historia, `gitleaks dir -v <path>` kuchanganua directories, na `--max-archive-depth 1` kukagua archives.<sup>[[6]](#references)</sup>
> - Nosey Parker imehifadhiwa na nafasi yake imechukuliwa na Titus. Usakinishaji uliopo bado unaunga mkono `noseyparker scan --datastore np.db <path|repo>` ikifuatiwa na `noseyparker report --datastore np.db`.<sup>[[7]](#references)[[8]](#references)</sup>
> - ggshield (GitGuardian CLI) huchanganua faili, repositories, na Docker images na huunganishwa na workflows za ndani au za CI: `ggshield secret scan repo <path-or-url>`.<sup>[[9]](#references)</sup>

### Sehemu ambazo secrets huvuja mara nyingi kwenye GitHub

- GitHub Code Search huorodhesha default branch pekee; kagua branches zisizo default moja kwa moja au uziclone.<sup>[[4]](#references)</sup>
- Historia kamili ya git na branches/tags nyingine (clone na uchanganue kwa gitleaks/trufflehog; utafutaji wa GitHub hushughulikia maudhui yaliyoorodheshwa pekee).<sup>[[4]](#references)[[6]](#references)</sup>
- Issues, pull requests, comments, na descriptions (GitHub source ya TruffleHog huunga mkono hivi kupitia flags kama `--issue-comments` na `--pr-comments`).<sup>[[2]](#references)</sup>
- Logs na artifacts za Actions workflow (ruhusa ya kusoma huruhusu kutazamwa au kupakuliwa, na uondoaji wa secrets haujahakikishwa).<sup>[[11]](#references)[[12]](#references)</sup>
- Wikis na release assets.
- Gists (tafuta kwa kutumia zana au UI; baadhi ya zana zinaweza kujumuisha gists).<sup>[[2]](#references)[[13]](#references)</sup>

> Mambo ya kuzingatia
> - UI ya GitHub Code Search inasaidia regex, ilhali njia ya REST/API (ikiwemo `gh search code`) hutumia engine ya zamani na haitoi vipengele vya regex. Kwa queries za regex, pendelea UI.<sup>[[3]](#references)[[5]](#references)</sup>
> - Utafutaji wa GitHub haujumuishi faili zilizo juu ya kikomo cha ukubwa kilichoandikwa na hauchunguzi kila kitu. Ili kufanya uchunguzi wa kina, clone na uchanganue locally kwa kutumia secrets scanner.<sup>[[4]](#references)</sup>

### Uchanganuzaji wa org nzima kwa kutumia programu

- TruffleHog (GitHub source).<sup>[[2]](#references)[[13]](#references)</sup>
```bash
export GITHUB_TOKEN=<token>
trufflehog github --org Target --results=verified \
  --include-wikis --issue-comments --pr-comments --gist-comments
```
- Tumia Gitleaks kwenye repos zote za org (clone shallow na uchanganue kwa gitleaks dir).<sup>[[6]](#references)</sup>
```bash
gh repo list Target --limit 1000 --json nameWithOwner,url \
| jq -r '.[].url' | while read -r r; do
  tmp=$(mktemp -d); git clone --depth 1 "$r" "$tmp" && \
  gitleaks dir -v "$tmp" || true; rm -rf "$tmp";
done
```
- Nosey Parker kupitia checkout ya mono (kwa usakinishaji uliopo).<sup>[[7]](#references)</sup>
```bash
# after cloning many repos beneath ./org
noseyparker scan --datastore np.db org/ && noseyparker report --datastore np.db
```
- uchanganuzi wa haraka wa ggshield.<sup>[[9]](#references)</sup>
```bash
# current working tree
ggshield secret scan path -r .
# full git history of a repo
ggshield secret scan repo <path-or-url>
```

> Kidokezo: Kwa historia ya git, pendelea scanners zinazochanganua `git log -p --all` ili kugundua secrets zilizoondolewa.<sup>[[6]](#references)</sup>

### Refs za pull-request na historia ya marekebisho ya Gist

Clones za kawaida hazichukui refs za GitHub za `refs/pull/<number>/head`, kwa hivyo `git log --all` hukosa commits zinazofikiwa kupitia refs hizo pekee hadi uzichukue.<sup>[[14]](#references)[[17]](#references)</sup> Refs za PR zinaweza kufichua commits ambazo hazijaunganishwa hata baada ya mchangiaji kufuta fork yake.<sup>[[15]](#references)</sup> Kubadilisha historia ya branch pekee kunaweza kuacha commits nyeti zikifikiwa kupitia marejeo ya PR.<sup>[[16]](#references)</sup>

Katika clone kamili, chukua head ya PR iliyochaguliwa kabla ya kuchanganua, au tumia refspec ya wildcard kwa heads zote za PR zilizotangazwa wakati upakuaji wa ziada unastahili.<sup>[[17]](#references)[[18]](#references)</sup> Gitleaks huchanganua patches za commits za ndani kwa kutumia `git log -p`, kwa hivyo iendeshe tena baada ya kuchukua refs.<sup>[[6]](#references)</sup>

```bash
git fetch origin 'refs/pull/123/head:refs/remotes/origin/pr/123'
# Or fetch every advertised PR head:
git fetch origin '+refs/pull/*/head:refs/remotes/origin/pr/*'
gitleaks git -v --log-opts="--all" .
```

Gist pia ina historia ya Git, kwa hivyo kukagua faili zake za sasa pekee kunaweza kukosa credential iliyoondolewa katika marekebisho ya baadaye.<sup>[[19]](#references)</sup> Kwa Gist ya umma iliyo ndani ya wigo, clone hazina yake ya Git na uchanganue marekebisho.<sup>[[19]](#references)[[6]](#references)</sup>

```bash
git clone https://gist.github.com/GIST_ID.git
gitleaks git -v --log-opts="--all" GIST_ID
```

### Dorks zilizosasishwa za tokeni za kisasa

- Tokeni za GitHub: `ghp_` `gho_` `ghu_` `ghs_` `ghr_` `github_pat_`.<sup>[[10]](#references)</sup>
- Tokeni za Slack: `xoxb-` `xoxp-` `xoxa-` `xoxs-` `xoxc-` `xoxe-`
- Wingu na za jumla:
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

Kwa workflows zaidi za kutafuta code, angalia [Utafutaji Mpana wa Msimbo Chanzo](wide-source-code-search.md).



## References

- [1] [Kuweka siri nje ya hazina za umma (Blogu ya GitHub, 29 Feb 2024)](https://github.blog/news-insights/product-news/keeping-secrets-out-of-public-repositories/)
- [2] [TruffleHog v3 – Kupata, kuthibitisha na kuchanganua credentials zilizovuja](https://github.com/trufflesecurity/trufflehog)
- [3] [Kuelewa sintaksia ya GitHub Code Search](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [4] [Kutafuta code (toleo la zamani)](https://docs.github.com/en/search-github/searching-on-github/searching-code)
- [5] [gh search code](https://cli.github.com/manual/gh_search_code)
- [6] [README ya Gitleaks](https://github.com/gitleaks/gitleaks/blob/master/README.md)
- [7] [README ya Nosey Parker](https://github.com/praetorian-inc/noseyparker#readme)
- [8] [README ya Titus](https://github.com/praetorian-inc/titus#readme)
- [9] [README ya ggshield](https://github.com/GitGuardian/ggshield#readme)
- [10] [Rejea ya secrets (GitHub Actions)](https://docs.github.com/en/actions/reference/security/secrets)
- [11] [Secrets (GitHub Actions)](https://docs.github.com/en/actions/concepts/security/secrets)
- [12] [Kutumia logi za uendeshaji wa workflow (GitHub Actions)](https://docs.github.com/en/actions/how-tos/monitor-workflows/use-workflow-run-logs)
- [13] [Chanzo cha TruffleHog GitHub](https://github.com/trufflesecurity/trufflehog/blob/main/main.go)
- [14] [Marejeo ya pull request na matawi ya merge (Nyaraka za GitHub)](https://docs.github.com/en/pull-requests/reference/pull-requests)
- [15] [Kukagua pull requests ndani ya kifaa (Nyaraka za GitHub)](https://docs.github.com/en/pull-requests/how-tos/review-pull-requests/checking-out-pull-requests-locally)
- [16] [Kuondoa data nyeti kutoka kwenye hazina (Nyaraka za GitHub)](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
- [17] [Nyaraka za git-fetch](https://git-scm.com/docs/git-fetch)
- [18] [Kuchanganua pull request (betterleaks)](https://github.com/betterleaks/betterleaks/blob/main/docs/scanning.md)
- [19] [REST API endpoints za Gists (Nyaraka za GitHub)](https://docs.github.com/en/rest/gists/gists)
{{#include ../../banners/hacktricks-training.md}}
