# Github Dorks & Leaks

{{#include ../../banners/hacktricks-training.md}}

### git repos और file system में secrets खोजने के Tools

- [TruffleHog](https://github.com/dxa4481/truffleHog)
- [Gitleaks](https://github.com/gitleaks/gitleaks)
- [Nosey Parker](https://github.com/praetorian-inc/noseyparker) (archived; इसकी जगह [Titus](https://github.com/praetorian-inc/titus) ने ली है)
- [ggshield](https://github.com/GitGuardian/ggshield)
- [RExpository](https://github.com/JaimePolop/RExpository)
- [detect-secrets](https://github.com/Yelp/detect-secrets)
- [gitGraber](https://github.com/hisxo/gitGraber)
- [shhgit](https://github.com/eth0izzle/shhgit) (अब maintained नहीं है)
- [github-dorks](https://github.com/techgaun/github-dorks)
- [gitrob](https://github.com/michenriksen/gitrob) (archived)
- [git-all-secrets](https://github.com/anshumanbh/git-all-secrets) (archived)
- [git-secrets](https://github.com/awslabs/git-secrets)
- [gittyleaks](https://github.com/kootenpv/gittyleaks)
- [GitDorker](https://github.com/obheda12/GitDorker)

> नोट्स
> - TruffleHog v3 कई credentials को live verify कर सकता है और GitHub orgs, issues/PRs, gists और wikis को scan कर सकता है। उदाहरण: `trufflehog github --org <ORG> --results=verified`.<sup>[[2]](#references)[[13]](#references)</sup>
> - Gitleaks Git repositories, directories और archives को scan करता है। History के लिए `gitleaks git -v --log-opts="--all" <repo>`, directories के लिए `gitleaks dir -v <path>` और archives की जाँच के लिए `--max-archive-depth 1` इस्तेमाल करें।<sup>[[6]](#references)</sup>
> - Nosey Parker archived है और इसकी जगह Titus ने ली है। मौजूदा installations अब भी `noseyparker scan --datastore np.db <path|repo>` चलाने के बाद `noseyparker report --datastore np.db` का समर्थन करते हैं।<sup>[[7]](#references)[[8]](#references)</sup>
> - ggshield (GitGuardian CLI) files, repositories और Docker images को scan करता है और local या CI workflows के साथ integrate होता है: `ggshield secret scan repo <path-or-url>`.<sup>[[9]](#references)</sup>

### GitHub पर secrets आम तौर पर कहाँ leak होते हैं

- GitHub Code Search सिर्फ default branch को index करता है; non-default branches की सीधे जाँच करें या उन्हें clone करें।<sup>[[4]](#references)</sup>
- पूरा git history और अन्य branches/tags (clone करके gitleaks/trufflehog से scan करें; GitHub search सिर्फ indexed content को कवर करता है)।<sup>[[4]](#references)[[6]](#references)</sup>
- Issues, pull requests, comments और descriptions (TruffleHog का GitHub source इन्हें `--issue-comments` और `--pr-comments` जैसे flags के ज़रिए support करता है)।<sup>[[2]](#references)</sup>
- Actions workflow logs और artifacts (read access से इन्हें देखा या download किया जा सकता है, और secret redaction की गारंटी नहीं है)।<sup>[[11]](#references)[[12]](#references)</sup>
- Wikis और release assets।
- Gists (tooling या UI से search करें; कुछ tools gists को शामिल कर सकते हैं)।<sup>[[2]](#references)[[13]](#references)</sup>

> ध्यान देने योग्य बातें
> - GitHub का Code Search UI regex support करता है, जबकि REST/API तरीका (`gh search code` सहित) legacy engine इस्तेमाल करता है और regex features उपलब्ध नहीं कराता। Regex queries के लिए UI को प्राथमिकता दें।<sup>[[3]](#references)[[5]](#references)</sup>
> - GitHub search अपने दस्तावेज़ में दी गई size limit से बड़ी files को छोड़ देता है और exhaustive नहीं है। पूरी जाँच के लिए repositories को clone करें और secrets scanner से locally scan करें।<sup>[[4]](#references)</sup>

### Programmatic org-wide scanning

- TruffleHog (GitHub source)।<sup>[[2]](#references)[[13]](#references)</sup>
```bash
export GITHUB_TOKEN=<token>
trufflehog github --org Target --results=verified \
  --include-wikis --issue-comments --pr-comments --gist-comments
```
- सभी org repos पर Gitleaks चलाएँ (shallow clone करें और `gitleaks dir` से scan करें)।<sup>[[6]](#references)</sup>
```bash
gh repo list Target --limit 1000 --json nameWithOwner,url \
| jq -r '.[].url' | while read -r r; do
  tmp=$(mktemp -d); git clone --depth 1 "$r" "$tmp" && \
  gitleaks dir -v "$tmp" || true; rm -rf "$tmp";
done
```
- मौजूदा इंस्टॉलेशन के लिए mono checkout पर Nosey Parker।<sup>[[7]](#references)</sup>
```bash
# after cloning many repos beneath ./org
noseyparker scan --datastore np.db org/ && noseyparker report --datastore np.db
```
- ggshield त्वरित स्कैन।<sup>[[9]](#references)</sup>
```bash
# current working tree
ggshield secret scan path -r .
# full git history of a repo
ggshield secret scan repo <path-or-url>
```

> सुझाव: git history के लिए, हटाए गए secrets का पता लगाने हेतु ऐसे scanners को प्राथमिकता दें जो `git log -p --all` को parse करते हैं।<sup>[[6]](#references)</sup>

### Pull-request refs और Gist revision history

सामान्य clones GitHub के `refs/pull/<number>/head` refs को fetch नहीं करते, इसलिए `git log --all` उन commits को नहीं दिखाता जो केवल इन refs के ज़रिए उपलब्ध हैं—जब तक आप उन्हें fetch न करें।<sup>[[14]](#references)[[17]](#references)</sup> PR refs, किसी contributor द्वारा अपना fork delete करने के बाद भी unmerged commits को उजागर कर सकते हैं।<sup>[[15]](#references)</sup> केवल branch history को rewrite करने से sensitive commits PR references के ज़रिए उपलब्ध रह सकते हैं।<sup>[[16]](#references)</sup>

Full clone में, scan करने से पहले चुने गए PR head को fetch करें, या जब अतिरिक्त download उचित हो, तब सभी advertised PR heads के लिए wildcard refspec का इस्तेमाल करें।<sup>[[17]](#references)[[18]](#references)</sup> Gitleaks `git log -p` से local commit patches को scan करता है, इसलिए refs fetch करने के बाद इसे फिर से चलाएँ।<sup>[[6]](#references)</sup>

```bash
git fetch origin 'refs/pull/123/head:refs/remotes/origin/pr/123'
# Or fetch every advertised PR head:
git fetch origin '+refs/pull/*/head:refs/remotes/origin/pr/*'
gitleaks git -v --log-opts="--all" .
```

Gist का Git history भी होता है, इसलिए केवल उसकी मौजूदा फ़ाइलें जाँचने से बाद के revision में हटाए गए credential का पता नहीं चल सकता।<sup>[[19]](#references)</sup> दायरे में आने वाले public Gist के लिए, उसका Git repository clone करें और revisions को scan करें।<sup>[[19]](#references)[[6]](#references)</sup>

```bash
git clone https://gist.github.com/GIST_ID.git
gitleaks git -v --log-opts="--all" GIST_ID
```

### आधुनिक tokens के लिए अपडेट किए गए dorks

- GitHub tokens: `ghp_` `gho_` `ghu_` `ghs_` `ghr_` `github_pat_`.<sup>[[10]](#references)</sup>
- Slack tokens: `xoxb-` `xoxp-` `xoxa-` `xoxs-` `xoxc-` `xoxe-`
- Cloud और सामान्य:
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

अतिरिक्त code-search workflows के लिए, [Wide Source Code Search](wide-source-code-search.md) देखें।



## References

- [1] [सार्वजनिक repositories से secrets को बाहर रखना (GitHub Blog, Feb 29, 2024)](https://github.blog/news-insights/product-news/keeping-secrets-out-of-public-repositories/)
- [2] [TruffleHog v3 – leaked credentials ढूँढ़ें, verify करें और analyze करें](https://github.com/trufflesecurity/trufflehog)
- [3] [GitHub Code Search syntax को समझना](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [4] [code खोजना (legacy)](https://docs.github.com/en/search-github/searching-on-github/searching-code)
- [5] [gh search code](https://cli.github.com/manual/gh_search_code)
- [6] [Gitleaks README](https://github.com/gitleaks/gitleaks/blob/master/README.md)
- [7] [Nosey Parker README](https://github.com/praetorian-inc/noseyparker#readme)
- [8] [Titus README](https://github.com/praetorian-inc/titus#readme)
- [9] [ggshield README](https://github.com/GitGuardian/ggshield#readme)
- [10] [Secrets संदर्भ (GitHub Actions)](https://docs.github.com/en/actions/reference/security/secrets)
- [11] [Secrets (GitHub Actions)](https://docs.github.com/en/actions/concepts/security/secrets)
- [12] [workflow run logs का उपयोग करना (GitHub Actions)](https://docs.github.com/en/actions/how-tos/monitor-workflows/use-workflow-run-logs)
- [13] [TruffleHog GitHub source](https://github.com/trufflesecurity/trufflehog/blob/main/main.go)
- [14] [Pull request refs और merge branches (GitHub Docs)](https://docs.github.com/en/pull-requests/reference/pull-requests)
- [15] [Pull requests को locally checkout करना (GitHub Docs)](https://docs.github.com/en/pull-requests/how-tos/review-pull-requests/checking-out-pull-requests-locally)
- [16] [repository से संवेदनशील data हटाना (GitHub Docs)](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
- [17] [git-fetch दस्तावेज़](https://git-scm.com/docs/git-fetch)
- [18] [Pull request को scan करना (betterleaks)](https://github.com/betterleaks/betterleaks/blob/main/docs/scanning.md)
- [19] [Gists के लिए REST API endpoints (GitHub Docs)](https://docs.github.com/en/rest/gists/gists)
{{#include ../../banners/hacktricks-training.md}}
