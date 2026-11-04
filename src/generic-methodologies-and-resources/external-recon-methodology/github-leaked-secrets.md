# Github Dorks & Leaks

{{#include ../../banners/hacktricks-training.md}}

### Git repo'larında ve dosya sisteminde secrets bulma araçları

- [TruffleHog](https://github.com/dxa4481/truffleHog)
- [Gitleaks](https://github.com/gitleaks/gitleaks)
- [Nosey Parker](https://github.com/praetorian-inc/noseyparker) (arşivlendi; yerini [Titus](https://github.com/praetorian-inc/titus) aldı)
- [ggshield](https://github.com/GitGuardian/ggshield)
- [RExpository](https://github.com/JaimePolop/RExpository)
- [detect-secrets](https://github.com/Yelp/detect-secrets)
- [gitGraber](https://github.com/hisxo/gitGraber)
- [shhgit](https://github.com/eth0izzle/shhgit) (bakımı yapılmıyor)
- [github-dorks](https://github.com/techgaun/github-dorks)
- [gitrob](https://github.com/michenriksen/gitrob) (arşivlendi)
- [git-all-secrets](https://github.com/anshumanbh/git-all-secrets) (arşivlendi)
- [git-secrets](https://github.com/awslabs/git-secrets)
- [gittyleaks](https://github.com/kootenpv/gittyleaks)
- [GitDorker](https://github.com/obheda12/GitDorker)

> Notlar
> - TruffleHog v3 birçok credential'ı canlı olarak doğrulayabilir ve GitHub org'larını, issue'ları/PR'ları, gist'leri ve wiki'leri tarayabilir. Örnek: `trufflehog github --org <ORG> --results=verified`.<sup>[[2]](#references)[[13]](#references)</sup>
> - Gitleaks, Git repository'lerini, dizinleri ve arşivleri tarar. Geçmişi taramak için `gitleaks git -v --log-opts="--all" <repo>`, dizinler için `gitleaks dir -v <path>` kullanın; arşivleri incelemek için `--max-archive-depth 1` ekleyin.<sup>[[6]](#references)</sup>
> - Nosey Parker arşivlendi ve yerini Titus aldı. Mevcut kurulumlarda `noseyparker scan --datastore np.db <path|repo>` komutunun ardından `noseyparker report --datastore np.db` komutu hâlâ kullanılabilir.<sup>[[7]](#references)[[8]](#references)</sup>
> - ggshield (GitGuardian CLI) dosyaları, repository'leri ve Docker image'larını tarar; yerel veya CI iş akışlarına entegre olur: `ggshield secret scan repo <path-or-url>`.<sup>[[9]](#references)</sup>

### GitHub'da secrets'ın sıkça leak olduğu yerler

- GitHub Code Search yalnızca varsayılan branch'i indeksler; varsayılan olmayan branch'leri doğrudan inceleyin veya clone edin.<sup>[[4]](#references)</sup>
- Tüm git geçmişi ve diğer branch/tag'ler (clone edip gitleaks/trufflehog ile tarayın; GitHub araması yalnızca indekslenmiş içeriği kapsar).<sup>[[4]](#references)[[6]](#references)</sup>
- Issue'lar, pull request'ler, yorumlar ve açıklamalar (TruffleHog'un GitHub kaynağı, `--issue-comments` ve `--pr-comments` gibi flag'lerle bunları destekler).<sup>[[2]](#references)</sup>
- Actions workflow log'ları ve artifact'ler (okuma erişimi bunları görüntülemeye veya indirmeye olanak tanır; secret'ların redakte edilmesi garanti değildir).<sup>[[11]](#references)[[12]](#references)</sup>
- Wiki'ler ve release asset'leri.
- Gist'ler (araçlarla veya arayüzden arayın; bazı araçlar gist'leri de kapsayabilir).<sup>[[2]](#references)[[13]](#references)</sup>

> Dikkat edilmesi gerekenler
> - GitHub'ın Code Search arayüzü regex'i desteklerken REST/API yolu (`gh search code` dahil) eski motoru kullanır ve regex özelliklerini sunmaz. Regex sorguları için arayüzü tercih edin.<sup>[[3]](#references)[[5]](#references)</sup>
> - GitHub araması, belgelenmiş boyut sınırını aşan dosyaları hariç tutar ve kapsamlı değildir. Eksiksiz tarama için repository'yi clone edip yerel bir secrets scanner ile tarayın.<sup>[[4]](#references)</sup>

### Programatik olarak org genelinde tarama

- TruffleHog (GitHub kaynağı).<sup>[[2]](#references)[[13]](#references)</sup>
```bash
export GITHUB_TOKEN=<token>
trufflehog github --org Target --results=verified \
  --include-wikis --issue-comments --pr-comments --gist-comments
```
- Kuruluşun tüm depolarında Gitleaks çalıştırın (sığ klonlayın ve `gitleaks dir` ile tarayın).<sup>[[6]](#references)</sup>
```bash
gh repo list Target --limit 1000 --json nameWithOwner,url \
| jq -r '.[].url' | while read -r r; do
  tmp=$(mktemp -d); git clone --depth 1 "$r" "$tmp" && \
  gitleaks dir -v "$tmp" || true; rm -rf "$tmp";
done
```
- Mevcut kurulumlar için mono checkout üzerinde Nosey Parker.<sup>[[7]](#references)</sup>
```bash
# after cloning many repos beneath ./org
noseyparker scan --datastore np.db org/ && noseyparker report --datastore np.db
```
- ggshield hızlı taramaları.<sup>[[9]](#references)</sup>
```bash
# current working tree
ggshield secret scan path -r .
# full git history of a repo
ggshield secret scan repo <path-or-url>
```

> İpucu: Git geçmişini taramak için, kaldırılmış secrets'ları yakalamak amacıyla `git log -p --all` komutunu ayrıştıran scanner'ları tercih edin.<sup>[[6]](#references)</sup>

### Pull request refs ve Gist revizyon geçmişi

Normal clone'lar GitHub'ın `refs/pull/<number>/head` ref'lerini getirmez. Bu nedenle, bu ref'ler üzerinden erişilebilen commit'leri fetch edene kadar `git log --all` çıktısında göremezsiniz.<sup>[[14]](#references)[[17]](#references)</sup> PR ref'leri, bir katkıcının fork'unu silmesinden sonra bile merge edilmemiş commit'leri açığa çıkarabilir.<sup>[[15]](#references)</sup> Yalnızca branch geçmişini yeniden yazmak, hassas commit'leri PR ref'leri üzerinden erişilebilir durumda bırakabilir.<sup>[[16]](#references)</sup>

Tam bir clone'da taramadan önce seçilen PR head'ini fetch edin veya ek indirme boyutu makulse duyurulan tüm PR head'lerini almak için wildcard refspec kullanın.<sup>[[17]](#references)[[18]](#references)</sup> Gitleaks yerel commit patch'lerini `git log -p` ile tarar; bu nedenle ref'leri fetch ettikten sonra taramayı yeniden çalıştırın.<sup>[[6]](#references)</sup>

```bash
git fetch origin 'refs/pull/123/head:refs/remotes/origin/pr/123'
# Or fetch every advertised PR head:
git fetch origin '+refs/pull/*/head:refs/remotes/origin/pr/*'
gitleaks git -v --log-opts="--all" .
```

Bir Gist'in Git geçmişi de vardır; bu nedenle yalnızca mevcut dosyalarını kontrol etmek, sonraki bir revizyonda kaldırılmış bir kimlik bilgisini gözden kaçırabilir.<sup>[[19]](#references)</sup> Kapsam dahilindeki herkese açık bir Gist için Git deposunu klonlayın ve revizyonları tarayın.<sup>[[19]](#references)[[6]](#references)</sup>

```bash
git clone https://gist.github.com/GIST_ID.git
gitleaks git -v --log-opts="--all" GIST_ID
```

### Modern token'lar için güncellenmiş dork'lar

- GitHub token'ları: `ghp_` `gho_` `ghu_` `ghs_` `ghr_` `github_pat_`.<sup>[[10]](#references)</sup>
- Slack token'ları: `xoxb-` `xoxp-` `xoxa-` `xoxs-` `xoxc-` `xoxe-`
- Cloud ve genel:
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

Ek code-search iş akışları için [Wide Source Code Search](wide-source-code-search.md) sayfasına bakın.



## References

- [1] [Gizli bilgileri herkese açık depolardan uzak tutma (GitHub Blog, 29 Şubat 2024)](https://github.blog/news-insights/product-news/keeping-secrets-out-of-public-repositories/)
- [2] [TruffleHog v3 – leaked kimlik bilgilerini bulma, doğrulama ve analiz etme](https://github.com/trufflesecurity/trufflehog)
- [3] [GitHub Code Search sözdizimini anlama](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [4] [Kod arama (eski)](https://docs.github.com/en/search-github/searching-on-github/searching-code)
- [5] [gh search code](https://cli.github.com/manual/gh_search_code)
- [6] [Gitleaks README](https://github.com/gitleaks/gitleaks/blob/master/README.md)
- [7] [Nosey Parker README](https://github.com/praetorian-inc/noseyparker#readme)
- [8] [Titus README](https://github.com/praetorian-inc/titus#readme)
- [9] [ggshield README](https://github.com/GitGuardian/ggshield#readme)
- [10] [Secrets başvurusu (GitHub Actions)](https://docs.github.com/en/actions/reference/security/secrets)
- [11] [Secrets (GitHub Actions)](https://docs.github.com/en/actions/concepts/security/secrets)
- [12] [İş akışı çalıştırma günlüklerini kullanma (GitHub Actions)](https://docs.github.com/en/actions/how-tos/monitor-workflows/use-workflow-run-logs)
- [13] [TruffleHog GitHub kaynak kodu](https://github.com/trufflesecurity/trufflehog/blob/main/main.go)
- [14] [Pull request referansları ve merge dalları (GitHub Docs)](https://docs.github.com/en/pull-requests/reference/pull-requests)
- [15] [Pull request'leri yerel olarak checkout etme (GitHub Docs)](https://docs.github.com/en/pull-requests/how-tos/review-pull-requests/checking-out-pull-requests-locally)
- [16] [Bir depodan hassas verileri kaldırma (GitHub Docs)](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
- [17] [git-fetch belgeleri](https://git-scm.com/docs/git-fetch)
- [18] [Bir pull request'i tarama (betterleaks)](https://github.com/betterleaks/betterleaks/blob/main/docs/scanning.md)
- [19] [Gists için REST API uç noktaları (GitHub Docs)](https://docs.github.com/en/rest/gists/gists)
{{#include ../../banners/hacktricks-training.md}}
