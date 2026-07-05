# Wide Source Code Search

{{#include ../../banners/hacktricks-training.md}}

Bu sayfanın amacı, **binlerce/milyonlarca repo** arasında kod aramanıza izin veren **platformları** listelemektir (literal, regex, symbol-aware veya path-scoped).

Bu, şunlar için faydalıdır:

- **Sızmış bilgileri aramak**
- **Vulnerable pattern’leri aramak**
- **Teknolojileri, internal host’ları, CI/CD’yi ve infrastructure-as-code’u eşlemek**
- **Bir şirket/organizasyon adından repo’lara, branch’lere ve yüksek sinyalli dosyalara pivot yapmak**

- [**Sourcebot**](https://www.sourcebot.dev/): Açık kaynak/self-hosted code search. **Birçok repo’yu** indexlemek istediğinizde ve, yapılandırılırsa, `repo:`, `file:`, `lang:`, `rev:` ve `sym:` gibi regex filtrelerini korurken ek branch/tag’leri de dahil etmek için çok kullanışlıdır.
- [**SourceGraph**](https://sourcegraph.com/search): Milyonlarca repo içinde arama. Regex genellikle en güvenli seçenektir; structural search bazı deployment’larda vardır, ancak performans sınırlamaları vardır ve her zaman etkin değildir.
- [**GitHub Code Search**](https://github.com/search): Regex, boolean logic ve `repo:`, `org:`, `user:`, `path:`, `language:`, `symbol:`, `content:` ve `is:` gibi qualifiers destekler.
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/): Zoekt ile güçlendirilmiş modern GitLab code search. `file:`, `lang:`, `repo:` ve `sym:` gibi filtrelerle exact ve regex modlarını destekler.
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/) hâlâ geniş bir fallback olarak faydalıdır çünkü code, comments, commits, merge requests ve wikis içinde arama yapabilir.
- [**SearchCode**](https://searchcode.com/): Milyonlarca project içinde code arayın.

## Faydalı arama yetenekleri

Bir org’u bug bounty/red team bağlamında incelerken, en faydalı yetenekler genellikle şunlardır:

- Token formatlarını, URL scheme’lerini, dangerous function adlarını veya multiline parçaları aramak için **Regex** desteği.
- `.github/workflows/`, `terraform/`, `helm/`, `.env`, `values.yaml`, `secrets.*`, `credentials.*`, `Dockerfile`, `Jenkinsfile` veya `nginx.conf` gibi yüksek değerli dosyalara doğrudan gitmek için **Path filtreleri**.
- App code’u IaC ve pipeline’lardan ayırmak için **Language filtreleri**.
- Handler’ları, auth middleware’leri, webhook consumer’ları, dangerous helper function’ları veya belirli class/method’ları listelemek için **Symbol-aware search**.
- Gürültüyü azaltmak için **Boolean operatörler**: `NOT path:test`, `NOT is:generated`, `NOT is:vendored`, `foo OR bar`.

## Pratik metodoloji

1. Repos, sahipler, path’ler ve code family’lerini hızlıca belirlemek için önce **indexed platformlar** ile başlayın.
2. Yalnızca genel `password`/`secret` string’lerini aramak yerine **yüksek sinyalli lokasyonlara pivot yapın**.
3. Yalnızca credentials değil, **attack surface** arayın:
- CI/CD workflow’ları ve deployment script’leri
- Terraform/Helm/Kubernetes manifest’leri
- SSO/OIDC/SAML entegrasyonları
- Internal URL’ler, staging host’lar, admin panel’leri, message broker’lar ve callback endpoint’leri
- Dangerous code path’leri (`exec`, template rendering, SSRF fetchers, deserializers, ZIP extraction, YAML loaders, vb.)
4. Default olmayan branch’lere, full history’ye, daha iyi regex desteğine veya bulk automation’a ihtiyaç duyduğunuzda **lokalde clone edip arayın**.
5. Amaç secrets triage veya verification ise **dedicated scanner**’lara geçin (örneğin, aşağıdaki özel sayfaya bakın).

### Yüksek sinyalli sorgu fikirleri

Bunlar özellikle geniş tutulmuştur; böylece bunları GitHub, GitLab, Sourcegraph veya Sourcebot syntax’ına uyarlayabilirsiniz:
```text
org:target path:.github/workflows ("pull_request_target" OR "workflow_run" OR "ACTIONS_STEP_DEBUG")
org:target (path:terraform OR path:helm OR language:HCL OR language:YAML) ("role_arn" OR "assume_role" OR "client_secret" OR "access_key")
org:target ("BEGIN PRIVATE KEY" OR "ghp_" OR "github_pat_" OR "AIza" OR "xoxb-")
org:target (path:.env OR path:values.yaml OR path:application-prod OR path:credentials)
org:target ("internal" OR "corp" OR "staging") ("https://" OR "ssh://") NOT path:test
```
### İndekslenmiş arama yeterli olmadığında toplu yerel arama
```bash
gh repo list TARGET_ORG --limit 1000 --json nameWithOwner,sshUrl \
| jq -r '.[].sshUrl' \
| while read -r repo; do
dst="repos/$(basename "$repo" .git)"
git clone --depth 1 "$repo" "$dst" 2>/dev/null || true
done

rg -n --pcre2 \
-g '!{.git,node_modules,vendor,dist,build,coverage}' \
'(AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,255}|github_pat_[A-Za-z0-9_]{20,255}|AIza[0-9A-Za-z\-_]{35}|BEGIN (RSA|OPENSSH|EC) PRIVATE KEY)' \
repos/
```
Local searching kullanmanız gereken durumlar:

- **default olmayan branch**'leri veya **tag**'leri aramak
- **git history**'yi aramak
- **PCRE2/multiline** sorgularını daha agresif çalıştırmak
- UI limitleri olmadan çok sayıda repository'yi toplu triage etmek

## Common blind spots

- **Default-branch-only indexing** yaygındır. code search'ün tüm branch/tag/history'yi kapsadığını varsaymayın.
- **Large files, vendored code, generated code, or archives** atlanabilir veya gürültülü olabilir.
- **Comments, issues, PRs, gists, and wikis** çoğu zaman generic code search kapsamının dışındadır ve platforma özel araçlar gerektirebilir.
- **Search syntax platforma göre değişir**. GitHub Code Search'te çalışan bir dork, GitLab, Sourcegraph veya Sourcebot için küçük değişiklikler gerektirebilir.

### Platform-specific gotchas

- **GitHub Code Search** hızlı recon için mükemmeldir, ancak yalnızca **default branch**'i arar. Feature branch'lere, silinmiş secrets'a veya historical code'a ihtiyacınız varsa, repo'yu clone edip local olarak arayın.
- **GitLab Exact Code Search** da bir **default-branch** kısıtlamasına sahiptir ve yalnızca daha küçük dosyaları indexler, ancak **Advanced Search** comments, commits ve wikis'i aramak için yine de faydalı olabilir.
- **Sourcebot** varsayılan olarak **default branch**'i indexler, ancak ek branch'leri/tag'leri indexleyecek şekilde yapılandırılabilir ve ardından `rev:` filtreleriyle aranabilir; bu da index'i kontrol ettiğiniz branch/tag odaklı internal audit'ler için çok kullanışlıdır.
- **Sourcegraph** regex search, offensive work için genellikle en öngörülebilir seçenektir; structural search'ü zorunlu bir özellik değil, isteğe bağlı bir bonus olarak değerlendirin.

> [!WARNING]
> Bir repo'da leak ararken ve `git log -p` gibi bir şey çalıştırırken, **başka branch'lerde başka commits'lerin** secret içerebileceğini unutmayın!

Özel secret hunting, org-wide GitHub dork'ları ve TruffleHog/Gitleaks gibi araçlar için şuraya bakın:

{{#ref}}
github-leaked-secrets.md
{{#endref}}



## References

- [GitHub Code Search syntax](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
{{#include ../../banners/hacktricks-training.md}}
