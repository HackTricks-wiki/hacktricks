# Geniş Kapsamlı Source Code Araması

{{#include ../../banners/hacktricks-training.md}}

Bu sayfanın amacı, **binlerce/milyonlarca repo genelinde code aramanıza** (literal, regex, symbol-aware veya path-scoped) olanak tanıyan **platformları** listelemektir.

Bu, şunlar için kullanışlıdır:

- **Sızdırılmış bilgileri aramak**
- **Güvenlik açığı içeren pattern'leri aramak**
- **Teknolojileri, internal host'ları, CI/CD'yi ve infrastructure-as-code yapılarını haritalamak**
- **Bir şirket/org adından repo'lara, branch'lere ve yüksek sinyalli dosyalara pivot yapmak**

- [**Sourcebot**](https://www.sourcebot.dev/): Open-source/self-hosted code search. **Birçok repo'yu** index'lemek ve yapılandırıldığında regex filtrelerini (`repo:`, `file:`, `lang:`, `rev:` ve `sym:`) koruyarak ek branch/tag'leri dahil etmek istediğinizde oldukça kullanışlıdır.
- [**SourceGraph**](https://sourcegraph.com/search): Milyonlarca repo içinde arama yapar. Regex genellikle en güvenli seçenektir; bazı deployment'larda structural search bulunur, ancak performans sınırlamaları vardır ve her zaman etkin olmayabilir.
- [**GitHub Code Search**](https://github.com/search): Regex, boolean logic ve `repo:`, `org:`, `user:`, `path:`, `language:`, `symbol:`, `content:` ve `is:` gibi qualifier'ları destekler.<sup>[[1]](#references)</sup>
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/): Zoekt tarafından desteklenen modern GitLab code search özelliğidir. `file:`, `lang:`, `repo:` ve `sym:` gibi filtrelerle exact ve regex modlarını destekler.<sup>[[2]](#references)</sup>
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/) daha geniş bir fallback olarak hâlâ kullanışlıdır; çünkü code, comment, commit, merge request ve wiki'lerde arama yapabilir.
- [**SearchCode**](https://searchcode.com/): Milyonlarca project içinde code araması yapar.
- [**Grep**](https://grep.app/): Çok büyük bir GitHub corpus'u genelinde hızlı public search sağlar. **Content**, **file** ve **path** pivot'ları için ikinci bir indexing/ranking görünümü istediğinizde kullanışlıdır.

## Kullanışlı arama yetenekleri

Bir org'u bug bounty/red team bağlamında audit ederken en kullanışlı yetenekler genellikle şunlardır:

- **Regex** desteği; token format'larını, URL scheme'lerini, tehlikeli function adlarını veya multiline fragment'lerini aramak için.
- **Path filtreleri**; `.github/workflows/`, `terraform/`, `helm/`, `.env`, `values.yaml`, `secrets.*`, `credentials.*`, `Dockerfile`, `Jenkinsfile` veya `nginx.conf` gibi yüksek değerli dosyalara doğrudan geçmek için.
- **Language filtreleri**; app code'u IaC ve pipeline'lardan ayırmak için.
- **Symbol-aware search**; handler'ları, auth middleware'lerini, webhook consumer'larını, tehlikeli helper function'larını veya belirli class/method'ları listelemek için.
- **Boolean operator'lar**; gürültüyü azaltmak için: `NOT path:test`, `NOT is:generated`, `NOT is:vendored`, `foo OR bar`.
- Kullanılabildiğinde **revision/diff search**; böylece her şeyi önce clone etmeden **silinmiş string'leri** kurtarabilir, **security-relevant değişiklikleri** takip edebilir veya **default olmayan branch/tag'leri** inceleyebilirsiniz.

## Pratik metodoloji

1. Repo'ları, owner'ları, path'leri ve code family'lerini hızlıca belirlemek için **index'lenmiş platformlarla** başlayın.
2. Yalnızca genel `password`/`secret` string'lerini aramak yerine **yüksek sinyalli konumlara pivot yapın**.
3. **Yalnızca credential'ları değil, attack surface'i arayın**:
- CI/CD workflow'ları, reusable workflow'lar, composite action'lar ve deployment script'leri
- Dev Containers / Codespaces bootstrap dosyaları ve custom feature'lar
- Terraform/Helm/Kubernetes manifest'leri
- SSO/OIDC/SAML entegrasyonları
- Internal URL'ler, staging host'ları, admin panel'leri, message broker'lar ve callback endpoint'leri
- Tehlikeli code path'leri (`exec`, template rendering, SSRF fetcher'ları, deserializer'lar, ZIP extraction, YAML loader'ları vb.)
4. Default olmayan branch'lere, full history'ye, daha iyi regex desteğine veya bulk automation'a ihtiyaç duyduğunuzda **lokalde clone edip arama yapın**.
5. Amaç secrets triage veya verification olduğunda **dedicated scanner'lara geçin** (örneğin aşağıdaki dedicated page'e bakın).

### Yüksek sinyalli query fikirleri

Bunlar, GitHub, GitLab, Sourcegraph veya Sourcebot syntax'ına uyarlayabilmeniz için özellikle geniş tutulmuştur:
```text
org:target path:.github/workflows ("pull_request_target" OR "workflow_run" OR "ACTIONS_STEP_DEBUG")
org:target (path:terraform OR path:helm OR language:HCL OR language:YAML) ("role_arn" OR "assume_role" OR "client_secret" OR "access_key")
org:target ("BEGIN PRIVATE KEY" OR "ghp_" OR "github_pat_" OR "AIza" OR "xoxb-")
org:target (path:.env OR path:values.yaml OR path:application-prod OR path:credentials)
org:target path:.github/workflows ("pull_request_target" OR "workflow_run" OR "workflow_call" OR "secrets: inherit" OR "id-token: write" OR "self-hosted")
org:target path:.github/workflows ("uses:" AND NOT /@[0-9a-f]{40}/)
org:target (path:.devcontainer OR path:devcontainer.json) ("remoteEnv" OR "containerEnv" OR "initializeCommand" OR "postCreateCommand" OR "mounts")
org:target ("devcontainer-feature.json" OR "install.sh") ("curl " OR "wget " OR "docker.sock" OR "sudo ")
org:target ("internal" OR "corp" OR "staging") ("https://" OR "ssh://") NOT path:test
```
### Öncelik verilmeye değer daha yeni yüksek sinyalli dosyalar

- **`.github/workflows/*.yml`**: `pull_request_target`, `workflow_run`, `workflow_call`, `secrets: inherit`, `id-token: write`, `runs-on: self-hosted` ve yalnızca tam commit SHA'leri yerine tag/branch'lere sabitlenmiş üçüncü taraf `uses:` satırlarını arayın.<sup>[[3]](#references)</sup>
- **`.devcontainer/devcontainer.json`**, **`.devcontainer/<variant>/devcontainer.json`** ve **`.devcontainer.json`**: `remoteEnv`, `containerEnv`, `initializeCommand`, `postCreateCommand`, `mounts` ile başvurulan Dockerfile'ları/script'leri arayın. Bunlar genellikle dahili package registry'lerini, bootstrap URL'lerini, host mount'larını ve yalnızca geliştiricilere özel endpoint'leri açığa çıkarır.<sup>[[4]](#references)</sup>
- **Dev Container Features** (`devcontainer-feature.json`, `install.sh`): Ortam oluşturma sırasında çalışan kuruluşa özel installer mantığını bulmak için harikadır.
- **Diğer CI/control-plane dosyaları**: `.gitlab-ci.yml`, `azure-pipelines.yml`, `cloudbuild.yaml`, `Jenkinsfile`, `buildkite*`, `atlantis.yaml`, `terragrunt.hcl`, `helmfile.yaml`, `skaffold.yaml`, `argocd*`.

### Indexlenmiş arama yeterli olmadığında toplu yerel arama
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
İhtiyaç duyduğunuz durumlarda local searching kullanın:

- **non-default branches** veya **tags** içinde arama yapmak
- **git history** içinde arama yapmak
- **PCRE2/multiline** sorgularını daha agresif şekilde çalıştırmak
- UI limitleri olmadan birçok repository üzerinde toplu triage yapmak

### History, branches ve diffs içinde açıkça arama yapın
```bash
REPO_DIR=repos/some-repo
git -C "$REPO_DIR" fetch --all --tags --prune

git -C "$REPO_DIR" for-each-ref --format='%(refname:short)' refs/remotes/origin refs/tags \
| while read -r ref; do
git -C "$REPO_DIR" grep -nI -E 'pull_request_target|workflow_call|id-token: write|secrets: inherit|remoteEnv|containerEnv' "$ref" || true
done

git -C "$REPO_DIR" log --all -p -G 'gh[pousr]_|github_pat_|BEGIN [A-Z ]+PRIVATE KEY|internal.*https?://' -- .
```
Bu, ilginç string yalnızca bir **release branch**, **tag** veya **deleted commit** içinde mevcut olduğunda özellikle kullanışlıdır. Sourcegraph deployment'ınız bunu destekliyorsa, `type:diff` ve `type:commit` aramaları aynı sorun için clone gerektirmeyen mükemmel bir pivot seçeneğidir.

## Yaygın kör noktalar

- **Yalnızca default branch'in index'lenmesi** yaygındır. Code search'ün tüm branch/tag/history kapsamını içerdiğini varsaymayın.
- **Büyük dosyalar, vendored code, generated code veya arşivler** atlanabilir ya da gürültü oluşturabilir.
- **Yorumlar, issue'lar, PR'lar, gist'ler ve wiki'ler** çoğu zaman genel code search kapsamı dışındadır ve platforma özgü tooling gerektirebilir.
- **Codespaces / devcontainer config'leri branch'e özgü olabilir** ve birden fazla `.devcontainer/<variant>/devcontainer.json` path'inde bulunabilir. Bu nedenle temiz bir default branch, dev environment'ın her yerde temiz olduğu anlamına gelmez.
- **Reusable workflow/action'lar ve devcontainer feature'ları bariz dosyanın dışında bulunabilir**. Yalnızca üst düzey workflow dosyasını değil, `.github/actions/`, `action.yml`, `action.yaml`, `devcontainer-feature.json` ve `install.sh` dosyalarını da arayın.
- **Search syntax platforma göre değişir**. GitHub Code Search'te çalışan bir dork, GitLab, Sourcegraph veya Sourcebot için küçük değişiklikler gerektirebilir.

### Platforma özgü dikkat edilmesi gerekenler

- **GitHub Code Search** hızlı recon için mükemmeldir, ancak yalnızca **default branch** üzerinde arama yapar. Feature branch'lere, silinmiş secret'lara veya geçmişteki code'a ihtiyacınız varsa repo'yu clone edin ve yerel olarak arayın.
- **GitLab Exact Code Search** de **default branch** sınırlamasına sahiptir ve yalnızca daha küçük dosyaları index'ler; ancak **Advanced Search**, comment'leri, commit'leri ve wiki'leri aramak için yine de kullanışlı olabilir.<sup>[[2]](#references)</sup>
- **Sourcebot** varsayılan olarak **default branch**'i index'ler, ancak ek branch/tag'leri index'leyecek şekilde yapılandırılabilir ve ardından `rev:` filter'larıyla aranabilir. Bu, index'i kontrol ettiğiniz branch/tag odaklı internal audit'ler için oldukça kullanışlıdır.
- **Sourcegraph** regex search, offensive work için genellikle en öngörülebilir seçenektir; structural search'ü garanti edilen bir özellik olarak değil, isteğe bağlı bir bonus olarak değerlendirin. Deployment destekliyorsa, `type:diff` ve `type:commit` query'leri silinmiş string'leri veya güvenlikle ilgili yeni değişiklikleri kurtarmak için oldukça iyidir.

> [!WARNING]
> Bir repo'da leak ararken `git log -p` gibi bir şey çalıştırdığınızda, secret içeren **başka commit'lere sahip başka branch'ler** olabileceğini unutmayın!

Dedicated secret hunting, org-wide GitHub dork'ları ve TruffleHog/Gitleaks gibi tooling için şuraya bakın:

{{#ref}}
github-leaked-secrets.md
{{#endref}}

## References

- [1] [GitHub Code Search syntax](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [2] [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
- [3] [GitHub Actions secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [4] [Dev Container metadata reference](https://containers.dev/implementors/json_reference/)

{{#include ../../banners/hacktricks-training.md}}
