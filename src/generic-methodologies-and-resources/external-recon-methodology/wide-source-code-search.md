# Wide Source Code Search

{{#include ../../banners/hacktricks-training.md}}

Bu sayfanın amacı, **binlerce/milyonlarca repo genelinde code aramanıza** (literal, regex, symbol-aware veya path-scoped) olanak sağlayan **platformları** listelemektir.

Bu şu amaçlar için kullanışlıdır:

- **Leak edilmiş bilgileri aramak**
- **Vulnerable pattern'leri aramak**
- **Technology'leri, internal host'ları, CI/CD'yi ve infrastructure-as-code'u haritalamak**
- **Bir şirket/org adından repo'lara, branch'lere ve yüksek sinyalli file'lara pivot yapmak**

- [**Sourcebot**](https://www.sourcebot.dev/): Open-source/self-hosted code search. **Birçok repo'yu** index etmek ve yapılandırıldığında regex filter'larını (`repo:`, `file:`, `lang:`, `rev:` ve `sym:`) korurken ek branch/tag'leri de dahil etmek istediğinizde çok kullanışlıdır.
- [**SourceGraph**](https://sourcegraph.com/search): Milyonlarca repo'da arama yapar. Regex genellikle en güvenli seçenektir; bazı deployment'larda structural search bulunur, ancak performans sınırlamaları vardır ve her zaman etkin olmayabilir.
- [**GitHub Code Search**](https://github.com/search): Regex, boolean logic ve `repo:`, `org:`, `user:`, `path:`, `language:`, `symbol:`, `content:` ve `is:` gibi qualifier'ları destekler.
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/): Zoekt tarafından desteklenen modern GitLab code search. `file:`, `lang:`, `repo:` ve `sym:` gibi filter'larla exact ve regex mode'larını destekler.
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/) code, comment, commit, merge request ve wiki'lerde arama yapabildiği için daha geniş bir fallback olarak hâlâ kullanışlıdır.
- [**SearchCode**](https://searchcode.com/): Milyonlarca project'te code arar.
- [**Grep**](https://grep.app/): Çok büyük bir GitHub corpus'u genelinde hızlı public search. **Content**, **file** ve **path** pivot'ları için ikinci bir indexing/ranking görünümü istediğinizde kullanışlıdır.

## Useful search capabilities

Bir org'u bug bounty/red team bağlamında audit ederken en kullanışlı yetenekler genellikle şunlardır:

- Token format'larını, URL scheme'lerini, dangerous function name'lerini veya multiline fragment'larını aramak için **Regex** desteği.
- `.github/workflows/`, `terraform/`, `helm/`, `.env`, `values.yaml`, `secrets.*`, `credentials.*`, `Dockerfile`, `Jenkinsfile` veya `nginx.conf` gibi yüksek değerli file'lara doğrudan geçmek için **Path filter'ları**.
- App code'u IaC ve pipeline'larından ayırmak için **Language filter'ları**.
- Handler'ları, auth middleware'lerini, webhook consumer'larını, dangerous helper function'larını veya belirli class/method'ları listelemek için **Symbol-aware search**.
- Gürültüyü azaltmak için **Boolean operator'lar**: `NOT path:test`, `NOT is:generated`, `NOT is:vendored`, `foo OR bar`.
- Kullanılabilir olduğunda **Revision/diff search**; böylece her şeyi önce clone etmeden **silinmiş string'leri** kurtarabilir, **security-relevant change'leri** takip edebilir veya **non-default branch/tag'leri** inceleyebilirsiniz.

## Practical methodology

1. Repo'ları, owner'ları, path'leri ve code family'lerini hızlıca belirlemek için **index'lenmiş platform'larla başlayın**.
2. Yalnızca genel `password`/`secret` string'lerini aramak yerine **yüksek sinyalli konumlara pivot yapın**.
3. **Yalnızca credential'ları değil, attack surface'ü arayın**:
- CI/CD workflow'ları, reusable workflow'lar, composite action'lar ve deployment script'leri
- Dev Containers / Codespaces bootstrap file'ları ve custom feature'lar
- Terraform/Helm/Kubernetes manifest'leri
- SSO/OIDC/SAML integration'ları
- Internal URL'ler, staging host'ları, admin panel'leri, message broker'lar ve callback endpoint'leri
- Dangerous code path'leri (`exec`, template rendering, SSRF fetcher'ları, deserializer'lar, ZIP extraction, YAML loader'ları vb.)
4. Non-default branch'lere, full history'ye, daha iyi regex desteğine veya bulk automation'a ihtiyaç duyduğunuzda **clone edip local olarak arama yapın**.
5. Amaç secrets triage veya verification olduğunda **dedicated scanner'lara geçin** (örneğin aşağıdaki dedicated page'e bakın).

### High-signal query ideas

Bunlar, GitHub, GitLab, Sourcegraph veya Sourcebot syntax'ına uyarlayabilmeniz için kasıtlı olarak geniş tutulmuştur:
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
### Öncelik verilmeye değer daha yeni, yüksek sinyalli dosyalar

- **`.github/workflows/*.yml`**: `pull_request_target`, `workflow_run`, `workflow_call`, `secrets: inherit`, `id-token: write`, `runs-on: self-hosted` ve tam commit SHA'leri yerine yalnızca tag/branch'lere sabitlenmiş üçüncü taraf `uses:` satırlarını arayın.
- **`.devcontainer/devcontainer.json`**, **`.devcontainer/<variant>/devcontainer.json`** ve **`.devcontainer.json`**: `remoteEnv`, `containerEnv`, `initializeCommand`, `postCreateCommand`, `mounts` ile başvurulan Dockerfile ve script'leri arayın. Bunlar genellikle dahili package registry'lerini, bootstrap URL'lerini, host mount'larını ve yalnızca geliştiricilere özel endpoint'leri açığa çıkarır.
- **Dev Container Features** (`devcontainer-feature.json`, `install.sh`): Ortam oluşturma sırasında çalıştırılan kuruluşa özel installer mantığını bulmak için idealdir.
- **Diğer CI/control-plane dosyaları**: `.gitlab-ci.yml`, `azure-pipelines.yml`, `cloudbuild.yaml`, `Jenkinsfile`, `buildkite*`, `atlantis.yaml`, `terragrunt.hcl`, `helmfile.yaml`, `skaffold.yaml`, `argocd*`.

### İndeksli arama yeterli olmadığında toplu yerel arama
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
Şunlara ihtiyaç duyduğunuzda yerel aramayı kullanın:

- **Varsayılan olmayan branch** veya **tag**'lerde arama yapmak
- **git history** içinde arama yapmak
- **PCRE2/multiline** sorgularını daha agresif şekilde çalıştırmak
- UI limitleri olmadan birçok repository'yi toplu şekilde triage etmek

### History, branch ve diff'leri açıkça arayın
```bash
REPO_DIR=repos/some-repo
git -C "$REPO_DIR" fetch --all --tags --prune

git -C "$REPO_DIR" for-each-ref --format='%(refname:short)' refs/remotes/origin refs/tags \
| while read -r ref; do
git -C "$REPO_DIR" grep -nI -E 'pull_request_target|workflow_call|id-token: write|secrets: inherit|remoteEnv|containerEnv' "$ref" || true
done

git -C "$REPO_DIR" log --all -p -G 'gh[pousr]_|github_pat_|BEGIN [A-Z ]+PRIVATE KEY|internal.*https?://' -- .
```
Bu, özellikle ilgi çekici string yalnızca bir **release branch**, **tag** veya **deleted commit** içinde mevcut olduğunda kullanışlıdır. Sourcegraph deployment'ınız destekliyorsa `type:diff` ve `type:commit` aramaları, aynı problem için mükemmel bir no-clone pivot seçeneğidir.

## Yaygın kör noktalar

- **Yalnızca default branch indekslemesi** yaygındır. Code search'ün tüm branch/tag/history kapsamını içerdiğini varsaymayın.
- **Büyük dosyalar, vendored code, generated code veya arşivler** atlanabilir ya da gürültü oluşturabilir.
- **Yorumlar, issue'lar, PR'lar, gist'ler ve wiki'ler** genellikle generic code search kapsamı dışındadır ve platforma özgü tooling gerektirebilir.
- **Codespaces / devcontainer config'leri branch'e özgü olabilir** ve birden fazla `.devcontainer/<variant>/devcontainer.json` path'inde bulunabilir; bu nedenle temiz bir default branch, dev environment'ın her yerde temiz olduğu anlamına gelmez.
- **Reusable workflow/action'lar ve devcontainer feature'ları bariz dosyanın dışında bulunabilir**. Yalnızca üst düzey workflow dosyasında değil, `.github/actions/`, `action.yml`, `action.yaml`, `devcontainer-feature.json` ve `install.sh` dosyalarında da arama yapın.
- **Search syntax platforma göre değişir**. GitHub Code Search'te çalışan bir dork, GitLab, Sourcegraph veya Sourcebot için küçük değişiklikler gerektirebilir.

### Platforma özgü gotcha'lar

- **GitHub Code Search** hızlı recon için mükemmeldir, ancak yalnızca **default branch** üzerinde arama yapar. Feature branch'lere, deleted secret'lara veya historical code'a ihtiyacınız varsa repo'yu clone edin ve yerel olarak arayın.
- **GitLab Exact Code Search** de **default branch** sınırlamasına sahiptir ve yalnızca daha küçük dosyaları indeksler; ancak **Advanced Search**, yorumlarda, commit'lerde ve wiki'lerde arama yapmak için yine de kullanışlı olabilir.
- **Sourcebot** varsayılan olarak **default branch**'i indeksler; ancak ek branch/tag'leri indeksleyecek şekilde yapılandırılabilir ve ardından `rev:` filter'larıyla aranabilir. Bu, index'i kontrol ettiğiniz branch/tag odaklı internal audit'ler için oldukça kullanışlıdır.
- **Sourcegraph** regex search, offensive work için genellikle en öngörülebilir seçenektir; structural search'ü garantili bir capability olarak değil, isteğe bağlı bir bonus olarak değerlendirin. Deployment destekliyorsa `type:diff` ve `type:commit` query'leri, deleted string'leri veya yakın tarihli security-relevant değişiklikleri geri getirmek için oldukça iyidir.

> [!WARNING]
> Bir repo'da leak ararken `git log -p` gibi bir komut çalıştırdığınızda, secret içeren **başka commit'lere sahip başka branch'ler** olabileceğini unutmayın!

Dedicated secret hunting, org-wide GitHub dork'ları ve TruffleHog/Gitleaks gibi tooling için şuraya bakın:

{{#ref}}
github-leaked-secrets.md
{{#endref}}



## Referanslar

- [GitHub Code Search syntax](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
- [GitHub Actions secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [Dev Container metadata reference](https://containers.dev/implementors/json_reference/)
{{#include ../../banners/hacktricks-training.md}}
