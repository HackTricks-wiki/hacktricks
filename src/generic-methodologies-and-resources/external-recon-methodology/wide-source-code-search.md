# Geniş Kapsamlı Source Code Araması

{{#include ../../banners/hacktricks-training.md}}

Bu sayfanın amacı, **binlerce/milyonlarca repo** genelinde code araması yapmanıza (literal, regex, symbol-aware veya path-scoped) olanak tanıyan **platformları** listelemektir.

Bu şu amaçlarla kullanışlıdır:

- **Leak edilmiş bilgileri arama**
- **Vulnerable pattern'leri arama**
- **Technology'leri, internal host'ları, CI/CD'yi ve infrastructure-as-code'u haritalama**
- **Bir company/org adından repo'lara, branch'lere ve yüksek sinyalli file'lara pivot etme**

- [**Sourcebot**](https://www.sourcebot.dev/): Repository'ler genelinde regex, symbol ve filtered search özelliklerine sahip open-source/self-hosted code search. Ek branch/tag'leri configure edin ve branch coverage önemli olduğunda bunları `rev:` ile query edin.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- [**Sourcegraph**](https://sourcegraph.com/search): Regex, boolean, symbol, repository/file/language, branch/commit, diff ve commit-message query'leriyle code search. Structural search isteğe bağlıdır; mevcut documentation bunu default olarak disabled ve performans açısından sınırlı olarak tanımlar.<sup>[[8]](#references)[[10]](#references)</sup> <sup>[[9]](#references)</sup>
- [**GitHub Code Search**](https://github.com/search): Regex, boolean logic ve `repo:`, `org:`, `user:`, `path:`, `language:`, `symbol:`, `content:` ve `is:` gibi qualifier'ları destekler.<sup>[[1]](#references)</sup>
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/): Zoekt tarafından desteklenen code search; exact ve regex mode'larının yanı sıra `file:`, `lang:`, `repo:` ve `sym:` gibi filter'lara sahiptir.<sup>[[2]](#references)</sup>
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/), code, comment, commit, merge request ve wiki'lerde arama yapabildiği için daha geniş bir fallback'tir.<sup>[[11]](#references)</sup>
- [**SearchCode**](https://searchcode.com/): Boolean/regex/structural code search ile file ve symbol retrieval özelliklerine sahip bir code-intelligence service.<sup>[[12]](#references)</sup>
- [**Grep**](https://grep.app/): Bir milyon GitHub repository'si genelinde content, file ve path search özelliklerine sahip public code search.<sup>[[13]](#references)</sup>

## Kullanışlı search yetenekleri

Bir org'u bug bounty/red team context'inde audit ederken genellikle en kullanışlı yetenekler şunlardır:

- **Regex** desteği; token format'larını, URL scheme'lerini, dangerous function name'lerini veya multiline fragment'leri aramak için.
- **Path filter'ları**; `.github/workflows/`, `terraform/`, `helm/`, `.env`, `values.yaml`, `secrets.*`, `credentials.*`, `Dockerfile`, `Jenkinsfile` veya `nginx.conf` gibi yüksek değerli file'lara doğrudan geçmek için.
- **Language filter'ları**; app code'u IaC ve pipeline'lardan ayırmak için.
- **Symbol-aware search**; handler'ları, auth middleware'lerini, webhook consumer'larını, dangerous helper function'larını veya belirli class/method'ları listelemek için.
- **Boolean operator'lar**; gürültüyü azaltmak için: `NOT path:test`, `NOT is:generated`, `NOT is:vendored`, `foo OR bar`.
- **Revision/diff search** mevcut olduğunda; **deleted string'leri** kurtarmak, **security-relevant change'leri** takip etmek veya her şeyi önce clone etmeden **non-default branch/tag'leri** incelemek için.

## Pratik methodology

1. Repo'ları, owner'ları, path'leri ve code family'lerini hızlıca belirlemek için **indexed platform'larla** başlayın.
2. Yalnızca genel `password`/`secret` string'lerini aramak yerine **yüksek sinyalli konumlara** pivot edin.
3. **Yalnızca credential'ları değil, attack surface'ü de arayın**:
- CI/CD workflow'ları, reusable workflow'lar, composite action'lar ve deployment script'leri
- Dev Containers / Codespaces bootstrap file'ları ve custom feature'lar
- Terraform/Helm/Kubernetes manifest'leri
- SSO/OIDC/SAML integration'ları
- Internal URL'ler, staging host'ları, admin panel'leri, message broker'lar ve callback endpoint'leri
- Dangerous code path'leri (`exec`, template rendering, SSRF fetcher'lar, deserializer'lar, ZIP extraction, YAML loader'lar vb.)
4. Non-default branch'lere, full history'ye, daha iyi regex desteğine veya bulk automation'a ihtiyaç duyduğunuzda local olarak clone edip search edin.
5. Amaç secrets triage veya verification olduğunda dedicated scanner'lara geçin (örneğin aşağıdaki dedicated page'e bakın).

### Yüksek sinyalli query fikirleri

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
### Öncelik vermeye değer daha yeni, yüksek sinyalli dosyalar

- **`.github/workflows/*.yml`**: Ayrıcalıklı `pull_request_target` ve `workflow_run` tetikleyicilerini ve tam commit SHA'leri yerine yalnızca tag/branch'lere sabitlenmiş üçüncü taraf `uses:` satırlarını inceleyin.<sup>[[3]](#references)</sup> Ayrıca `workflow_call`, `secrets: inherit`, `id-token: write` ve `runs-on: self-hosted` için arama yapın.
- **`.devcontainer/devcontainer.json`**, **`.devcontainer/<variant>/devcontainer.json`** ve **`.devcontainer.json`**: Ortam değerlerini, bootstrap komutlarını, mount'ları ve ilgili dosyaları keşfetmek için `remoteEnv`, `containerEnv`, `initializeCommand`, `postCreateCommand`, `mounts` ile referans verilen Dockerfile/script'leri arayın.<sup>[[4]](#references)</sup>
- **Dev Container Features** (`devcontainer-feature.json`, `install.sh`): Bir Feature'ın minimum düzeni metadata ve bir `install.sh` entrypoint script'i içerdiğinden her iki dosyayı da inceleyin.<sup>[[14]](#references)</sup>
- **Diğer CI/control-plane dosyaları**: `.gitlab-ci.yml`, `azure-pipelines.yml`, `cloudbuild.yaml`, `Jenkinsfile`, `buildkite*`, `atlantis.yaml`, `terragrunt.hcl`, `helmfile.yaml`, `skaffold.yaml`, `argocd*`.

### Indexed search yeterli olmadığında toplu yerel arama
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
Yerel aramayı şu durumlarda kullanın:

- **non-default branches** veya **tags** içinde arama yapmak
- **git history** araması yapmak
- Daha kapsamlı **PCRE2/multiline** sorguları çalıştırmak
- UI limitleri olmadan çok sayıda repository üzerinde toplu triage yapmak

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
Bu, özellikle ilginç string yalnızca bir **release branch**, **tag** veya **deleted commit** içinde mevcut olduğunda kullanışlıdır. Sourcegraph deployment'ınız destekliyorsa `type:diff` ve `type:commit` aramaları, aynı sorun için clone gerektirmeyen mükemmel bir pivot seçeneğidir.<sup>[[8]](#references)[[10]](#references)</sup>

## Common blind spots

- **Yalnızca default branch'in index'lenmesi** yaygındır. Code search'in tüm branch/tag/history kapsamını içerdiğini varsaymayın.
- **Büyük dosyalar, vendored code, generated code veya arşivler** atlanabilir ya da fazla gürültü oluşturabilir.
- **Yorumlar, issue'lar, PR'lar, gist'ler ve wiki'ler** çoğu zaman generic code search kapsamı dışındadır ve platforma özel tooling gerektirebilir.
- **Codespaces / devcontainer config'leri branch'e özel olabilir**. Birden fazla `.devcontainer/<variant>/devcontainer.json` path'inde bulunabilirler; bu nedenle temiz bir default branch, dev environment'ın her yerde temiz olduğu anlamına gelmez.<sup>[[4]](#references)</sup>
- **Reusable workflow/action'lar ve devcontainer feature'ları bariz dosyanın dışında bulunabilir**. Yalnızca üst düzey workflow dosyasında değil, `.github/actions/`, `action.yml`, `action.yaml`, `devcontainer-feature.json` ve `install.sh` içinde de arama yapın.
- **Search syntax platforma göre değişir**. GitHub Code Search'te çalışan bir dork, GitLab, Sourcegraph veya Sourcebot için küçük değişiklikler gerektirebilir.

### Platform-specific gotchas

- **GitHub Code Search**, hızlı recon için kullanışlıdır ancak yalnızca **default branch** içinde arama yapar. Feature branch'lere, silinmiş secret'lara veya historical code'a ihtiyacınız varsa repository'yi clone edin ve yerel olarak arayın.<sup>[[15]](#references)</sup>
- **GitLab Exact Code Search** için **default branch** sınırlaması vardır ve yalnızca 1 MB'tan küçük, 20.000'den az trigram içeren dosyaları index'ler.<sup>[[2]](#references)</sup> **Advanced Search** yine de comment'leri, commit'leri ve wiki'leri kapsayabilir.<sup>[[11]](#references)</sup>
- **Sourcebot**, varsayılan olarak **default branch**'i index'ler; ancak index'i kontrol ettiğinizde ek branch/tag'leri index'leyecek şekilde yapılandırılabilir ve ardından `rev:` filter'larıyla aranabilir.<sup>[[7]](#references)</sup>
- **Sourcegraph** regex, symbol, diff ve commit query'lerini destekler; structural search'i yalnızca etkin olduğu yerlerde kullanın ve belgelenen performans sınırlamalarını dikkate alın.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

> [!WARNING]
> Bir repo'da leak ararken `git log -p` gibi bir şey çalıştırdığınızda, secret içeren **başka commit'lere sahip başka branch'ler** olabileceğini unutmayın!

Dedicated secret hunting, org-wide GitHub dork'ları ve TruffleHog/Gitleaks gibi tooling için [GitHub leaked secrets sayfasına](github-leaked-secrets.md) bakın.

## References

- [1] [GitHub Code Search syntax](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [2] [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
- [3] [GitHub Actions güvenli kullanım referansı](https://docs.github.com/en/actions/reference/security/secure-use)
- [4] [Dev Container metadata referansı](https://containers.dev/implementors/json_reference/)
- [5] [Sourcebot](https://www.sourcebot.dev/)
- [6] [Sourcebot search API](https://docs.sourcebot.dev/api-reference/search-%26-navigation/search-code)
- [7] [Sourcebot multi-branch indexing](https://docs.sourcebot.dev/docs/features/search/multi-branch-indexing)
- [8] [Sourcegraph Code Search](https://sourcegraph.com/docs/code-search)
- [9] [Sourcegraph Structural Search](https://sourcegraph.com/docs/code-search/types/structural)
- [10] [Sourcegraph Search Query Syntax](https://sourcegraph.com/docs/code-search/queries)
- [11] [GitLab Advanced Search](https://docs.gitlab.com/user/search/advanced_search/)
- [12] [SearchCode](https://searchcode.com/)
- [13] [Grep.app](https://grep.app/)
- [14] [Dev Container Feature yazımı](https://containers.dev/guide/author-a-feature)
- [15] [Security incident'ları için investigation tooling'i](https://docs.github.com/en/enterprise-cloud%40latest/code-security/reference/security-incident-response/investigation-tools)
{{#include ../../banners/hacktricks-training.md}}
