# Wide Source Code Search

{{#include ../../banners/hacktricks-training.md}}

इस पेज का लक्ष्य उन **platforms की सूची बनाना** है जो **हजारों/लाखों repos** में code को **search** करने की सुविधा देते हैं (literal, regex, symbol-aware, या path-scoped)।

यह इनके लिए उपयोगी है:

- **leaked information को search करना**
- **vulnerable patterns को search करना**
- **technologies, internal hosts, CI/CD, और infrastructure-as-code को map करना**
- **company/org name से repos, branches, और high-signal files तक pivot करना**

- [**Sourcebot**](https://www.sourcebot.dev/): Open-source/self-hosted code search। जब आप **कई repos** को index करना चाहते हैं और, यदि configure किया गया हो, तो अतिरिक्त branches/tags को भी index करना चाहते हैं, तब यह बहुत उपयोगी है। साथ ही `repo:`, `file:`, `lang:`, `rev:` और `sym:` जैसे regex filters बनाए रखता है।
- [**SourceGraph**](https://sourcegraph.com/search): लाखों repos में search करें। Regex आमतौर पर सबसे सुरक्षित विकल्प है; कुछ deployments में structural search उपलब्ध है, लेकिन इसकी performance limitations हैं और यह हमेशा enabled नहीं होता।
- [**GitHub Code Search**](https://github.com/search): regex, boolean logic और `repo:`, `org:`, `user:`, `path:`, `language:`, `symbol:`, `content:` और `is:` जैसे qualifiers को support करता है।
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/): Zoekt द्वारा powered आधुनिक GitLab code search। `file:`, `lang:`, `repo:` और `sym:` जैसे filters के साथ exact और regex modes को support करता है।
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/) अभी भी एक व्यापक fallback के रूप में उपयोगी है, क्योंकि यह code, comments, commits, merge requests और wikis में search कर सकता है।
- [**SearchCode**](https://searchcode.com/): लाखों projects में code search करें।
- [**Grep**](https://grep.app/): बहुत बड़े GitHub corpus में तेज public search। जब आप **content**, **file** और **path** pivots के लिए दूसरा indexing/ranking view चाहते हैं, तब उपयोगी है।

## Useful search capabilities

Bug bounty/red team context में किसी org का audit करते समय, आमतौर पर सबसे उपयोगी capabilities ये होती हैं:

- **Regex** support, ताकि token formats, URL schemes, dangerous function names या multiline fragments को search किया जा सके।
- **Path filters**, ताकि सीधे `.github/workflows/`, `terraform/`, `helm/`, `.env`, `values.yaml`, `secrets.*`, `credentials.*`, `Dockerfile`, `Jenkinsfile` या `nginx.conf` जैसी high-value files तक पहुंचा जा सके।
- **Language filters**, ताकि app code को IaC और pipelines से अलग किया जा सके।
- **Symbol-aware search**, ताकि handlers, auth middleware, webhook consumers, dangerous helper functions या specific classes/methods की सूची बनाई जा सके।
- **Boolean operators**, ताकि noise कम किया जा सके: `NOT path:test`, `NOT is:generated`, `NOT is:vendored`, `foo OR bar`।
- **Revision/diff search**, जब उपलब्ध हो, ताकि आप **deleted strings** recover कर सकें, **security-relevant changes** को follow कर सकें, या सब कुछ पहले clone किए बिना **non-default branches/tags** inspect कर सकें।

## Practical methodology

1. **Indexed platforms से शुरू करें**, ताकि repos, owners, paths और code families की जल्दी पहचान की जा सके।
2. केवल generic `password`/`secret` strings को search करने के बजाय **high-signal locations पर pivot करें**।
3. **केवल credentials नहीं, attack surface को भी search करें**:
- CI/CD workflows, reusable workflows, composite actions और deployment scripts
- Dev Containers / Codespaces bootstrap files और custom features
- Terraform/Helm/Kubernetes manifests
- SSO/OIDC/SAML integrations
- Internal URLs, staging hosts, admin panels, message brokers और callback endpoints
- Dangerous code paths (`exec`, template rendering, SSRF fetchers, deserializers, ZIP extraction, YAML loaders, आदि)
4. जब आपको non-default branches, full history, बेहतर regex support या bulk automation की आवश्यकता हो, तब **locally clone और search करें**।
5. जब लक्ष्य secrets triage या verification हो, तब **dedicated scanners का उपयोग करें** (उदाहरण के लिए, नीचे दिया गया dedicated page देखें)।

### High-signal query ideas

ये जानबूझकर व्यापक रखे गए हैं, ताकि आप उन्हें GitHub, GitLab, Sourcegraph या Sourcebot syntax के अनुसार adapt कर सकें:
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
### प्राथमिकता देने योग्य नए high-signal files

- **`.github/workflows/*.yml`**: `pull_request_target`, `workflow_run`, `workflow_call`, `secrets: inherit`, `id-token: write`, `runs-on: self-hosted`, और ऐसे third-party `uses:` lines खोजें जो full commit SHAs के बजाय केवल tags/branches पर pinned हों।
- **`.devcontainer/devcontainer.json`**, **`.devcontainer/<variant>/devcontainer.json`**, और **`.devcontainer.json`**: `remoteEnv`, `containerEnv`, `initializeCommand`, `postCreateCommand`, `mounts`, और referenced Dockerfiles/scripts खोजें। ये अक्सर internal package registries, bootstrap URLs, host mounts और केवल developers के लिए उपलब्ध endpoints उजागर करते हैं।
- **Dev Container Features** (`devcontainer-feature.json`, `install.sh`): environment creation के दौरान execute होने वाली org-specific installer logic खोजने के लिए उपयोगी हैं।
- **अन्य CI/control-plane files**: `.gitlab-ci.yml`, `azure-pipelines.yml`, `cloudbuild.yaml`, `Jenkinsfile`, `buildkite*`, `atlantis.yaml`, `terragrunt.hcl`, `helmfile.yaml`, `skaffold.yaml`, `argocd*`।

### जब indexed search पर्याप्त न हो, तब बड़े पैमाने पर local search
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
जब आपको निम्न कार्य करने हों, तब local searching का उपयोग करें:

- **non-default branches** या **tags** में search करें
- **git history** में search करें
- **PCRE2/multiline** queries को अधिक आक्रामक रूप से चलाएँ
- UI limits के बिना कई repositories का batch triage करें

### history, branches और diffs को स्पष्ट रूप से search करें
```bash
REPO_DIR=repos/some-repo
git -C "$REPO_DIR" fetch --all --tags --prune

git -C "$REPO_DIR" for-each-ref --format='%(refname:short)' refs/remotes/origin refs/tags \
| while read -r ref; do
git -C "$REPO_DIR" grep -nI -E 'pull_request_target|workflow_call|id-token: write|secrets: inherit|remoteEnv|containerEnv' "$ref" || true
done

git -C "$REPO_DIR" log --all -p -G 'gh[pousr]_|github_pat_|BEGIN [A-Z ]+PRIVATE KEY|internal.*https?://' -- .
```
यह विशेष रूप से तब उपयोगी है जब interesting string केवल **release branch**, **tag**, या **deleted commit** में मौजूद हो। यदि आपका Sourcegraph deployment इसे support करता है, तो `type:diff` और `type:commit` searches इसी समस्या के लिए एक excellent no-clone pivot हैं।

## सामान्य blind spots

- **Default-branch-only indexing** सामान्य है। यह न मानें कि code search सभी branches/tags/history को cover करता है।
- **Large files, vendored code, generated code, या archives** को skip किया जा सकता है या वे noisy हो सकते हैं।
- **Comments, issues, PRs, gists, और wikis** अक्सर generic code search के scope से बाहर होते हैं और इनके लिए platform-specific tooling की आवश्यकता हो सकती है।
- **Codespaces / devcontainer configs branch-specific हो सकते हैं** और कई `.devcontainer/<variant>/devcontainer.json` paths में मौजूद हो सकते हैं, इसलिए clean default branch का अर्थ यह नहीं है कि dev environment हर जगह clean है।
- **Reusable workflows/actions और devcontainer features obvious file के बाहर हो सकते हैं**। केवल top-level workflow file में नहीं, बल्कि `.github/actions/`, `action.yml`, `action.yaml`, `devcontainer-feature.json`, और `install.sh` में भी search करें।
- **Search syntax प्रत्येक platform पर अलग होती है**। GitHub Code Search पर काम करने वाले dork में GitLab, Sourcegraph, या Sourcebot के लिए छोटे बदलाव आवश्यक हो सकते हैं।

### Platform-specific gotchas

- **GitHub Code Search** fast recon के लिए excellent है, लेकिन यह केवल **default branch** को search करता है। यदि आपको feature branches, deleted secrets, या historical code की आवश्यकता है, तो repo को clone करके locally search करें।
- **GitLab Exact Code Search** में भी **default-branch** limitation है और यह केवल छोटी files को index करता है, लेकिन **Advanced Search** comments, commits, और wikis को search करने के लिए उपयोगी हो सकता है।
- **Sourcebot** default रूप से **default branch** को index करता है, लेकिन इसे additional branches/tags को index करने के लिए configure किया जा सकता है और फिर `rev:` filters के साथ search किया जा सकता है। जब आप index control करते हैं, तो branch/tag-focused internal audits के लिए यह बहुत convenient है।
- **Sourcegraph** regex search आम तौर पर offensive work के लिए सबसे predictable option है; structural search को optional bonus मानें, guaranteed capability नहीं। यदि deployment इसे support करता है, तो `type:diff` और `type:commit` queries deleted strings या हाल के security-relevant changes को recover करने के लिए बहुत अच्छी हैं।

> [!WARNING]
> जब आप किसी repo में leaks खोजते हैं और `git log -p` जैसा कुछ run करते हैं, तो यह न भूलें कि **अन्य branches में secrets वाले अन्य commits हो सकते हैं**!

Dedicated secret hunting, org-wide GitHub dorks, और TruffleHog/Gitleaks जैसे tooling के लिए देखें:

{{#ref}}
github-leaked-secrets.md
{{#endref}}



## References

- [GitHub Code Search syntax](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
- [GitHub Actions secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [Dev Container metadata reference](https://containers.dev/implementors/json_reference/)
{{#include ../../banners/hacktricks-training.md}}
