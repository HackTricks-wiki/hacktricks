# Wide Source Code Search

इस पेज का लक्ष्य उन **platforms की सूची देना है जो code search करने की सुविधा देते हैं** (literal, regex, symbol-aware या path-scoped), और यह search **हजारों/लाखों repos** में की जा सकती है।

यह इनके लिए उपयोगी है:

- **leak हुई जानकारी को search करना**
- **vulnerable patterns को search करना**
- **technologies, internal hosts, CI/CD और infrastructure-as-code को map करना**
- **किसी company/org name से repos, branches और high-signal files तक pivot करना**

- [**Sourcebot**](https://www.sourcebot.dev/): Repositories में regex, symbol और filtered search के साथ open-source/self-hosted code search। अतिरिक्त branches/tags configure करें और branch coverage महत्वपूर्ण होने पर उन्हें `rev:` के साथ query करें।<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- [**Sourcegraph**](https://sourcegraph.com/search): regex, boolean, symbol, repository/file/language, branch/commit, diff और commit-message queries के साथ code search।<sup>[[8]](#references)[[10]](#references)</sup> Structural search optional है, क्योंकि current documentation के अनुसार यह default रूप से disabled है और performance-limited है।<sup>[[9]](#references)</sup>
- [**GitHub Code Search**](https://github.com/search): regex, boolean logic और `repo:`, `org:`, `user:`, `path:`, `language:`, `symbol:`, `content:` तथा `is:` जैसे qualifiers को support करता है।<sup>[[1]](#references)</sup>
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/): Zoekt द्वारा powered code search, जिसमें exact और regex modes तथा `file:`, `lang:`, `repo:` और `sym:` जैसे filters हैं।<sup>[[2]](#references)</sup>
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/) एक व्यापक fallback है, क्योंकि यह code, comments, commits, merge requests और wikis में search कर सकता है।<sup>[[11]](#references)</sup>
- [**SearchCode**](https://searchcode.com/): boolean/regex/structural code search के साथ file और symbol retrieval प्रदान करने वाली code-intelligence service।<sup>[[12]](#references)</sup>
- [**Grep**](https://grep.app/): दस लाख GitHub repositories में public code search, जिसमें content, file और path search शामिल हैं।<sup>[[13]](#references)</sup>

## Useful search capabilities

Bug bounty/red team context में किसी org का audit करते समय आमतौर पर सबसे उपयोगी capabilities ये होती हैं:

- **Regex** support, जिससे token formats, URL schemes, dangerous function names या multiline fragments को search किया जा सके।
- **Path filters**, जिससे `.github/workflows/`, `terraform/`, `helm/`, `.env`, `values.yaml`, `secrets.*`, `credentials.*`, `Dockerfile`, `Jenkinsfile` या `nginx.conf` जैसी high-value files तक सीधे पहुँचा जा सके।
- **Language filters**, ताकि app code को IaC और pipelines से अलग किया जा सके।
- **Symbol-aware search**, जिससे handlers, auth middleware, webhook consumers, dangerous helper functions या specific classes/methods की सूची बनाई जा सके।
- **Boolean operators**, noise कम करने के लिए: `NOT path:test`, `NOT is:generated`, `NOT is:vendored`, `foo OR bar`.
- **Revision/diff search**, जब उपलब्ध हो, ताकि आप **deleted strings** recover कर सकें, **security-relevant changes** को follow कर सकें या सब कुछ पहले clone किए बिना **non-default branches/tags** inspect कर सकें।

## Practical methodology

1. **Indexed platforms से शुरू करें**, ताकि repos, owners, paths और code families की जल्दी पहचान हो सके।
2. केवल generic `password`/`secret` strings को search करने के बजाय **high-signal locations पर pivot करें**।
3. **केवल credentials ही नहीं, attack surface को भी search करें**:
- CI/CD workflows, reusable workflows, composite actions और deployment scripts
- Dev Containers / Codespaces bootstrap files और custom features
- Terraform/Helm/Kubernetes manifests
- SSO/OIDC/SAML integrations
- Internal URLs, staging hosts, admin panels, message brokers और callback endpoints
- Dangerous code paths (`exec`, template rendering, SSRF fetchers, deserializers, ZIP extraction, YAML loaders आदि)
4. जब आपको non-default branches, full history, बेहतर regex support या bulk automation की आवश्यकता हो, तो **clone करके locally search करें**।
5. जब लक्ष्य secrets triage या verification हो, तो **dedicated scanners का उपयोग करें** (उदाहरण के लिए, नीचे दिया गया dedicated page देखें)।

### High-signal query ideas

ये जानबूझकर व्यापक रखे गए हैं, ताकि आप इन्हें GitHub, GitLab, Sourcegraph या Sourcebot syntax के अनुसार अनुकूलित कर सकें:
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

- **`.github/workflows/*.yml`**: privileged `pull_request_target` और `workflow_run` triggers की समीक्षा करें और उन third-party `uses:` lines को जाँचें जो full commit SHAs के बजाय केवल tags/branches पर pinned हैं।<sup>[[3]](#references)</sup> साथ ही `workflow_call`, `secrets: inherit`, `id-token: write`, और `runs-on: self-hosted` खोजें।
- **`.devcontainer/devcontainer.json`**, **`.devcontainer/<variant>/devcontainer.json`**, और **`.devcontainer.json`**: environment values, bootstrap commands, mounts और संबंधित files खोजने के लिए `remoteEnv`, `containerEnv`, `initializeCommand`, `postCreateCommand`, `mounts` तथा referenced Dockerfiles/scripts खोजें।<sup>[[4]](#references)</sup>
- **Dev Container Features** (`devcontainer-feature.json`, `install.sh`): दोनों files का निरीक्षण करें, क्योंकि किसी Feature के minimum layout में metadata और `install.sh` entrypoint script शामिल होते हैं।<sup>[[14]](#references)</sup>
- **अन्य CI/control-plane files**: `.gitlab-ci.yml`, `azure-pipelines.yml`, `cloudbuild.yaml`, `Jenkinsfile`, `buildkite*`, `atlantis.yaml`, `terragrunt.hcl`, `helmfile.yaml`, `skaffold.yaml`, `argocd*`.

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
जब आपको निम्नलिखित की आवश्यकता हो, तब local searching का उपयोग करें:

- **non-default branches** या **tags** में search करें
- **git history** में search करें
- **PCRE2/multiline** queries को अधिक आक्रामक रूप से चलाएँ
- UI limits के बिना कई repositories का batch triage करें

### History, branches और diffs को explicitly search करें
```bash
REPO_DIR=repos/some-repo
git -C "$REPO_DIR" fetch --all --tags --prune

git -C "$REPO_DIR" for-each-ref --format='%(refname:short)' refs/remotes/origin refs/tags \
| while read -r ref; do
git -C "$REPO_DIR" grep -nI -E 'pull_request_target|workflow_call|id-token: write|secrets: inherit|remoteEnv|containerEnv' "$ref" || true
done

git -C "$REPO_DIR" log --all -p -G 'gh[pousr]_|github_pat_|BEGIN [A-Z ]+PRIVATE KEY|internal.*https?://' -- .
```
यह विशेष रूप से तब उपयोगी होता है जब interesting string केवल किसी **release branch**, **tag**, या **deleted commit** में मौजूद थी। यदि आपका Sourcegraph deployment इसे support करता है, तो `type:diff` और `type:commit` searches इसी समस्या के लिए एक उत्कृष्ट no-clone pivot हैं।<sup>[[8]](#references)[[10]](#references)</sup>

## सामान्य blind spots

- **केवल default-branch indexing** आम है। यह न मानें कि code search सभी branches/tags/history को cover करता है।
- **Large files, vendored code, generated code, या archives** skip किए जा सकते हैं या noisy हो सकते हैं।
- **Comments, issues, PRs, gists, और wikis** अक्सर generic code search के scope से बाहर होते हैं और इनके लिए platform-specific tooling की आवश्यकता हो सकती है।
- **Codespaces / devcontainer configs branch-specific हो सकते हैं**। वे कई `.devcontainer/<variant>/devcontainer.json` paths में मौजूद हो सकते हैं, इसलिए clean default branch का अर्थ यह नहीं है कि dev environment हर जगह clean है।<sup>[[4]](#references)</sup>
- **Reusable workflows/actions और devcontainer features स्पष्ट file के बाहर मौजूद हो सकते हैं**। केवल top-level workflow file में नहीं, बल्कि `.github/actions/`, `action.yml`, `action.yaml`, `devcontainer-feature.json`, और `install.sh` में भी search करें।
- **Search syntax प्रत्येक platform पर अलग होती है**। GitHub Code Search में काम करने वाले dork को GitLab, Sourcegraph, या Sourcebot के लिए छोटे बदलावों की आवश्यकता हो सकती है।

### Platform-specific gotchas

- **GitHub Code Search** fast recon के लिए उपयोगी है, लेकिन यह केवल **default branch** को search करता है। यदि आपको feature branches, deleted secrets, या historical code की आवश्यकता है, तो repo को clone करके locally search करें।<sup>[[15]](#references)</sup>
- **GitLab Exact Code Search** में **default-branch** limitation है और यह केवल 1 MB से छोटी तथा 20,000 से कम trigrams वाली files को index करता है।<sup>[[2]](#references)</sup> **Advanced Search** फिर भी comments, commits, और wikis को cover कर सकता है।<sup>[[11]](#references)</sup>
- **Sourcebot** default रूप से **default branch** को index करता है, लेकिन इसे additional branches/tags को index करने के लिए configure किया जा सकता है और फिर index को control करने पर `rev:` filters के साथ search किया जा सकता है।<sup>[[7]](#references)</sup>
- **Sourcegraph** regex, symbol, diff, और commit queries को support करता है; structural search का उपयोग केवल वहीं करें जहाँ यह enabled हो और इसकी documented performance limits को ध्यान में रखें।<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

> [!WARNING]
> जब आप किसी repo में leaks खोजते हैं और `git log -p` जैसा कुछ run करते हैं, तो यह न भूलें कि **अन्य branches में secrets वाले अन्य commits हो सकते हैं**!

Dedicated secret hunting, org-wide GitHub dorks, और TruffleHog/Gitleaks जैसे tooling के लिए [GitHub leaked secrets page](github-leaked-secrets.md) देखें।

## References

- [1] [GitHub Code Search syntax](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [2] [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
- [3] [GitHub Actions secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [4] [Dev Container metadata reference](https://containers.dev/implementors/json_reference/)
- [5] [Sourcebot](https://www.sourcebot.dev/)
- [6] [Sourcebot search API](https://docs.sourcebot.dev/api-reference/search-%26-navigation/search-code)
- [7] [Sourcebot multi-branch indexing](https://docs.sourcebot.dev/docs/features/search/multi-branch-indexing)
- [8] [Sourcegraph Code Search](https://sourcegraph.com/docs/code-search)
- [9] [Sourcegraph Structural Search](https://sourcegraph.com/docs/code-search/types/structural)
- [10] [Sourcegraph Search Query Syntax](https://sourcegraph.com/docs/code-search/queries)
- [11] [GitLab Advanced Search](https://docs.gitlab.com/user/search/advanced_search/)
- [12] [SearchCode](https://searchcode.com/)
- [13] [Grep.app](https://grep.app/)
- [14] [Authoring a Dev Container Feature](https://containers.dev/guide/author-a-feature)
- [15] [Investigation tools for security incidents](https://docs.github.com/en/enterprise-cloud%40latest/code-security/reference/security-incident-response/investigation-tools)
{{#include ../../banners/hacktricks-training.md}}
