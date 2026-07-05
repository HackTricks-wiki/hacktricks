# Wide Source Code Search

{{#include ../../banners/hacktricks-training.md}}

इस पेज का लक्ष्य उन **platforms** को enumerate करना है जो आपको **thousands/millions of repos** में code search करने देती हैं (literal, regex, symbol-aware, या path-scoped)।

यह उपयोगी है:

- **leaked information** खोजने के लिए
- **vulnerable patterns** खोजने के लिए
- technologies, internal hosts, CI/CD, और infrastructure-as-code को map करने के लिए
- किसी company/org name से repos, branches, और high-signal files तक pivot करने के लिए

- [**Sourcebot**](https://www.sourcebot.dev/): Open-source/self-hosted code search. जब आप **many repos** index करना चाहते हों और, अगर configured हो, अतिरिक्त branches/tags भी, साथ ही `repo:`, `file:`, `lang:`, `rev:` और `sym:` जैसे regex filters बनाए रखना चाहते हों, तब यह बहुत उपयोगी है।
- [**SourceGraph**](https://sourcegraph.com/search): लाखों repos में search. Regex आमतौर पर सबसे सुरक्षित option है; कुछ deployments में structural search मौजूद है, लेकिन उसकी performance सीमाएँ होती हैं और वह हमेशा enabled नहीं होती।
- [**GitHub Code Search**](https://github.com/search): regex, boolean logic, और `repo:`, `org:`, `user:`, `path:`, `language:`, `symbol:`, `content:` और `is:` जैसे qualifiers support करता है।
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/): Zoekt द्वारा powered modern GitLab code search. `file:`, `lang:`, `repo:` और `sym:` जैसे filters के साथ exact और regex modes support करता है।
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/) अभी भी wider fallback के रूप में उपयोगी है क्योंकि यह code, comments, commits, merge requests, और wikis search कर सकता है।
- [**SearchCode**](https://searchcode.com/): millions of projects में code search।

## Useful search capabilities

जब bug bounty/red team context में किसी org का audit कर रहे हों, तब सबसे उपयोगी capabilities आमतौर पर ये होती हैं:

- token formats, URL schemes, dangerous function names, या multiline fragments search करने के लिए **Regex** support।
- `.github/workflows/`, `terraform/`, `helm/`, `.env`, `values.yaml`, `secrets.*`, `credentials.*`, `Dockerfile`, `Jenkinsfile`, या `nginx.conf` जैसी high-value files में सीधे जाने के लिए **Path filters**।
- app code को IaC और pipelines से अलग करने के लिए **Language filters**।
- handlers, auth middleware, webhook consumers, dangerous helper functions, या specific classes/methods enumerate करने के लिए **Symbol-aware search**।
- noise कम करने के लिए **Boolean operators**: `NOT path:test`, `NOT is:generated`, `NOT is:vendored`, `foo OR bar`।

## Practical methodology

1. जल्दी से repos, owners, paths, और code families identify करने के लिए indexed platforms से **Start** करें।
2. केवल generic `password`/`secret` strings खोजने के बजाय **high-signal locations में pivot** करें।
3. केवल credentials नहीं, बल्कि **attack surface** खोजें:
- CI/CD workflows और deployment scripts
- Terraform/Helm/Kubernetes manifests
- SSO/OIDC/SAML integrations
- Internal URLs, staging hosts, admin panels, message brokers, और callback endpoints
- Dangerous code paths (`exec`, template rendering, SSRF fetchers, deserializers, ZIP extraction, YAML loaders, etc.)
4. जब आपको non-default branches, full history, बेहतर regex support, या bulk automation चाहिए हो, तब **Clone and search locally** करें।
5. जब लक्ष्य secrets triage या verification हो, तब dedicated scanners पर **Escalate** करें (उदाहरण के लिए, नीचे दिए गए dedicated page को देखें)।

### High-signal query ideas

ये intentionally broad हैं ताकि आप इन्हें GitHub, GitLab, Sourcegraph, या Sourcebot syntax के अनुसार adapt कर सकें:
```text
org:target path:.github/workflows ("pull_request_target" OR "workflow_run" OR "ACTIONS_STEP_DEBUG")
org:target (path:terraform OR path:helm OR language:HCL OR language:YAML) ("role_arn" OR "assume_role" OR "client_secret" OR "access_key")
org:target ("BEGIN PRIVATE KEY" OR "ghp_" OR "github_pat_" OR "AIza" OR "xoxb-")
org:target (path:.env OR path:values.yaml OR path:application-prod OR path:credentials)
org:target ("internal" OR "corp" OR "staging") ("https://" OR "ssh://") NOT path:test
```
### जब indexed search पर्याप्त न हो तब Mass local search
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
Use local searching when you need to:

- Search **non-default branches** or **tags**
- Search **git history**
- Run **PCRE2/multiline** queries more aggressively
- Batch triage many repositories without UI limits

## Common blind spots

- **Default-branch-only indexing** is common. Do not assume code search covers all branches/tags/history.
- **Large files, vendored code, generated code, or archives** may be skipped or noisy.
- **Comments, issues, PRs, gists, and wikis** are often outside the scope of generic code search and may require platform-specific tooling.
- **Search syntax differs per platform**. A dork that works in GitHub Code Search might need small changes for GitLab, Sourcegraph, or Sourcebot.

### Platform-specific gotchas

- **GitHub Code Search** is excellent for fast recon, but it searches the **default branch** only. If you need feature branches, deleted secrets, or historical code, clone the repo and search it locally.
- **GitLab Exact Code Search** also has a **default-branch** limitation and indexes only smaller files, but **Advanced Search** can still be useful to search comments, commits, and wikis.
- **Sourcebot** indexes the **default branch** by default, but it can be configured to index additional branches/tags and then searched with `rev:` filters, which is very convenient for branch/tag-focused internal audits when you control the index.
- **Sourcegraph** regex search is generally the most predictable option for offensive work; treat structural search as an optional bonus, not as a guaranteed capability.

> [!WARNING]
> जब आप किसी repo में leaks खोजते हैं और `git log -p` जैसा कुछ चलाते हैं, तो यह मत भूलिए कि **अन्य branches में अन्य commits** भी हो सकते हैं जिनमें secrets हों!

For dedicated secret hunting, org-wide GitHub dorks, and tooling such as TruffleHog/Gitleaks, check:

{{#ref}}
github-leaked-secrets.md
{{#endref}}



## References

- [GitHub Code Search syntax](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
{{#include ../../banners/hacktricks-training.md}}
