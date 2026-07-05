# Utafutaji Mpana wa Msimbo wa Chanzo

{{#include ../../banners/hacktricks-training.md}}

Lengo la ukurasa huu ni kuorodhesha **mifumo inayokuruhusu kutafuta code** (literal, regex, symbol-aware, au path-scoped) kwenye **mamilioni/maelfu ya repos**.

Hii ni muhimu kwa:

- **Kutafuta taarifa zilizovuja**
- **Kutafuta mifumo iliyo hatarishi**
- **Kuchora technologies, internal hosts, CI/CD, na infrastructure-as-code**
- **Kusogea kutoka jina la company/org kwenda kwenye repos, branches, na faili zenye ishara ya juu**

- [**Sourcebot**](https://www.sourcebot.dev/): Open-source/self-hosted code search. Ni muhimu sana unapotaka ku-index **repos nyingi** na, ikiwa imewekewa, branches/tags za ziada huku ukiweka filters za regex kama `repo:`, `file:`, `lang:`, `rev:` na `sym:`.
- [**SourceGraph**](https://sourcegraph.com/search): Tafuta kwenye mamilioni ya repos. Regex kwa kawaida ndiyo chaguo salama zaidi; structural search ipo kwenye baadhi ya deployments, lakini ina vikwazo vya performance na si mara zote imewezeshwa.
- [**GitHub Code Search**](https://github.com/search): Inaauni regex, boolean logic, na qualifiers kama `repo:`, `org:`, `user:`, `path:`, `language:`, `symbol:`, `content:` na `is:`.
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/): Modern GitLab code search inayotumia Zoekt. Inaunga mkono exact na regex modes pamoja na filters kama `file:`, `lang:`, `repo:` na `sym:`.
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/) bado ni muhimu kama fallback ya pana kwa sababu inaweza kutafuta code, comments, commits, merge requests, na wikis.
- [**SearchCode**](https://searchcode.com/): Tafuta code kwenye mamilioni ya projects.

## Uwezo muhimu wa kutafuta

Unapofanya auditing ya org katika muktadha wa bug bounty/red team, uwezo muhimu zaidi kwa kawaida ni:

- **Regex** support kutafuta token formats, URL schemes, majina ya function hatarishi, au vipande vya multiline.
- **Path filters** kuruka moja kwa moja hadi kwenye faili zenye thamani kubwa kama `.github/workflows/`, `terraform/`, `helm/`, `.env`, `values.yaml`, `secrets.*`, `credentials.*`, `Dockerfile`, `Jenkinsfile`, au `nginx.conf`.
- **Language filters** kutenganisha app code na IaC na pipelines.
- **Symbol-aware search** kuorodhesha handlers, auth middleware, webhook consumers, dangerous helper functions, au classes/methods maalum.
- **Boolean operators** kupunguza noise: `NOT path:test`, `NOT is:generated`, `NOT is:vendored`, `foo OR bar`.

## Mbinu ya vitendo

1. **Anza na platforms zilizo-indexiwa** ili kutambua haraka repos, owners, paths, na code families.
2. **Sogea hadi maeneo yenye ishara ya juu** badala ya kutafuta tu strings za jumla kama `password`/`secret`.
3. **Tafuta attack surface, si credentials pekee**:
- CI/CD workflows na deployment scripts
- Terraform/Helm/Kubernetes manifests
- SSO/OIDC/SAML integrations
- Internal URLs, staging hosts, admin panels, message brokers, na callback endpoints
- Dangerous code paths (`exec`, template rendering, SSRF fetchers, deserializers, ZIP extraction, YAML loaders, etc.)
4. **Clone na tafuta locally** unapohitaji non-default branches, full history, support bora ya regex, au bulk automation.
5. **Panda hadi dedicated scanners** wakati lengo ni secrets triage au verification (kwa mfano, angalia page maalum hapa chini).

### High-signal query ideas

Hizi zimekusudiwa kuwa pana ili uweze kuzibadilisha kwa syntax ya GitHub, GitLab, Sourcegraph, au Sourcebot:
```text
org:target path:.github/workflows ("pull_request_target" OR "workflow_run" OR "ACTIONS_STEP_DEBUG")
org:target (path:terraform OR path:helm OR language:HCL OR language:YAML) ("role_arn" OR "assume_role" OR "client_secret" OR "access_key")
org:target ("BEGIN PRIVATE KEY" OR "ghp_" OR "github_pat_" OR "AIza" OR "xoxb-")
org:target (path:.env OR path:values.yaml OR path:application-prod OR path:credentials)
org:target ("internal" OR "corp" OR "staging") ("https://" OR "ssh://") NOT path:test
```
### Utafutaji mkubwa wa ndani wakati indexed search haitoshi
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
Tumia local searching unapohitaji:

- Kutafuta **non-default branches** au **tags**
- Kutafuta **git history**
- Kuendesha hoja za **PCRE2/multiline** kwa nguvu zaidi
- Kufanya batch triage ya repositories nyingi bila UI limits

## Common blind spots

- **Default-branch-only indexing** ni ya kawaida. Usidhani code search inashughulikia branches/tags/history zote.
- **Large files, vendored code, generated code, au archives** vinaweza kurukwa au kuwa noisy.
- **Comments, issues, PRs, gists, na wikis** mara nyingi ziko nje ya wigo wa generic code search na huenda zikahitaji platform-specific tooling.
- **Search syntax hutofautiana per platform**. Dork inayofanya kazi katika GitHub Code Search inaweza kuhitaji mabadiliko madogo kwa GitLab, Sourcegraph, au Sourcebot.

### Platform-specific gotchas

- **GitHub Code Search** ni bora kwa fast recon, lakini hutafuta **default branch** pekee. Ikiwa unahitaji feature branches, deleted secrets, au historical code, clone repo na itafute locally.
- **GitLab Exact Code Search** pia ina limitation ya **default-branch** na hu-index files ndogo tu, lakini **Advanced Search** bado inaweza kuwa muhimu kutafuta comments, commits, na wikis.
- **Sourcebot** hu-index **default branch** kwa default, lakini inaweza kusanidiwa ku-index branches/tags za ziada na kisha kutafutwa kwa `rev:` filters, jambo ambalo ni rahisi sana kwa branch/tag-focused internal audits unapodhibiti index.
- **Sourcegraph** regex search kwa ujumla ndilo chaguo linalotabirika zaidi kwa offensive work; chukulia structural search kama bonus ya hiari, si uwezo wa uhakika.

> [!WARNING]
> Unapotafuta leaks katika repo na kuendesha kitu kama `git log -p` usisahau kunaweza kuwa na **other branches with other commits** zilizo na secrets!

Kwa dedicated secret hunting, org-wide GitHub dorks, na tooling kama TruffleHog/Gitleaks, angalia:

{{#ref}}
github-leaked-secrets.md
{{#endref}}



## References

- [GitHub Code Search syntax](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
{{#include ../../banners/hacktricks-training.md}}
