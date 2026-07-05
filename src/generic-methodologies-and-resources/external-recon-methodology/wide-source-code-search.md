# Wide Source Code Search

{{#include ../../banners/hacktricks-training.md}}

Die doel van hierdie bladsy is om **platforms te lys wat jou toelaat om kode te soek** (letterlik, regex, simbool-bewus, of pad-geskaleer) oor **duisende/miljoene repos**.

Dit is nuttig om:

- **Soek vir gelekte inligting**
- **Soek vir kwesbare patrone**
- **Kaart tegnologieë, interne hosts, CI/CD, en infrastructure-as-code**
- **Pivot vanaf 'n company/org naam na repos, branches, en hoë-sein lêers**

- [**Sourcebot**](https://www.sourcebot.dev/): Open-source/self-hosted kode soek. Baie nuttig wanneer jy **baie repos** wil indekseer en, indien gekonfigureer, bykomende branches/tags, terwyl regex filters soos `repo:`, `file:`, `lang:`, `rev:` en `sym:` behou word.
- [**SourceGraph**](https://sourcegraph.com/search): Soek in miljoene repos. Regex is gewoonlik die veiligste opsie; structural search bestaan in sommige ontplooiings, maar dit het prestasiebeperkings en is nie altyd geaktiveer nie.
- [**GitHub Code Search**](https://github.com/search): Ondersteun regex, boolean logic, en qualifiers soos `repo:`, `org:`, `user:`, `path:`, `language:`, `symbol:`, `content:` en `is:`.
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/): Moderne GitLab kode soek aangedryf deur Zoekt. Ondersteun exact en regex modusse met filters soos `file:`, `lang:`, `repo:` en `sym:`.
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/) is steeds nuttig as 'n wyer fallback omdat dit code, comments, commits, merge requests, en wikis kan soek.
- [**SearchCode**](https://searchcode.com/): Soek kode in miljoene projekte.

## Useful search capabilities

Wanneer jy 'n org in 'n bug bounty/red team konteks audit, is die nuttigste capabilities gewoonlik:

- **Regex** ondersteuning om vir token formate, URL schemes, gevaarlike function name, of multiline fragmente te soek.
- **Path filters** om direk na hoë-waarde lêers te spring soos `.github/workflows/`, `terraform/`, `helm/`, `.env`, `values.yaml`, `secrets.*`, `credentials.*`, `Dockerfile`, `Jenkinsfile`, of `nginx.conf`.
- **Language filters** om app code van IaC en pipelines te skei.
- **Symbol-aware search** om handlers, auth middleware, webhook consumers, gevaarlike helper functions, of spesifieke classes/methods te lys.
- **Boolean operators** om geraas te verminder: `NOT path:test`, `NOT is:generated`, `NOT is:vendored`, `foo OR bar`.

## Practical methodology

1. **Begin met die geïndekseerde platforms** om vinnig repos, owners, paths, en code families te identifiseer.
2. **Pivot na hoë-sein liggings** in plaas daarvan om net vir generiese `password`/`secret` stringe te soek.
3. **Soek vir attack surface, nie net credentials nie**:
- CI/CD workflows en deployment scripts
- Terraform/Helm/Kubernetes manifests
- SSO/OIDC/SAML integrations
- Interne URLs, staging hosts, admin panels, message brokers, en callback endpoints
- Gevaarlike code paths (`exec`, template rendering, SSRF fetchers, deserializers, ZIP extraction, YAML loaders, etc.)
4. **Clone en soek plaaslik** wanneer jy nie-default branches, volle history, beter regex ondersteuning, of bulk automation nodig het.
5. **Escalate na dedicated scanners** wanneer die doel secrets triage of verification is (byvoorbeeld, sien die dedicated bladsy hieronder).

### High-signal query ideas

Hierdie is doelbewus breed sodat jy hulle kan aanpas vir GitHub, GitLab, Sourcegraph, of Sourcebot syntax:
```text
org:target path:.github/workflows ("pull_request_target" OR "workflow_run" OR "ACTIONS_STEP_DEBUG")
org:target (path:terraform OR path:helm OR language:HCL OR language:YAML) ("role_arn" OR "assume_role" OR "client_secret" OR "access_key")
org:target ("BEGIN PRIVATE KEY" OR "ghp_" OR "github_pat_" OR "AIza" OR "xoxb-")
org:target (path:.env OR path:values.yaml OR path:application-prod OR path:credentials)
org:target ("internal" OR "corp" OR "staging") ("https://" OR "ssh://") NOT path:test
```
### Mass plaaslike soektog wanneer geïndekseerde soektog nie genoeg is nie
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
Gebruik plaaslike soektog wanneer jy dit nodig het om:

- **Nie-standaard branches** of **tags** te soek
- **git history** te soek
- **PCRE2/multiline** queries meer aggressief uit te voer
- Baie repositories in bondel te triage sonder UI-limiete

## Algemene blindekolle

- **Default-branch-only indexing** is algemeen. Moenie aanvaar code search dek alle branches/tags/history nie.
- **Groot files, vendored code, generated code, of archives** kan oorgeslaan word of geraas veroorsaak.
- **Comments, issues, PRs, gists, en wikis** is dikwels buite die omvang van generiese code search en kan platform-spesifieke tools vereis.
- **Search syntax verskil per platform**. ’n dork wat in GitHub Code Search werk, mag klein aanpassings nodig hê vir GitLab, Sourcegraph, of Sourcebot.

### Platform-spesifieke slaggate

- **GitHub Code Search** is uitstekend vir vinnige recon, maar dit soek slegs die **default branch**. As jy feature branches, verwyderde secrets, of historiese code nodig het, kloon die repo en soek dit plaaslik.
- **GitLab Exact Code Search** het ook ’n **default-branch** beperking en indekseer slegs kleiner files, maar **Advanced Search** kan steeds nuttig wees om comments, commits, en wikis te soek.
- **Sourcebot** indekseer by verstek die **default branch**, maar dit kan gekonfigureer word om bykomende branches/tags te indekseer en dan met `rev:` filters gesoek te word, wat baie gerieflik is vir branch/tag-gefokusde interne audits wanneer jy die index beheer.
- **Sourcegraph** regex search is oor die algemeen die mees voorspelbare opsie vir offensive work; beskou structural search as ’n opsionele bonus, nie as ’n gewaarborgde vermoë nie.

> [!WARNING]
> Wanneer jy na leaks in ’n repo soek en iets soos `git log -p` uitvoer, moet jy nie vergeet daar kan **ander branches met ander commits** wees wat secrets bevat nie!

Vir toegewyde secret hunting, org-wide GitHub dorks, en tooling soos TruffleHog/Gitleaks, kyk:

{{#ref}}
github-leaked-secrets.md
{{#endref}}



## Verwysings

- [GitHub Code Search syntax](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
{{#include ../../banners/hacktricks-training.md}}
