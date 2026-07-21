# Utafutaji Mpana wa Source Code

{{#include ../../banners/hacktricks-training.md}}

Lengo la ukurasa huu ni kuorodhesha **platforms zinazoruhusu kutafuta code** (literal, regex, symbol-aware, au path-scoped) katika **maelfu/mamilioni ya repos**.

Hii ni muhimu kwa:

- **Kutafuta taarifa zilizovuja**
- **Kutafuta vulnerable patterns**
- **Kuchora ramani ya technologies, internal hosts, CI/CD, na infrastructure-as-code**
- **Kufanya pivot kutoka jina la kampuni/org kwenda kwenye repos, branches, na high-signal files**

- [**Sourcebot**](https://www.sourcebot.dev/): Open-source/self-hosted code search. Ni muhimu sana unapotaka ku-index **repos nyingi** na, ikiwa imesanidiwa, branches/tags za ziada huku ukiendelea kutumia regex filters kama `repo:`, `file:`, `lang:`, `rev:` na `sym:`.
- [**SourceGraph**](https://sourcegraph.com/search): Hutafuta katika mamilioni ya repos. Regex kwa kawaida ndiyo chaguo salama zaidi; structural search inapatikana katika baadhi ya deployments, lakini ina vikwazo vya performance na huwa haijawezeshwa kila wakati.
- [**GitHub Code Search**](https://github.com/search): Inasaidia regex, boolean logic, na qualifiers kama `repo:`, `org:`, `user:`, `path:`, `language:`, `symbol:`, `content:` na `is:`.
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/): GitLab code search ya kisasa inayotumia Zoekt. Inasaidia exact na regex modes pamoja na filters kama `file:`, `lang:`, `repo:` na `sym:`.
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/) bado ni muhimu kama fallback pana zaidi kwa sababu inaweza kutafuta code, comments, commits, merge requests, na wikis.
- [**SearchCode**](https://searchcode.com/): Hutafuta code katika mamilioni ya projects.
- [**Grep**](https://grep.app/): Public search ya haraka katika GitHub corpus kubwa sana. Ni muhimu unapotaka indexing/ranking view ya pili kwa ajili ya pivots za **content**, **file**, na **path**.

## Uwezo muhimu wa search

Unapokagua org katika muktadha wa bug bounty/red team, uwezo muhimu zaidi kwa kawaida ni:

- **Regex** support ya kutafuta token formats, URL schemes, dangerous function names, au multiline fragments.
- **Path filters** za kwenda moja kwa moja kwenye high-value files kama `.github/workflows/`, `terraform/`, `helm/`, `.env`, `values.yaml`, `secrets.*`, `credentials.*`, `Dockerfile`, `Jenkinsfile`, au `nginx.conf`.
- **Language filters** za kutenganisha app code na IaC pamoja na pipelines.
- **Symbol-aware search** ya kuorodhesha handlers, auth middleware, webhook consumers, dangerous helper functions, au classes/methods mahususi.
- **Boolean operators** za kupunguza noise: `NOT path:test`, `NOT is:generated`, `NOT is:vendored`, `foo OR bar`.
- **Revision/diff search** inapopatikana, ili uweze kurejesha **deleted strings**, kufuatilia **security-relevant changes**, au kukagua **non-default branches/tags** bila ku-clone kila kitu kwanza.

## Methodology ya vitendo

1. **Anza na platforms zilizo-indexiwa** ili kutambua kwa haraka repos, owners, paths, na code families.
2. **Fanya pivot kwenda high-signal locations** badala ya kutafuta tu strings za jumla kama `password`/`secret`.
3. **Tafuta attack surface, si credentials pekee**:
- CI/CD workflows, reusable workflows, composite actions, na deployment scripts
- Dev Containers / Codespaces bootstrap files na custom features
- Terraform/Helm/Kubernetes manifests
- SSO/OIDC/SAML integrations
- Internal URLs, staging hosts, admin panels, message brokers, na callback endpoints
- Dangerous code paths (`exec`, template rendering, SSRF fetchers, deserializers, ZIP extraction, YAML loaders, n.k.)
4. **Clone na utafute locally** unapohitaji non-default branches, full history, regex support bora zaidi, au bulk automation.
5. **Hamishia uchunguzi kwenye dedicated scanners** wakati lengo ni secrets triage au verification (kwa mfano, tazama dedicated page hapa chini).

### Mawazo ya high-signal queries

Haya yamekusudiwa kuwa mapana ili uweze kuyarekebisha kwa GitHub, GitLab, Sourcegraph, au Sourcebot syntax:
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
### Faili mpya zenye signal kubwa zinazofaa kupewa kipaumbele

- **`.github/workflows/*.yml`**: Tafuta `pull_request_target`, `workflow_run`, `workflow_call`, `secrets: inherit`, `id-token: write`, `runs-on: self-hosted`, na mistari ya third-party `uses:` iliyowekwa kwenye tags/branches pekee badala ya full commit SHAs.
- **`.devcontainer/devcontainer.json`**, **`.devcontainer/<variant>/devcontainer.json`**, na **`.devcontainer.json`**: Tafuta `remoteEnv`, `containerEnv`, `initializeCommand`, `postCreateCommand`, `mounts`, pamoja na Dockerfiles/scripts zilizorejelewa. Mara nyingi hizi hufichua internal package registries, bootstrap URLs, host mounts, na developer-only endpoints.
- **Dev Container Features** (`devcontainer-feature.json`, `install.sh`): Ni nzuri kwa kupata installer logic maalum ya org inayotekelezwa wakati wa kuunda environment.
- **Faili nyingine za CI/control-plane**: `.gitlab-ci.yml`, `azure-pipelines.yml`, `cloudbuild.yaml`, `Jenkinsfile`, `buildkite*`, `atlantis.yaml`, `terragrunt.hcl`, `helmfile.yaml`, `skaffold.yaml`, `argocd*`.

### Mass local search wakati indexed search haitoshi
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
Tumia utafutaji wa ndani unapohitaji:

- Kutafuta **non-default branches** au **tags**
- Kutafuta **git history**
- Kuendesha queries za **PCRE2/multiline** kwa ukali zaidi
- Kufanya **batch triage** ya repositories nyingi bila **UI limits**

### Tafuta **history**, **branches**, na **diffs** kwa uwazi
```bash
REPO_DIR=repos/some-repo
git -C "$REPO_DIR" fetch --all --tags --prune

git -C "$REPO_DIR" for-each-ref --format='%(refname:short)' refs/remotes/origin refs/tags \
| while read -r ref; do
git -C "$REPO_DIR" grep -nI -E 'pull_request_target|workflow_call|id-token: write|secrets: inherit|remoteEnv|containerEnv' "$ref" || true
done

git -C "$REPO_DIR" log --all -p -G 'gh[pousr]_|github_pat_|BEGIN [A-Z ]+PRIVATE KEY|internal.*https?://' -- .
```
Hii ni muhimu hasa wakati string inayovutia ilikuwepo tu katika **release branch**, **tag**, au **deleted commit**. Ikiwa Sourcegraph deployment yako inaiunga mkono, utafutaji wa `type:diff` na `type:commit` ni njia bora ya no-clone pivot kwa tatizo hilo hilo.

## Common blind spots

- **Default-branch-only indexing** ni jambo la kawaida. Usidhani kuwa code search inashughulikia branches/tags/history zote.
- **Large files, vendored code, generated code, au archives** zinaweza kurukwa au kutoa kelele nyingi.
- **Comments, issues, PRs, gists, na wikis** mara nyingi ziko nje ya scope ya generic code search na zinaweza kuhitaji tooling maalum ya platform.
- **Codespaces / devcontainer configs** zinaweza kuwa branch-specific na zinaweza kuwepo katika paths kadhaa za `.devcontainer/<variant>/devcontainer.json`, hivyo default branch safi haimaanishi kuwa dev environment ni safi kila mahali.
- **Reusable workflows/actions na devcontainer features** zinaweza kuwepo nje ya file inayoonekana wazi. Tafuta `.github/actions/`, `action.yml`, `action.yaml`, `devcontainer-feature.json`, na `install.sh`, si file ya workflow ya kiwango cha juu pekee.
- **Search syntax hutofautiana kwa kila platform**. Dork inayofanya kazi katika GitHub Code Search inaweza kuhitaji mabadiliko madogo kwa GitLab, Sourcegraph, au Sourcebot.

### Platform-specific gotchas

- **GitHub Code Search** ni bora kwa recon ya haraka, lakini hutafuta **default branch** pekee. Ikiwa unahitaji feature branches, deleted secrets, au historical code, clone repo na uitafute locally.
- **GitLab Exact Code Search** pia ina **default-branch** limitation na hu-index files ndogo pekee, lakini **Advanced Search** bado inaweza kuwa muhimu kwa kutafuta comments, commits, na wikis.
- **Sourcebot** hu-index **default branch** kwa default, lakini inaweza kusanidiwa ku-index branches/tags za ziada na kisha kutafutwa kwa `rev:` filters. Hii ni rahisi sana kwa internal audits zinazolenga branch/tag wakati unadhibiti index.
- **Sourcegraph** regex search kwa ujumla ndiyo chaguo linalotabirika zaidi kwa offensive work; chukulia structural search kama bonus ya hiari, si capability inayohakikishwa. Ikiwa deployment inaiunga mkono, queries za `type:diff` na `type:commit` ni nzuri sana kwa kurejesha deleted strings au mabadiliko ya hivi karibuni yanayohusiana na security.

> [!WARNING]
> Unapotafuta leaks katika repo na kuendesha kitu kama `git log -p`, usisahau kwamba kunaweza kuwa na **branches nyingine zenye commits nyingine** zilizo na secrets!

Kwa secret hunting maalum, GitHub dorks za org-wide, na tooling kama TruffleHog/Gitleaks, angalia:

{{#ref}}
github-leaked-secrets.md
{{#endref}}



## References

- [GitHub Code Search syntax](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
- [GitHub Actions secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [Dev Container metadata reference](https://containers.dev/implementors/json_reference/)
{{#include ../../banners/hacktricks-training.md}}
