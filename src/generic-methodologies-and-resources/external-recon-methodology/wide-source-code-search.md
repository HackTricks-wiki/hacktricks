# Utafutaji Mpana wa Source Code

Lengo la ukurasa huu ni kuorodhesha **platforms zinazoruhusu kutafuta code** (literal, regex, symbol-aware, au path-scoped) katika **maelfu/mamilioni ya repos**.

Hii ni muhimu kwa:

- **Kutafuta taarifa za leak**
- **Kutafuta patterns zilizo vulnerable**
- **Kuchora ramani ya technologies, internal hosts, CI/CD, na infrastructure-as-code**
- **Kufanya pivot kutoka jina la kampuni/org kwenda kwenye repos, branches, na files zenye signal kubwa**

- [**Sourcebot**](https://www.sourcebot.dev/): Code search ya open-source/self-hosted yenye regex, symbol, na filtered search katika repositories. Configure branches/tags za ziada na ziulize kwa kutumia `rev:` wakati branch coverage ni muhimu.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- [**Sourcegraph**](https://sourcegraph.com/search): Code search yenye regex, boolean, symbol, repository/file/language, branch/commit, diff, na commit-message queries.<sup>[[8]](#references)[[10]](#references)</sup> Structural search ni optional kwa sababu documentation ya sasa inaeleza kuwa imezimwa kwa default na ina kikomo cha performance.<sup>[[9]](#references)</sup>
- [**GitHub Code Search**](https://github.com/search): Inasaidia regex, boolean logic, na qualifiers kama `repo:`, `org:`, `user:`, `path:`, `language:`, `symbol:`, `content:` na `is:`.<sup>[[1]](#references)</sup>
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/): Code search inayotumia Zoekt yenye exact na regex modes pamoja na filters kama `file:`, `lang:`, `repo:` na `sym:`.<sup>[[2]](#references)</sup>
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/) ni fallback pana zaidi kwa sababu inaweza kutafuta code, comments, commits, merge requests, na wikis.<sup>[[11]](#references)</sup>
- [**SearchCode**](https://searchcode.com/): Huduma ya code-intelligence yenye boolean/regex/structural code search pamoja na file na symbol retrieval.<sup>[[12]](#references)</sup>
- [**Grep**](https://grep.app/): Public code search katika GitHub repositories milioni moja, ikiwa na content, file, na path search.<sup>[[13]](#references)</sup>

## Uwezo wa utafutaji wenye manufaa

Unapofanya audit ya org katika muktadha wa bug bounty/red team, uwezo unaofaa zaidi kwa kawaida ni:

- **Regex** support ya kutafuta token formats, URL schemes, majina ya dangerous functions, au fragments za mistari mingi.
- **Path filters** za kwenda moja kwa moja kwenye files zenye thamani kubwa kama `.github/workflows/`, `terraform/`, `helm/`, `.env`, `values.yaml`, `secrets.*`, `credentials.*`, `Dockerfile`, `Jenkinsfile`, au `nginx.conf`.
- **Language filters** za kutenganisha app code na IaC pamoja na pipelines.
- **Symbol-aware search** ya kuorodhesha handlers, auth middleware, webhook consumers, dangerous helper functions, au classes/methods maalum.
- **Boolean operators** za kupunguza noise: `NOT path:test`, `NOT is:generated`, `NOT is:vendored`, `foo OR bar`.
- **Revision/diff search** inapopatikana, ili uweze kurejesha **deleted strings**, kufuatilia **security-relevant changes**, au kukagua **non-default branches/tags** bila ku-clone kila kitu kwanza.

## Methodology ya vitendo

1. **Anza na indexed platforms** ili kutambua kwa haraka repos, owners, paths, na code families.
2. **Fanya pivot kwenye maeneo yenye signal kubwa** badala ya kutafuta tu strings za jumla kama `password`/`secret`.
3. **Tafuta attack surface, si credentials pekee**:
- CI/CD workflows, reusable workflows, composite actions, na deployment scripts
- Dev Containers / Codespaces bootstrap files na custom features
- Terraform/Helm/Kubernetes manifests
- SSO/OIDC/SAML integrations
- Internal URLs, staging hosts, admin panels, message brokers, na callback endpoints
- Dangerous code paths (`exec`, template rendering, SSRF fetchers, deserializers, ZIP extraction, YAML loaders, n.k.)
4. **Clone na utafute locally** unapohitaji non-default branches, full history, regex support bora zaidi, au bulk automation.
5. **Hamishia uchunguzi kwa dedicated scanners** wakati lengo ni secrets triage au verification (kwa mfano, tazama dedicated page hapa chini).

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
### Faili mpya zenye ishara kali zinazostahili kupewa kipaumbele

- **`.github/workflows/*.yml`**: Kagua triggers zenye privileges za `pull_request_target` na `workflow_run`, pamoja na mistari ya third-party `uses:` iliyowekwa kwenye tags/branches pekee badala ya full commit SHAs.<sup>[[3]](#references)</sup> Pia tafuta `workflow_call`, `secrets: inherit`, `id-token: write`, na `runs-on: self-hosted`.
- **`.devcontainer/devcontainer.json`**, **`.devcontainer/<variant>/devcontainer.json`**, na **`.devcontainer.json`**: Tafuta `remoteEnv`, `containerEnv`, `initializeCommand`, `postCreateCommand`, `mounts`, pamoja na Dockerfiles/scripts zilizorejelewa ili kugundua environment values, bootstrap commands, mounts, na faili zinazohusiana.<sup>[[4]](#references)</sup>
- **Dev Container Features** (`devcontainer-feature.json`, `install.sh`): Kagua faili zote mbili kwa sababu layout ya chini kabisa ya Feature inajumuisha metadata na entrypoint script ya `install.sh`.<sup>[[14]](#references)</sup>
- **Faili nyingine za CI/control-plane**: `.gitlab-ci.yml`, `azure-pipelines.yml`, `cloudbuild.yaml`, `Jenkinsfile`, `buildkite*`, `atlantis.yaml`, `terragrunt.hcl`, `helmfile.yaml`, `skaffold.yaml`, `argocd*`.

### Utafutaji mpana wa ndani wakati indexed search haitoshi
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
- Kufanya **batch triage** ya repositories nyingi bila mipaka ya UI

### Tafuta history, branches na diffs kwa uwazi yaliyoainishwa
```bash
REPO_DIR=repos/some-repo
git -C "$REPO_DIR" fetch --all --tags --prune

git -C "$REPO_DIR" for-each-ref --format='%(refname:short)' refs/remotes/origin refs/tags \
| while read -r ref; do
git -C "$REPO_DIR" grep -nI -E 'pull_request_target|workflow_call|id-token: write|secrets: inherit|remoteEnv|containerEnv' "$ref" || true
done

git -C "$REPO_DIR" log --all -p -G 'gh[pousr]_|github_pat_|BEGIN [A-Z ]+PRIVATE KEY|internal.*https?://' -- .
```
Hii ni muhimu hasa wakati string ya kuvutia ilikuwepo tu kwenye **release branch**, **tag**, au **deleted commit**. Ikiwa Sourcegraph deployment yako inaiunga mkono, utafutaji wa `type:diff` na `type:commit` ni njia bora ya no-clone pivot kwa tatizo hilo hilo.<sup>[[8]](#references)[[10]](#references)</sup>

## Common blind spots

- **Default-branch-only indexing** ni jambo la kawaida. Usidhani kuwa code search inahusisha branches/tags/history zote.
- **Large files, vendored code, generated code, au archives** zinaweza kurukwa au kutoa kelele nyingi.
- **Comments, issues, PRs, gists, na wikis** mara nyingi ziko nje ya scope ya generic code search na zinaweza kuhitaji tooling maalum ya platform.
- **Codespaces / devcontainer configs** zinaweza kuwa maalum kwa branch. Zinaweza kuwepo kwenye paths kadhaa za `.devcontainer/<variant>/devcontainer.json`, hivyo default branch iliyo safi haimaanishi kuwa dev environment ni safi kila mahali.<sup>[[4]](#references)</sup>
- **Reusable workflows/actions na devcontainer features** zinaweza kuwa nje ya file inayoonekana wazi. Search `.github/actions/`, `action.yml`, `action.yaml`, `devcontainer-feature.json`, na `install.sh`, si file ya workflow ya kiwango cha juu pekee.
- **Search syntax hutofautiana kwa kila platform**. Dork inayofanya kazi kwenye GitHub Code Search inaweza kuhitaji mabadiliko madogo kwa GitLab, Sourcegraph, au Sourcebot.

### Platform-specific gotchas

- **GitHub Code Search** ni muhimu kwa recon ya haraka, lakini inatafuta **default branch** pekee. Ikiwa unahitaji feature branches, deleted secrets, au historical code, clone repo na utafute locally.<sup>[[15]](#references)</sup>
- **GitLab Exact Code Search** ina kizuizi cha **default-branch** na hu-index files zilizo chini ya 1 MB pekee zenye trigrams zisizozidi 20,000.<sup>[[2]](#references)</sup> **Advanced Search** bado inaweza kujumuisha comments, commits, na wikis.<sup>[[11]](#references)</sup>
- **Sourcebot** hu-index **default branch** kwa default, lakini inaweza kusanidiwa ku-index branches/tags za ziada na kisha kutafutwa kwa filters za `rev:` unapodhibiti index.<sup>[[7]](#references)</sup>
- **Sourcegraph** inasaidia regex, symbol, diff, na commit queries; tumia structural search pale tu inapowezeshwa na uzingatie performance limits zilizoandikwa.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

> [!WARNING]
> Unapotafuta leaks kwenye repo na kuendesha kitu kama `git log -p`, usisahau kuwa kunaweza kuwa na **branches nyingine zenye commits nyingine** zilizo na secrets!

Kwa secret hunting maalum, GitHub dorks za org-wide, na tooling kama TruffleHog/Gitleaks, angalia [ukurasa wa GitHub leaked secrets](github-leaked-secrets.md).

## References

- [1] [Sintaksia ya GitHub Code Search](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [2] [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
- [3] [Rejeleo la matumizi salama ya GitHub Actions](https://docs.github.com/en/actions/reference/security/secure-use)
- [4] [Rejeleo la metadata ya Dev Container](https://containers.dev/implementors/json_reference/)
- [5] [Sourcebot](https://www.sourcebot.dev/)
- [6] [Sourcebot search API](https://docs.sourcebot.dev/api-reference/search-%26-navigation/search-code)
- [7] [Sourcebot multi-branch indexing](https://docs.sourcebot.dev/docs/features/search/multi-branch-indexing)
- [8] [Sourcegraph Code Search](https://sourcegraph.com/docs/code-search)
- [9] [Sourcegraph Structural Search](https://sourcegraph.com/docs/code-search/types/structural)
- [10] [Sintaksia ya Sourcegraph Search Query](https://sourcegraph.com/docs/code-search/queries)
- [11] [GitLab Advanced Search](https://docs.gitlab.com/user/search/advanced_search/)
- [12] [SearchCode](https://searchcode.com/)
- [13] [Grep.app](https://grep.app/)
- [14] [Kuandika Dev Container Feature](https://containers.dev/guide/author-a-feature)
- [15] [Investigation tools for security incidents](https://docs.github.com/en/enterprise-cloud%40latest/code-security/reference/security-incident-response/investigation-tools)
{{#include ../../banners/hacktricks-training.md}}
