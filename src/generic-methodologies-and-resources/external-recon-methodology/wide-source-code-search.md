# Wye Source Code-soektog

Die doel van hierdie bladsy is om **platforms te lys waarmee jy code kan search** (literal, regex, symbol-aware of path-scoped) oor **duisende/miljoene repos**.

Dit is nuttig om:

- **Vir leaked information te search**
- **Vir kwesbare patrone te search**
- **Tegnologieë, interne hosts, CI/CD en infrastructure-as-code te karteer**
- **Van 'n maatskappy-/org-naam na repos, branches en hoë-sein-lêers te pivot**

- [**Sourcebot**](https://www.sourcebot.dev/): Open-source/self-hosted code search met regex-, symbol- en gefiltreerde search oor repositories. Configureer addisionele branches/tags en query hulle met `rev:` wanneer branch-dekking belangrik is.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- [**Sourcegraph**](https://sourcegraph.com/search): Code search met regex-, boolean-, symbol-, repository/file/language-, branch/commit-, diff- en commit-message-queries.<sup>[[8]](#references)[[10]](#references)</sup> Structural search is opsioneel omdat huidige dokumentasie dit as by verstek gedeaktiveer en beperk deur performance beskryf.<sup>[[9]](#references)</sup>
- [**GitHub Code Search**](https://github.com/search): Ondersteun regex, boolean logic en qualifiers soos `repo:`, `org:`, `user:`, `path:`, `language:`, `symbol:`, `content:` en `is:`.<sup>[[1]](#references)</sup>
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/): Code search aangedryf deur Zoekt, met exact- en regex-modes en filters soos `file:`, `lang:`, `repo:` en `sym:`.<sup>[[2]](#references)</sup>
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/) is 'n breër fallback omdat dit code, comments, commits, merge requests en wikis kan search.<sup>[[11]](#references)</sup>
- [**SearchCode**](https://searchcode.com/): Code-intelligence-diens met boolean/regex/structural code search, plus file- en symbol-retrieval.<sup>[[12]](#references)</sup>
- [**Grep**](https://grep.app/): Publieke code search oor 'n miljoen GitHub repositories, met content-, file- en path-search.<sup>[[13]](#references)</sup>

## Nuttige search-vermoëns

Wanneer jy 'n org in 'n bug bounty/red team-konteks oudit, is die nuttigste vermoëns gewoonlik:

- **Regex**-ondersteuning om vir token-formate, URL-skemas, gevaarlike funksiename of multiline-fragmente te search.
- **Path-filters** om direk na lêers met hoë waarde te spring, soos `.github/workflows/`, `terraform/`, `helm/`, `.env`, `values.yaml`, `secrets.*`, `credentials.*`, `Dockerfile`, `Jenkinsfile` of `nginx.conf`.
- **Language-filters** om app-code van IaC en pipelines te skei.
- **Symbol-aware search** om handlers, auth middleware, webhook-consumers, gevaarlike helper functions of spesifieke classes/methods te enumerate.
- **Boolean operators** om geraas te verminder: `NOT path:test`, `NOT is:generated`, `NOT is:vendored`, `foo OR bar`.
- **Revision/diff-search** wanneer beskikbaar, sodat jy **deleted strings** kan recover, **security-relevant changes** kan volg of **non-default branches/tags** kan inspecteer sonder om alles eers te clone.

## Praktiese metodologie

1. **Begin met die indexed platforms** om repos, owners, paths en code families vinnig te identifiseer.
2. **Pivot na locations met hoë sein** in plaas daarvan om net vir generiese `password`/`secret`-strings te search.
3. **Search vir attack surface, nie net credentials nie**:
- CI/CD workflows, reusable workflows, composite actions en deployment scripts
- Dev Containers / Codespaces bootstrap files en custom features
- Terraform/Helm/Kubernetes manifests
- SSO/OIDC/SAML-integrations
- Interne URLs, staging hosts, admin panels, message brokers en callback endpoints
- Gevaarlike code paths (`exec`, template rendering, SSRF fetchers, deserializers, ZIP extraction, YAML loaders, ens.)
4. **Clone en search plaaslik** wanneer jy non-default branches, volledige history, beter regex-ondersteuning of bulk automation benodig.
5. **Escalate na dedicated scanners** wanneer die doel secrets triage of verification is (byvoorbeeld, sien die toegewyde bladsy hieronder).

### Idees vir hoë-sein-queries

Hierdie is doelbewus breed sodat jy dit by GitHub-, GitLab-, Sourcegraph- of Sourcebot-syntax kan aanpas:
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
### Nuwer hoësein-lêers wat prioriteit behoort te kry

- **`.github/workflows/*.yml`**: Hersien bevoorregte `pull_request_target`- en `workflow_run`-triggers, asook derdeparty-`uses:`-lyne wat slegs aan tags/takke vasgemaak is in plaas van volledige commit-SHA's.<sup>[[3]](#references)</sup> Soek ook vir `workflow_call`, `secrets: inherit`, `id-token: write` en `runs-on: self-hosted`.
- **`.devcontainer/devcontainer.json`**, **`.devcontainer/<variant>/devcontainer.json`** en **`.devcontainer.json`**: Soek vir `remoteEnv`, `containerEnv`, `initializeCommand`, `postCreateCommand`, `mounts` en verwysde Dockerfiles/scripts om omgewingswaardes, bootstrap-opdragte, mounts en verwante lêers te ontdek.<sup>[[4]](#references)</sup>
- **Dev Container Features** (`devcontainer-feature.json`, `install.sh`): Inspekteer albei lêers, omdat 'n Feature se minimum-uitleg metadata en 'n `install.sh`-entrypoint-script insluit.<sup>[[14]](#references)</sup>
- **Ander CI/beheervlak-lêers**: `.gitlab-ci.yml`, `azure-pipelines.yml`, `cloudbuild.yaml`, `Jenkinsfile`, `buildkite*`, `atlantis.yaml`, `terragrunt.hcl`, `helmfile.yaml`, `skaffold.yaml`, `argocd*`.

### Massa-plaaslike soektog wanneer geïndekseerde soektog nie voldoende is nie
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
Gebruik plaaslike soektog wanneer jy moet:

- Soek in **nie-verstek branches** of **tags**
- Soek deur **git history**
- Voer **PCRE2/multiline** queries meer aggressief uit
- Doen **batch-triage** van baie repositories sonder **UI-limiete**

### Soek uitdruklik deur history, branches en diffs
```bash
REPO_DIR=repos/some-repo
git -C "$REPO_DIR" fetch --all --tags --prune

git -C "$REPO_DIR" for-each-ref --format='%(refname:short)' refs/remotes/origin refs/tags \
| while read -r ref; do
git -C "$REPO_DIR" grep -nI -E 'pull_request_target|workflow_call|id-token: write|secrets: inherit|remoteEnv|containerEnv' "$ref" || true
done

git -C "$REPO_DIR" log --all -p -G 'gh[pousr]_|github_pat_|BEGIN [A-Z ]+PRIVATE KEY|internal.*https?://' -- .
```
Dit is veral nuttig wanneer die interessante string slegs in ’n **release branch**, **tag**, of **deleted commit** bestaan het. Indien jou Sourcegraph-deployment dit ondersteun, is `type:diff`- en `type:commit`-soektogte ’n uitstekende no-clone pivot vir dieselfde probleem.<sup>[[8]](#references)[[10]](#references)</sup>

## Common blind spots

- **Default-branch-only indexing** is algemeen. Moenie aanvaar dat code search alle branches/tags/history dek nie.
- **Large files, vendored code, generated code, of archives** kan oorgeslaan word of raserig wees.
- **Comments, issues, PRs, gists, en wikis** val dikwels buite die omvang van generiese code search en mag platform-spesifieke tooling vereis.
- **Codespaces / devcontainer configs kan branch-specific wees**. Hulle kan in verskeie `.devcontainer/<variant>/devcontainer.json`-paths voorkom, dus beteken ’n skoon default branch nie dat die dev environment oral skoon is nie.<sup>[[4]](#references)</sup>
- **Reusable workflows/actions en devcontainer features kan buite die voor die hand liggende file wees**. Search `.github/actions/`, `action.yml`, `action.yaml`, `devcontainer-feature.json`, en `install.sh`, nie slegs die top-level workflow file nie.
- **Search syntax verskil per platform**. ’n Dork wat in GitHub Code Search werk, kan klein veranderinge vir GitLab, Sourcegraph, of Sourcebot vereis.

### Platform-specific gotchas

- **GitHub Code Search** is nuttig vir vinnige recon, maar dit search slegs die **default branch**. As jy feature branches, deleted secrets, of historical code benodig, clone die repo en search dit plaaslik.<sup>[[15]](#references)</sup>
- **GitLab Exact Code Search** het ’n **default-branch**-beperking en indexeer slegs files kleiner as 1 MB met minder as 20 000 trigrams.<sup>[[2]](#references)</sup> **Advanced Search** kan steeds comments, commits, en wikis dek.<sup>[[11]](#references)</sup>
- **Sourcebot** indexeer die **default branch** by verstek, maar dit kan gekonfigureer word om addisionele branches/tags te indexeer en dan met `rev:`-filters gesearch word wanneer jy die index beheer.<sup>[[7]](#references)</sup>
- **Sourcegraph** ondersteun regex-, symbol-, diff-, en commit-queries; gebruik structural search slegs waar dit ge-enabled is en neem die gedokumenteerde performance limits in ag.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

> [!WARNING]
> Wanneer jy vir leaks in ’n repo soek en iets soos `git log -p` uitvoer, moenie vergeet dat daar dalk **other branches with other commits** is wat secrets bevat nie!

Vir toegewyde secret hunting, org-wide GitHub dorks, en tooling soos TruffleHog/Gitleaks, kyk na [die GitHub leaked secrets-bladsy](github-leaked-secrets.md).

## References

- [1] [GitHub Code Search-sintaksis](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [2] [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
- [3] [GitHub Actions secure use-verwysing](https://docs.github.com/en/actions/reference/security/secure-use)
- [4] [Dev Container metadata-verwysing](https://containers.dev/implementors/json_reference/)
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
