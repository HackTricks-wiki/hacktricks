# Wide Source Code Search

{{#include ../../banners/hacktricks-training.md}}

Die doel van hierdie bladsy is om **platforms te lys wat jou toelaat om kode te soek** (letterlik, regex, simboolbewus of padbeperk) oor **duisende/miljoene repos**.

Dit is nuttig om:

- **Na leaked information te soek**
- **Na kwesbare patrone te soek**
- **Tegnologieë, interne hosts, CI/CD en infrastructure-as-code te karteer**
- **Van ’n maatskappy/org-naam na repos, branches en lêers met ’n hoë sein te pivot**

- [**Sourcebot**](https://www.sourcebot.dev/): Open-source/self-hosted code search. Baie nuttig wanneer jy **baie repos** wil indekseer en, indien gekonfigureer, addisionele branches/tags wil insluit terwyl regex-filters soos `repo:`, `file:`, `lang:`, `rev:` en `sym:` behoue bly.
- [**SourceGraph**](https://sourcegraph.com/search): Soek in miljoene repos. Regex is gewoonlik die veiligste opsie; structural search bestaan in sommige deployments, maar dit het performance-beperkings en is nie altyd geaktiveer nie.
- [**GitHub Code Search**](https://github.com/search): Ondersteun regex, boolean logic en qualifiers soos `repo:`, `org:`, `user:`, `path:`, `language:`, `symbol:`, `content:` en `is:`.
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/): Moderne GitLab code search, aangedryf deur Zoekt. Ondersteun exact- en regex-modes met filters soos `file:`, `lang:`, `repo:` en `sym:`.
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/) is steeds nuttig as ’n breër fallback omdat dit code, comments, commits, merge requests en wikis kan soek.
- [**SearchCode**](https://searchcode.com/): Soek code in miljoene projekte.
- [**Grep**](https://grep.app/): Vinnige publieke search oor ’n baie groot GitHub-corpus. Nuttig wanneer jy ’n tweede indexing/ranking-aansig vir **content**, **file** en **path** pivots wil hê.

## Useful search capabilities

Wanneer ’n org in ’n bug bounty/red team-konteks geoudit word, is die nuttigste capabilities gewoonlik:

- **Regex**-ondersteuning om na token-formate, URL-skemas, gevaarlike funksiename of multiline-fragmente te soek.
- **Path filters** om direk na lêers met ’n hoë waarde te spring, soos `.github/workflows/`, `terraform/`, `helm/`, `.env`, `values.yaml`, `secrets.*`, `credentials.*`, `Dockerfile`, `Jenkinsfile` of `nginx.conf`.
- **Language filters** om app code van IaC en pipelines te skei.
- **Symbol-aware search** om handlers, auth middleware, webhook consumers, gevaarlike helper functions of spesifieke classes/methods te lys.
- **Boolean operators** om noise te verminder: `NOT path:test`, `NOT is:generated`, `NOT is:vendored`, `foo OR bar`.
- **Revision/diff search** wanneer beskikbaar, sodat jy **deleted strings** kan herwin, **security-relevant changes** kan volg of **non-default branches/tags** kan inspekteer sonder om eers alles te clone.

## Practical methodology

1. **Begin met die indexed platforms** om vinnig repos, owners, paths en code families te identifiseer.
2. **Pivot na locations met ’n hoë sein** in plaas daarvan om slegs na generiese `password`/`secret`-strings te soek.
3. **Soek na attack surface, nie net credentials nie**:
- CI/CD-workflows, reusable workflows, composite actions en deployment scripts
- Dev Containers / Codespaces bootstrap files en custom features
- Terraform/Helm/Kubernetes manifests
- SSO/OIDC/SAML-integrations
- Interne URLs, staging hosts, admin panels, message brokers en callback endpoints
- Gevaarlike code paths (`exec`, template rendering, SSRF fetchers, deserializers, ZIP extraction, YAML loaders, ens.)
4. **Clone en search plaaslik** wanneer jy non-default branches, volledige history, beter regex-ondersteuning of bulk automation benodig.
5. **Escalate na dedicated scanners** wanneer die doel secrets triage of verification is (sien byvoorbeeld die toegewyde bladsy hieronder).

### High-signal query ideas

Hierdie is doelbewus breed sodat jy dit by GitHub-, GitLab-, Sourcegraph- of Sourcebot-sintaksis kan aanpas:
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
### Nuwer hoë-sein-lêers wat prioriteit verdien

- **`.github/workflows/*.yml`**: Soek na `pull_request_target`, `workflow_run`, `workflow_call`, `secrets: inherit`, `id-token: write`, `runs-on: self-hosted`, en derdeparty-`uses:`-reëls wat slegs aan tags/takke vasgepen is, eerder as volledige commit-SHA's.
- **`.devcontainer/devcontainer.json`**, **`.devcontainer/<variant>/devcontainer.json`**, en **`.devcontainer.json`**: Soek na `remoteEnv`, `containerEnv`, `initializeCommand`, `postCreateCommand`, `mounts`, en Dockerfiles/scripts waarna verwys word. Hierdie lêers onthul dikwels interne package registries, bootstrap-URL'e, host mounts en slegs-vir-ontwikkelaars-endpoints.
- **Dev Container Features** (`devcontainer-feature.json`, `install.sh`): Baie nuttig om organisasie-spesifieke installer-logika te vind wat tydens die skepping van die omgewing uitgevoer word.
- **Ander CI/control-plane-lêers**: `.gitlab-ci.yml`, `azure-pipelines.yml`, `cloudbuild.yaml`, `Jenkinsfile`, `buildkite*`, `atlantis.yaml`, `terragrunt.hcl`, `helmfile.yaml`, `skaffold.yaml`, `argocd*`.

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
Gebruik plaaslike soektogte wanneer jy moet:

- Soek in **nie-verstek-takke** of **tags**
- Soek deur **git-geskiedenis**
- Voer **PCRE2/multiline**-navrae meer aggressief uit
- Doen bondeltriage van baie repositories sonder UI-limiete

### Soek eksplisiet deur geskiedenis, takke en diffs
```bash
REPO_DIR=repos/some-repo
git -C "$REPO_DIR" fetch --all --tags --prune

git -C "$REPO_DIR" for-each-ref --format='%(refname:short)' refs/remotes/origin refs/tags \
| while read -r ref; do
git -C "$REPO_DIR" grep -nI -E 'pull_request_target|workflow_call|id-token: write|secrets: inherit|remoteEnv|containerEnv' "$ref" || true
done

git -C "$REPO_DIR" log --all -p -G 'gh[pousr]_|github_pat_|BEGIN [A-Z ]+PRIVATE KEY|internal.*https?://' -- .
```
Dit is veral nuttig wanneer die interessante string slegs in ’n **release branch**, **tag**, of **deleted commit** bestaan het. As jou Sourcegraph-deployment dit ondersteun, is `type:diff`- en `type:commit`-soektogte ’n uitstekende no-clone pivot vir dieselfde probleem.

## Algemene blinde kolle

- **Default-branch-only indexing** is algemeen. Moenie aanvaar dat code search alle branches/tags/history dek nie.
- **Groot lêers, vendored code, generated code, of archives** kan oorgeslaan word of raserig wees.
- **Comments, issues, PRs, gists, en wikis** val dikwels buite die omvang van generiese code search en kan platform-spesifieke tooling vereis.
- **Codespaces / devcontainer configs kan branch-specific wees** en kan in verskeie `.devcontainer/<variant>/devcontainer.json`-paths voorkom. ’n Skoon default branch beteken dus nie dat die dev environment oral skoon is nie.
- **Reusable workflows/actions en devcontainer features kan buite die voor-die-hand-liggende lêer wees**. Soek in `.github/actions/`, `action.yml`, `action.yaml`, `devcontainer-feature.json`, en `install.sh`, nie net in die top-level workflow-lêer nie.
- **Search syntax verskil per platform**. ’n Dork wat in GitHub Code Search werk, kan klein veranderinge vir GitLab, Sourcegraph, of Sourcebot vereis.

### Platform-spesifieke slaggate

- **GitHub Code Search** is uitstekend vir vinnige recon, maar dit soek slegs die **default branch**. As jy feature branches, deleted secrets, of historical code benodig, clone die repo en soek dit plaaslik.
- **GitLab Exact Code Search** het ook ’n **default-branch**-beperking en indekseer slegs kleiner lêers, maar **Advanced Search** kan steeds nuttig wees om comments, commits, en wikis te soek.
- **Sourcebot** indekseer by verstek die **default branch**, maar dit kan gekonfigureer word om addisionele branches/tags te indekseer en daarna met `rev:`-filters gesoek te word. Dit is baie gerieflik vir branch/tag-gefokusde interne audits wanneer jy die index beheer.
- **Sourcegraph** regex search is oor die algemeen die mees voorspelbare opsie vir offensive work; behandel structural search as ’n opsionele bonus, nie as ’n gewaarborgde vermoë nie. As die deployment dit ondersteun, is `type:diff`- en `type:commit`-queries baie goed om deleted strings of onlangse security-relevant changes te herwin.

> [!WARNING]
> Wanneer jy vir leaks in ’n repo soek en iets soos `git log -p` uitvoer, moenie vergeet dat daar **ander branches met ander commits** kan wees wat secrets bevat nie!

Vir toegewyde secret hunting, org-wide GitHub dorks, en tooling soos TruffleHog/Gitleaks, kyk na:

{{#ref}}
github-leaked-secrets.md
{{#endref}}



## References

- [GitHub Code Search syntax](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
- [GitHub Actions secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [Dev Container metadata reference](https://containers.dev/implementors/json_reference/)
{{#include ../../banners/hacktricks-training.md}}
