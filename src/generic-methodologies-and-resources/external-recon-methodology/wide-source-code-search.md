# Breë bronkodesoektog

{{#include ../../banners/hacktricks-training.md}}

Die doel van hierdie bladsy is om **platforms te lys waarmee jy kode kan soek** (letterlik, regex, simboolbewus of padgebaseerd) oor **duisende/miljoene repos**.

Dit is nuttig om:

- **Na gelekte inligting te soek**
- **Na kwesbare patrone te soek**
- **Tegnologieë, interne gashere, CI/CD en infrastructure-as-code te karteer**
- **Van ’n maatskappy-/org-naam na repos, takke en lêers met ’n hoë sein te pivot**

- [**Sourcebot**](https://www.sourcebot.dev/): Oopbron/self-hosted codesoektog met regex-, simbool- en gefiltreerde soektog oor repositories. Stel addisionele takke/tags op en bevraagteken hulle met `rev:` wanneer takdekking belangrik is.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- [**Sourcegraph**](https://sourcegraph.com/search): Codesoektog met regex-, boolean-, simbool-, repository/lêer/taal-, tak/commit-, diff- en commit-boodskap-navrae.<sup>[[8]](#references)[[10]](#references)</sup> Structural search is opsioneel omdat huidige dokumentasie dit as by verstek gedeaktiveer en beperk deur werkverrigting beskryf.<sup>[[9]](#references)</sup>
- [**GitHub Code Search**](https://github.com/search): Ondersteun regex, boolean-logika en kwalifiseerders soos `repo:`, `org:`, `user:`, `path:`, `language:`, `symbol:`, `content:` en `is:`.<sup>[[1]](#references)</sup>
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/): Codesoektog aangedryf deur Zoekt, met presiese en regex-modusse en filters soos `file:`, `lang:`, `repo:` en `sym:`.<sup>[[2]](#references)</sup>
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/) is ’n breër terugvalopsie omdat dit kode, kommentare, commits, merge requests en wikis kan deursoek.<sup>[[11]](#references)</sup>
- [**SearchCode**](https://searchcode.com/): Diens vir kode-intelligensie met boolean/regex/structural code search, plus lêer- en simboolherwinning.<sup>[[12]](#references)</sup>
- [**Grep**](https://grep.app/): Publieke codesoektog oor ’n miljoen GitHub-repositories, met inhoud-, lêer- en padsoektog.<sup>[[13]](#references)</sup>

## Nuttige soekvermoëns

Wanneer jy ’n org in ’n bug bounty/red team-konteks oudit, is die nuttigste vermoëns gewoonlik:

- **Regex**-ondersteuning om na tokenformate, URL-skemas, gevaarlike funksiename of multiline-fragmente te soek.
- **Padfilters** om direk na lêers met ’n hoë waarde te spring, soos `.github/workflows/`, `terraform/`, `helm/`, `.env`, `values.yaml`, `secrets.*`, `credentials.*`, `Dockerfile`, `Jenkinsfile` of `nginx.conf`.
- **Taalfilters** om app-kode van IaC en pipelines te skei.
- **Simboolbewuste soektog** om handlers, auth middleware, webhook-verbruikers, gevaarlike helperfunksies of spesifieke klasse/metodes te lys.
- **Boolean-operateurs** om geraas te verminder: `NOT path:test`, `NOT is:generated`, `NOT is:vendored`, `foo OR bar`.
- **Revisie-/diff-soektog** wanneer beskikbaar, sodat jy **geskrapte stringe** kan herstel, **sekuriteitsrelevante veranderinge** kan volg of **nie-verstek-takke/tags** kan inspekteer sonder om eers alles te clone.

## Praktiese metodologie

1. **Begin met die geïndekseerde platforms** om vinnig repos, eienaars, paaie en kodefamilies te identifiseer.
2. **Pivot na liggings met ’n hoë sein** in plaas daarvan om slegs vir generiese `password`/`secret`-stringe te soek.
3. **Soek na attack surface, nie net credentials nie**:
- CI/CD-workflows, herbruikbare workflows, composite actions en deployment-skripte
- Dev Containers / Codespaces-bootstraplêers en custom features
- Terraform/Helm/Kubernetes-manifeste
- SSO/OIDC/SAML-integrasies
- Interne URL’s, staging-gashere, adminpanele, message brokers en callback-endpunte
- Gevaarlike kodepaaie (`exec`, template rendering, SSRF fetchers, deserializers, ZIP extraction, YAML loaders, ens.)
4. **Clone en soek plaaslik** wanneer jy nie-verstek-takke, volledige geskiedenis, beter regex-ondersteuning of grootmaat-outomatisering benodig.
5. **Eskaleer na toegewyde scanners** wanneer die doel secrets-triage of verifikasie is (sien byvoorbeeld die toegewyde bladsy hieronder).

### Idees vir navrae met ’n hoë sein

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
### Nuwer lêers met hoë seinwaarde wat prioriteit verdien

- **`.github/workflows/*.yml`**: Hersien bevoorregte `pull_request_target`- en `workflow_run`-triggers, asook derdeparty-`uses:`-lyne wat slegs aan tags/takke vasgepen is, eerder as aan volledige commit-SHA's.<sup>[[3]](#references)</sup> Soek ook vir `workflow_call`, `secrets: inherit`, `id-token: write` en `runs-on: self-hosted`.
- **`.devcontainer/devcontainer.json`**, **`.devcontainer/<variant>/devcontainer.json`** en **`.devcontainer.json`**: Soek vir `remoteEnv`, `containerEnv`, `initializeCommand`, `postCreateCommand`, `mounts`, asook verwysde Dockerfiles/scripts om omgewingswaardes, bootstrap-opdragte, mounts en verwante lêers te ontdek.<sup>[[4]](#references)</sup>
- **Dev Container Features** (`devcontainer-feature.json`, `install.sh`): Ondersoek albei lêers, omdat 'n Feature se minimum-uitleg metadata en 'n `install.sh`-entrypoint-script insluit.<sup>[[14]](#references)</sup>
- **Ander CI/control-plane-lêers**: `.gitlab-ci.yml`, `azure-pipelines.yml`, `cloudbuild.yaml`, `Jenkinsfile`, `buildkite*`, `atlantis.yaml`, `terragrunt.hcl`, `helmfile.yaml`, `skaffold.yaml`, `argocd*`.

### Massa plaaslike soektog wanneer geïndekseerde soektog nie genoeg is nie
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

- Soek **non-default branches** of **tags**
- Soek **git history**
- Voer **PCRE2/multiline**-navrae meer aggressief uit
- Voer **batch triage** van baie repositories sonder UI-limiete uit

### Soek uitdruklik deur history, branches en diffsેણ
```bash
REPO_DIR=repos/some-repo
git -C "$REPO_DIR" fetch --all --tags --prune

git -C "$REPO_DIR" for-each-ref --format='%(refname:short)' refs/remotes/origin refs/tags \
| while read -r ref; do
git -C "$REPO_DIR" grep -nI -E 'pull_request_target|workflow_call|id-token: write|secrets: inherit|remoteEnv|containerEnv' "$ref" || true
done

git -C "$REPO_DIR" log --all -p -G 'gh[pousr]_|github_pat_|BEGIN [A-Z ]+PRIVATE KEY|internal.*https?://' -- .
```
Dit is veral nuttig wanneer die interessante string slegs in ’n **release branch**, **tag** of **deleted commit** bestaan het. As jou Sourcegraph-deployment dit ondersteun, is `type:diff`- en `type:commit`-searches ’n uitstekende no-clone-pivot vir dieselfde probleem.<sup>[[8]](#references)[[10]](#references)</sup>

## Algemene blinde kolle

- **Default-branch-only indexing** is algemeen. Moenie aanvaar dat code search alle branches/tags/history dek nie.
- **Groot lêers, vendored code, generated code of archives** kan oorgeslaan word of baie geraas veroorsaak.
- **Comments, issues, PRs, gists en wikis** val dikwels buite die omvang van generiese code search en kan platform-spesifieke tooling vereis.
- **Codespaces / devcontainer configs kan branch-specific wees**. Hulle kan in verskeie `.devcontainer/<variant>/devcontainer.json`-paths voorkom, dus beteken ’n skoon default branch nie dat die dev environment oral skoon is nie.<sup>[[4]](#references)</sup>
- **Reusable workflows/actions en devcontainer features kan buite die voor-die-hand-liggende file wees**. Search `.github/actions/`, `action.yml`, `action.yaml`, `devcontainer-feature.json` en `install.sh`, nie net die top-level workflow file nie.
- **Search syntax verskil per platform**. ’n Dork wat in GitHub Code Search werk, kan klein veranderinge vir GitLab, Sourcegraph of Sourcebot vereis.

### Platform-spesifieke gotchas

- **GitHub Code Search** is nuttig vir vinnige recon, maar dit search slegs die **default branch**. As jy feature branches, deleted secrets of historical code nodig het, clone die repo en search dit plaaslik.<sup>[[15]](#references)</sup>
- **GitLab Exact Code Search** het ’n **default-branch**-beperking en indexeer slegs files kleiner as 1 MB met minder as 20 000 trigrams.<sup>[[2]](#references)</sup> **Advanced Search** kan steeds comments, commits en wikis dek.<sup>[[11]](#references)</sup>
- **Sourcebot** indexeer by verstek die **default branch**, maar dit kan ingestel word om addisionele branches/tags te indexeer en dan met `rev:`-filters gesearch word wanneer jy die index beheer.<sup>[[7]](#references)</sup>
- **Sourcegraph** ondersteun regex-, symbol-, diff- en commit-queries; gebruik structural search slegs waar dit enabled is en neem die gedokumenteerde performance-limits in ag.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

> [!WARNING]
> Wanneer jy vir leaks in ’n repo soek en iets soos `git log -p` uitvoer, moenie vergeet dat daar dalk **ander branches met ander commits** is wat secrets bevat nie!

Vir toegewyde secret hunting, org-wide GitHub dorks en tooling soos TruffleHog/Gitleaks, kyk na [die GitHub leaked secrets-bladsy](github-leaked-secrets.md).

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
