# Wide Source Code Search

{{#include ../../banners/hacktricks-training.md}}

Cilj ove stranice je da navede **platforme koje omogućavaju pretragu koda** (literalnu, regex, pretragu zasnovanu na simbolima ili ograničenu na putanju) kroz **hiljade/milione repo-a**.

Ovo je korisno za:

- **Pretragu procurelih informacija**
- **Pretragu ranjivih obrazaca**
- **Mapiranje tehnologija, internih hostova, CI/CD-a i infrastructure-as-code-a**
- **Prelazak sa naziva kompanije/organizacije na repo-e, grane i fajlove sa relevantnim signalima**

- [**Sourcebot**](https://www.sourcebot.dev/): Open-source/self-hosted pretraga koda sa regex, symbol i filtriranom pretragom kroz repozitorijume. Konfigurišite dodatne grane/tagove i pretražujte ih pomoću `rev:` kada je pokrivenost grana važna.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- [**Sourcegraph**](https://sourcegraph.com/search): Pretraga koda sa regex, boolean, symbol, repository/file/language, branch/commit, diff i commit-message upitima.<sup>[[8]](#references)[[10]](#references)</sup> Structural search je opcionalan jer aktuelna dokumentacija navodi da je podrazumevano onemogućen i ograničen performansama.<sup>[[9]](#references)</sup>
- [**GitHub Code Search**](https://github.com/search): Podržava regex, boolean logiku i kvalifikatore kao što su `repo:`, `org:`, `user:`, `path:`, `language:`, `symbol:`, `content:` i `is:`.<sup>[[1]](#references)</sup>
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/): Pretraga koda koju pokreće Zoekt, sa exact i regex režimima i filterima kao što su `file:`, `lang:`, `repo:` i `sym:`.<sup>[[2]](#references)</sup>
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/) je šira rezervna opcija jer može da pretražuje kod, komentare, commit-e, merge request-ove i wiki-je.<sup>[[11]](#references)</sup>
- [**SearchCode**](https://searchcode.com/): Code-intelligence servis sa boolean/regex/structural code search funkcijama, kao i preuzimanjem fajlova i simbola.<sup>[[12]](#references)</sup>
- [**Grep**](https://grep.app/): Javna pretraga koda kroz milion GitHub repozitorijuma, sa pretragom sadržaja, fajlova i putanja.<sup>[[13]](#references)</sup>

## Useful search capabilities

Prilikom auditovanja organizacije u bug bounty/red team kontekstu, najkorisnije mogućnosti obično su:

- Podrška za **Regex** radi pretrage formata tokena, URL šema, naziva opasnih funkcija ili multiline fragmenata.
- **Path filteri** za direktan prelazak na fajlove visoke vrednosti kao što su `.github/workflows/`, `terraform/`, `helm/`, `.env`, `values.yaml`, `secrets.*`, `credentials.*`, `Dockerfile`, `Jenkinsfile` ili `nginx.conf`.
- **Language filteri** za razdvajanje aplikacionog koda od IaC-a i pipeline-ova.
- **Pretraga zasnovana na simbolima** za izlistavanje handler-a, auth middleware-a, webhook consumer-a, opasnih helper funkcija ili konkretnih klasa/metoda.
- **Boolean operatori** za smanjenje šuma: `NOT path:test`, `NOT is:generated`, `NOT is:vendored`, `foo OR bar`.
- **Pretraga revizija/diff-ova** kada je dostupna, kako biste mogli da pronađete **obrisane stringove**, pratite **promene relevantne za bezbednost** ili pregledate **grane/tagove koji nisu podrazumevani** bez prethodnog kloniranja svega.

## Practical methodology

1. **Počnite sa indeksiranim platformama** kako biste brzo identifikovali repo-e, vlasnike, putanje i familije koda.
2. **Pređite na lokacije sa relevantnim signalima** umesto da pretražujete samo generičke stringove kao što su `password`/`secret`.
3. **Pretražujte attack surface, a ne samo credential-e**:
- CI/CD workflow-e, reusable workflow-e, composite action-e i deployment skripte
- Dev Containers / Codespaces bootstrap fajlove i custom features
- Terraform/Helm/Kubernetes manifeste
- SSO/OIDC/SAML integracije
- Interne URL-ove, staging hostove, admin panele, message broker-e i callback endpoint-e
- Opasne putanje koda (`exec`, template rendering, SSRF fetcher-e, deserializer-e, ZIP extraction, YAML loader-e itd.)
4. **Klonirajte i pretražujte lokalno** kada su vam potrebne grane koje nisu podrazumevane, kompletna istorija, bolja regex podrška ili bulk automatizacija.
5. **Pređite na namenske skenere** kada je cilj triage ili verifikacija secret-a (na primer, pogledajte namensku stranicu u nastavku).

### High-signal query ideas

Oni su namerno široki kako biste ih mogli prilagoditi sintaksi GitHub-a, GitLab-a, Sourcegraph-a ili Sourcebot-a:
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
### Noviji fajlovi sa mnogo korisnih signala kojima vredi dati prioritet

- **`.github/workflows/*.yml`**: Pregledajte privilegovane `pull_request_target` i `workflow_run` trigere, kao i linije trećih strana `uses:` koje su zakačene samo za tagove/grane umesto za pune commit SHA vrednosti.<sup>[[3]](#references)</sup> Takođe pretražite `workflow_call`, `secrets: inherit`, `id-token: write` i `runs-on: self-hosted`.
- **`.devcontainer/devcontainer.json`**, **`.devcontainer/<variant>/devcontainer.json`** i **`.devcontainer.json`**: Pretražite `remoteEnv`, `containerEnv`, `initializeCommand`, `postCreateCommand`, `mounts` i povezane Dockerfiles/scripts kako biste otkrili vrednosti okruženja, bootstrap komande, mount-ove i povezane fajlove.<sup>[[4]](#references)</sup>
- **Dev Container Features** (`devcontainer-feature.json`, `install.sh`): Pregledajte oba fajla, jer minimalni raspored jednog Feature-a uključuje metadata podatke i ulazni `install.sh` script.<sup>[[14]](#references)</sup>
- **Ostali CI/control-plane fajlovi**: `.gitlab-ci.yml`, `azure-pipelines.yml`, `cloudbuild.yaml`, `Jenkinsfile`, `buildkite*`, `atlantis.yaml`, `terragrunt.hcl`, `helmfile.yaml`, `skaffold.yaml`, `argocd*`.

### Masovna lokalna pretraga kada indeksirana pretraga nije dovoljna
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
Koristi lokalno pretraživanje kada treba da:

- Pretražuješ **grane** ili **tagove** koji nisu podrazumevani
- Pretražuješ **git history**
- Agresivnije pokrećeš **PCRE2/multiline** upite
- Grupno radiš **triage** nad mnogim repozitorijumima bez UI ograničenja

### Eksplicitno pretraži history, grane i diff-oveેણ
```bash
REPO_DIR=repos/some-repo
git -C "$REPO_DIR" fetch --all --tags --prune

git -C "$REPO_DIR" for-each-ref --format='%(refname:short)' refs/remotes/origin refs/tags \
| while read -r ref; do
git -C "$REPO_DIR" grep -nI -E 'pull_request_target|workflow_call|id-token: write|secrets: inherit|remoteEnv|containerEnv' "$ref" || true
done

git -C "$REPO_DIR" log --all -p -G 'gh[pousr]_|github_pat_|BEGIN [A-Z ]+PRIVATE KEY|internal.*https?://' -- .
```
Ovo je naročito korisno kada je zanimljiv string postojao samo u **release branch**, **tag** ili **deleted commit**. Ako vaša Sourcegraph deployment podržava ovu funkcionalnost, pretrage `type:diff` i `type:commit` predstavljaju odličan no-clone pivot za isti problem.<sup>[[8]](#references)[[10]](#references)</sup>

## Uobičajene slepe tačke

- **Indeksiranje samo podrazumevane grane** je uobičajeno. Nemojte pretpostaviti da code search obuhvata sve grane/tagove/istoriju.
- **Veliki fajlovi, vendored code, generisani code ili arhive** mogu biti preskočeni ili mogu stvarati šum.
- **Komentari, issues, PR-ovi, gists i wikis** često nisu obuhvaćeni generičkim code search-om i mogu zahtevati tooling specifičan za platformu.
- **Codespaces / devcontainer konfiguracije mogu biti specifične za granu**. Mogu se nalaziti na više putanja poput `.devcontainer/<variant>/devcontainer.json`, tako da čista default grana ne znači da je dev okruženje svuda čisto.<sup>[[4]](#references)</sup>
- **Reusable workflows/actions i devcontainer features mogu se nalaziti izvan očiglednog fajla**. Pretražite `.github/actions/`, `action.yml`, `action.yaml`, `devcontainer-feature.json` i `install.sh`, a ne samo workflow fajl na najvišem nivou.
- **Sintaksa pretrage razlikuje se po platformama**. Dork koji radi u GitHub Code Search-u možda će zahtevati male izmene za GitLab, Sourcegraph ili Sourcebot.

### Specifične zamke platformi

- **GitHub Code Search** je koristan za brzi recon, ali pretražuje samo **default branch**. Ako su vam potrebne feature grane, obrisani secrets ili istorijski code, klonirajte repo i pretražite ga lokalno.<sup>[[15]](#references)</sup>
- **GitLab Exact Code Search** ima ograničenje na **default branch** i indeksira samo fajlove manje od 1 MB sa manje od 20.000 trigram-a.<sup>[[2]](#references)</sup> **Advanced Search** i dalje može obuhvatiti komentare, commit-e i wikis.<sup>[[11]](#references)</sup>
- **Sourcebot** po podrazumevanim postavkama indeksira **default branch**, ali može biti konfigurisan za indeksiranje dodatnih grana/tagova, nakon čega se može pretraživati pomoću `rev:` filtera kada kontrolišete indeks.<sup>[[7]](#references)</sup>
- **Sourcegraph** podržava regex, symbol, diff i commit upite; structural search koristite samo tamo gde je omogućen i uzmite u obzir njegova dokumentovana ograničenja performansi.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

> [!WARNING]
> Kada tražite leak-ove u repozitorijumu i pokrenete nešto poput `git log -p`, ne zaboravite da mogu postojati **druge grane sa drugim commit-ima** koji sadrže secrets!

Za namenski lov na secrets, GitHub dorks na nivou cele organizacije i alate kao što su TruffleHog/Gitleaks, pogledajte [GitHub stranicu sa procurelim secrets](github-leaked-secrets.md).

## References

- [1] [Sintaksa GitHub Code Search-a](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [2] [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
- [3] [Referenca za bezbednu upotrebu GitHub Actions](https://docs.github.com/en/actions/reference/security/secure-use)
- [4] [Referenca Dev Container metadata](https://containers.dev/implementors/json_reference/)
- [5] [Sourcebot](https://www.sourcebot.dev/)
- [6] [Sourcebot search API](https://docs.sourcebot.dev/api-reference/search-%26-navigation/search-code)
- [7] [Sourcebot indeksiranje više grana](https://docs.sourcebot.dev/docs/features/search/multi-branch-indexing)
- [8] [Sourcegraph Code Search](https://sourcegraph.com/docs/code-search)
- [9] [Sourcegraph Structural Search](https://sourcegraph.com/docs/code-search/types/structural)
- [10] [Sourcegraph sintaksa upita za pretragu](https://sourcegraph.com/docs/code-search/queries)
- [11] [GitLab Advanced Search](https://docs.gitlab.com/user/search/advanced_search/)
- [12] [SearchCode](https://searchcode.com/)
- [13] [Grep.app](https://grep.app/)
- [14] [Authoring a Dev Container Feature](https://containers.dev/guide/author-a-feature)
- [15] [Alati za istragu bezbednosnih incidenata](https://docs.github.com/en/enterprise-cloud%40latest/code-security/reference/security-incident-response/investigation-tools)
{{#include ../../banners/hacktricks-training.md}}
