# Široka pretraga izvornog koda

{{#include ../../banners/hacktricks-training.md}}

Cilj ove stranice je da navede **platforme koje omogućavaju pretragu koda** (literalnu, regex, pretragu zasnovanu na simbolima ili ograničenu na putanje) kroz **hiljade/milione repo-a**.

Ovo je korisno za:

- **Pretragu procurelih informacija**
- **Pretragu ranjivih obrazaca**
- **Mapiranje tehnologija, internih hostova, CI/CD-a i infrastructure-as-code-a**
- **Pivotiranje sa imena kompanije/organizacije na repo-e, grane i fajlove sa visokim signalom**

- [**Sourcebot**](https://www.sourcebot.dev/): Open-source/self-hosted pretraga koda. Veoma korisno kada želite da indeksirate **veliki broj repo-a** i, ako je konfigurisano, dodatne grane/tagove, uz zadržavanje regex filtera kao što su `repo:`, `file:`, `lang:`, `rev:` i `sym:`.
- [**SourceGraph**](https://sourcegraph.com/search): Pretraga miliona repo-a. Regex je obično najsigurnija opcija; structural search postoji u nekim deployment-ima, ali ima ograničenja performansi i nije uvek omogućen.
- [**GitHub Code Search**](https://github.com/search): Podržava regex, boolean logiku i kvalifikatore kao što su `repo:`, `org:`, `user:`, `path:`, `language:`, `symbol:`, `content:` i `is:`.
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/): Moderna GitLab pretraga koda zasnovana na Zoekt-u. Podržava exact i regex režime sa filterima kao što su `file:`, `lang:`, `repo:` i `sym:`.
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/) je i dalje koristan kao širi fallback jer može da pretražuje kod, komentare, commit-e, merge request-e i wiki-je.
- [**SearchCode**](https://searchcode.com/): Pretraga koda u milionima projekata.
- [**Grep**](https://grep.app/): Brza javna pretraga kroz veoma veliki GitHub korpus. Korisno kada želite drugi prikaz indeksiranja/rangiranja za pivotiranje po **content**, **file** i **path**.

## Korisne mogućnosti pretrage

Prilikom auditovanja organizacije u kontekstu bug bounty/red team-a, najkorisnije mogućnosti su obično:

- Podrška za **Regex** radi pretrage formata tokena, URL šema, imena opasnih funkcija ili multiline fragmenata.
- **Path filteri** za direktan prelazak na fajlove velike vrednosti, kao što su `.github/workflows/`, `terraform/`, `helm/`, `.env`, `values.yaml`, `secrets.*`, `credentials.*`, `Dockerfile`, `Jenkinsfile` ili `nginx.conf`.
- **Language filteri** za razdvajanje app koda od IaC-a i pipeline-ova.
- **Pretraga zasnovana na simbolima** za enumeraciju handler-a, auth middleware-a, webhook consumer-a, opasnih helper funkcija ili određenih klasa/metoda.
- **Boolean operatori** za smanjenje buke: `NOT path:test`, `NOT is:generated`, `NOT is:vendored`, `foo OR bar`.
- **Revision/diff pretraga** kada je dostupna, kako biste mogli da povratite **obrisane stringove**, pratite **promene relevantne za bezbednost** ili pregledate **grane/tagove koji nisu podrazumevani** bez prethodnog kloniranja svega.

## Praktična metodologija

1. **Počnite sa indeksiranim platformama** kako biste brzo identifikovali repo-e, vlasnike, putanje i familije koda.
2. **Pivotirajte na lokacije sa visokim signalom** umesto da pretražujete samo generičke stringove poput `password`/`secret`.
3. **Pretražujte attack surface, a ne samo credentials**:
- CI/CD workflow-e, reusable workflow-e, composite action-e i deployment skripte
- Dev Containers / Codespaces bootstrap fajlove i custom feature-e
- Terraform/Helm/Kubernetes manifeste
- SSO/OIDC/SAML integracije
- Interne URL-ove, staging hostove, admin panele, message broker-e i callback endpoint-e
- Opasne putanje koda (`exec`, template rendering, SSRF fetcher-e, deserializer-e, ZIP extraction, YAML loader-e itd.)
4. **Klonirajte i pretražujte lokalno** kada su vam potrebne grane koje nisu podrazumevane, puna istorija, bolja regex podrška ili bulk automatizacija.
5. **Pređite na dedicated scanner-e** kada je cilj triage ili verifikacija secrets-a (na primer, pogledajte namensku stranicu ispod).

### Ideje za upite sa visokim signalom

Ovi upiti su namerno široki kako biste ih mogli prilagoditi GitHub, GitLab, Sourcegraph ili Sourcebot sintaksi:
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
### Novije datoteke sa visokim signalom koje vredi prioritizovati

- **`.github/workflows/*.yml`**: Potražite `pull_request_target`, `workflow_run`, `workflow_call`, `secrets: inherit`, `id-token: write`, `runs-on: self-hosted` i linije trećih strana `uses:` koje su pinned samo na tags/branches umesto na pune commit SHA vrednosti.
- **`.devcontainer/devcontainer.json`**, **`.devcontainer/<variant>/devcontainer.json`** i **`.devcontainer.json`**: Pretražite `remoteEnv`, `containerEnv`, `initializeCommand`, `postCreateCommand`, `mounts` i referencirane Dockerfiles/scripts. Oni često otkrivaju interne package registries, bootstrap URLs, host mounts i developer-only endpoints.
- **Dev Container Features** (`devcontainer-feature.json`, `install.sh`): Odlični su za pronalaženje org-specifične installer logike koja se izvršava tokom kreiranja okruženja.
- **Druge CI/control-plane datoteke**: `.gitlab-ci.yml`, `azure-pipelines.yml`, `cloudbuild.yaml`, `Jenkinsfile`, `buildkite*`, `atlantis.yaml`, `terragrunt.hcl`, `helmfile.yaml`, `skaffold.yaml`, `argocd*`.

### Masovna lokalna pretraga kada indexed search nije dovoljna
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
Koristite lokalno pretraživanje kada je potrebno da:

- Pretražujete **non-default branches** ili **tags**
- Pretražujete **git** istoriju
- Agresivnije pokrećete **PCRE2/multiline** upite
- Grupno analizirate veliki broj repozitorijuma bez **UI** ograničenja

### Eksplicitno pretražujte istoriju, grane i **diffs**
```bash
REPO_DIR=repos/some-repo
git -C "$REPO_DIR" fetch --all --tags --prune

git -C "$REPO_DIR" for-each-ref --format='%(refname:short)' refs/remotes/origin refs/tags \
| while read -r ref; do
git -C "$REPO_DIR" grep -nI -E 'pull_request_target|workflow_call|id-token: write|secrets: inherit|remoteEnv|containerEnv' "$ref" || true
done

git -C "$REPO_DIR" log --all -p -G 'gh[pousr]_|github_pat_|BEGIN [A-Z ]+PRIVATE KEY|internal.*https?://' -- .
```
Ovo je posebno korisno kada je zanimljiv string postojao samo u **release branch**, **tag** ili **deleted commit**. Ako vaša Sourcegraph deployment podržava ovu mogućnost, pretrage `type:diff` i `type:commit` su odličan no-clone pivot za isti problem.

## Uobičajene slepe tačke

- **Indeksiranje samo default branch-a** je uobičajeno. Nemojte pretpostaviti da code search obuhvata sve branch-eve/tagove/istoriju.
- **Veliki fajlovi, vendored code, generated code ili arhive** mogu biti preskočeni ili generisati mnogo šuma.
- **Komentari, issue-ji, PR-ovi, gist-ovi i wiki-ji** često nisu obuhvaćeni generičkim code search-om i mogu zahtevati tooling specifičan za platformu.
- **Codespaces / devcontainer konfiguracije mogu biti specifične za branch** i mogu se nalaziti na više putanja poput `.devcontainer/<variant>/devcontainer.json`, tako da čist default branch ne znači da je dev okruženje svuda čisto.
- **Reusable workflows/actions i devcontainer features mogu se nalaziti izvan očiglednog fajla**. Pretražite `.github/actions/`, `action.yml`, `action.yaml`, `devcontainer-feature.json` i `install.sh`, a ne samo workflow fajl na najvišem nivou.
- **Sintaksa pretrage se razlikuje po platformi**. Dork koji radi u GitHub Code Search-u možda zahteva male izmene za GitLab, Sourcegraph ili Sourcebot.

### Specifične zamke platformi

- **GitHub Code Search** je odličan za brzi recon, ali pretražuje samo **default branch**. Ako su vam potrebni feature branch-evi, obrisani secret-i ili istorijski code, klonirajte repo i pretražite ga lokalno.
- **GitLab Exact Code Search** takođe ima ograničenje na **default branch** i indeksira samo manje fajlove, ali **Advanced Search** i dalje može biti koristan za pretragu komentara, commit-a i wiki-ja.
- **Sourcebot** podrazumevano indeksira **default branch**, ali se može konfigurisati za indeksiranje dodatnih branch-eva/tagova, a zatim pretraživati pomoću `rev:` filtera, što je veoma praktično za interne audite fokusirane na branch/tag kada vi kontrolišete index.
- **Sourcegraph** regex search je uglavnom najpredvidljivija opcija za offensive rad; structural search posmatrajte kao opcioni dodatak, a ne kao zagarantovanu mogućnost. Ako deployment to podržava, `type:diff` i `type:commit` upiti su veoma dobri za pronalaženje obrisanih stringova ili nedavnih security-relevant izmena.

> [!WARNING]
> Kada tražite leak-ove u repo-u i pokrenete nešto poput `git log -p`, ne zaboravite da mogu postojati **drugi branch-evi sa drugim commit-ima** koji sadrže secret-e!

Za namenski secret hunting, GitHub dork-ove na nivou cele organizacije i tooling kao što su TruffleHog/Gitleaks, pogledajte:

{{#ref}}
github-leaked-secrets.md
{{#endref}}



## Reference

- [GitHub Code Search syntax](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
- [GitHub Actions secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [Dev Container metadata reference](https://containers.dev/implementors/json_reference/)
{{#include ../../banners/hacktricks-training.md}}
