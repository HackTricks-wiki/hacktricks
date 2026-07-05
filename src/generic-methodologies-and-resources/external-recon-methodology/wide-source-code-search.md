# Wide Source Code Search

{{#include ../../banners/hacktricks-training.md}}

Cilj ove stranice je da nabroji **platforme koje omogućavaju pretragu koda** (literalno, regex, simbol-svesno ili ograničeno na putanju) kroz **hiljade/milione repozitorijuma**.

Ovo je korisno za:

- **Pretragu procurelih informacija**
- **Pretragu ranjivih obrazaca**
- **Mapiranje tehnologija, internih hostova, CI/CD i infrastructure-as-code**
- **Pivotiranje od naziva kompanije/org-a ka repozitorijumima, granama i fajlovima visokog signala**

- [**Sourcebot**](https://www.sourcebot.dev/): Open-source/self-hosted code search. Veoma korisno kada želite da indeksirate **mnogo repo-a** i, ako je podešeno, dodatne grane/tagove uz zadržavanje regex filtera kao što su `repo:`, `file:`, `lang:`, `rev:` i `sym:`.
- [**SourceGraph**](https://sourcegraph.com/search): Pretraga kroz milione repozitorijuma. Regex je obično najsigurnija opcija; structural search postoji u nekim deploymentima, ali ima ograničenja u performansama i nije uvek omogućena.
- [**GitHub Code Search**](https://github.com/search): Podržava regex, boolean logiku i kvalifikatore kao što su `repo:`, `org:`, `user:`, `path:`, `language:`, `symbol:`, `content:` i `is:`.
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/): Modern GitLab code search pokretan Zoekt-om. Podržava exact i regex režime sa filterima kao što su `file:`, `lang:`, `repo:` i `sym:`.
- [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/) je i dalje koristan kao širi fallback zato što može da pretražuje code, komentare, commit-ove, merge requests i wikije.
- [**SearchCode**](https://searchcode.com/): Pretraga code-a kroz milione projekata.

## Korisne mogućnosti pretrage

Kada vršite audit nekog org-a u bug bounty/red team kontekstu, najkorisnije mogućnosti su obično:

- **Regex** podrška za pretragu formata tokena, URL šema, opasnih naziva funkcija ili višelinijskih fragmenata.
- **Filteri putanja** za direktan skok u fajlove visoke vrednosti kao što su `.github/workflows/`, `terraform/`, `helm/`, `.env`, `values.yaml`, `secrets.*`, `credentials.*`, `Dockerfile`, `Jenkinsfile`, ili `nginx.conf`.
- **Filteri jezika** za razdvajanje app code-a od IaC i pipeline-ova.
- **Symbol-aware search** za enumeraciju handler-a, auth middleware-a, webhook consumer-a, opasnih helper funkcija ili određenih klasa/metoda.
- **Boolean operatori** za smanjenje šuma: `NOT path:test`, `NOT is:generated`, `NOT is:vendored`, `foo OR bar`.

## Praktična metodologija

1. **Počnite sa indeksiranim platformama** da brzo identifikujete repo-e, vlasnike, putanje i familije code-a.
2. **Pivotirajte ka lokacijama visokog signala** umesto da tražite samo generičke `password`/`secret` stringove.
3. **Tražite attack surface, ne samo kredencijale**:
- CI/CD workflow-i i deployment skripte
- Terraform/Helm/Kubernetes manifesti
- SSO/OIDC/SAML integracije
- Interni URL-ovi, staging hostovi, admin paneli, message broker-i i callback endpoint-i
- Opasne code putanje (`exec`, template rendering, SSRF fetchers, deserializeri, ZIP extraction, YAML loaderi, itd.)
4. **Klонирајte i pretražujte lokalno** kada su vam potrebne ne-default grane, puna istorija, bolja regex podrška ili bulk automatizacija.
5. **Pređite na dedicated scanner-e** kada je cilj secrets triage ili verifikacija (na primer, pogledajte dedicated stranicu ispod).

### Ideje za upite visokog signala

Ovo je namerno široko kako biste mogli da ga prilagodite GitHub, GitLab, Sourcegraph ili Sourcebot sintaksi:
```text
org:target path:.github/workflows ("pull_request_target" OR "workflow_run" OR "ACTIONS_STEP_DEBUG")
org:target (path:terraform OR path:helm OR language:HCL OR language:YAML) ("role_arn" OR "assume_role" OR "client_secret" OR "access_key")
org:target ("BEGIN PRIVATE KEY" OR "ghp_" OR "github_pat_" OR "AIza" OR "xoxb-")
org:target (path:.env OR path:values.yaml OR path:application-prod OR path:credentials)
org:target ("internal" OR "corp" OR "staging") ("https://" OR "ssh://") NOT path:test
```
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
Koristi lokalno pretraživanje kada ti treba:

- Pretraživanje **nepodrazumevanih grana** ili **tagova**
- Pretraživanje **git istorije**
- Pokretanje **PCRE2/multiline** upita agresivnije
- Batch trijaža mnogo repozitorijuma bez UI ograničenja

## Uobičajene slepe tačke

- **Indeksiranje samo podrazumevane grane** je uobičajeno. Ne pretpostavljaj da code search pokriva sve grane/tagove/istoriju.
- **Veliki fajlovi, vendored code, generated code ili archives** mogu biti preskočeni ili bučni.
- **Komentari, issues, PR-ovi, gists i wikis** su često van opsega generičkog code search-a i mogu zahtevati alatke specifične za platformu.
- **Search sintaksa se razlikuje po platformi**. Dork koji radi u GitHub Code Search može zahtevati male izmene za GitLab, Sourcegraph ili Sourcebot.

### Platform-specific gotchas

- **GitHub Code Search** je odličan za brzo recon, ali pretražuje samo **podrazumevanu granu**. Ako su ti potrebne feature branches, obrisani secrets ili istorijski code, kloniraj repo i pretraži ga lokalno.
- **GitLab Exact Code Search** takođe ima ograničenje na **podrazumevanu granu** i indeksira samo manje fajlove, ali **Advanced Search** i dalje može biti koristan za pretragu komentara, commit-ova i wiki-ja.
- **Sourcebot** po podrazumevanom ponašanju indeksira **podrazumevanu granu**, ali može da se konfiguriše da indeksira dodatne grane/tagove i zatim pretražuje pomoću `rev:` filtera, što je vrlo zgodno za interne audite fokusirane na grane/tagove kada kontrolišeš indeks.
- **Sourcegraph** regex search je generalno najpredvidljivija opcija za offensive work; structural search tretiraj kao opcioni bonus, a ne kao garantovanu mogućnost.

> [!WARNING]
> Kada tražiš leaks u repou i pokreneš nešto poput `git log -p` ne zaboravi da možda postoje **druge grane sa drugim commit-ovima** koji sadrže secrets!

Za namensko hunting za secrets, org-wide GitHub dorks i alate kao što su TruffleHog/Gitleaks, pogledaj:

{{#ref}}
github-leaked-secrets.md
{{#endref}}



## References

- [GitHub Code Search syntax](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
{{#include ../../banners/hacktricks-training.md}}
