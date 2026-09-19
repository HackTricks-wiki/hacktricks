# AGENTS.md

Smernice za buduće agente koji rade u ovom repository-ju.

## Kontekst repository-ja

Ovo je glavni HackTricks mdBook repository. Povezana cloud knjiga se nalazi na:

`/Users/carlospolop/git/hacktricks-cloud`

Izmene zajedničkog ponašanja theme/search često moraju biti primenjene u oba repository-ja.

## Ugovor za učitavanje search index-a

Prilagođeni search UI se nalazi u:

`theme/ht_searcher.js`

Može postojati i generisana kopija na:

`book/theme/ht_searcher.js`

Ako production deploy-uje već izgrađeni `book/` directory, ažurirajte obe kopije ili ponovo izgradite
knjigu pre deployment-a.

Redosled učitavanja search index-a je važan i utiče na troškove:

1. Učitajte svaki jezički specifičan i fallback search index iz GitHub repository-ja:
`HackTricks-wiki/hacktricks-searchindex`
2. Samo ako svi kandidati hostovani na GitHub-u ne uspeju, koristite fallback ka mdBook output-u sa istog origin-a.

Nemojte postavljati lokalni `/searchindex.js` fallback ispred bilo kog GitHub fallback-a, kao što je
`searchindex-en.js.gz`. Serviranje `searchindex.js` sa `hacktricks.wiki` u production-u je skupo.

Za ovaj repo, očekivani lokalni fallback je:

`/searchindex.js`

Cloud index ne treba da koristi lokalni fallback sa ovog origin-a. Treba da se oslanja na udaljene
`searchindex-cloud-<lang>.js.gz` fajlove.

## Objavljivanje search index-a

Workflow-i koji objavljuju enkriptovane kompresovane search index-e na
`HackTricks-wiki/hacktricks-searchindex` su:

- `.github/workflows/build_master.yml`
- `.github/workflows/translate_all.yml`

Generisani source fajl je `book/searchindex.js`. Imena objavljenih remote artifact-a su:

- `searchindex-v2-en.json.gz` (preferirani kompaktni index)
- `searchindex-v2-<lang>.json.gz` (preferirani kompaktni index)
- `searchindex-en.js.gz`
- `searchindex-<lang>.js.gz`

Browser loader daje prednost kompaktnom v2 artifact-u i zadržava `.js.gz` artifact kao legacy
fallback. Oba su XOR-enkriptovani gzip payload-i koji koriste ključ definisan u
`theme/ht_searcher.js`.

Loader mora ostati lazy: uobičajena navigacija kroz stranice ne sme kreirati search worker niti
preuzimati index dok posetilac ne otvori ili ne koristi search. Remote kompresovani odgovori se
čuvaju u Cache Storage-u 24 sata po origin-u kako bi ih naredne stranice mogle ponovo koristiti.
Zadržite fallback ka zastarelom cache-u kada osvežavanje isteklog unosa ne uspe.

## Build i validacija

Uobičajene lokalne provere:

- `node --check theme/ht_searcher.js`
- `mdbook build`

Ako `mdbook build` ne uspe, proverite:

- `hacktricks-preprocessor-error.log`
- `hacktricks-preprocessor.log`

## Napomene za uređivanje

- Za pretragu preferirajte `rg`.
- Držite generisani `book/` output van commit-a osim ako to nije izričito zatraženo. Izmene search loader-a su izuzetak kada već izgrađene stranice moraju odmah biti ispravljene.
- Ako menjate ponašanje zajedničkog theme-a, uporedite i ažurirajte odgovarajući fajl u
`/Users/carlospolop/git/hacktricks-cloud`.
- Nemojte vraćati nepovezane lokalne izmene.
