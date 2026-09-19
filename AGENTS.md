# AGENTS.md

Smernice za buduće agente koji rade u ovom repozitorijumu.

## Kontekst repozitorijuma

Ovo je glavni HackTricks mdBook repozitorijum. Povezana cloud knjiga se nalazi na:

`/Users/carlospolop/git/hacktricks-cloud`

Promene zajedničkog theme/search ponašanja često moraju da se primene u oba repozitorijuma.

## Ugovor za učitavanje Search Index-a

Prilagođeni search UI se nalazi u:

`theme/ht_searcher.js`

Može da postoji i generisana kopija na:

`book/theme/ht_searcher.js`

Ako production koristi već izgrađeni `book/` direktorijum, ažurirajte obe kopije ili ponovo izgradite
book pre deployment-a.

Redosled učitavanja search index-a je važan i osetljiv na troškove:

1. Učitajte svaki language-specific i fallback search index iz GitHub repozitorijuma:
`HackTricks-wiki/hacktricks-searchindex`
2. Samo ako svi kandidati hostovani na GitHub-u ne uspeju, pređite na mdBook output sa istog origin-a.

Nemojte postavljati lokalni `/searchindex.js` fallback ispred bilo kog GitHub-hostovanog fallback-a kao što je
`searchindex-en.js.gz`. Serviranje `searchindex.js` sa `hacktricks.wiki` u production-u je skupo.

Za ovaj repo, očekivani lokalni fallback je:

`/searchindex.js`

Cloud index ne treba da koristi lokalni fallback sa ovog origin-a. Treba da se oslanja na udaljene
`searchindex-cloud-<lang>.js.gz` fajlove.

## Objavljivanje Search Index-a

Workflow-i koji objavljuju enkriptovane kompresovane search index-e u
`HackTricks-wiki/hacktricks-searchindex` su:

- `.github/workflows/build_master.yml`
- `.github/workflows/translate_all.yml`

Generisani source fajl je `book/searchindex.js`. Nazivi objavljenih udaljenih artifact-a su:

- `searchindex-v2-en.json.gz` (preferirani kompaktni index)
- `searchindex-v2-<lang>.json.gz` (preferirani kompaktni index)
- `searchindex-en.js.gz`
- `searchindex-<lang>.js.gz`

Browser loader daje prednost kompaktom v2 artifact-u i zadržava `.js.gz` artifact kao legacy
fallback. Oba su XOR-enkriptovani gzip payload-i koji koriste ključ definisan u `theme/ht_searcher.js`.

## Build i validacija

Uobičajene lokalne provere:

- `node --check theme/ht_searcher.js`
- `mdbook build`

Ako `mdbook build` ne uspe, proverite:

- `hacktricks-preprocessor-error.log`
- `hacktricks-preprocessor.log`

## Napomene za uređivanje

- Za pretragu preferirajte `rg`.
- Držite generisani `book/` output van commit-a osim ako to nije izričito zatraženo. Ispravke search loader-a su
  izuzetak kada već izgrađene stranice moraju odmah da budu ispravljene.
- Ako menjate zajedničko theme ponašanje, uporedite i ažurirajte odgovarajući fajl u
`/Users/carlospolop/git/hacktricks-cloud`.
- Nemojte vraćati nepovezane lokalne promene.
