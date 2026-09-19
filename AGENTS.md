# AGENTS.md

Smernice za buduće agente koji rade u ovom repozitorijumu.

## Kontekst repozitorijuma

Ovo je glavni HackTricks mdBook repozitorijum. Povezana cloud knjiga se nalazi na:

`/Users/carlospolop/git/hacktricks-cloud`

Promene zajedničkog ponašanja theme/search često je potrebno primeniti u oba repozitorijuma.

## Ugovor o učitavanju indeksa pretrage

Prilagođeni interfejs za pretragu nalazi se u:

`theme/ht_searcher.js`

Može postojati i generisana kopija na:

`book/theme/ht_searcher.js`

Ako production koristi već izgrađeni `book/` direktorijum, ažurirajte obe kopije ili ponovo izgradite
book pre deployment-a.

Politika izvora indeksa pretrage je važna i osetljiva je po pitanju troškova:

- Na public hostovima učitajte svakog language-specific i fallback kandidata isključivo iz
`HackTricks-wiki/hacktricks-searchindex`. Nikada nemojte koristiti fallback na mdBook output sa istog origin-a;
serviranje velikog indeksa sa `hacktricks.wiki` u production-u je skupo.
- Na localhost, `.local`/`.internal` hostovima, loopback adresama, RFC1918, carrier-grade NAT, link-local ili
private IPv6 adresama, učitajte samo mdBook output sa istog origin-a, kako bi local/container deployment-i
ostali self-contained.

Za ovaj repo, očekivani local fallback je:

`/searchindex.js`

Na private hostovima, cloud indeks nije dostupan sa ovog origin-a i ne sme pokrenuti remote download. Na public
hostovima treba koristiti remote `searchindex-cloud-<lang>.js.gz` fajlove.

## Objavljivanje indeksa pretrage

Workflow-i koji objavljuju enkriptovane kompresovane indekse pretrage u
`HackTricks-wiki/hacktricks-searchindex` su:

- `.github/workflows/build_master.yml`
- `.github/workflows/translate_all.yml`

Generisani source fajl je `book/searchindex.js`. Nazivi objavljenih remote artifact-a su:

- `searchindex-v2-en.json.gz` (preferred compact index)
- `searchindex-v2-<lang>.json.gz` (preferred compact index)
- `searchindex-en.js.gz`
- `searchindex-<lang>.js.gz`

Browser loader daje prednost compact v2 artifact-u i zadržava `.js.gz` artifact kao legacy fallback. Oba su
XOR-enkriptovani gzip payload-i koji koriste ključ definisan u `theme/ht_searcher.js`.

Loader mora ostati lazy: normalna navigacija kroz stranice ne sme kreirati search worker niti preuzimati indeks
dok posetilac ne otvori ili ne upotrebi pretragu. Remote kompresovani response-i se čuvaju u Cache Storage-u
24 časa po origin-u, kako bi naredne stranice mogle ponovo da ih koriste. Zadržite stale-cache fallback
kada osvežavanje isteklog unosa ne uspe.

## Izgradnja i validacija

Uobičajene local provere:

- `node --check theme/ht_searcher.js`
- `mdbook build`

Ako `mdbook build` ne uspe, proverite:

- `hacktricks-preprocessor-error.log`
- `hacktricks-preprocessor.log`

## Napomene za uređivanje

- Prednost dajte alatu `rg` za pretragu.
- Držite generisani `book/` output izvan commit-a osim ako to nije izričito zatraženo. Izmene search loader-a
su izuzetak kada već izgrađene stranice moraju odmah biti ispravljene.
- Ako menjate ponašanje zajedničkog theme-a, uporedite i ažurirajte odgovarajući fajl u
`/Users/carlospolop/git/hacktricks-cloud`.
- Nemojte vraćati nepovezane lokalne izmene.
