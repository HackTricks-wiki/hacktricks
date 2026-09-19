# AGENTS.md

Smernice za buduće agente koji rade u ovom repozitorijumu.

## Kontekst repozitorijuma

Ovo je glavni HackTricks mdBook repozitorijum. Povezana cloud knjiga nalazi se na:

`/Users/carlospolop/git/hacktricks-cloud`

Izmene deljenog ponašanja theme/search često treba primeniti u oba repozitorijuma.

## Ugovor o učitavanju indeksa pretrage

Prilagođeni interfejs za pretragu nalazi se u:

`theme/ht_searcher.js`

Može postojati i generisana kopija na lokaciji:

`book/theme/ht_searcher.js`

Ako production koristi već izgrađeni direktorijum `book/`, ažurirajte obe kopije ili ponovo izgradite
knjigu pre deployment-a.

Politika izvora search index-a je važna i osetljiva na troškove:

- Na public hostovima, učitajte svakog kandidata specifičnog za jezik i fallback kandidata samo iz
`HackTricks-wiki/hacktricks-searchindex`. Nikada nemojte koristiti fallback ka mdBook output-u sa istog origin-a;
serviranje velikog index-a sa `hacktricks.wiki` u production-u je skupo.
- Na localhost-u, `.local`/`.internal` hostovima, loopback-u, RFC1918, carrier-grade NAT, link-local ili
private IPv6 adresama, učitajte samo mdBook output sa istog origin-a kako bi local/container deployment-i
ostali samostalni. Za non-English stranicu, prvo pokušajte sa lokalnom putanjom sa prefiksom jezika (na
primer `/es/searchindex.js`) i koristite root English index samo kao fallback.

Za ovaj repozitorijum očekivani lokalni fallback je:

`/searchindex.js`

Na private hostovima cloud index nije dostupan sa ovog origin-a i ne sme pokrenuti remote download. Na public
hostovima treba koristiti remote `searchindex-cloud-<lang>.js.gz` fajlove.

## Objavljivanje search index-a

Workflow-i koji objavljuju encrypted compressed search index-e u
`HackTricks-wiki/hacktricks-searchindex` su:

- `.github/workflows/build_master.yml`
- `.github/workflows/translate_all.yml`

Generisani source fajl je `book/searchindex.js`. Objavljena imena remote artifact-a su:

- `searchindex-v2-en.json.gz` (preferred compact index)
- `searchindex-v2-<lang>.json.gz` (preferred compact index)
- `searchindex-en.js.gz`
- `searchindex-<lang>.js.gz`

Browser loader daje prednost compact v2 artifact-u i zadržava `.js.gz` artifact kao legacy fallback. Oba su
XOR-encrypted gzip payload-i koji koriste ključ definisan u `theme/ht_searcher.js`.

Loader mora ostati lazy: normalna navigacija stranicama ne sme kreirati search worker niti preuzimati index
dok posetilac ne otvori ili ne upotrebi pretragu. Remote compressed odgovori čuvaju se u Cache Storage-u
24 sata po origin-u kako bi naredne stranice mogle da ih ponovo koriste. Sačuvajte stale-cache fallback
kada osvežavanje isteklog unosa ne uspe.

## Izgradnja i validacija

Uobičajene lokalne provere:

- `node --check theme/ht_searcher.js`
- `mdbook build`

Ako `mdbook build` ne uspe, proverite:

- `hacktricks-preprocessor-error.log`
- `hacktricks-preprocessor.log`

## Napomene o uređivanju

- Za pretragu preferirajte `rg`.
- Držite generisani `book/` output izvan commit-a osim ako to nije izričito zatraženo. Izmene search loader-a
su izuzetak kada već izgrađene stranice moraju odmah biti ispravljene.
- Ako menjate ponašanje deljenog theme-a, uporedite i ažurirajte odgovarajući fajl u
`/Users/carlospolop/git/hacktricks-cloud`.
- Nemojte vraćati nepovezane lokalne izmene.
