# AGENTS.md

Linee guida per i futuri agent che lavorano in questo repository.

## Contesto del repository

Questo è il repository principale mdBook di HackTricks. Il libro cloud correlato si trova in:

`/Users/carlospolop/git/hacktricks-cloud`

Le modifiche al comportamento condiviso di theme/search spesso devono essere applicate in entrambi i repository.

## Contratto di caricamento del search index

L'interfaccia custom di search si trova in:

`theme/ht_searcher.js`

Potrebbe esserci anche una copia generata in:

`book/theme/ht_searcher.js`

Se la produzione esegue il deploy della directory `book/` già compilata, aggiorna entrambe le copie oppure ricompila il
book prima del deploy.

La policy della sorgente del search index è importante e sensibile ai costi:

- Sugli host pubblici, carica ogni candidato specifico per la lingua e di fallback solo da
`HackTricks-wiki/hacktricks-searchindex`. Non usare mai come fallback lo stesso output mdBook dell'origine;
servire il grande index da `hacktricks.wiki` in produzione è costoso.
- Su localhost, sugli host `.local`/`.internal`, sul loopback, sugli indirizzi RFC1918, CGNAT, link-local o
sugli indirizzi IPv6 privati, carica solo l'output mdBook della stessa origine, in modo che i deploy
locali/in container rimangano autonomi.

Per questo repository, il fallback locale previsto è:

`/searchindex.js`

Sugli host privati, il cloud index non è disponibile da questa origine e non deve attivare un download
remoto. Sugli host pubblici deve usare i file remoti `searchindex-cloud-<lang>.js.gz`.

## Pubblicazione del search index

I workflow che pubblicano i search index compressi e cifrati in
`HackTricks-wiki/hacktricks-searchindex` sono:

- `.github/workflows/build_master.yml`
- `.github/workflows/translate_all.yml`

Il file sorgente generato è `book/searchindex.js`. I nomi degli artifact remoti pubblicati sono:

- `searchindex-v2-en.json.gz` (compact index preferito)
- `searchindex-v2-<lang>.json.gz` (compact index preferito)
- `searchindex-en.js.gz`
- `searchindex-<lang>.js.gz`

Il browser loader preferisce l'artifact compatto v2 e mantiene l'artifact `.js.gz` come fallback legacy.
Entrambi sono payload gzip cifrati con XOR usando la chiave definita in `theme/ht_searcher.js`.

Il loader deve rimanere lazy: la normale navigazione delle pagine non deve creare il search worker né scaricare un
index finché il visitatore non apre o utilizza la search. Le risposte remote compresse vengono persistite nella Cache
Storage per 24 ore per origine, in modo che le pagine successive possano riutilizzarle. Mantieni il fallback
alla cache obsoleta quando l'aggiornamento di una voce scaduta fallisce.

## Build e validazione

Controlli locali comuni:

- `node --check theme/ht_searcher.js`
- `mdbook build`

Se `mdbook build` fallisce, controlla:

- `hacktricks-preprocessor-error.log`
- `hacktricks-preprocessor.log`

## Note sulle modifiche

- Preferisci `rg` per le ricerche.
- Mantieni l'output `book/` generato fuori dai commit, salvo esplicita richiesta. Le correzioni al search loader
sono un'eccezione quando le pagine già compilate devono essere corrette immediatamente.
- Se modifichi il comportamento condiviso del theme, confronta e aggiorna il file corrispondente in
`/Users/carlospolop/git/hacktricks-cloud`.
- Non annullare modifiche locali non correlate.
