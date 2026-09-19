# AGENTS.md

Indicazioni per i futuri agent che lavorano in questo repository.

## Contesto del repository

Questo è il repository principale HackTricks mdBook. Il relativo cloud book si trova in:

`/Users/carlospolop/git/hacktricks-cloud`

Le modifiche al comportamento condiviso di theme/search spesso devono essere applicate in entrambi i repository.

## Contratto di caricamento dell'indice di ricerca

La UI di ricerca personalizzata si trova in:

`theme/ht_searcher.js`

Potrebbe esserci anche una copia generata in:

`book/theme/ht_searcher.js`

Se in produzione viene distribuita la directory `book/` già compilata, aggiorna entrambe le copie oppure ricompila il book.

La policy relativa all'origine dell'indice di ricerca è importante e sensibile ai costi:

- Sugli host pubblici, carica ogni candidato specifico per la lingua e di fallback esclusivamente da `HackTricks-wiki/hacktricks-searchindex`. Non usare mai come fallback l'output mdBook della stessa origine; distribuire il grande indice da `hacktricks.wiki` in produzione è costoso.
- Su localhost, sugli host `.local`/`.internal`, loopback, RFC1918, carrier-grade NAT, indirizzi link-local o indirizzi IPv6 privati, carica esclusivamente l'output mdBook della stessa origine, in modo che le distribuzioni locali/in container rimangano autosufficienti. Per una pagina non inglese, prova prima il percorso locale con prefisso della lingua (ad esempio `/es/searchindex.js`) e usa l'indice inglese nella root solo come fallback.

Per questo repository, il fallback locale previsto è:

`/searchindex.js`

Sugli host privati, l'indice cloud non è disponibile da questa origine e non deve avviare un download remoto. Sugli host pubblici deve usare i file remoti `searchindex-cloud-<lang>.js.gz`.

## Pubblicazione dell'indice di ricerca

I workflow che pubblicano gli indici di ricerca compressi e cifrati su `HackTricks-wiki/hacktricks-searchindex` sono:

- `.github/workflows/build_master.yml`
- `.github/workflows/translate_all.yml`

Il file sorgente generato è `book/searchindex.js`. I nomi degli artifact remoti pubblicati sono:

- `searchindex-v2-en.json.gz` (indice compatto preferito)
- `searchindex-v2-<lang>.json.gz` (indice compatto preferito)
- `searchindex-en.js.gz`
- `searchindex-<lang>.js.gz`

Il browser loader preferisce l'artifact compatto v2 e mantiene l'artifact `.js.gz` come fallback legacy. Entrambi sono payload gzip cifrati con XOR usando la chiave definita in `theme/ht_searcher.js`.

Il loader deve rimanere lazy: la normale navigazione tra le pagine non deve creare il search worker né scaricare un indice finché il visitatore non apre o utilizza la ricerca. Le risposte remote compresse vengono conservate nella Cache Storage per 24 ore per origine, così le pagine successive possono riutilizzarle. Mantieni il fallback alla cache obsoleta quando l'aggiornamento di una voce scaduta non riesce.

## Compilazione e validazione

Controlli locali comuni:

- `node --check theme/ht_searcher.js`
- `mdbook build`

Se `mdbook build` fallisce, controlla:

- `hacktricks-preprocessor-error.log`
- `hacktricks-preprocessor.log`

## Note sulla modifica

- Preferisci `rg` per le ricerche.
- Mantieni l'output `book/` generato fuori dai commit, salvo richiesta esplicita. Le correzioni del search loader fanno eccezione quando le pagine già compilate devono essere corrette immediatamente.
- Se modifichi il comportamento condiviso di theme, confronta e aggiorna il file corrispondente in
`/Users/carlospolop/git/hacktricks-cloud`.
- Non annullare modifiche locali non correlate.
