# AGENTS.md

Indicazioni per i futuri agenti che lavorano in questo repository.

## Contesto del repository

Questo è il repository principale mdBook di HackTricks. Il relativo cloud book si trova in:

`/Users/carlospolop/git/hacktricks-cloud`

Le modifiche al comportamento condiviso di theme/search spesso devono essere applicate in entrambi i repository.

## Contratto di caricamento dell'indice di ricerca

La UI di ricerca personalizzata si trova in:

`theme/ht_searcher.js`

Potrebbe esserci anche una copia generata in:

`book/theme/ht_searcher.js`

Se in production viene eseguita la directory `book/` già compilata, aggiorna entrambe le copie oppure ricompila il
book prima del deployment.

L'ordine di caricamento dell'indice di ricerca è importante e sensibile ai costi:

1. Carica ogni indice di ricerca specifico per la lingua e di fallback dal repository GitHub:
`HackTricks-wiki/hacktricks-searchindex`
2. Solo se tutti i candidati ospitati su GitHub falliscono, esegui il fallback sullo stesso origin dell'output mdBook.

Non posizionare il fallback locale `/searchindex.js` prima di qualsiasi fallback ospitato su GitHub come
`searchindex-en.js.gz`. Servire `searchindex.js` da `hacktricks.wiki` in production è costoso.

Per questo repository, il fallback locale previsto è:

`/searchindex.js`

L'indice cloud non deve usare un fallback locale da questo origin. Deve fare affidamento sui file remoti
`searchindex-cloud-<lang>.js.gz`.

## Pubblicazione dell'indice di ricerca

I workflow che pubblicano gli indici di ricerca compressi e cifrati in
`HackTricks-wiki/hacktricks-searchindex` sono:

- `.github/workflows/build_master.yml`
- `.github/workflows/translate_all.yml`

Il file sorgente generato è `book/searchindex.js`. I nomi degli artifact remoti pubblicati sono:

- `searchindex-v2-en.json.gz` (indice compatto preferito)
- `searchindex-v2-<lang>.json.gz` (indice compatto preferito)
- `searchindex-en.js.gz`
- `searchindex-<lang>.js.gz`

Il browser loader preferisce l'artifact compatto v2 e mantiene l'artifact `.js.gz` come fallback legacy. Entrambi sono payload gzip cifrati con XOR usando la chiave definita in `theme/ht_searcher.js`.

Il loader deve rimanere lazy: la normale navigazione tra le pagine non deve creare il search worker né scaricare un indice finché il visitatore non apre o utilizza la ricerca. Le risposte remote compresse vengono mantenute nella Cache Storage per 24 ore per origin, in modo che le pagine successive possano riutilizzarle. Mantieni il fallback della stale cache quando l'aggiornamento di una voce scaduta fallisce.

## Build e validazione

Controlli locali comuni:

- `node --check theme/ht_searcher.js`
- `mdbook build`

Se `mdbook build` fallisce, controlla:

- `hacktricks-preprocessor-error.log`
- `hacktricks-preprocessor.log`

## Note sulla modifica

- Preferisci `rg` per le ricerche.
- Mantieni l'output `book/` generato fuori dai commit, salvo richiesta esplicita. Le correzioni al search loader fanno eccezione quando le pagine già compilate devono essere corrette immediatamente.
- Se modifichi il comportamento condiviso di theme, confronta e aggiorna il file corrispondente in
`/Users/carlospolop/git/hacktricks-cloud`.
- Non annullare modifiche locali non correlate.
