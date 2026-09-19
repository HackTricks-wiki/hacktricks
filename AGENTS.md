# AGENTS.md

Wskazówki dla przyszłych agentów pracujących w tym repozytorium.

## Kontekst repozytorium

To jest główne repozytorium HackTricks mdBook. Powiązana cloud book znajduje się pod adresem:

`/Users/carlospolop/git/hacktricks-cloud`

Zmiany dotyczące współdzielonego theme/search behavior często trzeba zastosować w obu repozytoriach.

## Kontrakt ładowania indeksu wyszukiwania

Niestandardowy interfejs search znajduje się w:

`theme/ht_searcher.js`

Może także istnieć wygenerowana kopia pod adresem:

`book/theme/ht_searcher.js`

Jeśli production wdraża już zbudowany katalog `book/`, zaktualizuj obie kopie lub przebuduj
book przed deploymentem.

Polityka źródła search index jest ważna i wrażliwa na koszty:

- Na publicznych hostach ładuj każdego language-specific i fallback candidate wyłącznie z
`HackTricks-wiki/hacktricks-searchindex`. Nigdy nie stosuj fallbacku do outputu mdBook z tego samego originu;
serwowanie dużego indexu z `hacktricks.wiki` w production jest kosztowne.
- Na localhost, hostach `.local`/`.internal`, loopback, RFC1918, carrier-grade NAT, link-local lub
prywatnych adresach IPv6 ładuj wyłącznie output mdBook z tego samego originu, aby lokalne/container deployments
pozostały self-contained.

Dla tego repozytorium oczekiwany local fallback to:

`/searchindex.js`

Na prywatnych hostach cloud index jest niedostępny z tego originu i nie może powodować remote
downloadu. Na publicznych hostach należy używać zdalnych plików `searchindex-cloud-<lang>.js.gz`.

## Publikowanie indeksu wyszukiwania

Workflowy publikujące zaszyfrowane skompresowane search indexes do
`HackTricks-wiki/hacktricks-searchindex` to:

- `.github/workflows/build_master.yml`
- `.github/workflows/translate_all.yml`

Wygenerowany source file to `book/searchindex.js`. Nazwy publikowanych remote artifacts to:

- `searchindex-v2-en.json.gz` (preferowany compact index)
- `searchindex-v2-<lang>.json.gz` (preferowany compact index)
- `searchindex-en.js.gz`
- `searchindex-<lang>.js.gz`

Browser loader preferuje compact v2 artifact i zachowuje artifact `.js.gz` jako legacy
fallback. Oba są payloadami gzip zaszyfrowanymi XOR z użyciem klucza zdefiniowanego w `theme/ht_searcher.js`.

Loader musi pozostać lazy: standardowa nawigacja po stronach nie może tworzyć search workera ani pobierać
indexu, dopóki visitor nie otworzy lub nie użyje search. Zdalne skompresowane responses są przechowywane w Cache
Storage przez 24 godziny dla każdego originu, aby kolejne strony mogły ich ponownie użyć. Zachowaj stale-cache
fallback, gdy odświeżenie wygasłego wpisu zakończy się niepowodzeniem.

## Build i walidacja

Typowe local checks:

- `node --check theme/ht_searcher.js`
- `mdbook build`

Jeśli `mdbook build` zakończy się niepowodzeniem, sprawdź:

- `hacktricks-preprocessor-error.log`
- `hacktricks-preprocessor.log`

## Uwagi dotyczące edycji

- Do wyszukiwania preferuj `rg`.
- Nie umieszczaj wygenerowanego outputu `book/` w commitach, chyba że wyraźnie o to poproszono. Search loader fixes
są wyjątkiem, gdy już zbudowane pages muszą zostać natychmiast poprawione.
- Jeśli zmieniasz shared theme behavior, porównaj i zaktualizuj odpowiadający plik w
`/Users/carlospolop/git/hacktricks-cloud`.
- Nie wycofuj niezwiązanych local changes.
