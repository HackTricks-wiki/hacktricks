# AGENTS.md

Wytyczne dla przyszłych agentów pracujących w tym repozytorium.

## Kontekst repozytorium

To główne repozytorium mdBook HackTricks. Powiązana książka cloud znajduje się w:

`/Users/carlospolop/git/hacktricks-cloud`

Zmiany dotyczące współdzielonego theme/search behavior często należy zastosować w obu repozytoriach.

## Kontrakt ładowania indeksu wyszukiwania

Niestandardowy interfejs search znajduje się w:

`theme/ht_searcher.js`

Może również istnieć wygenerowana kopia w:

`book/theme/ht_searcher.js`

Jeśli produkcja wdraża już zbudowany katalog `book/`, zaktualizuj obie kopie albo przebuduj
book przed wdrożeniem.

Kolejność ładowania indeksu wyszukiwania jest istotna i ma wpływ na koszty:

1. Załaduj każdy indeks wyszukiwania właściwy dla języka oraz indeks fallback z repozytorium GitHub:
`HackTricks-wiki/hacktricks-searchindex`
2. Dopiero jeśli wszystkie kandydaty hostowane w GitHub zawiodą, użyj fallbacku do wyniku mdBook z tego samego originu.

Nie umieszczaj lokalnego fallbacku `/searchindex.js` przed żadnym fallbackiem hostowanym w GitHub, takim jak
`searchindex-en.js.gz`. Udostępnianie `searchindex.js` z `hacktricks.wiki` w produkcji jest kosztowne.

Dla tego repozytorium oczekiwany lokalny fallback to:

`/searchindex.js`

Indeks cloud nie powinien używać lokalnego fallbacku z tego originu. Powinien korzystać ze zdalnych
plików `searchindex-cloud-<lang>.js.gz`.

## Publikowanie indeksu wyszukiwania

Workflowy publikujące zaszyfrowane, skompresowane indeksy wyszukiwania w
`HackTricks-wiki/hacktricks-searchindex` to:

- `.github/workflows/build_master.yml`
- `.github/workflows/translate_all.yml`

Wygenerowany plik źródłowy to `book/searchindex.js`. Nazwy publikowanych zdalnych artefaktów to:

- `searchindex-v2-en.json.gz` (preferowany kompaktowy indeks)
- `searchindex-v2-<lang>.json.gz` (preferowany kompaktowy indeks)
- `searchindex-en.js.gz`
- `searchindex-<lang>.js.gz`

Loader przeglądarkowy preferuje kompaktowy artefakt v2 i zachowuje artefakt `.js.gz` jako
legacy fallback. Oba są zaszyfrowanymi payloadami gzip z użyciem klucza zdefiniowanego w `theme/ht_searcher.js`.

Loader musi pozostać lazy: zwykła nawigacja między stronami nie może tworzyć workera search ani pobierać indeksu, dopóki odwiedzający nie otworzy lub nie użyje search. Zdalne skompresowane odpowiedzi są przechowywane w Cache
Storage przez 24 godziny dla każdego originu, aby kolejne strony mogły z nich korzystać. Zachowaj fallback
do nieaktualnego cache, gdy odświeżenie wygasłego wpisu się nie powiedzie.

## Budowanie i walidacja

Typowe lokalne kontrole:

- `node --check theme/ht_searcher.js`
- `mdbook build`

Jeśli `mdbook build` zakończy się niepowodzeniem, sprawdź:

- `hacktricks-preprocessor-error.log`
- `hacktricks-preprocessor.log`

## Uwagi dotyczące edycji

- Preferuj `rg` do wyszukiwania.
- Nie dodawaj wygenerowanego wyniku `book/` do commitów, chyba że wyraźnie o to poproszono. Wyjątkiem są poprawki search loadera, gdy już zbudowane strony muszą zostać natychmiast poprawione.
- Jeśli zmieniasz zachowanie współdzielonego theme, porównaj i zaktualizuj odpowiedni plik w
`/Users/carlospolop/git/hacktricks-cloud`.
- Nie cofaj niezwiązanych lokalnych zmian.
