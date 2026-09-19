# AGENTS.md

Wskazówki dla przyszłych agentów pracujących w tym repozytorium.

## Kontekst repozytorium

To główne repozytorium HackTricks mdBook. Powiązana książka cloud znajduje się pod adresem:

`/Users/carlospolop/git/hacktricks-cloud`

Zmiany dotyczące współdzielonego theme/zachowania wyszukiwania często trzeba zastosować w obu repozytoriach.

## Kontrakt ładowania indeksu wyszukiwania

Niestandardowy interfejs wyszukiwania znajduje się w:

`theme/ht_searcher.js`

Może również istnieć wygenerowana kopia pod adresem:

`book/theme/ht_searcher.js`

Jeśli produkcja wdraża już zbudowany katalog `book/`, zaktualizuj obie kopie albo przebuduj
book przed wdrożeniem.

Polityka źródła indeksu wyszukiwania jest ważna i wrażliwa na koszty:

- Na publicznych hostach ładuj każdego kandydata specyficznego dla języka oraz fallback wyłącznie z
`HackTricks-wiki/hacktricks-searchindex`. Nigdy nie używaj fallbacku do wyjścia mdBook z tego samego originu;
serwowanie dużego indeksu z `hacktricks.wiki` w produkcji jest kosztowne.
- Na localhost, hostach `.local`/`.internal`, loopback, RFC1918, carrier-grade NAT, adresach link-local lub
prywatnych adresach IPv6 ładuj wyłącznie wyjście mdBook z tego samego originu, aby lokalne/wdrożenia kontenerowe
pozostały samowystarczalne. Dla strony w języku innym niż angielski najpierw wypróbuj lokalną ścieżkę z prefiksem języka
(na przykład `/es/searchindex.js`), a główny indeks angielski użyj wyłącznie jako fallbacku.

Dla tego repozytorium oczekiwanym lokalnym fallbackiem jest:

`/searchindex.js`

Na prywatnych hostach indeks cloud jest niedostępny z tego originu i nie może powodować zdalnego pobierania.
Na publicznych hostach należy używać zdalnych plików `searchindex-cloud-<lang>.js.gz`.

## Publikowanie indeksu wyszukiwania

Workflowy publikujące zaszyfrowane, skompresowane indeksy wyszukiwania do
`HackTricks-wiki/hacktricks-searchindex` to:

- `.github/workflows/build_master.yml`
- `.github/workflows/translate_all.yml`

Wygenerowany plik źródłowy to `book/searchindex.js`. Nazwy publikowanych zdalnych artefaktów to:

- `searchindex-v2-en.json.gz` (preferowany kompaktowy indeks)
- `searchindex-v2-<lang>.json.gz` (preferowany kompaktowy indeks)
- `searchindex-en.js.gz`
- `searchindex-<lang>.js.gz`

Loader przeglądarkowy preferuje kompaktowy artefakt v2 i zachowuje artefakt `.js.gz` jako legacy
fallback. Oba są zaszyfrowanymi za pomocą XOR payloadami gzip, używającymi klucza zdefiniowanego w `theme/ht_searcher.js`.

Loader musi pozostać lazy: zwykła nawigacja po stronach nie może tworzyć search workera ani pobierać indeksu,
dopóki odwiedzający nie otworzy lub nie użyje wyszukiwania. Zdalne skompresowane odpowiedzi są przechowywane
w Cache Storage przez 24 godziny dla każdego originu, aby kolejne strony mogły ich ponownie użyć. Zachowaj
stale-cache fallback na wypadek, gdy odświeżenie wygasłego wpisu się nie powiedzie.

## Budowanie i walidacja

Typowe kontrole lokalne:

- `node --check theme/ht_searcher.js`
- `mdbook build`

Jeśli `mdbook build` zakończy się niepowodzeniem, sprawdź:

- `hacktricks-preprocessor-error.log`
- `hacktricks-preprocessor.log`

## Uwagi dotyczące edycji

- Preferuj `rg` do wyszukiwania.
- Nie umieszczaj wygenerowanego wyjścia `book/` w commitach, chyba że wyraźnie o to poproszono. Wyjątkiem są poprawki
  search loadera, gdy już zbudowane strony muszą zostać natychmiast skorygowane.
- Jeśli zmieniasz współdzielone zachowanie theme, porównaj i zaktualizuj odpowiadający plik w
  `/Users/carlospolop/git/hacktricks-cloud`.
- Nie cofaj niezwiązanych lokalnych zmian.
