# GitHub Issues i pliki repozytorium jako kanał C2

{{#include ../banners/hacktricks-training.md}}

Prywatne repozytorium może rozdzielać **stan sesji** od **transferu payloadów**: zgłoszenia zapisują informacje o każdym hoście i stanie jego handshake, a pliki repozytorium przenoszą zaszyfrowane dane w obu kierunkach. To coś więcej niż samo odpytywanie treści zgłoszenia o polecenia. Zaobserwowana implementacja używa GitHub personal access token (PAT) do uzyskiwania dostępu do obu API.<sup>[[1]](#references)</sup> W przypadku fine-grained PAT tworzenie lub aktualizowanie zgłoszeń wymaga uprawnienia Issues write, a przesyłanie plików — Contents write. Classic PAT wymaga natomiast zakresu `repo`. Każdy, kto zdobędzie token z odpowiednimi uprawnieniami, może uzyskać dostęp do tego samego kanału.<sup>[[2]](#references)[[3]](#references)</sup>

## Handshake zgłoszeń i plików

Jeden z zaobserwowanych przepływów używa krótkiego szesnastkowego ID hosta i następującej maszyny stanów. Dokładny zakres ID, ciągi znaków i prefiksy są znacznikami protokołu, a nie wymaganiami GitHub API.<sup>[[1]](#references)</sup>

1. Po uruchomieniu odpytaj otwarte i zamknięte zgłoszenia za pomocą `GET /repos/{owner}/{repo}/issues?state=open` (oraz `state=closed`), aby znaleźć poprzedni stan sesji. Utwórz otwarte zgłoszenie o tytule `1[ID]` i treści `hel`, używając `POST /repos/{owner}/{repo}/issues`.
2. Odczytaj plik repozytorium, którego nazwa zaczyna się od `2[ID]`; zawiera on publiczny klucz RSA serwera. Wygeneruj nowy 16-bajtowy klucz sesji, zaszyfruj go RSA i prześlij wynik w pliku z prefiksem `1[ID]`.
3. Wyprowadź kolejny IV, wykonując XOR osadzonego IV z tym kluczem sesji. Dla każdego wymienianego pliku użyj losowego 16-bajtowego klucza z jego nazwy, aby zaszyfrować lub odszyfrować zawartość za pomocą AES. Prefiks `2` oznacza dane przesyłane z serwera do hosta; prefiks `1` oznacza dane przesyłane z hosta do serwera. Nazwa pliku zawiera więc informacje o routingu i materiał kluczowy dla danego pliku, a zgłoszenie przechowuje stan.
4. Odczytaj następny plik z prefiksem `2` i sprawdź, czy jego odszyfrowana zawartość jest równa `hel`. Prześlij zaszyfrowane informacje o hoście, a następnie zmień treść zgłoszenia na `hey` za pomocą `PATCH /repos/{owner}/{repo}/issues/{issue_number}`. Dopiero wtedy rozpocznij odpytywanie o polecenia.

GitHub Contents API odczytuje plik za pomocą `GET /repos/{owner}/{repo}/contents/{path}`, a tworzy go lub zastępuje za pomocą `PUT` pod tą ścieżką. W przypadku plików o rozmiarze do 1 MB domyślna odpowiedź JSON zawiera treść zakodowaną w Base64; pliki o rozmiarze od 1 do 100 MB wymagają surowego typu mediów, aby pobrać ich zawartość. Treść żądania przesyłającego plik musi zawierać komunikat commit oraz zawartość pliku zakodowaną w Base64; zastąpienie istniejącego pliku wymaga również aktualnego blob SHA. Te szczegóły API są niezależne od opisanego wyżej protokołu szyfrowania.<sup>[[2]](#references)[[3]](#references)</sup>

W autoryzowanym repozytorium testowym część sterującą opartą na zgłoszeniach można sprawdzić za pomocą REST API (podstaw testowe repozytorium i testowy PAT). Nie umieszczaj aktywnego tokenu w URL-u, treści zgłoszenia ani commitowanym pliku.<sup>[[2]](#references)</sup>

```bash
base="https://api.github.com/repos/$OWNER/$REPO"
curl -fsS -H "Authorization: Bearer $GH_TOKEN" "$base/issues?state=open"
issue_number=$(curl -fsS -X POST -H "Authorization: Bearer $GH_TOKEN" -H 'Accept: application/vnd.github+json' \
  "$base/issues" -d '{"title":"11000","body":"hel"}' | jq -r .number)
curl -fsS -X PATCH -H "Authorization: Bearer $GH_TOKEN" -H 'Accept: application/vnd.github+json' \
  "$base/issues/$issue_number" -d '{"body":"hey"}'
```

Mechanizm **nie** wymaga tytułu issue, znaczników `hel`/`hey` ani konkretnych wyborów szyfrów pokazanych tutaj; te elementy identyfikują jedną implementację. Możliwy do ponownego wykorzystania pomysł polega na oddzieleniu zmiennego stanu hosta od dwukierunkowych zaszyfrowanych obiektów oraz powiązaniu obu z identyfikatorem hosta.<sup>[[1]](#references)</sup> Informacje o innym transporcie opartym na GitHub issue znajdziesz w [notatkach o niestandardowym listenerze AdaptixC2](basic-forensic-methodology/adaptixc2-config-extraction-and-ttps.md#custom-listener-profiles-dont-hard-code-only-the-classic-http-schema). Informacje o awaryjnym rozwiązaniu opartym na komentarzach do issue, które rotuje dane uwierzytelniające repozytorium zamiast przenosić stan sesji, znajdziesz w sekcji [Usługi internetowe i resolvery dead-drop](../privacy/offensive-infrastructure-and-attribution-evasion.md#web-services-and-dead-drop-resolvers).

## References

- [1] [Kaspersky Securelist – Operacja FlashHole](https://securelist.com/lazarus-operation-flashhole/121541/)
- [2] [GitHub Docs – Punkty końcowe REST API dla issue](https://docs.github.com/en/rest/issues/issues)
- [3] [GitHub Docs – Punkty końcowe REST API dla zawartości repozytorium](https://docs.github.com/en/rest/repos/contents)
