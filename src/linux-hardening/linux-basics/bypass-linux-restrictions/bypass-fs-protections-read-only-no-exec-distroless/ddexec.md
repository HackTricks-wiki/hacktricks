# DDexec / EverythingExec

{{#include ../../../../banners/hacktricks-training.md}}

## Kontekst

W systemie Linux, aby uruchomić program, musi on istnieć jako plik i być w pewien sposób dostępny poprzez hierarchię systemu plików (tak właśnie działa `execve()`). Plik ten może znajdować się na dysku lub w pamięci RAM (tmpfs, memfd), ale potrzebujesz ścieżki do pliku. Dzięki temu bardzo łatwo kontrolować to, co jest uruchamiane w systemie Linux, wykrywać zagrożenia i narzędzia atakującego oraz uniemożliwiać im podejmowanie prób uruchomienia czegokolwiek własnego (_np._ nie zezwalając nieuprzywilejowanym użytkownikom na umieszczanie plików wykonywalnych w dowolnym miejscu).

Ta technika ma jednak całkowicie to zmienić. Jeśli nie możesz uruchomić wybranego procesu... **przejmujesz już istniejący**.

Ta technika pozwala **ominąć typowe mechanizmy ochrony, takie jak read-only, noexec, whitelistowanie nazw plików i whitelistowanie hashy**.<sup>[[1]](#references)</sup>

## Zależności

Końcowy skrypt zależy od poniższych narzędzi, aby działać; muszą one być dostępne w atakowanym systemie (domyślnie znajdziesz je wszędzie):
```
dd
bash | zsh | ash (busybox)
head
tail
cut
grep
od
readlink
wc
tr
base64
```
## Technika

Jeśli możesz dowolnie modyfikować pamięć procesu, możesz przejąć nad nim kontrolę. Można to wykorzystać do przejęcia już istniejącego procesu i zastąpienia go innym programem. Możemy to osiągnąć za pomocą syscalla `ptrace()` (co wymaga możliwości wykonywania syscalli lub dostępności gdb w systemie) albo, co ciekawsze, zapisując do `/proc/$pid/mem`.<sup>[[1]](#references)</sup>

Plik `/proc/$pid/mem` jest odwzorowaniem jeden do jednego całej przestrzeni adresowej procesu (_np._ od `0x0000000000000000` do `0x7ffffffffffff000` w x86-64). Oznacza to, że odczyt z tego pliku lub zapis do niego pod offsetem `x` jest równoznaczny z odczytem lub modyfikacją zawartości pod adresem wirtualnym `x`.

Teraz musimy zmierzyć się z czterema podstawowymi problemami:

- Ogólnie tylko root i właściciel programu mogą go modyfikować.
- ASLR.
- Jeśli spróbujemy odczytać lub zapisać adres, który nie jest odwzorowany w przestrzeni adresowej programu, otrzymamy błąd I/O.

Problemy te mają rozwiązania, które — choć nie są idealne — dobrze spełniają swoje zadanie:

- Większość interpreterów shell pozwala na tworzenie deskryptorów plików, które następnie będą dziedziczone przez procesy potomne. Możemy utworzyć fd wskazujący na plik `mem` shella z uprawnieniami do zapisu... dzięki temu procesy potomne korzystające z tego fd będą mogły modyfikować pamięć shella.
- ASLR nie stanowi nawet problemu — możemy sprawdzić plik `maps` shella lub dowolny inny plik z procfs, aby uzyskać informacje o przestrzeni adresowej procesu.
- Musimy więc wykonać `lseek()` na pliku. Z poziomu shella nie można tego zrobić bez użycia niesławnego `dd`.

### Bardziej szczegółowo

Kroki są stosunkowo proste i nie wymagają żadnej specjalistycznej wiedzy, aby je zrozumieć:<sup>[[1]](#references)</sup>

- Przeanalizuj plik binarny, który chcemy uruchomić, oraz loader, aby ustalić, jakich mapowań potrzebują. Następnie przygotuj "shell"code, który w ogólnym zarysie wykona te same kroki, co kernel przy każdym wywołaniu `execve()`:
- Utwórz wspomniane mapowania.
- Wczytaj do nich pliki binarne.
- Skonfiguruj uprawnienia.
- Na koniec zainicjalizuj stos argumentami programu i umieść na nim wektor pomocniczy (wymagany przez loader).
- Przeskocz do loadera i pozwól mu wykonać resztę (załadować biblioteki wymagane przez program).
- Uzyskaj z pliku `syscall` adres, pod który proces powróci po zakończeniu wykonywanego syscalla.
- Nadpisz to miejsce, które będzie wykonywalne, naszym shellcode'em (za pośrednictwem `mem` możemy modyfikować strony bez uprawnień do zapisu).
- Przekaż program, który chcemy uruchomić, na stdin procesu (zostanie `read()` przez wspomniany "shell"code).
- W tym momencie loader zajmie się załadowaniem niezbędnych bibliotek naszego programu i przeskoczy do niego.

**Sprawdź narzędzie na stronie** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec).<sup>[[1]](#references)</sup>

## EverythingExec

Istnieje kilka alternatyw dla `dd`, z których jedna — `tail` — jest obecnie domyślnym programem używanym do wykonywania `lseek()` w pliku `mem` (co było jedynym powodem używania `dd`). Wspomniane alternatywy to:<sup>[[1]](#references)</sup>
```bash
tail
hexdump
cmp
xxd
```
Ustawiając zmienną `SEEKER`, możesz zmienić używany mechanizm wyszukiwania, _np._:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Jeśli znajdziesz inny prawidłowy seeker, który nie został zaimplementowany w skrypcie, nadal możesz go użyć, ustawiając zmienną `SEEKER_ARGS`:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Zablokujcie to, EDR-y.

## References

- [1] [DDexec: Technika uruchamiania plików binarnych bez użycia plików i w sposób ukryty w systemie Linux](https://github.com/arget13/DDexec)
{{#include ../../../../banners/hacktricks-training.md}}
