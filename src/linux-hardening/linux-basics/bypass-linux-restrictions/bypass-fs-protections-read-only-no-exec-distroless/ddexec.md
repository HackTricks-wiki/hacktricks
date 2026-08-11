# DDexec / EverythingExec

## Kontekst

W systemie Linux, aby uruchomić program, musi on istnieć jako plik i musi być w jakiś sposób dostępny w hierarchii systemu plików (tak właśnie działa `execve()`). Plik ten może znajdować się na dysku lub w pamięci RAM (tmpfs, memfd), ale potrzebujesz ścieżki do pliku. Dzięki temu bardzo łatwo kontrolować, co jest uruchamiane w systemie Linux, wykrywać zagrożenia i narzędzia atakującego lub całkowicie uniemożliwić mu próbę wykonania czegokolwiek własnego (_np._ nie zezwalając użytkownikom bez uprawnień na umieszczanie plików wykonywalnych w dowolnym miejscu).

Ta technika ma jednak to wszystko zmienić. Jeśli nie możesz uruchomić wybranego procesu... **w takim razie przejmujesz już istniejący**.

Ta technika pozwala **ominąć typowe mechanizmy ochrony, takie jak read-only, noexec, file-name whitelisting i hash whitelisting**.<sup>[[1]](#references)</sup>

## Zależności

Końcowy skrypt zależy od następujących narzędzi, aby działać. Muszą one być dostępne w atakowanym systemie (domyślnie znajdziesz je wszędzie):
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

Jeśli możesz dowolnie modyfikować pamięć procesu, możesz przejąć nad nim kontrolę. Można to wykorzystać do przejęcia już istniejącego procesu i zastąpienia go innym programem. Możemy to osiągnąć, korzystając z syscalla `ptrace()` (co wymaga możliwości wykonywania syscalli lub dostępności `gdb` w systemie) albo, co ciekawsze, zapisując do `/proc/$pid/mem`.<sup>[[1]](#references)</sup>

Plik `/proc/$pid/mem` jest mapowaniem jeden do jednego całej przestrzeni adresowej procesu (_np._ od `0x0000000000000000` do `0x7ffffffffffff000` w x86-64). Oznacza to, że odczyt z tego pliku lub zapis do niego pod offsetem `x` jest tym samym co odczyt lub modyfikacja zawartości pod adresem wirtualnym `x`.

Teraz musimy zmierzyć się z czterema podstawowymi problemami:

- Ogólnie rzecz biorąc, tylko root i właściciel pliku mogą go modyfikować.
- ASLR.
- Jeśli spróbujemy odczytać lub zapisać adres, który nie jest zmapowany w przestrzeni adresowej programu, otrzymamy błąd I/O.

Problemy te mają rozwiązania, które nie są idealne, ale są skuteczne:

- Większość interpreterów shell umożliwia tworzenie deskryptorów plików, które będą następnie dziedziczone przez procesy potomne. Możemy utworzyć fd wskazujący na plik `mem` shell z uprawnieniami do zapisu... dzięki temu procesy potomne korzystające z tego fd będą mogły modyfikować pamięć shell.
- ASLR nie stanowi nawet problemu — możemy sprawdzić plik `maps` shell lub dowolny inny plik z procfs, aby uzyskać informacje o przestrzeni adresowej procesu.
- Musimy więc wykonać `lseek()` na pliku. Z poziomu shell nie można tego zrobić bez użycia osławionego `dd`.

### Szczegóły

Kroki są stosunkowo proste i nie wymagają żadnej specjalistycznej wiedzy, aby je zrozumieć:<sup>[[1]](#references)</sup>

- Przeanalizuj binary, który chcemy uruchomić, oraz loader, aby ustalić, jakich mappingów wymagają. Następnie przygotuj "shell"code, który, ogólnie rzecz biorąc, wykona te same kroki, co kernel przy każdym wywołaniu `execve()`:
- Utwórz wspomniane mappingi.
- Wczytaj do nich binary.
- Skonfiguruj uprawnienia.
- Na koniec zainicjalizuj stack argumentami programu i umieść auxiliary vector (wymagany przez loader).
- Przeskocz do loadera i pozwól mu wykonać resztę (załadować biblioteki wymagane przez program).
- Z pliku `syscall` uzyskaj adres, pod który proces powróci po syscallu, który wykonuje.
- Nadpisz to miejsce, które będzie executable, naszym shellcode (przez `mem` możemy modyfikować strony bez uprawnień do zapisu).
- Przekaż program, który chcemy uruchomić, na stdin procesu (zostanie `read()` przez wspomniany "shell"code).
- W tym momencie loader musi załadować niezbędne biblioteki naszego programu i przeskoczyć do niego.

**Sprawdź tool w** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec).<sup>[[1]](#references)</sup>

## EverythingExec

Istnieje kilka alternatyw dla `dd`, z których jedną, `tail`, jest obecnie domyślny program używany do wykonywania `lseek()` w pliku `mem` (co było jedynym powodem używania `dd`). Wspomniane alternatywy to:<sup>[[1]](#references)</sup>
```bash
tail
hexdump
cmp
xxd
```
Ustawiając zmienną `SEEKER`, możesz zmienić używany seeker, _np._:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Jeśli znajdziesz inny poprawny seeker, który nie został zaimplementowany w skrypcie, nadal możesz go użyć, ustawiając zmienną `SEEKER_ARGS`:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Zablokujcie to, EDR-y.

## References

- [1] [DDexec: Technika uruchamiania plików binarnych bez użycia plików i w sposób ukryty w systemie Linux](https://github.com/arget13/DDexec)
{{#include ../../../../banners/hacktricks-training.md}}
