# DDexec / EverythingExec

{{#include ../../../../banners/hacktricks-training.md}}

## Kontekst

W systemie Linux, aby uruchomić program, musi on istnieć jako plik i być w jakiś sposób dostępny w hierarchii systemu plików (tak właśnie działa `execve()`). Plik ten może znajdować się na dysku lub w pamięci RAM (tmpfs, memfd), ale potrzebujesz filepath. Dzięki temu bardzo łatwo kontrolować, co jest uruchamiane w systemie Linux, wykrywać threats i narzędzia attackera albo całkowicie uniemożliwić im próbę wykonania czegokolwiek własnego (_np._ nie zezwalając unprivileged users na umieszczanie executable files w dowolnym miejscu).

Ta technique ma jednak to wszystko zmienić. Jeśli nie możesz uruchomić procesu, którego potrzebujesz... **przejmij już istniejący**.

Ta technique pozwala **omijać typowe protection techniques, takie jak read-only, noexec, file-name whitelisting, hash whitelisting...**

## Zależności

Final script zależy od poniższych tools, aby działać; muszą one być dostępne w atakowanym systemie (domyślnie znajdziesz je wszędzie):
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

Jeśli możesz dowolnie modyfikować pamięć procesu, możesz przejąć nad nim kontrolę. Można to wykorzystać do przejęcia już istniejącego procesu i zastąpienia go innym programem. Możemy to osiągnąć za pomocą syscalla `ptrace()` (co wymaga możliwości wykonywania syscalli lub dostępności `gdb` w systemie) albo, co ciekawsze, poprzez zapis do `/proc/$pid/mem`.

Plik `/proc/$pid/mem` jest odwzorowaniem jeden do jednego całej przestrzeni adresowej procesu (_np._ od `0x0000000000000000` do `0x7ffffffffffff000` w x86-64). Oznacza to, że odczyt lub zapis do tego pliku pod offsetem `x` jest równoznaczny z odczytem lub modyfikacją zawartości pod adresem wirtualnym `x`.

Teraz musimy zmierzyć się z czterema podstawowymi problemami:

- Ogólnie rzecz biorąc, tylko root i właściciel pliku mogą go modyfikować.
- ASLR.
- Jeśli spróbujemy odczytać lub zapisać adres, który nie jest zmapowany w przestrzeni adresowej programu, otrzymamy błąd I/O.

Problemy te mają rozwiązania, które — choć nie są idealne — są skuteczne:

- Większość interpreterów powłoki pozwala na tworzenie deskryptorów plików, które następnie są dziedziczone przez procesy potomne. Możemy utworzyć fd wskazujący na plik `mem` powłoki z uprawnieniami do zapisu... dzięki temu procesy potomne korzystające z tego fd będą mogły modyfikować pamięć powłoki.
- ASLR nie stanowi nawet problemu — możemy sprawdzić plik `maps` powłoki lub dowolny inny plik z procfs, aby uzyskać informacje o przestrzeni adresowej procesu.
- Musimy więc wykonać `lseek()` na pliku. Z poziomu powłoki nie można tego zrobić bez użycia osławionego `dd`.

### Szczegółowo

Kroki są stosunkowo proste i nie wymagają żadnej specjalistycznej wiedzy, aby je zrozumieć:

- Przeanalizuj binarny plik, który chcemy uruchomić, oraz loader, aby ustalić, jakich mapowań potrzebują. Następnie utwórz "shell"code, który ogólnie rzecz biorąc wykona te same kroki, co kernel przy każdym wywołaniu `execve()`:
- Utwórz wspomniane mapowania.
- Wczytaj do nich pliki binarne.
- Ustaw uprawnienia.
- Na koniec zainicjalizuj stos argumentami programu i umieść na nim wektor pomocniczy (potrzebny loaderowi).
- Przejdź do loadera i pozwól mu wykonać resztę (załadować biblioteki potrzebne programowi).
- Uzyskaj z pliku `syscall` adres, pod który proces powróci po zakończeniu wykonywanego przez niego syscalla.
- Nadpisz to miejsce — które będzie wykonywalne — naszym shellcode (za pomocą `mem` możemy modyfikować strony bez uprawnień do zapisu).
- Przekaż program, który chcemy uruchomić, na stdin procesu (zostanie `read()` przez wspomniany "shell"code).
- W tym momencie loader zajmie się załadowaniem niezbędnych bibliotek naszego programu i przejściem do niego.

**Sprawdź narzędzie w** [**https://github.com/arget13/DDexec**](**https://github.com/arget13/DDexec**)

## EverythingExec

Istnieje kilka alternatyw dla `dd`, z których jedna — `tail` — jest obecnie domyślnym programem używanym do wykonywania `lseek()` w pliku `mem` (co było jedynym powodem używania `dd`). Wspomniane alternatywy to:
```bash
tail
hexdump
cmp
xxd
```
Ustawiając zmienną `SEEKER`, możesz zmienić używany `seeker`, _np._:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Jeśli znajdziesz inny prawidłowy seeker, który nie został zaimplementowany w skrypcie, nadal możesz go użyć, ustawiając zmienną `SEEKER_ARGS`:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Zablokujcie to, EDR-y.

## Referencje

- [https://github.com/arget13/DDexec](https://github.com/arget13/DDexec)

{{#include ../../../../banners/hacktricks-training.md}}
