# DDexec / EverythingExec

{{#include ../../../../banners/hacktricks-training.md}}

## Kontekst

W systemie Linux, aby uruchomić program, musi on istnieć jako plik i być dostępny w jakiś sposób w hierarchii systemu plików (tak właśnie działa `execve()`). Plik ten może znajdować się na dysku lub w pamięci RAM (tmpfs, memfd), ale potrzebujesz ścieżki do pliku. Dzięki temu bardzo łatwo kontrolować to, co jest uruchamiane w systemie Linux, wykrywać zagrożenia i narzędzia atakującego lub całkowicie uniemożliwić im próbę uruchomienia czegokolwiek własnego (_np._ nie zezwalając użytkownikom bez uprawnień na umieszczanie plików wykonywalnych w dowolnym miejscu).

Ta technika ma jednak to wszystko zmienić. Jeśli nie możesz uruchomić procesu, którego potrzebujesz... **przejmujesz już istniejący proces**.

Ta technika pozwala **ominąć typowe mechanizmy ochrony, takie jak read-only, noexec, whitelisting nazw plików, whitelisting hashy...**<sup>[[1]](#references)</sup>

## Zależności

Końcowy skrypt zależy od następujących narzędzi, aby działać; muszą one być dostępne w atakowanym systemie (domyślnie znajdziesz je wszędzie):
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

Jeśli możesz dowolnie modyfikować pamięć procesu, możesz przejąć nad nim kontrolę. Można to wykorzystać do przejęcia już istniejącego procesu i zastąpienia go innym programem. Możemy to osiągnąć za pomocą syscalla `ptrace()` (co wymaga możliwości wykonywania syscalli lub dostępności gdb w systemie) albo, co ciekawsze, poprzez zapis do `/proc/$pid/mem`.<sup>[[1]](#references)</sup>

Plik `/proc/$pid/mem` jest mapowaniem jeden do jednego całej przestrzeni adresowej procesu (_np._ od `0x0000000000000000` do `0x7ffffffffffff000` w x86-64). Oznacza to, że odczyt z tego pliku lub zapis do niego pod offsetem `x` jest równoznaczny z odczytem lub modyfikacją zawartości pod wirtualnym adresem `x`.

Mamy teraz cztery podstawowe problemy do rozwiązania:

- Ogólnie rzecz biorąc, tylko root i właściciel pliku mogą go modyfikować.
- ASLR.
- Jeśli spróbujemy odczytać lub zapisać adres, który nie jest zmapowany w przestrzeni adresowej programu, otrzymamy błąd wejścia/wyjścia.

Problemy te mają rozwiązania, które choć nie są idealne, są skuteczne:

- Większość interpreterów shell pozwala na tworzenie deskryptorów plików, które następnie zostaną odziedziczone przez procesy potomne. Możemy utworzyć fd wskazujący na plik `mem` shella z uprawnieniami do zapisu... dzięki temu procesy potomne korzystające z tego fd będą mogły modyfikować pamięć shella.
- ASLR nie stanowi nawet problemu, ponieważ możemy sprawdzić plik `maps` shella lub dowolny inny plik z procfs, aby uzyskać informacje o przestrzeni adresowej procesu.
- Musimy więc wykonać `lseek()` na pliku. Z poziomu shella nie można tego zrobić bez użycia osławionego `dd`.

### Bardziej szczegółowo

Kroki są stosunkowo proste i do ich zrozumienia nie jest potrzebna żadna specjalistyczna wiedza:<sup>[[1]](#references)</sup>

- Przeanalizuj binary, który chcemy uruchomić, oraz loader, aby ustalić, jakich mappingów wymagają. Następnie przygotuj "shell"code, który ogólnie rzecz biorąc wykona te same kroki, które kernel wykonuje przy każdym wywołaniu `execve()`:
- Utwórz wspomniane mappingi.
- Wczytaj do nich binary.
- Ustaw permissions.
- Na koniec zainicjalizuj stack argumentami programu i umieść auxiliary vector (wymagany przez loader).
- Przejdź do loadera i pozwól mu wykonać resztę (załadować biblioteki wymagane przez program).
- Uzyskaj z pliku `syscall` adres, pod który proces powróci po zakończeniu wykonywanego syscalla.
- Nadpisz to miejsce, które będzie executable, naszym shellcode (za pomocą `mem` możemy modyfikować strony bez uprawnień do zapisu).
- Przekaż program, który chcemy uruchomić, na stdin procesu (zostanie `read()` przez wspomniany "shell"code).
- W tym momencie loader musi załadować niezbędne biblioteki naszego programu i przejść do jego wykonania.

**Sprawdź narzędzie pod adresem** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)<sup>[[1]](#references)</sup>

## EverythingExec

Istnieje kilka alternatyw dla `dd`, z których jedna, `tail`, jest obecnie domyślnym programem używanym do wykonywania `lseek()` w pliku `mem` (co było jedynym powodem używania `dd`). Wspomniane alternatywy to:<sup>[[1]](#references)</sup>
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
Jeśli znajdziesz inny poprawny `seeker`, który nie został zaimplementowany w skrypcie, nadal możesz go użyć, ustawiając zmienną `SEEKER_ARGS`:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Zablokujcie to, EDR-y.

## Referencje

- [1] [DDexec: Technika uruchamiania plików binarnych bez użycia plików i w sposób ukryty w systemie Linux](https://github.com/arget13/DDexec)

{{#include ../../../../banners/hacktricks-training.md}}
