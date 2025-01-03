# DDexec / EverythingExec

{{#include ../../../banners/hacktricks-training.md}}

## Kontekst

W systemie Linux, aby uruchomić program, musi on istnieć jako plik, musi być w jakiś sposób dostępny w hierarchii systemu plików (tak działa `execve()`). Plik ten może znajdować się na dysku lub w pamięci RAM (tmpfs, memfd), ale potrzebujesz ścieżki do pliku. To bardzo ułatwiło kontrolowanie tego, co jest uruchamiane w systemie Linux, co ułatwia wykrywanie zagrożeń i narzędzi atakujących lub zapobieganie ich próbom uruchomienia czegokolwiek (_np._ nie pozwalając użytkownikom bez uprawnień na umieszczanie plików wykonywalnych w dowolnym miejscu).

Ale ta technika ma na celu zmianę tego wszystkiego. Jeśli nie możesz uruchomić procesu, którego chcesz... **to przejmujesz już istniejący**.

Ta technika pozwala na **obejście powszechnych technik ochrony, takich jak tylko do odczytu, noexec, biała lista nazw plików, biała lista hashy...**

## Zależności

Ostateczny skrypt zależy od następujących narzędzi, które muszą być dostępne w systemie, który atakujesz (domyślnie znajdziesz je wszędzie):
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

Jeśli jesteś w stanie dowolnie modyfikować pamięć procesu, możesz go przejąć. Może to być użyte do przejęcia już istniejącego procesu i zastąpienia go innym programem. Możemy to osiągnąć, używając wywołania systemowego `ptrace()` (co wymaga posiadania możliwości wykonywania wywołań systemowych lub dostępności gdb w systemie) lub, co bardziej interesujące, pisząc do `/proc/$pid/mem`.

Plik `/proc/$pid/mem` jest mapowaniem jeden do jednego całej przestrzeni adresowej procesu (_np._ od `0x0000000000000000` do `0x7ffffffffffff000` w x86-64). Oznacza to, że odczyt lub zapis do tego pliku w przesunięciu `x` jest tym samym, co odczyt lub modyfikacja zawartości pod adresem wirtualnym `x`.

Teraz mamy cztery podstawowe problemy do rozwiązania:

- Generalnie tylko root i właściciel programu pliku mogą go modyfikować.
- ASLR.
- Jeśli spróbujemy odczytać lub zapisać do adresu, który nie jest mapowany w przestrzeni adresowej programu, otrzymamy błąd I/O.

Te problemy mają rozwiązania, które, chociaż nie są doskonałe, są dobre:

- Większość interpreterów powłoki pozwala na tworzenie deskryptorów plików, które będą dziedziczone przez procesy potomne. Możemy stworzyć fd wskazujący na plik `mem` powłoki z uprawnieniami do zapisu... więc procesy potomne, które używają tego fd, będą mogły modyfikować pamięć powłoki.
- ASLR nie jest nawet problemem, możemy sprawdzić plik `maps` powłoki lub jakikolwiek inny z procfs, aby uzyskać informacje o przestrzeni adresowej procesu.
- Musimy więc użyć `lseek()` na pliku. Z powłoki nie można tego zrobić, chyba że używając infamnego `dd`.

### W większych szczegółach

Kroki są stosunkowo łatwe i nie wymagają żadnego rodzaju ekspertyzy, aby je zrozumieć:

- Przeanalizuj binarny plik, który chcemy uruchomić, oraz loader, aby dowiedzieć się, jakie mapowania są potrzebne. Następnie stwórz "shell"code, który będzie wykonywał, ogólnie mówiąc, te same kroki, które jądro wykonuje przy każdym wywołaniu `execve()`:
- Utwórz wspomniane mapowania.
- Odczytaj binaria do nich.
- Ustaw uprawnienia.
- Na koniec zainicjalizuj stos z argumentami dla programu i umieść wektor pomocniczy (potrzebny loaderowi).
- Skocz do loadera i pozwól mu zrobić resztę (załaduj biblioteki potrzebne programowi).
- Uzyskaj z pliku `syscall` adres, do którego proces wróci po wywołaniu systemowym, które wykonuje.
- Nadpisz to miejsce, które będzie wykonywalne, naszym shellcode (poprzez `mem` możemy modyfikować strony, które nie są zapisywalne).
- Przekaż program, który chcemy uruchomić, do stdin procesu (zostanie `read()` przez wspomniany "shell"code).
- W tym momencie to loader jest odpowiedzialny za załadowanie niezbędnych bibliotek dla naszego programu i skok do niego.

**Sprawdź narzędzie w** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)

## EverythingExec

Istnieje kilka alternatyw dla `dd`, z których jedna, `tail`, jest obecnie domyślnym programem używanym do `lseek()` przez plik `mem` (co było jedynym celem użycia `dd`). Wspomniane alternatywy to:
```bash
tail
hexdump
cmp
xxd
```
Ustawiając zmienną `SEEKER`, możesz zmienić używanego seekera, _np._:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Jeśli znajdziesz inny ważny seeker, który nie został zaimplementowany w skrypcie, możesz go nadal użyć, ustawiając zmienną `SEEKER_ARGS`:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Zablokuj to, EDR-y.

## Odniesienia

- [https://github.com/arget13/DDexec](https://github.com/arget13/DDexec)

{{#include ../../../banners/hacktricks-training.md}}
