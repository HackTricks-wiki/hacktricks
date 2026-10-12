# DDexec / EverythingExec

{{#include ../../../../banners/hacktricks-training.md}}

## Kontekst

Linux zazwyczaj uruchamia programy z plików wykonywalnych zapisanych na dysku lub w pamięci. Potrafi rozpoznać plik wykonywalny na podstawie ścieżki lub deskryptora pliku, więc zwykła ścieżka w systemie plików nie zawsze jest wymagana.<sup>[[2]](#references)</sup>

DDexec / EverythingExec wykorzystuje pamięć **już uruchomionego procesu**. Strona [Linux Fileless Execution](../../../post-exploitation/linux-fileless-execution.md) opisuje wykonywanie z plików anonimowych oraz powiązane wykrywanie i zbieranie danych do analizy kryminalistycznej; [przegląd obejść opartych na pamięci](index.html#memory-bypasses) zawiera również odnośniki do MemExec i Memdlopen.<sup>[[1]](#references)</sup>

Ta technika pozwala **omijać typowe mechanizmy ochrony, takie jak tryb tylko do odczytu, noexec, biała lista nazw plików i biała lista hashy**.<sup>[[1]](#references)</sup>

## Zależności

Do działania końcowy skrypt wymaga poniższych narzędzi. Muszą być dostępne w atakowanym systemie (domyślnie znajdziesz je wszędzie):

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

Jeśli możesz dowolnie modyfikować pamięć procesu, możesz go przejąć. Można to wykorzystać do przejęcia już działającego procesu i zastąpienia go innym programem. Możemy to osiągnąć za pomocą syscalla `ptrace()` (co wymaga możliwości wykonywania syscalli albo dostępności gdb w systemie) lub, co ciekawsze, przez zapis do `/proc/$pid/mem`.<sup>[[1]](#references)</sup>

Plik `/proc/$pid/mem` jest odwzorowaniem jeden do jednego całej przestrzeni adresowej procesu (_np._ od `0x0000000000000000` do `0x7ffffffffffff000` w x86-64). Oznacza to, że odczyt z tego pliku lub zapis do niego pod offsetem `x` jest tym samym co odczyt lub modyfikacja zawartości pod adresem wirtualnym `x`.

Mamy teraz cztery podstawowe problemy do rozwiązania:

- Zasadniczo tylko root i właściciel pliku będący programem mogą go modyfikować.
- ASLR.
- Jeśli spróbujemy odczytać lub zapisać dane pod adresem, który nie jest zmapowany w przestrzeni adresowej programu, wystąpi błąd I/O.

Te problemy mają rozwiązania, które — choć nie są idealne — sprawdzają się dobrze:

- Większość interpreterów powłoki pozwala tworzyć deskryptory plików, które następnie są dziedziczone przez procesy potomne. Możemy utworzyć fd wskazujący na plik `mem` powłoki z uprawnieniami do zapisu... dzięki czemu procesy potomne korzystające z tego fd będą mogły modyfikować pamięć powłoki.
- ASLR nie stanowi nawet problemu — możemy sprawdzić plik `maps` powłoki lub inny plik z procfs, aby uzyskać informacje o przestrzeni adresowej procesu.
- Musimy więc wykonać `lseek()` na pliku. Z poziomu powłoki nie da się tego zrobić, chyba że użyjemy niesławnego `dd`.

### Szczegóły

Kroki są stosunkowo proste i ich zrozumienie nie wymaga żadnej specjalistycznej wiedzy:<sup>[[1]](#references)</sup>

- Przeanalizuj plik binarny, który chcemy uruchomić, oraz loader, aby ustalić, jakich mapowań potrzebują. Następnie utwórz „shell”code, który w ogólnym zarysie wykona te same kroki co kernel przy każdym wywołaniu `execve()`:
  - Utworzy wspomniane mapowania.
  - Wczyta do nich pliki binarne.
  - Ustawi uprawnienia.
  - Na koniec zainicjalizuje stos argumentami programu i umieści na nim wektor pomocniczy (wymagany przez loader).
  - Przeskoczy do loadera i pozwoli mu wykonać resztę (załadować biblioteki wymagane przez program).
- Odczytaj z pliku `syscall` adres, pod który proces powróci po wykonaniu syscalla.
- Nadpisz to miejsce, które będzie wykonywalne, naszym shellcode’em (za pomocą `mem` możemy modyfikować strony niezapisywalne).
- Przekaż program, który chcemy uruchomić, na stdin procesu (zostanie on `read()` przez wspomniany „shell”code).
- Na tym etapie loader załaduje biblioteki wymagane przez nasz program i przeskoczy do niego.

**Sprawdź narzędzie:** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec).<sup>[[1]](#references)</sup>

## EverythingExec

Istnieje kilka alternatyw dla `dd`. Jedną z nich jest `tail`, który jest obecnie domyślnym programem używanym do wykonywania `lseek()` na pliku `mem` (był to jedyny powód używania `dd`). Oto dostępne alternatywy:<sup>[[1]](#references)</sup>

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

Blokujcie to, EDR-y.

## References

- [1] [DDexec: Technika uruchamiania plików binarnych bez zapisu na dysku i w ukryty sposób w systemie Linux](https://github.com/arget13/DDexec)
- [2] [execveat(2) — strona podręcznika systemu Linux](https://manpages.debian.org/trixie/manpages-dev/execveat.2.en.html)
{{#include ../../../../banners/hacktricks-training.md}}
