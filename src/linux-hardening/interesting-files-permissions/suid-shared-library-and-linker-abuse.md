# Nadużycia bibliotek współdzielonych i linkera w SUID

{{#include ../../banners/hacktricks-training.md}}

Pliki binarne SUID są zwykle sprawdzane pod kątem bezpośredniego wykonywania poleceń, ale niestandardowe programy SUID mogą być też podatne na ataki za pośrednictwem dynamicznego linkera. Wspólny schemat jest prosty: uprzywilejowany plik wykonywalny ładuje kod ze ścieżki lub konfiguracji, na którą może wpływać użytkownik o niższych uprawnieniach.<sup>[[1]](#references)</sup>

Ta strona skupia się na ogólnych schematach technik: brakujących bibliotekach, katalogach bibliotek z prawem zapisu, `RPATH`/`RUNPATH`, `LD_PRELOAD` przez sudo, konfiguracji linkera oraz pomyleniu hardlinków w SUID.

Informacje o nagłówkach programu ELF, sekcji dynamicznej i działaniu loadera, które leżą u podstaw tych kontroli, znajdziesz w sekcji [Podstawowe informacje o ELF](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md).

## Szybkie rozpoznanie

Zacznij od znalezienia nietypowych plików SUID i sprawdzenia, czy są linkowane dynamicznie:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```

W przypadku nieznanego pliku wykonywalnego użyj `readelf`: [`ldd` może uruchomić niezaufany interpreter ELF](https://man7.org/linux/man-pages/man1/ldd.1.html). `readelf` pokazuje bezpośrednie zależności, więc osobno potwierdź ścieżkę faktycznie wybraną przez loader.<sup>[[1]](#references)[[3]](#references)</sup>

Skup się na niestandardowych lokalizacjach, niestandardowych ścieżkach aplikacji, plikach binarnych należących do roota, ale znajdujących się poza katalogami zarządzanymi przez menedżer pakietów, oraz zależnościach ładowanych z katalogów z prawem zapisu.<sup>[[1]](#references)</sup>

Przydatne kontrole prawa zapisu:

```bash
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```

## Missing Shared Object Injection

Niektóre niestandardowe pliki binarne SUID próbują załadować nieistniejący obiekt współdzielony. Jeśli brakująca ścieżka znajduje się w katalogu kontrolowanym przez atakującego, plik binarny może załadować dostarczony przez niego kod z uprawnieniami użytkownika efektywnego.<sup>[[1]](#references)</sup>

Ta sama zasada dotyczy **niestandardowego pliku binarnego dozwolonego przez sudo**, gdy wywołuje on `dlopen()` z bezwzględną ścieżką do `.so` znajdującego się w katalogu domowym lub konfiguracyjnym, do którego wywołujący ma prawo zapisu. Takie późne ładowanie biblioteki może nie być widoczne w wynikach `ldd` ani w wpisach ELF `NEEDED`. Ograniczony przegląd wyników `strings` lub śledzenie **wywołania bez uprawnień** może ujawnić próbę użycia tej ścieżki; wyszukiwanie może być uzależnione od hasła aplikacji lub wyboru w menu. Przed uznaniem tego za eskalację uprawnień sprawdź dokładną regułę sudo, ścieżkę i uprawnienia katalogu nadrzędnego oraz to, czy uprzywilejowane wywołanie dociera do tego wyszukiwania. Nie uruchamiaj celu sudo wyłącznie po to, by go enumerować.

Znajdź nieudane próby wyszukania bibliotek, używając filtra wywołań systemowych `strace`:<sup>[[2]](#references)</sup>

```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```

Jeśli plik binarny przeszukuje zapisywalną ścieżkę w poszukiwaniu `libexample.so`, minimalna biblioteka potwierdzająca podatność może użyć konstruktora. Podczas walidacji zachowaj nieszkodliwy proof-of-impact:<sup>[[6]](#references)</sup>

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

Zbuduj go pod dokładną nazwą pliku, którą próbuje załadować binarka:

```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```

Warunkiem umożliwiającym wykorzystanie podatności nie jest samo brakujące library. Atakujący musi móc umieścić zgodny shared object w ścieżce akceptowanej przez uprzywilejowany loader.<sup>[[1]](#references)</sup>

## Katalog biblioteki z prawem zapisu

Czasami wszystkie zależności są dostępne, ale jeden z katalogów używanych do ich rozwiązywania pozwala na zapis. Może to umożliwić zastąpienie załadowanej biblioteki lub umieszczenie biblioteki o tej samej nazwie, która będzie miała wyższy priorytet.<sup>[[1]](#references)</sup>

Ta sama analiza dotyczy niestandardowego ELF **dozwolonego przez sudo**, nawet gdy ELF nie ma bitu SUID, a dozwolone konto RunAs nie jest rootem. Porównaj wpisy `DT_NEEDED` z nazwami ścieżek bibliotek, które rozwiąże loader, a następnie sprawdź, czy wywołujący może zapisywać do danego pliku lub zastąpić go przez katalog nadrzędny z prawami zapisu i wyszukiwania. Potwierdź dokładną regułę sudo RunAs, symlinki i ACL, politykę loadera oraz to, czy proces docelowy ładuje bibliotekę jako konto o wyższych uprawnieniach. Plik `.so` z prawem zapisu lub sama nazwa zależności to jedynie wskazówka; sprawdź metadane bez uruchamiania polecenia sudo.<sup>[[1]](#references)[[3]](#references)[[5]](#references)</sup>

Sprawdź ścieżki zależności:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```

Jeśli katalog jest zapisywalny, zweryfikuj to w środowisku laboratoryjnym, używając podejścia bezpiecznego dla kopii. Zastąpienie bibliotek systemowych na działającym hoście może sprawić, że procesy uruchamiane w tym samym czasie będą korzystać z niespójnych wersji bibliotek.<sup>[[8]](#references)</sup>

### Zapisywalne biblioteki wewnątrz chroot

Sam chroot nie zamyka odziedziczonych deskryptorów plików ani nie ogranicza dostępu do całego systemu plików. Jeśli sandbox pozostawia deskryptor katalogu wskazujący poza nowy katalog główny, a proces w więzieniu może odwołać się do tego deskryptora (na przykład przez dostępny wpis `/proc/<pid>/fd/`), ścieżki hosta mogą pozostać osiągalne. Jest to problem z granicą systemu plików; samo w sobie nie nadaje uprawnień root.<sup>[[11]](#references)[[12]](#references)</sup>

Osobno sprawdź, czy użytkownik w więzieniu może zapisywać w katalogu bibliotek, z którego skorzysta **hostowy plik wykonywalny root-SUID** uruchomiony z więzienia. Loader rozwiązuje zależności w widoku systemu plików danego procesu, więc kontrolowana przez atakującego biblioteka w tym miejscu może zostać wykonana z efektywną tożsamością programu SUID. Potwierdź dokładny plik wykonywalny, jego bit SUID i politykę montowania, cel deskryptora i uprawnienia dostępu, ścieżkę wyszukiwania bibliotek w więzieniu oraz to, czy program rzeczywiście może uzyskać dostęp do pliku wykonywalnego hosta. Capability pliku launchera sandboxa, zapisywalne więzienie lub hostowy plik binarny SUID to jedynie trop; pełny łańcuch zależy od implementacji sandboxa.<sup>[[1]](#references)[[11]](#references)[[12]](#references)</sup>

## RPATH and RUNPATH

`RPATH` i `RUNPATH` to wpisy sekcji dynamicznej, które wskazują loaderowi, gdzie szukać bibliotek. Są niebezpieczne w programach SUID, jeśli wskazują na katalogi zapisywalne przez atakującego.<sup>[[1]](#references)</sup>

Wykryj je:<sup>[[3]](#references)[[10]](#references)</sup>

```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```

Przykładowy ryzykowny wynik:

```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```

Jeśli katalog `/opt/app/lib` jest zapisywalny, a plik binarny wymaga `libcustom.so`, atakujący może umieścić tam złośliwy plik `libcustom.so`:<sup>[[1]](#references)</sup>

```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```

`RPATH` i `RUNPATH` nie są identyczne pod każdym względem dotyczącym rozwiązywania ścieżek, ale podczas analizy pod kątem eskalacji uprawnień praktyczne pytanie jest takie samo: czy plik binarny SUID przeszukuje katalog zapisywalny przez atakującego w poszukiwaniu biblioteki o danej nazwie?<sup>[[1]](#references)</sup>

## LD_PRELOAD, LD_LIBRARY_PATH i SUID

W przypadku zwykłych programów zmienne `LD_PRELOAD` i `LD_LIBRARY_PATH` mogą wymuszać lub wpływać na ładowanie obiektów współdzielonych. W przypadku programów SUID dynamiczny loader zwykle przechodzi w tryb bezpiecznego wykonywania i ignoruje niebezpieczne zmienne środowiskowe.<sup>[[1]](#references)</sup>

Oznacza to, że sam fakt, iż użytkownik może ustawić `LD_PRELOAD`, zwykle nie sprawia, że zwykły plik binarny SUID jest podatny na ataki:<sup>[[1]](#references)</sup>

```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```

Częstym wyjątkiem jest polityka sudo, która zezwala na przypisanie zmiennej środowiskowej w wierszu poleceń dla procesu docelowego, na przykład za pomocą tagu `SETENV` lub odpowiedniej opcji `setenv`. Jeśli proces docelowy jest linkowany dynamicznie, a sudo akceptuje `LD_PRELOAD=/path/to/library`, może załadować kod kontrolowany przez użytkownika wywołującego. Sprawdź obowiązującą regułę i tożsamość procesu docelowego. Samo dodanie `LD_PRELOAD` do `env_keep` nie wystarczy w systemach, w których dynamiczny loader usuwa odziedziczoną zmienną `LD_PRELOAD`, zanim uruchomi się proces sudo z SUID; przypisanie zmiennej w wierszu poleceń jest przetwarzane przez sudo po jego uruchomieniu.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
sudo -l
# Check SETENV/setenv and the target command's allowed arguments
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```

Nie myl tych przypadków; odróżniają je opisane powyżej reguły loadera i polityki sudo:<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

- `LD_PRELOAD` dla zwykłego pliku binarnego SUID: zwykle blokowane podczas bezpiecznego wykonywania.
- `LD_PRELOAD` zaakceptowane jako przypisanie w wierszu poleceń sudo dla uprzywilejowanego, dynamicznie linkowanego programu docelowego: potencjalnie podatne na wykorzystanie.
- Brakujący plik `.so` w ścieżce z prawem zapisu: podatne na wykorzystanie, gdy plik binarny SUID naturalnie ładuje tę ścieżkę.
- `RPATH`/`RUNPATH` wskazujące katalog z prawem zapisu: podatne na wykorzystanie, gdy można kontrolować potrzebną bibliotekę.
- Dostęp do zapisu w `/etc/ld.so.preload` lub konfiguracji linkera: wpływ na cały system i poważne skutki.

## Konfiguracja linkera

`ld.so` korzysta z pamięci podręcznej linkera i `/etc/ld.so.preload`; `ldconfig` tworzy tę pamięć podręczną na podstawie `/etc/ld.so.conf` oraz dołączonych z niego plików, które zwykle znajdują się w `/etc/ld.so.conf.d/`.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Kontrole o wysokiej wartości:

```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```

Zapisywalna konfiguracja linkera jest zwykle poważniejszym problemem niż pojedynczy podatny plik binarny SUID, ponieważ może wpływać na wiele dynamicznie linkowanych procesów. `/etc/ld.so.preload` jest szczególnie niebezpieczny, ponieważ może wymusić załadowanie shared object do uprzywilejowanych procesów.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

## Pomieszanie hardlinków SUID

Hardlinki mogą sprawić, że ten sam inode SUID będzie widoczny pod wieloma nazwami.<sup>[[9]](#references)</sup> Można to wykorzystać do ukrycia uprzywilejowanego helpera, utrudnienia czyszczenia lub obejścia naiwnej weryfikacji opartej na ścieżkach.

Znajdź pliki SUID mające więcej niż jeden link:<sup>[[9]](#references)</sup>

```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```

Sprawdź wszystkie ścieżki do tego samego inode:<sup>[[9]](#references)</sup>

```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```

Nadużycie nie polega na tym, że hardlink zmienia uprawnienia. Chodzi o pomylenie ścieżek: uprzywilejowany inode może być dostępny pod nazwą, której obrońcy ani skrypty się nie spodziewają.<sup>[[9]](#references)</sup> Więcej informacji o inode’ach i pracy z hardlinkami znajdziesz w [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md).

## Uwagi dotyczące zabezpieczeń

- Ogranicz liczbę plików binarnych SUID do minimum, audytuj je i, jeśli to możliwe, zarządzaj nimi za pomocą menedżera pakietów.
- Unikaj wpisów `RPATH`/`RUNPATH` wskazujących na katalogi z możliwością zapisu lub zarządzane przez aplikację.<sup>[[1]](#references)[[8]](#references)</sup>
- Katalogi bibliotek powinny należeć do użytkownika root i nie mogą być zapisywalne przez zwykłych użytkowników.<sup>[[8]](#references)</sup>
- Nie zachowuj zmiennych loadera takich jak `LD_PRELOAD`, `LD_LIBRARY_PATH` ani podobnych podczas korzystania z sudo.<sup>[[1]](#references)[[5]](#references)</sup>
- Monitoruj `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` oraz nieoczekiwane pliki SUID.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
- Sprawdzaj pliki SUID z wieloma hardlinkami i analizuj niestandardowe wrappery SUID poza standardowymi ścieżkami systemowymi.<sup>[[9]](#references)</sup>

## References

- [1] [ld.so(8) — strona podręcznika Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [strace(1) — strona podręcznika Linux](https://man7.org/linux/man-pages/man1/strace.1.html)
- [3] [readelf (GNU Binary Utilities)](https://sourceware.org/binutils/docs/binutils/readelf.html)
- [4] [sudo(8) — strona podręcznika Linux](https://www.man7.org/linux/man-pages/man8/sudo.8.html)
- [5] [sudoers(5) — strona podręcznika Linux](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [6] [Common Attributes (GCC)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [7] [ldconfig(8) — strona podręcznika Linux](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [8] [Hardening dynamicznego linkera (The GNU C Library)](https://www.sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [9] [Hardlinki (GNU Findutils)](https://www.gnu.org/software/findutils/manual/html_node/find_html/Hard-Links.html)
- [10] [objdump (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/objdump.html)
- [11] [chroot(2) — strona podręcznika Linux](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [12] [proc_pid_fd(5) — strona podręcznika Linux](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)
{{#include ../../banners/hacktricks-training.md}}
