# Nadużycia bibliotek współdzielonych i linkera SUID

{{#include ../../banners/hacktricks-training.md}}

Pliki binarne SUID są zwykle sprawdzane pod kątem bezpośredniego wykonywania poleceń, ale własne programy SUID mogą być również podatne na ataki za pośrednictwem dynamicznego linkera. Wspólny schemat jest prosty: uprzywilejowany plik wykonywalny ładuje kod ze ścieżki lub konfiguracji, na którą użytkownik o niższych uprawnieniach może mieć wpływ.<sup>[[1]](#references)</sup>

Ta strona skupia się na ogólnych wzorcach technik: brakujących bibliotekach, katalogach bibliotek z prawem zapisu, `RPATH`/`RUNPATH`, `LD_PRELOAD` za pośrednictwem sudo, konfiguracji linkera oraz pomyłkach związanych z hardlinkami SUID.

Informacje o nagłówkach programu ELF, sekcji dynamicznej i działaniu loadera, które leżą u podstaw tych kontroli, znajdziesz w [Podstawowe informacje o ELF](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md).

## Szybka enumeracja

Zacznij od znalezienia nietypowych plików SUID i sprawdzenia, czy są dynamicznie linkowane:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```

W przypadku nieznanego pliku wykonywalnego użyj `readelf`: [`ldd` może uruchomić niezaufany interpreter ELF](https://man7.org/linux/man-pages/man1/ldd.1.html). `readelf` pokazuje bezpośrednie zależności, dlatego osobno potwierdź ścieżkę faktycznie wybraną przez loader.<sup>[[1]](#references)[[3]](#references)</sup>

Skup się na niestandardowych lokalizacjach, niestandardowych ścieżkach aplikacji, plikach binarnych należących do roota, ale znajdujących się poza katalogami zarządzanymi przez pakiety, oraz zależnościach ładowanych z katalogów z prawem zapisu.<sup>[[1]](#references)</sup>

Przydatne sposoby sprawdzania prawa zapisu:

```bash
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```

## Missing Shared Object Injection

Niektóre niestandardowe pliki binarne SUID próbują załadować nieistniejący obiekt współdzielony. Jeśli brakująca ścieżka znajduje się w katalogu kontrolowanym przez atakującego, plik binarny może załadować dostarczony przez niego kod z uprawnieniami użytkownika efektywnego.<sup>[[1]](#references)</sup>

Ta sama zasada dotyczy **niestandardowego pliku binarnego dozwolonego przez sudo**, który wywołuje `dlopen()` dla bezwzględnej ścieżki `.so` w katalogu domowym lub konfiguracyjnym, do którego wywołujący może zapisywać. To późne ładowanie biblioteki może nie być widoczne w `ldd` ani w wpisach ELF `NEEDED`. Ograniczona analiza `strings` lub śledzenie **wywołania bez uprawnień** może ujawnić próbę dostępu do danej ścieżki; hasło aplikacji lub wybór z menu mogą warunkować to wyszukiwanie. Zanim uznasz to za eskalację uprawnień, sprawdź dokładną regułę sudo, ścieżkę i uprawnienia katalogu nadrzędnego oraz upewnij się, że wywołanie z podwyższonymi uprawnieniami dociera do tego wyszukiwania. Nie uruchamiaj celu sudo wyłącznie po to, by go wyliczyć.

Znajdź nieudane próby wyszukania bibliotek za pomocą filtra wywołań systemowych `strace`:<sup>[[2]](#references)</sup>

```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```

Jeśli plik binarny szuka `libexample.so` w ścieżce z prawem zapisu, minimalna biblioteka demonstracyjna może używać konstruktora. Podczas walidacji niech potwierdzenie wpływu będzie nieszkodliwe:<sup>[[6]](#references)</sup>

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

Skompiluj ją pod dokładną nazwą pliku, którą próbuje załadować plik binarny:

```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```

Warunkiem wykorzystania podatności nie jest samo brakujące library. Atakujący musi mieć możliwość umieszczenia zgodnego shared object w ścieżce akceptowanej przez uprzywilejowany loader.<sup>[[1]](#references)</sup>

## Katalog biblioteki z prawem zapisu

Czasami wszystkie zależności są dostępne, ale jeden z katalogów używanych do ich wyszukiwania ma prawa zapisu. Może to umożliwić zastąpienie załadowanej biblioteki lub umieszczenie biblioteki o tej samej nazwie, która ma wyższy priorytet.<sup>[[1]](#references)</sup>

Ta sama analiza dotyczy niestandardowego ELF **dozwolonego przez sudo**, nawet jeśli ELF nie ma bitu SUID, a dozwolone konto RunAs nie jest kontem root. Porównaj wpisy `DT_NEEDED` z nazwą ścieżki biblioteki, którą rozwiąże loader; następnie sprawdź, czy wywołujący może zapisać ten plik lub zastąpić go przez zapisywalny katalog nadrzędny z prawem wyszukiwania. Potwierdź dokładną regułę sudo RunAs, symlinki i ACL, zasady loadera oraz to, czy proces docelowy ładuje bibliotekę jako konto o wyższych uprawnieniach. Zapisywalny plik `.so` lub sama nazwa zależności to tylko wskazówka; sprawdź metadane bez uruchamiania polecenia sudo.<sup>[[1]](#references)[[3]](#references)[[5]](#references)</sup>

Sprawdź ścieżki zależności:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```

Jeśli katalog jest zapisywalny, zweryfikuj to w laboratorium, korzystając z bezpiecznej kopii. Zastąpienie bibliotek systemowych na działającym hoście może sprawić, że procesy uruchamiane równolegle użyją niespójnych wersji bibliotek.<sup>[[8]](#references)</sup>

### Zapisywalne biblioteki wewnątrz chroota

Samo użycie chroota nie zamyka odziedziczonych deskryptorów plików ani nie ogranicza dostępu do całego systemu plików. Jeśli sandbox pozostawia deskryptor katalogu wskazujący poza nowy katalog główny, a uwięziony proces może odwołać się do tego deskryptora (na przykład przez dostępny wpis `/proc/<pid>/fd/`), ścieżki hosta mogą pozostać osiągalne. To problem z granicą systemu plików; sam w sobie nie nadaje uprawnień root.<sup>[[11]](#references)[[12]](#references)</sup>

Osobno sprawdź, czy uwięziony użytkownik może zapisywać w katalogu bibliotek, którego użyje **hostowy plik wykonywalny root-SUID** uruchomiony z jaila. Loader rozwiązuje zależności w widoku systemu plików danego procesu, więc kontrolowana przez atakującego biblioteka w tym katalogu może zostać wykonana z efektywną tożsamością programu SUID. Potwierdź dokładny plik wykonywalny, jego bit SUID i politykę montowania, cel deskryptora i uprawnienia dostępu, ścieżkę wyszukiwania bibliotek jaila oraz to, że program rzeczywiście może uzyskać dostęp do hostowego pliku wykonywalnego. Możliwość pliku na launcherze sandboxa, zapisywalny jail lub hostowy plik binarny SUID to jedynie trop; pełny łańcuch zależy od implementacji sandboxa.<sup>[[1]](#references)[[11]](#references)[[12]](#references)</sup>

## RPATH and RUNPATH

`RPATH` i `RUNPATH` to wpisy sekcji dynamicznej, które informują loader, gdzie szukać bibliotek. Są niebezpieczne w programach SUID, gdy wskazują katalogi zapisywalne przez atakującego.<sup>[[1]](#references)</sup>

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

Jeśli katalog `/opt/app/lib` umożliwia zapis, a plik binarny wymaga `libcustom.so`, atakujący może umieścić tam złośliwy plik `libcustom.so`:<sup>[[1]](#references)</sup>

```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```

`RPATH` i `RUNPATH` nie są identyczne pod każdym względem dotyczącym rozwiązywania ścieżek, ale w praktycznej analizie eskalacji uprawnień pytanie jest takie samo: czy SUID binary szuka biblioteki o danej nazwie w katalogu, w którym atakujący może zapisywać?<sup>[[1]](#references)</sup>

## LD_PRELOAD, LD_LIBRARY_PATH i SUID

W przypadku zwykłych programów `LD_PRELOAD` i `LD_LIBRARY_PATH` mogą wymusić lub wpłynąć na ładowanie bibliotek współdzielonych. W przypadku programów SUID dynamic loader zwykle przechodzi w tryb bezpiecznego wykonania i ignoruje niebezpieczne zmienne środowiskowe.<sup>[[1]](#references)</sup>

Oznacza to, że zwykły SUID binary zazwyczaj nie jest podatny tylko dlatego, że użytkownik może ustawić `LD_PRELOAD`:<sup>[[1]](#references)</sup>

```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```

Częstym wyjątkiem jest konfiguracja sudo, która zezwala na przypisanie zmiennej środowiskowej w wierszu poleceń dla programu docelowego, na przykład za pomocą tagu `SETENV` lub odpowiedniej opcji `setenv`. Jeśli program docelowy jest linkowany dynamicznie, a sudo akceptuje `LD_PRELOAD=/path/to/library`, może załadować kod kontrolowany przez użytkownika wywołującego. Sprawdź efektywną regułę i tożsamość programu docelowego. Samo dodanie `LD_PRELOAD` do `env_keep` nie wystarczy w systemach, w których dynamic loader usuwa odziedziczone `LD_PRELOAD`, zanim uruchomi się proces SUID `sudo`; przypisanie w wierszu poleceń jest przetwarzane przez sudo po jego uruchomieniu.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
sudo -l
# Check SETENV/setenv and the target command's allowed arguments
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```

Nie myl tych przypadków; odróżniają je opisane wyżej reguły loadera i polityki sudo:<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

- `LD_PRELOAD` w przypadku zwykłego binarnego SUID: zazwyczaj blokowane przez secure execution.
- `LD_PRELOAD` zaakceptowane jako przypisanie w wierszu poleceń sudo dla uprzywilejowanego, dynamicznie linkowanego celu: potencjalnie podatne na exploit.
- Brakujący plik `.so` w zapisywalnej ścieżce: podatność występuje, gdy binarny plik SUID naturalnie ładuje tę ścieżkę.
- `RPATH`/`RUNPATH` wskazujące na zapisywalny katalog: podatność występuje, gdy można kontrolować wymaganą bibliotekę.
- Dostęp do zapisu w `/etc/ld.so.preload` lub konfiguracji linkera: wpływ na cały system i wysokie ryzyko.

## Konfiguracja linkera

`ld.so` korzysta z pamięci podręcznej linkera i pliku `/etc/ld.so.preload`; `ldconfig` tworzy tę pamięć podręczną na podstawie `/etc/ld.so.conf` oraz wskazanych w nim plików, zwykle z katalogu `/etc/ld.so.conf.d/`.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Najważniejsze kontrole:

```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```

Zapisywalna konfiguracja linkera jest zwykle poważniejszym problemem niż pojedynczy podatny plik binarny SUID, ponieważ może wpływać na wiele procesów linkowanych dynamicznie. `/etc/ld.so.preload` jest szczególnie niebezpieczny, ponieważ może wymusić załadowanie obiektu współdzielonego do procesów uprzywilejowanych.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

## SUID Hardlink Confusion

Hardlinki mogą sprawić, że ten sam inode SUID będzie widoczny pod wieloma nazwami.<sup>[[9]](#references)</sup> Można to wykorzystać do ukrycia uprzywilejowanego helpera, wprowadzenia w błąd podczas czyszczenia lub obejścia naiwnego przeglądu opartego na ścieżkach.

Znajdź pliki SUID z więcej niż jednym dowiązaniem:<sup>[[9]](#references)</sup>

```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```

Sprawdź wszystkie ścieżki do tego samego inode'a:<sup>[[9]](#references)</sup>

```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```

Nadużycie nie polega na tym, że hardlink zmienia uprawnienia. Polega na niejednoznaczności ścieżek: uprzywilejowany inode może być dostępny pod nazwą, której obrońcy lub skrypty się nie spodziewają.<sup>[[9]](#references)</sup> Więcej informacji o inode’ach i pracy z hardlinkami znajdziesz w [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md).

## Uwagi dotyczące zabezpieczeń

- Ogranicz liczbę binariów SUID do minimum, regularnie je audytuj i, jeśli to możliwe, zarządzaj nimi za pomocą menedżera pakietów.
- Unikaj wpisów `RPATH`/`RUNPATH` wskazujących na katalogi, w których można zapisywać, lub katalogi zarządzane przez aplikacje.<sup>[[1]](#references)[[8]](#references)</sup>
- Katalogi bibliotek powinny należeć do root i nie mogą być zapisywalne przez zwykłych użytkowników.<sup>[[8]](#references)</sup>
- Nie zachowuj `LD_PRELOAD`, `LD_LIBRARY_PATH` ani podobnych zmiennych loadera podczas używania sudo.<sup>[[1]](#references)[[5]](#references)</sup>
- Monitoruj `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` oraz nieoczekiwane pliki SUID.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
- Sprawdzaj pliki SUID z hardlinkami i badaj niestandardowe wrappery SUID poza standardowymi ścieżkami systemowymi.<sup>[[9]](#references)</sup>

## References

- [1] [ld.so(8) — strona podręcznika Linuxa](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [strace(1) — strona podręcznika Linuxa](https://man7.org/linux/man-pages/man1/strace.1.html)
- [3] [readelf (narzędzia binutils GNU)](https://sourceware.org/binutils/docs/binutils/readelf.html)
- [4] [sudo(8) — strona podręcznika Linuxa](https://www.man7.org/linux/man-pages/man8/sudo.8.html)
- [5] [sudoers(5) — strona podręcznika Linuxa](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [6] [Wspólne atrybuty (GCC)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [7] [ldconfig(8) — strona podręcznika Linuxa](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [8] [Utwardzanie dynamicznego linkera (biblioteka GNU C)](https://www.sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [9] [Twarde linki (GNU Findutils)](https://www.gnu.org/software/findutils/manual/html_node/find_html/Hard-Links.html)
- [10] [objdump (narzędzia binutils GNU)](https://www.sourceware.org/binutils/docs/binutils/objdump.html)
- [11] [chroot(2) — strona podręcznika Linuxa](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [12] [proc_pid_fd(5) — strona podręcznika Linuxa](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)
{{#include ../../banners/hacktricks-training.md}}
