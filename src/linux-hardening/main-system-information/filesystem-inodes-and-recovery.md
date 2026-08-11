# System plików, inode'y i odzyskiwanie

{{#include ../../banners/hacktricks-training.md}}

Abuse systemu plików często polega na zmyleniu relacji między widoczną ścieżką a obiektem, który się za nią znajduje.

Obrazy dysków mogą ukrywać inny system plików.<sup>[[1]](#references)</sup> Zapisywalne mounty mogą być wykorzystywane przez zadania uruchamiane z uprawnieniami.

Hardlinki mogą udostępniać ten sam inode pod inną nazwą.<sup>[[3]](#references)</sup> Usunięte pliki mogą nadal być odczytywane za pośrednictwem otwartego deskryptora pliku.<sup>[[5]](#references)[[6]](#references)</sup>

Ta strona koncentruje się na technice, a nie na konkretnym labie ani celu.

## Obrazy dysków i mounty loop

Zwykły plik może zawierać kompletny system plików, dlatego obraz dysku po zamontowaniu może udostępniać drugie drzewo systemu plików.<sup>[[1]](#references)</sup>

Obrazy kopii zapasowych, skopiowane urządzenia blokowe, artefakty VM lub przemianowane obiekty binarne mogą zawierać dane uwierzytelniające, skrypty, klucze SSH, pliki konfiguracyjne lub flagi, nawet jeśli z zewnątrz nie wyglądają na przydatne.

Zidentyfikuj prawdopodobne obrazy za pomocą `file`, aby sklasyfikować kandydata, `blkid`, aby sprawdzić rozpoznane metadane systemu plików, oraz `strings -a`, aby przeskanować cały plik pod kątem drukowalnych sekwencji.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>
```bash
file ./candidate
ls -lh ./candidate
blkid ./candidate 2>/dev/null
strings -a ./candidate | head -n 50
```
Gdy montowanie jest dozwolone, użyj montowania loop z `ro`, aby obraz został dołączony w trybie tylko do odczytu; poniższe polecenie `find` ogranicza głębokość inspekcji i typ plików.<sup>[[1]](#references)[[4]](#references)</sup>
```bash
mkdir -p /tmp/imgmnt
sudo mount -o loop,ro ./candidate /tmp/imgmnt
find /tmp/imgmnt -maxdepth 3 -type f -ls 2>/dev/null
sudo umount /tmp/imgmnt
```
Jeśli montowanie nie jest dostępne, a obraz używa systemu plików ext2/ext3/ext4, przeanalizuj jego metadane bezpośrednio za pomocą `debugfs`.<sup>[[2]](#references)</sup>
```bash
debugfs -R 'ls -l /' ./candidate 2>/dev/null
debugfs -R 'stat /' ./candidate 2>/dev/null
```
Technika jest przydatna, ponieważ zamienia zwyczajnie wyglądający plik w drugie drzewo systemu plików.<sup>[[1]](#references)</sup> Traktuj ją jako sposób na odzyskiwanie ukrytych danych, a nie jako samodzielną metodę eskalacji uprawnień.

## Nadużywanie zapisywalnego montowania

Zapisywalne montowanie staje się niebezpieczne, gdy bardziej uprzywilejowany kontekst zaczyna później ufać czemuś, co się w nim znajduje. Ważne pytanie nie brzmi tylko: „czy mogę tu zapisywać?”, lecz także: „kto później odczytuje, wykonuje, importuje lub ładuje dane z tego miejsca?”.

Użyj `findmnt`, aby sprawdzić zamontowane systemy plików i ich opcje.<sup>[[9]](#references)</sup>

Znajdź zapisywalne montowania i podejrzanych konsumentów za pomocą udokumentowanych predykatów `find` dotyczących uprawnień, typu i granic systemu plików, a następnie użyj rekursywnego `grep`, aby przeszukać prawdopodobną konfigurację konsumentów.<sup>[[4]](#references)[[20]](#references)</sup>
```bash
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
find /mnt /media /srv /opt -xdev -type d -writable -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|backup|hook|plugin|sh |bash |python' /mnt /media /srv /opt 2>/dev/null | head -n 50
```
Typowe wzorce nadużyć:

- Zadanie cron lub usługa systemd uruchamia zapisywalny skrypt z mountu.<sup>[[13]](#references)[[14]](#references)</sup>
- Uprzywilejowana usługa ładuje pluginy, konfiguracje, szablony lub pomocnicze pliki binarne z mountu.
- Mount zawiera pliki SUID i umożliwia ich modyfikację, zastąpienie lub manipulowanie ścieżką.
- Kontener lub chroot udostępnia ścieżkę opartą na hoście, która jest zapisywalna z poziomu ograniczonego środowiska. Przestrzenie nazw mount zapewniają odrębne hierarchie mountów, podczas gdy `chroot()` zmienia tylko rozwiązywanie nazw ścieżek i nie jest pełną piaskownicą.<sup>[[15]](#references)[[16]](#references)</sup>

Ogólny wzorzec walidacji wykorzystujący te same predykaty `find`.<sup>[[4]](#references)</sup>
```bash
find /mnt /media /srv /opt -xdev -perm -4000 -type f -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
```
Wykazując wpływ w autoryzowanym labie, zachowaj payload jako obserwowalny i minimalny, na przykład zapisując wynik `id` do pliku tymczasowego.<sup>[[23]](#references)</sup> Podstawową techniką jest opóźnione wykonanie za pośrednictwem zaufanej lokalizacji z prawem zapisu.

## Inodes and Path Confusion

Inode jest obiektem systemu plików; ścieżka jest tylko nazwą wskazującą na ten obiekt. Metadane urządzenia i inode pozwalają rozróżniać obiekty w różnych systemach plików, natomiast liczba dowiązań ujawnia wiele hard links.<sup>[[3]](#references)</sup> Usunięta nazwa ścieżki nie zawsze oznacza, że dane zniknęły, jeśli proces nadal ma otwarty plik.<sup>[[5]](#references)</sup>

Poniższe predykaty `find` porównują tożsamość inode, liczbę dowiązań, granice urządzeń i znaczniki czasu.<sup>[[4]](#references)</sup>

Porównuj pliki według inode i urządzenia za pomocą `ls -i` oraz formatów metadanych `stat`.<sup>[[17]](#references)[[18]](#references)</sup>
```bash
ls -li /path/a /path/b
stat -c 'dev=%d inode=%i links=%h mode=%A owner=%U:%G path=%n' /path/a /path/b
```
Znajdź każdą widoczną ścieżkę do tego samego inode za pomocą `find -samefile`.<sup>[[4]](#references)</sup>
```bash
find / -xdev -samefile /path/to/file -ls 2>/dev/null
```
Wyszukuj bezpośrednio według numeru inode za pomocą `find -inum`, gdy masz tylko metadane.<sup>[[4]](#references)</sup>
```bash
find / -xdev -inum <inode_number> -ls 2>/dev/null
```
Ta technika jest przydatna, gdy plik pojawia się pod nieoczekiwaną nazwą, gdy aplikacja sprawdza jedną ścieżkę, ale używa innej, lub gdy uprzywilejowany wrapper korzysta z inodu, do którego można również uzyskać dostęp z innego miejsca.

## Hardlink Abuse

Hardlinki tworzą wiele nazw dla tego samego inodu. Nie wskazują ścieżki docelowej, tak jak symlinki; są równoważnymi nazwami tego samego obiektu pliku.<sup>[[3]](#references)</sup>

Znajdź pliki SUID z wieloma hardlinkami, używając predykatów `find` dotyczących uprawnień i liczby linków.<sup>[[4]](#references)</sup>
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Zbadaj jeden podejrzany plik za pomocą `stat` i `find -samefile`.<sup>[[4]](#references)[[17]](#references)</sup>
```bash
stat /path/to/suspicious
find / -xdev -samefile /path/to/suspicious -ls 2>/dev/null
```
Dlaczego ma to znaczenie:

- Wrażliwy plik może być dostępny za pośrednictwem mniej oczywistej ścieżki.
- Wrapper SUID może być ukryty pod nazwą, która nie wygląda na uprzywilejowaną.
- Czyszczenie, które usuwa jedną nazwę ścieżki, może pozostawić aktywny inny hardlink.

Sysctl `fs.protected_hardlinks` systemu Linux może ograniczać tworzenie hardlinków między granicami uprawnień.<sup>[[7]](#references)</sup> Istniejące hardlinki nadal wymagają sprawdzenia.

## Odzyskiwanie usuniętych plików przez otwarte FD

Gdy proces utrzymuje plik otwarty, usunięcie jego ostatniej nazwy ścieżki pozostawia plik aktywny do momentu zamknięcia ostatniego deskryptora; Linux udostępnia te deskryptory w `/proc/<pid>/fd/`.<sup>[[5]](#references)[[6]](#references)</sup>

Znajdź usunięte, otwarte pliki, wyświetlając deskryptory w `/proc` i filtrując dane wyjściowe dotyczące otwartych plików.<sup>[[5]](#references)[[6]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>
```bash
ls -l /proc/*/fd/* 2>/dev/null | grep ' (deleted)' | head -n 50
lsof 2>/dev/null | grep deleted | head -n 50
```
Odzyskiwanie za pośrednictwem tych linków zależy od uprawnień, ponieważ dereferencjonowanie `/proc/<pid>/fd` podlega kontrolom dostępu ptrace i uprawnieniom do plików.<sup>[[6]](#references)</sup>

Jeśli jest dozwolone, `readlink` wyświetla cel deskryptora, a `cp` kopiuje jego zawartość.<sup>[[21]](#references)[[22]](#references)</sup>
```bash
readlink /proc/<pid>/fd/<fd>
cp /proc/<pid>/fd/<fd> /tmp/recovered-file
file /tmp/recovered-file
```
Jest to praktyczna technika odzyskiwania usuniętych logów, tymczasowych sekretów, porzuconych plików binarnych, obróconych plików lub skryptów usuniętych po wykonaniu.

## Odzyskiwanie ext za pomocą debugfs

W systemach plików ext2/ext3/ext4 narzędzie `debugfs` może sprawdzać metadane inode i zrzucać zawartość inode z urządzenia blokowego lub obrazu; bez opcji `-w` otwiera system plików w trybie tylko do odczytu.<sup>[[2]](#references)</sup> W miarę możliwości pracuj na kopii lub obrazie tylko do odczytu.

Wyświetlaj wpisy i sprawdzaj inode za pomocą żądań `debugfs` służących do wyświetlania zawartości katalogów, sprawdzania stanu inode oraz weryfikowania ścieżek na podstawie inode.<sup>[[2]](#references)</sup>
```bash
debugfs -R 'ls -l /' ./disk.img
debugfs -R 'stat <inode_number>' ./disk.img
debugfs -R 'ncheck <inode_number>' ./disk.img
```
Zrzuć znany inode za pomocą polecenia `debugfs dump`, a następnie sklasyfikuj odzyskane dane wyjściowe za pomocą `file`.<sup>[[2]](#references)[[10]](#references)</sup>
```bash
debugfs -R 'dump <inode_number> /tmp/recovered.bin' ./disk.img
file /tmp/recovered.bin
```
Nie gwarantuje to odzyskania danych. Zależy ono od stanu systemu plików, od tego, czy bloki zostały ponownie użyte, oraz od tego, czy metadane nadal istnieją. W przypadku ext3/ext4 podręcznik `debugfs` wskazuje, że odzyskiwanie usuniętych inode może się nie powieść, ponieważ zwolnione bloki danych inode nie są już dostępne.<sup>[[2]](#references)</sup> Technika ta jest nadal cenna, ponieważ pozwala badać stan na poziomie inode bez polegania na normalnym przechodzeniu po ścieżkach.

## Wyczerpanie i kolejność inode

Wyczerpanie inode występuje, gdy system plików wyczerpie węzły plików, nawet jeśli pozostanie wolne miejsce na dysku.<sup>[[8]](#references)[[17]](#references)</sup> Zwykle powoduje problemy z niezawodnością, ale może również wyjaśniać nietypowe zachowanie podczas obsługi incydentu lub analizy w labie.

Użyj `df -i`, aby wyświetlić informacje o inode zamiast informacji o zajętości bloków.<sup>[[8]](#references)</sup>

Sprawdź obciążenie inode za pomocą `df` oraz zliczania nadrzędnych katalogów poleceniem `find`.<sup>[[4]](#references)[[8]](#references)</sup>
```bash
df -h
df -i
find /var /tmp /home -xdev -printf '%h\n' 2>/dev/null | sort | uniq -c | sort -n | tail
```
Numery inode'ów i znaczniki czasu mogą również pomóc w odtworzeniu aktywności w prostych środowiskach laboratoryjnych.

Poniższe dyrektywy formatu `find` udostępniają te pola.<sup>[[4]](#references)</sup>
```bash
find /path -xdev -printf '%i %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -n | tail -n 50
find /path -xdev -newermt '2026-01-01' -ls 2>/dev/null
```
Traktuj kolejność jako wskazówkę, a nie dowód. Operacje kopiowania, wypakowywanie archiwów, typ systemu plików, przywracanie oraz równoczesne zapisy mogą zmieniać wzorce alokacji.

## Uwagi dotyczące zabezpieczeń

- Podczas analizy montuj nieznane obrazy tylko do odczytu.<sup>[[1]](#references)</sup>
- Przechowuj uprzywilejowane skrypty, jednostki usług, plugins oraz ścieżki helperów poza punktami montowania zapisywalnymi przez użytkowników.
- Używaj `nosuid`, `nodev` oraz `noexec`, gdy jest to odpowiednie z punktu widzenia działania; opcje te wyłączają wykonywanie set-ID/capability, interpretację urządzeń lub bezpośrednie wykonywanie plików binarnych w punkcie montowania.<sup>[[1]](#references)</sup> Nie traktuj ich jako kompletnej granicy.
- Ogranicz dostęp do `/proc/<pid>/fd`; dereferencjonowanie tych linków jest kontrolowane przez kontrole dostępu ptrace oraz uprawnienia do plików.<sup>[[6]](#references)</sup> W miarę możliwości ogranicz także szerszy dostęp do metadanych procesów i inspekcję między użytkownikami.
- Monitoruj zapisywalne punkty montowania, nieoczekiwane hardlinki do uprzywilejowanych plików oraz usunięte, ale nadal otwarte, wrażliwe pliki.

## References

- [1] [mount(8) — strona podręcznika Linux](https://man7.org/linux/man-pages/man8/mount.8.html)
- [2] [debugfs(8) — strona podręcznika Linux](https://man7.org/linux/man-pages/man8/debugfs.8.html)
- [3] [inode(7) — strona podręcznika Linux](https://man7.org/linux/man-pages/man7/inode.7.html)
- [4] [find(1) — strona podręcznika Linux](https://man7.org/linux/man-pages/man1/find.1.html)
- [5] [unlink(2) — strona podręcznika Linux](https://man7.org/linux/man-pages/man2/unlink.2.html)
- [6] [proc_pid_fd(5) — strona podręcznika Linux](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)
- [7] [Dokumentacja /proc/sys/fs/ — dokumentacja Linux Kernel](https://www.kernel.org/doc/html/latest/admin-guide/sysctl/fs.html)
- [8] [df(1) — strona podręcznika Linux](https://man7.org/linux/man-pages/man1/df.1.html)
- [9] [findmnt(8) — strona podręcznika Linux](https://man7.org/linux/man-pages/man8/findmnt.8.html)
- [10] [file(1) — strona podręcznika Linux](https://man7.org/linux/man-pages/man1/file.1.html)
- [11] [blkid(8) — strona podręcznika Linux](https://man7.org/linux/man-pages/man8/blkid.8.html)
- [12] [strings(1) — strona podręcznika Linux](https://man7.org/linux/man-pages/man1/strings.1.html)
- [13] [crontab(5) — strona podręcznika Linux](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [14] [systemd.service(5) — strona podręcznika Linux](https://man7.org/linux/man-pages/man5/systemd.service.5.html)
- [15] [mount_namespaces(7) — strona podręcznika Linux](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html)
- [16] [chroot(2) — strona podręcznika Linux](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [17] [stat(1) — strona podręcznika Linux](https://man7.org/linux/man-pages/man1/stat.1.html)
- [18] [ls(1) — strona podręcznika Linux](https://man7.org/linux/man-pages/man1/ls.1.html)
- [19] [lsof(8) — strona podręcznika Linux](https://man7.org/linux/man-pages/man8/lsof.8.html)
- [20] [grep(1) — strona podręcznika Linux](https://man7.org/linux/man-pages/man1/grep.1.html)
- [21] [readlink(1) — strona podręcznika Linux](https://man7.org/linux/man-pages/man1/readlink.1.html)
- [22] [cp(1) — strona podręcznika Linux](https://man7.org/linux/man-pages/man1/cp.1.html)
- [23] [id(1) — strona podręcznika Linux](https://man7.org/linux/man-pages/man1/id.1.html)
{{#include ../../banners/hacktricks-training.md}}
