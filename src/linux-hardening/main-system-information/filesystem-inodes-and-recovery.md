# System plików, inody i odzyskiwanie

Nadużywanie systemu plików często polega na myleniu relacji między widoczną ścieżką a obiektem, który się za nią znajduje.

Obrazy dysków mogą ukrywać inny system plików.<sup>[[1]](#references)</sup> Zapisywalne mounty mogą być wykorzystywane przez zadania uprzywilejowane.

Hardlinki mogą udostępniać ten sam inode pod inną nazwą.<sup>[[3]](#references)</sup> Usunięte pliki mogą nadal być odczytywane przez otwarty deskryptor pliku.<sup>[[5]](#references)[[6]](#references)</sup>

Ta strona koncentruje się na technice, a nie na jednym konkretnym labie lub celu.

## Obrazy dysków i montowania loop

Zwykły plik może zawierać kompletny system plików, dlatego obraz dysku po zamontowaniu może udostępniać drugie drzewo systemu plików.<sup>[[1]](#references)</sup>

Obrazy kopii zapasowych, skopiowane urządzenia blokowe, artefakty VM lub przemianowane bloby mogą zawierać credentials, skrypty, klucze SSH, pliki konfiguracyjne lub flagi, nawet jeśli z zewnątrz nie wyglądają na użyteczne.

Zidentyfikuj prawdopodobne obrazy za pomocą `file`, aby sklasyfikować kandydata, `blkid`, aby sprawdzić rozpoznane metadane systemu plików, oraz `strings -a`, aby przeskanować cały plik pod kątem drukowalnych sekwencji.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>
```bash
file ./candidate
ls -lh ./candidate
blkid ./candidate 2>/dev/null
strings -a ./candidate | head -n 50
```
Gdy montowanie jest dozwolone, użyj montowania loop z opcją `ro`, aby obraz został dołączony tylko do odczytu; poniższe polecenie `find` ogranicza głębokość inspekcji i typ plików.<sup>[[1]](#references)[[4]](#references)</sup>
```bash
mkdir -p /tmp/imgmnt
sudo mount -o loop,ro ./candidate /tmp/imgmnt
find /tmp/imgmnt -maxdepth 3 -type f -ls 2>/dev/null
sudo umount /tmp/imgmnt
```
Jeśli montowanie nie jest dostępne, a obraz jest w formacie ext2/ext3/ext4, sprawdź jego metadane bezpośrednio za pomocą `debugfs`.<sup>[[2]](#references)</sup>
```bash
debugfs -R 'ls -l /' ./candidate 2>/dev/null
debugfs -R 'stat /' ./candidate 2>/dev/null
```
Technika jest przydatna, ponieważ zamienia zwyczajnie wyglądający plik w drugie drzewo systemu plików.<sup>[[1]](#references)</sup> Traktuj ją jako sposób na odzyskanie ukrytych danych, a nie jako samodzielną metodę privilege escalation.

## Writable Mount Abuse

Zapisywalny mount staje się niebezpieczny, gdy uprzywilejowany kontekst później zaufa czemuś, co się w nim znajduje. Ważne pytanie nie brzmi tylko: „czy mogę tu zapisywać?”, lecz także: „kto później odczytuje, wykonuje, importuje lub ładuje dane z tego miejsca?”.

Użyj `findmnt`, aby sprawdzić zamontowane systemy plików i ich opcje.<sup>[[9]](#references)</sup>

Znajdź zapisywalne mounty i podejrzanych odbiorców za pomocą udokumentowanych predykatów `find` dotyczących uprawnień, typu i granic systemu plików, a następnie użyj rekurencyjnego `grep`, aby przeszukać prawdopodobne konfiguracje odbiorców.<sup>[[4]](#references)[[20]](#references)</sup>
```bash
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
find /mnt /media /srv /opt -xdev -type d -writable -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|backup|hook|plugin|sh |bash |python' /mnt /media /srv /opt 2>/dev/null | head -n 50
```
Typowe wzorce nadużyć:

- Zadanie cron lub usługa systemd uruchamia zapisywalny skrypt z punktu montowania.<sup>[[13]](#references)[[14]](#references)</sup>
- Usługa uprzywilejowana ładuje wtyczki, konfiguracje, szablony lub pomocnicze pliki binarne z punktu montowania.
- Punkt montowania zawiera pliki SUID i umożliwia ich modyfikację, zastąpienie lub manipulowanie ścieżką.
- Kontener lub chroot udostępnia ścieżkę opartą na hoście, która jest zapisywalna z ograniczonego środowiska. Przestrzenie nazw montowania zapewniają odrębne hierarchie montowania, podczas gdy `chroot()` zmienia tylko rozwiązywanie nazw ścieżek i nie jest pełną piaskownicą.<sup>[[15]](#references)[[16]](#references)</sup>

Ogólny wzorzec walidacji wykorzystujący te same predykaty `find`.<sup>[[4]](#references)</sup>
```bash
find /mnt /media /srv /opt -xdev -perm -4000 -type f -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
```
Podczas wykazywania wpływu w autoryzowanym labie payload powinien być obserwowalny i minimalny, na przykład przez zapisanie wyniku `id` do pliku tymczasowego.<sup>[[23]](#references)</sup> Podstawową techniką jest opóźnione wykonanie za pośrednictwem zaufanej lokalizacji z prawem zapisu.

## Inody i niejednoznaczność ścieżek

Inode jest obiektem systemu plików; ścieżka jest tylko wskazującą na niego nazwą. Metadane urządzenia i inode pozwalają rozróżniać obiekty w różnych systemach plików, a liczniki dowiązań ujawniają istnienie wielu dowiązań twardych.<sup>[[3]](#references)</sup> Usunięta nazwa ścieżki nie zawsze oznacza, że dane zniknęły, jeśli proces nadal ma otwarty plik.<sup>[[5]](#references)</sup>

Poniższe predykaty `find` porównują tożsamość inode, liczniki dowiązań, granice urządzeń i znaczniki czasu.<sup>[[4]](#references)</sup>

Porównuj pliki na podstawie inode i urządzenia za pomocą `ls -i` oraz formatów metadanych `stat`.<sup>[[17]](#references)[[18]](#references)</sup>
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
Ta technika jest przydatna, gdy plik pojawia się pod nieoczekiwaną nazwą, gdy aplikacja sprawdza jedną ścieżkę, ale używa innej, lub gdy uprzywilejowany wrapper korzysta z inode, do którego można również uzyskać dostęp z innego miejsca.

## Hardlink Abuse

Hardlinki tworzą wiele nazw dla tego samego inode. Nie wskazują ścieżki docelowej, tak jak robią to symlinki; są równoważnymi nazwami tego samego obiektu pliku.<sup>[[3]](#references)</sup>

Znajdź pliki SUID z wieloma hardlinkami, używając predykatów `find` dotyczących uprawnień i liczby linków.<sup>[[4]](#references)</sup>
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Sprawdź jeden podejrzany plik za pomocą `stat` i `find -samefile`.<sup>[[4]](#references)[[17]](#references)</sup>
```bash
stat /path/to/suspicious
find / -xdev -samefile /path/to/suspicious -ls 2>/dev/null
```
Dlaczego ma to znaczenie:

- Wrażliwy plik może być dostępny przez mniej oczywistą ścieżkę.
- Wrapper SUID może być ukryty za nazwą, która nie wygląda na uprzywilejowaną.
- Czyszczenie, które usuwa jedną ścieżkę, może pozostawić aktywny inny hardlink.

Linuxowy sysctl `fs.protected_hardlinks` może ograniczać tworzenie hardlinków między różnymi poziomami uprawnień.<sup>[[7]](#references)</sup> Istniejące hardlinki nadal wymagają sprawdzenia.

## Odzyskiwanie usuniętych plików za pomocą otwartych FD

Gdy proces utrzymuje plik otwarty, usunięcie jego ostatniej ścieżki pozostawia plik aktywny do momentu zamknięcia ostatniego deskryptora; Linux udostępnia te deskryptory w `/proc/<pid>/fd/`.<sup>[[5]](#references)[[6]](#references)</sup>

Znajdź usunięte, otwarte pliki, wyświetlając deskryptory w `/proc` i filtrując dane wyjściowe dotyczące otwartych plików.<sup>[[5]](#references)[[6]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>
```bash
ls -l /proc/*/fd/* 2>/dev/null | grep ' (deleted)' | head -n 50
lsof 2>/dev/null | grep deleted | head -n 50
```
Odzyskiwanie za pośrednictwem tych linków zależy od uprawnień, ponieważ odwoływanie się do `/proc/<pid>/fd` podlega kontrolom dostępu ptrace i uprawnieniom plików.<sup>[[6]](#references)</sup>

Jeśli jest dozwolone, `readlink` wyświetla cel deskryptora, a `cp` kopiuje jego zawartość.<sup>[[21]](#references)[[22]](#references)</sup>
```bash
readlink /proc/<pid>/fd/<fd>
cp /proc/<pid>/fd/<fd> /tmp/recovered-file
file /tmp/recovered-file
```
This is a practical technique for recovering deleted logs, temporary secrets, dropped binaries, rotated files, or scripts removed after execution.

## Odzyskiwanie ext za pomocą debugfs

On ext2/ext3/ext4 filesystems, `debugfs` can inspect inode metadata and dump inode contents from a block device or image; without `-w`, it opens the filesystem read-only.<sup>[[2]](#references)</sup> Work on a copy or a read-only image whenever possible.

List entries and inspect inodes with `debugfs` requests for directory listings, inode status, and inode-to-path checks.<sup>[[2]](#references)</sup>
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
Nie jest to gwarantowane odzyskiwanie danych. Zależy ono od stanu filesystemu, od tego, czy bloki zostały ponownie użyte, oraz od tego, czy metadane nadal istnieją. W przypadku ext3/ext4 manual `debugfs` informuje, że odzyskiwanie usuniętych inode'ów może się nie powieść, ponieważ zwolnione bloki danych inode'ów nie są już dostępne.<sup>[[2]](#references)</sup> Technika ta jest nadal cenna, ponieważ pozwala analizować stan na poziomie inode'ów bez polegania na standardowym przechodzeniu po ścieżkach.

## Wyczerpanie inode'ów i kolejność

Wyczerpanie inode'ów występuje, gdy filesystemowi zabraknie węzłów plików, nawet jeśli nadal pozostaje wolne miejsce na dysku.<sup>[[8]](#references)[[17]](#references)</sup> Zwykle powoduje problemy z niezawodnością, ale może również wyjaśniać nietypowe zachowanie podczas reagowania na incydenty lub triage'u w laboratorium.

Użyj `df -i`, aby wyświetlić informacje o inode'ach zamiast informacji o zajętości bloków.<sup>[[8]](#references)</sup>

Sprawdź presję na inode'y za pomocą `df` oraz zliczania katalogów nadrzędnych przy użyciu `find`.<sup>[[4]](#references)[[8]](#references)</sup>
```bash
df -h
df -i
find /var /tmp /home -xdev -printf '%h\n' 2>/dev/null | sort | uniq -c | sort -n | tail
```
Numery inode i znaczniki czasu mogą również pomóc w odtworzeniu aktywności w prostych środowiskach laboratoryjnych.

Poniższe dyrektywy formatu `find` udostępniają te pola.<sup>[[4]](#references)</sup>
```bash
find /path -xdev -printf '%i %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -n | tail -n 50
find /path -xdev -newermt '2026-01-01' -ls 2>/dev/null
```
Traktuj kolejność jako wskazówkę, a nie dowód. Operacje kopiowania, rozpakowywanie archiwów, typ systemu plików, przywracanie danych i równoczesne zapisy mogą zmieniać wzorce alokacji.

## Uwagi dotyczące ochrony

- Podczas analizy montuj nieznane obrazy tylko do odczytu.<sup>[[1]](#references)</sup>
- Przechowuj uprzywilejowane skrypty, jednostki usług, pluginy i ścieżki pomocnicze poza punktami montowania zapisywalnymi przez użytkowników.
- Używaj `nosuid`, `nodev` i `noexec`, gdy jest to odpowiednie z punktu widzenia działania systemu; opcje te wyłączają wykonywanie set-ID/capability, interpretację urządzeń lub bezpośrednie wykonywanie plików binarnych w punkcie montowania.<sup>[[1]](#references)</sup> Nie traktuj ich jako kompletnej granicy bezpieczeństwa.
- Ogranicz dostęp do `/proc/<pid>/fd`; rozwiązywanie tych linków jest kontrolowane przez kontrole dostępu ptrace i uprawnienia plików.<sup>[[6]](#references)</sup> W miarę możliwości ogranicz również szerszy dostęp do metadanych procesów i inspekcję między użytkownikami.
- Monitoruj zapisywalne punkty montowania, nieoczekiwane hardlinki do uprzywilejowanych plików oraz wrażliwe pliki usunięte, ale nadal otwarte.

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
