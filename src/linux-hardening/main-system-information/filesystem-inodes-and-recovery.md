# System plików, inode'y i odzyskiwanie

{{#include ../../banners/hacktricks-training.md}}

Abuse systemu plików często polega na zmyleniu relacji między widoczną ścieżką a znajdującym się za nią obiektem. Obrazy dysków mogą ukrywać inny system plików, zapisywalne mounty mogą być wykorzystywane przez zadania uprzywilejowane, hardlinki mogą udostępniać ten sam inode pod inną nazwą, a usunięte pliki mogą nadal być odczytywane za pośrednictwem otwartego deskryptora pliku.

Ta strona koncentruje się na technice, a nie na konkretnym labie lub celu.

## Obrazy dysków i montowania loop

Zwykły plik może zawierać kompletny system plików. Obrazy kopii zapasowych, skopiowane urządzenia blokowe, artefakty VM lub zmienione nazwy blobów mogą zatem zawierać dane uwierzytelniające, skrypty, klucze SSH, pliki konfiguracyjne lub flagi, nawet jeśli z zewnątrz nie wyglądają na przydatne.

Zidentyfikuj prawdopodobne obrazy:
```bash
file ./candidate
ls -lh ./candidate
blkid ./candidate 2>/dev/null
strings -a ./candidate | head -n 50
```
Jeśli montowanie jest dozwolone, najpierw zamontuj nieznane obrazy w trybie tylko do odczytu:
```bash
mkdir -p /tmp/imgmnt
sudo mount -o loop,ro ./candidate /tmp/imgmnt
find /tmp/imgmnt -maxdepth 3 -type f -ls 2>/dev/null
sudo umount /tmp/imgmnt
```
Jeśli montowanie nie jest dostępne, zbadaj bezpośrednio metadane systemu plików:
```bash
debugfs -R 'ls -l /' ./candidate 2>/dev/null
debugfs -R 'stat /' ./candidate 2>/dev/null
```
Technika jest przydatna, ponieważ przekształca zwyczajnie wyglądający plik w drugie drzewo systemu plików. Traktuj ją jako sposób na odzyskanie ukrytych danych, a nie jako samodzielną metodę privilege escalation.

## Writable Mount Abuse

Writable mount staje się niebezpieczny, gdy uprzywilejowany kontekst później ufa czemuś, co się w nim znajduje. Ważne pytanie nie brzmi tylko: „czy mogę tutaj zapisywać?”, ale także: „kto później odczytuje, wykonuje, importuje lub ładuje dane z tego miejsca?”.

Znajdź writable mounts i podejrzanych konsumentów:
```bash
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
find /mnt /media /srv /opt -xdev -type d -writable -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|backup|hook|plugin|sh |bash |python' /mnt /media /srv /opt 2>/dev/null | head -n 50
```
Typowe wzorce nadużyć:

- Uprzywilejowany cron lub unit systemd uruchamia zapisywalny skrypt z zamontowanego systemu plików.
- Uprzywilejowana usługa ładuje pluginy, konfigurację, szablony lub pomocnicze pliki binarne z zamontowanego systemu plików.
- Zamontowany system plików zawiera pliki SUID i umożliwia ich modyfikowanie, podmienianie lub manipulowanie ścieżkami.
- Kontener lub chroot udostępnia ścieżkę opartą na hoście, która jest zapisywalna z ograniczonego środowiska.

Ogólny wzorzec walidacji:
```bash
find /mnt /media /srv /opt -xdev -perm -4000 -type f -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
```
Podczas wykazywania wpływu w autoryzowanym laboratorium payload powinien być możliwy do zaobserwowania i minimalny, na przykład poprzez zapisanie wyniku `id` do pliku tymczasowego. Podstawowa technika polega na opóźnionym wykonaniu za pośrednictwem zaufanej lokalizacji z prawem zapisu.

## Inody i niejednoznaczność ścieżek

Inode jest obiektem systemu plików; path to tylko wskazująca na niego nazwa. Ma to znaczenie, ponieważ dwie różne ścieżki mogą wskazywać ten sam inode, a usunięcie pathname nie zawsze oznacza, że dane zniknęły.

Porównuj pliki według inode i urządzenia:
```bash
ls -li /path/a /path/b
stat -c 'dev=%d inode=%i links=%h mode=%A owner=%U:%G path=%n' /path/a /path/b
```
Znajdź każdą widoczną ścieżkę do tego samego inode:
```bash
find / -xdev -samefile /path/to/file -ls 2>/dev/null
```
Wyszukuj bezpośrednio według numeru inode, gdy masz tylko metadane:
```bash
find / -xdev -inum <inode_number> -ls 2>/dev/null
```
Ta technika jest przydatna, gdy plik pojawia się pod nieoczekiwaną nazwą, gdy aplikacja sprawdza jedną ścieżkę, ale używa innej, lub gdy uprzywilejowany wrapper korzysta z inode, do którego można również uzyskać dostęp z innego miejsca.

## Nadużywanie hardlinków

Hardlinki tworzą wiele nazw dla tego samego inode. Nie wskazują ścieżki docelowej, tak jak symlinki; są równoważnymi nazwami tego samego obiektu pliku.

Znajdź pliki SUID z wieloma hardlinkami:
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Zbadaj jeden podejrzany plik:
```bash
stat /path/to/suspicious
find / -xdev -samefile /path/to/suspicious -ls 2>/dev/null
```
Dlaczego ma to znaczenie:

- Wrażliwy plik może być dostępny za pośrednictwem mniej oczywistej ścieżki.
- Wrapper SUID może być ukryty pod nazwą, która nie wygląda na uprzywilejowaną.
- Czyszczenie, które usuwa jedną nazwę ścieżki, może pozostawić aktywny inny hardlink.

Nowoczesne jądra i opcje montowania mogą ograniczać tworzenie hardlinków, aby zmniejszyć ryzyko tego rodzaju nadużyć, ale istniejące hardlinki nadal warto sprawdzać.

## Odzyskiwanie usuniętych plików za pośrednictwem otwartych FD

Gdy proces ma otwarty plik, dane pliku mogą pozostać dostępne nawet po usunięciu nazwy ścieżki. Linux udostępnia te otwarte deskryptory w katalogu `/proc/<pid>/fd/`.

Znajdź usunięte otwarte pliki:
```bash
ls -l /proc/*/fd/* 2>/dev/null | grep ' (deleted)' | head -n 50
lsof 2>/dev/null | grep deleted | head -n 50
```
Odzyskaj dane, gdy pozwalają na to uprawnienia:
```bash
readlink /proc/<pid>/fd/<fd>
cp /proc/<pid>/fd/<fd> /tmp/recovered-file
file /tmp/recovered-file
```
To praktyczna technika odzyskiwania usuniętych logów, sekretów tymczasowych, porzuconych plików binarnych, rotowanych plików lub skryptów usuniętych po wykonaniu.

## Odzyskiwanie ext za pomocą debugfs

W systemach plików ext narzędzie `debugfs` może analizować metadane inode i czasami zrzucać zawartość plików z obrazu systemu plików. W miarę możliwości pracuj na kopii lub obrazie zamontowanym tylko do odczytu.

Wyświetl wpisy i przeanalizuj inode'y:
```bash
debugfs -R 'ls -l /' ./disk.img
debugfs -R 'stat <inode_number>' ./disk.img
debugfs -R 'ncheck <inode_number>' ./disk.img
```
Zrzut znanego inode'a:
```bash
debugfs -R 'dump <inode_number> /tmp/recovered.bin' ./disk.img
file /tmp/recovered.bin
```
Nie gwarantuje to odzyskania danych. Zależy ono od stanu filesystemu, od tego, czy bloki zostały ponownie użyte, oraz od tego, czy metadane nadal istnieją. Technika ta jest nadal wartościowa, ponieważ pozwala sprawdzać stan na poziomie inode bez polegania na standardowym przechodzeniu po ścieżkach.

## Wyczerpanie inode i kolejność

Wyczerpanie inode ma miejsce, gdy filesystemowi zabraknie obiektów plików, nawet jeśli pozostanie wolne miejsce na dysku. Zwykle powoduje to problemy z niezawodnością, ale może również wyjaśniać nietypowe zachowanie podczas incident response lub analizy w labie.

Sprawdź obciążenie inode:
```bash
df -h
df -i
find /var /tmp /home -xdev -printf '%h\n' 2>/dev/null | sort | uniq -c | sort -n | tail
```
Numery inode i znaczniki czasu mogą również pomóc w odtworzeniu aktywności w prostych środowiskach laboratoryjnych:
```bash
find /path -xdev -printf '%i %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -n | tail -n 50
find /path -xdev -newermt '2026-01-01' -ls 2>/dev/null
```
Traktuj kolejność jako wskazówkę, a nie dowód. Operacje kopiowania, wypakowywanie archiwów, typ systemu plików, przywracanie oraz równoczesne zapisy mogą zmieniać wzorce alokacji.

## Uwagi dotyczące ochrony

- Podczas analizy montuj nieznane obrazy w trybie tylko do odczytu.
- Przechowuj uprzywilejowane skrypty, jednostki usług, wtyczki i ścieżki pomocnicze poza punktami montowania zapisywalnymi przez użytkowników.
- Używaj `nosuid`, `nodev` i `noexec`, gdy jest to odpowiednie z operacyjnego punktu widzenia, ale nie traktuj ich jako kompletnej granicy ochrony.
- W miarę możliwości ograniczaj dostęp do `/proc/<pid>/fd`, metadanych procesów i inspekcji procesów innych użytkowników.
- Monitoruj zapisywalne punkty montowania, nieoczekiwane hardlinki do uprzywilejowanych plików oraz usunięte, ale nadal otwarte poufne pliki.
{{#include ../../banners/hacktricks-training.md}}
