# System plików, Inode i odzyskiwanie

{{#include ../../banners/hacktricks-training.md}}

Abuse systemu plików często polega na zmyleniu relacji między widoczną ścieżką a obiektem, który się za nią znajduje. Obrazy dysków mogą ukrywać inny system plików, zapisywalne mounty mogą być wykorzystywane przez zadania uruchamiane z uprawnieniami, hardlinki mogą udostępniać ten sam inode pod inną nazwą, a usunięte pliki mogą nadal być odczytywane za pośrednictwem otwartego deskryptora pliku.

Ta strona skupia się na technice, a nie na jednym konkretnym labie lub celu.

## Obrazy dysków i montowania loop

Zwykły plik może zawierać kompletny system plików. Obrazy kopii zapasowych, skopiowane urządzenia blokowe, artefakty VM lub przemianowane obiekty binarne mogą więc zawierać poświadczenia, skrypty, klucze SSH, pliki konfiguracyjne lub flagi, nawet jeśli z zewnątrz nie wyglądają na przydatne.

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
Jeśli montowanie nie jest dostępne, sprawdź bezpośrednio metadane systemu plików:
```bash
debugfs -R 'ls -l /' ./candidate 2>/dev/null
debugfs -R 'stat /' ./candidate 2>/dev/null
```
Technika jest przydatna, ponieważ przekształca zwyczajnie wyglądający plik w drugie drzewo systemu plików. Traktuj ją jako sposób na odzyskanie ukrytych danych, a nie jako samodzielne privilege escalation.

## Writable Mount Abuse

Writable mount staje się niebezpieczny, gdy bardziej uprzywilejowany kontekst zaczyna później ufać czemuś, co się w nim znajduje. Ważne pytanie nie brzmi tylko: „czy mogę tutaj zapisywać?”, ale także: „kto później odczytuje, wykonuje, importuje lub ładuje dane z tego miejsca?”.

Znajdź writable mounts i podejrzanych konsumentów:
```bash
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
find /mnt /media /srv /opt -xdev -type d -writable -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|backup|hook|plugin|sh |bash |python' /mnt /media /srv /opt 2>/dev/null | head -n 50
```
Typowe wzorce nadużyć:

- Uprzywilejowany cron lub unit systemd uruchamia skrypt z możliwością zapisu znajdujący się w punkcie montowania.
- Uprzywilejowana usługa ładuje wtyczki, konfiguracje, szablony lub pomocnicze pliki binarne z punktu montowania.
- Punkt montowania zawiera pliki SUID i umożliwia ich modyfikację, zastąpienie lub manipulację ścieżką.
- Kontener lub chroot udostępnia ścieżkę obsługiwaną przez hosta, która jest zapisywalna z poziomu ograniczonego środowiska.

Ogólny schemat walidacji:
```bash
find /mnt /media /srv /opt -xdev -perm -4000 -type f -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
```
Podczas wykazywania wpływu w autoryzowanym laboratorium zachowaj payload możliwym do zaobserwowania i minimalnym, na przykład zapisując wynik `id` do pliku tymczasowego. Istotą tej techniki jest opóźnione wykonanie za pośrednictwem zaufanej lokalizacji z prawem zapisu.

## Inode'y i niejednoznaczność ścieżek

Inode jest obiektem systemu plików; ścieżka jest tylko wskazującą na niego nazwą. Ma to znaczenie, ponieważ dwie różne ścieżki mogą wskazywać ten sam inode, a usunięcie nazwy ścieżki nie zawsze oznacza, że dane zostały usunięte.

Porównuj pliki na podstawie inode'a i urządzenia:
```bash
ls -li /path/a /path/b
stat -c 'dev=%d inode=%i links=%h mode=%A owner=%U:%G path=%n' /path/a /path/b
```
Znajdź każdą widoczną ścieżkę dla tego samego inode:
```bash
find / -xdev -samefile /path/to/file -ls 2>/dev/null
```
Wyszukuj bezpośrednio według numeru inode, gdy masz tylko metadane:
```bash
find / -xdev -inum <inode_number> -ls 2>/dev/null
```
Ta technika jest przydatna, gdy plik występuje pod nieoczekiwaną nazwą, gdy aplikacja sprawdza jedną ścieżkę, ale używa innej, lub gdy uprzywilejowany wrapper korzysta z inodu, do którego można również uzyskać dostęp z innego miejsca.

## Hardlink Abuse

Hardlinki tworzą wiele nazw dla tego samego inodu. Nie wskazują na docelową ścieżkę, tak jak robią to symlinki; są równorzędnymi nazwami tego samego obiektu pliku.

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

Nowoczesne kernele i opcje montowania mogą ograniczać tworzenie hardlinków, aby zmniejszyć ryzyko tego rodzaju nadużyć, ale istniejące hardlinki nadal warto sprawdzać.

## Odzyskiwanie usuniętych plików przez otwarte FD

Gdy proces utrzymuje plik otwarty, dane pliku mogą pozostać dostępne nawet po usunięciu nazwy ścieżki. Linux udostępnia te otwarte deskryptory w `/proc/<pid>/fd/`.

Znajdź usunięte otwarte pliki:
```bash
ls -l /proc/*/fd/* 2>/dev/null | grep ' (deleted)' | head -n 50
lsof 2>/dev/null | grep deleted | head -n 50
```
Odzyskaj dane, gdy uprawnienia na to pozwalają:
```bash
readlink /proc/<pid>/fd/<fd>
cp /proc/<pid>/fd/<fd> /tmp/recovered-file
file /tmp/recovered-file
```
To praktyczna technika odzyskiwania usuniętych logów, tymczasowych sekretów, porzuconych plików binarnych, obróconych plików lub skryptów usuniętych po wykonaniu.

## Odzyskiwanie ext za pomocą debugfs

W systemach plików ext narzędzie `debugfs` może analizować metadane inode i czasami zrzucać zawartość plików z obrazu systemu plików. W miarę możliwości pracuj na kopii lub obrazie tylko do odczytu.

Wyświetl wpisy i sprawdź inode:
```bash
debugfs -R 'ls -l /' ./disk.img
debugfs -R 'stat <inode_number>' ./disk.img
debugfs -R 'ncheck <inode_number>' ./disk.img
```
Zrzut znanego inode:
```bash
debugfs -R 'dump <inode_number> /tmp/recovered.bin' ./disk.img
file /tmp/recovered.bin
```
Nie jest to gwarantowane odzyskiwanie danych. Zależy od stanu filesystemu, od tego, czy bloki zostały ponownie użyte, oraz od tego, czy metadane nadal istnieją. Technika jest nadal wartościowa, ponieważ pozwala badać stan na poziomie inode bez polegania na standardowym przechodzeniu po ścieżkach.

## Wyczerpanie inode i kolejność

Wyczerpanie inode występuje, gdy filesystemowi zabraknie obiektów plików, nawet jeśli pozostaje wolne miejsce na dysku. Zwykle powoduje to problemy z niezawodnością, ale może również wyjaśniać nietypowe zachowanie podczas incident response lub triage w labie.

Sprawdź wykorzystanie inode:
```bash
df -h
df -i
find /var /tmp /home -xdev -printf '%h\n' 2>/dev/null | sort | uniq -c | sort -n | tail
```
Numery inode i znaczniki czasu mogą również pomóc odtworzyć aktywność w prostych środowiskach laboratoryjnych:
```bash
find /path -xdev -printf '%i %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -n | tail -n 50
find /path -xdev -newermt '2026-01-01' -ls 2>/dev/null
```
Traktuj kolejność jako wskazówkę, a nie dowód. Operacje kopiowania, rozpakowywanie archiwów, typ systemu plików, przywracanie oraz równoczesne zapisy mogą zmieniać wzorce alokacji.

## Uwagi dotyczące obrony

- Podczas analizy montuj nieznane obrazy w trybie tylko do odczytu.
- Przechowuj uprzywilejowane skrypty, jednostki usług, pluginy i ścieżki helperów poza punktami montowania z możliwością zapisu przez użytkowników.
- Używaj `nosuid`, `nodev` i `noexec`, gdy jest to odpowiednie operacyjnie, ale nie traktuj ich jako kompletnej granicy bezpieczeństwa.
- W miarę możliwości ograniczaj dostęp do `/proc/<pid>/fd`, metadanych procesów oraz inspekcji procesów innych użytkowników.
- Monitoruj punkty montowania z możliwością zapisu, nieoczekiwane hardlinki do uprzywilejowanych plików oraz usunięte, ale wciąż otwarte wrażliwe pliki.

{{#include ../../banners/hacktricks-training.md}}
