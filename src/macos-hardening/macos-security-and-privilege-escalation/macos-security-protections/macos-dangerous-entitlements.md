# Niebezpieczne Entitlements i uprawnienia TCC w macOS

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> Należy pamiętać, że entitlements zaczynające się od **`com.apple`** nie są dostępne dla stron trzecich — tylko Apple może je przyznawać... Jeśli jednak używasz certyfikatu enterprise, możesz faktycznie utworzyć własne entitlements zaczynające się od **`com.apple`** i ominąć oparte na tym zabezpieczenia.

## Wysokie

### `com.apple.rootless.install.heritable`

Entitlement **`com.apple.rootless.install.heritable`** pozwala na **bypass SIP**. Sprawdź [tutaj więcej informacji](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Entitlement **`com.apple.rootless.install`** pozwala na **bypass SIP**. Sprawdź [tutaj więcej informacji](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (wcześniej nazywany `task_for_pid-allow`)**

Ten entitlement pozwala uzyskać **task port dowolnego** procesu, z wyjątkiem kernela. Sprawdź [**tutaj więcej informacji**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

Ten entitlement pozwala innym procesom posiadającym entitlement **`com.apple.security.cs.debugger`** uzyskać task port procesu uruchomionego przez binary z tym entitlementem oraz **wstrzyknąć do niego code**. Sprawdź [**tutaj więcej informacji**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Apps z Debugging Tool Entitlement mogą wywołać `task_for_pid()`, aby pobrać prawidłowy task port dla unsigned i third-party apps z ustawionym entitlementem `Get Task Allow` o wartości `true`. Jednak nawet z debugging tool entitlement debugger **nie może uzyskać task ports** procesów, które **nie mają entitlements `Get Task Allow`** i dlatego są chronione przez System Integrity Protection. Sprawdź [**tutaj więcej informacji**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).

### `com.apple.security.cs.disable-library-validation`

Ten entitlement pozwala **ładować frameworks, plug-ins lub libraries bez konieczności podpisania ich przez Apple lub podpisania tym samym Team ID** co główny executable, więc attacker mógłby wykorzystać dowolne ładowanie library do wstrzyknięcia code. Sprawdź [**tutaj więcej informacji**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Ten entitlement jest bardzo podobny do **`com.apple.security.cs.disable-library-validation`**, ale **zamiast** **bezpośrednio wyłączać** library validation, pozwala procesowi **wywołać system call `csops` w celu wyłączenia go** w czasie runtime.

Nazwa entitlementu jest hardcoded w XNU obok operacji `csops`, która go wykorzystuje:<sup>[2]</sup>
```c
/* bsd/sys/codesign.h */
#define CLEAR_LV_ENTITLEMENT "com.apple.private.security.clear-library-validation"
...
#define CS_OPS_CLEAR_LV     15  /* clear the library validation flag */
```
Obsługa jądra dla `CS_OPS_CLEAR_LV` (`bsd/kern/kern_proc.c`) dokładnie pokazuje, jak ograniczony jest ten prymityw:<sup>[3]</sup>
```c
case CS_OPS_CLEAR_LV: {
#if !defined(XNU_TARGET_OS_OSX)
// We only support dropping library validation on macOS
error = ENOTSUP;
#else
if (forself == 1 && IOTaskHasEntitlement(proc_task(pt), CLEAR_LV_ENTITLEMENT)) {
proc_lock(pt);
if (!(proc_getcsflags(pt) & CS_INSTALLER) && (pt->p_subsystem_root_path == NULL)) {
proc_csflags_clear(pt, CS_REQUIRE_LV | CS_FORCED_LV);
error = 0;
```
Zatem operacja:

- Jest dostępna wyłącznie w **macOS** (`ENOTSUP` na każdej innej platformie).
- Działa wyłącznie na **sobie samej** (`forself == 1`) — nie można za jej pomocą usunąć library validation z innego procesu.
- Wymaga, aby proces faktycznie **posiadał entitlement**, i odmawia działania, jeśli proces ma flagę `CS_INSTALLER` lub działa w ramach ścieżki głównej subsystemu.
- Usuwa **`CS_REQUIRE_LV | CS_FORCED_LV`** z flag code-signing procesu.

Komentarz XNU wyjaśnia zamierzone zastosowanie, a także to, dlaczego jest ono interesujące dla atakującego:

> Ta opcja służy do usuwania library validation z działającego procesu. Jest używana w architekturach pluginów, gdy program musi ładować niezaufane biblioteki. [...] Gdy proces załaduje niezaufaną bibliotekę, poleganie na library validation w przyszłości nie będzie skuteczne.

Innymi słowy, **każdy binary posiadający ten entitlement jest celem dylib-injection**: uruchom code wewnątrz niego (lub nakłoń go do załadowania swojego plug-inu) po usunięciu `CS_REQUIRE_LV`, a odziedziczysz wszystkie uprawnienia host processu.

### `com.apple.security.cs.allow-dyld-environment-variables`

Ten entitlement pozwala **używać zmiennych środowiskowych DYLD**, które mogą służyć do wstrzykiwania bibliotek i code. Więcej informacji znajdziesz [**tutaj**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` lub `com.apple.rootless.storage`.`TCC`

[**Według tego bloga**](https://objective-see.org/blog/blog_0x4C.html) **oraz** [**tego bloga**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), te entitlementy pozwalają **modyfikować** bazę danych **TCC**.

### **`system.install.apple-software`** i **`system.install.apple-software.standar-user`**

Te entitlementy pozwalają **instalować software bez pytania użytkownika o zgodę**, co może pomóc w **privilege escalation**.

### `com.apple.private.security.kext-management`

Entitlement wymagany do poproszenia **kernela o załadowanie kernel extension**.

### **`com.apple.private.icloud-account-access`**

Dzięki entitlementowi **`com.apple.private.icloud-account-access`** można komunikować się z usługą XPC **`com.apple.iCloudHelper`**, która **udostępni tokeny iCloud**.

**iMovie** i **Garageband** posiadały ten entitlement.

Więcej **informacji** o exploicie umożliwiającym **uzyskanie tokenów iCloud** dzięki temu entitlementowi znajdziesz w nagraniu: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Nie wiem, co to umożliwia

### `com.apple.private.apfs.revert-to-snapshot`

TODO: W [**tym raporcie**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **wspomniano, że można tego użyć do** aktualizacji zawartości chronionej przez SSV po ponownym uruchomieniu. Jeśli wiesz, jak to działa, wyślij PR!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: W [**tym raporcie**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **wspomniano, że można tego użyć do** aktualizacji zawartości chronionej przez SSV po ponownym uruchomieniu. Jeśli wiesz, jak to działa, wyślij PR!

### `keychain-access-groups`

Ta lista entitlementów określa grupy **keychain**, do których aplikacja ma dostęp:
```xml
<key>keychain-access-groups</key>
<array>
<string>ichat</string>
<string>apple</string>
<string>appleaccount</string>
<string>InternetAccounts</string>
<string>IMCore</string>
</array>
```
### **`kTCCServiceSystemPolicyAllFiles`**

Przyznaje uprawnienia **Full Disk Access**, jedne z najwyższych uprawnień TCC, jakie można uzyskać.

### **`kTCCServiceAppleEvents`**

Umożliwia aplikacji wysyłanie zdarzeń do innych aplikacji, które są powszechnie używane do **automatyzacji zadań**. Kontrolując inne aplikacje, może nadużywać uprawnień przyznanych tym aplikacjom.

Na przykład zmuszając je do poproszenia użytkownika o hasło:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Lub nakłonienie ich do wykonywania **arbitrary actions**.

### **`kTCCServiceEndpointSecurityClient`**

Umożliwia między innymi **zapis do bazy danych TCC użytkownika**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Umożliwia **zmianę** atrybutu **`NFSHomeDirectory`** użytkownika, co zmienia ścieżkę jego folderu domowego, a tym samym umożliwia **bypass TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Umożliwia modyfikowanie plików wewnątrz pakietów aplikacji (wewnątrz app.app), co jest **domyślnie niedozwolone**.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

Można sprawdzić, kto ma ten dostęp, w _Ustawieniach systemowych_ > _Prywatność i ochrona_ > _Zarządzanie aplikacjami._

### `kTCCServiceAccessibility`

Proces będzie mógł **nadużywać funkcji ułatwień dostępu macOS**, co oznacza na przykład możliwość wysyłania naciśnięć klawiszy. W ten sposób mógłby zażądać dostępu do sterowania aplikacją, taką jak Finder, i zatwierdzić okno dialogowe przy użyciu tego uprawnienia.

## Uprawnienia związane z Trustcache/CDhash

Istnieją uprawnienia, których można użyć do ominięcia zabezpieczeń Trustcache/CDhash, uniemożliwiających uruchamianie obniżonych wersji binariów Apple.

## Średnie

### `com.apple.security.cs.allow-jit`

To uprawnienie umożliwia **tworzenie pamięci, która jest zapisywalna i wykonywalna**, poprzez przekazanie flagi `MAP_JIT` do funkcji systemowej `mmap()`. Sprawdź [**więcej informacji tutaj**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

To uprawnienie umożliwia **nadpisywanie lub patchowanie kodu C**, korzystanie z dawno przestarzałej funkcji **`NSCreateObjectFileImageFromMemory`** (która jest zasadniczo niebezpieczna) lub korzystanie z frameworka **DVDPlayback**. Sprawdź [**więcej informacji tutaj**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).

> [!CAUTION]
> Uwzględnienie tego uprawnienia naraża aplikację na typowe podatności występujące w językach programowania, których kod nie zapewnia bezpieczeństwa pamięci. Należy dokładnie rozważyć, czy aplikacja potrzebuje tego wyjątku.

### `com.apple.security.cs.disable-executable-page-protection`

To uprawnienie umożliwia **modyfikowanie sekcji własnych plików wykonywalnych** na dysku w celu wymuszenia zakończenia działania. Sprawdź [**więcej informacji tutaj**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).

> [!CAUTION]
> Uprawnienie Disable Executable Memory Protection jest uprawnieniem skrajnym, które usuwa fundamentalne zabezpieczenie aplikacji, umożliwiając atakującemu przepisanie kodu wykonywalnego aplikacji bez wykrycia. Jeśli to możliwe, należy preferować węższy zakres uprawnień.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

To uprawnienie umożliwia zamontowanie systemu plików nullfs (domyślnie zabronione). Narzędzie: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

Zgodnie z tym wpisem na blogu, to uprawnienie TCC zwykle występuje w postaci:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Pozwala procesowi **prosić o wszystkie uprawnienia TCC**.

### **`kTCCServicePostEvent`**

Pozwala na **wstrzykiwanie syntetycznych zdarzeń klawiatury i myszy** w całym systemie za pośrednictwem `CGEventPost()`. Proces posiadający to uprawnienie może symulować naciśnięcia klawiszy, kliknięcia myszy i zdarzenia przewijania w dowolnej aplikacji — skutecznie zapewniając **zdalną kontrolę** nad pulpitem.

Jest to szczególnie niebezpieczne w połączeniu z `kTCCServiceAccessibility` lub `kTCCServiceListenEvent`, ponieważ umożliwia zarówno odczytywanie, JAK I wstrzykiwanie danych wejściowych.
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

Umożliwia **przechwytywanie wszystkich zdarzeń klawiatury i myszy** w całym systemie (monitorowanie wejścia / keylogging). Proces może zarejestrować `CGEventTap`, aby przechwytywać każde naciśnięcie klawisza w dowolnej aplikacji, w tym hasła, numery kart kredytowych i prywatne wiadomości.

Szczegółowe techniki exploitation opisano tutaj:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

Umożliwia **odczytywanie bufora ekranu** — wykonywanie zrzutów ekranu i nagrywanie obrazu z dowolnej aplikacji, w tym zabezpieczonych pól tekstowych. W połączeniu z OCR pozwala automatycznie wyodrębniać hasła i poufne dane wyświetlane na ekranie.

> [!WARNING]
> Począwszy od macOS Sonoma, przechwytywanie ekranu wyświetla stały wskaźnik na pasku menu. W starszych wersjach nagrywanie ekranu może odbywać się całkowicie bezgłośnie.

### **`kTCCServiceCamera`**

Umożliwia **przechwytywanie zdjęć i obrazu wideo** z wbudowanej kamery lub podłączonych kamer USB. Code injection do binary z uprawnieniami kamery umożliwia cichy nadzór wizualny.

### **`kTCCServiceMicrophone`**

Umożliwia **nagrywanie dźwięku** ze wszystkich urządzeń wejściowych. Daemony działające w tle z dostępem do mikrofonu zapewniają stały nadzór nad dźwiękami otoczenia bez widocznego okna aplikacji.

### **`kTCCServiceLocation`**

Umożliwia odpytywanie o **fizyczną lokalizację** urządzenia za pomocą triangulacji Wi-Fi lub beaconów Bluetooth. Ciągłe monitorowanie ujawnia adresy domu i pracy, wzorce podróży oraz codzienne rutyny.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

Dostęp do **Contacts** (nazwy, adresy e-mail, numery telefonów — przydatne w spear-phishing), **Calendar** (harmonogramy spotkań, listy uczestników) oraz **Photos** (prywatne zdjęcia i zrzuty ekranu, które mogą zawierać dane uwierzytelniające oraz metadane lokalizacji).

Kompletne techniki exploitation służące do kradzieży danych uwierzytelniających za pośrednictwem uprawnień TCC opisano tutaj:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox i uprawnienia Code Signing

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Tymczasowe wyjątki Sandbox** osłabiają App Sandbox, umożliwiając komunikację z systemowymi usługami Mach/XPC, które Sandbox normalnie blokuje. Jest to **podstawowy mechanizm ucieczki z Sandbox** — przejęta aplikacja działająca w Sandbox może używać wyjątków mach-lookup do uzyskiwania dostępu do uprzywilejowanych daemonów i wykorzystywania ich interfejsów XPC.
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && codesign -d --entitlements - "$binary" 2>&1 | grep -q "mach-lookup" && echo "$(basename "$1")"
' _ {} \; 2>/dev/null
```
Szczegółowy łańcuch exploitation: sandboxed app → mach-lookup exception → vulnerable daemon → sandbox escape — zobacz:

{{#ref}}
macos-code-signing-weaknesses-and-sandbox-escapes.md
{{#endref}}

### `com.apple.developer.driverkit`

**DriverKit entitlements** umożliwiają binariom sterowników działającym w user-space bezpośrednią komunikację z kernelem za pośrednictwem interfejsów IOKit. Binarne sterowniki DriverKit zarządzają sprzętem: USB, Thunderbolt, PCIe, urządzeniami HID, dźwiękiem i siecią.

Przejęcie binarnego sterownika DriverKit umożliwia:
- **Kernel attack surface** za pośrednictwem spreparowanych wywołań `IOConnectCallMethod`
- **USB device spoofing** (emulowanie klawiatury w celu wykonania HID injection)
- **DMA attacks** za pośrednictwem interfejsów PCIe/Thunderbolt
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
W celu uzyskania szczegółowych informacji na temat exploitation IOKit/DriverKit zobacz:

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}

## Odnośniki

- [1] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [2] [XNU — `bsd/sys/codesign.h` (operacje `CS_OPS_*` i `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [3] [XNU — `bsd/kern/kern_proc.c` (obsługa `csops` / `CS_OPS_CLEAR_LV`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)

{{#include ../../../banners/hacktricks-training.md}}
