# Niebezpieczne Entitlements macOS i uprawnienia TCC

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> Pamiętaj, że entitlements rozpoczynające się od **`com.apple`** nie są dostępne dla podmiotów trzecich — tylko Apple może je przyznawać... Jeśli jednak używasz certyfikatu enterprise, możesz faktycznie utworzyć własne entitlements rozpoczynające się od **`com.apple`** i ominąć oparte na tym zabezpieczenia.

## Wysoki

### `com.apple.rootless.install.heritable`

Entitlement **`com.apple.rootless.install.heritable`** umożliwia **bypass SIP**. Sprawdź [tutaj więcej informacji](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Entitlement **`com.apple.rootless.install`** umożliwia **bypass SIP**. Sprawdź[ tutaj więcej informacji](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (wcześniej nazywany `task_for_pid-allow`)**

Ten entitlement umożliwia uzyskanie **task port dla dowolnego** procesu z wyjątkiem kernela. Sprawdź [**tutaj więcej informacji**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

Ten entitlement umożliwia innym procesom posiadającym entitlement **`com.apple.security.cs.debugger`** uzyskanie task port procesu uruchomionego przez binary z tym entitlementem oraz **wstrzyknięcie do niego kodu**. Sprawdź [**tutaj więcej informacji**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Aplikacje posiadające Debugging Tool Entitlement mogą wywoływać `task_for_pid()`, aby pobrać prawidłowy task port dla niepodpisanych aplikacji oraz aplikacji firm trzecich z ustawionym entitlementem `Get Task Allow` o wartości `true`. Jednak nawet przy użyciu debugging tool entitlement debugger **nie może uzyskać task ports** procesów, które **nie posiadają entitlements `Get Task Allow`** i dlatego są chronione przez System Integrity Protection. Sprawdź [**tutaj więcej informacji**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).<sup>[[3]](#references)</sup>

### `com.apple.security.cs.disable-library-validation`

Ten entitlement umożliwia **ładowanie frameworks, plug-ins lub libraries bez podpisu Apple ani podpisu z tym samym Team ID** co główny executable, więc attacker może wykorzystać dowolne ładowanie library do wstrzyknięcia kodu. Sprawdź [**tutaj więcej informacji**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).<sup>[[4]](#references)</sup>

### `com.apple.private.security.clear-library-validation`

Ten entitlement jest bardzo podobny do **`com.apple.security.cs.disable-library-validation`**, ale **zamiast** **bezpośredniego wyłączenia** library validation umożliwia procesowi **wywołanie system call `csops` w celu wyłączenia jej** w czasie działania.

Nazwa entitlementu jest hardcoded w XNU obok operacji `csops`, która go wykorzystuje:<sup>[[1]](#references)</sup>
```c
/* bsd/sys/codesign.h */
#define CLEAR_LV_ENTITLEMENT "com.apple.private.security.clear-library-validation"
...
#define CS_OPS_CLEAR_LV     15  /* clear the library validation flag */
```
Obsługa jądra dla `CS_OPS_CLEAR_LV` (`bsd/kern/kern_proc.c`) pokazuje dokładnie, jak ograniczony jest ten prymityw:<sup>[[2]](#references)</sup>
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

- Jest dostępna **wyłącznie na macOS** (`ENOTSUP` na każdej innej platformie).
- Działa tylko na **samym sobie** (`forself == 1`) — nie można za jej pomocą usunąć library validation z innego procesu.
- Wymaga, aby proces faktycznie **posiadał entitlement**, i odmawia działania, jeśli proces ma flagę `CS_INSTALLER` lub działa w ramach ścieżki głównej subsystemu.
- Usuwa **`CS_REQUIRE_LV | CS_FORCED_LV`** z flag code-signing procesu.

Komentarz XNU wyjaśnia zamierzony przypadek użycia, a także to, dlaczego jest on interesujący dla atakującego:

> Ta opcja służy do usunięcia library validation z uruchomionego procesu. Jest używana w architekturach pluginów, gdy program musi załadować niezaufane biblioteki. [...] Po załadowaniu przez proces niezaufanej biblioteki poleganie na library validation w przyszłości nie będzie skuteczne.

Innymi słowy, **każdy binary posiadający ten entitlement jest celem dylib-injection**: uruchom kod wewnątrz niego (lub nakłoń go do załadowania swojego plug-inu) po usunięciu przez niego `CS_REQUIRE_LV`, a odziedziczysz wszystkie uprawnienia host process.

### `com.apple.security.cs.allow-dyld-environment-variables`

Ten entitlement pozwala **używać zmiennych środowiskowych DYLD**, które mogą służyć do injectowania bibliotek i kodu. Sprawdź [**to, aby uzyskać więcej informacji**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).<sup>[[5]](#references)</sup>

### `com.apple.private.tcc.manager` lub `com.apple.rootless.storage`.`TCC`

[**Według tego bloga**](https://objective-see.org/blog/blog_0x4C.html) **oraz** [**tego bloga**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/) te entitlements pozwalają **modyfikować** bazę danych **TCC**.<sup>[[6]](#references)[[7]](#references)</sup>

### **`system.install.apple-software`** oraz **`system.install.apple-software.standar-user`**

Te entitlements pozwalają **instalować software bez pytania użytkownika o uprawnienia**, co może być pomocne przy **privilege escalation**.

### `com.apple.private.security.kext-management`

Entitlement wymagany do poproszenia **kernela o załadowanie kernel extension**.

### **`com.apple.private.icloud-account-access`**

Dzięki entitlementowi **`com.apple.private.icloud-account-access`** możliwa jest komunikacja z usługą XPC **`com.apple.iCloudHelper`**, która **udostępni tokeny iCloud**.

**iMovie** i **Garageband** posiadały ten entitlement.

Aby uzyskać więcej **informacji** o exploicie pozwalającym **pozyskać tokeny iCloud** dzięki temu entitlementowi, sprawdź prelekcję: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[8]](#references)</sup>

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Nie wiem, na co to pozwala

### `com.apple.private.apfs.revert-to-snapshot`

TODO: W [**tym raporcie**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **wspomniano, że można tego użyć do** aktualizacji zawartości chronionej przez SSV po ponownym uruchomieniu. Jeśli wiesz, jak to działa, wyślij PR!<sup>[[9]](#references)</sup>

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: W [**tym raporcie**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **wspomniano, że można tego użyć do** aktualizacji zawartości chronionej przez SSV po ponownym uruchomieniu. Jeśli wiesz, jak to działa, wyślij PR!<sup>[[9]](#references)</sup>

### `keychain-access-groups`

Ten entitlement określa grupy **keychain**, do których aplikacja ma dostęp:
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

Nadaje uprawnienia **Full Disk Access**, jedne z najwyższych uprawnień TCC, jakie można uzyskać.

### **`kTCCServiceAppleEvents`**

Pozwala aplikacji wysyłać zdarzenia do innych aplikacji, które są powszechnie używane do **automatyzowania zadań**. Kontrolując inne aplikacje, może nadużywać uprawnień przyznanych tym aplikacjom.

Na przykład nakłaniając je do poproszenia użytkownika o hasło:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Lub zmuszać je do wykonywania **dowolnych działań**.

### **`kTCCServiceEndpointSecurityClient`**

Umożliwia między innymi **zapis do bazy danych TCC użytkownika**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Umożliwia **zmianę** atrybutu **`NFSHomeDirectory`** użytkownika, co zmienia ścieżkę jego folderu domowego i pozwala tym samym **ominąć TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Umożliwia modyfikowanie plików wewnątrz bundle aplikacji (wewnątrz app.app), co jest **domyślnie niedozwolone**.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

Można sprawdzić, kto ma ten dostęp w _Ustawienia systemowe_ > _Prywatność i ochrona_ > _Zarządzanie aplikacjami._

### `kTCCServiceAccessibility`

Proces będzie mógł **nadużywać funkcji accessibility systemu macOS**, co oznacza na przykład możliwość naciskania klawiszy. Dzięki temu może poprosić o dostęp do sterowania aplikacją taką jak Finder i zatwierdzić okno dialogowe przy użyciu tego uprawnienia.

## Entitlements związane z Trustcache/CDhash

Istnieją entitlements, które można wykorzystać do ominięcia zabezpieczeń Trustcache/CDhash, zapobiegających uruchamianiu obniżonych wersji binariów Apple.

## Średnie

### `com.apple.security.cs.allow-jit`

Ten entitlement umożliwia **tworzenie pamięci, która jest zapisywalna i wykonywalna**, poprzez przekazanie flagi `MAP_JIT` do funkcji systemowej `mmap()`. Więcej informacji znajdziesz [**tutaj**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).<sup>[[10]](#references)</sup>

### `com.apple.security.cs.allow-unsigned-executable-memory`

Ten entitlement umożliwia **nadpisywanie lub patchowanie kodu C**, korzystanie z dawno przestarzałej funkcji **`NSCreateObjectFileImageFromMemory`** (która jest zasadniczo niebezpieczna) lub korzystanie z frameworka **DVDPlayback**. Więcej informacji znajdziesz [**tutaj**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).<sup>[[11]](#references)</sup>

> [!CAUTION]
> Dołączenie tego entitlement naraża aplikację na typowe podatności występujące w językach programowania z niebezpiecznym zarządzaniem pamięcią. Dokładnie rozważ, czy aplikacja rzeczywiście potrzebuje tego wyjątku.

### `com.apple.security.cs.disable-executable-page-protection`

Ten entitlement umożliwia **modyfikowanie sekcji własnych plików wykonywalnych** na dysku w celu wymuszenia zakończenia działania. Więcej informacji znajdziesz [**tutaj**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).<sup>[[12]](#references)</sup>

> [!CAUTION]
> Entitlement Disable Executable Memory Protection jest skrajnym uprawnieniem, które usuwa podstawowe zabezpieczenie z aplikacji, umożliwiając atakującemu przepisanie kodu wykonywalnego aplikacji bez wykrycia. Jeśli to możliwe, preferuj węższe entitlements.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Ten entitlement umożliwia zamontowanie systemu plików nullfs (domyślnie zabronione). Narzędzie: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

Zgodnie z tym wpisem na blogu, to uprawnienie TCC zwykle występuje w postaci:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Umożliwia procesowi **zażądanie wszystkich uprawnień TCC**.

### **`kTCCServicePostEvent`**

Umożliwia **wstrzykiwanie syntetycznych zdarzeń klawiatury i myszy** w całym systemie za pośrednictwem `CGEventPost()`. Proces posiadający to uprawnienie może symulować naciśnięcia klawiszy, kliknięcia myszy i zdarzenia przewijania w dowolnej aplikacji — zapewniając w praktyce **zdalne sterowanie** pulpitem.

Jest to szczególnie niebezpieczne w połączeniu z `kTCCServiceAccessibility` lub `kTCCServiceListenEvent`, ponieważ umożliwia zarówno odczytywanie, jak i **wstrzykiwanie danych wejściowych**.
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

Umożliwia **przechwytywanie wszystkich zdarzeń klawiatury i myszy** w całym systemie (input monitoring / keylogging). Proces może zarejestrować `CGEventTap`, aby przechwytywać każde naciśnięcie klawisza w dowolnej aplikacji, w tym hasła, numery kart kredytowych i prywatne wiadomości.

Szczegółowe techniki exploitation opisano tutaj:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

Umożliwia **odczytywanie bufora ekranu** — wykonywanie screenshotów i nagrywanie obrazu ekranu dowolnej aplikacji, w tym pól z bezpiecznym tekstem. W połączeniu z OCR pozwala automatycznie wyodrębniać hasła i wrażliwe dane wyświetlane na ekranie.

> [!WARNING]
> Począwszy od macOS Sonoma, screen capture wyświetla stały wskaźnik na pasku menu. W starszych wersjach screen recording może odbywać się całkowicie po cichu.

### **`kTCCServiceCamera`**

Umożliwia **przechwytywanie zdjęć i obrazu wideo** z wbudowanej kamery lub podłączonych kamer USB. Code injection do binary z uprawnieniami dostępu do kamery umożliwia cichy visual surveillance.

### **`kTCCServiceMicrophone`**

Umożliwia **nagrywanie dźwięku** ze wszystkich urządzeń wejściowych. Background daemons z dostępem do mikrofonu zapewniają stały ambient audio surveillance bez widocznego okna aplikacji.

### **`kTCCServiceLocation`**

Umożliwia odpytywanie o **fizyczną lokalizację** urządzenia za pomocą triangulacji Wi-Fi lub beaconów Bluetooth. Ciągłe monitorowanie ujawnia adresy domu i pracy, wzorce podróży oraz codzienne rutyny.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

Dostęp do **Contacts** (nazwy, adresy e-mail, numery telefonów — przydatne do spear-phishingu), **Calendar** (harmonogramy spotkań, listy uczestników) oraz **Photos** (prywatne zdjęcia i screenshoty, które mogą zawierać dane uwierzytelniające oraz metadane lokalizacji).

Kompletne techniki credential theft z wykorzystaniem uprawnień TCC opisano tutaj:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox i Code Signing Entitlements

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Tymczasowe wyjątki Sandbox** osłabiają App Sandbox, umożliwiając komunikację z systemowymi usługami Mach/XPC, które Sandbox normalnie blokuje. Jest to **główny sandbox escape primitive** — przejęta aplikacja działająca w Sandbox może używać wyjątków mach-lookup do uzyskiwania dostępu do uprzywilejowanych daemonów i exploitowania ich interfejsów XPC.
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && codesign -d --entitlements - "$binary" 2>&1 | grep -q "mach-lookup" && echo "$(basename "$1")"
' _ {} \; 2>/dev/null
```
For detailed exploitation chain: sandboxed app → mach-lookup exception → vulnerable daemon → sandbox escape, see:

{{#ref}}
macos-code-signing-weaknesses-and-sandbox-escapes.md
{{#endref}}

### `com.apple.developer.driverkit`

**DriverKit entitlements** pozwalają binariom sterowników w przestrzeni użytkownika komunikować się bezpośrednio z kernelem za pośrednictwem interfejsów IOKit. Binarne pliki DriverKit zarządzają sprzętem: USB, Thunderbolt, PCIe, urządzeniami HID, audio i sieciowymi.

Compromising a DriverKit binary enables:
- **Kernel attack surface** poprzez spreparowane wywołania `IOConnectCallMethod`
- **USB device spoofing** (emulowanie klawiatury w celu wykonania HID injection)
- **DMA attacks** za pośrednictwem interfejsów PCIe/Thunderbolt
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
W przypadku szczegółowych informacji na temat exploitation IOKit/DriverKit zobacz:

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}

## References

- [1] [XNU — `bsd/sys/codesign.h` (operacje `CS_OPS_*` i `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [2] [XNU — `bsd/kern/kern_proc.c` (handler `csops` / `CS_OPS_CLEAR_LV`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [3] [Apple Developer — Entitlement narzędzia do debugowania (`com.apple.security.cs.debugger`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger)
- [4] [Apple Developer — Entitlement wyłączający Library Validation](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation)
- [5] [Apple Developer — Entitlement zezwalający na zmienne środowiskowe DYLD](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [6] [Objective-See — CVE-2020-9934: Bypassing TCC](https://objective-see.org/blog/blog_0x4C.html)
- [7] [Wojciech Reguła — Play the music and bypass TCC aka CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [8] [#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula (YouTube)](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [9] [The Nightmare of Apple's OTA Update: Bypassing the Signature Verification and Pwning the Kernel](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [10] [Apple Developer — Entitlement zezwalający na wykonywanie kodu skompilowanego przez JIT (`com.apple.security.cs.allow-jit`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)
- [11] [Apple Developer — Entitlement zezwalający na niezopatrzoną podpisem pamięć wykonywalną](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory)
- [12] [Apple Developer — Entitlement wyłączający ochronę pamięci wykonywalnej](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection)
- [13] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)

{{#include ../../../banners/hacktricks-training.md}}
