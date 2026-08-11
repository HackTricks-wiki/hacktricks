# Niebezpieczne entitlements macOS i uprawnienia TCC

{{#include ../../../banners/hacktricks-training.md}}

Entitlements deklarują możliwości i wyjątki bezpieczeństwa, które system operacyjny przyznaje podpisanemu kodowi. Poniższe wpisy koncentrują się na tych, które są szczególnie przydatne podczas offensive review.<sup>[[13]](#references)</sup>

> [!WARNING]
> Należy pamiętać, że entitlements zaczynające się od **`com.apple`** nie są dostępne dla podmiotów trzecich — tylko Apple może je przyznawać... Jeśli jednak używasz certyfikatu enterprise, możesz faktycznie utworzyć własne entitlements zaczynające się od **`com.apple`** i obejść zabezpieczenia oparte na tym mechanizmie.

## Wysoki

### `com.apple.rootless.install.heritable`

Entitlement **`com.apple.rootless.install.heritable`** pozwala procesowi **obejść SIP**. Sprawdź [więcej informacji tutaj](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Entitlement **`com.apple.rootless.install`** pozwala procesowi **obejść SIP**. Sprawdź [więcej informacji tutaj](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (wcześniej nazywany `task_for_pid-allow`)**

Ten entitlement pozwala procesowi uzyskać **task port dowolnego** procesu z wyjątkiem kernela. Sprawdź [**więcej informacji tutaj**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

Ten entitlement pozwala innym procesom posiadającym entitlement **`com.apple.security.cs.debugger`** uzyskać task port procesu uruchomionego przez binary z tym entitlementem oraz **wstrzyknąć do niego kod**. Sprawdź [**więcej informacji tutaj**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Aplikacje z Debugging Tool Entitlement mogą wywołać `task_for_pid()`, aby pobrać prawidłowy task port dla unsigned i third-party apps z ustawionym na `true` entitlementem `Get Task Allow`. Jednak nawet z debugging tool entitlement debugger **nie może uzyskać task ports** procesów, które **nie mają entitlementu `Get Task Allow`** i dlatego są chronione przez System Integrity Protection. Sprawdź [**więcej informacji tutaj**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).<sup>[[3]](#references)</sup>

### `com.apple.security.cs.disable-library-validation`

Ten entitlement pozwala aplikacji **ładować frameworks, plug-ins lub libraries bez wymogu podpisania ich przez Apple lub użycia tego samego Team ID** co główny executable, dzięki czemu attacker może wykorzystać arbitrary library load do wstrzyknięcia kodu. Sprawdź [**więcej informacji tutaj**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).<sup>[[4]](#references)</sup>

### `com.apple.private.security.clear-library-validation`

Ten entitlement jest bardzo podobny do **`com.apple.security.cs.disable-library-validation`**, ale **zamiast** **bezpośrednio wyłączać** library validation, pozwala procesowi **wywołać system call `csops` w celu wyłączenia go** w runtime.

Nazwa entitlenmentu jest zahardkodowana w XNU obok operacji `csops`, która go wykorzystuje:<sup>[[1]](#references)</sup>
```c
/* bsd/sys/codesign.h */
#define CLEAR_LV_ENTITLEMENT "com.apple.private.security.clear-library-validation"
...
#define CS_OPS_CLEAR_LV     15  /* clear the library validation flag */
```
Obsługa jądra dla `CS_OPS_CLEAR_LV` (`bsd/kern/kern_proc.c`) dokładnie pokazuje, jak wąski jest ten primitive:<sup>[[2]](#references)</sup>
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

- Jest **dostępna wyłącznie w macOS** (`ENOTSUP` na każdej innej platformie).
- Działa tylko na **samym sobie** (`forself == 1`) — nie można za jej pomocą usunąć library validation z innego procesu.
- Wymaga, aby proces faktycznie **posiadał entitlement**, i odmawia działania, jeśli proces ma flagę `CS_INSTALLER` lub działa ze ścieżki głównej subsystemu.
- Usuwa **`CS_REQUIRE_LV | CS_FORCED_LV`** z flag code-signingu procesu.

Komentarz XNU wyjaśnia zamierzony przypadek użycia, a także to, dlaczego jest on interesujący dla atakującego:

> Ta opcja służy do usunięcia library validation z działającego procesu. Jest używana w architekturach pluginów, gdy program musi załadować niezaufane biblioteki. [...] Gdy proces załaduje niezaufaną bibliotekę, poleganie na library validation w przyszłości nie będzie skuteczne.

Innymi słowy, **każdy binary posiadający ten entitlement jest celem dylib-injection**: uruchom code wewnątrz niego (lub nakłoń go do załadowania swojego pluginu) po usunięciu przez niego `CS_REQUIRE_LV`, a odziedziczysz wszystko, co host process ma uprawnienia wykonywać.

### `com.apple.security.cs.allow-dyld-environment-variables`

Ten entitlement pozwala **używać zmiennych środowiskowych DYLD**, które mogą służyć do wstrzykiwania bibliotek i code. Więcej informacji znajdziesz [**tutaj**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).<sup>[[5]](#references)</sup>

### `com.apple.private.tcc.manager` lub `com.apple.rootless.storage`.`TCC`

[**Według tego bloga**](https://objective-see.org/blog/blog_0x4C.html) **oraz** [**tego bloga**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/) te entitlements pozwalają procesowi **modyfikować** bazę danych **TCC**.<sup>[[6]](#references)[[7]](#references)</sup>

### **`system.install.apple-software`** i **`system.install.apple-software.standar-user`**

Te entitlements pozwalają procesowi **instalować software bez pytania użytkownika o zgodę**, co może być pomocne przy **privilege escalation**.

### `com.apple.private.security.kext-management`

Entitlement wymagany do poproszenia **kernela o załadowanie kernel extension**.

### **`com.apple.private.icloud-account-access`**

Entitlement **`com.apple.private.icloud-account-access`** umożliwia komunikację z usługą XPC **`com.apple.iCloudHelper`**, która **dostarcza tokeny iCloud**.

**iMovie** i **Garageband** posiadały ten entitlement.

Więcej **informacji** o exploicie umożliwiającym **pozyskanie tokenów iCloud** za pomocą tego entitlements znajdziesz w talku: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[8]](#references)</sup>

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Nie wiem, co to umożliwia

### `com.apple.private.apfs.revert-to-snapshot`

TODO: [**Ten raport**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) wspomina, że ten entitlement może służyć do aktualizowania zawartości chronionej przez SSV po ponownym uruchomieniu. Jeśli wiesz jak, wyślij PR!<sup>[[9]](#references)</sup>

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: [**Ten sam raport**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) wspomina, że utworzenie sealed snapshot może służyć do aktualizowania zawartości chronionej przez SSV po ponownym uruchomieniu. Jeśli wiesz jak, wyślij PR!<sup>[[9]](#references)</sup>

### `keychain-access-groups`

Ten entitlement wylicza grupy **keychain**, do których aplikacja ma dostęp:
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

Zapewnia uprawnienia **Full Disk Access**, jedne z najwyższych uprawnień TCC, jakie można uzyskać.

### **`kTCCServiceAppleEvents`**

Umożliwia aplikacji wysyłanie zdarzeń do innych aplikacji, które są powszechnie używane do **automatyzacji zadań**. Kontrolując inne aplikacje, może nadużywać uprawnień przyznanych tym aplikacjom.

Na przykład zmuszając je do poproszenia użytkownika o hasło:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Lub zmuszać je do wykonywania **dowolnych działań**.

### **`kTCCServiceEndpointSecurityClient`**

Umożliwia między innymi **zapis do bazy danych TCC użytkownika**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Umożliwia **zmianę** atrybutu **`NFSHomeDirectory`** użytkownika, co zmienia ścieżkę jego katalogu domowego, a tym samym umożliwia **ominięcie TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Umożliwia modyfikowanie plików wewnątrz pakietów aplikacji (wewnątrz app.app), co jest **domyślnie niedozwolone**.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

Możliwe jest sprawdzenie, kto ma ten dostęp w _Ustawienia systemowe_ > _Prywatność i ochrona_ > _Zarządzanie aplikacjami._

### `kTCCServiceAccessibility`

Proces będzie mógł **nadużywać funkcji ułatwień dostępu macOS**, co oznacza na przykład możliwość wysyłania naciśnięć klawiszy. Dzięki temu może poprosić o dostęp do sterowania aplikacją taką jak Finder i zatwierdzić okno dialogowe przy użyciu tego uprawnienia.

## Uprawnienia związane z Trustcache/CDhash

Istnieją uprawnienia, które mogą zostać użyte do ominięcia zabezpieczeń Trustcache/CDhash, zapobiegających wykonywaniu obniżonych wersji binariów Apple.

## Średnie

### `com.apple.security.cs.allow-jit`

To uprawnienie umożliwia procesowi **tworzenie pamięci, która jest zapisywalna i wykonywalna**, poprzez przekazanie flagi `MAP_JIT` do funkcji systemowej `mmap()`. Więcej informacji znajdziesz [**tutaj**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).<sup>[[10]](#references)</sup>

### `com.apple.security.cs.allow-unsigned-executable-memory`

To uprawnienie umożliwia **nadpisywanie lub modyfikowanie kodu C**, używanie dawno przestarzałej funkcji **`NSCreateObjectFileImageFromMemory`** (która jest zasadniczo niebezpieczna) lub korzystanie z frameworka **DVDPlayback**. Więcej informacji znajdziesz [**tutaj**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).<sup>[[11]](#references)</sup>

> [!CAUTION]
> Dołączenie tego uprawnienia naraża aplikację na typowe podatności występujące w językach programowania, w których pamięć nie jest bezpieczna. Dokładnie rozważ, czy aplikacja potrzebuje tego wyjątku.

### `com.apple.security.cs.disable-executable-page-protection`

To uprawnienie umożliwia **modyfikowanie sekcji własnych plików wykonywalnych** na dysku w celu wymuszenia zakończenia działania. Więcej informacji znajdziesz [**tutaj**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).<sup>[[12]](#references)</sup>

> [!CAUTION]
> Uprawnienie Disable Executable Memory Protection jest skrajnym uprawnieniem, które usuwa fundamentalną ochronę bezpieczeństwa z aplikacji, umożliwiając atakującemu przepisanie kodu wykonywalnego aplikacji bez wykrycia. Jeśli to możliwe, preferuj węższy zakres uprawnień.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

To uprawnienie umożliwia zamontowanie systemu plików nullfs (domyślnie zabronione). Narzędzie: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

Zgodnie z tym wpisem na blogu to uprawnienie TCC jest zwykle spotykane w postaci:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Pozwala procesowi **żądać wszystkich uprawnień TCC**.

### **`kTCCServicePostEvent`**

Umożliwia **wstrzykiwanie syntetycznych zdarzeń klawiatury i myszy** w całym systemie za pośrednictwem `CGEventPost()`. Proces posiadający to uprawnienie może symulować naciśnięcia klawiszy, kliknięcia myszy i zdarzenia przewijania w dowolnej aplikacji — skutecznie zapewniając **zdalną kontrolę** nad pulpitem.

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

Umożliwia **odczytywanie bufora ekranu** — wykonywanie zrzutów ekranu i nagrywanie obrazu ekranu dowolnej aplikacji, w tym bezpiecznych pól tekstowych. W połączeniu z OCR pozwala automatycznie wydobywać hasła i poufne dane z ekranu.

> [!WARNING]
> Począwszy od macOS Sonoma, przechwytywanie ekranu wyświetla stały wskaźnik na pasku menu. W starszych wersjach nagrywanie ekranu może odbywać się całkowicie po cichu.

### **`kTCCServiceCamera`**

Umożliwia **przechwytywanie zdjęć i obrazu wideo** z wbudowanej kamery lub podłączonych kamer USB. Code injection do pliku binarnego posiadającego uprawnienia kamery umożliwia cichy nadzór wizualny.

### **`kTCCServiceMicrophone`**

Umożliwia **nagrywanie dźwięku** ze wszystkich urządzeń wejściowych. Demaony działające w tle i mające dostęp do mikrofonu zapewniają trwały nadzór nad dźwiękami otoczenia bez widocznego okna aplikacji.

### **`kTCCServiceLocation`**

Umożliwia odpytywanie o **fizyczną lokalizację** urządzenia za pomocą triangulacji Wi-Fi lub beaconów Bluetooth. Ciągłe monitorowanie ujawnia adresy domu i pracy, wzorce przemieszczania się oraz codzienne rutyny.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

Dostęp do **Kontaktów** (nazwy, adresy e-mail, numery telefonów — przydatne w spear-phishingu), **Kalendarza** (harmonogramy spotkań, listy uczestników) oraz **Zdjęć** (prywatne zdjęcia, zrzuty ekranu mogące zawierać dane uwierzytelniające, metadane lokalizacji).

Kompletne techniki exploitation służące do kradzieży danych uwierzytelniających za pośrednictwem uprawnień TCC opisano tutaj:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Uprawnienia Sandbox i Code Signing

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Tymczasowe wyjątki Sandbox** osłabiają App Sandbox, umożliwiając komunikację z systemowymi usługami Mach/XPC, które Sandbox normalnie blokuje. Jest to **główny primitive ucieczki z Sandbox** — przejęta aplikacja działająca w Sandbox może używać wyjątków mach-lookup, aby uzyskać dostęp do uprzywilejowanych daemonów i exploitować ich interfejsy XPC.
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

**DriverKit entitlements** pozwalają binariom sterowników działającym w user space komunikować się bezpośrednio z kernelem za pośrednictwem interfejsów IOKit. Binarne pliki DriverKit zarządzają sprzętem: USB, Thunderbolt, PCIe, urządzeniami HID, dźwiękiem i siecią.

Przejęcie binarnego pliku DriverKit umożliwia:
- **Powierzchnię ataku kernela** za pośrednictwem nieprawidłowo sformatowanych wywołań `IOConnectCallMethod`
- **Podszywanie się pod urządzenia USB** (emulowanie klawiatury w celu przeprowadzania iniekcji HID)
- **Ataki DMA** za pośrednictwem interfejsów PCIe/Thunderbolt
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
W celu uzyskania szczegółowych informacji na temat exploitation IOKit/DriverKit zobacz:

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}

## References

- [1] [XNU — `bsd/sys/codesign.h` (operacje `CS_OPS_*` i `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [2] [XNU — `bsd/kern/kern_proc.c` (handler `csops` / `CS_OPS_CLEAR_LV`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [3] [Apple Developer — Uprawnienie narzędzia debugowania (`com.apple.security.cs.debugger`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger)
- [4] [Apple Developer — Uprawnienie wyłączenia walidacji bibliotek](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation)
- [5] [Apple Developer — Uprawnienie zezwalające na zmienne środowiskowe DYLD](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [6] [Objective-See — CVE-2020-9934: Omijanie TCC](https://objective-see.org/blog/blog_0x4C.html)
- [7] [Wojciech Reguła — Odtwarzanie muzyki i omijanie TCC, czyli CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [8] [#OBTS v5.0: „Co dzieje się na twoim Macu, pozostaje w iCloud firmy Apple?!” — Wojciech Regula (YouTube)](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [9] [Koszmar aktualizacji OTA firmy Apple: omijanie weryfikacji podpisu i przejęcie kernela](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [10] [Apple Developer — Uprawnienie zezwalające na wykonywanie kodu skompilowanego za pomocą JIT (`com.apple.security.cs.allow-jit`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)
- [11] [Apple Developer — Uprawnienie zezwalające na niepodpisaną pamięć wykonywalną](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory)
- [12] [Apple Developer — Uprawnienie wyłączenia ochrony pamięci wykonywalnej](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection)
- [13] [Apple Developer — Uprawnienia](https://developer.apple.com/documentation/bundleresources/entitlements)
{{#include ../../../banners/hacktricks-training.md}}
