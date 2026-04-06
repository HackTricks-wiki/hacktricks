# macOS Niebezpieczne entitlements i uprawnienia TCC

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> Zauważ, że uprawnienia zaczynające się od **`com.apple`** nie są dostępne dla stron trzecich, tylko Apple może je przyznać... Lub jeśli używasz certyfikatu enterprise możesz tak naprawdę stworzyć własne uprawnienia zaczynające się od **`com.apple`** i obejść na ich podstawie zabezpieczenia.

## Wysokie

### `com.apple.rootless.install.heritable`

Uprawnienie **`com.apple.rootless.install.heritable`** pozwala na **bypass SIP**. Sprawdź [this for more info](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Uprawnienie **`com.apple.rootless.install`** pozwala na **bypass SIP**. Sprawdź[ this for more info](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (previously called `task_for_pid-allow`)**

To uprawnienie pozwala uzyskać **task port dla dowolnego** procesu, z wyjątkiem jądra. Sprawdź [**this for more info**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

To uprawnienie pozwala innym procesom z uprawnieniem **`com.apple.security.cs.debugger`** uzyskać task port procesu uruchomionego przez binarkę z tym uprawnieniem i **wstrzykiwać w nim kod**. Sprawdź [**this for more info**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Aplikacje z Debugging Tool Entitlement mogą wywołać `task_for_pid()` aby otrzymać ważny task port dla niepodpisanych i aplikacji firm trzecich z uprawnieniem `Get Task Allow` ustawionym na `true`. Jednak nawet z uprawnieniem Debugging Tool, debugger **nie może uzyskać task portów** procesów, które **nie mają uprawnienia `Get Task Allow`**, i które są w związku z tym chronione przez System Integrity Protection. Sprawdź [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).

### `com.apple.security.cs.disable-library-validation`

To uprawnienie pozwala **ładować frameworks, plug-iny lub biblioteki bez ich podpisania przez Apple lub bez podpisania tym samym Team ID** co główny executable, więc atakujący mógłby wykorzystać dowolne ładowanie biblioteki do wstrzyknięcia kodu. Sprawdź [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

To uprawnienie jest bardzo podobne do **`com.apple.security.cs.disable-library-validation`**, ale **zamiast** **bezpośredniego wyłączenia** walidacji bibliotek, pozwala procesowi **wywołać syscall `csops`, aby ją wyłączyć**.\
Sprawdź [**this for more info**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

To uprawnienie pozwala **używać zmiennych środowiskowych DYLD**, które mogą być użyte do wstrzykiwania bibliotek i kodu. Sprawdź [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` or `com.apple.rootless.storage`.`TCC`

[**According to this blog**](https://objective-see.org/blog/blog_0x4C.html) **and** [**this blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), te uprawnienia pozwalają **modyfikować** bazę danych **TCC**.

### **`system.install.apple-software`** and **`system.install.apple-software.standar-user`**

Te uprawnienia pozwalają **install software without asking for permissions** od użytkownika, co może być pomocne przy **eskalacji uprawnień**.

### `com.apple.private.security.kext-management`

Uprawnienie potrzebne do zażądania od **jądra załadowania kernel extension**.

### **`com.apple.private.icloud-account-access`**

Dzięki uprawnieniu **`com.apple.private.icloud-account-access`** możliwa jest komunikacja z XPC service **`com.apple.iCloudHelper`**, który **dostarczy iCloud tokens**.

**iMovie** i **Garageband** miały to uprawnienie.

Po więcej informacji o exploicie umożliwiającym **uzyskanie iCloud tokens** z tego uprawnienia zobacz prezentację: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Nie wiem, do czego to pozwala

### `com.apple.private.apfs.revert-to-snapshot`

TODO: W [**tym raporcie**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **wzmiankowano, że to może być użyte do** aktualizacji zawartości chronionej przez SSV po restarcie. Jeśli wiesz jak — wyślij PR proszę!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: W [**tym raporcie**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **wzmiankowano, że to może być użyte do** aktualizacji zawartości chronionej przez SSV po restarcie. Jeśli wiesz jak — wyślij PR proszę!

### `keychain-access-groups`

To uprawnienie wymienia grupy **keychain**, do których aplikacja ma dostęp:
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

Nadaje uprawnienia Full Disk Access, jedno z najwyższych uprawnień TCC, jakie można mieć.

### **`kTCCServiceAppleEvents`**

Pozwala aplikacji wysyłać zdarzenia do innych aplikacji, które są powszechnie używane do automatyzacji zadań. Kontrolując inne aplikacje, może nadużywać uprawnień przyznanych tym aplikacjom.

Na przykład, zmuszając je do poproszenia użytkownika o hasło:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Lub zmuszanie ich do wykonywania **dowolnych działań**.

### **`kTCCServiceEndpointSecurityClient`**

Pozwala m.in. na **zapis do bazy TCC użytkownika**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Pozwala **zmienić** atrybut **`NFSHomeDirectory`** użytkownika, co zmienia ścieżkę jego katalogu domowego i w związku z tym pozwala **obejść TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Pozwala na modyfikację plików wewnątrz bundle aplikacji (wewnątrz app.app), co jest **domyślnie zabronione**.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

Można sprawdzić, kto ma ten dostęp w _Ustawienia systemowe_ > _Prywatność i bezpieczeństwo_ > _Zarządzanie aplikacjami_.

### `kTCCServiceAccessibility`

Proces będzie mógł **nadużyć funkcji dostępności macOS**, co oznacza, że na przykład będzie mógł wykonywać naciśnięcia klawiszy. Może więc zażądać dostępu do kontrolowania aplikacji takiej jak Finder i zatwierdzić dialog mając to uprawnienie.

## Uprawnienia związane z Trustcache/CDhash

Istnieją uprawnienia, które mogą być użyte do obejścia zabezpieczeń Trustcache/CDhash, które zapobiegają uruchamianiu starszych wersji binarek Apple.

## Średnie

### `com.apple.security.cs.allow-jit`

To uprawnienie pozwala **zarezerwować pamięć zapisywalną i wykonalną** przez przekazanie flagi `MAP_JIT` do funkcji systemowej `mmap()`. Zobacz [**więcej informacji**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

To uprawnienie pozwala **nadpisać lub załatać kod w C**, użyć dawno przestarzałej funkcji **`NSCreateObjectFileImageFromMemory`** (która jest z założenia niebezpieczna), lub użyć frameworka **DVDPlayback**. Zobacz [**więcej informacji**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).

> [!CAUTION]
> Dołączenie tego uprawnienia naraża Twoją aplikację na typowe podatności w językach niebezpiecznych pamięciowo. Uważnie rozważ, czy Twoja aplikacja naprawdę potrzebuje tego wyjątku.

### `com.apple.security.cs.disable-executable-page-protection`

To uprawnienie pozwala **modyfikować sekcje własnych plików wykonywalnych** na dysku. Zobacz [**więcej informacji**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).

> [!CAUTION]
> Disable Executable Memory Protection Entitlement to ekstremalne uprawnienie, które usuwa podstawową ochronę bezpieczeństwa z Twojej aplikacji, umożliwiając atakującemu przepisanie kodu wykonywalnego aplikacji bez wykrycia. Jeśli to możliwe, preferuj węższe uprawnienia.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

To uprawnienie pozwala zamontować system plików nullfs (domyślnie zabronione). Narzędzie: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

Według tego wpisu na blogu, to uprawnienie TCC zwykle występuje w postaci:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Pozwala procesowi **zażądać wszystkich uprawnień TCC**.

### **`kTCCServicePostEvent`**

Pozwala na **wstrzykiwanie syntetycznych zdarzeń klawiatury i myszy** w całym systemie za pomocą `CGEventPost()`. Proces z tym uprawnieniem może symulować naciśnięcia klawiszy, kliknięcia myszy i zdarzenia przewijania w dowolnej aplikacji — co w praktyce daje **zdalną kontrolę** nad pulpitem.

Jest to szczególnie niebezpieczne w połączeniu z `kTCCServiceAccessibility` lub `kTCCServiceListenEvent`, ponieważ pozwala zarówno na odczytywanie, jak i wstrzykiwanie danych wejściowych.
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

Pozwala na **przechwytywanie wszystkich zdarzeń klawiatury i myszy** w całym systemie (input monitoring / keylogging). Proces może zarejestrować `CGEventTap`, aby przechwycić każde naciśnięcie klawisza w dowolnej aplikacji, w tym hasła, numery kart kredytowych i prywatne wiadomości.

Dla szczegółowych technik eksploatacji zobacz:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

Pozwala na **odczyt bufora wyświetlania** — wykonywanie zrzutów ekranu i nagrywanie wideo ekranu dowolnej aplikacji, w tym zabezpieczonych pól tekstowych. W połączeniu z OCR może to automatycznie wydobywać hasła i wrażliwe dane z ekranu.

> [!WARNING]
> Począwszy od macOS Sonoma, przechwytywanie ekranu pokazuje stały wskaźnik na pasku menu. W starszych wersjach nagrywanie ekranu może być całkowicie ciche.

### **`kTCCServiceCamera`**

Pozwala na **przechwytywanie zdjęć i wideo** z wbudowanej kamery lub podłączonych kamer USB. Wstrzyknięcie kodu do binarki z uprawnieniem do kamery umożliwia ciche monitorowanie wizualne.

### **`kTCCServiceMicrophone`**

Pozwala na **nagrywanie dźwięku** ze wszystkich urządzeń wejściowych. Background daemons z dostępem do mikrofonu zapewniają stałą, otoczeniową inwigilację audio bez widocznego okna aplikacji.

### **`kTCCServiceLocation`**

Pozwala na zapytywanie o **fizyczną lokalizację** urządzenia za pomocą triangulacji Wi‑Fi lub beaconów Bluetooth. Ciągłe monitorowanie ujawnia adresy domowe/zawodowe, wzorce podróży i codzienne rutyny.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

Dostęp do **Contacts** (nazwiska, e‑maile, telefony — przydatne do spear-phishingu), **Calendar** (harmonogramy spotkań, listy uczestników) oraz **Photos** (zdjęcia osobiste, zrzuty ekranu mogące zawierać poświadczenia, metadane lokalizacji).

Dla pełnych technik kradzieży poświadczeń za pomocą uprawnień TCC zobacz:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox i uprawnienia podpisywania kodu

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Sandbox temporary exceptions** osłabiają App Sandbox, umożliwiając komunikację z ogólnosystemowymi usługami Mach/XPC, które sandbox normalnie blokuje. To jest **primary sandbox escape primitive** — skompromitowana aplikacja działająca w sandboxie może użyć mach-lookup exceptions, aby dotrzeć do uprzywilejowanych daemons i wykorzystać ich XPC interfaces.
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

**DriverKit entitlements** pozwalają binariom sterowników w przestrzeni użytkownika komunikować się bezpośrednio z jądrem przez interfejsy IOKit.

Binaria DriverKit zarządzają sprzętem: USB, Thunderbolt, PCIe, urządzeniami HID, audio i siecią.

Kompromitacja binarki DriverKit umożliwia:
- **Powierzchnia ataku jądra** poprzez nieprawidłowe wywołania `IOConnectCallMethod`
- **USB device spoofing** (emulować klawiaturę dla HID injection)
- **DMA attacks** przez interfejsy PCIe/Thunderbolt
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
Aby uzyskać szczegółowe informacje o eksploatacji IOKit/DriverKit, zobacz:

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}



{{#include ../../../banners/hacktricks-training.md}}
