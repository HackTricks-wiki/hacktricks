# macOS Niebezpieczne Uprawnienia i uprawnienia TCC

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> Zauważ, że uprawnienia zaczynające się od **`com.apple`** nie są dostępne dla osób trzecich, tylko Apple może je przyznać.

## Wysoki

### `com.apple.rootless.install.heritable`

Uprawnienie **`com.apple.rootless.install.heritable`** pozwala na **obejście SIP**. Sprawdź [to dla więcej informacji](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Uprawnienie **`com.apple.rootless.install`** pozwala na **obejście SIP**. Sprawdź [to dla więcej informacji](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (wcześniej nazywane `task_for_pid-allow`)**

To uprawnienie pozwala uzyskać **port zadania dla dowolnego** procesu, z wyjątkiem jądra. Sprawdź [**to dla więcej informacji**](../macos-proces-abuse/macos-ipc-inter-process-communication/).

### `com.apple.security.get-task-allow`

To uprawnienie pozwala innym procesom z uprawnieniem **`com.apple.security.cs.debugger`** uzyskać port zadania procesu uruchomionego przez binarny plik z tym uprawnieniem i **wstrzyknąć kod**. Sprawdź [**to dla więcej informacji**](../macos-proces-abuse/macos-ipc-inter-process-communication/).

### `com.apple.security.cs.debugger`

Aplikacje z uprawnieniem Debugging Tool mogą wywołać `task_for_pid()`, aby uzyskać ważny port zadania dla niepodpisanych i aplikacji osób trzecich z uprawnieniem `Get Task Allow` ustawionym na `true`. Jednak nawet z uprawnieniem narzędzia debugowania, debugger **nie może uzyskać portów zadań** procesów, które **nie mają uprawnienia `Get Task Allow`**, a które są zatem chronione przez System Integrity Protection. Sprawdź [**to dla więcej informacji**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).

### `com.apple.security.cs.disable-library-validation`

To uprawnienie pozwala na **ładowanie frameworków, wtyczek lub bibliotek bez bycia podpisanym przez Apple lub podpisanym tym samym identyfikatorem zespołu** co główny plik wykonywalny, więc atakujący mógłby nadużyć ładowania dowolnej biblioteki, aby wstrzyknąć kod. Sprawdź [**to dla więcej informacji**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

To uprawnienie jest bardzo podobne do **`com.apple.security.cs.disable-library-validation`**, ale **zamiast** **bezpośrednio wyłączać** walidację bibliotek, pozwala procesowi **wywołać wywołanie systemowe `csops`, aby je wyłączyć**.\
Sprawdź [**to dla więcej informacji**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

To uprawnienie pozwala na **używanie zmiennych środowiskowych DYLD**, które mogą być używane do wstrzykiwania bibliotek i kodu. Sprawdź [**to dla więcej informacji**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` lub `com.apple.rootless.storage`.`TCC`

[**Zgodnie z tym blogiem**](https://objective-see.org/blog/blog_0x4C.html) **i** [**tym blogiem**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), te uprawnienia pozwalają na **modyfikację** bazy danych **TCC**.

### **`system.install.apple-software`** i **`system.install.apple-software.standar-user`**

Te uprawnienia pozwalają na **instalację oprogramowania bez pytania o pozwolenie** użytkownika, co może być pomocne w przypadku **eskalacji uprawnień**.

### `com.apple.private.security.kext-management`

Uprawnienie potrzebne do poproszenia **jądra o załadowanie rozszerzenia jądra**.

### **`com.apple.private.icloud-account-access`**

Uprawnienie **`com.apple.private.icloud-account-access`** umożliwia komunikację z usługą XPC **`com.apple.iCloudHelper`**, która **dostarczy tokeny iCloud**.

**iMovie** i **Garageband** miały to uprawnienie.

Aby uzyskać więcej **informacji** na temat exploita do **uzyskania tokenów icloud** z tego uprawnienia, sprawdź wykład: [**#OBTS v5.0: "Co się dzieje na twoim Macu, zostaje na iCloud Apple?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Nie wiem, co to pozwala zrobić

### `com.apple.private.apfs.revert-to-snapshot`

TODO: W [**tym raporcie**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **wspomniano, że może to być użyte do** aktualizacji zawartości chronionej SSV po ponownym uruchomieniu. Jeśli wiesz jak, wyślij PR, proszę!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: W [**tym raporcie**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **wspomniano, że może to być użyte do** aktualizacji zawartości chronionej SSV po ponownym uruchomieniu. Jeśli wiesz jak, wyślij PR, proszę!

### `keychain-access-groups`

To uprawnienie listuje **grupy keychain**, do których aplikacja ma dostęp:
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

Daje **Pełny dostęp do dysku**, jedno z najwyższych uprawnień TCC, jakie można mieć.

### **`kTCCServiceAppleEvents`**

Pozwala aplikacji na wysyłanie zdarzeń do innych aplikacji, które są powszechnie używane do **automatyzacji zadań**. Kontrolując inne aplikacje, może nadużywać uprawnień przyznanych tym innym aplikacjom.

Na przykład, zmuszając je do proszenia użytkownika o hasło:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Lub sprawić, by wykonywały **dowolne działania**.

### **`kTCCServiceEndpointSecurityClient`**

Pozwala, między innymi, na **zapisywanie bazy danych TCC użytkowników**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Pozwala na **zmianę** atrybutu **`NFSHomeDirectory`** użytkownika, co zmienia ścieżkę do jego folderu domowego i tym samym pozwala na **obejście TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Pozwala na modyfikację plików wewnątrz pakietu aplikacji (wewnątrz app.app), co jest **domyślnie zabronione**.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

Można sprawdzić, kto ma ten dostęp w _Ustawieniach systemowych_ > _Prywatność i bezpieczeństwo_ > _Zarządzanie aplikacjami._

### `kTCCServiceAccessibility`

Proces będzie mógł **nadużywać funkcji dostępności macOS**, co oznacza, że na przykład będzie mógł naciskać klawisze. MOŻE poprosić o dostęp do kontrolowania aplikacji, takiej jak Finder, i zatwierdzić okno dialogowe z tym uprawnieniem.

## Średni

### `com.apple.security.cs.allow-jit`

To uprawnienie pozwala na **tworzenie pamięci, która jest zapisywalna i wykonywalna** poprzez przekazanie flagi `MAP_JIT` do funkcji systemowej `mmap()`. Sprawdź [**to dla więcej informacji**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

To uprawnienie pozwala na **nadpisywanie lub patchowanie kodu C**, używanie długo przestarzałej **`NSCreateObjectFileImageFromMemory`** (co jest zasadniczo niebezpieczne) lub korzystanie z frameworka **DVDPlayback**. Sprawdź [**to dla więcej informacji**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).

> [!CAUTION]
> Włączenie tego uprawnienia naraża Twoją aplikację na powszechne luki w kodzie języków, które nie są bezpieczne w pamięci. Starannie rozważ, czy Twoja aplikacja potrzebuje tego wyjątku.

### `com.apple.security.cs.disable-executable-page-protection`

To uprawnienie pozwala na **modyfikację sekcji własnych plików wykonywalnych** na dysku, aby wymusić wyjście. Sprawdź [**to dla więcej informacji**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).

> [!CAUTION]
> Uprawnienie do wyłączenia ochrony pamięci wykonywalnej to ekstremalne uprawnienie, które usuwa fundamentalną ochronę bezpieczeństwa z Twojej aplikacji, co umożliwia atakującemu przepisanie kodu wykonywalnego Twojej aplikacji bez wykrycia. Preferuj węższe uprawnienia, jeśli to możliwe.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

To uprawnienie pozwala na zamontowanie systemu plików nullfs (domyślnie zabronione). Narzędzie: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

Zgodnie z tym wpisem na blogu, to uprawnienie TCC zazwyczaj występuje w formie:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Zezwól procesowi na **poproszenie o wszystkie uprawnienia TCC**.

### **`kTCCServicePostEvent`**

{{#include ../../../banners/hacktricks-training.md}}
