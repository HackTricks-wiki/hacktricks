# macOS Dangerous Entitlements & TCC perms

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> Зауважте, що entitlements, які починаються з **`com.apple`**, недоступні стороннім розробникам — їх може надати лише Apple... Або, якщо ви використовуєте enterprise certificate, ви фактично можете створити власні entitlements, що починаються з **`com.apple`**, і таким чином обійти захисти, засновані на цьому.

## Високий

### `com.apple.rootless.install.heritable`

Entitlement **`com.apple.rootless.install.heritable`** дає змогу **обійти SIP**. Check [this for more info](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Entitlement **`com.apple.rootless.install`** дає змогу **обійти SIP**. Check[ this for more info](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (previously called `task_for_pid-allow`)**

Цей entitlement дозволяє отримати **task port для будь-якого** процесу, за винятком ядра. Check [**this for more info**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

Цей entitlement дозволяє іншим процесам з entitlement **`com.apple.security.cs.debugger`** отримувати task port процесу, який виконується бінарником з цим entitlement, та **інжектувати код у нього**. Check [**this for more info**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Додатки з Debugging Tool Entitlement можуть викликати `task_for_pid()` щоб отримати дійсний task port для unsigned та third-party додатків із `Get Task Allow` entitlement, встановленим у `true`. Однак навіть з Debugging Tool Entitlement дебаггер **не може отримати task ports** процесів, які **не мають `Get Task Allow` entitlement**, і тому захищені System Integrity Protection. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).

### `com.apple.security.cs.disable-library-validation`

Цей entitlement дозволяє **завантажувати frameworks, plug-ins або бібліотеки без підпису Apple або без підпису з тим самим Team ID**, що й головний виконуваний файл, тому нападник може зловживати завантаженням довільної бібліотеки для інжекції коду. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Цей entitlement дуже схожий на **`com.apple.security.cs.disable-library-validation`**, але **замість прямого відключення** валідації бібліотек він дозволяє процесу **викликати системний виклик `csops` для її відключення**.\
Check [**this for more info**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

Цей entitlement дозволяє **використовувати DYLD environment variables**, які можуть застосовуватись для інжекції бібліотек та коду. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` or `com.apple.rootless.storage`.`TCC`

[**According to this blog**](https://objective-see.org/blog/blog_0x4C.html) **and** [**this blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), ці entitlements дозволяють **модифікувати** базу даних **TCC**.

### **`system.install.apple-software`** and **`system.install.apple-software.standar-user`**

Ці entitlements дозволяють **встановлювати програмне забезпечення без запиту дозволу у користувача**, що може бути корисним для **privilege escalation**.

### `com.apple.private.security.kext-management`

Entitlement, необхідний, щоб попросити **ядро завантажити kernel extension**.

### **`com.apple.private.icloud-account-access`**

Завдяки entitlement **`com.apple.private.icloud-account-access`** можливо взаємодіяти зі службою XPC **`com.apple.iCloudHelper`**, яка надає **iCloud tokens**.

**iMovie** та **Garageband** мали цей entitlement.

Для більшої **інформації** про експлойт для **отримання iCloud tokens** через цей entitlement дивіться доповідь: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Я не знаю, що це дозволяє робити

### `com.apple.private.apfs.revert-to-snapshot`

TODO: В [**this report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **згадується, що це може бути використано для** оновлення вмісту, захищеного SSV, після перезавантаження. Якщо ви знаєте як — надішліть PR, будь ласка!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: В [**this report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **згадується, що це може бути використано для** оновлення вмісту, захищеного SSV, після перезавантаження. Якщо ви знаєте як — надішліть PR, будь ласка!

### `keychain-access-groups`

Цей entitlement перелічує **keychain** групи, до яких додаток має доступ:
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

Дає **повний доступ до диска** — один із найвищих дозволів TCC, який ви можете отримати.

### **`kTCCServiceAppleEvents`**

Дозволяє додатку надсилати події іншим застосункам, які зазвичай використовуються для **автоматизації завдань**. Контролюючи інші застосунки, він може зловживати дозволами, наданими цим застосункам.

Наприклад, змусити їх попросити у користувача пароль:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Або примусити їх виконувати **довільні дії**.

### **`kTCCServiceEndpointSecurityClient`**

Дозволяє, серед інших дозволів, **записувати в базу даних TCC користувача**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Дозволяє **змінювати** атрибут **`NFSHomeDirectory`** користувача, який змінює шлях його домашньої папки і, отже, дозволяє **обійти TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Дозволяє змінювати файли всередині бандла додатка (inside app.app), що **за замовчуванням заборонено**.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

Можна перевірити, хто має цей доступ, у _Налаштування системи_ > _Конфіденційність і безпека_ > _Управління додатками_.

### `kTCCServiceAccessibility`

Процес зможе **зловживати функціями доступності macOS**, що означає, наприклад, що він зможе відправляти натискання клавіш. Таким чином він міг би запитати доступ для керування додатком на кшталт Finder і підтвердити діалог за допомогою цього дозволу.

## Entitlements, пов'язані з Trustcache/CDhash

Існують деякі entitlements, які можна використати для обходу захистів Trustcache/CDhash, що запобігають виконанню старіших версій бінарних файлів Apple.

## Середній

### `com.apple.security.cs.allow-jit`

Це entitlement дозволяє **створювати пам'ять, яка є одночасно записуваною та виконуваною**, передаючи прапорець `MAP_JIT` в системну функцію `mmap()`. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Це entitlement дозволяє **перезаписувати або патчити C-код**, використовувати давно застарілий **`NSCreateObjectFileImageFromMemory`** (що є принципово небезпечним), або використовувати фреймворк **DVDPlayback**. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).

> [!CAUTION]
> Включення цього entitlement піддає ваш додаток типовим вразливостям у мовах з небезпечним керуванням пам'яттю. Ретельно оцініть, чи потрібен вашому додатку цей виняток.

### `com.apple.security.cs.disable-executable-page-protection`

Це entitlement дозволяє **модифікувати секції власних виконуваних файлів** на диску для примусового виходу. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).

> [!CAUTION]
> The Disable Executable Memory Protection Entitlement — це радикальний entitlement, який видаляє фундаментальний рівень захисту з вашого додатка, роблячи можливим для атакуючого перезаписати виконуваний код вашого додатка без виявлення. За можливості віддавайте перевагу більш вузьким entitlements.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Цей entitlement дозволяє монтувати файлову систему nullfs (за замовчуванням заборонено). Tool: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

Згідно з цим записом у блозі, цей TCC-дозвіл зазвичай зустрічається у формі:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Дозволяє процесу **запитувати всі дозволи TCC**.

### **`kTCCServicePostEvent`**

Дозволяє **вводити синтетичні події клавіатури та миші** по всій системі через `CGEventPost()`. Процес з цим дозволом може імітувати натискання клавіш, кліки миші та події прокрутки в будь-якому додатку — фактично забезпечуючи **віддалений контроль** над робочим столом.

Це особливо небезпечно у поєднанні з `kTCCServiceAccessibility` або `kTCCServiceListenEvent`, оскільки дає змогу як читати, так і інжектувати введення.
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

Дозволяє **перехоплювати всі події клавіатури та миші** по всій системі (input monitoring / keylogging). Процес може зареєструвати `CGEventTap`, щоб захоплювати кожне натискання клавіші в будь-якому додатку, включно з паролями, номерами кредитних карток та приватними повідомленнями.

Для детальних методів експлуатації див.:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

Дозволяє **читати буфер відображення** — робити скріншоти та записувати відео екрана будь-якого застосунку, включно з полями для введення захищеного тексту. У поєднанні з OCR це може автоматично витягувати паролі та конфіденційні дані з екрана.

> [!WARNING]
> Починаючи з macOS Sonoma, запис екрана показує постійний індикатор у рядку меню. На старіших версіях запис екрану може бути повністю безшумним.

### **`kTCCServiceCamera`**

Дозволяє **знімати фото та відео** з вбудованої камери або підключених USB-камер. Ін'єкція коду у camera-entitled binary дозволяє приховано вести візуальне спостереження.

### **`kTCCServiceMicrophone`**

Дозволяє **записувати аудіо** з усіх пристроїв введення. Фонові демони з доступом до мікрофона забезпечують постійне навколишнє аудіоспостереження без видимого вікна застосунку.

### **`kTCCServiceLocation`**

Дозволяє визначати **фізичне розташування** пристрою за допомогою триангуляції Wi‑Fi або Bluetooth-маячків. Постійний моніторинг виявляє адреси дому/роботи, маршрути подорожей та щоденні рутини.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

Доступ до **Contacts** (імена, електронні адреси, телефони — корисні для spear-phishing), **Calendar** (розклад зустрічей, списки учасників) та **Photos** (особисті фото, скріншоти, які можуть містити облікові дані, метадані місця розташування).

Для повних технік викрадення облікових даних через дозволи TCC див.:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox & Code Signing Entitlements

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Sandbox temporary exceptions** послаблюють App Sandbox, дозволяючи зв'язок із системними Mach/XPC сервісами, які зазвичай блокує sandbox. Це є **primary sandbox escape primitive** — скомпрометований sandboxed app може використовувати mach-lookup exceptions, щоб звернутися до привілейованих daemon-ів і експлуатувати їхні XPC interfaces.
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && codesign -d --entitlements - "$binary" 2>&1 | grep -q "mach-lookup" && echo "$(basename "$1")"
' _ {} \; 2>/dev/null
```
Для детального ланцюга експлуатації: sandboxed app → mach-lookup exception → vulnerable daemon → sandbox escape, див.:

{{#ref}}
macos-code-signing-weaknesses-and-sandbox-escapes.md
{{#endref}}

### `com.apple.developer.driverkit`

**DriverKit entitlements** дозволяють user-space driver binaries безпосередньо взаємодіяти з kernel через IOKit interfaces. DriverKit binaries керують апаратурою: USB, Thunderbolt, PCIe, HID devices, audio, and networking.

Компрометація DriverKit binary дає можливість:
- **Kernel attack surface** через неправильно сформовані виклики `IOConnectCallMethod`
- **USB device spoofing** (імітувати клавіатуру для HID injection)
- **DMA attacks** через інтерфейси PCIe/Thunderbolt
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
Докладніше про IOKit/DriverKit exploitation дивіться:

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}



{{#include ../../../banners/hacktricks-training.md}}
