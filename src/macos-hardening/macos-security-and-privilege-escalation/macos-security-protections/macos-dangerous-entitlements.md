# Небезпечні Entitlements і TCC perms у macOS

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> Зверніть увагу, що entitlements, які починаються з **`com.apple`**, недоступні стороннім розробникам — лише Apple може їх надавати... Або, якщо ви використовуєте enterprise certificate, ви фактично можете створити власні entitlements, що починаються з **`com.apple`**, і обійти захист, заснований на цьому.

## Високий

### `com.apple.rootless.install.heritable`

Entitlement **`com.apple.rootless.install.heritable`** дозволяє **обійти SIP**. Докладніше див. [тут](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Entitlement **`com.apple.rootless.install`** дозволяє **обійти SIP**. Докладніше див. [тут](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (раніше називався `task_for_pid-allow`)**

Цей entitlement дозволяє отримати **task port для будь-якого** процесу, крім kernel. Докладніше див. [**тут**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

Цей entitlement дозволяє іншим процесам із entitlement **`com.apple.security.cs.debugger`** отримати task port процесу, запущеного binary з цим entitlement, і **інжектити в нього code**. Докладніше див. [**тут**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Apps із Debugging Tool Entitlement можуть викликати `task_for_pid()`, щоб отримати дійсний task port для unsigned і third-party apps, у яких параметр `Get Task Allow` встановлено в `true`. Однак навіть за наявності debugging tool entitlement debugger **не може отримати task ports** процесів, які **не мають entitlement `Get Task Allow`** і тому захищені System Integrity Protection. Докладніше див. [**тут**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).<sup>[[3]](#references)</sup>

### `com.apple.security.cs.disable-library-validation`

Цей entitlement дозволяє **завантажувати frameworks, plug-ins або libraries, які не підписані Apple або не підписані з тим самим Team ID**, що й основний executable, тому attacker може використати довільне завантаження library для інжекції code. Докладніше див. [**тут**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).<sup>[[4]](#references)</sup>

### `com.apple.private.security.clear-library-validation`

Цей entitlement дуже схожий на **`com.apple.security.cs.disable-library-validation`**, але **замість** **безпосереднього вимкнення** library validation він дозволяє процесу **викликати system call `csops`, щоб вимкнути її** під час виконання.

Назва entitlement жорстко задана в XNU поруч з операцією `csops`, яка його використовує:<sup>[[1]](#references)</sup>
```c
/* bsd/sys/codesign.h */
#define CLEAR_LV_ENTITLEMENT "com.apple.private.security.clear-library-validation"
...
#define CS_OPS_CLEAR_LV     15  /* clear the library validation flag */
```
Обробник ядра для `CS_OPS_CLEAR_LV` (`bsd/kern/kern_proc.c`) чітко показує, наскільки вузькою є ця примітива:<sup>[[2]](#references)</sup>
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
Отже, операція:

- Працює **лише на macOS** (`ENOTSUP` на всіх інших платформах).
- Працює лише над **самим процесом** (`forself == 1`) — за її допомогою неможливо прибрати library validation з іншого процесу.
- Вимагає, щоб процес фактично **володів entitlement**, і відмовляє, якщо процес має прапорець `CS_INSTALLER` або запущений з кореневого шляху subsystem.
- Очищає **`CS_REQUIRE_LV | CS_FORCED_LV`** із прапорців code-signing процесу.

Коментар XNU пояснює передбачений варіант використання, а також те, чому це цікаво attacker'у:

> Ця опція використовується для видалення library validation із запущеного процесу. Вона застосовується в plugin architectures, коли програмі потрібно завантажувати untrusted libraries. [...] Після того як процес завантажив untrusted library, покладатися на library validation у майбутньому буде неефективно.

Іншими словами, **будь-який binary із цим entitlement є ціллю для dylib-injection**: запустіть code всередині нього (або переконайте його завантажити ваш plug-in) після того, як він прибере `CS_REQUIRE_LV`, і ви успадкуєте всі можливості, для яких host process має trust.

### `com.apple.security.cs.allow-dyld-environment-variables`

Цей entitlement дозволяє **використовувати змінні середовища DYLD**, які можуть застосовуватися для ін'єкції libraries і code. Дивіться [**тут для отримання додаткової інформації**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).<sup>[[5]](#references)</sup>

### `com.apple.private.tcc.manager` або `com.apple.rootless.storage`.`TCC`

[**Згідно з цим blog**](https://objective-see.org/blog/blog_0x4C.html) **і** [**цим blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), ці entitlements дозволяють **змінювати** database **TCC**.<sup>[[6]](#references)[[7]](#references)</sup>

### **`system.install.apple-software`** і **`system.install.apple-software.standar-user`**

Ці entitlements дозволяють **інсталювати software без запиту дозволу** користувача, що може бути корисним для **privilege escalation**.

### `com.apple.private.security.kext-management`

Entitlement, необхідний для того, щоб попросити **kernel завантажити kernel extension**.

### **`com.apple.private.icloud-account-access`**

За наявності entitlement **`com.apple.private.icloud-account-access`** можна взаємодіяти з XPC service **`com.apple.iCloudHelper`**, який **надасть iCloud tokens**.

**iMovie** і **Garageband** мали цей entitlement.

Для отримання додаткової **інформації** про exploit для **отримання iCloud tokens** за допомогою цього entitlement перегляньте доповідь: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[8]](#references)</sup>

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Я не знаю, що це дозволяє робити

### `com.apple.private.apfs.revert-to-snapshot`

TODO: У [**цьому звіті**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **згадується, що це можна використати для** оновлення contents, захищених SSV, після reboot. Якщо ви знаєте, як це працює, надішліть PR!<sup>[[9]](#references)</sup>

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: У [**цьому звіті**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **згадується, що це можна використати для** оновлення contents, захищених SSV, після reboot. Якщо ви знаєте, як це працює, надішліть PR!<sup>[[9]](#references)</sup>

### `keychain-access-groups`

Цей entitlement містить перелік груп **keychain**, до яких application має доступ:
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

Надає дозволи **Full Disk Access** — один із найвищих дозволів TCC, які можна отримати.

### **`kTCCServiceAppleEvents`**

Дозволяє застосунку надсилати події іншим застосункам, які зазвичай використовуються для **автоматизації завдань**. Керуючи іншими застосунками, він може зловживати дозволами, наданими цим застосункам.

Наприклад, змусити їх запитати в користувача його пароль:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Або змушувати їх виконувати **довільні дії**.

### **`kTCCServiceEndpointSecurityClient`**

Дозволяє, зокрема, **записувати базу даних TCC користувача**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Дозволяє **змінювати** атрибут **`NFSHomeDirectory`** користувача, який змінює шлях до своєї домашньої папки, і, відповідно, дозволяє **обійти TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Дозволяє змінювати файли всередині app bundle (у app.app), що **заборонено за замовчуванням**.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

Перевірити, хто має цей доступ, можна в _Системних параметрах_ > _Конфіденційність і безпека_ > _Керування програмами._

### `kTCCServiceAccessibility`

Процес зможе **зловживати функціями доступності macOS**, тобто, наприклад, натискати клавіші. Отже, він зможе запросити доступ для керування програмою, наприклад Finder, і схвалити діалогове вікно за допомогою цього дозволу.

## Entitlements, пов’язані з Trustcache/CDhash

Існують entitlements, які можна використовувати для обходу захистів Trustcache/CDhash, що запобігають виконанню знижених версій бінарних файлів Apple.

## Середній рівень

### `com.apple.security.cs.allow-jit`

Цей entitlement дозволяє **створювати пам’ять, доступну для запису та виконання**, передаючи прапорець `MAP_JIT` системній функції `mmap()`. Дивіться [**докладнішу інформацію тут**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).<sup>[[10]](#references)</sup>

### `com.apple.security.cs.allow-unsigned-executable-memory`

Цей entitlement дозволяє **перевизначати або змінювати C-код**, використовувати давно застарілу **`NSCreateObjectFileImageFromMemory`** (яка є принципово небезпечною) або використовувати framework **DVDPlayback**. Дивіться [**докладнішу інформацію тут**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).<sup>[[11]](#references)</sup>

> [!CAUTION]
> Додавання цього entitlement наражає вашу програму на поширені вразливості мов програмування з небезпечною роботою з пам’яттю. Уважно розгляньте, чи потрібен вашій програмі цей виняток.

### `com.apple.security.cs.disable-executable-page-protection`

Цей entitlement дозволяє **змінювати секції власних виконуваних файлів** на диску, щоб примусово завершувати роботу. Дивіться [**докладнішу інформацію тут**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).<sup>[[12]](#references)</sup>

> [!CAUTION]
> Entitlement Disable Executable Memory Protection є надзвичайним entitlement, який усуває фундаментальний захист вашої програми, унаслідок чого зловмисник може непомітно переписати виконуваний код вашої програми. За можливості надавайте перевагу entitlements із вужчими дозволами.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Цей entitlement дозволяє монтувати файлову систему nullfs (за замовчуванням заборонено). Інструмент: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

Згідно з цим дописом у блозі, цей дозвіл TCC зазвичай зустрічається у формі:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Дозволяє процесу **запитувати всі дозволи TCC**.

### **`kTCCServicePostEvent`**

Дозволяє **впроваджувати синтетичні події клавіатури та миші** у всій системі через `CGEventPost()`. Процес із цим дозволом може імітувати натискання клавіш, кліки миші та події прокручування в будь-якій програмі — фактично отримуючи **віддалене керування** робочим столом.

Це особливо небезпечно в поєднанні з `kTCCServiceAccessibility` або `kTCCServiceListenEvent`, оскільки дозволяє як читати, ТАК І впроваджувати введення.
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

Дозволяє **перехоплювати всі події клавіатури та миші** у масштабах усієї системи (input monitoring / keylogging). Процес може зареєструвати `CGEventTap`, щоб перехоплювати кожне натискання клавіш у будь-якій програмі, зокрема паролі, номери кредитних карток і приватні повідомлення.

Докладні техніки exploitation див. у:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

Дозволяє **читати буфер дисплея** — робити знімки екрана та записувати відео з екрана будь-якої програми, зокрема захищених текстових полів. У поєднанні з OCR це дає змогу автоматично вилучати паролі та чутливі дані з екрана.

> [!WARNING]
> Починаючи з macOS Sonoma, захоплення екрана показує постійний індикатор у рядку меню. У старіших версіях запис екрана може виконуватися повністю непомітно.

### **`kTCCServiceCamera`**

Дозволяє **знімати фото та відео** за допомогою вбудованої камери або підключених USB-камер. Code injection у binary із camera entitlement дає змогу непомітно здійснювати візуальне спостереження.

### **`kTCCServiceMicrophone`**

Дозволяє **записувати аудіо** з усіх пристроїв введення. Фонові daemons із доступом до мікрофона забезпечують постійне приховане прослуховування навколишнього звуку без видимого вікна програми.

### **`kTCCServiceLocation`**

Дозволяє запитувати **фізичне місцезнаходження** пристрою через Wi-Fi-тріангуляцію або Bluetooth-маяки. Безперервний моніторинг розкриває домашні та робочі адреси, маршрути переміщень і щоденні звички.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

Доступ до **Contacts** (імена, електронні адреси, номери телефонів — корисні для spear-phishing), **Calendar** (розклад зустрічей, списки учасників) і **Photos** (особисті фотографії, знімки екрана, які можуть містити облікові дані, метадані місцезнаходження).

Повний опис технік credential theft exploitation через дозволи TCC див. у:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Entitlements Sandbox і Code Signing

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Тимчасові винятки Sandbox** послаблюють App Sandbox, дозволяючи взаємодію із загальносистемними Mach/XPC-сервісами, які Sandbox зазвичай блокує. Це **основний примітив виходу із Sandbox** — скомпрометована програма в Sandbox може використовувати винятки mach-lookup для доступу до привілейованих daemons і exploitation їхніх XPC-інтерфейсів.
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && codesign -d --entitlements - "$binary" 2>&1 | grep -q "mach-lookup" && echo "$(basename "$1")"
' _ {} \; 2>/dev/null
```
For детального ланцюжка експлуатації: застосунок у sandbox → виняток `mach-lookup` → вразливий daemon → sandbox escape, див.:

{{#ref}}
macos-code-signing-weaknesses-and-sandbox-escapes.md
{{#endref}}

### `com.apple.developer.driverkit`

**Entitlements DriverKit** дозволяють бінарним файлам драйверів у просторі користувача безпосередньо взаємодіяти з ядром через інтерфейси IOKit. Бінарні файли DriverKit керують hardware: USB, Thunderbolt, PCIe, HID-пристроями, аудіо та мережевими інтерфейсами.

Компрометація бінарного файлу DriverKit надає:
- **Поверхню атаки ядра** через неправильно сформовані виклики `IOConnectCallMethod`
- **Підміну USB-пристроїв** (емуляція клавіатури для HID-ін'єкції)
- **DMA-атаки** через інтерфейси PCIe/Thunderbolt
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
Для детального ознайомлення з exploitation IOKit/DriverKit див.:

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}

## Посилання

- [1] [XNU — `bsd/sys/codesign.h` (операції `CS_OPS_*` і `CLEAR_LV_ENTITLEMENT)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [2] [XNU — `bsd/kern/kern_proc.c` (обробник `csops` / `CS_OPS_CLEAR_LV`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [3] [Apple Developer — Entitlement для debugging tool (`com.apple.security.cs.debugger`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger)
- [4] [Apple Developer — Entitlement для вимкнення library validation](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation)
- [5] [Apple Developer — Entitlement для дозволу змінних середовища DYLD](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [6] [Objective-See — CVE-2020-9934: обхід TCC](https://objective-see.org/blog/blog_0x4C.html)
- [7] [Wojciech Reguła — Увімкнути музику та обійти TCC, або CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [8] [#OBTS v5.0: «What Happens on your Mac, Stays on Apple's iCloud?!» — Wojciech Regula (YouTube)](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [9] [Кошмар OTA Update від Apple: обхід перевірки підпису та pwning kernel](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [10] [Apple Developer — Entitlement для дозволу виконання JIT-compiled code (`com.apple.security.cs.allow-jit`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)
- [11] [Apple Developer — Entitlement для дозволу unsigned executable memory](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple.security.cs.allow-unsigned-executable-memory)
- [12] [Apple Developer — Entitlement для вимкнення захисту executable memory](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple.security.cs_disable-executable-page-protection)
- [13] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)

{{#include ../../../banners/hacktricks-training.md}}
