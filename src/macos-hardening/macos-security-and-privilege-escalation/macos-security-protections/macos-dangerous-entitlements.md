# Небезпечні Entitlements macOS та TCC perms

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> Зверніть увагу, що entitlements, які починаються з **`com.apple`**, недоступні для сторонніх розробників — лише Apple може їх надавати... Або, якщо ви використовуєте enterprise certificate, ви фактично можете створювати власні entitlements, що починаються з **`com.apple`**, і обходити захист, заснований на цьому.

## Високий ризик

### `com.apple.rootless.install.heritable`

Entitlement **`com.apple.rootless.install.heritable`** дозволяє **обійти SIP**. Дивіться [тут докладніше](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Entitlement **`com.apple.rootless.install`** дозволяє **обійти SIP**. Дивіться [тут докладніше](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (раніше називався `task_for_pid-allow`)**

Цей entitlement дозволяє отримати **task port будь-якого** процесу, окрім kernel. Дивіться [**тут докладніше**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

Цей entitlement дозволяє іншим процесам із entitlement **`com.apple.security.cs.debugger`** отримати task port процесу, запущеного binary із цим entitlement, і **інжектити в нього код**. Дивіться [**тут докладніше**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Apps із Debugging Tool Entitlement можуть викликати `task_for_pid()`, щоб отримати дійсний task port для unsigned і third-party apps, у яких для entitlement `Get Task Allow` встановлено значення `true`. Однак навіть із debugging tool entitlement debugger **не може отримати task ports** процесів, які **не мають entitlement `Get Task Allow`** і тому захищені System Integrity Protection. Дивіться [**тут докладніше**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).

### `com.apple.security.cs.disable-library-validation`

Цей entitlement дозволяє **завантажувати frameworks, plug-ins або libraries, які не підписані Apple і не підписані з тим самим Team ID**, що й основний executable, тому attacker може скористатися довільним завантаженням library для інжекції коду. Дивіться [**тут докладніше**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Цей entitlement дуже схожий на **`com.apple.security.cs.disable-library-validation`**, але **замість** **безпосереднього вимкнення** library validation він дозволяє процесу **викликати системний виклик `csops`, щоб вимкнути її** під час виконання.

Назва entitlement жорстко задана в XNU поруч з операцією `csops`, яка його використовує:<sup>[[2]](#references)</sup>
```c
/* bsd/sys/codesign.h */
#define CLEAR_LV_ENTITLEMENT "com.apple.private.security.clear-library-validation"
...
#define CS_OPS_CLEAR_LV     15  /* clear the library validation flag */
```
Обробник ядра для `CS_OPS_CLEAR_LV` (`bsd/kern/kern_proc.c`) чітко показує, наскільки вузьким є цей примітив:<sup>[[3]](#references)</sup>
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

- Працює **лише в macOS** (`ENOTSUP` на всіх інших платформах).
- Працює лише з **самим собою** (`forself == 1`) — за її допомогою неможливо прибрати library validation з іншого процесу.
- Вимагає, щоб процес дійсно **мав entitlement**, і відмовляє, якщо процес позначений як `CS_INSTALLER` або працює під кореневим шляхом підсистеми.
- Очищує **`CS_REQUIRE_LV | CS_FORCED_LV`** із прапорців code-signing процесу.

Коментар XNU пояснює передбачений сценарій використання, а також те, чому він цікавий для attacker:

> Ця опція використовується для видалення library validation із запущеного процесу. Вона застосовується в plugin architectures, коли програмі потрібно завантажувати untrusted libraries. [...] Після того як процес завантажив untrusted library, покладатися на library validation у майбутньому буде неефективно.

Іншими словами, **будь-який binary із цим entitlement є ціллю для dylib-injection**: запустіть code всередині нього (або переконайте його завантажити ваш plug-in) після того, як він прибрав `CS_REQUIRE_LV`, і ви успадкуєте всі можливості, для виконання яких host process має довіру.

### `com.apple.security.cs.allow-dyld-environment-variables`

Цей entitlement дозволяє **використовувати DYLD environment variables**, які можуть застосовуватися для ін’єкції libraries і code. Дивіться [**тут більше інформації**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` або `com.apple.rootless.storage`.`TCC`

[**Згідно з цим blog**](https://objective-see.org/blog/blog_0x4C.html) **і** [**цим blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), ці entitlements дозволяють **змінювати** базу даних **TCC**.

### **`system.install.apple-software`** та **`system.install.apple-software.standar-user`**

Ці entitlements дозволяють **встановлювати software без запиту дозволу** користувача, що може бути корисним для **privilege escalation**.

### `com.apple.private.security.kext-management`

Entitlement, необхідний для запиту до **kernel на завантаження kernel extension**.

### **`com.apple.private.icloud-account-access`**

За наявності entitlement **`com.apple.private.icloud-account-access`** можна взаємодіяти із сервісом **`com.apple.iCloudHelper`** XPC, який **надає iCloud tokens**.

**iMovie** та **Garageband** мали цей entitlement.

Для отримання додаткової **інформації** про exploit для **отримання iCloud tokens** за допомогою цього entitlement дивіться доповідь: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Я не знаю, що це дозволяє робити

### `com.apple.private.apfs.revert-to-snapshot`

TODO: У [**цьому звіті**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **згадується, що це можна використовувати для** оновлення вмісту, захищеного SSV, після reboot. Якщо ви знаєте, як це зробити, надішліть PR!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: У [**цьому звіті**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **згадується, що це можна використовувати для** оновлення вмісту, захищеного SSV, після reboot. Якщо ви знаєте, як це зробити, надішліть PR!

### `keychain-access-groups`

Цей entitlement містить список груп **keychain**, до яких має доступ application:
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

Надає дозволи **Full Disk Access** — один із найвищих рівнів дозволів TCC, які можна отримати.

### **`kTCCServiceAppleEvents`**

Дозволяє застосунку надсилати події іншим застосункам, які зазвичай використовуються для **автоматизації завдань**. Керуючи іншими застосунками, він може зловживати дозволами, наданими цим застосункам.

Наприклад, змусити їх запитати в користувача його пароль:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Або змусити їх виконувати **довільні дії**.

### **`kTCCServiceEndpointSecurityClient`**

Дозволяє, серед іншого, **записувати базу даних TCC користувача**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Дозволяє **змінювати** атрибут **`NFSHomeDirectory`** користувача, що змінює шлях до його домашньої папки й, відповідно, дозволяє **обійти TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Дозволяє змінювати файли всередині bundle програм (усередині app.app), що **типово заборонено**.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

Перевірити, хто має цей доступ, можна в _System Settings_ > _Privacy & Security_ > _App Management._

### `kTCCServiceAccessibility`

Процес зможе **зловживати функціями accessibility macOS**, тобто, наприклад, натискати клавіші. Отже, він зможе запросити доступ для керування програмою на кшталт Finder і схвалити діалогове вікно за допомогою цього дозволу.

## Entitlements, пов’язані з Trustcache/CDhash

Існують entitlements, які можна використовувати для обходу захистів Trustcache/CDhash, що запобігають виконанню знижених версій бінарних файлів Apple.

## Середній рівень

### `com.apple.security.cs.allow-jit`

Цей entitlement дозволяє **створювати пам’ять, доступну для запису та виконання**, передаючи прапорець `MAP_JIT` системній функції `mmap()`. Див. [**докладнішу інформацію тут**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Цей entitlement дозволяє **перезаписувати або змінювати C-код**, використовувати давно застарілу **`NSCreateObjectFileImageFromMemory`** (яка є фундаментально небезпечною) або використовувати framework **DVDPlayback**. Див. [**докладнішу інформацію тут**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).

> [!CAUTION]
> Додавання цього entitlement наражає вашу програму на поширені вразливості мов програмування з небезпечною роботою з пам’яттю. Уважно розгляньте, чи потрібен вашій програмі цей виняток.

### `com.apple.security.cs.disable-executable-page-protection`

Цей entitlement дозволяє **змінювати секції власних виконуваних файлів** на диску для примусового завершення роботи. Див. [**докладнішу інформацію тут**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).

> [!CAUTION]
> Entitlement Disable Executable Memory Protection є надзвичайним entitlement, який видаляє фундаментальний захист вашої програми, унаслідок чого зловмисник може непомітно переписати виконуваний код вашої програми. За можливості надавайте перевагу вужчим entitlements.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Цей entitlement дозволяє монтувати файлову систему nullfs (типово заборонено). Інструмент: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

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

Дозволяє **впроваджувати синтетичні події клавіатури та миші** на рівні всієї системи через `CGEventPost()`. Процес із цим дозволом може імітувати натискання клавіш, клацання миші та події прокручування в будь-якій програмі — фактично отримуючи **віддалене керування** робочим столом.

Це особливо небезпечно в поєднанні з `kTCCServiceAccessibility` або `kTCCServiceListenEvent`, оскільки дозволяє як читати, ТАК І впроваджувати ввід.
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

Дозволяє **перехоплювати всі події клавіатури та миші** у системі (моніторинг введення / keylogging). Процес може зареєструвати `CGEventTap`, щоб перехоплювати кожне натискання клавіш у будь-якій програмі, зокрема паролі, номери кредитних карток і приватні повідомлення.

Докладні техніки exploitation див. у:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

Дозволяє **читати буфер дисплея** — робити знімки екрана та записувати відео з екрана будь-якої програми, зокрема захищених текстових полів. У поєднанні з OCR це дає змогу автоматично вилучати паролі та конфіденційні дані з екрана.

> [!WARNING]
> Починаючи з macOS Sonoma, під час захоплення екрана в рядку меню постійно відображається індикатор. У старіших версіях запис екрана може виконуватися повністю непомітно.

### **`kTCCServiceCamera`**

Дозволяє **знімати фото та відео** за допомогою вбудованої камери або підключених USB-камер. Ін'єкція коду в binary з правом доступу до камери дає змогу непомітно здійснювати візуальне спостереження.

### **`kTCCServiceMicrophone`**

Дозволяє **записувати аудіо** з усіх пристроїв введення. Фонові daemons із доступом до мікрофона забезпечують постійне прослуховування навколишнього середовища без видимого вікна програми.

### **`kTCCServiceLocation`**

Дозволяє запитувати **фізичне розташування** пристрою через Wi-Fi-тріангуляцію або Bluetooth-маяки. Безперервний моніторинг розкриває домашні й робочі адреси, маршрути переміщення та щоденні звички.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

Доступ до **Контактів** (імена, адреси електронної пошти, номери телефонів — корисно для spear-phishing), **Календаря** (розклад зустрічей, списки учасників) і **Фото** (особисті фотографії, знімки екрана, які можуть містити облікові дані, метадані розташування).

Повний опис технік крадіжки облікових даних через дозволи TCC див. у:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Entitlements Sandbox і Code Signing

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Тимчасові винятки Sandbox** послаблюють App Sandbox, дозволяючи обмін даними із загальносистемними Mach/XPC-сервісами, які Sandbox зазвичай блокує. Це **основний примітив обходу Sandbox** — скомпрометована програма в Sandbox може використовувати винятки mach-lookup для доступу до привілейованих daemons і exploitation їхніх XPC-інтерфейсів.
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && codesign -d --entitlements - "$binary" 2>&1 | grep -q "mach-lookup" && echo "$(basename "$1")"
' _ {} \; 2>/dev/null
```
Для детального ланцюжка exploitation: sandboxed app → mach-lookup exception → vulnerable daemon → sandbox escape див.:

{{#ref}}
macos-code-signing-weaknesses-and-sandbox-escapes.md
{{#endref}}

### `com.apple.developer.driverkit`

**DriverKit entitlements** дозволяють user-space driver binaries безпосередньо взаємодіяти з kernel через інтерфейси IOKit. Бінарні файли DriverKit керують hardware: USB, Thunderbolt, PCIe, HID devices, audio та networking.

Компрометація бінарного файлу DriverKit забезпечує:
- **Kernel attack surface** через malformed виклики `IOConnectCallMethod`
- **USB device spoofing** (емуляція keyboard для HID injection)
- **DMA attacks** через PCIe/Thunderbolt interfaces
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
Для детальної інформації про експлуатацію IOKit/DriverKit дивіться:

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}

## Посилання

- [1] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [2] [XNU — `bsd/sys/codesign.h` (операції `CS_OPS_*` і `CLEAR_LV_ENTITLEMENT)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [3] [XNU — `bsd/kern/kern_proc.c` (обробник `csops` / `CS_OPS_CLEAR_LV`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)

{{#include ../../../banners/hacktricks-training.md}}
