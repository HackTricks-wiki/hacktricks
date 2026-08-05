# Небезпечні Entitlements macOS та дозволи TCC

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> Зверніть увагу, що entitlements, які починаються з **`com.apple`**, недоступні third-parties — їх може надавати лише Apple... Або, якщо ви використовуєте enterprise certificate, ви фактично можете створити власні entitlements, що починаються з **`com.apple`**, і обійти захист, який на них базується.

## Високий

### `com.apple.rootless.install.heritable`

Entitlement **`com.apple.rootless.install.heritable`** дозволяє **обійти SIP**. Перегляньте [цю інформацію для деталей](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Entitlement **`com.apple.rootless.install`** дозволяє **обійти SIP**. Перегляньте [цю інформацію для деталей](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (раніше називався `task_for_pid-allow`)**

Цей entitlement дозволяє отримати **task port для будь-якого** процесу, крім kernel. Перегляньте [**цю інформацію для деталей**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

Цей entitlement дозволяє іншим процесам із entitlement **`com.apple.security.cs.debugger`** отримати task port процесу, запущеного binary із цим entitlement, і **інжектити в нього code**. Перегляньте [**цю інформацію для деталей**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Apps із Debugging Tool Entitlement можуть викликати `task_for_pid()`, щоб отримати дійсний task port для unsigned і third-party apps із параметром `Get Task Allow`, встановленим у `true`. Однак навіть за наявності debugging tool entitlement debugger **не може отримати task ports** процесів, які **не мають entitlement `Get Task Allow`** і тому захищені System Integrity Protection. Перегляньте [**цю інформацію для деталей**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).

### `com.apple.security.cs.disable-library-validation`

Цей entitlement дозволяє **завантажувати frameworks, plug-ins або libraries, які не підписані Apple або не підписані з тим самим Team ID**, що й основний executable, тому attacker може зловживати довільним завантаженням library для інжекції code. Перегляньте [**цю інформацію для деталей**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Цей entitlement дуже схожий на **`com.apple.security.cs.disable-library-validation`**, але **замість** **безпосереднього вимкнення** library validation він дозволяє процесу **викликати системний виклик `csops`, щоб вимкнути її** під час runtime.

Назва entitlement жорстко задана в XNU поруч з операцією `csops`, яка його використовує:<sup>[2]</sup>
```c
/* bsd/sys/codesign.h */
#define CLEAR_LV_ENTITLEMENT "com.apple.private.security.clear-library-validation"
...
#define CS_OPS_CLEAR_LV     15  /* clear the library validation flag */
```
Обробник ядра для `CS_OPS_CLEAR_LV` (`bsd/kern/kern_proc.c`) наочно показує, наскільки вузьким є цей примітив:<sup>[3]</sup>
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

- Є **лише для macOS** (`ENOTSUP` на всіх інших платформах).
- Працює лише із **самим процесом** (`forself == 1`) — за її допомогою не можна прибрати library validation з іншого процесу.
- Вимагає, щоб процес фактично **мав entitlement**, і відмовляє, якщо процес позначений як `CS_INSTALLER` або запущений із кореневого шляху підсистеми.
- Очищає **`CS_REQUIRE_LV | CS_FORCED_LV`** із прапорців code-signing процесу.

Коментар XNU пояснює передбачений сценарій використання, а також те, чому це цікаво для зловмисника:

> Ця опція використовується для видалення library validation із запущеного процесу. Вона застосовується в plugin architectures, коли програмі потрібно завантажувати ненадійні бібліотеки. [...] Після того як процес завантажив ненадійну бібліотеку, покладатися на library validation у майбутньому буде неефективно.

Іншими словами, **будь-який binary із цим entitlement є ціллю для dylib-injection**: запустіть код усередині нього (або переконайте його завантажити ваш plug-in) після того, як він видалить `CS_REQUIRE_LV`, і ви отримаєте всі можливості, яким довірено host process.

### `com.apple.security.cs.allow-dyld-environment-variables`

Цей entitlement дозволяє **використовувати змінні середовища DYLD**, які можуть застосовуватися для ін'єкції бібліотек і коду. Див. [**тут більше інформації**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` або `com.apple.rootless.storage`.`TCC`

[**Відповідно до цього блогу**](https://objective-see.org/blog/blog_0x4C.html) **та** [**цього блогу**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), ці entitlements дозволяють **змінювати** базу даних **TCC**.

### **`system.install.apple-software`** та **`system.install.apple-software.standar-user`**

Ці entitlements дозволяють **встановлювати software без запиту дозволу** користувача, що може бути корисним для **privilege escalation**.

### `com.apple.private.security.kext-management`

Entitlement, необхідний для запиту до **kernel на завантаження kernel extension**.

### **`com.apple.private.icloud-account-access`**

За наявності entitlement **`com.apple.private.icloud-account-access`** можна взаємодіяти з **`com.apple.iCloudHelper`** XPC service, який **надасть iCloud tokens**.

**iMovie** та **Garageband** мали цей entitlement.

Щоб отримати більше **інформації** про exploit для **отримання icloud tokens** за допомогою цього entitlement, перегляньте доповідь: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Я не знаю, що саме це дозволяє робити

### `com.apple.private.apfs.revert-to-snapshot`

TODO: У [**цьому звіті**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **зазначено, що це можна використати для** оновлення вмісту, захищеного SSV, після перезавантаження. Якщо ви знаєте, як це працює, надішліть PR!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: У [**цьому звіті**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **зазначено, що це можна використати для** оновлення вмісту, захищеного SSV, після перезавантаження. Якщо ви знаєте, як це працює, надішліть PR!

### `keychain-access-groups`

Цей entitlement перелічує групи **keychain**, до яких має доступ application:
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

Наприклад, змушувати їх запитувати в користувача його пароль:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Або змусити їх виконувати **довільні дії**.

### **`kTCCServiceEndpointSecurityClient`**

Дозволяє, серед іншого, **записувати базу даних TCC користувача**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Дозволяє **змінювати** атрибут **`NFSHomeDirectory`** користувача, що змінює шлях до його домашньої папки, і тому дозволяє **обійти TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Дозволяє змінювати файли всередині bundle застосунків (у app.app), що **типово заборонено**.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

Перевірити, хто має цей доступ, можна в _System Settings_ > _Privacy & Security_ > _App Management._

### `kTCCServiceAccessibility`

Процес зможе **зловживати функціями доступності macOS**, тобто, наприклад, натискати клавіші. Отже, він зможе запитати доступ для керування застосунком, наприклад Finder, і підтвердити діалог за допомогою цього дозволу.

## Entitlements, пов’язані з Trustcache/CDhash

Існують entitlements, які можна використати для обходу захисту Trustcache/CDhash, що запобігає виконанню downgrade-версій бінарних файлів Apple.

## Середній рівень

### `com.apple.security.cs.allow-jit`

Цей entitlement дозволяє **створювати пам’ять, доступну для запису та виконання**, передаючи прапорець `MAP_JIT` системній функції `mmap()`. Перегляньте [**цю сторінку для отримання додаткової інформації**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Цей entitlement дозволяє **перевизначати або змінювати C-код**, використовувати давно застарілу **`NSCreateObjectFileImageFromMemory`** (яка є принципово небезпечною) або використовувати framework **DVDPlayback**. Перегляньте [**цю сторінку для отримання додаткової інформації**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).

> [!CAUTION]
> Додавання цього entitlement наражає ваш застосунок на типові вразливості в memory-unsafe мовах програмування. Уважно розгляньте, чи потрібен вашому застосунку цей виняток.

### `com.apple.security.cs.disable-executable-page-protection`

Цей entitlement дозволяє **змінювати секції власних виконуваних файлів** на диску, щоб примусово завершити роботу. Перегляньте [**цю сторінку для отримання додаткової інформації**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).

> [!CAUTION]
> Entitlement Disable Executable Memory Protection є надзвичайним entitlement, який усуває фундаментальний захист вашого застосунку, унаслідок чого зловмисник може непомітно переписати виконуваний код вашого застосунку. За можливості надавайте перевагу entitlements із вужчою сферою дії.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Цей entitlement дозволяє монтувати файлову систему nullfs (типово заборонено). Інструмент: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

Згідно з цим blogpost, цей дозвіл TCC зазвичай має такий вигляд:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Дозволяє процесу **запитувати всі дозволи TCC**.

### **`kTCCServicePostEvent`**

Дозволяє **впроваджувати синтетичні події клавіатури та миші** у всій системі через `CGEventPost()`. Процес із цим дозволом може імітувати натискання клавіш, кліки миші та події прокручування в будь-якій програмі — фактично отримуючи **віддалене керування** робочим столом.

Це особливо небезпечно в поєднанні з `kTCCServiceAccessibility` або `kTCCServiceListenEvent`, оскільки дозволяє як читати, ТАК І впроваджувати input.
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

Дозволяє **перехоплювати всі події клавіатури та миші** у всій системі (input monitoring / keylogging). Процес може зареєструвати `CGEventTap`, щоб перехоплювати кожне натискання клавіш у будь-якій програмі, зокрема паролі, номери кредитних карток і приватні повідомлення.

Докладні exploitation techniques див. тут:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

Дозволяє **читати буфер дисплея** — робити знімки екрана та записувати відео з екрана будь-якої програми, зокрема захищених текстових полів. У поєднанні з OCR це може автоматично вилучати паролі та конфіденційні дані з екрана.

> [!WARNING]
> Починаючи з macOS Sonoma, під час screen capture у рядку меню постійно відображається індикатор. У старіших версіях screen recording може виконуватися повністю непомітно.

### **`kTCCServiceCamera`**

Дозволяє **знімати фото та відео** за допомогою вбудованої камери або підключених USB-камер. Code injection у binary із правом доступу до камери дає змогу непомітно здійснювати візуальне спостереження.

### **`kTCCServiceMicrophone`**

Дозволяє **записувати аудіо** з усіх пристроїв введення. Фонові daemons із доступом до мікрофона забезпечують постійне прослуховування навколишнього звуку без видимого вікна програми.

### **`kTCCServiceLocation`**

Дозволяє запитувати **фізичне розташування** пристрою через тріангуляцію Wi-Fi або Bluetooth-маяки. Безперервний моніторинг розкриває домашні та робочі адреси, маршрути переміщення й повсякденні звички.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

Доступ до **Контактів** (імена, електронні адреси, телефони — корисно для spear-phishing), **Календаря** (розклад зустрічей, списки учасників) і **Фотографій** (особисті фото, знімки екрана, які можуть містити облікові дані, метадані розташування).

Повний опис exploitation techniques для викрадення облікових даних через дозволи TCC див. тут:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox і Code Signing Entitlements

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Тимчасові винятки Sandbox** послаблюють App Sandbox, дозволяючи обмінюватися даними із загальносистемними Mach/XPC-сервісами, які Sandbox зазвичай блокує. Це **основний primitive для втечі із Sandbox** — скомпрометована програма в Sandbox може використовувати винятки mach-lookup для доступу до привілейованих daemons і exploitation їхніх XPC-інтерфейсів.
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

**DriverKit entitlements** дозволяють драйверним бінарним файлам у user space безпосередньо взаємодіяти з kernel через інтерфейси IOKit. Бінарні файли DriverKit керують hardware: USB, Thunderbolt, PCIe, HID-пристроями, аудіо та мережевим обладнанням.

Компрометація бінарного файлу DriverKit надає:
- **Поверхню атаки kernel** через некоректно сформовані виклики `IOConnectCallMethod`
- **Підміну USB-пристроїв** (емуляція клавіатури для HID-ін'єкції)
- **DMA-атаки** через інтерфейси PCIe/Thunderbolt
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
Для детального exploitation IOKit/DriverKit див.:

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}

## Посилання

- [1] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [2] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*` operations and `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [3] [XNU — `bsd/kern/kern_proc.c` (`csops` / `CS_OPS_CLEAR_LV` handler)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)

{{#include ../../../banners/hacktricks-training.md}}
