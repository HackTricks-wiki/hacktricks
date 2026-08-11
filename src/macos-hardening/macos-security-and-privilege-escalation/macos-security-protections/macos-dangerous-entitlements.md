# Небезпечні Entitlements і дозволи TCC у macOS

{{#include ../../../banners/hacktricks-training.md}}

Entitlements оголошують можливості та винятки безпеки, які операційна система надає підписаному коду. Наведені нижче записи зосереджені на тих, що особливо корисні під час offensive review.<sup>[[13]](#references)</sup>

> [!WARNING]
> Зверніть увагу, що entitlements, які починаються з **`com.apple`**, недоступні стороннім розробникам — надати їх може лише Apple... Або, якщо ви використовуєте enterprise certificate, ви фактично можете створити власні entitlements, що починаються з **`com.apple`**, і обійти захист, побудований на цьому.

## High

### `com.apple.rootless.install.heritable`

Entitlement **`com.apple.rootless.install.heritable`** дозволяє процесу **обійти SIP**. Дивіться [докладніше тут](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Entitlement **`com.apple.rootless.install`** дозволяє процесу **обійти SIP**. Дивіться [докладніше тут](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (раніше називався `task_for_pid-allow`)**

Цей entitlement дозволяє процесу отримати **task port будь-якого** процесу, крім kernel. Дивіться [**докладніше тут**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

Цей entitlement дозволяє іншим процесам із entitlement **`com.apple.security.cs.debugger`** отримати task port процесу, запущеного binary з цим entitlement, і **впровадити в нього code**. Дивіться [**докладніше тут**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Apps із Debugging Tool Entitlement можуть викликати `task_for_pid()`, щоб отримати дійсний task port для unsigned і third-party apps, у яких для entitlement `Get Task Allow` встановлено значення `true`. Однак навіть за наявності debugging tool entitlement debugger **не може отримати task ports** процесів, які **не мають entitlement `Get Task Allow`** і тому захищені System Integrity Protection. Дивіться [**докладніше тут**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).<sup>[[3]](#references)</sup>

### `com.apple.security.cs.disable-library-validation`

Цей entitlement дозволяє application **завантажувати frameworks, plug-ins або libraries без вимоги, щоб вони були підписані Apple або мали такий самий Team ID**, як і main executable, тому attacker може скористатися довільним завантаженням library для code injection. Дивіться [**докладніше тут**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).<sup>[[4]](#references)</sup>

### `com.apple.private.security.clear-library-validation`

Цей entitlement дуже схожий на **`com.apple.security.cs.disable-library-validation`**, але **замість** **безпосереднього вимкнення** library validation він дозволяє процесу **викликати системний виклик `csops`, щоб вимкнути її** під час виконання.

Назва entitlement жорстко задана в XNU поруч з операцією `csops`, яка його використовує:<sup>[[1]](#references)</sup>
```c
/* bsd/sys/codesign.h */
#define CLEAR_LV_ENTITLEMENT "com.apple.private.security.clear-library-validation"
...
#define CS_OPS_CLEAR_LV     15  /* clear the library validation flag */
```
Обробник ядра для `CS_OPS_CLEAR_LV` (`bsd/kern/kern_proc.c`) наочно показує, наскільки вузьким є цей примітив:<sup>[[2]](#references)</sup>
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
- Працює лише над **самим процесом** (`forself == 1`) — за її допомогою не можна вилучити library validation з іншого процесу.
- Вимагає, щоб процес дійсно **мав entitlement**, і відмовляє, якщо процес позначений як `CS_INSTALLER` або запущений у кореневому шляху підсистеми.
- Очищує **`CS_REQUIRE_LV | CS_FORCED_LV`** із прапорців code-signing процесу.

Коментар XNU пояснює передбачений варіант використання, а також те, чому це цікаво зловмиснику:

> Цей параметр використовується для вилучення library validation із запущеного процесу. Це застосовується в архітектурах плагінів, коли програмі потрібно завантажувати ненадійні бібліотеки. [...] Після того як процес завантажив ненадійну бібліотеку, покладатися на library validation у майбутньому буде неефективно.

Іншими словами, **будь-який бінарний файл із цим entitlement є ціллю для dylib-injection**: запустіть код усередині нього (або переконайте його завантажити ваш plug-in) після того, як він скасував `CS_REQUIRE_LV`, і ви успадкуєте всі можливості, які дозволено виконувати довіреному процесу-хосту.

### `com.apple.security.cs.allow-dyld-environment-variables`

Цей entitlement дозволяє **використовувати змінні середовища DYLD**, які можна застосовувати для ін'єкції бібліотек і коду. Докладніше див. [**тут**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).<sup>[[5]](#references)</sup>

### `com.apple.private.tcc.manager` або `com.apple.rootless.storage`.`TCC`

[**Згідно з цим блогом**](https://objective-see.org/blog/blog_0x4C.html) **та** [**цим блогом**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), ці entitlements дозволяють процесу **змінювати** базу даних **TCC**.<sup>[[6]](#references)[[7]](#references)</sup>

### **`system.install.apple-software`** та **`system.install.apple-software.standar-user`**

Ці entitlements дозволяють процесу **встановлювати програмне забезпечення без запиту дозволу користувача**, що може бути корисним для **підвищення привілеїв**.

### `com.apple.private.security.kext-management`

Entitlement, необхідний для надсилання **ядру запиту на завантаження kernel extension**.

### **`com.apple.private.icloud-account-access`**

Entitlement **`com.apple.private.icloud-account-access`** дає змогу взаємодіяти з **сервісом XPC `com.apple.iCloudHelper`**, який **надає токени iCloud**.

**iMovie** та **Garageband** мали цей entitlement.

Щоб отримати додаткову **інформацію** про exploit для **отримання токенів iCloud** за допомогою цього entitlement, перегляньте доповідь: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[8]](#references)</sup>

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Я не знаю, що саме дозволяє робити цей entitlement

### `com.apple.private.apfs.revert-to-snapshot`

TODO: [**У цьому звіті**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) зазначено, що цей entitlement можна використовувати для оновлення вмісту, захищеного SSV, після перезавантаження. Якщо ви знаєте як, надішліть PR!<sup>[[9]](#references)</sup>

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: [**У тому ж звіті**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) зазначено, що створення sealed snapshot можна використовувати для оновлення вмісту, захищеного SSV, після перезавантаження. Якщо ви знаєте як, надішліть PR!<sup>[[9]](#references)</sup>

### `keychain-access-groups`

Цей entitlement містить перелік груп **keychain**, до яких має доступ застосунок:
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

Надає дозволи **Full Disk Access**, одні з найвищих дозволів TCC, які можна отримати.

### **`kTCCServiceAppleEvents`**

Дозволяє застосунку надсилати події іншим застосункам, які зазвичай використовуються для **автоматизації завдань**. Керуючи іншими застосунками, він може зловживати дозволами, наданими цим застосункам.

Наприклад, змусити їх попросити користувача ввести пароль:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Або змусити їх виконувати **довільні дії**.

### **`kTCCServiceEndpointSecurityClient`**

Дозволяє, серед інших дозволів, **записувати базу даних TCC користувача**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Дозволяє **змінювати** атрибут **`NFSHomeDirectory`** користувача, що змінює шлях до його домашньої папки, і тому дозволяє **обійти TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Дозволяє змінювати файли всередині bundle застосунків (усередині app.app), що **типово заборонено**.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

Перевірити, хто має цей доступ, можна в _Системні параметри_ > _Конфіденційність і безпека_ > _Керування застосунками._

### `kTCCServiceAccessibility`

Процес зможе **зловживати функціями accessibility macOS**, тобто, наприклад, натискати клавіші. Отже, він зможе запросити доступ для керування застосунком, наприклад Finder, і схвалити діалогове вікно за допомогою цього дозволу.

## Entitlements, пов’язані з Trustcache/CDhash

Існують entitlements, які можна використати для обходу захисту Trustcache/CDhash, що запобігає виконанню знижених версій бінарних файлів Apple.

## Середній рівень

### `com.apple.security.cs.allow-jit`

Цей entitlement дозволяє процесу **створювати пам’ять, доступну для запису та виконання**, передаючи прапорець `MAP_JIT` системній функції `mmap()`. Див. [**додаткову інформацію тут**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).<sup>[[10]](#references)</sup>

### `com.apple.security.cs.allow-unsigned-executable-memory`

Цей entitlement дозволяє **перевизначати або змінювати C-код**, використовувати давно застарілу **`NSCreateObjectFileImageFromMemory`** (яка є принципово небезпечною) або використовувати framework **DVDPlayback**. Див. [**додаткову інформацію тут**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).<sup>[[11]](#references)</sup>

> [!CAUTION]
> Додавання цього entitlement створює для вашого застосунку ризик поширених вразливостей у мовах програмування з небезпечною роботою з пам’яттю. Уважно розгляньте, чи потрібен вашому застосунку цей виняток.

### `com.apple.security.cs.disable-executable-page-protection`

Цей entitlement дозволяє **змінювати секції власних виконуваних файлів** на диску, щоб примусово завершити роботу. Див. [**додаткову інформацію тут**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).<sup>[[12]](#references)</sup>

> [!CAUTION]
> Entitlement Disable Executable Memory Protection є надзвичайним entitlement, який видаляє фундаментальний захист вашого застосунку, що дає зловмиснику змогу непомітно переписувати виконуваний код вашого застосунку. Якщо можливо, надавайте перевагу вужчим entitlements.

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

Дозволяє **впроваджувати синтетичні події клавіатури та миші** на рівні всієї системи через `CGEventPost()`. Процес із цим дозволом може імітувати натискання клавіш, клацання миші та події прокручування в будь-якій програмі, фактично отримуючи **віддалене керування** робочим столом.

Це особливо небезпечно в поєднанні з `kTCCServiceAccessibility` або `kTCCServiceListenEvent`, оскільки дозволяє як читати, ТАК І впроваджувати ввід.
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

Дозволяє **перехоплювати всі події клавіатури та миші** у всій системі (input monitoring / keylogging). Процес може зареєструвати `CGEventTap`, щоб перехоплювати кожне натискання клавіш у будь-якій програмі, зокрема паролі, номери кредитних карток і приватні повідомлення.

Докладні техніки експлуатації див. у:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

Дозволяє **читати буфер дисплея** — робити знімки екрана та записувати відео екрана будь-якої програми, зокрема захищених текстових полів. У поєднанні з OCR це може автоматично вилучати паролі та конфіденційні дані з екрана.

> [!WARNING]
> Починаючи з macOS Sonoma, захоплення екрана показує постійний індикатор у рядку меню. У старіших версіях запис екрана може відбуватися повністю непомітно.

### **`kTCCServiceCamera`**

Дозволяє **знімати фото та відео** за допомогою вбудованої камери або підключених USB-камер. Ін'єкція коду в binary із camera entitlement забезпечує приховане візуальне спостереження.

### **`kTCCServiceMicrophone`**

Дозволяє **записувати аудіо** з усіх пристроїв введення. Фонові daemons із доступом до мікрофона забезпечують постійне прослуховування навколишнього середовища без видимого вікна програми.

### **`kTCCServiceLocation`**

Дозволяє запитувати **фізичне місцезнаходження** пристрою через тріангуляцію Wi-Fi або Bluetooth-маяки. Безперервний моніторинг розкриває домашні й робочі адреси, маршрути пересування та щоденні звички.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

Доступ до **Contacts** (імена, адреси електронної пошти, номери телефонів — корисно для spear-phishing), **Calendar** (розклад зустрічей, списки учасників) і **Photos** (особисті фотографії, знімки екрана, які можуть містити credentials, а також метадані місцезнаходження).

Повний опис технік крадіжки credentials через дозволи TCC див. у:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Entitlements Sandbox і Code Signing

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Тимчасові винятки Sandbox** послаблюють App Sandbox, дозволяючи взаємодію із загальносистемними Mach/XPC-сервісами, які Sandbox зазвичай блокує. Це **основний примітив обходу Sandbox** — скомпрометована програма в Sandbox може використовувати винятки mach-lookup для доступу до привілейованих daemons і експлуатації їхніх XPC-інтерфейсів.
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && codesign -d --entitlements - "$binary" 2>&1 | grep -q "mach-lookup" && echo "$(basename "$1")"
' _ {} \; 2>/dev/null
```
Для детального ланцюжка експлуатації: sandboxed app → mach-lookup exception → vulnerable daemon → sandbox escape див.:

{{#ref}}
macos-code-signing-weaknesses-and-sandbox-escapes.md
{{#endref}}

### `com.apple.developer.driverkit`

**DriverKit entitlements** дозволяють драйверним бінарним файлам у user space безпосередньо взаємодіяти з kernel через інтерфейси IOKit. Бінарні файли DriverKit керують hardware: USB, Thunderbolt, PCIe, HID-пристроями, audio та networking.

Компрометація бінарного файлу DriverKit надає:
- **Поверхню атаки kernel** через malformed виклики `IOConnectCallMethod`
- **Підміну USB-пристроїв** (імітація keyboard для HID injection)
- **DMA-атаки** через інтерфейси PCIe/Thunderbolt
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
Для детальної інформації щодо exploitation IOKit/DriverKit дивіться:

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}

## References

- [1] [XNU — `bsd/sys/codesign.h` (операції `CS_OPS_*` і `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [2] [XNU — `bsd/kern/kern_proc.c` (обробник `csops` / `CS_OPS_CLEAR_LV`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [3] [Apple Developer — Entitlement для інструментів налагодження (`com.apple.security.cs.debugger`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger)
- [4] [Apple Developer — Entitlement для вимкнення перевірки бібліотек](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation)
- [5] [Apple Developer — Entitlement для дозволу змінних середовища DYLD](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [6] [Objective-See — CVE-2020-9934: обхід TCC](https://objective-see.org/blog/blog_0x4C.html)
- [7] [Wojciech Reguła — відтворення музики та обхід TCC, або CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [8] [#OBTS v5.0: «Що відбувається на вашому Mac, залишається в iCloud Apple?!» — Wojciech Regula (YouTube)](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [9] [Кошмар OTA Update від Apple: обхід перевірки підпису та Pwning Kernel](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [10] [Apple Developer — Entitlement для дозволу виконання JIT-компільованого коду (`com.apple.security.cs.allow-jit`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)
- [11] [Apple Developer — Entitlement для дозволу непідписаної виконуваної пам’яті](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory)
- [12] [Apple Developer — Entitlement для вимкнення захисту виконуваної пам’яті](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection)
- [13] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
{{#include ../../../banners/hacktricks-training.md}}
