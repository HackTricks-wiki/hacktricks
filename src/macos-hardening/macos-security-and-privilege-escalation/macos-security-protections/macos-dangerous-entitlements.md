# Небезпечні Entitlements macOS і дозволи TCC

{{#include ../../../banners/hacktricks-training.md}}

Entitlements оголошують можливості та винятки безпеки, які операційна система надає підписаному коду. Наведені нижче записи зосереджені на тих, що особливо корисні під час offensive review.<sup>[[13]](#references)</sup>

> [!WARNING]
> Зверніть увагу, що entitlements, які починаються з **`com.apple`**, недоступні стороннім розробникам — надавати їх може лише Apple... Або, якщо ви використовуєте enterprise certificate, ви фактично можете створити власні entitlements, що починаються з **`com.apple`**, і обійти захист, заснований на цьому.

## Високий рівень

### `com.apple.rootless.install.heritable`

Entitlement **`com.apple.rootless.install.heritable`** дозволяє процесу **обійти SIP**. Дивіться [цю сторінку для отримання додаткової інформації](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Entitlement **`com.apple.rootless.install`** дозволяє процесу **обійти SIP**. Дивіться [цю сторінку для отримання додаткової інформації](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (раніше називався `task_for_pid-allow`)**

Цей entitlement дозволяє процесу отримати **порт task для будь-якого** процесу, крім kernel. Дивіться [**цю сторінку для отримання додаткової інформації**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

Цей entitlement дозволяє іншим процесам із entitlement **`com.apple.security.cs.debugger`** отримати порт task процесу, запущеного binary із цим entitlement, і **впровадити в нього code**. Дивіться [**цю сторінку для отримання додаткової інформації**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Apps із Debugging Tool Entitlement можуть викликати `task_for_pid()`, щоб отримати дійсний порт task для unsigned і third-party apps, у яких entitlement `Get Task Allow` встановлено в `true`. Однак навіть із debugging tool entitlement debugger **не може отримати порти task** процесів, які **не мають entitlement `Get Task Allow`** і тому захищені System Integrity Protection. Дивіться [**цю сторінку для отримання додаткової інформації**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).<sup>[[3]](#references)</sup>

### `com.apple.security.cs.disable-library-validation`

Цей entitlement дозволяє application **завантажувати frameworks, plug-ins або libraries без вимоги, щоб вони були підписані Apple або мали той самий Team ID**, що й основний executable, тому attacker може використати довільне завантаження library для впровадження code. Дивіться [**цю сторінку для отримання додаткової інформації**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).<sup>[[4]](#references)</sup>

### `com.apple.private.security.clear-library-validation`

Цей entitlement дуже схожий на **`com.apple.security.cs.disable-library-validation`**, але **замість** **безпосереднього вимкнення** library validation він дозволяє процесу **викликати системний виклик `csops`, щоб вимкнути її** під час виконання.

Назва entitlement жорстко задана в XNU поруч з операцією `csops`, яка його використовує:<sup>[[1]](#references)</sup>
```c
/* bsd/sys/codesign.h */
#define CLEAR_LV_ENTITLEMENT "com.apple.private.security.clear-library-validation"
...
#define CS_OPS_CLEAR_LV     15  /* clear the library validation flag */
```
Обробник ядра для `CS_OPS_CLEAR_LV` (`bsd/kern/kern_proc.c`) точно показує, наскільки вузькою є ця примітива:<sup>[[2]](#references)</sup>
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
- Працює лише з **самим собою** (`forself == 1`) — за її допомогою не можна вилучити library validation з іншого процесу.
- Вимагає, щоб процес справді **мав entitlement**, і відмовляє, якщо процес позначений як `CS_INSTALLER` або працює з кореневого шляху підсистеми.
- Очищає **`CS_REQUIRE_LV | CS_FORCED_LV`** із прапорців підписування коду процесу.

Коментар XNU пояснює передбачений сценарій використання, а також те, чому він цікавий зловмиснику:

> Цей параметр використовується для вилучення library validation із запущеного процесу. Він застосовується в plugin architectures, коли програмі потрібно завантажувати ненадійні бібліотеки. [...] Після того як процес завантажив ненадійну бібліотеку, покладатися на library validation надалі буде неефективно.

Іншими словами, **будь-який binary із цим entitlement є ціллю для dylib-injection**: виконайте код усередині нього (або переконайте його завантажити ваш plug-in) після того, як він скинув `CS_REQUIRE_LV`, і ви успадкуєте всі можливості, якими має право користуватися host process.

### `com.apple.security.cs.allow-dyld-environment-variables`

Цей entitlement дозволяє **використовувати змінні середовища DYLD**, які можна застосовувати для ін'єкції бібліотек і коду. Перегляньте [**це джерело для отримання додаткової інформації**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).<sup>[[5]](#references)</sup>

### `com.apple.private.tcc.manager` або `com.apple.rootless.storage`.`TCC`

[**Згідно з цим blog**](https://objective-see.org/blog/blog_0x4C.html) **і** [**цим blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), ці entitlements дозволяють процесу **змінювати** базу даних **TCC**.<sup>[[6]](#references)[[7]](#references)</sup>

### Права авторизації **`system.install.apple-software`** і **`system.install.apple-software.standard-user`**

Ці права Authorization Services керують інсталяцією програмного забезпечення, наданого Apple. Процес, якому дозволено їх отримувати, може обійти звичайний процес авторизації, що може бути корисним для **підвищення привілеїв**.<sup>[[14]](#references)</sup>

### `com.apple.private.security.kext-management`

Entitlement, необхідний для надсилання **kernel запиту на завантаження kernel extension**.

### **`com.apple.private.icloud-account-access`**

Entitlement **`com.apple.private.icloud-account-access`** дає змогу взаємодіяти із сервісом **`com.apple.iCloudHelper`** XPC, який **надає iCloud tokens**.

**iMovie** і **Garageband** мали цей entitlement.

Для отримання додаткової **інформації** про exploit, який дає змогу **отримати iCloud tokens** завдяки цьому entitlement, перегляньте доповідь: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[8]](#references)</sup>

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Я не знаю, що це дозволяє робити

### `com.apple.private.apfs.revert-to-snapshot`

TODO: [**У цьому звіті**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) згадується, що цей entitlement можна було б використати для оновлення вмісту, захищеного SSV, після перезавантаження. Якщо ви знаєте як, надішліть PR!<sup>[[9]](#references)</sup>

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: [**У цьому ж звіті**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) згадується, що створення sealed snapshot можна було б використати для оновлення вмісту, захищеного SSV, після перезавантаження. Якщо ви знаєте як, надішліть PR!<sup>[[9]](#references)</sup>

### `keychain-access-groups`

Цей entitlement перелічує групи **keychain**, до яких має доступ застосунок:
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

Надає права **Full Disk Access** — один із найвищих рівнів дозволів TCC, які можна отримати.

### **`kTCCServiceAppleEvents`**

Дозволяє застосунку надсилати події іншим застосункам, які зазвичай використовуються для **автоматизації завдань**. Керуючи іншими застосунками, він може зловживати дозволами, наданими цим застосункам.

Наприклад, змусити їх запитати в користувача пароль:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Або змусити їх виконувати **довільні дії**.

### **`kTCCServiceEndpointSecurityClient`**

Надає, серед інших дозволів, можливість **записувати базу даних TCC користувача**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Дозволяє **змінювати** атрибут **`NFSHomeDirectory`** користувача, що змінює шлях до його домашньої папки й у такий спосіб дозволяє **обійти TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Дозволяє змінювати файли всередині bundle застосунків (усередині app.app), що **типово заборонено**.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

Перевірити, хто має цей доступ, можна в _System Settings_ > _Privacy & Security_ > _App Management._

### `kTCCServiceAccessibility`

Процес зможе **зловживати функціями доступності macOS**, тобто, наприклад, натискати клавіші. Тому він зможе запросити доступ для керування застосунком, наприклад Finder, і схвалити діалогове вікно за допомогою цього дозволу.

## Entitlements, пов’язані з Trustcache/CDhash

Існують entitlements, які можна використати для обходу захистів Trustcache/CDhash, що запобігають виконанню downgraded версій бінарних файлів Apple.

## Середній рівень

### `com.apple.security.cs.allow-jit`

Цей entitlement дозволяє процесу **створювати пам’ять, доступну для запису та виконання**, передаючи прапорець `MAP_JIT` системній функції `mmap()`. Перегляньте [**це для отримання додаткової інформації**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).<sup>[[10]](#references)</sup>

### `com.apple.security.cs.allow-unsigned-executable-memory`

Цей entitlement дозволяє **перевизначати або змінювати C-код**, використовувати давно застарілу **`NSCreateObjectFileImageFromMemory`** (яка є принципово небезпечною) або використовувати framework **DVDPlayback**. Перегляньте [**це для отримання додаткової інформації**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).<sup>[[11]](#references)</sup>

> [!CAUTION]
> Додавання цього entitlement робить ваш застосунок вразливим до поширених вразливостей у мовах програмування з небезпечною роботою з пам’яттю. Уважно розгляньте, чи потрібен вашому застосунку цей виняток.

### `com.apple.security.cs.disable-executable-page-protection`

Цей entitlement дозволяє **змінювати секції власних виконуваних файлів** на диску, щоб примусово завершити роботу. Перегляньте [**це для отримання додаткової інформації**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).<sup>[[12]](#references)</sup>

> [!CAUTION]
> Entitlement Disable Executable Memory Protection є надзвичайно небезпечним entitlement, який видаляє фундаментальний захист вашого застосунку, уможливлюючи для атакувальника непомітний перезапис виконуваного коду вашого застосунку. За можливості надавайте перевагу entitlements із вужчими повноваженнями.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Цей entitlement дозволяє монтувати файлову систему nullfs (типово заборонено). Інструмент: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

Згідно з цим дописом у блозі, цей дозвіл TCC зазвичай має такий вигляд:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Дозволяє процесу **запитувати всі дозволи TCC**.

### **`kTCCServicePostEvent`**

Дозволяє **впроваджувати синтетичні події клавіатури та миші** в усій системі через `CGEventPost()`. Процес із цим дозволом може імітувати натискання клавіш, клацання мишею та події прокручування в будь-якій програмі — фактично забезпечуючи **віддалене керування** робочим столом.

Це особливо небезпечно в поєднанні з `kTCCServiceAccessibility` або `kTCCServiceListenEvent`, оскільки дає змогу одночасно зчитувати ТА впроваджувати введення.
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

Дозволяє **перехоплювати всі події клавіатури та миші** на рівні всієї системи (моніторинг введення / keylogging). Процес може зареєструвати `CGEventTap`, щоб захоплювати кожне натискання клавіш у будь-якій програмі, зокрема паролі, номери кредитних карток і приватні повідомлення.

Докладні техніки експлуатації див. у:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

Дозволяє **читати буфер дисплея** — робити знімки екрана та записувати відео з екрана будь-якої програми, зокрема захищених текстових полів. У поєднанні з OCR це може автоматично вилучати паролі та конфіденційні дані з екрана.

> [!WARNING]
> Починаючи з macOS Sonoma, захоплення екрана відображає постійний індикатор у рядку меню. У старіших версіях запис екрана може виконуватися повністю безшумно.

### **`kTCCServiceCamera`**

Дозволяє **захоплювати фото та відео** з вбудованої камери або підключених USB-камер. Code injection у бінарний файл із правом доступу до камери дає змогу здійснювати приховане візуальне спостереження.

### **`kTCCServiceMicrophone`**

Дозволяє **записувати аудіо** з усіх пристроїв введення. Фонові демони з доступом до мікрофона забезпечують постійне приховане прослуховування навколишнього звуку без видимого вікна програми.

### **`kTCCServiceLocation`**

Дозволяє запитувати **фізичне розташування** пристрою через Wi-Fi-тріангуляцію або Bluetooth-маяки. Безперервний моніторинг розкриває домашні й робочі адреси, маршрути переміщення та повсякденний розпорядок.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

Доступ до **Контактів** (імена, електронні адреси, номери телефонів — корисно для spear-phishing), **Календаря** (розклад зустрічей, списки учасників) і **Фото** (особисті фотографії, знімки екрана, що можуть містити облікові дані, метадані розташування).

Повний опис технік крадіжки облікових даних через дозволи TCC див. у:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox і Code Signing Entitlements

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Тимчасові винятки Sandbox** послаблюють App Sandbox, дозволяючи взаємодію із загальносистемними Mach/XPC-сервісами, які Sandbox зазвичай блокує. Це **основний примітив виходу з Sandbox** — скомпрометована програма в Sandbox може використовувати винятки mach-lookup для доступу до привілейованих демонів та експлуатації їхніх XPC-інтерфейсів.
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

**DriverKit entitlements** дозволяють user-space driver binaries безпосередньо взаємодіяти з kernel через інтерфейси IOKit. DriverKit binaries керують hardware: USB, Thunderbolt, PCIe, HID devices, аудіо та networking.

Компрометація DriverKit binary надає:
- **Kernel attack surface** через неправильно сформовані виклики `IOConnectCallMethod`
- **USB device spoofing** (емуляція keyboard для HID injection)
- **DMA attacks** через PCIe/Thunderbolt interfaces
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
Для детальної експлуатації IOKit/DriverKit див.:

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}

## References

- [1] [XNU — `bsd/sys/codesign.h` (операції `CS_OPS_*` і `CLEAR_LV_ENTITLEMENT)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [2] [XNU — `bsd/kern/kern_proc.c` (обробник `csops` / `CS_OPS_CLEAR_LV`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [3] [Apple Developer — Entitlement для інструментів налагодження (`com.apple.security.cs.debugger`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger)
- [4] [Apple Developer — Entitlement для вимкнення перевірки бібліотек](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation)
- [5] [Apple Developer — Entitlement для дозволу змінних середовища DYLD](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [6] [Objective-See — CVE-2020-9934: Обхід TCC](https://objective-see.org/blog/blog_0x4C.html)
- [7] [Wojciech Reguła — Увімкнути музику й обійти TCC, або CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [8] [#OBTS v5.0: «Що відбувається на вашому Mac, залишається в iCloud Apple?!» — Wojciech Regula (YouTube)](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [9] [Кошмар OTA-оновлення Apple: обхід перевірки підпису та отримання контролю над Kernel](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [10] [Apple Developer — Entitlement для дозволу виконання JIT-компільованого коду (`com.apple.security.cs.allow-jit`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)
- [11] [Apple Developer — Entitlement для дозволу непідписаної виконуваної пам’яті](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory)
- [12] [Apple Developer — Entitlement для вимкнення захисту виконуваної пам’яті](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection)
- [13] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [14] [Архів Apple Developer — Посібник із програмування Authorization Services](https://developer.apple.com/library/archive/documentation/Security/Conceptual/authorization_concepts/01introduction/introduction.html)
{{#include ../../../banners/hacktricks-training.md}}
