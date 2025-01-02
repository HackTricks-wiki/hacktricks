# macOS Небезпечні права доступу та TCC дозволи

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> Зверніть увагу, що права доступу, які починаються з **`com.apple`**, недоступні для третіх осіб, лише Apple може їх надати.

## Високий

### `com.apple.rootless.install.heritable`

Право доступу **`com.apple.rootless.install.heritable`** дозволяє **обійти SIP**. Перевірте [це для отримання додаткової інформації](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Право доступу **`com.apple.rootless.install`** дозволяє **обійти SIP**. Перевірте [це для отримання додаткової інформації](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (раніше називався `task_for_pid-allow`)**

Це право доступу дозволяє отримати **порт завдання для будь-якого** процесу, за винятком ядра. Перевірте [**це для отримання додаткової інформації**](../macos-proces-abuse/macos-ipc-inter-process-communication/).

### `com.apple.security.get-task-allow`

Це право доступу дозволяє іншим процесам з правом доступу **`com.apple.security.cs.debugger`** отримати порт завдання процесу, запущеного бінарним файлом з цим правом доступу, і **впроваджувати код у нього**. Перевірте [**це для отримання додаткової інформації**](../macos-proces-abuse/macos-ipc-inter-process-communication/).

### `com.apple.security.cs.debugger`

Додатки з правом доступу до інструментів налагодження можуть викликати `task_for_pid()`, щоб отримати дійсний порт завдання для незахищених і сторонніх додатків з правом доступу `Get Task Allow`, встановленим на `true`. Однак, навіть з правом доступу до інструментів налагодження, налагоджувач **не може отримати порти завдання** процесів, які **не мають права доступу `Get Task Allow`**, і які, отже, захищені захистом цілісності системи. Перевірте [**це для отримання додаткової інформації**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).

### `com.apple.security.cs.disable-library-validation`

Це право доступу дозволяє **завантажувати фреймворки, плагіни або бібліотеки без підпису Apple або підпису з тим же ідентифікатором команди**, як основний виконуваний файл, тому зловмисник може зловживати завантаженням деякої довільної бібліотеки для впровадження коду. Перевірте [**це для отримання додаткової інформації**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Це право доступу дуже схоже на **`com.apple.security.cs.disable-library-validation`**, але **замість** **прямого відключення** перевірки бібліотек, воно дозволяє процесу **викликати системний виклик `csops`, щоб відключити його**.\
Перевірте [**це для отримання додаткової інформації**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

Це право доступу дозволяє **використовувати змінні середовища DYLD**, які можуть бути використані для впровадження бібліотек і коду. Перевірте [**це для отримання додаткової інформації**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` або `com.apple.rootless.storage`.`TCC`

[**Згідно з цим блогу**](https://objective-see.org/blog/blog_0x4C.html) **і** [**цим блогом**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), ці права доступу дозволяють **модифікувати** базу даних **TCC**.

### **`system.install.apple-software`** та **`system.install.apple-software.standar-user`**

Ці права доступу дозволяють **встановлювати програмне забезпечення без запиту дозволів** у користувача, що може бути корисним для **підвищення привілеїв**.

### `com.apple.private.security.kext-management`

Право доступу, необхідне для запиту **ядра на завантаження розширення ядра**.

### **`com.apple.private.icloud-account-access`**

Право доступу **`com.apple.private.icloud-account-access`** дозволяє спілкуватися з **`com.apple.iCloudHelper`** XPC сервісом, який надасть **токени iCloud**.

**iMovie** та **Garageband** мали це право доступу.

Для отримання більшої **інформації** про експлойт для **отримання токенів iCloud** з цього права доступу перевірте доповідь: [**#OBTS v5.0: "Що відбувається на вашому Mac, залишається в iCloud Apple?!" - Войцех Регула**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Я не знаю, що це дозволяє робити

### `com.apple.private.apfs.revert-to-snapshot`

TODO: У [**цьому звіті**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **зазначено, що це може бути використано для** оновлення вмісту, захищеного SSV, після перезавантаження. Якщо ви знаєте, як це зробити, надішліть PR, будь ласка!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: У [**цьому звіті**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **зазначено, що це може бути використано для** оновлення вмісту, захищеного SSV, після перезавантаження. Якщо ви знаєте, як це зробити, надішліть PR, будь ласка!

### `keychain-access-groups`

Це право доступу містить **групи ключів**, до яких має доступ додаток:
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

Надає **Повний доступ до диска**, одне з найвищих дозволів TCC, які ви можете мати.

### **`kTCCServiceAppleEvents`**

Дозволяє додатку надсилати події іншим додаткам, які зазвичай використовуються для **автоматизації завдань**. Контролюючи інші додатки, він може зловживати дозволами, наданими цим іншим додаткам.

Наприклад, змушуючи їх запитувати у користувача його пароль:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Або змусити їх виконувати **произвольні дії**.

### **`kTCCServiceEndpointSecurityClient`**

Дозволяє, серед інших дозволів, **записувати базу даних TCC користувачів**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Дозволяє **змінювати** атрибут **`NFSHomeDirectory`** користувача, що змінює шлях до його домашньої папки і, отже, дозволяє **обійти TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Дозволяє модифікувати файли всередині пакету додатків (всередині app.app), що **за замовчуванням заборонено**.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

Можна перевірити, хто має цей доступ у _Системних налаштуваннях_ > _Конфіденційність та безпека_ > _Управління додатками._

### `kTCCServiceAccessibility`

Процес зможе **зловживати функціями доступності macOS**, що означає, що, наприклад, він зможе натискати клавіші. Тому він може запитати доступ для контролю додатка, такого як Finder, і підтвердити діалог з цим дозволом.

## Середній

### `com.apple.security.cs.allow-jit`

Цей привілей дозволяє **створювати пам'ять, яка є записуваною та виконуваною**, передаючи прапорець `MAP_JIT` функції системи `mmap()`. Перевірте [**це для отримання додаткової інформації**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Цей привілей дозволяє **перезаписувати або патчити C код**, використовувати давно застарілу **`NSCreateObjectFileImageFromMemory`** (яка є фундаментально небезпечною), або використовувати фреймворк **DVDPlayback**. Перевірте [**це для отримання додаткової інформації**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).

> [!CAUTION]
> Включення цього привілею піддає ваш додаток загальним вразливостям у мовах програмування з небезпечним управлінням пам'яттю. Уважно розгляньте, чи потрібен вашому додатку цей виняток.

### `com.apple.security.cs.disable-executable-page-protection`

Цей привілей дозволяє **модифікувати секції своїх власних виконуваних файлів** на диску, щоб примусово вийти. Перевірте [**це для отримання додаткової інформації**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).

> [!CAUTION]
> Привілей Disable Executable Memory Protection є екстремальним привілеєм, який усуває основний захист безпеки з вашого додатку, що робить можливим для зловмисника переписати виконуваний код вашого додатку без виявлення. Вибирайте вужчі привілеї, якщо це можливо.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Цей привілей дозволяє монтувати файлову систему nullfs (заборонену за замовчуванням). Інструмент: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

Згідно з цим блогом, цей дозвіл TCC зазвичай зустрічається у формі:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Дозвольте процесу **запитувати всі дозволи TCC**.

### **`kTCCServicePostEvent`**

{{#include ../../../banners/hacktricks-training.md}}
