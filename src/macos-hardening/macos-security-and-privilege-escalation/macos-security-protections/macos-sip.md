# macOS SIP

{{#include ../../../banners/hacktricks-training.md}}

## **Основна інформація**

**System Integrity Protection (SIP)** у macOS — це механізм, призначений для запобігання несанкціонованим змінам ключових системних папок навіть найбільш привілейованими користувачами. Ця функція відіграє важливу роль у підтриманні цілісності системи, обмежуючи такі дії, як додавання, змінення або видалення файлів у захищених областях. Основні папки, захищені SIP, включають:

- **/System**
- **/bin**
- **/sbin**
- **/usr**

Правила, що визначають поведінку SIP, містяться у конфігураційному файлі **`/System/Library/Sandbox/rootless.conf`**. У цьому файлі шляхи, перед якими стоїть зірочка (\*), позначаються як винятки із загальних суворих обмежень SIP.

Розглянемо наведений нижче приклад:
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
Цей фрагмент означає, що хоча SIP зазвичай захищає каталог **`/usr`**, існують певні підкаталоги (`/usr/libexec/cups`, `/usr/local` і `/usr/share/man`), у яких дозволено внесення змін, що позначено зірочкою (\*) перед їхніми шляхами.

Щоб перевірити, чи захищені каталог або файл SIP, можна використати команду **`ls -lOd`** і перевірити наявність прапорця **`restricted`** або **`sunlnk`**. Наприклад:
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
У цьому випадку прапорець **`sunlnk`** означає, що сам каталог `/usr/libexec/cups` **не можна видалити**, хоча файли в ньому можна створювати, змінювати або видаляти.

З іншого боку:
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
Тут прапорець **`restricted`** вказує, що каталог `/usr/libexec` захищений SIP. У каталозі, захищеному SIP, не можна створювати, змінювати або видаляти файли.

Крім того, якщо файл містить розширений **атрибут** **`com.apple.rootless`**, цей файл також буде **захищений SIP**.

> [!TIP]
> Зверніть увагу, що hook **`hook_vnode_check_setextattr`** у **Sandbox** запобігає будь-якій спробі змінити розширений атрибут **`com.apple.rootless`.**

**SIP також обмежує інші дії root**, зокрема:

- Завантаження ненадійних kernel extensions
- Отримання task-ports для процесів, підписаних Apple
- Зміну змінних NVRAM
- Дозвіл на kernel debugging

Параметри зберігаються у змінній nvram як bitflag (`csr-active-config` на Intel, а `lp-sip0` зчитується з Device Tree завантаженої системи на ARM). Прапорці можна знайти у вихідному коді XNU в `csr.sh`:

<figure><img src="../../../images/image (1192).png" alt=""><figcaption></figcaption></figure>

### Статус SIP

Перевірити, чи ввімкнено SIP у вашій системі, можна за допомогою такої команди:
```bash
csrutil status
```
Якщо вам потрібно вимкнути SIP, перезавантажте комп'ютер у режимі відновлення (натиснувши Command+R під час запуску), а потім виконайте таку команду:
```bash
csrutil disable
```
Якщо ви хочете залишити SIP увімкненим, але вимкнути захист від налагодження, це можна зробити за допомогою:
```bash
csrutil enable --without debug
```
### Інші обмеження

- **Забороняє завантаження непідписаних розширень ядра** (kexts), гарантуючи, що лише перевірені розширення взаємодіють із системним ядром.
- **Перешкоджає налагодженню** системних процесів macOS, захищаючи основні компоненти системи від несанкціонованого доступу та модифікації.
- **Обмежує інструменти**, такі як dtrace, у перевірці системних процесів, додатково захищаючи цілісність роботи системи.

[**Дізнатися більше про SIP можна в цій доповіді**](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)**.**<sup>[[1]](#references)</sup>

### **Entitlements, пов'язані із SIP**

- `com.apple.rootless.xpc.bootstrap`: Керування launchd
- `com.apple.rootless.install[.heritable]`: Доступ до файлової системи
- `com.apple.rootless.kext-management`: `kext_request`
- `com.apple.rootless.datavault.controller`: Керування UF_DATAVAULT
- `com.apple.rootless.xpc.bootstrap`: Можливості налаштування XPC
- `com.apple.rootless.xpc.effective-root`: Root через launchd XPC
- `com.apple.rootless.restricted-block-devices`: Доступ до необроблених блокових пристроїв
- `com.apple.rootless.internal.installer-equivalent`: Необмежений доступ до файлової системи
- `com.apple.rootless.restricted-nvram-variables[.heritable]`: Повний доступ до NVRAM
- `com.apple.rootless.storage.label`: Модифікація файлів, обмежених xattr com.apple.rootless із відповідною міткою
- `com.apple.rootless.volume.VM.label`: Підтримка VM swap на томі

## Обхід SIP

Обхід SIP дозволяє зловмиснику:

- **Отримати доступ до даних користувачів**: Читати конфіденційні дані користувачів, такі як пошта, повідомлення та історія Safari, з усіх облікових записів користувачів.
- **TCC Bypass**: Безпосередньо маніпулювати базою даних TCC (Transparency, Consent, and Control), щоб надати несанкціонований доступ до вебкамери, мікрофона та інших ресурсів.
- **Забезпечити persistence**: Розмістити malware у місцях, захищених SIP, зробивши його стійким до видалення навіть із root privileges. Це також включає можливість втручання в Malware Removal Tool (MRT).
- **Завантажувати розширення ядра**: Хоча існують додаткові захисні механізми, обхід SIP спрощує процес завантаження непідписаних розширень ядра.

### Пакети Installer

**Пакети Installer, підписані сертифікатом Apple,** можуть обходити його захист. Це означає, що навіть пакети, підписані стандартними розробниками, будуть заблоковані, якщо вони намагаються змінити каталоги, захищені SIP.

### Неіснуючий файл SIP

Однією з потенційних лазівок є ситуація, коли файл, зазначений у **`rootless.conf`, але наразі не існує**, можна створити. Malware може скористатися цим для **забезпечення persistence** у системі. Наприклад, шкідлива програма може створити файл .plist у `/System/Library/LaunchDaemons`, якщо він зазначений у `rootless.conf`, але відсутній.

### com.apple.rootless.install.heritable

> [!CAUTION]
> Entitlement **`com.apple.rootless.install.heritable`** дозволяє обійти SIP

#### [CVE-2019-8561](https://objective-see.org/blog/blog_0x42.html) <a href="#cve" id="cve"></a>

Було виявлено, що можна було **замінити пакет Installer після того, як система перевірила його code** signature, після чого система встановлювала шкідливий пакет замість оригінального. Оскільки ці дії виконувалися процесом **`system_installd`**, це дозволяло обійти SIP.<sup>[[2]](#references)</sup>

#### [CVE-2020–9854](https://objective-see.org/blog/blog_0x4D.html) <a href="#cve-unauthd-chain" id="cve-unauthd-chain"></a>

Якщо пакет встановлювався зі змонтованого образу або зовнішнього диска, **Installer** **виконував** binary із **цієї файлової системи** (замість розташування, захищеного SIP), змушуючи **`system_installd`** виконати довільний binary.<sup>[[3]](#references)</sup>

#### CVE-2021-30892 - Shrootless

[**Дослідники з цієї публікації в блозі**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) виявили вразливість у механізмі System Integrity Protection (SIP) macOS, названу вразливістю «Shrootless». Ця вразливість пов'язана з daemon **`system_installd`**, який має entitlement **`com.apple.rootless.install.heritable`**, що дозволяє будь-яким його дочірнім процесам обходити обмеження SIP для файлової системи.<sup>[[4]](#references)</sup>

Daemon **`system_installd`** встановлює пакети, підписані **Apple**.

Дослідники виявили, що під час встановлення пакета, підписаного Apple (файлу .pkg), **`system_installd`** **запускає** будь-які скрипти **post-install**, включені до пакета. Ці скрипти виконуються оболонкою за замовчуванням — **`zsh`**, яка автоматично **запускає** команди з файлу **`/etc/zshenv`**, якщо він існує, навіть у неінтерактивному режимі. Зловмисники могли скористатися цією поведінкою: створивши шкідливий файл `/etc/zshenv` і дочекавшись, поки **`system_installd` запустить `zsh`**, вони могли виконувати довільні операції на пристрої.<sup>[[4]](#references)</sup>

Крім того, було виявлено, що **`/etc/zshenv` можна використовувати як загальну attack technique**, а не лише для обходу SIP. Кожен профіль користувача має файл `~/.zshenv`, який поводиться так само, як `/etc/zshenv`, але не потребує root permissions. Цей файл можна використовувати як persistence mechanism, що спрацьовує щоразу під час запуску `zsh`, або як mechanism підвищення привілеїв. Якщо користувач-адміністратор підвищує привілеї до root за допомогою `sudo -s` або `sudo <command>`, файл `~/.zshenv` буде активовано, фактично підвищуючи привілеї до root.<sup>[[4]](#references)</sup>

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

У [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) було виявлено, що тим самим процесом **`system_installd`** усе ще можна було зловживати, оскільки він поміщав **post-install script у папку з випадковою назвою, захищену SIP, усередині `/tmp`**. Проблема полягала в тому, що сам **`/tmp` не захищений SIP**, тому на нього можна було **змонтувати** **віртуальний образ**, після чого **Installer** поміщав би туди **post-install script**, **відмонтовував** віртуальний образ, **повторно створював** усі **папки** та **додавав** **post-install** script із **payload** для виконання.<sup>[[5]](#references)</sup>

#### [fsck_cs utility](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)

Було виявлено вразливість, за якої **`fsck_cs`** вводили в оману, змушуючи пошкодити критично важливий файл через його здатність переходити за **symbolic links**. Зокрема, зловмисники створювали link з _`/dev/diskX`_ на файл `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist`. Запуск **`fsck_cs`** для _`/dev/diskX`_ призводив до пошкодження `Info.plist`. Цілісність цього файлу є критично важливою для SIP (System Integrity Protection) операційної системи, який контролює завантаження розширень ядра. Після пошкодження здатність SIP керувати виключеннями ядра порушується.<sup>[[6]](#references)</sup>

Команди для експлуатації цієї вразливості:
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
Експлуатація цієї вразливості має серйозні наслідки. Файл `Info.plist`, який зазвичай відповідає за керування дозволами для kernel extensions, стає неефективним. Це включає неможливість додавати до blacklist певні extensions, як-от `AppleHWAccess.kext`. Унаслідок цього, коли механізм контролю SIP виходить з ладу, цей extension можна завантажити, отримавши несанкціонований доступ на читання та запис до системної RAM.<sup>[[6]](#references)</sup>

#### [Mount поверх захищених SIP папок](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

Було можливо змонтувати нову файлову систему поверх **захищених SIP папок, щоб обійти захист**.<sup>[[1]](#references)</sup>
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Обхід Upgrader (2016)](https://objective-see.org/blog/blog_0x14.html)

Систему налаштовано на завантаження із вбудованого образу диска інсталятора в `Install macOS Sierra.app` для оновлення ОС за допомогою утиліти `bless`. Використовується така команда:<sup>[[7]](#references)</sup>
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
Безпеку цього процесу можна скомпрометувати, якщо зловмисник змінить образ оновлення (`InstallESD.dmg`) перед завантаженням. Стратегія передбачає заміну dynamic loader (dyld) на шкідливу версію (`libBaseIA.dylib`). Унаслідок цієї заміни код зловмисника виконується під час запуску інсталятора.<sup>[[7]](#references)</sup>

Код зловмисника отримує контроль під час процесу оновлення, використовуючи довіру системи до інсталятора. Атака здійснюється шляхом зміни образу `InstallESD.dmg` через method swizzling, зокрема із ціллю методу `extractBootBits`. Це дає змогу впровадити шкідливий код до того, як буде використано disk image.<sup>[[7]](#references)</sup>

Крім того, всередині `InstallESD.dmg` міститься `BaseSystem.dmg`, який є root file system для коду оновлення. Впровадження dynamic library у нього дає змогу шкідливому коду працювати в процесі, здатному змінювати файли на рівні ОС, що значно підвищує потенціал компрометації системи.<sup>[[7]](#references)</sup>

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

У цій доповіді на [**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk) показано, як **`systemmigrationd`** (який може обходити SIP) запускає **bash**- і **perl**-скрипти, якими можна зловживати через env variables **`BASH_ENV`** і **`PERL5OPT`**.<sup>[[8]](#references)</sup>

#### CVE-2023-42860 <a href="#cve-a-detailed-look" id="cve-a-detailed-look"></a>

Як [**детально описано в цій публікації блогу**](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts), дозволений пакетами `InstallAssistant.pkg` скрипт `postinstall` виконував:<sup>[[9]](#references)</sup>
```bash
/usr/bin/chflags -h norestricted "${SHARED_SUPPORT_PATH}/SharedSupport.dmg"
```
і можна було створити symlink у `${SHARED_SUPPORT_PATH}/SharedSupport.dmg`, що дозволяло користувачу **зняти обмеження з будь-якого файлу, обходячи захист SIP**.<sup>[[9]](#references)</sup>

### **com.apple.rootless.install**

> [!CAUTION]
> Entitlement **`com.apple.rootless.install`** дозволяє обходити SIP

Відомо, що entitlement `com.apple.rootless.install` дозволяє обходити System Integrity Protection (SIP) у macOS. Це було особливо згадано у зв’язку з [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/).<sup>[[10]](#references)</sup>

У цьому конкретному випадку системний XPC service, розташований у `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc`, має цей entitlement. Це дозволяє пов’язаному процесу обходити обмеження SIP. Крім того, цей service має метод, який дозволяє переміщувати файли без застосування будь-яких заходів безпеки.<sup>[[10]](#references)</sup>

## Герметизовані системні знімки

Герметизовані системні знімки — це функція, представлена Apple у **macOS Big Sur (macOS 11)** як частина механізму **System Integrity Protection (SIP)** для забезпечення додаткового рівня безпеки та стабільності системи. По суті, це версії системного тому, доступні лише для читання.

Ось детальніший огляд:

1. **Незмінна система**: герметизовані системні знімки роблять системний том macOS «незмінним», тобто його неможливо модифікувати. Це запобігає несанкціонованим або випадковим змінам системи, які можуть поставити під загрозу безпеку чи стабільність системи.
2. **Оновлення системного ПЗ**: коли ви встановлюєте оновлення або upgrade macOS, macOS створює новий системний знімок. Потім startup volume macOS використовує **APFS (Apple File System)** для перемикання на цей новий знімок. Увесь процес застосування оновлень стає безпечнішим і надійнішим, оскільки система завжди може повернутися до попереднього знімка, якщо під час оновлення щось піде не так.
3. **Розділення даних**: разом із концепцією розділення Data та System volume, представленою в macOS Catalina, функція герметизованих системних знімків гарантує, що всі ваші дані та налаштування зберігаються в окремому томі **«Data»**. Це розділення робить ваші дані незалежними від системи, що спрощує процес оновлення системи та підвищує її безпеку.

Пам’ятайте, що macOS керує цими знімками автоматично, і вони не займають додаткового місця на диску завдяки можливостям APFS щодо спільного використання простору. Також важливо зазначити, що ці знімки відрізняються від **знімків Time Machine**, які є доступними користувачу резервними копіями всієї системи.

### Перевірка знімків

Команда **`diskutil apfs list`** виводить **деталі APFS volumes** та їхню структуру:

<pre><code>+-- Container disk3 966B902E-EDBA-4775-B743-CF97A0556A13
|   ====================================================
|   APFS Container Reference:     disk3
|   Size (Capacity Ceiling):      494384795648 B (494.4 GB)
|   Capacity In Use By Volumes:   219214536704 B (219.2 GB) (44.3% used)
|   Capacity Not Allocated:       275170258944 B (275.2 GB) (55.7% free)
|   |
|   +-< Physical Store disk0s2 86D4B7EC-6FA5-4042-93A7-D3766A222EBE
|   |   -----------------------------------------------------------
|   |   APFS Physical Store Disk:   disk0s2
|   |   Size:                       494384795648 B (494.4 GB)
|   |
|   +-> Volume disk3s1 7A27E734-880F-4D91-A703-FB55861D49B7
|   |   ---------------------------------------------------
<strong>|   |   APFS Volume Disk (Role):   disk3s1 (System)
</strong>|   |   Name:                      Macintosh HD (Case-insensitive)
<strong>|   |   Mount Point:               /System/Volumes/Update/mnt1
</strong>|   |   Capacity Consumed:         12819210240 B (12.8 GB)
|   |   Sealed:                    Broken
|   |   FileVault:                 Yes (Unlocked)
|   |   Encrypted:                 No
|   |   |
|   |   Snapshot:                  FAA23E0C-791C-43FF-B0E7-0E1C0810AC61
|   |   Snapshot Disk:             disk3s1s1
<strong>|   |   Snapshot Mount Point:      /
</strong><strong>|   |   Snapshot Sealed:           Yes
</strong>[...]
+-> Volume disk3s5 281959B7-07A1-4940-BDDF-6419360F3327
|   ---------------------------------------------------
|   APFS Volume Disk (Role):   disk3s5 (Data)
|   Name:                      Macintosh HD - Data (Case-insensitive)
<strong>    |   Mount Point:               /System/Volumes/Data
</strong><strong>    |   Capacity Consumed:         412071784448 B (412.1 GB)
</strong>    |   Sealed:                    No
|   FileVault:                 Yes (Unlocked)
</code></pre>

У попередньому виводі видно, що **доступні користувачу розташування** змонтовані в `/System/Volumes/Data`.

Крім того, **знімок System volume macOS** змонтований у `/` і є **герметизованим** (криптографічно підписаним ОС). Тому, якщо SIP буде обійдено та цей том буде модифіковано, **ОС більше не завантажиться**.

Також можна **перевірити, що герметизацію ввімкнено**, виконавши:
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
Крім того, диск знімка також змонтовано в режимі **лише для читання**:
```bash
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
## Посилання

- [1] [SyScan360 - Stefan Esser - OS X El Capitan sinking the S\H/IP](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)
- [2] [CVE-2019-8561 - Блог Objective-See](https://objective-see.org/blog/blog_0x42.html)
- [3] [CVE-2020–9854: "Unauthd" (three) logic bugs ftw! - Блог Objective-See](https://objective-see.org/blog/blog_0x4D.html)
- [4] [Microsoft finds new macOS vulnerability, Shrootless, that could bypass System Integrity Protection](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [5] [Technical Analysis: CVE-2022-22583 - Perception Point](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)
- [6] [Apple's fruitless rootless security broken by code that fits in a tweet - The Register](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)
- [7] [\[0day\] Bypassing Apple's System Integrity Protection - Блог Objective-See](https://objective-see.org/blog/blog_0x14.html)
- [8] [DEF CON 31 - Getting a Migraine - Unique SIP Bypass on MacOS - Or, Pearse, Bohra](https://www.youtube.com/watch?v=zxZesAN-TEk)
- [9] [Apple Mitigates Vulnerabilities in Installer Scripts - Блог Kandji](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts)
- [10] [CVE-2022-26712: The POC for SIP-Bypass Is Even Tweetable](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/)

{{#include ../../../banners/hacktricks-training.md}}
