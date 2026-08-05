# macOS SIP

{{#include ../../../banners/hacktricks-training.md}}

## **Основна інформація**

**System Integrity Protection (SIP)** у macOS — це механізм, призначений для запобігання внесенню навіть найбільш привілейованими користувачами несанкціонованих змін до ключових системних папок. Ця функція відіграє важливу роль у забезпеченні цілісності системи, обмежуючи такі дії, як додавання, зміна або видалення файлів у захищених областях. Основні папки, захищені SIP:

- **/System**
- **/bin**
- **/sbin**
- **/usr**

Правила, що визначають поведінку SIP, задані у файлі конфігурації **`/System/Library/Sandbox/rootless.conf`**. У цьому файлі шляхи, перед якими стоїть зірочка (\*), позначаються як винятки із суворих обмежень SIP.

Розглянемо наведений нижче приклад:
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
Цей фрагмент означає, що хоча SIP зазвичай захищає каталог **`/usr`**, існують певні підкаталоги (`/usr/libexec/cups`, `/usr/local` і `/usr/share/man`), у яких дозволені зміни, що позначено зірочкою (\*) перед їхніми шляхами.

Щоб перевірити, чи захищені каталог або файл SIP, можна використати команду **`ls -lOd`** і перевірити наявність прапорця **`restricted`** або **`sunlnk`**. Наприклад:
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
У цьому випадку прапорець **`sunlnk`** означає, що сам каталог `/usr/libexec/cups` **не можна видалити**, хоча файли всередині нього можна створювати, змінювати або видаляти.

З іншого боку:
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
Тут прапорець **`restricted`** вказує, що каталог `/usr/libexec` захищений SIP. У каталозі, захищеному SIP, файли не можна створювати, змінювати або видаляти.

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

### Стан SIP

Перевірити, чи ввімкнено SIP у вашій системі, можна за допомогою такої команди:
```bash
csrutil status
```
Якщо потрібно вимкнути SIP, перезавантажте комп’ютер у режим відновлення (натиснувши Command+R під час запуску), а потім виконайте наведену нижче команду:
```bash
csrutil disable
```
Якщо ви хочете залишити SIP увімкненим, але вимкнути захист від налагодження, це можна зробити так:
```bash
csrutil enable --without debug
```
### Інші обмеження

- **Забороняє завантаження непідписаних kernel extensions** (kexts), гарантуючи, що із системним kernel взаємодіють лише перевірені extensions.
- **Перешкоджає debugging** системних процесів macOS, захищаючи основні компоненти системи від несанкціонованого доступу та модифікації.
- **Блокує інструменти**, як-от dtrace, від перевірки системних процесів, додатково захищаючи цілісність роботи системи.

[**Дізнайтеся більше про SIP у цій доповіді**](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)**.**<sup>[1]</sup>

### **Entitlements, пов’язані із SIP**

- `com.apple.rootless.xpc.bootstrap`: Контроль launchd
- `com.apple.rootless.install[.heritable]`: Доступ до file system
- `com.apple.rootless.kext-management`: `kext_request`
- `com.apple.rootless.datavault.controller`: Керування UF_DATAVAULT
- `com.apple.rootless.xpc.bootstrap`: Можливості налаштування XPC
- `com.apple.rootless.xpc.effective-root`: Root через launchd XPC
- `com.apple.rootless.restricted-block-devices`: Доступ до raw block devices
- `com.apple.rootless.internal.installer-equivalent`: Необмежений доступ до file system
- `com.apple.rootless.restricted-nvram-variables[.heritable]`: Повний доступ до NVRAM
- `com.apple.rootless.storage.label`: Модифікація файлів, обмежених xattr com.apple.rootless із відповідною міткою
- `com.apple.rootless.volume.VM.label`: Підтримка VM swap на volume

## Обхід SIP

Обхід SIP дає зловмиснику змогу:

- **Отримувати доступ до даних користувачів**: Читати конфіденційні дані користувачів, як-от пошту, повідомлення та історію Safari, з усіх облікових записів користувачів.
- **Обхід TCC**: Безпосередньо маніпулювати базою даних TCC (Transparency, Consent, and Control), щоб надати несанкціонований доступ до webcam, microphone та інших ресурсів.
- **Встановлювати persistence**: Розміщувати malware у захищених SIP місцях, ускладнюючи його видалення навіть із root privileges. Це також включає можливість втручання в Malware Removal Tool (MRT).
- **Завантажувати Kernel Extensions**: Хоча існують додаткові заходи захисту, обхід SIP спрощує процес завантаження непідписаних kernel extensions.

### Installer Packages

**Installer packages, підписані сертифікатом Apple,** можуть обходити його захист. Це означає, що навіть packages, підписані стандартними developers, буде заблоковано, якщо вони спробують змінити каталоги, захищені SIP.

### Неіснуючий SIP-файл

Однією з потенційних лазівок є ситуація, коли файл указано в **`rootless.conf`, але наразі він не існує**: тоді його можна створити. Malware може скористатися цим для **встановлення persistence** у системі. Наприклад, malicious program може створити .plist-файл у `/System/Library/LaunchDaemons`, якщо його вказано в `rootless.conf`, але він відсутній.

### com.apple.rootless.install.heritable

> [!CAUTION]
> Entitlement **`com.apple.rootless.install.heritable`** дозволяє обійти SIP

#### [CVE-2019-8561](https://objective-see.org/blog/blog_0x42.html) <a href="#cve" id="cve"></a>

Було виявлено, що installer package можна було **підмінити після того, як система перевірила його code** signature, після чого система встановлювала malicious package замість оригінального. Оскільки ці дії виконувалися процесом **`system_installd`**, це дозволяло обійти SIP.<sup>[2]</sup>

#### [CVE-2020–9854](https://objective-see.org/blog/blog_0x4D.html) <a href="#cve-unauthd-chain" id="cve-unauthd-chain"></a>

Якщо package встановлювався із mounted image або external drive, **installer** **виконував** binary із **цієї file system** (замість SIP-protected location), змушуючи **`system_installd`** виконати довільний binary.<sup>[3]</sup>

#### CVE-2021-30892 - Shrootless

[**Дослідники з цієї публікації**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) виявили вразливість у механізмі System Integrity Protection (SIP) macOS, названу вразливістю «Shrootless». Ця вразливість пов’язана з daemon **`system_installd`**, який має entitlement **`com.apple.rootless.install.heritable`**, що дозволяє будь-яким його child processes обходити обмеження SIP для file system.<sup>[4]</sup>

Daemon **`system_installd`** встановлює packages, підписані **Apple**.

Дослідники виявили, що під час встановлення package, підписаного Apple (.pkg-файлу), **`system_installd`** **запускає** будь-які **post-install** scripts, включені до package. Ці scripts виконуються default shell — **`zsh`**, який автоматично **запускає** команди з файлу **`/etc/zshenv`**, якщо він існує, навіть у non-interactive mode. Цю поведінку могли експлуатувати attackers: створивши malicious файл `/etc/zshenv` і дочекавшись, поки **`system_installd` викличе `zsh`**, вони могли виконувати довільні операції на пристрої.<sup>[4]</sup>

Крім того, було виявлено, що **`/etc/zshenv` можна використовувати як загальну attack technique**, а не лише для обходу SIP. Кожен user profile має файл `~/.zshenv`, який працює так само, як `/etc/zshenv`, але не потребує root permissions. Цей файл можна використовувати як persistence mechanism, що спрацьовує щоразу під час запуску `zsh`, або як mechanism privilege escalation. Якщо admin user підвищує привілеї до root за допомогою `sudo -s` або `sudo <command>`, файл `~/.zshenv` буде активовано, фактично підвищивши привілеї до root.<sup>[4]</sup>

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

У [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) було виявлено, що той самий процес **`system_installd`** усе ще можна було використати, оскільки він розміщував **post-install script у папці з випадковою назвою, захищеній SIP, усередині `/tmp`**. Проблема полягала в тому, що сам **`/tmp` не захищений SIP**, тому на нього можна було **змонтувати** **virtual image**, після чого **installer** розміщував би там **post-install script**, **розмонтовував** virtual image, **повторно створював** усі **папки** та **додавав** **post-install** script із **payload** для виконання.<sup>[5]</sup>

#### [fsck_cs utility](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)

Було виявлено вразливість, за якої **`fsck_cs`** вводили в оману, що призводило до пошкодження важливого файлу через його здатність переходити за **symbolic links**. Зокрема, attackers створювали link із _`/dev/diskX`_ на файл `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist`. Запуск **`fsck_cs`** для _`/dev/diskX`_ призводив до пошкодження `Info.plist`. Цілісність цього файлу критично важлива для SIP (System Integrity Protection) операційної системи, який контролює завантаження kernel extensions. Після пошкодження здатність SIP керувати kernel exclusions була скомпрометована.<sup>[6]</sup>

Команди для експлуатації цієї вразливості:
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
Експлуатація цієї вразливості має серйозні наслідки. Файл `Info.plist`, який зазвичай відповідає за керування дозволами для kernel extensions, стає неефективним. Це також унеможливлює внесення певних extensions до чорного списку, зокрема `AppleHWAccess.kext`. У результаті, коли механізм керування SIP виходить з ладу, цей extension можна завантажити, отримавши несанкціонований доступ на читання та запис до системної RAM.<sup>[6]</sup>

#### [Монтування поверх захищених SIP папок](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

Було можливо змонтувати нову файлову систему поверх **захищених SIP папок, щоб обійти захист**.<sup>[1]</sup>
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Upgrader bypass (2016)](https://objective-see.org/blog/blog_0x14.html)

Систему налаштовано на завантаження із вбудованого образу диска інсталятора в `Install macOS Sierra.app` для оновлення ОС із використанням утиліти `bless`. Використовується така команда:<sup>[7]</sup>
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
Безпеку цього процесу можна порушити, якщо зловмисник змінить образ оновлення (`InstallESD.dmg`) перед завантаженням. Стратегія передбачає заміну dynamic loader (dyld) на шкідливу версію (`libBaseIA.dylib`). Унаслідок цієї заміни код зловмисника виконується під час запуску інсталятора.<sup>[7]</sup>

Код зловмисника отримує контроль під час процесу оновлення, використовуючи довіру системи до інсталятора. Атака здійснюється шляхом зміни образу `InstallESD.dmg` через method swizzling, зокрема із застосуванням методу `extractBootBits`. Це дає змогу впровадити шкідливий код до використання образу диска.<sup>[7]</sup>

Крім того, всередині `InstallESD.dmg` міститься `BaseSystem.dmg`, який є кореневою файловою системою коду оновлення. Впровадження dynamic library у цей образ дає змогу шкідливому коду працювати в процесі, здатному змінювати файли на рівні ОС, що значно підвищує потенціал компрометації системи.<sup>[7]</sup>

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

У цій доповіді з [**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk) показано, як **`systemmigrationd`** (який може обходити SIP) виконує скрипти **bash** і **perl**, що можна використати через змінні середовища **`BASH_ENV`** і **`PERL5OPT`**.<sup>[8]</sup>

#### CVE-2023-42860 <a href="#cve-a-detailed-look" id="cve-a-detailed-look"></a>

Як [**детально описано в цьому дописі в блозі**](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts), скрипт `postinstall` із пакетів `InstallAssistant.pkg` дозволяв виконання:<sup>[9]</sup>
```bash
/usr/bin/chflags -h norestricted "${SHARED_SUPPORT_PATH}/SharedSupport.dmg"
```
і можна було створити symlink у `${SHARED_SUPPORT_PATH}/SharedSupport.dmg`, що дозволило б користувачу **зняти обмеження з будь-якого файлу, обійшовши захист SIP**.<sup>[9]</sup>

### **com.apple.rootless.install**

> [!CAUTION]
> Entitlement **`com.apple.rootless.install`** дозволяє обійти SIP

Відомо, що entitlement `com.apple.rootless.install` дозволяє обійти System Integrity Protection (SIP) у macOS. Це було зокрема згадано у зв’язку з [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/).<sup>[10]</sup>

У цьому конкретному випадку системний XPC service, розташований за адресою `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc`, має цей entitlement. Це дозволяє пов’язаному процесу обходити обмеження SIP. Крім того, цей service містить method, який дозволяє переміщувати файли без застосування будь-яких заходів безпеки.<sup>[10]</sup>

## Sealed System Snapshots

Sealed System Snapshots — це функція, представлена Apple у **macOS Big Sur (macOS 11)** як частина механізму **System Integrity Protection (SIP)** для забезпечення додаткового рівня безпеки та стабільності системи. По суті, це версії системного тому, доступні лише для читання.

Докладніше:

1. **Незмінна система**: Sealed System Snapshots роблять системний том macOS «незмінним», тобто його неможливо модифікувати. Це запобігає несанкціонованим або випадковим змінам системи, які можуть поставити під загрозу безпеку чи стабільність системи.
2. **Оновлення системного програмного забезпечення**: коли ви встановлюєте оновлення або нові версії macOS, macOS створює новий snapshot системи. Після цього startup volume macOS використовує **APFS (Apple File System)** для перемикання на цей новий snapshot. Увесь процес застосування оновлень стає безпечнішим і надійнішим, оскільки система завжди може повернутися до попереднього snapshot, якщо під час оновлення щось піде не так.
3. **Розділення даних**: разом із концепцією розділення Data та System volume, представленою в macOS Catalina, функція Sealed System Snapshot забезпечує зберігання всіх ваших даних і налаштувань на окремому томі "**Data**". Це розділення робить ваші дані незалежними від системи, спрощує процес оновлення системи та підвищує її безпеку.

Пам’ятайте, що macOS автоматично керує цими snapshot і вони не займають додаткового місця на диску завдяки можливостям APFS зі спільного використання простору. Також важливо зазначити, що ці snapshot відрізняються від **Time Machine snapshots**, які є доступними користувачу резервними копіями всієї системи.

### Перевірка Snapshots

Команда **`diskutil apfs list`** виводить **деталі томів APFS** та їхню структуру:

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
|   Encrypted:                 No
</code></pre>

У попередньому виводі видно, що **доступні користувачу розташування** змонтовані в `/System/Volumes/Data`.

Крім того, **snapshot системного тому macOS** змонтований у `/` і є **sealed** (криптографічно підписаний операційною системою). Отже, якщо SIP буде обійдено й цей snapshot буде змінено, **ОС більше не завантажиться**.

Також можна **перевірити, що seal увімкнено**, виконавши:
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
Крім того, диск snapshot також змонтовано як **доступний лише для читання**:
```bash
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
## Посилання

- [1] [SyScan360 - Stefan Esser - OS X El Capitan топить S\H/IP](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)
- [2] [CVE-2019-8561 - Блог Objective-See](https://objective-see.org/blog/blog_0x42.html)
- [3] [CVE-2020–9854: "Unauthd" (три) логічні помилки ftw! - Блог Objective-See](https://objective-see.org/blog/blog_0x4D.html)
- [4] [Microsoft виявила нову вразливість macOS — Shrootless, яка може обійти System Integrity Protection](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [5] [Технічний аналіз: CVE-2022-22583 - Perception Point](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)
- [6] [Безпека Apple fruitless rootless зламана кодом, який вміщується в одному твіті - The Register](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)
- [7] [\[0day\] Обхід Apple's System Integrity Protection - Блог Objective-See](https://objective-see.org/blog/blog_0x14.html)
- [8] [DEF CON 31 - Getting a Migraine - Унікальний SIP Bypass на MacOS - Or, Pearse, Bohra](https://www.youtube.com/watch?v=zxZesAN-TEk)
- [9] [Apple усуває вразливості в Installer Scripts - Блог Kandji](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts)
- [10] [CVE-2022-26712: POC для SIP-Bypass також можна вмістити в один твіт](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/)

{{#include ../../../banners/hacktricks-training.md}}
