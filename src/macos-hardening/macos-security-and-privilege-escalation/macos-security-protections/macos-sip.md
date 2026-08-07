# macOS SIP

{{#include ../../../banners/hacktricks-training.md}}

## **Основна інформація**

**System Integrity Protection (SIP)** у macOS — це механізм, призначений для запобігання внесенню навіть найбільш привілейованими користувачами несанкціонованих змін до ключових системних папок. Ця функція відіграє важливу роль у підтриманні цілісності системи, обмежуючи такі дії, як додавання, зміна або видалення файлів у захищених областях. Основні папки, захищені SIP:

- **/System**
- **/bin**
- **/sbin**
- **/usr**

Правила, що визначають поведінку SIP, містяться у файлі конфігурації **`/System/Library/Sandbox/rootless.conf`**. У цьому файлі шляхи, перед якими стоїть зірочка (\*), позначені як винятки із загалом суворих обмежень SIP.

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
У цьому випадку прапорець **`sunlnk`** означає, що сам каталог `/usr/libexec/cups` **не можна видалити**, хоча файли всередині нього можна створювати, змінювати або видаляти.

З іншого боку:
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
Тут прапорець **`restricted`** вказує, що каталог `/usr/libexec` захищений SIP. У каталозі, захищеному SIP, неможливо створювати, змінювати або видаляти файли.

Крім того, якщо файл містить розширений **атрибут** **`com.apple.rootless`**, цей файл також буде **захищений SIP**.

> [!TIP]
> Зверніть увагу, що hook **`hook_vnode_check_setextattr`** у **Sandbox** запобігає будь-якій спробі змінити розширений атрибут **`com.apple.rootless`.**

**SIP також обмежує інші дії root**, зокрема:

- Завантаження ненадійних kernel extensions
- Отримання task-портів для процесів, підписаних Apple
- Зміну змінних NVRAM
- Дозвіл на kernel debugging

Параметри зберігаються у змінній nvram як bitflag (`csr-active-config` на Intel, а `lp-sip0` зчитується із завантаженого Device Tree на ARM). Прапорці можна знайти у вихідному коді XNU в `csr.sh`:

<figure><img src="../../../images/image (1192).png" alt=""><figcaption></figcaption></figure>

### Стан SIP

Перевірити, чи ввімкнено SIP у вашій системі, можна за допомогою такої команди:
```bash
csrutil status
```
Якщо потрібно вимкнути SIP, перезавантажте комп’ютер у режимі відновлення (натиснувши Command+R під час запуску), а потім виконайте наведену нижче команду:
```bash
csrutil disable
```
Якщо ви хочете залишити SIP увімкненим, але вимкнути захист від налагодження, це можна зробити за допомогою:
```bash
csrutil enable --without debug
```
### Інші обмеження

- **Забороняє завантаження непідписаних kernel extensions** (kexts), гарантуючи, що із системним kernel взаємодіють лише перевірені extensions.
- **Запобігає debugging** системних процесів macOS, захищаючи основні компоненти системи від несанкціонованого доступу та модифікації.
- **Перешкоджає tools** на кшталт dtrace перевіряти системні процеси, додатково захищаючи цілісність роботи системи.

[**Дізнатися більше про SIP можна в цьому виступі**](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)**.**<sup>[[1]](#references)</sup>

### **Entitlements, пов'язані із SIP**

- `com.apple.rootless.xpc.bootstrap`: Керування launchd
- `com.apple.rootless.install[.heritable]`: Доступ до файлової системи
- `com.apple.rootless.kext-management`: `kext_request`
- `com.apple.rootless.datavault.controller`: Керування UF_DATAVAULT
- `com.apple.rootless.xpc.bootstrap`: Можливості налаштування XPC
- `com.apple.rootless.xpc.effective-root`: Root через launchd XPC
- `com.apple.rootless.restricted-block-devices`: Доступ до необроблених block devices
- `com.apple.rootless.internal.installer-equivalent`: Необмежений доступ до файлової системи
- `com.apple.rootless.restricted-nvram-variables[.heritable]`: Повний доступ до NVRAM
- `com.apple.rootless.storage.label`: Модифікація файлів, обмежених xattr `com.apple.rootless` із відповідним label
- `com.apple.rootless.volume.VM.label`: Підтримка VM swap на томі

## Обходи SIP

Обхід SIP дає attacker змогу:

- **Отримувати доступ до даних користувачів**: Читати конфіденційні дані користувачів, як-от пошту, повідомлення та історію Safari з усіх облікових записів користувачів.
- **TCC Bypass**: Безпосередньо маніпулювати базою даних TCC (Transparency, Consent, and Control), щоб надати несанкціонований доступ до вебкамери, мікрофона та інших ресурсів.
- **Забезпечувати Persistence**: Розміщувати malware у захищених SIP місцях, ускладнюючи його видалення навіть із root privileges. Це також включає можливість втручання в Malware Removal Tool (MRT).
- **Завантажувати Kernel Extensions**: Хоча існують додаткові засоби захисту, обхід SIP спрощує процес завантаження непідписаних kernel extensions.

### Пакети встановлення

**Пакети встановлення, підписані сертифікатом Apple**, можуть обходити його захист. Це означає, що навіть пакети, підписані стандартними developers, будуть заблоковані, якщо вони намагаються змінити захищені SIP директорії.

### Неіснуючий SIP файл

Однією з потенційних лазівок є ситуація, коли файл указано в **`rootless.conf`**, але наразі він не існує: тоді його можна створити. Malware може скористатися цим для **забезпечення persistence** у системі. Наприклад, malicious program може створити файл .plist у `/System/Library/LaunchDaemons`, якщо його вказано в `rootless.conf`, але самого файлу немає.

### com.apple.rootless.install.heritable

> [!CAUTION]
> Entitlement **`com.apple.rootless.install.heritable`** дозволяє обходити SIP

#### [CVE-2019-8561](https://objective-see.org/blog/blog_0x42.html) <a href="#cve" id="cve"></a>

Було виявлено, що після того, як система перевіряла **code** signature пакета встановлення, його можна було **підмінити**, після чого система встановлювала malicious package замість оригінального. Оскільки ці дії виконувалися через **`system_installd`**, це дозволяло обійти SIP.<sup>[[2]](#references)</sup>

#### [CVE-2020–9854](https://objective-see.org/blog/blog_0x4D.html) <a href="#cve-unauthd-chain" id="cve-unauthd-chain"></a>

Якщо пакет встановлювався із змонтованого image або external drive, **installer** **виконував** binary із **цієї файлової системи** (а не із захищеного SIP місця), що змушувало **`system_installd`** виконувати довільний binary.<sup>[[3]](#references)</sup>

#### CVE-2021-30892 - Shrootless

[**Дослідники з цього blog post**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) виявили вразливість у механізмі System Integrity Protection (SIP) macOS, названу вразливістю «Shrootless». Ця вразливість пов'язана з daemon **`system_installd`**, який має entitlement **`com.apple.rootless.install.heritable`**, що дозволяє будь-яким його child processes обходити обмеження файлової системи SIP.<sup>[[4]](#references)</sup>

Daemon **`system_installd`** встановлює пакети, підписані **Apple**.

Дослідники встановили, що під час встановлення пакета, підписаного Apple (файлу .pkg), **`system_installd`** **запускає** будь-які **post-install** scripts, що входять до пакета. Ці scripts виконуються default shell, **`zsh`**, який автоматично **запускає** commands із файлу **`/etc/zshenv`**, якщо він існує, навіть у non-interactive mode. Attackers могли експлуатувати цю поведінку: створивши malicious файл `/etc/zshenv` і дочекавшись, коли **`system_installd` викличе `zsh`**, вони могли виконувати довільні операції на пристрої.<sup>[[4]](#references)</sup>

Крім того, було виявлено, що **`/etc/zshenv` можна використовувати як загальну attack technique**, а не лише для обходу SIP. Кожен user profile має файл `~/.zshenv`, який працює так само, як `/etc/zshenv`, але не потребує root permissions. Цей файл можна використовувати як persistence mechanism, що спрацьовує щоразу під час запуску `zsh`, або як mechanism elevation of privilege. Якщо admin user підвищує privileges до root за допомогою `sudo -s` або `sudo <command>`, файл `~/.zshenv` буде активовано, фактично підвищуючи privileges до root.<sup>[[4]](#references)</sup>

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

У [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) було виявлено, що тим самим процесом **`system_installd`** усе ще можна було зловживати, оскільки він поміщав **post-install script у папку з випадковою назвою, захищену SIP, усередині `/tmp`**. Проблема полягала в тому, що сам `/tmp` не захищений SIP, тому на нього можна було **змонтувати** **virtual image**, після чого **installer** поміщав би туди **post-install script**, **відмонтовував** virtual image, **повторно створював** усі **папки** та **додавав** **post-install** script із **payload** для виконання.<sup>[[5]](#references)</sup>

#### [fsck_cs utility](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)

Було виявлено вразливість, через яку **`fsck_cs`** можна було змусити пошкодити важливий файл, оскільки ця utility могла переходити за **symbolic links**. Зокрема, attackers створювали link із _`/dev/diskX`_ на файл `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist`. Виконання **`fsck_cs`** для _`/dev/diskX`_ призводило до пошкодження `Info.plist`. Цілісність цього файлу є критично важливою для SIP (System Integrity Protection) операційної системи, оскільки SIP контролює завантаження kernel extensions. Після пошкодження здатність SIP керувати виключеннями kernel стає скомпрометованою.<sup>[[6]](#references)</sup>

Команди для експлуатації цієї вразливості:
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
Експлуатація цієї вразливості має серйозні наслідки. Файл `Info.plist`, який зазвичай відповідає за керування дозволами для kernel extensions, стає неефективним. Це включає неможливість додавати певні extensions, як-от `AppleHWAccess.kext`, до blacklist. Отже, коли механізм контролю SIP виходить з ладу, цей extension можна завантажити, отримавши несанкціонований доступ на читання та запис до системної RAM.<sup>[[6]](#references)</sup>

#### [Монтування поверх захищених SIP папок](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

Було можливо змонтувати нову файлову систему поверх **захищених SIP папок, щоб обійти захист**.<sup>[[1]](#references)</sup>
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Upgrader bypass (2016)](https://objective-see.org/blog/blog_0x14.html)

Систему налаштовано на завантаження із вбудованого образу диска інсталятора в `Install macOS Sierra.app` для оновлення ОС за допомогою утиліти `bless`. Використовується така команда:<sup>[[7]](#references)</sup>
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
Безпеку цього процесу можна скомпрометувати, якщо attacker змінить upgrade image (`InstallESD.dmg`) перед завантаженням. Стратегія передбачає заміну dynamic loader (dyld) на malicious version (`libBaseIA.dylib`). У результаті цієї заміни код attacker виконується під час запуску installer.<sup>[[7]](#references)</sup>

Код attacker отримує контроль під час процесу upgrade, використовуючи довіру системи до installer. Атака виконується шляхом зміни image `InstallESD.dmg` через method swizzling, зокрема з націлюванням на метод `extractBootBits`. Це дозволяє інжектити malicious code до того, як disk image буде використано.<sup>[[7]](#references)</sup>

Крім того, всередині `InstallESD.dmg` міститься `BaseSystem.dmg`, який слугує root file system для upgrade code. Інжектування dynamic library до нього дозволяє malicious code працювати всередині процесу, здатного змінювати файли на рівні OS, що значно підвищує потенціал компрометації системи.<sup>[[7]](#references)</sup>

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

У цій доповіді з [**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk) показано, як **`systemmigrationd`** (який може обходити SIP) виконує **bash** і **perl** scripts, якими можна зловживати через env variables **`BASH_ENV`** і **`PERL5OPT`**.<sup>[[8]](#references)</sup>

#### CVE-2023-42860 <a href="#cve-a-detailed-look" id="cve-a-detailed-look"></a>

Як [**детально описано в цьому blog post**](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts), `postinstall` script із пакетів `InstallAssistant.pkg` дозволяв виконання:<sup>[[9]](#references)</sup>
```bash
/usr/bin/chflags -h norestricted "${SHARED_SUPPORT_PATH}/SharedSupport.dmg"
```
і можна було створити symlink у `${SHARED_SUPPORT_PATH}/SharedSupport.dmg`, що дозволяло користувачу **unrestrict будь-який файл, обходячи захист SIP**.<sup>[[9]](#references)</sup>

### **com.apple.rootless.install**

> [!CAUTION]
> Entitlement **`com.apple.rootless.install`** дозволяє обійти SIP

Відомо, що entitlement `com.apple.rootless.install` дозволяє обійти System Integrity Protection (SIP) у macOS. Про це, зокрема, згадувалося у зв'язку з [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/).<sup>[[10]](#references)</sup>

У цьому конкретному випадку системний XPC service, розташований за адресою `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc`, має цей entitlement. Це дозволяє пов'язаному процесу обходити обмеження SIP. Крім того, цей service містить метод, який дозволяє переміщувати файли без застосування будь-яких заходів безпеки.<sup>[[10]](#references)</sup>

## Sealed System Snapshots

Sealed System Snapshots — це функція, представлена Apple у **macOS Big Sur (macOS 11)** як частина механізму **System Integrity Protection (SIP)** для забезпечення додаткового рівня безпеки та стабільності системи. По суті, це версії системного тому, доступні лише для читання.

Розглянемо це докладніше:

1. **Незмінна система**: Sealed System Snapshots роблять системний том macOS «незмінним», тобто його не можна модифікувати. Це запобігає несанкціонованим або випадковим змінам системи, які можуть поставити під загрозу безпеку чи стабільність системи.
2. **Оновлення системного програмного забезпечення**: Коли ви встановлюєте оновлення або upgrade macOS, macOS створює новий system snapshot. Потім startup volume macOS використовує **APFS (Apple File System)** для перемикання на цей новий snapshot. Увесь процес застосування оновлень стає безпечнішим і надійнішим, оскільки система завжди може повернутися до попереднього snapshot, якщо під час оновлення щось піде не так.
3. **Розділення даних**: У поєднанні з концепцією розділення Data та System volume, представленою в macOS Catalina, функція Sealed System Snapshot гарантує, що всі ваші дані й налаштування зберігаються на окремому томі "**Data**". Це розділення робить ваші дані незалежними від системи, спрощує процес оновлення системи та підвищує її безпеку.

Пам'ятайте, що macOS керує цими snapshot автоматично, і вони не займають додаткового місця на диску завдяки можливостям APFS зі спільного використання простору. Також важливо зазначити, що ці snapshot відрізняються від **Time Machine snapshots**, які є доступними користувачу backup-копіями всієї системи.

### Перевірка snapshot

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
</code></pre>

У попередньому виводі видно, що **доступні користувачу locations** змонтовані в `/System/Volumes/Data`.

Крім того, **snapshot системного тому macOS** змонтований у `/` і є **sealed** (криптографічно підписаний операційною системою). Отже, якщо SIP буде обійдено й цей snapshot модифіковано, **ОС більше не завантажиться**.

Також можна **перевірити, що seal увімкнено**, виконавши:
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
Крім того, snapshot-диск також змонтовано в режимі **лише для читання**:
```bash
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
## Посилання

- [1] [SyScan360 - Stefan Esser - OS X El Capitan sinking the S\H/IP](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)
- [2] [CVE-2019-8561 - Блог Objective-See](https://objective-see.org/blog/blog_0x42.html)
- [3] [CVE-2020–9854: "Unauthd" (three) logic bugs ftw! - Блог Objective-See](https://objective-see.org/blog/blog_0x4D.html)
- [4] [Microsoft знаходить нову вразливість macOS, Shrootless, яка може обійти System Integrity Protection](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [5] [Технічний аналіз: CVE-2022-22583 - Perception Point](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)
- [6] [Безпековий захист Apple fruitless rootless зламано кодом, який вміщується в одному твіті - The Register](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)
- [7] [\[0day\] Обхід Apple's System Integrity Protection - Блог Objective-See](https://objective-see.org/blog/blog_0x14.html)
- [8] [DEF CON 31 - Getting a Migraine - Унікальний SIP Bypass на MacOS - Or, Pearse, Bohra](https://www.youtube.com/watch?v=zxZesAN-TEk)
- [9] [Apple усуває вразливості в Installer Scripts - Блог Kandji](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts)
- [10] [CVE-2022-26712: POC для SIP-Bypass тепер можна навіть опублікувати у твіті](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/)

{{#include ../../../banners/hacktricks-training.md}}
