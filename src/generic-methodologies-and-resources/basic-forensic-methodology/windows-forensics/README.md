# Артефакти Windows

{{#include ../../../banners/hacktricks-training.md}}

## Загальні артефакти Windows

### Сповіщення Windows 10

За шляхом `\Users\<username>\AppData\Local\Microsoft\Windows\Notifications` можна знайти базу даних `appdb.dat` (до Windows anniversary) або `wpndatabase.db` (після Windows Anniversary).

У цій базі даних SQLite можна знайти таблицю `Notification` з усіма сповіщеннями (у форматі XML), які можуть містити цікаві дані.

### Timeline

Timeline — це характеристика Windows, яка надає **хронологію** відвіданих вебсторінок, відредагованих документів і запущених застосунків.

База даних розташована за шляхом `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Цю базу даних можна відкрити за допомогою інструмента SQLite або інструмента [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd), **який генерує 2 файли, що можна відкрити за допомогою інструмента** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md).

### ADS (Alternate Data Streams)

Завантажені файли можуть містити **ADS Zone.Identifier**, що вказує, **як** їх було **завантажено** з інтрамережі, інтернету тощо. Деяке програмне забезпечення (наприклад, браузери) зазвичай додає ще **більше** **інформації**, як-от **URL**, з якого було завантажено файл.

## **Резервні копії файлів**

### Кошик

У Vista/Win7/Win8/Win10 **Кошик** можна знайти в папці **`$Recycle.bin`** у корені диска (`C:\$Recycle.bin`).\
Коли файл видаляється в цій папці, створюються 2 спеціальні файли:

- `$I{id}`: Інформація про файл (дата його видалення}
- `$R{id}`: Вміст файлу

![Резервні копії файлів — Кошик: $R{id}: Вміст файлу](<../../../images/image (1029).png>)

Маючи ці файли, можна використати інструмент [**Rifiuti**](https://github.com/abelcheung/rifiuti2), щоб отримати початкову адресу видалених файлів і дату їх видалення (для Vista – Win10 використовуйте `rifiuti-vista.exe`).
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![Резервні копії файлів - Кошик: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Тіньові копії томів

Shadow Copy - це технологія, включена до Microsoft Windows, яка може створювати **резервні копії** або знімки комп'ютерних файлів чи томів, навіть коли вони використовуються.

Ці резервні копії зазвичай розташовані в `\System Volume Information` у корені файлової системи, а їхні назви складаються з **UID**, показаних на наступному зображенні:

![Кошик - Тіньові копії томів: ці резервні копії зазвичай розташовані в System Volume Information у корені файлової системи, а їхні назви складаються з UID, показаних на...](<../../../images/image (94).png>)

Після монтування forensic-образу за допомогою **ArsenalImageMounter** інструмент [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) можна використовувати для перегляду тіньової копії та навіть **видобування файлів** із резервних копій тіньової копії.

![Кошик - Тіньові копії томів: після монтування forensic-образу за допомогою ArsenalImageMounter інструмент ShadowCopyView можна використовувати для перегляду тіньової копії та навіть видобування файлів...](<../../../images/image (576).png>)

Розділ реєстру `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` містить файли та ключі, **які не потрібно копіювати**:

![Кошик - Тіньові копії томів: розділ реєстру HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore містить файли та ключі, які не потрібно копіювати](<../../../images/image (254).png>)

Реєстр `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` також містить інформацію про конфігурацію `Volume Shadow Copies`.

### Автоматично збережені файли Office

Автоматично збережені файли Office можна знайти в: `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Елементи Shell

Елемент Shell - це елемент, який містить інформацію про спосіб доступу до іншого файлу.

### Останні документи (LNK)

Windows **автоматично** **створює** ці **ярлики**, коли користувач **відкриває, використовує або створює файл** у:

- Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
- Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

Коли створюється папка, також створюється посилання на папку, батьківську папку та папку на два рівні вище.

Ці автоматично створені файли посилань **містять інформацію про походження**, наприклад, чи є це **файл** **чи** **папка**, **часові позначки** **MAC** цього файлу, **інформацію про том**, де зберігається файл, і **папку цільового файлу**. Ця інформація може бути корисною для відновлення цих файлів, якщо їх було видалено.

Крім того, **дата створення файлу посилання** - це перший **момент**, коли оригінальний файл був **вперше** **використаний**, а **дата** **модифікації** файлу посилання - це останній **момент**, коли використовувався вихідний файл.

Для перегляду цих файлів можна використовувати [**LinkParser**](http://4discovery.com/our-tools/).

У цьому інструменті ви знайдете **2 набори** часових позначок:

- **Перший набір:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **Другий набір:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

Перший набір часових позначок посилається на **часові позначки самого файлу**. Другий набір посилається на **часові позначки пов'язаного файлу**.

Ви можете отримати ту саму інформацію, запустивши інструмент Windows CLI: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd)
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
У цьому випадку інформацію буде збережено у CSV-файлі.

### Jumplists

Це нещодавні файли, указані для кожної програми. Це список **нещодавніх файлів, використаних програмою**, до якого можна отримати доступ у кожній програмі. Вони можуть створюватися **автоматично або вручну**.

**Jumplists**, створені автоматично, зберігаються в `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`. Jumplists мають формат імені `{id}.autmaticDestinations-ms`, де початковий ID є ID програми.

Власні jumplists зберігаються в `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\`, і зазвичай вони створюються програмою через те, що з файлом сталася **важлива подія** (можливо, його позначено як вибране).

**Час створення** будь-якого jumplist указує на **перший момент доступу до файлу**, а **час зміни — на останній**.

Ви можете перевірити jumplists за допомогою [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).

![Recent Documents (LNK) - Jumplists: You can inspect the jumplists using JumplistExplorer](<../../../images/image (168).png>)

(_Зверніть увагу, що часові мітки, надані JumplistExplorer, стосуються самого файлу jumplist._)

### Shellbags

[**Перейдіть за цим посиланням, щоб дізнатися, що таке shellbags.**](interesting-windows-registry-keys.md#shellbags)

## Використання Windows USB-пристроїв

Можна визначити, що USB-пристрій використовувався, завдяки створенню:

- Windows Recent Folder
- Microsoft Office Recent Folder
- Jumplists

Зверніть увагу, що деякі LNK-файли замість посилання на початковий шлях указують на папку WPDNSE:

![Shellbags - Use of Windows USBs: Note that some LNK file instead of pointing to the original path, points to the WPDNSE folder](<../../../images/image (218).png>)

Файли в папці WPDNSE є копіями оригінальних файлів, тому вони не зберігаються після перезапуску ПК, а GUID береться із shellbag.

### Інформація реєстру

[Перегляньте цю сторінку, щоб дізнатися](interesting-windows-registry-keys.md#usb-information), які ключі реєстру містять цікаву інформацію про підключені USB-пристрої.

### setupapi

Перевірте файл `C:\Windows\inf\setupapi.dev.log`, щоб отримати часові мітки підключення USB (виконайте пошук за `Section start`).

![Registry Information - setupapi: Check the file C: Windows inf setupapi.dev.log to get the timestamps about when the USB connection was produced (search for Section start)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) можна використовувати для отримання інформації про USB-пристрої, які були підключені до образу.

![setupapi - USB Detective: USBDetective can be used to obtain information about the USB devices that have been connected to an image](<../../../images/image (452).png>)

### Plug and Play Cleanup

Заплановане завдання під назвою 'Plug and Play Cleanup' призначене переважно для видалення застарілих версій драйверів. На відміну від заявленого призначення — збереження останньої версії пакета драйвера — в онлайн-джерелах зазначається, що воно також видаляє драйвери, які не використовувалися протягом 30 днів. Отже, драйвери знімних пристроїв, які не підключалися протягом останніх 30 днів, можуть бути видалені.<sup>[[1]](#references)</sup>

Завдання розташоване за таким шляхом: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

Нижче наведено знімок екрана із вмістом завдання: ![USB Detective - Plug and Play Cleanup: The task is located at the following path: C: Windows System32 Tasks Microsoft Windows Plug and Play Plug and Play Cleanup](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Основні компоненти та налаштування завдання:**

- **pnpclean.dll**: Ця DLL відповідає за фактичний процес очищення.
- **UseUnifiedSchedulingEngine**: Встановлено значення `TRUE`, що вказує на використання універсального механізму планування завдань.
- **MaintenanceSettings**:
- **Period ('P1M')**: Вказує Task Scheduler запускати завдання очищення щомісяця під час звичайного автоматичного обслуговування.
- **Deadline ('P2M')**: Вказує Task Scheduler, якщо завдання не виконувалося протягом двох послідовних місяців, запустити його під час аварійного автоматичного обслуговування.

Ця конфігурація забезпечує регулярне обслуговування та очищення драйверів, а також повторну спробу виконання завдання у разі послідовних невдалих запусків.

**Докладніше:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

## Електронні листи

Електронні листи містять **2 цікаві частини: заголовки та вміст** листа. У **заголовках** можна знайти таку інформацію:

- **Хто** надіслав листи (електронна адреса, IP-адреса, поштові сервери, які перенаправили лист)
- **Коли** було надіслано лист

Також у заголовках `References` і `In-Reply-To` можна знайти ID повідомлень:

![Plug and Play Cleanup - Emails: When was the email sent](<../../../images/image (593).png>)

### Windows Mail App

Ця програма зберігає електронні листи у форматі HTML або тексту. Листи можна знайти у вкладених папках усередині `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`. Листи зберігаються з розширенням `.dat`.

**Метадані** листів і **контакти** можна знайти в **базі даних EDB**: `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`

**Змініть розширення** файлу з `.vol` на `.edb`, після чого для його відкриття можна використати інструмент [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html). У таблиці `Message` можна переглянути електронні листи.

### Microsoft Outlook

Якщо використовуються Exchange-сервери або клієнти Outlook, будуть присутні заголовки MAPI:

- `Mapi-Client-Submit-Time`: час у системі, коли було надіслано лист
- `Mapi-Conversation-Index`: кількість дочірніх повідомлень у ланцюжку та часова мітка кожного повідомлення ланцюжка
- `Mapi-Entry-ID`: ідентифікатор повідомлення.
- `Mappi-Message-Flags` і `Pr_last_Verb-Executed`: інформація про MAPI-клієнт (повідомлення прочитано? не прочитано? на нього відповіли? перенаправили? активовано автовідповідь?)

У клієнті Microsoft Outlook усі надіслані/отримані повідомлення, дані контактів і дані календаря зберігаються у файлі PST за такими шляхами:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Шлях реєстру `HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` указує на файл, який використовується.

Відкрити файл PST можна за допомогою інструмента [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).

![Windows Mail App - Microsoft Outlook: You can open the PST file using the tool Kernel PST Viewer](<../../../images/image (498).png>)

### Файли Microsoft Outlook OST

**Файл OST** створюється Microsoft Outlook, коли його налаштовано з сервером **IMAP** або **Exchange**, і містить інформацію, подібну до файлу PST. Цей файл синхронізується із сервером, зберігаючи дані за **останні 12 місяців** і маючи **максимальний розмір 50 ГБ**. Він розташований у тому самому каталозі, що й файл PST. Для перегляду файлу OST можна використати [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html).

### Отримання вкладень

Втрачені вкладення можна відновити з таких розташувань:

- Для **IE10**: `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
- Для **IE11 і новіших версій**: `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### Файли Thunderbird MBOX

**Thunderbird** використовує **файли MBOX** для зберігання даних. Вони розташовані в `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`.

### Ескізи зображень

- **Windows XP і 8-8.1**: Відкриття папки з ескізами створює файл `thumbs.db`, у якому зберігаються попередні перегляди зображень навіть після їх видалення.
- **Windows 7/10**: `thumbs.db` створюється, коли доступ до папки здійснюється через мережу за UNC-шляхом.
- **Windows Vista і новіші версії**: Попередні перегляди ескізів централізовано зберігаються в `%userprofile%\AppData\Local\Microsoft\Windows\Explorer` у файлах із назвами **thumbcache_xxx.db**. [**Thumbsviewer**](https://thumbsviewer.github.io) і [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) — це інструменти для перегляду цих файлів.

### Інформація реєстру Windows

Реєстр Windows, у якому зберігається значний обсяг даних про активність системи та користувачів, міститься у файлах за такими шляхами:

- `%windir%\System32\Config` для різних підрозділів `HKEY_LOCAL_MACHINE`.
- `%UserProfile%{User}\NTUSER.DAT` для `HKEY_CURRENT_USER`.
- Windows Vista і новіші версії створюють резервні копії файлів реєстру `HKEY_LOCAL_MACHINE` у `%Windir%\System32\Config\RegBack\`.
- Крім того, інформація про виконання програм зберігається у `%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT`, починаючи з Windows Vista і Windows 2008 Server.

### Інструменти

Деякі інструменти корисні для аналізу файлів реєстру:

- **Registry Editor**: Встановлений у Windows. Це GUI для навігації реєстром Windows поточного сеансу.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): Дозволяє завантажити файл реєстру та переміщатися ним за допомогою GUI. Також містить закладки, які виділяють ключі з цікавою інформацією.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Також має GUI, що дає змогу переміщатися завантаженим реєстром, а також містить плагіни, які виділяють цікаву інформацію в завантаженому реєстрі.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Ще одна GUI-програма, здатна витягувати важливу інформацію із завантаженого реєстру.

### Відновлення видалених елементів

Коли ключ видаляється, він позначається як видалений, але не буде остаточно вилучений, доки не знадобиться простір, який він займає. Тому за допомогою таких інструментів, як **Registry Explorer**, можна відновити ці видалені ключі.

### Час останнього запису

Кожна пара ключ-значення містить **часову мітку**, яка вказує на останній момент її зміни.

### SAM

Файл/вулик **SAM** містить хеші **паролів користувачів, груп і користувачів** системи.

У `SAM\Domains\Account\Users` можна отримати ім’я користувача, RID, час останнього входу, час останньої невдалої автентифікації, лічильник входів, політику паролів і час створення облікового запису. Для отримання **хешів** також **потрібен** файл/вулик **SYSTEM**.

### Цікаві записи в реєстрі Windows


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Виконані програми

### Основні процеси Windows

У [цьому дописі](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) можна дізнатися про поширені процеси Windows для виявлення підозрілої поведінки.

### Нещодавні програми Windows

У реєстрі `NTUSER.DAT` за шляхом `Software\Microsoft\Current Version\Search\RecentApps` можна знайти підрозділи з інформацією про **виконану програму**, **час її останнього запуску** та **кількість запусків**.

### BAM (Background Activity Moderator)

Можна відкрити файл `SYSTEM` за допомогою редактора реєстру та за шляхом `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` знайти інформацію про **програми, виконані кожним користувачем** (зверніть увагу на `{SID}` у шляху), а також **час** їх виконання (час міститься у значенні Data реєстру).

### Windows Prefetch

Prefetching — це техніка, яка дає змогу комп’ютеру непомітно **отримувати необхідні ресурси для відображення вмісту**, до якого користувач **може звернутися найближчим часом**, щоб забезпечити швидший доступ до ресурсів.

Windows prefetch передбачає створення **кешів виконаних програм**, щоб мати змогу швидше їх завантажувати. Ці кеші створюються як файли `.pf` за шляхом `C:\Windows\Prefetch`. Існує обмеження: 128 файлів у XP/VISTA/WIN7 і 1024 файли у Win8/Win10.

Ім’я файлу має формат `{program_name}-{hash}.pf` (хеш залежить від шляху та аргументів виконуваного файлу). У W10 ці файли стискаються. Зверніть увагу, що сама наявність файлу вказує на те, що **програму було виконано** в певний момент.

Файл `C:\Windows\Prefetch\Layout.ini` містить **назви папок файлів, для яких створено prefetch**. Цей файл містить **інформацію про кількість виконань**, **дати** виконання та **файли**, **відкриті** програмою.

Для перевірки цих файлів можна використати інструмент [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd):
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superprefetch** має ту саму мету, що й prefetch, — **швидше завантажувати програми**, передбачаючи, що буде завантажено далі. Однак він не замінює службу prefetch.\
Ця служба створює файли баз даних у `C:\Windows\Prefetch\Ag*.db`.

У цих базах даних можна знайти **назву** **програми**, **кількість** її **запусків**, **відкриті** **файли**, **доступний** **том**, **повний** **шлях**, **періоди часу** та **часові мітки**.

Отримати доступ до цієї інформації можна за допомогою інструмента [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/).

### SRUM

**System Resource Usage Monitor** (SRUM) **відстежує** **ресурси**, **спожиті** **процесом**. Він з’явився у W8 і зберігає дані в базі даних ESE, розташованій у `C:\Windows\System32\sru\SRUDB.dat`.

Він надає таку інформацію:

- AppID і шлях
- Користувач, який запустив процес
- Надіслані байти
- Отримані байти
- Мережевий інтерфейс
- Тривалість з’єднання
- Тривалість процесу

Ця інформація оновлюється кожні 60 хвилин.

Отримати дату з цього файлу можна за допомогою інструмента [**srum_dump**](https://github.com/MarkBaggett/srum-dump).
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

**AppCompatCache**, також відомий як **ShimCache**, є частиною **Application Compatibility Database**, розробленої **Microsoft** для вирішення проблем сумісності застосунків. Цей системний компонент записує різні фрагменти метаданих файлів, зокрема:

- Повний шлях до файлу
- Розмір файлу
- Час останньої модифікації у **$Standard_Information** (SI)
- Час останнього оновлення ShimCache
- Прапорець виконання процесу

Ці дані зберігаються в реєстрі за певними розташуваннями залежно від версії операційної системи:

- Для XP дані зберігаються в `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache` з місткістю 96 записів.
- Для Server 2003, а також Windows 2008, 2012, 2016, 7, 8 і 10 шляхом зберігання є `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache`, що підтримує відповідно 512 і 1024 записи.

Для аналізу збереженої інформації рекомендується використовувати [**AppCompatCacheParser tool**](https://github.com/EricZimmerman/AppCompatCacheParser).

![SRUM - AppCompatCache (ShimCache): Для аналізу збереженої інформації рекомендується використовувати AppCompatCacheParser tool](<../../../images/image (75).png>)

### Amcache

Файл **Amcache.hve** по суті є hive реєстру, у якому реєструються відомості про застосунки, що виконувалися в системі. Зазвичай він розташований за адресою `C:\Windows\AppCompat\Programas\Amcache.hve`.

Цей файл примітний тим, що зберігає записи про нещодавно виконані процеси, зокрема шляхи до виконуваних файлів і їхні SHA1-хеші. Ця інформація є надзвичайно цінною для відстеження активності застосунків у системі.

Для видобування й аналізу даних із **Amcache.hve** можна використовувати інструмент [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser). Нижче наведено приклад команди для використання AmcacheParser з метою аналізу вмісту файлу **Amcache.hve** і виведення результатів у форматі CSV:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Серед згенерованих CSV-файлів особливої уваги заслуговує `Amcache_Unassociated file entries` через великий обсяг інформації, який він надає про непов’язані записи файлів.

Найцікавішим згенерованим CSV-файлом є `Amcache_Unassociated file entries`.

### RecentFileCache

Цей артефакт можна знайти лише у W7 за шляхом `C:\Windows\AppCompat\Programs\RecentFileCache.bcf`, і він містить інформацію про нещодавній запуск деяких бінарних файлів.

Для аналізу цього файлу можна використати інструмент [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser).

### Заплановані завдання

Їх можна вилучити з `C:\Windows\Tasks` або `C:\Windows\System32\Tasks` і прочитати як XML.

### Служби

Їх можна знайти в реєстрі за адресою `SYSTEM\ControlSet001\Services`. Там можна побачити, що саме буде виконано і коли.

### **Windows Store**

Встановлені застосунки можна знайти в `\ProgramData\Microsoft\Windows\AppRepository`\
Цей репозиторій містить **журнал** з **кожним застосунком, встановленим** у системі, усередині бази даних **`StateRepository-Machine.srd`**.

У таблиці Application цієї бази даних можна знайти стовпці: "Application ID", "PackageNumber" і "Display Name". Ці стовпці містять інформацію про попередньо встановлені та встановлені застосунки; також можна визначити, чи були деякі застосунки видалені, оскільки ID встановлених застосунків мають бути послідовними.

Також **встановлені застосунки** можна знайти в розділі реєстру: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications`\
А **видалені** **застосунки** — у: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Події Windows

Інформація, що міститься в подіях Windows:

- Що сталося
- Часова мітка (UTC + 0)
- Задіяні користувачі
- Задіяні хости (ім’я хоста, IP)
- Доступні активи (файли, папки, принтери, служби)

Журнали розташовані в `C:\Windows\System32\config` до Windows Vista та в `C:\Windows\System32\winevt\Logs` починаючи з Windows Vista. До Windows Vista журнали подій мали бінарний формат, а після неї вони мають **XML-формат** і використовують розширення **`.evtx`**.

Розташування файлів подій можна знайти в реєстрі SYSTEM за адресою **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**

Їх можна переглядати за допомогою Windows Event Viewer (**`eventvwr.msc`**) або інших інструментів, таких як [**Event Log Explorer**](https://eventlogxp.com) **або** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)**.**

## Розуміння журналювання подій безпеки Windows

Події доступу записуються у файл конфігурації безпеки, розташований за адресою `C:\Windows\System32\winevt\Security.evtx`. Розмір цього файлу можна налаштувати; коли його місткість досягнуто, старіші події перезаписуються. Записані події включають входи та виходи користувачів із системи, дії користувачів і зміни параметрів безпеки, а також доступ до файлів, папок і спільних активів.

### Ключові ID подій для автентифікації користувачів:

- **EventID 4624**: вказує, що користувач успішно пройшов автентифікацію.
- **EventID 4625**: сигналізує про помилку автентифікації.
- **EventIDs 4634/4647**: позначають події виходу користувача із системи.
- **EventID 4672**: позначає вхід із адміністративними привілеями.

#### Підтипи в EventID 4634/4647:

- **Interactive (2)**: безпосередній вхід користувача.
- **Network (3)**: доступ до спільних папок.
- **Batch (4)**: виконання пакетних процесів.
- **Service (5)**: запуск служб.
- **Proxy (6)**: автентифікація через proxy.
- **Unlock (7)**: розблокування екрана за допомогою пароля.
- **Network Cleartext (8)**: передавання пароля у відкритому вигляді, часто з IIS.
- **New Credentials (9)**: використання інших облікових даних для доступу.
- **Remote Interactive (10)**: вхід через remote desktop або terminal services.
- **Cache Interactive (11)**: вхід із кешованими обліковими даними без контакту з контролером домену.
- **Cache Remote Interactive (12)**: віддалений вхід із кешованими обліковими даними.
- **Cached Unlock (13)**: розблокування за допомогою кешованих облікових даних.

#### Коди Status і Sub Status для EventID 4625:

- **0xC0000064**: ім’я користувача не існує — може вказувати на атаку з перерахуванням імен користувачів.
- **0xC000006A**: правильне ім’я користувача, але неправильний пароль — можлива спроба вгадування пароля або brute-force.
- **0xC0000234**: обліковий запис користувача заблоковано — може бути наслідком brute-force-атаки, що спричинила численні невдалі входи.
- **0xC0000072**: обліковий запис вимкнено — несанкціоновані спроби отримати доступ до вимкнених облікових записів.
- **0xC000006F**: вхід поза дозволеним часом — вказує на спроби доступу поза встановленими годинами входу та може свідчити про несанкціонований доступ.
- **0xC0000070**: порушення обмежень робочої станції — може бути спробою входу з неавторизованого розташування.
- **0xC0000193**: завершення терміну дії облікового запису — спроби доступу з використанням прострочених облікових записів.
- **0xC0000071**: термін дії пароля завершився — спроби входу зі застарілими паролями.
- **0xC0000133**: проблеми синхронізації часу — значні розбіжності часу між клієнтом і сервером можуть вказувати на складніші атаки, наприклад pass-the-ticket.
- **0xC0000224**: потрібна обов’язкова зміна пароля — часті обов’язкові зміни можуть свідчити про спробу дестабілізувати безпеку облікового запису.
- **0xC0000225**: вказує на системну помилку, а не на проблему безпеки.
- **0xC000015b**: тип входу заборонено — спроба доступу з несанкціонованим типом входу, наприклад спроба користувача виконати вхід до служби.

#### EventID 4616:

- **Time Change**: зміна системного часу, яка може приховати часову послідовність подій.

#### EventID 6005 і 6006:

- **Запуск і завершення роботи системи**: EventID 6005 вказує на запуск системи, а EventID 6006 — на її завершення роботи.

#### EventID 1102:

- **Видалення журналу**: очищення журналів безпеки, що часто є ознакою приховування незаконної діяльності.

#### EventIDs для відстеження USB-пристроїв:

- **20001 / 20003 / 10000**: перше підключення USB-пристрою.
- **10100**: оновлення USB-драйвера.
- **EventID 112**: час підключення USB-пристрою.

Практичні приклади імітації цих типів входу та можливостей вилучення облікових даних наведено в докладному посібнику [Altered Security](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).

Відомості про події, зокрема коди status і sub-status, надають додаткові дані про причини подій; це особливо важливо для Event ID 4625.

### Відновлення подій Windows

Щоб підвищити ймовірність відновлення видалених подій Windows, рекомендується вимкнути підозрілий комп’ютер, безпосередньо від’єднавши його від живлення. Для спроби відновлення таких подій рекомендується **Bulk_extractor** із зазначенням розширення `.evtx`.

### Виявлення поширених атак за подіями Windows

Вичерпний посібник із використання Windows Event IDs для виявлення поширених cyber attacks доступний на сайті [Red Team Recipe](https://redteamrecipe.com/event-codes/).

#### Brute Force Attacks

Виявляються за численними записами EventID 4625, після яких у разі успішної атаки з’являється EventID 4624.

#### Time Change

Фіксується EventID 4616; зміни системного часу можуть ускладнити forensic analysis.

#### USB Device Tracking

Корисні System EventIDs для відстеження USB-пристроїв: 20001/20003/10000 для першого використання, 10100 для оновлень драйверів і EventID 112 від DeviceSetupManager для часових міток підключення.

#### System Power Events

EventID 6005 вказує на запуск системи, а EventID 6006 — на завершення роботи.

#### Log Deletion

Security EventID 1102 сигналізує про видалення журналів — критичну подію для forensic analysis.

## References

- [1] [Windows Plug and Play Cleanup](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

{{#include ../../../banners/hacktricks-training.md}}
