# Артефакти Windows

{{#include ../../../banners/hacktricks-training.md}}

## Загальні артефакти Windows

### Сповіщення Windows 10

База даних сповіщень для окремого користувача розташована в `%LOCALAPPDATA%\Microsoft\Windows\Notifications` (наприклад, `C:\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`). У ранніх випусках Windows 10 використовувався файл `appdb.dat`; у Anniversary Update (1607) було представлено `wpndatabase.db`. База даних SQLite містить таблицю `Notification` із даними сповіщень і полями часу, хоча обсяг збережених і доступних даних залежить від випуску та політики очищення.<sup>[[3]](#references)</sup>

### Timeline

Windows Timeline — це функція історії активності, яка може містити записи для підтримуваних застосунків, документів та іншої активності користувача; охоплення залежить від застосунку та версії Windows.<sup>[[4]](#references)</sup>

База даних розташована за шляхом `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Її можна відкрити за допомогою SQLite або проаналізувати за допомогою [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd), а результати можна переглянути за допомогою [**Timeline Explorer**](https://ericzimmerman.github.io/#!index.md).<sup>[[4]](#references)[[5]](#references)</sup>

### ADS (Alternate Data Streams)

Файли, завантажені за межами локальної довіреної межі, можуть містити **альтернативний потік даних `Zone.Identifier`**, у якому записується інформація про зону та можуть міститися метадані джерела, наприклад URL. Його наявність і поля залежать від програми-джерела та системної політики.<sup>[[6]](#references)</sup>

## **Резервні копії файлів**

### Кошик

У Vista та новіших версіях **Кошик** можна знайти в папці **`$Recycle.bin`** у корені диска (наприклад, `C:\$Recycle.bin`).\
Коли файл видаляється в цій папці, створюються 2 конкретні файли:

- `$I{id}`: Інформація про файл, зокрема час видалення та початковий шлях
- `$R{id}`: Вміст файлу

![Резервні копії файлів — Кошик: $R{id}: Вміст файлу](<../../../images/image (1029).png>)

Маючи ці файли, можна використати [**Rifiuti2**](https://github.com/abelcheung/rifiuti2), щоб отримати початковий шлях і час видалення (використовуйте версію, що відповідає цільовому випуску Windows).<sup>[[7]](#references)</sup>
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![File Backups - Recycle Bin: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Тіньові копії томів

Volume Shadow Copy Service (VSS) може створювати тіньові копії томів у певний момент часу, коли файли використовуються; тіньова копія не є заміною forensic image.<sup>[[8]](#references)</sup>

Метадані копії зазвичай пов'язані з `\System Volume Information` у корені тому, а ідентифікатори залежать від системи:

![Recycle Bin - Volume Shadow Copies: Ці резервні копії зазвичай розташовані в System Volume Information у корені файлової системи, а ім'я складається з UID, показаних на...](<../../../images/image (94).png>)

Після монтування image за допомогою відповідного forensic mounter [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) може перелічити доступні знімки VSS і переглядати або копіювати з них файли.<sup>[[9]](#references)</sup>

![Recycle Bin - Volume Shadow Copies: Після монтування forensic image за допомогою ArsenalImageMounter інструмент ShadowCopyView можна використовувати для перевірки тіньової копії та навіть вилучення файлів...](<../../../images/image (576).png>)

Конфігурація registry writer VSS містить `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore`, де можна вказати файли та ключі, виключені з резервного копіювання:<sup>[[10]](#references)[[11]](#references)</sup>

![Recycle Bin - Volume Shadow Copies: Запис реєстру HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore містить файли та ключі, які не потрібно резервно копіювати](<../../../images/image (254).png>)

Ключ `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` також містить конфігурацію служби VSS.<sup>[[8]](#references)</sup>

### Автоматично збережені файли Office

Розташування AutoRecover залежить від застосунку Office, його версії та конфігурації. Для Word Microsoft вказує `%APPDATA%\Microsoft\Word` як розташування за замовчуванням; перевірте налаштування застосунку, щоб визначити активний шлях.<sup>[[12]](#references)</sup>

## Елементи Shell

Елемент shell — це елемент, який містить інформацію про доступ до іншого файлу.

### Останні документи (LNK)

Windows зазвичай створює ярлики останніх елементів, коли користувач відкриває елемент або іншим чином отримує до нього доступ:

- Win7-Win10: `%APPDATA%\Microsoft\Windows\Recent\`
- Office: `%APPDATA%\Microsoft\Office\Recent\`

Доступ до папки також може створити посилання для папки та пов'язаних батьківських папок.

Ці файли посилань можуть містити тип цільового об'єкта, MAC times цільового об'єкта, інформацію про том і шлях до цільового об'єкта. Ці метадані можуть допомогти ідентифікувати видалений цільовий об'єкт, але сам артефакт не є доказом того, що цільовий об'єкт було відкрито конкретним користувачем.<sup>[[13]](#references)[[14]](#references)</sup>

Власні файлові timestamps LNK і вбудовані timestamps цільового об'єкта є різними. Не вважайте створення посилання першим використанням або зміну посилання останнім використанням без підтвердження іншими артефактами; формат зберігає timestamps цільового об'єкта окремо від timestamps файлу посилання.<sup>[[13]](#references)[[14]](#references)</sup>

Наявне посилання на [**LinkParser**](http://4discovery.com/our-tools/) збережено як історичний варіант, але під час перевірки його документація була недоступна. Для документованого парсера командного рядка використовуйте [**LECmd**](https://github.com/EricZimmerman/LECmd).<sup>[[15]](#references)</sup>

Ці інструменти зазвичай показують два набори timestamps:

- **Timestamps цільового об'єкта:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **Timestamps файлу посилання:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

Перший набір стосується цільового об'єкта; другий — самого LNK-файлу. Інтерпретуйте обидва набори з урахуванням документації парсера та контексту файлової системи.<sup>[[14]](#references)[[15]](#references)</sup>

Ви можете отримати ту саму інформацію, запустивши інструмент Windows CLI: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd).<sup>[[15]](#references)</sup>
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
У цьому випадку інформацію буде збережено у CSV-файлі.

### Jumplists

Jump Lists — це списки нещодавніх або пов’язаних із завданнями елементів для окремих застосунків; вони можуть бути автоматичними або користувацькими.<sup>[[13]](#references)</sup>

Automatic Jump Lists зберігаються в `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` і використовують такі імена, як `{id}.automaticDestinations-ms`, де ID ідентифікує застосунок.

Custom Jump Lists зберігаються в `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\`; застосунок визначає, які записи завдань або елементів він створює.

Часи створення та зміни файлової системи описують файл Jump List, а не автоматично перший і останній доступ до кожної цілі зі списку. Співвідносите проаналізовані записи з часовими мітками файлу та іншими артефактами.<sup>[[13]](#references)</sup>

Переглядати Jump Lists можна за допомогою [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).<sup>[[5]](#references)</sup>

![Recent Documents (LNK) - Jumplists: Переглядати jumplists можна за допомогою JumplistExplorer](<../../../images/image (168).png>)

(_Зверніть увагу, що часові мітки, надані JumplistExplorer, стосуються самого файлу jumplist_)

### Shellbags

[**Перейдіть за цим посиланням, щоб дізнатися, що таке shellbags.**](interesting-windows-registry-keys.md#shellbags)

## Використання Windows USB

Використання USB іноді можна підтвердити за артефактами, створеними під час доступу до файлів зі змінних носіїв, зокрема:

- Windows Recent Folder
- Microsoft Office Recent Folder
- Jumplists

Такі інструменти, як [**USBDetective**](https://usbdetective.com), співвідносять ці артефакти із записами про USB-пристрої, але доступність артефактів залежить від версії Windows і застосунку.<sup>[[18]](#references)</sup>

Під час тестування робочих процесів MTP у Windows XP і Windows 7 було встановлено, що деякі LNK-файли вказували на папку `WPDNSE`, а не на оригінальний шлях.<sup>[[16]](#references)</sup>

![Shellbags - Використання Windows USB: Зверніть увагу, що деякі LNK-файли замість оригінального шляху вказують на папку WPDNSE](<../../../images/image (218).png>)

У цьому дослідженні було виявлено копії в `%LOCALAPPDATA%\Temp\WPDNSE\{FolderGUID}`; за результатами тестів тимчасовий вміст не зберігався після перезапуску, а GUID можна було співвіднести з даними shellbag. Розглядайте це як поведінку, що залежить від ОС, пристрою та застосунку, а не як універсальне правило.<sup>[[16]](#references)</sup>

### Інформація в Registry

[Перегляньте цю сторінку, щоб дізнатися](interesting-windows-registry-keys.md#usb-information), які ключі Registry містять цікаву інформацію про підключені USB-пристрої.

### setupapi

У Vista та новіших версіях перевіряйте `C:\Windows\inf\setupapi.dev.log` на наявність активності зі встановлення пристроїв. Заголовки секцій містять часові мітки `Section start`; вони документують обробку встановлення, тому їх слід співвідносити з іншими доказами підключення, а не вважати точним часом фізичного підключення.<sup>[[17]](#references)</sup>

![Registry Information - setupapi: Перевірте файл C: Windows inf setupapi.dev.log, щоб отримати часові мітки підключення USB (шукайте Section start)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) можна використовувати для отримання інформації про USB-пристрої, підключені до образу.<sup>[[18]](#references)</sup>

![setupapi - USB Detective: USBDetective можна використовувати для отримання інформації про USB-пристрої, підключені до образу](<../../../images/image (452).png>)

### Plug and Play Cleanup

Заплановане завдання `Plug and Play Cleanup` видаляє застарілі версії драйверів. В описі завдання Windows 10, задокументованому Adam Harrison, також зазначено драйвери, неактивні протягом 30 днів, тому дані про драйвери змінних пристроїв можуть бути очищені; перед узагальненням цієї поведінки перевіряйте локальне визначення завдання та збірку Windows.<sup>[[1]](#references)</sup>

Завдання розташоване за таким шляхом: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

![XML definition of the Windows Plug and Play Cleanup scheduled task](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Основні компоненти та налаштування завдання:**

- **pnpclean.dll**: ця DLL відповідає за фактичний процес очищення.
- **UseUnifiedSchedulingEngine**: має значення `TRUE`, що вказує на використання загального рушія планування завдань.
- **MaintenanceSettings**:
- **Period ('P1M')**: вказує Task Scheduler запускати завдання очищення щомісяця під час регулярного Automatic maintenance.
- **Deadline ('P2M')**: наказує Task Scheduler, якщо завдання не виконувалося протягом двох послідовних місяців, запустити його під час екстреного Automatic maintenance.

Ця конфігурація планує регулярне обслуговування та повторні спроби після послідовних невдалих запусків; точні XML і поведінка залежать від версії.<sup>[[1]](#references)</sup>

**Для отримання додаткової інформації перегляньте:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html).<sup>[[1]](#references)</sup>

## Електронні листи

Електронні листи містять **2 цікаві частини: заголовки та вміст** листа. У **заголовках** можна знайти таку інформацію:

- **Хто** надіслав листи (адреса електронної пошти, IP, поштові сервери, які перенаправляли лист)
- **Коли** було надіслано лист

Крім того, заголовки `References` і `In-Reply-To` можуть містити ID повідомлень, які використовуються для пов’язування відповідей із розмовою.<sup>[[76]](#references)</sup>

![Plug and Play Cleanup - Emails: Коли було надіслано лист](<../../../images/image (593).png>)

### Windows Mail App

Цей застосунок зберігає вміст електронних листів у допоміжних текстових або HTML-файлах за такими шляхами, як `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`; точна структура нумерованих папок і файлів може відрізнятися залежно від артефакту.<sup>[[75]](#references)</sup>

**Метадані** електронних листів і **контакти** можна знайти в **ESE database** `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`.<sup>[[75]](#references)</sup>

`store.vol` використовує формат Extensible Storage Engine (ESE). Працюйте з копією та використовуйте ESE parser, наприклад [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html); якщо інструмент потребує суфікса `.edb`, перейменовуйте лише копію та перевіряйте схему таблиць перед тим, як покладатися на таблицю `Message`.<sup>[[19]](#references)[[75]](#references)</sup>

### Microsoft Outlook

Під час перевірки властивостей Outlook MAPI канонічні властивості включають:

- `PidTagClientSubmitTime`: час UTC, коли клієнт надіслав повідомлення.
- `PidTagConversationIndex`: відносна позиція повідомлення в ланцюжку розмови.
- `PidTagEntryId`: ідентифікатор об’єкта повідомлення.
- `PidTagMessageFlags`: прапорці стану, наприклад надіслано, прочитано, не прочитано або наявні вкладення.
- `PidTagLastVerbExecuted`: остання операція, записана для повідомлення, наприклад відкриття, відповідь або пересилання.<sup>[[20]](#references)[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Розташування файлів даних Outlook залежить від версії та типу облікового запису. Microsoft документує такі поширені розташування PST/OST-файлів:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Шлях Registry `HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` може ідентифікувати профіль Outlook і пов’язану конфігурацію файлів даних.

PST-файли можуть містити повідомлення, контакти, дані календаря та інші елементи Outlook. Копію можна переглянути за допомогою [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).<sup>[[25]](#references)[[67]](#references)</sup>

![Windows Mail App - Microsoft Outlook: PST-файл можна відкрити за допомогою інструмента Kernel PST Viewer](<../../../images/image (498).png>)

### Microsoft Outlook OST Files

**OST file** — це локальний кеш для облікових записів Exchange або Microsoft 365; Cached Exchange Mode не застосовується до облікових записів POP або IMAP. Період автономного зберігання можна налаштувати, і зазвичай за замовчуванням він становить 12 місяців, тоді як обмеження розміру PST/OST є окремими параметрами, які також можна налаштувати. Для перегляду OST-файлу можна використовувати [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html).<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[68]](#references)</sup>

### Отримання вкладень

Втрачені вкладення іноді можна відновити з таких місць:

- Для застарілих конфігурацій Outlook/IE: `%LOCALAPPDATA%\Temporary Internet Files\Content.Outlook`
- Для новіших конфігурацій Outlook/IE11: `%LOCALAPPDATA%\Microsoft\Windows\INetCache\Content.Outlook`.<sup>[[65]](#references)</sup>

### Thunderbird MBOX Files

**Thunderbird** зберігає дані профілю в `%APPDATA%\Thunderbird\Profiles`; поштові папки зазвичай використовують mbox-файли без розширення в каталогах `Mail` або `ImapMail`, специфічних для облікового запису.<sup>[[29]](#references)[[30]](#references)</sup>

### Ескізи зображень

- **Windows XP**: попередні перегляди ескізів зазвичай зберігалися в окремих для кожної папки файлах `thumbs.db`.
- **Мережеві папки**: файл `thumbs.db` усе ще може створюватися для UNC-папки, якщо відповідну поведінку ескізів увімкнено; не вважайте, що кожна версія Windows або політика створює такий файл.
- **Windows Vista та новіші версії**: системний кеш ескізів централізовано зберігається в `%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer` у файлах на кшталт **thumbcache_xxx.db**. [**Thumbsviewer**](https://thumbsviewer.github.io) може аналізувати застарілі `Thumbs.db`, а [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) — сучасні бази даних кешу ескізів.<sup>[[31]](#references)[[32]](#references)[[33]](#references)</sup>

### Інформація Windows Registry

Windows Registry, що зберігає системні та користувацькі конфігураційні дані, міститься у файлах hive за такими шляхами:

- `%WINDIR%\System32\Config` — для машинних hive, що підтримують різні підрозділи `HKEY_LOCAL_MACHINE`.
- `%USERPROFILE%\NTUSER.DAT` — для hive користувача `HKEY_CURRENT_USER`.
- Деякі старіші інсталяції Windows містять копії в `%WINDIR%\System32\Config\RegBack\`; Windows 10 версії 1803 і новіші не заповнюють цей каталог автоматично, якщо не ввімкнено періодичне резервне копіювання.<sup>[[34]](#references)[[35]](#references)</sup>
- Дані shell і реєстрації класів для окремих користувачів у сучасних версіях Windows також зазвичай зберігаються в `%LOCALAPPDATA%\Microsoft\Windows\UsrClass.dat`.<sup>[[34]](#references)[[66]](#references)</sup>

### Інструменти

Деякі інструменти корисні для аналізу registry hives; перед використанням результатів перевіряйте підтримувані кожним інструментом формати hive та версії:

- **Registry Editor**: встановлений у Windows. Це GUI для навігації Windows Registry поточного сеансу.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): дає змогу завантажити файл Registry і переглядати його через GUI. Також містить Bookmarks, що виділяють ключі з цікавою інформацією.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): також має GUI для навігації завантаженим Registry і містить plugins, які виділяють цікаву інформацію в завантаженому Registry.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): ще один GUI-застосунок, здатний отримувати інформацію із завантаженого registry hive.<sup>[[5]](#references)[[36]](#references)[[37]](#references)</sup>

### Відновлення видаленого елемента

Видалені hive cells можуть залишатися, доки їхній простір не буде повторно використано, але відновлення залежить від стану hive та parser; розглядайте відновлені видалені ключі як докази, що потребують перевірки, а не як гарантовані записи.

### Час останнього запису

Registry keys містять часову мітку останнього запису; Windows надає її для ключа або будь-якого з його value entries, тому значення не обов’язково має власну незалежну часову мітку зміни.<sup>[[69]](#references)</sup>

### SAM

**SAM** hive містить дані локальних облікових записів користувачів і груп, зокрема password hashes, захищені матеріалом системного boot-key.<sup>[[38]](#references)[[39]](#references)</sup>

У `SAM\Domains\Account\Users` можна отримати ідентифікатори облікових записів і деякі поля входу та політик. Для offline hash extraction також потрібен `SYSTEM` hive, щоб відновити відповідний матеріал boot-key.<sup>[[38]](#references)[[39]](#references)</sup>

### Цікаві записи у Windows Registry


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Виконані програми

### Основні процеси Windows

Існуючий [post про поширені процеси Windows](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) збережено як додатковий матеріал; твердження щодо поведінки процесів слід підтверджувати актуальною документацією Windows і локальними доказами.<sup>[[2]](#references)</sup>

### Windows Recent APPs

У версіях Windows 10, де цей артефакт доступний, `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps` містить підрозділи для окремих застосунків із такими полями, як час останнього використання та кількість запусків; у пізніших випусках артефакт було видалено, тому перевіряйте цільову збірку.<sup>[[64]](#references)</sup>

### BAM (Background Activity Moderator)

У системах, де доступний Background Activity Moderator, перевіряйте шлях `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` або новіший шлях `...\bam\State\UserSettings\{SID}`. Значення індексуються за SID користувача й можуть містити відстежувані шляхи до виконуваних файлів і дані виконання, подібні до FILETIME; артефакт залежить від версії, тому його слід підтверджувати іншими доказами.<sup>[[63]](#references)</sup>

### Windows Prefetch

Prefetch кешує ресурси та метадані запуску, щоб програми могли запускатися швидше.

Файли Prefetch зберігаються як `.pf`-файли в `C:\Windows\Prefetch`; формат, зберігання та обмеження кількості файлів залежать від версії Windows. Microsoft документує зберігання останніх восьми часів виконання та до 1024 файлів у Windows 8 і новіших версіях, тому старі описи фіксованих обмежень не слід узагальнювати.<sup>[[13]](#references)</sup>

Ім’я файлу зазвичай має формат `{program_name}-{hash}.pf`, де hash обчислюється на основі контексту виконання, наприклад шляху та аргументів; Windows 10 і новіші версії можуть стискати файл. Наявність файлу є корисною ознакою виконання, але сама по собі не доводить виконання програми користувачем і має підтверджуватися іншими артефактами.<sup>[[13]](#references)</sup>

Для перевірки цих файлів можна використовувати [**PECmd.exe**](https://github.com/EricZimmerman/PECmd), який документує аналіз каталогів, виведення у CSV/HTML і підтримку розпакування відповідних Prefetch-файлів Windows 10.<sup>[[40]](#references)</sup>
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superfetch/SysMain** доповнює Prefetch, використовуючи історичні шаблони використання для прискорення завантаження. У системах, які їх створюють, файли бази даних зазвичай знаходяться в `C:\Windows\Prefetch\Ag*.db`; формат і наявність залежать від версії.<sup>[[41]](#references)</sup>

Ці бази даних можуть містити назви застосунків, кількість використань, доступні файли або томи, шляхи та часові діапазони, але їх не слід розглядати як точний журнал виконання.<sup>[[41]](#references)</sup>

Наявне посилання на [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) збережено як можливий парсер; перед використанням перевірте його поточну доступність і підтримуваний формат виводу за документацією інструмента.

### SRUM

**System Resource Usage Monitor** (SRUM) записує використання ресурсів застосунками та користувачами. Його було представлено у Windows 8, і він зберігає дані в базі даних ESE `C:\Windows\System32\sru\SRUDB.dat`.<sup>[[13]](#references)</sup>

Він надає таку інформацію:

- AppID і шлях
- Користувач/SID, пов’язаний із записом
- Надіслані байти
- Отримані байти
- Мережевий інтерфейс
- Тривалість підключення
- Тривалість процесу

Періодичність збору та зберігання даних залежать від реалізації; не слід припускати, що кожен запис відповідає точному 60-хвилинному інтервалу виконання.<sup>[[13]](#references)</sup>

Ви можете отримати й переглянути дані за допомогою [**srum_dump**](https://github.com/MarkBaggett/srum-dump), використовуючи параметри, задокументовані в поточній версії інструмента.<sup>[[42]](#references)</sup>
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -o C:\Users\student\Desktop\srum --NO_CONFIRM
```
### AppCompatCache (ShimCache)

**AppCompatCache**, також відомий як **ShimCache**, є частиною інфраструктури сумісності застосунків Windows і записує метадані файлів для ухвалення рішень щодо сумісності. Шлях до hive, формат записів, обсяг збережених даних і поля відрізняються залежно від версії Windows; у сучасних версіях Windows сам по собі ShimCache не може довести, що користувач виконував файл. Проаналізуйте відповідний hive `SYSTEM` за допомогою інструмента [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser) і підтвердьте його результати іншими артефактами виконання.<sup>[[13]](#references)[[43]](#references)</sup>

![SRUM - AppCompatCache (ShimCache): Для аналізу збереженої інформації рекомендується використовувати інструмент AppCompatCacheParser](<../../../images/image (75).png>)

### Amcache

Файл **Amcache.hve** є registry hive, який містить перелік застосунків і файлів, виявлених Windows. Зазвичай він знаходиться за шляхом `C:\Windows\AppCompat\Programs\Amcache.hve`.

Він може містити записи пов’язаних і непов’язаних файлів, шляхи та значення SHA1, але його наявність є доказом інвентаризації й сама по собі не доводить, що процес було виконано.<sup>[[13]](#references)[[44]](#references)</sup>

Для вилучення й аналізу **Amcache.hve** використовуйте інструмент [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser). Ця команда аналізує hive і записує результат у форматі CSV.<sup>[[44]](#references)</sup>

Наприклад:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Серед згенерованих CSV-файлів `Amcache_Unassociated file entries` може бути корисним під час дослідження файлів, які не пов’язані з розпізнаною програмою.<sup>[[44]](#references)</sup>

### RecentFileCache

У системах Windows 7 файл `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` може містити інформацію про нещодавно виявлені бінарні файли; його доступність і семантика залежать від версії.

Для аналізу цього файлу можна використовувати [**RecentFileCacheParser**](https://github.com/EricZimmerman/RecentFileCacheParser).<sup>[[45]](#references)</sup>

### Заплановані завдання

Артефакти запланованих завдань можна знайти в `C:\Windows\System32\Tasks` для сучасних завдань і в `C:\Windows\Tasks` у вигляді файлів `.job` для застарілих завдань; аналізуйте формат визначення завдання, відповідний до версії ОС.<sup>[[73]](#references)[[74]](#references)</sup>

### Служби

База даних Service Control Manager розташована в `SYSTEM\CurrentControlSet\Services` (для офлайн-вулика SYSTEM перевіряйте відповідний ключ control-set); вона містить конфігурацію служб і драйверів, зокрема шляхи до виконуваних файлів і типи запуску.<sup>[[72]](#references)</sup>

### **Windows Store**

Встановлені програми Windows Store можуть бути представлені в `\ProgramData\Microsoft\Windows\AppRepository\`, зокрема базою даних **`StateRepository-Machine.srd`**. Схема та шляхи відрізняються залежно від випуску Windows.<sup>[[71]](#references)</sup>

База даних може містити ідентифікатори програм, номери пакетів і відображувані імена. Пропуски в ідентифікаторах самі по собі не є доказом видалення програми; підтверджуйте висновки станом пакетів і реєстру.

Реєстрації пакетів також можуть з’являтися в `HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`. Microsoft документує версійний підключ `Deprovisioned` для видалених підготовлених програм; не припускайте, що підключ `Deleted` існує в кожній збірці.<sup>[[70]](#references)</sup>

## Події Windows

Залежно від постачальника, події Windows можуть містити:

- Що сталося
- Мітку часу `TimeCreated`, яку потрібно інтерпретувати з урахуванням схеми події та часового контексту хоста
- Задіяних користувачів
- Задіяні хости (ім’я хоста, IP)
- Доступні активи (файли, папки, принтери або служби).<sup>[[49]](#references)</sup>

До Windows Vista журнали подій зазвичай використовували застарілий двійковий формат у `C:\Windows\System32\config`; Vista та новіші версії використовують формат Windows Event Log, зазвичай у `C:\Windows\System32\winevt\Logs`, а файли `.evtx` містять дані подій, відображені у форматі XML.<sup>[[46]](#references)[[47]](#references)</sup>

Реєстр SYSTEM зберігає конфігурацію каналів у **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**, зокрема налаштований шлях до файлу та параметри зберігання.<sup>[[47]](#references)</sup>

Їх можна переглядати за допомогою Windows Event Viewer (**`eventvwr.msc`**) або таких інструментів, як [**Event Log Explorer**](https://eventlogxp.com) і [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md).<sup>[[5]](#references)[[48]](#references)[[61]](#references)</sup>

## Розуміння журналювання подій безпеки Windows

У Vista та новіших версіях канал Security зазвичай зберігається в `C:\Windows\System32\winevt\Logs\Security.evtx`. Його максимальний розмір і політика зберігання налаштовуються; за циклічного журналювання старі записи можуть бути перезаписані, коли файл досягає встановленого ліміту. Канал може записувати події автентифікації, виходу із системи, привілеїв, політики аудиту та доступу до об’єктів, якщо відповідний аудит увімкнено.<sup>[[46]](#references)[[47]](#references)</sup>

### Ключові ідентифікатори подій для автентифікації користувачів:

- **Event ID 4624**: Успішний вхід облікового запису.<sup>[[50]](#references)</sup>
- **Event ID 4625**: Невдалий вхід облікового запису.<sup>[[51]](#references)</sup>
- **Event ID 4634**: Сеанс входу було завершено.<sup>[[52]](#references)</sup>
- **Event ID 4647**: Користувач ініціював вихід із системи.<sup>[[53]](#references)</sup>
- **Event ID 4672**: Новому входу було призначено спеціальні привілеї; це поширено для системних облікових записів і облікових записів адміністраторів, тому саме по собі не є доказом шкідливої активності.<sup>[[54]](#references)</sup>

#### Типи входу, які зазвичай записуються в 4624, 4625, 4634 і 4647:

- **Interactive (2)**: Інтерактивний локальний вхід.
- **Network (3)**: Доступ до спільного ресурсу.
- **Batch (4)**: Вхід пакетного процесу.
- **Service (5)**: Вхід служби.
- **Unlock (7)**: Розблокування робочої станції.
- **NetworkCleartext (8)**: Мережевий вхід, під час якого облікові дані передаються пакету автентифікації у відкритому тексті.
- **NewCredentials (9)**: Вхід із використанням наданих альтернативних облікових даних для вихідних підключень.
- **RemoteInteractive (10)**: Вхід через Remote Desktop або Terminal Services.
- **CachedInteractive (11)**: Інтерактивний вхід із використанням кешованих доменних облікових даних.
- **CachedRemoteInteractive (12)**: Кешований віддалений інтерактивний вхід.
- **CachedUnlock (13)**: Розблокування з використанням кешованих облікових даних.<sup>[[50]](#references)[[51]](#references)</sup>

#### Коди Status і Sub Status для EventID 4625:

- **0xC0000064**: Такого користувача не існує.
- **0xC000006A**: Ім’я користувача правильне, але пароль неправильний.
- **0xC0000234**: Обліковий запис заблоковано.
- **0xC0000072**: Обліковий запис вимкнено.
- **0xC000006F**: Вхід за межами дозволених годин.
- **0xC0000070**: Порушення обмеження робочої станції.
- **0xC0000193**: Термін дії облікового запису минув.
- **0xC0000071**: Термін дії пароля минув.
- **0xC0000133**: Різниця в часі між клієнтом і сервером надто велика.
- **0xC0000224**: Обліковий запис повинен змінити пароль.
- **0xC0000225**: `STATUS_NOT_FOUND`; сам код не ідентифікує системну помилку або атаку.
- **0xC000015B**: Запитаний тип входу не надано обліковому запису.<sup>[[51]](#references)[[55]](#references)</sup>

#### EventID 4616:

- **Time Change**: Системний час було змінено. Багато подій відображають штатну корекцію часу службою синхронізації, тому перед трактуванням цього як втручання зіставте виконавця та джерело часу.<sup>[[56]](#references)</sup>

#### Event IDs 12, 13, 1074, 6005, 6006, 6008 і 6009:

- **Контекст живлення та служб**: Подія 12 фіксує запуск ОС, 13 — завершення роботи ОС, 1074 — заплановане завершення роботи або перезапуск, 6008 вказує на неочікуване завершення роботи, а 6009 записує версію Windows під час завантаження. Події 6005 і 6006 вказують відповідно на запуск і зупинку служби Event Log; самі по собі вони не є доказом запуску та завершення роботи ОС.<sup>[[57]](#references)[[58]](#references)</sup>

#### EventID 1102:

- **Видалення журналу**: Подія 1102 фіксує очищення журналу аудиту Security; досліджуйте виконавця та прилеглі події, а не робіть висновок про намір лише на підставі цієї події.<sup>[[62]](#references)</sup>

#### EventIDs для відстеження USB-пристроїв:

- **20001 / 20003**: Події встановлення пристроїв `UserPnp`, які можуть допомогти встановити факт першого використання або встановлення.
- **10000 / 10100**: Події `DriverFrameworks-UserMode`, які можуть супроводжувати активність пристрою.
- **Event ID 112**: Активність `DeviceSetupManager/Admin`, яка може надати мітки часу, пов’язані з підключенням.
- Постачальник, канал і семантика подій залежать від версії Windows; перш ніж надавати події певне значення, перевірте ім’я постачальника та вміст події.<sup>[[59]](#references)</sup>

Практичні приклади типів входу та пов’язаного з ними матеріалу облікових даних наведено в [детальному посібнику Altered Security](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).<sup>[[60]](#references)</sup>

Деталі події, зокрема тип входу, статус, підстатус, адресу джерела та поля процесу, надають контекст для Event ID 4625; код статусу або повторювана схема невдалих спроб є напрямом для дослідження, а не остаточним висновком.<sup>[[51]](#references)[[55]](#references)</sup>

### Відновлення подій Windows

Оскільки журнали подій зазвичай працюють у циклічному режимі, записи, перезаписані засобом журналювання, можуть бути невідновними. Створіть forensic image або робочу копію перед взаємодією з активною системою; використовуйте перевірений parser або carver, наприклад **Bulk_extractor**, лише після підтвердження, що версія інструмента підтримує цільові дані `.evtx`, і не від’єднуйте працюючу систему лише для спроби відновити події.<sup>[[46]](#references)</sup>

### Виявлення поширених атак за допомогою подій Windows

Практичний довідник з ідентифікаторами подій доступний за наявним посиланням [Red Team Recipe](https://redteamrecipe.com/event-codes/); перевіряйте його приклади за документацією постачальників, наведеною вище.

#### Brute Force Attacks

Зіставляйте повторювані невдалі спроби Event ID 4625 із подальшим успішним входом 4624, типом входу, статусом, джерелом і контекстом облікового запису; така послідовність є індикатором для дослідження, а не доказом атаки.<sup>[[50]](#references)[[51]](#references)</sup>

#### Зміна часу

Event ID 4616 фіксує зміни системного часу, які можуть ускладнити аналіз часової шкали; порівнюйте цю подію з даними служби синхронізації часу та хоста.<sup>[[56]](#references)</sup>

#### Відстеження USB-пристроїв

Ідентифікатори USB-подій залежать від постачальника; зіставляйте `UserPnp` 20001/20003, `DriverFrameworks-UserMode` 10000/10100 і `DeviceSetupManager/Admin` 112 з артефактами SetupAPI та реєстру.<sup>[[17]](#references)[[59]](#references)</sup>

#### Системні події живлення

Використовуйте 12/13/1074/6008/6009 для визначення контексту запуску ОС, завершення роботи, перезапуску та неочікуваного вимкнення; 6005/6006 позначають запуск/зупинку служби Event Log.<sup>[[57]](#references)[[58]](#references)</sup>

#### Видалення журналу

Security Event ID 1102 фіксує очищення журналу аудиту Security; його слід зіставляти з відповідним обліковим записом і процесом.<sup>[[62]](#references)</sup>

## References

- [1] [Очищення Windows Plug and Play](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)
- [2] [jonahacks.medium.com - Дослідження поширених процесів Windows](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)
- [3] [Цифрово-криміналістичний погляд на сповіщення Windows 10](https://iconline.ipleiria.pt/server/api/core/bitstreams/833e160a-e382-46b4-82ad-fb2c8c995d62/content)
- [4] [WxTCmd](https://github.com/EricZimmerman/WxTCmd)
- [5] [Криміналістичні інструменти Eric Zimmerman](https://ericzimmerman.github.io/#!index.md)
- [6] [Zone.Identifier і Alternate Data Streams](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/6e3f7352-d11c-4d76-8c39-2516a9df36e8)
- [7] [Rifiuti2](https://github.com/abelcheung/rifiuti2)
- [8] [Volume Shadow Copy Service](https://learn.microsoft.com/en-us/windows/server/storage/file-server/volume-shadow-copy-service)
- [9] [ShadowCopyView](https://www.nirsoft.net/utils/shadow_copy_view.html)
- [10] [Операції резервного копіювання та відновлення реєстру в рамках VSS](https://learn.microsoft.com/en-us/windows/win32/vss/registry-backup-and-restore-operations-under-vss)
- [11] [Ключі реєстру для резервного копіювання та відновлення](https://learn.microsoft.com/en-us/windows/win32/backup/registry-keys-for-backup-and-restore)
- [12] [Проблема продуктивності Word у розташуванні AutoRecover](https://learn.microsoft.com/en-us/previous-versions/troubleshoot/microsoft-365/microsoft-365-apps/word/performance-issue-on-autorecover-location)
- [13] [Посібник з реагування на інциденти](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/final/en-us/microsoft-brand/documents/IR-Guidebook-Final.pdf)
- [14] [MS-SHLLINK: двійковий формат Shell Link](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/c3376b21-0931-45e4-b2fc-a48ac0e60d15)
- [15] [LECmd](https://github.com/EricZimmerman/LECmd)
- [16] [Криміналістичний аналіз USB MTP: ідентифікація артефактів ексфільтрації даних](https://studylib.net/doc/8690663/usb-devices-and-media-transfer-protocol)
- [17] [Записи журналу встановлення пристроїв SetupAPI](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/setupapi-device-installation-log-entries)
- [18] [USB Detective](https://usbdetective.com)
- [19] [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)
- [20] [PidTagClientSubmitTime](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/ca98145f-7f87-42b4-b0ef-124c6c6f8d83)
- [21] [PidTagConversationIndex](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/57f8de0f-5f53-423a-8947-7943dd959997)
- [22] [EntryID і пов’язані типи](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcdata/57e8bcbf-11d0-40fe-8833-5558bb9c0c89)
- [23] [PidTagMessageFlags](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcmsg/a0c52fe2-3014-43a7-942d-f43f6f91c366)
- [24] [PidTagLastVerbExecuted](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxomsg/87a8b6b8-59a4-4859-9dcd-8b0f36e3d729?redirectedfrom=MSDN)
- [25] [Пошук і перенесення файлів даних Outlook](https://support.microsoft.com/en-us/outlook/find-and-transfer-outlook-data-files-from-one-computer-to-another)
- [26] [Увімкнення Cached Exchange Mode](https://support.microsoft.com/en-us/outlook/turn-on-cached-exchange-mode)
- [27] [Синхронізовано лише підмножину елементів](https://learn.microsoft.com/en-us/troubleshoot/outlook/user-interface/only-subset-items-synchronized)
- [28] [Налаштування обмежень розміру файлів даних Outlook](https://learn.microsoft.com/en-us/microsoft-365-apps/outlook/data-files/configure-size-limit-outlook-data-files)
- [29] [Профілі - де Thunderbird зберігає дані користувача](https://support.mozilla.org/bm/kb/profiles-where-thunderbird-stores-user-data)
- [30] [Налаштування облікових записів Thunderbird і каталоги mbox](https://support.mozilla.org/en-US/kb/dangerous-directories-Thunderbird-account-settings)
- [31] [Інтерфейс IThumbnailCache](https://learn.microsoft.com/en-us/windows/win32/api/thumbcache/nn-thumbcache-ithumbnailcache)
- [32] [Thumbs Viewer](https://thumbsviewer.github.io)
- [33] [Thumbcache Viewer](https://thumbcacheviewer.github.io)
- [34] [Вулики реєстру](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives)
- [35] [Системний реєстр не створює резервну копію в RegBack](https://learn.microsoft.com/en-gb/troubleshoot/windows-client/installing-updates-features-roles/system-registry-no-backed-up-regback-folder)
- [36] [RegRipper 3.0](https://github.com/keydet89/RegRipper3.0)
- [37] [Windows Registry Recovery](https://www.mitec.cz/wrr.html)
- [38] [Віддалене редагування реєстру](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remotely-edit-the-registry)
- [39] [Технічний огляд паролів](https://learn.microsoft.com/en-us/windows-server/security/kerberos/passwords-technical-overview)
- [40] [PECmd](https://github.com/EricZimmerman/PECmd)
- [41] [Артефакти Superfetch](https://kb.binalyze.com/air/features/acquisition/supported-evidence/windows-collections-detail/superfetch)
- [42] [srum-dump](https://github.com/MarkBaggett/srum-dump)
- [43] [AppCompatCacheParser](https://github.com/EricZimmerman/AppCompatCacheParser)
- [44] [AmcacheParser](https://github.com/EricZimmerman/AmcacheParser)
- [45] [RecentFileCacheParser](https://github.com/EricZimmerman/RecentFileCacheParser)
- [46] [Формат файлу журналу подій](https://learn.microsoft.com/en-us/windows/win32/eventlog/event-log-file-format)
- [47] [Ключ реєстру Eventlog](https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key)
- [48] [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.5)
- [49] [Властивість події TimeCreated](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-timecreated-systempropertiestype-element)
- [50] [Подія 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- [51] [Подія 4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- [52] [Подія 4634](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4634)
- [53] [Подія 4647](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4647)
- [54] [Подія 4672](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672)
- [55] [MS-ERREF: значення NTSTATUS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55)
- [56] [Подія 4616](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4616)
- [57] [Усунення неполадок неочікуваних перезавантажень за допомогою системних журналів подій](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [58] [Усунення неполадок із завершенням роботи в процесі](https://learn.microsoft.com/en-us/troubleshoot/windows-server/installing-updates-features-roles/troubleshoot-error-shutdown-in-process)
- [59] [Криміналістичний аналіз USB-накопичувачів у Windows 10](https://www.researchgate.net/publication/318514858_USB_Storage_Device_Forensics_for_Windows_10)
- [60] [Типи входу у Windows](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)
- [61] [Event Log Explorer](https://eventlogxp.com)
- [62] [Подія 1102](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102)
- [63] [Модератор фонової активності](https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/Background-activity-moderator.html)
- [64] [Реєстр - RecentApps](https://artefacts.help/windows_registry_recentapps.html)
- [65] [Quick Print припиняє друкувати PDF-вкладення в Outlook Desktop](https://support.microsoft.com/en-gb/office/quick-print-stops-printing-pdf-attachments-in-outlook-desktop-512fdeb0-6a88-4e6c-9285-cf957290aad2)
- [66] [Файли реєстру Windows](https://winreg-kb.readthedocs.io/en/latest/sources/windows-registry/Files.html)
- [67] [Kernel PST Viewer](https://www.nucleustechnologies.com/es/visor-de-pst.html)
- [68] [Kernel OST Viewer](https://www.nucleustechnologies.com/ost-viewer.html)
- [69] [RegQueryInfoKeyA](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeya)
- [70] [Заборона повернення видалених програм під час оновлення](https://learn.microsoft.com/en-us/windows/application-management/remove-provisioned-apps-during-update)
- [71] [NIST CFTT: результати тестування FTK і Registry Viewer](https://www.dhs.gov/sites/default/files/publications/test_results_nist_windows_registry_forensic_tool_ftk_7.0.0.163_registry_viewer_2.0.0.7_april_2019.pdf)
- [72] [База даних встановлених служб](https://learn.microsoft.com/en-us/windows/win32/services/database-of-installed-services)
- [73] [Завдання](https://learn.microsoft.com/en-us/windows/win32/taskschd/tasks)
- [74] [Заплановані завдання завершуються помилкою «Служба Task Scheduler недоступна»](https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/task-schedular-service-is-not-available)
- [75] [Навігація базою даних Windows Mail](https://eprints.whiterose.ac.uk/133161/1/Navigating_the_Windows_Mail_database_accepted.pdf)
- [76] [RFC 5322: формат інтернет-повідомлень](https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.4)
{{#include ../../../banners/hacktricks-training.md}}
