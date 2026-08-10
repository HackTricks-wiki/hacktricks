# Артефакти Windows

## Загальні артефакти Windows

### Сповіщення Windows 10

База даних сповіщень для кожного користувача зберігається в `%LOCALAPPDATA%\Microsoft\Windows\Notifications` (наприклад, `C:\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`). У ранніх випусках Windows 10 використовувався файл `appdb.dat`; Anniversary Update (1607) представив `wpndatabase.db`. База даних SQLite містить таблицю `Notification` із даними сповіщень і полями часу, хоча термін зберігання та доступні дані залежать від випуску й політики очищення.<sup>[[3]](#references)</sup>

### Timeline

Windows Timeline — це функція історії активності, яка може містити записи для підтримуваних застосунків, документів та іншої активності користувача; охоплення залежить від застосунку та версії Windows.<sup>[[4]](#references)</sup>

База даних розташована за адресою `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Її можна відкрити за допомогою SQLite або розібрати за допомогою [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd), а його вивід можна переглянути за допомогою [**Timeline Explorer**](https://ericzimmerman.github.io/#!index.md).<sup>[[4]](#references)[[5]](#references)</sup>

### ADS (Alternate Data Streams)

Файли, завантажені з-за меж локальної зони довіри, можуть містити **альтернативний потік даних `Zone.Identifier`**, який записує інформацію про зону та може містити метадані джерела, наприклад URL. Його наявність і поля залежать від програми-джерела та системної політики.<sup>[[6]](#references)</sup>

## **Резервні копії файлів**

### Кошик

У Vista та новіших версіях **Кошик** можна знайти в папці **`$Recycle.bin`** у корені диска (наприклад, `C:\$Recycle.bin`).\
Коли файл видаляється в цій папці, створюються два конкретні файли:

- `$I{id}`: Інформація про файл, зокрема час видалення та початковий шлях
- `$R{id}`: Вміст файлу

![Резервні копії файлів — Кошик: $R{id}: Вміст файлу](<../../../images/image (1029).png>)

Маючи ці файли, можна використати [**Rifiuti2**](https://github.com/abelcheung/rifiuti2), щоб отримати початковий шлях і час видалення (використовуйте версію, що відповідає цільовому випуску Windows).<sup>[[7]](#references)</sup>
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![File Backups - Recycle Bin: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Тіньові копії томів

Volume Shadow Copy Service (VSS) може створювати тіньові копії томів на певний момент часу, коли файли використовуються; тіньова копія не є заміною forensic image.<sup>[[8]](#references)</sup>

Метадані копії зазвичай пов'язані з `\System Volume Information` у корені тому та містять ідентифікатори, які відрізняються залежно від системи:

![Recycle Bin - Volume Shadow Copies: Ці резервні копії зазвичай розташовані в System Volume Information у корені файлової системи, а ім'я складається з UID, показаних на...](<../../../images/image (94).png>)

Після монтування image за допомогою відповідного forensic mounter [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) може перелічити доступні VSS snapshots і переглядати або копіювати файли з них.<sup>[[9]](#references)</sup>

![Recycle Bin - Volume Shadow Copies: Після монтування forensic image за допомогою ArsenalImageMounter інструмент ShadowCopyView можна використовувати для перевірки shadow copy і навіть вилучення файлів...](<../../../images/image (576).png>)

Конфігурація registry writer для VSS містить `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore`, де можна вказати файли та ключі, виключені з backup:<sup>[[10]](#references)[[11]](#references)</sup>

![Recycle Bin - Volume Shadow Copies: Запис реєстру HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore містить файли та ключі, які не потрібно включати до backup](<../../../images/image (254).png>)

Ключ `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` також містить конфігурацію служби VSS.<sup>[[8]](#references)</sup>

### Автоматично збережені файли Office

Розташування AutoRecover відрізняються залежно від застосунку Office, версії та конфігурації. Для Word Microsoft вказує `%APPDATA%\Microsoft\Word` як розташування за замовчуванням; перевірте налаштування застосунку, щоб визначити активний шлях.<sup>[[12]](#references)</sup>

## Елементи Shell

Елемент shell — це елемент, який містить інформацію про спосіб доступу до іншого файлу.

### Останні документи (LNK)

Windows зазвичай створює shortcuts для нещодавніх елементів, коли користувач відкриває елемент або іншим чином отримує до нього доступ:

- Win7-Win10: `%APPDATA%\Microsoft\Windows\Recent\`
- Office: `%APPDATA%\Microsoft\Office\Recent\`

Доступ до папки також може створювати links для папки та пов'язаних батьківських папок.

Ці link files можуть містити тип цільового об'єкта, MAC times цільового об'єкта, інформацію про том і шлях до цільового об'єкта. Ці метадані можуть допомогти ідентифікувати видалений цільовий об'єкт, але сам artifact не є доказом того, що цільовий об'єкт було відкрито певним користувачем.<sup>[[13]](#references)[[14]](#references)</sup>

Власні filesystem timestamps LNK і вбудовані timestamps цільового об'єкта є різними. Не інтерпретуйте створення link як перше використання або зміну link як останнє використання без підтвердження іншими artifacts; формат зберігає timestamps цільового об'єкта окремо від timestamps link file.<sup>[[13]](#references)[[14]](#references)</sup>

Посилання на наявний [**LinkParser**](http://4discovery.com/our-tools/) збережено як історичний варіант, але під час перевірки його документація була недоступна. Для документованого command-line parser використовуйте [**LECmd**](https://github.com/EricZimmerman/LECmd).<sup>[[15]](#references)</sup>

Ці tools зазвичай показують два набори timestamps:

- **Timestamps цільового об'єкта:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **Timestamps link file:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

Перший набір стосується цільового об'єкта, другий — самого LNK file. Інтерпретуйте обидва набори з урахуванням документації parser і контексту файлової системи.<sup>[[14]](#references)[[15]](#references)</sup>

Отримати ту саму інформацію можна за допомогою Windows CLI tool: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd).<sup>[[15]](#references)</sup>
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
У цьому випадку інформація буде збережена у CSV-файлі.

### Jumplists

Jump Lists — це списки нещодавніх або пов'язаних із завданнями елементів для окремих застосунків, які можуть бути автоматичними або користувацькими.<sup>[[13]](#references)</sup>

Автоматичні Jump Lists зберігаються в `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` і використовують такі назви, як `{id}.automaticDestinations-ms`, де ID ідентифікує застосунок.

Користувацькі Jump Lists зберігаються в `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\`; застосунок визначає, які записи завдань або елементів він створює.

Часи створення та модифікації файлової системи описують файл Jump List, а не автоматично перший і останній доступ до кожного переліченого об'єкта. Співвідносіть розібрані записи з часовими мітками файлу та іншими артефактами.<sup>[[13]](#references)</sup>

Переглядати Jump Lists можна за допомогою [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).<sup>[[5]](#references)</sup>

![Нещодавні документи (LNK) - Jumplists: переглядати jumplists можна за допомогою JumplistExplorer](<../../../images/image (168).png>)

(_Зверніть увагу, що часові мітки, надані JumplistExplorer, стосуються самого файлу jumplist_)

### Shellbags

[**Перейдіть за цим посиланням, щоб дізнатися, що таке shellbags.**](interesting-windows-registry-keys.md#shellbags)

## Використання Windows USB

Використання USB іноді можна підтвердити артефактами, створеними під час доступу до файлів зі змінних носіїв, зокрема:

- Windows Recent Folder
- Microsoft Office Recent Folder
- Jumplists

Такі інструменти, як [**USBDetective**](https://usbdetective.com), співвідносять ці артефакти із записами про USB-пристрої, але доступність артефактів залежить від версії Windows і застосунку.<sup>[[18]](#references)</sup>

У тестуванні робочих процесів MTP, задокументованому для Windows XP і Windows 7, деякі LNK-файли вказували на папку `WPDNSE`, а не на початковий шлях.<sup>[[16]](#references)</sup>

![Shellbags - Використання Windows USB: зверніть увагу, що деякі LNK-файли замість початкового шляху вказують на папку WPDNSE](<../../../images/image (218).png>)

У цьому дослідженні спостерігалися копії в `%LOCALAPPDATA%\Temp\WPDNSE\{FolderGUID}`; у тестах тимчасовий вміст не зберігався після перезапуску, а GUID можна було співвіднести з даними shellbag. Розглядайте це як поведінку, що залежить від ОС, пристрою та застосунку, а не як універсальне правило.<sup>[[16]](#references)</sup>

### Інформація в реєстрі

[Перегляньте цю сторінку, щоб дізнатися](interesting-windows-registry-keys.md#usb-information), які ключі реєстру містять цікаву інформацію про підключені USB-пристрої.

### setupapi

У Vista та новіших версіях перевіряйте `C:\Windows\inf\setupapi.dev.log` на наявність активності зі встановлення пристроїв. Заголовки секцій містять часові мітки `Section start`; вони документують обробку встановлення, тому їх слід співвідносити з іншими доказами підключення, а не розглядати як точний час фізичного підключення.<sup>[[17]](#references)</sup>

![Інформація в реєстрі - setupapi: перевірте файл C: Windows inf setupapi.dev.log, щоб отримати часові мітки підключення USB (виконайте пошук за Section start)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) можна використовувати для отримання інформації про USB-пристрої, підключені до образу.<sup>[[18]](#references)</sup>

![setupapi - USB Detective: USBDetective можна використовувати для отримання інформації про USB-пристрої, підключені до образу](<../../../images/image (452).png>)

### Plug and Play Cleanup

Заплановане завдання `Plug and Play Cleanup` видаляє застарілі версії драйверів. Визначення завдання Windows 10, задокументоване Adam Harrison, також націлене на драйвери, неактивні протягом 30 днів, тому докази використання драйверів змінних пристроїв можуть бути очищені; перед узагальненням цієї поведінки перевірте локальне визначення завдання та версію Windows.<sup>[[1]](#references)</sup>

Завдання розташоване за таким шляхом: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

**Ключові компоненти та параметри завдання:**

- **pnpclean.dll**: ця DLL відповідає за фактичний процес очищення.
- **UseUnifiedSchedulingEngine**: має значення `TRUE`, що вказує на використання загального механізму планування завдань.
- **MaintenanceSettings**:
- **Period ('P1M')**: вказує Task Scheduler запускати завдання очищення щомісяця під час регулярного Automatic maintenance.
- **Deadline ('P2M')**: вказує Task Scheduler, якщо завдання не виконується протягом двох послідовних місяців, запустити його під час emergency Automatic maintenance.

Ця конфігурація планує регулярне обслуговування та повторні спроби після послідовних невдалих запусків; точні XML і поведінка залежать від версії.<sup>[[1]](#references)</sup>

**Докладніше:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html).<sup>[[1]](#references)</sup>

## Електронні листи

Електронні листи містять **2 цікаві частини: заголовки та вміст** листа. У **заголовках** можна знайти таку інформацію:

- **Хто** надіслав листи (адреса електронної пошти, IP-адреса, поштові сервери, які перенаправили лист)
- **Коли** було надіслано лист

Крім того, заголовки `References` і `In-Reply-To` можуть містити ID повідомлень, які використовуються для пов'язування відповідей із розмовою.<sup>[[76]](#references)</sup>

![Plug and Play Cleanup - Електронні листи: коли було надіслано лист](<../../../images/image (593).png>)

### Windows Mail App

Цей застосунок зберігає вміст електронних листів у допоміжних текстових або HTML-файлах за такими шляхами, як `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`; точна структура нумерованих папок і файлів може відрізнятися залежно від артефакту.<sup>[[75]](#references)</sup>

**Метадані** електронних листів і **контакти** можна знайти в **базі даних ESE** `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`.<sup>[[75]](#references)</sup>

`store.vol` використовує формат Extensible Storage Engine (ESE). Працюйте з копією та використовуйте ESE parser, наприклад [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html); якщо інструмент потребує суфікса `.edb`, перейменуйте лише копію та перевірте схему таблиць, перш ніж покладатися на таблицю `Message`.<sup>[[19]](#references)[[75]](#references)</sup>

### Microsoft Outlook

Під час перевірки властивостей Outlook MAPI канонічні властивості включають:

- `PidTagClientSubmitTime`: час UTC, коли клієнт надіслав повідомлення.
- `PidTagConversationIndex`: відносна позиція повідомлення в ланцюжку розмови.
- `PidTagEntryId`: ідентифікатор об'єкта повідомлення.
- `PidTagMessageFlags`: прапорці стану, наприклад надіслано, прочитано, не прочитано або наявність вкладень.
- `PidTagLastVerbExecuted`: остання операція, записана для повідомлення, наприклад відкриття, відповідь або пересилання.<sup>[[20]](#references)[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Розташування файлів даних Outlook залежить від версії та типу облікового запису. Microsoft документує такі поширені розташування PST/OST-файлів:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Шлях реєстру `HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` може ідентифікувати профіль Outlook і пов'язану конфігурацію файлів даних.

PST-файли можуть містити повідомлення, контакти, дані календаря та інші елементи Outlook. Копію можна переглянути за допомогою [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).<sup>[[25]](#references)[[67]](#references)</sup>

![Windows Mail App - Microsoft Outlook: PST-файл можна відкрити за допомогою інструмента Kernel PST Viewer](<../../../images/image (498).png>)

### Microsoft Outlook OST Files

**OST-файл** — це локальний кеш для облікових записів Exchange або Microsoft 365; Cached Exchange Mode не застосовується до облікових записів POP або IMAP. Період зберігання даних в автономному режимі можна налаштувати, і за замовчуванням він часто становить 12 місяців, тоді як обмеження розміру PST/OST є окремими параметрами, які також можна налаштувати. Для перегляду OST-файлу можна використовувати [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html).<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[68]](#references)</sup>

### Отримання вкладень

Втрачені вкладення можна спробувати відновити з таких розташувань:

- Для застарілих конфігурацій Outlook/IE: `%LOCALAPPDATA%\Temporary Internet Files\Content.Outlook`
- Для новіших конфігурацій Outlook/IE11: `%LOCALAPPDATA%\Microsoft\Windows\INetCache\Content.Outlook`.<sup>[[65]](#references)</sup>

### Thunderbird MBOX Files

**Thunderbird** зберігає дані профілю в `%APPDATA%\Thunderbird\Profiles`; поштові папки зазвичай використовують файли mbox без розширення в каталогах `Mail` або `ImapMail`, що належать окремим обліковим записам.<sup>[[29]](#references)[[30]](#references)</sup>

### Мініатюри зображень

- **Windows XP**: попередні перегляди мініатюр зазвичай зберігалися в окремих для кожної папки файлах `thumbs.db`.
- **Мережеві папки**: файл `thumbs.db` усе ще може створюватися для UNC-папки, якщо ввімкнено відповідну поведінку мініатюр; не припускайте, що кожна версія Windows або політика створює такий файл.
- **Windows Vista і новіші версії**: системний кеш мініатюр централізовано зберігається в `%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer` у файлах, таких як **thumbcache_xxx.db**. [**Thumbsviewer**](https://thumbsviewer.github.io) може аналізувати застарілі `Thumbs.db`, а [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) — сучасні бази даних кешу мініатюр.<sup>[[31]](#references)[[32]](#references)[[33]](#references)</sup>

### Інформація в реєстрі Windows

Реєстр Windows, у якому зберігаються дані конфігурації системи та користувачів, міститься у файлах hive за такими шляхами:

- `%WINDIR%\System32\Config` для машинних hive, що підтримують різні підрозділи `HKEY_LOCAL_MACHINE`.
- `%USERPROFILE%\NTUSER.DAT` для hive користувача `HKEY_CURRENT_USER`.
- Деякі старі інсталяції Windows містять копії в `%WINDIR%\System32\Config\RegBack\`; Windows 10 версії 1803 і новіших не заповнює цей каталог автоматично, якщо не ввімкнено періодичне резервне копіювання.<sup>[[34]](#references)[[35]](#references)</sup>
- Дані shell і реєстрації класів для окремих користувачів також зазвичай зберігаються в `%LOCALAPPDATA%\Microsoft\Windows\UsrClass.dat` у сучасних версіях Windows.<sup>[[34]](#references)[[66]](#references)</sup>

### Інструменти

Деякі інструменти корисні для аналізу registry hives; перед використанням результату перевіряйте підтримувані формати hive та версії кожного інструмента:

- **Registry Editor**: встановлений у Windows. Це GUI для навігації реєстром Windows поточного сеансу.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): дає змогу завантажити файл реєстру та переміщатися ним за допомогою GUI. Також містить Bookmarks, які виділяють ключі з цікавою інформацією.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): також має GUI для навігації завантаженим реєстром і містить plugins, які виділяють цікаву інформацію в завантаженому реєстрі.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): ще один GUI-застосунок, здатний видобувати інформацію із завантаженого registry hive.<sup>[[5]](#references)[[36]](#references)[[37]](#references)</sup>

### Відновлення видаленого елемента

Видалені комірки hive можуть залишатися, доки їхній простір не буде повторно використано, але відновлення залежить від стану hive та parser; розглядайте відновлені видалені ключі як докази, що потребують перевірки, а не як гарантовані записи.

### Час останнього запису

Ключі реєстру містять часову мітку останнього запису; Windows надає її для ключа або будь-якого з його записів значень, тому значення не обов'язково має власну незалежну часову мітку модифікації.<sup>[[69]](#references)</sup>

### SAM

Hive **SAM** містить дані локальних облікових записів користувачів і груп, зокрема хеші паролів, захищені матеріалом boot-key системи.<sup>[[38]](#references)[[39]](#references)</sup>

У `SAM\Domains\Account\Users` можна отримати ідентифікатори облікових записів і деякі поля входу та політик. Для offline hash extraction також потрібен hive `SYSTEM`, щоб відновити відповідний матеріал boot-key.<sup>[[38]](#references)[[39]](#references)</sup>

### Цікаві записи в реєстрі Windows


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Виконані програми

### Основні процеси Windows

Наявна [публікація про поширені процеси Windows](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) зберігається як додатковий матеріал; твердження про поведінку процесів слід підтверджувати актуальною документацією Windows і локальними доказами.<sup>[[2]](#references)</sup>

### Нещодавні застосунки Windows

У версіях Windows 10, де цей артефакт доступний, `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps` містить підрозділи для окремих застосунків із такими полями, як час останнього використання та кількість запусків; у пізніших випусках артефакт було видалено, тому перевіряйте цільову збірку.<sup>[[64]](#references)</sup>

### BAM (Background Activity Moderator)

У системах, де доступний Background Activity Moderator, перевіряйте `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` або новіший шлях `...\bam\State\UserSettings\{SID}`. Значення індексуються за SID користувача й можуть містити шляхи відстежуваних виконуваних файлів і дані виконання, подібні до FILETIME; артефакт залежить від версії, тому його слід підтверджувати іншими доказами.<sup>[[63]](#references)</sup>

### Windows Prefetch

Prefetching кешує ресурси та метадані запуску, щоб програми могли швидше запускатися.

Prefetch-файли зберігаються як файли `.pf` у `C:\Windows\Prefetch`; формат, термін зберігання та обмеження кількості файлів залежать від версії Windows. Microsoft документує збереження останніх восьми часів виконання та до 1024 файлів у Windows 8 і новіших версіях, тому не слід узагальнювати старі описи фіксованих обмежень.<sup>[[13]](#references)</sup>

Назва файлу зазвичай має формат `{program_name}-{hash}.pf`, де hash обчислюється на основі контексту виконання, наприклад шляху та аргументів; Windows 10 і новіші версії можуть стискати файл. Наявність файлу є корисним доказом виконання, але сама по собі не доводить, що програму запустив користувач, тому її слід співвідносити з іншими артефактами.<sup>[[13]](#references)</sup>

Для перевірки цих файлів можна використовувати [**PECmd.exe**](https://github.com/EricZimmerman/PECmd), який документує аналіз каталогів, виведення у форматах CSV/HTML і підтримку декомпресії відповідних Prefetch-файлів Windows 10.<sup>[[40]](#references)</sup>
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superfetch/SysMain** доповнює Prefetch, використовуючи історичні шаблони використання для покращення завантаження. У системах, які їх створюють, файли баз даних зазвичай знаходяться в `C:\Windows\Prefetch\Ag*.db`; їхній формат і наявність залежать від версії.<sup>[[41]](#references)</sup>

Ці бази даних можуть містити назви застосунків, кількість використань, доступні файли або томи, шляхи та часові діапазони, але їх не слід розглядати як точний журнал виконання.<sup>[[41]](#references)</sup>

Посилання на наявний [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) збережено як можливий parser; перед використанням перевірте його поточну доступність і підтримуваний формат виводу за документацією tool.

### SRUM

**System Resource Usage Monitor** (SRUM) записує використання ресурсів застосунками та користувачами. Цю функцію було представлено у Windows 8, а дані зберігаються в ESE database `C:\Windows\System32\sru\SRUDB.dat`.<sup>[[13]](#references)</sup>

Вона надає таку інформацію:

- AppID and Path
- User/SID associated with the record
- Sent Bytes
- Received Bytes
- Network Interface
- Connection duration
- Process duration

Періодичність збору та зберігання даних залежать від реалізації; не слід вважати, що кожен запис відповідає точному 60-хвилинному інтервалу виконання.<sup>[[13]](#references)</sup>

Ви можете отримувати й переглядати дані за допомогою [**srum_dump**](https://github.com/MarkBaggett/srum-dump), використовуючи параметри, задокументовані в поточній версії tool.<sup>[[42]](#references)</sup>
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -o C:\Users\student\Desktop\srum --NO_CONFIRM
```
### AppCompatCache (ShimCache)

**AppCompatCache**, also known as **ShimCache**, is part of the Windows application-compatibility infrastructure and records file metadata for compatibility decisions. The hive path, record format, retained capacity, and fields vary by Windows release; on modern Windows, ShimCache alone cannot prove that a user executed a file. Parse the relevant `SYSTEM` hive with the [**AppCompatCacheParser tool**](https://github.com/EricZimmerman/AppCompatCacheParser) and corroborate its output with execution artifacts.<sup>[[13]](#references)[[43]](#references)</sup>

![SRUM - AppCompatCache (ShimCache): Для аналізу збереженої інформації рекомендується використовувати інструмент AppCompatCacheParser](<../../../images/image (75).png>)

### Amcache

The **Amcache.hve** file is a registry hive that inventories applications and files observed by Windows. It is typically found at `C:\Windows\AppCompat\Programs\Amcache.hve`.

It can contain associated and unassociated file entries, paths, and SHA1 values, but its presence is inventory evidence and does not by itself prove that a process executed.<sup>[[13]](#references)[[44]](#references)</sup>

To extract and analyze **Amcache.hve**, use the [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser) tool. This command parses the hive and writes CSV output.<sup>[[44]](#references)</sup>

For example:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Серед згенерованих CSV-файлів `Amcache_Unassociated file entries` може бути корисним під час дослідження файлів, не пов’язаних із розпізнаною програмою.<sup>[[44]](#references)</sup>

### RecentFileCache

У системах Windows 7 файл `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` може містити інформацію про нещодавно виявлені бінарні файли; його доступність і семантика залежать від версії.

Для аналізу цього файлу можна використати [**RecentFileCacheParser**](https://github.com/EricZimmerman/RecentFileCacheParser).<sup>[[45]](#references)</sup>

### Scheduled tasks

Артефакти запланованих завдань можна знайти в `C:\Windows\System32\Tasks` для сучасних завдань і в `C:\Windows\Tasks` у файлах `.job` для застарілих завдань; аналізуйте формат визначення завдання, що відповідає версії ОС.<sup>[[73]](#references)[[74]](#references)</sup>

### Services

База даних Service Control Manager розташована в `SYSTEM\CurrentControlSet\Services` (для автономного SYSTEM hive перевірте відповідний ключ control-set); вона містить конфігурацію служб і драйверів, зокрема шляхи до виконуваних файлів і типи запуску.<sup>[[72]](#references)</sup>

### **Windows Store**

Встановлені Windows Store applications можуть бути представлені в `\ProgramData\Microsoft\Windows\AppRepository\`, зокрема базою даних **`StateRepository-Machine.srd`**. Схема та шляхи відрізняються залежно від випуску Windows.<sup>[[71]](#references)</sup>

База даних може містити ідентифікатори програм, номери пакетів і відображувані назви. Пропуски в ідентифікаторах самі по собі не доводять, що програму було видалено; підтверджуйте висновки станом пакетів і registry.

Реєстрації пакетів також можуть відображатися в `HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`. Microsoft документує version-specific subkey `Deprovisioned` для видалених provisioned apps; не припускайте, що subkey `Deleted` існує в кожній збірці.<sup>[[70]](#references)</sup>

## Windows Events

Залежно від provider, Windows events можуть містити:

- Що сталося
- Часову мітку `TimeCreated`, яку потрібно інтерпретувати з урахуванням event schema і часового контексту host
- Задіяних users
- Задіяні hosts (hostname, IP)
- Доступні assets (files, folders, printers або services).<sup>[[49]](#references)</sup>

До Windows Vista журнали подій зазвичай використовували legacy binary format у `C:\Windows\System32\config`; Vista та новіші версії використовують Windows Event Log format, зазвичай у `C:\Windows\System32\winevt\Logs`, де файли `.evtx` містять дані подій, відображені у форматі XML.<sup>[[46]](#references)[[47]](#references)</sup>

SYSTEM registry зберігає конфігурацію channel у **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**, зокрема налаштований шлях до файлу та параметри зберігання.<sup>[[47]](#references)</sup>

Їх можна переглядати за допомогою Windows Event Viewer (**`eventvwr.msc`**) або таких tools, як [**Event Log Explorer**](https://eventlogxp.com) і [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md).<sup>[[5]](#references)[[48]](#references)[[61]](#references)</sup>

## Understanding Windows Security Event Logging

У Vista та новіших версіях channel Security зазвичай зберігається в `C:\Windows\System32\winevt\Logs\Security.evtx`. Його максимальний розмір і політика зберігання налаштовуються; за circular logging старі записи можуть бути перезаписані після досягнення файлом установленого ліміту. Channel може реєструвати події автентифікації, виходу із системи, привілеїв, audit policy та доступу до об’єктів, якщо відповідний auditing увімкнено.<sup>[[46]](#references)[[47]](#references)</sup>

### Key Event IDs for User Authentication:

- **Event ID 4624**: Успішний logon облікового запису.<sup>[[50]](#references)</sup>
- **Event ID 4625**: Невдалий logon облікового запису.<sup>[[51]](#references)</sup>
- **Event ID 4634**: Сеанс logon було завершено.<sup>[[52]](#references)</sup>
- **Event ID 4647**: Користувач ініціював logoff.<sup>[[53]](#references)</sup>
- **Event ID 4672**: Новому logon було призначено спеціальні привілеї; це часто трапляється для system і administrator accounts, тому саме по собі не є доказом malicious activity.<sup>[[54]](#references)</sup>

#### Logon types commonly recorded in 4624, 4625, 4634, and 4647:

- **Interactive (2)**: Інтерактивний local logon.
- **Network (3)**: Доступ до shared resource.
- **Batch (4)**: Logon batch process.
- **Service (5)**: Logon service.
- **Unlock (7)**: Розблокування workstation.
- **NetworkCleartext (8)**: Network logon, під час якого credentials передаються до authentication package у cleartext.
- **NewCredentials (9)**: Logon із використанням наданих alternate credentials для outbound connections.
- **RemoteInteractive (10)**: Logon через Remote Desktop або Terminal Services.
- **CachedInteractive (11)**: Інтерактивний logon із використанням cached domain credentials.
- **CachedRemoteInteractive (12)**: Cached remote-interactive logon.
- **CachedUnlock (13)**: Розблокування з використанням cached credentials.<sup>[[50]](#references)[[51]](#references)</sup>

#### Status and Sub Status Codes for EventID 4625:

- **0xC0000064**: Такого user не існує.
- **0xC000006A**: Правильне user name, але неправильний password.
- **0xC0000234**: Account заблоковано.
- **0xC0000072**: Account вимкнено.
- **0xC000006F**: Logon поза дозволеними годинами.
- **0xC0000070**: Порушення обмеження workstation.
- **0xC0000193**: Account expired.
- **0xC0000071**: Password expired.
- **0xC0000133**: Різниця в часі між client і server занадто велика.
- **0xC0000224**: Account повинен змінити свій password.
- **0xC0000225**: `STATUS_NOT_FOUND`; сам код не ідентифікує system bug або attack.
- **0xC000015B**: Запитаний тип logon не надано account.<sup>[[51]](#references)[[55]](#references)</sup>

#### EventID 4616:

- **Time Change**: Системний час було змінено. Багато events відображають штатну корекцію time service, тому перед трактуванням цього як tampering зіставте actor і джерело часу.<sup>[[56]](#references)</sup>

#### Event IDs 12, 13, 1074, 6005, 6006, 6008, and 6009:

- **Power and service context**: Event 12 реєструє запуск OS, 13 — завершення роботи OS, 1074 — заплановане завершення роботи або restart, 6008 вказує на неочікуване завершення роботи, а 6009 реєструє версію Windows під час boot. Events 6005 і 6006 відповідно вказують на запуск і зупинку Event Log service; самі по собі вони не доводять запуск і завершення роботи OS.<sup>[[57]](#references)[[58]](#references)</sup>

#### EventID 1102:

- **Log Deletion**: Event 1102 реєструє очищення Security audit log; досліджуйте actor і пов’язані events, а не робіть висновок про intent лише на підставі цієї події.<sup>[[62]](#references)</sup>

#### EventIDs for USB Device Tracking:

- **20001 / 20003**: Events встановлення device від `UserPnp`, які можуть допомогти встановити перше використання або activity встановлення.
- **10000 / 10100**: Events від `DriverFrameworks-UserMode`, які можуть супроводжувати activity device.
- **Event ID 112**: Activity `DeviceSetupManager/Admin`, що може надати timestamps, пов’язані з підключенням.
- Provider, channel і semantics events відрізняються залежно від версії Windows; перевіряйте provider name і event payload перед визначенням їхнього значення.<sup>[[59]](#references)</sup>

Практичні приклади типів logon і пов’язаного з ними credential material наведено в [детальному guide від Altered Security](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).<sup>[[60]](#references)</sup>

Деталі events, зокрема тип logon, status, substatus, source address і process fields, надають контекст для Event ID 4625; status code або повторювана pattern невдалих спроб є напрямом для investigation, а не висновком.<sup>[[51]](#references)[[55]](#references)</sup>

### Recovering Windows Events

Оскільки журнали подій зазвичай працюють у circular mode, записи, перезаписані logger, можуть бути невідновними. Збережіть forensic image або working copy перед взаємодією з live system; використовуйте validated parser або carver, наприклад **Bulk_extractor**, лише після підтвердження, що версія tool підтримує цільові дані `.evtx`, і не від’єднуйте працюючу system лише заради спроби відновити events.<sup>[[46]](#references)</sup>

### Identifying Common Attacks via Windows Events

Практичний довідник event IDs див. за наявним посиланням [Red Team Recipe](https://redteamrecipe.com/event-codes/) і перевіряйте його приклади за наведеною вище provider documentation.

#### Brute Force Attacks

Зіставляйте повторювані невдалі спроби Event ID 4625 із подальшим успішним 4624, типом logon, status, source і контекстом account; ця послідовність є indicator для investigation, а не доказом attack.<sup>[[50]](#references)[[51]](#references)</sup>

#### Time Change

Event ID 4616 реєструє зміни системного часу, які можуть ускладнити аналіз timeline; порівнюйте його з evidence time service і host.<sup>[[56]](#references)</sup>

#### USB Device Tracking

USB event IDs залежать від provider; зіставляйте `UserPnp` 20001/20003, `DriverFrameworks-UserMode` 10000/10100 і `DeviceSetupManager/Admin` 112 з артефактами SetupAPI та registry.<sup>[[17]](#references)[[59]](#references)</sup>

#### System Power Events

Використовуйте 12/13/1074/6008/6009 для контексту запуску OS, завершення роботи, restart і неочікуваного вимкнення живлення; 6005/6006 позначають запуск/зупинку Event Log service.<sup>[[57]](#references)[[58]](#references)</sup>

#### Log Deletion

Security Event ID 1102 реєструє очищення Security audit log; його слід зіставляти з відповідальним account і process.<sup>[[62]](#references)</sup>

## References

- [1] [Очищення Windows Plug and Play](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)
- [2] [jonahacks.medium.com - Дослідження поширених Windows processes](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)
- [3] [Цифровий forensic view сповіщень Windows 10](https://iconline.ipleiria.pt/server/api/core/bitstreams/833e160a-e382-46b4-82ad-fb2c8c995d62/content)
- [4] [WxTCmd](https://github.com/EricZimmerman/WxTCmd)
- [5] [Forensic tools Eric Zimmerman](https://ericzimmerman.github.io/#!index.md)
- [6] [Zone.Identifier і Alternate Data Streams](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/6e3f7352-d11c-4d76-8c39-2516a9df36e8)
- [7] [Rifiuti2](https://github.com/abelcheung/rifiuti2)
- [8] [Volume Shadow Copy Service](https://learn.microsoft.com/en-us/windows/server/storage/file-server/volume-shadow-copy-service)
- [9] [ShadowCopyView](https://www.nirsoft.net/utils/shadow_copy_view.html)
- [10] [Операції backup і restore registry у VSS](https://learn.microsoft.com/en-us/windows/win32/vss/registry-backup-and-restore-operations-under-vss)
- [11] [Registry keys для backup і restore](https://learn.microsoft.com/en-us/windows/win32/backup/registry-keys-for-backup-and-restore)
- [12] [Проблема продуктивності Word в AutoRecover location](https://learn.microsoft.com/en-us/previous-versions/troubleshoot/microsoft-365/microsoft-365-apps/word/performance-issue-on-autorecover-location)
- [13] [Incident Response Guidebook](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/final/en-us/microsoft-brand/documents/IR-Guidebook-Final.pdf)
- [14] [MS-SHLLINK: Shell Link Binary File Format](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/c3376b21-0931-45e4-b2fc-a48ac0e60d15)
- [15] [LECmd](https://github.com/EricZimmerman/LECmd)
- [16] [USB MTP Forensics: Виявлення артефактів Data Exfiltration](https://studylib.net/doc/8690663/usb-devices-and-media-transfer-protocol)
- [17] [Записи журналу встановлення device SetupAPI](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/setupapi-device-installation-log-entries)
- [18] [USB Detective](https://usbdetective.com)
- [19] [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)
- [20] [PidTagClientSubmitTime](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/ca98145f-7f87-42b4-b0ef-124c6c6f8d83)
- [21] [PidTagConversationIndex](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/57f8de0f-5f53-423a-8947-7943dd959997)
- [22] [EntryID і Related Types](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcdata/57e8bcbf-11d0-40fe-8833-5558bb9c0c89)
- [23] [PidTagMessageFlags](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcmsg/a0c52fe2-3014-43a7-942d-f43f6f91c366)
- [24] [PidTagLastVerbExecuted](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxomsg/87a8b6b8-59a4-4859-9dcd-8b0f36e3d729?redirectedfrom=MSDN)
- [25] [Пошук і перенесення Outlook data files](https://support.microsoft.com/en-us/outlook/find-and-transfer-outlook-data-files-from-one-computer-to-another)
- [26] [Увімкнення Cached Exchange Mode](https://support.microsoft.com/en-us/outlook/turn-on-cached-exchange-mode)
- [27] [Синхронізується лише subset items](https://learn.microsoft.com/en-us/troubleshoot/outlook/user-interface/only-subset-items-synchronized)
- [28] [Налаштування size limits для Outlook data files](https://learn.microsoft.com/en-us/microsoft-365-apps/outlook/data-files/configure-size-limit-outlook-data-files)
- [29] [Profiles - Де Thunderbird зберігає user data](https://support.mozilla.org/bm/kb/profiles-where-thunderbird-stores-user-data)
- [30] [Налаштування Thunderbird account і mbox directories](https://support.mozilla.org/en-US/kb/dangerous-directories-Thunderbird-account-settings)
- [31] [IThumbnailCache interface](https://learn.microsoft.com/en-us/windows/win32/api/thumbcache/nn-thumbcache-ithumbnailcache)
- [32] [Thumbs Viewer](https://thumbsviewer.github.io)
- [33] [Thumbcache Viewer](https://thumbcacheviewer.github.io)
- [34] [Registry Hives](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives)
- [35] [System registry не зберігається в RegBack](https://learn.microsoft.com/en-gb/troubleshoot/windows-client/installing-updates-features-roles/system-registry-no-backed-up-regback-folder)
- [36] [RegRipper 3.0](https://github.com/keydet89/RegRipper3.0)
- [37] [Windows Registry Recovery](https://www.mitec.cz/wrr.html)
- [38] [Віддалене редагування registry](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remotely-edit-the-registry)
- [39] [Технічний огляд passwords](https://learn.microsoft.com/en-us/windows-server/security/kerberos/passwords-technical-overview)
- [40] [PECmd](https://github.com/EricZimmerman/PECmd)
- [41] [Superfetch evidence](https://kb.binalyze.com/air/features/acquisition/supported-evidence/windows-collections-detail/superfetch)
- [42] [srum-dump](https://github.com/MarkBaggett/srum-dump)
- [43] [AppCompatCacheParser](https://github.com/EricZimmerman/AppCompatCacheParser)
- [44] [AmcacheParser](https://github.com/EricZimmerman/AmcacheParser)
- [45] [RecentFileCacheParser](https://github.com/EricZimmerman/RecentFileCacheParser)
- [46] [Формат Event Log File](https://learn.microsoft.com/en-us/windows/win32/eventlog/event-log-file-format)
- [47] [Ключ registry Eventlog](https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key)
- [48] [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.5)
- [49] [Властивість події TimeCreated](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-timecreated-systempropertiestype-element)
- [50] [Event 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- [51] [Event 4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- [52] [Event 4634](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4634)
- [53] [Event 4647](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4647)
- [54] [Event 4672](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672)
- [55] [MS-ERREF: Значення NTSTATUS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55)
- [56] [Event 4616](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4616)
- [57] [Діагностика неочікуваних reboot за допомогою system event logs](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [58] [Діагностика shutdown in process](https://learn.microsoft.com/en-us/troubleshoot/windows-server/installing-updates-features-roles/troubleshoot-error-shutdown-in-process)
- [59] [Forensics USB Storage Device для Windows 10](https://www.researchgate.net/publication/318514858_USB_Storage_Device_Forensics_for_Windows_10)
- [60] [Fantastic Windows Logon Types](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)
- [61] [Event Log Explorer](https://eventlogxp.com)
- [62] [Event 1102](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102)
- [63] [Background activity moderator](https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/Background-activity-moderator.html)
- [64] [Registry - RecentApps](https://artefacts.help/windows_registry_recentapps.html)
- [65] [Quick Print припиняє друкувати PDF attachments в Outlook Desktop](https://support.microsoft.com/en-gb/office/quick-print-stops-printing-pdf-attachments-in-outlook-desktop-512fdeb0-6a88-4e6c-9285-cf957290aad2)
- [66] [Файли Windows Registry](https://winreg-kb.readthedocs.io/en/latest/sources/windows-registry/Files.html)
- [67] [Kernel PST Viewer](https://www.nucleustechnologies.com/es/visor-de-pst.html)
- [68] [Kernel OST Viewer](https://www.nucleustechnologies.com/ost-viewer.html)
- [69] [RegQueryInfoKeyA](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeya)
- [70] [Як запобігти поверненню видалених apps під час update](https://learn.microsoft.com/en-us/windows/application-management/remove-provisioned-apps-during-update)
- [71] [NIST CFTT: Результати тестування FTK і Registry Viewer](https://www.dhs.gov/sites/default/files/publications/test_results_nist_windows_registry_forensic_tool_ftk_7.0.0.163_registry_viewer_2.0.0.7_april_2019.pdf)
- [72] [Database of Installed Services](https://learn.microsoft.com/en-us/windows/win32/services/database-of-installed-services)
- [73] [Tasks](https://learn.microsoft.com/en-us/windows/win32/taskschd/tasks)
- [74] [Scheduled Tasks Fail with Error Task Scheduler Service Is Not Available](https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/task-schedular-service-is-not-available)
- [75] [Навігація в базі даних Windows Mail](https://eprints.whiterose.ac.uk/133161/1/Navigating_the_Windows_Mail_database_accepted.pdf)
- [76] [RFC 5322: Internet Message Format](https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.4)
{{#include ../../../banners/hacktricks-training.md}}
