# Артефакти Windows

{{#include ../../../banners/hacktricks-training.md}}

## Загальні артефакти Windows

### Сповіщення Windows 10

Користувацька база даних сповіщень розташована в `%LOCALAPPDATA%\Microsoft\Windows\Notifications` (наприклад, `C:\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`). У ранніх версіях Windows 10 використовувався файл `appdb.dat`; у Anniversary Update (1607) було представлено `wpndatabase.db`. База даних SQLite містить таблицю `Notification` із даними сповіщень і полями часу, хоча обсяг збережених і доступних даних залежить від версії та політики очищення.<sup>[[3]](#references)</sup>

### Timeline

Windows Timeline — це функція історії активності, яка може містити записи для підтримуваних застосунків, документів та іншої активності користувача; її охоплення залежить від застосунку та версії Windows.<sup>[[4]](#references)</sup>

База даних розташована за адресою `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Її можна відкрити за допомогою SQLite або обробити за допомогою [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd), а результати можна переглянути за допомогою [**Timeline Explorer**](https://ericzimmerman.github.io/#!index.md).<sup>[[4]](#references)[[5]](#references)</sup>

### ADS (Alternate Data Streams)

Файли, завантажені з-за меж локальної межі довіри, можуть містити **альтернативний потік даних `Zone.Identifier`**, який зберігає інформацію про зону та може містити метадані походження, як-от URL. Його наявність і поля залежать від програми-джерела та системної політики.<sup>[[6]](#references)</sup>

## **Резервні копії файлів**

### Кошик

У Vista та новіших версіях **Кошик** можна знайти в папці **`$Recycle.bin`** у корені диска (наприклад, `C:\$Recycle.bin`).\
Коли файл видаляється в цій папці, створюються 2 конкретні файли:

- `$I{id}`: Інформація про файл, зокрема час видалення та початковий шлях
- `$R{id}`: Вміст файлу

![Резервні копії файлів — Кошик: $R{id}: Вміст файлу](<../../../images/image (1029).png>)

Маючи ці файли, можна скористатися [**Rifiuti2**](https://github.com/abelcheung/rifiuti2), щоб отримати початковий шлях і час видалення (використовуйте версію, що відповідає цільовому випуску Windows).<sup>[[7]](#references)</sup>
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![Резервні копії файлів — Кошик: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Тіньові копії томів

Volume Shadow Copy Service (VSS) може створювати тіньові копії томів у певний момент часу, поки файли використовуються; тіньова копія не є заміною forensic image.<sup>[[8]](#references)</sup>

Метадані копії зазвичай пов'язані з `\System Volume Information` у корені тому, а ідентифікатори відрізняються залежно від системи:

![Кошик — Тіньові копії томів: ці резервні копії зазвичай розташовані в System Volume Information у корені файлової системи, а їхня назва складається з UID, показаних на...](<../../../images/image (94).png>)

Після монтування image за допомогою відповідного forensic mounter, [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) може перелічити доступні VSS snapshots і переглядати або копіювати файли з них.<sup>[[9]](#references)</sup>

![Кошик — Тіньові копії томів: після монтування forensic image за допомогою ArsenalImageMounter інструмент ShadowCopyView можна використовувати для перевірки тіньової копії та навіть вилучення файлів...](<../../../images/image (576).png>)

Конфігурація registry writer VSS містить `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore`, де можна вказати файли та ключі, виключені з резервного копіювання:<sup>[[10]](#references)[[11]](#references)</sup>

![Кошик — Тіньові копії томів: запис реєстру HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore містить файли та ключі, які не слід копіювати](<../../../images/image (254).png>)

Ключ `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` також містить конфігурацію служби VSS.<sup>[[8]](#references)</sup>

### Автоматично збережені файли Office

Розташування AutoRecover відрізняються залежно від програми Office, версії та конфігурації. Для Word Microsoft вказує `%APPDATA%\Microsoft\Word` як стандартне розташування; перевірте налаштування програми, щоб визначити активний шлях.<sup>[[12]](#references)</sup>

## Елементи Shell

Елемент shell — це елемент, який містить інформацію про спосіб доступу до іншого файлу.

### Останні документи (LNK)

Windows зазвичай створює ярлики останніх елементів, коли користувач відкриває елемент або іншим чином отримує до нього доступ:

- Win7-Win10: `%APPDATA%\Microsoft\Windows\Recent\`
- Office: `%APPDATA%\Microsoft\Office\Recent\`

Доступ до папки також може створити посилання для самої папки та пов'язаних батьківських папок.

Ці файли посилань можуть містити тип цільового об'єкта, MAC-часові мітки цільового об'єкта, інформацію про том і шлях до цільового об'єкта. Ці метадані можуть допомогти ідентифікувати видалений цільовий об'єкт, але сам артефакт не є доказом того, що цільовий об'єкт відкривав певний користувач.<sup>[[13]](#references)[[14]](#references)</sup>

Власні файлові часові мітки LNK і вбудовані часові мітки цільового об'єкта є різними. Не трактуйте створення посилання як перше використання або зміну посилання як останнє використання без підтвердження іншими артефактами; формат зберігає часові мітки цільового об'єкта окремо від часових міток самого файлу посилання.<sup>[[13]](#references)[[14]](#references)</sup>

Наявне посилання на [**LinkParser**](http://4discovery.com/our-tools/) збережено як історичний варіант, але під час перевірки документація до нього була недоступна. Для документованого парсера командного рядка використовуйте [**LECmd**](https://github.com/EricZimmerman/LECmd).<sup>[[15]](#references)</sup>

Ці інструменти зазвичай показують два набори часових міток:

- **Часові мітки цільового об'єкта:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **Часові мітки файлу посилання:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

Перший набір стосується цільового об'єкта; другий — самого LNK-файлу. Інтерпретуйте обидва набори з урахуванням документації парсера та контексту файлової системи.<sup>[[14]](#references)[[15]](#references)</sup>

Отримати ту саму інформацію можна за допомогою інструмента Windows CLI: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd).<sup>[[15]](#references)</sup>
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
У цьому випадку інформацію буде збережено у CSV-файлі.

### Jumplists

Jump Lists — це списки нещодавніх або пов’язаних із завданнями елементів для окремих застосунків; вони можуть бути автоматичними або користувацькими.<sup>[[13]](#references)</sup>

Automatic Jump Lists зберігаються в `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` і використовують такі імена, як `{id}.automaticDestinations-ms`, де ID ідентифікує застосунок.

Custom Jump Lists зберігаються в `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\`; застосунок визначає, які записи завдань або елементів він створює.

Час створення та зміни файлової системи описує файл Jump List, а не автоматично перший і останній доступ до кожної цілі зі списку. Співвідносьте розібрані записи з часовими мітками файлу та іншими артефактами.<sup>[[13]](#references)</sup>

Переглядати Jump Lists можна за допомогою [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).<sup>[[5]](#references)</sup>

![Нещодавні документи (LNK) — Jumplists: переглядати jumplists можна за допомогою JumplistExplorer](<../../../images/image (168).png>)

(_Зверніть увагу, що часові мітки, надані JumplistExplorer, пов’язані із самим файлом jumplist_)

### Shellbags

[**Перейдіть за цим посиланням, щоб дізнатися, що таке shellbags.**](interesting-windows-registry-keys.md#shellbags)

## Використання Windows USB-пристроїв

Використання USB іноді можна підтвердити за артефактами, створеними під час доступу до файлів зі змінних носіїв, зокрема:

- Windows Recent Folder
- Microsoft Office Recent Folder
- Jumplists

Такі інструменти, як [**USBDetective**](https://usbdetective.com), співвідносять ці артефакти із записами про USB-пристрої, але доступність артефактів залежить від версії Windows і застосунку.<sup>[[18]](#references)</sup>

У тестуванні робочих процесів MTP, задокументованому для Windows XP і Windows 7, деякі LNK-файли вказували на папку `WPDNSE`, а не на оригінальний шлях.<sup>[[16]](#references)</sup>

![Shellbags — Використання Windows USB-пристроїв: зверніть увагу, що деякі LNK-файли замість оригінального шляху вказують на папку WPDNSE](<../../../images/image (218).png>)

У цьому дослідженні спостерігалися копії в `%LOCALAPPDATA%\Temp\WPDNSE\{FolderGUID}`; у тестах тимчасовий вміст не зберігався після перезапуску, а GUID можна було співвіднести з даними shellbag. Розглядайте це як поведінку, що залежить від ОС, пристрою та застосунку, а не як універсальне правило.<sup>[[16]](#references)</sup>

### Інформація з Registry

[Перегляньте цю сторінку, щоб дізнатися](interesting-windows-registry-keys.md#usb-information), які ключі Registry містять цікаву інформацію про підключені USB-пристрої.

### setupapi

У Vista та новіших версіях перевіряйте `C:\Windows\inf\setupapi.dev.log` на наявність активності зі встановлення пристроїв. Заголовки секцій містять часові мітки `Section start`; вони документують обробку встановлення, і їх слід співвідносити з іншими доказами підключення, а не розглядати як точний час фізичного підключення.<sup>[[17]](#references)</sup>

![Інформація з Registry — setupapi: перевірте файл C: Windows inf setupapi.dev.log, щоб отримати часові мітки підключення USB (виконайте пошук за Section start)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) можна використовувати для отримання інформації про USB-пристрої, підключені до образу.<sup>[[18]](#references)</sup>

![setupapi — USB Detective: USBDetective можна використовувати для отримання інформації про USB-пристрої, підключені до образу](<../../../images/image (452).png>)

### Plug and Play Cleanup

Заплановане завдання під назвою `Plug and Play Cleanup` видаляє застарілі версії драйверів. Визначення завдання Windows 10, задокументоване Adam Harrison, також стосується драйверів, неактивних протягом 30 днів, тому дані про драйвери змінних пристроїв можуть бути очищені; перед узагальненням цієї поведінки перевірте локальне визначення завдання та збірку Windows.<sup>[[1]](#references)</sup>

Завдання розташоване за таким шляхом: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

**Основні компоненти та налаштування завдання:**

- **pnpclean.dll**: ця DLL відповідає за фактичний процес очищення.
- **UseUnifiedSchedulingEngine**: встановлено значення `TRUE`, що вказує на використання загального механізму планування завдань.
- **MaintenanceSettings**:
- **Period ('P1M')**: вказує Task Scheduler запускати завдання очищення щомісяця під час звичайного Automatic maintenance.
- **Deadline ('P2M')**: вказує Task Scheduler, якщо завдання не виконується протягом двох послідовних місяців, запустити його під час emergency Automatic maintenance.

Ця конфігурація планує регулярне обслуговування та повторні спроби після послідовних помилок; точні XML і поведінка залежать від версії.<sup>[[1]](#references)</sup>

**Додаткову інформацію дивіться:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html).<sup>[[1]](#references)</sup>

## Електронні листи

Електронні листи містять **2 цікаві частини: заголовки та вміст** листа. У **заголовках** можна знайти таку інформацію:

- **Хто** надіслав листи (адреса електронної пошти, IP, поштові сервери, які перенаправили лист)
- **Коли** було надіслано лист

Крім того, заголовки `References` та `In-Reply-To` можуть містити ID повідомлень, які використовуються для пов’язування відповідей із розмовою.<sup>[[76]](#references)</sup>

![Plug and Play Cleanup — Електронні листи: коли було надіслано лист](<../../../images/image (593).png>)

### Windows Mail App

Цей застосунок зберігає вміст електронних листів у допоміжних текстових або HTML-файлах за такими шляхами, як `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`; точна структура нумерованих папок і файлів може відрізнятися залежно від артефакту.<sup>[[75]](#references)</sup>

**Метадані** електронних листів і **контакти** можна знайти в **ESE database** `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`.<sup>[[75]](#references)</sup>

`store.vol` використовує формат Extensible Storage Engine (ESE). Працюйте з копією та використовуйте ESE-парсер, наприклад [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html); якщо інструмент потребує суфікса `.edb`, перейменовуйте лише копію та перевірте схему таблиць, перш ніж покладатися на таблицю `Message`.<sup>[[19]](#references)[[75]](#references)</sup>

### Microsoft Outlook

Під час перевірки властивостей Outlook MAPI до канонічних властивостей належать:

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

![Windows Mail App — Microsoft Outlook: PST-файл можна відкрити за допомогою інструмента Kernel PST Viewer](<../../../images/image (498).png>)

### Microsoft Outlook OST Files

**OST-файл** — це локальний кеш для облікових записів Exchange або Microsoft 365; Cached Exchange Mode не застосовується до облікових записів POP або IMAP. Період роботи в автономному режимі можна налаштувати, і за замовчуванням він часто становить 12 місяців, тоді як обмеження розміру PST/OST є окремими параметрами, які також можна налаштувати. Для перегляду OST-файлу можна використовувати [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html).<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[68]](#references)</sup>

### Отримання вкладень

Втрачені вкладення можна спробувати відновити з таких розташувань:

- Для застарілих конфігурацій Outlook/IE: `%LOCALAPPDATA%\Temporary Internet Files\Content.Outlook`
- Для новіших конфігурацій Outlook/IE11: `%LOCALAPPDATA%\Microsoft\Windows\INetCache\Content.Outlook`.<sup>[[65]](#references)</sup>

### Thunderbird MBOX Files

**Thunderbird** зберігає дані профілю в `%APPDATA%\Thunderbird\Profiles`; поштові папки зазвичай використовують mbox-файли без розширення в каталогах `Mail` або `ImapMail`, специфічних для облікового запису.<sup>[[29]](#references)[[30]](#references)</sup>

### Мініатюри зображень

- **Windows XP**: попередні перегляди мініатюр зазвичай зберігалися в окремих для кожної папки файлах `thumbs.db`.
- **Мережеві папки**: файл `thumbs.db` усе ще може створюватися для UNC-папки, якщо відповідну поведінку мініатюр увімкнено; не слід вважати, що кожна версія Windows або політика створює такий файл.
- **Windows Vista і новіші версії**: системний кеш мініатюр централізовано зберігається в `%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer` у файлах на кшталт **thumbcache_xxx.db**. [**Thumbsviewer**](https://thumbsviewer.github.io) може аналізувати застарілі `Thumbs.db`, а [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) — сучасні бази даних кешу мініатюр.<sup>[[31]](#references)[[32]](#references)[[33]](#references)</sup>

### Інформація з Windows Registry

Windows Registry, що зберігає дані конфігурації системи та користувачів, міститься у файлах hive в таких каталогах:

- `%WINDIR%\System32\Config` — для машинних hive, що є основою різних підрозділів `HKEY_LOCAL_MACHINE`.
- `%USERPROFILE%\NTUSER.DAT` — для hive користувача `HKEY_CURRENT_USER`.
- Деякі старі інсталяції Windows містять копії в `%WINDIR%\System32\Config\RegBack\`; Windows 10 версії 1803 і новіші не заповнюють цей каталог автоматично, якщо не ввімкнено періодичне резервне копіювання.<sup>[[34]](#references)[[35]](#references)</sup>
- Дані shell і реєстрації класів для окремих користувачів також зазвичай зберігаються в `%LOCALAPPDATA%\Microsoft\Windows\UsrClass.dat` у сучасних версіях Windows.<sup>[[34]](#references)[[66]](#references)</sup>

### Інструменти

Деякі інструменти корисні для аналізу Registry hive; перед використанням результату перевіряйте підтримувані кожним інструментом формати hive і версії:

- **Registry Editor**: встановлений у Windows. Це GUI для навігації Windows Registry поточного сеансу.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): дає змогу завантажити файл Registry і переглядати його за допомогою GUI. Також містить Bookmarks, які виділяють ключі з цікавою інформацією.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): також має GUI для навігації завантаженим Registry і містить plugins, які виділяють цікаву інформацію в завантаженому Registry.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): інший GUI-застосунок, здатний витягувати інформацію із завантаженого Registry hive.<sup>[[5]](#references)[[36]](#references)[[37]](#references)</sup>

### Відновлення видаленого елемента

Видалені комірки hive можуть залишатися, доки їхній простір не буде повторно використано, але відновлення залежить від стану hive та парсера; розглядайте відновлені видалені ключі як докази, що потребують перевірки, а не як гарантовані записи.

### Час останнього запису

Ключі Registry містять часову мітку останнього запису; Windows надає її для ключа або будь-якого його запису-значення, тому значення не обов’язково має власну незалежну часову мітку зміни.<sup>[[69]](#references)</sup>

### SAM

Hive **SAM** містить дані локальних облікових записів користувачів і груп, зокрема хеші паролів, захищені матеріалом системного boot-key.<sup>[[38]](#references)[[39]](#references)</sup>

У `SAM\Domains\Account\Users` можна отримати ідентифікатори облікових записів і деякі поля входу та політики. Для offline-вилучення хешів також потрібен hive `SYSTEM`, щоб відновити відповідний матеріал boot-key.<sup>[[38]](#references)[[39]](#references)</sup>

### Цікаві записи у Windows Registry


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Виконані програми

### Основні процеси Windows

Наявна [публікація про поширені процеси Windows](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) зберігається як додатковий матеріал для читання; твердження щодо поведінки процесів слід підтверджувати актуальною документацією Windows і локальними доказами.<sup>[[2]](#references)</sup>

### Windows Recent APPs

У версіях Windows 10, де цей артефакт доступний, `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps` містить підрозділи для окремих застосунків із такими полями, як час останнього використання та кількість запусків; в наступних випусках артефакт було видалено, тому перевіряйте цільову збірку.<sup>[[64]](#references)</sup>

### BAM (Background Activity Moderator)

У системах, де доступний Background Activity Moderator, перевіряйте шлях `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` або новіший шлях `...\bam\State\UserSettings\{SID}`. Значення індексуються за SID користувача та можуть містити відстежувані шляхи виконуваних файлів і дані виконання, подібні до FILETIME; артефакт залежить від версії, тому його слід підтверджувати іншими доказами.<sup>[[63]](#references)</sup>

### Windows Prefetch

Prefetch кешує ресурси та метадані запуску, щоб програми могли швидше запускатися.

Файли Prefetch зберігаються як файли `.pf` у `C:\Windows\Prefetch`; формат, термін зберігання та обмеження кількості файлів залежать від версії Windows. Microsoft документує збереження часу останніх восьми запусків і до 1024 файлів у Windows 8 та новіших версіях, тому не слід узагальнювати старі описи фіксованих обмежень.<sup>[[13]](#references)</sup>

Ім’я файлу зазвичай має формат `{program_name}-{hash}.pf`, де hash обчислюється з контексту виконання, наприклад шляху та аргументів; Windows 10 і новіші версії можуть стискати файл. Наявність файлу є корисною ознакою виконання, але сама по собі не доводить виконання користувачем і має співвідноситися з іншими артефактами.<sup>[[13]](#references)</sup>

Для перевірки цих файлів можна використовувати [**PECmd.exe**](https://github.com/EricZimmerman/PECmd), який документує аналіз каталогів, виведення у CSV/HTML і підтримку розпакування відповідних файлів Prefetch Windows 10.<sup>[[40]](#references)</sup>
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superfetch/SysMain** доповнює Prefetch, використовуючи історичні шаблони використання для покращення завантаження. У системах, які їх створюють, файли баз даних зазвичай знаходяться в `C:\Windows\Prefetch\Ag*.db`; формат і наявність залежать від версії.<sup>[[41]](#references)</sup>

Ці бази даних можуть містити назви застосунків, кількість використань, доступні файли або томи, шляхи та часові діапазони, але їх не слід розглядати як точний журнал виконання.<sup>[[41]](#references)</sup>

Наявне посилання на [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) збережено як можливий парсер; перед використанням перевірте його поточну доступність і підтримуваний формат виводу за документацією інструмента.

### SRUM

**System Resource Usage Monitor** (SRUM) записує використання ресурсів застосунками та користувачами. Цю функцію було представлено у Windows 8, а дані зберігаються в базі даних ESE `C:\Windows\System32\sru\SRUDB.dat`.<sup>[[13]](#references)</sup>

Вона надає таку інформацію:

- AppID і Path
- Користувач/SID, пов'язаний із записом
- Надіслані байти
- Отримані байти
- Мережевий інтерфейс
- Тривалість з'єднання
- Тривалість процесу

Періодичність збору та зберігання даних залежать від реалізації; не слід припускати, що кожен запис являє собою точний 60-хвилинний інтервал виконання.<sup>[[13]](#references)</sup>

Ви можете видобувати та переглядати дані за допомогою [**srum_dump**](https://github.com/MarkBaggett/srum-dump), використовуючи опції, задокументовані в поточній версії інструмента.<sup>[[42]](#references)</sup>
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -o C:\Users\student\Desktop\srum --NO_CONFIRM
```
### AppCompatCache (ShimCache)

**AppCompatCache**, також відомий як **ShimCache**, є частиною інфраструктури сумісності застосунків Windows і записує метадані файлів для прийняття рішень щодо сумісності. Шлях до hive, формат записів, обсяг збережених даних і поля відрізняються залежно від версії Windows; у сучасних версіях Windows сам по собі ShimCache не може довести, що користувач запускав файл. Розберіть відповідний hive `SYSTEM` за допомогою інструмента [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser) і підтвердьте його результати іншими артефактами виконання.<sup>[[13]](#references)[[43]](#references)</sup>

![SRUM - AppCompatCache (ShimCache): Для аналізу збереженої інформації рекомендується використовувати інструмент AppCompatCacheParser](<../../../images/image (75).png>)

### Amcache

Файл **Amcache.hve** є реєстровим hive, у якому Windows веде інвентаризацію виявлених застосунків і файлів. Зазвичай він розташований за адресою `C:\Windows\AppCompat\Programs\Amcache.hve`.

Він може містити пов’язані й непов’язані записи файлів, шляхи та значення SHA1, але його наявність є доказом інвентаризації й сама по собі не доводить, що процес було виконано.<sup>[[13]](#references)[[44]](#references)</sup>

Для вилучення й аналізу **Amcache.hve** використовуйте інструмент [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser). Ця команда аналізує hive і записує результат у форматі CSV.<sup>[[44]](#references)</sup>

Наприклад:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Серед згенерованих CSV-файлів `Amcache_Unassociated file entries` може бути корисним під час дослідження файлів, не пов’язаних із розпізнаною програмою.<sup>[[44]](#references)</sup>

### RecentFileCache

У системах Windows 7 файл `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` може містити інформацію про нещодавно виявлені бінарні файли; його доступність і семантика залежать від версії.

Для аналізу цього файлу можна використовувати [**RecentFileCacheParser**](https://github.com/EricZimmerman/RecentFileCacheParser).<sup>[[45]](#references)</sup>

### Заплановані завдання

Докази запланованих завдань можна знайти в `C:\Windows\System32\Tasks` для сучасних завдань і в `C:\Windows\Tasks` у файлах `.job` для застарілих завдань; аналізуйте формат визначення завдання, відповідний до версії ОС.<sup>[[73]](#references)[[74]](#references)</sup>

### Служби

База даних Service Control Manager розташована в `SYSTEM\CurrentControlSet\Services` (для автономного SYSTEM hive перевірте відповідний ключ control-set); вона містить конфігурацію служб і драйверів, зокрема шляхи до виконуваних файлів і типи запуску.<sup>[[72]](#references)</sup>

### **Windows Store**

Встановлені застосунки Windows Store можуть бути представлені в `\ProgramData\Microsoft\Windows\AppRepository\`, зокрема базою даних **`StateRepository-Machine.srd`**. Схема та шляхи залежать від випуску Windows.<sup>[[71]](#references)</sup>

База даних може містити ідентифікатори застосунків, номери пакетів і відображувані назви. Пропуски в ідентифікаторах самі по собі не є доказом видалення застосунку; підтверджуйте висновки станом пакетів і реєстру.

Реєстрації пакетів також можуть міститися в `HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`. Microsoft документує версійний підключ `Deprovisioned` для видалених підготовлених застосунків; не припускайте, що підключ `Deleted` існує в кожній збірці.<sup>[[70]](#references)</sup>

## Події Windows

Залежно від provider, події Windows можуть містити:

- Що сталося
- Мітку часу `TimeCreated`, яку потрібно інтерпретувати з урахуванням схеми події та часового контексту хоста
- Задіяних користувачів
- Задіяні хости (ім’я хоста, IP)
- Доступні активи (файли, папки, принтери або служби).<sup>[[49]](#references)</sup>

До Windows Vista журнали подій зазвичай використовували застарілий бінарний формат у `C:\Windows\System32\config`; у Vista та новіших версіях використовується формат Windows Event Log, зазвичай у `C:\Windows\System32\winevt\Logs`, де файли `.evtx` містять дані подій, представлені у форматі XML.<sup>[[46]](#references)[[47]](#references)</sup>

Реєстр SYSTEM зберігає конфігурацію каналів у **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**, зокрема налаштований шлях до файлу та параметри зберігання.<sup>[[47]](#references)</sup>

Їх можна переглядати за допомогою Windows Event Viewer (**`eventvwr.msc`**) або таких інструментів, як [**Event Log Explorer**](https://eventlogxp.com) і [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md).<sup>[[5]](#references)[[48]](#references)[[61]](#references)</sup>

## Розуміння журналювання подій безпеки Windows

У Vista та новіших версіях канал Security зазвичай зберігається в `C:\Windows\System32\winevt\Logs\Security.evtx`. Його максимальний розмір і політика зберігання налаштовуються; за циклічного журналювання старі записи можуть бути перезаписані після досягнення файлом встановленого обмеження. Канал може реєструвати події автентифікації, виходу із системи, привілеїв, політики аудиту та доступу до об’єктів, якщо відповідний аудит увімкнено.<sup>[[46]](#references)[[47]](#references)</sup>

### Ключові Event ID для автентифікації користувачів:

- **Event ID 4624**: Успішний вхід облікового запису.<sup>[[50]](#references)</sup>
- **Event ID 4625**: Невдалий вхід облікового запису.<sup>[[51]](#references)</sup>
- **Event ID 4634**: Сеанс входу було завершено.<sup>[[52]](#references)</sup>
- **Event ID 4647**: Користувач ініціював вихід із системи.<sup>[[53]](#references)</sup>
- **Event ID 4672**: Новому входу було призначено спеціальні привілеї; це поширено для системних облікових записів і облікових записів адміністраторів, тому саме по собі не є доказом шкідливої активності.<sup>[[54]](#references)</sup>

#### Типи входу, які зазвичай реєструються в 4624, 4625, 4634 і 4647:

- **Interactive (2)**: Інтерактивний локальний вхід.
- **Network (3)**: Доступ до спільного ресурсу.
- **Batch (4)**: Вхід пакетного процесу.
- **Service (5)**: Вхід служби.
- **Unlock (7)**: Розблокування робочої станції.
- **NetworkCleartext (8)**: Мережевий вхід, під час якого облікові дані передаються пакету автентифікації у відкритому вигляді.
- **NewCredentials (9)**: Вхід із використанням наданих альтернативних облікових даних для вихідних підключень.
- **RemoteInteractive (10)**: Вхід через Remote Desktop або Terminal Services.
- **CachedInteractive (11)**: Інтерактивний вхід із використанням кешованих доменних облікових даних.
- **CachedRemoteInteractive (12)**: Кешований віддалений інтерактивний вхід.
- **CachedUnlock (13)**: Розблокування з використанням кешованих облікових даних.<sup>[[50]](#references)[[51]](#references)</sup>

#### Коди Status і Sub Status для EventID 4625:

- **0xC0000064**: Такого користувача не існує.
- **0xC000006A**: Правильне ім’я користувача, але неправильний пароль.
- **0xC0000234**: Обліковий запис заблоковано.
- **0xC0000072**: Обліковий запис вимкнено.
- **0xC000006F**: Вхід поза дозволеними годинами.
- **0xC0000070**: Порушення обмеження робочої станції.
- **0xC0000193**: Термін дії облікового запису минув.
- **0xC0000071**: Термін дії пароля минув.
- **0xC0000133**: Різниця в часі між клієнтом і сервером надто велика.
- **0xC0000224**: Обліковий запис має змінити пароль.
- **0xC0000225**: `STATUS_NOT_FOUND`; сам код не визначає системну помилку або атаку.
- **0xC000015B**: Запитаний тип входу не надано обліковому запису.<sup>[[51]](#references)[[55]](#references)</sup>

#### EventID 4616:

- **Зміна часу**: Системний час було змінено. Багато подій відображають звичайне коригування часу службою синхронізації, тому перед трактуванням події як втручання перевірте виконавця та джерело часу.<sup>[[56]](#references)</sup>

#### Event IDs 12, 13, 1074, 6005, 6006, 6008 і 6009:

- **Контекст живлення та служб**: Подія 12 реєструє запуск ОС, 13 — завершення роботи ОС, 1074 — заплановане завершення роботи або перезапуск, 6008 вказує на неочікуване завершення роботи, а 6009 реєструє версію Windows під час завантаження. Події 6005 і 6006 вказують відповідно на запуск і зупинку служби Event Log; самі по собі вони не є доказом запуску та завершення роботи ОС.<sup>[[57]](#references)[[58]](#references)</sup>

#### EventID 1102:

- **Видалення журналу**: Подія 1102 реєструє очищення журналу аудиту Security; досліджуйте виконавця та сусідні події, а не робіть висновок про намір лише на підставі цієї події.<sup>[[62]](#references)</sup>

#### EventIDs для відстеження USB-пристроїв:

- **20001 / 20003**: Події встановлення пристроїв `UserPnp`, які можуть допомогти встановити факт першого використання або встановлення.
- **10000 / 10100**: Події `DriverFrameworks-UserMode`, які можуть супроводжувати активність пристрою.
- **Event ID 112**: Активність `DeviceSetupManager/Admin`, яка може надавати мітки часу, пов’язані з підключенням.
- Provider, канал і семантика подій залежать від версії Windows; перевіряйте назву provider і payload події перед визначенням її значення.<sup>[[59]](#references)</sup>

Практичні приклади типів входу та пов’язаних із ними матеріалів облікових даних наведено в [докладному посібнику Altered Security](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).<sup>[[60]](#references)</sup>

Деталі події, зокрема тип входу, status, substatus, адреса джерела та поля процесу, надають контекст для Event ID 4625; код status або повторюваний шаблон невдалих спроб є напрямом для дослідження, а не остаточним висновком.<sup>[[51]](#references)[[55]](#references)</sup>

### Відновлення подій Windows

Оскільки журнали подій зазвичай працюють у циклічному режимі, записи, перезаписані logger, можуть бути невідновними. Перед взаємодією з активною системою збережіть forensic image або робочу копію; використовуйте перевірений parser або carver, наприклад **Bulk_extractor**, лише після підтвердження, що версія інструмента підтримує цільові дані `.evtx`, і не від’єднуйте працюючу систему лише заради спроби відновити події.<sup>[[46]](#references)</sup>

### Виявлення поширених атак за допомогою подій Windows

Практичний довідник з Event ID дивіться за наявним посиланням [Red Team Recipe](https://redteamrecipe.com/event-codes/) і перевіряйте його приклади за наведеною вище документацією provider.

#### Атаки методом brute force

Співвідносіть повторювані невдалі спроби Event ID 4625 із подальшим успішним входом 4624, типом входу, status, джерелом і контекстом облікового запису; така послідовність є індикатором для дослідження, а не доказом атаки.<sup>[[50]](#references)[[51]](#references)</sup>

#### Зміна часу

Event ID 4616 реєструє зміни системного часу, які можуть ускладнювати аналіз часової шкали; порівнюйте цю подію з даними служби синхронізації часу та хоста.<sup>[[56]](#references)</sup>

#### Відстеження USB-пристроїв

USB event IDs залежать від provider; співвідносьте `UserPnp` 20001/20003, `DriverFrameworks-UserMode` 10000/10100 і `DeviceSetupManager/Admin` 112 з артефактами SetupAPI та реєстру.<sup>[[17]](#references)[[59]](#references)</sup>

#### Події живлення системи

Використовуйте 12/13/1074/6008/6009 для визначення контексту запуску ОС, завершення роботи, перезапуску та неочікуваного вимкнення живлення; 6005/6006 позначають запуск і зупинку служби Event Log.<sup>[[57]](#references)[[58]](#references)</sup>

#### Видалення журналу

Security Event ID 1102 реєструє очищення журналу аудиту Security; цю подію слід співвідносити з відповідним обліковим записом і процесом.<sup>[[62]](#references)</sup>

## References

- [1] [Очищення Windows Plug and Play](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)
- [2] [jonahacks.medium.com — Дослідження поширених процесів Windows](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)
- [3] [Цифрово-криміналістичний погляд на сповіщення Windows 10](https://iconline.ipleiria.pt/server/api/core/bitstreams/833e160a-e382-46b4-82ad-fb2c8c995d62/content)
- [4] [WxTCmd](https://github.com/EricZimmerman/WxTCmd)
- [5] [Криміналістичні інструменти Eric Zimmerman](https://ericzimmerman.github.io/#!index.md)
- [6] [Zone.Identifier та альтернативні потоки даних](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/6e3f7352-d11c-4d76-8c39-2516a9df36e8)
- [7] [Rifiuti2](https://github.com/abelcheung/rifiuti2)
- [8] [Служба Volume Shadow Copy](https://learn.microsoft.com/en-us/windows/server/storage/file-server/volume-shadow-copy-service)
- [9] [ShadowCopyView](https://www.nirsoft.net/utils/shadow_copy_view.html)
- [10] [Операції резервного копіювання та відновлення реєстру через VSS](https://learn.microsoft.com/en-us/windows/win32/vss/registry-backup-and-restore-operations-under-vss)
- [11] [Ключі реєстру для резервного копіювання та відновлення](https://learn.microsoft.com/en-us/windows/win32/backup/registry-keys-for-backup-and-restore)
- [12] [Проблема продуктивності Word у розташуванні AutoRecover](https://learn.microsoft.com/en-us/previous-versions/troubleshoot/microsoft-365/microsoft-365-apps/word/performance-issue-on-autorecover-location)
- [13] [Посібник з реагування на інциденти](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/final/en-us/microsoft-brand/documents/IR-Guidebook-Final.pdf)
- [14] [MS-SHLLINK: Бінарний формат Shell Link](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/c3376b21-0931-45e4-b2fc-a48ac0e60d15)
- [15] [LECmd](https://github.com/EricZimmerman/LECmd)
- [16] [Криміналістичний аналіз USB MTP: виявлення артефактів ексфільтрації даних](https://studylib.net/doc/8690663/usb-devices-and-media-transfer-protocol)
- [17] [Записи журналу встановлення пристроїв SetupAPI](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/setupapi-device-installation-log-entries)
- [18] [USB Detective](https://usbdetective.com)
- [19] [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)
- [20] [PidTagClientSubmitTime](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/ca98145f-7f87-42b4-b0ef-124c6c6f8d83)
- [21] [PidTagConversationIndex](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/57f8de0f-5f53-423a-8947-7943dd959997)
- [22] [EntryID та пов’язані типи](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcdata/57e8bcbf-11d0-40fe-8833-5558bb9c0c89)
- [23] [PidTagMessageFlags](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcmsg/a0c52fe2-3014-43a7-942d-f43f6f91c366)
- [24] [PidTagLastVerbExecuted](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxomsg/87a8b6b8-59a4-4859-9dcd-8b0f36e3d729?redirectedfrom=MSDN)
- [25] [Пошук і перенесення файлів даних Outlook](https://support.microsoft.com/en-us/outlook/find-and-transfer-outlook-data-files-from-one-computer-to-another)
- [26] [Увімкнення Cached Exchange Mode](https://support.microsoft.com/en-us/outlook/turn-on-cached-exchange-mode)
- [27] [Синхронізовано лише частину елементів](https://learn.microsoft.com/en-us/troubleshoot/outlook/user-interface/only-subset-items-synchronized)
- [28] [Налаштування обмежень розміру для файлів даних Outlook](https://learn.microsoft.com/en-us/microsoft-365-apps/outlook/data-files/configure-size-limit-outlook-data-files)
- [29] [Профілі — де Thunderbird зберігає дані користувача](https://support.mozilla.org/bm/kb/profiles-where-thunderbird-stores-user-data)
- [30] [Налаштування облікових записів Thunderbird і каталоги mbox](https://support.mozilla.org/en-US/kb/dangerous-directories-Thunderbird-account-settings)
- [31] [Інтерфейс IThumbnailCache](https://learn.microsoft.com/en-us/windows/win32/api/thumbcache/nn-thumbcache-ithumbnailcache)
- [32] [Thumbs Viewer](https://thumbsviewer.github.io)
- [33] [Thumbcache Viewer](https://thumbcacheviewer.github.io)
- [34] [Hive реєстру](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives)
- [35] [Системний реєстр не резервується до RegBack](https://learn.microsoft.com/en-gb/troubleshoot/windows-client/installing-updates-features-roles/system-registry-no-backed-up-regback-folder)
- [36] [RegRipper 3.0](https://github.com/keydet89/RegRipper3.0)
- [37] [Відновлення реєстру Windows](https://www.mitec.cz/wrr.html)
- [38] [Віддалене редагування реєстру](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remotely-edit-the-registry)
- [39] [Технічний огляд паролів](https://learn.microsoft.com/en-us/windows-server/security/kerberos/passwords-technical-overview)
- [40] [PECmd](https://github.com/EricZimmerman/PECmd)
- [41] [Докази Superfetch](https://kb.binalyze.com/air/features/acquisition/supported-evidence/windows-collections-detail/superfetch)
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
- [55] [MS-ERREF: Значення NTSTATUS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55)
- [56] [Подія 4616](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4616)
- [57] [Усунення непередбачених перезапусків за допомогою системних журналів подій](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [58] [Усунення проблеми завершення роботи в процесі](https://learn.microsoft.com/en-us/troubleshoot/windows-server/installing-updates-features-roles/troubleshoot-error-shutdown-in-process)
- [59] [Криміналістичний аналіз USB-накопичувачів у Windows 10](https://www.researchgate.net/publication/318514858_USB_Storage_Device_Forensics_for_Windows_10)
- [60] [Типи входу Windows](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)
- [61] [Event Log Explorer](https://eventlogxp.com)
- [62] [Подія 1102](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102)
- [63] [Модератор фонової активності](https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/Background-activity-moderator.html)
- [64] [Реєстр — RecentApps](https://artefacts.help/windows_registry_recentapps.html)
- [65] [Quick Print припиняє друкувати PDF-вкладення в Outlook Desktop](https://support.microsoft.com/en-gb/office/quick-print-stops-printing-pdf-attachments-in-outlook-desktop-512fdeb0-6a88-4e6c-9285-cf957290aad2)
- [66] [Файли реєстру Windows](https://winreg-kb.readthedocs.io/en/latest/sources/windows-registry/Files.html)
- [67] [Kernel PST Viewer](https://www.nucleustechnologies.com/es/visor-de-pst.html)
- [68] [Kernel OST Viewer](https://www.nucleustechnologies.com/ost-viewer.html)
- [69] [RegQueryInfoKeyA](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeya)
- [70] [Запобігання повторній появі видалених застосунків під час оновлення](https://learn.microsoft.com/en-us/windows/application-management/remove-provisioned-apps-during-update)
- [71] [NIST CFTT: результати тестування FTK і Registry Viewer](https://www.dhs.gov/sites/default/files/publications/test_results_nist_windows_registry_forensic_tool_ftk_7.0.0.163_registry_viewer_2.0.0.7_april_2019.pdf)
- [72] [База даних встановлених служб](https://learn.microsoft.com/en-us/windows/win32/services/database-of-installed-services)
- [73] [Завдання](https://learn.microsoft.com/en-us/windows/win32/taskschd/tasks)
- [74] [Заплановані завдання завершуються помилкою «Служба Task Scheduler недоступна»](https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/task-schedular-service-is-not-available)
- [75] [Навігація базою даних Windows Mail](https://eprints.whiterose.ac.uk/133161/1/Navigating_the_Windows_Mail_database_accepted.pdf)
- [76] [RFC 5322: Формат Internet-повідомлень](https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.4)
{{#include ../../../banners/hacktricks-training.md}}
