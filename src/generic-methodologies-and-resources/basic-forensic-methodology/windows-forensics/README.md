# Артефакти Windows

{{#include ../../../banners/hacktricks-training.md}}

## Загальні артефакти Windows

### Сповіщення Windows 10

База даних сповіщень користувача розташована в `%LOCALAPPDATA%\Microsoft\Windows\Notifications` (наприклад, `C:\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`). У ранніх випусках Windows 10 використовувався файл `appdb.dat`; в Anniversary Update (1607) з’явився `wpndatabase.db`. База даних SQLite містить таблицю `Notification` із даними сповіщень і часовими полями, хоча термін зберігання та доступні дані залежать від випуску й політики очищення.<sup>[[3]](#references)</sup>

### Timeline

Windows Timeline — це функція журналу активності, яка може містити записи про підтримувані програми, документи та інші дії користувача; обсяг даних залежить від програми та версії Windows.<sup>[[4]](#references)</sup>

База даних розташована за адресою `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Її можна відкрити за допомогою SQLite або проаналізувати за допомогою [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd), а результати переглянути у [**Timeline Explorer**](https://ericzimmerman.github.io/#!index.md).<sup>[[4]](#references)[[5]](#references)</sup>

### Знімки Windows Recall (ПК Copilot+)

На підтримуваних ПК Copilot+ з Windows 11 функція Recall потребує явного ввімкнення. У поточних збірках знімки та їхній індекс шифруються ключами, пов’язаними з Windows Hello та анклавом VBS. Не вважайте автономну копію сховища незашифрованою базою даних SQLite: у попередній версії 2024 року та випущеній версії різні властивості доступу.<sup>[[77]](#references)</sup>

Для **активного сеансу Recall із увімкненою функцією** процес рендерингу `AIXHost.exe` того самого користувача є окремою поверхнею доступу. У підтвердженні концепції TotalRecall Reloaded DLL впроваджується в цей процес і викликає COM-інтерфейси Recall. Для вилучення повної історії користувач має пройти автентифікацію за допомогою Windows Hello; це не автономне розшифрування і не обхід Hello. Дослідник задокументував роботу інструмента у Windows 11 ARM64, тому перед використанням перевірте його сумісність із цільовою збіркою.<sup>[[78]](#references)[[77]](#references)</sup>

```powershell
totalrecall.exe --preauth  # Most recent capture and settings; no Hello prompt
totalrecall.exe --wait     # Wait for the user to open Recall and authenticate
```

`--preauth` використовує `GetRecentCaptureThumbnail`, щоб запитати велику версію останнього знімка без Hello. Після авторизації `--wait` може отримувати знімки екрана, текст OCR і метадані окремих знімків, зокрема контекст застосунку та вікна. Результати записуються в каталог `extraction_*` із міткою часу. Це результати, отримані під час перевірки концепції, які залежать від збірки системи; вони не гарантують, що Recall увімкнено або що було зафіксовано кожен екран.<sup>[[78]](#references)</sup>

### ADS (Alternate Data Streams)

Файли, завантажені з-за меж локальної зони довіри, можуть містити **альтернативний потік даних `Zone.Identifier`**, який зберігає інформацію про зону та може містити метадані походження, як-от URL. Його наявність і поля залежать від програми, що створила файл, і системної політики.<sup>[[6]](#references)</sup>

## **Резервні копії файлів**

### Кошик

У Vista та новіших версіях **Кошик** міститься в папці **`$Recycle.bin`** у корені диска (наприклад, `C:\$Recycle.bin`).\
Коли файл видаляють у цій папці, створюються два спеціальні файли:

- `$I{id}`: інформація про файл, зокрема час видалення та початковий шлях
- `$R{id}`: вміст файлу

![Резервні копії файлів — Кошик: $R{id}: вміст файлу](<../../../images/image (1029).png>)

За допомогою цих файлів можна використати [**Rifiuti2**](https://github.com/abelcheung/rifiuti2), щоб отримати початковий шлях і час видалення (використовуйте версію, відповідну випуску Windows на цільовій системі).<sup>[[7]](#references)</sup>

```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```

![Резервні копії файлів — Кошик: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Тіньові копії томів

Служба тіньового копіювання томів (VSS) може створювати тіньові копії томів на певний момент часу, поки файли використовуються; тіньова копія не є заміною forensic-образу.<sup>[[8]](#references)</sup>

Метадані копії зазвичай пов’язані з `\System Volume Information` у корені тому; ідентифікатори залежать від системи:

![Кошик — тіньові копії томів: ці резервні копії зазвичай розташовані в System Volume Information у корені файлової системи, а їхні назви складаються з UID, показаних на...](<../../../images/image (94).png>)

Після монтування образу за допомогою відповідного forensic-монтера [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) може перелічити доступні знімки VSS і переглядати або копіювати файли з них.<sup>[[9]](#references)</sup>

![Кошик — тіньові копії томів: після монтування forensic-образу за допомогою ArsenalImageMounter інструмент ShadowCopyView можна використовувати для перегляду тіньової копії та навіть вилучення файлів...](<../../../images/image (576).png>)

Конфігурація засобу запису реєстру VSS містить `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore`, де можна вказати файли й ключі, виключені з резервного копіювання:<sup>[[10]](#references)[[11]](#references)</sup>

![Кошик — тіньові копії томів: запис реєстру HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore містить файли й ключі, які не потрібно включати до резервної копії](<../../../images/image (254).png>)

Ключ `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` також містить конфігурацію служби VSS.<sup>[[8]](#references)</sup>

### Автозбережені файли Office

Розташування AutoRecover відрізняються залежно від програми Office, версії та конфігурації. Для Word Microsoft вказує `%APPDATA%\Microsoft\Word` як розташування за замовчуванням; перевірте налаштування програми, щоб дізнатися активний шлях.<sup>[[12]](#references)</sup>

## Елементи оболонки

Елемент оболонки — це елемент, який містить інформацію про доступ до іншого файлу.

### Нещодавні документи (LNK)

Windows зазвичай створює ярлики нещодавніх елементів, коли користувач відкриває елемент або іншим чином отримує до нього доступ:

- Win7-Win10: `%APPDATA%\Microsoft\Windows\Recent\`
- Office: `%APPDATA%\Microsoft\Office\Recent\`

Доступ до папки також може створювати посилання на саму папку та пов’язані батьківські папки.

Ці файли ярликів можуть містити тип цільового об’єкта, часові мітки MAC цільового об’єкта, інформацію про том і шлях до цільового об’єкта. Ці метадані можуть допомогти ідентифікувати видалений цільовий об’єкт, але артефакт сам по собі не є доказом того, що цільовий об’єкт відкрив певний користувач.<sup>[[13]](#references)[[14]](#references)</sup>

Власні часові мітки файлової системи LNK і вбудовані часові мітки цільового об’єкта — це різні дані. Не вважайте створення ярлика першим використанням, а його зміну — останнім використанням без підтвердження іншими артефактами; формат зберігає часові мітки цільового об’єкта окремо від часових міток самого файлу ярлика.<sup>[[13]](#references)[[14]](#references)</sup>

Наявне посилання на [**LinkParser**](http://4discovery.com/our-tools/) залишено як історичний варіант, але під час перевірки документація була недоступна. Для документованого парсера командного рядка використовуйте [**LECmd**](https://github.com/EricZimmerman/LECmd).<sup>[[15]](#references)</sup>

Ці інструменти зазвичай показують два набори часових міток:

- **Часові мітки цільового об’єкта:**
  1. FileModifiedDate
  2. FileAccessDate
  3. FileCreationDate
- **Часові мітки файлу ярлика:**
  1. LinkModifiedDate
  2. LinkAccessDate
  3. LinkCreationDate.

Перший набір стосується цільового об’єкта; другий — самого файлу LNK. Інтерпретуйте обидва набори з урахуванням документації парсера та контексту файлової системи.<sup>[[14]](#references)[[15]](#references)</sup>

Таку саму інформацію можна отримати за допомогою інструмента Windows CLI: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd).<sup>[[15]](#references)</sup>

```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```

У цьому випадку інформацію буде збережено у файлі CSV.

### Jumplists

Jump Lists — це списки нещодавніх або пов’язаних із певними завданнями елементів для окремих програм; вони можуть бути автоматичними або користувацькими.<sup>[[13]](#references)</sup>

Автоматичні Jump Lists зберігаються в `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` і мають назви на кшталт `{id}.automaticDestinations-ms`, де ID визначає програму.

Користувацькі Jump Lists зберігаються в `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\`; програма визначає, які записи завдань або елементів створювати.

Час створення та зміни у файловій системі стосується файлу Jump List, а не автоматично першого й останнього доступу до кожного переліченого об’єкта. Зіставляйте проаналізовані записи з часовими мітками файлу та іншими артефактами.<sup>[[13]](#references)</sup>

Переглянути Jump Lists можна за допомогою [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).<sup>[[5]](#references)</sup>

![Recent Documents (LNK) - Jumplists: Переглядати jumplists можна за допомогою JumplistExplorer](<../../../images/image (168).png>)

(_Зверніть увагу: часові мітки, які показує JumplistExplorer, стосуються самого файлу jumplist_)

### Shellbags

[**Перейдіть за цим посиланням, щоб дізнатися, що таке shellbags.**](interesting-windows-registry-keys.md#shellbags)

## Використання USB-пристроїв у Windows

Використання USB-пристроїв іноді можна підтвердити артефактами, створеними під час доступу до файлів на знімному носії, зокрема:

- Windows Recent Folder
- Microsoft Office Recent Folder
- Jumplists

Такі інструменти, як [**USBDetective**](https://usbdetective.com), зіставляють ці артефакти із записами про USB-пристрої, але наявність артефактів залежить від версії Windows і програми.<sup>[[18]](#references)</sup>

Під час тестування робочих процесів MTP у Windows XP і Windows 7 було зафіксовано, що деякі LNK вказували на папку `WPDNSE`, а не на оригінальний шлях.<sup>[[16]](#references)</sup>

![Shellbags - Використання USB-пристроїв у Windows: Зверніть увагу: деякі LNK-файли вказують не на оригінальний шлях, а на папку WPDNSE](<../../../images/image (218).png>)

У цьому дослідженні було виявлено копії за шляхом `%LOCALAPPDATA%\Temp\WPDNSE\{FolderGUID}`; під час тестування тимчасовий вміст не зберігався після перезапуску, а GUID можна було зіставити з даними shellbag. Вважайте це поведінкою, що залежить від ОС, пристрою та програми, а не універсальним правилом.<sup>[[16]](#references)</sup>

### Інформація в реєстрі

[Перегляньте цю сторінку, щоб дізнатися](interesting-windows-registry-keys.md#usb-information), які розділи реєстру містять цікаві відомості про підключені USB-пристрої.

### setupapi

У Vista та новіших версіях перевірте `C:\Windows\inf\setupapi.dev.log` на наявність активності зі встановлення пристроїв. Заголовки розділів містять часові мітки `Section start`; вони документують обробку встановлення, тож їх слід зіставляти з іншими свідченнями підключення, а не вважати точним часом фізичного підключення.<sup>[[17]](#references)</sup>

![Інформація в реєстрі - setupapi: Перевірте файл C: Windows inf setupapi.dev.log, щоб отримати часові мітки підключення USB (шукайте Section start)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) можна використовувати для отримання відомостей про USB-пристрої, підключені до образу.<sup>[[18]](#references)</sup>

![setupapi - USB Detective: USBDetective можна використовувати для отримання відомостей про USB-пристрої, підключені до образу](<../../../images/image (452).png>)

### Очищення Plug and Play

Заплановане завдання `Plug and Play Cleanup` видаляє застарілі версії драйверів. Згідно з документацією Adam Harrison, визначення завдання для Windows 10 також охоплює драйвери, які не використовувалися протягом 30 днів, тож дані про драйвери знімних пристроїв можуть бути очищені; перш ніж поширювати це твердження на інші системи, перевірте локальне визначення завдання та збірку Windows.<sup>[[1]](#references)</sup>

Завдання розташоване за таким шляхом: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

![XML-визначення запланованого завдання Windows Plug and Play Cleanup](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Основні компоненти та параметри завдання:**

- **pnpclean.dll**: Ця DLL відповідає за виконання очищення.
- **UseUnifiedSchedulingEngine**: Встановлено значення `TRUE`, що вказує на використання універсального механізму планування завдань.
- **MaintenanceSettings**:
  - **Period ('P1M')**: Вказує Планувальнику завдань запускати очищення щомісяця під час звичайного автоматичного обслуговування.
  - **Deadline ('P2M')**: Вказує Планувальнику завдань, якщо завдання не виконується протягом двох місяців поспіль, запустити його під час аварійного автоматичного обслуговування.

Ця конфігурація планує регулярне обслуговування та повторні спроби після послідовних збоїв; конкретні XML і поведінка залежать від версії.<sup>[[1]](#references)</sup>

**Докладніше:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html).<sup>[[1]](#references)</sup>

## Електронна пошта

Електронні листи містять **2 важливі частини: заголовки та вміст**. У **заголовках** можна знайти такі відомості:

- **Хто** надіслав лист (адреса електронної пошти, IP-адреса, поштові сервери, які перенаправляли лист)
- **Коли** було надіслано лист

Заголовки `References` і `In-Reply-To` також можуть містити ID повідомлень, за якими відповіді пов’язують із листуванням.<sup>[[76]](#references)</sup>

![Plug and Play Cleanup - Електронна пошта: Коли було надіслано лист](<../../../images/image (593).png>)

### Програма Windows Mail

Ця програма зберігає вміст листів у допоміжних текстових або HTML-файлах за такими шляхами, як `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`; точне розташування нумерованих папок і файлів може відрізнятися залежно від артефакту.<sup>[[75]](#references)</sup>

**Метадані** листів і **контакти** можна знайти в **базі даних ESE** `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`.<sup>[[75]](#references)</sup>

`store.vol` використовує формат Extensible Storage Engine (ESE). Працюйте з копією та використовуйте парсер ESE, наприклад [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html); якщо інструмент вимагає розширення `.edb`, перейменуйте лише копію та перевірте схему таблиць, перш ніж покладатися на таблицю `Message`.<sup>[[19]](#references)[[75]](#references)</sup>

### Microsoft Outlook

Під час аналізу властивостей Outlook MAPI важливими є такі канонічні властивості:

- `PidTagClientSubmitTime`: час у форматі UTC, коли клієнт надіслав повідомлення.
- `PidTagConversationIndex`: відносне положення повідомлення в ланцюжку листування.
- `PidTagEntryId`: ідентифікатор об’єкта повідомлення.
- `PidTagMessageFlags`: прапорці стану, як-от надіслане, прочитане, непрочитане або з вкладеннями.
- `PidTagLastVerbExecuted`: остання зафіксована дія з повідомленням, наприклад відкриття, відповідь або пересилання.<sup>[[20]](#references)[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Розташування файлів даних Outlook залежить від версії та типу облікового запису. Microsoft зазначає такі поширені розташування файлів PST/OST:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Шлях реєстру `HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` може містити дані профілю Outlook і пов’язану конфігурацію файлів даних.

Файли PST можуть містити листи, контакти, дані календаря та інші елементи Outlook. Переглянути копію можна за допомогою [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).<sup>[[25]](#references)[[67]](#references)</sup>

![Програма Windows Mail - Microsoft Outlook: Файл PST можна відкрити за допомогою Kernel PST Viewer](<../../../images/image (498).png>)

### Файли Microsoft Outlook OST

**Файл OST** — це локальний кеш для облікових записів Exchange або Microsoft 365; режим Cached Exchange не застосовується до облікових записів POP чи IMAP. Період зберігання офлайн можна налаштувати, і зазвичай типовим є значення 12 місяців; обмеження розміру PST/OST налаштовуються окремо. Щоб переглянути файл OST, можна скористатися [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html).<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[68]](#references)</sup>

### Відновлення вкладень

Втрачені вкладення іноді можна відновити з таких розташувань:

- Для застарілих конфігурацій Outlook/IE: `%LOCALAPPDATA%\Temporary Internet Files\Content.Outlook`
- Для новіших конфігурацій Outlook/IE11: `%LOCALAPPDATA%\Microsoft\Windows\INetCache\Content.Outlook`.<sup>[[65]](#references)</sup>

### Файли Thunderbird MBOX

**Thunderbird** зберігає дані профілю в `%APPDATA%\Thunderbird\Profiles`; папки пошти зазвичай представлені файлами mbox без розширення в каталогах `Mail` або `ImapMail`, специфічних для облікового запису.<sup>[[29]](#references)[[30]](#references)</sup>

### Ескізи зображень

- **Windows XP**: Попередні перегляди ескізів зазвичай зберігалися в файлах `thumbs.db` окремих папок.
- **Мережеві папки**: файл `thumbs.db` усе ще може створюватися для UNC-папки, якщо ввімкнено відповідну поведінку ескізів; не вважайте, що його створюють у кожній версії Windows або за будь-якої політики.
- **Windows Vista і новіші версії**: Системний кеш ескізів централізовано зберігається в `%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer` у файлах на кшталт **thumbcache_xxx.db**. [**Thumbsviewer**](https://thumbsviewer.github.io) може аналізувати застарілі файли `Thumbs.db`, а [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) — сучасні бази даних кешу ескізів.<sup>[[31]](#references)[[32]](#references)[[33]](#references)</sup>

### Інформація в реєстрі Windows

Реєстр Windows, у якому зберігаються дані конфігурації системи та користувачів, міститься у файлах-кущах за такими шляхами:

- `%WINDIR%\System32\Config` — системні кущі, що забезпечують різні підрозділи `HKEY_LOCAL_MACHINE`.
- `%USERPROFILE%\NTUSER.DAT` — кущ `HKEY_CURRENT_USER` користувача.
- У деяких старих інсталяціях Windows є копії в `%WINDIR%\System32\Config\RegBack\`; у Windows 10 версії 1803 і новіших цей каталог не заповнюється автоматично, якщо не ввімкнено періодичне резервне копіювання.<sup>[[34]](#references)[[35]](#references)</sup>
- Дані оболонки та реєстрації класів для окремих користувачів у сучасних версіях Windows також зазвичай зберігаються в `%LOCALAPPDATA%\Microsoft\Windows\UsrClass.dat`.<sup>[[34]](#references)[[66]](#references)</sup>

### Інструменти

Для аналізу кущів реєстру можна використовувати різні інструменти; перш ніж покладатися на результати, перевірте, які формати кущів і версії підтримує кожен інструмент:

- **Registry Editor**: Вбудований у Windows. Це графічний інтерфейс для перегляду реєстру Windows у поточному сеансі.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): Дозволяє завантажити файл реєстру та переглядати його за допомогою графічного інтерфейсу. Також містить закладки, що позначають ключі з цікавою інформацією.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Також має графічний інтерфейс для перегляду завантаженого реєстру, а ще містить плагіни, які позначають цікаві відомості в ньому.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Ще одна програма з графічним інтерфейсом, яка може витягувати інформацію із завантаженого куща реєстру.<sup>[[5]](#references)[[36]](#references)[[37]](#references)</sup>

### Відновлення видалених елементів

Видалені комірки куща можуть залишатися, доки їхній простір не буде повторно використано, але можливість відновлення залежить від стану куща та парсера; розглядайте відновлені видалені ключі як докази, що потребують перевірки, а не як гарантовано достовірні записи.

### Час останнього запису

Ключі реєстру мають часову мітку останнього запису; Windows надає її для ключа, а не для кожного його значення окремо, тож значення не обов’язково має власну незалежну часову мітку зміни.<sup>[[69]](#references)</sup>

### SAM

Кущ **SAM** містить дані про локальні облікові записи користувачів і груп, зокрема хеші паролів, захищені матеріалом системного boot key.<sup>[[38]](#references)[[39]](#references)</sup>

У `SAM\Domains\Account\Users` можна отримати ідентифікатори облікових записів, а також деякі поля входу та політик. Для офлайн-вилучення хешів також потрібен кущ `SYSTEM`, щоб отримати відповідний матеріал boot key.<sup>[[38]](#references)[[39]](#references)</sup>

### Цікаві записи в реєстрі Windows


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Виконані програми

### Основні процеси Windows

[Публікацію про поширені процеси Windows](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) наведено для додаткового ознайомлення; твердження про поведінку процесів перевіряйте за актуальною документацією Windows і локальними доказами.<sup>[[2]](#references)</sup>

### Нещодавні програми Windows

У версіях Windows 10, де доступний цей артефакт, `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps` містить підрозділи для окремих програм із такими полями, як час останнього використання та кількість запусків; у пізніших випусках цей артефакт прибрали, тож перевірте цільову збірку.<sup>[[64]](#references)</sup>

### BAM (Background Activity Moderator)

У системах, де доступний Background Activity Moderator, перевірте шлях `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` або новіший шлях `...\bam\State\UserSettings\{SID}`. Значення впорядковано за SID користувача; вони можуть містити відстежувані шляхи до виконуваних файлів і дані про виконання у форматі, подібному до FILETIME. Артефакт залежить від версії, тому його слід підтверджувати іншими доказами.<sup>[[63]](#references)</sup>

### Windows Prefetch

Prefetch кешує ресурси та метадані запуску, щоб програми запускалися швидше.

Файли Prefetch зберігаються як файли `.pf` у `C:\Windows\Prefetch`; формат, термін зберігання та обмеження на кількість файлів залежать від версії Windows. Microsoft документує збереження часу останніх восьми запусків і до 1024 файлів у Windows 8 та новіших версіях, тому не слід узагальнювати застарілі описи фіксованих обмежень.<sup>[[13]](#references)</sup>

Зазвичай назва файлу має формат `{program_name}-{hash}.pf`, де хеш залежить від контексту виконання, зокрема шляху та аргументів; Windows 10 і новіші версії можуть стискати файл. Наявність такого файлу є корисним свідченням виконання, але сама по собі не доводить, що програму запустив користувач; її слід зіставити з іншими артефактами.<sup>[[13]](#references)</sup>

Для аналізу цих файлів можна скористатися [**PECmd.exe**](https://github.com/EricZimmerman/PECmd), який підтримує аналіз каталогів, виведення даних у CSV/HTML і розпакування відповідних файлів Prefetch у Windows 10.<sup>[[40]](#references)</sup>

```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```

![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superfetch/SysMain** доповнює Prefetch, використовуючи історичні шаблони використання для пришвидшення завантаження. У системах, де створюються відповідні файли, їхні бази даних зазвичай розташовані в `C:\Windows\Prefetch\Ag*.db`; формат і наявність залежать від версії.<sup>[[41]](#references)</sup>

Ці бази даних можуть містити назви програм, кількість запусків, доступні файли або томи, шляхи та часові діапазони, але їх не слід вважати точним журналом виконання.<sup>[[41]](#references)</sup>

Посилання на [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) збережено як можливий парсер; перед використанням перевірте його доступність і підтримуваний формат виводу за документацією інструмента.

### SRUM

**System Resource Usage Monitor** (SRUM) реєструє використання ресурсів програмами та користувачами. Його було представлено у Windows 8; дані зберігаються в базі даних ESE `C:\Windows\System32\sru\SRUDB.dat`.<sup>[[13]](#references)</sup>

Він надає таку інформацію:

- AppID and Path
- User/SID associated with the record
- Sent Bytes
- Received Bytes
- Network Interface
- Connection duration
- Process duration

Періодичність збору та термін зберігання залежать від реалізації; не припускайте, що кожен запис відповідає точному 60-хвилинному інтервалу виконання.<sup>[[13]](#references)</sup>

Витягнути й переглянути дані можна за допомогою [**srum_dump**](https://github.com/MarkBaggett/srum-dump), використовуючи параметри, описані в документації поточної версії інструмента.<sup>[[42]](#references)</sup>

```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -o C:\Users\student\Desktop\srum --NO_CONFIRM
```

### AppCompatCache (ShimCache)

**AppCompatCache**, також відомий як **ShimCache**, є частиною інфраструктури сумісності застосунків Windows і записує метадані файлів для ухвалення рішень щодо сумісності. Шлях до hive, формат записів, місткість збереження та поля залежать від версії Windows; у сучасних версіях Windows сам по собі ShimCache не може довести, що користувач запускав файл. Проаналізуйте відповідний hive `SYSTEM` за допомогою інструмента [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser) і зіставте його дані з артефактами виконання.<sup>[[13]](#references)[[43]](#references)</sup>

![SRUM - AppCompatCache (ShimCache): Для аналізу збереженої інформації рекомендується використовувати інструмент AppCompatCacheParser](<../../../images/image (75).png>)

### Amcache

Файл **Amcache.hve** — це hive реєстру, у якому Windows веде облік виявлених застосунків і файлів. Зазвичай він розташований за шляхом `C:\Windows\AppCompat\Programs\Amcache.hve`.

Він може містити записи про пов’язані та непов’язані файли, шляхи й значення SHA1, але сам факт його наявності є лише свідченням інвентаризації й не доводить, що процес виконувався.<sup>[[13]](#references)[[44]](#references)</sup>

Щоб витягти дані з **Amcache.hve** та проаналізувати їх, скористайтеся інструментом [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser). Ця команда аналізує hive і створює вихідні дані у форматі CSV.<sup>[[44]](#references)</sup>

Наприклад:

```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```

Серед створених CSV-файлів `Amcache_Unassociated file entries` може бути корисним під час дослідження файлів, не пов’язаних із розпізнаною програмою.<sup>[[44]](#references)</sup>

### RecentFileCache

У системах Windows 7 файл `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` може містити інформацію про нещодавно виявлені бінарні файли; його доступність і семантика залежать від версії.

Для аналізу цього файлу можна скористатися [**RecentFileCacheParser**](https://github.com/EricZimmerman/RecentFileCacheParser).<sup>[[45]](#references)</sup>

### Заплановані завдання

Дані про заплановані завдання можна знайти в `C:\Windows\System32\Tasks` для сучасних завдань і в `C:\Windows\Tasks` у файлах `.job` для застарілих завдань; перевіряйте формат визначення завдання, відповідний до версії ОС.<sup>[[73]](#references)[[74]](#references)</sup>

### Служби

База даних Service Control Manager розташована в `SYSTEM\CurrentControlSet\Services` (для офлайн-куща SYSTEM перевірте відповідний розділ control set); вона містить конфігурацію служб і драйверів, зокрема шляхи до виконуваних файлів і типи запуску.<sup>[[72]](#references)</sup>

### **Windows Store**

Інстальовані програми Windows Store можуть бути представлені в `\ProgramData\Microsoft\Windows\AppRepository\`, зокрема в базі даних **`StateRepository-Machine.srd`**. Схема та шляхи відрізняються залежно від випуску Windows.<sup>[[71]](#references)</sup>

База даних може містити ідентифікатори програм, номери пакетів і відображувані імена. Прогалини в ідентифікаторах самі по собі не доводять, що програму було видалено; підтверджуйте це даними про пакети та станом реєстру.

Реєстрації пакетів також можуть міститися в `HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`. Microsoft документує підрозділ `Deprovisioned`, специфічний для певної версії, для видалених попередньо підготовлених програм; не припускайте, що підрозділ `Deleted` існує в кожній збірці.<sup>[[70]](#references)</sup>

## Події Windows

Залежно від постачальника, події Windows можуть містити:

- Що сталося
- Часову позначку `TimeCreated`, яку потрібно інтерпретувати з урахуванням схеми події та контексту часу на хості
- Задіяних користувачів
- Задіяні хости (ім’я хоста, IP)
- Ресурси, до яких зверталися (файли, папки, принтери або служби).<sup>[[49]](#references)</sup>

До Windows Vista журнали подій зазвичай використовували застарілий двійковий формат і зберігалися в `C:\Windows\System32\config`; у Vista та новіших версіях використовується формат Windows Event Log, зазвичай у `C:\Windows\System32\winevt\Logs`, де файли `.evtx` містять дані подій, відображені у форматі XML.<sup>[[46]](#references)[[47]](#references)</sup>

У реєстрі SYSTEM конфігурація каналів зберігається в **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**, зокрема налаштований шлях до файлу та параметри зберігання.<sup>[[47]](#references)</sup>

Їх можна переглядати за допомогою Windows Event Viewer (**`eventvwr.msc`**) або таких інструментів, як [**Event Log Explorer**](https://eventlogxp.com) і [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md).<sup>[[5]](#references)[[48]](#references)[[61]](#references)</sup>

## Розуміння журналювання подій безпеки Windows

У Vista та новіших версіях канал Security зазвичай зберігається в `C:\Windows\System32\winevt\Logs\Security.evtx`. Його максимальний розмір і політику зберігання можна налаштувати; за циклічного журналювання старі записи можуть перезаписуватися, коли файл досягає обмеження. Канал може реєструвати події автентифікації, виходу із системи, привілеїв, політики аудиту та доступу до об’єктів, якщо ввімкнено відповідний аудит.<sup>[[46]](#references)[[47]](#references)</sup>

### Основні Event ID для автентифікації користувачів:

- **Event ID 4624**: Успішний вхід облікового запису.<sup>[[50]](#references)</sup>
- **Event ID 4625**: Невдалий вхід облікового запису.<sup>[[51]](#references)</sup>
- **Event ID 4634**: Сеанс входу завершено.<sup>[[52]](#references)</sup>
- **Event ID 4647**: Користувач ініціював вихід із системи.<sup>[[53]](#references)</sup>
- **Event ID 4672**: Новому входу призначено спеціальні привілеї; це типово для системних облікових записів і облікових записів адміністраторів, тож саме по собі не доводить зловмисну активність.<sup>[[54]](#references)</sup>

#### Типи входу, які зазвичай реєструються в 4624, 4625, 4634 і 4647:

- **Interactive (2)**: Інтерактивний локальний вхід.
- **Network (3)**: Доступ до спільного ресурсу.
- **Batch (4)**: Вхід пакетного процесу.
- **Service (5)**: Вхід служби.
- **Unlock (7)**: Розблокування робочої станції.
- **NetworkCleartext (8)**: Мережевий вхід, під час якого облікові дані передаються пакету автентифікації у відкритому тексті.
- **NewCredentials (9)**: Вхід із використанням наданих альтернативних облікових даних для вихідних з’єднань.
- **RemoteInteractive (10)**: Вхід через Remote Desktop або Terminal Services.
- **CachedInteractive (11)**: Інтерактивний вхід із використанням кешованих доменних облікових даних.
- **CachedRemoteInteractive (12)**: Кешований віддалений інтерактивний вхід.
- **CachedUnlock (13)**: Розблокування з використанням кешованих облікових даних.<sup>[[50]](#references)[[51]](#references)</sup>

#### Коди Status і Sub Status для EventID 4625:

- **0xC0000064**: Такого користувача немає.
- **0xC000006A**: Ім’я користувача правильне, але пароль неправильний.
- **0xC0000234**: Обліковий запис заблоковано.
- **0xC0000072**: Обліковий запис вимкнено.
- **0xC000006F**: Спроба входу поза дозволеними годинами.
- **0xC0000070**: Порушення обмеження робочої станції.
- **0xC0000193**: Термін дії облікового запису завершився.
- **0xC0000071**: Термін дії пароля завершився.
- **0xC0000133**: Різниця в часі між клієнтом і сервером надто велика.
- **0xC0000224**: Обліковий запис має змінити пароль.
- **0xC0000225**: `STATUS_NOT_FOUND`; сам код не вказує на системну помилку чи атаку.
- **0xC000015B**: Обліковому запису не надано запитаний тип входу.<sup>[[51]](#references)[[55]](#references)</sup>

#### EventID 4616:

- **Зміна часу**: Системний час було змінено. Багато подій відображають звичайне коригування часу службою часу, тому перш ніж вважати це втручанням, зіставте дані про ініціатора та джерело часу.<sup>[[56]](#references)</sup>

#### Event ID 12, 13, 1074, 6005, 6006, 6008 і 6009:

- **Контекст живлення та служб**: Подія 12 фіксує запуск ОС, 13 — її завершення роботи, 1074 — заплановане завершення роботи або перезапуск, 6008 вказує на неочікуване завершення роботи, а 6009 фіксує версію Windows під час завантаження. Події 6005 і 6006 відповідно вказують на запуск і зупинку служби Event Log; самі по собі вони не доводять запуск і завершення роботи ОС.<sup>[[57]](#references)[[58]](#references)</sup>

#### EventID 1102:

- **Видалення журналу**: Подія 1102 фіксує очищення журналу аудиту Security; дослідіть ініціатора та сусідні події, а не робіть висновок про намір лише на підставі цієї події.<sup>[[62]](#references)</sup>

#### EventID для відстеження USB-пристроїв:

- **20001 / 20003**: Події встановлення пристроїв `UserPnp`, які можуть допомогти визначити перше використання або встановлення.
- **10000 / 10100**: Події `DriverFrameworks-UserMode`, що можуть супроводжувати активність пристрою.
- **Event ID 112**: Подія `DeviceSetupManager/Admin`, що може містити часові позначки, пов’язані з підключенням.
- Семантика постачальника, каналу й подій відрізняється залежно від версії Windows; перш ніж тлумачити подію, перевірте назву постачальника та її дані.<sup>[[59]](#references)</sup>

Практичні приклади типів входу та пов’язаних із ними облікових даних наведено в [детальному посібнику Altered Security](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).<sup>[[60]](#references)</sup>

Деталі події, зокрема тип входу, статус, підстатус, вихідна адреса та поля процесу, дають контекст для Event ID 4625; код статусу або повторювані невдалі спроби — це привід для розслідування, а не остаточний висновок.<sup>[[51]](#references)[[55]](#references)</sup>

### Відновлення подій Windows

Оскільки в журналах подій зазвичай використовується циклічний режим, записи, перезаписані засобом журналювання, можуть бути невідновними. Перш ніж взаємодіяти з активною системою, збережіть forensic-образ або робочу копію; використовуйте перевірений аналізатор чи carving-інструмент, наприклад **Bulk_extractor**, лише після того, як переконаєтеся, що ця версія інструмента підтримує цільові дані `.evtx`, і не від’єднуйте працюючу систему від живлення лише заради спроби відновити події.<sup>[[46]](#references)</sup>

### Виявлення поширених атак за подіями Windows

Практичний довідник з Event ID див. за посиланням [Red Team Recipe](https://redteamrecipe.com/event-codes/); перевіряйте наведені там приклади за документацією постачальників вище.

#### Атаки методом перебору

Зіставляйте повторні невдалі спроби з Event ID 4625 із подальшим успішним входом 4624, типом входу, статусом, джерелом і контекстом облікового запису; така послідовність є ознакою для розслідування, а не доказом атаки.<sup>[[50]](#references)[[51]](#references)</sup>

#### Зміна часу

Event ID 4616 фіксує зміни системного часу, які можуть ускладнити аналіз часової шкали; порівняйте їх із даними служби часу та хоста.<sup>[[56]](#references)</sup>

#### Відстеження USB-пристроїв

Event ID USB залежать від постачальника; зіставляйте `UserPnp` 20001/20003, `DriverFrameworks-UserMode` 10000/10100 і `DeviceSetupManager/Admin` 112 з артефактами SetupAPI та реєстру.<sup>[[17]](#references)[[59]](#references)</sup>

#### Події живлення системи

Використовуйте 12/13/1074/6008/6009 для отримання контексту запуску, завершення роботи, перезапуску ОС і неочікуваних збоїв живлення; 6005/6006 позначають запуск і зупинку служби Event Log.<sup>[[57]](#references)[[58]](#references)</sup>

#### Видалення журналу

Security Event ID 1102 фіксує очищення журналу аудиту Security; зіставте її з відповідним обліковим записом і процесом.<sup>[[62]](#references)</sup>



## References

- [1] [Очищення Plug and Play у Windows](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)
- [2] [jonahacks.medium.com — Дослідження поширених процесів Windows](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)
- [3] [Цифрова криміналістика сповіщень Windows 10](https://iconline.ipleiria.pt/server/api/core/bitstreams/833e160a-e382-46b4-82ad-fb2c8c995d62/content)
- [4] [WxTCmd](https://github.com/EricZimmerman/WxTCmd)
- [5] [Криміналістичні інструменти Eric Zimmerman](https://ericzimmerman.github.io/#!index.md)
- [6] [Zone.Identifier та альтернативні потоки даних](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/6e3f7352-d11c-4d76-8c39-2516a9df36e8)
- [7] [Rifiuti2](https://github.com/abelcheung/rifiuti2)
- [8] [Служба тіньового копіювання томів](https://learn.microsoft.com/en-us/windows/server/storage/file-server/volume-shadow-copy-service)
- [9] [ShadowCopyView](https://www.nirsoft.net/utils/shadow_copy_view.html)
- [10] [Резервне копіювання та відновлення реєстру за допомогою VSS](https://learn.microsoft.com/en-us/windows/win32/vss/registry-backup-and-restore-operations-under-vss)
- [11] [Розділи реєстру для резервного копіювання та відновлення](https://learn.microsoft.com/en-us/windows/win32/backup/registry-keys-for-backup-and-restore)
- [12] [Проблема з продуктивністю Word у розташуванні AutoRecover](https://learn.microsoft.com/en-us/previous-versions/troubleshoot/microsoft-365/microsoft-365-apps/word/performance-issue-on-autorecover-location)
- [13] [Посібник із реагування на інциденти](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/final/en-us/microsoft-brand/documents/IR-Guidebook-Final.pdf)
- [14] [MS-SHLLINK: двійковий формат Shell Link](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/c3376b21-0931-45e4-b2fc-a48ac0e60d15)
- [15] [LECmd](https://github.com/EricZimmerman/LECmd)
- [16] [Криміналістика USB MTP: виявлення артефактів витоку даних](https://studylib.net/doc/8690663/usb-devices-and-media-transfer-protocol)
- [17] [Записи журналу встановлення пристроїв SetupAPI](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/setupapi-device-installation-log-entries)
- [18] [USB Detective](https://usbdetective.com)
- [19] [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)
- [20] [PidTagClientSubmitTime](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/ca98145f-7f87-42b4-b0ef-124c6c6f8d83)
- [21] [PidTagConversationIndex](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/57f8de0f-5f53-423a-8947-7943dd959997)
- [22] [EntryID та пов’язані типи](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcdata/57e8bcbf-11d0-40fe-8833-5558bb9c0c89)
- [23] [PidTagMessageFlags](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcmsg/a0c52fe2-3014-43a7-942d-f43f6f91c366)
- [24] [PidTagLastVerbExecuted](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxomsg/87a8b6b8-59a4-4859-9dcd-8b0f36e3d729?redirectedfrom=MSDN)
- [25] [Пошук і перенесення файлів даних Outlook](https://support.microsoft.com/en-us/outlook/find-and-transfer-outlook-data-files-from-one-computer-to-another)
- [26] [Увімкнення режиму кешованого Exchange](https://support.microsoft.com/en-us/outlook/turn-on-cached-exchange-mode)
- [27] [Синхронізується лише частина елементів](https://learn.microsoft.com/en-us/troubleshoot/outlook/user-interface/only-subset-items-synchronized)
- [28] [Налаштування обмежень розміру файлів даних Outlook](https://learn.microsoft.com/en-us/microsoft-365-apps/outlook/data-files/configure-size-limit-outlook-data-files)
- [29] [Профілі — де Thunderbird зберігає дані користувача](https://support.mozilla.org/bm/kb/profiles-where-thunderbird-stores-user-data)
- [30] [Параметри облікового запису Thunderbird і каталоги mbox](https://support.mozilla.org/en-US/kb/dangerous-directories-Thunderbird-account-settings)
- [31] [Інтерфейс IThumbnailCache](https://learn.microsoft.com/en-us/windows/win32/api/thumbcache/nn-thumbcache-ithumbnailcache)
- [32] [Thumbs Viewer](https://thumbsviewer.github.io)
- [33] [Thumbcache Viewer](https://thumbcacheviewer.github.io)
- [34] [Кущі реєстру](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives)
- [35] [Резервна копія системного реєстру не зберігається в RegBack](https://learn.microsoft.com/en-gb/troubleshoot/windows-client/installing-updates-features-roles/system-registry-no-backed-up-regback-folder)
- [36] [RegRipper 3.0](https://github.com/keydet89/RegRipper3.0)
- [37] [Відновлення реєстру Windows](https://www.mitec.cz/wrr.html)
- [38] [Віддалене редагування реєстру](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remotely-edit-the-registry)
- [39] [Технічний огляд паролів](https://learn.microsoft.com/en-us/windows-server/security/kerberos/passwords-technical-overview)
- [40] [PECmd](https://github.com/EricZimmerman/PECmd)
- [41] [Артефакти Superfetch](https://kb.binalyze.com/air/features/acquisition/supported-evidence/windows-collections-detail/superfetch)
- [42] [srum-dump](https://github.com/MarkBaggett/srum-dump)
- [43] [AppCompatCacheParser](https://github.com/EricZimmerman/AppCompatCacheParser)
- [44] [AmcacheParser](https://github.com/EricZimmerman/AmcacheParser)
- [45] [RecentFileCacheParser](https://github.com/EricZimmerman/RecentFileCacheParser)
- [46] [Формат файлу журналу подій](https://learn.microsoft.com/en-us/windows/win32/eventlog/event-log-file-format)
- [47] [Розділ реєстру Eventlog](https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key)
- [48] [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.5)
- [49] [Властивість події TimeCreated](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-timecreated-systempropertiestype-element)
- [50] [Подія 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- [51] [Подія 4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- [52] [Подія 4634](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4634)
- [53] [Подія 4647](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4647)
- [54] [Подія 4672](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672)
- [55] [MS-ERREF: значення NTSTATUS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55)
- [56] [Подія 4616](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4616)
- [57] [Усунення несправностей неочікуваних перезавантажень за допомогою журналів системних подій](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [58] [Усунення несправностей під час завершення роботи](https://learn.microsoft.com/en-us/troubleshoot/windows-server/installing-updates-features-roles/troubleshoot-error-shutdown-in-process)
- [59] [Криміналістика USB-накопичувачів у Windows 10](https://www.researchgate.net/publication/318514858_USB_Storage_Device_Forensics_for_Windows_10)
- [60] [Чудовий посібник із типів входу Windows](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)
- [61] [Event Log Explorer](https://eventlogxp.com)
- [62] [Подія 1102](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102)
- [63] [Модератор фонової активності](https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/Background-activity-moderator.html)
- [64] [Реєстр — RecentApps](https://artefacts.help/windows_registry_recentapps.html)
- [65] [Quick Print перестає друкувати вкладення PDF в Outlook Desktop](https://support.microsoft.com/en-gb/office/quick-print-stops-printing-pdf-attachments-in-outlook-desktop-512fdeb0-6a88-4e6c-9285-cf957290aad2)
- [66] [Файли реєстру Windows](https://winreg-kb.readthedocs.io/en/latest/sources/windows-registry/Files.html)
- [67] [Kernel PST Viewer](https://www.nucleustechnologies.com/es/visor-de-pst.html)
- [68] [Kernel OST Viewer](https://www.nucleustechnologies.com/ost-viewer.html)
- [69] [RegQueryInfoKeyA](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeya)
- [70] [Як запобігти повторному встановленню видалених програм під час оновлення](https://learn.microsoft.com/en-us/windows/application-management/remove-provisioned-apps-during-update)
- [71] [NIST CFTT: результати тестування FTK і Registry Viewer](https://www.dhs.gov/sites/default/files/publications/test_results_nist_windows_registry_forensic_tool_ftk_7.0.0.163_registry_viewer_2.0.0.7_april_2019.pdf)
- [72] [База даних інстальованих служб](https://learn.microsoft.com/en-us/windows/win32/services/database-of-installed-services)
- [73] [Завдання](https://learn.microsoft.com/en-us/windows/win32/taskschd/tasks)
- [74] [Помилка запланованих завдань: служба планувальника завдань недоступна](https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/task-schedular-service-is-not-available)
- [75] [Навігація базою даних Windows Mail](https://eprints.whiterose.ac.uk/133161/1/Navigating_the_Windows_Mail_database_accepted.pdf)
- [76] [RFC 5322: формат інтернет-повідомлень](https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.4)
- [77] [Керування Recall для клієнтів Windows](https://learn.microsoft.com/en-us/windows/client-management/manage-recall)
- [78] [TotalRecall Reloaded](https://github.com/xaitax/TotalRecall)
{{#include ../../../banners/hacktricks-training.md}}
