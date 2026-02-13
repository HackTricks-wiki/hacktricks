# BloodHound & 其他 Active Directory 枚举工具

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> 注意：此页面汇总了一些最有用的实用程序，用于**枚举**和**可视化** Active Directory 关系。要通过隐蔽的 **Active Directory Web Services (ADWS)** 通道进行收集，请查看上面的参考。

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) 是一个高级的 **AD 查看器 & 编辑器**，功能包括：

* 通过 GUI 浏览目录树
* 编辑对象属性和安全描述符
* 创建快照/比较以进行离线分析

### 快速使用

1. 启动工具并使用任何域凭据连接到 `dc01.corp.local`。
2. 通过 `File ➜ Create Snapshot` 创建离线快照。
3. 使用 `File ➜ Compare` 比较两个快照以发现权限漂移。

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) 从域中提取大量工件（ACLs、GPOs、trusts、CA templates …）并生成一个 **Excel 报告**。
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (图谱可视化)

[BloodHound](https://github.com/BloodHoundAD/BloodHound) 使用图论 + Neo4j 来揭示本地部署 AD 与 Azure AD 内隐藏的权限关系。

### 部署 (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### 收集器

* `SharpHound.exe` / `Invoke-BloodHound` – 本地或 PowerShell 变体
* `AzureHound` – Azure AD 枚举
* **SoaPy + BOFHound** – ADWS 收集（见顶部链接）

#### 常见 SharpHound 模式
```powershell
SharpHound.exe --CollectionMethods All           # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
```
收集器生成 JSON 并由 BloodHound GUI 摄取。

### 特权与登录权限收集

Windows **token privileges**（例如 `SeBackupPrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`）可以绕过 DACL 检查，因此在域范围内映射它们会暴露仅靠 ACL 图无法发现的本地 LPE 边。**Logon rights**（`SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeServiceLogonRight`, `SeBatchLogonRight` 及其 `SeDeny*` 对应项）在 token 生成之前由 LSA 强制执行，并且 deny 优先，所以它们会实质性地限制横向移动（RDP/SMB/计划任务/服务登录）。

尽可能以提升权限运行收集器：UAC 会为交互管理员创建一个被过滤的 token（通过 `NtFilterToken`），剥离敏感特权并将管理员 SID 标记为 deny-only。如果你从非提升的 shell 枚举特权，高价值特权将不可见，BloodHound 也不会摄取这些边。

现在存在两种互补的 SharpHound 收集策略：

- **GPO/SYSVOL 解析（隐蔽、低权限）：**
1. 通过 LDAP 枚举 GPO（`(objectCategory=groupPolicyContainer)`），并读取每个 `gPCFileSysPath`。
2. 从 SYSVOL 获取 `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` 并解析映射特权/登录权限名到 SID 的 `[Privilege Rights]` 部分。
3. 通过 OU/站点/域上的 `gPLink` 解析 GPO 链接，列出链接容器中的计算机，并将这些权限归属到相应机器。
4. 优点：可用普通用户运行且安静；缺点：只看到通过 GPO 推送的权限（本地调整会被遗漏）。

- **LSA RPC 枚举（噪声大、准确）：**
- 在具有目标主机本地管理员权限的上下文中，打开 Local Security Policy 并对每个特权/登录权限调用 `LsaEnumerateAccountsWithUserRight`，通过 RPC 枚举已分配的主体。
- 优点：捕获本地或 GPO 之外设置的权限；缺点：产生显著网络噪声且每台主机需管理员权限。

**这些边暴露的典型滥用路径示例：** `CanRDP` ➜ 你的用户在该主机上也具有 `SeBackupPrivilege` ➜ 启动提升的 shell 以避免被过滤的 token ➜ 使用备份语义读取尽管有严格 DACL 的 `SAM` 和 `SYSTEM` hives ➜ 外带并离线运行 `secretsdump.py` 恢复本地 Administrator 的 NT hash，用于横向移动/权限提升。

### 使用 BloodHound 优先化 Kerberoasting

使用图上下文来保持 Kerberoasting 的目标聚焦：

1. 使用兼容 ADWS 的收集器收集一次并离线处理：
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. 导入 ZIP，标记被攻破的主体为 owned，并运行内置查询（*Kerberoastable Users*, *Shortest Paths to Domain Admins*）以查找具有管理员/基础设施权限的 SPN 帐户。
3. 按爆破影响半径对 SPN 排序；在破解前检查 `pwdLastSet`、`lastLogon` 和允许的加密类型。
4. 仅请求选定的票据，离线破解，然后用新获得的访问重新查询 BloodHound：
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```

## Group3r

[Group3r](https://github.com/Group3r/Group3r) 枚举 **组策略对象** 并突出显示配置错误。
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) 执行对 Active Directory 的 **健康检查** 并生成带有风险评分的 HTML 报告。
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## 参考资料

- [HackTheBox Mirage：串联 NFS Leaks、Dynamic DNS Abuse、NATS Credential Theft、JetStream Secrets 和 Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [Beyond ACLs：使用 BloodHound 映射 Windows Privilege Escalation Paths](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)

{{#include ../../banners/hacktricks-training.md}}
