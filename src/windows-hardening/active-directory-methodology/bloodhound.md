# BloodHound 和其他 Active Directory 枚举工具

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
adws-enumeration.md
{{#endref}}

> 注意：本页面汇总了一些最实用的工具，用于**枚举**和**可视化** Active Directory 关系。有关通过隐蔽的 **Active Directory Web Services (ADWS)** 通道进行收集的信息，请查看上面的参考链接。

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) 是一个高级的 **AD 查看器和编辑器**，支持：

* 通过 GUI 浏览目录树
* 编辑对象属性和安全描述符
* 创建和比较 Snapshot，以便进行离线分析

### 快速使用

1. 启动工具，并使用任意域凭据连接到 `dc01.corp.local`。
2. 通过 `File ➜ Create Snapshot` 创建离线 Snapshot。
3. 使用 `File ➜ Compare` 比较两个 Snapshot，以发现权限漂移。

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) 可从域中提取大量 artefacts（ACL、GPO、信任关系、CA 模板……），并生成 **Excel 报告**。
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound（图可视化）

[BloodHound](https://github.com/SpecterOps/BloodHound) 使用图论来揭示本地 AD、Entra ID 内部的隐藏权限关系，以及你通过 OpenGraph 导入的任何额外 attack-surface 数据。<sup>[[1]](#references)</sup>

### 部署（Docker CE）
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Collectors

* `SharpHound.exe` / `Invoke-BloodHound` – 原生或 PowerShell 变体
* `RustHound-CE` – 支持 Linux、macOS 和 Windows 的跨平台 CE collector
* `NetExec --bloodhound` – 从 Linux 快速执行基于 LDAP 的收集
* `AzureHound` – Entra ID 枚举
* **SoaPy + BOFHound** – ADWS 收集（参见顶部链接）

> BloodHound CE `v8+` 在 OpenGraph 引入后更改了 collector 输出格式。从 legacy BloodHound 或较旧的 CE 安装升级后，请使用当前 collectors 重新执行 discovery，然后再导入数据。<sup>[[1]](#references)</sup>

#### 常见的 SharpHound 模式
```powershell
SharpHound.exe --CollectionMethods All               # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
SharpHound.exe --CollectionMethods Session --Loop --Loopduration 03:09:41
```
collectors 生成的 JSON 会通过 BloodHound GUI 导入。

#### 来自未加入域的 Windows 主机的 SharpHound

如果你的 operator VM 未加入目标域，请将 DNS 指向 DC，启动一个 **network-only** shell，确认可以在某个 DC 上看到 `SYSVOL`/`NETLOGON`，然后针对远程域进行收集：
```cmd
runas /netonly /user:CORP\svc_bh cmd.exe
net view \\dc01.corp.local
SharpHound.exe -d corp.local --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
```
这对于不应加入域的临时 jump box 或 operator 工作站非常有用。

#### 从 Linux/macOS 进行跨平台收集
```bash
# CE-compatible ZIP from Linux/macOS/Windows
rusthound-ce -d corp.local -u svc.collector@corp.local -p 'Passw0rd!' -z

# Quick LDAP-driven BloodHound dump from Linux
nxc ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --bloodhound --collection All
```
`RustHound-CE` 是从非 Windows 主机获取 CE-compatible output 时的良好默认选择。<sup>[[2]](#references)</sup> 如果你已经在使用 `NetExec` 进行 LDAP 验证或 spraying，那么它很方便，可以快速导入 graph。对于非 AD 数据集，可以通过 [ShareHound](../../network-services-pentesting/pentesting-smb/README.md) 等 collectors 扩展 BloodHound OpenGraph。<sup>[[1]](#references)</sup>

### ADPathFinder（OpenGraph 路径优先级排序）

当 graph 过大、无法手动 pivot 时， [ADPathFinder](https://github.com/NetSPI/AD-PathFinder) 可以在 BloodHound CE/OpenGraph 之上运行。它不只是询问某个 principal 是否能够到达某个 target，还会计算多个低权限用户和计算机到高价值对象的最短路径，将重复使用相同 edges 的路径分组，并找出应当优先修复的共享 choke point。<sup>[[4]](#references)</sup>
```bash
adpathfinder --setup-bloodhound-api
adpathfinder -i SharpHound.zip --ad
adpathfinder -i SharpHound.zip MSSQLHound.zip ConfigManBearPig.zip --ad --pwd Contoso,ContosoIT --ntds ntds.txt -p hashcat.potfile
```
导入 `MSSQLHound` 和 `ConfigManBearPig` 数据后，一个发现可以贯穿 [AD CS](ad-certificates.md)、[MSSQL AD abuse](abusing-ad-mssql.md) 和 [SCCM attack paths](sccm-management-point-relay-sql-policy-secrets.md)，而不是将它们作为彼此独立的线索。<sup>[[4]](#references)</sup> 共享路径示例：
```text
J.REPORTER > MSSQL_HasLogin > j.reporter > MSSQL_ExecuteAs > ReportSvc >
MSSQL_Connect > lab-sql01.training.local > MSSQL_LinkedAsAdmin > sccmdb.training.local >
MSSQL_ExecuteOnHost (as DA@TRAINING.LOCAL) > SCCMDB.TRAINING.LOCAL >
SCCM_AssignAllPermissions > SCCM_Site(TRN)
```
- 跟踪每条边上的**有效安全上下文**。只要某次转换以特权域身份执行，即使路径最初来自普通用户，该路径也会立即变为域关键路径。
- 分组结果非常适合进行**瓶颈点修复**：移除一项 SQL impersonation 权限、linked-server trust、certificate-template abuse path 或 SCCM assignment，就可能一次性消除许多最短路径。
- 使用**图上下文**重新评估“medium”级别的结果。当受感染节点存在通往 Domain Admins、Domain Controllers、CAs 或 SCCM site servers 的后续路径时，应提高 SMB signing disabled、WebClient exposure、delegation mistakes 或可进行 NTLM-relay 的 SQL servers 的优先级。
- 如果你同时拥有 `NTDS.dit` 输出和 hashcat potfile，`--pwd` 会将已破解的密码与 BloodHound 属性关联起来，从而快速区分普通密码复用，以及出现在特权、Kerberoastable、AS-REP roastable 或路径相关账户上的已破解凭据。

### Privilege & logon-right collection

Windows **token privileges**（例如 `SeBackupPrivilege`、`SeDebugPrivilege`、`SeImpersonatePrivilege`、`SeAssignPrimaryTokenPrivilege`）可以绕过 DACL 检查，因此在整个域中映射这些权限，可以暴露 ACL-only 图遗漏的本地 LPE 边。**Logon rights**（`SeInteractiveLogonRight`、`SeRemoteInteractiveLogonRight`、`SeNetworkLogonRight`、`SeServiceLogonRight`、`SeBatchLogonRight` 及其对应的 `SeDeny*` 权限）会在 token 甚至创建之前由 LSA 强制执行，并且 deny 权限优先，因此它们会实质性地限制横向移动（RDP/SMB/scheduled task/service logon）。<sup>[[3]](#references)</sup>

**尽可能以 elevated 权限运行 collectors**：UAC 会为 interactive admins 创建 filtered token（通过 `NtFilterToken`），移除敏感权限，并将 admin SIDs 标记为 deny-only。如果你从 non-elevated shell 枚举权限，高价值权限将不可见，BloodHound 也不会导入这些边。<sup>[[3]](#references)</sup>

目前存在两种互补的 SharpHound collection strategies：<sup>[[3]](#references)</sup>

- **GPO/SYSVOL parsing（stealthy、low-privilege）：**
1. 通过 LDAP 枚举 GPO（`(objectCategory=groupPolicyContainer)`），并读取每个 GPO 的 `gPCFileSysPath`。
2. 从 SYSVOL 获取 `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf`，并解析其中将 privilege/logon-right 名称映射到 SIDs 的 `[Privilege Rights]` 部分。
3. 通过 OUs/sites/domains 上的 `gPLink` 解析 GPO links，列出已链接容器中的 computers，并将这些权限归属到相应 machines。
4. 优点：使用普通用户即可运行且较为安静；缺点：只能看到通过 GPO 推送的权限（会遗漏本地 tweaks）。

- **LSA RPC enumeration（noisy、accurate）：**
- 在目标上拥有 local admin 的上下文中，打开 Local Security Policy，并针对每项 privilege/logon right 调用 `LsaEnumerateAccountsWithUserRight`，通过 RPC 枚举已分配的 principals。
- 优点：可以捕获在本地或 GPO 之外设置的权限；缺点：会产生 noisy network traffic，并且每台 host 都要求 admin 权限。

**这些边暴露的示例 abuse path：** `CanRDP` ➜ 你的用户同时拥有 `SeBackupPrivilege` 的 host ➜ 启动 elevated shell 以避免 filtered tokens ➜ 使用 backup semantics 读取 `SAM` 和 `SYSTEM` hives，即使它们具有严格的 DACL ➜ 导出并离线运行 `secretsdump.py`，恢复本地 Administrator NT hash，用于横向移动/权限提升。<sup>[[3]](#references)</sup>

### Prioritising Kerberoasting with BloodHound

使用图上下文，使 roasting 保持目标性：

1. 使用兼容 ADWS 的 collector 进行一次 collection，然后离线处理：
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. 导入 ZIP，将已攻陷的 principal 标记为 owned，并运行内置查询（*Kerberoastable Users*、*Shortest Paths to Domain Admins*），以发现拥有 admin/infra 权限的 SPN accounts。
3. 根据 blast radius 对 SPNs 排序；在 cracking 前检查 `pwdLastSet`、`lastLogon` 和允许的 encryption types。
4. 仅请求选定的 tickets，离线 crack，然后使用新的 access 重新查询 BloodHound：
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```

## Group3r

[Group3r](https://github.com/Group3r/Group3r) 用于枚举 **Group Policy Objects** 并突出显示 misconfigurations。
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) 对 Active Directory 执行**健康检查**，并生成带有风险评分的 HTML 报告。
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## 参考资料

- [1] [BloodHound Community Edition v8 Launches with OpenGraph: 超越 Active Directory 和 Entra ID 的 OpenGraph 身份攻击路径](https://specterops.io/blog/2025/07/29/bloodhound-community-edition-v8-launches-with-opengraph-identity-attack-paths-beyond-active-directory-entra-id/)
- [2] [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [3] [超越 ACL：使用 BloodHound 映射 Windows 权限提升路径](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)
- [4] [ADPathFinder：BloodHound CE 中的 OpenGraph 攻击路径映射](https://www.netspi.com/blog/technical-blog/network-pentesting/adpathfinder-opengraph-attack-path-mapping-in-bloodhound-ce/)

{{#include ../../banners/hacktricks-training.md}}
