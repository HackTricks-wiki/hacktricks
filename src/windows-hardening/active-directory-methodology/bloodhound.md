# BloodHound & Other Active Directory Enumeration Tools

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> NOTE: 本页汇总了一些最有用的用于**enumerate**和**visualise** Active Directory 关系的工具。关于通过隐蔽的 **Active Directory Web Services (ADWS)** 通道进行收集，请查看上面的参考。

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) 是一款高级的 **AD viewer & editor**，可用于：

* 通过 GUI 浏览目录树
* 编辑对象属性和安全描述符
* 创建/比较快照以进行离线分析

### Quick usage

1. 启动工具，并使用任意域凭据连接到 `dc01.corp.local`。
2. 通过 `File ➜ Create Snapshot` 创建一个离线快照。
3. 使用 `File ➜ Compare` 比较两个快照，以发现权限漂移。

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) 会从域中提取大量 artefacts（ACLs、GPOs、trusts、CA templates …），并生成一个 **Excel report**。
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound（图形可视化）

[BloodHound](https://github.com/SpecterOps/BloodHound) 使用图论来揭示 on-prem AD、Entra ID，以及你通过 OpenGraph 导入的任何额外 attack-surface 数据中的隐藏特权关系。

### 部署（Docker CE）
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Collectors

* `SharpHound.exe` / `Invoke-BloodHound` – 原生或 PowerShell 版本
* `RustHound-CE` – 适用于 Linux、macOS 和 Windows 的跨平台 CE collector
* `NetExec --bloodhound` – 来自 Linux 的快速基于 LDAP 的收集
* `AzureHound` – Entra ID 枚举
* **SoaPy + BOFHound** – ADWS 收集（见顶部链接）

> BloodHound CE `v8+` 在 OpenGraph 上线后更改了 collector 输出格式。从旧版 BloodHound 或更早的 CE 安装升级后，在导入数据前，请使用当前 collectors 重新运行 discovery。

#### Common SharpHound modes
```powershell
SharpHound.exe --CollectionMethods All               # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
SharpHound.exe --CollectionMethods Session --Loop --Loopduration 03:09:41
```
收集器生成 JSON，并通过 BloodHound GUI 导入。

#### 来自未加入域的 Windows 主机的 SharpHound

如果你的 operator VM 未加入目标域，将 DNS 指向一台 DC，启动一个 **network-only** shell，确认你能在 DC 上看到 `SYSVOL`/`NETLOGON`，然后针对远程域进行收集：
```cmd
runas /netonly /user:CORP\svc_bh cmd.exe
net view \\dc01.corp.local
SharpHound.exe -d corp.local --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
```
这对于不应加入域的 disposable jump boxes 或 operator workstations 很有用。

#### 从 Linux/macOS 进行跨平台收集
```bash
# CE-compatible ZIP from Linux/macOS/Windows
rusthound-ce -d corp.local -u svc.collector@corp.local -p 'Passw0rd!' -z

# Quick LDAP-driven BloodHound dump from Linux
nxc ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --bloodhound --collection All
```
`RustHound-CE` 在你想从非-Windows 主机获得 CE-compatible 输出时是一个很好的默认选择。`NetExec` 则在你已经用它做 LDAP validation 或 spraying，并且只想快速导入 graph 时很方便。对于非-AD datasets，BloodHound OpenGraph 可以通过像 [ShareHound](../../network-services-pentesting/pentesting-smb/README.md) 这样的 collectors 扩展。

### Privilege & logon-right collection

Windows **token privileges**（例如 `SeBackupPrivilege`、`SeDebugPrivilege`、`SeImpersonatePrivilege`、`SeAssignPrimaryTokenPrivilege`）可以绕过 DACL checks，所以在整个 domain 范围内映射它们可以暴露 ACL-only graphs 会漏掉的本地 LPE edges。**Logon rights**（`SeInteractiveLogonRight`、`SeRemoteInteractiveLogonRight`、`SeNetworkLogonRight`、`SeServiceLogonRight`、`SeBatchLogonRight` 以及它们的 `SeDeny*` 对应项）会在 token 甚至存在之前由 LSA enforced，而 deny 会优先，因此它们会实质性地限制 lateral movement（RDP/SMB/scheduled task/service logon）。

**尽可能以 elevated 方式运行 collectors**：UAC 会为交互式管理员创建一个 filtered token（通过 `NtFilterToken`），移除敏感 privileges，并将 admin SIDs 标记为 deny-only。如果你在 non-elevated shell 中枚举 privileges，高价值 privileges 将不可见，BloodHound 也不会 ingest 这些 edges。

现在有两种互补的 SharpHound collection 策略：

- **GPO/SYSVOL parsing（stealthy, low-privilege）:**
1. 通过 LDAP 枚举 GPOs（`(objectCategory=groupPolicyContainer)`），并读取每个 `gPCFileSysPath`。
2. 从 SYSVOL 获取 `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf`，并解析 `[Privilege Rights]` 部分，该部分把 privilege/logon-right 名称映射到 SIDs。
3. 通过 OUs/sites/domains 上的 `gPLink` 解析 GPO links，列出这些 linked containers 中的 computers，并将 rights 归属到这些机器。
4. 优点：可在 normal user 下工作，而且很安静；缺点：只能看到通过 GPO 推送的 rights（会漏掉本地调整）。

- **LSA RPC enumeration（noisy, accurate）:**
- 从在目标上拥有 local admin 的上下文打开 Local Security Policy，并对每个 privilege/logon right 调用 `LsaEnumerateAccountsWithUserRight`，通过 RPC 枚举已分配的 principals。
- 优点：能捕获在本地或 GPO 之外设置的 rights；缺点：网络流量噪音大，而且每台主机都需要 admin 权限。

**这些 edges 展示出的一个示例 abuse path：** `CanRDP` ➜ 你的用户也拥有 `SeBackupPrivilege` 的 host ➜ 启动一个 elevated shell 以避免 filtered tokens ➜ 使用 backup semantics 读取 `SAM` 和 `SYSTEM` hives，即使存在 restrictive DACLs ➜ 导出并离线运行 `secretsdump.py`，恢复本地 Administrator NT hash，用于 lateral movement/privilege escalation。

### Prioritising Kerberoasting with BloodHound

使用 graph context 来保持 roasting 的目标性：

1. 用一个 ADWS-compatible collector 收集一次，然后离线工作：
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. 导入 ZIP，将已 compromised 的 principal 标记为 owned，并运行内置查询（*Kerberoastable Users*、*Shortest Paths to Domain Admins*）以找出具有 admin/infra rights 的 SPN accounts。
3. 按 blast radius 对 SPNs 排优先级；在 cracking 之前检查 `pwdLastSet`、`lastLogon` 和允许的 encryption types。
4. 只请求选定的 tickets，离线 crack，然后用新 access 重新查询 BloodHound：
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```

## Group3r

[Group3r](https://github.com/Group3r/Group3r) 枚举 **Group Policy Objects** 并突出显示 misconfigurations。
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) 会对 Active Directory 执行 **health-check**，并生成带有风险评分的 HTML 报告。
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## References

- [BloodHound Community Edition v8 Launches with OpenGraph: Identity Attack Paths Beyond Active Directory & Entra ID](https://specterops.io/blog/2025/07/29/bloodhound-community-edition-v8-launches-with-opengraph-identity-attack-paths-beyond-active-directory-entra-id/)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [Beyond ACLs: Mapping Windows Privilege Escalation Paths with BloodHound](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)

{{#include ../../banners/hacktricks-training.md}}
