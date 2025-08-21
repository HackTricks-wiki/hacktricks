# BloodHound & Other Active Directory Enumeration Tools

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
adws-enumeration.md
{{#endref}}

> 注意：本页面汇集了一些最有用的工具，用于**枚举**和**可视化**Active Directory关系。有关通过隐秘的**Active Directory Web Services (ADWS)**通道进行收集，请查看上述参考。

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) 是一个高级的**AD查看器和编辑器**，允许：

* 通过GUI浏览目录树
* 编辑对象属性和安全描述符
* 创建/比较快照以进行离线分析

### 快速使用

1. 启动工具并使用任何域凭据连接到`dc01.corp.local`。
2. 通过`File ➜ Create Snapshot`创建离线快照。
3. 使用`File ➜ Compare`比较两个快照，以发现权限差异。

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) 从域中提取大量文物（ACLs、GPOs、信任、CA模板等），并生成**Excel报告**。
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (图形可视化)

[BloodHound](https://github.com/BloodHoundAD/BloodHound) 使用图论 + Neo4j 来揭示本地 AD 和 Azure AD 中隐藏的权限关系。

### 部署 (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### 收集器

* `SharpHound.exe` / `Invoke-BloodHound` – 本地或 PowerShell 变体
* `AzureHound` – Azure AD 枚举
* **SoaPy + BOFHound** – ADWS 收集（见顶部链接）

#### 常见的 SharpHound 模式
```powershell
SharpHound.exe --CollectionMethods All           # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
```
收集器生成 JSON，通过 BloodHound GUI 进行摄取。

---

## Group3r

[Group3r](https://github.com/Group3r/Group3r) 枚举 **组策略对象** 并突出显示错误配置。
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) 对 Active Directory 进行 **健康检查** 并生成带有风险评分的 HTML 报告。
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
{{#include ../../banners/hacktricks-training.md}}
