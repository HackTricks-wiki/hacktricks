# BloodHound & 其他 Active Directory 枚举工具

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> 注意：本页汇总了一些用于 **枚举** 和 **可视化** Active Directory 关系的最有用实用工具。若要通过隐蔽的 **Active Directory Web Services (ADWS)** 通道进行收集，请查看上面的参考。

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) 是一个高级的 **AD 查看与编辑工具**，它允许：

* GUI 浏览目录树
* 编辑对象属性和安全描述符
* 创建/比较快照以进行离线分析

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

[BloodHound](https://github.com/BloodHoundAD/BloodHound) 使用图论 + Neo4j 揭示本地 AD 和 Azure AD 中隐藏的特权关系。

### 部署 (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### 收集器

* `SharpHound.exe` / `Invoke-BloodHound` – 本地或 PowerShell 变体
* `AzureHound` – Azure AD enumeration
* **SoaPy + BOFHound** – ADWS collection (见顶部链接)

#### 常见的 SharpHound 模式
```powershell
SharpHound.exe --CollectionMethods All           # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
```
收集器生成 JSON，并由 BloodHound GUI 导入。

---

## 使用 BloodHound 对 Kerberoasting 进行优先级排序

图上下文对于避免噪声大、无差别的 roasting 至关重要。一个轻量级工作流程：

1. **一次性收集所有内容** 使用兼容 ADWS 的收集器（例如 RustHound-CE），这样你可以离线工作并在不再次接触 DC 的情况下排练路径：
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. **Import the ZIP, mark the compromised principal as owned**, then run built-in queries such as *Kerberoastable Users* and *Shortest Paths to Domain Admins*. This instantly highlights SPN-bearing accounts with useful group memberships (Exchange, IT, tier0 service accounts, etc.).  
2. **导入 ZIP，将被攻破的主体标记为已拥有**，然后运行内置查询，例如 *Kerberoastable Users* 和 *Shortest Paths to Domain Admins*。这会立即突出显示带有 SPN 的账户及其有用的组成员身份（Exchange、IT、tier0 service accounts 等）。

3. **Prioritise by blast radius** – focus on SPNs that control shared infrastructure or have admin rights, and check `pwdLastSet`, `lastLogon`, and allowed encryption types before spending cracking cycles.  
3. **按影响范围优先排序** —— 集中于控制共享基础设施或具有管理员权限的 SPN，并在投入破解之前检查 `pwdLastSet`、`lastLogon` 和允许的加密类型。

4. **Request only the tickets you care about**. Tools like NetExec can target selected `sAMAccountName`s so that each LDAP ROAST request has a clear justification:  
4. **只请求你关心的票据**。像 NetExec 这样的工具可以针对选定的 `sAMAccountName`s，因此每个 LDAP ROAST 请求都有明确的理由：
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```
5. **Crack offline**，然后立即重新查询 BloodHound，以使用新的权限规划 post-exploitation。

这种做法能保持较高的信噪比，降低可被检测的流量（不会进行大量 SPN 请求），并确保每个 cracked ticket 都转化为有意义的 privilege escalation 步骤。

## Group3r

[Group3r](https://github.com/Group3r/Group3r) 枚举 **组策略对象** 并突出显示错误配置。
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) 执行 Active Directory 的 **健康检查** 并生成带有风险评分的 HTML 报告。
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## 参考资料

- [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, and Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)

{{#include ../../banners/hacktricks-training.md}}
