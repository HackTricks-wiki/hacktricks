# Active Directory 方法论

{{#include ../../banners/hacktricks-training.md}}

## 基本概述

**Active Directory** 是一项基础技术，使得 **网络管理员** 能够高效地在网络中创建和管理 **域**、**用户** 和 **对象**。它被设计为可扩展的，便于将大量用户组织成可管理的 **组** 和 **子组**，并在不同层级上控制 **访问权限**。

**Active Directory** 的结构由三个主要层级组成：**域**、**树** 和 **林**。一个 **域** 包含一组对象，例如 **用户** 或 **设备**，共享一个公共数据库。**树** 是这些域按共享结构连接起来的分组，而 **林** 则代表由多个树通过 **信任关系** 相互连接所形成的最高级别组织结构。可以在每个层级上指定特定的 **访问** 和 **通信权限**。

Active Directory 的关键概念包括：

1. **Directory** – 存储与 Active Directory 对象相关的所有信息。
2. **Object** – 表示目录内的实体，包括 **用户**、**组** 或 **共享文件夹**。
3. **Domain** – 作为目录对象的容器，多个域可以共存于一个 **forest** 中，每个域维护自己的对象集合。
4. **Tree** – 共享根域的域的分组。
5. **Forest** – Active Directory 中的组织结构顶层，由若干棵树组成并具有相互之间的 **信任关系**。

**Active Directory Domain Services (AD DS)** 包含一系列对集中式管理和网络内通信至关重要的服务。这些服务包括：

1. **Domain Services** – 集中数据存储并管理 **用户** 与 **域** 之间的交互，包括 **认证** 和 **搜索** 功能。
2. **Certificate Services** – 负责生成、分发和管理安全的 **数字证书**。
3. **Lightweight Directory Services** – 通过 **LDAP protocol** 支持启用目录的应用程序。
4. **Directory Federation Services** – 提供 **single-sign-on** 功能，使用户可以在一次会话中对多个 web 应用进行认证。
5. **Rights Management** – 通过控制未授权分发和使用来帮助保护版权材料。
6. **DNS Service** – 对 **域名** 解析至关重要。

更多详细说明请参考: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos 认证**

要学习如何攻击 AD，你需要非常了解 **Kerberos** 的认证流程。\
[**如果你还不知道它如何工作，请阅读此页面。**](kerberos-authentication.md)

## 速查表

你可以访问 [https://wadcoms.github.io/](https://wadcoms.github.io) 快速查看可用于枚举/利用 AD 的常用命令。

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not Kerberos**.

## Recon Active Directory (No creds/sessions)

如果你只能访问到一个 AD 环境但没有任何凭证/会话，你可以：

- **Pentest the network:**
- 扫描网络，查找主机和开放端口，尝试 **exploit vulnerabilities** 或从中 **extract credentials**（例如，[printers could be very interesting targets](ad-information-in-printers.md)）。
- 枚举 DNS 可以提供关于域内关键服务器的信息，如 web、printers、shares、vpn、media 等等。
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- 查看通用的 [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) 以获取有关如何执行这些操作的更多信息。
- **Check for null and Guest access on smb services**（这在现代 Windows 版本上通常无效）:
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- 关于如何枚举 SMB 服务器的更详细指南可以在这里找到：


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- 关于如何枚举 LDAP 的更详细指南可以在这里找到（请**特别注意匿名访问**）:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- 通过使用 Responder 假冒服务来收集凭证（gather credentials）: [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- 通过 [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) 访问主机
- 通过暴露伪造的 UPnP 服务（使用 evil-S）收集凭证 **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- 从内部文档、社交媒体、域内的服务（主要是 web）以及公开可用资源中提取用户名/姓名。
- 如果你获得了公司员工的完整姓名，可以尝试不同的 AD **username conventions**（[**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)）。最常见的命名约定有：_NameSurname_, _Name.Surname_, _NamSur_（每个部分取3个字母）, _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 以及 3 个随机字母加 3 个随机数字（例如 abc123）。
- 工具:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### 用户枚举

- **Anonymous SMB/LDAP enum:** 请查看 [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) 和 [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) 页面。
- **Kerbrute enum**: 当请求的用户名无效时，服务器会使用 **Kerberos** 错误代码 _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ 响应，从而允许我们确定用户名是否无效。**有效用户名** 要么会在 AS-REP 响应中返回 **TGT**，要么会返回错误 _KRB5KDC_ERR_PREAUTH_REQUIRED_，表示该用户需要执行预认证。
- **No Authentication against MS-NRPC**: 对域控制器上的 MS-NRPC (Netlogon) 接口使用 auth-level = 1（无认证）。该方法在绑定 MS-NRPC 接口后调用 `DsrGetDcNameEx2` 函数，以在无需任何凭证的情况下检查用户或计算机是否存在。该类型枚举的工具实现为 [NauthNRPC](https://github.com/sud0Ru/NauthNRPC)。相关研究可见 [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

如果你在网络中发现了这些服务器，你也可以对其进行 **user enumeration**。例如，你可以使用工具 [**MailSniper**](https://github.com/dafthack/MailSniper):
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

### Knowing one or several usernames

好，假如你已经知道一个或多个有效的用户名但没有密码…… 那么试试：

- [**ASREPRoast**](asreproast.md)：如果某个用户**没有**属性 _DONT_REQ_PREAUTH_，你可以**请求一个 AS_REP 消息**，该消息会包含用该用户密码的派生值加密的一些数据。
- [**Password Spraying**](password-spraying.md)：对已发现的每个用户尝试最常见的**弱口令**，也许有人在使用不安全的密码（注意密码策略！）。
- 注意你也可以**对 OWA 服务器进行 spray**以尝试获取用户的邮箱访问权限。

{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

你可能能够通过**对网络的一些协议进行 poisoning**来**获取**可用于破解的挑战**hashes**：


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

如果你已经枚举到了 Active Directory，你会得到**更多的邮箱地址和对网络的更好理解**。你或许可以强制 NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) 来获取对 AD 环境的访问。

### Steal NTLM Creds

如果你能够以 **null 或 guest 用户** 访问其他 PC 或 shares，你可以**放置文件**（比如 SCF 文件），当这些文件被某种方式访问时会**触发对你的 NTLM 认证**，从而让你**窃取**可用于破解的 **NTLM challenge**：


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Enumerating Active Directory WITH credentials/session

在这个阶段你需要已经**攻陷了一个有效域账户的凭据或会话**。如果你有一些有效凭据或以域用户的 shell，**请记住之前提到的那些方法仍然可以用来攻陷其他用户**。

在开始认证枚举之前，你应该了解 **Kerberos double hop problem**。


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

攻陷一个账户是**开始攻陷整个域的重要一步**，因为你将能够开始进行 **Active Directory 枚举：**

关于 [**ASREPRoast**](asreproast.md) 你现在可以发现所有可能的易受攻击用户；关于 [**Password Spraying**](password-spraying.md) 你可以获得**所有用户名的列表**并尝试使用被攻陷账户的密码、空密码或其他可能的密码。

- 你可以使用 [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- 你也可以使用 [**powershell for recon**](../basic-powershell-for-pentesters/index.html)，这会更隐蔽
- 你还可以 [**use powerview**](../basic-powershell-for-pentesters/powerview.md) 来提取更详细的信息
- 另一个用于 Active Directory 枚举的优秀工具是 [**BloodHound**](bloodhound.md)。它**不太隐蔽**（取决于你使用的收集方法），但**如果你不在意**被检测的话，非常值得一试。找出哪些用户可以 RDP，找到通往其他组的路径等。
- **其他自动化 AD 枚举工具有：** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**AD 的 DNS 记录**](ad-dns-records.md)，因为其中可能包含有价值的信息。
- 一个带 GUI 的目录枚举工具是 **AdExplorer.exe**，来自 **SysInternal** 套件。
- 你也可以用 **ldapsearch** 在 LDAP 数据库中搜索，查看字段 _userPassword_ & _unixUserPassword_，甚至 _Description_ 中是否有凭据。参见 PayloadsAllTheThings 中的 [Password in AD User comment](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) 获取其他方法。
- 如果你使用 **Linux**，也可以使用 [**pywerview**](https://github.com/the-useless-one/pywerview) 枚举域。
- 你还可以尝试这些自动化工具：
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **提取所有域用户**

从 Windows 上很容易获取所有域用户名（`net user /domain`，`Get-DomainUser` 或 `wmic useraccount get name,sid`）。在 Linux 上，你可以使用：`GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` 或 `enum4linux -a -u "user" -p "password" <DC IP>`

> 即使这个 Enumeration 部分看起来很短，它也是最重要的部分。在评估前请访问这些链接（主要是 cmd、powershell、powerview 和 BloodHound），学习如何枚举域并反复练习直到熟练。在一次评估中，这将是能否找到通往 DA 的关键时刻，或判断无法继续的决断点。

### Kerberoast

Kerberoasting 涉及获取与服务相关联的用户账户所使用的 **TGS tickets**，并离线破解其基于用户密码的加密。

更多内容见：


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

一旦你获得了一些凭据，可以检查是否对任何**机器**有访问权限。为此，你可以使用 **CrackMapExec** 根据你的端口扫描尝试通过不同协议连接多个服务器。

### Local Privilege Escalation

如果你以普通域用户的凭据或会话入侵并且这个用户对域内的**任何机器有访问权限**，你应尝试在本地**提升权限并搜集凭据**。因为只有在拥有本地管理员权限时，你才能**转储其他用户的哈希**（内存中的 LSASS 或本地的 SAM）。

本书中有完整章节讨论 [**Windows 本地权限提升**](../windows-local-privilege-escalation/index.html) 和一个 [**检查清单**](../checklist-windows-privilege-escalation.md)。另外别忘了使用 [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)。

### Current Session Tickets

在当前用户会话中找到能让你访问意外资源的 **tickets** 的可能性非常**低**，但你仍然可以检查：
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

If you have managed to enumerate the Active Directory you will have **more emails and a better understanding of the network**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### 在 Computer Shares 中查找 Creds | SMB Shares

现在既然你有了一些基本的 credentials，你应该检查是否能 **找到** 在 AD 内共享的任何 **有趣的文件**。你可以手动执行，但那是非常无聊且重复的任务（如果你发现数百个需要检查的文档，会更麻烦）。

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

如果你可以 **访问其他电脑或共享**，你可以 **放置文件**（例如 SCF 文件），如果这些文件被某种方式访问，会 t**rigger an NTLM authentication against you**，这样你就可以 **steal** **NTLM challenge** 去破解它：


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

该漏洞允许任何已认证用户 **攻陷域控制器**。


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**对于下面的技术，普通域用户不足以执行，你需要一些特殊的特权/credentials 来执行这些攻击。**

### Hash extraction

希望你已经设法使用 [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html) 成功 **compromise some local admin** 账户。\
然后，该是转储内存和本地所有 hashes 的时候了。\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**一旦你拥有某个用户的 hash**，你可以用它来**impersonate**该用户。\
你需要使用某个**tool** 来**perform** 使用该 **hash** 的 **NTLM authentication**，或者你可以创建一个新的 **sessionlogon** 并将该 **hash** 注入 **LSASS**，这样当任何 **NTLM authentication** 被执行时，该 **hash** 就会被使用。最后一种方法是 mimikatz 所做的。\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

This attack aims to **use the user NTLM hash to request Kerberos tickets**, as an alternative to the common Pass The Hash over NTLM protocol. Therefore, this could be especially **在 NTLM protocol 被禁用 的网络中有用**，且仅 **允许 Kerberos** 作为身份验证协议。

{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

In the **Pass The Ticket (PTT)** attack method, attackers **steal a user's authentication ticket** instead of their password or hash values. This stolen ticket is then used to **impersonate the user**, gaining unauthorized access to resources and services within a network.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

如果你拥有某个 **local administrator** 的 **hash** 或 **password**，你应该尝试用它在其他 **PCs** 上 **login locally**。
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> 注意这相当 **嘈杂**，**LAPS** 可以 **缓解**。

### MSSQL Abuse & Trusted Links

如果用户有权限 **访问 MSSQL 实例**，他可能能够利用它在 MSSQL 主机上 **执行命令**（如果以 SA 运行）、**窃取** NetNTLM **hash**，甚至执行 **relay attack**。\
另外，如果一个 MSSQL 实例被另一个 MSSQL 实例信任（database link），且该用户对受信任的数据库具有权限，那么他将能够 **利用信任关系在另一实例上执行查询**。这些信任可以链式连接，用户最终可能找到配置错误的数据库并在那里执行命令。\
**数据库之间的链接甚至在 forest trusts 之间也能工作。**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

第三方的资产清点与部署套件通常会暴露可用于获取凭据和执行代码的强大路径。参见：

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

如果你发现任何 Computer 对象具有属性 [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>)，并且你在该计算机上有域权限，你将能够从每个登录到该计算机的用户的内存中导出 TGT。\
因此，如果一个 **Domain Admin 登录到该计算机**，你将能够导出他的 TGT 并使用 [Pass the Ticket](pass-the-ticket.md) 冒充他。\
借助 constrained delegation 你甚至可以 **自动攻陷打印服务器**（希望它是 DC）。


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

如果某个用户或计算机被允许使用 “Constrained Delegation”，它将能够 **以任意用户身份模拟并访问某台计算机上的某些服务**。\
然后，如果你 **获取到该用户/计算机的 hash**，你将能够 **以任何用户（甚至 domain admins）身份模拟** 来访问某些服务。


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

对远程计算机的 Active Directory 对象具有 **WRITE** 权限，能够带来以 **提升权限** 的方式执行代码的机会：


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

被攻陷的用户可能对某些域对象具有一些**有趣的权限**，这可能让你在后续**横向移动**或**提权**。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

在域内发现 **Spool service 处于监听状态** 可以被 **滥用** 来 **获取新凭据** 并 **提升权限**。


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

如果 **其他用户** **访问** 被 **攻陷** 的机器，就有可能 **从内存中收集凭据**，甚至 **向他们的进程注入 beacons** 来冒充他们。\
通常用户会通过 RDP 访问系统，下面介绍几种针对第三方 RDP 会话的攻击方法：


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** 提供了一个管理域联机计算机上 **本地 Administrator 密码** 的系统，确保密码被 **随机化**、唯一并且定期 **更改**。这些密码存储在 Active Directory 中，通过 ACL 只授权给特定用户访问。只要拥有足够的权限访问这些密码，就可以实现对其他计算机的 pivot。

{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**从被攻陷机器上收集证书** 可能是提升环境内权限的一种方式：


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

如果配置了**易受攻击的模板**，就可能滥用它们来提升权限：


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

一旦你获得 **Domain Admin** 或更高的 **Enterprise Admin** 权限，你可以 **转储** 域数据库：_ntds.dit_。

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

前面讨论的一些技术可以被用来作为持久化。\
例如，你可以：

- 使用户易受 [**Kerberoast**](kerberoast.md) 攻击

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- 使用户易受 [**ASREPRoast**](asreproast.md) 攻击

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- 授予某用户 [**DCSync**](#dcsync) 权限

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Silver Ticket attack** 使用 **NTLM hash**（例如 **PC 账户的 hash**）为特定服务创建合法的 Ticket Granting Service (TGS) ticket，从而 **访问该服务的权限**。


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** 涉及攻击者获取 Active Directory 环境中 krbtgt 账户的 **NTLM hash**。该账户用于签名所有的 **Ticket Granting Tickets (TGTs)**，这些 TGT 对在 AD 网络中的认证至关重要。

一旦攻击者获取到该 hash，就可以为任何账户伪造 **TGTs**（即 Silver ticket 攻击的手段）。


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

这类票据类似于 golden tickets，但以能够 **绕过常见 golden tickets 检测机制** 的方式伪造。


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**拥有某账户的证书或能够请求该证书** 是在用户账户中保持持久访问的非常有效的方法（即使用户更改了密码）：


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**使用证书也可以在域内以高权限保持持久化：**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory 中的 **AdminSDHolder** 对象通过对这些组应用标准的 **Access Control List (ACL)** 来保护 **特权组**（如 Domain Admins 和 Enterprise Admins），以防止未经授权的更改。然而，这一功能也可能被利用；如果攻击者修改 AdminSDHolder 的 ACL，赋予普通用户完全访问权限，则该用户将对所有特权组获得广泛控制。这个旨在保护的安全机制若未被严格监控，反而可能导致未经授权的访问。

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

每台 **Domain Controller (DC)** 内部都存在一个本地管理员账户。通过在这样的机器上获得管理员权限，可以使用 **mimikatz** 提取本地 Administrator 的 hash。随后需要修改注册表以 **启用对该密码的使用**，从而允许远程访问本地 Administrator 账户。


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

你可以赋予某个 **用户** 对特定域对象的一些**特殊权限**，从而让该用户在未来能够 **提升权限**。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**安全描述符（security descriptors）** 用于**存储对象的权限**。如果你能在对象的安全描述符上做一点小改动，就可以在无需成为特权组成员的情况下，获得对该对象的非常有价值的权限。


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

在内存中修改 **LSASS**，以建立一个**通用密码（universal password）**，从而获得对所有域账户的访问权限。


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
你可以创建你自己的 SSP 来**捕获**用于访问机器的**明文凭据**。


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

它在 AD 中注册一个 **新的 Domain Controller** 并利用它向指定对象 **推送属性**（如 SIDHistory、SPNs...），而不会留下有关这些 **修改** 的任何日志。你需要 DA 权限并且位于根域内。\
注意：如果你使用了错误的数据，会产生非常明显的日志记录。


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

之前我们讨论了如果你拥有读取 LAPS 密码的权限，如何进行提权。然而，这些密码也可以被用来 **维持持久化**。\
参见：


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft 将 **Forest** 视为安全边界。这意味着 **攻破单个域可能会导致整个 Forest 被攻破**。

### Basic Information

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) 是一种安全机制，允许来自一个 **域** 的用户访问另一个 **域** 中的资源。它本质上在两个域的认证系统之间创建了连接，允许认证验证在两者之间流动。当域建立信任时，它们在各自的 **Domain Controllers (DCs)** 中交换并保留某些用于维护信任完整性的 **keys**。

在典型场景中，如果用户想要访问 **受信任域** 中的服务，首先必须向其本域的 DC 请求一个特殊的票据，称为 **inter-realm TGT**。该 TGT 使用双方约定的共享 **key** 进行加密。然后用户将此 TGT 提供给 **受信任域的 DC** 以获取服务票据（**TGS**）。受信任域的 DC 验证 inter-realm TGT，并在验证通过后颁发 TGS，从而授予用户访问服务的权限。

**步骤**：

1. **Domain 1** 中的一台 **client computer** 通过使用其 **NTLM hash** 向其 **Domain Controller (DC1)** 请求 **Ticket Granting Ticket (TGT)** 来启动该流程。
2. 如果客户端认证成功，DC1 将颁发新的 TGT。
3. 然后客户端向 DC1 请求访问 **Domain 2** 所需的 **inter-realm TGT**。
4. inter-realm TGT 使用作为双向域信任一部分的 DC1 与 DC2 之间共享的 **trust key** 加密。
5. 客户端将 inter-realm TGT 提交给 **Domain 2 的 Domain Controller (DC2)**。
6. DC2 使用其共享的 trust key 验证 inter-realm TGT，如果有效，则为客户端想要访问的 Domain 2 的服务器签发 **Ticket Granting Service (TGS)**。
7. 最后，客户端将此 TGS 提交给服务器，该票据使用服务器账户的 hash 加密，以获取对 Domain 2 中服务的访问权限。

### Different trusts

需要注意的是，**信任可以是单向或双向的**。在双向选项中，两个域相互信任；但在 **单向** 信任关系中，一个域为 **trusted**，另一个为 **trusting**。在这种情况下，**你只能从被信任域访问信任域内的资源**。

如果 Domain A 信任 Domain B，则 A 为 trusting 域，B 为 trusted 域。此外，在 **Domain A** 中，这将是一个 **Outbound trust**；而在 **Domain B** 中，这将是一个 **Inbound trust**。

**不同的信任关系类型**

- **Parent-Child Trusts**：这是同一 forest 内常见的设置，子域会自动与父域形成双向可传递信任（two-way transitive trust）。这意味着认证请求可以在父域和子域之间无缝流动。
- **Cross-link Trusts**：也称为 “shortcut trusts”，这些信任在子域之间建立以加速引用过程。在复杂的 forest 中，认证引用通常需要向上到 forest 根然后再向下到目标域。通过创建 cross-links，可以缩短该路径，尤其在地理上分散的环境中很有用。
- **External Trusts**：这些是在不同、无关联域之间建立的信任，且本质上是非传递的。根据 [Microsoft 的文档](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)，external trusts 对于访问不在当前 forest 且未通过 forest trust 连接的域中的资源很有用。通过 SID filtering 可以增强外部信任的安全性。
- **Tree-root Trusts**：这些信任在 forest 根域与新添加的 tree root 之间自动建立。虽然不常见，但在向 forest 添加新的域树时，tree-root trusts 很重要，它们允许新的域树保持唯一域名并确保双向可传递性。更多信息见 [Microsoft 指南](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)。
- **Forest Trusts**：此类信任是两个 forest 根域之间的双向可传递信任，同时也强制执行 SID filtering 以增强安全措施。
- **MIT Trusts**：这些信任与非 Windows 的、符合 [RFC4120](https://tools.ietf.org/html/rfc4120) 的 Kerberos 域建立。MIT trusts 更加专业化，适用于需与 Windows 生态外的 Kerberos 系统集成的环境。

#### Other differences in **trusting relationships**

- 信任关系也可以是 **传递性的**（A 信任 B，B 信任 C，则 A 信任 C）或 **非传递性的**。
- 信任关系可以设置为 **双向信任**（双方互相信任）或 **单向信任**（仅一方信任另一方）。

### Attack Path

1. **枚举** 信任关系
2. 检查是否有任何 **security principal**（user/group/computer）对 **另一个域** 的资源具有 **访问** 权限，可能是通过 ACE 条目或作为另一个域的组成员。查找 **跨域的关系**（信任可能就是为此创建的）。
1. 在这种情况下，kerberoast 可能是另一种选择。
3. **攻破** 可以 **跨域 pivot** 的 **账户**。

攻击者可以通过三种主要机制访问另一个域的资源：

- **Local Group Membership**：主体可能被添加到机器的本地组（例如服务器上的 “Administrators” 组），从而获得对该机器的显著控制权。
- **Foreign Domain Group Membership**：主体也可能成为外部域内某些组的成员。然而，该方法的有效性取决于信任的性质和组的作用范围。
- **Access Control Lists (ACLs)**：主体可能被列在 **ACL** 中，特别是在 **DACL** 的 **ACE** 条目中，赋予他们对特定资源的访问权限。对于想深入了解 ACL、DACL 和 ACE 机制的人来说，题为 “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” 的白皮书是非常有价值的资源。

### Find external users/groups with permissions

你可以检查 **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** 来查找域中的外部安全主体（foreign security principals）。这些将是来自 **外部域/forest** 的用户/组。

你可以在 Bloodhound 中检查这一点，或者使用 powerview：
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
> 存在 **2 个受信任的密钥**，一个用于 _Child --> Parent_，另一个用于 _Parent_ --> _Child_。\
> 你可以使用以下命令查看当前域使用的是哪个：
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

通过滥用 trust 和 SID-History injection，将自己提升为 child/parent domain 的 Enterprise admin：


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

理解如何利用 Configuration Naming Context (NC) 十分关键。Configuration NC 是 Active Directory (AD) 环境中跨林配置数据的集中存储库。该数据会复制到林中的每个 Domain Controller (DC)，可写的 DC 会保留 Configuration NC 的可写副本。要利用它，你必须在某台 DC 上获得 **SYSTEM** 权限，最好是 child DC。

**将 GPO 链接到 root DC site**

Configuration NC 的 Sites 容器包含有关 AD forest 中所有加入域的计算机 site 的信息。通过在任一 DC 上以 **SYSTEM** 权限操作，攻击者可以将 GPOs 链接到 root DC 的 site。此操作可能通过操纵应用于这些 site 的策略来危及 root domain。

有关深入信息，可参考研究 [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**妥协 forest 中的任意 gMSA**

一种攻击向量是针对域内的特权 gMSA。用于计算 gMSA 密码的 KDS Root key 存储在 Configuration NC 中。若在任一 DC 上拥有 **SYSTEM** 权限，即可访问 KDS Root key 并计算整个 forest 中任意 gMSA 的密码。

详细分析和逐步指导见：


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

补充的 delegated MSA 攻击 (BadSuccessor – 滥用 migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

附加外部研究： [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

这种方法需要耐心，等待新特权 AD 对象的创建。获得 **SYSTEM** 权限后，攻击者可以修改 AD Schema，授予任意用户对所有类的完全控制权限。这可能导致对新创建的 AD 对象的未经授权访问和控制。

更多阅读见 [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

ADCS ESC5 漏洞针对对 Public Key Infrastructure (PKI) 对象的控制，通过创建证书模板来实现以林内任意用户身份进行认证。由于 PKI 对象位于 Configuration NC 中，攻陷一个可写的 child DC 即可执行 ESC5 攻击。

更多细节见 [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c)。在没有 ADCS 的场景中，攻击者也可以搭建所需组件，详见 [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
在此场景中，**您的域被一个外部域信任**，从而对您赋予了**对其的未明确权限**。您需要找出**您域中的哪些主体在外部域上拥有哪些访问权限**，然后尝试利用它：

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
在此场景中，**你的域** 正在 **向来自不同域的主体授予** 一些 **权限**。

然而，当一个 **域被信任**（被信任域由信任域信任）时，受信任域会 **创建一个具有可预测名称的用户**，并使用 **受信任密码作为该用户的密码**。这意味着可以 **使用来自信任域的用户访问权进入受信任域**，对其进行枚举并尝试提升更多权限：

{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

另一种攻陷受信任域的方法是找到在域信任的**相反方向**创建的[**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links)（这并不常见）。

另一种攻陷受信任域的方法是在一台机器上等待 **受信任域的用户可以通过 RDP 登录**。然后，攻击者可以在 RDP 会话进程中注入代码，并从那里 **访问受害者的原始域**。\
此外，如果 **受害者挂载了他的硬盘**，攻击者可以从 **RDP 会话** 进程在 **硬盘的启动文件夹** 中存放 **后门**。该技术称为 **RDPInception。**

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- 利用 SID history 属性跨林信任发起攻击的风险可通过 SID Filtering 缓解，SID Filtering 在所有跨林信任上默认启用。微软的立场基于将森林（forest）而非域（domain）视为安全边界，从而假设林内信任是安全的。
- 但需要注意的是：SID filtering 可能会影响应用和用户访问，因此有时会被停用。

### **Selective Authentication:**

- 对于跨林信任，采用 Selective Authentication 可确保两个林的用户不会被自动认证。相反，用户必须获得明确权限才能访问信任域或林内的域和服务器。
- 需要注意的是，这些措施不能防止对可写的 Configuration Naming Context (NC) 的利用或对信任账户的攻击。

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) 将 bloodyAD-style 的 LDAP 原语重新实现为 x64 Beacon Object Files，完全在主机植入物内部运行（例如 Adaptix C2）。操作员使用 `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` 编译包，加载 `ldap.axs`，然后从 beacon 调用 `ldap <subcommand>`。所有流量都在当前登录的安全上下文下通过 LDAP (389)（使用 signing/sealing）或 LDAPS (636)（自动信任证书）传输，因此不需要 socks 代理或磁盘残留。

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` 将短名/OU 路径解析为完整 DN 并转储相应对象。
- `get-object`, `get-attribute`, and `get-domaininfo` 拉取任意属性（包括 security descriptors），以及来自 `rootDSE` 的林/域元数据。
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` 直接从 LDAP 暴露 roasting 候选、delegation 设置，以及现有的 [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) 描述符。
- `get-acl` and `get-writable --detailed` 解析 DACL，列出 trustees、权限（GenericAll/WriteDACL/WriteOwner/attribute writes）和继承情况，从而提供用于 ACL 提权的直接目标。
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) 允许操作者在存在 OU 权限的任何位置部署新的主体或计算机账户。`add-groupmember`、`set-password`、`add-attribute` 和 `set-attribute` 在发现 write-property 权限后可直接劫持目标。
- 面向 ACL 的命令如 `add-ace`、`set-owner`、`add-genericall`、`add-genericwrite` 和 `add-dcsync` 将对任意 AD 对象的 WriteDACL/WriteOwner 权限转换为密码重置、组成员控制或 DCSync 复制特权，而不会留下 PowerShell/ADSI 残留。对应的 `remove-*` 命令可清理注入的 ACEs。

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` 能立即使被攻陷的用户变为 Kerberoastable；`add-asreproastable`（UAC 切换）在不修改密码的情况下将其标记为可进行 AS-REP roasting。
- Delegation macros（`add-delegation`、`set-delegation`、`add-constrained`、`add-unconstrained`、`add-rbcd`）可从 beacon 重写 `msDS-AllowedToDelegateTo`、UAC 标志或 `msDS-AllowedToActOnBehalfOfOtherIdentity`，启用 constrained/unconstrained/RBCD 攻击路径，并消除对远程 PowerShell 或 RSAT 的需求。

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` 将特权 SIDs 注入受控主体的 SID history（见 [SID-History Injection](sid-history-injection.md)），通过 LDAP/LDAPS 完全提供隐蔽的访问继承。
- `move-object` 更改计算机或用户的 DN/OU，允许攻击者在滥用 `set-password`、`add-groupmember` 或 `add-spn` 之前将资产拖入已有委派权限的 OU。
- 范围严格的移除命令（`remove-attribute`、`remove-delegation`、`remove-rbcd`、`remove-uac`、`remove-groupmember` 等）允许操作者在窃取凭据或建立持久性后快速回滚，最小化遥测痕迹。

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: 建议 Domain Admins 仅被允许登录到 Domain Controllers，避免在其他主机上使用。
- **Service Account Privileges**: 服务不应以 Domain Admin (DA) 权限运行以维护安全性。
- **Temporal Privilege Limitation**: 对于需要 DA 权限的任务，应限制其持续时间。可以通过以下方式实现：`Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementing Deception Techniques**

- 实施欺骗涉及设置陷阱，例如诱饵用户或计算机，其特征可能包括密码不失效或被标记为 Trusted for Delegation。详细方法包括创建具有特定权限的用户或将其添加到高权限组。
- 一个实际示例涉及使用如下命令：`Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- 关于部署欺骗技术的更多信息请见 [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: 可疑指标包括异常的 ObjectSID、罕见的登录、创建日期以及较低的坏密码计数。
- **General Indicators**: 将潜在诱饵对象的属性与真实对象进行比较可以发现不一致之处。类似 [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) 的工具可帮助识别此类欺骗。

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: 避免在 Domain Controllers 上进行会话枚举以防止 ATA 检测。
- **Ticket Impersonation**: 使用 **aes** 密钥创建票证可以通过不降级到 NTLM 来帮助规避检测。
- **DCSync Attacks**: 建议从非 Domain Controller 执行以避免 ATA 检测，因为直接在 Domain Controller 上执行会触发告警。

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)

{{#include ../../banners/hacktricks-training.md}}
