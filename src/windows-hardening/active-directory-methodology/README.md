# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## 基本概述

**Active Directory** 是一项基础技术，使得 **network administrators** 能够高效地在网络中创建和管理 **domains**、**users** 和 **objects**。它被设计为可扩展，便于将大量用户组织为可管理的 **groups** 与 **subgroups**，并在不同层级控制 **access rights**。

**Active Directory** 的结构由三个主要层级组成：**domains**、**trees** 和 **forests**。一个 **domain** 包含一组对象（例如 **users** 或 **devices**），这些对象共享同一数据库。**Trees** 是这些 domains 的组合，具有共享的结构；**forest** 则是由多个 tree 通过 **trust relationships** 互联组成的最上层组织结构。可以在每个层级上指定特定的 **access** 和 **communication rights**。

Active Directory 的关键概念包括：

1. **Directory** – 存储与 Active Directory 对象相关的所有信息。
2. **Object** – 指目录中的实体，包括 **users**、**groups** 或 **shared folders**。
3. **Domain** – 用于容纳目录对象的容器，一个 **forest** 中可以存在多个 domain，每个 domain 保持其自己的对象集合。
4. **Tree** – 共享根域的 domain 分组。
5. **Forest** – Active Directory 组织结构的顶层，由多个具有 **trust relationships** 的 trees 组成。

**Active Directory Domain Services (AD DS)** 包含一系列对集中管理和网络内通信至关重要的服务。这些服务包括：

1. **Domain Services** – 集中存储数据并管理 **users** 与 **domains** 之间的交互，包括 **authentication** 与 **search** 功能。
2. **Certificate Services** – 负责创建、分发和管理安全的 **digital certificates**。
3. **Lightweight Directory Services** – 通过 **LDAP protocol** 支持目录启用的应用。
4. **Directory Federation Services** – 提供 **single-sign-on** 功能，使用户可在单次会话中对多个 Web 应用进行认证。
5. **Rights Management** – 通过控制未授权的分发和使用，协助保护版权材料。
6. **DNS Service** – 对于 **domain name** 的解析至关重要。

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

To learn how to **attack an AD** you need to **understand** really good the **Kerberos authentication process**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## 速查表

你可以访问 [https://wadcoms.github.io/](https://wadcoms.github.io) 快速查看可用于枚举/利用 AD 的常用命令。

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

如果你只对一个 AD 环境有访问权限，但没有任何凭据/会话，可以：

- **Pentest the network:**
- 扫描网络，发现机器和开放端口，尝试 **exploit vulnerabilities** 或 **extract credentials**（例如，[printers could be very interesting targets](ad-information-in-printers.md)）。
- 枚举 DNS 可以提供域内关键服务器的信息，如 web、printers、shares、vpn、media 等。
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- 查看通用的 [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) 以获取更多如何执行这些操作的信息。
- **Check for null and Guest access on smb services**（这在现代 Windows 版本上通常不起作用）：
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- 更详细的 SMB 枚举指南可在此找到：


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- 更详细的 LDAP 枚举指南可在此找到（对匿名访问需格外注意）：


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- 通过 [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) 收集凭据。
- 通过 [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) 访问主机。
- 通过 **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) 收集凭据。
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- 从域环境内的内部文档、社交媒体、服务（主要是 web）以及公开可用资源中提取用户名/姓名。
- 如果你找到了公司员工的完整姓名，可以尝试不同的 AD **username conventions**（[**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)）。最常见的命名规则有：_NameSurname_、_Name.Surname_、_NamSur_（各取 3 个字母）、_Nam.Sur_、_NSurname_、_N.Surname_、_SurnameName_、_Surname.Name_、_SurnameN_、_Surname.N_、3 个随机字母加 3 个随机数字（如 abc123）。
- 工具：
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### 用户枚举

- **Anonymous SMB/LDAP enum:** 检查 [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) 和 [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) 页面。
- **Kerbrute enum**: 当请求一个 **invalid username** 时，服务器会通过 **Kerberos error** 代码 _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ 响应，从而让我们判断该用户名无效。**Valid usernames** 会触发 AS-REP 中的 **TGT** 或返回错误 _KRB5KDC_ERR_PREAUTH_REQUIRED_，指示该用户需要进行 pre-authentication。
- **No Authentication against MS-NRPC**: 对域控制器上的 MS-NRPC (Netlogon) 接口使用 auth-level = 1（No authentication）。该方法在绑定 MS-NRPC 接口后调用 `DsrGetDcNameEx2` 函数，以在不使用任何凭据的情况下检查用户或计算机是否存在。该类型枚举由 [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) 工具实现。相关研究可见 [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

如果在网络中发现了这类服务器，你也可以对其进行 **user enumeration**。例如，你可以使用工具 [**MailSniper**](https://github.com/dafthack/MailSniper)：
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
> 不过，你应该已经在之前的 recon 步骤中收集到公司的员工姓名。通过名字和姓氏，你可以使用脚本 [**namemash.py**](https://gist.github.com/superkojiman/11076951) 生成潜在的有效用户名。

### 已知一个或多个用户名

好，假设你已经知道一个有效的用户名但没有密码…… 那么可以尝试：

- [**ASREPRoast**](asreproast.md)：如果某个用户**没有**属性 _DONT_REQ_PREAUTH_，你可以**请求一个 AS_REP message**，该消息会包含一些用该用户密码派生值加密的数据。
- [**Password Spraying**](password-spraying.md)：对每个已发现的用户尝试最常见的**密码**，也许某些用户在使用弱密码（记住密码策略！）。
- 注意你也可以**spray OWA servers** 来尝试访问用户的邮件服务器。

{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

你可能能够通过**poisoning**某些**network**协议来**obtain**一些 challenge **hashes** 以进行 crack：


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

如果你已经成功枚举了 active directory，你会获得**更多的邮箱信息和对网络的更好理解**。你或许能够强制进行 NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) 来获取对 AD env 的访问权限。

### Steal NTLM Creds

如果你可以使用 **null or guest user** 访问其他 PC 或 shares，你可以**放置文件**（例如 SCF file），当这些文件被访问时会 t**rigger an NTLM authentication against you**，这样你就能**steal**该 **NTLM challenge** 并进行破解：


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## 使用凭据/会话枚举 Active Directory

在此阶段，你需要已**compromised the credentials or a session of a valid domain account。** 如果你有一些有效的 credentials 或以域用户身份获得了 shell，**请记住之前提到的选项仍然是用来 compromise 其他用户的可选方法**。

在开始 authenticated enumeration 之前，你应该了解 **Kerberos double hop problem**。


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

妥协一个账户是开始 compromise 整个 domain 的**重要一步**，因为你将能够开始进行 **Active Directory Enumeration：**

关于 [**ASREPRoast**](asreproast.md)，你现在可以找到所有可能的易受影响用户；关于 [**Password Spraying**](password-spraying.md)，你可以得到**所有用户名的列表**并尝试使用被 compromise 的账户密码、空密码或其他可能的密码。

- 你可以使用 [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- 你也可以使用 [**powershell for recon**](../basic-powershell-for-pentesters/index.html)，这会更隐蔽
- 你还可以 [**use powerview**](../basic-powershell-for-pentesters/powerview.md) 提取更详细的信息
- 另一个用于 Active Directory recon 的强大工具是 [**BloodHound**](bloodhound.md)。它（取决于你使用的收集方法）**不太隐蔽**，但如果你不在意被发现，强烈推荐尝试。查找用户可以 RDP 的位置、到其他组的路径等。
- **其他自动化 AD 枚举工具有：** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**。**
- [**DNS records of the AD**](ad-dns-records.md)，它们可能包含有用的信息。
- 一个带 GUI 的工具用于枚举目录是来自 SysInternal 套件的 AdExplorer.exe。
- 你也可以使用 ldapsearch 在 LDAP 数据库中搜索，查找字段 _userPassword_ & _unixUserPassword_ 中的凭据，或者在 _Description_ 字段中查找。参见 [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) 获取其他方法。
- 如果你使用的是 Linux，你还可以使用 [**pywerview**](https://github.com/the-useless-one/pywerview) 枚举域。
- 你也可以尝试以下自动化工具：
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **提取所有域用户**

从 Windows 上很容易获取所有域用户名（`net user /domain`、`Get-DomainUser` 或 `wmic useraccount get name,sid`）。在 Linux 上，你可以使用：`GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` 或 `enum4linux -a -u "user" -p "password" <DC IP>`

> 即使这一 Enumeration 部分看起来很短，它也是最重要的部分。访问这些链接（主要是 cmd、powershell、powerview 和 BloodHound 的链接），学习如何枚举域并反复练习直到熟练。在一次评估中，这将是你找到通往 DA 的关键时刻，或者判断无能为力的决定点。

### Kerberoast

Kerberoasting 涉及获取由与用户账户关联的服务使用的 **TGS tickets**，并离线破解其基于用户密码的加密。

更多内容见：


{{#ref}}
kerberoast.md
{{#endref}}

### 远程连接 (RDP, SSH, FTP, Win-RM, etc)

一旦你获得了一些 credentials，你可以检查是否对任何 **machine** 有访问权限。为此，你可以使用 **CrackMapExec** 根据你的端口扫描尝试通过不同协议连接多台服务器。

### Local Privilege Escalation

如果你以常规域用户的身份拥有被 compromise 的 credentials 或 session，并且该用户对域内的**任何机器**有**访问**权限，你应该尝试寻找在本地 **escalate privileges locally and looting for credentials** 的方式。只有获得本地管理员权限，你才能在内存（LSASS）或本地（SAM）中**dump hashes of other users**。

本书中有一整页内容介绍 [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) 和一份 [**checklist**](../checklist-windows-privilege-escalation.md)。另外，不要忘了使用 [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)。

### Current Session Tickets

当前用户下找到**tickets** 并赋予你访问意外资源权限的情况非常**unlikely**，但你仍然可以检查：
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

如果你已经成功枚举了 Active Directory，你将会有 **更多的电子邮件以及对网络更好的理解**。你可能能够强制执行 NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

现在你已有一些基本的凭证，应该检查是否能在 AD 内 **找到** 任何 **有趣的共享文件**。你可以手动执行，但那是非常枯燥且重复的工作（如果发现数百个文档需要检查就更麻烦了）。

[**点击此链接了解可用的工具。**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

如果你可以 **访问其他 PC 或共享**，你可以 **放置文件**（例如 SCF 文件），当这些文件被访问时会触发针对你的 **NTLM 身份验证**，从而让你可以 **窃取** 要破解的 **NTLM challenge**：


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

该漏洞允许任何经过身份验证的用户 **攻破域控制器**。


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**对于以下技术，普通域用户权限不足，你需要一些特殊的特权/凭证来执行这些攻击。**

### Hash extraction

希望你已经设法使用 [AsRepRoast](asreproast.md)、[Password Spraying](password-spraying.md)、[Kerberoast](kerberoast.md)、[Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)（包括 relaying）、[EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md）、[escalating privileges locally](../windows-local-privilege-escalation/index.html) 等方法**攻陷了一些本地管理员**账户。  
然后，是时候将内存和本地的所有 hashes 转储出来了。  
[**阅读此页面，了解获取 hashes 的不同方法。**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**一旦你获得了某用户的 hash**，你就可以用它来 **冒充** 该用户。  
你需要使用某个 **tool** 来使用该 **hash** 执行 **NTLM 身份验证**，**或者** 可以创建一个新的 **sessionlogon** 并将该 **hash** 注入到 **LSASS** 中，这样当进行任何 **NTLM 身份验证** 时就会使用该 **hash**。最后一种方法就是 mimikatz 所做的。  
[**阅读此页面了解更多信息。**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

此攻击旨在**使用用户的 NTLM hash 请求 Kerberos ticket**，作为常见的通过 NTLM 协议的 Pass The Hash 的替代方法。因此，在 NTLM 协议被禁用且仅允许 Kerberos 作为身份验证协议的网络中，这种方法可能特别 **有用**。


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

在 **Pass The Ticket (PTT)** 攻击方法中，攻击者**窃取用户的身份验证票据**，而不是他们的密码或 hash 值。该被窃取的票据随后被用来**冒充该用户**，从而在网络中获得对资源和服务的未授权访问。


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

如果你拥有某个 **本地 administrator** 的 **hash** 或 **password**，你应该尝试使用它在其他 **PCs** 上 **本地登录**。
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> 请注意，这会产生相当多的**噪音**，并且**LAPS**可以**缓解**它。

### MSSQL 滥用与受信任链接

如果用户有权限**访问 MSSQL instances**，他可能会利用它在 MSSQL 主机上**执行命令**（如果以 SA 身份运行），**窃取** NetNTLM **hash**，甚至执行 **relay** **attack**。\
此外，如果一个 MSSQL 实例被另一个 MSSQL 实例信任（database link），且该用户对受信任的数据库有权限，他将能够**利用信任关系在另一个实例中执行查询**。这些信任可以链式连接，最终用户可能会找到一个配置错误的数据库，在那里他可以执行命令。\
**数据库之间的链接甚至在 forest trusts 跨域时也能工作。**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT 资产/部署平台 滥用

第三方的 inventory 和 deployment 套件通常会暴露访问凭证和代码执行的强大途径。参见：

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

如果你发现任意 Computer 对象具有属性 [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>)，且你在该计算机上拥有域权限，你将能够从内存中转储每个登录到该计算机的用户的 TGTs。\
因此，如果有 **Domain Admin logins onto the computer**，你将能够转储他的 TGT 并使用 [Pass the Ticket](pass-the-ticket.md) 冒充他。\
借助 constrained delegation，你甚至可以**自动攻陷 Print Server**（希望它是一个 DC）。


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

如果某个用户或计算机被允许进行 "Constrained Delegation"，它将能够**以任何用户的身份模拟来访问计算机上的某些服务**。\
然后，如果你**compromise the hash**（掌握该用户/计算机的 hash），你将能够**以任何用户的身份模拟**（甚至 domain admins）来访问某些服务。


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

对远程计算机的 Active Directory 对象拥有 **WRITE** 权限，可能导致以**提升的权限**获得代码执行：


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

被攻陷的用户可能对某些域对象拥有一些**有趣的权限**，这些权限可能允许你 laterally **移动**或**escalate** 权限。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

在域内发现 **Spool service listening** 可以被**滥用**以**获取新凭证**并**提升权限**。


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

如果**其他用户**访问**被攻陷**的机器，就有可能**从内存中收集凭证**，甚至**在他们的进程中注入 beacons**以模拟他们。\
通常用户会通过 RDP 访问系统，下面展示了在第三方 RDP 会话上执行的几种攻击：


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** 提供了一套用于管理域加入计算机上本地 Administrator 密码的系统，确保这些密码**随机化**、唯一且经常**更改**。这些密码存储在 Active Directory 中，并通过 ACL 控制只授权给特定用户访问。拥有足够权限读取这些密码后，可以进行横向跳转访问其他计算机。


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**从被攻陷的机器收集证书**可能是提升环境内权限的一种方式：


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

如果配置了**易受攻击的 template**，可以滥用它们来提升权限：


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## 使用高权限账号的后渗透

### Dumping Domain Credentials

一旦你获得 **Domain Admin** 或更高的 **Enterprise Admin** 权限，你可以**转储域数据库**：_ntds.dit_。

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

前面讨论的一些技术可以用于持久化。\
例如你可以：

- 使用户容易受到 [**Kerberoast**](kerberoast.md) 攻击

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- 使用户容易受到 [**ASREPRoast**](asreproast.md) 攻击

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- 授予某用户 [**DCSync**](#dcsync) 权限

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Silver Ticket attack** 通过使用 **NTLM hash**（例如 **PC account 的 hash**），为特定服务创建一个**合法的 Ticket Granting Service (TGS) ticket**。此方法用于**访问该服务的权限**。


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** 涉及攻击者获取 Active Directory 环境中 krbtgt 帐户的 **NTLM hash**。该帐户用于对所有 **Ticket Granting Tickets (TGTs)** 签名，这些 TGT 对在 AD 网络中的身份验证至关重要。

一旦攻击者获得此 hash，他们就可以为任意帐户创建 **TGTs**（即 Silver ticket attack）。


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

这些类似于 golden tickets，但以能够**绕过常见的 golden tickets 检测机制**的方式伪造。


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**拥有某个账户的证书或能够请求到它们**，是实现账户持久化的非常有效的方法（即使该用户更改了密码也能保持持久化）：


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**使用证书也可以在域内以高权限实现持久化：**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory 中的 **AdminSDHolder** 对象通过对特权组（如 Domain Admins 和 Enterprise Admins）应用标准的 **Access Control List (ACL)** 来确保这些组的安全，防止未经授权的更改。然而，这一功能可能被滥用；如果攻击者修改 AdminSDHolder 的 ACL 以授予普通用户完全访问权限，则该用户将对所有特权组获得广泛控制。这个本用于保护的安全措施如果不被密切监控，反而可能导致未授权访问。

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

每台 **Domain Controller (DC)** 内都存在一个本地管理员账号。通过在这样的机器上获取管理员权限，可以使用 **mimikatz** 提取本地 Administrator 的 hash。随后需要修改注册表以**启用使用该密码**，从而允许远程访问本地 Administrator 账号。


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

你可以为某个**用户**赋予对某些特定域对象的**特殊权限**，使该用户在将来能够**提升权限**。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** 用于**存储对象的权限**。如果你能在某个对象的 security descriptor 上做一点小改动，就可以在不成为特权组成员的情况下获得对该对象的非常有价值的权限。


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

在内存中修改 **LSASS** 以建立一个**通用密码**，从而获得对所有域账户的访问权。


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[了解什么是 SSP (Security Support Provider) 在这里。](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
你可以创建你自己的 **SSP** 来**以明文捕获**用于访问机器的**凭证**。


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

它在 AD 中注册一个**新的 Domain Controller** 并使用它在指定对象上**推送属性**（如 SIDHistory、SPNs...），同时**不留下任何关于这些修改的日志**。你需要 DA 权限并且位于**root domain** 内。\
注意：如果你使用错误的数据，会产生相当难看的日志。

{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

之前我们讨论了如果你有**足够权限读取 LAPS 密码**，如何提升权限。然而，这些密码也可以用于**维持持久化**。\
参见：


{{#ref}}
laps.md
{{#endref}}

## Forest 权限提升 - 域信任

Microsoft 将 **Forest** 视为安全边界。这意味着**攻破单个域可能导致整个 Forest 被攻破**。

### 基本信息

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) 是一种安全机制，允许一个域的用户访问另一个域的资源。它在两个域的认证系统之间创建了关联，使认证验证能够无缝流动。当域建立信任关系时，它们会在各自的 **Domain Controllers (DCs)** 中交换并保留某些关键 **keys**，这些 keys 对信任的完整性至关重要。

在典型场景中，如果用户要访问**被信任域**中的服务，他们必须先从自己域的 DC 请求一个特殊的票据，称为**inter-realm TGT**。该 TGT 使用双方同意的共享 **key** 进行加密。随后用户将此 TGT 提交给**被信任域的 DC**以获取服务票据（**TGS**）。一旦被信任域的 DC 验证 inter-realm TGT 有效，它会签发 TGS，授予用户对该服务的访问。

**步骤**：

1. **Domain 1** 中的**客户端计算机**开始流程，使用其 **NTLM hash** 向其 **Domain Controller (DC1)** 请求 **Ticket Granting Ticket (TGT)**。
2. 如果客户端认证成功，DC1 会签发一个新的 TGT。
3. 客户端随后向 DC1 请求一个 **inter-realm TGT**，以访问 **Domain 2** 中的资源。
4. inter-realm TGT 使用作为双向域信任一部分的 DC1 与 DC2 共享的 **trust key** 进行加密。
5. 客户端将 inter-realm TGT 带到 **Domain 2 的 Domain Controller (DC2)**。
6. DC2 使用其共享的 trust key 验证 inter-realm TGT，如果有效，就为客户端想要访问的 Domain 2 中的服务器签发 **Ticket Granting Service (TGS)**。
7. 最后，客户端将此 TGS 提交给服务器，该 TGS 使用服务器账户的 hash 进行加密，以便访问 Domain 2 中的服务。

### 不同类型的信任

需要注意的是，**信任可以是单向或双向的**。在双向信任中，两个域相互信任；而在**单向**信任关系中，一个域是 **trusted**，另一个是 **trusting** 域。在后一种情况下，**你只能从被信任域访问信任域内的资源**。

如果 Domain A trusts Domain B，则 A 为 trusting 域，B 为 trusted 域。此外，在 **Domain A** 中，这将显示为一个 **Outbound trust**；而在 **Domain B** 中，这将显示为一个 **Inbound trust**。

**不同的信任关系类型**

- **Parent-Child Trusts**：这是同一森林内的常见设置，子域与其父域自动建立双向可传递的信任。基本上，这意味着父域和子域之间的认证请求可以无缝流动。
- **Cross-link Trusts**：称为“shortcut trusts”，这些在子域之间建立以加速引用过程。在复杂的森林中，认证引用通常需要先上行到森林根，然后下行到目标域。通过创建 cross-links，这一路径被缩短，这在地理上分散的环境中特别有用。
- **External Trusts**：这些用于不同、无关联的域之间，且本质上是非传递性的。根据 [Microsoft 的文档](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)，external trusts 对于访问不在当前 forest 且未通过 forest trust 连接的域资源很有用。外部信任通常通过 SID 过滤来增强安全性。
- **Tree-root Trusts**：当向森林添加新的 tree root 时，forest root domain 与新添加的 tree root 之间会自动建立此类信任。虽然不常见，但 tree-root trusts 对于向森林中添加新域树并使其保持唯一域名、保证双向传递性很重要。更多信息见 [Microsoft 指南](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)。
- **Forest Trusts**：这是两个 forest root domains 之间的双向可传递信任，同时也强制执行 SID 过滤以增强安全措施。
- **MIT Trusts**：这些与非 Windows、符合 [RFC4120](https://tools.ietf.org/html/rfc4120) 的 Kerberos 域建立信任。MIT trusts 更为专业，适用于需要与 Windows 生态外的基于 Kerberos 的系统集成的环境。

#### 信任关系的其他差异

- 信任关系也可以是**可传递的**（例如 A trusts B，B trusts C，则 A trusts C）或**非传递的**。
- 信任关系可以设置为**双向信任**（双方互相信任）或**单向信任**（仅一方信任另一方）。

### 攻击路径

1. **枚举** 信任关系
2. 检查是否有任何 **security principal**（user/group/computer）对**另一个域**的资源拥有**访问**，可能通过 ACE 条目或成为另一个域的组成员。查找跨域的**关系**（信任可能就是为此创建的）。
1. 在这种情况下，kerberoast 也可能是另一个选项。
3. **攻破** 可以用于**跨域 pivot** 的 **账户**。

攻击者通过三种主要机制访问另一个域中的资源：

- **Local Group Membership**：主体可能被添加到机器上的本地组（例如服务器的 “Administrators” 组），从而获得对该机器的重大控制权。
- **Foreign Domain Group Membership**：主体也可能是外域中的某些组的成员。然而，这种方法的有效性取决于信任的性质和组的作用域。
- **Access Control Lists (ACLs)**：主体可能被列在 **ACL** 中，特别是作为 **DACL** 中 **ACE** 的实体，从而为其提供对特定资源的访问。想深入了解 ACL、DACL 和 ACE 的机制，可参阅白皮书 “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” 。

### 查找具有权限的外部用户/组

你可以检查 **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** 来查找域中的外部安全主体。这些将来自**外部域/forest**的用户/组。

你可以在 Bloodhound 中或使用 powerview 来检查：
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
> 存在 **2 个 trusted keys**，一个用于 _Child --> Parent_，另一个用于 _Parent_ --> _Child_.\
> 你可以使用以下命令查看当前域使用的 key：
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

以 Enterprise admin 身份滥用信任进行 SID-History injection，提升到子域/父域：


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

理解如何利用 Configuration NC 非常关键。Configuration NC 是 Active Directory (AD) 林中用于存放配置信息的集中仓库。此数据会复制到林内的每个 Domain Controller (DC)，可写的 DC 会保有 Configuration NC 的可写副本。要利用它，必须在某个 DC 上拥有 **DC 上的 SYSTEM 权限**，最好是子 DC。

**Link GPO to root DC site**

Configuration NC 的 Sites 容器包含了林中所有加入域的计算机所在站点的信息。通过在任一 DC 上以 SYSTEM 权限操作，攻击者可以将 GPO 链接到根 DC 的站点。此操作可能通过操纵应用于这些站点的策略来危及根域。

更多深入信息可参考研究：[Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

一个攻击向量是针对域内的特权 gMSA。用于计算 gMSA 密码的 KDS Root key 存储在 Configuration NC 中。拥有任一 DC 的 SYSTEM 权限后，攻击者可以访问 KDS Root key，并计算出林内任意 gMSA 的密码。

详细分析和逐步指南可以在以下找到：


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

补充的委派 MSA 攻击（BadSuccessor — 滥用迁移属性）：


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

附加外部研究：[Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

此方法需要耐心，等待新特权 AD 对象的创建。拥有 SYSTEM 权限后，攻击者可以修改 AD Schema 以授予任意用户对所有类的完全控制权。这可能导致对新创建 AD 对象的未授权访问和控制。

更多阅读请见 [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

ADCS ESC5 漏洞针对对 Public Key Infrastructure (PKI) 对象的控制，创建一个证书模板，从而使得能以林内任意用户身份进行认证。由于 PKI 对象位于 Configuration NC，攻陷一个可写的子 DC 就能执行 ESC5 攻击。

更多细节见 [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c)。在没有 ADCS 的场景中，攻击者也能按需搭建必要组件，相关讨论见 [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
在此场景中 **你的域被一个外部域所信任**，从而赋予你对其 **未确定的权限**。你需要找出 **你域中的哪些安全主体对外部域拥有哪些访问权限**，然后尝试利用它：

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
在本场景中，**你的域** 正在 **信任** 来自 **不同域** 的主体并授予其某些 **权限**。

然而，当一个 **域被信任**（被信任方）被信任域信任时，受信任域会**创建一个用户**，该用户具有**可预测的名称**，并使用**受信任密码作为密码**。这意味着可以**利用来自信任域的用户访问来进入受信任域**，枚举其信息并尝试提升更多权限：


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

另一种破坏受信任域的方法是发现一个在域信任**相反方向**创建的[**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links)（这并不常见）。

另一种破坏受信任域的方法是等待在一台**受信任域的用户可以通过 RDP 登录**的机器上。然后，攻击者可以在 RDP 会话进程中注入代码，并从那里**访问受害者的源域**。\
此外，如果**受害者挂载了他的硬盘**，攻击者可以从 **RDP session** 进程在**硬盘的启动文件夹**中存放 **backdoors**。该技术称为 **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### 域信任滥用缓解

### **SID Filtering:**

- SID Filtering 默认为所有跨林信任启用，以降低利用 SID history 属性进行跨林攻击的风险。其前提是假设林内信任是安全的，将安全边界视为森林（forest），而非域，这与 Microsoft 的立场一致。
- 但有一点需要注意：SID filtering 可能会影响应用程序和用户访问，因此有时会被停用。

### **Selective Authentication:**

- 对于跨林信任，使用 Selective Authentication 可确保来自两个林的用户不会被自动验证。相反，用户需要明确的权限才能访问信任域或林内的域和服务器。
- 需要注意的是，这些措施并不能防止对可写的 Configuration Naming Context (NC) 的利用或对信任账户的攻击。

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## 一些通用防御措施

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**：建议 Domain Admins 仅被允许登录到 Domain Controllers，避免在其他主机上使用。
- **Service Account Privileges**：服务不应以 Domain Admin (DA) 权限运行，以维护安全。
- **Temporal Privilege Limitation**：对于需要 DA 权限的任务，应限制其持续时间。可以使用如下命令实现： `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementing Deception Techniques**

- 实施欺骗包括设置陷阱，例如诱饵用户或计算机，具有诸如密码永不过期或被标记为 Trusted for Delegation 等特性。详细方法包括创建具有特定权限的用户或将其添加到高权限组中。
- 一个实际示例涉及使用如下工具： `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- 有关部署欺骗技术的更多信息，请参阅 [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception)。

### **Identifying Deception**

- **For User Objects**：可疑指标包括不寻常的 ObjectSID、罕见的登录、创建日期异常以及低错误密码计数。
- **General Indicators**：将潜在诱饵对象的属性与真实对象进行比较可揭示不一致之处。像 [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) 这样的工具可以帮助识别此类欺骗。

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**：避免在 Domain Controllers 上进行会话枚举以防触发 ATA 检测。
- **Ticket Impersonation**：使用 **aes** 密钥创建票证有助于逃避检测，因为不会降级到 NTLM。
- **DCSync Attacks**：建议在非 Domain Controller 上执行以避免 ATA 检测，因为直接在 Domain Controller 上执行会触发告警。

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

{{#include ../../banners/hacktricks-training.md}}
