# Active Directory 方法论

{{#include ../../banners/hacktricks-training.md}}

## 基本概述

**Active Directory** 是一种基础技术，使 **网络管理员** 能够在网络中高效地创建和管理 **域（domains）**、**用户（users）** 和 **对象（objects）**。它被设计为可扩展，便于将大量用户组织成可管理的 **组（groups）** 和 **子组（subgroups）**，并在多个层级上控制 **访问权（access rights）**。

**Active Directory** 的结构由三层主要层级组成：**域（domains）**、**树（trees）** 和 **林（forests）**。**域** 包含一组对象（例如 **用户** 或 **设备**），共享一个公共数据库。**树** 是由这些域按照共享结构连接而成的分组，**林** 则表示由多个树通过 **信任关系（trust relationships）** 相互连接形成的最高组织层级。可以在每个层级上指定特定的 **访问** 和 **通信权限**。

Active Directory 的关键概念包括：

1. **Directory** – 存放与 Active Directory 对象相关的所有信息。
2. **Object** – 表示目录中的实体，包括 **用户**、**组** 或 **共享文件夹**。
3. **Domain** – 用作目录对象的容器，多个域可以共存于一个 **forest** 中，每个域维护自己的对象集合。
4. **Tree** – 共享根域的一组域。
5. **Forest** – Active Directory 的最高组织结构，由多个具有 **信任关系** 的树组成。

**Active Directory Domain Services (AD DS)** 包含一系列对集中管理和网络内通信至关重要的服务。这些服务包括：

1. **Domain Services** – 集中存储数据并管理 **用户** 与 **域** 之间的交互，包括 **authentication** 和 **search** 功能。
2. **Certificate Services** – 负责创建、分发和管理安全的 **digital certificates**。
3. **Lightweight Directory Services** – 通过 **LDAP protocol** 支持启用目录的应用。
4. **Directory Federation Services** – 提供 **single-sign-on** 能力，以在单次会话中对多个 web 应用进行认证。
5. **Rights Management** – 帮助通过限制未经授权的分发和使用来保护版权材料。
6. **DNS Service** – 对 **domain names** 的解析至关重要。

有关更详细的解释，请查看：[**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

要学习如何 **attack an AD**，你需要非常理解 **Kerberos authentication process**。\
[如果你还不知道它如何工作，请阅读此页。](kerberos-authentication.md)

## 速查表

你可以访问 https://wadcoms.github.io/ 来快速查看可用于枚举/利用 AD 的命令。

> [!WARNING]
> Kerberos 通信在执行操作时**需要完全限定域名（FQDN）**。如果你尝试通过 IP 地址访问机器，**它将使用 NTLM 而不是 kerberos**。

## 侦察 Active Directory (No creds/sessions)

如果你只对 AD 环境有访问权限但没有任何凭证/会话，你可以：

- **Pentest the network:**
- 扫描网络，查找机器和开放端口，尝试 **exploit vulnerabilities** 或 **extract credentials**（例如，[打印机可能是非常有趣的目标](ad-information-in-printers.md)）。
- 枚举 DNS 可以提供域内关键服务器的信息，如 web、打印机、shares、vpn、media 等。
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- 查看通用的 [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) 以获取有关如何执行这些操作的更多信息。
- **检查 smb 服务上的 null 和 Guest 访问**（这在现代 Windows 版本上不起作用）：
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- 有关如何枚举 SMB 服务器的更详细指南，请参见：


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- 有关如何枚举 LDAP 的更详细指南，请参见（请**特别注意匿名访问**）：


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- 通过 [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) 收集凭证
- 通过 [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) 访问主机
- 通过公开 [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) 收集凭证
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- 从域环境内的内部文档、社交媒体、服务（主要是 web）以及公开可用资源中提取用户名/姓名等信息。
- 如果你找到了公司员工的完整姓名，可以尝试不同的 AD **username conventions**（[**阅读此处**](https://activedirectorypro.com/active-directory-user-naming-convention/)）。最常见的命名规则有：_NameSurname_, _Name.Surname_, _NamSur_（各取 3 个字母），_Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 以及 3 个随机字母加 3 个随机数字（abc123）。
- 工具：
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### 用户枚举

- **Anonymous SMB/LDAP enum:** 查看 [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) 和 [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) 页面。
- **Kerbrute enum**: 当请求一个 **invalid username** 时，服务器会使用 **Kerberos error** 代码 _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ 响应，从而让我们判断该用户名无效。**Valid usernames** 会触发要么在 AS-REP 中返回 **TGT**，要么返回错误 _KRB5KDC_ERR_PREAUTH_REQUIRED_，表示该用户需要执行预认证。
- **No Authentication against MS-NRPC**: 在域控制器上对 MS-NRPC (Netlogon) 接口使用 auth-level = 1（无认证）。该方法在绑定 MS-NRPC 接口后调用 `DsrGetDcNameEx2` 函数，以在无需任何凭证的情况下检查用户或计算机是否存在。工具 [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) 实现了这种类型的枚举。相关研究可在此处找到：[here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

如果在网络中发现了其中一台服务器，你也可以针对它执行 **user enumeration**。例如，你可以使用工具 [**MailSniper**](https://github.com/dafthack/MailSniper):
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

### 知道一个或多个用户名

好，你已经知道一个或多个有效的用户名但没有密码…… 那么尝试：

- [**ASREPRoast**](asreproast.md): 如果一个用户**没有**属性 _DONT_REQ_PREAUTH_，你可以为该用户**请求一个 AS_REP 消息**，其中会包含一些由该用户密码派生出的加密数据。
- [**Password Spraying**](password-spraying.md): 对发现的每个用户尝试一些**最常见的密码**，也许某些用户在使用弱密码（注意密码策略！）。
- 注意你也可以**对 OWA 服务器进行喷洒**，尝试访问用户的邮件服务器。

{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

你可能能够通过**投毒**网络中的某些协议来**获取**一些可供破解的挑战**哈希**：

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

如果你已经成功枚举了 Active Directory，你将会有**更多的邮箱地址和对网络的更好理解**。你可能能够强制执行 NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) 来获取对 AD 环境的访问。

### Steal NTLM Creds

如果你能以 **null** 或 **guest user** 访问其他 PC 或共享，你可以**放置文件**（例如 SCF 文件），当这些文件被访问时会**触发对你的 NTLM 认证**，这样你就可以**窃取**用于破解的 **NTLM challenge**：

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## 使用凭证/会话 枚举 Active Directory

在此阶段，你需要**已攻破一个有效域账号的凭证或会话**。如果你有一些有效凭证或以域用户身份的 shell，**请记住之前提到的那些选项仍然可以用来攻破其他用户**。

在开始认证枚举之前，你应该了解 **Kerberos double hop problem**。

{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### 枚举

已攻破一个账号是开始攻破整个域的**重要一步**，因为你将能够开始进行 **Active Directory 枚举：**

关于 [**ASREPRoast**](asreproast.md) 你现在可以找到所有可能的易受影响用户，关于 [**Password Spraying**](password-spraying.md) 你可以获取**所有用户名的列表**并尝试使用被攻破账号的密码、空密码以及其他可能的密码。

- 你可以使用 [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- 你也可以使用 [**powershell for recon**](../basic-powershell-for-pentesters/index.html)，这会更隐蔽
- 你也可以 [**use powerview**](../basic-powershell-for-pentesters/powerview.md) 来提取更详细的信息
- 另一个用于 Active Directory 枚举的优秀工具是 [**BloodHound**](bloodhound.md)。它**比较不隐蔽**（取决于你使用的收集方法），但**如果你不在意**，强烈推荐尝试。找出用户可以 RDP 的位置，查找通往其他组的路径等。
- **其他自动化 AD 枚举工具包括：** [**AD Explorer**](bloodhound.md#ad-explorer)**，** [**ADRecon**](bloodhound.md#adrecon)**，** [**Group3r**](bloodhound.md#group3r)**，** [**PingCastle**](bloodhound.md#pingcastle)**。**
- [**AD 的 DNS 记录**](ad-dns-records.md)，因为它们可能包含有趣的信息。
- 一个带 GUI 的目录枚举工具是来自 **SysInternal** 套件的 **AdExplorer.exe**。
- 你也可以用 **ldapsearch** 在 LDAP 数据库中搜索 _userPassword_ 与 _unixUserPassword_ 字段中的凭证，或在 _Description_ 字段中查找。参见 PayloadsAllTheThings 上的 [Password in AD User comment](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) 了解其他方法。
- 如果你使用 **Linux**，你也可以使用 [**pywerview**](https://github.com/the-useless-one/pywerview) 来枚举域。
- 你也可以尝试以下自动化工具：
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **提取所有域用户**

从 Windows 很容易获取所有域用户名（`net user /domain`、`Get-DomainUser` 或 `wmic useraccount get name,sid`）。在 Linux 上，你可以使用：`GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` 或 `enum4linux -a -u "user" -p "password" <DC IP>`

> 即便这个枚举章节看起来很短，它却是最重要的部分。打开链接（主要是 cmd、powershell、powerview 和 BloodHound 的链接），学习如何枚举域并反复练习直到你感到熟练。在一次评估中，这将是通往 DA 的关键时刻，或者让你决定无法继续的关键判断点。

### Kerberoast

Kerberoasting 包括获取由与用户账号关联的服务使用的 **TGS tickets**，并离线破解其基于用户密码的加密。

更多内容见：

{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

一旦你获得了一些凭证，你可以检查是否能访问任何 **机器**。为此，你可以使用 **CrackMapExec** 根据端口扫描结果尝试通过不同协议连接多台服务器。

### Local Privilege Escalation

如果你以普通域用户的凭证或会话入侵并且以该用户身份**能够访问域中的任意机器**，你应该尝试寻找本地提权路径并搜集凭证。因为只有获得本地管理员权限，你才能**转储其他用户的哈希**（内存中的 LSASS 或本地的 SAM）。

本书有关于 [**Windows 本地权限提升**](../windows-local-privilege-escalation/index.html) 的完整章节和一份 [**检查清单**](../checklist-windows-privilege-escalation.md)。另外，不要忘记使用 [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)。

### Current Session Tickets

当前用户持有的 **tickets** 很**不太可能**会赋予你访问意外资源的权限，但你仍可以检查：
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

如果你已经成功枚举了 Active Directory，你将会有**更多的邮箱地址并更好地了解网络**。你可能能够强制执行 NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**。**

### 在计算机共享中查找 Creds | SMB Shares

既然你有了一些基本的凭证，你应该检查是否能**找到**任何在 AD 内被共享的**有趣文件**。你可以手动执行，但那是非常乏味且重复的任务（如果你发现数百个需要检查的文档就更甚）。

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

如果你能**访问其他 PC 或 shares**，你可以**放置文件**（例如 SCF 文件），如果这些文件被访问会**触发针对你的 NTLM 验证**，这样你就可以**窃取**用于破解的**NTLM challenge**：


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

此漏洞允许任何已认证用户**攻陷域控制器**。


{{#ref}}
printnightmare.md
{{#endref}}

## 在拥有特权凭证/会话的情况下对 Active Directory 提权

**对于下面的技术，普通域用户不足以执行，你需要一些特殊的权限/凭证来实施这些攻击。**

### Hash extraction

希望你已经通过 [AsRepRoast](asreproast.md)、[Password Spraying](password-spraying.md)、[Kerberoast](kerberoast.md)、[Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)（包括 relaying）、[EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)、[escalating privileges locally](../windows-local-privilege-escalation/index.html) 等方法成功**攻陷某些本地管理员**账户。然后，是时候导出内存和本地的所有哈希了。\
[**阅读此页以了解获取哈希的不同方法。**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**一旦你得到了某用户的哈希**，你可以用它来**伪装成该用户**。\
你需要使用某些**工具**来**用该哈希执行 NTLM 认证**，**或者**你可以创建一个新的 **sessionlogon** 并将该 **哈希注入到 LSASS**，这样当执行任何 **NTLM 认证** 时，就会使用该 **哈希**。最后一种方法就是 mimikatz 所做的。\
[**阅读此页以获取更多信息。**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

该攻击旨在**使用用户的 NTLM 哈希来请求 Kerberos 票证**，作为常见的通过 NTLM 协议的 Pass The Hash 的替代方案。因此，在**NTLM 协议被禁用**、仅允许 **Kerberos** 作为认证协议的网络中，这种方法可能特别**有用**。


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

在 **Pass The Ticket (PTT)** 攻击方法中，攻击者**窃取用户的认证票证**，而不是其密码或哈希值。被窃取的票证随后被用来**冒充该用户**，从而在网络内未授权访问资源和服务。


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

如果你拥有某个本地管理员的**哈希**或**密码**，你应该尝试用它在其他 **PC** 上**本地登录**。
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> 注意这会非常**嘈杂**，并且**LAPS**可以**缓解**。

### MSSQL Abuse & Trusted Links

如果用户有权限**访问 MSSQL 实例**，他可能利用它在 MSSQL 主机上**执行命令**（如果以 SA 身份运行）、**窃取**NetNTLM **hash**，甚至执行 **relay** **attack**。\
另外，如果一个 MSSQL 实例被另一个 MSSQL 实例信任（database link），且用户对被信任的数据库拥有权限，那么他将能够**利用信任关系在其他实例上也执行查询**。这些信任关系可以链式相连，最终用户可能找到一个配置错误的数据库并在其上执行命令。\
**数据库之间的链接甚至可以跨越 forest trusts。**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

第三方的资产清点和部署套件通常会暴露可获取凭据和代码执行的强大路径。参见：

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

如果你发现任何 Computer 对象具有属性 [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) 并且你在该计算机上有域权限，你将能够从所有登录到该计算机的用户内存中导出 TGT。\
因此，如果一个**Domain Admin 登录到该计算机**，你将能够转储他的 TGT 并使用 [Pass the Ticket](pass-the-ticket.md) 冒充他。\
借助 constrained delegation 你甚至可以**自动攻陷一个 Print Server**（希望它是 DC）。


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

如果某个用户或计算机被允许进行 "Constrained Delegation"，它将能够**以任何用户的身份模拟访问某台计算机上的某些服务**。\
然后，如果你**攻破该用户/计算机的 hash**，你将能够**以任何用户（甚至 domain admins）的身份**访问这些服务。


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

对远程计算机的 Active Directory 对象具有 **WRITE** 权限可以使得获得**提升权限的代码执行**成为可能：


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

被攻破的用户可能对某些域对象拥有一些**有趣的权限**，这些权限可能让你在之后**横向移动/提升权限**。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

在域内发现有**Spool 服务监听**的主机可以被**滥用**来**获取新凭证**并**提升权限**。


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

如果**其他用户**访问**被攻破的**机器，就有可能**从内存收集凭据**，甚至**在他们的进程中注入 beacons**以冒充他们。\
通常用户会通过 RDP 访问系统，下面展示了如何对第三方 RDP 会话执行几种攻击：


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** 提供了一个在域加入计算机上管理**本地 Administrator 密码**的系统，确保密码**随机化**、唯一并且经常**更改**。这些密码存储在 Active Directory 中，并通过 ACL 只授予授权用户访问。拥有足够权限读取这些密码后，就可以实现对其他计算机的 pivot。

{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**从被攻破的机器收集证书**可能是提升环境内权限的一种途径：


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

如果配置了**易受攻击的 template**，则有可能滥用它们以提升权限：


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

一旦你获得 **Domain Admin** 或更高的 **Enterprise Admin** 权限，你可以**转储域数据库**：_ntds.dit_。

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

之前讨论的一些技术可以被用于持久化。\
例如你可以：

- 让用户易受 [**Kerberoast**](kerberoast.md) 攻击

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- 让用户易受 [**ASREPRoast**](asreproast.md) 攻击

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- 授予用户 [**DCSync**](#dcsync) 权限

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Silver Ticket attack** 利用目标服务的 **NTLM hash**（例如 PC 帐号的 hash）创建一个合法的 Ticket Granting Service (TGS) ticket，以便**访问该服务的权限**。


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** 涉及攻击者获取 Active Directory 环境中 **krbtgt 帐户** 的 **NTLM hash**。该帐户用于签名所有的 **Ticket Granting Tickets (TGTs)**，这些票据在 AD 网络中进行身份验证时至关重要。

一旦攻击者获得该 hash，他们就可以为任意帐户创建 **TGTs**（即 Silver ticket 攻击的原理）。


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

这些票据类似于 golden tickets，但以能够**绕过常见的 golden tickets 检测机制**的方式伪造。


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**持有某个帐户的证书或能够请求其证书**是保持该用户帐户持久化（即使用户更改密码）的非常有效的方法：


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**使用证书也可以在域内以高权限保持持久化：**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory 中的 **AdminSDHolder** 对象通过在这些特权组（如 Domain Admins 和 Enterprise Admins）上应用标准的 **ACL** 来确保它们的安全，从而防止未授权更改。然而，这一功能也可以被滥用；如果攻击者修改 AdminSDHolder 的 ACL 给普通用户完全控制权，该用户就能对所有特权组获得广泛控制。这个旨在保护的安全机制如果不被密切监控，反而可能被用来获取不当访问。

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

在每台 **Domain Controller (DC)** 中都存在一个**本地管理员**帐户。通过在这样一台机器上获取管理员权限，可以使用 **mimikatz** 导出本地 Administrator 的 hash。随后需要修改注册表以**启用使用该密码**，从而远程访问本地 Administrator 帐户。


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

你可以**赋予**某个**用户**对某些特定域对象的**特殊权限**，这些权限将允许该用户在未来**提升权限**。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**security descriptors** 用于**存储**对象对另一个对象的**权限**。如果你能对对象的 **security descriptor** 做一个**小改动**，你可以在无需成为特权组成员的情况下，获得对该对象的非常有价值的权限。


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

在内存中更改 **LSASS** 以建立一个**通用密码（universal password）**，从而获取对所有域帐户的访问。


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
你可以创建你自己的 **SSP** 来**捕获**访问机器时使用的**明文凭据**。


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

它会在 AD 中注册一个**新的 Domain Controller** 并用它来**推送属性**（如 SIDHistory、SPNs…）到指定对象，且在关于这些**修改**方面不会留下日志。你需要 DA 权限并处于**root domain** 内。\
注意如果你使用了错误的数据，会产生相当难看的日志。


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

前面我们讨论了如果你有**足够权限读取 LAPS 密码**时如何提升权限。然而，这些密码也可以用来**维持持久化**。\
参见：


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft 将 **Forest** 视为安全边界。这意味着**攻破单个域可能导致整个 Forest 被攻破**。

### Basic Information

A [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) 是一种安全机制，允许来自一个**域**的用户访问另一个**域**中的资源。它本质上在两个域的认证系统之间创建了一个链接，使得认证验证可以顺畅地传递。当域设置了信任时，它们会在各自的 **Domain Controllers (DCs)** 中交换并保留特定的**密钥**，这些密钥对信任的完整性至关重要。

在典型场景中，如果用户想访问**被信任域**中的服务，首先必须向自己域的 DC 请求一个特殊的票据，称为 **inter-realm TGT**。这个 TGT 使用双方约定的共享**密钥**加密。然后用户将该 TGT 提交给**被信任域的 DC**以获取服务票据（**TGS**）。被信任域的 DC 成功验证 inter-realm TGT 后，会签发一个 TGS，授予用户访问该服务的权限。

**步骤**：

1. 一台位于 **Domain 1** 的**客户端计算机**使用其 **NTLM hash** 向其 **Domain Controller (DC1)** 请求 **Ticket Granting Ticket (TGT)**，启动该过程。
2. 如果客户端认证成功，DC1 会签发一个新的 TGT。
3. 然后客户端向 DC1 请求一个**inter-realm TGT**，该票据用于访问 **Domain 2** 的资源。
4. inter-realm TGT 使用作为双向域信任一部分的 DC1 与 DC2 共享的**trust key**进行加密。
5. 客户端将 inter-realm TGT 带到 **Domain 2 的 Domain Controller (DC2)**。
6. DC2 使用其共享的 trust key 验证 inter-realm TGT，如果有效，则为客户端想要访问的 Domain 2 中的服务器签发 **Ticket Granting Service (TGS)**。
7. 最后，客户端将此 TGS 提交给服务器，该票据使用服务器账户的 hash 加密，从而获得对 Domain 2 中服务的访问权限。

### Different trusts

需要注意的是，**信任可以是单向或双向的**。在双向的情况下，两个域会互相信任，但在**单向**信任关系中，一个域为**trusted**，另一个为**trusting**。在后一种情况下，**你只能从被信任域访问信任域内的资源**。

如果 Domain A 信任 Domain B，则 A 是 trusting domain，B 是 trusted domain。此外，在 **Domain A** 中，这将是一个 **Outbound trust**；而在 **Domain B** 中，这将是一个 **Inbound trust**。

**不同的信任关系**

- **Parent-Child Trusts**：这是同一 forest 内的常见设置，child domain 会自动与其 parent domain 建立双向可传递的信任。本质上，这意味着父域与子域之间的身份验证请求可以无缝流通。
- **Cross-link Trusts**：也称为 "shortcut trusts"，在子域之间建立以加快引用过程。在复杂的 forest 中，身份验证引用通常需要向上到 forest root 然后再向下到目标域。通过创建 cross-links，引用路径被缩短，这在地理分散的环境中特别有用。
- **External Trusts**：在不同、无关联的域之间建立，且本质上是非传递性的。根据 [Microsoft 的文档](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)，external trusts 对于访问当前 forest 之外且未由 forest trust 连接的域中的资源很有用。external trusts 通过 SID filtering 增强安全性。
- **Tree-root Trusts**：这些信任在 forest root domain 与新添加的 tree root 之间自动建立。虽然不常见，但在向 forest 添加新的域树时很重要，允许它们保持唯一域名并确保双向传递性。更多信息请参见 [Microsoft 的指南](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)。
- **Forest Trusts**：这类信任是在两个 forest root 域之间建立的双向可传递信任，同时执行 SID filtering 以增强安全措施。
- **MIT Trusts**：这些信任与非 Windows、符合 [RFC4120](https://tools.ietf.org/html/rfc4120) 的 Kerberos 域建立。MIT trusts 更加专业，适用于需要与 Windows 生态系统外的 Kerberos 基础系统集成的环境。

#### Other differences in **trusting relationships**

- 信任关系也可以是**可传递的**（A 信任 B，B 信任 C，则 A 信任 C）或 **非传递的**。
- 信任关系可以设置为 **bidirectional trust**（双方互信）或 **one-way trust**（仅一方信任另一方）。

### Attack Path

1. **Enumerate** 信任关系
2. 检查是否有任何 **security principal**（user/group/computer）对**另一域**的资源有**访问**权限，可能是通过 ACE 条目或位于对方域的组中。查找**跨域的关系**（信任可能就是为此创建的）。
1. 在这种情况下，kerberoast 也可能是另一个选项。
3. **Compromise** 能够**pivot** 跨域的**帐户**。

攻击者可能通过三种主要机制访问另一个域的资源：

- **Local Group Membership**：主体可能被添加到机器上的本地组（例如服务器上的 “Administrators” 组），从而获得对该机器的显著控制权。
- **Foreign Domain Group Membership**：主体也可能是外域中某些组的成员。然而，这种方法的有效性取决于信任的性质和组的作用范围。
- **Access Control Lists (ACLs)**：主体可能在 **ACL** 中被指定，尤其是在 **DACL** 内的 **ACE** 条目中，从而为其提供对特定资源的访问。想深入了解 ACL、DACL 和 ACE 机制的人，可以参考题为 “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” 的白皮书。

### Find external users/groups with permissions

你可以检查 **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** 来查找域中的外部安全主体。这些将是来自**外部域/forest**的用户/组。

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
> 有 **2 个受信任的密钥**，一个用于 _Child --> Parent_，另一个用于 _Parent_ --> _Child_.\
> 你可以使用以下命令查看当前域使用的密钥：
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

滥用信任并通过 SID-History injection 将权限升级为子/父域的 Enterprise admin：

{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

理解如何利用 Configuration Naming Context (NC) 十分关键。Configuration NC 在 Active Directory (AD) 环境的森林中充当配置数据的中央存储库。该数据会复制到森林内的每个 Domain Controller (DC)，可写的 DC 会保有 Configuration NC 的可写副本。要利用此项，需要在某个 DC 上拥有 **SYSTEM 特权**，最好是子 DC。

**Link GPO to root DC site**

Configuration NC 的 Sites 容器包含有关 AD forest 中所有加入域的计算机站点的信息。通过在任意 DC 上以 SYSTEM 权限操作，攻击者可以将 GPO 链接到 root DC 的站点。此举可能通过操纵应用于这些站点的策略来危及根域。

如需深入信息，可参考研究 [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research)。

**Compromise any gMSA in the forest**

一种攻击向量是针对域内具有特权的 gMSA。用于计算 gMSA 密码的 KDS Root key 存储在 Configuration NC 中。在任意 DC 上拥有 SYSTEM 特权的情况下，可访问 KDS Root key 并计算森林中任何 gMSA 的密码。

详细分析和逐步指导可参见：

{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

补充的委派 MSA 攻击（BadSuccessor – 滥用 migration attributes）：

{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

额外外部研究：[Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent)。

**Schema change attack**

此方法需要耐心，等待新创建的具有特权的 AD 对象的出现。拥有 SYSTEM 特权后，攻击者可以修改 AD Schema，授予任何用户对所有类的完全控制权。这可能导致对新创建 AD 对象的未授权访问和控制。

更多阅读请见 [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent)。

**From DA to EA with ADCS ESC5**

ADCS ESC5 漏洞针对对 PKI 对象的控制，允许创建一个证书模板，从而在整个林中以任何用户进行身份验证。由于 PKI 对象位于 Configuration NC 中，攻陷一个可写的子 DC 可以执行 ESC5 攻击。

关于此攻击的更多细节可见 [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c)。在没有 ADCS 的场景中，攻击者也能够搭建所需组件，详见 [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)。

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
在此场景中 **你的域被一个外部域信任**，这使你对其拥有 **未确定的权限**。你需要找出 **你域中的哪些主体对外部域具有哪些访问权限**，然后尝试利用它：

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
在这种情形下，**你的域** 正在 **信任** 来自 **不同域** 的主体的一些 **权限**。

但是，当一个 **域被信任** 时，被信任的域会在信任域中 **创建一个用户**，其 **名称可预测**，并且将 **trusted password** 作为该用户的 **密码**。这意味着可以 **访问来自信任域的用户以进入被信任域**，对其进行枚举并尝试升级更多权限：


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

另一种攻破被信任域的方法是找到在域信任的 **相反方向** 创建的 [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links)（这并不常见）。

另一种攻破被信任域的方法是等待在一台 **被信任域的用户可以访问** 的机器上，通过 **RDP** 登录。然后，攻击者可以在 RDP 会话进程中注入代码，并从那里 **访问受害者的源域**。\
此外，如果 **受害者挂载了他的硬盘**，攻击者可以从 **RDP 会话** 进程在硬盘的 **startup folder** 中存放 **后门**。该技术称为 **RDPInception。**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### 域信任滥用缓解

### **SID Filtering:**

- 跨林信任利用 SID history 属性的攻击风险可以通过 SID Filtering 来缓解，SID Filtering 在所有林间信任上默认启用。其前提是认为林（forest）而非域（domain）是安全边界，这是基于 Microsoft 的立场。
- 但有一个问题：SID Filtering 可能会破坏某些应用程序和用户访问，因此有时会被停用。

### **Selective Authentication:**

- 对于林间信任，采用 Selective Authentication 可以确保来自两个林的用户不会被自动认证。取而代之的是，需要明确授予权限，才能让这些用户访问信任域或林内的域和服务器。
- 需要注意的是，这些措施无法防止对可写的 Configuration Naming Context (NC) 的利用，或对 trust account 的攻击。

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## 一些常见防御措施

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **凭证保护的防御措施**

- **Domain Admins 限制**：建议 Domain Admins 只允许登录到 Domain Controllers，避免在其他主机上使用该账户。
- **服务账号权限**：服务不应以 Domain Admin (DA) 权限运行以保持安全。
- **临时权限限制**：对于需要 DA 权限的任务，应限制其持续时间。可以通过以下方式实现：`Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **实施诱饵（Deception）技术**

- 实施诱饵包括设置陷阱，例如诱饵用户或计算机，特征可以是密码永不过期或被标记为 Trusted for Delegation。详细方法包括创建具有特定权限的用户或将其添加到高权限组中。
- 一个实用示例包含使用如下工具：`Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- 有关部署诱饵技术的更多信息，请参见 [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception)。

### **识别诱饵**

- **针对用户对象**：可疑指标包括非典型的 ObjectSID、稀少的登录、创建日期异常以及较低的错误密码计数。
- **一般指标**：将潜在诱饵对象的属性与真实对象进行比较可以揭示不一致。像 [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) 这样的工具可以帮助识别此类诱饵。

### **规避检测系统**

- **Microsoft ATA Detection Bypass**：
- **用户枚举**：避免在 Domain Controllers 上进行会话枚举以防触发 ATA 检测。
- **Ticket Impersonation**：使用 **aes** 密钥创建票证有助于规避检测，因为这样可以避免降级到 NTLM。
- **DCSync 攻击**：建议从非 Domain Controller 执行以避免 ATA 检测，因为直接从 Domain Controller 执行会触发告警。

## 参考文献

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

{{#include ../../banners/hacktricks-training.md}}
