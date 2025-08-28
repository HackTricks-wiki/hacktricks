# Active Directory 方法論

{{#include ../../banners/hacktricks-training.md}}

## 基本概要

**Active Directory** は基盤技術として機能し、ネットワーク内で **network administrators** が **domains**, **users**, および **objects** を効率的に作成・管理できるようにします。スケーラブルに設計されており、多数のユーザーを扱いやすい **groups** や **subgroups** に整理し、さまざまなレベルでの **access rights** を制御できます。

**Active Directory** の構造は主に三つのレイヤーで構成されます：**domains**, **trees**, および **forests**。**domain** は共通のデータベースを共有する **users** や **devices** といったオブジェクトの集合を含みます。**trees** は共通の構造で結ばれたこれらのドメインのグループであり、**forest** は複数のツリーを **trust relationships** を通じて結びつけた、組織構造の最上位レイヤーです。各レベルで特定の **access** や **communication rights** を指定できます。

**Active Directory** の主要概念は以下の通りです:

1. **Directory** – Active Directory オブジェクトに関する全情報を保持します。
2. **Object** – ディレクトリ内のエンティティを指し、**users**, **groups**, または **shared folders** を含みます。
3. **Domain** – ディレクトリオブジェクトのコンテナで、複数のドメインが **forest** 内に共存でき、それぞれ独自のオブジェクトコレクションを保持します。
4. **Tree** – 共通のルートドメインを共有するドメインのグループです。
5. **Forest** – Active Directory の組織構造における頂点で、複数のツリーとそれらの間にある **trust relationships** で構成されます。

**Active Directory Domain Services (AD DS)** はネットワーク内での集中管理と通信に不可欠な一連のサービスを含みます。これらのサービスには以下が含まれます:

1. **Domain Services** – データの中央集約と **users** と **domains** 間のやり取り（**authentication** や **search** 機能を含む）を管理します。
2. **Certificate Services** – 安全な **digital certificates** の作成、配布、管理を監督します。
3. **Lightweight Directory Services** – **LDAP protocol** を通じてディレクトリ対応アプリケーションをサポートします。
4. **Directory Federation Services** – 複数の web アプリケーションに対して**single-sign-on** を提供し、1回のセッションでユーザーを認証します。
5. **Rights Management** – 著作物の無許可配布や使用を制御して保護を支援します。
6. **DNS Service** – **domain names** の解決に不可欠です。

詳細は次を参照してください: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

AD を攻撃する方法を学ぶには、**Kerberos authentication process** を非常によく理解する必要があります。\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## チートシート

列挙/悪用のために実行できるコマンドを手早く確認するには、[https://wadcoms.github.io/](https://wadcoms.github.io) を参照してください。

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

もし AD 環境にアクセスはあるが資格情報/セッションがない場合、次のことが可能です:

- **Pentest the network:**
- ネットワークをスキャンし、マシンや開いているポートを見つけて、**exploit vulnerabilities** したりそれらから **extract credentials** を試みます（例えば、[printers could be very interesting targets](ad-information-in-printers.md)）。
- DNS の列挙は、web、printers、shares、vpn、media などドメイン内の主要なサーバーに関する情報を与えることがあります。
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- 詳細は一般的な [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) を参照してください。
- **Check for null and Guest access on smb services**（これは最新の Windows バージョンでは機能しません）:
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- SMB サーバーを列挙する詳細ガイドは以下にあります:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- LDAP を列挙する詳細ガイドはここにあります（**anonymous access** に特に注意してください）:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Responder を使って **impersonating services** を行い資格情報を収集する（[**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)）
- [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) によりホストへアクセスする
- fake UPnP サービスを **evil-S** で公開して資格情報を収集する（[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)）
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- ドメイン環境内および公開されている資料からユーザー名や氏名を抽出します（主に web）。
- 企業の従業員のフルネームが見つかった場合、さまざまな AD **username conventions** を試すことができます（[**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)）。最も一般的な規則は: _NameSurname_, _Name.Surname_, _NamSur_（各3文字ずつ）, _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, そして 3 つの _random letters and 3 random numbers_（abc123）。
- ツール:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) および [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) のページを確認してください。
- **Kerbrute enum**: 無効なユーザー名がリクエストされた場合、サーバーは **Kerberos error** コード _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ を返し、ユーザー名が無効であることを判別できます。有効なユーザー名は **TGT in a AS-REP** レスポンスか、プリ認証が必要であることを示すエラー _KRB5KDC_ERR_PREAUTH_REQUIRED_ のいずれかを引き起こします。
- **No Authentication against MS-NRPC**: domain controllers 上の MS-NRPC (Netlogon) インターフェイスに対して auth-level = 1 (No authentication) を使用する方法です。この手法は MS-NRPC インターフェイスにバインドした後 `DsrGetDcNameEx2` 関数を呼び出し、資格情報なしでユーザーやコンピュータが存在するかを確認します。NauthNRPC ツールはこのタイプの列挙を実装しています。研究はここにあります: [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

ネットワーク内でこれらのサーバーを見つけた場合、**user enumeration against it** を実行することもできます。例えば、ツール [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> ユーザー名の一覧は [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  およびこのリポジトリ ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)) で見つけられます。
>
> ただし、事前に行った recon のステップから、その会社で働いている人の **name of the people working on the company** を把握しているはずです。名前と姓が分かれば、スクリプト [**namemash.py**](https://gist.github.com/superkojiman/11076951) を使って潜在的な有効ユーザー名を生成できます。

### Knowing one or several usernames

Ok, so you know you have already a valid username but no passwords... Then try:

- [**ASREPRoast**](asreproast.md): ユーザーが属性 _DONT_REQ_PREAUTH_ を**持っていない**場合、そのユーザーに対して **AS_REP message を要求**できます。これにはユーザーのパスワードの派生鍵で暗号化されたデータが含まれます。
- [**Password Spraying**](password-spraying.md): 発見した各ユーザーに対して最も**common passwords** を試してみてください。悪いパスワードを使っているユーザーがいるかもしれません（パスワードポリシーに注意！）。
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

### Steal NTLM Creds

If you can **access other PCs or shares** with the **null or guest user** you could **place files** (like a SCF file) that if somehow accessed will t**rigger an NTLM authentication against you** so you can **steal** the **NTLM challenge** to crack it:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Enumerating Active Directory WITH credentials/session

For this phase you need to have **compromised the credentials or a session of a valid domain account.** If you have some valid credentials or a shell as a domain user, **you should remember that the options given before are still options to compromise other users**.

Before start the authenticated enumeration you should know what is the **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Having compromised an account is a **big step to start compromising the whole domain**, because you are going to be able to start the **Active Directory Enumeration:**

Regarding [**ASREPRoast**](asreproast.md) you can now find every possible vulnerable user, and regarding [**Password Spraying**](password-spraying.md) you can get a **list of all the usernames** and try the password of the compromised account, empty passwords and new promising passwords.

- [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info) を使って基本的な recon を実行できます。
- [**powershell for recon**](../basic-powershell-for-pentesters/index.html) を使うこともでき、こちらのほうがよりステルスです。
- [**use powerview**](../basic-powershell-for-pentesters/powerview.md) を使ってより詳細な情報を抽出できます。
- Active Directory の recon にもう一つ素晴らしいツールは [**BloodHound**](bloodhound.md) です。収集手法によりますが **not very stealthy** です。ですが、それを気にしないなら、ぜひ試してみてください。ユーザーがどこで RDP できるか、他のグループへの経路などを見つけられます。
- **Other automated AD enumeration tools are:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) は興味深い情報を含んでいる可能性があります。
- ディレクトリを列挙するために使える **tool with GUI** は **SysInternal** Suite の **AdExplorer.exe** です。
- **ldapsearch** で LDAP データベースを検索し、_userPassword_ & _unixUserPassword_ フィールド、あるいは _Description_ 内の資格情報を探すこともできます。その他の手法は cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) を参照してください。
- **Linux** を使用している場合、[**pywerview**](https://github.com/the-useless-one/pywerview) を使ってドメインを列挙することもできます。
- 自動化ツールとして次のものも試せます:
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

If you have managed to enumerate the Active Directory you will have **more emails and a better understanding of the network**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Computer Shares の Creds を探す | SMB Shares

基本的な資格情報を入手したら、**AD 内で共有されている興味深いファイルを見つけられるか**確認するべきです。手動でも可能ですが、とても退屈で反復的な作業です（確認すべきドキュメントが何百もあればなおさら）。

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

もし **他のPCや共有にアクセスできる** なら、（SCF ファイルのような）**ファイルを配置**して、誰かがアクセスしたときに t**rigger an NTLM authentication against you** ことで **NTLM challenge** を **steal** してクラックすることができます:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

この脆弱性により、認証済みユーザーであれば誰でも **ドメインコントローラを侵害する** ことが可能でした。


{{#ref}}
printnightmare.md
{{#endref}}

## Active Directory での特権昇格 WITH privileged credentials/session

**以下の技術には通常のドメインユーザーでは不十分で、これらの攻撃を実行するために特別な権限/資格情報が必要です。**

### Hash extraction

運良く [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)（リレーを含む）, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html) などを使って **いくつかのローカル管理者アカウントを compromise している** ことでしょう。\
その後、メモリ上およびローカルからすべてのハッシュをダンプする時です。\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Once you have the hash of a user**, you can use it to **impersonate** it.\
You need to use some **tool** that will **perform** the **NTLM authentication using** that **hash**, **or** you could create a new **sessionlogon** and **inject** that **hash** inside the **LSASS**, so when any **NTLM authentication is performed**, that **hash will be used.** The last option is what mimikatz does.\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

This attack aims to **use the user NTLM hash to request Kerberos tickets**, as an alternative to the common Pass The Hash over NTLM protocol. Therefore, this could be especially **useful in networks where NTLM protocol is disabled** and only **Kerberos is allowed** as authentication protocol.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

In the **Pass The Ticket (PTT)** attack method, attackers **steal a user's authentication ticket** instead of their password or hash values. This stolen ticket is then used to **impersonate the user**, gaining unauthorized access to resources and services within a network.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

If you have the **hash** or **password** of a **local administrato**r you should try to **login locally** to other **PCs** with it.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> これはかなり**ノイズが多く**、**LAPS**があれば**軽減**されることに注意してください。

### MSSQL Abuse & Trusted Links

ユーザが**MSSQL instances にアクセスする権限**を持っている場合、MSSQL ホスト上で（SAとして動作していれば）**コマンドを実行**したり、NetNTLM の **hash を盗む**、あるいは **relay attack** を実行できる可能性があります。\
また、ある MSSQL インスタンスが別の MSSQL インスタンスから信頼（database link）されている場合、信頼されたデータベースに対する権限を持つユーザは、**信頼関係を利用して他のインスタンスでもクエリを実行する**ことが可能です。これらの信頼は連鎖することがあり、最終的にコマンドを実行できるような誤設定されたデータベースを発見できるかもしれません。\
**データベース間のリンクはフォレスト間のトラストを越えても機能します。**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

サードパーティのインベントリやデプロイメントスイートは、しばしば資格情報やコード実行につながる強力な経路を公開しています。参照：

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

[ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) 属性を持つ Computer オブジェクトを見つけ、かつそのコンピュータ上でドメイン権限を持っている場合、そのコンピュータにログオンするすべてのユーザのメモリから TGT をダンプできます。\
したがって、もし**Domain Admin がそのコンピュータにログイン**すると、その TGT をダンプして [Pass the Ticket](pass-the-ticket.md) を使ってそのユーザになりすますことが可能になります。\
constrained delegation によっては、**Print Server を自動的に乗っ取る**ことさえあり得ます（幸いにもそれが DC である場合があるかもしれません）。


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

ユーザまたはコンピュータが "Constrained Delegation" に許可されていると、そのコンピュータ上の特定のサービスに対して**任意のユーザを偽装してアクセスする**ことができます。\
そして、もしそのユーザ/コンピュータの**ハッシュを奪取**すれば、（Domain Admin を含む）**任意のユーザを偽装して特定のサービスにアクセスする**ことが可能になります。


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

リモートコンピュータの Active Directory オブジェクトに対して **WRITE 権限** を持つことは、**昇格された権限でのコード実行**を得ることを可能にします：


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

侵害されたユーザが一部のドメインオブジェクトに対して**興味深い権限**を持っている場合、それを利用して**横移動**や**権限昇格**が可能になります。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

ドメイン内で**Spool service がリッスンしている**ことを発見すると、これを**悪用**して**新しい資格情報を取得**したり**権限を昇格**させたりすることができます。


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

**他のユーザ**が**侵害された**マシンに**アクセス**する場合、メモリから資格情報を**収集**したり、彼らのプロセスにビークンを**インジェクト**して彼らになりすますことが可能です。\
通常、ユーザは RDP を介してシステムにアクセスするため、第三者の RDP セッションに対するいくつかの攻撃方法はこちら：


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** はドメイン参加コンピュータの**ローカル Administrator パスワード**を管理する仕組みで、パスワードを**ランダム化**し一意にし頻繁に**変更**します。これらのパスワードは Active Directory に保存され、アクセスは ACL によって認可されたユーザに制御されます。これらのパスワードにアクセスする十分な権限があれば、他のコンピュータへピボットすることが可能になります。


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

侵害されたマシンから**証明書を収集**することは、環境内での権限昇格の手段になり得ます：


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

**脆弱なテンプレート**が設定されている場合、それを悪用して権限昇格することが可能です：


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

一旦 **Domain Admin** またはより上位の **Enterprise Admin** 権限を得ると、ドメインデータベースである _ntds.dit_ を**ダンプ**できます。

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

前述した技術のいくつかは永続化に利用できます。\
例えば、次のようなことが可能です：

- ユーザを [**Kerberoast**](kerberoast.md) に脆弱にする

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- ユーザを [**ASREPRoast**](asreproast.md) に脆弱にする

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- ユーザに [**DCSync**](#dcsync) 権限を付与する

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Silver Ticket attack** は、特定のサービス向けに正当な Ticket Granting Service (TGS) チケットを、例えば**PC account の NTLM hash**などを使って作成する攻撃です。この方法を用いて**サービスの権限にアクセス**します。


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** とは、Active Directory 環境で **krbtgt account の NTLM hash** に攻撃者がアクセスすることを含みます。このアカウントはすべての **Ticket Granting Tickets (TGTs)** の署名に使用されるため特別です。攻撃者がこのハッシュを取得すると、任意のアカウントのための **TGT を作成**することができます（Silver ticket attack と同様の利用法）。


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

これらは golden ticket に似ていますが、**一般的な golden ticket 検出メカニズムを回避する**ように偽造されたものです。


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**アカウントの証明書を持っている、またはそれを要求できる**ことは、ユーザのパスワードが変更されてもアカウントに**永続化**する非常に有効な手段です：


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**証明書を使用することでドメイン内で高権限を持って永続化**することも可能です：


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory の **AdminSDHolder** オブジェクトは、Domain Admins や Enterprise Admins のような**特権グループ**のセキュリティを維持するため、これらのグループに標準的な **ACL** を適用して不正な変更を防ぎます。しかし、この機能は悪用可能で、攻撃者が AdminSDHolder の ACL を変更して通常ユーザにフルアクセスを与えると、そのユーザはすべての特権グループに対して広範な制御を得ることになります。この保護機能は監視が不十分だと裏目に出る可能性があります。

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

すべての **Domain Controller (DC)** にはローカル管理者アカウントが存在します。そのようなマシンで管理者権を取得すると、mimikatz を使用してローカル Administrator hash を抽出できます。その後、リモートでこのパスワードを使用できるようにするためにレジストリの変更が必要です。


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

特定のドメインオブジェクトに対して**特別な権限**をあるユーザに**付与**することで、そのユーザが将来的に**権限を昇格**できるようにすることができます。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**security descriptors** はオブジェクトが持つ**権限を格納**するために使われます。オブジェクトの **security descriptor** に小さな変更を加えるだけで、特権グループのメンバでなくてもそのオブジェクトに対して非常に興味深い権限を得ることができます。


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

LSASS をメモリ上で改変して**ユニバーサルパスワード**を設定し、すべてのドメインアカウントへのアクセスを可能にします。


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
独自の **SSP** を作成して、マシンにアクセスする際に使用される **資格情報を平文でキャプチャ**することができます。


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

新しい Domain Controller を AD に登録し、それを利用して指定したオブジェクトに対して（SIDHistory、SPNs などの）属性を **ログを残さずに** プッシュします。これを行うには DA 権限とルートドメイン内での実行が必要です。\
ただし、誤ったデータを使うとかなり醜いログが出る点に注意してください。


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

前述の通り、**LAPS パスワードを読むのに十分な権限**があれば権限昇格できますが、これらのパスワードは**永続化**にも利用できます。\
参照：


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft は **フォレスト (Forest)** をセキュリティ境界とみなしています。これは、**単一のドメインを侵害するとフォレスト全体が侵害される可能性がある**ことを意味します。

### Basic Information

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) は、ある **ドメイン** のユーザが別の **ドメイン** のリソースにアクセスすることを可能にするセキュリティメカニズムです。これは両ドメインの認証システム間に連携を作り、認証検証がシームレスに流れるようにします。ドメインがトラストを設定すると、それらは特定の **keys** を各々の **Domain Controllers (DCs)** に交換して保持し、トラストの整合性に重要な役割を果たします。

典型的なシナリオでは、ユーザが **trusted domain** のサービスにアクセスしようとする場合、まず自ドメインの DC から特別なチケットである **inter-realm TGT** を要求する必要があります。この TGT は両ドメインが合意した共有 **key** で暗号化されます。ユーザはこの TGT を **trusted domain の DC** に提示してサービスチケット（**TGS**）を取得します。trusted domain の DC が inter-realm TGT を検証して有効と判断すると、サービスへのアクセスを許可する TGS を発行します。

**Steps**:

1. **Domain 1** の **client computer** が自身の **NTLM hash** を使って **Domain Controller (DC1)** から **Ticket Granting Ticket (TGT)** を要求してプロセスを開始します。
2. クライアントが正常に認証されると DC1 は新しい TGT を発行します。
3. クライアントは次に **Domain 2** のリソースにアクセスするために DC1 から **inter-realm TGT** を要求します。
4. inter-realm TGT は、両ドメイン間の双方向トラストの一部として DC1 と DC2 が共有する **trust key** で暗号化されます。
5. クライアントは inter-realm TGT を **Domain 2 の Domain Controller (DC2)** に持っていきます。
6. DC2 は共有された trust key を使って inter-realm TGT を検証し、有効であればクライアントがアクセスしようとする Domain 2 のサーバに対する **Ticket Granting Service (TGS)** を発行します。
7. 最後にクライアントはこの TGS をサーバに提示します。TGS はサーバのアカウントハッシュで暗号化されており、これによって Domain 2 のサービスへのアクセスが得られます。

### Different trusts

トラストは **片方向** または **双方向** であり得る点に注意が必要です。双方向の場合は両ドメインが互いに信頼しますが、**片方向** のトラスト関係では一方が **trusted**、もう一方が **trusting** ドメインになります。この場合、**trusted 側からは trusting 側のリソースにのみアクセスできる**ことになります。

もし Domain A が Domain B を信頼しているなら、A は trusting ドメインで B は trusted ドメインです。さらに、**Domain A** においてはこれは **Outbound trust** であり、**Domain B** においては **Inbound trust** となります。

**Different trusting relationships**

- **Parent-Child Trusts**: 同一フォレスト内で一般的な設定で、child domain は自動的に parent domain と二方向のトランジティブトラストを持ちます。これにより親と子の間で認証要求がシームレスに流れます。
- **Cross-link Trusts**: 「shortcut trusts」とも呼ばれ、child ドメイン間でのリファラルプロセスを短縮するために設定されます。複雑なフォレストでは認証リファラルがフォレストルートまで上がってからターゲットドメインに下る必要がありますが、cross-link を作成するとその経路が短縮され、地理的に分散した環境で有益です。
- **External Trusts**: 異なる無関係なドメイン間で設定されるもので、トランジティブではありません。Microsoft のドキュメントによれば、external trusts はフォレストトラストで接続されていないフォレスト外のドメインのリソースにアクセスするのに有用です。External trusts では SID filtering によってセキュリティが強化されます。
- **Tree-root Trusts**: フォレストルートドメインと新しく追加されたツリールートとの間に自動的に確立されるトラストです。頻繁には見られませんが、フォレストに新しいドメインツリーを追加する際に重要で、固有のドメイン名を維持し二方向のトランジティビティを確保します。詳細は Microsoft のガイドを参照してください。
- **Forest Trusts**: これは二つのフォレストルートドメイン間の二方向トランジティブトラストで、SID filtering によるセキュリティ強化も適用されます。
- **MIT Trusts**: これらは非 Windows の、[RFC4120 準拠](https://tools.ietf.org/html/rfc4120) の Kerberos ドメインと確立されるトラストです。MIT trusts は外部の Kerberos ベースのシステムと統合する環境に適した特殊なケースです。

#### Other differences in **trusting relationships**

- トラスト関係は **トランジティブ**（A は B を信頼し、B は C を信頼していれば A は C を信頼する）である場合と **非トランジティブ**である場合があります。
- トラスト関係は **双方向トラスト**（両者が互いに信頼する）または **片方向トラスト**（片方のみがもう片方を信頼する）として設定できます。

### Attack Path

1. 信頼関係を**列挙**する
2. いずれかの **security principal**（user/group/computer）が**他ドメインのリソースにアクセスできるか**を ACE エントリや他ドメインのグループメンバシップで確認する。**ドメイン間の関係**を探せ（トラストはこれを目的に作成されている可能性がある）。
1. この場合 kerberoast も別のオプションになり得る。
3. ドメインを横断して**ピボット**できるアカウントを**侵害**する。

攻撃者が別ドメインのリソースにアクセスするために使える主要なメカニズムは次の3つです：

- **Local Group Membership**: プリンシパルがサーバ上の “Administrators” グループのようなローカルグループに追加されている場合、そのマシンに対して大きな制御を得られます。
- **Foreign Domain Group Membership**: プリンシパルが外国ドメイン内のグループのメンバである場合もあります。ただし、この方法の有効性はトラストの性質とグループのスコープに依存します。
- **Access Control Lists (ACLs)**: プリンシパルが **ACL**、特に **DACL** 内の **ACE** として指定されている場合、特定のリソースへのアクセスが与えられます。ACL、DACL、ACE の仕組みに深く入るには、ホワイトペーパー “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” が非常に有用です。

### Find external users/groups with permissions

外部セキュリティプリンシパルを見つけるには **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** をチェックできます。これらは **外部のドメイン/フォレスト** からの user/group です。

これは Bloodhound か powerview を使って確認できます：
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Child-to-Parent forest privilege escalation
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
ドメインの信頼関係を列挙する他の方法:
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
> **2つの trusted keys** が存在します。1つは _Child --> Parent_ 用、もう1つは _Parent_ --> _Child_ 用です。\
> 現在のドメインで使用されているキーは次のコマンドで確認できます：
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

信頼を悪用して SID-History injection により、child/parent domain に対して Enterprise admin として権限を昇格します:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Configuration Naming Context (NC) がどのように悪用できるかを理解することは重要です。Configuration NC は Active Directory (AD) 環境内のフォレスト全体の構成データの中央リポジトリとして機能します。このデータはフォレスト内のすべての Domain Controller (DC) にレプリケートされ、書き込み可能な DC は Configuration NC の書き込み可能なコピーを保持します。これを悪用するには、**DC 上の SYSTEM privileges**（できれば child DC）が必要です。

**Link GPO to root DC site**

Configuration NC の Sites コンテナには、AD フォレスト内のすべてのドメイン参加コンピュータのサイト情報が含まれます。任意の DC 上で SYSTEM privileges を持って操作することで、攻撃者は GPO を root DC site にリンクできます。この操作により、これらのサイトに適用されるポリシーを操作して root domain を危殆化させる可能性があります。

詳しくは [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research) の研究を参照してください。

**Compromise any gMSA in the forest**

攻撃ベクターの一つは、ドメイン内の特権的な gMSA を標的にすることです。gMSA のパスワードを計算するために必要な KDS Root key は Configuration NC に保存されています。任意の DC 上で SYSTEM privileges を持てば、KDS Root key にアクセスしてフォレスト内の任意の gMSA のパスワードを算出することが可能です。

Detailed analysis and step-by-step guidance can be found in:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Complementary delegated MSA attack (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

追加の外部研究: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

この手法は、特権を持つ新しい AD オブジェクトの作成を待つ忍耐を要求します。SYSTEM privileges があれば、攻撃者は AD Schema を変更して任意のユーザに全クラスに対する完全な制御を付与できます。これにより、新たに作成された AD オブジェクトへの不正アクセスや制御が発生する可能性があります。

詳しくは [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent) を参照してください。

**From DA to EA with ADCS ESC5**

ADCS ESC5 脆弱性は、Public Key Infrastructure (PKI) オブジェクトを制御することで、フォレスト内の任意のユーザとして認証を可能にする証明書テンプレートを作成することを狙います。PKI オブジェクトは Configuration NC に存在するため、書き込み可能な child DC を侵害すれば ESC5 攻撃を実行できます。

この詳細は [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c) を参照してください。ADCS が存在しないシナリオでは、攻撃者は必要なコンポーネントをセットアップできる場合があり、これは [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) で議論されています。

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
このシナリオでは、**あなたのドメインは外部ドメインによって信頼されており**、外部ドメイン上であなたに対して**不確定な権限**が与えられています。あなたは、**あなたのドメインのどのプリンシパルが外部ドメインに対してどのようなアクセスを持っているか**を特定し、それを悪用できるか試す必要があります:

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
このシナリオでは **your domain** が **different domains** からのプリンシパルに対していくつかの **privileges** を **trusting** しています。

しかし、ある **domain is trusted** と、trusting domain によって trusted domain は **creates a user** を行い、**predictable name** のユーザーを作成し、その **password** として **trusted password** を使用します。つまり、**access a user from the trusting domain to get inside the trusted one** して列挙し、さらに権限昇格を試みることが可能になります：

{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

trusted domain を侵害する別の方法は、domain trust の **opposite direction** に作成された [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) を見つけることです（これはあまり一般的ではありません）。

trusted domain を侵害するもう一つの方法は、**user from the trusted domain can access** して **RDP** でログインできるマシンに待ち構えることです。攻撃者は RDP セッションプロセスにコードを注入し、そこから **access the origin domain of the victim** することができます。\
さらに、もし **victim mounted his hard drive** している場合、RDP セッションプロセスから攻撃者はハードドライブの **startup folder of the hard drive** に **backdoors** を置くことができます。この手法は **RDPInception** と呼ばれます。

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### ドメイントラストの悪用に対する緩和策

### **SID Filtering:**

- SID history 属性を横断するフォレスト間トラストを悪用した攻撃のリスクは、SID Filtering によって緩和されます。SID Filtering はすべての inter-forest trusts でデフォルトで有効になっています。これは、Microsoft の見解に基づき、security boundary を domain ではなく forest と見なすため、intra-forest trusts は安全であるという前提に支えられています。
- ただし注意点があります。SID filtering はアプリケーションやユーザーアクセスに影響を与える可能性があり、場合によっては無効化されることがあります。

### **Selective Authentication:**

- inter-forest trusts に対して Selective Authentication を適用すると、両フォレストのユーザーが自動的に認証されることはなくなります。代わりに、trusting domain やフォレスト内のドメインやサーバーにアクセスするには明示的な権限が必要になります。
- これらの対策は、writable Configuration Naming Context (NC) の悪用や trust account に対する攻撃を防ぐものではない点に注意が必要です。

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD

{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## 一般的な防御策

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Domain Admins は可能な限り Domain Controllers のみにログインを許可し、他のホストでは使用しないことが推奨されます。
- **Service Account Privileges**: サービスは Domain Admin (DA) 権限で実行すべきではありません。
- **Temporal Privilege Limitation**: DA 権限を要するタスクについては、その期間を限定するべきです。例: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementing Deception Techniques**

- deception の実装は、パスワードが期限切れにならない、Trusted for Delegation にマークされているなどのトラップ（デコイユーザーやデコイコンピュータ）を設置することを含みます。具体的には特定の権利を持つユーザーを作成したり、高権限グループに追加したりする方法があります。
- 実用例としては次のようなツールの使用が挙げられます: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- deception の展開に関する詳細は [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception) を参照してください。

### **Identifying Deception**

- **For User Objects**: 疑わしい指標には、異常な ObjectSID、まれなログオン、作成日時、低い bad password カウントなどがあります。
- **General Indicators**: デコイオブジェクトと実際のオブジェクトの属性を比較することで矛盾を暴くことができます。[HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) のようなツールがこの識別に役立ちます。

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: ATA 検出を避けるために Domain Controllers 上でのセッション列挙を避ける。
- **Ticket Impersonation**: aes キーを使ったチケット作成は、NTLM にダウングレードしないことで検出を回避するのに役立ちます。
- **DCSync Attacks**: Domain Controller 以外のマシンから実行することで ATA 検出を回避するのが推奨されます。Domain Controller から直接実行するとアラートが発生します。

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

{{#include ../../banners/hacktricks-training.md}}
