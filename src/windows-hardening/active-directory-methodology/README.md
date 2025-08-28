# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Basic overview

**Active Directory** は基盤技術として機能し、**network administrators** がネットワーク内で **domains**, **users**, および **objects** を効率的に作成・管理できるようにします。スケールするように設計され、多数のユーザーを管理しやすい **groups** や **subgroups** に整理し、様々なレベルで **access rights** を制御できます。

**Active Directory** の構造は主に三つの層で構成されています: **domains**, **trees**, および **forests**。**domain** は共通のデータベースを共有する **users** や **devices** のようなオブジェクトの集合を包含します。**trees** は共通の構造で結ばれたこれらの domains のグループで、**forest** は複数の trees が **trust relationships** を介して接続された最上位の組織構造を表します。各レベルで特定の **access** や **communication rights** を指定できます。

**Active Directory** の主要な概念には次のものがあります:

1. **Directory** – Active Directory オブジェクトに関する全情報を格納します。
2. **Object** – ディレクトリ内の実体を指し、**users**, **groups**, または **shared folders** などが含まれます。
3. **Domain** – ディレクトリオブジェクトのコンテナとして機能し、複数の domains が **forest** 内に共存でき、それぞれが独自のオブジェクト集合を保持します。
4. **Tree** – 共通の root domain を共有する domains のグループです。
5. **Forest** – Active Directory の組織構造の頂点で、複数の trees とそれらの間の **trust relationships** で構成されます。

**Active Directory Domain Services (AD DS)** は、ネットワーク内の集中管理と通信に重要な一連のサービスを含みます。これらのサービスには次が含まれます:

1. **Domain Services** – データの集中格納と **users** と **domains** 間のやり取りを管理し、**authentication** や **search** 機能を提供します。
2. **Certificate Services** – 安全な **digital certificates** の作成、配布、管理を行います。
3. **Lightweight Directory Services** – **LDAP protocol** を通じてディレクトリ対応アプリケーションをサポートします。
4. **Directory Federation Services** – 複数の web アプリケーション間での **single-sign-on** を提供します。
5. **Rights Management** – 著作物の不正配布や使用を制御して保護を支援します。
6. **DNS Service** – **domain names** の解決に不可欠です。

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

To learn how to **attack an AD** you need to **understand** really good the **Kerberos authentication process**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

You can take a lot to [https://wadcoms.github.io/](https://wadcoms.github.io) to have a quick view of which commands you can run to enumerate/exploit an AD.

> [!WARNING]
> Kerberos communication **requires a full qualified name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not Kerberos**.

## Recon Active Directory (No creds/sessions)

If you just have access to an AD environment but you don't have any credentials/sessions you could:

- **Pentest the network:**
- Scan the network, find machines and open ports and try to **exploit vulnerabilities** or **extract credentials** from them (for example, [printers could be very interesting targets](ad-information-in-printers.md).
- Enumerating DNS could give information about key servers in the domain as web, printers, shares, vpn, media, etc.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Take a look to the General [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) to find more information about how to do this.
- **Check for null and Guest access on smb services** (this won't work on modern Windows versions):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- A more detailed guide on how to enumerate a SMB server can be found here:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- A more detailed guide on how to enumerate LDAP can be found here (pay **special attention to the anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Gather credentials [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Access host by [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Gather credentials **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Extract usernames/names from internal documents, social media, services (mainly web) inside the domain environments and also from the publicly available.
- If you find the complete names of company workers, you could try different AD **username conventions (**[**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). The most common conventions are: _NameSurname_, _Name.Surname_, _NamSur_ (3letters of each), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Check the [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) and [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) pages.
- **Kerbrute enum**: When an **invalid username is requested** the server will respond using the **Kerberos error** code _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, allowing us to determine that the username was invalid. **Valid usernames** will illicit either the **TGT in a AS-REP** response or the error _KRB5KDC_ERR_PREAUTH_REQUIRED_, indicating that the user is required to perform pre-authentication.
- **No Authentication against MS-NRPC**: Using auth-level = 1 (No authentication) against the MS-NRPC (Netlogon) interface on domain controllers. The method calls the `DsrGetDcNameEx2` function after binding MS-NRPC interface to check if the user or computer exists without any credentials. The [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) tool implements this type of enumeration. The research can be found [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

ネットワーク内でこれらのサーバーを見つけた場合、**user enumeration against it** を実行することもできます。例えば、ツール [**MailSniper**](https://github.com/dafthack/MailSniper) を使用できます:
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
> ユーザー名の一覧は [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) および ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)) にあります。
>
> ただし、事前に行うべき recon ステップでその会社で働いている人々の **name** を把握しておくべきです。名前と姓がわかればスクリプト [**namemash.py**](https://gist.github.com/superkojiman/11076951) を使って有効な username の候補を生成できます。

### Knowing one or several usernames

OK、すでに有効な username を把握しているが passwords を持っていない場合は、次を試してください:

- [**ASREPRoast**](asreproast.md): ユーザーが属性 _DONT_REQ_PREAUTH_ を **持っていない** 場合、そのユーザーの AS_REP メッセージを **要求** でき、そのメッセージはユーザーの password の導出で暗号化されたデータを含みます。
- [**Password Spraying**](password-spraying.md): 発見した各ユーザーに対して最も **一般的な passwords** を試してみてください。悪い password を使っているユーザーがいるかもしれません（password policy を忘れずに！）。
- OWA サーバーを **spray** してユーザーの mail サーバーへのアクセスを試みることもできます。


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

一部のチャレンジ **hashes** を取得してネットワーク内のいくつかのプロトコルを **poisoning** し、後で crack することができるかもしれません:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Active Directory を列挙できていれば、**より多くのメールアドレスやネットワークの理解** が得られます。NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) を強制して AD 環境へアクセスできる可能性があります。

### Steal NTLM Creds

**null** や **guest user** で他の PC や shares に **アクセス** できる場合、SCF ファイルのようなファイルを **配置** して、誰かがそれを参照すると **あなたに対する NTLM 認証がトリガーされ**、NTLM チャレンジを盗んで crack できる可能性があります:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## 資格情報/セッションありでの Active Directory 列挙

このフェーズでは、有効なドメインアカウントの **credentials または session を奪取** している必要があります。もし有効な credentials やドメインユーザーとしてのシェルを持っているなら、前に挙げたオプションは他のユーザーを侵害するための選択肢として引き続き有効であることを覚えておいてください。

認証済み列挙を開始する前に、**Kerberos double hop problem** を理解しておくべきです。


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### 列挙

アカウントを侵害することはドメイン全体を侵害し始めるための **大きな一歩** です。これにより Active Directory 列挙を開始できます:

[**ASREPRoast**](asreproast.md) に関しては、今や脆弱なユーザーを全て見つけられますし、[**Password Spraying**](password-spraying.md) に関しては、**すべての username のリスト** を取得して、侵害したアカウントの password、空の password、その他有望な password を試すことができます。

- 基本的な recon を実行するには [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info) を使うことができます
- よりステルスに行うなら [**powershell for recon**](../basic-powershell-for-pentesters/index.html) を使用できます
- より詳細な情報を抽出するには [**use powerview**](../basic-powershell-for-pentesters/powerview.md) を使えます
- Active Directory の recon に便利なツールとして [**BloodHound**](bloodhound.md) があります。収集方法によっては **あまりステルスではありません** が、気にしないならぜひ試してください。どこでユーザーが RDP できるか、他のグループへのパスなどを見つけられます。
- **その他の自動化された AD 列挙ツール:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**。**
- 興味深い情報が含まれている可能性があるので、[**AD の DNS レコード**](ad-dns-records.md) を確認してください。
- GUI ベースのディレクトリ列挙ツールとしては **SysInternal** Suite の **AdExplorer.exe** を使えます。
- ldapsearch を使って LDAP データベースを検索し、フィールド _userPassword_ や _unixUserPassword_、あるいは _Description_ に credential がないか探すこともできます。その他の方法については PayloadsAllTheThings の "Password in AD User comment" を参照してください（https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment）。
- **Linux** を使っているなら [**pywerview**](https://github.com/the-useless-one/pywerview) でドメインを列挙できます。
- 自動化ツールの例:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

Windows ではドメイン内の全ユーザー名を取得するのは非常に簡単です（`net user /domain`、`Get-DomainUser`、または `wmic useraccount get name,sid`）。Linux では `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` や `enum4linux -a -u "user" -p "password" <DC IP>` を使えます。

> この列挙セクションは短く見えるかもしれませんが、最も重要な部分です。リンク先（主に cmd, powershell, powerview, BloodHound）を参照して、ドメインの列挙方法を学び、十分に慣れるまで練習してください。評価時に、ここが DA に到達する鍵となるか、何もできないと判断する決定点になります。

### Kerberoast

Kerberoasting は、サービスに紐づくユーザーアカウントのために使われる **TGS tickets** を取得し、その暗号化（ユーザーの password に基づく）をオフラインで crack する攻撃です。

詳しくは以下を参照してください:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

いったん credentials を入手したら、どの **machine** にアクセスできるか確認してください。そのために、ポートスキャンに基づいて様々なプロトコルで複数のサーバーに接続を試みるために **CrackMapExec** を使うことができます。

### Local Privilege Escalation

通常のドメインユーザーとして credentials や session を奪取し、そのユーザーでドメイン内の **任意のマシンにアクセス** できる場合は、ローカルでの権限昇格と credential の収集を試みるべきです。ローカル管理者権限を得て初めて、他のユーザーのハッシュをメモリ（LSASS）やローカル（SAM）からダンプできます。

この書籍には [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) に関する完全なページと、[**checklist**](../checklist-windows-privilege-escalation.md) があります。また [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) の使用も忘れないでください。

### Current Session Tickets

現在のユーザーに予期しないリソースへのアクセス権を与えるような **tickets** が見つかる可能性は非常に **低い** ですが、次の点を確認することはできます：
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

If you have managed to enumerate the active directory you will have **more emails and a better understanding of the network**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

基本的な資格情報を入手したら、AD 内で共有されている**興味深いファイルを見つけられないか**を確認すべきです。手作業でも可能ですが、非常に退屈で反復的な作業になります（数百のドキュメントを確認する必要がある場合はさらに大変です）。

[**使用できるツールについてはこちらを参照してください。**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

他のPCや共有に**アクセスできる**場合、アクセスされるとあなたに対してNTLM認証を**引き起こす**ようなファイル（例えば SCF ファイル）を**配置**して、**NTLM challenge** を盗み出して解析することができます:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

この脆弱性により、認証済みの任意のユーザーが**ドメインコントローラーを侵害できました**。


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**For the following techniques a regular domain user is not enough, you need some special privileges/credentials to perform these attacks.**

### Hash extraction

幸いにも、[AsRepRoast](asreproast.md)、[Password Spraying](password-spraying.md)、[Kerberoast](kerberoast.md)、[Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)（リレーを含む）、[EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)、[escalating privileges locally](../windows-local-privilege-escalation/index.html)などを使って**いくつかのローカル管理者アカウントを侵害できている**ことを期待します。\
その後、メモリ上およびローカルにあるすべてのハッシュをダンプする時です。\
[**ハッシュを取得するさまざまな方法についてはこちらを読んでください。**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

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

ローカル管理者の**ハッシュ**または**パスワード**を入手している場合は、それを使って他の**PC**に**ローカルログイン**を試みてください。
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> これはかなり**ノイジー**であり、**LAPS**で**緩和**できる点に注意してください。

### MSSQL Abuse & Trusted Links

ユーザーが**MSSQL インスタンスにアクセス**する権限を持っている場合、MSSQL ホスト上で（SA として実行されていれば）**コマンドを実行**したり、NetNTLM の **hash** を**盗む**、あるいは **relay attack** を行うことが可能です。\
また、ある MSSQL インスタンスが別の MSSQL インスタンスから信頼（database link）されている場合、ユーザーが信頼されたデータベース上の権限を持っていれば、**信頼関係を利用して別インスタンスでもクエリを実行する**ことができます。これらの信頼は連鎖する可能性があり、最終的にコマンド実行可能な誤設定されたデータベースを見つけることがありえます。\
**データベース間のリンクはフォレストトラストを跨いでも機能します。**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

サードパーティのインベントリ/デプロイメントスイートは、しばしば資格情報やコード実行への強力な経路を露出します。参照：

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

属性 [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) を持つ Computer オブジェクトを見つけ、かつそのコンピュータ上でドメイン権限を持っている場合、当該コンピュータにログインするすべてのユーザーの TGT をメモリからダンプすることができます。\
したがって、**Domain Admin がそのコンピュータにログイン**した場合、その TGT をダンプして [Pass the Ticket](pass-the-ticket.md) を使って権限を偽装できます。\
constrained delegation により、**プリントサーバーを自動的に乗っ取る**（運が良ければそれが DC である）ことさえ可能です。


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

ユーザーやコンピュータが "Constrained Delegation" を許可されていると、**あるコンピュータ上の特定サービスに対して任意のユーザーを偽装してアクセス**することが可能になります。\
そのため、このユーザー/コンピュータの **hash を奪取**すれば、（Domain Admin を含む）**任意のユーザーを偽装してサービスにアクセス**できます。


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

リモートコンピュータの Active Directory オブジェクトに対して **WRITE** 権限があると、**昇格権限でのコード実行**を達成できる可能性があります：


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

侵害したユーザーが一部のドメインオブジェクトに対して**興味深い権限**を持っている場合、それにより**横展開や権限昇格**が可能になることがあります。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

ドメイン内で **Spool サービスがリッスンしている**ことを発見すると、これを**悪用して新たな資格情報を取得**したり、**権限昇格**を行ったりできます。


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

**他のユーザーが侵害されたマシンにアクセス**している場合、メモリから資格情報を**収集**したり、彼らのプロセスにビーコンを**インジェクト**して偽装することが可能です。\
通常ユーザーは RDP でシステムにアクセスするため、第三者の RDP セッションに対するいくつかの攻撃手法は次の通りです：


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** はドメイン参加コンピュータの**ローカル Administrator パスワード**を管理するシステムで、それらを**ランダム化・一意化・頻繁に変更**します。これらのパスワードは Active Directory に保存され、ACL によって許可されたユーザーのみがアクセスできます。これらのパスワードにアクセスできる十分な権限があれば、他のコンピュータへのピボットが可能になります。


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

侵害したマシンから**証明書を収集**することは、環境内での権限昇格手段になり得ます：


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

脆弱なテンプレートが設定されている場合、それを悪用して権限昇格することが可能です：


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

一度 **Domain Admin**、あるいはさらに **Enterprise Admin** の権限を得たら、ドメインデータベースである _ntds.dit_ を**ダンプ**できます。

[**DCSync attack に関する詳細はここにあります**](dcsync.md)。

[**NTDS.dit の盗み方に関する詳細はここにあります**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

前述のいくつかの手法は、永続化にも利用できます。\
例えば、次のようなことが可能です：

- ユーザーを [**Kerberoast**](kerberoast.md) に**脆弱**にする

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- ユーザーを [**ASREPRoast**](asreproast.md) に**脆弱**にする

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- ユーザーに [**DCSync**](#dcsync) 権限を付与する

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Silver Ticket attack** は、特定サービス向けの**正当な TGS チケット**を（例えば PC アカウントの）**NTLM hash** を使って作成し、そのサービスの権限へアクセスする手法です。


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** は、Active Directory 環境で **krbtgt アカウントの NTLM hash** を入手することで行われます。このアカウントはすべての **TGT** を署名するために使われる特別なアカウントです。

攻撃者がこのハッシュを取得すると、任意のアカウントの **TGT を生成**でき（Silver ticket attack と同様）、ネットワーク内での認証を偽装できます。


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

golden ticket に似ていますが、**一般的な golden ticket 検出メカニズムを回避するように加工された**チケットです。


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

アカウントの**証明書を保持している、あるいは要求できる**ことは、パスワードが変更されてもそのアカウントに**永続的にアクセス**する非常に有効な方法です：


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**証明書を用いることでドメイン内で高権限を維持する**ことも可能です：


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory の **AdminSDHolder** オブジェクトは、Domain Admins や Enterprise Admins のような**特権グループ**のセキュリティを保つために、標準の ACL を適用してこれらのグループへの不正な変更を防ぎます。しかし、この機能は悪用されることがあり、攻撃者が AdminSDHolder の ACL を変更して通常ユーザーにフルアクセスを与えると、そのユーザーはすべての特権グループに対する広範な制御を得てしまいます。保護を意図したこの仕組みが、監視されていないと逆に不正アクセスを許す原因になります。

[**AdminDSHolder Group に関する詳細はこちら。**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

すべての **Domain Controller (DC)** にはローカルの管理者アカウントが存在します。そのようなマシンで管理者権限を取得すると、mimikatz を使ってローカル Administrator のハッシュを抽出できます。その後、レジストリの変更によりそのパスワードの利用を有効化し、ローカル Administrator アカウントへのリモートアクセスを可能にします。


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

特定のドメインオブジェクトに対してユーザーに**特別な権限**を与えることで、その後にそのユーザーが**権限を昇格**できるようにすることができます。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**security descriptors** はオブジェクトが持つ**権限**を保持するために使われます。オブジェクトの security descriptor に**小さな変更**を加えるだけで、特権グループに属していなくてもそのオブジェクトに対して非常に強力な権限を取得できる場合があります。


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

メモリ内の **LSASS** を改変して**全アカウント共通のパスワード（universal password）**を設定し、全ドメインアカウントへのアクセスを得ます。


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[SSP (Security Support Provider) が何かはこちらを参照。](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
独自の **SSP** を作成して、マシンへのアクセスに使用される資格情報を**平文でキャプチャ**することができます。


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

AD に **新しい Domain Controller を登録**し、それを使って指定オブジェクトに対して（SIDHistory, SPNs... など）属性を **ログを残さずに push** します。DA 権限が必要で、ルートドメイン内で実行する必要があります。\
ただし誤ったデータを使うと派手なログが残る点に注意してください。


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

前述したように、**LAPS パスワードを読む十分な権限**があると権限昇格できますが、これらのパスワードは**永続化**にも利用可能です。\
参照：


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft は **Forest** をセキュリティ境界と見なしています。つまり **単一ドメインの侵害がフォレスト全体の侵害につながる可能性がある**ということです。

### Basic Information

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) は、ある **ドメイン** のユーザーが別の **ドメイン** のリソースへアクセスすることを可能にするセキュリティ機構です。ドメイン間の認証システムを連結し、認証情報のやり取りを可能にします。ドメインが信頼を設定すると、両ドメインの Domain Controller (DC) にその信頼の整合性を保つための特定の **キー** が交換・保持されます。

典型的なシナリオでは、ユーザーが**信頼されたドメイン**のサービスへアクセスするには、まず自身のドメインの DC から **inter-realm TGT** を要求する必要があります。この TGT は両ドメインで共有される **trust key** で暗号化されます。ユーザーはこの inter-realm TGT を信頼先ドメインの DC に提出して TGS を取得します。信頼先の DC が inter-realm TGT を検証すると、対象サービスのための TGS を発行してアクセスを許可します。

**手順**:

1. **Domain 1** のクライアントコンピュータが、その **NTLM hash** を使用して **Ticket Granting Ticket (TGT)** をその **Domain Controller (DC1)** に要求する。
2. クライアントが認証されると DC1 は新しい TGT を発行する。
3. クライアントは **Domain 2** のリソースにアクセスするために DC1 から **inter-realm TGT** を要求する。
4. inter-realm TGT は、2-way domain trust の一部として DC1 と DC2 が共有する **trust key** で暗号化される。
5. クライアントは inter-realm TGT を **Domain 2 の Domain Controller (DC2)** に持っていく。
6. DC2 は共有された trust key を使って inter-realm TGT を検証し、有効であればクライアントがアクセスしようとする Domain 2 内のサーバ向けに **Ticket Granting Service (TGS)** を発行する。
7. 最後にクライアントはこの TGS をサーバに提示し、サーバのアカウントハッシュで暗号化されたそれによって Domain 2 のサービスへアクセスする。

### Different trusts

信頼は **一方向（1 way）か双方向（2 ways）** になり得る点に注意してください。双方向の場合は両ドメインが互いを信頼しますが、**一方通行**の場合は片方が **trusted**、もう片方が **trusting** になります。この場合、**trusted 側からは trusting ドメイン内のリソースにしかアクセスできません**。

もし Domain A が Domain B を信頼しているなら、A が trusting domain、B が trusted domain です。さらに、**Domain A** ではこれは **Outbound trust** になり、**Domain B** では **Inbound trust** になります。

**異なる信頼関係の種類**

- **Parent-Child Trusts**: 同一フォレスト内でよくある構成で、子ドメインは親ドメインと自動的に two-way transitive trust を持ちます。認証要求は親と子の間で透過的に流れます。
- **Cross-link Trusts**: "shortcut trusts" とも呼ばれ、子ドメイン間の参照を高速化するために設定されます。大規模なフォレストでは認証参照がフォレストルートまで上がってから目的ドメインへ降りる必要があり、cross-link によってその経路が短縮されます。
- **External Trusts**: 無関係な別ドメイン間で設定される非推移的な信頼です。Microsoft のドキュメントによれば、external trusts はフォレストトラストで接続されていない外部ドメインのリソースにアクセスする際に有用で、SID フィルタリングによってセキュリティが強化されます。
- **Tree-root Trusts**: フォレストルートドメインと新しく追加されたツリールート間に自動的に確立される信頼です。新しいドメインツリーをフォレストに追加する際に重要で、二方向の推移性を保持します。
- **Forest Trusts**: 二つのフォレストルートドメイン間の two-way transitive trust で、SID フィルタリングも強制されセキュリティを高めます。
- **MIT Trusts**: 非 Windows の、[RFC4120 準拠](https://tools.ietf.org/html/rfc4120) の Kerberos ドメインと確立される信頼です。Windows 以外の Kerberos ベースのシステムと統合する環境向けの専門的な信頼です。

#### Other differences in **trusting relationships**

- 信頼関係は **transitive（推移的）**（A が B を信頼し、B が C を信頼すると A は C を信頼する）または **non-transitive（非推移的）** に設定できます。
- 信頼関係は **bidirectional trust（双方信頼）**（互いに信頼）または **one-way trust（一方向信頼）**（一方のみが他方を信頼）として設定できます。

### Attack Path

1. 信頼関係を**列挙**する
2. いずれかの **security principal**（user/group/computer）が**他ドメインのリソースにアクセス**できるかを確認する。ACE エントリや他ドメインのグループに含まれているかを調べ、**ドメイン間の関係性**を探す（多くの場合信頼はこれを目的に作成されている）。
1. この場合、kerberoast も別のオプションになり得る。
3. ドメイン間を**ピボット**できるアカウントを**侵害**する。

攻撃者が別ドメインのリソースにアクセスする手段は主に次の3つです：

- **Local Group Membership**: プリンシパルがサーバの "Administrators" グループなどローカルグループに追加されると、そのマシンに対して強力な制御権を得られます。
- **Foreign Domain Group Membership**: プリンシパルが外部ドメイン内のグループのメンバーである場合。ただしこの方法の有効性は信頼の性質やグループのスコープに依存します。
- **Access Control Lists (ACLs)**: プリンシパルが **ACL**、特に **DACL** 内の **ACE** として指定されている場合、特定のリソースへのアクセスが与えられます。ACL、DACL、ACE の仕組みに深く踏み込むには、ホワイトペーパー “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” が有用です。

### Find external users/groups with permissions

ドメイン内の foreign security principals を見つけるには、**`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** を確認できます。これらは **外部ドメイン/フォレスト** の user/group です。

これを Bloodhound や powerview を使って確認できます：
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
> 信頼されたキーが**2つ**あります。1つは _Child --> Parent_ 用、もう1つは _Parent_ --> _Child_ 用です。\
> 現在のドメインで使用されているキーを確認するには、次を実行します:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

信頼関係を悪用して SID-History injection により child/parent ドメインで Enterprise admin として権限昇格します:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Configuration Naming Context (NC) がどのように悪用され得るかを理解することは重要です。Configuration NC は Active Directory (AD) 環境のフォレスト全体の設定データを格納する中央リポジトリとして機能します。このデータはフォレスト内のすべての Domain Controller (DC) に複製され、書き込み可能な DC は Configuration NC の書き込み可能なコピーを保持します。これを悪用するには、**DC 上で SYSTEM 特権** を持っている必要があり、できれば child DC が望ましいです。

**Link GPO to root DC site**

Configuration NC の Sites コンテナには、AD フォレスト内のドメイン参加コンピュータのサイト情報が含まれます。任意の DC 上で SYSTEM 特権を持っていれば、GPO を root DC site にリンクすることができます。これにより、これらのサイトに適用されるポリシーを操作して root domain を危殆化させる可能性があります。

詳細は、[Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research) の研究を参照してください。

**Compromise any gMSA in the forest**

攻撃ベクターとして、ドメイン内の特権 gMSA を標的にする方法があります。gMSA のパスワード計算に必要な KDS Root key は Configuration NC に保存されています。任意の DC 上で SYSTEM 特権を持っていれば、KDS Root key にアクセスしてフォレスト内の任意の gMSA のパスワードを計算することが可能です。

詳細な解析と手順は以下を参照してください:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

補完的な delegated MSA 攻撃（BadSuccessor – migration attributes の悪用）:


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

追加の外部研究: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent)。

**Schema change attack**

この手法は、新しく作成される特権 AD オブジェクトを待つ必要があるため忍耐が必要です。SYSTEM 特権を持っていれば、AD スキーマを変更して任意のユーザにすべてのクラスに対する完全な制御権を付与することができます。これにより、新しく作成された AD オブジェクトに対して不正なアクセスや制御が可能になります。

詳しくは [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent) を参照してください。

**From DA to EA with ADCS ESC5**

ADCS ESC5 脆弱性は PKI オブジェクトを制御して、フォレスト内の任意ユーザとして認証可能な証明書テンプレートを作成することを狙ったものです。PKI オブジェクトは Configuration NC に存在するため、書き込み可能な child DC を奪取すれば ESC5 攻撃を実行できます。

詳細は [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c) を参照してください。ADCS が存在しない場合でも、攻撃者は必要なコンポーネントをセットアップできるため、[Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) も参照してください。

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
このシナリオでは、**あなたのドメインは外部ドメインによって信頼されており**、それに対して**不明な権限**が付与されています。あなたは、**自ドメインのどのプリンシパルが外部ドメインに対してどのようなアクセス権を持っているか**を特定し、それを悪用しようと試みる必要があります：

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
このシナリオでは **あなたのドメイン** が **別のドメイン** からのプリンシパルに対していくつかの **権限** を **信頼** しています。

しかし、信頼するドメインによって **domain is trusted** が行われると、trusted domain は **予測可能な名前のユーザ** を作成し、その **パスワード** として **trusted password** を使用します。つまり、**trusting domain のユーザにアクセスして trusted domain に侵入**し、列挙やさらなる権限昇格を試みることが可能になる、ということです：


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

他の方法としては、ドメイントラストの**逆方向**に作成された[**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links)（あまり一般的ではありません）を見つけることで trusted domain を侵害する方法があります。

また別の方法として、trusted domain の **ユーザがアクセスできる** マシン上に待機して、そのユーザが **RDP** でログインするのを待つ方法があります。その場合、攻撃者は RDP セッションのプロセスにコードを注入し、そこから **被害者の元のドメインにアクセス** することができます。\
さらに、もし **被害者が自分のハードドライブをマウントしていた** 場合、攻撃者は **RDP セッション** のプロセスからハードドライブの **スタートアップフォルダ** に **backdoors** を置くことができます。この手法は **RDPInception** と呼ばれます。


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### ドメイン信頼の悪用に対する緩和策

### **SID Filtering:**

- SID history 属性を悪用した攻撃のリスクは、SID Filtering によって緩和されており、これはすべてのフォレスト間トラストでデフォルトで有効になっています。これは、Microsoft の考え方に従い、セキュリティ境界をドメインではなくフォレストとして扱う前提に基づいています。
- ただし注意点として、SID filtering はアプリケーションやユーザのアクセスを妨げる可能性があり、そのため無効化されることがある点に留意してください。

### **Selective Authentication:**

- フォレスト間トラストでは、Selective Authentication を利用することで、両フォレストのユーザが自動的に認証されないようにできます。代わりに、trusting domain/forest 内のドメインやサーバにアクセスするためには明示的な権限が必要となります。
- ただし、これらの対策は writable Configuration Naming Context (NC) の悪用や trust account に対する攻撃からは保護しない点に注意が必要です。

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## 一般的な防御策

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Domain Admins は Domain Controllers にのみログインを許可し、他のホストでの使用を避けることが推奨されます。
- **Service Account Privileges**: サービスは Domain Admin (DA) 権限で実行すべきではありません。
- **Temporal Privilege Limitation**: DA 権限が必要なタスクについてはその期間を制限するべきです。例： `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementing Deception Techniques**

- ディセプションの実装は罠（例：パスワード期限切れなし、Trusted for Delegation に設定されたダミーユーザやコンピュータ）を仕掛けることを含みます。具体的には特定の権利を持つユーザを作成したり、高権限グループに追加したりします。
- 実例として次のようなツールを使用します： `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- ディセプション技術の展開については [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception) を参照してください。

### **Identifying Deception**

- **For User Objects**: 疑わしい指標には、異常な ObjectSID、低頻度のログオン、作成日、不自然に少ない bad password count などがあります。
- **General Indicators**: 潜在的なダミーオブジェクトの属性を実在オブジェクトと比較することで不整合を明らかにできます。ツールとして [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) などが役立ちます。

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: ATA 検出を回避するために Domain Controllers 上でのセッション列挙を避ける。
- **Ticket Impersonation**: チケット作成に **aes** キーを利用することで NTLM にダウングレードせずに検出を回避するのに役立ちます。
- **DCSync Attacks**: Domain Controller 以外から実行することで ATA 検出を回避することが推奨されます。Domain Controller から直接実行するとアラートが発生します。

## 参考

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

{{#include ../../banners/hacktricks-training.md}}
