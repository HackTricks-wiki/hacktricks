# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Basic overview

**Active Directory** は、ネットワーク内で **domains**, **users**, **objects** を効率的に作成・管理するための基盤技術です。大規模にスケールするよう設計されており、多数のユーザを管理可能な **groups** や **subgroups** に整理し、さまざまなレベルでの **access rights** を制御できます。

**Active Directory** の構造は主に三つのレイヤーで構成されています: **domains**, **trees**, **forests**。**domain** は共通のデータベースを共有する **users** や **devices** といったオブジェクトの集合を含みます。**trees** は共通の構造で結ばれたこれらのドメインのグループであり、**forest** は複数の trees をまとめたもので、**trust relationships** を通じて相互に接続され、組織構造の最上位を形成します。各レベルで特定の **access** や **communication rights** を指定できます。

**Active Directory** の主要な概念は以下の通りです:

1. **Directory** – Active Directory オブジェクトに関するすべての情報を格納します。
2. **Object** – directory 内の実体を指し、**users**, **groups**, **shared folders** などが含まれます。
3. **Domain** – ディレクトリオブジェクトのコンテナとして機能し、複数のドメインが **forest** 内で共存し、それぞれが独自のオブジェクト集合を保持できます。
4. **Tree** – 共通の root domain を共有するドメインのグループです。
5. **Forest** – Active Directory の組織構造の最上位で、複数の trees で構成され、それらの間に **trust relationships** が存在します。

**Active Directory Domain Services (AD DS)** は、ネットワーク内の集中管理と通信に不可欠な一連のサービスを包含します。これらのサービスには次のものが含まれます:

1. **Domain Services** – データの集中管理を行い、**users** と **domains** 間の相互作用（**authentication** や **search** 機能を含む）を管理します。
2. **Certificate Services** – 安全な **digital certificates** の作成、配布、管理を担当します。
3. **Lightweight Directory Services** – **LDAP protocol** を通じてディレクトリ対応アプリケーションをサポートします。
4. **Directory Federation Services** – 複数の web アプリケーションに対して **single-sign-on** を提供し、単一セッションでの認証を可能にします。
5. **Rights Management** – 著作物の不正配布や使用を制限することで保護を支援します。
6. **DNS Service** – **domain names** の解決に不可欠です。

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

To learn how to **attack an AD** you need to **understand** really good the **Kerberos authentication process**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

You can take a lot to [https://wadcoms.github.io/](https://wadcoms.github.io) to have a quick view of which commands you can run to enumerate/exploit an AD.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

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

ネットワーク内でこのようなサーバーを見つけた場合、そのサーバーに対して**user enumeration**を実行することもできます。例えば、[**MailSniper**](https://github.com/dafthack/MailSniper)というツールを使用できます：
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

OK、すでに有効なユーザー名を把握していてパスワードがない場合は、次を試してください:

- [**ASREPRoast**](asreproast.md): If a user **doesn't have** the attribute _DONT_REQ_PREAUTH_ you can **request a AS_REP message** for that user that will contain some data encrypted by a derivation of the password of the user.
- [**Password Spraying**](password-spraying.md): 最も**一般的なパスワード**を発見した各ユーザーに対して試してみてください。もしかすると誰かが弱いパスワードを使っているかもしれません（パスワードポリシーに注意してください）。
- Note that you can also **spray OWA servers** to try to get access to the users mail servers.

{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

ネットワークのいくつかのプロトコルを**poisoning**することで、クラッキング可能なチャレンジ**hashes**を**取得**できる可能性があります:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Active Directory を列挙できていれば、**より多くのメールアドレスやネットワークの理解**が得られます。NTLM の [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) を強制して AD 環境へアクセスできる可能性があります。

### Steal NTLM Creds

もし **null や guest ユーザー**で他の PC や共有に**アクセス**できるなら、SCF ファイルのようなファイルを**配置**して、誰かがそれにアクセスしたときにあなたに対して **NTLM 認証をトリガー**させ、**NTLM チャレンジ**を盗んでクラッキングする、ということが可能です:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Enumerating Active Directory WITH credentials/session

このフェーズでは、**有効なドメインアカウントの認証情報またはセッションを奪取していること**が必要です。もし有効な認証情報やドメインユーザーとしてのシェルを持っているなら、前述のオプションは他ユーザーを侵害するための手段として依然有効であることを覚えておいてください。

認証付き列挙を開始する前に、**Kerberos double hop problem** を理解しておくべきです。


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

アカウントを奪取することは、ドメイン全体を侵害するための**大きな一歩**です。これにより **Active Directory Enumeration** を開始できます:

[**ASREPRoast**](asreproast.md) に関しては、今や全ての潜在的に脆弱なユーザーを見つけられますし、[**Password Spraying**](password-spraying.md) に関しては、**すべてのユーザー名のリスト**を得て、奪取したアカウントのパスワード、空パスワード、あるいは有望な新しいパスワードを試すことができます。

- You could use the [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- You can also use [**powershell for recon**](../basic-powershell-for-pentesters/index.html) which will be stealthier
- You can also [**use powerview**](../basic-powershell-for-pentesters/powerview.md) to extract more detailed information
- Another amazing tool for recon in an active directory is [**BloodHound**](bloodhound.md). It is **not very stealthy** (depending on the collection methods you use), but **if you don't care** about that, you should totally give it a try. Find where users can RDP, find path to other groups, etc.
- **Other automated AD enumeration tools are:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) as they might contain interesting information.
- GUI を持つディレクトリ列挙用ツールとしては **SysInternal** スイートの **AdExplorer.exe** が使えます。
- LDAP データベースを **ldapsearch** で検索し、_userPassword_ や _unixUserPassword_ のフィールド、または _Description_ に認証情報がないか探せます。その他の方法は cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) を参照してください。
- **Linux** を使っている場合は [**pywerview**](https://github.com/the-useless-one/pywerview) でドメインを列挙することもできます。
- 次の自動化ツールも試してみてください:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

Windows ではドメインの全ユーザー名を取得するのは非常に簡単です（`net user /domain`、`Get-DomainUser`、または `wmic useraccount get name,sid`）。Linux では `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` や `enum4linux -a -u "user" -p "password" <DC IP>` を使用できます。

> たとえこの Enumeration セクションが短く見えても、これは最も重要な部分です。リンク（主に cmd、powershell、powerview、BloodHound のもの）にアクセスして、ドメインの列挙方法を学び、十分に慣れるまで練習してください。評価中は、ここが DA に到達する道を見つけるか、何もできないと判断する重要な瞬間になります。

### Kerberoast

Kerberoasting は、サービスに紐付いたユーザーアカウントが使う **TGS tickets** を取得し、その暗号（ユーザーパスワードに基づく）をオフラインでクラッキングする手法です。

詳細は以下を参照:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

認証情報を入手したら、任意の **machine** にアクセスできるか確認してください。そのために、CrackMapExec を使用してポートスキャン結果に基づき複数のサーバーへ異なるプロトコルで接続を試みることができます。

### Local Privilege Escalation

通常のドメインユーザーとして認証情報やセッションを奪取し、かつドメイン内の任意の **machine** へそのユーザーで**アクセス**できる場合は、まずローカルでの権限昇格と認証情報の収集を試みるべきです。ローカル管理者権限を得ることで、LSASS のメモリやローカル SAM などから他ユーザーのハッシュを**ダンプ**できるようになります。

本書には [**Windows のローカル権限昇格**](../windows-local-privilege-escalation/index.html) に関する完全なページと、[**チェックリスト**](../checklist-windows-privilege-escalation.md) があります。また、[**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) の使用も忘れないでください。

### Current Session Tickets

現在のユーザーに予期せぬリソースへアクセスする権限を与える**チケット**が見つかる可能性は非常に**低い**ですが、確認は可能です:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

active directory を列挙できれば、**より多くのメールアドレスとネットワークの理解**が得られます。NTLM の [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

基本的な資格情報を持っているなら、AD 内で共有されている**興味深いファイル**がないか**確認**すべきです。手動で調べることもできますが、非常に退屈で反復的な作業です（チェックすべきドキュメントが何百もあればなおさらです）。

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

もし**他の PCs や shares にアクセスできる**なら、**ファイルを配置**（例: SCF file）して、誰かがアクセスしたときに**あなたに対して NTLM 認証がトリガーされる**ようにし、**NTLM challenge** を**盗んで**クラックすることができます：

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

この脆弱性により、認証済みユーザーであれば誰でも**domain controller を侵害**できました。

{{#ref}}
printnightmare.md
{{#endref}}

## Active Directory での権限昇格（privileged credentials/session 必須）

**以下の手法では通常のドメインユーザーでは不十分で、これらの攻撃を実行するには特別な権限/資格情報が必要です。**

### Hash extraction

幸いにも [AsRepRoast](asreproast.md)、[Password Spraying](password-spraying.md)、[Kerberoast](kerberoast.md)、[Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)（リレーを含む）、[EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md）、[escalating privileges locally](../windows-local-privilege-escalation/index.html) 等を使って**ローカル管理者アカウントを侵害**できているかもしれません。\
その後、メモリおよびローカルからハッシュをすべてダンプする時です。\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**ユーザーの hash を入手したら**、それを使って**そのユーザーになりすます**ことができます。\
そのためには、当該 **hash を使って NTLM 認証を行う**ような**ツール**を使うか、新しい **sessionlogon** を作成してその **hash を LSASS に注入**し、以後の **NTLM 認証が実行される際にその hash が使用される**ようにする方法があります。最後の方法が mimikatz のやり方です。\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

この攻撃は、ユーザーの NTLM hash を使って Kerberos チケットを要求することを目的としています。これは NTLM プロトコル上での一般的な Pass The Hash の代替手段であり、NTLM が無効化され Kerberos のみが認証に許可されているネットワークで特に**有用**です。

{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Pass The Ticket (PTT) 攻撃では、攻撃者はパスワードやハッシュの代わりにユーザーの**認証チケットを盗み**ます。盗まれたチケットはユーザーに**成りすます**ために使用され、ネットワーク内のリソースやサービスへの不正アクセスを可能にします。

{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

local administrator の **hash** または **password** を持っている場合は、それを使って他の **PCs** に**ローカルログイン**してみてください。
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> これはかなり**ノイズが多い**点に注意してください。**LAPS**はこれを**軽減**します。

### MSSQL Abuse & Trusted Links

ユーザーが**MSSQL instances にアクセスする**権限を持っている場合、MSSQL ホスト上で（SA として動作していれば）**コマンドを実行する**、NetNTLM **hash を盗む**、あるいは**relay attack を実行する**ことが可能になります。\
また、ある MSSQL インスタンスが別の MSSQL インスタンスから信頼（database link）されている場合、もしユーザーが信頼されたデータベースに対する権限を持っていれば、**信頼関係を利用して他のインスタンスでもクエリを実行できる**ようになります。これらの信頼は連鎖することがあり、最終的にコマンドを実行できるようにミスコンフィグされたデータベースを見つけられるかもしれません。\
**データベース間のリンクはフォレストトラストを越えても機能します。**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

サードパーティ製のインベントリやデプロイメントスイートは、資格情報やコード実行への強力な経路を露出することがよくあります。参照:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

属性 [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) を持つ Computer オブジェクトを見つけ、かつそのコンピュータ上でドメイン権限を持っている場合、そのコンピュータにログオンするすべてのユーザーのメモリから TGT をダンプすることができます。\
したがって、**Domain Admin がそのコンピュータにログオンした場合**、その TGT をダンプして [Pass the Ticket](pass-the-ticket.md) を用いてなりすますことができます。\
constrained delegation を利用すれば、**プリントサーバーを自動的に乗っ取る**（運良く DC であれば）ことさえ可能です。


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

ユーザーやコンピュータが "Constrained Delegation" を許可されている場合、そのユーザー/コンピュータは**特定のコンピュータ上のサービスに対して任意のユーザーを偽装してアクセスできる**ようになります。\
そのため、このユーザー/コンピュータのハッシュを**奪取**すると、（Domain Admin を含む）**任意のユーザーを偽装してサービスにアクセスできる**ようになります。


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

リモートコンピュータの Active Directory オブジェクトに対する **WRITE** 権限を持っていると、**昇格した権限でのコード実行**を得ることが可能になります：


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

侵害されたユーザーは、後で横移動や権限昇格を行えるような**ドメインオブジェクトに対する興味深い特権**を持っている場合があります。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

ドメイン内で**Spool サービスが待ち受けている**ことを発見すると、これを**悪用して新しい資格情報を取得**したり**権限を昇格**させたりすることができます。


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

**他のユーザー**が**侵害された**マシンに**アクセス**している場合、メモリから資格情報を**収集**したり、彼らのプロセスにビーコンを**インジェクト**してなりすますことが可能です。\
通常ユーザーは RDP 経由でシステムにアクセスするため、ここでは第三者の RDP セッションに対するいくつかの攻撃方法を示します:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** はドメイン参加コンピュータの **ローカル Administrator パスワード** を管理するためのシステムで、パスワードを**ランダム化**し一意にし、頻繁に**変更**します。これらのパスワードは Active Directory に保存され、アクセスは ACL によって認可ユーザーのみに制御されます。これらのパスワードにアクセスする十分な権限があれば、他のコンピュータへピボットすることが可能になります。


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

侵害したマシンから**証明書を収集する**ことは、環境内で権限を昇格させる手段となり得ます：


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

**脆弱なテンプレート**が設定されている場合、それらを悪用して権限を昇格させることが可能です：


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

一度 **Domain Admin**、あるいはさらに良く **Enterprise Admin** の権限を得たら、ドメインデータベース _ntds.dit_ を**ダンプ**することができます。

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

前述したいくつかの手法は、パーシステンスに利用できます。\
例えば以下のようなことが可能です:

- ユーザーを [**Kerberoast**](kerberoast.md) に脆弱にする

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- ユーザーを [**ASREPRoast**](asreproast.md) に脆弱にする

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- ユーザーに [**DCSync**](#dcsync) 権限を付与する

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Silver Ticket attack** は、特定のサービス用の正当な Ticket Granting Service (TGS) チケットを、（例えば PC アカウントの）**NTLM hash** を使用して作成し、サービス権限へアクセスするために用いられます。


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** は、Active Directory 環境で **krbtgt アカウントの NTLM hash** を攻撃者が取得することを伴います。このアカウントはすべての **Ticket Granting Ticket (TGT)** に署名するために使われる特別な存在です。

攻撃者がこの hash を手に入れると、任意のアカウント用に **TGT** を生成できるようになります（Silver ticket attack と組み合わせ可能です）。


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

これらは、一般的な golden tickets 検知メカニズムを**回避する**ように偽造された golden ticket のようなものです。


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

アカウントの **証明書を所持すること、またはそれを要求できること** は、（ユーザーがパスワードを変更しても）そのアカウントにパーシステンスを持つ非常に良い方法です：


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**証明書を使用することで、ドメイン内で高い特権を持ったままパーシステンスを維持する**ことも可能です：


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory の **AdminSDHolder** オブジェクトは、Domain Admins や Enterprise Admins のような**特権グループ**のセキュリティを確保するため、これらのグループに標準の **ACL** を適用して不正な変更を防ぎます。しかしこの機能は悪用され得ます。攻撃者が AdminSDHolder の ACL を変更して通常ユーザーにフルアクセスを与えると、そのユーザーはすべての特権グループを広範に制御できるようになります。この保護機能は注意深く監視されていなければ、逆に不正アクセスを許してしまう可能性があります。

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

すべての **Domain Controller (DC)** にはローカル管理者アカウントが存在します。そうしたマシンで管理者権限を取得すると、mimikatz を使ってローカル Administrator のハッシュを抽出できます。その後、レジストリを変更して**このパスワードの使用を可能にする**必要があり、これによりリモートからローカル Administrator アカウントへアクセスできます。


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

特定のドメインオブジェクトに対して、将来的に権限を昇格させることができるような**特別な権限**をユーザーに**付与する**ことができます。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** はオブジェクトが持つ**権限**を**格納**するために使用されます。オブジェクトのセキュリティディスクリプタに**少しの変更**を加えるだけで、特権グループに属していなくてもそのオブジェクトに対して非常に興味深い権限を得ることができます。


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

LSASS のメモリを改変して**全アカウントに共通のパスワード**を設定し、すべてのドメインアカウントへアクセス可能にします。


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
独自の **SSP** を作成して、マシンへアクセスする際に使われる **資格情報を平文でキャプチャする**ことができます。


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

新しい Domain Controller を AD に登録し、それを使って指定したオブジェクトに対して（SIDHistory、SPNs などの）属性を **ログを残さずに**プッシュします。これを行うには DA 権限が必要で、ルートドメイン内にいる必要があります。\
ただし、間違ったデータを使うと、かなり不自然なログが出るので注意してください。


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

前述の通り、**LAPS パスワードを読む十分な権限**があれば権限を昇格できますが、これらのパスワードは **パーシステンスを維持する**ためにも利用できます。\
参照:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft は **Forest** をセキュリティ境界と見なしています。つまり **単一のドメインを侵害することでフォレスト全体が侵害される可能性がある**ということです。

### Basic Information

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) は、ある **ドメイン** のユーザーが別の **ドメイン** のリソースにアクセスすることを可能にするセキュリティ機構です。これは両ドメイン間の認証システムを連結し、認証情報のやり取りを円滑にします。ドメインがトラストを設定すると、トラストの整合性に重要な特定の **キー** が各ドメインの **Domain Controller (DC)** に交換・保持されます。

典型的なシナリオでは、あるユーザーが **trusted domain** のサービスにアクセスしたい場合、まず自ドメインの DC から特別なチケットである **inter-realm TGT** を要求します。この TGT は両ドメインが合意した共有 **キー** で暗号化されています。ユーザーはこの TGT を **trusted domain の DC** に提示してサービスチケット（**TGS**）を取得します。trusted domain の DC が inter-realm TGT を検証すると、サービスへのアクセスを許可する TGS を発行します。

**ステップ**:

1. **Domain 1** のクライアントコンピュータが自身の **NTLM hash** を使って **Ticket Granting Ticket (TGT)** を **Domain Controller (DC1)** に要求することから開始します。
2. クライアントが認証されると DC1 は新しい TGT を発行します。
3. クライアントは次に **Domain 2** のリソースへアクセスするために DC1 から **inter-realm TGT** を要求します。
4. inter-realm TGT は、双方の二方向ドメイントラストの一部として DC1 と DC2 が共有する **trust key** で暗号化されます。
5. クライアントは inter-realm TGT を **Domain 2 の Domain Controller (DC2)** に持って行きます。
6. DC2 は共有された trust key を使って inter-realm TGT を検証し、有効であればクライアントがアクセスしたい Domain 2 のサーバー向けに **Ticket Granting Service (TGS)** を発行します。
7. 最後にクライアントはこの TGS をサーバー（サーバーのアカウントハッシュで暗号化されている）に提示して、Domain 2 内のサービスへアクセスします。

### Different trusts

トラストは **一方向** または **双方向** のどちらかであることに注意してください。双方向トラストでは両ドメインが相互に信頼しますが、**一方向** の場合は一方が **trusted**、もう一方が **trusting** ドメインになります。この場合、**trusted 側から trusting 側のリソースにのみアクセス可能**です。

もし Domain A が Domain B を信頼しているなら、A が trusting domain、B が trusted domain です。さらに、**Domain A** ではこれは **Outbound trust** になり、**Domain B** では **Inbound trust** になります。

**異なる信頼関係の種類**

- **Parent-Child Trusts**: 同一フォレスト内で一般的な設定で、子ドメインは自動的に親ドメインと双方向の推移的トラストを持ちます。これにより親子間で認証要求がシームレスに流れます。
- **Cross-link Trusts**: 「shortcut trusts」とも呼ばれ、参照プロセスを高速化するために子ドメイン間で設定されます。複雑なフォレストでは認証参照がフォレストルートまで上がりターゲットドメインまで下りる必要があるため、cross-link によってその経路が短縮されます。
- **External Trusts**: 相互に関連のない異なるドメイン間で設定され、非推移的です。Microsoft のドキュメントによると、external trusts はフォレストトラストによって接続されていない外部ドメインのリソースにアクセスする際に有用です。セキュリティは外部トラストにおける SID フィルタリングによって強化されます。
- **Tree-root Trusts**: フォレストルートドメインと新しく追加されたツリールート間で自動的に確立されるトラストです。あまり一般的ではありませんが、フォレストに新しいドメインツリーを追加する際に重要で、二方向の推移性を維持します。
- **Forest Trusts**: これは二つのフォレストルートドメイン間の双方向推移トラストで、SID フィルタリングも適用されセキュリティが強化されます。
- **MIT Trusts**: RFC4120 準拠の Kerberos ドメイン（Windows 以外）との間に確立されるトラストです。MIT trusts は Windows 以外の Kerberos ベースのシステムとの統合を必要とする環境向けのやや専門的なトラストです。

#### Other differences in **trusting relationships**

- トラスト関係は **推移的（transitive）** に設定できる（A が B を信頼し、B が C を信頼していれば A は C を信頼する）場合と、**非推移的** に設定できる場合があります。
- トラスト関係は **双方向**（双方が相互に信頼）または **一方向**（一方のみが他方を信頼）として設定できます。

### Attack Path

1. **信頼関係を列挙**する
2. いずれかの **security principal**（ユーザー/グループ/コンピュータ）が**他ドメインのリソースにアクセスできるか**を確認する。ACE エントリや他ドメインのグループに属しているかを調べ、**ドメイン間の関係**を探す（おそらくトラストはこれらのために作られている）。
1. この場合 kerberoast が別のオプションになり得る。
3. ドメイン間で **ピボットできるアカウントを侵害**する。

別ドメインのリソースにアクセスできる攻撃者は、主に次の3つのメカニズムを通じてそれを行えます:

- **ローカルグループメンバーシップ**: プリンシパルがサーバーの “Administrators” グループのようなローカルグループに追加されている場合、そのマシンに対して大きな制御権を持ちます。
- **外部ドメイングループメンバーシップ**: プリンシパルが外部ドメイン内のグループのメンバーである場合もあります。ただし、この方法の有効性はトラストの性質やグループのスコープに依存します。
- **Access Control Lists (ACLs)**: プリンシパルが **ACL** に指定されている、特に **DACL** 内の **ACE** として指定されている場合、特定のリソースへのアクセス権を得ることができます。ACL、DACL、ACE の詳細に踏み込むには、白書 “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” が非常に有益です。

### Find external users/groups with permissions

ドメイン内の外部セキュリティプリンシパルを見つけるには、**`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** を確認できます。これらは **外部ドメイン/フォレスト** のユーザー/グループです。

これを Bloodhound で確認するか、powerview を使用して確認できます:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Child-to-Parent forest の privilege escalation
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
> **2 trusted keys** が存在します。1つは _Child --> Parent_ 用、もう1つは _Parent_ --> _Child_ 用です。\
> 現在のドメインで使用されているキーを確認するには以下を実行します:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

信頼関係を悪用して SID-History injection により child/parent domain へ Enterprise admin として権限昇格する:

{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Configuration Naming Context (NC) がどのように悪用できるかを理解することは重要です。Configuration NC は Active Directory (AD) 環境のフォレスト全体の設定データの中央リポジトリとして機能します。このデータはフォレスト内のすべての Domain Controller (DC) にレプリケートされ、書き込み可能な DC は Configuration NC の書き込み可能なコピーを保持します。これを悪用するには、**DC 上での SYSTEM 権限**（できれば child DC）が必要です。

**Link GPO to root DC site**

Configuration NC の Sites コンテナには、AD フォレスト内のすべてのドメイン参加コンピュータのサイトに関する情報が含まれています。任意の DC 上で SYSTEM 権限を取得すると、攻撃者は GPO を root DC site にリンクできます。この操作により、これらのサイトに適用されるポリシーを操作して root domain を危険に晒す可能性があります。

詳細については、[Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research) の研究を参照してください。

**Compromise any gMSA in the forest**

攻撃ベクターの一つは、ドメイン内の特権 gMSA を狙うことです。gMSA のパスワード計算に必要な KDS Root key は Configuration NC に格納されています。任意の DC 上で SYSTEM 権限を持っていれば、KDS Root key にアクセスしてフォレスト内の任意の gMSA のパスワードを算出することが可能です。

詳細な解析と手順は以下を参照してください:

{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

補完的な委任された MSA 攻撃（BadSuccessor – migration 属性の悪用）:

{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

追加の外部研究: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent)。

**Schema change attack**

この手法は新たに作成される特権 AD オブジェクトの出現を待つ必要があり、忍耐が必要です。SYSTEM 権限があれば、攻撃者は AD Schema を変更して任意のユーザーにすべてのクラスに対する完全な制御を付与できます。これにより、新たに作成された AD オブジェクトへの不正アクセスや制御が発生する可能性があります。

詳細は [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent) を参照してください。

**From DA to EA with ADCS ESC5**

ADCS ESC5 の脆弱性は、PKI オブジェクトの制御を狙い、フォレスト内の任意のユーザーとして認証できる証明書テンプレートを作成することを目的としています。PKI オブジェクトは Configuration NC に存在するため、書き込み可能な child DC を侵害することで ESC5 攻撃を実行できます。

詳細は [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c) を参照してください。ADCS が存在しないケースでも、攻撃者は必要なコンポーネントを設定することが可能であり、その点は [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) で議論されています。

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
このシナリオでは、**あなたのドメインが外部ドメインから信頼されており**、その外部ドメインに対して**不明な権限**が与えられています。どのプリンシパルが外部ドメインに対してどのアクセスを持っているかを特定し、それを利用して攻撃を試みる必要があります:

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
In this scenario **あなたのドメイン** は **信頼** により **別のドメイン** からの主体にいくつかの **権限 (privileges)** を付与しています。

しかし、**trusting domain** によって **domain is trusted** された場合、trusted domain は **予測可能な名前** を持つ **ユーザーを作成し**、その **パスワードに trusted password を使う** ことがあります。つまり、**trusting domain のユーザーにアクセスして trusted domain 内に入り込み**、列挙やさらなる権限昇格を試みることが可能になるということです:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

別の方法として、trusted domain を侵害する手段は、ドメイントラストの **逆方向** に作成された [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) を見つけることですが、これはあまり一般的ではありません。

また別の方法としては、trusted domain の **ユーザーが RDP でログインできる** マシン上で待ち構えることです。攻撃者は RDP セッションのプロセスにコードを注入し、そこから **被害者の元のドメインにアクセス** することができます。\
さらに、もし **victim が自分のハードドライブをマウントしていた** 場合、攻撃者は **RDP session** プロセスからハードドライブの **startup folder** に **バックドア** を置くことができます。この手法は **RDPInception** と呼ばれます。


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### ドメイントラスト悪用の緩和策

### **SID Filtering:**

- フォレスト間トラストで SID history 属性を悪用する攻撃のリスクは、SID Filtering によって軽減されます。SID Filtering は全てのフォレスト間トラストでデフォルトで有効になっており、Microsoft の見解に基づきセキュリティ境界をドメインではなくフォレストとみなす前提で成り立っています。
- しかし注意点として、SID Filtering はアプリケーションやユーザーアクセスに影響を与える可能性があり、そのため時折無効化されることがあります。

### **Selective Authentication:**

- フォレスト間トラストでは、Selective Authentication を用いることで両フォレストのユーザーが自動的に認証されることを防ぎます。代わりに、trusting domain/forest 内のドメインやサーバーにアクセスするためには明示的な許可が必要になります。
- これらの対策は、書き込み可能な Configuration Naming Context (NC) の悪用やトラストアカウントへの攻撃を防ぐものではない点に注意が必要です。

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## 一般的な防御策

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Domain Admins は Domain Controllers にのみログインを許可し、他のホストで使用しないことが推奨されます。
- **Service Account Privileges**: サービスは Domain Admin (DA) 権限で実行すべきではありません。
- **Temporal Privilege Limitation**: DA 権限を必要とするタスクについては、その期間を制限することが推奨されます。例: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementing Deception Techniques**

- デセプションの実装は、パスワードが期限切れにならない、あるいは Trusted for Delegation にマークされたデコイユーザーやコンピュータのような罠を設定することを含みます。具体的には特定の権限を持つユーザーを作成したり、それらを高権限グループに追加することが含まれます。
- 実用的な例としては次のようなツールを使用します: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- デセプション手法の導入については [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception) を参照してください。

### **Identifying Deception**

- **ユーザーオブジェクトに関して**: 異常な ObjectSID、ログオン頻度の低さ、作成日時、誤パスワードのカウントが少ないなどが疑わしい指標です。
- **一般的な指標**: 潜在的なデコイオブジェクトの属性を正規のオブジェクトと比較することで矛盾点があぶり出されます。HoneypotBuster のようなツールがデセプションの特定に役立ちます。

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: ATA 検出を避けるために Domain Controllers 上でのセッション列挙を避けること。
- **Ticket Impersonation**: aes キーを用いたチケット作成は、NTLM へダウングレードしないため検出回避に有効です。
- **DCSync Attacks**: Domain Controller 以外から実行することで ATA 検出を避けることが推奨されます。Domain Controller から直接実行するとアラートが発生します。

## 参考文献

- http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/
- https://www.labofapenetrationtester.com/2018/10/deploy-deception.html
- https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain

{{#include ../../banners/hacktricks-training.md}}
