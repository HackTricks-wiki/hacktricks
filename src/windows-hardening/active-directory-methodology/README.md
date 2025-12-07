# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Basic overview

**Active Directory** は、ネットワーク管理者がネットワーク内の **domains**, **users**, **objects** を効率的に作成・管理するための基盤技術です。大規模にスケールするよう設計されており、多数のユーザーを管理しやすい **groups** や **subgroups** に整理し、さまざまなレベルでの **access rights** を制御できます。

**Active Directory** の構造は主に 3 層で構成されます: **domains**, **trees**, **forests**。**domain** は共通のデータベースを共有する **users** や **devices** といったオブジェクトの集合を含みます。**trees** は共通の構造で結びついたこれらのドメインのグループであり、**forest** は複数のツリーが **trust relationships** によって相互接続された、組織構造の最上位を表します。各レイヤーで特定の **access** や **communication rights** を指定できます。

**Active Directory** の主要な概念は以下の通りです:

1. **Directory** – Active Directory オブジェクトに関する全情報を格納します。
2. **Object** – ディレクトリ内のエンティティ（**users**, **groups**, **shared folders** など）を指します。
3. **Domain** – ディレクトリオブジェクトのコンテナであり、複数のドメインが **forest** 内に共存し、それぞれ独自のオブジェクト集合を保持できます。
4. **Tree** – 共通のルートドメインを共有するドメインの集合です。
5. **Forest** – Active Directory の組織構造の頂点であり、複数のツリーとそれらの間の **trust relationships** で構成されます。

**Active Directory Domain Services (AD DS)** は、ネットワーク内での集中管理と通信に不可欠な一連のサービスを包含します。これらのサービスには以下が含まれます:

1. **Domain Services** – データの集中保存を行い、**users** と **domains** 間の相互作用（**authentication** や **search** 機能を含む）を管理します。
2. **Certificate Services** – セキュアな **digital certificates** の作成、配布、管理を監督します。
3. **Lightweight Directory Services** – **LDAP protocol** を通じてディレクトリ対応アプリケーションをサポートします。
4. **Directory Federation Services** – 複数の Web アプリケーションに対して **single-sign-on** を提供します。
5. **Rights Management** – 著作物の不正配布や使用を制御して保護する助けになります。
6. **DNS Service** – **domain names** の解決に不可欠です。

より詳細な説明は次を参照してください: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

AD を攻撃する方法を学ぶには、**Kerberos authentication process** を非常に良く理解する必要があります。\
[**まだ仕組みがわからない場合はこのページを読んでください。**](kerberos-authentication.md)

## Cheat Sheet

クイックにどのコマンドで AD を列挙/悪用できるか確認したい場合は、[https://wadcoms.github.io/](https://wadcoms.github.io) を参照してください。

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

AD 環境にアクセスできるが資格情報/セッションがない場合、次のことができます:

- **Pentest the network:**
- ネットワークをスキャンし、マシンや開いているポートを見つけ、**exploit vulnerabilities** や **extract credentials** を試みます（たとえば、[printers could be very interesting targets](ad-information-in-printers.md)）。
- DNS の列挙は、ドメイン内の重要なサーバ（web, printers, shares, vpn, media など）に関する情報を提供してくれる可能性があります。
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- 詳細は General な [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) を参照して方法を確認してください。
- **Check for null and Guest access on smb services** (これは最新の Windows バージョンでは機能しません):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- SMB サーバの列挙方法についての詳細ガイドは次を参照してください:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- LDAP の列挙方法についての詳細ガイドはこちら（**anonymous access** に特に注意）:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Responder を使った **impersonating services** により資格情報を収集する（{#ref}../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md{#endref}）
- [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) によりホストにアクセスする
- **evil-S** を用いて **exposing fake UPnP services** として資格情報を収集する（{#ref}../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md{#endref}）[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- 内部ドキュメント、ソーシャルメディア、ドメイン内のサービス（主に web）や公開されている情報からユーザー名や氏名を抽出します。
- 社員のフルネームがわかれば、さまざまな AD **username conventions** を試すことができます（[**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)）。一般的な規則は: _NameSurname_, _Name.Surname_, _NamSur_（各名前の最初の3文字）, _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 文字のランダム + 3 数字（例: abc123）。
- ツール:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) と [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) のページを参照してください。
- **Kerbrute enum**: 無効なユーザー名がリクエストされた場合、サーバは **Kerberos error** コード _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ を返し、ユーザー名が無効であることを特定できます。有効なユーザー名は **AS-REP 内の TGT** の応答か、または事前認証が必要であることを示すエラー _KRB5KDC_ERR_PREAUTH_REQUIRED_ を返します。
- **No Authentication against MS-NRPC**: domain controllers の MS-NRPC (Netlogon) インターフェースに対して auth-level = 1 (No authentication) を使用します。この方法は MS-NRPC インターフェースにバインドした後 `DsrGetDcNameEx2` 関数を呼び出して、資格情報なしでユーザーやコンピュータが存在するかを確認します。NauthNRPC ツールはこの種の列挙を実装しています。研究はこちらで参照できます: https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

ネットワーク内でこれらのサーバのいずれかを見つけた場合、**user enumeration against it** を実行できます。例えば、ツール [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> ユーザー名のリストは [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) および ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)) にあります。
>
> ただし、事前に実施した recon の段階で **会社で働く人々の名前** を把握しているはずです。名と姓が分かれば、スクリプト [**namemash.py**](https://gist.github.com/superkojiman/11076951) を使って候補となる有効なユーザー名を生成できます。

### Knowing one or several usernames

では、有効なユーザー名は既にわかっているがパスワードはない、という場合は次を試してください：

- [**ASREPRoast**](asreproast.md): ユーザーが属性 _DONT_REQ_PREAUTH_ を**持っていない**場合、そのユーザーに対して**AS_REPメッセージを要求**でき、そのメッセージにはユーザーのパスワード派生で暗号化されたデータが含まれます。
- [**Password Spraying**](password-spraying.md): 発見した各ユーザーに対して最も**一般的なパスワード**を試してみましょう。弱いパスワードを使っているユーザーがいるかもしれません（パスワードポリシーに注意してください）。
- また、ユーザーのメールサーバーへアクセスを試みるために **spray OWA servers** することもできます。


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

ネットワークのいくつかのプロトコルを **poisoning** することで、クラック可能なチャレンジの **hashes** を取得できる場合があります：


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Active Directory の列挙に成功すれば、**より多くのメールアドレスやネットワークの理解**が得られます。NTLM の [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) を強制して AD 環境にアクセスできる可能性があります。

### Steal NTLM Creds

もし **null または guest user** で他の PC や共有にアクセスできるなら、SCF ファイルのようなファイルを配置しておき、それが何らかの形で参照されるとあなたに対して **NTLM 認証をトリガー** させることができ、**NTLM challenge** を盗んでクラックすることができます：


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Enumerating Active Directory WITH credentials/session

このフェーズでは、有効なドメインアカウントの **資格情報またはセッションを奪取している** 必要があります。もし有効な資格情報やドメインユーザーとしてのシェルを持っているなら、前述のオプションは依然として他のユーザーを侵害するための選択肢であることを忘れないでください。

認証済みの列挙を開始する前に、**Kerberos double hop problem** を理解しておくべきです。


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

アカウントを奪取することは、ドメイン全体を侵害し始めるための**大きな一歩**です。これにより **Active Directory Enumeration** を開始できます：

[**ASREPRoast**](asreproast.md) に関しては、今や可能な脆弱ユーザーをすべて見つけられますし、[**Password Spraying**](password-spraying.md) に関しては全ユーザー名の**リスト**を取得して、奪取したアカウントのパスワード、空パスワード、新たに有望なパスワードを試すことができます。

- You could use the [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- また、よりステルスに行いたいなら [**powershell for recon**](../basic-powershell-for-pentesters/index.html) を使うことができます
- より詳細な情報抽出には [**use powerview**](../basic-powershell-for-pentesters/powerview.md) も利用できます
- Active Directory のリコンにもう一つ素晴らしいツールは [**BloodHound**](bloodhound.md) です。収集方法によりますが **それほどステルスではない** ことが多いです。**気にしない**のであればぜひ試してみてください。ユーザーがどこで RDP できるか、他のグループへの経路などを見つけられます。
- **Other automated AD enumeration tools are:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) は興味深い情報を含んでいる可能性があります。
- GUI を備えたディレクトリ列挙用ツールとしては **AdExplorer.exe**（**SysInternal** Suite）があります。
- **ldapsearch** を使って LDAP データベースを検索し、フィールド _userPassword_ と _unixUserPassword_、あるいは _Description_ にクレデンシャルが含まれていないか確認することもできます。その他の手法は cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) を参照してください。
- **Linux** を使用している場合は [**pywerview**](https://github.com/the-useless-one/pywerview) でドメイン列挙することもできます。
- また、以下の自動化ツールを試すこともできます:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

Windows ではドメインの全ユーザー名を取得するのは非常に簡単です（`net user /domain`、`Get-DomainUser`、または `wmic useraccount get name,sid`）。Linux では `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` や `enum4linux -a -u "user" -p "password" <DC IP>` を使用できます。

> たとえこの Enumeration セクションが短く見えても、これは最も重要な部分です。リンク（主に cmd、powershell、powerview、BloodHound のもの）にアクセスして、ドメインの列挙方法を学び、十分に慣れるまで練習してください。評価中、これが DA に到達するための鍵となる瞬間、あるいは何もできないと判断するための重要なポイントになります。

### Kerberoast

Kerberoasting は、ユーザーアカウントに紐づくサービスが使用する **TGS tickets** を取得し、それらの暗号（ユーザーパスワードに基づく）を **オフライン** でクラックする手法です。

詳細は：


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

いくつかの資格情報を入手したら、どの **machine** にアクセス可能かを確認してください。そのために、ポートスキャン結果に応じて複数のサーバーへ異なるプロトコルで接続を試みるために **CrackMapExec** を使うことができます。

### Local Privilege Escalation

通常のドメインユーザーとして資格情報やセッションを奪取していて、ドメイン内のいずれかのマシンにそのユーザーで**アクセスできる**場合は、ローカルで権限昇格してクレデンシャルを収集する方法を探すべきです。ローカルの管理者権限を得ることでのみ、他のユーザーのハッシュをメモリ（LSASS）やローカル（SAM）からダンプすることが可能になります。

本書には [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) に関する完全なページと、[**checklist**](../checklist-windows-privilege-escalation.md) があります。また、[**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) の使用も忘れないでください。

### Current Session Tickets

現在のユーザーのチケットが予期しないリソースへのアクセス権を与えていることを見つけるのは非常に**稀**ですが、確認してみる価値はあります：
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Active Directoryを列挙できれば、**より多くのメール情報とネットワークの理解を得られます**。NTLMの[**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)を強制できる可能性があります。

### コンピューター共有で資格情報を探す | SMB Shares

基本的な資格情報を入手したら、AD内で共有されている**興味深いファイルを**見つけられないか確認してください。手動で行うこともできますが、非常に退屈で反復的な作業です（何百ものドキュメントを確認する必要がある場合はさらに大変です）。

[**利用可能なツールについてはこのリンクを参照してください。**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### NTLM 資格情報の窃取

他のPCや共有に**アクセスできる**なら、(例: SCF file)を**配置する**ことができます。それが何らかの形で参照されると、あなたに対してNTLM認証を**トリガー**し、**NTLM challenge**を**盗んで**クラッキングすることができます:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

この脆弱性により、認証済みの任意のユーザーが**ドメインコントローラーを乗っ取る**ことが可能になりました。

{{#ref}}
printnightmare.md
{{#endref}}

## Active Directory上での特権認証/セッションを持つ場合の権限昇格

**以下の技術を実行するには通常のドメインユーザーでは不十分で、これらの攻撃を行うために特別な権限や資格情報が必要です。**

### Hash extraction

幸いにも [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)（リレーを含む）、[EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)、[escalating privileges locally](../windows-local-privilege-escalation/index.html) などを使って**いくつかのローカル管理者アカウントを侵害する**ことができているかもしれません。  
その後、メモリおよびローカルからすべてのハッシュをダンプする時です。  
[**ハッシュを取得するさまざまな方法についてはこちらを読んでください。**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**ユーザーのhashを入手したら**、それを使ってそのユーザーを**偽装（impersonate）**できます。  
そのhashを使って**NTLM認証を実行する**ような**ツール**を使うか、新しい**sessionlogon**を作成してその**hash**を**LSASS**内に**注入（inject）**し、以降の**NTLM認証が実行されるとそのhashが使用される**ようにする方法があります。後者がmimikatzのやり方です。  
[**詳しくはこのページを読んでください。**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

この攻撃は、一般的なPass The Hash（NTLM経由）の代替として、ユーザーのNTLMハッシュを使ってKerberosチケットを要求することを目的としています。したがって、**NTLMプロトコルが無効化されており**、**Kerberosのみが認証プロトコルとして許可されている**ネットワークで特に有用です。

{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

**Pass The Ticket (PTT)** 攻撃では、攻撃者はパスワードやハッシュ値の代わりにユーザーの認証チケットを**盗み**ます。盗まれたチケットを使ってユーザーを**偽装（impersonate）**し、ネットワーク内のリソースやサービスへ不正アクセスを行います。

{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

ローカル管理者の**hash**または**password**を持っている場合は、それを使って他の**PC**に**ローカルでログイン**してみてください。
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> これはかなり**ノイズが多い**ので、**LAPS**がそれを**軽減**します。

### MSSQL の悪用と信頼されたリンク

ユーザーが**MSSQL インスタンスにアクセスする権限**を持っている場合、MSSQLホスト上で（SAとして動作していれば）**コマンドを実行する**、NetNTLM の **hash** を**盗む**、あるいは**relay** **attack** を実行することが可能です。\
また、ある MSSQL インスタンスが別の MSSQL インスタンスから信頼（database link）されている場合、ユーザーが信頼されたデータベースに対する権限を持っていれば、**信頼関係を利用して別のインスタンスでもクエリを実行できる**ようになります。これらの信頼は連鎖することがあり、最終的にコマンドを実行できるような誤設定されたデータベースを見つけられるかもしれません。\
**データベース間のリンクはフォレスト間の trust を越えても機能します。**

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

サードパーティのインベントリやデプロイメントスイートは、しばしば資格情報やコード実行への強力な経路を露出します。参照：

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

もし [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) 属性を持つ Computer オブジェクトが見つかり、そのコンピュータ上でドメイン権限を持っている場合、そのコンピュータにログオンするすべてのユーザーのメモリから TGT をダンプすることができます。\
したがって、**Domain Admin がそのコンピュータにログオンした場合**、その TGT をダンプして [Pass the Ticket](pass-the-ticket.md) を使って偽装することが可能になります。\
constrained delegation によっては、（運が良ければそれが DC である）Print Server を**自動的に乗っ取る**ことさえ可能です。

{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

もしユーザーまたはコンピュータが "Constrained Delegation" を許可されていると、そのコンピュータ内のいくつかのサービスに対して**任意のユーザーを偽装してアクセスする**ことができます。\
そのため、このユーザー/コンピュータのハッシュを**奪取**すれば、（Domain Admin を含む）**任意のユーザーを偽装して特定のサービスにアクセスする**ことが可能になります。

{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

リモートコンピュータの Active Directory オブジェクトに対して **WRITE** 権限を持つことは、**昇格した権限**でコード実行を得る手段を可能にします：

{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

侵害されたユーザーがドメインオブジェクトに対して**興味深い権限**を持っている場合、それを使って横移動や**権限昇格**を行えることがあります。

{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler サービスの悪用

ドメイン内で **Spool サービスがリッスンしている**ことを発見すると、これを**悪用**して新たな資格情報を**取得**し、権限を**昇格**させることができます。

{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

**他のユーザー**が**侵害された**マシンに**アクセス**すると、メモリから資格情報を**収集**したり、彼らのプロセスにビーコンを注入して**偽装**することが可能です。\
通常ユーザーは RDP を介してシステムにアクセスするので、第三者の RDP セッションに対して行ういくつかの攻撃方法が以下にあります：

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** はドメイン参加したコンピュータの**ローカル Administrator パスワード**を管理するためのシステムで、パスワードを**ランダム化**し、一意にし、頻繁に**変更**します。これらのパスワードは Active Directory に保存され、アクセスは ACL により許可されたユーザーのみに制御されます。これらのパスワードにアクセスするための十分な権限があれば、他のコンピュータへピボットすることが可能になります。

{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

侵害されたマシンから**証明書を収集する**ことは、環境内での権限昇格の手段となり得ます：

{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

**脆弱なテンプレート**が設定されている場合、それらを悪用して権限を昇格することが可能です：

{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## 高権限アカウントでのポストエクスプロイテーション

### Dumping Domain Credentials

一度 **Domain Admin**、あるいはさらに **Enterprise Admin** の権限を得ると、ドメインデータベース _ntds.dit_ を**ダンプ**することができます。

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

前述のいくつかの手法は永続化のためにも使用できます。\
例：

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

**Silver Ticket attack** は、特定のサービスのための**正当な Ticket Granting Service (TGS) チケット**を、（例えば**PC アカウントのハッシュ**のような）**NTLM hash** を使って作成する攻撃です。この手法はサービス権限への**アクセス**を目的として利用されます。

{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** は、Active Directory 環境における **krbtgt アカウントの NTLM hash** を攻撃者が取得することを伴います。このアカウントはすべての **Ticket Granting Ticket (TGT)** に署名するために使われる特権的なアカウントです。

攻撃者がこのハッシュを取得すると、任意のアカウント用の **TGT** を作成することが可能になり（Silver ticket 攻撃と同様）、ネットワーク内で認証を偽装できます。

{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

これは、一般的な golden ticket 検出メカニズムを**回避するように偽造された** golden ticket のようなものです。

{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**アカウントの証明書を保有する、または要求できること**は、（パスワードが変更されても）そのユーザーアカウント内に永続化するための非常に有効な手段です：

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**証明書を使うことでドメイン内で高権限の永続化を行う**ことも可能です：

{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory の **AdminSDHolder** オブジェクトは、Domain Admins や Enterprise Admins のような **特権グループ**のセキュリティを確保するために、これらのグループに標準の **ACL** を適用して不正な変更を防ぎます。しかし、この機能は悪用され得ます。攻撃者が AdminSDHolder の ACL を変更して通常ユーザーにフルアクセスを与えると、そのユーザーはすべての特権グループに対して広範な制御を得ることができます。このセキュリティ対策は、監視が不十分だと逆に不正アクセスを許してしまう可能性があります。

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

すべての **Domain Controller (DC)** にはローカル管理者アカウントが存在します。そのようなマシンで管理権を取得すると、**mimikatz** を用いてローカル Administrator のハッシュを抽出できます。その後、リモートでローカル Administrator アカウントを利用可能にするためにレジストリの変更が必要になります。

{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

将来的にユーザーが**権限昇格**できるように、特定のドメインオブジェクトに対して**特別な権限**をユーザーに付与することができます。

{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** はオブジェクトが持つ**権限**を**格納**するために使われます。オブジェクトのセキュリティディスクリプタに**少しの変更**を加えるだけで、特権グループに属していなくてもそのオブジェクトに対して非常に興味深い権限を得ることができます。

{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

メモリ内の **LSASS** を改変して**ユニバーサルパスワード**を設定し、すべてのドメインアカウントへのアクセスを可能にします。

{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
独自の **SSP** を作成して、マシンへのアクセスに使用される**認証情報を平文でキャプチャ**することができます。

{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

新しい **Domain Controller** を AD に登録し、それを使って指定したオブジェクトに対して SIDHistory や SPN などの属性を **ログを残さずに**プッシュします。これを行うには DA 権限が必要で、ルートドメイン内にいる必要があります。\
ただし、もし間違ったデータを使用すると、かなり目立つログが生成されます。

{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

前述したように、**LAPS パスワードを読む権限**があれば権限昇格が可能です。しかし、これらのパスワードは**永続化**にも利用できます。\
参照：

{{#ref}}
laps.md
{{#endref}}

## フォレストの権限昇格 - ドメイントラスト

Microsoft は **Forest** をセキュリティ境界と見なします。これは、**単一ドメインの侵害がフォレスト全体の侵害につながる可能性がある**ことを意味します。

### 基本情報

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) は、あるドメインのユーザーが別のドメインのリソースにアクセスできるようにするセキュリティ機構です。これは両ドメインの認証システム間に連結を作り、認証の確認がシームレスに流れるようにします。ドメインがトラストを設定すると、両ドメインの Domain Controller (DC) はトラストの整合性に重要な特定の **キー** を交換・保持します。

典型的なシナリオでは、ユーザーが **trusted domain** のサービスにアクセスするには、まず自ドメインの DC から特別なチケットである **inter-realm TGT** を要求する必要があります。この TGT は両ドメインが合意した共有の **key** で暗号化されます。ユーザーはこの TGT を **trusted domain の DC** に提示してサービスチケット（**TGS**）を取得します。trusted domain の DC が inter-realm TGT を検証すると、クライアントに TGS を発行し、サービスへのアクセスを許可します。

**手順**:

1. **Domain 1** のクライアントコンピュータが自身の **NTLM hash** を使って **Domain Controller (DC1)** に **Ticket Granting Ticket (TGT)** を要求します。
2. クライアントが正しく認証されると DC1 は新しい TGT を発行します。
3. クライアントは次に **Domain 2** のリソースにアクセスするために DC1 から **inter-realm TGT** を要求します。
4. inter-realm TGT は、双方向のドメイントラストの一部として DC1 と DC2 の間で共有される **trust key** で暗号化されています。
5. クライアントは inter-realm TGT を **Domain 2 の Domain Controller (DC2)** に持っていきます。
6. DC2 は共有された trust key を使って inter-realm TGT を検証し、有効であればクライアントがアクセスしようとしている Domain 2 のサーバに対する **Ticket Granting Service (TGS)** を発行します。
7. 最後にクライアントはこの TGS をサーバに提示します。この TGS はサーバのアカウントハッシュで暗号化されており、Domain 2 のサービスへのアクセスが得られます。

### Different trusts

トラストは **片方向** または **双方向** のいずれかである点に注意が必要です。双方向の場合、両ドメインは互いに信頼しますが、**片方向** のトラストでは一方が **trusted** で他方が **trusting** となります。この場合、**trusted のドメインから trusting のドメイン内のリソースにのみアクセス可能**です。

もし Domain A が Domain B を信頼している場合、A が trusting ドメインで B が trusted ドメインです。さらに、**Domain A** ではこれは **Outbound trust**、**Domain B** では **Inbound trust** になります。

**Different trusting relationships**

- **Parent-Child Trusts**: 同一フォレスト内で一般的な構成で、子ドメインは自動的に親ドメインと双方向の推移的トラストを持ちます。これにより親と子の間で認証要求がシームレスに流れます。
- **Cross-link Trusts**: 「shortcut trusts」とも呼ばれ、子ドメイン間でリファーラル処理を高速化するために設定されます。複雑なフォレストでは認証リファーラルはフォレストルートまで上がり、ターゲットドメインまで下がる必要がありますが、cross-link を作ることでその経路を短縮できます。
- **External Trusts**: 異なる無関係なドメイン間に設定されるトラストで、非推移的です。Microsoft のドキュメントによると、external trusts はフォレストトラストによって接続されていないフォレスト外のドメインのリソースにアクセスする際に有用です。外部トラストでは SID filtering によってセキュリティが強化されます。
- **Tree-root Trusts**: フォレストルートドメインと新しく追加されたツリールート間で自動的に確立されるトラストです。一般的ではありませんが、新しいドメインツリーをフォレストに追加する際に重要です（双方向の推移性を維持します）。
- **Forest Trusts**: これは二つのフォレストルートドメイン間の双方向推移的トラストで、SID filtering を強制してセキュリティを強化します。
- **MIT Trusts**: 非 Windows の、[RFC4120 準拠](https://tools.ietf.org/html/rfc4120) の Kerberos ドメインと確立されるトラストです。外部の Kerberos ベースのシステムと統合する必要がある環境向けに使われます。

#### Other differences in **trusting relationships**

- トラスト関係は **推移的**（A trust B, B trust C → A trust C）または **非推移的** に設定できます。
- トラスト関係は **双方向**（双方が互いを信頼）または **片方向**（一方のみが他方を信頼）として設定できます。

### Attack Path

1. **Enumerate** して trusting 関係を列挙する
2. どの **security principal**（ユーザー/グループ/コンピュータ）が **他ドメインのリソースにアクセス**できるか（ACE エントリや別ドメインのグループに所属しているか）を確認する。**ドメインを越えた関係性**を探す（トラストはそのために作られている可能性が高い）。
1. このケースでは kerberoast も別のオプションになり得る。
3. ドメインをピボットできる**アカウントを侵害**する。

攻撃者は他ドメインのリソースにアクセスするために主に以下の3つのメカニズムを利用できます：

- **Local Group Membership**: プリンシパルがサーバ上の “Administrators” グループなどのローカルグループに追加されている場合、そのマシンに対する大きな制御を得ます。
- **Foreign Domain Group Membership**: プリンシパルが外部ドメインのグループのメンバーであることもあります。ただし、この方法の有効性はトラストの性質やグループの範囲に依存します。
- **Access Control Lists (ACLs)**: プリンシパルが ACL、特に DACL 内の ACE として指定されている場合、特定リソースへのアクセス権を持ちます。ACL、DACL、ACE の仕組みをより深く理解したい場合は、ホワイトペーパー “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” が非常に参考になります。

### Find external users/groups with permissions

ドメイン内の外部セキュリティプリンシパルを見つけるには、**`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** を確認できます。これらは **外部ドメイン/フォレスト** から来たユーザー/グループです。

この確認は **Bloodhound** や powerview を使って行うことができます：
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
domain trusts を列挙するその他の方法:
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
> 現在のドメインで使用されているキーは次のコマンドで確認できます：
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

SID-History injection を悪用して、trust を利用し child/parent domain に対して Enterprise admin に昇格します:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Configuration Naming Context (NC) がどのように悪用され得るかを理解することは重要です。Configuration NC は Active Directory (AD) 環境におけるフォレスト全体の構成データの中央リポジトリとして機能します。このデータはフォレスト内のすべての Domain Controller (DC) に複製され、書き込み可能な DC は Configuration NC の書き込み可能なコピーを保持します。これを悪用するには、**DC 上での SYSTEM privileges** が必要で、望ましくは child DC です。

**Link GPO to root DC site**

Configuration NC の Sites コンテナには、AD フォレスト内のドメイン参加コンピュータすべてのサイト情報が含まれます。任意の DC 上で SYSTEM privileges を持って操作することで、攻撃者は GPO を root DC のサイトにリンクできます。これにより、これらのサイトに適用されるポリシーを操作して root ドメインを危険にさらす可能性があります。

詳細については、[Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research) の調査を参照してください。

**Compromise any gMSA in the forest**

攻撃ベクトルの一つは、ドメイン内の特権的な gMSA を標的にすることです。gMSA のパスワード算出に必要な KDS Root key は Configuration NC に保存されています。任意の DC 上で SYSTEM privileges を持てば、KDS Root key にアクセスしてフォレスト内の任意の gMSA のパスワードを算出することが可能です。

詳細な解析と手順は以下を参照してください：


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

補完的な delegated MSA 攻撃（BadSuccessor – migration 属性の悪用）:


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

追加の外部研究: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent)。

**Schema change attack**

この手法は新しい特権 AD オブジェクトの作成を待つなど忍耐が必要です。SYSTEM privileges を持てば、攻撃者は AD Schema を変更して任意のユーザにすべてのクラスに対する完全な制御を付与できます。これにより、新しく作成される AD オブジェクトに対する不正なアクセスや制御が可能になります。

詳細は [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent) を参照してください。

**From DA to EA with ADCS ESC5**

ADCS ESC5 脆弱性は、PKI オブジェクトの制御を狙い、フォレスト内の任意のユーザとして認証できる証明書テンプレートを作成することを目的としています。PKI オブジェクトは Configuration NC に存在するため、書き込み可能な child DC を侵害することで ESC5 攻撃を実行できます。

詳細は [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c) を参照してください。ADCS が存在しない場合でも、攻撃者は必要なコンポーネントを構築できることが [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) で議論されています。

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
このシナリオでは、**あなたのドメインが外部ドメインから信頼されており**、外部ドメイン上で**未確定の権限**が与えられています。自ドメインのどのプリンシパルが外部ドメインに対してどのようなアクセスを持っているかを特定し、それを悪用する必要があります:

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
In this scenario **あなたのドメイン**は**信頼している**別の**ドメイン**のプリンシパルにいくつかの**権限**を与えています。

しかし、**ドメインが信頼される**と、trusted ドメインは**予測可能な名前**の**ユーザーを作成**し、その**パスワードに信頼側のパスワードを使用**します。つまり、**信頼ドメインのユーザーにアクセスし、信頼先ドメインへ侵入できる**可能性があり、そこを列挙してさらに権限昇格を試みることができます:

{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

もう一つの方法は、ドメイン信頼の**逆方向**に作成された[**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links)を見つけることです（これはあまり一般的ではありません）。

別の方法としては、**trusted ドメインのユーザーが RDP でログインできる**マシン上で待ち構えることです。その場合、攻撃者は RDP セッションプロセスにコードを注入し、そこから**被害者の元ドメインにアクセス**することができます。\
さらに、**被害者がそのハードドライブをマウントしていた**場合、RDP セッションプロセスからハードドライブの**スタートアップフォルダ**に**backdoors**を置くことが可能です。この手法は **RDPInception** と呼ばれます。

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### ドメイン信頼の悪用緩和

### **SID Filtering:**

- SID Filtering が有効になっていると、フォレスト間トラストにおける SID history 属性を悪用した攻撃のリスクは軽減されます。これは、Microsoft の見解に従い、セキュリティ境界をドメインではなくフォレストと見なす前提のもと、すべてのフォレスト間トラストでデフォルトで有効になっています。
- ただし、注意点として SID Filtering はアプリケーションやユーザーアクセスを妨げる可能性があり、そのために無効化されることがあります。

### **Selective Authentication:**

- フォレスト間トラストでは、Selective Authentication を使用することで、2 つのフォレストのユーザーが自動的に認証されることを防ぎます。代わりに、信頼するドメインやフォレスト内のドメインやサーバーにアクセスするためには明示的な権限が必要になります。
- これらの対策は、書き込み可能な Configuration Naming Context (NC) の悪用やトラストアカウントへの攻撃からは保護しない点に注意してください。

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAPベースのAD悪用（On-Host Implantsから）

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) は bloodyAD-style の LDAP プリミティブを x64 Beacon Object Files として再実装しており、これらはオンホストインプラント（例: Adaptix C2）内で完全に実行されます。オペレータはパックを `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` でコンパイルし、`ldap.axs` をロードしてからビーコン内で `ldap <subcommand>` を呼び出します。すべてのトラフィックは現在のログオン セキュリティ コンテキスト上で LDAP (389) の signing/sealing、または自動証明書信頼を使った LDAPS (636) を介して行われるため、socks プロキシやディスク上の痕跡は不要です。

### インプラント側のLDAP列挙

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` は短い名前や OU パスを完全な DN に解決し、対応するオブジェクトをダンプします。
- `get-object`, `get-attribute`, and `get-domaininfo` は任意の属性（security descriptors を含む）と `rootDSE` からのフォレスト/ドメインのメタデータを取得します。
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` は roasting candidates、delegation 設定、および LDAP から直接既存の [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) ディスクリプタを露出します。
- `get-acl` and `get-writable --detailed` は DACL を解析して trustees、権利（GenericAll/WriteDACL/WriteOwner/attribute writes）、および継承を列挙し、ACL 権限昇格の即時ターゲットを提供します。
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives — エスカレーションと永続化向け

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) により、オペレーターはOU権限がある場所に新しいプリンシパルやマシンアカウントを配置できます。`add-groupmember`、`set-password`、`add-attribute`、および `set-attribute` は write-property 権限を得ると対象を直接ハイジャックします。
- ACL 指向のコマンド（`add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, `add-dcsync` 等）は、任意の AD オブジェクトの WriteDACL/WriteOwner をパスワードリセット、グループメンバーシップ操作、または DCSync レプリケーション権限に変換し、PowerShell/ADSI のアーティファクトを残さずに行えます。`remove-*` 系は注入した ACE をクリーンアップします。

### Delegation、roasting、および Kerberos の悪用

- `add-spn`/`set-spn` により、侵害されたユーザーを即座に Kerberoastable にできます。`add-asreproastable`（UAC トグル）はパスワードに触れずに AS-REP ロースト対象としてマークします。
- Delegation マクロ（`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`）はビーコンから `msDS-AllowedToDelegateTo`、UAC フラグ、または `msDS-AllowedToActOnBehalfOfOtherIdentity` を書き換え、constrained/unconstrained/RBCD の攻撃経路を有効にし、リモート PowerShell や RSAT の必要性を排します。

### sidHistory injection、OU の移動、および攻撃対象面の形成

- `add-sidhistory` は管理対象プリンシパルの SID history に特権 SID を注入します（[SID-History Injection](sid-history-injection.md) を参照）。これにより LDAP/LDAPS 上でステルスにアクセス継承が可能になります。
- `move-object` はコンピュータやユーザーの DN/OU を変更し、攻撃者が `set-password`、`add-groupmember`、または `add-spn` を悪用する前に、既に委任権が存在する OU に資産を移動できます。
- スコープを限定した削除コマンド（`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` など）は、オペレーターが資格情報や永続化を収集した後に迅速なロールバックを可能にし、テレメトリを最小化します。

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## 一般的な防御策

[**認証情報の保護方法について詳しくはこちら。**](../stealing-credentials/credentials-protections.md)

### **認証情報保護の防御対策**

- **Domain Admins の制限**：Domain Admins は Domain Controllers のみにログインを許可し、他のホストでの使用を避けることが推奨されます。
- **サービスアカウントの権限**：サービスを Domain Admin (DA) 権限で実行しないようにしてください。
- **一時的な権限制限**：DA 権限が必要なタスクでは、その期間を制限するべきです。例： `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **デセプション（欺瞞）技術の実装**

- デセプションの実装は、パスワードが期限切れにならない、または Trusted for Delegation とマークされたデコイユーザーやデコイコンピュータなどの罠を設置することを伴います。詳細な手法には、特定の権限を持つユーザーを作成したり、高権限グループに追加したりすることが含まれます。
- 実用的な例： `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- デセプション技術の展開について詳しくは [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception) を参照してください。

### **デセプションの識別**

- **ユーザーオブジェクトの場合**：疑わしい指標には、非典型的な ObjectSID、ログオン頻度の低さ、作成日時、および誤パスワード試行回数が少ないことなどがあります。
- **一般的な指標**：潜在的なデコイオブジェクトの属性を実際のオブジェクトと比較すると不整合が明らかになります。ツール例として [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) が役立ちます。

### **検出システムの回避**

- **Microsoft ATA の検出回避**：
- **ユーザー列挙**：ATA 検出を避けるために Domain Controllers 上でのセッション列挙を避ける。
- **チケット偽装**：チケット作成に **aes** キーを使用すると NTLM へダウングレードせず、検出を回避しやすくなります。
- **DCSync 攻撃**：Domain Controller 以外から実行して ATA 検出を回避することが推奨されます。Domain Controller から直接実行するとアラートが発生します。

## 参考資料

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)

{{#include ../../banners/hacktricks-training.md}}
