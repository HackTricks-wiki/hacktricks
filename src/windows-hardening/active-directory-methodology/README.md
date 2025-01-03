# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## 基本概要

**Active Directory**は、**ネットワーク管理者**がネットワーク内で**ドメイン**、**ユーザー**、および**オブジェクト**を効率的に作成および管理できる基盤技術として機能します。これはスケーラブルに設計されており、大規模なユーザーを管理可能な**グループ**および**サブグループ**に整理し、さまざまなレベルで**アクセス権**を制御します。

**Active Directory**の構造は、**ドメイン**、**ツリー**、および**フォレスト**の3つの主要な層で構成されています。**ドメイン**は、共通のデータベースを共有する**ユーザー**や**デバイス**などのオブジェクトのコレクションを含みます。**ツリー**は、共有構造によってリンクされたこれらのドメインのグループであり、**フォレスト**は、**信頼関係**を通じて相互接続された複数のツリーのコレクションを表し、組織構造の最上層を形成します。特定の**アクセス**および**通信権**は、これらの各レベルで指定できます。

**Active Directory**内の主要な概念には以下が含まれます：

1. **ディレクトリ** – Active Directoryオブジェクトに関するすべての情報を保持します。
2. **オブジェクト** – ディレクトリ内のエンティティを示し、**ユーザー**、**グループ**、または**共有フォルダー**を含みます。
3. **ドメイン** – ディレクトリオブジェクトのコンテナとして機能し、複数のドメインが**フォレスト**内で共存でき、それぞれが独自のオブジェクトコレクションを維持します。
4. **ツリー** – 共通のルートドメインを共有するドメインのグループです。
5. **フォレスト** – Active Directoryにおける組織構造の頂点であり、**信頼関係**を持ついくつかのツリーで構成されています。

**Active Directory Domain Services (AD DS)**は、ネットワーク内での集中管理および通信に不可欠な一連のサービスを含みます。これらのサービスには以下が含まれます：

1. **ドメインサービス** – データストレージを集中化し、**ユーザー**と**ドメイン**間の相互作用を管理し、**認証**および**検索**機能を含みます。
2. **証明書サービス** – 安全な**デジタル証明書**の作成、配布、および管理を監督します。
3. **軽量ディレクトリサービス** – **LDAPプロトコル**を通じてディレクトリ対応アプリケーションをサポートします。
4. **ディレクトリフェデレーションサービス** – 複数のWebアプリケーションでのユーザー認証を単一のセッションで行う**シングルサインオン**機能を提供します。
5. **権利管理** – 著作権資料を保護し、その無断配布および使用を規制するのを支援します。
6. **DNSサービス** – **ドメイン名**の解決に重要です。

詳細な説明については、[**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)を確認してください。

### **Kerberos認証**

**ADを攻撃する**方法を学ぶには、**Kerberos認証プロセス**を非常によく**理解する**必要があります。\
[**まだその仕組みがわからない場合はこのページを読んでください。**](kerberos-authentication.md)

## チートシート

[https://wadcoms.github.io/](https://wadcoms.github.io)にアクセスして、ADを列挙/悪用するために実行できるコマンドの概要を確認できます。

## Recon Active Directory (クレデンシャル/セッションなし)

AD環境にアクセスできるが、クレデンシャル/セッションがない場合は、次のことができます：

- **ネットワークのペンテスト:**
- ネットワークをスキャンし、マシンやオープンポートを見つけ、そこから**脆弱性を悪用**したり、**クレデンシャルを抽出**したりします（例えば、[プリンターは非常に興味深いターゲットになる可能性があります](ad-information-in-printers.md)）。
- DNSを列挙することで、ドメイン内の重要なサーバーに関する情報を得ることができます。ウェブ、プリンター、共有、VPN、メディアなど。
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- 一般的な[**ペンテスト手法**](../../generic-methodologies-and-resources/pentesting-methodology.md)を確認して、これを行う方法についての詳細情報を見つけてください。
- **smbサービスでのnullおよびGuestアクセスを確認**（これは最新のWindowsバージョンでは機能しません）：
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- SMBサーバーを列挙する方法についての詳細なガイドはここにあります：

{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Ldapを列挙**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- LDAPを列挙する方法についての詳細なガイドはここにあります（**匿名アクセスに特に注意してください**）：

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **ネットワークを毒する**
- [**Responderを使用してサービスを偽装してクレデンシャルを収集**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- [**リレー攻撃を悪用してホストにアクセス**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- [**悪意のあるUPnPサービスを公開してクレデンシャルを収集**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.xyz/external-recon-methodology):
- 内部文書、ソーシャルメディア、サービス（主にウェブ）からユーザー名/名前を抽出し、公開されている情報からも収集します。
- 会社の従業員の完全な名前が見つかった場合、さまざまなAD **ユーザー名の慣習**を試すことができます（[**これを読む**](https://activedirectorypro.com/active-directory-user-naming-convention/)）。最も一般的な慣習は：_NameSurname_、_Name.Surname_、_NamSur_（各3文字）、_Nam.Sur_、_NSurname_、_N.Surname_、_SurnameName_、_Surname.Name_、_SurnameN_、_Surname.N_、3 _ランダムな文字と3つのランダムな数字_（abc123）です。
- ツール：
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### ユーザー列挙

- **匿名SMB/LDAP列挙:** [**ペンテストSMB**](../../network-services-pentesting/pentesting-smb/)および[**ペンテストLDAP**](../../network-services-pentesting/pentesting-ldap.md)ページを確認してください。
- **Kerbrute列挙**: **無効なユーザー名が要求される**と、サーバーは**Kerberosエラー**コード_KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_を使用して応答し、ユーザー名が無効であることを判断できます。**有効なユーザー名**は、**AS-REP**応答で**TGT**を引き起こすか、エラー_KRB5KDC_ERR_PREAUTH_REQUIRED_を示し、ユーザーが事前認証を行う必要があることを示します。
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
```
- **OWA (Outlook Web Access) サーバー**

ネットワーク内でこれらのサーバーの1つを見つけた場合、**ユーザー列挙を実行することもできます**。たとえば、ツール [**MailSniper**](https://github.com/dafthack/MailSniper) を使用できます：
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
> ユーザー名のリストは[**このgithubリポジトリ**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) \*\*\*\*やこのリポジトリ（[**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)）で見つけることができます。
>
> ただし、事前に実施したリコンステップから**会社で働いている人々の名前**を持っている必要があります。名前と姓があれば、スクリプト[**namemash.py**](https://gist.github.com/superkojiman/11076951)を使用して、潜在的な有効なユーザー名を生成できます。

### 1つまたは複数のユーザー名を知っている場合

さて、有効なユーザー名はすでに知っているが、パスワードはない... それなら試してみてください：

- [**ASREPRoast**](asreproast.md): ユーザーが**_DONT_REQ_PREAUTH_**属性を持っていない場合、そのユーザーのために**AS_REPメッセージを要求**でき、ユーザーのパスワードの派生によって暗号化されたデータが含まれます。
- [**Password Spraying**](password-spraying.md): 発見した各ユーザーに対して最も**一般的なパスワード**を試してみましょう。もしかしたら、誰かが悪いパスワードを使用しているかもしれません（パスワードポリシーに注意してください！）。
- OWAサーバーを**スプレー**して、ユーザーのメールサーバーへのアクセスを試みることもできます。

{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS ポイズニング

ネットワークの**プロトコルをポイズニング**することで、いくつかのチャレンジ**ハッシュ**を**取得**できるかもしれません：

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTML リレー

アクティブディレクトリを列挙できた場合、**より多くのメールとネットワークの理解が得られます**。NTMLの[**リレー攻撃**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) \*\*\*\*を強制してAD環境にアクセスできるかもしれません。

### NTLM クレデンシャルの盗難

**nullまたはゲストユーザー**で他のPCや共有に**アクセス**できる場合、**ファイルを配置**（SCFファイルなど）して、何らかの形でアクセスされると、**あなたに対してNTML認証をトリガー**し、**NTLMチャレンジを盗む**ことができます：

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## 資格情報/セッションを使用したアクティブディレクトリの列挙

このフェーズでは、**有効なドメインアカウントの資格情報またはセッションを侵害している必要があります。** 有効な資格情報またはドメインユーザーとしてのシェルがある場合、**前に示したオプションは他のユーザーを侵害するためのオプションとして依然として有効です**。

認証された列挙を開始する前に、**Kerberosダブルホップ問題**が何であるかを知っておく必要があります。

{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### 列挙

アカウントを侵害することは、**ドメイン全体を侵害するための大きなステップ**です。なぜなら、**アクティブディレクトリの列挙を開始できるからです**：

[**ASREPRoast**](asreproast.md)に関しては、今やすべての可能な脆弱なユーザーを見つけることができ、[**Password Spraying**](password-spraying.md)に関しては、**すべてのユーザー名のリスト**を取得し、侵害されたアカウントのパスワード、空のパスワード、新しい有望なパスワードを試すことができます。

- [**CMDを使用して基本的なリコンを実行**](../basic-cmd-for-pentesters.md#domain-info)できます。
- [**PowerShellを使用してリコン**](../basic-powershell-for-pentesters/)することもでき、よりステルス性があります。
- [**PowerViewを使用**](../basic-powershell-for-pentesters/powerview.md)して、より詳細な情報を抽出できます。
- アクティブディレクトリのリコンに最適なツールは[**BloodHound**](bloodhound.md)です。**あまりステルス性はありません**（使用する収集方法によります）が、**それを気にしないのであれば**、ぜひ試してみてください。ユーザーがRDPできる場所を見つけたり、他のグループへのパスを見つけたりします。
- **他の自動化されたAD列挙ツールは：** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**ADのDNSレコード**](ad-dns-records.md)は、興味深い情報を含んでいるかもしれません。
- ディレクトリを列挙するために使用できる**GUIツール**は、**SysInternal**スイートの**AdExplorer.exe**です。
- **ldapsearch**を使用してLDAPデータベースを検索し、_userPassword_および_unixUserPassword_フィールドや、_Description_を探すことができます。cf. [PayloadsAllTheThingsのADユーザーコメントのパスワード](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment)で他の方法を確認してください。
- **Linux**を使用している場合、[**pywerview**](https://github.com/the-useless-one/pywerview)を使用してドメインを列挙することもできます。
- 自動化ツールを試すこともできます：
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **すべてのドメインユーザーの抽出**

Windowsからすべてのドメインユーザー名を取得するのは非常に簡単です（`net user /domain`、`Get-DomainUser`または`wmic useraccount get name,sid`）。Linuxでは、次のように使用できます：`GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username`または`enum4linux -a -u "user" -p "password" <DC IP>`。

> この列挙セクションは小さく見えるかもしれませんが、これはすべての中で最も重要な部分です。リンクにアクセスし（特にcmd、powershell、powerview、BloodHoundのリンク）、ドメインを列挙する方法を学び、快適に感じるまで練習してください。評価中、これはDAへの道を見つけるか、何もできないと決定するための重要な瞬間になります。

### Kerberoast

Kerberoastingは、ユーザーアカウントに関連付けられたサービスによって使用される**TGSチケット**を取得し、その暗号化をクラックすることを含みます—これはユーザーパスワードに基づいており、**オフライン**で行われます。

詳細については：

{{#ref}}
kerberoast.md
{{#endref}}

### リモート接続（RDP、SSH、FTP、Win-RMなど）

資格情報を取得したら、**マシン**へのアクセスがあるかどうかを確認できます。そのために、**CrackMapExec**を使用して、ポートスキャンに応じて異なるプロトコルで複数のサーバーに接続を試みることができます。

### ローカル特権昇格

通常のドメインユーザーとしての資格情報またはセッションを侵害し、**ドメイン内の任意のマシンにこのユーザーでアクセス**できる場合、**ローカルで特権を昇格させ、資格情報を盗む**方法を見つけるべきです。これは、ローカル管理者権限がないと、他のユーザーのハッシュをメモリ（LSASS）やローカル（SAM）で**ダンプ**できないためです。

この本には、[**Windowsにおけるローカル特権昇格**](../windows-local-privilege-escalation/)に関する完全なページと、[**チェックリスト**](../checklist-windows-privilege-escalation.md)があります。また、[**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)を使用することを忘れないでください。

### 現在のセッションチケット

現在のユーザーに**予期しないリソースへのアクセスを許可する**チケットが見つかる可能性は非常に**低い**ですが、確認することができます：
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTML Relay

アクティブディレクトリを列挙できた場合、**より多くのメールとネットワークの理解が得られます**。NTML [**リレー攻撃**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**を強制することができるかもしれません。**

### **コンピュータ共有内のクレデンシャルを探す**

基本的なクレデンシャルを持っているので、**AD内で共有されている興味深いファイルを見つける**ことができるか確認してください。手動で行うこともできますが、非常に退屈で繰り返しの作業です（特に確認する必要のある数百のドキュメントを見つけた場合はなおさらです）。

[**使用できるツールについて学ぶにはこのリンクをフォローしてください。**](../../network-services-pentesting/pentesting-smb/#domain-shared-folders-search)

### NTLMクレデンシャルの盗難

他のPCや共有に**アクセスできる**場合、**ファイル**（SCFファイルなど）を**配置する**ことができ、何らかの形でアクセスされると、**あなたに対してNTML認証をトリガー**するので、**NTLMチャレンジを盗む**ことができます：

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

この脆弱性により、認証されたユーザーは**ドメインコントローラーを侵害**することができました。

{{#ref}}
printnightmare.md
{{#endref}}

## 特権クレデンシャル/セッションを使用したActive Directoryの特権昇格

**以下の技術には、通常のドメインユーザーでは不十分で、これらの攻撃を実行するために特別な特権/クレデンシャルが必要です。**

### ハッシュ抽出

幸運にも、[AsRepRoast](asreproast.md)、[Password Spraying](password-spraying.md)、[Kerberoast](kerberoast.md)、[Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)を含むリレー、[EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)、[ローカルでの特権昇格](../windows-local-privilege-escalation/)を使用して**ローカル管理者**アカウントを**侵害**できたことを願っています。\
次に、メモリとローカルのすべてのハッシュをダンプする時です。\
[**ハッシュを取得するさまざまな方法についてこのページをお読みください。**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### パス・ザ・ハッシュ

**ユーザーのハッシュを取得したら**、それを使用して**なりすます**ことができます。\
その**ハッシュ**を使用して**NTLM認証を実行する**ツールを使用する必要があります。**または**、新しい**sessionlogon**を作成し、その**ハッシュ**を**LSASS**内に**注入**することができます。これにより、**NTLM認証が実行されると、その**ハッシュが使用されます。**最後のオプションはmimikatzが行うことです。\
[**詳細についてはこのページをお読みください。**](../ntlm/#pass-the-hash)

### オーバーパス・ザ・ハッシュ/パス・ザ・キー

この攻撃は、**ユーザーのNTLMハッシュを使用してKerberosチケットを要求する**ことを目的としています。これは、一般的なNTLMプロトコルのパス・ザ・ハッシュの代替手段です。したがって、これは特に**NTLMプロトコルが無効**で、**Kerberosのみが認証プロトコルとして許可されているネットワーク**で**役立つ**可能性があります。

{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### パス・ザ・チケット

**パス・ザ・チケット（PTT）**攻撃手法では、攻撃者は**ユーザーの認証チケットを盗む**ことで、パスワードやハッシュ値を盗むのではなく、その盗まれたチケットを使用して**ユーザーになりすまし**、ネットワーク内のリソースやサービスに不正アクセスします。

{{#ref}}
pass-the-ticket.md
{{#endref}}

### クレデンシャルの再利用

**ローカル管理者**の**ハッシュ**または**パスワード**を持っている場合は、それを使用して他の**PCにローカルでログイン**してみてください。
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> 注意してください、これは非常に**騒がしい**ものであり、**LAPS**がこれを**軽減**します。

### MSSQLの悪用と信頼されたリンク

ユーザーが**MSSQLインスタンスにアクセスする権限**を持っている場合、MSSQLホストで**コマンドを実行**したり（SAとして実行されている場合）、NetNTLMの**ハッシュ**を**盗む**ことができるか、さらには**リレー****攻撃**を行うことができるかもしれません。\
また、MSSQLインスタンスが別のMSSQLインスタンスによって信頼されている場合（データベースリンク）。ユーザーが信頼されたデータベースに対して権限を持っている場合、**信頼関係を利用して他のインスタンスでもクエリを実行することができます**。これらの信頼は連鎖することができ、ユーザーはコマンドを実行できる誤設定されたデータベースを見つけることができるかもしれません。\
**データベース間のリンクは、フォレストの信頼を越えても機能します。**

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### 制約のない委任

[ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>)属性を持つコンピュータオブジェクトを見つけ、コンピュータにドメイン権限がある場合、コンピュータにログインするすべてのユーザーのメモリからTGTをダンプすることができます。\
したがって、**ドメイン管理者がコンピュータにログインすると**、そのTGTをダンプして[Pass the Ticket](pass-the-ticket.md)を使用して彼を偽装することができます。\
制約のある委任のおかげで、**プリントサーバーを自動的に侵害する**ことさえ可能です（できればDCであることを願っています）。

{{#ref}}
unconstrained-delegation.md
{{#endref}}

### 制約された委任

ユーザーまたはコンピュータが「制約された委任」を許可されている場合、**コンピュータ内のいくつかのサービスにアクセスするために任意のユーザーを偽装することができます**。\
その後、**このユーザー/コンピュータのハッシュを侵害**すると、**任意のユーザー**（ドメイン管理者を含む）を偽装していくつかのサービスにアクセスすることができます。

{{#ref}}
constrained-delegation.md
{{#endref}}

### リソースベースの制約された委任

リモートコンピュータのActive Directoryオブジェクトに対して**WRITE**権限を持つことは、**昇格された権限**でのコード実行を可能にします：

{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### ACLの悪用

侵害されたユーザーは、**ドメインオブジェクトのいくつかに対して興味深い権限**を持っている可能性があり、これにより**横移動**や**権限の昇格**が可能になります。

{{#ref}}
acl-persistence-abuse/
{{#endref}}

### プリンタースプーラーサービスの悪用

ドメイン内で**スプールサービスがリッスンしている**ことを発見することは、**新しい資格情報を取得**し、**権限を昇格**させるために**悪用**される可能性があります。

{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### サードパーティセッションの悪用

**他のユーザー**が**侵害された**マシンに**アクセス**すると、メモリから**資格情報を収集**し、彼らのプロセスに**ビーコンを注入**して彼らを偽装することが可能です。\
通常、ユーザーはRDPを介してシステムにアクセスするため、ここではサードパーティのRDPセッションに対していくつかの攻撃を実行する方法を示します：

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS**は、ドメインに参加しているコンピュータ上の**ローカル管理者パスワード**を管理するためのシステムを提供し、それが**ランダム化**され、ユニークで、頻繁に**変更**されることを保証します。これらのパスワードはActive Directoryに保存され、ACLを通じて認可されたユーザーのみがアクセスできるように制御されます。これらのパスワードにアクセスするための十分な権限があれば、他のコンピュータにピボットすることが可能になります。

{{#ref}}
laps.md
{{#endref}}

### 証明書の盗難

**侵害されたマシンから証明書を収集する**ことは、環境内で権限を昇格させる方法となる可能性があります：

{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### 証明書テンプレートの悪用

**脆弱なテンプレート**が設定されている場合、それを悪用して権限を昇格させることが可能です：

{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## 高権限アカウントによるポストエクスプロイト

### ドメイン資格情報のダンプ

**ドメイン管理者**またはさらに良い**エンタープライズ管理者**権限を取得すると、**ドメインデータベース**を**ダンプ**できます：_ntds.dit_。

[**DCSync攻撃に関する詳細情報はここにあります**](dcsync.md)。

[**NTDS.ditを盗む方法に関する詳細情報はここにあります**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### プライバシー昇格としての持続性

前述のいくつかの技術は持続性に使用できます。\
例えば、次のことができます：

- ユーザーを[**Kerberoast**](kerberoast.md)に対して脆弱にする

```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- ユーザーを[**ASREPRoast**](asreproast.md)に対して脆弱にする

```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- ユーザーに[**DCSync**](./#dcsync)権限を付与する

```powershell
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### シルバーチケット

**シルバーチケット攻撃**は、特定のサービスのために**正当なチケットグラントサービス（TGS）チケット**を**NTLMハッシュ**（例えば、**PCアカウントのハッシュ**）を使用して作成します。この方法は、**サービス権限にアクセスする**ために使用されます。

{{#ref}}
silver-ticket.md
{{#endref}}

### ゴールデンチケット

**ゴールデンチケット攻撃**は、攻撃者がActive Directory（AD）環境内の**krbtgtアカウントのNTLMハッシュ**にアクセスすることを含みます。このアカウントは特別で、すべての**チケットグラントチケット（TGT）**に署名するために使用され、ADネットワーク内での認証に不可欠です。

攻撃者がこのハッシュを取得すると、任意のアカウントのために**TGT**を作成することができます（シルバーチケット攻撃）。

{{#ref}}
golden-ticket.md
{{#endref}}

### ダイヤモンドチケット

これらは、**一般的なゴールデンチケットの検出メカニズムを回避する**方法で偽造されたゴールデンチケットのようなものです。

{{#ref}}
diamond-ticket.md
{{#endref}}

### **証明書アカウントの持続性**

**アカウントの証明書を持っているか、要求できること**は、ユーザーアカウントに持続する非常に良い方法です（たとえ彼がパスワードを変更しても）：

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **証明書ドメインの持続性**

**証明書を使用することは、ドメイン内で高権限を持続することも可能です：**

{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolderグループ

Active Directory内の**AdminSDHolder**オブジェクトは、**特権グループ**（ドメイン管理者やエンタープライズ管理者など）のセキュリティを確保するために、これらのグループ全体に標準の**アクセス制御リスト（ACL）**を適用して、無許可の変更を防ぎます。しかし、この機能は悪用される可能性があります。攻撃者がAdminSDHolderのACLを変更して通常のユーザーに完全なアクセスを与えると、そのユーザーはすべての特権グループに対して広範な制御を得ることになります。このセキュリティ対策は保護を目的としていますが、厳重に監視されない限り、逆効果をもたらす可能性があります。

[**AdminDSHolderグループに関する詳細情報はここにあります。**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM資格情報

すべての**ドメインコントローラー（DC）**内には、**ローカル管理者**アカウントが存在します。このようなマシンで管理者権限を取得することで、**mimikatz**を使用してローカル管理者ハッシュを抽出できます。その後、このパスワードを**使用できるようにするためのレジストリ変更**が必要で、ローカル管理者アカウントへのリモートアクセスを可能にします。

{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL持続性

特定のドメインオブジェクトに対して**ユーザー**に**特別な権限**を与えることで、そのユーザーが将来的に**権限を昇格**させることができるようになります。

{{#ref}}
acl-persistence-abuse/
{{#endref}}

### セキュリティ記述子

**セキュリティ記述子**は、**オブジェクト**が**オブジェクト**に対して持つ**権限**を**保存**するために使用されます。オブジェクトの**セキュリティ記述子**に**少し変更**を加えることができれば、そのオブジェクトに対して特権グループのメンバーである必要なく非常に興味深い権限を取得できます。

{{#ref}}
security-descriptors.md
{{#endref}}

### スケルトンキー

**LSASS**をメモリ内で変更して、すべてのドメインアカウントにアクセスを許可する**ユニバーサルパスワード**を確立します。

{{#ref}}
skeleton-key.md
{{#endref}}

### カスタムSSP

[SSP（セキュリティサポートプロバイダー）とは何かをここで学びます。](../authentication-credentials-uac-and-efs/#security-support-provider-interface-sspi)\
自分の**SSP**を作成して、マシンにアクセスするために使用される**資格情報**を**平文**で**キャプチャ**することができます。\\

{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

ADに**新しいドメインコントローラー**を登録し、指定されたオブジェクトに**属性**（SIDHistory、SPNs...）を**プッシュ**するために使用しますが、**変更**に関する**ログ**を残さずに行います。**DA**権限が必要で、**ルートドメイン**内にいる必要があります。\
間違ったデータを使用すると、非常に醜いログが表示されることに注意してください。

{{#ref}}
dcshadow.md
{{#endref}}

### LAPS持続性

以前に、**LAPSパスワードを読み取るための十分な権限がある場合**に権限を昇格させる方法について説明しました。しかし、これらのパスワードは**持続性を維持するためにも使用できます**。\
確認してください：

{{#ref}}
laps.md
{{#endref}}

## フォレスト権限昇格 - ドメイン信頼

Microsoftは**フォレスト**をセキュリティ境界と見なしています。これは、**単一のドメインを侵害することが、フォレスト全体の侵害につながる可能性がある**ことを意味します。

### 基本情報

[**ドメイン信頼**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>)は、1つの**ドメイン**のユーザーが別の**ドメイン**のリソースにアクセスできるようにするセキュリティメカニズムです。これは、2つのドメインの認証システム間にリンクを作成し、認証確認がシームレスに流れることを可能にします。ドメインが信頼を設定すると、特定の**キー**を**ドメインコントローラー（DC）**内で交換し保持します。これは信頼の整合性にとって重要です。

典型的なシナリオでは、ユーザーが**信頼されたドメイン**のサービスにアクセスしようとする場合、最初に自分のドメインのDCから**インターレルムTGT**と呼ばれる特別なチケットを要求する必要があります。このTGTは、両方のドメインが合意した共有**キー**で暗号化されています。ユーザーはこのTGTを**信頼されたドメインのDC**に提示してサービスチケット（**TGS**）を取得します。信頼されたドメインのDCによってインターレルムTGTが正常に検証されると、TGSが発行され、ユーザーはサービスにアクセスできるようになります。

**手順**：

1. **ドメイン1**の**クライアントコンピュータ**が、**ドメインコントローラー（DC1）**から**チケットグラントチケット（TGT）**を要求するプロセスを開始します。
2. クライアントが正常に認証されると、DC1は新しいTGTを発行します。
3. クライアントは次に、**ドメイン2**のリソースにアクセスするために必要な**インターレルムTGT**をDC1に要求します。
4. インターレルムTGTは、DC1とDC2の間で共有された**信頼キー**で暗号化されています。
5. クライアントはインターレルムTGTを**ドメイン2のドメインコントローラー（DC2）**に持っていきます。
6. DC2は、共有信頼キーを使用してインターレルムTGTを検証し、正当であれば、クライアントがアクセスしたいドメイン2のサーバーのために**チケットグラントサービス（TGS）**を発行します。
7. 最後に、クライアントはこのTGSをサーバーに提示し、サーバーのアカウントハッシュで暗号化されているため、ドメイン2のサービスにアクセスします。

### 異なる信頼

**信頼は1方向または2方向**であることに注意することが重要です。2方向のオプションでは、両方のドメインが互いに信頼しますが、**1方向**の信頼関係では、1つのドメインが**信頼された**ものであり、もう1つが**信頼する**ドメインです。この場合、**信頼されたドメインから信頼するドメイン内のリソースにのみアクセスできます**。

ドメインAがドメインBを信頼している場合、Aは信頼するドメインであり、Bは信頼されたドメインです。さらに、**ドメインA**では、これは**アウトバウンド信頼**となり、**ドメインB**では、これは**インバウンド信頼**となります。

**異なる信頼関係**

- **親子信頼**：これは同じフォレスト内で一般的な設定であり、子ドメインは自動的に親ドメインとの双方向の推移的信頼を持ちます。基本的に、これは認証要求が親と子の間でシームレスに流れることを意味します。
- **クロスリンク信頼**：これは「ショートカット信頼」と呼ばれ、子ドメイン間で設立され、紹介プロセスを迅速化します。複雑なフォレストでは、認証紹介は通常、フォレストルートまで上昇し、ターゲットドメインまで下降する必要があります。クロスリンクを作成することで、旅が短縮され、特に地理的に分散した環境で有益です。
- **外部信頼**：これは異なる、無関係なドメイン間で設定され、非推移的です。 [Microsoftの文書](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)によると、外部信頼は、現在のフォレスト外のドメインのリソースにアクセスするために便利であり、フォレスト信頼によって接続されていないドメインに対して有用です。セキュリティは、外部信頼に対するSIDフィルタリングによって強化されます。
- **ツリー根信頼**：これらの信頼は、フォレストルートドメインと新しく追加されたツリー根の間で自動的に確立されます。一般的には遭遇しませんが、ツリー根信頼は新しいドメインツリーをフォレストに追加するために重要であり、ユニークなドメイン名を維持し、双方向の推移性を確保します。詳細情報は[Microsoftのガイド](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)で確認できます。
- **フォレスト信頼**：このタイプの信頼は、2つのフォレストルートドメイン間の双方向推移的信頼であり、セキュリティ対策を強化するためにSIDフィルタリングを強制します。
- **MIT信頼**：これらの信頼は、非Windowsの[RF4120準拠](https://tools.ietf.org/html/rfc4120)のKerberosドメインとの間で確立されます。MIT信頼は、Windowsエコシステムの外部でKerberosベースのシステムとの統合を必要とする環境に特化しています。

#### **信頼関係の他の違い**

- 信頼関係は**推移的**（AがBを信頼し、BがCを信頼する場合、AはCを信頼する）または**非推移的**であることができます。
- 信頼関係は**双方向信頼**（両方が互いに信頼する）または**一方向信頼**（一方だけが他方を信頼する）として設定できます。

### 攻撃パス

1. **信頼関係を列挙**する
2. どの**セキュリティプリンシパル**（ユーザー/グループ/コンピュータ）が**他のドメインのリソースにアクセス**できるかを確認します。ACEエントリや他のドメインのグループにいることによって、**ドメイン間の関係**を探します（信頼がこのために作成された可能性があります）。
1. この場合、kerberoastが別のオプションになる可能性があります。
3. **アカウントを侵害**し、ドメインを通じて**ピボット**します。

攻撃者は、他のドメインのリソースにアクセスするために、主に3つのメカニズムを使用できます：

- **ローカルグループメンバーシップ**：プリンシパルは、サーバーの「Administrators」グループなどのマシンのローカルグループに追加されることがあり、そのマシンに対して重要な制御を与えます。
- **外国ドメイングループメンバーシップ**：プリンシパルは、外国ドメイン内のグループのメンバーでもあります。ただし、この方法の効果は、信頼の性質とグループの範囲に依存します。
- **アクセス制御リスト（ACL）**：プリンシパルは、特定のリソースへのアクセスを提供する**ACL**内の**ACE**のエンティティとして指定されることがあります。ACL、DACL、およびACEのメカニズムに深く入りたい方には、ホワイトペーパー「[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)」が貴重なリソースです。

### 子から親へのフォレスト権限昇格
```
Get-DomainTrust

SourceName      : sub.domain.local    --> current domain
TargetName      : domain.local        --> foreign domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST       --> WITHIN_FOREST: Both in the same forest
TrustDirection  : Bidirectional       --> Trust direction (2ways in this case)
WhenCreated     : 2/19/2021 1:28:00 PM
WhenChanged     : 2/19/2021 1:28:00 PM
```
> [!WARNING]
> **2つの信頼されたキー**があります。1つは_Child --> Parent_用、もう1つは_Parent_ --> _Child_用です。\
> 現在のドメインで使用されているものを次のコマンドで確認できます：
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

SID-Historyインジェクションを悪用して、子/親ドメインにエンタープライズ管理者として昇格します：

{{#ref}}
sid-history-injection.md
{{#endref}}

#### 書き込み可能なConfiguration NCの悪用

Configuration Naming Context (NC)がどのように悪用されるかを理解することは重要です。Configuration NCは、Active Directory (AD)環境内のフォレスト全体の構成データの中央リポジトリとして機能します。このデータはフォレスト内のすべてのドメインコントローラー (DC) に複製され、書き込み可能なDCはConfiguration NCの書き込み可能なコピーを保持します。これを悪用するには、**DC上でSYSTEM権限を持つ必要があります**。できれば子DCが望ましいです。

**GPOをルートDCサイトにリンクする**

Configuration NCのSitesコンテナには、ADフォレスト内のすべてのドメイン参加コンピュータのサイトに関する情報が含まれています。任意のDCでSYSTEM権限を持って操作することで、攻撃者はGPOをルートDCサイトにリンクできます。このアクションは、これらのサイトに適用されるポリシーを操作することによって、ルートドメインを危険にさらす可能性があります。

詳細情報については、[SIDフィルタリングのバイパス](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research)に関する研究を探ることができます。

**フォレスト内の任意のgMSAを妥協する**

攻撃ベクトルは、ドメイン内の特権gMSAをターゲットにすることです。gMSAのパスワードを計算するために必要なKDS Rootキーは、Configuration NC内に保存されています。任意のDCでSYSTEM権限を持つことで、KDS Rootキーにアクセスし、フォレスト内の任意のgMSAのパスワードを計算することが可能です。

詳細な分析は、[Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent)の議論で見つけることができます。

**スキーマ変更攻撃**

この方法は、新しい特権ADオブジェクトの作成を待つ忍耐が必要です。SYSTEM権限を持つ攻撃者は、ADスキーマを変更して、任意のユーザーにすべてのクラスに対する完全な制御を付与できます。これにより、新しく作成されたADオブジェクトへの不正アクセスと制御が可能になる可能性があります。

さらなる読み物は、[スキーマ変更信頼攻撃](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent)で利用できます。

**ADCS ESC5を使用してDAからEAへ**

ADCS ESC5の脆弱性は、フォレスト内の任意のユーザーとして認証を可能にする証明書テンプレートを作成するために、公開鍵基盤 (PKI) オブジェクトの制御をターゲットにしています。PKIオブジェクトはConfiguration NCに存在するため、書き込み可能な子DCを妥協することでESC5攻撃を実行できます。

この件に関する詳細は、[ESC5を使用してDAからEAへ](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c)で読むことができます。ADCSがないシナリオでは、攻撃者は必要なコンポーネントを設定する能力を持ち、[子ドメイン管理者からエンタープライズ管理者への昇格](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)で議論されています。

### 外部フォレストドメイン - 一方向（インバウンド）または双方向
```powershell
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes :
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM
```
このシナリオでは、**あなたのドメインが外部のドメインによって信頼されています**。これにより、**不明な権限**が与えられます。あなたは、**あなたのドメインのどのプリンシパルが外部ドメインに対してどのようなアクセス権を持っているかを見つけ**、それを悪用しようとする必要があります：

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### 外部フォレストドメイン - 一方向（アウトバウンド）
```powershell
Get-DomainTrust -Domain current.local

SourceName      : current.local   --> Current domain
TargetName      : external.local  --> Destination domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound        --> Outbound trust
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM
```
このシナリオでは、**あなたのドメイン**が**異なるドメイン**のプリンシパルに**特権**を**信頼**しています。

しかし、**ドメインが信頼される**と、信頼されたドメインは**予測可能な名前**の**ユーザーを作成**し、**信頼されたパスワード**を**パスワード**として使用します。これは、**信頼するドメインのユーザーにアクセスして信頼されたドメインに入る**ことが可能であり、それを列挙し、さらに特権を昇格させることを意味します：

{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

信頼されたドメインを侵害する別の方法は、ドメイン信頼の**逆方向**に作成された[**SQL信頼リンク**](abusing-ad-mssql.md#mssql-trusted-links)を見つけることです（これはあまり一般的ではありません）。

信頼されたドメインを侵害する別の方法は、**信頼されたドメインのユーザーがアクセスできる**マシンで待機し、**RDP**を介してログインすることです。次に、攻撃者はRDPセッションプロセスにコードを注入し、そこから**被害者の元のドメインにアクセス**できます。\
さらに、**被害者がハードドライブをマウントした場合**、攻撃者は**RDPセッション**プロセスから**ハードドライブのスタートアップフォルダー**に**バックドア**を保存できます。この技術は**RDPInception**と呼ばれます。

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### ドメイン信頼の悪用緩和

### **SIDフィルタリング：**

- SID履歴属性を利用した攻撃のリスクは、すべてのインターフォレスト信頼でデフォルトで有効になっているSIDフィルタリングによって緩和されます。これは、マイクロソフトの見解に従い、フォレストをセキュリティ境界と見なすことから、イントラフォレスト信頼が安全であるという前提に基づいています。
- しかし、注意が必要です：SIDフィルタリングはアプリケーションやユーザーアクセスに影響を与える可能性があり、そのため時折無効にされることがあります。

### **選択的認証：**

- インターフォレスト信頼の場合、選択的認証を使用することで、2つのフォレストのユーザーが自動的に認証されないようにします。代わりに、信頼するドメインまたはフォレスト内のドメインやサーバーにアクセスするためには明示的な権限が必要です。
- これらの対策は、書き込み可能な構成命名コンテキスト（NC）の悪用や信頼アカウントへの攻撃から保護するものではないことに注意が必要です。

[**ired.teamのドメイン信頼に関する詳細情報。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD

{% embed url="https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-lateral-movements/azure-ad-connect-hybrid-identity" %}

## 一般的な防御策

[**ここで資格情報を保護する方法について詳しく学ぶ。**](../stealing-credentials/credentials-protections.md)\\

### **資格情報保護のための防御策**

- **ドメイン管理者の制限**：ドメイン管理者はドメインコントローラーにのみログインできるようにし、他のホストでの使用を避けることが推奨されます。
- **サービスアカウントの特権**：サービスはセキュリティを維持するためにドメイン管理者（DA）特権で実行されるべきではありません。
- **一時的特権制限**：DA特権を必要とするタスクについては、その期間を制限する必要があります。これは次のように実現できます：`Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **欺瞞技術の実装**

- 欺瞞を実装するには、パスワードが期限切れにならないか、委任のために信頼されているとマークされたデコイユーザーやコンピュータのような罠を設定します。詳細なアプローチには、特定の権利を持つユーザーを作成したり、高特権グループに追加したりすることが含まれます。
- 実用的な例として、次のようなツールを使用します：`Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- 欺瞞技術の展開に関する詳細は、[Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception)で確認できます。

### **欺瞞の特定**

- **ユーザーオブジェクトの場合**：疑わしい指標には、異常なObjectSID、稀なログオン、作成日、低い不正パスワードカウントが含まれます。
- **一般的な指標**：潜在的なデコイオブジェクトの属性を本物のものと比較することで不一致を明らかにできます。[HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster)のようなツールが、こうした欺瞞を特定するのに役立ちます。

### **検出システムの回避**

- **Microsoft ATA検出回避**：
- **ユーザー列挙**：ドメインコントローラーでのセッション列挙を避け、ATA検出を防ぎます。
- **チケットの偽装**：チケット作成に**aes**キーを使用することで、NTLMにダウングレードせずに検出を回避します。
- **DCSync攻撃**：ATA検出を避けるために、ドメインコントローラーから直接実行するのではなく、非ドメインコントローラーから実行することが推奨されます。

## 参考文献

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

{{#include ../../banners/hacktricks-training.md}}
