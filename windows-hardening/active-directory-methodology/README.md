# Active Directory Methodology

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でAWSハッキングをゼロからヒーローまで学びましょう</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手してください
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをご覧ください
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)をフォローしてください。
- **HackTricks**と**HackTricks Cloud**のgithubリポジトリにPRを提出して、あなたのハッキングテクニックを共有してください。

</details>

## 基本的な概要

**Active Directory**は、**ネットワーク管理者**が**ドメイン**、**ユーザー**、および**オブジェクト**を効率的に作成および管理できるようにする基本技術として機能します。これはスケーラビリティが備わっており、膨大な数のユーザーを管理可能な**グループ**や**サブグループ**に整理し、さまざまなレベルで**アクセス権**を制御することを可能にしています。

**Active Directory**の構造は、**ドメイン**、**ツリー**、および**フォレスト**の3つの主要なレイヤーで構成されています。**ドメイン**は、共通のデータベースを共有する**ユーザー**や**デバイス**などのオブジェクトのコレクションを包括しています。**ツリー**は、これらのドメインを共有構造でリンクしたグループであり、**フォレスト**は、**信頼関係**によって相互に接続された複数のツリーのコレクションを表し、組織構造の最上位レイヤーを形成しています。これらのレベルごとに特定の**アクセス**および**通信権限**を指定できます。

**Active Directory**内の主要な概念には次のものがあります：

1. **ディレクトリ** - Active Directoryオブジェクトに関するすべての情報を保持します。
2. **オブジェクト** - **ユーザー**、**グループ**、または**共有フォルダ**などのディレクトリ内のエンティティを示します。
3. **ドメイン** - ディレクトリオブジェクトのコンテナとして機能し、各々が独自のオブジェクトコレクションを維持できる**フォレスト**内に複数のドメインが存在できます。
4. **ツリー** - 共通のルートドメインを共有するドメインのグループです。
5. **フォレスト** - Active Directoryの組織構造の最上位に位置する、複数のツリーから構成され、それらの間に**信頼関係**が形成されています。

**Active Directory Domain Services (AD DS)** は、ネットワーク内での中央集中管理と通信に不可欠なさまざまなサービスを含んでいます。これらのサービスには次が含まれます：

1. **ドメインサービス** - **ユーザー**と**ドメイン**の間のデータストレージを一元化し、**認証**や**検索**機能を含む相互作用を管理します。
2. **証明書サービス** - 安全な**デジタル証明書**の作成、配布、および管理を監督します。
3. **軽量ディレクトリサービス** - **LDAPプロトコル**を介してディレクトリ対応アプリケーションをサポートします。
4. **ディレクトリフェデレーションサービス** - 複数のWebアプリケーションで**シングルサインオン**機能を提供し、ユーザーの認証を単一セッションで行います。
5. **権利管理** - 著作権物資の不正な配布と使用を規制することで、著作権物資の保護を支援します。
6. **DNSサービス** - **ドメイン名**の解決に不可欠です。

詳細な説明については、[**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)を参照してください。

### **Kerberos認証**

**ADを攻撃**する方法を学ぶには、**Kerberos認証プロセス**を非常によく理解する必要があります。\
[**まだその動作方法を知らない場合は、このページを読んでください。**](kerberos-authentication.md)

## チートシート

[https://wadcoms.github.io/](https://wadcoms.github.io) にアクセスして、ADを列挙/悪用するために実行できるコマンドを簡単に確認できます。

## Active Directoryの調査（資格情報/セッションなし）

AD環境にアクセス権があるが、資格情報/セッションがない場合は、次のことができます：

- **ネットワークのペンテスト：**
- ネットワークをスキャンし、マシンとオープンポートを見つけ、そこから**脆弱性を悪用**したり、そこから**資格情報を抽出**したりします（たとえば、[プリンターは非常に興味深いターゲットになる場合があります](ad-information-in-printers.md)。
- DNSの列挙は、ドメイン内の重要なサーバー（Web、プリンター、共有、VPN、メディアなど）に関する情報を提供する可能性があります。
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- これを行う方法については、一般的な[**ペンテスト手法**](../../generic-methodologies-and-resources/pentesting-methodology.md)を参照してください。
- **SMBサービスでのnullおよびGuestアクセスを確認**（これは最新のWindowsバージョンでは機能しません）：
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- SMBサーバーを列挙する方法の詳細なガイドはこちら：

{% content-ref url="../../network-services-pentesting/pentesting-smb.md" %}
[pentesting-smb.md](../../network-services-pentesting/pentesting-smb.md)
{% endcontent-ref %}

- **LDAPの列挙**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- LDAPの列挙方法の詳細なガイドはこちら（**匿名アクセスに特に注意**を払ってください）：

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

- **ネットワークを汚染する**
- [Responderを使用してサービスをなりすまし](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)、資格情報を収集します
- [リレーアタックを悪用してホストにアクセス](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- [evil-Sを使用して偽のUPnPサービスを公開](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)し、資格情報を収集します
- [OSINT](https://book.hacktricks.xyz/external-recon-methodology)：
- 内部文書、ソーシャルメディア、ドメイン環境内のサービス（主にWeb）、および公開されている情報からユーザー名/名前を抽出します。
- 会社の従業員の完全な名前を見つけた場合、異なるAD **ユーザー名規則**を試すことができます（[**こちらを読んでください**](https://activedirectorypro.com/active-directory-user-naming-convention/)）。最も一般的な規則は、_NameSurname_、_Name.Surname_、_NamSur_（各3文字）、_Nam.Sur_、_NSurname_、_N.Surname_、_SurnameName_、_Surname.Name_、_SurnameN_、_Surname.N_、3つの_ランダムな文字と3つのランダムな数字_（abc123）です。
- ツール：
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### ユーザー列挙

- **匿名SMB/LDAP列挙：** [**SMBのペンテスト**](../../network-services-pentesting/pentesting-smb.md)および[**LDAPのペンテスト**](../../network-services-pentesting/pentesting-ldap.md)ページを参照してください。
- **Kerbrute列挙**：**無効なユーザー名が要求される**と、サーバーは**Kerberosエラー**コード _KRB5KDC\_ERR\_C\_PRINCIPAL\_UNKNOWN_ を使用して無効なユーザー名であることを示します。**有効なユーザー名**は、**AS-REP**応答内のTGTまたはエラー _KRB5KDC\_ERR\_PREAUTH\_REQUIRED_ を返し、ユーザーが事前認証を実行する必要があることを示します。
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
```
* **OWA (Outlook Web Access) サーバー**

ネットワーク内でこのようなサーバーを見つけた場合、**それに対してユーザー列挙を実行する**こともできます。たとえば、[**MailSniper**](https://github.com/dafthack/MailSniper)ツールを使用できます。
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
{% hint style="warning" %}
[**このGitHubリポジトリ**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)と[**このリポジトリ**](https://github.com/insidetrust/statistically-likely-usernames)でユーザー名のリストを見つけることができます。

ただし、これより前に実行すべきreconステップで**会社で働いている人の名前**を持っているはずです。名前と姓を持っている場合は、[**namemash.py**](https://gist.github.com/superkojiman/11076951)スクリプトを使用して潜在的な有効なユーザー名を生成できます。
{% endhint %}

### 1つまたは複数のユーザー名を知っている場合

よし、有効なユーザー名がわかっているがパスワードがわからない場合は、次のことを試してみてください:

* [**ASREPRoast**](asreproast.md): ユーザーが属性 _DONT\_REQ\_PREAUTH_ を持っていない場合、そのユーザーのために**AS\_REPメッセージをリクエスト**して、ユーザーのパスワードの派生によって暗号化されたデータを含むメッセージを取得できます。
* [**パスワードスプレー**](password-spraying.md): 発見されたユーザーごとに最も**一般的なパスワード**を試してみてください。おそらく、一部のユーザーが簡単なパスワードを使用しているかもしれません（パスワードポリシーに注意してください）。
* ユーザーのメールサーバーへのアクセスを試みるために、OWAサーバーにも**スプレー**を行うことができます。

{% content-ref url="password-spraying.md" %}
[password-spraying.md](password-spraying.md)
{% endcontent-ref %}

### LLMNR/NBT-NSポイズニング

**ネットワーク**のいくつかのプロトコルを**ポイズニング**して、いくつかのチャレンジ**ハッシュ**を取得して**クラック**できるかもしれません:

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

### NTMLリレー

Active Directoryを列挙した場合、**より多くの電子メール**と**ネットワークの理解**を得ることができます。NTML [**リレーアタック**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)を強制することで、AD環境へのアクセスを取得できるかもしれません。

### NTLMクレデンシャルの盗難

**他のPCや共有**に**アクセス**できる場合、**nullまたはguestユーザー**を使用して、（SCFファイルなどの）**ファイルを配置**して、何らかの方法でアクセスされると**NTML認証がトリガー**され、**NTLMチャレンジ**を盗むことができます:

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

## 資格情報/セッションを使用したActive Directoryの列挙

このフェーズでは、**有効なドメインアカウントの資格情報またはセッションを侵害する必要があります。** 有効な資格情報またはドメインユーザーとしてのシェルがある場合、**以前に与えられたオプションは他のユーザーを侵害するためのオプションであることを覚えておく必要があります**。

認証された列挙を開始する前に、**Kerberosダブルホップ問題**を知っておく必要があります。

{% content-ref url="kerberos-double-hop-problem.md" %}
[kerberos-double-hop-problem.md](kerberos-double-hop-problem.md)
{% endcontent-ref %}

### 列挙

アカウントを侵害することは、**全体のドメインを侵害し始める大きなステップ**です。なぜなら、**Active Directoryの列挙を開始**できるからです:

[**ASREPRoast**](asreproast.md)に関しては、今やすべての脆弱なユーザーを見つけることができ、[**パスワードスプレー**](password-spraying.md)に関しては、**すべてのユーザー名のリスト**を取得し、侵害されたアカウントのパスワード、空のパスワード、および新しい有望なパスワードを試すことができます。

* [**基本的なreconを実行するためのCMD**](../basic-cmd-for-pentesters.md#domain-info)を使用できます
* よりステルス性の高い[**powershell for recon**](../basic-powershell-for-pentesters/)を使用することもできます
* [**powerview**](../basic-powershell-for-pentesters/powerview.md)を使用して詳細な情報を抽出することもできます
* Active Directoryでのreconのための素晴らしいツールの1つは[**BloodHound**](bloodhound.md)です。**非常にステルス性が低い**（使用する収集方法による）、しかし**それを気にしない**場合は、ぜひ試してみてください。ユーザーがRDPできる場所を見つけたり、他のグループへのパスを見つけたりできます。
* **他の自動化されたAD列挙ツールには:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**があります。**
* [**ADのDNSレコード**](ad-dns-records.md)には興味深い情報が含まれている可能性があります。
* ディレクトリを列挙するために使用できる**GUIツール**は、**SysInternal** Suiteの**AdExplorer.exe**です。
* _userPassword_＆_unixUserPassword_フィールド、または_Description_のフィールドで資格情報を検索するために**ldapsearch**を使用してLDAPデータベースを検索できます。他の方法については、[PayloadsAllTheThingsのADユーザーコメント内のパスワード](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment)を参照してください。
* **Linux**を使用している場合、[**pywerview**](https://github.com/the-useless-one/pywerview)を使用してドメインを列挙できます。
* 自動化ツールも試すことができます:
* [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
* [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
*   **すべてのドメインユーザーを抽出**

Windowsからすべてのドメインユーザー名を取得するのは非常に簡単です（`net user /domain`、`Get-DomainUser`、または`wmic useraccount get name,sid`）。Linuxでは、`GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username`または`enum4linux -a -u "user" -p "password" <DC IP>`を使用できます。

> この列挙セクションは小さく見えるかもしれませんが、これがすべての中で最も重要な部分です。リンク（特にcmd、powershell、powerview、BloodHoundのリンク）にアクセスし、ドメインの列挙方法を学び、快適になるまで練習してください。アセスメント中、これはDAへの道を見つけるための鍵となる瞬間です。

### Kerberoast

Kerberoastingは、ユーザーアカウントに関連付けられたサービスによって使用される**TGSチケット**を取得し、その暗号化をクラックすることを含みます。この暗号化は、ユーザーパスワードに基づいており、**オフライン**で行われます。

詳細は以下を参照してください:

{% content-ref url="kerberoast.md" %}
[kerberoast.md](kerberoast.md)
{% endcontent-ref %}

### リモート接続（RDP、SSH、FTP、Win-RMなど）

一部の資格情報を取得した場合、さまざまなプロトコルを使用して複数のサーバーに接続を試みるために**CrackMapExec**を使用できます。

### ローカル特権昇格

通常のドメインユーザーとして資格情報またはセッションを取得し、ドメイン内の**任意のマシンにアクセス**できる場合は、**ローカル特権を昇格して資格情報を収集**する方法を見つけてみてください。これは、ローカル管理者特権を持っている場合にのみ、メモリ（LSASS）およびローカル（SAM）の他のユーザーのハッシュをダンプできるからです。

この本には[**Windowsでのローカル特権昇格**](../windows-local-privilege-escalation/)に関する完全なページと[**チェックリスト**](../checklist-windows-privilege-escalation.md)があります。また、[**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)を使用することも忘れないでください。

### 現在のセッションチケット

現在のユーザーに**アクセス権を与える**チケットを見つける可能性は非常に**低い**ですが、チェックしてみることができます:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTML Relay

アクティブディレクトリを列挙できた場合、**より多くのメールとネットワークの理解**が得られます。NTML [**リレーアタック**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**を強制できるかもしれません**。

### **コンピュータ共有内の資格情報を検索**

基本的な資格情報を持っている場合、AD内で**共有されている興味深いファイル**を見つけることができます。手動で行うこともできますが、非常に退屈で繰り返しの作業です（何百もの文書をチェックする必要がある場合はさらにそうです）。

[**こちらのリンクを参照して使用できるツールについて学びます。**](../../network-services-pentesting/pentesting-smb.md#domain-shared-folders-search)

### NTLM資格情報の盗み出し

他のPCや共有に**アクセスできる**場合、（SCFファイルなど）**ファイルを配置**して、何らかの方法でアクセスされると**NTML認証があなたに対してトリガー**され、**NTLMチャレンジを盗む**ことができます。

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

この脆弱性により、認証済みユーザーはドメインコントローラーを**侵害**することができました。

{% content-ref url="printnightmare.md" %}
[printnightmare.md](printnightmare.md)
{% endcontent-ref %}

## 特権昇格：特権付き資格情報/セッションを使用したActive Directory上での特権昇格

**次のテクニックにおいては、通常のドメインユーザーでは不十分であり、これらの攻撃を実行するために特別な特権/資格情報が必要です。**

### ハッシュ抽出

[AsRepRoast](asreproast.md)、[Password Spraying](password-spraying.md)、[Kerberoast](kerberoast.md)、[Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)（リレーを含む）、[EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)、[ローカル特権昇格](../windows-local-privilege-escalation/)を使用して、**いくつかのローカル管理者アカウントを侵害**できたことを願っています。\
その後、メモリとローカルに保存されているすべてのハッシュをダンプする時が来ました。\
[**異なるハッシュを取得する方法についてのこのページを読んでください。**](broken-reference/)

### ハッシュの渡し

**ユーザーのハッシュを持っている場合**、それを使用して**そのユーザーをなりすます**ことができます。\
その**ハッシュを使用して**NTLM認証を実行する**ツール**を使用する必要があります。**または**新しい**セッションログオン**を作成し、その**ハッシュ**を**LSASS**内に**インジェクト**することができます。したがって、**NTLM認証が実行されると、そのハッシュが使用されます。**最後のオプションがmimikatzが行うことです。\
[**詳細についてはこのページを参照してください。**](../ntlm/#pass-the-hash)

### ハッシュの渡し/キーの渡し

この攻撃は、一般的なPass The Hash over NTLMプロトコルの代替として、**ユーザーNTLMハッシュを使用してKerberosチケットを要求**することを目的としています。したがって、これは**NTLMプロトコルが無効**になっており、認証プロトコルとして**Kerberosのみが許可**されているネットワークで特に**有用**です。

{% content-ref url="over-pass-the-hash-pass-the-key.md" %}
[over-pass-the-hash-pass-the-key.md](over-pass-the-hash-pass-the-key.md)
{% endcontent-ref %}

### チケットの渡し

**Pass The Ticket (PTT)**攻撃方法では、攻撃者はユーザーのパスワードやハッシュ値ではなく、**ユーザーの認証チケットを盗みます**。この盗まれたチケットは、ユーザーをなりすまして、ネットワーク内のリソースやサービスに不正アクセスを取得します。

{% content-ref url="pass-the-ticket.md" %}
[pass-the-ticket.md](pass-the-ticket.md)
{% endcontent-ref %}

### 資格情報の再利用

**ローカル管理者のハッシュ**または**パスワード**を持っている場合、それを使用して他の**PCにローカルログイン**を試みる必要があります。
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
{% hint style="warning" %}
これはかなり**ノイズが多い**ため、**LAPS** がこれを**軽減**するでしょう。
{% endhint %}

### MSSQLの悪用と信頼されたリンク

ユーザーが**MSSQLインスタンスにアクセス権**を持っている場合、それを使用してMSSQLホストでコマンドを**実行**したり（SAとして実行されている場合）、NetNTLM **ハッシュを盗む**か、**リレー攻撃**を実行することができるかもしれません。\
また、MSSQLインスタンスが別のMSSQLインスタンスに信頼されている場合（データベースリンク）。ユーザーが信頼されたデータベースに権限を持っている場合、その信頼関係を使用して他のインスタンスでもクエリを実行できます。これらの信頼関係は連鎖する可能性があり、ユーザーは誤って構成されたデータベースを見つけてそこでコマンドを実行できるかもしれません。\
**データベース間のリンクはフォレストトラストを超えて機能します。**

{% content-ref url="abusing-ad-mssql.md" %}
[abusing-ad-mssql.md](abusing-ad-mssql.md)
{% endcontent-ref %}

### 制約のない委任

[ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx)属性を持つコンピューターオブジェクトを見つけ、そのコンピューターでドメイン権限を持っている場合、そのコンピューターにログインするすべてのユーザーのTGTをメモリからダンプできます。\
したがって、**ドメイン管理者がそのコンピューターにログイン**すると、彼のTGTをダンプして[チケット渡し](pass-the-ticket.md)を使用して彼を偽装できます。\
制約付き委任を使用すると、**プリントサーバーを自動的に侵害**することさえできます（うまくいけばDCである可能性があります）。

{% content-ref url="unconstrained-delegation.md" %}
[unconstrained-delegation.md](unconstrained-delegation.md)
{% endcontent-ref %}

### 制約付き委任

ユーザーまたはコンピューターが「制約付き委任」に許可されている場合、そのユーザー/コンピューターはコンピューター内の一部のサービスにアクセスするために**任意のユーザーを偽装**できます。\
その後、このユーザー/コンピューターのハッシュを**妥協**すると、一部のサービスにアクセスするために**任意のユーザー**（ドメイン管理者さえも）を**偽装**できるようになります。

{% content-ref url="constrained-delegation.md" %}
[constrained-delegation.md](constrained-delegation.md)
{% endcontent-ref %}

### リソースベースの制約委任

リモートコンピューターのActive Directoryオブジェクトに**WRITE**権限があると、**昇格権限を持つコードの実行**が可能になります：

{% content-ref url="resource-based-constrained-delegation.md" %}
[resource-based-constrained-delegation.md](resource-based-constrained-delegation.md)
{% endcontent-ref %}

### ACLの悪用

侵害されたユーザーは、いくつかの**ドメインオブジェクトに対する興味深い権限**を持っている可能性があり、それにより**横断的に移動**したり、**権限を昇格**したりできるかもしれません。

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### プリンタースプーラーサービスの悪用

ドメイン内で**スプールサービスがリスニング**されていることがわかれば、これを**悪用**して**新しい資格情報を取得**し、**権限を昇格**させることができます。

{% content-ref url="acl-persistence-abuse/" %}
[printers-spooler-service-abuse](printers-spooler-service-abuse.md)
{% endcontent-ref %}

### サードパーティーセッションの悪用

**他のユーザー**が**侵害された**マシンに**アクセス**する場合、そのユーザーのメモリから**資格情報を収集**し、さらにはそのプロセスに**ビーコンをインジェクト**して彼らを偽装することが可能です。\
通常、ユーザーはRDP経由でシステムにアクセスしますので、ここではサードパーティーRDPセッションに対していくつかの攻撃を実行する方法があります：

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### LAPS

**LAPS**は、ドメインに参加したコンピューターの**ローカル管理者パスワード**を管理するシステムを提供し、**ランダム化**され、一意で頻繁に**変更**されることを保証します。これらのパスワードはActive Directoryに保存され、アクセスは認可されたユーザーのみが制御します。これらのパスワードにアクセスする十分な権限があれば、他のコンピューターにピボットすることが可能になります。

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

### 証明書の盗難

侵害されたマシンから**証明書を収集**することは、環境内で権限を昇格する方法となります：

{% content-ref url="ad-certificates/certificate-theft.md" %}
[certificate-theft.md](ad-certificates/certificate-theft.md)
{% endcontent-ref %}

### 証明書テンプレートの悪用

**脆弱なテンプレート**が構成されている場合、それらを悪用して権限を昇格することが可能です：

{% content-ref url="ad-certificates/domain-escalation.md" %}
[domain-escalation.md](ad-certificates/domain-escalation.md)
{% endcontent-ref %}

## 高権限アカウントでの事後侵害

### ドメイン資格情報のダンプ

**ドメイン管理者**またはさらに**エンタープライズ管理者**権限を取得すると、**ドメインデータベース**： _ntds.dit_を**ダンプ**できます。

[**DCSync攻撃に関する詳細情報はこちら**](dcsync.md)。

[**NTDS.ditを盗む方法に関する詳細情報はこちら**](broken-reference/)

### 権限昇格としての持続性

以前に議論されたいくつかの技術は持続性のために使用できます。\
例えば、次のようにすることができます：

*   ユーザーを[Kerberoastに脆弱にする](kerberoast.md)

```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```
*   ユーザーを[ASREPRoastに脆弱にする](asreproast.md)

```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
*   ユーザーに[DCSync権限を付与する](./#dcsync)

```powershell
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### シルバーチケット

**シルバーチケット攻撃**は、特定のサービスのために**NTLMハッシュ**（たとえば、PCアカウントのハッシュ）を使用して**正当なチケット発行サービス（TGS）チケット**を作成します。この方法は、サービス権限にアクセスするために使用されます。

{% content-ref url="silver-ticket.md" %}
[silver-ticket.md](silver-ticket.md)
{% endcontent-ref %}

### ゴールデンチケット

**ゴールデンチケット攻撃**は、Active Directory（AD）環境で**krbtgtアカウントのNTLMハッシュ**にアクセスする攻撃です。このアカウントは、すべての**チケット発行チケット（TGT）**に署名するために使用される特別なアカウントであり、ADネットワーク内で認証するために不可欠です。

攻撃者がこのハッシュを取得すると、任意のアカウントのためにTGTを作成できるようになります（シルバーチケット攻撃）。

{% content-ref url="golden-ticket.md" %}
[golden-ticket.md](golden-ticket.md)
{% endcontent-ref %}

### ダイヤモンドチケット

これらは一般的なゴールデンチケット検出メカニズムを**バイパス**する方法で作成されたゴールデンチケットのようなものです。

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### **証明書アカウントの持続性**

**アカウントの証明書を持っているか、それらをリクエストできる**ということは、そのアカウントで持続する非常に良い方法です（パスワードを変更しても）：

{% content-ref url="ad-certificates/account-persistence.md" %}
[account-persistence.md](ad-certificates/account-persistence.md)
{% endcontent-ref %}

### **証明書ドメインの持続性**

**証明書を使用することで、ドメイン内で高い権限で持続することも可能です**：

{% content-ref url="ad-certificates/domain-persistence.md" %}
[domain-persistence.md](ad-certificates/domain-persistence.md)
{% endcontent-ref %}

### AdminSDHolderグループ

Active Directoryの**AdminSDHolder**オブジェクトは、特権グループ（ドメイン管理者やエンタープライズ管理者など）のセキュリティを確保するために、これらのグループ全体に標準の**アクセス制御リスト（ACL）**を適用します。ただし、この機能は悪用される可能性があります。攻撃者がAdminSDHolderのACLを変更して通常のユーザーに完全アクセス権を与えると、そのユーザーはすべての特権グループに広範な制御権を持つことになります。この保護機能は、監視が十分でない限り、不正なアクセスを許可する可能性があります。

[**AdminDSHolderグループに関する詳細情報はこちら。**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM資格情報

すべての**ドメインコントローラー（DC）**には、**ローカル管理者**アカウントが存在します。そのようなマシンで管理者権限を取得すると、**mimikatz**を使用してローカル管理者ハッシュを抽出し、このパスワードを使用できるようにするためにレジストリの変更が必要です。これにより、ローカル管理者アカウントへのリモートアクセスが可能になります。

{% content-ref url="dsrm-credentials.md" %}
[dsrm-credentials.md](dsrm-credentials.md)
{% endcontent-ref %}

### ACL持続性

将来的に**権限を昇格**できるように、特定のドメインオブジェクトに対して**ユーザーに**いくつかの**特別な権限**を与えることができます。

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### セキュリティ記述子

**セキュリティ記述子**は、オブジェクトが持つ**権限**を格納するために使用されます。オブジェクトの**セキュリティ記述子**をわずかに変更するだけで、特権グループのメンバーである必要がなく、そのオブジェクトに対して非常に興味深い権限を取得できます。

{% content-ref url="security-descriptors.md" %}
[security-descriptors.md](security-descriptors.md)
{% endcontent-ref %}

### スケルトンキー

**LSASS**をメモリ内で変更して、すべてのドメインアカウントにアクセス権を与える**ユニバーサルパスワード**を設定します。

{% content-ref url="skeleton-key.md" %}
[skeleton-key.md](skeleton-key.md)
{% endcontent-ref %}

### カスタムSSP

[ここでSSP（セキュリティサポートプロバイダ）とは何かを学びます。](../authentication-credentials-uac-and-efs.md#security-support-provider-interface-sspi)\
**独自のSSP**を作成して、マシンへのアクセスに使用される**資格情報を平文でキャプチャ**することができます。

{% content-ref url="custom-ssp.md" %}
[custom-ssp.md](custom-ssp.md)
{% endcontent-ref %}

### DCShadow

これは新しい**ドメインコントローラー**をADに登録し、指定されたオブジェクトに（SIDHistory、SPNなど）を**ログなしでプッシュ**するために使用します。**DA権限**と**ルートドメイン**内にいる必要があります。\
間違ったデータを使用すると、非常に
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
{% hint style="warning" %}
**信頼されたキーは2つ**あります。1つは_Child --> Parent_用で、もう1つは_Parent_ --> _Child_用です。\
現在のドメインで使用されているキーは次のようにして確認できます:
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
```
{% endhint %}

#### SID-History Injection

信頼関係を悪用して、子/親ドメインへのエンタープライズ管理者の昇格をSID-Historyインジェクションで行います：

{% content-ref url="sid-history-injection.md" %}
[sid-history-injection.md](sid-history-injection.md)
{% endcontent-ref %}

#### Exploit writeable Configuration NC

Configuration Naming Context（NC）の悪用方法を理解することは重要です。Configuration NCは、Active Directory（AD）環境全体での構成データの中央リポジトリとして機能します。このデータは、森林内のすべてのドメインコントローラ（DC）にレプリケートされ、書き込み可能なDCはConfiguration NCの書き込み可能なコピーを維持します。これを悪用するには、**DC上でSYSTEM権限**を持っている必要があります。できれば子DCです。

**ルートDCサイトにGPOをリンク**

Configuration NCのSitesコンテナには、ADフォレスト内のすべてのドメイン参加コンピュータのサイトに関する情報が含まれています。任意のDCでSYSTEM権限で操作することで、攻撃者はGPOをルートDCサイトにリンクすることができます。この操作は、これらのサイトに適用されるポリシーを操作することで、ルートドメインを潜在的に危険にさらす可能性があります。

詳細な情報については、[SIDフィルタリングのバイパス](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research)の研究を探求することができます。

**フォレスト内の任意のgMSAを妥協する**

攻撃ベクトルには、ドメイン内の特権のあるgMSAを標的とすることが含まれます。gMSAのパスワードを計算するために必要なKDSルートキーは、Configuration NC内に保存されています。任意のDCでSYSTEM権限を持っている場合、フォレスト全体の任意のgMSAのパスワードを計算することができます。

詳細な分析は、[ゴールデンgMSAトラスト攻撃](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent)の議論で見つけることができます。

**スキーマ変更攻撃**

この方法には、新しい特権のあるADオブジェクトの作成を待つ忍耐が必要です。SYSTEM権限を持つ攻撃者は、ADスキーマを変更して、任意のユーザーにすべてのクラスの完全な制御を付与することができます。これにより、新しく作成されたADオブジェクトに対する未承認のアクセスと制御が可能になります。

詳細については、[スキーマ変更トラスト攻撃](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent)で読むことができます。

**DAからEAへのADCS ESC5**

ADCS ESC5脆弱性は、PKIオブジェクトの制御をターゲットにして、フォレスト内の任意のユーザーとして認証を可能にする証明書テンプレートを作成します。PKIオブジェクトはConfiguration NCに存在するため、書き込み可能な子DCを妥協することでESC5攻撃を実行できます。

これについての詳細は、[DAからEAへのESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c)で読むことができます。ADCSがないシナリオでは、攻撃者は[子ドメイン管理者からエンタープライズ管理者への昇格](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)を設定する能力を持っています。

### 外部フォレストドメイン - 片方向（インバウンド）または双方向
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
このシナリオでは、**外部ドメインが信頼している**状況で、**未確定の権限**を持っています。**あなたのドメインのどの主体が外部ドメインに対してどのようなアクセス権を持っているか**を見つけ、それを悪用しようとします:

{% content-ref url="external-forest-domain-oneway-inbound.md" %}
[external-forest-domain-oneway-inbound.md](external-forest-domain-oneway-inbound.md)
{% endcontent-ref %}

### 外部フォレストドメイン - ワンウェイ（アウトバウンド）
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
このシナリオでは、**あなたのドメイン**が**別のドメイン**から**特権を委任**しています。

しかし、信頼するドメインによって信頼されるドメインが**予測可能な名前**のユーザーを**作成**し、そのユーザーの**パスワードに信頼されるパスワード**を使用することがあります。これは、信頼するドメインからのユーザーを**使用して信頼されるドメインに侵入**し、それを列挙してさらなる特権を昇格させる可能性があることを意味します：

{% content-ref url="external-forest-domain-one-way-outbound.md" %}
[external-forest-domain-one-way-outbound.md](external-forest-domain-one-way-outbound.md)
{% endcontent-ref %}

信頼されるドメインを侵害する別の方法は、ドメイン信頼の**逆方向**に作成された[**SQL信頼リンク**](abusing-ad-mssql.md#mssql-trusted-links)を見つけることです（これは非常に一般的ではありません）。

信頼されるドメインを侵害する別の方法は、信頼されるドメインのユーザーがアクセスできるマシンで待機し、**RDP**経由でログインすることができるようにすることです。その後、攻撃者はRDPセッションプロセスにコードをインジェクトし、そこから被害者の元のドメインにアクセスできます。\
さらに、被害者が**ハードドライブをマウント**している場合、攻撃者はRDPセッションプロセスから**ハードドライブのスタートアップフォルダーにバックドア**を保存できます。この技術は**RDPInception**と呼ばれます。

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### ドメイン信頼の乱用の緩和

### **SIDフィルタリング:**

- フォレスト間の信頼に関連する攻撃リスクは、SIDフィルタリングによって緩和されます。これは、すべてのフォレスト間信頼でデフォルトで有効になっています。これは、フォレストではなくドメインをセキュリティ境界と見なすことに基づいています。
- ただし、SIDフィルタリングには注意が必要です。SIDフィルタリングは、アプリケーションやユーザーアクセスに支障をきたす可能性があり、時折無効になることがあります。

### **選択的認証:**

- フォレスト間の信頼において、選択的認証を使用することで、2つのフォレストからのユーザーが自動的に認証されないようにします。代わりに、ユーザーが信頼するドメインまたはフォレスト内のドメインやサーバーにアクセスするためには、明示的なアクセス許可が必要です。
- これらの対策は、書き込み可能な構成名前コンテキスト（NC）の悪用や信頼アカウントへの攻撃に対して保護されないことに注意することが重要です。

[**ired.teamでドメイン信頼に関する詳細情報を入手してください。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD

{% embed url="https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-lateral-movements/azure-ad-connect-hybrid-identity" %}

## 一般的な防御策

[**こちらで資格情報の保護方法について詳しく学びましょう。**](../stealing-credentials/credentials-protections.md)\

### **資格情報保護の防御策**

- **ドメイン管理者の制限**: ドメイン管理者はドメインコントローラーにのみログインできるように制限されるべきです。他のホストでの使用は避けるべきです。
- **サービスアカウントの特権**: サービスはドメイン管理者（DA）特権で実行されるべきではなく、セキュリティを維持するためにはそうすべきです。
- **一時的な特権制限**: DA特権が必要なタスクについては、その期間を制限するべきです。これは次のように実現できます: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **欺瞞技術の実装**

- 欺瞞の実装には、罠を設定することが含まれます。例えば、期限切れでないパスワードや信頼されたデータとしてマークされたパスワードなどの特徴を持つデコイユーザーやコンピュータを設定します。具体的なアプローチには、特定の権限を持つユーザーを作成したり、高特権グループに追加したりすることが含まれます。
- 実際の例には、次のようなツールの使用があります: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- 欺瞞技術の展開に関する詳細は、[GitHubのDeploy-Deception](https://github.com/samratashok/Deploy-Deception)で見つけることができます。

### **欺瞞の特定**

- **ユーザーオブジェクトの場合**: 異常なObjectSID、頻度の低いログオン、作成日、および低い不正なパスワード回数など、疑わしい指標があります。
- **一般的な指標**: 潜在的なデコイオブジェクトの属性を本物のオブジェクトと比較することで、不一致を明らかにすることができます。[HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster)などのツールを使用して、そのような欺瞞を特定するのに役立ちます。

### **検出システムの回避**

- **Microsoft ATA検出の回避**:
- **ユーザー列挙**: ATA検出を回避するために、ドメインコントローラーでのセッション列挙を避けることが重要です。
- **チケット詐称**: チケット作成に**aes**キーを使用することで、NTLMへのダウングレードを行わずに検出を回避できます。
- **DCSync攻撃**: ATA検出を回避するために、ドメインコントローラーから直接実行するのではなく、非ドメインコントローラーから実行することが推奨されます。

## 参考文献

* [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
* [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

<details>

<summary><strong>**htARTE（HackTricks AWS Red Team Expert）**で**ゼロからヒーローまでのAWSハッキング**を学びましょう！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksで企業を宣伝**したり、**HackTricksをPDFでダウンロード**したりするには、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう
* 独占的な[NFTs](https://opensea.io/collection/the-peass-family)を含む、[**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォロー**しましょう。
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks)のGitHubリポジトリにPRを提出して、自分のハッキングトリックを共有しましょう。

</details>
