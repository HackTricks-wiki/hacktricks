# Active Directory Methodology

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## 基本的な概要

Active Directoryは、ネットワーク管理者がネットワーク内のドメイン、ユーザー、およびオブジェクトを作成および管理することを可能にします。たとえば、管理者はユーザーグループを作成し、サーバー上の特定のディレクトリへのアクセス権を与えることができます。ネットワークが成長するにつれて、Active Directoryは大量のユーザーを論理的なグループやサブグループに整理し、各レベルでアクセス制御を提供します。

Active Directoryの構造には、以下の3つの主要な階層があります：1）ドメイン、2）ツリー、および3）フォレスト。同じデータベースを使用する複数のオブジェクト（ユーザーまたはデバイス）は、単一のドメインにグループ化される場合があります。複数のドメインは、ツリーと呼ばれる単一のグループに組み合わされることができます。複数のツリーは、フォレストと呼ばれるコレクションにグループ化されることができます。これらのレベルのそれぞれに特定のアクセス権と通信特権を割り当てることができます。

Active Directoryは、次のようなさまざまなサービスを提供します。これらのサービスは、「Active Directoryドメインサービス」とも呼ばれます。

1. **ドメインサービス** - 集中データを格納し、ユーザーとドメイン間の通信を管理します。ログイン認証や検索機能を含みます。
2. **証明書サービス** - 安全な証明書の作成、配布、および管理を行います。
3. **軽量ディレクトリサービス** - オープンな（LDAP）プロトコルを使用してディレクトリ対応アプリケーションをサポートします。
4. **ディレクトリフェデレーションサービス** - シングルサインオン（SSO）を提供し、1つのセッションで複数のWebアプリケーションでユーザーを認証します。
5. **権利管理** - 著作権情報を保護し、デジタルコンテンツの未承認使用と配布を防止します。
6. **DNSサービス** - ドメイン名を解決するために使用されます。

AD DSは、Windows Server（Windows Server 10を含む）に含まれており、クライアントシステムを管理するために設計されています。通常のWindowsバージョンを実行しているシステムには、AD DSの管理機能はありませんが、Active Directoryをサポートしています。これは、ユーザーが正しいログイン資格情報を持っている場合、任意のWindowsコンピュータがWindowsワークグループに接続できることを意味します。\
**From:** [**https://techterms.com/definition/active\_directory**](https://techterms.com/definition/active\_directory)

### **Kerberos認証**

ADを攻撃するためには、**Kerberos認証プロセス**を非常によく理解する必要があります。\
[**まだどのように機能するかわからない場合は、このページを読んでください。**](kerberos-authentication.md)

## チートシート

[https://wadcoms.github.io/](https://wadcoms.github.io)にアクセスして、ADの列挙/攻撃に実行できるコマンドを簡単に確認できます。

## Active Directoryのリコン（認証情報/セッションなし）

AD環境にアクセス権しかない場合でも、次の操作を行うことができます：

* **ネットワークのペンテスト：**
* ネットワークをスキャンし、マシンとオープンポートを見つけ、それらから**脆弱性を攻撃**したり、**認証情報を抽出**したりします（たとえば、[プリンターは非常に興味深いターゲットになる場合があります](ad-information-in-printers.md)）。
* DNSの列挙は、ドメイン内の重要なサーバー（Web、プリンター、共有、VPN、メディアなど）に関する情報を提供する場合があります。
* `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
* より詳細な情報については、一般的な[**ペンテスト手法**](../../generic-methodologies-and-resources/pentesting-methodology.md)を参照してください。
* **SMBサービスでのnullおよびGuestアクセスをチェック**（これは最新のWindowsバージョンでは機能しません）：
* `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
* `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
* `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
* SMBサーバーの列挙についての詳細
* [**リレーアタックを悪用して**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)ホストにアクセスする
* [**evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)を使用して[**偽のUPnPサービスを公開**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)し、資格情報を収集する
* [**OSINT**](https://book.hacktricks.xyz/external-recon-methodology):
* ドメイン環境内および公開されている内部ドキュメント、ソーシャルメディア、サービス（主にWeb）からユーザー名/名前を抽出する
* 会社の従業員の完全な名前を見つけた場合、異なるAD **ユーザー名の規則**を試すことができます（[**こちらを参照**](https://activedirectorypro.com/active-directory-user-naming-convention/)）
* 最も一般的な規則は次のとおりです：_NameSurname_、_Name.Surname_、_NamSur_（各3文字）、_Nam.Sur_、_NSurname_、_N.Surname_、_SurnameName_、_Surname.Name_、_SurnameN_、_Surname.N_、3 _ランダムな文字と3つのランダムな数字_（abc123）。
* ツール：
* [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
* [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### ユーザー列挙

* **匿名SMB/LDAP列挙：** [**SMBのペントesting**](../../network-services-pentesting/pentesting-smb.md)と[**LDAPのペントesting**](../../network-services-pentesting/pentesting-ldap.md)ページを確認してください。
* **Kerbrute列挙：** **無効なユーザー名が要求**されると、サーバーは**Kerberosエラー**コード_KRB5KDC\_ERR\_C\_PRINCIPAL\_UNKNOWN_を使用して応答し、ユーザー名が無効であることを判断できます。**有効なユーザー名**は、AS-REP応答内の**TGT**またはエラー_KRB5KDC\_ERR\_PREAUTH\_REQUIRED_を引き起こし、ユーザーが事前認証を実行する必要があることを示します。
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
```
* **OWA (Outlook Web Access) サーバー**

ネットワーク内でこのようなサーバーを見つけた場合、それに対して**ユーザー列挙を実行する**こともできます。例えば、[**MailSniper**](https://github.com/dafthack/MailSniper)というツールを使用することができます。
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
[**このGitHubリポジトリ**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)と[**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)にユーザー名のリストがあります。

ただし、これより前の調査ステップで会社で働いている人々の**名前を知っている**必要があります。名前と姓を持っていれば、スクリプト[**namemash.py**](https://gist.github.com/superkojiman/11076951)を使用して潜在的な有効なユーザー名を生成できます。
{% endhint %}

### 1つまたは複数のユーザー名を知っている場合

すでに有効なユーザー名を持っているが、パスワードがわからない場合は、次の方法を試してみてください：

* [**ASREPRoast**](asreproast.md)：ユーザーが属性_DONT_REQ_PREAUTH_を持っていない場合、そのユーザーのAS_REPメッセージをリクエストできます。このメッセージには、ユーザーのパスワードの派生によって暗号化されたデータが含まれます。
* [**パスワードスプレー**](password-spraying.md)：発見された各ユーザーに対して最も**一般的なパスワード**を試してみてください。おそらく、いくつかのユーザーが弱いパスワードを使用しているかもしれません（パスワードポリシーに注意してください）。
* ユーザーのメールサーバーへのアクセスを試みるために、OWAサーバーにも**スプレー**を行うことができます。

{% content-ref url="password-spraying.md" %}
[password-spraying.md](password-spraying.md)
{% endcontent-ref %}

### LLMNR/NBT-NSポイズニング

ネットワークのいくつかのプロトコルを**ポイズニング**することで、いくつかのチャレンジ**ハッシュ**を取得できるかもしれません：

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

### NTMLリレー

Active Directoryを列挙するためには、**Active Directoryの列挙ツール**を使用することができます。これにより、**メールアドレスが増え、ネットワークの理解が深まる**かもしれません。NTML [**リレーアタック**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)を強制することで、AD環境へのアクセスを取得できるかもしれません。

### NTLMクレデンシャルの盗難

**nullまたはguestユーザー**を使用して他のPCや共有にアクセスできる場合、SCFファイルなどの**ファイルを配置**することができます。これらのファイルがいずれかの方法でアクセスされると、あなたに対してNTML認証がトリガーされるため、NTLMチャレンジを**盗む**ことができます。

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

## 認証情報/セッションを使用してActive Directoryを列挙する

このフェーズでは、**有効なドメインアカウントの認証情報またはセッションを侵害**する必要があります。有効な認証情報またはドメインユーザーとしてのシェルを持っている場合、前述のオプションは他のユーザーを侵害するためのオプションとして引き続き使用できます。

認証された列挙を開始する前に、**Kerberosのダブルホップ問題**を理解しておく必要があります。

{% content-ref url="kerberos-double-hop-problem.md" %}
[kerberos-double-hop-problem.md](kerberos-double-hop-problem.md)
{% endcontent-ref %}

### 列挙

アカウントを侵害することは、**ドメイン全体を侵害するための大きなステップ**です。なぜなら、**Active Directoryの列挙**を開始できるからです：

[**ASREPRoast**](asreproast.md)に関しては、可能な脆弱なユーザーをすべて見つけることができます。[**パスワードスプレー**](password-spraying.md)に関しては、**すべてのユーザー名のリスト**を取得し、侵害されたアカウントのパスワード、空のパスワード、および有望な新しいパスワードを試すことができます。

* [**基本的なリコンのためのCMD**](../basic-cmd-for-pentesters.md#domain-info)を使用することができます。
* よりステルス性の高い[**powershell for recon**](../basic-powershell-for-pentesters/)を使用することもできます。
* [**powerview**を使用](../basic-powershell-for-pentesters/powerview.md)して詳細な情報を抽出することもできます。
* Active Directoryでのリコンには、[**BloodHound**](bloodhound.md)という素晴らしいツールもあります。**ステルス性はあまり高くありません**（使用する収集方法によります）が、それを気にしないのであれば、ぜひ試してみてください。ユーザーがRDPできる場所を見つけたり、他のグループへのパスを見つけたりできます。
* **他の自動化されたAD列挙ツールには、**[**AD Explorer**](bloodhound.md#ad-explorer)**、**[**ADRecon**](bloodhound.md#adrecon)**、**[**Group3r**](bloodhound.md#group3r)**、**[**PingCastle**](bloodhound.md#pingcastle)**があります。**
* **ADのDNSレコード**（ad-dns-records.md）には興味深い情報が含まれている場合があります。
* ディレクトリを列挙するための**GUIツール**として、**SysInternal** Suiteの**AdExplorer.exe**を使用することができます。
* **ldapsearch**を使用してLDAPデータベースを検索し、_userPassword_＆_unixUserPassword_フィールド、または_Description_フィールドなどの資格情報を検索することもできます。他の方法については、[PayloadsAllTheThingsのAD User commentのPassword](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment)を参照してください。
* **Linux**を使用している場合、[**pywerview**](https://github.com/the-useless-one/pywerview)を使用してドメインを列挙することもできます。
* 以下の自動化ツールも試すことができます：
* [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
* [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
* **すべてのドメインユーザーを抽出する**

Windowsでは、非常に簡単にドメインのユーザー名を取得できます（`net user /domain`、`Get-DomainUser`、または`wmic useraccount get name,sid`）。Linuxでは、次のコマンドを使用できます：`GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username`または`enum4linux -a
### Kerberoast（Kerberoast）

Kerberoastの目的は、ドメインユーザーアカウントの代わりに実行されるサービスのためのTGSチケットを収集することです。これらのTGSチケットの一部は、ユーザーパスワードから派生したキーで暗号化されています。その結果、これらの資格情報はオフラインでクラックされる可能性があります。
詳細については、[kerberoast.md](kerberoast.md)を参照してください。

### リモート接続（RDP、SSH、FTP、Win-RMなど）

いくつかの資格情報を入手したら、どのマシンにアクセスできるかを確認できます。そのために、ポートスキャンに応じて、さまざまなプロトコルを使用していくつかのサーバーに接続を試みるために、CrackMapExecを使用することができます。

### ローカル特権昇格

もし、侵害された資格情報や通常のドメインユーザーとしてのセッションがあり、ドメイン内の任意のマシンにこのユーザーでアクセスできる場合、ローカル特権昇格の方法を見つけて特権を昇格させ、資格情報を盗むことを試すべきです。これは、ローカル管理者特権を持っている場合にのみ、メモリ（LSASS）およびローカル（SAM）の他のユーザーのハッシュをダンプすることができるからです。

この本には、[Windowsのローカル特権昇格に関する完全なページ](../windows-local-privilege-escalation/)と[チェックリスト](../checklist-windows-privilege-escalation.md)があります。また、[WinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)を使用することも忘れないでください。

### 現在のセッションチケット

現在のユーザーのチケットには、予期しないリソースへのアクセス権が与えられることは非常にまれですが、確認することができます。
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTML Relay

アクティブディレクトリの列挙に成功した場合、**より多くのメールとネットワークの理解**を持つことができます。NTML [**リレーアタック**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**を強制する**ことができるかもしれません。

### コンピュータ共有内の資格情報を探す

基本的な資格情報を入手したら、AD内で**共有されている興味深いファイル**がないか確認してみるべきです。これは手動で行うこともできますが、非常に退屈で繰り返しの作業です（特に数百のドキュメントをチェックする場合はさらにそうです）。

[**こちらのリンクを参照して使用できるツールについて学びましょう。**](../../network-services-pentesting/pentesting-smb.md#domain-shared-folders-search)

### NTLM資格情報の盗み出し

他のPCや共有に**アクセスできる場合**、SCFファイルなどの**ファイルを配置**することができます。これが何らかの方法でアクセスされると、**NTML認証がトリガー**され、それによって**NTLMチャレンジ**を盗み出してクラックすることができます。

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

この脆弱性により、認証済みのユーザーはドメインコントローラーを**危険にさらす**ことができました。

{% content-ref url="printnightmare.md" %}
[printnightmare.md](printnightmare.md)
{% endcontent-ref %}

## 特権昇格（特権付きの資格情報/セッションを使用した）Active Directory

**以下のテクニックでは、通常のドメインユーザーでは不十分で、これらの攻撃を実行するために特別な特権/資格情報が必要です。**

### ハッシュの抽出

[AsRepRoast](asreproast.md)、[Password Spraying](password-spraying.md)、[Kerberoast](kerberoast.md)、[Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)（リレーを含む）、[EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)、[特権の昇格（ローカル）](../windows-local-privilege-escalation/)を使用して、いくつかのローカル管理者アカウントを**侵害**することができたことを願っています。\
その後、メモリとローカルに保存されているすべてのハッシュをダンプする時が来ました。\
[**異なる方法でハッシュを取得するためのこのページを読んでください。**](broken-reference)

### ハッシュの渡し

**ユーザーのハッシュを取得したら**、それを**なりすまし**に使用することができます。\
その**ハッシュを使用して**NTLM認証を**実行するツール**を使用する必要があります。または、新しい**セッションログオン**を作成し、その**ハッシュ**を**LSASS**に**注入**することもできます。そのため、**NTLM認証が実行されると、そのハッシュが使用されます。**最後のオプションは、mimikatzが行うことです。\
[**詳細については、このページを読んでください。**](../ntlm/#pass-the-hash)

### Over Pass the Hash/Pass the Key

この攻撃は、一般的なPass The Hash over NTLMプロトコルの代わりに、ユーザーのNTLMハッシュを使用してKerberosチケットを要求することを目的としています。したがって、これは特にNTLMプロトコルが無効化され、認証プロトコルとしてKerberosのみが許可されているネットワークで特に**有用**です。

{% content-ref url="over-pass-the-hash-pass-the-key.md" %}
[over-pass-the-hash-pass-the-key.md](over-pass-the-hash-pass-the-key.md)
{% endcontent-ref %}

### チケットの渡し

この攻撃はPass the Keyと似ていますが、ハッシュを使用してチケットを要求する代わりに、**チケット自体が盗まれ**、所有者として認証に使用されます。

{% content-ref url="pass-the-ticket.md" %}
[pass-the-ticket.md](pass-the-ticket.md)
{% endcontent-ref %}

### 資格情報の再利用

ローカル管理者の**ハッシュ**または**パスワード**を持っている場合は、それを使用して他の**PCにローカルログイン**を試みるべきです。
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
{% hint style="warning" %}
これはかなり**ノイズが多い**です。**LAPS**を使用すると、これを**軽減**することができます。
{% endhint %}

### MSSQLの乱用と信頼されたリンク

ユーザーが**MSSQLインスタンスにアクセスする権限**を持っている場合、それを使用してMSSQLホストで**コマンドを実行**したり、NetNTLM **ハッシュを盗む**ことができるかもしれません。また、MSSQLインスタンスが別のMSSQLインスタンスによって信頼されている場合。ユーザーが信頼されたデータベースに対する特権を持っている場合、他のインスタンスでもクエリを実行するために信頼関係を使用することができます。これらの信頼関係はチェーン化することができ、ユーザーはコマンドを実行できる設定の誤ったデータベースを見つけることができるかもしれません。**データベース間のリンクはフォレスト間の信頼でも機能します。**

{% content-ref url="abusing-ad-mssql.md" %}
[abusing-ad-mssql.md](abusing-ad-mssql.md)
{% endcontent-ref %}

### 制約のない委任

[ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx)属性を持つコンピュータオブジェクトを見つけ、コンピュータにドメイン特権がある場合、そのコンピュータにログインするすべてのユーザーのメモリからTGTをダンプすることができます。したがって、**ドメイン管理者がコンピュータにログインする**場合、彼のTGTをダンプして[チケットを渡す](pass-the-ticket.md)ことで彼をなりすますことができます。制約のある委任により、**プリントサーバーを自動的に侵害**することさえできます（DCであることを願っています）。

{% content-ref url="unconstrained-delegation.md" %}
[unconstrained-delegation.md](unconstrained-delegation.md)
{% endcontent-ref %}

### 制約のある委任

ユーザーまたはコンピュータが「制約のある委任」を許可されている場合、そのユーザー/コンピュータはコンピュータ内の一部のサービスにアクセスするために**任意のユーザーをなりすます**ことができます。その後、このユーザー/コンピュータのハッシュを**侵害する**と、一部のサービスにアクセスするために**任意のユーザー**（ドメイン管理者でさえ）をなりすますことができます。

{% content-ref url="constrained-delegation.md" %}
[constrained-delegation.md](constrained-delegation.md)
{% endcontent-ref %}

### リソースベースの制約委任

リモートコンピュータで**WRITE権限**を持っている場合、リモートコンピュータで**昇格権限を持つコードを実行**することができます。

{% content-ref url="resource-based-constrained-delegation.md" %}
[resource-based-constrained-delegation.md](resource-based-constrained-delegation.md)
{% endcontent-ref %}

### ACLの乱用

侵害されたユーザーには、**ドメインオブジェクトに対する興味深い特権**がある場合があります。これにより、横方向に**移動**したり、特権を**エスカレート**したりすることができます。

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### プリンタースプーラーサービスの乱用

ドメイン内で**Spoolサービスがリッスン**している場合、それを**乱用**して新しい資格情報を**取得**し、特権を**エスカレート**することができるかもしれません。\
[**Spoolerサービスの乱用方法の詳細はこちら**](printers-spooler-service-abuse.md)

### サードパーティのセッションの乱用

**他のユーザー**が**侵害された**マシンに**アクセス**する場合、メモリから**資格情報を収集**し、さらには彼らのプロセスに**ビーコンをインジェクト**して彼らをなりすますことができます。\
通常、ユーザーはRDP経由でシステムにアクセスしますので、ここではサードパーティのRDPセッションに対していくつかの攻撃を実行する方法があります。

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### LAPS

**LAPS**を使用すると、ドメインに参加しているコンピュータの**ローカル管理者パスワード**（**ランダム化**、一意で**定期的に変更**される）を**管理**することができます。これらのパスワードはActive Directoryに集中的に保存され、ACLを使用して認可されたユーザーに制限されます。これらのパスワードを読み取るための**十分な権限がある場合、他のコンピュータに移動**することができます。

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

### 証明書の窃取

侵害されたマシンから証明書を収集することは、環境内で特権をエスカレートする方法です。

{% content-ref url="ad-certificates/certificate-theft.md" %}
[certificate-theft.md](ad-certificates/certificate-theft.md)
{% endcontent-ref %}

### 証明書テンプレートの乱用

脆弱なテンプレートが構成されている場合、特権をエスカレートするためにそれらを乱用することができます。

{% content-ref url="ad-certificates/domain-escalation.md" %}
[domain-escalation.md](ad-certificates/domain-escalation.md)
{% endcontent-ref %}

## 高特権アカウントでのポストエクスプロイテーション

### ドメイン資格情報のダンプ

**ドメイン管理者**またはさらに**エンタープライズ管理者**特権を取得した場合、**ドメインデータベース**（_ntds.dit_）を**ダンプ**することができます。

[**DCSync攻撃の詳細についてはこちら**](dcsync.md)を参照してください。

[**NTDS.ditを盗む方法の詳細についてはこちら**](broken-reference)

### 特権昇格としての永続化

以前に議論されたいくつかの技術は永続化に使用することができます。\
例えば、次のようにすることができます。

*   ユーザーを[Kerberoast](kerberoast.md)に対して脆弱にする

```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```
*   ユーザーを[ASREPRoast](asreproast.md)に対して脆弱にする

```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
*   ユーザーに[DCSync](./#dcsync)特権を付与する

```powershell
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### シルバーチケット

シルバーチケット攻撃は、**サービスのNTLMハッシュ（PCアカウントハッシュなど）を所有している場合に有効なTGSを作成**することに基づいています。したがって、特権アクセスを持つユーザーとしてカスタムTGSを偽造することで、そのサービスにアクセスすることができます。

{% content-ref url="silver-ticket.md" %}
[silver-ticket.md](silver-ticket.md)
{% endcontent-ref %}
### ゴールデンチケット

有効な**TGTとして任意のユーザー**を作成することができます。これは、krbtgt ADアカウントのNTLMハッシュを使用して行われます。TGSを偽造するよりもTGTを偽造することの利点は、なんらかのサービス（またはマシン）にアクセスできることです。これは、なりすましユーザーとしてのアクセス権を持つことを意味します。

{% content-ref url="golden-ticket.md" %}
[golden-ticket.md](golden-ticket.md)
{% endcontent-ref %}

### ダイヤモンドチケット

これらは、一般的なゴールデンチケットの検出メカニズムを**バイパスする方法で偽造されたゴールデンチケット**のようなものです。

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### **証明書アカウントの永続性**

**アカウントの証明書を持っているか、それらを要求できる**ということは、ユーザーアカウントで永続性を持つ非常に良い方法です（パスワードを変更しても）。

{% content-ref url="ad-certificates/account-persistence.md" %}
[account-persistence.md](ad-certificates/account-persistence.md)
{% endcontent-ref %}

### **証明書ドメインの永続性**

**証明書を使用することで、ドメイン内で高い特権を持つことも可能です**。

{% content-ref url="ad-certificates/domain-persistence.md" %}
[domain-persistence.md](ad-certificates/domain-persistence.md)
{% endcontent-ref %}

### AdminSDHolderグループ

**AdminSDHolder**オブジェクトのアクセス制御リスト（ACL）は、Active Directoryの**「保護されたグループ」**およびそのメンバーに**「権限」**を**コピーするためのテンプレート**として使用されます。保護されたグループには、Domain Admins、Administrators、Enterprise Admins、Schema Admins、Backup Operators、krbtgtなどの特権グループが含まれます。\
デフォルトでは、このグループのACLは、すべての「保護されたグループ」内にコピーされます。これは、これらの重要なグループへの意図的または偶発的な変更を防ぐために行われます。ただし、攻撃者が例えばグループ**AdminSDHolder**のACLを変更して、通常のユーザーに完全な権限を与えると、このユーザーは保護されたグループ内のすべてのグループに対して完全な権限を持つことになります（1時間以内に）。\
そして、1時間以内にこのユーザーをDomain Adminsから削除しようとすると、ユーザーはグループに戻ります。\
[**AdminSDHolderグループの詳細についてはこちらを参照してください。**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM資格情報

各**DC**には**ローカル管理者**アカウントがあります。このマシンで管理者特権を持っている場合、mimikatzを使用してローカル管理者のハッシュをダンプすることができます。その後、レジストリを変更してこのパスワードを**有効化**し、リモートでこのローカル管理者ユーザーにアクセスできるようにすることができます。

{% content-ref url="dsrm-credentials.md" %}
[dsrm-credentials.md](dsrm-credentials.md)
{% endcontent-ref %}

### ACL永続性

将来の特権エスカレーションを可能にするために、特定のドメインオブジェクトに対して**ユーザーに特別な権限を与える**ことができます。

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### セキュリティ記述子

**セキュリティ記述子**は、オブジェクトがオブジェクトに対して持つ**権限**を**保存**するために使用されます。オブジェクトのセキュリティ記述子に**わずかな変更**を加えるだけで、特権グループのメンバーである必要がなくても、そのオブジェクトに対して非常に興味深い特権を得ることができます。

{% content-ref url="security-descriptors.md" %}
[security-descriptors.md](security-descriptors.md)
{% endcontent-ref %}

### スケルトンキー

メモリ内のLSASSを**変更**して、ドメイン内の任意のアカウントで機能する**マスターパスワード**を作成します。

{% content-ref url="skeleton-key.md" %}
[skeleton-key.md](skeleton-key.md)
{% endcontent-ref %}

### カスタムSSP

[ここでSSP（セキュリティサポートプロバイダ）とは何かを学びます。](../authentication-credentials-uac-and-efs.md#security-support-provider-interface-sspi)\
自分自身のSSPを作成して、マシンへのアクセスに使用される**資格情報**を**クリアテキスト**で**キャプチャ**することができます。

{% content-ref url="custom-ssp.md" %}
[custom-ssp.md](custom-ssp.md)
{% endcontent-ref %}

### DCShadow

これは、新しいドメインコントローラをADに登録し、指定されたオブジェクトに対して（SIDHistory、SPNなどの）属性を**修正**するために使用します。この操作により、**変更に関するログが残らない**まま、指定されたオブジェクトに属性を追加することができます。DA特権とルートドメイン内にいる必要があります。\
ただし、間違ったデータを使用すると、非常に醜いログが表示されます。

{% content-ref url="dcshadow.md" %}
[dcshadow.md](dcshadow.md)
{% endcontent-ref %}

### LAPS永続性

以前、LAPSパスワードを読み取るための**十分な権限**がある場合に特権エスカレーションする方法について説明しました。ただし、これらのパスワードは**永続性を維持するためにも使用**できます。\
確認してください：

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

## フォレスト特権エスカレーション - ドメイン信頼関係

Microsoftは、**ドメインはセキュリティ境界ではなく、フォレストがセキュリティ境界**であると考えています。これは、フォレスト内のドメインを侵害すると、フォレスト全体を侵害する可能性があることを意味します。

### 基本情報

高レベルでは、[**ドメイン信頼関係**](http://technet.microsoft.com/en-us/library/cc759554\(v=ws.10\).aspx)は、**1つのドメインのユーザーが別のドメインで認証**したり、[セキュリティプリンシパル](https://technet.microsoft.com/en-us/library/cc780957\(v=ws.10\).aspx)として**動作**したりするための能力を確立します。

基本的に、信頼関係は2つのドメインの認証システムを**リンク**し、リファラルシステムを介して認証トラフィックが流れることを可能にするだけです。\
**2つのドメインが互いに信頼すると、鍵が交換**されます。これらの**鍵**は、各ドメインのDCに**保存**され、鍵は信頼の基礎となります。

ユーザーが信頼するドメインのサービスにアクセスしようとすると、ユーザーは自身のドメインのDCに対して**相互領域TGT**を要求します。DCはこのTGTをクライアントに提供しますが、これは両ドメインが**交換した相互領域鍵**で**暗号化/署名**されています。その後、クライアント
### 異なる信頼関係

重要なことは、**信頼関係は片方向または双方向のいずれか**であることです。双方向の場合、両方のドメインは互いを信頼しますが、**片方向**の信頼関係では、1つのドメインが**信頼される**ドメインであり、もう1つが**信頼する**ドメインです。最後の場合、**信頼されるドメインから信頼するドメイン内のリソースにのみアクセスできます**。

ドメインAがドメインBを信頼している場合、Aは信頼するドメインであり、Bは信頼されるドメインです。さらに、**ドメインA**では、これは**アウトバウンド信頼**であり、**ドメインB**では、これは**インバウンド信頼**です。

**異なる信頼関係**

* **親-子** - 同じフォレストの一部 - 子ドメインは親との暗黙の双方向推移的な信頼を保持します。これはおそらく最も一般的な信頼のタイプです。
* **クロスリンク** - 参照時間を改善するための子ドメイン間の「ショートカット信頼」。通常、複雑なフォレストの参照はフォレストルートまでフィルタリングされ、その後ターゲットドメインに戻る必要があるため、地理的に広がったシナリオでは、クロスリンクを使用して認証時間を短縮することができます。
* **外部** - 異なるドメイン間で暗黙の非推移的な信頼が作成されます。外部信頼は、既にフォレスト信頼によって結合されていないフォレスト外のドメインへのアクセスを提供します。外部信頼は、後で説明するセキュリティ保護であるSIDフィルタリングを強制します。
* **ツリールート** - フォレストルートドメインと新しいツリールートの間の暗黙の双方向推移的な信頼。私はあまりツリールート信頼に遭遇したことはありませんが、[Microsoftのドキュメント](https://technet.microsoft.com/en-us/library/cc773178\(v=ws.10\).aspx)によれば、フォレスト内で新しいドメインツリーを作成するときに作成されます。これらはフォレスト内の信頼であり、[双方向推移性を保持](https://technet.microsoft.com/en-us/library/cc757352\(v=ws.10\).aspx)しながら、ツリーに別のドメイン名（child.parent.comではなく）を持たせることができます。
* **フォレスト** - 2つのフォレストルートドメイン間の推移的な信頼。フォレスト信頼もSIDフィルタリングを強制します。
* **MIT** - Windows以外の[RFC4120準拠](https://tools.ietf.org/html/rfc4120)のKerberosドメインとの信頼。将来的にはMIT信頼についてもっと詳しく調査したいと思っています。

#### **信頼関係**の他の違い

* 信頼関係は**推移的**（AがBを信頼し、BがCを信頼する場合、AがCを信頼する）または**非推移的**である場合があります。
* 信頼関係は**双方向信頼**（お互いを信頼する）または**片方向信頼**（片方だけがもう一方を信頼する）として設定できます。

### 攻撃経路

1. 信頼関係を**列挙**する
2. **セキュリティプリンシパル**（ユーザー/グループ/コンピュータ）が**他のドメイン**のリソースに**アクセス**できるかどうかを確認します。おそらく、ACEエントリまたは他のドメインのグループに所属していることによる**ドメイン間の関係**を探します。この場合、kerberoastも別のオプションです。
3. ドメインを**ピボット**できる**アカウント**を**侵害**します。

1つのドメインから別の外部/信頼するドメインのリソースにアクセスできるセキュリティプリンシパル（ユーザー/グループ/コンピュータ）には、次の3つの**主要な**方法があります。

* 個々のマシンの**ローカルグループ**に追加されることがあります。たとえば、サーバーのローカルの「Administrators」グループです。
* **外部ドメインのグループ**に追加されることがあります。信頼のタイプとグループのスコープにはいくつかの注意点がありますが、後で説明します。
* アクセス制御リストの**主体**として追加されることがあります。私たちにとって最も興味深いのは、DACLのACE内の主体としてのACEです。ACL/DACL/ACEに関する詳細は、「[An ACE Up The Sleeve](https://specterops.io/assets/resources/an\_ace\_up\_the\_sleeve.pdf)」ホワイトペーパーを参照してください。

### 子から親へのフォレスト特権エスカレーション
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
信頼されたキーは2つあります。1つは「子 → 親」用で、もう1つは「親 → 子」用です。\
現在のドメインで使用されているキーを次のように取得できます。
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
```
{% endhint %}

#### SID-History Injection

SID-Historyインジェクションを利用して、エンタープライズ管理者として子/親ドメインにエスカレーションします。

{% content-ref url="sid-history-injection.md" %}
[sid-history-injection.md](sid-history-injection.md)
{% endcontent-ref %}

#### 書き込み可能なConfiguration NCの悪用

Configuration NCは、フォレストの設定情報の主要なリポジトリであり、フォレスト内のすべてのDCにレプリケートされます。さらに、フォレスト内のすべての書き込み可能なDC（読み取り専用DCではないDC）は、Configuration NCの書き込み可能なコピーを保持しています。これを悪用するには、（子）DCでSYSTEMとして実行する必要があります。

以下で説明するさまざまな方法で、ルートドメインを侵害することができます。

##### ルートDCサイトにGPOをリンクする
Configuration NCのSitesコンテナには、ADフォレストのドメインに参加しているコンピュータのすべてのサイトが含まれています。フォレスト内の任意のDCでSYSTEMとして実行する場合、フォレストルートDCのサイト（またはサイト）にGPOをリンクし、これらを侵害することができます。

詳細はこちらを参照してください：[Bypass SID filtering research](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

##### フォレスト内の任意のgMSAを侵害する
攻撃は、対象ドメインの特権gMSAに依存しています。

フォレスト内のgMSAのパスワードを計算するために使用されるKDSルートキーは、Configuration NCに格納されています。フォレスト内の任意のDCでSYSTEMとして実行する場合、KDSルートキーを読み取り、フォレスト内の任意のgMSAのパスワードを計算することができます。

詳細はこちらを参照してください：[Golden gMSA trust attack from child to parent](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

##### スキーマ変更攻撃
攻撃には、攻撃者が特権のADオブジェクトが作成されるのを待つ必要があります。

フォレスト内の任意のDCでSYSTEMとして実行する場合、ADスキーマのすべてのクラスに対して任意のユーザーに完全な制御権限を付与することができます。この制御権限は、侵害されたプリンシパルに完全な制御権限を付与するACEをADオブジェクトのデフォルトのセキュリティ記述子に作成するために悪用することができます。変更されたADオブジェクトタイプのすべての新しいインスタンスには、このACEがあります。

詳細はこちらを参照してください：[Schema change trust attack from child to parent](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

##### DAからEAへのADCS ESC5を使用したエスカレーション
ADCS ESC5（脆弱なPKIオブジェクトアクセス制御）攻撃は、PKIオブジェクトの制御を悪用して、フォレスト内の任意のユーザーとして認証するために悪用される脆弱な証明書テンプレートを作成します。すべてのPKIオブジェクトはConfiguration NCに格納されているため、フォレスト内の任意の書き込み可能な（子）DCを侵害している場合、ESC5を実行することができます。

詳細はこちらを参照してください：[From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c)

ADフォレストにADCSがない場合、攻撃者はこちらで説明されているように必要なコンポーネントを作成することができます：[Escalating from child domain’s admins to enterprise admins in 5 minutes by abusing AD CS, a follow up](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
このシナリオでは、**外部のドメインが信頼している**ドメインに対して、**未確定の権限**を持っています。まず、**自分のドメインの主体が外部ドメインに対してどのようなアクセス権を持っているか**を見つけ、それを悪用しようとします。

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
このシナリオでは、**あなたのドメイン**が別のドメインの主体に一部の**特権**を信頼しています。

ただし、ドメインが信頼するドメインによって、信頼されたドメインは**予測可能な名前**を持つユーザーを**作成**し、信頼されたパスワードを使用します。つまり、信頼するドメインからのユーザーにアクセスして、信頼されたドメインに入り込んで列挙し、さらに特権をエスカレーションすることが可能です。

{% content-ref url="external-forest-domain-one-way-outbound.md" %}
[external-forest-domain-one-way-outbound.md](external-forest-domain-one-way-outbound.md)
{% endcontent-ref %}

信頼されたドメインを侵害する別の方法は、ドメイン信頼の**逆方向**に作成された[**SQL信頼リンク**](abusing-ad-mssql.md#mssql-trusted-links)を見つけることです（これは非常に一般的ではありません）。

信頼されたドメインを侵害する別の方法は、信頼されたドメインの**ユーザーがアクセスできるマシン**で待機し、**RDP**を介してログインすることです。その後、攻撃者はRDPセッションプロセスにコードをインジェクトし、そこから被害者の元のドメインにアクセスすることができます。\
さらに、被害者が**ハードドライブをマウント**した場合、RDPセッションプロセスから攻撃者はハードドライブの**スタートアップフォルダーにバックドア**を保存することができます。この技術は**RDPInception**と呼ばれます。

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### ドメイン信頼の乱用の緩和策

**SIDフィルタリング:**

* フォレスト間の信頼を悪用する攻撃を防ぐ。
* フォレスト間の信頼ではデフォルトで有効になっています。フォレスト内の信頼はデフォルトでセキュリティが確保されていると見なされます（Microsoftはドメインではなくフォレストをセキュリティの境界と考えています）。
* ただし、SIDフィルタリングはアプリケーションやユーザーアクセスに影響を与える可能性があるため、しばしば無効にされています。
* 選択的認証
* フォレスト間の信頼で選択的認証が構成されている場合、信頼するドメイン間のユーザーは自動的に認証されません。信頼するドメイン/フォレストのドメインとサーバーへの個別のアクセス権限を与える必要があります。
* 書き込み可能なConfigration NCの悪用と信頼アカウント攻撃を防ぐことはできません。

[**ired.teamのドメイン信頼に関する詳細情報**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> クラウド & クラウド -> AD

{% embed url="https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-lateral-movements/azure-ad-connect-hybrid-identity" %}

## 一般的な防御策

[**ここで資格情報を保護する方法について詳しく学びましょう。**](../stealing-credentials/credentials-protections.md)\
**各技術に対するいくつかの対策を説明した説明でマイグレーションを見つけてください。**

* ドメイン管理者はドメインコントローラー以外のホストにログインできないようにする
* DA特権でサービスを実行しない
* ドメイン管理者特権が必要な場合は、時間を制限する：`Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### デセプション

* パスワードの有効期限が切れない
* 委任が信頼されている
* SPNを持つユーザー
* 説明にパスワードが含まれている
* 高特権グループのメンバーであるユーザー
* 他のユーザー、グループ、またはコンテナに対するACL権限を持つユーザー
* コンピュータオブジェクト
* ...
* [https://github.com/samratashok/Deploy-Deception](https://github.com/samratashok/Deploy-Deception)
* `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`

## デセプションの特定方法

**ユーザーオブジェクトの場合：**

* ObjectSID（ドメインとは異なる）
* lastLogon、lastlogontimestamp
* Logoncount（非常に低い数値は疑わしい）
* whenCreated
* Badpwdcount（非常に低い数値は疑わしい）

**一般的な方法：**

* 一部のソリューションは、すべての可能な属性に情報を埋めます。たとえば、コンピュータオブジェクトの属性をDCなどの100％実際のコンピュータオブジェクトの属性と比較します。または、RID 500（デフォルトの管理者）に対するユーザーをチェックします。
* 何かがあまりにも良すぎる場合は疑ってみてください
* [https://github.com/JavelinNetworks/HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster)

### Microsoft ATAの検出のバイパス

#### ユーザーの列挙

ATAは、DCでセッションを列挙しようとすると警告を表示するため、DCではなく他のホストでセッションを検索すれば、検出されない可能性があります。

#### チケットの偽装作成（パスハッシュの乗っ取り、ゴールデンチケットなど）

ATAが悪意のあるものと見なすのはNTLMへの劣化ですので、常に**aes**キーを使用してチケットを作成してください。

#### DCSync

これをドメインコントローラー以外から実行すると、ATAにキャッチされます。

## その他のツール

* [ドメイン監査自動化のためのPowerShellスクリプト](https://github.com/phillips321/adaudit)
* [Active Directoryの列挙のためのPythonスクリプト](https://github.com/ropnop/windapsearch)
* [Active Directoryの列挙のためのPythonスクリプト](https://github.com/CroweCybersecurity/ad-ldap-enum)

## 参考文献

* [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-method
