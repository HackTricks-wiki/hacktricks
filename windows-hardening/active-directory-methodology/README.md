# Active Directory Methodology

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？**HackTricksにあなたの会社を広告したい**ですか？または、**PEASSの最新バージョンにアクセスしたい**、または**HackTricksをPDFでダウンロードしたい**ですか？[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見してください。私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションです。
* [**公式のPEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手してください。
* **[**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**にフォローしてください。**
* **ハッキングのコツを共有するために、**[**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks)と[**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。

</details>

## 基本概要

Active Directoryは、ネットワーク管理者がドメイン、ユーザー、およびネットワーク内のオブジェクトを作成および管理することを可能にします。例えば、管理者はユーザーグループを作成し、サーバー上の特定のディレクトリへの特定のアクセス権を与えることができます。ネットワークが成長するにつれて、Active Directoryは多数のユーザーを論理的なグループとサブグループに編成し、各レベルでアクセス制御を提供する方法を提供します。

Active Directoryの構造には、主に3つの階層が含まれます：1) ドメイン、2) ツリー、3) フォレスト。同じデータベースを使用する複数のオブジェクト（ユーザーまたはデバイス）は、単一のドメインにグループ化することができます。複数のドメインは、ツリーと呼ばれる単一のグループに組み合わせることができます。複数のツリーは、フォレストと呼ばれるコレクションにグループ化することができます。これらの各レベルは、特定のアクセス権と通信権限を割り当てることができます。

Active Directoryの主な概念：

1. **ディレクトリ** – Active Directoryのオブジェクトに関するすべての情報を含む
2. **オブジェクト** – ディレクトリ内のほぼすべてのものを参照する（ユーザー、グループ、共有フォルダーなど）
3. **ドメイン** – ディレクトリのオブジェクトはドメイン内に含まれる。"フォレスト"内には複数のドメインが存在し、それぞれが独自のオブジェクトコレクションを持つことができる。
4. **ツリー** – 同じルートを持つドメインのグループ。例：_dom.local, email.dom.local, www.dom.local_
5. **フォレスト** – フォレストは組織階層の最上位レベルであり、ツリーのグループで構成される。ツリーは信頼関係によって接続される。

Active Directoryはいくつかの異なるサービスを提供し、これらは"Active Directory Domain Services"、またはAD DSの傘下にあります。これらのサービスには以下が含まれます：

1. **ドメインサービス** – 中央集権的なデータを保存し、ユーザーとドメイン間の通信を管理する；ログイン認証と検索機能を含む
2. **証明書サービス** – 安全な証明書を作成、配布、および管理する
3. **軽量ディレクトリサービス** – 開かれた（LDAP）プロトコルを使用するディレクトリ対応アプリケーションをサポートする
4. **ディレクトリ連合サービス** – 単一セッションで複数のWebアプリケーションにユーザーを認証するシングルサインオン（SSO）を提供する
5. **権利管理** – 著作権情報を保護し、デジタルコンテンツの不正使用と流通を防ぐ
6. **DNSサービス** – ドメイン名を解決するために使用される。

AD DSはWindows Server（Windows Server 10を含む）に含まれており、クライアントシステムを管理するように設計されています。通常のバージョンのWindowsを実行しているシステムは、AD DSの管理機能を持っていませんが、Active Directoryをサポートしています。これは、ユーザーが正しいログイン資格情報を持っていれば、任意のWindowsコンピューターがWindowsワークグループに接続できることを意味します。\
**出典:** [**https://techterms.com/definition/active\_directory**](https://techterms.com/definition/active\_directory)

### **Kerberos認証**

**ADを攻撃する**方法を学ぶには、**Kerberos認証プロセス**を非常によく**理解する**必要があります。\
[**まだその仕組みを知らない場合は、このページを読んでください。**](kerberos-authentication.md)

## チートシート

[https://wadcoms.github.io/](https://wadcoms.github.io)を見ると、ADを列挙/悪用するために実行できるコマンドのクイックビューが得られます。

## Recon Active Directory (No creds/sessions)

AD環境にアクセスできるが、資格情報/セッションがない場合は以下のことができます：

* **ネットワークのペネトレーションテスト：**
* ネットワークをスキャンし、マシンとオープンポートを見つけて、**脆弱性を悪用する**か、それらから**資格情報を抽出する**（例えば、[プリンターは非常に興味深いターゲットになる可能性があります](ad-information-in-printers.md)。
* DNSの列挙は、ドメイン内の重要なサーバー（Web、プリンター、共有、VPN、メディアなど）に関する情報を提供する可能性があります。
* `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
* これを行う方法についての詳細は、一般的な[**ペネトレーションテスト方法論**](../../generic-methodologies-and-resources/pentesting-methodology.md)を参照してください。
* **smbサービスでnullおよびGuestアクセスをチェックする**（これは現代のWindowsバージョンでは機能しません）：
* `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
* `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
* `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
* SMBサーバーを列挙する方法についての詳細なガイドはこちらです：

{% content-ref url="../../network-services-pentesting/pentesting-smb.md" %}
[pentesting-smb.md](../../network-services-pentesting/pentesting-smb.md)
{% endcontent-ref %}

* **Ldapを列挙する**
* `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
* LDAPを列挙する方法についての詳細なガイドはこちらです（**匿名アクセスに特に注意してください**）：

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

* **ネットワークをポイズニングする**
* [**Responderを使用してサービスを偽装し、資格情報を収集する**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
* [**リレーアタックを悪用してホストにアクセスする**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
* [**evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)を使用して偽のUPnPサービスを公開し、資格情報を収集する
* [**OSINT**](https://book.hacktricks.xyz/external-recon-methodology)：
* 内部文書、ソーシャルメディア、サービス（主にWeb）からユーザー名/名前を抽出し、ドメイン環境内および公開されている情報から抽出します。
* 会社の従業員のフルネームを見つけた場合、異なるAD **ユーザー名の規則**（[**これを読んでください**](https://activedirectorypro.com/active-directory-user-naming-convention/))を試すことができます。最も一般的な規則は：_NameSurname_, _Name.Surname_, _NamSur_（各3文字）、_Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _ランダムな文字と3つのランダムな数字_（abc123）。
* ツール：
* [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
* [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### ユーザー列挙

* **匿名SMB/LDAP enum:** [**ペネトレーションテスト SMB**](../../network-services-pentesting/pentesting-smb.md) と [**ペネトレーションテスト LDAP**](../../network-services-pentesting/pentesting-ldap.md) のページを確認してください。
* **Kerbrute enum**: **無効なユーザー名が要求された**場合、サーバーは **Kerberosエラー** コード _KRB5KDC\_ERR\_C\_PRINCIPAL\_UNKNOWN_ を使用して応答し、ユーザー名が無効であることを判断することができます。**有効なユーザー名**は、**TGT in a AS-REP** 応答またはエラー _KRB5KDC\_ERR\_PREAUTH\_REQUIRED_ を引き出し、ユーザーが事前認証を行う必要があることを示します。
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
```
* **OWA (Outlook Web Access) サーバー**

ネットワーク内でこれらのサーバーを見つけた場合、**ユーザー列挙を実行する**こともできます。例えば、ツール [**MailSniper**](https://github.com/dafthack/MailSniper) を使用できます：
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
このGitHubリポジトリでユーザー名のリストを見つけることができます。[**このgithubリポジトリ**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) とこのリポジトリ ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames))。

しかし、この段階までに行ったリコンステップから**企業で働いている人々の名前**を持っているべきです。名前と姓を使って、スクリプト [**namemash.py**](https://gist.github.com/superkojiman/11076951) を使用して、有効な可能性のあるユーザー名を生成できます。
{% endhint %}

### 一つまたは複数のユーザー名を知っている

有効なユーザー名をすでに知っているが、パスワードはない場合、次の方法を試してみてください：

* [**ASREPRoast**](asreproast.md): ユーザーが _DONT\_REQ\_PREAUTH_ 属性を**持っていない**場合、そのユーザーのために AS\_REP メッセージを**要求**でき、それにはユーザーのパスワードの派生によって暗号化されたデータが含まれます。
* [**Password Spraying**](password-spraying.md): 発見された各ユーザーで最も**一般的なパスワード**を試してみましょう。もしかすると、何人かのユーザーが悪いパスワードを使用しているかもしれません（パスワードポリシーを念頭に置いてください！）。
* OWAサーバーに対しても**スプレー**を行い、ユーザーのメールサーバーへのアクセスを試みることができます。

{% content-ref url="password-spraying.md" %}
[password-spraying.md](password-spraying.md)
{% endcontent-ref %}

### LLMNR/NBT-NSポイズニング

**ネットワーク**のプロトコルを**ポイズニング**することで、クラックするためのチャレンジ**ハッシュ**を**取得**できるかもしれません：

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

### NTMLリレー

アクティブディレクトリを列挙することができれば、**より多くのメールアドレスとネットワークのより良い理解**を得ることができます。NTML [**リレー攻撃**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) を強制して、AD環境へのアクセスを得ることができるかもしれません。

### NTLMクレデンシャルの盗難

**nullまたはゲストユーザー**で他のPCや共有に**アクセス**できる場合、SCFファイルのような**ファイルを配置**できます。これが何らかの方法でアクセスされると、NTML認証があなたに対して**トリガー**され、**NTLMチャレンジ**を**盗む**ことができます：

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

## クレデンシャル/セッションを持ってアクティブディレクトリを列挙する

このフェーズでは、有効なドメインアカウントのクレデンシャルまたはセッションを**侵害**している必要があります。有効なクレデンシャルを持っているか、ドメインユーザーとしてシェルを持っている場合、**以前に提供されたオプションが他のユーザーを侵害するためのオプションであることを覚えておくべきです**。

認証された列挙を開始する前に、**Kerberosダブルホップ問題**について知っておくべきです。

{% content-ref url="kerberos-double-hop-problem.md" %}
[kerberos-double-hop-problem.md](kerberos-double-hop-problem.md)
{% endcontent-ref %}

### 列挙

アカウントを侵害することは、**ドメイン全体を侵害するための大きなステップ**です。なぜなら、**アクティブディレクトリの列挙**を開始できるからです：

[**ASREPRoast**](asreproast.md) に関しては、今ではすべての可能性のある脆弱なユーザーを見つけることができ、[**Password Spraying**](password-spraying.md) に関しては、すべてのユーザー名の**リストを取得**し、侵害されたアカウントのパスワード、空のパスワード、そして新しい有望なパスワードを試すことができます。

* [**CMDを使用して基本的なリコンを実行**](../basic-cmd-for-pentesters.md#domain-info) することができます。
* より慎重に行うために [**powershellを使用してリコン**](../basic-powershell-for-pentesters/) を行うこともできます。
* より詳細な情報を抽出するために [**powerviewを使用**](../basic-powershell-for-pentesters/powerview.md) することもできます。
* アクティブディレクトリでのリコンには [**BloodHound**](bloodhound.md) という素晴らしいツールがあります。それは（使用する収集方法によっては）**あまり慎重ではありません**が、気にしないのであれば、絶対に試してみるべきです。RDPできるユーザーを見つけたり、他のグループへのパスを見つけたりすることができます。
* **他の自動化されたAD列挙ツールには**：[**AD Explorer**](bloodhound.md#ad-explorer)**、** [**ADRecon**](bloodhound.md#adrecon)**、** [**Group3r**](bloodhound.md#group3r)**、** [**PingCastle**](bloodhound.md#pingcastle)**があります。**
* [**ADのDNSレコード**](ad-dns-records.md) には興味深い情報が含まれている可能性があります。
* ディレクトリを列挙するために使用できる**GUIを備えたツール**は、**SysInternal**スイートの**AdExplorer.exe**です。
* **ldapsearch** を使用してLDAPデータベースを検索し、_userPassword_ および _unixUserPassword_ フィールド、または _Description_ でクレデンシャルを探すこともできます。他の方法については、[PayloadsAllTheThingsのADユーザーコメントのパスワード](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) を参照してください。
* **Linux**を使用している場合は、[**pywerview**](https://github.com/the-useless-one/pywerview) を使用してドメインを列挙することもできます。
* 自動化されたツールとして次のものも試してみることができます：
* [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
* [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
*   **すべてのドメインユーザーを抽出する**

Windowsからすべてのドメインユーザー名を取得するのは非常に簡単です（`net user /domain`、`Get-DomainUser`、または `wmic useraccount get name,sid`）。Linuxでは、次のように使用できます：`GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` または `enum4linux -a -u "user" -p "password" <DC IP>`

> この列挙セクションが小さく見えるかもしれませんが、これが全ての中で最も重要な部分です。リンク（特にcmd、powershell、powerview、BloodHoundのリンク）にアクセスし、ドメインを列挙する方法を学び、快適に感じるまで練習してください。評価中には、DAへの道を見つけるか、何もできないと判断するための鍵となる瞬間です。

### Kerberoast

Kerberoastingの目的は、ドメインユーザーアカウントを代表して実行されるサービスの**TGSチケットを収穫する**ことです。これらのTGSチケットの一部は、ユーザーパスワードから派生したキーで**暗号化されています**。その結果、そのクレデンシャルを**オフラインでクラック**することができます。\
詳細はこちらで：

{% content-ref url="kerberoast.md" %}
[kerberoast.md](kerberoast.md)
{% endcontent-ref %}

### リモート接続（RDP、SSH、FTP、Win-RMなど）

いくつかのクレデンシャルを取得したら、**マシン**へのアクセスがあるかどうかを確認できます。そのためには、**CrackMapExec** を使用して、ポートスキャンに応じて、さまざまなサーバーで異なるプロトコルで接続を試みることができます。

### ローカル特権昇格

通常のドメインユーザーとしてクレデンシャルまたはセッションを侵害し、このユーザーで**ドメイン内の任意のマシン**に**アクセス**できる場合、ローカルで特権を昇格させ、クレデンシャルを探す方法を見つけるべきです。これは、他のユーザーのハッシュをメモリ（LSASS）およびローカル（SAM）から**ダンプ**することができるのは、ローカル管理者権限を持っている場合のみだからです。

この本には[**Windowsでのローカル特権昇格**](../windows-local-privilege-escalation/)についての完全なページと[**チェックリスト**](../checklist-windows-privilege-escalation.md)があります。また、[**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) の使用も忘れないでください。

### 現在のセッションチケット

現在のユーザーに**アクセス許可を与えるチケット**が見つかる可能性は非常に**低い**ですが、確認することができます：
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTMLリレー

アクティブディレクトリを列挙することができれば、**より多くのメールアドレスとネットワークの理解が深まります**。NTMLの[**リレー攻撃**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)を強制することができるかもしれません。

### **コンピュータ共有で資格情報を探す**

基本的な資格情報を手に入れたら、AD内で共有されている**興味深いファイルを探す**べきです。手動で行うこともできますが、それは非常に退屈で繰り返しの作業です（特に、確認する必要がある数百のドキュメントが見つかった場合）。

[**使用できるツールについて学ぶには、このリンクをたどってください。**](../../network-services-pentesting/pentesting-smb.md#domain-shared-folders-search)

### NTLM資格情報を盗む

他のPCや共有に**アクセスできる**場合、SCFファイルのような**ファイルを配置**することができます。これが何らかの形でアクセスされると、**あなたに対してNTML認証をトリガー**し、**NTLMチャレンジを盗む**ことができます。

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

この脆弱性により、任意の認証済みユーザーが**ドメインコントローラーを侵害する**ことができました。

{% content-ref url="printnightmare.md" %}
[printnightmare.md](printnightmare.md)
{% endcontent-ref %}

## 特権資格情報/セッションを持つActive Directoryの権限昇格

**以下の技術には、通常のドメインユーザーでは不十分で、これらの攻撃を実行するために特別な権限/資格情報が必要です。**

### ハッシュ抽出

[AsRepRoast](asreproast.md)、[Password Spraying](password-spraying.md)、[Kerberoast](kerberoast.md)、[Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)（リレーを含む）、[EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)、[ローカルでの権限昇格](../windows-local-privilege-escalation/)を使用して、いくつかのローカル管理者アカウントを侵害することができたら、メモリとローカルにあるすべてのハッシュをダンプする時です。\
[**ハッシュを取得するさまざまな方法については、このページを読んでください。**](broken-reference/)

### ハッシュを渡す

**ユーザーのハッシュを手に入れたら**、それを使用して**なりすまし**を行うことができます。\
**NTLM認証をそのハッシュを使用して実行する**ツールを使用するか、新しい**sessionlogonを作成**してそのハッシュを**LSASS内に注入**し、**NTLM認証が実行されるときにそのハッシュが使用される**ようにする必要があります。最後のオプションはmimikatzが行うことです。\
[**詳細については、このページを読んでください。**](../ntlm/#pass-the-hash)

### ハッシュ/キーを渡す

この攻撃は、ユーザーのNTLMハッシュを使用してKerberosチケットを要求することを目的としており、NTLMプロトコルの一般的なハッシュを渡す代わりになります。したがって、NTLMプロトコルが無効になっており、認証プロトコルとして**Kerberosのみが許可されているネットワークでは特に有用**です。

{% content-ref url="over-pass-the-hash-pass-the-key.md" %}
[over-pass-the-hash-pass-the-key.md](over-pass-the-hash-pass-the-key.md)
{% endcontent-ref %}

### チケットを渡す

この攻撃はPass the Keyに似ていますが、ハッシュを使用してチケットを要求する代わりに、**チケット自体が盗まれ**、その所有者として認証に使用されます。

{% content-ref url="pass-the-ticket.md" %}
[pass-the-ticket.md](pass-the-ticket.md)
{% endcontent-ref %}

### 資格情報の再利用

**ローカル管理者**の**ハッシュ**または**パスワード**を持っている場合、他の**PC**に**ローカルでログイン**を試みるべきです。
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
{% hint style="warning" %}
この方法はかなり**騒々しい**ものであり、**LAPS**がこれを**軽減**するでしょう。
{% endhint %}

### MSSQL Abuse & Trusted Links

ユーザーが**MSSQLインスタンスにアクセスする権限**を持っている場合、MSSQLホストで**コマンドを実行**したり（SAとして実行されている場合）、NetNTLMの**ハッシュを盗む**、または**リレー攻撃**を実行することができるかもしれません。\
また、異なるMSSQLインスタンスによって信頼されている（データベースリンクされている）MSSQLインスタンスがある場合、ユーザーが信頼されたデータベースに対する権限を持っていれば、**信頼関係を利用して他のインスタンスでもクエリを実行することができます**。これらの信頼は連鎖的になり、ユーザーはコマンドを実行できる誤設定されたデータベースを見つけるかもしれません。\
**データベース間のリンクは、フォレストの信頼を越えても機能します。**

{% content-ref url="abusing-ad-mssql.md" %}
[abusing-ad-mssql.md](abusing-ad-mssql.md)
{% endcontent-ref %}

### Unconstrained Delegation

[ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx)属性を持つコンピュータオブジェクトを見つけ、そのコンピュータのドメイン権限を持っている場合、そのコンピュータにログインするすべてのユーザーのTGTをメモリからダンプすることができます。\
したがって、**ドメイン管理者がそのコンピュータにログインする**と、そのTGTをダンプして[Pass the Ticket](pass-the-ticket.md)を使用して彼を偽装することができます。\
制約付き委任を利用すると、**プリントサーバーを自動的に侵害する**こともできます（できればDCになるでしょう）。

{% content-ref url="unconstrained-delegation.md" %}
[unconstrained-delegation.md](unconstrained-delegation.md)
{% endcontent-ref %}

### Constrained Delegation

ユーザーやコンピュータが「制約付き委任」を許可されている場合、**任意のユーザーになりすまして特定のコンピュータのサービスにアクセスする**ことができます。\
その後、このユーザー/コンピュータのハッシュを**侵害する**と、**任意のユーザー**（ドメイン管理者でさえ）になりすまして一部のサービスにアクセスすることができます。

{% content-ref url="constrained-delegation.md" %}
[constrained-delegation.md](constrained-delegation.md)
{% endcontent-ref %}

### Resource-based Constrained Delegation

そのコンピュータのADオブジェクトに**書き込み権限**を持っている場合、リモートコンピュータで**特権を持つコード実行**を獲得することが可能です。

{% content-ref url="resource-based-constrained-delegation.md" %}
[resource-based-constrained-delegation.md](resource-based-constrained-delegation.md)
{% endcontent-ref %}

### ACLs Abuse

侵害されたユーザーは、ドメインオブジェクトに対していくつかの**興味深い権限**を持っている可能性があり、それによって横方向に**移動**したり権限を**エスカレート**することができます。

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Printer Spooler service abuse

ドメイン内で**Spoolサービスがリスニングしている**のを見つけることができれば、それを**悪用して新しい資格情報を取得**し、権限を**エスカレート**することができます。\
[**Spoolerサービスの悪用方法についての詳細はこちら。**](printers-spooler-service-abuse.md)

### Third party sessions abuse

**他のユーザー**が**侵害された**マシンに**アクセス**する場合、メモリから資格情報を**収集**したり、彼らのプロセスにビーコンを**注入**して偽装することが可能です。\
通常、ユーザーはRDPを介してシステムにアクセスするため、ここでは第三者のRDPセッションに対して攻撃を行う方法をいくつか紹介します：

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### LAPS

**LAPS**は、ドメインに参加しているコンピュータのローカル管理者パスワード（**ランダム化**され、ユニークで、**定期的に変更**される）を**管理する**ことを可能にします。これらのパスワードはActive Directoryに中央集中的に保存され、ACLを使用して承認されたユーザーに制限されています。これらのパスワードを**読む十分な権限を持っていれば、他のコンピュータに移動することができます**。

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

### Certificate Theft

侵害されたマシンから証明書を収集することは、環境内で権限をエスカレートする方法になる可能性があります：

{% content-ref url="ad-certificates/certificate-theft.md" %}
[certificate-theft.md](ad-certificates/certificate-theft.md)
{% endcontent-ref %}

### Certificate Templates Abuse

脆弱なテンプレートが設定されている場合、それらを悪用して権限をエスカレートすることが可能です：

{% content-ref url="ad-certificates/domain-escalation.md" %}
[domain-escalation.md](ad-certificates/domain-escalation.md)
{% endcontent-ref %}

## 高権限アカウントを使用した侵害後の活動

### Dumping Domain Credentials

**ドメイン管理者**またはさらに良い**エンタープライズ管理者**の権限を得たら、**ドメインデータベース**：_ntds.dit_を**ダンプ**することができます。

[**DCSync攻撃に関する詳細情報はこちら**](dcsync.md)。

[**NTDS.ditを盗む方法に関する詳細情報はこちら**](broken-reference/)

### Privesc as Persistence

前に議論したいくつかの技術は、永続性のために使用することができます。\
例えば、以下のようにすることができます：

*   [**Kerberoast**](kerberoast.md)に対してユーザーを脆弱にする

```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```
*   [**ASREPRoast**](asreproast.md)に対してユーザーを脆弱にする

```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
*   ユーザーに[**DCSync**](./#dcsync)権限を付与する

```powershell
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

Silver ticket攻撃は、サービスのNTLMハッシュ（例えば**PCアカウントハッシュ**）を所有している場合に、そのサービスに対する有効なTGSを**作成する**ことに基づいています。したがって、カスタムTGSを偽造して**任意のユーザー**としてそのサービスに**アクセスする**ことが可能です（例えば、コンピュータへの特権アクセス）。

{% content-ref url="silver-ticket.md" %}
[silver-ticket.md](silver-ticket.md)
{% endcontent-ref %}

### Golden Ticket

krbtgt ADアカウントのNTLMハッシュを使用して、**任意のユーザー**として有効な**TGTを作成**することができます。TGSの代わりにTGTを偽造する利点は、偽装したユーザーとしてドメイン内の**任意のサービス**（またはマシン）に**アクセスできる**ことです。

{% content-ref url="golden-ticket.md" %}
[golden-ticket.md](golden-ticket.md)
{% endcontent-ref %}

### Diamond Ticket

これらは、一般的なゴールデンチケットの検出メカニズムを**回避する**方法で偽造されたゴールデンチケットのようなものです。

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### **Certificates Account Persistence**

アカウントの証明書を持っているか、それらを要求することができると、ユーザーアカウントに永続的に留まることができます（たとえ彼がパスワードを変更したとしても）：

{% content-ref url="ad-certificates/account-persistence.md" %}
[account-persistence.md](ad-certificates/account-persistence.md)
{% endcontent-ref %}

### **Certificates Domain Persistence**

証明書を使用して、ドメイン内で高権限を持つ永続性を維持することも可能です：

{% content-ref url="ad-certificates/domain-persistence.md" %}
[domain-persistence.md](ad-certificates/domain-persistence.md)
{% endcontent-ref %}

### AdminSDHolder Group

**AdminSDHolder**オブジェクトのアクセス制御リスト（ACL）は、Active Directory内のすべての「保護されたグループ」とそのメンバーに**権限をコピーする**ためのテンプレートとして使用されます。保護されたグループには、ドメイン管理者、管理者、エンタープライズ管理者、スキーマ管理者、バックアップオペレーター、krbtgtなどの特権グループが含まれます。\
デフォルトでは、このグループのACLはすべての「保護されたグループ」内にコピーされます。これは、これらの重要なグループに意図的または偶発的な変更が加えられるのを防ぐためです。しかし、攻撃者が例えば、通常のユーザーに完全な権限を与えることで**AdminSDHolder**グループのACLを**変更する**と、このユーザーは保護されたグループ内のすべてのグループに対して完全な権限を持つことになります（1時間以内に）。\
そして、もし誰かがこのユーザーをドメイン管理者（例えば）から削除しようとしても、1時間以内にそのユーザーはグループに戻ります。\
[**AdminDSHolder Groupに関する詳細情報はこちら。**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

各**DC**内には**ローカル管理者**アカウントがあります。このマシンで管理者権限を持っている場合、mimikatzを使用して**ローカル管理者のハッシュをダンプ**することができます。その後、レジストリを変更してこのパスワードを**アクティブにし**、リモートからこのローカル管理者ユーザーにアクセスできるようにします。

{% content-ref url="dsrm-credentials.md" %}
[dsrm-credentials.md](dsrm-credentials.md)
{% endcontent-ref %}

### ACL Persistence

特定のドメインオブジェクトに対して**ユーザー**にいくつかの**特別な権限**を**与える**ことができ、将来的にユーザーが権限を**エスカレート**することを可能にします。

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Security Descriptors

**セキュリティディスクリプタ**は、オブジェクトが他のオブジェクトに対して持つ**権限**を**保存**するために使用されます。オブジェクトのセキュリティディスクリプタに**わずかな変更**を**加える**ことができれば、特権グループのメンバーでなくてもそのオブジェクトに対して非常に興味深い権限を得ることができます。

{% content-ref url="security-descriptors.md" %}
[security-descriptors.md](security-descriptors.md)
{% endcontent-ref %}

### Skeleton Key

メモリ内のLSASSを**変更**して、ドメイン内の任意のアカウントで機能する**マスターパスワード**を作成します。

{% content-ref url="skeleton-key.md" %}
[skeleton-key.md](skeleton-key.md)
{% endcontent-ref %}

### Custom SSP

SSP（セキュリティサポートプロバイダ）については[こちらで学ぶ](../authentication-credentials-uac-and-efs.md#security-support-provider-interface-sspi)。\
自分**自身のSSP**を作成して、マシンにアクセスするために使用される**資格情報**を**クリアテキスト**で**キャプチャ**することができます。\\

{% content-ref url="custom-ssp.md" %}
[custom-ssp.md](custom-ssp.md)
{% endcontent-ref %}

### DCShadow

ADに**新しいドメインコントローラー**を登録し、それを使用して指定されたオブジェクトに対して属性（SIDHistory、SPNsなど）を**プッシュ**し、**変更に関するログ**を残さずに**行います**。これを行うには**DA**権限が必要で、**ルート
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
**2つの信頼されたキー**があります。一つは _Child --> Parent_ 用、もう一つは _Parent_ --> _Child_ 用です。\
現在のドメインで使用されているキーは次のコマンドで確認できます:
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
```
#### SID-History インジェクション

SID-History インジェクションを悪用して、信頼関係を利用して子/親ドメインのエンタープライズ管理者に昇格します：

{% content-ref url="sid-history-injection.md" %}
[sid-history-injection.md](sid-history-injection.md)
{% endcontent-ref %}

#### 書き込み可能な Configuration NC を悪用する

Configuration NC はフォレストの設定情報の主要なリポジトリであり、フォレスト内のすべての DC にレプリケートされます。さらに、フォレスト内のすべての書き込み可能な DC（読み取り専用の DC は除く）は、書き込み可能な Configuration NC のコピーを保持しています。これを悪用するには、（子）DC 上で SYSTEM として実行する必要があります。

以下に記載されている様々な方法でルートドメインを侵害することが可能です。

**ルート DC サイトに GPO をリンクする**

Configuration NC の Sites コンテナには、AD フォレストに参加しているコンピュータのすべてのサイトが含まれています。フォレスト内の任意の DC 上で SYSTEM として実行することにより、フォレストのルート DC のサイトを含むサイトに GPO をリンクし、これらを侵害することが可能です。

詳細はこちらで読むことができます [Bypass SID filtering research](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research)。

**フォレスト内の任意の gMSA を侵害する**

攻撃は、対象ドメイン内の特権を持つ gMSA に依存しています。

フォレスト内の gMSA のパスワードを計算するために使用される KDS Root キーは、Configuration NC に保存されています。フォレスト内の任意の DC 上で SYSTEM として実行することにより、KDS Root キーを読み取り、フォレスト内の任意の gMSA のパスワードを計算することができます。

詳細はこちらで読むことができます：[Golden gMSA trust attack from child to parent](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent)。

**スキーマ変更攻撃**

攻撃者は新しい特権 AD オブジェクトが作成されるのを待つ必要があります。

フォレスト内の任意の DC 上で SYSTEM として実行することにより、任意のユーザーに AD スキーマのすべてのクラスに対する完全な制御を付与することができます。その制御は、侵害されたプリンシパルに完全な制御を付与する ACE を任意の AD オブジェクトのデフォルトセキュリティ記述子に作成するために悪用される可能性があります。変更された AD オブジェクトタイプの新しいインスタンスは、この ACE を持つことになります。

詳細はこちらで読むことができます：[Schema change trust attack from child to parent](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent)。

**DA から EA へ ADCS ESC5 を使って**

ADCS ESC5（Vulnerable PKI Object Access Control）攻撃は、PKI オブジェクトの制御を悪用して、フォレスト内の任意のユーザーとして認証するために悪用できる脆弱な証明書テンプレートを作成します。PKI オブジェクトはすべて Configuration NC に保存されているため、フォレスト内の任意の書き込み可能な（子）DC を侵害した場合、ESC5 を実行することができます。

詳細はこちらで読むことができます：[From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c)

AD フォレストに ADCS がない場合、攻撃者はこちらに記載されているように必要なコンポーネントを作成することができます：[Escalating from child domain’s admins to enterprise admins in 5 minutes by abusing AD CS, a follow up](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)。

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
このシナリオでは、**あなたのドメインは信頼されています** 外部のドメインによって、それに対して**不特定の権限**を与えられています。あなたは**あなたのドメインのどのプリンシパルが外部ドメインにどのようなアクセス権を持っているか**を見つけ出し、それを利用しようとする必要があります：

{% content-ref url="external-forest-domain-oneway-inbound.md" %}
[external-forest-domain-oneway-inbound.md](external-forest-domain-oneway-inbound.md)
{% endcontent-ref %}

### 外部フォレストドメイン - 片方向（アウトバウンド）
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
```markdown
このシナリオでは、**あなたのドメイン**が**異なるドメイン**のプリンシパルに対していくつかの**権限**を**信頼**しています。

しかし、**ドメインが信頼される**と、信頼しているドメインによって、予測可能な名前を持つユーザーが**作成され**、**信頼されたパスワードをパスワードとして使用します**。つまり、信頼しているドメインのユーザーが信頼されたドメインに**アクセスして列挙し、さらに権限をエスカレートしようとすることが可能です**：

{% content-ref url="external-forest-domain-one-way-outbound.md" %}
[external-forest-domain-one-way-outbound.md](external-forest-domain-one-way-outbound.md)
{% endcontent-ref %}

信頼されたドメインを侵害する別の方法は、ドメインの信頼の**逆方向**に作成された[**SQL信頼リンク**](abusing-ad-mssql.md#mssql-trusted-links)を見つけることです（これはあまり一般的ではありません）。

信頼されたドメインを侵害するもう一つの方法は、信頼されたドメインの**ユーザーがアクセスできる**マシンで待ち、**RDP**経由でログインするのを待つことです。その後、攻撃者はRDPセッションプロセスにコードを注入し、そこから**被害者の元のドメインにアクセス**することができます。\
さらに、**被害者がハードドライブをマウントした**場合、**RDPセッション**プロセスから攻撃者は**ハードドライブのスタートアップフォルダーにバックドア**を保存することができます。この技術は**RDPInception**と呼ばれています。

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### ドメイン信頼の悪用緩和

**SIDフィルタリング：**

* フォレスト信頼を越えたSID履歴属性の悪用を防ぎます。
* すべてのインターフォレスト信頼でデフォルトで有効になっています。インターフォレスト信頼はデフォルトで安全と見なされています（MSはドメインではなくフォレストをセキュリティ境界と見なしています）。
* しかし、SIDフィルタリングはアプリケーションやユーザーアクセスを中断する可能性があるため、しばしば無効にされます。
* 選択的認証
* インターフォレスト信頼で選択的認証が設定されている場合、信頼間のユーザーは自動的に認証されません。信頼しているドメイン/フォレスト内のドメインとサーバーへの個別のアクセスを与えるべきです。
* 書き込み可能なConfigration NCの悪用と信頼アカウント攻撃を防ぐことはできません。

[**ired.teamでドメイン信頼についての詳細情報。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> クラウド & クラウド -> AD

{% embed url="https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-lateral-movements/azure-ad-connect-hybrid-identity" %}

## いくつかの一般的な防御

[**ここで資格情報を保護する方法についてもっと学ぶ。**](../stealing-credentials/credentials-protections.md)\
**技術の説明で各技術に対するいくつかの移行について見つけてください。**

* ドメイン管理者がドメインコントローラー以外のホストにログインすることを許可しない
* DA権限でサービスを実行しない
* ドメイン管理者権限が必要な場合は、時間を制限する：`Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### 欺瞞

* パスワードの有効期限が切れない
* 委任のために信頼されている
* SPNを持つユーザー
* 説明の中のパスワード
* 高権限グループのメンバーであるユーザー
* 他のユーザー、グループ、またはコンテナに対するACL権限を持つユーザー
* コンピューターオブジェクト
* ...
* [https://github.com/samratashok/Deploy-Deception](https://github.com/samratashok/Deploy-Deception)
* `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`

## 欺瞞の特定方法

**ユーザーオブジェクトについて：**

* ObjectSID（ドメインと異なる）
* lastLogon, lastlogontimestamp
* Logoncount（非常に低い数は怪しい）
* whenCreated
* Badpwdcount（非常に低い数は怪しい）

**一般的に：**

* いくつかのソリューションは、可能なすべての属性に情報を記入します。例えば、コンピューターオブジェクトの属性とDCのような100%実際のコンピューターオブジェクトの属性を比較します。または、RID 500（デフォルトの管理者）に対するユーザー。
* 何かがあまりにも良すぎる場合は確認してください
* [https://github.com/JavelinNetworks/HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster)

### Microsoft ATA検出のバイパス

#### ユーザー列挙

ATAはDCでセッションを列挙しようとするときにのみ文句を言うので、DCではなく他のホストでセッションを探さなければ、おそらく検出されません。

#### チケットのなりすまし作成（Over pass the hash, golden ticket...）

チケットを作成するときは、ATAがNTLMへの劣化として悪意のあるものと識別するので、**aes**キーも使用してください。

#### DCSync

ドメインコントローラーから実行しない場合、ATAに捕まります、ごめんなさい。

## その他のツール

* [ドメイン監査の自動化を行うPowershellスクリプト](https://github.com/phillips321/adaudit)
* [アクティブディレクトリを列挙するPythonスクリプト](https://github.com/ropnop/windapsearch)
* [アクティブディレクトリを列挙するPythonスクリプト](https://github.com/CroweCybersecurity/ad-ldap-enum)

## 参考文献

* [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？ **HackTricksであなたの会社を広告したいですか？** または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロードしたいですか？** [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見してください、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* [**公式のPEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加するか**、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**に**フォローしてください。**
* **ハッキングのトリックを共有するために、** [**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください。**

</details>
```
