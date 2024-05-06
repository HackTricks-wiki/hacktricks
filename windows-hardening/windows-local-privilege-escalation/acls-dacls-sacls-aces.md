# ACLs - DACLs/SACLs/ACEs

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=acls-dacls-sacls-aces)を使用して、世界で最も**高度な**コミュニティツールによって**強化**された**ワークフロー**を簡単に構築し**自動化**します。\
今すぐアクセスを取得:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=acls-dacls-sacls-aces" %}

<details>

<summary><strong>**ゼロからヒーローまでのAWSハッキングを学ぶ**</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksで企業を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を入手
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォロー**する
* **ハッキングテクニックを共有**するために、[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出する

</details>

## **アクセス制御リスト（ACL）**

アクセス制御リスト（ACL）は、オブジェクトとそのプロパティの保護を指示するアクセス制御エントリ（ACE）の順序付きセットで構成されます。基本的に、ACLは、どのセキュリティプリンシパル（ユーザーまたはグループ）が特定のオブジェクトで許可または拒否されるアクションを定義します。

ACLには2種類あります:

* **自由なアクセス制御リスト（DACL）:** オブジェクトへのアクセス権を持つユーザーとグループを指定します。
* **システムアクセス制御リスト（SACL）:** オブジェクトへのアクセス試行の監査を管理します。

ファイルへのアクセスプロセスは、ACEに基づいてアクセス権を決定するために、オブジェクトのセキュリティ記述子をユーザーのアクセストークンと照合することによって行われます。

### **主要コンポーネント**

* **DACL:** オブジェクトへのアクセス権をユーザーとグループに付与または拒否するACEを含みます。基本的には、アクセス権を定義する主要なACLです。
* **SACL:** オブジェクトへのアクセスを監査するために使用され、ACEはセキュリティイベントログに記録されるべきアクセスの種類を定義します。これは、未承認のアクセス試行を検出したり、アクセスの問題をトラブルシューティングするために非常に役立ちます。

### **ACLとシステムの相互作用**

各ユーザーセッションは、そのセッションに関連するセキュリティ情報（ユーザー、グループのアイデンティティ、特権など）を含むアクセストークンと関連付けられます。このトークンには、セッションを一意に識別するログオンSIDも含まれます。

ローカルセキュリティ機関（LSASS）は、アクセス要求を処理し、アクセスを試みるセキュリティプリンシパルに一致するACEをDACLで調べることによってオブジェクトへのアクセスを処理します。関連するACEが見つからない場合、アクセスは直ちに許可されます。それ以外の場合、LSASSはACEをアクセストークン内のセキュリティプリンシパルのSIDと比較してアクセスの適格性を決定します。

### **要約されたプロセス**

* **ACL:** DACLを介してアクセス権を定義し、SACLを介して監査ルールを定義します。
* **アクセストークン:** セッションのユーザー、グループ、特権情報を含みます。
* **アクセス判断:** DACL ACEをアクセストークンと比較することで行われます。監査のためにSACLが使用されます。

### ACEs

**アクセス制御エントリ（ACE）**には、**3つの主要なタイプ**があります:

* **アクセス拒否ACE:** このACEは、指定されたユーザーやグループに対するオブジェクトへのアクセスを明示的に拒否します（DACL内）。
* **アクセス許可ACE:** このACEは、指定されたユーザーやグループに対するオブジェクトへのアクセスを明示的に許可します（DACL内）。
* **システム監査ACE:** システムアクセス制御リスト（SACL）内に配置され、このACEはユーザーやグループによるオブジェクトへのアクセス試行時に監査ログを生成します。アクセスが許可されたか拒否されたか、アクセスの性質を文書化します。

各ACEには、**4つの重要なコンポーネント**があります:

1. ユーザーまたはグループの**セキュリティ識別子（SID）**（またはグラフィカル表現での主要名）。
2. ACEタイプ（アクセス拒否、許可、システム監査を識別するフラグ）。
3. 子オブジェクトが親からACEを継承できるかを決定する**継承フラグ**。
4. オブジェクトの付与された権利を指定する32ビット値である[**アクセスマスク**](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN)。

アクセスの決定は、すべてのACEを順番に調べて行われます:

* **アクセス拒否ACE**がアクセストークン内のトラスティに要求された権利を明示的に拒否する場合。
* **アクセス許可ACE**がアクセストークン内のトラスティにすべての要求された権利を明示的に付与する場合。
* すべてのACEを確認した後、要求された権利が**明示的に許可されていない**場合、アクセスは暗黙的に**拒否**されます。

### ACEの順序

**ACE**（誰がアクセスできるかできないかを示すルール）がリストである**DACL**に配置される方法は非常に重要です。これは、システムがこれらのルールに基づいてアクセスを許可または拒否した後、残りを見なくなるためです。

これらのACEを整理する最良の方法があり、それを**"正準順序"**と呼びます。この方法は、すべてがスムーズにかつ公平に機能するようにするのに役立ちます。**Windows 2000**や**Windows Server 2003**などのシステムでは、次のようになります:

* まず、**このアイテムに特に作成されたすべてのルール**を、親フォルダーなどの他の場所から来たものよりも前に配置します。
* これらの特定のルールには、**"no"（拒否）**を示すものを**"yes"（許可）**を示すものの前に配置します。
* 他の場所から来たルールについては、親などの**最も近いソース**から始めて、そこから戻ります。再び、**"no"**を**"yes"**の前に配置します。

この設定には2つの大きな利点があります:

* 特定の**"no"**がある場合、他の**"yes"**ルールがあっても尊重されることを確認します。
* アイテムの所有者が、親フォルダーやさらに後ろからのルールが適用される前に、誰が入るかについて**最終的な決定権**を持つことができます。

この方法で行うことで、ファイルやフォルダーの所有者は、アクセス権を非常に正確に制御し、正しい人が入れるようにし、間違った人が入れないようにします。

![](https://www.ntfs.com/images/screenshots/ACEs.gif)

したがって、**"正準順序"**は、アクセスルールが明確でうまく機能し、特定のルールを最初に配置し、すべてをスマートに整理することに関するものです。

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)を使用して、世界で最も**高度な**コミュニティツールによって**強化**された**ワークフロー**を簡単に構築し**自動化**します。\
今すぐアクセスを取得:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
### GUIの例

[**ここからの例**](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)

これはACL、DACL、およびACEを表示するフォルダのクラシックなセキュリティタブです：

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../.gitbook/assets/classicsectab.jpg)

**詳細ボタン**をクリックすると、継承などの追加オプションが表示されます：

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../.gitbook/assets/aceinheritance.jpg)

そして、セキュリティプリンシパルを追加または編集する場合：

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../.gitbook/assets/editseprincipalpointers1.jpg)

最後に、監査タブのSACLがあります：

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../.gitbook/assets/audit-tab.jpg)

### 簡略化された方法でアクセス制御を説明する

リソースへのアクセスを管理する際、フォルダなどのリストとルールであるアクセス制御リスト（ACL）とアクセス制御エントリ（ACE）が使用されます。これらは特定のデータにアクセスできるかどうかを定義します。

#### 特定のグループへのアクセスを拒否する

Costという名前のフォルダがあると想像してください。マーケティングチームを除いて誰もがアクセスできるようにしたいとします。ルールを正しく設定することで、マーケティングチームがアクセスを拒否される前に他の全員がアクセスできるように確認できます。

#### 拒否されたグループの特定のメンバーへのアクセスを許可する

一般的にマーケティングチームがアクセス権を持つべきでないにもかかわらず、マーケティングディレクターであるBobがCostフォルダにアクセスする必要があるとします。Bobのためにアクセスを許可する特定のルール（ACE）を追加し、マーケティングチームへのアクセスを拒否するルールの前に配置します。これにより、Bobはチーム全体の制限にもかかわらずアクセス権を取得します。

#### アクセス制御エントリの理解

ACEはACL内の個々のルールです。ユーザーまたはグループを識別し、許可または拒否されるアクセスを指定し、これらのルールがサブアイテムにどのように適用されるか（継承）を決定します。ACEには次の2つの主要なタイプがあります：

* **一般的なACE**：これらは広く適用され、オブジェクトのすべてのタイプに影響を与えるか、コンテナ（フォルダなど）と非コンテナ（ファイルなど）の間だけを区別します。たとえば、ユーザーがフォルダの内容を見ることを許可するが、フォルダ内のファイルにアクセスすることを許可しないルールなどがあります。
* **オブジェクト固有のACE**：これらはより正確な制御を提供し、特定のオブジェクトのタイプまたはオブジェクト内の個々のプロパティに対してルールを設定できます。たとえば、ユーザーディレクトリ内で、ユーザーが電話番号を更新することを許可するが、ログイン時間を更新することを許可しないルールがあるかもしれません。

各ACEには、ルールが適用される対象（セキュリティ識別子またはSID）、ルールが許可または拒否する内容（アクセスマスク）、および他のオブジェクトに継承される方法などの重要な情報が含まれています。

#### ACEタイプ間の主な違い

* **一般的なACE**は、オブジェクトのすべての側面またはコンテナ内のすべてのオブジェクトに同じルールが適用される単純なアクセス制御シナリオに適しています。
* **オブジェクト固有のACE**は、特にActive Directoryなどの環境で、オブジェクトの特定のプロパティへのアクセスを異なる方法で制御する必要がある場合に使用されます。

要するに、ACLとACEは正確なアクセス制御を定義し、機密情報やリソースにアクセスできるのは適切な個人やグループだけであり、アクセス権を個々のプロパティやオブジェクトタイプのレベルまで調整できるようにします。

### アクセス制御エントリのレイアウト

| ACEフィールド | 説明                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| タイプ        | ACEのタイプを示すフラグ。Windows 2000およびWindows Server 2003では、6つのACEタイプがサポートされています。すべてのセキュア可能なオブジェクトにアタッチされる3つの一般的なACEタイプ。Active Directoryオブジェクトに発生する可能性のある3つのオブジェクト固有のACEタイプ。                                                                                                                                                                                                                                                            |
| フラグ       | 継承と監査を制御するビットフラグのセット。                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| サイズ        | ACEに割り当てられたメモリのバイト数。                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| アクセスマスク | オブジェクトのアクセス権に対応する32ビット値。ビットはオンまたはオフに設定できますが、設定の意味はACEのタイプに依存します。たとえば、読み取り権限に対応するビットがオンになっており、ACEのタイプが拒否である場合、ACEはオブジェクトの権限を読み取る権利を拒否します。同じビットがオンに設定されていても、ACEのタイプが許可である場合、ACEはオブジェクトの権限を読み取る権利を付与します。アクセスマスクの詳細については、次の表を参照してください。 |
| SID         | このACEによって制御または監視されるユーザーまたはグループを識別します。                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### アクセスマスクのレイアウト

| ビット（範囲） | 意味                            | 説明/例                       |
| ----------- | ---------------------------------- | ----------------------------------------- |
| 0 - 15      | オブジェクト固有のアクセス権      | データの読み取り、実行、データの追加           |
| 16 - 22     | 標準アクセス権             | 削除、ACLの書き込み、所有者の書き込み            |
| 23          | セキュリティACLにアクセスできる            |                                           |
| 24 - 27     | 予約済み                           |                                           |
| 28          | 一般ALL（読み取り、書き込み、実行） | 以下すべて                          |
| 29          | 一般実行                    | プログラムを実行するために必要なすべてのもの |
| 30          | 一般書き込み                      | ファイルに書き込むために必要なすべてのもの   |
| 31          | 一般読み取り                       | ファイルを読むために必要なすべてのもの       |

## 参考文献

* [https://www.ntfs.com/ntfs-permissions-acl-use.htm](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
* [https://secureidentity.se/acl-dacl-sacl-and-the-ace/](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)
* [https://www.coopware.in2.info/\_ntfsacl\_ht.htm](https://www.coopware.in2.info/\_ntfsacl\_ht.htm)

<details>

<summary><strong>ゼロからヒーローまでのAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksのスウォッグ**](https://peass.creator-spring.com)を手に入れる
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFTs](https://opensea.io/collection/the-peass-family)のコレクションを見る
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**または[telegramグループ](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **ハッキングトリックを共有する**には、[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=acls-dacls-sacls-aces)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築**および**自動化**します。\
今すぐアクセスしてください：

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=acls-dacls-sacls-aces" %}
