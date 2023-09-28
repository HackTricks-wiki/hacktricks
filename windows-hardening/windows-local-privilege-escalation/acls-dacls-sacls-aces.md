# ACLs - DACLs/SACLs/ACEs

<figure><img src="../../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築**し、自動化します。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** HackTricksで**会社を宣伝**したいですか？または、**最新バージョンのPEASSをダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです
* [**公式のPEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **および** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください。**

</details>

## **アクセス制御リスト（ACL）**

ACLは、オブジェクトとそのプロパティに適用される保護を定義するACEの順序付きリストです。各ACEはセキュリティプリンシパルを識別し、そのセキュリティプリンシパルに対して許可、拒否、または監査されるアクセス権のセットを指定します。

オブジェクトのセキュリティ記述子には、次の2つのACLが含まれる場合があります。

1. アクセスが許可または拒否されるユーザーとグループを識別するDACL
2. アクセスが監査される方法を制御するSACL

ユーザーがファイルにアクセスしようとすると、WindowsシステムはAccessCheckを実行し、セキュリティ記述子をユーザーのアクセストークンと比較し、ユーザーがアクセスを許可され、どの種類のアクセスが許可されるかを評価します。

### **自由裁量アクセス制御リスト（DACL）**

DACL（ACLとしても言及されることが多い）は、オブジェクトに割り当てられたアクセス許可を識別するユーザーとグループを識別します。それは、セキュアオブジェクトに対してペアのACE（アカウント+アクセス権）のリストを含んでいます。

### **システムアクセス制御リスト（SACL）**

SACLを使用すると、セキュリティの保護されたオブジェクトへのアクセスを監視できます。SACLのACEは、セキュリティイベントログに記録されるアクセスの種類を決定します。モニタリングツールを使用すると、悪意のあるユーザーがセキュリティの保護されたオブジェクトにアクセスしようとすると、適切な人に警告を発することができます。また、インシデントのシナリオでは、ログを使用して過去の手順を追跡することができます。そして最後に、トラブルシューティングのためにアクセスの問題を解決するためにログを有効にすることができます。

## システムがACLを使用する方法

システムにログインしている**各ユーザーは、そのログオンセッションのセキュリティ情報を持つアクセストークンを保持**しています。ユーザーがログオンすると、システムはアクセストークンを作成します。ユーザーの代わりに実行される**すべてのプロセスには、アクセストークンのコピーがあります**。トークンは、ユーザー、ユーザーのグループ、およびユーザーの特権を識別します。トークンには、現在のログオンセッションを識別するログオンSID（セキュリティ識別子）も含まれています。

スレッドがセキュリティの保護されたオブジェクトにアクセスしようとすると、LSASS（ローカルセキュリティ機関）はアクセスを許可または拒否します。これを行うために、LSASSはスレッドに適用されるACEを探すためにSDSデータストリーム内のDACL（自由裁量アクセス制御リスト）を検索します。

オブジェクトのDACLの各ACEは、セキュリティプリンシパルまたはログオンセッションに対して許可または拒否されるアクセス権を指定します。オブジェクトの所有者がそのオブジェクトのDACLにACEを作成していない場合、システムはすぐにアクセスを許可します。

LSASSがACEを見つけた場合、各ACEの委任SIDをスレッドのアクセストークンで識別される委任SIDと比較します。

### ACE

ADのすべてのセキュリティオブジェクトに適用できる**3つの主要なACEのタイプ**があります：

| **ACE**                  | **説明**                                                                                                                                                            |
| ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`アクセス拒否ACE`**  | ユーザーまたはグループがオブジェクトに明示的にアクセスが拒否されていることを示すためにDACL内で使用されます                                                                                   |
| **`アクセス許可ACE`** | ユーザーまたはグループがオブジェクトに明示的にアクセスが許可されていることを示すためにDACL内で使用されます                                                                                  |
| **`システム監査ACE`**   | ユーザーまたはグループがオブジェクトにアクセスしようとすると、SACL内のACEが監査ログを生成します。ア
### ACEの順序

要求されたアクセスが明示的に許可または拒否された場合、システムはACEのチェックを停止するため、DACL内のACEの順序は重要です。

DACL内のACEの優先順位は「正準」順序と呼ばれます。Windows 2000およびWindows Server 2003では、正準順序は次のとおりです。

1. すべての「明示的」ACEは、任意の「継承」ACEの前にグループに配置されます。
2. 「明示的」ACEのグループ内では、「アクセス拒否」ACEは「アクセス許可」ACEの前に配置されます。
3. 「継承」グループ内では、子オブジェクトの親から継承されたACEが最初に配置され、その後、祖父から継承されたACEなど、オブジェクトツリーを上に向かって継承されたACEが配置されます。その後、アクセス拒否ACEはアクセス許可ACEの前に配置されます。

以下の図は、ACEの正準順序を示しています。

### ACEの正準順序

![ACE](https://www.ntfs.com/images/screenshots/ACEs.gif)

正準順序により、次のことが実現されます。

* 明示的な「アクセス拒否ACE」は、明示的な「アクセス許可ACE」に関係なく強制されます。つまり、オブジェクトの所有者は、ユーザーグループへのアクセスを許可し、そのグループの一部にアクセスを拒否する権限を定義できます。
* すべての「明示的ACE」は、継承されたACEの前に処理されます。これは、任意のアクセス制御の概念と一致しています。子オブジェクト（たとえばファイル）へのアクセスは、親オブジェクト（たとえばフォルダ）の所有者ではなく、子オブジェクトの所有者の裁量によるものです。子オブジェクトの所有者は、直接子オブジェクトに対してアクセス権を定義できます。その結果、継承されたアクセス許可の効果が変更されます。

<figure><img src="../../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化されたワークフローを簡単に構築および自動化できます。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### GUIの例

これは、ACL、DACL、およびACEを表示するフォルダのクラシックなセキュリティタブです。

![](../../.gitbook/assets/classicsectab.jpg)

「詳細」ボタンをクリックすると、継承などの追加オプションが表示されます。

![](../../.gitbook/assets/aceinheritance.jpg)

セキュリティプリンシパルを追加または編集する場合：

![](../../.gitbook/assets/editseprincipalpointers1.jpg)

最後に、監査タブのSACLがあります。

![](../../.gitbook/assets/audit-tab.jpg)

### 例：グループへの明示的なアクセス拒否

この例では、アクセス許可されたグループは「Everyone」であり、アクセス拒否されたグループは「Marketing」であり、それは「Everyone」の一部です。

「Cost」フォルダへのMarketingグループのアクセスを拒否したい場合、CostフォルダのACEが正準順序であれば、Marketingを拒否するACEはEveryoneを許可するACEの前に配置されます。

アクセスチェック中、オペレーティングシステムはオブジェクトのDACLに表示される順序でACEをステップ実行するため、許可するACEの前に拒否するACEが処理されます。その結果、Marketingグループのメンバーはアクセスが拒否されます。他のユーザーはオブジェクトにアクセスが許可されます。

### 例：明示的なアクセス許可が継承よりも優先

この例では、CostフォルダにはMarketing（親オブジェクト）へのアクセスを拒否する継承可能なACEがあります。つまり、Marketingグループのメンバー（または子）であるすべてのユーザーは、継承によってアクセスが拒否されます。

MarketingディレクターであるBobにアクセスを許可したい場合、BobはMarketingグループのメンバーとして、継承によってCostフォルダへのアクセスが拒否されます。子オブジェクト（ユーザーBob）の所有者は、Costフォルダへのアクセスを許可する明示的なACEを定義します。子オブジェクトのACEが正準順序であれば、Bobへのアクセスを許可する明示的なACEは、Marketingグループへのアクセスを拒否する継承されたACEを含む継承されたACEの前に配置されます。

アクセスチェック中、オペレーティングシステムはMarketingグループへのアクセスを拒否するACEに到達する前に、Bobへのアクセスを許可するACEに到達します。その結果、BobはMarketingグループのメンバーであるにもかかわらず、オブジェクトにアクセスが許可されます。Marketingグループの他のメンバーはアクセスが拒否されます。

### アクセス制御エントリ

前述のように、ACL（アクセス制御リスト）は、ACE（アクセス制御エントリ）の順序付きリストです。各ACEには、次の情報が含まれます。

* 特定のユーザーまたはグループを識別するセキュリティ識別子（SID）。
* アクセス権を指定するアクセスマスク。
* 子オブジェクトがACEを継承できるかどうかを決定するビットフラグのセット。
* ACEのタイプを示すフラグ。

ACEは基本的に同じです。それらを区別するのは、継承とオブジェクトへのアクセスに対する制御の度合いです。2つのタイプのACEがあります。

* すべてのセキュリティ可能なオブジェクトにアタッチされるジェネリックタイプ。
* Active DirectoryオブジェクトのACLにのみ存在できるオブジェクト固有のタイプ。

### ジェネリックACE

ジェネリックACEは、継承される子オブジェクトの種類を制御するための制限された制御を提供します。基本的に、コンテナと非コンテナの区別しかできません。

たとえば、NTFSのFolderオブジェクトのDACLには、フォルダの内容をリストするためのジェネリックACEが含まれる場合があります。フォルダの内容をリストすることは、コンテナオブジェクトでのみ実行できる操作ですので、操作を許可するACEはCONTAINER\_INHERIT\_ACEとしてフラグ付けされます。フォル
### アクセス制御エントリのレイアウト

| ACEフィールド | 説明                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| ------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| タイプ       | ACEのタイプを示すフラグ。Windows 2000とWindows Server 2003では、6つのACEタイプがサポートされています。すべてのセキュリティオブジェクトに関連付けられる3つの一般的なACEタイプと、Active Directoryオブジェクトに発生する可能性のある3つのオブジェクト固有のACEタイプがあります。                                                                                                                                                                                                                          |
| フラグ       | 継承と監査を制御するためのビットフラグのセット。                                                                                                                                                                                                                                                                                                                                                                                                 |
| サイズ       | ACEに割り当てられるメモリのバイト数。                                                                                                                                                                                                                                                                                                                                                                                                           |
| アクセスマスク | オブジェクトのアクセス権に対応する32ビットの値。ビットはオンまたはオフに設定できますが、設定の意味はACEのタイプに依存します。たとえば、読み取り権限に対応するビットがオンになっており、ACEのタイプがDenyである場合、ACEはオブジェクトの権限の読み取りを拒否します。同じビットがオンに設定されていても、ACEのタイプがAllowである場合、ACEはオブジェクトの権限の読み取りを許可します。アクセスマスクの詳細については、次の表を参照してください。 |
| SID          | このACEによって制御または監視されるユーザーまたはグループを識別します。                                                                                                                                                                                                                                                                                                                                                                         |

### アクセスマスクのレイアウト

| ビット（範囲） | 意味                               | 説明/例                                 |
| -------------- | ---------------------------------- | ---------------------------------------- |
| 0 - 15         | オブジェクト固有のアクセス権         | データの読み取り、実行、データの追加       |
| 16 - 22        | 標準的なアクセス権                 | 削除、ACLの書き込み、所有者の書き込み     |
| 23             | セキュリティACLにアクセスできる     |                                          |
| 24 - 27        | 予約済み                           |                                          |
| 28             | 一般的なALL（読み取り、書き込み、実行） | 以下のすべて                            |
| 29             | 一般的な実行                       | プログラムを実行するために必要なすべてのもの |
| 30             | 一般的な書き込み                   | ファイルに書き込むために必要なすべてのもの |
| 31             | 一般的な読み取り                   | ファイルを読み取るために必要なすべてのもの |

## 参考文献

* [https://www.ntfs.com/ntfs-permissions-acl-use.htm](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
* [https://secureidentity.se/acl-dacl-sacl-and-the-ace/](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** HackTricksで**会社を宣伝**したいですか？または、**PEASSの最新バージョンやHackTricksのPDFをダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけて、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションを発見してください。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください。**

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化されたワークフローを簡単に構築して自動化します。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
