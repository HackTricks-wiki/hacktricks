# アクセス トークン

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricks で企業を宣伝**してみたいですか？または **最新バージョンの PEASS にアクセスしたり、HackTricks を PDF でダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) を発見しましょう。独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクションです。
* [**公式 PEASS & HackTricks スワッグ**](https://peass.creator-spring.com) を手に入れましょう。
* **💬** [**Discord グループ**](https://discord.gg/hRep4RUj7f) に参加するか、[**telegram グループ**](https://t.me/peass) に参加するか、**Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live) **をフォロー**してください。
* **ハッキングテクニックを共有するには、** [**hacktricks リポジトリ**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud リポジトリ**](https://github.com/carlospolop/hacktricks-cloud) **に PR を提出してください。**

</details>

## アクセス トークン

**システムにログインした各ユーザーは、そのログオンセッションのセキュリティ情報を持つアクセス トークンを保持**しています。ユーザーがログオンすると、システムはアクセス トークンを作成します。**ユーザーの代理で実行されるすべてのプロセスには、アクセス トークンのコピーがあります**。トークンには、ユーザー、ユーザーのグループ、およびユーザーの特権を識別する情報が含まれています。また、トークンには、現在のログオンセッションを識別するログオン SID（セキュリティ識別子）も含まれています。

この情報は `whoami /all` を実行して確認できます。
```
whoami /all

USER INFORMATION
----------------

User Name             SID
===================== ============================================
desktop-rgfrdxl\cpolo S-1-5-21-3359511372-53430657-2078432294-1001


GROUP INFORMATION
-----------------

Group Name                                                    Type             SID                                                                                                           Attributes
============================================================= ================ ============================================================================================================= ==================================================
Mandatory Label\Medium Mandatory Level                        Label            S-1-16-8192
Everyone                                                      Well-known group S-1-1-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114                                                                                                     Group used for deny only
BUILTIN\Administrators                                        Alias            S-1-5-32-544                                                                                                  Group used for deny only
BUILTIN\Users                                                 Alias            S-1-5-32-545                                                                                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Performance Log Users                                 Alias            S-1-5-32-559                                                                                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                                      Well-known group S-1-5-4                                                                                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                                                 Well-known group S-1-2-1                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11                                                                                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                                Well-known group S-1-5-15                                                                                                      Mandatory group, Enabled by default, Enabled group
MicrosoftAccount\cpolop@outlook.com                           User             S-1-11-96-3623454863-58364-18864-2661722203-1597581903-3158937479-2778085403-3651782251-2842230462-2314292098 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                    Well-known group S-1-5-113                                                                                                     Mandatory group, Enabled by default, Enabled group
LOCAL                                                         Well-known group S-1-2-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Cloud Account Authentication                     Well-known group S-1-5-64-36                                                                                                   Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```
または、Sysinternalsの_Process Explorer_を使用する（プロセスを選択して"Security"タブにアクセス）：

![](<../../.gitbook/assets/image (321).png>)

### ローカル管理者

ローカル管理者がログインすると、**2つのアクセス トークンが作成**されます：1つは管理者権限を持ち、もう1つは通常の権限を持ちます。**デフォルトでは**、このユーザーがプロセスを実行するときは、**通常**（管理者でない）**権限を使用**します。このユーザーが管理者として何かを**実行**しようとすると（たとえば"管理者として実行"を選択すると）、**UAC**が許可を求めるために使用されます。\
[UACについて詳しく知りたい場合は、[このページを読んでください](../authentication-credentials-uac-and-efs.md#uac)**。

### 資格情報ユーザーの偽装

他のユーザーの**有効な資格情報**を持っている場合、それらの資格情報で**新しいログオン セッションを作成**できます：
```
runas /user:domain\username cmd.exe
```
**アクセス トークン** には、**LSASS** 内のログオン セッションの **参照** も含まれており、プロセスがネットワークのオブジェクトにアクセスする必要がある場合に役立ちます。\
ネットワーク サービスにアクセスするために **異なる資格情報を使用するプロセス** を起動できます。
```
runas /user:domain\username /netonly cmd.exe
```
### トークンの種類

利用可能な2種類のトークンがあります：

- **プライマリトークン**：プロセスのセキュリティ資格情報の表現として機能します。プライマリトークンの作成とプロセスへの関連付けは昇格された特権を必要とするアクションであり、特権の分離の原則を強調しています。通常、認証サービスがトークンの作成を担当し、ログオンサービスがユーザーのオペレーティングシステムシェルとの関連付けを処理します。プロセスは作成時に親プロセスのプライマリトークンを継承することに注意する価値があります。

- **模倣トークン**：サーバーアプリケーションが一時的にクライアントのアイデンティティを採用して安全なオブジェクトにアクセスするための権限を与えます。このメカニズムは、次の4つの操作レベルに分類されます：
  - **匿名**：未識別のユーザーと同様のサーバーアクセスを許可します。
  - **識別**：オブジェクトアクセスに使用せずにクライアントのアイデンティティをサーバーが検証できるようにします。
  - **模倣**：サーバーがクライアントのアイデンティティの下で操作できるようにします。
  - **委任**：模倣に似ていますが、サーバーが対話するリモートシステムにこのアイデンティティの仮定を拡張できる能力を含み、資格情報の保持を確保します。

#### トークンの模倣

十分な特権を持っている場合、metasploitの**incognito**モジュールを使用して他の**トークン**を簡単に**リスト**および**模倣**することができます。これは**他のユーザーとして操作を行う**のに役立つ場合があります。このテクニックを使用して**特権を昇格**することもできます。

### トークン特権

**特権を昇格させるために悪用できるトークン特権**を学びます：

{% content-ref url="privilege-escalation-abusing-tokens/" %}
[privilege-escalation-abusing-tokens](privilege-escalation-abusing-tokens/)
{% endcontent-ref %}

[**すべての可能なトークン特権とこの外部ページでの定義について詳しく見る**](https://github.com/gtworek/Priv2Admin)。

## 参考文献

このチュートリアルでトークンについて詳しく学ぶ：[https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa)および[https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)。
