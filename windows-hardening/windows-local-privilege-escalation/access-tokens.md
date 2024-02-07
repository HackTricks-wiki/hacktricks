# アクセス トークン

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricks で企業を宣伝**したいですか？または **最新版の PEASS にアクセスしたい**ですか？または **HackTricks を PDF でダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) を発見しましょう、当社の独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクション
* [**公式 PEASS & HackTricks スワッグ**](https://peass.creator-spring.com) を手に入れましょう
* **[**💬**](https://emojipedia.org/speech-balloon/) [**Discord グループ**](https://discord.gg/hRep4RUj7f) に参加するか、[**telegram グループ**](https://t.me/peass) に参加するか、**Twitter** **🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)** をフォローしてください。**
* **ハッキングテクニックを共有するために PR を** [**hacktricks リポジトリ**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud リポジトリ**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## アクセス トークン

**システムにログインした各ユーザー**は、そのログオンセッションのセキュリティ情報を持つ **アクセス トークンを保持**しています。ユーザーがログオンすると、システムはアクセス トークンを作成します。ユーザーの代わりに実行される **すべてのプロセスには、アクセス トークンのコピーがあります**。トークンには、ユーザー、ユーザーのグループ、およびユーザーの特権が識別されます。トークンには、現在のログオンセッションを識別するログオン SID（セキュリティ識別子）も含まれています。

この情報は `whoami /all` を実行することで確認できます。
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

ローカル管理者がログインすると、**2つのアクセス トークンが作成されます**：1つは管理者権限を持ち、もう1つは通常の権限を持ちます。**デフォルトでは**、このユーザーがプロセスを実行するときは、**通常の（管理者でない）権限が使用されます**。このユーザーが管理者として何かを実行しようとすると（たとえば"管理者として実行"）、**UAC**が許可を求めるために使用されます。\
[**UACについて詳しく学びたい場合は、このページを読んでください**](../authentication-credentials-uac-and-efs.md#uac)**。**

### 資格情報ユーザーの模倣

他のユーザーの**有効な資格情報を持っている場合**、それらの資格情報で**新しいログオン セッションを作成**できます：
```
runas /user:domain\username cmd.exe
```
**アクセス トークン** には、**LSASS** 内のログオン セッションの **参照** も含まれており、プロセスがネットワークのオブジェクトにアクセスする必要がある場合に役立ちます。\
ネットワーク サービスにアクセスするために **異なる資格情報を使用するプロセス** を起動できます。
```
runas /user:domain\username /netonly cmd.exe
```
### トークンの種類

利用可能なトークンには2種類あります：

- **プライマリトークン**：プライマリトークンは**プロセスに関連付け**ることができ、プロセスのセキュリティサブジェクトを表します。プライマリトークンの作成とプロセスへの関連付けは、特権操作であり、特権の分離の名の下で2つの異なる特権が必要です。一般的なシナリオでは、認証サービスがトークンを作成し、ログオンサービスがユーザーのオペレーティングシステムシェルに関連付けます。プロセスは最初に親プロセスのプライマリトークンのコピーを継承します。
- **模倣トークン**：模倣はWindows NTに実装されたセキュリティコンセプトで、サーバーアプリケーションが安全なオブジェクトへのアクセスに関して一時的に**クライアントとして振る舞う**ことを可能にします。模倣には**4つの可能なレベル**があります：

  - **匿名**：サーバーに匿名/未識別ユーザーのアクセス権を与えます。
  - **識別**：サーバーがクライアントのアイデンティティを調査できるが、そのアイデンティティを使用してオブジェクトにアクセスすることはできません。
  - **模倣**：サーバーがクライアントを代表して行動できるようにします。
  - **委任**：模倣と同じですが、サーバーが接続するリモートシステムにも拡張されます（資格情報の保持を通じて）。

クライアントは、接続パラメータとしてサーバーに利用可能な最大模倣レベル（あれば）を選択できます。模倣と委任は特権操作です（模倣は最初はそうではありませんでしたが、クライアントAPIの実装における歴史的な不注意が、デフォルトレベルを「識別」に制限しなかったため、特権のないサーバーが不本意な特権を持つクライアントを模倣することを促しました）。**模倣トークンはスレッドにのみ関連付けることができ、クライアントプロセスのセキュリティサブジェクトを表します。** 模倣トークンは通常、DCE RPC、DDE、名前付きパイプなどのIPCメカニズムによって、暗黙的に現在のスレッドに作成および関連付けられます。

#### トークンの模倣

十分な特権がある場合、metasploitの**incognito**モジュールを使用して他の**トークン**を簡単に**リスト**および**模倣**することができます。これは、**他のユーザーであるかのようにアクションを実行**したり、このテクニックを使用して**特権を昇格**するのに役立ちます。

### トークン特権

特権を昇格させるために悪用できる**トークン特権**を学びます：

{% content-ref url="privilege-escalation-abusing-tokens/" %}
[privilege-escalation-abusing-tokens](privilege-escalation-abusing-tokens/)
{% endcontent-ref %}

[**すべての可能なトークン特権とこの外部ページでの定義について詳しく見る**](https://github.com/gtworek/Priv2Admin)。

## 参考文献

このチュートリアルでトークンについて詳しく学ぶ：[https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa) および [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)。
