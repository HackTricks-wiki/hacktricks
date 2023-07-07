# アクセス トークン

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricks で会社を宣伝**したいですか？または、**最新バージョンの PEASS にアクセスしたり、HackTricks を PDF でダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な [**NFT**](https://opensea.io/collection/the-peass-family) のコレクションです。
* [**公式の PEASS & HackTricks スワッグ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord グループ**](https://discord.gg/hRep4RUj7f) または [**telegram グループ**](https://t.me/peass) に**参加**するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)** をフォロー**してください。
* **ハッキングのトリックを共有**するには、[**hacktricks リポジトリ**](https://github.com/carlospolop/hacktricks) と [**hacktricks-cloud リポジトリ**](https://github.com/carlospolop/hacktricks-cloud) に PR を提出してください。

</details>

## アクセス トークン

**システムにログインしたユーザーごとに、セキュリティ情報を持つアクセス トークンが作成**されます。ユーザーがログインすると、システムはアクセス トークンを作成します。**ユーザーの代わりに実行されるすべてのプロセスには、アクセス トークンのコピーがあります**。トークンには、ユーザー、ユーザーのグループ、およびユーザーの特権が識別されます。トークンには、現在のログインセッションを識別するログオン SID（セキュリティ識別子）も含まれています。

この情報は、`whoami /all` を実行して確認できます。
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
または、Sysinternalsの_Process Explorer_を使用して（プロセスを選択し、「セキュリティ」タブにアクセス）：

![](<../../.gitbook/assets/image (321).png>)

### ローカル管理者

ローカル管理者がログインすると、**2つのアクセス トークンが作成**されます：1つは管理者権限を持ち、もう1つは通常の権限を持ちます。**デフォルトでは**、このユーザーがプロセスを実行するときには、**通常の**（管理者ではない）**権限のトークンが使用**されます。このユーザーが管理者として何かを実行しようとすると（たとえば、「管理者として実行」など）、**UAC**が許可を求めるために使用されます。\
UACについて[**詳しくは、このページを読んでください**](../authentication-credentials-uac-and-efs.md#uac)**。**

### 資格情報のユーザーなりすまし

他のユーザーの**有効な資格情報**を持っている場合、それらの資格情報で**新しいログオンセッション**を作成できます：
```
runas /user:domain\username cmd.exe
```
アクセストークンには、LSASS内のログオンセッションの参照もあります。これは、プロセスがネットワークのオブジェクトにアクセスする必要がある場合に便利です。\
ネットワークサービスにアクセスするために異なる資格情報を使用するプロセスを起動することができます。
```
runas /user:domain\username /netonly cmd.exe
```
これは、ネットワーク内のオブジェクトにアクセスするための有用な資格情報を持っているが、これらの資格情報が現在のホスト内では有効ではない場合に役立ちます（現在のホストでは現在のユーザー権限が使用されます）。

### トークンの種類

利用可能な2つのトークンの種類があります：

* **プライマリトークン**：プライマリトークンは、**プロセスに関連付けられる**ことができ、プロセスのセキュリティサブジェクトを表します。プライマリトークンの作成とプロセスへの関連付けは、特権操作であり、特権の分離のために2つの異なる特権が必要です。典型的なシナリオでは、認証サービスがトークンを作成し、ログオンサービスがユーザーのオペレーティングシステムシェルに関連付けます。プロセスは最初に親プロセスのプライマリトークンのコピーを継承します。
* **模倣トークン**：模倣は、Windows NTで実装されたセキュリティの概念であり、サーバーアプリケーションがセキュアオブジェクトへのアクセスに関して一時的に「クライアントとして」振る舞うことを可能にします。模倣には**4つの可能なレベル**があります：

* **匿名**：サーバーに匿名/未識別のユーザーのアクセス権を与えます
* **識別**：サーバーがクライアントのアイデンティティを調査することを許可しますが、そのアイデンティティを使用してオブジェクトにアクセスすることはできません
* **模倣**：サーバーがクライアントの代わりに動作することを許可します
* **委任**：模倣と同じですが、サーバーが接続するリモートシステムにも拡張されます（資格情報の保存を通じて）。

クライアントは、接続パラメータとしてサーバーに利用可能な最大模倣レベル（あれば）を選択できます。委任と模倣は特権操作です（模倣は元々特権ではありませんでしたが、クライアントAPIの実装上の注意不足により、デフォルトレベルを「識別」に制限しないことで、特権のないサーバーが意図しない特権のあるクライアントを模倣することができるようになりました）。**模倣トークンはスレッドにのみ関連付けることができ、クライアントプロセスのセキュリティサブジェクトを表します。模倣トークンは通常、DCE RPC、DDE、名前付きパイプなどのIPCメカニズムによって、暗黙的に現在のスレッドに作成および関連付けられます。**

#### トークンの模倣

Metasploitの_**incognito**_モジュールを使用すると、十分な特権があれば他のトークンを簡単に**リスト**して**模倣**することができます。これは、他のユーザーとして操作を実行するために役立つ場合があります。また、この技術を使用して特権を昇格させることもできます。

### トークン特権

特権を昇格させるために悪用できる**トークン特権**を学びましょう：

{% content-ref url="privilege-escalation-abusing-tokens/" %}
[privilege-escalation-abusing-tokens](privilege-escalation-abusing-tokens/)
{% endcontent-ref %}

[**外部ページ**](https://github.com/gtworek/Priv2Admin)で**可能なトークン特権とその定義の一覧**をご覧ください。

## 参考文献

トークンについての詳細は、次のチュートリアルを参照してください：[https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa)および[https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？ HackTricksであなたの会社を宣伝したいですか？または、PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロードしたりしたいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクション
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください。**

</details>
