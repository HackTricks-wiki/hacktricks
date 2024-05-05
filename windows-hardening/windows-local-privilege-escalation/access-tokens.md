# アクセス トークン

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert) でゼロからヒーローまでAWSハッキングを学びましょう</strong></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricks で企業を宣伝**したいですか？または **最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な [**NFTs**](https://opensea.io/collection/the-peass-family)コレクションです。
* [**公式PEASS＆HackTricksスウェグ**](https://peass.creator-spring.com)を手に入れましょう。
* **[💬](https://emojipedia.org/speech-balloon/) Discordグループ**に参加するか、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter**で私をフォローしてください 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングテクニックを共有するために、** [**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください。**

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) は、**ダークウェブ**を活用した検索エンジンで、**企業やその顧客が** **スティーラーマルウェアによって** **侵害されたかどうかを確認する** **無料**の機能を提供しています。

WhiteIntelの主な目標は、情報窃取マルウェアによるアカウント乗っ取りやランサムウェア攻撃に対抗することです。

彼らのウェブサイトをチェックして、**無料**でエンジンを試すことができます：

{% embed url="https://whiteintel.io" %}

***

## アクセス トークン

**システムにログインした各ユーザーは、そのログオンセッションのセキュリティ情報を持つアクセス トークンを保持**しています。ユーザーがログオンすると、システムはアクセス トークンを作成します。**ユーザーの代理で実行されるすべてのプロセスには、アクセス トークンのコピーがあります**。 トークンには、ユーザー、ユーザーのグループ、およびユーザーの特権が識別されます。 トークンには、現在のログオンセッションを識別するログオンSID（セキュリティ識別子）も含まれています。

この情報は、`whoami /all`を実行して確認できます。
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

![](<../../.gitbook/assets/image (772).png>)

### ローカル管理者

ローカル管理者がログインすると、**2つのアクセス トークンが作成**されます：1つは管理者権限を持ち、もう1つは通常の権限を持ちます。**デフォルトでは**、このユーザーがプロセスを実行するときは、**通常**（管理者でない）**権限を使用**します。このユーザーが管理者として何かを**実行**しようとすると（たとえば"管理者として実行"）、**UAC**が許可を求めるために使用されます。\
UACについて[**詳しく学びたい場合は、このページを読んでください**](../authentication-credentials-uac-and-efs/#uac)**。**

### 資格情報ユーザーの偽装

他のユーザーの**有効な資格情報**を持っている場合、それらの資格情報で**新しいログオン セッションを作成**できます：
```
runas /user:domain\username cmd.exe
```
**アクセス トークン** には、**LSASS** 内のログオン セッションの **参照** も含まれています。これは、プロセスがネットワークのオブジェクトにアクセスする必要がある場合に役立ちます。\
次の方法で、ネットワーク サービスにアクセスするために **異なる資格情報を使用するプロセス** を起動できます:
```
runas /user:domain\username /netonly cmd.exe
```
### トークンの種類

利用可能な2種類のトークンがあります：

- **プライマリトークン**：プロセスのセキュリティ資格情報の表現として機能します。プライマリトークンの作成とプロセスへの関連付けは昇格された特権を必要とするアクションであり、特権の分離の原則を強調しています。通常、認証サービスがトークンの作成を担当し、ログオンサービスがユーザーのオペレーティングシステムシェルとの関連付けを処理します。プロセスは作成時に親プロセスのプライマリトークンを継承します。
- **模倣トークン**：サーバーアプリケーションが一時的にクライアントのアイデンティティを採用して安全なオブジェクトにアクセスするための権限を与えます。このメカニズムは次の4つの操作レベルに分層されます：
  - **匿名**：未識別のユーザーと同様のサーバーアクセスを許可します。
  - **識別**：オブジェクトアクセスに使用せずにクライアントのアイデンティティをサーバーが確認できるようにします。
  - **模倣**：サーバーがクライアントのアイデンティティの下で動作できるようにします。
  - **委任**：模倣に似ていますが、サーバーが対話するリモートシステムにこのアイデンティティ仮定を拡張し、資格情報の保持を確保します。

#### トークンの模倣

十分な特権がある場合、metasploitの**incognito**モジュールを使用して他の**トークン**を簡単に**リスト**および**模倣**できます。これは**他のユーザーであるかのようにアクションを実行**するのに役立ちます。このテクニックを使用して**特権を昇格**することもできます。

### トークン特権

**特権を濫用して特権を昇格させるために濫用できる**トークン特権を学びます：

{% content-ref url="privilege-escalation-abusing-tokens.md" %}
[privilege-escalation-abusing-tokens.md](privilege-escalation-abusing-tokens.md)
{% endcontent-ref %}

[**すべての可能なトークン特権とこの外部ページでの定義について詳しく見る**](https://github.com/gtworek/Priv2Admin)
