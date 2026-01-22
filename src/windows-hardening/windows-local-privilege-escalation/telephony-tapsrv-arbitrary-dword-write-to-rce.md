# Telephony tapsrv Arbitrary DWORD Write to RCE (TAPI Server Mode)

{{#include ../../banners/hacktricks-training.md}}

जब Windows Telephony service (TapiSrv, `tapisrv.dll`) को **TAPI server** के रूप में कॉन्फ़िगर किया जाता है, तो यह प्रमाणीकृत SMB क्लाइंट्स को **`tapsrv` MSRPC interface को `\pipe\tapsrv` named pipe पर एक्सपोज़ करता है**। रिमोट क्लाइंट्स के लिए asynchronous event delivery में एक डिज़ाइन बग एक हमलावर को mailslot handle को किसी भी पहले से मौजूद ऐसी फ़ाइल पर **नियंत्रित 4‑byte write** में बदलने देता है जो `NETWORK SERVICE` द्वारा writable हो। इस primitive को चैन करके Telephony admin list को overwrite किया जा सकता है और एक **admin-only arbitrary DLL load** का दुरुपयोग करके `NETWORK SERVICE` के रूप में कोड execute करवाया जा सकता है।

## हमला सतह
- **केवल सक्षम होने पर रिमोट एक्सपोज़र**: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Telephony\Server\DisableSharing` को शेयरिंग की अनुमति देनी चाहिए (या `TapiMgmt.msc` / `tcmsetup /c <server>` के माध्यम से कॉन्फ़िगर)। डिफ़ॉल्ट रूप से `tapsrv` केवल लोकल-ओनली होता है।
- Interface: MS-TRP (`tapsrv`) over **SMB named pipe**, इसलिए हमलावर को वैध SMB auth चाहिए।
- Service account: `NETWORK SERVICE` (मैन्युअल स्टार्ट, ऑन‑डिमैंड)।

## Primitive: Mailslot Path Confusion → Arbitrary DWORD Write
- `ClientAttach(pszDomainUser, pszMachine, ...)` async event delivery को initialize करता है। pull mode में, सर्विस यह करती है:
```c
CreateFileW(pszDomainUser, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
```
बिना यह validate किए कि `pszDomainUser` एक mailslot path (`\\*\MAILSLOT\...`) है। किसी भी **पहले से मौजूद फ़ाइल सिस्टम पथ** को स्वीकार कर लिया जाता है जो `NETWORK SERVICE` द्वारा writable हो।
- हर async event write खोले गए handle पर एक single **`DWORD` = `InitContext`** (जो बाद की `Initialize` request में हमलावर द्वारा नियंत्रित होता है) स्टोर करता है, जिससे **write-what/write-where (4 bytes)** प्राप्त होता है।

## Deterministic Writes को मजबूर करना
1. **टार्गेट फ़ाइल खोलें**: `ClientAttach` के साथ `pszDomainUser = <existing writable path>` (उदा., `C:\Windows\TAPI\tsec.ini`)।
2. हर `DWORD` लिखने के लिए, `ClientRequest` के खिलाफ यह RPC अनुक्रम निष्पादित करें:
- `Initialize` (`Req_Func 47`): `InitContext = <4-byte value>` सेट करें और `pszModuleName = DIALER.EXE` (या per-user priority list में शीर्ष कोई और एंट्री)।
- `LRegisterRequestRecipient` (`Req_Func 61`): `dwRequestMode = LINEREQUESTMODE_MAKECALL`, `bEnable = 1` (line app को रजिस्टर करता है, highest priority recipient को पुनः गणना करता है)।
- `TRequestMakeCall` (`Req_Func 121`): `NotifyHighestPriorityRequestRecipient` को फोर्स करता है, जिससे async event जनरेट होता है।
- `GetAsyncEvents` (`Req_Func 0`): write को dequeue/complete करता है।
- `LRegisterRequestRecipient` को फिर `bEnable = 0` के साथ कॉल करें (unregister)।
- `Shutdown` (`Req_Func 86`) से line app को teardown करें।
- Priority control: “highest priority” recipient का चयन `pszModuleName` की तुलना करके किया जाता है `HKCU\Software\Microsoft\Windows\CurrentVersion\Telephony\HandoffPriorities\RequestMakeCall` के साथ (क्लाइंट की impersonation के दौरान पढ़ा जाता है)। यदि आवश्यक हो तो अपना module name `LSetAppPriority` (`Req_Func 69`) के जरिए डालें।
- फ़ाइल **पहले से मौजूद होनी चाहिए** क्योंकि `OPEN_EXISTING` उपयोग किया जाता है। सामान्य `NETWORK SERVICE`-writable उम्मीदवार: `C:\Windows\System32\catroot2\dberr.txt`, `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\MpCmdRun.log`, `...\MpSigStub.log`।

## From DWORD Write to RCE inside TapiSrv
1. **खुद को Telephony “admin” बनवाएँ**: `C:\Windows\TAPI\tsec.ini` को टार्गेट करें और ऊपर बताए गए 4‑byte writes का उपयोग करके `[TapiAdministrators]\r\n<DOMAIN\\user>=1` जोड़ें। एक **नई** session (`ClientAttach`) शुरू करें ताकि सर्विस INI को फिर से पढ़े और आपके खाते के लिए `ptClient->dwFlags |= 9` सेट करे।
2. **Admin-only DLL load**: `GetUIDllName` भेजें साथ में `dwObjectType = TUISPIDLL_OBJECT_PROVIDERID` और `dwProviderFilenameOffset` के माध्यम से एक path प्रदान करें। admins के लिए, सर्विस `LoadLibrary(path)` करती है फिर export `TSPI_providerUIIdentify` को कॉल करती है:
- यह एक वास्तविक Windows SMB share के UNC paths के साथ काम करता है; कुछ attacker SMB सर्वर `ERROR_SMB_GUEST_LOGON_BLOCKED` के साथ fail कर जाते हैं।
- वैकल्पिक: समान 4‑byte write primitive का उपयोग करके धीरे-धीरे एक लोकल DLL ड्रॉप करें, फिर उसे लोड करें।
3. **Payload**: export `NETWORK SERVICE` के अंतर्गत execute होता है। एक न्यूनतम DLL `cmd.exe /c whoami /all > C:\Windows\Temp\poc.txt` चला सकता है और एक non-zero value (उदा., `0x1337`) रिटर्न कर सकता है ताकि सर्विस DLL को unload कर दे, जिससे execution की पुष्टि हो।

## सुरक्षा कड़े करना / डिटेक्शन नोट्स
- जब तक आवश्यक न हो TAPI server mode को disable रखें; `\pipe\tapsrv` पर रिमोट एक्सेस ब्लॉक करें।
- client-supplied paths को खोलने से पहले mailslot namespace validation (`\\*\MAILSLOT\`) लागू करें।
- `C:\Windows\TAPI\tsec.ini` के ACLs को लॉकडाउन करें और परिवर्तनों की निगरानी करें; गैर‑डिफ़ॉल्ट paths लोड करने वाले `GetUIDllName` कॉल्स पर अलर्ट करें।

## References
- [Who’s on the line? Exploiting RCE in Windows Telephony Service (CVE-2026-20931)](https://swarm.ptsecurity.com/whos-on-the-line-exploiting-rce-in-windows-telephony-service/)

{{#include ../../banners/hacktricks-training.md}}
