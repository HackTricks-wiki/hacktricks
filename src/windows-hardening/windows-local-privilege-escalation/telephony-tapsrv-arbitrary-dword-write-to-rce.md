# Telephony tapsrv Arbitrary DWORD Write to RCE (TAPI Server Mode)

{{#include ../../banners/hacktricks-training.md}}

जब Windows Telephony service (TapiSrv, `tapisrv.dll`) को **TAPI server** के रूप में configured किया जाता है, तो यह authenticated SMB clients के लिए **`\pipe\tapsrv` named pipe पर `tapsrv` MSRPC interface** expose करती है। Asynchronous event delivery में CVE-2026-20931 के कारण attacker किसी कथित mailslot handle को **`NETWORK SERVICE` द्वारा writable किसी पहले से मौजूद file में controlled 4-byte write** में बदल सकता है। Published chain Telephony administrator list को overwrite करती है, फिर administrator-only DLL load तक पहुंचती है और `NETWORK SERVICE` के रूप में execute होती है।<sup>[[1]](#references)[[2]](#references)</sup>

## Attack Surface

- **Remote exposure केवल enabled होने पर**: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Telephony\Server\DisableSharing` को sharing की अनुमति देनी चाहिए (या `TapiMgmt.msc` / `tcmsetup /c <server>` के माध्यम से configured होना चाहिए)। Default रूप से `tapsrv` केवल local होता है।
- Interface: **SMB named pipe** के माध्यम से MS-TRP (`tapsrv`), इसलिए attacker को valid SMB auth की आवश्यकता होती है।
- Service account: `NETWORK SERVICE` (manual start, on-demand)।<sup>[[1]](#references)</sup>

## Primitive: Mailslot Path Confusion → Arbitrary DWORD Write
- `ClientAttach(pszDomainUser, pszMachine, ...)` async event delivery को initialize करता है। Pull mode में service यह करती है:
```c
CreateFileW(pszDomainUser, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
```
और यह validate नहीं करती कि `pszDomainUser` एक mailslot path (`\\*\MAILSLOT\...`) है। `NETWORK SERVICE` द्वारा writable कोई भी **existing filesystem path** स्वीकार कर लिया जाता है।
- प्रत्येक async event write खुले हुए handle में एक single **`DWORD` = `InitContext`** store करता है (`InitContext` subsequent `Initialize` request में attacker-controlled होता है), जिससे **write-what/write-where (4 bytes)** primitive मिलती है।<sup>[[1]](#references)</sup>

## Deterministic Writes को Force करना
1. **Target file खोलें**: `pszDomainUser = <existing writable path>` के साथ `ClientAttach` करें (उदाहरण के लिए, `C:\Windows\TAPI\tsec.ini`)।
2. प्रत्येक लिखे जाने वाले `DWORD` के लिए `ClientRequest` के विरुद्ध यह RPC sequence execute करें:
- `Initialize` (`Req_Func 47`): `InitContext = <4-byte value>` और `pszModuleName = DIALER.EXE` (या per-user priority list में कोई अन्य top entry) set करें।
- `LRegisterRequestRecipient` (`Req_Func 61`): `dwRequestMode = LINEREQUESTMODE_MAKECALL`, `bEnable = 1` (line app register करता है और highest priority recipient को फिर से calculate करता है)।
- `TRequestMakeCall` (`Req_Func 121`): `NotifyHighestPriorityRequestRecipient` को force करता है और async event generate करता है।
- `GetAsyncEvents` (`Req_Func 0`): write को dequeue/complete करता है।
- `LRegisterRequestRecipient` को फिर से `bEnable = 0` के साथ चलाएं (unregister)।
- `Shutdown` (`Req_Func 86`) से line app को tear down करें।
- Priority control: “highest priority” recipient का चयन `HKCU\Software\Microsoft\Windows\CurrentVersion\Telephony\HandoffPriorities\RequestMakeCall` के विरुद्ध `pszModuleName` की तुलना करके किया जाता है (client को impersonate करते समय read किया जाता है)। आवश्यकता होने पर `LSetAppPriority` (`Req_Func 69`) के माध्यम से अपना module name insert करें।
- File का **पहले से मौजूद होना आवश्यक है**, क्योंकि `OPEN_EXISTING` का उपयोग किया जाता है। `NETWORK SERVICE` द्वारा writable common candidates: `C:\Windows\System32\catroot2\dberr.txt`, `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\MpCmdRun.log`, `...\MpSigStub.log`।<sup>[[1]](#references)</sup>

## DWORD Write से TapiSrv के अंदर RCE तक
1. **अपने लिए Telephony “admin” privilege grant करें**: `C:\Windows\TAPI\tsec.ini` को target करें और ऊपर दिए गए 4-byte writes का उपयोग करके `[TapiAdministrators]\r\n<DOMAIN\\user>=1` append करें। एक **नई** session (`ClientAttach`) शुरू करें, ताकि service INI को फिर से read करे और आपके account के लिए `ptClient->dwFlags |= 9` set करे।
2. **Admin-only DLL load**: `dwObjectType = TUISPIDLL_OBJECT_PROVIDERID` के साथ `GetUIDllName` भेजें और `dwProviderFilenameOffset` के माध्यम से एक path दें। Admins के लिए service `LoadLibrary(path)` करती है और फिर export `TSPI_providerUIIdentify` को call करती है:
- वास्तविक Windows SMB share के UNC paths के साथ काम करता है; कुछ attacker SMB servers `ERROR_SMB_GUEST_LOGON_BLOCKED` के कारण fail हो जाते हैं।
- Alternative: इसी 4-byte write primitive का उपयोग करके local DLL को धीरे-धीरे drop करें, फिर उसे load करें।
3. **Payload**: export `NETWORK SERVICE` के अंतर्गत execute होता है। एक minimal DLL `cmd.exe /c whoami /all > C:\Windows\Temp\poc.txt` चला सकती है और non-zero value (जैसे `0x1337`) return कर सकती है, जिससे service DLL को unload कर देती है और execution confirm हो जाता है।<sup>[[1]](#references)</sup>

## Hardening / Detection Notes
- CVE-2026-20931 के लिए Microsoft security update install करें। इसके अतिरिक्त, जब तक आवश्यक न हो TAPI server mode disable करें और `\pipe\tapsrv` तक remote access block करें।
- Client द्वारा दिए गए paths को खोलने से पहले mailslot namespace validation (`\\*\MAILSLOT\`) लागू करें।
- `C:\Windows\TAPI\tsec.ini` ACLs को lock down करें और changes monitor करें; non-default paths load करने वाली `GetUIDllName` calls पर alert करें।<sup>[[1]](#references)</sup>

## References

- [1] [लाइन पर कौन है? Windows Telephony Service में RCE का Exploitation (CVE-2026-20931)](https://swarm.ptsecurity.com/whos-on-the-line-exploiting-rce-in-windows-telephony-service/)
- [2] [Microsoft Security Response Center — CVE-2026-20931](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-20931)
{{#include ../../banners/hacktricks-training.md}}
