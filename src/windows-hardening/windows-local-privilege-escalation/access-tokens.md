# Access Tokens

{{#include ../../banners/hacktricks-training.md}}

## Access Tokens

हर process के पास एक **primary access token** होता है, जो उसका security context तय करता है। आमतौर पर thread इसी token का उपयोग करता है, लेकिन उसके पास अस्थायी रूप से **impersonation token** भी हो सकता है। Tokens में user SID, group SIDs, privileges, integrity information और logon session के लिए एक logon SID शामिल होते हैं। आमतौर पर processes को parent के primary token का reference विरासत में मिलता है; उन्हें token की सामग्री की स्वतंत्र copy नहीं मिलती।<sup>[[4]](#references)</sup>

आप `whoami /all` चलाकर यह जानकारी देख सकते हैं।

```
whoami /all

USER INFORMATION
----------------

User Name             SID
===================== ============================================
desktop-rgfrdxl\cpolo S-1-5-21-3359511372-53430657-2078432294-1001


GROUP INFORMATION
-----------------

Group Name                                                    Type             SID                                                                                                           Attributes
============================================================= ================ ============================================================================================================= ==================================================
Mandatory Label\Medium Mandatory Level                        Label            S-1-16-8192
Everyone                                                      Well-known group S-1-1-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114                                                                                                     Group used for deny only
BUILTIN\Administrators                                        Alias            S-1-5-32-544                                                                                                  Group used for deny only
BUILTIN\Users                                                 Alias            S-1-5-32-545                                                                                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Performance Log Users                                 Alias            S-1-5-32-559                                                                                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                                      Well-known group S-1-5-4                                                                                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                                                 Well-known group S-1-2-1                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11                                                                                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                                Well-known group S-1-5-15                                                                                                      Mandatory group, Enabled by default, Enabled group
MicrosoftAccount\cpolop@outlook.com                           User             S-1-11-96-3623454863-58364-18864-2661722203-1597581903-3158937479-2778085403-3651782251-2842230462-2314292098 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                    Well-known group S-1-5-113                                                                                                     Mandatory group, Enabled by default, Enabled group
LOCAL                                                         Well-known group S-1-2-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Cloud Account Authentication                     Well-known group S-1-5-64-36                                                                                                   Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```

या Sysinternals के _Process Explorer_ का उपयोग करके (process चुनें और "Security" tab खोलें):

![Access Tokens - Access Tokens: या Sysinternals के Process Explorer का उपयोग करके (process चुनें और "Security" tab खोलें)](<../../images/image (772).png>)

### स्थानीय administrator

जब किसी administrator पर **UAC Admin Approval Mode** लागू होता है, तो interactive logon एक full administrator token और एक filtered token बनाता है। Explorer और सामान्य child processes, डिफ़ॉल्ट रूप से filtered token का उपयोग करते हैं। **Run as administrator** जैसी elevation request, UAC से प्रोग्राम को full token के साथ शुरू करने के लिए कहती है। सटीक व्यवहार, built-in Administrator account और Admin Approval Mode के disabled होने पर अलग होता है।<sup>[[5]](#references)</sup>

bypass techniques और policy details के लिए समर्पित [**UAC page**](../authentication-credentials-uac-and-efs/uac-user-account-control.md) पढ़ें।

व्यवहार में, इसका अर्थ है कि **non-elevated admin shell आमतौर पर filtered token के साथ चलता है**। इसी कारण, process के elevated होने तक `whoami /groups` में अक्सर **`BUILTIN\Administrators` को `Deny only` के रूप में दिखाया जाता है**। आंतरिक रूप से, Windows एक **linked elevated token** (`TokenLinkedToken`) रखता है और `TokenElevationType` जैसे fields से स्थिति को track करता है।

### Credentials के साथ user impersonation

अगर आपके पास किसी भी दूसरे user के **valid credentials** हैं, तो आप उन credentials से एक **नया logon session बना** सकते हैं:

```
runas /user:domain\username cmd.exe
```

**access token** में **LSASS** के अंदर मौजूद logon sessions का एक **reference** भी होता है। यह तब उपयोगी होता है जब process को network के कुछ objects तक पहुँचने की ज़रूरत हो।\
आप ऐसा process launch कर सकते हैं जो network services तक पहुँचने के लिए **अलग credentials का उपयोग करता है**:

```
runas /user:domain\username /netonly cmd.exe
```

यह तब उपयोगी है जब आपके पास नेटवर्क में objects तक पहुँचने के लिए उपयोगी credentials हों, लेकिन वे credentials मौजूदा host पर मान्य न हों, क्योंकि उनका उपयोग केवल नेटवर्क में किया जाना है (मौजूदा host पर आपके वर्तमान user privileges का उपयोग होगा)।

#### `runas /netonly` का विवरण

`runas /netonly` (और `make_token` जैसे C2 helpers) एक **`LOGON32_LOGON_NEW_CREDENTIALS`** token बनाता है। Lateral movement के दौरान इसे समझना बहुत उपयोगी है, क्योंकि:<sup>[[3]](#references)</sup>

- **स्थानीय रूप से**, नई process वही **स्थानीय पहचान**, groups, integrity level और मौजूदा token जैसे अधिकांश access decisions बनाए रखती है।
- **दूरस्थ रूप से**, outbound authentication, SMB / WinRM / LDAP / HTTP / Kerberos / NTLM के लिए **दिए गए credentials** का उपयोग कर सकता है।
- इसलिए, नेटवर्क access **वैकल्पिक account** के रूप में होने पर भी `whoami` में **मूल स्थानीय user** दिख सकता है।

यह तब एक बेहतरीन विकल्प है जब credentials domain या किसी अन्य host में मान्य हों, लेकिन user मौजूदा machine पर **स्थानीय रूप से log on नहीं कर सकता या उसे ऐसा नहीं करना चाहिए**।

### Tokens के प्रकार

दो प्रकार के tokens उपलब्ध हैं:<sup>[[4]](#references)[[6]](#references)</sup>

- **Primary token**: किसी process के security context को दर्शाता है। सामान्यतः child अपने parent का primary token inherit करता है, जबकि explicit-token process-creation APIs अपनी token-access और caller-privilege आवश्यकताएँ लागू करती हैं।
- **Impersonation token**: किसी server thread को access checks के लिए अस्थायी रूप से client का security context उपयोग करने देता है। इसके चार levels हैं:
  - **Anonymous**: Server को ऐसा access देता है जो किसी अज्ञात user के access जैसा होता है।
  - **Identification**: Server को client की पहचान सत्यापित करने देता है, लेकिन object access के लिए उसका उपयोग नहीं करने देता।
  - **Impersonation**: Server को client की पहचान के अंतर्गत काम करने देता है।
  - **Delegation**: Authentication mechanism और account configuration में delegation समर्थित होने पर server को remote systems पर client का impersonation करने देता है।

#### उपयोग करने से पहले captured token की जाँच करें

केवल username के आधार पर token न चुनें। एक ही account के कई tokens हो सकते हैं, जिनमें logon sessions, service SIDs, privileges, integrity levels, restrictions और network credentials अलग-अलग हों।<sup>[[9]](#references)</sup> `GetTokenInformation` से कम-से-कम **`TokenType`**, **`TokenImpersonationLevel`**, **`TokenElevationType`**, **`TokenLinkedToken`**, **`TokenIntegrityLevel`**, **`TokenSessionId`**, **`TokenIsRestricted`** / **`TokenHasRestrictions`**, और **`TokenStatistics.AuthenticationId`** की जाँच करें।<sup>[[7]](#references)</sup>

Restricted token में deny-only SIDs, हटाए गए privileges और restricting SIDs हो सकते हैं। Restricting SIDs मौजूद होने पर, Windows enabled SIDs के साथ एक access check और restricting SIDs के साथ दूसरा access check करता है; **दोनों checks में access की अनुमति मिलनी चाहिए**। इसलिए, output में आकर्षक user SID या enabled group दिखना अपने-आप यह साबित नहीं करता कि token target object तक पहुँच सकता है।<sup>[[8]](#references)</sup>

दस्तावेज़ में बताई गई token और process-creation आवश्यकताओं के लिए यह decision flow अपनाएँ:<sup>[[6]](#references)[[9]](#references)[[10]](#references)</sup>

1. `CreateProcessWithTokenW` या `CreateProcessAsUserW` को देने से पहले **primary token** के handle में `TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY` होना आवश्यक है।
2. **Impersonation token** को `DuplicateTokenEx(..., SecurityImpersonation, TokenPrimary, ...)` से convert करें। Identification-level tokens पहचान संबंधी data दिखा सकते हैं, लेकिन उस client के रूप में access checks नहीं कर सकते।
3. `CreateProcessWithTokenW` के लिए `SeImpersonatePrivilege` आवश्यक है और यह child को caller के session में शुरू करता है। इसके बजाय, `CreateProcessAsUserW` token का session उपयोग करता है, लेकिन सामान्यतः इसके लिए `SeIncreaseQuotaPrivilege` आवश्यक है और `SeAssignPrimaryTokenPrivilege` की भी आवश्यकता हो सकती है। यदि credentials उपलब्ध हैं और ये privileges नहीं हैं, तो `CreateProcessWithLogonW` दस्तावेज़ में दिया गया विकल्प है।

#### केवल process owners नहीं, token handles भी खोजें

हर process का primary token खोलने से services और broker processes के अंदर साधारण handles के रूप में रखे गए **impersonation tokens छूट सकते हैं**। Handle-table की एक पुनः उपयोग योग्य workflow में system handles की enumeration करना, token objects को filter करना, `PROCESS_DUP_HANDLE` के साथ प्रत्येक owner को खोलना, candidate handle को मौजूदा process में duplicate करना और फिर ऊपर दिए गए fields की जाँच करना शामिल है। पुष्टि करें कि duplicated handle में `TOKEN_QUERY` और `TOKEN_DUPLICATE` शामिल हैं; token handle दिखने का अर्थ यह नहीं कि उसे उपयोगी primary token में duplicate किया जा सकता है। Protected processes और process DACLs अब भी owner-process handle को रोक सकते हैं।<sup>[[11]](#references)[[12]](#references)</sup>

`SharpToken` process-primary-token और retained-token-handle, दोनों की enumeration स्वचालित करता है। `list_token` प्रत्येक username के लिए एक पसंदीदा candidate रखता है, जबकि `list_all_token` हर candidate प्रिंट करता है। PID देने पर enumeration केवल एक owner process तक सीमित रहती है।<sup>[[12]](#references)</sup>

```cmd
SharpToken.exe list_token
SharpToken.exe list_all_token
SharpToken.exe list_all_token 1234
SharpToken.exe execute "DOMAIN\User" "cmd /c whoami /all"
```

मैन्युअल निरीक्षण और access जाँच के लिए, **TokenUniverse** process/thread tokens खोल सकता है, मौजूदा token handles खोज सकता है, restrictions और logon sessions का निरीक्षण कर सकता है, tokens duplicate कर सकता है और process बनाने के कई तरीकों का परीक्षण कर सकता है।<sup>[[13]](#references)</sup> अंतर्निहित cross-process handle primitive के लिए, देखें:

{{#ref}}
leaked-handle-exploitation.md
{{#endref}}

### Live thread impersonation tokens खोजें

किसी service thread द्वारा अस्थायी रूप से client का impersonation किया जा सकता है, भले ही उसका **process primary token** service account का हो। इसलिए process-owner scan में client context छूट सकता है।<sup>[[4]](#references)</sup> TokenUniverse सुलभ process/thread tokens की सूची दिखा सकता है; System Informer में candidate threads खोजने के लिए किसी process का **Threads** tab और उसका **Impersonation** column देखें।<sup>[[13]](#references)[[14]](#references)</sup>

किसी लक्षित API जाँच के लिए, `TH32CS_SNAPTHREAD` snapshot लें, `THREADENTRY32.th32OwnerProcessID` को service PID से filter करें, फिर हर सुलभ thread के लिए `OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid)` और `OpenThreadToken(thread, TOKEN_QUERY | TOKEN_DUPLICATE, TRUE, &token)` को call करें।<sup>[[15]](#references)[[16]](#references)</sup> `TRUE` से token-open access check में caller का **process** context इस्तेमाल होता है, जो तब महत्वपूर्ण है जब scanner खुद identification level पर impersonate कर रहा हो।<sup>[[17]](#references)</sup> ऊपर बताए गए duplication/process-creation flow को आज़माने से पहले token के user, type, impersonation level और logon ID की जानकारी लें।<sup>[[7]](#references)</sup> Enumeration और open के बीच कोई thread impersonation बंद कर सकता है; token न होना, anonymous tokens, protected threads, thread DACLs और token DACLs—ये सभी संग्रह को रोक सकते हैं।<sup>[[16]](#references)[[17]](#references)</sup> किसी service के पास मौजूद token handles को scan करने के बजाय, यह **वर्तमान में assigned thread token** की जाँच करता है।

मौजूदा threads को scan करने के बजाय, किसी privileged client से आपकी pipe पर connect करवाकर thread token प्राप्त करने वाले attack path के लिए, [named-pipe client impersonation](named-pipe-client-impersonation.md) देखें।

#### Tokens का Impersonate करना

यदि आपके पास पर्याप्त privileges हैं, तो metasploit के _**incognito**_ module का उपयोग करके आप आसानी से दूसरे **tokens** की **सूची** देख सकते हैं और उनका **impersonate** कर सकते हैं। यह **दूसरे user की तरह actions करने** में उपयोगी हो सकता है। इस technique से आप **privileges escalate** भी कर सकते हैं।

काम करते समय आसानी से भूल जाने वाली कुछ व्यावहारिक बातें:<sup>[[1]](#references)</sup>

- **`CreateProcessWithTokenW`** के लिए caller में **`SeImpersonatePrivilege`** होना आवश्यक है और नया process **caller के session** में चलेगा।
- **`CreateProcessWithTokenW`** के `1314` के साथ fail होने पर **`CreateProcessAsUserW`** एक संभावित fallback है, लेकिन तभी जब caller इसकी privilege requirements पूरी करता हो। जब child को **token में निर्दिष्ट session** में चलाना हो, तब भी यही सही विकल्प है।<sup>[[9]](#references)[[10]](#references)</sup>
- **`LogonUser(LOGON32_LOGON_NETWORK)`** एक **impersonation token** देता है। Process बनाने से पहले इसे **`DuplicateTokenEx(..., TokenPrimary, ...)`** से convert करें। Conversion के बाद भी, परिणामी process उस network logon का उपयोग करके authenticated remote shares या printers तक पहुँच नहीं सकता: इस logon type में credentials cache नहीं होते। यदि आपके पास credentials हैं और आगे network access चाहिए, तो interactive या network-cleartext logon का उपयोग करें; इसे `LOGON32_LOGON_NEW_CREDENTIALS` (`runas /netonly`) से भ्रमित न करें, जो outbound credentials देते हुए local identity बनाए रखता है।<sup>[[18]](#references)</sup>
- हर impersonation token समान रूप से उपयोगी नहीं होता: **`SecurityIdentification`** आपको user का निरीक्षण करने देता है, लेकिन **उसके रूप में कार्य करने** नहीं देता। यदि coercion primitive या pipe/RPC client आपको केवल identification-level token देता है, तो **`TokenImpersonationLevel`** जाँचें और ऐसे primitive पर जाएँ जो **`SecurityImpersonation`** या उससे बेहतर स्तर का token देता हो।

#### LSASS को छुए बिना token चोरी

यदि आपके पास पहले से **service** या **SYSTEM** context है और कोई **privileged user logged on है**, तो उस user का token चुराना या duplicate करना अक्सर **LSASS** dump करने से ज़्यादा शांत तरीका होता है। कई वास्तविक intrusions में इतना ही पर्याप्त होता है:<sup>[[2]](#references)</sup>

- उस user के रूप में local actions करना
- उस user के रूप में remote resources तक पहुँचना
- पहले reusable credentials निकाले बिना AD operations करना

Privileged context से **session/user token hijacking** के उदाहरणों के लिए [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md) देखें। याद रखें कि **`WTSQueryUserToken`** जैसी APIs **अत्यधिक trusted services** के लिए हैं और आमतौर पर **`LocalSystem` + `SeTcbPrivilege`** की आवश्यकता होती है। इसलिए ये मुख्य रूप से तब उपयोगी हैं जब आप पहले से service-level context नियंत्रित करते हों। पहले **SYSTEM** प्राप्त करने के privilege-विशिष्ट तरीकों के लिए नीचे दिए गए pages देखें।

### Token Privileges

जानें कि privileges escalate करने के लिए **किन token privileges का दुरुपयोग किया जा सकता है:**

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

[**सभी संभावित token privileges और उनकी कुछ परिभाषाओं के लिए यह बाहरी page देखें**](https://github.com/gtworek/Priv2Admin).



## References

- [1] [Access Tokens को समझना और उनका दुरुपयोग करना — भाग II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [2] [LSASS को छुए बिना Active Directory से समझौता करने के लिए Windows tokens का दुरुपयोग](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Cobalt Strike के "make_token" Command का रहस्य समझना](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)
- [4] [Access Tokens - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- [5] [User Account Control कैसे काम करता है - Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works)
- [6] [Impersonation Levels - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/impersonation-levels)
- [7] [TOKEN_INFORMATION_CLASS enumeration - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class)
- [8] [Restricted Tokens - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens)
- [9] [CreateProcessWithTokenW function - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [10] [CreateProcessAsUserW function - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
- [11] [DuplicateHandle function - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle)
- [12] [BeichenDream/SharpToken](https://github.com/BeichenDream/SharpToken)
- [13] [diversenok/TokenUniverse](https://github.com/diversenok/TokenUniverse)
- [14] [System Informer thread-token feature request](https://github.com/winsiderss/systeminformer/issues/1275)
- [15] [Thread list को traverse करना - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/toolhelp/traversing-the-thread-list)
- [16] [NtOpenThreadToken - Microsoft Learn](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntopenthreadtoken)
- [17] [OpenThreadToken - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthreadtoken)
- [18] [LogonUserA - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonusera)
{{#include ../../banners/hacktricks-training.md}}
