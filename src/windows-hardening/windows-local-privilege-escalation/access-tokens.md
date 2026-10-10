# Access Tokens

{{#include ../../banners/hacktricks-training.md}}

## Access Tokens

हर process के पास एक **primary access token** होता है, जो उसका security context निर्धारित करता है। आम तौर पर thread उसी token का उपयोग करता है, लेकिन उसके पास अस्थायी रूप से **impersonation token** भी हो सकता है। Tokens में user SID, group SIDs, privileges, integrity information और logon session के लिए logon SID शामिल होते हैं। आम तौर पर processes को parent के primary token का reference विरासत में मिलता है; उन्हें उसके contents की स्वतंत्र copy नहीं मिलती।<sup>[[4]](#references)</sup>

आप `whoami /all` चलाकर यह जानकारी देख सकते हैं.

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

या Sysinternals के _Process Explorer_ का उपयोग करके (प्रोसेस चुनें और "Security" टैब खोलें):

![Access Tokens - Access Tokens: या Sysinternals के Process Explorer का उपयोग करके (प्रोसेस चुनें और "Security" टैब खोलें)](<../../images/image (772).png>)

### स्थानीय एडमिनिस्ट्रेटर

जब किसी एडमिनिस्ट्रेटर पर **UAC Admin Approval Mode** लागू होता है, तो इंटरैक्टिव लॉगऑन एक पूर्ण एडमिनिस्ट्रेटर टोकन और एक फ़िल्टर किया गया टोकन बनाता है। Explorer और सामान्य चाइल्ड प्रोसेस डिफ़ॉल्ट रूप से फ़िल्टर किए गए टोकन का उपयोग करते हैं। **Run as administrator** जैसे elevation अनुरोध पर UAC प्रोग्राम को पूर्ण टोकन के साथ शुरू करता है। सटीक व्यवहार अंतर्निहित Administrator खाते और Admin Approval Mode अक्षम होने पर अलग होता है।<sup>[[5]](#references)</sup>

बायपास तकनीकों और पॉलिसी के विवरण के लिए समर्पित [**UAC पेज**](../authentication-credentials-uac-and-efs/uac-user-account-control.md) पढ़ें।

व्यवहार में, इसका अर्थ है कि **non-elevated admin shell आमतौर पर फ़िल्टर किए गए टोकन के साथ चलता है**। इसीलिए `whoami /groups` अक्सर दिखाता है कि प्रोसेस के elevated होने तक **`BUILTIN\Administrators` `Deny only` के रूप में सूचीबद्ध है**। आंतरिक रूप से, Windows एक **linked elevated token** (`TokenLinkedToken`) रखता है और `TokenElevationType` जैसे फ़ील्ड से स्थिति को ट्रैक करता है।

### क्रेडेंशियल के ज़रिए यूज़र इम्पर्सनेशन

अगर आपके पास **किसी अन्य यूज़र के मान्य क्रेडेंशियल** हैं, तो आप उन क्रेडेंशियल के साथ एक **नया लॉगऑन सेशन बना** सकते हैं:

```
runas /user:domain\username cmd.exe
```

**access token** में **LSASS** के अंदर मौजूद logon sessions का एक **reference** भी होता है। यह तब उपयोगी होता है जब process को network के कुछ objects तक access करना हो।\
आप ऐसा process launch कर सकते हैं जो **network services को access करने के लिए अलग credentials का उपयोग करता है**:

```
runas /user:domain\username /netonly cmd.exe
```

यह तब उपयोगी है जब आपके पास नेटवर्क में ऑब्जेक्ट्स तक पहुँचने के लिए उपयोगी credentials हों, लेकिन वे credentials मौजूदा host पर मान्य न हों, क्योंकि उनका उपयोग केवल नेटवर्क में किया जाएगा (मौजूदा host पर आपके वर्तमान user privileges का उपयोग होगा)।

#### `runas /netonly` का विवरण

`runas /netonly` (और `make_token` जैसे C2 helpers) **`LOGON32_LOGON_NEW_CREDENTIALS`** token बनाते हैं। Lateral movement के दौरान इसे समझना बहुत उपयोगी है, क्योंकि:<sup>[[3]](#references)</sup>

- **स्थानीय रूप से**, नई process में **वही स्थानीय identity**, groups, integrity level और वर्तमान token जैसे अधिकांश access decisions बने रहते हैं।
- **दूरस्थ रूप से**, outbound authentication में SMB / WinRM / LDAP / HTTP / Kerberos / NTLM के लिए **दिए गए credentials** का उपयोग हो सकता है।
- इसलिए, नेटवर्क access **वैकल्पिक account** के रूप में होने पर भी `whoami` में **मूल स्थानीय user** दिख सकता है।

यह तब एक बढ़िया विकल्प है जब credentials domain या किसी अन्य host पर मान्य हों, लेकिन user मौजूदा machine पर **स्थानीय रूप से log on नहीं कर सकता या उसे ऐसा नहीं करना चाहिए**।

### Tokens के प्रकार

दो प्रकार के tokens उपलब्ध हैं:<sup>[[4]](#references)[[6]](#references)</sup>

- **Primary token**: किसी process security context को दर्शाता है। सामान्यतः child अपने parent का primary token inherit करता है, जबकि explicit-token process-creation APIs की अपनी token-access और caller-privilege आवश्यकताएँ होती हैं।
- **Impersonation token**: किसी server thread को access checks के लिए अस्थायी रूप से client का security context उपयोग करने देता है। इसके चार levels हैं:
  - **Anonymous**: Server को ऐसा access देता है जो किसी अज्ञात user के access जैसा होता है।
  - **Identification**: Server को client की identity verify करने देता है, लेकिन object access के लिए उसका उपयोग नहीं करने देता।
  - **Impersonation**: Server को client की identity के तहत कार्य करने देता है।
  - **Delegation**: Authentication mechanism और account configuration में delegation समर्थित होने पर server को दूरस्थ systems पर client का impersonate करने देता है।

#### उपयोग करने से पहले captured token की जाँच करें

केवल username के आधार पर token न चुनें। एक ही account के कई tokens हो सकते हैं, जिनके logon sessions, service SIDs, privileges, integrity levels, restrictions और network credentials अलग-अलग हों।<sup>[[9]](#references)</sup> `GetTokenInformation` से कम-से-कम **`TokenType`**, **`TokenImpersonationLevel`**, **`TokenElevationType`**, **`TokenLinkedToken`**, **`TokenIntegrityLevel`**, **`TokenSessionId`**, **`TokenIsRestricted`** / **`TokenHasRestrictions`**, और **`TokenStatistics.AuthenticationId`** की जाँच करें।<sup>[[7]](#references)</sup>

Restricted token में deny-only SIDs, हटाए गए privileges और restricting SIDs हो सकते हैं। जब restricting SIDs मौजूद हों, तो Windows enabled SIDs के साथ एक access check और restricting SIDs के साथ दूसरा access check करता है; **दोनों checks को access की अनुमति देनी होगी**। इसलिए, output में किसी आकर्षक user SID या enabled group का होना अपने आप यह साबित नहीं करता कि token target object तक पहुँच सकता है।<sup>[[8]](#references)</sup>

दस्तावेज़ीकृत token और process-creation आवश्यकताओं के लिए यह decision flow अपनाएँ:<sup>[[6]](#references)[[9]](#references)[[10]](#references)</sup>

1. `CreateProcessWithTokenW` या `CreateProcessAsUserW` को देने से पहले **primary token** के handle में `TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY` होना चाहिए।
2. `DuplicateTokenEx(..., SecurityImpersonation, TokenPrimary, ...)` से **impersonation token** को convert करें। Identification-level tokens identity data दिखा सकते हैं, लेकिन उस client के रूप में access checks नहीं कर सकते।
3. `CreateProcessWithTokenW` के लिए `SeImpersonatePrivilege` आवश्यक है और यह child को caller के session में शुरू करता है। इसके बजाय `CreateProcessAsUserW` token के session का उपयोग करता है, लेकिन इसके लिए सामान्यतः `SeIncreaseQuotaPrivilege` आवश्यक है और `SeAssignPrimaryTokenPrivilege` भी आवश्यक हो सकता है। यदि credentials उपलब्ध हैं और ये privileges नहीं हैं, तो दस्तावेज़ीकृत विकल्प `CreateProcessWithLogonW` है।

#### केवल process owners नहीं, token handles भी खोजें

हर process का primary token खोलने से services और broker processes के भीतर सामान्य handles के रूप में रखे गए **impersonation tokens छूट सकते हैं**। Reusable handle-table workflow में system handles enumerate करें, token objects को filter करें, हर owner को `PROCESS_DUP_HANDLE` के साथ खोलें, candidate handle को मौजूदा process में duplicate करें, फिर ऊपर दिए गए fields की जाँच करें। पुष्टि करें कि duplicated handle में `TOKEN_QUERY` और `TOKEN_DUPLICATE` शामिल हैं; token handle दिखने का मतलब यह नहीं कि उसे किसी उपयोगी primary token में duplicate किया जा सकता है। Protected processes और process DACLs अब भी owner-process handle को block कर सकते हैं।<sup>[[11]](#references)[[12]](#references)</sup>

`SharpToken` process-primary-token और retained-token-handle, दोनों की enumeration को automate करता है। `list_token` हर username के लिए एक पसंदीदा candidate रखता है, जबकि `list_all_token` हर candidate दिखाता है। PID देने से enumeration एक owner process तक सीमित हो जाती है।<sup>[[12]](#references)</sup>

```cmd
SharpToken.exe list_token
SharpToken.exe list_all_token
SharpToken.exe list_all_token 1234
SharpToken.exe execute "DOMAIN\User" "cmd /c whoami /all"
```

मैन्युअल निरीक्षण और access जाँच के लिए, **TokenUniverse** process/thread tokens खोल सकता है, मौजूदा token handles खोज सकता है, restrictions और logon sessions का निरीक्षण कर सकता है, tokens duplicate कर सकता है, और process बनाने के कई तरीकों को test कर सकता है।<sup>[[13]](#references)</sup> अंतर्निहित cross-process handle primitive के लिए देखें:

{{#ref}}
leaked-handle-exploitation.md
{{#endref}}

#### Impersonate Tokens

यदि आपके पास पर्याप्त privileges हैं, तो metasploit के _**incognito**_ module का उपयोग करके आप आसानी से दूसरे **tokens** को **list** और **impersonate** कर सकते हैं। यह **दूसरे user की तरह actions करने** के लिए उपयोगी हो सकता है। इस technique से आप **privileges escalate** भी कर सकते हैं।

काम करते समय आसानी से भूल जाने वाली कुछ व्यावहारिक बातें:<sup>[[1]](#references)</sup>

- **`CreateProcessWithTokenW`** के लिए caller में **`SeImpersonatePrivilege`** होना आवश्यक है और नया process **caller के session** में चलेगा।
- **`CreateProcessAsUserW`** एक संभावित fallback है, जब `CreateProcessWithTokenW` `1314` error के साथ fail हो—लेकिन तभी, जब caller इसकी privilege requirements पूरी करता हो। जब child को **token में संदर्भित session** में चलाना हो, तब भी यही सही विकल्प है।<sup>[[9]](#references)[[10]](#references)</sup>
- अगर token **`LogonUser(LOGON32_LOGON_NETWORK)`** से मिला है, तो वह आमतौर पर **impersonation token** होता है। इसलिए उससे process शुरू करने की कोशिश से पहले आपको **`DuplicateTokenEx(..., TokenPrimary, ...)`** करना होगा।
- सभी impersonation tokens एक जैसे उपयोगी नहीं होते: **`SecurityIdentification`** से आप user का निरीक्षण कर सकते हैं, लेकिन **उसकी तरह कार्य नहीं कर सकते**। अगर किसी coercion primitive या pipe/RPC client से आपको केवल identification-level token मिलता है, तो **`TokenImpersonationLevel`** जाँचें और ऐसे primitive का उपयोग करें जो **`SecurityImpersonation`** या उससे बेहतर स्तर का token देता हो।

#### LSASS को छुए बिना token चोरी

अगर आपके पास पहले से **service** या **SYSTEM** context है और कोई **privileged user logged on** है, तो उस user का token चुराना या duplicate करना अक्सर **LSASS** dump करने से अधिक शांत तरीका होता है। कई वास्तविक intrusions में इतना करना ही पर्याप्त होता है:<sup>[[2]](#references)</sup>

- उस user के रूप में local actions करना
- उस user के रूप में remote resources तक पहुँचना
- पहले reusable credentials निकाले बिना AD operations करना

Privileged context से **session/user token hijacking** के उदाहरणों के लिए [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md) देखें। ध्यान रखें कि **`WTSQueryUserToken`** जैसी APIs **अत्यधिक trusted services** के लिए होती हैं और इनके लिए आमतौर पर **`LocalSystem` + `SeTcbPrivilege`** आवश्यक हैं। इसलिए ये मुख्य रूप से तब उपयोगी होती हैं, जब आप पहले से service-level context पर नियंत्रण रखते हों। पहले **SYSTEM** प्राप्त करने के privilege-विशिष्ट तरीकों के लिए नीचे दिए गए pages देखें।

### Token Privileges

जानें कि **privileges escalate करने के लिए किन token privileges का दुरुपयोग किया जा सकता है:**

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

[**सभी संभावित token privileges और उनकी कुछ परिभाषाओं के लिए यह बाहरी page देखें**](https://github.com/gtworek/Priv2Admin).

## References

- [1] [Access Tokens को समझना और उनका दुरुपयोग करना — भाग II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [2] [LSASS को छुए बिना Active Directory compromise करने के लिए Windows tokens का दुरुपयोग](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Cobalt Strike के "make_token" Command का रहस्य स्पष्ट करना](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)
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
{{#include ../../banners/hacktricks-training.md}}
