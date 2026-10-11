# Access Tokens

{{#include ../../banners/hacktricks-training.md}}

## Access Tokens

हर process के पास एक **primary access token** होता है, जो उसका security context तय करता है। आम तौर पर thread उसी token का उपयोग करता है, लेकिन उसके पास अस्थायी रूप से **impersonation token** भी हो सकता है। Tokens में user SID, group SIDs, privileges, integrity information और logon session के लिए logon SID शामिल होते हैं। Processes आम तौर पर parent के primary token का reference inherit करते हैं; उन्हें उसके contents की स्वतंत्र copy नहीं मिलती।<sup>[[4]](#references)</sup>

आप यह जानकारी `whoami /all` चलाकर देख सकते हैं।

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

or Sysinternals के _Process Explorer_ का उपयोग करके (process चुनें और "Security" tab खोलें):

![Access Tokens - Access Tokens: or using Process Explorer from Sysinternals (select process and access"Security" tab)](<../../images/image (772).png>)

### Local administrator

जब किसी administrator पर **UAC Admin Approval Mode** लागू होता है, तो interactive logon एक full administrator token और एक filtered token बनाता है। Explorer और सामान्य child processes डिफ़ॉल्ट रूप से filtered token का उपयोग करते हैं। **Run as administrator** जैसे elevation request, UAC से प्रोग्राम को full token के साथ शुरू करने के लिए कहता है। सटीक व्यवहार built-in Administrator account और Admin Approval Mode के disabled होने पर अलग होता है।<sup>[[5]](#references)</sup>

Bypass techniques और policy details के लिए समर्पित [**UAC पेज**](../authentication-credentials-uac-and-efs/uac-user-account-control.md) पढ़ें।

व्यवहार में, इसका अर्थ है कि **non-elevated admin shell आमतौर पर filtered token के साथ चलता है**। इसी वजह से, process के elevated होने तक `whoami /groups` में अक्सर **`BUILTIN\Administrators` को `Deny only` के रूप में दिखाया जाता है**। आंतरिक रूप से, Windows एक **linked elevated token** (`TokenLinkedToken`) रखता है और `TokenElevationType` जैसे fields से स्थिति को track करता है।

### Credentials के साथ user impersonation

अगर आपके पास **किसी भी अन्य user के valid credentials** हैं, तो आप उन credentials के साथ एक **नया logon session बना** सकते हैं :

```
runas /user:domain\username cmd.exe
```

**access token** में **LSASS** के अंदर मौजूद logon sessions का एक **reference** भी होता है। यह तब उपयोगी होता है जब process को network के कुछ objects तक पहुंचने की आवश्यकता हो।\
आप इसका उपयोग करके ऐसा process launch कर सकते हैं जो **network services तक पहुंचने के लिए अलग-अलग credentials का उपयोग करता है**:

```
runas /user:domain\username /netonly cmd.exe
```

यदि आपके पास नेटवर्क में objects तक पहुँचने के लिए उपयोगी credentials हैं, लेकिन वे credentials मौजूदा host पर मान्य नहीं हैं, तो यह उपयोगी है; उनका उपयोग केवल नेटवर्क में किया जाएगा (मौजूदा host पर आपके वर्तमान user privileges का उपयोग होगा)।

#### `runas /netonly` का विवरण

`runas /netonly` (और `make_token` जैसे C2 helpers) **`LOGON32_LOGON_NEW_CREDENTIALS`** token बनाते हैं। lateral movement के दौरान इसे समझना बहुत उपयोगी है:<sup>[[3]](#references)</sup>

- **स्थानीय रूप से**, नया process वही **स्थानीय identity**, groups, integrity level और मौजूदा token जैसे अधिकतर access decisions रखता है।
- **दूरस्थ रूप से**, outbound authentication में SMB / WinRM / LDAP / HTTP / Kerberos / NTLM के लिए **दिए गए credentials** का उपयोग किया जा सकता है।
- इसलिए, नेटवर्क access **वैकल्पिक account** के रूप में होने पर भी `whoami` **मूल स्थानीय user** दिखा सकता है।

यह तब एक बेहतरीन विकल्प है, जब credentials domain या किसी दूसरे host पर मान्य हों, लेकिन user मौजूदा machine पर **स्थानीय रूप से log on नहीं कर सकता या उसे ऐसा नहीं करना चाहिए**।

### Tokens के प्रकार

दो प्रकार के tokens उपलब्ध हैं:<sup>[[4]](#references)[[6]](#references)</sup>

- **Primary token**: किसी process का security context दर्शाता है। सामान्यतः child process को अपने parent का primary token विरासत में मिलता है, जबकि explicit-token process-creation APIs की अपनी token-access और caller-privilege आवश्यकताएँ होती हैं।
- **Impersonation token**: किसी server thread को access checks के लिए अस्थायी रूप से client का security context उपयोग करने देता है। इसके चार levels हैं:
  - **Anonymous**: server को किसी अज्ञात user के समान access देता है।
  - **Identification**: server को object access के लिए client की identity का उपयोग किए बिना उसे verify करने देता है।
  - **Impersonation**: server को client की identity के अंतर्गत काम करने देता है।
  - **Delegation**: authentication mechanism और account configuration द्वारा delegation समर्थित होने पर server को remote systems पर client का impersonation करने देता है।

#### इस्तेमाल करने से पहले captured token की जाँच करें

किसी token का चयन केवल username के आधार पर न करें। एक ही account के कई tokens हो सकते हैं, जिनके logon sessions, service SIDs, privileges, integrity levels, restrictions और network credentials अलग-अलग हों।<sup>[[9]](#references)</sup> `GetTokenInformation` का उपयोग करके कम-से-कम **`TokenType`**, **`TokenImpersonationLevel`**, **`TokenElevationType`**, **`TokenLinkedToken`**, **`TokenIntegrityLevel`**, **`TokenSessionId`**, **`TokenIsRestricted`** / **`TokenHasRestrictions`**, और **`TokenStatistics.AuthenticationId`** की जाँच करें।<sup>[[7]](#references)</sup>

एक restricted token में deny-only SIDs, हटाए गए privileges और restricting SIDs हो सकते हैं। जब restricting SIDs मौजूद हों, तो Windows enabled SIDs के साथ एक access check और restricting SIDs के साथ दूसरा access check करता है; **दोनों checks में access की अनुमति मिलनी चाहिए**। इसलिए, output में आकर्षक user SID या enabled group होना अपने-आप यह साबित नहीं करता कि token target object तक पहुँच सकता है।<sup>[[8]](#references)</sup>

दस्तावेज़ में बताई गई token और process-creation आवश्यकताओं के लिए यह decision flow अपनाएँ:<sup>[[6]](#references)[[9]](#references)[[10]](#references)</sup>

1. `CreateProcessWithTokenW` या `CreateProcessAsUserW` को देने से पहले **primary token** के handle में `TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY` होना आवश्यक है।
2. **Impersonation token** को `DuplicateTokenEx(..., SecurityImpersonation, TokenPrimary, ...)` से convert करें। Identification-level tokens identity data दिखा सकते हैं, लेकिन उस client के रूप में access checks नहीं कर सकते।
3. `CreateProcessWithTokenW` को `SeImpersonatePrivilege` चाहिए और यह child को caller के session में शुरू करता है। इसके बजाय `CreateProcessAsUserW` token के session का उपयोग करता है, लेकिन सामान्यतः इसे `SeIncreaseQuotaPrivilege` की और कभी-कभी `SeAssignPrimaryTokenPrivilege` की आवश्यकता हो सकती है। यदि credentials उपलब्ध हों और ये privileges न हों, तो दस्तावेज़ में दिया गया विकल्प `CreateProcessWithLogonW` है।

#### केवल process owners नहीं, token handles भी खोजें

हर process का primary token खोलने से services और broker processes के अंदर **सामान्य handles के रूप में रखे गए impersonation tokens** छूट सकते हैं। Handle-table workflow को फिर से इस्तेमाल करने का एक तरीका है: system handles enumerate करें, token objects को filter करें, हर owner को `PROCESS_DUP_HANDLE` के साथ खोलें, candidate handle को मौजूदा process में duplicate करें, फिर ऊपर दिए गए fields की जाँच करें। पुष्टि करें कि duplicated handle में `TOKEN_QUERY` और `TOKEN_DUPLICATE` शामिल हों; token handle दिखने का अर्थ यह नहीं कि उसे उपयोगी primary token में duplicate किया जा सकता है। Protected processes और process DACLs अब भी owner-process handle को रोक सकते हैं।<sup>[[11]](#references)[[12]](#references)</sup>

`SharpToken` process-primary-token और retained-token-handle enumeration, दोनों को automate करता है। `list_token` हर username के लिए एक पसंदीदा candidate रखता है, जबकि `list_all_token` हर candidate दिखाता है। PID देने पर enumeration एक owner process तक सीमित हो जाता है।<sup>[[12]](#references)</sup>

```cmd
SharpToken.exe list_token
SharpToken.exe list_all_token
SharpToken.exe list_all_token 1234
SharpToken.exe execute "DOMAIN\User" "cmd /c whoami /all"
```

मैन्युअल निरीक्षण और access की जाँच के लिए, **TokenUniverse** process/thread tokens खोल सकता है, मौजूदा token handles खोज सकता है, restrictions और logon sessions का निरीक्षण कर सकता है, tokens duplicate कर सकता है और process बनाने के कई तरीकों को आज़मा सकता है।<sup>[[13]](#references)</sup> underlying cross-process handle primitive के लिए देखें:

{{#ref}}
leaked-handle-exploitation.md
{{#endref}}

#### Tokens का Impersonation

यदि आपके पास पर्याप्त privileges हैं, तो metasploit के _**incognito**_ module का इस्तेमाल करके आप आसानी से दूसरे **tokens** को **list** और **impersonate** कर सकते हैं। इससे आप **ऐसे actions कर सकते हैं जैसे आप वह दूसरा user हों**। इस technique से आप **privileges escalate** भी कर सकते हैं।

काम करते समय आसानी से भूल जाने वाली कुछ व्यावहारिक बातें:<sup>[[1]](#references)</sup>

- **`CreateProcessWithTokenW`** के लिए caller के पास **`SeImpersonatePrivilege`** होना ज़रूरी है और नया process **caller के session** में चलेगा।
- `CreateProcessWithTokenW` के `1314` के साथ fail होने पर **`CreateProcessAsUserW`** एक संभावित fallback है, लेकिन तभी जब caller इसकी privilege requirements पूरी करता हो। जब child को **token में निर्दिष्ट session** में चलना हो, तब भी यही सही विकल्प है।<sup>[[9]](#references)[[10]](#references)</sup>
- यदि token **`LogonUser(LOGON32_LOGON_NETWORK)`** से आया है, तो वह आमतौर पर एक **impersonation token** होता है। इसलिए इससे process शुरू करने की कोशिश करने से पहले आपको **`DuplicateTokenEx(..., TokenPrimary, ...)`** करना होगा।
- हर impersonation token समान रूप से उपयोगी नहीं होता: **`SecurityIdentification`** आपको user का निरीक्षण करने देता है, लेकिन **उसके रूप में कार्य करने नहीं देता**। यदि कोई coercion primitive या pipe/RPC client आपको केवल identification-level token देता है, तो **`TokenImpersonationLevel`** जाँचें और ऐसे primitive का इस्तेमाल करें जो **`SecurityImpersonation`** या उससे बेहतर स्तर का token देता हो।

#### LSASS को छुए बिना Token theft

यदि आपके पास पहले से **service** या **SYSTEM** context है और कोई **privileged user लॉग इन है**, तो उस user का token चुराना या duplicate करना अक्सर **LSASS** dump करने से ज़्यादा शांत तरीका होता है। कई वास्तविक intrusions में इससे इतना करना संभव होता है:<sup>[[2]](#references)</sup>

- उस user के रूप में स्थानीय actions करना
- उस user के रूप में remote resources तक पहुँचना
- पहले reusable credentials निकाले बिना AD operations करना

Privileged context से **session/user token hijacking** के उदाहरणों के लिए [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md) देखें। ध्यान रखें कि **`WTSQueryUserToken`** जैसी APIs **अत्यधिक trusted services** के लिए हैं और इनके लिए आमतौर पर **`LocalSystem` + `SeTcbPrivilege`** की ज़रूरत होती है। इसलिए ये मुख्यतः तभी उपयोगी हैं जब आपके पास पहले से service-level context का control हो। पहले **SYSTEM** पाने के privilege-विशिष्ट तरीकों के लिए नीचे दिए गए पेज देखें।

### Token Privileges

जानें कि **privileges escalate करने के लिए किन token privileges का दुरुपयोग किया जा सकता है:**

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

[**सभी संभावित token privileges और कुछ परिभाषाएँ इस बाहरी पेज पर देखें**](https://github.com/gtworek/Priv2Admin).

## References

- [1] [Access Tokens को समझना और उनका दुरुपयोग करना — भाग II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [2] [LSASS को छुए बिना Active Directory को compromise करने के लिए Windows tokens का दुरुपयोग](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
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
