# Access Tokens

{{#include ../../banners/hacktricks-training.md}}

## Access Tokens

सिस्टम पर **लॉग इन किया हुआ प्रत्येक user, उस लॉगऑन session की security information वाला access token रखता है**। सिस्टम user के लॉग ऑन करने पर access token बनाता है। **User की ओर से execute की जाने वाली प्रत्येक process के पास access token की एक copy होती है**। यह token user, user के groups और user के privileges की पहचान करता है। Token में एक logon SID (Security Identifier) भी होता है, जो वर्तमान logon session की पहचान करता है।

आप यह information `whoami /all` execute करके देख सकते हैं
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
or Sysinternals से _Process Explorer_ का उपयोग करके (process चुनें और "Security" tab access करें):

![Access Tokens - Access Tokens: या Sysinternals से Process Explorer का उपयोग करके (process चुनें और "Security" tab access करें)](<../../images/image (772).png>)

### Local administrator

जब कोई local administrator login करता है, **दो access tokens बनाए जाते हैं**: एक admin rights वाला और दूसरा normal rights वाला। **By default**, जब यह user कोई process execute करता है, तो **regular** (non-administrator) **rights वाला token उपयोग किया जाता है**। जब यह user किसी चीज़ को **as administrator** execute करने का प्रयास करता है (उदाहरण के लिए, "Run as Administrator"), तो permission मांगने के लिए **UAC** का उपयोग किया जाता है।\
यदि आप [**UAC के बारे में अधिक जानना चाहते हैं, तो यह page पढ़ें**](../authentication-credentials-uac-and-efs/index.html#uac)**.**

व्यवहार में, इसका अर्थ है कि एक **non-elevated admin shell आमतौर पर filtered token के साथ चलता है**। इसी कारण `whoami /groups` अक्सर process के elevated होने तक **`BUILTIN\Administrators` को `Deny only` के रूप में दिखाता है**। आंतरिक रूप से, Windows एक **linked elevated token** (`TokenLinkedToken`) बनाए रखता है और `TokenElevationType` जैसे fields के साथ इसकी स्थिति track करता है।

### Credentials user impersonation

यदि आपके पास **किसी अन्य user के valid credentials** हैं, तो आप उन credentials के साथ एक **नया logon session create** कर सकते हैं:
```
runas /user:domain\username cmd.exe
```
**access token** में **LSASS** के अंदर मौजूद logon sessions का एक **reference** भी होता है, यह तब उपयोगी होता है जब process को network के कुछ objects तक access करना हो।\
आप एक ऐसा process launch कर सकते हैं जो **network services को access करने के लिए अलग credentials का उपयोग करता है**:
```
runas /user:domain\username /netonly cmd.exe
```
यह तब उपयोगी है जब आपके पास network में objects को access करने के लिए उपयोगी credentials हों, लेकिन वे credentials current host के अंदर valid न हों, क्योंकि उनका उपयोग केवल network में किया जाना है (current host में आपके current user privileges का उपयोग किया जाएगा)।

#### `runas /netonly` विवरण

`runas /netonly` (और `make_token` जैसे C2 helpers) एक **`LOGON32_LOGON_NEW_CREDENTIALS`** token बनाता है। Lateral movement के दौरान इसे समझना बहुत उपयोगी है, क्योंकि:<sup>[[3]](#references)</sup>

- **Locally**, नया process **same local identity**, groups, integrity level और current token के समान अधिकांश access decisions बनाए रखता है।
- **Remotely**, outbound authentication SMB / WinRM / LDAP / HTTP / Kerberos / NTLM के लिए **supplied credentials** का उपयोग कर सकता है।
- इसलिए `whoami` अभी भी **original local user** दिखा सकता है, जबकि network access **alternate account** के रूप में होता है।

यह एक बढ़िया विकल्प है जब credentials domain या किसी अन्य host में valid हों, लेकिन user current machine पर **locally log on नहीं कर सकता या नहीं करना चाहिए**।

### Tokens के प्रकार

दो प्रकार के tokens उपलब्ध हैं:

- **Primary Token**: यह किसी process के security credentials के representation के रूप में काम करता है। Processes के साथ primary tokens का creation और association ऐसे actions हैं जिनके लिए elevated privileges आवश्यक होते हैं, जो privilege separation के principle को दर्शाता है। आमतौर पर authentication service token creation के लिए जिम्मेदार होती है, जबकि logon service इसे user के operating system shell के साथ associate करती है। यह ध्यान देने योग्य है कि processes creation के समय अपने parent process का primary token inherit करते हैं।
- **Impersonation Token**: यह किसी server application को secure objects access करने के लिए अस्थायी रूप से client की identity अपनाने में सक्षम बनाता है। यह mechanism operation के चार levels में विभाजित है:
- **Anonymous**: Server को किसी unidentified user के समान access देता है।
- **Identification**: Server को client की identity verify करने देता है, लेकिन object access के लिए उसका उपयोग नहीं करने देता।
- **Impersonation**: Server को client की identity के तहत operate करने में सक्षम बनाता है।
- **Delegation**: Impersonation के समान, लेकिन इसमें इस identity assumption को उन remote systems तक extend करने की क्षमता भी शामिल होती है जिनसे server interact करता है, जिससे credentials सुरक्षित रहते हैं।

#### Impersonate Tokens

यदि आपके पास पर्याप्त privileges हैं, तो metasploit के _**incognito**_ module का उपयोग करके आप आसानी से अन्य **tokens** को **list** और **impersonate** कर सकते हैं। यह **ऐसे actions करने** के लिए उपयोगी हो सकता है **मानो आप कोई अन्य user हों**। इस technique से आप **privileges escalate** भी कर सकते हैं।

Operating के दौरान आसानी से भूल जाने वाले कुछ practical notes:<sup>[[1]](#references)</sup>

- **`CreateProcessWithTokenW`** को caller में **`SeImpersonatePrivilege`** की आवश्यकता होती है और नया process **caller's session** में चलेगा।
- **`CreateProcessAsUserW`** सामान्य fallback है जब `CreateProcessWithTokenW` `1314` के साथ fail हो जाए, या जब आपको **token द्वारा referenced session** में launch करना हो।
- यदि कोई token **`LogonUser(LOGON32_LOGON_NETWORK)`** से आता है, तो वह आमतौर पर **impersonation token** होता है, इसलिए उसके साथ process spawn करने का प्रयास करने से पहले आपको **`DuplicateTokenEx(..., TokenPrimary, ...)`** की आवश्यकता होती है।
- हर impersonation token समान रूप से उपयोगी नहीं होता: **`SecurityIdentification`** आपको user का निरीक्षण करने देता है, लेकिन **उसके रूप में act करने** नहीं देता। यदि किसी coercion primitive या pipe/RPC client से आपको केवल identification-level token मिलता है, तो **`TokenImpersonationLevel`** check करें और ऐसे primitive पर switch करें जो **`SecurityImpersonation`** या उससे बेहतर level देता हो।

#### LSASS को छुए बिना Token theft

यदि आपके पास पहले से कोई **service** या **SYSTEM** context है और कोई **privileged user logged on** है, तो उस user के token को steal या duplicate करना अक्सर **LSASS** dump करने से अधिक शांत तरीका होता है। कई वास्तविक intrusions में यह निम्नलिखित के लिए पर्याप्त होता है:<sup>[[2]](#references)</sup>

- उस user के रूप में local actions चलाना
- उस user के रूप में remote resources access करना
- पहले reusable credentials extract किए बिना AD operations करना

Privileged context से **session/user token hijacking** के examples के लिए [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md) देखें। याद रखें कि **`WTSQueryUserToken`** जैसे APIs **highly trusted services** के लिए बनाए गए हैं और सामान्यतः **`LocalSystem` + `SeTcbPrivilege`** की आवश्यकता होती है, इसलिए वे मुख्य रूप से तब उपयोगी होते हैं जब आपके पास पहले से service-level context का control हो। पहले **SYSTEM** प्राप्त करने के privilege-specific तरीकों के लिए नीचे दिए गए pages देखें।

### Token Privileges

जानें कि privileges escalate करने के लिए किन **token privileges का दुरुपयोग किया जा सकता है:**

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

[**all the possible token privileges and some definitions on this external page**](https://github.com/gtworek/Priv2Admin) देखें।

## References

- [1] [Understanding and Abusing Access Tokens — Part II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [2] [Abusing Windows' tokens to compromise Active Directory without touching LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Demystifying Cobalt Strike's "make_token" Command](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)

{{#include ../../banners/hacktricks-training.md}}
