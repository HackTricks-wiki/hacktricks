# Access Tokens

{{#include ../../banners/hacktricks-training.md}}

## Access Tokens

सिस्टम पर लॉग इन किया गया प्रत्येक **user** उस logon session के लिए **security information वाला access token** रखता है। सिस्टम तब access token बनाता है जब user log on करता है। **User की behalf पर execute होने वाला हर process** access token की एक copy रखता है। Token user, user के groups, और user के privileges को identify करता है। Token में एक logon SID (Security Identifier) भी होता है जो current logon session को identify करता है।

आप यह information `whoami /all` चलाकर देख सकते हैं
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
या तो Sysinternals के _Process Explorer_ का उपयोग करके (process चुनें और "Security" tab access करें):

![Access Tokens - Access Tokens: or using Process Explorer from Sysinternals (select process and access"Security" tab)](<../../images/image (772).png>)

### Local administrator

जब एक local administrator logins करता है, **दो access tokens बनाए जाते हैं**: एक admin rights के साथ और दूसरा normal rights के साथ। **By default**, जब यह user कोई process execute करता है, तो **regular** (non-administrator) **rights वाला token उपयोग किया जाता है**। जब यह user कुछ भी **administrator के रूप में execute** करने की कोशिश करता है ("Run as Administrator" उदाहरण के लिए), तो अनुमति माँगने के लिए **UAC** उपयोग किया जाएगा।\
अगर आप [**UAC के बारे में अधिक जानना चाहते हैं तो यह page पढ़ें**](../authentication-credentials-uac-and-efs/index.html#uac)**.**

व्यावहारिक रूप से, इसका मतलब है कि एक **non-elevated admin shell आमतौर पर filtered token के साथ चलता है**। इसलिए `whoami /groups` अक्सर **`BUILTIN\Administrators` को `Deny only` के रूप में दिखाता है** जब तक process elevated न हो जाए। अंदरूनी तौर पर, Windows एक **linked elevated token** (`TokenLinkedToken`) रखता है और `TokenElevationType` जैसे fields के साथ state को track करता है।

### Credentials user impersonation

अगर आपके पास **किसी दूसरे user की valid credentials** हैं, तो आप उन credentials के साथ एक **new logon session** **create** कर सकते हैं :
```
runas /user:domain\username cmd.exe
```
**access token** के पास **LSASS** के अंदर logon sessions का एक **reference** भी होता है, यह तब उपयोगी है जब process को network के कुछ objects access करने हों।\
आप एक process launch कर सकते हैं जो network services access करने के लिए **different credentials** use करता है, using:
```
runas /user:domain\username /netonly cmd.exe
```
यह तब उपयोगी है जब आपके पास नेटवर्क में objects तक पहुंचने के लिए उपयोगी credentials हों, लेकिन वे credentials current host के अंदर valid नहीं हों, क्योंकि उनका उपयोग केवल network में किया जाएगा (current host में आपके current user privileges का उपयोग होगा).

#### `runas /netonly` details

`runas /netonly` (और C2 helpers जैसे `make_token`) एक **`LOGON32_LOGON_NEW_CREDENTIALS`** token बनाता है. lateral movement के दौरान इसे समझना बहुत उपयोगी है क्योंकि:

- **Locally**, नया process **same local identity**, groups, integrity level, और current token के अधिकांश same access decisions बनाए रखता है।
- **Remotely**, outbound authentication SMB / WinRM / LDAP / HTTP / Kerberos / NTLM के लिए **supplied credentials** का उपयोग कर सकती है।
- इसलिए `whoami` अभी भी **original local user** दिखा सकता है, जबकि network access **alternate account** के रूप में होता है।

यह एक बढ़िया विकल्प है जब credentials domain में या किसी दूसरे host पर valid हों, लेकिन user **current machine पर locally log on नहीं कर सकता या नहीं करना चाहिए**।

### Types of tokens

उपलब्ध tokens के दो प्रकार हैं:

- **Primary Token**: यह process की security credentials का representation होता है। primary tokens का processes के साथ creation और association elevated privileges की मांग करते हैं, जो privilege separation के principle को दर्शाता है। आम तौर पर, token creation के लिए authentication service जिम्मेदार होती है, जबकि logon service उसे user के operating system shell के साथ associate करती है। यह ध्यान देने योग्य है कि processes creation के समय अपने parent process का primary token inherit करते हैं।
- **Impersonation Token**: server application को secure objects तक पहुंचने के लिए client की identity को अस्थायी रूप से अपनाने में सक्षम बनाता है। यह mechanism operation के चार levels में विभाजित है:
- **Anonymous**: unidentified user जैसी server access प्रदान करता है।
- **Identification**: server को client की identity verify करने देता है, बिना उसे object access के लिए उपयोग किए।
- **Impersonation**: server को client की identity के तहत operate करने में सक्षम बनाता है।
- **Delegation**: Impersonation जैसा ही है, लेकिन server जिन remote systems के साथ interact करता है, वहां इस identity assumption को extend करने की क्षमता भी शामिल करता है, जिससे credential preservation सुनिश्चित होती है।

#### Impersonate Tokens

metasploit के _**incognito**_ module का उपयोग करके, यदि आपके पास पर्याप्त privileges हों, तो आप आसानी से अन्य **tokens** को **list** और **impersonate** कर सकते हैं। यह **ऐसे actions** करने में उपयोगी हो सकता है जैसे आप **दूसरे user** हों। आप इस technique से **privileges escalate** भी कर सकते हैं।

काम करते समय कुछ practical notes, जिन्हें भूलना आसान होता है:

- **`CreateProcessWithTokenW`** को caller में **`SeImpersonatePrivilege`** चाहिए, और नया process **caller's session** में चलेगा।
- जब **`CreateProcessWithTokenW`** `1314` के साथ fail हो, या जब आपको **token द्वारा referenced session** में launch करना हो, तो **`CreateProcessAsUserW`** आम fallback है।
- अगर token **`LogonUser(LOGON32_LOGON_NETWORK)`** से आता है, तो वह आम तौर पर **impersonation token** होता है, इसलिए process spawn करने से पहले **`DuplicateTokenEx(..., TokenPrimary, ...)`** चाहिए।
- हर impersonation token समान रूप से उपयोगी नहीं होता: **`SecurityIdentification`** आपको user inspect करने देता है, लेकिन **उनकी तरह act** नहीं करने देता। अगर कोई coercion primitive या pipe/RPC client आपको केवल identification-level token देता है, तो **`TokenImpersonationLevel`** जांचें और ऐसे primitive पर स्विच करें जो **`SecurityImpersonation`** या उससे बेहतर दे।

#### Token theft without touching LSASS

अगर आपके पास पहले से **service** या **SYSTEM** context है और कोई **privileged user logged on** है, तो उस user का token steal या duplicate करना अक्सर **LSASS** dump करने से अधिक quiet होता है। कई real intrusions में यह इतना ही पर्याप्त होता है कि:

- उस user के रूप में local actions चलाएं
- उस user के रूप में remote resources access करें
- पहले reusable credentials extract किए बिना AD operations perform करें

Privileged context से **session/user token hijacking** के examples के लिए देखें [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md). याद रखें कि **`WTSQueryUserToken`** जैसी APIs **highly trusted services** के लिए होती हैं और सामान्यतः **`LocalSystem` + `SeTcbPrivilege`** की आवश्यकता होती है, इसलिए ये मुख्यतः तब उपयोगी हैं जब आपके पास पहले से service-level context हो। पहले **SYSTEM** पाने के privilege-specific तरीकों के लिए नीचे दिए गए pages देखें।

### Token Privileges

जानें कि कौन-से **token privileges** का उपयोग **privileges escalate** करने के लिए किया जा सकता है:

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

[**all the possible token privileges and some definitions on this external page**](https://github.com/gtworek/Priv2Admin) पर एक नज़र डालें।

## References

- [https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa)
- [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)

{{#include ../../banners/hacktricks-training.md}}
