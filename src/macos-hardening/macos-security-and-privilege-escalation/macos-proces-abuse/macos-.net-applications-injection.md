# macOS .Net Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

**Đây là bản tóm tắt bài viết [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/). Hãy xem bài viết để biết thêm chi tiết!**<sup>[[1]](#references)</sup>

## `DOTNET_STARTUP_HOOKS`

.NET Core 3.0 trở lên hỗ trợ biến môi trường `DOTNET_STARTUP_HOOKS`. Mỗi đường dẫn phải trỏ đến một managed assembly có kiểu `StartupHook` toàn cục với phương thức `public static void Initialize()`. Host tải các assembly này và gọi các hàm khởi tạo một cách đồng bộ trước điểm vào `Main` của ứng dụng, tạo ra một primitive thực thi mã trước `Main` khi kiểm soát được môi trường và có một DLL đọc được.<sup>[[2]](#references)</sup>

```csharp
// StartupHook.cs — compile as a class-library assembly.
using System.IO;

internal class StartupHook
{
    public static void Initialize()
    {
        File.WriteAllText("/tmp/dotnet-startup-hook-executed", "executed\n");
    }
}
```

```bash
dotnet new classlib -n StartupHookPayload -f net8.0
cp StartupHook.cs StartupHookPayload/Class1.cs
dotnet build StartupHookPayload -c Release

DOTNET_STARTUP_HOOKS="$PWD/StartupHookPayload/bin/Release/net8.0/StartupHookPayload.dll" \
  dotnet /path/to/TargetApplication.dll
```

Assembly hook phải tương thích với runtime và các dependency của ứng dụng. Các đường dẫn tương đối có chứa dấu phân cách thư mục sẽ bị từ chối; hãy dùng đường dẫn tuyệt đối hoặc tên assembly có thể phân giải từ load context mặc định. Startup hooks bị tắt theo mặc định trong các ứng dụng đã trim, và các native host tùy chỉnh có thể cung cấp trực tiếp các thuộc tính runtime thay vì kế thừa từ môi trường.<sup>[[2]](#references)</sup>

Các launcher phòng thủ nên xóa `DOTNET_STARTUP_HOOKS`, ngăn chặn việc ghi trái phép vào các đường dẫn assembly của ứng dụng và assembly dùng chung, đồng thời kiểm thử riêng các bản triển khai self-contained và đã trim.

## Gỡ lỗi .NET Core <a href="#net-core-debugging" id="net-core-debugging"></a>

### **Thiết lập phiên gỡ lỗi** <a href="#net-core-debugging" id="net-core-debugging"></a>

Việc xử lý giao tiếp giữa debugger và debuggee trong .NET do [**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp) quản lý. Thành phần này thiết lập hai named pipe cho mỗi tiến trình .NET như trong [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127); các pipe này được khởi tạo thông qua [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27). Tên các pipe này có hậu tố **`-in`** và **`-out`**.

Truy cập **`$TMPDIR`** của người dùng để tìm các FIFO gỡ lỗi có sẵn cho việc gỡ lỗi ứng dụng .Net.

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259) chịu trách nhiệm quản lý giao tiếp từ debugger. Để bắt đầu một phiên gỡ lỗi mới, debugger phải gửi một thông điệp qua pipe `out`, bắt đầu bằng một struct `MessageHeader`, được mô tả trong mã nguồn .NET:

```c
struct MessageHeader {
    MessageType   m_eType;        // Message type
    DWORD         m_cbDataBlock;  // Size of following data block (can be zero)
    DWORD         m_dwId;         // Message ID from sender
    DWORD         m_dwReplyId;    // Reply-to Message ID
    DWORD         m_dwLastSeenId; // Last seen Message ID by sender
    DWORD         m_dwReserved;   // Reserved for future (initialize to zero)
        union {
            struct {
                DWORD         m_dwMajorVersion;   // Requested/accepted protocol version
                DWORD         m_dwMinorVersion;
            } VersionInfo;
          ...
        } TypeSpecificData;
    BYTE          m_sMustBeZero[8];
}
```

Để yêu cầu một phiên mới, struct này được điền như sau, với loại thông điệp được đặt thành `MT_SessionRequest` và phiên bản giao thức được đặt thành phiên bản hiện tại:

```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Configure the message type and version
sSendHeader.m_eType = MT_SessionRequest;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```

Header này sau đó được gửi đến mục tiêu bằng syscall `write`, tiếp theo là struct `sessionRequestData` chứa GUID của phiên:

```c
write(wr, &sSendHeader, sizeof(MessageHeader));
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));
write(wr, &sDataBlock, sizeof(SessionRequestData));
```

Thao tác đọc trên pipe `out` xác nhận việc thiết lập phiên gỡ lỗi thành công hay thất bại:

```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```

## Đọc bộ nhớ

Sau khi thiết lập phiên gỡ lỗi, có thể đọc bộ nhớ bằng loại thông điệp [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896). Hàm readMemory được trình bày chi tiết, thực hiện các bước cần thiết để gửi yêu cầu đọc và nhận phản hồi:

```c
bool readMemory(void *addr, int len, unsigned char **output) {
// Allocation and initialization
...
// Write header and read response
...
// Read the memory from the debuggee
...
return true;
}
```

Bản proof of concept (POC) đầy đủ có tại [đây](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b).

## Ghi vào bộ nhớ

Tương tự, có thể ghi vào bộ nhớ bằng hàm `writeMemory`. Quy trình gồm đặt loại thông điệp thành `MT_WriteMemory`, chỉ định địa chỉ và độ dài dữ liệu, rồi gửi dữ liệu:

```c
bool writeMemory(void *addr, int len, unsigned char *input) {
// Increment IDs, set message type, and specify memory location
...
// Write header and data, then read the response
...
// Confirm memory write was successful
...
return true;
}
```

POC liên quan có tại [đây](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5).

## Thực thi mã .NET Core <a href="#net-core-code-execution" id="net-core-code-execution"></a>

Để thực thi mã, cần xác định một vùng bộ nhớ có quyền rwx. Có thể thực hiện việc này bằng vmmap -pages:

```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```

Việc xác định vị trí để ghi đè function pointer là cần thiết. Trong .NET Core, có thể nhắm mục tiêu vào **Dynamic Function Table (DFT)**. Bảng này, được mô tả trong [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h), được runtime sử dụng cho các hàm trợ giúp biên dịch JIT.

Trên hệ thống x64, có thể dùng signature hunting để tìm tham chiếu đến ký hiệu `_hlpDynamicFuncTable` trong `libcorclr.dll`.

Hàm debugger `MT_GetDCB` cung cấp thông tin hữu ích, bao gồm địa chỉ của hàm trợ giúp `m_helperRemoteStartAddr`, cho biết vị trí của `libcorclr.dll` trong bộ nhớ của tiến trình. Sau đó, dùng địa chỉ này để bắt đầu tìm DFT và ghi đè một function pointer bằng địa chỉ của shellcode.

Có thể xem toàn bộ mã POC để injection vào PowerShell [tại đây](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6).

## References

- [1] [Adam Chester (xpnsec) - Injection trên macOS qua framework của bên thứ ba](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)
- [2] [Thiết kế host startup hook của .NET runtime](https://github.com/dotnet/runtime/blob/main/docs/design/features/host-startup-hook.md)
{{#include ../../../banners/hacktricks-training.md}}
