# macOS .Net Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

**本文是对文章 [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/) 的总结。更多详细信息请参阅该文章！**<sup>[[1]](#references)</sup>

## .NET Core Debugging <a href="#net-core-debugging" id="net-core-debugging"></a>

### **建立 Debugging Session** <a href="#net-core-debugging" id="net-core-debugging"></a>

.NET 中 debugger 与 debuggee 之间通信的处理由 [**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp) 管理。该组件会为每个 .NET process 建立两个 named pipe，如 [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127) 中所示，这些 pipe 通过 [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27) 初始化。这些 pipe 的后缀分别为 **`-in`** 和 **`-out`**。

访问用户的 **`$TMPDIR`** 后，可以找到用于 debugging .Net applications 的 debugging FIFO。

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259) 负责管理来自 debugger 的通信。要启动新的 debugging session，debugger 必须通过 `out` pipe 发送一条以 `MessageHeader` struct 开头的消息，其定义详见 .NET source code：
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
要请求新会话，此结构体按如下方式填充，将消息类型设置为 `MT_SessionRequest`，并将协议版本设置为当前版本：
```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Configure the message type and version
sSendHeader.m_eType = MT_SessionRequest;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```
该 header 随后通过 `write` syscall 发送到目标，之后是包含会话 GUID 的 `sessionRequestData` struct：
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
对 `out` 管道执行读取操作可确认调试会话建立成功或失败：
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
## 读取内存

建立 debugging 会话后，可以使用 [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896) message type 读取内存。函数 readMemory 的详细流程如下，它执行发送读取请求并获取响应所需的步骤：
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
完整的 proof of concept (POC) 可在[此处](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b)获取。

## 写入内存

同样，可以使用 `writeMemory` 函数写入内存。该过程包括将消息类型设置为 `MT_WriteMemory`，指定数据的地址和长度，然后发送数据：
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
相关的 POC 可在[此处](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5)获取。

## .NET Core Code Execution <a href="#net-core-code-execution" id="net-core-code-execution"></a>

要执行代码，需要识别具有 rwx 权限的内存区域，这可以使用 vmmap -pages 完成：
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
定位一个可以覆盖函数指针的位置是必要的。在 .NET Core 中，可以通过针对 **Dynamic Function Table (DFT)** 来实现。该表的详细信息见 [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h)，运行时使用它来处理 JIT compilation helper functions。

对于 x64 系统，可以使用 signature hunting 在 `libcorclr.dll` 中查找对符号 `_hlpDynamicFuncTable` 的引用。

`MT_GetDCB` debugger function 提供了有用的信息，包括 helper function `m_helperRemoteStartAddr` 的地址，该地址表示 `libcorclr.dll` 在进程内存中的位置。随后可以使用该地址开始搜索 DFT，并将一个函数指针覆盖为 shellcode 的地址。

用于注入 PowerShell 的完整 POC code 可在[此处](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6)获取。

## References

- [1] [Adam Chester (xpnsec) - macOS Injection via Third Party Frameworks](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)

{{#include ../../../banners/hacktricks-training.md}}
