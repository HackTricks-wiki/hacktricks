# macOS .Net 应用程序注入

{{#include ../../../banners/hacktricks-training.md}}

**这是帖子 [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/) 的摘要。请查看以获取更多详细信息！**

## .NET Core 调试 <a href="#net-core-debugging" id="net-core-debugging"></a>

### **建立调试会话** <a href="#net-core-debugging" id="net-core-debugging"></a>

在 .NET 中，调试器与被调试程序之间的通信处理由 [**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp) 管理。该组件为每个 .NET 进程设置两个命名管道，如 [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127) 所示，这些管道通过 [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27) 初始化。这些管道的后缀为 **`-in`** 和 **`-out`**。

通过访问用户的 **`$TMPDIR`**，可以找到可用于调试 .Net 应用程序的调试 FIFO。

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259) 负责管理来自调试器的通信。要启动新的调试会话，调试器必须通过 `out` 管道发送一条以 `MessageHeader` 结构开头的消息，该结构在 .NET 源代码中详细说明：
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
要请求一个新会话，结构体如下填充，将消息类型设置为 `MT_SessionRequest`，并将协议版本设置为当前版本：
```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Configure the message type and version
sSendHeader.m_eType = MT_SessionRequest;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```
该头部随后通过 `write` 系统调用发送到目标，后面跟着包含会话 GUID 的 `sessionRequestData` 结构：
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
对`out`管道的读取操作确认调试会话建立的成功或失败：
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
## 读取内存

一旦建立了调试会话，就可以使用 [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896) 消息类型读取内存。函数 readMemory 进行了详细说明，执行发送读取请求和检索响应所需的步骤：
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
完整的概念验证（POC）可在 [这里](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b) 获取。

## 写入内存

类似地，可以使用 `writeMemory` 函数写入内存。该过程涉及将消息类型设置为 `MT_WriteMemory`，指定数据的地址和长度，然后发送数据：
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
相关的POC可以在[这里](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5)找到。

## .NET Core 代码执行 <a href="#net-core-code-execution" id="net-core-code-execution"></a>

要执行代码，需要识别一个具有rwx权限的内存区域，这可以通过使用vmmap -pages:来完成。
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
定位一个覆盖函数指针的位置是必要的，在 .NET Core 中，可以通过针对 **Dynamic Function Table (DFT)** 来实现。这个表在 [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h) 中有详细说明，运行时使用它来进行 JIT 编译辅助函数。

对于 x64 系统，可以使用签名搜索来找到 `libcorclr.dll` 中符号 `_hlpDynamicFuncTable` 的引用。

`MT_GetDCB` 调试器函数提供了有用的信息，包括一个辅助函数的地址 `m_helperRemoteStartAddr`，指示 `libcorclr.dll` 在进程内存中的位置。然后使用这个地址开始搜索 DFT，并用 shellcode 的地址覆盖一个函数指针。

注入 PowerShell 的完整 POC 代码可以在 [这里](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6) 访问。

## References

- [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)

{{#include ../../../banners/hacktricks-training.md}}
