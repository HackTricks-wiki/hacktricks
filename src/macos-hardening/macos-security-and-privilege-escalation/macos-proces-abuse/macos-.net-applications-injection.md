# macOS .Net Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

**이 내용은 [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/) 게시글을 요약한 것입니다. 자세한 내용은 해당 글을 확인하세요!**<sup>[[1]](#references)</sup>

## .NET Core Debugging <a href="#net-core-debugging" id="net-core-debugging"></a>

### **Debugging Session 설정** <a href="#net-core-debugging" id="net-core-debugging"></a>

.NET에서 debugger와 debuggee 간 통신 처리는 [**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp)에서 관리합니다. 이 component는 [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127)에 나와 있듯이 각 .NET process에 두 개의 named pipe를 설정하며, 이 pipe들은 [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27)을 통해 초기화됩니다. 이 pipe들은 **`-in`** 및 **`-out`** 접미사를 사용합니다.

사용자의 **`$TMPDIR`**로 이동하면 .Net applications을 debugging하는 데 사용할 수 있는 debugging FIFO를 찾을 수 있습니다.

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259)는 debugger에서 전달되는 통신을 관리합니다. 새로운 debugging session을 시작하려면 debugger는 `out` pipe를 통해 .NET source code에 자세히 설명된 `MessageHeader` struct로 시작하는 message를 전송해야 합니다:
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
새 세션을 요청하려면 이 struct는 다음과 같이 채워지며, message type은 `MT_SessionRequest`로, protocol version은 현재 버전으로 설정됩니다:
```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Configure the message type and version
sSendHeader.m_eType = MT_SessionRequest;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```
이 헤더는 그런 다음 `write` syscall을 사용해 대상에 전송되며, 세션의 GUID를 포함하는 `sessionRequestData` struct가 뒤따릅니다:
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
`out` pipe에 대한 read operation은 debugging session establishment의 성공 또는 실패를 확인합니다:
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
## 메모리 읽기

debugging session이 설정되면 [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896) message type을 사용하여 메모리를 읽을 수 있습니다. function readMemory에는 read request를 전송하고 response를 가져오는 데 필요한 단계가 자세히 설명되어 있습니다:
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
전체 proof of concept (POC)는 [여기](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b)에서 확인할 수 있습니다.

## 메모리 쓰기

마찬가지로 `writeMemory` 함수를 사용하여 메모리에 쓸 수 있습니다. 이 과정에서는 메시지 유형을 `MT_WriteMemory`로 설정하고 데이터의 주소와 길이를 지정한 다음 데이터를 전송합니다:
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
관련 POC는 [여기](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5)에서 확인할 수 있습니다.

## .NET Core Code Execution <a href="#net-core-code-execution" id="net-core-code-execution"></a>

code를 실행하려면 rwx 권한이 있는 memory region을 식별해야 하며, 이는 다음과 같이 vmmap -pages를 사용하여 수행할 수 있습니다:
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
함수 포인터를 overwrite할 위치를 찾는 것이 필요하며, .NET Core에서는 **Dynamic Function Table (DFT)** 을 대상으로 지정하여 이를 수행할 수 있습니다. [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h)에 자세히 설명된 이 테이블은 runtime에서 JIT compilation helper functions에 사용됩니다.

x64 시스템에서는 signature hunting을 사용하여 `libcorclr.dll` 내의 `_hlpDynamicFuncTable` 심볼에 대한 참조를 찾을 수 있습니다.

`MT_GetDCB` debugger function은 helper function인 `m_helperRemoteStartAddr`의 주소를 포함한 유용한 정보를 제공합니다. 이 주소는 프로세스 메모리에서 `libcorclr.dll`의 위치를 나타냅니다. 그런 다음 이 주소를 사용하여 DFT 검색을 시작하고 function pointer를 shellcode의 주소로 overwrite합니다.

PowerShell에 injection하는 전체 POC code는 [여기](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6)에서 확인할 수 있습니다.

## References

- [1] [Adam Chester (xpnsec) - macOS Injection via Third Party Frameworks](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)

{{#include ../../../banners/hacktricks-training.md}}
