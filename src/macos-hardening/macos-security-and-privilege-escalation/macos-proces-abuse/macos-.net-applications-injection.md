# macOS .Net Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

**이 내용은 [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/) 게시글을 요약한 것입니다. 자세한 내용은 해당 글을 확인하세요!**<sup>[[1]](#references)</sup>

## .NET Core Debugging <a href="#net-core-debugging" id="net-core-debugging"></a>

### **Debugging Session 설정** <a href="#net-core-debugging" id="net-core-debugging"></a>

.NET에서 debugger와 debuggee 간 통신 처리는 [**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp)에서 관리합니다. 이 구성 요소는 [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127)에 나오는 것처럼 각 .NET process에 대해 두 개의 named pipe를 설정하며, 이 pipe들은 [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27)을 통해 초기화됩니다. 이러한 pipe의 접미사는 **`-in`** 및 **`-out`**입니다.

사용자의 **`$TMPDIR`**을 확인하면 .Net applications debugging에 사용할 수 있는 debugging FIFO를 찾을 수 있습니다.

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259)는 debugger로부터의 통신을 관리합니다. 새로운 debugging session을 시작하려면 debugger가 `MessageHeader` struct로 시작하는 message를 `out` pipe를 통해 보내야 합니다. 이 struct에 대한 자세한 내용은 .NET source code에 나와 있습니다:
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
새 세션을 요청하려면 이 struct를 다음과 같이 채우고, message type을 `MT_SessionRequest`로, protocol version을 현재 버전으로 설정합니다:
```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Configure the message type and version
sSendHeader.m_eType = MT_SessionRequest;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```
이 헤더는 이후 `write` syscall을 통해 target으로 전송되고, 이어서 세션을 위한 GUID를 포함한 `sessionRequestData` struct가 전송됩니다:
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
`out` pipe에 대한 read 작업은 debugging session 설정의 성공 또는 실패를 확인합니다:
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
## Memory 읽기

debugging session이 설정되면 [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896) message type을 사용하여 memory를 읽을 수 있습니다. 함수 `readMemory`는 read request를 전송하고 response를 가져오는 데 필요한 단계를 수행하며, 다음과 같이 자세히 설명됩니다:
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
완전한 proof of concept (POC)은 [여기](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b)에 있습니다.

## 메모리 쓰기

마찬가지로 `writeMemory` function을 사용하여 메모리를 쓸 수 있습니다. 이 과정에서는 message type을 `MT_WriteMemory`로 설정하고, 데이터의 address와 length를 지정한 다음 데이터를 전송합니다:
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

Code를 execute하려면 rwx 권한이 있는 memory region을 식별해야 하며, 이는 vmmap -pages를 사용하여 수행할 수 있습니다:
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
함수 포인터를 overwrite할 위치를 찾는 것이 필요하며, .NET Core에서는 **Dynamic Function Table (DFT)** 을 대상으로 지정하여 이를 수행할 수 있습니다. [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h)에 자세히 설명된 이 테이블은 JIT compilation helper functions를 위해 runtime에서 사용됩니다.

x64 systems에서는 signature hunting을 사용하여 `libcorclr.dll` 내의 `_hlpDynamicFuncTable` symbol에 대한 reference를 찾을 수 있습니다.

`MT_GetDCB` debugger function은 helper function인 `m_helperRemoteStartAddr`의 address를 비롯한 유용한 정보를 제공합니다. 이 address는 process memory 내 `libcorclr.dll`의 위치를 나타냅니다. 그런 다음 이 address를 사용하여 DFT 검색을 시작하고 function pointer를 shellcode의 address로 overwrite합니다.

PowerShell에 injection하는 전체 POC code는 [여기](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6)에서 확인할 수 있습니다.

## References

- [1] [Adam Chester (xpnsec) - macOS Injection via Third Party Frameworks](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)

{{#include ../../../banners/hacktricks-training.md}}
