# macOS .Net Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

**यह [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/) post का summary है। अधिक details के लिए इसे देखें!**<sup>[[1]](#references)</sup>

## .NET Core Debugging <a href="#net-core-debugging" id="net-core-debugging"></a>

### **Debugging Session स्थापित करना** <a href="#net-core-debugging" id="net-core-debugging"></a>

.NET में debugger और debuggee के बीच communication को [**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp) द्वारा manage किया जाता है। यह component प्रत्येक .NET process के लिए दो named pipes set up करता है, जैसा कि [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127) में देखा जा सकता है। इन्हें [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27) के माध्यम से initiate किया जाता है। इन pipes के अंत में **`-in`** और **`-out`** suffix होते हैं।

User के **`$TMPDIR`** पर जाकर, .Net applications की debugging के लिए available debugging FIFOs खोजे जा सकते हैं।

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259) debugger से होने वाले communication को manage करने के लिए responsible है। नई debugging session initiate करने के लिए, debugger को `out` pipe के माध्यम से एक message भेजना होगा, जो `MessageHeader` struct से शुरू होता है। इसका विवरण .NET source code में दिया गया है:
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
नए session का अनुरोध करने के लिए, इस struct को निम्नानुसार populate किया जाता है, जिसमें message type को `MT_SessionRequest` और protocol version को current version पर सेट किया जाता है:
```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Configure the message type and version
sSendHeader.m_eType = MT_SessionRequest;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```
यह header फिर `write` syscall का उपयोग करके target को भेजा जाता है, जिसके बाद session के लिए GUID वाली `sessionRequestData` struct भेजी जाती है:
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
`out` pipe पर एक `read` operation debugging session establishment की सफलता या विफलता की पुष्टि करता है:
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
## Memory पढ़ना

एक debugging session स्थापित होने के बाद, [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896) message type का उपयोग करके memory पढ़ी जा सकती है। Function readMemory का विवरण आवश्यक steps के साथ दिया गया है, जो read request भेजने और response प्राप्त करने का कार्य करता है:
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
पूरा POC [यहाँ](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b) उपलब्ध है।

## Memory लिखना

इसी तरह, `writeMemory` function का उपयोग करके memory लिखी जा सकती है। इस प्रक्रिया में message type को `MT_WriteMemory` पर set करना, data का address और length निर्दिष्ट करना, और फिर data भेजना शामिल है:
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
The associated POC [यहाँ](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5) उपलब्ध है।

## .NET Core Code Execution <a href="#net-core-code-execution" id="net-core-code-execution"></a>

Code execute करने के लिए, rwx permissions वाले memory region की पहचान करनी होगी, जिसे vmmap -pages का उपयोग करके किया जा सकता है:
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
किसी function pointer को overwrite करने के लिए उपयुक्त स्थान ढूँढना आवश्यक है, और .NET Core में यह **Dynamic Function Table (DFT)** को target करके किया जा सकता है। यह table, जिसका विवरण [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h) में दिया गया है, runtime द्वारा JIT compilation helper functions के लिए उपयोग की जाती है।

x64 systems के लिए, `libcorclr.dll` में symbol `_hlpDynamicFuncTable` का reference ढूँढने हेतु signature hunting का उपयोग किया जा सकता है।

`MT_GetDCB` debugger function उपयोगी जानकारी प्रदान करता है, जिसमें एक helper function का address, `m_helperRemoteStartAddr`, भी शामिल है। यह process memory में `libcorclr.dll` के location को दर्शाता है। इसके बाद इस address का उपयोग DFT की search शुरू करने और किसी function pointer को shellcode के address से overwrite करने के लिए किया जाता है।

PowerShell में injection के लिए पूरा POC code [यहाँ](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6) उपलब्ध है।

## संदर्भ

- [1] [Adam Chester (xpnsec) - macOS Injection via Third Party Frameworks](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)

{{#include ../../../banners/hacktricks-training.md}}
