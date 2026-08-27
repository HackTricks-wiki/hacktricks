# macOS .Net Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

**यह पोस्ट [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/) का सारांश है। अधिक विवरण के लिए इसे देखें!**<sup>[[1]](#references)</sup>

## `DOTNET_STARTUP_HOOKS`

.NET Core 3.0 और उसके बाद के संस्करण `DOTNET_STARTUP_HOOKS` environment variable का support करते हैं। प्रत्येक path को एक ऐसे managed assembly की पहचान करनी चाहिए जिसमें `public static void Initialize()` method वाला global `StartupHook` type हो। Host assemblies को load करता है और application के `Main` entry point से पहले उनके initializers को synchronously call करता है, जिससे environment control के साथ-साथ एक readable DLL को direct pre-main code-execution primitive मिलता है।<sup>[[2]](#references)</sup>
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
Hook assembly application's runtime और dependencies के साथ compatible होना चाहिए। Directory separators वाले relative paths अस्वीकार कर दिए जाते हैं; absolute path या default load context से resolvable assembly name का उपयोग करें। Trimmed applications में startup hooks default रूप से disabled होते हैं, और custom native hosts environment से inherit करने के बजाय runtime properties सीधे प्रदान कर सकते हैं।<sup>[[2]](#references)</sup>

Defensive launchers को `DOTNET_STARTUP_HOOKS` clear करना चाहिए, application और shared assembly paths पर untrusted writes को रोकना चाहिए, और self-contained तथा trimmed deployments का अलग-अलग परीक्षण करना चाहिए।

## .NET Core Debugging <a href="#net-core-debugging" id="net-core-debugging"></a>

### **Debugging Session स्थापित करना** <a href="#net-core-debugging" id="net-core-debugging"></a>

.NET में debugger और debuggee के बीच communication का handling [**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp) द्वारा managed किया जाता है। यह component प्रत्येक .NET process के लिए दो named pipes set up करता है, जैसा कि [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127) में देखा जा सकता है। इन्हें [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27) के माध्यम से initiate किया जाता है। इन pipes के अंत में **`-in`** और **`-out`** जोड़े जाते हैं।

User के **`$TMPDIR`** पर जाकर, .Net applications की debugging के लिए उपलब्ध debugging FIFOs खोजे जा सकते हैं।

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259) debugger से होने वाले communication को manage करने के लिए responsible है। नया debugging session initiate करने के लिए, debugger को `out` pipe के माध्यम से एक message भेजना होगा, जो `MessageHeader` struct से शुरू हो। इसका विवरण .NET source code में दिया गया है:
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
नए session का अनुरोध करने के लिए, इस struct को निम्नलिखित तरीके से populate किया जाता है, जिसमें message type को `MT_SessionRequest` और protocol version को current version पर set किया जाता है:
```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Configure the message type and version
sSendHeader.m_eType = MT_SessionRequest;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```
यह header फिर `write` syscall का उपयोग करके target को भेजा जाता है, इसके बाद `sessionRequestData` struct भेजा जाता है, जिसमें session के लिए GUID होता है:
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
`out` pipe पर read operation debugging session स्थापित होने की सफलता या विफलता की पुष्टि करता है:
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
## Memory पढ़ना

एक debugging session स्थापित हो जाने के बाद, [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896) message type का उपयोग करके memory पढ़ी जा सकती है। आवश्यक steps को पूरा करते हुए read request भेजने और response प्राप्त करने के लिए function readMemory का विवरण दिया गया है:
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
पूरा proof of concept (POC) [यहाँ](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b) उपलब्ध है।

## Memory लिखना

इसी तरह, `writeMemory` function का उपयोग करके memory में लिखा जा सकता है। इस प्रक्रिया में message type को `MT_WriteMemory` पर सेट करना, data का address और length निर्दिष्ट करना, और फिर data भेजना शामिल है:
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
The associated POC [here](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5) उपलब्ध है।

## .NET Core Code Execution <a href="#net-core-code-execution" id="net-core-code-execution"></a>

Code execute करने के लिए, rwx permissions वाले memory region की पहचान करनी होती है, जिसे vmmap -pages: का उपयोग करके किया जा सकता है।
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
किसी function pointer को overwrite करने के लिए स्थान ढूँढना आवश्यक है, और .NET Core में यह **Dynamic Function Table (DFT)** को target करके किया जा सकता है। [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h) में विस्तार से बताई गई यह table, runtime द्वारा JIT compilation helper functions के लिए उपयोग की जाती है।

x64 systems के लिए, `libcorclr.dll` में symbol `_hlpDynamicFuncTable` का reference खोजने के लिए signature hunting का उपयोग किया जा सकता है।

`MT_GetDCB` debugger function उपयोगी जानकारी प्रदान करता है, जिसमें एक helper function का address, `m_helperRemoteStartAddr`, शामिल है। यह process memory में `libcorclr.dll` के स्थान को दर्शाता है। इसके बाद इस address का उपयोग DFT की search शुरू करने और shellcode के address से function pointer को overwrite करने के लिए किया जाता है।

PowerShell में injection के लिए पूरा POC code [यहाँ](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6) उपलब्ध है।

## References

- [1] [Adam Chester (xpnsec) - Third Party Frameworks के माध्यम से macOS Injection](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)
- [2] [.NET runtime host startup hook design](https://github.com/dotnet/runtime/blob/main/docs/design/features/host-startup-hook.md)
{{#include ../../../banners/hacktricks-training.md}}
