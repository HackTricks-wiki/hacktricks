# macOS .Net Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

**Dit is 'n opsomming van die plasing [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/). Sien dit vir verdere besonderhede!**<sup>[[1]](#references)</sup>

## .NET Core Debugging <a href="#net-core-debugging" id="net-core-debugging"></a>

### **Vestiging van 'n Debugging-sessie** <a href="#net-core-debugging" id="net-core-debugging"></a>

Die hantering van kommunikasie tussen debugger en debuggee in .NET word deur [**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp) bestuur. Hierdie komponent stel twee named pipes per .NET-proses op, soos gesien in [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127), wat geïnisieer word via [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27). Hierdie pipes het die agtervoegsels **`-in`** en **`-out`**.

Deur die gebruiker se **`$TMPDIR`** te besoek, kan ’n mens debugging-FIFOs vind wat beskikbaar is vir debugging van .Net-toepassings.

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259) is verantwoordelik vir die bestuur van kommunikasie vanaf ’n debugger. Om ’n nuwe debugging-sessie te inisieer, moet ’n debugger ’n boodskap via die `out`-pipe stuur wat met ’n `MessageHeader`-struct begin, soos uiteengesit in die .NET-bronkode:
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
Om 'n nuwe sessie aan te vra, word hierdie struct soos volg ingevul, met die boodskaptipe op `MT_SessionRequest` en die protokolweergawe op die huidige weergawe gestel:
```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Configure the message type and version
sSendHeader.m_eType = MT_SessionRequest;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```
Hierdie header word dan na die target gestuur met die `write` syscall, gevolg deur die `sessionRequestData`-struct wat ’n GUID vir die session bevat:
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
’n Leesbewerking op die `out`-pyp bevestig die sukses of mislukking van die vestiging van die debugging session:
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
## Lees van geheue

Sodra ’n debugging-sessie gevestig is, kan geheue gelees word deur die [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896)-boodskaptipe te gebruik. Die funksie readMemory word uiteengesit en voer die nodige stappe uit om ’n leesversoek te stuur en die antwoord te verkry:
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

## Geheue skryf

Net so kan geheue met die `writeMemory`-funksie geskryf word. Die proses behels dat die boodskaptipe op `MT_WriteMemory` gestel word, die adres en lengte van die data gespesifiseer word, en die data dan gestuur word:
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
The associated POC is beskikbaar [hier](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5).

## .NET Core Code Execution <a href="#net-core-code-execution" id="net-core-code-execution"></a>

Om code uit te voer, moet ’n geheuegebied met rwx-permissies geïdentifiseer word, wat met vmmap -pages gedoen kan word:
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
Om 'n plek te vind om 'n function pointer te oorskryf, is noodsaaklik, en in .NET Core kan dit gedoen word deur die **Dynamic Function Table (DFT)** te teiken. Hierdie tabel, wat in [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h) uiteengesit word, word deur die runtime vir JIT compilation helper functions gebruik.

Vir x64-stelsels kan signature hunting gebruik word om 'n verwysing na die simbool `_hlpDynamicFuncTable` in `libcorclr.dll` te vind.

Die `MT_GetDCB` debugger function verskaf nuttige inligting, insluitend die adres van 'n helper function, `m_helperRemoteStartAddr`, wat die ligging van `libcorclr.dll` in die proses se geheue aandui. Hierdie adres word dan gebruik om 'n search na die DFT te begin en 'n function pointer met die shellcode se adres te oorskryf.

Die volledige POC code vir injection in PowerShell is [hier](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6) beskikbaar.

## Verwysings

- [1] [Adam Chester (xpnsec) - macOS Injection via Third Party Frameworks](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)

{{#include ../../../banners/hacktricks-training.md}}
