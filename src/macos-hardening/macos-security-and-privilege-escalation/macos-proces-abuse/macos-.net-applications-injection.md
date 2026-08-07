# Injection ya .Net Applications kwenye macOS

{{#include ../../../banners/hacktricks-training.md}}

**Huu ni muhtasari wa chapisho [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/). Liangalie kwa maelezo zaidi!**<sup>[[1]](#references)</sup>

## Debugging ya .NET Core <a href="#net-core-debugging" id="net-core-debugging"></a>

### **Kuanzisha Kipindi cha Debugging** <a href="#net-core-debugging" id="net-core-debugging"></a>

Ushughulikiaji wa mawasiliano kati ya debugger na debuggee katika .NET unasimamiwa na [**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp). Kipengele hiki huanzisha named pipes mbili kwa kila mchakato wa .NET, kama inavyoonekana katika [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127), ambazo huanzishwa kupitia [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27). Pipes hizi huongezewa viambishi **`-in`** na **`-out`**.

Kwa kutembelea **`$TMPDIR`** ya mtumiaji, mtu anaweza kupata debugging FIFOs zinazopatikana kwa ajili ya debugging ya .Net applications.

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259) inawajibika kusimamia mawasiliano kutoka kwa debugger. Ili kuanzisha kipindi kipya cha debugging, debugger lazima itume ujumbe kupitia pipe ya `out` unaoanza na muundo wa `MessageHeader`, uliofafanuliwa katika source code ya .NET:
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
Kichwa hiki hutumwa kwa target kwa kutumia syscall ya `write`, kikifuatiwa na struct ya `sessionRequestData` iliyo na GUID ya session:
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
Operesheni ya kusoma kwenye pipe ya `out` inathibitisha kufanikiwa au kushindikana kwa uanzishaji wa kipindi cha debugging:
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
## Kusoma Memory

Mara tu session ya debugging inapokuwa imeanzishwa, Memory inaweza kusomwa kwa kutumia aina ya ujumbe ya [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896). Function ya readMemory imeelezwa kwa kina, ikifanya hatua zinazohitajika kutuma ombi la kusoma na kupata jibu:
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
POC inayohusiana inapatikana [hapa](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5).

## .NET Core Code Execution <a href="#net-core-code-execution" id="net-core-code-execution"></a>

Ili kutekeleza code, mtu anahitaji kutambua memory region yenye ruhusa za rwx, jambo linaloweza kufanywa kwa kutumia vmmap -pages:
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
Kutafuta mahali pa kubadilisha function pointer ni muhimu, na katika .NET Core, hili linaweza kufanywa kwa kulenga **Dynamic Function Table (DFT)**. Jedwali hili, lililoelezwa katika [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h), hutumiwa na runtime kwa JIT compilation helper functions.

Kwa mifumo ya x64, signature hunting inaweza kutumiwa kupata rejeleo la symbol `_hlpDynamicFuncTable` katika `libcorclr.dll`.

Debugger function `MT_GetDCB` hutoa taarifa muhimu, ikiwemo anwani ya helper function, `m_helperRemoteStartAddr`, inayoonyesha eneo la `libcorclr.dll` katika kumbukumbu ya process. Anwani hii hutumiwa kuanzisha utafutaji wa DFT na kubadilisha function pointer kwa anwani ya shellcode.

Msimbo kamili wa POC wa injection kwenye PowerShell unapatikana [hapa](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6).

## Marejeleo

- [1] [Adam Chester (xpnsec) - macOS Injection via Third Party Frameworks](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)

{{#include ../../../banners/hacktricks-training.md}}
