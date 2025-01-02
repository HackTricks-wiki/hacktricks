# macOS .Net Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

**Hii ni muhtasari wa posti [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/). Angalia kwa maelezo zaidi!**

## .NET Core Debugging <a href="#net-core-debugging" id="net-core-debugging"></a>

### **Kuweka Kikao cha Ufuatiliaji** <a href="#net-core-debugging" id="net-core-debugging"></a>

Usimamizi wa mawasiliano kati ya debugger na debuggee katika .NET unashughulikiwa na [**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp). Kipengele hiki kinaanzisha bomba mbili zenye majina kwa kila mchakato wa .NET kama inavyoonekana katika [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127), ambazo zinaanzishwa kupitia [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27). Mabomba haya yanaishia na **`-in`** na **`-out`**.

Kwa kutembelea **`$TMPDIR`** ya mtumiaji, mtu anaweza kupata FIFOs za ufuatiliaji zinazopatikana kwa ajili ya programu za .Net.

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259) inawajibika kwa usimamizi wa mawasiliano kutoka kwa debugger. Ili kuanzisha kikao kipya cha ufuatiliaji, debugger lazima itume ujumbe kupitia bomba la `out` linaloanza na muundo wa `MessageHeader`, ulioelezwa katika msimbo wa chanzo wa .NET:
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
Ili kuomba kikao kipya, muundo huu unajazwa kama ifuatavyo, ukipanga aina ya ujumbe kuwa `MT_SessionRequest` na toleo la protokali kuwa toleo la sasa:
```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Configure the message type and version
sSendHeader.m_eType = MT_SessionRequest;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```
Kichwa hiki kisha kinatumwa kwa lengo kwa kutumia syscall ya `write`, ikifuatiwa na muundo wa `sessionRequestData` unao zawadi ya GUID kwa ajili ya kikao:
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
Operesheni ya kusoma kwenye bomba la `out` inathibitisha mafanikio au kushindwa kwa kuanzishwa kwa kikao cha ufuatiliaji:
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
## Kusoma Kumbukumbu

Mara tu kikao cha ufuatiliaji kimeanzishwa, kumbukumbu inaweza kusomwa kwa kutumia aina ya ujumbe [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896). Kazi readMemory inaelezewa kwa undani, ikifanya hatua zinazohitajika kutuma ombi la kusoma na kupata jibu:
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
Dhibitisho kamili la dhana (POC) linapatikana [hapa](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b).

## Kuandika Kumbukumbu

Vivyo hivyo, kumbukumbu inaweza kuandikwa kwa kutumia kazi ya `writeMemory`. Mchakato unahusisha kuweka aina ya ujumbe kuwa `MT_WriteMemory`, kubainisha anwani na urefu wa data, na kisha kutuma data:
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
POC inayohusiana inapatikana [here](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5).

## .NET Core Code Execution <a href="#net-core-code-execution" id="net-core-code-execution"></a>

Ili kutekeleza msimbo, mtu anahitaji kubaini eneo la kumbukumbu lenye ruhusa za rwx, ambalo linaweza kufanywa kwa kutumia vmmap -pages:
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
Kupata mahali pa kubadilisha kiashiria cha kazi ni muhimu, na katika .NET Core, hii inaweza kufanywa kwa kulenga **Dynamic Function Table (DFT)**. Meza hii, iliyoelezewa katika [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h), inatumika na runtime kwa kazi za msaada wa JIT compilation.

Kwa mifumo ya x64, utafutaji wa saini unaweza kutumika kupata rejeleo kwa alama `_hlpDynamicFuncTable` katika `libcorclr.dll`.

Kazi ya debugger `MT_GetDCB` inatoa taarifa muhimu, ikiwa ni pamoja na anwani ya kazi ya msaada, `m_helperRemoteStartAddr`, ikionyesha mahali pa `libcorclr.dll` katika kumbukumbu ya mchakato. Anwani hii kisha inatumika kuanza utafutaji wa DFT na kubadilisha kiashiria cha kazi na anwani ya shellcode.

Msimbo kamili wa POC kwa sindano katika PowerShell unapatikana [hapa](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6).

## Marejeleo

- [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)

{{#include ../../../banners/hacktricks-training.md}}
