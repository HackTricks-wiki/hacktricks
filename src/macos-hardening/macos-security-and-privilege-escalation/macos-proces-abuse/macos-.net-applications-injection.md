# Injekcija u .Net aplikacije na macOS-u

{{#include ../../../banners/hacktricks-training.md}}

**Ovo je sažetak posta [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/). Pogledajte ga za više detalja!**<sup>[[1]](#references)</sup>

## .NET Core Debugging <a href="#net-core-debugging" id="net-core-debugging"></a>

### **Uspostavljanje Debugging sesije** <a href="#net-core-debugging" id="net-core-debugging"></a>

Komunikacijom između debugger-a i debuggee-a u .NET-u upravlja [**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp). Ova komponenta postavlja dva imenovana pipe-a po .NET procesu, kao što je prikazano u [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127), koji se inicijalizuju putem [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27). Ovi pipe-ovi imaju sufikse **`-in`** i **`-out`**.

Ako otvorite korisnički **`$TMPDIR`**, možete pronaći debugging FIFO datoteke dostupne za debugging .Net aplikacija.

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259) zadužen je za upravljanje komunikacijom od strane debugger-a. Da bi započeo novu debugging sesiju, debugger mora poslati poruku putem `out` pipe-a, koja počinje strukturom `MessageHeader`, opisanom u .NET izvornom kodu:
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
Da bi se zatražila nova sesija, ova struktura se popunjava na sledeći način, pri čemu se tip poruke postavlja na `MT_SessionRequest`, a verzija protokola na trenutnu verziju:
```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Configure the message type and version
sSendHeader.m_eType = MT_SessionRequest;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```
Ovo zaglavlje se zatim šalje ciljnom sistemu pomoću `write` syscall-a, nakon čega sledi `sessionRequestData` struktura koja sadrži GUID sesije:
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
Operacija čitanja iz `out` cevi potvrđuje uspešno ili neuspešno uspostavljanje debugging sesije:
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
## Čitanje memorije

Kada se uspostavi debugging sesija, memorija se može čitati pomoću tipa poruke [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896). Funkcija readMemory je detaljno prikazana i obavlja neophodne korake za slanje zahteva za čitanje i preuzimanje odgovora:
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
Kompletan proof of concept (POC) dostupan je [ovde](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b).

## Upisivanje memorije

Slično tome, memorija se može upisati pomoću funkcije `writeMemory`. Proces podrazumeva podešavanje tipa poruke na `MT_WriteMemory`, navođenje adrese i dužine podataka, a zatim slanje podataka:
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
Pripadajući POC je dostupan [ovde](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5).

## .NET Core Code Execution <a href="#net-core-code-execution" id="net-core-code-execution"></a>

Za izvršavanje koda potrebno je identifikovati memorijski region sa rwx dozvolama, što se može uraditi pomoću vmmap -pages:
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
Pronalaženje mesta za prepisivanje pokazivača funkcije je neophodno, a u .NET Core to se može uraditi ciljanjem **Dynamic Function Table (DFT)**. Ova tabela, detaljno opisana u [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h), koristi se u runtime-u za pomoćne funkcije JIT kompilacije.

Na x64 sistemima, signature hunting se može koristiti za pronalaženje reference na simbol `_hlpDynamicFuncTable` u `libcorclr.dll`.

Debugger funkcija `MT_GetDCB` pruža korisne informacije, uključujući adresu pomoćne funkcije, `m_helperRemoteStartAddr`, koja ukazuje na lokaciju `libcorclr.dll` u memoriji procesa. Ova adresa se zatim koristi za započinjanje pretrage DFT-a i prepisivanje pokazivača funkcije adresom shellcode-a.

Kompletan POC kod za injection u PowerShell dostupan je [ovde](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6).

## Reference

- [1] [Adam Chester (xpnsec) - macOS Injection via Third Party Frameworks](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)

{{#include ../../../banners/hacktricks-training.md}}
