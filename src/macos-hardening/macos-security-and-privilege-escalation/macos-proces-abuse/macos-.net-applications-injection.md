# macOS .Net Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

**Questo è un riepilogo del post [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/). Controllalo per ulteriori dettagli!**

## .NET Core Debugging <a href="#net-core-debugging" id="net-core-debugging"></a>

### **Stabilire una Sessione di Debugging** <a href="#net-core-debugging" id="net-core-debugging"></a>

La gestione della comunicazione tra debugger e debuggee in .NET è gestita da [**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp). Questo componente imposta due pipe nominate per ogni processo .NET come visto in [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127), che sono iniziate tramite [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27). Queste pipe sono suffisse con **`-in`** e **`-out`**.

Visitando il **`$TMPDIR`** dell'utente, si possono trovare FIFO di debugging disponibili per il debugging delle applicazioni .Net.

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259) è responsabile della gestione della comunicazione da un debugger. Per avviare una nuova sessione di debugging, un debugger deve inviare un messaggio tramite la pipe `out` che inizia con una struct `MessageHeader`, dettagliata nel codice sorgente di .NET:
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
Per richiedere una nuova sessione, questa struct viene popolata come segue, impostando il tipo di messaggio su `MT_SessionRequest` e la versione del protocollo sulla versione attuale:
```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Configure the message type and version
sSendHeader.m_eType = MT_SessionRequest;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```
Questo header viene quindi inviato al target utilizzando la syscall `write`, seguito dalla struct `sessionRequestData` contenente un GUID per la sessione:
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
Un'operazione di lettura sul pipe `out` conferma il successo o il fallimento dell'instaurazione della sessione di debug:
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
## Lettura della memoria

Una volta stabilita una sessione di debug, la memoria può essere letta utilizzando il tipo di messaggio [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896). La funzione readMemory è dettagliata, eseguendo i passaggi necessari per inviare una richiesta di lettura e recuperare la risposta:
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
La prova di concetto completa (POC) è disponibile [qui](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b).

## Scrittura della Memoria

Allo stesso modo, la memoria può essere scritta utilizzando la funzione `writeMemory`. Il processo prevede di impostare il tipo di messaggio su `MT_WriteMemory`, specificare l'indirizzo e la lunghezza dei dati, e poi inviare i dati:
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
Il POC associato è disponibile [qui](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5).

## Esecuzione di Codice .NET Core <a href="#net-core-code-execution" id="net-core-code-execution"></a>

Per eseguire codice, è necessario identificare una regione di memoria con permessi rwx, cosa che può essere fatta usando vmmap -pages:
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
Trovare un luogo per sovrascrivere un puntatore di funzione è necessario, e in .NET Core, questo può essere fatto mirando alla **Dynamic Function Table (DFT)**. Questa tabella, dettagliata in [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h), è utilizzata dal runtime per le funzioni di aiuto della compilazione JIT.

Per i sistemi x64, la ricerca delle firme può essere utilizzata per trovare un riferimento al simbolo `_hlpDynamicFuncTable` in `libcorclr.dll`.

La funzione del debugger `MT_GetDCB` fornisce informazioni utili, incluso l'indirizzo di una funzione di aiuto, `m_helperRemoteStartAddr`, che indica la posizione di `libcorclr.dll` nella memoria del processo. Questo indirizzo viene quindi utilizzato per avviare una ricerca per la DFT e sovrascrivere un puntatore di funzione con l'indirizzo del shellcode.

Il codice POC completo per l'iniezione in PowerShell è accessibile [qui](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6).

## Riferimenti

- [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)

{{#include ../../../banners/hacktricks-training.md}}
