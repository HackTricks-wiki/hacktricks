# Iniezione in applicazioni .Net su macOS

{{#include ../../../banners/hacktricks-training.md}}

**Questo è un riepilogo del post [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/). Consultalo per ulteriori dettagli!**<sup>[[1]](#references)</sup>

## `DOTNET_STARTUP_HOOKS`

.NET Core 3.0 e versioni successive supportano la variabile d'ambiente `DOTNET_STARTUP_HOOKS`. Ogni percorso deve identificare un assembly gestito contenente un tipo globale `StartupHook` con un metodo `public static void Initialize()`. L'host carica gli assembly e chiama i relativi initializer in modo sincrono prima dell'entry point `Main` dell'applicazione, fornendo il controllo dell'ambiente e una primitiva diretta di esecuzione del codice prima di `Main` tramite una DLL leggibile.<sup>[[2]](#references)</sup>
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
L'assembly dell'hook deve essere compatibile con il runtime e le dipendenze dell'applicazione. I percorsi relativi contenenti separatori di directory vengono rifiutati; usa un percorso assoluto o un nome di assembly risolvibile dal contesto di caricamento predefinito. Gli startup hook sono disabilitati per impostazione predefinita nelle applicazioni trimmed e gli host nativi personalizzati possono fornire direttamente le proprietà del runtime invece di ereditarle dall'ambiente.<sup>[[2]](#references)</sup>

I launcher difensivi dovrebbero cancellare `DOTNET_STARTUP_HOOKS`, impedire scritture non attendibili nei percorsi degli assembly dell'applicazione e condivisi e testare separatamente i deployment self-contained e trimmed.

## Debugging di .NET Core <a href="#net-core-debugging" id="net-core-debugging"></a>

### **Stabilire una sessione di debugging** <a href="#net-core-debugging" id="net-core-debugging"></a>

La gestione della comunicazione tra debugger e processo sottoposto a debugging in .NET è gestita da [**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp). Questo componente configura due named pipe per ogni processo .NET, come mostrato in [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127), che vengono inizializzate tramite [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27). Queste pipe hanno i suffissi **`-in`** e **`-out`**.

Visitando il **`$TMPDIR`** dell'utente, è possibile trovare FIFO di debugging disponibili per il debugging delle applicazioni .Net.

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259) è responsabile della gestione della comunicazione proveniente da un debugger. Per avviare una nuova sessione di debugging, un debugger deve inviare un messaggio tramite la pipe `out` che inizi con una struct `MessageHeader`, descritta nel codice sorgente di .NET:
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
Per richiedere una nuova sessione, questa struct viene popolata come segue, impostando il tipo di messaggio su `MT_SessionRequest` e la versione del protocollo sulla versione corrente:
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
Un'operazione di lettura sulla pipe `out` conferma il successo o il fallimento dell'instaurazione della sessione di debugging:
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
## Lettura della memoria

Una volta stabilita una sessione di debug, la memoria può essere letta utilizzando il tipo di messaggio [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896). La funzione readMemory è dettagliata e svolge i passaggi necessari per inviare una richiesta di lettura e recuperare la risposta:
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
La proof of concept (POC) completa è disponibile [qui](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b).

## Scrittura della memoria

Analogamente, la memoria può essere scritta utilizzando la funzione `writeMemory`. Il processo consiste nell'impostare il tipo di messaggio su `MT_WriteMemory`, specificare l'indirizzo e la lunghezza dei dati, quindi inviare i dati:
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

## .NET Core Code Execution <a href="#net-core-code-execution" id="net-core-code-execution"></a>

Per eseguire il codice, è necessario identificare una regione di memoria con permessi rwx, operazione che può essere eseguita utilizzando vmmap -pages:
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
Individuare un punto in cui sovrascrivere un function pointer è necessario e, in .NET Core, ciò può essere fatto prendendo di mira la **Dynamic Function Table (DFT)**. Questa tabella, descritta in [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h), viene utilizzata dal runtime per le funzioni helper della compilazione JIT.

Nei sistemi x64, il signature hunting può essere utilizzato per trovare un riferimento al simbolo `_hlpDynamicFuncTable` in `libcorclr.dll`.

La funzione debugger `MT_GetDCB` fornisce informazioni utili, incluso l'indirizzo di una funzione helper, `m_helperRemoteStartAddr`, che indica la posizione di `libcorclr.dll` nella memoria del processo. Questo indirizzo viene quindi utilizzato per avviare una ricerca della DFT e sovrascrivere un function pointer con l'indirizzo dello shellcode.

Il codice POC completo per l'injection in PowerShell è disponibile [qui](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6).

## References

- [1] [Adam Chester (xpnsec) - Injection in macOS tramite framework di terze parti](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)
- [2] [Design dell'host startup hook di .NET runtime](https://github.com/dotnet/runtime/blob/main/docs/design/features/host-startup-hook.md)
{{#include ../../../banners/hacktricks-training.md}}
