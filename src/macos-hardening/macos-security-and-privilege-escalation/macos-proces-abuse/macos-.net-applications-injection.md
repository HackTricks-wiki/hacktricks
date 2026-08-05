# Injection in .NET-Anwendungen unter macOS

{{#include ../../../banners/hacktricks-training.md}}

**Dies ist eine Zusammenfassung des Beitrags [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/). Weitere Details findest du dort!**<sup>[1]</sup>

## .NET Core Debugging <a href="#net-core-debugging" id="net-core-debugging"></a>

### **Eine Debugging-Sitzung einrichten** <a href="#net-core-debugging" id="net-core-debugging"></a>

Die Kommunikation zwischen Debugger und Debuggee in .NET wird von [**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp) verwaltet. Diese Komponente richtet für jeden .NET-Prozess zwei Named Pipes ein, wie in [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127) zu sehen ist. Diese werden über [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27) initialisiert. Diese Pipes tragen die Suffixe **`-in`** und **`-out`**.

Durch den Aufruf des **`$TMPDIR`** des Benutzers lassen sich für das Debugging von .NET-Anwendungen verfügbare Debugging-FIFOs finden.

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259) ist für die Verwaltung der Kommunikation von einem Debugger verantwortlich. Um eine neue Debugging-Sitzung zu starten, muss ein Debugger eine Nachricht über die `out`-Pipe senden, die mit einer `MessageHeader`-Struktur beginnt, wie im .NET-Quellcode beschrieben:
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
Um eine neue Sitzung anzufordern, wird diese Struktur wie folgt befüllt, wobei der Nachrichtentyp auf `MT_SessionRequest` und die Protokollversion auf die aktuelle Version gesetzt wird:
```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Configure the message type and version
sSendHeader.m_eType = MT_SessionRequest;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```
Dieser Header wird anschließend über den `write`-syscall an das Ziel gesendet, gefolgt von der `sessionRequestData`-Struktur, die eine GUID für die Sitzung enthält:
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
Ein Lesevorgang an der `out`-Pipe bestätigt den Erfolg oder Misserfolg des Aufbaus der Debugging-Sitzung:
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
## Speicher lesen

Sobald eine Debugging-Sitzung eingerichtet wurde, kann Speicher mithilfe des Nachrichtentyps [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896) gelesen werden. Die Funktion `readMemory` wird im Detail beschrieben und führt die erforderlichen Schritte zum Senden einer Leseanforderung und zum Abrufen der Antwort aus:
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
Der vollständige Proof of Concept (POC) ist [hier](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b) verfügbar.

## Speicher schreiben

Ebenso kann Speicher mithilfe der Funktion `writeMemory` geschrieben werden. Dabei wird der Nachrichtentyp auf `MT_WriteMemory` gesetzt, die Adresse und Länge der Daten angegeben und anschließend werden die Daten gesendet:
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
Der zugehörige POC ist [hier](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5) verfügbar.

## .NET Core Code Execution <a href="#net-core-code-execution" id="net-core-code-execution"></a>

Um Code auszuführen, muss man eine Speicherregion mit rwx-Berechtigungen identifizieren. Dies kann mit vmmap -pages erfolgen:
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
Das Auffinden einer Stelle zum Überschreiben eines function pointers ist erforderlich. In .NET Core kann dies durch das Anvisieren der **Dynamic Function Table (DFT)** erfolgen. Diese Tabelle, die in [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h) beschrieben ist, wird von der Runtime für JIT-Kompilierungs-Hilfsfunktionen verwendet.

Auf x64-Systemen kann Signature Hunting verwendet werden, um eine Referenz auf das Symbol `_hlpDynamicFuncTable` in `libcorclr.dll` zu finden.

Die Debugger-Funktion `MT_GetDCB` liefert nützliche Informationen, einschließlich der Adresse einer Hilfsfunktion, `m_helperRemoteStartAddr`, die den Speicherort von `libcorclr.dll` im Prozessspeicher angibt. Diese Adresse wird anschließend verwendet, um eine Suche nach der DFT zu starten und einen function pointer mit der Adresse des Shellcodes zu überschreiben.

Der vollständige POC-Code für die Injection in PowerShell ist [hier](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6) verfügbar.

## Referenzen

- [1] [Adam Chester (xpnsec) - macOS Injection via Third Party Frameworks](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)

{{#include ../../../banners/hacktricks-training.md}}
