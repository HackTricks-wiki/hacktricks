# macOS .Net Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

**Dies ist eine Zusammenfassung des Beitrags [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/). Weitere Details findest du dort!**<sup>[[1]](#references)</sup>

## `DOTNET_STARTUP_HOOKS`

.NET Core 3.0 und höher unterstützen die Umgebungsvariable `DOTNET_STARTUP_HOOKS`. Jeder Pfad muss eine verwaltete Assembly angeben, die einen globalen Typ `StartupHook` mit einer Methode `public static void Initialize()` enthält. Der Host lädt die Assemblies und ruft ihre Initializer synchron vor dem `Main`-Einstiegspunkt der Anwendung auf. Dadurch ermöglichen die Kontrolle über die Umgebung und eine lesbare DLL ein direktes Primitive zur Codeausführung vor `Main`.<sup>[[2]](#references)</sup>
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
Die Hook-Assembly muss mit der Runtime und den Abhängigkeiten der Anwendung kompatibel sein. Relative Pfade, die Verzeichnistrennzeichen enthalten, werden abgelehnt; verwenden Sie einen absoluten Pfad oder einen Assembly-Namen, der aus dem standardmäßigen Load Context aufgelöst werden kann. Startup Hooks sind in getrimmten Anwendungen standardmäßig deaktiviert, und benutzerdefinierte native Hosts können Runtime-Eigenschaften direkt bereitstellen, anstatt die Umgebung zu übernehmen.<sup>[[2]](#references)</sup>

Defensive Launcher sollten `DOTNET_STARTUP_HOOKS` löschen, nicht vertrauenswürdige Schreibzugriffe auf Anwendungs- und gemeinsam genutzte Assembly-Pfade verhindern und Self-contained- sowie getrimmte Deployments separat testen.

## .NET Core-Debugging <a href="#net-core-debugging" id="net-core-debugging"></a>

### **Einrichten einer Debugging-Sitzung** <a href="#net-core-debugging" id="net-core-debugging"></a>

Die Kommunikation zwischen Debugger und Debugging-Ziel in .NET wird von [**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp) verwaltet. Diese Komponente richtet, wie in [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127) zu sehen ist, zwei benannte Pipes pro .NET-Prozess ein, die über [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27) initiiert werden. Diese Pipes tragen die Suffixe **`-in`** und **`-out`**.

Durch den Besuch von **`$TMPDIR`** des Benutzers können für das Debugging von .Net-Anwendungen verfügbare Debugging-FIFOs gefunden werden.

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259) ist für die Verwaltung der Kommunikation von einem Debugger verantwortlich. Um eine neue Debugging-Sitzung zu initiieren, muss ein Debugger eine Nachricht über die `out`-Pipe senden, die mit einer `MessageHeader`-Struktur beginnt, die im .NET-Quellcode ausführlich beschrieben wird:
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
Dieser Header wird dann mithilfe des `write`-Syscalls an das Ziel gesendet, gefolgt von der `sessionRequestData`-Struktur, die eine GUID für die Sitzung enthält:
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

Sobald eine Debugging-Sitzung eingerichtet ist, kann der Speicher mithilfe des Nachrichtentyps [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896) gelesen werden. Die Funktion readMemory wird detailliert beschrieben und führt die erforderlichen Schritte aus, um eine Leseanforderung zu senden und die Antwort abzurufen:
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

Ebenso kann Speicher mithilfe der Funktion `writeMemory` geschrieben werden. Dazu wird der Nachrichtentyp auf `MT_WriteMemory` gesetzt, die Adresse und Länge der Daten angegeben und anschließend werden die Daten gesendet:
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

Um Code auszuführen, muss man eine Speicherregion mit rwx-Berechtigungen identifizieren. Dies ist mit vmmap -pages möglich:
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
Das Auffinden einer Stelle zum Überschreiben eines Funktionszeigers ist erforderlich. In .NET Core kann dies durch das Anvisieren der **Dynamic Function Table (DFT)** erfolgen. Diese in [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h) beschriebene Tabelle wird von der Runtime für JIT-Kompilierungs-Hilfsfunktionen verwendet.

Bei x64-Systemen kann signature hunting verwendet werden, um eine Referenz auf das Symbol `_hlpDynamicFuncTable` in `libcorclr.dll` zu finden.

Die Debugger-Funktion `MT_GetDCB` liefert nützliche Informationen, darunter die Adresse einer Hilfsfunktion, `m_helperRemoteStartAddr`, die den Speicherort von `libcorclr.dll` im Prozessspeicher angibt. Diese Adresse wird anschließend verwendet, um eine Suche nach der DFT zu starten und einen Funktionszeiger mit der Adresse des Shellcodes zu überschreiben.

Der vollständige POC-Code für die Injection in PowerShell ist [hier](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6) verfügbar.

## References

- [1] [Adam Chester (xpnsec) - macOS-Injection über Third-Party-Frameworks](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)
- [2] [Design des .NET-Runtime-Host-Startup-Hooks](https://github.com/dotnet/runtime/blob/main/docs/design/features/host-startup-hook.md)
{{#include ../../../banners/hacktricks-training.md}}
